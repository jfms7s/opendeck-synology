//! One DSM login shared by every poller.
//!
//! - A single async `Mutex` around the session state serialises logins:
//!   when several pollers find the session expired at once, the first logs
//!   in again and the rest reuse its sid (they see a newer `generation`).
//! - Credential failures are remembered (`blocked`) and returned without
//!   contacting DSM until the settings change or a 2FA code is submitted -
//!   retrying a wrong password is what trips DSM's auto-block.

use crate::dsm::api::{AUTH, ApiInfo, ApiMap, discover};
use crate::dsm::error::{AuthError, DsmError};
use crate::dsm::transport::Transport;
use serde_json::Value;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// DSM lists sessions by this name (Control Panel › Security › Account activity).
pub const SESSION_NAME: &str = "OpenDeck";

/// Codes meaning "your session is gone", worth one silent re-login.
const SESSION_LOST: [i64; 3] = [106, 107, 119];
/// "No permission" - also what a just-expired session can look like, so it
/// gets one re-login before being believed.
const NO_PERMISSION: i64 = 105;
/// DSM's "API does not exist".
const NO_SUCH_API: i64 = 102;

#[derive(Clone)]
pub struct Credentials {
    pub account: String,
    pub password: String,
    /// 2FA device token from an earlier OTP login.
    pub did: Option<String>,
    /// How this device appears in DSM's trusted-device list.
    pub device_name: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("account", &self.account)
            .field("password", &"<redacted>")
            .field("did", &self.did.as_ref().map(|_| "<redacted>"))
            .field("device_name", &self.device_name)
            .finish()
    }
}

/// Told about a new device token (`Some`) or one DSM stopped honouring (`None`).
pub type DidListener = Arc<dyn Fn(Option<String>) + Send + Sync>;

struct State {
    apis: Option<Arc<ApiMap>>,
    sid: Option<String>,
    generation: u64,
    blocked: Option<AuthError>,
    creds: Credentials,
}

pub struct Session {
    transport: Arc<dyn Transport>,
    state: Mutex<State>,
    on_did: DidListener,
}

impl Session {
    pub fn new(transport: Arc<dyn Transport>, creds: Credentials, on_did: DidListener) -> Self {
        Self {
            transport,
            state: Mutex::new(State {
                apis: None,
                sid: None,
                generation: 0,
                blocked: None,
                creds,
            }),
            on_did,
        }
    }

    /// Calls `api`.`method` with the current session, logging in first if
    /// needed and once more if DSM says the session is gone.
    pub async fn call(
        &self,
        api: &str,
        method: &str,
        params: &[(&str, &str)],
    ) -> Result<Value, DsmError> {
        let (apis, sid, generation) = self.ensure_login().await?;
        let info = apis.get(api).ok_or_else(|| DsmError::Api {
            api: api.into(),
            code: NO_SUCH_API,
        })?;
        match self.request(info, api, method, &sid, params).await? {
            Ok(data) => return Ok(data),
            Err(code) if SESSION_LOST.contains(&code) || code == NO_PERMISSION => {}
            Err(code) => {
                return Err(DsmError::Api {
                    api: api.into(),
                    code,
                });
            }
        }
        let sid = self.relogin(generation).await?;
        match self.request(info, api, method, &sid, params).await? {
            Ok(data) => Ok(data),
            Err(NO_PERMISSION) => Err(DsmError::Permission { api: api.into() }),
            Err(code) => Err(DsmError::Api {
                api: api.into(),
                code,
            }),
        }
    }

    /// Logs in with a 2FA code, asking DSM to remember this device; the new
    /// device token goes to `on_did` for safekeeping.
    pub async fn submit_otp(&self, code: &str) -> Result<(), DsmError> {
        let mut st = self.state.lock().await;
        match st.blocked.take() {
            None | Some(AuthError::NeedOtp | AuthError::BadOtp) => {}
            Some(other) => {
                st.blocked = Some(other); // a code can't fix a wrong password
                return Err(other.into());
            }
        }
        self.discover_once(&mut st).await?;
        self.login(&mut st, Some(code)).await
    }

    /// Best effort; never takes more than a second.
    pub async fn logout(&self) {
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            let st = self.state.lock().await;
            let (Some(apis), Some(sid)) = (&st.apis, &st.sid) else {
                return;
            };
            let Some(info) = apis.get(AUTH) else { return };
            let version = info.version.to_string();
            let form = [
                ("api", AUTH),
                ("version", version.as_str()),
                ("method", "logout"),
                ("session", SESSION_NAME),
                ("_sid", sid.as_str()),
            ];
            let _ = self.transport.call(&info.path, &form).await;
        })
        .await;
    }

    async fn request(
        &self,
        info: &ApiInfo,
        api: &str,
        method: &str,
        sid: &str,
        params: &[(&str, &str)],
    ) -> Result<Result<Value, i64>, DsmError> {
        let version = info.version.to_string();
        let mut form = vec![
            ("api", api),
            ("version", version.as_str()),
            ("method", method),
            ("_sid", sid),
        ];
        form.extend_from_slice(params);
        self.transport.call(&info.path, &form).await
    }

    async fn discover_once(&self, st: &mut State) -> Result<(), DsmError> {
        if st.apis.is_none() {
            st.apis = Some(Arc::new(discover(self.transport.as_ref()).await?));
        }
        Ok(())
    }

    /// (apis, sid, generation), logging in first if there is no session.
    async fn ensure_login(&self) -> Result<(Arc<ApiMap>, String, u64), DsmError> {
        let mut st = self.state.lock().await;
        if let Some(e) = st.blocked {
            return Err(e.into());
        }
        self.discover_once(&mut st).await?;
        if st.sid.is_none() {
            self.login(&mut st, None).await?;
        }
        let apis = st.apis.clone().expect("discovered above");
        let sid = st.sid.clone().expect("logged in above");
        Ok((apis, sid, st.generation))
    }

    /// Replaces the session the caller saw expire - unless another caller
    /// already did (the generation moved on), in which case its sid is reused.
    async fn relogin(&self, seen_generation: u64) -> Result<String, DsmError> {
        let mut st = self.state.lock().await;
        if let Some(e) = st.blocked {
            return Err(e.into());
        }
        if st.generation == seen_generation || st.sid.is_none() {
            st.sid = None;
            self.login(&mut st, None).await?;
        }
        Ok(st.sid.clone().expect("logged in above"))
    }

    async fn login(&self, st: &mut State, otp: Option<&str>) -> Result<(), DsmError> {
        let apis = st.apis.clone().expect("discover before login");
        let info = apis.get(AUTH).expect("discover guarantees SYNO.API.Auth");
        let version = info.version.to_string();
        let c = st.creds.clone();
        let mut form = vec![
            ("api", AUTH),
            ("version", version.as_str()),
            ("method", "login"),
            ("account", c.account.as_str()),
            ("passwd", c.password.as_str()),
            ("session", SESSION_NAME),
            ("format", "sid"),
        ];
        match (otp, c.did.as_deref()) {
            (Some(code), _) => form.extend([
                ("otp_code", code),
                ("enable_device_token", "yes"),
                ("device_name", c.device_name.as_str()),
            ]),
            (None, Some(did)) => {
                form.extend([("device_id", did), ("device_name", c.device_name.as_str())])
            }
            (None, None) => {}
        }
        match self.transport.call(&info.path, &form).await? {
            Ok(data) => {
                let sid = data["sid"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| DsmError::Parse {
                        api: AUTH.into(),
                        detail: "login returned no session id".into(),
                    })?;
                st.sid = Some(sid.to_string());
                st.generation += 1;
                if otp.is_some()
                    && let Some(did) = data["did"].as_str().filter(|d| !d.is_empty())
                {
                    st.creds.did = Some(did.to_string());
                    (self.on_did)(Some(did.to_string()));
                }
                Ok(())
            }
            Err(code) => {
                let Some(err) = AuthError::from_login_code(code) else {
                    return Err(DsmError::Api {
                        api: AUTH.into(),
                        code,
                    });
                };
                if err == AuthError::NeedOtp && st.creds.did.take().is_some() {
                    // DSM no longer honours the stored device token.
                    (self.on_did)(None);
                }
                st.sid = None;
                st.blocked = Some(err);
                Err(err.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsm::api::UTILIZATION;
    use crate::dsm::fake::{FakeDsm, Req};
    use serde_json::json;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicU32, Ordering::SeqCst};

    fn creds(did: Option<&str>) -> Credentials {
        Credentials {
            account: "jf".into(),
            password: "p&ss=w+rd%ü".into(),
            did: did.map(str::to_string),
            device_name: "OpenDeck-desk".into(),
        }
    }

    fn get(r: &Req, k: &str) -> Option<String> {
        r.get(k).cloned()
    }

    /// Records every `on_did` call.
    fn did_log() -> (DidListener, Arc<StdMutex<Vec<Option<String>>>>) {
        let log = Arc::new(StdMutex::new(Vec::new()));
        let l = log.clone();
        (Arc::new(move |d| l.lock().unwrap().push(d)), log)
    }

    #[tokio::test]
    async fn logs_in_once_and_reuses_the_sid() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") => Ok(json!({ "sid": "s1" })),
            _ if get(r, "_sid").as_deref() == Some("s1") => Ok(json!({ "cpu": 1 })),
            _ => Err(119),
        });
        let (on_did, _) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        assert_eq!(
            s.call(UTILIZATION, "get", &[]).await.unwrap(),
            json!({ "cpu": 1 })
        );
        assert_eq!(
            s.call(UTILIZATION, "get", &[]).await.unwrap(),
            json!({ "cpu": 1 })
        );
        assert_eq!(fake.count("login"), 1);
        let login = fake
            .requests()
            .into_iter()
            .find(|r| get(r, "method").as_deref() == Some("login"))
            .unwrap();
        assert_eq!(
            get(&login, "passwd").as_deref(),
            Some("p&ss=w+rd%ü"),
            "password passed through untouched"
        );
        assert_eq!(get(&login, "session").as_deref(), Some(SESSION_NAME));
        assert_eq!(get(&login, "version").as_deref(), Some("6"));
        assert_eq!(get(&login, "device_id"), None, "no device token yet");
    }

    #[tokio::test]
    async fn two_factor_flow_stores_the_device_token() {
        let fake =
            FakeDsm::new(
                |r| match (get(r, "method").as_deref(), get(r, "otp_code").as_deref()) {
                    (Some("login"), Some("123456"))
                        if get(r, "enable_device_token").as_deref() == Some("yes") =>
                    {
                        Ok(json!({ "sid": "s1", "did": "dev-1" }))
                    }
                    (Some("login"), Some(_)) => Err(404),
                    (Some("login"), None) => Err(403),
                    _ => Ok(json!({ "ok": true })),
                },
            );
        let (on_did, dids) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        assert_eq!(
            s.call(UTILIZATION, "get", &[]).await,
            Err(DsmError::Auth(AuthError::NeedOtp))
        );
        assert_eq!(
            s.call(UTILIZATION, "get", &[]).await,
            Err(DsmError::Auth(AuthError::NeedOtp))
        );
        assert_eq!(
            fake.count("login"),
            1,
            "waits for the user instead of retrying"
        );

        assert_eq!(
            s.submit_otp("000000").await,
            Err(DsmError::Auth(AuthError::BadOtp))
        );
        s.submit_otp("123456").await.unwrap();
        assert_eq!(
            dids.lock().unwrap().as_slice(),
            &[Some("dev-1".to_string())]
        );
        assert!(s.call(UTILIZATION, "get", &[]).await.is_ok());
        let last_login = fake
            .requests()
            .into_iter()
            .rev()
            .find(|r| get(r, "method").as_deref() == Some("login"))
            .unwrap();
        assert_eq!(
            get(&last_login, "device_name").as_deref(),
            Some("OpenDeck-desk")
        );
    }

    #[tokio::test]
    async fn a_stored_device_token_skips_the_code() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") if get(r, "device_id").as_deref() == Some("dev-1") => {
                Ok(json!({ "sid": "s1" }))
            }
            Some("login") => Err(403),
            _ => Ok(json!({ "ok": true })),
        });
        let (on_did, dids) = did_log();
        let s = Session::new(fake.clone(), creds(Some("dev-1")), on_did);
        assert!(s.call(UTILIZATION, "get", &[]).await.is_ok());
        assert!(dids.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_rejected_device_token_is_dropped() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") => Err(403),
            _ => Ok(json!({})),
        });
        let (on_did, dids) = did_log();
        let s = Session::new(fake.clone(), creds(Some("revoked")), on_did);
        assert_eq!(
            s.call(UTILIZATION, "get", &[]).await,
            Err(DsmError::Auth(AuthError::NeedOtp))
        );
        assert_eq!(dids.lock().unwrap().as_slice(), &[None]);
    }

    #[tokio::test]
    async fn never_retries_a_wrong_password() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") => Err(400),
            _ => Ok(json!({})),
        });
        let (on_did, _) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        for _ in 0..3 {
            assert_eq!(
                s.call(UTILIZATION, "get", &[]).await,
                Err(DsmError::Auth(AuthError::BadCredentials))
            );
        }
        assert_eq!(fake.count("login"), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_callers_share_one_relogin() {
        let logins = Arc::new(AtomicU32::new(0));
        let l = logins.clone();
        let fake = FakeDsm::new(move |r| match get(r, "method").as_deref() {
            Some("login") => Ok(json!({ "sid": format!("s{}", l.fetch_add(1, SeqCst) + 1) })),
            // The first session expires; the second one works.
            _ if get(r, "_sid").as_deref() == Some("s2") => Ok(json!({ "ok": true })),
            _ => Err(119),
        });
        let (on_did, _) = did_log();
        let s = Arc::new(Session::new(fake.clone(), creds(None), on_did));
        let calls = (0..4).map(|_| {
            let s = s.clone();
            tokio::spawn(async move { s.call(UTILIZATION, "get", &[]).await })
        });
        for r in futures::future::join_all(calls).await {
            assert!(r.unwrap().is_ok());
        }
        assert_eq!(
            logins.load(SeqCst),
            2,
            "initial login + exactly one re-login"
        );
    }

    #[tokio::test]
    async fn persistent_105_is_a_permission_error() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") => Ok(json!({ "sid": "s1" })),
            _ => Err(105),
        });
        let (on_did, _) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        assert_eq!(
            s.call(crate::dsm::api::STORAGE, "load_info", &[]).await,
            Err(DsmError::Permission {
                api: "SYNO.Storage.CGI.Storage".into()
            })
        );
        assert_eq!(
            fake.count("login"),
            2,
            "one re-login to rule out a lost session"
        );
    }

    #[tokio::test]
    async fn other_error_codes_surface_as_api_errors() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") => Ok(json!({ "sid": "s1" })),
            _ => Err(117),
        });
        let (on_did, _) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        assert_eq!(
            s.call(UTILIZATION, "get", &[]).await,
            Err(DsmError::Api {
                api: UTILIZATION.into(),
                code: 117
            })
        );
        assert_eq!(fake.count("login"), 1);
    }

    #[tokio::test]
    async fn logout_ends_the_session() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") => Ok(json!({ "sid": "s1" })),
            _ => Ok(json!({})),
        });
        let (on_did, _) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        s.call(UTILIZATION, "get", &[]).await.unwrap();
        s.logout().await;
        let last = fake.requests().pop().unwrap();
        assert_eq!(get(&last, "method").as_deref(), Some("logout"));
        assert_eq!(get(&last, "_sid").as_deref(), Some("s1"));
    }

    #[test]
    fn debug_output_hides_secrets() {
        let text = format!("{:?}", creds(Some("dev-1")));
        assert!(!text.contains("p&ss") && !text.contains("dev-1"), "{text}");
    }
}
