//! One DSM login shared by every poller.
//!
//! - A single async `Mutex` around the session state serialises logins:
//!   when several pollers find the session expired at once, the first logs
//!   in again and the rest reuse its sid (they see a newer `generation`).
//! - Credential failures are remembered (`blocked`) and returned without
//!   contacting DSM until the settings change or a 2FA code is submitted -
//!   retrying a wrong password is what trips DSM's auto-block.
//! - `logout` closes a session for good: a request still on its way when the
//!   connection was replaced can't sign it in again and leak a DSM session.

use crate::dsm::api::{AUTH, ApiInfo, ApiMap, discover};
use crate::dsm::error::{AuthError, DsmError};
use crate::dsm::transport::Transport;
use serde_json::Value;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
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
    /// Whether to send and ask for a device token. Off over plain HTTP:
    /// the password and the token together would let anyone sniffing the
    /// link sign in without a 2FA code.
    pub remember_device: bool,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("account", &self.account)
            .field("password", &"<redacted>")
            .field("did", &self.did.as_ref().map(|_| "<redacted>"))
            .field("device_name", &self.device_name)
            .field("remember_device", &self.remember_device)
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
    /// Set by `logout`: a replaced session must never sign in again, or a
    /// request still on its way would leave a session behind in DSM.
    closed: AtomicBool,
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
            closed: AtomicBool::new(false),
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
        let code = match self.request(info, api, method, &sid, params).await? {
            Ok(data) => return Ok(data),
            Err(code) if SESSION_LOST.contains(&code) || code == NO_PERMISSION => code,
            Err(code) => {
                return Err(DsmError::Api {
                    api: api.into(),
                    code,
                });
            }
        };
        let (sid, superseded) = self.relogin(generation).await?;
        // After 105 the old session may well still be alive in DSM: end it,
        // or every backoff period would leave one more behind. (After 106,
        // 107 or 119 DSM has already ended it.)
        if code == NO_PERMISSION
            && let Some(old) = superseded.filter(|old| *old != sid)
            && let Some(auth) = apis.get(AUTH)
        {
            self.send_logout(auth, &old).await;
        }
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
    ///
    /// Only when DSM asked for a code: a code sent while signed in (a stale
    /// settings panel, a double submit) would replace a working session with
    /// a failed login. A code that can't be one (empty, not digits) never
    /// reaches DSM, where it would count as a failed sign-in.
    pub async fn submit_otp(&self, code: &str) -> Result<(), DsmError> {
        if !is_otp_code(code) {
            return Err(AuthError::BadOtp.into());
        }
        let mut st = self.state.lock().await;
        if self.closed.load(SeqCst) {
            return Err(DsmError::NotConfigured);
        }
        match st.blocked {
            Some(AuthError::NeedOtp | AuthError::BadOtp) => st.blocked = None,
            Some(other) => return Err(other.into()), // a code can't fix a wrong password
            None => return Ok(()),
        }
        let result = match self.discover_once(&mut st).await {
            Ok(()) => self.login(&mut st, Some(code)).await,
            Err(e) => Err(e),
        };
        // The code never reached DSM's verdict (network, API error): still
        // waiting for one, rather than logging in again without it.
        if matches!(&result, Err(e) if !matches!(e, DsmError::Auth(_))) {
            st.blocked = Some(AuthError::NeedOtp);
        }
        result
    }

    /// Ends the session for good: best effort, never more than a second.
    /// Forgets the sid whether or not the logout request itself succeeds,
    /// and any later `call()` fails with `NotConfigured` instead of signing
    /// in again - a new connection gets a new `Session`.
    pub async fn logout(&self) {
        self.closed.store(true, SeqCst);
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            let (info, sid) = {
                let mut st = self.state.lock().await;
                let Some(sid) = st.sid.take() else { return };
                st.generation += 1;
                let Some(info) = st.apis.as_ref().and_then(|apis| apis.get(AUTH)) else {
                    return;
                };
                (info.clone(), sid)
            };
            self.send_logout(&info, &sid).await;
        })
        .await;
    }

    /// Ends DSM session `sid`; best effort, at most a second. Never call it
    /// while holding the state lock.
    async fn send_logout(&self, auth: &ApiInfo, sid: &str) {
        let version = auth.version.to_string();
        let form = [
            ("api", AUTH),
            ("version", version.as_str()),
            ("method", "logout"),
            ("session", SESSION_NAME),
            ("_sid", sid),
        ];
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            self.transport.call(&auth.path, &form),
        )
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
        if self.closed.load(SeqCst) {
            return Err(DsmError::NotConfigured);
        }
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
    /// Returns the new sid and, if this call replaced one, the old sid.
    async fn relogin(&self, seen_generation: u64) -> Result<(String, Option<String>), DsmError> {
        let mut st = self.state.lock().await;
        if self.closed.load(SeqCst) {
            return Err(DsmError::NotConfigured);
        }
        if let Some(e) = st.blocked {
            return Err(e.into());
        }
        let mut superseded = None;
        if st.generation == seen_generation || st.sid.is_none() {
            superseded = st.sid.take();
            self.login(&mut st, None).await?;
        }
        Ok((st.sid.clone().expect("logged in above"), superseded))
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
        let did = c.did.as_deref().filter(|_| c.remember_device);
        match (otp, did) {
            (Some(code), _) if c.remember_device => form.extend([
                ("otp_code", code),
                ("enable_device_token", "yes"),
                ("device_name", c.device_name.as_str()),
            ]),
            (Some(code), _) => form.push(("otp_code", code)),
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
                    && c.remember_device
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
                if err == AuthError::NeedOtp && otp.is_none() && did.is_some() {
                    // DSM no longer honours the device token we sent.
                    st.creds.did = None;
                    (self.on_did)(None);
                }
                st.sid = None;
                st.blocked = Some(err);
                Err(err.into())
            }
        }
    }
}

/// What a TOTP code can look like once whitespace is gone: 6-8 digits.
pub fn is_otp_code(code: &str) -> bool {
    (6..=8).contains(&code.len()) && code.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsm::api::UTILIZATION;
    use crate::dsm::fake::{Drops, FakeDsm, Req};
    use serde_json::json;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::AtomicU32;

    fn creds(did: Option<&str>) -> Credentials {
        Credentials {
            account: "jf".into(),
            password: "p&ss=w+rd%ü".into(),
            did: did.map(str::to_string),
            device_name: "OpenDeck-desk".into(),
            remember_device: true,
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
    async fn an_otp_submit_that_never_arrives_still_waits_for_a_code() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") => Err(403),
            _ => Ok(json!({})),
        });
        let (on_did, _) = did_log();
        let s = Session::new(
            Arc::new(Drops(fake.clone(), "otp_code")),
            creds(None),
            on_did,
        );
        assert_eq!(
            s.call(UTILIZATION, "get", &[]).await,
            Err(DsmError::Auth(AuthError::NeedOtp))
        );
        assert!(matches!(
            s.submit_otp("123456").await,
            Err(DsmError::Transport(_))
        ));
        let sent = fake.requests().len();
        assert_eq!(
            s.call(UTILIZATION, "get", &[]).await,
            Err(DsmError::Auth(AuthError::NeedOtp)),
            "still waiting for a code"
        );
        assert_eq!(fake.requests().len(), sent, "without contacting DSM");
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
    async fn a_relogin_after_105_logs_out_the_superseded_session() {
        let logins = Arc::new(AtomicU32::new(0));
        let l = logins.clone();
        let fake = FakeDsm::new(move |r| match get(r, "method").as_deref() {
            Some("login") => Ok(json!({ "sid": format!("s{}", l.fetch_add(1, SeqCst) + 1) })),
            Some("logout") => Ok(json!({})),
            _ => Err(105),
        });
        let (on_did, _) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        assert!(matches!(
            s.call(crate::dsm::api::STORAGE, "load_info", &[]).await,
            Err(DsmError::Permission { .. })
        ));
        let logouts: Vec<_> = fake
            .requests()
            .into_iter()
            .filter(|r| get(r, "method").as_deref() == Some("logout"))
            .map(|r| get(&r, "_sid"))
            .collect();
        assert_eq!(logouts, [Some("s1".to_string())], "the replaced sid, only");
    }

    #[tokio::test]
    async fn a_relogin_after_a_lost_session_sends_no_logout() {
        let logins = Arc::new(AtomicU32::new(0));
        let l = logins.clone();
        let fake = FakeDsm::new(move |r| match get(r, "method").as_deref() {
            Some("login") => Ok(json!({ "sid": format!("s{}", l.fetch_add(1, SeqCst) + 1) })),
            _ if get(r, "_sid").as_deref() == Some("s2") => Ok(json!({ "ok": true })),
            _ => Err(119),
        });
        let (on_did, _) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        assert!(s.call(UTILIZATION, "get", &[]).await.is_ok());
        assert_eq!(fake.count("logout"), 0, "DSM already ended that session");
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

    #[tokio::test]
    async fn a_logged_out_session_never_signs_in_again() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") => Ok(json!({ "sid": "s1" })),
            _ => Ok(json!({ "ok": true })),
        });
        let (on_did, _) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        s.call(UTILIZATION, "get", &[]).await.unwrap();
        s.logout().await;
        // A request that was still on its way when the connection was
        // replaced (a poll, the firmware lookup) must not revive it: that
        // would leave a session behind in DSM.
        assert_eq!(
            s.call(UTILIZATION, "get", &[]).await,
            Err(DsmError::NotConfigured)
        );
        assert_eq!(fake.count("login"), 1);
        assert_eq!(fake.count("logout"), 1);
    }

    #[tokio::test]
    async fn a_code_that_cannot_be_one_never_reaches_dsm() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") => Err(403),
            _ => Ok(json!({})),
        });
        let (on_did, _) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        assert_eq!(
            s.call(UTILIZATION, "get", &[]).await,
            Err(DsmError::Auth(AuthError::NeedOtp))
        );
        let sent = fake.requests().len();
        for code in ["", "12345", "12a456", "123456789"] {
            assert_eq!(
                s.submit_otp(code).await,
                Err(DsmError::Auth(AuthError::BadOtp)),
                "{code:?}"
            );
        }
        assert_eq!(
            fake.requests().len(),
            sent,
            "no failed sign-in on DSM's counter"
        );
        assert_eq!(
            s.call(UTILIZATION, "get", &[]).await,
            Err(DsmError::Auth(AuthError::NeedOtp)),
            "still waiting for a real code"
        );
    }

    #[tokio::test]
    async fn a_code_sent_while_signed_in_is_ignored() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") if get(r, "otp_code").is_some() => Err(404),
            Some("login") => Ok(json!({ "sid": "s1" })),
            _ => Ok(json!({ "ok": true })),
        });
        let (on_did, _) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        assert!(s.call(UTILIZATION, "get", &[]).await.is_ok());
        assert_eq!(s.submit_otp("999999").await, Ok(()));
        assert_eq!(fake.count("login"), 1, "no second login");
        assert!(
            s.call(UTILIZATION, "get", &[]).await.is_ok(),
            "still connected"
        );
        assert_eq!(fake.count("logout"), 0);
    }

    #[tokio::test]
    async fn without_remember_device_no_token_is_sent_or_asked_for() {
        let fake =
            FakeDsm::new(
                |r| match (get(r, "method").as_deref(), get(r, "otp_code").as_deref()) {
                    (Some("login"), Some(_)) => Ok(json!({ "sid": "s1", "did": "dev-2" })),
                    (Some("login"), None) => Err(403),
                    _ => Ok(json!({ "ok": true })),
                },
            );
        let (on_did, dids) = did_log();
        let c = Credentials {
            remember_device: false,
            ..creds(Some("dev-1"))
        };
        let s = Session::new(fake.clone(), c, on_did);
        assert_eq!(
            s.call(UTILIZATION, "get", &[]).await,
            Err(DsmError::Auth(AuthError::NeedOtp))
        );
        s.submit_otp("123456").await.unwrap();
        for r in fake.requests() {
            assert_eq!(get(&r, "device_id"), None, "{r:?}");
            assert_eq!(get(&r, "enable_device_token"), None, "{r:?}");
        }
        assert!(dids.lock().unwrap().is_empty(), "nothing to store");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_refused_relogin_is_not_repeated_by_other_callers() {
        let logins = Arc::new(AtomicU32::new(0));
        let l = logins.clone();
        let fake = FakeDsm::new(move |r| match get(r, "method").as_deref() {
            // The first login works; then the password is changed on the NAS.
            Some("login") if l.fetch_add(1, SeqCst) == 0 => Ok(json!({ "sid": "s1" })),
            Some("login") => Err(400),
            _ => Err(119),
        });
        let (on_did, _) = did_log();
        let s = Arc::new(Session::new(fake.clone(), creds(None), on_did));
        let calls = (0..4).map(|_| {
            let s = s.clone();
            tokio::spawn(async move { s.call(UTILIZATION, "get", &[]).await })
        });
        for r in futures::future::join_all(calls).await {
            assert_eq!(r.unwrap(), Err(DsmError::Auth(AuthError::BadCredentials)));
        }
        assert_eq!(
            fake.count("login"),
            2,
            "the first login and one refused re-login, never a third"
        );
    }

    /// The fake NAS, except that some requests never get an answer.
    struct Hangs(Arc<FakeDsm>, &'static str);

    #[async_trait::async_trait]
    impl Transport for Hangs {
        async fn call(
            &self,
            path: &str,
            form: &[(&str, &str)],
        ) -> Result<Result<Value, i64>, DsmError> {
            if form.contains(&("method", self.1)) {
                return std::future::pending().await;
            }
            self.0.call(path, form).await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn logout_gives_up_after_a_second_even_while_a_login_hangs() {
        let fake = FakeDsm::new(|_| Ok(json!({})));
        let (on_did, _) = did_log();
        let s = Arc::new(Session::new(
            Arc::new(Hangs(fake, "login")),
            creds(None),
            on_did,
        ));
        let busy = s.clone();
        tokio::spawn(async move { busy.call(UTILIZATION, "get", &[]).await });
        tokio::task::yield_now().await;
        let t0 = tokio::time::Instant::now();
        s.logout().await;
        assert_eq!(t0.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_hanging_logout_of_a_superseded_session_costs_at_most_a_second() {
        let logins = Arc::new(AtomicU32::new(0));
        let l = logins.clone();
        let fake = FakeDsm::new(move |r| match get(r, "method").as_deref() {
            Some("login") => Ok(json!({ "sid": format!("s{}", l.fetch_add(1, SeqCst) + 1) })),
            _ => Err(105),
        });
        let (on_did, _) = did_log();
        let s = Session::new(Arc::new(Hangs(fake, "logout")), creds(None), on_did);
        let t0 = tokio::time::Instant::now();
        assert!(matches!(
            s.call(crate::dsm::api::STORAGE, "load_info", &[]).await,
            Err(DsmError::Permission { .. })
        ));
        assert_eq!(t0.elapsed(), Duration::from_secs(1));
    }

    #[test]
    fn otp_codes_are_six_to_eight_digits() {
        assert!(is_otp_code("123456") && is_otp_code("12345678"));
        assert!(!is_otp_code("") && !is_otp_code("12345") && !is_otp_code("12 456"));
    }

    #[test]
    fn debug_output_hides_secrets() {
        let text = format!("{:?}", creds(Some("dev-1")));
        assert!(!text.contains("p&ss") && !text.contains("dev-1"), "{text}");
    }
}
