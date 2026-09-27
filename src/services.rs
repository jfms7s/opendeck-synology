//! The plugin's shared state: the connection settings, the one DSM
//! session, the four endpoint pollers every key and dial subscribes to, and
//! the connection status they all watch.

use crate::dsm::api::{STORAGE, SYSTEM, UPGRADE, UTILIZATION};
use crate::dsm::error::DsmError;
use crate::dsm::model::{self, Payload};
use crate::dsm::session::{Credentials, DidListener, Session};
use crate::dsm::transport::Transport;
use crate::metric::Endpoint;
use crate::poller::{Fetch, Poller};
use crate::secrets::{SecretStore, did_key, password_key};
use crate::settings::{Connection, FallbackSecrets, GlobalSettings, TempUnit};
use crate::status::ConnStatus;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

#[async_trait]
pub trait SettingsSink: Send + Sync {
    /// Persists the plugin-wide settings (OpenDeck's `setGlobalSettings`).
    async fn save(&self, settings: &GlobalSettings);
}

pub type TransportFactory =
    Arc<dyn Fn(&Connection) -> Result<Arc<dyn Transport>, DsmError> + Send + Sync>;

#[derive(Debug, Clone, Copy)]
enum Secret {
    Password,
    Did,
}

pub struct Services {
    utilization: Poller<Payload>,
    system: Poller<Payload>,
    storage: Poller<Payload>,
    update: Poller<Payload>,
    global: Mutex<GlobalSettings>,
    loaded: AtomicBool,
    session: Mutex<Option<Arc<Session>>>,
    has_password: AtomicBool,
    status: watch::Sender<ConnStatus>,
    secrets: Arc<dyn SecretStore>,
    sink: Arc<dyn SettingsSink>,
    transports: TransportFactory,
    device_name: String,
}

impl Services {
    pub fn new(
        secrets: Arc<dyn SecretStore>,
        sink: Arc<dyn SettingsSink>,
        transports: TransportFactory,
        device_name: String,
    ) -> Arc<Self> {
        let poller = |e: Endpoint| Poller::new(e.default_interval());
        Arc::new(Self {
            utilization: poller(Endpoint::Utilization),
            system: poller(Endpoint::SystemInfo),
            storage: poller(Endpoint::Storage),
            update: poller(Endpoint::Update),
            global: Mutex::new(GlobalSettings::default()),
            loaded: AtomicBool::new(false),
            session: Mutex::new(None),
            has_password: AtomicBool::new(false),
            // Until OpenDeck hands over the saved settings, keys show "…".
            status: watch::Sender::new(ConnStatus::Connecting),
            secrets,
            sink,
            transports,
            device_name,
        })
    }

    pub fn poller(&self, e: Endpoint) -> &Poller<Payload> {
        match e {
            Endpoint::Utilization => &self.utilization,
            Endpoint::SystemInfo => &self.system,
            Endpoint::Storage => &self.storage,
            Endpoint::Update => &self.update,
        }
    }

    pub fn status(&self) -> watch::Receiver<ConnStatus> {
        self.status.subscribe()
    }

    pub fn current_status(&self) -> ConnStatus {
        self.status.borrow().clone()
    }

    pub fn global(&self) -> GlobalSettings {
        self.global.lock().unwrap().clone()
    }

    pub fn has_password(&self) -> bool {
        self.has_password.load(SeqCst)
    }

    /// Adopts settings loaded from OpenDeck, at startup or when they change.
    pub async fn load_global(self: &Arc<Self>, g: GlobalSettings) {
        let unchanged = {
            let mut cur = self.global.lock().unwrap();
            let same = *cur == g;
            *cur = g;
            same
        };
        if self.loaded.swap(true, SeqCst) && unchanged {
            return;
        }
        self.reconnect().await;
    }

    /// Saves the connection block of the settings panel. `password: None`
    /// keeps the stored password.
    pub async fn save_connection(self: &Arc<Self>, mut conn: Connection, password: Option<String>) {
        let mut g = self.global();
        // Another NAS has another certificate: the old pin must not carry over.
        let same_nas = conn.host() == g.connection.host() && conn.port == g.connection.port;
        conn.pinned_sha256 = if same_nas {
            g.connection.pinned_sha256.clone()
        } else {
            None
        };
        g.connection = conn;
        if let Some(pw) = password {
            self.put_secret(&mut g, Secret::Password, Some(pw)).await;
        }
        self.persist(g).await;
        self.reconnect().await;
    }

    pub async fn set_temp_unit(self: &Arc<Self>, unit: TempUnit) {
        let mut g = self.global();
        g.temp_unit = unit;
        self.persist(g).await;
        // Nothing about the connection changed, but every key must redraw.
        self.status.send_modify(|_| {});
    }

    pub async fn submit_otp(&self, code: &str) -> Result<(), DsmError> {
        let session = self
            .session
            .lock()
            .unwrap()
            .clone()
            .ok_or(DsmError::NotConfigured)?;
        let result = session.submit_otp(code).await;
        match &result {
            Ok(()) => {
                self.set_status(ConnStatus::Connecting);
                for e in Endpoint::ALL {
                    self.poller(e).refresh_now();
                }
            }
            Err(e) => {
                if let Some(s) = ConnStatus::from_error(e) {
                    self.set_status(s);
                }
            }
        }
        result
    }

    /// Pins the certificate the last failed handshake presented.
    pub async fn trust_certificate(self: &Arc<Self>) {
        let ConnStatus::Certificate { fingerprint, .. } = self.current_status() else {
            return;
        };
        let mut g = self.global();
        g.connection.pinned_sha256 = Some(fingerprint);
        self.persist(g).await;
        self.reconnect().await;
    }

    pub async fn logout(&self) {
        let session = self.session.lock().unwrap().clone();
        if let Some(s) = session {
            s.logout().await;
        }
    }

    async fn persist(&self, g: GlobalSettings) {
        *self.global.lock().unwrap() = g.clone();
        self.sink.save(&g).await;
    }

    fn set_status(&self, next: ConnStatus) {
        self.status.send_if_modified(|cur| {
            let changed = *cur != next;
            *cur = next;
            changed
        });
    }

    /// Replaces the session and points every poller at it.
    async fn reconnect(self: &Arc<Self>) {
        let old = self.session.lock().unwrap().take();
        if let Some(old) = old {
            tokio::spawn(async move { old.logout().await });
        }
        let g = self.global();
        let password = self
            .read_secret(&g, Secret::Password)
            .await
            .filter(|p| !p.is_empty());
        self.has_password.store(password.is_some(), SeqCst);
        let Some(password) = password.filter(|_| g.connection.is_complete()) else {
            return self.go_idle(ConnStatus::NotConfigured);
        };
        let transport = match (self.transports)(&g.connection) {
            Ok(t) => t,
            Err(e) => {
                let status = ConnStatus::from_error(&e)
                    .unwrap_or_else(|| ConnStatus::Unreachable(e.to_string()));
                return self.go_idle(status);
            }
        };
        let creds = Credentials {
            account: g.connection.account.trim().to_string(),
            password,
            did: self.read_secret(&g, Secret::Did).await,
            device_name: self.device_name.clone(),
        };
        let session = Arc::new(Session::new(transport, creds, self.did_listener()));
        *self.session.lock().unwrap() = Some(session.clone());
        self.set_status(ConnStatus::Connecting);
        for e in Endpoint::ALL {
            self.poller(e).set_fetch(Some(self.fetch_for(e, &session)));
        }
    }

    fn go_idle(&self, status: ConnStatus) {
        self.set_status(status);
        for e in Endpoint::ALL {
            self.poller(e).set_fetch(None);
        }
    }

    fn fetch_for(self: &Arc<Self>, e: Endpoint, session: &Arc<Session>) -> Fetch<Payload> {
        let this = Arc::downgrade(self);
        let session = session.clone();
        Arc::new(move || {
            let (this, session) = (this.clone(), session.clone());
            Box::pin(async move {
                let result = fetch_endpoint(&session, e).await;
                if let Some(s) = this.upgrade() {
                    s.observe(&session, &result);
                }
                result
            })
        })
    }

    /// Updates the connection status from a poll result - unless it came
    /// from a session that has since been replaced.
    fn observe(&self, session: &Arc<Session>, result: &Result<Payload, DsmError>) {
        let current = self
            .session
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|s| Arc::ptr_eq(s, session));
        if !current {
            return;
        }
        let next = match result {
            Ok(_) => ConnStatus::Connected {
                account: self.global().connection.account.trim().to_string(),
            },
            Err(e) => match ConnStatus::from_error(e) {
                Some(s) => s,
                None => return,
            },
        };
        self.set_status(next);
    }

    fn did_listener(self: &Arc<Self>) -> DidListener {
        let this = Arc::downgrade(self);
        Arc::new(move |did| {
            if let Some(s) = this.upgrade() {
                tokio::spawn(async move { s.store_did(did).await });
            }
        })
    }

    async fn store_did(&self, did: Option<String>) {
        let mut g = self.global();
        let before = g.clone();
        self.put_secret(&mut g, Secret::Did, did).await;
        if g != before {
            self.persist(g).await;
        }
    }

    fn secret_key(g: &GlobalSettings, which: Secret) -> String {
        let scope = g.connection.secret_scope();
        match which {
            Secret::Password => password_key(&scope),
            Secret::Did => did_key(&scope),
        }
    }

    async fn read_secret(&self, g: &GlobalSettings, which: Secret) -> Option<String> {
        let key = Self::secret_key(g, which);
        let store = self.secrets.clone();
        let from_keyring = tokio::task::spawn_blocking(move || store.get(&key))
            .await
            .ok()
            .and_then(Result::ok)
            .flatten();
        from_keyring.or_else(|| {
            let f = g.fallback_secrets.as_ref()?;
            match which {
                Secret::Password => f.password.clone(),
                Secret::Did => f.did.clone(),
            }
        })
    }

    /// Stores (or with `None`, deletes) a secret in the keyring, falling back
    /// to the settings file - with a warning - when there is no keyring.
    async fn put_secret(&self, g: &mut GlobalSettings, which: Secret, value: Option<String>) {
        let key = Self::secret_key(g, which);
        let store = self.secrets.clone();
        let v = value.clone();
        let result = tokio::task::spawn_blocking(move || store.set(&key, v.as_deref()))
            .await
            .unwrap_or_else(|e| Err(e.to_string()));
        let fallback = g
            .fallback_secrets
            .get_or_insert_with(FallbackSecrets::default);
        let slot = match which {
            Secret::Password => &mut fallback.password,
            Secret::Did => &mut fallback.did,
        };
        match result {
            Ok(()) => *slot = None,
            Err(e) => {
                log::warn!(
                    "no usable system keyring ({e}); keeping the {which:?} in OpenDeck's settings file"
                );
                *slot = value;
            }
        }
        if g.fallback_secrets == Some(FallbackSecrets::default()) {
            g.fallback_secrets = None;
        }
    }
}

pub async fn fetch_endpoint(session: &Session, e: Endpoint) -> Result<Payload, DsmError> {
    let (api, method) = match e {
        Endpoint::Utilization => (UTILIZATION, "get"),
        Endpoint::SystemInfo => (SYSTEM, "info"),
        Endpoint::Storage => (STORAGE, "load_info"),
        Endpoint::Update => (UPGRADE, "check"),
    };
    let data = session.call(api, method, &[]).await?;
    parse_payload(e, &data).map_err(|detail| DsmError::Parse {
        api: api.into(),
        detail,
    })
}

fn parse_payload(e: Endpoint, data: &Value) -> Result<Payload, String> {
    match e {
        Endpoint::Utilization => model::parse_utilization(data).map(Payload::Utilization),
        Endpoint::SystemInfo => model::parse_system_info(data).map(Payload::SystemInfo),
        Endpoint::Storage => model::parse_storage(data).map(Payload::Storage),
        Endpoint::Update => model::parse_update(data).map(Payload::Update),
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use crate::dsm::fake::FakeDsm;
    use crate::secrets::MemoryStore;
    use serde_json::json;

    #[derive(Default)]
    pub struct RecordingSink(pub Mutex<Vec<GlobalSettings>>);

    impl RecordingSink {
        pub fn last(&self) -> GlobalSettings {
            self.0
                .lock()
                .unwrap()
                .last()
                .cloned()
                .expect("nothing saved")
        }
    }

    #[async_trait]
    impl SettingsSink for RecordingSink {
        async fn save(&self, s: &GlobalSettings) {
            self.0.lock().unwrap().push(s.clone());
        }
    }

    pub fn services_with(
        fake: Arc<FakeDsm>,
        secrets: Arc<MemoryStore>,
    ) -> (Arc<Services>, Arc<RecordingSink>) {
        let sink = Arc::new(RecordingSink::default());
        let transports: TransportFactory =
            Arc::new(move |_| Ok(fake.clone() as Arc<dyn Transport>));
        (
            Services::new(secrets, sink.clone(), transports, "OpenDeck-test".into()),
            sink,
        )
    }

    fn fixture(name: &str) -> Value {
        let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// A NAS without 2FA that answers every endpoint from the fixtures.
    pub fn healthy_nas() -> Arc<FakeDsm> {
        FakeDsm::new(|r| match r.get("method").map(String::as_str) {
            Some("login") => Ok(json!({ "sid": "s1" })),
            Some("get") => Ok(fixture("utilization.json")),
            Some("info") => Ok(fixture("system.json")),
            Some("load_info") => Ok(fixture("storage.json")),
            Some("check") => Ok(fixture("update.json")),
            _ => Ok(json!({})),
        })
    }

    pub fn conn() -> Connection {
        Connection {
            host: "nas.lan".into(),
            account: "jf".into(),
            ..Connection::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::dsm::error::AuthError;
    use crate::dsm::fake::FakeDsm;
    use crate::secrets::{MemoryStore, did_key, password_key};
    use serde_json::json;
    use std::time::Duration;

    async fn wait_for(s: &Services, want: impl Fn(&ConnStatus) -> bool) {
        let mut rx = s.status();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if want(&rx.borrow_and_update()) {
                    return;
                }
                rx.changed().await.unwrap();
            }
        })
        .await
        .unwrap_or_else(|_| panic!("status stuck at {:?}", s.current_status()));
    }

    fn connected(s: &ConnStatus) -> bool {
        matches!(s, ConnStatus::Connected { .. })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn starts_unconfigured() {
        let (s, _) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        assert_eq!(s.current_status(), ConnStatus::NotConfigured);
        assert!(!s.has_password());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn saving_a_connection_keeps_the_password_out_of_the_settings_file() {
        let secrets = Arc::new(MemoryStore::default());
        let (s, sink) = services_with(healthy_nas(), secrets.clone());
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        assert_eq!(
            secrets.get(&password_key("jf@nas.lan")),
            Ok(Some("pw".into()))
        );
        assert_eq!(sink.last().fallback_secrets, None);
        assert!(s.has_password());
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
        assert!(s.poller(Endpoint::Utilization).latest().value.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn without_a_keyring_secrets_fall_back_to_the_settings_file() {
        let (s, sink) = services_with(healthy_nas(), Arc::new(MemoryStore::broken()));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        assert_eq!(
            sink.last().fallback_secrets.and_then(|f| f.password),
            Some("pw".into())
        );
        let _rx = s.poller(Endpoint::SystemInfo).subscribe("key-1", None);
        wait_for(&s, connected).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_new_host_drops_the_certificate_pin() {
        let (s, _) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        let g = GlobalSettings {
            connection: Connection {
                pinned_sha256: Some("ab".into()),
                ..conn()
            },
            ..GlobalSettings::default()
        };
        s.load_global(g).await;
        s.save_connection(conn(), None).await;
        assert_eq!(
            s.global().connection.pinned_sha256.as_deref(),
            Some("ab"),
            "same NAS keeps it"
        );
        s.save_connection(
            Connection {
                host: "other.lan".into(),
                ..conn()
            },
            None,
        )
        .await;
        assert_eq!(s.global().connection.pinned_sha256, None);
    }

    /// Refuses the certificate until one is pinned.
    struct UntrustedCert;
    #[async_trait]
    impl Transport for UntrustedCert {
        async fn call(&self, _: &str, _: &[(&str, &str)]) -> Result<Result<Value, i64>, DsmError> {
            Err(DsmError::CertificateNotTrusted {
                fingerprint: "ab".into(),
            })
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn trusting_the_certificate_pins_it_and_reconnects() {
        let sink = Arc::new(RecordingSink::default());
        let nas = healthy_nas();
        let transports: TransportFactory = Arc::new(move |c: &Connection| match c.pinned_sha256 {
            None => Ok(Arc::new(UntrustedCert) as Arc<dyn Transport>),
            Some(_) => Ok(nas.clone() as Arc<dyn Transport>),
        });
        let s = Services::new(
            Arc::new(MemoryStore::default()),
            sink.clone(),
            transports,
            "t".into(),
        );
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, |st| {
            matches!(st, ConnStatus::Certificate { changed: false, .. })
        })
        .await;
        s.trust_certificate().await;
        assert_eq!(sink.last().connection.pinned_sha256.as_deref(), Some("ab"));
        wait_for(&s, connected).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_2fa_code_connects_and_stores_the_device_token() {
        let nas =
            FakeDsm::new(
                |r| match (r.get("method").map(String::as_str), r.get("otp_code")) {
                    (Some("login"), Some(_)) => Ok(json!({ "sid": "s1", "did": "dev-1" })),
                    (Some("login"), None) => Err(403),
                    _ => Ok(serde_json::from_str(include_str!(
                        "../tests/fixtures/utilization.json"
                    ))
                    .unwrap()),
                },
            );
        let secrets = Arc::new(MemoryStore::default());
        let (s, _) = services_with(nas, secrets.clone());
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, |st| *st == ConnStatus::Auth(AuthError::NeedOtp)).await;
        s.submit_otp("123456").await.unwrap();
        wait_for(&s, connected).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while secrets.get(&did_key("jf@nas.lan")) != Ok(Some("dev-1".into())) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("device token stored in the keyring");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn changing_the_unit_saves_and_redraws() {
        let (s, sink) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        let mut rx = s.status();
        rx.borrow_and_update();
        s.set_temp_unit(TempUnit::Fahrenheit).await;
        assert_eq!(sink.last().temp_unit, TempUnit::Fahrenheit);
        assert!(
            rx.has_changed().unwrap(),
            "render loops are woken to redraw"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reloading_identical_settings_does_not_reconnect() {
        let nas = healthy_nas();
        let (s, _) = services_with(nas.clone(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
        s.load_global(s.global()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(nas.count("login"), 1);
    }
}
