//! The plugin's shared state: the connection settings, the one DSM
//! session, the four endpoint pollers every key and dial subscribes to, and
//! the connection status they all watch.
//!
//! One "connection epoch" ties it together: it moves on whenever the session
//! is replaced, and every late callback (a poll result, a new device token,
//! the firmware lookup) carries the epoch it was started in, so nothing from
//! an old connection lands on the new one.

use crate::dsm::api::{AUTH, INFO};
use crate::dsm::endpoint::Endpoint;
use crate::dsm::error::DsmError;
use crate::dsm::model::Payload;
use crate::dsm::session::{Credentials, DidListener, Session};
use crate::dsm::transport::{Target, Transport};
use crate::poller::{Fetch, Poller};
use crate::secrets::{Secret, SecretStore, StoreError, Stored, Vault};
use crate::settings::{Connection, GlobalSettings, TempUnit};
use crate::status::ConnStatus;
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// First wait before reading an unreadable keyring again; doubles per try.
const KEYRING_RETRY: Duration = if cfg!(test) {
    Duration::from_millis(20)
} else {
    Duration::from_secs(5)
};
/// Retries before waiting for the user (each read may show an unlock prompt).
const KEYRING_RETRIES: u32 = 5;
/// A keyring call taking longer than this is taken to wait on a prompt.
const KEYRING_PATIENCE: Duration = if cfg!(test) {
    Duration::from_millis(50)
} else {
    Duration::from_secs(2)
};

#[async_trait]
pub trait SettingsSink: Send + Sync {
    /// Persists the plugin-wide settings (OpenDeck's `setGlobalSettings`).
    async fn save(&self, settings: &GlobalSettings);
}

pub type TransportFactory =
    Arc<dyn Fn(&Target) -> Result<Arc<dyn Transport>, DsmError> + Send + Sync>;

pub fn target_for(conn: &Connection) -> Target {
    Target {
        base_url: conn.base_url(),
        https: conn.https,
        pinned_sha256: conn.pinned_sha256.clone(),
    }
}

pub struct Services {
    pollers: [Poller<Payload>; 4],
    global: Mutex<GlobalSettings>,
    /// Serialises keyring writes (and the settings changes recording their
    /// outcome), so secret writes never reorder against each other. Held
    /// across keyring calls, which may wait on a prompt for as long as the
    /// user takes. Lock order: `connecting`, then `secrets`, then `writing`.
    secrets: tokio::sync::Mutex<()>,
    /// Serialises read-modify-write of `global`, so no change puts back a
    /// stale snapshot. Never held across a keyring call: a secret write
    /// takes it only once the keyring answered, re-reads `global` and
    /// applies the outcome to that (`Vault::apply`). Taken after `secrets`.
    writing: tokio::sync::Mutex<()>,
    /// Serialises session swaps.
    connecting: tokio::sync::Mutex<()>,
    /// Settings from OpenDeck waiting to be applied, in order.
    inbox: OnceLock<mpsc::UnboundedSender<GlobalSettings>>,
    loaded: AtomicBool,
    session: Mutex<Option<Arc<Session>>>,
    epoch: AtomicU64,
    password: Mutex<Option<Stored>>,
    keyring_retries: AtomicU32,
    /// A key press is asking a refusing keyring again.
    asking_keyring: AtomicBool,
    /// Saves of the connection block in progress; each reconnects itself.
    saving: AtomicU32,
    /// The DSM version of the current connection, and the epoch it was
    /// looked up for.
    firmware: Mutex<Option<String>>,
    firmware_epoch: AtomicU64,
    status: watch::Sender<ConnStatus>,
    /// Display settings every key draws with; separate from the connection
    /// status so a unit change is not mistaken for a connection change.
    display: watch::Sender<TempUnit>,
    vault: Vault,
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
        Arc::new(Self {
            pollers: Endpoint::ALL.map(|e| Poller::new(e.default_interval())),
            global: Mutex::new(GlobalSettings::default()),
            secrets: tokio::sync::Mutex::new(()),
            writing: tokio::sync::Mutex::new(()),
            connecting: tokio::sync::Mutex::new(()),
            inbox: OnceLock::new(),
            loaded: AtomicBool::new(false),
            session: Mutex::new(None),
            epoch: AtomicU64::new(0),
            password: Mutex::new(None),
            keyring_retries: AtomicU32::new(0),
            asking_keyring: AtomicBool::new(false),
            saving: AtomicU32::new(0),
            firmware: Mutex::new(None),
            firmware_epoch: AtomicU64::new(0),
            // Until OpenDeck hands over the saved settings, keys show "…".
            status: watch::Sender::new(ConnStatus::Connecting),
            display: watch::Sender::new(TempUnit::default()),
            vault: Vault::new(secrets),
            sink,
            transports,
            device_name,
        })
    }

    pub fn poller(&self, e: Endpoint) -> &Poller<Payload> {
        &self.pollers[e.index()]
    }

    pub fn status(&self) -> watch::Receiver<ConnStatus> {
        self.status.subscribe()
    }

    pub fn display(&self) -> watch::Receiver<TempUnit> {
        self.display.subscribe()
    }

    pub fn current_status(&self) -> ConnStatus {
        self.status.borrow().clone()
    }

    pub fn global(&self) -> GlobalSettings {
        self.global.lock().unwrap().clone()
    }

    /// Where the current connection's password was found, if anywhere.
    pub fn password_stored(&self) -> Option<Stored> {
        *self.password.lock().unwrap()
    }

    pub fn has_password(&self) -> bool {
        self.password_stored().is_some()
    }

    /// A key press or dial tap on a key showing `e`: polls it now - or,
    /// after the keyring refused the password, asks the keyring again (in
    /// the background: it may wait on a prompt).
    pub fn refresh(self: &Arc<Self>, e: Endpoint) {
        if !matches!(self.current_status(), ConnStatus::KeyringRefused(_)) {
            return self.poller(e).refresh_now();
        }
        // A save in progress reconnects (and asks the keyring) itself.
        if self.saving.load(SeqCst) > 0 || self.asking_keyring.swap(true, SeqCst) {
            return;
        }
        let epoch = self.epoch.load(SeqCst);
        let this = self.clone();
        tokio::spawn(async move {
            let c = this.connecting.lock().await;
            // Skip it if anything reconnected or started saving meanwhile.
            if this.is_current(epoch)
                && this.saving.load(SeqCst) == 0
                && matches!(this.current_status(), ConnStatus::KeyringRefused(_))
            {
                this.reconnect_locked(c).await;
            }
            this.asking_keyring.store(false, SeqCst);
        });
    }

    /// The connected NAS's DSM version, once looked up.
    pub fn firmware(&self) -> Option<String> {
        self.firmware.lock().unwrap().clone()
    }

    /// Hands settings from OpenDeck over without waiting for them to be
    /// applied: openaction handles one event at a time, and applying them may
    /// wait on a keyring prompt, which would hold up every key and panel
    /// event meanwhile. They are still applied one after another, in order.
    pub fn receive_global(self: &Arc<Self>, g: GlobalSettings) {
        let inbox = self.inbox.get_or_init(|| {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let this = Arc::downgrade(self);
            tokio::spawn(async move {
                while let Some(g) = rx.recv().await {
                    let Some(s) = this.upgrade() else { return };
                    // Reconnecting may wait on a keyring prompt; the next
                    // settings must not queue behind it. Reconnects queue on
                    // `connecting` and each reads the settings afresh.
                    if s.adopt(g).await {
                        tokio::spawn(async move { s.reconnect().await });
                    }
                }
            });
            tx
        });
        // The receiver lives as long as `self`.
        let _ = inbox.send(g);
    }

    /// Adopts settings loaded from OpenDeck and waits for the reconnect, if
    /// any: what the inbox does, for tests that need it done.
    #[cfg(test)]
    pub async fn load_global(self: &Arc<Self>, g: GlobalSettings) {
        if self.adopt(g).await {
            self.reconnect().await;
        }
    }

    /// Adopts settings loaded from OpenDeck, at startup or when they
    /// change, and says whether the connection needs replacing: the first
    /// time, and after any change but the display unit's.
    async fn adopt(&self, g: GlobalSettings) -> bool {
        let same_connection = {
            let _w = self.writing.lock().await;
            let mut cur = self.global.lock().unwrap();
            let same = GlobalSettings {
                temp_unit: g.temp_unit,
                ..cur.clone()
            } == g;
            self.display.send_if_modified(|u| {
                let changed = *u != g.temp_unit;
                *u = g.temp_unit;
                changed
            });
            *cur = g;
            same
        };
        !(self.loaded.swap(true, SeqCst) && same_connection)
    }

    /// Saves the connection block of the settings panel. `password: None`
    /// keeps the stored password for the same account and NAS (scheme, host
    /// and port), while any other connection starts without one: a password
    /// saved for HTTPS is never sent over plain HTTP unless typed in again.
    pub async fn save_connection(self: &Arc<Self>, mut conn: Connection, password: Option<String>) {
        let _saving = Saving::start(&self.saving);
        {
            let _s = self.secrets.lock().await;
            // The new connection's password first: the keyring may wait on
            // a prompt, and nothing else waits for it meanwhile.
            let written = match password {
                Some(pw) => Some(
                    self.vault
                        .store(conn.secret_scope(), Secret::Password, Some(pw))
                        .await,
                ),
                None => None,
            };
            // Then the connection and where its password ended up, together.
            let _w = self.writing.lock().await;
            let mut g = self.global();
            // Another NAS has another certificate: the old pin must not carry over.
            conn.pinned_sha256 = if conn.same_nas(&g.connection) {
                g.connection.pinned_sha256.clone()
            } else {
                None
            };
            // Secrets that fell back to the settings file belong to the old
            // connection: never send them to, or file them under, a new one.
            if conn.secret_scope() != g.connection.secret_scope() {
                g.fallback_secrets = None;
            }
            g.connection = conn;
            if let Some(w) = written {
                self.vault.apply(&mut g, w);
            }
            self.persist(g).await;
        }
        self.reconnect().await;
    }

    pub async fn set_temp_unit(self: &Arc<Self>, unit: TempUnit) {
        let _w = self.writing.lock().await;
        let mut g = self.global();
        g.temp_unit = unit;
        self.persist(g).await;
        self.display.send_replace(unit);
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
                if matches!(self.current_status(), ConnStatus::Auth(_)) {
                    self.set_status(ConnStatus::Connecting);
                }
                for e in Endpoint::ALL {
                    // The keys' "Login" error is solved; don't show it
                    // until the next poll lands.
                    self.poller(e).clear_error();
                    self.poller(e).refresh_now();
                }
            }
            Err(e) => {
                if let Some(s) = ConnStatus::from_error(e) {
                    self.set_status(s);
                }
                if !matches!(e, DsmError::Auth(_)) {
                    // The session still wants a code; let the (paused)
                    // pollers report that, so the 2FA box comes back.
                    for e in Endpoint::ALL {
                        self.poller(e).refresh_now();
                    }
                }
            }
        }
        result
    }

    /// Pins `fingerprint` - the certificate the user compared - if it is the
    /// one the NAS is presenting now. Anything else (the certificate changed
    /// again since the panel showed it) pins nothing. Returns whether it did.
    pub async fn trust_certificate(self: &Arc<Self>, fingerprint: &str) -> bool {
        let ConnStatus::Certificate {
            fingerprint: current,
            ..
        } = self.current_status()
        else {
            return false;
        };
        if !current.eq_ignore_ascii_case(fingerprint.trim()) {
            log::warn!("not trusting a certificate: the NAS now presents a different one");
            return false;
        }
        {
            let _w = self.writing.lock().await;
            let mut g = self.global();
            g.connection.pinned_sha256 = Some(current);
            self.persist(g).await;
        }
        self.reconnect().await;
        true
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

    fn is_current(&self, epoch: u64) -> bool {
        self.epoch.load(SeqCst) == epoch
    }

    /// Replaces the session and points every poller at it.
    async fn reconnect(self: &Arc<Self>) {
        let c = self.connecting.lock().await;
        self.reconnect_locked(c).await;
    }

    /// `reconnect`, for a caller already holding `connecting`.
    async fn reconnect_locked(self: &Arc<Self>, _c: tokio::sync::MutexGuard<'_, ()>) {
        let old = self.session.lock().unwrap().take();
        let epoch = self.epoch.fetch_add(1, SeqCst) + 1;
        *self.firmware.lock().unwrap() = None;
        self.connect(epoch).await;
        // Only now that no poller uses the old session can it be logged out:
        // a poller still on it would just log it in again.
        if let Some(old) = old {
            tokio::spawn(async move { old.logout().await });
        }
    }

    /// Makes a session for the current settings and gives every poller a
    /// new fetch (`None` when it can't connect).
    async fn connect(self: &Arc<Self>, epoch: u64) {
        let g = self
            .keyring_step(async {
                let _s = self.secrets.lock().await;
                let moved = self.vault.migrate(&self.global()).await;
                let _w = self.writing.lock().await;
                let mut g = self.global();
                let before = g.clone();
                for w in moved {
                    self.vault.apply(&mut g, w);
                }
                if g != before {
                    self.persist(g.clone()).await;
                }
                g
            })
            .await;
        if !g.connection.is_complete() {
            *self.password.lock().unwrap() = None;
            return self.go_idle(ConnStatus::NotConfigured);
        }
        let password = match self
            .keyring_step(self.vault.read(&g, Secret::Password))
            .await
        {
            Ok(Some((p, stored))) if !p.is_empty() => {
                *self.password.lock().unwrap() = Some(stored);
                self.keyring_retries.store(0, SeqCst);
                p
            }
            Ok(_) => {
                *self.password.lock().unwrap() = None;
                return self.go_idle(ConnStatus::NotConfigured);
            }
            Err(StoreError::Refused(e)) => {
                // Asking again by itself would show the prompt again and
                // train the user to allow it: wait for a key press or a save.
                log::warn!("the system keyring refused to hand over the password: {e}");
                *self.password.lock().unwrap() = None;
                return self.go_idle(ConnStatus::KeyringRefused(e));
            }
            Err(StoreError::Unavailable(e)) => {
                // Not "no password": the keyring may well hold it.
                log::warn!("can't read the password from the system keyring: {e}");
                *self.password.lock().unwrap() = None;
                self.go_idle(ConnStatus::Keyring(e));
                return self.retry_keyring_later(epoch);
            }
        };
        let target = target_for(&g.connection);
        let transport = match (self.transports)(&target) {
            Ok(t) => t,
            Err(e) => {
                let status = ConnStatus::from_error(&e)
                    .unwrap_or_else(|| ConnStatus::Unreachable(e.to_string()));
                return self.go_idle(status);
            }
        };
        // Over plain HTTP no device token is sent or asked for.
        let did = if g.connection.https {
            self.keyring_step(self.vault.read(&g, Secret::Did))
                .await
                .unwrap_or_else(|e| {
                    log::warn!("can't read the 2FA device token from the system keyring: {e}");
                    None
                })
                .map(|(d, _)| d)
        } else {
            None
        };
        let creds = Credentials {
            account: g.connection.account.trim().to_string(),
            password,
            did,
            device_name: self.device_name.clone(),
            remember_device: g.connection.https,
        };
        let session = Arc::new(Session::new(transport, creds, self.did_listener(epoch)));
        *self.session.lock().unwrap() = Some(session.clone());
        self.set_status(ConnStatus::Connecting);
        for e in Endpoint::ALL {
            self.poller(e)
                .set_fetch(Some(self.fetch_for(e, &session, epoch)));
        }
    }

    /// Awaits a step that calls the keyring. If it takes long - a prompt
    /// waiting for the user - keys and panel say so, and nothing polls the
    /// old session meanwhile; the step's outcome then sets the status.
    async fn keyring_step<T>(&self, step: impl Future<Output = T>) -> T {
        let mut step = std::pin::pin!(step);
        if let Ok(v) = tokio::time::timeout(KEYRING_PATIENCE, step.as_mut()).await {
            return v;
        }
        log::info!("waiting for the system keyring (an access or unlock prompt?)");
        self.go_idle(ConnStatus::KeyringPending);
        step.await
    }

    /// Reads the keyring again after a while (it may not have been up yet,
    /// e.g. right after login), a few times before leaving it to the user.
    fn retry_keyring_later(self: &Arc<Self>, epoch: u64) {
        let attempt = self.keyring_retries.fetch_add(1, SeqCst);
        if attempt >= KEYRING_RETRIES {
            return;
        }
        let this = Arc::downgrade(self);
        let delay = KEYRING_RETRY.saturating_mul(1 << attempt);
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            if let Some(s) = this.upgrade()
                && s.is_current(epoch)
                && matches!(s.current_status(), ConnStatus::Keyring(_))
            {
                s.reconnect().await;
            }
        });
    }

    fn go_idle(&self, status: ConnStatus) {
        self.set_status(status);
        for e in Endpoint::ALL {
            self.poller(e).set_fetch(None);
        }
    }

    fn fetch_for(
        self: &Arc<Self>,
        e: Endpoint,
        session: &Arc<Session>,
        epoch: u64,
    ) -> Fetch<Payload> {
        let this = Arc::downgrade(self);
        let session = session.clone();
        Arc::new(move || {
            let (this, session) = (this.clone(), session.clone());
            Box::pin(async move {
                let result = e.fetch(&session).await;
                if let Some(s) = this.upgrade() {
                    s.observe(epoch, &session, &result);
                }
                result
            })
        })
    }

    /// Updates the connection status from a poll result - unless it came
    /// from a connection that has since been replaced.
    fn observe(
        self: &Arc<Self>,
        epoch: u64,
        session: &Arc<Session>,
        result: &Result<Payload, DsmError>,
    ) {
        if !self.is_current(epoch) {
            return;
        }
        let next = match result {
            Ok(_) => self.connected(),
            // DSM answered an endpoint call with a working session, e.g. an
            // account without admin rights (every endpoint says 105).
            Err(e) if endpoint_answered(e) => self.connected(),
            Err(e) => match ConnStatus::from_error(e) {
                Some(s) => s,
                None => return,
            },
        };
        if matches!(next, ConnStatus::Connected { .. }) {
            self.look_up_firmware(epoch, session);
        }
        self.set_status(next);
    }

    fn connected(&self) -> ConnStatus {
        ConnStatus::Connected {
            account: self.global().connection.account.trim().to_string(),
        }
    }

    /// The DSM version belongs to the connection, not to whichever keys are
    /// on screen: look it up once per connection.
    fn look_up_firmware(self: &Arc<Self>, epoch: u64, session: &Arc<Session>) {
        if self.firmware_epoch.swap(epoch, SeqCst) == epoch {
            return;
        }
        let (this, session) = (Arc::downgrade(self), session.clone());
        tokio::spawn(async move {
            let Ok(Payload::SystemInfo(info)) = Endpoint::SystemInfo.fetch(&session).await else {
                return;
            };
            if let Some(s) = this.upgrade()
                && s.is_current(epoch)
            {
                *s.firmware.lock().unwrap() = info.firmware;
            }
        });
    }

    /// `epoch` is the connection the session was made for: a device token
    /// arriving after the settings moved on is dropped.
    fn did_listener(self: &Arc<Self>, epoch: u64) -> DidListener {
        let this = Arc::downgrade(self);
        Arc::new(move |did| {
            if let Some(s) = this.upgrade() {
                tokio::spawn(async move { s.store_did(epoch, did).await });
            }
        })
    }

    async fn store_did(&self, epoch: u64, did: Option<String>) {
        let _s = self.secrets.lock().await;
        if !self.is_current(epoch) {
            return;
        }
        let scope = self.global().connection.secret_scope();
        let written = self.vault.store(scope, Secret::Did, did).await;
        let _w = self.writing.lock().await;
        let mut g = self.global();
        let before = g.clone();
        self.vault.apply(&mut g, written);
        if g != before {
            self.persist(g).await;
        }
    }
}

/// Counts a save in progress for as long as it lives.
struct Saving<'a>(&'a AtomicU32);

impl<'a> Saving<'a> {
    fn start(n: &'a AtomicU32) -> Self {
        n.fetch_add(1, SeqCst);
        Self(n)
    }
}

impl Drop for Saving<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, SeqCst);
    }
}

/// An error from a data endpoint itself, which proves the login worked -
/// unlike one from logging in (`SYNO.API.Auth`) or API discovery.
fn endpoint_answered(e: &DsmError) -> bool {
    match e {
        DsmError::Permission { .. } => true,
        DsmError::Api { api, .. } | DsmError::Parse { api, .. } => api != AUTH && api != INFO,
        _ => false,
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use crate::dsm::fake::{FakeDsm, fixture};
    use crate::poller::PollState;
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
        let transports: TransportFactory =
            Arc::new(move |_| Ok(fake.clone() as Arc<dyn Transport>));
        services_over(transports, secrets)
    }

    pub fn services_over(
        transports: TransportFactory,
        secrets: Arc<MemoryStore>,
    ) -> (Arc<Services>, Arc<RecordingSink>) {
        let sink = Arc::new(RecordingSink::default());
        (
            Services::new(secrets, sink.clone(), transports, "OpenDeck-test".into()),
            sink,
        )
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

    /// Waits (up to 5 s) until the poller has delivered a value.
    pub async fn wait_for_value(rx: &mut watch::Receiver<PollState<Payload>>) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while rx.borrow_and_update().value.is_none() {
                rx.changed().await.unwrap();
            }
        })
        .await
        .expect("the poller never delivered a value");
    }

    /// Waits (up to 5 s) until `check` holds, polling every 10 ms.
    pub async fn eventually(what: &str, check: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !check() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("never happened: {what}"));
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::dsm::error::AuthError;
    use crate::dsm::fake::{Drops, FakeDsm, Req, fixture};
    use crate::secrets::{MemoryStore, did_key, password_key};
    use crate::settings::FallbackSecrets;
    use serde_json::{Value, json};

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

    fn http_conn() -> Connection {
        Connection {
            https: false,
            port: 5000,
            ..conn()
        }
    }

    fn scope() -> String {
        conn().secret_scope()
    }

    /// A NAS that wants a 2FA code unless it gets device token `dev-1`.
    fn nas_with_2fa() -> Arc<FakeDsm> {
        FakeDsm::new(|r| {
            match (
                r.get("method").map(String::as_str),
                r.get("otp_code"),
                r.get("device_id").map(String::as_str),
            ) {
                (Some("login"), Some(_), _) => Ok(json!({ "sid": "s1", "did": "dev-1" })),
                (Some("login"), None, Some("dev-1")) => Ok(json!({ "sid": "s1" })),
                (Some("login"), None, _) => Err(403),
                _ => Ok(fixture("utilization.json")),
            }
        })
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
        assert_eq!(secrets.get(&password_key(&scope())), Ok(Some("pw".into())));
        assert_eq!(sink.last().fallback_secrets, None);
        assert_eq!(s.password_stored(), Some(Stored::Keyring));
        let mut rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
        // The status is published before the poller's value: wait for it.
        wait_for_value(&mut rx).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn without_a_keyring_the_password_falls_back_to_the_settings_file() {
        let (s, sink) = services_with(healthy_nas(), Arc::new(MemoryStore::broken()));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        assert_eq!(
            sink.last().fallback_secrets.and_then(|f| f.password),
            Some("pw".into())
        );
        assert_eq!(
            s.password_stored(),
            Some(Stored::SettingsFile),
            "the panel can say where it really is"
        );
        let _rx = s.poller(Endpoint::SystemInfo).subscribe("key-1", None);
        wait_for(&s, connected).await;
    }

    /// Every settings snapshot handed to OpenDeck, none with a password.
    fn assert_no_password_saved(sink: &RecordingSink) {
        let saved = sink.0.lock().unwrap();
        assert!(!saved.is_empty(), "something was saved");
        for g in saved.iter() {
            assert_eq!(
                g.fallback_secrets.as_ref().and_then(|f| f.password.clone()),
                None,
                "a refused keyring put the password in the settings file"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_refused_keyring_keeps_the_password_in_memory_not_the_settings_file() {
        let (s, sink) = services_with(healthy_nas(), Arc::new(MemoryStore::refusing(&[])));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        assert_no_password_saved(&sink);
        assert_eq!(
            s.password_stored(),
            Some(Stored::Memory),
            "the panel can say where it really is"
        );
        // Still usable for this run.
        let _rx = s.poller(Endpoint::SystemInfo).subscribe("key-1", None);
        wait_for(&s, connected).await;
        s.reconnect().await;
        wait_for(&s, connected).await;
        assert_eq!(s.password_stored(), Some(Stored::Memory));
        assert_no_password_saved(&sink);
    }

    fn with_file_password(pw: &str) -> GlobalSettings {
        GlobalSettings {
            connection: conn(),
            fallback_secrets: Some(FallbackSecrets {
                password: Some(pw.into()),
                scope: Some(scope()),
                ..FallbackSecrets::default()
            }),
            ..GlobalSettings::default()
        }
    }

    fn last_login_password(nas: &FakeDsm) -> Option<String> {
        nas.requests()
            .into_iter()
            .rev()
            .find(|r| r.get("method").map(String::as_str) == Some("login"))
            .and_then(|r| r.get("passwd").cloned())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_refused_new_password_beats_the_old_one_still_in_the_keyring() {
        // The keyring holds "old"; the user saves "new" and dismisses the
        // prompt, then unlocks the keyring at the next prompt.
        let key = password_key(&scope());
        let secrets = Arc::new(MemoryStore::refusing(&[(&key, "old")]));
        let nas = healthy_nas();
        let (s, _) = services_with(nas.clone(), secrets.clone());
        s.load_global(GlobalSettings {
            connection: conn(),
            ..GlobalSettings::default()
        })
        .await;
        s.save_connection(conn(), Some("new".into())).await;
        assert_eq!(s.password_stored(), Some(Stored::Memory));
        secrets.set_refusing(false);
        let reads = secrets.reads_of(&key);
        s.reconnect().await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
        assert_eq!(
            last_login_password(&nas).as_deref(),
            Some("new"),
            "signed in with the replaced password"
        );
        assert_eq!(s.password_stored(), Some(Stored::Memory));
        assert_eq!(secrets.reads_of(&key), reads, "no second keyring prompt");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_settings_file_password_beats_an_older_one_in_a_read_only_keyring() {
        // The keyring still reads "old" but won't take writes, so the new
        // password lands in the settings file: that copy is the newer one.
        let key = password_key(&scope());
        let secrets = Arc::new(MemoryStore::read_only(&[(&key, "old")]));
        let nas = healthy_nas();
        let (s, sink) = services_with(nas.clone(), secrets.clone());
        s.load_global(GlobalSettings {
            connection: conn(),
            ..GlobalSettings::default()
        })
        .await;
        s.save_connection(conn(), Some("new".into())).await;
        assert_eq!(
            sink.last().fallback_secrets.and_then(|f| f.password),
            Some("new".into())
        );
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
        assert_eq!(
            last_login_password(&nas).as_deref(),
            Some("new"),
            "signed in with the password the keyring still held"
        );
        assert_eq!(s.password_stored(), Some(Stored::SettingsFile));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_legacy_keyring_entry_never_replaces_a_refused_new_password() {
        let secrets = Arc::new(MemoryStore::refusing(&[("jf@nas.lan/password", "old")]));
        let nas = healthy_nas();
        let (s, _) = services_with(nas.clone(), secrets.clone());
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("new".into())).await;
        secrets.set_refusing(false);
        s.reconnect().await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
        assert_eq!(last_login_password(&nas).as_deref(), Some("new"));
        assert_eq!(
            secrets.keys(),
            ["jf@nas.lan/password"],
            "the old password is not filed under the new scope"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_key_press_during_a_save_does_not_reconnect_twice() {
        let secrets = Arc::new(
            MemoryStore::refusing(&[(&password_key(&scope()), "pw")])
                .with_write_delay(Duration::from_millis(300)),
        );
        let (s, _) = services_with(healthy_nas(), secrets.clone());
        s.load_global(GlobalSettings {
            connection: conn(),
            ..GlobalSettings::default()
        })
        .await;
        assert!(matches!(s.current_status(), ConnStatus::KeyringRefused(_)));
        let before = s.epoch.load(SeqCst);
        let save = {
            let s = s.clone();
            tokio::spawn(async move { s.save_connection(conn(), Some("new".into())).await })
        };
        // While the save waits on the keyring prompt, the user presses a key.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(matches!(s.current_status(), ConnStatus::KeyringRefused(_)));
        s.refresh(Endpoint::Utilization);
        save.await.unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            s.epoch.load(SeqCst),
            before + 1,
            "one reconnect, the save's"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_refused_write_drops_an_older_settings_file_copy() {
        // Saved to the file while there was no keyring; now there is one,
        // and the user denies it the newly typed password.
        let nas = healthy_nas();
        let (s, sink) = services_with(nas.clone(), Arc::new(MemoryStore::refusing(&[])));
        s.load_global(with_file_password("old")).await;
        s.save_connection(conn(), Some("new".into())).await;
        assert_eq!(s.password_stored(), Some(Stored::Memory));
        assert_eq!(
            sink.last().fallback_secrets.and_then(|f| f.password),
            None,
            "neither the new password nor the stale one stays in the file"
        );
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
        let last = nas
            .requests()
            .into_iter()
            .rev()
            .find(|r| r.get("method").map(String::as_str) == Some("login"))
            .unwrap();
        assert_eq!(last.get("passwd").map(String::as_str), Some("new"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_refused_move_into_the_keyring_leaves_the_settings_file_copy() {
        // Moving it out of the file would lose the only copy kept across
        // restarts on a dismissed prompt; it is tried again next time.
        let (s, sink) = services_with(healthy_nas(), Arc::new(MemoryStore::refusing(&[])));
        s.load_global(with_file_password("pw")).await;
        assert_eq!(s.password_stored(), Some(Stored::SettingsFile));
        assert!(
            sink.0.lock().unwrap().iter().all(|g| g
                .fallback_secrets
                .as_ref()
                .and_then(|f| f.password.as_deref())
                == Some("pw")),
            "never dropped from the file"
        );
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
    }

    /// The memory copy follows the same scope rule as everything else.
    async fn requests_after_leaving_a_memory_password(
        next: Connection,
    ) -> (Arc<Services>, Vec<Req>) {
        let nas = healthy_nas();
        let (s, _) = services_with(nas.clone(), Arc::new(MemoryStore::refusing(&[])));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
        assert_eq!(s.password_stored(), Some(Stored::Memory));
        assert_ne!(next.secret_scope(), scope(), "the test must change scope");
        let before = nas.requests().len();
        s.save_connection(next, None).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        (s, nas.requests().split_off(before))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_memory_password_never_goes_to_another_nas_port_or_scheme() {
        for next in [
            Connection {
                host: "other.lan".into(),
                ..conn()
            },
            Connection {
                port: conn().port + 1,
                ..conn()
            },
            Connection {
                account: "someone-else".into(),
                ..conn()
            },
            http_conn(),
        ] {
            let (s, after) = requests_after_leaving_a_memory_password(next.clone()).await;
            assert!(
                after.iter().all(|r| r.get("passwd").is_none()),
                "the password went to {next:?}"
            );
            assert!(!s.has_password(), "{next:?} has no password of its own");
            // And the original connection still has it.
            s.save_connection(conn(), None).await;
            wait_for(&s, connected).await;
            assert_eq!(s.password_stored(), Some(Stored::Memory));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_refused_read_is_not_retried_until_a_key_press() {
        let secrets = Arc::new(MemoryStore::refusing(&[(&password_key(&scope()), "pw")]));
        let (s, _) = services_with(healthy_nas(), secrets.clone());
        s.load_global(GlobalSettings {
            connection: conn(),
            ..GlobalSettings::default()
        })
        .await;
        assert!(
            matches!(s.current_status(), ConnStatus::KeyringRefused(_)),
            "{:?}",
            s.current_status()
        );
        assert!(!s.has_password());
        let _k = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        let reads = secrets.reads();
        // Longer than every automatic retry would take (20+40+80+160+320 ms).
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(secrets.reads(), reads, "no prompt shown again by itself");
        assert!(matches!(s.current_status(), ConnStatus::KeyringRefused(_)));
        // The user presses a key and allows access this time.
        secrets.set_refusing(false);
        s.refresh(Endpoint::Utilization);
        wait_for(&s, connected).await;
        assert_eq!(s.password_stored(), Some(Stored::Keyring));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn saving_after_a_refused_read_asks_the_keyring_again() {
        let secrets = Arc::new(MemoryStore::refusing(&[(&password_key(&scope()), "pw")]));
        let (s, _) = services_with(healthy_nas(), secrets.clone());
        s.load_global(GlobalSettings {
            connection: conn(),
            ..GlobalSettings::default()
        })
        .await;
        assert!(matches!(s.current_status(), ConnStatus::KeyringRefused(_)));
        secrets.set_refusing(false);
        let _k = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        s.save_connection(conn(), None).await;
        wait_for(&s, connected).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn without_a_keyring_the_device_token_stays_out_of_the_settings_file() {
        let nas = nas_with_2fa();
        let (s, sink) = services_with(nas.clone(), Arc::new(MemoryStore::broken()));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, |st| *st == ConnStatus::Auth(AuthError::NeedOtp)).await;
        s.submit_otp("123456").await.unwrap();
        wait_for(&s, connected).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        for saved in sink.0.lock().unwrap().iter() {
            assert_eq!(
                saved.fallback_secrets.as_ref().and_then(|f| f.did.clone()),
                None,
                "password + device token in plain text would get past 2FA"
            );
        }
        // Still remembered for this run: a reconnect needs no new code.
        let logins = nas.count("login");
        s.reconnect().await;
        wait_for(&s, connected).await;
        let last = nas
            .requests()
            .into_iter()
            .rev()
            .find(|r| r.get("method").map(String::as_str) == Some("login"))
            .unwrap();
        assert!(nas.count("login") > logins);
        assert_eq!(last.get("device_id").map(String::as_str), Some("dev-1"));
    }

    /// Signs in to `conn()` with 2FA and no keyring, so device token `dev-1`
    /// lives only in memory, then saves `next` and returns every request the
    /// NAS saw after the switch. Waits for either outcome, so a leak fails
    /// the caller's assertion instead of timing out on `NeedOtp`.
    async fn requests_after_leaving_a_memory_device_token(next: Connection) -> Vec<Req> {
        let nas = nas_with_2fa();
        let (s, _) = services_with(nas.clone(), Arc::new(MemoryStore::broken()));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, |st| *st == ConnStatus::Auth(AuthError::NeedOtp)).await;
        s.submit_otp("123456").await.unwrap();
        wait_for(&s, connected).await;
        assert_ne!(next.secret_scope(), scope(), "the test must change scope");
        let before = nas.requests().len();
        s.save_connection(next, Some("pw".into())).await;
        wait_for(&s, |st| {
            *st == ConnStatus::Auth(AuthError::NeedOtp) || connected(st)
        })
        .await;
        nas.requests().split_off(before)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_memory_device_token_never_goes_to_another_nas() {
        let next = Connection {
            host: "other.lan".into(),
            ..conn()
        };
        let after = requests_after_leaving_a_memory_device_token(next).await;
        assert!(
            after
                .iter()
                .any(|r| r.get("method").map(String::as_str) == Some("login"))
        );
        assert!(
            after.iter().all(|r| r.get("device_id").is_none()),
            "NAS A's device token went to NAS B"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_memory_device_token_never_goes_to_another_port_on_the_same_host() {
        // Still HTTPS, so only the scope check can stop it.
        let next = Connection {
            port: conn().port + 1,
            ..conn()
        };
        assert!(next.https);
        let after = requests_after_leaving_a_memory_device_token(next).await;
        assert!(
            after
                .iter()
                .any(|r| r.get("method").map(String::as_str) == Some("login"))
        );
        assert!(
            after.iter().all(|r| r.get("device_id").is_none()),
            "the device token went to another port's DSM"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_device_token_already_in_the_settings_file_leaves_it() {
        let nas = nas_with_2fa();
        let (s, sink) = services_with(nas.clone(), Arc::new(MemoryStore::broken()));
        let g = GlobalSettings {
            connection: conn(),
            fallback_secrets: Some(FallbackSecrets {
                password: Some("pw".into()),
                did: Some("dev-1".into()),
                scope: Some("jf@nas.lan".into()),
            }),
            ..GlobalSettings::default()
        };
        s.load_global(g).await;
        let f = sink.last().fallback_secrets.unwrap();
        assert_eq!((f.password.as_deref(), f.did), (Some("pw"), None));
        assert_eq!(f.scope, Some(scope()), "re-filed under the new scope");
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
        assert_eq!(nas.count("login"), 1, "the token still worked this run");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fallback_secrets_move_into_the_keyring_once_it_works() {
        let secrets = Arc::new(MemoryStore::default());
        let (s, sink) = services_with(healthy_nas(), secrets.clone());
        let g = GlobalSettings {
            connection: conn(),
            fallback_secrets: Some(FallbackSecrets {
                password: Some("pw".into()),
                ..FallbackSecrets::default()
            }),
            ..GlobalSettings::default()
        };
        s.load_global(g).await;
        assert_eq!(secrets.get(&password_key(&scope())), Ok(Some("pw".into())));
        assert_eq!(sink.last().fallback_secrets, None);
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn keyring_entries_from_before_v0_3_move_to_the_https_scope() {
        let secrets = Arc::new(MemoryStore::default());
        secrets.set("jf@nas.lan/password", Some("pw")).unwrap();
        secrets.set("jf@nas.lan/did", Some("dev-1")).unwrap();
        let nas = nas_with_2fa();
        let (s, _) = services_with(nas.clone(), secrets.clone());
        s.load_global(GlobalSettings {
            connection: conn(),
            ..GlobalSettings::default()
        })
        .await;
        assert_eq!(
            secrets.keys(),
            [did_key(&scope()), password_key(&scope())],
            "moved, not copied"
        );
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
        assert_eq!(nas.count("login"), 1, "no 2FA code needed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn secrets_from_before_v0_3_are_never_sent_over_plain_http() {
        let secrets = Arc::new(MemoryStore::default());
        secrets.set("jf@nas.lan/password", Some("pw")).unwrap();
        let nas = healthy_nas();
        let (s, _) = services_with(nas.clone(), secrets.clone());
        s.load_global(GlobalSettings {
            connection: http_conn(),
            fallback_secrets: Some(FallbackSecrets {
                password: Some("pw2".into()),
                ..FallbackSecrets::default()
            }),
            ..GlobalSettings::default()
        })
        .await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(s.current_status(), ConnStatus::NotConfigured);
        assert_eq!(nas.count("login"), 0);
        assert_eq!(
            secrets.keys(),
            ["jf@nas.lan/password"],
            "left for HTTPS to pick up"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn switching_to_http_never_sends_the_saved_password() {
        let nas = healthy_nas();
        let targets = Arc::new(Mutex::new(Vec::<Target>::new()));
        let (t, n) = (targets.clone(), nas.clone());
        let transports: TransportFactory = Arc::new(move |target: &Target| {
            t.lock().unwrap().push(target.clone());
            Ok(n.clone() as Arc<dyn Transport>)
        });
        let (s, _) = services_over(transports, Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
        let logins = nas.count("login");
        // Untick HTTPS and save with the password field left empty.
        s.save_connection(http_conn(), None).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(s.current_status(), ConnStatus::NotConfigured);
        assert!(!s.has_password(), "the panel asks for the password again");
        assert_eq!(nas.count("login"), logins, "nothing sent in the clear");
        assert!(targets.lock().unwrap().iter().all(|t| t.https));
        // Typing it in again is an explicit choice to send it unencrypted.
        s.save_connection(http_conn(), Some("pw".into())).await;
        wait_for(&s, connected).await;
        // And HTTPS still has its own.
        s.save_connection(conn(), None).await;
        wait_for(&s, connected).await;
        assert_eq!(s.password_stored(), Some(Stored::Keyring));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn over_http_no_device_token_is_sent_or_stored() {
        let secrets = Arc::new(MemoryStore::default());
        secrets
            .set(&did_key(&http_conn().secret_scope()), Some("dev-1"))
            .unwrap();
        let nas = nas_with_2fa();
        let (s, _) = services_with(nas.clone(), secrets.clone());
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(http_conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, |st| *st == ConnStatus::Auth(AuthError::NeedOtp)).await;
        s.submit_otp("123456").await.unwrap();
        wait_for(&s, connected).await;
        for r in nas.requests() {
            assert_eq!(r.get("device_id"), None, "{r:?}");
            assert_eq!(r.get("enable_device_token"), None, "{r:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unreadable_keyring_is_not_mistaken_for_no_password() {
        let secrets = Arc::new(MemoryStore::unreadable(&[(&password_key(&scope()), "pw")]));
        let (s, _) = services_with(healthy_nas(), secrets.clone());
        let mut rx = s.status();
        s.load_global(GlobalSettings {
            connection: conn(),
            ..GlobalSettings::default()
        })
        .await;
        assert!(
            matches!(s.current_status(), ConnStatus::Keyring(_)),
            "{:?}",
            s.current_status()
        );
        assert_ne!(*rx.borrow_and_update(), ConnStatus::NotConfigured);
        let _k = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        // Read again a little later, when the keyring is up.
        secrets.set_readable(true);
        wait_for(&s, connected).await;
        assert_eq!(s.password_stored(), Some(Stored::Keyring));
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

    #[tokio::test(flavor = "multi_thread")]
    async fn a_new_host_never_gets_the_old_hosts_fallback_secrets() {
        let nas = healthy_nas();
        let (s, sink) = services_with(nas.clone(), Arc::new(MemoryStore::broken()));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        assert!(s.has_password());
        let logins_before = nas.count("login");
        s.save_connection(
            Connection {
                host: "other.lan".into(),
                ..conn()
            },
            None,
        )
        .await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!s.has_password(), "other.lan has no password of its own");
        assert!(
            matches!(s.current_status(), ConnStatus::Keyring(_)),
            "no keyring and nothing in the settings file: {:?}",
            s.current_status()
        );
        assert_eq!(
            nas.count("login"),
            logins_before,
            "nothing sent to other.lan"
        );
        assert_eq!(
            sink.last().fallback_secrets.and_then(|f| f.password),
            None,
            "the old host's password is not filed under the new one"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_device_token_arriving_after_a_reconnect_is_dropped() {
        let secrets = Arc::new(MemoryStore::default());
        let (s, _) = services_with(healthy_nas(), secrets.clone());
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let old_epoch = s.epoch.load(SeqCst);
        let other = Connection {
            host: "other.lan".into(),
            ..conn()
        };
        s.save_connection(other.clone(), Some("pw2".into())).await;
        s.store_did(old_epoch, Some("dev-old".into())).await;
        assert_eq!(secrets.get(&did_key(&other.secret_scope())), Ok(None));
        assert_eq!(secrets.get(&did_key(&scope())), Ok(None));
    }

    /// Refuses the certificate until one is pinned.
    struct UntrustedCert(&'static str);
    #[async_trait]
    impl Transport for UntrustedCert {
        async fn call(&self, _: &str, _: &[(&str, &str)]) -> Result<Result<Value, i64>, DsmError> {
            Err(DsmError::CertificateNotTrusted {
                fingerprint: self.0.into(),
            })
        }
    }

    fn cert_then_nas(nas: Arc<FakeDsm>) -> TransportFactory {
        Arc::new(move |t: &Target| match t.pinned_sha256 {
            None => Ok(Arc::new(UntrustedCert("ab")) as Arc<dyn Transport>),
            Some(_) => Ok(nas.clone() as Arc<dyn Transport>),
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn trusting_the_certificate_pins_it_and_reconnects() {
        let (s, sink) = services_over(
            cert_then_nas(healthy_nas()),
            Arc::new(MemoryStore::default()),
        );
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, |st| {
            matches!(st, ConnStatus::Certificate { changed: false, .. })
        })
        .await;
        assert!(s.trust_certificate("AB").await);
        assert_eq!(sink.last().connection.pinned_sha256.as_deref(), Some("ab"));
        wait_for(&s, connected).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn only_the_fingerprint_the_user_saw_is_trusted() {
        let (s, sink) = services_over(
            cert_then_nas(healthy_nas()),
            Arc::new(MemoryStore::default()),
        );
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, |st| matches!(st, ConnStatus::Certificate { .. })).await;
        let saves = sink.0.lock().unwrap().len();
        assert!(
            !s.trust_certificate("cd").await,
            "the NAS presents another certificate by now"
        );
        assert_eq!(sink.0.lock().unwrap().len(), saves, "nothing pinned");
        assert_eq!(s.global().connection.pinned_sha256, None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_2fa_code_connects_and_stores_the_device_token() {
        let secrets = Arc::new(MemoryStore::default());
        let (s, _) = services_with(nas_with_2fa(), secrets.clone());
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, |st| *st == ConnStatus::Auth(AuthError::NeedOtp)).await;
        s.submit_otp("123456").await.unwrap();
        wait_for(&s, connected).await;
        eventually("device token stored in the keyring", || {
            secrets.get(&did_key(&scope())) == Ok(Some("dev-1".into()))
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_account_without_permissions_still_counts_as_connected() {
        let nas = FakeDsm::new(|r| match r.get("method").map(String::as_str) {
            Some("login") => Ok(json!({ "sid": "s1" })),
            _ => Err(105),
        });
        let (s, _) = services_with(nas, Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Storage).subscribe("key-1", None);
        wait_for(&s, connected).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_lost_2fa_submit_asks_for_the_code_again() {
        let nas = FakeDsm::new(|r| match r.get("method").map(String::as_str) {
            Some("login") => Err(403),
            _ => Ok(json!({})),
        });
        let transports: TransportFactory =
            Arc::new(move |_| Ok(Arc::new(Drops(nas.clone(), "otp_code")) as Arc<dyn Transport>));
        let (s, _) = services_over(transports, Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        let need_otp = |st: &ConnStatus| *st == ConnStatus::Auth(AuthError::NeedOtp);
        wait_for(&s, need_otp).await;
        assert!(s.submit_otp("123456").await.is_err());
        wait_for(&s, need_otp).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_good_2fa_code_clears_the_keys_login_error_at_once() {
        let nas =
            FakeDsm::new(
                |r| match (r.get("method").map(String::as_str), r.get("otp_code")) {
                    (Some("login"), Some(_)) => Ok(json!({ "sid": "s1", "did": "dev-1" })),
                    (Some("login"), None) => Err(403),
                    _ => {
                        // A slow NAS: the next poll can't land before the check.
                        std::thread::sleep(Duration::from_millis(300));
                        Ok(json!({}))
                    }
                },
            );
        let (s, _) = services_with(nas, Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let mut rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, |st| *st == ConnStatus::Auth(AuthError::NeedOtp)).await;
        // The status is published just before the poller stores its error.
        tokio::time::timeout(Duration::from_secs(5), async {
            while rx.borrow_and_update().error.is_none() {
                rx.changed().await.unwrap();
            }
        })
        .await
        .expect("the poller never reported the login error");
        s.submit_otp("123456").await.unwrap();
        let st = s.poller(Endpoint::Utilization).latest();
        assert_eq!((st.error, st.failures), (None, 0), "no red \"Login\" key");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn changing_the_unit_saves_and_redraws_without_a_status_change() {
        let (s, sink) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        let mut status = s.status();
        let mut display = s.display();
        status.borrow_and_update();
        display.borrow_and_update();
        s.set_temp_unit(TempUnit::Fahrenheit).await;
        assert_eq!(sink.last().temp_unit, TempUnit::Fahrenheit);
        assert!(
            display.has_changed().unwrap(),
            "render loops are woken to redraw"
        );
        assert_eq!(*display.borrow(), TempUnit::Fahrenheit);
        assert!(
            !status.has_changed().unwrap(),
            "the connection status didn't change"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_unit_change_during_a_slow_keyring_write_is_not_lost() {
        let secrets = Arc::new(MemoryStore::slow_writes(Duration::from_millis(200)));
        let (s, sink) = services_with(healthy_nas(), secrets);
        s.load_global(GlobalSettings::default()).await;
        let saving = {
            let s = s.clone();
            tokio::spawn(async move { s.save_connection(conn(), Some("pw".into())).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        s.set_temp_unit(TempUnit::Fahrenheit).await;
        saving.await.unwrap();
        let last = sink.last();
        assert_eq!(last.temp_unit, TempUnit::Fahrenheit);
        assert_eq!(last.connection.host, "nas.lan");
    }

    /// Waits (up to 500 ms) until `check` holds: what a keyring prompt must
    /// not hold up.
    async fn promptly(what: &str, check: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_millis(500), async {
            while !check() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("waited for the keyring: {what}"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn set_temp_unit_does_not_wait_for_a_keyring_write() {
        let secrets = Arc::new(MemoryStore::slow_writes(Duration::from_millis(1500)));
        let (s, sink) = services_with(healthy_nas(), secrets);
        s.load_global(GlobalSettings::default()).await;
        let saving = {
            let s = s.clone();
            tokio::spawn(async move { s.save_connection(conn(), Some("pw".into())).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::time::timeout(
            Duration::from_millis(500),
            s.set_temp_unit(TempUnit::Fahrenheit),
        )
        .await
        .expect("the unit change waited for the keyring write");
        assert_eq!(sink.last().temp_unit, TempUnit::Fahrenheit);
        assert_eq!(*s.display().borrow(), TempUnit::Fahrenheit);
        saving.await.unwrap();
        let last = sink.last();
        assert_eq!(last.temp_unit, TempUnit::Fahrenheit);
        assert_eq!(last.connection.host, "nas.lan");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_unit_change_from_opendeck_does_not_wait_for_a_keyring_write() {
        let secrets = Arc::new(MemoryStore::slow_writes(Duration::from_millis(1500)));
        let (s, sink) = services_with(healthy_nas(), secrets);
        s.load_global(GlobalSettings::default()).await;
        let saving = {
            let s = s.clone();
            tokio::spawn(async move { s.save_connection(conn(), Some("pw".into())).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let unit_only = GlobalSettings {
            temp_unit: TempUnit::Fahrenheit,
            ..s.global()
        };
        tokio::time::timeout(Duration::from_millis(500), s.load_global(unit_only))
            .await
            .expect("the settings change waited for the keyring write");
        assert_eq!(*s.display().borrow(), TempUnit::Fahrenheit);
        saving.await.unwrap();
        let last = sink.last();
        assert_eq!(last.temp_unit, TempUnit::Fahrenheit, "not put back");
        assert_eq!(last.connection.host, "nas.lan");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn opendeck_settings_do_not_queue_behind_a_keyring_prompt() {
        // Startup: reading the keyring waits on its access prompt.
        let secrets = Arc::new(MemoryStore::gated(&[(&password_key(&scope()), "pw")]));
        let (s, _) = services_with(healthy_nas(), secrets.clone());
        let _k = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        let first = GlobalSettings {
            connection: conn(),
            ..GlobalSettings::default()
        };
        s.receive_global(first.clone());
        wait_for(&s, |st| *st == ConnStatus::KeyringPending).await;
        let second = GlobalSettings {
            temp_unit: TempUnit::Fahrenheit,
            ..first
        };
        s.receive_global(second.clone());
        promptly("a unit change from OpenDeck", || {
            s.global() == second && *s.display().borrow() == TempUnit::Fahrenheit
        })
        .await;
        secrets.open_gate();
        wait_for(&s, connected).await;
        assert_eq!(s.global(), second);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn trusting_a_certificate_does_not_wait_for_a_keyring_write() {
        let secrets = Arc::new(MemoryStore::slow_writes(Duration::from_millis(1000)));
        let (s, sink) = services_over(cert_then_nas(healthy_nas()), secrets.clone());
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, |st| {
            matches!(st, ConnStatus::Certificate { changed: false, .. })
        })
        .await;
        // The user types a new password, then trusts the certificate while
        // the keyring still takes the password.
        let saving = {
            let s = s.clone();
            tokio::spawn(async move { s.save_connection(conn(), Some("pw2".into())).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let trusting = {
            let s = s.clone();
            tokio::spawn(async move { s.trust_certificate("AB").await })
        };
        promptly("the pin is saved", || {
            sink.last().connection.pinned_sha256.as_deref() == Some("ab")
        })
        .await;
        assert!(trusting.await.unwrap());
        saving.await.unwrap();
        assert_eq!(
            sink.last().connection.pinned_sha256.as_deref(),
            Some("ab"),
            "the save kept the pin"
        );
        assert_eq!(secrets.get(&password_key(&scope())), Ok(Some("pw2".into())));
        wait_for(&s, connected).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn secret_writes_and_other_changes_never_save_a_stale_snapshot() {
        let secrets = Arc::new(MemoryStore::slow_writes(Duration::from_millis(150)));
        let (s, sink) = services_with(healthy_nas(), secrets.clone());
        s.load_global(GlobalSettings::default()).await;
        let other = Connection {
            host: "other.lan".into(),
            ..conn()
        };
        let a = {
            let s = s.clone();
            tokio::spawn(async move { s.save_connection(conn(), Some("pw-a".into())).await })
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        s.set_temp_unit(TempUnit::Fahrenheit).await;
        let b = {
            let (s, other) = (s.clone(), other.clone());
            tokio::spawn(async move { s.save_connection(other, Some("pw-b".into())).await })
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        s.set_temp_unit(TempUnit::Fahrenheit).await;
        a.await.unwrap();
        b.await.unwrap();

        let saved = sink.0.lock().unwrap().clone();
        let f = saved
            .iter()
            .position(|g| g.temp_unit == TempUnit::Fahrenheit)
            .expect("the unit was saved");
        for (i, g) in saved.iter().enumerate().skip(f) {
            assert_eq!(g.temp_unit, TempUnit::Fahrenheit, "save {i} put °C back");
        }
        let first_a = saved
            .iter()
            .position(|g| g.connection.host == "nas.lan")
            .expect("save A landed");
        let first_b = saved
            .iter()
            .position(|g| g.connection.host == "other.lan")
            .expect("save B landed");
        assert!(first_a < first_b, "the saves landed in order");
        for (i, g) in saved.iter().enumerate().skip(first_b) {
            assert_eq!(g.connection.host, "other.lan", "save {i} put A back");
        }
        assert_eq!(
            secrets.get(&password_key(&scope())),
            Ok(Some("pw-a".into()))
        );
        assert_eq!(
            secrets.get(&password_key(&other.secret_scope())),
            Ok(Some("pw-b".into()))
        );
        assert_eq!(s.global().connection.host, "other.lan");
        assert_eq!(s.global().temp_unit, TempUnit::Fahrenheit);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_secret_write_for_a_connection_left_meanwhile_files_nothing_under_the_new_one() {
        // No keyring, and a slow one: moving the file password "into the
        // keyring" fails only after the settings switched to another NAS.
        let secrets = Arc::new(MemoryStore::broken().with_write_delay(Duration::from_millis(300)));
        let (s, sink) = services_with(healthy_nas(), secrets);
        let first = {
            let s = s.clone();
            tokio::spawn(async move { s.load_global(with_file_password("pw")).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        let other = GlobalSettings {
            connection: Connection {
                host: "other.lan".into(),
                ..conn()
            },
            ..GlobalSettings::default()
        };
        s.load_global(other.clone()).await;
        first.await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        for g in sink.0.lock().unwrap().iter() {
            if g.connection.host == "other.lan" {
                assert_eq!(
                    g.fallback_secrets, None,
                    "nas.lan's password went to other.lan"
                );
            }
        }
        assert_eq!(s.global(), other);
        assert!(!s.has_password(), "other.lan has no password of its own");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_device_token_stored_while_the_connection_changes_leaves_the_new_ones_file_alone() {
        // No keyring, and a slow one: the token's write fails only after
        // OpenDeck switched the settings to another NAS with its own file
        // password.
        let secrets = Arc::new(MemoryStore::broken().with_write_delay(Duration::from_millis(300)));
        let (s, sink) = services_with(healthy_nas(), secrets);
        s.load_global(with_file_password("pw")).await;
        let epoch = s.epoch.load(SeqCst);
        let storing = {
            let s = s.clone();
            tokio::spawn(async move { s.store_did(epoch, Some("dev-1".into())).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let other = Connection {
            host: "other.lan".into(),
            ..conn()
        };
        let next = GlobalSettings {
            connection: other.clone(),
            fallback_secrets: Some(FallbackSecrets {
                password: Some("pw-other".into()),
                scope: Some(other.secret_scope()),
                ..FallbackSecrets::default()
            }),
            ..GlobalSettings::default()
        };
        s.load_global(next.clone()).await;
        storing.await.unwrap();
        for g in sink.0.lock().unwrap().iter() {
            if g.connection.host == "other.lan" {
                assert_eq!(g.fallback_secrets, next.fallback_secrets, "re-filed");
            }
        }
        assert_eq!(s.global(), next);
        assert_eq!(s.password_stored(), Some(Stored::SettingsFile));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_file_password_replaced_while_it_moves_to_the_keyring_is_not_lost() {
        let secrets = Arc::new(MemoryStore::slow_writes(Duration::from_millis(300)));
        let nas = healthy_nas();
        let (s, _) = services_with(nas.clone(), secrets.clone());
        let first = {
            let s = s.clone();
            tokio::spawn(async move { s.load_global(with_file_password("old")).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        // OpenDeck hands over a newer file password meanwhile.
        s.load_global(with_file_password("new")).await;
        first.await.unwrap();
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
        assert_eq!(secrets.get(&password_key(&scope())), Ok(Some("new".into())));
        assert_eq!(last_login_password(&nas).as_deref(), Some("new"));
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

    /// Hands out sids s1, s2, ... and records every logout.
    fn counting_nas() -> Arc<FakeDsm> {
        let n = Arc::new(AtomicU32::new(0));
        FakeDsm::new(move |r| match r.get("method").map(String::as_str) {
            Some("login") => Ok(json!({ "sid": format!("s{}", n.fetch_add(1, SeqCst) + 1) })),
            Some("logout") => Ok(json!({})),
            _ => Ok(fixture("utilization.json")),
        })
    }

    fn logouts(nas: &FakeDsm) -> Vec<String> {
        nas.requests()
            .into_iter()
            .filter(|r| r.get("method").map(String::as_str) == Some("logout"))
            .filter_map(|r| r.get("_sid").cloned())
            .collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_new_connection_logs_the_old_session_out_once() {
        let nas = counting_nas();
        let (s, _) = services_with(nas.clone(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let mut rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for_value(&mut rx).await;
        s.save_connection(
            Connection {
                account: "admin".into(),
                ..conn()
            },
            Some("pw".into()),
        )
        .await;
        wait_for_value(&mut rx).await;
        eventually("the old session is logged out", || logouts(&nas) == ["s1"]).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(logouts(&nas), ["s1"], "once, and never the new one");
        assert_eq!(nas.count("login"), 2, "the old session wasn't revived");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_late_answer_from_the_old_connection_leaves_the_status_alone() {
        // The old NAS answers the storage poll slowly, and then not at all.
        let old = FakeDsm::new(|r| match r.get("method").map(String::as_str) {
            Some("login") => Ok(json!({ "sid": "s1" })),
            Some("load_info") => {
                std::thread::sleep(Duration::from_millis(300));
                Ok(json!({}))
            }
            _ => Ok(fixture("utilization.json")),
        });
        let old: Arc<dyn Transport> = Arc::new(LateFailure(old));
        // The new NAS is fine, but slow to answer its own storage poll.
        let new = FakeDsm::new(|r| match r.get("method").map(String::as_str) {
            Some("login") => Ok(json!({ "sid": "s1" })),
            Some("load_info") => {
                std::thread::sleep(Duration::from_millis(1500));
                Ok(fixture("storage.json"))
            }
            _ => Ok(fixture("utilization.json")),
        });
        let transports: TransportFactory = Arc::new(move |t: &Target| {
            if t.base_url.contains("old.lan") {
                Ok(old.clone())
            } else {
                Ok(new.clone() as Arc<dyn Transport>)
            }
        });
        let (s, _) = services_over(transports, Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        let old_conn = Connection {
            host: "old.lan".into(),
            ..conn()
        };
        s.save_connection(old_conn, Some("pw".into())).await;
        let _storage = s.poller(Endpoint::Storage).subscribe("key-1", None);
        let _cpu = s.poller(Endpoint::Utilization).subscribe("key-2", None);
        tokio::time::sleep(Duration::from_millis(100)).await;
        s.save_connection(conn(), Some("pw".into())).await;
        wait_for(&s, connected).await;
        // The old storage request fails at ~300 ms, while the new one is
        // still running.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(connected(&s.current_status()), "{:?}", s.current_status());
    }

    /// Turns the storage calls of a slow NAS into a network failure (after
    /// it took its time), as if the old NAS dropped off.
    struct LateFailure(Arc<FakeDsm>);
    #[async_trait]
    impl Transport for LateFailure {
        async fn call(&self, p: &str, f: &[(&str, &str)]) -> Result<Result<Value, i64>, DsmError> {
            let r = self.0.call(p, f).await;
            if f.contains(&("method", "load_info")) {
                return Err(DsmError::Transport("old NAS gone".into()));
            }
            r
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_dsm_version_is_known_without_a_system_key_on_screen() {
        let (s, _) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
        eventually("firmware looked up", || s.firmware().is_some()).await;
        assert_eq!(s.firmware().as_deref(), Some("DSM 7.2.2-72806 Update 3"));
        s.save_connection(
            Connection {
                host: "other.lan".into(),
                ..conn()
            },
            None,
        )
        .await;
        assert_eq!(s.firmware(), None, "it belonged to the old connection");
    }
}
