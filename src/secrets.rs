//! Where the password and the 2FA device token live: the system keyring
//! (Secret Service on Linux, the login Keychain on macOS), keeping them out
//! of OpenDeck's plain-JSON settings file.
//!
//! `Vault` adds the fallbacks for when the keyring can't be used:
//! - with no keyring at all (e.g. OpenDeck as a Flatpak without access to
//!   it) the password goes to the settings file - which the settings panel
//!   then says;
//! - when a keyring is there but refuses (a denied or dismissed prompt, a
//!   locked collection) the password is kept in memory for this run only:
//!   the user said no, so it never lands unencrypted in a file;
//! - the device token is kept in memory only either way, since password and
//!   token together would get past 2FA.

use crate::settings::{FallbackSecrets, GlobalSettings};
use std::sync::{Arc, Mutex};

pub const SERVICE: &str = "com.jfms7s.synology";

/// Blocking key-value secret storage. Call through `spawn_blocking`.
pub trait SecretStore: Send + Sync {
    /// `Ok(None)`: no such secret.
    fn get(&self, key: &str) -> Result<Option<String>, StoreError>;
    /// `None` deletes (deleting a missing secret is not an error).
    fn set(&self, key: &str, value: Option<&str>) -> Result<(), StoreError>;
}

/// Why the keyring could not be used. The text is the keyring's own error
/// message, which never holds the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// There is no usable keyring at all: no Secret Service on the bus (a
    /// Flatpak, no keyring daemon), or no keychain on macOS.
    Unavailable(String),
    /// A keyring is there but did not let the plugin in: a denied or
    /// cancelled access prompt, a dismissed unlock prompt, a locked
    /// collection.
    Refused(String),
}

#[cfg(test)]
impl StoreError {
    pub fn is_refused(&self) -> bool {
        matches!(self, Self::Refused(_))
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(m) | Self::Refused(m) => f.write_str(m),
        }
    }
}

/// Sorts a keyring error into "no keyring here" and "the keyring said no".
/// The `keyring` crate maps the same situations differently per OS:
/// - Secret Service (Linux): a dismissed prompt or a locked collection is
///   `NoStorageAccess`; "Secret Service not on the bus" (Flatpak, no
///   daemon) and every other D-Bus failure is `PlatformFailure`.
/// - macOS: only a missing, read-only or invalid keychain is
///   `NoStorageAccess`; a denied or cancelled access prompt is
///   `PlatformFailure`.
///
/// Anything not known to mean "no keyring" counts as a refusal, so a
/// password never lands in the settings file by mistake.
pub fn classify(e: keyring::Error, macos: bool) -> StoreError {
    let msg = e.to_string();
    match (e, macos) {
        (keyring::Error::NoStorageAccess(_), true)
        | (keyring::Error::PlatformFailure(_), false) => StoreError::Unavailable(msg),
        _ => StoreError::Refused(msg),
    }
}

pub fn password_key(scope: &str) -> String {
    format!("{scope}/password")
}

pub fn did_key(scope: &str) -> String {
    format!("{scope}/did")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secret {
    Password,
    Did,
}

impl Secret {
    fn key(self, scope: &str) -> String {
        match self {
            Self::Password => password_key(scope),
            Self::Did => did_key(scope),
        }
    }

    fn memory(self, v: &Vault) -> &Mutex<Option<(String, String)>> {
        match self {
            Self::Password => &v.memory_password,
            Self::Did => &v.memory_did,
        }
    }

    fn slot(self, f: &mut FallbackSecrets) -> &mut Option<String> {
        match self {
            Self::Password => &mut f.password,
            Self::Did => &mut f.did,
        }
    }
}

/// Where a secret was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stored {
    Keyring,
    /// OpenDeck's plain-JSON settings file (no usable keyring).
    SettingsFile,
    /// This process's memory only: a device token without a keyring, or a
    /// password the keyring refused.
    Memory,
}

impl Stored {
    /// The settings panel's name for it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Keyring => "keyring",
            Self::SettingsFile => "settingsFile",
            Self::Memory => "memory",
        }
    }
}

/// Whether OpenDeck (and so this plugin) runs inside a Flatpak sandbox,
/// which has no keyring access unless the user grants it.
pub fn in_flatpak() -> bool {
    std::env::var_os("FLATPAK_ID").is_some() || std::path::Path::new("/.flatpak-info").exists()
}

pub struct Vault {
    store: Arc<dyn SecretStore>,
    /// (scope, device token) when the keyring couldn't take it.
    memory_did: Mutex<Option<(String, String)>>,
    /// (scope, password) when the keyring refused it.
    memory_password: Mutex<Option<(String, String)>>,
}

impl Vault {
    pub fn new(store: Arc<dyn SecretStore>) -> Self {
        Self {
            store,
            memory_did: Mutex::new(None),
            memory_password: Mutex::new(None),
        }
    }

    // A keyring call that panicked proves nothing about the keyring being
    // absent: count it as a refusal, which never writes the settings file.
    async fn get(&self, key: String) -> Result<Option<String>, StoreError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || store.get(&key))
            .await
            .unwrap_or_else(|e| Err(StoreError::Refused(e.to_string())))
    }

    async fn set(&self, key: String, value: Option<String>) -> Result<(), StoreError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || store.set(&key, value.as_deref()))
            .await
            .unwrap_or_else(|e| Err(StoreError::Refused(e.to_string())))
    }

    /// The settings-file secrets, if they belong to the current connection.
    pub fn fallback_for(g: &GlobalSettings) -> Option<&FallbackSecrets> {
        g.fallback_secrets
            .as_ref()
            .filter(|f| f.belongs_to(&g.connection))
    }

    /// The memory copy of a secret, if it belongs to `scope`.
    fn in_memory(&self, which: Secret, scope: &str) -> Option<String> {
        which
            .memory(self)
            .lock()
            .unwrap()
            .as_ref()
            .filter(|(s, _)| s == scope)
            .map(|(_, v)| v.clone())
    }

    /// A secret for the current connection and where it was found, looked
    /// up memory first, then the settings file, then the keyring: the
    /// fallbacks only exist when a newer keyring write failed. `Err` only
    /// when the keyring failed and no fallback has it - which is not the
    /// same as "no password saved".
    pub async fn read(
        &self,
        g: &GlobalSettings,
        which: Secret,
    ) -> Result<Option<(String, Stored)>, StoreError> {
        let scope = g.connection.secret_scope();
        // A memory copy or a settings-file copy is always newer than the
        // keyring's: each exists only because a later keyring write failed,
        // and a write that succeeds clears both, so the keyring may still
        // hold the value they replaced. Asking the keyring first would also
        // show its prompt again.
        if let Some(v) = self.in_memory(which, &scope) {
            return Ok(Some((v, Stored::Memory)));
        }
        let fallback = Self::fallback_for(g)
            .cloned()
            .and_then(|mut f| which.slot(&mut f).take());
        if let Some(v) = fallback {
            return Ok(Some((v, Stored::SettingsFile)));
        }
        match self.get(which.key(&scope)).await {
            Ok(Some(v)) => Ok(Some((v, Stored::Keyring))),
            other => other.map(|_| None),
        }
    }

    /// Stores (or with `None`, deletes) a secret in the keyring, falling
    /// back - with a warning - when it can't: the password to the settings
    /// file only when there is no keyring at all, and to memory when the
    /// keyring refused it; the device token to memory either way.
    /// `store` and then `apply`, for a caller that owns `g` throughout.
    #[cfg(test)]
    pub async fn write(&self, g: &mut GlobalSettings, which: Secret, value: Option<String>) {
        let written = self.store(g.connection.secret_scope(), which, value).await;
        self.apply(g, written);
    }

    /// The keyring half of `write`: stores (or deletes) the secret for
    /// `scope` and returns the outcome for `apply`. Touches no settings, so
    /// it can wait on a keyring prompt without holding them.
    pub async fn store(&self, scope: String, which: Secret, value: Option<String>) -> Written {
        let result = self.set(which.key(&scope), value.clone()).await;
        Written {
            scope,
            which,
            value,
            result,
            from_file: false,
        }
    }

    /// The bookkeeping half of `write`: records where the secret ended up
    /// (the settings-file copy in `g`, the memory copy). If `g` moved on to
    /// another connection while the keyring call ran, nothing is filed
    /// under the new one; a move out of the settings file applies only if
    /// the file still holds the value that was moved.
    pub fn apply(&self, g: &mut GlobalSettings, w: Written) {
        let Written {
            scope,
            which,
            value,
            result,
            from_file,
        } = w;
        let memory = which.memory(self);
        if g.connection.secret_scope() != scope {
            log::info!("the connection changed while the keyring stored the {which:?}");
            // The keyring now holds the newest value for that connection.
            if result.is_ok() && self.in_memory(which, &scope).is_some() {
                *memory.lock().unwrap() = None;
            }
            return;
        }
        if from_file
            && Self::fallback_for(g)
                .cloned()
                .and_then(|mut f| which.slot(&mut f).take())
                != value
        {
            log::info!("the settings file changed while its {which:?} moved to the keyring");
            return;
        }
        if Self::fallback_for(g).is_none() {
            // Nothing there, or another connection's secrets: start afresh.
            g.fallback_secrets = None;
        }
        let fallback = g
            .fallback_secrets
            .get_or_insert_with(FallbackSecrets::default);
        fallback.scope = Some(scope.clone());
        let slot = which.slot(fallback);
        *memory.lock().unwrap() = None;
        match (result, which) {
            (Ok(()), _) => *slot = None,
            // Moving a file password: on a refusal it stays in the file, the
            // only copy that outlives a restart.
            (Err(StoreError::Refused(_)), Secret::Password) if from_file => {}
            (Err(e @ StoreError::Refused(_)), Secret::Password) => {
                log::warn!(
                    "the system keyring refused the password ({e}); keeping it in memory only until OpenDeck restarts"
                );
                *slot = None;
                *memory.lock().unwrap() = value.map(|v| (scope, v));
            }
            (Err(e @ StoreError::Unavailable(_)), Secret::Password) => {
                log::warn!(
                    "no usable system keyring ({e}); keeping the password in OpenDeck's settings file"
                );
                *slot = value;
            }
            (Err(e), Secret::Did) => {
                log::warn!(
                    "can't store the 2FA device token in the system keyring ({e}); it is kept in memory only, so a code is asked for again after a restart"
                );
                *slot = None;
                *memory.lock().unwrap() = value.map(|v| (scope, v));
            }
        }
        if g.fallback_secrets
            .as_ref()
            .is_some_and(|f| f.password.is_none() && f.did.is_none())
        {
            g.fallback_secrets = None;
        }
    }

    /// Brings stored secrets up to date for the connection in `g`, a
    /// snapshot of the settings:
    /// - secrets that fell back to the settings file move into the keyring
    ///   if it works now (a device token never stays in the file; a
    ///   password the keyring refuses stays where it is, the only copy that
    ///   outlives a restart);
    /// - keyring entries filed under the pre-0.3 `account@host` scope move
    ///   to this connection's scope - for an HTTPS connection only, since
    ///   they may have been saved for HTTPS.
    ///
    /// Only calls the keyring: the returned moves out of the settings file
    /// go to `apply`, against the settings as they are by then.
    pub async fn migrate(&self, g: &GlobalSettings) -> Vec<Written> {
        let scope = g.connection.secret_scope();
        let fallback = Self::fallback_for(g).cloned().unwrap_or_default();
        let mut moved = Vec::new();
        for (which, value) in [
            (Secret::Password, fallback.password),
            (Secret::Did, fallback.did),
        ] {
            if let Some(v) = value {
                let w = self.store(scope.clone(), which, Some(v)).await;
                moved.push(Written {
                    from_file: true,
                    ..w
                });
            }
        }
        if !g.connection.https {
            return moved;
        }
        let legacy = g.connection.legacy_secret_scope();
        for which in [Secret::Password, Secret::Did] {
            let (new_key, old_key) = (which.key(&scope), which.key(&legacy));
            // A memory copy replaced whatever the old entry holds.
            if self.in_memory(which, &scope).is_some()
                || self.get(new_key.clone()).await != Ok(None)
            {
                continue;
            }
            let Ok(Some(v)) = self.get(old_key.clone()).await else {
                continue;
            };
            if self.set(new_key, Some(v)).await.is_ok() {
                let _ = self.set(old_key, None).await;
                log::info!("moved the saved {which:?} to the new keyring entry name");
            }
        }
        moved
    }
}

/// A finished keyring write, waiting for `Vault::apply` to record where the
/// secret ended up. `Debug` leaves the value out.
pub struct Written {
    scope: String,
    which: Secret,
    value: Option<String>,
    result: Result<(), StoreError>,
    /// Moves a settings-file copy into the keyring.
    from_file: bool,
}

impl std::fmt::Debug for Written {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Written")
            .field("scope", &self.scope)
            .field("which", &self.which)
            .field("result", &self.result)
            .field("from_file", &self.from_file)
            .finish_non_exhaustive()
    }
}

pub struct KeyringStore;

fn keyring_error(e: keyring::Error) -> StoreError {
    classify(e, cfg!(target_os = "macos"))
}

impl SecretStore for KeyringStore {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        let entry = keyring::Entry::new(SERVICE, key).map_err(keyring_error)?;
        match entry.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(keyring_error(e)),
        }
    }

    fn set(&self, key: &str, value: Option<&str>) -> Result<(), StoreError> {
        let entry = keyring::Entry::new(SERVICE, key).map_err(keyring_error)?;
        match value {
            Some(v) => entry.set_password(v).map_err(keyring_error),
            None => match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(keyring_error(e)),
            },
        }
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct MemoryStore {
    map: std::sync::Mutex<std::collections::HashMap<String, String>>,
    broken: bool,
    /// Reads work but writes fail as "no keyring" (a Secret Service that
    /// denies creating items).
    read_only: bool,
    /// Reads fail while set (Secret Service not up yet, a locked collection,
    /// a denied Keychain prompt).
    unreadable: std::sync::atomic::AtomicBool,
    /// How long each write takes.
    write_delay: std::time::Duration,
    /// While closed, reads wait (an access or unlock prompt nobody has
    /// answered yet).
    gate: Gate,
    /// Reads and writes are refused while set (a denied Keychain prompt, a
    /// dismissed unlock prompt).
    refusing: std::sync::atomic::AtomicBool,
    /// The keys of every read attempted so far, refused ones included.
    reads: std::sync::Mutex<Vec<String>>,
}

/// Holds keyring reads until opened.
#[cfg(test)]
#[derive(Default)]
struct Gate {
    closed: std::sync::Mutex<bool>,
    opened: std::sync::Condvar,
}

#[cfg(test)]
impl MemoryStore {
    /// Behaves like a machine without a usable keyring.
    pub fn broken() -> Self {
        Self {
            broken: true,
            ..Self::default()
        }
    }

    /// A keyring that holds `entries` but can't be read until
    /// `set_readable(true)` (Secret Service not on D-Bus yet, a locked
    /// collection, a denied Keychain prompt).
    pub fn unreadable(entries: &[(&str, &str)]) -> Self {
        let s = Self {
            unreadable: true.into(),
            ..Self::default()
        };
        for (k, v) in entries {
            s.map.lock().unwrap().insert(k.to_string(), v.to_string());
        }
        s
    }

    /// A keyring that holds `entries` but whose reads wait until
    /// `open_gate()` - like macOS waiting on its Keychain access prompt.
    pub fn gated(entries: &[(&str, &str)]) -> Self {
        let s = Self::default();
        *s.gate.closed.lock().unwrap() = true;
        for (k, v) in entries {
            s.map.lock().unwrap().insert(k.to_string(), v.to_string());
        }
        s
    }

    /// Answers the prompt: waiting and later reads go through.
    pub fn open_gate(&self) {
        *self.gate.closed.lock().unwrap() = false;
        self.gate.opened.notify_all();
    }

    /// A keyring that holds `entries` and reads them, but whose writes fail
    /// as unavailable, so a new password lands in the settings file.
    pub fn read_only(entries: &[(&str, &str)]) -> Self {
        let s = Self {
            read_only: true,
            ..Self::default()
        };
        for (k, v) in entries {
            s.map.lock().unwrap().insert(k.to_string(), v.to_string());
        }
        s
    }

    /// A keyring that holds `entries` but refuses every read and write until
    /// `set_refusing(false)` - the user denying the access prompt.
    pub fn refusing(entries: &[(&str, &str)]) -> Self {
        let s = Self {
            refusing: true.into(),
            ..Self::default()
        };
        for (k, v) in entries {
            s.map.lock().unwrap().insert(k.to_string(), v.to_string());
        }
        s
    }

    pub fn set_refusing(&self, refusing: bool) {
        self.refusing
            .store(refusing, std::sync::atomic::Ordering::SeqCst);
    }

    /// How many reads were attempted, refused or not.
    pub fn reads(&self) -> usize {
        self.reads.lock().unwrap().len()
    }

    /// How many reads of `key` were attempted, refused or not.
    pub fn reads_of(&self, key: &str) -> usize {
        self.reads
            .lock()
            .unwrap()
            .iter()
            .filter(|k| *k == key)
            .count()
    }

    /// The same store, with writes taking `delay` (failing ones too).
    pub fn with_write_delay(mut self, delay: std::time::Duration) -> Self {
        self.write_delay = delay;
        self
    }

    pub fn set_readable(&self, readable: bool) {
        self.unreadable
            .store(!readable, std::sync::atomic::Ordering::SeqCst);
    }

    /// A keyring whose writes take `delay` (an unlock prompt).
    pub fn slow_writes(delay: std::time::Duration) -> Self {
        Self {
            write_delay: delay,
            ..Self::default()
        }
    }

    pub fn keys(&self) -> Vec<String> {
        let mut k: Vec<_> = self.map.lock().unwrap().keys().cloned().collect();
        k.sort();
        k
    }
}

#[cfg(test)]
impl SecretStore for MemoryStore {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        use std::sync::atomic::Ordering::SeqCst;
        self.reads.lock().unwrap().push(key.to_string());
        if self.broken {
            return Err(StoreError::Unavailable("no keyring".into()));
        }
        if self.refusing.load(SeqCst) {
            return Err(StoreError::Refused("the user denied access".into()));
        }
        if self.unreadable.load(SeqCst) {
            return Err(StoreError::Unavailable(
                "org.freedesktop.secrets was not provided".into(),
            ));
        }
        // Bounded, so a failing test can't hang on a blocked reader thread
        // (the runtime waits for blocking tasks when it shuts down).
        let closed = self.gate.closed.lock().unwrap();
        let (closed, _) = self
            .gate
            .opened
            .wait_timeout_while(closed, std::time::Duration::from_secs(10), |c| *c)
            .unwrap();
        drop(closed);
        Ok(self.map.lock().unwrap().get(key).cloned())
    }

    fn set(&self, key: &str, value: Option<&str>) -> Result<(), StoreError> {
        std::thread::sleep(self.write_delay);
        if self.read_only {
            return Err(StoreError::Unavailable("cannot create item".into()));
        }
        if self.broken {
            return Err(StoreError::Unavailable("no keyring".into()));
        }
        if self.refusing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(StoreError::Refused("the user denied access".into()));
        }
        let mut map = self.map.lock().unwrap();
        match value {
            Some(v) => map.insert(key.to_string(), v.to_string()),
            None => map.remove(key),
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_scoped_per_connection() {
        assert_eq!(
            password_key("jf@https://nas.lan:5001"),
            "jf@https://nas.lan:5001/password"
        );
        assert_eq!(
            did_key("jf@https://nas.lan:5001"),
            "jf@https://nas.lan:5001/did"
        );
    }

    #[test]
    fn memory_store_round_trips_and_deletes() {
        let s = MemoryStore::default();
        assert_eq!(s.get("k"), Ok(None));
        s.set("k", Some("v")).unwrap();
        assert_eq!(s.get("k"), Ok(Some("v".into())));
        s.set("k", None).unwrap();
        assert_eq!(s.get("k"), Ok(None));
    }

    #[test]
    fn a_gated_store_holds_reads_until_opened() {
        let s = Arc::new(MemoryStore::gated(&[("k", "v")]));
        let reader = {
            let s = s.clone();
            std::thread::spawn(move || s.get("k"))
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!reader.is_finished(), "the read waits for the gate");
        s.open_gate();
        assert_eq!(reader.join().unwrap(), Ok(Some("v".into())));
    }

    #[test]
    fn a_broken_store_errors() {
        let s = MemoryStore::broken();
        assert!(s.get("k").is_err());
        assert!(s.set("k", Some("v")).is_err());
    }

    fn platform_failure() -> keyring::Error {
        keyring::Error::PlatformFailure("org.freedesktop.secrets was not provided".into())
    }

    fn no_storage_access() -> keyring::Error {
        keyring::Error::NoStorageAccess("prompt dismissed".into())
    }

    #[test]
    fn on_linux_only_a_missing_secret_service_counts_as_no_keyring() {
        // No Secret Service on the bus (Flatpak, no daemon): the settings
        // file may hold the password.
        assert!(matches!(
            classify(platform_failure(), false),
            StoreError::Unavailable(_)
        ));
        // A dismissed unlock prompt or a locked collection: a refusal.
        assert!(classify(no_storage_access(), false).is_refused());
        assert!(classify(keyring::Error::BadEncoding(vec![0xff]), false).is_refused());
        assert!(classify(keyring::Error::Invalid("a".into(), "b".into()), false).is_refused());
    }

    #[test]
    fn on_macos_only_a_missing_keychain_counts_as_no_keyring() {
        // A missing, read-only or invalid keychain.
        assert!(matches!(
            classify(no_storage_access(), true),
            StoreError::Unavailable(_)
        ));
        // A denied or cancelled Keychain prompt comes as PlatformFailure.
        assert!(classify(platform_failure(), true).is_refused());
        assert!(classify(keyring::Error::TooLong("a".into(), 1), true).is_refused());
    }

    #[test]
    fn store_errors_show_the_keyring_message_only() {
        let e = classify(no_storage_access(), false);
        assert!(e.to_string().contains("prompt dismissed"), "{e}");
    }

    fn settings_with(conn: crate::settings::Connection) -> GlobalSettings {
        GlobalSettings {
            connection: conn,
            ..GlobalSettings::default()
        }
    }

    fn nas() -> crate::settings::Connection {
        crate::settings::Connection {
            host: "nas.lan".into(),
            account: "jf".into(),
            ..crate::settings::Connection::default()
        }
    }

    #[tokio::test]
    async fn a_refused_password_is_kept_in_memory_for_its_scope_only() {
        let vault = Vault::new(Arc::new(MemoryStore::refusing(&[])));
        let mut g = settings_with(nas());
        vault
            .write(&mut g, Secret::Password, Some("pw".into()))
            .await;
        assert_eq!(g.fallback_secrets, None, "nothing for the settings file");
        assert_eq!(
            vault.read(&g, Secret::Password).await,
            Ok(Some(("pw".into(), Stored::Memory)))
        );
        for other in [
            crate::settings::Connection {
                host: "other.lan".into(),
                ..nas()
            },
            crate::settings::Connection {
                port: nas().port + 1,
                ..nas()
            },
            crate::settings::Connection {
                https: false,
                ..nas()
            },
            crate::settings::Connection {
                account: "someone".into(),
                ..nas()
            },
        ] {
            let read = vault
                .read(&settings_with(other.clone()), Secret::Password)
                .await;
            assert!(
                read.as_ref().is_err_and(StoreError::is_refused),
                "{other:?}: {read:?}"
            );
        }
        // Deleting it clears the memory copy too.
        vault.write(&mut g, Secret::Password, None).await;
        assert!(vault.read(&g, Secret::Password).await.is_err());
    }

    #[tokio::test]
    async fn without_a_keyring_the_password_still_goes_to_the_settings_file() {
        let vault = Vault::new(Arc::new(MemoryStore::broken()));
        let mut g = settings_with(nas());
        vault
            .write(&mut g, Secret::Password, Some("pw".into()))
            .await;
        assert_eq!(
            g.fallback_secrets.and_then(|f| f.password),
            Some("pw".into())
        );
    }

    /// Talks to the real system keyring (Secret Service or the Keychain).
    /// CI runs it on macOS; on Linux, run it by hand in a desktop session:
    /// `cargo test keyring_round_trip -- --ignored`
    #[test]
    #[ignore]
    fn keyring_round_trip() {
        let s = KeyringStore;
        let key = "test/opendeck-synology-roundtrip";
        s.set(key, Some("secret")).unwrap();
        assert_eq!(s.get(key), Ok(Some("secret".into())));
        s.set(key, None).unwrap();
        assert_eq!(s.get(key), Ok(None));
    }
}
