//! Where the password and the 2FA device token live: the system keyring
//! (Secret Service), keeping them out of OpenDeck's plain-JSON settings file.
//!
//! `Vault` adds the fallbacks for a machine without a usable keyring (e.g.
//! OpenDeck as a Flatpak without access to it): the password goes to the
//! settings file - which the settings panel then says - and the device token
//! is kept in memory only, since the two together would get past 2FA.

use crate::settings::{FallbackSecrets, GlobalSettings};
use std::sync::{Arc, Mutex};

pub const SERVICE: &str = "com.jfms7s.synology";

/// Blocking key-value secret storage. Call through `spawn_blocking`.
pub trait SecretStore: Send + Sync {
    /// `Ok(None)`: no such secret. `Err`: no usable keyring at all.
    fn get(&self, key: &str) -> Result<Option<String>, String>;
    /// `None` deletes (deleting a missing secret is not an error).
    fn set(&self, key: &str, value: Option<&str>) -> Result<(), String>;
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
    /// This process's memory only (a device token without a keyring).
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
    /// (scope, device token) when the keyring refused it.
    memory_did: Mutex<Option<(String, String)>>,
}

impl Vault {
    pub fn new(store: Arc<dyn SecretStore>) -> Self {
        Self {
            store,
            memory_did: Mutex::new(None),
        }
    }

    async fn get(&self, key: String) -> Result<Option<String>, String> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || store.get(&key))
            .await
            .unwrap_or_else(|e| Err(e.to_string()))
    }

    async fn set(&self, key: String, value: Option<String>) -> Result<(), String> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || store.set(&key, value.as_deref()))
            .await
            .unwrap_or_else(|e| Err(e.to_string()))
    }

    /// The settings-file secrets, if they belong to the current connection.
    pub fn fallback_for(g: &GlobalSettings) -> Option<&FallbackSecrets> {
        g.fallback_secrets
            .as_ref()
            .filter(|f| f.belongs_to(&g.connection))
    }

    /// A secret for the current connection and where it was found. `Err`
    /// only when the keyring failed and no fallback has it - which is not
    /// the same as "no password saved".
    pub async fn read(
        &self,
        g: &GlobalSettings,
        which: Secret,
    ) -> Result<Option<(String, Stored)>, String> {
        let scope = g.connection.secret_scope();
        let keyring = self.get(which.key(&scope)).await;
        if let Ok(Some(v)) = keyring {
            return Ok(Some((v, Stored::Keyring)));
        }
        let fallback = Self::fallback_for(g)
            .cloned()
            .and_then(|mut f| which.slot(&mut f).take());
        if let Some(v) = fallback {
            return Ok(Some((v, Stored::SettingsFile)));
        }
        if which == Secret::Did
            && let Some((s, v)) = self.memory_did.lock().unwrap().clone()
            && s == scope
        {
            return Ok(Some((v, Stored::Memory)));
        }
        keyring.map(|_| None)
    }

    /// Stores (or with `None`, deletes) a secret in the keyring, falling
    /// back - with a warning - to the settings file for the password and to
    /// memory for the device token.
    pub async fn write(&self, g: &mut GlobalSettings, which: Secret, value: Option<String>) {
        let scope = g.connection.secret_scope();
        if Self::fallback_for(g).is_none() {
            // Nothing there, or another connection's secrets: start afresh.
            g.fallback_secrets = None;
        }
        let result = self.set(which.key(&scope), value.clone()).await;
        let fallback = g
            .fallback_secrets
            .get_or_insert_with(FallbackSecrets::default);
        fallback.scope = Some(scope.clone());
        let slot = which.slot(fallback);
        if which == Secret::Did {
            *self.memory_did.lock().unwrap() = None;
        }
        match (result, which) {
            (Ok(()), _) => *slot = None,
            (Err(e), Secret::Password) => {
                log::warn!(
                    "no usable system keyring ({e}); keeping the password in OpenDeck's settings file"
                );
                *slot = value;
            }
            (Err(e), Secret::Did) => {
                log::warn!(
                    "no usable system keyring ({e}); the 2FA device token is kept in memory only, so a code is asked for again after a restart"
                );
                *slot = None;
                *self.memory_did.lock().unwrap() = value.map(|v| (scope, v));
            }
        }
        if g.fallback_secrets
            .as_ref()
            .is_some_and(|f| f.password.is_none() && f.did.is_none())
        {
            g.fallback_secrets = None;
        }
    }

    /// Brings stored secrets up to date for the current connection:
    /// - secrets that fell back to the settings file move into the keyring
    ///   if it works now (a device token never stays in the file);
    /// - keyring entries filed under the pre-0.3 `account@host` scope move
    ///   to this connection's scope - for an HTTPS connection only, since
    ///   they may have been saved for HTTPS.
    pub async fn migrate(&self, g: &mut GlobalSettings) {
        let fallback = Self::fallback_for(g).cloned().unwrap_or_default();
        if let Some(pw) = fallback.password {
            self.write(g, Secret::Password, Some(pw)).await;
        }
        if let Some(did) = fallback.did {
            self.write(g, Secret::Did, Some(did)).await;
        }
        if !g.connection.https {
            return;
        }
        let (scope, legacy) = (
            g.connection.secret_scope(),
            g.connection.legacy_secret_scope(),
        );
        for which in [Secret::Password, Secret::Did] {
            let (new_key, old_key) = (which.key(&scope), which.key(&legacy));
            if self.get(new_key.clone()).await != Ok(None) {
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
    }
}

pub struct KeyringStore;

impl SecretStore for KeyringStore {
    fn get(&self, key: &str) -> Result<Option<String>, String> {
        let entry = keyring::Entry::new(SERVICE, key).map_err(|e| e.to_string())?;
        match entry.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn set(&self, key: &str, value: Option<&str>) -> Result<(), String> {
        let entry = keyring::Entry::new(SERVICE, key).map_err(|e| e.to_string())?;
        match value {
            Some(v) => entry.set_password(v).map_err(|e| e.to_string()),
            None => match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(e.to_string()),
            },
        }
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct MemoryStore {
    map: std::sync::Mutex<std::collections::HashMap<String, String>>,
    broken: bool,
    /// Reads fail while set (Secret Service not up yet, a locked collection).
    unreadable: std::sync::atomic::AtomicBool,
    /// How long each write takes.
    write_delay: std::time::Duration,
    /// While closed, reads wait (an access or unlock prompt nobody has
    /// answered yet).
    gate: Gate,
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
    /// collection).
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
    fn get(&self, key: &str) -> Result<Option<String>, String> {
        if self.broken {
            return Err("no keyring".into());
        }
        if self.unreadable.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("org.freedesktop.secrets was not provided".into());
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

    fn set(&self, key: &str, value: Option<&str>) -> Result<(), String> {
        if self.broken {
            return Err("no keyring".into());
        }
        std::thread::sleep(self.write_delay);
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

    /// Talks to the real Secret Service. Run by hand on a desktop session:
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
