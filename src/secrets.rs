//! Where the password and the 2FA device token live: the system keyring
//! (Secret Service), keeping them out of OpenDeck's plain-JSON settings file.

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
}

#[cfg(test)]
impl SecretStore for MemoryStore {
    fn get(&self, key: &str) -> Result<Option<String>, String> {
        if self.broken {
            return Err("no keyring".into());
        }
        Ok(self.map.lock().unwrap().get(key).cloned())
    }

    fn set(&self, key: &str, value: Option<&str>) -> Result<(), String> {
        if self.broken {
            return Err("no keyring".into());
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
    fn keys_are_scoped_per_account_and_host() {
        assert_eq!(password_key("jf@nas.lan"), "jf@nas.lan/password");
        assert_eq!(did_key("jf@nas.lan"), "jf@nas.lan/did");
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
