//! Persisted configuration. `GlobalSettings` is OpenDeck's plugin-wide
//! settings file - plain JSON on disk, so it carries no secrets unless the
//! system keyring is unavailable. `ActionSettings` belongs to one key or dial.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Connection {
    /// As typed by the user; see `host()` for the normalised form.
    pub host: String,
    pub port: u16,
    pub https: bool,
    pub account: String,
    /// SHA-256 of the NAS's leaf certificate (lowercase hex) once trusted.
    pub pinned_sha256: Option<String>,
}

impl Default for Connection {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 5001,
            https: true,
            account: String::new(),
            pinned_sha256: None,
        }
    }
}

impl Connection {
    /// The bare host from whatever was typed: drops a scheme, a path and a
    /// `:port` suffix ("https://nas.lan:5001/" -> "nas.lan"). The port always
    /// comes from the separate port field.
    pub fn host(&self) -> String {
        let s = self.host.trim();
        let s = s.split_once("://").map_or(s, |(_, rest)| rest);
        let s = s.split('/').next().unwrap_or("");
        if s.starts_with('[') {
            return s
                .split_once(']')
                .map_or_else(|| s.to_string(), |(h, _)| format!("{h}]"));
        }
        match s.rsplit_once(':') {
            Some((h, port)) if !h.contains(':') && port.chars().all(|c| c.is_ascii_digit()) => {
                h.to_string()
            }
            _ => s.to_string(),
        }
    }

    pub fn base_url(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        let host = self.host();
        // A bare IPv6 literal needs brackets in a URL.
        let host = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]")
        } else {
            host
        };
        format!("{scheme}://{host}:{}", self.port)
    }

    pub fn is_complete(&self) -> bool {
        !self.host().is_empty() && !self.account.trim().is_empty() && self.port != 0
    }

    /// Namespaces keyring entries, so another NAS or account never reuses a
    /// password or device token.
    pub fn secret_scope(&self) -> String {
        format!("{}@{}", self.account.trim(), self.host())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TempUnit {
    #[default]
    Celsius,
    Fahrenheit,
}

/// Secrets kept in the settings file only when no system keyring works.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FallbackSecrets {
    pub password: Option<String>,
    pub did: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalSettings {
    pub connection: Connection,
    pub temp_unit: TempUnit,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_secrets: Option<FallbackSecrets>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CpuView {
    #[default]
    Total,
    Load1,
    Load5,
    Load15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    #[default]
    In,
    Out,
    Combined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Amount {
    #[default]
    Percent,
    Used,
}

/// One key's or dial's settings. A single struct serves all ten actions;
/// each reads only the fields that apply to it.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ActionSettings {
    /// Refresh interval override in seconds (clamped to at least 2).
    pub interval_secs: Option<u64>,
    pub warn: Option<f64>,
    pub crit: Option<f64>,
    /// Disk, volume or pool id, or a network interface. `None` selects the
    /// aggregate: hottest disk, worst disk, all interfaces, first volume/pool.
    pub target: Option<String>,
    pub cpu_view: CpuView,
    pub direction: Direction,
    pub amount: Amount,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn conn(host: &str, port: u16, https: bool) -> Connection {
        Connection {
            host: host.into(),
            port,
            https,
            account: "jf".into(),
            pinned_sha256: None,
        }
    }

    #[test]
    fn base_url_accepts_whatever_the_user_typed() {
        assert_eq!(
            conn("nas.lan", 5001, true).base_url(),
            "https://nas.lan:5001"
        );
        assert_eq!(
            conn("https://nas.lan:5001/", 5001, true).base_url(),
            "https://nas.lan:5001"
        );
        assert_eq!(
            conn("  NAS.lan  ", 5000, false).base_url(),
            "http://NAS.lan:5000"
        );
        assert_eq!(
            conn("http://192.168.1.10/webman", 5001, true).base_url(),
            "https://192.168.1.10:5001"
        );
        assert_eq!(
            conn("[fe80::1]:5001", 5001, true).base_url(),
            "https://[fe80::1]:5001"
        );
        assert_eq!(
            conn("fe80::1", 5001, true).base_url(),
            "https://[fe80::1]:5001"
        );
    }

    #[test]
    fn completeness_needs_host_account_and_port() {
        assert!(conn("nas.lan", 5001, true).is_complete());
        assert!(!conn("  ", 5001, true).is_complete());
        assert!(!conn("nas.lan", 0, true).is_complete());
        let mut c = conn("nas.lan", 5001, true);
        c.account = " ".into();
        assert!(!c.is_complete());
    }

    #[test]
    fn secret_scope_uses_normalised_host_and_account() {
        let mut c = conn("https://nas.lan:5001/", 5001, true);
        c.account = " jf ".into();
        assert_eq!(c.secret_scope(), "jf@nas.lan");
    }

    #[test]
    fn global_settings_default_from_empty_object() {
        let g: GlobalSettings = serde_json::from_value(json!({})).unwrap();
        assert_eq!(g.connection.port, 5001);
        assert!(g.connection.https);
        assert_eq!(g.temp_unit, TempUnit::Celsius);
        let out = serde_json::to_value(&g).unwrap();
        assert!(
            out.get("fallback_secrets").is_none(),
            "no secrets key unless needed"
        );
    }

    #[test]
    fn null_thresholds_deserialize() {
        let s: ActionSettings =
            serde_json::from_value(json!({ "warn": null, "crit": 90, "target": "sata2" })).unwrap();
        assert_eq!(s.warn, None);
        assert_eq!(s.crit, Some(90.0));
        assert_eq!(s.target.as_deref(), Some("sata2"));
    }

    #[test]
    fn view_enums_use_lowercase_names() {
        let s: ActionSettings = serde_json::from_value(
            json!({ "cpu_view": "load5", "direction": "combined", "amount": "used" }),
        )
        .unwrap();
        assert_eq!(
            (s.cpu_view, s.direction, s.amount),
            (CpuView::Load5, Direction::Combined, Amount::Used)
        );
        assert_eq!(ActionSettings::default().cpu_view, CpuView::Total);
    }
}
