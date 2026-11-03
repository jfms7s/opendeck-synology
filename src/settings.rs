//! Persisted configuration. `GlobalSettings` is OpenDeck's plugin-wide
//! settings file - plain JSON on disk, so it carries no secrets unless the
//! system keyring is unavailable. `ActionSettings` belongs to one key or dial.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

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
            port: Connection::DEFAULT_PORT,
            https: true,
            account: String::new(),
            pinned_sha256: None,
        }
    }
}

impl Connection {
    /// DSM's HTTPS port (the settings panel gets it too).
    pub const DEFAULT_PORT: u16 = 5001;

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

    /// The one identity of "this NAS": scheme, host and port. The certificate
    /// pin and the secrets both belong to it.
    pub fn same_nas(&self, other: &Connection) -> bool {
        self.base_url() == other.base_url()
    }

    /// Namespaces keyring entries by account, scheme, host and port, so a
    /// password or device token saved for one NAS - or for HTTPS - is never
    /// sent to another one, or over unencrypted HTTP (which only settings
    /// from before 0.7.0 can name, and which never connects).
    pub fn secret_scope(&self) -> String {
        format!("{}@{}", self.account.trim(), self.base_url())
    }

    /// The scope used up to v0.2.1 (`account@host`, no scheme or port).
    /// Secrets filed under it are only adopted by an HTTPS connection.
    pub fn legacy_secret_scope(&self) -> String {
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
/// `Debug` redacts the password and device token.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FallbackSecrets {
    pub password: Option<String>,
    pub did: Option<String>,
    /// The `Connection::secret_scope` these secrets belong to, so another
    /// account or NAS never gets them. `None` in files written before the
    /// scope was recorded: those belong to the connection saved with them.
    pub scope: Option<String>,
}

impl fmt::Debug for FallbackSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FallbackSecrets")
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("did", &self.did.as_ref().map(|_| "<redacted>"))
            .field("scope", &self.scope)
            .finish()
    }
}

impl FallbackSecrets {
    /// Whether these secrets may be used for `conn`. Secrets from before
    /// the scope included the scheme and port (no scope, or the legacy
    /// `account@host` one) are only trusted over HTTPS: they may have been
    /// saved for an HTTPS connection, and must not leak over unencrypted HTTP.
    pub fn belongs_to(&self, conn: &Connection) -> bool {
        match self.scope.as_deref() {
            Some(s) if s == conn.secret_scope() => true,
            None => conn.https,
            Some(s) => conn.https && s == conn.legacy_secret_scope(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalSettings {
    pub connection: Connection,
    pub temp_unit: TempUnit,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_secrets: Option<FallbackSecrets>,
}

/// Reads `obj[name]`, or the default (noting `name` in `bad`) when it is
/// there but unreadable.
fn field<T: DeserializeOwned + Default>(obj: &Value, name: &str, bad: &mut Vec<String>) -> T {
    field_or(obj, name, T::default(), bad)
}

/// [`field`] with an explicit default, for fields whose default is not
/// `T::default()` (a port of 5001, HTTPS on).
fn field_or<T: DeserializeOwned>(obj: &Value, name: &str, default: T, bad: &mut Vec<String>) -> T {
    match obj.get(name) {
        None | Some(Value::Null) => default,
        Some(v) => serde_json::from_value(v.clone()).unwrap_or_else(|_| {
            bad.push(name.to_string());
            default
        }),
    }
}

/// A block that is there but is not an object (`"connection": "nas.lan"`)
/// loses every field in it: name it in `bad` rather than dropping it silently.
fn object_or_note(v: &Value, name: &str, bad: &mut Vec<String>) -> Value {
    match v.get(name) {
        None | Some(Value::Null) => Value::Null,
        Some(o) if o.is_object() => o.clone(),
        Some(_) => {
            bad.push(name.to_string());
            Value::Null
        }
    }
}

impl GlobalSettings {
    /// Reads OpenDeck's settings file field by field: one unreadable value
    /// (say a hand-edited `"port": "5001"`) costs that value, not the whole
    /// configuration - which the next save would otherwise overwrite with
    /// defaults. Returns the names of the fields that were dropped.
    pub fn from_value_lenient(v: &Value) -> (Self, Vec<String>) {
        if let Ok(g) = serde_json::from_value(v.clone()) {
            return (g, Vec::new());
        }
        if !v.is_object() && !v.is_null() {
            return (Self::default(), vec!["settings".into()]);
        }
        let mut bad = Vec::new();
        let c = object_or_note(v, "connection", &mut bad);
        let d = Connection::default();
        let mut conn_bad = Vec::new();
        let connection = Connection {
            host: field(&c, "host", &mut conn_bad),
            port: field_or(&c, "port", d.port, &mut conn_bad),
            https: field_or(&c, "https", d.https, &mut conn_bad),
            account: field(&c, "account", &mut conn_bad),
            pinned_sha256: field(&c, "pinned_sha256", &mut conn_bad),
        };
        bad.extend(conn_bad.into_iter().map(|f| format!("connection.{f}")));
        let g = GlobalSettings {
            connection,
            temp_unit: field(v, "temp_unit", &mut bad),
            fallback_secrets: field(v, "fallback_secrets", &mut bad),
        };
        (g, bad)
    }
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
    /// Free space or memory (`1.9 TB free`).
    Free,
}

/// What a Volume key's warn/critical thresholds measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdBasis {
    /// Percent used, alarming upwards (80/90 % by default).
    #[default]
    UsedPct,
    /// GB free, alarming downwards; off until the user sets a value.
    FreeGb,
}

/// What a Storage I/O key shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IoView {
    /// Busy %, the view the thresholds and the bar are about.
    #[default]
    Busy,
    Read,
    Write,
    /// Read plus write operations per second.
    Iops,
}

/// What pressing a key, pushing a dial or tapping its touch strip does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PressAction {
    /// Poll the key's endpoint now (and, after a refused keyring read, ask
    /// the keyring again).
    #[default]
    Refresh,
    /// Open the NAS's DSM web UI in the default browser.
    Dsm,
}

/// One key's or dial's settings. A single struct serves all eleven actions;
/// each reads only the fields that apply to it. Deserialising is lenient
/// (see the `Deserialize` impl): openaction falls back to
/// `Default::default()` for the whole key on any error, so one unreadable
/// field would otherwise reset its target, thresholds and view.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct ActionSettings {
    // The per-key refresh override (before 0.7.0) is gone;
    // settings saved with it still load, since unknown fields are ignored.
    pub warn: Option<f64>,
    pub crit: Option<f64>,
    /// Disk, volume or pool id, or a network interface. `None` selects the
    /// aggregate: hottest disk, worst disk, all interfaces, first volume/pool.
    pub target: Option<String>,
    pub cpu_view: CpuView,
    pub direction: Direction,
    pub amount: Amount,
    pub threshold_basis: ThresholdBasis,
    pub io_view: IoView,
    pub press: PressAction,
}

impl ActionSettings {
    /// Reads a key's settings field by field: an unreadable value (a view
    /// from a newer plugin version, a hand-edited profile) costs that field
    /// only. Returns the names of the fields that were dropped; a value that
    /// is not an object at all yields the defaults and `["settings"]`.
    pub fn from_value_lenient(v: &Value) -> (Self, Vec<String>) {
        let mut bad = Vec::new();
        if !v.is_object() && !v.is_null() {
            return (Self::default(), vec!["settings".into()]);
        }
        let s = ActionSettings {
            warn: field(v, "warn", &mut bad),
            crit: field(v, "crit", &mut bad),
            // An unreadable target falls back to the aggregate (hottest disk,
            // all interfaces, first volume); the subject line names it.
            target: field(v, "target", &mut bad),
            cpu_view: field(v, "cpu_view", &mut bad),
            direction: field(v, "direction", &mut bad),
            amount: field(v, "amount", &mut bad),
            threshold_basis: field(v, "threshold_basis", &mut bad),
            io_view: field(v, "io_view", &mut bad),
            press: field(v, "press", &mut bad),
        };
        (s, bad)
    }
}

impl<'de> Deserialize<'de> for ActionSettings {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (s, bad) = Self::from_value_lenient(&Value::deserialize(d)?);
        if !bad.is_empty() {
            warn_unreadable_once(&bad);
        }
        Ok(s)
    }
}

/// Logs dropped key-setting names (never values) once per distinct set:
/// openaction deserialises a key's settings on every event, and a press
/// should not add a log line each time.
fn warn_unreadable_once(bad: &[String]) {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<HashSet<Vec<String>>>> = OnceLock::new();
    let mut seen = SEEN
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if seen.insert(bad.to_vec()) {
        log::warn!("unreadable key settings {bad:?}: using their defaults, keeping the rest");
    }
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
    fn secret_scope_uses_normalised_account_scheme_host_and_port() {
        let mut c = conn("https://nas.lan:5001/", 5001, true);
        c.account = " jf ".into();
        assert_eq!(c.secret_scope(), "jf@https://nas.lan:5001");
        assert_eq!(c.legacy_secret_scope(), "jf@nas.lan");
        let http = conn("nas.lan", 5001, false);
        assert_ne!(
            http.secret_scope(),
            c.secret_scope(),
            "HTTP never shares HTTPS secrets"
        );
        let other_port = conn("nas.lan", 5002, true);
        assert_ne!(other_port.secret_scope(), c.secret_scope());
    }

    #[test]
    fn same_nas_means_same_scheme_host_and_port() {
        let a = conn("nas.lan", 5001, true);
        assert!(a.same_nas(&conn("https://nas.lan:5001/", 5001, true)));
        assert!(!a.same_nas(&conn("nas.lan", 5002, true)));
        assert!(!a.same_nas(&conn("nas.lan", 5001, false)));
        assert!(!a.same_nas(&conn("other.lan", 5001, true)));
    }

    #[test]
    fn one_unreadable_field_costs_only_that_field() {
        let v = json!({
            "connection": { "host": "nas.lan", "port": "5001x", "account": "jf", "pinned_sha256": "ab" },
            "temp_unit": "kelvin",
        });
        let (g, bad) = GlobalSettings::from_value_lenient(&v);
        assert_eq!(g.connection.host, "nas.lan");
        assert_eq!(g.connection.account, "jf");
        assert_eq!(g.connection.pinned_sha256.as_deref(), Some("ab"));
        assert_eq!(g.connection.port, 5001, "the default");
        assert_eq!(g.temp_unit, TempUnit::Celsius);
        assert_eq!(bad, ["connection.port", "temp_unit"]);
        let (_, bad) = GlobalSettings::from_value_lenient(&json!({}));
        assert!(bad.is_empty());
    }

    #[test]
    fn a_connection_that_is_not_an_object_is_named() {
        let (g, bad) = GlobalSettings::from_value_lenient(&json!({
            "connection": "nas.lan",
            "temp_unit": "fahrenheit",
        }));
        assert_eq!(bad, ["connection"]);
        assert_eq!(g.connection, Connection::default());
        assert_eq!(g.temp_unit, TempUnit::Fahrenheit);
        let (_, bad) =
            GlobalSettings::from_value_lenient(&json!({ "connection": null, "temp_unit": 1 }));
        assert_eq!(bad, ["temp_unit"]);
    }

    #[test]
    fn unreadable_port_or_https_take_their_own_defaults() {
        let (g, bad) = GlobalSettings::from_value_lenient(&json!({
            "connection": { "host": "nas.lan", "port": -1, "https": "yes", "account": "jf" },
        }));
        assert_eq!((g.connection.port, g.connection.https), (5001, true));
        assert_eq!(g.connection.host, "nas.lan");
        assert_eq!(bad, ["connection.port", "connection.https"]);
    }

    #[test]
    fn one_unknown_key_setting_keeps_the_others() {
        let s: ActionSettings = serde_json::from_value(json!({
            "target": "volume_2", "cpu_view": "load60", "warn": 70, "crit": "high",
            "direction": "out", "interval": 10,
        }))
        .unwrap();
        assert_eq!(s.target.as_deref(), Some("volume_2"));
        assert_eq!(s.warn, Some(70.0));
        assert_eq!(s.crit, None);
        assert_eq!(s.cpu_view, CpuView::Total);
        assert_eq!(s.direction, Direction::Out);
        let (_, bad) = ActionSettings::from_value_lenient(&json!({
            "cpu_view": "load60", "crit": "high", "interval": 10,
        }));
        assert_eq!(bad, ["crit", "cpu_view"]);
    }

    #[test]
    fn settings_saved_before_the_press_setting_refresh_on_press() {
        let s: ActionSettings = serde_json::from_value(json!({
            "target": "volume_2", "warn": 70, "interval": 10,
        }))
        .unwrap();
        assert_eq!(s.press, PressAction::Refresh);
        assert_eq!(s.io_view, IoView::Busy);
        assert_eq!(s.target.as_deref(), Some("volume_2"));
        let s: ActionSettings = serde_json::from_value(json!({ "press": "storage" })).unwrap();
        assert_eq!(s.press, PressAction::Refresh, "an unknown choice refreshes");
    }

    #[test]
    fn key_settings_that_are_not_an_object_are_the_defaults() {
        for v in [json!("volume_2"), json!([1, 2]), json!(7)] {
            let s: ActionSettings = serde_json::from_value(v.clone()).unwrap();
            assert_eq!(s, ActionSettings::default());
            assert_eq!(ActionSettings::from_value_lenient(&v).1, ["settings"]);
        }
        let s: ActionSettings = serde_json::from_value(json!(null)).unwrap();
        assert_eq!(s, ActionSettings::default());
        let s: ActionSettings = serde_json::from_value(json!({})).unwrap();
        assert_eq!(s, ActionSettings::default());
    }

    #[test]
    fn key_settings_round_trip_with_the_same_wire_names() {
        let s = ActionSettings {
            warn: Some(1.5),
            crit: None,
            target: Some("eth0".into()),
            cpu_view: CpuView::Load15,
            direction: Direction::Combined,
            amount: Amount::Used,
            threshold_basis: ThresholdBasis::FreeGb,
            io_view: IoView::Iops,
            press: PressAction::Dsm,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["threshold_basis"], "free_gb");
        assert_eq!(v["press"], "dsm");
        assert_eq!(v["io_view"], "iops");
        assert_eq!(v["cpu_view"], "load15");
        assert_eq!(v["direction"], "combined");
        assert_eq!(v["amount"], "used");
        assert_eq!(serde_json::from_value::<ActionSettings>(v).unwrap(), s);
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
    fn fallback_secrets_without_a_scope_still_load() {
        let g: GlobalSettings =
            serde_json::from_value(json!({ "fallback_secrets": { "password": "pw" } })).unwrap();
        let f = g.fallback_secrets.unwrap();
        assert_eq!(
            (f.password.as_deref(), f.scope.as_deref()),
            (Some("pw"), None)
        );
        let https = conn("nas.lan", 5001, true);
        let http = conn("nas.lan", 5000, false);
        assert!(f.belongs_to(&https), "older files: the saved connection's");
        assert!(!f.belongs_to(&http), "but never over unencrypted HTTP");
        let legacy = FallbackSecrets {
            scope: Some("jf@nas.lan".into()),
            ..f.clone()
        };
        assert!(legacy.belongs_to(&https));
        assert!(!legacy.belongs_to(&http));
        assert!(!legacy.belongs_to(&conn("other.lan", 5001, true)));
        let scoped = FallbackSecrets {
            scope: Some(http.secret_scope()),
            ..f
        };
        assert!(
            scoped.belongs_to(&http),
            "typed in for this HTTP connection"
        );
        assert!(!scoped.belongs_to(&https));
    }

    #[test]
    fn debug_output_hides_fallback_secrets() {
        let g = GlobalSettings {
            fallback_secrets: Some(FallbackSecrets {
                password: Some("p&ss=w+rd".into()),
                did: Some("dev-1".into()),
                scope: Some("jf@nas.lan".into()),
            }),
            ..GlobalSettings::default()
        };
        let text = format!("{g:?}");
        assert!(!text.contains("p&ss") && !text.contains("dev-1"), "{text}");
        assert!(text.contains("jf@nas.lan"), "{text}");
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
        let s: ActionSettings =
            serde_json::from_value(json!({ "amount": "free", "threshold_basis": "free_gb" }))
                .unwrap();
        assert_eq!(
            (s.amount, s.threshold_basis),
            (Amount::Free, ThresholdBasis::FreeGb)
        );
    }

    /// A key saved before headroom existed reads exactly as it did: no new
    /// field is dropped as unreadable and the basis stays percent used.
    #[test]
    fn a_key_saved_before_headroom_reads_as_before() {
        let saved = json!({ "amount": "used", "warn": 85, "crit": null, "target": "volume_1" });
        let (s, bad) = ActionSettings::from_value_lenient(&saved);
        assert!(bad.is_empty(), "{bad:?}");
        assert_eq!(
            s,
            ActionSettings {
                warn: Some(85.0),
                amount: Amount::Used,
                target: Some("volume_1".into()),
                ..ActionSettings::default()
            }
        );
        assert_eq!(s.threshold_basis, ThresholdBasis::UsedPct);
    }
}
