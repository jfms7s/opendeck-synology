//! The settings panel's side channel. The panel saves a key's own settings
//! directly (`setSettings`). Anything plugin-wide or secret - connection,
//! password, 2FA code, certificate trust, temperature unit - comes through
//! here, so the password never lands in a settings file.
//!
//! Payloads are never logged: they can carry the password.

use crate::dsm::session::is_otp_code;
use crate::metric::Metric;
use crate::metrics;
use crate::secrets::{Stored, in_flatpak};
use crate::services::Services;
use crate::settings::{Connection, TempUnit};
use crate::status::ConnStatus;
use openaction::{Instance, OpenActionResult};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

// Debug only in tests: a derived Debug would print the password.
#[derive(Deserialize, PartialEq)]
#[cfg_attr(test, derive(Debug))]
#[serde(tag = "event", rename_all = "camelCase")]
pub enum Request {
    GetState,
    SaveConnection {
        host: String,
        /// Checked by `port()`, so a bad value gets an answer instead of
        /// failing the whole message.
        port: Value,
        https: bool,
        account: String,
        #[serde(default)]
        password: Option<String>,
    },
    SubmitOtp {
        code: String,
    },
    /// The fingerprint the panel showed - the one the user compared.
    TrustCertificate {
        fingerprint: String,
    },
    SetTempUnit {
        unit: TempUnit,
    },
}

/// Drops whatever surrounds a pasted 2FA code: " 123 456\n" -> "123456".
pub fn normalise_otp(code: &str) -> String {
    code.chars().filter(|c| !c.is_whitespace()).collect()
}

/// A TCP port: a whole number from 1 to 65535.
fn port(v: &Value) -> Option<u16> {
    v.as_u64()
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p != 0)
}

pub fn state_message(services: &Services, metric: Metric, notice: Option<&str>) -> Value {
    let g = services.global();
    let status = services.current_status();
    let targets: Vec<Value> = services
        .poller(metric.endpoint())
        .latest()
        .value
        .as_deref()
        .map(|p| metrics::target_options(metric, p))
        .unwrap_or_default()
        .into_iter()
        .map(|(id, label)| json!({ "id": id, "label": label }))
        .collect();
    let (fingerprint, changed) = match &status {
        ConnStatus::Certificate {
            fingerprint,
            changed,
        } => (Some(fingerprint.clone()), *changed),
        _ => (None, false),
    };
    let firmware = matches!(status, ConnStatus::Connected { .. })
        .then(|| services.firmware())
        .flatten();
    let defaults = metric.default_thresholds();
    json!({
        "event": "state",
        "connection": {
            "host": g.connection.host,
            "port": g.connection.port,
            "https": g.connection.https,
            "account": g.connection.account,
        },
        "hasPassword": services.has_password(),
        // Where the password really is, so the panel never claims a keyring
        // it couldn't use.
        "passwordStorage": services.password_stored().map(Stored::name),
        "flatpak": in_flatpak(),
        "tempUnit": g.temp_unit,
        "status": {
            "kind": status.kind(),
            "severity": status.severity(),
            "text": status.describe(),
            "fingerprint": fingerprint,
            "changed": changed,
            "firmware": firmware,
        },
        "notice": notice,
        "fields": metric.fields(),
        "targets": targets,
        "defaults": {
            "warn": defaults.map(|d| d.0),
            "crit": defaults.map(|d| d.1),
            "interval": metric.endpoint().default_interval().as_secs(),
        },
    })
}

pub async fn send_state(
    services: &Services,
    metric: Metric,
    instance: &Instance,
    notice: Option<&str>,
) -> OpenActionResult<()> {
    instance
        .send_to_property_inspector(state_message(services, metric, notice))
        .await
}

pub async fn handle(
    services: &Arc<Services>,
    metric: Metric,
    instance: &Instance,
    payload: &Value,
) -> OpenActionResult<()> {
    let req = match serde_json::from_value::<Request>(payload.clone()) {
        Ok(Request::GetState) => return send_state(services, metric, instance, None).await,
        Ok(req) => req,
        Err(_) => {
            log::warn!("ignoring an unrecognised settings-panel message");
            let notice = "The plugin didn't understand that request - is the plugin up to date?";
            return send_state(services, metric, instance, Some(notice)).await;
        }
    };
    // openaction handles one event at a time: a login against a slow NAS or
    // a keyring unlock prompt must not freeze every key and dial meanwhile.
    let (services, id) = (services.clone(), instance.instance_id.clone());
    tokio::spawn(async move {
        let notice = apply(&services, req).await;
        if let Some(instance) = openaction::get_instance(id).await
            && let Err(e) = send_state(&services, metric, &instance, notice.as_deref()).await
        {
            log::warn!("updating the settings panel failed: {e}");
        }
    });
    Ok(())
}

/// Carries out a panel request; `Some` is a message for the panel.
async fn apply(services: &Arc<Services>, req: Request) -> Option<String> {
    match req {
        Request::GetState => None,
        Request::SaveConnection {
            host,
            port: p,
            https,
            account,
            password,
        } => {
            let Some(port) = port(&p) else {
                return Some("The port must be a whole number from 1 to 65535.".into());
            };
            let conn = Connection {
                host,
                port,
                https,
                account,
                pinned_sha256: None,
            };
            services
                .save_connection(conn, password.filter(|p| !p.is_empty()))
                .await;
            None
        }
        Request::SubmitOtp { code } => {
            let code = normalise_otp(&code);
            if !is_otp_code(&code) {
                return Some("Enter the 6-digit code from your authenticator app.".into());
            }
            if let Err(e) = services.submit_otp(&code).await {
                log::info!("2FA sign-in failed: {e}");
            }
            None
        }
        Request::TrustCertificate { fingerprint } => {
            if services.trust_certificate(&fingerprint).await {
                None
            } else {
                Some(
                    "The NAS presents a different certificate now. Compare the new fingerprint before trusting it."
                        .into(),
                )
            }
        }
        Request::SetTempUnit { unit } => {
            services.set_temp_unit(unit).await;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsm::fake::FakeDsm;
    use crate::metric::Endpoint;
    use crate::secrets::MemoryStore;
    use crate::services::testing::{eventually, healthy_nas, services_with};
    use crate::settings::GlobalSettings;

    fn req(v: Value) -> Request {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn parses_panel_requests() {
        assert_eq!(req(json!({ "event": "getState" })), Request::GetState);
        assert_eq!(
            req(json!({ "event": "trustCertificate", "fingerprint": "ab" })),
            Request::TrustCertificate {
                fingerprint: "ab".into()
            }
        );
        assert_eq!(
            req(json!({ "event": "setTempUnit", "unit": "fahrenheit" })),
            Request::SetTempUnit {
                unit: TempUnit::Fahrenheit
            }
        );
        assert_eq!(
            req(json!({ "event": "submitOtp", "code": "123456" })),
            Request::SubmitOtp {
                code: "123456".into()
            }
        );
        let save = req(
            json!({ "event": "saveConnection", "host": "nas.lan", "port": 5001, "https": true, "account": "jf", "password": null }),
        );
        assert_eq!(
            save,
            Request::SaveConnection {
                host: "nas.lan".into(),
                port: json!(5001),
                https: true,
                account: "jf".into(),
                password: None
            }
        );
        assert!(serde_json::from_value::<Request>(json!({ "event": "reboot" })).is_err());
        assert!(
            serde_json::from_value::<Request>(json!({ "event": "trustCertificate" })).is_err(),
            "trusting needs the fingerprint the user saw"
        );
    }

    #[test]
    fn otp_code_is_normalised() {
        assert_eq!(normalise_otp(" 123 456\n"), "123456");
    }

    #[test]
    fn ports_are_whole_numbers_from_1_to_65535() {
        assert_eq!(port(&json!(5001)), Some(5001));
        assert_eq!(port(&json!(65535)), Some(65535));
        for bad in [
            json!(0),
            json!(70000),
            json!(5001.5),
            json!("5001"),
            json!(-1),
        ] {
            assert_eq!(port(&bad), None, "{bad}");
        }
    }

    fn save_on(port: Value, password: Option<&str>) -> Request {
        Request::SaveConnection {
            host: "nas.lan".into(),
            port,
            https: true,
            account: "jf".into(),
            password: password.map(str::to_string),
        }
    }

    fn save(password: Option<&str>) -> Request {
        save_on(json!(5001), password)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_password_is_never_echoed_or_saved_in_settings() {
        let (s, sink) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        assert_eq!(apply(&s, save(Some("pw-secret"))).await, None);
        let msg = state_message(&s, Metric::Cpu, None);
        assert_eq!(msg["hasPassword"], true);
        assert_eq!(msg["passwordStorage"], "keyring");
        assert!(!msg.to_string().contains("pw-secret"));
        assert!(
            !serde_json::to_string(&sink.last())
                .unwrap()
                .contains("pw-secret")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_panel_is_told_when_the_password_is_in_the_settings_file() {
        let (s, _) = services_with(healthy_nas(), Arc::new(MemoryStore::broken()));
        s.load_global(GlobalSettings::default()).await;
        apply(&s, save(Some("pw"))).await;
        let msg = state_message(&s, Metric::Cpu, None);
        assert_eq!(msg["passwordStorage"], "settingsFile");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_invalid_port_is_answered_and_nothing_is_saved() {
        let (s, sink) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        let notice = apply(&s, save_on(json!(70000), Some("pw"))).await;
        assert!(notice.unwrap().contains("port"));
        assert!(sink.0.lock().unwrap().is_empty(), "nothing saved");
        assert!(!s.has_password());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_empty_2fa_code_makes_no_request() {
        let nas = FakeDsm::new(|r| match r.get("method").map(String::as_str) {
            Some("login") => Err(403),
            _ => Ok(json!({})),
        });
        let (s, _) = services_with(nas.clone(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        apply(&s, save(Some("pw"))).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("k", None);
        eventually("asks for a code", || s.current_status().kind() == "needOtp").await;
        let sent = nas.requests().len();
        let notice = apply(&s, Request::SubmitOtp { code: " ".into() }).await;
        assert!(notice.is_some());
        assert_eq!(nas.requests().len(), sent, "nothing sent to DSM");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_empty_password_keeps_the_stored_one() {
        let (s, _) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        apply(&s, save(Some("pw"))).await;
        apply(&s, save(Some(""))).await;
        assert!(s.has_password());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn state_lists_targets_fields_and_defaults() {
        let (s, _) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        apply(&s, save(Some("pw"))).await;
        let _rx = s.poller(Endpoint::Storage).subscribe("k", None);
        eventually("storage polled", || {
            s.poller(Endpoint::Storage).latest().value.is_some()
        })
        .await;
        let msg = state_message(&s, Metric::DiskTemp, Some("hello"));
        assert_eq!(
            msg["targets"][0],
            json!({ "id": null, "label": "Hottest disk" })
        );
        assert_eq!(
            msg["targets"][1],
            json!({ "id": "sata1", "label": "Drive 1" })
        );
        assert_eq!(
            msg["defaults"],
            json!({ "warn": 50.0, "crit": 60.0, "interval": 60 })
        );
        assert_eq!(
            msg["fields"],
            json!({ "target": "Disk", "cpuView": false, "direction": false, "amount": false, "thresholdUnit": "°C" })
        );
        assert_eq!(msg["connection"]["host"], "nas.lan");
        assert_eq!(msg["notice"], "hello");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_status_line_names_the_dsm_version_with_only_a_cpu_key() {
        let (s, _) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        apply(&s, save(Some("pw"))).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("k", None);
        eventually("firmware in the status", || {
            state_message(&s, Metric::Cpu, None)["status"]["firmware"] == "DSM 7.2.2-72806 Update 3"
        })
        .await;
        assert!(s.poller(Endpoint::SystemInfo).latest().value.is_none());
        let msg = state_message(&s, Metric::Cpu, None);
        assert_eq!(msg["status"]["severity"], "ok");
    }
}
