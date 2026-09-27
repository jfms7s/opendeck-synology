//! The settings panel's side channel. The panel saves a key's own settings
//! directly (`setSettings`). Anything plugin-wide or secret - connection,
//! password, 2FA code, certificate trust, temperature unit - comes through
//! here, so the password never lands in a settings file.
//!
//! Payloads are never logged: they can carry the password.

use crate::dsm::model::Payload;
use crate::metric::{Endpoint, Metric};
use crate::metrics;
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
        port: u16,
        https: bool,
        account: String,
        #[serde(default)]
        password: Option<String>,
    },
    SubmitOtp {
        code: String,
    },
    TrustCertificate,
    SetTempUnit {
        unit: TempUnit,
    },
}

/// Drops whatever surrounds a pasted 2FA code: " 123 456\n" -> "123456".
pub fn normalise_otp(code: &str) -> String {
    code.chars().filter(|c| !c.is_whitespace()).collect()
}

pub fn state_message(services: &Services, metric: Metric) -> Value {
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
    let firmware = match services
        .poller(Endpoint::SystemInfo)
        .latest()
        .value
        .as_deref()
    {
        Some(Payload::SystemInfo(s)) => s.firmware.clone(),
        _ => None,
    };
    let fingerprint = match &status {
        ConnStatus::Certificate { fingerprint, .. } => Some(fingerprint.clone()),
        _ => None,
    };
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
        "tempUnit": g.temp_unit,
        "status": { "kind": status.kind(), "text": status.describe(), "fingerprint": fingerprint, "firmware": firmware },
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
) -> OpenActionResult<()> {
    instance
        .send_to_property_inspector(state_message(services, metric))
        .await
}

pub async fn handle(
    services: &Arc<Services>,
    metric: Metric,
    instance: &Instance,
    payload: &Value,
) -> OpenActionResult<()> {
    match serde_json::from_value::<Request>(payload.clone()) {
        Ok(req) => apply(services, req).await,
        Err(_) => {
            log::warn!("ignoring an unrecognised settings-panel message");
            return Ok(());
        }
    }
    send_state(services, metric, instance).await
}

async fn apply(services: &Arc<Services>, req: Request) {
    match req {
        Request::GetState => {}
        Request::SaveConnection {
            host,
            port,
            https,
            account,
            password,
        } => {
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
        }
        Request::SubmitOtp { code } => {
            if let Err(e) = services.submit_otp(&normalise_otp(&code)).await {
                log::info!("2FA sign-in failed: {e}");
            }
        }
        Request::TrustCertificate => services.trust_certificate().await,
        Request::SetTempUnit { unit } => services.set_temp_unit(unit).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::MemoryStore;
    use crate::services::testing::{healthy_nas, services_with};
    use crate::settings::GlobalSettings;
    use std::time::Duration;

    fn req(v: Value) -> Request {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn parses_panel_requests() {
        assert_eq!(req(json!({ "event": "getState" })), Request::GetState);
        assert_eq!(
            req(json!({ "event": "trustCertificate" })),
            Request::TrustCertificate
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
                port: 5001,
                https: true,
                account: "jf".into(),
                password: None
            }
        );
        assert!(serde_json::from_value::<Request>(json!({ "event": "reboot" })).is_err());
    }

    #[test]
    fn otp_code_is_normalised() {
        assert_eq!(normalise_otp(" 123 456\n"), "123456");
    }

    fn save(password: Option<&str>) -> Request {
        Request::SaveConnection {
            host: "nas.lan".into(),
            port: 5001,
            https: true,
            account: "jf".into(),
            password: password.map(str::to_string),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_password_is_never_echoed_or_saved_in_settings() {
        let (s, sink) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        apply(&s, save(Some("pw-secret"))).await;
        let msg = state_message(&s, Metric::Cpu);
        assert_eq!(msg["hasPassword"], true);
        assert!(!msg.to_string().contains("pw-secret"));
        assert!(
            !serde_json::to_string(&sink.last())
                .unwrap()
                .contains("pw-secret")
        );
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
    async fn state_lists_targets_and_defaults() {
        let (s, _) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        apply(&s, save(Some("pw"))).await;
        let _rx = s.poller(Endpoint::Storage).subscribe("k", None);
        tokio::time::timeout(Duration::from_secs(5), async {
            while s.poller(Endpoint::Storage).latest().value.is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let msg = state_message(&s, Metric::DiskTemp);
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
        assert_eq!(msg["connection"]["host"], "nas.lan");
    }
}
