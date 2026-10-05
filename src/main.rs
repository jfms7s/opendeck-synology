mod actions;
mod dsm;
mod format;
mod inspector;
mod instances;
mod metric;
mod metrics;
mod poller;
mod render;
mod secrets;
mod services;
mod settings;
mod status;

use async_trait::async_trait;
use dsm::transport::{HttpTransport, Target, Transport};
use instances::Instances;
use openaction::global_events::{
    DidReceiveGlobalSettingsEvent, GlobalEventHandler, set_global_event_handler,
};
use openaction::{OpenActionResult, run};
use secrets::KeyringStore;
use services::{Services, SettingsSink, TransportFactory};
use settings::GlobalSettings;
use std::sync::Arc;

/// Persists plugin-wide settings through OpenDeck.
struct OpenDeckSettings;

#[async_trait]
impl SettingsSink for OpenDeckSettings {
    async fn save(&self, settings: &GlobalSettings) {
        if let Err(e) = openaction::set_global_settings(settings).await {
            log::warn!("saving the plugin settings failed: {e}");
        }
    }
}

struct GlobalEvents {
    services: Arc<Services>,
}

#[async_trait]
impl GlobalEventHandler for GlobalEvents {
    async fn plugin_ready(&self) -> OpenActionResult<()> {
        openaction::get_global_settings().await
    }

    async fn did_receive_global_settings(
        &self,
        event: DidReceiveGlobalSettingsEvent,
    ) -> OpenActionResult<()> {
        let (settings, unreadable) = GlobalSettings::from_value_lenient(&event.payload.settings);
        if !unreadable.is_empty() {
            log::warn!(
                "unreadable plugin settings {unreadable:?}: using their defaults, keeping the rest"
            );
        }
        self.services.receive_global(settings);
        Ok(())
    }
}

// Two workers are plenty for one NAS connection and a handful of keys;
// keyring calls run on the blocking pool.
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> OpenActionResult<()> {
    // A start-and-exit check that needs no OpenDeck (the release workflow
    // runs the aarch64 build this way under emulation).
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    simplelog::SimpleLogger::init(log::LevelFilter::Info, simplelog::Config::default())
        .expect("logger init");

    let device_name = format!("OpenDeck-{}", gethostname::gethostname().to_string_lossy());
    let transports: TransportFactory =
        Arc::new(|t: &Target| Ok(Arc::new(HttpTransport::new(t)?) as Arc<dyn Transport>));
    let services = Services::new(
        Arc::new(KeyringStore),
        Arc::new(OpenDeckSettings),
        transports,
        device_name,
    );
    let instances = Arc::new(Instances::default());

    // openaction keeps a 'static reference; the handler lives as long as the process.
    set_global_event_handler(Box::leak(Box::new(GlobalEvents {
        services: services.clone(),
    })));
    actions::register_all(&services, &instances).await;

    let result = run(std::env::args().collect()).await;
    // OpenDeck closed the connection: end the DSM session instead of leaving
    // it to time out.
    services.logout().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsm::endpoint::Endpoint;
    use crate::secrets::{MemoryStore, password_key};
    use crate::services::testing::{conn, eventually, healthy_nas, services_with, wait_for_value};
    use crate::settings::TempUnit;
    use crate::status::ConnStatus;
    use std::time::Duration;

    fn settings_event(g: &GlobalSettings) -> DidReceiveGlobalSettingsEvent {
        serde_json::from_value(serde_json::json!({ "payload": { "settings": g } })).unwrap()
    }

    /// openaction handles one event at a time. While the keyring waits for
    /// the user (macOS's Keychain access prompt after an update, a locked
    /// Secret Service), the settings handler must not hold up every key
    /// press and panel message behind it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_keyring_prompt_does_not_hold_up_other_events() {
        let secrets = Arc::new(MemoryStore::gated(&[(
            &password_key(&conn().secret_scope()),
            "pw",
        )]));
        let (services, _) = services_with(healthy_nas(), secrets.clone());
        let mut key = services
            .poller(Endpoint::Utilization)
            .subscribe("key-1", None);
        let events = GlobalEvents {
            services: services.clone(),
        };
        let first = GlobalSettings {
            connection: conn(),
            ..GlobalSettings::default()
        };
        let second = GlobalSettings {
            temp_unit: TempUnit::Fahrenheit,
            ..first.clone()
        };

        for g in [&first, &second] {
            tokio::time::timeout(
                Duration::from_millis(500),
                events.did_receive_global_settings(settings_event(g)),
            )
            .await
            .expect("the settings handler waited for the keyring")
            .unwrap();
        }
        eventually("keys say the plugin waits for the keyring", || {
            services.current_status() == ConnStatus::KeyringPending
        })
        .await;

        secrets.open_gate();
        eventually("connected once the prompt is answered", || {
            matches!(services.current_status(), ConnStatus::Connected { .. })
        })
        .await;
        wait_for_value(&mut key).await;
        eventually("later settings applied after earlier ones", || {
            services.global() == second
        })
        .await;
    }
}
