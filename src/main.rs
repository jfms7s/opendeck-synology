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
        self.services.load_global(settings).await;
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
