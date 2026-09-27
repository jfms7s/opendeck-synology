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
use dsm::transport::{HttpTransport, Transport};
use instances::Instances;
use openaction::global_events::{
    DidReceiveGlobalSettingsEvent, GlobalEventHandler, set_global_event_handler,
};
use openaction::{OpenActionResult, run};
use secrets::KeyringStore;
use services::{Services, SettingsSink, TransportFactory};
use settings::{Connection, GlobalSettings};
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
        let settings = serde_json::from_value(event.payload.settings).unwrap_or_else(|e| {
            log::warn!("unreadable plugin settings, starting from defaults: {e}");
            GlobalSettings::default()
        });
        self.services.load_global(settings).await;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> OpenActionResult<()> {
    simplelog::SimpleLogger::init(log::LevelFilter::Info, simplelog::Config::default())
        .expect("logger init");

    let device_name = format!("OpenDeck-{}", gethostname::gethostname().to_string_lossy());
    let transports: TransportFactory =
        Arc::new(|conn: &Connection| Ok(Arc::new(HttpTransport::new(conn)?) as Arc<dyn Transport>));
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
