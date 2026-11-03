//! The eleven actions. They differ only in which metric they show, so one
//! generic `MetricAction` is instantiated per metric through a marker type;
//! everything metric-specific lives in `metrics`.

use crate::inspector::{self, PanelInbox, PanelWatchers};
use crate::instances::Instances;
use crate::metric::Metric;
use crate::services::Services;
use crate::settings::ActionSettings;
use crate::settings::{Connection, PressAction};
use crate::status::ConnStatus;
use async_trait::async_trait;
use openaction::{Action, Instance, OpenActionResult, register_action};
use serde_json::Value;
use std::marker::PhantomData;
use std::sync::Arc;

/// The wire value OpenDeck sends as `Instance::controller` for a key
/// (a dial is `"Encoder"`).
const KEYPAD: &str = "Keypad";

pub trait MetricKind: Send + Sync + 'static {
    const METRIC: Metric;
}

/// Declares one marker type per metric and `register_all`, which registers
/// an action for each - from this one list, so no action can be declared
/// but never registered.
macro_rules! kinds {
    ($($name:ident),* $(,)?) => {
        $(
            pub struct $name;
            impl MetricKind for $name {
                const METRIC: Metric = Metric::$name;
            }
        )*

        /// The metric of every action `register_all` registers.
        #[cfg(test)]
        pub const REGISTERED: &[Metric] = &[$(Metric::$name),*];

        pub async fn register_all(
            services: &Arc<Services>,
            instances: &Arc<Instances>,
            panel: &PanelInbox,
        ) {
            $( register_action(MetricAction::<$name>::new(services.clone(), instances.clone(), panel.clone())).await; )*
        }
    };
}

kinds!(
    Cpu, Ram, Network, SysTemp, DiskTemp, DiskHealth, Volume, Pool, Health, StorageIo, Update
);

pub struct MetricAction<K> {
    services: Arc<Services>,
    instances: Arc<Instances>,
    panel: PanelInbox,
    /// Pushes state to this action's open settings panels.
    watchers: PanelWatchers,
    _kind: PhantomData<fn() -> K>,
}

impl<K: MetricKind> MetricAction<K> {
    pub fn new(services: Arc<Services>, instances: Arc<Instances>, panel: PanelInbox) -> Self {
        Self {
            services,
            instances,
            panel,
            watchers: PanelWatchers::default(),
            _kind: PhantomData,
        }
    }

    fn refresh(&self) {
        self.services.refresh(K::METRIC.endpoint());
    }

    /// A key press, dial push or touch tap: refreshes, or opens DSM in the
    /// browser when the key is set to. While the keyring refuses the
    /// password, a press is how the user asks it again, so it refreshes.
    async fn press(&self, settings: &ActionSettings) {
        let refused = matches!(
            self.services.current_status(),
            ConnStatus::KeyringRefused(_)
        );
        let url = press_url(settings.press, &self.services.global().connection);
        match url.filter(|_| !refused) {
            Some(url) => {
                if let Err(e) = openaction::open_url(url).await {
                    log::warn!("couldn't ask OpenDeck to open DSM: {e}");
                }
            }
            None => self.refresh(),
        }
    }
}

/// The page a press opens, or `None` to refresh. Only the configured NAS's
/// own address: no account, session id or other secret, and only HTTPS
/// (a connection from before 0.7.0 saved as HTTP never connects).
pub fn press_url(press: PressAction, conn: &Connection) -> Option<String> {
    match press {
        PressAction::Refresh => None,
        // A host with userinfo, a query or a fragment in it could name
        // another site than the NAS: refresh instead of opening it.
        PressAction::Dsm
            if conn.is_complete()
                && conn.https
                && !conn
                    .host()
                    .contains(|c: char| c.is_whitespace() || "@?#\\%".contains(c)) =>
        {
            Some(format!("{}/", conn.base_url()))
        }
        PressAction::Dsm => None,
    }
}

#[async_trait]
impl<K: MetricKind> Action for MetricAction<K> {
    const UUID: &'static str = K::METRIC.uuid();
    type Settings = ActionSettings;

    async fn will_appear(
        &self,
        instance: &Instance,
        settings: &ActionSettings,
    ) -> OpenActionResult<()> {
        let is_key = instance.controller == KEYPAD;
        self.instances.show(
            &self.services,
            K::METRIC,
            &instance.instance_id,
            is_key,
            settings.clone(),
        );
        Ok(())
    }

    async fn did_receive_settings(
        &self,
        instance: &Instance,
        settings: &ActionSettings,
    ) -> OpenActionResult<()> {
        self.will_appear(instance, settings).await
    }

    async fn will_disappear(
        &self,
        instance: &Instance,
        _: &ActionSettings,
    ) -> OpenActionResult<()> {
        self.instances.hide(&self.services, &instance.instance_id);
        Ok(())
    }

    async fn key_up(&self, _: &Instance, settings: &ActionSettings) -> OpenActionResult<()> {
        self.press(settings).await;
        Ok(())
    }

    async fn dial_up(&self, _: &Instance, settings: &ActionSettings) -> OpenActionResult<()> {
        self.press(settings).await;
        Ok(())
    }

    async fn touch_tap(
        &self,
        _: &Instance,
        settings: &ActionSettings,
        _: (u16, u16),
        _: bool,
    ) -> OpenActionResult<()> {
        self.press(settings).await;
        Ok(())
    }

    async fn dial_rotate(
        &self,
        instance: &Instance,
        _: &ActionSettings,
        ticks: i16,
        _: bool,
    ) -> OpenActionResult<()> {
        self.instances
            .rotate(&self.services, &instance.instance_id, ticks);
        Ok(())
    }

    async fn property_inspector_did_appear(
        &self,
        instance: &Instance,
        _: &ActionSettings,
    ) -> OpenActionResult<()> {
        self.watchers
            .start(&self.services, K::METRIC, &instance.instance_id);
        inspector::send_state(&self.services, K::METRIC, instance, None).await
    }

    async fn property_inspector_did_disappear(
        &self,
        instance: &Instance,
        _: &ActionSettings,
    ) -> OpenActionResult<()> {
        self.watchers.stop(&instance.instance_id);
        Ok(())
    }

    async fn send_to_plugin(
        &self,
        instance: &Instance,
        _: &ActionSettings,
        payload: &Value,
    ) -> OpenActionResult<()> {
        inspector::handle(&self.services, &self.panel, K::METRIC, instance, payload).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn manifest() -> Value {
        serde_json::from_str(include_str!("../assets/manifest.json")).unwrap()
    }

    #[test]
    fn every_metric_is_in_the_manifest_on_keys_and_dials() {
        let m = manifest();
        let actions = m["Actions"].as_array().unwrap();
        assert_eq!(actions.len(), Metric::ALL.len());
        for metric in Metric::ALL {
            let a = actions
                .iter()
                .find(|a| a["UUID"] == metric.uuid())
                .unwrap_or_else(|| panic!("{metric:?} missing"));
            assert_eq!(a["Controllers"], serde_json::json!(["Keypad", "Encoder"]));
            assert_eq!(a["Encoder"]["layout"], "layouts/metric.json");
            let icon = a["Icon"].as_str().unwrap();
            let png = format!("{}/assets/{icon}.png", env!("CARGO_MANIFEST_DIR"));
            assert!(
                std::path::Path::new(&png).exists(),
                "{png} missing - run scripts/render-icons.sh"
            );
        }
        assert_eq!(m["Category"], "Synology");
    }

    #[test]
    fn every_metric_gets_an_action() {
        let mut registered = REGISTERED.to_vec();
        registered.dedup();
        assert_eq!(registered.len(), Metric::ALL.len());
        for m in Metric::ALL {
            assert!(REGISTERED.contains(&m), "{m:?} is never registered");
        }
    }

    fn nas(host: &str) -> Connection {
        Connection {
            host: host.into(),
            account: "jf".into(),
            ..Connection::default()
        }
    }

    #[test]
    fn refresh_opens_nothing() {
        assert_eq!(press_url(PressAction::Refresh, &nas("nas.lan")), None);
    }

    #[test]
    fn open_dsm_opens_the_configured_nas() {
        assert_eq!(
            press_url(PressAction::Dsm, &nas("nas.lan")).as_deref(),
            Some("https://nas.lan:5001/")
        );
        let c = Connection {
            port: 443,
            ..nas("https://nas.lan:5001/webman")
        };
        assert_eq!(
            press_url(PressAction::Dsm, &c).as_deref(),
            Some("https://nas.lan:443/")
        );
    }

    #[test]
    fn open_dsm_brackets_an_ipv6_host() {
        assert_eq!(
            press_url(PressAction::Dsm, &nas("fe80::1")).as_deref(),
            Some("https://[fe80::1]:5001/")
        );
    }

    #[test]
    fn open_dsm_without_a_usable_connection_refreshes() {
        assert_eq!(press_url(PressAction::Dsm, &Connection::default()), None);
        assert_eq!(press_url(PressAction::Dsm, &nas("  ")), None);
        let http = Connection {
            https: false,
            ..nas("nas.lan")
        };
        assert_eq!(press_url(PressAction::Dsm, &http), None);
    }

    #[test]
    fn open_dsm_never_opens_a_host_that_could_point_elsewhere() {
        for host in [
            "nas.lan@evil.example",
            "nas.lan?x=evil.example",
            "nas.lan#evil",
            "nas lan",
            "nas%2elan",
            "nas.lan\\evil.example",
        ] {
            assert_eq!(press_url(PressAction::Dsm, &nas(host)), None, "{host}");
        }
    }

    #[test]
    fn the_dsm_url_carries_no_account_or_session() {
        let c = Connection {
            account: "secret-admin".into(),
            pinned_sha256: Some("ab".repeat(32)),
            ..nas("nas.lan")
        };
        let url = press_url(PressAction::Dsm, &c).unwrap();
        for leak in ["secret-admin", "@", "sid", "_sid", "?", "abab"] {
            assert!(!url.contains(leak), "{url} contains {leak}");
        }
    }

    #[test]
    fn action_uuids_come_from_the_metric() {
        assert_eq!(
            <MetricAction<Cpu> as Action>::UUID,
            "com.jfms7s.synology.cpu"
        );
        assert_eq!(
            <MetricAction<Pool> as Action>::UUID,
            "com.jfms7s.synology.pool"
        );
    }
}
