//! The ten actions. They differ only in which metric they show, so one
//! generic `MetricAction` is instantiated per metric through a marker type;
//! everything metric-specific lives in `metrics`.

use crate::inspector;
use crate::instances::Instances;
use crate::metric::Metric;
use crate::services::Services;
use crate::settings::ActionSettings;
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

macro_rules! kinds {
    ($($name:ident),* $(,)?) => {
        $(
            pub struct $name;
            impl MetricKind for $name {
                const METRIC: Metric = Metric::$name;
            }
        )*
    };
}

kinds!(
    Cpu, Ram, Network, SysTemp, Uptime, DiskTemp, DiskHealth, Volume, Pool, Update
);

pub struct MetricAction<K> {
    services: Arc<Services>,
    instances: Arc<Instances>,
    _kind: PhantomData<fn() -> K>,
}

impl<K: MetricKind> MetricAction<K> {
    pub fn new(services: Arc<Services>, instances: Arc<Instances>) -> Self {
        Self {
            services,
            instances,
            _kind: PhantomData,
        }
    }

    fn refresh(&self) {
        self.services.poller(K::METRIC.endpoint()).refresh_now();
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

    async fn key_up(&self, _: &Instance, _: &ActionSettings) -> OpenActionResult<()> {
        self.refresh();
        Ok(())
    }

    async fn dial_up(&self, _: &Instance, _: &ActionSettings) -> OpenActionResult<()> {
        self.refresh();
        Ok(())
    }

    async fn touch_tap(
        &self,
        _: &Instance,
        _: &ActionSettings,
        _: (u16, u16),
        _: bool,
    ) -> OpenActionResult<()> {
        self.refresh();
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
        inspector::send_state(&self.services, K::METRIC, instance).await
    }

    async fn send_to_plugin(
        &self,
        instance: &Instance,
        _: &ActionSettings,
        payload: &Value,
    ) -> OpenActionResult<()> {
        inspector::handle(&self.services, K::METRIC, instance, payload).await
    }
}

pub async fn register_all(services: &Arc<Services>, instances: &Arc<Instances>) {
    macro_rules! register {
        ($($kind:ident),*) => {
            $( register_action(MetricAction::<$kind>::new(services.clone(), instances.clone())).await; )*
        };
    }
    register!(
        Cpu, Ram, Network, SysTemp, Uptime, DiskTemp, DiskHealth, Volume, Pool, Update
    );
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
