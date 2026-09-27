//! Keys and dials currently on screen. Each has a render task that redraws
//! when its endpoint's poll result, the connection status, or its dial view
//! changes - so nothing redraws on a timer.

use crate::dsm::model::Payload;
use crate::metric::Metric;
use crate::metrics::{self, Context, Reading};
use crate::poller::PollState;
use crate::render::{dial, key};
use crate::services::Services;
use crate::settings::ActionSettings;
use dashmap::DashMap;
use openaction::{Instance, OpenActionResult};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;

struct Live {
    metric: Metric,
    /// As saved; a change re-subscribes and resets the view.
    settings: ActionSettings,
    /// The settings as turned on the dial (never saved).
    view: Arc<Mutex<ActionSettings>>,
    redraw: Arc<Notify>,
    task: JoinHandle<()>,
}

#[derive(Default)]
pub struct Instances {
    live: DashMap<String, Live>,
}

impl Instances {
    pub fn show(
        &self,
        services: &Arc<Services>,
        metric: Metric,
        id: &str,
        is_key: bool,
        settings: ActionSettings,
    ) {
        if let Some(l) = self.live.get(id)
            && l.settings == settings
        {
            l.redraw.notify_one();
            return;
        }
        self.hide(services, id);
        let interval = settings.interval_secs.map(Duration::from_secs);
        let rx = services.poller(metric.endpoint()).subscribe(id, interval);
        let view = Arc::new(Mutex::new(settings.clone()));
        let redraw = Arc::new(Notify::new());
        let task = tokio::spawn(render_loop(
            services.clone(),
            metric,
            id.to_string(),
            is_key,
            rx,
            view.clone(),
            redraw.clone(),
        ));
        self.live.insert(
            id.to_string(),
            Live {
                metric,
                settings,
                view,
                redraw,
                task,
            },
        );
    }

    pub fn hide(&self, services: &Services, id: &str) {
        if let Some((_, l)) = self.live.remove(id) {
            l.task.abort();
            services.poller(l.metric.endpoint()).unsubscribe(id);
        }
    }

    pub fn rotate(&self, services: &Services, id: &str, ticks: i16) {
        let Some(l) = self.live.get(id) else { return };
        let latest = services.poller(l.metric.endpoint()).latest();
        metrics::rotate(
            l.metric,
            &mut l.view.lock().unwrap(),
            latest.value.as_deref(),
            ticks,
        );
        l.redraw.notify_one();
    }

    #[cfg(test)]
    pub fn view(&self, id: &str) -> Option<ActionSettings> {
        self.live.get(id).map(|l| l.view.lock().unwrap().clone())
    }
}

async fn render_loop(
    services: Arc<Services>,
    metric: Metric,
    id: String,
    is_key: bool,
    mut rx: watch::Receiver<PollState<Payload>>,
    view: Arc<Mutex<ActionSettings>>,
    redraw: Arc<Notify>,
) {
    let mut status = services.status();
    // Unchanged readings aren't re-sent, so ten keys don't flood OpenDeck
    // with identical images every 5 s.
    let mut last: Option<Reading> = None;
    loop {
        let state = rx.borrow_and_update().clone();
        let conn = status.borrow_and_update().clone();
        let v = view.lock().unwrap().clone();
        let unit = services.global().temp_unit;
        let reading = metrics::read(
            metric,
            &state,
            &v,
            &Context {
                status: &conn,
                unit,
            },
        );
        if last.as_ref() != Some(&reading)
            && let Some(instance) = openaction::get_instance(id.clone()).await
        {
            match draw(&instance, metric, &reading, is_key).await {
                Ok(()) => last = Some(reading),
                Err(e) => log::warn!("drawing {} failed: {e}", metric.uuid()),
            }
        }
        tokio::select! {
            changed = rx.changed() => if changed.is_err() { return },
            changed = status.changed() => if changed.is_err() { return },
            // An explicit redraw (appear, settings re-sent, dial turned) always draws.
            _ = redraw.notified() => last = None,
        }
    }
}

async fn draw(
    instance: &Instance,
    metric: Metric,
    r: &Reading,
    is_key: bool,
) -> OpenActionResult<()> {
    if is_key {
        // The text is inside the image; clear the native title so OpenDeck
        // doesn't paint a second copy on top.
        instance.set_title(Some(String::new()), None).await?;
        instance
            .set_image(Some(key::key_image(metric, r)), None)
            .await
    } else {
        instance.set_feedback(&dial::feedback(metric, r)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metric::Endpoint;
    use crate::secrets::MemoryStore;
    use crate::services::testing::{conn, healthy_nas, services_with};
    use crate::settings::GlobalSettings;
    use std::time::Duration as StdDuration;

    async fn connected_services() -> Arc<Services> {
        let (s, _) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        s
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn showing_subscribes_and_hiding_unsubscribes() {
        let s = connected_services().await;
        let live = Instances::default();
        live.show(&s, Metric::Cpu, "k1", true, ActionSettings::default());
        assert_eq!(
            s.poller(Endpoint::Utilization).effective_interval(),
            Some(StdDuration::from_secs(5))
        );
        let faster = ActionSettings {
            interval_secs: Some(3),
            ..ActionSettings::default()
        };
        live.show(&s, Metric::Cpu, "k1", true, faster);
        assert_eq!(
            s.poller(Endpoint::Utilization).effective_interval(),
            Some(StdDuration::from_secs(3))
        );
        live.hide(&s, "k1");
        assert_eq!(s.poller(Endpoint::Utilization).effective_interval(), None);
        assert!(live.view("k1").is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn new_settings_reset_the_dial_view() {
        let s = connected_services().await;
        let live = Instances::default();
        live.show(&s, Metric::Cpu, "d1", false, ActionSettings::default());
        live.rotate(&s, "d1", 1);
        assert_eq!(
            live.view("d1").unwrap().cpu_view,
            crate::settings::CpuView::Load1
        );
        live.show(&s, Metric::Cpu, "d1", false, ActionSettings::default());
        assert_eq!(
            live.view("d1").unwrap().cpu_view,
            crate::settings::CpuView::Load1,
            "same settings keep it"
        );
        let other = ActionSettings {
            warn: Some(50.0),
            ..ActionSettings::default()
        };
        live.show(&s, Metric::Cpu, "d1", false, other);
        assert_eq!(
            live.view("d1").unwrap().cpu_view,
            crate::settings::CpuView::Total
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rotating_a_disk_dial_uses_the_latest_storage_data() {
        let s = connected_services().await;
        let live = Instances::default();
        live.show(&s, Metric::DiskTemp, "d1", false, ActionSettings::default());
        tokio::time::timeout(StdDuration::from_secs(5), async {
            while s.poller(Endpoint::Storage).latest().value.is_none() {
                tokio::time::sleep(StdDuration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        live.rotate(&s, "d1", 1);
        assert_eq!(live.view("d1").unwrap().target.as_deref(), Some("sata1"));
    }
}
