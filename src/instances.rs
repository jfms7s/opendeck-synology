//! Keys and dials currently on screen. Each has a render task that redraws
//! when its endpoint's poll result, the connection status, the display
//! settings (°C/°F) or its dial view changes - so nothing redraws on a timer.

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
        let rx = services.poller(metric.endpoint()).subscribe(id);
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
    let mut display = services.display();
    // Unchanged readings aren't re-sent, so ten keys don't flood OpenDeck
    // with identical images every 5 s.
    let mut last: Option<Reading> = None;
    loop {
        let state = rx.borrow_and_update().clone();
        let conn = status.borrow_and_update().clone();
        let v = view.lock().unwrap().clone();
        let unit = *display.borrow_and_update();
        let reading = metrics::read(
            metric,
            &state,
            &v,
            &Context {
                status: &conn,
                unit,
            },
        );
        let frames = frames(last.as_ref(), &reading, is_key);
        if frames != Frames::Nothing
            && let Some(instance) = openaction::get_instance(id.clone()).await
        {
            match draw(&instance, metric, &reading, frames).await {
                Ok(()) => last = Some(reading),
                Err(e) => log::warn!("drawing {} failed: {e}", metric.uuid()),
            }
        }
        tokio::select! {
            changed = rx.changed() => if changed.is_err() { return },
            changed = status.changed() => if changed.is_err() { return },
            changed = display.changed() => if changed.is_err() { return },
            // An explicit redraw (appear, settings re-sent, dial turned) always draws.
            _ = redraw.notified() => last = None,
        }
    }
}

/// What a redraw sends to OpenDeck.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Frames {
    /// The reading didn't change: ten keys don't flood OpenDeck with
    /// identical images every 5 s.
    Nothing,
    /// A key's image, after clearing its native title when `clear_title`.
    KeyImage { clear_title: bool },
    /// A dial's touch-strip feedback.
    DialFeedback,
}

/// Whether and what to send for `next`, given what was last drawn (`None`:
/// nothing yet, or an explicit redraw - appear, settings re-sent, dial
/// turned - which always draws). The native title only needs clearing then:
/// a steady-state change is one frame.
fn frames(last: Option<&Reading>, next: &Reading, is_key: bool) -> Frames {
    if last == Some(next) {
        Frames::Nothing
    } else if is_key {
        Frames::KeyImage {
            clear_title: last.is_none(),
        }
    } else {
        Frames::DialFeedback
    }
}

async fn draw(
    instance: &Instance,
    metric: Metric,
    r: &Reading,
    frames: Frames,
) -> OpenActionResult<()> {
    match frames {
        Frames::Nothing => Ok(()),
        Frames::KeyImage { clear_title } => {
            // The text is inside the image; clear the native title so
            // OpenDeck doesn't paint a second copy on top.
            if clear_title {
                instance.set_title(Some(String::new()), None).await?;
            }
            instance
                .set_image(Some(key::key_image(metric, r)), None)
                .await
        }
        Frames::DialFeedback => instance.set_feedback(&dial::feedback(metric, r)).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metric::Endpoint;
    use crate::secrets::MemoryStore;
    use crate::services::testing::{conn, eventually, healthy_nas, services_with};
    use crate::settings::GlobalSettings;
    use std::time::Duration as StdDuration;

    #[test]
    fn only_a_changed_reading_is_sent_and_a_key_title_is_cleared_once() {
        use crate::metrics::Level;
        let a = Reading::new(Metric::Cpu, "37%", Level::Normal);
        let b = Reading::new(Metric::Cpu, "38%", Level::Normal);
        // Unchanged: nothing, key or dial.
        assert_eq!(frames(Some(&a), &a, true), Frames::Nothing);
        assert_eq!(frames(Some(&a), &a, false), Frames::Nothing);
        // Changed: one frame, the title left alone.
        assert_eq!(
            frames(Some(&a), &b, true),
            Frames::KeyImage { clear_title: false }
        );
        assert_eq!(frames(Some(&a), &b, false), Frames::DialFeedback);
        // First draw or explicit redraw: always drawn, a key's title cleared.
        assert_eq!(
            frames(None, &a, true),
            Frames::KeyImage { clear_title: true }
        );
        assert_eq!(frames(None, &a, false), Frames::DialFeedback);
    }

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
        // A key saved before 0.7.0 with its own interval still loads, and
        // polls at the endpoint default.
        let old: ActionSettings =
            serde_json::from_value(serde_json::json!({ "interval_secs": 3, "warn": 75.0 }))
                .expect("old settings still load");
        assert_eq!(old.warn, Some(75.0));
        live.show(&s, Metric::Cpu, "k1", true, old);
        assert_eq!(
            s.poller(Endpoint::Utilization).effective_interval(),
            Some(StdDuration::from_secs(5))
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
        eventually("storage polled", || {
            s.poller(Endpoint::Storage).latest().value.is_some()
        })
        .await;
        live.rotate(&s, "d1", 1);
        assert_eq!(live.view("d1").unwrap().target.as_deref(), Some("sata1"));
    }
}
