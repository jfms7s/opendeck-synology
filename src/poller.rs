//! One background poller per DSM endpoint. It runs only while some key or
//! dial is subscribed, at the shortest interval any of them asked for, and
//! broadcasts every result on a `watch` channel - so ten keys reading the
//! same endpoint cost one request per refresh.

use crate::dsm::error::DsmError;
use futures::future::BoxFuture;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, watch};
use tokio::time::Instant;

pub const MIN_INTERVAL: Duration = Duration::from_secs(2);
pub const MAX_BACKOFF: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub struct PollState<T> {
    /// Last good value - kept through failures, so keys go stale, not blank.
    pub value: Option<Arc<T>>,
    /// The latest attempt's error; cleared by the next success.
    pub error: Option<DsmError>,
    /// Consecutive failed attempts.
    pub failures: u32,
}

impl<T> Default for PollState<T> {
    fn default() -> Self {
        Self {
            value: None,
            error: None,
            failures: 0,
        }
    }
}

impl<T> Clone for PollState<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            error: self.error.clone(),
            failures: self.failures,
        }
    }
}

pub type Fetch<T> = Arc<dyn Fn() -> BoxFuture<'static, Result<T, DsmError>> + Send + Sync>;

/// How long to wait after `failures` consecutive failures: the interval
/// doubled per failure, capped at `MAX_BACKOFF` (but never below the interval).
pub fn backoff(interval: Duration, failures: u32) -> Duration {
    let factor = 2u32.saturating_pow(failures.min(16));
    interval
        .saturating_mul(factor)
        .min(MAX_BACKOFF.max(interval))
}

struct Registry<T> {
    subscribers: HashMap<String, Duration>,
    fetch: Option<Fetch<T>>,
    /// Bumped by `set_fetch`, so a request started on the old connection
    /// can't overwrite the new connection's state when it finishes. (The
    /// poller's own view of `Services`' connection epoch: `set_fetch` is
    /// called exactly when that epoch moves on.)
    generation: u64,
    running: bool,
    /// When the current connection last returned a value: data younger than
    /// the interval is not fetched again just because a key appeared.
    last_ok: Option<Instant>,
    /// When the last request on the current connection started; the
    /// backoff after a failure counts from here.
    last_attempt: Option<Instant>,
    /// Set by `refresh_now`: the next round polls even if the data is fresh.
    force: bool,
}

struct Inner<T> {
    default_interval: Duration,
    registry: Mutex<Registry<T>>,
    tx: watch::Sender<PollState<T>>,
    wake: Notify,
}

pub struct Poller<T> {
    inner: Arc<Inner<T>>,
}

impl<T: Send + Sync + 'static> Poller<T> {
    pub fn new(default_interval: Duration) -> Self {
        let (tx, _) = watch::channel(PollState::default());
        Self {
            inner: Arc::new(Inner {
                default_interval,
                registry: Mutex::new(Registry {
                    subscribers: HashMap::new(),
                    fetch: None,
                    generation: 0,
                    running: false,
                    last_ok: None,
                    last_attempt: None,
                    force: false,
                }),
                tx,
                wake: Notify::new(),
            }),
        }
    }

    /// Registers (or re-registers) a subscriber, starting the poll loop if
    /// it isn't running. `interval: None` means the endpoint's default.
    /// Polls right away unless the last value is younger than the (new)
    /// effective interval, or an outage's backoff is still running; fresh
    /// data is shared as is, and the next poll is rescheduled for the new
    /// interval.
    pub fn subscribe(&self, id: &str, interval: Option<Duration>) -> watch::Receiver<PollState<T>> {
        let interval = interval
            .unwrap_or(self.inner.default_interval)
            .max(MIN_INTERVAL);
        let rx = self.inner.tx.subscribe();
        let start = {
            let mut reg = self.inner.registry.lock().unwrap();
            reg.subscribers.insert(id.to_string(), interval);
            !std::mem::replace(&mut reg.running, true)
        };
        if start {
            tokio::spawn(run(self.inner.clone()));
        } else {
            self.inner.wake.notify_one();
        }
        rx
    }

    pub fn unsubscribe(&self, id: &str) {
        let running = {
            let mut reg = self.inner.registry.lock().unwrap();
            reg.subscribers.remove(id);
            reg.running
        };
        // Let the loop re-plan: longer interval, or exit if nobody is left.
        self.wake_if(running);
    }

    /// Swaps what a poll does - a new session after the settings changed, or
    /// `None` while unconfigured. Clears the last value: it belonged to the
    /// old connection.
    pub fn set_fetch(&self, fetch: Option<Fetch<T>>) {
        let running = {
            let mut reg = self.inner.registry.lock().unwrap();
            reg.fetch = fetch;
            reg.generation += 1;
            reg.last_ok = None;
            reg.last_attempt = None;
            reg.running
        };
        self.inner.tx.send_replace(PollState::default());
        self.wake_if(running);
    }

    /// Forgets the last attempt's error (and the failure count) but keeps the
    /// value - for when the cause was just fixed (a 2FA code accepted), so
    /// keys stop showing it before the next poll lands.
    pub fn clear_error(&self) {
        self.inner.tx.send_if_modified(|st| {
            let changed = st.error.is_some() || st.failures > 0;
            st.error = None;
            st.failures = 0;
            changed
        });
    }

    /// Polls now instead of waiting out the interval or a pause - even when
    /// the data is fresh.
    pub fn refresh_now(&self) {
        let running = {
            let mut reg = self.inner.registry.lock().unwrap();
            reg.force = reg.running;
            reg.running
        };
        self.wake_if(running);
    }

    /// `Notify` stores a permit when nobody is waiting; waking a loop that
    /// isn't running would leave one behind and cause a spurious extra poll
    /// right after the next start.
    fn wake_if(&self, running: bool) {
        if running {
            self.inner.wake.notify_one();
        }
    }

    #[cfg(test)]
    pub fn effective_interval(&self) -> Option<Duration> {
        self.inner
            .registry
            .lock()
            .unwrap()
            .subscribers
            .values()
            .min()
            .copied()
    }

    pub fn latest(&self) -> PollState<T> {
        self.inner.tx.borrow().clone()
    }
}

/// Marks the loop as stopped if a fetch panics, so the next `subscribe`
/// starts a new one instead of waking a loop that no longer exists. (A
/// normal exit clears the flag itself, under the same lock that saw no
/// subscribers left.)
struct Running<'a, T>(&'a Inner<T>);

impl<T> Drop for Running<'_, T> {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Ok(mut reg) = self.0.registry.lock()
        {
            reg.running = false;
        }
    }
}

/// When the next poll is due: `None` waits for `refresh_now` or a new
/// connection (an error only the user can fix).
fn next_due<T>(reg: &Registry<T>, st: &PollState<T>, interval: Duration) -> Option<Instant> {
    let now = Instant::now();
    match &st.error {
        Some(e) if e.needs_user() => None,
        // During an outage the backoff holds, however many keys come and go.
        Some(_) => Some(
            reg.last_attempt
                .map_or(now, |t| t + backoff(interval, st.failures)),
        ),
        None => Some(reg.last_ok.map_or(now, |t| t + interval)),
    }
}

async fn run<T: Send + Sync + 'static>(inner: Arc<Inner<T>>) {
    let _running = Running(&inner);
    loop {
        // Every wake-up (a key appearing or leaving, a new interval) only
        // re-plans; a poll happens when one is due, forced, or the
        // connection changed.
        let plan = {
            let mut reg = inner.registry.lock().unwrap();
            let Some(interval) = reg.subscribers.values().min().copied() else {
                reg.running = false;
                return;
            };
            let force = std::mem::take(&mut reg.force);
            let due = if force {
                Some(Instant::now())
            } else {
                next_due(&reg, &inner.tx.borrow(), interval)
            };
            match (reg.fetch.clone(), due) {
                (Some(fetch), Some(due)) if due <= Instant::now() => {
                    reg.last_attempt = Some(Instant::now());
                    Ok((fetch, reg.generation))
                }
                (None, _) => Err(None),
                (Some(_), due) => Err(due),
            }
        };
        let (fetch, generation) = match plan {
            Ok(p) => p,
            Err(Some(due)) => {
                tokio::select! {
                    _ = tokio::time::sleep_until(due) => {}
                    _ = inner.wake.notified() => {}
                }
                continue;
            }
            Err(None) => {
                inner.wake.notified().await;
                continue;
            }
        };
        let result = fetch().await;
        {
            let mut reg = inner.registry.lock().unwrap();
            if reg.generation != generation {
                continue; // the connection changed mid-request; discard
            }
            if result.is_ok() {
                reg.last_ok = Some(Instant::now());
            }
        }
        inner.tx.send_modify(|st| match result {
            Ok(v) => {
                *st = PollState {
                    value: Some(Arc::new(v)),
                    error: None,
                    failures: 0,
                }
            }
            Err(e) => {
                st.failures += 1;
                st.error = Some(e);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsm::error::AuthError;
    use std::sync::atomic::{AtomicU32, Ordering::SeqCst};

    fn counting(n: Arc<AtomicU32>) -> Fetch<u32> {
        Arc::new(move || {
            let n = n.clone();
            Box::pin(async move { Ok(n.fetch_add(1, SeqCst) + 1) })
        })
    }

    fn failing(n: Arc<AtomicU32>, err: DsmError) -> Fetch<u32> {
        Arc::new(move || {
            let (n, err) = (n.clone(), err.clone());
            Box::pin(async move {
                n.fetch_add(1, SeqCst);
                Err(err)
            })
        })
    }

    const S: fn(u64) -> Duration = Duration::from_secs;

    #[test]
    fn backoff_doubles_per_failure_up_to_five_minutes() {
        assert_eq!(backoff(S(5), 0), S(5));
        assert_eq!(backoff(S(5), 1), S(10));
        assert_eq!(backoff(S(5), 2), S(20));
        assert_eq!(backoff(S(5), 10), S(300));
        assert_eq!(
            backoff(S(6 * 3600), 3),
            S(6 * 3600),
            "never below the interval"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn polls_at_the_shortest_subscriber_interval() {
        let p = Poller::new(S(60));
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(counting(n.clone())));
        let _a = p.subscribe("a", Some(S(10)));
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(n.load(SeqCst), 1, "polls as soon as someone subscribes");
        let _b = p.subscribe("b", Some(S(5)));
        assert_eq!(p.effective_interval(), Some(S(5)));
        tokio::time::sleep(Duration::from_millis(20_500)).await;
        // No extra poll for the new subscriber (the data is fresh), but the
        // schedule tightens to every 5 s: at 5, 10, 15 and 20 s.
        assert_eq!(n.load(SeqCst), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_subscriber_reuses_fresh_data() {
        let p = Poller::new(S(60));
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(counting(n.clone())));
        let _a = p.subscribe("a", None);
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(n.load(SeqCst), 1);
        tokio::time::sleep(S(30)).await;
        let _b = p.subscribe("b", None);
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(
            n.load(SeqCst),
            1,
            "30 s old data is fresh at a 60 s interval"
        );
        tokio::time::sleep(S(30)).await;
        assert_eq!(n.load(SeqCst), 2, "the schedule is unchanged");
        p.refresh_now();
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(n.load(SeqCst), 3, "refresh_now still forces a poll");
    }

    #[tokio::test(start_paused = true)]
    async fn a_restart_within_the_interval_waits_out_the_rest_of_it() {
        let p = Poller::new(S(60));
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(counting(n.clone())));
        let _a = p.subscribe("a", None);
        tokio::time::sleep(Duration::from_millis(1)).await;
        p.unsubscribe("a");
        tokio::time::sleep(S(10)).await;
        let _b = p.subscribe("b", None);
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(
            n.load(SeqCst),
            1,
            "a page switch doesn't re-poll fresh data"
        );
        tokio::time::sleep(S(50)).await;
        assert_eq!(n.load(SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn stops_when_the_last_subscriber_leaves() {
        let p = Poller::new(S(5));
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(counting(n.clone())));
        let _a = p.subscribe("a", None);
        tokio::time::sleep(Duration::from_millis(1)).await;
        p.unsubscribe("a");
        tokio::time::sleep(S(60)).await;
        assert_eq!(n.load(SeqCst), 1);
        assert_eq!(p.effective_interval(), None);
        // ...and starts again for a new subscriber.
        let _b = p.subscribe("b", None);
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(n.load(SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn clamps_intervals_to_the_minimum() {
        let p: Poller<u32> = Poller::new(S(5));
        let _a = p.subscribe("a", Some(Duration::from_millis(100)));
        assert_eq!(p.effective_interval(), Some(MIN_INTERVAL));
    }

    #[tokio::test(start_paused = true)]
    async fn broadcasts_values_and_keeps_them_through_failures() {
        let p = Poller::new(S(5));
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(counting(n.clone())));
        let mut rx = p.subscribe("a", None);
        rx.changed().await.unwrap();
        assert_eq!(rx.borrow().value.as_deref(), Some(&1));

        p.set_fetch(Some(failing(n.clone(), DsmError::Transport("down".into()))));
        // set_fetch clears the old connection's value...
        assert!(p.latest().value.is_none());
        p.set_fetch(Some(counting(Arc::new(AtomicU32::new(41)))));
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(p.latest().value.as_deref(), Some(&42));
        // ...but a failure on the same connection keeps it.
        let fail = failing(n.clone(), DsmError::Transport("down".into()));
        p.inner.registry.lock().unwrap().fetch = Some(fail);
        p.refresh_now();
        tokio::time::sleep(Duration::from_millis(1)).await;
        let st = p.latest();
        assert_eq!(st.value.as_deref(), Some(&42));
        assert_eq!(st.failures, 1);
        assert_eq!(st.error, Some(DsmError::Transport("down".into())));
    }

    #[tokio::test(start_paused = true)]
    async fn backs_off_after_transport_errors() {
        let p = Poller::new(S(5));
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(failing(n.clone(), DsmError::Transport("down".into()))));
        let _a = p.subscribe("a", None);
        // Polls at t=0, then waits 10 s (1 failure), then 20 s (2 failures).
        tokio::time::sleep(Duration::from_millis(29_000)).await;
        assert_eq!(n.load(SeqCst), 2);
        tokio::time::sleep(Duration::from_millis(2_000)).await;
        assert_eq!(n.load(SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn pauses_on_errors_the_user_must_fix_until_woken() {
        let p = Poller::new(S(5));
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(failing(
            n.clone(),
            DsmError::Auth(AuthError::BadCredentials),
        )));
        let _a = p.subscribe("a", None);
        tokio::time::sleep(S(3600)).await;
        assert_eq!(n.load(SeqCst), 1, "no retry of a wrong password");
        p.refresh_now();
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(n.load(SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn clearing_the_error_keeps_the_value() {
        let p = Poller::new(S(5));
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(counting(n.clone())));
        let _a = p.subscribe("a", None);
        tokio::time::sleep(Duration::from_millis(1)).await;
        let fail = failing(n.clone(), DsmError::Auth(AuthError::NeedOtp));
        p.inner.registry.lock().unwrap().fetch = Some(fail);
        p.refresh_now();
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(p.latest().failures, 1);
        p.clear_error();
        let st = p.latest();
        assert_eq!(
            (st.value.as_deref(), st.error, st.failures),
            (Some(&1), None, 0)
        );
    }

    /// Fails until `ok` is set, then counts up from 100.
    fn flaky(n: Arc<AtomicU32>, ok: Arc<std::sync::atomic::AtomicBool>) -> Fetch<u32> {
        Arc::new(move || {
            let (n, ok) = (n.clone(), ok.clone());
            Box::pin(async move {
                let i = n.fetch_add(1, SeqCst);
                if ok.load(SeqCst) {
                    Ok(100 + i)
                } else {
                    Err(DsmError::Transport("down".into()))
                }
            })
        })
    }

    #[tokio::test(start_paused = true)]
    async fn recovers_after_an_outage_and_resets_the_backoff() {
        let p = Poller::new(S(5));
        let n = Arc::new(AtomicU32::new(0));
        let ok = Arc::new(std::sync::atomic::AtomicBool::new(false));
        p.set_fetch(Some(flaky(n.clone(), ok.clone())));
        let _a = p.subscribe("a", None);
        // Fails at 0, 10 and 30 s.
        tokio::time::sleep(Duration::from_millis(30_500)).await;
        assert_eq!((n.load(SeqCst), p.latest().failures), (3, 3));
        ok.store(true, SeqCst);
        p.refresh_now();
        tokio::time::sleep(Duration::from_millis(1)).await;
        let st = p.latest();
        assert_eq!(
            (st.value.is_some(), st.error, st.failures),
            (true, None, 0),
            "a success forgets the outage"
        );
        assert_eq!(n.load(SeqCst), 4);
        // Back to the plain interval, not the 40 s the fourth failure would wait.
        tokio::time::sleep(S(5)).await;
        assert_eq!(n.load(SeqCst), 5);
        tokio::time::sleep(S(5)).await;
        assert_eq!(n.load(SeqCst), 6);
    }

    #[tokio::test(start_paused = true)]
    async fn keys_appearing_during_an_outage_do_not_skip_the_backoff() {
        let p = Poller::new(S(5));
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(failing(n.clone(), DsmError::Transport("down".into()))));
        let _a = p.subscribe("a", None);
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(n.load(SeqCst), 1);
        // Page flips during the 10 s backoff.
        for i in 0..5 {
            let id = format!("k{i}");
            let _rx = p.subscribe(&id, None);
            tokio::time::sleep(Duration::from_millis(1)).await;
            p.unsubscribe(&id);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(n.load(SeqCst), 1, "no request per page flip");
        tokio::time::sleep(S(10)).await;
        assert_eq!(n.load(SeqCst), 2, "the backoff still ends on time");
    }

    #[tokio::test(start_paused = true)]
    async fn a_value_goes_stale_seven_intervals_after_the_last_success() {
        let p = Poller::new(S(5));
        let n = Arc::new(AtomicU32::new(0));
        let ok = Arc::new(std::sync::atomic::AtomicBool::new(true));
        p.set_fetch(Some(flaky(n.clone(), ok.clone())));
        let _a = p.subscribe("a", None);
        tokio::time::sleep(Duration::from_millis(1)).await;
        ok.store(false, SeqCst);
        // Failures at 5, 15 and 35 s: the third one marks the value stale.
        tokio::time::sleep(Duration::from_millis(34_000)).await;
        assert_eq!(p.latest().failures, 2);
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        assert_eq!(p.latest().failures, crate::metrics::STALE_AFTER);
        assert!(p.latest().value.is_some(), "the last value is kept");
    }

    #[tokio::test(start_paused = true)]
    async fn a_result_from_the_old_connection_is_discarded() {
        let p = Poller::new(S(60));
        let slow: Fetch<u32> = Arc::new(|| {
            Box::pin(async {
                tokio::time::sleep(S(5)).await;
                Ok(1)
            })
        });
        p.set_fetch(Some(slow));
        let _a = p.subscribe("a", None);
        tokio::time::sleep(S(1)).await;
        let never: Fetch<u32> = Arc::new(|| Box::pin(std::future::pending()));
        p.set_fetch(Some(never));
        tokio::time::sleep(S(10)).await;
        assert_eq!(
            p.latest().value,
            None,
            "the old request's answer is dropped"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_panicking_fetch_leaves_the_poller_restartable() {
        let p = Poller::new(S(5));
        let boom: Fetch<u32> = Arc::new(|| Box::pin(async { panic!("malformed reply") }));
        p.set_fetch(Some(boom));
        let _a = p.subscribe("a", None);
        tokio::time::sleep(Duration::from_millis(1)).await;
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(counting(n.clone())));
        let _b = p.subscribe("b", None);
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(n.load(SeqCst), 1, "a new loop started");
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_fetch_it_idles_until_one_is_set() {
        let p = Poller::new(S(5));
        let mut rx = p.subscribe("a", None);
        tokio::time::sleep(S(60)).await;
        assert!(rx.borrow_and_update().value.is_none());
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(counting(n.clone())));
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(n.load(SeqCst), 1);
    }
}
