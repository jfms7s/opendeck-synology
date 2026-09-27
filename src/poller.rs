//! One background poller per DSM endpoint. It runs only while some key or
//! dial is subscribed, at the shortest interval any of them asked for, and
//! broadcasts every result on a `watch` channel - so ten keys reading the
//! same endpoint cost one request per refresh.

use crate::dsm::error::DsmError;
use futures::FutureExt;
use futures::future::BoxFuture;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, watch};

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
    /// can't overwrite the new connection's state when it finishes.
    generation: u64,
    running: bool,
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
                }),
                tx,
                wake: Notify::new(),
            }),
        }
    }

    /// Registers (or re-registers) a subscriber, starting the poll loop if
    /// it isn't running. `interval: None` means the endpoint's default.
    /// Also triggers an immediate poll, so a new key gets fresh data.
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
            reg.running
        };
        self.inner.tx.send_replace(PollState::default());
        self.wake_if(running);
    }

    /// Polls now instead of waiting out the interval or a pause.
    pub fn refresh_now(&self) {
        let running = self.inner.registry.lock().unwrap().running;
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

async fn run<T: Send + Sync + 'static>(inner: Arc<Inner<T>>) {
    loop {
        // Drain a stale wake permit before reading state: `Notify` stores at
        // most one permit, but two `notify_one` calls with no `await`
        // between them (e.g. two `set_fetch`s back to back) can each find
        // no registered waiter and each store one, one after the other. We
        // are about to read the freshest registry state anyway, so any
        // permit already sitting here is redundant and would otherwise fire
        // the `select!` below immediately, causing a spurious extra poll.
        let _ = inner.wake.notified().now_or_never();
        let (interval, fetch, generation) = {
            let mut reg = inner.registry.lock().unwrap();
            let Some(interval) = reg.subscribers.values().min().copied() else {
                reg.running = false;
                return;
            };
            (interval, reg.fetch.clone(), reg.generation)
        };
        // `None` = wait until woken (unconfigured, or an error only the user can fix).
        let wait = match fetch {
            None => None,
            Some(fetch) => {
                let result = fetch().await;
                if inner.registry.lock().unwrap().generation != generation {
                    continue; // the connection changed mid-request; discard
                }
                let mut next = inner.tx.borrow().clone();
                let wait = match result {
                    Ok(v) => {
                        next = PollState {
                            value: Some(Arc::new(v)),
                            error: None,
                            failures: 0,
                        };
                        Some(interval)
                    }
                    Err(e) => {
                        next.failures += 1;
                        let wait = (!e.needs_user()).then(|| backoff(interval, next.failures));
                        next.error = Some(e);
                        wait
                    }
                };
                inner.tx.send_replace(next);
                wait
            }
        };
        match wait {
            Some(d) => {
                tokio::select! {
                    _ = tokio::time::sleep(d) => {}
                    _ = inner.wake.notified() => {}
                }
            }
            None => inner.wake.notified().await,
        }
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
        // One immediate poll for the new subscriber, then every 5 s.
        assert_eq!(n.load(SeqCst), 6);
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
