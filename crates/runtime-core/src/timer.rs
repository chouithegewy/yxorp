//! Userspace timer wheel plus `sleep` / `timeout`.
//!
//! Thousands of sleeping futures collapse to a single kernel wait deadline: the
//! executor asks the wheel for the nearest deadline each idle iteration and passes it
//! as the ring-wait timeout, then expires due timers after draining completions. No
//! per-timer timeout SQE.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use crate::executor::with_timers;

pub(crate) struct TimerWheel {
    next_id: u64,
    /// Ordered by (deadline, id) so the earliest deadline is the first key.
    timers: BTreeMap<(Instant, u64), Waker>,
    /// id -> deadline, for updating the parked waker and cancelling on drop.
    by_id: HashMap<u64, Instant>,
}

impl TimerWheel {
    pub fn new() -> Self {
        TimerWheel {
            next_id: 1,
            timers: BTreeMap::new(),
            by_id: HashMap::new(),
        }
    }

    /// Arm a timer for `deadline`, returning its id.
    fn register(&mut self, deadline: Instant, waker: Waker) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.timers.insert((deadline, id), waker);
        self.by_id.insert(id, deadline);
        id
    }

    /// Replace the parked waker for an armed timer (called on re-poll).
    fn update_waker(&mut self, id: u64, waker: Waker) {
        if let Some(&deadline) = self.by_id.get(&id) {
            self.timers.insert((deadline, id), waker);
        }
    }

    /// Disarm a timer. Tolerant of already-fired/absent ids.
    fn cancel(&mut self, id: u64) {
        if let Some(deadline) = self.by_id.remove(&id) {
            self.timers.remove(&(deadline, id));
        }
    }

    /// Nearest deadline as a relative duration (`ZERO` if already due), or `None`.
    pub fn next_timeout(&self) -> Option<Duration> {
        self.timers
            .keys()
            .next()
            .map(|(deadline, _)| deadline.saturating_duration_since(Instant::now()))
    }

    /// Wake and remove every timer whose deadline has passed.
    pub fn expire(&mut self) {
        let now = Instant::now();
        while let Some((&(deadline, id), _)) = self.timers.iter().next() {
            if deadline > now {
                break;
            }
            let waker = self.timers.remove(&(deadline, id)).expect("just observed");
            self.by_id.remove(&id);
            waker.wake();
        }
    }

    pub fn is_empty(&self) -> bool {
        self.timers.is_empty()
    }
}

/// A future that completes once its deadline passes.
pub struct Sleep {
    deadline: Instant,
    id: Option<u64>,
    done: bool,
}

/// Sleep until `dur` from now has elapsed.
pub fn sleep(dur: Duration) -> Sleep {
    Sleep {
        deadline: Instant::now() + dur,
        id: None,
        done: false,
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if Instant::now() >= this.deadline {
            this.done = true;
            if let Some(id) = this.id.take() {
                with_timers(|wheel| wheel.cancel(id));
            }
            return Poll::Ready(());
        }
        match this.id {
            None => {
                let id = with_timers(|wheel| wheel.register(this.deadline, cx.waker().clone()));
                this.id = Some(id);
            }
            Some(id) => with_timers(|wheel| wheel.update_waker(id, cx.waker().clone())),
        }
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            with_timers(|wheel| wheel.cancel(id));
        }
    }
}

/// Error returned by [`timeout`] when the inner future does not finish in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elapsed;

impl std::fmt::Display for Elapsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("future timed out")
    }
}

impl std::error::Error for Elapsed {}

/// Run `future`, cancelling it (by drop) if `dur` elapses first. Dropping the inner
/// future in flight exercises the runtime's orphan-and-cancel path.
pub async fn timeout<F: Future>(dur: Duration, future: F) -> Result<F::Output, Elapsed> {
    let mut future = Box::pin(future);
    let mut sleep = Box::pin(sleep(dur));
    std::future::poll_fn(move |cx| {
        if let Poll::Ready(value) = future.as_mut().poll(cx) {
            return Poll::Ready(Ok(value));
        }
        match sleep.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(Elapsed)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}
