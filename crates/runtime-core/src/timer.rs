//! Userspace timer wheel (Phase 1: stub).
//!
//! Fully implemented in the timers task. The executor already queries it each idle
//! iteration so the nearest deadline can bound the ring wait — a single kernel wait
//! deadline per loop instead of one timeout SQE per sleeping future.

use std::time::Duration;

pub(crate) struct TimerWheel {
    // Filled in by the timers task.
}

impl TimerWheel {
    pub fn new() -> Self {
        TimerWheel {}
    }

    /// Nearest pending deadline as a relative duration, or `None` when no timers are
    /// armed (the executor then waits indefinitely for a completion).
    pub fn next_timeout(&self) -> Option<Duration> {
        None
    }

    /// Wake any futures whose deadline has passed.
    pub fn expire(&mut self) {}

    pub fn is_empty(&self) -> bool {
        true
    }
}
