//! Single-thread, completion-driven executor.
//!
//! One `Runtime` per thread owns the [`Ring`] and a cooperative task scheduler. The
//! executor loop drives I/O completion-first: run every ready task (batching the SQEs
//! they prepare), then, when nothing is runnable, submit the batch and wait for at
//! least one completion (bounded by the nearest timer). Completions wake the parked
//! tasks that were waiting on them.
//!
//! Wakers are hand-rolled over `Rc` because the wake target is `!Send` (`std::task::
//! Wake` requires `Send + Sync`). The resulting `Waker` must never cross threads —
//! guaranteed by the runtime being strictly single-threaded, the same discipline
//! tokio-uring/glommio rely on.

use std::cell::{Cell, RefCell};
use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crate::ring::Ring;
use crate::timer::TimerWheel;

thread_local! {
    static CURRENT: RefCell<Option<Rc<Runtime>>> = const { RefCell::new(None) };
}

/// Is a completion-native runtime usable in this environment? Cheap probe used by
/// tests to skip gracefully in sandboxes without io_uring.
pub fn is_runtime_available() -> bool {
    runtime_uring_sys::KernelCaps::probe().is_some_and(|caps| caps.mandatory_opcodes_present())
}

struct Task {
    future: Pin<Box<dyn Future<Output = ()>>>,
}

/// Shared scheduler state reachable from wakers (which only hold this, never the
/// task table).
struct SchedShared {
    ready: RefCell<VecDeque<usize>>,
    queued: RefCell<HashSet<usize>>,
}

impl SchedShared {
    fn schedule(&self, id: usize) {
        if self.queued.borrow_mut().insert(id) {
            self.ready.borrow_mut().push_back(id);
        }
    }
}

pub struct Runtime {
    shared: Rc<SchedShared>,
    tasks: RefCell<Vec<Option<Task>>>,
    free: RefCell<Vec<usize>>,
    ring: RefCell<Ring>,
    timers: RefCell<TimerWheel>,
}

impl Runtime {
    fn new() -> std::io::Result<Self> {
        Ok(Runtime {
            shared: Rc::new(SchedShared {
                ready: RefCell::new(VecDeque::new()),
                queued: RefCell::new(HashSet::new()),
            }),
            tasks: RefCell::new(Vec::new()),
            free: RefCell::new(Vec::new()),
            ring: RefCell::new(Ring::new()?),
            timers: RefCell::new(TimerWheel::new()),
        })
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()>>>) -> usize {
        let id = {
            let mut tasks = self.tasks.borrow_mut();
            if let Some(id) = self.free.borrow_mut().pop() {
                tasks[id] = Some(Task { future });
                id
            } else {
                tasks.push(Some(Task { future }));
                tasks.len() - 1
            }
        };
        self.shared.schedule(id);
        id
    }

    /// Poll every runnable task until the ready queue drains. A task is removed from
    /// the table while polled so it may freely spawn or reschedule itself.
    fn run_ready(&self) {
        loop {
            let id = match self.shared.ready.borrow_mut().pop_front() {
                Some(id) => id,
                None => break,
            };
            self.shared.queued.borrow_mut().remove(&id);

            let mut task = match self.tasks.borrow_mut().get_mut(id).and_then(Option::take) {
                Some(task) => task,
                None => continue,
            };

            let waker = make_waker(self.shared.clone(), id);
            let mut cx = Context::from_waker(&waker);
            match task.future.as_mut().poll(&mut cx) {
                Poll::Ready(()) => {
                    // Slot is already `None`; return it to the free list.
                    self.free.borrow_mut().push(id);
                }
                Poll::Pending => {
                    self.tasks.borrow_mut()[id] = Some(task);
                }
            }
        }
    }

    /// Tear the runtime down cleanly. Drops every still-pending task first (while the
    /// runtime is installed, so their in-flight futures orphan their buffers via
    /// `Drop`), then reaps all outstanding ops before the ring is exited.
    fn shutdown(&self) {
        // Release tasks without holding the table borrow across their drops (a drop
        // may touch the ring/timers).
        let tasks = std::mem::take(&mut *self.tasks.borrow_mut());
        drop(tasks);
        self.free.borrow_mut().clear();
        self.shared.ready.borrow_mut().clear();
        self.shared.queued.borrow_mut().clear();
        self.ring.borrow_mut().shutdown();
    }

    /// One wait/drain step. Only called when the ready queue is empty and the driver
    /// still has pending work (in-flight ops or armed timers).
    fn drive_io(&self) -> std::io::Result<()> {
        let timeout = self.timers.borrow().next_timeout();
        self.ring.borrow_mut().submit_and_wait(1, timeout)?;
        self.ring.borrow_mut().drain();
        self.timers.borrow_mut().expire();
        Ok(())
    }
}

/// Run `future` to completion on a fresh single-thread runtime, driving I/O until it
/// resolves. Panics if io_uring is unavailable (guard with [`is_runtime_available`]).
pub fn block_on<F>(future: F) -> F::Output
where
    F: Future + 'static,
    F::Output: 'static,
{
    let runtime = Rc::new(Runtime::new().expect("failed to start io_uring runtime"));
    install(runtime.clone());

    // Capture the root output through a shared cell so the driver can detect
    // completion without polling a JoinHandle of itself.
    let output: Rc<RefCell<Option<F::Output>>> = Rc::new(RefCell::new(None));
    let sink = output.clone();
    runtime.spawn(Box::pin(async move {
        let value = future.await;
        *sink.borrow_mut() = Some(value);
    }));

    let result = loop {
        runtime.run_ready();
        if let Some(value) = output.borrow_mut().take() {
            break value;
        }
        let inflight = runtime.ring.borrow().in_flight();
        let has_timers = !runtime.timers.borrow().is_empty();
        assert!(
            inflight > 0 || has_timers,
            "runtime stalled: root task parked with no pending io or timers"
        );
        runtime
            .drive_io()
            .expect("io_uring submit/wait failed while driving the runtime");
    };

    // Cancel and reap any spawned-but-unfinished tasks and their in-flight ops before
    // the runtime (and its buffers) are dropped.
    runtime.shutdown();
    uninstall();
    result
}

/// Spawn `future` onto the current runtime, returning a [`JoinHandle`] for its output.
/// Must be called from within [`block_on`].
pub fn spawn_local<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + 'static,
    F::Output: 'static,
{
    with_current(|runtime| {
        let inner: Rc<JoinInner<F::Output>> = Rc::new(JoinInner::new());
        let sink = inner.clone();
        runtime.spawn(Box::pin(async move {
            let value = future.await;
            sink.complete(value);
        }));
        JoinHandle(inner)
    })
}

/// Borrow the current runtime's [`Ring`]. Panics if called outside [`block_on`].
pub(crate) fn with_ring<R>(f: impl FnOnce(&mut Ring) -> R) -> R {
    CURRENT.with(|cell| {
        let runtime = cell.borrow();
        let runtime = runtime.as_ref().expect("no runtime on this thread");
        let mut ring = runtime.ring.borrow_mut();
        f(&mut ring)
    })
}

/// Borrow the current runtime's timer wheel. Panics if called outside [`block_on`].
pub(crate) fn with_timers<R>(f: impl FnOnce(&mut TimerWheel) -> R) -> R {
    CURRENT.with(|cell| {
        let runtime = cell.borrow();
        let runtime = runtime.as_ref().expect("no runtime on this thread");
        let mut timers = runtime.timers.borrow_mut();
        f(&mut timers)
    })
}

/// Number of operations currently in flight on the current runtime. Diagnostic; used
/// by tests to assert orphaned ops are reaped.
pub fn in_flight() -> usize {
    with_ring(|ring| ring.in_flight())
}

fn with_current<R>(f: impl FnOnce(&Runtime) -> R) -> R {
    CURRENT.with(|cell| {
        let runtime = cell.borrow();
        f(runtime.as_ref().expect("no runtime on this thread"))
    })
}

fn install(runtime: Rc<Runtime>) {
    CURRENT.with(|cell| {
        assert!(
            cell.borrow().is_none(),
            "block_on cannot be nested on one thread"
        );
        *cell.borrow_mut() = Some(runtime);
    });
}

fn uninstall() {
    CURRENT.with(|cell| *cell.borrow_mut() = None);
}

// ---- JoinHandle -----------------------------------------------------------------

struct JoinInner<T> {
    result: RefCell<Option<T>>,
    waker: RefCell<Option<Waker>>,
    done: Cell<bool>,
}

impl<T> JoinInner<T> {
    fn new() -> Self {
        JoinInner {
            result: RefCell::new(None),
            waker: RefCell::new(None),
            done: Cell::new(false),
        }
    }

    fn complete(&self, value: T) {
        *self.result.borrow_mut() = Some(value);
        self.done.set(true);
        if let Some(waker) = self.waker.borrow_mut().take() {
            waker.wake();
        }
    }
}

/// Awaitable handle to a spawned task's output.
pub struct JoinHandle<T>(Rc<JoinInner<T>>);

impl<T> Future for JoinHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        if self.0.done.get() {
            Poll::Ready(
                self.0
                    .result
                    .borrow_mut()
                    .take()
                    .expect("JoinHandle polled twice after completion"),
            )
        } else {
            *self.0.waker.borrow_mut() = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

// ---- Waker (Rc-backed RawWaker) --------------------------------------------------

struct WakerCore {
    shared: Rc<SchedShared>,
    id: usize,
}

fn make_waker(shared: Rc<SchedShared>, id: usize) -> Waker {
    let core = Rc::new(WakerCore { shared, id });
    let raw = Rc::into_raw(core) as *const ();
    // SAFETY: `raw` came from `Rc::into_raw` and the vtable upholds Rc refcounting.
    unsafe { Waker::from_raw(RawWaker::new(raw, &VTABLE)) }
}

static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_waker, wake, wake_by_ref, drop_waker);

unsafe fn clone_waker(ptr: *const ()) -> RawWaker {
    unsafe { Rc::increment_strong_count(ptr as *const WakerCore) };
    RawWaker::new(ptr, &VTABLE)
}

unsafe fn wake(ptr: *const ()) {
    // Consumes one strong ref.
    let core = unsafe { Rc::from_raw(ptr as *const WakerCore) };
    core.shared.schedule(core.id);
}

unsafe fn wake_by_ref(ptr: *const ()) {
    let core = unsafe { &*(ptr as *const WakerCore) };
    core.shared.schedule(core.id);
}

unsafe fn drop_waker(ptr: *const ()) {
    drop(unsafe { Rc::from_raw(ptr as *const WakerCore) });
}

#[cfg(test)]
mod tests {
    use super::*;

    // A cooperative yield: pending once, then ready — exercises the waker/ready-queue
    // path with no I/O.
    struct YieldNow(bool);
    impl Future for YieldNow {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    #[test]
    fn block_on_runs_a_plain_future() {
        if !is_runtime_available() {
            return;
        }
        let out = block_on(async { 40 + 2 });
        assert_eq!(out, 42);
    }

    #[test]
    fn block_on_drives_cooperative_yields() {
        if !is_runtime_available() {
            return;
        }
        let out = block_on(async {
            YieldNow(false).await;
            YieldNow(false).await;
            7
        });
        assert_eq!(out, 7);
    }

    #[test]
    fn spawn_local_join_returns_output() {
        if !is_runtime_available() {
            return;
        }
        let out = block_on(async {
            let a = spawn_local(async { 20 });
            let b = spawn_local(async {
                YieldNow(false).await;
                22
            });
            a.await + b.await
        });
        assert_eq!(out, 42);
    }
}
