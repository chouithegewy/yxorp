//! The io_uring wrapper: ring construction (probe-with-fallback), batched
//! submission, and completion draining that resolves CQEs back to slab ops.
//!
//! One `Ring` is owned by one runtime on one thread — never shared. All submission
//! and completion goes through here; the executor batches SQEs prepared by many
//! futures into a single `io_uring_enter`.

use std::collections::VecDeque;
use std::io;
use std::task::Waker;
use std::time::Duration;

use runtime_uring_sys::ffi;
use runtime_uring_sys::inline;
use runtime_uring_sys::KernelCaps;

use crate::bufring::{BufRing, BUF_RING_ENTRIES, BUF_SIZE};
use crate::op::{CqeResult, Op};
use crate::slab::{OpKey, OpSlab};

/// Top `user_data` bit, set on `MSG_RING`-delivered completions to distinguish a
/// cross-shard message from an op completion. Our [`OpKey`]s pack a small slot index
/// into bits 32..63, so bit 63 is always clear for them.
const MSG_TAG: u64 = 1 << 63;

/// One step of consuming a multishot op's completions.
pub(crate) enum MultishotPoll {
    /// A completion is ready.
    Value(CqeResult),
    /// The op has terminated (no `IORING_CQE_F_MORE`); its keepalive is returned.
    Done(Option<Box<dyn std::any::Any>>),
    /// No completion yet; the waker is parked.
    Pending,
}

/// Default submission-queue depth. The completion queue is sized larger (multishot /
/// zero-copy notifications in later phases can produce more CQEs than SQEs).
const SQ_ENTRIES: u32 = 256;
const CQ_ENTRIES: u32 = 1024;
/// Size of the per-ring sparse fixed-file table. Accepted/outbound sockets are
/// installed here as direct descriptors (Phase 2), skipping per-op fd refcounting.
const FIXED_FILE_SLOTS: u32 = 4096;

pub struct Ring {
    // Boxed so its address is stable across moves into the runtime's Rc.
    ring: Box<ffi::io_uring>,
    ops: OpSlab<Op>,
    caps: KernelCaps,
    fixed_files: bool,
    /// Cross-shard messages delivered to this ring via `MSG_RING`, awaiting a receiver.
    inbox: VecDeque<u64>,
    inbox_waker: Option<Waker>,
    /// Default provided-buffer ring, created lazily on first multishot recv.
    buf_ring: Option<BufRing>,
}

impl Ring {
    /// Construct a ring using the richest flag set this kernel supports, degrading to
    /// a plain ring if the modern flags are unavailable. Returns
    /// [`io::ErrorKind::Unsupported`] when io_uring itself is missing or lacks a
    /// mandatory opcode.
    pub fn new() -> io::Result<Self> {
        let caps = KernelCaps::probe().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "io_uring is unavailable")
        })?;
        if !caps.mandatory_opcodes_present() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "io_uring is missing a mandatory Phase 1 opcode",
            ));
        }

        let mut ring = Box::new(unsafe { std::mem::zeroed::<ffi::io_uring>() });
        let preferred = caps.preferred_setup_flags();
        // First attempt: preferred flags (+ enlarged CQ where supported). On failure,
        // fall back to a bare ring — belt-and-suspenders, since the caps probe already
        // validated each flag individually.
        for flags in [preferred, 0] {
            let mut params: ffi::io_uring_params = unsafe { std::mem::zeroed() };
            params.flags = flags;
            let cq = if caps.cqsize {
                params.flags |= ffi::IORING_SETUP_CQSIZE;
                params.cq_entries = CQ_ENTRIES;
                CQ_ENTRIES
            } else {
                0
            };
            let rc = unsafe {
                ffi::io_uring_queue_init_params(SQ_ENTRIES, ring.as_mut(), &mut params)
            };
            if rc == 0 {
                let _ = cq;
                // Register a sparse fixed-file table so accepted/outbound sockets can
                // live as direct descriptors. Best-effort: on failure we fall back to
                // raw-fd sockets.
                let fixed_files = caps.sparse_files
                    && unsafe {
                        ffi::io_uring_register_files_sparse(ring.as_mut(), FIXED_FILE_SLOTS) == 0
                    };
                return Ok(Ring {
                    ring,
                    ops: OpSlab::with_capacity(SQ_ENTRIES as usize),
                    caps,
                    fixed_files,
                    inbox: VecDeque::new(),
                    inbox_waker: None,
                    buf_ring: None,
                });
            }
            if flags == 0 {
                return Err(io::Error::from_raw_os_error(-rc));
            }
        }
        unreachable!("the flags==0 arm always returns")
    }

    pub fn caps(&self) -> &KernelCaps {
        &self.caps
    }

    /// Whether a sparse fixed-file table is registered (direct descriptors usable).
    pub(crate) fn has_fixed_files(&self) -> bool {
        self.fixed_files
    }

    /// The underlying io_uring fd, used as the target of an `MSG_RING` from a peer shard.
    pub(crate) fn ring_fd(&self) -> i32 {
        self.ring.ring_fd
    }

    /// Post a `payload` message to a peer ring identified by `target_fd` (its
    /// `ring_fd`). Queued on this ring; delivered to the peer's CQ as a tagged
    /// completion. Fire-and-forget: this ring's completion for the op is untracked.
    pub(crate) fn post_msg(&mut self, target_fd: i32, payload: u64) -> io::Result<()> {
        let sqe = self.next_sqe()?;
        unsafe {
            inline::io_uring_prep_msg_ring(sqe, target_fd, 0, MSG_TAG | (payload & !MSG_TAG), 0);
            inline::io_uring_sqe_set_data64(sqe, 0);
        }
        Ok(())
    }

    /// Pop the next delivered cross-shard message, or park `waker` if none yet.
    pub(crate) fn poll_message(&mut self, waker: &Waker) -> Option<u64> {
        if let Some(payload) = self.inbox.pop_front() {
            Some(payload)
        } else {
            self.inbox_waker = Some(waker.clone());
            None
        }
    }

    /// Whether a receiver is currently parked waiting for a cross-shard message (a
    /// legitimate reason for the executor to block on the ring).
    pub(crate) fn has_inbox_waiter(&self) -> bool {
        self.inbox_waker.is_some()
    }

    /// Ensure the default provided-buffer ring exists, returning its group id.
    pub(crate) fn ensure_buf_ring(&mut self) -> io::Result<u16> {
        if self.buf_ring.is_none() {
            let br = BufRing::new(self.ring.as_mut(), 0, BUF_RING_ENTRIES, BUF_SIZE)?;
            self.buf_ring = Some(br);
        }
        Ok(self.buf_ring.as_ref().expect("buf ring present").bgid())
    }

    /// Pointer to a provided buffer's storage (valid while this ring lives).
    pub(crate) fn buf_ring_ptr(&self, bid: u16) -> *const u8 {
        self.buf_ring
            .as_ref()
            .expect("buf ring present")
            .buffer_ptr(bid)
    }

    /// Return a consumed provided buffer to the ring for reuse.
    pub(crate) fn buf_ring_recycle(&mut self, bid: u16) {
        if let Some(br) = self.buf_ring.as_mut() {
            br.recycle(bid);
        }
    }

    /// Number of operations currently in flight (submitted or awaiting drain).
    pub fn in_flight(&self) -> usize {
        self.ops.len()
    }

    /// Reserve an SQE, submitting the current batch to make room if the SQ is full.
    fn next_sqe(&mut self) -> io::Result<*mut ffi::io_uring_sqe> {
        unsafe {
            let mut sqe = inline::io_uring_get_sqe(self.ring.as_mut());
            if sqe.is_null() {
                // SQ full: flush what we have, then retry once.
                let rc = inline::io_uring_submit(self.ring.as_mut());
                if rc < 0 {
                    return Err(io::Error::from_raw_os_error(-rc));
                }
                sqe = inline::io_uring_get_sqe(self.ring.as_mut());
            }
            if sqe.is_null() {
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "submission queue exhausted",
                ))
            } else {
                Ok(sqe)
            }
        }
    }

    /// Register an operation and prepare its SQE. `keepalive` holds any kernel-visible
    /// buffer/metadata to retain until completion. `prep` fills the SQE with the
    /// desired opcode/arguments; it must NOT set `user_data` — the slab key is stamped
    /// here. The SQE is queued, not yet submitted (the executor batches submission).
    pub fn submit_op(
        &mut self,
        keepalive: Option<Box<dyn std::any::Any>>,
        prep: impl FnOnce(*mut ffi::io_uring_sqe),
    ) -> io::Result<OpKey> {
        let key = self.ops.insert(Op::new(keepalive));
        let sqe = match self.next_sqe() {
            Ok(sqe) => sqe,
            Err(err) => {
                // Roll back the reserved slot so we don't leak it.
                self.ops.remove(key);
                return Err(err);
            }
        };
        prep(sqe);
        unsafe { inline::io_uring_sqe_set_data64(sqe, key.as_u64()) };
        Ok(key)
    }

    /// Poll an operation's terminal result. Returns `Some((result, keepalive))` — and
    /// frees the slot, handing the retained buffer back to the caller — once the CQE
    /// has arrived; otherwise parks `waker` and returns `None`.
    pub(crate) fn poll_op(
        &mut self,
        key: OpKey,
        waker: &std::task::Waker,
    ) -> Option<(CqeResult, Option<Box<dyn std::any::Any>>)> {
        let result = {
            let op = self.ops.get_mut(key)?;
            match op.results.pop_front() {
                Some(result) => result,
                None => {
                    op.waker = Some(waker.clone());
                    return None;
                }
            }
        };
        // Single-shot: the one completion is terminal, so free the slot and hand back
        // the retained buffer.
        let op = self.ops.remove(key).expect("op present");
        Some((result, op.keepalive))
    }

    /// Consume the next completion of a multishot op (accept/recv). Unlike [`poll_op`]
    /// the slot survives across completions until the op terminates.
    pub(crate) fn poll_multishot(&mut self, key: OpKey, waker: &std::task::Waker) -> MultishotPoll {
        let step = match self.ops.get_mut(key) {
            None => return MultishotPoll::Done(None),
            Some(op) => {
                if let Some(result) = op.results.pop_front() {
                    return MultishotPoll::Value(result);
                }
                if op.terminated {
                    None
                } else {
                    op.waker = Some(waker.clone());
                    Some(())
                }
            }
        };
        match step {
            Some(()) => MultishotPoll::Pending,
            None => {
                let op = self.ops.remove(key);
                MultishotPoll::Done(op.and_then(|op| op.keepalive))
            }
        }
    }

    /// Attach kernel-visible memory to an already-submitted op. Used by buffer ops,
    /// which move the buffer into the slot only after a successful submit so it can be
    /// handed back to the caller if submission fails.
    pub(crate) fn attach_keepalive(&mut self, key: OpKey, keepalive: Box<dyn std::any::Any>) {
        if let Some(op) = self.ops.get_mut(key) {
            op.keepalive = Some(keepalive);
        }
    }

    /// Called when an I/O future is dropped. If the terminal CQE already arrived, the
    /// slot is freed immediately; otherwise the op is orphaned (its buffer retained)
    /// and an exact-`user_data` async cancellation is queued. Either way the buffer is
    /// never freed while the kernel might still touch it.
    pub fn orphan(&mut self, key: OpKey) {
        enum Action {
            None,
            Free,
            Cancel,
        }
        let action = match self.ops.get_mut(key) {
            None => Action::None,
            Some(op) if op.terminated => Action::Free,
            Some(op) => {
                op.orphaned = true;
                op.waker = None; // drop the stale waker
                Action::Cancel
            }
        };
        match action {
            Action::None => {}
            Action::Free => {
                self.ops.remove(key);
            }
            Action::Cancel => {
                // Fire-and-forget cancellation (user_data 0 = untracked).
                if let Ok(sqe) = self.next_sqe() {
                    unsafe {
                        inline::io_uring_prep_cancel64(sqe, key.as_u64(), 0);
                        inline::io_uring_sqe_set_data64(sqe, 0);
                    }
                }
            }
        }
    }

    /// Submit the queued SQE batch and wait for at least `wait_nr` completions, or
    /// until `timeout` elapses. A single `io_uring_enter` amortised over the batch.
    pub fn submit_and_wait(&mut self, wait_nr: u32, timeout: Option<Duration>) -> io::Result<()> {
        let rc = unsafe {
            match timeout {
                None => inline::io_uring_submit_and_wait(self.ring.as_mut(), wait_nr),
                Some(dur) => {
                    let mut ts = ffi::__kernel_timespec {
                        tv_sec: dur.as_secs() as i64,
                        tv_nsec: dur.subsec_nanos() as i64,
                    };
                    let mut cqe: *mut ffi::io_uring_cqe = std::ptr::null_mut();
                    ffi::io_uring_submit_and_wait_timeout(
                        self.ring.as_mut(),
                        &mut cqe,
                        wait_nr,
                        &mut ts,
                        std::ptr::null_mut(),
                    )
                }
            }
        };
        if rc >= 0 {
            return Ok(());
        }
        match -rc {
            // Timed out / interrupted / no completions yet: all expected, not errors.
            libc::ETIME | libc::EINTR | libc::EAGAIN | libc::EBUSY => Ok(()),
            errno => Err(io::Error::from_raw_os_error(errno)),
        }
    }

    /// Flush any queued SQEs without waiting.
    pub fn flush(&mut self) -> io::Result<()> {
        let rc = unsafe { inline::io_uring_submit(self.ring.as_mut()) };
        if rc < 0 {
            Err(io::Error::from_raw_os_error(-rc))
        } else {
            Ok(())
        }
    }

    /// Drain every visible completion, resolving each to its slab op: waking the
    /// waiter for live ops, or freeing (and dropping the retained buffer of) orphaned
    /// ops. Returns the number of CQEs processed. Untracked completions (`user_data`
    /// 0, e.g. cancellations) are consumed and ignored.
    pub fn drain(&mut self) -> usize {
        enum Action {
            Ignore,
            Free,
            Wake(Option<std::task::Waker>),
        }
        let mut count = 0;
        loop {
            let mut cqe: *mut ffi::io_uring_cqe = std::ptr::null_mut();
            let (data, res, flags) = unsafe {
                if inline::io_uring_peek_cqe(self.ring.as_mut(), &mut cqe) != 0 {
                    break;
                }
                let data = inline::io_uring_cqe_get_data64(cqe);
                let res = (*cqe).res;
                let flags = (*cqe).flags;
                inline::io_uring_cqe_seen(self.ring.as_mut(), cqe);
                (data, res, flags)
            };
            count += 1;
            if data == 0 {
                continue;
            }
            if data & MSG_TAG != 0 {
                // Cross-shard message from a peer ring (res carries the length field,
                // unused here). Deliver to the inbox and wake any receiver.
                self.inbox.push_back(data & !MSG_TAG);
                if let Some(waker) = self.inbox_waker.take() {
                    waker.wake();
                }
                continue;
            }
            let key = OpKey::from_u64(data);
            let more = flags & ffi::IORING_CQE_F_MORE != 0;
            let action = match self.ops.get_mut(key) {
                None => Action::Ignore,
                Some(op) => {
                    op.results.push_back(CqeResult { res, flags });
                    if !more {
                        op.terminated = true;
                    }
                    if op.orphaned {
                        // Reap only once no more completions can arrive.
                        if op.terminated {
                            Action::Free
                        } else {
                            Action::Ignore
                        }
                    } else {
                        Action::Wake(op.waker.take())
                    }
                }
            };
            match action {
                Action::Ignore => {}
                Action::Free => {
                    self.ops.remove(key);
                }
                Action::Wake(waker) => {
                    if let Some(waker) = waker {
                        waker.wake();
                    }
                }
            }
        }
        count
    }

    /// Fire-and-forget close of a direct (fixed) descriptor, used when a fixed-fd
    /// stream is dropped without an explicit async close. The freed slot returns to
    /// the table once the kernel processes it.
    pub(crate) fn close_direct_detached(&mut self, index: u32) {
        if let Ok(sqe) = self.next_sqe() {
            unsafe {
                inline::io_uring_prep_close_direct(sqe, index);
                inline::io_uring_sqe_set_data64(sqe, 0);
            }
        }
    }

    /// Queue a request that cancels every outstanding operation (untracked).
    fn cancel_all(&mut self) {
        if let Ok(sqe) = self.next_sqe() {
            let flags = (ffi::IORING_ASYNC_CANCEL_ALL | ffi::IORING_ASYNC_CANCEL_ANY) as i32;
            unsafe {
                inline::io_uring_prep_cancel64(sqe, 0, flags);
                inline::io_uring_sqe_set_data64(sqe, 0);
            }
        }
    }

    /// Deterministic teardown: cancel every outstanding operation and reap its
    /// terminal completion before any buffer is freed, so the kernel is never left
    /// holding memory we are about to drop. Bounded so a stuck completion cannot hang
    /// teardown forever.
    pub(crate) fn shutdown(&mut self) {
        // Nothing will poll during teardown, so every remaining op must be freed by
        // the drain itself.
        self.ops.for_each_mut(|op| op.orphaned = true);
        self.drain();
        let mut guard = 0;
        while !self.ops.is_empty() {
            self.cancel_all();
            let _ = self.submit_and_wait(1, Some(Duration::from_millis(200)));
            self.drain();
            guard += 1;
            if guard > 1000 {
                debug_assert!(false, "ring shutdown failed to reap all ops");
                break;
            }
        }
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        // Reap any stragglers (idempotent if the executor already drained), then free
        // the provided-buffer ring, then exit.
        self.shutdown();
        if let Some(mut br) = self.buf_ring.take() {
            br.free(self.ring.as_mut());
        }
        unsafe { ffi::io_uring_queue_exit(self.ring.as_mut()) };
    }
}
