//! The shared operation future: submits one SQE, parks until its CQE, and — the
//! whole point — orphans (not frees) its kernel-visible buffer if dropped in flight.
//!
//! Typed I/O primitives (`net`, buffers) are thin wrappers that construct an
//! `OpFuture` with the right `prep` closure and `keepalive` payload.

use std::any::Any;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use runtime_uring_sys::ffi;

use crate::executor::with_ring;
use crate::op::CqeResult;
use crate::slab::OpKey;

/// A future over a single io_uring operation. `P` prepares the SQE (opcode + args);
/// `keepalive` is any memory the kernel will touch, retained until the terminal CQE.
pub struct OpFuture<P: FnOnce(*mut ffi::io_uring_sqe)> {
    prep: Option<P>,
    keepalive: Option<Box<dyn Any>>,
    key: Option<OpKey>,
    done: bool,
}

impl<P: FnOnce(*mut ffi::io_uring_sqe)> OpFuture<P> {
    /// `prep` receives the raw SQE and must fill in the opcode/arguments but NOT
    /// `user_data`. `keepalive` holds buffers/metadata the SQE points at.
    pub fn new(keepalive: Option<Box<dyn Any>>, prep: P) -> Self {
        OpFuture {
            prep: Some(prep),
            keepalive,
            key: None,
            done: false,
        }
    }

    fn finish(&mut self, result: CqeResult) -> io::Result<i32> {
        self.key = None;
        self.done = true;
        if result.res < 0 {
            Err(io::Error::from_raw_os_error(-result.res))
        } else {
            Ok(result.res)
        }
    }
}

impl<P: FnOnce(*mut ffi::io_uring_sqe) + Unpin> Future for OpFuture<P> {
    /// The raw `cqe.res` on success (bytes transferred, accepted fd, or 0), or the
    /// mapped `-errno` as an `io::Error`.
    type Output = io::Result<i32>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        debug_assert!(!this.done, "OpFuture polled after completion");

        // Already submitted: just check for the terminal completion.
        if let Some(key) = this.key {
            return match with_ring(|ring| ring.poll_op(key, cx.waker())) {
                Some((result, _keepalive)) => Poll::Ready(this.finish(result)),
                None => Poll::Pending,
            };
        }

        // First poll: reserve a slot, prepare and queue the SQE.
        let prep = this.prep.take().expect("OpFuture prep consumed twice");
        let keepalive = this.keepalive.take();
        let key = match with_ring(|ring| ring.submit_op(keepalive, prep)) {
            Ok(key) => key,
            Err(err) => {
                this.done = true;
                return Poll::Ready(Err(err));
            }
        };
        this.key = Some(key);
        // Park on the freshly-registered op (it cannot be complete yet — not even
        // submitted — so this stores our waker and returns Pending).
        match with_ring(|ring| ring.poll_op(key, cx.waker())) {
            Some((result, _keepalive)) => Poll::Ready(this.finish(result)),
            None => Poll::Pending,
        }
    }
}

impl<P: FnOnce(*mut ffi::io_uring_sqe)> Drop for OpFuture<P> {
    fn drop(&mut self) {
        // In flight when dropped: orphan the op so its buffer survives until the
        // kernel is done, and queue an async cancellation.
        if let Some(key) = self.key {
            with_ring(|ring| ring.orphan(key));
        }
    }
}
