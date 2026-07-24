//! Per-operation state stored in the [`crate::slab::OpSlab`].
//!
//! An `Op` is the runtime-visible half of an in-flight io_uring operation. Its
//! lifetime is decoupled from the future that created it: if that future is dropped
//! while the op is still in the kernel, the op is marked [`Op::orphaned`] and its
//! `keepalive` (the kernel-visible buffer/metadata) is retained here until the
//! terminal CQE arrives — never freed early.

use std::any::Any;
use std::task::Waker;

/// The result the kernel reported for a completed operation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CqeResult {
    /// Raw `cqe.res` (>= 0 on success, `-errno` on failure).
    pub res: i32,
    /// Raw `cqe.flags` (e.g. `IORING_CQE_F_MORE` in later phases).
    pub flags: u32,
}

pub(crate) enum OpState {
    /// Submitted (or queued); the future is parked on `Waker` until completion.
    Waiting(Option<Waker>),
    /// Terminal CQE observed; the future will read this on its next poll.
    Complete(CqeResult),
}

pub(crate) struct Op {
    pub state: OpState,
    /// Whether the owning future has been dropped. An orphaned op is freed by the
    /// completion drain itself (dropping `keepalive`), since nothing will poll it.
    pub orphaned: bool,
    /// Kernel-visible memory kept alive for the op's whole lifetime. Type-erased so
    /// the slab need not know the buffer type. Dropped only on the terminal CQE.
    pub keepalive: Option<Box<dyn Any>>,
}

impl Op {
    pub fn waiting(keepalive: Option<Box<dyn Any>>) -> Self {
        Op {
            state: OpState::Waiting(None),
            orphaned: false,
            keepalive,
        }
    }
}
