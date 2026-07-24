//! Per-operation state stored in the [`crate::slab::OpSlab`].
//!
//! An `Op` is the runtime-visible half of an in-flight io_uring operation. Its
//! lifetime is decoupled from the future that created it: if that future is dropped
//! while the op is still live, the op is [`Op::orphaned`] and its `keepalive` (the
//! kernel-visible buffer/metadata) is retained until the terminal CQE — never freed
//! early.
//!
//! Ops may be **multishot**: one SQE that yields many CQEs (multishot accept/recv).
//! Completions are queued in `results`; a CQE without `IORING_CQE_F_MORE` marks the op
//! `terminated` (no further completions will arrive). Single-shot ops are simply the
//! degenerate case of exactly one, terminal, completion.

use std::any::Any;
use std::collections::VecDeque;
use std::task::Waker;

/// The result the kernel reported for a completed operation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CqeResult {
    /// Raw `cqe.res` (>= 0 on success, `-errno` on failure).
    pub res: i32,
    /// Raw `cqe.flags` (buffer id, `IORING_CQE_F_MORE`, …).
    pub flags: u32,
}

pub(crate) struct Op {
    /// Completions delivered by the drain, FIFO, awaiting consumption.
    pub results: VecDeque<CqeResult>,
    /// The consumer's parked waker.
    pub waker: Option<Waker>,
    /// A CQE without `IORING_CQE_F_MORE` has arrived: no further completions.
    pub terminated: bool,
    /// The owning future was dropped; the drain reaps this op once terminated.
    pub orphaned: bool,
    /// Kernel-visible memory kept alive for the op's whole lifetime, dropped only when
    /// the slot is freed.
    pub keepalive: Option<Box<dyn Any>>,
}

impl Op {
    pub fn new(keepalive: Option<Box<dyn Any>>) -> Self {
        Op {
            results: VecDeque::new(),
            waker: None,
            terminated: false,
            orphaned: false,
            keepalive,
        }
    }
}
