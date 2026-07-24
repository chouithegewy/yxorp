//! Completion-native, single-thread io_uring runtime (Phase 1 correctness kernel).
//!
//! Layers, bottom-up:
//! - [`slab`]: generational op-slab — the memory-safety cornerstone.
//! - [`op`]: per-operation state retained across a dropped future.
//! - [`ring`]: io_uring wrapper — construction, batched submit, completion drain.
//! - [`executor`]: single-thread scheduler, `block_on` / `spawn_local`, wakers.
//! - [`fut`]: the shared operation future (submit one SQE, park, orphan-on-drop).
//! - [`timer`]: userspace timer wheel (filled in the timers task).
//! - `net`: owned-buffer TCP primitives (added in the I/O task).
//!
//! See `docs/uring_migration_analysis.md` and the Phase 1 plan for rationale.

#![allow(dead_code)]

pub mod buf;
mod bufring;
pub mod executor;
pub mod fut;
pub mod net;
pub mod op;
pub mod ring;
pub mod shard;
pub mod slab;
pub mod timer;

pub use buf::{IoBuf, IoBufMut};
pub use executor::{
    block_on, current_ring_fd, in_flight, is_runtime_available, post_message, recv_message,
    spawn_local, JoinHandle,
};
pub use net::{AcceptStream, BufLease, RecvStream, TcpListener, TcpStream};
pub use shard::{num_cpus, spawn_shards};
pub use timer::{sleep, timeout, Elapsed, Sleep};

#[cfg(test)]
mod reactor_tests {
    use runtime_uring_sys::inline;

    use crate::executor::{block_on, is_runtime_available};
    use crate::fut::OpFuture;

    /// End-to-end reactor smoke test: a bare `NOP` op driven through submit → wait →
    /// drain → waker → completion. Proves the ring, executor loop, and op future all
    /// cooperate. `NOP` completes with res 0.
    #[test]
    fn nop_op_drives_through_the_reactor() {
        if !is_runtime_available() {
            return;
        }
        let res = block_on(async {
            OpFuture::new(None, |sqe| unsafe { inline::io_uring_prep_nop(sqe) }).await
        });
        assert_eq!(res.unwrap(), 0);
    }

    /// Many concurrent NOPs to shake out batching and CQ draining.
    #[test]
    fn many_concurrent_nops() {
        if !is_runtime_available() {
            return;
        }
        let total = block_on(async {
            let mut handles = Vec::new();
            for _ in 0..64 {
                handles.push(crate::spawn_local(async {
                    OpFuture::new(None, |sqe| unsafe { inline::io_uring_prep_nop(sqe) })
                        .await
                        .unwrap()
                }));
            }
            let mut sum = 0i64;
            for h in handles {
                sum += h.await as i64;
            }
            sum
        });
        assert_eq!(total, 0);
    }
}
