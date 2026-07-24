//! Thread-per-core sharding.
//!
//! Each shard is an OS thread running its own single-thread [`crate::block_on`]
//! runtime with its own ring — share-nothing, no cross-thread locking on the hot
//! path. Shards are optionally pinned to distinct CPUs. Combined with per-shard
//! `SO_REUSEPORT` listeners (`TcpListener::bind_reuseport`), the kernel load-balances
//! incoming connections across shards while each connection stays on one core from
//! accept to close.

use std::future::Future;
use std::mem;
use std::sync::Arc;
use std::thread;

/// Number of online CPUs (fallback 1).
pub fn num_cpus() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

/// Pin the calling thread to `cpu`.
fn pin_current_thread(cpu: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(0, mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

/// Spawn `shards` worker threads, each running `f(shard_index)` to completion on its
/// own runtime. When `pin` is set, shard `i` is pinned to CPU `i % num_cpus`. Returns
/// the join handles in shard-index order; the caller joins them to collect results.
///
/// `f` is shared across threads (so it must be `Send + Sync`), but the future it
/// returns runs and is driven entirely on one thread, so it need not be `Send`.
pub fn spawn_shards<F, Fut, T>(shards: usize, pin: bool, f: F) -> Vec<thread::JoinHandle<T>>
where
    F: Fn(usize) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = T> + 'static,
    T: Send + 'static,
{
    let f = Arc::new(f);
    let ncpu = num_cpus();
    (0..shards)
        .map(|i| {
            let f = Arc::clone(&f);
            thread::Builder::new()
                .name(format!("shard-{i}"))
                .spawn(move || {
                    if pin {
                        pin_current_thread(i % ncpu);
                    }
                    crate::block_on(f(i))
                })
                .expect("failed to spawn shard thread")
        })
        .collect()
}
