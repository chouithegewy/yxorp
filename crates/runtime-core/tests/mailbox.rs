//! Cross-shard messaging over MSG_RING.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use runtime_core::{
    current_ring_fd, is_runtime_available, post_message, recv_message, sleep, spawn_shards,
};

/// Shard 0 posts a message to shard 1's ring via MSG_RING; shard 1 receives it. Each
/// shard publishes its ring fd to a shared registry, synchronised by a barrier.
#[test]
fn message_crosses_from_one_shard_to_another() {
    if !is_runtime_available() {
        return;
    }
    const S: usize = 2;
    const PAYLOAD: u64 = 0xA5A5_1234;

    let registry: Arc<Vec<AtomicI32>> =
        Arc::new((0..S).map(|_| AtomicI32::new(-1)).collect());
    let barrier = Arc::new(Barrier::new(S));

    let handles = spawn_shards(S, false, move |i| {
        let registry = Arc::clone(&registry);
        let barrier = Arc::clone(&barrier);
        async move {
            // Publish this shard's ring fd, then wait until all shards have published.
            registry[i].store(current_ring_fd(), Ordering::SeqCst);
            barrier.wait();

            if i == 0 {
                let target = registry[1].load(Ordering::SeqCst);
                post_message(target, PAYLOAD);
                // Drive the runtime so the queued MSG_RING SQE is submitted.
                sleep(Duration::from_millis(50)).await;
                0
            } else {
                recv_message().await
            }
        }
    });

    let results: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results[1], PAYLOAD, "shard 1 did not receive the message");
}
