//! Thread-per-core sharding: multiple pinned worker threads, each its own runtime.

use std::io::{Read, Write};
use std::sync::mpsc;

use runtime_core::{is_runtime_available, spawn_shards, TcpListener};

/// Four pinned shards, each running an independent runtime with its own listener and
/// ring, concurrently accept a connection, echo one byte, and return it. Proves N
/// independent single-thread runtimes run in parallel across cores.
#[test]
fn shards_run_independent_runtimes_in_parallel() {
    if !is_runtime_available() {
        return;
    }
    const SHARDS: usize = 4;

    // Each shard reports its bound address so the main thread can drive it.
    let (addr_tx, addr_rx) = mpsc::channel();

    let handles = spawn_shards(SHARDS, true, move |i| {
        let addr_tx = addr_tx.clone();
        async move {
            let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            addr_tx.send((i, listener.local_addr().unwrap())).unwrap();
            drop(addr_tx);

            let (stream, _peer) = listener.accept().await.unwrap();
            // Echo the single request byte back.
            let (n, buf) = stream.recv(vec![0u8; 8]).await;
            assert_eq!(n.unwrap(), 1);
            let byte = buf[0];
            let (sent, _b) = stream.send_all(buf).await;
            sent.unwrap();
            stream.close().await.unwrap();
            byte
        }
    });

    // Collect each shard's address, then connect to it from the main thread (plain
    // std sockets) sending a byte equal to the shard index.
    let mut addrs = vec![(0usize, "127.0.0.1:0".parse().unwrap()); SHARDS];
    for _ in 0..SHARDS {
        let (i, addr) = addr_rx.recv().unwrap();
        addrs[i] = (i, addr);
    }
    for (i, addr) in &addrs {
        let mut sock = std::net::TcpStream::connect(addr).unwrap();
        sock.write_all(&[*i as u8]).unwrap();
        let mut echo = [0u8; 1];
        sock.read_exact(&mut echo).unwrap();
        assert_eq!(echo[0], *i as u8, "shard {i} echoed wrong byte");
    }

    // Each shard returns the byte it served; handle[i] is shard i.
    let results: Vec<u8> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results, (0..SHARDS as u8).collect::<Vec<_>>());
}
