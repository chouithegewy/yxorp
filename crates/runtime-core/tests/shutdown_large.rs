//! Deterministic shutdown and large-payload buffer-lifetime integration tests.

use std::rc::Rc;
use std::time::Duration;

use runtime_core::{
    block_on, in_flight, is_runtime_available, sleep, spawn_local, TcpListener, TcpStream,
};

/// `block_on` returning with a spawned task still parked on an in-flight `accept`
/// must cancel and reap that op during teardown — never free its kept-alive sockaddr
/// while the kernel still holds it. Correctness is proven by a clean exit (and no
/// AddressSanitizer report when run under ASAN).
#[test]
fn shutdown_reaps_inflight_ops() {
    if !is_runtime_available() {
        return;
    }
    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        // Detached: never awaited, and no client ever connects, so it stays parked on
        // accept when block_on returns.
        let _detached = spawn_local(async move {
            let _ = listener.accept().await;
        });
        sleep(Duration::from_millis(20)).await;
        assert!(in_flight() >= 1, "accept should be in flight before shutdown");
        // Fall off the end: block_on's shutdown must cancel + reap the accept.
    });
}

/// Move several MiB through the loopback echo, exercising owned-buffer lifetime across
/// many recv/send completions. Client send and recv run concurrently (shared fd via
/// Rc) so socket buffers cannot deadlock.
#[test]
fn large_payload_echo_preserves_bytes() {
    if !is_runtime_available() {
        return;
    }
    const N: usize = 4 << 20; // 4 MiB
    const CHUNK: usize = 256 * 1024;

    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();

        let server = spawn_local(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let mut remaining = N;
            while remaining > 0 {
                let (n, buf) = stream.recv(vec![0u8; CHUNK]).await;
                let n = n.unwrap();
                if n == 0 {
                    break;
                }
                remaining -= n;
                let (sent, _buf) = stream.send_all(buf).await;
                sent.unwrap();
            }
        });

        let payload: Vec<u8> = (0..N).map(|i| (i % 251) as u8).collect();
        let client = Rc::new(TcpStream::connect(addr).await.unwrap());

        let sender = {
            let client = client.clone();
            let payload = payload.clone();
            spawn_local(async move {
                let (sent, _buf) = client.send_all(payload).await;
                sent.unwrap();
            })
        };
        let receiver = {
            let client = client.clone();
            spawn_local(async move {
                let mut got = Vec::with_capacity(N);
                while got.len() < N {
                    let (n, buf) = client.recv(vec![0u8; CHUNK]).await;
                    let n = n.unwrap();
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                got
            })
        };

        sender.await;
        let got = receiver.await;
        server.await;

        assert_eq!(got.len(), N, "echoed byte count mismatch");
        assert!(got == payload, "echoed payload differs from source");
    });
}
