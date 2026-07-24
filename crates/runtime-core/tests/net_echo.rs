//! Loopback integration tests for the owned-buffer TCP primitives.

use runtime_core::{block_on, is_runtime_available, spawn_local, TcpListener, TcpStream};

#[test]
fn loopback_echo_roundtrips() {
    if !is_runtime_available() {
        eprintln!("io_uring unavailable; skipping");
        return;
    }
    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();

        let server = spawn_local(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let (n, buf) = stream.recv(vec![0u8; 1024]).await;
            let n = n.unwrap();
            assert!(n > 0, "server read EOF unexpectedly");
            let (sent, _buf) = stream.send_all(buf).await; // buf.len() == n
            sent.unwrap();
            stream.close().await.unwrap();
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let (sent, _b) = client.send_all(b"hello uring".to_vec()).await;
        sent.unwrap();

        let (n, got) = client.recv(vec![0u8; 1024]).await;
        let n = n.unwrap();
        assert_eq!(&got[..n], b"hello uring");

        server.await;
    });
}

#[test]
fn connect_to_dead_port_errors() {
    if !is_runtime_available() {
        return;
    }
    block_on(async {
        // 127.0.0.1:1 is (almost certainly) not listening; connect must fail cleanly.
        let result = TcpStream::connect("127.0.0.1:1".parse().unwrap()).await;
        assert!(result.is_err(), "connect to dead port unexpectedly succeeded");
    });
}
