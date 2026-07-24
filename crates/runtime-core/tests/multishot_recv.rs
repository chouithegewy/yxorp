//! Multishot recv over the provided-buffer ring.

use runtime_core::{block_on, is_runtime_available, spawn_local, TcpListener, TcpStream};

#[test]
fn multishot_recv_reads_via_provided_buffers() {
    if !is_runtime_available() {
        return;
    }
    const MSG: &[u8] = b"provided-buffer multishot recv works end to end!";

    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();

        let server = spawn_local(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            {
                let mut recv = stream.recv_multishot().unwrap();
                while received.len() < MSG.len() {
                    match recv.recv().await.unwrap() {
                        Some(lease) => received.extend_from_slice(&lease), // lease recycled on drop
                        None => break,
                    }
                }
            }
            // Echo what we read back to the client.
            let (sent, _b) = stream.send_all(received.clone()).await;
            sent.unwrap();
            received
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let (sent, _b) = client.send_all(MSG.to_vec()).await;
        sent.unwrap();

        let (n, got) = client.recv(vec![0u8; 128]).await;
        let n = n.unwrap();
        assert_eq!(&got[..n], MSG);

        let served = server.await;
        assert_eq!(served, MSG);
    });
}
