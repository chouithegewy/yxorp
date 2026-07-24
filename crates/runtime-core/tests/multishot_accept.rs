//! Multishot accept: one SQE yields many accepted connections.

use runtime_core::{block_on, is_runtime_available, spawn_local, TcpListener, TcpStream};

#[test]
fn multishot_accept_yields_many_connections() {
    if !is_runtime_available() {
        return;
    }
    const N: u8 = 4;

    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();

        let server = spawn_local(async move {
            let mut accept = listener.accept_multishot();
            let mut sum: u32 = 0;
            for _ in 0..N {
                let stream = accept.accept().await.unwrap();
                let (n, buf) = stream.recv(vec![0u8; 8]).await;
                assert_eq!(n.unwrap(), 1);
                sum += buf[0] as u32;
                stream.close().await.unwrap();
            }
            sum
        });

        for i in 0..N {
            let client = TcpStream::connect(addr).await.unwrap();
            let (sent, _b) = client.send_all(vec![i + 1]).await;
            sent.unwrap();
            client.close().await.unwrap();
        }

        let sum = server.await;
        assert_eq!(sum, (1..=N as u32).sum());
    });
}
