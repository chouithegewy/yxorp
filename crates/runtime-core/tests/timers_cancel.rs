//! Timer behaviour and the marquee drop-cancellation safety test.

use std::time::{Duration, Instant};

use runtime_core::{
    block_on, in_flight, is_runtime_available, sleep, spawn_local, timeout, TcpListener, TcpStream,
};

#[test]
fn sleep_elapses_approximately() {
    if !is_runtime_available() {
        return;
    }
    block_on(async {
        let start = Instant::now();
        sleep(Duration::from_millis(40)).await;
        assert!(start.elapsed() >= Duration::from_millis(35), "slept too little");
    });
}

#[test]
fn timeout_returns_value_when_fast() {
    if !is_runtime_available() {
        return;
    }
    let out = block_on(async {
        timeout(Duration::from_millis(200), async { 99 }).await
    });
    assert_eq!(out, Ok(99));
}

#[test]
fn timeout_elapses_on_slow_future() {
    if !is_runtime_available() {
        return;
    }
    let out = block_on(async {
        timeout(Duration::from_millis(30), sleep(Duration::from_secs(10))).await
    });
    assert_eq!(out, Err(runtime_core::Elapsed));
}

/// The correctness-kernel headline: dropping an in-flight `recv` (via `timeout`) must
/// orphan the op — retaining its buffer until the terminal (cancel) CQE — and the slot
/// must be reaped only then. We observe the reap via `in_flight()` returning to zero,
/// and run under ASAN to prove the buffer is never freed while the kernel holds it.
#[test]
fn dropped_inflight_recv_is_orphaned_then_reaped() {
    if !is_runtime_available() {
        return;
    }
    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();

        // Server accepts and holds the connection open WITHOUT ever sending, so the
        // client's recv stays pending in the kernel until we cancel it.
        let server = spawn_local(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            sleep(Duration::from_millis(300)).await;
            drop(stream);
        });

        let client = TcpStream::connect(addr).await.unwrap();

        // A large recv that will never receive data; force-drop it via timeout.
        let recv = client.recv(vec![0u8; 1 << 20]);
        let result = timeout(Duration::from_millis(40), recv).await;
        assert!(result.is_err(), "recv unexpectedly completed");

        // The recv future was dropped in flight -> orphaned + async-cancel queued.
        // Drive the runtime so the cancellation is submitted and reaped.
        sleep(Duration::from_millis(80)).await;
        assert_eq!(in_flight(), 0, "orphaned recv was not reaped after cancellation");

        // Runtime is still healthy afterwards.
        let echo = spawn_local(async { 5 + 5 });
        assert_eq!(echo.await, 10);

        server.await;
    });
}
