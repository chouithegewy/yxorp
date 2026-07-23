//! Compares zero-copy `splice` body forwarding against the buffered read/write
//! copy loop the fast engine uses as its fallback. Both move an identical payload
//! between two loopback TCP socket pairs; throughput is reported in bytes/s.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use yxorp::proxy::zerocopy::{splice_exact, splice_supported};

/// A connected loopback pair: `.0` is the local end, `.1` its peer.
async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let local = TcpStream::connect(addr).await.unwrap();
    let (peer, _) = listener.accept().await.unwrap();
    (local, peer)
}

/// Buffered baseline mirroring `h1_fast::copy_exact_body`'s fallback loop.
async fn buffered_copy(src: &mut TcpStream, dst: &mut TcpStream, mut remaining: usize) {
    let mut scratch = [0u8; 16 * 1024];
    while remaining > 0 {
        let limit = scratch.len().min(remaining);
        let read = src.read(&mut scratch[..limit]).await.unwrap();
        dst.write_all(&scratch[..read]).await.unwrap();
        remaining -= read;
    }
}

/// Feed `len` bytes into `src` and drain `len` bytes out of `dst` concurrently
/// with `mover`, which moves the body from the read side to the write side.
async fn move_once<F, Fut>(len: usize, mover: F)
where
    F: FnOnce(TcpStream, TcpStream) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let (src, src_peer) = pair().await;
    let (dst, dst_peer) = pair().await;
    let payload = vec![0xABu8; len];
    let feeder = tokio::spawn(async move {
        let mut peer = src_peer;
        peer.write_all(&payload).await.unwrap();
        peer
    });
    let drain = tokio::spawn(async move {
        let mut peer = dst_peer;
        let mut sink = vec![0u8; len];
        peer.read_exact(&mut sink).await.unwrap();
        peer
    });
    mover(src, dst).await;
    let _keep_alive = (feeder.await.unwrap(), drain.await.unwrap());
}

fn bench_body_forward(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("body_forward");
    let splice_ok = splice_supported();

    for &len in &[4 * 1024usize, 256 * 1024, 1024 * 1024] {
        group.throughput(Throughput::Bytes(len as u64));
        let label = match len {
            4096 => "4KiB",
            262144 => "256KiB",
            _ => "1MiB",
        };

        group.bench_with_input(BenchmarkId::new("buffered", label), &len, |b, &len| {
            b.iter(|| {
                rt.block_on(move_once(len, |mut src, mut dst| async move {
                    buffered_copy(&mut src, &mut dst, len).await;
                }));
                black_box(());
            });
        });

        if splice_ok {
            group.bench_with_input(BenchmarkId::new("splice", label), &len, |b, &len| {
                b.iter(|| {
                    rt.block_on(move_once(len, |src, dst| async move {
                        splice_exact(&src, &dst, len).await.unwrap();
                    }));
                    black_box(());
                });
            });
        }
    }

    group.finish();
}

criterion_group!(benches, bench_body_forward);
criterion_main!(benches);
