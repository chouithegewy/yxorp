use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::sync::Arc;
use std::thread;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use yxorp::proxy::h1_fast::FastConnectionPool;

fn bench_connection_pool_contention(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // We can't easily mock TcpStream without a real connection, so let's start a dummy server
    let _server = rt.spawn(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // just accept and drop
        while let Ok((_, _)) = listener.accept().await {}
    });

    let mut group = c.benchmark_group("fast_connection_pool");

    group.bench_function("checkout_miss_single_thread", |b| {
        let pool = FastConnectionPool::new();
        b.iter(|| {
            let _ = pool.checkout(black_box("127.0.0.1:8080"));
        });
    });

    // To test contention with sharding, we simulate realistic proxy traffic where requests go to different upstreams/authorities
    group.bench_function("checkout_miss_multi_thread_contention", |b| {
        let pool = Arc::new(FastConnectionPool::new());
        b.iter(|| {
            std::thread::scope(|s| {
                for i in 0..4 {
                    let p = pool.clone();
                    // Each thread targets a different authority to hit different shards
                    let authority = format!("127.0.0.1:{}", 8080 + i);
                    s.spawn(move || {
                        for _ in 0..1000 {
                            let _ = p.checkout(black_box(&authority));
                        }
                    });
                }
            });
        });
    });

    group.finish();
}

criterion_group!(benches, bench_connection_pool_contention);
criterion_main!(benches);
