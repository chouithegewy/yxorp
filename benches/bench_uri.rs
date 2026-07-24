use criterion::{Criterion, black_box, criterion_group, criterion_main};
use http::Uri;

fn bench_uri(c: &mut Criterion) {
    let scheme = http::uri::Scheme::HTTP;
    let authority: http::uri::Authority = "127.0.0.1:9000".parse().unwrap();
    let path = "/api/v1/users?id=123";
    let prefix = "http://127.0.0.1:9000";

    let mut group = c.benchmark_group("uri");

    group.bench_function("builder", |b| {
        b.iter(|| {
            let _ = Uri::builder()
                .scheme(scheme.clone())
                .authority(authority.clone())
                .path_and_query(path)
                .build()
                .unwrap();
        })
    });

    group.bench_function("format_parse", |b| {
        b.iter(|| {
            let uri_str = format!("{}{}", prefix, path);
            let _ = uri_str.parse::<Uri>().unwrap();
        })
    });

    group.bench_function("string_push_parse", |b| {
        b.iter(|| {
            let mut s = String::with_capacity(64);
            s.push_str(prefix);
            s.push_str(path);
            let _ = s.parse::<Uri>().unwrap();
        })
    });

    group.finish();
}

criterion_group!(benches, bench_uri);
criterion_main!(benches);
