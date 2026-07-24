use criterion::{Criterion, black_box, criterion_group, criterion_main};
use yxorp::config::ConfigSnapshot;

/// Benchmark the optimized single wildcard root route matching.
fn bench_single_wildcard_routing(c: &mut Criterion) {
    let config = r#"
        [[listeners]]
        name = "public"
        bind = "127.0.0.1:8080"
        protocols = ["h1"]

        [[routes]]
        name = "root"
        host = "*"
        path_prefix = "/"
        upstream_pool = "web"

        [upstream_pools.web]
        [[upstream_pools.web.upstreams]]
        name = "web-a"
        url = "http://127.0.0.1:9000"
        protocol = "h1"
        weight = 1
    "#;
    let snapshot = ConfigSnapshot::parse(config, "inline").unwrap();

    c.bench_function("route_match_single_wildcard", |b| {
        b.iter(|| {
            let _ = snapshot.routes.match_route(
                black_box(Some("example.com")),
                black_box("/api/v1/users?id=123"),
            );
        })
    });
}

/// Benchmark route matching with a list of multiple routes to evaluate linear search overhead.
fn bench_multi_route_routing(c: &mut Criterion) {
    // Generate a configuration with 10 distinct routes
    let mut config = String::from(
        r#"
        [[listeners]]
        name = "public"
        bind = "127.0.0.1:8080"
        protocols = ["h1"]

        [upstream_pools.web]
        [[upstream_pools.web.upstreams]]
        name = "web-a"
        url = "http://127.0.0.1:9000"
        protocol = "h1"
        weight = 1
    "#,
    );

    for i in 1..=10 {
        config.push_str(&format!(
            r#"
            [[routes]]
            name = "route_{}"
            host = "host{}.example.com"
            path_prefix = "/path{}"
            upstream_pool = "web"
            "#,
            i, i, i
        ));
    }

    let snapshot = ConfigSnapshot::parse(&config, "inline").unwrap();

    let mut group = c.benchmark_group("multi_route_matching");

    // Case 1: Match the first route in the sorted list
    group.bench_function("match_first", |b| {
        b.iter(|| {
            let _ = snapshot.routes.match_route(
                black_box(Some("host1.example.com")),
                black_box("/path1/resource"),
            );
        })
    });

    // Case 2: Match a middle route (e.g., 5th route)
    group.bench_function("match_middle", |b| {
        b.iter(|| {
            let _ = snapshot.routes.match_route(
                black_box(Some("host5.example.com")),
                black_box("/path5/resource"),
            );
        })
    });

    // Case 3: Match the last route (e.g., 10th route)
    group.bench_function("match_last", |b| {
        b.iter(|| {
            let _ = snapshot.routes.match_route(
                black_box(Some("host10.example.com")),
                black_box("/path10/resource"),
            );
        })
    });

    // Case 4: No match (scans all routes and returns None)
    group.bench_function("match_none", |b| {
        b.iter(|| {
            let _ = snapshot.routes.match_route(
                black_box(Some("unknown.example.com")),
                black_box("/unknown/resource"),
            );
        })
    });

    group.finish();
}

/// Benchmark the end-to-end parsing of TOML configurations.
fn bench_config_parsing(c: &mut Criterion) {
    let config = r#"
        [[listeners]]
        name = "public"
        bind = "127.0.0.1:8080"
        protocols = ["h1", "h2"]
        tls = false
        reuse_port = true
        accept_workers = 0
        backlog = 16384

        [admin]
        enabled = true
        bind = "127.0.0.1:9080"

        [telemetry]
        prometheus = true

        [runtime]
        drain_timeout_ms = 30000

        [[routes]]
        name = "local"
        host = "*"
        path_prefix = "/"
        upstream_pool = "local"

        [upstream_pools.local]
        passive_failure_threshold = 3

        [[upstream_pools.local.upstreams]]
        name = "app-a"
        url = "http://127.0.0.1:9000"
        protocol = "h1"
        weight = 1
        connect_timeout_ms = 2000
        request_timeout_ms = 30000

        [upstream_pools.local.upstreams.health_check]
        enabled = true
        path = "/healthz"
        interval_ms = 10000
        timeout_ms = 2000
    "#;

    c.bench_function("config_parsing_and_validation", |b| {
        b.iter(|| {
            let _ = ConfigSnapshot::parse(black_box(config), black_box("inline")).unwrap();
        })
    });
}

/// Benchmark upstream pool selection (weighted round-robin).
fn bench_upstream_pool_select(c: &mut Criterion) {
    let config = r#"
        [[listeners]]
        name = "public"
        bind = "127.0.0.1:8080"
        protocols = ["h1"]

        [[routes]]
        name = "root"
        host = "*"
        path_prefix = "/"
        upstream_pool = "pool"

        [upstream_pools.pool]
        passive_failure_threshold = 5

        [[upstream_pools.pool.upstreams]]
        name = "app-a"
        url = "http://127.0.0.1:9001"
        protocol = "h1"
        weight = 3

        [[upstream_pools.pool.upstreams]]
        name = "app-b"
        url = "http://127.0.0.1:9002"
        protocol = "h1"
        weight = 2

        [[upstream_pools.pool.upstreams]]
        name = "app-c"
        url = "http://127.0.0.1:9003"
        protocol = "h1"
        weight = 1
    "#;
    let snapshot = ConfigSnapshot::parse(config, "inline").unwrap();
    let route_match = snapshot.routes.match_route(None, "/").unwrap();

    let mut group = c.benchmark_group("upstream_pool");

    // Weighted round-robin selection from a 3-upstream pool
    group.bench_function("select_weighted_3", |b| {
        b.iter(|| {
            let _ = black_box(route_match.pool.select());
        })
    });

    group.finish();
}

/// Benchmark upstream pool selection with a single upstream (fast path).
fn bench_upstream_pool_select_single(c: &mut Criterion) {
    let config = r#"
        [[listeners]]
        name = "public"
        bind = "127.0.0.1:8080"
        protocols = ["h1"]

        [[routes]]
        name = "root"
        host = "*"
        path_prefix = "/"
        upstream_pool = "pool"

        [upstream_pools.pool]
        [[upstream_pools.pool.upstreams]]
        name = "app-a"
        url = "http://127.0.0.1:9001"
        protocol = "h1"
        weight = 1
    "#;
    let snapshot = ConfigSnapshot::parse(config, "inline").unwrap();
    let route_match = snapshot.routes.match_route(None, "/").unwrap();

    c.bench_function("upstream_select_single", |b| {
        b.iter(|| {
            let _ = black_box(route_match.pool.select());
        })
    });
}

/// Benchmark URI building for upstream forwarding.
fn bench_upstream_uri_build(c: &mut Criterion) {
    let config = r#"
        [[listeners]]
        name = "public"
        bind = "127.0.0.1:8080"
        protocols = ["h1"]

        [[routes]]
        name = "root"
        host = "*"
        path_prefix = "/"
        upstream_pool = "pool"

        [upstream_pools.pool]
        [[upstream_pools.pool.upstreams]]
        name = "app-a"
        url = "http://127.0.0.1:9001/base"
        protocol = "h1"
        weight = 1
    "#;
    let snapshot = ConfigSnapshot::parse(config, "inline").unwrap();
    let route_match = snapshot.routes.match_route(None, "/").unwrap();
    let upstream = route_match.pool.select().unwrap();

    let mut group = c.benchmark_group("upstream_uri");

    // Simple path passthrough (no base_path, starts with /)
    group.bench_function("build_uri_with_base", |b| {
        b.iter(|| {
            let _ = upstream
                .build_uri(black_box("/api/v1/users?id=123"))
                .unwrap();
        })
    });

    group.finish();
}

/// Benchmark route matching with large route tables (100 routes).
fn bench_large_route_table(c: &mut Criterion) {
    let mut config = String::from(
        r#"
        [[listeners]]
        name = "public"
        bind = "127.0.0.1:8080"
        protocols = ["h1"]

        [upstream_pools.web]
        [[upstream_pools.web.upstreams]]
        name = "web-a"
        url = "http://127.0.0.1:9000"
        protocol = "h1"
        weight = 1
    "#,
    );

    for i in 1..=100 {
        config.push_str(&format!(
            r#"
            [[routes]]
            name = "route_{}"
            host = "host{}.example.com"
            path_prefix = "/path{}"
            upstream_pool = "web"
            "#,
            i, i, i
        ));
    }

    let snapshot = ConfigSnapshot::parse(&config, "inline").unwrap();

    let mut group = c.benchmark_group("large_route_table_100");

    // Hit in the middle of 100 routes
    group.bench_function("match_50th", |b| {
        b.iter(|| {
            let _ = snapshot.routes.match_route(
                black_box(Some("host50.example.com")),
                black_box("/path50/resource"),
            );
        })
    });

    // Miss - scan all 100 routes
    group.bench_function("match_none", |b| {
        b.iter(|| {
            let _ = snapshot.routes.match_route(
                black_box(Some("nonexistent.example.com")),
                black_box("/nonexistent"),
            );
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_single_wildcard_routing,
    bench_multi_route_routing,
    bench_config_parsing,
    bench_upstream_pool_select,
    bench_upstream_pool_select_single,
    bench_upstream_uri_build,
    bench_large_route_table,
);
criterion_main!(benches);
