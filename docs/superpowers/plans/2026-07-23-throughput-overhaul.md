# Throughput Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut userspace body copies and per-request syscalls/allocations on the `fast` and `uring` HTTP/1.1 engines via zero-copy `splice`/registered buffers, liveness-probe gating, write coalescing, and allocation elimination.

**Architecture:** A shared zero-copy body core (`src/proxy/zerocopy.rs`) provides `splice(2)` for the epoll `fast` engine (raw fds + thread-local pipe, tokio readiness) and registered-fixed-buffer transfer for the `tokio-uring` engine. Surrounding changes remove the per-checkout liveness syscall (idle-gated), coalesce header+body writes, and drop per-request `String`/`Vec` clones. Every fast path is startup-feature-detected and degrades to the current code.

**Tech Stack:** Rust (edition 2024), tokio 1.48, tokio-uring 0.5 (`FixedBufPool`/`read_fixed`/`write_fixed`), libc 0.2 (`splice`, `pipe2`, `MSG_MORE`, `recv`), httparse, memchr.

## Global Constraints

- Rust edition 2024; `panic = "abort"` release profile — no `panic!` on the request path.
- No new crate dependencies; libc and tokio-uring are already present.
- Plaintext only on `fast`/`uring` engines (TLS stays on the `hyper` engine) — unchanged.
- New config knobs live on `RuntimeConfig` (`src/config/mod.rs:733`) with `#[serde(default)]`: `zero_copy: bool` (default `true`), `liveness_probe_idle_ms: u64` (default `250`). No config break; existing TOML must still parse.
- Every unsupported primitive logs once via `tracing::warn!` and falls back to today's path.
- `cargo test` and `cargo build` green after every task. Commit after every task.

---

## Phase 1 — Allocation elimination, liveness gating, write coalescing (fast engine)

### Task 1: Config knobs on RuntimeConfig

**Files:**
- Modify: `src/config/mod.rs:733-749` (RuntimeConfig struct + Default + impl)
- Test: inline `#[cfg(test)]` in `src/config/mod.rs`

**Interfaces:**
- Produces: `RuntimeConfig { zero_copy: bool, liveness_probe_idle_ms: u64, drain_timeout_ms: u64 }`; method `fn liveness_probe_idle(&self) -> Duration`.

- [ ] **Step 1: Write failing test** — add to the config tests module:
```rust
#[test]
fn runtime_defaults_enable_zero_copy() {
    let cfg = crate::config::RuntimeConfig::default();
    assert!(cfg.zero_copy);
    assert_eq!(cfg.liveness_probe_idle_ms, 250);
    assert_eq!(cfg.liveness_probe_idle().as_millis(), 250);
}

#[test]
fn runtime_omitted_fields_use_defaults() {
    // A config with no [runtime] table must still parse and default zero_copy on.
    let toml = r#"
        [[routes]]
        name = "r"
        host = "*"
        path_prefix = "/"
        upstream_pool = "web"
        [upstream_pools.web]
        [[upstream_pools.web.upstreams]]
        name = "a"
        url = "http://127.0.0.1:9000"
    "#;
    let snap = crate::config::ConfigSnapshot::parse(toml, "inline").unwrap();
    assert!(snap.config.runtime.zero_copy);
}
```
- [ ] **Step 2: Run test, verify fails** — `cargo test -p yxorp runtime_defaults_enable_zero_copy` — Expected: FAIL (field missing / does not compile).
- [ ] **Step 3: Implement** — replace the RuntimeConfig block:
```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    pub drain_timeout_ms: u64,
    pub zero_copy: bool,
    pub liveness_probe_idle_ms: u64,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            drain_timeout_ms: 30_000,
            zero_copy: true,
            liveness_probe_idle_ms: 250,
        }
    }
}

impl RuntimeConfig {
    pub fn drain_timeout(&self) -> Duration {
        Duration::from_millis(self.drain_timeout_ms)
    }
    pub fn liveness_probe_idle(&self) -> Duration {
        Duration::from_millis(self.liveness_probe_idle_ms)
    }
}
```
Confirm `RuntimeConfig` already carries `#[serde(default, deny_unknown_fields)]`; if the existing attribute differs, keep `default` so omitted fields fall back.
- [ ] **Step 4: Run tests** — `cargo test -p yxorp runtime_` and `cargo test -p yxorp config` — Expected: PASS.
- [ ] **Step 5: Commit** — `git add src/config/mod.rs && git commit -m "feat(config): add zero_copy and liveness_probe_idle_ms runtime knobs"`

---

### Task 2: Idle-gated liveness probe in the fast connection pool

**Files:**
- Modify: `src/proxy/h1_fast.rs:78-175` (FastConnectionPool, checkout/checkin, is_connection_alive, get_connection)
- Test: inline `#[cfg(test)]` in `src/proxy/h1_fast.rs`

**Interfaces:**
- Consumes: `RuntimeConfig::liveness_probe_idle()` (Task 1).
- Produces: `FastConnectionPool::checkin(&self, upstream_id: usize, conn: TcpStream)`, `FastConnectionPool::checkout(&self, upstream_id: usize, idle_threshold: Duration) -> Option<TcpStream>`. Pooled entries carry an `Instant`. (Keying moves to `usize` upstream id here so Task 4 can drop the authority `String`.)

- [ ] **Step 1: Write failing test** — verify a freshly checked-in connection is returned without probing, and that keying is by id:
```rust
#[tokio::test]
async fn pool_checkout_is_idle_gated_and_id_keyed() {
    use std::time::Duration;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { let _c = listener.accept().await.unwrap(); loop { tokio::time::sleep(Duration::from_secs(1)).await; } });
    let client = TcpStream::connect(addr).await.unwrap();
    let pool = FastConnectionPool::new();
    pool.checkin(7, client);
    // Immediately available under id 7, not under a different id.
    assert!(pool.checkout(9, Duration::from_millis(250)).is_none());
    assert!(pool.checkout(7, Duration::from_millis(250)).is_some());
}
```
- [ ] **Step 2: Run test, verify fails** — `cargo test -p yxorp pool_checkout_is_idle_gated_and_id_keyed` — Expected: FAIL (signature mismatch).
- [ ] **Step 3: Implement** — change the pool to id-keyed sharded vectors of `(TcpStream, Instant)` and gate the probe:
```rust
pub struct FastConnectionPool {
    shards: [std::sync::Mutex<std::collections::HashMap<usize, Vec<(TcpStream, Instant)>>>; POOL_SHARDS],
}

impl FastConnectionPool {
    pub fn new() -> Self {
        Self { shards: std::array::from_fn(|_| std::sync::Mutex::new(std::collections::HashMap::new())) }
    }
    fn shard_idx(id: usize) -> usize { id % POOL_SHARDS }

    pub fn checkout(&self, id: usize, idle_threshold: Duration) -> Option<TcpStream> {
        let idx = Self::shard_idx(id);
        let mut guard = self.shards[idx].lock().unwrap();
        if let Some(conns) = guard.get_mut(&id) {
            while let Some((conn, idle_since)) = conns.pop() {
                // Only probe connections idle beyond the threshold; hot reuse skips the syscall.
                if idle_since.elapsed() < idle_threshold || is_connection_alive(&conn) {
                    return Some(conn);
                }
            }
        }
        None
    }

    pub fn checkin(&self, id: usize, conn: TcpStream) {
        let idx = Self::shard_idx(id);
        let mut guard = self.shards[idx].lock().unwrap();
        guard.entry(id).or_default().push((conn, Instant::now()));
    }
}
```
Add `use std::time::Instant;` (already imported) and drop `DefaultHasher`/`Hash` imports if now unused. Update `get_connection` to accept `id: usize` + `idle_threshold: Duration` and call `pool.checkout(id, idle_threshold)`.
- [ ] **Step 4: Run tests** — `cargo test -p yxorp -- h1_fast` — Expected: PASS (existing serve_connection test still green after Task 4 wires the id through; for now, adjust its call sites in the same task if they reference the old signature).
- [ ] **Step 5: Commit** — `git add src/proxy/h1_fast.rs && git commit -m "perf(fast): idle-gate liveness probe and key pool by upstream id"`

---

### Task 3: Drop per-request String/Vec clones in build_request

**Files:**
- Modify: `src/proxy/h1_fast.rs:45-53` (SelectedUpstream), `:384-460` (build_request), `:255-372` (serve_connection usage sites)
- Test: existing `forwards_canonical_request_framing_and_hop_headers` + a new assertion.

**Interfaces:**
- Consumes: `Arc<UpstreamState>` with `authority() -> &Authority`, `host_header() -> &HeaderValue`, and a stable per-upstream id. Requires an id accessor on `UpstreamState` — add `pub fn pool_id(&self) -> usize` backed by a field set at pool construction, OR derive the id from `Arc::as_ptr` address hashed to a stable slot. **Chosen:** add `id: usize` to `UpstreamState` assigned globally at config load.
- Produces: `SelectedUpstream { state: Arc<UpstreamState>, protocol, connect_timeout, request_timeout, id }` — no owned `authority`/`host_header`.

- [ ] **Step 1: Add global upstream id** — in `src/config/mod.rs`, add `id: usize` to `UpstreamState`, assign from a process-global `AtomicUsize` in `UpstreamState::new`, expose `pub fn id(&self) -> usize`. Test:
```rust
#[test]
fn upstream_states_have_unique_ids() {
    let toml = r#"
        [[routes]]
        name="r"
        host="*"
        path_prefix="/"
        upstream_pool="web"
        [upstream_pools.web]
        [[upstream_pools.web.upstreams]]
        name="a"
        url="http://127.0.0.1:9000"
        [[upstream_pools.web.upstreams]]
        name="b"
        url="http://127.0.0.1:9001"
    "#;
    let snap = crate::config::ConfigSnapshot::parse(toml, "inline").unwrap();
    let ups = snap.routes.all_upstreams();
    assert_ne!(ups[0].id(), ups[1].id());
}
```
- [ ] **Step 2: Run, verify fails** — `cargo test -p yxorp upstream_states_have_unique_ids` — Expected: FAIL.
- [ ] **Step 3: Implement id** — global counter:
```rust
static NEXT_UPSTREAM_ID: AtomicUsize = AtomicUsize::new(0);
// in UpstreamState::new: id: NEXT_UPSTREAM_ID.fetch_add(1, Ordering::Relaxed),
pub fn id(&self) -> usize { self.id }
```
- [ ] **Step 4: Rework SelectedUpstream** — hold the Arc, borrow through it:
```rust
#[derive(Clone)]
struct SelectedUpstream {
    state: Arc<UpstreamState>,
    protocol: UpstreamProtocol,
    connect_timeout: Duration,
    request_timeout: Duration,
}
impl SelectedUpstream {
    fn authority(&self) -> &str { self.state.authority().as_str() }
    fn host_header_bytes(&self) -> &[u8] { self.state.host_header().as_bytes() }
    fn id(&self) -> usize { self.state.id() }
}
```
In `build_request`, construct `SelectedUpstream { state: Arc::clone(&upstream), protocol: upstream.config.protocol, connect_timeout: ..., request_timeout: ... }` and write `outbound.extend_from_slice(selected.host_header_bytes())`. Replace `request.upstream.state.mark_failure()` with `request.upstream.state.mark_failure()` (unchanged), `pool.checkin(request.upstream.id(), stream)`, `get_connection(&pool, &request.upstream, idle_threshold)` connecting via `request.upstream.authority()`.
- [ ] **Step 5: Run tests** — `cargo test -p yxorp -- h1_fast` — Expected: PASS.
- [ ] **Step 6: Commit** — `git add -A && git commit -m "perf(fast): eliminate per-request authority/host_header clones"`

---

### Task 4: Wire idle_threshold through serve_connection and coalesce writes

**Files:**
- Modify: `src/proxy/h1_fast.rs:177-375` (serve_connection), `:462-483` (read_and_forward_response)

**Interfaces:**
- Consumes: `snapshot.config.runtime.liveness_probe_idle()`, `snapshot.config.runtime.zero_copy`.
- Produces: response header + buffered body written in one syscall; single terminal flush.

- [ ] **Step 1: Write failing test** — extend the existing `proxies_keepalive_post_and_chunked_response` test to also assert a 1xx-then-final and a small-body response still round-trips byte-for-byte (guards the coalescing change). Add a GET returning `Content-Length: 2` body `ok` where the upstream writes header and body in a single `write_all` so the proxy's buffered-body coalescing path is exercised.
- [ ] **Step 2: Run, verify current passes** (regression guard) — `cargo test -p yxorp proxies_keepalive_post_and_chunked_response` — Expected: PASS before change.
- [ ] **Step 3: Implement coalescing** in `read_and_forward_response`: write `&upstream_buf[..header_end]` and, when `response.body` is `ContentLength(n)` with buffered bytes present, write header+min(n, buffered) as one slice, then continue the body copy for the remainder; remove the `downstream.flush()` that sits between header and body for non-1xx responses (keep the single flush after the body). Compute `idle_threshold` once at top of `serve_connection` from the snapshot and pass to `get_connection`.
- [ ] **Step 4: Run tests** — `cargo test -p yxorp -- h1_fast` — Expected: PASS.
- [ ] **Step 5: Commit** — `git add src/proxy/h1_fast.rs && git commit -m "perf(fast): coalesce response header+body writes, thread idle threshold"`

---

### Task 5: Idle-gate the uring pool probe

**Files:**
- Modify: `src/proxy/h1_uring.rs:76-134` (URING_POOL, checkout/checkin, is_uring_conn_alive, get_uring_connection)

**Interfaces:**
- Consumes: `snapshot.config.runtime.liveness_probe_idle()`.
- Produces: thread-local pool entries carry an `Instant`; probe gated by idle threshold.

- [ ] **Step 1: Write failing test** — inline test constructing the thread-local pool path is awkward; instead assert behavior through a small helper. Add a unit test that checks in a live stream and immediately checks it out within the threshold without the probe rejecting it. (Run inside `tokio_uring::start` in the test.)
- [ ] **Step 2: Run, verify fails.**
- [ ] **Step 3: Implement** — change `URING_POOL` value type to `Vec<(UringTcpStream, Instant)>`; `checkin` pushes `(conn, Instant::now())`; `checkout(addr, idle_threshold)` pops and returns when `idle_since.elapsed() < idle_threshold || is_uring_conn_alive(&conn)`. Thread `idle_threshold` from `serve_connection`.
- [ ] **Step 4: Run tests** — `cargo test -p yxorp -- h1_uring` — Expected: PASS.
- [ ] **Step 5: Commit** — `git add src/proxy/h1_uring.rs && git commit -m "perf(uring): idle-gate liveness probe"`

---

## Phase 2 — Zero-copy body core

### Task 6: `zerocopy` module — capability probe + fast-engine splice

**Files:**
- Create: `src/proxy/zerocopy.rs`
- Modify: `src/proxy/mod.rs` (add `pub mod zerocopy;`)
- Test: inline `#[cfg(test)]` in `src/proxy/zerocopy.rs`

**Interfaces:**
- Produces:
  - `pub fn splice_supported() -> bool` — cached one-time probe (`pipe2` + trial splice of 0 bytes between two pipe ends); logs once on failure.
  - `pub async fn splice_exact(src: &TcpStream, dst: &TcpStream, len: usize) -> std::io::Result<()>` — moves exactly `len` body bytes src→dst via a thread-local pipe pair, `SPLICE_F_MOVE|SPLICE_F_MORE|SPLICE_F_NONBLOCK`, driving readiness with `src.readable()/dst.writable()` + `try_io`. Returns `UnexpectedEof` if src closes early.
  - `pub async fn splice_stream(src: &TcpStream, dst: &TcpStream) -> std::io::Result<u64>` — close-delimited variant, splices until src EOF, returns bytes moved.

- [ ] **Step 1: Write failing test**:
```rust
#[tokio::test]
async fn splice_exact_moves_bytes() {
    if !splice_supported() { return; }
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up.local_addr().unwrap();
    let dn = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dn_addr = dn.local_addr().unwrap();
    // src: connect and send 5 bytes; dst: sink that reads.
    let src = TcpStream::connect(up_addr).await.unwrap();
    let (mut src_peer, _) = up.accept().await.unwrap();
    let dst = TcpStream::connect(dn_addr).await.unwrap();
    let (mut dst_peer, _) = dn.accept().await.unwrap();
    tokio::spawn(async move { src_peer.write_all(b"hello").await.unwrap(); });
    let mover = tokio::spawn(async move { splice_exact(&src, &dst, 5).await.unwrap(); });
    let mut got = vec![0u8; 5];
    dst_peer.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"hello");
    mover.await.unwrap();
}
```
- [ ] **Step 2: Run, verify fails** — `cargo test -p yxorp splice_exact_moves_bytes` — Expected: FAIL (module missing).
- [ ] **Step 3: Implement** the module. Thread-local `RefCell<Option<(OwnedFd read, OwnedFd write)>>` pipe created with `libc::pipe2(fds, O_NONBLOCK)`. `splice_exact` loop: `splice(src_fd -> pipe_w, chunk)` then drain `splice(pipe_r -> dst_fd)` until the moved bytes are flushed; on `EAGAIN` await the relevant readiness via tokio (`src.readable().await` / `dst.writable().await`); decrement `len`. Use `TcpStream::try_io(Interest, || raw_splice)` to stay inside tokio's reactor. Cap each splice request at e.g. 1 MiB. Handle `res == 0` (EOF) as `UnexpectedEof` when `len` unmet. `splice_supported()` uses `std::sync::OnceLock<bool>`.
- [ ] **Step 4: Run tests** — `cargo test -p yxorp zerocopy` — Expected: PASS (or early-return skip if unsupported).
- [ ] **Step 5: Commit** — `git add src/proxy/zerocopy.rs src/proxy/mod.rs && git commit -m "feat(zerocopy): splice-based body forwarding with capability probe"`

---

### Task 7: Use splice in the fast engine body paths

**Files:**
- Modify: `src/proxy/h1_fast.rs` — `copy_exact_body` (:568), `copy_body` (:546), `read_and_forward_response` (:462), request-body copy call site (:291)

**Interfaces:**
- Consumes: `zerocopy::{splice_supported, splice_exact, splice_stream}`; `snapshot.config.runtime.zero_copy`.

- [ ] **Step 1: Guard with regression tests** — the existing `proxies_keepalive_post_and_chunked_response` covers CL, chunked, and close-delimited bodies both directions. Ensure it passes before and after. Add a large-body case: a 256 KiB Content-Length response asserted byte-for-byte through the proxy.
- [ ] **Step 2: Run, verify current passes.**
- [ ] **Step 3: Implement** — in `copy_exact_body`, after writing the buffered prefix, if `zero_copy && splice_supported()` and `remaining > 0`, call `zerocopy::splice_exact(src, dst, remaining)` instead of the read/write scratch loop; else keep the loop. For `CloseDelimited` in `copy_body`, after flushing `src_buf`, use `splice_stream` when enabled. Chunked stays on the parse loop but each `copy_exact_body(src, src_buf, dst, size + 2)` now benefits from splice. Thread a `zero_copy: bool` flag into `copy_body`/`copy_exact_body` (read once in `serve_connection`).
- [ ] **Step 4: Run tests** — `cargo test -p yxorp -- h1_fast` — Expected: PASS. Also run with fallback: temporarily set `zero_copy=false` path covered by a test that forces the flag off and asserts identical output.
- [ ] **Step 5: Commit** — `git add src/proxy/h1_fast.rs && git commit -m "perf(fast): zero-copy body forwarding via splice with fallback"`

---

### Task 8: Registered fixed buffers in the uring engine

**Files:**
- Modify: `src/proxy/h1_uring.rs` — worker setup (:155-198), `serve_connection` (:229), `copy_exact_body` (:565), `read_header_block` (:538)

**Interfaces:**
- Consumes: `tokio_uring::buf::fixed::{FixedBufPool, FixedBuf}`, `UringTcpStream::{read_fixed, write_fixed}`; `snapshot.config.runtime.zero_copy`.

- [ ] **Step 1: Guard tests** — uring engine tests are limited (`h1_uring` unit tests cover `build_request`). Add an integration-style test behind `#[cfg(target_os = "linux")]` that runs a `tokio_uring::start` block: proxy one Content-Length request end-to-end through `serve_connection` and assert the body. Skip gracefully if `preflight_io_uring()` fails (CI without io_uring).
- [ ] **Step 2: Run, verify fails/first passes** accordingly.
- [ ] **Step 3: Implement** — per worker, build and `register()` a `FixedBufPool` of N buffers of `READ_CHUNK_BYTES` once inside the `tokio_uring::start` closure (before the accept loop). Store a handle accessible to `serve_connection` (pass by `Rc`/argument). In `copy_exact_body`, when `zero_copy` and the pool has a free buffer (`pool.try_next(cap)`), use `read_fixed`/`write_fixed`; else fall back to the existing `read`/`write_all` path. `register()` failure (e.g. RLIMIT_MEMLOCK) logs once and disables the fixed path for that worker.
- [ ] **Step 4: Run tests** — `cargo test -p yxorp -- h1_uring` — Expected: PASS or graceful skip.
- [ ] **Step 5: Commit** — `git add src/proxy/h1_uring.rs && git commit -m "perf(uring): registered fixed-buffer body forwarding with fallback"`

---

## Phase 3 — Measurement

### Task 9: Body-forwarding micro-bench + end-to-end throughput script

**Files:**
- Create: `benches/bench_body_forward.rs` (criterion) — measures `splice_exact` vs the scratch-loop copy over a loopback socket pair for 4 KiB / 256 KiB / 1 MiB.
- Modify: `Cargo.toml` — register the new `[[bench]]`.
- Create: `benchmarks/throughput_compare.sh` — starts yxorp with a `fast` and a `uring` listener against a loopback echo upstream, runs a small-body (64 B, RPS) and large-body (1 MiB, MB/s) load with an available HTTP load tool, records numbers, then reruns with `zero_copy=false` for the fallback baseline.

**Interfaces:**
- Consumes: `yxorp::proxy::zerocopy` (bench), the built `yxorp` binary (script).

- [ ] **Step 1:** Write `benches/bench_body_forward.rs` with criterion groups; register in `Cargo.toml`.
- [ ] **Step 2: Run** — `cargo bench --bench bench_body_forward` — Expected: completes, prints comparative timings.
- [ ] **Step 3:** Write `benchmarks/throughput_compare.sh`; make executable.
- [ ] **Step 4: Run** — execute the script on this host; capture before/after RPS + MB/s for both engines and the fallback path into the PR description.
- [ ] **Step 5: Commit** — `git add benches/bench_body_forward.rs Cargo.toml benchmarks/throughput_compare.sh && git commit -m "bench: body-forwarding micro-bench and end-to-end throughput script"`

---

## Self-review notes

- **Spec coverage:** A→Tasks 6-8; B→Tasks 2,5; C→Task 4; D→Tasks 2,3; E→Task 9; runtime knobs→Task 1. All spec components mapped.
- **Ordering:** Task 2 changes the pool signature to id-keyed; Task 3 adds the id source and updates call sites; Task 4 threads the idle threshold. Implement 2→3→4 without an intermediate green `cargo build` gap by completing call-site updates within each task (note in Task 2 Step 4).
- **Fallback:** every zero-copy path (Tasks 6-8) is gated on `zero_copy && *_supported()`; `zero_copy=false` must reproduce today's bytes exactly — asserted in Task 7 Step 4.
