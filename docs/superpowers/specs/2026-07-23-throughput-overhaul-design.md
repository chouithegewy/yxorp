# Zero-copy, low-syscall throughput overhaul — design

- **Date:** 2026-07-23
- **Status:** approved, phased implementation
- **Scope:** `src/proxy/h1_fast.rs`, `src/proxy/h1_uring.rs`, new `src/proxy/zerocopy.rs`, `src/config/mod.rs`

## Context

`yxorp` ships three interchangeable HTTP/1.1 proxy engines selected per listener via
`Http1Engine` (`src/config/mod.rs`): `hyper` (default, full-featured), `fast`
(`h1_fast.rs`, hand-rolled httparse+memchr, plaintext), and `uring`
(`h1_uring.rs`, thread-per-core `tokio-uring`). The `fast` and `uring` engines are
the throughput paths.

Profiling the hot path by inspection surfaced costs that no current code addresses
(confirmed: no `splice`, `sendfile`, kTLS, `writev`, or registered io_uring buffers
anywhere in `src/`):

1. **Body bytes are copied through userspace.** `copy_exact_body`
   (`h1_fast.rs:568`, `h1_uring.rs:565`) reads into a 16 KB buffer then `write_all`s
   it — two userspace copies per body chunk, no kernel-to-kernel path.
2. **A `recv(MSG_PEEK)` syscall on every pool checkout** (`is_connection_alive`,
   `h1_fast.rs:136`; `is_uring_conn_alive`, `h1_uring.rs:101`) — an extra syscall per
   request purely to liveness-probe, even for a connection returned microseconds ago.
3. **Split header/body writes with mid-flush** on the response path
   (`read_and_forward_response`, `h1_fast.rs:462`) — multiple `send` syscalls where a
   coalesced write would do.
4. **Per-request allocations** in `build_request` — `SelectedUpstream` clones
   `authority: String` + `host_header: Vec<u8>` every request; the fast pool clones
   the authority `String` on every checkin and hashes it on every checkout.
5. **The `uring` engine uses no modern io_uring features** — no registered buffers;
   it juggles `Option<Vec<u8>>` allocate/resize/take per read.

The dpbench dataplane suite (`dpbench/`) is the throughput yardstick.

### Intended outcome

Cut the two dominant costs on both hot engines — userspace body copies (bandwidth)
and per-request syscalls/allocations (RPS) — with every fast path feature-detected at
startup and degrading cleanly to today's code on unsupported kernels. Target profiles:
small-request RPS **and** large-body MB/s, both engines.

## Design

### Platform facts (verified)

- Fast-engine zero-copy = plain `libc::splice(2)` on raw fds, driven by tokio
  readiness (`TcpStream::try_io`). No new crate.
- `tokio-uring 0.5` exposes **no** splice/multishot/provided-buffers but **does**
  expose registered fixed buffers (`FixedBufPool`/`FixedBufRegistry` +
  `read_fixed`/`write_fixed`). Raw-ring `Splice` opcode exists in the `io-uring`
  crate but will not compose with tokio-uring's driver, so the uring engine's SOTA
  move is registered-buffer single-copy I/O, not splice.

### Components

**A. Shared zero-copy body core — new `src/proxy/zerocopy.rs`**
- Fast engine: `splice(2)` through a **thread-local reused pipe pair**,
  `SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK`, readiness via `try_io`.
  Engages for `ContentLength` / `CloseDelimited` bodies and per-chunk **data
  segments** of chunked bodies (chunk sizes are already parsed and re-emitted).
  Buffered prefix bytes (already read past the header) are written first, then the
  remainder is spliced.
- uring engine: `read_fixed` → `write_fixed` over a per-worker registered
  `FixedBufPool`, replacing the `Option<Vec<u8>>` allocate/resize/take churn with a
  single registered copy.

**B. Kill the per-checkout liveness syscall (both pools)**
- Tag each pooled connection with an idle-since `Instant`. On checkout, run the
  `recv(MSG_PEEK)` probe **only** when idle > threshold (default 250 ms,
  configurable via `liveness_probe_idle_ms`). Hot keepalive reuse skips the syscall.

**C. Syscall coalescing (fast engine)**
- Write the response header together with the already-buffered leading body bytes as
  one contiguous `write_all` (they are contiguous in `upstream_buf`); drop the
  mid-flush. When splicing the body, send the header with `MSG_MORE` / `TCP_CORK` so
  the kernel coalesces it with the spliced body, then uncork. Same on the request
  path (outbound header + buffered request-body prefix).

**D. Per-request allocation elimination (fast engine)**
- `SelectedUpstream` holds the `Arc<UpstreamState>` (already present) and borrows
  `authority`/`host_header` from `UpstreamUriBase` instead of cloning `String` +
  `Vec<u8>`; only `Copy` scalars (timeouts, protocol) are copied.
- The fast connection pool is keyed by upstream **integer id** (fixed at config
  load) instead of `String` authority, removing the per-checkin `clone()` and
  per-checkout hashing. Pooled entries become `(TcpStream, Instant)`.

**E. Measurement**
- Criterion micro-bench plus a loopback end-to-end throughput script measuring
  small-request RPS and large-body MB/s on both engines, reusing `benches/` and
  `benchmarks/proxy_compare.py` / dpbench. Capture before/after numbers.

### Runtime posture

A one-time startup capability probe (pipe2 + a trial splice; fixed-buffer
`register()`). Any unsupported primitive logs once and falls back to today's path.
New config knobs, both with safe defaults, no config break:
- `zero_copy: bool` (default `true`) — master switch for splice / fixed-buffer paths.
- `liveness_probe_idle_ms: u64` (default `250`) — idle threshold for the probe.

### Correctness / risk

- Splice preserves exact framing: chunked size lines and trailers stay on the parse
  path; only data segments splice. No-body responses (HEAD / 1xx / 204 / 304) and
  TE/CL ambiguity are already handled in `build_request` / `parse_response`, so
  splice only engages for byte-carrying bodies.
- Idle-gated probe still catches stale pooled connections beyond the threshold.
- Each change is TDD'd; full `cargo test` + benches gate each phase.

## Phasing

1. **Phase 1 — D + B + C:** allocation elimination, liveness-probe idle gating,
   response/request write coalescing. Pure low-risk wins, no new syscalls beyond
   `MSG_MORE`.
2. **Phase 2 — A:** `zerocopy` module — fast-engine `splice`, uring registered
   fixed buffers. The zero-copy core.
3. **Phase 3 — E:** benchmarks, before/after capture, tuning.

## Verification

- `cargo test` (unit + integration) green after every phase.
- `cargo bench` (existing `bench_yxorp`, `bench_pool`, plus new body-forwarding
  bench) shows no regression on route-match / pool micro-benches.
- Loopback end-to-end run (`benchmarks/proxy_compare.py` or dpbench) on `fast` and
  `uring` listeners for two profiles: 64 B keepalive responses (RPS) and 1 MB
  responses (MB/s), before vs after, on this kernel.
- Force-fallback run (`zero_copy = false`) proves the degraded path stays correct.
