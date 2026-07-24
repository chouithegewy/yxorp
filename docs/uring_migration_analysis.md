# Maximizing io_uring in yxorp: migration off `tokio-uring` to a bespoke `io-uring` reactor

- **Date:** 2026-07-23
- **Branch:** `perf/throughput-overhaul`
- **Status:** analysis / design proposal (no code changed)
- **Scope studied:** `src/proxy/h1_uring.rs`, `src/proxy/mod.rs`, `src/proxy/zerocopy.rs`, `src/proxy/h1_fast.rs`, `src/config/mod.rs`, `Cargo.toml`, throughput-overhaul design/plan docs.

---

## 1. Your thesis is correct

> "io_uring is not guaranteed to be a performance boost by simply switching notifications from epoll to uring."

Right — and that is essentially what the current `uring` engine does. It runs on `tokio-uring 0.5`, which models **one future per I/O op**: each `read`/`write`/`accept` submits a single SQE and awaits its single CQE. That is epoll-shaped request/response semantics riding an io_uring transport. It pays io_uring's submit/complete bookkeeping **without** collecting the structural wins that actually make io_uring faster than epoll:

- no batched submission (one `io_uring_enter` amortized over many ops),
- no multishot accept / multishot recv,
- no provided buffer rings,
- no `SPLICE`/`SEND_ZC` ops,
- no linked SQEs,
- no SQPOLL,
- no registered files.

The code itself already admits this — `src/proxy/mod.rs:222` warns that on single-core builds "io_uring submit/complete overhead rarely amortizes on one core," and the design doc (`docs/superpowers/specs/2026-07-23-throughput-overhaul-design.md`) notes tokio-uring 0.5 lacks splice/multishot/provided-buffers. The `zero_copy` win the current engine does get is only `read_fixed`/`write_fixed_all` over a `FixedBufPool` (registered buffers) — a single registered copy, not zero copy.

`tokio-uring` is also effectively unmaintained (last meaningful release 0.5, 2023), so it will never gain those ops. Continuing to invest in it is a dead end.

## 2. What "migrate to liburing" means in Rust

`liburing` is the C library. In a Rust project the idiomatic equivalent is the **`io-uring` crate** (Quininer / tokio-rs org) — a thin, maintained, `no_std`-friendly binding over the raw io_uring interface (setup flags, SQ/CQ, every opcode, `Probe`, buffer-ring and file/buffer registration). **It is already a direct dependency** (`io-uring = "0.6.4"`, currently used only for the `preflight_io_uring()` capability check at `h1_uring.rs:252`).

`tokio-uring` is built *on top of* the `io-uring` crate and adds the futures/runtime layer that costs us the per-op model. So the migration is:

> **Drop `tokio-uring`. Build a bespoke, completion-driven, thread-per-core reactor directly on the `io-uring` crate, using `libc` for the socket/`setsockopt`/pipe plumbing the crate doesn't wrap.**

**Recommendation: use the `io-uring` crate, not raw FFI to C `liburing`.** It exposes everything we need (opcodes, `Probe`, `submitter.register_files/register_buffers`, `buf_ring`), is memory-safe at the binding layer, and needs no `build.rs`/C toolchain. `libc` (already a dep) covers `socket`/`bind`/`setsockopt`/`pipe2`/`SO_REUSEPORT` — call those directly, exactly as `zerocopy.rs` already calls `splice`/`pipe2`/`fcntl`. FFI to C liburing buys nothing here and adds a native build dependency.

## 3. Where the real wins are (ranked for an HTTP/1.1 reverse proxy)

The core architectural shift is from **"async/await future per op"** to an **explicit per-connection state machine driven by completions**, with one ring per worker thread. Because a proxy connection is a fixed pipeline (downstream ⇄ upstream), a hand-rolled state machine tagged by `user_data` is what unlocks batching and multishot.

| # | Technique | io_uring primitive | Payoff | Cost / risk | Min kernel |
|---|-----------|--------------------|--------|-------------|-----------|
| 1 | **Batched submit + full CQ drain** | one `submit()` per loop iter, drain all CQEs, dispatch by `user_data` | **High** — this is where "fewer syscalls" actually materializes; one `enter` amortized over N ops | Core reactor rewrite | any |
| 2 | **Multishot accept** | `AcceptMulti` | Med-High — one accept SQE yields a CQE per new conn; no re-arm | fd lifecycle | 5.19 |
| 3 | **Provided buffer rings + multishot recv** | `PbufRing` (`buf_ring`) + `RecvMulti` w/ `IOSQE_BUFFER_SELECT` | **High** — kernel picks the recv buffer (returns `bid`); no per-read owned-`Vec` churn; recv re-arms itself. Kills the `Option<Vec<u8>>` take/resize/reclaim dance in `read_header_block`/`copy_*` | Buffer recycle discipline; short-read/`ENOBUFS` handling | 5.19 |
| 4 | **Zero-copy body relay via SPLICE** | `Splice` (socket→pipe, pipe→socket), pair linked with `IOSQE_IO_LINK` | **High for large bodies** — kernel-to-kernel, no userspace copy; the ring-native analog of today's `zerocopy.rs` | pipe per conn/worker; link cancel semantics | 5.7 |
| 5 | **Ring-native timeouts** | `Timeout` / `LinkTimeout` | **Mandatory** — dropping tokio-uring drops tokio's timer; header/body/request deadlines must become ring ops (or a userspace timer wheel woken by `Timeout`) | Replaces every `tokio::time::timeout` in the engine | any |
| 6 | **Registered files (fixed fds)** | `register_files` + `IOSQE_FIXED_FILE`; accept installs into a fixed slot | Med — skips per-op `fget/fput`; prerequisite for full SQPOLL benefit | fd-slot allocator | 5.1 / 5.19 for direct-accept |
| 7 | **Zero-copy send** | `SendZc` / `SendMsgZc` (extra "notif" CQE when buffer is free) | Med — only when body already sits in userspace/registered buffers and is large (> a few KiB); fixed notif overhead makes it a loss for small responses | Two CQEs per send; buffer pin lifetime | 6.0 |
| 8 | **SQPOLL** | `IORING_SETUP_SQPOLL` (+ registered files) | Med-High at high RPS — removes submit-side `enter` syscalls entirely | Dedicated kernel poller thread burns a core; competes with thread-per-core workers; make it opt-in | 5.1+ (cap relaxed on newer) |
| 9 | **Registered send buffers** | `register_buffers` + `WriteFixed` for headers/small bodies | Low-Med — keep the current `FixedBufPool` concept | buffer index mgmt | 5.1 |

### Body-relay decision (splice vs SEND_ZC)
- **Large `Content-Length` / close-delimited bodies → SPLICE** through a pipe, mirroring `zerocopy.rs` semantics (`SPLICE_F_MOVE|F_MORE`), but submitted as linked ring ops. Payload never enters userspace.
- **Small bodies already recv'd into a provided buffer → plain `Send`** (a memcpy under ~32–64 KiB is cheaper than SEND_ZC's page-pin + second CQE).
- Reserve `SEND_ZC` for the case where a large body is already resident in a registered buffer.

## 4. The honest caveats (measure, don't assume)

- **This is a large rewrite.** ~1000 lines of `async` state machine (`h1_uring.rs`) become a hand-rolled completion state machine with explicit **buffer lifetime** (a buffer must outlive its SQE until the CQE arrives — the classic io_uring use-after-free footgun that tokio-uring's owned-buffer API hid from us), **fd-slot lifecycle**, `user_data` tagging, **cancellation**, and **timeout** management.
- **Not guaranteed faster — exactly your point.** Wins are workload-shaped: syscall batching + multishot recv + SQPOLL help **small-request keepalive RPS**; splice/SEND_ZC help **large-body MB/s**. At low concurrency, tiny requests, or the (out-of-scope here) TLS path, io_uring can *regress* versus epoll. The existing `fast` engine (epoll + `splice` + coalescing, `h1_fast.rs`/`zerocopy.rs`) is already well-optimized and is the bar to beat, not just the old tokio-uring engine.
- **Kernel-version sensitivity.** Multishot recv, buffer rings, multishot accept need 5.19+; SEND_ZC needs 6.0; SPLICE 5.7. Must runtime-probe via `io_uring::Probe` and fall back — the repo already has this culture (`splice_supported()` in `zerocopy.rs:29`, the `FIXED_POOL_DISABLED` latch and `preflight_io_uring()` in `h1_uring.rs`).
- **No tokio timers, no tokio tasks** inside the ring worker. Everything the current engine gets "for free" from tokio (`tokio::time::timeout`, `spawn`) must be rebuilt on ring primitives. The listener/shutdown orchestration in `serve_listener` (`h1_uring.rs:174`) stays tokio-side; only the per-worker hot loop goes bespoke.

## 5. What can be reused unchanged

The HTTP logic is transport-agnostic and should be lifted out of the tokio-uring engine verbatim:

- Request building / header rewriting: `build_request`, `append_forward_headers`, `should_skip_header`, `content_length`, `request_wants_close` (`h1_uring.rs:450-772`).
- Response parsing: `parse_response`, `response_content_length`, `ResponseBody` (`h1_uring.rs:513-579`).
- Routing / upstream selection: `snapshot.routes.match_route(...)`, `pool.select_arc()` — same calls the `fast` engine uses (`h1_fast.rs:425/431`).
- Rate limiting: `crate::proxy::rate_limit::RateLimiter`.
- Listener/shutdown scaffolding, `SO_REUSEPORT` socket setup: `bind_listener_socket`, `set_reuseport` (`h1_uring.rs:809-847`), `ConnectionTracker` (`proxy/mod.rs:123`).
- Config knobs: `RuntimeConfig { zero_copy, liveness_probe_idle_ms }` (`config/mod.rs:733`); add SQPOLL/registered-files knobs alongside.

So the rewrite is confined to the **I/O engine** (accept loop, buffer management, read/write/splice, timeouts, connection pool), not the proxy semantics.

## 6. Recommended migration strategy — incremental + A/B, not big-bang

Because it is risky and must be measured against the `fast` engine, do **not** rip out tokio-uring first.

1. **Add a new engine variant** `Http1Engine::Ring` (keep `Uring` = tokio-uring temporarily) so both run side-by-side for benchmarking. New module `src/proxy/h1_ring.rs`.
2. **Phase 1 — reactor skeleton:** one ring/worker (thread-per-core, `SO_REUSEPORT`), multishot accept, batched submit + CQ drain, a per-connection state machine doing plain `Recv`/`Send`, ring-native `Timeout`s. Lift the reusable HTTP logic (§5). Gate on `Probe`; must pass the existing `h1_uring` integration tests (ported).
3. **Phase 2 — provided buffer rings + multishot recv.** Retire the `Option<Vec<u8>>` buffer churn.
4. **Phase 3 — SPLICE body relay** (linked in/out ops) for `ContentLength`/`CloseDelimited`; ring-native corking of header+first-body.
5. **Phase 4 — registered files + optional SQPOLL** (new opt-in config knobs, default off; document the dedicated-core cost).
6. **Phase 5 — SEND_ZC** where a large body is already in a registered buffer.
7. **Phase 6 — benchmark gate** vs the `fast` engine using `benchmarks/proxy_compare.py` / `dpbench` on two profiles (64 B keepalive RPS, ≥1 MiB MB/s) on the target kernel. Only if `Ring` wins do we make it the default and **delete `tokio-uring` + `h1_uring.rs`**, folding `Ring` into `Uring`.

Each phase is independently testable, benchmarked, and revertible; the `fast` engine remains the safety net throughout.

## 7. Concrete next step

If you want to proceed, the first commit is **Phase 1 scaffolding**: `Http1Engine::Ring` variant + `h1_ring.rs` with a single-ring reactor (multishot accept, batched submit/drain, plain recv/send state machine, ring `Timeout`s) reusing the HTTP-logic functions from §5, gated behind an `io_uring::Probe` feature check with fallback to the `fast` engine. That establishes the reactor shape and CI coverage before layering buffer rings / splice / SQPOLL on top.

I recommend we run the brainstorming/planning skill on Phase 1 to nail the buffer-lifetime and timeout design before writing reactor code — that is where the io_uring footguns live.
