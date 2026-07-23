# `single-core` feature build — scope

- **Date:** 2026-07-23
- **Status:** scoping
- **Target:** fixed single-vCPU deployment (e.g. chilos.dev — 1 vCPU, ~1 GB, Debian 12)

## Context

The throughput overhaul (`2026-07-23-throughput-overhaul-design.md`) optimized for a
multi-core, bandwidth-bound edge: `splice` zero-copy, thread-per-core io_uring,
registered buffers. Deploying to a **single-core** VPS and benchmarking showed that
premise is wrong for this target:

- On one core, throughput ≈ 1 / (CPU cycles per request/byte). Memory-bandwidth
  avoidance (the point of `splice`) optimizes the resource that is **not** scarce.
- The remote loopback test showed `splice` on the fast engine **reducing** large-body
  throughput (~2.9 vs ~5.0 Gb/s) — the extra socket→pipe→socket hop and readiness
  round-trips cost more CPU than the memcpy they remove. TTFB still improved ~19×.
- The runtime is **already** single-threaded: `#[actix::main]` → `actix-rt 2.11`
  builds its `System` with `tokio::runtime::Builder::new_current_thread()`
  (`actix-rt/src/runtime.rs:16`). All `tokio::spawn` accept-workers/connections run
  on that one thread. So a "current_thread runtime option" is redundant.

Because the target's core count is fixed and known at build time, a **build
configuration** beats a runtime toggle: it can drop `rt-multi-thread` entirely
(removing tokio's internal `enum Scheduler` match and the multi-thread scheduler from
the binary), and it is the only way to swap `Arc`→`Rc`, `Mutex`/atomics→`RefCell`/
`Cell`, and `Send`→`!Send` futures on hot paths — removing thread-safety overhead the
single thread never needs. A runtime option forces the code to stay written to the
strictest (Send + atomic) requirements.

### Intended outcome

A `single-core` cargo feature (built via `--no-default-features --features single-core`)
that minimizes per-request/per-byte CPU on a fixed one-core host, validated against a
HAProxy single-thread baseline on the same machine with the same `h1load` harness.

## Feature model

Features are additive in cargo, so removal is expressed by inverting the default:

```toml
[features]
default = ["multi-core"]
multi-core = ["tokio/rt-multi-thread"]
single-core = []              # built with --no-default-features --features single-core
```

`single-core` builds get tokio without `rt-multi-thread`. (Audit transitive pulls:
`hyper-util`'s `tokio` features must not force `rt-multi-thread`; if they do, that
engine path is gated out under `single-core` — see Tier 2.)

## Tiers (increasing effort, decreasing certainty)

### Tier 1 — cheap, high-certainty, engine-agnostic (no `Send` changes)

1. **`zero_copy` default false under `single-core`.** `#[cfg(feature = "single-core")]`
   changes `RuntimeConfig::default().zero_copy` to `false`. Splice stays available via
   explicit config for latency-sensitive or real-NIC large-body cases. (`src/config/mod.rs`)
2. **Larger body buffers.** `READ_CHUNK_BYTES` 16 KiB → 64 KiB under the feature, cutting
   read+write syscalls per MiB ~4×. `cfg`-gated const in `h1_fast.rs` / `h1_uring.rs`.
3. **Read-all-available per wakeup** in the buffered copy loop to reduce reactor
   round-trips (fewer context switches). `h1_fast::copy_exact_body`.

These target small-request RPS and syscall count — the regime a single-core edge lives
in — and carry no `Send`/`!Send` risk.

### Tier 2 — runtime/build trimming

4. **Drop `rt-multi-thread`** via the feature model above; build with
   `--no-default-features --features single-core`. Removes the multi-thread scheduler
   and its hot-path enum match from the binary.
5. **Prefer the `fast` engine; gate/deprioritize `uring` under `single-core`.** io_uring's
   submit/complete overhead needs concurrency to amortize; on one core it rarely pays.
   Log a warning if a `uring` listener is configured in a `single-core` build.

### Tier 3 — thread-safety elision (real atomic removal; measure before committing)

6. **Type aliases** in a `sync` module: `#[cfg(feature = "single-core")] type Shared<T> =
   Rc<T>; type Cell<T> = RefCell<T>;` else `Arc`/`Mutex`. Swap hot-path
   `Arc`/`Mutex`/atomics: `FastConnectionPool` (`Mutex`→`RefCell`), `UpstreamState`
   (`AtomicUsize`/`AtomicBool`→`Cell`), pool `cursor`. Removes uncontended-but-nonzero
   atomic RMW (`lock`-prefixed instrs + fences) from per-request paths.
7. **`spawn_local` instead of `tokio::spawn`** for accept/connection tasks under
   `single-core`, so those futures may be `!Send` and hold `Rc`/`RefCell`. Requires a
   `LocalSet` (actix provides one) and careful `!Send` propagation.
   Note: `ArcSwap` requires `Arc`; the config snapshot stays `Arc`-based (swapped rarely,
   off the hot path), so Tier 3 targets the pool and upstream counters only.

**Caveat:** uncontended atomics on one core are cheap (a few ns each); Tier 3's win is
real but modest and must be justified by measurement, not assumed. Tier 1+2 are the
high-confidence wins.

## Verification

- Build both configs: `cargo build --release` (multi) and
  `cargo build --release --no-default-features --features single-core`. Both must pass
  `cargo test` under their config.
- Re-benchmark **with the proxy isolated**: yxorp alone on the 1-core host, origin
  (`httpterm`) and load (`h1load`) off-box / across the network — so we measure the proxy,
  not three-way loopback contention.
- Compare against the HAProxy single-thread baseline (`nbthread 1`) on the same box,
  same `h1load` params, same `httpterm` origin. Report yxorp small-request RPS and
  large-body Gb/s as a fraction of HAProxy's.

## Baseline (measured on chilos.dev, 1 vCPU)

HAProxy 2.6.12 `nbthread 1` vs yxorp `fast`, identical conditions: `httpterm` origin +
proxy + `h1load` colocated on the one core (so absolute numbers are contended, but the
HAProxy-vs-yxorp ratio is apples-to-apples). 20 conns, 5 s, 3rd-second sample.

**Small 64 B responses (RPS-bound):**

| Proxy | rps | vs HAProxy |
|-------|----:|-----------:|
| HAProxy nbthread=1 | ~19.9k | 1.00 |
| yxorp fast, zero_copy=off | ~19.3k | 0.97 |
| yxorp fast, zero_copy=on | ~19.7k | 0.99 |

All three cluster at ~20k — the shared single core (origin+client contention) is the
ceiling here, so read this as **parity: yxorp matches HAProxy on small-request RPS**,
no regression. `zero_copy` is irrelevant for bodyless responses.

**Large 1 MiB responses (bandwidth-bound):**

| Proxy | rps | Gb/s | TTFB | vs HAProxy (Gb/s) |
|-------|----:|-----:|-----:|------------------:|
| HAProxy nbthread=1 | ~912 | ~7.66 | 6.9 ms | 1.00 |
| yxorp fast, zero_copy=off | ~590 | ~5.01 | 15.3 ms | 0.65 |
| yxorp fast, zero_copy=on | ~363 | ~3.08 | **0.54 ms** | 0.40 |

**Findings:**
- **Small-request RPS: yxorp is at HAProxy parity.** The Phase-1 CPU/syscall reductions
  put it level with the reference.
- **Large-body throughput: yxorp's buffered path is ~65 % of HAProxy; splice is ~40 %.**
  This is the real single-core gap, and it is an **I/O-loop / syscall-count** gap
  (buffer size, wakeups per MiB, event-loop overhead), not an atomics gap — HAProxy's
  hand-rolled epoll loop with large-batch splice beats a general async runtime here.
- **splice confirmed counterproductive for single-core throughput** (worst of the three)
  while delivering by far the best TTFB (0.54 ms).

**Scope implication:** the highest-leverage single-core work is **Tier 1** (larger body
buffers + read-all-available → fewer syscalls/wakeups per MiB), which directly targets
the large-body gap. **Tier 3** (atomic elision) will not close an I/O-loop gap and is
deprioritized — measure before investing. `zero_copy` default off (Tier 1) is confirmed
correct for this target.
