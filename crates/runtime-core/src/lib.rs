//! Completion-native, single-thread io_uring runtime (Phase 1 correctness kernel).
//!
//! Modules are filled in over Phase 1: generational op-slab, Ring driver + executor,
//! owned-buffer I/O primitives, timer wheel, cancellation-safe futures, deterministic
//! shutdown. See docs/superpowers plan + docs/uring_migration_analysis.md.

#![allow(dead_code)]
