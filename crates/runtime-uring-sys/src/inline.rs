//! Hand-declared externs for liburing's `static inline` API helpers.
//!
//! bindgen does not emit `static inline` functions (they have no external symbol in
//! a normal translation unit), but the vendored **liburing-ffi** archive exports
//! every one of them as a real symbol — verified in `build.rs` against
//! `src/liburing-ffi.map`. We therefore declare them by hand with the stable
//! liburing 2.15 C ABI and let the linker resolve them against that archive.

use std::os::raw::{c_int, c_uint, c_void};

use libc::{sockaddr, socklen_t};

use crate::ffi::{__kernel_timespec, io_uring, io_uring_cqe, io_uring_probe, io_uring_sqe};

unsafe extern "C" {
    // Submission / completion queue plumbing.
    pub fn io_uring_get_sqe(ring: *mut io_uring) -> *mut io_uring_sqe;
    pub fn io_uring_submit(ring: *mut io_uring) -> c_int;
    pub fn io_uring_submit_and_wait(ring: *mut io_uring, wait_nr: c_uint) -> c_int;
    pub fn io_uring_peek_cqe(ring: *mut io_uring, cqe_ptr: *mut *mut io_uring_cqe) -> c_int;
    pub fn io_uring_wait_cqe_nr(
        ring: *mut io_uring,
        cqe_ptr: *mut *mut io_uring_cqe,
        wait_nr: c_uint,
    ) -> c_int;
    pub fn io_uring_cqe_seen(ring: *mut io_uring, cqe: *mut io_uring_cqe);
    pub fn io_uring_cq_advance(ring: *mut io_uring, nr: c_uint);

    // SQE tagging.
    pub fn io_uring_sqe_set_data64(sqe: *mut io_uring_sqe, data: u64);
    pub fn io_uring_cqe_get_data64(cqe: *const io_uring_cqe) -> u64;
    pub fn io_uring_sqe_set_flags(sqe: *mut io_uring_sqe, flags: c_uint);

    // Capability probe.
    pub fn io_uring_opcode_supported(p: *const io_uring_probe, op: c_int) -> c_int;

    // Operation prep helpers (Phase 1 set).
    pub fn io_uring_prep_nop(sqe: *mut io_uring_sqe);
    pub fn io_uring_prep_accept(
        sqe: *mut io_uring_sqe,
        fd: c_int,
        addr: *mut sockaddr,
        addrlen: *mut socklen_t,
        flags: c_int,
    );
    pub fn io_uring_prep_connect(
        sqe: *mut io_uring_sqe,
        fd: c_int,
        addr: *const sockaddr,
        addrlen: socklen_t,
    );
    pub fn io_uring_prep_recv(
        sqe: *mut io_uring_sqe,
        fd: c_int,
        buf: *mut c_void,
        len: usize,
        flags: c_int,
    );
    pub fn io_uring_prep_send(
        sqe: *mut io_uring_sqe,
        fd: c_int,
        buf: *const c_void,
        len: usize,
        flags: c_int,
    );
    pub fn io_uring_prep_read(
        sqe: *mut io_uring_sqe,
        fd: c_int,
        buf: *mut c_void,
        nbytes: c_uint,
        offset: u64,
    );
    pub fn io_uring_prep_write(
        sqe: *mut io_uring_sqe,
        fd: c_int,
        buf: *const c_void,
        nbytes: c_uint,
        offset: u64,
    );
    pub fn io_uring_prep_close(sqe: *mut io_uring_sqe, fd: c_int);
    pub fn io_uring_prep_timeout(
        sqe: *mut io_uring_sqe,
        ts: *mut __kernel_timespec,
        count: c_uint,
        flags: c_uint,
    );
    pub fn io_uring_prep_link_timeout(
        sqe: *mut io_uring_sqe,
        ts: *mut __kernel_timespec,
        flags: c_uint,
    );
    pub fn io_uring_prep_cancel64(sqe: *mut io_uring_sqe, user_data: u64, flags: c_int);

    // Direct (fixed) descriptor prep helpers (Phase 2).
    pub fn io_uring_prep_accept_direct(
        sqe: *mut io_uring_sqe,
        fd: c_int,
        addr: *mut sockaddr,
        addrlen: *mut socklen_t,
        flags: c_int,
        file_index: c_uint,
    );
    pub fn io_uring_prep_socket_direct_alloc(
        sqe: *mut io_uring_sqe,
        domain: c_int,
        socket_type: c_int,
        protocol: c_int,
        flags: c_uint,
    );
    pub fn io_uring_prep_close_direct(sqe: *mut io_uring_sqe, file_index: c_uint);

    // Cross-ring messaging (Phase 2).
    pub fn io_uring_prep_msg_ring(
        sqe: *mut io_uring_sqe,
        fd: c_int,
        len: c_uint,
        data: u64,
        flags: c_uint,
    );
}

/// `IOSQE_FIXED_FILE` flag value: `1 << IOSQE_FIXED_FILE_BIT`. bindgen only exposes the
/// bit position, so we define the flag here. Set on an SQE to interpret its `fd` field
/// as an index into the registered fixed-file table.
pub const IOSQE_FIXED_FILE: u32 = 1 << 0;

/// Passed as `file_index` to a direct op to auto-allocate a free fixed-file slot; the
/// chosen index is returned in `cqe.res`. Equals `IORING_FILE_INDEX_ALLOC` (`~0u32`).
pub const FILE_INDEX_ALLOC: u32 = u32::MAX;
