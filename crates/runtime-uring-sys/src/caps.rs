//! Runtime capability probe. We never infer support from `uname()`: every optional
//! io_uring primitive is detected by attempting the real setup / opcode, matching the
//! repo's existing preflight+fallback culture (`preflight_io_uring`, `splice_supported`).

use std::fmt;

use crate::ffi;
use crate::inline;

/// The io_uring capabilities relevant to the Phase 1 correctness kernel. Later phases
/// extend this (provided-buffer rings, multishot, SEND_ZC, direct descriptors, …).
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelCaps {
    // Setup flags (detected by attempting ring creation).
    pub single_issuer: bool,
    pub defer_taskrun: bool,
    pub taskrun_flag: bool,
    pub submit_all: bool,
    pub cqsize: bool,
    pub no_sqarray: bool,
    // Opcodes (detected via io_uring_get_probe).
    pub op_accept: bool,
    pub op_connect: bool,
    pub op_recv: bool,
    pub op_send: bool,
    pub op_read: bool,
    pub op_write: bool,
    pub op_close: bool,
    pub op_timeout: bool,
    pub op_link_timeout: bool,
    pub op_async_cancel: bool,
    pub op_socket: bool,
    pub op_msg_ring: bool,
    // Registration capabilities (Phase 2).
    pub sparse_files: bool,
    pub register_ring_fd: bool,
}

impl KernelCaps {
    /// Probe the running kernel. Returns `None` when io_uring itself is unavailable
    /// (e.g. `ENOSYS`/`EPERM` in a restricted sandbox), so callers can fall back.
    pub fn probe() -> Option<Self> {
        // A baseline ring must be creatable at all.
        if !try_setup(0, 0) {
            return None;
        }
        let mut caps = KernelCaps {
            single_issuer: try_setup(ffi::IORING_SETUP_SINGLE_ISSUER, 0),
            submit_all: try_setup(ffi::IORING_SETUP_SUBMIT_ALL, 0),
            no_sqarray: try_setup(ffi::IORING_SETUP_NO_SQARRAY, 0),
            cqsize: try_setup(ffi::IORING_SETUP_CQSIZE, 64),
            // DEFER_TASKRUN requires SINGLE_ISSUER.
            defer_taskrun: try_setup(
                ffi::IORING_SETUP_SINGLE_ISSUER | ffi::IORING_SETUP_DEFER_TASKRUN,
                0,
            ),
            // TASKRUN_FLAG is only valid alongside DEFER_TASKRUN (or COOP_TASKRUN);
            // probing it in isolation returns EINVAL, so combine it.
            taskrun_flag: try_setup(
                ffi::IORING_SETUP_SINGLE_ISSUER
                    | ffi::IORING_SETUP_DEFER_TASKRUN
                    | ffi::IORING_SETUP_TASKRUN_FLAG,
                0,
            ),
            ..Default::default()
        };
        caps.probe_opcodes();
        caps.probe_registration();
        Some(caps)
    }

    /// Whether direct (fixed) descriptors — sparse file table + direct accept/socket —
    /// are usable. Later phases treat this as the normal socket path.
    pub fn direct_descriptors_supported(&self) -> bool {
        self.sparse_files && self.op_accept && self.op_socket
    }

    /// The flag set the runtime prefers, masked to what this kernel actually supports.
    /// Missing optional flags simply drop out (probe-with-fallback).
    pub fn preferred_setup_flags(&self) -> u32 {
        let mut flags = 0;
        if self.single_issuer {
            flags |= ffi::IORING_SETUP_SINGLE_ISSUER;
        }
        if self.single_issuer && self.defer_taskrun {
            flags |= ffi::IORING_SETUP_DEFER_TASKRUN;
            // TASKRUN_FLAG only makes sense (and is only accepted) with deferred taskrun.
            if self.taskrun_flag {
                flags |= ffi::IORING_SETUP_TASKRUN_FLAG;
            }
        }
        if self.submit_all {
            flags |= ffi::IORING_SETUP_SUBMIT_ALL;
        }
        if self.no_sqarray {
            flags |= ffi::IORING_SETUP_NO_SQARRAY;
        }
        flags
    }

    /// Opcodes the Phase 1 I/O primitives require. A missing one is a hard error for
    /// the Ring engine (rather than a silent degradation).
    pub fn mandatory_opcodes_present(&self) -> bool {
        self.op_accept
            && self.op_connect
            && self.op_recv
            && self.op_send
            && self.op_read
            && self.op_write
            && self.op_close
            && self.op_timeout
            && self.op_async_cancel
    }

    fn probe_opcodes(&mut self) {
        unsafe {
            let probe = ffi::io_uring_get_probe();
            if probe.is_null() {
                return;
            }
            let supported = |op: ffi::io_uring_op::Type| {
                inline::io_uring_opcode_supported(probe, op as i32) != 0
            };
            use ffi::io_uring_op::*;
            self.op_accept = supported(IORING_OP_ACCEPT);
            self.op_connect = supported(IORING_OP_CONNECT);
            self.op_recv = supported(IORING_OP_RECV);
            self.op_send = supported(IORING_OP_SEND);
            self.op_read = supported(IORING_OP_READ);
            self.op_write = supported(IORING_OP_WRITE);
            self.op_close = supported(IORING_OP_CLOSE);
            self.op_timeout = supported(IORING_OP_TIMEOUT);
            self.op_link_timeout = supported(IORING_OP_LINK_TIMEOUT);
            self.op_async_cancel = supported(IORING_OP_ASYNC_CANCEL);
            self.op_socket = supported(IORING_OP_SOCKET);
            self.op_msg_ring = supported(IORING_OP_MSG_RING);
            ffi::io_uring_free_probe(probe);
        }
    }

    /// Probe registration features by attempting them on a throwaway ring.
    fn probe_registration(&mut self) {
        unsafe {
            let mut ring: ffi::io_uring = std::mem::zeroed();
            if ffi::io_uring_queue_init(8, &mut ring, 0) != 0 {
                return;
            }
            self.sparse_files = ffi::io_uring_register_files_sparse(&mut ring, 8) == 0;
            // register_ring_fd returns 1 (count) on success, negative errno on failure.
            self.register_ring_fd = ffi::io_uring_register_ring_fd(&mut ring) >= 0;
            ffi::io_uring_queue_exit(&mut ring);
        }
    }
}

impl fmt::Display for KernelCaps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "io_uring caps: setup[single_issuer={} defer_taskrun={} taskrun_flag={} submit_all={} cqsize={} no_sqarray={}] \
             ops[accept={} connect={} recv={} send={} read={} write={} close={} timeout={} link_timeout={} async_cancel={} socket={} msg_ring={}] \
             reg[sparse_files={} register_ring_fd={}]",
            self.single_issuer, self.defer_taskrun, self.taskrun_flag, self.submit_all, self.cqsize, self.no_sqarray,
            self.op_accept, self.op_connect, self.op_recv, self.op_send, self.op_read, self.op_write,
            self.op_close, self.op_timeout, self.op_link_timeout, self.op_async_cancel, self.op_socket, self.op_msg_ring,
            self.sparse_files, self.register_ring_fd,
        )
    }
}

/// Attempt to create (and immediately tear down) a ring with `flags`. Returns whether
/// setup succeeded. `cq_entries` is only consulted when `IORING_SETUP_CQSIZE` is set.
fn try_setup(flags: u32, cq_entries: u32) -> bool {
    unsafe {
        let mut params: ffi::io_uring_params = std::mem::zeroed();
        params.flags = flags;
        if flags & ffi::IORING_SETUP_CQSIZE != 0 {
            params.cq_entries = cq_entries;
        }
        let mut ring: ffi::io_uring = std::mem::zeroed();
        let rc = ffi::io_uring_queue_init_params(8, &mut ring, &mut params);
        if rc == 0 {
            ffi::io_uring_queue_exit(&mut ring);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_reports_caps_or_skips() {
        let Some(caps) = KernelCaps::probe() else {
            eprintln!("io_uring unavailable in this environment; skipping");
            return;
        };
        eprintln!("{caps}");
        // Any kernel new enough to run io_uring at all has these base opcodes.
        assert!(caps.mandatory_opcodes_present(), "missing base opcodes: {caps}");
    }
}
