//! A provided-buffer ring (`IORING_REGISTER_PBUF_RING`).
//!
//! Instead of handing the kernel a buffer with every `recv`, we register a ring of
//! fixed-size buffers once; the kernel picks one when data actually arrives and
//! reports its buffer id in the completion. Combined with multishot `recv`, this
//! removes per-read buffer submission entirely. Consumed buffers are recycled back to
//! the ring (see `BufLease`'s `Drop` in `net`).

use std::io;
use std::os::raw::{c_int, c_void};

use runtime_uring_sys::ffi;
use runtime_uring_sys::inline;

/// Number of buffers in the default group. Power of two (buffer-ring requirement).
pub(crate) const BUF_RING_ENTRIES: u32 = 256;
/// Size of each provided buffer.
pub(crate) const BUF_SIZE: usize = 64 * 1024;

pub(crate) struct BufRing {
    br: *mut ffi::io_uring_buf_ring,
    /// Backing storage for all buffers. Never resized after construction, so the
    /// addresses baked into the kernel ring stay valid.
    arena: Vec<u8>,
    entries: u32,
    buf_size: usize,
    bgid: u16,
    mask: c_int,
}

impl BufRing {
    pub(crate) fn new(
        ring: *mut ffi::io_uring,
        bgid: u16,
        entries: u32,
        buf_size: usize,
    ) -> io::Result<Self> {
        let mut err: c_int = 0;
        let br = unsafe { ffi::io_uring_setup_buf_ring(ring, entries, bgid as c_int, 0, &mut err) };
        if br.is_null() {
            return Err(io::Error::from_raw_os_error(err.abs()));
        }
        let mut arena = vec![0u8; entries as usize * buf_size];
        let mask = unsafe { inline::io_uring_buf_ring_mask(entries) };
        // Publish every buffer to the ring, then advance once for the whole batch.
        for bid in 0..entries {
            let addr = unsafe { arena.as_mut_ptr().add(bid as usize * buf_size) };
            unsafe {
                inline::io_uring_buf_ring_add(
                    br,
                    addr as *mut c_void,
                    buf_size as u32,
                    bid as u16,
                    mask,
                    bid as c_int,
                );
            }
        }
        unsafe { inline::io_uring_buf_ring_advance(br, entries as c_int) };
        Ok(BufRing {
            br,
            arena,
            entries,
            buf_size,
            bgid,
            mask,
        })
    }

    pub(crate) fn bgid(&self) -> u16 {
        self.bgid
    }

    /// Pointer to buffer `bid`'s storage.
    pub(crate) fn buffer_ptr(&self, bid: u16) -> *const u8 {
        unsafe { self.arena.as_ptr().add(bid as usize * self.buf_size) }
    }

    /// Return buffer `bid` to the ring for reuse.
    pub(crate) fn recycle(&mut self, bid: u16) {
        let addr = unsafe { self.arena.as_mut_ptr().add(bid as usize * self.buf_size) };
        unsafe {
            inline::io_uring_buf_ring_add(
                self.br,
                addr as *mut c_void,
                self.buf_size as u32,
                bid,
                self.mask,
                0,
            );
            inline::io_uring_buf_ring_advance(self.br, 1);
        }
    }

    /// Unregister and free the ring. Must run before `io_uring_queue_exit`.
    pub(crate) fn free(&mut self, ring: *mut ffi::io_uring) {
        unsafe {
            ffi::io_uring_free_buf_ring(ring, self.br, self.entries, self.bgid as c_int);
        }
    }
}
