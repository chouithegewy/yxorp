//! Sealed owned-buffer traits.
//!
//! A completion runtime cannot safely lend a borrowed slice to the kernel: if the
//! future is dropped while a cancellation races, the borrow ends before the kernel is
//! guaranteed to have stopped touching the memory. So the core I/O API consumes
//! **owned** buffers that move into the operation for its whole lifetime and are
//! handed back on completion.
//!
//! The traits are `unsafe` and sealed: implementors must guarantee a stable heap
//! address and capacity for as long as the value is owned (so moving the buffer
//! value, e.g. into the op slot, does not move the bytes the kernel sees). `Vec<u8>`
//! satisfies this — its heap allocation is stable across moves of the `Vec` itself.

mod sealed {
    pub trait Sealed {}
    impl Sealed for Vec<u8> {}
}

/// An owned, stably-addressed byte buffer the kernel may read from.
///
/// # Safety
/// `stable_ptr` must return the same address for as long as the value is owned and
/// not mutated through a `&mut` outside an in-flight op, and `bytes_init` bytes from
/// it must be initialized and valid to read.
pub unsafe trait IoBuf: sealed::Sealed + Unpin + 'static {
    /// Stable pointer to the start of the buffer.
    fn stable_ptr(&self) -> *const u8;
    /// Number of initialized bytes available to transmit.
    fn bytes_init(&self) -> usize;
}

/// An owned, stably-addressed byte buffer the kernel may write into.
///
/// # Safety
/// `stable_mut_ptr` must return the same address as [`IoBuf::stable_ptr`] and remain
/// valid to write up to `bytes_total` bytes; `set_init(n)` marks the first `n` bytes
/// initialized after a completed write.
pub unsafe trait IoBufMut: IoBuf {
    /// Stable mutable pointer to the start of the buffer.
    fn stable_mut_ptr(&mut self) -> *mut u8;
    /// Total writable capacity in bytes.
    fn bytes_total(&self) -> usize;
    /// Record that the kernel initialized the first `n` bytes.
    ///
    /// # Safety
    /// `n` bytes starting at `stable_mut_ptr` must actually have been initialized.
    unsafe fn set_init(&mut self, n: usize);
}

// SAFETY: a `Vec<u8>`'s heap allocation address and capacity are stable across moves
// of the `Vec` struct; only the 3-word header moves. `bytes_init` is its length.
unsafe impl IoBuf for Vec<u8> {
    fn stable_ptr(&self) -> *const u8 {
        self.as_ptr()
    }
    fn bytes_init(&self) -> usize {
        self.len()
    }
}

// SAFETY: as above; writable region spans the full capacity, and `set_init` sets the
// length (the bytes are initialized by the kernel write before this is called).
unsafe impl IoBufMut for Vec<u8> {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_ptr()
    }
    fn bytes_total(&self) -> usize {
        self.capacity()
    }
    unsafe fn set_init(&mut self, n: usize) {
        debug_assert!(n <= self.capacity());
        unsafe { self.set_len(n) };
    }
}
