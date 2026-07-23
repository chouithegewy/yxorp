//! Zero-copy body forwarding for the epoll `fast` engine.
//!
//! Moves request/response body bytes between the downstream and upstream sockets
//! with `splice(2)` through a per-thread reused pipe, so the payload never lands in
//! a userspace buffer. Readiness is driven by tokio's reactor via
//! [`TcpStream::async_io`], keeping the non-blocking sockets cooperating with the
//! runtime.
//!
//! Every entry point is gated on [`splice_supported`], a one-time capability probe;
//! callers fall back to the buffered copy path when splice is unavailable (older or
//! sandboxed kernels).

use std::cell::RefCell;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::OnceLock;

use tokio::io::Interest;
use tokio::net::TcpStream;

const SPLICE_FLAGS: libc::c_uint =
    (libc::SPLICE_F_MOVE | libc::SPLICE_F_MORE | libc::SPLICE_F_NONBLOCK) as libc::c_uint;
/// Per-splice request cap and pipe capacity. 1 MiB matches the enlarged pipe so a
/// full pipe drains in a single `splice` on each side.
const PIPE_CAPACITY: usize = 1 << 20;

/// Returns whether `splice(2)` is usable in this process. Cached after the first
/// call; logs once on failure so a fallback to the buffered copy path is visible.
pub fn splice_supported() -> bool {
    static SUPPORTED: OnceLock<bool> = OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        let ok = probe_splice();
        if !ok {
            tracing::warn!(
                "splice(2) is unavailable in this environment; falling back to buffered body copies"
            );
        }
        ok
    })
}

fn probe_splice() -> bool {
    unsafe {
        let mut a = [0 as RawFd; 2];
        let mut b = [0 as RawFd; 2];
        if libc::pipe2(a.as_mut_ptr(), libc::O_NONBLOCK) != 0 {
            return false;
        }
        if libc::pipe2(b.as_mut_ptr(), libc::O_NONBLOCK) != 0 {
            libc::close(a[0]);
            libc::close(a[1]);
            return false;
        }
        // Splice zero bytes between two empty pipes: 0 on support, -1/ENOSYS if the
        // syscall is blocked. EAGAIN (empty source) also proves support.
        let rc = libc::splice(
            a[0],
            std::ptr::null_mut(),
            b[1],
            std::ptr::null_mut(),
            0,
            SPLICE_FLAGS,
        );
        let ok = rc >= 0
            || io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN);
        libc::close(a[0]);
        libc::close(a[1]);
        libc::close(b[0]);
        libc::close(b[1]);
        ok
    }
}

/// Owns a persistent pipe so its fds are closed when the worker thread exits.
struct PipePair {
    read: RawFd,
    write: RawFd,
}

impl Drop for PipePair {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.read);
            libc::close(self.write);
        }
    }
}

thread_local! {
    static PIPE: RefCell<Option<PipePair>> = const { RefCell::new(None) };
}

/// Fetches this thread's reusable pipe fds, creating the pipe on first use. The
/// returned fds are plain `Copy` values, so no borrow is held across `.await`.
fn pipe_fds() -> io::Result<(RawFd, RawFd)> {
    PIPE.with(|cell| {
        let mut guard = cell.borrow_mut();
        if guard.is_none() {
            let mut fds = [0 as RawFd; 2];
            let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            // Best-effort: enlarge the pipe so large bodies move in fewer hops.
            unsafe {
                libc::fcntl(fds[1], libc::F_SETPIPE_SZ, PIPE_CAPACITY as libc::c_int);
            }
            *guard = Some(PipePair {
                read: fds[0],
                write: fds[1],
            });
        }
        let pipe = guard.as_ref().expect("pipe initialized");
        Ok((pipe.read, pipe.write))
    })
}

/// Splice exactly `len` body bytes from `src` to `dst` through this thread's pipe.
/// Returns [`io::ErrorKind::UnexpectedEof`] if `src` closes before `len` is met.
pub async fn splice_exact(src: &TcpStream, dst: &TcpStream, len: usize) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    let (pipe_r, pipe_w) = pipe_fds()?;
    let src_fd = src.as_raw_fd();
    let dst_fd = dst.as_raw_fd();
    let mut remaining = len;

    while remaining > 0 {
        // Fill the (empty) pipe from the source socket.
        let want = remaining.min(PIPE_CAPACITY);
        let moved = src
            .async_io(Interest::READABLE, || {
                splice_raw(src_fd, pipe_w, want)
            })
            .await?;
        if moved == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        remaining -= moved;
        // Drain everything we just buffered into the destination socket.
        drain_pipe(dst, pipe_r, dst_fd, moved).await?;
    }
    Ok(())
}

/// Splice from `src` to `dst` until `src` reaches EOF (close-delimited body).
/// Returns the number of bytes moved.
pub async fn splice_stream(src: &TcpStream, dst: &TcpStream) -> io::Result<u64> {
    let (pipe_r, pipe_w) = pipe_fds()?;
    let src_fd = src.as_raw_fd();
    let dst_fd = dst.as_raw_fd();
    let mut total = 0u64;

    loop {
        let moved = src
            .async_io(Interest::READABLE, || {
                splice_raw(src_fd, pipe_w, PIPE_CAPACITY)
            })
            .await?;
        if moved == 0 {
            return Ok(total);
        }
        total += moved as u64;
        drain_pipe(dst, pipe_r, dst_fd, moved).await?;
    }
}

/// Move exactly `count` bytes already sitting in the pipe out to `dst`.
async fn drain_pipe(
    dst: &TcpStream,
    pipe_r: RawFd,
    dst_fd: RawFd,
    mut count: usize,
) -> io::Result<()> {
    while count > 0 {
        let moved = dst
            .async_io(Interest::WRITABLE, || splice_raw(pipe_r, dst_fd, count))
            .await?;
        if moved == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        count -= moved;
    }
    Ok(())
}

/// One non-blocking `splice` call. Maps EAGAIN to `WouldBlock` so `async_io`
/// re-arms readiness instead of treating it as a hard error.
fn splice_raw(fd_in: RawFd, fd_out: RawFd, len: usize) -> io::Result<usize> {
    let rc = unsafe {
        libc::splice(
            fd_in,
            std::ptr::null_mut(),
            fd_out,
            std::ptr::null_mut(),
            len,
            SPLICE_FLAGS,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn splice_exact_moves_bytes() {
        if !splice_supported() {
            return;
        }
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        let dn = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dn_addr = dn.local_addr().unwrap();

        let src = TcpStream::connect(up_addr).await.unwrap();
        let (mut src_peer, _) = up.accept().await.unwrap();
        let dst = TcpStream::connect(dn_addr).await.unwrap();
        let (mut dst_peer, _) = dn.accept().await.unwrap();

        tokio::spawn(async move {
            src_peer.write_all(b"hello").await.unwrap();
            // Keep the peer alive so the connection is not reset mid-splice.
            std::future::pending::<()>().await;
        });

        let mover = tokio::spawn(async move {
            splice_exact(&src, &dst, 5).await.unwrap();
            src
        });

        let mut got = vec![0u8; 5];
        dst_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
        mover.await.unwrap();
    }

    #[tokio::test]
    async fn splice_exact_large_payload_is_intact() {
        if !splice_supported() {
            return;
        }
        let payload: Vec<u8> = (0..500_000u32).map(|i| (i % 251) as u8).collect();
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        let dn = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dn_addr = dn.local_addr().unwrap();

        let src = TcpStream::connect(up_addr).await.unwrap();
        let (mut src_peer, _) = up.accept().await.unwrap();
        let dst = TcpStream::connect(dn_addr).await.unwrap();
        let (mut dst_peer, _) = dn.accept().await.unwrap();

        let send = payload.clone();
        tokio::spawn(async move {
            src_peer.write_all(&send).await.unwrap();
            std::future::pending::<()>().await;
        });

        let len = payload.len();
        let mover = tokio::spawn(async move {
            splice_exact(&src, &dst, len).await.unwrap();
            src
        });

        let mut got = vec![0u8; len];
        dst_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
        mover.await.unwrap();
    }
}
