//! Owned-buffer TCP primitives over the completion runtime.
//!
//! Socket creation / bind / listen are one-time synchronous `libc` calls (matching
//! the existing `bind_listener_socket`); accept, connect, recv, send, and close are
//! io_uring operations. All data-path buffers are **owned**: they move into the op
//! and are handed back on completion (`(result, buffer)`), so a dropped future can
//! orphan the buffer safely rather than free it under the kernel.

use std::future::Future;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::RawFd;
use std::os::raw::{c_int, c_void};
use std::pin::Pin;
use std::task::{Context, Poll};

use runtime_uring_sys::inline;

use crate::buf::IoBufMut;
use crate::executor::with_ring;
use crate::slab::OpKey;

// ---- address helpers ------------------------------------------------------------

fn to_sockaddr(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    unsafe {
        let mut storage: libc::sockaddr_storage = mem::zeroed();
        let len = match addr {
            SocketAddr::V4(a) => {
                let sin = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in);
                sin.sin_family = libc::AF_INET as libc::sa_family_t;
                sin.sin_port = a.port().to_be();
                sin.sin_addr = libc::in_addr {
                    s_addr: u32::from_ne_bytes(a.ip().octets()),
                };
                mem::size_of::<libc::sockaddr_in>()
            }
            SocketAddr::V6(a) => {
                let sin6 = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6);
                sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sin6.sin6_port = a.port().to_be();
                sin6.sin6_addr = libc::in6_addr {
                    s6_addr: a.ip().octets(),
                };
                sin6.sin6_flowinfo = a.flowinfo();
                sin6.sin6_scope_id = a.scope_id();
                mem::size_of::<libc::sockaddr_in6>()
            }
        };
        (storage, len as libc::socklen_t)
    }
}

fn from_sockaddr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    unsafe {
        match storage.ss_family as c_int {
            libc::AF_INET => {
                let sin = &*(storage as *const _ as *const libc::sockaddr_in);
                Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()),
                    u16::from_be(sin.sin_port),
                )))
            }
            libc::AF_INET6 => {
                let sin6 = &*(storage as *const _ as *const libc::sockaddr_in6);
                Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                    u16::from_be(sin6.sin6_port),
                    sin6.sin6_flowinfo,
                    sin6.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}

fn new_socket(addr: &SocketAddr) -> io::Result<RawFd> {
    let domain = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

fn getsockname(fd: RawFd) -> io::Result<SocketAddr> {
    unsafe {
        let mut storage: libc::sockaddr_storage = mem::zeroed();
        let mut len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if libc::getsockname(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len) < 0 {
            return Err(io::Error::last_os_error());
        }
        from_sockaddr(&storage).ok_or_else(|| io::Error::other("unknown address family"))
    }
}

// ---- listener -------------------------------------------------------------------

pub struct TcpListener {
    fd: RawFd,
}

impl TcpListener {
    /// Bind + listen synchronously (one-time), enabling `SO_REUSEADDR`.
    pub fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
        let fd = new_socket(&addr)?;
        unsafe {
            let one: c_int = 1;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &one as *const _ as *const c_void,
                mem::size_of::<c_int>() as libc::socklen_t,
            );
            let (storage, len) = to_sockaddr(&addr);
            if libc::bind(fd, &storage as *const _ as *const libc::sockaddr, len) < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }
            if libc::listen(fd, 1024) < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }
        }
        Ok(TcpListener { fd })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        getsockname(self.fd)
    }

    /// Accept one connection via io_uring, returning the stream and peer address.
    pub fn accept(&self) -> AcceptFut {
        AcceptFut {
            fd: self.fd,
            slot: Some(Box::new(AcceptSlot {
                storage: unsafe { mem::zeroed() },
                len: mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            })),
            key: None,
            done: false,
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

struct AcceptSlot {
    storage: libc::sockaddr_storage,
    len: libc::socklen_t,
}

pub struct AcceptFut {
    fd: RawFd,
    slot: Option<Box<AcceptSlot>>,
    key: Option<OpKey>,
    done: bool,
}

impl Future for AcceptFut {
    type Output = io::Result<(TcpStream, SocketAddr)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        debug_assert!(!this.done);

        if let Some(key) = this.key {
            return match with_ring(|ring| ring.poll_op(key, cx.waker())) {
                Some((result, keepalive)) => {
                    this.done = true;
                    this.key = None;
                    let slot = keepalive
                        .expect("accept keepalive present")
                        .downcast::<AcceptSlot>()
                        .expect("accept keepalive type");
                    if result.res < 0 {
                        Poll::Ready(Err(io::Error::from_raw_os_error(-result.res)))
                    } else {
                        let peer = from_sockaddr(&slot.storage)
                            .ok_or_else(|| io::Error::other("unknown peer address family"));
                        Poll::Ready(peer.map(|peer| (TcpStream { fd: result.res }, peer)))
                    }
                }
                None => Poll::Pending,
            };
        }

        let mut slot = this.slot.take().expect("accept slot present");
        let fd = this.fd;
        let addr_ptr = &mut slot.storage as *mut _ as *mut libc::sockaddr;
        let len_ptr = &mut slot.len as *mut libc::socklen_t;
        let key = with_ring(|ring| {
            ring.submit_op(Some(slot as Box<dyn std::any::Any>), move |sqe| unsafe {
                inline::io_uring_prep_accept(sqe, fd, addr_ptr, len_ptr, libc::SOCK_CLOEXEC);
            })
        });
        match key {
            Ok(key) => {
                this.key = Some(key);
                match with_ring(|ring| ring.poll_op(key, cx.waker())) {
                    Some(_) => unreachable!("accept cannot complete before submission"),
                    None => Poll::Pending,
                }
            }
            Err(err) => {
                this.done = true;
                Poll::Ready(Err(err))
            }
        }
    }
}

// ---- stream ---------------------------------------------------------------------

pub struct TcpStream {
    fd: RawFd,
}

impl TcpStream {
    /// Connect to `addr` via io_uring.
    pub async fn connect(addr: SocketAddr) -> io::Result<TcpStream> {
        let fd = new_socket(&addr)?;
        let (storage, len) = to_sockaddr(&addr);
        let result = ConnectFut {
            fd,
            slot: Some(Box::new(ConnectSlot { storage, len })),
            key: None,
            done: false,
        }
        .await;
        match result {
            Ok(()) => Ok(TcpStream { fd }),
            Err(err) => {
                unsafe { libc::close(fd) };
                Err(err)
            }
        }
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Receive into an owned buffer, returning the byte count (0 = EOF) and the buffer
    /// (its length set to the bytes read).
    pub fn recv<B: IoBufMut>(&self, buf: B) -> BufFut<B> {
        BufFut::new(self.fd, Dir::Recv, 0, buf)
    }

    /// Send from an owned buffer's initialized bytes, returning bytes sent and the
    /// buffer. May be a partial send; see [`TcpStream::send_all`].
    pub fn send<B: IoBufMut>(&self, buf: B) -> BufFut<B> {
        BufFut::new(self.fd, Dir::Send, 0, buf)
    }

    /// Send every initialized byte, looping over partial sends. Returns the buffer.
    pub async fn send_all<B: IoBufMut>(&self, buf: B) -> (io::Result<()>, B) {
        let total = crate::buf::IoBuf::bytes_init(&buf);
        let mut buf = buf;
        let mut off = 0;
        while off < total {
            let (result, returned) = BufFut::new(self.fd, Dir::Send, off, buf).await;
            buf = returned;
            match result {
                Ok(0) => return (Err(io::ErrorKind::WriteZero.into()), buf),
                Ok(n) => off += n,
                Err(err) => return (Err(err), buf),
            }
        }
        (Ok(()), buf)
    }

    /// Close via io_uring, consuming the stream (no synchronous close in `Drop`).
    pub async fn close(self) -> io::Result<()> {
        let fd = self.fd;
        mem::forget(self);
        crate::fut::OpFuture::new(None, move |sqe| unsafe {
            inline::io_uring_prep_close(sqe, fd);
        })
        .await
        .map(|_| ())
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

struct ConnectSlot {
    storage: libc::sockaddr_storage,
    len: libc::socklen_t,
}

struct ConnectFut {
    fd: RawFd,
    slot: Option<Box<ConnectSlot>>,
    key: Option<OpKey>,
    done: bool,
}

impl Future for ConnectFut {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        debug_assert!(!this.done);

        if let Some(key) = this.key {
            return match with_ring(|ring| ring.poll_op(key, cx.waker())) {
                Some((result, _keepalive)) => {
                    this.done = true;
                    this.key = None;
                    if result.res < 0 {
                        Poll::Ready(Err(io::Error::from_raw_os_error(-result.res)))
                    } else {
                        Poll::Ready(Ok(()))
                    }
                }
                None => Poll::Pending,
            };
        }

        let slot = this.slot.take().expect("connect slot present");
        let fd = this.fd;
        let addr_ptr = &slot.storage as *const _ as *const libc::sockaddr;
        let len = slot.len;
        let key = with_ring(|ring| {
            ring.submit_op(Some(slot as Box<dyn std::any::Any>), move |sqe| unsafe {
                inline::io_uring_prep_connect(sqe, fd, addr_ptr, len);
            })
        });
        match key {
            Ok(key) => {
                this.key = Some(key);
                match with_ring(|ring| ring.poll_op(key, cx.waker())) {
                    Some(_) => unreachable!("connect cannot complete before submission"),
                    None => Poll::Pending,
                }
            }
            Err(err) => {
                this.done = true;
                Poll::Ready(Err(err))
            }
        }
    }
}

// ---- buffered recv/send ---------------------------------------------------------

enum Dir {
    Recv,
    Send,
}

/// A single recv or send over an owned buffer. The buffer moves into the op after a
/// successful submit and is returned on completion (or on submit error).
pub struct BufFut<B: IoBufMut> {
    fd: RawFd,
    dir: Dir,
    off: usize,
    buf: Option<B>,
    key: Option<OpKey>,
    done: bool,
}

impl<B: IoBufMut> BufFut<B> {
    fn new(fd: RawFd, dir: Dir, off: usize, buf: B) -> Self {
        BufFut {
            fd,
            dir,
            off,
            buf: Some(buf),
            key: None,
            done: false,
        }
    }
}

impl<B: IoBufMut> Future for BufFut<B> {
    type Output = (io::Result<usize>, B);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        debug_assert!(!this.done);

        if let Some(key) = this.key {
            return match with_ring(|ring| ring.poll_op(key, cx.waker())) {
                Some((result, keepalive)) => {
                    this.done = true;
                    this.key = None;
                    let mut buf = *keepalive
                        .expect("buf op keepalive present")
                        .downcast::<B>()
                        .expect("buf op keepalive type");
                    if result.res < 0 {
                        Poll::Ready((Err(io::Error::from_raw_os_error(-result.res)), buf))
                    } else {
                        let n = result.res as usize;
                        if matches!(this.dir, Dir::Recv) {
                            // SAFETY: the kernel initialized `n` bytes at the buffer start.
                            unsafe { buf.set_init(n) };
                        }
                        Poll::Ready((Ok(n), buf))
                    }
                }
                None => Poll::Pending,
            };
        }

        let mut buf = this.buf.take().expect("buf present");
        let fd = this.fd;
        let submit = match this.dir {
            Dir::Recv => {
                let ptr = buf.stable_mut_ptr();
                let len = buf.bytes_total();
                with_ring(|ring| {
                    ring.submit_op(None, move |sqe| unsafe {
                        inline::io_uring_prep_recv(sqe, fd, ptr as *mut c_void, len, 0);
                    })
                })
            }
            Dir::Send => {
                let base = crate::buf::IoBuf::stable_ptr(&buf);
                let total = crate::buf::IoBuf::bytes_init(&buf);
                let off = this.off.min(total);
                let len = total - off;
                let ptr = unsafe { base.add(off) };
                with_ring(|ring| {
                    ring.submit_op(None, move |sqe| unsafe {
                        inline::io_uring_prep_send(sqe, fd, ptr as *const c_void, len, 0);
                    })
                })
            }
        };
        match submit {
            Ok(key) => {
                with_ring(|ring| ring.attach_keepalive(key, Box::new(buf)));
                this.key = Some(key);
                match with_ring(|ring| ring.poll_op(key, cx.waker())) {
                    Some(_) => unreachable!("buf op cannot complete before submission"),
                    None => Poll::Pending,
                }
            }
            Err(err) => {
                this.done = true;
                Poll::Ready((Err(err), buf))
            }
        }
    }
}

impl<B: IoBufMut> Drop for BufFut<B> {
    fn drop(&mut self) {
        if let Some(key) = self.key {
            with_ring(|ring| ring.orphan(key));
        }
    }
}
