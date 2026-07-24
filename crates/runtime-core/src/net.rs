//! Owned-buffer TCP primitives over the completion runtime.
//!
//! Socket bind/listen are one-time synchronous `libc` calls; accept, connect, recv,
//! send, and close are io_uring operations. When the ring has a registered fixed-file
//! table (Phase 2), accepted and outbound sockets are **direct descriptors** — the
//! kernel installs them into the fixed table and ops reference them by index with
//! `IOSQE_FIXED_FILE`, skipping the per-op `fget`/`fput`. The runtime falls back to
//! raw fds where fixed files are unavailable. Data buffers are always owned: they move
//! into the op and are handed back on completion.

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
use crate::fut::OpFuture;
use crate::slab::OpKey;

/// A connected socket: either a raw process fd or a direct (fixed-table) descriptor.
#[derive(Clone, Copy)]
enum Fd {
    Raw(RawFd),
    Fixed(u32),
}

impl Fd {
    /// Prepare an SQE's fd field for this descriptor, setting `IOSQE_FIXED_FILE` when
    /// it is a direct descriptor. Call BEFORE stamping user_data, AFTER the `prep_*`
    /// helper (which zeroes flags).
    fn set_fixed_flag(self, sqe: *mut runtime_uring_sys::ffi::io_uring_sqe) {
        if let Fd::Fixed(_) = self {
            unsafe { inline::io_uring_sqe_set_flags(sqe, inline::IOSQE_FIXED_FILE) };
        }
    }

    fn arg(self) -> c_int {
        match self {
            Fd::Raw(fd) => fd,
            Fd::Fixed(index) => index as c_int,
        }
    }
}

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

fn set_reuseaddr(fd: RawFd) {
    let one: c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const c_void,
            mem::size_of::<c_int>() as libc::socklen_t,
        );
    }
}

fn set_reuseport(fd: RawFd) {
    let one: c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &one as *const _ as *const c_void,
            mem::size_of::<c_int>() as libc::socklen_t,
        );
    }
}

fn bind_listen(fd: RawFd, addr: &SocketAddr) -> io::Result<()> {
    let (storage, len) = to_sockaddr(addr);
    unsafe {
        if libc::bind(fd, &storage as *const _ as *const libc::sockaddr, len) < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::listen(fd, 1024) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
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
    /// Bind + listen with `SO_REUSEADDR`.
    pub fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
        Self::bind_inner(addr, false)
    }

    /// Bind + listen with `SO_REUSEPORT` so multiple shards can each own a listener on
    /// the same address and the kernel load-balances incoming connections.
    pub fn bind_reuseport(addr: SocketAddr) -> io::Result<TcpListener> {
        Self::bind_inner(addr, true)
    }

    fn bind_inner(addr: SocketAddr, reuseport: bool) -> io::Result<TcpListener> {
        let fd = new_socket(&addr)?;
        set_reuseaddr(fd);
        if reuseport {
            set_reuseport(fd);
        }
        if let Err(err) = bind_listen(fd, &addr) {
            unsafe { libc::close(fd) };
            return Err(err);
        }
        Ok(TcpListener { fd })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        getsockname(self.fd)
    }

    /// A multishot accept stream: one SQE that keeps yielding accepted connections,
    /// eliminating the per-connection accept submission. Peer addresses are not
    /// reported on this path (multishot reuses one address buffer). Uses
    /// direct-descriptor accept when the ring supports it.
    pub fn accept_multishot(&self) -> AcceptStream {
        AcceptStream {
            fd: self.fd,
            direct: with_ring(|ring| ring.has_fixed_files()),
            key: None,
            done: false,
        }
    }

    /// Accept one connection. Uses direct-descriptor accept when the ring supports it.
    pub fn accept(&self) -> AcceptFut {
        AcceptFut {
            fd: self.fd,
            slot: Some(Box::new(AcceptSlot {
                storage: unsafe { mem::zeroed() },
                len: mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            })),
            direct: with_ring(|ring| ring.has_fixed_files()),
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
    direct: bool,
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
                        // Direct accept returns the allocated fixed index in res; plain
                        // accept returns a raw fd. Both populate the peer sockaddr.
                        let fd = if this.direct {
                            Fd::Fixed(result.res as u32)
                        } else {
                            Fd::Raw(result.res)
                        };
                        let peer = from_sockaddr(&slot.storage)
                            .ok_or_else(|| io::Error::other("unknown peer address family"));
                        Poll::Ready(peer.map(|peer| (TcpStream { fd }, peer)))
                    }
                }
                None => Poll::Pending,
            };
        }

        let mut slot = this.slot.take().expect("accept slot present");
        let fd = this.fd;
        let direct = this.direct;
        let addr_ptr = &mut slot.storage as *mut _ as *mut libc::sockaddr;
        let len_ptr = &mut slot.len as *mut libc::socklen_t;
        let key = with_ring(|ring| {
            ring.submit_op(Some(slot as Box<dyn std::any::Any>), move |sqe| unsafe {
                if direct {
                    inline::io_uring_prep_accept_direct(
                        sqe,
                        fd,
                        addr_ptr,
                        len_ptr,
                        0,
                        inline::FILE_INDEX_ALLOC,
                    );
                } else {
                    inline::io_uring_prep_accept(sqe, fd, addr_ptr, len_ptr, libc::SOCK_CLOEXEC);
                }
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

/// A stream of accepted connections backed by a single multishot accept SQE.
pub struct AcceptStream {
    fd: RawFd,
    direct: bool,
    key: Option<OpKey>,
    done: bool,
}

impl AcceptStream {
    /// Await the next accepted connection. Returns an error once the multishot op
    /// terminates (e.g. the listener closed or the kernel dropped the request); the
    /// caller may re-arm by calling [`TcpListener::accept_multishot`] again.
    pub async fn accept(&mut self) -> io::Result<TcpStream> {
        std::future::poll_fn(|cx| self.poll_accept(cx)).await
    }

    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<TcpStream>> {
        if self.done {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "accept stream terminated",
            )));
        }
        // Arm the multishot accept on first poll.
        let key = match self.key {
            Some(key) => key,
            None => {
                let fd = self.fd;
                let direct = self.direct;
                let key = with_ring(|ring| {
                    ring.submit_op(None, move |sqe| unsafe {
                        if direct {
                            inline::io_uring_prep_multishot_accept_direct(
                                sqe,
                                fd,
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                                0,
                            );
                        } else {
                            inline::io_uring_prep_multishot_accept(
                                sqe,
                                fd,
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                                0,
                            );
                        }
                    })
                });
                match key {
                    Ok(key) => {
                        self.key = Some(key);
                        key
                    }
                    Err(err) => {
                        self.done = true;
                        return Poll::Ready(Err(err));
                    }
                }
            }
        };

        match with_ring(|ring| ring.poll_multishot(key, cx.waker())) {
            crate::ring::MultishotPoll::Value(result) => {
                if result.res < 0 {
                    Poll::Ready(Err(io::Error::from_raw_os_error(-result.res)))
                } else if self.direct {
                    Poll::Ready(Ok(TcpStream {
                        fd: Fd::Fixed(result.res as u32),
                    }))
                } else {
                    Poll::Ready(Ok(TcpStream {
                        fd: Fd::Raw(result.res),
                    }))
                }
            }
            crate::ring::MultishotPoll::Done(_) => {
                self.done = true;
                self.key = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "accept stream terminated",
                )))
            }
            crate::ring::MultishotPoll::Pending => Poll::Pending,
        }
    }
}

impl Drop for AcceptStream {
    fn drop(&mut self) {
        if let Some(key) = self.key {
            with_ring(|ring| ring.orphan(key));
        }
    }
}

// ---- stream ---------------------------------------------------------------------

pub struct TcpStream {
    fd: Fd,
}

impl TcpStream {
    /// Connect to `addr`. Uses a direct (fixed) socket when the ring supports it.
    pub async fn connect(addr: SocketAddr) -> io::Result<TcpStream> {
        if with_ring(|ring| ring.has_fixed_files()) {
            Self::connect_direct(addr).await
        } else {
            Self::connect_raw(addr).await
        }
    }

    async fn connect_direct(addr: SocketAddr) -> io::Result<TcpStream> {
        let domain = match addr {
            SocketAddr::V4(_) => libc::AF_INET,
            SocketAddr::V6(_) => libc::AF_INET6,
        };
        // Allocate a direct socket; the fixed index comes back in res.
        let index = OpFuture::new(None, move |sqe| unsafe {
            inline::io_uring_prep_socket_direct_alloc(sqe, domain, libc::SOCK_STREAM, 0, 0);
        })
        .await? as u32;
        let fd = Fd::Fixed(index);

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
                with_ring(|ring| ring.close_direct_detached(index));
                Err(err)
            }
        }
    }

    async fn connect_raw(addr: SocketAddr) -> io::Result<TcpStream> {
        let raw = new_socket(&addr)?;
        let fd = Fd::Raw(raw);
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
                unsafe { libc::close(raw) };
                Err(err)
            }
        }
    }

    /// The raw fd, if this stream is backed by one (not a direct descriptor).
    pub fn as_raw_fd(&self) -> Option<RawFd> {
        match self.fd {
            Fd::Raw(fd) => Some(fd),
            Fd::Fixed(_) => None,
        }
    }

    /// Receive into an owned buffer; returns the byte count (0 = EOF) and the buffer
    /// with its length set to the bytes read.
    pub fn recv<B: IoBufMut>(&self, buf: B) -> BufFut<B> {
        BufFut::new(self.fd, Dir::Recv, 0, buf)
    }

    /// Send an owned buffer's initialized bytes (may be partial; see [`send_all`]).
    pub fn send<B: IoBufMut>(&self, buf: B) -> BufFut<B> {
        BufFut::new(self.fd, Dir::Send, 0, buf)
    }

    /// Send every initialized byte, looping over partial sends.
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
        OpFuture::new(None, move |sqe| unsafe {
            match fd {
                Fd::Raw(raw) => inline::io_uring_prep_close(sqe, raw),
                Fd::Fixed(index) => inline::io_uring_prep_close_direct(sqe, index),
            }
        })
        .await
        .map(|_| ())
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        match self.fd {
            Fd::Raw(fd) => unsafe {
                libc::close(fd);
            },
            // A fixed descriptor is a table slot, not a process fd: free it via a
            // fire-and-forget direct close on the ring.
            Fd::Fixed(index) => with_ring(|ring| ring.close_direct_detached(index)),
        }
    }
}

struct ConnectSlot {
    storage: libc::sockaddr_storage,
    len: libc::socklen_t,
}

struct ConnectFut {
    fd: Fd,
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
                inline::io_uring_prep_connect(sqe, fd.arg(), addr_ptr, len);
                fd.set_fixed_flag(sqe);
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

/// A single recv or send over an owned buffer.
pub struct BufFut<B: IoBufMut> {
    fd: Fd,
    dir: Dir,
    off: usize,
    buf: Option<B>,
    key: Option<OpKey>,
    done: bool,
}

impl<B: IoBufMut> BufFut<B> {
    fn new(fd: Fd, dir: Dir, off: usize, buf: B) -> Self {
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
                        inline::io_uring_prep_recv(sqe, fd.arg(), ptr as *mut c_void, len, 0);
                        fd.set_fixed_flag(sqe);
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
                        inline::io_uring_prep_send(sqe, fd.arg(), ptr as *const c_void, len, 0);
                        fd.set_fixed_flag(sqe);
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
