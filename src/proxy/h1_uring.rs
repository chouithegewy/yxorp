use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use memchr::memmem;
use tokio::net::TcpSocket;
use tokio::sync::watch;
use tokio_uring::buf::fixed::FixedBufPool;
use tokio_uring::buf::BoundedBuf;
use tokio_uring::net::{TcpListener as UringTcpListener, TcpStream as UringTcpStream};
use tracing::{error, info, warn};

use crate::config::{ConfigSnapshot, ListenerConfig, UpstreamProtocol, UpstreamState};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const READ_CHUNK_BYTES: usize = 16 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024 * 1024;
const DOWNSTREAM_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

type Result<T> = std::result::Result<T, UringError>;

#[derive(Debug)]
enum UringError {
    Io(io::Error),
    Parse(&'static str),
    Upstream(&'static str),
}

impl std::fmt::Display for UringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Parse(message) | Self::Upstream(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for UringError {}

impl From<io::Error> for UringError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone)]
struct SelectedUpstream {
    connect_addr: std::net::SocketAddr,
    host_header: Vec<u8>,
    protocol: UpstreamProtocol,
    connect_timeout: Duration,
    request_timeout: Duration,
    state: Arc<UpstreamState>,
}

struct RequestHead {
    body_len: usize,
    outbound: Vec<u8>,
    close_after_response: bool,
    head_response: bool,
}

struct MatchedRequest {
    head: RequestHead,
    upstream: SelectedUpstream,
    rate_limiter: Option<Arc<crate::proxy::rate_limit::RateLimiter>>,
}

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;

thread_local! {
    static URING_POOL: RefCell<HashMap<SocketAddr, Vec<(UringTcpStream, Instant)>>> = RefCell::new(HashMap::new());
}

/// Number of buffers registered with each worker ring (× READ_CHUNK_BYTES).
const FIXED_BUF_COUNT: usize = 64;

thread_local! {
    // Per-worker registered fixed buffer pool. `None` until first use; `disabled`
    // latches on if registration fails (e.g. RLIMIT_MEMLOCK) so we fall back to
    // ordinary heap buffers without retrying.
    static FIXED_POOL: RefCell<Option<std::rc::Rc<FixedBufPool<Vec<u8>>>>> =
        const { RefCell::new(None) };
    static FIXED_POOL_DISABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// This worker's registered fixed buffer pool, registering it on first use.
/// Returns `None` when registration is unavailable so callers use heap buffers.
fn fixed_pool() -> Option<std::rc::Rc<FixedBufPool<Vec<u8>>>> {
    if FIXED_POOL_DISABLED.with(|d| d.get()) {
        return None;
    }
    FIXED_POOL.with(|cell| {
        let mut guard = cell.borrow_mut();
        if guard.is_none() {
            let pool =
                FixedBufPool::new((0..FIXED_BUF_COUNT).map(|_| vec![0u8; READ_CHUNK_BYTES]));
            if let Err(err) = pool.register() {
                warn!(error = %err, "io_uring fixed buffer registration failed; using heap buffers");
                FIXED_POOL_DISABLED.with(|d| d.set(true));
                return None;
            }
            *guard = Some(std::rc::Rc::new(pool));
        }
        guard.clone()
    })
}

fn checkout_uring_conn(addr: SocketAddr, idle_threshold: Duration) -> Option<UringTcpStream> {
    URING_POOL.with(|pool| {
        let mut guard = pool.borrow_mut();
        if let Some(conns) = guard.get_mut(&addr) {
            while let Some((conn, idle_since)) = conns.pop() {
                // Hot keepalive reuse (idle under the threshold) skips the
                // recv(MSG_PEEK) probe; only longer-idle connections are checked.
                if idle_since.elapsed() < idle_threshold || is_uring_conn_alive(&conn) {
                    return Some(conn);
                }
            }
        }
        None
    })
}

fn checkin_uring_conn(addr: SocketAddr, conn: UringTcpStream) {
    URING_POOL.with(|pool| {
        let mut guard = pool.borrow_mut();
        guard.entry(addr).or_default().push((conn, Instant::now()));
    });
}

fn is_uring_conn_alive(stream: &UringTcpStream) -> bool {
    let fd = stream.as_raw_fd();
    let mut buf = [0u8; 1];
    let res = unsafe {
        libc::recv(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if res == 0 {
        false // EOF
    } else if res > 0 {
        false // Pending bytes would desynchronize the next response.
    } else {
        let err = std::io::Error::last_os_error();
        err.kind() == std::io::ErrorKind::WouldBlock
    }
}

async fn get_uring_connection(
    addr: SocketAddr,
    connect_timeout: Duration,
    idle_threshold: Duration,
) -> std::io::Result<UringTcpStream> {
    if let Some(stream) = checkout_uring_conn(addr, idle_threshold) {
        return Ok(stream);
    }
    let stream = tokio::time::timeout(connect_timeout, UringTcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream connect timed out"))??;
    stream.set_nodelay(true)?;
    Ok(stream)
}

pub async fn serve_listener(
    snapshot: Arc<ArcSwap<ConfigSnapshot>>,
    listener: ListenerConfig,
    mut shutdown: watch::Receiver<bool>,
    connections: Arc<super::ConnectionTracker>,
) -> io::Result<()> {
    preflight_io_uring()?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let bind = listener.bind;

    let worker_count = if listener.accept_workers == 0 {
        std::thread::available_parallelism().map_or(1, usize::from)
    } else {
        listener.accept_workers.max(1)
    };

    info!(listener = listener.name, worker_count, %bind, "spawning io_uring worker threads");

    for worker_id in 0..worker_count {
        let listener_config = listener.clone();
        let snapshot = Arc::clone(&snapshot);
        let stop_thread = Arc::clone(&stop_thread);
        let connections = Arc::clone(&connections);

        thread::Builder::new()
            .name(format!("yxorp-uring-{}-{}", listener.name, worker_id))
            .spawn(move || {
                tokio_uring::start(async move {
                    let std_listener = match bind_listener_socket(&listener_config) {
                        Ok(l) => l,
                        Err(err) => {
                            error!(error = %err, "io_uring failed to bind listener socket");
                            return;
                        }
                    };
                    let listener = UringTcpListener::from_std(std_listener);
                    info!(listener = listener_config.name, worker_id, %bind, "io_uring listener worker started");
                    while !stop_thread.load(Ordering::Relaxed) {
                        let accepted = listener.accept().await;
                        if stop_thread.load(Ordering::Relaxed) {
                            break;
                        }
                        match accepted {
                            Ok((stream, peer_addr)) => {
                                let snapshot_arc = snapshot.load_full();
                                let connections = Arc::clone(&connections);
                                connections.started();
                                if let Err(err) = stream.set_nodelay(true) {
                                    warn!(error = %err, %peer_addr, "failed to set TCP_NODELAY");
                                }
                                tokio_uring::spawn(async move {
                                    if let Err(err) = serve_connection(snapshot_arc, stream, peer_addr).await {
                                        error!(error = %err, %peer_addr, "io_uring h1 connection failed");
                                    }
                                    connections.finished();
                                });
                            }
                            Err(err) => error!(error = %err, "io_uring accept failed"),
                        }
                    }
                });
            })?;
    }

    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            stop.store(true, Ordering::Relaxed);
            for _ in 0..worker_count {
                let _ = std::net::TcpStream::connect(bind);
            }
            break;
        }
    }
    Ok(())
}

fn preflight_io_uring() -> io::Result<()> {
    match io_uring::IoUring::new(1) {
        Ok(_) => Ok(()),
        Err(err) if matches!(err.raw_os_error(), Some(libc::ENOSYS | libc::EPERM)) => {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "io_uring is not available in this environment ({}). Podman rootless containers often need seccomp to allow io_uring syscalls.",
                    err
                ),
            ))
        }
        Err(err) => Err(err),
    }
}

async fn serve_connection(
    snapshot: Arc<ConfigSnapshot>,
    downstream: UringTcpStream,
    peer_addr: SocketAddr,
) -> Result<()> {
    let idle_threshold = snapshot.config.runtime.liveness_probe_idle();
    let zero_copy = snapshot.config.runtime.zero_copy;
    let mut downstream_buf = Vec::with_capacity(READ_CHUNK_BYTES);
    let mut upstream_buf = Vec::with_capacity(READ_CHUNK_BYTES);
    let mut downstream_read_buf = Some(vec![0; READ_CHUNK_BYTES]);
    let mut upstream_read_buf = Some(vec![0; READ_CHUNK_BYTES]);

    loop {
        let Some((header_len, buf, returned_buf)) = tokio::time::timeout(
            DOWNSTREAM_HEADER_TIMEOUT,
            read_header_block(&downstream, downstream_buf, downstream_read_buf),
        )
        .await
        .map_err(|_| UringError::Parse("downstream header read timed out"))??
        else {
            return Ok(());
        };
        downstream_buf = buf;
        downstream_read_buf = returned_buf;

        let request = {
            let snapshot_guard = snapshot.as_ref();
            build_request(snapshot_guard, &downstream_buf[..header_len])?
        };

        let Some(request) = request else {
            write_all(
                &downstream,
                static_response(404, "Not Found", b"no matching route\n"),
            )
            .await?;
            return Ok(());
        };
        if let Some(rate_limiter) = request.rate_limiter.as_deref()
            && !rate_limiter.acquire(peer_addr.ip())
        {
            write_all(
                &downstream,
                static_response(429, "Too Many Requests", b"rate limit exceeded\n"),
            )
            .await?;
            return Ok(());
        }
        if request.upstream.protocol == UpstreamProtocol::H3 {
            write_all(
                &downstream,
                static_response(
                    501,
                    "Not Implemented",
                    b"HTTP/3 upstream driver is configured but not enabled in this baseline\n",
                ),
            )
            .await?;
            return Ok(());
        }

        let upstream_stream = match get_uring_connection(
            request.upstream.connect_addr,
            request.upstream.connect_timeout,
            idle_threshold,
        )
        .await
        {
            Ok(stream) => stream,
            Err(_) => {
                request.upstream.state.mark_failure();
                write_all(
                    &downstream,
                    static_response(502, "Bad Gateway", b"upstream request failed\n"),
                )
                .await?;
                return Ok(());
            }
        };

        if let Err(_) = write_all(&upstream_stream, request.head.outbound).await {
            request.upstream.state.mark_failure();
            write_all(
                &downstream,
                static_response(502, "Bad Gateway", b"upstream request failed\n"),
            )
            .await?;
            return Ok(());
        }

        discard_buffer_prefix(&mut downstream_buf, header_len);
        let (returned_ds_buf, returned_read_buf) = match tokio::time::timeout(
            request.upstream.request_timeout,
            copy_exact_body(
                &downstream,
                downstream_buf,
                &upstream_stream,
                request.head.body_len,
                downstream_read_buf,
                zero_copy,
            ),
        )
        .await
        .map_err(|_| UringError::Parse("downstream body read timed out"))
        .and_then(|result| result)
        {
            Ok(val) => val,
            Err(_) => {
                request.upstream.state.mark_failure();
                return Ok(());
            }
        };
        downstream_buf = returned_ds_buf;
        downstream_read_buf = returned_read_buf;

        let response = loop {
            let response_header = tokio::time::timeout(
                request.upstream.request_timeout,
                read_header_block(&upstream_stream, upstream_buf, upstream_read_buf),
            )
            .await
            .map_err(|_| UringError::Parse("upstream response timed out"))??;
            let Some((response_header_len, returned_us_buf, returned_read_buf)) = response_header
            else {
                request.upstream.state.mark_failure();
                return Err(UringError::Parse("upstream closed before response"));
            };
            upstream_buf = returned_us_buf;
            upstream_read_buf = returned_read_buf;
            let response = parse_response(
                &upstream_buf[..response_header_len],
                request.head.head_response,
            )?;
            let header = upstream_buf[..response_header_len].to_vec();
            write_all(&downstream, header).await?;
            discard_buffer_prefix(&mut upstream_buf, response_header_len);
            if (100..200).contains(&response.status) {
                continue;
            }
            break response;
        };

        let (returned_us_buf, returned_read_buf) = match tokio::time::timeout(
            request.upstream.request_timeout,
            copy_response_body(
                &upstream_stream,
                upstream_buf,
                &downstream,
                response.body,
                upstream_read_buf,
                zero_copy,
            ),
        )
        .await
        .map_err(|_| UringError::Parse("upstream response timed out"))
        .and_then(|result| result)
        {
            Ok(val) => val,
            Err(_) => {
                request.upstream.state.mark_failure();
                return Ok(());
            }
        };
        upstream_buf = returned_us_buf;
        upstream_read_buf = returned_read_buf;

        if response.status >= 500 {
            request.upstream.state.mark_failure();
        } else {
            request.upstream.state.mark_success();
        }

        let close_conn = request.head.close_after_response || response.close_after_response;
        if !close_conn {
            checkin_uring_conn(request.upstream.connect_addr, upstream_stream);
        }

        if close_conn {
            return Ok(());
        }
    }
}

fn build_request(snapshot: &ConfigSnapshot, raw_headers: &[u8]) -> Result<Option<MatchedRequest>> {
    let mut headers = [httparse::EMPTY_HEADER; 96];
    let mut parsed = httparse::Request::new(&mut headers);
    let status = parsed
        .parse(raw_headers)
        .map_err(|_| UringError::Parse("invalid request headers"))?;
    if !status.is_complete() {
        return Err(UringError::Parse("incomplete request headers"));
    }
    let method = parsed
        .method
        .ok_or(UringError::Parse("request method missing"))?;
    let path_and_query = parsed
        .path
        .ok_or(UringError::Parse("request target missing"))?;
    let host = if snapshot.routes.requires_host_match() {
        header_value(parsed.headers, "host").and_then(|value| std::str::from_utf8(value).ok())
    } else {
        None
    };
    let Some(route_match) = snapshot
        .routes
        .match_route(host.map(str::trim), path_and_query)
    else {
        return Ok(None);
    };
    let upstream = route_match
        .pool
        .select_arc()
        .ok_or(UringError::Upstream("no available upstream"))?;
    let upstream_path = upstream.upstream_path_and_query(path_and_query);
    let selected = SelectedUpstream {
        connect_addr: upstream.connect_addr()?,
        host_header: upstream.host_header().as_bytes().to_vec(),
        protocol: upstream.config.protocol,
        connect_timeout: Duration::from_millis(upstream.config.connect_timeout_ms),
        request_timeout: Duration::from_millis(upstream.config.request_timeout_ms),
        state: Arc::clone(&upstream),
    };
    let rate_limiter = route_match.rate_limiter;
    let body_len = content_length(parsed.headers, true)?;
    let close_after_response = request_wants_close(parsed.version == Some(0), parsed.headers);
    let mut outbound = Vec::with_capacity(raw_headers.len() + upstream_path.len() + 64);
    outbound.extend_from_slice(method.as_bytes());
    outbound.extend_from_slice(b" ");
    outbound.extend_from_slice(upstream_path.as_bytes());
    outbound.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    outbound.extend_from_slice(&selected.host_header);
    outbound.extend_from_slice(b"\r\nConnection: keep-alive\r\n");
    append_forward_headers(&mut outbound, parsed.headers, body_len);
    outbound.extend_from_slice(b"\r\n");
    Ok(Some(MatchedRequest {
        head: RequestHead {
            body_len,
            outbound,
            close_after_response,
            head_response: method.eq_ignore_ascii_case("HEAD"),
        },
        upstream: selected,
        rate_limiter,
    }))
}

struct ResponseMeta {
    status: u16,
    body: ResponseBody,
    close_after_response: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResponseBody {
    None,
    ContentLength(usize),
    CloseDelimited,
}

fn parse_response(raw_headers: &[u8], head_response: bool) -> Result<ResponseMeta> {
    let mut headers = [httparse::EMPTY_HEADER; 96];
    let mut parsed = httparse::Response::new(&mut headers);
    let status = parsed
        .parse(raw_headers)
        .map_err(|_| UringError::Parse("invalid response headers"))?;
    if !status.is_complete() {
        return Err(UringError::Parse("incomplete response headers"));
    }
    let status_code = parsed.code.unwrap_or(0);
    let body = if head_response
        || (100..200).contains(&status_code)
        || status_code == 204
        || status_code == 304
    {
        ResponseBody::None
    } else if let Some(length) = response_content_length(parsed.headers)? {
        ResponseBody::ContentLength(length)
    } else {
        ResponseBody::CloseDelimited
    };
    Ok(ResponseMeta {
        status: status_code,
        body,
        close_after_response: request_wants_close(parsed.version == Some(0), parsed.headers)
            || body == ResponseBody::CloseDelimited,
    })
}

fn response_content_length(headers: &[httparse::Header<'_>]) -> Result<Option<usize>> {
    for header in headers {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(UringError::Parse(
                "transfer-encoding is not supported by io_uring engine yet",
            ));
        }
    }
    let mut found = None;
    for header in headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            if found.is_some() {
                return Err(UringError::Parse("duplicate content-length"));
            }
            found = Some(
                std::str::from_utf8(header.value)
                    .map_err(|_| UringError::Parse("invalid content-length"))?
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| UringError::Parse("invalid content-length"))?,
            );
        }
    }
    Ok(found)
}

async fn read_header_block(
    stream: &UringTcpStream,
    mut buf: Vec<u8>,
    mut read_buf: Option<Vec<u8>>,
) -> Result<Option<(usize, Vec<u8>, Option<Vec<u8>>)>> {
    loop {
        if let Some(index) = memmem::find(&buf, b"\r\n\r\n") {
            return Ok(Some((index + 4, buf, read_buf)));
        }
        if buf.len() >= MAX_HEADER_BYTES {
            return Err(UringError::Parse("headers too large"));
        }
        let active_buf = read_buf.take().unwrap_or_else(|| vec![0; READ_CHUNK_BYTES]);
        let (result, active_buf) = stream.read(active_buf).await;
        let read = result?;
        if read == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(UringError::Io(io::ErrorKind::UnexpectedEof.into()))
            };
        }
        buf.extend_from_slice(&active_buf[..read]);
        read_buf = Some(active_buf);
    }
}

async fn copy_exact_body(
    src: &UringTcpStream,
    mut src_buf: Vec<u8>,
    dst: &UringTcpStream,
    mut remaining: usize,
    mut read_buf: Option<Vec<u8>>,
    zero_copy: bool,
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let buffered = src_buf.len().min(remaining);
    if buffered > 0 {
        let slice = src_buf.slice(..buffered);
        let slice = write_all(dst, slice).await?;
        src_buf = slice.into_inner();
        discard_buffer_prefix(&mut src_buf, buffered);
        remaining -= buffered;
    }
    // Registered fixed buffers: read_fixed/write_fixed_all avoid the per-op buffer
    // mapping the kernel does for ordinary reads. Falls back to a heap buffer for
    // any iteration where no registered buffer is free or registration is disabled.
    let pool = if zero_copy { fixed_pool() } else { None };
    while remaining > 0 {
        if let Some(pool) = &pool
            && let Some(fbuf) = pool.try_next(READ_CHUNK_BYTES)
        {
            let want = READ_CHUNK_BYTES.min(remaining);
            let (result, rslice) = src.read_fixed(fbuf.slice(..want)).await;
            let read = result?;
            if read == 0 {
                return Err(UringError::Io(io::ErrorKind::UnexpectedEof.into()));
            }
            let fbuf = rslice.into_inner();
            let (result, _) = dst.write_fixed_all(fbuf.slice(..read)).await;
            result?;
            remaining -= read;
            continue;
        }
        let mut active_buf = read_buf.take().unwrap_or_else(|| vec![0; READ_CHUNK_BYTES]);
        let limit = READ_CHUNK_BYTES.min(remaining);
        // Truncate to the read limit; tokio_uring reads up to buf.len() bytes.
        active_buf.resize(limit, 0);
        let (result, active_buf) = src.read(active_buf).await;
        let read = result?;
        if read == 0 {
            return Err(UringError::Io(io::ErrorKind::UnexpectedEof.into()));
        }
        let slice_to_write = active_buf.slice(..read);
        let slice_to_write = write_all(dst, slice_to_write).await?;
        let mut reclaimed = slice_to_write.into_inner();
        // Restore to full capacity for reuse.
        reclaimed.resize(READ_CHUNK_BYTES, 0);
        read_buf = Some(reclaimed);
        remaining -= read;
    }
    Ok((src_buf, read_buf))
}

async fn copy_response_body(
    src: &UringTcpStream,
    mut src_buf: Vec<u8>,
    dst: &UringTcpStream,
    body: ResponseBody,
    mut read_buf: Option<Vec<u8>>,
    zero_copy: bool,
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    match body {
        ResponseBody::None => Ok((src_buf, read_buf)),
        ResponseBody::ContentLength(length) => {
            copy_exact_body(src, src_buf, dst, length, read_buf, zero_copy).await
        }
        ResponseBody::CloseDelimited => {
            if !src_buf.is_empty() {
                let slice = write_all(dst, src_buf.slice(..)).await?;
                src_buf = slice.into_inner();
            }
            loop {
                let active_buf = read_buf.take().unwrap_or_else(|| vec![0; READ_CHUNK_BYTES]);
                let (result, active_buf) = src.read(active_buf).await;
                let read = result?;
                if read == 0 {
                    return Ok((src_buf, Some(active_buf)));
                }
                let slice = write_all(dst, active_buf.slice(..read)).await?;
                read_buf = Some(slice.into_inner());
            }
        }
    }
}

async fn write_all<T>(stream: &UringTcpStream, buf: T) -> Result<T>
where
    T: tokio_uring::buf::BoundedBuf,
{
    let (result, buf) = stream.write_all(buf).await;
    result?;
    Ok(buf)
}

fn content_length(headers: &[httparse::Header<'_>], enforce_limit: bool) -> Result<usize> {
    let mut content_length = None;
    for header in headers {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(UringError::Parse(
                "transfer-encoding is not supported by io_uring engine yet",
            ));
        }
        if header.name.eq_ignore_ascii_case("content-length")
            && content_length.replace(header.value).is_some()
        {
            return Err(UringError::Parse("duplicate content-length"));
        }
    }
    if let Some(value) = content_length {
        let text = std::str::from_utf8(value)
            .map_err(|_| UringError::Parse("invalid content-length"))?
            .trim();
        let length = text
            .parse::<usize>()
            .map_err(|_| UringError::Parse("invalid content-length"))?;
        if enforce_limit && length > MAX_REQUEST_BODY_BYTES {
            return Err(UringError::Parse("request body too large"));
        }
        return Ok(length);
    }
    Ok(0)
}

fn append_forward_headers(out: &mut Vec<u8>, headers: &[httparse::Header<'_>], body_len: usize) {
    for header in headers {
        if should_skip_header(header.name, headers) {
            continue;
        }
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(header.value);
        out.extend_from_slice(b"\r\n");
    }
    if body_len > 0 {
        out.extend_from_slice(format!("Content-Length: {body_len}\r\n").as_bytes());
    }
}

fn should_skip_header(name: &str, headers: &[httparse::Header<'_>]) -> bool {
    if name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("upgrade")
    {
        return true;
    }
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("connection"))
        .filter_map(|header| std::str::from_utf8(header.value).ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case(name))
}

fn request_wants_close(http10: bool, headers: &[httparse::Header<'_>]) -> bool {
    connection_has(headers, b"close") || (http10 && !connection_has(headers, b"keep-alive"))
}

fn connection_has(headers: &[httparse::Header<'_>], needle: &[u8]) -> bool {
    header_value(headers, "connection").is_some_and(|value| ascii_contains(value, needle))
}

fn header_value<'a>(headers: &'a [httparse::Header<'a>], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value)
}

fn ascii_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn discard_buffer_prefix(buf: &mut Vec<u8>, count: usize) {
    if count >= buf.len() {
        buf.clear();
    } else {
        buf.drain(..count);
    }
}

fn static_response(status: u16, reason: &str, body: &'static [u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn bind_listener_socket(listener: &ListenerConfig) -> io::Result<std::net::TcpListener> {
    let socket = if listener.bind.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.set_nodelay(true)?;
    socket.set_keepalive(true)?;
    if listener.reuse_port {
        set_reuseport(&socket)?;
    }
    socket.bind(listener.bind)?;
    let listener = socket.listen(listener.backlog)?;
    listener.into_std()
}

#[cfg(all(
    unix,
    not(target_os = "solaris"),
    not(target_os = "illumos"),
    not(target_os = "cygwin"),
))]
fn set_reuseport(socket: &TcpSocket) -> io::Result<()> {
    socket.set_reuseport(true)
}

#[cfg(not(all(
    unix,
    not(target_os = "solaris"),
    not(target_os = "illumos"),
    not(target_os = "cygwin"),
)))]
fn set_reuseport(_socket: &TcpSocket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_REUSEPORT is not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uring_pool_idle_gating_returns_fresh_checkin() {
        // io_uring may be unavailable in sandboxed CI; skip gracefully there.
        if preflight_io_uring().is_err() {
            return;
        }
        tokio_uring::start(async {
            let listener =
                UringTcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let addr = listener.local_addr().unwrap();
            // Keep the accepted peer alive for the duration of the test.
            tokio_uring::spawn(async move {
                let _accepted = listener.accept().await;
                std::future::pending::<()>().await;
            });
            let conn = UringTcpStream::connect(addr).await.unwrap();
            checkin_uring_conn(addr, conn);
            // Reused within the idle threshold: returned without probing, and only
            // under its own address key.
            assert!(checkout_uring_conn("127.0.0.1:1".parse().unwrap(), Duration::from_millis(250)).is_none());
            assert!(checkout_uring_conn(addr, Duration::from_millis(250)).is_some());
        });
    }

    fn snapshot_for(upstream_addr: SocketAddr) -> ConfigSnapshot {
        ConfigSnapshot::parse(
            &format!(
                r#"
                [[routes]]
                name = "root"
                host = "*"
                path_prefix = "/"
                upstream_pool = "web"

                [upstream_pools.web]
                [[upstream_pools.web.upstreams]]
                name = "web"
                url = "http://{upstream_addr}"
                protocol = "h1"
                weight = 1
                "#
            ),
            "inline",
        )
        .unwrap()
    }

    async fn read_until_headers(stream: &UringTcpStream) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let rb = vec![0u8; 4096];
            let (res, rb) = stream.read(rb).await;
            let n = res.unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&rb[..n]);
            if memmem::find(&buf, b"\r\n\r\n").is_some() {
                break;
            }
        }
        buf
    }

    #[test]
    fn uring_proxies_content_length_response_end_to_end() {
        // Exercises the registered fixed-buffer body path end to end. Skips where
        // io_uring is unavailable (sandboxed CI).
        if preflight_io_uring().is_err() {
            return;
        }
        tokio_uring::start(async {
            let body = vec![7u8; 100_000];

            // Upstream: reply with a fixed Content-Length body, then stay open.
            let upstream = UringTcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let up_addr = upstream.local_addr().unwrap();
            let up_body = body.clone();
            tokio_uring::spawn(async move {
                let (stream, _) = upstream.accept().await.unwrap();
                let _ = read_until_headers(&stream).await;
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                    up_body.len()
                );
                let (r, _) = stream.write_all(header.into_bytes()).await;
                r.unwrap();
                let (r, _) = stream.write_all(up_body).await;
                r.unwrap();
                std::future::pending::<()>().await;
            });

            // Proxy front listener.
            let front = UringTcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let front_addr = front.local_addr().unwrap();
            let snapshot = Arc::new(snapshot_for(up_addr));
            tokio_uring::spawn(async move {
                let (stream, peer) = front.accept().await.unwrap();
                let _ = serve_connection(snapshot, stream, peer).await;
            });

            // Client.
            let client = UringTcpStream::connect(front_addr).await.unwrap();
            let (r, _) = client
                .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec())
                .await;
            r.unwrap();

            let mut got: Vec<u8> = Vec::new();
            loop {
                let rb = vec![0u8; 16384];
                let (res, rb) = client.read(rb).await;
                let n = res.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&rb[..n]);
                if let Some(i) = memmem::find(&got, b"\r\n\r\n")
                    && got.len() - (i + 4) >= body.len()
                {
                    break;
                }
            }
            let idx = memmem::find(&got, b"\r\n\r\n").unwrap() + 4;
            assert_eq!(&got[idx..idx + body.len()], &body[..]);
        });
    }

    fn snapshot() -> ConfigSnapshot {
        ConfigSnapshot::parse(
            r#"
            [[routes]]
            name = "root"
            host = "*"
            path_prefix = "/"
            upstream_pool = "web"

            [upstream_pools.web]
            [[upstream_pools.web.upstreams]]
            name = "web"
            url = "http://127.0.0.1:9000"
            protocol = "h1"
            weight = 1
            "#,
            "inline",
        )
        .unwrap()
    }

    #[test]
    fn rejects_duplicate_or_transfer_encoded_framing() {
        let snapshot = snapshot();
        assert!(
            build_request(
                &snapshot,
                b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n",
            )
            .is_err()
        );
        assert!(build_request(
            &snapshot,
            b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
        )
        .is_err());
    }

    #[test]
    fn forwards_canonical_content_length() {
        let snapshot = snapshot();
        let request = build_request(
            &snapshot,
            b"POST / HTTP/1.1\r\nHost: example.test\r\nConnection: X-Remove\r\nX-Remove: bad\r\nContent-Length: 5\r\n\r\n",
        )
        .unwrap()
        .unwrap();
        let raw = String::from_utf8(request.head.outbound).unwrap();
        assert!(raw.contains("\r\nContent-Length: 5\r\n"));
        assert!(!raw.contains("X-Remove: bad"));
        assert!(!raw.contains("Connection: X-Remove"));
    }
}
