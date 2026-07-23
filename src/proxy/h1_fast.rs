use std::fmt;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Instant;

use memchr::memmem;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

use crate::config::{ConfigSnapshot, UpstreamProtocol, UpstreamState};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const READ_CHUNK_BYTES: usize = 16 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024 * 1024;
const DOWNSTREAM_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

type Result<T> = std::result::Result<T, FastH1Error>;

#[derive(Debug)]
pub enum FastH1Error {
    Io(std::io::Error),
    Parse(&'static str),
    Upstream(String),
}

impl fmt::Display for FastH1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Parse(message) => f.write_str(message),
            Self::Upstream(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for FastH1Error {}

impl From<std::io::Error> for FastH1Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone)]
struct SelectedUpstream {
    protocol: UpstreamProtocol,
    connect_timeout: Duration,
    request_timeout: Duration,
    state: Arc<UpstreamState>,
}

impl SelectedUpstream {
    fn authority(&self) -> &str {
        self.state.authority().as_str()
    }

    fn host_header_bytes(&self) -> &[u8] {
        self.state.host_header().as_bytes()
    }

    fn id(&self) -> usize {
        self.state.id()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum BodyKind {
    None,
    ContentLength(usize),
    Chunked,
    CloseDelimited,
}

struct RequestHead {
    head_response: bool,
    close_after_response: bool,
    body: BodyKind,
}

struct ResponseHead {
    status: u16,
    close_after_response: bool,
    body: BodyKind,
}

const POOL_SHARDS: usize = 32;

/// Idle keepalive connections to upstreams, sharded to reduce lock contention and
/// keyed by the stable per-upstream id (see `UpstreamState::id`) so checkin/checkout
/// need neither a `String` allocation nor authority hashing on the hot path. Each
/// entry records when it was returned to the pool so the liveness probe can be
/// skipped for connections reused within the configured idle threshold.
pub struct FastConnectionPool {
    shards: [std::sync::Mutex<std::collections::HashMap<usize, Vec<(TcpStream, Instant)>>>;
        POOL_SHARDS],
}

impl FastConnectionPool {
    pub fn new() -> Self {
        Self {
            shards: std::array::from_fn(
                |_| std::sync::Mutex::new(std::collections::HashMap::new()),
            ),
        }
    }

    fn shard_idx(id: usize) -> usize {
        id % POOL_SHARDS
    }

    pub fn checkout(&self, id: usize, idle_threshold: Duration) -> Option<TcpStream> {
        let idx = Self::shard_idx(id);
        let mut guard = self.shards[idx].lock().unwrap();
        if let Some(conns) = guard.get_mut(&id) {
            while let Some((conn, idle_since)) = conns.pop() {
                // Hot keepalive reuse (idle under the threshold) skips the
                // recv(MSG_PEEK) syscall; only longer-idle connections are probed.
                if idle_since.elapsed() < idle_threshold || is_connection_alive(&conn) {
                    return Some(conn);
                }
                tracing::debug!(upstream_id = id, shard = idx, "checkout dropping dead connection");
            }
        }
        None
    }

    pub fn checkin(&self, id: usize, conn: TcpStream) {
        let idx = Self::shard_idx(id);
        let mut guard = self.shards[idx].lock().unwrap();
        guard.entry(id).or_default().push((conn, Instant::now()));
    }
}

fn is_connection_alive(stream: &TcpStream) -> bool {
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
        false
    } else if res > 0 {
        false
    } else {
        let err = std::io::Error::last_os_error();
        err.kind() == std::io::ErrorKind::WouldBlock
    }
}

async fn get_connection(
    pool: &FastConnectionPool,
    upstream: &SelectedUpstream,
    idle_threshold: Duration,
) -> std::io::Result<TcpStream> {
    if let Some(stream) = pool.checkout(upstream.id(), idle_threshold) {
        return Ok(stream);
    }
    tracing::debug!(authority = %upstream.authority(), "opening new upstream connection");
    let stream = tokio::time::timeout(
        upstream.connect_timeout,
        TcpStream::connect(upstream.authority()),
    )
    .await
    .map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream connect timed out")
    })??;
    stream.set_nodelay(true)?;
    Ok(stream)
}

#[tracing::instrument(skip(snapshot, pool, downstream))]
pub async fn serve_connection(
    snapshot: Arc<ConfigSnapshot>,
    pool: Arc<FastConnectionPool>,
    mut downstream: TcpStream,
) -> Result<()> {
    tracing::debug!("accepted new h1 downstream connection");
    let idle_threshold = snapshot.config.runtime.liveness_probe_idle();
    let mut downstream_buf = Vec::with_capacity(READ_CHUNK_BYTES);
    let mut upstream_buf = Vec::with_capacity(READ_CHUNK_BYTES);
    let mut outbound_buf = Vec::with_capacity(READ_CHUNK_BYTES);

    loop {
        let header_end = match timeout(
            DOWNSTREAM_HEADER_TIMEOUT,
            read_header_block(&mut downstream, &mut downstream_buf),
        )
        .await
        {
            Err(_) => return Err(FastH1Error::Parse("downstream header read timed out")),
            Ok(Ok(Some(header_end))) => header_end,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(FastH1Error::Io(err))) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Ok(Err(err)) => return Err(err),
        };

        outbound_buf.clear();
        let metrics_enabled;
        let started;
        let request = {
            let snapshot_guard = snapshot.as_ref();
            metrics_enabled = snapshot_guard.config.telemetry.prometheus;
            started = metrics_enabled.then(Instant::now);
            build_request(
                snapshot_guard,
                &downstream_buf[..header_end],
                &mut outbound_buf,
            )?
        };

        let Some(request) = request else {
            write_static_response(&mut downstream, 404, "Not Found", b"no matching route\n")
                .await?;
            metrics_no_route(metrics_enabled);
            return Ok(());
        };

        if let Some(rate_limiter) = request.rate_limiter.as_deref() {
            if let Ok(peer_addr) = downstream.peer_addr() {
                if !rate_limiter.acquire(peer_addr.ip()) {
                    metrics_rate_limited(metrics_enabled);
                    emit_access_log(&request, 429, started, &downstream);
                    write_static_response(
                        &mut downstream,
                        429,
                        "Too Many Requests",
                        b"rate limit exceeded\n",
                    )
                    .await?;
                    return Ok(());
                }
            }
        }

        if request.upstream.protocol == UpstreamProtocol::H3 {
            write_static_response(
                &mut downstream,
                501,
                "Not Implemented",
                b"HTTP/3 upstream driver is configured but not enabled in this baseline\n",
            )
            .await?;
            metrics_h3_not_enabled(metrics_enabled);
            emit_access_log(&request, 501, started, &downstream);
            return Ok(());
        };

        let request_close = request.head.close_after_response;
        let request_body = request.head.body;
        let request_timeout = request.upstream.request_timeout;

        let mut upstream_stream = match get_connection(&pool, &request.upstream, idle_threshold).await {
            Ok(stream) => stream,
            Err(_) => {
                request.upstream.state.mark_failure();
                metrics_upstream_error(metrics_enabled);
                emit_access_log(&request, 502, started, &downstream);
                write_static_response(
                    &mut downstream,
                    502,
                    "Bad Gateway",
                    b"upstream request failed\n",
                )
                .await?;
                return Ok(());
            }
        };

        if let Err(_) = upstream_stream.write_all(&outbound_buf).await {
            request.upstream.state.mark_failure();
            metrics_upstream_error(metrics_enabled);
            emit_access_log(&request, 502, started, &downstream);
            write_static_response(
                &mut downstream,
                502,
                "Bad Gateway",
                b"upstream request failed\n",
            )
            .await?;
            return Ok(());
        }

        discard_buffer_prefix(&mut downstream_buf, header_end);
        if let Err(_) = timeout(
            request_timeout,
            copy_body(
                &mut downstream,
                &mut downstream_buf,
                &mut upstream_stream,
                request_body,
                Some(MAX_REQUEST_BODY_BYTES),
            ),
        )
        .await
        .map_err(|_| FastH1Error::Parse("downstream body read timed out"))
        .and_then(|result| result)
        {
            request.upstream.state.mark_failure();
            metrics_upstream_error(metrics_enabled);
            emit_access_log(&request, 502, started, &downstream);
            if request_close {
                return Ok(());
            }
            continue;
        }

        if let Err(_) = upstream_stream.flush().await {
            request.upstream.state.mark_failure();
            metrics_upstream_error(metrics_enabled);
            emit_access_log(&request, 502, started, &downstream);
            if request_close {
                return Ok(());
            }
            continue;
        }

        let response_result = timeout(
            request_timeout,
            read_and_forward_response(
                &mut upstream_stream,
                &mut upstream_buf,
                &mut downstream,
                request.head.head_response,
            ),
        )
        .await
        .map_err(|_| FastH1Error::Upstream("upstream request timed out".to_string()));

        match response_result {
            Ok(Ok(response)) => {
                if response.status >= 500 {
                    request.upstream.state.mark_failure();
                } else {
                    request.upstream.state.mark_success();
                }
                metrics_proxied(metrics_enabled, started);
                emit_access_log(&request, response.status, started, &downstream);

                let close_conn = request_close
                    || response.close_after_response
                    || response.body == BodyKind::CloseDelimited;

                if !close_conn {
                    pool.checkin(request.upstream.id(), upstream_stream);
                }

                if close_conn {
                    return Ok(());
                }
            }
            _ => {
                request.upstream.state.mark_failure();
                metrics_upstream_error(metrics_enabled);
                emit_access_log(&request, 502, started, &downstream);
                write_static_response(
                    &mut downstream,
                    502,
                    "Bad Gateway",
                    b"upstream request failed\n",
                )
                .await?;
                if request_close {
                    return Ok(());
                }
            }
        }
    }
}

struct MatchedRequest {
    head: RequestHead,
    upstream: SelectedUpstream,
    rate_limiter: Option<Arc<crate::proxy::rate_limit::RateLimiter>>,
    access_log: Option<(String, String)>,
}

fn build_request(
    snapshot: &ConfigSnapshot,
    raw_headers: &[u8],
    outbound: &mut Vec<u8>,
) -> Result<Option<MatchedRequest>> {
    let mut headers = [httparse::EMPTY_HEADER; 96];
    let mut parsed = httparse::Request::new(&mut headers);
    let status = parsed
        .parse(raw_headers)
        .map_err(|_| FastH1Error::Parse("invalid request headers"))?;
    if !status.is_complete() {
        return Err(FastH1Error::Parse("incomplete request headers"));
    }

    let method = parsed
        .method
        .ok_or(FastH1Error::Parse("request method missing"))?;
    let path_and_query = parsed
        .path
        .ok_or(FastH1Error::Parse("request target missing"))?;
    let http10 = parsed.version == Some(0);
    let host = if snapshot.routes.requires_host_match() {
        header_value(parsed.headers, "host").and_then(header_to_str)
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
        .ok_or(FastH1Error::Upstream("no available upstream".to_string()))?;
    let rate_limiter = route_match.rate_limiter;
    let upstream_path = upstream.upstream_path_and_query(path_and_query);
    let selected = SelectedUpstream {
        protocol: upstream.config.protocol,
        connect_timeout: Duration::from_millis(upstream.config.connect_timeout_ms),
        request_timeout: Duration::from_millis(upstream.config.request_timeout_ms),
        state: upstream,
    };

    let close_after_response = request_wants_close(http10, parsed.headers);
    let body = body_kind(parsed.headers, true)?;

    outbound.reserve(raw_headers.len() + upstream_path.len() + 64);
    outbound.extend_from_slice(method.as_bytes());
    outbound.extend_from_slice(b" ");
    outbound.extend_from_slice(upstream_path.as_bytes());
    outbound.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    outbound.extend_from_slice(selected.host_header_bytes());
    outbound.extend_from_slice(b"\r\nConnection: keep-alive\r\n");
    append_forward_headers(outbound, parsed.headers, body);
    outbound.extend_from_slice(b"\r\n");

    let access_log = if snapshot.config.telemetry.access_log {
        Some((method.to_string(), path_and_query.to_string()))
    } else {
        None
    };

    Ok(Some(MatchedRequest {
        head: RequestHead {
            head_response: method.eq_ignore_ascii_case("HEAD"),
            close_after_response,
            body,
        },
        upstream: selected,
        rate_limiter,
        access_log,
    }))
}

async fn read_and_forward_response(
    upstream: &mut TcpStream,
    upstream_buf: &mut Vec<u8>,
    downstream: &mut TcpStream,
    head_response: bool,
) -> Result<ResponseHead> {
    loop {
        let header_end = read_header_block(upstream, upstream_buf)
            .await?
            .ok_or(FastH1Error::Parse("upstream closed before response"))?;
        let response = parse_response(&upstream_buf[..header_end], head_response)?;
        if (100..200).contains(&response.status) {
            // 1xx interim response: forward the header, flush, keep reading for
            // the final status line.
            downstream.write_all(&upstream_buf[..header_end]).await?;
            discard_buffer_prefix(upstream_buf, header_end);
            downstream.flush().await?;
            continue;
        }

        // Coalesce the response header with any already-buffered leading body
        // bytes into a single write, so a small response leaves the proxy as one
        // send() / one segment instead of a header packet followed by a body
        // packet under TCP_NODELAY.
        let buffered_body = upstream_buf.len() - header_end;
        let coalesced = match response.body {
            BodyKind::ContentLength(length) => header_end + buffered_body.min(length),
            _ => header_end,
        };
        downstream.write_all(&upstream_buf[..coalesced]).await?;
        discard_buffer_prefix(upstream_buf, coalesced);

        match response.body {
            BodyKind::ContentLength(length) => {
                // Bytes of the body already sent as part of the coalesced write.
                let already_sent = coalesced - header_end;
                copy_exact_body(upstream, upstream_buf, downstream, length - already_sent).await?;
            }
            _ => copy_body(upstream, upstream_buf, downstream, response.body, None).await?,
        }
        downstream.flush().await?;
        return Ok(response);
    }
}

fn parse_response(raw_headers: &[u8], head_response: bool) -> Result<ResponseHead> {
    let mut headers = [httparse::EMPTY_HEADER; 96];
    let mut parsed = httparse::Response::new(&mut headers);
    let status = parsed
        .parse(raw_headers)
        .map_err(|_| FastH1Error::Parse("invalid response headers"))?;
    if !status.is_complete() {
        return Err(FastH1Error::Parse("incomplete response headers"));
    }
    let code = parsed
        .code
        .ok_or(FastH1Error::Parse("response status missing"))?;
    let body = if head_response || (100..200).contains(&code) || code == 204 || code == 304 {
        BodyKind::None
    } else {
        body_kind(parsed.headers, false)?.or_close_delimited()
    };
    let close_after_response = !(100..200).contains(&code)
        && (response_wants_close(parsed.version == Some(0), parsed.headers)
            || body == BodyKind::CloseDelimited);

    Ok(ResponseHead {
        status: code,
        close_after_response,
        body,
    })
}

impl BodyKind {
    fn or_close_delimited(self) -> Self {
        if self == Self::None {
            Self::CloseDelimited
        } else {
            self
        }
    }
}

async fn read_header_block(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Result<Option<usize>> {
    loop {
        if let Some(index) = memmem::find(buf, b"\r\n\r\n") {
            return Ok(Some(index + 4));
        }
        if buf.len() >= MAX_HEADER_BYTES {
            return Err(FastH1Error::Parse("headers too large"));
        }
        let before = buf.len();
        buf.resize(before + READ_CHUNK_BYTES, 0);
        let read = stream.read(&mut buf[before..]).await?;
        if read == 0 {
            buf.truncate(before);
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(FastH1Error::Io(std::io::ErrorKind::UnexpectedEof.into()))
            };
        }
        buf.truncate(before + read);
    }
}

async fn copy_body(
    src: &mut TcpStream,
    src_buf: &mut Vec<u8>,
    dst: &mut TcpStream,
    body: BodyKind,
    max_body_bytes: Option<usize>,
) -> Result<()> {
    match body {
        BodyKind::None => Ok(()),
        BodyKind::ContentLength(length) => copy_exact_body(src, src_buf, dst, length).await,
        BodyKind::Chunked => copy_chunked_body(src, src_buf, dst, max_body_bytes).await,
        BodyKind::CloseDelimited => {
            if !src_buf.is_empty() {
                dst.write_all(src_buf).await?;
                src_buf.clear();
            }
            tokio::io::copy(src, dst).await?;
            Ok(())
        }
    }
}

async fn copy_exact_body(
    src: &mut TcpStream,
    src_buf: &mut Vec<u8>,
    dst: &mut TcpStream,
    mut remaining: usize,
) -> Result<()> {
    let buffered = src_buf.len().min(remaining);
    if buffered > 0 {
        dst.write_all(&src_buf[..buffered]).await?;
        discard_buffer_prefix(src_buf, buffered);
        remaining -= buffered;
    }
    let mut scratch = [0_u8; READ_CHUNK_BYTES];
    while remaining > 0 {
        let limit = scratch.len().min(remaining);
        let read = src.read(&mut scratch[..limit]).await?;
        if read == 0 {
            return Err(FastH1Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
        }
        dst.write_all(&scratch[..read]).await?;
        remaining -= read;
    }
    Ok(())
}

async fn copy_chunked_body(
    src: &mut TcpStream,
    src_buf: &mut Vec<u8>,
    dst: &mut TcpStream,
    max_body_bytes: Option<usize>,
) -> Result<()> {
    let mut copied = 0usize;
    loop {
        let line = read_line(src, src_buf).await?;
        dst.write_all(&line).await?;
        let line_text = std::str::from_utf8(&line).map_err(|_| FastH1Error::Parse("bad chunk"))?;
        let size_text = line_text
            .trim()
            .split(';')
            .next()
            .ok_or(FastH1Error::Parse("bad chunk size"))?;
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| FastH1Error::Parse("bad chunk size"))?;
        if size == 0 {
            loop {
                let trailer = read_line(src, src_buf).await?;
                dst.write_all(&trailer).await?;
                if trailer == b"\r\n" {
                    return Ok(());
                }
            }
        }
        copied = copied
            .checked_add(size)
            .ok_or(FastH1Error::Parse("request body too large"))?;
        if let Some(max) = max_body_bytes
            && copied > max
        {
            return Err(FastH1Error::Parse("request body too large"));
        }
        copy_exact_body(src, src_buf, dst, size + 2).await?;
    }
}

async fn read_line(src: &mut TcpStream, src_buf: &mut Vec<u8>) -> Result<Vec<u8>> {
    loop {
        if let Some(index) = memmem::find(src_buf, b"\r\n") {
            let line = src_buf[..index + 2].to_vec();
            discard_buffer_prefix(src_buf, index + 2);
            return Ok(line);
        }
        let before = src_buf.len();
        src_buf.resize(before + READ_CHUNK_BYTES, 0);
        let read = src.read(&mut src_buf[before..]).await?;
        if read == 0 {
            src_buf.truncate(before);
            return Err(FastH1Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
        }
        src_buf.truncate(before + read);
    }
}

fn body_kind(headers: &[httparse::Header<'_>], enforce_limit: bool) -> Result<BodyKind> {
    let mut transfer_encoding = None;
    let mut content_length = None;
    for header in headers {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding.replace(header.value).is_some() {
                return Err(FastH1Error::Parse("duplicate transfer-encoding"));
            }
        } else if header.name.eq_ignore_ascii_case("content-length") {
            if content_length.replace(header.value).is_some() {
                return Err(FastH1Error::Parse("duplicate content-length"));
            }
        }
    }

    if let Some(value) = transfer_encoding {
        if content_length.is_some() {
            return Err(FastH1Error::Parse(
                "conflicting transfer-encoding and content-length",
            ));
        }
        let text = std::str::from_utf8(value)
            .map_err(|_| FastH1Error::Parse("invalid transfer-encoding"))?;
        let mut codings = text.split(',').map(str::trim);
        let Some(first) = codings.next() else {
            return Err(FastH1Error::Parse("invalid transfer-encoding"));
        };
        if !first.eq_ignore_ascii_case("chunked") || codings.any(|coding| !coding.is_empty()) {
            return Err(FastH1Error::Parse("unsupported transfer-encoding"));
        }
        return Ok(BodyKind::Chunked);
    }
    if let Some(value) = content_length {
        let text = std::str::from_utf8(value)
            .map_err(|_| FastH1Error::Parse("invalid content-length"))?
            .trim();
        let length = text
            .parse::<usize>()
            .map_err(|_| FastH1Error::Parse("invalid content-length"))?;
        if enforce_limit && length > MAX_REQUEST_BODY_BYTES {
            return Err(FastH1Error::Parse("request body too large"));
        }
        return Ok(BodyKind::ContentLength(length));
    }
    Ok(BodyKind::None)
}

fn append_forward_headers(out: &mut Vec<u8>, headers: &[httparse::Header<'_>], body: BodyKind) {
    for header in headers {
        if should_skip_header(header.name, headers) {
            continue;
        }
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(header.value);
        out.extend_from_slice(b"\r\n");
    }
    match body {
        BodyKind::ContentLength(length) => {
            let mut len_buf = [0u8; 20];
            out.extend_from_slice(b"Content-Length: ");
            out.extend_from_slice(format_usize(length, &mut len_buf));
            out.extend_from_slice(b"\r\n");
        }
        BodyKind::Chunked => out.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
        BodyKind::None | BodyKind::CloseDelimited => {}
    }
}

fn should_skip_header(name: &str, headers: &[httparse::Header<'_>]) -> bool {
    match name.len() {
        2 => {
            if name.eq_ignore_ascii_case("te") {
                return true;
            }
        }
        4 => {
            if name.eq_ignore_ascii_case("host") {
                return true;
            }
        }
        10 => {
            if name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("keep-alive") {
                return true;
            }
        }
        7 => {
            if name.eq_ignore_ascii_case("trailer") || name.eq_ignore_ascii_case("upgrade") {
                return true;
            }
        }
        14 => {
            if name.eq_ignore_ascii_case("content-length") {
                return true;
            }
        }
        17 => {
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return true;
            }
        }
        16 => {
            if name.eq_ignore_ascii_case("proxy-connection") {
                return true;
            }
        }
        _ => {}
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

fn response_wants_close(http10: bool, headers: &[httparse::Header<'_>]) -> bool {
    request_wants_close(http10, headers)
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

fn header_to_str(value: &[u8]) -> Option<&str> {
    std::str::from_utf8(value).ok()
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
        buf.copy_within(count.., 0);
        buf.truncate(buf.len() - count);
    }
}

async fn write_static_response(
    downstream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &'static [u8],
) -> Result<()> {
    // Build the response header on the stack to avoid heap allocation via format!()
    let mut header_buf = Vec::with_capacity(128);
    header_buf.extend_from_slice(b"HTTP/1.1 ");
    // itoa-style: write status digits directly
    let mut status_buf = [0u8; 3];
    status_buf[0] = b'0' + (status / 100) as u8;
    status_buf[1] = b'0' + ((status / 10) % 10) as u8;
    status_buf[2] = b'0' + (status % 10) as u8;
    header_buf.extend_from_slice(&status_buf);
    header_buf.extend_from_slice(b" ");
    header_buf.extend_from_slice(reason.as_bytes());
    header_buf
        .extend_from_slice(b"\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ");
    // Write body length without allocation
    let mut len_buf = [0u8; 20];
    let len_str = format_usize(body.len(), &mut len_buf);
    header_buf.extend_from_slice(len_str);
    header_buf.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
    downstream.write_all(&header_buf).await?;
    downstream.write_all(body).await?;
    downstream.flush().await?;
    Ok(())
}

/// Format a usize into a stack-allocated byte buffer, returning the formatted slice.
fn format_usize(mut n: usize, buf: &mut [u8; 20]) -> &[u8] {
    if n == 0 {
        buf[19] = b'0';
        return &buf[19..];
    }
    let mut pos = 20;
    while n > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[pos..]
}

fn metrics_no_route(enabled: bool) {
    if enabled {
        metrics::counter!("yxorp_requests_total", "result" => "no_route").increment(1);
    }
}

fn metrics_h3_not_enabled(enabled: bool) {
    if enabled {
        metrics::counter!("yxorp_requests_total", "result" => "h3_not_enabled").increment(1);
    }
}

fn metrics_rate_limited(enabled: bool) {
    if enabled {
        metrics::counter!("yxorp_requests_total", "result" => "rate_limited").increment(1);
    }
}

fn metrics_proxied(enabled: bool, started: Option<Instant>) {
    if enabled {
        metrics::counter!("yxorp_requests_total", "result" => "proxied").increment(1);
        if let Some(started) = started {
            metrics::histogram!("yxorp_request_duration_seconds")
                .record(started.elapsed().as_secs_f64());
        }
    }
}

fn emit_access_log(
    request: &MatchedRequest,
    status: u16,
    started: Option<Instant>,
    downstream: &TcpStream,
) {
    if let Some((ref method, ref path)) = request.access_log {
        let duration = started
            .map(|t| t.elapsed().as_secs_f64() * 1000.0)
            .unwrap_or(0.0);
        let client_ip = downstream
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        tracing::info!(
            target: "access",
            method = %method,
            path = %path,
            status = status,
            duration_ms = duration,
            client_ip = %client_ip,
            upstream = %request.upstream.authority(),
        );
    }
}

fn metrics_upstream_error(enabled: bool) {
    if enabled {
        metrics::counter!("yxorp_requests_total", "result" => "upstream_error").increment(1);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::net::TcpListener;

    use super::*;
    use crate::config::ConfigSnapshot;

    fn fast_snapshot(upstream_addr: impl std::fmt::Display) -> ConfigSnapshot {
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

    #[tokio::test]
    async fn proxies_large_content_length_response_byte_for_byte() {
        // Exercises the coalesced header+buffered-body write and the remainder
        // read path for a body larger than one read chunk.
        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let server_body = body.clone();
        tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut buf = Vec::new();
            let _ = read_header_block(&mut stream, &mut buf).await.unwrap().unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                server_body.len()
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(&server_body).await.unwrap();
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let snapshot = Arc::new(fast_snapshot(upstream_addr));
        let pool = Arc::new(FastConnectionPool::new());
        tokio::spawn(async move {
            let (stream, _) = proxy.accept().await.unwrap();
            let _ = serve_connection(snapshot, pool, stream).await;
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"GET /large HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(read_client_body(&mut client).await, body);
    }

    #[tokio::test]
    async fn pool_checkout_is_idle_gated_and_id_keyed() {
        use std::time::Duration;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _c = listener.accept().await.unwrap();
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
        let client = TcpStream::connect(addr).await.unwrap();
        let pool = FastConnectionPool::new();
        pool.checkin(7, client);
        // Fresh checkin is available under its own id and skips the probe; a
        // different id sees nothing.
        assert!(pool.checkout(9, Duration::from_millis(250)).is_none());
        assert!(pool.checkout(7, Duration::from_millis(250)).is_some());
    }

    #[test]
    fn rejects_ambiguous_request_framing() {
        let snapshot = fast_snapshot("127.0.0.1:9000");
        let mut outbound = Vec::new();
        let err = match build_request(
            &snapshot,
            b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
            &mut outbound,
        ) {
            Ok(_) => panic!("ambiguous TE/CL request was accepted"),
            Err(err) => err,
        };
        assert!(matches!(err, FastH1Error::Parse(_)));

        outbound.clear();
        let err = match build_request(
            &snapshot,
            b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
            &mut outbound,
        ) {
            Ok(_) => panic!("duplicate Content-Length request was accepted"),
            Err(err) => err,
        };
        assert!(matches!(err, FastH1Error::Parse(_)));
    }

    #[test]
    fn forwards_canonical_request_framing_and_hop_headers() {
        let snapshot = fast_snapshot("127.0.0.1:9000");
        let mut outbound = Vec::new();
        build_request(
            &snapshot,
            b"POST / HTTP/1.1\r\nHost: example.test\r\nConnection: X-Remove\r\nX-Remove: bad\r\nContent-Length: 5\r\n\r\n",
            &mut outbound,
        )
        .unwrap()
        .unwrap();
        let raw = String::from_utf8(outbound).unwrap();
        assert!(raw.contains("\r\nContent-Length: 5\r\n"));
        assert!(!raw.contains("X-Remove: bad"));
        assert!(!raw.contains("Connection: X-Remove"));
    }

    #[tokio::test]
    async fn proxies_keepalive_post_and_chunked_response() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut buf = Vec::new();
            while let Some(header_end) = read_header_block(&mut stream, &mut buf).await.unwrap() {
                let raw = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let target = raw
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_string();
                let lower = raw.to_ascii_lowercase();
                let body = if lower.contains("content-length: 5") {
                    discard_buffer_prefix(&mut buf, header_end);
                    let mut body = vec![0; 5];
                    let buffered = buf.len().min(5);
                    body[..buffered].copy_from_slice(&buf[..buffered]);
                    discard_buffer_prefix(&mut buf, buffered);
                    if buffered < 5 {
                        stream.read_exact(&mut body[buffered..]).await.unwrap();
                    }
                    body
                } else if lower.contains("transfer-encoding: chunked") {
                    discard_buffer_prefix(&mut buf, header_end);
                    read_chunked_test_body(&mut stream, &mut buf).await
                } else {
                    discard_buffer_prefix(&mut buf, header_end);
                    Vec::new()
                };

                if target == "/chunked-response" {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
                        )
                        .await
                        .unwrap();
                } else {
                    let response_body = if body.is_empty() {
                        b"ok".to_vec()
                    } else {
                        [b"body:".as_slice(), body.as_slice()].concat()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                        response_body.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                    stream.write_all(&response_body).await.unwrap();
                }
            }
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let snapshot = Arc::new(fast_snapshot(upstream_addr));
        let pool = Arc::new(FastConnectionPool::new());
        tokio::spawn(async move {
            let (stream, _) = proxy.accept().await.unwrap();
            serve_connection(snapshot, pool, stream).await.unwrap();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"GET /bench HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(read_client_body(&mut client).await, b"ok");

        client
            .write_all(
                b"POST /post HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello",
            )
            .await
            .unwrap();
        assert_eq!(read_client_body(&mut client).await, b"body:hello");

        client
            .write_all(
                b"POST /chunked-request HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
            )
            .await
            .unwrap();
        assert_eq!(read_client_body(&mut client).await, b"body:hello");

        client
            .write_all(b"GET /chunked-response HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(read_client_body(&mut client).await, b"hello world");
    }

    async fn read_client_body(stream: &mut TcpStream) -> Vec<u8> {
        let mut buf = Vec::new();
        let header_end = read_header_block(stream, &mut buf).await.unwrap().unwrap();
        let headers = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
        discard_buffer_prefix(&mut buf, header_end);
        if let Some(length) = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .and_then(|value| value.trim().parse::<usize>().ok())
        {
            let mut body = vec![0; length];
            let buffered = buf.len().min(length);
            body[..buffered].copy_from_slice(&buf[..buffered]);
            discard_buffer_prefix(&mut buf, buffered);
            if buffered < length {
                stream.read_exact(&mut body[buffered..]).await.unwrap();
            }
            return body;
        }

        let mut body = Vec::new();
        loop {
            let line = read_line(stream, &mut buf).await.unwrap();
            let size_text = std::str::from_utf8(line.strip_suffix(b"\r\n").unwrap()).unwrap();
            let size = usize::from_str_radix(size_text, 16).unwrap();
            if size == 0 {
                let _ = read_line(stream, &mut buf).await.unwrap();
                return body;
            }
            let start = body.len();
            body.resize(start + size, 0);
            let buffered = buf.len().min(size);
            body[start..start + buffered].copy_from_slice(&buf[..buffered]);
            discard_buffer_prefix(&mut buf, buffered);
            if buffered < size {
                stream
                    .read_exact(&mut body[start + buffered..start + size])
                    .await
                    .unwrap();
            }
            let mut crlf = [0; 2];
            if buf.len() >= 2 {
                discard_buffer_prefix(&mut buf, 2);
            } else {
                stream.read_exact(&mut crlf).await.unwrap();
            }
        }
    }

    async fn read_chunked_test_body(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Vec<u8> {
        let mut body = Vec::new();
        loop {
            let line = read_line(stream, buf).await.unwrap();
            let size_text = std::str::from_utf8(line.strip_suffix(b"\r\n").unwrap()).unwrap();
            let size = usize::from_str_radix(size_text, 16).unwrap();
            if size == 0 {
                let _ = read_line(stream, buf).await.unwrap();
                return body;
            }
            let start = body.len();
            body.resize(start + size, 0);
            let buffered = buf.len().min(size);
            body[start..start + buffered].copy_from_slice(&buf[..buffered]);
            discard_buffer_prefix(buf, buffered);
            if buffered < size {
                stream
                    .read_exact(&mut body[start + buffered..start + size])
                    .await
                    .unwrap();
            }
            if buf.len() >= 2 {
                discard_buffer_prefix(buf, 2);
            } else {
                let mut crlf = [0; 2];
                stream.read_exact(&mut crlf).await.unwrap();
            }
        }
    }
}
