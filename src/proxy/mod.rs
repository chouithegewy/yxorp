use std::convert::Infallible;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{Notify, watch};
use tracing::{error, info, warn};

use crate::config::{
    ConfigSnapshot, Http1Engine, ListenerConfig, ListenerProtocol, UpstreamProtocol,
};

pub mod h1_fast;
mod h1_uring;
pub mod rate_limit;

#[cfg(feature = "h3")]
mod h3_quiche;

pub mod ebpf;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = BoxBody<Bytes, BoxError>;

fn load_tls_config(
    cert_path: &Path,
    key_path: &Path,
    protocols: &[ListenerProtocol],
) -> Result<rustls::ServerConfig, BoxError> {
    use rustls::ServerConfig;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(cert_path)?.collect::<Result<_, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key_path)?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let mut alpn = Vec::new();
    if protocols.contains(&ListenerProtocol::H2) {
        alpn.push(b"h2".to_vec());
    }
    if protocols.contains(&ListenerProtocol::H1) {
        alpn.push(b"http/1.1".to_vec());
    }
    config.alpn_protocols = alpn;

    Ok(config)
}

enum MaybeTlsStream {
    Plain(TcpStream),
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[derive(Clone)]
pub struct ProxyRuntime {
    snapshot: Arc<ArcSwap<ConfigSnapshot>>,
    client: Client<HttpConnector, Incoming>,
    fast_pool: Arc<h1_fast::FastConnectionPool>,
    connections: Arc<ConnectionTracker>,
}

pub struct ConnectionTracker {
    active: AtomicUsize,
    idle: Notify,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
            idle: Notify::new(),
        }
    }

    fn started(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    fn finished(&self) {
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.idle.notify_waiters();
        }
    }

    pub async fn wait(&self) {
        loop {
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            self.idle.notified().await;
        }
    }
}

impl ProxyRuntime {
    pub fn new(snapshot: Arc<ArcSwap<ConfigSnapshot>>) -> Self {
        // Install aws-lc-rs default crypto provider to avoid runtime panics in rustls 0.23
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();

        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        connector.set_nodelay(true);
        let client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(1024)
            .pool_idle_timeout(Duration::from_secs(90))
            .http1_writev(true)
            .build(connector);
        let fast_pool = Arc::new(h1_fast::FastConnectionPool::new());
        Self {
            snapshot,
            client,
            fast_pool,
            connections: Arc::new(ConnectionTracker::new()),
        }
    }

    pub async fn serve_listener(
        self,
        listener: ListenerConfig,
        mut shutdown: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        let tls_config = if listener.tls {
            let snapshot = self.snapshot.load();
            let cert_cfg = snapshot.config.tls.certs.first().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "TLS enabled on listener but no certificates configured in global tls config",
                )
            })?;
            let rustls_cfg =
                load_tls_config(&cert_cfg.cert_path, &cert_cfg.key_path, &listener.protocols)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
            Some(Arc::new(rustls_cfg))
        } else {
            None
        };

        if listener.protocols == [ListenerProtocol::H3] {
            #[cfg(feature = "h3")]
            {
                return h3_quiche::serve_listener(self.snapshot, listener, tls_config, shutdown)
                    .await;
            }
            #[cfg(not(feature = "h3"))]
            {
                warn!(
                    listener = listener.name,
                    "HTTP/3-only listener configured but h3 feature is not compiled"
                );
                return Ok(());
            }
        }

        info!(listener = listener.name, bind = %listener.bind, "listener started");
        let h1_only = listener.protocols == [ListenerProtocol::H1];
        let fast_h1 = listener.http1_engine == Http1Engine::Fast;
        if listener.http1_engine == Http1Engine::Uring {
            return h1_uring::serve_listener(
                self.snapshot,
                listener,
                shutdown,
                Arc::clone(&self.connections),
            )
            .await;
        }
        let accept_workers = accept_worker_count(&listener);
        let mut sockets = Vec::with_capacity(accept_workers);
        for _ in 0..accept_workers {
            sockets.push(bind_listener_socket(&listener)?);
        }

        if accept_workers == 1 {
            return self
                .accept_loop(
                    listener.name,
                    0,
                    sockets.pop().expect("listener socket"),
                    h1_only,
                    fast_h1,
                    tls_config,
                    shutdown,
                )
                .await;
        }

        info!(
            listener = listener.name,
            accept_workers,
            reuse_port = listener.reuse_port,
            backlog = listener.backlog,
            "listener accept sharding enabled"
        );

        let listener_name = Arc::<str>::from(listener.name);
        let mut handles = Vec::with_capacity(accept_workers);
        for (worker_id, socket) in sockets.into_iter().enumerate() {
            let runtime = self.clone();
            let worker_shutdown = shutdown.clone();
            let worker_listener_name = Arc::clone(&listener_name);
            let worker_tls = tls_config.clone();
            handles.push(tokio::spawn(async move {
                if let Err(err) = runtime
                    .accept_loop(
                        worker_listener_name,
                        worker_id,
                        socket,
                        h1_only,
                        fast_h1,
                        worker_tls,
                        worker_shutdown,
                    )
                    .await
                {
                    error!(error = %err, worker_id, "accept worker stopped");
                }
            }));
        }

        while shutdown.changed().await.is_ok() {
            if *shutdown.borrow() {
                break;
            }
        }
        for handle in handles {
            let _ = handle.await;
        }
        Ok(())
    }

    async fn accept_loop(
        self,
        listener_name: impl AsRef<str>,
        worker_id: usize,
        socket: TcpListener,
        h1_only: bool,
        fast_h1: bool,
        tls_config: Option<Arc<rustls::ServerConfig>>,
        mut shutdown: watch::Receiver<bool>,
    ) -> io::Result<()> {
        let listener_name = Arc::<str>::from(listener_name.as_ref());
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        info!(listener = %listener_name, worker_id, "listener worker shutting down");
                        return Ok(());
                    }
                }
                accepted = socket.accept() => {
                    let (stream, peer_addr) = accepted?;
                    self.spawn_connection(stream, peer_addr, h1_only, fast_h1, tls_config.clone());
                }
            }
        }
    }

    fn spawn_connection(
        &self,
        stream: TcpStream,
        peer_addr: std::net::SocketAddr,
        h1_only: bool,
        fast_h1: bool,
        tls_config: Option<Arc<rustls::ServerConfig>>,
    ) {
        if let Err(err) = stream.set_nodelay(true) {
            warn!(error = %err, %peer_addr, "failed to set TCP_NODELAY");
        }
        let runtime = self.clone();
        let connections = Arc::clone(&runtime.connections);
        connections.started();
        let connection_metrics_enabled = runtime.snapshot.load().config.telemetry.prometheus;
        tokio::spawn(async move {
            if connection_metrics_enabled {
                metrics::gauge!("yxorp_active_connections").increment(1.0);
            }

            let result = async {
                if fast_h1 {
                    let snapshot = runtime.snapshot.load_full();
                    let pool = runtime.fast_pool.clone();
                    h1_fast::serve_connection(snapshot, pool, stream)
                        .await
                        .map_err(Into::into)
                } else {
                    let io = if let Some(tls_cfg) = tls_config {
                        let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
                        let tls_stream = acceptor.accept(stream).await?;
                        TokioIo::new(MaybeTlsStream::Tls(tls_stream))
                    } else {
                        TokioIo::new(MaybeTlsStream::Plain(stream))
                    };

                    let service = service_fn(move |request| {
                        let runtime = runtime.clone();
                        async move { runtime.proxy(request, peer_addr).await }
                    });

                    if h1_only {
                        let mut builder = http1::Builder::new();
                        builder.writev(true).pipeline_flush(true);
                        builder
                            .serve_connection(io, service)
                            .await
                            .map_err(Into::into)
                    } else {
                        let mut builder =
                            hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                        builder.http1().writev(true).pipeline_flush(true);
                        builder.serve_connection_with_upgrades(io, service).await
                    }
                }
            }
            .await;

            if connection_metrics_enabled {
                metrics::gauge!("yxorp_active_connections").decrement(1.0);
            }
            if let Err(err) = result {
                error!(error = %err, %peer_addr, "connection failed");
            }
            connections.finished();
        });
    }

    pub fn connection_tracker(&self) -> Arc<ConnectionTracker> {
        Arc::clone(&self.connections)
    }

    async fn proxy(
        &self,
        request: Request<Incoming>,
        peer_addr: std::net::SocketAddr,
    ) -> Result<Response<ProxyBody>, Infallible> {
        let path = request
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");

        let snapshot = self.snapshot.load();
        let host = if snapshot.routes.requires_host_match() {
            request
                .headers()
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
        } else {
            None
        };
        let metrics_enabled = snapshot.config.telemetry.prometheus;
        let started = metrics_enabled.then(Instant::now);
        let Some(route_match) = snapshot.routes.match_route(host, path) else {
            if metrics_enabled {
                metrics::counter!("yxorp_requests_total", "result" => "no_route").increment(1);
            }
            return Ok(text_response(StatusCode::NOT_FOUND, "no matching route\n"));
        };
        if let Some(rate_limiter) = route_match.rate_limiter.as_deref()
            && !rate_limiter.acquire(peer_addr.ip())
        {
            if metrics_enabled {
                metrics::counter!("yxorp_requests_total", "result" => "rate_limited").increment(1);
            }
            return Ok(text_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded\n",
            ));
        }
        let Some(upstream) = route_match.pool.select() else {
            if metrics_enabled {
                metrics::counter!("yxorp_requests_total", "result" => "no_upstream").increment(1);
            }
            return Ok(text_response(
                StatusCode::BAD_GATEWAY,
                "no available upstream\n",
            ));
        };

        if upstream.config.protocol == UpstreamProtocol::H3 {
            if metrics_enabled {
                metrics::counter!("yxorp_requests_total", "result" => "h3_not_enabled")
                    .increment(1);
            }
            return Ok(text_response(
                StatusCode::NOT_IMPLEMENTED,
                "HTTP/3 upstream driver is configured but not enabled in this baseline\n",
            ));
        }

        let upstream_uri = match upstream.build_uri(&path) {
            Ok(uri) => uri,
            Err(err) => {
                upstream.mark_failure();
                error!(error = %err, upstream = upstream.config.name, route = route_match.route.name, "invalid upstream URI");
                return Ok(text_response(
                    StatusCode::BAD_GATEWAY,
                    "invalid upstream URI\n",
                ));
            }
        };

        let (mut parts, body) = request.into_parts();
        parts.uri = upstream_uri;
        parts
            .headers
            .insert(http::header::HOST, upstream.host_header().clone());
        let outbound = Request::from_parts(parts, body);

        let request_timeout = Duration::from_millis(upstream.config.request_timeout_ms);
        match tokio::time::timeout(request_timeout, self.client.request(outbound)).await {
            Err(_) => {
                upstream.mark_failure();
                if metrics_enabled {
                    metrics::counter!("yxorp_requests_total", "result" => "upstream_error")
                        .increment(1);
                }
                error!(
                    upstream = upstream.config.name,
                    route = route_match.route.name,
                    "upstream request timed out"
                );
                Ok(text_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream request timed out\n",
                ))
            }
            Ok(Ok(response)) => {
                let status = response.status();
                if status.is_server_error() {
                    upstream.mark_failure();
                } else {
                    upstream.mark_success();
                }
                if metrics_enabled {
                    metrics::counter!("yxorp_requests_total", "result" => "proxied").increment(1);
                    if let Some(started) = started {
                        metrics::histogram!("yxorp_request_duration_seconds")
                            .record(started.elapsed().as_secs_f64());
                    }
                }
                Ok(response.map(|body| body.map_err(Into::into).boxed()))
            }
            Ok(Err(err)) => {
                upstream.mark_failure();
                if metrics_enabled {
                    metrics::counter!("yxorp_requests_total", "result" => "upstream_error")
                        .increment(1);
                }
                error!(error = %err, upstream = upstream.config.name, route = route_match.route.name, "upstream request failed");
                Ok(text_response(
                    StatusCode::BAD_GATEWAY,
                    "upstream request failed\n",
                ))
            }
        }
    }
}

fn text_response(status: StatusCode, text: &'static str) -> Response<ProxyBody> {
    let body = Full::new(Bytes::from_static(text.as_bytes()))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body)
        .expect("static response is valid")
}

fn accept_worker_count(listener: &ListenerConfig) -> usize {
    if !listener.reuse_port {
        return 1;
    }
    if listener.accept_workers == 0 {
        return std::thread::available_parallelism().map_or(1, usize::from);
    }
    listener.accept_workers.max(1)
}

fn bind_listener_socket(listener: &ListenerConfig) -> io::Result<TcpListener> {
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
    socket.listen(listener.backlog)
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
    use crate::config::ConfigSnapshot;

    #[test]
    fn joins_upstream_base_path() {
        let config = r#"
            [[routes]]
            name = "root"
            host = "*"
            path_prefix = "/"
            upstream_pool = "web"

            [upstream_pools.web]
            [[upstream_pools.web.upstreams]]
            name = "web-a"
            url = "http://127.0.0.1:9000/base"
            protocol = "h1"
            weight = 1
        "#;
        let snapshot = ConfigSnapshot::parse(config, "inline").unwrap();
        let matched = snapshot.routes.match_route(None, "/api?q=1").unwrap();
        let upstream = matched.pool.select().unwrap();
        let uri = upstream.build_uri("/api?q=1").unwrap();
        assert_eq!(uri.to_string(), "http://127.0.0.1:9000/base/api?q=1");
    }
}
