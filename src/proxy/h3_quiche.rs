use arc_swap::ArcSwap;
use futures_util::StreamExt;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::watch;
use tokio_quiche::ServerH3Driver;
use tokio_quiche::metrics::DefaultMetrics;
use tracing::{Instrument, error, info};

use crate::config::{ConfigSnapshot, ListenerConfig};

/// Serve incoming HTTP/3 (QUIC) connections on the configured listener.
pub async fn serve_listener(
    snapshot: Arc<ArcSwap<ConfigSnapshot>>,
    listener: ListenerConfig,
    _tls_config: Option<Arc<rustls::ServerConfig>>, // Ignored, as QUIC uses BoringSSL
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    info!(listener = %listener.name, bind = %listener.bind, "starting HTTP/3 listener");

    // 1. Detect network interface and active MAC addresses for eBPF
    let iface = listener
        .interface
        .clone()
        .unwrap_or_else(|| super::ebpf::detect_interface(listener.bind.ip()));

    if let Err(err) = super::ebpf::init_ebpf(&iface) {
        error!(error = %err, interface = %iface, "failed to initialize/attach eBPF XDP program");
    } else {
        info!(interface = %iface, "eBPF XDP program active");
    }

    let local_mac = super::ebpf::get_interface_mac(&iface);

    // 2. Load certs and configure tokio-quiche server settings
    let snapshot_guard = snapshot.load();
    let cert_cfg = snapshot_guard.config.tls.certs.first().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "TLS/H3 enabled but no certificates configured in global tls config",
        )
    })?;

    let cert_path_str = cert_cfg.cert_path.to_string_lossy();
    let key_path_str = cert_cfg.key_path.to_string_lossy();

    let tls_cert = tokio_quiche::settings::TlsCertificatePaths {
        cert: &cert_path_str,
        private_key: &key_path_str,
        kind: tokio_quiche::settings::CertificateKind::X509,
    };

    let mut settings = tokio_quiche::settings::QuicSettings::default();
    settings.alpn = vec![b"h3".to_vec()];

    let params = tokio_quiche::ConnectionParams::new_server(
        settings,
        tls_cert,
        tokio_quiche::settings::Hooks::default(),
    );

    // 3. Bind UDP socket and start quic listener
    let socket = tokio::net::UdpSocket::bind(listener.bind).await?;
    let mut listeners = tokio_quiche::listen([socket], params, DefaultMetrics)?;
    let mut accept_stream = listeners.remove(0);

    info!(listener = %listener.name, "HTTP/3 socket listening");

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    info!(listener = %listener.name, "HTTP/3 listener shutting down");
                    return Ok(());
                }
            }
            conn_res = accept_stream.next() => {
                let Some(conn_res) = conn_res else {
                    break;
                } ;
                let conn = match conn_res {
                    Ok(c) => c,
                    Err(err) => {
                        error!(error = %err, "failed to accept QUIC connection");
                        continue;
                    }
                };

                let snapshot = Arc::clone(&snapshot);
                let local_mac = local_mac.clone();
                let peer_addr = conn.peer_addr();

                let connection_metrics_enabled = snapshot.load().config.telemetry.prometheus;
                if connection_metrics_enabled {
                    metrics::gauge!("yxorp_active_connections").increment(1.0);
                }

                let connection_span = tracing::info_span!("quic_connection", peer = %peer_addr);

                tokio::spawn(async move {
                    let (driver, mut controller) = ServerH3Driver::new(tokio_quiche::http3::settings::Http3Settings::default());
                    let qconn = conn.start(driver);
                    let scid = qconn.scid().to_vec();

                    info!("established HTTP/3 connection");

                    let event_receiver = controller.event_receiver_mut();
                    while let Some(event) = event_receiver.recv().await {
                        match event {
                            tokio_quiche::http3::driver::ServerH3Event::Headers {
                                incoming_headers,
                                ..
                            } => {
                                let snapshot = Arc::clone(&snapshot);
                                let scid = scid.clone();
                                let local_mac = local_mac.clone();
                                let peer_addr = peer_addr;
                                tokio::spawn(async move {
                                    if let Err(err) = handle_h3_request(incoming_headers, snapshot, &scid, local_mac, peer_addr).await {
                                        error!(error = %err, "failed to handle HTTP/3 request");
                                    }
                                });
                            }
                            _ => {}
                        }
                    }

                    // Connection closed, deregister from eBPF map
                    info!("HTTP/3 connection closed; removing eBPF route");
                    let _ = super::ebpf::deregister_quic_route(&scid);
                    if connection_metrics_enabled {
                        metrics::gauge!("yxorp_active_connections").decrement(1.0);
                    }
                }.instrument(connection_span));
            }
        }
    }

    Ok(())
}

async fn handle_h3_request(
    mut incoming_headers: tokio_quiche::http3::driver::IncomingH3Headers,
    snapshot: Arc<ArcSwap<ConfigSnapshot>>,
    scid: &[u8],
    local_mac: Option<[u8; 6]>,
    peer_addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::sink::SinkExt;
    use quiche::h3::NameValue;
    use tokio_quiche::http3::driver::OutboundFrame;

    // 1. Extract host, path, and method
    let mut host = None;
    let mut path = None;
    let mut method = "GET".to_string();

    for header in &incoming_headers.headers {
        let name = header.name();
        let value = header.value();
        if name == b":authority" {
            host = String::from_utf8(value.to_vec()).ok();
        } else if name == b":path" {
            path = String::from_utf8(value.to_vec()).ok();
        } else if name == b":method" {
            method = String::from_utf8(value.to_vec()).unwrap_or_else(|_| "GET".to_string());
        }
    }

    if !incoming_headers.read_fin
        || header_value(&incoming_headers.headers, b"content-length")
            .and_then(|value| std::str::from_utf8(value).ok())
            .and_then(|value| value.trim().parse::<usize>().ok())
            .is_some_and(|length| length > 0)
    {
        let response_headers = vec![
            quiche::h3::Header::new(b":status", b"413"),
            quiche::h3::Header::new(b"content-type", b"text/plain"),
        ];
        incoming_headers
            .send
            .send(OutboundFrame::Headers(response_headers, None))
            .await?;
        incoming_headers
            .send
            .send(OutboundFrame::Body(
                bytes::Bytes::from_static(b"HTTP/3 request bodies are not supported\n"),
                true,
            ))
            .await?;
        return Ok(());
    }

    let host_str = host.as_deref().map(|h| h.trim());
    let path_str = path.as_deref().unwrap_or("/");

    let snapshot_guard = snapshot.load();
    let metrics_enabled = snapshot_guard.config.telemetry.prometheus;
    let started = metrics_enabled.then(Instant::now);

    let request_span = tracing::info_span!(
        "h3_request",
        method = %method,
        host = host_str.unwrap_or(""),
        path = path_str
    );

    async move {
        let Some(route_match) = snapshot_guard.routes.match_route(host_str, path_str) else {
            if metrics_enabled {
                metrics::counter!("yxorp_requests_total", "result" => "no_route").increment(1);
            }
            let response_headers = vec![
                quiche::h3::Header::new(b":status", b"404"),
                quiche::h3::Header::new(b"content-type", b"text/plain"),
            ];
            let _ = incoming_headers.send.send(OutboundFrame::Headers(response_headers, None)).await;
            let _ = incoming_headers.send.send(OutboundFrame::Body(bytes::Bytes::from("no matching route\n"), true)).await;
            return Ok(());
        };
        if let Some(rate_limiter) = route_match.rate_limiter.as_deref()
            && !rate_limiter.acquire(peer_addr.ip())
        {
            if metrics_enabled {
                metrics::counter!("yxorp_requests_total", "result" => "rate_limited").increment(1);
            }
            let response_headers = vec![
                quiche::h3::Header::new(b":status", b"429"),
                quiche::h3::Header::new(b"content-type", b"text/plain"),
            ];
            incoming_headers.send.send(OutboundFrame::Headers(response_headers, None)).await?;
            incoming_headers
                .send
                .send(OutboundFrame::Body(
                    bytes::Bytes::from_static(b"rate limit exceeded\n"),
                    true,
                ))
                .await?;
            return Ok(());
        }

        let Some(upstream) = route_match.pool.select() else {
            if metrics_enabled {
                metrics::counter!("yxorp_requests_total", "result" => "no_upstream").increment(1);
            }
            let response_headers = vec![
                quiche::h3::Header::new(b":status", b"502"),
                quiche::h3::Header::new(b"content-type", b"text/plain"),
            ];
            let _ = incoming_headers.send.send(OutboundFrame::Headers(response_headers, None)).await;
            let _ = incoming_headers.send.send(OutboundFrame::Body(bytes::Bytes::from("no available upstream\n"), true)).await;
            return Ok(());
        };

        // 2. Non-blocking Async DNS & eBPF Map registration optimization
        let ebpf_start = Instant::now();
        let url: http::Uri = upstream.config.url.parse()?;
        let upstream_host = url.host().unwrap_or("127.0.0.1");
        let upstream_port = url.port_u16().unwrap_or(80);

        let resolved_addr = if let Ok(ip) = upstream_host.parse::<std::net::Ipv4Addr>() {
            Some(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, upstream_port)))
        } else {
            // Avoid blocking Tokio executor threads - spawn blocking DNS resolve
            let host_to_resolve = upstream_host.to_string();
            let port_to_resolve = upstream_port;
            tokio::task::spawn_blocking(move || {
                use std::net::ToSocketAddrs;
                (host_to_resolve.as_str(), port_to_resolve)
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut addrs| addrs.find(|a| a.is_ipv4()))
            })
            .await
            .ok()
            .flatten()
        };

        if let Some(std::net::SocketAddr::V4(addr)) = resolved_addr {
            let dst_ip = u32::from(*addr.ip()).to_be();
            let dst_port = addr.port().to_be();

            // Measure latency of dynamic ARP MAC lookup
            let arp_start = Instant::now();
            let dst_mac = super::ebpf::get_arp_mac(std::net::IpAddr::V4(*addr.ip()));
            if metrics_enabled {
                metrics::histogram!("yxorp_arp_lookup_duration_seconds")
                    .record(arp_start.elapsed().as_secs_f64());
            }

            if let (Some(dst_mac), Some(src_mac)) = (dst_mac, local_mac) {
                let route = super::ebpf::QuicRoute {
                    dst_ip,
                    dst_port,
                    dst_mac,
                    src_mac,
                };

                let reg_start = Instant::now();
                let _ = super::ebpf::register_quic_route(scid, route);
                if metrics_enabled {
                    metrics::histogram!("yxorp_ebpf_registration_duration_seconds")
                        .record(reg_start.elapsed().as_secs_f64());
                }
            } else {
                tracing::warn!(
                    upstream = %upstream.config.name,
                    "skipping eBPF QUIC route registration because a real source or destination MAC was not available"
                );
            }
        }

        if metrics_enabled {
            metrics::histogram!("yxorp_h3_ebpf_total_setup_duration_seconds")
                .record(ebpf_start.elapsed().as_secs_f64());
        }

        // 3. Forward request to upstream in user-space
        let upstream_uri = upstream.build_uri(path_str)?;

        let mut req_builder = http::Request::builder()
            .method(method.as_str())
            .uri(upstream_uri);

        for header in &incoming_headers.headers {
            let name = header.name();
            let value = header.value();
            if !name.starts_with(b":") {
                if let (Ok(h_name), Ok(h_val)) = (
                    http::header::HeaderName::from_bytes(name),
                    http::header::HeaderValue::from_bytes(value),
                ) {
                    req_builder = req_builder.header(h_name, h_val);
                }
            }
        }

        let connector = hyper_util::client::legacy::connect::HttpConnector::new();
        let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector);

        let req = req_builder.body(http_body_util::Full::new(bytes::Bytes::new()))?;
        let proxy_start = Instant::now();
        let res_res = tokio::time::timeout(
            std::time::Duration::from_millis(upstream.config.request_timeout_ms),
            client.request(req),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream request timed out")
        })?;

        let res = match res_res {
            Ok(r) => {
                upstream.mark_success();
                r
            }
            Err(err) => {
                upstream.mark_failure();
                if metrics_enabled {
                    metrics::counter!("yxorp_requests_total", "result" => "upstream_error").increment(1);
                }
                return Err(err.into());
            }
        };

        if metrics_enabled {
            metrics::histogram!("yxorp_h3_upstream_proxy_duration_seconds")
                .record(proxy_start.elapsed().as_secs_f64());
        }

        let (parts, mut body) = res.into_parts();

        // 4. Construct response headers
        let mut resp_headers = vec![
            quiche::h3::Header::new(b":status", parts.status.as_str().as_bytes()),
        ];
        for (name, value) in parts.headers.iter() {
            resp_headers.push(quiche::h3::Header::new(name.as_str().as_bytes(), value.as_bytes()));
        }

        incoming_headers.send.send(OutboundFrame::Headers(resp_headers, None)).await?;

        // 5. Stream response body
        use http_body_util::BodyExt;
        while let Some(frame_res) = body.frame().await {
            if let Ok(frame) = frame_res {
                if let Some(data) = frame.data_ref() {
                    incoming_headers.send.send(OutboundFrame::Body(data.clone(), false)).await?;
                }
            }
        }

        // Send FIN frame
        incoming_headers.send.send(OutboundFrame::Body(bytes::Bytes::new(), true)).await?;

        if metrics_enabled {
            metrics::counter!("yxorp_requests_total", "result" => "proxied").increment(1);
            if let Some(started) = started {
                metrics::histogram!("yxorp_request_duration_seconds")
                    .record(started.elapsed().as_secs_f64());
            }
        }

        Ok(())
    }.instrument(request_span).await
}

fn header_value<'a>(headers: &'a [quiche::h3::Header], name: &[u8]) -> Option<&'a [u8]> {
    use quiche::h3::NameValue;
    headers
        .iter()
        .find(|header| header.name().eq_ignore_ascii_case(name))
        .map(|header| header.value())
}
