use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::config::UpstreamState;

pub async fn check_upstream(upstream: Arc<UpstreamState>) {
    let config = &upstream.config.health_check;
    if !config.enabled {
        return;
    }

    let addr = match upstream.connect_addr() {
        Ok(addr) => addr,
        Err(_) => {
            upstream.set_active_healthy(false);
            return;
        }
    };

    let path = config.path.as_str();
    let authority = upstream.authority().as_str();

    // Simple HTTP/1.1 GET request byte buffer
    let request_bytes = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, authority
    );

    let check_future = async {
        let mut stream = TcpStream::connect(addr).await?;
        stream.write_all(request_bytes.as_bytes()).await?;

        let mut response_buf = [0u8; 128];
        let n = stream.read(&mut response_buf).await?;
        if n >= 12 && &response_buf[0..12] == b"HTTP/1.1 200" {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "upstream health check did not return HTTP 200 OK",
            ))
        }
    };

    match timeout(Duration::from_millis(config.timeout_ms), check_future).await {
        Ok(Ok(_)) => {
            upstream.set_active_healthy(true);
            upstream.mark_success();
            debug!(upstream = %upstream.config.name, "health check passed");
        }
        Ok(Err(e)) => {
            upstream.set_active_healthy(false);
            warn!(upstream = %upstream.config.name, error = %e, "health check failed");
        }
        Err(_) => {
            upstream.set_active_healthy(false);
            warn!(upstream = %upstream.config.name, "health check timed out");
        }
    }
}

pub struct HealthWorkerSet {
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl HealthWorkerSet {
    pub fn start(
        snapshot: Arc<arc_swap::ArcSwap<crate::config::ConfigSnapshot>>,
        parent_shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let current = snapshot.load();
        let upstreams = current.routes.all_upstreams();

        let mut handles = Vec::new();
        for upstream in upstreams {
            let config = upstream.config.health_check.clone();
            if !config.enabled {
                continue;
            }
            let mut rx = shutdown_rx.clone();
            let upstream_clone = Arc::clone(&upstream);

            handles.push(tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_millis(config.interval_ms));
                interval.tick().await; // Initial tick
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            check_upstream(Arc::clone(&upstream_clone)).await;
                        }
                        _ = rx.changed() => {
                            if *rx.borrow() { break; }
                        }
                    }
                }
            }));
        }

        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            let mut parent_shutdown = parent_shutdown;
            if parent_shutdown.changed().await.is_ok() && *parent_shutdown.borrow() {
                let _ = tx.send(true);
            }
        });

        Self {
            shutdown_tx,
            handles,
        }
    }

    pub async fn replace(
        &mut self,
        snapshot: Arc<arc_swap::ArcSwap<crate::config::ConfigSnapshot>>,
    ) {
        self.stop().await;
        let (_parent_tx, parent_rx) = tokio::sync::watch::channel(false);
        *self = Self::start(snapshot, parent_rx);
    }

    pub async fn stop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        for handle in self.handles.drain(..) {
            let _ = handle.await;
        }
    }
}
