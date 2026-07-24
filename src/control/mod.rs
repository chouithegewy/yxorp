use std::path::PathBuf;
use std::sync::Arc;

use actix::prelude::*;
use arc_swap::ArcSwap;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::admin::{AdminCommand, AdminRuntime};
use crate::config::{ConfigSnapshot, ListenerConfig};
use crate::l4::{L4Reconciler, L4State};
use crate::proxy::{ConnectionTracker, ProxyRuntime};
use crate::telemetry;

mod health;

pub struct Supervisor;

impl Supervisor {
    pub async fn run(
        config_path: PathBuf,
        initial: Arc<ConfigSnapshot>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _config_manager = ConfigManager.start();
        let _cert_manager = CertManager.start();
        let _metrics_reporter = MetricsReporter.start();
        let _listener_manager = ListenerManager.start();

        let snapshot = Arc::new(ArcSwap::from(initial));
        L4Reconciler::preflight(&snapshot.load().config)?;
        L4Reconciler::apply(&[], &snapshot.load().config.l4_services)?;
        let mut l4_state = L4State::new(&snapshot.load().config);
        let metrics = if snapshot.load().config.telemetry.prometheus {
            Some(telemetry::install_prometheus()?)
        } else {
            None
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut listeners = ListenerSet::start(Arc::clone(&snapshot), shutdown_rx.clone());
        let mut health_workers =
            health::HealthWorkerSet::start(Arc::clone(&snapshot), shutdown_rx.clone());
        let (command_tx, mut command_rx) = mpsc::channel(16);

        if snapshot.load().config.admin.enabled {
            let admin = AdminRuntime::new(Arc::clone(&snapshot), command_tx, metrics);
            let admin_shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                if let Err(err) = admin.serve(admin_shutdown).await {
                    error!(error = %err, "admin listener stopped");
                }
            });
        }

        info!("yxorp supervisor started");
        loop {
            tokio::select! {
                command = command_rx.recv() => {
                    match command {
                        Some(AdminCommand::Reload { reply }) => {
                            let result = reload(&config_path, Arc::clone(&snapshot), &mut listeners, &mut health_workers, &mut l4_state).await;
                            let _ = reply.send(result);
                        }
                        Some(AdminCommand::Drain { reply }) => {
                            let _ = shutdown_tx.send(true);
                            listeners.stop().await;
                            listeners.wait_for_drain(snapshot.load().config.runtime.drain_timeout()).await;
                            health_workers.stop().await;
                            if let Err(err) = L4Reconciler::apply(l4_state.services(), &[]) {
                                error!(error = %err, "failed to remove l4 ipvs services while draining");
                            }
                            let _ = reply.send(Ok("draining".to_string()));
                            break;
                        }
                        None => break,
                    }
                }
                signal = tokio::signal::ctrl_c() => {
                    signal?;
                    info!("shutdown signal received");
                    let _ = shutdown_tx.send(true);
                    listeners.stop().await;
                    listeners.wait_for_drain(snapshot.load().config.runtime.drain_timeout()).await;
                    health_workers.stop().await;
                    if let Err(err) = L4Reconciler::apply(l4_state.services(), &[]) {
                        error!(error = %err, "failed to remove l4 ipvs services during shutdown");
                    }
                    break;
                }
            }
        }

        Ok(())
    }
}

async fn reload(
    config_path: &PathBuf,
    snapshot: Arc<ArcSwap<ConfigSnapshot>>,
    listeners: &mut ListenerSet,
    health_workers: &mut health::HealthWorkerSet,
    l4_state: &mut L4State,
) -> Result<String, String> {
    let next = Arc::new(ConfigSnapshot::load(config_path).map_err(|err| err.to_string())?);
    let current = snapshot.load_full();
    let listeners_changed = !same_listener_shape(&current.config.listeners, &next.config.listeners);
    L4Reconciler::preflight(&next.config).map_err(|err| err.to_string())?;
    L4Reconciler::apply(l4_state.services(), &next.config.l4_services)
        .map_err(|err| err.to_string())?;
    *l4_state = L4State::new(&next.config);
    snapshot.store(next);
    metrics::counter!("yxorp_reloads_total", "result" => "success").increment(1);

    if listeners_changed {
        warn!("listener shape changed; restarting listener tasks");
        listeners.replace(Arc::clone(&snapshot)).await;
    }
    health_workers.replace(Arc::clone(&snapshot)).await;

    Ok("reloaded".to_string())
}

fn same_listener_shape(a: &[ListenerConfig], b: &[ListenerConfig]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(left, right)| {
            left.name == right.name
                && left.bind == right.bind
                && left.protocols == right.protocols
                && left.http1_engine == right.http1_engine
                && left.tls == right.tls
                && left.reuse_port == right.reuse_port
                && left.accept_workers == right.accept_workers
                && left.backlog == right.backlog
                && left.interface == right.interface
        })
}

struct ListenerSet {
    shutdown_tx: watch::Sender<bool>,
    handles: Vec<JoinHandle<()>>,
    connections: Vec<Arc<ConnectionTracker>>,
}

impl ListenerSet {
    fn start(
        snapshot: Arc<ArcSwap<ConfigSnapshot>>,
        parent_shutdown: watch::Receiver<bool>,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut handles = Vec::new();
        let mut connections = Vec::new();
        for listener in snapshot.load().config.listeners.clone() {
            let runtime = ProxyRuntime::new(Arc::clone(&snapshot));
            connections.push(runtime.connection_tracker());
            let listener_shutdown = shutdown_rx.clone();
            handles.push(tokio::spawn(async move {
                if let Err(err) = runtime.serve_listener(listener, listener_shutdown).await {
                    error!(error = %err, "proxy listener stopped");
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
            connections,
        }
    }

    async fn replace(&mut self, snapshot: Arc<ArcSwap<ConfigSnapshot>>) {
        self.stop().await;
        let (_parent_tx, parent_rx) = watch::channel(false);
        *self = Self::start(snapshot, parent_rx);
    }

    async fn stop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        for handle in self.handles.drain(..) {
            let _ = handle.await;
        }
    }

    async fn wait_for_drain(&self, timeout: tokio::time::Duration) {
        let waiters = self.connections.iter().map(|tracker| tracker.wait());
        let _ = tokio::time::timeout(timeout, futures_util::future::join_all(waiters)).await;
    }
}

pub struct ConfigManager;
impl Actor for ConfigManager {
    type Context = Context<Self>;
}

pub struct ListenerManager;
impl Actor for ListenerManager {
    type Context = Context<Self>;
}

pub struct CertManager;
impl Actor for CertManager {
    type Context = Context<Self>;
}

pub struct MetricsReporter;
impl Actor for MetricsReporter {
    type Context = Context<Self>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Http1Engine, ListenerConfig, ListenerProtocol};

    #[test]
    fn detects_listener_shape_changes() {
        let base = ListenerConfig::default();
        let mut changed = base.clone();
        changed.protocols = vec![
            ListenerProtocol::H1,
            ListenerProtocol::H2,
            ListenerProtocol::H3,
        ];
        let mut changed_socket_options = base.clone();
        changed_socket_options.reuse_port = true;
        changed_socket_options.accept_workers = 2;
        let mut changed_engine = base.clone();
        changed_engine.protocols = vec![ListenerProtocol::H1];
        changed_engine.http1_engine = Http1Engine::Fast;

        assert!(same_listener_shape(
            std::slice::from_ref(&base),
            &[base.clone()]
        ));
        assert!(!same_listener_shape(
            &[ListenerConfig::default()],
            &[changed]
        ));
        assert!(!same_listener_shape(
            &[ListenerConfig::default()],
            &[changed_socket_options]
        ));
        assert!(!same_listener_shape(
            &[ListenerConfig::default()],
            &[changed_engine]
        ));
    }
}
