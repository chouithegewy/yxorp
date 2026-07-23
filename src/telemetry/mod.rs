use std::sync::OnceLock;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing_subscriber::EnvFilter;

static PROMETHEUS: OnceLock<PrometheusHandle> = OnceLock::new();

pub fn init_tracing(json: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if json {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    }
}

pub fn install_prometheus() -> Result<PrometheusHandle, metrics_exporter_prometheus::BuildError> {
    if let Some(handle) = PROMETHEUS.get() {
        return Ok(handle.clone());
    }
    let handle = PrometheusBuilder::new().install_recorder()?;
    let _ = PROMETHEUS.set(handle.clone());
    Ok(handle)
}

pub fn prometheus_handle() -> Option<PrometheusHandle> {
    PROMETHEUS.get().cloned()
}
