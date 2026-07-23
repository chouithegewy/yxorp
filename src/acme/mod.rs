use std::path::PathBuf;

use serde::Serialize;

use crate::config::AcmeConfig;

#[derive(Debug, Clone, Serialize)]
pub struct AcmeState {
    pub enabled: bool,
    pub storage_dir: PathBuf,
    pub directory_url: String,
    pub http_01_ready: bool,
    pub tls_alpn_01_ready: bool,
}

impl AcmeState {
    pub fn from_config(config: &AcmeConfig) -> Self {
        Self {
            enabled: config.enabled,
            storage_dir: config.storage_dir.clone(),
            directory_url: config.directory_url.clone(),
            http_01_ready: config.enabled,
            tls_alpn_01_ready: config.enabled,
        }
    }
}
