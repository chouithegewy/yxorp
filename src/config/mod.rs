use std::collections::{BTreeMap, HashSet};
use std::net::ToSocketAddrs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use http::{
    HeaderValue, Uri,
    uri::{Authority, Scheme},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_UPSTREAM_WEIGHT: u32 = 10_000;
const MAX_TOTAL_POOL_WEIGHT: u64 = 100_000;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse TOML config {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("invalid config: {0}")]
    Validation(String),
}

#[derive(Debug, Clone)]
pub struct ConfigSnapshot {
    pub config: ProxyConfig,
    pub routes: Arc<RouteTable>,
}

impl ConfigSnapshot {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text, path)
    }

    pub fn parse(text: &str, path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let config: ProxyConfig = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        config.validate()?;
        let routes = Arc::new(RouteTable::new(&config)?);
        Ok(Self { config, routes })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    pub listeners: Vec<ListenerConfig>,
    pub l4_services: Vec<L4ServiceConfig>,
    pub tls: TlsConfig,
    pub routes: Vec<RouteConfig>,
    pub upstream_pools: BTreeMap<String, UpstreamPoolConfig>,
    pub admin: AdminConfig,
    pub telemetry: TelemetryConfig,
    pub runtime: RuntimeConfig,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listeners: vec![ListenerConfig::default()],
            l4_services: Vec::new(),
            tls: TlsConfig::default(),
            routes: Vec::new(),
            upstream_pools: BTreeMap::new(),
            admin: AdminConfig::default(),
            telemetry: TelemetryConfig::default(),
            runtime: RuntimeConfig::default(),
        }
    }
}

impl ProxyConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listeners.is_empty() && self.l4_services.is_empty() {
            return Err(ConfigError::Validation(
                "at least one listener or l4_service must be configured".to_string(),
            ));
        }
        if !self.listeners.is_empty() && self.routes.is_empty() {
            return Err(ConfigError::Validation(
                "at least one route must be configured when listeners are configured".to_string(),
            ));
        }

        let mut listener_ids = HashSet::new();
        for listener in &self.listeners {
            if !listener_ids.insert(listener.name.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate listener name '{}'",
                    listener.name
                )));
            }
            if listener.protocols.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "listener '{}' must enable at least one protocol",
                    listener.name
                )));
            }
            if matches!(
                listener.http1_engine,
                Http1Engine::Fast | Http1Engine::Uring
            ) {
                if listener.tls {
                    return Err(ConfigError::Validation(format!(
                        "listener '{}' http1_engine = {} requires tls = false",
                        listener.name, listener.http1_engine
                    )));
                }
                if listener.protocols != [ListenerProtocol::H1] {
                    return Err(ConfigError::Validation(format!(
                        "listener '{}' http1_engine = {} requires protocols = [\"h1\"]",
                        listener.name, listener.http1_engine
                    )));
                }
            }
            if listener.accept_workers > 1 && !listener.reuse_port {
                return Err(ConfigError::Validation(format!(
                    "listener '{}' must enable reuse_port when accept_workers > 1",
                    listener.name
                )));
            }
            if listener.backlog == 0 {
                return Err(ConfigError::Validation(format!(
                    "listener '{}' backlog must be > 0",
                    listener.name
                )));
            }
        }

        let mut l4_service_ids = HashSet::new();
        let mut l4_vips = HashSet::new();
        for service in &self.l4_services {
            if !l4_service_ids.insert(service.name.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate l4_service name '{}'",
                    service.name
                )));
            }
            if service.domains.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "l4_service '{}' must list at least one domain",
                    service.name
                )));
            }
            if service.port == 0 {
                return Err(ConfigError::Validation(format!(
                    "l4_service '{}' port must be > 0",
                    service.name
                )));
            }
            if !l4_vips.insert((service.vip, service.port, service.protocol)) {
                return Err(ConfigError::Validation(format!(
                    "duplicate l4_service vip/port/protocol '{}:{} {}'",
                    service.vip, service.port, service.protocol
                )));
            }
            for listener in &self.listeners {
                if listener.bind.ip() == service.vip && listener.bind.port() == service.port {
                    return Err(ConfigError::Validation(format!(
                        "l4_service '{}' conflicts with listener '{}' on {}:{}",
                        service.name, listener.name, service.vip, service.port
                    )));
                }
            }
            if service.real_servers.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "l4_service '{}' must contain at least one real_server",
                    service.name
                )));
            }
            for real_server in &service.real_servers {
                if real_server.port == 0 {
                    return Err(ConfigError::Validation(format!(
                        "real_server '{}:{}' in l4_service '{}' port must be > 0",
                        real_server.address, real_server.port, service.name
                    )));
                }
                if real_server.weight == 0 {
                    return Err(ConfigError::Validation(format!(
                        "real_server '{}:{}' in l4_service '{}' weight must be > 0",
                        real_server.address, real_server.port, service.name
                    )));
                }
            }
        }

        let mut route_ids = HashSet::new();
        for route in &self.routes {
            if !route_ids.insert(route.name.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate route name '{}'",
                    route.name
                )));
            }
            if !route.path_prefix.starts_with('/') {
                return Err(ConfigError::Validation(format!(
                    "route '{}' path_prefix must start with /",
                    route.name
                )));
            }
            if route.host != "*" && parse_authority_host(&route.host).is_none() {
                return Err(ConfigError::Validation(format!(
                    "route '{}' host '{}' must be a valid HTTP authority host",
                    route.name, route.host
                )));
            }
            if !self.upstream_pools.contains_key(&route.upstream_pool) {
                return Err(ConfigError::Validation(format!(
                    "route '{}' references missing upstream_pool '{}'",
                    route.name, route.upstream_pool
                )));
            }
            if route.rate_limit.enabled && route.rate_limit.capacity == 0 {
                return Err(ConfigError::Validation(format!(
                    "route '{}' rate_limit capacity must be > 0",
                    route.name
                )));
            }
            if route.rate_limit.enabled
                && (!route.rate_limit.fill_rate.is_finite() || route.rate_limit.fill_rate <= 0.0)
            {
                return Err(ConfigError::Validation(format!(
                    "route '{}' rate_limit fill_rate must be finite and > 0",
                    route.name
                )));
            }
        }

        for (pool_name, pool) in &self.upstream_pools {
            if pool.upstreams.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "upstream pool '{pool_name}' must contain at least one upstream"
                )));
            }
            let mut total_weight = 0_u64;
            for upstream in &pool.upstreams {
                if upstream.weight == 0 {
                    return Err(ConfigError::Validation(format!(
                        "upstream '{}' in pool '{pool_name}' must have weight > 0",
                        upstream.name
                    )));
                }
                if upstream.weight > MAX_UPSTREAM_WEIGHT {
                    return Err(ConfigError::Validation(format!(
                        "upstream '{}' in pool '{pool_name}' weight must be <= {MAX_UPSTREAM_WEIGHT}",
                        upstream.name
                    )));
                }
                total_weight += u64::from(upstream.weight);
                let uri: Uri = upstream.url.parse().map_err(|_| {
                    ConfigError::Validation(format!(
                        "upstream '{}' in pool '{pool_name}' has invalid url '{}'",
                        upstream.name, upstream.url
                    ))
                })?;
                if uri.scheme().is_none() || uri.authority().is_none() {
                    return Err(ConfigError::Validation(format!(
                        "upstream '{}' in pool '{pool_name}' url must include scheme and authority",
                        upstream.name
                    )));
                }
                if uri.scheme() != Some(&Scheme::HTTP) {
                    return Err(ConfigError::Validation(format!(
                        "upstream '{}' in pool '{pool_name}' url scheme must be http until upstream TLS is implemented",
                        upstream.name
                    )));
                }
                if upstream.protocol == UpstreamProtocol::H3 && !upstream.opt_in_h3 {
                    return Err(ConfigError::Validation(format!(
                        "upstream '{}' uses protocol h3 but opt_in_h3 is not true",
                        upstream.name
                    )));
                }
            }
            if total_weight > MAX_TOTAL_POOL_WEIGHT {
                return Err(ConfigError::Validation(format!(
                    "upstream pool '{pool_name}' total weight must be <= {MAX_TOTAL_POOL_WEIGHT}"
                )));
            }
        }

        if let Some(token) = &self.admin.auth_token
            && token.is_empty()
        {
            return Err(ConfigError::Validation(
                "admin auth_token must not be empty when configured".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ListenerConfig {
    pub name: String,
    pub bind: SocketAddr,
    pub protocols: Vec<ListenerProtocol>,
    pub http1_engine: Http1Engine,
    pub tls: bool,
    pub reuse_port: bool,
    pub accept_workers: usize,
    pub backlog: u32,
    pub interface: Option<String>,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            name: "public".to_string(),
            bind: "127.0.0.1:8080".parse().expect("valid default bind"),
            protocols: vec![ListenerProtocol::H1, ListenerProtocol::H2],
            http1_engine: Http1Engine::Hyper,
            tls: false,
            reuse_port: false,
            accept_workers: 1,
            backlog: 4096,
            interface: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ListenerProtocol {
    H1,
    H2,
    H3,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Http1Engine {
    Hyper,
    Fast,
    Uring,
}

impl Default for Http1Engine {
    fn default() -> Self {
        Self::Hyper
    }
}

impl std::fmt::Display for Http1Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hyper => f.write_str("hyper"),
            Self::Fast => f.write_str("fast"),
            Self::Uring => f.write_str("uring"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct L4ServiceConfig {
    pub name: String,
    pub domains: Vec<String>,
    pub vip: IpAddr,
    pub port: u16,
    pub protocol: L4Protocol,
    pub scheduler: L4Scheduler,
    pub mode: L4Mode,
    pub real_servers: Vec<L4RealServerConfig>,
    pub health_check: L4HealthCheckConfig,
}

impl Default for L4ServiceConfig {
    fn default() -> Self {
        Self {
            name: "l4-service".to_string(),
            domains: Vec::new(),
            vip: "127.0.0.1".parse().expect("valid default vip"),
            port: 80,
            protocol: L4Protocol::Tcp,
            scheduler: L4Scheduler::Wrr,
            mode: L4Mode::IpvsDsr,
            real_servers: Vec::new(),
            health_check: L4HealthCheckConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum L4Protocol {
    Tcp,
    Udp,
}

impl Default for L4Protocol {
    fn default() -> Self {
        Self::Tcp
    }
}

impl std::fmt::Display for L4Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => f.write_str("tcp"),
            Self::Udp => f.write_str("udp"),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum L4Scheduler {
    Rr,
    Wrr,
    Sh,
}

impl Default for L4Scheduler {
    fn default() -> Self {
        Self::Wrr
    }
}

impl std::fmt::Display for L4Scheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rr => f.write_str("rr"),
            Self::Wrr => f.write_str("wrr"),
            Self::Sh => f.write_str("sh"),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum L4Mode {
    IpvsDsr,
}

impl Default for L4Mode {
    fn default() -> Self {
        Self::IpvsDsr
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct L4RealServerConfig {
    pub address: IpAddr,
    pub port: u16,
    pub weight: u32,
}

impl Default for L4RealServerConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1".parse().expect("valid default real server"),
            port: 80,
            weight: 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct L4HealthCheckConfig {
    pub enabled: bool,
    pub kind: L4HealthCheckKind,
    pub path: String,
    pub interval_ms: u64,
    pub timeout_ms: u64,
}

impl Default for L4HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            kind: L4HealthCheckKind::Tcp,
            path: "/healthz".to_string(),
            interval_ms: 10_000,
            timeout_ms: 2_000,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum L4HealthCheckKind {
    Tcp,
    Http,
}

impl Default for L4HealthCheckKind {
    fn default() -> Self {
        Self::Tcp
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    pub acme: AcmeConfig,
    pub certs: Vec<CertConfig>,
    pub keylog: bool,
    pub qlog_dir: Option<PathBuf>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            acme: AcmeConfig::default(),
            certs: Vec::new(),
            keylog: false,
            qlog_dir: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AcmeConfig {
    pub enabled: bool,
    pub directory_url: String,
    pub contact: Vec<String>,
    pub storage_dir: PathBuf,
    pub renew_before_days: u64,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
            contact: Vec::new(),
            storage_dir: PathBuf::from("/var/lib/yxorp/acme"),
            renew_before_days: 30,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CertConfig {
    pub domains: Vec<String>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl Default for CertConfig {
    fn default() -> Self {
        Self {
            domains: Vec::new(),
            cert_path: PathBuf::new(),
            key_path: PathBuf::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub capacity: u32,
    pub fill_rate: f32, // tokens per second
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            capacity: 100,
            fill_rate: 10.0,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RouteConfig {
    pub name: String,
    pub host: String,
    pub path_prefix: String,
    pub upstream_pool: String,
    pub rate_limit: RateLimitConfig,
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            host: "*".to_string(),
            path_prefix: "/".to_string(),
            upstream_pool: "default".to_string(),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamPoolConfig {
    pub upstreams: Vec<UpstreamConfig>,
    pub passive_failure_threshold: u32,
}

impl Default for UpstreamPoolConfig {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            passive_failure_threshold: 3,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamConfig {
    pub name: String,
    pub url: String,
    pub protocol: UpstreamProtocol,
    pub opt_in_h3: bool,
    pub weight: u32,
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub health_check: HealthCheckConfig,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            name: "upstream".to_string(),
            url: "http://127.0.0.1:8081".to_string(),
            protocol: UpstreamProtocol::H1,
            opt_in_h3: false,
            weight: 1,
            connect_timeout_ms: 2_000,
            request_timeout_ms: 30_000,
            health_check: HealthCheckConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    H1,
    H2,
    H3,
}

impl Default for UpstreamProtocol {
    fn default() -> Self {
        Self::H1
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub path: String,
    pub interval_ms: u64,
    pub timeout_ms: u64,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "/healthz".to_string(),
            interval_ms: 10_000,
            timeout_ms: 2_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    pub bind: SocketAddr,
    pub enabled: bool,
    pub auth_token: Option<String>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:9080".parse().expect("valid default admin bind"),
            enabled: true,
            auth_token: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    pub json_tracing: bool,
    pub prometheus: bool,
    pub access_log: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            json_tracing: false,
            prometheus: true,
            access_log: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    pub drain_timeout_ms: u64,
    pub zero_copy: bool,
    pub liveness_probe_idle_ms: u64,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            drain_timeout_ms: 30_000,
            zero_copy: true,
            liveness_probe_idle_ms: 250,
        }
    }
}

impl RuntimeConfig {
    pub fn drain_timeout(&self) -> Duration {
        Duration::from_millis(self.drain_timeout_ms)
    }

    pub fn liveness_probe_idle(&self) -> Duration {
        Duration::from_millis(self.liveness_probe_idle_ms)
    }
}

#[derive(Debug)]
pub struct RouteTable {
    routes: Vec<CompiledRoute>,
    host_routes: BTreeMap<String, Vec<CompiledRoute>>,
    wildcard_routes: Vec<CompiledRoute>,
    single_wildcard_root: bool,
    requires_host_match: bool,
}

impl RouteTable {
    pub fn new(config: &ProxyConfig) -> Result<Self, ConfigError> {
        let mut pools = BTreeMap::new();
        for (name, pool) in &config.upstream_pools {
            pools.insert(name.clone(), Arc::new(UpstreamPool::new(pool)));
        }

        let mut routes = config
            .routes
            .iter()
            .cloned()
            .map(|route| {
                let pool = pools.get(&route.upstream_pool).ok_or_else(|| {
                    ConfigError::Validation(format!(
                        "route '{}' references missing upstream_pool '{}'",
                        route.name, route.upstream_pool
                    ))
                })?;
                let rate_limiter = if route.rate_limit.enabled {
                    Some(Arc::new(RateLimiter::new(
                        route.rate_limit.capacity,
                        route.rate_limit.fill_rate,
                    )))
                } else {
                    None
                };

                Ok(CompiledRoute {
                    route,
                    pool: Arc::clone(pool),
                    rate_limiter,
                })
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;
        routes.sort_by(|a, b| b.route.path_prefix.len().cmp(&a.route.path_prefix.len()));

        let mut host_routes: BTreeMap<String, Vec<CompiledRoute>> = BTreeMap::new();
        let mut wildcard_routes = Vec::new();

        for compiled in &routes {
            if compiled.route.host == "*" {
                wildcard_routes.push(compiled.clone());
            } else {
                let key = parse_authority_host(&compiled.route.host).expect("validated route host");
                host_routes.entry(key).or_default().push(compiled.clone());
            }
        }

        let single_wildcard_root =
            routes.len() == 1 && routes[0].route.host == "*" && routes[0].route.path_prefix == "/";
        let requires_host_match = routes.iter().any(|route| route.route.host != "*");

        Ok(Self {
            routes,
            host_routes,
            wildcard_routes,
            single_wildcard_root,
            requires_host_match,
        })
    }

    pub fn requires_host_match(&self) -> bool {
        self.requires_host_match
    }

    pub fn all_upstreams(&self) -> Vec<Arc<UpstreamState>> {
        let mut upstreams = Vec::new();
        for route in &self.routes {
            for upstream in route.pool.upstreams() {
                upstreams.push(Arc::clone(upstream));
            }
        }
        upstreams.sort_by_key(|u| Arc::as_ptr(u));
        upstreams.dedup_by_key(|u| Arc::as_ptr(u));
        upstreams
    }

    pub fn match_route(&self, host: Option<&str>, path: &str) -> Option<RouteMatch<'_>> {
        if self.single_wildcard_root {
            let compiled = &self.routes[0];
            return Some(RouteMatch {
                route: &compiled.route,
                pool: &compiled.pool,
                rate_limiter: compiled.rate_limiter.clone(),
            });
        }

        if let Some(host_str) = host {
            let cleaned_host = parse_authority_host(host_str)?;

            // 1. Try exact match lookup first to achieve zero-allocation matching for lowercase hosts
            if let Some(host_specific_routes) = self.host_routes.get(cleaned_host.as_str()) {
                for compiled in host_specific_routes {
                    if path_matches_prefix(path, &compiled.route.path_prefix) {
                        return Some(RouteMatch {
                            route: &compiled.route,
                            pool: &compiled.pool,
                            rate_limiter: compiled.rate_limiter.clone(),
                        });
                    }
                }
            }
        }

        // Fallback to wildcard host routes
        for compiled in &self.wildcard_routes {
            if path_matches_prefix(path, &compiled.route.path_prefix) {
                return Some(RouteMatch {
                    route: &compiled.route,
                    pool: &compiled.pool,
                    rate_limiter: compiled.rate_limiter.clone(),
                });
            }
        }

        None
    }

    pub fn debug_routes(&self) -> Vec<RouteConfig> {
        self.routes
            .iter()
            .map(|route| route.route.clone())
            .collect()
    }
}

use crate::proxy::rate_limit::RateLimiter;

#[derive(Debug, Clone)]
pub struct CompiledRoute {
    pub route: RouteConfig,
    pub pool: Arc<UpstreamPool>,
    pub rate_limiter: Option<Arc<RateLimiter>>,
}

#[derive(Debug)]
pub struct RouteMatch<'a> {
    pub route: &'a RouteConfig,
    pub pool: &'a UpstreamPool,
    pub rate_limiter: Option<Arc<RateLimiter>>,
}

#[derive(Debug)]
pub struct UpstreamPool {
    upstreams: Vec<Arc<UpstreamState>>,
    expanded: Vec<usize>,
    cursor: AtomicUsize,
    passive_failure_threshold: u32,
}

impl UpstreamPool {
    fn new(config: &UpstreamPoolConfig) -> Self {
        let upstreams = config
            .upstreams
            .iter()
            .cloned()
            .map(|config| Arc::new(UpstreamState::new(config)))
            .collect::<Vec<_>>();
        let expanded = upstreams
            .iter()
            .enumerate()
            .flat_map(|(idx, upstream)| std::iter::repeat_n(idx, upstream.config.weight as usize))
            .collect();
        Self {
            upstreams,
            expanded,
            cursor: AtomicUsize::new(0),
            passive_failure_threshold: config.passive_failure_threshold,
        }
    }

    pub fn upstreams(&self) -> &[Arc<UpstreamState>] {
        &self.upstreams
    }

    pub fn select(&self) -> Option<&UpstreamState> {
        if self.expanded.is_empty() {
            return None;
        }
        if self.upstreams.len() == 1 {
            return Some(self.upstreams[0].as_ref());
        }
        for _ in 0..self.expanded.len() {
            let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % self.expanded.len();
            let upstream = self.upstreams[self.expanded[idx]].as_ref();
            if upstream.is_available(self.passive_failure_threshold) {
                return Some(upstream);
            }
        }
        Some(self.upstreams[self.expanded[0]].as_ref())
    }

    pub fn select_arc(&self) -> Option<Arc<UpstreamState>> {
        if self.expanded.is_empty() {
            return None;
        }
        if self.upstreams.len() == 1 {
            return Some(Arc::clone(&self.upstreams[0]));
        }
        for _ in 0..self.expanded.len() {
            let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % self.expanded.len();
            let upstream = Arc::clone(&self.upstreams[self.expanded[idx]]);
            if upstream.is_available(self.passive_failure_threshold) {
                return Some(upstream);
            }
        }
        Some(Arc::clone(&self.upstreams[self.expanded[0]]))
    }
}

/// Process-global monotonic source of stable per-upstream ids. Used to key the
/// fast engine's connection pool without hashing the authority string per request.
static NEXT_UPSTREAM_ID: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
pub struct UpstreamState {
    pub config: UpstreamConfig,
    uri_base: UpstreamUriBase,
    id: usize,
    connect_addr: OnceLock<SocketAddr>,
    passive_failures: AtomicUsize,
    active_healthy: std::sync::atomic::AtomicBool,
}

impl UpstreamState {
    fn new(config: UpstreamConfig) -> Self {
        let uri_base = UpstreamUriBase::parse(&config.url).expect("validated upstream URL");
        Self {
            config,
            uri_base,
            id: NEXT_UPSTREAM_ID.fetch_add(1, Ordering::Relaxed),
            connect_addr: OnceLock::new(),
            passive_failures: AtomicUsize::new(0),
            active_healthy: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Stable, process-unique id assigned at construction. Cheap integer key for
    /// the fast connection pool.
    pub fn id(&self) -> usize {
        self.id
    }

    pub fn build_uri(&self, path_and_query: &str) -> Result<Uri, http::Error> {
        self.uri_base.build_uri(path_and_query)
    }

    pub fn upstream_path_and_query<'a>(
        &self,
        path_and_query: &'a str,
    ) -> std::borrow::Cow<'a, str> {
        self.uri_base.path_and_query(path_and_query)
    }

    pub fn host_header(&self) -> &HeaderValue {
        &self.uri_base.host_header
    }

    pub fn authority(&self) -> &Authority {
        &self.uri_base.authority
    }

    pub fn connect_addr(&self) -> std::io::Result<SocketAddr> {
        if let Some(addr) = self.connect_addr.get() {
            return Ok(*addr);
        }
        let resolved = resolve_socket_addr(self.uri_base.authority.as_str())?;
        let _ = self.connect_addr.set(resolved);
        Ok(*self.connect_addr.get().expect("connect addr initialized"))
    }

    pub fn mark_success(&self) {
        if self.passive_failures.load(Ordering::Relaxed) != 0 {
            self.passive_failures.store(0, Ordering::Relaxed);
        }
    }

    pub fn mark_failure(&self) {
        self.passive_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn passive_failures(&self) -> usize {
        self.passive_failures.load(Ordering::Relaxed)
    }

    pub fn set_active_healthy(&self, healthy: bool) {
        self.active_healthy.store(healthy, Ordering::Relaxed);
    }

    pub fn is_active_healthy(&self) -> bool {
        self.active_healthy.load(Ordering::Relaxed)
    }

    pub fn is_available(&self, threshold: u32) -> bool {
        self.active_healthy.load(Ordering::Relaxed) && self.passive_failures() < threshold as usize
    }
}

#[derive(Debug)]
struct UpstreamUriBase {
    scheme: Scheme,
    authority: Authority,
    host_header: HeaderValue,
    base_path: String,
}

impl UpstreamUriBase {
    fn parse(url: &str) -> Result<Self, http::uri::InvalidUri> {
        let uri: Uri = url.parse()?;
        let scheme = uri.scheme().cloned().unwrap_or(Scheme::HTTP);
        let authority = uri.authority().cloned().expect("validated URI authority");
        Ok(Self {
            scheme,
            host_header: HeaderValue::from_str(authority.as_str())
                .expect("validated URI authority"),
            authority,
            base_path: uri.path().trim_end_matches('/').to_string(),
        })
    }

    fn build_uri(&self, path_and_query: &str) -> Result<Uri, http::Error> {
        let path = self.path_and_query(path_and_query);
        let mut s = String::with_capacity(
            self.scheme.as_str().len() + 3 + self.authority.as_str().len() + path.len(),
        );
        s.push_str(self.scheme.as_str());
        s.push_str("://");
        s.push_str(self.authority.as_str());
        s.push_str(&path);

        // Use a generic http::Error construction by mapping an InvalidUri error
        s.parse().map_err(|_e: http::uri::InvalidUri| {
            // Re-use builder just to generate the http::Error format since InvalidUri isn't directly convertible
            http::uri::Builder::new()
                .scheme("http")
                .build()
                .unwrap_err()
        })
    }

    fn path_and_query<'a>(&self, path_and_query: &'a str) -> std::borrow::Cow<'a, str> {
        path_for_upstream(&self.base_path, path_and_query)
    }
}

fn path_for_upstream<'a>(base_path: &str, path_and_query: &'a str) -> std::borrow::Cow<'a, str> {
    if base_path.is_empty() && path_and_query.starts_with('/') {
        return std::borrow::Cow::Borrowed(path_and_query);
    }

    let request_path = path_and_query.trim_start_matches('/');
    if base_path.is_empty() {
        std::borrow::Cow::Owned(format!("/{request_path}"))
    } else if request_path.is_empty() {
        std::borrow::Cow::Owned(base_path.to_string())
    } else {
        std::borrow::Cow::Owned(format!("{base_path}/{request_path}"))
    }
}

fn parse_authority_host(host: &str) -> Option<String> {
    let authority: Authority = host.parse().ok()?;
    let authority_text = authority.as_str();
    if authority_text.contains('@') {
        return None;
    }

    let host_part = authority.host();
    if host_part.is_empty() {
        return None;
    }

    let after_host = authority_text.strip_prefix(host_part)?;
    if !after_host.is_empty() {
        if !after_host.starts_with(':') || authority.port().is_none() {
            return None;
        }
    }

    Some(host_part.to_ascii_lowercase())
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    if path == prefix {
        return true;
    }
    let Some(rest) = path.strip_prefix(prefix) else {
        return false;
    };
    rest.starts_with('/') || rest.starts_with('?')
}

fn resolve_socket_addr(authority: &str) -> std::io::Result<SocketAddr> {
    authority
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::other("could not resolve upstream authority"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_states_have_unique_ids() {
        let toml = r#"
            [[routes]]
            name = "r"
            host = "*"
            path_prefix = "/"
            upstream_pool = "web"
            [upstream_pools.web]
            [[upstream_pools.web.upstreams]]
            name = "a"
            url = "http://127.0.0.1:9000"
            [[upstream_pools.web.upstreams]]
            name = "b"
            url = "http://127.0.0.1:9001"
        "#;
        let snap = ConfigSnapshot::parse(toml, "inline").unwrap();
        let ups = snap.routes.all_upstreams();
        assert_eq!(ups.len(), 2);
        assert_ne!(ups[0].id(), ups[1].id());
    }

    #[test]
    fn runtime_defaults_enable_zero_copy() {
        let cfg = RuntimeConfig::default();
        assert!(cfg.zero_copy);
        assert_eq!(cfg.liveness_probe_idle_ms, 250);
        assert_eq!(cfg.liveness_probe_idle().as_millis(), 250);
    }

    #[test]
    fn runtime_omitted_fields_use_defaults() {
        // A config with no [runtime] table must still parse and default zero_copy on.
        let toml = r#"
            [[routes]]
            name = "r"
            host = "*"
            path_prefix = "/"
            upstream_pool = "web"
            [upstream_pools.web]
            [[upstream_pools.web.upstreams]]
            name = "a"
            url = "http://127.0.0.1:9000"
        "#;
        let snap = ConfigSnapshot::parse(toml, "inline").unwrap();
        assert!(snap.config.runtime.zero_copy);
    }

    fn sample() -> &'static str {
        r#"
            [[routes]]
            name = "api"
            host = "example.com"
            path_prefix = "/api"
            upstream_pool = "api"

            [[routes]]
            name = "root"
            host = "*"
            path_prefix = "/"
            upstream_pool = "web"

            [upstream_pools.api]
            [[upstream_pools.api.upstreams]]
            name = "api-a"
            url = "http://127.0.0.1:9001"
            protocol = "h1"
            weight = 2

            [upstream_pools.web]
            [[upstream_pools.web.upstreams]]
            name = "web-a"
            url = "http://127.0.0.1:9002"
            protocol = "h2"
            weight = 1
        "#
    }

    #[test]
    fn parses_and_matches_longest_route() {
        let snapshot = ConfigSnapshot::parse(sample(), "inline").unwrap();
        let matched = snapshot
            .routes
            .match_route(Some("example.com:443"), "/api/users")
            .unwrap();
        assert_eq!(matched.route.name, "api");
    }

    #[test]
    fn route_prefixes_require_segment_boundaries() {
        let snapshot = ConfigSnapshot::parse(sample(), "inline").unwrap();
        let matched = snapshot
            .routes
            .match_route(Some("example.com"), "/apiary")
            .unwrap();
        assert_eq!(matched.route.name, "root");
        let matched = snapshot
            .routes
            .match_route(Some("example.com"), "/api?x=1")
            .unwrap();
        assert_eq!(matched.route.name, "api");
    }

    #[test]
    fn rejects_malformed_host_authority() {
        let snapshot = ConfigSnapshot::parse(sample(), "inline").unwrap();
        assert!(
            snapshot
                .routes
                .match_route(Some("example.com:bad"), "/api")
                .is_none()
        );
    }

    #[test]
    fn rejects_unsupported_https_upstream_scheme() {
        let config = r#"
            [[routes]]
            name = "root"
            host = "*"
            path_prefix = "/"
            upstream_pool = "web"

            [upstream_pools.web]
            [[upstream_pools.web.upstreams]]
            name = "web-a"
            url = "https://127.0.0.1:9002"
            protocol = "h1"
            weight = 1
        "#;
        assert!(ConfigSnapshot::parse(config, "inline").is_err());
    }

    #[test]
    fn rejects_excessive_upstream_weight() {
        let config = r#"
            [[routes]]
            name = "root"
            host = "*"
            path_prefix = "/"
            upstream_pool = "web"

            [upstream_pools.web]
            [[upstream_pools.web.upstreams]]
            name = "web-a"
            url = "http://127.0.0.1:9002"
            protocol = "h1"
            weight = 10001
        "#;
        assert!(ConfigSnapshot::parse(config, "inline").is_err());
    }

    #[test]
    fn rejects_h3_without_explicit_opt_in() {
        let config = r#"
            [[routes]]
            name = "root"
            host = "*"
            path_prefix = "/"
            upstream_pool = "web"

            [upstream_pools.web]
            [[upstream_pools.web.upstreams]]
            name = "web-h3"
            url = "https://127.0.0.1:9443"
            protocol = "h3"
            weight = 1
        "#;
        assert!(ConfigSnapshot::parse(config, "inline").is_err());
    }

    #[test]
    fn weighted_selection_marks_passive_failures() {
        let snapshot = ConfigSnapshot::parse(sample(), "inline").unwrap();
        let matched = snapshot
            .routes
            .match_route(Some("example.com"), "/api")
            .unwrap();
        let first = matched.pool.select().unwrap();
        first.mark_failure();
        assert_eq!(first.passive_failures(), 1);
        first.mark_success();
        assert_eq!(first.passive_failures(), 0);
    }

    #[test]
    fn validates_fast_http1_engine_shape() {
        let config = r#"
            [[listeners]]
            name = "fast"
            bind = "127.0.0.1:8080"
            protocols = ["h1"]
            http1_engine = "fast"

            [[routes]]
            name = "root"
            host = "*"
            path_prefix = "/"
            upstream_pool = "web"

            [upstream_pools.web]
            [[upstream_pools.web.upstreams]]
            name = "web-a"
            url = "http://127.0.0.1:9002"
            protocol = "h1"
            weight = 1
        "#;
        let snapshot = ConfigSnapshot::parse(config, "inline").unwrap();
        assert_eq!(snapshot.config.listeners[0].http1_engine, Http1Engine::Fast);
    }

    #[test]
    fn rejects_fast_http1_engine_for_mixed_protocols() {
        let config = r#"
            [[listeners]]
            name = "fast"
            bind = "127.0.0.1:8080"
            protocols = ["h1", "h2"]
            http1_engine = "fast"

            [[routes]]
            name = "root"
            host = "*"
            path_prefix = "/"
            upstream_pool = "web"

            [upstream_pools.web]
            [[upstream_pools.web.upstreams]]
            name = "web-a"
            url = "http://127.0.0.1:9002"
            protocol = "h1"
            weight = 1
        "#;
        assert!(ConfigSnapshot::parse(config, "inline").is_err());
    }

    #[test]
    fn validates_uring_http1_engine_shape() {
        let config = r#"
            [[listeners]]
            name = "uring"
            bind = "127.0.0.1:8080"
            protocols = ["h1"]
            http1_engine = "uring"

            [[routes]]
            name = "root"
            host = "*"
            path_prefix = "/"
            upstream_pool = "web"

            [upstream_pools.web]
            [[upstream_pools.web.upstreams]]
            name = "web-a"
            url = "http://127.0.0.1:9002"
            protocol = "h1"
            weight = 1
        "#;
        let snapshot = ConfigSnapshot::parse(config, "inline").unwrap();
        assert_eq!(
            snapshot.config.listeners[0].http1_engine,
            Http1Engine::Uring
        );
    }

    #[test]
    fn parses_l4_only_service() {
        let config = r#"
            listeners = []

            [[l4_services]]
            name = "edge-web"
            domains = ["example.com", "www.example.com"]
            vip = "192.0.2.10"
            port = 443
            protocol = "tcp"
            scheduler = "wrr"
            mode = "ipvs_dsr"

            [[l4_services.real_servers]]
            address = "10.0.0.11"
            port = 443
            weight = 2
        "#;
        let snapshot = ConfigSnapshot::parse(config, "inline").unwrap();
        assert!(snapshot.config.listeners.is_empty());
        assert_eq!(
            snapshot.config.l4_services[0].domains,
            ["example.com", "www.example.com"]
        );
        assert_eq!(snapshot.config.l4_services[0].real_servers[0].weight, 2);
    }

    #[test]
    fn rejects_l4_listener_bind_conflict() {
        let config = r#"
            [[listeners]]
            name = "public"
            bind = "192.0.2.10:443"
            protocols = ["h1"]

            [[routes]]
            name = "root"
            host = "*"
            path_prefix = "/"
            upstream_pool = "web"

            [upstream_pools.web]
            [[upstream_pools.web.upstreams]]
            name = "web-a"
            url = "http://127.0.0.1:9002"
            protocol = "h1"
            weight = 1

            [[l4_services]]
            name = "edge-web"
            domains = ["example.com"]
            vip = "192.0.2.10"
            port = 443

            [[l4_services.real_servers]]
            address = "10.0.0.11"
            port = 443
            weight = 1
        "#;
        assert!(ConfigSnapshot::parse(config, "inline").is_err());
    }
}
