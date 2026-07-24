//! # yxorp
//!
//! `yxorp` is a highly-optimized, Linux-first edge reverse proxy.
//! It supports deep eBPF UDP steering for HTTP/3, zero-allocation HTTP/1.1 parsing over `io_uring`,
//! and integrated L4 IPVS DSR routing.
//!
//! ## Example Usage
//!
//! You can parse configurations and interact with the internal representations programmatically.
//!
//! ```rust
//! use yxorp::config::{ProxyConfig, ConfigSnapshot};
//!
//! // In a real scenario, this is typically loaded from `yxorp.toml`.
//! let toml_str = r#"
//! [[listeners]]
//! name = "public"
//! bind = "0.0.0.0:80"
//! protocols = ["h1"]
//! http1_engine = "fast"
//!
//! [upstream_pools.backend]
//! [[upstream_pools.backend.upstreams]]
//! name = "backend-1"
//! url = "http://127.0.0.1:8080"
//!
//! [[routes]]
//! name = "default"
//! host = "*"
//! path_prefix = "/"
//! upstream_pool = "backend"
//! "#;
//!
//! let snapshot = ConfigSnapshot::parse(toml_str, "yxorp.toml").unwrap();
//!
//! // Match a route
//! let matched = snapshot.routes.match_route(Some("example.com"), "/api/v1").unwrap();
//! assert_eq!(matched.route.name, "default");
//! assert_eq!(matched.pool.upstreams().len(), 1);
//! ```

pub mod acme;
pub mod admin;
pub mod config;
pub mod control;
pub mod l4;
pub mod proxy;
pub mod telemetry;

pub use config::{ConfigSnapshot, ProxyConfig, RouteTable};
