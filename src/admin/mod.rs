use std::convert::Infallible;
use std::sync::Arc;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use metrics_exporter_prometheus::PrometheusHandle;
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{error, info};

use crate::config::ConfigSnapshot;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type AdminBody = BoxBody<Bytes, BoxError>;

#[derive(Debug)]
pub enum AdminCommand {
    Reload {
        reply: oneshot::Sender<Result<String, String>>,
    },
    Drain {
        reply: oneshot::Sender<Result<String, String>>,
    },
}

#[derive(Clone)]
pub struct AdminRuntime {
    snapshot: Arc<ArcSwap<ConfigSnapshot>>,
    commands: mpsc::Sender<AdminCommand>,
    metrics: Option<PrometheusHandle>,
}

impl AdminRuntime {
    pub fn new(
        snapshot: Arc<ArcSwap<ConfigSnapshot>>,
        commands: mpsc::Sender<AdminCommand>,
        metrics: Option<PrometheusHandle>,
    ) -> Self {
        Self {
            snapshot,
            commands,
            metrics,
        }
    }

    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) -> std::io::Result<()> {
        let bind = self.snapshot.load().config.admin.bind;
        let listener = TcpListener::bind(bind).await?;
        info!(%bind, "admin listener started");

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        info!("admin listener shutting down");
                        return Ok(());
                    }
                }
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let runtime = self.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let service = service_fn(move |request| {
                            let runtime = runtime.clone();
                            async move { runtime.handle(request).await }
                        });
                        if let Err(err) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                            .serve_connection(io, service)
                            .await {
                            error!(error = %err, "admin connection failed");
                        }
                    });
                }
            }
        }
    }

    const UI_HTML: &str = include_str!("ui.html");

    async fn handle(&self, request: Request<Incoming>) -> Result<Response<AdminBody>, Infallible> {
        let method = request.method().clone();
        let path = request.uri().path().to_string();
        if !is_public_endpoint(&method, path.as_str()) && !self.is_authorized(request.headers()) {
            return Ok(unauthorized_response());
        }
        let response = match (method, path.as_str()) {
            (Method::GET, "/") => html_response(StatusCode::OK, Self::UI_HTML.to_string()),
            (Method::GET, "/healthz") => json_response(StatusCode::OK, json!({"status": "ok"})),
            (Method::GET, "/readyz") => json_response(StatusCode::OK, json!({"status": "ready"})),
            (Method::GET, "/metrics") => match &self.metrics {
                Some(handle) => text_response(StatusCode::OK, handle.render()),
                None => text_response(StatusCode::NOT_FOUND, "metrics disabled\n".to_string()),
            },
            (Method::GET, "/api/state") => {
                let snapshot = self.snapshot.load();
                let upstreams: Vec<_> = snapshot
                    .routes
                    .all_upstreams()
                    .iter()
                    .map(|u| {
                        json!({
                            "name": u.config.name,
                            "url": u.config.url,
                            "weight": u.config.weight,
                            "protocol": u.config.protocol,
                            "passive_failures": u.passive_failures(),
                            "active_healthy": u.is_active_healthy(),
                        })
                    })
                    .collect();
                let routes = snapshot.routes.debug_routes();
                json_response(
                    StatusCode::OK,
                    json!({ "routes": routes, "upstreams": upstreams }),
                )
            }
            (Method::GET, "/debug/routes") => {
                let routes = self.snapshot.load().routes.debug_routes();
                json_response(StatusCode::OK, json!({ "routes": routes }))
            }
            (Method::GET, "/debug/certs") => {
                let snapshot = self.snapshot.load();
                json_response(
                    StatusCode::OK,
                    json!({
                        "acme_enabled": snapshot.config.tls.acme.enabled,
                        "storage_dir": snapshot.config.tls.acme.storage_dir,
                        "configured_certs": snapshot.config.tls.certs,
                    }),
                )
            }
            (Method::POST, "/reload") => self.command_reload().await,
            (Method::POST, "/drain") => self.command_drain().await,
            _ => json_response(StatusCode::NOT_FOUND, json!({"error": "not found"})),
        };
        Ok(response)
    }

    fn is_authorized(&self, headers: &HeaderMap) -> bool {
        let snapshot = self.snapshot.load();
        let Some(expected) = snapshot.config.admin.auth_token.as_deref() else {
            return false;
        };
        let Some(provided) = admin_token_from_headers(headers) else {
            return false;
        };
        expected.as_bytes().ct_eq(provided.as_bytes()).into()
    }

    async fn command_reload(&self) -> Response<AdminBody> {
        let (reply, receiver) = oneshot::channel();
        if self
            .commands
            .send(AdminCommand::Reload { reply })
            .await
            .is_err()
        {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "supervisor unavailable"}),
            );
        }
        command_response(receiver).await
    }

    async fn command_drain(&self) -> Response<AdminBody> {
        let (reply, receiver) = oneshot::channel();
        if self
            .commands
            .send(AdminCommand::Drain { reply })
            .await
            .is_err()
        {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "supervisor unavailable"}),
            );
        }
        command_response(receiver).await
    }
}

fn is_public_endpoint(method: &Method, path: &str) -> bool {
    matches!(
        (method, path),
        (&Method::GET, "/") | (&Method::GET, "/healthz") | (&Method::GET, "/readyz")
    )
}

fn admin_token_from_headers(headers: &HeaderMap) -> Option<&str> {
    if let Some(value) = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    {
        return Some(value);
    }
    headers
        .get("x-yxorp-admin-token")
        .and_then(|value| value.to_str().ok())
}

fn unauthorized_response() -> Response<AdminBody> {
    let body = Full::new(Bytes::from_static(br#"{"error":"unauthorized"}"#))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(
            http::header::WWW_AUTHENTICATE,
            "Bearer realm=\"yxorp-admin\"",
        )
        .body(body)
        .expect("static response is valid")
}

async fn command_response(
    receiver: oneshot::Receiver<Result<String, String>>,
) -> Response<AdminBody> {
    match receiver.await {
        Ok(Ok(message)) => json_response(StatusCode::OK, json!({ "status": message })),
        Ok(Err(error)) => json_response(StatusCode::BAD_REQUEST, json!({ "error": error })),
        Err(_) => json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": "supervisor dropped command"}),
        ),
    }
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response<AdminBody> {
    text_with_content_type(status, value.to_string(), "application/json")
}

fn text_response(status: StatusCode, text: String) -> Response<AdminBody> {
    text_with_content_type(status, text, "text/plain; charset=utf-8")
}

fn text_with_content_type(
    status: StatusCode,
    text: String,
    content_type: &'static str,
) -> Response<AdminBody> {
    let body = Full::new(Bytes::from(text))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .body(body)
        .expect("static response is valid")
}

fn html_response(status: StatusCode, text: String) -> Response<AdminBody> {
    text_with_content_type(status, text, "text/html; charset=utf-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bearer_admin_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer secret".parse().unwrap(),
        );
        assert_eq!(admin_token_from_headers(&headers), Some("secret"));
    }

    #[test]
    fn marks_only_liveness_and_ui_as_public() {
        assert!(is_public_endpoint(&Method::GET, "/"));
        assert!(is_public_endpoint(&Method::GET, "/healthz"));
        assert!(!is_public_endpoint(&Method::GET, "/metrics"));
        assert!(!is_public_endpoint(&Method::POST, "/reload"));
    }
}
