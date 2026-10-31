//! HTTP routes. Logs carry the route template, status and latency only: never paths (endpoint
//! IDs are capabilities), headers, bodies, targets or keys.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pushharbor_core::Error;
use pushharbor_core::export;
use pushharbor_core::fcm::{Fcm, ServiceAccount};
use pushharbor_core::registration::{ConfirmRequest, RegisterRequest, RekeyRequest, parse_json};
use pushharbor_core::relay::{RateLimits, Relay, SendRequest};
use pushharbor_core::send::Headers;
use serde_json::json;
use tower_http::timeout::TimeoutLayer;

use crate::adapters::{
    MemoryTokenCache, NativeCrypto, NativeRateLimiter, ReqwestHttp, SqlStore, now,
};

/// Request bodies are at most 2,900 B (push) or small JSON; anything near this is abuse.
/// Push bodies are at most 2,900 B and JSON requests small; imports get their own, larger limit.
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_IMPORT_BYTES: usize = 256 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct AppState {
    pub origin: String,
    pub admin_token: Option<String>,
    pub limits: RateLimits,
    pub trust_proxy: bool,
    pub account: ServiceAccount,
    pub store: SqlStore,
    pub limiter: NativeRateLimiter,
    pub crypto: NativeCrypto,
    pub http: ReqwestHttp,
    pub cache: MemoryTokenCache,
}

impl AppState {
    fn relay(
        &self,
    ) -> Relay<'_, SqlStore, NativeRateLimiter, NativeCrypto, ReqwestHttp, MemoryTokenCache> {
        Relay {
            origin: &self.origin,
            limits: &self.limits,
            store: &self.store,
            limiter: &self.limiter,
            crypto: &self.crypto,
            fcm: Fcm {
                account: &self.account,
                crypto: &self.crypto,
                http: &self.http,
                cache: &self.cache,
            },
        }
    }

    fn client_ip(&self, headers: &HeaderMap, peer: SocketAddr) -> String {
        let forwarded = || {
            headers
                .get("x-forwarded-for")?
                .to_str()
                .ok()?
                .split(',')
                .next()
                .map(|ip| ip.trim().to_owned())
        };
        self.trust_proxy
            .then(forwarded)
            .flatten()
            .unwrap_or_else(|| peer.ip().to_string())
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/v1/health",
            get(|| async { Json(json!({"status": "ok"})) }),
        )
        .route("/v1/push/{id}", post(push).delete(unregister))
        .route("/v1/push/{id}/rekey", post(rekey))
        .route("/v1/registrations", post(register))
        .route("/v1/registrations/{rid}/challenge", post(resend_challenge))
        .route("/v1/registrations/{rid}/confirm", post(confirm))
        .route("/v1/admin/export", get(admin_export))
        .route(
            "/v1/admin/import",
            post(admin_import).layer(DefaultBodyLimit::max(MAX_IMPORT_BYTES)),
        )
        .layer(middleware::from_fn(log_request))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .with_state(state)
}

struct ApiError(Error);

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut body = json!({"error": self.0.code()});
        if let Error::BadRequest(reason) = self.0 {
            body["message"] = reason.into();
        }
        let mut response = (status, Json(body)).into_response();
        if let Some(secs) = self.0.retry_after() {
            response
                .headers_mut()
                .insert("retry-after", HeaderValue::from(secs));
        }
        response
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

async fn push(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let client_ip = state.client_ip(&headers, peer);
    let request = SendRequest {
        endpoint: &id,
        authorization: header(&headers, "authorization"),
        headers: Headers {
            content_encoding: header(&headers, "content-encoding"),
            ttl: header(&headers, "ttl"),
            urgency: header(&headers, "urgency"),
            topic: header(&headers, "topic"),
            idempotency_key: header(&headers, "idempotency-key"),
        },
        body: &body,
        client_ip: Some(&client_ip),
    };
    state.relay().send(&request, now()).await?;
    Ok(StatusCode::CREATED)
}

async fn unregister(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    state.relay().unregister(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn rekey(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let request: RekeyRequest = parse_json(&body)?;
    state
        .relay()
        .rekey(&id, header(&headers, "authorization"), &request, now())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    let request: RegisterRequest = parse_json(&body)?;
    let client_ip = state.client_ip(&headers, peer);
    let pending = state
        .relay()
        .register(&request, Some(&client_ip), now())
        .await?;
    Ok((StatusCode::ACCEPTED, Json(pending)))
}

async fn resend_challenge(
    State(state): State<Arc<AppState>>,
    Path(rid): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let pending = state.relay().resend_challenge(&rid, now()).await?;
    Ok((StatusCode::ACCEPTED, Json(pending)))
}

async fn confirm(
    State(state): State<Arc<AppState>>,
    Path(rid): Path<String>,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    let request: ConfirmRequest = parse_json(&body)?;
    let subscription = state.relay().confirm(&rid, &request, now()).await?;
    Ok((StatusCode::CREATED, Json(subscription)))
}

async fn admin_export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    export::authorize_admin(
        header(&headers, "authorization"),
        state.admin_token.as_deref(),
    )?;
    let file = export::export(&state.store, &state.origin, now()).await?;
    Ok(([("content-type", "application/x-ndjson")], file))
}

async fn admin_import(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorized = export::authorize_admin(
        header(&headers, "authorization"),
        state.admin_token.as_deref(),
    );
    if let Err(e) = authorized {
        return ApiError(e).into_response();
    }
    let Ok(file) = std::str::from_utf8(&body) else {
        return ApiError(Error::BadRequest("export files are UTF-8")).into_response();
    };
    import_response(export::import(&state.store, &state.origin, file).await)
}

/// `{"imported": n}`, or 400 with the offending line (spec: export.md).
pub fn import_response(result: Result<usize, export::ImportError>) -> Response {
    match result {
        Ok(imported) => Json(json!({"imported": imported})).into_response(),
        Err(export::ImportError::Invalid { line, reason }) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "bad_request", "message": reason, "line": line})),
        )
            .into_response(),
        Err(export::ImportError::Store(e)) => ApiError(e).into_response(),
    }
}

async fn log_request(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("<unmatched>".to_owned(), |p| p.as_str().to_owned());
    let started = Instant::now();
    let response = next.run(request).await;
    tracing::info!(
        %method,
        route,
        status = response.status().as_u16(),
        ms = started.elapsed().as_millis() as u64,
        "request"
    );
    response
}
