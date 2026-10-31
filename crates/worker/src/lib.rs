//! Pushharbor on Cloudflare Workers (workers-rs).
//!
//! The Worker forwards every API request to one SQLite-backed Durable Object, `Relay`, which runs
//! the shared core with all state in its SQL storage: registrations, pending registrations,
//! idempotency claims, rate-limit windows and the FCM token. One object means every check is exact
//! and atomic without coordination. shortcut: a single object serializes the deployment (hundreds
//! of sends per second, far above the 6,000/min default limit); shard registrations by endpoint ID
//! when an app outgrows it, keeping global limits in their own object.
//!
//! Configuration (wrangler vars, the service account as a secret), same names as native:
//! `PUSHHARBOR_ORIGIN`, `PUSHHARBOR_FCM_SERVICE_ACCOUNT`, `PUSHHARBOR_LIMIT_<NAME>`,
//! `PUSHHARBOR_PROVIDER_TIMEOUT_SECS`, `PUSHHARBOR_ADMIN_TOKEN` (secret; enables
//! `/v1/admin/export` and `/v1/admin/import`), `PUSHHARBOR_FCM_API_BASE` (tests only).

#![cfg(target_arch = "wasm32")]

mod adapters;

use std::cell::{Cell, OnceCell};
use std::time::Duration;

use pushharbor_core::Error;
use pushharbor_core::export;
use pushharbor_core::fcm::{self, Fcm, ServiceAccount};
use pushharbor_core::registration::{ConfirmRequest, RegisterRequest, RekeyRequest, parse_json};
use pushharbor_core::relay::{RateLimits, Relay, SendRequest};
use pushharbor_core::send::Headers as SendHeaders;
use serde_json::json;
// The `durable_object` macro expects `wasm_bindgen` in scope.
use worker::wasm_bindgen;
use worker::{
    DurableObject, Env, Method, Request, RequestInit, Response, Result, State, durable_object,
    event,
};

use crate::adapters::{
    DoRateLimiter, DoStore, DoTokenCache, FetchHttp, SCHEMA, WebCrypto, now, purge_expired,
};

/// Set by the Worker from `CF-Connecting-IP`; the object is only reachable through the Worker.
const CLIENT_IP: &str = "x-pushharbor-client-ip";
/// Push bodies are at most 2,900 B and JSON requests small; imports get their own, larger limit.
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_IMPORT_BYTES: usize = 64 * 1024 * 1024;
const PURGE_EVERY_SECS: u64 = 600;

#[event(fetch)]
async fn fetch(mut req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    if req.method() == Method::Get && req.path() == "/v1/health" {
        return Response::from_json(&json!({"status": "ok"}));
    }
    if !req.path().starts_with("/v1/") {
        return error_response(&Error::NotFound);
    }
    let headers = req.headers().clone();
    let ip = headers.get("CF-Connecting-IP")?.unwrap_or_default();
    headers.set(CLIENT_IP, &ip)?;
    let body = req.bytes().await?;
    let mut init = RequestInit::new();
    init.with_method(req.method()).with_headers(headers);
    if !body.is_empty() {
        init.with_body(Some(
            worker::js_sys::Uint8Array::from(body.as_slice()).into(),
        ));
    }
    let forwarded = Request::new_with_init(req.url()?.as_str(), &init)?;
    let stub = env
        .durable_object("RELAY")?
        .id_from_name("relay")?
        .get_stub()?;
    let method = req.method();
    let route = route_template(&method, &req.path());
    let response = stub.fetch_with_request(forwarded).await?;
    // Workers Analytics Engine, if bound: counts by method, route template and status only.
    if let Ok(metrics) = env.analytics_engine("METRICS") {
        let status = response.status_code().to_string();
        let _ = worker::AnalyticsEngineDataPointBuilder::new()
            .indexes([route])
            .blobs([method.to_string(), route.to_owned(), status])
            .add_double(1)
            .write_to(&metrics);
    }
    Ok(response)
}

/// The route of an API path without its IDs (endpoint IDs and rids are capabilities).
fn route_template(method: &Method, path: &str) -> &'static str {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match (method, segments.as_slice()) {
        (Method::Post | Method::Delete, ["v1", "push", _]) => "/v1/push/{id}",
        (Method::Post, ["v1", "push", _, "rekey"]) => "/v1/push/{id}/rekey",
        (Method::Post, ["v1", "registrations"]) => "/v1/registrations",
        (Method::Post, ["v1", "registrations", _, "challenge"]) => {
            "/v1/registrations/{rid}/challenge"
        }
        (Method::Post, ["v1", "registrations", _, "confirm"]) => "/v1/registrations/{rid}/confirm",
        (Method::Get, ["v1", "admin", "export"]) => "/v1/admin/export",
        (Method::Post, ["v1", "admin", "import"]) => "/v1/admin/import",
        _ => "<unmatched>",
    }
}

struct Config {
    origin: String,
    limits: RateLimits,
    account: ServiceAccount,
    provider_timeout: Duration,
    admin_token: Option<String>,
}

impl Config {
    fn from_env(env: &Env) -> std::result::Result<Self, String> {
        let var = |name: &str| {
            env.var(name)
                .map(|v| v.to_string())
                .ok()
                .filter(|v| !v.is_empty())
        };
        let origin = var("PUSHHARBOR_ORIGIN")
            .ok_or("PUSHHARBOR_ORIGIN is required")?
            .trim_end_matches('/')
            .to_owned();
        let account_json = env
            .secret("PUSHHARBOR_FCM_SERVICE_ACCOUNT")
            .map(|s| s.to_string())
            .or_else(|_| var("PUSHHARBOR_FCM_SERVICE_ACCOUNT").ok_or(()))
            .map_err(|_| "PUSHHARBOR_FCM_SERVICE_ACCOUNT secret is required")?;
        let mut account = ServiceAccount::from_json(&account_json)
            .map_err(|_| "invalid PUSHHARBOR_FCM_SERVICE_ACCOUNT JSON")?;
        account.api_base = var("PUSHHARBOR_FCM_API_BASE").unwrap_or_else(|| fcm::API_BASE.into());
        let timeout = var("PUSHHARBOR_PROVIDER_TIMEOUT_SECS")
            .map(|v| {
                v.parse()
                    .map_err(|_| "PUSHHARBOR_PROVIDER_TIMEOUT_SECS must be a number")
            })
            .transpose()?
            .unwrap_or(10);
        let admin_token = env
            .secret("PUSHHARBOR_ADMIN_TOKEN")
            .map(|s| s.to_string())
            .ok()
            .or_else(|| var("PUSHHARBOR_ADMIN_TOKEN"))
            .filter(|t| !t.is_empty());
        if admin_token
            .as_ref()
            .is_some_and(|t| t.len() < export::MIN_ADMIN_TOKEN_LEN)
        {
            return Err("PUSHHARBOR_ADMIN_TOKEN must be at least 32 characters".into());
        }
        Ok(Self {
            admin_token,
            origin,
            limits: RateLimits::from_lookup(|name| var(&format!("PUSHHARBOR_LIMIT_{name}")))?,
            account,
            provider_timeout: Duration::from_secs(timeout),
        })
    }
}

#[durable_object]
pub struct RelayObject {
    state: State,
    env: Env,
    /// Parsed once per object instance (the service account's PEM decode isn't free).
    config: OnceCell<std::result::Result<Config, String>>,
    last_purge: Cell<u64>,
}

impl DurableObject for RelayObject {
    fn new(state: State, env: Env) -> Self {
        let sql = state.storage().sql();
        for statement in SCHEMA {
            if let Err(e) = sql.exec(statement, None) {
                worker::console_error!("schema setup failed: {e}");
            }
        }
        Self {
            state,
            env,
            config: OnceCell::new(),
            last_purge: Cell::new(0),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let config = match self.config.get_or_init(|| Config::from_env(&self.env)) {
            Ok(config) => config,
            Err(problem) => {
                worker::console_error!("configuration error: {problem}");
                return error_response(&Error::Internal);
            }
        };
        let sql = self.state.storage().sql();
        let now = now();
        if now >= self.last_purge.get() + PURGE_EVERY_SECS {
            self.last_purge.set(now);
            if let Err(e) = purge_expired(&sql, now) {
                worker::console_error!("purging expired rows failed: {e}");
            }
        }

        let body = req.bytes().await?;
        let limit = if req.path() == "/v1/admin/import" {
            MAX_IMPORT_BYTES
        } else {
            MAX_REQUEST_BYTES
        };
        if body.len() > limit {
            return error_response(&Error::PayloadTooLarge);
        }
        let (store, limiter, cache) = (DoStore(&sql), DoRateLimiter(&sql), DoTokenCache(&sql));
        let (crypto, http) = (
            WebCrypto,
            FetchHttp {
                timeout: config.provider_timeout,
            },
        );
        let relay = Relay {
            origin: &config.origin,
            limits: &config.limits,
            store: &store,
            limiter: &limiter,
            crypto: &crypto,
            fcm: Fcm {
                account: &config.account,
                crypto: &crypto,
                http: &http,
                cache: &cache,
            },
        };
        let header = |name: &str| req.headers().get(name).ok().flatten();
        let client_ip = header(CLIENT_IP).filter(|ip| !ip.is_empty());
        let path = req.path();
        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();

        let result = match (req.method(), segments.as_slice()) {
            (Method::Post, ["v1", "push", id]) => {
                let (authorization, encoding, ttl, urgency, topic, idempotency_key) = (
                    header("authorization"),
                    header("content-encoding"),
                    header("ttl"),
                    header("urgency"),
                    header("topic"),
                    header("idempotency-key"),
                );
                let request = SendRequest {
                    endpoint: id,
                    authorization: authorization.as_deref(),
                    headers: SendHeaders {
                        content_encoding: encoding.as_deref(),
                        ttl: ttl.as_deref(),
                        urgency: urgency.as_deref(),
                        topic: topic.as_deref(),
                        idempotency_key: idempotency_key.as_deref(),
                    },
                    body: &body,
                    client_ip: client_ip.as_deref(),
                };
                relay
                    .send(&request, now)
                    .await
                    .map(|()| Response::empty().map(|r| r.with_status(201)))
            }
            (Method::Delete, ["v1", "push", id]) => relay
                .unregister(id)
                .await
                .map(|()| Response::empty().map(|r| r.with_status(204))),
            (Method::Post, ["v1", "push", id, "rekey"]) => {
                let authorization = header("authorization");
                match parse_json::<RekeyRequest>(&body) {
                    Ok(request) => relay
                        .rekey(id, authorization.as_deref(), &request, now)
                        .await
                        .map(|()| Response::empty().map(|r| r.with_status(204))),
                    Err(e) => Err(e),
                }
            }
            (Method::Post, ["v1", "registrations"]) => match parse_json::<RegisterRequest>(&body) {
                Ok(request) => relay
                    .register(&request, client_ip.as_deref(), now)
                    .await
                    .map(|pending| json_response(&pending, 202)),
                Err(e) => Err(e),
            },
            (Method::Post, ["v1", "registrations", rid, "challenge"]) => relay
                .resend_challenge(rid, now)
                .await
                .map(|pending| json_response(&pending, 202)),
            (Method::Post, ["v1", "registrations", rid, "confirm"]) => {
                match parse_json::<ConfirmRequest>(&body) {
                    Ok(request) => relay
                        .confirm(rid, &request, now)
                        .await
                        .map(|subscription| json_response(&subscription, 201)),
                    Err(e) => Err(e),
                }
            }
            (Method::Get, ["v1", "admin", "export"]) => {
                match export::authorize_admin(
                    header("authorization").as_deref(),
                    config.admin_token.as_deref(),
                ) {
                    Ok(()) => export::export(&store, &config.origin, now)
                        .await
                        .map(|file| {
                            let response = Response::ok(file)?;
                            response
                                .headers()
                                .set("Content-Type", "application/x-ndjson")?;
                            Ok(response)
                        }),
                    Err(e) => Err(e),
                }
            }
            (Method::Post, ["v1", "admin", "import"]) => {
                match export::authorize_admin(
                    header("authorization").as_deref(),
                    config.admin_token.as_deref(),
                ) {
                    Ok(()) => match std::str::from_utf8(&body) {
                        Ok(file) => {
                            return import_response(
                                export::import(&store, &config.origin, file).await,
                            );
                        }
                        Err(_) => Err(Error::BadRequest("export files are UTF-8")),
                    },
                    Err(e) => Err(e),
                }
            }
            _ => Err(Error::NotFound),
        };
        match result {
            Ok(response) => response,
            Err(e) => error_response(&e),
        }
    }
}

/// `{"imported": n}`, or 400 with the offending line (spec: export.md).
fn import_response(result: std::result::Result<usize, export::ImportError>) -> Result<Response> {
    match result {
        Ok(imported) => json_response(&json!({"imported": imported}), 200),
        Err(export::ImportError::Invalid { line, reason }) => json_response(
            &json!({"error": "bad_request", "message": reason, "line": line}),
            400,
        ),
        Err(export::ImportError::Store(e)) => error_response(&e),
    }
}

fn json_response(value: &impl serde::Serialize, status: u16) -> Result<Response> {
    Ok(Response::from_json(value)?.with_status(status))
}

/// Same JSON error body and `Retry-After` as the native server (spec: errors.md).
fn error_response(error: &Error) -> Result<Response> {
    let mut body = json!({"error": error.code()});
    if let Error::BadRequest(reason) = error {
        body["message"] = (*reason).into();
    }
    let response = Response::from_json(&body)?.with_status(error.status());
    if let Some(secs) = error.retry_after() {
        response.headers().set("Retry-After", &secs.to_string())?;
    }
    Ok(response)
}
