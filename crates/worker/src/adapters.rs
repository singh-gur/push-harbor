//! Core adapter traits on Workers: Durable Object SQL storage (registrations, pending
//! registrations, idempotency, rate limits, the FCM token), WebCrypto, and `fetch`.
//!
//! Durable Object SQL calls are synchronous and the object runs one event at a time between
//! awaits, so every method below is atomic without explicit transactions.

use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::future::{Either, select};
use pushharbor_core::Error;
use pushharbor_core::adapter::{
    AccessToken, Crypto, HttpClient, HttpRequest, HttpResponse, IdempotencyState, RateLimiter,
    Store, TokenCache,
};
use pushharbor_core::model::{EndpointId, KeyId, PendingRegistration, Platform, Registration};
use pushharbor_core::vapid::PublicKey;
use serde::Deserialize;
use worker::js_sys::{self, Array, Function, Object, Promise, Reflect, Uint8Array};
use worker::wasm_bindgen::{JsCast, JsValue};
use worker::wasm_bindgen_futures::JsFuture;
use worker::{Date, Delay, Fetch, Headers, Method, RequestInit, SqlStorage, SqlStorageValue};

pub fn now() -> u64 {
    Date::now().as_millis() / 1000
}

pub const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS registrations (endpoint TEXT PRIMARY KEY, platform TEXT NOT NULL,
        target TEXT NOT NULL, key_id TEXT NOT NULL, sender_key TEXT NOT NULL, created_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS pending_registrations (rid TEXT PRIMARY KEY, platform TEXT NOT NULL,
        target TEXT NOT NULL, key_id TEXT NOT NULL, sender_key TEXT NOT NULL, nonce TEXT NOT NULL,
        expires_at INTEGER NOT NULL, challenges_sent INTEGER NOT NULL, replaces TEXT)",
    "CREATE TABLE IF NOT EXISTS idempotency (endpoint TEXT NOT NULL, key TEXT NOT NULL,
        delivered INTEGER NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (endpoint, key))",
    "CREATE TABLE IF NOT EXISTS rate_limits (bucket TEXT PRIMARY KEY, window_end INTEGER NOT NULL,
        count INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS tokens (name TEXT PRIMARY KEY, token TEXT NOT NULL,
        expires_at INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS pending_expiry ON pending_registrations (expires_at)",
    "CREATE INDEX IF NOT EXISTS idempotency_expiry ON idempotency (expires_at)",
    "CREATE INDEX IF NOT EXISTS rate_limits_expiry ON rate_limits (window_end)",
];

/// Deletes expired pending registrations, idempotency claims and rate-limit windows.
pub fn purge_expired(sql: &SqlStorage, now: u64) -> worker::Result<()> {
    for statement in [
        "DELETE FROM pending_registrations WHERE expires_at <= ?",
        "DELETE FROM idempotency WHERE expires_at <= ?",
        "DELETE FROM rate_limits WHERE window_end <= ?",
    ] {
        sql.exec(statement, vec![int(now)])?;
    }
    Ok(())
}

fn int(value: u64) -> SqlStorageValue {
    SqlStorageValue::Integer(value as i64)
}

fn text(value: &str) -> SqlStorageValue {
    value.into()
}

fn db_error(e: worker::Error) -> Error {
    // SQLite errors name the statement problem, never bound values.
    worker::console_error!("storage error: {e}");
    Error::Internal
}

fn platform_name(platform: Platform) -> &'static str {
    match platform {
        Platform::Fcm => "fcm",
        Platform::Apns => "apns",
    }
}

fn parse_platform(name: &str) -> Result<Platform, Error> {
    match name {
        "fcm" => Ok(Platform::Fcm),
        "apns" => Ok(Platform::Apns),
        _ => Err(Error::Internal),
    }
}

/// Keys are stored as base64url text: DO SQL returns blobs as ArrayBuffers, text is simpler.
fn parse_key(value: &str) -> Result<PublicKey, Error> {
    URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::Internal)
}

#[derive(Deserialize)]
struct RegistrationRow {
    endpoint: String,
    platform: String,
    target: String,
    key_id: String,
    sender_key: String,
    created_at: i64,
}

impl RegistrationRow {
    fn into_model(self) -> Result<Registration, Error> {
        Ok(Registration {
            endpoint: EndpointId::parse(&self.endpoint).ok_or(Error::Internal)?,
            platform: parse_platform(&self.platform)?,
            target: self.target,
            key_id: KeyId::parse(&self.key_id).ok_or(Error::Internal)?,
            sender_key: parse_key(&self.sender_key)?,
            created_at: self.created_at as u64,
        })
    }
}

#[derive(Deserialize)]
struct PendingRow {
    rid: String,
    platform: String,
    target: String,
    key_id: String,
    sender_key: String,
    nonce: String,
    expires_at: i64,
    challenges_sent: i64,
    replaces: Option<String>,
}

impl PendingRow {
    fn into_model(self) -> Result<PendingRegistration, Error> {
        Ok(PendingRegistration {
            rid: EndpointId::parse(&self.rid).ok_or(Error::Internal)?,
            platform: parse_platform(&self.platform)?,
            target: self.target,
            key_id: KeyId::parse(&self.key_id).ok_or(Error::Internal)?,
            sender_key: parse_key(&self.sender_key)?,
            nonce: self.nonce,
            expires_at: self.expires_at as u64,
            challenges_sent: self.challenges_sent as u8,
            replaces: self
                .replaces
                .as_deref()
                .map(|id| EndpointId::parse(id).ok_or(Error::Internal))
                .transpose()?,
        })
    }
}

pub struct DoStore<'a>(pub &'a SqlStorage);

impl DoStore<'_> {
    fn rows<T: for<'de> Deserialize<'de>>(
        &self,
        query: &str,
        bindings: Vec<SqlStorageValue>,
    ) -> Result<Vec<T>, Error> {
        self.0
            .exec(query, bindings)
            .and_then(|cursor| cursor.to_array())
            .map_err(db_error)
    }

    fn run(&self, query: &str, bindings: Vec<SqlStorageValue>) -> Result<(), Error> {
        self.0.exec(query, bindings).map(drop).map_err(db_error)
    }
}

impl Store for DoStore<'_> {
    async fn get(&self, id: &EndpointId) -> Result<Option<Registration>, Error> {
        self.rows::<RegistrationRow>(
            "SELECT * FROM registrations WHERE endpoint = ?",
            vec![text(id.as_str())],
        )?
        .pop()
        .map(RegistrationRow::into_model)
        .transpose()
    }

    async fn put(&self, r: &Registration) -> Result<(), Error> {
        self.run(
            "INSERT INTO registrations (endpoint, platform, target, key_id, sender_key, created_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT (endpoint) DO UPDATE SET platform = excluded.platform, target = excluded.target,
                 key_id = excluded.key_id, sender_key = excluded.sender_key",
            vec![
                text(r.endpoint.as_str()),
                text(platform_name(r.platform)),
                text(&r.target),
                text(r.key_id.as_str()),
                text(&URL_SAFE_NO_PAD.encode(r.sender_key)),
                int(r.created_at),
            ],
        )
    }

    async fn delete(&self, id: &EndpointId) -> Result<(), Error> {
        self.run(
            "DELETE FROM registrations WHERE endpoint = ?",
            vec![text(id.as_str())],
        )
    }

    async fn put_pending(&self, p: &PendingRegistration) -> Result<(), Error> {
        self.run(
            "INSERT OR REPLACE INTO pending_registrations
                 (rid, platform, target, key_id, sender_key, nonce, expires_at, challenges_sent, replaces)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                text(p.rid.as_str()),
                text(platform_name(p.platform)),
                text(&p.target),
                text(p.key_id.as_str()),
                text(&URL_SAFE_NO_PAD.encode(p.sender_key)),
                text(&p.nonce),
                int(p.expires_at),
                int(u64::from(p.challenges_sent)),
                p.replaces
                    .as_ref()
                    .map_or(SqlStorageValue::Null, |id| text(id.as_str())),
            ],
        )
    }

    async fn get_pending(&self, rid: &EndpointId) -> Result<Option<PendingRegistration>, Error> {
        self.rows::<PendingRow>(
            "SELECT * FROM pending_registrations WHERE rid = ?",
            vec![text(rid.as_str())],
        )?
        .pop()
        .map(PendingRow::into_model)
        .transpose()
    }

    async fn take_pending(&self, rid: &EndpointId) -> Result<Option<PendingRegistration>, Error> {
        self.rows::<PendingRow>(
            "DELETE FROM pending_registrations WHERE rid = ? RETURNING *",
            vec![text(rid.as_str())],
        )?
        .pop()
        .map(PendingRow::into_model)
        .transpose()
    }

    async fn claim_idempotency(
        &self,
        id: &EndpointId,
        key: &str,
        now: u64,
        expires_at: u64,
    ) -> Result<Option<IdempotencyState>, Error> {
        #[derive(Deserialize)]
        struct Claim {
            delivered: i64,
        }
        let live = self
            .rows::<Claim>(
                "SELECT delivered FROM idempotency WHERE endpoint = ? AND key = ? AND expires_at > ?",
                vec![text(id.as_str()), text(key), int(now)],
            )?
            .pop();
        if let Some(claim) = live {
            return Ok(Some(if claim.delivered == 1 {
                IdempotencyState::Delivered
            } else {
                IdempotencyState::Pending
            }));
        }
        self.run(
            "INSERT OR REPLACE INTO idempotency (endpoint, key, delivered, expires_at) VALUES (?, ?, 0, ?)",
            vec![text(id.as_str()), text(key), int(expires_at)],
        )?;
        Ok(None)
    }

    async fn finish_idempotency(
        &self,
        id: &EndpointId,
        key: &str,
        delivered: bool,
    ) -> Result<(), Error> {
        let query = if delivered {
            "UPDATE idempotency SET delivered = 1 WHERE endpoint = ? AND key = ?"
        } else {
            "DELETE FROM idempotency WHERE endpoint = ? AND key = ?"
        };
        self.run(query, vec![text(id.as_str()), text(key)])
    }
}

/// Fixed windows in the object's SQL storage, so they survive eviction (hourly limits).
pub struct DoRateLimiter<'a>(pub &'a SqlStorage);

impl RateLimiter for DoRateLimiter<'_> {
    async fn acquire(
        &self,
        bucket: &str,
        limit: u32,
        window_secs: u64,
        now: u64,
    ) -> Result<(), Error> {
        #[derive(Deserialize)]
        struct Window {
            window_end: i64,
            count: i64,
        }
        let window = DoStore(self.0)
            .rows::<Window>(
                "INSERT INTO rate_limits (bucket, window_end, count) VALUES (?1, ?2 + ?3, 1)
                 ON CONFLICT (bucket) DO UPDATE SET
                     window_end = CASE WHEN rate_limits.window_end <= ?2 THEN ?2 + ?3 ELSE rate_limits.window_end END,
                     count = CASE WHEN rate_limits.window_end <= ?2 THEN 1 ELSE rate_limits.count + 1 END
                 RETURNING window_end, count",
                vec![text(bucket), int(now), int(window_secs)],
            )?
            .pop()
            .ok_or(Error::Internal)?;
        if window.count > i64::from(limit) {
            return Err(Error::RateLimited {
                retry_after: (window.window_end as u64).saturating_sub(now),
            });
        }
        Ok(())
    }
}

/// The FCM OAuth token, kept in storage so an evicted object doesn't mint a new one.
pub struct DoTokenCache<'a>(pub &'a SqlStorage);

impl TokenCache for DoTokenCache<'_> {
    async fn get(&self) -> Result<Option<AccessToken>, Error> {
        #[derive(Deserialize)]
        struct Row {
            token: String,
            expires_at: i64,
        }
        Ok(DoStore(self.0)
            .rows::<Row>(
                "SELECT token, expires_at FROM tokens WHERE name = 'fcm'",
                vec![],
            )?
            .pop()
            .map(|row| AccessToken {
                token: row.token,
                expires_at: row.expires_at as u64,
            }))
    }

    async fn put(&self, token: &AccessToken) -> Result<(), Error> {
        DoStore(self.0).run(
            "INSERT OR REPLACE INTO tokens (name, token, expires_at) VALUES ('fcm', ?, ?)",
            vec![text(&token.token), int(token.expires_at)],
        )
    }

    async fn clear(&self) -> Result<(), Error> {
        DoStore(self.0).run("DELETE FROM tokens WHERE name = 'fcm'", vec![])
    }
}

/// The runtime's WebCrypto: native code, far cheaper in CPU than the same math in wasm (PH-21).
pub struct WebCrypto;

impl WebCrypto {
    fn crypto() -> JsValue {
        Reflect::get(&js_sys::global(), &"crypto".into()).expect("crypto global")
    }

    async fn subtle(method: &str, args: Array) -> Result<JsValue, JsValue> {
        let subtle = Reflect::get(&Self::crypto(), &"subtle".into())?;
        let function: Function = Reflect::get(&subtle, &method.into())?.dyn_into()?;
        JsFuture::from(function.apply(&subtle, &args)?.dyn_into::<Promise>()?).await
    }

    fn algorithm(fields: &[(&str, &str)]) -> Object {
        let algorithm = Object::new();
        for (name, value) in fields {
            Reflect::set(&algorithm, &(*name).into(), &(*value).into()).expect("plain object");
        }
        algorithm
    }
}

impl Crypto for WebCrypto {
    fn random_bytes(&self, out: &mut [u8]) {
        let array = Uint8Array::new_with_length(out.len() as u32);
        let crypto = Self::crypto();
        let function: Function = Reflect::get(&crypto, &"getRandomValues".into())
            .and_then(|f| f.dyn_into())
            .expect("crypto.getRandomValues");
        function
            .call1(&crypto, &array)
            .expect("crypto.getRandomValues failed");
        array.copy_to(out);
    }

    async fn verify_es256(&self, key: &PublicKey, message: &[u8], signature: &[u8; 64]) -> bool {
        let import = Self::algorithm(&[("name", "ECDSA"), ("namedCurve", "P-256")]);
        let Ok(key) = Self::subtle(
            "importKey",
            Array::of5(
                &"raw".into(),
                &Uint8Array::from(key.as_slice()),
                &import,
                &false.into(),
                &Array::of1(&"verify".into()),
            ),
        )
        .await
        else {
            return false;
        };
        let algorithm = Self::algorithm(&[("name", "ECDSA"), ("hash", "SHA-256")]);
        Self::subtle(
            "verify",
            Array::of4(
                &algorithm,
                &key,
                &Uint8Array::from(signature.as_slice()),
                &Uint8Array::from(message),
            ),
        )
        .await
        .is_ok_and(|valid| valid.is_truthy())
    }

    async fn sign_rs256(&self, pkcs8_der: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
        let algorithm = Self::algorithm(&[("name", "RSASSA-PKCS1-v1_5"), ("hash", "SHA-256")]);
        let key = Self::subtle(
            "importKey",
            Array::of5(
                &"pkcs8".into(),
                &Uint8Array::from(pkcs8_der),
                &algorithm,
                &false.into(),
                &Array::of1(&"sign".into()),
            ),
        )
        .await
        .map_err(|_| Error::Internal)?;
        let signature = Self::subtle(
            "sign",
            Array::of3(&algorithm, &key, &Uint8Array::from(message)),
        )
        .await
        .map_err(|_| Error::Internal)?;
        Ok(Uint8Array::new(&signature).to_vec())
    }
}

/// `fetch` with a timeout; transport failures and timeouts become 503 in core.
pub struct FetchHttp {
    pub timeout: Duration,
}

impl HttpClient for FetchHttp {
    async fn post(&self, request: HttpRequest) -> Result<HttpResponse, Error> {
        let unavailable = |_| Error::Unavailable { retry_after: None };
        let headers = Headers::new();
        for (name, value) in &request.headers {
            headers.set(name, value).map_err(unavailable)?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(Uint8Array::from(request.body.as_slice()).into()));
        let fetch = Fetch::Request(
            worker::Request::new_with_init(&request.url, &init).map_err(unavailable)?,
        );
        let sent = std::pin::pin!(fetch.send());
        let timeout = std::pin::pin!(Delay::from(self.timeout));
        let mut response = match select(sent, timeout).await {
            Either::Left((response, _)) => response.map_err(unavailable)?,
            Either::Right(_) => return Err(Error::Unavailable { retry_after: None }),
        };
        let status = response.status_code();
        let headers = response.headers().entries().collect();
        let body = response.bytes().await.map_err(unavailable)?;
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}
