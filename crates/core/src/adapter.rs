//! Ports each hosting option implements (Workers: DO/fetch/WebCrypto; native: SQLite/Postgres/reqwest).
//!
//! The traits use `async fn` without a `Send` bound on purpose: Workers futures wrap JS promises
//! and are `!Send`.
// shortcut: the native adapter (PH-15) still has to decide how to get `Send` futures for axum
// (e.g. `trait-variant` or a current-thread runtime per request) once it implements these.
#![allow(async_fn_in_trait)]

use crate::error::Error;
use crate::model::{EndpointId, Registration};
use crate::vapid::PublicKey;

pub trait Clock {
    /// Unix seconds.
    fn now(&self) -> u64;
}

pub trait Crypto {
    /// Cryptographically secure random bytes (endpoint IDs, challenge nonces).
    fn random_bytes(&self, out: &mut [u8]);

    /// ES256 (P-256 / SHA-256) verification of a raw `r || s` signature. Workers should use
    /// WebCrypto here (PH-21: wasm verify costs more CPU); native can use `p256`.
    async fn verify_es256(&self, key: &PublicKey, message: &[u8], signature: &[u8; 64]) -> bool;

    /// RSASSA-PKCS1-v1_5 / SHA-256 with a PKCS#8 DER key (Google service-account OAuth).
    /// Workers: WebCrypto (PH-21); native: an RSA crate.
    async fn sign_rs256(&self, pkcs8_der: &[u8], message: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Provider OAuth token (e.g. FCM), shared by every request of a deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken {
    pub token: String,
    /// Unix seconds.
    pub expires_at: u64,
}

/// Where the provider token lives: a Durable Object on Workers, process memory on native.
pub trait TokenCache {
    async fn get(&self) -> Result<Option<AccessToken>, Error>;
    async fn put(&self, token: &AccessToken) -> Result<(), Error>;
    async fn clear(&self) -> Result<(), Error>;
}

pub trait Store {
    async fn get(&self, id: &EndpointId) -> Result<Option<Registration>, Error>;
    /// Insert or replace.
    async fn put(&self, registration: &Registration) -> Result<(), Error>;
    async fn delete(&self, id: &EndpointId) -> Result<(), Error>;

    /// Atomically claims `(id, key)` for one send. `None`: the caller now owns the claim (stored as
    /// `Pending` until `expires_at`). `Some(state)`: an unexpired earlier claim exists.
    /// Must be atomic across instances, e.g. `INSERT ... ON CONFLICT DO NOTHING` or a Durable Object.
    async fn claim_idempotency(
        &self,
        id: &EndpointId,
        key: &str,
        now: u64,
        expires_at: u64,
    ) -> Result<Option<IdempotencyState>, Error>;

    /// `delivered = true` keeps the claim as the replay answer; `false` releases it so a retry can
    /// go through (the send failed).
    async fn finish_idempotency(
        &self,
        id: &EndpointId,
        key: &str,
        delivered: bool,
    ) -> Result<(), Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdempotencyState {
    /// Another request with the same key is being delivered right now.
    Pending,
    /// Already delivered: replay success without sending again.
    Delivered,
}

pub trait RateLimiter {
    /// Takes one unit from `bucket` (fixed window of `window_secs` starting at the first hit).
    /// `Err(Error::RateLimited { retry_after })` when the window is exhausted.
    async fn acquire(
        &self,
        bucket: &str,
        limit: u32,
        window_secs: u64,
        now: u64,
    ) -> Result<(), Error>;
}

/// Outbound HTTP to push providers (always POST).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub trait HttpClient {
    /// `Err` only for transport failures (timeout, DNS, TLS); HTTP error statuses are `Ok`.
    async fn post(&self, request: HttpRequest) -> Result<HttpResponse, Error>;
}
