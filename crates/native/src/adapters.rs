//! Core adapter traits for the native server: SQLite or PostgreSQL (sqlx `Any`, one set of
//! statements for both), rate limits in process memory (SQLite, single instance) or in PostgreSQL
//! (shared by all instances), in-process token cache, aws-lc-rs crypto, reqwest HTTP.
//!
//! Statements use `$n` placeholders in first-use order, which both backends bind positionally.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use pushharbor_core::Error;
use pushharbor_core::adapter::{
    AccessToken, Crypto, HttpClient, HttpRequest, HttpResponse, IdempotencyState, RateLimiter,
    Store, TokenCache,
};
use pushharbor_core::model::{EndpointId, KeyId, PendingRegistration, Platform, Registration};
use pushharbor_core::vapid::{PublicKey, verify_es256_p256};
use sqlx::any::AnyRow;
use sqlx::{AnyPool, Row};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Default)]
pub struct NativeCrypto {
    rng: SystemRandom,
}

impl Crypto for NativeCrypto {
    fn random_bytes(&self, out: &mut [u8]) {
        self.rng
            .fill(out)
            .expect("system random number generator failed");
    }

    async fn verify_es256(&self, key: &PublicKey, message: &[u8], signature: &[u8; 64]) -> bool {
        verify_es256_p256(key, message, signature)
    }

    async fn sign_rs256(&self, pkcs8_der: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
        let key = RsaKeyPair::from_pkcs8(pkcs8_der).map_err(|_| Error::Internal)?;
        let mut signature = vec![0; key.public_modulus_len()];
        key.sign(&RSA_PKCS1_SHA256, &self.rng, message, &mut signature)
            .map_err(|_| Error::Internal)?;
        Ok(signature)
    }
}

pub struct ReqwestHttp(reqwest::Client);

impl ReqwestHttp {
    /// `timeout` bounds the whole provider call; on expiry core answers 503.
    pub fn new(timeout: Duration) -> Self {
        Self(
            reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .expect("HTTP client"),
        )
    }
}

impl HttpClient for ReqwestHttp {
    async fn post(&self, request: HttpRequest) -> Result<HttpResponse, Error> {
        let mut builder = self.0.post(&request.url).body(request.body);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let unavailable = |_| Error::Unavailable { retry_after: None };
        let response = builder.send().await.map_err(unavailable)?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| Some((name.to_string(), value.to_str().ok()?.to_owned())))
            .collect();
        let body = response.bytes().await.map_err(unavailable)?.to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

#[derive(Default)]
pub struct MemoryTokenCache(Mutex<Option<AccessToken>>);

impl TokenCache for MemoryTokenCache {
    async fn get(&self) -> Result<Option<AccessToken>, Error> {
        Ok(self.0.lock().unwrap().clone())
    }

    async fn put(&self, token: &AccessToken) -> Result<(), Error> {
        *self.0.lock().unwrap() = Some(token.clone());
        Ok(())
    }

    async fn clear(&self) -> Result<(), Error> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

/// Fixed-window counters in process memory: correct for a single instance (SQLite). Multiple
/// instances share [`SqlRateLimiter`] instead.
#[derive(Default)]
pub struct MemoryRateLimiter(Mutex<HashMap<String, (u64, u32)>>);

const PRUNE_ABOVE: usize = 100_000;

impl RateLimiter for MemoryRateLimiter {
    async fn acquire(
        &self,
        bucket: &str,
        limit: u32,
        window_secs: u64,
        now: u64,
    ) -> Result<(), Error> {
        let mut windows = self.0.lock().unwrap();
        if windows.len() > PRUNE_ABOVE {
            windows.retain(|_, (window_end, _)| *window_end > now);
        }
        let (window_end, count) = windows
            .entry(bucket.to_owned())
            .or_insert((now + window_secs, 0));
        if now >= *window_end {
            (*window_end, *count) = (now + window_secs, 0);
        }
        if *count >= limit {
            return Err(Error::RateLimited {
                retry_after: *window_end - now,
            });
        }
        *count += 1;
        Ok(())
    }
}

/// SQLite or PostgreSQL, chosen by the database URL.
pub struct SqlStore(pub AnyPool);

fn db_error(e: sqlx::Error) -> Error {
    // sqlx errors carry no bound values, so this can't leak targets or keys.
    tracing::error!(error = %e, "database error");
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

fn sender_key(row: &AnyRow) -> Result<PublicKey, Error> {
    let bytes: Vec<u8> = row.try_get("sender_key").map_err(db_error)?;
    bytes.try_into().map_err(|_| Error::Internal)
}

fn key_id(row: &AnyRow) -> Result<KeyId, Error> {
    KeyId::parse(row.try_get("key_id").map_err(db_error)?).ok_or(Error::Internal)
}

fn registration(row: &AnyRow) -> Result<Registration, Error> {
    Ok(Registration {
        endpoint: EndpointId::parse(row.try_get("endpoint").map_err(db_error)?)
            .ok_or(Error::Internal)?,
        platform: parse_platform(row.try_get("platform").map_err(db_error)?)?,
        target: row.try_get("target").map_err(db_error)?,
        key_id: key_id(row)?,
        sender_key: sender_key(row)?,
        created_at: row.try_get::<i64, _>("created_at").map_err(db_error)? as u64,
    })
}

fn pending(row: &AnyRow) -> Result<PendingRegistration, Error> {
    let replaces: Option<String> = row.try_get("replaces").map_err(db_error)?;
    Ok(PendingRegistration {
        rid: EndpointId::parse(row.try_get("rid").map_err(db_error)?).ok_or(Error::Internal)?,
        platform: parse_platform(row.try_get("platform").map_err(db_error)?)?,
        target: row.try_get("target").map_err(db_error)?,
        key_id: key_id(row)?,
        sender_key: sender_key(row)?,
        nonce: row.try_get("nonce").map_err(db_error)?,
        expires_at: row.try_get::<i64, _>("expires_at").map_err(db_error)? as u64,
        challenges_sent: row.try_get::<i64, _>("challenges_sent").map_err(db_error)? as u8,
        replaces: replaces
            .as_deref()
            .map(|id| EndpointId::parse(id).ok_or(Error::Internal))
            .transpose()?,
    })
}

impl Store for SqlStore {
    async fn get(&self, id: &EndpointId) -> Result<Option<Registration>, Error> {
        sqlx::query("SELECT * FROM registrations WHERE endpoint = $1")
            .bind(id.as_str())
            .fetch_optional(&self.0)
            .await
            .map_err(db_error)?
            .as_ref()
            .map(registration)
            .transpose()
    }

    async fn put(&self, r: &Registration) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO registrations (endpoint, platform, target, key_id, sender_key, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (endpoint) DO UPDATE SET platform = excluded.platform, target = excluded.target,
                 key_id = excluded.key_id, sender_key = excluded.sender_key",
        )
        .bind(r.endpoint.as_str())
        .bind(platform_name(r.platform))
        .bind(&r.target)
        .bind(r.key_id.as_str())
        .bind(r.sender_key.as_slice())
        .bind(r.created_at as i64)
        .execute(&self.0)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn delete(&self, id: &EndpointId) -> Result<(), Error> {
        sqlx::query("DELETE FROM registrations WHERE endpoint = $1")
            .bind(id.as_str())
            .execute(&self.0)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn put_pending(&self, p: &PendingRegistration) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO pending_registrations
                 (rid, platform, target, key_id, sender_key, nonce, expires_at, challenges_sent, replaces)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (rid) DO UPDATE SET challenges_sent = excluded.challenges_sent",
        )
        .bind(p.rid.as_str())
        .bind(platform_name(p.platform))
        .bind(&p.target)
        .bind(p.key_id.as_str())
        .bind(p.sender_key.as_slice())
        .bind(&p.nonce)
        .bind(p.expires_at as i64)
        .bind(i64::from(p.challenges_sent))
        .bind(p.replaces.as_ref().map(EndpointId::as_str))
        .execute(&self.0)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn get_pending(&self, rid: &EndpointId) -> Result<Option<PendingRegistration>, Error> {
        sqlx::query("SELECT * FROM pending_registrations WHERE rid = $1")
            .bind(rid.as_str())
            .fetch_optional(&self.0)
            .await
            .map_err(db_error)?
            .as_ref()
            .map(pending)
            .transpose()
    }

    async fn take_pending(&self, rid: &EndpointId) -> Result<Option<PendingRegistration>, Error> {
        // One statement: two concurrent confirms can't both get the row.
        sqlx::query("DELETE FROM pending_registrations WHERE rid = $1 RETURNING *")
            .bind(rid.as_str())
            .fetch_optional(&self.0)
            .await
            .map_err(db_error)?
            .as_ref()
            .map(pending)
            .transpose()
    }

    async fn claim_idempotency(
        &self,
        id: &EndpointId,
        key: &str,
        now: u64,
        expires_at: u64,
    ) -> Result<Option<IdempotencyState>, Error> {
        // Inserts, or takes over an expired claim, atomically; a live claim leaves 0 rows changed.
        let claimed = sqlx::query(
            "INSERT INTO idempotency (endpoint, key, delivered, expires_at) VALUES ($1, $2, 0, $3)
             ON CONFLICT (endpoint, key) DO UPDATE SET delivered = 0, expires_at = excluded.expires_at
             WHERE idempotency.expires_at <= $4",
        )
        .bind(id.as_str())
        .bind(key)
        .bind(expires_at as i64)
        .bind(now as i64)
        .execute(&self.0)
        .await
        .map_err(db_error)?
        .rows_affected()
            == 1;
        if claimed {
            return Ok(None);
        }
        let delivered: Option<i64> = sqlx::query_scalar(
            "SELECT delivered FROM idempotency WHERE endpoint = $1 AND key = $2",
        )
        .bind(id.as_str())
        .bind(key)
        .fetch_optional(&self.0)
        .await
        .map_err(db_error)?;
        Ok(Some(match delivered {
            Some(1) => IdempotencyState::Delivered,
            // Released between our statements: treat as in flight, the sender retries in 1 s.
            _ => IdempotencyState::Pending,
        }))
    }

    async fn finish_idempotency(
        &self,
        id: &EndpointId,
        key: &str,
        delivered: bool,
    ) -> Result<(), Error> {
        let sql = if delivered {
            "UPDATE idempotency SET delivered = 1 WHERE endpoint = $1 AND key = $2"
        } else {
            "DELETE FROM idempotency WHERE endpoint = $1 AND key = $2"
        };
        sqlx::query(sql)
            .bind(id.as_str())
            .bind(key)
            .execute(&self.0)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

/// Fixed-window counters shared by every instance on the same PostgreSQL database. One upsert
/// per check: the row lock serializes concurrent checks of a bucket, so instances agree exactly.
pub struct SqlRateLimiter(pub AnyPool);

impl RateLimiter for SqlRateLimiter {
    async fn acquire(
        &self,
        bucket: &str,
        limit: u32,
        window_secs: u64,
        now: u64,
    ) -> Result<(), Error> {
        let row = sqlx::query(
            "INSERT INTO rate_limits (bucket, window_end, count) VALUES ($1, $2 + $3, 1)
             ON CONFLICT (bucket) DO UPDATE SET
                 window_end = CASE WHEN rate_limits.window_end <= $2 THEN $2 + $3 ELSE rate_limits.window_end END,
                 count = CASE WHEN rate_limits.window_end <= $2 THEN 1 ELSE rate_limits.count + 1 END
             RETURNING window_end, count",
        )
        .bind(bucket)
        .bind(now as i64)
        .bind(window_secs as i64)
        .fetch_one(&self.0)
        .await
        .map_err(db_error)?;
        let window_end: i64 = row.try_get("window_end").map_err(db_error)?;
        let count: i64 = row.try_get("count").map_err(db_error)?;
        // Rejected checks count too; harmless, the window resets all the same.
        if count > i64::from(limit) {
            return Err(Error::RateLimited {
                retry_after: (window_end as u64).saturating_sub(now),
            });
        }
        Ok(())
    }
}

/// In memory for SQLite (one instance), in the database for PostgreSQL (many instances).
pub enum NativeRateLimiter {
    Memory(MemoryRateLimiter),
    Shared(SqlRateLimiter),
}

impl RateLimiter for NativeRateLimiter {
    async fn acquire(
        &self,
        bucket: &str,
        limit: u32,
        window_secs: u64,
        now: u64,
    ) -> Result<(), Error> {
        match self {
            Self::Memory(l) => l.acquire(bucket, limit, window_secs, now).await,
            Self::Shared(l) => l.acquire(bucket, limit, window_secs, now).await,
        }
    }
}

/// Deletes expired pending registrations, idempotency claims and (PostgreSQL) rate-limit rows.
pub async fn purge_expired(
    pool: &AnyPool,
    shared_limits: bool,
    now: u64,
) -> Result<(), sqlx::Error> {
    let mut statements = vec![
        "DELETE FROM pending_registrations WHERE expires_at <= $1",
        "DELETE FROM idempotency WHERE expires_at <= $1",
    ];
    if shared_limits {
        statements.push("DELETE FROM rate_limits WHERE window_end <= $1");
    }
    for statement in statements {
        sqlx::query(statement)
            .bind(now as i64)
            .execute(pool)
            .await?;
    }
    Ok(())
}
