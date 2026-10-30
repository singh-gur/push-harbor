//! Shared test setup: a relay wired to in-memory fakes, VAPID signing, and request helpers.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

use crate::adapter::{AccessToken, HttpResponse, Store};
use crate::error::Error;
use crate::fakes::{FakeCrypto, FakeHttp, MemoryRateLimiter, MemoryStore, MemoryTokenCache};
use crate::fcm::{Fcm, ServiceAccount};
use crate::model::{EndpointId, KeyId, Platform, Registration};
use crate::relay::{RateLimit, RateLimits, Relay, SendRequest};
use crate::send::Headers;
use crate::vapid::PublicKey;

pub const ORIGIN: &str = "https://relay.example";
pub const NOW: u64 = 1_800_000_000;

pub struct World {
    pub account: ServiceAccount,
    pub store: MemoryStore,
    pub limiter: MemoryRateLimiter,
    pub crypto: FakeCrypto,
    pub http: FakeHttp,
    pub cache: MemoryTokenCache,
    pub limits: RateLimits,
}

impl World {
    pub fn new(limits: RateLimits) -> Self {
        let world = Self {
            account: ServiceAccount {
                project_id: "demo".into(),
                client_email: "relay@demo".into(),
                token_uri: "https://oauth2.googleapis.com/token".into(),
                private_key_der: vec![0],
                api_base: crate::fcm::API_BASE.into(),
            },
            store: MemoryStore::default(),
            limiter: MemoryRateLimiter::default(),
            crypto: FakeCrypto::default(),
            http: FakeHttp::default(),
            cache: MemoryTokenCache::default(),
            limits,
        };
        // Skip OAuth: a valid cached token.
        *world.cache.0.borrow_mut() = Some(AccessToken {
            token: "tok".into(),
            expires_at: NOW + 3600,
        });
        world
    }

    pub fn relay(
        &self,
    ) -> Relay<'_, MemoryStore, MemoryRateLimiter, FakeCrypto, FakeHttp, MemoryTokenCache> {
        Relay {
            origin: ORIGIN,
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

    /// Stores a confirmed registration bound to `sender` and returns its endpoint ID.
    pub fn seed_registration(&self, seed: u8, sender: &SigningKey) -> String {
        let id = EndpointId::from_random([seed; 16]);
        let registration = Registration {
            endpoint: id.clone(),
            platform: Platform::Fcm,
            target: format!("fid-{seed}"),
            key_id: KeyId::parse("k1").unwrap(),
            sender_key: public(sender),
            created_at: NOW,
        };
        pollster::block_on(self.store.put(&registration)).unwrap();
        id.as_str().to_owned()
    }

    pub fn fcm_replies(&self, statuses: &[u16]) {
        for &status in statuses {
            let body = match status {
                404 => r#"{"error":{"details":[{"errorCode":"UNREGISTERED"}]}}"#,
                _ => "{}",
            };
            self.http.responses.borrow_mut().push_back(Ok(HttpResponse {
                status,
                headers: vec![],
                body: body.as_bytes().to_vec(),
            }));
        }
    }

    pub fn fcm_calls(&self) -> usize {
        self.http.requests.borrow().len()
    }

    pub fn send(
        &self,
        endpoint: &str,
        auth: &str,
        idempotency_key: Option<&str>,
        ip: Option<&str>,
    ) -> Result<(), Error> {
        let body = aes128gcm_body(200);
        let request = SendRequest {
            endpoint,
            authorization: Some(auth),
            headers: Headers {
                content_encoding: Some("aes128gcm"),
                ttl: Some("60"),
                idempotency_key,
                ..Default::default()
            },
            body: &body,
            client_ip: ip,
        };
        pollster::block_on(self.relay().send(&request, NOW))
    }
}

pub fn signer(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}

pub fn public(k: &SigningKey) -> PublicKey {
    k.verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}

/// ES256 VAPID JWT for the test relay origin, valid for an hour from `NOW`.
pub fn vapid_token(k: &SigningKey) -> String {
    let claims = format!(
        r#"{{"aud":"{ORIGIN}","exp":{},"sub":"mailto:ops@example.com"}}"#,
        NOW + 3600
    );
    let signed = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(r#"{"typ":"JWT","alg":"ES256"}"#),
        URL_SAFE_NO_PAD.encode(claims)
    );
    let signature: Signature = k.sign(signed.as_bytes());
    format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

pub fn vapid_header(k: &SigningKey) -> String {
    format!(
        "vapid t={}, k={}",
        vapid_token(k),
        URL_SAFE_NO_PAD.encode(public(k))
    )
}

pub fn aes128gcm_body(len: usize) -> Vec<u8> {
    let mut body = vec![0xAB; len];
    body[16..20].copy_from_slice(&4096u32.to_be_bytes());
    body[20] = 65;
    body
}

pub fn generous() -> RateLimits {
    let big = RateLimit {
        limit: 1000,
        window_secs: 60,
    };
    RateLimits {
        global: big,
        per_ip: big,
        per_sender: big,
        per_endpoint: big,
        registrations_per_ip: big,
        challenges_per_target: big,
    }
}
