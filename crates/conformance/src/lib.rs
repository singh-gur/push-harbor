//! Black-box conformance suite for Pushharbor relays (PH-5). Every hosting configuration
//! (Workers, native + SQLite, native + PostgreSQL) must pass it.
//!
//! The tests talk HTTP to a running relay (`RELAY_URL`) and play the provider themselves: a fake
//! FCM in the test process answers OAuth and `messages:send`, records every message, and acts
//! out failures chosen by the FID prefix. Tests skip when `RELAY_URL` is unset.
//!
//! # Relay configuration contract
//! Start the relay under test with:
//! - origin (VAPID `aud`) = `RELAY_URL`;
//! - FCM service account = [`SERVICE_ACCOUNT_JSON`] and FCM API base = `http://` + [`FAKE_FCM_ADDR`];
//! - rate limits = [`LIMITS`], provider request timeout <= [`MAX_PROVIDER_TIMEOUT_SECS`];
//! - admin token = [`ADMIN_TOKEN`] (export/import API);
//! - its logs written to a file named in `RELAY_LOG` if the log check should run.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};

/// `PUSHHARBOR_ADMIN_TOKEN` of the relay under test.
pub const ADMIN_TOKEN: &str = "conformance-admin-token-not-a-secret-0123456789";

/// Where the fake FCM listens; the relay's FCM API base must point here.
pub const FAKE_FCM_ADDR: &str = "127.0.0.1:9790";
/// Service-account key file for the relay under test (throwaway key, fake token URI).
pub const SERVICE_ACCOUNT_JSON: &str = include_str!("../fixtures/service-account.json");
/// The relay must give up on a provider call within this, so `slow-` FIDs can be tested.
pub const MAX_PROVIDER_TIMEOUT_SECS: u64 = 10;
/// How long the fake FCM stalls for `slow-` FIDs.
pub const SLOW_SECS: u64 = 20;

/// `(limit, window_secs)` the relay under test must use. IP-based and global limits are set
/// out of reach because every test request comes from 127.0.0.1; core unit tests cover them.
pub struct Limits {
    pub global: (u32, u64),
    pub per_ip: (u32, u64),
    pub per_sender: (u32, u64),
    pub per_endpoint: (u32, u64),
    pub registrations_per_ip: (u32, u64),
    pub challenges_per_target: (u32, u64),
}

pub const LIMITS: Limits = Limits {
    global: (1_000_000, 60),
    per_ip: (1_000_000, 60),
    per_sender: (10, 60),
    per_endpoint: (5, 60),
    registrations_per_ip: (1_000_000, 3600),
    challenges_per_target: (5, 3600),
};

/// Largest accepted body (PH-19); mirrors `pushharbor_core::limits::MAX_BODY_BYTES` on purpose:
/// the suite tests the published contract, not the implementation's constant.
pub const MAX_BODY_BYTES: usize = 2900;

/// Messages the fake FCM received, by target (FID).
#[derive(Default)]
pub struct FakeFcm {
    messages: Mutex<HashMap<String, Vec<Value>>>,
    token_requests: Mutex<u32>,
}

impl FakeFcm {
    pub fn messages_for(&self, fid: &str) -> Vec<Value> {
        self.messages
            .lock()
            .unwrap()
            .get(fid)
            .cloned()
            .unwrap_or_default()
    }

    pub fn token_requests(&self) -> u32 {
        *self.token_requests.lock().unwrap()
    }
}

/// Starts the fake FCM once per test binary and returns it.
pub fn fake_fcm() -> &'static FakeFcm {
    static FAKE: OnceLock<Arc<FakeFcm>> = OnceLock::new();
    FAKE.get_or_init(|| {
        let fake = Arc::new(FakeFcm::default());
        let state = fake.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async move {
                let app = Router::new()
                    .route("/token", post(token))
                    .route("/v1/projects/{project}/messages:send", post(messages_send))
                    .with_state(state);
                // `FAKE_FCM_LISTEN=0.0.0.0:9790` lets relays in containers or clusters reach it.
                let address =
                    std::env::var("FAKE_FCM_LISTEN").unwrap_or_else(|_| FAKE_FCM_ADDR.into());
                let listener = tokio::net::TcpListener::bind(&address)
                    .await
                    .unwrap_or_else(|e| panic!("fake FCM can't listen on {address}: {e}"));
                ready_tx.send(()).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        ready_rx.recv().unwrap();
        fake
    })
}

async fn token(State(fake): State<Arc<FakeFcm>>, body: String) -> Response {
    *fake.token_requests.lock().unwrap() += 1;
    if !body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer")
        || !body.contains("assertion=")
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    }
    Json(json!({"access_token": "fake-access-token", "expires_in": 3600, "token_type": "Bearer"}))
        .into_response()
}

/// Behaviour by FID prefix: `gone-` UNREGISTERED, `throttle-` 429, `down-` 503, `slow-` stalls.
/// Challenges (no `p`) succeed for every prefix except `dead-` and `slow-`, so tests can register
/// a device that fails later; `dead-` is a device FCM never knew.
async fn messages_send(
    State(fake): State<Arc<FakeFcm>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if headers.get("authorization").and_then(|v| v.to_str().ok())
        != Some("Bearer fake-access-token")
    {
        return fcm_error(StatusCode::UNAUTHORIZED, "THIRD_PARTY_AUTH_ERROR");
    }
    let message = &body["message"];
    let target = message["fid"]
        .as_str()
        .or(message["token"].as_str())
        .unwrap_or_default()
        .to_owned();
    fake.messages
        .lock()
        .unwrap()
        .entry(target.clone())
        .or_default()
        .push(message.clone());
    let is_challenge = message["data"].get("p").is_none();
    match target.split('-').next().unwrap_or_default() {
        "dead" => fcm_error(StatusCode::NOT_FOUND, "UNREGISTERED"),
        "gone" | "throttle" | "down" if is_challenge => {
            Json(json!({"name": "projects/conformance/messages/challenge"})).into_response()
        }
        "gone" => fcm_error(StatusCode::NOT_FOUND, "UNREGISTERED"),
        "throttle" => {
            let mut response = fcm_error(StatusCode::TOO_MANY_REQUESTS, "QUOTA_EXCEEDED");
            response
                .headers_mut()
                .insert("retry-after", "7".parse().unwrap());
            response
        }
        "down" => fcm_error(StatusCode::SERVICE_UNAVAILABLE, "UNAVAILABLE"),
        "slow" => {
            tokio::time::sleep(Duration::from_secs(SLOW_SECS)).await;
            Json(json!({"name": "projects/conformance/messages/slow"})).into_response()
        }
        _ => Json(json!({"name": format!("projects/conformance/messages/{}", random_id())}))
            .into_response(),
    }
}

fn fcm_error(status: StatusCode, code: &str) -> Response {
    let body = json!({"error": {"code": status.as_u16(), "status": code,
        "details": [{"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": code}]}});
    (status, Json(body)).into_response()
}

/// File listing values that must never appear in relay logs (one per line); checked by the
/// `logs` test after the suite ran. Path from `CONFORMANCE_SECRETS`.
pub fn secrets_file() -> String {
    std::env::var("CONFORMANCE_SECRETS").unwrap_or_else(|_| {
        std::env::temp_dir()
            .join("pushharbor-conformance-secrets.txt")
            .display()
            .to_string()
    })
}

pub fn record_secret(value: &str) {
    use std::io::Write;
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(secrets_file())
        .unwrap();
    writeln!(file, "{value}").unwrap();
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).unwrap();
    bytes
}

/// Unique per call and per run (the relay under test may keep state between runs).
pub fn random_id() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<9>())
}

pub fn new_sender() -> SigningKey {
    loop {
        if let Ok(key) = SigningKey::from_slice(&random_bytes::<32>()) {
            return key;
        }
    }
}

pub fn public_key_b64(k: &SigningKey) -> String {
    URL_SAFE_NO_PAD.encode(k.verifying_key().to_sec1_point(false).as_bytes())
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// ES256 VAPID JWT (`t`) for `aud`, expiring `exp_in` seconds from now (may be negative).
pub fn vapid_token(k: &SigningKey, aud: &str, exp_in: i64) -> String {
    let exp = now() as i64 + exp_in;
    let claims = json!({"aud": aud, "exp": exp, "sub": "mailto:conformance@example.com"});
    let signed = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(r#"{"typ":"JWT","alg":"ES256"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature: Signature = k.sign(signed.as_bytes());
    format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

pub fn vapid_header(k: &SigningKey, aud: &str) -> String {
    format!(
        "vapid t={}, k={}",
        vapid_token(k, aud, 3600),
        public_key_b64(k)
    )
}

/// Structurally valid aes128gcm body of `len` bytes (random content: the relay never decrypts).
pub fn aes128gcm_body(len: usize) -> Vec<u8> {
    let mut body: Vec<u8> = (0..len.div_ceil(32))
        .flat_map(|_| random_bytes::<32>())
        .take(len)
        .collect();
    body[16..20].copy_from_slice(&4096u32.to_be_bytes());
    body[20] = 65;
    body[21] = 4;
    body
}

/// A test's view of the relay under test.
pub struct Relay {
    pub base: String,
    pub http: reqwest::Client,
    pub fcm: &'static FakeFcm,
}

/// A confirmed subscription as the app would hand it to its server.
pub struct Subscription {
    pub id: String,
    pub endpoint: String,
    pub fid: String,
    pub key_id: String,
}

impl Relay {
    /// `None` (test skipped) when `RELAY_URL` is not set.
    pub fn from_env() -> Option<Self> {
        let Ok(base) = std::env::var("RELAY_URL") else {
            eprintln!("RELAY_URL not set: skipping conformance test");
            return None;
        };
        Some(Self {
            base: base.trim_end_matches('/').to_owned(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .unwrap(),
            fcm: fake_fcm(),
        })
    }

    pub async fn post_json(&self, path: &str, body: Value) -> reqwest::Response {
        self.http
            .post(format!("{}{path}", self.base))
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    pub async fn register(
        &self,
        sender: &SigningKey,
        fid: &str,
        replaces: Option<&str>,
    ) -> reqwest::Response {
        record_secret(fid);
        record_secret(&public_key_b64(sender));
        let mut body = json!({"platform": "fcm", "target": fid, "key_id": "k1", "sender_key": public_key_b64(sender)});
        if let Some(id) = replaces {
            body["replaces"] = id.into();
        }
        self.post_json("/v1/registrations", body).await
    }

    /// The nonce and rid of the last challenge the fake FCM received for `fid`.
    pub fn last_challenge(&self, fid: &str) -> (String, String) {
        let message = self
            .fcm
            .messages_for(fid)
            .into_iter()
            .rev()
            .find(|m| m["data"]["c"].is_string())
            .expect("no challenge sent");
        let data = &message["data"];
        (
            data["c"].as_str().unwrap().to_owned(),
            data["r"].as_str().unwrap().to_owned(),
        )
    }

    pub async fn confirm(&self, rid: &str, nonce: &str) -> reqwest::Response {
        self.post_json(
            &format!("/v1/registrations/{rid}/confirm"),
            json!({"c": nonce}),
        )
        .await
    }

    /// Full app flow: register, take the challenge from the fake FCM, confirm.
    pub async fn subscribe(&self, sender: &SigningKey, fid: &str) -> Subscription {
        let response = self.register(sender, fid, None).await;
        assert_eq!(
            response.status(),
            202,
            "register: {}",
            response.text().await.unwrap()
        );
        let (nonce, rid) = self.last_challenge(fid);
        record_secret(&nonce);
        let response = self.confirm(&rid, &nonce).await;
        assert_eq!(response.status(), 201, "confirm");
        let body: Value = response.json().await.unwrap();
        record_secret(body["id"].as_str().unwrap());
        Subscription {
            id: body["id"].as_str().unwrap().to_owned(),
            endpoint: body["endpoint"].as_str().unwrap().to_owned(),
            fid: fid.to_owned(),
            key_id: "k1".into(),
        }
    }

    /// `GET /v1/admin/export` with the given bearer token.
    pub async fn export(&self, token: &str) -> reqwest::Response {
        self.http
            .get(format!("{}/v1/admin/export", self.base))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
    }

    /// `POST /v1/admin/import` of `file` with the given bearer token.
    pub async fn import(&self, token: &str, file: String) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/admin/import", self.base))
            .bearer_auth(token)
            .body(file)
            .send()
            .await
            .unwrap()
    }

    /// Web Push send with the given `Authorization` and extra headers.
    pub async fn push(
        &self,
        endpoint: &str,
        authorization: Option<&str>,
        body: &[u8],
        headers: &[(&str, &str)],
    ) -> reqwest::Response {
        let mut request = self.http.post(endpoint).body(body.to_vec());
        for (name, default) in [("Content-Encoding", "aes128gcm"), ("TTL", "60")] {
            if !headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
                request = request.header(name, default);
            }
        }
        record_secret(&URL_SAFE_NO_PAD.encode(body));
        if let Some(auth) = authorization {
            if let Some(t) = auth
                .strip_prefix("vapid t=")
                .and_then(|rest| rest.split(',').next())
            {
                record_secret(t);
            }
            request = request.header("Authorization", auth);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        request.send().await.unwrap()
    }

    /// Push signed by `sender` with a fresh small body.
    pub async fn push_as(&self, sub: &Subscription, sender: &SigningKey) -> reqwest::Response {
        self.push_as_to(&sub.endpoint, sender).await
    }

    /// Push to an endpoint URL signed by `sender` (VAPID `aud` = this relay's base).
    pub async fn push_as_to(&self, endpoint: &str, sender: &SigningKey) -> reqwest::Response {
        self.push(
            endpoint,
            Some(&vapid_header(sender, &self.base)),
            &aes128gcm_body(200),
            &[],
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fcm_send(client: &reqwest::Client, fid: &str, auth: &str) -> reqwest::Response {
        client
            .post(format!(
                "http://{FAKE_FCM_ADDR}/v1/projects/conformance/messages:send"
            ))
            .header("Authorization", auth)
            .json(&json!({"message": {"fid": fid, "data": {"p": "AA", "s": "k1"}}}))
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn fake_fcm_behaves_by_fid_prefix() {
        let fake = fake_fcm();
        let client = reqwest::Client::new();

        let bad_grant = client
            .post(format!("http://{FAKE_FCM_ADDR}/token"))
            .body("grant_type=password")
            .send()
            .await
            .unwrap();
        assert_eq!(bad_grant.status(), 400);
        let grant: Value = client
            .post(format!("http://{FAKE_FCM_ADDR}/token"))
            .body(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=a.b.c",
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(grant["access_token"], "fake-access-token");
        assert!(fake.token_requests() >= 2);

        let bearer = "Bearer fake-access-token";
        let id = random_id();
        assert_eq!(
            fcm_send(&client, &format!("ok-{id}"), "Bearer wrong")
                .await
                .status(),
            401
        );
        assert_eq!(
            fcm_send(&client, &format!("ok-{id}"), bearer)
                .await
                .status(),
            200
        );
        assert_eq!(
            fcm_send(&client, &format!("gone-{id}"), bearer)
                .await
                .status(),
            404
        );
        let throttled = fcm_send(&client, &format!("throttle-{id}"), bearer).await;
        assert_eq!(
            (
                throttled.status().as_u16(),
                throttled.headers()["retry-after"].to_str().unwrap()
            ),
            (429, "7")
        );
        let down: Value = fcm_send(&client, &format!("down-{id}"), bearer)
            .await
            .json()
            .await
            .unwrap();
        assert_eq!(down["error"]["details"][0]["errorCode"], "UNAVAILABLE");

        // Every authorised message is recorded by target, including failures.
        assert_eq!(fake.messages_for(&format!("ok-{id}")).len(), 1);
        assert_eq!(
            fake.messages_for(&format!("gone-{id}"))[0]["data"]["s"],
            "k1"
        );
    }

    #[test]
    fn helpers_build_valid_inputs() {
        let body = aes128gcm_body(MAX_BODY_BYTES);
        assert_eq!((body.len(), body[20]), (MAX_BODY_BYTES, 65));
        assert_eq!(u32::from_be_bytes(body[16..20].try_into().unwrap()), 4096);
        let sender = new_sender();
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(public_key_b64(&sender))
                .unwrap()
                .len(),
            65
        );
        assert_eq!(vapid_token(&sender, "https://r", 60).split('.').count(), 3);
        assert_ne!(random_id(), random_id());
        let sa: Value = serde_json::from_str(SERVICE_ACCOUNT_JSON).unwrap();
        assert_eq!(sa["token_uri"], format!("http://{FAKE_FCM_ADDR}/token"));
        assert!(
            sa["private_key"]
                .as_str()
                .unwrap()
                .starts_with("-----BEGIN PRIVATE KEY-----")
        );
    }
}
