//! The protocol spec's machine-readable vectors (`docs/spec/vectors`), checked against core.
//! Any change to the protocol must change the spec, the vectors and core together.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use pushharbor_core::Error;
use pushharbor_core::adapter::{Crypto, HttpResponse};
use pushharbor_core::fcm::map_response;
use pushharbor_core::limits::{MAX_BODY_BYTES, VAPID_MAX_LIFETIME_SECS};
use pushharbor_core::send::{Headers, Urgency, validate};
use pushharbor_core::vapid::{PublicKey, authorize, verify, verify_es256_p256};
use serde::Deserialize;
use serde_json::Value;

macro_rules! vectors {
    ($file:literal) => {
        serde_json::from_str(include_str!(concat!("../../../docs/spec/vectors/", $file))).unwrap()
    };
}

fn b64(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value).unwrap()
}

struct P256;

impl Crypto for P256 {
    fn random_bytes(&self, _: &mut [u8]) {
        unreachable!("not used by verify")
    }

    async fn verify_es256(&self, key: &PublicKey, message: &[u8], signature: &[u8; 64]) -> bool {
        verify_es256_p256(key, message, signature)
    }

    async fn sign_rs256(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, Error> {
        unreachable!("not used here")
    }
}

#[derive(Deserialize)]
struct VapidFile {
    sub: String,
    max_lifetime_secs: u64,
    vectors: Vec<VapidVector>,
}

#[derive(Deserialize)]
struct VapidVector {
    name: String,
    authorization: String,
    audience: String,
    now: u64,
    expect: String,
    /// Expected `sub` when it differs from the file-level one (vectors from other libraries).
    sub: Option<String>,
    /// Check `authorize` against this bound key instead of plain `verify`.
    bound_key: Option<String>,
}

#[test]
fn vapid() {
    let file: VapidFile = vectors!("vapid.json");
    assert_eq!(
        file.max_lifetime_secs, VAPID_MAX_LIFETIME_SECS,
        "vectors were built for another limit"
    );
    for v in file.vectors {
        if let Some(bound) = &v.bound_key {
            let bound: PublicKey = b64(bound).try_into().unwrap();
            let got = pollster::block_on(authorize(
                &v.authorization,
                &v.audience,
                v.now,
                &bound,
                &P256,
            ));
            assert_eq!(format!("{:?}", got.unwrap_err()), v.expect, "{}", v.name);
            continue;
        }
        let got = pollster::block_on(verify(&v.authorization, &v.audience, v.now, &P256));
        match (v.expect.as_str(), got) {
            ("ok", Ok(vapid)) => assert_eq!(
                vapid.sub,
                v.sub.unwrap_or_else(|| file.sub.clone()),
                "{}",
                v.name
            ),
            (want, Err(err)) => assert_eq!(format!("{err:?}"), want, "{}", v.name),
            (want, got) => panic!("{}: want {want}, got {got:?}", v.name),
        }
    }
}

#[derive(Deserialize)]
struct EncryptionFile {
    max_body_bytes: usize,
    vectors: Vec<EncryptionVector>,
}

#[derive(Deserialize)]
struct EncryptionVector {
    name: String,
    ua_private: String,
    ua_public: String,
    auth: String,
    as_private: String,
    plaintext: Option<String>,
    body: String,
    body_bytes: usize,
    decrypt: String,
    relay_status: u16,
}

/// Reference RFC 8291 decrypter (single record), as a device implements it.
fn decrypt(body: &[u8], ua_private: &[u8], ua_public: &[u8], auth: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use hkdf::Hkdf;
    use sha2::Sha256;

    let (salt, rest) = body.split_at_checked(16)?;
    let idlen = *rest.get(4)? as usize;
    let as_public = rest.get(5..5 + idlen)?;
    let ciphertext = rest.get(5 + idlen..)?;

    let secret = p256::SecretKey::from_slice(ua_private).ok()?;
    let peer = p256::PublicKey::from_sec1_bytes(as_public).ok()?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());

    let info = [b"WebPush: info\0".as_slice(), ua_public, as_public].concat();
    let mut ikm = [0; 32];
    Hkdf::<Sha256>::new(Some(auth), shared.raw_secret_bytes())
        .expand(&info, &mut ikm)
        .ok()?;
    let prk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let (mut cek, mut nonce) = ([0; 16], [0; 12]);
    prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek)
        .ok()?;
    prk.expand(b"Content-Encoding: nonce\0", &mut nonce).ok()?;

    let mut padded = aes_gcm::Aes128Gcm::new_from_slice(&cek)
        .ok()?
        .decrypt(&nonce.into(), ciphertext)
        .ok()?;
    // Strip padding: zeros after the last-record delimiter 0x02.
    let delimiter = padded.iter().rposition(|&b| b != 0)?;
    (padded[delimiter] == 2).then(|| {
        padded.truncate(delimiter);
        padded
    })
}

#[test]
fn encryption() {
    let file: EncryptionFile = vectors!("encryption.json");
    assert_eq!(file.max_body_bytes, MAX_BODY_BYTES);
    let headers = Headers {
        content_encoding: Some("aes128gcm"),
        ..Default::default()
    };
    for v in file.vectors {
        let body = b64(&v.body);
        assert_eq!(body.len(), v.body_bytes, "{}", v.name);
        // The sender key travels as the aes128gcm key id.
        let as_public = p256::SecretKey::from_slice(&b64(&v.as_private))
            .unwrap()
            .public_key();
        assert_eq!(
            &body[21..86],
            p256::elliptic_curve::sec1::ToSec1Point::to_sec1_point(&as_public, false).as_bytes(),
            "{}",
            v.name
        );

        let plaintext = decrypt(
            &body,
            &b64(&v.ua_private),
            &b64(&v.ua_public),
            &b64(&v.auth),
        );
        match v.decrypt.as_str() {
            "ok" => assert_eq!(
                plaintext.as_deref(),
                v.plaintext.as_deref().map(str::as_bytes),
                "{}",
                v.name
            ),
            _ => assert_eq!(plaintext, None, "{}", v.name),
        }

        let status = validate(&headers, &body).map_or_else(|e| e.status(), |_| 201);
        assert_eq!(status, v.relay_status, "{}", v.name);
    }
}

#[derive(Deserialize)]
struct SendFile {
    vectors: Vec<SendVector>,
}

#[derive(Deserialize)]
struct SendVector {
    name: String,
    headers: BTreeMap<String, String>,
    body: SyntheticBody,
    expect: Value,
}

#[derive(Deserialize)]
struct SyntheticBody {
    len: usize,
    rs: u32,
    #[serde(default = "p256_key_len")]
    idlen: u8,
}

fn p256_key_len() -> u8 {
    65
}

#[test]
fn send_validation() {
    let file: SendFile = vectors!("send.json");
    for v in file.vectors {
        let mut body = vec![0xAB; v.body.len];
        if body.len() > 20 {
            body[16..20].copy_from_slice(&v.body.rs.to_be_bytes());
            body[20] = v.body.idlen;
        }
        let header = |name: &str| {
            v.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        };
        let headers = Headers {
            content_encoding: header("content-encoding"),
            ttl: header("ttl"),
            urgency: header("urgency"),
            topic: header("topic"),
            idempotency_key: header("idempotency-key"),
        };
        let got = match validate(&headers, &body) {
            Ok(send) => {
                let urgency = match send.urgency {
                    Urgency::VeryLow => "very-low",
                    Urgency::Low => "low",
                    Urgency::Normal => "normal",
                    Urgency::High => "high",
                };
                serde_json::json!({"status": 201, "ttl": send.ttl, "urgency": urgency,
                    "topic": send.topic, "idempotency_key": send.idempotency_key})
            }
            Err(e) => serde_json::json!({"status": e.status()}),
        };
        assert_eq!(got, v.expect, "{}", v.name);
    }
}

#[derive(Deserialize)]
struct ErrorsFile {
    errors: Vec<ErrorRow>,
    provider: Vec<ProviderRow>,
}

#[derive(Deserialize)]
struct ErrorRow {
    code: String,
    status: u16,
    retry_after: String,
}

#[derive(Deserialize)]
struct ProviderRow {
    name: String,
    fcm_status: u16,
    fcm_error: Option<String>,
    retry_after: Option<String>,
    expect: String,
    expect_retry_after: Option<u64>,
}

#[test]
fn errors() {
    let file: ErrorsFile = vectors!("errors.json");
    let all = [
        Error::BadRequest("x"),
        Error::Unauthorized(pushharbor_core::vapid::VapidError::Expired),
        Error::Forbidden,
        Error::NotFound,
        Error::Gone,
        Error::PayloadTooLarge,
        Error::RateLimited { retry_after: 1 },
        Error::Unavailable {
            retry_after: Some(1),
        },
        Error::Internal,
    ];
    assert_eq!(file.errors.len(), all.len(), "every error is specified");
    for (row, error) in file.errors.iter().zip(&all) {
        assert_eq!(
            (row.code.as_str(), row.status),
            (error.code(), error.status())
        );
        let never = row.retry_after == "never";
        assert_eq!(never, error.retry_after().is_none(), "{}", row.code);
    }
    assert_eq!(
        Error::RateLimited { retry_after: 1 }.retry_after(),
        Some(1),
        "429 always has Retry-After"
    );

    for row in file.provider {
        let body = row.fcm_error.as_ref().map_or_else(Vec::new, |code| {
            serde_json::to_vec(&serde_json::json!({"error": {"code": row.fcm_status,
                "details": [{"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                    "errorCode": code}]}}))
            .unwrap()
        });
        let response = HttpResponse {
            status: row.fcm_status,
            headers: row
                .retry_after
                .iter()
                .map(|v| ("Retry-After".to_owned(), v.clone()))
                .collect(),
            body,
        };
        let got = map_response(&response);
        let code = got.as_ref().map_or_else(|e| e.code(), |()| "ok");
        assert_eq!(code, row.expect, "{}", row.name);
        if let Some(secs) = row.expect_retry_after {
            assert_eq!(got.unwrap_err().retry_after(), Some(secs), "{}", row.name);
        }
    }
}
