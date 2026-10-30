//! FCM HTTP v1 provider (Android): service-account OAuth, the message envelope, and mapping FCM
//! responses onto relay errors. All I/O goes through the adapter traits.
//!
//! Envelope (PH-19/PH-20/PH-21): `{"message": {"fid", "data": {"p": base64url(body), "s": key_id},
//! "android": {"priority", "ttl", "collapse_key"?}}}`.

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::adapter::{AccessToken, Crypto, HttpClient, HttpRequest, HttpResponse, TokenCache};
use crate::error::Error;
use crate::model::Registration;
use crate::send::{Urgency, ValidSend};

const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// Mint a new OAuth token when the cached one expires within this many seconds.
const TOKEN_REFRESH_MARGIN_SECS: u64 = 300;
/// `Retry-After` for FCM 429s that don't send one.
const DEFAULT_RETRY_AFTER_SECS: u64 = 60;

/// The fields of a Google service-account key file the relay needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccount {
    pub project_id: String,
    pub client_email: String,
    pub token_uri: String,
    /// PKCS#8 DER of `private_key`.
    pub private_key_der: Vec<u8>,
}

impl ServiceAccount {
    /// Parses the JSON key file downloaded from the Firebase console.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        #[derive(Deserialize)]
        struct File {
            project_id: String,
            client_email: String,
            token_uri: String,
            private_key: String,
        }
        let file: File = serde_json::from_str(json)
            .map_err(|_| Error::BadRequest("invalid service account JSON"))?;
        let pem: String = file
            .private_key
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let private_key_der = STANDARD
            .decode(pem.trim())
            .ok()
            .filter(|der| !der.is_empty())
            .ok_or(Error::BadRequest(
                "service account private_key is not a PEM key",
            ))?;
        Ok(Self {
            project_id: file.project_id,
            client_email: file.client_email,
            token_uri: file.token_uri,
            private_key_der,
        })
    }
}

/// FCM sender for one deployment.
pub struct Fcm<'a, C, H, T> {
    pub account: &'a ServiceAccount,
    pub crypto: &'a C,
    pub http: &'a H,
    pub cache: &'a T,
}

impl<C: Crypto, H: HttpClient, T: TokenCache> Fcm<'_, C, H, T> {
    /// Delivers `body` (an aes128gcm Web Push body) to the device behind `registration`.
    /// `Err(Error::Gone)` means FCM no longer knows the device: the caller deletes the endpoint.
    pub async fn send(
        &self,
        registration: &Registration,
        body: &[u8],
        send: &ValidSend<'_>,
        now: u64,
    ) -> Result<(), Error> {
        let token = self.access_token(now).await?;
        let request = HttpRequest {
            url: format!(
                "https://fcm.googleapis.com/v1/projects/{}/messages:send",
                self.account.project_id
            ),
            headers: vec![
                ("Authorization".into(), format!("Bearer {token}")),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: message(registration, body, send).to_string().into_bytes(),
        };
        let response = self
            .http
            .post(request)
            .await
            .map_err(|_| Error::Unavailable { retry_after: None })?;
        if response.status == 401 {
            // Our OAuth token was rejected (revoked key, clock skew): mint a fresh one next time.
            self.cache.clear().await?;
        }
        map_response(&response)
    }

    /// Cached OAuth access token, minted (RS256 JWT bearer grant) when missing or about to expire.
    pub async fn access_token(&self, now: u64) -> Result<String, Error> {
        if let Some(cached) = self.cache.get().await?
            && cached.expires_at > now + TOKEN_REFRESH_MARGIN_SECS
        {
            return Ok(cached.token);
        }
        let account = self.account;
        let claims = json!({
            "iss": account.client_email,
            "scope": SCOPE,
            "aud": account.token_uri,
            "iat": now,
            "exp": now + 3600,
        });
        let unsigned = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = self
            .crypto
            .sign_rs256(&account.private_key_der, unsigned.as_bytes())
            .await?;
        // The assertion is base64url + '.', so it needs no form encoding.
        let form = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={unsigned}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        );
        let response = self
            .http
            .post(HttpRequest {
                url: account.token_uri.clone(),
                headers: vec![(
                    "Content-Type".into(),
                    "application/x-www-form-urlencoded".into(),
                )],
                body: form.into_bytes(),
            })
            .await
            .map_err(|_| Error::Unavailable { retry_after: None })?;

        #[derive(Deserialize)]
        struct Grant {
            access_token: String,
            expires_in: u64,
        }
        // A rejected grant is a deployment misconfiguration; senders can only wait.
        let grant: Grant = (response.status == 200)
            .then(|| serde_json::from_slice(&response.body).ok())
            .flatten()
            .ok_or(Error::Unavailable { retry_after: None })?;
        let token = AccessToken {
            token: grant.access_token,
            expires_at: now + grant.expires_in,
        };
        self.cache.put(&token).await?;
        Ok(token.token)
    }
}

/// FCM HTTP v1 request body for one push.
pub fn message(registration: &Registration, body: &[u8], send: &ValidSend<'_>) -> Value {
    let mut android = Map::new();
    // High priority is what gets data messages through Doze and to killed apps (PH-20).
    let priority = match send.urgency {
        Urgency::High | Urgency::Normal => "HIGH",
        Urgency::Low | Urgency::VeryLow => "NORMAL",
    };
    android.insert("priority".into(), priority.into());
    android.insert("ttl".into(), format!("{}s", send.ttl).into());
    if let Some(topic) = send.topic {
        // RFC 8030 topic = "replace the pending message with the same topic" = FCM collapse key.
        android.insert("collapse_key".into(), topic.into());
    }
    json!({
        "message": {
            "fid": registration.target,
            "data": { "p": URL_SAFE_NO_PAD.encode(body), "s": registration.key_id.as_str() },
            "android": android,
        }
    })
}

/// FCM HTTP v1 response → relay outcome. Only answers that prove the device is gone delete it.
pub fn map_response(response: &HttpResponse) -> Result<(), Error> {
    if (200..300).contains(&response.status) {
        return Ok(());
    }
    let retry_after = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, value)| value.trim().parse::<u64>().ok());
    match (response.status, error_code(&response.body).as_deref()) {
        (_, Some("UNREGISTERED" | "SENDER_ID_MISMATCH")) | (404, _) => Err(Error::Gone),
        (429, _) | (_, Some("QUOTA_EXCEEDED")) => Err(Error::RateLimited {
            retry_after: retry_after.unwrap_or(DEFAULT_RETRY_AFTER_SECS),
        }),
        (401 | 500..=599, _) | (_, Some("UNAVAILABLE" | "INTERNAL" | "THIRD_PARTY_AUTH_ERROR")) => {
            Err(Error::Unavailable { retry_after })
        }
        // INVALID_ARGUMENT and anything unknown: our request is wrong, don't blame the device.
        _ => Err(Error::Internal),
    }
}

/// `FcmError.errorCode` from `error.details[]`, else the generic `error.status`.
fn error_code(body: &[u8]) -> Option<String> {
    let error = serde_json::from_slice::<Value>(body)
        .ok()?
        .get("error")?
        .clone();
    let detail = error
        .get("details")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find_map(|d| d.get("errorCode").and_then(Value::as_str));
    detail
        .or_else(|| error.get("status").and_then(Value::as_str))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakes::{FakeCrypto, FakeHttp, MemoryTokenCache};
    use crate::model::{EndpointId, KeyId, Platform};

    const NOW: u64 = 1_800_000_000;
    const FCM_URL: &str = "https://fcm.googleapis.com/v1/projects/demo/messages:send";

    fn account() -> ServiceAccount {
        ServiceAccount::from_json(
            r#"{"type":"service_account","project_id":"demo","client_email":"relay@demo.iam.gserviceaccount.com",
                "token_uri":"https://oauth2.googleapis.com/token",
                "private_key":"-----BEGIN PRIVATE KEY-----\nAAEC\nAwQF\n-----END PRIVATE KEY-----\n"}"#,
        )
        .unwrap()
    }

    fn registration() -> Registration {
        Registration {
            endpoint: EndpointId::from_random([1; 16]),
            platform: Platform::Fcm,
            target: "fid-123".into(),
            key_id: KeyId::parse("k1").unwrap(),
            sender_key: [4; 65],
            created_at: 0,
        }
    }

    fn send(ttl: u32, urgency: Urgency, topic: Option<&str>) -> ValidSend<'_> {
        ValidSend {
            ttl,
            urgency,
            topic,
            idempotency_key: None,
        }
    }

    fn response(status: u16, headers: &[(&str, &str)], body: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn grant(expires_in: u64) -> HttpResponse {
        response(
            200,
            &[],
            &format!(r#"{{"access_token":"tok","expires_in":{expires_in},"token_type":"Bearer"}}"#),
        )
    }

    fn fcm_error(status: u16, code: &str) -> String {
        format!(
            r#"{{"error":{{"code":{status},"status":"X","details":[{{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"{code}"}}]}}}}"#
        )
    }

    #[test]
    fn service_account_parsing() {
        let sa = account();
        assert_eq!(
            (sa.project_id.as_str(), sa.private_key_der.as_slice()),
            ("demo", [0u8, 1, 2, 3, 4, 5].as_slice())
        );
        assert!(ServiceAccount::from_json("{}").is_err());
        assert!(
            ServiceAccount::from_json(r#"{"project_id":"p","client_email":"e","token_uri":"u","private_key":"not base64!"}"#).is_err()
        );
    }

    #[test]
    fn message_envelope() {
        let msg = message(
            &registration(),
            b"\x01\x02\xff",
            &send(60, Urgency::Normal, None),
        );
        assert_eq!(
            msg,
            json!({"message": {"fid": "fid-123", "data": {"p": "AQL_", "s": "k1"},
                "android": {"priority": "HIGH", "ttl": "60s"}}})
        );
        let low = message(
            &registration(),
            b"x",
            &send(0, Urgency::VeryLow, Some("chat_1")),
        );
        assert_eq!(
            low["message"]["android"],
            json!({"priority": "NORMAL", "ttl": "0s", "collapse_key": "chat_1"})
        );
    }

    #[test]
    fn oauth_mint_cache_and_refresh() {
        pollster::block_on(async {
            let (sa, crypto, http, cache) = (
                account(),
                FakeCrypto::default(),
                FakeHttp::default(),
                MemoryTokenCache::default(),
            );
            let fcm = Fcm {
                account: &sa,
                crypto: &crypto,
                http: &http,
                cache: &cache,
            };
            http.responses.borrow_mut().push_back(Ok(grant(3600)));
            assert_eq!(fcm.access_token(NOW).await, Ok("tok".into()));

            let mint = http.requests.borrow()[0].clone();
            assert_eq!(mint.url, "https://oauth2.googleapis.com/token");
            let form = String::from_utf8(mint.body).unwrap();
            let assertion = form.split("assertion=").nth(1).unwrap();
            let parts: Vec<_> = assertion.split('.').collect();
            assert_eq!(parts.len(), 3);
            let claims: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
            assert_eq!(claims["iss"], "relay@demo.iam.gserviceaccount.com");
            assert_eq!(
                (claims["scope"].as_str(), claims["exp"].as_u64()),
                (Some(SCOPE), Some(NOW + 3600))
            );
            // FakeCrypto's stand-in signature covers exactly "header.claims".
            let signed = format!("{}.{}", parts[0], parts[1]);
            assert_eq!(
                URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
                [b"rs256:".as_slice(), signed.as_bytes()].concat()
            );

            // Cached until 5 minutes before expiry, then minted again.
            assert_eq!(fcm.access_token(NOW + 3000).await, Ok("tok".into()));
            assert_eq!(http.requests.borrow().len(), 1);
            http.responses.borrow_mut().push_back(Ok(grant(3600)));
            fcm.access_token(NOW + 3301).await.unwrap();
            assert_eq!(http.requests.borrow().len(), 2);
            assert_eq!(
                cache.0.borrow().as_ref().map(|t| t.expires_at),
                Some(NOW + 3301 + 3600)
            );
        });
    }

    #[test]
    fn oauth_failures_are_unavailable() {
        pollster::block_on(async {
            let (sa, crypto, http, cache) = (
                account(),
                FakeCrypto::default(),
                FakeHttp::default(),
                MemoryTokenCache::default(),
            );
            let fcm = Fcm {
                account: &sa,
                crypto: &crypto,
                http: &http,
                cache: &cache,
            };
            http.responses.borrow_mut().push_back(Ok(response(
                400,
                &[],
                r#"{"error":"invalid_grant"}"#,
            )));
            assert_eq!(
                fcm.access_token(NOW).await,
                Err(Error::Unavailable { retry_after: None })
            );
            http.responses.borrow_mut().push_back(Err(Error::Internal));
            assert_eq!(
                fcm.access_token(NOW).await,
                Err(Error::Unavailable { retry_after: None })
            );
            assert_eq!(*cache.0.borrow(), None);
        });
    }

    #[test]
    fn send_posts_the_envelope_and_maps_every_error_class() {
        let cases: [(Result<HttpResponse, Error>, Result<(), Error>); 11] = [
            (
                Ok(response(200, &[], r#"{"name":"projects/demo/messages/1"}"#)),
                Ok(()),
            ),
            (
                Ok(response(404, &[], &fcm_error(404, "UNREGISTERED"))),
                Err(Error::Gone),
            ),
            (
                Ok(response(400, &[], &fcm_error(400, "UNREGISTERED"))),
                Err(Error::Gone),
            ),
            (
                Ok(response(403, &[], &fcm_error(403, "SENDER_ID_MISMATCH"))),
                Err(Error::Gone),
            ),
            (
                Ok(response(
                    429,
                    &[("Retry-After", "30")],
                    &fcm_error(429, "QUOTA_EXCEEDED"),
                )),
                Err(Error::RateLimited { retry_after: 30 }),
            ),
            (
                Ok(response(429, &[], "")),
                Err(Error::RateLimited {
                    retry_after: DEFAULT_RETRY_AFTER_SECS,
                }),
            ),
            (
                Ok(response(
                    503,
                    &[("retry-after", "10")],
                    &fcm_error(503, "UNAVAILABLE"),
                )),
                Err(Error::Unavailable {
                    retry_after: Some(10),
                }),
            ),
            (
                Ok(response(500, &[], &fcm_error(500, "INTERNAL"))),
                Err(Error::Unavailable { retry_after: None }),
            ),
            (
                Ok(response(
                    401,
                    &[],
                    &fcm_error(401, "THIRD_PARTY_AUTH_ERROR"),
                )),
                Err(Error::Unavailable { retry_after: None }),
            ),
            (
                Ok(response(400, &[], &fcm_error(400, "INVALID_ARGUMENT"))),
                Err(Error::Internal),
            ),
            (
                Err(Error::Internal),
                Err(Error::Unavailable { retry_after: None }),
            ),
        ];
        for (fcm_response, want) in cases {
            pollster::block_on(async {
                let (sa, crypto, http, cache) = (
                    account(),
                    FakeCrypto::default(),
                    FakeHttp::default(),
                    MemoryTokenCache::default(),
                );
                *cache.0.borrow_mut() = Some(AccessToken {
                    token: "tok".into(),
                    expires_at: NOW + 3600,
                });
                http.responses.borrow_mut().push_back(fcm_response.clone());
                let fcm = Fcm {
                    account: &sa,
                    crypto: &crypto,
                    http: &http,
                    cache: &cache,
                };
                assert_eq!(
                    fcm.send(
                        &registration(),
                        b"body",
                        &send(60, Urgency::High, None),
                        NOW
                    )
                    .await,
                    want,
                    "{fcm_response:?}"
                );

                let request = http.requests.borrow()[0].clone();
                assert_eq!(request.url, FCM_URL);
                assert!(
                    request
                        .headers
                        .contains(&("Authorization".into(), "Bearer tok".into()))
                );
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(body["message"]["fid"], "fid-123");
                // A 401 means our OAuth token is bad: it must not be reused.
                let status = fcm_response.as_ref().map(|r| r.status).unwrap_or(0);
                assert_eq!(
                    cache.0.borrow().is_none(),
                    status == 401,
                    "{fcm_response:?}"
                );
            });
        }
    }
}
