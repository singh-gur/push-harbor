//! The send path, shared by every hosting option:
//! validate → global/IP limits → registration → VAPID binding → idempotency claim →
//! endpoint/sender limits → deliver → respond.
//!
//! Payloads only pass through: nothing here stores or logs bodies, tokens or keys.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::adapter::{Crypto, HttpClient, IdempotencyState, RateLimiter, Store, TokenCache};
use crate::error::Error;
use crate::fcm::Fcm;
use crate::limits::IDEMPOTENCY_WINDOW_SECS;
use crate::model::{EndpointId, Platform, Registration};
use crate::send::{self, Headers, ValidSend};
use crate::vapid::{self, Vapid};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub limit: u32,
    pub window_secs: u64,
}

/// Deployment-tunable limits (fixed windows).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    /// Whole deployment; protects the provider quota. Checked before any crypto.
    pub global: RateLimit,
    /// Per client IP. Checked before any crypto.
    pub per_ip: RateLimit,
    /// Per sender (bound VAPID key), across all its endpoints.
    pub per_sender: RateLimit,
    /// Per endpoint (one device subscription).
    pub per_endpoint: RateLimit,
    /// New registrations per client IP.
    pub registrations_per_ip: RateLimit,
    /// Challenge pushes per provider target, so a known FID can't be spammed with challenges.
    pub challenges_per_target: RateLimit,
}

impl Default for RateLimits {
    fn default() -> Self {
        let per_minute = |limit| RateLimit {
            limit,
            window_secs: 60,
        };
        Self {
            global: per_minute(6_000),
            per_ip: per_minute(600),
            per_sender: per_minute(600),
            per_endpoint: per_minute(60),
            registrations_per_ip: RateLimit {
                limit: 30,
                window_secs: 3600,
            },
            challenges_per_target: RateLimit {
                limit: 10,
                window_secs: 3600,
            },
        }
    }
}

/// One incoming Web Push request, as the adapter received it.
#[derive(Debug, Clone, Copy)]
pub struct SendRequest<'a> {
    /// The `<id>` of `/v1/push/<id>`.
    pub endpoint: &'a str,
    pub authorization: Option<&'a str>,
    pub headers: Headers<'a>,
    pub body: &'a [u8],
    pub client_ip: Option<&'a str>,
}

pub struct Relay<'a, S, L, C, H, T> {
    /// Relay origin, the VAPID `aud` senders must use.
    pub origin: &'a str,
    pub limits: &'a RateLimits,
    pub store: &'a S,
    pub limiter: &'a L,
    pub crypto: &'a C,
    pub fcm: Fcm<'a, C, H, T>,
}

impl<S: Store, L: RateLimiter, C: Crypto, H: HttpClient, T: TokenCache> Relay<'_, S, L, C, H, T> {
    /// Handles one send. `Ok(())` is a 201; `Err(e)` maps to `e.status()` and `e.retry_after()`.
    pub async fn send(&self, request: &SendRequest<'_>, now: u64) -> Result<(), Error> {
        let id = EndpointId::parse(request.endpoint).ok_or(Error::NotFound)?;
        let valid = send::validate(&request.headers, request.body)?;
        self.limit("global".into(), self.limits.global, now).await?;
        if let Some(ip) = request.client_ip {
            self.limit(format!("ip:{ip}"), self.limits.per_ip, now)
                .await?;
        }
        let registration = self.store.get(&id).await?.ok_or(Error::NotFound)?;
        let sender = vapid::authorize(
            request.authorization.unwrap_or_default(),
            self.origin,
            now,
            &registration.sender_key,
            self.crypto,
        )
        .await?;

        if let Some(key) = valid.idempotency_key {
            let expires_at = now + IDEMPOTENCY_WINDOW_SECS;
            match self
                .store
                .claim_idempotency(&id, key, now, expires_at)
                .await?
            {
                None => {}
                Some(IdempotencyState::Delivered) => return Ok(()),
                // A duplicate is in flight right now: never deliver twice, ask for a quick retry.
                Some(IdempotencyState::Pending) => {
                    return Err(Error::RateLimited { retry_after: 1 });
                }
            }
        }

        let result = self
            .deliver(&registration, &sender, request.body, &valid, now)
            .await;

        // The provider has answered; bookkeeping failures must not turn that into another status.
        if let Some(key) = valid.idempotency_key {
            let _ = self
                .store
                .finish_idempotency(&id, key, result.is_ok())
                .await;
        }
        if result == Err(Error::Gone) {
            let _ = self.store.delete(&id).await;
        }
        result
    }

    async fn deliver(
        &self,
        registration: &Registration,
        sender: &Vapid,
        body: &[u8],
        valid: &ValidSend<'_>,
        now: u64,
    ) -> Result<(), Error> {
        let endpoint = registration.endpoint.as_str();
        self.limit(format!("ep:{endpoint}"), self.limits.per_endpoint, now)
            .await?;
        let sender = URL_SAFE_NO_PAD.encode(sender.public_key);
        self.limit(format!("sender:{sender}"), self.limits.per_sender, now)
            .await?;
        match registration.platform {
            Platform::Fcm => self.fcm.send(registration, body, valid, now).await,
            // iOS milestone (PH-30); registration rejects APNs until then (PH-12).
            Platform::Apns => Err(Error::Internal),
        }
    }

    pub(crate) async fn limit(
        &self,
        bucket: String,
        limit: RateLimit,
        now: u64,
    ) -> Result<(), Error> {
        self.limiter
            .acquire(&bucket, limit.limit, limit.window_secs, now)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::*;
    use serde_json::Value;

    #[test]
    fn delivers_through_fcm() {
        let w = World::new(generous());
        let sender = signer(7);
        let endpoint = w.seed_registration(1, &sender);
        w.fcm_replies(&[200]);
        assert_eq!(
            w.send(&endpoint, &vapid_header(&sender), None, None),
            Ok(())
        );

        let request = w.http.requests.borrow()[0].clone();
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["message"]["fid"], "fid-1");
        assert_eq!(body["message"]["data"]["s"], "k1");
        assert_eq!(body["message"]["android"]["ttl"], "60s");
    }

    #[test]
    fn rejects_without_reaching_fcm() {
        let w = World::new(generous());
        let (sender, other) = (signer(7), signer(9));
        let endpoint = w.seed_registration(1, &sender);
        let auth = vapid_header(&sender);
        assert_eq!(w.send("not-an-id", &auth, None, None), Err(Error::NotFound));
        assert_eq!(
            w.send(EndpointId::from_random([2; 16]).as_str(), &auth, None, None),
            Err(Error::NotFound)
        );
        assert_eq!(
            w.send(&endpoint, "", None, None),
            Err(Error::Unauthorized(vapid::VapidError::NotVapid))
        );
        assert_eq!(
            w.send(&endpoint, &vapid_header(&other), None, None),
            Err(Error::Forbidden)
        );

        let too_big = aes128gcm_body(crate::limits::MAX_BODY_BYTES + 1);
        let request = SendRequest {
            endpoint: &endpoint,
            authorization: Some(&auth),
            headers: Headers {
                content_encoding: Some("aes128gcm"),
                ..Default::default()
            },
            body: &too_big,
            client_ip: None,
        };
        assert_eq!(
            pollster::block_on(w.relay().send(&request, NOW)),
            Err(Error::PayloadTooLarge)
        );
        assert_eq!(w.fcm_calls(), 0);
    }

    #[test]
    fn gone_device_deletes_the_endpoint() {
        let w = World::new(generous());
        let sender = signer(7);
        let endpoint = w.seed_registration(1, &sender);
        w.fcm_replies(&[404]);
        assert_eq!(
            w.send(&endpoint, &vapid_header(&sender), None, None),
            Err(Error::Gone)
        );
        let id = EndpointId::parse(&endpoint).unwrap();
        assert_eq!(pollster::block_on(w.store.get(&id)), Ok(None));
        assert_eq!(
            w.send(&endpoint, &vapid_header(&sender), None, None),
            Err(Error::NotFound)
        );
        assert_eq!(w.fcm_calls(), 1);
    }

    #[test]
    fn idempotent_replay_never_delivers_twice() {
        let w = World::new(generous());
        let sender = signer(7);
        let endpoint = w.seed_registration(1, &sender);
        let auth = vapid_header(&sender);
        w.fcm_replies(&[200, 200]);
        assert_eq!(w.send(&endpoint, &auth, Some("msg-1"), None), Ok(()));
        assert_eq!(w.send(&endpoint, &auth, Some("msg-1"), None), Ok(()));
        assert_eq!(w.fcm_calls(), 1);
        assert_eq!(w.send(&endpoint, &auth, Some("msg-2"), None), Ok(()));
        assert_eq!(w.fcm_calls(), 2);
    }

    #[test]
    fn failed_send_releases_the_idempotency_key() {
        let w = World::new(generous());
        let sender = signer(7);
        let endpoint = w.seed_registration(1, &sender);
        let auth = vapid_header(&sender);
        w.fcm_replies(&[503, 200]);
        assert_eq!(
            w.send(&endpoint, &auth, Some("msg-1"), None),
            Err(Error::Unavailable { retry_after: None })
        );
        assert_eq!(w.send(&endpoint, &auth, Some("msg-1"), None), Ok(()));
        assert_eq!(w.fcm_calls(), 2);
    }

    #[test]
    fn concurrent_duplicate_gets_retry_later() {
        let w = World::new(generous());
        let sender = signer(7);
        let endpoint = w.seed_registration(1, &sender);
        // Another request with the same key holds the claim and has not finished yet.
        let id = EndpointId::parse(&endpoint).unwrap();
        pollster::block_on(w.store.claim_idempotency(&id, "msg-1", NOW, NOW + 3600)).unwrap();
        assert_eq!(
            w.send(&endpoint, &vapid_header(&sender), Some("msg-1"), None),
            Err(Error::RateLimited { retry_after: 1 })
        );
        assert_eq!(w.fcm_calls(), 0);
    }

    #[test]
    fn each_rate_limit_applies() {
        let two = RateLimit {
            limit: 2,
            window_secs: 60,
        };
        let (a, b) = (signer(7), signer(9));

        // Per endpoint: the third send to one endpoint is refused; another endpoint still works.
        let w = World::new(RateLimits {
            per_endpoint: two,
            ..generous()
        });
        let (ep1, ep2) = (w.seed_registration(1, &a), w.seed_registration(2, &a));
        w.fcm_replies(&[200, 200, 200]);
        assert!(w.send(&ep1, &vapid_header(&a), None, None).is_ok());
        assert!(w.send(&ep1, &vapid_header(&a), None, None).is_ok());
        assert_eq!(
            w.send(&ep1, &vapid_header(&a), None, None),
            Err(Error::RateLimited { retry_after: 60 })
        );
        assert!(w.send(&ep2, &vapid_header(&a), None, None).is_ok());

        // Per sender: counted across all of the sender's endpoints; other senders unaffected.
        let w = World::new(RateLimits {
            per_sender: two,
            ..generous()
        });
        let (ep1, ep2, ep3) = (
            w.seed_registration(1, &a),
            w.seed_registration(2, &a),
            w.seed_registration(3, &b),
        );
        w.fcm_replies(&[200, 200, 200]);
        assert!(w.send(&ep1, &vapid_header(&a), None, None).is_ok());
        assert!(w.send(&ep2, &vapid_header(&a), None, None).is_ok());
        assert!(matches!(
            w.send(&ep1, &vapid_header(&a), None, None),
            Err(Error::RateLimited { .. })
        ));
        assert!(w.send(&ep3, &vapid_header(&b), None, None).is_ok());

        // Per IP and global: enforced before the endpoint lookup, so even unknown endpoints count.
        let unknown = EndpointId::from_random([9; 16]);
        let w = World::new(RateLimits {
            per_ip: two,
            ..generous()
        });
        for _ in 0..2 {
            assert_eq!(
                w.send(unknown.as_str(), "", None, Some("203.0.113.7")),
                Err(Error::NotFound)
            );
        }
        assert!(matches!(
            w.send(unknown.as_str(), "", None, Some("203.0.113.7")),
            Err(Error::RateLimited { .. })
        ));
        assert_eq!(
            w.send(unknown.as_str(), "", None, Some("198.51.100.1")),
            Err(Error::NotFound)
        );

        let w = World::new(RateLimits {
            global: two,
            ..generous()
        });
        for ip in ["a", "b"] {
            assert_eq!(
                w.send(unknown.as_str(), "", None, Some(ip)),
                Err(Error::NotFound)
            );
        }
        assert!(matches!(
            w.send(unknown.as_str(), "", None, Some("c")),
            Err(Error::RateLimited { .. })
        ));
        assert_eq!(w.fcm_calls(), 0);
    }
}
