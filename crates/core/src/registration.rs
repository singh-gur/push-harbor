//! App-facing registration lifecycle with challenge proof of possession (PH-12, PH-18), and the
//! server-facing VAPID rekey (PH-9). Same dependencies as the send path, so these are `Relay`
//! methods too.
//!
//! - `POST /v1/registrations` → [`Relay::register`] → 202 [`Pending`]; sends the challenge push.
//! - `POST /v1/registrations/<rid>/challenge` → [`Relay::resend_challenge`] → 202 [`Pending`].
//! - `POST /v1/registrations/<rid>/confirm` → [`Relay::confirm`] → 201 [`Subscription`].
//! - `DELETE /v1/push/<id>` → [`Relay::unregister`] → 204.
//! - `POST /v1/push/<id>/rekey` (server, VAPID-signed) → [`Relay::rekey`] → 204.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::adapter::{Crypto, HttpClient, RateLimiter, Store, TokenCache};
use crate::error::Error;
use crate::limits::{MAX_CHALLENGE_SENDS, PENDING_TTL_SECS};
use crate::model::{EndpointId, KeyId, PendingRegistration, Platform, Registration};
use crate::relay::Relay;
use crate::vapid::{self, PublicKey};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RegisterRequest {
    /// `"fcm"` (APNs arrives with the iOS milestone).
    pub platform: String,
    /// Provider address: the FCM Firebase Installation ID.
    pub target: String,
    /// Client-chosen key ID, echoed to the device as `s` (PH-9).
    pub key_id: String,
    /// The server's VAPID public key (uncompressed P-256, base64url) this endpoint is bound to.
    pub sender_key: String,
    /// Target rotation: an existing endpoint ID that should move to the new target on confirm.
    #[serde(default)]
    pub replaces: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Pending {
    pub rid: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ConfirmRequest {
    /// The challenge nonce the device received.
    pub c: String,
}

/// What the app hands to its server: the Web Push endpoint (plus its own `p256dh`/`auth`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Subscription {
    pub id: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RekeyRequest {
    /// New VAPID public key (uncompressed P-256, base64url).
    pub k: String,
    /// Proof of possession: a VAPID JWT for the relay origin signed by the new key.
    pub t: String,
}

/// Parses a JSON request body into one of the request types.
pub fn parse_json<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, Error> {
    serde_json::from_slice(body).map_err(|_| Error::BadRequest("invalid JSON body"))
}

impl<S: Store, L: RateLimiter, C: Crypto, H: HttpClient, T: TokenCache> Relay<'_, S, L, C, H, T> {
    /// Creates a pending registration and sends its challenge push. Nothing can be sent to the
    /// device until [`Relay::confirm`] proves the app received that push.
    pub async fn register(
        &self,
        request: &RegisterRequest,
        client_ip: Option<&str>,
        now: u64,
    ) -> Result<Pending, Error> {
        let platform = match request.platform.as_str() {
            "fcm" => Platform::Fcm,
            "apns" => return Err(Error::BadRequest("platform apns is not supported yet")),
            _ => return Err(Error::BadRequest("platform must be fcm")),
        };
        let target = parse_target(&request.target)?;
        let key_id = KeyId::parse(&request.key_id).ok_or(Error::BadRequest(
            "key_id must be 1-32 characters of [A-Za-z0-9_-]",
        ))?;
        let sender_key = parse_public_key(&request.sender_key)?;
        let replaces = match &request.replaces {
            None => None,
            Some(id) => {
                let id = EndpointId::parse(id).ok_or(Error::NotFound)?;
                let existing = self.store.get(&id).await?.ok_or(Error::NotFound)?;
                if existing.sender_key != sender_key {
                    return Err(Error::BadRequest(
                        "sender_key must match the endpoint being replaced",
                    ));
                }
                Some(id)
            }
        };
        if let Some(ip) = client_ip {
            self.limit(
                format!("register:{ip}"),
                self.limits.registrations_per_ip,
                now,
            )
            .await?;
        }

        let mut pending = PendingRegistration {
            rid: self.random_id(),
            platform,
            target: target.to_owned(),
            key_id,
            sender_key,
            nonce: self.random_id().as_str().to_owned(),
            expires_at: now + PENDING_TTL_SECS,
            challenges_sent: 0,
            replaces,
        };
        self.challenge(&mut pending, now).await?;
        Ok(Pending {
            rid: pending.rid.as_str().to_owned(),
            expires_at: pending.expires_at,
        })
    }

    /// Sends the same challenge again (the app saw nothing within its wait window), up to
    /// [`MAX_CHALLENGE_SENDS`] in total.
    pub async fn resend_challenge(&self, rid: &str, now: u64) -> Result<Pending, Error> {
        let rid = EndpointId::parse(rid).ok_or(Error::NotFound)?;
        let mut pending = self
            .store
            .get_pending(&rid)
            .await?
            .filter(|p| p.expires_at > now)
            .ok_or(Error::NotFound)?;
        if pending.challenges_sent >= MAX_CHALLENGE_SENDS {
            return Err(Error::RateLimited {
                retry_after: pending.expires_at - now,
            });
        }
        self.challenge(&mut pending, now).await?;
        Ok(Pending {
            rid: rid.as_str().to_owned(),
            expires_at: pending.expires_at,
        })
    }

    /// Checks the echoed nonce (single use: any answer consumes the pending registration) and
    /// only then mints the endpoint, or moves an existing one to the new target.
    pub async fn confirm(
        &self,
        rid: &str,
        request: &ConfirmRequest,
        now: u64,
    ) -> Result<Subscription, Error> {
        let rid = EndpointId::parse(rid).ok_or(Error::NotFound)?;
        let pending = self
            .store
            .take_pending(&rid)
            .await?
            .filter(|p| p.expires_at > now)
            .ok_or(Error::NotFound)?;
        if !constant_time_eq(pending.nonce.as_bytes(), request.c.as_bytes()) {
            return Err(Error::Forbidden);
        }
        let registration = match &pending.replaces {
            Some(id) => {
                let mut existing = self.store.get(id).await?.ok_or(Error::NotFound)?;
                existing.platform = pending.platform;
                existing.target = pending.target;
                existing.key_id = pending.key_id;
                existing
            }
            None => Registration {
                endpoint: self.random_id(),
                platform: pending.platform,
                target: pending.target,
                key_id: pending.key_id,
                sender_key: pending.sender_key,
                created_at: now,
            },
        };
        self.store.put(&registration).await?;
        let id = registration.endpoint.as_str();
        Ok(Subscription {
            id: id.to_owned(),
            endpoint: format!("{}/v1/push/{id}", self.origin),
        })
    }

    /// Deletes the endpoint; sends to it get 404 immediately. Idempotent.
    pub async fn unregister(&self, endpoint: &str) -> Result<(), Error> {
        let id = EndpointId::parse(endpoint).ok_or(Error::NotFound)?;
        self.store.delete(&id).await
    }

    /// Server-authorized VAPID key rotation (PH-9): signed by the currently bound key, with a
    /// token from the new key as proof of possession.
    pub async fn rekey(
        &self,
        endpoint: &str,
        authorization: Option<&str>,
        request: &RekeyRequest,
        now: u64,
    ) -> Result<(), Error> {
        let id = EndpointId::parse(endpoint).ok_or(Error::NotFound)?;
        let mut registration = self.store.get(&id).await?.ok_or(Error::NotFound)?;
        vapid::authorize(
            authorization.unwrap_or_default(),
            self.origin,
            now,
            &registration.sender_key,
            self.crypto,
        )
        .await?;
        let new_key = parse_public_key(&request.k)?;
        let proof = format!("vapid t={}, k={}", request.t, request.k);
        vapid::verify(&proof, self.origin, now, self.crypto)
            .await
            .map_err(|_| {
                Error::BadRequest("t must be a valid VAPID token signed by the new key")
            })?;
        registration.sender_key = new_key;
        self.store.put(&registration).await
    }

    async fn challenge(&self, pending: &mut PendingRegistration, now: u64) -> Result<(), Error> {
        self.limit(
            format!("challenge:{}", pending.target),
            self.limits.challenges_per_target,
            now,
        )
        .await?;
        let sent = match pending.platform {
            Platform::Fcm => {
                self.fcm
                    .send_challenge(&pending.target, pending.rid.as_str(), &pending.nonce, now)
                    .await
            }
            // iOS milestone (PH-29/PH-30); `register` rejects APNs until then.
            Platform::Apns => Err(Error::Internal),
        };
        match sent {
            Err(Error::Gone) => Err(Error::BadRequest(
                "target is not registered with the push provider",
            )),
            other => other,
        }?;
        pending.challenges_sent += 1;
        self.store.put_pending(pending).await
    }

    fn random_id(&self) -> EndpointId {
        let mut bytes = [0; 16];
        self.crypto.random_bytes(&mut bytes);
        EndpointId::from_random(bytes)
    }
}

/// FCM FIDs are 22 characters, APNs tokens 64 hex; anything printable without spaces up to 256.
fn parse_target(target: &str) -> Result<&str, Error> {
    let valid = (1..=256).contains(&target.len()) && target.bytes().all(|b| b.is_ascii_graphic());
    valid.then_some(target).ok_or(Error::BadRequest(
        "target must be 1-256 printable characters",
    ))
}

fn parse_public_key(value: &str) -> Result<PublicKey, Error> {
    URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .ok()
        .and_then(|bytes| PublicKey::try_from(bytes).ok())
        .filter(|key| p256::PublicKey::from_sec1_bytes(key).is_ok())
        .ok_or(Error::BadRequest(
            "key must be an uncompressed P-256 public key (base64url)",
        ))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::*;
    use p256::ecdsa::SigningKey;
    use serde_json::Value;

    fn key_b64(k: &SigningKey) -> String {
        URL_SAFE_NO_PAD.encode(public(k))
    }

    fn request(target: &str, sender: &SigningKey, replaces: Option<&str>) -> RegisterRequest {
        RegisterRequest {
            platform: "fcm".into(),
            target: target.into(),
            key_id: "k1".into(),
            sender_key: key_b64(sender),
            replaces: replaces.map(Into::into),
        }
    }

    impl World {
        fn register(&self, req: &RegisterRequest, now: u64) -> Result<Pending, Error> {
            pollster::block_on(self.relay().register(req, Some("203.0.113.7"), now))
        }

        fn confirm(&self, rid: &str, nonce: &str, now: u64) -> Result<Subscription, Error> {
            pollster::block_on(
                self.relay()
                    .confirm(rid, &ConfirmRequest { c: nonce.into() }, now),
            )
        }

        /// The last FCM message sent (a challenge).
        fn last_message(&self) -> Value {
            let requests = self.http.requests.borrow();
            serde_json::from_slice(&requests.last().unwrap().body).unwrap()
        }

        fn last_nonce(&self) -> String {
            self.last_message()["message"]["data"]["c"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    }

    #[test]
    fn challenge_then_confirm_yields_a_working_endpoint() {
        let w = World::new(generous());
        let sender = signer(7);
        w.fcm_replies(&[200]);
        let pending = w.register(&request("fid-a", &sender, None), NOW).unwrap();
        assert_eq!(pending.expires_at, NOW + PENDING_TTL_SECS);

        let challenge = w.last_message();
        assert_eq!(challenge["message"]["fid"], "fid-a");
        assert_eq!(challenge["message"]["data"]["r"], pending.rid.as_str());
        assert_eq!(challenge["message"]["android"]["priority"], "HIGH");
        assert_eq!(challenge["message"]["android"]["ttl"], "60s");
        assert!(challenge["message"]["data"].get("p").is_none());

        let sub = w.confirm(&pending.rid, &w.last_nonce(), NOW + 5).unwrap();
        assert_eq!(sub.endpoint, format!("{ORIGIN}/v1/push/{}", sub.id));
        let stored = pollster::block_on(w.store.get(&EndpointId::parse(&sub.id).unwrap()))
            .unwrap()
            .unwrap();
        assert_eq!(
            (stored.target.as_str(), stored.sender_key),
            ("fid-a", public(&sender))
        );
        // The rid is not an endpoint.
        assert_ne!(sub.id, pending.rid);

        w.fcm_replies(&[200]);
        assert_eq!(w.send(&sub.id, &vapid_header(&sender), None, None), Ok(()));
    }

    #[test]
    fn no_endpoint_without_the_right_answer() {
        let w = World::new(generous());
        let sender = signer(7);
        w.fcm_replies(&[200, 200]);

        // Wrong nonce: refused, and the pending registration is used up.
        let pending = w.register(&request("fid-a", &sender, None), NOW).unwrap();
        let nonce = w.last_nonce();
        assert_eq!(w.confirm(&pending.rid, "guess", NOW), Err(Error::Forbidden));
        assert_eq!(w.confirm(&pending.rid, &nonce, NOW), Err(Error::NotFound));

        // Right nonce, but too late.
        let pending = w.register(&request("fid-a", &sender, None), NOW).unwrap();
        assert_eq!(
            w.confirm(&pending.rid, &w.last_nonce(), NOW + PENDING_TTL_SECS),
            Err(Error::NotFound)
        );

        assert_eq!(w.confirm("unknown", "x", NOW), Err(Error::NotFound));
        // Single use: a confirmed registration can't be confirmed again.
        w.fcm_replies(&[200]);
        let pending = w.register(&request("fid-a", &sender, None), NOW).unwrap();
        let nonce = w.last_nonce();
        assert!(w.confirm(&pending.rid, &nonce, NOW).is_ok());
        assert_eq!(w.confirm(&pending.rid, &nonce, NOW), Err(Error::NotFound));
    }

    #[test]
    fn resend_reuses_the_nonce_up_to_the_limit() {
        let w = World::new(generous());
        let sender = signer(7);
        w.fcm_replies(&[200, 200, 200]);
        let pending = w.register(&request("fid-a", &sender, None), NOW).unwrap();
        let nonce = w.last_nonce();
        for _ in 1..MAX_CHALLENGE_SENDS {
            pollster::block_on(w.relay().resend_challenge(&pending.rid, NOW + 30)).unwrap();
            assert_eq!(w.last_nonce(), nonce);
        }
        assert_eq!(w.fcm_calls(), MAX_CHALLENGE_SENDS as usize);
        assert_eq!(
            pollster::block_on(w.relay().resend_challenge(&pending.rid, NOW + 40)),
            Err(Error::RateLimited {
                retry_after: PENDING_TTL_SECS - 40
            })
        );
        assert_eq!(
            pollster::block_on(
                w.relay()
                    .resend_challenge(&pending.rid, NOW + PENDING_TTL_SECS)
            ),
            Err(Error::NotFound)
        );
        // An answer to any of the resends still works.
        assert!(w.confirm(&pending.rid, &nonce, NOW + 60).is_ok());
    }

    #[test]
    fn rejects_bad_registrations() {
        let w = World::new(generous());
        let sender = signer(7);
        let bad = |change: fn(&mut RegisterRequest)| {
            let mut req = request("fid-a", &sender, None);
            change(&mut req);
            w.register(&req, NOW)
        };
        for change in [
            (|r: &mut RegisterRequest| r.platform = "apns".into()) as fn(&mut RegisterRequest),
            |r| r.platform = "gcm".into(),
            |r| r.target = String::new(),
            |r| r.target = "has space".into(),
            |r| r.target = "t".repeat(257),
            |r| r.key_id = "bad.id".into(),
            |r| r.sender_key = "AAAA".into(),
            |r| r.sender_key = URL_SAFE_NO_PAD.encode([4u8; 65]),
        ] {
            assert!(matches!(bad(change), Err(Error::BadRequest(_))));
        }
        assert_eq!(w.fcm_calls(), 0);

        // The provider doesn't know the target: no pending registration is left behind.
        w.fcm_replies(&[404]);
        assert!(matches!(
            w.register(&request("fid-dead", &sender, None), NOW),
            Err(Error::BadRequest(_))
        ));
        assert!(parse_json::<RegisterRequest>(b"{\"platform\":1}").is_err());
    }

    #[test]
    fn target_rotation_keeps_the_endpoint() {
        let w = World::new(generous());
        let (sender, other) = (signer(7), signer(9));
        let endpoint = w.seed_registration(1, &sender);

        w.fcm_replies(&[200]);
        let pending = w
            .register(&request("fid-new", &sender, Some(&endpoint)), NOW)
            .unwrap();
        let sub = w.confirm(&pending.rid, &w.last_nonce(), NOW).unwrap();
        assert_eq!(sub.id, endpoint);
        let stored = pollster::block_on(w.store.get(&EndpointId::parse(&endpoint).unwrap()))
            .unwrap()
            .unwrap();
        assert_eq!(stored.target, "fid-new");

        w.fcm_replies(&[200]);
        assert_eq!(
            w.send(&endpoint, &vapid_header(&sender), None, None),
            Ok(())
        );
        assert_eq!(w.last_message()["message"]["fid"], "fid-new");

        let unknown = EndpointId::from_random([9; 16]);
        assert_eq!(
            w.register(&request("fid-x", &sender, Some(unknown.as_str())), NOW),
            Err(Error::NotFound)
        );
        assert!(matches!(
            w.register(&request("fid-x", &other, Some(&endpoint)), NOW),
            Err(Error::BadRequest(_))
        ));
    }

    #[test]
    fn unregister_stops_sends_immediately() {
        let w = World::new(generous());
        let sender = signer(7);
        let endpoint = w.seed_registration(1, &sender);
        assert_eq!(pollster::block_on(w.relay().unregister(&endpoint)), Ok(()));
        assert_eq!(
            w.send(&endpoint, &vapid_header(&sender), None, None),
            Err(Error::NotFound)
        );
        assert_eq!(pollster::block_on(w.relay().unregister(&endpoint)), Ok(()));
        assert_eq!(w.fcm_calls(), 0);
    }

    #[test]
    fn rekey_moves_the_binding_to_the_new_key() {
        let w = World::new(generous());
        let (old, new, stranger) = (signer(7), signer(8), signer(9));
        let endpoint = w.seed_registration(1, &old);
        let rekey = |auth: &SigningKey, proof_signer: &SigningKey, k: &SigningKey| {
            let req = RekeyRequest {
                k: key_b64(k),
                t: vapid_token(proof_signer),
            };
            pollster::block_on(
                w.relay()
                    .rekey(&endpoint, Some(&vapid_header(auth)), &req, NOW),
            )
        };

        assert_eq!(rekey(&stranger, &new, &new), Err(Error::Forbidden));
        assert!(matches!(rekey(&old, &old, &new), Err(Error::BadRequest(_))));
        assert_eq!(rekey(&old, &new, &new), Ok(()));

        w.fcm_replies(&[200]);
        assert_eq!(
            w.send(&endpoint, &vapid_header(&old), None, None),
            Err(Error::Forbidden)
        );
        assert_eq!(w.send(&endpoint, &vapid_header(&new), None, None), Ok(()));
    }

    #[test]
    fn registration_limits() {
        let two = crate::relay::RateLimit {
            limit: 2,
            window_secs: 3600,
        };
        let sender = signer(7);

        let w = World::new(crate::relay::RateLimits {
            registrations_per_ip: two,
            ..generous()
        });
        w.fcm_replies(&[200, 200]);
        assert!(w.register(&request("fid-a", &sender, None), NOW).is_ok());
        assert!(w.register(&request("fid-b", &sender, None), NOW).is_ok());
        assert!(matches!(
            w.register(&request("fid-c", &sender, None), NOW),
            Err(Error::RateLimited { .. })
        ));

        // Challenges per target count resends too, so a known FID can't be flooded.
        let w = World::new(crate::relay::RateLimits {
            challenges_per_target: two,
            ..generous()
        });
        w.fcm_replies(&[200, 200, 200]);
        let pending = w.register(&request("fid-a", &sender, None), NOW).unwrap();
        assert!(pollster::block_on(w.relay().resend_challenge(&pending.rid, NOW)).is_ok());
        assert!(matches!(
            w.register(&request("fid-a", &sender, None), NOW),
            Err(Error::RateLimited { .. })
        ));
        assert!(w.register(&request("fid-b", &sender, None), NOW).is_ok());
        assert_eq!(w.fcm_calls(), 3);
    }
}
