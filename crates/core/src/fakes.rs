//! In-memory implementations of every adapter trait, for unit tests here and in the adapters
//! (enable the `fakes` feature).

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};

use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

use crate::adapter::{Clock, Crypto, HttpClient, HttpRequest, HttpResponse, RateLimiter, Store};
use crate::error::Error;
use crate::model::{EndpointId, Registration};
use crate::vapid::PublicKey;

/// Clock that only moves when told to.
pub struct FakeClock(pub Cell<u64>);

impl Clock for FakeClock {
    fn now(&self) -> u64 {
        self.0.get()
    }
}

/// Deterministic "random" bytes (a counter) and real `p256` verification.
#[derive(Default)]
pub struct FakeCrypto {
    next: Cell<u8>,
}

impl Crypto for FakeCrypto {
    fn random_bytes(&self, out: &mut [u8]) {
        for b in out {
            *b = self.next.get();
            self.next.set(self.next.get().wrapping_add(1));
        }
    }

    async fn verify_es256(&self, key: &PublicKey, message: &[u8], signature: &[u8; 64]) -> bool {
        let (Ok(key), Ok(sig)) = (
            VerifyingKey::from_sec1_bytes(key),
            Signature::from_slice(signature),
        ) else {
            return false;
        };
        key.verify(message, &sig).is_ok()
    }
}

#[derive(Default)]
pub struct MemoryStore {
    registrations: RefCell<HashMap<EndpointId, Registration>>,
    idempotency: RefCell<HashMap<(EndpointId, String), (u16, u64)>>,
}

impl Store for MemoryStore {
    async fn get(&self, id: &EndpointId) -> Result<Option<Registration>, Error> {
        Ok(self.registrations.borrow().get(id).cloned())
    }

    async fn put(&self, registration: &Registration) -> Result<(), Error> {
        self.registrations
            .borrow_mut()
            .insert(registration.endpoint.clone(), registration.clone());
        Ok(())
    }

    async fn delete(&self, id: &EndpointId) -> Result<(), Error> {
        self.registrations.borrow_mut().remove(id);
        Ok(())
    }

    async fn idempotent_status(
        &self,
        id: &EndpointId,
        key: &str,
        now: u64,
    ) -> Result<Option<u16>, Error> {
        Ok(self
            .idempotency
            .borrow()
            .get(&(id.clone(), key.to_owned()))
            .filter(|(_, expires_at)| *expires_at > now)
            .map(|(status, _)| *status))
    }

    async fn record_idempotent(
        &self,
        id: &EndpointId,
        key: &str,
        status: u16,
        expires_at: u64,
    ) -> Result<(), Error> {
        self.idempotency
            .borrow_mut()
            .insert((id.clone(), key.to_owned()), (status, expires_at));
        Ok(())
    }
}

/// Fixed-window counters.
#[derive(Default)]
pub struct MemoryRateLimiter {
    windows: RefCell<HashMap<String, (u64, u32)>>,
}

impl RateLimiter for MemoryRateLimiter {
    async fn acquire(
        &self,
        bucket: &str,
        limit: u32,
        window_secs: u64,
        now: u64,
    ) -> Result<(), Error> {
        let mut windows = self.windows.borrow_mut();
        let (start, count) = windows.entry(bucket.to_owned()).or_insert((now, 0));
        if now >= *start + window_secs {
            (*start, *count) = (now, 0);
        }
        if *count >= limit {
            return Err(Error::RateLimited {
                retry_after: *start + window_secs - now,
            });
        }
        *count += 1;
        Ok(())
    }
}

/// Replays queued responses in order and records every request.
#[derive(Default)]
pub struct FakeHttp {
    pub responses: RefCell<VecDeque<Result<HttpResponse, Error>>>,
    pub requests: RefCell<Vec<HttpRequest>>,
}

impl HttpClient for FakeHttp {
    async fn post(&self, request: HttpRequest) -> Result<HttpResponse, Error> {
        self.requests.borrow_mut().push(request);
        self.responses
            .borrow_mut()
            .pop_front()
            .unwrap_or(Err(Error::Internal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{KeyId, Platform};
    use p256::ecdsa::{SigningKey, signature::Signer};

    fn registration(id: &EndpointId) -> Registration {
        Registration {
            endpoint: id.clone(),
            platform: Platform::Fcm,
            target: "fid".into(),
            key_id: KeyId::parse("k1").unwrap(),
            sender_key: [4; 65],
            created_at: 0,
        }
    }

    #[test]
    fn store_and_idempotency_window() {
        pollster::block_on(async {
            let store = MemoryStore::default();
            let id = EndpointId::from_random([1; 16]);
            assert_eq!(store.get(&id).await, Ok(None));
            store.put(&registration(&id)).await.unwrap();
            assert_eq!(store.get(&id).await.unwrap().unwrap().target, "fid");
            store.record_idempotent(&id, "k", 201, 100).await.unwrap();
            assert_eq!(store.idempotent_status(&id, "k", 99).await, Ok(Some(201)));
            assert_eq!(store.idempotent_status(&id, "k", 100).await, Ok(None));
            store.delete(&id).await.unwrap();
            assert_eq!(store.get(&id).await, Ok(None));
        });
    }

    #[test]
    fn rate_limiter_window_and_retry_after() {
        pollster::block_on(async {
            let limiter = MemoryRateLimiter::default();
            assert!(limiter.acquire("b", 2, 60, 1000).await.is_ok());
            assert!(limiter.acquire("b", 2, 60, 1010).await.is_ok());
            assert_eq!(
                limiter.acquire("b", 2, 60, 1020).await,
                Err(Error::RateLimited { retry_after: 40 })
            );
            assert!(limiter.acquire("b", 2, 60, 1060).await.is_ok());
        });
    }

    #[test]
    fn crypto_verifies_real_signatures() {
        pollster::block_on(async {
            let signer = SigningKey::from_slice(&[7; 32]).unwrap();
            let key: PublicKey = signer
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .try_into()
                .unwrap();
            let sig: Signature = signer.sign(b"msg");
            let crypto = FakeCrypto::default();
            assert!(
                crypto
                    .verify_es256(&key, b"msg", &sig.to_bytes().into())
                    .await
            );
            assert!(
                !crypto
                    .verify_es256(&key, b"other", &sig.to_bytes().into())
                    .await
            );
            let mut a = [0; 4];
            crypto.random_bytes(&mut a);
            assert_eq!(a, [0, 1, 2, 3]);
        });
    }

    #[test]
    fn http_replays_and_records() {
        pollster::block_on(async {
            let http = FakeHttp::default();
            let ok = HttpResponse {
                status: 200,
                headers: vec![],
                body: vec![],
            };
            http.responses.borrow_mut().push_back(Ok(ok.clone()));
            let req = HttpRequest {
                url: "https://fcm".into(),
                headers: vec![],
                body: b"x".to_vec(),
            };
            assert_eq!(http.post(req.clone()).await, Ok(ok));
            assert_eq!(http.post(req.clone()).await, Err(Error::Internal));
            assert_eq!(http.requests.borrow().len(), 2);
        });
    }
}
