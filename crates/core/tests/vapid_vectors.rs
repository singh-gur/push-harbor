//! Interop vectors produced by real sender libraries (see `source` in the JSON).

use pushharbor_core::adapter::Crypto;
use pushharbor_core::limits::VAPID_MAX_LIFETIME_SECS;
use pushharbor_core::vapid::{PublicKey, verify, verify_es256_p256};
use serde::Deserialize;

#[derive(Deserialize)]
struct File {
    sub: String,
    max_lifetime_secs: u64,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    authorization: String,
    audience: String,
    now: u64,
    expect: String,
    /// Expected `sub` when it differs from the file-level one (vectors from other libraries).
    sub: Option<String>,
}

struct P256;

impl Crypto for P256 {
    fn random_bytes(&self, _: &mut [u8]) {
        unreachable!("not used by verify")
    }

    async fn verify_es256(&self, key: &PublicKey, message: &[u8], signature: &[u8; 64]) -> bool {
        verify_es256_p256(key, message, signature)
    }

    async fn sign_rs256(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, pushharbor_core::Error> {
        unreachable!("not used here")
    }
}

#[test]
fn vapid_vectors() {
    let file: File = serde_json::from_str(include_str!("vectors/vapid.json")).unwrap();
    assert_eq!(
        file.max_lifetime_secs, VAPID_MAX_LIFETIME_SECS,
        "vectors were built for another limit"
    );
    for v in file.vectors {
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
