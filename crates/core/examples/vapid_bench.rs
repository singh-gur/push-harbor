//! Rough per-call cost of `vapid::verify` on a real web-push token.
//! Native: `cargo run --release --example vapid_bench -p pushharbor-core`
//! V8/wasm: see `just bench-vapid`.

use std::time::Instant;

use pushharbor_core::adapter::Crypto;
use pushharbor_core::vapid::{PublicKey, verify, verify_es256_p256};

/// The pure-Rust verifier a native adapter would use.
struct P256;

impl Crypto for P256 {
    fn random_bytes(&self, _: &mut [u8]) {}

    async fn verify_es256(&self, key: &PublicKey, message: &[u8], signature: &[u8; 64]) -> bool {
        verify_es256_p256(key, message, signature)
    }

    async fn sign_rs256(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, pushharbor_core::Error> {
        unreachable!("not used here")
    }
}

fn main() {
    let file: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/spec/vectors/vapid.json")).unwrap();
    let v = &file["vectors"][0];
    let (auth, aud) = (
        v["authorization"].as_str().unwrap(),
        v["audience"].as_str().unwrap(),
    );
    let now = v["now"].as_u64().unwrap();

    let run = |n: u32| {
        let start = Instant::now();
        for _ in 0..n {
            pollster::block_on(verify(auth, aud, now, &P256)).unwrap();
        }
        start.elapsed() / n
    };
    run(200); // warm up (V8 tiers up wasm)
    println!("vapid::verify: {:?} per call", run(2_000));
}
