//! Rough per-call cost of `vapid::verify` on a real web-push token.
//! Native: `cargo run --release --example vapid_bench -p pushharbor-core`
//! V8/wasm: see `just bench-vapid`.

use std::time::Instant;

fn main() {
    let file: serde_json::Value =
        serde_json::from_str(include_str!("../tests/vectors/vapid.json")).unwrap();
    let v = &file["vectors"][0];
    let (auth, aud) = (
        v["authorization"].as_str().unwrap(),
        v["audience"].as_str().unwrap(),
    );
    let now = v["now"].as_u64().unwrap();

    let run = |n: u32| {
        let start = Instant::now();
        for _ in 0..n {
            pushharbor_core::vapid::verify(auth, aud, now, 86_400).unwrap();
        }
        start.elapsed() / n
    };
    run(200); // warm up (V8 tiers up wasm)
    println!("vapid::verify: {:?} per call", run(2_000));
}
