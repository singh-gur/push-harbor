//! Send latency through a running relay (PH-26 cost check), skipped unless `BENCH_SENDS` is set.
//! Start the relay with limits out of reach, e.g. PUSHHARBOR_LIMIT_PER_ENDPOINT=1000000/60 and
//! PUSHHARBOR_LIMIT_PER_SENDER=1000000/60. Prints p50/p90/p99 of sequential sends.

use std::time::Instant;

use pushharbor_conformance::*;

#[tokio::test]
async fn send_latency() {
    let Some(sends) = std::env::var("BENCH_SENDS")
        .ok()
        .and_then(|n| n.parse::<usize>().ok())
    else {
        return;
    };
    let r = Relay::from_env().expect("RELAY_URL");
    let sender = new_sender();
    let sub = r.subscribe(&sender, &format!("ok-{}", random_id())).await;
    let auth = vapid_header(&sender, &r.base);
    let body = aes128gcm_body(2900);
    let mut micros = Vec::with_capacity(sends);
    for i in 0..sends + 50 {
        let started = Instant::now();
        let response = r.push(&sub.endpoint, Some(&auth), &body, &[]).await;
        assert_eq!(response.status(), 201);
        if i >= 50 {
            micros.push(started.elapsed().as_micros());
        }
    }
    micros.sort_unstable();
    let p = |q: f64| micros[((micros.len() - 1) as f64 * q) as usize];
    eprintln!(
        "{sends} sends: p50 {} us, p90 {} us, p99 {} us",
        p(0.5),
        p(0.9),
        p(0.99)
    );
}
