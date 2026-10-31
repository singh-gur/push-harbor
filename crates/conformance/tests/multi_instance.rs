//! Two relay instances on one shared database (PH-26) must behave like one relay: rate limits,
//! idempotency and pending registrations are shared. Env: `RELAY_URL` (instance A, also the
//! origin both use) and `RELAY_URL_2` (instance B); skipped when `RELAY_URL_2` is unset.

use pushharbor_conformance::*;

fn instances() -> Option<(Relay, Relay)> {
    let second = std::env::var("RELAY_URL_2").ok()?;
    let a = Relay::from_env()?;
    let b = Relay {
        base: second.trim_end_matches('/').to_owned(),
        http: a.http.clone(),
        fcm: a.fcm,
    };
    Some((a, b))
}

fn fid() -> String {
    format!("ok-{}", random_id())
}

/// The endpoint URL as served by the other instance (same path, other address).
fn via(relay: &Relay, origin: &Relay, sub: &Subscription) -> String {
    sub.endpoint.replacen(&origin.base, &relay.base, 1)
}

#[tokio::test]
async fn rate_limits_are_shared() {
    let Some((a, b)) = instances() else { return };
    let sender = new_sender();
    let sub = a.subscribe(&sender, &fid()).await;
    let (limit, _) = LIMITS.per_endpoint;
    for i in 0..limit {
        let relay = if i % 2 == 0 { &a } else { &b };
        let response = relay
            .push(
                &via(relay, &a, &sub),
                Some(&vapid_header(&sender, &a.base)),
                &aes128gcm_body(200),
                &[],
            )
            .await;
        assert_eq!(response.status(), 201, "send {i}");
    }
    for relay in [&a, &b] {
        let response = relay
            .push(
                &via(relay, &a, &sub),
                Some(&vapid_header(&sender, &a.base)),
                &aes128gcm_body(200),
                &[],
            )
            .await;
        assert_eq!(
            response.status(),
            429,
            "the other instance must see the same count"
        );
        assert!(response.headers().contains_key("retry-after"));
    }
}

#[tokio::test]
async fn idempotency_is_shared() {
    let Some((a, b)) = instances() else { return };
    let sender = new_sender();
    let sub = a.subscribe(&sender, &fid()).await;
    let key = format!("multi-{}", random_id());
    let headers = [("Idempotency-Key", key.as_str())];
    for relay in [&a, &b] {
        let response = relay
            .push(
                &via(relay, &a, &sub),
                Some(&vapid_header(&sender, &a.base)),
                &aes128gcm_body(200),
                &headers,
            )
            .await;
        assert_eq!(response.status(), 201);
    }
    let delivered = a
        .fcm
        .messages_for(&sub.fid)
        .iter()
        .filter(|m| m["data"]["p"].is_string())
        .count();
    assert_eq!(
        delivered, 1,
        "the repeat on the other instance must not be delivered again"
    );
}

#[tokio::test]
async fn registration_can_finish_on_another_instance() {
    let Some((a, b)) = instances() else { return };
    let sender = new_sender();
    let target = fid();
    assert_eq!(a.register(&sender, &target, None).await.status(), 202);
    let (nonce, rid) = a.last_challenge(&target);
    let response = b.confirm(&rid, &nonce).await;
    assert_eq!(response.status(), 201);
    let body: serde_json::Value = response.json().await.unwrap();
    // Issued by B, valid on A.
    let endpoint = body["endpoint"].as_str().unwrap();
    let response = a
        .push(
            endpoint,
            Some(&vapid_header(&sender, &a.base)),
            &aes128gcm_body(200),
            &[],
        )
        .await;
    assert_eq!(response.status(), 201);
    // Confirm is single use across instances too.
    assert_eq!(a.confirm(&rid, &nonce).await.status(), 404);
}
