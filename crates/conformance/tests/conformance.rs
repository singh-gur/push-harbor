//! Conformance cases (PH-5). Run against a relay configured per the crate docs:
//!   RELAY_URL=http://127.0.0.1:8080 cargo test -p pushharbor-conformance --test conformance
//! Every test uses fresh senders and FIDs, so tests are independent and runs can repeat.

use std::time::Instant;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use pushharbor_conformance::*;
use serde_json::{Value, json};

macro_rules! relay {
    () => {
        match Relay::from_env() {
            Some(relay) => relay,
            None => return,
        }
    };
}

fn fid(prefix: &str) -> String {
    format!("{prefix}-{}", random_id())
}

#[tokio::test]
async fn health() {
    let r = relay!();
    let response = r
        .http
        .get(format!("{}/v1/health", r.base))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn register_confirm_and_deliver() {
    let r = relay!();
    let sender = new_sender();
    let sub = r.subscribe(&sender, &fid("ok")).await;
    assert_eq!(sub.endpoint, format!("{}/v1/push/{}", r.base, sub.id));

    let challenge = r.fcm.messages_for(&sub.fid)[0].clone();
    assert_eq!(challenge["android"]["priority"], "HIGH");
    assert!(
        challenge["data"].get("p").is_none(),
        "a challenge carries no payload"
    );

    let body = aes128gcm_body(512);
    let response = r
        .push(
            &sub.endpoint,
            Some(&vapid_header(&sender, &r.base)),
            &body,
            &[("TTL", "120"), ("Topic", "chat_1")],
        )
        .await;
    assert_eq!(response.status(), 201);

    let delivered = r.fcm.messages_for(&sub.fid).last().unwrap().clone();
    assert_eq!(delivered["fid"], sub.fid.as_str());
    assert_eq!(
        delivered["data"]["p"],
        URL_SAFE_NO_PAD.encode(&body),
        "body must reach FCM byte-exact"
    );
    assert_eq!(delivered["data"]["s"], sub.key_id.as_str());
    assert_eq!(delivered["android"]["ttl"], "120s");
    assert_eq!(delivered["android"]["collapse_key"], "chat_1");
}

#[tokio::test]
async fn payload_cap_boundary() {
    let r = relay!();
    let sender = new_sender();
    let sub = r.subscribe(&sender, &fid("ok")).await;
    let auth = vapid_header(&sender, &r.base);
    assert_eq!(
        r.push(
            &sub.endpoint,
            Some(&auth),
            &aes128gcm_body(MAX_BODY_BYTES),
            &[]
        )
        .await
        .status(),
        201
    );
    assert_eq!(
        r.push(
            &sub.endpoint,
            Some(&auth),
            &aes128gcm_body(MAX_BODY_BYTES + 1),
            &[]
        )
        .await
        .status(),
        413
    );
}

#[tokio::test]
async fn malformed_sends() {
    let r = relay!();
    let sender = new_sender();
    let sub = r.subscribe(&sender, &fid("ok")).await;
    let auth = vapid_header(&sender, &r.base);
    let wrong_encoding = r
        .http
        .post(&sub.endpoint)
        .header("Authorization", &auth)
        .header("Content-Encoding", "aesgcm")
        .body(aes128gcm_body(200))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_encoding.status(), 400);
    assert_eq!(
        r.push(&sub.endpoint, Some(&auth), b"not aes128gcm", &[])
            .await
            .status(),
        400
    );
    assert_eq!(
        r.push(
            &sub.endpoint,
            Some(&auth),
            &aes128gcm_body(200),
            &[("TTL", "-1")]
        )
        .await
        .status(),
        400
    );
    let unknown = format!(
        "{}/v1/push/{}",
        r.base,
        URL_SAFE_NO_PAD.encode(random_bytes::<16>())
    );
    assert_eq!(
        r.push(&unknown, Some(&auth), &aes128gcm_body(200), &[])
            .await
            .status(),
        404
    );
}

#[tokio::test]
async fn vapid_rejections() {
    let r = relay!();
    let sender = new_sender();
    let sub = r.subscribe(&sender, &fid("ok")).await;
    let body = aes128gcm_body(200);
    let key = public_key_b64(&sender);
    let with_token = |t: String| format!("vapid t={t}, k={key}");

    assert_eq!(r.push(&sub.endpoint, None, &body, &[]).await.status(), 401);
    assert_eq!(
        r.push(
            &sub.endpoint,
            Some(&with_token(vapid_token(&sender, &r.base, -60))),
            &body,
            &[]
        )
        .await
        .status(),
        401
    );
    assert_eq!(
        r.push(
            &sub.endpoint,
            Some(&with_token(vapid_token(
                &sender,
                "https://other.example",
                3600
            ))),
            &body,
            &[]
        )
        .await
        .status(),
        401
    );
    assert_eq!(
        r.push(
            &sub.endpoint,
            Some(&with_token(vapid_token(&sender, &r.base, 2 * 86_400))),
            &body,
            &[]
        )
        .await
        .status(),
        401
    );
    // A valid token from a sender this endpoint is not bound to.
    assert_eq!(
        r.push(
            &sub.endpoint,
            Some(&vapid_header(&new_sender(), &r.base)),
            &body,
            &[]
        )
        .await
        .status(),
        403
    );
    // Only the rejections above were attempted: nothing reached FCM besides the challenge.
    assert_eq!(r.fcm.messages_for(&sub.fid).len(), 1);
}

#[tokio::test]
async fn idempotency_key_dedupes() {
    let r = relay!();
    let sender = new_sender();
    let sub = r.subscribe(&sender, &fid("ok")).await;
    let auth = vapid_header(&sender, &r.base);
    let body = aes128gcm_body(200);
    for _ in 0..2 {
        let response = r
            .push(
                &sub.endpoint,
                Some(&auth),
                &body,
                &[("Idempotency-Key", "msg-1")],
            )
            .await;
        assert_eq!(response.status(), 201);
    }
    assert_eq!(
        r.fcm.messages_for(&sub.fid).len(),
        2,
        "challenge + one delivery"
    );
    assert_eq!(
        r.push(
            &sub.endpoint,
            Some(&auth),
            &body,
            &[("Idempotency-Key", "msg-2")]
        )
        .await
        .status(),
        201
    );
    assert_eq!(r.fcm.messages_for(&sub.fid).len(), 3);
}

#[tokio::test]
async fn per_endpoint_limit() {
    let r = relay!();
    let sender = new_sender();
    let sub = r.subscribe(&sender, &fid("ok")).await;
    for _ in 0..LIMITS.per_endpoint.0 {
        assert_eq!(r.push_as(&sub, &sender).await.status(), 201);
    }
    let limited = r.push_as(&sub, &sender).await;
    assert_eq!(limited.status(), 429);
    assert!(limited.headers().contains_key("retry-after"));
}

#[tokio::test]
async fn per_sender_limit() {
    let r = relay!();
    let sender = new_sender();
    let subs = [
        r.subscribe(&sender, &fid("ok")).await,
        r.subscribe(&sender, &fid("ok")).await,
        r.subscribe(&sender, &fid("ok")).await,
    ];
    let mut accepted = 0;
    for i in 0..LIMITS.per_sender.0 {
        // Spread over endpoints so the per-endpoint limit is not what stops us.
        let status = r
            .push_as(&subs[i as usize % subs.len()], &sender)
            .await
            .status();
        accepted += u32::from(status == 201);
    }
    assert_eq!(accepted, LIMITS.per_sender.0);
    assert_eq!(r.push_as(&subs[0], &sender).await.status(), 429);
    // Another sender is unaffected.
    let other = new_sender();
    let other_sub = r.subscribe(&other, &fid("ok")).await;
    assert_eq!(r.push_as(&other_sub, &other).await.status(), 201);
}

#[tokio::test]
async fn provider_error_mapping() {
    let r = relay!();
    let sender = new_sender();
    let gone = r.subscribe(&sender, &fid("gone")).await;
    assert_eq!(r.push_as(&gone, &sender).await.status(), 410);
    assert_eq!(
        r.push_as(&gone, &sender).await.status(),
        404,
        "a gone device's endpoint is deleted"
    );

    let throttled = r.subscribe(&sender, &fid("throttle")).await;
    let response = r.push_as(&throttled, &sender).await;
    assert_eq!(response.status(), 429);
    assert_eq!(response.headers()["retry-after"], "7");

    let down = r.subscribe(&sender, &fid("down")).await;
    assert_eq!(r.push_as(&down, &sender).await.status(), 503);

    // A target FCM never knew can't even be registered.
    assert_eq!(r.register(&sender, &fid("dead"), None).await.status(), 400);
}

#[tokio::test]
async fn provider_timeout() {
    let r = relay!();
    let sender = new_sender();
    let fid = fid("slow");
    // The challenge itself is slow too, so register directly and expect the relay to give up.
    let started = Instant::now();
    let response = r.register(&sender, &fid, None).await;
    assert_eq!(response.status(), 503);
    assert!(
        started.elapsed().as_secs() <= MAX_PROVIDER_TIMEOUT_SECS + 2,
        "took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn challenge_rules() {
    let r = relay!();
    let sender = new_sender();
    let target = fid("ok");

    // Wrong answer: refused and the pending registration is gone.
    assert_eq!(r.register(&sender, &target, None).await.status(), 202);
    let (nonce, rid) = r.last_challenge(&target);
    assert_eq!(r.confirm(&rid, "wrong").await.status(), 403);
    assert_eq!(r.confirm(&rid, &nonce).await.status(), 404);

    // Resends reuse the nonce, up to 3 sends in total.
    let target = fid("ok");
    assert_eq!(r.register(&sender, &target, None).await.status(), 202);
    let (nonce, rid) = r.last_challenge(&target);
    for _ in 0..2 {
        assert_eq!(
            r.post_json(&format!("/v1/registrations/{rid}/challenge"), json!({}))
                .await
                .status(),
            202
        );
    }
    assert_eq!(
        r.post_json(&format!("/v1/registrations/{rid}/challenge"), json!({}))
            .await
            .status(),
        429
    );
    assert_eq!(r.fcm.messages_for(&target).len(), 3);
    assert_eq!(r.confirm(&rid, &nonce).await.status(), 201);

    // Bad input never reaches FCM.
    let bad = r.post_json("/v1/registrations", json!({"platform": "fcm", "target": "x y", "key_id": "k1", "sender_key": public_key_b64(&sender)})).await;
    assert_eq!(bad.status(), 400);
    let apns = r.post_json("/v1/registrations", json!({"platform": "apns", "target": "abc", "key_id": "k1", "sender_key": public_key_b64(&sender)})).await;
    assert_eq!(apns.status(), 400);
    let error: Value = apns.json().await.unwrap();
    assert_eq!(error["error"], "bad_request");
}

#[tokio::test]
async fn challenges_per_target_limit() {
    let r = relay!();
    let sender = new_sender();
    let target = fid("ok");
    for _ in 0..LIMITS.challenges_per_target.0 {
        assert_eq!(r.register(&sender, &target, None).await.status(), 202);
    }
    assert_eq!(r.register(&sender, &target, None).await.status(), 429);
}

#[tokio::test]
async fn unregister_and_rotate() {
    let r = relay!();
    let sender = new_sender();

    let sub = r.subscribe(&sender, &fid("ok")).await;
    assert_eq!(
        r.http.delete(&sub.endpoint).send().await.unwrap().status(),
        204
    );
    assert_eq!(r.push_as(&sub, &sender).await.status(), 404);

    let sub = r.subscribe(&sender, &fid("ok")).await;
    let new_fid = fid("ok");
    assert_eq!(
        r.register(&sender, &new_fid, Some(&sub.id)).await.status(),
        202
    );
    let (nonce, rid) = r.last_challenge(&new_fid);
    let confirmed: Value = r.confirm(&rid, &nonce).await.json().await.unwrap();
    assert_eq!(
        confirmed["id"],
        sub.id.as_str(),
        "rotation keeps the endpoint"
    );
    assert_eq!(r.push_as(&sub, &sender).await.status(), 201);
    assert_eq!(
        r.fcm.messages_for(&new_fid).len(),
        2,
        "challenge + delivery go to the new FID"
    );
}

#[tokio::test]
async fn server_rekey() {
    let r = relay!();
    let (old, new) = (new_sender(), new_sender());
    let sub = r.subscribe(&old, &fid("ok")).await;
    let rekey = r
        .http
        .post(format!("{}/rekey", sub.endpoint))
        .header("Authorization", vapid_header(&old, &r.base))
        .json(&json!({"k": public_key_b64(&new), "t": vapid_token(&new, &r.base, 3600)}))
        .send()
        .await
        .unwrap();
    assert_eq!(rekey.status(), 204);
    assert_eq!(r.push_as(&sub, &old).await.status(), 403);
    assert_eq!(r.push_as(&sub, &new).await.status(), 201);
}

#[tokio::test]
async fn export_import_round_trip() {
    let r = relay!();
    record_secret(ADMIN_TOKEN);
    let sender = new_sender();
    let sub = r.subscribe(&sender, &fid("ok")).await;

    // The admin API needs the token.
    assert_eq!(r.export("wrong-token").await.status(), 403);
    let response = r
        .http
        .get(format!("{}/v1/admin/export", r.base))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);

    let response = r.export(ADMIN_TOKEN).await;
    assert_eq!(response.status(), 200);
    let file = response.text().await.unwrap();
    let mut lines = file.lines();
    let header: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    assert_eq!(header["format"], "pushharbor-registrations");
    assert_eq!(header["version"], 1);
    assert_eq!(header["origin"], r.base.as_str());
    let line: Value = lines
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|l| l["id"] == sub.id.as_str())
        .expect("subscription exported");
    assert_eq!(line["platform"], "fcm");
    assert_eq!(line["target"], sub.fid.as_str());
    assert_eq!(line["key_id"], "k1");
    assert_eq!(line["sender_key"], public_key_b64(&sender).as_str());
    let header = file.lines().next().unwrap().to_owned();

    // A registration created only by import works like any other.
    let new_id = URL_SAFE_NO_PAD.encode(random_bytes::<16>());
    let new_fid = fid("ok");
    record_secret(&new_id);
    let new_line = json!({"id": new_id, "platform": "fcm", "target": new_fid, "key_id": "k2",
        "sender_key": public_key_b64(&sender), "created_at": now()})
    .to_string();
    let endpoint = format!("{}/v1/push/{new_id}", r.base);

    // Invalid files import nothing, and say which line is wrong.
    let response = r
        .import(ADMIN_TOKEN, format!("{header}\n{new_line}\nnot json\n"))
        .await;
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(
        (body["error"].as_str(), body["line"].as_u64()),
        (Some("bad_request"), Some(3))
    );
    assert_eq!(r.push_as_to(&endpoint, &sender).await.status(), 404);
    let other_origin = header.replace(&r.base, "https://other.example");
    let response = r
        .import(ADMIN_TOKEN, format!("{other_origin}\n{new_line}\n"))
        .await;
    assert_eq!(response.status(), 400);
    assert_eq!(
        r.import("wrong-token", format!("{header}\n{new_line}\n"))
            .await
            .status(),
        403
    );

    let response = r
        .import(ADMIN_TOKEN, format!("{header}\n{new_line}\n"))
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.json::<Value>().await.unwrap()["imported"], 1);
    assert_eq!(r.push_as_to(&endpoint, &sender).await.status(), 201);
    let delivered = r.fcm.messages_for(&new_fid);
    assert_eq!(delivered.last().unwrap()["data"]["s"], "k2");

    // Re-importing an exported line is harmless; the endpoint keeps working. (Only this test's
    // line: other tests run in parallel and an import overwrites with the exported state.)
    let own_line = file.lines().find(|l| l.contains(&sub.id)).unwrap();
    let response = r
        .import(ADMIN_TOKEN, format!("{header}\n{own_line}\n"))
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(r.push_as(&sub, &sender).await.status(), 201);
}
