//! Moving between hosting options (PH-23): registrations exported from one relay and imported
//! into another keep working, unchanged for apps and servers. Env: `MIGRATION_RELAYS`, a
//! comma-separated chain `name=url,...` of running relays that all use the origin
//! `MIGRATION_ORIGIN` (as they would behind one domain); skipped when unset. Each relay hands its
//! registrations to the next one, and the last one to the first.

use pushharbor_conformance::*;

fn relay(base: &str, via: &Relay) -> Relay {
    Relay {
        base: base.trim_end_matches('/').to_owned(),
        http: via.http.clone(),
        fcm: via.fcm,
    }
}

#[tokio::test]
async fn registrations_move_between_hosting_options() {
    let (Ok(chain), Ok(origin)) = (
        std::env::var("MIGRATION_RELAYS"),
        std::env::var("MIGRATION_ORIGIN"),
    ) else {
        eprintln!("MIGRATION_RELAYS not set: skipping migration test");
        return;
    };
    record_secret(ADMIN_TOKEN);
    let origin = origin.trim_end_matches('/').to_owned();
    // `Relay::from_env` only to get the shared client and fake FCM.
    // SAFETY: single-threaded at this point; the variable is only read by from_env below.
    unsafe { std::env::set_var("RELAY_URL", &origin) };
    let base = Relay::from_env().unwrap();
    let relays: Vec<(String, Relay)> = chain
        .split(',')
        .map(|entry| {
            let (name, url) = entry.split_once('=').expect("name=url");
            (name.to_owned(), relay(url, &base))
        })
        .collect();

    for (i, (from_name, from)) in relays.iter().enumerate() {
        let (to_name, to) = &relays[(i + 1) % relays.len()];
        let step = format!("{from_name} -> {to_name}");

        // An app registers on the source relay; its server keeps the endpoint URL.
        let sender = new_sender();
        let fid = format!("ok-{}", random_id());
        assert_eq!(
            from.register(&sender, &fid, None).await.status(),
            202,
            "{step}"
        );
        let (nonce, rid) = from.last_challenge(&fid);
        let confirmed: serde_json::Value = from.confirm(&rid, &nonce).await.json().await.unwrap();
        let endpoint = confirmed["endpoint"].as_str().unwrap().to_owned();
        assert!(
            endpoint.starts_with(&origin),
            "{step}: endpoint uses the shared origin"
        );

        let response = from.export(ADMIN_TOKEN).await;
        assert_eq!(response.status(), 200, "{step}: export");
        let file = response.text().await.unwrap();
        let response = to.import(ADMIN_TOKEN, file).await;
        assert_eq!(response.status(), 200, "{step}: import");

        // The server keeps sending to the same URL (VAPID aud = origin); now the destination
        // answers it and the device still gets the message.
        let at_destination = endpoint.replacen(&origin, &to.base, 1);
        let auth = vapid_header(&sender, &origin);
        let response = to
            .push(&at_destination, Some(&auth), &aes128gcm_body(200), &[])
            .await;
        assert_eq!(response.status(), 201, "{step}: send after import");
        let delivered = base
            .fcm
            .messages_for(&fid)
            .iter()
            .filter(|m| m["data"]["p"].is_string())
            .count();
        assert_eq!(delivered, 1, "{step}: delivered to the same device");
        eprintln!("{step}: ok");
    }
}
