//! Sender interop (PH-22): unmodified Web Push libraries, configured only as `docs/spec/send.md`
//! says, send to a running relay. The relay must be reachable over HTTPS at its origin (Node's
//! web-push only speaks HTTPS); `just interop-native` sets that up. Env:
//! - `RELAY_URL`: plain-HTTP address used for app-side setup (register/confirm/delete);
//! - `INTEROP_LIBS`: comma-separated subset of `node,python,go,php` (skipped when unset);
//! - `INTEROP_CA`: PEM certificate the senders must trust for the relay origin.
//!
//! Each sender program (`interop/<lib>/`) gets a fixture file (keys, endpoints, payloads), runs
//! the same cases and prints one JSON line per case: `{"case", "status", "retry_after"}`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::SigningKey;
use pushharbor_conformance::*;
use serde_json::{Value, json};

/// Plaintext envelope of exactly `len` bytes (spec: envelope.md).
fn envelope(len: usize) -> String {
    let empty = json!({"t": "Interop", "b": ""}).to_string().len();
    json!({"t": "Interop", "b": "x".repeat(len - empty)}).to_string()
}

const SHORT: &str = r#"{"t":"Hello","b":"from a Web Push library"}"#;
const MAX_PLAINTEXT: usize = MAX_BODY_BYTES - 103;

fn key_pair(k: &SigningKey) -> Value {
    json!({"public": public_key_b64(k), "private": URL_SAFE_NO_PAD.encode(k.to_bytes())})
}

/// RFC 8291 decrypt of one single-record message, as the device does it.
fn decrypt(body: &[u8], ua: &p256::SecretKey, auth: &[u8]) -> Option<String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use hkdf::Hkdf;
    use p256::elliptic_curve::sec1::ToSec1Point;
    use sha2::Sha256;

    let (salt, rest) = body.split_at_checked(16)?;
    let idlen = *rest.get(4)? as usize;
    let as_public = rest.get(5..5 + idlen)?;
    let peer = p256::PublicKey::from_sec1_bytes(as_public).ok()?;
    let shared = p256::ecdh::diffie_hellman(ua.to_nonzero_scalar(), peer.as_affine());
    let ua_public = ua.public_key().to_sec1_point(false);
    let info = [
        b"WebPush: info\0".as_slice(),
        ua_public.as_bytes(),
        as_public,
    ]
    .concat();
    let mut ikm = [0; 32];
    Hkdf::<Sha256>::new(Some(auth), shared.raw_secret_bytes())
        .expand(&info, &mut ikm)
        .ok()?;
    let prk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let (mut cek, mut nonce) = ([0; 16], [0; 12]);
    prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek)
        .ok()?;
    prk.expand(b"Content-Encoding: nonce\0", &mut nonce).ok()?;
    let mut padded = aes_gcm::Aes128Gcm::new_from_slice(&cek)
        .ok()?
        .decrypt(&nonce.into(), rest.get(5 + idlen..)?)
        .ok()?;
    let delimiter = padded.iter().rposition(|&b| b != 0)?;
    (padded[delimiter] == 2).then_some(())?;
    padded.truncate(delimiter);
    String::from_utf8(padded).ok()
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// The command running one library's sender program, with the CA trusted the way each
/// ecosystem documents it (environment only, no library options).
fn sender_command(lib: &str, fixture: &Path, ca: &str) -> Command {
    let root = repo_root();
    let mut cmd = match lib {
        "node" => {
            let mut c = Command::new("node");
            c.arg(root.join("interop/node/send.mjs"))
                .env("NODE_EXTRA_CA_CERTS", ca);
            c
        }
        "python" => {
            let mut c = Command::new("uv");
            c.args(["run", "-q", "--with", "pywebpush==2.5.0", "python"])
                .arg(root.join("interop/python/send.py"))
                .env("REQUESTS_CA_BUNDLE", ca);
            c
        }
        // Built by the just recipe (module downloads must not see the test CA).
        "go" => {
            let mut c = Command::new(root.join("target/interop/go-send"));
            c.env("SSL_CERT_FILE", ca);
            c
        }
        "php" => {
            let mut c = Command::new("docker");
            let mount = format!("{}:/repo:Z", root.display());
            let ca_in = format!(
                "/repo/{}",
                Path::new(ca).strip_prefix(&root).unwrap().display()
            );
            c.args([
                "run",
                "--rm",
                "--network",
                "host",
                "-v",
                &mount,
                "-w",
                "/repo",
            ])
            .args([
                "composer:2",
                "php",
                "-d",
                "error_reporting=E_ALL & ~E_NOTICE & ~E_USER_NOTICE",
            ])
            .arg(format!("-dcurl.cainfo={ca_in}"))
            .arg("interop/php/send.php");
            let fixture = fixture.strip_prefix(&root).unwrap();
            c.arg(format!("/repo/{}", fixture.display()));
            return c;
        }
        other => panic!("unknown library {other}"),
    };
    cmd.arg(fixture);
    cmd
}

#[tokio::test]
async fn sender_libraries() {
    let Ok(libs) = std::env::var("INTEROP_LIBS") else {
        eprintln!("INTEROP_LIBS not set: skipping interop test");
        return;
    };
    let r = Relay::from_env().expect("RELAY_URL");
    let ca = std::env::var("INTEROP_CA").expect("INTEROP_CA");
    let dir = repo_root().join("target/interop");
    std::fs::create_dir_all(&dir).unwrap();

    for lib in libs.split(',').map(str::trim).filter(|l| !l.is_empty()) {
        let (sender, unbound, limited_sender) = (new_sender(), new_sender(), new_sender());
        let ua = p256::SecretKey::from_slice(&random_bytes::<32>()).unwrap();
        let auth = random_bytes::<16>();
        let fid = |prefix: &str| format!("{prefix}-{lib}-{}", random_id());
        let ok = r.subscribe(&sender, &fid("ok")).await;
        let gone = r.subscribe(&sender, &fid("gone")).await;
        let deleted = r.subscribe(&sender, &fid("ok")).await;
        let limited = r.subscribe(&limited_sender, &fid("ok")).await;
        let response = r
            .http
            .delete(format!("{}/v1/push/{}", r.base, deleted.id))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 204);

        let at_cap = envelope(MAX_PLAINTEXT);
        let fixture = json!({
            "subject": "mailto:interop@example.com",
            "vapid": key_pair(&sender),
            "unbound": key_pair(&unbound),
            "limited_vapid": key_pair(&limited_sender),
            "keys": {
                "p256dh": URL_SAFE_NO_PAD.encode(p256::elliptic_curve::sec1::ToSec1Point::to_sec1_point(&ua.public_key(), false).as_bytes()),
                "auth": URL_SAFE_NO_PAD.encode(auth),
            },
            "endpoints": {"ok": ok.endpoint, "gone": gone.endpoint, "deleted": deleted.endpoint, "limited": limited.endpoint},
            "at_cap": at_cap,
            "over_cap": envelope(MAX_PLAINTEXT + 1),
            "short": SHORT,
            "idempotency_key": format!("interop-{lib}-{}", random_id()),
            "expired_exp": now() - 60,
        });
        let path = dir.join(format!("fixture-{lib}.json"));
        std::fs::write(&path, fixture.to_string()).unwrap();

        let output = tokio::task::spawn_blocking({
            let (path, ca, lib) = (path.clone(), ca.clone(), lib.to_owned());
            move || sender_command(&lib, &path, &ca).output()
        })
        .await
        .unwrap()
        .unwrap_or_else(|e| panic!("{lib}: cannot start sender: {e}"));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{lib} sender failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let results: BTreeMap<String, Value> = stdout
            .lines()
            .filter(|l| l.starts_with('{'))
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .map(|v| (v["case"].as_str().unwrap().to_owned(), v))
            .collect();

        // Required everywhere; the optional ones only where the library can express them.
        let mut expected = vec![
            ("at_cap", 201),
            ("over_cap", 413),
            ("no_key", 201),
            ("unbound_key", 403),
            ("gone_first", 410),
            ("gone_second", 404),
            ("deleted", 404),
            ("limited", 429),
        ];
        if lib != "php" {
            expected.extend([("idempotent_first", 201), ("idempotent_repeat", 201)]);
        }
        if matches!(lib, "node" | "python") {
            expected.push(("expired", 401));
        }
        for (case, status) in &expected {
            let got = results
                .get(*case)
                .unwrap_or_else(|| panic!("{lib}: case {case} missing in:\n{stdout}"));
            // webpush-go with RecordSize 2900 refuses an over-cap payload before sending.
            if (lib, *case) == ("go", "over_cap") && got["status"].is_null() {
                assert!(got["error"].is_string(), "{lib}: {case}: {got}");
                continue;
            }
            assert_eq!(got["status"], *status, "{lib}: {case}: {got}");
        }
        let retry_after = results["limited"]["retry_after"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok());
        assert!(
            retry_after.is_some_and(|s| (1..=60).contains(&s)),
            "{lib}: Retry-After not surfaced: {}",
            results["limited"]
        );

        // What reached the device: every accepted send exactly once (the idempotent repeat was
        // not re-sent), byte-for-byte decryptable to what the library encrypted.
        let mut delivered: Vec<String> = r
            .fcm
            .messages_for(&ok.fid)
            .iter()
            .filter_map(|m| m["data"]["p"].as_str())
            .map(|p| {
                decrypt(&URL_SAFE_NO_PAD.decode(p).unwrap(), &ua, &auth)
                    .unwrap_or_else(|| panic!("{lib}: delivered body does not decrypt"))
            })
            .collect();
        delivered.sort();
        let mut want = vec![at_cap.clone(), SHORT.to_owned()];
        if lib != "php" {
            want.push(SHORT.to_owned());
        }
        want.sort();
        assert_eq!(delivered, want, "{lib}: delivered payloads");
        eprintln!("{lib}: {} cases ok", expected.len());
    }
}
