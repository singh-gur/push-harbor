//! PH-21 spike: Web Push-shaped send → VAPID check → FCM HTTP v1, with the Google OAuth access
//! token minted (RS256 via WebCrypto) and cached in a Durable Object.
//!
//! `POST /send?fid=<FID>` (or `?token=<legacy registration token>`)
//! with `Authorization: vapid t=…, k=…` and the RFC 8291 `aes128gcm` body.
//! Responds 201 when FCM accepted the message, otherwise FCM's status, plus JSON diagnostics.

use std::cell::RefCell;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use worker::js_sys::{self, Array, Function, Object, Promise, Reflect, Uint8Array};
use worker::wasm_bindgen::JsCast;
use worker::wasm_bindgen_futures::JsFuture;
use worker::*;

/// RFC 8292 caps `exp` at 24 h; 5 min of clock-skew allowance (decision pending in PH-9).
const VAPID_MAX_LIFETIME: u64 = 24 * 3600 + 300;
/// Refresh the OAuth token this long before it expires.
const TOKEN_REFRESH_MARGIN: u64 = 300;

#[derive(Deserialize)]
struct ServiceAccount {
    project_id: String,
    client_email: String,
    private_key: String,
    token_uri: String,
}

#[derive(Serialize, Deserialize)]
struct AccessToken {
    access_token: String,
    project_id: String,
    cache: String,
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    if req.method() != Method::Post || req.path() != "/send" {
        return Response::error("not found", 404);
    }
    send(req, env).await
}

async fn send(mut req: Request, env: Env) -> Result<Response> {
    let url = req.url()?;
    let Some((field, target)) = url
        .query_pairs()
        .find(|(k, _)| k == "fid" || k == "token")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
    else {
        return Response::error("missing ?fid=", 400);
    };

    let origin = env.var("RELAY_ORIGIN")?.to_string();
    let auth = req.headers().get("Authorization")?.unwrap_or_default();
    let now = Date::now().as_millis() / 1000;
    if let Err(e) = pushharbor_core::vapid::verify(&auth, &origin, now, VAPID_MAX_LIFETIME) {
        return Response::error(format!("vapid: {e:?}"), 401);
    }
    let body = req.bytes().await?;

    // Date.now() only advances across I/O in Workers, so these are wall times of the two hops.
    let t0 = Date::now().as_millis();
    let stub = env
        .durable_object("FCM_TOKEN")?
        .id_from_name("fcm")?
        .get_stub()?;
    let token: AccessToken = stub
        .fetch_with_str("https://do/token")
        .await?
        .json()
        .await?;
    let t1 = Date::now().as_millis();

    let mut message = Map::new();
    message.insert(field, Value::String(target));
    message.insert("data".into(), json!({ "p": URL_SAFE_NO_PAD.encode(&body) }));
    message.insert("android".into(), json!({ "priority": "HIGH" }));
    let headers = Headers::new();
    headers.set("Authorization", &format!("Bearer {}", token.access_token))?;
    headers.set("Content-Type", "application/json")?;
    let mut fcm = post(
        &format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            token.project_id
        ),
        headers,
        json!({ "message": message }).to_string(),
    )
    .await?;
    let t2 = Date::now().as_millis();

    let fcm_status = fcm.status_code();
    let fcm_body: Value = fcm.json().await.unwrap_or(Value::Null);
    let status = if fcm_status == 200 { 201 } else { fcm_status };
    Ok(Response::from_json(&json!({
        "fcm_status": fcm_status,
        "fcm": fcm_body,
        "token_cache": token.cache,
        "do_ms": t1 - t0,
        "fcm_ms": t2 - t1,
    }))?
    .with_status(status))
}

/// Holds the FCM OAuth access token for the whole deployment (one instance, `id_from_name("fcm")`).
#[durable_object]
pub struct FcmToken {
    env: Env,
    cached: RefCell<Option<(String, u64)>>,
}

impl DurableObject for FcmToken {
    fn new(_state: State, env: Env) -> Self {
        Self {
            env,
            cached: RefCell::new(None),
        }
    }

    async fn fetch(&self, _req: Request) -> Result<Response> {
        let sa: ServiceAccount =
            serde_json::from_str(&self.env.secret("FCM_SERVICE_ACCOUNT")?.to_string())?;
        let now = Date::now().as_millis() / 1000;
        let reply = |access_token: String, cache: &str| AccessToken {
            access_token,
            project_id: sa.project_id.clone(),
            cache: cache.into(),
        };
        let hit = self
            .cached
            .borrow()
            .clone()
            .filter(|(_, exp)| *exp > now + TOKEN_REFRESH_MARGIN);
        if let Some((token, _)) = hit {
            return Response::from_json(&reply(token, "hit"));
        }
        // shortcut: memory only and no single-flight; concurrent cold requests may each mint a
        // token, and an evicted object mints again. Fine at one mint per hour.
        let (token, ttl) = mint(&sa, now).await?;
        *self.cached.borrow_mut() = Some((token.clone(), now + ttl));
        Response::from_json(&reply(token, "miss"))
    }
}

/// Google service-account OAuth (RFC 7523 JWT bearer grant).
async fn mint(sa: &ServiceAccount, now: u64) -> Result<(String, u64)> {
    let claims = json!({
        "iss": sa.client_email,
        "scope": "https://www.googleapis.com/auth/firebase.messaging",
        "aud": sa.token_uri,
        "iat": now,
        "exp": now + 3600,
    });
    let unsigned = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = rs256_sign(&pem_to_der(&sa.private_key)?, unsigned.as_bytes()).await?;
    let headers = Headers::new();
    headers.set("Content-Type", "application/x-www-form-urlencoded")?;
    // The assertion is base64url + '.', so it needs no form encoding.
    let form = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={unsigned}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    );
    let mut res = post(&sa.token_uri, headers, form).await?;
    if res.status_code() != 200 {
        return Err(Error::RustError(format!(
            "oauth {}: {}",
            res.status_code(),
            res.text().await?
        )));
    }
    #[derive(Deserialize)]
    struct Grant {
        access_token: String,
        expires_in: u64,
    }
    let grant: Grant = res.json().await?;
    Ok((grant.access_token, grant.expires_in))
}

/// RSASSA-PKCS1-v1_5 / SHA-256 via the runtime's WebCrypto (native code, not wasm).
async fn rs256_sign(pkcs8: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let subtle = Reflect::get(
        &Reflect::get(&js_sys::global(), &"crypto".into())?,
        &"subtle".into(),
    )?;
    let algorithm = Object::new();
    Reflect::set(&algorithm, &"name".into(), &"RSASSA-PKCS1-v1_5".into())?;
    Reflect::set(&algorithm, &"hash".into(), &"SHA-256".into())?;
    let call = |method: &str, args: Array| -> Result<JsFuture> {
        let function: Function = Reflect::get(&subtle, &method.into())?.dyn_into()?;
        Ok(JsFuture::from(
            function.apply(&subtle, &args)?.dyn_into::<Promise>()?,
        ))
    };
    let key = call(
        "importKey",
        Array::of5(
            &"pkcs8".into(),
            &Uint8Array::from(pkcs8),
            &algorithm,
            &false.into(),
            &Array::of1(&"sign".into()),
        ),
    )?
    .await?;
    let signature = call(
        "sign",
        Array::of3(&algorithm, &key, &Uint8Array::from(data)),
    )?
    .await?;
    Ok(Uint8Array::new(&signature).to_vec())
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    STANDARD
        .decode(body.trim())
        .map_err(|e| Error::RustError(format!("private_key: {e}")))
}

async fn post(url: &str, headers: Headers, body: String) -> Result<Response> {
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(body.into()));
    Fetch::Request(Request::new_with_init(url, &init)?)
        .send()
        .await
}
