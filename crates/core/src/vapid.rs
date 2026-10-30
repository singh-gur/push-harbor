//! VAPID sender authentication (RFC 8292): parse `Authorization: vapid t=<jwt>, k=<key>`
//! and verify the ES256 JWT.
//!
//! Only the RFC 8292 `vapid` scheme is accepted. The legacy draft form
//! (`Authorization: WebPush <jwt>` + `Crypto-Key: p256ecdsa=<key>`) is only emitted
//! together with the old `aesgcm` content encoding, which the relay rejects anyway.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::Deserialize;

use crate::adapter::Crypto;
use crate::error::Error;
use crate::limits::VAPID_MAX_LIFETIME_SECS;

/// Uncompressed SEC1 P-256 public key, as sent in `k=`.
pub type PublicKey = [u8; 65];

/// A successfully verified VAPID token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vapid {
    /// Sender identity: the key bound to the endpoint, and the per-sender rate-limit key.
    pub public_key: PublicKey,
    pub sub: String,
    pub exp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VapidError {
    /// Header is missing or uses another scheme (e.g. legacy `WebPush`).
    NotVapid,
    /// `t=` or `k=` missing or unparsable.
    MalformedHeader,
    InvalidKey,
    MalformedToken,
    UnsupportedAlgorithm,
    BadSignature,
    WrongAudience,
    Expired,
    LifetimeTooLong,
    MissingSubject,
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
}

#[derive(Deserialize)]
struct Claims {
    aud: String,
    exp: u64,
    sub: Option<String>,
}

/// A structurally valid ES256 token whose signature has not been checked yet.
#[derive(Debug)]
pub struct Token<'a> {
    pub public_key: PublicKey,
    signed: &'a str,
    claims: &'a str,
    signature: [u8; 64],
}

/// Parses `Authorization: vapid t=<jwt>, k=<key>` without any signature work.
pub fn parse(authorization: &str) -> Result<Token<'_>, VapidError> {
    use VapidError::*;

    let (token, key) = parse_header(authorization)?;
    let public_key: PublicKey = b64(key)
        .and_then(|bytes| bytes.try_into().ok())
        .filter(|key: &PublicKey| key[0] == 4)
        .ok_or(InvalidKey)?;
    let (signed, signature) = token.rsplit_once('.').ok_or(MalformedToken)?;
    let (header, claims) = signed.split_once('.').ok_or(MalformedToken)?;
    let header: JwtHeader = json(header)?;
    if header.alg != "ES256" {
        return Err(UnsupportedAlgorithm);
    }
    let signature = b64(signature)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(MalformedToken)?;
    Ok(Token {
        public_key,
        signed,
        claims,
        signature,
    })
}

/// Verifies a VAPID header for `audience` (the relay origin, `https://host[:port]`) at unix time
/// `now`, using the adapter's ES256 implementation. Accepts `exp` up to
/// [`VAPID_MAX_LIFETIME_SECS`] ahead.
pub async fn verify(
    authorization: &str,
    audience: &str,
    now: u64,
    crypto: &impl Crypto,
) -> Result<Vapid, VapidError> {
    check(parse(authorization)?, audience, now, crypto).await
}

/// [`verify`] plus endpoint binding: only the key bound at registration may send (RFC 8292
/// section 4.2). A different key gets 403 before any signature work; invalid tokens get 401.
pub async fn authorize(
    authorization: &str,
    audience: &str,
    now: u64,
    bound: &PublicKey,
    crypto: &impl Crypto,
) -> Result<Vapid, Error> {
    let token = parse(authorization)?;
    if token.public_key != *bound {
        return Err(Error::Forbidden);
    }
    Ok(check(token, audience, now, crypto).await?)
}

async fn check(
    token: Token<'_>,
    audience: &str,
    now: u64,
    crypto: &impl Crypto,
) -> Result<Vapid, VapidError> {
    use VapidError::*;

    if !crypto
        .verify_es256(&token.public_key, token.signed.as_bytes(), &token.signature)
        .await
    {
        return Err(BadSignature);
    }
    // Claims are only trusted after the signature check.
    let claims: Claims = json(token.claims)?;
    if claims.aud != audience {
        return Err(WrongAudience);
    }
    if claims.exp <= now {
        return Err(Expired);
    }
    if claims.exp - now > VAPID_MAX_LIFETIME_SECS {
        return Err(LifetimeTooLong);
    }
    let sub = claims
        .sub
        .filter(|sub| !sub.is_empty())
        .ok_or(MissingSubject)?;
    Ok(Vapid {
        public_key: token.public_key,
        sub,
        exp: claims.exp,
    })
}

/// Pure-Rust ES256 verification for native adapters and tests. Workers should use WebCrypto
/// instead (PH-21: cheaper CPU). Accepts high-S signatures (P-256 does not normalize S).
pub fn verify_es256_p256(key: &PublicKey, message: &[u8], signature: &[u8; 64]) -> bool {
    let (Ok(key), Ok(signature)) = (
        VerifyingKey::from_sec1_bytes(key),
        Signature::from_slice(signature),
    ) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

/// Returns `(t, k)`. Auth params are comma-separated, names case-insensitive, values may be quoted.
fn parse_header(value: &str) -> Result<(&str, &str), VapidError> {
    let (scheme, params) = value.trim().split_once(' ').ok_or(VapidError::NotVapid)?;
    if !scheme.eq_ignore_ascii_case("vapid") {
        return Err(VapidError::NotVapid);
    }
    let (mut t, mut k) = (None, None);
    for param in params.split(',') {
        let (name, value) = param.split_once('=').ok_or(VapidError::MalformedHeader)?;
        let value = value.trim().trim_matches('"');
        match name.trim() {
            n if n.eq_ignore_ascii_case("t") => t = Some(value),
            n if n.eq_ignore_ascii_case("k") => k = Some(value),
            _ => {}
        }
    }
    t.zip(k).ok_or(VapidError::MalformedHeader)
}

/// base64url, tolerating `=` padding some encoders add.
fn b64(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')).ok()
}

fn json<T: for<'de> Deserialize<'de>>(segment: &str) -> Result<T, VapidError> {
    b64(segment)
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or(VapidError::MalformedToken)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakes::FakeCrypto;
    use p256::ecdsa::{SigningKey, signature::Signer};

    const AUD: &str = "https://relay.example";
    const NOW: u64 = 1_800_000_000;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn token(signer: &SigningKey, alg: &str, claims: &str) -> (String, Signature) {
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(format!(r#"{{"typ":"JWT","alg":"{alg}"}}"#)),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let signature: Signature = signer.sign(signed.as_bytes());
        (signed, signature)
    }

    fn header(signed: &str, signature: &Signature, k: &SigningKey) -> String {
        let k = k.verifying_key().to_sec1_point(false);
        format!(
            "vapid t={signed}.{}, k={}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            URL_SAFE_NO_PAD.encode(k.as_bytes())
        )
    }

    fn claims(aud: &str, exp: u64) -> String {
        format!(r#"{{"aud":"{aud}","exp":{exp},"sub":"mailto:ops@example.com"}}"#)
    }

    fn run(auth: &str) -> Result<Vapid, VapidError> {
        pollster::block_on(verify(auth, AUD, NOW, &FakeCrypto::default()))
    }

    fn public(k: &SigningKey) -> PublicKey {
        k.verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    #[test]
    fn accepts_valid_token() {
        let k = key(7);
        let (signed, sig) = token(&k, "ES256", &claims(AUD, NOW + 3600));
        let vapid = run(&header(&signed, &sig, &k)).unwrap();
        assert_eq!(vapid.sub, "mailto:ops@example.com");
        assert_eq!(vapid.exp, NOW + 3600);
        assert_eq!(
            vapid.public_key.as_slice(),
            k.verifying_key().to_sec1_point(false).as_bytes()
        );
    }

    #[test]
    fn accepts_both_s_forms() {
        // Senders may emit high-S or low-S signatures; both are valid ECDSA.
        let k = key(7);
        let (signed, sig) = token(&k, "ES256", &claims(AUD, NOW + 3600));
        let (r, s) = sig.split_scalars();
        let flipped = Signature::from_scalars(r.to_bytes(), (-s).to_bytes()).unwrap();
        assert!(run(&header(&signed, &sig, &k)).is_ok());
        assert!(run(&header(&signed, &flipped, &k)).is_ok());
    }

    #[test]
    fn header_syntax_variants() {
        let k = key(7);
        let (signed, sig) = token(&k, "ES256", &claims(AUD, NOW + 3600));
        let auth = header(&signed, &sig, &k);
        let (t, kk) = auth["vapid ".len()..].split_once(", ").unwrap();
        let variants = [
            format!("VAPID {t},{kk}"),
            format!("vapid {kk}, {t}"),
            format!(r#"vapid t="{}", k="{}=""#, &t[2..], &kk[2..]),
        ];
        for v in variants {
            assert!(run(&v).is_ok(), "{v}");
        }
    }

    #[test]
    fn rejects() {
        let k = key(7);
        let other = key(9);
        let good = |c: &str| {
            let (signed, sig) = token(&k, "ES256", c);
            header(&signed, &sig, &k)
        };
        let (signed, sig) = token(&k, "ES256", &claims(AUD, NOW + 3600));
        let (hs_signed, hs_sig) = token(&k, "HS256", &claims(AUD, NOW + 3600));
        let tampered = {
            let (h, _) = signed.split_once('.').unwrap();
            let forged = URL_SAFE_NO_PAD.encode(claims(AUD, NOW + 7200));
            header(&format!("{h}.{forged}"), &sig, &k)
        };
        let cases = [
            (String::new(), VapidError::NotVapid),
            (format!("WebPush {signed}"), VapidError::NotVapid),
            ("vapid t=abc".into(), VapidError::MalformedHeader),
            (format!("vapid t={signed}, k=AAAA"), VapidError::InvalidKey),
            // Right length and prefix but not a curve point: the crypto adapter rejects it.
            (
                format!(
                    "vapid t={signed}.{}, k={}",
                    URL_SAFE_NO_PAD.encode(sig.to_bytes()),
                    URL_SAFE_NO_PAD.encode([4u8; 65])
                ),
                VapidError::BadSignature,
            ),
            (header(&signed, &sig, &other), VapidError::BadSignature),
            (tampered, VapidError::BadSignature),
            (
                header(&hs_signed, &hs_sig, &k),
                VapidError::UnsupportedAlgorithm,
            ),
            (
                good(&claims("https://evil.example", NOW + 60)),
                VapidError::WrongAudience,
            ),
            (good(&claims(AUD, NOW)), VapidError::Expired),
            (
                good(&claims(AUD, NOW + VAPID_MAX_LIFETIME_SECS + 1)),
                VapidError::LifetimeTooLong,
            ),
            (
                good(&format!(r#"{{"aud":"{AUD}","exp":{}}}"#, NOW + 60)),
                VapidError::MissingSubject,
            ),
        ];
        for (auth, want) in cases {
            assert_eq!(run(&auth), Err(want), "{auth}");
        }
        assert!(run(&good(&claims(AUD, NOW + VAPID_MAX_LIFETIME_SECS))).is_ok());
    }

    #[test]
    fn authorize_enforces_the_bound_key() {
        let (k, other) = (key(7), key(9));
        let (signed, sig) = token(&k, "ES256", &claims(AUD, NOW + 3600));
        let auth = header(&signed, &sig, &k);
        let crypto = FakeCrypto::default();
        let authorize = |auth: &str, bound: &PublicKey| {
            pollster::block_on(authorize(auth, AUD, NOW, bound, &crypto))
        };

        assert_eq!(
            authorize(&auth, &public(&k)).unwrap().public_key,
            public(&k)
        );
        // A valid token from another sender is forbidden, not unauthorized.
        assert_eq!(authorize(&auth, &public(&other)), Err(Error::Forbidden));
        // The bound key with a forged signature is still a 401.
        let (_, other_sig) = token(&other, "ES256", &claims(AUD, NOW + 3600));
        assert_eq!(
            authorize(&header(&signed, &other_sig, &k), &public(&k)),
            Err(Error::Unauthorized(VapidError::BadSignature))
        );
        assert_eq!(
            authorize("", &public(&k)),
            Err(Error::Unauthorized(VapidError::NotVapid))
        );
    }
}
