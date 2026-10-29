//! VAPID sender authentication (RFC 8292): parse `Authorization: vapid t=<jwt>, k=<key>`
//! and verify the ES256 JWT.
//!
//! Only the RFC 8292 `vapid` scheme is accepted. The legacy draft form
//! (`Authorization: WebPush <jwt>` + `Crypto-Key: p256ecdsa=<key>`) is only emitted
//! together with the old `aesgcm` content encoding, which the relay rejects anyway.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::Deserialize;

/// Uncompressed SEC1 P-256 public key, as sent in `k=`.
pub type PublicKey = [u8; 65];

/// A successfully verified VAPID token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vapid {
    /// Sender identity; compare with the key bound to the endpoint.
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

/// Verify a VAPID `Authorization` header value.
///
/// `audience` is the relay origin (`https://host[:port]`, no trailing slash). `now` is unix
/// seconds. `max_lifetime` is the longest accepted `exp - now`; callers add any clock-skew
/// allowance to it.
pub fn verify(
    authorization: &str,
    audience: &str,
    now: u64,
    max_lifetime: u64,
) -> Result<Vapid, VapidError> {
    use VapidError::*;

    let (token, key) = parse_header(authorization)?;
    let public_key: PublicKey = b64(key)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(InvalidKey)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key).map_err(|_| InvalidKey)?;

    let (signed, signature) = token.rsplit_once('.').ok_or(MalformedToken)?;
    let (header, claims) = signed.split_once('.').ok_or(MalformedToken)?;
    let header: JwtHeader = json(header)?;
    if header.alg != "ES256" {
        return Err(UnsupportedAlgorithm);
    }
    let signature = b64(signature)
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or(MalformedToken)?;
    verifying_key
        .verify(signed.as_bytes(), &signature)
        .map_err(|_| BadSignature)?;

    // Claims are only trusted after the signature check.
    let claims: Claims = json(claims)?;
    if claims.aud != audience {
        return Err(WrongAudience);
    }
    if claims.exp <= now {
        return Err(Expired);
    }
    if claims.exp - now > max_lifetime {
        return Err(LifetimeTooLong);
    }
    let sub = claims
        .sub
        .filter(|sub| !sub.is_empty())
        .ok_or(MissingSubject)?;
    Ok(Vapid {
        public_key,
        sub,
        exp: claims.exp,
    })
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
    use p256::ecdsa::{SigningKey, signature::Signer};

    const AUD: &str = "https://relay.example";
    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 86_400;

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

    fn check(auth: &str) -> Result<Vapid, VapidError> {
        verify(auth, AUD, NOW, DAY)
    }

    #[test]
    fn accepts_valid_token() {
        let k = key(7);
        let (signed, sig) = token(&k, "ES256", &claims(AUD, NOW + 3600));
        let vapid = check(&header(&signed, &sig, &k)).unwrap();
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
        assert!(check(&header(&signed, &sig, &k)).is_ok());
        assert!(check(&header(&signed, &flipped, &k)).is_ok());
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
            assert!(check(&v).is_ok(), "{v}");
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
                good(&claims(AUD, NOW + DAY + 1)),
                VapidError::LifetimeTooLong,
            ),
            (
                good(&format!(r#"{{"aud":"{AUD}","exp":{}}}"#, NOW + 60)),
                VapidError::MissingSubject,
            ),
        ];
        for (auth, want) in cases {
            assert_eq!(check(&auth), Err(want), "{auth}");
        }
    }
}
