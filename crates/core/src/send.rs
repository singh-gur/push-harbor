//! Validation of an incoming Web Push send (RFC 8030 headers + RFC 8291 body), before any I/O.
//! VAPID is checked separately (`vapid::verify`), since it needs the endpoint's bound key.

use crate::error::Error;
use crate::limits::{
    DEFAULT_TTL_SECS, MAX_BODY_BYTES, MAX_IDEMPOTENCY_KEY_LEN, MAX_TTL_SECS, RFC8291_OVERHEAD,
};

/// Raw header values as received (`None` when absent).
#[derive(Debug, Default, Clone, Copy)]
pub struct Headers<'a> {
    pub content_encoding: Option<&'a str>,
    pub ttl: Option<&'a str>,
    pub urgency: Option<&'a str>,
    pub topic: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
}

/// RFC 8030 §5.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Urgency {
    VeryLow,
    Low,
    Normal,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidSend<'a> {
    /// Seconds, already defaulted and clamped; 0 = deliver now or drop.
    pub ttl: u32,
    pub urgency: Urgency,
    /// RFC 8030 topic: a newer message with the same topic replaces a pending one.
    pub topic: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
}

const HEADER_LEN: usize = 86; // salt 16 + rs 4 + idlen 1 + 65-byte P-256 key

pub fn validate<'a>(headers: &Headers<'a>, body: &[u8]) -> Result<ValidSend<'a>, Error> {
    if !headers
        .content_encoding
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("aes128gcm"))
    {
        return Err(Error::BadRequest("Content-Encoding must be aes128gcm"));
    }
    if body.len() > MAX_BODY_BYTES {
        return Err(Error::PayloadTooLarge);
    }
    if body.len() < RFC8291_OVERHEAD || body[20] != 65 {
        return Err(Error::BadRequest("body is not an aes128gcm message"));
    }
    let rs = u32::from_be_bytes([body[16], body[17], body[18], body[19]]) as usize;
    // Devices decrypt a single record only; at this cap that holds for any rs libraries use.
    if rs < 18 || body.len() - HEADER_LEN > rs {
        return Err(Error::BadRequest("body must be a single aes128gcm record"));
    }

    Ok(ValidSend {
        ttl: parse_ttl(headers.ttl)?,
        urgency: parse_urgency(headers.urgency)?,
        topic: headers.topic.map(parse_topic).transpose()?,
        idempotency_key: headers
            .idempotency_key
            .map(parse_idempotency_key)
            .transpose()?,
    })
}

fn parse_ttl(value: Option<&str>) -> Result<u32, Error> {
    let Some(value) = value.map(str::trim) else {
        return Ok(DEFAULT_TTL_SECS);
    };
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::BadRequest("TTL must be a non-negative integer"));
    }
    // Digits only, so a parse failure means it overflowed: clamp like any other large value.
    Ok(value
        .parse::<u64>()
        .map_or(MAX_TTL_SECS, |ttl| ttl.min(MAX_TTL_SECS as u64) as u32))
}

fn parse_urgency(value: Option<&str>) -> Result<Urgency, Error> {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        None | Some("normal") => Ok(Urgency::Normal),
        Some("very-low") => Ok(Urgency::VeryLow),
        Some("low") => Ok(Urgency::Low),
        Some("high") => Ok(Urgency::High),
        Some(_) => Err(Error::BadRequest(
            "Urgency must be very-low, low, normal or high",
        )),
    }
}

/// RFC 8030 §5.4: at most 32 characters from the base64url alphabet.
fn parse_topic(value: &str) -> Result<&str, Error> {
    let value = value.trim();
    let valid = (1..=32).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    valid
        .then_some(value)
        .ok_or(Error::BadRequest("Topic must be 1-32 base64url characters"))
}

fn parse_idempotency_key(value: &str) -> Result<&str, Error> {
    let value = value.trim();
    let valid = (1..=MAX_IDEMPOTENCY_KEY_LEN).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    valid.then_some(value).ok_or(Error::BadRequest(
        "Idempotency-Key must be 1-64 characters of [A-Za-z0-9._:-]",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Structurally valid aes128gcm body of `len` bytes with record size `rs` (content is random-ish).
    fn body(len: usize, rs: u32) -> Vec<u8> {
        let mut b = vec![0xAB; len];
        b[16..20].copy_from_slice(&rs.to_be_bytes());
        b[20] = 65;
        b
    }

    fn ok_headers() -> Headers<'static> {
        Headers {
            content_encoding: Some("aes128gcm"),
            ..Default::default()
        }
    }

    #[test]
    fn accepts_cap_and_rejects_one_byte_over() {
        let at_cap = validate(&ok_headers(), &body(MAX_BODY_BYTES, 4096)).unwrap();
        assert_eq!(at_cap.ttl, DEFAULT_TTL_SECS);
        assert_eq!(at_cap.urgency, Urgency::Normal);
        assert_eq!(
            validate(&ok_headers(), &body(MAX_BODY_BYTES + 1, 4096)),
            Err(Error::PayloadTooLarge)
        );
        // webpush-go with RecordSize 2900 pads every body to exactly rs.
        assert!(validate(&ok_headers(), &body(2900, 2900)).is_ok());
    }

    #[test]
    fn rejects_bad_bodies_and_encoding() {
        let h = ok_headers();
        let bad = Error::BadRequest("body is not an aes128gcm message");
        assert_eq!(validate(&h, &[]), Err(bad.clone()));
        assert_eq!(
            validate(&h, &body(RFC8291_OVERHEAD - 1, 4096)),
            Err(bad.clone())
        );
        let mut wrong_idlen = body(200, 4096);
        wrong_idlen[20] = 0;
        assert_eq!(validate(&h, &wrong_idlen), Err(bad));
        assert_eq!(
            validate(&h, &body(1000, 512)),
            Err(Error::BadRequest("body must be a single aes128gcm record"))
        );
        for encoding in [None, Some("aesgcm"), Some("gzip")] {
            let h = Headers {
                content_encoding: encoding,
                ..Default::default()
            };
            assert!(
                matches!(validate(&h, &body(200, 4096)), Err(Error::BadRequest(_))),
                "{encoding:?}"
            );
        }
        let upper = Headers {
            content_encoding: Some(" AES128GCM "),
            ..Default::default()
        };
        assert!(validate(&upper, &body(200, 4096)).is_ok());
    }

    #[test]
    fn ttl_default_zero_clamp_and_invalid() {
        let ttl = |v: &'static str| {
            validate(
                &Headers {
                    ttl: Some(v),
                    ..ok_headers()
                },
                &body(200, 4096),
            )
            .map(|s| s.ttl)
        };
        assert_eq!(ttl("0"), Ok(0));
        assert_eq!(ttl("60"), Ok(60));
        assert_eq!(ttl("2419200"), Ok(MAX_TTL_SECS));
        assert_eq!(ttl("9999999999999999999999"), Ok(MAX_TTL_SECS));
        for bad in ["", "-1", "1.5", "abc"] {
            assert!(ttl(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn urgency_topic_and_idempotency_key() {
        let check = |h: Headers<'static>| {
            validate(
                &Headers {
                    content_encoding: Some("aes128gcm"),
                    ..h
                },
                &body(200, 4096),
            )
        };
        assert_eq!(
            check(Headers {
                urgency: Some("HIGH"),
                ..Default::default()
            })
            .unwrap()
            .urgency,
            Urgency::High
        );
        assert!(
            check(Headers {
                urgency: Some("urgent"),
                ..Default::default()
            })
            .is_err()
        );
        assert_eq!(
            check(Headers {
                topic: Some("chat_42"),
                ..Default::default()
            })
            .unwrap()
            .topic,
            Some("chat_42")
        );
        assert!(
            check(Headers {
                topic: Some(&*"t".repeat(33).leak()),
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            check(Headers {
                topic: Some("has.dot"),
                ..Default::default()
            })
            .is_err()
        );
        assert_eq!(
            check(Headers {
                idempotency_key: Some("idem-node:1.2_x"),
                ..Default::default()
            })
            .unwrap()
            .idempotency_key,
            Some("idem-node:1.2_x")
        );
        assert!(
            check(Headers {
                idempotency_key: Some(&*"k".repeat(65).leak()),
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            check(Headers {
                idempotency_key: Some("space key"),
                ..Default::default()
            })
            .is_err()
        );
    }
}
