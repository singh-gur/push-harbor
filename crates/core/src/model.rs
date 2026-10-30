//! Domain types shared by both adapters.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::limits::MAX_KEY_ID_LEN;
use crate::vapid::PublicKey;

/// Opaque 128-bit endpoint ID, base64url (22 chars): `https://<relay>/v1/push/<id>` (PH-9).
/// It is a capability: whoever holds it (plus the bound VAPID key) can push to the device.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointId(String);

impl EndpointId {
    /// From 16 random bytes supplied by the adapter's [`Crypto`](crate::adapter::Crypto).
    pub fn from_random(bytes: [u8; 16]) -> Self {
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn parse(value: &str) -> Option<Self> {
        let valid = value.len() == 22
            && URL_SAFE_NO_PAD
                .decode(value)
                .is_ok_and(|bytes| bytes.len() == 16);
        valid.then(|| Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Client-chosen key ID, echoed to the device as `s` so it can pick the decryption key (PH-9).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
    pub fn parse(value: &str) -> Option<Self> {
        let valid = (1..=MAX_KEY_ID_LEN).contains(&value.len())
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        valid.then(|| Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Android via FCM HTTP v1; the target is a Firebase Installation ID (`message.fid`).
    Fcm,
    /// iOS via APNs (iOS milestone); the target is an APNs device token.
    Apns,
}

/// One device subscription, bound to one sender (VAPID key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub endpoint: EndpointId,
    pub platform: Platform,
    /// Provider address: FCM FID or APNs device token.
    pub target: String,
    pub key_id: KeyId,
    /// The only VAPID key allowed to send to this endpoint; changed by rekey (PH-9).
    pub sender_key: PublicKey,
    pub created_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_id_round_trip_and_rejects_bad_input() {
        let id = EndpointId::from_random([7; 16]);
        assert_eq!(id.as_str().len(), 22);
        assert_eq!(EndpointId::parse(id.as_str()), Some(id));
        for bad in [
            "",
            "short",
            "!!!!!!!!!!!!!!!!!!!!!!",
            "AAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert_eq!(EndpointId::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn key_id_charset_and_length() {
        assert!(KeyId::parse("abc_DEF-123").is_some());
        assert!(KeyId::parse(&"k".repeat(MAX_KEY_ID_LEN)).is_some());
        for bad in ["", "has space", "dot.ted", &"k".repeat(MAX_KEY_ID_LEN + 1)] {
            assert!(KeyId::parse(bad).is_none(), "{bad}");
        }
    }
}
