//! Protocol limits decided in the spikes. Single source of truth for every hosting option.

/// Largest accepted Web Push request body (PH-19): APNs fits 2,952 B (on paper), FCM 3,659 B
/// (measured); 52 B kept as slack for future envelope fields. Bodies above it get 413.
pub const MAX_BODY_BYTES: usize = 2900;
/// RFC 8291 `aes128gcm` overhead: 86-byte header + 1 padding delimiter + 16-byte tag.
pub const RFC8291_OVERHEAD: usize = 103;
/// Largest plaintext a sender can encrypt without padding.
pub const MAX_PLAINTEXT_BYTES: usize = MAX_BODY_BYTES - RFC8291_OVERHEAD;

/// Longest accepted VAPID token lifetime (`exp - now`): RFC 8292's 24 h plus 5 min clock skew (PH-9).
pub const VAPID_MAX_LIFETIME_SECS: u64 = 24 * 3600 + 300;

/// TTL is clamped to FCM's maximum, and used when a sender omits the header (PH-9).
pub const MAX_TTL_SECS: u32 = 28 * 24 * 3600;
pub const DEFAULT_TTL_SECS: u32 = MAX_TTL_SECS;

/// `Idempotency-Key` replays within this window return the original status (PH-9).
pub const IDEMPOTENCY_WINDOW_SECS: u64 = 3600;
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 64;

/// Client-chosen key ID echoed to the device as `s` (PH-9, budgeted in PH-19).
pub const MAX_KEY_ID_LEN: usize = 32;

/// A pending registration (and its challenge) expires after this (PH-18).
pub const PENDING_TTL_SECS: u64 = 300;
/// Challenge pushes per pending registration, the first one included (PH-18).
pub const MAX_CHALLENGE_SENDS: u8 = 3;
