//! One error type for both APIs: its HTTP status for Web Push senders, its `code` for the JSON
//! registration API.

use crate::vapid::VapidError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Malformed request: bad headers, not an `aes128gcm` body, invalid field.
    BadRequest(&'static str),
    /// Missing or invalid VAPID token (RFC 8292: 401).
    Unauthorized(VapidError),
    /// Valid token, but not the key bound to this endpoint (RFC 8292: 403).
    Forbidden,
    /// Unknown endpoint.
    NotFound,
    /// Endpoint existed but is dead (unregistered, or the provider reported the device gone).
    Gone,
    PayloadTooLarge,
    RateLimited {
        retry_after: u64,
    },
    /// Provider down or throttling the relay; the sender should retry later.
    Unavailable {
        retry_after: Option<u64>,
    },
    Internal,
}

impl Error {
    /// HTTP status. Success on the send API is 201.
    pub fn status(&self) -> u16 {
        match self {
            Error::BadRequest(_) => 400,
            Error::Unauthorized(_) => 401,
            Error::Forbidden => 403,
            Error::NotFound => 404,
            Error::Gone => 410,
            Error::PayloadTooLarge => 413,
            Error::RateLimited { .. } => 429,
            Error::Unavailable { .. } => 503,
            Error::Internal => 500,
        }
    }

    /// Value for the `Retry-After` header, in seconds.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Error::RateLimited { retry_after } => Some(*retry_after),
            Error::Unavailable { retry_after } => *retry_after,
            _ => None,
        }
    }

    /// Stable machine-readable code for JSON error bodies.
    pub fn code(&self) -> &'static str {
        match self {
            Error::BadRequest(_) => "bad_request",
            Error::Unauthorized(_) => "unauthorized",
            Error::Forbidden => "forbidden",
            Error::NotFound => "not_found",
            Error::Gone => "gone",
            Error::PayloadTooLarge => "payload_too_large",
            Error::RateLimited { .. } => "rate_limited",
            Error::Unavailable { .. } => "unavailable",
            Error::Internal => "internal",
        }
    }
}

impl From<VapidError> for Error {
    fn from(e: VapidError) -> Self {
        Error::Unauthorized(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_retry_after_and_code() {
        let cases = [
            (Error::BadRequest("x"), 400, None, "bad_request"),
            (
                Error::Unauthorized(VapidError::Expired),
                401,
                None,
                "unauthorized",
            ),
            (Error::Forbidden, 403, None, "forbidden"),
            (Error::NotFound, 404, None, "not_found"),
            (Error::Gone, 410, None, "gone"),
            (Error::PayloadTooLarge, 413, None, "payload_too_large"),
            (
                Error::RateLimited { retry_after: 30 },
                429,
                Some(30),
                "rate_limited",
            ),
            (
                Error::Unavailable {
                    retry_after: Some(5),
                },
                503,
                Some(5),
                "unavailable",
            ),
            (
                Error::Unavailable { retry_after: None },
                503,
                None,
                "unavailable",
            ),
            (Error::Internal, 500, None, "internal"),
        ];
        for (error, status, retry_after, code) in cases {
            assert_eq!(error.status(), status, "{error:?}");
            assert_eq!(error.retry_after(), retry_after, "{error:?}");
            assert_eq!(error.code(), code, "{error:?}");
        }
    }
}
