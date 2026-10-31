//! Configuration from environment variables. Secrets (the FCM service account) come from a file
//! or an env var, never from the command line.

use std::net::SocketAddr;
use std::time::Duration;

use pushharbor_core::export;
use pushharbor_core::fcm::{self, ServiceAccount};
use pushharbor_core::relay::RateLimits;

pub struct Config {
    /// Public origin (`https://push.example.com`): VAPID `aud` and the base of endpoint URLs.
    pub origin: String,
    pub listen: SocketAddr,
    /// `sqlite://<path>` or `postgres://...`.
    pub database_url: String,
    pub fcm: ServiceAccount,
    pub provider_timeout: Duration,
    pub limits: RateLimits,
    /// Take the client IP from `X-Forwarded-For` (only behind a trusted reverse proxy).
    pub trust_proxy: bool,
    /// Enables the admin API (export/import) when set.
    pub admin_token: Option<String>,
}

/// Documented in `--help` output and the deploy guide.
pub const USAGE: &str = "\
pushharbor-native: Web Push relay (FCM).

Usage: pushharbor-native            serve
       pushharbor-native export     write all registrations to stdout (docs/spec/export.md)
       pushharbor-native import F   import registrations from file F (- for stdin)

Configure with environment variables:

  PUSHHARBOR_ORIGIN                     public origin, e.g. https://push.example.com (required)
  PUSHHARBOR_FCM_SERVICE_ACCOUNT_FILE   path to the Firebase service-account JSON (or:)
  PUSHHARBOR_FCM_SERVICE_ACCOUNT        the service-account JSON itself
  PUSHHARBOR_LISTEN                     listen address (default 0.0.0.0:8080)
  PUSHHARBOR_DATABASE_URL               sqlite://<path> (one instance; default
                                        sqlite:///data/pushharbor.db) or postgres://... (any
                                        number of instances: limits and idempotency are shared)
  PUSHHARBOR_PROVIDER_TIMEOUT_SECS      FCM request timeout (default 10)
  PUSHHARBOR_TRUST_PROXY                true: client IP from X-Forwarded-For (default false)
  PUSHHARBOR_LIMIT_<NAME>               <limit>/<window seconds>, NAME one of GLOBAL, PER_IP,
                                        PER_SENDER, PER_ENDPOINT, REGISTRATIONS_PER_IP,
                                        CHALLENGES_PER_TARGET
  PUSHHARBOR_ADMIN_TOKEN                enables GET /v1/admin/export and POST /v1/admin/import
                                        (Authorization: Bearer <token>, >= 32 characters)
  PUSHHARBOR_FCM_API_BASE               FCM API origin override (tests only)
  RUST_LOG                              log filter (default info)
";

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());

        let origin = var("PUSHHARBOR_ORIGIN")
            .ok_or("PUSHHARBOR_ORIGIN is required")?
            .trim_end_matches('/')
            .to_owned();
        if !(origin.starts_with("https://") || origin.starts_with("http://")) {
            return Err(
                "PUSHHARBOR_ORIGIN must start with https:// (or http:// for local testing)".into(),
            );
        }

        let service_account = match (
            var("PUSHHARBOR_FCM_SERVICE_ACCOUNT_FILE"),
            var("PUSHHARBOR_FCM_SERVICE_ACCOUNT"),
        ) {
            (Some(path), _) => {
                std::fs::read_to_string(&path).map_err(|e| format!("can't read {path}: {e}"))?
            }
            (None, Some(json)) => json,
            (None, None) => {
                return Err(
                    "set PUSHHARBOR_FCM_SERVICE_ACCOUNT_FILE or PUSHHARBOR_FCM_SERVICE_ACCOUNT"
                        .into(),
                );
            }
        };
        let mut fcm = ServiceAccount::from_json(&service_account)
            .map_err(|_| "invalid FCM service account JSON")?;
        fcm.api_base = var("PUSHHARBOR_FCM_API_BASE").unwrap_or_else(|| fcm::API_BASE.into());

        let limits = RateLimits::from_lookup(|name| var(&format!("PUSHHARBOR_LIMIT_{name}")))?;

        Ok(Self {
            origin,
            listen: var("PUSHHARBOR_LISTEN")
                .unwrap_or_else(|| "0.0.0.0:8080".into())
                .parse()
                .map_err(|e| format!("PUSHHARBOR_LISTEN: {e}"))?,
            database_url: var("PUSHHARBOR_DATABASE_URL")
                .unwrap_or_else(|| "sqlite:///data/pushharbor.db".into()),
            fcm,
            provider_timeout: Duration::from_secs(
                var("PUSHHARBOR_PROVIDER_TIMEOUT_SECS")
                    .map(|v| {
                        v.parse()
                            .map_err(|_| "PUSHHARBOR_PROVIDER_TIMEOUT_SECS must be a number")
                    })
                    .transpose()?
                    .unwrap_or(10),
            ),
            limits,
            admin_token: match var("PUSHHARBOR_ADMIN_TOKEN") {
                Some(t) if t.len() < export::MIN_ADMIN_TOKEN_LEN => {
                    return Err("PUSHHARBOR_ADMIN_TOKEN must be at least 32 characters".into());
                }
                token => token,
            },
            trust_proxy: var("PUSHHARBOR_TRUST_PROXY").is_some_and(|v| v == "true" || v == "1"),
        })
    }
}
