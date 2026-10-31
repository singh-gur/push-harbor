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
    pub metrics_listen: Option<SocketAddr>,
    /// `sqlite://<path>` or `postgres://...`.
    pub database_url: String,
    pub fcm: ServiceAccount,
    pub provider_timeout: Duration,
    pub request_timeout: Duration,
    pub limits: RateLimits,
    /// Take the client IP from `X-Forwarded-For` (only behind a trusted reverse proxy).
    /// Proxies in front of the relay that append to X-Forwarded-For (0: use the peer address).
    pub trusted_proxies: usize,
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
  PUSHHARBOR_METRICS_LISTEN             address for GET /metrics (Prometheus), e.g. 0.0.0.0:9090;
                                        off by default, keep it off the public network
  PUSHHARBOR_DATABASE_URL               sqlite://<path> (one instance; default
                                        sqlite:///data/pushharbor.db) or postgres://... (any
                                        number of instances: limits and idempotency are shared)
  PUSHHARBOR_PROVIDER_TIMEOUT_SECS      FCM request timeout (default 10)
  PUSHHARBOR_REQUEST_TIMEOUT_SECS       whole-request timeout incl. body upload, then 408
                                        (default 30). Header timeouts: run behind a TLS proxy
  PUSHHARBOR_TRUST_PROXY                number of proxies in front that append to X-Forwarded-For
                                        (true = 1); the client IP is taken that many entries from
                                        the right (default 0: the TCP peer)
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
            metrics_listen: var("PUSHHARBOR_METRICS_LISTEN")
                .map(|v| {
                    v.parse()
                        .map_err(|e| format!("PUSHHARBOR_METRICS_LISTEN: {e}"))
                })
                .transpose()?,
            database_url: var("PUSHHARBOR_DATABASE_URL")
                .unwrap_or_else(|| "sqlite:///data/pushharbor.db".into()),
            fcm,
            request_timeout: Duration::from_secs(
                var("PUSHHARBOR_REQUEST_TIMEOUT_SECS")
                    .map(|v| {
                        v.parse()
                            .map_err(|_| "PUSHHARBOR_REQUEST_TIMEOUT_SECS must be a number")
                    })
                    .transpose()?
                    .unwrap_or(30),
            ),
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
            trusted_proxies: match var("PUSHHARBOR_TRUST_PROXY").as_deref() {
                None | Some("false") => 0,
                Some("true") => 1,
                Some(n) => n.parse().map_err(
                    |_| "PUSHHARBOR_TRUST_PROXY must be a number of proxies or true/false",
                )?,
            },
        })
    }
}
