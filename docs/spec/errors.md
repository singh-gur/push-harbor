# Errors

Every error response has an HTTP status and a JSON body:

```json
{ "error": "bad_request", "message": "TTL must be a non-negative integer" }
```

`error` is a stable code. `message` is only present for `bad_request`; it is for humans and may
change. Statuses and codes are the same on both APIs and in every hosting option.

| Code | Status | `Retry-After` | When |
|---|---|---|---|
| `bad_request` | 400 | – | Malformed headers, body or JSON field; registration target unknown to the provider. |
| `unauthorized` | 401 | – | VAPID token missing or invalid. |
| `forbidden` | 403 | – | VAPID key not bound to the endpoint; wrong challenge answer. |
| `not_found` | 404 | – | Unknown endpoint, pending registration or `replaces`. |
| `gone` | 410 | – | The provider reports the device gone; the endpoint has just been deleted. |
| `payload_too_large` | 413 | – | Body over 2,900 bytes. |
| `rate_limited` | 429 | always | A rate limit, a duplicate in flight, or the provider throttling the relay. Seconds until a retry can succeed. |
| `unavailable` | 503 | when known | Push provider down or unreachable. |
| `internal` | 500 | – | Relay bug or misconfiguration. |

A relay MAY also answer 408 when a request exceeds its processing timeout, and 413 for request
bodies far above any valid size, before the API logic runs; such responses may lack the JSON
body.

## Provider errors (FCM)

Only answers that prove the device is gone delete an endpoint. A request the relay built wrongly
is never blamed on the device.

| FCM response | Relay |
|---|---|
| 2xx | 201 |
| error code `UNREGISTERED` (any status), `SENDER_ID_MISMATCH`, or status 404 | 410 `gone`, endpoint deleted |
| status 429 or `QUOTA_EXCEEDED` | 429 `rate_limited`, `Retry-After` from FCM or 60 |
| status 401 or 5xx, or `UNAVAILABLE`, `INTERNAL`, `THIRD_PARTY_AUTH_ERROR` | 503 `unavailable`, FCM's `Retry-After` if any |
| `INVALID_ARGUMENT` and anything else | 500 `internal` |
| timeout or connection failure | 503 `unavailable` |

During registration, a challenge the provider answers with "gone" becomes 400 `bad_request` (the
target is not a valid device), and no pending registration is created.

`docs/spec/vectors/errors.json` lists both tables in machine-readable form.
