# Send API

Servers send with a standard Web Push request: RFC 8030 request shape, RFC 8291 `aes128gcm`
payload encryption, RFC 8292 VAPID authentication. Existing Web Push libraries are the sender SDK
(see [Library settings](#library-settings)).

## Subscription

The server receives a subscription from the app, in the usual Web Push JSON form:

```json
{
  "endpoint": "https://push.example.com/v1/push/7Qp2v0bZ3k8mYx1aR4tW9g",
  "expirationTime": null,
  "keys": { "p256dh": "BG3…", "auth": "q1d…" }
}
```

- `endpoint`: `<origin>/v1/push/<id>`, where `<id>` is 16 random bytes in base64url (22
  characters). Opaque: servers MUST NOT parse it.
- `keys.p256dh`: the app's uncompressed P-256 public key (65 bytes, base64url).
- `keys.auth`: the app's 16-byte auth secret (base64url).

The endpoint is bound to one VAPID public key, chosen by the app at registration (the server's
key). Only that key can send to it or rekey it.

## Request

```http
POST /v1/push/<id> HTTP/1.1
Host: push.example.com
Authorization: vapid t=<JWT>, k=<VAPID public key>
Content-Encoding: aes128gcm
Content-Type: application/octet-stream
TTL: 86400
Urgency: high
Topic: chat_42
Idempotency-Key: msg-7f3a:1

<aes128gcm body>
```

| Header | Required | Rules |
|---|---|---|
| `Authorization` | yes | RFC 8292 `vapid` scheme: `t` is an ES256 JWT, `k` the uncompressed P-256 public key (base64url). Parameter names are case-insensitive and values may be quoted. The legacy `WebPush` scheme is rejected (401). |
| `Content-Encoding` | yes | `aes128gcm` (case-insensitive). `aesgcm` and anything else: 400. |
| `TTL` | no | Seconds as a non-negative integer. Absent: 2,419,200 (28 days). `0`: deliver now or drop. Larger than 28 days: clamped to 28 days. Not an integer: 400. |
| `Urgency` | no | `very-low`, `low`, `normal` (default) or `high`, case-insensitive. Otherwise 400. |
| `Topic` | no | 1–32 characters of `[A-Za-z0-9_-]`. A newer message with the same topic replaces one still waiting for delivery. Otherwise 400. |
| `Idempotency-Key` | no | Pushharbor extension, 1–64 characters of `[A-Za-z0-9._:-]`. See [Idempotency](#idempotency). Otherwise 400. |

Header values are trimmed of surrounding whitespace.

### VAPID token

The JWT header has `"alg": "ES256"`. Claims:

| Claim | Rule |
|---|---|
| `aud` | Exactly `<origin>` (scheme, host, and port if not default). Web Push libraries derive it from the endpoint URL. Otherwise 401. |
| `exp` | Later than now, and at most 86,700 s (24 h + 5 min) ahead. Otherwise 401. |
| `sub` | Required, non-empty (`mailto:` or `https:` contact). Otherwise 401. |

The signature is verified with the key in `k`. If `k` is a valid key but not the one bound to the
endpoint, the relay answers **403** without checking the signature.

### Body

An RFC 8291 message with a single `aes128gcm` record:

- At most **2,900 bytes**; larger: **413**. This fits both FCM and APNs once base64-encoded in
  the provider envelope ([envelope.md](envelope.md)).
- The header's key ID MUST be the 65-byte sender public key (`idlen` = 65), as RFC 8291 requires.
- The whole ciphertext MUST fit in one record (`body length − 86 ≤ rs`); devices decrypt a
  single record only. With libraries' default `rs` of 4096 this always holds under the cap.
- Shorter than 103 bytes, or any of the above violated: **400**.

The relay does not decrypt or inspect the ciphertext. The plaintext SHOULD be a Pushharbor
envelope ([envelope.md](envelope.md)); with `rs` 4096 and no padding the maximum is **2,797
bytes of plaintext**.

## Responses

| Status | Meaning | Sender action |
|---|---|---|
| **201** | Accepted by the push provider. Empty body. | Done. |
| 400 | Malformed request. | Fix the request; do not retry unchanged. |
| 401 | VAPID token missing or invalid (expired, wrong `aud`, bad signature, lifetime too long). | Fix the token. |
| 403 | Valid token, but signed by a key not bound to this endpoint. | Use the bound key, or [rekey](#sender-key-rotation). |
| 404 | No such endpoint (never existed, unregistered, or deleted after a 410). | Delete the subscription. |
| 410 | The device is gone (uninstalled, data cleared); the relay has just deleted the endpoint. | Delete the subscription. |
| 413 | Body larger than 2,900 bytes. | Shorten the payload. |
| 429 | Rate limited, or a duplicate of an in-flight request. Always has `Retry-After` (seconds). | Retry after that many seconds. |
| 503 | Push provider unavailable. `Retry-After` when known. | Retry with backoff. |
| 500 | Relay bug or misconfiguration. | Retry later; report to the relay operator. |

Error bodies and codes are in [errors.md](errors.md). The relay attempts delivery synchronously
and does not queue or retry: a 201 means the provider accepted the message, not that the device
displayed it.

Order of checks (determines which error a bad request gets): endpoint ID format (404) → headers
and body (400, 413) → deployment and IP rate limits (429) → endpoint lookup (404) → VAPID (401,
403) → idempotency → endpoint and sender rate limits (429) → delivery (201, 410, 429, 503, 500).

## Idempotency

`Idempotency-Key` makes retries safe. It is scoped to (endpoint, key) and remembered for 3,600 s
from the first attempt:

- First request with the key: delivered normally.
- Repeat after a **201**: answered 201 again **without** sending.
- Repeat while the first is still in flight: **429** with `Retry-After: 1`.
- Repeat after a failure: the key is released and the repeat is delivered normally.

It is optional. Without it, a retry after a lost response can deliver twice; the plaintext tag
`g` ([envelope.md](envelope.md)) then makes the device show it once.

## Sender key rotation

A server changing its VAPID key rebinds each endpoint itself; the app is not involved.

```http
POST /v1/push/<id>/rekey HTTP/1.1
Authorization: vapid t=<JWT signed by the CURRENT key>, k=<current public key>
Content-Type: application/json

{"k": "<new public key, base64url>", "t": "<VAPID JWT signed by the NEW key>"}
```

- `Authorization` follows the send rules (401/403 likewise).
- `t` is a proof of possession: a VAPID JWT for the same `aud`, valid `exp` and `sub`, signed by
  the new key. Invalid: 400. `k` not an uncompressed P-256 key: 400.
- **204** on success. From then on only the new key can send or rekey.

## Library settings

Measured with each library sending a 2,797-byte plaintext (the maximum):

| Library | Required setting | `Idempotency-Key` | Notes |
|---|---|---|---|
| web-push (Node) 3.6.7 | none | `headers` option | HTTPS endpoints only. Pass `TTL`. Errors reject with `WebPushError` (`statusCode`, `headers`). |
| pywebpush 2.5.0 | none | `headers=` | **TTL defaults to 0** (deliver now or drop); pass `ttl=`. Raises `WebPushException` for non-2xx. |
| webpush-go 1.4.0 | **`RecordSize: 2900`** (otherwise every body is 4,096 B → 413) | custom `HTTPClient` only | Bodies are padded to exactly 2,900 B; larger payloads fail in the library (`payload has exceeded the maximum length`) instead of getting 413. Returns `*http.Response` without error: check `StatusCode`. |
| web-push-php 11.0 | **`setAutomaticPadding(false)`** (otherwise 2,922 B → 413) | custom PSR-18 client only | Drops the port from the VAPID `aud`, so it only works with relays on the default port (443), as production relays are. `MessageSentReport::isSubscriptionExpired()` is true for 404/410. |

All four send 12-hour VAPID tokens, well within the 24 h + 5 min limit. `interop/` holds a
sender program per library using exactly these settings; `just interop native` and
`just interop worker` run them against both relays in CI.
