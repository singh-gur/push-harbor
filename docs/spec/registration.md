# Registration API

Called by the app (through a client library), never by servers. Requests and responses are JSON;
errors follow [errors.md](errors.md). None of these calls needs authentication: possession of the
provider target is proven by the challenge, and endpoint IDs are capabilities.

## Keys the app holds

Per subscription, generated on the device and never sent to the relay:

- a P-256 key pair; the public key is `p256dh` (65 bytes uncompressed),
- a 16-byte random `auth` secret,
- a key ID `key_id`: 1–32 characters of `[A-Za-z0-9_-]`, random, unique among the app's
  subscriptions. The relay echoes it with every push (as `s`) so the app can pick the right key;
  it carries no meaning.

The app also needs the server's VAPID public key (`sender_key`), obtained from its server over
the user's authenticated session.

## Register

```http
POST /v1/registrations
```
```json
{
  "platform": "fcm",
  "target": "dXl7S0lJ_3pWQ4m2rZ8yAb",
  "key_id": "k7Gq2",
  "sender_key": "BG4kV_wdOWn4UH9PnI0-IEaju8oyUbv6rQ-EhSAmQz8vDzBcrwu7u2lDsv0hx063ISllIUtYT-CZMONCW82SEUI",
  "replaces": null
}
```

| Field | Rules |
|---|---|
| `platform` | `fcm`. `apns` is reserved and rejected with 400 until the iOS milestone. |
| `target` | Provider address: for `fcm` the **Firebase Installation ID** (FID), not a legacy registration token. 1–256 printable ASCII characters without spaces. |
| `key_id` | As above. |
| `sender_key` | Uncompressed P-256 public key, base64url. The endpoint will only accept this key. |
| `replaces` | Optional endpoint ID; see [Target rotation](#target-rotation). |

**202** response:

```json
{ "rid": "Zm9vYmFyYmF6cXV4cXV1eA", "expires_at": 1793335277 }
```

`rid` identifies the pending registration (22 characters; never an endpoint ID). It expires 300
seconds after registration. The relay has sent a challenge push to the target.

Errors: 400 for invalid fields or a target the provider does not know; 404 if `replaces` is
unknown; 429 for the registrations-per-IP or challenges-per-target limit; 503 if the provider is
unavailable.

## Challenge

The challenge reaches the app through the provider (FCM data message, see
[envelope.md](envelope.md)): `{"c": <nonce>, "r": <rid>}`, high priority, TTL 60 s. The nonce is
128 random bits in base64url and single use.

The app MUST:

1. Answer only challenges whose `r` is a registration **it started** and has not finished. (If it
   answered any challenge, someone who learned the device's FID could register it and the
   victim's own phone would confirm.)
2. Answer to **its configured relay URL**, never to a URL taken from the push.
3. Answer from native code; the JavaScript runtime may not be running.

## Confirm

```http
POST /v1/registrations/<rid>/confirm
```
```json
{ "c": "<nonce>" }
```

**201** response, the subscription endpoint:

```json
{ "id": "7Qp2v0bZ3k8mYx1aR4tW9g", "endpoint": "https://push.example.com/v1/push/7Qp2v0bZ3k8mYx1aR4tW9g" }
```

Every answer consumes the pending registration: a wrong nonce gets **403** and the app has to
register again. Unknown, expired or already used `rid`: **404**.

The app then gives its server the subscription: `endpoint`, `p256dh` and `auth` (see
[send.md](send.md#subscription)).

## Resend the challenge

If no challenge arrives within **30 seconds**, the app asks for it again:

```http
POST /v1/registrations/<rid>/challenge
```

**202** with the same body as Register (the nonce is unchanged). At most **3** challenge pushes per
pending registration, the first included; then **429** with `Retry-After` set to the seconds
until the pending registration expires. Unknown or expired `rid`: **404**.

If the last challenge also goes unanswered, registration fails. The app MUST NOT fall back to an
unverified endpoint. Suggested message: "Couldn't set up notifications on this device. Make sure
you're online and Google Play services is up to date, then try again."

## Target rotation

When the provider target changes (FCM issues a new FID: app reinstall with backup restore, data
cleared, FID expiry), the app keeps its endpoint by registering the new target with `replaces`
set to the existing endpoint ID and the **same** `sender_key` (a different key: 400). After the
challenge, confirm returns the **same** `id` and `endpoint`; pushes now go to the new target.
`key_id` may change in the same step. Nothing changes for the server.

## Unregister

```http
DELETE /v1/push/<id>
```

**204**, also when the endpoint is already gone. Sends then get 404. A malformed ID gets 404. The
app SHOULD also tell its server to forget the subscription.

## Health

```http
GET /v1/health
```

**200** `{"status": "ok"}`.

## Client checklist

- Request `ACCESS_LOCAL_NETWORK` (Android 17+) when the relay URL resolves to a private or LAN
  address; without it the confirm request is blocked.
- A force-stopped app receives no FCM messages at all (the provider still accepts them). It
  cannot happen during registration (the app is in the foreground), but affects delivery.
- Keep pending `rid`s only until confirmed, failed or expired.
