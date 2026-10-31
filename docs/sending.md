# Sending notifications from your server

Your server sends to a Pushharbor relay with an ordinary **Web Push** library: the relay speaks
the same protocol as browser push services (RFC 8030, 8291, 8292). This guide covers what your
server needs, the settings each library requires, and how to handle the relay's answers. The
exact rules are in the [protocol spec](spec/send.md).

Complete, runnable examples, tested in CI against the relay with exactly these settings:
[Node.js](../examples/senders/node/send.mjs) · [Python](../examples/senders/python/send.py) ·
[Go](../examples/senders/go/main.go).

## 1. Create a VAPID key pair (once per server)

VAPID identifies your server to the relay. Generate the pair once and keep the private key secret:

```sh
npx web-push generate-vapid-keys --json
```

The base64url keys it prints work with every library below (Go also has
`webpush.GenerateVAPIDKeys()`). The **public** key is 87 characters and starts with `B`.

Your server must give the public key to its signed-in app users, for example:

```http
GET /api/push/vapid-public-key   →   {"key": "BG4kV_wd..."}
```

Each endpoint the app creates is bound to this key: only your server can send to it. To change
keys later without involving the apps, rekey every endpoint ([spec](spec/send.md#sender-key-rotation)).

## 2. Store the subscriptions your app sends you

The app registers with the relay and posts its subscription to your server, over the user's
session:

```json
{
  "id": "D5by-dr1NM3RyuR_",
  "endpoint": "https://push.example.com/v1/push/0ZvJ9RS0PqxODBmUTZojeQ",
  "expirationTime": null,
  "keys": { "p256dh": "BBdCGPY2p6...", "auth": "19pU8ZUk_O3thTtg3dT2EQ" }
}
```

Store it per user and device. Web Push libraries take this object as it is. Treat it like a
credential (the endpoint URL is a capability) and don't log it. `id` is the app's local
identifier; you may ignore it.

## 3. Send

The payload is a small JSON object (at most **2,797 bytes**), encrypted by the library for the
device. The app shows `t`/`b` as a notification ([envelope](spec/envelope.md#plaintext-envelope)):

```json
{"t": "New message", "b": "Alice: are we still on for 7?", "u": "myapp://chat/42", "g": "chat-42", "d": {"chat": 42}}
```

| Key | Meaning |
|---|---|
| `t`, `b` | Title and body. Without either, nothing is shown and `d` goes to the app only. |
| `u` | Opened when tapped, if the app handles it (its own deep links). |
| `g` | Tag: a newer notification with the same tag replaces the shown one. |
| `d` | Your data, passed to the app unchanged. |

### Node.js: [web-push](https://github.com/web-push-libs/web-push)

```js
webpush.setVapidDetails("mailto:ops@example.com", VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
await webpush.sendNotification(subscription, JSON.stringify(envelope), {
  TTL: 86400,
  urgency: "high",
  headers: { "Idempotency-Key": messageId },
});
```

No special settings. web-push only connects over HTTPS (relays are HTTPS anyway). Errors are
thrown as `WebPushError` with `statusCode` and `headers`.

### Python: [pywebpush](https://github.com/web-push-libs/pywebpush)

```python
webpush(subscription, json.dumps(envelope),
        vapid_private_key=VAPID_PRIVATE_KEY,
        vapid_claims={"sub": "mailto:ops@example.com"},
        ttl=86400,
        headers={"Idempotency-Key": message_id, "Urgency": "high"})
```

**Pass `ttl`**: pywebpush defaults to 0 (deliver now or drop). Pass a fresh `vapid_claims` dict
per call; pywebpush writes `aud` and `exp` into it. Errors raise `WebPushException` with
`.response`.

### Go: [webpush-go](https://github.com/SherClockHolmes/webpush-go)

```go
resp, err := webpush.SendNotification(envelope, &sub, &webpush.Options{
	Subscriber:      "ops@example.com",
	VAPIDPublicKey:  vapidPublicKey,
	VAPIDPrivateKey: vapidPrivateKey,
	TTL:             86400,
	Urgency:         webpush.UrgencyHigh,
	RecordSize:      2900, // required
	HTTPClient:      headerClient{messageID}, // adds Idempotency-Key
})
```

**`RecordSize: 2900` is required**: without it every body is padded to 4,096 bytes and the
relay answers 413. webpush-go returns error responses **without** an error; check
`resp.StatusCode`. Custom headers need an `HTTPClient` wrapper (see the example).

### PHP: [web-push-php](https://github.com/web-push-libs/web-push-php)

Call `$webPush->setAutomaticPadding(false)` (otherwise 413). It has no option for
`Idempotency-Key`, and it drops the port from the VAPID audience, which is fine because
relays use port 443. `MessageSentReport::isSubscriptionExpired()` is true for 404/410.

## 4. Handle the answer

| Status | Meaning | Do |
|---|---|---|
| 201 | Accepted by the push provider | Done. |
| 404, 410 | The device or subscription is gone | **Delete the subscription.** |
| 429 | Rate limited, or the same `Idempotency-Key` is still in flight | Retry after `Retry-After` seconds. |
| 503 | Push provider unavailable | Retry with backoff (`Retry-After` if present). |
| 413 | Payload over 2,797 bytes of JSON (2,900-byte body) | Shorten it; don't retry. |
| 400 | Malformed request (settings, headers) | Fix the code; don't retry. |
| 401, 403 | VAPID token invalid, or signed by a key the endpoint isn't bound to | Fix the keys; don't retry. |
| 500 | Relay problem | Retry later; tell the relay operator if it persists. |

### Retries without duplicates

Send an `Idempotency-Key` (up to 64 characters of `[A-Za-z0-9._:-]`, e.g. a UUID per message)
and **reuse it on every retry** of that message. The relay remembers it for an hour: a repeat
after success answers 201 without sending again; a repeat while the first is still in flight gets
429 with `Retry-After: 1`. Without the header, a retry after a lost response can deliver twice; a
tag `g` then at least makes the device replace instead of stack.

The examples retry 429, 503 and network errors three times in total, waiting `Retry-After`
(capped at 60 s) or 1 s, 2 s, 4 s, and stop immediately on everything else.

## Checklist

- VAPID private key kept secret; public key served to your app.
- Subscriptions stored per device, deleted on 404/410.
- TTL set explicitly; Go `RecordSize: 2900`; PHP automatic padding off.
- Payload JSON at most 2,797 bytes.
- One `Idempotency-Key` per message, reused on retries.
