# What reaches the device

## Provider envelope (FCM)

The relay sends an FCM HTTP v1 **data message** addressed by Firebase Installation ID. Payload
pushes:

```json
{
  "message": {
    "fid": "<target>",
    "data": { "p": "<base64url of the Web Push body>", "s": "<key_id>" },
    "android": { "priority": "HIGH", "ttl": "86400s", "collapse_key": "chat_42" }
  }
}
```

| Field | From |
|---|---|
| `data.p` | The sender's `aes128gcm` body, unchanged, base64url. |
| `data.s` | The registration's `key_id`. The endpoint ID never travels through the provider. |
| `android.priority` | `HIGH` for Urgency `normal`/`high`, `NORMAL` for `low`/`very-low`. High priority is what wakes killed apps and apps in Doze. |
| `android.ttl` | The send's TTL (`"0s"` for deliver now or drop). |
| `android.collapse_key` | The `Topic` header, when present. |

Challenge pushes (see [registration.md](registration.md#challenge)) carry `data: {"c": <nonce>,
"r": <rid>}`, priority `HIGH`, TTL `60s`, and no `p`.

The app tells the two apart by the keys: `c` and `r` mean a challenge, `p` and `s` a payload.
Anything else MUST be ignored.

## Decryption

For a payload push the app:

1. Looks up the subscription keys by `s`. Unknown `s`: drop.
2. Decodes `p` and decrypts it as RFC 8291 `aes128gcm` with the subscription's private key and
   `auth` secret. The relay only forwards single-record bodies, whatever record size the header
   names; padding (zeros after the `0x02` delimiter) is removed.
3. Parses the plaintext as the envelope below.

If any step fails (unknown key ID, bad base64, authentication tag mismatch, wrong `auth`
secret, not a JSON object), the message MUST be **dropped**:

- **Android**: silently. No notification, no error to the user.
- **iOS**: defined in the iOS milestone. A notification cannot be suppressed without an Apple
  entitlement that Pushharbor does not use, so iOS will show a fixed generic notice.

The private key and `auth` secret never leave the device. They SHOULD be kept in the platform
keystore.

## Plaintext envelope

The plaintext a server encrypts is a compact JSON object (at most 2,797 bytes with library
defaults):

```json
{
  "t": "New message",
  "b": "Alice: are we still on for 7?",
  "u": "https://chat.example/c/42",
  "g": "chat-42",
  "d": { "chat": 42 }
}
```

| Key | Type | Meaning |
|---|---|---|
| `t` | string | Notification title. |
| `b` | string | Notification body text. |
| `u` | string | URL or deep link to open when the notification is tapped. |
| `g` | string | Tag: a newer notification with the same tag replaces the shown one (also de-duplicates repeats). |
| `d` | object | App data, passed to the app unchanged. |

All keys are optional and unknown keys MUST be ignored, so new keys can be added within v1.

- With `t` or `b`: the client library shows a notification.
- With neither: nothing is shown; `d` is delivered to the app as a data message.
- The client SHOULD only open `u` if it matches what the app accepts (its own scheme or the
  server's origin), since any server holding a subscription can choose it.

`docs/spec/vectors/encryption.json` contains envelopes encrypted by a real Web Push library,
including one at the size cap, one padded to the record size, and two that MUST be dropped.
