# Pushharbor protocol, version 1

Pushharbor is a push relay for apps whose servers are self-hosted. The app's publisher runs one relay
with the app's Firebase (and later APNs) credentials; every self-hosted server sends through it
with a standard **Web Push** request. The relay sees only ciphertext.

This specification is normative for senders, relays and client libraries. The key words MUST,
SHOULD and MAY are used as in RFC 2119.

| Document | Audience | Contents |
|---|---|---|
| [send.md](send.md) | Server developers, relay | Send API (RFC 8030/8291/8292), payload cap, idempotency, sender key rotation, library settings |
| [registration.md](registration.md) | Client libraries, relay | Registration API with challenge, target rotation, unregister, health |
| [envelope.md](envelope.md) | Client libraries, relay | What reaches the device, plaintext envelope, decryption and failure handling |
| [errors.md](errors.md) | Everyone | Status codes, JSON error bodies, provider error mapping |
| [export.md](export.md) | Relay operators | Registration export/import format |
| [vectors/](vectors/) | Implementers | Machine-readable test vectors |

## Parties

```
 app (device)  ──register / confirm──▶  relay  ◀──Web Push send──  app's server (self-hosted)
      ▲                                   │
      └──────────── FCM data message ◀────┘
```

- **App**: the mobile app. Generates the Web Push keys, registers with the relay, hands the
  resulting subscription to its own server, decrypts and shows notifications.
- **Server** (sender): a self-hosted backend of the app. It never signs up with the relay; it
  only holds subscriptions its users' apps gave it, and a VAPID key pair.
- **Relay**: one deployment per published app. Stores, per endpoint: platform, provider target
  (FCM Firebase Installation ID), key ID and the bound VAPID key. It never stores payloads.

## Flow

1. The server publishes its VAPID public key to its signed-in app users.
2. The app generates a subscription key pair (P-256, `p256dh`) and a 16-byte `auth` secret, then
   registers its provider target and the server's VAPID key with the relay, proving it receives
   pushes on that target (challenge). The relay returns an endpoint URL.
3. The app gives the server a standard Web Push subscription: endpoint, `p256dh`, `auth`.
4. The server sends with any Web Push library. The relay checks the VAPID token against the key
   bound to the endpoint and forwards the ciphertext to the device.
5. The app decrypts the payload on the device and shows it. Anything that fails is dropped.

## Conventions

- **base64url** means RFC 4648 section 5 without padding. Receivers MUST accept padded values
  for keys and tokens.
- Times are Unix seconds (UTC).
- JSON bodies are UTF-8 with `Content-Type: application/json`. Receivers MUST ignore unknown
  fields.
- `<origin>` is the relay's public origin, e.g. `https://push.example.com`, without a trailing
  slash. It is both the base of every URL and the VAPID audience.

## Versioning

All paths start with `/v1`. Within v1, changes are additive only: new optional fields, headers,
envelope keys and error codes. Clients and servers MUST ignore what they do not understand. An
incompatible change gets `/v2`, served next to `/v1`.

## Limits

Fixed by the protocol (`crates/core/src/limits.rs`):

| Limit | Value |
|---|---|
| Web Push body | ≤ 2,900 bytes (2,797 bytes of plaintext without padding) |
| VAPID token lifetime (`exp − now`) | ≤ 86,700 s (24 h + 5 min skew) |
| TTL | default and maximum 2,419,200 s (28 days); 0 allowed |
| Idempotency window | 3,600 s |
| Pending registration lifetime | 300 s |
| Challenge pushes per pending registration | 3 |

Rate limits are per deployment (fixed windows). Defaults:

| Bucket | Default |
|---|---|
| Whole deployment (sends) | 6,000 per minute |
| Per client IP (sends) | 600 per minute |
| Per sender, i.e. bound VAPID key (sends) | 600 per minute |
| Per endpoint (sends) | 60 per minute |
| Registrations per client IP | 30 per hour |
| Challenge pushes per provider target | 10 per hour |

## Security model in short

- **Endpoint URLs are capabilities.** Whoever holds one can delete the endpoint or move it to
  another device they own (but cannot read past or future payloads). Apps, servers and relay
  operators MUST treat endpoint URLs like credentials and MUST NOT log them.
- **Sending needs the endpoint and the bound VAPID private key.** A leaked endpoint alone cannot
  send.
- **Payloads are end-to-end encrypted** (RFC 8291) between the server and the app; the relay,
  Google and Apple see ciphertext only. VAPID does not bind the body, so a leaked token plus a
  leaked endpoint can send until the token expires; the app drops anything that does not decrypt
  with its `auth` secret.
- **Proof of possession**: an endpoint is only issued after the app answers a challenge pushed to
  its provider target, so knowing someone's FCM ID is not enough to reach their device.
- The relay cannot stop a server from misrouting messages among its own users.

## Test vectors

`vectors/` holds JSON files that implementations SHOULD test against; core's unit tests
(`crates/core/tests/spec_vectors.rs`) run all of them.

| File | Covers |
|---|---|
| `encryption.json` | RFC 8291 bodies with keys and plaintext: the RFC example, envelopes from web-push's encrypter (short, at the cap, over the cap, padded to the record size) and two that MUST be dropped (tampered, wrong `auth`). Regenerate with `spikes/sender-survey/encryption-vectors.mjs`. |
| `vapid.json` | `Authorization` headers: valid, wrong `aud`, expired, lifetime too long, bad signature, other key, legacy scheme, a key not bound to the endpoint, and real headers from four Web Push libraries. |
| `send.json` | Header and body validation: defaults, TTL clamp, size boundary (2,900 / 2,901), invalid values. |
| `errors.json` | Error codes, statuses and `Retry-After`; FCM response mapping. |

## Platform status

Android (FCM) is specified here. iOS (APNs) is reserved: `platform: "apns"` is rejected with 400
until the iOS milestone adds the APNs envelope, the challenge variant and the iOS client
behaviour. The payload cap already accounts for APNs.
