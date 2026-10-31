<div align="center">

# Pushharbor

### Push notifications for self-hosted apps.<br>Your users run the server. You keep the keys. Nobody in between reads the messages.

[![CI](https://github.com/singh-gur/push-harbor/actions/workflows/ci.yml/badge.svg)](https://github.com/singh-gur/push-harbor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Android: supported](https://img.shields.io/badge/Android-supported-3ddc84)
![iOS: planned](https://img.shields.io/badge/iOS-planned-lightgrey)

</div>

---

You publish a mobile app. Your users run their own server for it. Now they want push
notifications, and you hit the wall every self-hosted project hits: **phones only accept pushes
through Google and Apple, and those credentials belong to you, the publisher.** You can't hand
your Firebase key to thousands of strangers' servers.

**Pushharbor is the one relay you run for your app.** Every self-hosted server sends through it
with the Web Push library it already has, and messages are end-to-end encrypted, so only the
user's phone can read them. You, Google and Apple only ever see ciphertext.

## Why teams pick Pushharbor

**Zero setup for self-hosters.** Servers never sign up, never get an API key, never see your
Firebase credentials. They send standard Web Push, the protocol browsers have used for years,
with the library of their choice: web-push for Node, pywebpush, webpush-go, web-push-php.

**Private by design.** Each notification is encrypted on the server for one device (RFC 8291).
The relay forwards ciphertext it cannot decrypt; you never become the custodian of your users'
messages.

**Locked to the right sender.** Every device endpoint is bound to one server's key. A leaked URL
alone sends nothing, and a server can only reach the devices whose apps gave it an endpoint.

**Can't be pointed at strangers.** A device gets an endpoint only after it answers a challenge
push, so knowing someone's push ID isn't enough to reach their phone.

**Costs almost nothing to run.** It fits Cloudflare Workers' free plan: a send takes a few
milliseconds of CPU. Prefer your own infrastructure? One container with SQLite, or a fleet behind
PostgreSQL.

**No lock-in.** The same API, the same endpoints, on every hosting option. Export your
registrations and move from Workers to Kubernetes (or back) without touching a single app or
server.

## How it works

![How a notification travels: the app registers with the relay and gives its server a
subscription; the server sends an encrypted Web Push to the relay, which forwards the ciphertext
through FCM to the device](docs/assets/architecture.png)

1. **The app registers** with your relay and proves it owns the device.
2. **It hands its server a subscription**: an endpoint URL plus encryption keys.
3. **The server sends** an encrypted Web Push to that endpoint.
4. **The relay checks** the sender's signature and forwards the ciphertext through FCM.
5. **The phone decrypts** and shows the notification, even if the app was closed.

## Three steps to your first notification

**1. Deploy the relay once, for your app** ([guide](docs/deploy.md))

```sh
npx wrangler secret put PUSHHARBOR_FCM_SERVICE_ACCOUNT < service-account.json
npx wrangler deploy --var PUSHHARBOR_ORIGIN:https://push.example.com
```

Or `docker compose up` with SQLite, a Helm chart with PostgreSQL, or Cloud Run.

**2. Register the device in your app** ([guide](docs/expo.md))

```ts
import * as Pushharbor from '@pushharbor/expo';

const subscription = await Pushharbor.register({
  relayUrl: 'https://push.example.com',
  senderKey: serverVapidPublicKey, // fetched from the user's server
});
await api.post('/push/subscriptions', subscription);
```

**3. Send from any self-hosted server** ([guide](docs/sending.md))

```js
webpush.setVapidDetails('mailto:ops@example.com', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
await webpush.sendNotification(subscription, JSON.stringify({
  t: 'New message',
  b: 'Alice: are we still on for 7?',
}));
```

That's the whole integration. No SDK on the server, no account, no keys to distribute.

## How it compares

| | Ship your FCM key to every server | Run a plain push proxy | **Pushharbor** |
|---|---|---|---|
| Self-hosters need your credentials | yes | no | **no** |
| Self-hosters need an account or API key | no | usually | **no** |
| Who can read notifications in transit | Google | you and Google | **nobody: end-to-end encrypted** |
| A leaked endpoint lets anyone send | n/a | depends on the proxy | **no, bound to one sender key** |
| Works with existing Web Push libraries | no | rarely | **yes** |
| Hosting | n/a | one way | **Workers, Docker, Kubernetes, Cloud Run** |

## Built to be trusted

- **Open protocol.** A versioned [specification](docs/spec/README.md) with machine-readable
  test vectors, so anyone can write a client or another relay.
- **One test suite, every deployment.** The same conformance suite runs in CI against Workers,
  SQLite, PostgreSQL, a two-instance cluster, Docker Compose, a Helm install and the Cloud Run
  container on every commit.
- **Real libraries, real phones.** Four Web Push libraries are tested against the relay in CI,
  and the full flow was verified on a Pixel 8 Pro through both Workers and a container.
- **Nothing sensitive in logs.** A CI guard and a runtime check make sure device IDs, keys and
  endpoint URLs never reach a log line.
- **MIT licensed.** Self-host it, fork it, ship it.

## Status

| | |
|---|---|
| **Android** | Supported: relay (Workers and container), Expo / React Native module, real-device tested |
| **iOS** | Planned: the protocol and message size limit are already designed for APNs |
| **Releases** | Pre-release: the container image and the npm package publish with the first tagged version |

## Documentation

| Guide | For |
|---|---|
| [Deploy a relay](docs/deploy.md) | App publishers: Firebase setup, Workers, Docker Compose, Helm, Cloud Run, moving between them |
| [Send notifications](docs/sending.md) | Server developers: Node, Python, Go and PHP, with errors and retries |
| [Expo module](docs/expo.md) | App developers: install, register, receive |
| [Protocol spec](docs/spec/README.md) | Implementers: APIs, encryption envelope, errors, test vectors |

## Contributing

Pushharbor is written in Rust (one core shared by the Workers and container builds) with a
Kotlin/TypeScript Expo module. You need Rust, Node.js and Docker; run `just` to list tasks and
`just ci` for the checks CI runs first.

<details>
<summary>Repository layout</summary>

- `crates/core`: protocol logic without I/O (native and wasm32)
- `crates/native`: axum/tokio server for containers (SQLite or PostgreSQL)
- `crates/worker`: Cloudflare Workers + Durable Objects adapter
- `crates/conformance`: black-box test suite every hosting option must pass
- `packages/expo`: Expo / React Native client module (Android); example app in `examples/expo`
- `examples/senders`: sending examples from the guide, tested in CI
- `interop`: Web Push libraries (Node, Python, Go, PHP) tested against the relay
- `deploy`: reference deployments (Compose, Helm, Cloud Run)
- `docs`: guides, the protocol spec and the device test checklist

</details>

## License

[MIT](LICENSE)

<details>
<summary>Diagram sources</summary>

The diagram is generated from [docs/src/architecture.diagram.json](docs/src/architecture.diagram.json)
(editable scene: `docs/src/architecture.excalidraw`). Icons from [Iconify](https://iconify.design/):

| Icon | File | Set | Author | License | Source |
| --- | --- | --- | --- | --- | --- |
| `mdi:cellphone` | `docs/assets/icons/mdi--cellphone.svg` | Material Design Icons | Pictogrammers | Apache 2.0 | https://api.iconify.design/mdi/cellphone.svg?color=%231971c2 |
| `mdi:server` | `docs/assets/icons/mdi--server.svg` | Material Design Icons | Pictogrammers | Apache 2.0 | https://api.iconify.design/mdi/server.svg?color=%23364fc7 |
| `mdi:transit-connection-variant` | `docs/assets/icons/mdi--transit-connection-variant.svg` | Material Design Icons | Pictogrammers | Apache 2.0 | https://api.iconify.design/mdi/transit-connection-variant.svg?color=%23d9480f |
| `simple-icons:firebase` | `docs/assets/icons/simple-icons--firebase.svg` | Simple Icons | Simple Icons Collaborators | CC0 1.0 | https://api.iconify.design/simple-icons/firebase.svg?color=%23a61e4d |
| `simple-icons:apple` | `docs/assets/icons/simple-icons--apple.svg` | Simple Icons | Simple Icons Collaborators | CC0 1.0 | https://api.iconify.design/simple-icons/apple.svg?color=%23495057 |

</details>
