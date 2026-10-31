# Pushharbor

Push notifications for apps whose servers are self-hosted.

If you publish a mobile app and your users run their own server for it, those servers can't
hold your Firebase or APNs credentials. Pushharbor is the relay you run once for your app:
every self-hosted server sends through it with a standard **Web Push** library, and only the
user's phone can read the message.

![How a notification travels: the app registers with the relay and gives its server a
subscription; the server sends an encrypted Web Push to the relay, which forwards the ciphertext
through FCM to the device](docs/assets/architecture.png)

- **Servers need no account.** A server can reach only the devices whose apps gave it a
  subscription, and only with the VAPID key the app bound it to.
- **End-to-end encrypted.** The server encrypts for the device (RFC 8291); the relay, Google and
  Apple see ciphertext only. Anything that doesn't decrypt is dropped on the device.
- **Proof of possession.** An endpoint is issued only after the device answers a challenge push,
  so knowing someone's FCM ID isn't enough to reach them.
- **Runs where you want.** Cloudflare Workers (lowest cost), or one container with SQLite, or
  any number of containers with PostgreSQL. Same API everywhere, and you can move between them.

## Status

| | |
|---|---|
| Android (FCM) | Supported: relay, Expo module, end-to-end tested on a Pixel 8 Pro (Android 17) through both relays |
| iOS (APNs) | Planned; the protocol and payload cap already account for it |
| Releases | Not yet published (container image on the first tag, npm package after) |

## Documentation

| Guide | For |
|---|---|
| [Deploying a relay](docs/deploy.md) | App publishers: Firebase setup, Workers, Docker Compose, Helm, Cloud Run, moving between them |
| [Sending notifications](docs/sending.md) | Server developers: Node, Python, Go and PHP with the required settings, errors and retries |
| [Expo module](docs/expo.md) | App developers: install, register, receive |
| [Protocol spec v1](docs/spec/README.md) | Implementers: send and registration APIs, envelope, errors, export format, test vectors |

## Repository

- `crates/core`: protocol logic without I/O (native and wasm32)
- `crates/native`: axum/tokio server for containers (SQLite or PostgreSQL)
- `crates/worker`: Cloudflare Workers + Durable Objects adapter
- `crates/conformance`: black-box test suite every hosting option must pass
- `packages/expo`: Expo / React Native client module (Android); example app in `examples/expo`
- `examples/senders`: sending examples from the guide, tested in CI
- `interop`: Web Push libraries (Node, Python, Go, PHP) tested against the relay
- `deploy`: reference deployments (Compose, Helm, Cloud Run)
- `docs`: guides and the protocol spec

Development needs Rust, Node.js and Docker. Run `just` to list tasks; `just ci` runs the checks
CI runs first.

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
