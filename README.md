# Pushharbor

Open-source, Web Push compatible push relay that lets self-hosted servers of an app send notifications to its iOS and Android users without holding APNs/FCM credentials.

**Status:** pre-alpha, nothing usable yet.

## Layout

- `crates/core` – protocol logic, no I/O (native + wasm32)
- `crates/worker` – Cloudflare Workers + Durable Objects adapter
- `crates/native` – axum/tokio server for containers (SQLite / PostgreSQL)
- `crates/conformance` – black-box test suite every hosting option must pass
- `docs/spec` – protocol specification v1 and test vectors
- `docs/deploy.md`, `deploy/` – reference deployments: Workers, Docker Compose, Helm, Cloud Run
- `packages/expo` – Expo / React Native client module (Android), example app in `examples/expo`
- `interop` – Web Push sender libraries (Node, Python, Go, PHP) tested against the relay

Run `just` to list development tasks.

## License

[MIT](LICENSE)
