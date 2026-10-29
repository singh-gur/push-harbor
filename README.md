# Pushharbor

Open-source, Web Push compatible push relay that lets self-hosted servers of an app send notifications to its iOS and Android users without holding APNs/FCM credentials.

**Status:** pre-alpha, nothing usable yet.

## Layout

- `crates/core` – protocol logic, no I/O (native + wasm32)
- `crates/worker` – Cloudflare Workers + Durable Objects adapter
- `crates/native` – axum/tokio server for containers (SQLite / PostgreSQL)

Run `just` to list development tasks.

## License

[MIT](LICENSE)
