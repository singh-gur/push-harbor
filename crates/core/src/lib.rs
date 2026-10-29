//! Pushharbor core: protocol logic shared by the Workers and native adapters.
//!
//! Must stay free of I/O so it builds for both `wasm32-unknown-unknown` and native targets.

pub mod vapid;
