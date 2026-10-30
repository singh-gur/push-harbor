//! Pushharbor core: protocol logic shared by the Workers and native adapters.
//!
//! Must stay free of I/O so it builds for both `wasm32-unknown-unknown` and native targets.
//! Adapters provide time, randomness, storage, rate limits and HTTP through [`adapter`].

pub mod adapter;
pub mod error;
#[cfg(any(test, feature = "fakes"))]
pub mod fakes;
pub mod fcm;
pub mod limits;
pub mod model;
pub mod send;
pub mod vapid;

pub use error::Error;
