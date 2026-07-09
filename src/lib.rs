//! GoatCoin (GOAT) V1.0 core — the sealed `#![no_std]`, allocation-free, panic-free protocol crate.
//!
//! Six modules make up the device-neutral, post-quantum, DoS-hardened core (see `ARCHITECTURE.md`).
//! The `goatd` binary (`src/bin/goatd.rs`) is the *only* place `std`, the allocator, and async live;
//! it wraps this crate behind a `tokio` runtime.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod crypto;
pub mod daemon;
pub mod gossip;
pub mod state;
pub mod transport;
pub mod types;
