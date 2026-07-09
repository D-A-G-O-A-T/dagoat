//! GoatCoin (GOAT) MVP-2 — distributed verification (device-agnostic).
//!
//! PQ-authenticated transport (ML-KEM-768 + AES-GCM), an orchestrator enforcing the
//! executor-set spread rule with signed assignment logs, beacon-seeded lottery
//! third-executor selection, and the distributed verification loop that reuses the MVP-1
//! ledger + fraud-proof logic. Roles communicate only through the transport.

pub mod codec;
pub mod density;
pub mod distributed;
pub mod stats;
pub mod testnet;
pub mod transport;
