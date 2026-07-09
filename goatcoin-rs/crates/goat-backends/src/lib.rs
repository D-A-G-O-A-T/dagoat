//! GoatCoin (GOAT) reference backends (DEVICE layer). Below the GoatHAL trait; device-
//! specific by nature and excluded from the neutrality scan. Backends still never inspect
//! payload content/model/license — only run opaque work.

pub mod refcompute;
pub mod reference_a;
pub mod reference_b;

pub use reference_a::ReferenceBackendA;
pub use reference_b::ReferenceBackendB;
