//! GoatCoin (GOAT) Phase 3 protocol core (device-agnostic).
//!
//! Layer discipline: this crate must never name a device type or inspect
//! model/content/license. Enforced at compile time (no backend dependency) and at
//! lint time by the `goat-neutrality` auditor.

pub mod attestation_chain;
pub mod backend;
pub mod capability;
pub mod commit;
pub mod conformance;
pub mod hll;
pub mod maturity;
pub mod pqsign;
pub mod provenance;
pub mod types;
pub mod verification;

#[cfg(test)]
mod pqsign_smoke {
    use crate::pqsign::*;

    #[test]
    fn mldsa_sizes_match_fips204() {
        let s = MlDsaSigner::generate();
        assert_eq!(s.public_key().len(), ML_DSA_65_PUBKEY_BYTES);
        assert_eq!(s.sign(b"x").len(), ML_DSA_65_SIG_BYTES);
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let s = MlDsaSigner::generate();
        let pk = s.public_key();
        let sig = s.sign(b"hello");
        assert!(verify(AlgId::MlDsa65, &pk, b"hello", &sig));
        assert!(!verify(AlgId::MlDsa65, &pk, b"HELLO", &sig));
    }

    #[test]
    fn wrong_key_rejected() {
        let a = MlDsaSigner::generate();
        let b = MlDsaSigner::generate();
        let sig = a.sign(b"m");
        assert!(!verify(AlgId::MlDsa65, &b.public_key(), b"m", &sig));
    }
}
