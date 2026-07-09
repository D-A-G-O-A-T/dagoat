//! Hash-chain and rolling re-attestation (device-agnostic). A-3 (signed-record commitment),
//! A-4 (strict epoch monotonicity), A-5 (staleness weights, never penalizes).

use crate::capability::{record_hash, verify_record_signature, CapabilityRecord, ZERO32};

#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    BadSignature,
    BrokenLink,
    NonIncreasingEpoch,
}

/// ~30 days at hourly attestation epochs.
pub const DEFAULT_MAX_BENCH_AGE_EPOCHS: u64 = 30 * 24;

pub struct RecordChain {
    pubkey: Vec<u8>,
    records: Vec<CapabilityRecord>,
}

impl RecordChain {
    pub fn new(pubkey: Vec<u8>) -> Self {
        Self {
            pubkey,
            records: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn head_hash(&self) -> Vec<u8> {
        match self.records.last() {
            Some(r) => record_hash(r),
            None => ZERO32.to_vec(),
        }
    }

    pub fn append(&mut self, r: CapabilityRecord) -> Result<(), ChainError> {
        if !verify_record_signature(&r, &self.pubkey) {
            return Err(ChainError::BadSignature);
        }
        if r.prev_record != self.head_hash() {
            return Err(ChainError::BrokenLink);
        }
        if let Some(last) = self.records.last() {
            if r.epoch <= last.epoch {
                return Err(ChainError::NonIncreasingEpoch); // A-4
            }
        }
        self.records.push(r);
        Ok(())
    }

    pub fn verify_integrity(&self) -> bool {
        let mut prev = ZERO32.to_vec();
        for r in &self.records {
            if !verify_record_signature(r, &self.pubkey) {
                return false;
            }
            if r.prev_record != prev {
                return false;
            }
            prev = record_hash(r);
        }
        true
    }

    /// Test/inspection hook: replace a stored record (used to prove tamper detection).
    #[doc(hidden)]
    pub fn replace_record(&mut self, idx: usize, r: CapabilityRecord) {
        self.records[idx] = r;
    }
}

/// A node may declare a longer attestation cadence for bandwidth reasons. Within cadence it
/// is full-weight; beyond, capability is confidence-weighted down (never penalized). (0, 1].
pub fn staleness_weight(
    record_epoch: u64,
    current_epoch: u64,
    declared_cadence_epochs: u64,
) -> f64 {
    let age = current_epoch.saturating_sub(record_epoch);
    if age <= declared_cadence_epochs {
        1.0
    } else {
        (declared_cadence_epochs as f64 / age as f64).max(0.1)
    }
}

pub fn needs_rebenchmark(
    last_bench_epoch: u64,
    current_epoch: u64,
    fingerprint_changed: bool,
    profile_version_changed: bool,
    max_age_epochs: u64,
) -> bool {
    fingerprint_changed
        || profile_version_changed
        || current_epoch.saturating_sub(last_bench_epoch) >= max_age_epochs
}
