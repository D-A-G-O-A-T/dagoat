//! Epoch batch builder + proposer (full daily + enrollment snapshots + confirm).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::chain::{ChainClient, ChainError};
use crate::evidence::{evidence_ref_keccak, write_evidence_json};
use crate::fah::{FahClient, FahError, HttpGet};
use crate::merkle::{Leaf, MerkleTree, parse_address};
use crate::registry::{WorkerEntry, WorkerRegistry};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochLeafRecord {
    pub wallet: String,
    pub username: String,
    pub cumulative_score: u128,
    pub leaf_hash_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochBatch {
    pub epoch_id: u64,
    pub leaves: Vec<EpochLeafRecord>,
    pub merkle_root: [u8; 32],
    pub merkle_root_hex: String,
    pub evidence_ref: [u8; 32],
    pub evidence_path: Option<String>,
}

#[derive(Debug, Error)]
pub enum ProposerError {
    #[error("FAH: {0}")]
    Fah(#[from] FahError),
    #[error("chain: {0}")]
    Chain(#[from] ChainError),
    #[error("registry: {0}")]
    Registry(String),
    #[error("merkle: {0}")]
    Merkle(String),
    #[error("evidence: {0}")]
    Evidence(String),
    #[error("empty batch")]
    EmptyBatch,
}

/// Daily epoch id: `YYYYMMDD` as u64 (UTC).
pub fn daily_epoch_id(unix_secs: u64) -> u64 {
    // Civil date from unix without chrono: use a simple algorithm.
    let days = (unix_secs / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    (y as u64) * 10_000 + (m as u64) * 100 + d as u64
}

/// Base of the enrollment freeform epoch id space (disjoint from `YYYYMMDD` dailies).
pub const ENROLLMENT_EPOCH_BASE: u64 = 9_000_000_000_000;

/// Enrollment epoch id space: `ENROLLMENT_EPOCH_BASE + unix` (freeform, disjoint from daily).
pub fn enrollment_epoch_id(unix_secs: u64) -> u64 {
    ENROLLMENT_EPOCH_BASE + unix_secs
}

/// True when `epoch_id` is in the enrollment-snapshot id space.
///
/// Challengers MUST use strict equality (`proposed == public`) for these epochs —
/// under-reporting a baseline is protocol theft, not "worker loss".
pub fn is_enrollment_epoch(epoch_id: u64) -> bool {
    epoch_id >= ENROLLMENT_EPOCH_BASE
}

/// Howard Hinnant civil_from_days (proleptic Gregorian).
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build an epoch batch from worker list + already-fetched scores.
pub fn build_epoch_batch(
    epoch_id: u64,
    workers: &[(WorkerEntry, u128)],
    evidence_dir: Option<&Path>,
) -> Result<EpochBatch, ProposerError> {
    if workers.is_empty() {
        return Err(ProposerError::EmptyBatch);
    }

    let mut leaves = Vec::with_capacity(workers.len());
    let mut records = Vec::with_capacity(workers.len());

    for (w, score) in workers {
        let wallet = parse_address(&w.wallet).map_err(ProposerError::Merkle)?;
        let leaf = Leaf {
            wallet,
            cumulative_score: *score,
        };
        let h = crate::merkle::leaf_hash(&leaf);
        records.push(EpochLeafRecord {
            wallet: w.wallet.clone(),
            username: w.username.clone(),
            cumulative_score: *score,
            leaf_hash_hex: format!("0x{}", hex::encode(h)),
        });
        leaves.push(leaf);
    }

    let tree = MerkleTree::build(leaves);
    let root = tree.root();

    #[derive(Serialize)]
    struct EvidenceDoc<'a> {
        epoch_id: u64,
        leaves: &'a [EpochLeafRecord],
        merkle_root: String,
    }

    let doc = EvidenceDoc {
        epoch_id,
        leaves: &records,
        merkle_root: format!("0x{}", hex::encode(root)),
    };
    let json = serde_json::to_vec_pretty(&doc).map_err(|e| ProposerError::Evidence(e.to_string()))?;
    let evidence_ref = evidence_ref_keccak(&json);

    let evidence_path = if let Some(dir) = evidence_dir {
        let name = format!("epoch_{epoch_id}.json");
        let path = write_evidence_json(dir, &name, &doc)
            .map_err(ProposerError::Evidence)?;
        Some(path.display().to_string())
    } else {
        None
    };

    Ok(EpochBatch {
        epoch_id,
        leaves: records,
        merkle_root: root,
        merkle_root_hex: format!("0x{}", hex::encode(root)),
        evidence_ref,
        evidence_path,
    })
}

pub struct Proposer<'a, C: ChainClient + ?Sized, H: HttpGet> {
    pub chain: &'a C,
    pub fah: &'a FahClient<H>,
    pub bond_wei: u128,
    pub evidence_dir: PathBuf,
    /// Directory for persisted enrollment batches (`enrollment_{epoch}.json`) used by retry.
    pub state_dir: PathBuf,
}

impl<'a, C: ChainClient + ?Sized, H: HttpGet> Proposer<'a, C, H> {
    /// Fetch FAH scores for all bound workers and propose a daily batch.
    ///
    /// When `epoch_id` is `None`, the daily epoch is derived from chain time
    /// when known, wall clock otherwise (keeps lab time-warps and dailies in sync).
    pub fn propose_full(
        &self,
        registry: &WorkerRegistry,
        epoch_id: Option<u64>,
    ) -> Result<EpochBatch, ProposerError> {
        let epoch = epoch_id.unwrap_or_else(|| {
            // 0 = unknown (ChainClient::block_timestamp default / Err) → wall-clock fallback.
            let ts = self.chain.block_timestamp().unwrap_or(0);
            daily_epoch_id(if ts > 0 { ts } else { now_unix() })
        });
        let mut scored = Vec::new();
        for w in registry.all_bound() {
            let stats = self.fah.fetch_user(&w.username)?;
            scored.push((w.clone(), stats.score as u128));
        }
        let batch = build_epoch_batch(epoch, &scored, Some(&self.evidence_dir))?;
        self.chain.propose_batch(
            batch.epoch_id,
            batch.merkle_root,
            batch.evidence_ref,
            self.bond_wei,
        )?;
        Ok(batch)
    }

    /// Propose enrollment-snapshot batches for workers not yet baseline-batched.
    /// Each newly-bound worker gets a prompt single-leaf (or multi-leaf) batch so
    /// first claimPayout can stamp baseline (mint 0).
    pub fn propose_enrollment_snapshots(
        &self,
        registry: &mut WorkerRegistry,
    ) -> Result<Vec<EpochBatch>, ProposerError> {
        let need: Vec<WorkerEntry> = registry
            .needs_enrollment_batch()
            .into_iter()
            .cloned()
            .collect();
        if need.is_empty() {
            return Ok(vec![]);
        }

        let mut scored = Vec::new();
        for w in &need {
            let stats = self.fah.fetch_user(&w.username)?;
            scored.push((w.clone(), stats.score as u128));
        }

        let epoch = enrollment_epoch_id(now_unix());
        let batch = build_epoch_batch(epoch, &scored, Some(&self.evidence_dir))?;
        self.chain.propose_batch(
            batch.epoch_id,
            batch.merkle_root,
            batch.evidence_ref,
            self.bond_wei,
        )?;

        // Persist full batch for enrollment retry when settle fails or is deferred.
        std::fs::create_dir_all(&self.state_dir).map_err(|e| {
            ProposerError::Evidence(format!("create state_dir {:?}: {e}", self.state_dir))
        })?;
        let path = self
            .state_dir
            .join(format!("enrollment_{}.json", batch.epoch_id));
        let json = serde_json::to_string_pretty(&batch)
            .map_err(|e| ProposerError::Evidence(format!("serialize enrollment batch: {e}")))?;
        std::fs::write(&path, json).map_err(|e| {
            ProposerError::Evidence(format!("write enrollment batch {:?}: {e}", path))
        })?;

        for w in &need {
            registry.mark_baseline_batched(&w.wallet, batch.epoch_id);
        }

        Ok(vec![batch])
    }

    /// Watcher heartbeat: confirm epoch if batch is in Proposed status.
    pub fn confirm_if_ready(&self, epoch_id: u64) -> Result<bool, ProposerError> {
        let view = self.chain.get_batch(epoch_id)?;
        if view.status == crate::chain::BatchStatus::Proposed {
            self.chain.confirm_epoch(epoch_id)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::MockChain;
    use crate::fah::{FixtureHttp, default_fixtures_dir};
    use std::time::Duration;
    use tempfile::tempdir;

    fn alice_bob_workers() -> Vec<(WorkerEntry, u128)> {
        vec![
            (
                WorkerEntry {
                    wallet: "0x00000000000000000000000000000000000000A1".into(),
                    username: "GOAT-alice".into(),
                    baseline_batched: true,
                    fah_id: Some(1001),
                    enrollment_epoch: None,
                },
                51_022_340,
            ),
            (
                WorkerEntry {
                    wallet: "0x00000000000000000000000000000000000000B2".into(),
                    username: "GOAT-bob".into(),
                    baseline_batched: true,
                    fah_id: Some(1002),
                    enrollment_epoch: None,
                },
                600_000,
            ),
        ]
    }

    #[test]
    fn build_epoch_batch_alice_bob() {
        let batch = build_epoch_batch(20260714, &alice_bob_workers(), None).unwrap();
        assert_eq!(batch.leaves.len(), 2);
        assert_eq!(batch.leaves[0].cumulative_score, 51_022_340);
        assert_eq!(batch.leaves[1].cumulative_score, 600_000);
        assert_ne!(batch.merkle_root, [0u8; 32]);
        // Root must match tree rebuild
        let leaves = vec![
            Leaf::from_hex(&batch.leaves[0].wallet, batch.leaves[0].cumulative_score).unwrap(),
            Leaf::from_hex(&batch.leaves[1].wallet, batch.leaves[1].cumulative_score).unwrap(),
        ];
        let tree = MerkleTree::build(leaves);
        assert_eq!(tree.root(), batch.merkle_root);
    }

    #[test]
    fn daily_epoch_id_format() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        let id = daily_epoch_id(1_704_067_200);
        assert_eq!(id, 20240101);
    }

    #[test]
    fn enrollment_epoch_disjoint() {
        let e = enrollment_epoch_id(1_700_000_000);
        assert!(e > 9_000_000_000_000);
        assert_ne!(e, daily_epoch_id(1_700_000_000));
    }

    #[test]
    fn propose_full_records_on_mock() {
        let dir = tempdir().unwrap();
        let chain = MockChain::new();
        let http = FixtureHttp::new(default_fixtures_dir());
        let fah = FahClient::new(http, "https://api.foldingathome.org", Duration::from_millis(0));
        let mut reg = WorkerRegistry::new();
        reg.upsert(WorkerEntry {
            wallet: "0x00000000000000000000000000000000000000A1".into(),
            username: "GOAT-alice".into(),
            baseline_batched: true,
            fah_id: None,
            enrollment_epoch: None,
        });
        reg.upsert(WorkerEntry {
            wallet: "0x00000000000000000000000000000000000000B2".into(),
            username: "GOAT-bob".into(),
            baseline_batched: true,
            fah_id: None,
            enrollment_epoch: None,
        });
        let p = Proposer {
            chain: &chain,
            fah: &fah,
            bond_wei: 1_000_000_000_000_000_000,
            evidence_dir: dir.path().to_path_buf(),
            state_dir: dir.path().join("state"),
        };
        let batch = p.propose_full(&reg, Some(20260714)).unwrap();
        assert_eq!(batch.epoch_id, 20260714);
        assert!(p.confirm_if_ready(20260714).unwrap());
        assert_eq!(chain.ops().len(), 2);
    }

    #[test]
    fn propose_full_daily_epoch_follows_chain_time_warp() {
        let dir = tempdir().unwrap();
        let chain = MockChain::new();
        let http = FixtureHttp::new(default_fixtures_dir());
        let fah = FahClient::new(http, "https://api.foldingathome.org", Duration::from_millis(0));
        let mut reg = WorkerRegistry::new();
        reg.upsert(WorkerEntry {
            wallet: "0x00000000000000000000000000000000000000A1".into(),
            username: "GOAT-alice".into(),
            baseline_batched: true,
            fah_id: None,
            enrollment_epoch: None,
        });
        reg.upsert(WorkerEntry {
            wallet: "0x00000000000000000000000000000000000000B2".into(),
            username: "GOAT-bob".into(),
            baseline_batched: true,
            fah_id: None,
            enrollment_epoch: None,
        });
        let p = Proposer {
            chain: &chain,
            fah: &fah,
            bond_wei: 1_000_000_000_000_000_000,
            evidence_dir: dir.path().to_path_buf(),
            state_dir: dir.path().join("state"),
        };

        chain.set_now(1_704_067_200); // 2024-01-01 00:00:00 UTC
        let b1 = p.propose_full(&reg, None).unwrap();
        assert_eq!(b1.epoch_id, 20240101);

        chain.increase_time(86_400).unwrap(); // lab analog of evm_increaseTime +1 day
        let b2 = p.propose_full(&reg, None).unwrap();
        assert_eq!(b2.epoch_id, 20240102);
    }

    #[test]
    fn propose_full_daily_epoch_wall_clock_fallback() {
        let dir = tempdir().unwrap();
        let chain = MockChain::new();
        let http = FixtureHttp::new(default_fixtures_dir());
        let fah = FahClient::new(http, "https://api.foldingathome.org", Duration::from_millis(0));
        let mut reg = WorkerRegistry::new();
        reg.upsert(WorkerEntry {
            wallet: "0x00000000000000000000000000000000000000A1".into(),
            username: "GOAT-alice".into(),
            baseline_batched: true,
            fah_id: None,
            enrollment_epoch: None,
        });
        reg.upsert(WorkerEntry {
            wallet: "0x00000000000000000000000000000000000000B2".into(),
            username: "GOAT-bob".into(),
            baseline_batched: true,
            fah_id: None,
            enrollment_epoch: None,
        });
        let p = Proposer {
            chain: &chain,
            fah: &fah,
            bond_wei: 1_000_000_000_000_000_000,
            evidence_dir: dir.path().to_path_buf(),
            state_dir: dir.path().join("state"),
        };

        chain.set_now(0); // timestamp unknown → wall-clock fallback
        let before = daily_epoch_id(now_unix());
        let b = p.propose_full(&reg, None).unwrap();
        let after = daily_epoch_id(now_unix());
        assert!(b.epoch_id == before || b.epoch_id == after);
    }
}
