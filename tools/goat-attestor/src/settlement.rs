//! Auto confirm → finalize → claim after a proposed epoch batch (pilot automation).
//!
//! On anvil, warps past `challengeDeadline` so the 12h window does not block lab loops.
//! First claim per worker stamps baseline (mint 0); later epochs mint score delta × rate.

use tracing::{info, warn};

use crate::chain::{BatchStatus, ChainClient, ChainError};
use crate::merkle::{Leaf, MerkleTree, parse_address};
use crate::proposer::EpochBatch;

#[derive(Debug, Clone)]
pub struct SettleClaimReport {
    pub epoch_id: u64,
    pub confirmed: bool,
    pub finalized: bool,
    pub claims_ok: usize,
    pub claims_fail: usize,
    pub claims_skipped: usize,
    /// Leaves deferred due to RPC/infrastructure errors (non-forfeiting; retry next cycle).
    pub claims_deferred: usize,
    pub notes: Vec<String>,
}

/// Close challenge window (anvil warp), watcher-confirm, finalize, claim every leaf.
pub fn settle_and_claim_batch(
    chain: &dyn ChainClient,
    batch: &EpochBatch,
    auto_warp: bool,
) -> Result<SettleClaimReport, ChainError> {
    let mut report = SettleClaimReport {
        epoch_id: batch.epoch_id,
        confirmed: false,
        finalized: false,
        claims_ok: 0,
        claims_fail: 0,
        claims_skipped: 0,
        claims_deferred: 0,
        notes: Vec::new(),
    };

    let mut view = chain.get_batch(batch.epoch_id)?;
    if view.status == BatchStatus::None {
        return Err(ChainError::NotFound(batch.epoch_id));
    }
    if view.status == BatchStatus::Finalized {
        report.notes.push("already finalized".into());
    } else {
        // Wait until past challenge deadline.
        let now = chain.block_timestamp().unwrap_or(0);
        let deadline = view.challenge_deadline;
        if now <= deadline {
            let wait = (deadline - now).saturating_add(2);
            if auto_warp {
                info!(
                    "auto-warp +{wait}s past challengeDeadline for epoch {}",
                    batch.epoch_id
                );
                chain.increase_time(wait)?;
                report.notes.push(format!("warped +{wait}s"));
            } else {
                return Err(ChainError::Msg(format!(
                    "challenge window open until {deadline} (now={now}); set AUTO_WARP=1 on anvil or wait"
                )));
            }
        }

        // Watcher confirm (required unless past deadline + watcherGrace).
        match chain.confirm_epoch(batch.epoch_id) {
            Ok(tx) => {
                report.confirmed = true;
                report
                    .notes
                    .push(format!("confirm tx=0x{}", hex::encode(tx)));
            }
            Err(e) => {
                warn!("confirm_epoch({}): {e}", batch.epoch_id);
                report.notes.push(format!("confirm: {e}"));
                // Lab fallback: warp past 1d watcherGrace so finalize is permissionless.
                if auto_warp {
                    let grace = 86_400u64 + 2;
                    info!("confirm failed — warping +{grace}s for watcherGrace timeout");
                    chain.increase_time(grace)?;
                    report.notes.push(format!("grace warp +{grace}s"));
                }
            }
        }

        match chain.finalize_batch(batch.epoch_id) {
            Ok(tx) => {
                report.finalized = true;
                report
                    .notes
                    .push(format!("finalize tx=0x{}", hex::encode(tx)));
            }
            Err(e) => {
                return Err(ChainError::Msg(format!(
                    "finalize_batch({}): {e}",
                    batch.epoch_id
                )));
            }
        }
        view = chain.get_batch(batch.epoch_id)?;
    }

    if view.status != BatchStatus::Finalized {
        return Err(ChainError::WrongStatus {
            epoch: batch.epoch_id,
        });
    }

    // Rebuild Merkle tree from batch leaves for OZ proofs.
    let mut leaves = Vec::with_capacity(batch.leaves.len());
    for rec in &batch.leaves {
        let wallet = parse_address(&rec.wallet)
            .map_err(|e| ChainError::Msg(format!("leaf wallet: {e}")))?;
        leaves.push(Leaf {
            wallet,
            cumulative_score: rec.cumulative_score,
        });
    }
    let tree = MerkleTree::build(leaves);

    for rec in &batch.leaves {
        let wallet = match parse_address(&rec.wallet) {
            Ok(w) => w,
            Err(e) => {
                report.claims_fail += 1;
                report.notes.push(format!("skip {}: {e}", rec.wallet));
                continue;
            }
        };
        // Gas-skip / defer policy:
        // - Err from last_claimed_cumulative or (when lc>=score) has_baseline → DEFER:
        //   infrastructure failure; do not submit blind; retry next cycle (non-forfeiting).
        // - Ok(None) from last_claimed_cumulative → SUBMIT: "unknown" is not failure;
        //   baseline liveness requires claiming when the ChainClient cannot answer.
        // - Ok(Some(lc)) if lc >= score and has_baseline Ok(Some(true)) → SKIP (already claimed).
        // - Ok(Some(lc)) if lc >= score and has_baseline Ok(Some(false)|None) → SUBMIT (stamp baseline).
        // TODO(v1.1): optional skip when expected liquid after keeper fee would be 0
        // (review §6.2.3) — out of scope for enrollment-barrier hardening.
        match chain.last_claimed_cumulative(&rec.wallet) {
            Err(e) => {
                warn!(
                    "defer claim epoch={} worker={}: last_claimed_cumulative error: {e}",
                    batch.epoch_id, rec.wallet
                );
                report.claims_deferred += 1;
                report.notes.push(format!(
                    "defer claim {}: last_claimed_cumulative error: {e}",
                    rec.wallet
                ));
                continue;
            }
            Ok(Some(lc)) if lc >= rec.cumulative_score => {
                match chain.has_baseline(&rec.wallet) {
                    Ok(Some(true)) => {
                        info!(
                            "skip claim epoch={} worker={} last_claimed={} leaf_score={} (already claimed)",
                            batch.epoch_id, rec.wallet, lc, rec.cumulative_score
                        );
                        report.claims_skipped += 1;
                        report.notes.push(format!(
                            "skip claim {}: last_claimed={lc} >= score={}",
                            rec.wallet, rec.cumulative_score
                        ));
                        continue;
                    }
                    Err(e) => {
                        warn!(
                            "defer claim epoch={} worker={}: has_baseline error: {e}",
                            batch.epoch_id, rec.wallet
                        );
                        report.claims_deferred += 1;
                        report.notes.push(format!(
                            "defer claim {}: has_baseline error: {e}",
                            rec.wallet
                        ));
                        continue;
                    }
                    Ok(Some(false)) | Ok(None) => {
                        // No baseline yet / unknown: submit claim (stamps watermark; may mint 0).
                    }
                }
            }
            Ok(Some(_)) | Ok(None) => {
                // Proceed to claim (unknown or lower last_claimed must not gas-skip).
            }
        }
        let proof = match tree.proof_for_wallet(&wallet) {
            Ok(p) => p,
            Err(e) => {
                report.claims_fail += 1;
                report.notes.push(format!("proof {}: {e}", rec.wallet));
                continue;
            }
        };
        match chain.claim_payout(
            batch.epoch_id,
            wallet,
            rec.cumulative_score,
            &proof,
        ) {
            Ok(tx) => {
                report.claims_ok += 1;
                info!(
                    "claim epoch={} worker={} score={} tx=0x{}",
                    batch.epoch_id,
                    rec.wallet,
                    rec.cumulative_score,
                    hex::encode(tx)
                );
            }
            Err(e) => {
                report.claims_fail += 1;
                warn!(
                    "claim failed epoch={} worker={}: {e}",
                    batch.epoch_id, rec.wallet
                );
                report
                    .notes
                    .push(format!("claim {}: {e}", rec.wallet));
            }
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{MockChain, MockOp};
    use crate::proposer::build_epoch_batch;
    use crate::registry::WorkerEntry;

    const BOND: u128 = 1_000_000_000_000_000_000;
    const WALLET: &str = "0x00000000000000000000000000000000000000A1";

    fn alice_worker(score: u128) -> (WorkerEntry, u128) {
        (
            WorkerEntry {
                wallet: WALLET.into(),
                username: "GOAT-alice".into(),
                baseline_batched: false,
                fah_id: None,
                enrollment_epoch: None,
            },
            score,
        )
    }

    fn propose_and_finalize(chain: &MockChain, epoch: u64, score: u128) -> crate::proposer::EpochBatch {
        let workers = [alice_worker(score)];
        let batch = build_epoch_batch(epoch, &workers, None).unwrap();
        chain
            .propose_batch(
                batch.epoch_id,
                batch.merkle_root,
                batch.evidence_ref,
                BOND,
            )
            .unwrap();
        batch
    }

    #[test]
    fn mock_settle_and_claim_baseline() {
        let chain = MockChain::new().with_bonds(BOND, BOND);
        let batch = propose_and_finalize(&chain, 9_000_000_000_001, 1_000_000);
        // Mock confirm requires Proposed + window — mock doesn't check window.
        let report = settle_and_claim_batch(&chain, &batch, true).unwrap();
        assert!(report.finalized || report.claims_ok >= 1 || report.confirmed);
        // After claim, has baseline
        assert_eq!(
            chain.has_baseline("0x00000000000000000000000000000000000000a1").unwrap(),
            Some(true)
        );
        assert_eq!(report.claims_skipped, 0);
        assert!(
            chain.ops().iter().any(|op| matches!(
                op,
                MockOp::Claim {
                    epoch: 9_000_000_000_001,
                    proven_score: 1_000_000,
                    ..
                }
            )),
            "expected Claim op, got {:?}",
            chain.ops()
        );
    }

    #[test]
    fn gas_skip_when_last_claimed_gte_leaf_score() {
        let chain = MockChain::new().with_bonds(BOND, BOND);
        let score = 1_000_000u128;
        // Already-baselined worker: lc-based gas-skip only applies with hasBaseline.
        chain.set_has_baseline(WALLET, true);
        chain.set_last_claimed_cumulative(WALLET, score);
        let batch = propose_and_finalize(&chain, 20260714, score);
        let report = settle_and_claim_batch(&chain, &batch, true).unwrap();
        assert_eq!(report.claims_skipped, 1);
        assert_eq!(report.claims_ok, 0);
        assert!(
            !chain.ops().iter().any(|op| matches!(op, MockOp::Claim { .. })),
            "must not claim when last_claimed >= leaf score: {:?}",
            chain.ops()
        );
    }

    #[test]
    fn claim_when_last_claimed_lt_leaf_score() {
        let chain = MockChain::new().with_bonds(BOND, BOND);
        let score = 2_000_000u128;
        chain.set_last_claimed_cumulative(WALLET, 1_000_000);
        let batch = propose_and_finalize(&chain, 20260715, score);
        let report = settle_and_claim_batch(&chain, &batch, true).unwrap();
        assert_eq!(report.claims_ok, 1);
        assert_eq!(report.claims_skipped, 0);
        assert!(
            chain.ops().iter().any(|op| matches!(
                op,
                MockOp::Claim {
                    epoch: 20260715,
                    proven_score: 2_000_000,
                    ..
                }
            )),
            "expected Claim, got {:?}",
            chain.ops()
        );
    }

    #[test]
    fn unset_last_claimed_never_skips() {
        let chain = MockChain::new().with_bonds(BOND, BOND);
        // last_claimed unset → Ok(None) → must claim
        let batch = propose_and_finalize(&chain, 20260716, 500_000);
        let report = settle_and_claim_batch(&chain, &batch, true).unwrap();
        assert_eq!(report.claims_skipped, 0);
        assert_eq!(report.claims_deferred, 0);
        assert_eq!(report.claims_ok, 1);
        assert!(
            chain.ops().iter().any(|op| matches!(op, MockOp::Claim { .. })),
            "unset last_claimed must not skip: {:?}",
            chain.ops()
        );
    }

    /// (h) last_claimed_cumulative Err → defer: no Claim, claims_deferred==1.
    #[test]
    fn defer_when_last_claimed_rpc_err() {
        let chain = MockChain::new().with_bonds(BOND, BOND);
        chain.set_force_last_claimed_err(WALLET, true);
        let batch = propose_and_finalize(&chain, 20260719, 1_000_000);
        let report = settle_and_claim_batch(&chain, &batch, true).unwrap();
        assert_eq!(report.claims_deferred, 1);
        assert_eq!(report.claims_skipped, 0);
        assert_eq!(report.claims_ok, 0);
        assert!(
            !chain.ops().iter().any(|op| matches!(op, MockOp::Claim { .. })),
            "must not claim when last_claimed RPC fails: {:?}",
            chain.ops()
        );
    }

    /// (i) last_claimed >= leaf score AND has_baseline Err → defer.
    #[test]
    fn defer_when_has_baseline_rpc_err_with_last_claimed_gte() {
        let chain = MockChain::new().with_bonds(BOND, BOND);
        let score = 1_000_000u128;
        chain.set_last_claimed_cumulative(WALLET, score);
        chain.set_force_has_baseline_err(WALLET, true);
        let batch = propose_and_finalize(&chain, 20260720, score);
        let report = settle_and_claim_batch(&chain, &batch, true).unwrap();
        assert_eq!(report.claims_deferred, 1);
        assert_eq!(report.claims_skipped, 0);
        assert_eq!(report.claims_ok, 0);
        assert!(
            !chain.ops().iter().any(|op| matches!(op, MockOp::Claim { .. })),
            "must not claim when has_baseline RPC fails: {:?}",
            chain.ops()
        );
    }

    /// (f) Fresh worker: mapping-default lastClaimed=0, no hasBaseline, leaf score 0.
    /// Must still submit baseline claim (stamps hasBaseline); must not gas-skip.
    #[test]
    fn fresh_worker_zero_score_with_default_last_claimed_still_claims() {
        let chain = MockChain::new().with_bonds(BOND, BOND);
        // Simulate Solidity mapping default: lastClaimedCumulative reads Some(0).
        // Do NOT call set_has_baseline — worker has no on-chain baseline yet.
        chain.set_last_claimed_cumulative(WALLET, 0);
        let batch = propose_and_finalize(&chain, 20260717, 0);
        let report = settle_and_claim_batch(&chain, &batch, true).unwrap();
        assert_eq!(report.claims_ok, 1);
        assert_eq!(report.claims_skipped, 0);
        assert!(
            chain.ops().iter().any(|op| matches!(
                op,
                MockOp::Claim {
                    epoch: 20260717,
                    proven_score: 0,
                    ..
                }
            )),
            "baseline claim must be submitted for fresh worker: {:?}",
            chain.ops()
        );
        assert_eq!(
            chain.has_baseline(WALLET).unwrap(),
            Some(true),
            "successful claim must stamp hasBaseline"
        );
    }

    /// (g) Already-baselined worker with last_claimed >= leaf score: still gas-skip.
    #[test]
    fn gas_skip_when_baselined_and_last_claimed_gte_leaf_score() {
        let chain = MockChain::new().with_bonds(BOND, BOND);
        let score = 1_000_000u128;
        chain.set_has_baseline(WALLET, true);
        chain.set_last_claimed_cumulative(WALLET, score);
        let batch = propose_and_finalize(&chain, 20260718, score);
        let report = settle_and_claim_batch(&chain, &batch, true).unwrap();
        assert_eq!(report.claims_skipped, 1);
        assert_eq!(report.claims_ok, 0);
        assert!(
            !chain.ops().iter().any(|op| matches!(op, MockOp::Claim { .. })),
            "must not claim when baselined and last_claimed >= leaf score: {:?}",
            chain.ops()
        );
    }
}
