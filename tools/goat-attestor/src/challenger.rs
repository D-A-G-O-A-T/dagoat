//! Challenger: re-read public FAH; slash bad proposals.
//!
//! # Challenge policy (consultant 2026-07-15 — baseline under-report hazard)
//!
//! - **Post-baseline daily batches:** inflate-only (`proposed > public`). Under-report
//!   is temporary worker loss; cumulative scores make them whole on a later honest batch.
//! - **Enrollment / pre-baseline leaves:** **strict equality** (`proposed != public`).
//!   Under-reporting a baseline is protocol theft: first `claimPayout` stamps the low
//!   watermark (mint 0), then a later true-score claim mints the entire historical delta.
//!
//! Enrollment epochs (`is_enrollment_epoch`) force strict for every leaf. Daily epochs
//! still apply strict to workers that have not yet been baseline-batched (or lack
//! on-chain baseline when the chain client can report it).

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Serialize;
use thiserror::Error;

use crate::chain::{BatchStatus, ChainClient, ChainError};
use crate::evidence::{evidence_ref_keccak, write_evidence_json};
use crate::fah::{FahClient, FahError, HttpGet};
use crate::proposer::is_enrollment_epoch;
use crate::registry::WorkerRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengePolicy {
    /// Daily post-baseline: challenge only if proposed > public.
    InflateOnly,
    /// Enrollment / pre-baseline: challenge any proposed != public (or missing public).
    StrictEquality,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeDecision {
    /// All checked leaves accepted under the applicable policy.
    Ok,
    /// At least one leaf violates policy — slash the proposer.
    Challenge {
        reason: String,
        worker: String,
        proposed: u128,
        public: Option<u128>,
        policy: ChallengePolicy,
    },
}

/// Evaluate proposed scores against public scores under a uniform policy.
pub fn evaluate_batch(
    proposed: &[(String, u128)],
    public: &[(String, u128)],
    policy: ChallengePolicy,
) -> ChallengeDecision {
    let pub_map: HashMap<String, u128> = public
        .iter()
        .map(|(w, s)| (w.to_ascii_lowercase(), *s))
        .collect();
    evaluate_batch_with_policy(proposed, &pub_map, |_| policy)
}

/// Per-wallet policy (enrollment epoch → all strict; else strict only pre-baseline).
pub fn evaluate_batch_with_policy<F>(
    proposed: &[(String, u128)],
    public: &HashMap<String, u128>,
    mut policy_for: F,
) -> ChallengeDecision
where
    F: FnMut(&str) -> ChallengePolicy,
{
    for (wallet, prop) in proposed {
        let policy = policy_for(wallet);
        let key = wallet.to_ascii_lowercase();
        match public.get(&key) {
            Some(pub_score) => match policy {
                ChallengePolicy::InflateOnly => {
                    if *prop > *pub_score {
                        return ChallengeDecision::Challenge {
                            reason: format!(
                                "inflate: proposed score {prop} > public score {pub_score} for {wallet}"
                            ),
                            worker: wallet.clone(),
                            proposed: *prop,
                            public: Some(*pub_score),
                            policy,
                        };
                    }
                }
                ChallengePolicy::StrictEquality => {
                    if *prop != *pub_score {
                        return ChallengeDecision::Challenge {
                            reason: format!(
                                "baseline-critical mismatch: proposed {prop} != public {pub_score} for {wallet} (under-report steals historical delta)"
                            ),
                            worker: wallet.clone(),
                            proposed: *prop,
                            public: Some(*pub_score),
                            policy,
                        };
                    }
                }
            },
            None => {
                if policy == ChallengePolicy::StrictEquality {
                    return ChallengeDecision::Challenge {
                        reason: format!(
                            "baseline-critical: public FAH score unavailable for {wallet}; cannot accept enrollment/pre-baseline leaf"
                        ),
                        worker: wallet.clone(),
                        proposed: *prop,
                        public: None,
                        policy,
                    };
                }
                // InflateOnly + missing public: cannot prove inflate; skip leaf.
            }
        }
    }
    ChallengeDecision::Ok
}

/// Resolve policy for one worker in an epoch.
///
/// Strict when:
/// - epoch is in the enrollment id space, OR
/// - worker has not completed a baseline-batch snapshot yet (`!baseline_batched`), OR
/// - chain reports `has_baseline == false` when available.
pub fn policy_for_worker(
    epoch_id: u64,
    baseline_batched: bool,
    has_baseline_on_chain: Option<bool>,
) -> ChallengePolicy {
    if is_enrollment_epoch(epoch_id) {
        return ChallengePolicy::StrictEquality;
    }
    if !baseline_batched {
        return ChallengePolicy::StrictEquality;
    }
    if has_baseline_on_chain == Some(false) {
        return ChallengePolicy::StrictEquality;
    }
    ChallengePolicy::InflateOnly
}

#[derive(Debug, Error)]
pub enum ChallengerError {
    #[error("FAH: {0}")]
    Fah(#[from] FahError),
    #[error("chain: {0}")]
    Chain(#[from] ChainError),
    #[error("evidence: {0}")]
    Evidence(String),
}

pub struct Challenger<'a, C: ChainClient + ?Sized, H: HttpGet> {
    pub chain: &'a C,
    pub fah: &'a FahClient<H>,
    pub bond_wei: u128,
    pub evidence_dir: PathBuf,
}

impl<'a, C: ChainClient + ?Sized, H: HttpGet> Challenger<'a, C, H> {
    /// Review a proposed epoch: re-fetch public scores and apply dual-mode policy.
    pub fn review_epoch(
        &self,
        epoch_id: u64,
        registry: &WorkerRegistry,
        proposed_scores: &[(String, u128)],
    ) -> Result<ChallengeDecision, ChallengerError> {
        let batch = self.chain.get_batch(epoch_id)?;
        if batch.status != BatchStatus::Proposed && batch.status != BatchStatus::None {
            return Ok(ChallengeDecision::Ok);
        }

        let mut public: HashMap<String, u128> = HashMap::new();
        let mut baseline_flag: HashMap<String, bool> = HashMap::new();
        for w in registry.all_bound() {
            baseline_flag.insert(w.wallet.to_ascii_lowercase(), w.baseline_batched);
            let stats = match self.fah.fetch_user_fresh(&w.username) {
                Ok((s, _)) => s,
                Err(FahError::RateLimited(_)) => self.fah.fetch_user(&w.username)?,
                Err(e) => {
                    // Strict path needs public score; still record absence for evaluate.
                    if is_enrollment_epoch(epoch_id) || !w.baseline_batched {
                        // leave missing → evaluate will challenge under StrictEquality
                        continue;
                    }
                    return Err(e.into());
                }
            };
            public.insert(w.wallet.to_ascii_lowercase(), stats.score as u128);
        }

        // Also index proposed wallets that may not be in registry (still check when possible).
        let reg_lookup: HashMap<String, bool> = registry
            .all_bound()
            .iter()
            .map(|w| (w.wallet.to_ascii_lowercase(), w.baseline_batched))
            .collect();

        let decision = evaluate_batch_with_policy(proposed_scores, &public, |wallet| {
            let key = wallet.to_ascii_lowercase();
            let batched = reg_lookup.get(&key).copied().unwrap_or(false);
            // Prefer on-chain baseline when client supports it.
            let on_chain = self.chain.has_baseline(wallet).ok().flatten();
            policy_for_worker(epoch_id, batched, on_chain)
        });

        if let ChallengeDecision::Challenge {
            ref reason,
            ref worker,
            proposed,
            public: pub_s,
            policy,
        } = decision
        {
            #[derive(Serialize)]
            struct CounterEvidence<'a> {
                epoch_id: u64,
                reason: &'a str,
                worker: &'a str,
                proposed: u128,
                public: Option<u128>,
                policy: &'a str,
            }
            let policy_s = match policy {
                ChallengePolicy::InflateOnly => "inflate_only",
                ChallengePolicy::StrictEquality => "strict_equality",
            };
            let doc = CounterEvidence {
                epoch_id,
                reason,
                worker,
                proposed,
                public: pub_s,
                policy: policy_s,
            };
            let path = write_evidence_json(
                &self.evidence_dir,
                &format!("challenge_{epoch_id}.json"),
                &doc,
            )
            .map_err(ChallengerError::Evidence)?;
            let bytes =
                std::fs::read(&path).map_err(|e| ChallengerError::Evidence(e.to_string()))?;
            let counter_ref = evidence_ref_keccak(&bytes);
            self.chain
                .challenge_batch(epoch_id, counter_ref, self.bond_wei)?;
        }
        let _ = baseline_flag; // built for future diagnostics
        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::MockChain;
    use crate::fah::{FixtureHttp, default_fixtures_dir};
    use crate::proposer::{enrollment_epoch_id, is_enrollment_epoch};
    use crate::registry::WorkerEntry;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn inflate_only_ok_when_le() {
        let proposed = vec![("0xA1".into(), 100u128), ("0xB2".into(), 50)];
        let public = vec![("0xA1".into(), 100u128), ("0xB2".into(), 60)];
        assert_eq!(
            evaluate_batch(&proposed, &public, ChallengePolicy::InflateOnly),
            ChallengeDecision::Ok
        );
    }

    #[test]
    fn inflate_only_ok_when_under_report() {
        // Daily post-baseline: under-report is worker loss, not slash.
        let proposed = vec![("0xA1".into(), 90u128)];
        let public = vec![("0xA1".into(), 100u128)];
        assert_eq!(
            evaluate_batch(&proposed, &public, ChallengePolicy::InflateOnly),
            ChallengeDecision::Ok
        );
    }

    #[test]
    fn inflate_only_challenge_when_greater() {
        let proposed = vec![("0xA1".into(), 200u128)];
        let public = vec![("0xA1".into(), 100u128)];
        match evaluate_batch(&proposed, &public, ChallengePolicy::InflateOnly) {
            ChallengeDecision::Challenge {
                proposed,
                public,
                policy,
                ..
            } => {
                assert_eq!(proposed, 200);
                assert_eq!(public, Some(100));
                assert_eq!(policy, ChallengePolicy::InflateOnly);
            }
            ChallengeDecision::Ok => panic!("expected Challenge"),
        }
    }

    #[test]
    fn strict_challenges_under_report_baseline_theft() {
        // Consultant exploit: true 100_000_000, proposed 0 → must slash.
        let proposed = vec![("0xA1".into(), 0u128)];
        let public = vec![("0xA1".into(), 100_000_000u128)];
        match evaluate_batch(&proposed, &public, ChallengePolicy::StrictEquality) {
            ChallengeDecision::Challenge {
                proposed,
                public,
                policy,
                ..
            } => {
                assert_eq!(proposed, 0);
                assert_eq!(public, Some(100_000_000));
                assert_eq!(policy, ChallengePolicy::StrictEquality);
            }
            ChallengeDecision::Ok => panic!("under-report baseline MUST be challenged"),
        }
    }

    #[test]
    fn strict_ok_when_exact_match() {
        let proposed = vec![("0xA1".into(), 100_000_000u128)];
        let public = vec![("0xA1".into(), 100_000_000u128)];
        assert_eq!(
            evaluate_batch(&proposed, &public, ChallengePolicy::StrictEquality),
            ChallengeDecision::Ok
        );
    }

    #[test]
    fn strict_challenges_missing_public() {
        let proposed = vec![("0xA1".into(), 0u128)];
        let public: Vec<(String, u128)> = vec![];
        assert!(matches!(
            evaluate_batch(&proposed, &public, ChallengePolicy::StrictEquality),
            ChallengeDecision::Challenge { public: None, .. }
        ));
    }

    #[test]
    fn enrollment_epoch_forces_strict_policy() {
        let eid = enrollment_epoch_id(1_700_000_000);
        assert!(is_enrollment_epoch(eid));
        assert_eq!(
            policy_for_worker(eid, true, Some(true)),
            ChallengePolicy::StrictEquality
        );
        // Daily + already baselined → inflate only
        assert_eq!(
            policy_for_worker(20260714, true, Some(true)),
            ChallengePolicy::InflateOnly
        );
        // Daily + not yet baseline-batched → strict
        assert_eq!(
            policy_for_worker(20260714, false, None),
            ChallengePolicy::StrictEquality
        );
        // Daily + registry says batched but chain says no baseline yet → strict
        assert_eq!(
            policy_for_worker(20260714, true, Some(false)),
            ChallengePolicy::StrictEquality
        );
    }

    #[test]
    fn review_epoch_challenges_enrollment_under_report() {
        let dir = tempdir().unwrap();
        let chain = MockChain::new();
        let bond = 1_000_000_000_000_000_000;
        let epoch = enrollment_epoch_id(1_720_000_000);
        chain
            .propose_batch(epoch, [9u8; 32], [8u8; 32], bond)
            .unwrap();

        let http = FixtureHttp::new(default_fixtures_dir());
        let fah = FahClient::new(http, "https://api.foldingathome.org", Duration::from_millis(0));
        let mut reg = WorkerRegistry::new();
        reg.upsert(WorkerEntry {
            wallet: "0x00000000000000000000000000000000000000A1".into(),
            username: "GOAT-alice".into(),
            baseline_batched: false,
            fah_id: None,
            enrollment_epoch: None,
        });

        let c = Challenger {
            chain: &chain,
            fah: &fah,
            bond_wei: bond,
            evidence_dir: dir.path().to_path_buf(),
        };
        // Public alice score is 51022340; malicious enrollment proposes 0.
        let proposed = vec![(
            "0x00000000000000000000000000000000000000A1".into(),
            0u128,
        )];
        let d = c.review_epoch(epoch, &reg, &proposed).unwrap();
        assert!(
            matches!(
                d,
                ChallengeDecision::Challenge {
                    policy: ChallengePolicy::StrictEquality,
                    ..
                }
            ),
            "got {d:?}"
        );
        let ops = chain.ops();
        assert!(ops.iter().any(|o| matches!(
            o,
            crate::chain::MockOp::Challenge { epoch: e, .. } if *e == epoch
        )));
    }

    #[test]
    fn review_epoch_challenges_inflated() {
        let dir = tempdir().unwrap();
        let chain = MockChain::new();
        let bond = 1_000_000_000_000_000_000;
        chain
            .propose_batch(20260714, [9u8; 32], [8u8; 32], bond)
            .unwrap();

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
        // Mark on-chain baseline so daily under-report would be inflate-only.
        chain.set_has_baseline("0x00000000000000000000000000000000000000A1", true);

        let c = Challenger {
            chain: &chain,
            fah: &fah,
            bond_wei: bond,
            evidence_dir: dir.path().to_path_buf(),
        };
        let proposed = vec![(
            "0x00000000000000000000000000000000000000A1".into(),
            99_999_999u128,
        )];
        let d = c.review_epoch(20260714, &reg, &proposed).unwrap();
        assert!(matches!(d, ChallengeDecision::Challenge { .. }));
    }
}
