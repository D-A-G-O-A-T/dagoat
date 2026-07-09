//! Minimal mechanism ledger (WP-1.1) + fraud-proof adjudication (WP-1.3).
//!
//! Stores exactly what the Phase-3 mechanisms need on-chain: accumulator roots + claimed
//! maturity transitions (window postings), orchestrator bonds, and slash actions. No token,
//! no rewards, no balances. Permissioned/simulated is acceptable for the testnet MVP.
//!
//! Receipts are published off-chain and referenced by a deterministic manifest; anyone can
//! regenerate them and recompute. The ledger adjudicates a challenge by INDEPENDENTLY
//! re-running `verify_posting` — it never trusts the challenger's claim. Two independent
//! recomputations agreeing (challenger + ledger) is the trustless-by-recomputation property.
//!
//! Device-agnostic: class_id is an opaque string; nothing here names a device type.

use std::collections::HashMap;

use goat_protocol::maturity::{
    verify_posting, ClassState, FraudProof, GateThresholds, Receipt, WindowPosting, SUB_WINDOWS,
};

use crate::beacon::{
    assess_delay, BeaconError, BeaconMode, DelayAssessment, EpochBeacon, NonRevealerPolicy,
    SealedBeacon,
};

/// Deterministic manifest for a window's published receipts. Regenerating from the manifest
/// yields byte-identical receipts on any node (mirrors content-addressed publication).
#[derive(Clone, Debug)]
pub struct ReceiptsManifest {
    pub class_id: String,
    pub window: u64,
    pub n: u32,
    pub clusters: u32,
    pub asns: u32,
    pub diverged: u32,
    pub fault: u32,
    /// When true, all anomalous receipts share one sub-window (a concentration in time —
    /// the R-MAT2 burst shape); otherwise receipts spread across sub-windows.
    pub concentrated: bool,
}

impl ReceiptsManifest {
    pub fn generate(&self) -> Vec<Receipt> {
        (0..self.n)
            .map(|i| {
                let anomalous = i < self.diverged || i < self.fault;
                Receipt {
                    class_id: self.class_id.clone(),
                    task_class_id: 10,
                    window: self.window,
                    sub_window: if self.concentrated && anomalous {
                        0
                    } else {
                        i % SUB_WINDOWS
                    },
                    cluster_id: format!("c{}", i % self.clusters),
                    asn: format!("a{}", i % self.asns),
                    diverged: i < self.diverged,
                    fault: i < self.fault,
                }
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct Bond {
    pub orchestrator: String,
    pub amount: u64,
    pub slashed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    Pending,
    Finalized,
    Slashed(FraudProof),
}

pub struct PostingEntry {
    pub id: usize,
    pub orchestrator: String,
    pub posting: WindowPosting,
    pub manifest: ReceiptsManifest,
    pub resolution: Resolution,
}

#[derive(Clone, Debug)]
pub struct SlashEvent {
    pub orchestrator: String,
    pub posting_id: usize,
    pub reason: &'static str,
    pub burned: u64,
    pub to_challenger: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LedgerError {
    NoBond,
    UnknownPosting,
    AlreadyResolved,
}

pub struct Ledger {
    th: GateThresholds,
    beacon_mode: BeaconMode,
    non_revealer_policy: NonRevealerPolicy,
    anchored_beacons: HashMap<u64, SealedBeacon>,
    bonds: HashMap<String, Bond>,
    accepted_state: HashMap<String, ClassState>,
    postings: Vec<PostingEntry>,
    pub slash_events: Vec<SlashEvent>,
}

impl Ledger {
    /// Default ledger: plain commit-reveal beacon with the strict non-revealer policy — the
    /// permissioned-testnet posture (H2). Use `with_beacon_mode` for the delay-sealed path.
    pub fn new(th: GateThresholds) -> Self {
        Self::with_beacon_mode(th, BeaconMode::CommitReveal, NonRevealerPolicy::Strict)
    }

    /// Ledger with an explicit beacon finalization strategy (H2). `DelaySealed` targets
    /// public/adversarial settings (last-revealer-bias-resistant); `CommitReveal` is the
    /// permissioned-testnet default. The policy governs missing reveals at finalization.
    pub fn with_beacon_mode(
        th: GateThresholds,
        beacon_mode: BeaconMode,
        non_revealer_policy: NonRevealerPolicy,
    ) -> Self {
        Self {
            th,
            beacon_mode,
            non_revealer_policy,
            anchored_beacons: HashMap::new(),
            bonds: HashMap::new(),
            accepted_state: HashMap::new(),
            postings: Vec::new(),
            slash_events: Vec::new(),
        }
    }

    pub fn beacon_mode(&self) -> BeaconMode {
        self.beacon_mode
    }

    /// Reconfigure the beacon strategy (e.g. switch a public deployment to `DelaySealed`).
    pub fn set_beacon_mode(&mut self, mode: BeaconMode, policy: NonRevealerPolicy) {
        self.beacon_mode = mode;
        self.non_revealer_policy = policy;
    }

    /// Advisory calibration check (H2): assess the configured delay against the epoch's reveal
    /// window. Returns `None` for non-delayed modes. Uses the PLACEHOLDER-VDF throughput anchor;
    /// re-calibrate against the real VDF when it lands. The ledger never panics on a weak delay —
    /// the caller decides (a deployment script should refuse `TooShort` for public settings).
    pub fn assess_beacon_delay(&self, reveal_window_secs: f64) -> Option<DelayAssessment> {
        match self.beacon_mode {
            BeaconMode::DelaySealed { delay_iterations } => Some(assess_delay(
                delay_iterations,
                crate::beacon::PLACEHOLDER_VDF_HASHES_PER_SEC,
                reveal_window_secs,
            )),
            _ => None,
        }
    }

    /// Finalize an epoch beacon under the ledger's configured mode and ANCHOR the sealed result
    /// (the ledger is the only on-chain randomness surface — R-CAP3). Returns the `SealedBeacon`;
    /// consumers read the plain value via `beacon_value`. Under `CommitReveal` the anchored value
    /// equals the plain commit-reveal output (backward compatible); under `DelaySealed` it is the
    /// delay-function output, unknowable within the reveal window (removing last-revealer bias).
    pub fn anchor_beacon(&mut self, beacon: &mut EpochBeacon) -> Result<SealedBeacon, BeaconError> {
        let sealed = beacon.finalize_for(self.beacon_mode, self.non_revealer_policy)?;
        self.anchored_beacons.insert(beacon.epoch, sealed.clone());
        Ok(sealed)
    }

    /// The anchored beacon value for an epoch, in the `[u8; 32]` shape every consumer already uses
    /// (lottery seed, capability nonce). Identical call shape whether the beacon was plain or
    /// delay-sealed — consumers need no change.
    pub fn beacon_value(&self, epoch: u64) -> Option<[u8; 32]> {
        self.anchored_beacons.get(&epoch).map(|s| s.value)
    }

    /// The full anchored `SealedBeacon` for an epoch (value + re-verifiable delay proof +
    /// recorded non-revealers), for a recomputer that wants to verify the seal.
    pub fn sealed_beacon(&self, epoch: u64) -> Option<&SealedBeacon> {
        self.anchored_beacons.get(&epoch)
    }

    pub fn register_bond(&mut self, orchestrator: &str, amount: u64) {
        self.bonds.insert(
            orchestrator.to_string(),
            Bond {
                orchestrator: orchestrator.to_string(),
                amount,
                slashed: false,
            },
        );
    }

    /// Seed a class's accepted state after Stage-1 registration (e.g. PROBATION / 1.0).
    pub fn seed_state(&mut self, class_id: &str, state: ClassState) {
        self.accepted_state.insert(class_id.to_string(), state);
    }

    /// Public read: the accepted prior state a posting's transition must chain from.
    pub fn prior_state(&self, class_id: &str) -> Option<ClassState> {
        self.accepted_state.get(class_id).copied()
    }

    pub fn bond(&self, orchestrator: &str) -> Option<&Bond> {
        self.bonds.get(orchestrator)
    }

    pub fn posting(&self, id: usize) -> Option<&PostingEntry> {
        self.postings.get(id)
    }

    /// Record a pending posting (root + claimed transition + receipts manifest).
    pub fn post(
        &mut self,
        orchestrator: &str,
        posting: WindowPosting,
        manifest: ReceiptsManifest,
    ) -> Result<usize, LedgerError> {
        if !self.bonds.contains_key(orchestrator) {
            return Err(LedgerError::NoBond);
        }
        let id = self.postings.len();
        self.postings.push(PostingEntry {
            id,
            orchestrator: orchestrator.to_string(),
            posting,
            manifest,
            resolution: Resolution::Pending,
        });
        Ok(id)
    }

    /// Adjudicate a challenge: the ledger INDEPENDENTLY recomputes (never trusts the
    /// challenger). On proven fraud, slash the bond and void the posting. Returns the proof
    /// if fraud was found, else None (challenge rejected — the posting stands).
    pub fn challenge(&mut self, id: usize) -> Result<Option<FraudProof>, LedgerError> {
        let entry = self.postings.get(id).ok_or(LedgerError::UnknownPosting)?;
        if entry.resolution != Resolution::Pending {
            return Err(LedgerError::AlreadyResolved);
        }
        let receipts = entry.manifest.generate();
        let prior = self
            .accepted_state
            .get(&entry.posting.class_id)
            .copied()
            .unwrap_or(ClassState {
                stage: goat_protocol::maturity::Stage::Candidate,
                p_class: 1.0,
                last_transition_window: -1,
                slash_mult: 15.0,
                pioneer_armed: false,
            });
        let proof = verify_posting(&entry.posting, &receipts, &prior, &self.th, &[]);
        match proof {
            Some(fp) => {
                let orch = entry.orchestrator.clone();
                let amount = self.bonds.get(&orch).map(|b| b.amount).unwrap_or(0);
                if let Some(b) = self.bonds.get_mut(&orch) {
                    b.slashed = true;
                }
                let burned = amount / 2;
                self.slash_events.push(SlashEvent {
                    orchestrator: orch,
                    posting_id: id,
                    reason: fp.reason,
                    burned,
                    to_challenger: amount - burned,
                });
                self.postings[id].resolution = Resolution::Slashed(fp.clone());
                Ok(Some(fp))
            }
            None => Ok(None),
        }
    }

    /// Finalize an unchallenged/clean posting: accept it and advance the class's state.
    pub fn finalize(&mut self, id: usize) -> Result<(), LedgerError> {
        let entry = self.postings.get(id).ok_or(LedgerError::UnknownPosting)?;
        if entry.resolution != Resolution::Pending {
            return Err(LedgerError::AlreadyResolved);
        }
        let class = entry.posting.class_id.clone();
        let (to_stage, to_p) = (entry.posting.claimed_to_stage, entry.posting.claimed_to_p);
        let prev = self.accepted_state.get(&class).copied();
        self.accepted_state.insert(
            class,
            ClassState {
                stage: to_stage,
                p_class: to_p,
                last_transition_window: entry.posting.window as i64,
                slash_mult: prev.map(|s| s.slash_mult).unwrap_or(15.0),
                pioneer_armed: prev.map(|s| s.pioneer_armed).unwrap_or(false),
            },
        );
        self.postings[id].resolution = Resolution::Finalized;
        Ok(())
    }
}

#[cfg(test)]
mod beacon_integration_tests {
    use super::*;
    use crate::beacon::{commitment, delay_verify, EpochBeacon};
    use goat_protocol::maturity::Stage;

    fn th() -> GateThresholds {
        GateThresholds {
            v_min: 100,
            epsilon: 0.01,
            phi: 50.0,
            x_clusters: 25,
            x_asns: 10,
        }
    }

    // Build a committed-and-revealed beacon for `epoch`; `withhold` names a committer that does
    // NOT reveal (to exercise the non-revealer policies).
    fn revealed_beacon(
        epoch: u64,
        reveals: &[(&str, &[u8], &[u8])],
        withhold: &[&str],
    ) -> EpochBeacon {
        let mut b = EpochBeacon::new(epoch);
        for (p, r, s) in reveals {
            b.commit(p, commitment(r, s)).unwrap();
        }
        b.close_commit().unwrap();
        for (p, r, s) in reveals {
            if !withhold.contains(p) {
                b.reveal(p, r, s).unwrap();
            }
        }
        b
    }

    #[test]
    fn commit_reveal_anchor_matches_plain_finalize() {
        // a CommitReveal-mode ledger anchors exactly the plain commit-reveal value (back-compat)
        let reveals: &[(&str, &[u8], &[u8])] = &[("a", b"ra", b"sa"), ("b", b"rb", b"sb")];
        let plain = revealed_beacon(1, reveals, &[]).finalize().unwrap();

        let mut led = Ledger::new(th()); // default = CommitReveal / Strict
        let mut beacon = revealed_beacon(1, reveals, &[]);
        let sealed = led.anchor_beacon(&mut beacon).unwrap();
        assert_eq!(sealed.value, plain);
        assert_eq!(led.beacon_value(1), Some(plain));
        assert!(sealed.non_revealers.is_empty());
    }

    #[test]
    fn delay_sealed_anchor_produces_verifiable_sealed_beacon() {
        let reveals: &[(&str, &[u8], &[u8])] = &[("a", b"ra", b"sa"), ("b", b"rb", b"sb")];
        let plain = revealed_beacon(7, reveals, &[]).finalize().unwrap();

        let mut led = Ledger::with_beacon_mode(
            th(),
            BeaconMode::DelaySealed {
                delay_iterations: 256,
            },
            NonRevealerPolicy::Strict,
        );
        let mut beacon = revealed_beacon(7, reveals, &[]);
        let sealed = led.anchor_beacon(&mut beacon).unwrap();

        // the anchored value is the delay-function output, re-verifiable, and != the plain seed
        assert_eq!(sealed.value, sealed.proof.output);
        assert!(delay_verify(&sealed.proof));
        assert_ne!(sealed.value, plain);
        // consumers read the value in the same [u8;32] shape regardless of mode
        assert_eq!(led.beacon_value(7), Some(sealed.value));
        assert_eq!(led.sealed_beacon(7).unwrap().value, sealed.value);
    }

    #[test]
    fn delay_sealed_subset_policy_keeps_liveness_and_records_non_revealers() {
        // one committer withholds; SubsetWithSlashing still finalizes (liveness) and records it —
        // safe under DelaySealed because the withholder cannot predict the delayed value.
        let reveals: &[(&str, &[u8], &[u8])] = &[("a", b"ra", b"sa"), ("b", b"rb", b"sb")];
        let mut led = Ledger::with_beacon_mode(
            th(),
            BeaconMode::DelaySealed {
                delay_iterations: 256,
            },
            NonRevealerPolicy::SubsetWithSlashing,
        );
        let mut beacon = revealed_beacon(3, reveals, &["b"]); // "b" withholds
        let sealed = led.anchor_beacon(&mut beacon).unwrap();
        assert!(delay_verify(&sealed.proof));
        assert_eq!(sealed.non_revealers, vec!["b".to_string()]);
        assert!(led.beacon_value(3).is_some());
    }

    #[test]
    fn strict_missing_reveal_fails_anchoring() {
        let reveals: &[(&str, &[u8], &[u8])] = &[("a", b"ra", b"sa"), ("b", b"rb", b"sb")];
        let mut led = Ledger::new(th()); // CommitReveal / Strict
        let mut beacon = revealed_beacon(9, reveals, &["b"]); // "b" withholds
        assert_eq!(
            led.anchor_beacon(&mut beacon),
            Err(BeaconError::MissingReveals)
        );
        assert_eq!(led.beacon_value(9), None); // nothing anchored on failure
    }

    #[test]
    fn anchored_beacon_value_seeds_a_consumer() {
        // the anchored value is usable as a &[u8] seed exactly like the previous plain beacon —
        // here a stand-in consumer (hash the seed) to show the call shape is unchanged.
        let reveals: &[(&str, &[u8], &[u8])] = &[("a", b"ra", b"sa"), ("b", b"rb", b"sb")];
        let mut led = Ledger::with_beacon_mode(
            th(),
            BeaconMode::DelaySealed {
                delay_iterations: 128,
            },
            NonRevealerPolicy::Strict,
        );
        let mut beacon = revealed_beacon(2, reveals, &[]);
        led.anchor_beacon(&mut beacon).unwrap();
        let seed: [u8; 32] = led.beacon_value(2).unwrap();
        let seed_bytes: &[u8] = &seed; // consumers take &[u8] (lottery_select, nonce derivation)
        assert_eq!(seed_bytes.len(), 32);
        // sanity: an unrelated class state still round-trips (ledger otherwise unaffected)
        led.seed_state(
            "cls.x",
            ClassState {
                stage: Stage::Probation,
                p_class: 1.0,
                last_transition_window: 0,
                slash_mult: 15.0,
                pioneer_armed: true,
            },
        );
        assert_eq!(led.prior_state("cls.x").unwrap().stage, Stage::Probation);
    }
}
