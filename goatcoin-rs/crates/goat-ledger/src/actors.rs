//! MVP-1 actors (WP-1.4): Orchestrator and Challenger. They communicate ONLY through the
//! Ledger (no shared memory), demonstrating role separation and public verifiability. The
//! Challenger recomputes independently from published data; the Ledger adjudicates
//! independently again — neither trusts the other.

use goat_protocol::maturity::{
    anomaly_burst, evaluate_transition, fold_receipts, gate, ClassState, FraudProof,
    GateThresholds, Stage, WindowPosting,
};

use crate::ledger::ReceiptsManifest;

/// The ways an orchestrator's posting can deviate from the legal transition.
#[derive(Clone, Copy, Debug)]
pub enum PostingScenario {
    /// honest posting
    None,
    /// posted root does not match the published receipts
    RootMismatch,
    /// claim a lower sampling rate than the gate justifies
    Undersample,
    /// claim a more-advanced stage than legal
    OverAdvance,
    /// misstate the prior state
    BadPrior,
    /// conservative: HIGHER sampling than legal (must NOT be judged fraud)
    Conservative,
    /// withhold the recomputable burst snap (R-MAT2): claim the non-burst transition even
    /// though the published receipts contain an anomaly burst
    WithheldBurstSnap,
}

pub struct Orchestrator {
    pub name: String,
}

impl Orchestrator {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }

    /// Build a window posting from the (honest) prior and published receipts, applying the
    /// requested posting scenario. Returns the posting to submit to the ledger.
    pub fn make_posting(
        &self,
        prior: ClassState,
        manifest: &ReceiptsManifest,
        th: &GateThresholds,
        scenario: PostingScenario,
    ) -> WindowPosting {
        let receipts = manifest.generate();
        let folded = fold_receipts(&receipts, &[]);
        let acc = folded
            .get(&(manifest.class_id.clone(), manifest.window))
            .expect("non-empty window");
        let honest_root = acc.root();
        let (gate_ok, _) = gate(acc, th);
        // R-MAT2: the honest orchestrator recomputes the burst from its own receipts.
        let burst = anomaly_burst(acc);
        let (legal_stage, legal_p, _) =
            evaluate_transition(prior.stage, prior.p_class, gate_ok, burst);

        let mut p = WindowPosting {
            class_id: manifest.class_id.clone(),
            window: manifest.window,
            accumulator_root: honest_root,
            claimed_from_stage: prior.stage,
            claimed_from_p: prior.p_class,
            claimed_to_stage: legal_stage,
            claimed_to_p: legal_p,
        };
        match scenario {
            PostingScenario::None => {}
            PostingScenario::RootMismatch => p.accumulator_root = vec![0u8; 32],
            PostingScenario::Undersample => p.claimed_to_p = (legal_p - 0.1).max(0.0), // below legal
            PostingScenario::OverAdvance => {
                p.claimed_to_stage = Stage::Mature; // rank above legal (keep p == legal)
                p.claimed_to_p = legal_p;
            }
            PostingScenario::BadPrior => p.claimed_from_p = prior.p_class + 0.1,
            PostingScenario::Conservative => {
                // hold at higher sampling than legal (safe): keep from-stage/p
                p.claimed_to_stage = prior.stage;
                p.claimed_to_p = prior.p_class.max(legal_p);
            }
            PostingScenario::WithheldBurstSnap => {
                // claim the transition that WOULD be legal without the burst — only illegal
                // (and detectable) when the receipts actually contain one
                let (nb_stage, nb_p, _) =
                    evaluate_transition(prior.stage, prior.p_class, gate_ok, false);
                p.claimed_to_stage = nb_stage;
                p.claimed_to_p = nb_p;
            }
        }
        p
    }
}

pub struct Challenger {
    pub th: GateThresholds,
}

impl Challenger {
    pub fn new(th: GateThresholds) -> Self {
        Self { th }
    }

    /// Independently recompute from published receipts + the ledger's accepted prior. Returns
    /// a candidate fraud proof if the posting is illegal (this is the public-verifiability
    /// step — anyone can run it).
    pub fn recompute(
        &self,
        posting: &WindowPosting,
        manifest: &ReceiptsManifest,
        prior: &ClassState,
    ) -> Option<FraudProof> {
        let receipts = manifest.generate();
        goat_protocol::maturity::verify_posting(posting, &receipts, prior, &self.th, &[])
    }
}

/// Convenience: an honest Stage-1 initial state (PROBATION / 1.0).
pub fn probation_state(slash_mult: f64) -> ClassState {
    ClassState {
        stage: Stage::Probation,
        p_class: 1.0,
        last_transition_window: 0,
        slash_mult,
        pioneer_armed: true,
    }
}
