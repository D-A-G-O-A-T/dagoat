//! GoatCoin (GOAT) MVP-1 — minimal mechanism ledger + fraud-proof loop (device-agnostic).
//!
//! The only on-chain surface of the testnet MVP: beacon, accumulator roots + claimed
//! transitions, orchestrator bonds, and slashing. Everything token/reward-related is out of
//! scope. Public verifiability (SC5) is proven by the fraud-proof adjudication: a challenger
//! recomputes from published receipts and the ledger independently re-adjudicates.

pub mod actors;
pub mod beacon;
pub mod ledger;

#[cfg(test)]
mod harness {
    //! WP-1.4 non-compliant-orchestrator harness — proves SC5 locally through the three roles
    //! (orchestrator, ledger, challenger) communicating only via the ledger.

    use crate::actors::{probation_state, Challenger, Orchestrator, PostingScenario};
    use crate::ledger::{Ledger, ReceiptsManifest, Resolution};
    use goat_protocol::maturity::{GateThresholds, Stage};

    fn th() -> GateThresholds {
        GateThresholds {
            v_min: 100,
            epsilon: 0.01,
            phi: 50.0,
            x_clusters: 25,
            x_asns: 10,
        }
    }
    fn good_manifest(class_id: &str, window: u64) -> ReceiptsManifest {
        ReceiptsManifest {
            class_id: class_id.into(),
            window,
            n: 200,
            clusters: 30,
            asns: 12,
            diverged: 0,
            fault: 0,
            concentrated: false,
        }
    }

    /// Receipts holding an R-MAT2 anomaly burst: 8 divergences concentrated in ONE
    /// sub-window, but a window-wide divergence rate (8/2000 = 0.004) below epsilon (0.01)
    /// — the gate holds, so ONLY the recomputable burst mandates the snap.
    fn bursty_manifest(class_id: &str, window: u64) -> ReceiptsManifest {
        ReceiptsManifest {
            class_id: class_id.into(),
            window,
            n: 2000,
            clusters: 30,
            asns: 12,
            diverged: 8,
            fault: 0,
            concentrated: true,
        }
    }

    /// Drive one window: orchestrator posts (with `scenario`), challenger recomputes and (if it
    /// finds fraud) challenges, ledger independently adjudicates. Returns (challenger_found,
    /// ledger_slashed, orch_bond_slashed).
    fn run_window(scenario: PostingScenario, prior_from_relax: bool) -> (bool, bool, bool) {
        let mut led = Ledger::new(th());
        led.register_bond("orch", 1000);
        // For undersample/over-advance we want a RELAX prior (so there is a legal step to lie
        // about); for the rest, PROBATION is fine.
        let prior = if prior_from_relax {
            goat_protocol::maturity::ClassState {
                stage: Stage::Relax,
                p_class: 0.5,
                last_transition_window: 0,
                slash_mult: 15.0,
                pioneer_armed: true,
            }
        } else {
            probation_state(15.0)
        };
        led.seed_state("cls.new.v1", prior);

        let orch = Orchestrator::new("orch");
        let manifest = good_manifest("cls.new.v1", 1);
        let posting = orch.make_posting(prior, &manifest, &th(), scenario);
        let id = led.post("orch", posting.clone(), manifest.clone()).unwrap();

        // Challenger recomputes independently from published data + ledger's prior.
        let challenger = Challenger::new(th());
        let led_prior = led.prior_state("cls.new.v1").unwrap();
        let challenger_found = challenger
            .recompute(&posting, &manifest, &led_prior)
            .is_some();

        // Regardless of the challenger's opinion, the LEDGER adjudicates independently.
        let slashed_proof = led.challenge(id).unwrap();
        let ledger_slashed = slashed_proof.is_some();
        let bond_slashed = led.bond("orch").unwrap().slashed;
        (challenger_found, ledger_slashed, bond_slashed)
    }

    #[test]
    fn honest_posting_is_not_fraud() {
        let (found, slashed, bond) = run_window(PostingScenario::None, false);
        assert!(!found && !slashed && !bond);
    }

    #[test]
    fn root_mismatch_is_caught_and_slashed() {
        let (found, slashed, bond) = run_window(PostingScenario::RootMismatch, false);
        assert!(found && slashed && bond);
    }

    #[test]
    fn undersampling_is_caught_and_slashed() {
        let (found, slashed, bond) = run_window(PostingScenario::Undersample, true);
        assert!(found && slashed && bond);
    }

    #[test]
    fn over_advance_is_caught_and_slashed() {
        let (found, slashed, bond) = run_window(PostingScenario::OverAdvance, true);
        assert!(found && slashed && bond);
    }

    #[test]
    fn bad_prior_is_caught_and_slashed() {
        let (found, slashed, bond) = run_window(PostingScenario::BadPrior, false);
        assert!(found && slashed && bond);
    }

    #[test]
    fn conservative_orchestrator_is_never_slashed() {
        // higher sampling than legal is safe -> challenger finds nothing, ledger does not slash
        let (found, slashed, bond) = run_window(PostingScenario::Conservative, true);
        assert!(!found && !slashed && !bond);
    }

    fn relax_prior(p: f64) -> goat_protocol::maturity::ClassState {
        goat_protocol::maturity::ClassState {
            stage: Stage::Relax,
            p_class: p,
            last_transition_window: 0,
            slash_mult: 15.0,
            pioneer_armed: true,
        }
    }

    #[test]
    fn withheld_burst_snap_is_caught_and_slashed() {
        // R-MAT2: the receipts contain a recomputable anomaly burst; the posting claims the
        // non-burst transition. Challenger and ledger each recompute the burst independently.
        let mut led = Ledger::new(th());
        led.register_bond("orch", 1000);
        let prior = relax_prior(0.25);
        led.seed_state("cls.new.v1", prior);
        let orch = Orchestrator::new("orch");
        let manifest = bursty_manifest("cls.new.v1", 1);
        let posting =
            orch.make_posting(prior, &manifest, &th(), PostingScenario::WithheldBurstSnap);
        let id = led.post("orch", posting.clone(), manifest.clone()).unwrap();

        let challenger = Challenger::new(th());
        let found = challenger
            .recompute(&posting, &manifest, &led.prior_state("cls.new.v1").unwrap())
            .expect("challenger detects the withheld snap");
        assert_eq!(found.reason, "withheld_burst_snap");

        let proof = led.challenge(id).unwrap().expect("ledger agrees");
        assert_eq!(proof.reason, "withheld_burst_snap");
        assert!(led.bond("orch").unwrap().slashed);
    }

    #[test]
    fn honest_burst_snap_posting_finalizes() {
        // Same bursty receipts, honest orchestrator: it recomputes the burst itself and posts
        // the snap (0.25 -> 0.5), which no recomputer can flag.
        let mut led = Ledger::new(th());
        led.register_bond("orch", 1000);
        let prior = relax_prior(0.25);
        led.seed_state("cls.new.v1", prior);
        let orch = Orchestrator::new("orch");
        let manifest = bursty_manifest("cls.new.v1", 1);
        let posting = orch.make_posting(prior, &manifest, &th(), PostingScenario::None);
        assert!((posting.claimed_to_p - 0.5).abs() < 1e-9); // the snap is in the honest claim
        let id = led.post("orch", posting, manifest).unwrap();
        assert!(led.challenge(id).unwrap().is_none()); // not fraud
        led.finalize(id).unwrap();
        let st = led.prior_state("cls.new.v1").unwrap();
        assert!((st.p_class - 0.5).abs() < 1e-9);
    }

    #[test]
    fn challenger_and_ledger_agree_independently() {
        // The two independent recomputations must reach the same verdict for every case.
        for (scenario, relax) in [
            (PostingScenario::None, false),
            (PostingScenario::RootMismatch, false),
            (PostingScenario::Undersample, true),
            (PostingScenario::OverAdvance, true),
            (PostingScenario::BadPrior, false),
            (PostingScenario::Conservative, true),
            // no burst in good receipts -> withholding is indistinguishable from honest
            (PostingScenario::WithheldBurstSnap, true),
        ] {
            let (found, slashed, _) = run_window(scenario, relax);
            assert_eq!(
                found, slashed,
                "challenger/ledger disagree for {scenario:?}"
            );
        }
    }

    #[test]
    fn clean_posting_finalizes_and_advances_state() {
        let mut led = Ledger::new(th());
        led.register_bond("orch", 1000);
        led.seed_state("cls.new.v1", probation_state(15.0));
        let orch = Orchestrator::new("orch");
        let manifest = good_manifest("cls.new.v1", 1);
        let prior = led.prior_state("cls.new.v1").unwrap();
        let posting = orch.make_posting(prior, &manifest, &th(), PostingScenario::None);
        let id = led.post("orch", posting, manifest).unwrap();
        assert!(led.challenge(id).unwrap().is_none()); // no fraud
        led.finalize(id).unwrap();
        assert_eq!(led.posting(id).unwrap().resolution, Resolution::Finalized);
        // PROBATION + good window -> RELAX 0.5 accepted
        let st = led.prior_state("cls.new.v1").unwrap();
        assert_eq!(st.stage, Stage::Relax);
        assert!((st.p_class - 0.5).abs() < 1e-9);
    }
}
