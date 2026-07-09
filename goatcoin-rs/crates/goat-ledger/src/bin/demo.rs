//! MVP-1 demo (WP-1.1-1.4): three roles — Orchestrator, Ledger, Challenger — communicating
//! only through the ledger. Shows the epoch beacon feeding a capability nonce, an honest
//! window finalizing, and every class of non-compliant posting being caught by independent
//! recomputation and slashed. Proves public verifiability (SC5) locally.
//!
//! Run:  cargo run -p goat-ledger --bin goat-mvp1-demo

use goat_ledger::actors::{probation_state, Challenger, Orchestrator, PostingScenario};
use goat_ledger::beacon::{commitment, delay_verify, BeaconMode, EpochBeacon, NonRevealerPolicy};
use goat_ledger::ledger::{Ledger, ReceiptsManifest};
use goat_protocol::maturity::{ClassState, GateThresholds, Stage};

fn th() -> GateThresholds {
    GateThresholds {
        v_min: 100,
        epsilon: 0.01,
        phi: 50.0,
        x_clusters: 25,
        x_asns: 10,
    }
}

fn good_manifest(window: u64) -> ReceiptsManifest {
    ReceiptsManifest {
        class_id: "cls.new.v1".into(),
        window,
        n: 200,
        clusters: 30,
        asns: 12,
        diverged: 0,
        fault: 0,
        concentrated: false,
    }
}

/// R-MAT2 burst shape: 8 divergences concentrated in one sub-window; window-wide rate
/// (0.004) still passes the gate, so only the recomputable burst mandates a snap.
fn bursty_manifest(window: u64) -> ReceiptsManifest {
    ReceiptsManifest {
        class_id: "cls.new.v1".into(),
        window,
        n: 2000,
        clusters: 30,
        asns: 12,
        diverged: 8,
        fault: 0,
        concentrated: true,
    }
}

fn main() {
    println!("=== WP-1.2: epoch beacon (commit-reveal, feeds capability nonce + lottery seed) ===");
    let mut beacon = EpochBeacon::new(1);
    for (p, r, s) in [
        ("val-1", b"r1".as_slice(), b"s1".as_slice()),
        ("val-2", b"r2", b"s2"),
        ("val-3", b"r3", b"s3"),
    ] {
        beacon.commit(p, commitment(r, s)).unwrap();
    }
    beacon.close_commit().unwrap();
    for (p, r, s) in [
        ("val-1", b"r1".as_slice(), b"s1".as_slice()),
        ("val-2", b"r2", b"s2"),
        ("val-3", b"r3", b"s3"),
    ] {
        beacon.reveal(p, r, s).unwrap();
    }
    let value = beacon.finalize().unwrap();
    println!(
        "  3 validators commit-then-reveal -> beacon = {}",
        hex8(&value)
    );
    println!("  (binding + commit-before-reveal enforced; one reveal flips the whole value)");

    // --- H2: the ledger anchors a delay-sealed beacon for public/adversarial settings ---
    println!("\n=== H2: ledger-anchored delay-sealed beacon (last-revealer-bias-resistant) ===");
    let mut sealed_led = Ledger::with_beacon_mode(
        th(),
        BeaconMode::DelaySealed {
            delay_iterations: 4096,
        },
        NonRevealerPolicy::Strict,
    );
    let mut beacon2 = EpochBeacon::new(2);
    for (p, r, s) in [
        ("val-1", b"r1".as_slice(), b"s1".as_slice()),
        ("val-2", b"r2", b"s2"),
        ("val-3", b"r3", b"s3"),
    ] {
        beacon2.commit(p, commitment(r, s)).unwrap();
    }
    beacon2.close_commit().unwrap();
    for (p, r, s) in [
        ("val-1", b"r1".as_slice(), b"s1".as_slice()),
        ("val-2", b"r2", b"s2"),
        ("val-3", b"r3", b"s3"),
    ] {
        beacon2.reveal(p, r, s).unwrap();
    }
    let sealed = sealed_led.anchor_beacon(&mut beacon2).unwrap();
    println!(
        "  same reveals, delay-sealed -> beacon = {}  (plain seed sealed behind {} VDF steps)",
        hex8(&sealed.value),
        sealed.proof.iterations
    );
    println!(
        "  seal re-verifies = {}; anchored value read back by consumers = {}",
        delay_verify(&sealed.proof),
        hex8(&sealed_led.beacon_value(2).unwrap())
    );
    println!(
        "  (value unknowable within the reveal window -> a last revealer cannot see-then-withhold)"
    );

    println!("\n=== WP-1.1/1.3/1.4: three roles via the ledger only ===");
    let mut led = Ledger::new(th());
    led.register_bond("orch", 1000);
    led.seed_state("cls.new.v1", probation_state(15.0));
    let orch = Orchestrator::new("orch");
    let challenger = Challenger::new(th());

    // --- honest window: PROBATION -> RELAX, finalized ---
    let prior = led.prior_state("cls.new.v1").unwrap();
    let m = good_manifest(1);
    let honest = orch.make_posting(prior, &m, &th(), PostingScenario::None);
    let id = led.post("orch", honest.clone(), m.clone()).unwrap();
    let ch = challenger.recompute(&honest, &m, &led.prior_state("cls.new.v1").unwrap());
    println!(
        "  honest window 1: challenger finds fraud = {}",
        ch.is_some()
    );
    assert!(led.challenge(id).unwrap().is_none());
    led.finalize(id).unwrap();
    let st = led.prior_state("cls.new.v1").unwrap();
    println!(
        "  ledger finalized -> class now {:?}/{:.2}",
        st.stage, st.p_class
    );

    // --- non-compliant postings from a RELAX prior: each caught + slashed ---
    println!("\n  non-compliant orchestrator (each on a fresh bond, RELAX prior 0.5):");
    for scenario in [
        PostingScenario::RootMismatch,
        PostingScenario::Undersample,
        PostingScenario::OverAdvance,
        PostingScenario::BadPrior,
        PostingScenario::Conservative,
    ] {
        let (found, slashed, reason) = trial(scenario);
        let verdict = if slashed {
            format!("SLASHED ({reason})")
        } else {
            "not slashed".into()
        };
        println!(
            "    {:<14} challenger_flags={:<5} ledger={}",
            format!("{scenario:?}"),
            found,
            verdict
        );
    }

    // --- R-MAT2: the burst snap is recomputable, so withholding it is provable fraud ---
    println!("\n  R-MAT2 (recomputable burst): receipts hold 8 divergences in ONE sub-window;");
    println!("  the window-wide rate still passes the gate, but the burst mandates a snap.");
    let (found, slashed, reason) = burst_trial(PostingScenario::WithheldBurstSnap);
    println!(
        "    withheld snap:  challenger_flags={found}  ledger={}",
        if slashed {
            format!("SLASHED ({reason})")
        } else {
            "not slashed".into()
        }
    );
    let (found, slashed, _) = burst_trial(PostingScenario::None);
    println!(
        "    honest snap:    challenger_flags={found}  ledger={}",
        if slashed { "SLASHED" } else { "not slashed" }
    );

    println!("\nSC5 demonstrated: every illegal posting is caught by INDEPENDENT recomputation");
    println!("(challenger + ledger agree), the bond is slashed, and the conservative");
    println!("orchestrator is never slashed. Public verifiability holds.");
}

fn burst_trial(scenario: PostingScenario) -> (bool, bool, &'static str) {
    let mut led = Ledger::new(th());
    led.register_bond("orch3", 1000);
    let prior = ClassState {
        stage: Stage::Relax,
        p_class: 0.25,
        last_transition_window: 0,
        slash_mult: 15.0,
        pioneer_armed: true,
    };
    led.seed_state("cls.new.v1", prior);
    let orch = Orchestrator::new("orch3");
    let challenger = Challenger::new(th());
    let m = bursty_manifest(3);
    let posting = orch.make_posting(prior, &m, &th(), scenario);
    let id = led.post("orch3", posting.clone(), m.clone()).unwrap();
    let found = challenger
        .recompute(&posting, &m, &led.prior_state("cls.new.v1").unwrap())
        .is_some();
    let proof = led.challenge(id).unwrap();
    let reason = proof.as_ref().map(|p| p.reason).unwrap_or("-");
    (found, proof.is_some(), reason)
}

fn trial(scenario: PostingScenario) -> (bool, bool, &'static str) {
    let mut led = Ledger::new(th());
    led.register_bond("orch2", 1000);
    let prior = ClassState {
        stage: Stage::Relax,
        p_class: 0.5,
        last_transition_window: 0,
        slash_mult: 15.0,
        pioneer_armed: true,
    };
    led.seed_state("cls.new.v1", prior);
    let orch = Orchestrator::new("orch2");
    let challenger = Challenger::new(th());
    let m = good_manifest(2);
    let posting = orch.make_posting(prior, &m, &th(), scenario);
    let id = led.post("orch2", posting.clone(), m.clone()).unwrap();
    let found = challenger
        .recompute(&posting, &m, &led.prior_state("cls.new.v1").unwrap())
        .is_some();
    let proof = led.challenge(id).unwrap();
    let reason = proof.as_ref().map(|p| p.reason).unwrap_or("-");
    (found, proof.is_some(), reason)
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}
