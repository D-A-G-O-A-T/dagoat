//! Parity integration tests (WP-0.5): re-express the Python reference's key behaviors and
//! the AI-response-16 amendments in Rust. Proves the port matches the reference oracle.

use std::collections::HashMap;

use goat_backends::{ReferenceBackendA, ReferenceBackendB};
use goat_protocol::attestation_chain::*;
use goat_protocol::backend::GoatBackend;
use goat_protocol::capability::*;
use goat_protocol::conformance::run_conformance;
use goat_protocol::maturity::*;
use goat_protocol::pqsign::*;
use goat_protocol::types::*;
use goat_protocol::verification::*;

// ---------- helpers ----------
fn dev_cap(
    class_id: &str,
    gcu: f64,
    endpoint: &[u8],
    density: u32,
    nc: NetworkClass,
    fp: u8,
) -> DeviceCapability {
    DeviceCapability {
        class_id: class_id.into(),
        fingerprint_commit: vec![fp; 32],
        task_classes: vec![TaskClassCap {
            task_class_id: 10,
            measured_gcu_rate: gcu,
            mem_capacity_mb: 24000,
            batch_limit: 32,
            last_bench_epoch: 0,
        }],
        determinism_ref: (class_id.into(), 1),
        availability: Availability {
            window_bitmap: 1u128 << 100,
            expected_idle_h: 8,
            preempt_p50_ms: 10,
            preempt_p95_ms: 40,
        },
        envelope: Envelope {
            max_power_w: 200,
            thermal_policy_class: 1,
        },
        density_witness: DensityWitness {
            endpoint_id_commit: endpoint.to_vec(),
            observed_compute_equiv: density,
        },
        attestation_refs: AttestationRefs {
            idle_score_epoch: 0,
            network_class: nc,
            tee: false,
        },
    }
}

fn signed_record(
    signer: &MlDsaSigner,
    devices: Vec<DeviceCapability>,
    epoch: u64,
    nonce: &[u8],
    prev: Vec<u8>,
) -> CapabilityRecord {
    let rec = CapabilityRecord {
        version: 1,
        node_id: vec![],
        operator_binding: vec![0u8; 32],
        epoch,
        nonce: nonce.to_vec(),
        devices,
        prev_record: prev,
        alg_id: AlgId::MlDsa65,
        signature: vec![],
    };
    sign_record(rec, signer)
}

fn run_backend_a(seed: u64) -> RunFn<'static> {
    Box::new(move |t: &Task| {
        let mut b = ReferenceBackendA::new(seed);
        let dev = b.enumerate_devices()[0].clone();
        match b.execute(
            &dev,
            t,
            ExecPolicy {
                power_cap_w: 10_000,
            },
            Preempt::default(),
        ) {
            ExecOutcome::Completed(r) => r,
            _ => panic!("preempted"),
        }
    })
}
fn run_backend_b(seed: u64) -> RunFn<'static> {
    Box::new(move |t: &Task| {
        let mut b = ReferenceBackendB::new(seed);
        let dev = b.enumerate_devices()[0].clone();
        match b.execute(
            &dev,
            t,
            ExecPolicy {
                power_cap_w: 10_000,
            },
            Preempt::default(),
        ) {
            ExecOutcome::Completed(r) => r,
            _ => panic!("preempted"),
        }
    })
}
fn perturb(run: RunFn<'static>, d: i64) -> RunFn<'static> {
    Box::new(move |t: &Task| {
        let mut r = run(t);
        r.vector = r.vector.iter().map(|v| v + d).collect();
        r
    })
}
fn task() -> Task {
    Task {
        task_class_id: 10,
        engine_build_id: "build-1".into(),
        payload: b"corpus-42".to_vec(),
        seed: 7,
        determinism_bound: 10.0,
    }
}
fn good_receipts(class_id: &str, window: u64) -> Vec<Receipt> {
    (0..200)
        .map(|i| Receipt {
            class_id: class_id.into(),
            task_class_id: 10,
            window,
            sub_window: i as u32, // spread across sub-window buckets (folded mod SUB_WINDOWS)
            cluster_id: format!("c{}", i % 30),
            asn: format!("a{}", i % 12),
            diverged: false,
            fault: false,
        })
        .collect()
}

/// 2000 receipts with 8 divergences: the window-wide rate (0.004) passes epsilon (0.01), so
/// the gate holds either way. `concentrated` puts all 8 anomalies in ONE sub-window (the
/// R-MAT2 burst shape); otherwise they spread across distinct sub-windows.
fn bursty_receipts(class_id: &str, window: u64, concentrated: bool) -> Vec<Receipt> {
    (0..2000)
        .map(|i| Receipt {
            class_id: class_id.into(),
            task_class_id: 10,
            window,
            sub_window: if concentrated && i < 8 { 0 } else { i as u32 },
            cluster_id: format!("c{}", i % 30),
            asn: format!("a{}", i % 12),
            diverged: i < 8,
            fault: false,
        })
        .collect()
}
fn th() -> GateThresholds {
    GateThresholds {
        v_min: 100,
        epsilon: 0.01,
        phi: 50.0,
        x_clusters: 25,
        x_asns: 10,
    }
}

// ---------- capability + F6 ----------
#[test]
fn capability_sign_verify_and_tamper() {
    let s = MlDsaSigner::generate();
    let mut r = signed_record(
        &s,
        vec![dev_cap(
            "cls.a.v1",
            1.0,
            b"e",
            1,
            NetworkClass::Residential,
            0xAB,
        )],
        1,
        b"nonce",
        ZERO32.to_vec(),
    );
    assert!(verify_record_signature(&r, &s.public_key()));
    r.epoch = 999; // signature was over old epoch
    assert!(!verify_record_signature(&r, &s.public_key()));
}

#[test]
fn capability_wrong_key_rejected() {
    let s = MlDsaSigner::generate();
    let other = MlDsaSigner::generate();
    let r = signed_record(
        &s,
        vec![dev_cap(
            "cls.a.v1",
            1.0,
            b"e",
            1,
            NetworkClass::Residential,
            0xAB,
        )],
        1,
        b"nonce",
        ZERO32.to_vec(),
    );
    assert!(!verify_record_signature(&r, &other.public_key()));
}

#[test]
fn f6_density_signals() {
    let d6 = dev_cap("cls.a.v1", 1.0, b"e", 6, NetworkClass::Residential, 0xAB);
    assert_eq!(evaluate_density(&d6), DensitySignal::CohortMerge);
    for k in [1, 3, 5] {
        let d = dev_cap("cls.a.v1", 1.0, b"e", k, NetworkClass::Residential, 0xAB);
        assert_eq!(evaluate_density(&d), DensitySignal::Ok);
    }
    let dc = dev_cap("cls.a.v1", 1.0, b"e", 60, NetworkClass::Datacenter, 0xAB);
    assert_eq!(evaluate_density(&dc), DensitySignal::Ok);
}

#[test]
fn q_network_factor_monotone() {
    assert_eq!(q_network_factor(3), 0.85);
    assert_eq!(q_network_factor(5), 0.85);
    assert!(q_network_factor(10) < 0.85);
    assert!(q_network_factor(10) > q_network_factor(30));
    assert_eq!(q_network_factor(1000), 0.10);
}

fn ctx(s: &MlDsaSigner) -> ValidationContext {
    let mut c = ValidationContext::new(s.public_key(), b"nonce".to_vec());
    c.tolerance_bands.insert(10, (0.9, 1.1));
    c
}

#[test]
fn validity_full_pass() {
    let s = MlDsaSigner::generate();
    let r = signed_record(
        &s,
        vec![dev_cap(
            "cls.a.v1",
            1.0,
            b"e",
            1,
            NetworkClass::Residential,
            0xAB,
        )],
        1,
        b"nonce",
        ZERO32.to_vec(),
    );
    assert!(validate_record(&r, &ctx(&s)).ok);
}

#[test]
fn validity_bad_nonce_and_chain_and_gcu() {
    let s = MlDsaSigner::generate();
    // bad nonce
    let r = signed_record(
        &s,
        vec![dev_cap(
            "cls.a.v1",
            1.0,
            b"e",
            1,
            NetworkClass::Residential,
            0xAB,
        )],
        1,
        b"WRONG",
        ZERO32.to_vec(),
    );
    assert!(!validate_record(&r, &ctx(&s)).ok);
    // broken chain
    let r2 = signed_record(
        &s,
        vec![dev_cap(
            "cls.a.v1",
            1.0,
            b"e",
            1,
            NetworkClass::Residential,
            0xAB,
        )],
        1,
        b"nonce",
        vec![0x11; 32],
    );
    let mut c = ctx(&s);
    c.last_record_hash = Some(vec![0x22; 32]);
    assert!(!validate_record(&r2, &c).ok);
    // gcu out of band
    let r3 = signed_record(
        &s,
        vec![dev_cap(
            "cls.a.v1",
            5.0,
            b"e",
            1,
            NetworkClass::Residential,
            0xAB,
        )],
        1,
        b"nonce",
        ZERO32.to_vec(),
    );
    let res = validate_record(&r3, &ctx(&s));
    assert!(!res.ok);
    assert!(!res.checks["gcu_tolerance"]);
}

#[test]
fn validity_density_underclaim_fails_and_merges_on_probe() {
    let s = MlDsaSigner::generate();
    let ep = b"Z-endpoint".to_vec();
    let r = signed_record(
        &s,
        vec![dev_cap(
            "cls.a.v1",
            1.0,
            &ep,
            1,
            NetworkClass::Residential,
            0xAB,
        )],
        1,
        b"nonce",
        ZERO32.to_vec(),
    );
    let mut c = ctx(&s);
    c.probe_observed_equiv.insert(ep, 60);
    let res = validate_record(&r, &c);
    assert!(!res.ok);
    assert!(!res.checks["density_consistent"]);
    assert_eq!(res.density_signals["cls.a.v1"], DensitySignal::CohortMerge); // fires on probe value
}

#[test]
fn validity_fingerprint_drift_is_soft() {
    let s = MlDsaSigner::generate();
    let r = signed_record(
        &s,
        vec![dev_cap(
            "cls.a.v1",
            1.0,
            b"e",
            1,
            NetworkClass::Residential,
            0xCD,
        )],
        1,
        b"nonce",
        ZERO32.to_vec(),
    );
    let mut c = ctx(&s);
    c.prior_fingerprints
        .insert("cls.a.v1".into(), vec![0xAB; 32]); // different prior
    let res = validate_record(&r, &c);
    assert!(!res.checks["fingerprint_stable"]); // flagged
    assert!(res.ok); // but not a hard reject
}

// ---------- hash-chain ----------
fn chain_of(s: &MlDsaSigner, n: u64) -> RecordChain {
    let mut chain = RecordChain::new(s.public_key());
    let mut prev = ZERO32.to_vec();
    for e in 1..=n {
        let r = signed_record(
            s,
            vec![dev_cap(
                "cls.a.v1",
                1.0,
                b"e",
                e as u32,
                NetworkClass::Residential,
                0xAB,
            )],
            e,
            b"nonce",
            prev.clone(),
        );
        prev = record_hash(&r);
        chain.append(r).unwrap();
    }
    chain
}

#[test]
fn chain_append_integrity_and_rejections() {
    let s = MlDsaSigner::generate();
    let chain = chain_of(&s, 3);
    assert_eq!(chain.len(), 3);
    assert!(chain.verify_integrity());

    let mut c1 = chain_of(&s, 1);
    let bad = signed_record(
        &s,
        vec![dev_cap(
            "cls.a.v1",
            1.0,
            b"e",
            2,
            NetworkClass::Residential,
            0xAB,
        )],
        2,
        b"nonce",
        vec![0x99; 32],
    );
    assert_eq!(c1.append(bad), Err(ChainError::BrokenLink));

    let other = MlDsaSigner::generate();
    let mut c2 = RecordChain::new(s.public_key());
    let foreign = signed_record(
        &other,
        vec![dev_cap(
            "cls.a.v1",
            1.0,
            b"e",
            1,
            NetworkClass::Residential,
            0xAB,
        )],
        1,
        b"nonce",
        ZERO32.to_vec(),
    );
    assert_eq!(c2.append(foreign), Err(ChainError::BadSignature));
}

#[test]
fn chain_non_increasing_epoch_rejected() {
    let s = MlDsaSigner::generate();
    let mut chain = chain_of(&s, 2);
    let prev = chain.head_hash();
    let r = signed_record(
        &s,
        vec![dev_cap(
            "cls.a.v1",
            1.0,
            b"e",
            2,
            NetworkClass::Residential,
            0xAB,
        )],
        2,
        b"nonce",
        prev,
    );
    assert_eq!(chain.append(r), Err(ChainError::NonIncreasingEpoch));
}

#[test]
fn chain_tamper_breaks_integrity() {
    let s = MlDsaSigner::generate();
    let mut chain = chain_of(&s, 2);
    let r0_tampered = signed_record(
        &s,
        vec![dev_cap(
            "cls.a.v1",
            1.0,
            b"e",
            99,
            NetworkClass::Residential,
            0xAB,
        )],
        1,
        b"nonce",
        ZERO32.to_vec(),
    );
    chain.replace_record(0, r0_tampered);
    assert!(!chain.verify_integrity());
}

#[test]
fn rolling_reattestation_rules() {
    assert_eq!(staleness_weight(100, 105, 24), 1.0);
    let w = staleness_weight(100, 148, 24);
    assert!((0.1..1.0).contains(&w));
    assert!(needs_rebenchmark(
        0,
        DEFAULT_MAX_BENCH_AGE_EPOCHS,
        false,
        false,
        DEFAULT_MAX_BENCH_AGE_EPOCHS
    ));
    assert!(needs_rebenchmark(
        0,
        1,
        true,
        false,
        DEFAULT_MAX_BENCH_AGE_EPOCHS
    ));
    assert!(!needs_rebenchmark(
        0,
        10,
        false,
        false,
        DEFAULT_MAX_BENCH_AGE_EPOCHS
    ));
}

// ---------- maturity ----------
#[test]
fn r_mat1_cross_instance_root_reproducibility() {
    let r = good_receipts("x", 0);
    let a = fold_receipts(&r, &[]);
    // fold again, receipts in reverse order -> HLL is order-independent -> identical root
    let mut rev = r.clone();
    rev.reverse();
    let b = fold_receipts(&rev, &[]);
    assert_eq!(
        a[&("x".to_string(), 0)].root(),
        b[&("x".to_string(), 0)].root()
    );
}

#[test]
fn gate_pass_and_low_coverage_fail() {
    let acc = fold_receipts(&good_receipts("x", 0), &[]);
    assert!(gate(&acc[&("x".to_string(), 0)], &th()).0);
    let sparse: Vec<Receipt> = (0..200)
        .map(|i| Receipt {
            class_id: "x".into(),
            task_class_id: 10,
            window: 0,
            sub_window: i as u32,
            cluster_id: format!("c{}", i % 10),
            asn: format!("a{}", i % 12),
            diverged: false,
            fault: false,
        })
        .collect();
    let acc2 = fold_receipts(&sparse, &[]);
    assert!(!gate(&acc2[&("x".to_string(), 0)], &th()).0);
}

#[test]
fn full_progression_to_mature() {
    let mut c = MaturityController::new(th(), 8.0);
    assert!(c.register_class(
        "x",
        RegistrationSet {
            nodes: 50,
            clusters: 25,
            asns: 10,
            regions: 5
        },
        4.0,
        0
    ));
    let mut seq = Vec::new();
    for w in 1..=5u64 {
        let (tr, _) = c.process_window("x", &good_receipts("x", w), &[], false, w);
        seq.push((tr.to_stage, (tr.to_p * 100.0).round() as i64));
    }
    assert_eq!(
        seq,
        vec![
            (Stage::Relax, 50),
            (Stage::Relax, 25),
            (Stage::Relax, 15),
            (Stage::Mature, 15),
            (Stage::Mature, 15)
        ]
    );
}

#[test]
fn registration_gates_on_diversity() {
    let mut c = MaturityController::new(th(), 8.0);
    assert!(!c.register_class(
        "y",
        RegistrationSet {
            nodes: 49,
            clusters: 25,
            asns: 10,
            regions: 5
        },
        4.0,
        0
    ));
    assert_eq!(c.states["y"].stage, Stage::Candidate);
}

#[test]
fn relax_breach_snaps_and_mature_breach_reenters_relax() {
    let mut c = MaturityController::new(th(), 8.0);
    c.register_class(
        "x",
        RegistrationSet {
            nodes: 50,
            clusters: 25,
            asns: 10,
            regions: 5,
        },
        4.0,
        0,
    );
    c.process_window("x", &good_receipts("x", 1), &[], false, 1); // RELAX 0.5
    c.process_window("x", &good_receipts("x", 2), &[], false, 2); // RELAX 0.25
    let mut breach = good_receipts("x", 3);
    for r in breach.iter_mut().take(10) {
        r.diverged = true;
    }
    let (tr, _) = c.process_window("x", &breach, &[], false, 3);
    assert_eq!(tr.kind, "snap");
    assert_eq!(tr.to_stage, Stage::Relax);
    assert!((tr.to_p - 0.5).abs() < 1e-9);
}

#[test]
fn anomaly_burst_forces_snap_when_gate_ok() {
    // a DECLARED snap (conservative extra trigger) still snaps even with clean receipts
    let mut c = MaturityController::new(th(), 8.0);
    c.register_class(
        "x",
        RegistrationSet {
            nodes: 50,
            clusters: 25,
            asns: 10,
            regions: 5,
        },
        4.0,
        0,
    );
    c.process_window("x", &good_receipts("x", 1), &[], false, 1);
    c.process_window("x", &good_receipts("x", 2), &[], false, 2); // RELAX 0.25
    let (tr, _) = c.process_window("x", &good_receipts("x", 3), &[], true, 3);
    assert!(tr.gate_ok);
    assert_eq!(tr.kind, "snap");
}

fn reg_50() -> RegistrationSet {
    RegistrationSet {
        nodes: 50,
        clusters: 25,
        asns: 10,
        regions: 5,
    }
}

#[test]
fn r_mat2_recomputed_burst_forces_snap_without_declared_flag() {
    // the burst is derived from the receipts themselves: no declared flag, gate holds,
    // yet the concentration of anomalies snaps the class
    let mut c = MaturityController::new(th(), 8.0);
    c.register_class("x", reg_50(), 4.0, 0);
    c.process_window("x", &good_receipts("x", 1), &[], false, 1); // RELAX 0.5
    c.process_window("x", &good_receipts("x", 2), &[], false, 2); // RELAX 0.25
    let (tr, _) = c.process_window("x", &bursty_receipts("x", 3, true), &[], false, 3);
    assert!(tr.gate_ok); // window-wide rates pass
    assert_eq!(tr.kind, "snap"); // the recomputed burst snaps anyway
    assert!((tr.to_p - 0.5).abs() < 1e-9);
}

#[test]
fn r_mat2_spread_anomalies_do_not_burst() {
    // the SAME anomaly count spread across sub-windows is not a burst: relaxation proceeds
    let mut c = MaturityController::new(th(), 8.0);
    c.register_class("x", reg_50(), 4.0, 0);
    c.process_window("x", &good_receipts("x", 1), &[], false, 1); // RELAX 0.5
    c.process_window("x", &good_receipts("x", 2), &[], false, 2); // RELAX 0.25
    let (tr, _) = c.process_window("x", &bursty_receipts("x", 3, false), &[], false, 3);
    assert!(tr.gate_ok);
    assert_eq!(tr.kind, "relax");
    assert!((tr.to_p - 0.15).abs() < 1e-9); // 0.25 -> max(0.125, P_FLOOR)
}

#[test]
fn r_mat2_withheld_burst_snap_is_fraud_and_honest_snap_is_legal() {
    let prior = ClassState {
        stage: Stage::Relax,
        p_class: 0.25,
        last_transition_window: 0,
        slash_mult: 15.0,
        pioneer_armed: true,
    };
    let r = bursty_receipts("x", 2, true);
    let root = fold_receipts(&r, &[])[&("x".to_string(), 2)].root();

    // withholding the recomputable snap (claiming the legal NON-burst relax step) is fraud
    let withheld = WindowPosting {
        class_id: "x".into(),
        window: 2,
        accumulator_root: root.clone(),
        claimed_from_stage: Stage::Relax,
        claimed_from_p: 0.25,
        claimed_to_stage: Stage::Relax,
        claimed_to_p: 0.15,
    };
    assert_eq!(
        verify_posting(&withheld, &r, &prior, &th(), &[])
            .unwrap()
            .reason,
        "withheld_burst_snap"
    );

    // the honest burst snap (0.25 -> 0.5) on the same receipts is legal
    let snapped = WindowPosting {
        claimed_to_p: 0.5,
        ..withheld.clone()
    };
    assert!(verify_posting(&snapped, &r, &prior, &th(), &[]).is_none());

    // over-conservative (full resample at PROBATION) is also never fraud
    let cons = WindowPosting {
        claimed_to_stage: Stage::Probation,
        claimed_to_p: 1.0,
        ..withheld
    };
    assert!(verify_posting(&cons, &r, &prior, &th(), &[]).is_none());
}

#[test]
fn r_mat2_no_burst_means_no_false_flag() {
    // spread anomalies: the non-burst relax step is legal, not "withheld"
    let prior = ClassState {
        stage: Stage::Relax,
        p_class: 0.25,
        last_transition_window: 0,
        slash_mult: 15.0,
        pioneer_armed: true,
    };
    let r = bursty_receipts("x", 2, false);
    let root = fold_receipts(&r, &[])[&("x".to_string(), 2)].root();
    let posting = WindowPosting {
        class_id: "x".into(),
        window: 2,
        accumulator_root: root,
        claimed_from_stage: Stage::Relax,
        claimed_from_p: 0.25,
        claimed_to_stage: Stage::Relax,
        claimed_to_p: 0.15,
    };
    assert!(verify_posting(&posting, &r, &prior, &th(), &[]).is_none());
}

#[test]
fn r_mat2_root_binds_sub_window_distribution() {
    // same aggregate counts, different temporal distribution -> different roots: the root
    // commits to WHEN anomalies occurred, so the burst evidence is tamper-evident
    let a = fold_receipts(&bursty_receipts("x", 0, true), &[]);
    let b = fold_receipts(&bursty_receipts("x", 0, false), &[]);
    assert_ne!(
        a[&("x".to_string(), 0)].root(),
        b[&("x".to_string(), 0)].root()
    );
}

#[test]
fn cohort_merge_collapses_coverage_and_snaps() {
    let mut c = MaturityController::new(th(), 8.0);
    c.register_class(
        "x",
        RegistrationSet {
            nodes: 50,
            clusters: 25,
            asns: 10,
            regions: 5,
        },
        4.0,
        0,
    );
    c.process_window("x", &good_receipts("x", 1), &[], false, 1); // RELAX 0.5
    let merge: Vec<Vec<String>> = vec![(0..25).map(|i| format!("c{}", i)).collect()];
    let (tr, _) = c.process_window("x", &good_receipts("x", 2), &merge, false, 2);
    assert_eq!(tr.kind, "snap");
}

#[test]
fn slash_coupling_and_margin() {
    assert!((slash_multiple(0.0, 8.0) - 15.0).abs() < 1e-9);
    assert!((slash_multiple(8.0, 8.0) - 20.0).abs() < 1e-9);
    assert!(slash_multiple(4.0, 8.0) > 15.0 && slash_multiple(4.0, 8.0) < 20.0);
    assert!((slash_multiple(100.0, 8.0) - 20.0).abs() < 1e-9);
    assert!(fault_ev_margin(15.0, P_FLOOR) > 1.0);
}

fn honest_posting(prior: &ClassState, receipts: &[Receipt], window: u64) -> WindowPosting {
    let folded = fold_receipts(receipts, &[]);
    let acc = &folded[&("x".to_string(), window)];
    let (gate_ok, _) = gate(acc, &th());
    let (to_s, to_p, kind) = evaluate_transition(prior.stage, prior.p_class, gate_ok, false);
    let tr = Transition {
        class_id: "x".into(),
        window,
        from_stage: prior.stage,
        from_p: prior.p_class,
        to_stage: to_s,
        to_p,
        kind,
        gate_ok,
        reasons: vec![],
    };
    make_posting(&tr, acc.root())
}

#[test]
fn fraud_valid_none_and_detections() {
    let prior = ClassState {
        stage: Stage::Probation,
        p_class: 1.0,
        last_transition_window: 0,
        slash_mult: 15.0,
        pioneer_armed: true,
    };
    let r = good_receipts("x", 1);
    let posting = honest_posting(&prior, &r, 1);
    assert!(verify_posting(&posting, &r, &prior, &th(), &[]).is_none());

    let mut bad = posting.clone();
    bad.accumulator_root = vec![0u8; 32];
    assert_eq!(
        verify_posting(&bad, &r, &prior, &th(), &[]).unwrap().reason,
        "root_mismatch"
    );

    // undersampling: prior RELAX 0.5, legal -> 0.25, claim 0.15
    let prior2 = ClassState {
        stage: Stage::Relax,
        p_class: 0.5,
        last_transition_window: 0,
        slash_mult: 15.0,
        pioneer_armed: true,
    };
    let r2 = good_receipts("x", 2);
    let acc2 = fold_receipts(&r2, &[])[&("x".to_string(), 2)].root();
    let lie = WindowPosting {
        class_id: "x".into(),
        window: 2,
        accumulator_root: acc2.clone(),
        claimed_from_stage: Stage::Relax,
        claimed_from_p: 0.5,
        claimed_to_stage: Stage::Relax,
        claimed_to_p: 0.15,
    };
    assert_eq!(
        verify_posting(&lie, &r2, &prior2, &th(), &[])
            .unwrap()
            .reason,
        "undersampling"
    );

    // over-advanced: keep p==legal (0.25), claim MATURE
    let lie2 = WindowPosting {
        class_id: "x".into(),
        window: 2,
        accumulator_root: acc2.clone(),
        claimed_from_stage: Stage::Relax,
        claimed_from_p: 0.5,
        claimed_to_stage: Stage::Mature,
        claimed_to_p: 0.25,
    };
    assert_eq!(
        verify_posting(&lie2, &r2, &prior2, &th(), &[])
            .unwrap()
            .reason,
        "over_advanced"
    );

    // bad prior
    let lie3 = WindowPosting {
        class_id: "x".into(),
        window: 2,
        accumulator_root: acc2.clone(),
        claimed_from_stage: Stage::Relax,
        claimed_from_p: 0.25,
        claimed_to_stage: Stage::Relax,
        claimed_to_p: 0.25,
    };
    assert_eq!(
        verify_posting(&lie3, &r2, &prior2, &th(), &[])
            .unwrap()
            .reason,
        "bad_prior"
    );

    // conservative (higher sampling) is NOT fraud
    let cons = WindowPosting {
        class_id: "x".into(),
        window: 2,
        accumulator_root: acc2,
        claimed_from_stage: Stage::Relax,
        claimed_from_p: 0.5,
        claimed_to_stage: Stage::Relax,
        claimed_to_p: 0.5,
    };
    assert!(verify_posting(&cons, &r2, &prior2, &th(), &[]).is_none());
}

// ---------- cross-class verification ----------
fn exact() -> DeterminismProfile {
    DeterminismProfile::exact()
}
fn tol8() -> DeterminismProfile {
    DeterminismProfile::tolerance(8.0)
}

#[test]
fn effective_profile_rules() {
    assert_eq!(
        effective_profile(&exact(), &exact(), true, 10.0)
            .unwrap()
            .kind,
        DetKind::Exact
    );
    let cross = effective_profile(&exact(), &tol8(), false, 10.0).unwrap();
    assert_eq!(cross.kind, DetKind::Tolerance);
    assert_eq!(cross.bound, 8.0);
    assert!(effective_profile(&exact(), &tol8(), false, 2.0).is_none()); // ineligible
    assert!(effective_profile(&tol8(), &tol8(), true, 2.0).is_none()); // wide class can't serve strict
}

#[test]
fn agree_cross_class_real_backends() {
    let ra = run_backend_a(0)(&task());
    let rb = run_backend_b(0)(&task());
    let prof = effective_profile(&exact(), &tol8(), false, 10.0).unwrap();
    assert!(agree(&ra, &rb, &prof, TOKEN_THRESHOLD));
    let mut deviant = rb.clone();
    deviant.vector = deviant.vector.iter().map(|v| v + 50).collect();
    assert!(!agree(&ra, &deviant, &prof, TOKEN_THRESHOLD));
}

fn a_ref() -> ExecutorRef {
    ExecutorRef {
        node_id: "nodeA".into(),
        class_id: "cls.a.v1".into(),
        cluster_id: "clu-1".into(),
        asn: "asn-1".into(),
        profile: exact(),
    }
}
fn b_ref() -> ExecutorRef {
    ExecutorRef {
        node_id: "nodeB".into(),
        class_id: "cls.b.v1".into(),
        cluster_id: "clu-2".into(),
        asn: "asn-2".into(),
        profile: tol8(),
    }
}
fn c_a_ref() -> ExecutorRef {
    ExecutorRef {
        node_id: "nodeC".into(),
        class_id: "cls.a.v1".into(),
        cluster_id: "clu-3".into(),
        asn: "asn-3".into(),
        profile: exact(),
    }
}

#[test]
fn harness_settle_and_ineligible() {
    let h = VerificationHarness::new(8.0);
    let out = h.verify(
        &task(),
        &Submission {
            executor: a_ref(),
            result: run_backend_a(0)(&task()),
        },
        &Submission {
            executor: b_ref(),
            result: run_backend_b(0)(&task()),
        },
        &[],
        5,
    );
    assert_eq!(out.status, Status::Settled);
    assert_eq!(out.receipts.len(), 2);

    let strict = Task {
        determinism_bound: 2.0,
        ..task()
    };
    let out2 = h.verify(
        &strict,
        &Submission {
            executor: a_ref(),
            result: run_backend_a(0)(&strict),
        },
        &Submission {
            executor: b_ref(),
            result: run_backend_b(0)(&strict),
        },
        &[],
        5,
    );
    assert_eq!(out2.status, Status::IneligibleCrossClass);
}

#[test]
fn escalation_c_agrees_a_slashes_b() {
    let h = VerificationHarness::new(8.0);
    let pool: Vec<(ExecutorRef, RunFn)> = vec![(c_a_ref(), run_backend_a(0))];
    let out = h.verify(
        &task(),
        &Submission {
            executor: a_ref(),
            result: run_backend_a(0)(&task()),
        },
        &Submission {
            executor: b_ref(),
            result: perturb(run_backend_b(0), 50)(&task()),
        },
        &pool,
        5,
    );
    assert_eq!(out.status, Status::SettledEscalated);
    assert_eq!(out.winner.as_deref(), Some("nodeA"));
    assert_eq!(out.slashed.as_deref(), Some("nodeB"));
    assert!((out.slash_mult.unwrap() - 20.0).abs() < 1e-9); // band 8 == tol_ref -> cap
    let faulted: Vec<_> = out.receipts.iter().filter(|r| r.fault).collect();
    assert_eq!(faulted.len(), 1);
    assert_eq!(faulted[0].class_id, "cls.b.v1");
}

#[test]
fn escalation_c_agrees_b_slashes_a() {
    let h = VerificationHarness::new(8.0);
    let pool: Vec<(ExecutorRef, RunFn)> = vec![(c_a_ref(), run_backend_a(0))];
    let out = h.verify(
        &task(),
        &Submission {
            executor: a_ref(),
            result: perturb(run_backend_a(0), 50)(&task()),
        },
        &Submission {
            executor: b_ref(),
            result: run_backend_b(0)(&task()),
        },
        &pool,
        5,
    );
    assert_eq!(out.slashed.as_deref(), Some("nodeA"));
    assert!((out.slash_mult.unwrap() - 15.0).abs() < 1e-9); // EXACT band 0 -> base
}

#[test]
fn escalation_three_way_split_quarantines() {
    let h = VerificationHarness::new(8.0);
    let c_b = ExecutorRef {
        node_id: "nodeCb".into(),
        class_id: "cls.b.v1".into(),
        cluster_id: "clu-3".into(),
        asn: "asn-3".into(),
        profile: tol8(),
    };
    let pool: Vec<(ExecutorRef, RunFn)> = vec![(c_b, perturb(run_backend_a(0), -50))];
    let out = h.verify(
        &task(),
        &Submission {
            executor: a_ref(),
            result: run_backend_a(0)(&task()),
        },
        &Submission {
            executor: b_ref(),
            result: perturb(run_backend_b(0), 50)(&task()),
        },
        &pool,
        5,
    );
    assert_eq!(out.status, Status::Quarantined);
    assert!(out.slashed.is_none());
    assert!(out.profile_remeasure);
}

#[test]
fn escalation_c_agrees_both_no_attribution() {
    let h = VerificationHarness::new(8.0);
    // B = A+14 (disagrees at band 8), C = A+7 (within band 8 of both), tokens identical
    let b14 = ExecutorRef {
        node_id: "nodeB14".into(),
        class_id: "cls.b.v1".into(),
        cluster_id: "clu-2".into(),
        asn: "asn-2".into(),
        profile: tol8(),
    };
    let c_b = ExecutorRef {
        node_id: "nodeCb".into(),
        class_id: "cls.b.v1".into(),
        cluster_id: "clu-3".into(),
        asn: "asn-3".into(),
        profile: tol8(),
    };
    let pool: Vec<(ExecutorRef, RunFn)> = vec![(c_b, perturb(run_backend_a(0), 7))];
    let out = h.verify(
        &task(),
        &Submission {
            executor: a_ref(),
            result: run_backend_a(0)(&task()),
        },
        &Submission {
            executor: b14,
            result: perturb(run_backend_a(0), 14)(&task()),
        },
        &pool,
        5,
    );
    assert_eq!(out.status, Status::SettledEscalated);
    assert_eq!(out.winner.as_deref(), Some("nodeA"));
    assert!(out.slashed.is_none());
    assert!(out.profile_remeasure);
}

#[test]
fn receipt_integration_faulted_class_gets_d_num() {
    let h = VerificationHarness::new(8.0);
    let pool: Vec<(ExecutorRef, RunFn)> = vec![(c_a_ref(), run_backend_a(0))];
    let out = h.verify(
        &task(),
        &Submission {
            executor: a_ref(),
            result: run_backend_a(0)(&task()),
        },
        &Submission {
            executor: b_ref(),
            result: perturb(run_backend_b(0), 50)(&task()),
        },
        &pool,
        3,
    );
    let accs = fold_receipts(&out.receipts, &[]);
    let acc_b = &accs[&("cls.b.v1".to_string(), 3)];
    let acc_a = &accs[&("cls.a.v1".to_string(), 3)];
    assert_eq!((acc_b.v_c, acc_b.d_num, acc_b.f_num), (1, 1, 1));
    assert_eq!((acc_a.v_c, acc_a.d_num, acc_a.f_num), (2, 0, 0)); // A + C clean
}

// ---------- conformance ----------
#[test]
fn conformance_both_backends_pass() {
    let a = run_conformance(&|s| ReferenceBackendA::new(s), 25);
    for (name, (ok, detail)) in &a.results {
        assert!(*ok, "A {name}: {detail}");
    }
    let b = run_conformance(&|s| ReferenceBackendB::new(s), 25);
    for (name, (ok, detail)) in &b.results {
        assert!(*ok, "B {name}: {detail}");
    }
}

#[test]
fn conformance_d6_envelope_binds_over_policy() {
    let mut b = ReferenceBackendA::new(0);
    let dev = b.enumerate_devices()[0].clone();
    b.enforce_envelope(&dev, 30);
    let _ = b.execute(
        &dev,
        &task(),
        ExecPolicy {
            power_cap_w: 100_000,
        },
        Preempt::default(),
    );
    assert!(b.peak_power_w() <= 30.0);
}

// silence unused-import warnings for HashMap in some builds
#[allow(dead_code)]
fn _uses(_: HashMap<String, u32>) {}
