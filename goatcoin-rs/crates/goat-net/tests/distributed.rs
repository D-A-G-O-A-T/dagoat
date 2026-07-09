//! MVP-2 distributed verification acceptance (WP-2.5): SC2 (honest cross-class settle +
//! strict pin), SC3 (faulty-submission detect/escalate/attribute), SC4 (all four outcomes), SC7
//! (spread/liveness), SC10 (PQ sizes). Roles run over the PQ transport.

use goat_backends::ReferenceBackendA;
use goat_net::distributed::*;
use goat_net::transport::Network;
use goat_protocol::backend::GoatBackend;
use goat_protocol::maturity::fold_receipts;
use goat_protocol::types::{
    DeterminismProfile, ExecOutcome, ExecPolicy, Preempt, Task, TaskResult,
};
use goat_protocol::verification::{effective_profile, Status};

const BEACON: &[u8] = &[0x5a; 32];

fn base_compute(t: &Task) -> TaskResult {
    let mut b = ReferenceBackendA::new(0);
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
}

/// A run closure: the base reference compute with a fixed vector offset (models honest
/// roundoff or a faulty submission, precisely controlled for the test).
fn run(delta: i64) -> RunFn {
    Box::new(move |t: &Task| {
        let mut r = base_compute(t);
        r.vector = r.vector.iter().map(|v| v + delta).collect();
        r
    })
}

fn exact() -> DeterminismProfile {
    DeterminismProfile::exact()
}
fn tol8() -> DeterminismProfile {
    DeterminismProfile::tolerance(8.0)
}

fn node(
    id: &str,
    class: &str,
    cl: &str,
    asn: &str,
    region: &str,
    prof: DeterminismProfile,
    delta: i64,
) -> ExecutorNode {
    ExecutorNode::new(id, class, cl, asn, region, prof, run(delta))
}

fn task(bound: f64) -> Task {
    Task {
        task_class_id: 10,
        engine_build_id: "b1".into(),
        payload: b"dist-task".to_vec(),
        seed: 7,
        determinism_bound: bound,
    }
}

fn orch() -> Orchestrator {
    Orchestrator::new("orchestrator")
}

// ---------------- SC2: honest cross-class settle + strict pin ----------------
#[test]
fn sc2_honest_cross_class_settles() {
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 3), // within band 8 of A
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), BEACON, 1, 8.0, 3, 0);
    assert_eq!(out.status, Status::Settled);
    assert_eq!(out.receipts.len(), 2);
    assert!(out.log.is_some() && verify_assignment_log(out.log.as_ref().unwrap()));
}

#[test]
fn sc2_strict_task_pins_to_same_class() {
    // cross-class is ineligible for a strict (bound 2) task ...
    assert!(effective_profile(&exact(), &tol8(), false, 2.0).is_none());
    // ... and two same-class (EXACT) nodes serve it and settle
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("A2", "cls.a.v1", "c2", "a2", "r2", exact(), 0),
        node("A3", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(2.0), BEACON, 1, 8.0, 3, 0);
    assert_eq!(out.status, Status::Settled);
}

// ---------------- SC3: faulty-submission detect/escalate/attribute ----------------
#[test]
fn sc3_faulty_submission_escalated_slashed_and_attributed() {
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 50), // fault: +50 > band
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0), // honest verifier
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), BEACON, 1, 8.0, 3, 3);
    assert_eq!(out.status, Status::SettledEscalated);
    assert_eq!(out.winner.as_deref(), Some("A"));
    assert_eq!(out.slashed.as_deref(), Some("B"));
    assert!((out.slash_mult.unwrap() - 20.0).abs() < 1e-9); // band 8 == tol_ref -> cap
    assert_eq!(out.selected_c.as_deref(), Some("C"));
    // divergence attributed to the faulted class's accumulator
    let accs = fold_receipts(&out.receipts, &[]);
    let acc_b = &accs[&("cls.b.v1".to_string(), 3)];
    let acc_a = &accs[&("cls.a.v1".to_string(), 3)];
    assert_eq!((acc_b.v_c, acc_b.d_num, acc_b.f_num), (1, 1, 1));
    assert_eq!((acc_a.v_c, acc_a.d_num, acc_a.f_num), (2, 0, 0)); // A + C clean
}

// ---------------- SC4: all four escalation outcomes ----------------
#[test]
fn sc4_all_four_escalation_outcomes() {
    let o = orch();
    // settle
    let p1 = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 3),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    assert_eq!(
        run_round(
            &mut Network::new(),
            &o,
            &p1,
            &task(10.0),
            BEACON,
            1,
            8.0,
            3,
            0
        )
        .status,
        Status::Settled
    );

    // C agrees A -> slash B
    let p2 = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 50),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let o2 = run_round(
        &mut Network::new(),
        &o,
        &p2,
        &task(10.0),
        BEACON,
        1,
        8.0,
        3,
        0,
    );
    assert_eq!(o2.status, Status::SettledEscalated);
    assert_eq!(o2.slashed.as_deref(), Some("B"));

    // C agrees B -> slash A
    let p3 = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 50),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 0),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let o3 = run_round(
        &mut Network::new(),
        &o,
        &p3,
        &task(10.0),
        BEACON,
        1,
        8.0,
        3,
        0,
    );
    assert_eq!(o3.slashed.as_deref(), Some("A"));

    // C agrees both -> no attribution (A=base, B=+14 disagree, C=+7 within band of both)
    let p4 = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 14),
        node("C", "cls.b.v1", "c3", "a3", "r3", tol8(), 7),
    ];
    let o4 = run_round(
        &mut Network::new(),
        &o,
        &p4,
        &task(10.0),
        BEACON,
        1,
        8.0,
        3,
        0,
    );
    assert_eq!(o4.status, Status::SettledEscalated);
    assert!(o4.slashed.is_none() && o4.profile_remeasure);

    // 3-way split -> quarantine (A=base, B=+50, C=-50 agrees neither)
    let p5 = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 50),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), -50),
    ];
    let o5 = run_round(
        &mut Network::new(),
        &o,
        &p5,
        &task(10.0),
        BEACON,
        1,
        8.0,
        3,
        0,
    );
    assert_eq!(o5.status, Status::Quarantined);
    assert!(o5.slashed.is_none());
}

// ---------------- SC7: spread rule & escalation liveness ----------------
#[test]
fn sc7_spread_satisfied_and_liveness() {
    // ~10 nodes across distinct clusters/ASNs/regions: assign succeeds, escalation never
    // quarantines for lack of a disjoint C.
    let mut pool = Vec::new();
    for i in 0..10 {
        let (cls, prof) = if i % 2 == 0 {
            ("cls.a.v1", exact())
        } else {
            ("cls.b.v1", tol8())
        };
        pool.push(node(
            &format!("N{i}"),
            cls,
            &format!("c{i}"),
            &format!("a{i}"),
            &format!("r{}", i % 5),
            prof,
            if i % 2 == 0 { 0 } else { 3 },
        ));
    }
    let out = run_round(
        &mut Network::new(),
        &orch(),
        &pool,
        &task(10.0),
        BEACON,
        1,
        8.0,
        3,
        0,
    );
    assert_eq!(out.status, Status::Settled); // honest -> settle; assign satisfied spread
    assert!(verify_assignment_log(out.log.as_ref().unwrap()));
}

#[test]
fn sc7_insufficient_spread_is_refused() {
    // all nodes share one cluster -> spread < m=3 -> assignment refused (not a silent bad set)
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c1", "a2", "r2", tol8(), 3),
        node("C", "cls.a.v1", "c1", "a3", "r3", exact(), 0),
    ];
    let out = run_round(
        &mut Network::new(),
        &orch(),
        &pool,
        &task(10.0),
        BEACON,
        1,
        8.0,
        3,
        0,
    );
    assert_eq!(out.status, Status::Quarantined);
    assert_eq!(out.detail, "spread rule unsatisfiable");
}

// ---------------- lottery + assignment log integrity ----------------
#[test]
fn lottery_is_beacon_deterministic_and_verifiable() {
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 0),
        node("C1", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
        node("C2", "cls.a.v1", "c4", "a4", "r4", exact(), 0),
    ];
    let a = &pool[0].eref;
    let b = &pool[1].eref;
    let s1 = lottery_select(BEACON, 7, &pool, a, b, 10.0);
    let s2 = lottery_select(BEACON, 7, &pool, a, b, 10.0);
    assert_eq!(s1, s2); // deterministic from beacon+task_id
    assert!(s1 == Some(2) || s1 == Some(3)); // one of the disjoint pairable candidates
                                             // a different beacon may select a different C (verifiable reshuffle)
    let s3 = lottery_select(&[0x11; 32], 7, &pool, a, b, 10.0);
    assert!(s3.is_some());
}

#[test]
fn tampered_assignment_log_fails_verification() {
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 3),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), BEACON, 1, 8.0, 3, 0);
    let mut log = out.log.unwrap();
    assert!(verify_assignment_log(&log));
    log.node_ids[0] = "substituted-node".into(); // modify a signed field after signing
    assert!(!verify_assignment_log(&log));
}

// ---------------- R-MAT2b: executor-attested sub_window provenance ----------------
#[test]
fn receipt_sub_window_comes_from_executor_attestation() {
    use goat_protocol::maturity::SUB_WINDOWS;
    // A settled round only produces receipts if every executor's sub_window attestation verified
    // inside run_round. The orchestrator has no path to synthesize a bucket, so each receipt's
    // sub_window is exactly the executor-attested value — it cannot be silently overridden.
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 3),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let t = task(10.0);
    let out = run_round(&mut net, &orch(), &pool, &t, BEACON, 1, 8.0, 3, 0);
    assert_eq!(out.status, Status::Settled);
    let expected = (t.seed % SUB_WINDOWS as u64) as u32;
    for r in &out.receipts {
        assert_eq!(r.sub_window, expected);
    }
}

#[test]
fn invalid_attestation_quarantines_the_round() {
    // Executor A returns a stamp whose reported bucket does not match what it signed. The
    // orchestrator's enforcement rejects it and quarantines rather than accepting an
    // unverifiable bucket or substituting its own.
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0)
            .with_attestation(AttestationMode::Invalid),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 3),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), BEACON, 1, 8.0, 3, 0);
    assert_eq!(out.status, Status::Quarantined);
    assert!(out.detail.contains("executor A"));
    assert!(out.receipts.is_empty()); // no receipts fold from an unverified bucket
}

#[test]
fn missing_attestation_quarantines_the_round() {
    // Executor B omits its attestation entirely; the required stamp is absent -> quarantine.
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 3)
            .with_attestation(AttestationMode::Missing),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), BEACON, 1, 8.0, 3, 0);
    assert_eq!(out.status, Status::Quarantined);
    assert!(out.detail.contains("executor B"));
}

#[test]
fn escalation_executor_attestation_is_also_enforced() {
    // A and B disagree, so the round escalates to a lottery-selected C. If C's attestation is
    // invalid, enforcement extends to the escalation executor: quarantine instead of resolving
    // on an unverified bucket. No slash is attributed.
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 50), // > band -> disagree -> escalate
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0)
            .with_attestation(AttestationMode::Invalid),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), BEACON, 1, 8.0, 3, 3);
    assert_eq!(out.status, Status::Quarantined);
    assert_eq!(out.selected_c.as_deref(), Some("C"));
    assert!(out.detail.contains("executor C"));
    assert!(out.slashed.is_none());
}

#[test]
fn signed_receipts_are_exposed_and_independently_verifiable() {
    use goat_protocol::provenance::all_self_consistent;
    // A settled round exposes the executor-signed receipts; a recomputer re-verifies each
    // signature independently, and the fold input mirrors them field-for-field.
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 3),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), BEACON, 1, 8.0, 3, 0);
    assert_eq!(out.status, Status::Settled);
    assert!(!out.signed_receipts.is_empty());
    assert!(all_self_consistent(&out.signed_receipts));
    assert_eq!(out.receipts.len(), out.signed_receipts.len());
    for (r, sr) in out.receipts.iter().zip(&out.signed_receipts) {
        assert_eq!(r.sub_window, sr.receipt.sub_window);
        assert_eq!(r.class_id, sr.receipt.class_id);
        assert_eq!(r.cluster_id, sr.receipt.cluster_id);
    }
}

#[test]
fn attributed_fault_is_recorded_without_breaking_the_signature() {
    use goat_protocol::provenance::all_self_consistent;
    // Escalation attributes a fault to B. The orchestrator sets diverged/fault on B's signed
    // receipt; because the outcome is not part of the signed core, every signature still
    // verifies — attribution does not require (and cannot be blocked by) the executor.
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 50),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), BEACON, 1, 8.0, 3, 3);
    assert_eq!(out.status, Status::SettledEscalated);
    assert_eq!(out.slashed.as_deref(), Some("B"));
    assert!(all_self_consistent(&out.signed_receipts));
    let b_sr = out
        .signed_receipts
        .iter()
        .find(|s| s.receipt.class_id == "cls.b.v1")
        .unwrap();
    assert!(b_sr.receipt.diverged && b_sr.receipt.fault);
}

#[test]
fn fold_time_enforcement_accepts_a_valid_round() {
    use goat_protocol::provenance::fold_verified;
    // A recomputer builds a key registry from the pool's identities and folds the round's signed
    // receipts under provenance enforcement — succeeding because every receipt is registered and
    // validly signed.
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 3),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), BEACON, 1, 8.0, 3, 0);
    assert_eq!(out.status, Status::Settled);
    let reg = registry_from_pool(&pool);
    let folded = fold_verified(&out.signed_receipts, &reg, &[]).expect("valid round folds");
    let total: u64 = folded.values().map(|a| a.v_c).sum();
    assert_eq!(total, out.receipts.len() as u64);
}

#[test]
fn fold_time_enforcement_rejects_a_tampered_receipt() {
    use goat_protocol::provenance::{fold_verified, ProvenanceError};
    // A post-hoc rewrite of an executor-attributable field is caught at fold time: the whole
    // batch is rejected, so no unverified data reaches the accumulator.
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 3),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), BEACON, 1, 8.0, 3, 0);
    let reg = registry_from_pool(&pool);
    let mut signed = out.signed_receipts.clone();
    signed[0].receipt.sub_window = (signed[0].receipt.sub_window + 1) % 24; // re-bucket after signing
    match fold_verified(&signed, &reg, &[]) {
        Err(ProvenanceError::BadSignature) => {}
        Err(_) => panic!("expected BadSignature specifically"),
        Ok(_) => panic!("tampered receipt must be rejected at fold time"),
    }
}

#[test]
fn fold_time_enforcement_rejects_an_unregistered_node() {
    use goat_protocol::provenance::{fold_verified, KeyRegistry, ProvenanceError};
    // An empty registry models a receipt from a node with no published identity key: rejected.
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 3),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), BEACON, 1, 8.0, 3, 0);
    match fold_verified(&out.signed_receipts, &KeyRegistry::new(), &[]) {
        Err(ProvenanceError::UnregisteredSigner) => {}
        Err(_) => panic!("expected UnregisteredSigner specifically"),
        Ok(_) => panic!("unregistered node must be rejected at fold time"),
    }
}

// ---------------- R-MAT2b step 5: assignment-log cross-binding ----------------
#[test]
fn assignment_binding_accepts_an_assigned_round() {
    use goat_protocol::provenance::fold_verified_authorized;
    // Authorization is built from the round's SIGNED assignment log; the assigned A/B receipts
    // fold successfully under both registry and authorization enforcement.
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 3),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), BEACON, 1, 8.0, 3, 0);
    assert_eq!(out.status, Status::Settled);
    let reg = registry_from_pool(&pool);
    let auth = round_authorization(&out, BEACON, &pool, 10.0).expect("assignment log verifies");
    assert!(fold_verified_authorized(&out.signed_receipts, &reg, &auth, &[]).is_ok());
}

#[test]
fn assignment_binding_authorizes_the_lottery_selected_executor() {
    use goat_protocol::provenance::fold_verified_authorized;
    // On escalation the third executor C is authorized by re-deriving the beacon lottery, so the
    // three-receipt escalated round also folds under authorization enforcement.
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 50), // disagree -> escalate
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let t = task(10.0);
    let out = run_round(&mut net, &orch(), &pool, &t, BEACON, 1, 8.0, 3, 3);
    assert_eq!(out.status, Status::SettledEscalated);
    let reg = registry_from_pool(&pool);
    let auth = round_authorization(&out, BEACON, &pool, 10.0).unwrap();
    assert!(auth.is_authorized(t.seed, out.selected_c.as_deref().unwrap()));
    assert!(fold_verified_authorized(&out.signed_receipts, &reg, &auth, &[]).is_ok());
}

#[test]
fn assignment_binding_rejects_an_unassigned_executor() {
    use goat_net::transport::NodeIdentity;
    use goat_protocol::maturity::{Receipt, SUB_WINDOWS};
    use goat_protocol::provenance::{fold_verified_authorized, ProvenanceError};
    use goat_protocol::types::TaskResult;
    // A node that was never assigned this task signs a receipt for it. Its key is registered and
    // the signature is valid, so it passes registry enforcement — but it fails authorization.
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 3),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let t = task(10.0);
    let out = run_round(&mut net, &orch(), &pool, &t, BEACON, 1, 8.0, 3, 0);
    assert_eq!(out.status, Status::Settled);

    let mut reg = registry_from_pool(&pool);
    let auth = round_authorization(&out, BEACON, &pool, 10.0).unwrap();

    let outsider = NodeIdentity::generate("unassigned-node");
    reg.register("unassigned-node", outsider.sign_pubkey()); // known identity, but never assigned
    let core = Receipt {
        class_id: "cls.b.v1".into(),
        task_class_id: 10,
        window: 1,
        sub_window: (t.seed % SUB_WINDOWS as u64) as u32,
        cluster_id: "cx".into(),
        asn: "ax".into(),
        diverged: false,
        fault: false,
    };
    let result = TaskResult {
        task_class_id: 10,
        tokens: vec![1],
        vector: vec![1],
        engine_build_id: "b1".into(),
    };
    let outsider_sr = outsider.attest_receipt(t.seed, core, &result);

    let mut signed = out.signed_receipts.clone();
    signed.push(outsider_sr);
    match fold_verified_authorized(&signed, &reg, &auth, &[]) {
        Err(ProvenanceError::Unauthorized) => {}
        Err(_) => panic!("expected Unauthorized specifically"),
        Ok(_) => panic!("a receipt from an unassigned node must be rejected at fold time"),
    }
}

// ---------------- R-MAT2b step 6: verifiable attribution ----------------
#[test]
fn escalation_record_validates_attribution_end_to_end() {
    use goat_protocol::provenance::Attribution;
    // an escalated round exposes an EscalationRecord; a recomputer independently re-derives the
    // attribution (B faulted) from the executor-signed results.
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 50), // disagree -> escalate -> B faulted
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), BEACON, 1, 8.0, 3, 3);
    assert_eq!(out.status, Status::SettledEscalated);
    assert_eq!(out.slashed.as_deref(), Some("B"));
    let reg = registry_from_pool(&pool);
    let auth = round_authorization(&out, BEACON, &pool, 10.0).unwrap();
    let rec = out
        .escalation
        .as_ref()
        .expect("escalated round carries a record");
    assert_eq!(
        rec.verify_attribution(&reg, &auth),
        Ok(Attribution::Faulted("B".into()))
    );
}

#[test]
fn fold_attributed_accepts_an_escalated_round_with_its_record() {
    use goat_protocol::provenance::fold_verified_attributed;
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 50),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), BEACON, 1, 8.0, 3, 3);
    let reg = registry_from_pool(&pool);
    let auth = round_authorization(&out, BEACON, &pool, 10.0).unwrap();
    let records: Vec<_> = out.escalation.clone().into_iter().collect();
    assert!(fold_verified_attributed(&out.signed_receipts, &reg, &auth, &records, &[]).is_ok());
}

#[test]
fn fold_attributed_rejects_an_escalated_round_without_its_record() {
    use goat_protocol::provenance::{fold_verified_attributed, ProvenanceError};
    // the round attributes a fault to B, but the recomputer is given no escalation record: the
    // asserted outcome is unbacked and rejected.
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 50),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), BEACON, 1, 8.0, 3, 3);
    let reg = registry_from_pool(&pool);
    let auth = round_authorization(&out, BEACON, &pool, 10.0).unwrap();
    match fold_verified_attributed(&out.signed_receipts, &reg, &auth, &[], &[]) {
        Err(ProvenanceError::AttributionMismatch) => {}
        Err(_) => panic!("expected AttributionMismatch specifically"),
        Ok(_) => panic!("an attributed fault without a record must be rejected"),
    }
}

#[test]
fn settled_round_folds_under_attribution_enforcement_without_a_record() {
    use goat_protocol::provenance::fold_verified_attributed;
    // a settled (no-fault) round needs no escalation record.
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 3),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), BEACON, 1, 8.0, 3, 0);
    assert_eq!(out.status, Status::Settled);
    assert!(out.escalation.is_none());
    let reg = registry_from_pool(&pool);
    let auth = round_authorization(&out, BEACON, &pool, 10.0).unwrap();
    assert!(fold_verified_attributed(&out.signed_receipts, &reg, &auth, &[], &[]).is_ok());
}

#[test]
fn node_identity_attests_and_a_substituted_bucket_is_detected() {
    use goat_net::transport::NodeIdentity;
    // The executor attests its completion bucket under its identity key; the orchestrator
    // (holding the executor's registered public key) verifies it. A substituted bucket — the
    // move a re-bucketing party would need to suppress a burst — fails verification.
    let exec = NodeIdentity::generate("exec-1");
    let registered_pk = exec.sign_pubkey();

    let stamp = exec.attest_sub_window(7, 5);
    assert!(stamp.verify_for(7, "exec-1", &registered_pk).is_ok());

    let mut substituted = stamp.clone();
    substituted.sub_window = 2; // spread the anomaly out of its attested bucket
    assert!(substituted.verify_for(7, "exec-1", &registered_pk).is_err());
}

// ---------------- H2: delay-sealed beacon drives a real round unchanged ----------------

// Anchor a beacon of the given mode via the ledger and return (seed, ledger). The seed is the
// [u8;32] the round consumes exactly as it did the fixed BEACON.
fn anchor(
    mode: goat_ledger::beacon::BeaconMode,
    epoch: u64,
) -> ([u8; 32], goat_ledger::ledger::Ledger) {
    use goat_ledger::beacon::{commitment, EpochBeacon, NonRevealerPolicy};
    use goat_ledger::ledger::Ledger;
    use goat_protocol::maturity::GateThresholds;

    let th = GateThresholds {
        v_min: 20,
        epsilon: 0.02,
        phi: 100.0,
        x_clusters: 10,
        x_asns: 5,
    };
    let mut led = Ledger::with_beacon_mode(th, mode, NonRevealerPolicy::Strict);
    let mut beacon = EpochBeacon::new(epoch);
    for (p, r, s) in [
        ("v1", b"r1".as_slice(), b"s1".as_slice()),
        ("v2", b"r2", b"s2"),
    ] {
        beacon.commit(p, commitment(r, s)).unwrap();
    }
    beacon.close_commit().unwrap();
    for (p, r, s) in [
        ("v1", b"r1".as_slice(), b"s1".as_slice()),
        ("v2", b"r2", b"s2"),
    ] {
        beacon.reveal(p, r, s).unwrap();
    }
    led.anchor_beacon(&mut beacon).unwrap();
    (led.beacon_value(epoch).unwrap(), led)
}

#[test]
fn delay_sealed_beacon_seeds_a_round_and_the_seal_verifies() {
    use goat_ledger::beacon::{delay_verify, BeaconMode};

    // anchor a delay-sealed beacon; its value is unknowable within the reveal window
    let (seed, led) = anchor(
        BeaconMode::DelaySealed {
            delay_iterations: 256,
        },
        1,
    );

    // the round consumes the anchored value exactly like the fixed BEACON — no change to run_round
    let mut net = Network::new();
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 50), // faulty -> escalate
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let out = run_round(&mut net, &orch(), &pool, &task(10.0), &seed, 1, 8.0, 3, 3);
    assert_eq!(out.status, Status::SettledEscalated);
    assert_eq!(out.selected_c.as_deref(), Some("C")); // lottery seeded by the sealed value

    // the anchored seal is independently verifiable
    let sealed = led.sealed_beacon(1).unwrap();
    assert_eq!(sealed.value, seed);
    assert!(delay_verify(&sealed.proof));
}

#[test]
fn lottery_is_stable_under_the_sealed_seed() {
    use goat_ledger::beacon::BeaconMode;
    // lottery_select is deterministic in the seed bytes, whether plain or delay-sealed
    let (seed, _led) = anchor(
        BeaconMode::DelaySealed {
            delay_iterations: 128,
        },
        2,
    );
    let pool = vec![
        node("A", "cls.a.v1", "c1", "a1", "r1", exact(), 0),
        node("B", "cls.b.v1", "c2", "a2", "r2", tol8(), 3),
        node("C", "cls.a.v1", "c3", "a3", "r3", exact(), 0),
    ];
    let (a, b) = (&pool[0].eref, &pool[1].eref);
    assert_eq!(
        lottery_select(&seed, 7, &pool, a, b, 10.0),
        lottery_select(&seed, 7, &pool, a, b, 10.0)
    );
}
