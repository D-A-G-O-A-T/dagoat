//! MVP-3 full-testnet acceptance (WP-3.2/3.3/3.4): SC1 (live class maturity), SC6 (co-located
//! Sybil merged by F6), SC8 (accumulator-root reproducibility across independent observers), on
//! a >=30-node / >=10-ASN / >=5-region network.

use std::collections::HashSet;

use goat_net::density::DensityProbe;
use goat_net::distributed::Orchestrator;
use goat_net::testnet::*;
use goat_net::transport::Network;
use goat_protocol::capability::NetworkClass;
use goat_protocol::maturity::{MaturityController, RegistrationSet, Stage};

const BEACON: &[u8] = &[0x5au8; 32];

fn residential_probe(testnet: &Testnet) -> DensityProbe {
    let mut p = DensityProbe::new();
    let endpoints: HashSet<&String> = testnet.node_endpoint.values().collect();
    for ep in endpoints {
        p.set_network_class(ep, NetworkClass::Residential);
    }
    p
}

fn scaled_reg() -> RegistrationSet {
    RegistrationSet {
        nodes: 20,
        clusters: 10,
        asns: 5,
        regions: 3,
    }
}

// ---------------- SC1: live class maturity PROBATION -> RELAX -> MATURE ----------------
#[test]
fn sc1_live_class_maturity_to_mature() {
    let testnet = Testnet::honest(60, 6);
    let mut probe = residential_probe(&testnet);
    let orch = Orchestrator::new("orchestrator");
    let mut ctrl = MaturityController::with_reg_min(testnet_thresholds(), 8.0, scaled_reg());

    let (n, c, a, r) = testnet.effective_registration(&probe, "cls.b.v1");
    assert!(ctrl.register_class(
        "cls.b.v1",
        RegistrationSet {
            nodes: n as u32,
            clusters: c as u32,
            asns: a as u32,
            regions: r as u32
        },
        8.0,
        0
    ));
    assert_eq!(ctrl.states["cls.b.v1"].stage, Stage::Probation);

    let mut net = Network::new();
    let mut trail = Vec::new();
    for w in 1..=4u64 {
        let receipts = run_window(
            &mut net, &orch, &testnet, &mut probe, "cls.b.v1", w, BEACON, 8.0, 3, 2,
        );
        let merges = probe.cohort_merge_groups(&testnet.node_cluster);
        let (tr, _root) = ctrl.process_window("cls.b.v1", &receipts, &merges, false, w);
        trail.push((tr.to_stage, tr.gate_ok, receipts.len()));
    }
    assert_eq!(
        ctrl.states["cls.b.v1"].stage,
        Stage::Mature,
        "progression: {trail:?}"
    );
}

// ---------------- SC6: co-located Sybil merged, coverage inflation prevented ----------------
#[test]
fn sc6_colocated_sybil_merged_by_f6() {
    let mut testnet = Testnet::honest(40, 5);
    let honest_clusters = {
        let (_, c, _, _) = testnet.effective_registration(&DensityProbe::new(), "cls.b.v1");
        c
    };
    testnet.add_sybil("warehouse", "cls.b.v1", 30); // 30 identities, ONE fat residential endpoint

    let mut probe = residential_probe(&testnet);
    // passive probe observes each Sybil identity's work at the shared endpoint
    for j in 0..30 {
        probe.observe("warehouse", &format!("S{}", 40 + j), 1.0);
    }
    // F6 fires on observed density (30 > plausible 5)
    assert_eq!(
        probe.density_signal("warehouse"),
        goat_protocol::capability::DensitySignal::CohortMerge
    );

    // naive coverage (no F6): sybil inflates cls.b clusters by ~30
    let (_, c_naive, _, _) = testnet.effective_registration(&DensityProbe::new(), "cls.b.v1");
    // with F6: the 30 sybil clusters collapse to one -> no inflation
    let (_, c_eff, _, _) = testnet.effective_registration(&probe, "cls.b.v1");
    assert!(
        c_naive >= honest_clusters + 25,
        "naive should inflate: {c_naive}"
    );
    assert!(
        c_eff <= honest_clusters + 1,
        "F6 must collapse the cohort: {c_eff} vs honest {honest_clusters}"
    );
    assert!(c_naive > c_eff);
}

// ---------------- SC8: accumulator-root reproducibility across observers ----------------
#[test]
fn sc8_accumulator_roots_reproducible() {
    let testnet = Testnet::honest(30, 5);
    let mut probe = residential_probe(&testnet);
    let orch = Orchestrator::new("orchestrator");
    let mut net = Network::new();
    let receipts = run_window(
        &mut net, &orch, &testnet, &mut probe, "cls.b.v1", 1, BEACON, 8.0, 3, 1,
    );
    let merges = probe.cohort_merge_groups(&testnet.node_cluster);

    // observer 1: receipts as produced
    let root1 = observe_accumulator_root(&receipts, &merges, "cls.b.v1", 1);
    // observer 2: same published set, different order (no ordering guarantee on-wire)
    let mut shuffled = receipts.clone();
    shuffled.reverse();
    let root2 = observe_accumulator_root(&shuffled, &merges, "cls.b.v1", 1);
    assert_eq!(root1, root2); // HLL order-independent -> byte-identical roots (SC8)
    assert!(!receipts.is_empty());
}

// ---------------- WP-3.4: network scale (>=30 nodes / >=10 ASNs / >=5 regions) ----------------
#[test]
fn network_meets_scale_requirements() {
    let testnet = Testnet::honest(60, 6);
    assert!(testnet.nodes.len() >= 30);
    let asns: HashSet<_> = testnet.node_asn.values().collect();
    let regions: HashSet<_> = testnet.node_region.values().collect();
    assert!(asns.len() >= 10, "asns={}", asns.len());
    assert!(regions.len() >= 5, "regions={}", regions.len());
}
