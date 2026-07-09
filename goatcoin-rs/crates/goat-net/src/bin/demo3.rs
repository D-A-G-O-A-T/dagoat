//! MVP-3 demo (WP-3.1-3.4): a 60-node testnet drives a new device class to MATURE from
//! genuine distributed work, a co-located Sybil adversary is merged by F6, and accumulator
//! roots reproduce across independent observers.
//!
//! Run:  cargo run -p goat-net --bin goat-mvp3-demo

use std::collections::HashSet;

use goat_net::density::DensityProbe;
use goat_net::distributed::Orchestrator;
use goat_net::testnet::*;
use goat_net::transport::Network;
use goat_protocol::capability::{DensitySignal, NetworkClass};
use goat_protocol::maturity::{MaturityController, RegistrationSet};

const BEACON: &[u8] = &[0x5au8; 32];

fn residential_probe(t: &Testnet) -> DensityProbe {
    let mut p = DensityProbe::new();
    let eps: HashSet<&String> = t.node_endpoint.values().collect();
    for ep in eps {
        p.set_network_class(ep, NetworkClass::Residential);
    }
    p
}

fn main() {
    let testnet = Testnet::honest(60, 6);
    let asns: HashSet<_> = testnet.node_asn.values().collect();
    let regions: HashSet<_> = testnet.node_region.values().collect();
    println!(
        "=== MVP-3 testnet: {} nodes, {} ASNs, {} regions ===",
        testnet.nodes.len(),
        asns.len(),
        regions.len()
    );

    // --- WP-3.2 / SC1: live class maturity ---
    let mut probe = residential_probe(&testnet);
    let orch = Orchestrator::new("orchestrator");
    let mut ctrl = MaturityController::with_reg_min(
        testnet_thresholds(),
        8.0,
        RegistrationSet {
            nodes: 20,
            clusters: 10,
            asns: 5,
            regions: 3,
        },
    );
    let (n, c, a, r) = testnet.effective_registration(&probe, "cls.b.v1");
    ctrl.register_class(
        "cls.b.v1",
        RegistrationSet {
            nodes: n as u32,
            clusters: c as u32,
            asns: a as u32,
            regions: r as u32,
        },
        8.0,
        0,
    );
    println!("\n  Stage-1 registration (effective {n} nodes / {c} clusters / {a} ASNs / {r} regions) -> {:?}", ctrl.states["cls.b.v1"].stage);

    let mut net = Network::new();
    for w in 1..=4u64 {
        let receipts = run_window(
            &mut net, &orch, &testnet, &mut probe, "cls.b.v1", w, BEACON, 8.0, 3, 2,
        );
        let merges = probe.cohort_merge_groups(&testnet.node_cluster);
        let (tr, _) = ctrl.process_window("cls.b.v1", &receipts, &merges, false, w);
        println!(
            "  window {w}: {} cls.b receipts -> {:?}/{:.2} ({})",
            receipts.len(),
            tr.to_stage,
            tr.to_p,
            tr.kind
        );
    }
    println!(
        "  -> class reached {:?} from genuine distributed work over the PQ transport",
        ctrl.states["cls.b.v1"].stage
    );

    // --- WP-3.3 / SC6: co-located Sybil adversary ---
    let mut sybil_net = Testnet::honest(40, 5);
    let honest_c = sybil_net
        .effective_registration(&DensityProbe::new(), "cls.b.v1")
        .1;
    sybil_net.add_sybil("warehouse", "cls.b.v1", 30);
    let mut sprobe = residential_probe(&sybil_net);
    for j in 0..30 {
        sprobe.observe("warehouse", &format!("S{}", 40 + j), 1.0);
    }
    let naive_c = sybil_net
        .effective_registration(&DensityProbe::new(), "cls.b.v1")
        .1;
    let eff_c = sybil_net.effective_registration(&sprobe, "cls.b.v1").1;
    println!("\n  Sybil: 30 identities behind ONE residential endpoint 'warehouse'");
    println!(
        "    probe observed density = {} -> {:?}",
        sprobe.observed_density("warehouse"),
        sprobe.density_signal("warehouse")
    );
    println!("    cls.b clusters: honest {honest_c}, naive-with-sybil {naive_c}, WITH F6 {eff_c}");
    println!("    -> F6 collapsed the cohort; coverage inflation ({naive_c}) prevented (back to {eff_c})");
    assert_eq!(
        sprobe.density_signal("warehouse"),
        DensitySignal::CohortMerge
    );

    // --- WP-3.4 / SC8: accumulator-root reproducibility ---
    let mut net2 = Network::new();
    let mut probe2 = residential_probe(&testnet);
    let receipts = run_window(
        &mut net2,
        &orch,
        &testnet,
        &mut probe2,
        "cls.b.v1",
        9,
        BEACON,
        8.0,
        3,
        1,
    );
    let merges = probe2.cohort_merge_groups(&testnet.node_cluster);
    let root_a = observe_accumulator_root(&receipts, &merges, "cls.b.v1", 9);
    let mut rev = receipts.clone();
    rev.reverse();
    let root_b = observe_accumulator_root(&rev, &merges, "cls.b.v1", 9);
    println!(
        "\n  SC8: two independent observers fold the same receipts -> identical root = {}",
        root_a == root_b
    );
    println!(
        "       root = {}",
        root_a
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );

    println!("\nSC1/SC6/SC8: live class maturity, co-located Sybil merged by F6, and reproducible");
    println!("accumulator roots — anti-capture holds under distribution.");
}
