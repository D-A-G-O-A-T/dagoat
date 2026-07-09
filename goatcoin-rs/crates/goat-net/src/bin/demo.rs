//! MVP-2 demo (WP-2.5): a ~10-node network runs distributed verification over the PQ
//! transport. Shows honest cross-class settlement, then a faulty submission escalated to a
//! beacon-lottery-selected disjoint executor, slashed, with divergence attributed — and the
//! signed assignment log verifiable by anyone.
//!
//! Run:  cargo run -p goat-net --bin goat-mvp2-demo

use goat_net::distributed::*;
use goat_net::transport::{Network, ML_KEM_768_CT_BYTES};
use goat_protocol::maturity::fold_receipts;
use goat_protocol::types::{DeterminismProfile, Task, TaskResult};
use sha3::{Digest, Sha3_256};

// A deterministic reference compute + offset (stands in for a real backend, honest or faulty).
fn run(delta: i64) -> RunFn {
    Box::new(move |t: &Task| {
        let mut h = Sha3_256::new();
        h.update(&t.payload);
        h.update(t.seed.to_be_bytes());
        let d = h.finalize();
        let vector: Vec<i64> = (0..8).map(|i| (d[i] as i64) + delta).collect();
        let tokens: Vec<u32> = (0..8).map(|i| d[i + 8] as u32).collect();
        TaskResult {
            task_class_id: t.task_class_id,
            tokens,
            vector,
            engine_build_id: t.engine_build_id.clone(),
        }
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

fn task() -> Task {
    Task {
        task_class_id: 10,
        engine_build_id: "b1".into(),
        payload: b"demo".to_vec(),
        seed: 7,
        determinism_bound: 10.0,
    }
}

fn build_pool(inject_fault: bool) -> Vec<ExecutorNode> {
    // 10 nodes across distinct clusters/ASNs/regions, two classes. Node B (index 1) submits a
    // fault when requested. Honest tolerance nodes carry a small (+3) roundoff within band 8.
    let mut pool = Vec::new();
    for i in 0..10 {
        let (cls, prof, delta) = if i % 2 == 0 {
            ("cls.a.v1", exact(), 0)
        } else {
            (
                "cls.b.v1",
                tol8(),
                if i == 1 && inject_fault { 50 } else { 3 },
            )
        };
        pool.push(node(
            &format!("N{i}"),
            cls,
            &format!("c{i}"),
            &format!("a{i}"),
            &format!("r{}", i % 5),
            prof,
            delta,
        ));
    }
    pool
}

fn main() {
    let beacon = [0x5au8; 32];
    let orch = Orchestrator::new("orchestrator");

    println!("=== MVP-2 distributed verification (10 nodes, PQ transport) ===");
    println!(
        "  transport: ML-KEM-768 handshake (ciphertext {ML_KEM_768_CT_BYTES} B) + AES-256-GCM,"
    );
    println!("             initiator authenticated with ML-DSA-65 (~3309 B signature)\n");

    // --- honest round ---
    let pool = build_pool(false);
    let mut net = Network::new();
    let out = run_round(&mut net, &orch, &pool, &task(), &beacon, 1, 8.0, 3, 0);
    println!("  honest round:");
    println!(
        "    assign: {:?} (signed log verifies = {})",
        out.log.as_ref().unwrap().node_ids,
        verify_assignment_log(out.log.as_ref().unwrap())
    );
    println!("    outcome: {:?} — {}", out.status, out.detail);

    // --- faulty-submission round ---
    let pool = build_pool(true);
    let mut net = Network::new();
    let out = run_round(&mut net, &orch, &pool, &task(), &beacon, 1, 8.0, 3, 5);
    println!("\n  faulty-submission round (node N1 posts a divergent result):");
    println!("    assign: {:?}", out.log.as_ref().unwrap().node_ids);
    println!(
        "    disagreement -> escalate; beacon-lottery selected C = {:?}",
        out.selected_c
    );
    println!("    outcome: {:?} — {}", out.status, out.detail);
    println!(
        "    winner={:?} slashed={:?} at {:?}x",
        out.winner,
        out.slashed,
        out.slash_mult.map(|x| x as u32)
    );
    let accs = fold_receipts(&out.receipts, &[]);
    for ((cid, w), acc) in accs.iter().collect::<std::collections::BTreeMap<_, _>>() {
        println!(
            "    accumulator[{cid}] window {w}: V_c={} D_num={} F_num={}",
            acc.v_c, acc.d_num, acc.f_num
        );
    }

    println!(
        "\nSC2/SC3/SC4/SC7/SC10: honest cross-class settlement, faulty-submission detection +"
    );
    println!("escalation + attribution, executor-set spread, and PQ-authenticated transport —");
    println!("all across nodes communicating only through the encrypted P2P layer.");
}
