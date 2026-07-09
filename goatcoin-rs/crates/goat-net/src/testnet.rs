//! Testnet driver (WP-3.2/3.3/3.4): compose the density probe (WP-3.1), the distributed
//! verification loop (MVP-2), and the maturity controller + ledger (MVP-1) into a live
//! network. Drives a new device class PROBATION -> RELAX -> MATURE from genuine distributed
//! work, handles a co-located Sybil adversary via F6, and keeps accumulator roots reproducible.
//! Device-agnostic throughout.

use std::collections::{HashMap, HashSet};

use sha3::{Digest, Sha3_256};

use goat_protocol::maturity::{ClassAccumulator, GateThresholds, Receipt};
use goat_protocol::types::{DeterminismProfile, Task, TaskResult};

use crate::density::DensityProbe;
use crate::distributed::{run_round, ExecutorNode, Orchestrator, RunFn};

/// Testnet gate thresholds, scaled to a small network (mainnet uses larger values that scale
/// with class size). Coverage thresholds stay meaningful at ~30-60 nodes.
pub fn testnet_thresholds() -> GateThresholds {
    GateThresholds {
        v_min: 20,
        epsilon: 0.02,
        phi: 100.0,
        x_clusters: 10,
        x_asns: 5,
    }
}

/// Deterministic reference compute + fixed offset (honest roundoff or deviation), for the demo/tests.
pub fn run(delta: i64) -> RunFn {
    Box::new(move |t: &Task| {
        let mut h = Sha3_256::new();
        h.update(&t.payload);
        h.update(t.seed.to_be_bytes());
        let d = h.finalize();
        let vector: Vec<i64> = (0..8).map(|i| d[i] as i64 + delta).collect();
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

/// A built testnet: nodes + the probe's node->endpoint and node->cluster maps.
pub struct Testnet {
    pub nodes: Vec<ExecutorNode>,
    pub node_endpoint: HashMap<String, String>,
    pub node_cluster: HashMap<String, String>,
    pub node_asn: HashMap<String, String>,
    pub node_region: HashMap<String, String>,
}

impl Testnet {
    /// n honest nodes, each on its own home endpoint (density ~1), interleaved classes, spread
    /// across distinct clusters/ASNs and `regions` regions.
    pub fn honest(n: usize, regions: usize) -> Self {
        let mut t = Testnet {
            nodes: Vec::new(),
            node_endpoint: HashMap::new(),
            node_cluster: HashMap::new(),
            node_asn: HashMap::new(),
            node_region: HashMap::new(),
        };
        for i in 0..n {
            let id = format!("N{i}");
            let (class, prof, delta) = if i % 2 == 0 {
                ("cls.a.v1", exact(), 0)
            } else {
                ("cls.b.v1", tol8(), 3)
            };
            let cluster = format!("c{i}");
            let asn = format!("a{i}");
            let region = format!("r{}", i % regions);
            let endpoint = format!("home-{i}"); // one home endpoint per node -> density ~1
            t.nodes.push(ExecutorNode::new(
                &id,
                class,
                &cluster,
                &asn,
                &region,
                prof,
                run(delta),
            ));
            t.node_endpoint.insert(id.clone(), endpoint);
            t.node_cluster.insert(id.clone(), cluster);
            t.node_asn.insert(id.clone(), asn);
            t.node_region.insert(id, region);
        }
        t
    }

    /// Inject `count` Sybil identities of `class` all behind ONE shared endpoint (a co-located
    /// adversary: many identities, one fat residential pipe). They claim distinct clusters.
    pub fn add_sybil(&mut self, endpoint: &str, class: &str, count: usize) {
        let base = self.nodes.len();
        for j in 0..count {
            let id = format!("S{}", base + j);
            let (prof, delta) = if class == "cls.a.v1" {
                (exact(), 0)
            } else {
                (tol8(), 3)
            };
            let cluster = format!("sc{}", base + j); // distinct declared clusters (the inflation attempt)
            let asn = format!("sa{}", base + j);
            let region = format!("sr{}", j % 3);
            self.nodes.push(ExecutorNode::new(
                &id,
                class,
                &cluster,
                &asn,
                &region,
                prof,
                run(delta),
            ));
            self.node_endpoint.insert(id.clone(), endpoint.to_string()); // ALL behind one endpoint
            self.node_cluster.insert(id.clone(), cluster);
            self.node_asn.insert(id.clone(), asn);
            self.node_region.insert(id, region);
        }
    }

    /// Effective registration diversity AFTER the probe's F6 merges collapse cohort endpoints.
    /// Honest nodes keep their distinct clusters; Sybil identities behind one endpoint collapse
    /// to a single cluster. This is what defeats registration gaming (R-MAT3).
    pub fn effective_registration(
        &self,
        probe: &DensityProbe,
        class_id: &str,
    ) -> (usize, usize, usize, usize) {
        let merges = probe.cohort_merge_groups(&self.node_cluster);
        let rep: HashMap<String, String> = merges
            .iter()
            .flat_map(|g| {
                let r = g.iter().min().cloned().unwrap();
                g.iter().map(move |c| (c.clone(), r.clone()))
            })
            .collect();
        let (mut clusters, mut asns, mut regions) =
            (HashSet::new(), HashSet::new(), HashSet::new());
        let mut nodes = 0usize;
        for n in self.nodes.iter().filter(|n| n.eref.class_id == class_id) {
            nodes += 1;
            let c = rep
                .get(&n.eref.cluster_id)
                .cloned()
                .unwrap_or_else(|| n.eref.cluster_id.clone());
            clusters.insert(c);
            asns.insert(n.eref.asn.clone());
            regions.insert(
                self.node_region
                    .get(&n.eref.node_id)
                    .cloned()
                    .unwrap_or_default(),
            );
        }
        (nodes, clusters.len(), asns.len(), regions.len())
    }
}

/// Independent-observer accumulator recomputation (SC8): fold receipts + merge_groups and
/// return the accumulator root. Any observer with the same published receipts + merges gets a
/// byte-identical root.
pub fn observe_accumulator_root(
    receipts: &[Receipt],
    merge_groups: &[Vec<String>],
    class_id: &str,
    window: u64,
) -> Vec<u8> {
    let folded = goat_protocol::maturity::fold_receipts(receipts, merge_groups);
    folded
        .get(&(class_id.to_string(), window))
        .map(|a| a.root())
        .unwrap_or_else(|| ClassAccumulator::empty(class_id.to_string(), window).root())
}

/// Run one window of genuine distributed work: many verification rounds over the PQ transport
/// across the node set, collecting receipts for `class_id` and observing per-endpoint work in
/// the probe. Returns the window's receipts.
#[allow(clippy::too_many_arguments)]
pub fn run_window(
    net: &mut crate::transport::Network,
    orch: &Orchestrator,
    testnet: &Testnet,
    probe: &mut DensityProbe,
    class_id: &str,
    window: u64,
    beacon: &[u8],
    tol_ref: f64,
    m: usize,
    passes: usize,
) -> Vec<Receipt> {
    let mut receipts = Vec::new();
    let n = testnet.nodes.len();
    for pass in 0..passes {
        let mut start = 0;
        while start + 3 <= n {
            let sub = &testnet.nodes[start..start + 3];
            let task = Task {
                task_class_id: 10,
                engine_build_id: "b1".into(),
                payload: b"work".to_vec(),
                seed: (window * 100_000 + pass as u64 * 1000 + start as u64),
                determinism_bound: 10.0,
            };
            let out = run_round(net, orch, sub, &task, beacon, 1, tol_ref, m, window);
            // probe observes work at each participating node's endpoint (passive)
            if let Some(log) = &out.log {
                for nid in &log.node_ids {
                    if let Some(ep) = testnet.node_endpoint.get(nid) {
                        probe.observe(ep, nid, 1.0);
                    }
                }
            }
            if let Some(cid) = &out.selected_c {
                if let Some(ep) = testnet.node_endpoint.get(cid) {
                    probe.observe(ep, cid, 1.0);
                }
            }
            receipts.extend(out.receipts.into_iter().filter(|r| r.class_id == class_id));
            start += 3;
        }
    }
    receipts
}
