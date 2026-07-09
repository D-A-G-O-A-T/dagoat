//! Verification Maturity Controller (device-agnostic). Spec B with amendments:
//! B-1 (slash coupling = 1/3), B-2 (directional fraud), B-3 (precise snap), B-5 (V_c
//! denominator). Coverage uses the deterministic HLL (R-MAT1) so accumulator roots
//! reproduce across recomputers. class_id/cluster_id/asn are opaque strings.
//!
//! R-MAT2 (recomputable burst snap): the anomaly-burst trigger is DERIVED from the published
//! receipts — each receipt carries an intra-window `sub_window` bucket, the fold tallies
//! anomalous receipts per bucket, and `anomaly_burst()` is a pure integer predicate over that
//! tally. Both the live controller and `verify_posting` recompute it identically, so a posting
//! that withholds a burst-mandated snap is detectable as an illegal (less-safe-than-legal)
//! transition. A declared snap remains possible but can only ADD conservatism.

use std::collections::HashMap;

use sha3::{Digest, Sha3_256};

use crate::capability::DensitySignal;
use crate::hll::Hll;
use crate::types::ClassId;

pub const P_FLOOR: f64 = 0.15;
pub const BASE_SLASH: f64 = 15.0;
pub const SLASH_CAP: f64 = 20.0;
const EPS: f64 = 1e-9;

pub const REG_MIN_NODES: u32 = 50;
pub const REG_MIN_CLUSTERS: u32 = 25;
pub const REG_MIN_ASNS: u32 = 10;
pub const REG_MIN_REGIONS: u32 = 5;

/// R-MAT2: number of intra-window buckets for the recomputable burst tally. A receipt's
/// `sub_window` stamp is folded mod this, so any u32 stamp is safe.
pub const SUB_WINDOWS: u32 = 24;
/// R-MAT2: minimum anomalous receipts in one sub-window before a burst can fire (absolute
/// floor so sparse noise never bursts).
pub const BURST_MIN_EVENTS: u64 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Candidate = 0,
    Probation = 1,
    Relax = 2,
    Mature = 3,
}

fn rank(s: Stage) -> i32 {
    s as i32
}

#[derive(Clone, Debug)]
pub struct Receipt {
    pub class_id: ClassId,
    pub task_class_id: u32,
    pub window: u64,
    /// Intra-window time bucket (R-MAT2). Folded mod SUB_WINDOWS; lets any recomputer
    /// reconstruct the temporal distribution of anomalies from published receipts.
    pub sub_window: u32,
    pub cluster_id: String,
    pub asn: String,
    pub diverged: bool,
    pub fault: bool,
}

pub struct ClassAccumulator {
    pub class_id: ClassId,
    pub window: u64,
    pub v_c: u64,
    pub d_num: u64,
    pub f_num: u64,
    /// Anomalous receipts (diverged or fault) per sub-window bucket (R-MAT2). Recomputable
    /// from published receipts and bound into `root()`.
    pub sub_events: [u64; SUB_WINDOWS as usize],
    pub cover_clusters_hll: Hll,
    pub cover_asns_hll: Hll,
}

impl ClassAccumulator {
    pub fn empty(class_id: ClassId, window: u64) -> Self {
        Self {
            class_id,
            window,
            v_c: 0,
            d_num: 0,
            f_num: 0,
            sub_events: [0; SUB_WINDOWS as usize],
            cover_clusters_hll: Hll::new(),
            cover_asns_hll: Hll::new(),
        }
    }
    pub fn cover_clusters(&self) -> u64 {
        self.cover_clusters_hll.count()
    }
    pub fn cover_asns(&self) -> u64 {
        self.cover_asns_hll.count()
    }
    pub fn divergence_rate(&self) -> f64 {
        if self.v_c == 0 {
            0.0
        } else {
            self.d_num as f64 / self.v_c as f64
        }
    }
    pub fn fault_rate_10k(&self) -> f64 {
        if self.v_c == 0 {
            0.0
        } else {
            self.f_num as f64 / self.v_c as f64 * 10_000.0
        }
    }
    /// Root over V/D/F, the per-sub-window anomaly tally (R-MAT2), and the HLL REGISTERS
    /// (deterministic) -> reproducible (R-MAT1). The root therefore commits to the TEMPORAL
    /// distribution of anomalies, not just their aggregate counts.
    pub fn root(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(b"GACC\x02");
        let b = self.class_id.as_bytes();
        o.extend_from_slice(&(b.len() as u32).to_be_bytes());
        o.extend_from_slice(b);
        for n in [self.window, self.v_c, self.d_num, self.f_num] {
            o.extend_from_slice(&n.to_be_bytes());
        }
        for n in self.sub_events {
            o.extend_from_slice(&n.to_be_bytes());
        }
        o.extend_from_slice(self.cover_clusters_hll.serialize());
        o.extend_from_slice(self.cover_asns_hll.serialize());
        let mut h = Sha3_256::new();
        h.update(&o);
        h.finalize().to_vec()
    }
}

fn cluster_representative(merge_groups: &[Vec<String>]) -> HashMap<String, String> {
    let mut rep = HashMap::new();
    for grp in merge_groups {
        if let Some(r) = grp.iter().min() {
            for c in grp {
                rep.insert(c.clone(), r.clone());
            }
        }
    }
    rep
}

/// Pure fold of published receipts. COHORT_MERGE groups (F6) collapse cluster ids to one
/// representative BEFORE coverage is counted, so overstated diversity cannot pass the gate.
pub fn fold_receipts(
    receipts: &[Receipt],
    merge_groups: &[Vec<String>],
) -> HashMap<(ClassId, u64), ClassAccumulator> {
    let rep = cluster_representative(merge_groups);
    let mut out: HashMap<(ClassId, u64), ClassAccumulator> = HashMap::new();
    for r in receipts {
        let key = (r.class_id.clone(), r.window);
        let acc = out
            .entry(key)
            .or_insert_with(|| ClassAccumulator::empty(r.class_id.clone(), r.window));
        acc.v_c += 1;
        if r.diverged {
            acc.d_num += 1;
        }
        if r.fault {
            acc.f_num += 1;
        }
        if r.diverged || r.fault {
            acc.sub_events[(r.sub_window % SUB_WINDOWS) as usize] += 1;
        }
        let cluster = rep.get(&r.cluster_id).unwrap_or(&r.cluster_id);
        acc.cover_clusters_hll.add(cluster.as_bytes());
        acc.cover_asns_hll.add(r.asn.as_bytes());
    }
    out
}

// ---- GATE ----
#[derive(Clone, Copy, Debug)]
pub struct GateThresholds {
    pub v_min: u64,
    pub epsilon: f64,
    pub phi: f64,
    pub x_clusters: u64,
    pub x_asns: u64,
}

pub fn gate(acc: &ClassAccumulator, th: &GateThresholds) -> (bool, Vec<(&'static str, bool)>) {
    let checks = vec![
        ("volume", acc.v_c >= th.v_min),
        ("divergence", acc.divergence_rate() < th.epsilon),
        ("faults", acc.fault_rate_10k() < th.phi),
        ("coverage_clusters", acc.cover_clusters() >= th.x_clusters),
        ("coverage_asns", acc.cover_asns() >= th.x_asns),
    ];
    (checks.iter().all(|&(_, v)| v), checks)
}

/// R-MAT2: recomputable anomaly-burst predicate, derived purely from the folded accumulator
/// (never from a declared flag). A burst is a concentration of anomalies in time: one
/// sub-window holds >= BURST_MIN_EVENTS anomalous receipts AND at least half of the window's
/// total. Catches an anomaly episode whose window-wide rates still pass the gate. Integer-only
/// and order-independent, so every recomputer reaches the identical verdict.
pub fn anomaly_burst(acc: &ClassAccumulator) -> bool {
    let total: u64 = acc.sub_events.iter().sum();
    let peak: u64 = acc.sub_events.iter().copied().max().unwrap_or(0);
    peak >= BURST_MIN_EVENTS && 2 * peak >= total
}

// ---- slash sizing (B-1: coupling = 1/3) ----
pub fn slash_multiple(tol_width: f64, tol_ref: f64) -> f64 {
    slash_multiple_cfg(tol_width, tol_ref, BASE_SLASH, SLASH_CAP, 1.0 / 3.0)
}

pub fn slash_multiple_cfg(tol_width: f64, tol_ref: f64, base: f64, cap: f64, coupling: f64) -> f64 {
    if tol_ref <= 0.0 {
        return base;
    }
    let raw = base * (1.0 + coupling * (tol_width / tol_ref));
    raw.clamp(base, cap)
}

pub fn fault_ev_margin(slash: f64, p_effective: f64) -> f64 {
    slash * p_effective
}

// ---- state machine (B-3) ----
#[derive(Clone, Copy, Debug)]
pub struct ClassState {
    pub stage: Stage,
    pub p_class: f64,
    pub last_transition_window: i64,
    pub slash_mult: f64,
    pub pioneer_armed: bool,
}

#[derive(Clone, Debug)]
pub struct Transition {
    pub class_id: ClassId,
    pub window: u64,
    pub from_stage: Stage,
    pub from_p: f64,
    pub to_stage: Stage,
    pub to_p: f64,
    pub kind: &'static str,
    pub gate_ok: bool,
    pub reasons: Vec<&'static str>,
}

fn snap(_stage: Stage, p: f64) -> (Stage, f64, &'static str) {
    let new_p = (p * 2.0).min(1.0);
    let new_stage = if new_p >= 1.0 - EPS {
        Stage::Probation
    } else {
        Stage::Relax
    };
    (new_stage, new_p, "snap")
}

/// Pure transition function — shared by the controller and the fraud verifier.
pub fn evaluate_transition(
    from_stage: Stage,
    from_p: f64,
    gate_ok: bool,
    force_snap: bool,
) -> (Stage, f64, &'static str) {
    if force_snap && matches!(from_stage, Stage::Relax | Stage::Mature) && from_p < 1.0 - EPS {
        return snap(from_stage, from_p);
    }
    match from_stage {
        Stage::Candidate => (Stage::Candidate, from_p, "hold"),
        Stage::Probation => {
            if gate_ok {
                (Stage::Relax, 0.5, "promote")
            } else {
                (Stage::Probation, 1.0, "hold")
            }
        }
        Stage::Relax => {
            if !gate_ok {
                snap(Stage::Relax, from_p)
            } else if from_p > P_FLOOR + EPS {
                (Stage::Relax, (from_p / 2.0).max(P_FLOOR), "relax")
            } else {
                (Stage::Mature, P_FLOOR, "mature")
            }
        }
        Stage::Mature => {
            if !gate_ok {
                snap(Stage::Mature, from_p)
            } else {
                (Stage::Mature, from_p, "hold")
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RegistrationSet {
    pub nodes: u32,
    pub clusters: u32,
    pub asns: u32,
    pub regions: u32,
}

impl RegistrationSet {
    /// Mainnet default thresholds (50/25/10/5).
    pub fn mainnet_min() -> Self {
        Self {
            nodes: REG_MIN_NODES,
            clusters: REG_MIN_CLUSTERS,
            asns: REG_MIN_ASNS,
            regions: REG_MIN_REGIONS,
        }
    }
    pub fn meets(&self, min: &RegistrationSet) -> bool {
        self.nodes >= min.nodes
            && self.clusters >= min.clusters
            && self.asns >= min.asns
            && self.regions >= min.regions
    }
    pub fn meets_diversity(&self) -> bool {
        self.meets(&RegistrationSet::mainnet_min())
    }
}

pub struct MaturityController {
    pub th: GateThresholds,
    pub tol_ref: f64,
    pub reg_min: RegistrationSet,
    pub states: HashMap<ClassId, ClassState>,
}

impl MaturityController {
    pub fn new(th: GateThresholds, tol_ref: f64) -> Self {
        Self {
            th,
            tol_ref,
            reg_min: RegistrationSet::mainnet_min(),
            states: HashMap::new(),
        }
    }

    /// Controller with scaled registration thresholds (e.g. for a small testnet).
    pub fn with_reg_min(th: GateThresholds, tol_ref: f64, reg_min: RegistrationSet) -> Self {
        Self {
            th,
            tol_ref,
            reg_min,
            states: HashMap::new(),
        }
    }

    pub fn register_class(
        &mut self,
        class_id: &str,
        reg: RegistrationSet,
        tol_width: f64,
        window: i64,
    ) -> bool {
        if !reg.meets(&self.reg_min) {
            self.states.insert(
                class_id.to_string(),
                ClassState {
                    stage: Stage::Candidate,
                    p_class: 1.0,
                    last_transition_window: window,
                    slash_mult: BASE_SLASH,
                    pioneer_armed: false,
                },
            );
            return false;
        }
        self.states.insert(
            class_id.to_string(),
            ClassState {
                stage: Stage::Probation,
                p_class: 1.0,
                last_transition_window: window,
                slash_mult: slash_multiple(tol_width, self.tol_ref),
                pioneer_armed: true,
            },
        );
        true
    }

    /// Process a window's receipts. The burst snap is RECOMPUTED from the receipts (R-MAT2);
    /// `declared_snap` can add a conservative extra snap but can never suppress the
    /// recomputable one.
    pub fn process_window(
        &mut self,
        class_id: &str,
        receipts: &[Receipt],
        merge_groups: &[Vec<String>],
        declared_snap: bool,
        window: u64,
    ) -> (Transition, Vec<u8>) {
        let st = *self.states.get(class_id).expect("class registered");
        let folded = fold_receipts(receipts, merge_groups);
        let empty;
        let acc = match folded.get(&(class_id.to_string(), window)) {
            Some(a) => a,
            None => {
                empty = ClassAccumulator::empty(class_id.to_string(), window);
                &empty
            }
        };
        let root = acc.root();
        let (gate_ok, checks) = gate(acc, &self.th);
        let force_snap = declared_snap || anomaly_burst(acc);
        let (to_stage, to_p, kind) = evaluate_transition(st.stage, st.p_class, gate_ok, force_snap);
        let reasons: Vec<&'static str> = checks
            .iter()
            .filter(|&&(_, v)| !v)
            .map(|&(k, _)| k)
            .collect();
        let tr = Transition {
            class_id: class_id.to_string(),
            window,
            from_stage: st.stage,
            from_p: st.p_class,
            to_stage,
            to_p,
            kind,
            gate_ok,
            reasons,
        };
        self.states.insert(
            class_id.to_string(),
            ClassState {
                stage: to_stage,
                p_class: to_p,
                last_transition_window: window as i64,
                slash_mult: st.slash_mult,
                pioneer_armed: st.pioneer_armed,
            },
        );
        (tr, root)
    }
}

/// Translate Item-2 COHORT_MERGE density signals into cluster merge groups.
pub fn cohort_merge_groups(
    signals: &HashMap<ClassId, DensitySignal>,
    endpoint_clusters: &HashMap<ClassId, Vec<String>>,
) -> Vec<Vec<String>> {
    let mut groups = Vec::new();
    for (key, sig) in signals {
        if *sig == DensitySignal::CohortMerge {
            if let Some(clusters) = endpoint_clusters.get(key) {
                groups.push(clusters.clone());
            }
        }
    }
    groups
}

// ---- fraud proof (B-2: directional) ----
#[derive(Clone, Debug)]
pub struct WindowPosting {
    pub class_id: ClassId,
    pub window: u64,
    pub accumulator_root: Vec<u8>,
    pub claimed_from_stage: Stage,
    pub claimed_from_p: f64,
    pub claimed_to_stage: Stage,
    pub claimed_to_p: f64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FraudProof {
    pub reason: &'static str,
    pub detail: String,
}

pub fn make_posting(tr: &Transition, root: Vec<u8>) -> WindowPosting {
    WindowPosting {
        class_id: tr.class_id.clone(),
        window: tr.window,
        accumulator_root: root,
        claimed_from_stage: tr.from_stage,
        claimed_from_p: tr.from_p,
        claimed_to_stage: tr.to_stage,
        claimed_to_p: tr.to_p,
    }
}

/// Recompute accumulators from published receipts and detect an illegal posting.
/// Fraud iff: root mismatch, wrong claimed prior, or a LESS SAFE claim than the
/// recomputable lower bound (lower sampling p, or more-advanced stage). Conservatism
/// (higher p / snap) is never fraudulent.
///
/// R-MAT2: the anomaly-burst snap is part of the recomputable lower bound. The verifier
/// derives the burst from the receipts (`anomaly_burst`) exactly as the controller does, so
/// a posting that withholds a burst-mandated snap is illegal and is reported with the
/// precise reason `withheld_burst_snap` when the claim matches the legal NON-burst
/// transition (i.e. the violation is explained entirely by the withheld snap).
pub fn verify_posting(
    posting: &WindowPosting,
    receipts: &[Receipt],
    prior: &ClassState,
    th: &GateThresholds,
    merge_groups: &[Vec<String>],
) -> Option<FraudProof> {
    let folded = fold_receipts(receipts, merge_groups);
    let empty;
    let acc = match folded.get(&(posting.class_id.clone(), posting.window)) {
        Some(a) => a,
        None => {
            empty = ClassAccumulator::empty(posting.class_id.clone(), posting.window);
            &empty
        }
    };
    let root = acc.root();
    let (gate_ok, _) = gate(acc, th);
    let burst = anomaly_burst(acc); // recomputed from receipts, never declared

    if root != posting.accumulator_root {
        return Some(FraudProof {
            reason: "root_mismatch",
            detail: "recomputed root != posted root".into(),
        });
    }
    if posting.claimed_from_stage != prior.stage
        || (posting.claimed_from_p - prior.p_class).abs() >= EPS
    {
        return Some(FraudProof {
            reason: "bad_prior",
            detail: format!(
                "claimed prior {:?}/{} != known {:?}/{}",
                posting.claimed_from_stage, posting.claimed_from_p, prior.stage, prior.p_class
            ),
        });
    }
    let (legal_stage, legal_p, _) = evaluate_transition(prior.stage, prior.p_class, gate_ok, burst);
    // A violation explained entirely by the recomputed burst (the claim IS the legal
    // non-burst transition or safer) gets the precise reason.
    let (base_stage, base_p, _) = evaluate_transition(prior.stage, prior.p_class, gate_ok, false);
    let withheld_snap =
        |cs: Stage, cp: f64| burst && cp >= base_p - EPS && rank(cs) <= rank(base_stage);
    if posting.claimed_to_p < legal_p - EPS {
        let reason = if withheld_snap(posting.claimed_to_stage, posting.claimed_to_p) {
            "withheld_burst_snap"
        } else {
            "undersampling"
        };
        return Some(FraudProof {
            reason,
            detail: format!(
                "claimed p={} < legal p={} (recomputed burst={})",
                posting.claimed_to_p, legal_p, burst
            ),
        });
    }
    if rank(posting.claimed_to_stage) > rank(legal_stage) {
        let reason = if withheld_snap(posting.claimed_to_stage, posting.claimed_to_p) {
            "withheld_burst_snap"
        } else {
            "over_advanced"
        };
        return Some(FraudProof {
            reason,
            detail: format!(
                "claimed {:?} more advanced than legal {:?} (recomputed burst={})",
                posting.claimed_to_stage, legal_stage, burst
            ),
        });
    }
    None
}
