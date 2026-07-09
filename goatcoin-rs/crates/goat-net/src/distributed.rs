//! Distributed verification: orchestrator + spread rule + signed logs (WP-2.2), executor
//! nodes across the transport (WP-2.3), beacon-seeded lottery C-selection (WP-2.4), and the
//! distributed round driver (WP-2.5). Reuses the goat-protocol verification predicates and
//! the goat-ledger receipts so distributed outcomes feed the same maturity/fraud machinery.
//!
//! Device-agnostic: class_id / cluster_id / asn are opaque strings; nothing branches on a
//! device type. Roles communicate ONLY through the PQ transport.

use sha3::{Digest, Sha3_256};

use goat_protocol::maturity::{slash_multiple, Receipt, SUB_WINDOWS};
use goat_protocol::pqsign::{verify, AlgId};
use goat_protocol::provenance::{
    AuthorizationSet, EscalationRecord, KeyRegistry, ProvenanceError, SignedReceipt,
};
use goat_protocol::types::Task;
use goat_protocol::verification::{
    agree, effective_profile, l_inf, ExecutorRef, Status, TOKEN_THRESHOLD,
};

use crate::codec::{decode_result, decode_task, encode_result, encode_task};
use crate::transport::{initiate, respond, Frame, Network, NodeIdentity};

pub type RunFn = Box<dyn Fn(&Task) -> goat_protocol::types::TaskResult>;

/// How an executor produces its `sub_window` attestation (R-MAT2b). `Honest` is the default;
/// the others model provenance faults used to validate orchestrator-level enforcement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AttestationMode {
    /// Sign the completion bucket correctly under the executor's identity key.
    #[default]
    Honest,
    /// Report a bucket different from the one signed (the stamp fails verification).
    Invalid,
    /// Omit the attestation entirely.
    Missing,
}

/// An executor node: its verification identity (opaque class/cluster/asn + determinism
/// profile), region, transport identity, a `run` closure wrapping its backend (honest or,
/// in tests, a faulty submitter), and its attestation behavior.
pub struct ExecutorNode {
    pub eref: ExecutorRef,
    pub region: String,
    pub ident: NodeIdentity,
    pub run: RunFn,
    pub attestation: AttestationMode,
}

impl ExecutorNode {
    pub fn new(
        node_id: &str,
        class_id: &str,
        cluster: &str,
        asn: &str,
        region: &str,
        profile: goat_protocol::types::DeterminismProfile,
        run: RunFn,
    ) -> Self {
        Self {
            eref: ExecutorRef {
                node_id: node_id.into(),
                class_id: class_id.into(),
                cluster_id: cluster.into(),
                asn: asn.into(),
                profile,
            },
            region: region.into(),
            ident: NodeIdentity::generate(node_id),
            run,
            attestation: AttestationMode::Honest,
        }
    }

    /// Builder: set a non-default attestation behavior (for provenance-enforcement tests).
    pub fn with_attestation(mut self, mode: AttestationMode) -> Self {
        self.attestation = mode;
        self
    }
}

/// Deliver an encrypted task to an executor over the PQ transport, have it execute, and return
/// the (encrypted-in-transit) result together with the executor's `SignedReceipt` (R-MAT2b step
/// 3). Exercises ML-KEM handshake + AES-GCM both ways.
///
/// The receipt core is built and signed AT THE EXECUTOR: it derives its intra-window
/// `sub_window` (deterministic in the MVP for reproducibility; a real completion time in
/// production), assembles the executor-attributable receipt (class/window/sub_window/cluster/asn)
/// with placeholder `diverged`/`fault`, and signs it plus a commitment to its output. The
/// orchestrator receives the signed receipt and can only honor it.
fn deliver(
    net: &mut Network,
    orch_ident: &NodeIdentity,
    exec: &ExecutorNode,
    task: &Task,
    window: u64,
) -> (goat_protocol::types::TaskResult, Option<SignedReceipt>) {
    let (hs, mut orch_chan) = initiate(orch_ident, &exec.ident.kem_public());
    let mut exec_chan = respond(&exec.ident, &hs).expect("handshake");

    let (ctr, sealed) = orch_chan.seal(&encode_task(task));
    net.send(Frame {
        from: orch_ident.node_id.clone(),
        to: exec.eref.node_id.clone(),
        ctr,
        ciphertext: sealed,
    });

    let inbound = net.drain(&exec.eref.node_id);
    let f = &inbound[0];
    let task_bytes = exec_chan.open(f.ctr, &f.ciphertext).expect("open task");
    let task = decode_task(&task_bytes);
    let result = (exec.run)(&task);

    // executor-side: assemble and sign the executor-attributable receipt core
    let sub_window = (task.seed % SUB_WINDOWS as u64) as u32;
    let core = Receipt {
        class_id: exec.eref.class_id.clone(),
        task_class_id: task.task_class_id,
        window,
        sub_window,
        cluster_id: exec.eref.cluster_id.clone(),
        asn: exec.eref.asn.clone(),
        diverged: false, // placeholder; the orchestrator attaches the verification outcome
        fault: false,
    };
    let signed = match exec.attestation {
        AttestationMode::Honest => Some(exec.ident.attest_receipt(task.seed, core, &result)),
        AttestationMode::Invalid => {
            // report an attributable field different from the one signed -> fails verification
            let mut sr = exec.ident.attest_receipt(task.seed, core, &result);
            sr.receipt.sub_window = (sub_window + 1) % SUB_WINDOWS;
            Some(sr)
        }
        AttestationMode::Missing => None,
    };

    let (ctr2, sealed2) = exec_chan.seal(&encode_result(&result));
    net.send(Frame {
        from: exec.eref.node_id.clone(),
        to: orch_ident.node_id.clone(),
        ctr: ctr2,
        ciphertext: sealed2,
    });

    let back = net.drain(&orch_ident.node_id);
    let rb = orch_chan
        .open(back[0].ctr, &back[0].ciphertext)
        .expect("open result");
    (decode_result(&rb), signed)
}

/// Orchestrator-side enforcement (R-MAT2b): return the verified `SignedReceipt`, or an error if
/// it is missing or fails verification against the executor's registered identity key. A verified
/// signed receipt is the ONLY source of receipt fields the orchestrator uses — it cannot
/// substitute or synthesize any executor-attributable field (class/window/sub_window/cluster/asn).
fn verify_delivered(
    signed: Option<SignedReceipt>,
    task_id: u64,
    exec: &ExecutorNode,
) -> Result<SignedReceipt, ProvenanceError> {
    let sr = signed.ok_or(ProvenanceError::MissingStamp)?;
    sr.verify_for(task_id, &exec.eref.node_id, &exec.ident.sign_pubkey())?;
    Ok(sr)
}

/// Attach the orchestrator's verification outcome to an executor-signed receipt. `diverged`/`fault`
/// are not part of the signed core (see `receipt_core_message`), so this does not invalidate the
/// signature — it records attribution the executor cannot itself produce.
fn with_outcome(mut sr: SignedReceipt, diverged: bool, fault: bool) -> SignedReceipt {
    sr.receipt.diverged = diverged;
    sr.receipt.fault = fault;
    sr
}

/// Build a node→identity-key registry from a pool's executor identities, for fold-time provenance
/// enforcement (`goat_protocol::provenance::fold_verified`). A recomputer would build the same map
/// from the network's published identities.
pub fn registry_from_pool(pool: &[ExecutorNode]) -> KeyRegistry {
    let mut reg = KeyRegistry::new();
    for n in pool {
        reg.register(&n.eref.node_id, n.ident.sign_pubkey());
    }
    reg
}

/// Build the authorization set for a round (R-MAT2b step 5): which nodes were assigned its task.
/// Two sources, both verifiable by a recomputer. First, the orchestrator's SIGNED assignment log
/// (its ML-DSA signature is checked here) authorizes the primary pair A and B. Second, if the
/// round escalated, the escalation executor C is authorized by re-deriving the beacon lottery from
/// `beacon`, so C's authorization is confirmed rather than taken on trust.
/// Returns None if the round has no assignment log or its signature does not verify.
pub fn round_authorization(
    out: &RoundOutcome,
    beacon: &[u8],
    pool: &[ExecutorNode],
    task_bound: f64,
) -> Option<AuthorizationSet> {
    let log = out.log.as_ref()?;
    if !verify_assignment_log(log) {
        return None;
    }
    let tid = log.task_id;
    let mut auth = AuthorizationSet::new();
    for nid in &log.node_ids {
        auth.authorize(tid, nid);
    }
    // escalation executor: authorized by the verifiable beacon lottery, re-derived to confirm the
    // orchestrator's selection rather than trusting `selected_c`.
    if out.selected_c.is_some() && log.node_ids.len() >= 2 {
        let a = pool.iter().find(|n| n.eref.node_id == log.node_ids[0]);
        let b = pool.iter().find(|n| n.eref.node_id == log.node_ids[1]);
        if let (Some(a), Some(b)) = (a, b) {
            if let Some(ci) = lottery_select(beacon, tid, pool, &a.eref, &b.eref, task_bound) {
                auth.authorize(tid, &pool[ci].eref.node_id);
            }
        }
    }
    Some(auth)
}

// ---- orchestrator + spread rule + signed logs (WP-2.2) ----
pub struct Orchestrator {
    pub ident: NodeIdentity,
}

#[derive(Clone, Debug)]
pub struct AssignmentLog {
    pub task_id: u64,
    pub node_ids: Vec<String>,
    pub beacon_epoch: u64,
    pub signature: Vec<u8>,
    pub signer_pk: Vec<u8>,
}

fn distinct<'a>(it: impl Iterator<Item = &'a String>) -> usize {
    let mut s: Vec<&String> = it.collect();
    s.sort();
    s.dedup();
    s.len()
}

impl Orchestrator {
    pub fn new(node_id: &str) -> Self {
        Self {
            ident: NodeIdentity::generate(node_id),
        }
    }

    fn log_message(task_id: u64, node_ids: &[String], beacon_epoch: u64) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&task_id.to_be_bytes());
        for id in node_ids {
            m.extend_from_slice(&(id.len() as u32).to_be_bytes());
            m.extend_from_slice(id.as_bytes());
        }
        m.extend_from_slice(&beacon_epoch.to_be_bytes());
        m
    }

    /// Assign a primary A and verifier B such that they are cross-class-pairable under the
    /// task bound and on DISTINCT clusters and ASNs, and the pool provides >= m distinct
    /// clusters AND ASNs overall (escalation-liveness headroom, C-4). Returns indices + a
    /// signed assignment log, or None if spread cannot be satisfied.
    pub fn assign(
        &self,
        pool: &[ExecutorNode],
        task: &Task,
        beacon_epoch: u64,
        m: usize,
    ) -> Option<(usize, usize, AssignmentLog)> {
        if distinct(pool.iter().map(|n| &n.eref.cluster_id)) < m
            || distinct(pool.iter().map(|n| &n.eref.asn)) < m
        {
            return None; // insufficient spread headroom
        }
        for a in 0..pool.len() {
            for b in 0..pool.len() {
                if a == b {
                    continue;
                }
                let (na, nb) = (&pool[a], &pool[b]);
                if na.eref.cluster_id == nb.eref.cluster_id || na.eref.asn == nb.eref.asn {
                    continue;
                }
                let same_class = na.eref.class_id == nb.eref.class_id;
                if effective_profile(
                    &na.eref.profile,
                    &nb.eref.profile,
                    same_class,
                    task.determinism_bound,
                )
                .is_none()
                {
                    continue;
                }
                let node_ids = vec![na.eref.node_id.clone(), nb.eref.node_id.clone()];
                let sig = self.ident_sign(task.seed, &node_ids, beacon_epoch);
                let log = AssignmentLog {
                    task_id: task.seed,
                    node_ids,
                    beacon_epoch,
                    signature: sig,
                    signer_pk: self.ident_pk(),
                };
                return Some((a, b, log));
            }
        }
        None
    }

    fn ident_sign(&self, task_id: u64, node_ids: &[String], beacon_epoch: u64) -> Vec<u8> {
        self.ident
            .sign_msg(&Self::log_message(task_id, node_ids, beacon_epoch))
    }
    fn ident_pk(&self) -> Vec<u8> {
        self.ident.sign_pubkey()
    }
}

/// Verify an assignment log against the orchestrator's public key (public auditability).
pub fn verify_assignment_log(log: &AssignmentLog) -> bool {
    let msg = Orchestrator::log_message(log.task_id, &log.node_ids, log.beacon_epoch);
    verify(AlgId::MlDsa65, &log.signer_pk, &msg, &log.signature)
}

// ---- beacon-seeded lottery C-selection (WP-2.4) ----
/// Deterministically select the escalation executor C from the pool: cluster- AND ASN-disjoint
/// from A and B, pairable with both under the task bound, ranked by H(beacon || task_id ||
/// node_id) and lowest wins. Verifiable — anyone recomputes it from the beacon. Returns the
/// pool index, or None if no eligible C exists.
pub fn lottery_select(
    beacon: &[u8],
    task_id: u64,
    pool: &[ExecutorNode],
    a: &ExecutorRef,
    b: &ExecutorRef,
    task_bound: f64,
) -> Option<usize> {
    let mut best: Option<(Vec<u8>, usize)> = None;
    for (i, n) in pool.iter().enumerate() {
        let c = &n.eref;
        if c.cluster_id == a.cluster_id
            || c.cluster_id == b.cluster_id
            || c.asn == a.asn
            || c.asn == b.asn
        {
            continue;
        }
        if effective_profile(&c.profile, &a.profile, c.class_id == a.class_id, task_bound).is_none()
        {
            continue;
        }
        if effective_profile(&c.profile, &b.profile, c.class_id == b.class_id, task_bound).is_none()
        {
            continue;
        }
        let mut h = Sha3_256::new();
        h.update(beacon);
        h.update(task_id.to_be_bytes());
        h.update(c.node_id.as_bytes());
        let rank = h.finalize().to_vec();
        if best.as_ref().map(|(r, _)| &rank < r).unwrap_or(true) {
            best = Some((rank, i));
        }
    }
    best.map(|(_, i)| i)
}

// ---- distributed round (WP-2.5) ----
/// Per-round telemetry for the WP-3.5 live-stats collector. Present once A/B have executed.
#[derive(Clone, Debug, Default)]
pub struct RoundTelemetry {
    pub class_a: String,
    pub class_b: String,
    pub l_inf_ab: f64, // numeric divergence between the primary pair
    pub escalated: bool,
    pub l_inf_ca: f64,            // C-vs-A divergence (escalation only)
    pub l_inf_cb: f64,            // C-vs-B divergence (escalation only)
    pub disjoint_pairable: usize, // eligible C candidates in the pool (pool composition)
    pub profile_remeasure: bool,
}

#[derive(Clone, Debug)]
pub struct RoundOutcome {
    pub status: Status,
    pub winner: Option<String>,
    pub slashed: Option<String>,
    pub slash_mult: Option<f64>,
    pub selected_c: Option<String>,
    pub receipts: Vec<Receipt>,
    /// The executor-signed receipts backing `receipts` (R-MAT2b): a recomputer can re-verify each
    /// signature independently. `receipts[i] == signed_receipts[i].receipt`.
    pub signed_receipts: Vec<SignedReceipt>,
    /// The verifiable escalation record for an escalated round (R-MAT2b step 6): lets a recomputer
    /// re-derive and validate the `diverged`/`fault` attribution. `None` for settled/quarantined
    /// rounds (no attribution to prove).
    pub escalation: Option<EscalationRecord>,
    pub profile_remeasure: bool,
    pub log: Option<AssignmentLog>,
    pub detail: &'static str,
    pub telemetry: Option<RoundTelemetry>,
}

/// Count pool members eligible as an escalation C for the (a, b) pair (cluster/ASN-disjoint and
/// pairable with both under the task bound). Feeds the collector's pool-composition stats.
pub fn count_disjoint_pairable(
    pool: &[ExecutorNode],
    a: &ExecutorRef,
    b: &ExecutorRef,
    task_bound: f64,
) -> usize {
    pool.iter()
        .filter(|n| {
            let c = &n.eref;
            c.cluster_id != a.cluster_id
                && c.cluster_id != b.cluster_id
                && c.asn != a.asn
                && c.asn != b.asn
                && effective_profile(&c.profile, &a.profile, c.class_id == a.class_id, task_bound)
                    .is_some()
                && effective_profile(&c.profile, &b.profile, c.class_id == b.class_id, task_bound)
                    .is_some()
        })
        .count()
}

/// Run one distributed verification round over the transport: assign (spread), deliver the
/// encrypted task to A and B, compare under the effective profile, and on disagreement
/// escalate to a beacon-lottery-selected disjoint C. Mirrors the goat-protocol escalation
/// state machine (all four outcomes) but with lottery selection and PQ-transport delivery.
#[allow(clippy::too_many_arguments)]
pub fn run_round(
    net: &mut Network,
    orch: &Orchestrator,
    pool: &[ExecutorNode],
    task: &Task,
    beacon: &[u8],
    beacon_epoch: u64,
    tol_ref: f64,
    m: usize,
    window: u64,
) -> RoundOutcome {
    let none = |status, detail| RoundOutcome {
        status,
        winner: None,
        slashed: None,
        slash_mult: None,
        selected_c: None,
        receipts: vec![],
        signed_receipts: vec![],
        escalation: None,
        profile_remeasure: false,
        log: None,
        detail,
        telemetry: None,
    };

    let (ai, bi, log) = match orch.assign(pool, task, beacon_epoch, m) {
        Some(x) => x,
        None => return none(Status::Quarantined, "spread rule unsatisfiable"),
    };
    let (a, b) = (&pool[ai], &pool[bi]);
    let same_class = a.eref.class_id == b.eref.class_id;
    let prof_ab = match effective_profile(
        &a.eref.profile,
        &b.eref.profile,
        same_class,
        task.determinism_bound,
    ) {
        Some(p) => p,
        None => {
            return none(
                Status::IneligibleCrossClass,
                "widened band exceeds task bound",
            )
        }
    };

    let (ra, signed_a) = deliver(net, &orch.ident, a, task, window);
    let (rb, signed_b) = deliver(net, &orch.ident, b, task, window);
    // R-MAT2b enforcement: each receipt MUST be a verified executor SignedReceipt. A missing or
    // invalid signature quarantines the submission — the orchestrator never synthesizes or
    // rewrites an executor-attributable field, so it cannot suppress a burst by re-bucketing.
    let sr_a = match verify_delivered(signed_a, task.seed, a) {
        Ok(x) => x,
        Err(_) => {
            return none(
                Status::Quarantined,
                "executor A signed receipt missing or invalid",
            )
        }
    };
    let sr_b = match verify_delivered(signed_b, task.seed, b) {
        Ok(x) => x,
        Err(_) => {
            return none(
                Status::Quarantined,
                "executor B signed receipt missing or invalid",
            )
        }
    };

    let mut tele = RoundTelemetry {
        class_a: a.eref.class_id.clone(),
        class_b: b.eref.class_id.clone(),
        l_inf_ab: l_inf(&ra.vector, &rb.vector),
        disjoint_pairable: count_disjoint_pairable(pool, &a.eref, &b.eref, task.determinism_bound),
        ..Default::default()
    };

    // decision variables, filled by the branches below, then one RoundOutcome is built.
    let mut status = Status::Settled;
    let mut winner = None;
    let mut slashed = None;
    let mut slash_mult = None;
    let mut selected_c = None;
    let mut signed_receipts: Vec<SignedReceipt> = vec![];
    let mut escalation: Option<EscalationRecord> = None;
    let mut profile_remeasure = false;
    let mut detail = "agree";

    if agree(&ra, &rb, &prof_ab, TOKEN_THRESHOLD) {
        winner = Some(a.eref.node_id.clone());
        signed_receipts = vec![
            with_outcome(sr_a, false, false),
            with_outcome(sr_b, false, false),
        ];
    } else {
        tele.escalated = true;
        // escalate: beacon-lottery-selected disjoint + pairable C
        match lottery_select(
            beacon,
            task.seed,
            pool,
            &a.eref,
            &b.eref,
            task.determinism_bound,
        ) {
            None => {
                status = Status::Quarantined;
                profile_remeasure = true;
                detail = "no disjoint pairable C";
            }
            Some(ci) => {
                let c = &pool[ci];
                let (rc, signed_c) = deliver(net, &orch.ident, c, task, window);
                selected_c = Some(c.eref.node_id.clone());
                // enforcement extends to the escalation executor: an unattested/invalid C receipt
                // quarantines rather than resolving on an orchestrator-supplied value.
                match verify_delivered(signed_c, task.seed, c) {
                    Err(_) => {
                        status = Status::Quarantined;
                        profile_remeasure = true;
                        detail = "executor C signed receipt missing or invalid";
                    }
                    Ok(sr_c) => {
                        let prof_ca = effective_profile(
                            &c.eref.profile,
                            &a.eref.profile,
                            c.eref.class_id == a.eref.class_id,
                            task.determinism_bound,
                        )
                        .unwrap();
                        let prof_cb = effective_profile(
                            &c.eref.profile,
                            &b.eref.profile,
                            c.eref.class_id == b.eref.class_id,
                            task.determinism_bound,
                        )
                        .unwrap();
                        let ca = agree(&rc, &ra, &prof_ca, TOKEN_THRESHOLD);
                        let cb = agree(&rc, &rb, &prof_cb, TOKEN_THRESHOLD);
                        tele.l_inf_ca = l_inf(&rc.vector, &ra.vector);
                        tele.l_inf_cb = l_inf(&rc.vector, &rb.vector);
                        if !ca && !cb {
                            status = Status::Quarantined;
                            profile_remeasure = true;
                            detail = "3-way split";
                        } else {
                            // one of the three SettledEscalated outcomes; attach outcomes per role
                            status = Status::SettledEscalated;
                            let (a_out, b_out) = if ca && cb {
                                winner = Some(a.eref.node_id.clone());
                                profile_remeasure = true;
                                detail = "C within band of both; no attribution";
                                ((false, false), (false, false))
                            } else if ca {
                                winner = Some(a.eref.node_id.clone());
                                slashed = Some(b.eref.node_id.clone());
                                slash_mult = Some(slash_multiple(b.eref.profile.bound, tol_ref));
                                detail = "C agrees with A; B faulted";
                                ((false, false), (true, true))
                            } else {
                                winner = Some(b.eref.node_id.clone());
                                slashed = Some(a.eref.node_id.clone());
                                slash_mult = Some(slash_multiple(a.eref.profile.bound, tol_ref));
                                detail = "C agrees with B; A faulted";
                                ((true, true), (false, false))
                            };
                            let osr_a = with_outcome(sr_a, a_out.0, a_out.1);
                            let osr_b = with_outcome(sr_b, b_out.0, b_out.1);
                            let osr_c = with_outcome(sr_c, false, false);
                            // the verifiable attribution record: signed receipts + raw results
                            // (each bound to its receipt via result_commit) + comparison profiles.
                            escalation = Some(EscalationRecord {
                                task_id: task.seed,
                                a: osr_a.clone(),
                                b: osr_b.clone(),
                                c: osr_c.clone(),
                                result_a: ra.clone(),
                                result_b: rb.clone(),
                                result_c: rc.clone(),
                                prof_ca,
                                prof_cb,
                                token_threshold: TOKEN_THRESHOLD,
                            });
                            signed_receipts = vec![osr_a, osr_b, osr_c];
                        }
                    }
                }
            }
        }
    }

    tele.profile_remeasure = profile_remeasure;
    // The fold input mirrors the signed receipts exactly: receipts[i] == signed_receipts[i].receipt.
    let receipts: Vec<Receipt> = signed_receipts.iter().map(|s| s.receipt.clone()).collect();
    RoundOutcome {
        status,
        winner,
        slashed,
        slash_mult,
        selected_c,
        receipts,
        signed_receipts,
        escalation,
        profile_remeasure,
        log: Some(log),
        detail,
        telemetry: Some(tele),
    }
}
