//! Receipt-stamp provenance (H1 / R-MAT2b, step 1). Device-agnostic.
//!
//! Background. R-MAT2 made the anomaly-burst snap accumulator-derived: each receipt carries an
//! intra-window `sub_window` bucket, the accumulator tallies anomalies per bucket, and both the
//! maturity controller and `verify_posting` recompute the burst identically. That closed the
//! *recomputability* gap, but left a residual trust assumption: in the MVP the `sub_window` is
//! stamped by the orchestrator when it publishes receipts. A party controlling the orchestrator
//! could therefore spread a genuine concentration of anomalies across buckets to suppress a
//! burst — the accumulator root makes such a rewrite *detectable after the fact*, but nothing
//! yet ties the bucket to the executor that actually performed the work.
//!
//! This module is the first step toward closing that: an executor produces a **signed
//! attestation** of the `sub_window` it completed the work in, so the bucket originates at the
//! source. An orchestrator can no longer choose the bucket unilaterally — it can only honor the
//! executor's signed value, and any substitution is a signature mismatch that any recomputer
//! detects.
//!
//! Scope of THIS step (deliberately narrow): attest and verify the `sub_window` value alone,
//! bound to `(task_id, node_id)`. Full R-MAT2b — signing the whole receipt (class, window,
//! diverged/fault, cluster, asn) and cross-binding it to the signed assignment log — is the
//! follow-on increment (see the module tests and the H1 roadmap item). Backward compatibility is
//! preserved: `Receipt.sub_window` is unchanged, so the fold, the burst predicate, and the
//! fraud proof all keep working on the same field; attestation is an additional, optional
//! verification layer over the value's origin.
//!
//! MVP note on the value itself: the reference executors derive the completion bucket
//! deterministically (`task.seed % SUB_WINDOWS`) so tests stay reproducible. The *mechanism*
//! built here is production-shaped — in production the bucket is the executor's real
//! completion-time sub-window, which is not derivable from the task, and the attestation is what
//! makes it trustworthy.
//!
//! Device-agnostic: nothing here names a device type or inspects content. `node_id` and the keys
//! are opaque identity, not hardware.

use std::collections::{HashMap, HashSet};

use crate::commit::commit;
use crate::maturity::{fold_receipts, ClassAccumulator, Receipt};
use crate::pqsign::{verify, AlgId, Signer};
use crate::types::{ClassId, DeterminismProfile, TaskResult};
use crate::verification::agree;

/// Domain separator for the attestation message (prevents cross-protocol signature reuse).
const STAMP_DOMAIN: &[u8] = b"GOAT/subwindow-attestation/v1";

#[derive(Debug, PartialEq, Eq)]
pub enum ProvenanceError {
    /// No stamp was supplied where an executor attestation is required.
    MissingStamp,
    /// The stamp's signature does not verify against its embedded public key.
    BadSignature,
    /// The stamp verifies, but its signer public key is not the executor's registered key.
    UnregisteredSigner,
    /// The stamp attests a different `(task_id, node_id)` than the receipt context expects.
    ContextMismatch,
    /// The signer is registered and the signature is valid, but the node was not authorized
    /// (assigned) to this task by the signed assignment log for the epoch.
    Unauthorized,
    /// A result carried in an escalation record does not match the `result_commit` its executor
    /// signed — the results were substituted.
    ResultCommitMismatch,
    /// The attributed `diverged`/`fault` outcome is not what the escalation record's re-derived
    /// agreement decision produces (an outcome asserted without, or inconsistent with, a proof).
    AttributionMismatch,
}

/// An executor's signed attestation that it completed task `task_id` in intra-window bucket
/// `sub_window`. Self-verifiable: it carries the signer public key, and `verify()` recomputes the
/// canonical message and checks the ML-DSA signature. `verify_for` additionally binds the signer
/// to a registered executor key so an orchestrator cannot forge a stamp with its own key.
#[derive(Clone, Debug)]
pub struct SubWindowStamp {
    pub task_id: u64,
    pub node_id: String,
    pub sub_window: u32,
    pub signer_pk: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Canonical, length-prefixed attestation message. Deterministic across recomputers.
pub fn sub_window_message(task_id: u64, node_id: &str, sub_window: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(STAMP_DOMAIN.len() + 8 + 4 + node_id.len() + 4);
    m.extend_from_slice(STAMP_DOMAIN);
    m.extend_from_slice(&task_id.to_be_bytes());
    m.extend_from_slice(&(node_id.len() as u32).to_be_bytes());
    m.extend_from_slice(node_id.as_bytes());
    m.extend_from_slice(&sub_window.to_be_bytes());
    m
}

/// Executor side: sign the completion bucket for a task. `signer` is the executor's identity key.
pub fn attest_sub_window(
    signer: &dyn Signer,
    task_id: u64,
    node_id: &str,
    sub_window: u32,
) -> SubWindowStamp {
    let msg = sub_window_message(task_id, node_id, sub_window);
    SubWindowStamp {
        task_id,
        node_id: node_id.to_string(),
        sub_window,
        signer_pk: signer.public_key(),
        signature: signer.sign(&msg),
    }
}

impl SubWindowStamp {
    /// Self-consistency: the signature verifies over the canonical message under the embedded
    /// public key. Does NOT establish *who* the signer is — use `verify_for` for that.
    pub fn verify(&self) -> bool {
        let msg = sub_window_message(self.task_id, &self.node_id, self.sub_window);
        verify(AlgId::MlDsa65, &self.signer_pk, &msg, &self.signature)
    }

    /// Full check for a recomputer/orchestrator: the signature verifies AND the signer is the
    /// executor's registered identity key AND the stamp is for the expected `(task_id, node_id)`.
    /// This is what prevents an orchestrator from substituting a bucket: it would have to forge
    /// the executor's ML-DSA signature.
    pub fn verify_for(
        &self,
        expected_task_id: u64,
        expected_node_id: &str,
        registered_pk: &[u8],
    ) -> Result<(), ProvenanceError> {
        if self.task_id != expected_task_id || self.node_id != expected_node_id {
            return Err(ProvenanceError::ContextMismatch);
        }
        if self.signer_pk != registered_pk {
            return Err(ProvenanceError::UnregisteredSigner);
        }
        if !self.verify() {
            return Err(ProvenanceError::BadSignature);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// SignedReceipt (H1 / R-MAT2b, step 3): generalize the single-field stamp to the executor's
// whole attributable receipt core.
// ---------------------------------------------------------------------------------------------

/// Domain separator for the signed-receipt message.
const RECEIPT_DOMAIN: &[u8] = b"GOAT/signed-receipt/v1";

fn put_str(m: &mut Vec<u8>, s: &str) {
    m.extend_from_slice(&(s.len() as u32).to_be_bytes());
    m.extend_from_slice(s.as_bytes());
}

/// Canonical message an executor signs for a receipt: `(task_id, node_id)` binding context plus
/// the **executor-attributable** receipt fields and a commitment to the executor's output.
///
/// Deliberately EXCLUDES `diverged` and `fault`: those are verification OUTCOMES the orchestrator
/// determines by comparing results (an executor cannot sign its own fault verdict, and a faulted
/// executor would simply refuse to). The orchestrator attaches them after the fact; binding the
/// outcome to an escalation proof is the follow-on increment (see the H1 roadmap item). So the
/// signature fixes everything the executor is responsible for — class, window, `sub_window`,
/// cluster, asn, and the result commitment — while leaving attribution to the verification layer.
pub fn receipt_core_message(
    task_id: u64,
    node_id: &str,
    r: &Receipt,
    result_commit: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(RECEIPT_DOMAIN);
    m.extend_from_slice(&task_id.to_be_bytes());
    put_str(&mut m, node_id);
    put_str(&mut m, &r.class_id);
    m.extend_from_slice(&r.task_class_id.to_be_bytes());
    m.extend_from_slice(&r.window.to_be_bytes());
    m.extend_from_slice(&r.sub_window.to_be_bytes());
    put_str(&mut m, &r.cluster_id);
    put_str(&mut m, &r.asn);
    m.extend_from_slice(result_commit);
    m
}

/// A receipt whose executor-attributable core is signed by the executor's identity key. The
/// embedded `receipt` carries the orchestrator-attached `diverged`/`fault` outcome; the signature
/// covers only the executor-attributable core (see `receipt_core_message`), so the orchestrator
/// can attach an outcome but cannot alter any field the executor is responsible for.
#[derive(Clone, Debug)]
pub struct SignedReceipt {
    pub receipt: Receipt,
    pub task_id: u64,
    pub node_id: String,
    /// Commitment (A-6 canonical) to the executor's output, bound by the signature.
    pub result_commit: [u8; 32],
    pub signer_pk: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Executor side: sign a receipt's attributable core (with a commitment to the output `result`).
/// The passed `receipt`'s `diverged`/`fault` are placeholders here — they are not signed.
pub fn attest_receipt(
    signer: &dyn Signer,
    task_id: u64,
    node_id: &str,
    receipt: Receipt,
    result_commit: [u8; 32],
) -> SignedReceipt {
    let msg = receipt_core_message(task_id, node_id, &receipt, &result_commit);
    SignedReceipt {
        receipt,
        task_id,
        node_id: node_id.to_string(),
        result_commit,
        signer_pk: signer.public_key(),
        signature: signer.sign(&msg),
    }
}

impl SignedReceipt {
    /// Self-consistency: the signature verifies over the recomputed core message under the
    /// embedded public key. Independent of the (unsigned) `diverged`/`fault` outcome.
    pub fn verify(&self) -> bool {
        let msg = receipt_core_message(
            self.task_id,
            &self.node_id,
            &self.receipt,
            &self.result_commit,
        );
        verify(AlgId::MlDsa65, &self.signer_pk, &msg, &self.signature)
    }

    /// Full check binding the signer to a registered executor key and the expected context. This
    /// is what a recomputer or the orchestrator runs before accepting the receipt's attributable
    /// fields: altering any of class/window/sub_window/cluster/asn/result would require forging
    /// the executor's ML-DSA signature.
    pub fn verify_for(
        &self,
        expected_task_id: u64,
        expected_node_id: &str,
        registered_pk: &[u8],
    ) -> Result<(), ProvenanceError> {
        if self.task_id != expected_task_id || self.node_id != expected_node_id {
            return Err(ProvenanceError::ContextMismatch);
        }
        if self.signer_pk != registered_pk {
            return Err(ProvenanceError::UnregisteredSigner);
        }
        if !self.verify() {
            return Err(ProvenanceError::BadSignature);
        }
        Ok(())
    }
}

/// Recomputer-side batch check: every signed receipt is self-consistent (its signature verifies
/// over its own core). Binds the signer to a registered key only with `KeyRegistry` (below).
pub fn all_self_consistent(receipts: &[SignedReceipt]) -> bool {
    receipts.iter().all(|r| r.verify())
}

// ---------------------------------------------------------------------------------------------
// Fold-time enforcement (H1 / R-MAT2b, step 4): a node→identity-key registry lets the
// accumulator path REQUIRE that every receipt it folds is signed by the registered key of the
// node it claims to come from — instead of trusting that the orchestrator already checked.
// ---------------------------------------------------------------------------------------------

/// Maps a `node_id` to its registered ML-DSA identity public key. A recomputer builds this from
/// the network's published identities; fold-time enforcement checks each signer against it.
#[derive(Clone, Debug, Default)]
pub struct KeyRegistry {
    keys: HashMap<String, Vec<u8>>,
}

impl KeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn register(&mut self, node_id: &str, pubkey: Vec<u8>) {
        self.keys.insert(node_id.to_string(), pubkey);
    }
    pub fn get(&self, node_id: &str) -> Option<&Vec<u8>> {
        self.keys.get(node_id)
    }
    pub fn len(&self) -> usize {
        self.keys.len()
    }
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Verify a batch of signed receipts against the registry: each must be signed by the registered
/// key of the `node_id` it claims, over its own core. A receipt whose node is not registered is
/// `UnregisteredSigner`; a tampered/forged one is `BadSignature`/`ContextMismatch`.
pub fn verify_signed_receipts(
    signed: &[SignedReceipt],
    registry: &KeyRegistry,
) -> Result<(), ProvenanceError> {
    for sr in signed {
        let pk = registry
            .get(&sr.node_id)
            .ok_or(ProvenanceError::UnregisteredSigner)?;
        sr.verify_for(sr.task_id, &sr.node_id, pk)?;
    }
    Ok(())
}

/// Provenance-enforcing fold: verify every signed receipt against the registry FIRST, then fold
/// the underlying receipts into accumulators. Returns an error (folding nothing) if any receipt
/// is unattested, unregistered, or tampered — so no unverified data can reach the accumulator or
/// influence the burst predicate. The pure `fold_receipts` is unchanged and remains the shared
/// recomputation primitive; this is the opt-in provenance-aware entry point.
pub fn fold_verified(
    signed: &[SignedReceipt],
    registry: &KeyRegistry,
    merge_groups: &[Vec<String>],
) -> Result<HashMap<(ClassId, u64), ClassAccumulator>, ProvenanceError> {
    verify_signed_receipts(signed, registry)?;
    let receipts: Vec<Receipt> = signed.iter().map(|s| s.receipt.clone()).collect();
    Ok(fold_receipts(&receipts, merge_groups))
}

// ---------------------------------------------------------------------------------------------
// Assignment-log cross-binding (H1 / R-MAT2b, step 5): the registry answers *who signed*; this
// answers *whether they were authorized to sign it*. An `AuthorizationSet` records which
// node_ids were assigned to each task_id — derived from the orchestrator's SIGNED assignment log
// (and, for an escalation executor, the verifiable beacon lottery). Fold-time enforcement then
// rejects a receipt from a node that was never assigned the task, even if that node is a
// registered executor with a valid signature.
// ---------------------------------------------------------------------------------------------

/// Which node_ids were authorized (assigned) to each task_id. Built by a recomputer from verified
/// assignment logs. Task-scoped: authorization for one task never implies authorization for another.
#[derive(Clone, Debug, Default)]
pub struct AuthorizationSet {
    by_task: HashMap<u64, HashSet<String>>,
}

impl AuthorizationSet {
    pub fn new() -> Self {
        Self::default()
    }
    /// Record that `node_id` was authorized for `task_id`.
    pub fn authorize(&mut self, task_id: u64, node_id: &str) {
        self.by_task
            .entry(task_id)
            .or_default()
            .insert(node_id.to_string());
    }
    pub fn is_authorized(&self, task_id: u64, node_id: &str) -> bool {
        self.by_task
            .get(&task_id)
            .is_some_and(|s| s.contains(node_id))
    }
}

/// Check that every signed receipt's `(task_id, node_id)` was authorized. `Unauthorized` on the
/// first receipt from a node not assigned its task.
pub fn check_authorization(
    signed: &[SignedReceipt],
    auth: &AuthorizationSet,
) -> Result<(), ProvenanceError> {
    for sr in signed {
        if !auth.is_authorized(sr.task_id, &sr.node_id) {
            return Err(ProvenanceError::Unauthorized);
        }
    }
    Ok(())
}

/// Provenance + authorization enforcing fold: verify each signature against the registry AND that
/// each signer was authorized for the task, then fold. Rejects the whole batch (folding nothing)
/// if any receipt is unattested, unregistered, tampered, or from an unassigned node — so neither
/// unverified nor unauthorized data can reach the accumulator or the burst predicate. `fold_verified`
/// (identity only) remains available for callers that do not have an assignment set.
pub fn fold_verified_authorized(
    signed: &[SignedReceipt],
    registry: &KeyRegistry,
    auth: &AuthorizationSet,
    merge_groups: &[Vec<String>],
) -> Result<HashMap<(ClassId, u64), ClassAccumulator>, ProvenanceError> {
    verify_signed_receipts(signed, registry)?;
    check_authorization(signed, auth)?;
    let receipts: Vec<Receipt> = signed.iter().map(|s| s.receipt.clone()).collect();
    Ok(fold_receipts(&receipts, merge_groups))
}

// ---------------------------------------------------------------------------------------------
// Verifiable attribution (H1 / R-MAT2b, step 6): the last trusted element of a receipt is the
// `diverged`/`fault` outcome (attached by the orchestrator, unsigned by design — an executor
// cannot sign its own fault verdict). An `EscalationRecord` makes attribution INDEPENDENTLY
// checkable: it carries the three participants' signed receipts and their raw results (bound to
// each receipt via `result_commit`), plus the comparison profiles. A recomputer re-runs the
// agreement decision and confirms the attributed outcome is exactly what that decision produces.
// The orchestrator cannot frame an honest node: it cannot forge the executor-signed result
// commitments, and the decision is deterministic given the results.
// ---------------------------------------------------------------------------------------------

/// The attribution an escalation record re-derives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attribution {
    /// No fault attributable (C agreed with both, or an un-attributable three-way split).
    NoFault,
    /// The named node was legitimately attributed a fault by the re-derived decision.
    Faulted(String),
}

/// A verifiable record of an escalation: the primary pair A and B, the disjoint escalation
/// executor C, their raw results (each bound to its signed receipt via `result_commit`), and the
/// two comparison profiles. `verify_attribution` re-runs the decision from this alone.
#[derive(Clone, Debug)]
pub struct EscalationRecord {
    pub task_id: u64,
    pub a: SignedReceipt,
    pub b: SignedReceipt,
    pub c: SignedReceipt,
    pub result_a: TaskResult,
    pub result_b: TaskResult,
    pub result_c: TaskResult,
    pub prof_ca: DeterminismProfile,
    pub prof_cb: DeterminismProfile,
    pub token_threshold: f64,
}

impl EscalationRecord {
    /// Independently validate the attribution: (1) all three receipts are signed by their
    /// registered keys and authorized for the task; (2) each carried result matches the
    /// `result_commit` its executor signed; (3) re-running the agreement decision
    /// (`agree(C,A)`, `agree(C,B)`) produces exactly the `diverged`/`fault` flags recorded on
    /// the three receipts. Returns the re-derived `Attribution`, or an error if any check fails.
    pub fn verify_attribution(
        &self,
        registry: &KeyRegistry,
        auth: &AuthorizationSet,
    ) -> Result<Attribution, ProvenanceError> {
        let trio = [self.a.clone(), self.b.clone(), self.c.clone()];
        verify_signed_receipts(&trio, registry)?;
        check_authorization(&trio, auth)?;

        if commit(&self.result_a) != self.a.result_commit
            || commit(&self.result_b) != self.b.result_commit
            || commit(&self.result_c) != self.c.result_commit
        {
            return Err(ProvenanceError::ResultCommitMismatch);
        }

        let ca = agree(
            &self.result_c,
            &self.result_a,
            &self.prof_ca,
            self.token_threshold,
        );
        let cb = agree(
            &self.result_c,
            &self.result_b,
            &self.prof_cb,
            self.token_threshold,
        );

        // expected (diverged, fault) per role, and the re-derived attribution
        let clean = (false, false);
        let faulted = (true, true);
        let (exp_a, exp_b, exp_c, attribution) = if ca && cb {
            (clean, clean, clean, Attribution::NoFault) // C within band of both
        } else if ca {
            (
                clean,
                faulted,
                clean,
                Attribution::Faulted(self.b.node_id.clone()),
            ) // B faulted
        } else if cb {
            (
                faulted,
                clean,
                clean,
                Attribution::Faulted(self.a.node_id.clone()),
            ) // A faulted
        } else {
            (clean, clean, clean, Attribution::NoFault) // three-way split: no attribution
        };

        let got = |sr: &SignedReceipt| (sr.receipt.diverged, sr.receipt.fault);
        if got(&self.a) != exp_a || got(&self.b) != exp_b || got(&self.c) != exp_c {
            return Err(ProvenanceError::AttributionMismatch);
        }
        Ok(attribution)
    }
}

/// The strictest fold entry point: registry + authorization enforcement (Steps 4–5) PLUS
/// verifiable attribution (Step 6). Every receipt asserting a `diverged`/`fault` outcome must be
/// backed by a verified `EscalationRecord` that re-derives that exact attribution; an unbacked or
/// inconsistent outcome is `AttributionMismatch`. Clean receipts fold as before. This makes every
/// element of a folded receipt — identity, bucket, authorization, and outcome — independently
/// verifiable, so nothing about it is trusted rather than checked.
pub fn fold_verified_attributed(
    signed: &[SignedReceipt],
    registry: &KeyRegistry,
    auth: &AuthorizationSet,
    records: &[EscalationRecord],
    merge_groups: &[Vec<String>],
) -> Result<HashMap<(ClassId, u64), ClassAccumulator>, ProvenanceError> {
    verify_signed_receipts(signed, registry)?;
    check_authorization(signed, auth)?;

    // the (task_id, node_id) pairs a verified escalation record legitimately attributes a fault to
    let mut proven_faults: HashSet<(u64, String)> = HashSet::new();
    for rec in records {
        if let Attribution::Faulted(node) = rec.verify_attribution(registry, auth)? {
            proven_faults.insert((rec.task_id, node));
        }
    }

    // any receipt asserting a fault/divergence must be covered by a verified attribution
    for sr in signed {
        if (sr.receipt.diverged || sr.receipt.fault)
            && !proven_faults.contains(&(sr.task_id, sr.node_id.clone()))
        {
            return Err(ProvenanceError::AttributionMismatch);
        }
    }

    let receipts: Vec<Receipt> = signed.iter().map(|s| s.receipt.clone()).collect();
    Ok(fold_receipts(&receipts, merge_groups))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maturity::{anomaly_burst, SUB_WINDOWS};
    use crate::pqsign::MlDsaSigner;

    fn stamped_receipt(
        signer: &MlDsaSigner,
        node_id: &str,
        task_id: u64,
        sub_window: u32,
        diverged: bool,
    ) -> (Receipt, SubWindowStamp) {
        let stamp = attest_sub_window(signer, task_id, node_id, sub_window);
        // The receipt's bucket is taken FROM the verified stamp, not chosen independently.
        let r = Receipt {
            class_id: "cls.x".into(),
            task_class_id: 10,
            window: 1,
            sub_window: stamp.sub_window,
            cluster_id: format!("c{node_id}"),
            asn: format!("a{node_id}"),
            diverged,
            fault: false,
        };
        (r, stamp)
    }

    #[test]
    fn attest_and_verify_roundtrip() {
        let s = MlDsaSigner::generate();
        let stamp = attest_sub_window(&s, 42, "exec-1", 7);
        assert!(stamp.verify());
        assert!(stamp.verify_for(42, "exec-1", &s.public_key()).is_ok());
    }

    #[test]
    fn substituted_sub_window_fails_verification() {
        // an orchestrator rewrites the bucket on a stamp it did not sign
        let s = MlDsaSigner::generate();
        let mut stamp = attest_sub_window(&s, 42, "exec-1", 7);
        stamp.sub_window = 3; // spread the anomaly out of its real bucket
        assert!(!stamp.verify()); // signature was over sub_window = 7
    }

    #[test]
    fn orchestrator_cannot_forge_with_its_own_key() {
        let executor = MlDsaSigner::generate();
        let orchestrator = MlDsaSigner::generate();
        // the executor's registered identity
        let registered = executor.public_key();
        // orchestrator forges a stamp claiming to be the executor, with a chosen bucket
        let forged = attest_sub_window(&orchestrator, 42, "exec-1", 3);
        // self-consistent (orchestrator signed its own message)...
        assert!(forged.verify());
        // ...but rejected because the signer is not the executor's registered key
        assert_eq!(
            forged.verify_for(42, "exec-1", &registered),
            Err(ProvenanceError::UnregisteredSigner)
        );
    }

    #[test]
    fn context_mismatch_is_rejected() {
        let s = MlDsaSigner::generate();
        let stamp = attest_sub_window(&s, 42, "exec-1", 7);
        assert_eq!(
            stamp.verify_for(99, "exec-1", &s.public_key()),
            Err(ProvenanceError::ContextMismatch)
        );
        assert_eq!(
            stamp.verify_for(42, "exec-2", &s.public_key()),
            Err(ProvenanceError::ContextMismatch)
        );
    }

    #[test]
    fn attested_buckets_pin_a_burst_against_rebucketing() {
        // Eight executors each attest an anomaly in the SAME sub-window (a concentration in time).
        // The verified stamps fix the buckets; an orchestrator honoring them cannot spread the
        // anomalies, so the burst survives into the accumulator.
        let mut receipts = Vec::new();
        let mut signers = Vec::new();
        for i in 0..8 {
            let s = MlDsaSigner::generate();
            let node = format!("exec-{i}");
            let (r, stamp) = stamped_receipt(&s, &node, 100 + i as u64, 5, true);
            // recomputer verifies provenance before accepting the bucket
            assert!(stamp
                .verify_for(100 + i as u64, &node, &s.public_key())
                .is_ok());
            assert_eq!(r.sub_window, stamp.sub_window);
            receipts.push(r);
            signers.push(s);
        }
        // pad with clean receipts spread across other buckets so window-wide rates stay low
        for i in 0..2000u32 {
            receipts.push(Receipt {
                class_id: "cls.x".into(),
                task_class_id: 10,
                window: 1,
                sub_window: 1 + (i % (SUB_WINDOWS - 1)), // buckets 1..SUB_WINDOWS, never 5's peak alone
                cluster_id: format!("c{i}"),
                asn: format!("a{}", i % 12),
                diverged: false,
                fault: false,
            });
        }
        let folded = fold_receipts(&receipts, &[]);
        let acc = &folded[&("cls.x".to_string(), 1)];
        assert!(anomaly_burst(acc)); // the executor-pinned concentration is visible as a burst
    }

    // ---- SignedReceipt (step 3) ----

    fn core_receipt(sub_window: u32) -> Receipt {
        Receipt {
            class_id: "cls.x".into(),
            task_class_id: 10,
            window: 1,
            sub_window,
            cluster_id: "c1".into(),
            asn: "a1".into(),
            diverged: false,
            fault: false,
        }
    }

    fn result() -> crate::types::TaskResult {
        crate::types::TaskResult {
            task_class_id: 10,
            tokens: vec![1, 2, 3],
            vector: vec![10, 20, 30],
            engine_build_id: "b1".into(),
        }
    }

    #[test]
    fn signed_receipt_roundtrip() {
        let s = MlDsaSigner::generate();
        let rc = crate::commit::commit(&result());
        let sr = attest_receipt(&s, 42, "exec-1", core_receipt(7), rc);
        assert!(sr.verify());
        assert!(sr.verify_for(42, "exec-1", &s.public_key()).is_ok());
        assert!(all_self_consistent(std::slice::from_ref(&sr)));
    }

    #[test]
    fn attaching_the_outcome_does_not_break_the_signature() {
        // the orchestrator attaches diverged/fault AFTER the executor signs; these are not part
        // of the signed core, so attribution is possible without the executor's cooperation and
        // does not invalidate the signature.
        let s = MlDsaSigner::generate();
        let rc = crate::commit::commit(&result());
        let mut sr = attest_receipt(&s, 42, "exec-1", core_receipt(7), rc);
        sr.receipt.diverged = true;
        sr.receipt.fault = true;
        assert!(sr.verify());
    }

    #[test]
    fn tampering_an_attributable_field_fails_verification() {
        // altering any executor-attributable field (here the bucket, and separately the cluster)
        // breaks the signature — the orchestrator cannot rewrite what the executor signed.
        let s = MlDsaSigner::generate();
        let rc = crate::commit::commit(&result());

        let mut sub = attest_receipt(&s, 42, "exec-1", core_receipt(7), rc);
        sub.receipt.sub_window = 3;
        assert!(!sub.verify());

        let mut clu = attest_receipt(&s, 42, "exec-1", core_receipt(7), rc);
        clu.receipt.cluster_id = "c99".into();
        assert!(!clu.verify());
    }

    #[test]
    fn tampering_the_result_commit_fails_verification() {
        let s = MlDsaSigner::generate();
        let rc = crate::commit::commit(&result());
        let mut sr = attest_receipt(&s, 42, "exec-1", core_receipt(7), rc);
        sr.result_commit = [0u8; 32]; // claim a different output than was signed
        assert!(!sr.verify());
    }

    #[test]
    fn signed_receipt_rejects_unregistered_signer_and_bad_context() {
        let executor = MlDsaSigner::generate();
        let other = MlDsaSigner::generate();
        let rc = crate::commit::commit(&result());
        let sr = attest_receipt(&executor, 42, "exec-1", core_receipt(7), rc);
        assert_eq!(
            sr.verify_for(42, "exec-1", &other.public_key()),
            Err(ProvenanceError::UnregisteredSigner)
        );
        assert_eq!(
            sr.verify_for(99, "exec-1", &executor.public_key()),
            Err(ProvenanceError::ContextMismatch)
        );
    }

    // ---- fold-time enforcement (step 4) ----

    /// Two executors, each signing a receipt for its own node, and a registry of their keys.
    fn signed_pair() -> (Vec<SignedReceipt>, KeyRegistry) {
        let mut reg = KeyRegistry::new();
        let mut out = Vec::new();
        for (i, node) in ["exec-1", "exec-2"].iter().enumerate() {
            let s = MlDsaSigner::generate();
            reg.register(node, s.public_key());
            let mut rc = core_receipt(5);
            rc.cluster_id = format!("c{i}");
            rc.asn = format!("a{i}");
            out.push(attest_receipt(
                &s,
                100 + i as u64,
                node,
                rc,
                crate::commit::commit(&result()),
            ));
        }
        (out, reg)
    }

    #[test]
    fn fold_verified_accepts_registered_signed_receipts() {
        let (signed, reg) = signed_pair();
        let folded = fold_verified(&signed, &reg, &[]).expect("all attested and registered");
        assert_eq!(folded[&("cls.x".to_string(), 1)].v_c, 2);
    }

    #[test]
    fn fold_verified_rejects_tampered_receipt() {
        // an attributable field is rewritten after signing -> the fold refuses the whole batch,
        // so no unverified data reaches the accumulator.
        let (mut signed, reg) = signed_pair();
        signed[0].receipt.sub_window = 9; // != the signed bucket
        assert_eq!(
            verify_signed_receipts(&signed, &reg),
            Err(ProvenanceError::BadSignature)
        );
        assert!(fold_verified(&signed, &reg, &[]).is_err());
    }

    #[test]
    fn fold_verified_rejects_unregistered_node() {
        // a receipt whose node has no registered key is rejected (models an unattested/unknown
        // submitter reaching the accumulator).
        let (signed, _reg) = signed_pair();
        let mut reg = KeyRegistry::new();
        // register only the first node, drop the second
        reg.register(&signed[0].node_id, signed[0].signer_pk.clone());
        assert_eq!(
            verify_signed_receipts(&signed, &reg),
            Err(ProvenanceError::UnregisteredSigner)
        );
        assert!(fold_verified(&signed, &reg, &[]).is_err());
    }

    #[test]
    fn fold_verified_matches_pure_fold_when_all_valid() {
        // provenance enforcement does not change the accumulator result for valid input.
        let (signed, reg) = signed_pair();
        let receipts: Vec<Receipt> = signed.iter().map(|s| s.receipt.clone()).collect();
        let enforced = fold_verified(&signed, &reg, &[]).unwrap();
        let pure = crate::maturity::fold_receipts(&receipts, &[]);
        assert_eq!(
            enforced[&("cls.x".to_string(), 1)].root(),
            pure[&("cls.x".to_string(), 1)].root()
        );
    }

    // ---- assignment-log cross-binding (step 5) ----

    fn authorize_all(signed: &[SignedReceipt]) -> AuthorizationSet {
        let mut auth = AuthorizationSet::new();
        for sr in signed {
            auth.authorize(sr.task_id, &sr.node_id);
        }
        auth
    }

    #[test]
    fn fold_verified_authorized_accepts_assigned_nodes() {
        let (signed, reg) = signed_pair();
        let auth = authorize_all(&signed);
        assert!(fold_verified_authorized(&signed, &reg, &auth, &[]).is_ok());
    }

    #[test]
    fn fold_verified_authorized_rejects_unassigned_node() {
        // registered + validly signed, but the second node was not assigned its task.
        let (signed, reg) = signed_pair();
        let mut auth = AuthorizationSet::new();
        auth.authorize(signed[0].task_id, &signed[0].node_id); // authorize only the first
        assert_eq!(
            check_authorization(&signed, &auth),
            Err(ProvenanceError::Unauthorized)
        );
        assert!(fold_verified_authorized(&signed, &reg, &auth, &[]).is_err());
    }

    #[test]
    fn authorization_is_task_scoped() {
        // being assigned a DIFFERENT task does not authorize this one.
        let (signed, _reg) = signed_pair();
        let mut auth = AuthorizationSet::new();
        auth.authorize(signed[0].task_id + 999, &signed[0].node_id);
        assert!(!auth.is_authorized(signed[0].task_id, &signed[0].node_id));
    }

    // ---- verifiable attribution (step 6) ----

    fn a_result(v: i64) -> TaskResult {
        TaskResult {
            task_class_id: 10,
            tokens: vec![v as u32],
            vector: vec![v],
            engine_build_id: "b1".into(),
        }
    }

    fn make_sr(
        node: &str,
        task_id: u64,
        result: &TaskResult,
        diverged: bool,
        fault: bool,
    ) -> (Vec<u8>, SignedReceipt) {
        let s = MlDsaSigner::generate();
        let pk = s.public_key();
        let receipt = Receipt {
            class_id: "cls.x".into(),
            task_class_id: 10,
            window: 1,
            sub_window: 5,
            cluster_id: format!("cl-{node}"),
            asn: format!("as-{node}"),
            diverged,
            fault,
        };
        (
            pk,
            attest_receipt(&s, task_id, node, receipt, commit(result)),
        )
    }

    /// Escalation where C agrees with A (identical result) and B diverged -> B faulted.
    fn escalation_b_faulted() -> (EscalationRecord, KeyRegistry, AuthorizationSet) {
        let task_id = 7;
        let good = a_result(10);
        let bad = a_result(99);
        let (pk_a, a) = make_sr("A", task_id, &good, false, false);
        let (pk_b, b) = make_sr("B", task_id, &bad, true, true); // faulted
        let (pk_c, c) = make_sr("C", task_id, &good, false, false);
        let mut reg = KeyRegistry::new();
        reg.register("A", pk_a);
        reg.register("B", pk_b);
        reg.register("C", pk_c);
        let mut auth = AuthorizationSet::new();
        for n in ["A", "B", "C"] {
            auth.authorize(task_id, n);
        }
        let rec = EscalationRecord {
            task_id,
            a,
            b,
            c,
            result_a: good.clone(),
            result_b: bad,
            result_c: good,
            prof_ca: DeterminismProfile::exact(),
            prof_cb: DeterminismProfile::exact(),
            token_threshold: crate::verification::TOKEN_THRESHOLD,
        };
        (rec, reg, auth)
    }

    #[test]
    fn verify_attribution_accepts_consistent_record() {
        let (rec, reg, auth) = escalation_b_faulted();
        assert_eq!(
            rec.verify_attribution(&reg, &auth),
            Ok(Attribution::Faulted("B".into()))
        );
    }

    #[test]
    fn verify_attribution_rejects_framing_an_honest_node() {
        // move the fault flags from B (the true faulter) onto A. C agreed with A, so the re-derived
        // decision expects B faulted, not A -> the asserted attribution is inconsistent.
        let (mut rec, reg, auth) = escalation_b_faulted();
        rec.a.receipt.diverged = true;
        rec.a.receipt.fault = true;
        rec.b.receipt.diverged = false;
        rec.b.receipt.fault = false;
        assert_eq!(
            rec.verify_attribution(&reg, &auth),
            Err(ProvenanceError::AttributionMismatch)
        );
    }

    #[test]
    fn verify_attribution_rejects_substituted_result() {
        // swap B's result for one that does not match the commitment B signed.
        let (mut rec, reg, auth) = escalation_b_faulted();
        rec.result_b = a_result(10); // != the (99) B signed
        assert_eq!(
            rec.verify_attribution(&reg, &auth),
            Err(ProvenanceError::ResultCommitMismatch)
        );
    }

    #[test]
    fn fold_attributed_accepts_a_backed_fault() {
        let (rec, reg, auth) = escalation_b_faulted();
        let signed = vec![rec.a.clone(), rec.b.clone(), rec.c.clone()];
        let records = vec![rec];
        assert!(fold_verified_attributed(&signed, &reg, &auth, &records, &[]).is_ok());
    }

    #[test]
    fn fold_attributed_rejects_a_fault_with_no_record() {
        // B's receipt asserts a fault, but no escalation record backs it -> rejected.
        let (rec, reg, auth) = escalation_b_faulted();
        let signed = vec![rec.a.clone(), rec.b.clone(), rec.c.clone()];
        match fold_verified_attributed(&signed, &reg, &auth, &[], &[]) {
            Err(ProvenanceError::AttributionMismatch) => {}
            _ => panic!("an unbacked fault must be rejected"),
        }
    }
}
