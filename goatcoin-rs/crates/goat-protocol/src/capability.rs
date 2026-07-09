//! CapabilityRecord / DeviceCapability, hash-chain, F6 density, validity predicate.
//! Amendments: A-1 (observed_compute_equiv), A-2 (density under-declaration hard + F6 on
//! probe), A-3 (hash-chain over the SIGNED record), A-5 (hard/soft checks), A-6 (commit is
//! device-blind, in commit.rs). All device-agnostic: class_id is an opaque string.

use std::collections::{BTreeMap, HashMap};

use sha3::{Digest, Sha3_256};

use crate::pqsign::{verify, AlgId, Signer};
use crate::types::{ClassId, TaskClassCap};

pub const ZERO32: [u8; 32] = [0u8; 32];
/// A residential last-mile credibly hosts ~1-5 reference-device-equivalents.
pub const RESIDENTIAL_DENSITY_PLAUSIBLE: u32 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkClass {
    Unknown = 0,
    Residential = 1,
    Datacenter = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DensitySignal {
    Ok,
    DegradeQNetwork,
    CohortMerge,
}

#[derive(Clone, Debug)]
pub struct Availability {
    pub window_bitmap: u128, // reference uses 128 bits; production uses 168 (24h x 7d)
    pub expected_idle_h: u32,
    pub preempt_p50_ms: u32,
    pub preempt_p95_ms: u32,
}

#[derive(Clone, Debug)]
pub struct Envelope {
    pub max_power_w: u32,
    pub thermal_policy_class: u16,
}

#[derive(Clone, Debug)]
pub struct DensityWitness {
    pub endpoint_id_commit: Vec<u8>, // 32-byte commitment to the network endpoint
    pub observed_compute_equiv: u32, // reference-device-equivalents (A-1)
}

#[derive(Clone, Debug)]
pub struct AttestationRefs {
    pub idle_score_epoch: u64,
    pub network_class: NetworkClass,
    pub tee: bool,
}

#[derive(Clone, Debug)]
pub struct DeviceCapability {
    pub class_id: ClassId,
    pub fingerprint_commit: Vec<u8>,
    pub task_classes: Vec<TaskClassCap>,
    pub determinism_ref: (ClassId, u32),
    pub availability: Availability,
    pub envelope: Envelope,
    pub density_witness: DensityWitness,
    pub attestation_refs: AttestationRefs,
}

#[derive(Clone, Debug)]
pub struct CapabilityRecord {
    pub version: u16,
    pub node_id: Vec<u8>,
    pub operator_binding: Vec<u8>,
    pub epoch: u64,
    pub nonce: Vec<u8>,
    pub devices: Vec<DeviceCapability>,
    pub prev_record: Vec<u8>,
    pub alg_id: AlgId,
    pub signature: Vec<u8>,
}

// ---- canonical serialization ----
fn put_u16(o: &mut Vec<u8>, n: u16) {
    o.extend_from_slice(&n.to_be_bytes());
}
fn put_u32(o: &mut Vec<u8>, n: u32) {
    o.extend_from_slice(&n.to_be_bytes());
}
fn put_u64(o: &mut Vec<u8>, n: u64) {
    o.extend_from_slice(&n.to_be_bytes());
}
fn blob(o: &mut Vec<u8>, b: &[u8]) {
    put_u32(o, b.len() as u32);
    o.extend_from_slice(b);
}
fn sstr(o: &mut Vec<u8>, s: &str) {
    blob(o, s.as_bytes());
}

fn ser_task_class(tc: &TaskClassCap) -> Vec<u8> {
    let mut o = Vec::new();
    put_u32(&mut o, tc.task_class_id);
    put_u64(&mut o, (tc.measured_gcu_rate * 1_000_000.0).round() as u64);
    put_u32(&mut o, tc.mem_capacity_mb);
    put_u16(&mut o, tc.batch_limit);
    put_u64(&mut o, tc.last_bench_epoch);
    o
}

fn ser_device(d: &DeviceCapability) -> Vec<u8> {
    let mut o = Vec::new();
    sstr(&mut o, &d.class_id);
    blob(&mut o, &d.fingerprint_commit);
    put_u32(&mut o, d.task_classes.len() as u32);
    for tc in &d.task_classes {
        blob(&mut o, &ser_task_class(tc));
    }
    sstr(&mut o, &d.determinism_ref.0);
    put_u32(&mut o, d.determinism_ref.1);
    blob(&mut o, &d.availability.window_bitmap.to_be_bytes());
    put_u32(&mut o, d.availability.expected_idle_h);
    put_u32(&mut o, d.availability.preempt_p50_ms);
    put_u32(&mut o, d.availability.preempt_p95_ms);
    put_u32(&mut o, d.envelope.max_power_w);
    put_u16(&mut o, d.envelope.thermal_policy_class);
    blob(&mut o, &d.density_witness.endpoint_id_commit);
    put_u32(&mut o, d.density_witness.observed_compute_equiv);
    put_u64(&mut o, d.attestation_refs.idle_score_epoch);
    put_u16(&mut o, d.attestation_refs.network_class as u16);
    put_u16(&mut o, d.attestation_refs.tee as u16);
    o
}

pub fn serialize_unsigned(r: &CapabilityRecord) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(b"GCAP\x01");
    put_u16(&mut o, r.version);
    blob(&mut o, &r.node_id);
    blob(&mut o, &r.operator_binding);
    put_u64(&mut o, r.epoch);
    blob(&mut o, &r.nonce);
    put_u32(&mut o, r.devices.len() as u32);
    for d in &r.devices {
        blob(&mut o, &ser_device(d));
    }
    blob(&mut o, &r.prev_record);
    put_u16(&mut o, r.alg_id.as_u16());
    o
}

pub fn serialize_signed(r: &CapabilityRecord) -> Vec<u8> {
    let mut o = serialize_unsigned(r);
    blob(&mut o, &r.signature);
    o
}

fn sha3(bytes: &[u8]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.update(bytes);
    h.finalize().to_vec()
}

/// Hash over the full SIGNED record (A-3): the hash-chain commits to the exact bytes.
pub fn record_hash(r: &CapabilityRecord) -> Vec<u8> {
    sha3(&serialize_signed(r))
}

pub fn node_id_from_pubkey(pubkey: &[u8]) -> Vec<u8> {
    sha3(pubkey)
}

// ---- signing ----
pub fn sign_record(mut r: CapabilityRecord, signer: &dyn Signer) -> CapabilityRecord {
    r.node_id = node_id_from_pubkey(&signer.public_key());
    r.alg_id = signer.alg_id();
    r.signature = Vec::new();
    let sig = signer.sign(&serialize_unsigned(&r));
    r.signature = sig;
    r
}

pub fn verify_record_signature(r: &CapabilityRecord, pubkey: &[u8]) -> bool {
    if r.node_id != node_id_from_pubkey(pubkey) {
        return false;
    }
    let mut unsigned = r.clone();
    unsigned.signature = Vec::new();
    verify(
        r.alg_id,
        pubkey,
        &serialize_unsigned(&unsigned),
        &r.signature,
    )
}

// ---- F6 density ----
/// F4 curve: residential score degrades sharply past the plausible device count.
pub fn q_network_factor(observed_compute_equiv: u32) -> f64 {
    let d = observed_compute_equiv.max(1) as f64;
    if d <= RESIDENTIAL_DENSITY_PLAUSIBLE as f64 {
        0.85
    } else {
        (0.85 * (RESIDENTIAL_DENSITY_PLAUSIBLE as f64 / d).powf(1.5)).max(0.10)
    }
}

fn density_signal_for(observed: u32, nc: NetworkClass) -> DensitySignal {
    if nc == NetworkClass::Residential && observed > RESIDENTIAL_DENSITY_PLAUSIBLE {
        DensitySignal::CohortMerge
    } else {
        DensitySignal::Ok
    }
}

/// F6 on the DECLARED value (used when there is no probe observation).
pub fn evaluate_density(dev: &DeviceCapability) -> DensitySignal {
    density_signal_for(
        dev.density_witness.observed_compute_equiv,
        dev.attestation_refs.network_class,
    )
}

// ---- validity predicate (A-2, A-5) ----
pub struct ValidationContext {
    pub registered_pubkey: Vec<u8>,
    pub expected_nonce: Vec<u8>,
    pub last_record_hash: Option<Vec<u8>>,
    pub tolerance_bands: HashMap<u32, (f64, f64)>,
    pub prior_fingerprints: HashMap<ClassId, Vec<u8>>,
    pub probe_observed_equiv: HashMap<Vec<u8>, u32>,
    pub density_underclaim_slack: u32,
}

impl ValidationContext {
    pub fn new(registered_pubkey: Vec<u8>, expected_nonce: Vec<u8>) -> Self {
        Self {
            registered_pubkey,
            expected_nonce,
            last_record_hash: None,
            tolerance_bands: HashMap::new(),
            prior_fingerprints: HashMap::new(),
            probe_observed_equiv: HashMap::new(),
            density_underclaim_slack: 1,
        }
    }
}

#[derive(Debug)]
pub struct ValidationResult {
    pub ok: bool,
    pub checks: BTreeMap<String, bool>,
    pub reasons: Vec<String>,
    pub density_signals: HashMap<ClassId, DensitySignal>,
}

pub fn validate_record(r: &CapabilityRecord, ctx: &ValidationContext) -> ValidationResult {
    let mut checks = BTreeMap::new();
    let mut reasons = Vec::new();
    let mut signals = HashMap::new();

    let sig_ok = verify_record_signature(r, &ctx.registered_pubkey);
    checks.insert("signature".to_string(), sig_ok);
    if !sig_ok {
        reasons.push("signature/node_id mismatch".to_string());
    }

    let nonce_ok = r.nonce == ctx.expected_nonce;
    checks.insert("nonce".to_string(), nonce_ok);
    if !nonce_ok {
        reasons.push("nonce does not match epoch beacon (possible replay)".to_string());
    }

    let expected_prev = ctx
        .last_record_hash
        .clone()
        .unwrap_or_else(|| ZERO32.to_vec());
    let chain_ok = r.prev_record == expected_prev;
    checks.insert("chain".to_string(), chain_ok);
    if !chain_ok {
        reasons.push("prev_record does not chain to last accepted record".to_string());
    }

    let mut gcu_ok = true;
    let mut fp_ok = true;
    let mut density_ok = true;
    for d in &r.devices {
        for tc in &d.task_classes {
            if let Some(&(lo, hi)) = ctx.tolerance_bands.get(&tc.task_class_id) {
                if !(lo <= tc.measured_gcu_rate && tc.measured_gcu_rate <= hi) {
                    gcu_ok = false;
                    reasons.push(format!(
                        "{} tc{} rate {} outside band ({lo},{hi})",
                        d.class_id, tc.task_class_id, tc.measured_gcu_rate
                    ));
                }
            }
        }
        if let Some(prior) = ctx.prior_fingerprints.get(&d.class_id) {
            if prior != &d.fingerprint_commit {
                fp_ok = false;
                reasons.push(format!(
                    "{} fingerprint drift (triggers re-benchmark)",
                    d.class_id
                ));
            }
        }
        // F6 cross-check: node must not under-declare density vs. probe observation.
        let probe = ctx
            .probe_observed_equiv
            .get(&d.density_witness.endpoint_id_commit)
            .copied();
        if let Some(p) = probe {
            if d.density_witness.observed_compute_equiv + ctx.density_underclaim_slack < p {
                density_ok = false;
                reasons.push(format!(
                    "{} density under-declared (claimed {} vs probe {})",
                    d.class_id, d.density_witness.observed_compute_equiv, p
                ));
            }
        }
        // Evaluate F6 on the PROBE value when available (defeats under-declaration).
        let effective = probe.unwrap_or(d.density_witness.observed_compute_equiv);
        signals.insert(
            d.class_id.clone(),
            density_signal_for(effective, d.attestation_refs.network_class),
        );
    }
    checks.insert("gcu_tolerance".to_string(), gcu_ok);
    checks.insert("fingerprint_stable".to_string(), fp_ok); // SOFT (A-5)
    checks.insert("density_consistent".to_string(), density_ok);

    // Hard checks gate acceptance; fingerprint drift is soft.
    let ok = sig_ok && nonce_ok && chain_ok && gcu_ok && density_ok;
    ValidationResult {
        ok,
        checks,
        reasons,
        density_signals: signals,
    }
}
