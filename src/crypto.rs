//! `crypto.rs` — ML-DSA-65 domain-separation contexts, a fallible canonical-serialization
//! contract, allocator-gated convenience, and the §18.2–§18.4 verification-plane pipeline.
//!
//! Phase-3 scaffolding. Context byte-strings are transcribed from the sealed Domain Context
//! Registry (`GoatCoin_Threat_Model.md` v1.3, Part V §10) and amendments. [`CanonicalSerialize`]
//! implements the Injectivity Invariant (Threat Model §11; Yellowpaper Appendix A, c.5).
//! [`symmetric_deviation_ppm`] is the §30.1 normative function, verbatim (E1-A1). No `unsafe`.
//!
//! ## RECON-05/06 (retained)
//!
//! Fallible serialization (`Result`, `#[must_use]`) with no silent truncation; complete `alloc`
//! feature-gating (zero allocator code under `--no-default-features`); `.to_le_bytes()` everywhere
//! (host-independent; R-MAT1 / SC8); the fold's `KeyRegistry` gate and exact largest-remainder
//! weight normalization.
//!
//! ## RECON-07 — structural cryptographic amendments
//!
//! 1. **Plagiarism closure.** [`ExecutionAttestation`] now binds the executor `node_id` in the
//!    signed core (`node_id` first in the amended order), and the fold's [`KeyRegistry`] check is
//!    keyed on `(public_key, node_id)` — a valid signature under a foreign staked key over a core
//!    claiming another node's id fails the registry (A-CI3). `MAX_*_LEN` recomputed (+32 B).
//! 2. **Escalation desync closure.** [`EscalationRecord`] holds three fused
//!    [`EscalatedResult`](crate::types::EscalatedResult)s (receipt + its trace commitment) instead
//!    of two parallel arrays — no positional misalignment possible.
//! 3. **Local authorization.** [`fold_verified_attributed`] takes an [`AuthorizationSet`]: a
//!    globally-staked node not assigned to this window/task by the orchestrator is dropped (§18.2).

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::types::{
    AggregatedAttribution, AuthorizationSet, BoundedVec, CapabilityRecord, ChainId,
    DeviceCapability, EndpointDensity, Epoch, EscalatedResult, EscalationRecord,
    ExecutionAttestation, FrameHeader, NetworkDensityFrame, OpaqueTag, Ppm,
    PresenceAvailabilityFrame, SignedReceipt, SignedRecord, BP_FULL, MAX_ATTRIBUTIONS_PER_FOLD,
    MAX_AUTHORIZED_EXECUTORS, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN, OPAQUE_TAG_CAP,
    PPM, SYMMETRIC_DEVIATION_MAX_PPM,
};

// ===========================================================================
// Serialization error typology (RECON-05)
// ===========================================================================

/// A total failure mode of the canonical encoder; `Result` makes handling compiler-enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerializationError {
    /// The target buffer could not hold the write — truncation refused (RECON-05, hazard 1).
    BufferOverflow,
    /// A bounded accumulator was pushed past capacity — over-count refused, never silent (§18.4).
    CapacityExceeded,
}

// ===========================================================================
// ML-DSA-65 Authorized Domain Context Registry (Threat Model Part V §10)
// ===========================================================================

/// `CapabilityRecord`. §11. **[shipped]**
pub const CTX_GOAT_CAPABILITY_RECORD: &[u8] = b"GOAT/v1/cap\x01";
/// Rolling re-attestation chain link. §12. **[shipped]**
pub const CTX_GOAT_ATTESTATION_CHAIN: &[u8] = b"GOAT/v1/attchain\x01";
/// `ExecutionAttestation` attributable core (RECON-07: now binds `node_id`). §18.1. **[shipped]**
pub const CTX_GOAT_EXEC_ATTESTATION: &[u8] = b"GOAT/v1/exec\x01";
/// Orchestrator signed assignment log → `AuthorizationSet`. §18.2. **[shipped]**
pub const CTX_GOAT_ASSIGNMENT_LOG: &[u8] = b"GOAT/v1/assign\x01";
/// `EscalationRecord`. §18.3. **[shipped]**
pub const CTX_GOAT_ESCALATION_RECORD: &[u8] = b"GOAT/v1/escal\x01";
/// Commit-reveal beacon commitment. §19.1. **[shipped]**
pub const CTX_GOAT_BEACON_COMMIT: &[u8] = b"GOAT/v1/beacon\x01";
/// Transport handshake auth. §17. **[shipped]**
pub const CTX_GOAT_TRANSPORT_HS: &[u8] = b"GOAT/v1/tls-hs\x01";
/// `HardwareExceptionLog`. §8.1 (R-C16). **[design]**
pub const CTX_GOAT_HW_EXCEPTION_LOG: &[u8] = b"GOAT/v1/hwexc\x01";
/// Validator DA attestation. §19.3. **[design]**
pub const CTX_GOAT_DA_ATTESTATION: &[u8] = b"GOAT/v1/gda\x01";
/// Oracle posting. §32. **[design]**
pub const CTX_GOAT_ORACLE_POSTING: &[u8] = b"GOAT/v1/oracle\x01";
/// `contention_timing` probe attestation. §14 (D-6, R-C17). **[design]**
pub const CTX_GOAT_ENTROPY_PROBE: &[u8] = b"GOAT/v1/probe\x01";
/// Host-daemon `WatchdogTombstone`. §8.1 (R-C19). **[design]**
pub const CTX_GOAT_WATCHDOG_TOMBSTONE: &[u8] = b"GOAT/v1/wdog\x01";
/// F5 study telemetry frame. F5 §1. **[design]** (amendment candidate)
pub const CTX_GOAT_F5_TELEMETRY: &[u8] = b"GOAT/v1/f5tel\x01";
/// Committed `SignedRecord` container tag (RECON-05). **[design]** (amendment candidate)
pub const CTX_GOAT_SIGNED_RECORD_WRAPPER: &[u8] = b"GOAT/v1/recwrap\x01";
/// Committed `SignedReceipt` container tag (RECON-05). **[design]** (amendment candidate)
pub const CTX_GOAT_SIGNED_RECEIPT_WRAPPER: &[u8] = b"GOAT/v1/rcptwrap\x01";

// NOTE `CTX_GOAT_IDENTITY_ATTESTATION` is not registered in §10; identity/attestation is served by
// CAPABILITY_RECORD (§11), ATTESTATION_CHAIN (§12), EXEC_ATTESTATION (§18.1). A new context is a §4
// registry amendment, not an inline addition.

/// The full ordered registry — for the A-CI1a exhaustiveness audit and A-CI1b/1d separation fuzz.
pub const ALL_CONTEXTS: &[&[u8]] = &[
    CTX_GOAT_CAPABILITY_RECORD,
    CTX_GOAT_ATTESTATION_CHAIN,
    CTX_GOAT_EXEC_ATTESTATION,
    CTX_GOAT_ASSIGNMENT_LOG,
    CTX_GOAT_ESCALATION_RECORD,
    CTX_GOAT_BEACON_COMMIT,
    CTX_GOAT_TRANSPORT_HS,
    CTX_GOAT_HW_EXCEPTION_LOG,
    CTX_GOAT_DA_ATTESTATION,
    CTX_GOAT_ORACLE_POSTING,
    CTX_GOAT_ENTROPY_PROBE,
    CTX_GOAT_WATCHDOG_TOMBSTONE,
    CTX_GOAT_F5_TELEMETRY,
    CTX_GOAT_SIGNED_RECORD_WRAPPER,
    CTX_GOAT_SIGNED_RECEIPT_WRAPPER,
];

// ===========================================================================
// ByteSink — heap Vec [alloc] or a stack SliceSink [always]
// ===========================================================================

/// A fallible byte sink the canonical encoder appends to. The `Result` return is the
/// compile-enforced anti-truncation gate.
pub trait ByteSink {
    /// Append `bytes`, or fail if the target cannot hold them (never silently truncates).
    fn put(&mut self, bytes: &[u8]) -> Result<(), SerializationError>;
}

#[cfg(feature = "alloc")]
impl ByteSink for Vec<u8> {
    #[inline]
    fn put(&mut self, bytes: &[u8]) -> Result<(), SerializationError> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

/// A fixed, caller-provided stack buffer used as a [`ByteSink`] — zero heap allocation. On overrun
/// it returns [`SerializationError::BufferOverflow`] and sets [`overflowed`](SliceSink::overflowed);
/// it never panics and never truncates silently.
pub struct SliceSink<'a> {
    buf: &'a mut [u8],
    pos: usize,
    overflow: bool,
}

impl<'a> SliceSink<'a> {
    /// Wrap a caller buffer.
    #[inline]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            overflow: false,
        }
    }
    /// The bytes written so far.
    #[inline]
    pub fn written(&self) -> &[u8] {
        &self.buf[..self.pos]
    }
    /// Bytes written.
    #[inline]
    pub fn len(&self) -> usize {
        self.pos
    }
    /// `true` iff nothing has been written.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }
    /// `true` iff a write exceeded the buffer.
    #[inline]
    pub fn overflowed(&self) -> bool {
        self.overflow
    }
}

impl ByteSink for SliceSink<'_> {
    #[inline]
    fn put(&mut self, bytes: &[u8]) -> Result<(), SerializationError> {
        let end = self.pos.saturating_add(bytes.len());
        if end <= self.buf.len() {
            self.buf[self.pos..end].copy_from_slice(bytes);
            self.pos = end;
            Ok(())
        } else {
            self.overflow = true;
            Err(SerializationError::BufferOverflow)
        }
    }
}

// ===========================================================================
// Canonical little-endian, length-prefixed primitives (Threat Model §11.3)
// ===========================================================================

#[inline]
fn put_u8<S: ByteSink>(out: &mut S, v: u8) -> Result<(), SerializationError> {
    out.put(&[v])
}
#[inline]
fn put_u16<S: ByteSink>(out: &mut S, v: u16) -> Result<(), SerializationError> {
    out.put(&v.to_le_bytes())
}
#[inline]
fn put_u32<S: ByteSink>(out: &mut S, v: u32) -> Result<(), SerializationError> {
    out.put(&v.to_le_bytes())
}
#[inline]
fn put_u64<S: ByteSink>(out: &mut S, v: u64) -> Result<(), SerializationError> {
    out.put(&v.to_le_bytes())
}
#[inline]
fn put_fixed<S: ByteSink>(out: &mut S, bytes: &[u8]) -> Result<(), SerializationError> {
    out.put(bytes)
}

/// Prepend the `u8` length byte to a domain context (`len_u8 ‖ ctx`; §10).
#[inline]
pub fn write_context_prefixed<S: ByteSink>(
    out: &mut S,
    ctx: &[u8],
) -> Result<(), SerializationError> {
    debug_assert!(ctx.len() <= u8::MAX as usize, "context > 255 bytes (§10)");
    put_u8(out, ctx.len() as u8)?;
    put_fixed(out, ctx)
}

// ===========================================================================
// The Canonical Serialization Contract (Threat Model §11) — fallible
// ===========================================================================

/// Injective, length-prefixed, byte-aligned serialization — the property that makes accumulator
/// roots and the receipt-provenance chain reproduce **bit-identically** across recomputers
/// (Yellowpaper §3.8, §22; Threat Model §11).
pub trait CanonicalSerialize {
    /// Append the canonical encoding of `self` to any [`ByteSink`], or fail without truncating.
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError>;

    /// Heap convenience (feature `alloc`): allocate and return the canonical encoding.
    #[cfg(feature = "alloc")]
    fn to_canonical_vec(&self) -> Result<Vec<u8>, SerializationError> {
        let mut out = Vec::new();
        self.serialize_into(&mut out)?;
        Ok(out)
    }
}

/// Byte width of the [`ChainId`] chain-domain binding folded into every signing preimage (RECON-15).
pub const CHAIN_ID_LEN: usize = 4;

/// The network this build signs and verifies for (RECON-15). Folding it into every preimage (below)
/// makes a signature minted on one network mathematically invalid on another — a Testnet receipt or
/// handshake cannot be replayed to desynchronize a Mainnet node's state or trigger its slashing. A
/// per-network build selects the constant; the wire also carries it in [`FrameHeader`] for cheap
/// pre-verification rejection.
///
/// **Track A / P4 (fail-closed default):** the default build binds **testnet** — the alpha ships
/// testnet, and a mainnet-domain default is the exact misconfiguration the review flagged. Opt into
/// mainnet only with `--features mainnet`. `goatd` additionally refuses to boot when `genesis.json`
/// declares a different chain than this compiled constant, so a testnet daemon can never mint a
/// mainnet-domain signature (and vice-versa) even under a mismatched config.
#[cfg(feature = "mainnet")]
pub const ACTIVE_CHAIN_ID: ChainId = crate::types::CHAIN_ID_GOAT_MAINNET;
/// Default (no `mainnet` feature): bind the testnet chain id. See the mainnet variant above.
#[cfg(not(feature = "mainnet"))]
pub const ACTIVE_CHAIN_ID: ChainId = crate::types::CHAIN_ID_GOAT_TESTNET;

/// Heap signing preimage `len_u8 ‖ ctx ‖ chain_id_le ‖ body` (feature `alloc`). RECON-15: the
/// `chain_id` is bound *between* the domain context and the body, so it separates networks for the
/// same message class exactly as the context separates message classes.
#[cfg(feature = "alloc")]
#[inline]
pub fn preimage<T: CanonicalSerialize>(
    value: &T,
    ctx: &[u8],
) -> Result<Vec<u8>, SerializationError> {
    let mut out = Vec::new();
    write_context_prefixed(&mut out, ctx)?;
    put_u32(&mut out, ACTIVE_CHAIN_ID)?; // RECON-15 cross-chain replay guard
    value.serialize_into(&mut out)?;
    Ok(out)
}

/// Zero-allocation signing preimage into a caller sink: `len_u8 ‖ ctx ‖ chain_id_le ‖ body`
/// (RECON-15). Every ML-DSA-65 signature path routes through here (directly or via
/// `*::write_signing_preimage`), so the chain binding is universal — handshakes, capability records,
/// receipts, escalations, telemetry.
#[inline]
pub fn write_preimage<T: CanonicalSerialize, S: ByteSink>(
    value: &T,
    ctx: &[u8],
    out: &mut S,
) -> Result<(), SerializationError> {
    write_context_prefixed(out, ctx)?;
    put_u32(out, ACTIVE_CHAIN_ID)?; // RECON-15 cross-chain replay guard
    value.serialize_into(out)
}

// --- Element impls (enable BoundedVec<T> serialization) --------------------

impl CanonicalSerialize for u16 {
    #[inline]
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        put_u16(out, *self)
    }
}

impl CanonicalSerialize for [u8; 32] {
    #[inline]
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        put_fixed(out, self) // fixed-width — no length prefix
    }
}

impl<T: CanonicalSerialize + Copy + Default, const N: usize> CanonicalSerialize
    for BoundedVec<T, N>
{
    #[inline]
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        put_u32(out, self.len() as u32)?; // count prefix (§11.2)
        for item in self.as_slice() {
            item.serialize_into(out)?;
        }
        Ok(())
    }
}

impl CanonicalSerialize for OpaqueTag {
    #[inline]
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        let b = self.as_bytes();
        put_u32(out, b.len() as u32)?; // length-prefixed opaque bytes (§11.2)
        put_fixed(out, b)
    }
}

impl CanonicalSerialize for DeviceCapability {
    #[inline]
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        self.task_class_id.serialize_into(out)?;
        put_u64(out, self.measured_gcu_per_hour)?;
        put_fixed(out, &self.determinism_profile_ref)
    }
}

// --- Telemetry frames ------------------------------------------------------

impl CanonicalSerialize for FrameHeader {
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        put_u16(out, self.schema_version)?;
        put_u8(out, self.frame_type)?;
        put_fixed(out, &self.endpoint_pseudonym)?;
        put_u16(out, self.identity_index)?;
        put_u64(out, self.epoch)?;
        put_fixed(out, &self.run_nonce)?;
        put_u32(out, self.chain_id) // RECON-15: wire-visible network tag
    }
}

impl CanonicalSerialize for EndpointDensity {
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        put_fixed(out, &self.endpoint_pseudonym)?;
        put_u8(out, self.ceil_sust_bin)?;
        put_u8(out, self.ceil_peak_bin)?;
        put_u8(out, self.ceil_oper_bin)?;
        put_u8(out, self.ceil_phys_bin)?;
        put_u64(out, self.shape_delta_ppm)?;
        put_u64(out, self.d_ppm)
    }
}

impl CanonicalSerialize for NetworkDensityFrame {
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        self.header.serialize_into(out)?;
        put_u16(out, self.tick_index)?;
        put_u8(out, self.dl_bin)?;
        put_u8(out, self.ul_bin)?;
        put_u8(out, self.concurrent_flag)?;
        put_u8(out, self.agg_dl_bin)?;
        put_u8(out, self.agg_ul_bin)?;
        for &rtt in &self.rtt_q {
            put_u16(out, rtt)?; // fixed-width [u16; 8] — no length prefix
        }
        put_u8(out, self.origin_change_count)?;
        put_u8(out, self.shared_origin_degree_bin)?;
        put_u8(out, self.xfer_bytes_bin)?;
        put_u8(out, self.morphology_id)?;
        put_u8(out, self.peak_micro_bin)?;
        put_u8(out, self.crest_eighth_oct)?;
        put_u32(out, self.duty_ppm)?;
        put_u8(out, self.throttle_onset_s)?;
        put_u8(out, self.pre_bin)?;
        put_u8(out, self.post_bin)
    }
}

impl CanonicalSerialize for PresenceAvailabilityFrame {
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        self.header.serialize_into(out)?;
        put_u64(out, self.presence_bitmap)?;
        put_u8(out, self.rise_edges)?;
        put_u8(out, self.fall_edges)?;
        self.edge_ticks.serialize_into(out)?; // count prefix + u16 elements (§9)
        put_u8(out, self.local_hour)
    }
}

// --- Signable bodies -------------------------------------------------------

impl CanonicalSerialize for CapabilityRecord {
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        put_fixed(out, &self.node_id)?;
        put_u64(out, self.epoch)?;
        put_fixed(out, &self.beacon_nonce)?;
        put_fixed(out, &self.prev_record)?;
        self.capabilities.serialize_into(out)?;
        put_u64(out, self.availability_ppm)?;
        put_u32(out, self.power_thermal_envelope.power_mw)?;
        put_u32(out, self.power_thermal_envelope.thermal_dk)?;
        put_u64(out, self.density_witness_ppm)
    }
}

impl CanonicalSerialize for ExecutionAttestation {
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        // Amended core order (RECON-07): node_id first (identity binding); outcome flags absent.
        put_fixed(out, &self.node_id)?;
        self.class_id.serialize_into(out)?;
        self.task_class_id.serialize_into(out)?;
        put_u64(out, self.window)?;
        put_u32(out, self.sub_window)?;
        put_fixed(out, &self.cluster_id)?;
        put_u32(out, self.asn)?;
        put_fixed(out, &self.result_commit)
    }
}

// --- Signed outer wrappers (committed-container domain separation, RECON-05) ---

impl<T: CanonicalSerialize> CanonicalSerialize for SignedRecord<T> {
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        write_context_prefixed(out, CTX_GOAT_SIGNED_RECORD_WRAPPER)?;
        self.payload.serialize_into(out)?;
        put_fixed(out, &self.public_key)?;
        put_fixed(out, &self.signature)
    }
}

impl CanonicalSerialize for SignedReceipt {
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        write_context_prefixed(out, CTX_GOAT_SIGNED_RECEIPT_WRAPPER)?;
        self.attestation.serialize_into(out)?;
        put_fixed(out, &self.public_key)?;
        put_fixed(out, &self.signature)
    }
}

// --- Verification-plane structures (§18.2 / §18.3, RECON-07) ----------------

impl CanonicalSerialize for AuthorizationSet {
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        put_u64(out, self.window)?;
        self.task_class_id.serialize_into(out)?;
        self.executors.serialize_into(out) // count-prefixed [u8; 32] identities
    }
}

impl CanonicalSerialize for EscalatedResult {
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        self.receipt.serialize_into(out)?; // receipt and its trace are fused — no positional desync
        put_fixed(out, &self.raw_trace_commit)
    }
}

impl CanonicalSerialize for EscalationRecord {
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        // Canonical order: class_id, then the three fused (receipt, trace) results.
        self.class_id.serialize_into(out)?;
        for result in &self.results {
            result.serialize_into(out)?;
        }
        Ok(())
    }
}

// ===========================================================================
// Per-struct signing preimages + exact serialized-size bounds
// ===========================================================================

/// Max serialized body of an [`ExecutionAttestation`] — RECON-07 adds `node_id` (`+32`): now
/// `152 + 32 = 184` B (node_id 32 + 2×OpaqueTag 72 + window 8 + sub 4 + cluster 32 + asn 4 +
/// commit 32).
pub const EXEC_ATTESTATION_MAX_BODY_LEN: usize = 184;
/// Max exec preimage: body + `len_u8 ‖ CTX_GOAT_EXEC_ATTESTATION ‖ chain_id` (RECON-15 adds
/// [`CHAIN_ID_LEN`]).
pub const EXEC_ATTESTATION_MAX_PREIMAGE_LEN: usize =
    EXEC_ATTESTATION_MAX_BODY_LEN + 1 + CTX_GOAT_EXEC_ATTESTATION.len() + CHAIN_ID_LEN;

/// Max serialized body of a fully-populated [`CapabilityRecord`]: `740` B.
pub const CAPABILITY_RECORD_MAX_BODY_LEN: usize = 740;
/// Max capability preimage: body + `len_u8 ‖ CTX_GOAT_CAPABILITY_RECORD ‖ chain_id` (RECON-15 adds
/// [`CHAIN_ID_LEN`]).
pub const CAPABILITY_RECORD_MAX_PREIMAGE_LEN: usize =
    CAPABILITY_RECORD_MAX_BODY_LEN + 1 + CTX_GOAT_CAPABILITY_RECORD.len() + CHAIN_ID_LEN;

/// Max serialized [`SignedReceipt`] (wrapper ctx + max attestation + ML-DSA key + signature).
pub const SIGNED_RECEIPT_MAX_LEN: usize = 1
    + CTX_GOAT_SIGNED_RECEIPT_WRAPPER.len()
    + EXEC_ATTESTATION_MAX_BODY_LEN
    + ML_DSA_65_PUBLIC_KEY_LEN
    + ML_DSA_65_SIGNATURE_LEN;

/// Max serialized body of an [`AuthorizationSet`] (task tag + executor set at capacity).
pub const AUTHORIZATION_SET_MAX_BODY_LEN: usize =
    8 + (4 + OPAQUE_TAG_CAP) + (4 + MAX_AUTHORIZED_EXECUTORS * 32);
/// Max authorization preimage: body + `len_u8 ‖ CTX_GOAT_ASSIGNMENT_LOG ‖ chain_id` (RECON-15).
pub const AUTHORIZATION_SET_MAX_PREIMAGE_LEN: usize =
    AUTHORIZATION_SET_MAX_BODY_LEN + 1 + CTX_GOAT_ASSIGNMENT_LOG.len() + CHAIN_ID_LEN;

/// Max serialized [`EscalatedResult`] (a fused receipt + its 32-byte trace commitment).
pub const ESCALATED_RESULT_MAX_LEN: usize = SIGNED_RECEIPT_MAX_LEN + 32;
/// Max serialized body of an [`EscalationRecord`] (class tag + 3 fused results). Large by nature —
/// three full ML-DSA receipts; a constrained verifier may prefer the heap path.
pub const ESCALATION_RECORD_MAX_BODY_LEN: usize =
    (4 + OPAQUE_TAG_CAP) + 3 * ESCALATED_RESULT_MAX_LEN;
/// Max escalation preimage: body + `len_u8 ‖ CTX_GOAT_ESCALATION_RECORD ‖ chain_id` (RECON-15).
pub const ESCALATION_RECORD_MAX_PREIMAGE_LEN: usize =
    ESCALATION_RECORD_MAX_BODY_LEN + 1 + CTX_GOAT_ESCALATION_RECORD.len() + CHAIN_ID_LEN;

impl ExecutionAttestation {
    /// Heap signing preimage bound to `CTX_GOAT_EXEC_ATTESTATION` (feature `alloc`).
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn signing_preimage(&self) -> Result<Vec<u8>, SerializationError> {
        preimage(self, CTX_GOAT_EXEC_ATTESTATION)
    }
    /// Zero-allocation preimage (size with [`EXEC_ATTESTATION_MAX_PREIMAGE_LEN`]).
    #[inline]
    pub fn write_signing_preimage<S: ByteSink>(
        &self,
        out: &mut S,
    ) -> Result<(), SerializationError> {
        write_preimage(self, CTX_GOAT_EXEC_ATTESTATION, out)
    }
}

impl CapabilityRecord {
    /// Heap signing preimage bound to `CTX_GOAT_CAPABILITY_RECORD` (feature `alloc`).
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn signing_preimage(&self) -> Result<Vec<u8>, SerializationError> {
        preimage(self, CTX_GOAT_CAPABILITY_RECORD)
    }
    /// Zero-allocation preimage (size with [`CAPABILITY_RECORD_MAX_PREIMAGE_LEN`]).
    #[inline]
    pub fn write_signing_preimage<S: ByteSink>(
        &self,
        out: &mut S,
    ) -> Result<(), SerializationError> {
        write_preimage(self, CTX_GOAT_CAPABILITY_RECORD, out)
    }
}

impl AuthorizationSet {
    /// Heap signing preimage bound to `CTX_GOAT_ASSIGNMENT_LOG` (feature `alloc`).
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn signing_preimage(&self) -> Result<Vec<u8>, SerializationError> {
        preimage(self, CTX_GOAT_ASSIGNMENT_LOG)
    }
    /// Zero-allocation preimage (size with [`AUTHORIZATION_SET_MAX_PREIMAGE_LEN`]).
    #[inline]
    pub fn write_signing_preimage<S: ByteSink>(
        &self,
        out: &mut S,
    ) -> Result<(), SerializationError> {
        write_preimage(self, CTX_GOAT_ASSIGNMENT_LOG, out)
    }
}

impl EscalationRecord {
    /// Heap signing preimage bound to `CTX_GOAT_ESCALATION_RECORD` (feature `alloc`).
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn signing_preimage(&self) -> Result<Vec<u8>, SerializationError> {
        preimage(self, CTX_GOAT_ESCALATION_RECORD)
    }
    /// Zero-allocation preimage (size with [`ESCALATION_RECORD_MAX_PREIMAGE_LEN`]).
    #[inline]
    pub fn write_signing_preimage<S: ByteSink>(
        &self,
        out: &mut S,
    ) -> Result<(), SerializationError> {
        write_preimage(self, CTX_GOAT_ESCALATION_RECORD, out)
    }
}

// ===========================================================================
// Symmetric Integer Deviation (Yellowpaper §30.1 — verbatim, E1-A1 mandate)
// ===========================================================================

/// `d(prev, cur) = min( 2·|cur − prev|·PPM / max(1, prev + cur), 2·PPM )`. Symmetric, total, and
/// panic-free on all `u64 × u64` (§30.1; verified against A-PF1 and the A-Q2-5b vectors).
pub fn symmetric_deviation_ppm(prev: u64, cur: u64) -> Ppm {
    let abs_diff = cur.abs_diff(prev) as u128; // cast FIRST → no u64 overflow (hyperinflation)
    let sum = prev as u128 + cur as u128; // < 2^65
    let denom = core::cmp::max(1u128, sum); // zero-guard: only prev == cur == 0 reaches 1
    let num = abs_diff * 2 * (PPM as u128); // < 2^85, fits u128
    core::cmp::min(num / denom, SYMMETRIC_DEVIATION_MAX_PPM as u128) as Ppm
}

// ===========================================================================
// §18.2–§18.4 verification plane: registry, verifier, and the fold boundary
// ===========================================================================

/// Abstracts the ML-DSA-65 verification primitive (library-provided, out of audit scope as an
/// algorithm — Threat Model §0) so the fold's *structural* logic is testable independently.
pub trait SignatureVerifier {
    /// `true` iff `signature` is a valid ML-DSA-65 signature over `message` under `public_key`.
    fn verify_ml_dsa_65(
        &self,
        public_key: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
        message: &[u8],
        signature: &[u8; ML_DSA_65_SIGNATURE_LEN],
    ) -> bool;
}

/// The active authorized/staked key set (§18.2, A-CI3). **RECON-07:** keyed on both `public_key`
/// **and** `node_id` — it returns `true` only if `public_key` is the currently-staked key
/// *registered for* `node_id`. This binding is what makes the plagiarism closure sufficient: a
/// valid signature under an attacker's staked key over a core claiming a *different* node's id
/// fails here (adding `node_id` to the signed core is necessary; this check is what closes it). A
/// production impl backs this with the on-ledger registry / stake set.
pub trait KeyRegistry {
    /// `true` iff `public_key` is the currently-staked key registered for `node_id`.
    fn is_authorized(
        &self,
        public_key: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
        node_id: &[u8; 32],
    ) -> bool;
}

/// Normalize `representation_weight_bp` across `attrs` to sum **exactly** `BP_FULL`, by the
/// largest-remainder (Hare-quota) method — pure-integer, deterministic, heap-free (Appendix A,
/// contract 4). Empty ⇒ nothing to do; all-zero counts ⇒ all-zero weights.
fn normalize_weights_largest_remainder(attrs: &mut [AggregatedAttribution]) {
    let n = attrs.len();
    if n == 0 {
        return;
    }
    let mut grand_total: u64 = 0;
    for a in attrs.iter() {
        grand_total = grand_total.saturating_add(a.total_verified_gcu_hours);
    }
    if grand_total == 0 {
        for a in attrs.iter_mut() {
            a.representation_weight_bp = 0;
        }
        return;
    }

    // Floored quota + remainder for each item. `prod` is `u128` (count·BP_FULL cannot fit u64).
    let mut rem = [0u64; MAX_ATTRIBUTIONS_PER_FOLD];
    let mut floored_sum: u32 = 0;
    for (i, a) in attrs.iter_mut().enumerate() {
        let prod = a.total_verified_gcu_hours as u128 * BP_FULL as u128;
        let w = (prod / grand_total as u128) as u32; // < BP_FULL
        rem[i] = (prod % grand_total as u128) as u64; // < grand_total ≤ u64::MAX
        a.representation_weight_bp = w;
        floored_sum = floored_sum.saturating_add(w);
    }

    // Deficit D = BP_FULL − Σfloor ∈ [0, n): distribute +1 bp to the D largest remainders.
    let deficit = BP_FULL.saturating_sub(floored_sum) as usize;
    if deficit == 0 {
        return;
    }
    let mut idx = [0usize; MAX_ATTRIBUTIONS_PER_FOLD];
    for (i, slot) in idx.iter_mut().enumerate().take(n) {
        *slot = i;
    }
    // Remainder descending; index ascending tie-break ⇒ fully deterministic (no alloc).
    idx[..n].sort_unstable_by(|&a, &b| rem[b].cmp(&rem[a]).then(a.cmp(&b)));
    for &i in &idx[..deficit.min(n)] {
        attrs[i].representation_weight_bp = attrs[i].representation_weight_bp.saturating_add(1);
    }
}

/// `fold_verified_attributed` (§18.4): fold signed receipts for one window into per-cluster
/// attributions — **no element is trusted rather than checked**. A receipt is counted only if
/// (a) its window matches, (b) its `(public_key, node_id)` is a currently-staked registered pair
/// (RECON-06/07 #1, [`KeyRegistry`] — closes the self-signed Sybil flood *and* the plagiarism
/// vector), (c) its `node_id` is **locally assigned** to this window/task by the orchestrator
/// (RECON-07 Deliverable 2, [`AuthorizationSet`]), and (d) its signature re-verifies over the
/// stack-rebuilt, context-bound preimage. Window/authz/signature failures are skipped (normal
/// conditions); a serialization or attribution-set overflow is a *reported* error, never a silent
/// drop. Weights sum to exactly `BP_FULL` (RECON-06 #2, largest remainder).
pub fn fold_verified_attributed<V: SignatureVerifier, R: KeyRegistry>(
    receipts: &[SignedReceipt],
    target_window: Epoch,
    verifier: &V,
    registry: &R,
    authorization: &AuthorizationSet,
) -> Result<BoundedVec<AggregatedAttribution, MAX_ATTRIBUTIONS_PER_FOLD>, SerializationError> {
    let mut accumulated: BoundedVec<AggregatedAttribution, MAX_ATTRIBUTIONS_PER_FOLD> =
        BoundedVec::new();
    let mut scratch = [0u8; EXEC_ATTESTATION_MAX_PREIMAGE_LEN];

    for receipt in receipts {
        let att = &receipt.attestation;
        if att.window != target_window {
            continue;
        }
        // RECON-07 plagiarism: the key must be staked *and registered for the claimed node_id*.
        if !registry.is_authorized(&receipt.public_key, &att.node_id) {
            continue;
        }
        // RECON-07 Deliverable 2: globally staked ≠ locally assigned. Drop a node the orchestrator
        // did not assign to *this* window/task (§18.2).
        let assigned = authorization.window == target_window
            && att.task_class_id == authorization.task_class_id
            && authorization.executors.as_slice().contains(&att.node_id);
        if !assigned {
            continue;
        }
        // Authenticity: signature over the stack-rebuilt, context-bound preimage (buffer provably
        // max-sized; a real overflow is a fault, propagated with `?`, never a silent skip).
        let mut sink = SliceSink::new(&mut scratch);
        att.write_signing_preimage(&mut sink)?;
        if !verifier.verify_ml_dsa_65(&receipt.public_key, sink.written(), &receipt.signature) {
            continue; // failed signature ⇒ not attributed (a normal adversarial condition)
        }

        let cid = att.cluster_id;
        let mut found = false;
        for attr in accumulated.as_mut_slice() {
            if attr.cluster_id == cid {
                attr.total_verified_gcu_hours = attr.total_verified_gcu_hours.saturating_add(1);
                found = true;
                break;
            }
        }
        if !found {
            accumulated
                .try_push(AggregatedAttribution {
                    cluster_id: cid,
                    total_verified_gcu_hours: 1,
                    representation_weight_bp: 0,
                })
                .map_err(|_| SerializationError::CapacityExceeded)?;
        }
    }

    // RECON-06 #2 — exact conservation: Σ weights == BP_FULL by largest remainder.
    normalize_weights_largest_remainder(accumulated.as_mut_slice());
    Ok(accumulated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PowerThermalEnvelope;

    struct AllowVerifier;
    impl SignatureVerifier for AllowVerifier {
        fn verify_ml_dsa_65(
            &self,
            _pk: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
            _msg: &[u8],
            _sig: &[u8; ML_DSA_65_SIGNATURE_LEN],
        ) -> bool {
            true
        }
    }
    struct AllowRegistry;
    impl KeyRegistry for AllowRegistry {
        fn is_authorized(&self, _pk: &[u8; ML_DSA_65_PUBLIC_KEY_LEN], _node: &[u8; 32]) -> bool {
            true
        }
    }
    struct DenyRegistry;
    impl KeyRegistry for DenyRegistry {
        fn is_authorized(&self, _pk: &[u8; ML_DSA_65_PUBLIC_KEY_LEN], _node: &[u8; 32]) -> bool {
            false
        }
    }

    fn full_exec() -> ExecutionAttestation {
        ExecutionAttestation {
            node_id: [0xEE; 32],
            class_id: OpaqueTag::from_bytes(&[0xAA; 32]).unwrap(),
            task_class_id: OpaqueTag::from_bytes(&[0xBB; 32]).unwrap(),
            window: 0x0102_0304_0506_0708,
            sub_window: 7,
            cluster_id: [0xCC; 32],
            asn: 64_512,
            result_commit: [0xDD; 32],
        }
    }

    fn receipt_for(cluster: u8, node: u8, window: Epoch) -> SignedReceipt {
        SignedReceipt {
            attestation: ExecutionAttestation {
                node_id: [node; 32],
                class_id: OpaqueTag::from_bytes(b"c").unwrap(),
                task_class_id: OpaqueTag::from_bytes(b"t").unwrap(),
                window,
                sub_window: 0,
                cluster_id: [cluster; 32],
                asn: 7,
                result_commit: [0u8; 32],
            },
            public_key: [0u8; ML_DSA_65_PUBLIC_KEY_LEN],
            signature: [0u8; ML_DSA_65_SIGNATURE_LEN],
        }
    }

    fn auth_for(window: Epoch, nodes: &[[u8; 32]]) -> AuthorizationSet {
        AuthorizationSet {
            window,
            task_class_id: OpaqueTag::from_bytes(b"t").unwrap(),
            executors: BoundedVec::from_slice(nodes).unwrap(),
        }
    }

    #[test]
    fn deviation_totality_and_guards() {
        assert_eq!(symmetric_deviation_ppm(0, 0), 0);
        assert_eq!(symmetric_deviation_ppm(5, 5), 0);
        assert_eq!(
            symmetric_deviation_ppm(u64::MAX, 0),
            SYMMETRIC_DEVIATION_MAX_PPM
        );
        assert_eq!(
            symmetric_deviation_ppm(50, 100),
            symmetric_deviation_ppm(100, 50)
        );
    }

    #[test]
    fn contexts_distinct_and_prefixed() {
        let mut buf = [0u8; 64];
        for (i, a) in ALL_CONTEXTS.iter().enumerate() {
            assert!(a.len() <= u8::MAX as usize);
            let mut sink = SliceSink::new(&mut buf);
            write_context_prefixed(&mut sink, a).unwrap();
            assert_eq!(sink.written()[0] as usize, a.len());
            for (j, b) in ALL_CONTEXTS.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn scalars_are_little_endian() {
        let mut buf = [0u8; 4];
        let mut sink = SliceSink::new(&mut buf);
        put_u32(&mut sink, 0x0102_0304).unwrap();
        assert_eq!(sink.written(), &[0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn truncation_is_refused() {
        let att = full_exec();
        let mut tiny = [0u8; 10];
        let mut sink = SliceSink::new(&mut tiny);
        assert_eq!(
            att.write_signing_preimage(&mut sink),
            Err(SerializationError::BufferOverflow)
        );
        assert!(sink.overflowed());
    }

    #[test]
    fn preimage_binds_context_and_separates_domains() {
        let att = full_exec();
        let mut b1 = [0u8; EXEC_ATTESTATION_MAX_PREIMAGE_LEN];
        let mut s1 = SliceSink::new(&mut b1);
        att.write_signing_preimage(&mut s1).unwrap();
        assert!(!s1.overflowed());
        assert_eq!(s1.written()[0] as usize, CTX_GOAT_EXEC_ATTESTATION.len());
        assert_eq!(
            &s1.written()[1..1 + CTX_GOAT_EXEC_ATTESTATION.len()],
            CTX_GOAT_EXEC_ATTESTATION
        );
        let mut b2 = [0u8; CAPABILITY_RECORD_MAX_PREIMAGE_LEN];
        let mut s2 = SliceSink::new(&mut b2);
        write_preimage(&att, CTX_GOAT_CAPABILITY_RECORD, &mut s2).unwrap();
        assert_ne!(s1.written(), s2.written());
    }

    // RECON-07: node_id is inside the signed preimage — flipping it changes the bytes to be signed.
    #[test]
    fn node_id_is_bound_in_preimage() {
        let a = full_exec();
        let mut b = a.clone();
        b.node_id = [0x11; 32];
        let mut ba = [0u8; EXEC_ATTESTATION_MAX_PREIMAGE_LEN];
        let mut bb = [0u8; EXEC_ATTESTATION_MAX_PREIMAGE_LEN];
        let mut sa = SliceSink::new(&mut ba);
        let mut sb = SliceSink::new(&mut bb);
        a.write_signing_preimage(&mut sa).unwrap();
        b.write_signing_preimage(&mut sb).unwrap();
        assert_ne!(sa.written(), sb.written());
    }

    // RECON-15: ACTIVE_CHAIN_ID is bound into the preimage between the context and the body
    // (`len_u8 ‖ ctx ‖ chain_id_le ‖ body`), so a signature minted for one network cannot validate
    // on another — cross-chain replay protection.
    #[test]
    fn chain_id_is_bound_in_preimage() {
        let att = full_exec();
        let mut buf = [0u8; EXEC_ATTESTATION_MAX_PREIMAGE_LEN];
        let mut s = SliceSink::new(&mut buf);
        att.write_signing_preimage(&mut s).unwrap();
        let w = s.written();
        let off = 1 + CTX_GOAT_EXEC_ATTESTATION.len();
        // The preimage embeds whichever network this build compiled for (default = testnet).
        assert_eq!(&w[off..off + CHAIN_ID_LEN], &ACTIVE_CHAIN_ID.to_le_bytes());
        // The two domains are distinct, so a signature minted on one cannot validate on the other.
        assert_ne!(
            crate::types::CHAIN_ID_GOAT_MAINNET.to_le_bytes(),
            crate::types::CHAIN_ID_GOAT_TESTNET.to_le_bytes()
        );
    }

    #[test]
    fn presence_frame_bounded_edges_wire_len() {
        let paf = PresenceAvailabilityFrame {
            header: FrameHeader {
                schema_version: 2,
                frame_type: crate::types::frame_type::PAF,
                endpoint_pseudonym: [7u8; 32],
                identity_index: 3,
                epoch: 42,
                run_nonce: [9u8; 32],
                chain_id: crate::types::CHAIN_ID_GOAT_MAINNET,
            },
            presence_bitmap: 0xABCD,
            rise_edges: 2,
            fall_edges: 1,
            edge_ticks: BoundedVec::from_slice(&[4u16, 8, 15]).unwrap(),
            local_hour: 13,
        };
        let mut buf = [0u8; 256];
        let mut sink = SliceSink::new(&mut buf);
        paf.serialize_into(&mut sink).unwrap();
        // Header 77 + chain_id 4 (RECON-15) + bitmap 8 + rise 1 + fall 1 + 2×3 edges + hour 1.
        assert_eq!(sink.len(), (77 + 4) + 8 + 1 + 1 + 4 + 6 + 1);
    }

    #[test]
    fn capability_record_within_max_body() {
        let cap = DeviceCapability {
            task_class_id: OpaqueTag::from_bytes(&[1u8; 32]).unwrap(),
            measured_gcu_per_hour: u64::MAX,
            determinism_profile_ref: [2u8; 32],
        };
        let mut caps = BoundedVec::new();
        for _ in 0..crate::types::MAX_CAPABILITIES {
            caps.try_push(cap).unwrap();
        }
        let rec = CapabilityRecord {
            node_id: [3u8; 32],
            epoch: u64::MAX,
            beacon_nonce: [4u8; 32],
            prev_record: [5u8; 32],
            capabilities: caps,
            availability_ppm: PPM,
            power_thermal_envelope: PowerThermalEnvelope {
                power_mw: u32::MAX,
                thermal_dk: u32::MAX,
            },
            density_witness_ppm: PPM,
        };
        let mut buf = [0u8; CAPABILITY_RECORD_MAX_BODY_LEN];
        let mut sink = SliceSink::new(&mut buf);
        rec.serialize_into(&mut sink).unwrap();
        assert!(!sink.overflowed());
    }

    #[test]
    fn fold_accumulates_and_weights() {
        let r = receipt_for(9, 1, 50);
        let receipts = [r.clone(), r];
        let auth = auth_for(50, &[[1u8; 32]]);
        let out =
            fold_verified_attributed(&receipts, 50, &AllowVerifier, &AllowRegistry, &auth).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out.as_slice()[0].total_verified_gcu_hours, 2);
        assert_eq!(out.as_slice()[0].representation_weight_bp, BP_FULL);
    }

    #[test]
    fn fold_filters_window() {
        let receipt = SignedReceipt {
            attestation: full_exec(), // window != 50
            public_key: [0u8; ML_DSA_65_PUBLIC_KEY_LEN],
            signature: [0u8; ML_DSA_65_SIGNATURE_LEN],
        };
        let auth = auth_for(50, &[[0xEE; 32]]);
        let out = fold_verified_attributed(&[receipt], 50, &AllowVerifier, &AllowRegistry, &auth)
            .unwrap();
        assert!(out.is_empty());
    }

    // RECON-06 #1: a valid signature over an unregistered key is dropped.
    #[test]
    fn fold_drops_unregistered_keys() {
        let receipts = [receipt_for(1, 1, 50), receipt_for(1, 1, 50)];
        let auth = auth_for(50, &[[1u8; 32]]);
        let out =
            fold_verified_attributed(&receipts, 50, &AllowVerifier, &DenyRegistry, &auth).unwrap();
        assert!(out.is_empty());
    }

    // RECON-07 Deliverable 2: globally staked but not assigned to this window/task ⇒ dropped.
    #[test]
    fn fold_drops_unassigned_node() {
        let receipts = [receipt_for(1, 7, 50)]; // node 7
        let auth = auth_for(50, &[[1u8; 32], [2u8; 32]]); // node 7 is not an authorized executor
        let out =
            fold_verified_attributed(&receipts, 50, &AllowVerifier, &AllowRegistry, &auth).unwrap();
        assert!(out.is_empty());
    }

    // RECON-06 #2: three equal clusters ⇒ weights [3334, 3333, 3333], summing exactly BP_FULL.
    #[test]
    fn fold_weights_sum_to_bp_full() {
        let receipts = [
            receipt_for(1, 1, 50),
            receipt_for(2, 2, 50),
            receipt_for(3, 3, 50),
        ];
        let auth = auth_for(50, &[[1u8; 32], [2u8; 32], [3u8; 32]]);
        let out =
            fold_verified_attributed(&receipts, 50, &AllowVerifier, &AllowRegistry, &auth).unwrap();
        assert_eq!(out.len(), 3);
        let sum: u32 = out
            .as_slice()
            .iter()
            .map(|a| a.representation_weight_bp)
            .sum();
        assert_eq!(sum, BP_FULL);
        assert_eq!(out.as_slice()[0].representation_weight_bp, 3334);
        assert_eq!(out.as_slice()[1].representation_weight_bp, 3333);
        assert_eq!(out.as_slice()[2].representation_weight_bp, 3333);
    }

    #[test]
    fn authorization_set_preimage_binds_context() {
        let mut execs = BoundedVec::new();
        execs.try_push([1u8; 32]).unwrap();
        execs.try_push([2u8; 32]).unwrap();
        let auth = AuthorizationSet {
            window: 99,
            task_class_id: OpaqueTag::from_bytes(b"t").unwrap(),
            executors: execs,
        };
        let mut buf = [0u8; AUTHORIZATION_SET_MAX_PREIMAGE_LEN];
        let mut sink = SliceSink::new(&mut buf);
        auth.write_signing_preimage(&mut sink).unwrap();
        assert!(!sink.overflowed());
        assert_eq!(sink.written()[0] as usize, CTX_GOAT_ASSIGNMENT_LOG.len());
        assert_eq!(
            &sink.written()[1..1 + CTX_GOAT_ASSIGNMENT_LOG.len()],
            CTX_GOAT_ASSIGNMENT_LOG
        );
    }

    #[test]
    fn escalation_record_fused_preimage_binds_context() {
        let mk = |c, n| EscalatedResult {
            receipt: receipt_for(c, n, 50),
            raw_trace_commit: [c; 32],
        };
        let esc = EscalationRecord {
            class_id: OpaqueTag::from_bytes(b"cls").unwrap(),
            results: [mk(1, 1), mk(2, 2), mk(3, 3)],
        };
        let mut buf = [0u8; ESCALATION_RECORD_MAX_PREIMAGE_LEN];
        let mut sink = SliceSink::new(&mut buf);
        esc.write_signing_preimage(&mut sink).unwrap();
        assert!(!sink.overflowed());
        assert_eq!(sink.written()[0] as usize, CTX_GOAT_ESCALATION_RECORD.len());
        assert_eq!(
            &sink.written()[1..1 + CTX_GOAT_ESCALATION_RECORD.len()],
            CTX_GOAT_ESCALATION_RECORD
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn heap_path_matches_stack() {
        let att = full_exec();
        let heap = att.to_canonical_vec().unwrap();
        let mut buf = [0u8; EXEC_ATTESTATION_MAX_BODY_LEN];
        let mut sink = SliceSink::new(&mut buf);
        att.serialize_into(&mut sink).unwrap();
        assert_eq!(sink.written(), heap.as_slice());
    }
}
