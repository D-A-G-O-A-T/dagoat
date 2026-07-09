//! `types.rs` — Pure-integer primitives, fixed-point aliases, bounded no-alloc containers, and
//! the F5 telemetry + signed wire state types.
//!
//! Phase-3 scaffolding. Every declaration is a faithful, field-exact translation of a layout
//! **sealed** in `GoatCoin_Yellowpaper.md` v1.0 (Appendix A fixed-point contracts; §11
//! `CapabilityRecord`; §18.1 `ExecutionAttestation` attributable core) and the F5 Empirical Study
//! design (frame schemas §1/§8/§9; §20 reductions, as amended F5-A1/A2). No field is invented and
//! no locked invariant is altered.
//!
//! ## `no_std` + zero heap (RECON-04 refinement)
//!
//! This module is **fully `no_std` and allocation-free**: the previously heap-backed
//! `edge_ticks: Vec<u16>` is replaced by [`BoundedVec`], a stack-resident, fixed-capacity
//! container, so no telemetry or receipt type touches the allocator on a fast-path verification
//! loop. The crate root must still declare `#![no_std]` and `#![forbid(unsafe_code)]`; `alloc` is
//! required only by `crypto.rs`'s heap *convenience* serializers, never by these types.
//!
//! ## In-memory layout vs. wire layout
//!
//! Struct field order below is the **spec-declared serialization order** (Appendix A, contract 5)
//! and is load-bearing for the canonical encoder in `crypto.rs`. The encoder walks fields
//! explicitly, so the *in-memory* representation (padding, alignment) never reaches the wire —
//! cross-architecture byte-identity is a property of the encoder, not of `#[repr]`.

// ===========================================================================
// Fixed-point integer aliases (Yellowpaper Appendix A.1)
// ===========================================================================

/// Parts-per-million multiplier. `PPM` (`1_000_000`) encodes `1.0`. (Appendix A.1)
pub type Ppm = u64;

/// Basis-point weight. `BP_FULL` (`10_000`) encodes `100%`. (Appendix A.1)
pub type Bp = u32;

/// Money rate in micro-USD: `1` == `10⁻⁶ USD`. (Appendix A.1)
pub type MicroUsd = u64;

/// Protocol time: `1` == one beacon epoch. (Appendix A.1)
pub type Epoch = u64;

/// Network domain identifier (RECON-15 cross-chain replay protection). It is bound into every
/// signing preimage (see `crypto::write_preimage`) and carried in [`FrameHeader`], so a signature
/// minted for one network mathematically invalidates on another — a Testnet receipt or handshake can
/// never be replayed against a Mainnet node to desynchronize its state or trigger slashing.
pub type ChainId = u32;

/// GoatCoin **Mainnet** chain id — the active network for a Mainnet build.
pub const CHAIN_ID_GOAT_MAINNET: ChainId = 0x60A7_0001;
/// GoatCoin **Testnet** chain id.
pub const CHAIN_ID_GOAT_TESTNET: ChainId = 0x60A7_7E57;

/// A **strictly advisory** stake floor emitted by the fault market on saturation (ARC-01-M12, H-3).
///
/// This is a deliberate **type-level tripwire**. It implements **no ordering** (`Ord`/`PartialOrd`),
/// no arithmetic, no `Deref`, and no `From<AdvisoryStakeFloor> for u64` — so a comparison of the
/// shape `node_stake >= floor` (the shape of a participation gate) **does not type-check**. The only
/// way to read the value is [`fee_market_hint`](Self::fee_market_hint), whose deliberately narrow
/// name makes any use at a participation, registration, or challenge gateway self-evidently wrong in
/// review and trivially greppable.
///
/// **Rationale.** The two-lane fair market ([`state::apply_epoch_penalties`](crate)) structurally
/// protects small actors, but the floor is emitted publicly; letting it gate participation would
/// re-introduce exactly the plutocratic censorship the market exists to prevent (ARC-01, H-3). It is
/// for **fee-priority / telemetry consumers only**.
///
/// **Invariant (do not weaken):** never derive `PartialOrd`/`Ord`, never add a `u64`/`MicroUsd`
/// `From`/`Into`/`Deref`, never expose the inner value except via [`fee_market_hint`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AdvisoryStakeFloor(MicroUsd);

impl AdvisoryStakeFloor {
    /// The unsaturated floor — no floor was raised this epoch.
    pub const NONE: Self = Self(0);

    /// Wrap a raw floor value. Constructed by the fault market only.
    #[inline]
    pub const fn new(micro_usd: MicroUsd) -> Self {
        Self(micro_usd)
    }

    /// Extract the value **strictly for fee-market / informational consumers** (ARC-01-M12). The
    /// narrow name is an intentional speed-bump: `fee_market_hint()` appearing at a participation,
    /// registration, or challenge gate is self-evident misuse. Because the type carries no comparison
    /// operators, *any* gating decision must route through this explicit, greppable, audit-visible
    /// call — it can never happen silently.
    #[inline]
    pub const fn fee_market_hint(self) -> MicroUsd {
        self.0
    }

    /// Whether saturation raised a floor this epoch — a **boolean** signal only, so no magnitude can
    /// silently flow into a gating comparison.
    #[inline]
    pub const fn is_raised(self) -> bool {
        self.0 > 0
    }
}

// ===========================================================================
// Fixed-point scale constants (Appendix A.1) and structural bounds (§30.1)
// ===========================================================================

/// Unity in `Ppm` fixed-point. (Appendix A.1)
pub const PPM: Ppm = 1_000_000;

/// `100%` in `Bp` fixed-point. (Appendix A.1)
pub const BP_FULL: Bp = 10_000;

/// The ±200% structural cap on a single symmetric deviation (§30.1).
pub const SYMMETRIC_DEVIATION_MAX_PPM: Ppm = 2_000_000;

// ===========================================================================
// Container capacity bounds (RECON-04: heap-free, statically bounded)
// ===========================================================================

/// Max capacity of an opaque device/task-class tag (`"cls.a.v1"`-style, §3.5). Generous for the
/// short opaque strings the protocol carries but never interprets.
pub const OPAQUE_TAG_CAP: usize = 32;

/// Max presence-transition edges in one PAF. Presence is a `u64` bitmap (≤ 60 used ticks; §9), so
/// the number of `0↔1` transitions cannot exceed the bit width — `64` is a hard structural bound.
pub const MAX_EDGE_TICKS: usize = 64;

/// Max measured per-(device, task-class) capability entries in one `CapabilityRecord` (§11).
pub const MAX_CAPABILITIES: usize = 8;

/// Max distinct operator clusters aggregated in one fold boundary (§18.4). A fold that would
/// exceed this is a *reported* `SerializationError::CapacityExceeded`, never a silent drop.
pub const MAX_ATTRIBUTIONS_PER_FOLD: usize = 32;

/// Max authorized executor identities in one `AuthorizationSet` (§18.2). Redundant executor sets
/// are small (spread rule ≥ m clusters); this bounds a window/task-class authorization heap-free.
pub const MAX_AUTHORIZED_EXECUTORS: usize = 16;

/// Max distinct faulted nodes aggregated in one epoch's slashing pipeline (RECON-10). Deliberately
/// far larger than `MAX_ATTRIBUTIONS_PER_FOLD` so a Sybil fault-flood cannot saturate the queue and
/// let real nodes escape penalty; **exceeding it is fail-closed** — a `StateError::FaultSaturationPanic`,
/// never a silent drop. NB: a `BoundedVec<_, 1024>` is a multi-KB stack object (an accessibility /
/// constrained-verifier consideration; the epoch ratchet is not the fast path).
pub const MAX_FAULTS_PER_EPOCH: usize = 1024;

// ===========================================================================
// Cryptographic footprints — FIPS 204 ML-DSA-65 (fixed-width, compile-time known)
// ===========================================================================

/// ML-DSA-65 public-key length in bytes (FIPS 204). Fixed-width so stack sizes are deterministic.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
/// ML-DSA-65 signature length in bytes (FIPS 204). Fixed-width, verified at compile time.
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;

// ===========================================================================
// Bounded, stack-resident container (replaces `alloc::vec::Vec` on the fast path)
// ===========================================================================

/// Returned when a bounded container is pushed past its capacity. Totality is preserved — the
/// caller decides; nothing panics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityError;

/// A fixed-capacity, heap-free vector: `N` inline slots plus a length. `T: Copy + Default` so the
/// backing array is initialized without `unsafe`. Unused slots are always `Default`
/// (zero-equivalent) and never observed — equality and `Debug` read only the active prefix.
#[derive(Clone)]
pub struct BoundedVec<T: Copy + Default, const N: usize> {
    buf: [T; N],
    len: u16,
}

impl<T: Copy + Default, const N: usize> BoundedVec<T, N> {
    /// An empty container (all slots `Default`).
    #[inline]
    pub fn new() -> Self {
        Self {
            buf: [T::default(); N],
            len: 0,
        }
    }

    /// Build from a slice, or `None` if it exceeds capacity `N`.
    #[inline]
    pub fn from_slice(items: &[T]) -> Option<Self> {
        if items.len() > N {
            return None;
        }
        let mut v = Self::new();
        v.buf[..items.len()].copy_from_slice(items);
        v.len = items.len() as u16;
        Some(v)
    }

    /// Append one item, or `Err(CapacityError)` if full. Never panics.
    #[inline]
    pub fn try_push(&mut self, item: T) -> Result<(), CapacityError> {
        let i = self.len as usize;
        if i >= N {
            return Err(CapacityError);
        }
        self.buf[i] = item;
        self.len += 1;
        Ok(())
    }

    /// The active elements.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.buf[..self.len as usize]
    }

    /// The active elements, mutably — for in-place fold accumulation (§18.4) without exposing the
    /// private backing array across module boundaries.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.buf[..self.len as usize]
    }

    /// Number of active elements.
    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// `true` iff empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The compile-time capacity `N`.
    #[inline]
    pub const fn capacity() -> usize {
        N
    }
}

impl<T: Copy + Default, const N: usize> Default for BoundedVec<T, N> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// Equality/Debug read only the active prefix, so trailing default slots never affect semantics.
impl<T: Copy + Default + PartialEq, const N: usize> PartialEq for BoundedVec<T, N> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl<T: Copy + Default + Eq, const N: usize> Eq for BoundedVec<T, N> {}

impl<T: Copy + Default + core::fmt::Debug, const N: usize> core::fmt::Debug for BoundedVec<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.as_slice().iter()).finish()
    }
}

// ===========================================================================
// OpaqueTag — a bounded, opaque, never-interpreted identifier (§3.5)
// ===========================================================================

/// An opaque device- or task-class identifier (`"cls.a.v1"`-style). The protocol **never**
/// branches on its contents (§3.5, Core Principle 7); it is carried, hashed, and compared as
/// bytes only. Bounded and heap-free.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpaqueTag {
    bytes: [u8; OPAQUE_TAG_CAP],
    len: u8,
}

impl OpaqueTag {
    /// Build from bytes, or `None` if longer than [`OPAQUE_TAG_CAP`]. Trailing bytes are zeroed,
    /// so equality is exact on the active prefix.
    #[inline]
    pub fn from_bytes(src: &[u8]) -> Option<Self> {
        if src.len() > OPAQUE_TAG_CAP {
            return None;
        }
        let mut bytes = [0u8; OPAQUE_TAG_CAP];
        bytes[..src.len()].copy_from_slice(src);
        Some(Self {
            bytes,
            len: src.len() as u8,
        })
    }

    /// The active bytes (never interpreted by the protocol).
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

// ===========================================================================
// Wire discriminants (F5 study §1 header; §8.2 morphology / F5-A2)
// ===========================================================================

/// Discriminants for [`FrameHeader::frame_type`] (F5 study §1).
pub mod frame_type {
    /// Network Density Frame.
    pub const NDF: u8 = 1;
    /// Presence/Availability Frame.
    pub const PAF: u8 = 2;
    /// Compute Contention Frame.
    pub const CCF: u8 = 3;
    /// Ground-Truth Frame.
    pub const GTF: u8 = 4;
}

/// Discriminants for [`NetworkDensityFrame::morphology_id`] (F5-A2) — a *study wire envelope*, a
/// property of the instrument, never of the device or participant.
pub mod morphology {
    /// Raw high-entropy stream (the shaping-sensitive control).
    pub const MORPH_R: u8 = 1;
    /// Genuine TLS 1.3 to study domains (the commonly-whitelisted envelope).
    pub const MORPH_T: u8 = 2;
    /// goat-net PQ transport framing — the **operative** morphology; the normative F4/F6 frame.
    pub const MORPH_P: u8 = 3;
}

// ===========================================================================
// F5 telemetry frames (F5 study §1/§8/§9, as amended F5-A1/A2)
// ===========================================================================

/// The fixed, common preamble every F5 telemetry frame carries (F5 §1). Field order is
/// spec-declared and load-bearing for canonical serialization (Appendix A, contract 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// Frame-schema version; a bump is a new schema, never an in-place reinterpretation.
    pub schema_version: u16,
    /// One of [`frame_type`].
    pub frame_type: u8,
    /// `HMAC-SHA3-256` of the enrollment record under the per-study pseudonymization key (F5 §12).
    pub endpoint_pseudonym: [u8; 32],
    /// Ordinal of this enrolled device within the endpoint (F5 §14.3).
    pub identity_index: u16,
    /// Study epoch (1 h) from the coordinator clock.
    pub epoch: Epoch,
    /// `SHA3-256(study_beacon ‖ pseudonym ‖ epoch)` — nonce-chain binding (F5 §1).
    pub run_nonce: [u8; 32],
    /// Network domain (RECON-15). A wire-visible, signature-bound network tag: a frame minted for one
    /// [`ChainId`] cannot be replayed on another — recipients may reject a wrong-network frame by
    /// field inspection *before* spending any ML-DSA-65 verification.
    pub chain_id: ChainId,
}

/// The per-endpoint density reduction (F5 §20.1–§20.2, as amended F5-A1/A2). Ceilings are
/// eighth-octave rate **bin indices**; densities and shaping bias are `Ppm`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointDensity {
    /// Endpoint this reduction belongs to (F5 §12 pseudonym).
    pub endpoint_pseudonym: [u8; 32],
    /// `CEIL_sust` — 12-tick sustained ceiling. (§20.1)
    pub ceil_sust_bin: u8,
    /// `CEIL_peak` — burst-revealed capacity (F5-A1). (§20.1)
    pub ceil_peak_bin: u8,
    /// `CEIL_oper` — `MORPH_P` peak; the normative F4/F6 frame (F5-A2). (§20.1)
    pub ceil_oper_bin: u8,
    /// `CEIL_phys` — `max` over morphologies; physical-truth lower bound (F5-A2). (§20.1)
    pub ceil_phys_bin: u8,
    /// `shape_delta_ppm` — measured DPI/shaping bias `(phys − oper)/phys` (F5-A2). (§20.1)
    pub shape_delta_ppm: Ppm,
    /// `d_ppm` — probe-observed density in reference-device-equivalents, operative frame. (§20.2)
    pub d_ppm: Ppm,
}

/// One Network Density Frame record: the common header plus the §8.2 per-tick measurement.
/// Field order matches the amended §8.2 table verbatim (original → F5-A1 → F5-A2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkDensityFrame {
    /// Common preamble (F5 §1).
    pub header: FrameHeader,
    /// 5-min tick within the epoch batch.
    pub tick_index: u16,
    /// Downlink sustained-rate bin (eighth-octave). Quantized at source.
    pub dl_bin: u8,
    /// Uplink sustained-rate bin (eighth-octave).
    pub ul_bin: u8,
    /// `1` if this tick ran in the coordinated-concurrent (aggregate) schedule, else `0`.
    pub concurrent_flag: u8,
    /// Endpoint-aggregate downlink bin for coordinated ticks (`0` = n/a).
    pub agg_dl_bin: u8,
    /// Endpoint-aggregate uplink bin for coordinated ticks (`0` = n/a).
    pub agg_ul_bin: u8,
    /// RTT (ms, capped) to the 8 fixed regional anchor reflectors; region-level multilateration.
    pub rtt_q: [u16; 8],
    /// Count of observed routing-origin changes this epoch (raw ASN/IP never uploaded).
    pub origin_change_count: u8,
    /// `log2` bin of distinct endpoints behind the same salted origin (CGNAT density).
    pub shared_origin_degree_bin: u8,
    /// Eighth-octave bin of bytes moved this tick.
    pub xfer_bytes_bin: u8,
    /// Wire morphology of this tick's transfer; one of [`morphology`]. (F5-A2)
    pub morphology_id: u8,
    /// Micro-burst peak: `max` over sliding `S_MICRO`-s windows of 1-s counters. (F5-A1)
    pub peak_micro_bin: u8,
    /// `peak_micro_bin − dl_bin` (saturating) — scale-free integer crest factor. (F5-A1)
    pub crest_eighth_oct: u8,
    /// Fraction of active transfer seconds at ≥ half the per-second peak. (F5-A1)
    pub duty_ppm: u32,
    /// Integer-changepoint onset second of a mid-flow rate discontinuity (`255` = none). (F5-A2)
    pub throttle_onset_s: u8,
    /// Eighth-octave rate before a detected onset (`0` = n/a). (F5-A2)
    pub pre_bin: u8,
    /// Eighth-octave rate after a detected onset (`0` = n/a). (F5-A2)
    pub post_bin: u8,
}

/// One Presence/Availability Frame (F5 §9). `edge_ticks` is now a heap-free [`BoundedVec`]
/// (RECON-04); the wire encoding is unchanged (`len_u32 ‖ [u16]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenceAvailabilityFrame {
    /// Common preamble (F5 §1).
    pub header: FrameHeader,
    /// 1 bit per 5-min tick (≤ 60 used). Heartbeat reachable / not.
    pub presence_bitmap: u64,
    /// Count of off→on transitions in the batch.
    pub rise_edges: u8,
    /// Count of on→off transitions in the batch.
    pub fall_edges: u8,
    /// Tick indices of transition edges — bounded by the presence-bitmap width (§9).
    pub edge_ticks: BoundedVec<u16, MAX_EDGE_TICKS>,
    /// Local hour-of-day `0..=23` at batch start (timezone itself is not uploaded).
    pub local_hour: u8,
}

// ===========================================================================
// Signed wire structures (Yellowpaper §11 CapabilityRecord, §18.1 ExecutionAttestation)
// ===========================================================================

/// One measured `(device, task-class)` capability aperture inside a [`CapabilityRecord`] (§11).
/// **Measured, never declared** (§3.4, §6): the figure must reproduce under the benchmark that is
/// simultaneously the hardware fingerprint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceCapability {
    /// Opaque task-class id (never interpreted; §3.5).
    pub task_class_id: OpaqueTag,
    /// Measured GCU throughput for this class (measured-work-only; §3.4, §6).
    pub measured_gcu_per_hour: u64,
    /// A-6 / C-6 determinism-profile commitment for this class (§10, §20).
    pub determinism_profile_ref: [u8; 32],
}

/// The measured power/thermal envelope of a node (§11) — a single named spec concept.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PowerThermalEnvelope {
    /// Sustained power draw, milliwatts.
    pub power_mw: u32,
    /// Thermal headroom / operating envelope, deci-kelvin.
    pub thermal_dk: u32,
}

/// **`CapabilityRecord`** (Yellowpaper §11): the ML-DSA-65-signed, canonically serialized wire
/// structure by which a node advertises measured capability, bound to one post-quantum identity,
/// one epoch, an anti-replay beacon nonce, and its attestation-chain position (§11, §12, §16,
/// §19). Signature/identity live in the outer `SignedRecord` wrapper (not modeled here); this is
/// the signable body whose [`signing_preimage`](crate::crypto::CanonicalSerialize) binds
/// `CTX_GOAT_CAPABILITY_RECORD`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityRecord {
    /// The operator's ML-DSA-65 identity binding (§11, §16).
    pub node_id: [u8; 32],
    /// The epoch this record is bound to (§11).
    pub epoch: Epoch,
    /// Anti-replay nonce drawn from the epoch beacon (§19).
    pub beacon_nonce: [u8; 32],
    /// `SHA3-256` of the full *signed* prior record — the A-3 hash-chain position (§12).
    pub prev_record: [u8; 32],
    /// The node's measured capability apertures, bounded and heap-free (§11).
    pub capabilities: BoundedVec<DeviceCapability, MAX_CAPABILITIES>,
    /// Availability, confidence-weighted, never penalized (A-5).
    pub availability_ppm: Ppm,
    /// Measured power/thermal envelope (§11).
    pub power_thermal_envelope: PowerThermalEnvelope,
    /// Probe-observed density witness feeding F4/F6 (§14).
    pub density_witness_ppm: Ppm,
}

/// **`ExecutionAttestation`** (Yellowpaper §18.1, **amended RECON-07**): the ML-DSA-65-signed
/// **attributable core** of a receipt.
///
/// **RECON-07 — plagiarism closure.** The executor's `node_id` is now bound *inside* the signed
/// core, so a signature cryptographically commits to its author. This closes the bearer-token
/// vector: an intercepted honest receipt can no longer be re-`cluster_id`'d and re-signed under a
/// different key to steal the attribution — the signer's identity is part of what is signed. (The
/// core binding is *necessary*; the registry's `public_key`↔`node_id` check is what makes it
/// *sufficient*, §18.2 / A-CI3.) Amended field order: `node_id`, `class_id`, `task_class_id`,
/// `window`, `sub_window`, `cluster_id`, `asn`, `result_commit`. Outcome flags remain
/// **deliberately excluded** (§18.1). Its [`signing_preimage`](crate::crypto::CanonicalSerialize)
/// binds `CTX_GOAT_EXEC_ATTESTATION`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionAttestation {
    /// The executor's ML-DSA-65 identity, bound into the signed core (RECON-07). The registry
    /// confirms the receipt's `public_key` is registered *for* this `node_id` (§18.2 / A-CI3).
    pub node_id: [u8; 32],
    /// Opaque device-class id (never interpreted; §3.5).
    pub class_id: OpaqueTag,
    /// Opaque task-class id (never interpreted; §3.5).
    pub task_class_id: OpaqueTag,
    /// Settlement window (§18.1).
    pub window: Epoch,
    /// Anomaly-burst sub-window bucket, bound into the signed core (R-MAT2b, §21.2).
    pub sub_window: u32,
    /// Operator cluster id (F6/§15).
    pub cluster_id: [u8; 32],
    /// Autonomous-system / routing origin (§14).
    pub asn: u32,
    /// `SHA3-256` commitment binding the raw result to this receipt (§18.3).
    pub result_commit: [u8; 32],
}

// ===========================================================================
// Signed outer wrappers (§11, §18.1) — payload + ML-DSA-65 identity + signature
// ===========================================================================

/// A signed outer wrapper for a network record (e.g. [`CapabilityRecord`]). The `signature` is
/// over the *payload's* context-bound signing preimage (§11, `CTX_GOAT_CAPABILITY_RECORD`); the
/// wrapper carries the ML-DSA-65 `public_key` for verification (`KeyRegistry` binding of the key
/// to a `node_id` is a separate layer, §18.2 / A-CI3). Fixed-width crypto arrays keep the stack
/// footprint deterministic. Not `Copy` — the ~5 KB body is moved/cloned explicitly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRecord<T> {
    /// The signable payload.
    pub payload: T,
    /// ML-DSA-65 public key (FIPS 204, `1952` B).
    pub public_key: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
    /// ML-DSA-65 signature over the payload's context-bound preimage (`3309` B).
    pub signature: [u8; ML_DSA_65_SIGNATURE_LEN],
}

/// A signed outer wrapper for an execution receipt. The `signature` is over the attestation's
/// `CTX_GOAT_EXEC_ATTESTATION`-bound preimage (§18.1); `KeyRegistry` binding of `public_key` to the
/// claimed node is a separate step (§18.2 / A-CI3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedReceipt {
    /// The signed attributable core (§18.1).
    pub attestation: ExecutionAttestation,
    /// ML-DSA-65 public key (FIPS 204, `1952` B).
    pub public_key: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
    /// ML-DSA-65 signature over the attestation preimage (`3309` B).
    pub signature: [u8; ML_DSA_65_SIGNATURE_LEN],
}

/// A per-cluster attribution accumulated at a fold boundary (§18.4). Pure-integer; `Copy + Default`
/// so it lives in a heap-free [`BoundedVec`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AggregatedAttribution {
    /// Operator cluster (F6/§15) this attribution belongs to.
    pub cluster_id: [u8; 32],
    /// Count of verified receipts attributed to the cluster in the window.
    pub total_verified_gcu_hours: u64,
    /// Cluster's share of the window's verified work, in basis points (§18.4, E4-N1). After the
    /// fold, `Σ representation_weight_bp == BP_FULL` exactly (largest-remainder, Appendix A c.4).
    pub representation_weight_bp: Bp,
}

// ===========================================================================
// Verification-plane structures (§18.2 AuthorizationSet, §18.3 EscalationRecord)
// ===========================================================================

/// **`AuthorizationSet`** (Yellowpaper §18.2): the authorized executor set for a window/task-class,
/// derived from the orchestrator's signed assignment log. A receipt whose executor is not in the
/// set (for its window/task-class), or whose escalation `C` does not re-derive from the beacon
/// lottery, is unauthorized regardless of a valid signature (§18.2, A-CI3). Signed under
/// `CTX_GOAT_ASSIGNMENT_LOG`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationSet {
    /// Settlement window the authorization applies to.
    pub window: Epoch,
    /// Opaque task-class the authorization applies to (never interpreted; §3.5).
    pub task_class_id: OpaqueTag,
    /// Authorized executor identities (node ids), bounded and heap-free.
    pub executors: BoundedVec<[u8; 32], MAX_AUTHORIZED_EXECUTORS>,
}

/// A fused `(receipt, raw-trace commitment)` pair (**RECON-07** desync closure). Binding the
/// receipt to its trace in **one** struct removes the parallel-array permutation vector: a
/// malicious orchestrator can no longer validate signed receipts while shuffling a separate
/// trace-commitment array to misalign the `agree()` comparison and trigger false-positive slashing.
/// Receipt↔trace alignment is now structural, not positional.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscalatedResult {
    /// One executor-signed receipt.
    pub receipt: SignedReceipt,
    /// Its raw execution-trace commitment (`SHA3-256`), bound to the receipt's `result_commit`
    /// (§18.1) — the recompute-from-published-data surface.
    pub raw_trace_commit: [u8; 32],
}

/// **`EscalationRecord`** (Yellowpaper §18.3, **amended RECON-07**): the evidence bundle produced
/// when a redundant set diverges — **exactly three** [`EscalatedResult`]s, each fusing a receipt
/// with its own trace commitment (no parallel arrays to desynchronize). Any recomputer re-runs the
/// `agree()` decision from the signed results and confirms (or refutes) an attribution; carrying
/// all three signed receipts is what makes the orchestrator unable to frame an honest node (§18.3).
/// Signed under `CTX_GOAT_ESCALATION_RECORD`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscalationRecord {
    /// Opaque device-class under adjudication (never interpreted; §3.5).
    pub class_id: OpaqueTag,
    /// The three fused (receipt, trace-commitment) results.
    pub results: [EscalatedResult; 3],
}
