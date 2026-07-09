//! `state.rs` — Active state-transition engines (Tracks I2 / I3).
//!
//! Phase-3 scaffolding. Where `types.rs`/`crypto.rs` define and serialize the sealed records, this
//! module *consumes* them under the zero-trust discipline: nothing a record asserts is trusted
//! until it is (a) authorized (staked + identity-bound, A-CI3), (b) cryptographically verified over
//! its context-bound preimage, and (c) range/coherence-checked. `no_std`, allocation-free (all
//! preimages are rebuilt into a stack [`SliceSink`]; SHA3-256 is inline and stack-only); no
//! `unsafe`.
//!
//! ## RECON-08 — state-consumption hazards (Track I2)
//!
//! 1. **Epoch replay (capability ingestion).** [`ingest_capability`] enforces a strict temporal
//!    window ([`MAX_ATTESTATION_AGE`]): stale ⇒ [`StateError::ExpiredRecord`], future-dated ⇒
//!    [`StateError::FutureEpoch`], applied *after* signature authentication.
//! 2. **Cross-task trap (dispute resolution).** [`verify_escalation_coherence`](fn@verify_escalation_coherence)
//!    rejects any bundle whose three receipts diverge on `window`/`sub_window`/`task_class_id`/
//!    `class_id`, or that repeats an executor (manufactured-majority variant).
//!
//! ## RECON-09 — systemic/temporal hazards (Track I3)
//!
//! 1. **RANDAO withholding (predictable lotteries).** [`derive_authorization_set`] draws with
//!    **lagged** entropy (epoch `E-1`), so the last orchestrator of `E` cannot withhold a reveal to
//!    bias the draw — the entropy is finalized before `E` begins.
//! 2. **Double-jeopardy (slashing amplification).** [`apply_epoch_penalties`] deduplicates faults
//!    per node before penalizing, so many concurrent faults against one honest node in a single
//!    epoch yield **one** downgrade + **one** slash, not many.
//!
//! ## RECON-10 — statistical fairness (V1.0 seal)
//!
//! 1. **Uniform lottery.** The draw index is a full **64-bit** value mod the pool size, so every
//!    slot in a multi-thousand-node registry is reachable with negligible modulo bias — the
//!    `hash[0] as u8` truncation the advisory describes was never present (the `u64` extraction has
//!    been in place since Track I3); this pass confirms and documents it, keeping the panic-free
//!    `copy_from_slice` form over `try_into().unwrap()`.
//!
//! ## RECON-13/16 · ARC-01-M9/M10 — Kamikaze Halt, state-bloat, and the two-lane fair market
//!
//! The RECON-10 slashing pipeline was **fail-closed** (a `FaultSaturationPanic` an adversary could
//! trigger with 1025 Sybil faults to halt epoch transitions). RECON-13 made the ratchet total and
//! infallible; RECON-16 removed the deferral queue so the fault set is hard-bounded per epoch (no
//! OOM). **ARC-01 (H-3)** closes the residual plutocracy: pricing a consensus-critical queue purely
//! on *linear* stake is a censorship primitive. [`apply_epoch_penalties`] now splits the
//! [`MAX_FAULTS_PER_EPOCH`] processing slots into **two lanes**:
//!
//! - a **concave-stake lane** ([`LANE_STAKE_SLOTS`], ARC-01-M10) ordered by `isqrt(stake)` with an
//!   egalitarian `node_id` tiebreak — prioritizes critical high-stake faults while bounding absolute
//!   dominance; and
//! - a **stake-blind fair lane** ([`LANE_FAIR_SLOTS`], ARC-01-M9) — a `prior_epoch_entropy`-seeded
//!   uniform sample over the remainder, so **every valid fault keeps a statistical path to finality
//!   regardless of the participant's capital**.
//!
//! Under a flood exceeding [`MAX_FAULT_MARKET`], candidates are retained by a stake-blind reservoir,
//! so low-stake faults are never systematically evicted before the fair lane can sample them. The
//! `adaptive_min_stake` output is **advisory only** (ARC-01-M12: it MUST NOT gate participation).
//!
//! Crate root: `pub mod state;` (after `pub mod types; pub mod crypto;`).

use crate::crypto::{
    KeyRegistry, SerializationError, SignatureVerifier, SliceSink,
    CAPABILITY_RECORD_MAX_PREIMAGE_LEN, EXEC_ATTESTATION_MAX_PREIMAGE_LEN,
};
use crate::types::{
    AdvisoryStakeFloor, AuthorizationSet, BoundedVec, CapabilityRecord, Epoch, EscalationRecord,
    OpaqueTag, SignedRecord, MAX_AUTHORIZED_EXECUTORS, MAX_FAULTS_PER_EPOCH, OPAQUE_TAG_CAP,
};

/// Maximum age (in epochs) of an ingested attestation. At 1-hour epochs this is a 24-hour window:
/// a record older than this is a replay and is dropped (RECON-08).
pub const MAX_ATTESTATION_AGE: Epoch = 24;

/// Bounded rejection-sampling budget for the lottery draw (RECON-09). Guarantees termination
/// without assuming the registry snapshot is duplicate-free; ample to fill
/// [`MAX_AUTHORIZED_EXECUTORS`] from any realistic pool. A degenerate, duplicate-heavy snapshot that
/// cannot supply enough distinct nodes yields a *smaller* set rather than looping.
const MAX_DRAW_ATTEMPTS: u64 = (MAX_AUTHORIZED_EXECUTORS as u64) * 64;

// ===========================================================================
// Error typology
// ===========================================================================

/// A state-transition rejection. Total and `Copy`; every consumption path returns one of these
/// rather than panicking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateError {
    /// The `(public_key, node_id)` pair is not a currently-staked registered executor (A-CI3).
    Unauthorized,
    /// The ML-DSA-65 signature did not verify over the context-bound preimage.
    BadSignature,
    /// The record is older than [`MAX_ATTESTATION_AGE`] — a stale-attestation replay (RECON-08).
    ExpiredRecord,
    /// The record is dated after the current epoch — clock-skew or forgery (RECON-08).
    FutureEpoch,
    /// An `EscalationRecord` mixes receipts from different work items, or repeats an executor —
    /// a forged-fault bundle (RECON-08 cross-task / duplicate-executor trap).
    IncoherentEscalation,
    /// A canonical-serialization failure while rebuilding a signing preimage. Unreachable with the
    /// correctly-sized stack buffers used here; surfaced rather than panicked (totality).
    Serialization(SerializationError),
}

impl From<SerializationError> for StateError {
    #[inline]
    fn from(e: SerializationError) -> Self {
        StateError::Serialization(e)
    }
}

// ===========================================================================
// Deliverable I2.1 — capability ingestion with the epoch replay guard
// ===========================================================================

/// Ingest a signed `CapabilityRecord` for task routing, or reject it.
///
/// Order (cheap authorization → authenticity → temporal, so an unverified `epoch` is never
/// range-checked before the signature that authenticates it):
/// 1. **Authorization (A-CI3):** the wrapper's `public_key` must be the staked key registered *for*
///    the payload's `node_id` — `KeyRegistry`.
/// 2. **Authenticity:** the ML-DSA-65 signature must verify over the `CTX_GOAT_CAPABILITY_RECORD`
///    context-bound preimage (rebuilt into a stack buffer, zero-alloc).
/// 3. **Temporal bound (RECON-08):** `future ⇒ FutureEpoch`; `age > MAX_ATTESTATION_AGE ⇒
///    ExpiredRecord`; otherwise accepted.
pub fn ingest_capability<V: SignatureVerifier, R: KeyRegistry>(
    wrapper: &SignedRecord<CapabilityRecord>,
    current_epoch: Epoch,
    verifier: &V,
    registry: &R,
) -> Result<CapabilityRecord, StateError> {
    let payload = &wrapper.payload;

    // 1. Global stake + identity binding: the key must be registered for this exact node_id.
    if !registry.is_authorized(&wrapper.public_key, &payload.node_id) {
        return Err(StateError::Unauthorized);
    }

    // 2. Authenticity over the context-bound preimage (stack-rebuilt; buffer is provably max-sized).
    let mut buf = [0u8; CAPABILITY_RECORD_MAX_PREIMAGE_LEN];
    let mut sink = SliceSink::new(&mut buf);
    payload.write_signing_preimage(&mut sink)?; // SerializationError → StateError via `From`
    if !verifier.verify_ml_dsa_65(&wrapper.public_key, sink.written(), &wrapper.signature) {
        return Err(StateError::BadSignature);
    }

    // 3. RECON-08 temporal bound — `epoch` is now authenticated, so range-checking it is sound.
    if payload.epoch > current_epoch {
        return Err(StateError::FutureEpoch);
    }
    if current_epoch.saturating_sub(payload.epoch) > MAX_ATTESTATION_AGE {
        return Err(StateError::ExpiredRecord);
    }

    Ok(payload.clone())
}

// ===========================================================================
// Deliverable I2.2 — dispute resolution & the cross-task trap
// ===========================================================================

/// The adjudicated outcome of a three-way `EscalationRecord`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisputeOutcome {
    /// All three executors produced the same trace commitment — no fault, nobody is slashed. (A
    /// complete adjudicator must represent this; otherwise a unanimous set would be mis-slashed.)
    Unanimous {
        /// The agreed commitment.
        commit: [u8; 32],
    },
    /// A 2-vs-1 split: `winning_commit` is the majority result; the dissenting executor
    /// (`slashed_node_id`) is slashed.
    Majority {
        /// The majority (authoritative) trace commitment.
        winning_commit: [u8; 32],
        /// The minority executor to be slashed.
        slashed_node_id: [u8; 32],
    },
    /// A 3-way divergence — no majority exists; all three executors are slashed. **RECON-09:** the
    /// three node ids are carried so the epoch ratchet can penalize (and deduplicate) them.
    TotalDivergence {
        /// The three dissenting executors, all slashed.
        slashed_node_ids: [[u8; 32]; 3],
    },
}

/// **RECON-08 coherence gate.** All three receipts in the bundle must adjudicate the *same* work
/// item — identical `window`, `sub_window`, `task_class_id`, and `class_id` (and the record's own
/// declared `class_id` must match) — **and** name three *distinct* executors. The first rejects
/// cross-task mixing; the second rejects a duplicated executor that could manufacture a 2-vs-1
/// majority against an honest node. Either divergence ⇒ [`StateError::IncoherentEscalation`].
fn verify_escalation_coherence(record: &EscalationRecord) -> Result<(), StateError> {
    let r0 = &record.results[0].receipt.attestation;

    // (a) Same work item across all three receipts, and consistent with the record's class.
    let same_item = record.class_id == r0.class_id
        && record.results.iter().all(|res| {
            let a = &res.receipt.attestation;
            a.window == r0.window
                && a.sub_window == r0.sub_window
                && a.task_class_id == r0.task_class_id
                && a.class_id == r0.class_id
        });
    if !same_item {
        return Err(StateError::IncoherentEscalation);
    }

    // (b) Distinct executors — a duplicated node_id could forge a majority (spread rule, §18.3).
    let n0 = record.results[0].receipt.attestation.node_id;
    let n1 = record.results[1].receipt.attestation.node_id;
    let n2 = record.results[2].receipt.attestation.node_id;
    if n0 == n1 || n0 == n2 || n1 == n2 {
        return Err(StateError::IncoherentEscalation);
    }

    Ok(())
}

/// Adjudicate a three-receipt `EscalationRecord` (§18.3 `verify_attribution` / `agree`).
///
/// 1. **Coherence** (`verify_escalation_coherence`) — same work item, distinct executors.
/// 2. **Authenticity** — re-verify all three fused receipts over their context-bound preimages; a
///    single malformed receipt invalidates the whole bundle ([`StateError::BadSignature`]).
/// 3. **Comparison** — compare the three `raw_trace_commit`s and return the [`DisputeOutcome`].
pub fn agree<V: SignatureVerifier>(
    record: &EscalationRecord,
    verifier: &V,
) -> Result<DisputeOutcome, StateError> {
    // 1. Coherence first — reject a forged/cross-task bundle before spending crypto.
    verify_escalation_coherence(record)?;

    // 2. Re-verify each fused receipt's signature over its exec-attestation preimage.
    let mut buf = [0u8; EXEC_ATTESTATION_MAX_PREIMAGE_LEN];
    for result in &record.results {
        let receipt = &result.receipt;
        let mut sink = SliceSink::new(&mut buf);
        receipt.attestation.write_signing_preimage(&mut sink)?;
        if !verifier.verify_ml_dsa_65(&receipt.public_key, sink.written(), &receipt.signature) {
            return Err(StateError::BadSignature);
        }
    }

    // 3. Compare the three trace commitments (executors are distinct — coherence guaranteed it).
    let c0 = record.results[0].raw_trace_commit;
    let c1 = record.results[1].raw_trace_commit;
    let c2 = record.results[2].raw_trace_commit;
    let n0 = record.results[0].receipt.attestation.node_id;
    let n1 = record.results[1].receipt.attestation.node_id;
    let n2 = record.results[2].receipt.attestation.node_id;

    let outcome = if c0 == c1 && c1 == c2 {
        DisputeOutcome::Unanimous { commit: c0 }
    } else if c0 == c1 {
        // c0 == c1 ≠ c2 → majority c0; the c2 executor dissents.
        DisputeOutcome::Majority {
            winning_commit: c0,
            slashed_node_id: n2,
        }
    } else if c0 == c2 {
        // c0 == c2 ≠ c1 → majority c0; the c1 executor dissents.
        DisputeOutcome::Majority {
            winning_commit: c0,
            slashed_node_id: n1,
        }
    } else if c1 == c2 {
        // c1 == c2 ≠ c0 → majority c1; the c0 executor dissents.
        DisputeOutcome::Majority {
            winning_commit: c1,
            slashed_node_id: n0,
        }
    } else {
        // RECON-09: carry the three ids so the ratchet can slash + deduplicate them.
        DisputeOutcome::TotalDivergence {
            slashed_node_ids: [n0, n1, n2],
        }
    };
    Ok(outcome)
}

// ===========================================================================
// Deliverable I3.1 — the beacon lottery with lagged entropy (RECON-09/10)
// ===========================================================================

/// Derive the `AuthorizationSet` for `target_window` (epoch `E`) from **lagged** entropy.
///
/// **RECON-09 (RANDAO withholding).** `prior_epoch_entropy` is the finalized entropy of epoch
/// `E-1`; seeding the draw for `E` with `E-1`'s entropy means the last revealer of `E` cannot
/// withhold to bias the assignment — the seed is already fixed when `E` opens.
///
/// The draw is a deterministic, pure-integer, `no_std` rejection sampler: for `counter = 0, 1, …`
/// it takes `idx = LE64(SHA3-256(prior_epoch_entropy ‖ len‖task_class_id ‖ counter)) mod n`, and
/// admits `registry_snapshot[idx]` if not already selected, until `min(MAX_AUTHORIZED_EXECUTORS, n)`
/// **distinct** node ids are drawn (or the bounded attempt budget is spent). Total; never panics.
pub fn derive_authorization_set(
    target_window: Epoch,
    task_class_id: OpaqueTag,
    registry_snapshot: &[&[u8; 32]],
    prior_epoch_entropy: &[u8; 32],
) -> Result<AuthorizationSet, StateError> {
    let mut executors: BoundedVec<[u8; 32], MAX_AUTHORIZED_EXECUTORS> = BoundedVec::new();
    let n = registry_snapshot.len();
    if n > 0 {
        let want = core::cmp::min(MAX_AUTHORIZED_EXECUTORS, n);
        let mut counter: u64 = 0;
        while executors.len() < want && counter < MAX_DRAW_ATTEMPTS {
            let digest = draw_hash(prior_epoch_entropy, &task_class_id, counter);
            counter += 1;
            // RECON-10: derive the index from a full 64-bit value (not a single byte), so every
            // slot in a multi-thousand-node registry is reachable and the residual modulo bias
            // `(2^64 mod n)/2^64` is cryptographically negligible. `copy_from_slice` into a fixed
            // `[u8; 8]` keeps this panic-free — preferred over `digest[..8].try_into().unwrap()`.
            let mut idx_bytes = [0u8; 8];
            idx_bytes.copy_from_slice(&digest[..8]);
            let idx = (u64::from_le_bytes(idx_bytes) % n as u64) as usize;
            let candidate = *registry_snapshot[idx];
            if executors.as_slice().contains(&candidate) {
                continue; // already drawn — try the next counter
            }
            if executors.try_push(candidate).is_err() {
                break; // capacity == want ≤ MAX; unreachable, but keeps the loop total
            }
        }
    }
    Ok(AuthorizationSet {
        window: target_window,
        task_class_id,
        executors,
    })
}

/// `SHA3-256( prior_epoch_entropy(32) ‖ len_u8 ‖ task_bytes ‖ counter(8 LE) )`, built on the stack.
/// The `len_u8` prefix keeps the task tag length-delimited (injective input), so distinct
/// `(task, counter)` never collide.
fn draw_hash(entropy: &[u8; 32], task: &OpaqueTag, counter: u64) -> [u8; 32] {
    let tb = task.as_bytes();
    let mut input = [0u8; 32 + 1 + OPAQUE_TAG_CAP + 8];
    input[..32].copy_from_slice(entropy);
    input[32] = tb.len() as u8;
    input[33..33 + tb.len()].copy_from_slice(tb);
    let end = 33 + tb.len();
    input[end..end + 8].copy_from_slice(&counter.to_le_bytes());
    sha3_256(&input[..end + 8])
}

// ===========================================================================
// Deliverable I3.2 — the maturity ratchet & two-lane fair fault market
// (RECON-09/10/13/16 · ARC-01-M9/M10)
// ===========================================================================

/// A single end-of-epoch penalty against one node. **RECON-09:** exactly one is emitted per unique
/// faulted node, regardless of how many disputes named it — closing the double-jeopardy trap.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PenaltyEvent {
    /// The penalized executor.
    pub node_id: [u8; 32],
    /// `p_class` downgrade steps to apply this epoch — always `1` (deduplicated).
    pub p_class_downgrade: u32,
    /// Slashing units to apply this epoch — always `1` (deduplicated).
    pub slash_units: u64,
}

/// The current staked weight (economic priority) bonded to a node. This is **consensus state** —
/// every node computes the identical value — so the fault market's ordering is deterministic across
/// the network. Device-neutral: a stake is an opaque economic weight, never a device attribute.
pub trait StakeOracle {
    /// Staked weight (micro-USD) bonded to `node_id`; an unknown or unstaked node yields `0`.
    fn stake_of(&self, node_id: &[u8; 32]) -> u64;
}

/// The outcome of an epoch's slashing ratchet (RECON-13/16 · ARC-01-M9/M10). **Total** — building it
/// can never fail or halt the network — and **hard-bounded**: no deferral queue, so the fault set
/// cannot accumulate across epochs (no OOM). The `MAX_FAULTS_PER_EPOCH` processing slots are split
/// into two lanes so **no capital level can fully censor a fault** (ARC-01, H-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochPenaltyReport {
    /// Penalties applied this epoch, at most [`MAX_FAULTS_PER_EPOCH`] — the union of the two lanes.
    pub penalties: BoundedVec<PenaltyEvent, MAX_FAULTS_PER_EPOCH>,
    /// Faults slashed via the **concave-stake lane** (ARC-01-M10), ordered by `isqrt(stake)`.
    pub stake_lane: usize,
    /// Faults slashed via the **stake-blind fair lane** (ARC-01-M9) — a beacon-seeded uniform sample
    /// over the remainder, so every valid fault keeps a statistical path to finality regardless of
    /// the participant's capital.
    pub fair_lane: usize,
    /// Count of faults **permanently dropped** this epoch (bounded eviction; never deferred → no OOM).
    pub dropped_faults: usize,
    /// **Advisory only** (ARC-01-M12): on saturation, the minimum *raw* stake that still earned a
    /// slash in the concave lane, wrapped in [`AdvisoryStakeFloor`] — a type-level tripwire with no
    /// ordering, so it *cannot* be used to gate participation, registration, or challenge rights
    /// (which would re-introduce plutocratic censorship, ARC-01 H-3). Read it only via
    /// [`AdvisoryStakeFloor::fee_market_hint`]. [`AdvisoryStakeFloor::NONE`] when unsaturated.
    pub adaptive_min_stake: AdvisoryStakeFloor,
}

/// One entry in the fault market: a distinct faulted node and its raw economic (stake) priority.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct FaultEntry {
    node_id: [u8; 32],
    priority: u64,
}

/// Slots in the concave-stake lane (ARC-01-M10): half of [`MAX_FAULTS_PER_EPOCH`].
pub const LANE_STAKE_SLOTS: usize = MAX_FAULTS_PER_EPOCH / 2;
/// Slots in the stake-blind fair lane (ARC-01-M9): the other half.
pub const LANE_FAIR_SLOTS: usize = MAX_FAULTS_PER_EPOCH - LANE_STAKE_SLOTS;
/// Candidate-buffer capacity (two epochs' worth). Distinct faults beyond this are folded in by a
/// beacon-seeded **stake-blind reservoir** (ARC-01, H-3), so a flood cannot systematically evict
/// low-stake faults *before* the fair lane can sample them.
pub const MAX_FAULT_MARKET: usize = 2 * MAX_FAULTS_PER_EPOCH;

/// Domain tags separating the two beacon-seeded random streams (reservoir vs. fair-lane shuffle) so
/// their draws never correlate.
const RAND_DOMAIN_RESERVOIR: u8 = 0x01;
const RAND_DOMAIN_FAIR: u8 = 0x02;

/// A deterministic, beacon-seeded 64-bit draw: `LE64(SHA3-256(entropy ‖ domain ‖ counter_le))`. Every
/// node derives the identical value from the finalized `prior_epoch_entropy` (consensus safety), yet
/// a flooder cannot predict it. Stack-only; total.
fn market_rand(entropy: &[u8; 32], domain: u8, counter: u64) -> u64 {
    let mut input = [0u8; 32 + 1 + 8];
    input[..32].copy_from_slice(entropy);
    input[32] = domain;
    input[33..].copy_from_slice(&counter.to_le_bytes());
    let digest = sha3_256(&input);
    let mut b = [0u8; 8];
    b.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(b)
}

/// Pure-integer square root — the concave weight for ARC-01-M10. Bit-by-bit (digit-by-digit binary);
/// total, panic-free, no float, no overflow (`res + bit < 2^63`).
fn isqrt_u64(n: u64) -> u64 {
    let mut res: u64 = 0;
    let mut bit: u64 = 1u64 << 62; // largest power of four ≤ u64::MAX
    while bit > n {
        bit >>= 2;
    }
    let mut rem = n;
    while bit != 0 {
        if rem >= res + bit {
            rem -= res + bit;
            res = (res >> 1) + bit;
        } else {
            res >>= 1;
        }
        bit >>= 2;
    }
    res
}

/// A bounded candidate market: distinct faults (deduplicated by node), retained via a **stake-blind
/// reservoir** so that under a flood exceeding [`MAX_FAULT_MARKET`], every fault — regardless of
/// stake — keeps an equal chance of retention (ARC-01, H-3). Fixed memory; total; never panics.
struct FaultMarket {
    entries: BoundedVec<FaultEntry, MAX_FAULT_MARKET>,
    seen: u64,
    overflow_dropped: usize,
}

impl FaultMarket {
    #[inline]
    fn new() -> Self {
        Self {
            entries: BoundedVec::new(),
            seen: 0,
            overflow_dropped: 0,
        }
    }

    /// Deduplicate, then retain. While the buffer has room, append; once full, apply Algorithm-R
    /// reservoir replacement seeded on `entropy` (stake-blind), so no capital level is preferentially
    /// retained or evicted. Total; never panics.
    fn insert(&mut self, node_id: [u8; 32], priority: u64, entropy: &[u8; 32]) {
        if self.entries.as_slice().iter().any(|e| e.node_id == node_id) {
            return; // RECON-09 one-penalty-per-node (even across the whole flood)
        }
        let entry = FaultEntry { node_id, priority };
        if self.entries.try_push(entry).is_ok() {
            self.seen += 1;
            return;
        }
        // Buffer full — reservoir (Algorithm R): the i-th distinct fault (`i = seen ≥ capacity`)
        // lands in slot `j = rand(0..=i)` iff `j < capacity`. Exactly one distinct fault is shed.
        let i = self.seen;
        let j = (market_rand(entropy, RAND_DOMAIN_RESERVOIR, i) % (i + 1)) as usize;
        if j < MAX_FAULT_MARKET {
            self.entries.as_mut_slice()[j] = entry;
        }
        self.seen += 1;
        self.overflow_dropped += 1;
    }
}

/// Move `k` beacon-seeded fair-random elements of `slice` to its front (partial Fisher–Yates). After
/// the call, `slice[..k]` is a uniform, stake-blind sample of the input (ARC-01-M9). Total; no alloc.
fn shuffle_front(slice: &mut [FaultEntry], k: usize, entropy: &[u8; 32]) {
    let len = slice.len();
    let k = core::cmp::min(k, len);
    for i in 0..k {
        let span = (len - i) as u64; // ≥ 1
        let j = i + (market_rand(entropy, RAND_DOMAIN_FAIR, i as u64) % span) as usize;
        slice.swap(i, j);
    }
}

/// **The maturity ratchet — a two-lane fair fault market (ARC-01-M9/M10, on RECON-13/16).** Total and
/// **hard-bounded**: it can neither halt nor grow without limit, and — crucially — **no capital level
/// can fully censor a fault**. Pipeline:
///
/// 1. Deduplicate this epoch's faults into a bounded [`FaultMarket`]; a flood beyond
///    [`MAX_FAULT_MARKET`] is folded in by a **stake-blind reservoir**, so low-stake faults are not
///    systematically evicted before selection.
/// 2. **Concave-stake lane** ([`LANE_STAKE_SLOTS`], ARC-01-M10): order candidates by `isqrt(stake)`
///    (egalitarian `node_id` tiebreak) and take the top slots. `isqrt` compresses whale advantage
///    into buckets within which `node_id` decides — bounding absolute dominance.
/// 3. **Stake-blind fair lane** ([`LANE_FAIR_SLOTS`], ARC-01-M9): from the remainder, take a
///    beacon-seeded (`prior_epoch_entropy`) uniform sample — every valid fault keeps a statistical
///    path to finality regardless of the participant's capital.
/// 4. Slash the union (one downgrade + one slash unit each — RECON-09). Report `dropped_faults`
///    (bounded, never deferred → no OOM) and an **advisory** `adaptive_min_stake` (ARC-01-M12: MUST
///    NOT gate participation).
///
/// The `prior_epoch_entropy` seed is the finalized `E-1` beacon (as in the lottery), so the fair lane
/// is deterministic across the network yet unpredictable to a flooder. Total; returns no error.
pub fn apply_epoch_penalties<S: StakeOracle>(
    outcomes: &[DisputeOutcome],
    stake: &S,
    prior_epoch_entropy: &[u8; 32],
) -> EpochPenaltyReport {
    let mut market = FaultMarket::new();
    for outcome in outcomes {
        match outcome {
            DisputeOutcome::Unanimous { .. } => {}
            DisputeOutcome::Majority {
                slashed_node_id, ..
            } => market.insert(
                *slashed_node_id,
                stake.stake_of(slashed_node_id),
                prior_epoch_entropy,
            ),
            DisputeOutcome::TotalDivergence { slashed_node_ids } => {
                for node in slashed_node_ids {
                    market.insert(*node, stake.stake_of(node), prior_epoch_entropy);
                }
            }
        }
    }

    let overflow_dropped = market.overflow_dropped;
    let entries = market.entries.as_mut_slice();
    let n = entries.len();

    // Lane A — concave-stake ordering (isqrt), egalitarian node_id tiebreak within each bucket.
    entries.sort_unstable_by(|a, b| {
        isqrt_u64(b.priority)
            .cmp(&isqrt_u64(a.priority))
            .then_with(|| a.node_id.cmp(&b.node_id))
    });
    let lane_a = core::cmp::min(n, LANE_STAKE_SLOTS);

    // Advisory floor (ARC-01-M12): min RAW stake retained in the concave lane, only on saturation.
    // Wrapped in `AdvisoryStakeFloor` so it can never silently gate participation (H-3).
    let saturated = overflow_dropped > 0 || n > MAX_FAULTS_PER_EPOCH;
    let adaptive_min_stake = if saturated && lane_a > 0 {
        let floor = entries[..lane_a]
            .iter()
            .map(|e| e.priority)
            .min()
            .unwrap_or(0);
        AdvisoryStakeFloor::new(floor)
    } else {
        AdvisoryStakeFloor::NONE
    };

    // Lane B — stake-blind fair sample over the remainder (beacon-seeded), moved to its front.
    let lane_b = core::cmp::min(n - lane_a, LANE_FAIR_SLOTS);
    shuffle_front(&mut entries[lane_a..], lane_b, prior_epoch_entropy);

    let processed = lane_a + lane_b; // Lane A = entries[..lane_a]; Lane B = entries[lane_a..processed]
    let mut penalties: BoundedVec<PenaltyEvent, MAX_FAULTS_PER_EPOCH> = BoundedVec::new();
    for entry in &entries[..processed] {
        // Cannot fail: processed ≤ MAX_FAULTS_PER_EPOCH == penalties capacity.
        let _ = penalties.try_push(PenaltyEvent {
            node_id: entry.node_id,
            p_class_downgrade: 1,
            slash_units: 1,
        });
    }

    EpochPenaltyReport {
        penalties,
        stake_lane: lane_a,
        fair_lane: lane_b,
        dropped_faults: (n - processed) + overflow_dropped,
        adaptive_min_stake,
    }
}

// ===========================================================================
// SHA3-256 (FIPS 202) — self-contained, no_std, no dependencies
// ===========================================================================

/// Keccak-f[1600] round constants.
const KECCAK_RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
/// ρ rotation offsets, in the ρ/π chase order.
const KECCAK_RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
/// π lane-permutation indices, in the ρ/π chase order (starting from lane 1).
const KECCAK_PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation over 25 little-endian `u64` lanes.
fn keccak_f(state: &mut [u64; 25]) {
    for &rc in &KECCAK_RC {
        // θ
        let mut c = [0u64; 5];
        for (x, cx) in c.iter_mut().enumerate() {
            *cx = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            let mut idx = x;
            while idx < 25 {
                state[idx] ^= d;
                idx += 5;
            }
        }
        // ρ + π
        let mut last = state[1];
        for i in 0..24 {
            let j = KECCAK_PI[i];
            let tmp = state[j];
            state[j] = last.rotate_left(KECCAK_RHO[i]);
            last = tmp;
        }
        // χ
        let mut y = 0;
        while y < 25 {
            let mut row = [0u64; 5];
            row.copy_from_slice(&state[y..y + 5]);
            for x in 0..5 {
                state[y + x] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
            y += 5;
        }
        // ι
        state[0] ^= rc;
    }
}

/// Absorb one full rate block (136 bytes = 17 lanes) and permute.
fn keccak_absorb(state: &mut [u64; 25], block: &[u8]) {
    for lane in 0..17 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&block[lane * 8..lane * 8 + 8]);
        state[lane] ^= u64::from_le_bytes(b);
    }
    keccak_f(state);
}

/// SHA3-256 (FIPS 202): rate 1088 bits, capacity 512, domain `0x06`, 32-byte output.
///
/// Exposed `pub(crate)` (RECON-11) so the Phase-4 network layer (`gossip` message-dedup hashing,
/// `transport` cookie HMAC) reuses this single FIPS-202-validated implementation instead of
/// duplicating Keccak. Visibility-only change: the implementation and every state-machine invariant
/// are untouched.
pub(crate) fn sha3_256(input: &[u8]) -> [u8; 32] {
    const RATE: usize = 136;
    let mut state = [0u64; 25];

    let mut i = 0;
    while i + RATE <= input.len() {
        keccak_absorb(&mut state, &input[i..i + RATE]);
        i += RATE;
    }
    // Final block with pad10*1 and the SHA3 domain separator.
    let mut block = [0u8; RATE];
    let rem = input.len() - i;
    block[..rem].copy_from_slice(&input[i..]);
    block[rem] = 0x06;
    block[RATE - 1] |= 0x80;
    keccak_absorb(&mut state, &block);

    // Squeeze 32 bytes (< rate → a single squeeze); lanes are little-endian.
    let mut out = [0u8; 32];
    for lane in 0..4 {
        out[lane * 8..lane * 8 + 8].copy_from_slice(&state[lane].to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        BoundedVec, EscalatedResult, ExecutionAttestation, OpaqueTag, PowerThermalEnvelope,
        SignedReceipt, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN, PPM,
    };

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
    struct DenyVerifier;
    impl SignatureVerifier for DenyVerifier {
        fn verify_ml_dsa_65(
            &self,
            _pk: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
            _msg: &[u8],
            _sig: &[u8; ML_DSA_65_SIGNATURE_LEN],
        ) -> bool {
            false
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

    fn signed_cap(node: u8, epoch: Epoch) -> SignedRecord<CapabilityRecord> {
        SignedRecord {
            payload: CapabilityRecord {
                node_id: [node; 32],
                epoch,
                beacon_nonce: [0u8; 32],
                prev_record: [0u8; 32],
                capabilities: BoundedVec::new(),
                availability_ppm: PPM,
                power_thermal_envelope: PowerThermalEnvelope {
                    power_mw: 1,
                    thermal_dk: 1,
                },
                density_witness_ppm: PPM,
            },
            public_key: [0u8; ML_DSA_65_PUBLIC_KEY_LEN],
            signature: [0u8; ML_DSA_65_SIGNATURE_LEN],
        }
    }

    fn escalated(node: u8, commit: u8, window: Epoch) -> EscalatedResult {
        EscalatedResult {
            receipt: SignedReceipt {
                attestation: ExecutionAttestation {
                    node_id: [node; 32],
                    class_id: OpaqueTag::from_bytes(b"cls").unwrap(),
                    task_class_id: OpaqueTag::from_bytes(b"t").unwrap(),
                    window,
                    sub_window: 0,
                    cluster_id: [node; 32],
                    asn: 7,
                    result_commit: [commit; 32],
                },
                public_key: [0u8; ML_DSA_65_PUBLIC_KEY_LEN],
                signature: [0u8; ML_DSA_65_SIGNATURE_LEN],
            },
            raw_trace_commit: [commit; 32],
        }
    }

    fn escalation(results: [EscalatedResult; 3]) -> EscalationRecord {
        EscalationRecord {
            class_id: OpaqueTag::from_bytes(b"cls").unwrap(),
            results,
        }
    }

    fn hex32(s: &str) -> [u8; 32] {
        let b = s.as_bytes();
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            let hi = (b[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (b[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            *o = (hi << 4) | lo;
        }
        out
    }

    /// A distinct node id keyed by index (for the saturation test).
    fn node_id_of(i: usize) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&(i as u64).to_le_bytes());
        id
    }

    // --- I2.1: ingestion + epoch replay guard ------------------------------

    #[test]
    fn ingest_accepts_fresh() {
        let w = signed_cap(1, 100);
        let rec = ingest_capability(&w, 110, &AllowVerifier, &AllowRegistry).unwrap();
        assert_eq!(rec.node_id, [1u8; 32]);
        assert_eq!(rec.epoch, 100);
    }

    #[test]
    fn ingest_boundary_exactly_max_age() {
        let w = signed_cap(1, 100);
        assert!(ingest_capability(&w, 124, &AllowVerifier, &AllowRegistry).is_ok()); // age 24 == max
        assert_eq!(
            ingest_capability(&w, 125, &AllowVerifier, &AllowRegistry), // age 25 > max
            Err(StateError::ExpiredRecord)
        );
    }

    #[test]
    fn ingest_rejects_expired() {
        let w = signed_cap(1, 100);
        assert_eq!(
            ingest_capability(&w, 200, &AllowVerifier, &AllowRegistry),
            Err(StateError::ExpiredRecord)
        );
    }

    #[test]
    fn ingest_rejects_future() {
        let w = signed_cap(1, 100);
        assert_eq!(
            ingest_capability(&w, 90, &AllowVerifier, &AllowRegistry),
            Err(StateError::FutureEpoch)
        );
    }

    #[test]
    fn ingest_rejects_unauthorized() {
        let w = signed_cap(1, 100);
        assert_eq!(
            ingest_capability(&w, 100, &AllowVerifier, &DenyRegistry),
            Err(StateError::Unauthorized)
        );
    }

    #[test]
    fn ingest_rejects_bad_signature() {
        let w = signed_cap(1, 100);
        assert_eq!(
            ingest_capability(&w, 100, &DenyVerifier, &AllowRegistry),
            Err(StateError::BadSignature)
        );
    }

    // --- I2.2: dispute resolution ------------------------------------------

    #[test]
    fn agree_unanimous() {
        let esc = escalation([
            escalated(1, 9, 50),
            escalated(2, 9, 50),
            escalated(3, 9, 50),
        ]);
        assert_eq!(
            agree(&esc, &AllowVerifier),
            Ok(DisputeOutcome::Unanimous { commit: [9u8; 32] })
        );
    }

    #[test]
    fn agree_majority_minority_is_slashed() {
        // c0 == c1 (commit 9) ≠ c2 (commit 7) ⇒ node 3 slashed.
        let esc = escalation([
            escalated(1, 9, 50),
            escalated(2, 9, 50),
            escalated(3, 7, 50),
        ]);
        assert_eq!(
            agree(&esc, &AllowVerifier),
            Ok(DisputeOutcome::Majority {
                winning_commit: [9u8; 32],
                slashed_node_id: [3u8; 32],
            })
        );
    }

    #[test]
    fn agree_majority_middle_dissenter() {
        // c0 == c2 (commit 5) ≠ c1 (commit 8) ⇒ node 2 slashed.
        let esc = escalation([
            escalated(1, 5, 50),
            escalated(2, 8, 50),
            escalated(3, 5, 50),
        ]);
        assert_eq!(
            agree(&esc, &AllowVerifier),
            Ok(DisputeOutcome::Majority {
                winning_commit: [5u8; 32],
                slashed_node_id: [2u8; 32],
            })
        );
    }

    #[test]
    fn agree_total_divergence() {
        let esc = escalation([
            escalated(1, 1, 50),
            escalated(2, 2, 50),
            escalated(3, 3, 50),
        ]);
        assert_eq!(
            agree(&esc, &AllowVerifier),
            Ok(DisputeOutcome::TotalDivergence {
                slashed_node_ids: [[1u8; 32], [2u8; 32], [3u8; 32]]
            })
        );
    }

    #[test]
    fn agree_rejects_cross_task_window() {
        // Coherence runs first — a mismatched window is rejected regardless of the verifier.
        let esc = escalation([
            escalated(1, 9, 50),
            escalated(2, 9, 51),
            escalated(3, 9, 50),
        ]);
        assert_eq!(
            agree(&esc, &AllowVerifier),
            Err(StateError::IncoherentEscalation)
        );
    }

    #[test]
    fn agree_rejects_duplicate_executor() {
        // Node 1 duplicated could forge a 2-vs-1 majority against node 3 — rejected as incoherent.
        let esc = escalation([
            escalated(1, 9, 50),
            escalated(1, 9, 50),
            escalated(3, 7, 50),
        ]);
        assert_eq!(
            agree(&esc, &AllowVerifier),
            Err(StateError::IncoherentEscalation)
        );
    }

    #[test]
    fn agree_rejects_bad_signature() {
        // Coherent bundle, but a receipt fails signature verification ⇒ whole bundle invalid.
        let esc = escalation([
            escalated(1, 9, 50),
            escalated(2, 9, 50),
            escalated(3, 7, 50),
        ]);
        assert_eq!(agree(&esc, &DenyVerifier), Err(StateError::BadSignature));
    }

    // --- SHA3-256 correctness (FIPS 202 vectors) ---------------------------

    #[test]
    fn sha3_256_known_vectors() {
        assert_eq!(
            sha3_256(b""),
            hex32("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        );
        assert_eq!(
            sha3_256(b"abc"),
            hex32("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        );
    }

    // --- I3.1: beacon lottery with lagged entropy (RECON-09/10) ------------

    #[test]
    fn lottery_deterministic_and_valid() {
        let nodes: [[u8; 32]; 20] = core::array::from_fn(|i| [i as u8; 32]);
        let snap: [&[u8; 32]; 20] = core::array::from_fn(|i| &nodes[i]);
        let entropy = [7u8; 32];
        let task = OpaqueTag::from_bytes(b"t").unwrap();

        let a = derive_authorization_set(50, task, &snap, &entropy).unwrap();
        let b = derive_authorization_set(50, task, &snap, &entropy).unwrap();
        assert_eq!(a, b); // deterministic
        assert_eq!(a.window, 50);
        assert_eq!(a.task_class_id, task);
        assert_eq!(a.executors.len(), MAX_AUTHORIZED_EXECUTORS); // pool 20 ≥ 16

        let sel = a.executors.as_slice();
        for (i, e) in sel.iter().enumerate() {
            assert!(nodes.contains(e)); // drawn from the pool
            for e2 in &sel[i + 1..] {
                assert_ne!(e, e2); // distinct
            }
        }
    }

    #[test]
    fn lottery_lagged_entropy_seeds_the_draw() {
        let nodes: [[u8; 32]; 20] = core::array::from_fn(|i| [i as u8; 32]);
        let snap: [&[u8; 32]; 20] = core::array::from_fn(|i| &nodes[i]);
        let task = OpaqueTag::from_bytes(b"t").unwrap();
        let a = derive_authorization_set(50, task, &snap, &[1u8; 32]).unwrap();
        let b = derive_authorization_set(50, task, &snap, &[2u8; 32]).unwrap();
        assert_ne!(a, b); // different E-1 entropy ⇒ different draw
    }

    // RECON-10: with a pool larger than a single byte can index, high-index nodes are reachable.
    #[test]
    fn lottery_reaches_high_indices_beyond_u8() {
        // 300-node pool; a u8-truncated index could never exceed 255. Draw enough that at least one
        // selected node lies at index ≥ 256, proving the 64-bit extraction spans the whole array.
        let nodes: [[u8; 32]; 300] = core::array::from_fn(node_id_of);
        let snap: [&[u8; 32]; 300] = core::array::from_fn(|i| &nodes[i]);
        let task = OpaqueTag::from_bytes(b"t").unwrap();
        // Sweep several entropies; the union of draws must include a node beyond index 255.
        let mut saw_high = false;
        for e in 0u8..16 {
            let a = derive_authorization_set(1, task, &snap, &[e; 32]).unwrap();
            for sel in a.executors.as_slice() {
                let idx = u64::from_le_bytes(sel[..8].try_into().unwrap()) as usize;
                if idx >= 256 {
                    saw_high = true;
                }
            }
        }
        assert!(saw_high);
    }

    #[test]
    fn lottery_small_pool_selects_all_distinct() {
        let nodes: [[u8; 32]; 3] = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let snap: [&[u8; 32]; 3] = [&nodes[0], &nodes[1], &nodes[2]];
        let a =
            derive_authorization_set(1, OpaqueTag::from_bytes(b"x").unwrap(), &snap, &[9u8; 32])
                .unwrap();
        assert_eq!(a.executors.len(), 3);
        for e in a.executors.as_slice() {
            assert!(nodes.contains(e));
        }
    }

    #[test]
    fn lottery_empty_pool_is_empty() {
        let snap: [&[u8; 32]; 0] = [];
        let a =
            derive_authorization_set(1, OpaqueTag::from_bytes(b"x").unwrap(), &snap, &[0u8; 32])
                .unwrap();
        assert!(a.executors.is_empty());
    }

    // --- I3.2: maturity ratchet & two-lane fair market (RECON-09/10/13/16 · ARC-01) ---

    const ENTROPY: [u8; 32] = [0x5A; 32];

    /// Flat stake: every node equal — priority reduces to the egalitarian `node_id`/fair-lane paths.
    struct FlatStake;
    impl StakeOracle for FlatStake {
        fn stake_of(&self, _node_id: &[u8; 32]) -> u64 {
            1
        }
    }

    /// One node richly staked, everyone else at the minimum.
    struct HighStakeFor([u8; 32]);
    impl StakeOracle for HighStakeFor {
        fn stake_of(&self, node_id: &[u8; 32]) -> u64 {
            if *node_id == self.0 {
                1_000_000
            } else {
                1
            }
        }
    }

    fn contains_node(events: &[PenaltyEvent], node: &[u8; 32]) -> bool {
        events.iter().any(|e| &e.node_id == node)
    }

    #[test]
    fn isqrt_is_correct_and_total() {
        assert_eq!(isqrt_u64(0), 0);
        assert_eq!(isqrt_u64(1), 1);
        assert_eq!(isqrt_u64(3), 1);
        assert_eq!(isqrt_u64(4), 2);
        assert_eq!(isqrt_u64(1_000_000), 1000);
        assert_eq!(isqrt_u64(u64::MAX), 4_294_967_295); // 2^32 - 1; no panic/overflow
    }

    #[test]
    fn ratchet_deduplicates_concurrent_faults() {
        // 50 concurrent Majority faults manufactured against node 7 ⇒ exactly ONE penalty.
        let outcomes = [DisputeOutcome::Majority {
            winning_commit: [1u8; 32],
            slashed_node_id: [7u8; 32],
        }; 50];
        let report = apply_epoch_penalties(&outcomes, &FlatStake, &ENTROPY);
        assert_eq!(report.penalties.len(), 1);
        assert_eq!(report.penalties.as_slice()[0].node_id, [7u8; 32]);
        assert_eq!(report.penalties.as_slice()[0].p_class_downgrade, 1);
        assert_eq!(report.penalties.as_slice()[0].slash_units, 1);
        assert_eq!(report.stake_lane, 1);
        assert_eq!(report.fair_lane, 0);
        assert_eq!(report.dropped_faults, 0);
        assert_eq!(report.adaptive_min_stake, AdvisoryStakeFloor::NONE);
    }

    #[test]
    fn ratchet_total_divergence_slashes_all_three_once() {
        let outcomes = [DisputeOutcome::TotalDivergence {
            slashed_node_ids: [[1u8; 32], [2u8; 32], [3u8; 32]],
        }];
        let report = apply_epoch_penalties(&outcomes, &FlatStake, &ENTROPY);
        assert_eq!(report.penalties.len(), 3);
    }

    #[test]
    fn ratchet_dedups_across_majority_and_divergence() {
        let outcomes = [
            DisputeOutcome::Majority {
                winning_commit: [0u8; 32],
                slashed_node_id: [1u8; 32],
            },
            DisputeOutcome::TotalDivergence {
                slashed_node_ids: [[1u8; 32], [2u8; 32], [3u8; 32]],
            },
            DisputeOutcome::Unanimous { commit: [9u8; 32] }, // no fault
        ];
        // Faulted set = {1 (majority), 1,2,3 (divergence, 1 dedup)} = {1,2,3}.
        let report = apply_epoch_penalties(&outcomes, &FlatStake, &ENTROPY);
        assert_eq!(report.penalties.len(), 3);
    }

    #[test]
    fn ratchet_unanimous_produces_no_penalty() {
        let outcomes = [DisputeOutcome::Unanimous { commit: [9u8; 32] }];
        let report = apply_epoch_penalties(&outcomes, &FlatStake, &ENTROPY);
        assert!(report.penalties.is_empty());
        assert_eq!(report.dropped_faults, 0);
    }

    // Exactly MAX_FAULTS_PER_EPOCH distinct faults is the accepted boundary — nothing dropped, both
    // lanes full.
    #[test]
    fn ratchet_boundary_processes_all() {
        let outcomes: [DisputeOutcome; MAX_FAULTS_PER_EPOCH] =
            core::array::from_fn(|i| DisputeOutcome::Majority {
                winning_commit: [0u8; 32],
                slashed_node_id: node_id_of(i),
            });
        let report = apply_epoch_penalties(&outcomes, &FlatStake, &ENTROPY);
        assert_eq!(report.penalties.len(), MAX_FAULTS_PER_EPOCH);
        assert_eq!(report.stake_lane, LANE_STAKE_SLOTS);
        assert_eq!(report.fair_lane, LANE_FAIR_SLOTS);
        assert_eq!(report.dropped_faults, 0);
        assert_eq!(report.adaptive_min_stake, AdvisoryStakeFloor::NONE);
    }

    // ARC-01-M9/M10: a flood is split into a concave-stake lane + a stake-blind fair lane; excess is
    // bounded-dropped (never deferred → no OOM), and the epoch never halts.
    #[test]
    fn ratchet_two_lane_split_and_bounded_drop() {
        const N: usize = MAX_FAULTS_PER_EPOCH + 500; // 1524 distinct faults, all fit the 2048 buffer
        let outcomes: [DisputeOutcome; N] = core::array::from_fn(|i| DisputeOutcome::Majority {
            winning_commit: [0u8; 32],
            slashed_node_id: node_id_of(i),
        });
        let report = apply_epoch_penalties(&outcomes, &FlatStake, &ENTROPY);
        assert_eq!(report.stake_lane, LANE_STAKE_SLOTS); // 512
        assert_eq!(report.fair_lane, LANE_FAIR_SLOTS); // 512
        assert_eq!(report.penalties.len(), MAX_FAULTS_PER_EPOCH); // 1024
        assert_eq!(report.dropped_faults, N - MAX_FAULTS_PER_EPOCH); // 500, bounded, not deferred
    }

    // ARC-01-M9 (H-3): under a whale + a large low-stake flood, the fair lane still processes 512
    // faults that a pure-stake queue would never reach — every fault keeps a statistical path.
    #[test]
    fn ratchet_fair_lane_gives_low_stake_a_path() {
        let whale = node_id_of(7_000_000);
        const N: usize = MAX_FAULTS_PER_EPOCH + 500;
        let outcomes: [DisputeOutcome; N] = core::array::from_fn(|i| DisputeOutcome::Majority {
            winning_commit: [0u8; 32],
            slashed_node_id: if i == 0 { whale } else { node_id_of(i) },
        });
        let report = apply_epoch_penalties(&outcomes, &HighStakeFor(whale), &ENTROPY);
        // The whale is slashed via the concave lane…
        assert!(contains_node(report.penalties.as_slice(), &whale));
        assert_eq!(report.stake_lane, LANE_STAKE_SLOTS);
        // …and 512 min-stake faults reach finality via the stake-blind fair lane.
        assert_eq!(report.fair_lane, LANE_FAIR_SLOTS);
        assert_eq!(report.penalties.len(), MAX_FAULTS_PER_EPOCH);
    }

    // The Kamikaze scenario still holds: a richly-staked fault is slashed NOW (concave lane).
    #[test]
    fn ratchet_prioritizes_stake_in_concave_lane() {
        let rich = node_id_of(9_000);
        let outcomes: [DisputeOutcome; MAX_FAULTS_PER_EPOCH + 1] =
            core::array::from_fn(|i| DisputeOutcome::Majority {
                winning_commit: [0u8; 32],
                slashed_node_id: if i == 0 { rich } else { node_id_of(i) },
            });
        let report = apply_epoch_penalties(&outcomes, &HighStakeFor(rich), &ENTROPY);
        assert!(contains_node(report.penalties.as_slice(), &rich));
        assert_eq!(report.penalties.len(), MAX_FAULTS_PER_EPOCH);
        assert_eq!(report.dropped_faults, 1);
    }

    // ARC-01-M12: on saturation the advisory floor is populated (> 0), but it is advisory only.
    #[test]
    fn ratchet_saturation_reports_advisory_floor() {
        let outcomes: [DisputeOutcome; MAX_FAULTS_PER_EPOCH + 1] =
            core::array::from_fn(|i| DisputeOutcome::Majority {
                winning_commit: [0u8; 32],
                slashed_node_id: node_id_of(i),
            });
        let report = apply_epoch_penalties(&outcomes, &FlatStake, &ENTROPY);
        assert_eq!(report.penalties.len(), MAX_FAULTS_PER_EPOCH);
        assert_eq!(report.dropped_faults, 1);
        assert!(report.adaptive_min_stake.is_raised()); // a floor exists once saturated
    }

    // ARC-01-M12 structural invariant: `adaptive_min_stake` is a type-level advisory. It carries no
    // ordering, so a participation gate (`node_stake >= floor`) does not compile; the value is
    // reachable only through the greppable `fee_market_hint()`. This test locks the advisory contract.
    #[test]
    fn adaptive_min_stake_is_advisory_only() {
        // Saturated ⇒ a floor is raised, readable *only* via the fee-market accessor.
        let flood: [DisputeOutcome; MAX_FAULTS_PER_EPOCH + 1] =
            core::array::from_fn(|i| DisputeOutcome::Majority {
                winning_commit: [0u8; 32],
                slashed_node_id: node_id_of(i),
            });
        let report = apply_epoch_penalties(&flood, &FlatStake, &ENTROPY);
        assert!(report.adaptive_min_stake.is_raised());
        let hint: u64 = report.adaptive_min_stake.fee_market_hint();
        assert!(hint > 0);

        // Unsaturated ⇒ NONE (no floor, not raised).
        let calm = apply_epoch_penalties(
            &[DisputeOutcome::Unanimous { commit: [9u8; 32] }],
            &FlatStake,
            &ENTROPY,
        );
        assert_eq!(calm.adaptive_min_stake, AdvisoryStakeFloor::NONE);
        assert!(!calm.adaptive_min_stake.is_raised());
        assert_eq!(calm.adaptive_min_stake.fee_market_hint(), 0);
    }

    // Consensus safety: the market is deterministic in (outcomes, stake, entropy) — every node
    // computes the identical report from the finalized beacon.
    #[test]
    fn ratchet_is_deterministic_in_entropy() {
        const N: usize = MAX_FAULTS_PER_EPOCH + 300;
        let outcomes: [DisputeOutcome; N] = core::array::from_fn(|i| DisputeOutcome::Majority {
            winning_commit: [0u8; 32],
            slashed_node_id: node_id_of(i),
        });
        let a = apply_epoch_penalties(&outcomes, &FlatStake, &ENTROPY);
        let b = apply_epoch_penalties(&outcomes, &FlatStake, &ENTROPY);
        assert_eq!(a, b);
    }

    // ARC-01 (H-3): a flood exceeding the candidate buffer is retained by a stake-blind reservoir —
    // bounded memory, no panic, deterministic; the excess is dropped, never deferred.
    #[test]
    fn ratchet_reservoir_bounds_extreme_flood() {
        const N: usize = MAX_FAULT_MARKET + 1; // 2049 distinct faults > candidate buffer
        let outcomes: [DisputeOutcome; N] = core::array::from_fn(|i| DisputeOutcome::Majority {
            winning_commit: [0u8; 32],
            slashed_node_id: node_id_of(i),
        });
        let report = apply_epoch_penalties(&outcomes, &FlatStake, &ENTROPY);
        assert_eq!(report.penalties.len(), MAX_FAULTS_PER_EPOCH);
        // dropped = (retained 2048 − processed 1024) + reservoir-shed 1 = 1025.
        assert_eq!(report.dropped_faults, N - MAX_FAULTS_PER_EPOCH);
        // Deterministic even on the reservoir path.
        let again = apply_epoch_penalties(&outcomes, &FlatStake, &ENTROPY);
        assert_eq!(report, again);
    }
}
