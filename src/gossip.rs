//! `gossip.rs` — Phase 4: epidemic gossip validation (dedup + strict verify-before-forward).
//!
//! Phase-3 `SignedRecord`s / `SignedReceipt`s disseminate across the DHT by epidemic gossip. Blind
//! forwarding is a trivial **signature-spam DoS** vector: a peer floods junk that every honest node
//! re-broadcasts. This module enforces **verify-before-forward** — a node fully deserializes a
//! message, checks the origin against the [`KeyRegistry`], and re-verifies the ML-DSA-65 signature
//! over the message's context-bound preimage **before** relaying it. A message that fails is not
//! forwarded and its peer is penalized (and dropped). Integrates with the sealed `crypto`/`types`
//! via their public API only; SHA3-256 is reused from `state`. `no_std`, allocation-free on the
//! validation path, no `unsafe`.
//!
//! ## RECON-11 — epidemic deduplication (O(N²) broadcast-storm defense)
//!
//! In a gossip mesh a node receives the **same** message from many neighbors. Without memory it
//! re-verifies (post-quantum, CPU-costly) and re-forwards every copy — an `O(N²)` broadcast storm.
//! [`MessageCache`] is a fixed-capacity FIFO ring of message digests. The validator computes a cheap
//! `SHA3-256` fingerprint **before** the expensive ML-DSA-65 verification; a digest already in the
//! cache short-circuits to [`GossipError::DuplicateMessage`], which carries a **zero** penalty — a
//! neighbor honestly relaying a message you already hold is not misbehavior. Only messages that pass
//! full validation are inserted, so junk never pollutes the cache and repeated junk is still
//! penalized as [`GossipError::SignatureSpam`] rather than masked as a duplicate.
//!
//! ## RECON-17 — per-identity rate limit (cache-thrash defense, Obsidian final audit)
//!
//! A pure FIFO ring lets one identity flush an expensive message out of the cache by broadcasting `N`
//! cheap frames, then re-broadcast the expensive message to force repeated ML-DSA-65 re-verification.
//! [`MessageCache`] therefore **partitions by origin identity**: each `public_key` /
//! `endpoint_pseudonym` may occupy at most `N / `[`CACHE_IDENTITY_DIVISOR`] slots, and once at that
//! cap it recycles only its **own** oldest slot. A single actor can neither dominate the window nor
//! evict another identity's digest — so it cannot thrash the shared ring.

use crate::crypto::{
    write_preimage, ByteSink, CanonicalSerialize, KeyRegistry, SerializationError,
    SignatureVerifier, SliceSink, CAPABILITY_RECORD_MAX_PREIMAGE_LEN, CTX_GOAT_CAPABILITY_RECORD,
    CTX_GOAT_F5_TELEMETRY,
};
use crate::state::sha3_256;
use crate::types::{
    CapabilityRecord, NetworkDensityFrame, SignedRecord, ML_DSA_65_PUBLIC_KEY_LEN,
    ML_DSA_65_SIGNATURE_LEN,
};

/// Stack buffer sized for the largest gossip payload's signing preimage. `CapabilityRecord`
/// (`≤ 753` B) dominates the `NetworkDensityFrame` telemetry preimage, so its bound is the ceiling.
const MAX_GOSSIP_PREIMAGE_LEN: usize = CAPABILITY_RECORD_MAX_PREIMAGE_LEN;

/// Stack buffer sized for a full message fingerprint: `context-bound payload preimage ‖ public_key ‖
/// signature`. The preimage's context byte makes the fingerprint domain-separated across variants,
/// and the fixed-width key+signature suffix keeps it injective.
const MAX_GOSSIP_MESSAGE_LEN: usize =
    MAX_GOSSIP_PREIMAGE_LEN + ML_DSA_65_PUBLIC_KEY_LEN + ML_DSA_65_SIGNATURE_LEN;

// ===========================================================================
// Error typology & peer scoring
// ===========================================================================

/// A gossip-validation rejection. All variants except [`DuplicateMessage`](GossipError::DuplicateMessage)
/// are drop-worthy — the peer that relayed the message is penalized (verify-before-forward: junk
/// never propagates). A duplicate is benign mesh redundancy and carries no penalty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GossipError {
    /// The message digest was already in the [`MessageCache`] — a redundant epidemic copy (RECON-11).
    /// Not forwarded, but **not** a fault: the relaying peer is **not** penalized.
    DuplicateMessage,
    /// The ML-DSA-65 signature did not verify over the context-bound preimage — signature-spam DoS.
    SignatureSpam,
    /// The `(public_key, identity)` origin is not a recognized/staked participant (A-CI3).
    UnauthorizedOrigin,
    /// The message could not be canonically re-serialized for verification (malformed).
    Serialization(SerializationError),
}

impl GossipError {
    /// Peer-score penalty for this rejection. A [`DuplicateMessage`](GossipError::DuplicateMessage)
    /// is benign redundancy (`0`); every genuine validation failure is drop-worthy — one strike
    /// reaches [`PeerScore::DROP_THRESHOLD`].
    #[inline]
    pub fn penalty(&self) -> i32 {
        match self {
            GossipError::DuplicateMessage => 0,
            GossipError::SignatureSpam
            | GossipError::UnauthorizedOrigin
            | GossipError::Serialization(_) => 100,
        }
    }
}

/// A minimal local peer-score backing the verify-before-forward gate. A peer whose message fails
/// [`validate_gossip_message`] is penalized; at or below [`DROP_THRESHOLD`](PeerScore::DROP_THRESHOLD)
/// it is dropped, so signature-spam cannot be amplified across the swarm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerScore {
    /// Current score; starts at `0`, decremented on each invalid message.
    pub score: i32,
}

impl PeerScore {
    /// A peer at or below this score is dropped.
    pub const DROP_THRESHOLD: i32 = -100;

    /// A fresh peer (score `0`).
    #[inline]
    pub const fn new() -> Self {
        Self { score: 0 }
    }

    /// Apply the penalty for a rejected message (saturating). A duplicate is a no-op.
    #[inline]
    pub fn penalize(&mut self, err: &GossipError) {
        self.score = self.score.saturating_sub(err.penalty());
    }

    /// Whether this peer should be dropped from the mesh.
    #[inline]
    pub fn should_drop(&self) -> bool {
        self.score <= Self::DROP_THRESHOLD
    }
}

impl Default for PeerScore {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// RECON-11 — the epidemic-dedup message cache (fixed-capacity FIFO ring)
// ===========================================================================

/// Fraction of a [`MessageCache`]'s capacity a single origin identity may occupy (RECON-17). A
/// gossip storm from one `public_key`/`endpoint_pseudonym` is confined to `N / DIVISOR` slots, so it
/// cannot flush the global FIFO ring to force repeated ML-DSA-65 re-verification of an evicted
/// expensive message (cache thrashing).
pub const CACHE_IDENTITY_DIVISOR: usize = 8;

/// A fixed-capacity, allocation-free ring of recently-accepted message digests, **partitioned by
/// origin identity** (RECON-11 dedup + RECON-17 per-identity fairness). Membership is `O(N)` over at
/// most `N` 32-byte digests; base eviction is FIFO, but any single identity is capped at
/// [`per_identity_cap`](Self::per_identity_cap) slots and recycles only its **own** oldest once at
/// that cap — so one actor can neither dominate the window nor thrash the shared ring to evict
/// another identity's expensive message.
#[derive(Clone, Debug)]
pub struct MessageCache<const N: usize> {
    hashes: [[u8; 32]; N],
    origins: [[u8; 32]; N],
    next: usize,
    filled: usize,
}

impl<const N: usize> MessageCache<N> {
    /// An empty cache.
    #[inline]
    pub const fn new() -> Self {
        Self {
            hashes: [[0u8; 32]; N],
            origins: [[0u8; 32]; N],
            next: 0,
            filled: 0,
        }
    }

    /// Per-identity slot quota: `N / CACHE_IDENTITY_DIVISOR`, at least `1` (RECON-17).
    #[inline]
    pub fn per_identity_cap(&self) -> usize {
        (N / CACHE_IDENTITY_DIVISOR).max(1)
    }

    /// Whether `hash` is currently in the window.
    #[inline]
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.hashes[..self.filled].iter().any(|h| h == hash)
    }

    /// Slots currently occupied by `origin`.
    #[inline]
    pub fn count_for(&self, origin: &[u8; 32]) -> usize {
        self.origins[..self.filled]
            .iter()
            .filter(|o| *o == origin)
            .count()
    }

    /// Record `hash` attributed to `origin` (RECON-11 dedup + RECON-17 per-identity fairness). If
    /// `origin` is already at its [`per_identity_cap`](Self::per_identity_cap), overwrite that
    /// identity's **own** oldest slot instead of advancing the global ring — so a flooding identity
    /// recycles only its own slots and can never evict another identity's message. Otherwise a normal
    /// FIFO insert (which may evict the global-oldest slot). A zero-capacity cache is inert.
    #[inline]
    pub fn insert(&mut self, hash: [u8; 32], origin: [u8; 32]) {
        if N == 0 {
            return;
        }
        if self.count_for(&origin) >= self.per_identity_cap() {
            if let Some(slot) = self.oldest_slot_of(&origin) {
                self.hashes[slot] = hash; // recycle this identity's own oldest; origin unchanged
            }
            return;
        }
        self.hashes[self.next] = hash;
        self.origins[self.next] = origin;
        self.next = (self.next + 1) % N;
        if self.filled < N {
            self.filled += 1;
        }
    }

    /// The oldest occupied slot belonging to `origin`, scanning in insertion (age) order.
    #[inline]
    fn oldest_slot_of(&self, origin: &[u8; 32]) -> Option<usize> {
        let start = if self.filled < N { 0 } else { self.next };
        (0..self.filled).find_map(|k| {
            let idx = (start + k) % N;
            (&self.origins[idx] == origin).then_some(idx)
        })
    }

    /// Number of digests currently retained (`≤ N`).
    #[inline]
    pub fn len(&self) -> usize {
        self.filled
    }

    /// Whether the cache holds no digests.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.filled == 0
    }

    /// Fixed capacity `N`.
    #[inline]
    pub fn capacity(&self) -> usize {
        N
    }
}

impl<const N: usize> Default for MessageCache<N> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Cheap `SHA3-256` fingerprint of a whole gossip message: `len_u8 ‖ ctx ‖ canonical(payload) ‖
/// public_key ‖ signature`. The per-variant context byte domain-separates the two payload types and
/// the fixed-width key+signature suffix keeps distinct wire messages distinct. Computed **before**
/// the ML-DSA-65 verification so redundant epidemic copies are dropped without post-quantum cost.
fn hash_message(message: &GossipMessage) -> Result<[u8; 32], SerializationError> {
    let mut buf = [0u8; MAX_GOSSIP_MESSAGE_LEN];
    let mut sink = SliceSink::new(&mut buf);
    match message {
        GossipMessage::NodeCapability(rec) => {
            write_preimage(&rec.payload, CTX_GOAT_CAPABILITY_RECORD, &mut sink)?;
            sink.put(&rec.public_key)?;
            sink.put(&rec.signature)?;
        }
        GossipMessage::TelemetryFrame(rec) => {
            write_preimage(&rec.payload, CTX_GOAT_F5_TELEMETRY, &mut sink)?;
            sink.put(&rec.public_key)?;
            sink.put(&rec.signature)?;
        }
    }
    Ok(sha3_256(sink.written()))
}

// ===========================================================================
// Gossip payloads & the dedup + verify-before-forward validator
// ===========================================================================

/// The allowed gossip payloads. Each wraps a Phase-3 signed wire structure; the validator matches
/// on the variant to select the origin identity and the signing-context used for verification.
//
// `large_enum_variant` is deliberately allowed: both variants are fixed-size, `no_std`, no-alloc
// wire structures each dominated by a ~5 KB ML-DSA-65 signature (`SignedRecord`); clippy's remedy —
// boxing the larger payload — requires `alloc` and would defeat the allocation-free gossip path.
// The residual ~590 B spread (`CapabilityRecord` vs `NetworkDensityFrame`) is inherent.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GossipMessage {
    /// A node's signed `CapabilityRecord` (routing/onboarding). Origin id = `payload.node_id`,
    /// signed under `CTX_GOAT_CAPABILITY_RECORD`.
    NodeCapability(SignedRecord<CapabilityRecord>),
    /// A signed F5 `NetworkDensityFrame` telemetry sample. Origin id = the endpoint pseudonym,
    /// signed under `CTX_GOAT_F5_TELEMETRY`.
    TelemetryFrame(SignedRecord<NetworkDensityFrame>),
}

/// **Dedup + strict verify-before-forward** (the anti-storm / anti-spam gate). Pipeline:
/// 1. Fingerprint the message (cheap `SHA3-256`) and consult `cache`; a hit returns
///    [`GossipError::DuplicateMessage`] (penalty-free) **before** any post-quantum work (RECON-11).
/// 2. Authorize the origin against `registry`, then verify the ML-DSA-65 signature over the correct
///    context-bound preimage.
/// 3. On success, record the fingerprint in `cache` and return `Ok(())` — the caller may forward.
///
/// On any `Err` the caller must **not** forward; for every variant except `DuplicateMessage` it
/// should also penalize the relaying peer (see [`PeerScore`]). Zero-allocation: preimage and
/// fingerprint are built in stack buffers. Only validated messages are cached, so junk neither
/// pollutes the window nor escapes penalization.
pub fn validate_gossip_message<const N: usize, V: SignatureVerifier, R: KeyRegistry>(
    message: &GossipMessage,
    cache: &mut MessageCache<N>,
    verifier: &V,
    registry: &R,
) -> Result<(), GossipError> {
    // 1. Cheap epidemic dedup BEFORE the expensive ML-DSA-65 verification (RECON-11).
    let digest = hash_message(message).map_err(GossipError::Serialization)?;
    if cache.contains(&digest) {
        return Err(GossipError::DuplicateMessage);
    }

    // 2. Origin authorization + signature verification. Capture the origin identity so the cache can
    //    attribute the slot to it (RECON-17 per-identity fairness).
    let origin = match message {
        GossipMessage::NodeCapability(rec) => {
            validate_origin_signed(
                &rec.payload,
                &rec.payload.node_id,
                &rec.public_key,
                &rec.signature,
                CTX_GOAT_CAPABILITY_RECORD,
                verifier,
                registry,
            )?;
            rec.payload.node_id
        }
        GossipMessage::TelemetryFrame(rec) => {
            validate_origin_signed(
                &rec.payload,
                &rec.payload.header.endpoint_pseudonym,
                &rec.public_key,
                &rec.signature,
                CTX_GOAT_F5_TELEMETRY,
                verifier,
                registry,
            )?;
            rec.payload.header.endpoint_pseudonym
        }
    };

    // 3. Record only fully-validated messages (RECON-11), attributed to their origin so a single
    //    identity cannot thrash the shared ring (RECON-17). Junk is never cached, so it stays
    //    penalizable as SignatureSpam rather than masked as a duplicate.
    cache.insert(digest, origin);
    Ok(())
}

/// The generic verify-before-forward core: (1) the `(public_key, identity)` origin must be
/// authorized; (2) the ML-DSA-65 signature must verify over `len_u8 ‖ ctx ‖ canonical(payload)`,
/// rebuilt on the stack. Order is cheap-authorization → crypto.
fn validate_origin_signed<T, V, R>(
    payload: &T,
    identity: &[u8; 32],
    public_key: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
    signature: &[u8; ML_DSA_65_SIGNATURE_LEN],
    ctx: &[u8],
    verifier: &V,
    registry: &R,
) -> Result<(), GossipError>
where
    T: CanonicalSerialize,
    V: SignatureVerifier,
    R: KeyRegistry,
{
    // 1. Origin authorization (A-CI3): the key must be registered for the claimed identity.
    if !registry.is_authorized(public_key, identity) {
        return Err(GossipError::UnauthorizedOrigin);
    }
    // 2. Signature over the context-bound preimage — reject spam before any forward.
    let mut buf = [0u8; MAX_GOSSIP_PREIMAGE_LEN];
    let mut sink = SliceSink::new(&mut buf);
    write_preimage(payload, ctx, &mut sink).map_err(GossipError::Serialization)?;
    if !verifier.verify_ml_dsa_65(public_key, sink.written(), signature) {
        return Err(GossipError::SignatureSpam);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        BoundedVec, FrameHeader, PowerThermalEnvelope, ML_DSA_65_PUBLIC_KEY_LEN,
        ML_DSA_65_SIGNATURE_LEN, PPM,
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

    fn capability_msg() -> GossipMessage {
        let rec = CapabilityRecord {
            node_id: [1u8; 32],
            epoch: 10,
            beacon_nonce: [0u8; 32],
            prev_record: [0u8; 32],
            capabilities: BoundedVec::new(),
            availability_ppm: PPM,
            power_thermal_envelope: PowerThermalEnvelope {
                power_mw: 1,
                thermal_dk: 1,
            },
            density_witness_ppm: PPM,
        };
        GossipMessage::NodeCapability(SignedRecord {
            payload: rec,
            public_key: [0u8; ML_DSA_65_PUBLIC_KEY_LEN],
            signature: [0u8; ML_DSA_65_SIGNATURE_LEN],
        })
    }

    fn telemetry_msg() -> GossipMessage {
        let frame = NetworkDensityFrame {
            header: FrameHeader {
                schema_version: 2,
                frame_type: crate::types::frame_type::NDF,
                endpoint_pseudonym: [9u8; 32],
                identity_index: 0,
                epoch: 5,
                run_nonce: [0u8; 32],
                chain_id: crate::types::CHAIN_ID_GOAT_MAINNET,
            },
            tick_index: 1,
            dl_bin: 10,
            ul_bin: 8,
            concurrent_flag: 1,
            agg_dl_bin: 12,
            agg_ul_bin: 9,
            rtt_q: [20; 8],
            origin_change_count: 0,
            shared_origin_degree_bin: 0,
            xfer_bytes_bin: 30,
            morphology_id: crate::types::morphology::MORPH_P,
            peak_micro_bin: 14,
            crest_eighth_oct: 4,
            duty_ppm: 800_000,
            throttle_onset_s: 255,
            pre_bin: 0,
            post_bin: 0,
        };
        GossipMessage::TelemetryFrame(SignedRecord {
            payload: frame,
            public_key: [0u8; ML_DSA_65_PUBLIC_KEY_LEN],
            signature: [0u8; ML_DSA_65_SIGNATURE_LEN],
        })
    }

    /// A generously-sized cache for tests.
    fn cache() -> MessageCache<64> {
        MessageCache::new()
    }

    #[test]
    fn valid_capability_forwards() {
        assert_eq!(
            validate_gossip_message(
                &capability_msg(),
                &mut cache(),
                &AllowVerifier,
                &AllowRegistry
            ),
            Ok(())
        );
    }

    #[test]
    fn valid_telemetry_forwards() {
        assert_eq!(
            validate_gossip_message(
                &telemetry_msg(),
                &mut cache(),
                &AllowVerifier,
                &AllowRegistry
            ),
            Ok(())
        );
    }

    #[test]
    fn unregistered_origin_is_rejected() {
        assert_eq!(
            validate_gossip_message(
                &capability_msg(),
                &mut cache(),
                &AllowVerifier,
                &DenyRegistry
            ),
            Err(GossipError::UnauthorizedOrigin)
        );
    }

    #[test]
    fn bad_signature_is_spam() {
        assert_eq!(
            validate_gossip_message(
                &capability_msg(),
                &mut cache(),
                &DenyVerifier,
                &AllowRegistry
            ),
            Err(GossipError::SignatureSpam)
        );
        // Telemetry path too.
        assert_eq!(
            validate_gossip_message(
                &telemetry_msg(),
                &mut cache(),
                &DenyVerifier,
                &AllowRegistry
            ),
            Err(GossipError::SignatureSpam)
        );
    }

    // Authorization is checked before the (more expensive) signature — an unregistered origin is
    // rejected as UnauthorizedOrigin even if its signature would also fail.
    #[test]
    fn authorization_precedes_signature() {
        assert_eq!(
            validate_gossip_message(
                &capability_msg(),
                &mut cache(),
                &DenyVerifier,
                &DenyRegistry
            ),
            Err(GossipError::UnauthorizedOrigin)
        );
    }

    #[test]
    fn peer_scoring_drops_on_spam() {
        let mut peer = PeerScore::new();
        assert!(!peer.should_drop());
        let err = validate_gossip_message(
            &capability_msg(),
            &mut cache(),
            &DenyVerifier,
            &AllowRegistry,
        )
        .unwrap_err();
        peer.penalize(&err);
        assert!(peer.should_drop()); // one signature-spam strike drops the peer
    }

    // --- RECON-11 epidemic deduplication ----------------------------------

    #[test]
    fn duplicate_is_dropped_without_penalty() {
        let mut c = cache();
        let msg = capability_msg();
        // First sighting validates and is cached.
        assert_eq!(
            validate_gossip_message(&msg, &mut c, &AllowVerifier, &AllowRegistry),
            Ok(())
        );
        assert_eq!(c.len(), 1);
        // Second sighting (any mesh path) is a penalty-free duplicate — no re-verification/forward.
        let err =
            validate_gossip_message(&msg, &mut c, &AllowVerifier, &AllowRegistry).unwrap_err();
        assert_eq!(err, GossipError::DuplicateMessage);
        assert_eq!(err.penalty(), 0);
        // The duplicate did not grow the window.
        assert_eq!(c.len(), 1);
        // And it does not drop an honest relaying peer.
        let mut peer = PeerScore::new();
        peer.penalize(&err);
        assert!(!peer.should_drop());
    }

    #[test]
    fn distinct_messages_do_not_alias() {
        let mut c = cache();
        assert_eq!(
            validate_gossip_message(&capability_msg(), &mut c, &AllowVerifier, &AllowRegistry),
            Ok(())
        );
        // A different payload type must NOT be seen as a duplicate.
        assert_eq!(
            validate_gossip_message(&telemetry_msg(), &mut c, &AllowVerifier, &AllowRegistry),
            Ok(())
        );
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn failed_validation_is_not_cached() {
        let mut c = cache();
        // A spam message fails and must NOT be inserted (else a re-send would masquerade as a
        // penalty-free duplicate and escape scoring).
        assert_eq!(
            validate_gossip_message(&capability_msg(), &mut c, &DenyVerifier, &AllowRegistry),
            Err(GossipError::SignatureSpam)
        );
        assert!(c.is_empty());
        // Re-sending the same junk is still SignatureSpam, not DuplicateMessage.
        assert_eq!(
            validate_gossip_message(&capability_msg(), &mut c, &DenyVerifier, &AllowRegistry),
            Err(GossipError::SignatureSpam)
        );
    }

    #[test]
    fn cache_ring_evicts_fifo() {
        // Distinct origins (A/B/C) each stay under the per-identity cap, so base FIFO applies.
        let mut c: MessageCache<2> = MessageCache::new();
        c.insert([1u8; 32], [10u8; 32]);
        c.insert([2u8; 32], [20u8; 32]);
        assert!(c.contains(&[1u8; 32]));
        assert!(c.contains(&[2u8; 32]));
        assert_eq!(c.len(), 2);
        // Overflow evicts the oldest ([1;32]).
        c.insert([3u8; 32], [30u8; 32]);
        assert!(!c.contains(&[1u8; 32]));
        assert!(c.contains(&[2u8; 32]));
        assert!(c.contains(&[3u8; 32]));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn zero_capacity_cache_is_inert() {
        let mut c: MessageCache<0> = MessageCache::new();
        c.insert([7u8; 32], [1u8; 32]);
        assert!(c.is_empty());
        assert!(!c.contains(&[7u8; 32]));
        // With no cache, the same valid message is (re)validated every time — never a duplicate.
        assert_eq!(
            validate_gossip_message(&capability_msg(), &mut c, &AllowVerifier, &AllowRegistry),
            Ok(())
        );
        assert_eq!(
            validate_gossip_message(&capability_msg(), &mut c, &AllowVerifier, &AllowRegistry),
            Ok(())
        );
    }

    // --- RECON-17 per-identity rate limit (cache-thrash defense) -----------

    #[test]
    fn per_identity_cap_confines_a_flooder() {
        // Cache of 64 ⇒ per-identity cap = 8. One victim message from identity Y, then a 100-message
        // flood from identity X. X is confined to 8 slots and can never evict Y.
        let mut c: MessageCache<64> = MessageCache::new();
        assert_eq!(c.per_identity_cap(), 8);
        let victim = [0xAB; 32];
        let y = [0xEE; 32];
        c.insert(victim, y);

        let x = [0xCC; 32];
        for i in 0..100u32 {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_le_bytes());
            c.insert(h, x);
        }
        // X occupies exactly its quota; the victim's slot survives; the ring never overflowed.
        assert_eq!(c.count_for(&x), 8);
        assert!(c.contains(&victim));
        assert_eq!(c.count_for(&y), 1);
        assert_eq!(c.len(), 9);
    }

    #[test]
    fn per_identity_cap_is_at_least_one() {
        // Tiny caches still admit one slot per identity (no divide-to-zero starvation).
        let c: MessageCache<4> = MessageCache::new();
        assert_eq!(c.per_identity_cap(), 1);
    }
}
