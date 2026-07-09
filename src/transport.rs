//! `transport.rs` — Phase 4: hybrid post-quantum transport handshake + secure-channel abstraction.
//!
//! Peers establish an `AES-256-GCM` tunnel keyed by an **ML-KEM-768** (Kyber) exchange and
//! authenticated by their long-term **ML-DSA-65** identity keys (Threat Model §16–§17). This module
//! defines the handshake messages, their canonical (injective, little-endian) serialization, their
//! `CTX_GOAT_TRANSPORT_HS`-bound signing preimages, the [`SecureChannel`] cipher abstraction, and
//! (RECON-11) the stateless-cookie anti-DoS state machine. Integrates with the **sealed** Phase-3
//! `crypto`/`types` through their public API only; SHA3-256 is reused from `state`. `no_std`, no
//! `unsafe`.
//!
//! ## Handshake shape (Noise-style, forward-secret)
//!
//! `HandshakeInitiation` carries the initiator's ML-DSA identity + an **ephemeral** ML-KEM
//! encapsulation key; `HandshakeResponse` carries the responder's identity + the ML-KEM
//! **ciphertext**. Both are ML-DSA-65-signed over their `CTX_GOAT_TRANSPORT_HS` preimage, so every
//! KEM element that influences the derived key is signed (A-CI4). The 32-byte ML-KEM shared secret
//! is expanded (session layer, via a KDF) into the `AES-256-GCM` key of a [`SecureChannel`].
//!
//! ## RECON-11 — stateless cookie (asymmetric-CPU DoS defense)
//!
//! Post-quantum operations (ML-KEM decapsulation, ML-DSA verification) are CPU-intensive; a spoofed
//! source address must not be able to force them. A DTLS-style **stateless cookie** proves address
//! ownership *before* any PQ work or session allocation:
//! 1. On a [`HandshakeInitiation`], the responder does **no** PQ crypto and allocates **no** session;
//!    it replies with a cheap [`CookieChallenge`] — `HMAC-SHA3-256(node_secret ‖ peer_addr ‖ ts)`.
//! 2. The initiator echoes it in a [`HandshakeCookieEcho`] carrying the original initiation.
//! 3. The responder recomputes the MAC over the *observed* source address; **only if it matches**
//!    (proving the peer controls the address) does it proceed to [`verify_initiation`] +
//!    decapsulation. The responder holds **zero** per-initiation state between steps 1 and 3.
//!
//! ## RECON-12 — single-use cookies (replay-within-window defense)
//!
//! The stateless cookie proves address ownership, but a node that *does* control its address can
//! request one legitimate cookie and replay the *same* MAC-valid [`HandshakeCookieEcho`] thousands
//! of times inside the freshness window — each copy forcing a fresh ML-KEM decapsulation + ML-DSA
//! verification. [`CookieCache`] makes an accepted cookie **strictly single-use**: after the MAC
//! passes, the cookie value is looked up and, if already seen, rejected as
//! [`TransportError::CookieReplayed`] *before* any post-quantum work; otherwise it is recorded. Like
//! the gossip [`MessageCache`](crate::gossip::MessageCache), only MAC-valid cookies are inserted, so
//! an adversarial node cannot pollute or evict the window with forged values.
//!
//! ## RECON-14 — the Chronos Trap (Obsidian final audit)
//!
//! Cookie freshness cannot depend on the raw local wall-clock: an NTP-poisoning adversary who drifts
//! a target's clock past `max_cookie_age` makes it reject every honest cookie as expired — a
//! cryptography-free eclipse. The [`NetworkClock`] maintains a **bounded median time offset** from
//! the *signed* `local_time` of successfully authenticated peers (one sample per distinct peer
//! address, so no single peer dominates; median, so a hostile minority cannot skew it; clamped to
//! ±[`MAX_CLOCK_SKEW_SECS`], so even an outlier majority is magnitude-bounded). Both [`issue_cookie`]
//! and [`verify_cookie_echo`] stamp and check against this drift-resilient **logical time**
//! ([`NetworkClock::logical_now`]) rather than the raw system clock, so a poisoned local clock is
//! transparently corrected back toward the network's authenticated consensus of "now."

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use crate::crypto::preimage;
use crate::crypto::{
    write_preimage, ByteSink, CanonicalSerialize, SerializationError, SignatureVerifier, SliceSink,
    CHAIN_ID_LEN, CTX_GOAT_TRANSPORT_HS,
};
use crate::state::sha3_256;
use crate::types::{Epoch, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN};

// ===========================================================================
// Cryptographic footprints — FIPS 203 ML-KEM-768 & AES-256-GCM (fixed-width)
// ===========================================================================

/// ML-KEM-768 encapsulation (public) key length in bytes (FIPS 203).
pub const ML_KEM_768_ENCAPS_KEY_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length in bytes (FIPS 203).
pub const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
/// ML-KEM-768 shared-secret length in bytes — the KDF input for the AES-256 key.
pub const ML_KEM_768_SHARED_SECRET_LEN: usize = 32;

/// AES-256-GCM key length in bytes.
pub const AES_256_GCM_KEY_LEN: usize = 32;
/// AES-256-GCM nonce length in bytes (96-bit; disjoint per-direction spaces, §17).
pub const AES_256_GCM_NONCE_LEN: usize = 12;
/// AES-256-GCM authentication-tag length in bytes.
pub const AES_256_GCM_TAG_LEN: usize = 16;

/// Peer address length bound for the cookie MAC — 16 bytes holds an IPv6 (or IPv4-mapped) address.
pub const PEER_ADDR_LEN: usize = 16;

/// Default cookie freshness window in seconds (RECON-11/12). A returned cookie older than this is
/// rejected as [`TransportError::CookieExpired`]; the single-use [`CookieCache`] must be sized to
/// cover the cookies issuable within this window ([calibration]).
pub const MAX_COOKIE_AGE_SECS: u64 = 60;

/// Number of authenticated-peer clock samples the [`NetworkClock`] holds — the median window
/// (RECON-14). One sample per distinct peer address; a robust median needs a modest quorum.
pub const NETWORK_TIME_WINDOW: usize = 16;

/// Hard clamp on the logical time offset, in seconds (RECON-14). Even if a majority of the sample
/// window were hostile, the median offset is bounded to ±this, capping any clock manipulation.
pub const MAX_CLOCK_SKEW_SECS: i64 = 300;

/// Grace, in seconds, allowed on the *future* side of the freshness check (RECON-14) — absorbs
/// benign skew between a just-minted cookie's logical timestamp and the verifier's logical now.
pub const CLOCK_FUTURE_TOLERANCE_SECS: u64 = 5;

/// Authenticated-peer samples the [`NetworkClock`] must hold before its median is trusted enough to
/// enforce cookie *freshness* (ARC-01-M5, bootstrap grace). Below this quorum a freshly-booted node
/// relies on the un-spoofable address-bound MAC + single-use cache instead of the not-yet-formed
/// median — resolving the cold-start clock deadlock (ARC-01, H-2) without weakening anti-spoof or
/// anti-replay.
pub const BOOTSTRAP_QUORUM: usize = 3;

/// SHA3-256 rate = the HMAC block size `B` for HMAC-SHA3-256.
const HMAC_BLOCK: usize = 136;

// ===========================================================================
// Error typology
// ===========================================================================

/// A transport-layer failure. Total and `Copy`; no path panics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// An output buffer was too small for the frame.
    BufferTooSmall,
    /// AEAD authentication failed — tag mismatch (tamper/forgery) or a replayed frame.
    DecryptionFailed,
    /// The per-direction nonce space is exhausted; the channel must be re-keyed.
    NonceExhausted,
    /// A handshake message's ML-DSA-65 signature did not verify over its context-bound preimage.
    BadHandshakeSignature,
    /// A returned cookie's MAC did not match — the peer does not control the claimed address, or the
    /// cookie is forged (RECON-11). No PQ crypto is spent.
    InvalidCookie,
    /// A returned cookie is outside the freshness window (stale replay or future-dated) (RECON-11).
    CookieExpired,
    /// A MAC-valid cookie was presented more than once inside its freshness window (RECON-12). The
    /// single-use [`CookieCache`] already holds it; the replay is dropped before any PQ crypto.
    CookieReplayed,
    /// A canonical-serialization failure while rebuilding a handshake preimage (unreachable with the
    /// correctly-sized stack buffers here; surfaced rather than panicked).
    Serialization(SerializationError),
}

impl From<SerializationError> for TransportError {
    #[inline]
    fn from(e: SerializationError) -> Self {
        TransportError::Serialization(e)
    }
}

// ===========================================================================
// Handshake messages
// ===========================================================================

/// `HandshakeInitiation` (initiator → responder). The signable body of the first handshake message:
/// the initiator's long-term ML-DSA-65 identity, an **ephemeral** ML-KEM-768 encapsulation key, the
/// handshake epoch (anti-stale), and an anti-replay nonce. Signed under `CTX_GOAT_TRANSPORT_HS`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeInitiation {
    /// Initiator's long-term ML-DSA-65 identity public key.
    pub initiator_identity: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
    /// Ephemeral ML-KEM-768 encapsulation (public) key the responder encapsulates against.
    pub ephemeral_kem_pk: [u8; ML_KEM_768_ENCAPS_KEY_LEN],
    /// Handshake epoch (rejects stale/replayed initiations).
    pub epoch: Epoch,
    /// Initiator's asserted wall-clock (Unix seconds), **signed** — the Chronos median-time anchor
    /// (RECON-14). Trusted only after the signature verifies; contributes one sample to the peer's
    /// [`NetworkClock`].
    pub local_time: u64,
    /// Anti-replay nonce (beacon-seeded at the session layer).
    pub nonce: [u8; 32],
}

/// `HandshakeResponse` (responder → initiator). The signable body of the second message: the
/// responder's ML-DSA-65 identity, the ML-KEM-768 **ciphertext** (encapsulated against the
/// initiator's ephemeral key — the shared secret's carrier), the epoch, and a nonce. Signed under
/// `CTX_GOAT_TRANSPORT_HS`, so the signature covers the ciphertext (A-CI4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeResponse {
    /// Responder's long-term ML-DSA-65 identity public key.
    pub responder_identity: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
    /// ML-KEM-768 ciphertext carrying the shared secret.
    pub kem_ciphertext: [u8; ML_KEM_768_CIPHERTEXT_LEN],
    /// Handshake epoch.
    pub epoch: Epoch,
    /// Responder's asserted wall-clock (Unix seconds), **signed** — the Chronos median-time anchor
    /// (RECON-14). Trusted only after the signature verifies; contributes one sample to the peer's
    /// [`NetworkClock`].
    pub local_time: u64,
    /// Anti-replay nonce.
    pub nonce: [u8; 32],
}

impl CanonicalSerialize for HandshakeInitiation {
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        // Fixed-width, little-endian, no length prefixes (all fields fixed-size).
        out.put(&self.initiator_identity)?;
        out.put(&self.ephemeral_kem_pk)?;
        out.put(&self.epoch.to_le_bytes())?;
        out.put(&self.local_time.to_le_bytes())?;
        out.put(&self.nonce)
    }
}

impl CanonicalSerialize for HandshakeResponse {
    fn serialize_into<S: ByteSink>(&self, out: &mut S) -> Result<(), SerializationError> {
        out.put(&self.responder_identity)?;
        out.put(&self.kem_ciphertext)?;
        out.put(&self.epoch.to_le_bytes())?;
        out.put(&self.local_time.to_le_bytes())?;
        out.put(&self.nonce)
    }
}

/// Max serialized body of a [`HandshakeInitiation`] (identity ‖ kem_pk ‖ epoch ‖ local_time ‖ nonce).
pub const HANDSHAKE_INITIATION_BODY_LEN: usize =
    ML_DSA_65_PUBLIC_KEY_LEN + ML_KEM_768_ENCAPS_KEY_LEN + 8 + 8 + 32;
/// Max signing-preimage length: body + `len_u8 ‖ CTX_GOAT_TRANSPORT_HS ‖ chain_id` (RECON-15 adds
/// [`CHAIN_ID_LEN`] — the handshake signature is chain-bound like every other preimage).
pub const HANDSHAKE_INITIATION_MAX_PREIMAGE_LEN: usize =
    HANDSHAKE_INITIATION_BODY_LEN + 1 + CTX_GOAT_TRANSPORT_HS.len() + CHAIN_ID_LEN;

/// Max serialized body of a [`HandshakeResponse`] (identity ‖ ciphertext ‖ epoch ‖ local_time ‖ nonce).
pub const HANDSHAKE_RESPONSE_BODY_LEN: usize =
    ML_DSA_65_PUBLIC_KEY_LEN + ML_KEM_768_CIPHERTEXT_LEN + 8 + 8 + 32;
/// Max signing-preimage length: body + `len_u8 ‖ CTX_GOAT_TRANSPORT_HS ‖ chain_id` (RECON-15).
pub const HANDSHAKE_RESPONSE_MAX_PREIMAGE_LEN: usize =
    HANDSHAKE_RESPONSE_BODY_LEN + 1 + CTX_GOAT_TRANSPORT_HS.len() + CHAIN_ID_LEN;

impl HandshakeInitiation {
    /// Heap signing preimage bound to `CTX_GOAT_TRANSPORT_HS` (feature `alloc`).
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn signing_preimage(&self) -> Result<Vec<u8>, SerializationError> {
        preimage(self, CTX_GOAT_TRANSPORT_HS)
    }
    /// Zero-allocation preimage into a caller sink (size with [`HANDSHAKE_INITIATION_MAX_PREIMAGE_LEN`]).
    #[inline]
    pub fn write_signing_preimage<S: ByteSink>(
        &self,
        out: &mut S,
    ) -> Result<(), SerializationError> {
        write_preimage(self, CTX_GOAT_TRANSPORT_HS, out)
    }
}

impl HandshakeResponse {
    /// Heap signing preimage bound to `CTX_GOAT_TRANSPORT_HS` (feature `alloc`).
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn signing_preimage(&self) -> Result<Vec<u8>, SerializationError> {
        preimage(self, CTX_GOAT_TRANSPORT_HS)
    }
    /// Zero-allocation preimage into a caller sink (size with [`HANDSHAKE_RESPONSE_MAX_PREIMAGE_LEN`]).
    #[inline]
    pub fn write_signing_preimage<S: ByteSink>(
        &self,
        out: &mut S,
    ) -> Result<(), SerializationError> {
        write_preimage(self, CTX_GOAT_TRANSPORT_HS, out)
    }
}

/// Verify a [`HandshakeInitiation`]'s ML-DSA-65 signature over its `CTX_GOAT_TRANSPORT_HS` preimage,
/// under the initiator's own identity key. Zero-allocation (stack preimage). **RECON-11:** call this
/// only *after* [`verify_cookie_echo`] passes — it is a post-quantum, CPU-costly step.
pub fn verify_initiation<V: SignatureVerifier>(
    init: &HandshakeInitiation,
    signature: &[u8; ML_DSA_65_SIGNATURE_LEN],
    verifier: &V,
) -> Result<(), TransportError> {
    let mut buf = [0u8; HANDSHAKE_INITIATION_MAX_PREIMAGE_LEN];
    let mut sink = SliceSink::new(&mut buf);
    init.write_signing_preimage(&mut sink)?;
    if verifier.verify_ml_dsa_65(&init.initiator_identity, sink.written(), signature) {
        Ok(())
    } else {
        Err(TransportError::BadHandshakeSignature)
    }
}

/// Verify a [`HandshakeResponse`]'s ML-DSA-65 signature over its `CTX_GOAT_TRANSPORT_HS` preimage,
/// under the responder's identity key. Zero-allocation (stack preimage).
pub fn verify_response<V: SignatureVerifier>(
    resp: &HandshakeResponse,
    signature: &[u8; ML_DSA_65_SIGNATURE_LEN],
    verifier: &V,
) -> Result<(), TransportError> {
    let mut buf = [0u8; HANDSHAKE_RESPONSE_MAX_PREIMAGE_LEN];
    let mut sink = SliceSink::new(&mut buf);
    resp.write_signing_preimage(&mut sink)?;
    if verifier.verify_ml_dsa_65(&resp.responder_identity, sink.written(), signature) {
        Ok(())
    } else {
        Err(TransportError::BadHandshakeSignature)
    }
}

// ===========================================================================
// RECON-11/12 — stateless single-use cookie challenge (address-ownership proof)
// ===========================================================================

/// A fixed-capacity, allocation-free FIFO ring of accepted **single-use cookie** values —
/// architecturally identical to [`MessageCache`](crate::gossip::MessageCache), specialized to the
/// 32-byte cookie. RECON-12: a MAC-valid cookie is recorded on first acceptance so any replay of it
/// within the freshness window is rejected before any post-quantum work. Eviction is FIFO; capacity
/// `N` must exceed the number of distinct cookies issuable within `max_cookie_age` ([calibration])
/// or an evicted-but-still-fresh cookie could be replayed once more.
#[derive(Clone, Debug)]
pub struct CookieCache<const N: usize> {
    cookies: [[u8; 32]; N],
    next: usize,
    filled: usize,
}

impl<const N: usize> CookieCache<N> {
    /// An empty cache.
    #[inline]
    pub const fn new() -> Self {
        Self {
            cookies: [[0u8; 32]; N],
            next: 0,
            filled: 0,
        }
    }

    /// Whether `cookie` is currently in the window.
    #[inline]
    pub fn contains(&self, cookie: &[u8; 32]) -> bool {
        self.cookies[..self.filled].iter().any(|c| c == cookie)
    }

    /// Record `cookie`, evicting the oldest entry once full (FIFO). A zero-capacity cache is inert.
    #[inline]
    pub fn insert(&mut self, cookie: [u8; 32]) {
        if N == 0 {
            return;
        }
        self.cookies[self.next] = cookie;
        self.next = (self.next + 1) % N;
        if self.filled < N {
            self.filled += 1;
        }
    }

    /// Number of cookies currently retained (`≤ N`).
    #[inline]
    pub fn len(&self) -> usize {
        self.filled
    }

    /// Whether the cache holds no cookies.
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

impl<const N: usize> Default for CookieCache<N> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// RECON-14 — median network time (Chronos Trap defense)
// ===========================================================================

/// A drift-resilient logical clock: the **bounded median offset** between this node's local
/// wall-clock and the *signed* `local_time` of successfully authenticated peers (RECON-14). It holds
/// at most [`NETWORK_TIME_WINDOW`] samples, **one per distinct peer address** (so a single peer
/// reconnecting cannot dominate), takes their **median** (robust to a hostile minority), and
/// **clamps** the result to ±[`MAX_CLOCK_SKEW_SECS`] (so even an outlier majority is
/// magnitude-bounded). A `genesis_floor` (ARC-01-M6) lower-bounds [`logical_now`](Self::logical_now)
/// so an *uninitialized* boot clock (reading near 0) cannot produce an absurd logical time. `no_std`,
/// allocation-free, panic-free.
#[derive(Clone, Debug)]
pub struct NetworkClock {
    addrs: [[u8; PEER_ADDR_LEN]; NETWORK_TIME_WINDOW],
    offsets: [i64; NETWORK_TIME_WINDOW],
    next: usize,
    filled: usize,
    genesis_floor: u64,
}

impl NetworkClock {
    /// A fresh clock with no samples and no floor — [`logical_now`](Self::logical_now) is the
    /// identity until the first authenticated peer is recorded.
    #[inline]
    pub const fn new() -> Self {
        Self {
            addrs: [[0u8; PEER_ADDR_LEN]; NETWORK_TIME_WINDOW],
            offsets: [0i64; NETWORK_TIME_WINDOW],
            next: 0,
            filled: 0,
            genesis_floor: 0,
        }
    }

    /// A fresh clock anchored to the network's `genesis_floor` (the hardcoded genesis Unix timestamp
    /// from the node configuration — ARC-01-M6). [`logical_now`](Self::logical_now) never returns a
    /// value below this floor, so a cold-boot node whose RTC reads ~0 still issues sane cookie
    /// timestamps (`≥ genesis`) instead of wild ones. Once real peer samples arrive they govern the
    /// offset; the floor stays inert whenever the local clock is plausibly post-genesis.
    #[inline]
    pub const fn with_genesis_anchor(genesis_floor: u64) -> Self {
        Self {
            addrs: [[0u8; PEER_ADDR_LEN]; NETWORK_TIME_WINDOW],
            offsets: [0i64; NETWORK_TIME_WINDOW],
            next: 0,
            filled: 0,
            genesis_floor,
        }
    }

    /// Record an **authenticated** peer's asserted clock. The caller MUST have verified the peer's
    /// handshake signature first — only then is `peer_time` trustworthy (RECON-14). One slot per
    /// distinct `peer_addr` (updated in place), so a single identity cannot stuff the window; a new
    /// address FIFO-evicts the oldest. Offsets saturate (no overflow/panic).
    pub fn record_peer_time(
        &mut self,
        peer_addr: &[u8; PEER_ADDR_LEN],
        peer_time: u64,
        local_time: u64,
    ) {
        let offset = (peer_time as i64).saturating_sub(local_time as i64);
        for i in 0..self.filled {
            if &self.addrs[i] == peer_addr {
                self.offsets[i] = offset; // most-recent reading for this peer
                return;
            }
        }
        self.addrs[self.next] = *peer_addr;
        self.offsets[self.next] = offset;
        self.next = (self.next + 1) % NETWORK_TIME_WINDOW;
        if self.filled < NETWORK_TIME_WINDOW {
            self.filled += 1;
        }
    }

    /// The bounded median offset: `0` with no samples (fall back to the raw local clock), otherwise
    /// the median of the per-peer offsets clamped to ±[`MAX_CLOCK_SKEW_SECS`].
    pub fn offset(&self) -> i64 {
        if self.filled == 0 {
            return 0;
        }
        let mut buf = [0i64; NETWORK_TIME_WINDOW];
        buf[..self.filled].copy_from_slice(&self.offsets[..self.filled]);
        let s = &mut buf[..self.filled];
        s.sort_unstable();
        let median = s[self.filled / 2]; // lower-median for even counts — deterministic
        median.clamp(-MAX_CLOCK_SKEW_SECS, MAX_CLOCK_SKEW_SECS)
    }

    /// Drift-resilient logical "now": the raw `local_time` corrected by the bounded median peer
    /// offset, then floored at `genesis_floor` (ARC-01-M6). A poisoned local clock is pulled toward
    /// network consensus; an uninitialized (near-zero) clock is lifted to at least genesis.
    #[inline]
    pub fn logical_now(&self, local_time: u64) -> u64 {
        let off = self.offset();
        let corrected = if off >= 0 {
            local_time.saturating_add(off as u64)
        } else {
            local_time.saturating_sub(off.unsigned_abs())
        };
        corrected.max(self.genesis_floor)
    }

    /// Number of distinct-peer samples currently held.
    #[inline]
    pub fn samples(&self) -> usize {
        self.filled
    }

    /// Whether any peer sample has been recorded.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.filled == 0
    }
}

impl Default for NetworkClock {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// A stateless anti-DoS cookie: the responder's `HMAC-SHA3-256(node_secret ‖ peer_addr ‖ timestamp)`
/// plus the timestamp it was minted at. Cheap to produce (one keyed hash) and holds **no**
/// per-initiation state — the peer must echo it back to prove address ownership (RECON-11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CookieChallenge {
    /// The cookie MAC over `(node_secret, peer_addr, timestamp)`.
    pub cookie: [u8; 32],
    /// When the cookie was minted (freshness / replay bound).
    pub timestamp: u64,
}

/// The initiator's reply that echoes a [`CookieChallenge`] back with the original initiation, so the
/// responder can re-derive and check the MAC before spending post-quantum crypto (RECON-11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeCookieEcho {
    /// The cookie echoed verbatim from the [`CookieChallenge`].
    pub cookie: [u8; 32],
    /// The echoed mint timestamp.
    pub timestamp: u64,
    /// The original initiation, now eligible for post-quantum processing once the cookie checks out.
    pub initiation: HandshakeInitiation,
}

/// `HMAC-SHA3-256(key = node_secret, msg = peer_addr ‖ timestamp_le)`. Pure-integer, `no_std`,
/// stack-only; reuses the FIPS-202 `sha3_256`.
fn cookie_mac(node_secret: &[u8; 32], peer_addr: &[u8; PEER_ADDR_LEN], timestamp: u64) -> [u8; 32] {
    // Key ≤ block size ⇒ zero-pad to B; standard HMAC ipad/opad.
    let mut k0 = [0u8; HMAC_BLOCK];
    k0[..32].copy_from_slice(node_secret);

    let mut inner_input = [0u8; HMAC_BLOCK + PEER_ADDR_LEN + 8];
    for (dst, &k) in inner_input[..HMAC_BLOCK].iter_mut().zip(k0.iter()) {
        *dst = k ^ 0x36;
    }
    inner_input[HMAC_BLOCK..HMAC_BLOCK + PEER_ADDR_LEN].copy_from_slice(peer_addr);
    inner_input[HMAC_BLOCK + PEER_ADDR_LEN..].copy_from_slice(&timestamp.to_le_bytes());
    let inner = sha3_256(&inner_input);

    let mut outer_input = [0u8; HMAC_BLOCK + 32];
    for (dst, &k) in outer_input[..HMAC_BLOCK].iter_mut().zip(k0.iter()) {
        *dst = k ^ 0x5c;
    }
    outer_input[HMAC_BLOCK..].copy_from_slice(&inner);
    sha3_256(&outer_input)
}

/// Constant-time equality for two 32-byte MACs (no early-exit timing leak).
#[inline]
fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// **RECON-11 step 1 (+ RECON-14).** Cheaply mint a stateless [`CookieChallenge`] for an initiation
/// observed from `peer_addr`, stamped with drift-resilient **logical** time
/// ([`NetworkClock::logical_now`]) rather than the raw local clock. Performs **no** post-quantum
/// crypto and allocates **no** session — one keyed hash.
pub fn issue_cookie(
    node_secret: &[u8; 32],
    peer_addr: &[u8; PEER_ADDR_LEN],
    clock: &NetworkClock,
    local_time: u64,
) -> CookieChallenge {
    let timestamp = clock.logical_now(local_time);
    CookieChallenge {
        cookie: cookie_mac(node_secret, peer_addr, timestamp),
        timestamp,
    }
}

/// **RECON-11 step 3 + RECON-12 single-use + RECON-14 network time.** Verify a returned
/// [`HandshakeCookieEcho`]:
/// 1. **Freshness against logical time** — resolve `network_time = clock.logical_now(local_time)`
///    (the drift-resilient median network clock, *not* the raw local wall-clock), then reject
///    cookies dated more than [`CLOCK_FUTURE_TOLERANCE_SECS`] in the future or older than
///    `max_cookie_age` ([`TransportError::CookieExpired`]). This closes the Chronos Trap: an
///    NTP-poisoned local clock no longer rejects honest cookies.
/// 2. **Address-bound MAC** — recompute over the **observed** source address (`peer_addr`) and the
///    echoed timestamp, constant-time-compare ([`TransportError::InvalidCookie`]). A spoofed source
///    cannot reproduce it.
/// 3. **Single-use** (RECON-12) — a MAC-valid cookie already in `cache` is a replay
///    ([`TransportError::CookieReplayed`]); otherwise it is recorded and consumed.
///
/// All checks are cheap (one keyed hash + ring lookups) and run **before** any post-quantum work.
/// Only on `Ok(())` should the caller spend PQ crypto ([`verify_initiation`], ML-KEM decapsulation)
/// and allocate a session. Only MAC-valid cookies are inserted, so an adversarial node cannot
/// pollute or evict the window with forged values.
pub fn verify_cookie_echo<const N: usize>(
    echo: &HandshakeCookieEcho,
    node_secret: &[u8; 32],
    peer_addr: &[u8; PEER_ADDR_LEN],
    clock: &NetworkClock,
    local_time: u64,
    max_cookie_age: u64,
    cache: &mut CookieCache<N>,
) -> Result<(), TransportError> {
    // 1. Freshness against drift-resilient logical time (RECON-14), not the raw local clock —
    //    EXCEPT during bootstrap grace (ARC-01-M5): below BOOTSTRAP_QUORUM authenticated samples the
    //    median is not yet trustworthy, so a cold node skips the freshness check and relies solely on
    //    the un-spoofable address MAC + single-use cache. This breaks the cold-start clock deadlock
    //    (H-2) without weakening anti-spoof (step 2) or anti-replay (step 3).
    if clock.samples() >= BOOTSTRAP_QUORUM {
        let network_time = clock.logical_now(local_time);
        if echo.timestamp > network_time.saturating_add(CLOCK_FUTURE_TOLERANCE_SECS)
            || network_time.saturating_sub(echo.timestamp) > max_cookie_age
        {
            return Err(TransportError::CookieExpired);
        }
    }
    // 2. Address-bound MAC over the *observed* address — a spoofed source cannot match.
    let expected = cookie_mac(node_secret, peer_addr, echo.timestamp);
    if !ct_eq_32(&expected, &echo.cookie) {
        return Err(TransportError::InvalidCookie);
    }
    // 3. RECON-12 single-use: a MAC-valid cookie replayed within the window would otherwise force a
    //    fresh ML-KEM decapsulation + ML-DSA verification on every copy. Consume it exactly once.
    if cache.contains(&echo.cookie) {
        return Err(TransportError::CookieReplayed);
    }
    cache.insert(echo.cookie);
    Ok(())
}

// ===========================================================================
// The AES-256-GCM secure channel (abstraction)
// ===========================================================================

/// The post-handshake `AES-256-GCM` framing interface. An implementation holds the derived 32-byte
/// key and manages **disjoint per-direction nonce spaces** (§17) so key–nonce pairs never repeat;
/// the AEAD primitive is library-provided (out of audit scope, Threat Model §0), abstracted here so
/// the protocol logic is testable independently of the cipher backend.
pub trait SecureChannel {
    /// Encrypt `plaintext` under the next outbound nonce, writing `ciphertext ‖ tag` into `out`.
    /// Returns the bytes written (`plaintext.len() + AES_256_GCM_TAG_LEN`), or
    /// [`TransportError::BufferTooSmall`] / [`TransportError::NonceExhausted`].
    fn encrypt_frame(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, TransportError>;

    /// Decrypt an inbound `frame` (`ciphertext ‖ tag`) under the expected inbound nonce, writing the
    /// plaintext into `out`. Returns the plaintext length, or [`TransportError::DecryptionFailed`]
    /// on a tag mismatch / replay, or [`TransportError::BufferTooSmall`].
    fn decrypt_frame(&mut self, frame: &[u8], out: &mut [u8]) -> Result<usize, TransportError>;
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A NON-cryptographic test stub for [`SecureChannel`] — XOR "cipher" + a fixed marker "tag".
    struct XorChannel {
        key: u8,
    }
    impl SecureChannel for XorChannel {
        fn encrypt_frame(
            &mut self,
            plaintext: &[u8],
            out: &mut [u8],
        ) -> Result<usize, TransportError> {
            let n = plaintext.len() + AES_256_GCM_TAG_LEN;
            if out.len() < n {
                return Err(TransportError::BufferTooSmall);
            }
            for (i, b) in plaintext.iter().enumerate() {
                out[i] = b ^ self.key;
            }
            for t in &mut out[plaintext.len()..n] {
                *t = 0xAA;
            }
            Ok(n)
        }
        fn decrypt_frame(&mut self, frame: &[u8], out: &mut [u8]) -> Result<usize, TransportError> {
            if frame.len() < AES_256_GCM_TAG_LEN {
                return Err(TransportError::DecryptionFailed);
            }
            let ct_len = frame.len() - AES_256_GCM_TAG_LEN;
            if frame[ct_len..].iter().any(|&t| t != 0xAA) {
                return Err(TransportError::DecryptionFailed);
            }
            if out.len() < ct_len {
                return Err(TransportError::BufferTooSmall);
            }
            for (i, b) in frame[..ct_len].iter().enumerate() {
                out[i] = b ^ self.key;
            }
            Ok(ct_len)
        }
    }

    fn initiation() -> HandshakeInitiation {
        HandshakeInitiation {
            initiator_identity: [0x11; ML_DSA_65_PUBLIC_KEY_LEN],
            ephemeral_kem_pk: [0x22; ML_KEM_768_ENCAPS_KEY_LEN],
            epoch: 7,
            local_time: 1_000,
            nonce: [0x33; 32],
        }
    }

    fn response() -> HandshakeResponse {
        HandshakeResponse {
            responder_identity: [0x44; ML_DSA_65_PUBLIC_KEY_LEN],
            kem_ciphertext: [0x55; ML_KEM_768_CIPHERTEXT_LEN],
            epoch: 7,
            local_time: 1_000,
            nonce: [0x66; 32],
        }
    }

    #[test]
    fn initiation_serialized_body_len() {
        let mut buf = [0u8; HANDSHAKE_INITIATION_BODY_LEN];
        let mut sink = SliceSink::new(&mut buf);
        initiation().serialize_into(&mut sink).unwrap();
        assert_eq!(sink.len(), HANDSHAKE_INITIATION_BODY_LEN);
        assert_eq!(HANDSHAKE_INITIATION_BODY_LEN, 1952 + 1184 + 8 + 8 + 32);
    }

    #[test]
    fn response_serialized_body_len() {
        let mut buf = [0u8; HANDSHAKE_RESPONSE_BODY_LEN];
        let mut sink = SliceSink::new(&mut buf);
        response().serialize_into(&mut sink).unwrap();
        assert_eq!(sink.len(), HANDSHAKE_RESPONSE_BODY_LEN);
        assert_eq!(HANDSHAKE_RESPONSE_BODY_LEN, 1952 + 1088 + 8 + 8 + 32);
    }

    #[test]
    fn preimage_binds_transport_context() {
        let init = initiation();
        let mut buf = [0u8; HANDSHAKE_INITIATION_MAX_PREIMAGE_LEN];
        let mut sink = SliceSink::new(&mut buf);
        init.write_signing_preimage(&mut sink).unwrap();
        assert!(!sink.overflowed());
        assert_eq!(sink.written()[0] as usize, CTX_GOAT_TRANSPORT_HS.len());
        assert_eq!(
            &sink.written()[1..1 + CTX_GOAT_TRANSPORT_HS.len()],
            CTX_GOAT_TRANSPORT_HS
        );
        assert_eq!(sink.len(), HANDSHAKE_INITIATION_MAX_PREIMAGE_LEN);
    }

    #[test]
    fn handshake_signature_accept_and_reject() {
        let sig = [0u8; ML_DSA_65_SIGNATURE_LEN];
        assert_eq!(
            verify_initiation(&initiation(), &sig, &AllowVerifier),
            Ok(())
        );
        assert_eq!(
            verify_initiation(&initiation(), &sig, &DenyVerifier),
            Err(TransportError::BadHandshakeSignature)
        );
        assert_eq!(verify_response(&response(), &sig, &AllowVerifier), Ok(()));
        assert_eq!(
            verify_response(&response(), &sig, &DenyVerifier),
            Err(TransportError::BadHandshakeSignature)
        );
    }

    #[test]
    fn secure_channel_round_trip() {
        let mut ch = XorChannel { key: 0x5A };
        let pt = b"goatcoin frame payload";
        let mut framed = [0u8; 64];
        let n = ch.encrypt_frame(pt, &mut framed).unwrap();
        assert_eq!(n, pt.len() + AES_256_GCM_TAG_LEN);
        let mut back = [0u8; 64];
        let m = ch.decrypt_frame(&framed[..n], &mut back).unwrap();
        assert_eq!(&back[..m], pt);
    }

    #[test]
    fn secure_channel_rejects_tampered_tag() {
        let mut ch = XorChannel { key: 0x5A };
        let pt = b"x";
        let mut framed = [0u8; 32];
        let n = ch.encrypt_frame(pt, &mut framed).unwrap();
        framed[n - 1] ^= 0xFF;
        let mut back = [0u8; 32];
        assert_eq!(
            ch.decrypt_frame(&framed[..n], &mut back),
            Err(TransportError::DecryptionFailed)
        );
    }

    #[test]
    fn secure_channel_encrypt_buffer_too_small() {
        let mut ch = XorChannel { key: 1 };
        let mut tiny = [0u8; 4];
        assert_eq!(
            ch.encrypt_frame(b"12345", &mut tiny),
            Err(TransportError::BufferTooSmall)
        );
    }

    // --- RECON-11/12 stateless single-use cookie (network-time framed) -----

    #[test]
    fn cookie_round_trip_valid() {
        let secret = [0xA5; 32];
        let addr = [1u8; PEER_ADDR_LEN];
        let clock = NetworkClock::new();
        let mut cache = CookieCache::<8>::new();
        let challenge = issue_cookie(&secret, &addr, &clock, 1000);
        let echo = HandshakeCookieEcho {
            cookie: challenge.cookie,
            timestamp: challenge.timestamp,
            initiation: initiation(),
        };
        assert_eq!(
            verify_cookie_echo(&echo, &secret, &addr, &clock, 1000, 60, &mut cache),
            Ok(())
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cookie_rejects_spoofed_address() {
        let secret = [0xA5; 32];
        let clock = NetworkClock::new();
        let mut cache = CookieCache::<8>::new();
        let challenge = issue_cookie(&secret, &[1u8; PEER_ADDR_LEN], &clock, 1000);
        let echo = HandshakeCookieEcho {
            cookie: challenge.cookie,
            timestamp: 1000,
            initiation: initiation(),
        };
        // The responder observes a DIFFERENT source address than the cookie was minted for.
        assert_eq!(
            verify_cookie_echo(
                &echo,
                &secret,
                &[2u8; PEER_ADDR_LEN],
                &clock,
                1000,
                60,
                &mut cache
            ),
            Err(TransportError::InvalidCookie)
        );
        // A rejected cookie is NOT consumed into the single-use window.
        assert!(cache.is_empty());
    }

    #[test]
    fn cookie_rejects_expired() {
        let secret = [0xA5; 32];
        let addr = [1u8; PEER_ADDR_LEN];
        // Seed the clock past BOOTSTRAP_QUORUM (offset 0) so freshness is *enforced* (not in grace).
        let mut clock = NetworkClock::new();
        for i in 0..BOOTSTRAP_QUORUM as u8 {
            clock.record_peer_time(&[i; PEER_ADDR_LEN], 1000, 1000);
        }
        let mut cache = CookieCache::<8>::new();
        let challenge = issue_cookie(&secret, &addr, &clock, 1000);
        let echo = HandshakeCookieEcho {
            cookie: challenge.cookie,
            timestamp: 1000,
            initiation: initiation(),
        };
        // 61s later, past a 60s max age — freshness enforced now the quorum is reached.
        assert_eq!(
            verify_cookie_echo(&echo, &secret, &addr, &clock, 1061, 60, &mut cache),
            Err(TransportError::CookieExpired)
        );
    }

    // ARC-01-M5 (H-2): below the bootstrap quorum a cold node accepts an otherwise-stale cookie on
    // the MAC + single-use alone (breaking the cold-start clock deadlock); once the quorum forms, the
    // same cookie is enforced-expired.
    #[test]
    fn cookie_bootstrap_grace_then_enforces() {
        let secret = [0xA5; 32];
        let addr = [1u8; PEER_ADDR_LEN];
        let minted = issue_cookie(&secret, &addr, &NetworkClock::new(), 1000);
        let echo = HandshakeCookieEcho {
            cookie: minted.cookie,
            timestamp: minted.timestamp,
            initiation: initiation(),
        };

        // Cold boot (0 samples < quorum): grace accepts on the un-spoofable MAC alone.
        let cold = NetworkClock::new();
        let mut cache_cold = CookieCache::<8>::new();
        assert_eq!(
            verify_cookie_echo(&echo, &secret, &addr, &cold, 100_000, 60, &mut cache_cold),
            Ok(())
        );

        // Once peers seed the quorum (offset 0), the same stale cookie is rejected.
        let mut warm = NetworkClock::new();
        for i in 0..BOOTSTRAP_QUORUM as u8 {
            warm.record_peer_time(&[i; PEER_ADDR_LEN], 100_000, 100_000);
        }
        let mut cache_warm = CookieCache::<8>::new();
        assert_eq!(
            verify_cookie_echo(&echo, &secret, &addr, &warm, 100_000, 60, &mut cache_warm),
            Err(TransportError::CookieExpired)
        );
    }

    // ARC-01-M6: the genesis floor lifts an uninitialized (near-zero) local clock to at least
    // genesis, so cold-boot cookie timestamps are sane; it stays inert for a plausible-recent clock.
    #[test]
    fn network_clock_genesis_anchor_floors_uninitialized() {
        let clock = NetworkClock::with_genesis_anchor(1_700_000_000);
        assert_eq!(clock.logical_now(0), 1_700_000_000); // uninitialized RTC lifted to genesis
        assert_eq!(clock.logical_now(1_700_000_500), 1_700_000_500); // plausible clock: floor inert
        assert_eq!(NetworkClock::new().logical_now(0), 0); // plain clock has no floor
    }

    // RECON-12: a MAC-valid cookie is strictly single-use — the second (replayed) presentation is
    // rejected before any post-quantum work, defeating replay-within-window CPU exhaustion.
    #[test]
    fn cookie_single_use_rejects_replay() {
        let secret = [0xA5; 32];
        let addr = [7u8; PEER_ADDR_LEN];
        let clock = NetworkClock::new();
        let mut cache = CookieCache::<8>::new();
        let challenge = issue_cookie(&secret, &addr, &clock, 2000);
        let echo = HandshakeCookieEcho {
            cookie: challenge.cookie,
            timestamp: challenge.timestamp,
            initiation: initiation(),
        };
        // First presentation: accepted and consumed.
        assert_eq!(
            verify_cookie_echo(&echo, &secret, &addr, &clock, 2000, 60, &mut cache),
            Ok(())
        );
        // Replay of the same MAC-valid cookie inside the freshness window: rejected.
        assert_eq!(
            verify_cookie_echo(&echo, &secret, &addr, &clock, 2001, 60, &mut cache),
            Err(TransportError::CookieReplayed)
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cookie_mac_is_key_and_addr_sensitive() {
        let clock = NetworkClock::new();
        let a = issue_cookie(&[1u8; 32], &[9u8; PEER_ADDR_LEN], &clock, 5);
        let b = issue_cookie(&[2u8; 32], &[9u8; PEER_ADDR_LEN], &clock, 5); // different key
        let c = issue_cookie(&[1u8; 32], &[8u8; PEER_ADDR_LEN], &clock, 5); // different addr
        assert_ne!(a.cookie, b.cookie);
        assert_ne!(a.cookie, c.cookie);
        assert_eq!(
            a,
            issue_cookie(&[1u8; 32], &[9u8; PEER_ADDR_LEN], &clock, 5)
        ); // deterministic
    }

    // --- RECON-14 median network time (Chronos Trap) -----------------------

    #[test]
    fn network_clock_empty_is_identity() {
        let clock = NetworkClock::new();
        assert!(clock.is_empty());
        assert_eq!(clock.offset(), 0);
        assert_eq!(clock.logical_now(42), 42);
    }

    #[test]
    fn network_clock_median_corrects_drift() {
        // Local clock reads TRUE + 61; three honest peers assert TRUE ⇒ median offset -61.
        let mut clock = NetworkClock::new();
        for i in 0..3u8 {
            clock.record_peer_time(&[i; PEER_ADDR_LEN], 1000, 1061);
        }
        assert_eq!(clock.samples(), 3);
        assert_eq!(clock.offset(), -61);
        assert_eq!(clock.logical_now(1061), 1000); // pulled back to TRUE
    }

    #[test]
    fn network_clock_minority_cannot_skew() {
        // 3 honest peers (offset 0) + 2 hostile (offset +1000): the median stays honest.
        let mut clock = NetworkClock::new();
        for i in 0..3u8 {
            clock.record_peer_time(&[i; PEER_ADDR_LEN], 1000, 1000);
        }
        for i in 3..5u8 {
            clock.record_peer_time(&[i; PEER_ADDR_LEN], 2000, 1000);
        }
        assert_eq!(clock.offset(), 0);
    }

    #[test]
    fn network_clock_clamps_extreme_offset() {
        let mut clock = NetworkClock::new();
        clock.record_peer_time(&[1u8; PEER_ADDR_LEN], 1_000_000, 0); // +1e6 offset
        assert_eq!(clock.offset(), MAX_CLOCK_SKEW_SECS); // clamped
    }

    #[test]
    fn network_clock_one_sample_per_address() {
        // The same peer reconnecting cannot stuff the window — its slot is updated in place.
        let mut clock = NetworkClock::new();
        clock.record_peer_time(&[9u8; PEER_ADDR_LEN], 100, 0);
        clock.record_peer_time(&[9u8; PEER_ADDR_LEN], 200, 0);
        clock.record_peer_time(&[9u8; PEER_ADDR_LEN], 300, 0);
        assert_eq!(clock.samples(), 1);
        assert_eq!(clock.offset(), 300); // most-recent reading
    }

    // The headline Chronos fix, contrasted at/above the bootstrap quorum (ARC-01-M5): a clock whose
    // peers merely echo the poisoned local time (offset 0) still rejects an honest cookie as expired,
    // whereas a clock corrected by honest peers (offset -61) ACCEPTS it. (Below the quorum, bootstrap
    // grace would accept either — covered by `cookie_bootstrap_grace_then_enforces`.)
    #[test]
    fn chronos_corrected_clock_accepts_honest_cookie() {
        let secret = [0xA5; 32];
        let addr = [1u8; PEER_ADDR_LEN];
        // TRUE time = 1000; this node's local clock is poisoned to 1061.
        let honest = issue_cookie(&secret, &addr, &NetworkClock::new(), 1000); // minted at TRUE
        let echo = HandshakeCookieEcho {
            cookie: honest.cookie,
            timestamp: honest.timestamp, // 1000
            initiation: initiation(),
        };

        // Uncorrected but past-quorum: peers echo the drifted local time ⇒ offset 0 ⇒ logical stays
        // 1061 ⇒ 1061 - 1000 = 61 > 60 ⇒ the eclipse.
        let mut raw = NetworkClock::new();
        for i in 0..BOOTSTRAP_QUORUM as u8 {
            raw.record_peer_time(&[i; PEER_ADDR_LEN], 1061, 1061);
        }
        let mut cache_raw = CookieCache::<8>::new();
        assert_eq!(
            verify_cookie_echo(&echo, &secret, &addr, &raw, 1061, 60, &mut cache_raw),
            Err(TransportError::CookieExpired)
        );

        // Corrected clock: honest peers anchor offset -61 ⇒ logical now = 1000 ⇒ accepted.
        let mut corrected = NetworkClock::new();
        for i in 0..BOOTSTRAP_QUORUM as u8 {
            corrected.record_peer_time(&[i; PEER_ADDR_LEN], 1000, 1061);
        }
        let mut cache_ok = CookieCache::<8>::new();
        assert_eq!(
            verify_cookie_echo(&echo, &secret, &addr, &corrected, 1061, 60, &mut cache_ok),
            Ok(())
        );
    }
}
