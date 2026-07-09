//! `daemon.rs` — Phase 5: the GoatCoin daemon (top-level network participant).
//!
//! With the execution, settlement, verification, and transport planes mathematically sealed, this
//! module instantiates the physical node — [`GoatNode`] — that holds the runtime engines together
//! and drives the **ingress pipeline**. It owns exactly the mutable runtime state a participant
//! carries across packets: the gossip [`MessageCache`] (RECON-11 epidemic dedup), the transport
//! [`CookieCache`] (RECON-12 single-use cookies), the [`NetworkClock`] (RECON-14 drift-resilient
//! median network time), plus the injected [`SignatureVerifier`] and [`KeyRegistry`] abstractions
//! and the node's own cookie secret / identity. `no_std`, allocation-free,
//! `#![forbid(unsafe_code)]` — no protocol logic lives here, only wiring.
//!
//! Cookie freshness is judged against the node's [`NetworkClock`] logical time, not the raw local
//! wall-clock: every authenticated handshake folds the peer's signed `local_time` into a bounded
//! median offset, so an NTP-poisoned local clock is transparently corrected (RECON-14, Chronos Trap).
//!
//! ## Ingress multiplexing
//!
//! [`GoatNode::process_ingress_packet`] takes raw network bytes, reads a one-byte type tag, and
//! demultiplexes into a [`NetworkPacket`], then routes each into the validation pipeline that owns
//! it — nothing is trusted that a sealed engine has not re-derived:
//!
//! | Tag | Packet | Route | Post-quantum cost |
//! |-----|--------|-------|-------------------|
//! | `0x01` | [`HandshakeInitiation`] | `issue_cookie` → reply with a stateless [`CookieChallenge`] | **none** (RECON-11) |
//! | `0x02` | [`HandshakeCookieEcho`] | `verify_cookie_echo` (freshness + address MAC + single-use) **then** `verify_initiation` | one ML-DSA verify, and only once per cookie (RECON-12) |
//! | `0x03` | [`HandshakeResponse`] | `verify_response` | one ML-DSA verify |
//! | `0x04` | encrypted `SecureChannel` frame | `decrypt_frame` → decode → `validate_gossip_message` (dedup + verify-before-forward) | one ML-DSA verify, deduplicated |
//!
//! The ordering is the whole point: the two cheap cookie checks gate the expensive ML-DSA
//! verification on the handshake path, and the cheap `SHA3-256` dedup gates it on the gossip path.
//!
//! ## Dependency injection (the not-yet-built primitives)
//!
//! A [`SecureChannel`] (AEAD/KDF) and a [`GossipCodec`] (plaintext → [`GossipMessage`] decode) are
//! passed per call, exactly as [`SignatureVerifier`] abstracts ML-DSA: a session's cipher is
//! per-peer and stateful, and canonical *de*serialization of the variable-length gossip payloads is
//! out of the sealed serialize-only scope. Both are traits so the daemon's routing is testable
//! without a cipher or wire-decoder backend.

use crate::crypto::{KeyRegistry, SignatureVerifier};
use crate::gossip::{validate_gossip_message, GossipError, GossipMessage, MessageCache};
use crate::transport::{
    issue_cookie, verify_cookie_echo, verify_initiation, verify_response, CookieCache,
    CookieChallenge, HandshakeCookieEcho, HandshakeInitiation, HandshakeResponse, NetworkClock,
    SecureChannel, TransportError, MAX_COOKIE_AGE_SECS, ML_KEM_768_CIPHERTEXT_LEN,
    ML_KEM_768_ENCAPS_KEY_LEN, PEER_ADDR_LEN,
};
use crate::types::{ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN};

/// One-byte wire tags that select the ingress route.
pub mod packet_tag {
    /// A [`super::HandshakeInitiation`] — triggers a stateless cookie, no PQ crypto.
    pub const INITIATION: u8 = 0x01;
    /// A [`super::HandshakeCookieEcho`] — cookie proof then handshake verification.
    pub const COOKIE_ECHO: u8 = 0x02;
    /// A [`super::HandshakeResponse`] — responder-side handshake verification.
    pub const RESPONSE: u8 = 0x03;
    /// An encrypted `SecureChannel` frame carrying a [`super::GossipMessage`].
    pub const SECURE_FRAME: u8 = 0x04;
}

/// Decodes a decrypted `SecureChannel` plaintext into a [`GossipMessage`]. Injected exactly as the
/// AEAD and ML-DSA primitives are — canonical *de*serialization of the variable-length gossip
/// payloads is outside the sealed serialize-only surface, so it lives behind a trait.
pub trait GossipCodec {
    /// Decode `plaintext` into a [`GossipMessage`], or `None` if it is malformed.
    fn decode(&self, plaintext: &[u8]) -> Option<GossipMessage>;
}

// ===========================================================================
// Error typology & ingress outcomes
// ===========================================================================

/// A failure while processing an ingress packet. Total and `Copy`; no path panics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaemonError {
    /// A zero-length packet (no type tag).
    Empty,
    /// The leading type tag matched no known [`packet_tag`].
    UnknownPacketType,
    /// A packet was truncated or carried trailing bytes — it does not parse to its declared type.
    Malformed,
    /// A transport-plane rejection (handshake signature, cookie MAC/expiry/replay, decryption).
    Transport(TransportError),
    /// A gossip-plane rejection (dedup duplicate, signature-spam, unauthorized origin).
    Gossip(GossipError),
    /// The `SecureChannel` plaintext did not decode to a [`GossipMessage`].
    Decode,
}

impl From<TransportError> for DaemonError {
    #[inline]
    fn from(e: TransportError) -> Self {
        DaemonError::Transport(e)
    }
}

impl From<GossipError> for DaemonError {
    #[inline]
    fn from(e: GossipError) -> Self {
        DaemonError::Gossip(e)
    }
}

/// What an accepted ingress packet resolved to — the caller acts on this (send a challenge, complete
/// a handshake, forward gossip).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressOutcome {
    /// An initiation was received; reply to the peer with this stateless cookie (no PQ crypto spent).
    ChallengeIssued(CookieChallenge),
    /// A cookie-echo passed freshness + address MAC + single-use, and the embedded initiation's
    /// signature verified — the session may proceed to ML-KEM decapsulation.
    HandshakeEstablished,
    /// A [`HandshakeResponse`]'s signature verified.
    ResponseVerified,
    /// A secure-channel frame decrypted, decoded, and its [`GossipMessage`] passed dedup +
    /// verify-before-forward — the caller may relay the original bytes onward.
    GossipAccepted,
}

// ===========================================================================
// NetworkPacket — the ingress multiplexer
// ===========================================================================

/// The demultiplexed ingress packet. Handshake variants are parsed (owned) from the wire; the secure
/// frame borrows the raw ciphertext for in-place decryption.
//
// `large_enum_variant` is deliberately allowed (as on `GossipMessage`): the handshake variants are
// fixed-size no-alloc wire structures dominated by ~1–3 KB arrays; boxing to equalize them requires
// `alloc` and would defeat the allocation-free ingress path.
#[allow(clippy::large_enum_variant)]
pub enum NetworkPacket<'a> {
    /// A parsed initiation (the responder spends no crypto on it; it echoes a cookie).
    Initiation(HandshakeInitiation),
    /// A parsed cookie-echo and the ML-DSA signature over its embedded initiation.
    CookieEcho(HandshakeCookieEcho, [u8; ML_DSA_65_SIGNATURE_LEN]),
    /// A parsed response and the ML-DSA signature over it.
    Response(HandshakeResponse, [u8; ML_DSA_65_SIGNATURE_LEN]),
    /// The raw AEAD frame (`ciphertext ‖ tag`), decrypted in place at routing time.
    SecureFrame(&'a [u8]),
}

/// A minimal bounds-checked forward cursor over an ingress byte slice — fail-closed, no panics.
struct SliceReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> SliceReader<'a> {
    #[inline]
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Consume exactly `n` bytes, or [`DaemonError::Malformed`] if fewer remain.
    #[inline]
    fn take(&mut self, n: usize) -> Result<&'a [u8], DaemonError> {
        let end = self.pos.checked_add(n).ok_or(DaemonError::Malformed)?;
        let s = self.buf.get(self.pos..end).ok_or(DaemonError::Malformed)?;
        self.pos = end;
        Ok(s)
    }

    /// Consume a fixed `[u8; K]`.
    #[inline]
    fn take_array<const K: usize>(&mut self) -> Result<[u8; K], DaemonError> {
        let mut a = [0u8; K];
        a.copy_from_slice(self.take(K)?);
        Ok(a)
    }

    /// Consume a little-endian `u64`.
    #[inline]
    fn take_u64_le(&mut self) -> Result<u64, DaemonError> {
        Ok(u64::from_le_bytes(self.take_array::<8>()?))
    }

    /// Assert the whole slice was consumed (no trailing bytes) — rejects ambiguous/padded packets.
    #[inline]
    fn finish(&self) -> Result<(), DaemonError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(DaemonError::Malformed)
        }
    }
}

/// Parse a fixed-width [`HandshakeInitiation`] body in canonical (little-endian) field order.
fn parse_initiation(r: &mut SliceReader) -> Result<HandshakeInitiation, DaemonError> {
    let initiator_identity = r.take_array::<ML_DSA_65_PUBLIC_KEY_LEN>()?;
    let ephemeral_kem_pk = r.take_array::<ML_KEM_768_ENCAPS_KEY_LEN>()?;
    let epoch = r.take_u64_le()?;
    let local_time = r.take_u64_le()?;
    let nonce = r.take_array::<32>()?;
    Ok(HandshakeInitiation {
        initiator_identity,
        ephemeral_kem_pk,
        epoch,
        local_time,
        nonce,
    })
}

/// Parse a fixed-width [`HandshakeResponse`] body in canonical (little-endian) field order.
fn parse_response(r: &mut SliceReader) -> Result<HandshakeResponse, DaemonError> {
    let responder_identity = r.take_array::<ML_DSA_65_PUBLIC_KEY_LEN>()?;
    let kem_ciphertext = r.take_array::<ML_KEM_768_CIPHERTEXT_LEN>()?;
    let epoch = r.take_u64_le()?;
    let local_time = r.take_u64_le()?;
    let nonce = r.take_array::<32>()?;
    Ok(HandshakeResponse {
        responder_identity,
        kem_ciphertext,
        epoch,
        local_time,
        nonce,
    })
}

/// Demultiplex raw ingress bytes into a [`NetworkPacket`] by the leading one-byte tag. Control-plane
/// packets are parsed fully (and must consume their whole slice); the secure frame borrows its body.
pub fn demux(raw: &[u8]) -> Result<NetworkPacket<'_>, DaemonError> {
    let (&tag, body) = raw.split_first().ok_or(DaemonError::Empty)?;
    match tag {
        packet_tag::INITIATION => {
            let mut r = SliceReader::new(body);
            let init = parse_initiation(&mut r)?;
            r.finish()?;
            Ok(NetworkPacket::Initiation(init))
        }
        packet_tag::COOKIE_ECHO => {
            let mut r = SliceReader::new(body);
            let cookie = r.take_array::<32>()?;
            let timestamp = r.take_u64_le()?;
            let initiation = parse_initiation(&mut r)?;
            let signature = r.take_array::<ML_DSA_65_SIGNATURE_LEN>()?;
            r.finish()?;
            Ok(NetworkPacket::CookieEcho(
                HandshakeCookieEcho {
                    cookie,
                    timestamp,
                    initiation,
                },
                signature,
            ))
        }
        packet_tag::RESPONSE => {
            let mut r = SliceReader::new(body);
            let resp = parse_response(&mut r)?;
            let signature = r.take_array::<ML_DSA_65_SIGNATURE_LEN>()?;
            r.finish()?;
            Ok(NetworkPacket::Response(resp, signature))
        }
        packet_tag::SECURE_FRAME => Ok(NetworkPacket::SecureFrame(body)),
        _ => Err(DaemonError::UnknownPacketType),
    }
}

// ===========================================================================
// GoatNode — the top-level participant
// ===========================================================================

/// The top-level GoatCoin network participant. Generic over the injected [`SignatureVerifier`] `V`
/// and [`KeyRegistry`] `R`, and over the two ring-buffer capacities: `M` gossip digests (RECON-11)
/// and `C` single-use cookies (RECON-12).
pub struct GoatNode<V, R, const M: usize, const C: usize>
where
    V: SignatureVerifier,
    R: KeyRegistry,
{
    /// This node's cookie-MAC secret (never leaves the node; keys the stateless cookie).
    node_secret: [u8; 32],
    /// This node's long-term ML-DSA-65 identity public key.
    identity_public_key: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
    /// Injected ML-DSA-65 verifier.
    verifier: V,
    /// Injected authorized-key registry.
    registry: R,
    /// RECON-11 epidemic-dedup window.
    message_cache: MessageCache<M>,
    /// RECON-12 single-use cookie window.
    cookie_cache: CookieCache<C>,
    /// RECON-14 drift-resilient logical clock, anchored to authenticated peers.
    network_clock: NetworkClock,
}

impl<V, R, const M: usize, const C: usize> GoatNode<V, R, M, C>
where
    V: SignatureVerifier,
    R: KeyRegistry,
{
    /// Construct a node with empty caches. `genesis_time` (the hardcoded genesis Unix timestamp from
    /// `genesis.json`) anchors the [`NetworkClock`] floor (ARC-01-M6), so a cold boot with an
    /// uninitialized RTC still issues sane cookie timestamps instead of wild ones.
    pub fn new(
        node_secret: [u8; 32],
        identity_public_key: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
        verifier: V,
        registry: R,
        genesis_time: u64,
    ) -> Self {
        Self {
            node_secret,
            identity_public_key,
            verifier,
            registry,
            message_cache: MessageCache::new(),
            cookie_cache: CookieCache::new(),
            network_clock: NetworkClock::with_genesis_anchor(genesis_time),
        }
    }

    /// This node's long-term ML-DSA-65 identity public key.
    #[inline]
    pub fn identity_public_key(&self) -> &[u8; ML_DSA_65_PUBLIC_KEY_LEN] {
        &self.identity_public_key
    }

    /// Live gossip-dedup window occupancy.
    #[inline]
    pub fn seen_messages(&self) -> usize {
        self.message_cache.len()
    }

    /// Live single-use-cookie window occupancy.
    #[inline]
    pub fn consumed_cookies(&self) -> usize {
        self.cookie_cache.len()
    }

    /// This node's drift-resilient logical time for a raw `local_time` (RECON-14) — the median
    /// network clock the cookie machinery evaluates against.
    #[inline]
    pub fn network_time(&self, local_time: u64) -> u64 {
        self.network_clock.logical_now(local_time)
    }

    /// Number of authenticated-peer samples currently anchoring the logical clock.
    #[inline]
    pub fn clock_samples(&self) -> usize {
        self.network_clock.samples()
    }

    /// **The ingress pipeline.** Demultiplex `raw` and route it through the owning validation plane,
    /// updating the node's caches as a side effect. `channel` decrypts a secure frame in place into
    /// `plaintext_buf`; `codec` decodes that plaintext into a [`GossipMessage`]. `peer_addr` is the
    /// **observed** source address (bound into the cookie MAC) and `now` the current time (cookie
    /// freshness). Returns the [`IngressOutcome`] on acceptance, or a fail-closed [`DaemonError`].
    pub fn process_ingress_packet<S, G>(
        &mut self,
        raw: &[u8],
        peer_addr: &[u8; PEER_ADDR_LEN],
        now: u64,
        channel: &mut S,
        codec: &G,
        plaintext_buf: &mut [u8],
    ) -> Result<IngressOutcome, DaemonError>
    where
        S: SecureChannel,
        G: GossipCodec,
    {
        match demux(raw)? {
            NetworkPacket::Initiation(_init) => {
                // RECON-11: a bare initiation triggers ZERO post-quantum work. Reply with a
                // stateless cookie stamped in drift-resilient logical time (RECON-14); the peer must
                // echo it (proving address ownership) before we spend any crypto. The initiation
                // itself is not yet trusted.
                Ok(IngressOutcome::ChallengeIssued(issue_cookie(
                    &self.node_secret,
                    peer_addr,
                    &self.network_clock,
                    now,
                )))
            }
            NetworkPacket::CookieEcho(echo, signature) => {
                // RECON-11 address proof + RECON-12 single-use + RECON-14 network-time freshness —
                // all BEFORE any PQ crypto.
                verify_cookie_echo(
                    &echo,
                    &self.node_secret,
                    peer_addr,
                    &self.network_clock,
                    now,
                    MAX_COOKIE_AGE_SECS,
                    &mut self.cookie_cache,
                )?;
                // Only now, with a fresh single-use cookie proven, do we spend the ML-DSA verify.
                verify_initiation(&echo.initiation, &signature, &self.verifier)?;
                // RECON-14: the initiator is now authenticated — fold its signed clock into the
                // median network time (bounded, one sample per address).
                self.network_clock
                    .record_peer_time(peer_addr, echo.initiation.local_time, now);
                Ok(IngressOutcome::HandshakeEstablished)
            }
            NetworkPacket::Response(resp, signature) => {
                verify_response(&resp, &signature, &self.verifier)?;
                // RECON-14: the responder is authenticated (no cookie gate on this path, so it seeds
                // the network clock even while our local clock is poisoned) — record its signed time.
                self.network_clock
                    .record_peer_time(peer_addr, resp.local_time, now);
                Ok(IngressOutcome::ResponseVerified)
            }
            NetworkPacket::SecureFrame(frame) => {
                // Data plane: decrypt in place, decode, then dedup + verify-before-forward.
                let n = channel.decrypt_frame(frame, plaintext_buf)?;
                let message = codec
                    .decode(&plaintext_buf[..n])
                    .ok_or(DaemonError::Decode)?;
                validate_gossip_message(
                    &message,
                    &mut self.message_cache,
                    &self.verifier,
                    &self.registry,
                )?;
                Ok(IngressOutcome::GossipAccepted)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ByteSink, CanonicalSerialize, SliceSink};
    use crate::transport::AES_256_GCM_TAG_LEN;
    use crate::types::{BoundedVec, CapabilityRecord, PowerThermalEnvelope, SignedRecord, PPM};

    const SECRET: [u8; 32] = [0x11; 32];
    // Genesis floor ≤ every `now` used below, so the ARC-01-M6 anchor stays inert in these vectors.
    const GENESIS_TIME: u64 = 500;

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

    /// A NON-cryptographic `SecureChannel` stub: XOR "cipher" + fixed 0xAA "tag" (mirrors transport).
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

    /// A stub codec that decodes any plaintext to the same capability message (deterministic, so the
    /// same wire frame yields the same digest and the RECON-11 dedup can be exercised end-to-end).
    struct FixedCodec;
    impl GossipCodec for FixedCodec {
        fn decode(&self, _plaintext: &[u8]) -> Option<GossipMessage> {
            Some(capability_msg())
        }
    }

    fn node() -> GoatNode<AllowVerifier, AllowRegistry, 64, 64> {
        GoatNode::new(
            SECRET,
            [0x22; ML_DSA_65_PUBLIC_KEY_LEN],
            AllowVerifier,
            AllowRegistry,
            GENESIS_TIME,
        )
    }

    fn initiation() -> HandshakeInitiation {
        HandshakeInitiation {
            initiator_identity: [0x33; ML_DSA_65_PUBLIC_KEY_LEN],
            ephemeral_kem_pk: [0x44; ML_KEM_768_ENCAPS_KEY_LEN],
            epoch: 7,
            local_time: 2_000, // consistent with the cookie-echo tests' `now`
            nonce: [0x55; 32],
        }
    }

    fn response() -> HandshakeResponse {
        HandshakeResponse {
            responder_identity: [0x66; ML_DSA_65_PUBLIC_KEY_LEN],
            kem_ciphertext: [0x77; ML_KEM_768_CIPHERTEXT_LEN],
            epoch: 7,
            local_time: 3_000,
            nonce: [0x88; 32],
        }
    }

    fn write_initiation_packet(buf: &mut [u8], init: &HandshakeInitiation) -> usize {
        let mut sink = SliceSink::new(buf);
        sink.put(&[packet_tag::INITIATION]).unwrap();
        init.serialize_into(&mut sink).unwrap();
        sink.len()
    }

    fn write_cookie_echo_packet(
        buf: &mut [u8],
        echo: &HandshakeCookieEcho,
        signature: &[u8; ML_DSA_65_SIGNATURE_LEN],
    ) -> usize {
        let mut sink = SliceSink::new(buf);
        sink.put(&[packet_tag::COOKIE_ECHO]).unwrap();
        sink.put(&echo.cookie).unwrap();
        sink.put(&echo.timestamp.to_le_bytes()).unwrap();
        echo.initiation.serialize_into(&mut sink).unwrap();
        sink.put(signature).unwrap();
        sink.len()
    }

    fn write_response_packet(
        buf: &mut [u8],
        resp: &HandshakeResponse,
        signature: &[u8; ML_DSA_65_SIGNATURE_LEN],
    ) -> usize {
        let mut sink = SliceSink::new(buf);
        sink.put(&[packet_tag::RESPONSE]).unwrap();
        resp.serialize_into(&mut sink).unwrap();
        sink.put(signature).unwrap();
        sink.len()
    }

    fn write_secure_packet(buf: &mut [u8], ch: &mut XorChannel, plaintext: &[u8]) -> usize {
        buf[0] = packet_tag::SECURE_FRAME;
        let n = ch.encrypt_frame(plaintext, &mut buf[1..]).unwrap();
        1 + n
    }

    #[test]
    fn initiation_yields_stateless_challenge() {
        let mut node = node();
        let addr = [9u8; PEER_ADDR_LEN];
        let mut buf = [0u8; 4096];
        let n = write_initiation_packet(&mut buf, &initiation());
        let mut ch = XorChannel { key: 1 };
        let mut pt = [0u8; 64];
        let out = node
            .process_ingress_packet(&buf[..n], &addr, 1000, &mut ch, &FixedCodec, &mut pt)
            .unwrap();
        // The reply cookie is exactly what issue_cookie would mint for this address/time.
        let expected = issue_cookie(&SECRET, &addr, &NetworkClock::new(), 1000);
        assert_eq!(out, IngressOutcome::ChallengeIssued(expected));
        // No cookie is consumed and no crypto spent on a bare initiation.
        assert_eq!(node.consumed_cookies(), 0);
    }

    #[test]
    fn cookie_echo_completes_handshake_then_replay_rejected() {
        let mut node = node();
        let addr = [5u8; PEER_ADDR_LEN];
        let challenge = issue_cookie(&SECRET, &addr, &NetworkClock::new(), 2000);
        let echo = HandshakeCookieEcho {
            cookie: challenge.cookie,
            timestamp: challenge.timestamp,
            initiation: initiation(),
        };
        let sig = [0u8; ML_DSA_65_SIGNATURE_LEN];
        let mut buf = [0u8; 8192];
        let n = write_cookie_echo_packet(&mut buf, &echo, &sig);
        let mut ch = XorChannel { key: 1 };
        let mut pt = [0u8; 64];

        // First echo: cookie proven single-use, initiation verified.
        assert_eq!(
            node.process_ingress_packet(&buf[..n], &addr, 2000, &mut ch, &FixedCodec, &mut pt),
            Ok(IngressOutcome::HandshakeEstablished)
        );
        assert_eq!(node.consumed_cookies(), 1);

        // RECON-12: replay the exact same MAC-valid packet within the window — rejected before any
        // post-quantum work, no matter how many times it is blasted.
        for t in 2001..2010 {
            assert_eq!(
                node.process_ingress_packet(&buf[..n], &addr, t, &mut ch, &FixedCodec, &mut pt),
                Err(DaemonError::Transport(TransportError::CookieReplayed))
            );
        }
        assert_eq!(node.consumed_cookies(), 1);
    }

    #[test]
    fn cookie_echo_from_spoofed_address_rejected() {
        let mut node = node();
        let minted_addr = [5u8; PEER_ADDR_LEN];
        let challenge = issue_cookie(&SECRET, &minted_addr, &NetworkClock::new(), 2000);
        let echo = HandshakeCookieEcho {
            cookie: challenge.cookie,
            timestamp: challenge.timestamp,
            initiation: initiation(),
        };
        let sig = [0u8; ML_DSA_65_SIGNATURE_LEN];
        let mut buf = [0u8; 8192];
        let n = write_cookie_echo_packet(&mut buf, &echo, &sig);
        let mut ch = XorChannel { key: 1 };
        let mut pt = [0u8; 64];
        // Observed source differs from the address the cookie was bound to.
        assert_eq!(
            node.process_ingress_packet(
                &buf[..n],
                &[6u8; PEER_ADDR_LEN],
                2000,
                &mut ch,
                &FixedCodec,
                &mut pt
            ),
            Err(DaemonError::Transport(TransportError::InvalidCookie))
        );
        assert_eq!(node.consumed_cookies(), 0);
    }

    #[test]
    fn response_is_verified() {
        let mut node = node();
        let sig = [0u8; ML_DSA_65_SIGNATURE_LEN];
        let mut buf = [0u8; 8192];
        let n = write_response_packet(&mut buf, &response(), &sig);
        let mut ch = XorChannel { key: 1 };
        let mut pt = [0u8; 64];
        assert_eq!(
            node.process_ingress_packet(
                &buf[..n],
                &[1u8; PEER_ADDR_LEN],
                3000,
                &mut ch,
                &FixedCodec,
                &mut pt
            ),
            Ok(IngressOutcome::ResponseVerified)
        );
    }

    #[test]
    fn secure_frame_accepts_then_dedups() {
        let mut node = node();
        let addr = [1u8; PEER_ADDR_LEN];
        let mut ch = XorChannel { key: 0x5A };
        let mut buf = [0u8; 256];
        let n = write_secure_packet(&mut buf, &mut ch, b"encoded-gossip");
        let mut pt = [0u8; 256];

        // First secure frame: decrypts, decodes, passes dedup + verify-before-forward.
        assert_eq!(
            node.process_ingress_packet(&buf[..n], &addr, 100, &mut ch, &FixedCodec, &mut pt),
            Ok(IngressOutcome::GossipAccepted)
        );
        assert_eq!(node.seen_messages(), 1);
        // Identical frame again: RECON-11 dedup drops it (same digest) — penalty-free duplicate.
        assert_eq!(
            node.process_ingress_packet(&buf[..n], &addr, 100, &mut ch, &FixedCodec, &mut pt),
            Err(DaemonError::Gossip(GossipError::DuplicateMessage))
        );
        assert_eq!(node.seen_messages(), 1);
    }

    #[test]
    fn empty_and_unknown_and_truncated_are_rejected() {
        let mut node = node();
        let addr = [1u8; PEER_ADDR_LEN];
        let mut ch = XorChannel { key: 1 };
        let mut pt = [0u8; 64];

        // Empty packet.
        assert_eq!(
            node.process_ingress_packet(&[], &addr, 0, &mut ch, &FixedCodec, &mut pt),
            Err(DaemonError::Empty)
        );
        // Unknown tag.
        assert_eq!(
            node.process_ingress_packet(&[0xFE, 0x00], &addr, 0, &mut ch, &FixedCodec, &mut pt),
            Err(DaemonError::UnknownPacketType)
        );
        // Truncated initiation (tag present, body too short).
        assert_eq!(
            node.process_ingress_packet(
                &[packet_tag::INITIATION, 0x00, 0x01],
                &addr,
                0,
                &mut ch,
                &FixedCodec,
                &mut pt
            ),
            Err(DaemonError::Malformed)
        );
    }

    #[test]
    fn trailing_bytes_are_malformed() {
        let mut node = node();
        let addr = [1u8; PEER_ADDR_LEN];
        let mut ch = XorChannel { key: 1 };
        let mut pt = [0u8; 64];
        let mut buf = [0u8; 4096];
        let n = write_initiation_packet(&mut buf, &initiation());
        // One extra trailing byte makes the fixed-width control packet ambiguous → Malformed.
        assert_eq!(
            node.process_ingress_packet(&buf[..n + 1], &addr, 0, &mut ch, &FixedCodec, &mut pt),
            Err(DaemonError::Malformed)
        );
    }

    #[test]
    fn demux_classifies_all_tags() {
        let mut buf = [0u8; 8192];
        let n = write_initiation_packet(&mut buf, &initiation());
        assert!(matches!(demux(&buf[..n]), Ok(NetworkPacket::Initiation(_))));

        let sig = [0u8; ML_DSA_65_SIGNATURE_LEN];
        let n = write_response_packet(&mut buf, &response(), &sig);
        assert!(matches!(
            demux(&buf[..n]),
            Ok(NetworkPacket::Response(_, _))
        ));

        // A secure-frame tag with an arbitrary body classifies as SecureFrame (no parse).
        let raw = [packet_tag::SECURE_FRAME, 1, 2, 3];
        assert!(matches!(demux(&raw), Ok(NetworkPacket::SecureFrame(_))));
    }

    // RECON-14 end-to-end: a node whose local clock is NTP-poisoned +61s corrects itself from
    // authenticated peers and then accepts an honest cookie a raw-clock node would eclipse.
    #[test]
    fn chronos_median_time_defeats_ntp_eclipse() {
        let mut node = node();
        let mut ch = XorChannel { key: 1 };
        let mut pt = [0u8; 64];
        let sig = [0u8; ML_DSA_65_SIGNATURE_LEN];

        // Seed the clock from 3 authenticated responders asserting TRUE=1000, observed at 1061.
        let mut resp = response();
        resp.local_time = 1000;
        let mut rbuf = [0u8; 8192];
        let rn = write_response_packet(&mut rbuf, &resp, &sig);
        for i in 0..3u8 {
            assert_eq!(
                node.process_ingress_packet(
                    &rbuf[..rn],
                    &[i; PEER_ADDR_LEN],
                    1061,
                    &mut ch,
                    &FixedCodec,
                    &mut pt
                ),
                Ok(IngressOutcome::ResponseVerified)
            );
        }
        assert_eq!(node.clock_samples(), 3);
        // Logical time is pulled back to TRUE despite the poisoned local clock.
        assert_eq!(node.network_time(1061), 1000);

        // An honest cookie minted at TRUE=1000 (raw-clock nodes reject: 1061-1000=61 > 60)…
        let addr = [42u8; PEER_ADDR_LEN];
        let honest = issue_cookie(&SECRET, &addr, &NetworkClock::new(), 1000);
        let echo = HandshakeCookieEcho {
            cookie: honest.cookie,
            timestamp: honest.timestamp,
            initiation: initiation(),
        };
        let mut ebuf = [0u8; 8192];
        let en = write_cookie_echo_packet(&mut ebuf, &echo, &sig);
        // …is ACCEPTED by the self-corrected node at the poisoned local time 1061.
        assert_eq!(
            node.process_ingress_packet(&ebuf[..en], &addr, 1061, &mut ch, &FixedCodec, &mut pt),
            Ok(IngressOutcome::HandshakeEstablished)
        );
    }
}
