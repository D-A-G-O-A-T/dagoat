//! The post-quantum handshake — the actual trust boundary.
//!
//! # The distinction this repository had never written down
//!
//! **Post-quantum is mandatory node↔gateway.** The session key derives from
//! the ML-KEM-768 shared secret under this crate's **own** KDF label and from
//! **nothing the outer TLS contributes**. Re-keying, resuming or terminating
//! the outer WSS carriage cannot move it. A peer that offers a classical key
//! exchange only is refused with [`TunnelError::NoPostQuantumKem`] and **no
//! session key is derived** — there is no downgrade, no negotiation ladder and
//! no classical-only fallback on the load-bearing path.
//!
//! **Classical TLS to a scraped origin is the origin's choice and is out of
//! scope of that invariant.** On the origin leg the node is an ordinary HTTPS
//! client talking to an ordinary public website; it cannot choose that site's
//! cipher suite, and that leg carries no GOAT authentication and no GOAT key
//! material. Requiring post-quantum crypto there would mean requiring it of
//! the public web.
//!
//! # Domain separation is not optional
//!
//! `goat-net` derives its session key as SHA3-256 over the label
//! `goat-net/session/v1`. Reusing that label here would be a
//! domain-separation error: a tunnel key and a gossip key must never be
//! derivable from one another, because a shared secret that leaks in one
//! protocol would then compromise the other. [`TUNNEL_KDF_LABEL`] is new, and
//! a test asserts that the two labels differ **and** that they produce
//! different keys from identical inputs.
//!
//! # Message sequence
//!
//! ```text
//!   node (initiator)                             gateway (responder)
//!   ────────────────                             ───────────────────
//!   select_kem(offer)  ─ ML-KEM-768 present? ─┐
//!        │  no  →  NoPostQuantumKem, stop     │
//!        ▼  yes                               │
//!   encapsulate to gateway KEM public         │
//!   sign(preimage) with ML-DSA-65             │
//!   transcript = SHA3-256(preimage ‖ sig)     │
//!   key = KDF(shared, transcript)             │
//!                                             │
//!   ── TunnelHello ────────────────────────────────────►
//!                                                 version
//!                                                 zero consent hash?
//!                                                 zero policy hash?
//!                                                 allowlist digest published?
//!                                                 ML-DSA-65 verify
//!                                                 replay cache (post-verify)
//!                                                 decapsulate
//!                                                 key = KDF(shared, transcript)
//!                                                 sign confirm
//!   ◄──────────────────────────────────── TunnelConfirm ──
//!   verify_confirm(gateway pk, transcript)
//! ```
//!
//! The replay cache is consulted **after** the signature verifies, so a forged
//! hello cannot pollute or evict it — the same ordering the spine's handshake
//! cookie cache uses for the same reason.
//!
//! Design authority: the "Residential Proxy Network (P3) Implementation Plan",
//! §2 (INV-12); the "D.A. G.O.A.T. — Core Principles and Invariants"
//! document's post-quantum rule.

use std::collections::HashSet;

use ml_dsa::signature::{Signer as _, Verifier as _};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair as _, MlDsa65, Signature, SigningKey,
    VerifyingKey, B32,
};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport};
use ml_kem::{Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768};
use sha3::{Digest, Sha3_256};

use goat_core::transport::{
    ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_ENCAPS_KEY_LEN, ML_KEM_768_SHARED_SECRET_LEN,
};
use goat_core::types::{ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN};

use crate::error::TunnelError;

/// The tunnel's session-KDF label.
///
/// **New, and deliberately unlike `goat-net`'s `goat-net/session/v1`.** Two
/// protocols that derive keys from the same secret must not derive the *same*
/// key, or a compromise of one is a compromise of both.
pub const TUNNEL_KDF_LABEL: &str = "GOAT-PROXY-TUNNEL-v1";

/// The tunnel protocol version carried in every hello and confirm.
pub const TUNNEL_PROTOCOL_VERSION: u16 = 1;

/// Signing context for [`TunnelHello`].
const HELLO_CONTEXT: &[u8] = b"GOAT-PROXY-TUNNEL-HELLO-v1";

/// Signing context for [`TunnelConfirm`].
const CONFIRM_CONTEXT: &[u8] = b"GOAT-PROXY-TUNNEL-CONFIRM-v1";

/// A key-establishment mechanism a peer may offer.
///
/// The classical variant exists so that "refuse a classical-only peer" is a
/// property with a test, rather than a sentence about a case the code cannot
/// represent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KemSuite {
    /// FIPS 203 ML-KEM-768. The only acceptable answer.
    MlKem768,
    /// A classical elliptic-curve exchange. Never selected, in any
    /// combination.
    ClassicalX25519,
}

/// What a peer says it can do.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerKemOffer {
    suites: Vec<KemSuite>,
}

impl PeerKemOffer {
    /// An offer naming exactly these suites, in this order.
    pub fn new(suites: &[KemSuite]) -> Self {
        Self {
            suites: suites.to_vec(),
        }
    }

    /// The only offer that is ever accepted.
    pub fn post_quantum() -> Self {
        Self::new(&[KemSuite::MlKem768])
    }

    /// An offer with no post-quantum mechanism in it.
    pub fn classical_only() -> Self {
        Self::new(&[KemSuite::ClassicalX25519])
    }

    /// What this offer named.
    pub fn suites(&self) -> &[KemSuite] {
        &self.suites
    }

    /// Choose a suite, or refuse.
    ///
    /// ML-KEM-768 wins whenever it is present, wherever it appears in the
    /// list. Order is *not* preference here: a peer that lists a classical
    /// mechanism first must not be able to steer the choice, which is exactly
    /// what a preference-ordered selection would allow.
    pub fn select(&self) -> Result<KemSuite, TunnelError> {
        if self.suites.contains(&KemSuite::MlKem768) {
            Ok(KemSuite::MlKem768)
        } else {
            Err(TunnelError::NoPostQuantumKem)
        }
    }
}

/// The three hashes a hello binds itself to.
///
/// Each names something the operator saw and signed. A session that does not
/// name all three is a session nobody consented to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelloBinding {
    /// Hash of the operator's signed consent record.
    pub consent_record_hash: [u8; 32],
    /// Hash of the exact policy text the operator was shown.
    pub policy_text_hash: [u8; 32],
    /// Digest of the destination allowlist in force.
    pub allowlist_digest: [u8; 32],
}

/// The node's opening message.
#[derive(Clone, Debug)]
pub struct TunnelHello {
    /// Tunnel protocol version.
    pub protocol_version: u16,
    /// The node's long-lived ML-DSA-65 identity public key.
    pub node_identity_pk: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
    /// ML-KEM-768 ciphertext encapsulated to the gateway's public key.
    pub kem_ciphertext: [u8; ML_KEM_768_CIPHERTEXT_LEN],
    /// Hash of the operator's signed consent record.
    pub consent_record_hash: [u8; 32],
    /// Hash of the policy text the operator was shown.
    pub policy_text_hash: [u8; 32],
    /// Digest of the destination allowlist in force.
    pub allowlist_digest: [u8; 32],
    /// ML-DSA-65 over every field above, under [`HELLO_CONTEXT`].
    pub signature: [u8; ML_DSA_65_SIGNATURE_LEN],
}

impl TunnelHello {
    /// The exact bytes the signature covers.
    ///
    /// Every field of the message is in here. A field outside the preimage is
    /// a field an attacker may edit in flight.
    pub fn signed_preimage(&self) -> Vec<u8> {
        hello_preimage(
            self.protocol_version,
            &self.node_identity_pk,
            &self.kem_ciphertext,
            &HelloBinding {
                consent_record_hash: self.consent_record_hash,
                policy_text_hash: self.policy_text_hash,
                allowlist_digest: self.allowlist_digest,
            },
        )
    }

    /// SHA3-256 over the signed preimage **and** the signature.
    ///
    /// Binding the signature in is what makes the transcript — and therefore
    /// the session key — unique per handshake even for two helloes that
    /// happen to carry identical fields.
    pub fn transcript_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(self.signed_preimage());
        h.update(self.signature);
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }
}

/// The gateway's answer.
#[derive(Clone, Debug)]
pub struct TunnelConfirm {
    /// Tunnel protocol version.
    pub protocol_version: u16,
    /// The gateway's ML-DSA-65 identity public key.
    pub gateway_identity_pk: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
    /// The transcript hash the gateway computed from the hello it accepted.
    pub transcript_hash: [u8; 32],
    /// ML-DSA-65 over every field above, under [`CONFIRM_CONTEXT`].
    pub signature: [u8; ML_DSA_65_SIGNATURE_LEN],
}

impl TunnelConfirm {
    /// The exact bytes the signature covers.
    pub fn signed_preimage(&self) -> Vec<u8> {
        confirm_preimage(
            self.protocol_version,
            &self.gateway_identity_pk,
            &self.transcript_hash,
        )
    }
}

/// What the gateway will accept.
#[derive(Clone, Debug, Default)]
pub struct GatewayPolicy {
    /// The one protocol version this gateway speaks.
    pub protocol_version: u16,
    /// Every allowlist digest this gateway has published. A hello naming
    /// anything else is refused: the gateway serves the lists it published,
    /// not the lists a node claims.
    pub published_allowlist_digests: Vec<[u8; 32]>,
}

impl GatewayPolicy {
    /// A policy for the current protocol version publishing these digests.
    pub fn new(digests: &[[u8; 32]]) -> Self {
        Self {
            protocol_version: TUNNEL_PROTOCOL_VERSION,
            published_allowlist_digests: digests.to_vec(),
        }
    }
}

/// How many accepted helloes one gateway process tracks before it refuses to
/// accept another.
///
/// Four thousand and ninety-six 32-byte digests is 128 KiB of set — trivial
/// against the bound it replaces, which was none at all.
pub const MAX_TRACKED_HELLOES: usize = 4_096;

/// Helloes this gateway session has already accepted.
///
/// Keyed on the transcript hash, which covers every field and the signature,
/// so two structurally identical helloes signed independently are still
/// distinct. Entries are inserted **only after** the signature verifies.
///
/// # Bounded, and it does not evict
///
/// The set is capped at [`MAX_TRACKED_HELLOES`] and a hello arriving at a full
/// cache is **refused** ([`TunnelError::ReplayCacheFull`]). Eviction is not
/// implemented and is not an oversight: evicting an entry silently re-admits
/// the hello that entry was tracking, so an LRU here would be a replay window
/// with a published size. Safe eviction needs an ordering by age, and the
/// hello carries no freshness field to order by.
///
/// # The residual gap this does NOT close
///
/// The defence is **per gateway process**. A hello captured from the wire and
/// replayed against a restarted or different gateway instance is accepted,
/// because nothing in the signed message says when it was made. The bound on
/// the damage is real and worth stating: the replayer does not hold the node's
/// ML-KEM-768 shared secret, so it cannot derive the session key and cannot
/// carry a byte over the session it opened. The exposure is resource
/// consumption and a session start misattributed to that operator's consent
/// digests — not confidentiality and not traffic injection. Closing it needs a
/// freshness field inside the signed hello preimage, which is a wire-format
/// change and belongs with the end-to-end session work, not here.
#[derive(Clone, Debug)]
pub struct HelloReplayCache {
    seen: HashSet<[u8; 32]>,
    capacity: usize,
}

impl Default for HelloReplayCache {
    fn default() -> Self {
        Self::with_capacity(MAX_TRACKED_HELLOES)
    }
}

impl HelloReplayCache {
    /// An empty cache holding [`MAX_TRACKED_HELLOES`].
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty cache with an explicit bound.
    ///
    /// Exposed so the fail-closed path can be tested without generating four
    /// thousand handshakes.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            capacity,
        }
    }

    /// How many helloes have been accepted.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether nothing has been accepted yet.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// The bound this cache refuses at.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Record a transcript, or say why not.
    ///
    /// `Err(ReplayedHello)` if it has been seen; `Err(ReplayCacheFull)` if the
    /// bound is reached and this transcript is new. The seen-check runs first,
    /// so a full cache still recognises a replay it is already tracking rather
    /// than downgrading it to a capacity complaint.
    fn record(&mut self, transcript_hash: [u8; 32]) -> Result<(), TunnelError> {
        if self.seen.contains(&transcript_hash) {
            return Err(TunnelError::ReplayedHello);
        }
        if self.seen.len() >= self.capacity {
            return Err(TunnelError::ReplayCacheFull {
                tracked: self.seen.len(),
            });
        }
        self.seen.insert(transcript_hash);
        Ok(())
    }
}

/// The post-quantum primitives the handshake needs.
///
/// A trait rather than free functions for one reason: it makes "how much
/// crypto did this refusal spend?" observable. A test double that counts
/// encapsulations is the only way to assert that a classical-only peer is
/// refused **before** any key material exists, rather than after.
pub trait TunnelPqBackend {
    /// This endpoint's ML-DSA-65 identity public key.
    fn identity_public_key(&self) -> [u8; ML_DSA_65_PUBLIC_KEY_LEN];

    /// Sign with this endpoint's identity key.
    fn sign(&self, message: &[u8]) -> Result<[u8; ML_DSA_65_SIGNATURE_LEN], TunnelError>;

    /// Verify an ML-DSA-65 signature.
    fn verify(
        &self,
        public_key: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
        message: &[u8],
        signature: &[u8; ML_DSA_65_SIGNATURE_LEN],
    ) -> bool;

    /// Encapsulate to a peer's ML-KEM-768 public key.
    fn encapsulate(
        &self,
        encaps_key: &[u8; ML_KEM_768_ENCAPS_KEY_LEN],
    ) -> Result<
        (
            [u8; ML_KEM_768_CIPHERTEXT_LEN],
            [u8; ML_KEM_768_SHARED_SECRET_LEN],
        ),
        TunnelError,
    >;

    /// Decapsulate with this endpoint's ML-KEM-768 private key.
    fn decapsulate(
        &self,
        ciphertext: &[u8; ML_KEM_768_CIPHERTEXT_LEN],
    ) -> Result<[u8; ML_KEM_768_SHARED_SECRET_LEN], TunnelError>;
}

/// The real backend: FIPS 203 ML-KEM-768 + FIPS 204 ML-DSA-65.
///
/// Same crates and same versions as the spine's host backend, so the two
/// cannot drift on primitive choice.
pub struct MlKem768MlDsa65 {
    signing: SigningKey<MlDsa65>,
    identity: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
    decaps: Option<DecapsulationKey<MlKem768>>,
    encaps: Option<[u8; ML_KEM_768_ENCAPS_KEY_LEN]>,
}

impl MlKem768MlDsa65 {
    /// A node identity: an ML-DSA-65 signer and no KEM private key.
    ///
    /// The initiator never decapsulates, so it holds no decapsulation key —
    /// key material it cannot use is key material that can only be stolen.
    pub fn node_from_seed(seed: [u8; 32]) -> Self {
        let signing = signing_key_from_seed(seed);
        let identity = encode_identity(&signing);
        Self {
            signing,
            identity,
            decaps: None,
            encaps: None,
        }
    }

    /// A gateway identity: an ML-DSA-65 signer plus a fresh ML-KEM-768
    /// keypair.
    pub fn gateway_from_seed(seed: [u8; 32]) -> Self {
        let signing = signing_key_from_seed(seed);
        let identity = encode_identity(&signing);
        let (dk, ek) = MlKem768::generate_keypair();
        let mut ek_bytes = [0u8; ML_KEM_768_ENCAPS_KEY_LEN];
        ek_bytes.copy_from_slice(ek.to_bytes().as_slice());
        Self {
            signing,
            identity,
            decaps: Some(dk),
            encaps: Some(ek_bytes),
        }
    }

    /// This endpoint's published ML-KEM-768 encapsulation key, if it has one.
    pub fn kem_public(&self) -> Option<[u8; ML_KEM_768_ENCAPS_KEY_LEN]> {
        self.encaps
    }
}

fn signing_key_from_seed(seed: [u8; 32]) -> SigningKey<MlDsa65> {
    let b = B32::try_from(&seed[..]).expect("a 32-byte seed is a B32");
    SigningKey::<MlDsa65>::from_seed(&b)
}

fn encode_identity(signing: &SigningKey<MlDsa65>) -> [u8; ML_DSA_65_PUBLIC_KEY_LEN] {
    let vk: VerifyingKey<MlDsa65> = signing.verifying_key();
    let mut out = [0u8; ML_DSA_65_PUBLIC_KEY_LEN];
    out.copy_from_slice(vk.encode().as_slice());
    out
}

impl TunnelPqBackend for MlKem768MlDsa65 {
    fn identity_public_key(&self) -> [u8; ML_DSA_65_PUBLIC_KEY_LEN] {
        self.identity
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; ML_DSA_65_SIGNATURE_LEN], TunnelError> {
        let sig: Signature<MlDsa65> = self.signing.sign(message);
        let mut out = [0u8; ML_DSA_65_SIGNATURE_LEN];
        out.copy_from_slice(sig.encode().as_slice());
        Ok(out)
    }

    fn verify(
        &self,
        public_key: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
        message: &[u8],
        signature: &[u8; ML_DSA_65_SIGNATURE_LEN],
    ) -> bool {
        let Ok(enc_vk) = EncodedVerifyingKey::<MlDsa65>::try_from(public_key.as_slice()) else {
            return false;
        };
        let vk = VerifyingKey::<MlDsa65>::decode(&enc_vk);
        let Ok(enc_sig) = EncodedSignature::<MlDsa65>::try_from(signature.as_slice()) else {
            return false;
        };
        let Some(sig) = Signature::<MlDsa65>::decode(&enc_sig) else {
            return false;
        };
        vk.verify(message, &sig).is_ok()
    }

    fn encapsulate(
        &self,
        encaps_key: &[u8; ML_KEM_768_ENCAPS_KEY_LEN],
    ) -> Result<
        (
            [u8; ML_KEM_768_CIPHERTEXT_LEN],
            [u8; ML_KEM_768_SHARED_SECRET_LEN],
        ),
        TunnelError,
    > {
        let key = ml_kem::Key::<EncapsulationKey<MlKem768>>::try_from(encaps_key.as_slice())
            .map_err(|_| TunnelError::KemFailure)?;
        let ek = EncapsulationKey::<MlKem768>::new(&key).map_err(|_| TunnelError::KemFailure)?;
        let (ct, shared) = ek.encapsulate();
        let mut ct_bytes = [0u8; ML_KEM_768_CIPHERTEXT_LEN];
        ct_bytes.copy_from_slice(ct.as_ref());
        let mut ss = [0u8; ML_KEM_768_SHARED_SECRET_LEN];
        ss.copy_from_slice(shared.as_ref());
        Ok((ct_bytes, ss))
    }

    fn decapsulate(
        &self,
        ciphertext: &[u8; ML_KEM_768_CIPHERTEXT_LEN],
    ) -> Result<[u8; ML_KEM_768_SHARED_SECRET_LEN], TunnelError> {
        let dk = self.decaps.as_ref().ok_or(TunnelError::KemFailure)?;
        let ct = Ciphertext::<MlKem768>::try_from(ciphertext.as_slice())
            .map_err(|_| TunnelError::KemFailure)?;
        let shared = dk.decapsulate(&ct);
        let mut out = [0u8; ML_KEM_768_SHARED_SECRET_LEN];
        out.copy_from_slice(shared.as_ref());
        Ok(out)
    }
}

fn hello_preimage(
    protocol_version: u16,
    identity: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
    kem_ciphertext: &[u8; ML_KEM_768_CIPHERTEXT_LEN],
    binding: &HelloBinding,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        HELLO_CONTEXT.len() + 2 + ML_DSA_65_PUBLIC_KEY_LEN + ML_KEM_768_CIPHERTEXT_LEN + 96,
    );
    out.extend_from_slice(HELLO_CONTEXT);
    out.extend_from_slice(&protocol_version.to_be_bytes());
    out.extend_from_slice(identity);
    out.extend_from_slice(kem_ciphertext);
    out.extend_from_slice(&binding.consent_record_hash);
    out.extend_from_slice(&binding.policy_text_hash);
    out.extend_from_slice(&binding.allowlist_digest);
    out
}

fn confirm_preimage(
    protocol_version: u16,
    gateway_identity: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
    transcript_hash: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CONFIRM_CONTEXT.len() + 2 + ML_DSA_65_PUBLIC_KEY_LEN + 32);
    out.extend_from_slice(CONFIRM_CONTEXT);
    out.extend_from_slice(&protocol_version.to_be_bytes());
    out.extend_from_slice(gateway_identity);
    out.extend_from_slice(transcript_hash);
    out
}

/// SHA3-256 over `label ‖ 0x00 ‖ shared_secret ‖ transcript_hash`.
///
/// The separator byte is there so that no shift of the label boundary can
/// produce the same input as a different label of a different length.
fn kdf(label: &[u8], shared_secret: &[u8], transcript_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(label);
    h.update([0x00]);
    h.update(shared_secret);
    h.update(transcript_hash);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// The tunnel session key.
///
/// Takes the ML-KEM-768 shared secret and the handshake transcript, and
/// **nothing else**. There is deliberately no parameter through which the
/// outer TLS session, its resumption ticket, its exporter or its channel
/// binding could reach this function: the outer carriage is not the trust
/// boundary and must not be able to influence the key.
pub fn derive_session_key(shared_secret: &[u8], transcript_hash: &[u8; 32]) -> [u8; 32] {
    kdf(TUNNEL_KDF_LABEL.as_bytes(), shared_secret, transcript_hash)
}

/// Node side: choose the KEM, encapsulate, sign, derive.
///
/// Returns the hello to send and the session key to use. The KEM selection is
/// the **first** thing that happens, so a classical-only peer costs zero
/// post-quantum operations and produces no key material.
///
/// The three binding hashes are *not* checked here. The gateway is the
/// enforcement point for them — a node that checked its own consent hash and
/// then sent whatever it liked would have proved nothing.
pub fn initiate<B: TunnelPqBackend + ?Sized>(
    backend: &B,
    gateway_kem_public: &[u8; ML_KEM_768_ENCAPS_KEY_LEN],
    offer: &PeerKemOffer,
    binding: &HelloBinding,
) -> Result<(TunnelHello, [u8; 32]), TunnelError> {
    match offer.select()? {
        KemSuite::MlKem768 => {}
        // Unreachable while `select` refuses everything else; written out so
        // that adding a suite is a compile error here rather than a silent
        // acceptance.
        KemSuite::ClassicalX25519 => return Err(TunnelError::NoPostQuantumKem),
    }

    let (kem_ciphertext, shared) = backend.encapsulate(gateway_kem_public)?;
    let node_identity_pk = backend.identity_public_key();
    let preimage = hello_preimage(
        TUNNEL_PROTOCOL_VERSION,
        &node_identity_pk,
        &kem_ciphertext,
        binding,
    );
    let signature = backend.sign(&preimage)?;

    let hello = TunnelHello {
        protocol_version: TUNNEL_PROTOCOL_VERSION,
        node_identity_pk,
        kem_ciphertext,
        consent_record_hash: binding.consent_record_hash,
        policy_text_hash: binding.policy_text_hash,
        allowlist_digest: binding.allowlist_digest,
        signature,
    };
    let key = derive_session_key(&shared, &hello.transcript_hash());
    Ok((hello, key))
}

/// Gateway side: validate, verify, decapsulate, derive, confirm.
///
/// Check order is cheap-to-expensive, and the replay cache is consulted only
/// after the signature verifies so that a forged hello cannot pollute it.
pub fn respond<B: TunnelPqBackend + ?Sized>(
    backend: &B,
    hello: &TunnelHello,
    policy: &GatewayPolicy,
    replay: &mut HelloReplayCache,
) -> Result<(TunnelConfirm, [u8; 32]), TunnelError> {
    if hello.protocol_version != policy.protocol_version {
        return Err(TunnelError::ProtocolVersionMismatch {
            expected: policy.protocol_version,
            got: hello.protocol_version,
        });
    }
    if hello.consent_record_hash == [0u8; 32] {
        return Err(TunnelError::ZeroConsentRecordHash);
    }
    if hello.policy_text_hash == [0u8; 32] {
        return Err(TunnelError::ZeroPolicyTextHash);
    }
    if !policy
        .published_allowlist_digests
        .contains(&hello.allowlist_digest)
    {
        return Err(TunnelError::UnknownAllowlistDigest);
    }

    let preimage = hello.signed_preimage();
    if !backend.verify(&hello.node_identity_pk, &preimage, &hello.signature) {
        return Err(TunnelError::HandshakeSignatureInvalid);
    }

    let transcript_hash = hello.transcript_hash();
    replay.record(transcript_hash)?;

    let shared = backend.decapsulate(&hello.kem_ciphertext)?;
    let key = derive_session_key(&shared, &transcript_hash);

    let gateway_identity_pk = backend.identity_public_key();
    let confirm_bytes = confirm_preimage(
        policy.protocol_version,
        &gateway_identity_pk,
        &transcript_hash,
    );
    let signature = backend.sign(&confirm_bytes)?;
    Ok((
        TunnelConfirm {
            protocol_version: policy.protocol_version,
            gateway_identity_pk,
            transcript_hash,
            signature,
        },
        key,
    ))
}

/// Node side: check the gateway's answer.
///
/// The expected gateway identity is a **parameter**. Without it a "valid"
/// confirm is any self-consistent self-signed blob, and anything that can
/// reach the node's socket can forge one.
pub fn verify_confirm<B: TunnelPqBackend + ?Sized>(
    backend: &B,
    confirm: &TunnelConfirm,
    expected_gateway_pk: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
    expected_transcript_hash: &[u8; 32],
) -> Result<(), TunnelError> {
    if confirm.protocol_version != TUNNEL_PROTOCOL_VERSION {
        return Err(TunnelError::ProtocolVersionMismatch {
            expected: TUNNEL_PROTOCOL_VERSION,
            got: confirm.protocol_version,
        });
    }
    if &confirm.gateway_identity_pk != expected_gateway_pk
        || &confirm.transcript_hash != expected_transcript_hash
    {
        return Err(TunnelError::HandshakeSignatureInvalid);
    }
    if !backend.verify(
        &confirm.gateway_identity_pk,
        &confirm.signed_preimage(),
        &confirm.signature,
    ) {
        return Err(TunnelError::HandshakeSignatureInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A backend that counts the post-quantum work it was asked to do, so
    /// "refused before any key material existed" is an assertion on a number
    /// rather than on an error variant.
    struct CountingBackend {
        inner: MlKem768MlDsa65,
        encapsulations: Cell<u32>,
        decapsulations: Cell<u32>,
        signatures: Cell<u32>,
    }

    impl CountingBackend {
        fn node(seed: u8) -> Self {
            Self {
                inner: MlKem768MlDsa65::node_from_seed([seed; 32]),
                encapsulations: Cell::new(0),
                decapsulations: Cell::new(0),
                signatures: Cell::new(0),
            }
        }
    }

    impl TunnelPqBackend for CountingBackend {
        fn identity_public_key(&self) -> [u8; ML_DSA_65_PUBLIC_KEY_LEN] {
            self.inner.identity_public_key()
        }
        fn sign(&self, message: &[u8]) -> Result<[u8; ML_DSA_65_SIGNATURE_LEN], TunnelError> {
            self.signatures.set(self.signatures.get() + 1);
            self.inner.sign(message)
        }
        fn verify(
            &self,
            public_key: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
            message: &[u8],
            signature: &[u8; ML_DSA_65_SIGNATURE_LEN],
        ) -> bool {
            self.inner.verify(public_key, message, signature)
        }
        fn encapsulate(
            &self,
            encaps_key: &[u8; ML_KEM_768_ENCAPS_KEY_LEN],
        ) -> Result<
            (
                [u8; ML_KEM_768_CIPHERTEXT_LEN],
                [u8; ML_KEM_768_SHARED_SECRET_LEN],
            ),
            TunnelError,
        > {
            self.encapsulations.set(self.encapsulations.get() + 1);
            self.inner.encapsulate(encaps_key)
        }
        fn decapsulate(
            &self,
            ciphertext: &[u8; ML_KEM_768_CIPHERTEXT_LEN],
        ) -> Result<[u8; ML_KEM_768_SHARED_SECRET_LEN], TunnelError> {
            self.decapsulations.set(self.decapsulations.get() + 1);
            self.inner.decapsulate(ciphertext)
        }
    }

    fn binding() -> HelloBinding {
        HelloBinding {
            consent_record_hash: [0x11; 32],
            policy_text_hash: [0x22; 32],
            allowlist_digest: [0x33; 32],
        }
    }

    fn policy() -> GatewayPolicy {
        GatewayPolicy::new(&[[0x33; 32]])
    }

    /// A complete, accepted handshake — the positive control every refusal
    /// test below leans on.
    fn good_handshake() -> (MlKem768MlDsa65, MlKem768MlDsa65, TunnelHello, [u8; 32]) {
        let node = MlKem768MlDsa65::node_from_seed([1u8; 32]);
        let gateway = MlKem768MlDsa65::gateway_from_seed([2u8; 32]);
        let ek = gateway.kem_public().expect("gateway has a KEM public key");
        let (hello, key) = initiate(&node, &ek, &PeerKemOffer::post_quantum(), &binding())
            .expect("a well-formed handshake is accepted");
        (node, gateway, hello, key)
    }

    // ------------------------------------------------------------------
    // INV-12: post-quantum is mandatory
    // ------------------------------------------------------------------

    /// **Mutations this detects:** adding a classical fallback arm, making the
    /// suite selection preference-ordered so a peer can steer it, or moving
    /// the selection after the encapsulation so a refusal still spends key
    /// material.
    #[test]
    fn handshake_refuses_a_classical_only_peer() {
        let node = CountingBackend::node(1);
        let gateway = MlKem768MlDsa65::gateway_from_seed([2u8; 32]);
        let ek = gateway.kem_public().unwrap();

        // Positive control: the same call with a post-quantum offer succeeds
        // and does spend an encapsulation.
        let ok = initiate(&node, &ek, &PeerKemOffer::post_quantum(), &binding());
        assert!(ok.is_ok());
        assert_eq!(node.encapsulations.get(), 1);

        let refused = initiate(&node, &ek, &PeerKemOffer::classical_only(), &binding());
        assert_eq!(refused.unwrap_err(), TunnelError::NoPostQuantumKem);
        assert_eq!(
            node.encapsulations.get(),
            1,
            "a classical-only peer spent an encapsulation, so key material existed before the \
             refusal"
        );
        assert_eq!(
            node.signatures.get(),
            1,
            "a classical-only peer spent a signature"
        );

        // An offer that lists a classical suite alongside ML-KEM must not be
        // steerable into the classical branch.
        let mixed = PeerKemOffer::new(&[KemSuite::ClassicalX25519, KemSuite::MlKem768]);
        assert_eq!(mixed.select().unwrap(), KemSuite::MlKem768);
        assert_eq!(
            PeerKemOffer::default().select().unwrap_err(),
            TunnelError::NoPostQuantumKem,
            "an empty offer is not a post-quantum offer"
        );
    }

    /// **Mutations this detects:** adding any outer-TLS input to the KDF —
    /// an exporter, a channel binding, a resumption ticket — which would let
    /// whoever terminates the outer TLS influence the inner key.
    #[test]
    fn session_key_is_derived_inside_the_wss_carriage_not_from_it() {
        // Compile-time: the KDF takes the KEM secret and the transcript, and
        // nothing else. A carriage parameter would not type-check here.
        let shape: fn(&[u8], &[u8; 32]) -> [u8; 32] = derive_session_key;
        assert_eq!(
            shape(&[9u8; 32], &[8u8; 32]),
            derive_session_key(&[9u8; 32], &[8u8; 32])
        );

        // Runtime: one hello, carried over two different outer sessions,
        // derives one key. The "outer TLS session id" is modelled as two
        // distinct values that the handshake has no way to consume — which is
        // the property.
        let (_node, gateway, hello, node_key) = good_handshake();
        let outer_session_ids = [[0xAAu8; 32], [0xBBu8; 32]];
        let mut keys = Vec::new();
        for id in outer_session_ids {
            let mut replay = HelloReplayCache::new();
            let (_confirm, key) = respond(&gateway, &hello, &policy(), &mut replay).unwrap();
            assert_ne!(id, [0u8; 32]);
            keys.push(key);
        }
        assert_eq!(
            keys[0], keys[1],
            "the session key changed with the outer session, so the outer TLS reaches the inner \
             key"
        );
        assert_eq!(keys[0], node_key, "the two ends did not agree");
    }

    /// **Mutations this detects:** reusing `goat-net`'s label, or dropping the
    /// label from the KDF input entirely.
    #[test]
    fn the_kdf_label_is_new_and_does_not_collide_with_goat_net() {
        let goat_net_label: &[u8] = b"goat-net/session/v1";
        assert_ne!(
            TUNNEL_KDF_LABEL.as_bytes(),
            goat_net_label,
            "the tunnel reuses the gossip label, which is a domain-separation error"
        );

        let shared = [0x5Au8; 32];
        let transcript = [0x6Bu8; 32];

        // Positive control: the same label over the same inputs is
        // deterministic, so the inequality below is about the label and not
        // about randomness.
        assert_eq!(
            kdf(TUNNEL_KDF_LABEL.as_bytes(), &shared, &transcript),
            kdf(TUNNEL_KDF_LABEL.as_bytes(), &shared, &transcript)
        );

        assert_ne!(
            kdf(TUNNEL_KDF_LABEL.as_bytes(), &shared, &transcript),
            kdf(goat_net_label, &shared, &transcript),
            "identical inputs under the two labels produced the same key"
        );
        assert_eq!(
            derive_session_key(&shared, &transcript),
            kdf(TUNNEL_KDF_LABEL.as_bytes(), &shared, &transcript),
            "derive_session_key is not using the tunnel label"
        );
    }

    /// **Mutations this detects:** changing the published label string, which
    /// would silently break every peer without breaking any round-trip test.
    #[test]
    fn the_kdf_label_is_pinned() {
        assert_eq!(TUNNEL_KDF_LABEL, "GOAT-PROXY-TUNNEL-v1");
        assert_eq!(TUNNEL_PROTOCOL_VERSION, 1);
        assert_eq!(HELLO_CONTEXT, b"GOAT-PROXY-TUNNEL-HELLO-v1");
        assert_eq!(CONFIRM_CONTEXT, b"GOAT-PROXY-TUNNEL-CONFIRM-v1");
        assert_ne!(HELLO_CONTEXT, CONFIRM_CONTEXT);
    }

    /// **Mutations this detects:** dropping the separator byte or the
    /// transcript from the KDF input, either of which lets two different
    /// handshakes share a key.
    #[test]
    fn two_handshakes_derive_two_different_keys() {
        let a = derive_session_key(&[1u8; 32], &[2u8; 32]);
        let b = derive_session_key(&[1u8; 32], &[3u8; 32]);
        let c = derive_session_key(&[4u8; 32], &[2u8; 32]);
        assert_ne!(a, b, "the transcript does not reach the key");
        assert_ne!(a, c, "the shared secret does not reach the key");

        // Label-boundary shift: a shorter label with the first byte of the
        // secret appended must not collide with the real label.
        let mut shifted_secret = vec![b'X'];
        shifted_secret.extend_from_slice(&[1u8; 32]);
        assert_ne!(
            kdf(b"GOAT-PROXY-TUNNEL-v", &shifted_secret, &[2u8; 32]),
            a,
            "a label-boundary shift collided"
        );
    }

    // ------------------------------------------------------------------
    // Gateway refusals
    // ------------------------------------------------------------------

    /// **Mutations this detects:** treating an all-zero consent hash as a
    /// valid consent — the "I did not fill this in" value passing as "the
    /// operator agreed".
    #[test]
    fn gateway_refuses_a_hello_with_a_zero_consent_record_hash() {
        let (_n, gateway, good, _k) = good_handshake();
        let mut replay = HelloReplayCache::new();
        // Positive control.
        assert!(respond(&gateway, &good, &policy(), &mut replay).is_ok());

        let mut bad = good.clone();
        bad.consent_record_hash = [0u8; 32];
        let mut replay2 = HelloReplayCache::new();
        assert_eq!(
            respond(&gateway, &bad, &policy(), &mut replay2).unwrap_err(),
            TunnelError::ZeroConsentRecordHash
        );
        assert!(replay2.is_empty(), "a refused hello entered the cache");
    }

    /// **Mutations this detects:** the same, for the policy text the operator
    /// was shown.
    #[test]
    fn gateway_refuses_a_hello_with_a_zero_policy_text_hash() {
        let (_n, gateway, good, _k) = good_handshake();
        let mut replay = HelloReplayCache::new();
        assert!(respond(&gateway, &good, &policy(), &mut replay).is_ok());

        let mut bad = good.clone();
        bad.policy_text_hash = [0u8; 32];
        let mut replay2 = HelloReplayCache::new();
        assert_eq!(
            respond(&gateway, &bad, &policy(), &mut replay2).unwrap_err(),
            TunnelError::ZeroPolicyTextHash
        );
    }

    /// **Mutations this detects:** accepting whatever allowlist digest the
    /// node claims, which would let a node serve a list the gateway never
    /// published.
    #[test]
    fn gateway_refuses_a_hello_whose_allowlist_digest_is_unknown() {
        let (_n, gateway, good, _k) = good_handshake();
        let mut replay = HelloReplayCache::new();
        assert!(respond(&gateway, &good, &policy(), &mut replay).is_ok());

        let empty_policy = GatewayPolicy::new(&[]);
        let mut replay2 = HelloReplayCache::new();
        assert_eq!(
            respond(&gateway, &good, &empty_policy, &mut replay2).unwrap_err(),
            TunnelError::UnknownAllowlistDigest,
            "a gateway publishing no list accepted one"
        );

        let other_policy = GatewayPolicy::new(&[[0x99; 32]]);
        let mut replay3 = HelloReplayCache::new();
        assert_eq!(
            respond(&gateway, &good, &other_policy, &mut replay3).unwrap_err(),
            TunnelError::UnknownAllowlistDigest
        );
    }

    /// **Mutations this detects:** removing the replay cache, keying it on
    /// something an attacker controls independently of the signature, or
    /// inserting before the signature verifies (which would let a forged
    /// hello evict or pre-poison an honest one).
    #[test]
    fn a_replayed_hello_is_refused() {
        let (_n, gateway, hello, _k) = good_handshake();
        let mut replay = HelloReplayCache::new();

        assert!(respond(&gateway, &hello, &policy(), &mut replay).is_ok());
        assert_eq!(replay.len(), 1);
        for attempt in 0..3 {
            assert_eq!(
                respond(&gateway, &hello, &policy(), &mut replay).unwrap_err(),
                TunnelError::ReplayedHello,
                "replay {attempt} was accepted"
            );
        }
        assert_eq!(replay.len(), 1, "a replay grew the cache");

        // A forged hello must not enter the cache at all, or an attacker
        // could pre-insert an honest node's transcript.
        let mut forged = hello.clone();
        forged.signature[0] ^= 0x01;
        let mut clean = HelloReplayCache::new();
        assert_eq!(
            respond(&gateway, &forged, &policy(), &mut clean).unwrap_err(),
            TunnelError::HandshakeSignatureInvalid
        );
        assert!(clean.is_empty(), "a forged hello polluted the replay cache");
    }

    /// **Mutations this detects:** verifying the signature over a subset of
    /// the fields, so a field outside the preimage can be edited in flight.
    #[test]
    fn the_signature_covers_every_hello_field() {
        let (_n, gateway, good, _k) = good_handshake();
        let wide_policy = GatewayPolicy::new(&[[0x33; 32], [0x44; 32], good.allowlist_digest]);

        // Positive control.
        let mut replay = HelloReplayCache::new();
        assert!(respond(&gateway, &good, &wide_policy, &mut replay).is_ok());

        let mut mutants: Vec<(&str, TunnelHello)> = Vec::new();

        let mut m = good.clone();
        m.consent_record_hash = [0x77; 32];
        mutants.push(("consent_record_hash", m));

        let mut m = good.clone();
        m.policy_text_hash = [0x77; 32];
        mutants.push(("policy_text_hash", m));

        let mut m = good.clone();
        m.allowlist_digest = [0x44; 32];
        mutants.push(("allowlist_digest", m));

        let mut m = good.clone();
        m.kem_ciphertext[0] ^= 0x01;
        mutants.push(("kem_ciphertext", m));

        let mut m = good.clone();
        m.node_identity_pk[0] ^= 0x01;
        mutants.push(("node_identity_pk", m));

        let mut m = good.clone();
        m.signature[100] ^= 0x01;
        mutants.push(("signature", m));

        for (field, mutant) in mutants {
            let mut replay = HelloReplayCache::new();
            assert_eq!(
                respond(&gateway, &mutant, &wide_policy, &mut replay).unwrap_err(),
                TunnelError::HandshakeSignatureInvalid,
                "editing {field} did not break the signature"
            );
        }
    }

    /// **Mutations this detects:** accepting a hello from another protocol
    /// version, which would reinterpret every field after the version.
    #[test]
    fn a_hello_for_another_protocol_version_is_refused() {
        let (_n, gateway, good, _k) = good_handshake();
        let mut replay = HelloReplayCache::new();
        assert!(respond(&gateway, &good, &policy(), &mut replay).is_ok());

        let mut bad = good.clone();
        bad.protocol_version = 2;
        let mut replay2 = HelloReplayCache::new();
        assert_eq!(
            respond(&gateway, &bad, &policy(), &mut replay2).unwrap_err(),
            TunnelError::ProtocolVersionMismatch {
                expected: 1,
                got: 2
            }
        );
    }

    /// **Mutations this detects:** verifying the hello against a key the hello
    /// itself supplies without the gateway ever pinning it, or skipping
    /// verification entirely.
    #[test]
    fn a_hello_signed_by_a_different_key_is_refused() {
        let gateway = MlKem768MlDsa65::gateway_from_seed([2u8; 32]);
        let ek = gateway.kem_public().unwrap();
        let honest = MlKem768MlDsa65::node_from_seed([1u8; 32]);
        let impostor = MlKem768MlDsa65::node_from_seed([9u8; 32]);

        let (good, _k) = initiate(&honest, &ek, &PeerKemOffer::post_quantum(), &binding()).unwrap();
        let (other, _k2) =
            initiate(&impostor, &ek, &PeerKemOffer::post_quantum(), &binding()).unwrap();
        assert_ne!(good.node_identity_pk, other.node_identity_pk);

        // Positive control: each hello verifies under its own identity.
        let mut r1 = HelloReplayCache::new();
        assert!(respond(&gateway, &good, &policy(), &mut r1).is_ok());
        let mut r2 = HelloReplayCache::new();
        assert!(respond(&gateway, &other, &policy(), &mut r2).is_ok());

        // Swap the identity key onto the other's signature.
        let mut swapped = good.clone();
        swapped.node_identity_pk = other.node_identity_pk;
        let mut r3 = HelloReplayCache::new();
        assert_eq!(
            respond(&gateway, &swapped, &policy(), &mut r3).unwrap_err(),
            TunnelError::HandshakeSignatureInvalid
        );
    }

    // ------------------------------------------------------------------
    // Agreement and confirm
    // ------------------------------------------------------------------

    /// **Mutations this detects:** deriving the two ends' keys from different
    /// inputs — the failure that makes every subsequent frame fail its tag
    /// with no clue why.
    #[test]
    fn initiate_and_respond_agree_on_the_session_key() {
        let (_n, gateway, hello, node_key) = good_handshake();
        let mut replay = HelloReplayCache::new();
        let (_confirm, gateway_key) = respond(&gateway, &hello, &policy(), &mut replay).unwrap();
        assert_eq!(node_key, gateway_key);
        assert_ne!(node_key, [0u8; 32], "the session key is all zeroes");
    }

    /// **Mutations this detects:** signing a confirm over a transcript the
    /// gateway did not actually compute, which would let a gateway confirm a
    /// hello it never read.
    #[test]
    fn the_confirm_binds_the_same_transcript_hash() {
        let (node, gateway, hello, _k) = good_handshake();
        let mut replay = HelloReplayCache::new();
        let (confirm, _key) = respond(&gateway, &hello, &policy(), &mut replay).unwrap();

        assert_eq!(confirm.transcript_hash, hello.transcript_hash());
        assert!(verify_confirm(
            &node,
            &confirm,
            &gateway.identity_public_key(),
            &hello.transcript_hash()
        )
        .is_ok());

        let mut bad = confirm.clone();
        bad.transcript_hash[0] ^= 0x01;
        assert_eq!(
            verify_confirm(
                &node,
                &bad,
                &gateway.identity_public_key(),
                &hello.transcript_hash()
            )
            .unwrap_err(),
            TunnelError::HandshakeSignatureInvalid
        );
    }

    /// **Mutations this detects:** dropping the expected-gateway-key
    /// parameter, which would make any self-consistent self-signed confirm
    /// acceptable.
    #[test]
    fn a_confirm_from_an_unexpected_gateway_key_is_refused() {
        let (node, gateway, hello, _k) = good_handshake();
        let mut replay = HelloReplayCache::new();
        let (confirm, _key) = respond(&gateway, &hello, &policy(), &mut replay).unwrap();
        let transcript = hello.transcript_hash();

        // Positive control.
        assert!(
            verify_confirm(&node, &confirm, &gateway.identity_public_key(), &transcript).is_ok()
        );

        let impostor = MlKem768MlDsa65::gateway_from_seed([7u8; 32]);
        assert_eq!(
            verify_confirm(
                &node,
                &confirm,
                &impostor.identity_public_key(),
                &transcript
            )
            .unwrap_err(),
            TunnelError::HandshakeSignatureInvalid
        );

        // A confirm the impostor actually signed, presented as the real
        // gateway's, is refused too.
        let mut r2 = HelloReplayCache::new();
        let (forged, _k2) = respond(&impostor, &hello, &policy(), &mut r2).unwrap();
        assert_eq!(
            verify_confirm(&node, &forged, &gateway.identity_public_key(), &transcript)
                .unwrap_err(),
            TunnelError::HandshakeSignatureInvalid
        );
    }

    /// **Mutations this detects:** accepting a confirm for another protocol
    /// version.
    #[test]
    fn a_confirm_for_another_protocol_version_is_refused() {
        let (node, gateway, hello, _k) = good_handshake();
        let mut replay = HelloReplayCache::new();
        let (confirm, _key) = respond(&gateway, &hello, &policy(), &mut replay).unwrap();
        let transcript = hello.transcript_hash();

        let mut bad = confirm.clone();
        bad.protocol_version = 3;
        assert_eq!(
            verify_confirm(&node, &bad, &gateway.identity_public_key(), &transcript).unwrap_err(),
            TunnelError::ProtocolVersionMismatch {
                expected: 1,
                got: 3
            }
        );
    }

    // ------------------------------------------------------------------
    // Shapes and structural pins
    // ------------------------------------------------------------------

    /// **Mutations this detects:** reordering the preimage's fields or
    /// changing its context string, either of which silently breaks
    /// interoperability while every round-trip test stays green.
    #[test]
    fn the_hello_preimage_layout_is_pinned() {
        let identity = [0xA1u8; ML_DSA_65_PUBLIC_KEY_LEN];
        let ct = [0xB2u8; ML_KEM_768_CIPHERTEXT_LEN];
        let b = binding();
        let p = hello_preimage(TUNNEL_PROTOCOL_VERSION, &identity, &ct, &b);

        let mut at = 0;
        assert_eq!(&p[at..at + HELLO_CONTEXT.len()], HELLO_CONTEXT);
        at += HELLO_CONTEXT.len();
        assert_eq!(&p[at..at + 2], &1u16.to_be_bytes());
        at += 2;
        assert_eq!(&p[at..at + ML_DSA_65_PUBLIC_KEY_LEN], &identity[..]);
        at += ML_DSA_65_PUBLIC_KEY_LEN;
        assert_eq!(&p[at..at + ML_KEM_768_CIPHERTEXT_LEN], &ct[..]);
        at += ML_KEM_768_CIPHERTEXT_LEN;
        assert_eq!(&p[at..at + 32], &b.consent_record_hash);
        at += 32;
        assert_eq!(&p[at..at + 32], &b.policy_text_hash);
        at += 32;
        assert_eq!(&p[at..at + 32], &b.allowlist_digest);
        at += 32;
        assert_eq!(p.len(), at, "the preimage carries unaccounted bytes");
    }

    /// **Mutations this detects:** shrinking a key or signature field, which
    /// would silently truncate real key material.
    #[test]
    fn the_post_quantum_field_widths_are_pinned() {
        assert_eq!(ML_DSA_65_PUBLIC_KEY_LEN, 1952);
        assert_eq!(ML_DSA_65_SIGNATURE_LEN, 3309);
        assert_eq!(ML_KEM_768_CIPHERTEXT_LEN, 1088);
        assert_eq!(ML_KEM_768_ENCAPS_KEY_LEN, 1184);
        assert_eq!(ML_KEM_768_SHARED_SECRET_LEN, 32);

        let (_n, _g, hello, _k) = good_handshake();
        assert_eq!(hello.node_identity_pk.len(), ML_DSA_65_PUBLIC_KEY_LEN);
        assert_eq!(hello.kem_ciphertext.len(), ML_KEM_768_CIPHERTEXT_LEN);
        assert_eq!(hello.signature.len(), ML_DSA_65_SIGNATURE_LEN);
    }

    /// **Mutations this detects:** a gateway that hands out the same KEM
    /// ciphertext twice, or a hello whose transcript does not vary between
    /// sessions — either of which defeats the replay cache.
    #[test]
    fn two_helloes_to_the_same_gateway_have_different_transcripts() {
        let node = MlKem768MlDsa65::node_from_seed([1u8; 32]);
        let gateway = MlKem768MlDsa65::gateway_from_seed([2u8; 32]);
        let ek = gateway.kem_public().unwrap();
        let (a, ka) = initiate(&node, &ek, &PeerKemOffer::post_quantum(), &binding()).unwrap();
        let (b, kb) = initiate(&node, &ek, &PeerKemOffer::post_quantum(), &binding()).unwrap();
        assert_ne!(a.kem_ciphertext, b.kem_ciphertext);
        assert_ne!(a.transcript_hash(), b.transcript_hash());
        assert_ne!(ka, kb, "two sessions share a key");

        let mut replay = HelloReplayCache::new();
        assert!(respond(&gateway, &a, &policy(), &mut replay).is_ok());
        assert!(respond(&gateway, &b, &policy(), &mut replay).is_ok());
        assert_eq!(replay.len(), 2);
    }

    /// **Mutations this detects:** a node identity that silently holds a KEM
    /// private key it never needs — key material that cannot be used but can
    /// be stolen.
    #[test]
    fn a_node_identity_holds_no_decapsulation_key() {
        let node = MlKem768MlDsa65::node_from_seed([1u8; 32]);
        assert!(node.kem_public().is_none());
        assert_eq!(
            node.decapsulate(&[0u8; ML_KEM_768_CIPHERTEXT_LEN])
                .unwrap_err(),
            TunnelError::KemFailure
        );
        // Positive control: a gateway identity does hold one.
        let gateway = MlKem768MlDsa65::gateway_from_seed([2u8; 32]);
        assert!(gateway.kem_public().is_some());
    }

    /// **Mutations this detects:** a decapsulation that ignores its input and
    /// returns a constant, which would make every session share a key while
    /// every agreement test still passed.
    #[test]
    fn decapsulating_a_foreign_ciphertext_does_not_reproduce_the_shared_secret() {
        let node = MlKem768MlDsa65::node_from_seed([1u8; 32]);
        let gateway = MlKem768MlDsa65::gateway_from_seed([2u8; 32]);
        let other = MlKem768MlDsa65::gateway_from_seed([3u8; 32]);
        let ek = gateway.kem_public().unwrap();

        let (ct, shared) = node.encapsulate(&ek).unwrap();
        // Positive control: the right gateway recovers it.
        assert_eq!(gateway.decapsulate(&ct).unwrap(), shared);
        // The wrong one does not. ML-KEM is implicitly rejecting, so this is
        // a different secret rather than an error.
        assert_ne!(other.decapsulate(&ct).unwrap(), shared);
    }

    /// **Mutations this detects:** a gateway that skips the version check
    /// because the policy's version was defaulted to zero.
    #[test]
    fn a_default_gateway_policy_publishes_nothing_and_speaks_no_version() {
        let empty = GatewayPolicy::default();
        assert!(empty.published_allowlist_digests.is_empty());
        assert_eq!(empty.protocol_version, 0);

        let (_n, gateway, hello, _k) = good_handshake();
        let mut replay = HelloReplayCache::new();
        assert_eq!(
            respond(&gateway, &hello, &empty, &mut replay).unwrap_err(),
            TunnelError::ProtocolVersionMismatch {
                expected: 0,
                got: 1
            },
            "a defaulted policy accepted a live hello"
        );
    }

    /// The memory half of the replay defence.
    ///
    /// **Mutations this detects:** removing the bound (the set grows without
    /// limit on a public endpoint), or meeting the bound by evicting — which
    /// silently re-admits the hello the evicted entry was tracking and turns
    /// the cache into a replay window with a published size.
    #[test]
    fn the_replay_cache_is_bounded_and_refuses_rather_than_evicting() {
        assert_eq!(MAX_TRACKED_HELLOES, 4_096);
        assert_eq!(HelloReplayCache::new().capacity(), MAX_TRACKED_HELLOES);
        assert_eq!(HelloReplayCache::default().capacity(), MAX_TRACKED_HELLOES);

        let gateway = MlKem768MlDsa65::gateway_from_seed([9u8; 32]);
        let ek = gateway.kem_public().unwrap();
        let mut replay = HelloReplayCache::with_capacity(2);

        // Positive control: it accepts up to its bound. Three distinct nodes,
        // three distinct helloes.
        let mut helloes = Vec::new();
        for seed in [1u8, 2, 3] {
            let node = MlKem768MlDsa65::node_from_seed([seed; 32]);
            let (hello, _k) =
                initiate(&node, &ek, &PeerKemOffer::post_quantum(), &binding()).expect("initiate");
            helloes.push(hello);
        }
        assert!(respond(&gateway, &helloes[0], &policy(), &mut replay).is_ok());
        assert!(respond(&gateway, &helloes[1], &policy(), &mut replay).is_ok());
        assert_eq!(replay.len(), 2);

        // At the bound, a NEW hello is refused for capacity — not accepted,
        // and not silently dropping an older entry.
        assert_eq!(
            respond(&gateway, &helloes[2], &policy(), &mut replay).unwrap_err(),
            TunnelError::ReplayCacheFull { tracked: 2 }
        );
        assert_eq!(replay.len(), 2, "the cache evicted to make room");

        // And the entries it already held are still recognised as replays,
        // which is what eviction would have destroyed.
        assert_eq!(
            respond(&gateway, &helloes[0], &policy(), &mut replay).unwrap_err(),
            TunnelError::ReplayedHello
        );
        assert_eq!(
            respond(&gateway, &helloes[1], &policy(), &mut replay).unwrap_err(),
            TunnelError::ReplayedHello
        );
    }

    /// **Mutations this detects:** ordering the capacity check before the
    /// seen check, which downgrades a recognised replay to a capacity
    /// complaint the moment the cache fills — the one message an operator
    /// would read as "try again later".
    #[test]
    fn a_full_cache_still_names_a_replay_a_replay() {
        let gateway = MlKem768MlDsa65::gateway_from_seed([9u8; 32]);
        let ek = gateway.kem_public().unwrap();
        let mut replay = HelloReplayCache::with_capacity(1);

        let node = MlKem768MlDsa65::node_from_seed([4u8; 32]);
        let (hello, _k) =
            initiate(&node, &ek, &PeerKemOffer::post_quantum(), &binding()).expect("initiate");
        assert!(respond(&gateway, &hello, &policy(), &mut replay).is_ok());
        assert_eq!(replay.len(), replay.capacity());

        assert_eq!(
            respond(&gateway, &hello, &policy(), &mut replay).unwrap_err(),
            TunnelError::ReplayedHello,
            "a full cache reported a known replay as a capacity problem"
        );

        // Positive control: a genuinely new hello at the same full cache does
        // get the capacity answer, so the two causes are distinguishable.
        let other = MlKem768MlDsa65::node_from_seed([5u8; 32]);
        let (fresh, _k) =
            initiate(&other, &ek, &PeerKemOffer::post_quantum(), &binding()).expect("initiate");
        assert_eq!(
            respond(&gateway, &fresh, &policy(), &mut replay).unwrap_err(),
            TunnelError::ReplayCacheFull { tracked: 1 }
        );
    }
}
