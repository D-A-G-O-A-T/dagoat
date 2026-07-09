//! PQ-authenticated transport (WP-2.1). ML-KEM-768 key encapsulation establishes a shared
//! secret; the initiator authenticates the handshake with its ML-DSA identity; an AES-256-GCM
//! channel then carries framed messages. Device-agnostic — nothing here names a device type.
//!
//! Accessibility note (standing consideration): the transport is intentionally lightweight —
//! one KEM ciphertext (~1088 B) + one ML-DSA signature (~3309 B) per handshake, then symmetric
//! AEAD. No high-end-hardware assumptions; a low-bandwidth node completes a handshake in a
//! few KB. See ACCESSIBILITY.md.
//!
//! In-process transport: nodes exchange handshake objects and framed ciphertext through the
//! in-memory `Network` (below). Over a socket the same bytes would cross the wire; the crypto
//! is identical. This mirrors the accepted MVP-1 in-process approach.

use std::collections::HashMap;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncapsulationKey, MlKem768};
use sha3::{Digest, Sha3_256};

use goat_protocol::commit::commit;
use goat_protocol::maturity::Receipt;
use goat_protocol::pqsign::{verify, AlgId, MlDsaSigner, Signer};
use goat_protocol::provenance::{
    attest_receipt, sub_window_message, SignedReceipt, SubWindowStamp,
};
use goat_protocol::types::TaskResult;

// FIPS 203 ML-KEM-768 sizes (bytes) — for SC10 bandwidth documentation.
pub const ML_KEM_768_EK_BYTES: usize = 1184;
pub const ML_KEM_768_CT_BYTES: usize = 1088;

/// A node's long-lived identity: an ML-DSA signer (authentication) + an ML-KEM decapsulation
/// key (to receive encapsulations). The encapsulation key is the node's published KEM public.
pub struct NodeIdentity {
    pub node_id: String,
    signer: MlDsaSigner,
    dk: ml_kem::DecapsulationKey<MlKem768>,
    ek: EncapsulationKey<MlKem768>,
}

impl NodeIdentity {
    pub fn generate(node_id: &str) -> Self {
        let (dk, ek) = <MlKem768 as ml_kem::kem::Kem>::generate_keypair();
        Self {
            node_id: node_id.to_string(),
            signer: MlDsaSigner::generate(),
            dk,
            ek,
        }
    }

    pub fn sign_pubkey(&self) -> Vec<u8> {
        self.signer.public_key()
    }

    /// Sign a message with this node's ML-DSA identity key (e.g. handshake auth, assignment logs).
    pub fn sign_msg(&self, msg: &[u8]) -> Vec<u8> {
        self.signer.sign(msg)
    }

    /// Executor attestation of the intra-window completion bucket for a task (R-MAT2b). The
    /// executor signs `(task_id, node_id, sub_window)` with its identity key so the bucket
    /// originates at the source; an orchestrator cannot substitute a value without forging this
    /// signature. Encapsulates the identity's private signer.
    pub fn attest_sub_window(&self, task_id: u64, sub_window: u32) -> SubWindowStamp {
        let msg = sub_window_message(task_id, &self.node_id, sub_window);
        SubWindowStamp {
            task_id,
            node_id: self.node_id.clone(),
            sub_window,
            signer_pk: self.signer.public_key(),
            signature: self.signer.sign(&msg),
        }
    }

    /// Executor attestation of a whole receipt core (R-MAT2b step 3): signs the
    /// executor-attributable fields of `receipt` plus a commitment to `result`. The receipt's
    /// `diverged`/`fault` are placeholders here — they are the orchestrator's verification
    /// outcome and are not signed. Encapsulates the identity's private signer.
    pub fn attest_receipt(
        &self,
        task_id: u64,
        receipt: Receipt,
        result: &TaskResult,
    ) -> SignedReceipt {
        attest_receipt(
            &self.signer,
            task_id,
            &self.node_id,
            receipt,
            commit(result),
        )
    }

    /// The node's published ML-KEM encapsulation key (public).
    pub fn kem_public(&self) -> EncapsulationKey<MlKem768> {
        self.ek.clone()
    }
}

/// The initiator's authenticated handshake to a responder.
pub struct Handshake {
    pub initiator_id: String,
    pub initiator_sign_pk: Vec<u8>,
    pub ciphertext: Ciphertext<MlKem768>,
    pub signature: Vec<u8>, // ML-DSA over the KEM ciphertext bytes (authentication)
}

fn derive_session_key(shared_secret: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"goat-net/session/v1");
    h.update(shared_secret);
    let d = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&d);
    k
}

/// An established, encrypted channel (post-handshake). Each endpoint has a role (0=initiator,
/// 1=responder) that separates the two directions' nonce spaces, so a bidirectional channel
/// never reuses a (key, nonce) pair.
pub struct SecureChannel {
    key: [u8; 32],
    role: u8,
    send_ctr: u64,
    peer_id: String,
}

impl SecureChannel {
    pub fn peer(&self) -> &str {
        &self.peer_id
    }

    fn nonce(role: u8, ctr: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[0] = role;
        n[4..].copy_from_slice(&ctr.to_be_bytes());
        n
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> (u64, Vec<u8>) {
        let ctr = self.send_ctr;
        self.send_ctr += 1;
        let cipher = Aes256Gcm::new(&aes_gcm::Key::<Aes256Gcm>::from(self.key));
        let nonce: Nonce<_> = Self::nonce(self.role, ctr).into();
        let ct = cipher.encrypt(&nonce, plaintext).expect("seal");
        (ctr, ct)
    }

    /// Open a message from the peer (the opposite role's nonce space).
    pub fn open(&self, ctr: u64, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let cipher = Aes256Gcm::new(&aes_gcm::Key::<Aes256Gcm>::from(self.key));
        let nonce: Nonce<_> = Self::nonce(1 - self.role, ctr).into();
        cipher.decrypt(&nonce, ciphertext).ok()
    }
}

/// Initiator side: encapsulate to the responder's KEM public, authenticate with ML-DSA.
pub fn initiate(
    initiator: &NodeIdentity,
    responder_kem_public: &EncapsulationKey<MlKem768>,
) -> (Handshake, SecureChannel) {
    let (ct, shared) = responder_kem_public.encapsulate();
    let sig = initiator.signer.sign(ct.as_ref());
    let key = derive_session_key(&shared[..32]);
    let hs = Handshake {
        initiator_id: initiator.node_id.clone(),
        initiator_sign_pk: initiator.sign_pubkey(),
        ciphertext: ct,
        signature: sig,
    };
    let chan = SecureChannel {
        key,
        role: 0,
        send_ctr: 0,
        peer_id: String::new(),
    };
    (hs, chan)
}

#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeError {
    BadSignature,
}

/// Responder side: verify the initiator's ML-DSA signature over the ciphertext (authentication),
/// then decapsulate to recover the same shared secret.
pub fn respond(responder: &NodeIdentity, hs: &Handshake) -> Result<SecureChannel, HandshakeError> {
    if !verify(
        AlgId::MlDsa65,
        &hs.initiator_sign_pk,
        hs.ciphertext.as_ref(),
        &hs.signature,
    ) {
        return Err(HandshakeError::BadSignature);
    }
    let shared = responder.dk.decapsulate(&hs.ciphertext);
    let key = derive_session_key(&shared[..32]);
    Ok(SecureChannel {
        key,
        role: 1,
        send_ctr: 0,
        peer_id: hs.initiator_id.clone(),
    })
}

/// In-process message bus standing in for sockets. Delivers framed ciphertext between nodes.
/// The transport does not decrypt — only the endpoints hold the session key.
#[derive(Default)]
pub struct Network {
    queues: HashMap<String, Vec<Frame>>,
}

#[derive(Clone)]
pub struct Frame {
    pub from: String,
    pub to: String,
    pub ctr: u64,
    pub ciphertext: Vec<u8>,
}

impl Network {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn send(&mut self, frame: Frame) {
        self.queues.entry(frame.to.clone()).or_default().push(frame);
    }
    pub fn drain(&mut self, node: &str) -> Vec<Frame> {
        self.queues.remove(node).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_handshake_and_encrypted_roundtrip() {
        let alice = NodeIdentity::generate("alice");
        let bob = NodeIdentity::generate("bob");
        let (hs, mut a_chan) = initiate(&alice, &bob.kem_public());
        assert_eq!(hs.ciphertext.len(), ML_KEM_768_CT_BYTES); // SC10 realistic size
        let b_chan = respond(&bob, &hs).expect("handshake");
        let (ctr, sealed) = a_chan.seal(b"cross-class task");
        assert_eq!(
            b_chan.open(ctr, &sealed).as_deref(),
            Some(b"cross-class task".as_ref())
        );
    }

    #[test]
    fn tampered_handshake_signature_rejected() {
        let alice = NodeIdentity::generate("alice");
        let bob = NodeIdentity::generate("bob");
        let mallory = NodeIdentity::generate("mallory");
        let (mut hs, _) = initiate(&alice, &bob.kem_public());
        hs.initiator_sign_pk = mallory.sign_pubkey(); // claim to be someone else
        assert!(matches!(
            respond(&bob, &hs),
            Err(HandshakeError::BadSignature)
        ));
    }

    #[test]
    fn wrong_key_cannot_open() {
        let alice = NodeIdentity::generate("alice");
        let bob = NodeIdentity::generate("bob");
        let carol = NodeIdentity::generate("carol");
        let (hs, mut a_chan) = initiate(&alice, &bob.kem_public());
        let _ = respond(&bob, &hs).unwrap();
        // carol establishes her own channel; it must not open alice->bob traffic
        let (hs2, _) = initiate(&alice, &carol.kem_public());
        let c_chan = respond(&carol, &hs2).unwrap();
        let (ctr, sealed) = a_chan.seal(b"secret");
        assert!(c_chan.open(ctr, &sealed).is_none());
    }
}
