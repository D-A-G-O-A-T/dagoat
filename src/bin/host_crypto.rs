//! Host-side (std) post-quantum crypto backends for `goatd`.
//!
//! Implements the frozen core traits without changing their signatures (DEPLOY.md C-1):
//! - [`SecureChannel`] ← real AES-256-GCM with disjoint TX/RX nonce spaces (role bit)
//! - [`SignatureVerifier`] ← real ML-DSA-65 (FIPS 204) via `ml-dsa`
//! - Session key ← ML-KEM-768 encapsulate/decapsulate + SHA3-256 domain-separated KDF
//!
//! Source of truth for algorithm choice: `goatcoin-rs` C3 (`pqsign`, `goat-net::transport`).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use ml_dsa::signature::{Signer as _, Verifier as _};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair as _, MlDsa65, Signature, SigningKey,
    VerifyingKey, B32,
};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport};
use ml_kem::{Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768};
use sha3::{Digest, Sha3_256};

use goat_core::crypto::SignatureVerifier;
use goat_core::transport::{
    SecureChannel, TransportError, AES_256_GCM_TAG_LEN, ML_KEM_768_CIPHERTEXT_LEN,
    ML_KEM_768_ENCAPS_KEY_LEN, ML_KEM_768_SHARED_SECRET_LEN,
};
use goat_core::types::{ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN};

// ===========================================================================
// Roles — disjoint AES-GCM nonce spaces (§17)
// ===========================================================================

/// Session role for nonce separation. Initiator = 0, responder = 1.
/// Encrypt uses `role`; decrypt uses `1 - role` (peer's space).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelRole {
    Initiator = 0,
    Responder = 1,
}

impl ChannelRole {
    #[inline]
    fn byte(self) -> u8 {
        self as u8
    }
    #[inline]
    fn peer(self) -> Self {
        match self {
            ChannelRole::Initiator => ChannelRole::Responder,
            ChannelRole::Responder => ChannelRole::Initiator,
        }
    }
}

// ===========================================================================
// AES-256-GCM secure channel
// ===========================================================================

/// Production AES-256-GCM channel behind the frozen [`SecureChannel`] trait.
///
/// Wire frame is still `ciphertext ‖ tag` (no explicit nonce); counters advance in lockstep.
/// Nonce = `[role ‖ 0×3 ‖ ctr_be_u64]` — TX and RX never share a (key, nonce) pair.
pub struct Aes256GcmChannel {
    cipher: Aes256Gcm,
    role: ChannelRole,
    tx_nonce: u64,
    rx_nonce: u64,
}

impl Aes256GcmChannel {
    pub fn new(key: [u8; ML_KEM_768_SHARED_SECRET_LEN], role: ChannelRole) -> Self {
        Self {
            cipher: Aes256Gcm::new((&key).into()),
            role,
            tx_nonce: 0,
            rx_nonce: 0,
        }
    }

    /// Keyless scratch channel (decrypt expected to fail) — still a valid cipher object.
    pub fn scratch() -> Self {
        Self::new([0u8; 32], ChannelRole::Initiator)
    }

    #[inline]
    fn make_nonce(role: ChannelRole, ctr: u64) -> Nonce<aes_gcm::aes::cipher::typenum::U12> {
        let mut n = [0u8; 12];
        n[0] = role.byte();
        n[4..].copy_from_slice(&ctr.to_be_bytes());
        n.into()
    }
}

impl SecureChannel for Aes256GcmChannel {
    fn encrypt_frame(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, TransportError> {
        let n = plaintext
            .len()
            .checked_add(AES_256_GCM_TAG_LEN)
            .ok_or(TransportError::BufferTooSmall)?;
        if out.len() < n {
            return Err(TransportError::BufferTooSmall);
        }
        let nonce = Self::make_nonce(self.role, self.tx_nonce);
        let ct = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| TransportError::DecryptionFailed)?;
        // aes-gcm returns ciphertext ‖ tag
        if ct.len() != n {
            return Err(TransportError::DecryptionFailed);
        }
        out[..n].copy_from_slice(&ct);
        self.tx_nonce = self
            .tx_nonce
            .checked_add(1)
            .ok_or(TransportError::NonceExhausted)?;
        Ok(n)
    }

    fn decrypt_frame(&mut self, frame: &[u8], out: &mut [u8]) -> Result<usize, TransportError> {
        if frame.len() < AES_256_GCM_TAG_LEN {
            return Err(TransportError::DecryptionFailed);
        }
        let pt_len = frame.len() - AES_256_GCM_TAG_LEN;
        if out.len() < pt_len {
            return Err(TransportError::BufferTooSmall);
        }
        let nonce = Self::make_nonce(self.role.peer(), self.rx_nonce);
        let pt = self
            .cipher
            .decrypt(&nonce, frame)
            .map_err(|_| TransportError::DecryptionFailed)?;
        out[..pt.len()].copy_from_slice(&pt);
        self.rx_nonce = self
            .rx_nonce
            .checked_add(1)
            .ok_or(TransportError::NonceExhausted)?;
        Ok(pt.len())
    }
}

// ===========================================================================
// ML-DSA-65
// ===========================================================================

/// Real ML-DSA-65 verifier (FIPS 204) — frozen [`SignatureVerifier`] surface.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostMlDsaVerifier;

impl SignatureVerifier for HostMlDsaVerifier {
    fn verify_ml_dsa_65(
        &self,
        public_key: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
        message: &[u8],
        signature: &[u8; ML_DSA_65_SIGNATURE_LEN],
    ) -> bool {
        let enc_vk = match EncodedVerifyingKey::<MlDsa65>::try_from(public_key.as_slice()) {
            Ok(e) => e,
            Err(_) => return false,
        };
        let vk = VerifyingKey::<MlDsa65>::decode(&enc_vk);
        let enc_sig = match EncodedSignature::<MlDsa65>::try_from(signature.as_slice()) {
            Ok(e) => e,
            Err(_) => return false,
        };
        let sig = match Signature::<MlDsa65>::decode(&enc_sig) {
            Some(s) => s,
            None => return false,
        };
        vk.verify(message, &sig).is_ok()
    }
}

/// Daemon-side ML-DSA-65 signer (secret held only at the edge; core only verifies).
pub struct HostMlDsaSigner {
    sk: SigningKey<MlDsa65>,
}

impl HostMlDsaSigner {
    /// Deterministic key from a 32-byte seed (testnet / compose / tests).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed_arr = B32::try_from(&seed[..]).expect("seed is 32 bytes");
        Self {
            sk: SigningKey::<MlDsa65>::from_seed(&seed_arr),
        }
    }

    pub fn public_key(&self) -> [u8; ML_DSA_65_PUBLIC_KEY_LEN] {
        let vk: VerifyingKey<MlDsa65> = self.sk.verifying_key();
        let enc = vk.encode();
        let mut out = [0u8; ML_DSA_65_PUBLIC_KEY_LEN];
        out.copy_from_slice(enc.as_slice());
        out
    }

    pub fn sign_ml_dsa_65(&self, message: &[u8]) -> [u8; ML_DSA_65_SIGNATURE_LEN] {
        let sig: Signature<MlDsa65> = self.sk.sign(message);
        let enc = sig.encode();
        let mut out = [0u8; ML_DSA_65_SIGNATURE_LEN];
        out.copy_from_slice(enc.as_slice());
        out
    }
}

// ===========================================================================
// ML-KEM-768 + session KDF
// ===========================================================================

/// Ephemeral ML-KEM-768 keypair for a handshake initiator.
pub struct EphemeralKem {
    pub dk: DecapsulationKey<MlKem768>,
    pub ek_bytes: [u8; ML_KEM_768_ENCAPS_KEY_LEN],
}

pub fn generate_ephemeral_kem() -> EphemeralKem {
    let (dk, ek) = MlKem768::generate_keypair();
    let ek_arr = ek.to_bytes();
    let mut ek_bytes = [0u8; ML_KEM_768_ENCAPS_KEY_LEN];
    ek_bytes.copy_from_slice(ek_arr.as_slice());
    EphemeralKem { dk, ek_bytes }
}

/// Responder: encapsulate to the initiator's ephemeral encapsulation key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KemError {
    InvalidKey,
    InvalidCiphertext,
}

pub fn kem_encapsulate(
    ek_bytes: &[u8; ML_KEM_768_ENCAPS_KEY_LEN],
) -> Result<
    (
        [u8; ML_KEM_768_CIPHERTEXT_LEN],
        [u8; ML_KEM_768_SHARED_SECRET_LEN],
    ),
    KemError,
> {
    let key = ml_kem::Key::<EncapsulationKey<MlKem768>>::try_from(ek_bytes.as_slice())
        .map_err(|_| KemError::InvalidKey)?;
    let ek = EncapsulationKey::<MlKem768>::new(&key).map_err(|_| KemError::InvalidKey)?;
    let (ct, shared) = ek.encapsulate();
    let mut ct_bytes = [0u8; ML_KEM_768_CIPHERTEXT_LEN];
    ct_bytes.copy_from_slice(ct.as_ref());
    let mut ss = [0u8; ML_KEM_768_SHARED_SECRET_LEN];
    ss.copy_from_slice(shared.as_ref());
    Ok((ct_bytes, ss))
}

/// Initiator: decapsulate the responder's ciphertext with the ephemeral decapsulation key.
pub fn kem_decapsulate(
    dk: &DecapsulationKey<MlKem768>,
    ct_bytes: &[u8; ML_KEM_768_CIPHERTEXT_LEN],
) -> Result<[u8; ML_KEM_768_SHARED_SECRET_LEN], KemError> {
    let ct = Ciphertext::<MlKem768>::try_from(ct_bytes.as_slice())
        .map_err(|_| KemError::InvalidCiphertext)?;
    let shared = dk.decapsulate(&ct);
    let mut out = [0u8; ML_KEM_768_SHARED_SECRET_LEN];
    out.copy_from_slice(shared.as_ref());
    Ok(out)
}

/// Domain-separated session KDF (matches goat-net spirit; distinct domain string for goatd wire).
pub fn derive_session_key(shared_secret: &[u8; ML_KEM_768_SHARED_SECRET_LEN]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"GOAT/v1/session\x01");
    h.update(shared_secret);
    let d = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&d);
    k
}

/// Fixed testnet signing seed for orchestrator index `i` (0..4). Documented as **dev-only**.
pub fn testnet_signing_seed(node_index: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 0x60;
    s[1] = 0xA7;
    s[2] = 0x7E;
    s[3] = 0x57; // echoes testnet chain id bytes
    s[4] = node_index;
    s[31] = 0xC1; // "compose identity"
    s
}
