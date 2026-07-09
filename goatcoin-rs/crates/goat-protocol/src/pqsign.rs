//! Post-quantum signatures (device-agnostic). WP-0.2.
//!
//! Production ML-DSA-65 (FIPS 204) via the RustCrypto `ml-dsa` crate, behind an
//! algorithm-agnostic `Signer` / `verify` interface. The Ed25519 reference stand-in used
//! during the Python reference (R-CAP1) is GONE — this is a genuine post-quantum signer.
//! The wire format length-prefixes signatures and public keys, so the algorithm's byte
//! sizes (pubkey 1952 B, sig 3309 B) are irrelevant to serialization.

use ml_dsa::signature::{Signer as _, Verifier as _};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Generate, Keypair as _, MlDsa65, Signature, SigningKey,
    VerifyingKey,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlgId {
    MlDsa65,
}

impl AlgId {
    pub fn as_u16(self) -> u16 {
        match self {
            AlgId::MlDsa65 => 1,
        }
    }
}

/// ML-DSA-65 sizes (FIPS 204). Asserted by tests against the live crate.
pub const ML_DSA_65_PUBKEY_BYTES: usize = 1952;
pub const ML_DSA_65_SIG_BYTES: usize = 3309;

/// Algorithm-agnostic signing surface used by the protocol.
pub trait Signer {
    fn alg_id(&self) -> AlgId;
    fn public_key(&self) -> Vec<u8>;
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
}

/// Verify with ONLY the public key, dispatched by algorithm.
pub fn verify(alg: AlgId, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match alg {
        AlgId::MlDsa65 => {
            let enc_vk = match EncodedVerifyingKey::<MlDsa65>::try_from(pubkey) {
                Ok(e) => e,
                Err(_) => return false,
            };
            let vk = VerifyingKey::<MlDsa65>::decode(&enc_vk);
            let enc_sig = match EncodedSignature::<MlDsa65>::try_from(sig) {
                Ok(e) => e,
                Err(_) => return false,
            };
            let signature = match Signature::<MlDsa65>::decode(&enc_sig) {
                Some(s) => s,
                None => return false,
            };
            vk.verify(msg, &signature).is_ok()
        }
    }
}

/// Real ML-DSA-65 signer.
pub struct MlDsaSigner {
    sk: SigningKey<MlDsa65>,
}

impl MlDsaSigner {
    pub fn generate() -> Self {
        Self {
            sk: SigningKey::<MlDsa65>::generate(),
        }
    }
}

impl Signer for MlDsaSigner {
    fn alg_id(&self) -> AlgId {
        AlgId::MlDsa65
    }
    fn public_key(&self) -> Vec<u8> {
        let vk: VerifyingKey<MlDsa65> = self.sk.verifying_key();
        vk.encode().as_slice().to_vec()
    }
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let sig: Signature<MlDsa65> = self.sk.sign(msg);
        sig.encode().as_slice().to_vec()
    }
}
