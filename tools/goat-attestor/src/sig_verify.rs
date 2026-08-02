//! Off-chain EIP-712 Bind / Enroll signature recovery (H1).
//!
//! Matches `WorkerBinding` / `EnrollmentRegistry` domains and TYPEHASHes so a
//! garbage signature is rejected before any gas is spent on-chain.

use alloy::primitives::{Address, Signature, B256};
use thiserror::Error;

use crate::merkle::keccak256;

// TYPEHASHes computed via pure keccak (tiny-keccak) — no hard-coded digests.
fn eip712_domain_typehash() -> [u8; 32] {
    keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
}

fn bind_typehash() -> [u8; 32] {
    keccak256(b"Bind(address wallet,string username,uint256 nonce,uint256 deadline)")
}

fn enroll_typehash() -> [u8; 32] {
    keccak256(b"Enroll(address wallet,uint256 nonce,uint256 deadline)")
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SigError {
    #[error("BadSignature: malformed signature hex or length")]
    Malformed,
    #[error("BadSignature: ecrecover failed")]
    RecoverFailed,
    #[error("BadSignature: signer mismatch expected={expected} got={got}")]
    SignerMismatch { expected: String, got: String },
    #[error("BadSignature: bad wallet address")]
    BadWallet,
}

/// Verify an EIP-712 Bind signature recovers to `wallet_hex`.
pub fn verify_bind_sig(
    wallet_hex: &str,
    username: &str,
    nonce: u64,
    deadline: u64,
    chain_id: u64,
    verifying_contract: [u8; 20],
    signature_hex: &str,
) -> Result<(), SigError> {
    let wallet = parse_wallet20(wallet_hex)?;
    let digest = bind_digest(
        wallet,
        username,
        nonce,
        deadline,
        chain_id,
        verifying_contract,
    );
    recover_and_match(wallet, wallet_hex, &digest, signature_hex)
}

/// Verify an EIP-712 Enroll signature recovers to `wallet_hex`.
pub fn verify_enroll_sig(
    wallet_hex: &str,
    nonce: u64,
    deadline: u64,
    chain_id: u64,
    verifying_contract: [u8; 20],
    signature_hex: &str,
) -> Result<(), SigError> {
    let wallet = parse_wallet20(wallet_hex)?;
    let digest = enroll_digest(wallet, nonce, deadline, chain_id, verifying_contract);
    recover_and_match(wallet, wallet_hex, &digest, signature_hex)
}

/// Public for tests / debug: Bind EIP-712 digest (32 bytes).
pub fn bind_digest(
    wallet: [u8; 20],
    username: &str,
    nonce: u64,
    deadline: u64,
    chain_id: u64,
    verifying_contract: [u8; 20],
) -> [u8; 32] {
    let domain = domain_separator("GoatWorkerBinding", "1", chain_id, verifying_contract);
    let mut struct_buf = Vec::with_capacity(32 * 5);
    struct_buf.extend_from_slice(&bind_typehash());
    struct_buf.extend_from_slice(&address_word(&wallet));
    struct_buf.extend_from_slice(&keccak256(username.as_bytes()));
    struct_buf.extend_from_slice(&u256_be(nonce as u128));
    struct_buf.extend_from_slice(&u256_be(deadline as u128));
    let struct_hash = keccak256(&struct_buf);
    eip712_digest(&domain, &struct_hash)
}

/// Public for tests / debug: Enroll EIP-712 digest (32 bytes).
pub fn enroll_digest(
    wallet: [u8; 20],
    nonce: u64,
    deadline: u64,
    chain_id: u64,
    verifying_contract: [u8; 20],
) -> [u8; 32] {
    let domain = domain_separator("GoatEnrollmentRegistry", "1", chain_id, verifying_contract);
    let mut struct_buf = Vec::with_capacity(32 * 4);
    struct_buf.extend_from_slice(&enroll_typehash());
    struct_buf.extend_from_slice(&address_word(&wallet));
    struct_buf.extend_from_slice(&u256_be(nonce as u128));
    struct_buf.extend_from_slice(&u256_be(deadline as u128));
    let struct_hash = keccak256(&struct_buf);
    eip712_digest(&domain, &struct_hash)
}

/// EIP-712 domain separator. `pub(crate)`, not `pub`: the fetch-network lane
/// (`crate::proxy::receipt`) signs under its own domain and must not grow a
/// second implementation of this, but nothing outside the crate needs it.
pub(crate) fn domain_separator(
    name: &str,
    version: &str,
    chain_id: u64,
    verifying: [u8; 20],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 5);
    buf.extend_from_slice(&eip712_domain_typehash());
    buf.extend_from_slice(&keccak256(name.as_bytes()));
    buf.extend_from_slice(&keccak256(version.as_bytes()));
    buf.extend_from_slice(&u256_be(chain_id as u128));
    buf.extend_from_slice(&address_word(&verifying));
    keccak256(&buf)
}

/// `keccak256(0x19 0x01 || domainSeparator || structHash)`. `pub(crate)` for the
/// same reason as [`domain_separator`].
pub(crate) fn eip712_digest(domain: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 66];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(domain);
    buf[34..66].copy_from_slice(struct_hash);
    keccak256(&buf)
}

/// Recover the address that signed `digest`, from a raw 65-byte `r‖s‖v`
/// signature.
///
/// **This is the crate's ONE secp256k1 recovery path**, and every caller goes
/// through it: [`recover_and_match`] below (the hex-string, expected-wallet
/// shape the Bind/Enroll relayer wants) and `crate::proxy::verify` (which
/// recovers three different parties against three different digests and cannot
/// use the expected-wallet shape, because two of the three expected signers are
/// looked up *from* the recovered value's context). Growing a second
/// `recover_address_from_prehash` call site elsewhere in the crate would mean
/// two places for the `v`-normalisation rule to be wrong.
///
/// `v` is accepted as `27`/`28` or `0`/`1` — alloy's `Signature` normalises
/// both, which `v_parity_0_1_also_accepted_when_normalized` pins.
pub(crate) fn recover_signer(digest: &[u8; 32], signature: &[u8]) -> Result<[u8; 20], SigError> {
    if signature.len() != 65 {
        return Err(SigError::Malformed);
    }
    let sig = Signature::try_from(signature).map_err(|_| SigError::Malformed)?;
    let prehash = B256::from_slice(digest);
    let recovered: Address = sig
        .recover_address_from_prehash(&prehash)
        .map_err(|_| SigError::RecoverFailed)?;
    Ok(recovered.into_array())
}

fn recover_and_match(
    wallet: [u8; 20],
    wallet_hex: &str,
    digest: &[u8; 32],
    signature_hex: &str,
) -> Result<(), SigError> {
    let sig_bytes = decode_sig65(signature_hex)?;
    let got = recover_signer(digest, &sig_bytes)?;
    if got != wallet {
        return Err(SigError::SignerMismatch {
            expected: normalize_wallet_hex(wallet_hex),
            got: format!("0x{}", hex::encode(got)),
        });
    }
    Ok(())
}

fn decode_sig65(sig: &str) -> Result<Vec<u8>, SigError> {
    let h = sig
        .strip_prefix("0x")
        .or_else(|| sig.strip_prefix("0X"))
        .unwrap_or(sig);
    if h.is_empty() {
        return Err(SigError::Malformed);
    }
    let bytes = hex::decode(h).map_err(|_| SigError::Malformed)?;
    if bytes.len() != 65 {
        return Err(SigError::Malformed);
    }
    Ok(bytes)
}

fn parse_wallet20(s: &str) -> Result<[u8; 20], SigError> {
    let s = s.trim();
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if hex.len() != 40 {
        return Err(SigError::BadWallet);
    }
    let bytes = hex::decode(hex).map_err(|_| SigError::BadWallet)?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn normalize_wallet_hex(s: &str) -> String {
    let s = s.trim();
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    format!("0x{}", hex.to_ascii_lowercase())
}

/// An address left-padded into one 32-byte word. `pub(crate)` alongside the
/// three helpers above, for the same reason: the alternative is a fifth private
/// copy of a four-line left-pad.
pub(crate) fn address_word(wallet: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(wallet);
    w
}

/// A `uint256` word, big-endian and right-aligned.
///
/// **This is the canonical `u256_be` for the crate**, and the one every
/// fetch-network module imports. Four other private copies exist
/// (`chain.rs:880`, `stream_g/base_fee.rs:295`,
/// `stream_g/root_authorization.rs:491`, and a `pub(crate)` one at
/// `stream_g/models.rs:299`); deduplicating those is a separate change and is
/// deliberately not done here.
pub(crate) fn u256_be(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use std::str::FromStr;

    /// Anvil account #0 — same key as contracts/Eip712DesktopParity.t.sol.
    const ANVIL0_PK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const ANVIL0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const VERIFY_BIND: [u8; 20] = [0x11; 20];
    const VERIFY_ENROLL: [u8; 20] = [0x22; 20];
    const CHAIN_ID: u64 = 31337;

    fn signer() -> PrivateKeySigner {
        PrivateKeySigner::from_str(ANVIL0_PK).unwrap()
    }

    fn sign_digest(digest: [u8; 32]) -> String {
        let s = signer();
        let sig = s.sign_hash_sync(&B256::from(digest)).unwrap();
        format!("0x{}", hex::encode(sig.as_bytes()))
    }

    #[test]
    fn bind_good_path() {
        let wallet = parse_wallet20(ANVIL0).unwrap();
        let username = "GOAT-alice";
        let nonce = 0u64;
        let deadline = 2_000_000_000u64;
        let digest = bind_digest(wallet, username, nonce, deadline, CHAIN_ID, VERIFY_BIND);
        // Pinned viem digest from Eip712DesktopParity.t.sol
        let pinned =
            hex::decode("6760436048cb4918b0cd773e2c2db5f6bb28c3b8fb7cf34f215da680806cdfa2")
                .unwrap();
        assert_eq!(
            digest.as_slice(),
            pinned.as_slice(),
            "Bind digest must match viem/forge pin"
        );

        let sig = sign_digest(digest);
        verify_bind_sig(
            ANVIL0,
            username,
            nonce,
            deadline,
            CHAIN_ID,
            VERIFY_BIND,
            &sig,
        )
        .unwrap();
    }

    #[test]
    fn enroll_good_path() {
        let wallet = parse_wallet20(ANVIL0).unwrap();
        let nonce = 0u64;
        let deadline = 2_000_000_000u64;
        let digest = enroll_digest(wallet, nonce, deadline, CHAIN_ID, VERIFY_ENROLL);
        let pinned =
            hex::decode("c815623fc9a5e16ee135627955085cd554d7a678a970dd8e97297b17f629c1e7")
                .unwrap();
        assert_eq!(
            digest.as_slice(),
            pinned.as_slice(),
            "Enroll digest must match viem/forge pin"
        );

        let sig = sign_digest(digest);
        verify_enroll_sig(ANVIL0, nonce, deadline, CHAIN_ID, VERIFY_ENROLL, &sig).unwrap();
    }

    #[test]
    fn bind_wrong_wallet_rejects() {
        let other = "0x00000000000000000000000000000000000000a1";
        // Attacker signs a Bind struct that claims `other` as the wallet, but
        // the recovered signer is ANVIL0 ≠ other → SignerMismatch.
        let digest_other = bind_digest(
            parse_wallet20(other).unwrap(),
            "GOAT-alice",
            0,
            2_000_000_000,
            CHAIN_ID,
            VERIFY_BIND,
        );
        let sig = sign_digest(digest_other);
        let err = verify_bind_sig(
            other,
            "GOAT-alice",
            0,
            2_000_000_000,
            CHAIN_ID,
            VERIFY_BIND,
            &sig,
        )
        .unwrap_err();
        assert!(
            matches!(err, SigError::SignerMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn garbage_hex_rejects() {
        let err = verify_bind_sig(
            ANVIL0,
            "GOAT-alice",
            0,
            1,
            CHAIN_ID,
            VERIFY_BIND,
            "0xdeadbeef",
        )
        .unwrap_err();
        assert_eq!(err, SigError::Malformed);

        let err = verify_enroll_sig(ANVIL0, 0, 1, CHAIN_ID, VERIFY_ENROLL, "not-hex").unwrap_err();
        assert_eq!(err, SigError::Malformed);
    }

    #[test]
    fn empty_sig_rejects() {
        assert_eq!(
            verify_bind_sig(ANVIL0, "GOAT-alice", 0, 1, CHAIN_ID, VERIFY_BIND, "").unwrap_err(),
            SigError::Malformed
        );
        assert_eq!(
            verify_enroll_sig(ANVIL0, 0, 1, CHAIN_ID, VERIFY_ENROLL, "0x").unwrap_err(),
            SigError::Malformed
        );
    }

    #[test]
    fn pinned_viem_bind_sig_recovers() {
        // BIND_SIG from Eip712DesktopParity.t.sol (signed by anvil#0 over BIND_DIGEST).
        let sig = "0x5519983078728025bbcbdd0a213cf4a1545bfa71a48e86552a9c2be2802927f343e7b82e6a3a974e6dff2139e28e6d9eb270c59cd3dbf45c7ff2a72cb16dd7a61c";
        verify_bind_sig(
            ANVIL0,
            "GOAT-alice",
            0,
            2_000_000_000,
            CHAIN_ID,
            VERIFY_BIND,
            sig,
        )
        .unwrap();
    }

    #[test]
    fn v_parity_0_1_also_accepted_when_normalized() {
        // alloy Signature::from_raw normalizes v 27/28 and 0/1.
        let wallet = parse_wallet20(ANVIL0).unwrap();
        let digest = bind_digest(wallet, "GOAT-bob", 1, 9_999_999_999, CHAIN_ID, VERIFY_BIND);
        let mut bytes = {
            let s = signer();
            s.sign_hash_sync(&B256::from(digest))
                .unwrap()
                .as_bytes()
                .to_vec()
        };
        // Force v into 0/1 range if it was 27/28.
        if bytes[64] >= 27 {
            bytes[64] -= 27;
        }
        let sig = format!("0x{}", hex::encode(&bytes));
        verify_bind_sig(
            ANVIL0,
            "GOAT-bob",
            1,
            9_999_999_999,
            CHAIN_ID,
            VERIFY_BIND,
            &sig,
        )
        .unwrap();
    }
}
