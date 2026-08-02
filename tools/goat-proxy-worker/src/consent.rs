//! The consent gate: a signed, timestamped, versioned record naming the exact
//! policy text, the exact destination list, and a **named** operator key.
//!
//! # This is a cryptographic gate, not a modal
//!
//! Without a record that verifies, the sidecar does not start. Not "logs a
//! warning and continues", not "starts with a reduced ceiling": [`load_consent`]
//! and [`verify_consent`] together are a precondition of the startup gate, and
//! every failure is a refusal with a distinct cause.
//!
//! # `expected_wallet` is a PARAMETER, not an option
//!
//! Verification that only checks a record's signature against *the address the
//! record itself names* accepts every self-consistent self-signed blob. Any
//! process running as the operator can generate a throwaway key, sign a record
//! naming that key, and authorise residential egress without the operator ever
//! unlocking a key or reading the disclosure. So the address the supervisor
//! believes is active is a required argument, and the three states stay
//! distinguishable:
//!
//! * [`ConsentError::BadSignature`] — the record does not check out against its
//!   own text;
//! * [`ConsentError::ForeignSigner`] — it checks out, but for somebody else's
//!   key;
//! * `Ok(())` — it checks out for the key the supervisor named.
//!
//! Recovery runs **before** any digest comparison, so a tampered record reads
//! `BadSignature` rather than being presented to the operator as a benign
//! version change.
//!
//! # Consent binds the SCOPE, not just the words
//!
//! [`ConsentRecord::allowlist_digest`] is in the preimage. A swapped destination
//! list invalidates consent, because "the operator agreed to the words" and "the
//! operator agreed to the scope" are different statements and only the second
//! one is worth having.
//!
//! # Consent is a CEILING
//!
//! [`effective_daily_ceiling`] and [`effective_throttle`] return
//! `min(consented, configured)`. Configuration may only lower what the operator
//! signed. This is why the two numbers are inside the signed preimage: a ceiling
//! that lived outside it could be raised by editing a file, and the signature
//! would still verify.
//!
//! # The hex-vs-bytes convention, pinned once
//!
//! The desktop signs `consentMessageHex(fields)` — the `0x`-hex encoding of the
//! UTF-8 preimage — through the wallet's message-signing command. **The EIP-191
//! prefix is applied over the DECODED bytes, never over the hex string**, which
//! is what `recover_address_from_msg(preimage(record).as_bytes())` assumes here.
//! Get it wrong and every operator signature fails; get it *inconsistently*
//! wrong and the desktop accepts a record the sidecar refuses, which is the
//! worse outcome. `fixtures/consent-preimage.json` pins one full record's
//! preimage **bytes** and its keccak so all three implementations assert the
//! same object.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Task 31 and its Security invariants section (INV-8, INV-19); and the
//! "Residential Proxy Network (P3) Implementation Plan", §4.1 (the
//! `CONSENT_TTL_SECS` row).

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use alloy_primitives::Signature;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

/// Ninety days. One constant serves both the age check and the expiry check,
/// because two constants is how the two drift apart.
pub const CONSENT_TTL_SECS: u64 = 7_776_000;

/// The record schema this build understands. A record naming another schema is
/// refused rather than best-effort parsed.
pub const CONSENT_SCHEMA: u32 = 1;

/// The lowest policy version this build accepts.
///
/// Raised whenever the disclosure text changes materially, which re-consents
/// every operator. A record naming an older version is refused: the operator
/// agreed to different words.
pub const MIN_POLICY_VERSION: u32 = 1;

/// Domain separation for the preimage keccak, so the digest of a consent record
/// cannot collide with the digest of anything else this project hashes.
const CONSENT_PREIMAGE_HEADER: &str = "GOAT Residential Proxy Consent Record v1";

/// The signed record.
///
/// **The wallet field is deliberate and is exempted by name from the sweep that
/// bans key-material paths (INV-19).** Consent naming a key is the entire point;
/// what the sidecar must never hold is a *path to* key material, and there is
/// none here — this is an address, which is public.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentRecord {
    pub schema: u32,
    pub policy_version: u32,
    /// Keccak-256 of the exact disclosure text the operator was shown.
    #[serde(with = "hex_bytes32")]
    pub policy_digest: [u8; 32],
    /// The digest of the destination list that was in force when they agreed.
    #[serde(with = "hex_bytes32")]
    pub allowlist_digest: [u8; 32],
    /// The operator's address. Twenty bytes, compared as bytes and never as a
    /// string, so a checksummed spelling and a lower-case one are one key.
    #[serde(with = "hex_bytes20")]
    pub wallet: [u8; 20],
    /// An opaque per-installation identifier. Never a hostname, never a serial
    /// number, never anything that identifies a person.
    pub device_id: String,
    /// The consented daily ceiling, in bytes.
    ///
    /// **Inside the preimage on purpose.** A ceiling that lived outside the
    /// signature could be raised by editing a file while the signature still
    /// verified, and `effective_daily_ceiling`'s "configuration may only lower"
    /// rule would have nothing to compare against.
    pub daily_ceiling_bytes: u64,
    /// The consented throttle, in bytes per second. Inside the preimage for the
    /// same reason as the ceiling.
    pub throttle_bytes_per_sec: u64,
    pub granted_at_unix: u64,
    /// Always `granted_at_unix + CONSENT_TTL_SECS`. A record where it is not is
    /// [`ConsentError::Malformed`] — a stretched expiry is the shape a
    /// hand-edited record takes when somebody wants a longer grant.
    pub expires_at_unix: u64,
    /// EIP-191 `personal_sign` over the DECODED UTF-8 bytes of [`preimage`].
    #[serde(with = "hex_bytes65")]
    pub signature: [u8; 65],
}

/// What the gate concluded, as one value the startup path and the operator
/// surface can both carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentState {
    /// Verified against the expected wallet, the policy text and the list.
    Valid,
    /// Refused, with the cause. The cause never carries a URL, a path or a
    /// header — the whole record is digests, integers and an address.
    Refused(ConsentError),
}

impl ConsentState {
    pub fn is_valid(&self) -> bool {
        matches!(self, ConsentState::Valid)
    }
}

/// Why consent did not verify. Each is a startup refusal.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConsentError {
    #[error("no consent record; the sidecar does not start without one")]
    Absent,
    #[error("the consent record exists and cannot be read: {0}")]
    Unreadable(String),
    #[error("the consent record is malformed: {0}")]
    Malformed(String),
    #[error("the consent record names schema {found}, this build understands {expected}")]
    SchemaMismatch { found: u32, expected: u32 },
    #[error("the consent record names policy version {found}; {expected} or later is required")]
    PolicyVersionTooOld { found: u32, expected: u32 },
    #[error("the consent record names a different disclosure text")]
    PolicyDigestMismatch,
    #[error("the consent record names a different destination list")]
    AllowlistDigestMismatch,
    #[error("the consent record does not check out against its own text")]
    BadSignature,
    #[error("the consent record checks out, but for a key that is not the active operator's")]
    ForeignSigner,
    #[error("the consent record is older than the ninety-day term")]
    Expired,
    #[error("the consent record is dated in the future")]
    NotYetValid,
}

/// The exact bytes the operator's signature is over.
///
/// Line-oriented, `\n`-joined, **no trailing newline**, every value in one
/// canonical spelling: hex is lower case with an `0x` prefix, integers are base
/// ten with no separators. The desktop builds the same string with `.join("\n")`
/// and `tools/goat-proxy-worker/fixtures/consent-preimage.json` pins the bytes,
/// so "we both wrote a `format!` and hoped" is not the integration test.
pub fn preimage(record: &ConsentRecord) -> String {
    [
        CONSENT_PREIMAGE_HEADER.to_string(),
        format!("schema: {}", record.schema),
        format!("policy_version: {}", record.policy_version),
        format!("policy_digest: 0x{}", hex::encode(record.policy_digest)),
        format!(
            "allowlist_digest: 0x{}",
            hex::encode(record.allowlist_digest)
        ),
        format!("wallet: 0x{}", hex::encode(record.wallet)),
        format!("device_id: {}", record.device_id),
        format!("daily_ceiling_bytes: {}", record.daily_ceiling_bytes),
        format!("throttle_bytes_per_sec: {}", record.throttle_bytes_per_sec),
        format!("granted_at_unix: {}", record.granted_at_unix),
        format!("expires_at_unix: {}", record.expires_at_unix),
    ]
    .join("\n")
}

/// Keccak-256 of the preimage bytes. Pinned by the cross-language fixture.
pub fn preimage_digest(record: &ConsentRecord) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(preimage(record).as_bytes());
    h.finalize().into()
}

/// Read a record from disk.
///
/// Absent, unreadable and malformed are three refusals and none of them
/// degrades to a default record.
pub fn load_consent(path: &Path) -> Result<ConsentRecord, ConsentError> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == ErrorKind::NotFound => return Err(ConsentError::Absent),
        Err(e) => return Err(ConsentError::Unreadable(e.kind().to_string())),
    };
    serde_json::from_str(&text).map_err(|e| ConsentError::Malformed(e.to_string()))
}

/// Verify a record against the wallet the supervisor named, the disclosure text
/// the operator was shown, and the list that is loaded.
///
/// **Order is load-bearing** and is the order below:
///
/// 1. structural checks that do not depend on the key (schema, term length);
/// 2. **recover** the signer from the preimage;
/// 3. recovered vs `record.wallet` → [`ConsentError::BadSignature`], so a
///    hand-written file naming the right wallet is a bad signature rather than a
///    mismatch;
/// 4. `record.wallet` vs `expected_wallet` → [`ConsentError::ForeignSigner`], so
///    a valid signature by the wrong key is not `Valid`;
/// 5. the two digests, then the version, then the clock.
pub fn verify_consent(
    record: &ConsentRecord,
    now_unix: u64,
    policy_text_hash: [u8; 32],
    allowlist_digest: [u8; 32],
    expected_wallet: [u8; 20],
) -> Result<(), ConsentError> {
    if record.schema != CONSENT_SCHEMA {
        return Err(ConsentError::SchemaMismatch {
            found: record.schema,
            expected: CONSENT_SCHEMA,
        });
    }

    // A stretched term, checked before the signature because a record whose
    // term is wrong is malformed whether or not the operator signed it -- and
    // the operator's own key signing a 400-day grant is exactly the case a
    // signature check cannot catch.
    if record.expires_at_unix != record.granted_at_unix.saturating_add(CONSENT_TTL_SECS) {
        return Err(ConsentError::Malformed(format!(
            "expires_at - granted_at is {}, and the term is fixed at {CONSENT_TTL_SECS}",
            record
                .expires_at_unix
                .saturating_sub(record.granted_at_unix)
        )));
    }

    // RECOVER FIRST. Everything below this line is a comparison between two
    // values that are already inside the signed text, so reaching any of them
    // means the text has not been altered.
    let signature =
        Signature::from_raw_array(&record.signature).map_err(|_| ConsentError::BadSignature)?;
    let recovered = signature
        .recover_address_from_msg(preimage(record).as_bytes())
        .map_err(|_| ConsentError::BadSignature)?;
    if recovered.as_slice() != record.wallet.as_slice() {
        return Err(ConsentError::BadSignature);
    }
    // Compared on the twenty BYTES, never on a string: a checksummed spelling
    // and a lower-case one name one key, and a string comparison would call them
    // two.
    if record.wallet != expected_wallet {
        return Err(ConsentError::ForeignSigner);
    }

    if record.policy_digest != policy_text_hash {
        return Err(ConsentError::PolicyDigestMismatch);
    }
    if record.allowlist_digest != allowlist_digest {
        return Err(ConsentError::AllowlistDigestMismatch);
    }
    if record.policy_version < MIN_POLICY_VERSION {
        return Err(ConsentError::PolicyVersionTooOld {
            found: record.policy_version,
            expected: MIN_POLICY_VERSION,
        });
    }

    if now_unix < record.granted_at_unix {
        return Err(ConsentError::NotYetValid);
    }
    // The age check and the expiry check are the same constant, and the boundary
    // is inclusive: a record exactly ninety days old is still valid, one second
    // past is not.
    if now_unix > record.expires_at_unix {
        return Err(ConsentError::Expired);
    }

    Ok(())
}

/// Load, verify, and summarise in one value.
pub fn consent_state(
    path: &Path,
    now_unix: u64,
    policy_text_hash: [u8; 32],
    allowlist_digest: [u8; 32],
    expected_wallet: [u8; 20],
) -> ConsentState {
    match load_consent(path) {
        Err(e) => ConsentState::Refused(e),
        Ok(record) => match verify_consent(
            &record,
            now_unix,
            policy_text_hash,
            allowlist_digest,
            expected_wallet,
        ) {
            Ok(()) => ConsentState::Valid,
            Err(e) => ConsentState::Refused(e),
        },
    }
}

/// `min(consented, configured)`. Configuration may only lower.
pub fn effective_daily_ceiling(record: &ConsentRecord, configured: u64) -> u64 {
    record.daily_ceiling_bytes.min(configured)
}

/// `min(consented, configured)`. Configuration may only lower.
pub fn effective_throttle(record: &ConsentRecord, configured: u64) -> u64 {
    record.throttle_bytes_per_sec.min(configured)
}

// ---------------------------------------------------------------------------
// Hex serde helpers
// ---------------------------------------------------------------------------
//
// Fixed-width hex with an `0x` prefix, in and out, so the JSON on disk is the
// same spelling the preimage uses. A `Vec<u8>` field would accept a short value
// and pad it, which would let two different disclosure texts land on one
// accepted record.

macro_rules! hex_array_serde {
    ($module:ident, $n:literal) => {
        mod $module {
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S: Serializer>(v: &[u8; $n], s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&format!("0x{}", hex::encode(v)))
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; $n], D::Error> {
                let raw = String::deserialize(d)?;
                let body = raw.strip_prefix("0x").unwrap_or(&raw);
                if body.len() != $n * 2 {
                    return Err(serde::de::Error::custom(format!(
                        "expected {} bytes of hex, got {}",
                        $n,
                        body.len() / 2
                    )));
                }
                let mut out = [0u8; $n];
                hex::decode_to_slice(body, &mut out).map_err(serde::de::Error::custom)?;
                Ok(out)
            }
        }
    };
}

hex_array_serde!(hex_bytes20, 20);
hex_array_serde!(hex_bytes32, 32);
hex_array_serde!(hex_bytes65, 65);

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    /// A deterministic test key. Production code cannot sign anything — `k256`
    /// is a **dev**-dependency for exactly that reason (INV-19).
    fn key(seed: u8) -> SigningKey {
        let mut bytes = [1u8; 32];
        bytes[31] = seed;
        SigningKey::from_slice(&bytes).expect("a non-zero scalar is a valid key")
    }

    fn address_of(k: &SigningKey) -> [u8; 20] {
        let point = k.verifying_key().to_encoded_point(false);
        let mut h = Keccak256::new();
        // Drop the 0x04 SEC1 tag: the address is keccak over the 64 coordinate
        // bytes.
        h.update(&point.as_bytes()[1..]);
        let digest: [u8; 32] = h.finalize().into();
        let mut out = [0u8; 20];
        out.copy_from_slice(&digest[12..]);
        out
    }

    /// EIP-191 `personal_sign` over the DECODED UTF-8 bytes of the preimage.
    fn sign(k: &SigningKey, message: &[u8]) -> [u8; 65] {
        let mut h = Keccak256::new();
        h.update(format!("\x19Ethereum Signed Message:\n{}", message.len()).as_bytes());
        h.update(message);
        let digest: [u8; 32] = h.finalize().into();
        let (sig, rid) = k
            .sign_prehash_recoverable(&digest)
            .expect("a 32-byte prehash signs");
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = rid.to_byte() + 27;
        out
    }

    const POLICY_HASH: [u8; 32] = [0xAA; 32];
    const LIST_DIGEST: [u8; 32] = [0xBB; 32];
    const GRANTED: u64 = 1_780_000_000;

    fn record_for(k: &SigningKey) -> ConsentRecord {
        let mut r = ConsentRecord {
            schema: CONSENT_SCHEMA,
            policy_version: MIN_POLICY_VERSION,
            policy_digest: POLICY_HASH,
            allowlist_digest: LIST_DIGEST,
            wallet: address_of(k),
            device_id: "device-0001".to_string(),
            daily_ceiling_bytes: 10_737_418_240,
            throttle_bytes_per_sec: 1_250_000,
            granted_at_unix: GRANTED,
            expires_at_unix: GRANTED + CONSENT_TTL_SECS,
            signature: [0u8; 65],
        };
        r.signature = sign(k, preimage(&r).as_bytes());
        r
    }

    fn verify(r: &ConsentRecord, now: u64, expected: [u8; 20]) -> Result<(), ConsentError> {
        verify_consent(r, now, POLICY_HASH, LIST_DIGEST, expected)
    }

    /// THE positive control for every refusal below.
    ///
    /// Mutations this detects: a verifier that refuses everything, against which
    /// every other test in this module would also pass.
    #[test]
    fn a_correctly_signed_record_is_valid() {
        let k = key(1);
        let r = record_for(&k);
        assert_eq!(verify(&r, GRANTED + 1, address_of(&k)), Ok(()));
        // The exact ninety-day boundary is still valid.
        assert_eq!(
            verify(&r, GRANTED + CONSENT_TTL_SECS, address_of(&k)),
            Ok(())
        );
    }

    /// THE dropper case, and the one test that could not be written at all
    /// against a verifier with no expected-wallet parameter.
    ///
    /// Mutations this detects: `expected_wallet` made an `Option` and skipped
    /// when `None`; the comparison written against `recovered` twice, so the
    /// record's own claim about its key is the only thing checked.
    #[test]
    fn consent_signed_by_a_key_that_is_not_the_operator_refuses_start() {
        let operator = key(1);
        let throwaway = key(9);

        // A PERFECTLY VALID, perfectly self-consistent record — signed by a
        // freshly generated key that is not the operator's.
        let forged = record_for(&throwaway);
        assert_eq!(
            verify(&forged, GRANTED + 1, address_of(&throwaway)),
            Ok(()),
            "the forged record really is self-consistent; that is the point"
        );
        assert_eq!(
            verify(&forged, GRANTED + 1, address_of(&operator)),
            Err(ConsentError::ForeignSigner)
        );
    }

    /// Mutations this detects: the wallet comparison run before recovery, under
    /// which a record naming the active wallet and signed by nobody reads as a
    /// benign mismatch instead of a forgery.
    #[test]
    fn consent_gate_refuses_a_forged_record_that_names_the_active_wallet() {
        let operator = key(1);
        let throwaway = key(9);

        // Signed by the throwaway key, but NAMING the operator's address.
        let mut forged = record_for(&throwaway);
        forged.wallet = address_of(&operator);
        // The signature is over the old preimage, so it no longer recovers to
        // the address the record now names.
        assert_eq!(
            verify(&forged, GRANTED + 1, address_of(&operator)),
            Err(ConsentError::BadSignature)
        );

        // Even re-signed by the throwaway over the NEW text, it is a forgery:
        // recovery yields the throwaway, and the record claims the operator.
        forged.signature = sign(&throwaway, preimage(&forged).as_bytes());
        assert_eq!(
            verify(&forged, GRANTED + 1, address_of(&operator)),
            Err(ConsentError::BadSignature)
        );

        // POSITIVE CONTROL: the genuine record still passes.
        let genuine = record_for(&operator);
        assert_eq!(verify(&genuine, GRANTED + 1, address_of(&operator)), Ok(()));
    }

    /// Mutations this detects: `policy_digest` dropped from the preimage, so the
    /// operator's signature no longer binds the words they read.
    #[test]
    fn consent_for_a_different_policy_hash_refuses_start() {
        let k = key(1);
        let r = record_for(&k);
        assert_eq!(
            verify_consent(&r, GRANTED + 1, [0xCC; 32], LIST_DIGEST, address_of(&k)),
            Err(ConsentError::PolicyDigestMismatch)
        );

        // And a record whose OWN digest was edited reads as a bad signature, not
        // as a stale policy: recovery runs first.
        let mut tampered = record_for(&k);
        tampered.policy_digest = [0xCC; 32];
        assert_eq!(
            verify_consent(
                &tampered,
                GRANTED + 1,
                [0xCC; 32],
                LIST_DIGEST,
                address_of(&k)
            ),
            Err(ConsentError::BadSignature)
        );
    }

    /// INV-8's scope half.
    ///
    /// Mutations this detects: `allowlist_digest` dropped from the preimage or
    /// from the comparison, after which swapping the destination list leaves the
    /// operator's consent apparently intact.
    #[test]
    fn consent_gate_refuses_a_record_naming_a_different_allowlist_digest() {
        let k = key(1);
        let r = record_for(&k);
        assert_eq!(
            verify_consent(&r, GRANTED + 1, POLICY_HASH, [0xDD; 32], address_of(&k)),
            Err(ConsentError::AllowlistDigestMismatch)
        );

        // POSITIVE CONTROL: the digest it was signed against still passes.
        assert_eq!(verify(&r, GRANTED + 1, address_of(&k)), Ok(()));
    }

    /// Mutations this detects: `>=` in place of `>` on the expiry comparison,
    /// which retires a record a day early; or the age measured against
    /// `expires_at` alone with no term check, under which a stretched expiry
    /// buys unlimited time.
    #[test]
    fn consent_older_than_ninety_days_refuses_start() {
        let k = key(1);
        let r = record_for(&k);
        let addr = address_of(&k);

        // Exactly ninety days: still valid.
        assert_eq!(verify(&r, GRANTED + CONSENT_TTL_SECS, addr), Ok(()));
        // Ninety days and one second: not.
        assert_eq!(
            verify(&r, GRANTED + CONSENT_TTL_SECS + 1, addr),
            Err(ConsentError::Expired)
        );
        // A clock before the grant is refused too, rather than read as very
        // fresh.
        assert_eq!(
            verify(&r, GRANTED - 1, addr),
            Err(ConsentError::NotYetValid)
        );
    }

    /// Mutations this detects: `expires_at_unix` taken from the record verbatim
    /// with no term check. The operator's own key can sign a four-hundred-day
    /// grant, and a signature check alone cannot tell that from a ninety-day
    /// one.
    #[test]
    fn consent_gate_refuses_a_stretched_expiry() {
        let k = key(1);
        let addr = address_of(&k);

        for stretched in [
            GRANTED + CONSENT_TTL_SECS + 1,
            GRANTED + CONSENT_TTL_SECS * 4,
            GRANTED,
            u64::MAX,
        ] {
            let mut r = record_for(&k);
            r.expires_at_unix = stretched;
            // Re-signed over the stretched text, so this is not a signature
            // failure: it is a well-formed record with a term nobody may choose.
            r.signature = sign(&k, preimage(&r).as_bytes());
            assert!(
                matches!(
                    verify(&r, GRANTED + 1, addr),
                    Err(ConsentError::Malformed(_))
                ),
                "a term of {stretched} was accepted"
            );
        }

        // POSITIVE CONTROL: the fixed term passes.
        assert_eq!(verify(&record_for(&k), GRANTED + 1, addr), Ok(()));
    }

    /// Mutations this detects: `recover_address_from_msg` applied to the HEX
    /// STRING instead of the decoded bytes, which changes the EIP-191 length
    /// prefix and makes every real operator signature fail; and any signature
    /// byte accepted without recovery.
    #[test]
    fn consent_with_foreign_signature_refuses_start() {
        let k = key(1);
        let addr = address_of(&k);

        // A signature over the HEX SPELLING of the preimage rather than over its
        // bytes: the exact convention error the module header pins.
        let mut hex_signed = record_for(&k);
        let hex_form = format!("0x{}", hex::encode(preimage(&hex_signed).as_bytes()));
        hex_signed.signature = sign(&k, hex_form.as_bytes());
        assert_eq!(
            verify(&hex_signed, GRANTED + 1, addr),
            Err(ConsentError::BadSignature),
            "the prefix must be applied over the DECODED bytes"
        );

        for corrupt in [[0u8; 65], [0xFFu8; 65]] {
            let mut r = record_for(&k);
            r.signature = corrupt;
            assert_eq!(
                verify(&r, GRANTED + 1, addr),
                Err(ConsentError::BadSignature)
            );
        }

        // A single flipped byte anywhere in the signature.
        let mut flipped = record_for(&k);
        flipped.signature[3] ^= 0x01;
        assert_eq!(
            verify(&flipped, GRANTED + 1, addr),
            Err(ConsentError::BadSignature)
        );

        // POSITIVE CONTROL: the untouched signature verifies.
        assert_eq!(verify(&record_for(&k), GRANTED + 1, addr), Ok(()));
    }

    /// Mutations this detects: `policy_version` compared with `!=` (which would
    /// refuse a NEWER text the operator has already agreed to) or not compared at
    /// all (which would accept a record for words that have since been replaced).
    #[test]
    fn consent_for_an_older_policy_version_refuses_start() {
        let k = key(1);
        let addr = address_of(&k);

        let mut old = record_for(&k);
        old.policy_version = MIN_POLICY_VERSION.saturating_sub(1);
        old.signature = sign(&k, preimage(&old).as_bytes());
        assert_eq!(
            verify(&old, GRANTED + 1, addr),
            Err(ConsentError::PolicyVersionTooOld {
                found: 0,
                expected: MIN_POLICY_VERSION
            })
        );

        // POSITIVE CONTROL: a newer version is accepted, so this is a floor and
        // not an equality.
        let mut newer = record_for(&k);
        newer.policy_version = MIN_POLICY_VERSION + 5;
        newer.signature = sign(&k, preimage(&newer).as_bytes());
        assert_eq!(verify(&newer, GRANTED + 1, addr), Ok(()));
    }

    /// Mutations this detects: a schema mismatch read as malformed, or not read
    /// at all, which would hand a v2 record to a v1 parser and let the
    /// unrecognised half of it go unchecked.
    #[test]
    fn a_record_naming_another_schema_refuses_start() {
        let k = key(1);
        let mut r = record_for(&k);
        r.schema = CONSENT_SCHEMA + 1;
        r.signature = sign(&k, preimage(&r).as_bytes());
        assert_eq!(
            verify(&r, GRANTED + 1, address_of(&k)),
            Err(ConsentError::SchemaMismatch {
                found: CONSENT_SCHEMA + 1,
                expected: CONSENT_SCHEMA
            })
        );
    }

    /// INV-8's "the app is not trusted to have checked" half, at the file seam.
    ///
    /// Mutations this detects: `load_consent` returning a default record when the
    /// file is absent; `serde(default)` on any field, which would let a record
    /// omit the wallet or the digests and still parse.
    #[test]
    fn absent_consent_record_refuses_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("proxy-consent.json");
        assert_eq!(load_consent(&missing), Err(ConsentError::Absent));
        assert_eq!(
            consent_state(&missing, GRANTED + 1, POLICY_HASH, LIST_DIGEST, [0u8; 20]),
            ConsentState::Refused(ConsentError::Absent)
        );

        for body in [
            "",
            "{}",
            "[]",
            r#"{"schema":1}"#,
            // Every field but the wallet.
            r#"{"schema":1,"policy_version":1,"policy_digest":"0xaa","allowlist_digest":"0xbb","device_id":"d","daily_ceiling_bytes":1,"throttle_bytes_per_sec":1,"granted_at_unix":1,"expires_at_unix":1,"signature":"0x00"}"#,
            // An unknown key: how a renamed field silently defaults.
            r#"{"schema":1,"extra":true}"#,
        ] {
            let path = dir.path().join("bad.json");
            fs::write(&path, body).expect("write");
            assert!(
                matches!(load_consent(&path), Err(ConsentError::Malformed(_))),
                "body {body:?} was not refused"
            );
        }

        // POSITIVE CONTROL: a real record round-trips through the same loader.
        let k = key(1);
        let r = record_for(&k);
        let path = dir.path().join("good.json");
        fs::write(&path, serde_json::to_string_pretty(&r).expect("render")).expect("write");
        assert_eq!(load_consent(&path).expect("loads"), r);
        assert_eq!(
            consent_state(&path, GRANTED + 1, POLICY_HASH, LIST_DIGEST, address_of(&k)),
            ConsentState::Valid
        );
    }

    /// Mutations this detects: `max` in place of `min` in either accessor, which
    /// would let a configuration file raise what the operator signed; or the
    /// ceiling read from configuration alone, ignoring the record.
    #[test]
    fn consent_ceiling_can_only_be_lowered_by_configuration_never_raised() {
        let k = key(1);
        let r = record_for(&k);
        assert_eq!(r.daily_ceiling_bytes, 10_737_418_240);
        assert_eq!(r.throttle_bytes_per_sec, 1_250_000);

        // Configuration below the consented value wins.
        assert_eq!(effective_daily_ceiling(&r, 1_000_000_000), 1_000_000_000);
        assert_eq!(effective_throttle(&r, 500_000), 500_000);

        // Configuration above it does NOT.
        assert_eq!(
            effective_daily_ceiling(&r, u64::MAX),
            r.daily_ceiling_bytes,
            "configuration raised the ceiling the operator signed"
        );
        assert_eq!(
            effective_throttle(&r, u64::MAX),
            r.throttle_bytes_per_sec,
            "configuration raised the throttle the operator signed"
        );

        // Equal values are the identity, so the boundary is not off by one.
        assert_eq!(
            effective_daily_ceiling(&r, r.daily_ceiling_bytes),
            r.daily_ceiling_bytes
        );

        // And the ceiling is INSIDE the signature: editing it invalidates the
        // record rather than raising the cap.
        let mut raised = r.clone();
        raised.daily_ceiling_bytes = 200_000_000_000;
        assert_eq!(
            verify(&raised, GRANTED + 1, address_of(&k)),
            Err(ConsentError::BadSignature)
        );
    }

    /// The cross-language pin.
    ///
    /// Mutations this detects: a trailing newline added to or removed from the
    /// preimage; a field reordered; hex spelled without `0x` or in upper case; a
    /// separator changed from `\n` to `\r\n`. Every one of those still produces a
    /// plausible-looking string and a signature that nothing but this fixture
    /// would catch.
    #[test]
    fn the_consent_preimage_matches_the_cross_language_fixture() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("consent-preimage.json");
        let text = fs::read_to_string(&path).expect("the preimage fixture must exist");
        let fixture: serde_json::Value = serde_json::from_str(&text).expect("fixture parses");

        let record = ConsentRecord {
            schema: fixture["record"]["schema"].as_u64().unwrap() as u32,
            policy_version: fixture["record"]["policy_version"].as_u64().unwrap() as u32,
            policy_digest: hex32(fixture["record"]["policy_digest"].as_str().unwrap()),
            allowlist_digest: hex32(fixture["record"]["allowlist_digest"].as_str().unwrap()),
            wallet: hex20(fixture["record"]["wallet"].as_str().unwrap()),
            device_id: fixture["record"]["device_id"].as_str().unwrap().to_string(),
            daily_ceiling_bytes: fixture["record"]["daily_ceiling_bytes"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            throttle_bytes_per_sec: fixture["record"]["throttle_bytes_per_sec"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            granted_at_unix: fixture["record"]["granted_at_unix"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            expires_at_unix: fixture["record"]["expires_at_unix"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            signature: [0u8; 65],
        };

        let built = preimage(&record);
        let built_hex = format!("0x{}", hex::encode(built.as_bytes()));
        let built_keccak = format!("0x{}", hex::encode(preimage_digest(&record)));

        // Printed so Step 5 of the task can copy them into the fixture the first
        // time, and so a failure shows both sides rather than only "not equal".
        println!("preimage_hex   = {built_hex}");
        println!("preimage_keccak= {built_keccak}");

        assert_eq!(
            built_hex,
            fixture["preimage_hex"].as_str().unwrap(),
            "the preimage BYTES drifted from the cross-language fixture"
        );
        assert_eq!(
            built_keccak,
            fixture["preimage_keccak"].as_str().unwrap(),
            "the preimage keccak drifted from the cross-language fixture"
        );

        // The fixture's term is the shipped term, so a fixture regenerated by
        // hand cannot quietly pin a different one.
        assert_eq!(
            record.expires_at_unix - record.granted_at_unix,
            CONSENT_TTL_SECS
        );

        // POSITIVE CONTROL: the comparison distinguishes two different strings.
        let mut other = record.clone();
        other.device_id.push('x');
        assert_ne!(
            format!("0x{}", hex::encode(preimage(&other).as_bytes())),
            built_hex,
            "the preimage does not depend on its own fields"
        );

        // NO TRAILING NEWLINE, asserted directly as well as through the bytes.
        assert!(!built.ends_with('\n'));
        assert!(!built.contains('\r'));
    }

    /// Step 6's end-to-end run: one record signed through the real signing path
    /// and verified through the real `verify_consent`, so three hand-written
    /// preimages are not three chances to be wrong in the same way.
    ///
    /// Mutations this detects: `preimage` used for signing but a second,
    /// divergent renderer used for verification.
    #[test]
    fn a_record_signed_over_the_real_preimage_verifies_end_to_end() {
        let k = key(7);
        let addr = address_of(&k);
        let mut r = ConsentRecord {
            schema: CONSENT_SCHEMA,
            policy_version: MIN_POLICY_VERSION,
            policy_digest: POLICY_HASH,
            allowlist_digest: LIST_DIGEST,
            wallet: addr,
            device_id: "end-to-end".to_string(),
            daily_ceiling_bytes: 5_000_000_000,
            throttle_bytes_per_sec: 900_000,
            granted_at_unix: GRANTED,
            expires_at_unix: GRANTED + CONSENT_TTL_SECS,
            signature: [0u8; 65],
        };
        r.signature = sign(&k, preimage(&r).as_bytes());

        // Through the file, as the sidecar reads it -- the app is not trusted to
        // have checked.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("proxy-consent.json");
        fs::write(&path, serde_json::to_string(&r).expect("render")).expect("write");

        assert_eq!(
            consent_state(&path, GRANTED + 10, POLICY_HASH, LIST_DIGEST, addr),
            ConsentState::Valid
        );
        // NEGATIVE CONTROL: the same file, a different expected wallet.
        assert_eq!(
            consent_state(&path, GRANTED + 10, POLICY_HASH, LIST_DIGEST, [0u8; 20]),
            ConsentState::Refused(ConsentError::ForeignSigner)
        );
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s.strip_prefix("0x").unwrap_or(s), &mut out).expect("32 bytes of hex");
        out
    }

    fn hex20(s: &str) -> [u8; 20] {
        let mut out = [0u8; 20];
        hex::decode_to_slice(s.strip_prefix("0x").unwrap_or(s), &mut out).expect("20 bytes of hex");
        out
    }
}
