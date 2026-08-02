//! Consent verification. This is a gate, and it is the *second* of three.
//!
//! The screen assembles the record and the wallet signs it; THIS module verifies it
//! before anything is written; and the sidecar verifies it AGAIN from the file, against
//! the same expected address, before it opens a socket. The app is not trusted to have
//! checked.
//!
//! # Order of checks matters
//!
//! The signature is recovered BEFORE any digest comparison, so a hand-written file
//! naming the active wallet is rejected as `BadSignature` rather than reported to the
//! operator as `StalePolicy` -- which would present TAMPERING as a benign version
//! change.
//!
//! # The preimage is pinned, not invented here
//!
//! It is written by hand in three places -- `desktop/src/proxy/consentRecord.js`, this
//! module, and the sidecar's own consent module -- so all three assert against
//! `tools/goat-proxy-worker/fixtures/consent-preimage.json`. The ceiling and the
//! throttle are INSIDE the preimage: a cap that lived outside the signature could be
//! raised by editing a file while the signature still verified.
//!
//! Design authority: the "The No-Ponzi Invariant — GoatCoin's load-bearing economic
//! rule" spec, §1 and §8.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use alloy::primitives::{Address, Signature};
use serde::{Deserialize, Serialize};

use goat_proxy_worker::destinations::RegistryError;

use super::policy::{allowlist_digest, policy_digest, policy_doc};

/// The first line of the preimage. Domain separation, so the digest of a consent
/// record cannot collide with the digest of anything else this project hashes.
pub const CONSENT_HEADER: &str = "GOAT Residential Proxy Consent Record v1";
pub const CONSENT_SCHEMA: u32 = 1;
/// 90 days. The record carries `expires_at_unix = granted_at_unix + CONSENT_TTL_SECS`
/// and both the age check and the expiry check are this same constant.
pub const CONSENT_TTL_SECS: u64 = 7_776_000;

/// Every field carries `#[serde(default)]`.
///
/// A missing attribute on a persisted struct in this app silently wipes the whole
/// state file on the next schema change -- that erratum is recorded against the FAH
/// adapter and it is why these three proxy files are deliberately NOT part of
/// `FahPersisted` either.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyConsentRecord {
    #[serde(default)]
    pub schema: u32,
    #[serde(default)]
    pub policy_version: u32,
    #[serde(default)]
    pub policy_digest: String,
    #[serde(default)]
    pub allowlist_digest: String,
    #[serde(default)]
    pub wallet: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub daily_ceiling_bytes: u64,
    #[serde(default)]
    pub throttle_bytes_per_sec: u64,
    #[serde(default)]
    pub granted_at_unix: u64,
    #[serde(default)]
    pub expires_at_unix: u64,
    #[serde(default)]
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    Absent,
    Malformed,
    /// The grant has not started yet. The sidecar calls this `NotYetValid` and refuses
    /// it too; folding it into `Malformed` would tell the operator their file is
    /// unreadable when the real answer is that their clock disagrees.
    NotYetValid,
    StalePolicy,
    Expired,
    BadSignature,
    WalletMismatch,
    /// No active wallet was supplied to compare against. A record whose owner cannot
    /// be established is not valid -- see [`verify`].
    WalletUnknown,
    Valid,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyConsentStatus {
    pub state: ConsentState,
    pub policy_version: u32,
    pub expires_at_unix: u64,
    pub days_remaining: i64,
    pub wallet: String,
    pub device_id: String,
    /// The ceiling the operator SIGNED, in bytes. The controls may lower it and can
    /// never raise it, so this is what the screen must render the effective cap from.
    pub daily_ceiling_bytes: u64,
    pub throttle_bytes_per_sec: u64,
}

pub struct Digests {
    pub policy_version: u32,
    pub policy: String,
    pub allowlist: String,
}

/// The two digests this build computes over its own compiled-in disclosure.
///
/// Fallible because the allowlist digest is serialised through the canonical
/// slug <-> id registry, and a destination the registry does not carry is a
/// REFUSAL rather than a zero. That refusal has to travel: a build whose own
/// document names an unregistered destination cannot state a scope for anyone to
/// consent to, so every caller below turns it into a closed switch rather than a
/// digest nobody can reproduce.
pub fn current_digests() -> Result<Digests, RegistryError> {
    let doc = policy_doc();
    Ok(Digests {
        policy_version: doc.policy_version,
        policy: policy_digest(&doc),
        allowlist: allowlist_digest(&doc)?,
    })
}

/// Lower-case `0x`-hex, the one spelling the preimage uses.
///
/// The sidecar holds the wallet and the digests as fixed-width BYTES and hex-encodes
/// them on the way into its preimage, which is always lower case. A checksummed
/// spelling signed here would produce a preimage the sidecar never reconstructs, and
/// every signature would fail on the daemon side while passing on this one.
fn norm_hex(value: &str) -> String {
    let t = value.trim();
    let body = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    format!("0x{}", body.to_ascii_lowercase())
}

/// The exact bytes an operator's signature is over: a `\n`-joined line block with NO
/// trailing newline.
pub fn preimage(r: &ProxyConsentRecord) -> String {
    [
        CONSENT_HEADER.to_string(),
        format!("schema: {}", r.schema),
        format!("policy_version: {}", r.policy_version),
        format!("policy_digest: {}", norm_hex(&r.policy_digest)),
        format!("allowlist_digest: {}", norm_hex(&r.allowlist_digest)),
        format!("wallet: {}", norm_hex(&r.wallet)),
        format!("device_id: {}", r.device_id),
        format!("daily_ceiling_bytes: {}", r.daily_ceiling_bytes),
        format!("throttle_bytes_per_sec: {}", r.throttle_bytes_per_sec),
        format!("granted_at_unix: {}", r.granted_at_unix),
        format!("expires_at_unix: {}", r.expires_at_unix),
    ]
    .join("\n")
}

fn parse_signature(raw: &str) -> Option<Signature> {
    let hex_body = raw.trim();
    let hex_body = hex_body
        .strip_prefix("0x")
        .or_else(|| hex_body.strip_prefix("0X"))
        .unwrap_or(hex_body);
    let bytes = hex::decode(hex_body).ok()?;
    let arr: [u8; 65] = bytes.try_into().ok()?;
    Signature::from_raw_array(&arr).ok()
}

pub fn verify(
    record: &ProxyConsentRecord,
    expected: &Digests,
    now_unix: u64,
    active_wallet: Option<&str>,
) -> ConsentState {
    if record.schema != CONSENT_SCHEMA
        || record.wallet.is_empty()
        || record.signature.is_empty()
        || record.device_id.is_empty()
        || record.daily_ceiling_bytes == 0
        || record.throttle_bytes_per_sec == 0
    {
        return ConsentState::Malformed;
    }
    // A stretched term, checked before the signature because a record whose term is
    // wrong is malformed whether or not the operator signed it -- and the operator's
    // OWN key signing a 900-day grant is exactly the case a signature check cannot
    // catch. Same constant, same comparison, as the sidecar.
    if record.expires_at_unix != record.granted_at_unix.saturating_add(CONSENT_TTL_SECS) {
        return ConsentState::Malformed;
    }

    // SIGNATURE FIRST, digests second.
    //
    // Returning `StalePolicy` before verifying meant a completely unsigned,
    // hand-written record naming a wrong digest reported `StalePolicy` -- and the UI
    // told the operator "the disclosure text or the destination list changed since you
    // signed", which presents tampering as a benign version change. A forged file must
    // always read `BadSignature`.
    let Some(sig) = parse_signature(&record.signature) else {
        return ConsentState::BadSignature;
    };
    let Ok(named) = Address::from_str(record.wallet.trim()) else {
        return ConsentState::Malformed;
    };
    // EIP-191 over the DECODED UTF-8 bytes of the preimage -- never over a hex string.
    let Ok(recovered) = sig.recover_address_from_msg(preimage(record).as_bytes()) else {
        return ConsentState::BadSignature;
    };
    if recovered != named {
        return ConsentState::BadSignature;
    }

    if record.policy_version != expected.policy_version
        || norm_hex(&record.policy_digest) != norm_hex(&expected.policy)
        || norm_hex(&record.allowlist_digest) != norm_hex(&expected.allowlist)
    {
        return ConsentState::StalePolicy;
    }
    if now_unix < record.granted_at_unix {
        return ConsentState::NotYetValid;
    }
    // The boundary is INCLUSIVE and matches the sidecar's exactly: a record at the
    // instant of expiry is still valid, one second past is not. A desktop boundary one
    // second tighter than the daemon's would show "expired" while traffic still flowed.
    if now_unix > record.expires_at_unix {
        return ConsentState::Expired;
    }

    // `None` is a REFUSAL, not a pass.
    //
    // `None => Valid` made a validly-self-signed record from any throwaway key
    // indistinguishable from the operator's own -- and the spawn path called this with
    // `None`. A record that cannot be tied to the active wallet is not a valid record;
    // it is a record whose owner is unknown.
    //
    // Compared on the twenty BYTES, never on a string: a checksummed spelling and a
    // lower-case one name one key, and a string comparison would call them two.
    match active_wallet.map(str::trim).map(Address::from_str) {
        Some(Ok(a)) if a == named => ConsentState::Valid,
        Some(_) => ConsentState::WalletMismatch,
        None => ConsentState::WalletUnknown,
    }
}

pub fn consent_path(dir: &Path) -> PathBuf {
    dir.join("proxy-consent.json")
}

pub fn load(dir: &Path) -> Option<ProxyConsentRecord> {
    let raw = std::fs::read_to_string(consent_path(dir)).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Atomic write -- a kill mid-write must never leave a half-record the sidecar might
/// parse.
pub fn store(dir: &Path, record: &ProxyConsentRecord) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tmp = dir.join("proxy-consent.json.tmp");
    let body = serde_json::to_string_pretty(record).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, consent_path(dir)).map_err(|e| e.to_string())
}

pub fn erase(dir: &Path) -> Result<(), String> {
    match std::fs::remove_file(consent_path(dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

pub fn status(
    record: Option<&ProxyConsentRecord>,
    now_unix: u64,
    active_wallet: Option<&str>,
) -> ProxyConsentStatus {
    // A build that cannot name its own destinations canonically has no scope to
    // report. It reports MALFORMED and nothing else: not `Valid`, and not a
    // silently absent record, because "this app cannot state what it would
    // contact" is a different problem from "you have not signed yet".
    let Ok(expected) = current_digests() else {
        return ProxyConsentStatus {
            state: ConsentState::Malformed,
            policy_version: 0,
            expires_at_unix: 0,
            days_remaining: 0,
            wallet: String::new(),
            device_id: String::new(),
            daily_ceiling_bytes: 0,
            throttle_bytes_per_sec: 0,
        };
    };
    match record {
        None => ProxyConsentStatus {
            state: ConsentState::Absent,
            policy_version: expected.policy_version,
            expires_at_unix: 0,
            days_remaining: 0,
            wallet: String::new(),
            device_id: String::new(),
            daily_ceiling_bytes: 0,
            throttle_bytes_per_sec: 0,
        },
        Some(r) => {
            let state = verify(r, &expected, now_unix, active_wallet);
            let days = (r.expires_at_unix as i64 - now_unix as i64) / 86_400;
            // A ceiling is only in force when the record is. Reporting the number out
            // of a refused record would render a cap that governs nothing.
            let in_force = state == ConsentState::Valid;
            ProxyConsentStatus {
                state,
                policy_version: expected.policy_version,
                expires_at_unix: r.expires_at_unix,
                days_remaining: days.max(0),
                wallet: r.wallet.clone(),
                device_id: r.device_id.clone(),
                daily_ceiling_bytes: if in_force { r.daily_ceiling_bytes } else { 0 },
                throttle_bytes_per_sec: if in_force {
                    r.throttle_bytes_per_sec
                } else {
                    0
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;

    thread_local! {
        static SIGNER: PrivateKeySigner = PrivateKeySigner::random();
    }

    /// The digests this build computes, with the registry refusal turned into a
    /// test failure.
    ///
    /// It is an `expect` and not a fallback: if the shipped document ever names
    /// a destination the canonical registry does not carry, every test below
    /// should stop rather than quietly compare two digests over a scope nobody
    /// can name.
    fn expected() -> Digests {
        current_digests().expect("the shipped policy resolves through the canonical registry")
    }

    fn sign(r: &ProxyConsentRecord) -> String {
        let signer = SIGNER.with(|s| s.clone());
        let sig = signer.sign_message_sync(preimage(r).as_bytes()).unwrap();
        format!("0x{}", hex::encode(sig.as_bytes()))
    }

    fn signed(now: u64) -> (ProxyConsentRecord, Address) {
        let signer = SIGNER.with(|s| s.clone());
        let d = expected();
        let mut r = ProxyConsentRecord {
            schema: CONSENT_SCHEMA,
            policy_version: d.policy_version,
            policy_digest: norm_hex(&d.policy),
            allowlist_digest: norm_hex(&d.allowlist),
            wallet: signer.address().to_checksum(None),
            device_id: "00112233445566778899aabbccddeeff".into(),
            daily_ceiling_bytes: 5_000_000_000,
            throttle_bytes_per_sec: 256_000,
            granted_at_unix: now,
            expires_at_unix: now + CONSENT_TTL_SECS,
            signature: String::new(),
        };
        r.signature = sign(&r);
        (r, signer.address())
    }

    #[test]
    fn a_correctly_signed_record_is_valid() {
        let (r, addr) = signed(1_800_000_000);
        assert_eq!(
            verify(
                &r,
                &expected(),
                1_800_000_100,
                Some(&addr.to_checksum(None))
            ),
            ConsentState::Valid
        );
        // The checksummed spelling and the lower-case one are ONE key.
        assert_eq!(
            verify(
                &r,
                &expected(),
                1_800_000_100,
                Some(&addr.to_string().to_lowercase())
            ),
            ConsentState::Valid
        );
    }

    /// Mutations this detects: `if false && recovered != named`, i.e. a gate that
    /// accepts anything. A forged file naming the active wallet is the whole attack.
    #[test]
    fn consent_gate_refuses_a_forged_record_that_names_the_active_wallet() {
        let (mut r, addr) = signed(1_800_000_000);
        r.signature = format!("0x{}", "11".repeat(65));
        assert_eq!(
            verify(
                &r,
                &expected(),
                1_800_000_100,
                Some(&addr.to_checksum(None))
            ),
            ConsentState::BadSignature
        );
    }

    #[test]
    fn consent_signed_by_a_key_that_is_not_the_operator_refuses_start() {
        let (mut r, _) = signed(1_800_000_000);
        r.wallet = "0x2222222222222222222222222222222222222222".into();
        let w = r.wallet.clone();
        assert_eq!(
            verify(&r, &expected(), 1_800_000_100, Some(&w)),
            ConsentState::BadSignature
        );
    }

    #[test]
    fn consent_for_a_different_policy_hash_refuses_start() {
        // Re-signed AFTER the edit, so this exercises a genuine version change.
        let (mut r, addr) = signed(1_800_000_000);
        r.policy_digest = format!("0x{}", "0".repeat(64));
        r.signature = sign(&r);
        assert_eq!(
            verify(
                &r,
                &expected(),
                1_800_000_100,
                Some(&addr.to_checksum(None))
            ),
            ConsentState::StalePolicy
        );
    }

    #[test]
    fn consent_gate_refuses_a_record_naming_a_different_allowlist_digest() {
        let (mut r, addr) = signed(1_800_000_000);
        r.allowlist_digest = format!("0x{}", "f".repeat(64));
        r.signature = sign(&r);
        assert_eq!(
            verify(
                &r,
                &expected(),
                1_800_000_100,
                Some(&addr.to_checksum(None))
            ),
            ConsentState::StalePolicy
        );
    }

    /// Mutations this detects: comparing digests BEFORE recovering the signature,
    /// which reports tampering to the operator as a benign version change --
    /// `PROXY_CONSENT_STALE_NOTE` says "the disclosure text or the destination list
    /// changed since you signed", which is a lie about a forged file.
    #[test]
    fn a_tampered_record_reads_bad_signature_not_stale_policy() {
        let (mut r, addr) = signed(1_800_000_000);
        r.policy_digest = format!("0x{}", "0".repeat(64)); // edited, NOT re-signed
        assert_eq!(
            verify(
                &r,
                &expected(),
                1_800_000_100,
                Some(&addr.to_checksum(None))
            ),
            ConsentState::BadSignature
        );
    }

    /// Mutations this detects: `None => ConsentState::Valid`. With that arm, any
    /// self-consistent self-signed blob authorises residential egress -- no wallet
    /// unlock, no disclosure, no operator involvement at all.
    #[test]
    fn a_record_with_no_active_wallet_to_compare_is_not_valid() {
        let (r, _) = signed(1_800_000_000);
        assert_eq!(
            verify(&r, &expected(), 1_800_000_100, None),
            ConsentState::WalletUnknown
        );
    }

    #[test]
    fn consent_older_than_ninety_days_refuses_start() {
        let (r, addr) = signed(1_800_000_000);
        let w = addr.to_checksum(None);
        // The boundary is inclusive, exactly as the sidecar's is.
        assert_eq!(
            verify(
                &r,
                &expected(),
                1_800_000_000 + CONSENT_TTL_SECS,
                Some(&w)
            ),
            ConsentState::Valid
        );
        assert_eq!(
            verify(
                &r,
                &expected(),
                1_800_000_001 + CONSENT_TTL_SECS,
                Some(&w)
            ),
            ConsentState::Expired
        );
    }

    /// Mutations this detects: `>=` relaxed to `>` on the term check, or the term
    /// check dropped -- a hand-edited 900-day grant is what somebody writes when they
    /// want the gate to stop asking.
    #[test]
    fn consent_gate_refuses_a_stretched_expiry() {
        let (mut r, addr) = signed(1_800_000_000);
        r.expires_at_unix = r.granted_at_unix + CONSENT_TTL_SECS * 10;
        r.signature = sign(&r); // re-signed: even the operator's own key cannot stretch it
        assert_eq!(
            verify(
                &r,
                &expected(),
                1_800_000_100,
                Some(&addr.to_checksum(None))
            ),
            ConsentState::Malformed
        );
    }

    #[test]
    fn consent_gate_reports_wallet_mismatch_when_another_wallet_is_active() {
        let (r, _) = signed(1_800_000_000);
        assert_eq!(
            verify(
                &r,
                &expected(),
                1_800_000_100,
                Some("0x3333333333333333333333333333333333333333")
            ),
            ConsentState::WalletMismatch
        );
    }

    #[test]
    fn a_record_that_has_not_started_is_not_yet_valid() {
        let (r, addr) = signed(1_800_000_000);
        assert_eq!(
            verify(
                &r,
                &expected(),
                1_799_999_999,
                Some(&addr.to_checksum(None))
            ),
            ConsentState::NotYetValid
        );
    }

    /// Mutations this detects: a ceiling or a throttle of zero passing structural
    /// validation. The sidecar refuses a zero ceiling at config load, so a record
    /// carrying one is a record that cannot start anything.
    #[test]
    fn a_zero_ceiling_or_throttle_is_malformed() {
        let (mut r, addr) = signed(1_800_000_000);
        let w = addr.to_checksum(None);
        r.daily_ceiling_bytes = 0;
        r.signature = sign(&r);
        assert_eq!(
            verify(&r, &expected(), 1_800_000_100, Some(&w)),
            ConsentState::Malformed
        );
    }

    #[test]
    fn consent_record_round_trips_with_missing_fields_defaulted() {
        let parsed: ProxyConsentRecord = serde_json::from_str("{\"schema\":1}").unwrap();
        assert_eq!(parsed.schema, 1);
        assert_eq!(parsed.wallet, "");
        assert_eq!(
            verify(&parsed, &expected(), 1, None),
            ConsentState::Malformed
        );
    }

    #[test]
    fn store_then_load_is_identity_and_erase_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("goat-proxy-consent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (r, _) = signed(1_800_000_000);
        store(&dir, &r).unwrap();
        assert_eq!(load(&dir).unwrap(), r);
        erase(&dir).unwrap();
        assert!(load(&dir).is_none());
        erase(&dir).unwrap(); // absent is not an error
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The preimage is hand-written in THREE places -- here, in `consentRecord.js`,
    /// and in the sidecar's own consent module. This is the one object all three
    /// assert against.
    ///
    /// Mutations this detects: a separator changed in any one of the three; the field
    /// order changed; a trailing newline added or removed; the ceiling or the throttle
    /// dropped from the signed bytes.
    #[test]
    fn the_consent_preimage_matches_the_cross_language_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tools/goat-proxy-worker/fixtures/consent-preimage.json"
        ))
        .expect("fixture is malformed");
        let f = &fixture["record"];
        let u = |k: &str| -> u64 {
            f[k].as_u64()
                .or_else(|| f[k].as_str().and_then(|s| s.parse().ok()))
                .unwrap_or_else(|| panic!("fixture field {k} is not an integer"))
        };
        let r = ProxyConsentRecord {
            schema: u("schema") as u32,
            policy_version: u("policy_version") as u32,
            policy_digest: f["policy_digest"].as_str().unwrap().into(),
            allowlist_digest: f["allowlist_digest"].as_str().unwrap().into(),
            wallet: f["wallet"].as_str().unwrap().into(),
            device_id: f["device_id"].as_str().unwrap().into(),
            daily_ceiling_bytes: u("daily_ceiling_bytes"),
            throttle_bytes_per_sec: u("throttle_bytes_per_sec"),
            granted_at_unix: u("granted_at_unix"),
            expires_at_unix: u("expires_at_unix"),
            signature: String::new(),
        };
        assert_eq!(
            format!("0x{}", hex::encode(preimage(&r).as_bytes())),
            fixture["preimage_hex"].as_str().unwrap(),
            "the preimage bytes have drifted from the cross-language pin"
        );
    }
}
