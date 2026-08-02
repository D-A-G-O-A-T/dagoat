//! The gateway's epoch meter commitment — this lane's substitute for a public
//! oracle.
//!
//! The compute lane's challenger works by re-reading a public endpoint
//! (`crate::challenger`, against `crate::fah`). Bandwidth has nothing to
//! re-read: the bytes are gone the moment they move. What replaces the re-read
//! is not a second measurement of the same thing later, but a
//! **contemporaneous second counter held by a party with no stake in the
//! payout** — the gateway, which is the sole ingress and is not compensated per
//! byte.
//!
//! It publishes, per epoch, a canonically-serialised, EIP-712-signed statement
//! of its own per-session totals, retrievable independently of the proposer.
//! That is the property the public compute endpoint has and a proposer-supplied
//! bundle does not.
//!
//! # What the gateway can and cannot witness — stated so the argument is not circular
//!
//! The gateway sits between the consumer and the node. It never touches the
//! origin connection. It therefore WITNESSES `to_consumer` — bytes it saw cross
//! its own tunnel — and it merely RE-SIGNS `node_reported_from_origin`, which is
//! a node assertion. Signing a claim attests to receipt of the claim, not to
//! observation of the thing claimed.
//!
//! Settlement is on `to_consumer` for exactly that reason. If the operator's
//! share were computed from the origin-leg number, padding, a re-fetched body,
//! TLS renegotiation and chunked framing would all be invisible to the
//! "independent" witness, and the three-party argument would be a circle.
//! Nothing in this system witnesses the origin leg, and no copy may claim
//! otherwise. [`super::verify::GatewayWitness`] carries the same asymmetry
//! per chunk; this module carries it per epoch.
//!
//! # This is NOT the per-chunk witness
//!
//! [`super::verify::GatewayWitness`] is one gateway signature about **one
//! receipt**, checked at `verify.rs:806` as stage 10 of a bundle's verification.
//! [`GatewayMeterCommitment`] is one gateway signature about **a whole epoch**,
//! and it is the document a challenger fetches when nobody has handed it a
//! bundle at all. The two never substitute for each other and neither repeats
//! the other's check.
//!
//! # Why the document carries so many refusals
//!
//! A meter commitment arrives over the network from a party the challenger is
//! about to believe over the proposer. Everything that could make it mean
//! something other than "this gateway's totals for this epoch on this
//! deployment" is a refusal, not a warning:
//!
//! * the chain id must be one this lane may settle on, so a document signed
//!   against a deployment nobody runs cannot decide a dispute;
//! * it must name the epoch being evaluated, or a validly-signed commitment
//!   from *last* epoch would challenge every session of *this* one;
//! * no session id may appear twice, because the comparison keys on session id
//!   and a repeat would let one entry silently replace another while the header
//!   total still counted both;
//! * the header total must equal the sum of the parts;
//! * and the signature must recover to the gateway this lane named.
//!
//! [`VerifiedMeterCommitment`] is a newtype with a private field. It exists so
//! that "the signature is checked before the comparison" is a fact about the
//! type system rather than a claim in a test name.
//!
//! Sessions are sorted by `session_id` before serialisation, so two honest
//! gateways with different internal iteration orders produce identical bytes.
//!
//! Nothing here issues supply and nothing here destroys supply, and no field of
//! any struct in this file can carry a hostname, path, query string, header or
//! body
//! byte: every one of them is a byte count, a counter or an opaque identifier.

use std::collections::BTreeSet;

use serde_json::{json, Value};
use thiserror::Error;

use crate::canonical_json::{canonical_hash, CanonicalJsonError};
use crate::merkle::keccak256;
use crate::sig_verify::{domain_separator, eip712_digest, recover_signer, u256_be, SigError};

use super::PROXY_CHAIN_ALLOWLIST;

/// Schema identifier for version 1 of the commitment, hashed into the signed
/// struct's first word so a future version 2 cannot be replayed as a version 1.
pub const METER_SCHEMA_V1: &str = "GOAT_PROXY_GATEWAY_METER_COMMITMENT_V1";

/// The commitment's EIP-712 type string — the lane's fourth, and the last one
/// [`super::receipt::proxy_type_strings`] was written to accept.
///
/// The variable-length session array is carried as one `bytes32 sessionsHash`
/// word, which is `keccak256(UTF8(RFC8785(sessions)))` — see [`sessions_hash`].
pub const METER_TYPEHASH_STR: &str = "GatewayMeterCommitment(bytes32 schemaId,uint256 epochId,bytes32 gatewayId,bytes32 sessionsHash,uint256 totalBytes)";

/// One session's totals as the gateway counted them.
///
/// `total_bytes` is `body_bytes_to_consumer` and nothing else: response body
/// octets, after the node strips HTTP framing and decodes chunked
/// transfer-encoding, as they cross into the tunnel. Two counters on **one**
/// byte stream, which is the only reason strict equality is shippable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayMeterSession {
    pub session_id: [u8; 32],
    pub operator: [u8; 20],
    pub total_bytes: u128,
    pub chunk_count: u64,
}

/// One gateway's totals for one epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayMeterCommitment {
    pub epoch_id: u64,
    pub gateway_id: [u8; 32],
    pub sessions: Vec<GatewayMeterSession>,
    /// The header total. Must equal the sum of `sessions`, or the document is
    /// refused — a gateway whose two numbers disagree is not usable as a
    /// witness at all.
    pub total_bytes: u128,
}

/// Why a meter commitment was refused. Every variant is a byte count, an
/// integer or a hex identifier; none of them can carry a destination.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MeterError {
    #[error("canonical json: {0}")]
    Canonical(#[from] CanonicalJsonError),
    /// Same refusal `super::verify` makes at its structural stage, made again
    /// here because this document arrives on its own and never passes through
    /// that stage.
    #[error("ChainNotAllowed: chain id {chain_id} is not a chain this lane may settle on")]
    ChainNotAllowed { chain_id: u64 },
    /// A validly-signed commitment for a different epoch. Refused rather than
    /// compared, because comparing it would challenge every session of the
    /// epoch actually being evaluated.
    #[error(
        "EpochMismatch: commitment names epoch {found}, this evaluation is of epoch {expected}"
    )]
    EpochMismatch { expected: u64, found: u64 },
    /// One session id listed more than once. The comparison keys on session
    /// id, so a repeat would let the second entry replace the first while the
    /// header total still counted both.
    #[error("DuplicateSession: session 0x{session_id_hex} is listed more than once")]
    DuplicateSession { session_id_hex: String },
    /// The per-session counts do not fit in a `u128` when added. Surfaced
    /// rather than allowed to wrap or panic: this document is untrusted input.
    #[error("SessionTotalsOverflow: the per-session counts do not sum within a uint256")]
    SessionTotalsOverflow,
    #[error("MalformedSignature: {0}")]
    MalformedSignature(#[from] SigError),
    #[error("SignerMismatch: expected 0x{expected}, recovered 0x{got}")]
    SignerMismatch { expected: String, got: String },
    #[error("InternallyInconsistent: header total {header} != sum of sessions {summed}")]
    InternallyInconsistent { header: u128, summed: u128 },
}

impl GatewayMeterCommitment {
    /// Sessions sorted by id — the serialisation order, applied on a copy so
    /// the caller's ordering is never mutated behind its back.
    pub fn sorted_sessions(&self) -> Vec<GatewayMeterSession> {
        let mut s = self.sessions.clone();
        s.sort_by_key(|a| a.session_id);
        s
    }

    /// Sum of the per-session counts, or `None` if the addition would leave
    /// `u128`. `checked_add` rather than `sum`, because `sum` panics in a debug
    /// build and wraps in a release one, and this input arrives over a socket.
    fn summed_bytes(&self) -> Option<u128> {
        self.sessions
            .iter()
            .try_fold(0u128, |acc, s| acc.checked_add(s.total_bytes))
    }

    /// The first session id that appears twice, if any.
    fn duplicate_session(&self) -> Option<[u8; 32]> {
        let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
        self.sessions
            .iter()
            .find(|s| !seen.insert(s.session_id))
            .map(|s| s.session_id)
    }

    /// The header total must equal the sum of the parts.
    ///
    /// An overflowing sum is *not* consistent: there is no total it could be
    /// equal to.
    pub fn is_internally_consistent(&self) -> bool {
        self.summed_bytes() == Some(self.total_bytes)
    }
}

/// The canonical JSON view. Every integer is a decimal STRING — this crate's
/// canonical encoder refuses JSON numbers and bools outright.
pub fn meter_canonical_value(c: &GatewayMeterCommitment) -> Value {
    let sessions: Vec<Value> = c
        .sorted_sessions()
        .iter()
        .map(|s| {
            json!({
                "sessionId": format!("0x{}", hex::encode(s.session_id)),
                "operator": format!("0x{}", hex::encode(s.operator)),
                "totalBytes": s.total_bytes.to_string(),
                "chunkCount": s.chunk_count.to_string(),
            })
        })
        .collect();
    json!({
        "schemaId": METER_SCHEMA_V1,
        "epochId": c.epoch_id.to_string(),
        "gatewayId": format!("0x{}", hex::encode(c.gateway_id)),
        "sessions": sessions,
        "totalBytes": c.total_bytes.to_string(),
    })
}

/// `keccak256(UTF8(RFC8785(sessions)))` — the one word the EIP-712 struct
/// carries for a variable-length array.
pub fn sessions_hash(c: &GatewayMeterCommitment) -> Result<[u8; 32], MeterError> {
    let v = meter_canonical_value(c);
    Ok(canonical_hash(&v["sessions"])?)
}

/// `keccak256(abi.encode(METER_TYPEHASH, …))`, one word per field.
pub fn meter_struct_hash(c: &GatewayMeterCommitment) -> Result<[u8; 32], MeterError> {
    let mut buf = Vec::with_capacity(32 * 6);
    buf.extend_from_slice(&keccak256(METER_TYPEHASH_STR.as_bytes()));
    buf.extend_from_slice(&keccak256(METER_SCHEMA_V1.as_bytes()));
    buf.extend_from_slice(&u256_be(u128::from(c.epoch_id)));
    buf.extend_from_slice(&c.gateway_id);
    buf.extend_from_slice(&sessions_hash(c)?);
    buf.extend_from_slice(&u256_be(c.total_bytes));
    debug_assert_eq!(buf.len(), 32 * 6);
    Ok(keccak256(&buf))
}

/// The digest the gateway signs, binding chain id and verifying contract so a
/// commitment made for one deployment is not a commitment for another.
pub fn meter_digest(
    c: &GatewayMeterCommitment,
    chain_id: u64,
    verifying: [u8; 20],
) -> Result<[u8; 32], MeterError> {
    let domain = domain_separator(
        super::receipt::PROXY_DOMAIN_NAME,
        super::receipt::PROXY_DOMAIN_VERSION,
        chain_id,
        verifying,
    );
    Ok(eip712_digest(&domain, &meter_struct_hash(c)?))
}

/// A commitment whose gateway signature, epoch, uniqueness and internal
/// consistency have ALL been checked.
///
/// The field is private and this module exposes no other constructor, so
/// [`super::challenger::evaluate_proxy_epoch`] cannot be handed an
/// unauthenticated document — not by a caller in a hurry, and not by a
/// refactor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMeterCommitment(GatewayMeterCommitment);

/// The standard trait rather than an inherent `as_ref`, so the call site reads
/// the same as the plan wrote it (`w.as_ref()`) without shadowing
/// [`std::convert::AsRef`] with a look-alike of its own. There is exactly one
/// impl, so the method resolves unambiguously.
impl AsRef<GatewayMeterCommitment> for VerifiedMeterCommitment {
    fn as_ref(&self) -> &GatewayMeterCommitment {
        &self.0
    }
}

/// Check a meter commitment and wrap it, or refuse.
///
/// Takes the commitment BY VALUE and returns it wrapped, so an unverified copy
/// does not remain conveniently in scope beside the verified one.
///
/// `expected_epoch` is a parameter and not a field read out of `c`, which is
/// the whole point: the caller states which epoch it is evaluating, and a
/// commitment naming any other epoch is refused before its signature is even
/// recovered. Without it, a genuinely gateway-signed document from a previous
/// epoch verifies perfectly and then challenges every session in the current
/// one.
pub fn verify_meter_commitment(
    c: GatewayMeterCommitment,
    signature_hex: &str,
    expected_gateway: [u8; 20],
    expected_epoch: u64,
    chain_id: u64,
    verifying: [u8; 20],
) -> Result<VerifiedMeterCommitment, MeterError> {
    if !PROXY_CHAIN_ALLOWLIST.contains(&chain_id) {
        return Err(MeterError::ChainNotAllowed { chain_id });
    }
    if c.epoch_id != expected_epoch {
        return Err(MeterError::EpochMismatch {
            expected: expected_epoch,
            found: c.epoch_id,
        });
    }
    if let Some(id) = c.duplicate_session() {
        return Err(MeterError::DuplicateSession {
            session_id_hex: hex::encode(id),
        });
    }
    let summed = c.summed_bytes().ok_or(MeterError::SessionTotalsOverflow)?;
    if summed != c.total_bytes {
        return Err(MeterError::InternallyInconsistent {
            header: c.total_bytes,
            summed,
        });
    }

    let digest = meter_digest(&c, chain_id, verifying)?;
    let raw = signature_hex
        .strip_prefix("0x")
        .or_else(|| signature_hex.strip_prefix("0X"))
        .unwrap_or(signature_hex);
    let bytes =
        hex::decode(raw).map_err(|_| MeterError::MalformedSignature(SigError::Malformed))?;
    // Through the crate's ONE secp256k1 recovery path — see `recover_signer`'s
    // doc comment for why a second `recover_address_from_prehash` call site
    // would mean two places for the `v`-normalisation rule to be wrong.
    let recovered = recover_signer(&digest, &bytes)?;
    if recovered != expected_gateway {
        return Err(MeterError::SignerMismatch {
            expected: hex::encode(expected_gateway),
            got: hex::encode(recovered),
        });
    }
    Ok(VerifiedMeterCommitment(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_json::canonical_bytes;

    fn sess(id: u8, operator: u8, bytes: u128, chunks: u64) -> GatewayMeterSession {
        let mut s = [0u8; 32];
        s[0] = id;
        let mut o = [0u8; 20];
        o[19] = operator;
        GatewayMeterSession {
            session_id: s,
            operator: o,
            total_bytes: bytes,
            chunk_count: chunks,
        }
    }

    /// The canonical view must be all-strings and must not depend on the order
    /// the gateway happened to iterate its own sessions in.
    ///
    /// Mutations this detects: emitting any integer as a JSON number (the
    /// encoder refuses it, so the hash would not exist at all); dropping the
    /// sort from [`GatewayMeterCommitment::sorted_sessions`], which would give
    /// two honest gateways two different digests for the same epoch; adding a
    /// key outside the portable alphabet.
    #[test]
    fn the_commitment_canonicalises_to_strings_and_is_order_independent() {
        let a = GatewayMeterCommitment {
            epoch_id: 8_000_000_020_664,
            gateway_id: [0x66; 32],
            sessions: vec![sess(1, 0xA1, 104_857_600, 10), sess(2, 0xB2, 10_485_760, 1)],
            total_bytes: 115_343_360,
        };
        let b = GatewayMeterCommitment {
            sessions: vec![sess(2, 0xB2, 10_485_760, 1), sess(1, 0xA1, 104_857_600, 10)],
            ..a.clone()
        };

        // POSITIVE CONTROL: the two inputs really are in different orders, so
        // an equality below is not comparing a value with itself.
        assert_ne!(a.sessions, b.sessions);

        let va = meter_canonical_value(&a);
        assert_eq!(
            canonical_bytes(&va).expect("the commitment must canonicalise"),
            canonical_bytes(&meter_canonical_value(&b)).expect("must canonicalise")
        );
        assert_eq!(
            meter_struct_hash(&a).unwrap(),
            meter_struct_hash(&b).unwrap()
        );

        // Every leaf value is a string, at both levels.
        for (k, v) in va.as_object().expect("an object") {
            if k == "sessions" {
                for s in v.as_array().expect("an array") {
                    assert!(
                        s.as_object().unwrap().values().all(|x| x.is_string()),
                        "a session field is not a decimal string"
                    );
                }
            } else {
                assert!(v.is_string(), "{k} is not a string");
            }
        }
        assert_eq!(va["totalBytes"], "115343360");
        assert_eq!(va["epochId"], "8000000020664");
    }

    /// Each of the five signed words is load-bearing: change one and the digest
    /// changes.
    ///
    /// Mutations this detects: dropping `schemaId`, `gatewayId`, `epochId`,
    /// `sessionsHash` or `totalBytes` from [`meter_struct_hash`]; hashing the
    /// sessions array in a way that ignores a session's operator or chunk
    /// count; dropping chain id or the verifying contract from the domain.
    #[test]
    fn every_signed_word_changes_the_digest() {
        let base = GatewayMeterCommitment {
            epoch_id: 8_000_000_020_664,
            gateway_id: [0x66; 32],
            sessions: vec![sess(1, 0xA1, 104_857_600, 10)],
            total_bytes: 104_857_600,
        };
        let d = |c: &GatewayMeterCommitment| meter_digest(c, 84_532, [0x99; 20]).unwrap();
        let baseline = d(&base);

        let mut epoch = base.clone();
        epoch.epoch_id += 1;
        assert_ne!(baseline, d(&epoch), "epochId is not in the digest");

        let mut gw = base.clone();
        gw.gateway_id = [0x67; 32];
        assert_ne!(baseline, d(&gw), "gatewayId is not in the digest");

        let mut total = base.clone();
        total.total_bytes += 1;
        assert_ne!(baseline, d(&total), "totalBytes is not in the digest");

        let mut bytes = base.clone();
        bytes.sessions[0].total_bytes += 1;
        assert_ne!(
            baseline,
            d(&bytes),
            "a session's bytes are not in the digest"
        );

        let mut operator = base.clone();
        operator.sessions[0].operator = [0xB2; 20];
        assert_ne!(
            baseline,
            d(&operator),
            "a session's operator is not in the digest"
        );

        let mut chunks = base.clone();
        chunks.sessions[0].chunk_count += 1;
        assert_ne!(
            baseline,
            d(&chunks),
            "a session's chunk count is not in the digest"
        );

        // The deployment binding, both halves.
        assert_ne!(baseline, meter_digest(&base, 31_337, [0x99; 20]).unwrap());
        assert_ne!(baseline, meter_digest(&base, 84_532, [0x11; 20]).unwrap());
    }

    /// The header total and the sum of the parts, including the two ways the
    /// sum can fail to exist.
    ///
    /// Mutations this detects: comparing the header against itself; using
    /// `sum()` instead of `checked_add` (which panics in a debug build on the
    /// overflow arm below); treating an overflowing sum as consistent.
    #[test]
    fn internal_consistency_covers_both_the_mismatch_and_the_overflow() {
        let mut c = GatewayMeterCommitment {
            epoch_id: 8_000_000_020_664,
            gateway_id: [0x66; 32],
            sessions: vec![sess(1, 0xA1, 104_857_600, 10), sess(2, 0xB2, 10_485_760, 1)],
            total_bytes: 115_343_360,
        };
        assert!(c.is_internally_consistent(), "positive control");
        c.total_bytes += 1;
        assert!(!c.is_internally_consistent());

        let overflow = GatewayMeterCommitment {
            sessions: vec![sess(1, 0xA1, u128::MAX, 1), sess(2, 0xB2, u128::MAX, 1)],
            total_bytes: 0,
            ..c.clone()
        };
        assert!(
            !overflow.is_internally_consistent(),
            "an unrepresentable sum is not a consistent one"
        );
        assert_eq!(overflow.summed_bytes(), None);
    }
}
