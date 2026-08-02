//! The ten-stage, three-party verification of a [`ProxyReceiptBundle`].
//!
//! # Three signatures, and why they are not interchangeable
//!
//! A settled chunk of the allowlisted fetch network carries three signatures
//! over three *different* structs, and collapsing any two of them would erase
//! the property that makes the lane defensible:
//!
//! 1. **Consumer intent** ([`super::receipt::INTENT_TYPEHASH_STR`]) — what was *asked for*,
//!    signed before any byte moved. It fixes the destination entry id, the
//!    operator, the price and the ceiling, so a chunk cannot be re-attributed
//!    afterwards.
//! 2. **Operator claim** ([`super::receipt::RECEIPT_TYPEHASH_STR`]) — what the node *says* it
//!    delivered. This is a claim by the party that is settled for it, and on
//!    its own it is worth nothing.
//! 3. **Gateway witness** ([`WITNESS_TYPEHASH_STR`]) — what the relay
//!    *observed*. This is the one that makes the operator's claim checkable.
//!
//! The third exists because **bandwidth has no public oracle to re-read**. The
//! compute lane's challenger works by re-scraping the same endpoint tomorrow
//! and comparing; the bytes of a proxied response are gone the moment they
//! move, and no later observer can reconstruct them. What replaces the re-read
//! is a *contemporaneous second counter held by a party with no stake in the
//! settlement*: the gateway is the sole ingress and is not compensated per
//! byte, so its count is the adversarially-useful one.
//!
//! The asymmetry inside the witness is load-bearing and is enforced here: the
//! gateway **witnesses** `body_bytes_to_consumer` — which
//! [`ProxyVerifyError::WitnessDisagreesWithClaim`] requires to equal the
//! operator's claimed `bytes_transferred` **exactly**, in both directions, with
//! no tolerance — and merely **re-signs** `node_reported_from_origin`, which
//! nothing in this system observes. That second number is carried, stored and
//! never compared, and no copy anywhere may describe the origin leg as
//! attested.
//!
//! # Order is the security argument
//!
//! Every **structural** refusal is reported before any signature is recovered.
//! Two reasons, both operational: signature recovery is the expensive step, and
//! a caller must be able to tell a malformed submission (retry it) from a
//! forged one (do not). [`VERIFY_STAGE_ORDER`] is the pinned order, and
//! `the_ten_stages_run_in_the_declared_order` proves it *observably* — for
//! every stage `i`, a bundle that violates stages `i..10` simultaneously must
//! report stage `i`. Swapping two calls in [`verify_receipt_bundle`] turns that
//! test red; an ordering comment alone would not.
//!
//! # What this module does NOT do
//!
//! Nothing here issues supply and nothing here destroys supply. It recovers
//! public keys and compares integers.
//!
//! It also does not *persist* anything: `super::store` is the only thing that
//! writes, and it accepts only a [`VerifiedReceipt`] — the type this module is
//! the sole constructor of.
//!
//! # The two lookups this module does not implement
//!
//! [`ProxyPartyDirectory`] is a seam, deliberately. Two of its four answers
//! (which key a consumer handle and a gateway id belong to) come from the
//! curated first-party sets; the other two (which sponsorship cluster an
//! operator wallet and a consumer handle root at) are the anti-fraud lane's,
//! and the cluster-root check is what [`VerifyStage::SelfDealing`] consumes.
//! Address inequality is **not** the test — an operator and a consumer in one
//! household are two addresses — so this module refuses to guess, and asks.

use std::fmt;

use crate::merkle::keccak256;
use crate::sig_verify::{domain_separator, eip712_digest, recover_signer, u256_be, SigError};

use super::fraud::{check_not_self_dealing_by_cluster_root, FraudError};
use super::proxy_merkle::is_proxy_epoch;
use super::receipt::{
    BytesTransferredReceipt, ProxySessionIntent, ReceiptError, PROXY_DOMAIN_NAME,
    PROXY_DOMAIN_VERSION, WITNESS_TYPEHASH_STR,
};
use super::{
    MAX_PRICE_GOAT_WEI_PER_MEBIBYTE, MIN_PRICE_GOAT_WEI_PER_MEBIBYTE, PROXY_CHAIN_ALLOWLIST,
};

/// Longest validity window an intent may declare, in seconds — 24 hours.
///
/// An intent with an unbounded window is a bearer credential with no expiry:
/// every receipt signed under it stays verifiable forever, so a leaked consumer
/// signature keeps producing settleable chunks long after the session it
/// described ended. The bound is generous — sessions are minutes — and it is a
/// **constant, not a knob**, for the same reason there is no tolerance
/// parameter and no chunk-size parameter anywhere in this lane.
pub const MAX_VALIDITY_WINDOW_SECS: u64 = 86_400;

/// Where a bundle stopped. Normative spelling and normative **order**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyStage {
    Structural,
    EpochSpace,
    ChunkSizeRule,
    ValidityWindow,
    IntentBinding,
    CrossFieldAgreement,
    SelfDealing,
    OperatorSignature,
    ConsumerSignature,
    GatewayWitness,
}

impl fmt::Display for VerifyStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            VerifyStage::Structural => "Structural",
            VerifyStage::EpochSpace => "EpochSpace",
            VerifyStage::ChunkSizeRule => "ChunkSizeRule",
            VerifyStage::ValidityWindow => "ValidityWindow",
            VerifyStage::IntentBinding => "IntentBinding",
            VerifyStage::CrossFieldAgreement => "CrossFieldAgreement",
            VerifyStage::SelfDealing => "SelfDealing",
            VerifyStage::OperatorSignature => "OperatorSignature",
            VerifyStage::ConsumerSignature => "ConsumerSignature",
            VerifyStage::GatewayWitness => "GatewayWitness",
        };
        f.write_str(name)
    }
}

/// The ten stages, in the order [`verify_receipt_bundle`] runs them.
///
/// This is a **pin**, not documentation: `the_ten_stages_run_in_the_declared_order`
/// compares it against the order the function is observed to refuse in, so the
/// constant and the code cannot drift apart.
pub const VERIFY_STAGE_ORDER: [VerifyStage; 10] = [
    VerifyStage::Structural,
    VerifyStage::EpochSpace,
    VerifyStage::ChunkSizeRule,
    VerifyStage::ValidityWindow,
    VerifyStage::IntentBinding,
    VerifyStage::CrossFieldAgreement,
    VerifyStage::SelfDealing,
    VerifyStage::OperatorSignature,
    VerifyStage::ConsumerSignature,
    VerifyStage::GatewayWitness,
];

/// Which of the three parties a signature belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningParty {
    Operator,
    Consumer,
    Gateway,
}

impl fmt::Display for SigningParty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SigningParty::Operator => "operator",
            SigningParty::Consumer => "consumer",
            SigningParty::Gateway => "gateway",
        })
    }
}

/// What the gateway saw, signed by the gateway.
///
/// Two counts, and the asymmetry between them is the whole point:
///
/// * `body_bytes_to_consumer` is **witnessed** — response body bytes, after
///   HTTP framing is stripped and chunked transfer-encoding is decoded, as they
///   crossed into the tunnel the gateway is the sole ingress for. This is the
///   settlement basis, and [`VerifyStage::GatewayWitness`] requires it to equal
///   the operator's claim exactly.
/// * `node_reported_from_origin` is **re-signed, not witnessed**. Nothing in
///   this system observes the origin leg. It is carried for diagnostics and is
///   never compared against anything — a test asserts that a bundle whose two
///   counts differ still verifies, so nobody can quietly promote it to a
///   second check and then describe the origin leg as attested.
///
/// Declared here rather than beside [`WITNESS_TYPEHASH_STR`] because the build
/// order puts this task ahead of the meter commitment that the type string's
/// doc comment anticipated, and a struct with no verifier is worse than a
/// verifier that owns its struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayWitness {
    /// The receipt this witness is about, bound by hash so the witness cannot
    /// be lifted onto a different chunk.
    pub receipt_struct_hash: [u8; 32],
    pub gateway_id: [u8; 32],
    /// Witnessed. The settlement basis.
    pub body_bytes_to_consumer: u64,
    /// Re-signed, never witnessed, never a settlement basis.
    pub node_reported_from_origin: u64,
    pub witnessed_at_unix: u64,
}

impl GatewayWitness {
    /// `keccak256(abi.encode(WITNESS_TYPEHASH, …))`, one word per field.
    pub fn witness_struct_hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(32 * 6);
        buf.extend_from_slice(&keccak256(WITNESS_TYPEHASH_STR.as_bytes()));
        buf.extend_from_slice(&self.receipt_struct_hash);
        buf.extend_from_slice(&self.gateway_id);
        buf.extend_from_slice(&u256_be(u128::from(self.body_bytes_to_consumer)));
        buf.extend_from_slice(&u256_be(u128::from(self.node_reported_from_origin)));
        buf.extend_from_slice(&u256_be(u128::from(self.witnessed_at_unix)));
        debug_assert_eq!(buf.len(), 32 * 6);
        keccak256(&buf)
    }

    /// The digest the gateway signs, binding chain id and verifying contract.
    pub fn witness_digest(&self, chain_id: u64, verifying_contract: [u8; 20]) -> [u8; 32] {
        let domain = domain_separator(
            PROXY_DOMAIN_NAME,
            PROXY_DOMAIN_VERSION,
            chain_id,
            verifying_contract,
        );
        eip712_digest(&domain, &self.witness_struct_hash())
    }
}

/// One submission: the three signed objects and the three signatures over them.
///
/// The witness is part of the bundle and not merely a signature, because a
/// signature over nothing is not checkable — the gateway's count has to be
/// *present* for `body_bytes_to_consumer == bytes_transferred` to mean
/// anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyReceiptBundle {
    pub receipt: BytesTransferredReceipt,
    pub intent: ProxySessionIntent,
    pub witness: GatewayWitness,
    /// 65-byte `r‖s‖v` over [`BytesTransferredReceipt::receipt_digest`].
    pub operator_sig: Vec<u8>,
    /// 65-byte `r‖s‖v` over [`ProxySessionIntent::intent_digest`].
    pub consumer_sig: Vec<u8>,
    /// 65-byte `r‖s‖v` over [`GatewayWitness::witness_digest`].
    pub gateway_sig: Vec<u8>,
}

/// The four questions this module cannot answer from the bundle alone.
///
/// The first two resolve an opaque handle to the key that speaks for it; the
/// last two resolve an address or a handle to the sponsorship cluster it roots
/// at, which is what makes [`VerifyStage::SelfDealing`] a real check rather
/// than an address-inequality test that any second wallet defeats.
///
/// `None` means "this lane does not know that party". For the two signer
/// lookups that is a refusal — an unknown consumer or gateway cannot have
/// signed anything this lane accepts. For the two cluster lookups it is **not**
/// a refusal: an unresolvable root is an absence of evidence, and refusing on
/// it would turn every un-enrolled honest consumer into a fraud finding.
/// Whether enrolment is *required* is the anti-fraud lane's decision, not this
/// module's.
pub trait ProxyPartyDirectory {
    fn consumer_signer(&self, consumer_id: &[u8; 32]) -> Option<[u8; 20]>;
    fn gateway_signer(&self, gateway_id: &[u8; 32]) -> Option<[u8; 20]>;
    fn operator_cluster_root(&self, operator_wallet: &[u8; 20]) -> Option<[u8; 32]>;
    fn consumer_cluster_root(&self, consumer_id: &[u8; 32]) -> Option<[u8; 32]>;
}

/// Everything the ten stages need that is not inside the bundle.
pub struct VerifyContext<'a> {
    /// Bound into every EIP-712 digest. Must be in [`PROXY_CHAIN_ALLOWLIST`].
    pub chain_id: u64,
    /// Bound into every EIP-712 digest alongside `chain_id`.
    pub verifying_contract: [u8; 20],
    /// The epoch being settled. A receipt naming any other epoch is refused,
    /// which is the first of the three replay defences (the other two are the
    /// store's two UNIQUE indexes).
    pub epoch_id: u64,
    pub now_unix: u64,
    /// Digest of the allowlist manifest currently in force. An intent naming a
    /// different one is stale.
    pub allowlist_manifest_digest: [u8; 32],
    /// Number of entries in that manifest; an entry id at or past it names
    /// nothing.
    pub allowlist_entry_count: u64,
    pub directory: &'a dyn ProxyPartyDirectory,
}

/// A bundle that cleared all ten stages. The only thing `super::store` accepts.
///
/// It carries the recovered signers rather than re-deriving them, so the store
/// records *who was recovered*, not who the submission claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReceipt {
    pub receipt: BytesTransferredReceipt,
    pub intent: ProxySessionIntent,
    pub witness: GatewayWitness,
    /// `keccak256` of the receipt's canonical JSON bytes — the content hash the
    /// store keys on. **Not** the EIP-712 digest.
    pub receipt_hash: [u8; 32],
    /// The EIP-712 struct hash, kept because the witness binds to it.
    pub receipt_struct_hash: [u8; 32],
    pub intent_struct_hash: [u8; 32],
    pub operator_signer: [u8; 20],
    pub consumer_signer: [u8; 20],
    pub gateway_signer: [u8; 20],
    pub operator_sig: Vec<u8>,
    pub consumer_sig: Vec<u8>,
    pub gateway_sig: Vec<u8>,
    pub chain_id: u64,
    pub verifying_contract: [u8; 20],
}

/// Why a bundle was refused, and at which stage.
///
/// Every variant names exactly one stage ([`ProxyVerifyError::stage`]), and
/// every message is made of byte counts, integer identifiers and hashes.
/// A destination never reaches one:
/// `no_refusal_message_can_carry_a_url_path_query_or_header` sweeps every
/// variant's rendered text with a positive control.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProxyVerifyError {
    // ---- Structural -------------------------------------------------
    #[error("Structural: chain id {chain_id} is not a chain this lane may settle on")]
    ChainNotAllowed { chain_id: u64 },

    #[error("Structural: the {party} signature is absent")]
    SignatureAbsent { party: SigningParty },

    #[error("Structural: the {party} signature is {len} bytes; a secp256k1 signature is 65")]
    SignatureMalformed { party: SigningParty, len: usize },

    #[error("Structural: {field} is all-zero, which is never a real identifier")]
    ZeroField { field: &'static str },

    #[error(
        "Structural: price {price} is outside the accepted band \
         {MIN_PRICE_GOAT_WEI_PER_MEBIBYTE}..={MAX_PRICE_GOAT_WEI_PER_MEBIBYTE} wei per mebibyte"
    )]
    PriceOutOfBand { price: u128 },

    #[error(
        "Structural: validity window {valid_from_unix}..{valid_to_unix} ends before it starts"
    )]
    InvertedValidityWindow {
        valid_from_unix: u64,
        valid_to_unix: u64,
    },

    #[error("Structural: the receipt does not canonicalise: {0}")]
    NotCanonical(ReceiptError),

    // ---- EpochSpace -------------------------------------------------
    #[error("EpochSpace: epoch {epoch_id} is outside the fetch-network epoch id space")]
    EpochOutsideProxySpace { epoch_id: u64 },

    #[error("EpochSpace: receipt names epoch {found}; the epoch being settled is {expected}")]
    EpochMismatch { expected: u64, found: u64 },

    #[error("EpochSpace: the receipt names epoch {receipt}; its intent names {intent}")]
    IntentEpochMismatch { receipt: u64, intent: u64 },

    // ---- ChunkSizeRule ----------------------------------------------
    #[error("ChunkSizeRule: {0}")]
    ChunkSize(ReceiptError),

    // ---- ValidityWindow ---------------------------------------------
    #[error("ValidityWindow: {now_unix} is outside {valid_from_unix}..={valid_to_unix}")]
    OutsideValidityWindow {
        now_unix: u64,
        valid_from_unix: u64,
        valid_to_unix: u64,
    },

    #[error(
        "ValidityWindow: a {seconds}s window is unbounded in practice; the ceiling is \
         {MAX_VALIDITY_WINDOW_SECS}s"
    )]
    UnboundedValidityWindow { seconds: u64 },

    // ---- IntentBinding ----------------------------------------------
    #[error("IntentBinding: the receipt names intent 0x{claimed}; the bundled intent hashes to 0x{bundled}")]
    IntentHashMismatch { claimed: String, bundled: String },

    #[error("IntentBinding: the intent names allowlist manifest 0x{named}; the manifest in force is 0x{in_force}")]
    StaleAllowlistManifest { named: String, in_force: String },

    #[error("IntentBinding: allowlist entry id {entry_id} is past the end of a {entry_count}-entry manifest")]
    AllowlistEntryPastEndOfManifest { entry_id: u64, entry_count: u64 },

    // ---- CrossFieldAgreement ----------------------------------------
    #[error("CrossFieldAgreement: the receipt's {field} disagrees with the signed intent's")]
    FieldDisagreesWithIntent { field: &'static str },

    #[error(
        "CrossFieldAgreement: {bytes} bytes exceeds the intent's agreed ceiling of {max_bytes}"
    )]
    BytesExceedIntentCeiling { bytes: u64, max_bytes: u64 },

    // ---- SelfDealing ------------------------------------------------
    /// The anti-fraud lane's refusal, surfaced verbatim rather than restated.
    ///
    /// The rule lives in `super::fraud` and there is no second copy of it here:
    /// this module supplies the two directory answers and the fraud module
    /// decides. Only [`FraudError::SelfDealing`] is reachable through this
    /// variant — the other four fraud controls are per-EPOCH and run in
    /// `super::aggregate`.
    #[error("fraud: {0}")]
    Fraud(#[from] FraudError),

    // ---- signature stages -------------------------------------------
    #[error("{party}Signature: this lane knows no signing key for that party's identifier")]
    UnknownParty { party: SigningParty },

    #[error("{stage}: signature recovery failed: {source}")]
    Unrecoverable {
        stage: VerifyStage,
        party: SigningParty,
        source: SigError,
    },

    #[error("{stage}: recovered 0x{recovered}, expected 0x{expected}")]
    SignerMismatch {
        stage: VerifyStage,
        recovered: String,
        expected: String,
    },

    // ---- GatewayWitness ---------------------------------------------
    #[error(
        "GatewayWitness: the witness binds receipt 0x{bound}; this bundle's receipt is 0x{actual}"
    )]
    WitnessBoundToAnotherReceipt { bound: String, actual: String },

    #[error(
        "GatewayWitness: the gateway witnessed {witnessed} bytes; the operator claims \
         {claimed}. This comparison is strict equality in both directions and has no \
         tolerance parameter"
    )]
    WitnessDisagreesWithClaim { witnessed: u64, claimed: u64 },

    #[error(
        "GatewayWitness: the witness names gateway 0x{witness}; the receipt names 0x{receipt}"
    )]
    WitnessGatewayMismatch { witness: String, receipt: String },

    #[error("GatewayWitness: witnessed at {witnessed_at_unix}, outside {valid_from_unix}..={valid_to_unix}")]
    WitnessedOutsideValidityWindow {
        witnessed_at_unix: u64,
        valid_from_unix: u64,
        valid_to_unix: u64,
    },
}

impl ProxyVerifyError {
    /// The stage this refusal belongs to. Exhaustive by construction: a new
    /// variant that forgets its stage does not compile.
    pub fn stage(&self) -> VerifyStage {
        match self {
            ProxyVerifyError::ChainNotAllowed { .. }
            | ProxyVerifyError::SignatureAbsent { .. }
            | ProxyVerifyError::SignatureMalformed { .. }
            | ProxyVerifyError::ZeroField { .. }
            | ProxyVerifyError::PriceOutOfBand { .. }
            | ProxyVerifyError::InvertedValidityWindow { .. }
            | ProxyVerifyError::NotCanonical(_) => VerifyStage::Structural,

            ProxyVerifyError::EpochOutsideProxySpace { .. }
            | ProxyVerifyError::EpochMismatch { .. }
            | ProxyVerifyError::IntentEpochMismatch { .. } => VerifyStage::EpochSpace,

            ProxyVerifyError::ChunkSize(_) => VerifyStage::ChunkSizeRule,

            ProxyVerifyError::OutsideValidityWindow { .. }
            | ProxyVerifyError::UnboundedValidityWindow { .. } => VerifyStage::ValidityWindow,

            ProxyVerifyError::IntentHashMismatch { .. }
            | ProxyVerifyError::StaleAllowlistManifest { .. }
            | ProxyVerifyError::AllowlistEntryPastEndOfManifest { .. } => {
                VerifyStage::IntentBinding
            }

            ProxyVerifyError::FieldDisagreesWithIntent { .. }
            | ProxyVerifyError::BytesExceedIntentCeiling { .. } => VerifyStage::CrossFieldAgreement,

            // Only `SelfDealing` is reachable per bundle. The other four fraud
            // controls are per-epoch — they run over a whole epoch's totals in
            // `super::aggregate` and no per-bundle path can produce one. They
            // are filed here anyway, under this module's only fraud stage,
            // because a `_` arm would hide a future wiring mistake instead of
            // reporting it at the stage the operator was told to look at.
            ProxyVerifyError::Fraud(
                FraudError::SelfDealing { .. }
                | FraudError::ClusterOverByteCeiling { .. }
                | FraudError::PairConcentrationExceeded { .. }
                | FraudError::ChunkSequenceGap { .. }
                | FraudError::MalformedSessionTail { .. },
            ) => VerifyStage::SelfDealing,

            ProxyVerifyError::UnknownParty { party } => match party {
                SigningParty::Operator => VerifyStage::OperatorSignature,
                SigningParty::Consumer => VerifyStage::ConsumerSignature,
                SigningParty::Gateway => VerifyStage::GatewayWitness,
            },
            ProxyVerifyError::Unrecoverable { stage, .. }
            | ProxyVerifyError::SignerMismatch { stage, .. } => *stage,

            ProxyVerifyError::WitnessBoundToAnotherReceipt { .. }
            | ProxyVerifyError::WitnessDisagreesWithClaim { .. }
            | ProxyVerifyError::WitnessGatewayMismatch { .. }
            | ProxyVerifyError::WitnessedOutsideValidityWindow { .. } => {
                VerifyStage::GatewayWitness
            }
        }
    }
}

/// `0x`-less lowercase hex, for the error messages above.
fn hx(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Verify a three-party bundle through all ten stages, in
/// [`VERIFY_STAGE_ORDER`].
///
/// The stages are separate functions called in sequence rather than a table of
/// closures, so the order is the control flow itself; the order is *proved* by
/// `the_ten_stages_run_in_the_declared_order` rather than asserted about.
pub fn verify_receipt_bundle(
    bundle: &ProxyReceiptBundle,
    ctx: &VerifyContext<'_>,
) -> Result<VerifiedReceipt, ProxyVerifyError> {
    let receipt_hash = stage_structural(bundle, ctx)?;
    stage_epoch_space(bundle, ctx)?;
    stage_chunk_size_rule(bundle)?;
    stage_validity_window(bundle, ctx)?;
    let intent_struct_hash = stage_intent_binding(bundle, ctx)?;
    stage_cross_field_agreement(bundle)?;
    stage_self_dealing(bundle, ctx)?;

    let receipt_struct_hash = bundle.receipt.receipt_struct_hash();
    let operator_signer = stage_operator_signature(bundle, ctx)?;
    let consumer_signer = stage_consumer_signature(bundle, ctx)?;
    let gateway_signer = stage_gateway_witness(bundle, ctx, &receipt_struct_hash)?;

    Ok(VerifiedReceipt {
        receipt: bundle.receipt.clone(),
        intent: bundle.intent.clone(),
        witness: bundle.witness.clone(),
        receipt_hash,
        receipt_struct_hash,
        intent_struct_hash,
        operator_signer,
        consumer_signer,
        gateway_signer,
        operator_sig: bundle.operator_sig.clone(),
        consumer_sig: bundle.consumer_sig.clone(),
        gateway_sig: bundle.gateway_sig.clone(),
        chain_id: ctx.chain_id,
        verifying_contract: ctx.verifying_contract,
    })
}

/// Stage 1 — shape only, and the deployment the digests are bound to. Returns
/// the canonical receipt hash, which is computed here because "canonicalises at
/// all" is a structural property.
fn stage_structural(
    bundle: &ProxyReceiptBundle,
    ctx: &VerifyContext<'_>,
) -> Result<[u8; 32], ProxyVerifyError> {
    if !PROXY_CHAIN_ALLOWLIST.contains(&ctx.chain_id) {
        return Err(ProxyVerifyError::ChainNotAllowed {
            chain_id: ctx.chain_id,
        });
    }

    for (party, sig) in [
        (SigningParty::Operator, &bundle.operator_sig),
        (SigningParty::Consumer, &bundle.consumer_sig),
        (SigningParty::Gateway, &bundle.gateway_sig),
    ] {
        if sig.is_empty() {
            return Err(ProxyVerifyError::SignatureAbsent { party });
        }
        if sig.len() != 65 {
            return Err(ProxyVerifyError::SignatureMalformed {
                party,
                len: sig.len(),
            });
        }
    }

    let r = &bundle.receipt;
    for (field, is_zero) in [
        ("session_id", r.session_id == [0u8; 32]),
        ("consumer_id", r.consumer_id == [0u8; 32]),
        ("gateway_id", r.gateway_id == [0u8; 32]),
        ("intent_hash", r.intent_hash == [0u8; 32]),
        ("consent_record_hash", r.consent_record_hash == [0u8; 32]),
        (
            "allowlist_manifest_digest",
            r.allowlist_manifest_digest == [0u8; 32],
        ),
        ("operator_wallet", r.operator_wallet == [0u8; 20]),
    ] {
        if is_zero {
            return Err(ProxyVerifyError::ZeroField { field });
        }
    }

    if !(MIN_PRICE_GOAT_WEI_PER_MEBIBYTE..=MAX_PRICE_GOAT_WEI_PER_MEBIBYTE)
        .contains(&r.price_goat_wei_per_mebibyte)
    {
        return Err(ProxyVerifyError::PriceOutOfBand {
            price: r.price_goat_wei_per_mebibyte,
        });
    }

    if r.valid_to_unix <= r.valid_from_unix {
        return Err(ProxyVerifyError::InvertedValidityWindow {
            valid_from_unix: r.valid_from_unix,
            valid_to_unix: r.valid_to_unix,
        });
    }

    r.canonical_hash().map_err(ProxyVerifyError::NotCanonical)
}

/// Stage 2 — the signed `epoch_id` is the first of the three replay defences.
fn stage_epoch_space(
    bundle: &ProxyReceiptBundle,
    ctx: &VerifyContext<'_>,
) -> Result<(), ProxyVerifyError> {
    let epoch_id = bundle.receipt.epoch_id;
    if !is_proxy_epoch(epoch_id) {
        return Err(ProxyVerifyError::EpochOutsideProxySpace { epoch_id });
    }
    if epoch_id != ctx.epoch_id {
        return Err(ProxyVerifyError::EpochMismatch {
            expected: ctx.epoch_id,
            found: epoch_id,
        });
    }
    if bundle.intent.epoch_id != epoch_id {
        return Err(ProxyVerifyError::IntentEpochMismatch {
            receipt: epoch_id,
            intent: bundle.intent.epoch_id,
        });
    }
    Ok(())
}

/// Stage 3 — interim chunks are exact, final chunks are bounded, zero is
/// neither.
fn stage_chunk_size_rule(bundle: &ProxyReceiptBundle) -> Result<(), ProxyVerifyError> {
    bundle
        .receipt
        .check_chunk_size()
        .map_err(ProxyVerifyError::ChunkSize)
}

/// Stage 4 — the window must contain `now` and must not be unbounded.
fn stage_validity_window(
    bundle: &ProxyReceiptBundle,
    ctx: &VerifyContext<'_>,
) -> Result<(), ProxyVerifyError> {
    let r = &bundle.receipt;
    // `stage_structural` already refused `valid_to <= valid_from`, so this
    // subtraction cannot wrap.
    let seconds = r.valid_to_unix - r.valid_from_unix;
    if seconds > MAX_VALIDITY_WINDOW_SECS {
        return Err(ProxyVerifyError::UnboundedValidityWindow { seconds });
    }
    if ctx.now_unix < r.valid_from_unix || ctx.now_unix > r.valid_to_unix {
        return Err(ProxyVerifyError::OutsideValidityWindow {
            now_unix: ctx.now_unix,
            valid_from_unix: r.valid_from_unix,
            valid_to_unix: r.valid_to_unix,
        });
    }
    Ok(())
}

/// Stage 5 — the receipt names the intent it was bundled with, and that intent
/// names a live manifest entry. Returns the intent's struct hash.
fn stage_intent_binding(
    bundle: &ProxyReceiptBundle,
    ctx: &VerifyContext<'_>,
) -> Result<[u8; 32], ProxyVerifyError> {
    let bundled = bundle.intent.intent_struct_hash();
    if bundle.receipt.intent_hash != bundled {
        return Err(ProxyVerifyError::IntentHashMismatch {
            claimed: hx(&bundle.receipt.intent_hash),
            bundled: hx(&bundled),
        });
    }
    if bundle.intent.allowlist_manifest_digest != ctx.allowlist_manifest_digest {
        return Err(ProxyVerifyError::StaleAllowlistManifest {
            named: hx(&bundle.intent.allowlist_manifest_digest),
            in_force: hx(&ctx.allowlist_manifest_digest),
        });
    }
    if bundle.intent.allowlist_entry_id >= ctx.allowlist_entry_count {
        return Err(ProxyVerifyError::AllowlistEntryPastEndOfManifest {
            entry_id: bundle.intent.allowlist_entry_id,
            entry_count: ctx.allowlist_entry_count,
        });
    }
    Ok(bundled)
}

/// Stage 6 — every field the two signed structs share must agree.
///
/// Stage 5 proved the receipt names *this* intent; it did not prove the receipt
/// copied the intent's terms correctly, and an operator who quietly raises the
/// price between intent and receipt is settled at the raised one otherwise.
fn stage_cross_field_agreement(bundle: &ProxyReceiptBundle) -> Result<(), ProxyVerifyError> {
    let (r, i) = (&bundle.receipt, &bundle.intent);
    for (field, agrees) in [
        ("session_id", r.session_id == i.session_id),
        ("operator_wallet", r.operator_wallet == i.operator_wallet),
        ("consumer_id", r.consumer_id == i.consumer_id),
        ("gateway_id", r.gateway_id == i.gateway_id),
        (
            "allowlist_entry_id",
            r.allowlist_entry_id == i.allowlist_entry_id,
        ),
        (
            "allowlist_manifest_digest",
            r.allowlist_manifest_digest == i.allowlist_manifest_digest,
        ),
        ("valid_from_unix", r.valid_from_unix == i.valid_from_unix),
        ("valid_to_unix", r.valid_to_unix == i.valid_to_unix),
        (
            "price_goat_wei_per_mebibyte",
            r.price_goat_wei_per_mebibyte == i.price_goat_wei_per_mebibyte,
        ),
    ] {
        if !agrees {
            return Err(ProxyVerifyError::FieldDisagreesWithIntent { field });
        }
    }
    if r.bytes_transferred > i.max_bytes {
        return Err(ProxyVerifyError::BytesExceedIntentCeiling {
            bytes: r.bytes_transferred,
            max_bytes: i.max_bytes,
        });
    }
    Ok(())
}

/// Stage 7 — operator and consumer must not be the same household.
///
/// The test is the **sponsorship cluster root**, not address inequality: two
/// addresses are free, a shared cluster root is not. Both roots must resolve
/// for this to fire — see [`ProxyPartyDirectory`] for why an unresolvable root
/// is an absence of evidence rather than a finding.
///
/// This module performs the two lookups and nothing else. The comparison is
/// `super::fraud`'s, reached through the trait's answers rather than through a
/// second directory of its own, so the per-bundle stage and the per-epoch
/// controls cannot come to different conclusions about what a household is.
fn stage_self_dealing(
    bundle: &ProxyReceiptBundle,
    ctx: &VerifyContext<'_>,
) -> Result<(), ProxyVerifyError> {
    let operator_root = ctx
        .directory
        .operator_cluster_root(&bundle.receipt.operator_wallet);
    let consumer_root = ctx
        .directory
        .consumer_cluster_root(&bundle.receipt.consumer_id);
    Ok(check_not_self_dealing_by_cluster_root(
        &bundle.receipt.consumer_id,
        &bundle.receipt.operator_wallet,
        consumer_root,
        operator_root,
    )?)
}

/// Stage 8 — the operator's claim was signed by the wallet it settles to.
///
/// This is the first stage that recovers a public key, and everything above it
/// is deliberately cheaper.
fn stage_operator_signature(
    bundle: &ProxyReceiptBundle,
    ctx: &VerifyContext<'_>,
) -> Result<[u8; 20], ProxyVerifyError> {
    let digest = bundle
        .receipt
        .receipt_digest(ctx.chain_id, ctx.verifying_contract);
    recover_expecting(
        VerifyStage::OperatorSignature,
        SigningParty::Operator,
        &digest,
        &bundle.operator_sig,
        bundle.receipt.operator_wallet,
    )
}

/// Stage 9 — the consumer's intent was signed by the key that handle belongs
/// to.
fn stage_consumer_signature(
    bundle: &ProxyReceiptBundle,
    ctx: &VerifyContext<'_>,
) -> Result<[u8; 20], ProxyVerifyError> {
    let expected = ctx
        .directory
        .consumer_signer(&bundle.receipt.consumer_id)
        .ok_or(ProxyVerifyError::UnknownParty {
            party: SigningParty::Consumer,
        })?;
    let digest = bundle
        .intent
        .intent_digest(ctx.chain_id, ctx.verifying_contract);
    recover_expecting(
        VerifyStage::ConsumerSignature,
        SigningParty::Consumer,
        &digest,
        &bundle.consumer_sig,
        expected,
    )
}

/// Stage 10 — the relay's own count, and the only stage that can settle a
/// dispute about how many bytes moved.
///
/// Four checks, and the third is the load-bearing one:
///
/// 1. the witness binds *this* receipt's struct hash;
/// 2. it names the same gateway the receipt does;
/// 3. `body_bytes_to_consumer == bytes_transferred`, **exactly**, in both
///    directions — there is no tolerance parameter here and none anywhere else
///    in this lane;
/// 4. it was observed inside the window the two parties agreed to.
///
/// `node_reported_from_origin` is read by none of them.
fn stage_gateway_witness(
    bundle: &ProxyReceiptBundle,
    ctx: &VerifyContext<'_>,
    receipt_struct_hash: &[u8; 32],
) -> Result<[u8; 20], ProxyVerifyError> {
    let w = &bundle.witness;
    if &w.receipt_struct_hash != receipt_struct_hash {
        return Err(ProxyVerifyError::WitnessBoundToAnotherReceipt {
            bound: hx(&w.receipt_struct_hash),
            actual: hx(receipt_struct_hash),
        });
    }
    if w.gateway_id != bundle.receipt.gateway_id {
        return Err(ProxyVerifyError::WitnessGatewayMismatch {
            witness: hx(&w.gateway_id),
            receipt: hx(&bundle.receipt.gateway_id),
        });
    }
    if w.body_bytes_to_consumer != bundle.receipt.bytes_transferred {
        return Err(ProxyVerifyError::WitnessDisagreesWithClaim {
            witnessed: w.body_bytes_to_consumer,
            claimed: bundle.receipt.bytes_transferred,
        });
    }
    if w.witnessed_at_unix < bundle.receipt.valid_from_unix
        || w.witnessed_at_unix > bundle.receipt.valid_to_unix
    {
        return Err(ProxyVerifyError::WitnessedOutsideValidityWindow {
            witnessed_at_unix: w.witnessed_at_unix,
            valid_from_unix: bundle.receipt.valid_from_unix,
            valid_to_unix: bundle.receipt.valid_to_unix,
        });
    }

    let expected =
        ctx.directory
            .gateway_signer(&w.gateway_id)
            .ok_or(ProxyVerifyError::UnknownParty {
                party: SigningParty::Gateway,
            })?;
    let digest = w.witness_digest(ctx.chain_id, ctx.verifying_contract);
    recover_expecting(
        VerifyStage::GatewayWitness,
        SigningParty::Gateway,
        &digest,
        &bundle.gateway_sig,
        expected,
    )
}

/// Recover through the crate's one secp256k1 path and compare against the
/// address this lane expects.
fn recover_expecting(
    stage: VerifyStage,
    party: SigningParty,
    digest: &[u8; 32],
    signature: &[u8],
    expected: [u8; 20],
) -> Result<[u8; 20], ProxyVerifyError> {
    let recovered =
        recover_signer(digest, signature).map_err(|source| ProxyVerifyError::Unrecoverable {
            stage,
            party,
            source,
        })?;
    if recovered != expected {
        return Err(ProxyVerifyError::SignerMismatch {
            stage,
            recovered: hx(&recovered),
            expected: hx(&expected),
        });
    }
    Ok(recovered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::str::FromStr;

    use alloy::primitives::B256;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;

    use crate::proxy::receipt::{ChunkKind, PROXY_EPOCH_BASE, RECEIPT_CHUNK_BYTES};

    // Anvil accounts #0..#3. Addresses are derived from the keys at runtime
    // rather than transcribed, so a typo cannot make a "different key" test
    // pass for the wrong reason.
    const OPERATOR_PK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const CONSUMER_PK: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    const GATEWAY_PK: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
    const STRANGER_PK: &str = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";

    const SESSION_ID: [u8; 32] = [0x5E; 32];
    const CONSUMER_ID: [u8; 32] = [0xC2; 32];
    const GATEWAY_ID: [u8; 32] = [0x67; 32];
    const MANIFEST_DIGEST: [u8; 32] = [0xD3; 32];
    const VERIFYING_CONTRACT: [u8; 20] = [0x11; 20];
    const ENTRY_COUNT: u64 = 12;

    #[derive(Clone, Default)]
    struct TestDirectory {
        consumer_signers: HashMap<[u8; 32], [u8; 20]>,
        gateway_signers: HashMap<[u8; 32], [u8; 20]>,
        operator_roots: HashMap<[u8; 20], [u8; 32]>,
        consumer_roots: HashMap<[u8; 32], [u8; 32]>,
    }

    impl ProxyPartyDirectory for TestDirectory {
        fn consumer_signer(&self, consumer_id: &[u8; 32]) -> Option<[u8; 20]> {
            self.consumer_signers.get(consumer_id).copied()
        }
        fn gateway_signer(&self, gateway_id: &[u8; 32]) -> Option<[u8; 20]> {
            self.gateway_signers.get(gateway_id).copied()
        }
        fn operator_cluster_root(&self, operator_wallet: &[u8; 20]) -> Option<[u8; 32]> {
            self.operator_roots.get(operator_wallet).copied()
        }
        fn consumer_cluster_root(&self, consumer_id: &[u8; 32]) -> Option<[u8; 32]> {
            self.consumer_roots.get(consumer_id).copied()
        }
    }

    fn signer(pk: &str) -> PrivateKeySigner {
        PrivateKeySigner::from_str(pk).expect("a fixed test key must parse")
    }

    fn sign(pk: &str, digest: [u8; 32]) -> Vec<u8> {
        signer(pk)
            .sign_hash_sync(&B256::from(digest))
            .expect("signing a 32-byte prehash cannot fail")
            .as_bytes()
            .to_vec()
    }

    fn address(pk: &str) -> [u8; 20] {
        signer(pk).address().into_array()
    }

    /// Everything a stage needs, plus the keys to re-sign after a mutation.
    struct Fixture {
        bundle: ProxyReceiptBundle,
        dir: TestDirectory,
        chain_id: u64,
        verifying_contract: [u8; 20],
        epoch_id: u64,
        now_unix: u64,
        manifest_digest: [u8; 32],
        entry_count: u64,
    }

    impl Fixture {
        /// A bundle that verifies. Every refusal test below is this, minus one
        /// thing.
        fn well_formed() -> Self {
            let epoch_id = PROXY_EPOCH_BASE + 20_664;
            let valid_from = 1_800_000_000u64;
            let valid_to = valid_from + 3_600;
            let operator = address(OPERATOR_PK);

            let intent = ProxySessionIntent {
                epoch_id,
                session_id: SESSION_ID,
                operator_wallet: operator,
                consumer_id: CONSUMER_ID,
                gateway_id: GATEWAY_ID,
                allowlist_entry_id: 7,
                allowlist_manifest_digest: MANIFEST_DIGEST,
                max_bytes: 104_857_600,
                valid_from_unix: valid_from,
                valid_to_unix: valid_to,
                price_goat_wei_per_mebibyte: 1_000_000_000_000,
            };

            let receipt = BytesTransferredReceipt {
                epoch_id,
                session_id: SESSION_ID,
                chunk_seq: 0,
                chunk_kind: ChunkKind::Final,
                operator_wallet: operator,
                consumer_id: CONSUMER_ID,
                gateway_id: GATEWAY_ID,
                allowlist_entry_id: 7,
                allowlist_manifest_digest: MANIFEST_DIGEST,
                bytes_transferred: 10_485_759,
                counter: 42,
                intent_hash: intent.intent_struct_hash(),
                consent_record_hash: [0x2C; 32],
                valid_from_unix: valid_from,
                valid_to_unix: valid_to,
                price_goat_wei_per_mebibyte: 1_000_000_000_000,
            };

            let witness = GatewayWitness {
                receipt_struct_hash: receipt.receipt_struct_hash(),
                gateway_id: GATEWAY_ID,
                body_bytes_to_consumer: receipt.bytes_transferred,
                // Deliberately NOT equal to the witnessed count: the origin leg
                // is re-signed, never witnessed, and never compared.
                node_reported_from_origin: receipt.bytes_transferred + 4_096,
                witnessed_at_unix: valid_from + 10,
            };

            let mut dir = TestDirectory::default();
            dir.consumer_signers
                .insert(CONSUMER_ID, address(CONSUMER_PK));
            dir.gateway_signers.insert(GATEWAY_ID, address(GATEWAY_PK));
            dir.operator_roots.insert(operator, [0xAA; 32]);
            dir.consumer_roots.insert(CONSUMER_ID, [0xBB; 32]);

            let mut fixture = Fixture {
                bundle: ProxyReceiptBundle {
                    receipt,
                    intent,
                    witness,
                    operator_sig: Vec::new(),
                    consumer_sig: Vec::new(),
                    gateway_sig: Vec::new(),
                },
                dir,
                chain_id: 31_337,
                verifying_contract: VERIFYING_CONTRACT,
                epoch_id,
                now_unix: valid_from + 60,
                manifest_digest: MANIFEST_DIGEST,
                entry_count: ENTRY_COUNT,
            };
            fixture.resign();
            fixture
        }

        /// Re-sign all three objects as they currently stand.
        fn resign(&mut self) {
            let chain = self.chain_id;
            let vc = self.verifying_contract;
            self.bundle.operator_sig =
                sign(OPERATOR_PK, self.bundle.receipt.receipt_digest(chain, vc));
            self.bundle.consumer_sig =
                sign(CONSUMER_PK, self.bundle.intent.intent_digest(chain, vc));
            self.bundle.gateway_sig =
                sign(GATEWAY_PK, self.bundle.witness.witness_digest(chain, vc));
        }

        fn ctx(&self) -> VerifyContext<'_> {
            VerifyContext {
                chain_id: self.chain_id,
                verifying_contract: self.verifying_contract,
                epoch_id: self.epoch_id,
                now_unix: self.now_unix,
                allowlist_manifest_digest: self.manifest_digest,
                allowlist_entry_count: self.entry_count,
                directory: &self.dir,
            }
        }

        fn verify(&self) -> Result<VerifiedReceipt, ProxyVerifyError> {
            verify_receipt_bundle(&self.bundle, &self.ctx())
        }

        fn refusal(&self) -> ProxyVerifyError {
            self.verify()
                .expect_err("this fixture is deliberately broken and must be refused")
        }
    }

    /// POSITIVE CONTROL for every refusal test in this module.
    ///
    /// Without it, each `expect_err` below also passes against a
    /// `verify_receipt_bundle` that refuses everything unconditionally — which
    /// is the single most likely way this file breaks and the least likely to
    /// be noticed.
    ///
    /// Mutations this detects: any stage that refuses a well-formed bundle;
    /// recovering the operator against the intent digest (or any other
    /// digest/party swap); dropping the domain binding so the recovered address
    /// is garbage.
    #[test]
    fn a_well_formed_three_party_bundle_verifies() {
        let f = Fixture::well_formed();
        let v = f.verify().expect("a well-formed bundle must verify");

        // The three recovered signers are three DIFFERENT keys, recovered from
        // three DIFFERENT digests. If any two stages shared a digest or a
        // party, at least two of these would collapse onto one address.
        assert_eq!(v.operator_signer, address(OPERATOR_PK));
        assert_eq!(v.consumer_signer, address(CONSUMER_PK));
        assert_eq!(v.gateway_signer, address(GATEWAY_PK));
        assert_ne!(v.operator_signer, v.consumer_signer);
        assert_ne!(v.consumer_signer, v.gateway_signer);
        assert_ne!(v.operator_signer, v.gateway_signer);

        // The operator is settled to the wallet inside the signed struct, and
        // that is the wallet that signed it.
        assert_eq!(v.operator_signer, v.receipt.operator_wallet);

        // Carried-forward hashes are the real ones, not defaults.
        assert_eq!(
            v.receipt_hash,
            f.bundle.receipt.canonical_hash().expect("canonicalises")
        );
        assert_eq!(
            v.receipt_struct_hash,
            f.bundle.receipt.receipt_struct_hash()
        );
        assert_eq!(v.intent_struct_hash, f.bundle.intent.intent_struct_hash());
        assert_ne!(v.receipt_hash, v.receipt_struct_hash);
        assert_eq!(v.chain_id, 31_337);
        assert_eq!(v.verifying_contract, VERIFYING_CONTRACT);
    }

    /// The witness is what replaces the missing public oracle, so a bundle
    /// without one is not a weaker receipt — it is not a receipt.
    ///
    /// Mutations this detects: treating an absent signature as an empty-but-ok
    /// one; checking only the operator and consumer signatures; deferring the
    /// length check into the recovery step, which would report
    /// `GatewayWitness` instead of `Structural`.
    #[test]
    fn a_receipt_without_a_gateway_witness_signature_is_refused() {
        let mut f = Fixture::well_formed();
        f.bundle.gateway_sig.clear();
        let err = f.refusal();
        assert_eq!(
            err,
            ProxyVerifyError::SignatureAbsent {
                party: SigningParty::Gateway
            }
        );
        assert_eq!(err.stage(), VerifyStage::Structural);

        // A present-but-truncated signature is a different refusal, so the
        // absence check above is not just "len != 65" wearing a hat.
        let mut f = Fixture::well_formed();
        f.bundle.gateway_sig.truncate(64);
        assert_eq!(
            f.refusal(),
            ProxyVerifyError::SignatureMalformed {
                party: SigningParty::Gateway,
                len: 64
            }
        );

        // Negative control: restoring it verifies.
        let f = Fixture::well_formed();
        assert!(f.verify().is_ok());
    }

    /// A valid signature by the wrong key is the forgery this lane exists to
    /// refuse.
    ///
    /// Mutations this detects: comparing recovered signers against the
    /// *submitted* address instead of the one inside the signed struct;
    /// dropping the `recovered != expected` arm entirely; accepting any of the
    /// three parties' signatures for another party's slot.
    #[test]
    fn an_operator_signature_from_a_different_key_is_refused() {
        let mut f = Fixture::well_formed();
        let digest = f
            .bundle
            .receipt
            .receipt_digest(f.chain_id, f.verifying_contract);
        // A perfectly well-formed signature over the correct digest — by
        // somebody else.
        f.bundle.operator_sig = sign(STRANGER_PK, digest);

        let err = f.refusal();
        assert_eq!(err.stage(), VerifyStage::OperatorSignature);
        assert_eq!(
            err,
            ProxyVerifyError::SignerMismatch {
                stage: VerifyStage::OperatorSignature,
                recovered: hx(&address(STRANGER_PK)),
                expected: hx(&address(OPERATOR_PK)),
            }
        );

        // The same substitution at the other two parties is refused at their
        // own stages, so no slot accepts a stranger.
        let mut f = Fixture::well_formed();
        f.bundle.consumer_sig = sign(
            STRANGER_PK,
            f.bundle
                .intent
                .intent_digest(f.chain_id, f.verifying_contract),
        );
        assert_eq!(f.refusal().stage(), VerifyStage::ConsumerSignature);

        let mut f = Fixture::well_formed();
        f.bundle.gateway_sig = sign(
            STRANGER_PK,
            f.bundle
                .witness
                .witness_digest(f.chain_id, f.verifying_contract),
        );
        assert_eq!(f.refusal().stage(), VerifyStage::GatewayWitness);

        // And the three signatures are not interchangeable: the operator's own
        // signature, moved into the consumer slot, is refused.
        let mut f = Fixture::well_formed();
        f.bundle.consumer_sig = f.bundle.operator_sig.clone();
        assert_eq!(f.refusal().stage(), VerifyStage::ConsumerSignature);
    }

    /// The receipt binds to the intent by hash, so a bundle carrying a
    /// different intent than the one signed is refused before any key is
    /// recovered.
    ///
    /// Mutations this detects: comparing the intent hash against the intent's
    /// *canonical* hash rather than its EIP-712 struct hash; skipping the
    /// comparison when the intent is present; moving the check after the
    /// signature stages.
    #[test]
    fn a_receipt_whose_intent_hash_does_not_match_the_bundled_intent_is_refused() {
        let mut f = Fixture::well_formed();
        f.bundle.receipt.intent_hash = [0x99; 32];
        f.resign();
        let err = f.refusal();
        assert_eq!(err.stage(), VerifyStage::IntentBinding);
        assert!(matches!(err, ProxyVerifyError::IntentHashMismatch { .. }));

        // The other direction: keep the receipt's hash, swap the intent. A
        // substituted intent with a *lower price* is the attack this closes.
        let mut f = Fixture::well_formed();
        f.bundle.intent.price_goat_wei_per_mebibyte = 1;
        f.resign();
        assert_eq!(f.refusal().stage(), VerifyStage::IntentBinding);
    }

    /// Every digest binds `chainId` and the verifying contract, so a signature
    /// gathered for one deployment is worthless at another.
    ///
    /// Mutations this detects: dropping `chain_id` or `verifying_contract` from
    /// `domain_separator`; verifying against a hard-coded chain id instead of
    /// the context's; reusing one domain separator across deployments.
    #[test]
    fn a_signature_made_for_another_chain_id_or_contract_is_refused() {
        // Signed for Base Sepolia, verified on Anvil. Both are allowlisted, so
        // this is a domain refusal and not a chain-allowlist one.
        let mut f = Fixture::well_formed();
        f.chain_id = 84_532;
        f.resign();
        f.chain_id = 31_337;
        let err = f.refusal();
        assert_eq!(err.stage(), VerifyStage::OperatorSignature);
        assert!(matches!(err, ProxyVerifyError::SignerMismatch { .. }));

        // Same chain, different verifying contract.
        let mut f = Fixture::well_formed();
        f.verifying_contract = [0x22; 20];
        f.resign();
        f.verifying_contract = VERIFYING_CONTRACT;
        assert_eq!(f.refusal().stage(), VerifyStage::OperatorSignature);

        // A chain this lane may not settle on at all is refused first, at
        // Structural — before a single key is recovered.
        let mut f = Fixture::well_formed();
        f.chain_id = 1;
        f.resign();
        assert_eq!(
            f.refusal(),
            ProxyVerifyError::ChainNotAllowed { chain_id: 1 }
        );

        // Negative control: the untouched fixture verifies, so the three
        // refusals above are the domain binding firing.
        assert!(Fixture::well_formed().verify().is_ok());
    }

    /// A window that has closed, and a window that never closes, are both
    /// refused — the second is the one that would otherwise go unnoticed.
    ///
    /// Mutations this detects: dropping the `now` bound; using `<`/`>` where
    /// `<=`/`>=` belongs at the edges; removing [`MAX_VALIDITY_WINDOW_SECS`],
    /// which turns an intent into a bearer credential with no expiry.
    #[test]
    fn a_receipt_outside_its_validity_window_or_with_an_unbounded_window_is_refused() {
        // After the window.
        let mut f = Fixture::well_formed();
        f.now_unix = f.bundle.receipt.valid_to_unix + 1;
        let err = f.refusal();
        assert_eq!(err.stage(), VerifyStage::ValidityWindow);
        assert!(matches!(
            err,
            ProxyVerifyError::OutsideValidityWindow { .. }
        ));

        // Before it.
        let mut f = Fixture::well_formed();
        f.now_unix = f.bundle.receipt.valid_from_unix - 1;
        assert_eq!(f.refusal().stage(), VerifyStage::ValidityWindow);

        // Both edges are INSIDE. Without these two the refusals above also
        // pass against an off-by-one that rejects the boundary seconds.
        for edge in [
            Fixture::well_formed().bundle.receipt.valid_from_unix,
            Fixture::well_formed().bundle.receipt.valid_to_unix,
        ] {
            let mut f = Fixture::well_formed();
            f.now_unix = edge;
            assert!(f.verify().is_ok(), "second {edge} is inside the window");
        }

        // Unbounded: one second past the ceiling, with `now` comfortably
        // inside, so this can only be the duration check firing.
        let mut f = Fixture::well_formed();
        f.bundle.receipt.valid_to_unix =
            f.bundle.receipt.valid_from_unix + MAX_VALIDITY_WINDOW_SECS + 1;
        f.bundle.intent.valid_to_unix = f.bundle.receipt.valid_to_unix;
        f.bundle.receipt.intent_hash = f.bundle.intent.intent_struct_hash();
        f.bundle.witness.receipt_struct_hash = f.bundle.receipt.receipt_struct_hash();
        f.resign();
        assert_eq!(
            f.refusal(),
            ProxyVerifyError::UnboundedValidityWindow {
                seconds: MAX_VALIDITY_WINDOW_SECS + 1
            }
        );

        // Exactly at the ceiling is accepted, so the refusal above is a
        // boundary and not a blanket. Editing the intent moves its struct
        // hash, so the receipt's `intent_hash` and the witness's binding are
        // both re-derived — otherwise this would fail at `IntentBinding` and
        // "prove" the ceiling for the wrong reason.
        let mut f = Fixture::well_formed();
        f.bundle.receipt.valid_to_unix =
            f.bundle.receipt.valid_from_unix + MAX_VALIDITY_WINDOW_SECS;
        f.bundle.intent.valid_to_unix = f.bundle.receipt.valid_to_unix;
        f.bundle.receipt.intent_hash = f.bundle.intent.intent_struct_hash();
        f.bundle.witness.receipt_struct_hash = f.bundle.receipt.receipt_struct_hash();
        f.resign();
        assert_eq!(f.verify().map(|_| ()), Ok(()));

        // An inverted window is structural, not a window refusal: it is
        // nonsense regardless of when it is read.
        let mut f = Fixture::well_formed();
        f.bundle.receipt.valid_to_unix = f.bundle.receipt.valid_from_unix;
        f.resign();
        assert_eq!(f.refusal().stage(), VerifyStage::Structural);
    }

    /// The signed `epoch_id` is the first of three independent replay
    /// defences, and it is the one that works before the receipt ever reaches
    /// the store.
    ///
    /// Mutations this detects: dropping `epoch_id` from the comparison against
    /// the settling epoch; accepting a receipt whose intent names another
    /// epoch; letting a non-fetch-network epoch id through, which would let a
    /// compute-lane epoch be settled here.
    #[test]
    fn a_receipt_replayed_into_a_later_epoch_is_rejected_by_the_signed_epoch_id() {
        // The whole bundle, valid for epoch N, resubmitted while N+1 settles.
        let f0 = Fixture::well_formed();
        let mut f = Fixture::well_formed();
        f.epoch_id = f0.epoch_id + 1;
        let err = f.refusal();
        assert_eq!(
            err,
            ProxyVerifyError::EpochMismatch {
                expected: f0.epoch_id + 1,
                found: f0.epoch_id,
            }
        );
        assert_eq!(err.stage(), VerifyStage::EpochSpace);

        // Re-signing it for the later epoch does not help either, because the
        // intent still names the original one.
        let mut f = Fixture::well_formed();
        f.epoch_id += 1;
        f.bundle.receipt.epoch_id = f.epoch_id;
        f.bundle.witness.receipt_struct_hash = f.bundle.receipt.receipt_struct_hash();
        f.resign();
        assert!(matches!(
            f.refusal(),
            ProxyVerifyError::IntentEpochMismatch { .. }
        ));

        // A daily compute epoch id can never be settled on this lane.
        let mut f = Fixture::well_formed();
        f.epoch_id = 20_260_731;
        f.bundle.receipt.epoch_id = f.epoch_id;
        f.bundle.intent.epoch_id = f.epoch_id;
        f.bundle.witness.receipt_struct_hash = f.bundle.receipt.receipt_struct_hash();
        f.resign();
        assert_eq!(
            f.refusal(),
            ProxyVerifyError::EpochOutsideProxySpace {
                epoch_id: 20_260_731
            }
        );
    }

    /// The allowlist manifest is versioned by digest, so an intent signed
    /// against a manifest that has since been curated is refused rather than
    /// silently re-interpreted against the new entry list.
    ///
    /// Mutations this detects: comparing the *receipt's* manifest digest
    /// instead of the intent's (the receipt copies it, the intent is what the
    /// consumer signed); dropping the comparison; comparing entry ids across
    /// manifests, which is exactly the re-interpretation this prevents.
    #[test]
    fn an_intent_naming_a_stale_allowlist_manifest_is_refused() {
        let mut f = Fixture::well_formed();
        f.manifest_digest = [0xEE; 32];
        let err = f.refusal();
        assert_eq!(err.stage(), VerifyStage::IntentBinding);
        assert_eq!(
            err,
            ProxyVerifyError::StaleAllowlistManifest {
                named: hx(&MANIFEST_DIGEST),
                in_force: hx(&[0xEEu8; 32]),
            }
        );

        // Negative control: the manifest in force verifies.
        assert!(Fixture::well_formed().verify().is_ok());
    }

    /// An entry id is an index into a finite curated manifest. One past the end
    /// names nothing, and a lane that accepted it would be settling traffic to
    /// a destination nobody curated.
    ///
    /// Mutations this detects: `>` instead of `>=` (which admits exactly the
    /// one-past-the-end id); comparing against a hard-coded ceiling; dropping
    /// the check when the manifest digest matches.
    #[test]
    fn an_allowlist_entry_id_past_the_end_of_the_manifest_is_refused() {
        // The last valid index is ENTRY_COUNT - 1.
        let mut f = Fixture::well_formed();
        f.bundle.intent.allowlist_entry_id = ENTRY_COUNT;
        f.bundle.receipt.allowlist_entry_id = ENTRY_COUNT;
        f.bundle.receipt.intent_hash = f.bundle.intent.intent_struct_hash();
        f.bundle.witness.receipt_struct_hash = f.bundle.receipt.receipt_struct_hash();
        f.resign();
        assert_eq!(
            f.refusal(),
            ProxyVerifyError::AllowlistEntryPastEndOfManifest {
                entry_id: ENTRY_COUNT,
                entry_count: ENTRY_COUNT,
            }
        );

        // The last in-range id is accepted, so the refusal above is a boundary
        // rather than a function that refuses every id.
        let mut f = Fixture::well_formed();
        f.bundle.intent.allowlist_entry_id = ENTRY_COUNT - 1;
        f.bundle.receipt.allowlist_entry_id = ENTRY_COUNT - 1;
        f.bundle.receipt.intent_hash = f.bundle.intent.intent_struct_hash();
        f.bundle.witness.receipt_struct_hash = f.bundle.receipt.receipt_struct_hash();
        f.resign();
        assert!(f.verify().is_ok());

        // An empty manifest admits nothing at all, including id 0.
        let mut f = Fixture::well_formed();
        f.entry_count = 0;
        f.bundle.intent.allowlist_entry_id = 0;
        f.bundle.receipt.allowlist_entry_id = 0;
        f.bundle.receipt.intent_hash = f.bundle.intent.intent_struct_hash();
        f.bundle.witness.receipt_struct_hash = f.bundle.receipt.receipt_struct_hash();
        f.resign();
        assert!(matches!(
            f.refusal(),
            ProxyVerifyError::AllowlistEntryPastEndOfManifest { entry_id: 0, .. }
        ));
    }

    /// The consent record is what makes the operator's participation a
    /// disclosed choice. An all-zero hash is the default value of an
    /// uninitialised field, not a record, so it is refused at the same stage as
    /// any other zero identifier.
    ///
    /// Mutations this detects: defaulting `consent_record_hash` instead of
    /// requiring it; checking only that it is 32 bytes long (it always is);
    /// dropping any one of the seven zero-field checks.
    #[test]
    fn a_receipt_with_a_zero_consent_record_hash_is_refused() {
        let mut f = Fixture::well_formed();
        f.bundle.receipt.consent_record_hash = [0u8; 32];
        f.resign();
        assert_eq!(
            f.refusal(),
            ProxyVerifyError::ZeroField {
                field: "consent_record_hash"
            }
        );

        // The whole zero-field set, each independently. A single missing arm
        // here is a field that can be left unset forever.
        type ZeroField = (&'static str, fn(&mut ProxyReceiptBundle));
        let zeroable: [ZeroField; 7] = [
            ("session_id", |b| b.receipt.session_id = [0u8; 32]),
            ("consumer_id", |b| b.receipt.consumer_id = [0u8; 32]),
            ("gateway_id", |b| b.receipt.gateway_id = [0u8; 32]),
            ("intent_hash", |b| b.receipt.intent_hash = [0u8; 32]),
            ("consent_record_hash", |b| {
                b.receipt.consent_record_hash = [0u8; 32]
            }),
            ("allowlist_manifest_digest", |b| {
                b.receipt.allowlist_manifest_digest = [0u8; 32]
            }),
            ("operator_wallet", |b| b.receipt.operator_wallet = [0u8; 20]),
        ];
        for (field, zero_it) in zeroable {
            let mut f = Fixture::well_formed();
            zero_it(&mut f.bundle);
            f.resign();
            assert_eq!(
                f.refusal(),
                ProxyVerifyError::ZeroField { field },
                "zeroing {field} must be refused"
            );
        }

        // Negative control: none of the seven is zero in a well-formed bundle,
        // so the loop above is not asserting against a fixture that was already
        // broken.
        assert!(Fixture::well_formed().verify().is_ok());
    }

    /// A submission that is both malformed and forged must report the
    /// **structural** stage, because the caller's next action differs: a
    /// malformed submission is a bug to fix, a forged one is an attack to log.
    ///
    /// Mutations this detects: moving any signature stage above any structural
    /// check; recovering a key "eagerly" before the shape checks; reporting the
    /// *last* failure instead of the first.
    #[test]
    fn structural_refusals_are_reported_before_any_signature_is_recovered() {
        // Broken in both ways at once: a truncated operator signature AND a
        // gateway signature that is 65 bytes of nonsense no key can produce.
        let mut f = Fixture::well_formed();
        f.bundle.operator_sig.truncate(10);
        f.bundle.gateway_sig = vec![0xFF; 65];
        let err = f.refusal();
        assert_eq!(err.stage(), VerifyStage::Structural);
        assert_eq!(
            err,
            ProxyVerifyError::SignatureMalformed {
                party: SigningParty::Operator,
                len: 10
            }
        );

        // CONTRAST — the same nonsense gateway signature, with nothing
        // structural wrong, DOES surface as a signature failure. Without this
        // arm the assertion above would also pass against an implementation
        // that never looks at signatures at all.
        let mut f = Fixture::well_formed();
        f.bundle.gateway_sig = vec![0xFF; 65];
        let err = f.refusal();
        assert_eq!(err.stage(), VerifyStage::GatewayWitness);
        assert!(
            matches!(
                err,
                ProxyVerifyError::Unrecoverable { .. } | ProxyVerifyError::SignerMismatch { .. }
            ),
            "expected a recovery failure, got {err:?}"
        );
    }

    /// One stage, and the single edit that violates it.
    type StageBreak = (VerifyStage, fn(&mut Fixture));

    /// One deliberate break per stage, in stage order. Applied from the LAST
    /// stage backwards so an earlier break always wins.
    fn one_break_per_stage() -> [StageBreak; 10] {
        [
            (VerifyStage::Structural, |f| f.bundle.gateway_sig.clear()),
            (VerifyStage::EpochSpace, |f| f.bundle.receipt.epoch_id += 1),
            (VerifyStage::ChunkSizeRule, |f| {
                f.bundle.receipt.chunk_kind = ChunkKind::Final;
                f.bundle.receipt.bytes_transferred = RECEIPT_CHUNK_BYTES + 1;
            }),
            (VerifyStage::ValidityWindow, |f| {
                f.now_unix = f.bundle.receipt.valid_to_unix + 1;
            }),
            (VerifyStage::IntentBinding, |f| {
                f.bundle.receipt.intent_hash = [0x99; 32];
            }),
            (VerifyStage::CrossFieldAgreement, |f| {
                f.bundle.receipt.price_goat_wei_per_mebibyte =
                    f.bundle.intent.price_goat_wei_per_mebibyte + 1;
            }),
            (VerifyStage::SelfDealing, |f| {
                let shared = [0xAA; 32];
                f.dir.consumer_roots.insert(CONSUMER_ID, shared);
            }),
            (VerifyStage::OperatorSignature, |f| {
                let digest = f
                    .bundle
                    .receipt
                    .receipt_digest(f.chain_id, f.verifying_contract);
                f.bundle.operator_sig = sign(STRANGER_PK, digest);
            }),
            (VerifyStage::ConsumerSignature, |f| {
                let digest = f
                    .bundle
                    .intent
                    .intent_digest(f.chain_id, f.verifying_contract);
                f.bundle.consumer_sig = sign(STRANGER_PK, digest);
            }),
            (VerifyStage::GatewayWitness, |f| {
                f.bundle.witness.body_bytes_to_consumer += 1;
                let digest = f
                    .bundle
                    .witness
                    .witness_digest(f.chain_id, f.verifying_contract);
                f.bundle.gateway_sig = sign(GATEWAY_PK, digest);
            }),
        ]
    }

    /// THE ORDERING PROOF. For every stage `i`, a bundle that violates stages
    /// `i..10` **simultaneously** must report stage `i`.
    ///
    /// That is a stronger statement than "the stages exist": it pins the total
    /// order, so swapping any two calls in [`verify_receipt_bundle`] turns this
    /// red. It also pins [`VERIFY_STAGE_ORDER`] against the observed order, so
    /// the constant cannot drift away from the control flow it documents.
    ///
    /// Mutations this detects: reordering any two stage calls; hoisting a
    /// signature stage above a structural one; deleting a stage entirely (its
    /// row then reports the next stage down); changing
    /// [`VERIFY_STAGE_ORDER`] without changing the function.
    #[test]
    fn the_ten_stages_run_in_the_declared_order() {
        let breaks = one_break_per_stage();

        // The table and the pinned order describe the same ten stages.
        let tabled: Vec<VerifyStage> = breaks.iter().map(|(s, _)| *s).collect();
        assert_eq!(tabled, VERIFY_STAGE_ORDER.to_vec());
        assert_eq!(VERIFY_STAGE_ORDER.len(), 10);

        // Each break, ALONE, must produce its own stage. Without this the
        // cumulative loop below could pass with several breaks that are all
        // silently no-ops.
        for (stage, apply) in breaks {
            let mut f = Fixture::well_formed();
            apply(&mut f);
            assert_eq!(
                f.refusal().stage(),
                stage,
                "the break written for {stage} does not produce {stage} on its own"
            );
        }

        // Cumulative: break stages i..10 and require stage i. Applied in
        // descending order so the earliest break is written last and cannot be
        // overwritten by a later one.
        for i in 0..10 {
            let mut f = Fixture::well_formed();
            for (_, apply) in breaks[i..].iter().rev() {
                apply(&mut f);
            }
            assert_eq!(
                f.refusal().stage(),
                VERIFY_STAGE_ORDER[i],
                "a bundle violating stages {i}..10 must report {}",
                VERIFY_STAGE_ORDER[i]
            );
        }

        // Positive control: with no breaks applied the same fixture verifies,
        // so the ten refusals above are the breaks firing.
        assert!(Fixture::well_formed().verify().is_ok());
    }

    /// THE COUNT THAT SETTLES DISPUTES. The gateway's witnessed byte count and
    /// the operator's claimed one must be equal, exactly, in both directions.
    ///
    /// There is no tolerance parameter here and none anywhere else in this
    /// lane: a proxy epoch allocates from a finite pool and closes, so an
    /// over-report is taken from other operators in the same pool and an
    /// under-report is unrecoverable. A tolerance would be an inflation budget
    /// with a published size.
    ///
    /// Mutations this detects: comparing with `>=`/`<=` instead of `==`;
    /// introducing any tolerance term; comparing against
    /// `node_reported_from_origin` (which nothing witnesses); dropping the
    /// comparison and trusting the witness signature alone.
    #[test]
    fn a_gateway_witness_that_disagrees_with_the_operator_claim_is_refused() {
        // Both directions, one byte each way. The witness is re-signed each
        // time, so this is a disagreement between two honest-looking
        // signatures, not a forgery.
        for delta in [1i64, -1] {
            let mut f = Fixture::well_formed();
            let claimed = f.bundle.receipt.bytes_transferred;
            let witnessed = u64::try_from(i64::try_from(claimed).unwrap() + delta).unwrap();
            f.bundle.witness.body_bytes_to_consumer = witnessed;
            f.resign();
            assert_eq!(
                f.refusal(),
                ProxyVerifyError::WitnessDisagreesWithClaim { witnessed, claimed },
                "a {delta}-byte discrepancy must be refused"
            );
        }

        // A witness lifted off a different receipt is refused before the byte
        // comparison, so an attacker cannot supply a matching count from
        // somebody else's chunk.
        let mut f = Fixture::well_formed();
        f.bundle.witness.receipt_struct_hash = [0x77; 32];
        f.resign();
        assert!(matches!(
            f.refusal(),
            ProxyVerifyError::WitnessBoundToAnotherReceipt { .. }
        ));

        // A witness naming another gateway is refused too.
        let mut f = Fixture::well_formed();
        f.bundle.witness.gateway_id = [0x68; 32];
        f.resign();
        assert!(matches!(
            f.refusal(),
            ProxyVerifyError::WitnessGatewayMismatch { .. }
        ));

        // Witnessed outside the agreed window.
        let mut f = Fixture::well_formed();
        f.bundle.witness.witnessed_at_unix = f.bundle.receipt.valid_to_unix + 1;
        f.resign();
        assert!(matches!(
            f.refusal(),
            ProxyVerifyError::WitnessedOutsideValidityWindow { .. }
        ));

        // Negative control: equality verifies, so the refusals above are the
        // comparison firing rather than a stage that refuses every witness.
        assert!(Fixture::well_formed().verify().is_ok());
    }

    /// HONESTY TEST. `node_reported_from_origin` is re-signed by the gateway,
    /// **not witnessed by it**, and nothing in this system observes the origin
    /// leg. It must therefore never be compared against anything — including
    /// the witnessed count.
    ///
    /// This test fails if somebody "tightens" the check by requiring the two
    /// counts to agree. That would look like a stricter lane and would in fact
    /// be a false claim that the origin leg is attested.
    ///
    /// Mutations this detects: adding `node_reported_from_origin ==
    /// body_bytes_to_consumer` to stage 10; settling on the origin count
    /// instead of the witnessed one.
    #[test]
    fn the_node_reported_origin_leg_is_re_signed_not_witnessed() {
        // Wildly different, in both directions, and both verify.
        for origin in [0u64, 1, 999_999_999, u64::from(u32::MAX)] {
            let mut f = Fixture::well_formed();
            f.bundle.witness.node_reported_from_origin = origin;
            f.resign();
            let v = f
                .verify()
                .expect("the origin count is carried, never compared");
            assert_eq!(v.witness.node_reported_from_origin, origin);
            // The settlement basis is unchanged by it.
            assert_eq!(
                v.witness.body_bytes_to_consumer,
                v.receipt.bytes_transferred
            );
        }

        // POSITIVE CONTROL for the sensitivity of this test: the *witnessed*
        // count is compared, so the tolerance-free equality is still live.
        let mut f = Fixture::well_formed();
        f.bundle.witness.body_bytes_to_consumer += 1;
        f.resign();
        assert!(f.verify().is_err());
    }

    /// A party this lane has never heard of cannot have signed anything it
    /// accepts, and the refusal names the stage rather than pretending the
    /// signature was merely wrong.
    ///
    /// Mutations this detects: defaulting an unknown consumer or gateway to the
    /// zero address (which a crafted signature can be made to recover to);
    /// skipping the lookup when the signature happens to recover.
    #[test]
    fn a_consumer_or_gateway_this_lane_does_not_know_is_refused() {
        let mut f = Fixture::well_formed();
        f.dir.consumer_signers.clear();
        assert_eq!(
            f.refusal(),
            ProxyVerifyError::UnknownParty {
                party: SigningParty::Consumer
            }
        );

        let mut f = Fixture::well_formed();
        f.dir.gateway_signers.clear();
        assert_eq!(
            f.refusal(),
            ProxyVerifyError::UnknownParty {
                party: SigningParty::Gateway
            }
        );

        // An unknown *cluster root*, by contrast, is NOT a refusal — absence of
        // evidence is not evidence of self-dealing. This is the asymmetry
        // `ProxyPartyDirectory` documents, asserted rather than described.
        let mut f = Fixture::well_formed();
        f.dir.operator_roots.clear();
        f.dir.consumer_roots.clear();
        assert!(f.verify().is_ok());
    }

    /// SELF-DEALING, through the wiring rather than through the fraud module's
    /// own unit tests: the operator and the consumer are one household, holding
    /// two perfectly valid keys and producing three perfectly valid signatures.
    ///
    /// Nothing cryptographic is wrong with this bundle. It is refused because
    /// the two parties root at one sponsorship cluster, and the refusal it
    /// carries is `super::fraud`'s own — this module restates nothing.
    ///
    /// Mutations this detects: deleting the `stage_self_dealing` call from
    /// [`verify_receipt_bundle`]; comparing the operator wallet against the
    /// consumer handle (which can never be equal, so the check would never
    /// fire); swapping the two `ProxyPartyDirectory` cluster lookups so each
    /// party is looked up in the other's table; refusing when only one root
    /// resolves.
    #[test]
    fn an_operator_and_a_consumer_in_one_sponsorship_cluster_are_refused_as_self_dealing() {
        let shared = [0xAAu8; 32];
        let mut f = Fixture::well_formed();
        f.dir.consumer_roots.insert(CONSUMER_ID, shared);

        let err = f.refusal();
        assert_eq!(err.stage(), VerifyStage::SelfDealing);
        assert_eq!(
            err,
            ProxyVerifyError::Fraud(FraudError::SelfDealing {
                consumer: hx(&CONSUMER_ID),
                operator: hx(&address(OPERATOR_PK)),
                root: hx(&shared),
            })
        );

        // POSITIVE CONTROL: the same bundle, with the consumer rooted at a
        // different household, verifies. So the refusal above is the cluster
        // comparison firing and not the fixture being broken.
        let f = Fixture::well_formed();
        assert!(f.verify().is_ok());

        // The refusal is reported BEFORE any key is recovered: a bundle that is
        // both self-dealt and forged reports SelfDealing, not a signature stage.
        let mut f = Fixture::well_formed();
        f.dir.consumer_roots.insert(CONSUMER_ID, shared);
        f.bundle.operator_sig = sign(
            STRANGER_PK,
            f.bundle
                .receipt
                .receipt_digest(f.chain_id, f.verifying_contract),
        );
        assert_eq!(f.refusal().stage(), VerifyStage::SelfDealing);
    }

    /// COLLUSION. The consumer and the operator — the party that pays and the
    /// party that is settled — agree on an inflated byte count and both sign it.
    /// Two of the three signatures are genuine and agree with each other.
    ///
    /// They are refused because they cannot produce the third. The gateway is
    /// the sole ingress, is not compensated per byte, and meters independently,
    /// so its count is the one the settlement basis is taken from.
    ///
    /// **What this does NOT stop, stated here so no copy claims otherwise:** if
    /// the gateway's signing key is compromised, or the gateway itself joins the
    /// collusion, this stage passes. The second artifact — the gateway's
    /// independently retrievable signed meter commitment, compared by
    /// `super::challenger` — catches only the sub-case where the gateway's two
    /// documents disagree with each other. A gateway that lies consistently in
    /// both is not caught anywhere in this lane.
    ///
    /// Mutations this detects: dropping the witness comparison and trusting the
    /// gateway signature alone; accepting the operator's count when the witness
    /// is merely present; letting the pair rebind the witness to a re-hashed
    /// receipt without re-signing it.
    #[test]
    fn a_colluding_consumer_and_operator_cannot_inflate_past_the_gateway_witness() {
        let honest = Fixture::well_formed().bundle.receipt.bytes_transferred;

        // The pair inflate the claim by one byte and re-sign what they CAN sign:
        // the receipt (operator key) and the witness binding (a public hash).
        // The intent is unchanged, so the consumer's signature still stands —
        // that is the collusion: the paying party is content with the number.
        let mut f = Fixture::well_formed();
        f.bundle.receipt.bytes_transferred = honest + 1;
        f.bundle.witness.receipt_struct_hash = f.bundle.receipt.receipt_struct_hash();
        f.bundle.operator_sig = sign(
            OPERATOR_PK,
            f.bundle
                .receipt
                .receipt_digest(f.chain_id, f.verifying_contract),
        );
        assert_eq!(
            f.refusal(),
            ProxyVerifyError::WitnessDisagreesWithClaim {
                witnessed: honest,
                claimed: honest + 1,
            }
        );

        // So they forge the witness too — with the only keys they have. A 65-byte
        // signature by a party that is not the gateway is refused at the gateway
        // stage, not accepted as "a signature is present".
        for forger in [OPERATOR_PK, CONSUMER_PK, STRANGER_PK] {
            let mut f = Fixture::well_formed();
            f.bundle.receipt.bytes_transferred = honest + 1;
            f.bundle.witness.receipt_struct_hash = f.bundle.receipt.receipt_struct_hash();
            f.bundle.witness.body_bytes_to_consumer = honest + 1;
            f.bundle.operator_sig = sign(
                OPERATOR_PK,
                f.bundle
                    .receipt
                    .receipt_digest(f.chain_id, f.verifying_contract),
            );
            f.bundle.gateway_sig = sign(
                forger,
                f.bundle
                    .witness
                    .witness_digest(f.chain_id, f.verifying_contract),
            );
            let err = f.refusal();
            assert_eq!(err.stage(), VerifyStage::GatewayWitness);
            assert!(
                matches!(err, ProxyVerifyError::SignerMismatch { .. }),
                "a forged witness must be a signer mismatch, got {err:?}"
            );
        }

        // THE HONEST LIMIT, asserted rather than described: the same inflated
        // number, countersigned by the REAL gateway key, verifies. The witness
        // is a second independent counter, not a proof of honesty — a
        // compromised gateway ends the argument.
        let mut f = Fixture::well_formed();
        f.bundle.receipt.bytes_transferred = honest + 1;
        f.bundle.witness.body_bytes_to_consumer = honest + 1;
        f.bundle.witness.receipt_struct_hash = f.bundle.receipt.receipt_struct_hash();
        f.resign();
        assert!(
            f.verify().is_ok(),
            "a compromised gateway key defeats this stage; the lane must not pretend otherwise"
        );
    }

    /// The receipt's ceiling was agreed in advance, in the object the consumer
    /// signed, so a chunk larger than the whole session's ceiling is refused
    /// even when its own chunk-size rule is satisfied.
    ///
    /// Mutations this detects: comparing against the chunk ceiling rather than
    /// the intent's `max_bytes`; dropping the comparison; using `>=`, which
    /// would refuse a session that used its ceiling exactly.
    #[test]
    fn bytes_beyond_the_intents_agreed_ceiling_are_refused() {
        let mut f = Fixture::well_formed();
        f.bundle.intent.max_bytes = 1_000;
        f.bundle.receipt.intent_hash = f.bundle.intent.intent_struct_hash();
        f.resign();
        assert_eq!(
            f.refusal(),
            ProxyVerifyError::BytesExceedIntentCeiling {
                bytes: 10_485_759,
                max_bytes: 1_000,
            }
        );

        // Exactly at the ceiling is accepted.
        let mut f = Fixture::well_formed();
        f.bundle.intent.max_bytes = f.bundle.receipt.bytes_transferred;
        f.bundle.receipt.intent_hash = f.bundle.intent.intent_struct_hash();
        f.bundle.witness.receipt_struct_hash = f.bundle.receipt.receipt_struct_hash();
        f.resign();
        assert!(f.verify().is_ok());
    }

    /// INV-11, on the refusal path. No refusal message may carry a URL, a path,
    /// a query string, a header name or a body byte — the destination is an
    /// allowlist entry id and nothing else, and an error message is the
    /// easiest place for that to leak.
    ///
    /// Mutations this detects: adding a `host`/`url`/`path` field to any
    /// variant; formatting a destination into a message; widening
    /// `FieldDisagreesWithIntent` to print the disagreeing values when one of
    /// them is a destination.
    #[test]
    fn no_refusal_message_can_carry_a_url_path_query_or_header() {
        // Every variant, rendered. Assembled from fragments at runtime the way
        // `citation_audit`'s marker builder does, so this file does not itself
        // contain the tokens it forbids.
        let forbidden: Vec<String> = [
            ["ht", "tp"].concat(),
            ["ho", "st"].concat(),
            ["pa", "th"].concat(),
            ["qu", "ery"].concat(),
            ["hea", "der"].concat(),
            ["coo", "kie"].concat(),
            ["do", "main"].concat(),
            ["/", "/"].concat(),
            ["?", "="].concat(),
        ]
        .to_vec();

        let messages: Vec<String> = vec![
            ProxyVerifyError::ChainNotAllowed { chain_id: 1 }.to_string(),
            ProxyVerifyError::SignatureAbsent {
                party: SigningParty::Gateway,
            }
            .to_string(),
            ProxyVerifyError::SignatureMalformed {
                party: SigningParty::Operator,
                len: 10,
            }
            .to_string(),
            ProxyVerifyError::ZeroField {
                field: "consent_record_hash",
            }
            .to_string(),
            ProxyVerifyError::PriceOutOfBand { price: 0 }.to_string(),
            ProxyVerifyError::InvertedValidityWindow {
                valid_from_unix: 2,
                valid_to_unix: 1,
            }
            .to_string(),
            ProxyVerifyError::EpochOutsideProxySpace { epoch_id: 1 }.to_string(),
            ProxyVerifyError::EpochMismatch {
                expected: 2,
                found: 1,
            }
            .to_string(),
            ProxyVerifyError::IntentEpochMismatch {
                receipt: 1,
                intent: 2,
            }
            .to_string(),
            ProxyVerifyError::OutsideValidityWindow {
                now_unix: 3,
                valid_from_unix: 1,
                valid_to_unix: 2,
            }
            .to_string(),
            ProxyVerifyError::UnboundedValidityWindow { seconds: 999_999 }.to_string(),
            ProxyVerifyError::IntentHashMismatch {
                claimed: hx(&[0x11u8; 32]),
                bundled: hx(&[0x22u8; 32]),
            }
            .to_string(),
            ProxyVerifyError::StaleAllowlistManifest {
                named: hx(&[0x11u8; 32]),
                in_force: hx(&[0x22u8; 32]),
            }
            .to_string(),
            ProxyVerifyError::AllowlistEntryPastEndOfManifest {
                entry_id: 9,
                entry_count: 9,
            }
            .to_string(),
            ProxyVerifyError::FieldDisagreesWithIntent {
                field: "price_goat_wei_per_mebibyte",
            }
            .to_string(),
            ProxyVerifyError::BytesExceedIntentCeiling {
                bytes: 2,
                max_bytes: 1,
            }
            .to_string(),
            ProxyVerifyError::Fraud(FraudError::SelfDealing {
                consumer: hx(&[0xC2u8; 32]),
                operator: hx(&[0x99u8; 20]),
                root: hx(&[0xAAu8; 32]),
            })
            .to_string(),
            ProxyVerifyError::UnknownParty {
                party: SigningParty::Consumer,
            }
            .to_string(),
            ProxyVerifyError::Unrecoverable {
                stage: VerifyStage::GatewayWitness,
                party: SigningParty::Gateway,
                source: SigError::Malformed,
            }
            .to_string(),
            ProxyVerifyError::SignerMismatch {
                stage: VerifyStage::OperatorSignature,
                recovered: hx(&[0x11u8; 20]),
                expected: hx(&[0x22u8; 20]),
            }
            .to_string(),
            ProxyVerifyError::WitnessBoundToAnotherReceipt {
                bound: hx(&[0x11u8; 32]),
                actual: hx(&[0x22u8; 32]),
            }
            .to_string(),
            ProxyVerifyError::WitnessDisagreesWithClaim {
                witnessed: 1,
                claimed: 2,
            }
            .to_string(),
            ProxyVerifyError::WitnessGatewayMismatch {
                witness: hx(&[0x11u8; 32]),
                receipt: hx(&[0x22u8; 32]),
            }
            .to_string(),
            ProxyVerifyError::WitnessedOutsideValidityWindow {
                witnessed_at_unix: 3,
                valid_from_unix: 1,
                valid_to_unix: 2,
            }
            .to_string(),
        ];

        // FLOOR. A shrinking list would make the sweep below pass by covering
        // nothing; 24 is every variant this module declares.
        assert_eq!(
            messages.len(),
            24,
            "every ProxyVerifyError variant must be rendered here"
        );
        let swept_bytes: usize = messages.iter().map(String::len).sum();
        assert!(
            swept_bytes > 1_000,
            "byte floor: only {swept_bytes} bytes swept"
        );

        for message in &messages {
            let lower = message.to_ascii_lowercase();
            for token in &forbidden {
                assert!(
                    !lower.contains(token.as_str()),
                    "a refusal message carries a destination-shaped token: {message}"
                );
            }
        }

        // POSITIVE CONTROL: the sweep can fire. A synthetic message with a real
        // destination in it must be caught by the same loop.
        let planted = ["a refusal naming ", "ht", "tps://example.invalid/a", "?b=c"].concat();
        let lower = planted.to_ascii_lowercase();
        assert!(
            forbidden.iter().any(|t| lower.contains(t.as_str())),
            "the sweep cannot detect a destination; its silence proves nothing"
        );
    }

    /// Every refusal maps to exactly one stage, and every stage is reachable.
    ///
    /// Mutations this detects: a variant filed under the wrong stage in
    /// `ProxyVerifyError::stage`; a stage in [`VERIFY_STAGE_ORDER`] no refusal
    /// can ever report, which would be a stage that cannot fail.
    #[test]
    fn every_stage_is_reachable_and_every_refusal_names_one() {
        let breaks = one_break_per_stage();
        let mut seen: Vec<VerifyStage> = Vec::new();
        for (_, apply) in breaks {
            let mut f = Fixture::well_formed();
            apply(&mut f);
            let stage = f.refusal().stage();
            assert!(!seen.contains(&stage), "{stage} reported twice");
            seen.push(stage);
        }
        assert_eq!(seen, VERIFY_STAGE_ORDER.to_vec());
    }
}
