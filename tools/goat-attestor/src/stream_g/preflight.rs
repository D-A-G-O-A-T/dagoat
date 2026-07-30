//! Sponsored-enrollment preflight — Stream G, Task 6b Wave B.
//!
//! Answers one question, without broadcasting anything: **would
//! `GoatRelayGateway.executeSponsoredEnrollment` succeed if the attestor
//! relayed this call right now?**
//!
//! Every [`Check`] this module can produce names a specific `revert` in
//! `contracts/src/GoatRelayGateway.sol` (or in the
//! `WalletSponsorshipRegistry.linkSecondary` call it makes), with the line
//! it lives on. Nothing here is a heuristic and nothing here is a policy of
//! our own invention: if preflight rejects, the transaction would have
//! reverted; the converse is emphatically **not** claimed — see
//! [`UNVERIFIED_CHECKS`].
//!
//! **One rejection is not a [`Check`] and must not be made one.** Task 8
//! Mandate 3 added a check on the ERC-2612 permit deadline, which reverts
//! inside `IERC20Permit(feeToken).permit` — the **fee token's** code, a
//! third contract that declares its own errors. It is reported as
//! [`PreflightError::PermitWouldRevert`], carrying the gateway call site
//! (`:833`) and the EIP-2612 clause. Folding it into `Check` would have
//! required widening `Check`'s "names a declared GoatRelayGateway /
//! WalletSponsorshipRegistry error" invariant, which
//! [`tests::every_check_names_a_real_revert_and_site`] exists to
//! enforce.
//!
//! ## Ground truth
//!
//! Read directly out of `contracts/src/GoatRelayGateway.sol` and
//! `contracts/src/StreamGTypes.sol` on 2026-07-24, not grepped and not
//! taken on trust from the task brief. Two places where the brief and the
//! contract disagree, contract wins:
//!
//! - **`_isDirectEthEnrollment` has SIX conditions, not three**
//!   (`StreamGEnroll._isDirectEthEnrollment`, `StreamGEnroll.sol:162-169`;
//!   it lived in `GoatRelayGateway.sol` when this note was written, before
//!   the gateway body moved into `library` DELEGATECALL targets):
//!   `feeToken == 0`,
//!   `feeAuthorizationMode == NONE`, `feeAuthorizationDigest == 0`,
//!   **`feeQuoteHash == 0`**, **`maxFee == 0`** and
//!   **`feeTokenConfigHash == 0`**. An intent that zeroes only the first
//!   three takes the *sponsored* branch and is then rejected by the quote
//!   validator, not by the direct-ETH one. [`is_direct_eth_enrollment`]
//!   implements all six.
//! - The brief's twenty-row table folds `_validateAndConsumeQuote`
//!   (`:392`) into one row. It expands to fourteen distinct reverts in
//!   `_validateAndConsumeQuoteGeneric` (`:704-738`), each with its own
//!   [`Check`] variant here, evaluated in the contract's order.
//!
//! ## Check 18 is the one that matters most
//!
//! `GoatRelayGateway.sol:394` compares `intent.feeQuoteHash` against
//! `_hashTypedDataV4(_feeQuoteStructHash(quote))` — the quote's **full
//! EIP-712 digest**, not its `quoteId`. Binding the intent to the quote by
//! `quoteId` instead would revert every single transaction with
//! `InvalidQuote`, and would be invisible to any test that did not
//! reconstruct the digest. [`Check::FeeQuoteHashMismatch`] recomputes it
//! with [`models::fee_quote_digest`], whose three layers (domain, struct
//! hash, digest) are pinned against `cast`-derived literals in `quotes.rs`
//! and cross-proven from Solidity in
//! `contracts/test/StreamGEip712Parity.t.sol`.
//!
//! ## The attestor cannot relay the direct-ETH path
//!
//! `GoatRelayGateway.sol:379` requires `msg.sender == intent.controller` on
//! that branch. A relayer is by definition not the controller, so
//! [`Disposition::ClientMustSubmitDirectly`] is the only honest answer —
//! never "here is a sponsored quote".
//!
//! ## Live sourcing
//!
//! [`read_live_preflight_state`] is the only production constructor of
//! [`LivePreflightState`]. It pins one block (`eth_blockNumber`) and issues
//! every state read against it (sourcing contract R4), takes the fee-token
//! state exclusively through [`token_manifest::read_live_token_state`]
//! (R1/R2) and the enrollment nonces exclusively through
//! [`LiveEnrollmentNonces::from_snapshot`] over **one**
//! `secondaryEnrollmentNonceSnapshot` call (R3). No live value is ever
//! populated from `StreamGConfig` or from the deployment manifest.
//!
//! One deliberate, disclosed deviation from the letter of the "obtain live
//! values via `LiveEnrollmentNonces::read_live`" instruction:
//! `read_live_preflight_state` performs the snapshot `eth_call` itself and
//! then hands the result to the same `pub(crate)` validator
//! (`LiveEnrollmentNonces::from_snapshot`) that `read_live` uses. This is
//! `read_live` unpacked, not a second read — the call count is still
//! exactly one per preflight (pinned by
//! [`tests::state_read_issues_exactly_one_nonce_snapshot_call`]) — and it
//! is necessary because `LiveEnrollmentNonces` deliberately exposes only
//! `v1EnrollNonce`/`linkNonce`, while the gateway's own preconditions 8, 9,
//! 10 and `_markIntentAndNonce` compare against `controller`,
//! `controllerEpoch` and `actionNonce`, which live in the *same* snapshot
//! word set. Calling `read_live` and then re-reading the snapshot for those
//! three fields would be two calls, which is exactly the shape R3 exists to
//! forbid.
//!
//! ## What preflight does NOT prove
//!
//! `ChainClient` has no generic `eth_call` — it exposes a fixed, audited set
//! of named reads — so several gateway/registry storage slots are simply not
//! readable from here. Every one of them is enumerated in
//! [`UNVERIFIED_CHECKS`] and returned on the report — a `Ok(PreflightReport)`
//! therefore means "none of the checks I *can* evaluate would revert", not
//! "this transaction will succeed". Callers must not collapse the two.
//!
//! That list shrinks only by adding a **specific** read and using it.
//! Task 8 did exactly that for entry 10, with
//! [`ChainClient::erc2612_nonces`] and
//! [`ChainClient::block_timestamp_at`], and entry 10 was rewritten down to
//! the residue instead of being deleted. (Task 6b's original wording here
//! said "this wave may not add trait methods"; that was a constraint on that
//! wave, not a standing property of the module.)

use thiserror::Error;

use alloy::primitives::{Signature, B256};

use crate::chain::{ChainClient, NonceSnapshotView, SNAP_ACTION_NONCE, SNAP_CONTROLLER};
use crate::merkle::keccak256;
use crate::sig_verify;

use super::models::{
    self, fee_quote_digest, link_secondary_digest, sponsor_enrollment_core_hash, ActionType,
    FeeQuote, LinkSecondary, LiveEnrollmentNonces, LiveNoncesError, SponsorEnrollmentCore,
};
use super::token_manifest::{
    self, Capability, DeploymentManifest, LiveTokenReading, TokenManifestError, TrustedChain,
};

// ---------------------------------------------------------------------------
// Constants transcribed from Solidity.
// ---------------------------------------------------------------------------

/// `StreamGTypes.AuthorizationMode.NONE` ordinal (`StreamGTypes.sol:13`).
/// An **ordinal**, not a `CAP_*` bit — see `token_manifest`'s module doc,
/// "`CAP_*` bits vs `AuthorizationMode` ordinals: independent numbering".
pub const AUTHORIZATION_MODE_NONE: u8 = 0;
/// `StreamGTypes.AuthorizationMode.EIP2612` ordinal (`StreamGTypes.sol:14`).
pub const AUTHORIZATION_MODE_EIP2612: u8 = 1;

/// `StreamGTypes.SPONSOR_ENROLLMENT_TYPEHASH` (`StreamGTypes.sol:65-67`),
/// transcribed here so a drift in either copy fails
/// [`tests::sponsor_enrollment_digest_regression_fixed_inputs`] loudly.
/// `cast keccak` of this string is
/// `0xaa3769f433b96287c3b0838abbc6b35619375fea0e81929c58cf672804b9e885`.
pub const SPONSOR_ENROLLMENT_TYPEHASH_STR: &str = "SponsorEnrollment(bytes32 intentId,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,address root,address controller,uint256 controllerEpoch,address secondary,bytes32 enrollDigest,bytes32 linkDigest,bytes32 rootAuthorizationDigest,address feeToken,uint8 feeAuthorizationMode,bytes32 feeAuthorizationDigest,uint256 maxFee,bytes32 feeQuoteHash,uint256 nonce,uint48 deadline)";

fn sponsor_enrollment_typehash() -> [u8; 32] {
    keccak256(SPONSOR_ENROLLMENT_TYPEHASH_STR.as_bytes())
}

// ---------------------------------------------------------------------------
// Calldata mirrors.
// ---------------------------------------------------------------------------

/// `StreamGTypes.SponsorEnrollment` (`StreamGTypes.sol:202-220`). Field
/// order is the EIP-712 encoding order used by
/// `GoatRelayGateway._sponsorEnrollmentStructHash` (`:1140-1164`); do not
/// reorder.
///
/// Width conventions match `models.rs`: `uint256` money-ish fields are
/// `u128`, counters and `uint48` timestamps are `u64`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SponsorEnrollment {
    pub intent_id: [u8; 32],
    pub deployment_manifest_hash: [u8; 32],
    pub fee_token_config_hash: [u8; 32],
    pub root: [u8; 20],
    pub controller: [u8; 20],
    pub controller_epoch: u64,
    pub secondary: [u8; 20],
    pub enroll_digest: [u8; 32],
    pub link_digest: [u8; 32],
    pub root_authorization_digest: [u8; 32],
    pub fee_token: [u8; 20],
    pub fee_authorization_mode: u8,
    pub fee_authorization_digest: [u8; 32],
    pub max_fee: u128,
    pub fee_quote_hash: [u8; 32],
    pub nonce: u64,
    pub deadline: u64,
}

/// `keccak256(abi.encode(SPONSOR_ENROLLMENT_TYPEHASH, ...17 fields...))` —
/// `GoatRelayGateway._sponsorEnrollmentStructHash` (`:1140-1164`).
pub fn sponsor_enrollment_struct_hash(i: &SponsorEnrollment) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 18);
    buf.extend_from_slice(&sponsor_enrollment_typehash());
    buf.extend_from_slice(&i.intent_id);
    buf.extend_from_slice(&i.deployment_manifest_hash);
    buf.extend_from_slice(&i.fee_token_config_hash);
    buf.extend_from_slice(&models::address_word(&i.root));
    buf.extend_from_slice(&models::address_word(&i.controller));
    buf.extend_from_slice(&models::u256_be(u128::from(i.controller_epoch)));
    buf.extend_from_slice(&models::address_word(&i.secondary));
    buf.extend_from_slice(&i.enroll_digest);
    buf.extend_from_slice(&i.link_digest);
    buf.extend_from_slice(&i.root_authorization_digest);
    buf.extend_from_slice(&models::address_word(&i.fee_token));
    buf.extend_from_slice(&models::u256_be_u8(i.fee_authorization_mode));
    buf.extend_from_slice(&i.fee_authorization_digest);
    buf.extend_from_slice(&models::u256_be(i.max_fee));
    buf.extend_from_slice(&i.fee_quote_hash);
    buf.extend_from_slice(&models::u256_be(u128::from(i.nonce)));
    buf.extend_from_slice(&models::u256_be(u128::from(i.deadline)));
    keccak256(&buf)
}

/// The digest `intent.controller` must have signed for
/// `GoatRelayGateway.sol:400-402` to recover them. This is a **user-side**
/// signature; the attestor verifies it and must never attempt to produce
/// it.
pub fn sponsor_enrollment_digest(
    i: &SponsorEnrollment,
    chain_id: u64,
    gateway: [u8; 20],
) -> [u8; 32] {
    let domain = models::eip712_domain_separator(
        models::FEE_QUOTE_DOMAIN_NAME,
        models::FEE_QUOTE_DOMAIN_VERSION,
        chain_id,
        gateway,
    );
    models::eip712_digest(&domain, &sponsor_enrollment_struct_hash(i))
}

/// `StreamGTypes.V1Enrollment` (`StreamGTypes.sol:308-313`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V1Enrollment {
    pub wallet: [u8; 20],
    pub nonce: u64,
    pub deadline: u64,
    pub signature_hex: String,
}

/// `StreamGTypes.RootAuthorization` (`StreamGTypes.sol:193-200`). On the
/// sponsored-enrollment path all six fields must be zero
/// (`GoatRelayGateway.sol:366-373`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RootAuthorization {
    pub root: [u8; 20],
    pub secondary: [u8; 20],
    pub enroll_digest: [u8; 32],
    pub link_digest: [u8; 32],
    pub nonce: u64,
    pub deadline: u64,
}

impl RootAuthorization {
    /// All six fields zero — the exact disjunction at
    /// `GoatRelayGateway.sol:366-373`, negated.
    pub fn is_all_zero(&self) -> bool {
        self.root == [0u8; 20]
            && self.secondary == [0u8; 20]
            && self.enroll_digest == [0u8; 32]
            && self.link_digest == [0u8; 32]
            && self.nonce == 0
            && self.deadline == 0
    }
}

/// `StreamGTypes.Eip2612Authorization` (`StreamGTypes.sol:316-324`) —
/// `TokenAuthorization.eip2612`, consumed on the sponsored-enrollment token
/// path by `StreamGCommon.collectEip2612`
/// (`StreamGCommon.sol:200-212`; it was `GoatRelayGateway._collectEip2612`
/// before the gateway was split into libraries).
///
/// Independent-verifier follow-up (Task 3, verifier §4): that function's
/// first line's three
/// conditions (`owner == payer`, `spender == address(this)`,
/// `value >= feeAmount`) were neither checked nor disclosed —
/// `SponsoredEnrollmentCall` did not even carry this struct. `owner`,
/// `spender` and `value` are now checked (see
/// [`Check::Eip2612FeeFieldsMismatch`]).
///
/// `deadline` **is** checked as of Task 8 Mandate 3, against the pinned
/// block's chain clock — see [`PreflightError::PermitWouldRevert`]. `v`,
/// `r` and `s` are still carried for fidelity to the on-chain struct and
/// for whatever later task builds calldata from this, and are still
/// unverifiable: EIP-2612's `permit()` has no nonce argument, so the nonce
/// they sign over is nowhere in this struct, and recovering the signer
/// would need the token's `DOMAIN_SEPARATOR`, which nothing in this crate
/// reads. See [`UNVERIFIED_CHECKS`] entry 10, which was narrowed to exactly
/// that residue rather than removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eip2612Authorization {
    pub owner: [u8; 20],
    pub spender: [u8; 20],
    /// `uint256` on-chain; `u128` here — same convention `FeeQuote::fee_amount` uses.
    pub value: u128,
    /// `uint256` on-chain. NOT independently verified here — see the struct
    /// doc's "residual" note.
    pub deadline: u64,
    pub v: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

/// The ten-argument `executeSponsoredEnrollment` call, as the attestor
/// would broadcast it. Signature fields are `0x`-prefixed hex; an **empty**
/// string means "zero-length `bytes`", which is what the contract requires
/// for `rootAuthorizationSignature` (`:370`) and, on the direct-ETH branch,
/// for `quoteSignature` (`:380`).
#[derive(Debug, Clone)]
pub struct SponsoredEnrollmentCall<'a> {
    pub intent: &'a SponsorEnrollment,
    pub quote: &'a FeeQuote,
    pub v1_enrollment: &'a V1Enrollment,
    pub link: &'a LinkSecondary,
    pub root_authorization: &'a RootAuthorization,
    /// `TokenAuthorization.mode` ordinal (`StreamGTypes.sol:342`).
    pub fee_authorization_mode: u8,
    /// `TokenAuthorization.eip2612` — see [`Eip2612Authorization`]. Only
    /// consulted on the sponsored (non-direct-ETH) branch, mirroring
    /// `_collectEip2612Fee`'s own call site (`GoatRelayGateway.sol:418`).
    pub fee_eip2612_authorization: &'a Eip2612Authorization,
    pub sponsor_signature_hex: &'a str,
    pub quote_signature_hex: &'a str,
    pub link_signature_hex: &'a str,
    pub root_authorization_signature_hex: &'a str,
}

/// `GoatRelayGateway._isDirectEthEnrollment` (`:645-652`) — **all six**
/// conditions, exactly as the contract writes them. See the module doc for
/// why three is not enough.
pub fn is_direct_eth_enrollment(intent: &SponsorEnrollment) -> bool {
    intent.fee_token == [0u8; 20]
        && intent.fee_authorization_mode == AUTHORIZATION_MODE_NONE
        && intent.fee_authorization_digest == [0u8; 32]
        && intent.fee_quote_hash == [0u8; 32]
        && intent.max_fee == 0
        && intent.fee_token_config_hash == [0u8; 32]
}

// ---------------------------------------------------------------------------
// Checks.
// ---------------------------------------------------------------------------

/// One precondition of `executeSponsoredEnrollment`, named for what it
/// checks rather than for the (heavily overloaded) revert it produces —
/// six distinct conditions all revert `InvalidFeeFields`, and eleven all
/// revert `InvalidQuote`. [`Check::revert`] gives the Solidity error and
/// [`Check::site`] the file and line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    // --- executeSponsoredEnrollment preamble ---------------------------
    ExpiredDeadline,
    ZeroRootOrSecondary,
    LinkFieldsMismatch,
    V1WalletMismatch,
    ControllerUnset,
    ControllerMismatch,
    EpochMismatch,
    EnrollDigestMismatch,
    BadV1Signature,
    LinkDigestMismatch,
    BadLinkSignature,
    NonZeroRootAuthorizationDigest,
    NonZeroRootAuthorization,
    // --- direct-ETH branch (:378-390) ----------------------------------
    DirectEthQuoteSignaturePresent,
    DirectEthQuoteNotZeroed,
    DirectEthFeeAuthorizationNotNone,
    // --- _validateAndConsumeQuoteGeneric (:704-738), contract order ----
    ZeroQuoteSigner,
    ZeroQuoteId,
    QuoteActionTypeMismatch,
    QuotePayerMismatch,
    QuoteFeeRecipientMismatch,
    QuoteFeeTokenMismatch,
    ZeroQuoteFeeAmount,
    FeeExceedsMax,
    QuoteWindow,
    ManifestHashMismatch,
    FeeScheduleHashMismatch,
    /// `:725`. Preflight never raises this as a
    /// [`PreflightError::WouldRevert`] — the hazard-3 gate is
    /// `token_manifest::assert_token_authorized`, whose own
    /// [`TokenManifestError`] is propagated instead so the five distinct
    /// diagnostic reasons survive. The variant exists so this enum remains
    /// a complete map of the preconditions, and so
    /// [`Check::revert`]/[`Check::site`] can name the on-chain revert.
    TokenNotAuthorized,
    FeeTokenConfigHashMismatch,
    QuoteActionCoreHashMismatch,
    BadQuoteSignature,
    // --- back in executeSponsoredEnrollment ----------------------------
    /// **Check 18.** `intent.feeQuoteHash` vs the quote's full EIP-712
    /// digest.
    FeeQuoteHashMismatch,
    UnsupportedFeeMode,
    BadSponsorSignature,
    // --- effects (:405-419) --------------------------------------------
    ZeroIntentId,
    BadActionNonce,
    V1EnrollNonceUnusable,
    FeeAuthorizationModeNotEip2612,
    /// `:832` — `_collectEip2612`'s combined `owner == payer && spender ==
    /// address(this) && value >= feeAmount` condition (a single Solidity
    /// `if` with three `||`-joined negated clauses, one revert). Token path
    /// only (`!direct`); see [`Eip2612Authorization`]'s doc for what this
    /// does and does not verify.
    Eip2612FeeFieldsMismatch,
    // --- nested WalletSponsorshipRegistry.linkSecondary ----------------
    LinkSecondaryEqualsRoot,
    LinkDeadlineExpired,
    LinkNonceMismatch,
}

impl Check {
    /// The Solidity `error` this condition raises.
    pub fn revert(self) -> &'static str {
        use Check::*;
        match self {
            ExpiredDeadline => "ExpiredDeadline",
            ZeroRootOrSecondary => "ZeroAddress",
            LinkFieldsMismatch
            | NonZeroRootAuthorizationDigest
            | NonZeroRootAuthorization
            | DirectEthFeeAuthorizationNotNone
            | Eip2612FeeFieldsMismatch => "InvalidFeeFields",
            V1WalletMismatch | EnrollDigestMismatch | V1EnrollNonceUnusable => {
                "InvalidV1Enrollment"
            }
            ControllerUnset | ControllerMismatch => "ControllerMismatch",
            EpochMismatch => "EpochMismatch",
            BadV1Signature => "BadV1Signature",
            LinkDigestMismatch | BadLinkSignature => "BadLinkSignature",
            DirectEthQuoteSignaturePresent
            | DirectEthQuoteNotZeroed
            | ZeroQuoteSigner
            | ZeroQuoteId
            | QuoteActionTypeMismatch
            | QuotePayerMismatch
            | QuoteFeeRecipientMismatch
            | QuoteFeeTokenMismatch
            | ZeroQuoteFeeAmount
            | QuoteWindow
            | QuoteActionCoreHashMismatch
            | FeeQuoteHashMismatch => "InvalidQuote",
            FeeExceedsMax => "FeeExceedsMax",
            ManifestHashMismatch | FeeScheduleHashMismatch | FeeTokenConfigHashMismatch => {
                "ConfigHashMismatch"
            }
            TokenNotAuthorized => "TokenNotAuthorized",
            BadQuoteSignature => "BadQuoteSignature",
            UnsupportedFeeMode | FeeAuthorizationModeNotEip2612 => "UnsupportedFeeMode",
            BadSponsorSignature => "BadSponsorSignature",
            ZeroIntentId => "ZeroIntentId",
            BadActionNonce => "BadActionNonce",
            LinkSecondaryEqualsRoot | LinkNonceMismatch => "InvalidRootAuthorization",
            LinkDeadlineExpired => "ExpiredSignature",
        }
    }

    /// `file:line` the revert is raised at.
    pub fn site(self) -> &'static str {
        use Check::*;
        match self {
            ExpiredDeadline => "GoatRelayGateway.sol:342",
            ZeroRootOrSecondary => "GoatRelayGateway.sol:343",
            LinkFieldsMismatch => "GoatRelayGateway.sol:344",
            V1WalletMismatch => "GoatRelayGateway.sol:345",
            ControllerUnset => "GoatRelayGateway.sol:351",
            ControllerMismatch => "GoatRelayGateway.sol:352",
            EpochMismatch => "GoatRelayGateway.sol:353",
            EnrollDigestMismatch => "GoatRelayGateway.sol:356",
            BadV1Signature => "GoatRelayGateway.sol:358",
            LinkDigestMismatch => "GoatRelayGateway.sol:361",
            BadLinkSignature => "GoatRelayGateway.sol:363",
            NonZeroRootAuthorizationDigest => "GoatRelayGateway.sol:365",
            NonZeroRootAuthorization => "GoatRelayGateway.sol:366-373",
            DirectEthQuoteSignaturePresent => "GoatRelayGateway.sol:380",
            DirectEthQuoteNotZeroed => "GoatRelayGateway.sol:381-389",
            DirectEthFeeAuthorizationNotNone => "GoatRelayGateway.sol:390",
            // The quote validator moved out of the gateway into
            // `StreamGCommon.validateAndConsumeQuote` (a `library` reached by
            // DELEGATECALL) when the gateway was split; the check ORDER inside
            // it is unchanged, which is what these rows are really about.
            ZeroQuoteSigner => "StreamGCommon.sol:107 (validateAndConsumeQuote)",
            ZeroQuoteId => "StreamGCommon.sol:108 (validateAndConsumeQuote)",
            QuoteActionTypeMismatch => "StreamGCommon.sol:110 (validateAndConsumeQuote)",
            QuotePayerMismatch => "StreamGCommon.sol:111 (validateAndConsumeQuote)",
            QuoteFeeRecipientMismatch => "StreamGCommon.sol:112 (validateAndConsumeQuote)",
            QuoteFeeTokenMismatch => "StreamGCommon.sol:113 (validateAndConsumeQuote)",
            ZeroQuoteFeeAmount => "StreamGCommon.sol:114 (validateAndConsumeQuote)",
            FeeExceedsMax => "StreamGCommon.sol:115 (validateAndConsumeQuote)",
            QuoteWindow => "StreamGCommon.sol:116 (validateAndConsumeQuote)",
            ManifestHashMismatch => "StreamGCommon.sol:118-121 (validateAndConsumeQuote)",
            FeeScheduleHashMismatch => "StreamGCommon.sol:122-124 (validateAndConsumeQuote)",
            TokenNotAuthorized => "StreamGCommon.sol:127 (assertTokenAuthorized)",
            FeeTokenConfigHashMismatch => "StreamGCommon.sol:128-131 (validateAndConsumeQuote)",
            QuoteActionCoreHashMismatch => "StreamGCommon.sol:133 (validateAndConsumeQuote)",
            BadQuoteSignature => "StreamGCommon.sol:135-137 (validateAndConsumeQuote)",
            FeeQuoteHashMismatch => "GoatRelayGateway.sol:394",
            UnsupportedFeeMode => "GoatRelayGateway.sol:395-397",
            BadSponsorSignature => "GoatRelayGateway.sol:400-402",
            ZeroIntentId => "GoatRelayGateway.sol:318",
            BadActionNonce => "GoatRelayGateway.sol:320",
            V1EnrollNonceUnusable => "StreamGEnroll.sol:200-218 (_enrollV1OrAcceptFrontRun)",
            FeeAuthorizationModeNotEip2612 => "StreamGEnroll.sol:155 (execute, token fee path)",
            Eip2612FeeFieldsMismatch => "StreamGCommon.sol:207 (collectEip2612)",
            LinkSecondaryEqualsRoot => "WalletSponsorshipRegistry.sol:190",
            LinkDeadlineExpired => "WalletSponsorshipRegistry.sol:191",
            LinkNonceMismatch => "WalletSponsorshipRegistry.sol:192",
        }
    }
}

/// A precondition preflight **cannot** evaluate, and why. Returned on every
/// [`PreflightReport`] so an `Ok` is never mistaken for "this will land".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnverifiedCheck {
    /// The Solidity revert that would be raised.
    pub revert: &'static str,
    /// `file:line`.
    pub site: &'static str,
    /// What would have to exist for preflight to evaluate it.
    pub why: &'static str,
}

/// The complete, honest list of preconditions this module does not check.
///
/// Most entries are here because the value they need lives in a
/// gateway/registry storage slot and `ChainClient` exposes no generic
/// `eth_call` — this wave may not add trait methods. Two entries are
/// weaker than "unchecked": they *are* checked, but against the deployment
/// manifest rather than against the gateway's own storage, which is a
/// materially different claim and is stated as such. One entry (the
/// `IERC20Permit.permit` residual, Task 3 follow-up) is a different kind
/// again: not a storage slot this crate cannot read, but external
/// fee-token-contract logic `_collectEip2612` invokes and does not itself
/// pre-validate — `:832`'s own three conditions ARE checked (see
/// [`Check::Eip2612FeeFieldsMismatch`]), Task 8 added the deadline and a
/// direct `nonces(owner)` read, and what is left is the permit
/// **signature** alone.
///
/// **The list is ELEVEN entries long.** Task 8 narrowed entry 10's text
/// rather than deleting the entry, because the residue is real: shrinking a
/// disclosure to the part that is still true is the mechanism working, and
/// removing it would be a false claim of closure. Wave 2 then *added* entry
/// 11 — the first entry that is not a Solidity precondition but one of this
/// crate's own gates (the native-ETH exposure gate) declaring where it does
/// not run. That is the same mechanism pointed inward, and the count moving
/// 10 → 11 is a deliberate, test-pinned change rather than drift.
pub const UNVERIFIED_CHECKS: &[UnverifiedCheck] = &[
    UnverifiedCheck {
        revert: "NotActivated / Paused",
        site: "GoatRelayGateway.sol:306-309 (_requireLive)",
        why: "needs GoatRelayGateway.activated()/paused(); no ChainClient read exists",
    },
    UnverifiedCheck {
        revert: "RootNotRegistered",
        site: "GoatRelayGateway.sol:348-349",
        why: "needs WalletSponsorshipRegistry.primaryOf(root); no ChainClient read exists",
    },
    UnverifiedCheck {
        revert: "ClusterSuspended",
        site: "GoatRelayGateway.sol:350",
        why: "needs WalletSponsorshipRegistry.suspendedClusters(root); no ChainClient read exists",
    },
    UnverifiedCheck {
        revert: "IntentAlreadyUsed",
        site: "GoatRelayGateway.sol:319",
        // TEXT CORRECTED IN TASK 8, SCOPE UNCHANGED. The old wording ("no
        // ChainClient read exists") became false in Task 7, which shipped
        // `ChainClient::intent_used` (`chain.rs:412`, selector `0xa4532c02`
        // pinned by `cast sig`, live impl `rpc_chain.rs:925`) for the
        // outbox's crash-recovery path. Preflight still does not call it, so
        // the check is still unevaluated here and the entry stays — but the
        // REASON is "unwired", not "unreadable", and those are different
        // claims. This is Mandate 3's exact shape a second time and is
        // reported to the architect as unassigned follow-up work; wiring it
        // was deliberately NOT done in this wave, which was scoped to
        // `erc2612_nonces` + `block_timestamp_at`.
        why: "needs GoatRelayGateway.intentUsed(intentId). The read EXISTS as \
              ChainClient::intent_used (Task 7, chain.rs:412) but preflight does not consume \
              it, so this precondition is unwired rather than unreadable",
    },
    UnverifiedCheck {
        revert: "QuoteAlreadyUsed",
        site: "StreamGCommon.sol:109 (validateAndConsumeQuote)",
        why: "needs GoatRelayGateway.quoteUsed(quoteId); no ChainClient read exists",
    },
    UnverifiedCheck {
        revert: "InvalidQuote (zero quoteSigner) / BadQuoteSignature",
        site: "StreamGCommon.sol:107, :135-137 (validateAndConsumeQuote)",
        why: "checked against manifest.quoteSigner, NOT against the gateway's own \
              quoteSigner storage slot, which policy can rotate without touching the manifest",
    },
    UnverifiedCheck {
        revert: "InvalidQuote (feeRecipient)",
        site: "StreamGCommon.sol:112 (validateAndConsumeQuote)",
        why: "checked against manifest.feeSafe, NOT against the gateway's immutable feeSafe",
    },
    UnverifiedCheck {
        revert: "InvalidV1Enrollment (blacklisted / already-enrolled branch)",
        site: "StreamGEnroll.sol:200-218 (_enrollV1OrAcceptFrontRun)",
        why: "needs EnrollmentRegistry.enrolled(wallet) and .blacklisted(wallet); only the \
              nonce half of _enrollV1OrAcceptFrontRun is checkable from the snapshot",
    },
    UnverifiedCheck {
        revert: "SecondaryAlreadyLinked / SecondaryIsRootController / V1 eligibility",
        site: "WalletSponsorshipRegistry.sol:193-195",
        why: "needs WalletSponsorshipRegistry.primaryOf/controlledRootOf and V1 eligibility; \
              no ChainClient read exists",
    },
    UnverifiedCheck {
        revert: "ERC-2612 permit() SIGNATURE revert (token-defined, not a GoatRelayGateway error)",
        site: "StreamGCommon.sol:208 (collectEip2612 → IERC20Permit(feeToken).permit(...))",
        why: "NARROWED by Task 8, not closed. Now checked: the permit deadline, against the \
              PINNED block's chain clock (PreflightError::PermitWouldRevert), and the fee \
              token's own nonces(owner), read directly via ChainClient::erc2612_nonces and \
              bound to the gateway snapshot's feeTokenPermitNonce word. Still unverifiable: \
              the SIGNATURE. EIP-2612's permit() takes no nonce argument, so the nonce the \
              client's v/r/s actually signed over is not present anywhere in the calldata and \
              cannot be compared against the live counter — a permit signed for a nonce the \
              token has since consumed is indistinguishable here from a valid one. Recovering \
              the signer instead would need the token's DOMAIN_SEPARATOR, which nothing in \
              this crate reads. :832's owner/spender/value conditions ARE checked \
              (Check::Eip2612FeeFieldsMismatch)",
    },
    // Entry 11 — Wave 2. Not a gateway revert at all, and deliberately so:
    // the disclosure mechanism is about "checks that did not run", and this
    // is one, even though the check in question is this crate's own money
    // gate rather than a Solidity precondition.
    UnverifiedCheck {
        revert: "NO REVERT — native-ETH exposure gate (hazard 1) SKIPPED on this chain",
        site: "stream_g/base_fee.rs (submit_exposure_for_chain / chain_carries_gas_price_oracle)",
        why: "The submit-time exposure gate calls the OP-Stack GasPriceOracle PREDEPLOY at \
              0x420000000000000000000000000000000000000F, which exists only because an OP-Stack \
              genesis puts it there. On chain 31337 (the local dev chain) nothing deploys or \
              etches it — DeployStreamG.s.sol does neither — so the three eth_calls would return \
              empty, decode as a hard Err, and classify Terminal, making every sponsored \
              enrollment on that chain permanently unsubmittable. The gate therefore does not \
              run there and NO native-ETH ceiling is enforced: gas_limit*max_fee_per_gas, the L1 \
              data-availability fee and the operator fee are all unbounded on such a chain. \
              This is now the ONLY residue: as of Wave C W4 the mounted route \
              POST /v1/stream-g/submit (submit::post_submit) binds \
              SubmitContext::max_native_exposure_wei from \
              StreamGConfig::max_native_exposure_wei, submit.rs copies it verbatim into \
              BroadcastPlan (Wave C W2), and the route refuses with a 503 rather than serving \
              requests while that config value is the 0 default. Hazard 1 is CLOSED on the \
              submit path for every chain that carries the predeploy, and OPEN on chain 31337",
    },
];

// ---------------------------------------------------------------------------
// Live state.
// ---------------------------------------------------------------------------

pub const ERR_PREFLIGHT_CHAIN_READ: &str = "PREFLIGHT_CHAIN_READ_FAILED";
pub const ERR_PREFLIGHT_ENDPOINT_CHAIN_MISMATCH: &str = "PREFLIGHT_ENDPOINT_CHAIN_MISMATCH";
pub const ERR_PREFLIGHT_STATE_MISBOUND: &str = "PREFLIGHT_STATE_MISBOUND";
pub const ERR_PREFLIGHT_SNAPSHOT_TOCTOU: &str = "PREFLIGHT_SNAPSHOT_TOCTOU";
pub const ERR_PREFLIGHT_WOULD_REVERT: &str = "PREFLIGHT_WOULD_REVERT";
/// Task 8 Mandate 3 — the fee token's own `permit()` would revert.
pub const ERR_PREFLIGHT_PERMIT_WOULD_REVERT: &str = "PREFLIGHT_PERMIT_WOULD_REVERT";
/// Task 8 Mandate 3 — the token's `nonces(owner)` and the gateway
/// snapshot's `feeTokenPermitNonce` disagree at the same pinned block.
pub const ERR_PREFLIGHT_PERMIT_NONCE_MISBOUND: &str = "PREFLIGHT_PERMIT_NONCE_MISBOUND";

/// Everything preflight compares against, all read at one pinned block.
///
/// Fields are private and the only production constructor is
/// [`read_live_preflight_state`] — the same `GatedExposure` /
/// `LiveTokenReading` / `LiveEnrollmentNonces` posture the rest of this
/// module tree uses. A caller cannot hand preflight a state record it
/// assembled from config.
#[derive(Debug, Clone)]
pub struct LivePreflightState {
    live_token: LiveTokenReading,
    live_nonces: LiveEnrollmentNonces,
    snapshot: NonceSnapshotView,
    active_manifest_hash: [u8; 32],
    chain_now: u64,
    /// The fee token's OWN ERC-2612 `nonces(controller)`, read directly from
    /// the token at [`Self::block`] (Task 8 Mandate 3) and bound at
    /// construction to the gateway snapshot's `feeTokenPermitNonce` word.
    fee_token_permit_nonce: u128,
    block: u64,
    gateway: [u8; 20],
    registry: [u8; 20],
    queried_root: [u8; 20],
    queried_secondary: [u8; 20],
    queried_fee_token: [u8; 20],
}

impl LivePreflightState {
    pub fn live_token(&self) -> &LiveTokenReading {
        &self.live_token
    }
    pub fn live_nonces(&self) -> &LiveEnrollmentNonces {
        &self.live_nonces
    }
    /// The snapshot [`Self::live_nonces`] was derived from — same call,
    /// same block. Read `controller`, `controllerEpoch` and `actionNonce`
    /// from here (their `presentMask` bits are validated at construction).
    pub fn snapshot(&self) -> &NonceSnapshotView {
        &self.snapshot
    }
    /// `FeeTokenRegistry.activeManifestHash()` at [`Self::block`] — sourcing
    /// contract R2 step 2.
    pub fn active_manifest_hash(&self) -> [u8; 32] {
        self.active_manifest_hash
    }
    /// `block.timestamp` **of [`Self::block`]**, as the chain reports it.
    ///
    /// Never a host wall clock: `GoatRelayGateway.sol:342` and `:714` are
    /// both chain-clock comparisons, and this crate's convention (see
    /// `quotes.rs` STEP 4) is that there is no wall-clock fallback anywhere.
    ///
    /// Task 8 Mandate 3 additionally made it the clock of the PINNED block
    /// rather than of floating `latest`: this value now comes from
    /// [`ChainClient::block_timestamp_at`]`(block)`, not from
    /// `ChainClient::block_timestamp()`. Before that change the state was
    /// read at block `N` while the clock came from whatever the head was a
    /// few RPC round-trips later, so a deadline falling in that window was
    /// judged against a timestamp the pinned state never saw.
    pub fn chain_now(&self) -> u64 {
        self.chain_now
    }
    /// The fee token's own ERC-2612 `nonces(controller)` at [`Self::block`],
    /// read from the token itself (not from the gateway's snapshot word,
    /// though construction requires the two to agree).
    pub fn fee_token_permit_nonce(&self) -> u128 {
        self.fee_token_permit_nonce
    }
    pub fn block(&self) -> u64 {
        self.block
    }
}

#[derive(Debug, Error)]
pub enum PreflightError {
    #[error("live chain read failed ({what}): {detail}")]
    ChainRead { what: &'static str, detail: String },
    #[error(transparent)]
    TokenState(#[from] TokenManifestError),
    #[error(transparent)]
    Nonces(#[from] LiveNoncesError),
    /// The endpoint is not on the chain the manifest was written for. Every
    /// EIP-712 digest below would be computed under the wrong domain, so
    /// there is nothing useful to preflight.
    #[error(
        "endpoint reports chain {endpoint_chain_id} but the manifest is for {manifest_chain_id}"
    )]
    EndpointChainMismatch {
        endpoint_chain_id: u64,
        manifest_chain_id: u64,
    },
    /// The state was read for a different root/secondary/fee token than the
    /// intent names, so its nonces and controller say nothing about this
    /// call.
    #[error("live state was read for {what} 0x{read_for} but the intent names 0x{intent}")]
    StateMisbound {
        what: &'static str,
        read_for: String,
        intent: String,
    },
    /// Sourcing contract R3's anti-TOCTOU binding: the fee-token config the
    /// gate authorized and the nonces the call commits to were observed in
    /// different chain states.
    #[error(
        "fee token config hash disagrees between the registry read (0x{live_token}) \
         and the gateway's snapshot (0x{snapshot})"
    )]
    SnapshotToctouMismatch {
        live_token: String,
        snapshot: String,
    },
    /// A precondition that would revert on chain.
    #[error("would revert {}() at {} — {detail}", .check.revert(), .check.site())]
    WouldRevert { check: Check, detail: String },
    /// The fee token's **own** ERC-2612 `permit()` would revert before
    /// `StreamGCommon.collectEip2612` (`StreamGCommon.sol:200-212`) could transfer
    /// anything (Task 8 Mandate 3).
    ///
    /// Deliberately **not** a [`Check`]. `Check`'s invariant — enforced by
    /// [`tests::every_check_names_a_real_revert_and_site`] — is that
    /// every variant names an error declared in `GoatRelayGateway.sol` or
    /// `WalletSponsorshipRegistry.sol`. This revert is raised inside a
    /// **third** contract (the fee token), which declares its own errors
    /// (`ERC2612ExpiredSignature` in OpenZeppelin v5, a string revert in
    /// v4). Forcing it into `Check` would have meant either lying about
    /// which contract reverts or widening that invariant until it stopped
    /// catching anything.
    #[error("the fee token's own ERC-2612 permit() would revert (called at {site}) — {detail}")]
    PermitWouldRevert {
        /// `file:line` of the `permit()` **call site** in the gateway, plus
        /// the standard clause the token would fail.
        site: &'static str,
        detail: String,
    },
    /// Task 8 Mandate 3's independent-read binding, the same shape as
    /// [`Self::SnapshotToctouMismatch`]: the fee token's own
    /// `nonces(controller)` and the gateway snapshot's `feeTokenPermitNonce`
    /// word were read at the SAME pinned block and disagree.
    ///
    /// At one block these cannot legitimately differ — the gateway's
    /// `_snapshot` (`GoatRelayGateway.sol:288`) populates that word with
    /// literally `IERC20Permit(feeToken).nonces(goatOwner)`. A disagreement
    /// therefore means the snapshot describes a different owner than the one
    /// `_collectEip2612` will pay with, the snapshot word was decoded from
    /// the wrong offset, or the token's `nonces` is not the function the
    /// gateway calls. None of those are safe to quote through.
    #[error(
        "fee token nonces(0x{owner}) = {token_nonce} but the gateway snapshot's \
         feeTokenPermitNonce = {snapshot_nonce}, both read at block {block}"
    )]
    PermitNonceMisbound {
        owner: String,
        token_nonce: u128,
        snapshot_nonce: u128,
        block: u64,
    },
}

impl PreflightError {
    /// Stable string code for logs/HTTP mapping.
    pub fn code(&self) -> &'static str {
        match self {
            PreflightError::ChainRead { .. } => ERR_PREFLIGHT_CHAIN_READ,
            PreflightError::TokenState(e) => e.code(),
            PreflightError::Nonces(e) => e.code(),
            PreflightError::EndpointChainMismatch { .. } => ERR_PREFLIGHT_ENDPOINT_CHAIN_MISMATCH,
            PreflightError::StateMisbound { .. } => ERR_PREFLIGHT_STATE_MISBOUND,
            PreflightError::SnapshotToctouMismatch { .. } => ERR_PREFLIGHT_SNAPSHOT_TOCTOU,
            PreflightError::WouldRevert { .. } => ERR_PREFLIGHT_WOULD_REVERT,
            PreflightError::PermitWouldRevert { .. } => ERR_PREFLIGHT_PERMIT_WOULD_REVERT,
            PreflightError::PermitNonceMisbound { .. } => ERR_PREFLIGHT_PERMIT_NONCE_MISBOUND,
        }
    }

    /// HTTP status for the shared Stream G error envelope
    /// (`super::http_error`). Wildcard-free on purpose — see
    /// [`super::base_fee::BaseFeeError::status`].
    ///
    /// The two "misbound" arms are **500**, not 4xx: they mean this process
    /// read state for one subject and is holding it against another, or that
    /// its RPC endpoint is on a different chain than the manifest it loaded.
    /// A caller cannot cause either and cannot fix either by changing the
    /// request.
    pub fn status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            PreflightError::ChainRead { .. } => StatusCode::BAD_GATEWAY,
            PreflightError::TokenState(e) => e.status(),
            PreflightError::Nonces(e) => e.status(),
            PreflightError::EndpointChainMismatch { .. } | PreflightError::StateMisbound { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            // The chain moved between two reads. Neither party is wrong;
            // re-reading at one block is the resolution.
            PreflightError::SnapshotToctouMismatch { .. }
            | PreflightError::PermitNonceMisbound { .. } => StatusCode::CONFLICT,
            // Well-formed call, would fail on chain.
            PreflightError::WouldRevert { .. } | PreflightError::PermitWouldRevert { .. } => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
        }
    }

    /// The [`Check`] that failed, when this is a `WouldRevert`.
    pub fn check(&self) -> Option<Check> {
        match self {
            PreflightError::WouldRevert { check, .. } => Some(*check),
            _ => None,
        }
    }
}

/// The only production constructor of [`LivePreflightState`].
///
/// Reads, in order:
/// 1. `eth_blockNumber` — the block every *state* read below is pinned to (R4).
/// 2. `token_manifest::read_live_token_state` — R1 (`eth_getCode`) + R2
///    (`getTokenConfig` bound to `getTokenConfigHash`) + `eth_chainId`.
/// 3. `FeeTokenRegistry.activeManifestHash()` — R2 step 2, which
///    `read_live_token_state` cannot do because it is given no manifest.
/// 4. **One** `secondaryEnrollmentNonceSnapshot` (R3), validated through
///    `LiveEnrollmentNonces::from_snapshot` and then additionally required
///    to carry `SNAP_CONTROLLER` and `SNAP_ACTION_NONCE`, because preflight
///    reads those words too and a cleared bit means the zero sitting there
///    is meaningless.
/// 5. **One** `IERC20Permit(feeToken).nonces(controller)` at the same block
///    (Task 8 Mandate 3), bound to the snapshot's `feeTokenPermitNonce`.
/// 6. `block.timestamp` **of `block`** via
///    [`ChainClient::block_timestamp_at`] — not `block_timestamp()`'s
///    floating `latest` — still fail-closed on a zero.
///
/// Then enforces the agreements that make the rest of preflight meaningful:
/// endpoint chain id vs `manifest.chain_id` (`:921`), the snapshot's
/// `feeTokenConfigHash` vs the registry's (`:966`), and the fee token's own
/// ERC-2612 nonce vs the snapshot's (`:1011`).
///
/// It does **not** compare `activeManifestHash()` against
/// `manifest.deployment_manifest_hash`. Step 3's value is carried out in
/// [`LivePreflightState::active_manifest_hash`] and compared by
/// [`preflight_sponsored_enrollment`] instead (`:1658-1674`), against the
/// intent, the quote and the snapshot — which is the comparison the gateway
/// itself makes (`contracts/src/libraries/StreamGCommon.sol:118-121`). The
/// manifest file is not a party to it, so a reader must not expect a refusal
/// here on a manifest the chain has replaced;
/// `tests::check_17_manifest_hash_comes_from_the_live_active_manifest_hash_read`
/// is where that verdict is pinned.
pub fn read_live_preflight_state<'c>(
    chain: impl Into<TrustedChain<'c>>,
    manifest: &DeploymentManifest,
    root: [u8; 20],
    secondary: [u8; 20],
) -> Result<LivePreflightState, PreflightError> {
    // Fail-closed chain-honesty gate — see [`TrustedChain`]. Preflight's whole
    // job is to believe what the chain says; in a release build the only thing
    // that satisfies `Into<TrustedChain>` is `TrustedChain::live(&RpcChain)`,
    // so `MockChain` cannot be the thing being believed.
    let trusted: TrustedChain<'c> = chain.into();
    let chain: &dyn ChainClient = trusted.client();

    let block = chain
        .pinned_block_number()
        .map_err(|e| PreflightError::ChainRead {
            what: "eth_blockNumber",
            detail: e.to_string(),
        })?;

    let live_token = token_manifest::read_live_token_state(
        trusted,
        manifest.fee_token_registry,
        manifest.fee_token,
        block,
    )?;

    // The endpoint's own `eth_chainId`, surfaced by `read_live_token_state`
    // as of Task 6 Wave B. If it disagrees with the manifest, every EIP-712
    // domain separator below is wrong and preflight has nothing to say.
    let endpoint_chain_id = live_token.live_chain_id().into_inner();
    if endpoint_chain_id != manifest.chain_id {
        return Err(PreflightError::EndpointChainMismatch {
            endpoint_chain_id,
            manifest_chain_id: manifest.chain_id,
        });
    }

    // R2 step 2 — a manifest the chain has since replaced means every hash
    // this call commits to is stale.
    let active_manifest_hash = chain
        .active_manifest_hash(manifest.fee_token_registry, block)
        .map_err(|e| PreflightError::ChainRead {
            what: "FeeTokenRegistry.activeManifestHash",
            detail: e.to_string(),
        })?;

    // R3 — exactly ONE snapshot call. See the module doc for why this is
    // `LiveEnrollmentNonces::read_live` unpacked rather than a second read.
    let snapshot = chain
        .secondary_enrollment_nonce_snapshot(
            manifest.goat_relay_gateway,
            root,
            secondary,
            manifest.fee_token,
            block,
        )
        .map_err(|e| PreflightError::ChainRead {
            what: "GoatRelayGateway.secondaryEnrollmentNonceSnapshot",
            detail: e.to_string(),
        })?;
    let live_nonces = LiveEnrollmentNonces::from_snapshot(&snapshot)?;

    // `from_snapshot` validates the bits IT reads. Preflight additionally
    // reads `controller`, `controllerEpoch` and `actionNonce`, so it must
    // validate their bits itself — a cleared bit is a meaningless zero
    // (sourcing contract R3), and reading `controller` as a meaningless zero
    // would turn check 8 into a false "controller unset" rejection while
    // reading `actionNonce` as one would fabricate a nonce agreement.
    require_snapshot_bit(&snapshot, SNAP_CONTROLLER, "controller/controllerEpoch")?;
    require_snapshot_bit(&snapshot, SNAP_ACTION_NONCE, "actionNonce")?;

    // R3's anti-TOCTOU binding, same comparison `quotes.rs` makes: two
    // INDEPENDENT reads (`getTokenConfigHash` via `read_live_token_state`,
    // and the gateway's own view inside the snapshot) must agree, or the two
    // straddled a config upsert / reorg.
    if live_token.fee_token_config_hash() != live_nonces.fee_token_config_hash() {
        return Err(PreflightError::SnapshotToctouMismatch {
            live_token: hex::encode(live_token.fee_token_config_hash()),
            snapshot: hex::encode(live_nonces.fee_token_config_hash()),
        });
    }

    // Task 8 Mandate 3, part 2 — the fee token's OWN ERC-2612 nonce.
    //
    // `_snapshot` (`GoatRelayGateway.sol:290`) fills `feeTokenPermitNonce`
    // with literally `IERC20Permit(feeToken).nonces(goatOwner)`. So the
    // gateway already hands us its view of that counter, and until this wave
    // that was the ONLY view: `ChainClient::erc2612_nonces` shipped in Task 7
    // with zero consumers anywhere in `src/stream_g/`.
    //
    // Reading the token directly at the SAME pinned block turns one reported
    // number into two independent ones that must agree — the identical shape
    // to the `getTokenConfigHash`-vs-snapshot binding above (R3). At a single
    // block they cannot legitimately differ, so a disagreement is real
    // evidence of misbinding, not of a race. `SNAP_FEE_TOKEN_PERMIT_NONCE`
    // was already required by `LiveEnrollmentNonces::from_snapshot`, and
    // `SNAP_CONTROLLER` was required immediately above, so both sides of the
    // comparison are known-populated words rather than meaningless zeroes.
    //
    // The owner must be the gateway's own derivation, not "the controller".
    // `:279` is `goatOwner = controller != 0 ? controller : (root != 0 ? root
    // : signer)`, and `secondaryEnrollmentNonceSnapshot` (`:201-214`) passes
    // `signer = controllerOf(root) == 0 ? root : controllerOf(root)`; both
    // fallbacks collapse to `root`, so the owner is exactly
    // `controller != 0 ? controller : root`. Reading `nonces(controller)`
    // unconditionally would compare `nonces(0)` against the snapshot's
    // `nonces(root)` on an unregistered root and reject it as a nonce
    // misbinding, when the honest verdict is `Check::ControllerUnset`.
    let permit_owner = if snapshot.controller() == [0u8; 20] {
        root
    } else {
        snapshot.controller()
    };
    let token_permit_nonce = chain
        .erc2612_nonces(manifest.fee_token, permit_owner, block)
        .map_err(|e| PreflightError::ChainRead {
            what: "IERC20Permit(feeToken).nonces",
            detail: e.to_string(),
        })?;
    let token_permit_nonce = u128::from(token_permit_nonce);
    if token_permit_nonce != snapshot.fee_token_permit_nonce() {
        return Err(PreflightError::PermitNonceMisbound {
            owner: hex::encode(permit_owner),
            token_nonce: token_permit_nonce,
            snapshot_nonce: snapshot.fee_token_permit_nonce(),
            block,
        });
    }

    // Task 8 Mandate 3, part 1 — the clock of the PINNED block, not of
    // floating `latest`. `block_timestamp_at` is a different method from
    // `block_timestamp` precisely so this cannot silently drift back: every
    // state word above came from `block`, and a deadline judged against a
    // later head is judged against a chain state this report never observed.
    let chain_now = chain
        .block_timestamp_at(block)
        .map_err(|e| PreflightError::ChainRead {
            what: "block.timestamp @ pinned block",
            detail: e.to_string(),
        })?;
    if chain_now == 0 {
        // `block_timestamp_at`'s trait default is `Err`, not `Ok(0)`, so this
        // guard no longer defends against an unimplemented method — it now
        // defends against a node that genuinely answers 0 (a devnet genesis
        // block, or a stub returning a zeroed header). Treating that as 1970
        // would put every deadline comparison below in the far future. Fail
        // closed, exactly as `quotes.rs` STEP 4 does.
        return Err(PreflightError::ChainRead {
            what: "block.timestamp @ pinned block",
            detail: format!(
                "block {block} reports timestamp 0, which cannot be a live chain clock"
            ),
        });
    }

    Ok(LivePreflightState {
        live_token,
        live_nonces,
        snapshot,
        active_manifest_hash,
        chain_now,
        fee_token_permit_nonce: token_permit_nonce,
        block,
        gateway: manifest.goat_relay_gateway,
        registry: manifest.fee_token_registry,
        queried_root: root,
        queried_secondary: secondary,
        queried_fee_token: manifest.fee_token,
    })
}

fn require_snapshot_bit(
    snap: &NonceSnapshotView,
    bit: u32,
    field: &'static str,
) -> Result<(), PreflightError> {
    if snap.present_mask() & bit == 0 {
        return Err(PreflightError::ChainRead {
            what: "GoatRelayGateway.secondaryEnrollmentNonceSnapshot",
            detail: format!(
                "presentMask 0x{:08x} has bit 0x{:08x} clear: {field} was never populated \
                 (live-chain sourcing contract R3)",
                snap.present_mask(),
                bit
            ),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Report.
// ---------------------------------------------------------------------------

/// What the caller should do with this call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The attestor may broadcast `executeSponsoredEnrollment` with the
    /// sponsored (token) branch.
    RelaySponsored,
    /// `_isDirectEthEnrollment` is true, so the contract requires
    /// `msg.sender == intent.controller` (`GoatRelayGateway.sol:379`). A
    /// relayer can never satisfy that. The client must submit the
    /// transaction itself; **do not** issue a sponsored quote for it.
    ClientMustSubmitDirectly,
}

/// The result of a passing preflight. Carries [`UNVERIFIED_CHECKS`] so a
/// caller reading only the happy path still sees the limits of the claim.
#[derive(Debug, Clone)]
pub struct PreflightReport {
    pub disposition: Disposition,
    pub unverified: &'static [UnverifiedCheck],
    /// The block every state read was pinned to.
    pub block: u64,
    /// `block.timestamp` the deadline/window checks were evaluated against.
    pub chain_now: u64,
}

// ---------------------------------------------------------------------------
// The preflight itself.
// ---------------------------------------------------------------------------

fn revert(check: Check, detail: impl Into<String>) -> PreflightError {
    PreflightError::WouldRevert {
        check,
        detail: detail.into(),
    }
}

fn ensure(cond: bool, check: Check, detail: impl Into<String>) -> Result<(), PreflightError> {
    if cond {
        Ok(())
    } else {
        Err(revert(check, detail))
    }
}

/// Generic ECDSA recover-and-compare. `quotes.rs` keeps its copy private
/// and `sig_verify.rs`'s wrappers are struct-specific, so this module has
/// its own — same crate convention.
fn recovers_to(digest: [u8; 32], signature_hex: &str, expected: [u8; 20]) -> Result<(), String> {
    let trimmed = signature_hex.trim();
    let h = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let bytes = hex::decode(h).map_err(|_| "malformed signature hex".to_string())?;
    if bytes.len() != 65 {
        return Err(format!("signature must be 65 bytes, got {}", bytes.len()));
    }
    let sig =
        Signature::try_from(bytes.as_slice()).map_err(|_| "malformed signature".to_string())?;
    let recovered = sig
        .recover_address_from_prehash(&B256::from_slice(&digest))
        .map_err(|_| "ecrecover failed".to_string())?;
    if recovered.into_array() != expected {
        return Err(format!(
            "recovered 0x{}, expected 0x{}",
            hex::encode(recovered.into_array()),
            hex::encode(expected)
        ));
    }
    Ok(())
}

fn signature_bytes_len(signature_hex: &str) -> usize {
    let trimmed = signature_hex.trim();
    let h = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    hex::decode(h).map(|b| b.len()).unwrap_or(usize::MAX)
}

/// All twelve `FeeQuote` fields zero — `GoatRelayGateway.sol:381-389`.
///
/// `pub(crate)` (Task 7 Wave E): `direct_eth.rs` enforces the same
/// precondition when it builds the envelope the controller submits, and a
/// second copy of a twelve-field predicate is precisely how one of them drifts
/// a field behind the other.
pub(crate) fn fee_quote_is_all_zero(q: &FeeQuote) -> bool {
    q.quote_id == [0u8; 32]
        && q.action_type == [0u8; 32]
        && q.action_core_hash == [0u8; 32]
        && q.deployment_manifest_hash == [0u8; 32]
        && q.fee_token_config_hash == [0u8; 32]
        && q.fee_schedule_hash == [0u8; 32]
        && q.payer == [0u8; 20]
        && q.fee_token == [0u8; 20]
        && q.fee_amount == 0
        && q.fee_recipient == [0u8; 20]
        && q.valid_after == 0
        && q.valid_until == 0
}

/// Would `executeSponsoredEnrollment(call)` succeed against `state`?
///
/// Checks run in **the contract's own order**, so the first rejection is
/// the revert the transaction would actually produce. `manifest` supplies
/// addresses and domain parameters only (which contract we are talking to,
/// which chain, which registries) — never a live value; those all come from
/// `state`.
pub fn preflight_sponsored_enrollment(
    call: &SponsoredEnrollmentCall<'_>,
    state: &LivePreflightState,
    manifest: &DeploymentManifest,
) -> Result<PreflightReport, PreflightError> {
    let intent = call.intent;
    let quote = call.quote;

    // --- 0. The state must be about THIS call. ------------------------
    if state.gateway != manifest.goat_relay_gateway || state.registry != manifest.fee_token_registry
    {
        return Err(PreflightError::StateMisbound {
            what: "gateway/registry",
            read_for: hex::encode(state.gateway),
            intent: hex::encode(manifest.goat_relay_gateway),
        });
    }
    let chain_id = state.live_token.live_chain_id().into_inner();

    // --- 1. `_requireLive` — UNVERIFIABLE, see UNVERIFIED_CHECKS. -----

    // --- 2. `:342` ----------------------------------------------------
    ensure(
        state.chain_now < intent.deadline,
        Check::ExpiredDeadline,
        format!(
            "block.timestamp {} >= intent.deadline {}",
            state.chain_now, intent.deadline
        ),
    )?;

    // --- 3. `:343` ----------------------------------------------------
    ensure(
        intent.secondary != [0u8; 20] && intent.root != [0u8; 20],
        Check::ZeroRootOrSecondary,
        "intent.secondary and intent.root must both be non-zero",
    )?;

    // Now that root/secondary are known non-zero: the live state must have
    // been read for THIS pair, or its nonces, controller and epoch describe
    // some other cluster entirely. Placed after checks 2-3 so a malformed
    // intent still gets the revert the chain would give it, rather than this
    // module's own binding error.
    if state.queried_root != intent.root {
        return Err(PreflightError::StateMisbound {
            what: "root",
            read_for: hex::encode(state.queried_root),
            intent: hex::encode(intent.root),
        });
    }
    if state.queried_secondary != intent.secondary {
        return Err(PreflightError::StateMisbound {
            what: "secondary",
            read_for: hex::encode(state.queried_secondary),
            intent: hex::encode(intent.secondary),
        });
    }

    // --- 4. `:344` ----------------------------------------------------
    ensure(
        intent.secondary == call.link.secondary && intent.root == call.link.root,
        Check::LinkFieldsMismatch,
        "link.root/link.secondary must equal intent.root/intent.secondary",
    )?;

    // --- 5. `:345` ----------------------------------------------------
    ensure(
        call.v1_enrollment.wallet == intent.secondary,
        Check::V1WalletMismatch,
        "v1Enrollment.wallet must equal intent.secondary",
    )?;

    // --- 6, 7 — UNVERIFIABLE (primaryOf / suspendedClusters). ---------

    // --- 8. `:351` — snapshot's `controller` is `controllerOf(root)`
    // (`GoatRelayGateway.sol:274`), read at the pinned block. ----------
    let live_controller = state.snapshot.controller();
    ensure(
        live_controller != [0u8; 20],
        Check::ControllerUnset,
        "sponsorship.controllerOf(root) is the zero address (root has no controller)",
    )?;

    // --- 9. `:352` ----------------------------------------------------
    ensure(
        intent.controller == live_controller,
        Check::ControllerMismatch,
        format!(
            "intent.controller 0x{} != live controllerOf(root) 0x{}",
            hex::encode(intent.controller),
            hex::encode(live_controller)
        ),
    )?;

    // --- 10. `:353` ---------------------------------------------------
    let live_epoch = state.snapshot.controller_epoch();
    ensure(
        u128::from(intent.controller_epoch) == live_epoch,
        Check::EpochMismatch,
        format!(
            "intent.controllerEpoch {} != live controllerEpoch {}",
            intent.controller_epoch, live_epoch
        ),
    )?;

    // --- 11. `:355-356` — `_v1EnrollDigest` reproduced by
    // `sig_verify::enroll_digest` under the EnrollmentRegistry domain. --
    let enroll_digest = sig_verify::enroll_digest(
        call.v1_enrollment.wallet,
        call.v1_enrollment.nonce,
        call.v1_enrollment.deadline,
        chain_id,
        manifest.enrollment_registry,
    );
    ensure(
        enroll_digest == intent.enroll_digest,
        Check::EnrollDigestMismatch,
        format!(
            "_v1EnrollDigest = 0x{} but intent.enrollDigest = 0x{}",
            hex::encode(enroll_digest),
            hex::encode(intent.enroll_digest)
        ),
    )?;

    // --- 12. `:357-358` -----------------------------------------------
    if let Err(e) = recovers_to(
        enroll_digest,
        &call.v1_enrollment.signature_hex,
        intent.secondary,
    ) {
        return Err(revert(Check::BadV1Signature, e));
    }

    // --- 13. `:360-361` -----------------------------------------------
    let link_digest =
        link_secondary_digest(call.link, chain_id, manifest.wallet_sponsorship_registry);
    ensure(
        link_digest == intent.link_digest,
        Check::LinkDigestMismatch,
        format!(
            "_linkDigest = 0x{} but intent.linkDigest = 0x{}",
            hex::encode(link_digest),
            hex::encode(intent.link_digest)
        ),
    )?;

    // --- 14. `:362-363` -----------------------------------------------
    if let Err(e) = recovers_to(link_digest, call.link_signature_hex, intent.secondary) {
        return Err(revert(Check::BadLinkSignature, e));
    }

    // --- 15. `:365` ---------------------------------------------------
    ensure(
        intent.root_authorization_digest == [0u8; 32],
        Check::NonZeroRootAuthorizationDigest,
        "intent.rootAuthorizationDigest must be zero on the sponsored-enrollment path",
    )?;

    // --- 16. `:366-373` -----------------------------------------------
    ensure(
        call.root_authorization.is_all_zero()
            && signature_bytes_len(call.root_authorization_signature_hex) == 0,
        Check::NonZeroRootAuthorization,
        "all six RootAuthorization fields and rootAuthorizationSignature must be empty/zero",
    )?;

    // --- branch: `:375` / `_isDirectEthEnrollment` (`:645-652`). ------
    let direct = is_direct_eth_enrollment(intent);

    if direct {
        // `:379` — `msg.sender == intent.controller`. A relayer never is.
        // Everything below is still validated so the client learns whether
        // ITS own submission would land.

        // `:380`
        ensure(
            signature_bytes_len(call.quote_signature_hex) == 0,
            Check::DirectEthQuoteSignaturePresent,
            "direct-ETH enrollment requires an empty quoteSignature",
        )?;
        // `:381-389`
        ensure(
            fee_quote_is_all_zero(quote),
            Check::DirectEthQuoteNotZeroed,
            "direct-ETH enrollment requires all twelve FeeQuote fields to be zero",
        )?;
        // `:390`
        ensure(
            call.fee_authorization_mode == AUTHORIZATION_MODE_NONE,
            Check::DirectEthFeeAuthorizationNotNone,
            "direct-ETH enrollment requires feeAuthorization.mode == NONE",
        )?;
    } else {
        preflight_quote(call, state, manifest)?;

        // --- 18. `:394` — THE check. `intent.feeQuoteHash` is the quote's
        // FULL EIP-712 digest, not its `quoteId`. -----------------------
        let expected_fee_quote_hash =
            fee_quote_digest(quote, chain_id, manifest.goat_relay_gateway);
        ensure(
            intent.fee_quote_hash == expected_fee_quote_hash,
            Check::FeeQuoteHashMismatch,
            format!(
                "intent.feeQuoteHash = 0x{} but _hashTypedDataV4(_feeQuoteStructHash(quote)) \
                 = 0x{} (note: this is the quote's full EIP-712 digest, NOT quote.quoteId 0x{})",
                hex::encode(intent.fee_quote_hash),
                hex::encode(expected_fee_quote_hash),
                hex::encode(quote.quote_id)
            ),
        )?;

        // --- 19. `:395-397` -------------------------------------------
        ensure(
            intent.fee_authorization_mode == AUTHORIZATION_MODE_EIP2612,
            Check::UnsupportedFeeMode,
            format!(
                "intent.feeAuthorizationMode = {} but the sponsored path requires \
                 AuthorizationMode.EIP2612 = {AUTHORIZATION_MODE_EIP2612}",
                intent.fee_authorization_mode
            ),
        )?;
    }

    // --- 20. `:400-402` — the CONTROLLER's signature over
    // SponsorEnrollment. User-side; the attestor verifies, never signs. -
    let sponsor_digest = sponsor_enrollment_digest(intent, chain_id, manifest.goat_relay_gateway);
    if let Err(e) = recovers_to(
        sponsor_digest,
        call.sponsor_signature_hex,
        intent.controller,
    ) {
        return Err(revert(Check::BadSponsorSignature, e));
    }

    // --- effects `:405` / `_markIntentAndNonce` (`:315-323`). ---------
    ensure(
        intent.intent_id != [0u8; 32],
        Check::ZeroIntentId,
        "intent.intentId must be non-zero",
    )?;
    // `intentUsed` — UNVERIFIABLE.
    let live_action_nonce = state.snapshot.action_nonce();
    ensure(
        u128::from(intent.nonce) == live_action_nonce,
        Check::BadActionNonce,
        format!(
            "intent.nonce {} != live actionNonces[controller][ACTION_SPONSORED_ENROLLMENT] {}",
            intent.nonce, live_action_nonce
        ),
    )?;

    // --- effects `:410` / `_enrollV1OrAcceptFrontRun` (`:741-758`). ---
    // `enrolled`/`blacklisted` are unreadable, but BOTH accepted branches
    // require `liveNonce == v1.nonce` or `liveNonce == v1.nonce + 1`;
    // anything else reverts `InvalidV1Enrollment` whatever `enrolled` is.
    let live_v1_nonce = state.live_nonces.v1_enroll_nonce();
    ensure(
        live_v1_nonce == call.v1_enrollment.nonce
            || live_v1_nonce == call.v1_enrollment.nonce.saturating_add(1),
        Check::V1EnrollNonceUnusable,
        format!(
            "live EnrollmentRegistry.nonces(secondary) = {live_v1_nonce}, but neither \
             branch of _enrollV1OrAcceptFrontRun accepts it against v1Enrollment.nonce {} \
             (needs {} or {})",
            call.v1_enrollment.nonce,
            call.v1_enrollment.nonce,
            call.v1_enrollment.nonce.saturating_add(1)
        ),
    )?;

    // --- effects `:414` / `WalletSponsorshipRegistry.linkSecondary`. --
    ensure(
        call.link.secondary != call.link.root,
        Check::LinkSecondaryEqualsRoot,
        "link.secondary must not equal link.root",
    )?;
    ensure(
        state.chain_now < call.link.deadline,
        Check::LinkDeadlineExpired,
        format!(
            "block.timestamp {} >= link.deadline {}",
            state.chain_now, call.link.deadline
        ),
    )?;
    ensure(
        call.link.nonce == state.live_nonces.link_nonce(),
        Check::LinkNonceMismatch,
        format!(
            "link.nonce {} != live linkNonces(secondary) {}",
            call.link.nonce,
            state.live_nonces.link_nonce()
        ),
    )?;

    // --- effects `:418` / `_collectEip2612Fee` (`:760-768`). ----------
    if !direct {
        ensure(
            call.fee_authorization_mode == AUTHORIZATION_MODE_EIP2612,
            Check::FeeAuthorizationModeNotEip2612,
            format!(
                "feeAuthorization.mode = {} but _collectEip2612Fee requires \
                 AuthorizationMode.EIP2612 = {AUTHORIZATION_MODE_EIP2612}",
                call.fee_authorization_mode
            ),
        )?;

        // --- effects `:418` / `_collectEip2612` (`:826-833`). Task 3
        // follow-up: `:832`'s combined `owner == payer && spender ==
        // address(this) && value >= feeAmount`. `feeAmount` here is
        // `quote.feeAmount` — `_validateAndConsumeQuoteGeneric` (`:738`)
        // returns exactly that value as the `feeAmount` `_collectEip2612Fee`
        // is later called with, and this branch has already proven
        // `quote.feeAmount` is the fee for this call (checks `:712-713`
        // above). See [`Eip2612Authorization`]'s doc for what remains
        // unverified (the `permit()` call itself).
        let p = call.fee_eip2612_authorization;
        ensure(
            p.owner == intent.controller
                && p.spender == manifest.goat_relay_gateway
                && p.value >= quote.fee_amount,
            Check::Eip2612FeeFieldsMismatch,
            format!(
                "Eip2612Authorization{{owner: 0x{}, spender: 0x{}, value: {}}} fails \
                 _collectEip2612's owner==payer(0x{})/spender==gateway(0x{})/value>=feeAmount({}) \
                 check",
                hex::encode(p.owner),
                hex::encode(p.spender),
                p.value,
                hex::encode(intent.controller),
                hex::encode(manifest.goat_relay_gateway),
                quote.fee_amount
            ),
        )?;

        // --- Task 8 Mandate 3: `:833` — inside `IERC20Permit(feeToken)
        // .permit(...)` itself, which is a THIRD contract's code and so is
        // reported as `PermitWouldRevert`, not as a `Check`.
        //
        // EIP-2612 makes the deadline clause part of the standard, not a
        // token's private policy: `permit` MUST revert when
        // `block.timestamp > deadline` (EIP-2612 "the current blocktime is
        // less than or equal to deadline"; OpenZeppelin's `ERC20Permit`
        // implements it as `require(block.timestamp <= deadline)`). The fee
        // token reached this branch only by carrying `CAP_EIP2612` in the
        // registry, which IS the registry's on-chain attestation that it
        // implements ERC-2612 — so this is a contract-derived check, not a
        // heuristic about what tokens usually do.
        //
        // `state.chain_now` is the timestamp of the PINNED block (part 1 of
        // this mandate), so this comparison is bound to the same chain state
        // as every nonce above it. With a floating `latest` clock a permit
        // expiring inside the read window would be judged against a block the
        // rest of this report never saw.
        //
        // This is the half of `UNVERIFIED_CHECKS` entry 10 that Task 8
        // closes. The other half — whether `v/r/s` signs the token's CURRENT
        // nonce under its own `DOMAIN_SEPARATOR` — is still open, and entry
        // 10 still says so.
        if state.chain_now > p.deadline {
            return Err(PreflightError::PermitWouldRevert {
                site: "StreamGCommon.sol:208 (collectEip2612) → \
                       IERC20Permit(feeToken).permit \
                       (EIP-2612 require(block.timestamp <= deadline))",
                detail: format!(
                    "block.timestamp {} > eip2612.deadline {} at pinned block {}",
                    state.chain_now, p.deadline, state.block
                ),
            });
        }
    }

    Ok(PreflightReport {
        disposition: if direct {
            Disposition::ClientMustSubmitDirectly
        } else {
            Disposition::RelaySponsored
        },
        unverified: UNVERIFIED_CHECKS,
        block: state.block,
        chain_now: state.chain_now,
    })
}

/// `_validateAndConsumeQuote` (`:654-691`) expanded through
/// `_validateAndConsumeQuoteGeneric` (`:693-739`), in the contract's order.
fn preflight_quote(
    call: &SponsoredEnrollmentCall<'_>,
    state: &LivePreflightState,
    manifest: &DeploymentManifest,
) -> Result<(), PreflightError> {
    let intent = call.intent;
    let quote = call.quote;
    let chain_id = state.live_token.live_chain_id().into_inner();

    // `:705` — gateway storage; checked against the manifest instead.
    ensure(
        manifest.quote_signer != [0u8; 20],
        Check::ZeroQuoteSigner,
        "manifest quoteSigner is the zero address",
    )?;
    // `:706`
    ensure(
        quote.quote_id != [0u8; 32],
        Check::ZeroQuoteId,
        "quote.quoteId must be non-zero",
    )?;
    // `:707` `quoteUsed` — UNVERIFIABLE.
    // `:708`
    let expected_action = ActionType::SponsoredEnrollment.digest();
    ensure(
        quote.action_type == expected_action,
        Check::QuoteActionTypeMismatch,
        "quote.actionType != ACTION_SPONSORED_ENROLLMENT",
    )?;
    // `:709`
    ensure(
        quote.payer == intent.controller,
        Check::QuotePayerMismatch,
        "quote.payer must be intent.controller",
    )?;
    // `:710` — gateway immutable; checked against the manifest instead.
    ensure(
        quote.fee_recipient == manifest.fee_safe,
        Check::QuoteFeeRecipientMismatch,
        "quote.feeRecipient must be feeSafe",
    )?;
    // `:711`
    ensure(
        quote.fee_token == intent.fee_token && quote.fee_token != [0u8; 20],
        Check::QuoteFeeTokenMismatch,
        "quote.feeToken must equal intent.feeToken and be non-zero",
    )?;
    // The state's reads were pinned to a fee token; if the intent names a
    // different one, none of the live values below describe it.
    if quote.fee_token != state.queried_fee_token {
        return Err(PreflightError::StateMisbound {
            what: "feeToken",
            read_for: hex::encode(state.queried_fee_token),
            intent: hex::encode(quote.fee_token),
        });
    }
    // `:712`
    ensure(
        quote.fee_amount != 0,
        Check::ZeroQuoteFeeAmount,
        "quote.feeAmount must be non-zero",
    )?;
    // `:713`
    ensure(
        quote.fee_amount <= intent.max_fee,
        Check::FeeExceedsMax,
        format!(
            "quote.feeAmount {} > intent.maxFee {}",
            quote.fee_amount, intent.max_fee
        ),
    )?;
    // `:714`
    ensure(
        quote.valid_after <= state.chain_now && state.chain_now < quote.valid_until,
        Check::QuoteWindow,
        format!(
            "block.timestamp {} outside [{}, {})",
            state.chain_now, quote.valid_after, quote.valid_until
        ),
    )?;
    // `:716-719` — `activeManifestHash()` read live at the pinned block.
    // The snapshot carries the gateway's own view of the same value
    // (`GoatRelayGateway.sol:284`); require all four to agree.
    let live_manifest = state.active_manifest_hash;
    ensure(
        live_manifest == state.snapshot.deployment_manifest_hash(),
        Check::ManifestHashMismatch,
        "activeManifestHash() and the snapshot's deploymentManifestHash disagree",
    )?;
    ensure(
        intent.deployment_manifest_hash == live_manifest
            && quote.deployment_manifest_hash == live_manifest,
        Check::ManifestHashMismatch,
        format!(
            "live activeManifestHash 0x{}, intent 0x{}, quote 0x{}",
            hex::encode(live_manifest),
            hex::encode(intent.deployment_manifest_hash),
            hex::encode(quote.deployment_manifest_hash)
        ),
    )?;
    // `:720-722` — the gateway's own `feeScheduleHash` storage, which the
    // snapshot exposes directly (`GoatRelayGateway.sol:285`). This is a
    // genuine live read, not a manifest comparison.
    let live_fee_schedule = state.snapshot.fee_schedule_hash();
    ensure(
        live_fee_schedule != [0u8; 32] && quote.fee_schedule_hash == live_fee_schedule,
        Check::FeeScheduleHashMismatch,
        format!(
            "gateway feeScheduleHash 0x{}, quote 0x{}",
            hex::encode(live_fee_schedule),
            hex::encode(quote.fee_schedule_hash)
        ),
    )?;
    // `:725` — the hazard-3 hard gate, over a `LiveTokenReading`.
    token_manifest::assert_token_authorized(&state.live_token, Capability::EIP2612)?;
    // `:726-729`
    let live_cfg = state.live_token.fee_token_config_hash();
    ensure(
        live_cfg != [0u8; 32]
            && intent.fee_token_config_hash == live_cfg
            && quote.fee_token_config_hash == live_cfg,
        Check::FeeTokenConfigHashMismatch,
        format!(
            "live getTokenConfigHash 0x{}, intent 0x{}, quote 0x{}",
            hex::encode(live_cfg),
            hex::encode(intent.fee_token_config_hash),
            hex::encode(quote.fee_token_config_hash)
        ),
    )?;
    // `:731` — `coreHash` is rebuilt from the INTENT, exactly as
    // `_validateAndConsumeQuote` (`:659-678`) does.
    let core = SponsorEnrollmentCore {
        intent_id: intent.intent_id,
        deployment_manifest_hash: intent.deployment_manifest_hash,
        fee_token_config_hash: intent.fee_token_config_hash,
        root: intent.root,
        controller: intent.controller,
        controller_epoch: intent.controller_epoch,
        secondary: intent.secondary,
        enroll_digest: intent.enroll_digest,
        link_digest: intent.link_digest,
        root_authorization_digest: intent.root_authorization_digest,
        fee_token: intent.fee_token,
        fee_authorization_mode: intent.fee_authorization_mode,
        max_fee: intent.max_fee,
        nonce: intent.nonce,
        deadline: intent.deadline,
    };
    let core_hash = sponsor_enrollment_core_hash(&core);
    ensure(
        quote.action_core_hash == core_hash,
        Check::QuoteActionCoreHashMismatch,
        format!(
            "quote.actionCoreHash 0x{} != _validateAndConsumeQuote's coreHash 0x{}",
            hex::encode(quote.action_core_hash),
            hex::encode(core_hash)
        ),
    )?;
    // `:733-735` — recovered against the MANIFEST's quoteSigner; see
    // UNVERIFIED_CHECKS.
    let quote_digest = fee_quote_digest(quote, chain_id, manifest.goat_relay_gateway);
    if let Err(e) = recovers_to(
        quote_digest,
        call.quote_signature_hex,
        manifest.quote_signer,
    ) {
        return Err(revert(Check::BadQuoteSignature, e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{
        FeeTokenConfigView, MockChain, SNAP_CONFIG_HASHES, SNAP_FEE_TOKEN_PERMIT_NONCE,
        SNAP_LINK_NONCE, SNAP_V1_ENROLL_NONCE,
    };
    use crate::stream_g::token_manifest::{fee_token_config_hash, TokenCapability, CAP_EIP2612};
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use std::str::FromStr;

    // Anvil's deterministic keys #1/#2/#3 — fixed so every digest in this
    // module is reproducible, and distinct so a check that compares the
    // wrong party fails loudly.
    const SECONDARY_KEY: &str =
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    const CONTROLLER_KEY: &str =
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
    const QUOTE_SIGNER_KEY: &str =
        "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";

    const REGISTRY: [u8; 20] = [0x77; 20];
    const FEE_TOKEN: [u8; 20] = [0x11; 20];
    const GATEWAY: [u8; 20] = [0x10; 20];
    const SPONSORSHIP: [u8; 20] = [0x12; 20];
    const ENROLL_REGISTRY: [u8; 20] = [0x13; 20];
    const FEE_SAFE: [u8; 20] = [0x14; 20];
    const ROOT: [u8; 20] = [0x21; 20];

    const BLOCK: u64 = 4_242;
    const CHAIN_NOW: u64 = 1_700_000_000;
    const CHAIN_ID: u64 = 31337;
    const MANIFEST_HASH: [u8; 32] = [0x31; 32];
    const FEE_SCHEDULE_HASH: [u8; 32] = [0x32; 32];
    const LIVE_ACTION_NONCE: u128 = 9;
    const LIVE_CONTROLLER_EPOCH: u128 = 5;
    const LIVE_V1_NONCE: u128 = 3;
    const LIVE_LINK_NONCE: u128 = 4;

    fn signer(key: &str) -> PrivateKeySigner {
        PrivateKeySigner::from_str(key).unwrap()
    }

    fn addr(key: &str) -> [u8; 20] {
        signer(key).address().into_array()
    }

    fn sign(key: &str, digest: [u8; 32]) -> String {
        let s = signer(key)
            .sign_hash_sync(&B256::from(digest))
            .expect("sign");
        format!("0x{}", hex::encode(s.as_bytes()))
    }

    fn token_code() -> Vec<u8> {
        b"fee token runtime bytecode".to_vec()
    }

    fn token_cfg() -> TokenCapability {
        TokenCapability {
            chain_id: CHAIN_ID,
            token_address: FEE_TOKEN,
            runtime_code_hash: keccak256(&token_code()),
            proxy_identity_hash: [0u8; 32],
            capability_mask: CAP_EIP2612,
            decimals: 6,
            domain_name_hash: [0x41; 32],
            domain_version_hash: [0x42; 32],
            built_in_mode_id: [0x43; 32],
            config_version: 1,
            active: true,
        }
    }

    fn cfg_view(cfg: &TokenCapability) -> FeeTokenConfigView {
        FeeTokenConfigView {
            chain_id: cfg.chain_id,
            token: cfg.token_address,
            runtime_code_hash: cfg.runtime_code_hash,
            proxy_identity_hash: cfg.proxy_identity_hash,
            capability_mask: cfg.capability_mask,
            decimals: cfg.decimals,
            domain_name_hash: cfg.domain_name_hash,
            domain_version_hash: cfg.domain_version_hash,
            built_in_mode_id: cfg.built_in_mode_id,
            config_version: cfg.config_version,
            active: cfg.active,
        }
    }

    fn manifest() -> DeploymentManifest {
        DeploymentManifest {
            schema_version: 1,
            chain_id: CHAIN_ID,
            phase: "G1".into(),
            enrollment_registry: ENROLL_REGISTRY,
            goat_coin: [0x15; 20],
            fee_token: FEE_TOKEN,
            fee_token_registry: REGISTRY,
            wallet_sponsorship_registry: SPONSORSHIP,
            sponsored_buy_desk: [0x16; 20],
            goat_relay_gateway: GATEWAY,
            policy_safe: [0x17; 20],
            fee_safe: FEE_SAFE,
            recovery_safe: [0x18; 20],
            desk_owner: [0x19; 20],
            quote_signer: addr(QUOTE_SIGNER_KEY),
            deployment_manifest_hash: MANIFEST_HASH,
            fee_schedule_hash: FEE_SCHEDULE_HASH,
        }
    }

    fn snapshot(cfg_hash: [u8; 32]) -> NonceSnapshotView {
        NonceSnapshotView {
            block_number: BLOCK,
            action_nonce: LIVE_ACTION_NONCE,
            v1_enroll_nonce: LIVE_V1_NONCE,
            link_nonce: LIVE_LINK_NONCE,
            root_registration_nonce: 1,
            rotation_nonce: 0,
            controller_epoch: LIVE_CONTROLLER_EPOCH,
            controller: addr(CONTROLLER_KEY),
            goat_permit_nonce: 0,
            fee_token_permit_nonce: LIVE_PERMIT_NONCE as u128,
            present_mask: SNAP_ACTION_NONCE
                | SNAP_V1_ENROLL_NONCE
                | SNAP_LINK_NONCE
                | SNAP_CONTROLLER
                | SNAP_FEE_TOKEN_PERMIT_NONCE
                | SNAP_CONFIG_HASHES,
            deployment_manifest_hash: MANIFEST_HASH,
            fee_token_config_hash: cfg_hash,
            fee_schedule_hash: FEE_SCHEDULE_HASH,
        }
    }

    /// The gateway snapshot's `feeTokenPermitNonce`, which the fee token's
    /// own `nonces(controller)` must agree with at the pinned block.
    const LIVE_PERMIT_NONCE: u64 = 2;

    /// A `MockChain` with every Stream G read armed and mutually agreeing.
    fn wired_chain() -> MockChain {
        let cfg = token_cfg();
        let cfg_hash = fee_token_config_hash(&cfg);
        let m = MockChain::new();
        // `set_now` arms the FLOATING `block_timestamp()`, which the state
        // read deliberately no longer consults (Task 8 Mandate 3 part 1);
        // `set_block_timestamp_at` arms the pinned one it does. They are the
        // same value here so the happy path is unremarkable — the tests that
        // care set them apart on purpose.
        m.set_now(CHAIN_NOW);
        m.set_block_timestamp_at(BLOCK, CHAIN_NOW);
        m.set_erc2612_nonces(FEE_TOKEN, addr(CONTROLLER_KEY), LIVE_PERMIT_NONCE);
        m.set_chain_id(CHAIN_ID);
        m.set_pinned_block_number(BLOCK);
        m.set_fee_token_code(FEE_TOKEN, &token_code());
        m.set_fee_token_config(REGISTRY, FEE_TOKEN, cfg_view(&cfg));
        m.set_fee_token_config_hash(REGISTRY, FEE_TOKEN, cfg_hash);
        m.set_active_manifest_hash(REGISTRY, MANIFEST_HASH);
        m.set_nonce_snapshot(
            GATEWAY,
            ROOT,
            addr(SECONDARY_KEY),
            FEE_TOKEN,
            snapshot(cfg_hash),
        );
        m
    }

    fn state(chain: &MockChain) -> LivePreflightState {
        read_live_preflight_state(chain, &manifest(), ROOT, addr(SECONDARY_KEY))
            .expect("wired chain must yield a state")
    }

    /// Everything the ten-argument call needs, owned so tests can mutate one
    /// field and re-derive only what genuinely depends on it.
    struct Fixture {
        intent: SponsorEnrollment,
        quote: FeeQuote,
        v1: V1Enrollment,
        link: LinkSecondary,
        root_auth: RootAuthorization,
        sponsor_sig: String,
        quote_sig: String,
        link_sig: String,
        root_auth_sig: String,
        fee_authorization_mode: u8,
        eip2612: Eip2612Authorization,
    }

    impl Fixture {
        fn call(&self) -> SponsoredEnrollmentCall<'_> {
            SponsoredEnrollmentCall {
                intent: &self.intent,
                quote: &self.quote,
                v1_enrollment: &self.v1,
                link: &self.link,
                root_authorization: &self.root_auth,
                fee_authorization_mode: self.fee_authorization_mode,
                fee_eip2612_authorization: &self.eip2612,
                sponsor_signature_hex: &self.sponsor_sig,
                quote_signature_hex: &self.quote_sig,
                link_signature_hex: &self.link_sig,
                root_authorization_signature_hex: &self.root_auth_sig,
            }
        }

        /// Re-sign `SponsorEnrollment` after mutating the intent, so a test
        /// that targets some *other* precondition does not accidentally
        /// trip check 20 instead.
        fn resign_sponsor(&mut self) {
            self.sponsor_sig = sign(
                CONTROLLER_KEY,
                sponsor_enrollment_digest(&self.intent, CHAIN_ID, GATEWAY),
            );
        }

        /// Re-derive `quote.actionCoreHash`, `intent.feeQuoteHash`, the
        /// quote signature and the sponsor signature — the dependency chain
        /// intent -> coreHash -> quote -> feeQuoteHash -> intent.
        fn rebind_quote(&mut self) {
            let core = SponsorEnrollmentCore {
                intent_id: self.intent.intent_id,
                deployment_manifest_hash: self.intent.deployment_manifest_hash,
                fee_token_config_hash: self.intent.fee_token_config_hash,
                root: self.intent.root,
                controller: self.intent.controller,
                controller_epoch: self.intent.controller_epoch,
                secondary: self.intent.secondary,
                enroll_digest: self.intent.enroll_digest,
                link_digest: self.intent.link_digest,
                root_authorization_digest: self.intent.root_authorization_digest,
                fee_token: self.intent.fee_token,
                fee_authorization_mode: self.intent.fee_authorization_mode,
                max_fee: self.intent.max_fee,
                nonce: self.intent.nonce,
                deadline: self.intent.deadline,
            };
            self.quote.action_core_hash = sponsor_enrollment_core_hash(&core);
            let qd = fee_quote_digest(&self.quote, CHAIN_ID, GATEWAY);
            self.quote_sig = sign(QUOTE_SIGNER_KEY, qd);
            self.intent.fee_quote_hash = qd;
            self.resign_sponsor();
        }
    }

    /// The happy path: an intent/quote pair that satisfies every one of the
    /// preconditions preflight can evaluate.
    fn fixture() -> Fixture {
        let secondary = addr(SECONDARY_KEY);
        let controller = addr(CONTROLLER_KEY);
        let cfg_hash = fee_token_config_hash(&token_cfg());
        let deadline = CHAIN_NOW + 600;

        let v1 = V1Enrollment {
            wallet: secondary,
            nonce: LIVE_V1_NONCE as u64,
            deadline,
            signature_hex: String::new(),
        };
        let enroll_digest =
            sig_verify::enroll_digest(v1.wallet, v1.nonce, v1.deadline, CHAIN_ID, ENROLL_REGISTRY);

        let link = LinkSecondary {
            root: ROOT,
            secondary,
            nonce: LIVE_LINK_NONCE as u64,
            deadline,
        };
        let link_digest = link_secondary_digest(&link, CHAIN_ID, SPONSORSHIP);

        let intent = SponsorEnrollment {
            intent_id: [0x51; 32],
            deployment_manifest_hash: MANIFEST_HASH,
            fee_token_config_hash: cfg_hash,
            root: ROOT,
            controller,
            controller_epoch: LIVE_CONTROLLER_EPOCH as u64,
            secondary,
            enroll_digest,
            link_digest,
            root_authorization_digest: [0u8; 32],
            fee_token: FEE_TOKEN,
            fee_authorization_mode: AUTHORIZATION_MODE_EIP2612,
            fee_authorization_digest: [0x52; 32],
            max_fee: 1_000_000,
            fee_quote_hash: [0u8; 32], // filled by rebind_quote
            nonce: LIVE_ACTION_NONCE as u64,
            deadline,
        };

        let quote = FeeQuote {
            quote_id: [0x53; 32],
            action_type: ActionType::SponsoredEnrollment.digest(),
            action_core_hash: [0u8; 32], // filled by rebind_quote
            deployment_manifest_hash: MANIFEST_HASH,
            fee_token_config_hash: cfg_hash,
            fee_schedule_hash: FEE_SCHEDULE_HASH,
            payer: controller,
            fee_token: FEE_TOKEN,
            fee_amount: 500_000,
            fee_recipient: FEE_SAFE,
            valid_after: CHAIN_NOW - 10,
            valid_until: CHAIN_NOW + 300,
        };

        // A valid EIP-2612 fee authorization for the happy path: owner is
        // the payer (intent.controller), spender is the gateway itself, and
        // value covers the quoted fee — the three conditions
        // `Check::Eip2612FeeFieldsMismatch` verifies. `deadline`/`v`/`r`/`s`
        // are not checked by preflight (see `Eip2612Authorization`'s doc)
        // and are populated only for structural completeness.
        let eip2612 = Eip2612Authorization {
            owner: controller,
            spender: GATEWAY,
            value: 500_000,
            deadline: CHAIN_NOW + 600,
            v: 27,
            r: [0x61; 32],
            s: [0x62; 32],
        };

        let mut f = Fixture {
            intent,
            quote,
            v1,
            link,
            root_auth: RootAuthorization::default(),
            sponsor_sig: String::new(),
            quote_sig: String::new(),
            link_sig: sign(SECONDARY_KEY, link_digest),
            root_auth_sig: String::new(),
            fee_authorization_mode: AUTHORIZATION_MODE_EIP2612,
            eip2612,
        };
        f.v1.signature_hex = sign(SECONDARY_KEY, enroll_digest);
        f.rebind_quote();
        f
    }

    /// Asserts the specific `Check` that failed — never a bare `is_err()`.
    #[track_caller]
    fn assert_rejects(f: &Fixture, st: &LivePreflightState, expected: Check) {
        let err = preflight_sponsored_enrollment(&f.call(), st, &manifest())
            .expect_err("preflight must reject");
        assert_eq!(err.code(), ERR_PREFLIGHT_WOULD_REVERT, "{err}");
        assert_eq!(err.check(), Some(expected), "wrong check fired: {err}");
    }

    // -----------------------------------------------------------------
    // Ground-truth pins.
    // -----------------------------------------------------------------

    /// Independently `cast`-derived, exactly as `quotes.rs`'s FeeQuote pin
    /// was. Detects: any reordering of the seventeen `SponsorEnrollment`
    /// fields, any edit to `SPONSOR_ENROLLMENT_TYPEHASH_STR`, wrong word
    /// packing for `feeAuthorizationMode` (`uint8`) / `deadline` (`uint48`)
    /// / `controllerEpoch`, or a dropped `\x19\x01` prefix.
    ///
    /// Derived with:
    /// `cast keccak "SponsorEnrollment(...)"` ->
    /// `0xaa3769f4…`, then
    /// `cast keccak $(cast abi-encode "f(bytes32,bytes32,bytes32,bytes32,address,address,uint256,address,bytes32,bytes32,bytes32,address,uint8,bytes32,uint256,bytes32,uint256,uint48)" …)`.
    #[test]
    fn sponsor_enrollment_digest_regression_fixed_inputs() {
        assert_eq!(
            hex::encode(sponsor_enrollment_typehash()),
            "aa3769f433b96287c3b0838abbc6b35619375fea0e81929c58cf672804b9e885",
            "SPONSOR_ENROLLMENT_TYPEHASH drift vs StreamGTypes.sol:65-67"
        );

        let i = SponsorEnrollment {
            intent_id: [0x01; 32],
            deployment_manifest_hash: [0x02; 32],
            fee_token_config_hash: [0x03; 32],
            root: [0x04; 20],
            controller: [0x05; 20],
            controller_epoch: 7,
            secondary: [0x06; 20],
            enroll_digest: [0x08; 32],
            link_digest: [0x09; 32],
            root_authorization_digest: [0u8; 32],
            fee_token: [0x0a; 20],
            fee_authorization_mode: 1,
            fee_authorization_digest: [0x0b; 32],
            max_fee: 1_000_000,
            fee_quote_hash: [0x0c; 32],
            nonce: 3,
            deadline: 2_000_000_100,
        };
        assert_eq!(
            hex::encode(sponsor_enrollment_struct_hash(&i)),
            "abe0223d45eaf26007f8617d87730e7bc3888b68ef91fbe90b8c4cf4e3390c45",
            "SponsorEnrollment struct hash drift: typehash, FIELD ORDER or word packing changed"
        );
        assert_eq!(
            hex::encode(sponsor_enrollment_digest(&i, 31337, [0x10; 20])),
            "fb47f0876c6437931605bf198175a8c81ea5216dbe7e37bdf112d54d0bda8403",
            "SponsorEnrollment digest drift: domain, typehash, field order or packing changed"
        );
    }

    /// `_isDirectEthEnrollment` has SIX conditions
    /// (`StreamGEnroll._isDirectEthEnrollment`), not the three the task brief
    /// lists.
    /// Zeroing only the brief's three must NOT take the direct branch.
    ///
    /// Mutation this detects: deleting any of the `fee_quote_hash`,
    /// `max_fee` or `fee_token_config_hash` clauses from
    /// [`is_direct_eth_enrollment`].
    #[test]
    fn direct_eth_predicate_requires_all_six_conditions() {
        let mut i = fixture().intent;
        i.fee_token = [0u8; 20];
        i.fee_authorization_mode = AUTHORIZATION_MODE_NONE;
        i.fee_authorization_digest = [0u8; 32];
        // The brief's three hold; the contract's other three do not.
        assert!(i.fee_quote_hash != [0u8; 32] && i.max_fee != 0);
        assert!(
            !is_direct_eth_enrollment(&i),
            "three-of-six must not be treated as direct-ETH"
        );

        i.fee_quote_hash = [0u8; 32];
        assert!(!is_direct_eth_enrollment(&i), "four-of-six");
        i.max_fee = 0;
        assert!(!is_direct_eth_enrollment(&i), "five-of-six");
        i.fee_token_config_hash = [0u8; 32];
        assert!(is_direct_eth_enrollment(&i), "all six");
    }

    // -----------------------------------------------------------------
    // Live sourcing.
    // -----------------------------------------------------------------

    #[test]
    fn happy_path_is_relayable() {
        let chain = wired_chain();
        let st = state(&chain);
        let report = preflight_sponsored_enrollment(&fixture().call(), &st, &manifest()).unwrap();
        assert_eq!(report.disposition, Disposition::RelaySponsored);
        assert_eq!(report.block, BLOCK);
        assert_eq!(report.chain_now, CHAIN_NOW);
        assert!(
            !report.unverified.is_empty(),
            "the report must always disclose what it could not check"
        );
    }

    /// R3: enrollment nonces come from ONE snapshot call, never two
    /// independent reads.
    ///
    /// Mutation this detects: adding a second
    /// `secondary_enrollment_nonce_snapshot` call to
    /// `read_live_preflight_state` (e.g. calling
    /// `LiveEnrollmentNonces::read_live` *and* re-reading the snapshot for
    /// the controller/epoch/actionNonce words).
    #[test]
    fn state_read_issues_exactly_one_nonce_snapshot_call() {
        let chain = wired_chain();
        let _ = state(&chain);
        assert_eq!(chain.secondary_enrollment_nonce_snapshot_call_count(), 1);
        assert_eq!(chain.chain_id_call_count(), 1);
        assert_eq!(chain.active_manifest_hash_call_count(), 1);
    }

    /// Every state read is pinned to the block `eth_blockNumber` returned
    /// (R4) — not `"latest"` five times.
    #[test]
    fn state_read_pins_every_read_to_one_block() {
        let chain = wired_chain();
        let st = state(&chain);
        assert_eq!(st.block(), BLOCK);
        let mut pinned_reads = 0usize;
        for op in chain.ops() {
            let block = match op {
                crate::chain::MockOp::FeeTokenCodeHash { block, .. }
                | crate::chain::MockOp::FeeTokenConfig { block, .. }
                | crate::chain::MockOp::FeeTokenConfigHash { block, .. }
                | crate::chain::MockOp::ActiveManifestHash { block, .. }
                | crate::chain::MockOp::SecondaryEnrollmentNonceSnapshot { block, .. }
                // Task 8 Mandate 3's new read is pinned by the same rule.
                | crate::chain::MockOp::Erc2612Nonces { block, .. } => block,
                _ => continue,
            };
            pinned_reads += 1;
            assert_eq!(block, BLOCK, "every pinned read must use one block");
        }
        // Non-zero arm: the loop above would pass vacuously on a state read
        // that issued no pinned calls at all.
        assert!(
            pinned_reads >= 6,
            "expected every pinned read to be recorded, saw {pinned_reads}"
        );
        assert!(
            chain
                .ops()
                .iter()
                .any(|op| matches!(op, crate::chain::MockOp::Erc2612Nonces { .. })),
            "the ERC-2612 nonces read must actually be issued by the state read"
        );
    }

    /// The endpoint's `eth_chainId` is a real input, not decoration: change
    /// only the mock's answer and the state read fails closed. Manifest and
    /// registry config are untouched.
    ///
    /// Mutation this detects: reverting `read_live_token_state` to source
    /// `live_chain_id` from `getTokenConfig(...).chainId` — with that
    /// change `live_chain_id` would be 31337 again and this test's
    /// `expect_err` panics.
    #[test]
    fn state_read_rejects_an_endpoint_on_the_wrong_chain() {
        let chain = wired_chain();
        chain.set_chain_id(8453); // Base mainnet; manifest says 31337
        let err = read_live_preflight_state(&chain, &manifest(), ROOT, addr(SECONDARY_KEY))
            .expect_err("wrong-chain endpoint must fail closed");
        // The token gate's chain-id check is reached first only if the gate
        // runs; here the endpoint/manifest disagreement is caught directly.
        assert_eq!(err.code(), ERR_PREFLIGHT_ENDPOINT_CHAIN_MISMATCH, "{err}");
    }

    /// R3's anti-TOCTOU binding: the registry's `getTokenConfigHash` and the
    /// gateway snapshot's own view of it must agree.
    #[test]
    fn state_read_rejects_config_hash_toctou_split() {
        let chain = wired_chain();
        chain.set_nonce_snapshot(
            GATEWAY,
            ROOT,
            addr(SECONDARY_KEY),
            FEE_TOKEN,
            snapshot([0xEE; 32]),
        );
        let err = read_live_preflight_state(&chain, &manifest(), ROOT, addr(SECONDARY_KEY))
            .expect_err("split config hash must fail closed");
        assert_eq!(err.code(), ERR_PREFLIGHT_SNAPSHOT_TOCTOU, "{err}");
    }

    /// A cleared `SNAP_CONTROLLER` bit means the `controller` word is a
    /// meaningless zero. Reading it anyway would reject every call with a
    /// bogus "controller unset"; failing the *read* closed is correct.
    #[test]
    fn state_read_rejects_snapshot_without_the_controller_bit() {
        let chain = wired_chain();
        let cfg_hash = fee_token_config_hash(&token_cfg());
        let mut snap = snapshot(cfg_hash);
        snap.present_mask &= !SNAP_CONTROLLER;
        chain.set_nonce_snapshot(GATEWAY, ROOT, addr(SECONDARY_KEY), FEE_TOKEN, snap);
        let err = read_live_preflight_state(&chain, &manifest(), ROOT, addr(SECONDARY_KEY))
            .expect_err("cleared SNAP_CONTROLLER must fail closed");
        assert_eq!(err.code(), ERR_PREFLIGHT_CHAIN_READ, "{err}");
        assert!(err.to_string().contains("controller"), "{err}");
    }

    /// A zero chain clock is 1970, which silently passes every deadline
    /// comparison in this module. Fail the READ closed instead.
    ///
    /// Task 8 Mandate 3 moved the clock source from `block_timestamp()` to
    /// `block_timestamp_at(block)`, whose trait default is `Err` rather than
    /// `Ok(0)`; the guard now defends against a node that genuinely answers
    /// 0 for the pinned block.
    ///
    /// Mutation this detects: deleting the `if chain_now == 0` guard from
    /// [`read_live_preflight_state`].
    #[test]
    fn state_read_fails_closed_on_unknown_chain_time() {
        let chain = wired_chain();
        chain.set_block_timestamp_at(BLOCK, 0);
        let err = read_live_preflight_state(&chain, &manifest(), ROOT, addr(SECONDARY_KEY))
            .expect_err("chain time 0 must fail closed");
        assert_eq!(err.code(), ERR_PREFLIGHT_CHAIN_READ, "{err}");

        // Non-zero arm: the same read with a real clock succeeds, so the
        // assertion above is discriminating rather than a state read that
        // happens to fail for some unrelated reason.
        chain.set_block_timestamp_at(BLOCK, CHAIN_NOW);
        let st = read_live_preflight_state(&chain, &manifest(), ROOT, addr(SECONDARY_KEY))
            .expect("a non-zero pinned clock must be accepted");
        assert_eq!(st.chain_now(), CHAIN_NOW);
    }

    /// Task 8 Mandate 3, part 1. The state read must take its clock from the
    /// **pinned** block, never from floating `latest`.
    ///
    /// The two sources are armed to DIFFERENT values here: `set_now` is the
    /// floating `block_timestamp()` and `set_block_timestamp_at(BLOCK, ..)`
    /// is the pinned one. Only one of them can be the answer.
    ///
    /// Mutation this detects: reverting `read_live_preflight_state` to
    /// `chain.block_timestamp()` — the state would then report
    /// `FLOATING_NOW` and this test fails on the first assertion.
    #[test]
    fn state_read_takes_chain_time_from_the_pinned_block() {
        const FLOATING_NOW: u64 = CHAIN_NOW + 9_999;
        let chain = wired_chain();
        chain.set_now(FLOATING_NOW);
        chain.set_block_timestamp_at(BLOCK, CHAIN_NOW);

        let st = read_live_preflight_state(&chain, &manifest(), ROOT, addr(SECONDARY_KEY))
            .expect("wired chain must yield a state");
        assert_eq!(
            st.chain_now(),
            CHAIN_NOW,
            "chain_now must be the PINNED block's timestamp"
        );
        assert_ne!(
            st.chain_now(),
            FLOATING_NOW,
            "chain_now must not come from the floating latest block"
        );
        assert_eq!(st.block(), BLOCK);

        // And the pin is by block NUMBER, not "whatever single timestamp the
        // mock holds": on a chain armed for only a NEIGHBOURING block the
        // pinned one is unanswerable, and the read must fail rather than fall
        // back to any other block's clock.
        let fresh = MockChain::new();
        fresh.set_now(CHAIN_NOW);
        fresh.set_chain_id(CHAIN_ID);
        fresh.set_pinned_block_number(BLOCK);
        let cfg = token_cfg();
        let cfg_hash = fee_token_config_hash(&cfg);
        fresh.set_fee_token_code(FEE_TOKEN, &token_code());
        fresh.set_fee_token_config(REGISTRY, FEE_TOKEN, cfg_view(&cfg));
        fresh.set_fee_token_config_hash(REGISTRY, FEE_TOKEN, cfg_hash);
        fresh.set_active_manifest_hash(REGISTRY, MANIFEST_HASH);
        fresh.set_nonce_snapshot(
            GATEWAY,
            ROOT,
            addr(SECONDARY_KEY),
            FEE_TOKEN,
            snapshot(cfg_hash),
        );
        fresh.set_erc2612_nonces(FEE_TOKEN, addr(CONTROLLER_KEY), LIVE_PERMIT_NONCE);
        fresh.set_block_timestamp_at(BLOCK + 1, CHAIN_NOW); // wrong block only
        let err = read_live_preflight_state(&fresh, &manifest(), ROOT, addr(SECONDARY_KEY))
            .expect_err("a clock armed only for another block must fail closed");
        assert_eq!(err.code(), ERR_PREFLIGHT_CHAIN_READ, "{err}");
    }

    /// Task 8 Mandate 3, part 2. `ChainClient::erc2612_nonces` shipped in
    /// Task 7 with **zero** consumers in `src/stream_g/`. It now has one: the
    /// state read queries the fee token's own `nonces(owner)` at the pinned
    /// block and requires it to agree with the gateway snapshot's
    /// `feeTokenPermitNonce` word, which `_snapshot` (`:290`) populates from
    /// exactly that call.
    ///
    /// Mutation this detects: deleting the `token_permit_nonce !=
    /// snapshot.fee_token_permit_nonce()` comparison from
    /// [`read_live_preflight_state`] — the disagreeing arm below would then
    /// be accepted.
    #[test]
    fn state_read_binds_the_token_permit_nonce_to_the_gateway_snapshot() {
        // Disagreeing arm: the token says a different nonce than the gateway
        // reported at the very same block.
        let chain = wired_chain();
        chain.set_erc2612_nonces(FEE_TOKEN, addr(CONTROLLER_KEY), LIVE_PERMIT_NONCE + 1);
        let err = read_live_preflight_state(&chain, &manifest(), ROOT, addr(SECONDARY_KEY))
            .expect_err("a split permit nonce must fail closed");
        assert_eq!(err.code(), ERR_PREFLIGHT_PERMIT_NONCE_MISBOUND, "{err}");
        assert!(
            matches!(err, PreflightError::PermitNonceMisbound { token_nonce, snapshot_nonce, .. }
                if token_nonce == u128::from(LIVE_PERMIT_NONCE) + 1
                    && snapshot_nonce == u128::from(LIVE_PERMIT_NONCE)),
            "{err}"
        );

        // Agreeing arm: the same read with the token and the gateway in
        // agreement yields a state carrying that nonce.
        let ok_chain = wired_chain();
        let st = read_live_preflight_state(&ok_chain, &manifest(), ROOT, addr(SECONDARY_KEY))
            .expect("agreeing permit nonces must be accepted");
        assert_eq!(st.fee_token_permit_nonce(), u128::from(LIVE_PERMIT_NONCE));

        // Unreadable arm: the read is REQUIRED, not best-effort. A token that
        // cannot answer `nonces(owner)` fails the state read closed rather
        // than defaulting the counter to 0.
        let unarmed = MockChain::new();
        unarmed.set_now(CHAIN_NOW);
        unarmed.set_block_timestamp_at(BLOCK, CHAIN_NOW);
        unarmed.set_chain_id(CHAIN_ID);
        unarmed.set_pinned_block_number(BLOCK);
        let cfg = token_cfg();
        let cfg_hash = fee_token_config_hash(&cfg);
        unarmed.set_fee_token_code(FEE_TOKEN, &token_code());
        unarmed.set_fee_token_config(REGISTRY, FEE_TOKEN, cfg_view(&cfg));
        unarmed.set_fee_token_config_hash(REGISTRY, FEE_TOKEN, cfg_hash);
        unarmed.set_active_manifest_hash(REGISTRY, MANIFEST_HASH);
        unarmed.set_nonce_snapshot(
            GATEWAY,
            ROOT,
            addr(SECONDARY_KEY),
            FEE_TOKEN,
            snapshot(cfg_hash),
        );
        let err = read_live_preflight_state(&unarmed, &manifest(), ROOT, addr(SECONDARY_KEY))
            .expect_err("an unreadable nonces(owner) must fail closed");
        assert_eq!(err.code(), ERR_PREFLIGHT_CHAIN_READ, "{err}");
        assert!(err.to_string().contains("nonces"), "{err}");
    }

    /// Task 8 Mandate 3, part 2 — the half of `UNVERIFIED_CHECKS` entry 10
    /// that Task 8 actually closes: the ERC-2612 permit **deadline**, judged
    /// against the pinned block's chain clock.
    ///
    /// EIP-2612 requires `permit` to revert when `block.timestamp > deadline`,
    /// and `CAP_EIP2612` in the fee-token registry is the on-chain attestation
    /// that this token implements EIP-2612 — so this is contract-derived, not
    /// a guess about token behaviour.
    ///
    /// Mutation this detects: deleting the `state.chain_now > p.deadline`
    /// block from [`preflight_sponsored_enrollment`].
    #[test]
    fn rejects_an_eip2612_permit_whose_deadline_has_passed() {
        let chain = wired_chain();
        let st = state(&chain);

        // Control (non-zero arm): the fixture's permit is still live.
        assert!(preflight_sponsored_enrollment(&fixture().call(), &st, &manifest()).is_ok());

        // Exactly expired: EIP-2612 permits `block.timestamp == deadline`.
        let mut boundary = fixture();
        boundary.eip2612.deadline = st.chain_now();
        assert!(
            preflight_sponsored_enrollment(&boundary.call(), &st, &manifest()).is_ok(),
            "deadline == block.timestamp is still valid under EIP-2612"
        );

        // One second past: rejected.
        let mut f = fixture();
        f.eip2612.deadline = st.chain_now() - 1;
        let err = preflight_sponsored_enrollment(&f.call(), &st, &manifest())
            .expect_err("an expired permit deadline must be rejected");
        assert_eq!(err.code(), ERR_PREFLIGHT_PERMIT_WOULD_REVERT, "{err}");
        assert_eq!(
            err.check(),
            None,
            "this revert is the fee token's, not a GoatRelayGateway Check"
        );

        // The direct-ETH branch has no fee to authorize, so an expired permit
        // deadline there must NOT be consulted at all.
        let mut d = fixture();
        d.intent.fee_token = [0u8; 20];
        d.intent.fee_authorization_mode = AUTHORIZATION_MODE_NONE;
        d.intent.fee_authorization_digest = [0u8; 32];
        d.intent.fee_quote_hash = [0u8; 32];
        d.intent.max_fee = 0;
        d.intent.fee_token_config_hash = [0u8; 32];
        d.quote = FeeQuote {
            quote_id: [0u8; 32],
            action_type: [0u8; 32],
            action_core_hash: [0u8; 32],
            deployment_manifest_hash: [0u8; 32],
            fee_token_config_hash: [0u8; 32],
            fee_schedule_hash: [0u8; 32],
            payer: [0u8; 20],
            fee_token: [0u8; 20],
            fee_amount: 0,
            fee_recipient: [0u8; 20],
            valid_after: 0,
            valid_until: 0,
        };
        d.quote_sig = String::new();
        d.fee_authorization_mode = AUTHORIZATION_MODE_NONE;
        d.eip2612.deadline = 1; // long expired
        d.resign_sponsor();
        let report = preflight_sponsored_enrollment(&d.call(), &st, &manifest())
            .expect("direct-ETH branch must not consult the permit deadline");
        assert_eq!(report.disposition, Disposition::ClientMustSubmitDirectly);
    }

    /// The disclosure that must NOT be claimed as closed. Entry 10 is
    /// narrowed by Task 8, not deleted: the permit **signature** is still
    /// unverifiable because EIP-2612's `permit()` carries no nonce argument
    /// and this crate reads no `DOMAIN_SEPARATOR`.
    ///
    /// Mutation this detects: removing the ERC-2612 entry from
    /// `UNVERIFIED_CHECKS` (a false claim of full closure).
    #[test]
    fn the_erc2612_disclosure_is_narrowed_but_still_present() {
        let entry = UNVERIFIED_CHECKS
            .iter()
            .find(|u| u.site.contains("IERC20Permit(feeToken).permit"))
            .expect("the ERC-2612 permit disclosure must not be deleted");
        assert!(
            entry.why.contains("DOMAIN_SEPARATOR"),
            "the residue must still name what makes it unverifiable: {}",
            entry.why
        );
        assert!(
            entry.revert.contains("SIGNATURE"),
            "the entry must be narrowed to the signature residue: {}",
            entry.revert
        );
        // The count is unchanged BY TASK 8 — a shrinking entry is not a
        // shrinking list. Wave 2 then added entry 11 (the native-exposure
        // gate's chain skip), which is why this is 11 and not 10; the pin
        // exists so that either direction of movement is a deliberate edit.
        assert_eq!(
            UNVERIFIED_CHECKS.len(),
            11,
            "Task 8 narrows entry 10's text; Wave 2 adds entry 11 (native exposure gate skip)"
        );
    }

    /// Wave 2, **amended by Wave C W4**. The exposure-gate skip must stay
    /// disclosed, and the disclosure must stay bounded in both directions.
    ///
    /// Wave 2 required the entry to name *two* residues: the chain-conditional
    /// skip and the fact that the ceiling had no production source (asserted
    /// by looking for `#[cfg(test)]` in the text). W4 mounted
    /// `POST /v1/stream-g/submit`, which binds the ceiling from
    /// `StreamGConfig::max_native_exposure_wei` and refuses a `0` one with a
    /// 503 — so the second residue is gone and continuing to publish it would
    /// be the mirror-image dishonesty of the one this test was written to
    /// prevent. What replaces it is an assertion in the *other* direction: the
    /// entry must still name the chain the gate does not run on, and must
    /// still refuse to claim unqualified closure.
    ///
    /// Mutations this detects: deleting entry 11 from `UNVERIFIED_CHECKS` (the
    /// `expect` fires); dropping the chain-skip residue; or rewriting the
    /// entry to say hazard 1 is simply closed, with no chain qualifier.
    #[test]
    fn native_exposure_gate_skip_is_disclosed_with_its_remaining_residue() {
        let entry = UNVERIFIED_CHECKS
            .iter()
            .find(|u| u.site.contains("base_fee.rs"))
            .expect("the native-exposure gate's skip must be disclosed");
        assert!(
            entry.why.contains("31337"),
            "the entry must name the chain the gate does not run on: {}",
            entry.why
        );
        assert!(
            entry.why.contains("OPEN on chain 31337"),
            "the entry must still say the residue is OPEN somewhere: {}",
            entry.why
        );
        // Bounded closure only. "CLOSED on the submit path for every chain
        // that carries the predeploy" is allowed and is what the entry says;
        // an unqualified claim is not.
        assert!(
            !entry.why.contains("Hazard 1 is CLOSED."),
            "the entry must not claim hazard 1 is closed without the chain \
             qualifier: {}",
            entry.why
        );
        assert!(
            !entry.why.contains("#[cfg(test)]"),
            "the ceiling now HAS a production source (submit::post_submit), so \
             the entry must no longer publish that residue: {}",
            entry.why
        );
    }

    /// Live state read for a different root says nothing about this intent.
    #[test]
    fn rejects_state_read_for_a_different_root() {
        let chain = wired_chain();
        let other_root = [0x22u8; 20];
        chain.set_nonce_snapshot(
            GATEWAY,
            other_root,
            addr(SECONDARY_KEY),
            FEE_TOKEN,
            snapshot(fee_token_config_hash(&token_cfg())),
        );
        let st = read_live_preflight_state(&chain, &manifest(), other_root, addr(SECONDARY_KEY))
            .unwrap();
        let f = fixture();
        let err = preflight_sponsored_enrollment(&f.call(), &st, &manifest()).unwrap_err();
        assert_eq!(err.code(), ERR_PREFLIGHT_STATE_MISBOUND, "{err}");
    }

    // -----------------------------------------------------------------
    // CHECK 18 — the highest-consequence one.
    // -----------------------------------------------------------------

    /// **Check 18** (`GoatRelayGateway.sol:394`). `intent.feeQuoteHash` is
    /// the quote's FULL EIP-712 digest. The single most likely way to get
    /// this wrong is to bind the intent to the quote by `quoteId`, which
    /// type-checks, reads plausibly, and reverts `InvalidQuote` on every
    /// single transaction.
    ///
    /// Mutation this detects: replacing the `fee_quote_digest(...)`
    /// right-hand side of the `Check::FeeQuoteHashMismatch` comparison with
    /// `quote.quote_id` (or with `fee_quote_struct_hash`, or with the same
    /// digest under a different domain) — the happy-path assertion below
    /// then fails because the fixture binds the real digest.
    #[test]
    fn check_18_rejects_intent_bound_to_quote_id_instead_of_the_full_digest() {
        let chain = wired_chain();
        let st = state(&chain);

        let mut f = fixture();
        // Control: the fixture binds the real digest and is accepted.
        assert_eq!(
            f.intent.fee_quote_hash,
            fee_quote_digest(&f.quote, CHAIN_ID, GATEWAY)
        );
        assert!(preflight_sponsored_enrollment(&f.call(), &st, &manifest()).is_ok());

        // Mutation: bind by quoteId, the plausible-looking wrong thing.
        f.intent.fee_quote_hash = f.quote.quote_id;
        f.resign_sponsor(); // so check 20 is not what fires
        assert_rejects(&f, &st, Check::FeeQuoteHashMismatch);
    }

    /// Check 18 must also catch a digest computed over a *stale* quote —
    /// same quoteId, one field changed after the intent was signed.
    #[test]
    fn check_18_rejects_a_digest_over_a_stale_quote() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        // The fee changed after the intent committed to a digest.
        f.quote.fee_amount = 400_000;
        f.quote_sig = sign(
            QUOTE_SIGNER_KEY,
            fee_quote_digest(&f.quote, CHAIN_ID, GATEWAY),
        );
        assert_rejects(&f, &st, Check::FeeQuoteHashMismatch);
    }

    /// A digest computed under the wrong EIP-712 domain (wrong verifying
    /// contract) must be rejected — the failure mode a hand-rolled digest
    /// helper produces.
    #[test]
    fn check_18_rejects_a_digest_under_the_wrong_domain() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.intent.fee_quote_hash = fee_quote_digest(&f.quote, CHAIN_ID, [0x99; 20]);
        f.resign_sponsor();
        assert_rejects(&f, &st, Check::FeeQuoteHashMismatch);
    }

    // -----------------------------------------------------------------
    // Direct-ETH branch.
    // -----------------------------------------------------------------

    /// The attestor cannot relay `_isDirectEthEnrollment`
    /// (`GoatRelayGateway.sol:379` requires `msg.sender == controller`), so
    /// the answer is a distinct disposition, never a sponsored quote.
    #[test]
    fn direct_eth_intent_tells_the_client_to_submit_directly() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();

        f.intent.fee_token = [0u8; 20];
        f.intent.fee_authorization_mode = AUTHORIZATION_MODE_NONE;
        f.intent.fee_authorization_digest = [0u8; 32];
        f.intent.fee_quote_hash = [0u8; 32];
        f.intent.max_fee = 0;
        f.intent.fee_token_config_hash = [0u8; 32];
        f.quote = FeeQuote {
            quote_id: [0u8; 32],
            action_type: [0u8; 32],
            action_core_hash: [0u8; 32],
            deployment_manifest_hash: [0u8; 32],
            fee_token_config_hash: [0u8; 32],
            fee_schedule_hash: [0u8; 32],
            payer: [0u8; 20],
            fee_token: [0u8; 20],
            fee_amount: 0,
            fee_recipient: [0u8; 20],
            valid_after: 0,
            valid_until: 0,
        };
        f.quote_sig = String::new();
        f.fee_authorization_mode = AUTHORIZATION_MODE_NONE;
        f.resign_sponsor();

        let report = preflight_sponsored_enrollment(&f.call(), &st, &manifest()).unwrap();
        assert_eq!(report.disposition, Disposition::ClientMustSubmitDirectly);
    }

    /// On the direct branch a non-empty `quoteSignature` is
    /// `InvalidQuote` (`:380`).
    #[test]
    fn direct_eth_rejects_a_present_quote_signature() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.intent.fee_token = [0u8; 20];
        f.intent.fee_authorization_mode = AUTHORIZATION_MODE_NONE;
        f.intent.fee_authorization_digest = [0u8; 32];
        f.intent.fee_quote_hash = [0u8; 32];
        f.intent.max_fee = 0;
        f.intent.fee_token_config_hash = [0u8; 32];
        f.fee_authorization_mode = AUTHORIZATION_MODE_NONE;
        f.resign_sponsor();
        // quote_sig is still the sponsored-path signature.
        assert_rejects(&f, &st, Check::DirectEthQuoteSignaturePresent);
    }

    /// On the direct branch every one of the twelve `FeeQuote` fields must
    /// be zero (`:381-389`). This test proves the check fires when the
    /// quote is fully populated — it detects deletion of the WHOLE `:381-389`
    /// check, but (verifier §9.2) does not by itself prove any individual
    /// clause is load-bearing, since it mutates all twelve fields at once
    /// via a still-populated fixture quote. Corrected per "claims ≤ code":
    /// `direct_eth_rejects_each_non_zero_quote_field_independently` below
    /// mutates one field at a time and proves each of the twelve clauses is
    /// independently required.
    #[test]
    fn direct_eth_rejects_a_non_zeroed_quote() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.intent.fee_token = [0u8; 20];
        f.intent.fee_authorization_mode = AUTHORIZATION_MODE_NONE;
        f.intent.fee_authorization_digest = [0u8; 32];
        f.intent.fee_quote_hash = [0u8; 32];
        f.intent.max_fee = 0;
        f.intent.fee_token_config_hash = [0u8; 32];
        f.quote_sig = String::new();
        f.fee_authorization_mode = AUTHORIZATION_MODE_NONE;
        f.resign_sponsor();
        // quote is still fully populated.
        assert_rejects(&f, &st, Check::DirectEthQuoteNotZeroed);
    }

    // -----------------------------------------------------------------
    // Per-precondition rejections, in contract order.
    // -----------------------------------------------------------------

    #[test]
    fn check_02_rejects_an_expired_intent_deadline() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.intent.deadline = CHAIN_NOW; // `>=` reverts
        f.rebind_quote();
        assert_rejects(&f, &st, Check::ExpiredDeadline);
    }

    #[test]
    fn check_03_rejects_zero_root_or_secondary() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.intent.secondary = [0u8; 20];
        f.rebind_quote();
        assert_rejects(&f, &st, Check::ZeroRootOrSecondary);
    }

    #[test]
    fn check_04_rejects_link_fields_that_disagree_with_the_intent() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.link.root = [0x23; 20];
        assert_rejects(&f, &st, Check::LinkFieldsMismatch);
    }

    #[test]
    fn check_05_rejects_v1_enrollment_for_another_wallet() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.v1.wallet = [0x24; 20];
        assert_rejects(&f, &st, Check::V1WalletMismatch);
    }

    /// Check 8 (`:351`) — `controllerOf(root) == 0`. Sourced from the
    /// snapshot's `controller` word, which is a live read.
    #[test]
    fn check_08_rejects_a_root_with_no_controller() {
        let chain = wired_chain();
        let cfg_hash = fee_token_config_hash(&token_cfg());
        let mut snap = snapshot(cfg_hash);
        snap.controller = [0u8; 20];
        chain.set_nonce_snapshot(GATEWAY, ROOT, addr(SECONDARY_KEY), FEE_TOKEN, snap);
        // With `controller == 0` the gateway's own `goatOwner` (`:279`) falls
        // back to `root`, so THAT is the address the state read's permit-nonce
        // binding queries. Arming it keeps this test about check 8; without
        // the fallback the read would ask for `nonces(0)` and this test would
        // fail with a nonce misbinding instead of `ControllerUnset`.
        chain.set_erc2612_nonces(FEE_TOKEN, ROOT, LIVE_PERMIT_NONCE);
        let st = state(&chain);
        assert_rejects(&fixture(), &st, Check::ControllerUnset);
    }

    /// Check 9 (`:352`). Mutating only the CHAIN-returned controller must
    /// reject while the intent is unchanged — proving the comparison is
    /// against a live value, not against itself.
    #[test]
    fn check_09_rejects_a_controller_the_chain_disagrees_with() {
        let chain = wired_chain();
        let cfg_hash = fee_token_config_hash(&token_cfg());
        let mut snap = snapshot(cfg_hash);
        snap.controller = [0x25; 20];
        chain.set_nonce_snapshot(GATEWAY, ROOT, addr(SECONDARY_KEY), FEE_TOKEN, snap);
        // The permit-nonce binding follows the snapshot's controller, so the
        // mutated address needs a nonce armed too — otherwise this test would
        // stop at an unarmed-read error and never reach check 9.
        chain.set_erc2612_nonces(FEE_TOKEN, [0x25; 20], LIVE_PERMIT_NONCE);
        let st = state(&chain);
        assert_rejects(&fixture(), &st, Check::ControllerMismatch);
    }

    /// Check 10 (`:353`).
    #[test]
    fn check_10_rejects_a_stale_controller_epoch() {
        let chain = wired_chain();
        let cfg_hash = fee_token_config_hash(&token_cfg());
        let mut snap = snapshot(cfg_hash);
        snap.controller_epoch = LIVE_CONTROLLER_EPOCH + 1;
        chain.set_nonce_snapshot(GATEWAY, ROOT, addr(SECONDARY_KEY), FEE_TOKEN, snap);
        let st = state(&chain);
        assert_rejects(&fixture(), &st, Check::EpochMismatch);
    }

    /// Check 11 (`:355-356`) — the intent's `enrollDigest` must be the one
    /// `_v1EnrollDigest` derives from the V1 payload actually supplied.
    #[test]
    fn check_11_rejects_an_enroll_digest_the_v1_payload_does_not_produce() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.intent.enroll_digest = [0x26; 32];
        f.rebind_quote();
        assert_rejects(&f, &st, Check::EnrollDigestMismatch);
    }

    /// Check 12 (`:357-358`) — signed by somebody other than `secondary`.
    #[test]
    fn check_12_rejects_a_v1_signature_from_the_wrong_signer() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.v1.signature_hex = sign(CONTROLLER_KEY, f.intent.enroll_digest);
        assert_rejects(&f, &st, Check::BadV1Signature);
    }

    /// Check 13 (`:360-361`).
    #[test]
    fn check_13_rejects_a_link_digest_the_link_struct_does_not_produce() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.intent.link_digest = [0x27; 32];
        f.rebind_quote();
        assert_rejects(&f, &st, Check::LinkDigestMismatch);
    }

    /// Check 14 (`:362-363`).
    #[test]
    fn check_14_rejects_a_link_signature_from_the_wrong_signer() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.link_sig = sign(CONTROLLER_KEY, f.intent.link_digest);
        assert_rejects(&f, &st, Check::BadLinkSignature);
    }

    /// Check 15 (`:365`).
    #[test]
    fn check_15_rejects_a_non_zero_root_authorization_digest() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.intent.root_authorization_digest = [0x28; 32];
        f.rebind_quote();
        assert_rejects(&f, &st, Check::NonZeroRootAuthorizationDigest);
    }

    /// Check 16 (`:366-373`) — each of the six fields on its own, plus the
    /// signature-length clause. A single combined assertion would pass even
    /// if five of the seven clauses were deleted.
    #[test]
    fn check_16_rejects_every_non_zero_root_authorization_field() {
        let chain = wired_chain();
        let st = state(&chain);

        type Mutation = Box<dyn Fn(&mut Fixture)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|f: &mut Fixture| f.root_auth.root = [0x29; 20]),
            Box::new(|f: &mut Fixture| f.root_auth.secondary = [0x2a; 20]),
            Box::new(|f: &mut Fixture| f.root_auth.enroll_digest = [0x2b; 32]),
            Box::new(|f: &mut Fixture| f.root_auth.link_digest = [0x2c; 32]),
            Box::new(|f: &mut Fixture| f.root_auth.nonce = 1),
            Box::new(|f: &mut Fixture| f.root_auth.deadline = 1),
            Box::new(|f: &mut Fixture| f.root_auth_sig = format!("0x{}", hex::encode([7u8; 65]))),
        ];
        for (idx, mutate) in mutations.iter().enumerate() {
            let mut f = fixture();
            mutate(&mut f);
            let err = preflight_sponsored_enrollment(&f.call(), &st, &manifest())
                .err()
                .unwrap_or_else(|| panic!("RootAuthorization mutation {idx} must be rejected"));
            assert_eq!(err.code(), ERR_PREFLIGHT_WOULD_REVERT, "{err}");
            assert_eq!(
                err.check(),
                Some(Check::NonZeroRootAuthorization),
                "mutation {idx} fired the wrong check: {err}"
            );
        }

        // Control: with all seven clauses satisfied the same fixture passes,
        // so the rejections above are caused by the mutations alone.
        assert!(preflight_sponsored_enrollment(&fixture().call(), &st, &manifest()).is_ok());
    }

    #[test]
    fn check_17_rejects_a_quote_for_the_wrong_action_type() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.quote.action_type = ActionType::SponsoredSell.digest();
        f.quote_sig = sign(
            QUOTE_SIGNER_KEY,
            fee_quote_digest(&f.quote, CHAIN_ID, GATEWAY),
        );
        f.intent.fee_quote_hash = fee_quote_digest(&f.quote, CHAIN_ID, GATEWAY);
        f.resign_sponsor();
        assert_rejects(&f, &st, Check::QuoteActionTypeMismatch);
    }

    #[test]
    fn check_17_rejects_a_payer_that_is_not_the_controller() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.quote.payer = [0x2d; 20];
        f.rebind_quote();
        assert_rejects(&f, &st, Check::QuotePayerMismatch);
    }

    #[test]
    fn check_17_rejects_a_fee_recipient_that_is_not_the_fee_safe() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.quote.fee_recipient = [0x2e; 20];
        f.rebind_quote();
        assert_rejects(&f, &st, Check::QuoteFeeRecipientMismatch);
    }

    #[test]
    fn check_17_rejects_a_zero_fee_amount() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.quote.fee_amount = 0;
        f.rebind_quote();
        assert_rejects(&f, &st, Check::ZeroQuoteFeeAmount);
    }

    #[test]
    fn check_17_rejects_a_fee_above_the_intents_max() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.quote.fee_amount = f.intent.max_fee + 1;
        f.rebind_quote();
        assert_rejects(&f, &st, Check::FeeExceedsMax);
    }

    /// `:714` — the window is a CHAIN-clock comparison. Mutating only the
    /// mock's `block.timestamp` must flip the verdict, with the quote
    /// untouched.
    #[test]
    fn check_17_rejects_a_quote_outside_its_validity_window() {
        let chain = wired_chain();
        let f = fixture();

        // Control: inside the window.
        assert!(preflight_sponsored_enrollment(&f.call(), &state(&chain), &manifest()).is_ok());

        // Mutation: chain time only — and specifically the PINNED block's
        // clock, which is the only one the state read consults as of Task 8
        // Mandate 3. (Moving `set_now`, the floating `block_timestamp()`,
        // now correctly changes nothing here.)
        chain.set_block_timestamp_at(BLOCK, f.quote.valid_until);
        assert_rejects(&f, &state(&chain), Check::QuoteWindow);
    }

    /// `:716-719` — **the discriminating half**: the value compared against
    /// must have come from the live `activeManifestHash()` read, not from
    /// the intent or the manifest file.
    ///
    /// Only the chain's `activeManifestHash()` answer is mutated; the
    /// snapshot, the intent and the quote all still say `MANIFEST_HASH`.
    ///
    /// Mutation this detects: sourcing `live_manifest` from
    /// `intent.deployment_manifest_hash` (or from
    /// `manifest.deployment_manifest_hash`) — with that change every
    /// comparison becomes `x == x` and this call is wrongly accepted. The
    /// sibling test below does NOT detect that mutation, which is precisely
    /// why this one exists.
    #[test]
    fn check_17_manifest_hash_comes_from_the_live_active_manifest_hash_read() {
        let chain = wired_chain();
        chain.set_active_manifest_hash(REGISTRY, [0x2f; 32]);
        let st = state(&chain);
        assert_rejects(&fixture(), &st, Check::ManifestHashMismatch);
    }

    /// `:716-719` — the manifest hash must equal the LIVE
    /// `activeManifestHash()`, not the file's own claim.
    #[test]
    fn check_17_rejects_a_manifest_hash_the_chain_has_replaced() {
        let chain = wired_chain();
        chain.set_active_manifest_hash(REGISTRY, [0x2f; 32]);
        let cfg_hash = fee_token_config_hash(&token_cfg());
        let mut snap = snapshot(cfg_hash);
        snap.deployment_manifest_hash = [0x2f; 32];
        chain.set_nonce_snapshot(GATEWAY, ROOT, addr(SECONDARY_KEY), FEE_TOKEN, snap);
        let st = state(&chain);
        assert_rejects(&fixture(), &st, Check::ManifestHashMismatch);
    }

    /// `:720-722` — the gateway's own `feeScheduleHash` storage, exposed by
    /// the snapshot (`GoatRelayGateway.sol:285`). Mutating only the chain's
    /// answer must reject, with the manifest untouched.
    #[test]
    fn check_17_rejects_a_fee_schedule_hash_the_gateway_disagrees_with() {
        let chain = wired_chain();
        let cfg_hash = fee_token_config_hash(&token_cfg());
        let mut snap = snapshot(cfg_hash);
        snap.fee_schedule_hash = [0x30; 32];
        chain.set_nonce_snapshot(GATEWAY, ROOT, addr(SECONDARY_KEY), FEE_TOKEN, snap);
        let st = state(&chain);
        assert_rejects(&fixture(), &st, Check::FeeScheduleHashMismatch);
    }

    /// `:725` — the hazard-3 hard gate. Mutating only the deployed
    /// bytecode (config, registry hash and manifest untouched) must reject.
    #[test]
    fn check_17_rejects_a_fee_token_whose_bytecode_was_replaced() {
        let chain = wired_chain();
        chain.set_fee_token_code(FEE_TOKEN, b"replaced runtime bytecode");
        let st = state(&chain);
        let err = preflight_sponsored_enrollment(&fixture().call(), &st, &manifest()).unwrap_err();
        assert_eq!(
            err.code(),
            crate::stream_g::token_manifest::ERR_TOKEN_UNSUPPORTED,
            "{err}"
        );
    }

    /// `:726-729` — the intent must commit to the registry's live config
    /// hash.
    #[test]
    fn check_17_rejects_a_stale_fee_token_config_hash_in_the_intent() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.intent.fee_token_config_hash = [0x33; 32];
        f.rebind_quote();
        assert_rejects(&f, &st, Check::FeeTokenConfigHashMismatch);
    }

    /// `:726-729` — **the discriminating half**. Intent AND quote agree with
    /// each other on a config hash the registry never reported, so a
    /// comparison sourced from either of them is `x == x` and accepts.
    ///
    /// Mutation this detects: sourcing `live_cfg` from
    /// `intent.fee_token_config_hash` or `quote.fee_token_config_hash`
    /// instead of `state.live_token.fee_token_config_hash()`.
    #[test]
    fn check_17_fee_token_config_hash_comes_from_the_registry_read() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.intent.fee_token_config_hash = [0x33; 32];
        f.quote.fee_token_config_hash = [0x33; 32];
        f.rebind_quote();
        assert_rejects(&f, &st, Check::FeeTokenConfigHashMismatch);
    }

    /// `:731` — the quote's `actionCoreHash` must be the one the gateway
    /// recomputes from the intent. This is what stops a quote being reused
    /// against a different intent.
    #[test]
    fn check_17_rejects_a_quote_bound_to_a_different_intent() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.quote.action_core_hash = [0x34; 32];
        let qd = fee_quote_digest(&f.quote, CHAIN_ID, GATEWAY);
        f.quote_sig = sign(QUOTE_SIGNER_KEY, qd);
        f.intent.fee_quote_hash = qd;
        f.resign_sponsor();
        assert_rejects(&f, &st, Check::QuoteActionCoreHashMismatch);
    }

    /// `:733-735` — a quote signed by anybody but the quote signer.
    #[test]
    fn check_17_rejects_a_quote_signed_by_the_wrong_key() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.quote_sig = sign(
            CONTROLLER_KEY,
            fee_quote_digest(&f.quote, CHAIN_ID, GATEWAY),
        );
        assert_rejects(&f, &st, Check::BadQuoteSignature);
    }

    /// Check 19 (`:395-397`).
    #[test]
    fn check_19_rejects_a_fee_authorization_mode_that_is_not_eip2612() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.intent.fee_authorization_mode = 3; // PRIOR_ALLOWANCE
        f.rebind_quote();
        assert_rejects(&f, &st, Check::UnsupportedFeeMode);
    }

    /// Check 20 (`:400-402`) — the sponsor signature is the CONTROLLER's.
    #[test]
    fn check_20_rejects_a_sponsor_signature_from_the_wrong_signer() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.sponsor_sig = sign(
            SECONDARY_KEY,
            sponsor_enrollment_digest(&f.intent, CHAIN_ID, GATEWAY),
        );
        assert_rejects(&f, &st, Check::BadSponsorSignature);
    }

    /// `_markIntentAndNonce` (`:318`).
    #[test]
    fn effects_reject_a_zero_intent_id() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.intent.intent_id = [0u8; 32];
        f.rebind_quote();
        assert_rejects(&f, &st, Check::ZeroIntentId);
    }

    /// `_markIntentAndNonce` (`:320`) — `BadActionNonce`, the real revert
    /// name (there is no `StaleNonce` on chain). Mutating only the
    /// chain-returned `actionNonce` must reject.
    #[test]
    fn effects_reject_an_action_nonce_the_chain_has_moved_past() {
        let chain = wired_chain();
        let cfg_hash = fee_token_config_hash(&token_cfg());
        let mut snap = snapshot(cfg_hash);
        snap.action_nonce = LIVE_ACTION_NONCE + 1;
        chain.set_nonce_snapshot(GATEWAY, ROOT, addr(SECONDARY_KEY), FEE_TOKEN, snap);
        let st = state(&chain);
        assert_rejects(&fixture(), &st, Check::BadActionNonce);
    }

    /// `_enrollV1OrAcceptFrontRun` (`:747-757`): both accepted branches
    /// require `liveNonce ∈ {v1.nonce, v1.nonce + 1}`. `+1` is the
    /// front-run branch and must be ACCEPTED, so this test is discriminating
    /// rather than a blanket "must equal".
    #[test]
    fn effects_accept_the_front_run_nonce_but_reject_anything_further() {
        let cfg_hash = fee_token_config_hash(&token_cfg());

        // liveNonce == v1.nonce + 1 -> front-run branch, accepted.
        let chain = wired_chain();
        let mut snap = snapshot(cfg_hash);
        snap.v1_enroll_nonce = LIVE_V1_NONCE + 1;
        chain.set_nonce_snapshot(GATEWAY, ROOT, addr(SECONDARY_KEY), FEE_TOKEN, snap);
        assert!(
            preflight_sponsored_enrollment(&fixture().call(), &state(&chain), &manifest()).is_ok(),
            "the front-run branch must not be rejected"
        );

        // liveNonce == v1.nonce + 2 -> neither branch, rejected.
        let chain2 = wired_chain();
        let mut snap2 = snapshot(cfg_hash);
        snap2.v1_enroll_nonce = LIVE_V1_NONCE + 2;
        chain2.set_nonce_snapshot(GATEWAY, ROOT, addr(SECONDARY_KEY), FEE_TOKEN, snap2);
        assert_rejects(&fixture(), &state(&chain2), Check::V1EnrollNonceUnusable);
    }

    /// `WalletSponsorshipRegistry.sol:192` — `linkNonces[secondary]`.
    #[test]
    fn effects_reject_a_stale_link_nonce() {
        let chain = wired_chain();
        let cfg_hash = fee_token_config_hash(&token_cfg());
        let mut snap = snapshot(cfg_hash);
        snap.link_nonce = LIVE_LINK_NONCE + 1;
        chain.set_nonce_snapshot(GATEWAY, ROOT, addr(SECONDARY_KEY), FEE_TOKEN, snap);
        let st = state(&chain);
        assert_rejects(&fixture(), &st, Check::LinkNonceMismatch);
    }

    /// `WalletSponsorshipRegistry.sol:191`.
    #[test]
    fn effects_reject_an_expired_link_deadline() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.link.deadline = CHAIN_NOW;
        f.link_sig = sign(
            SECONDARY_KEY,
            link_secondary_digest(&f.link, CHAIN_ID, SPONSORSHIP),
        );
        f.intent.link_digest = link_secondary_digest(&f.link, CHAIN_ID, SPONSORSHIP);
        f.rebind_quote();
        assert_rejects(&f, &st, Check::LinkDeadlineExpired);
    }

    /// `_collectEip2612Fee` (`:766`) — the `TokenAuthorization` envelope's
    /// mode, which is a separate field from `intent.feeAuthorizationMode`.
    #[test]
    fn effects_reject_a_fee_authorization_envelope_that_is_not_eip2612() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.fee_authorization_mode = 2; // EIP3009
        assert_rejects(&f, &st, Check::FeeAuthorizationModeNotEip2612);
    }

    // =========================================================================
    // -- Task 6b independent-verifier follow-up (2026-07-24)
    //
    // Task 3: `_collectEip2612` (`:826-833`) — neither checked nor disclosed.
    // Task 5: six `Check`s with code present and correct but no discriminating
    // test (verifier §7.2 neutralised `ensure(cond, ..)` -> `ensure(true, ..)`
    // for all 37 checks in this module; these six survived).
    // =========================================================================

    /// Task 3 (verifier §4): `:832` — `_collectEip2612`'s combined
    /// `owner == payer && spender == address(this) && value >= feeAmount`,
    /// each clause independently. `SponsoredEnrollmentCall` did not even
    /// carry an `Eip2612Authorization` before this task, so none of this was
    /// checkable OR disclosed; `Eip2612FeeFieldsMismatch`'s doc records what
    /// remains unverified (the `permit()` call itself).
    ///
    /// Mutation this detects: neutralising the `ensure(p.owner ==
    /// intent.controller && p.spender == manifest.goat_relay_gateway &&
    /// p.value >= quote.fee_amount, Check::Eip2612FeeFieldsMismatch, ..)`
    /// added by this task.
    #[test]
    fn effects_reject_every_mismatched_eip2612_fee_authorization_field() {
        let chain = wired_chain();
        let st = state(&chain);

        type Mutation = Box<dyn Fn(&mut Eip2612Authorization)>;
        let mutations: Vec<(&str, Mutation)> = vec![
            (
                "owner != controller",
                Box::new(|p: &mut Eip2612Authorization| p.owner = [0x64; 20]),
            ),
            (
                "spender != gateway",
                Box::new(|p: &mut Eip2612Authorization| p.spender = [0x65; 20]),
            ),
            (
                "value < feeAmount",
                Box::new(|p: &mut Eip2612Authorization| p.value -= 1),
            ),
        ];
        for (label, mutate) in &mutations {
            let mut f = fixture();
            mutate(&mut f.eip2612);
            let err = preflight_sponsored_enrollment(&f.call(), &st, &manifest())
                .err()
                .unwrap_or_else(|| panic!("Eip2612Authorization mutation ({label}) must reject"));
            assert_eq!(err.code(), ERR_PREFLIGHT_WOULD_REVERT, "{err}");
            assert_eq!(
                err.check(),
                Some(Check::Eip2612FeeFieldsMismatch),
                "mutation ({label}) fired the wrong check: {err}"
            );
        }

        // Control: the fixture's own authorization is valid.
        assert!(preflight_sponsored_enrollment(&fixture().call(), &st, &manifest()).is_ok());

        // This check is skipped entirely on the direct-ETH branch — a
        // deliberately garbage authorization there must NOT be rejected by
        // Eip2612FeeFieldsMismatch (there is no fee to authorize).
        let mut d = fixture();
        d.intent.fee_token = [0u8; 20];
        d.intent.fee_authorization_mode = AUTHORIZATION_MODE_NONE;
        d.intent.fee_authorization_digest = [0u8; 32];
        d.intent.fee_quote_hash = [0u8; 32];
        d.intent.max_fee = 0;
        d.intent.fee_token_config_hash = [0u8; 32];
        d.quote = FeeQuote {
            quote_id: [0u8; 32],
            action_type: [0u8; 32],
            action_core_hash: [0u8; 32],
            deployment_manifest_hash: [0u8; 32],
            fee_token_config_hash: [0u8; 32],
            fee_schedule_hash: [0u8; 32],
            payer: [0u8; 20],
            fee_token: [0u8; 20],
            fee_amount: 0,
            fee_recipient: [0u8; 20],
            valid_after: 0,
            valid_until: 0,
        };
        d.quote_sig = String::new();
        d.fee_authorization_mode = AUTHORIZATION_MODE_NONE;
        d.eip2612.owner = [0xEE; 20]; // garbage: would fail the check if it ran
        d.resign_sponsor();
        let report = preflight_sponsored_enrollment(&d.call(), &st, &manifest())
            .expect("direct-ETH branch must not consult fee_eip2612_authorization at all");
        assert_eq!(report.disposition, Disposition::ClientMustSubmitDirectly);
    }

    /// Task 5, item 1: `Check::DirectEthFeeAuthorizationNotNone` (`:390`).
    /// Isolated from the sibling direct-branch checks by keeping
    /// `quoteSignature` empty and the quote fully zeroed (so those two fire
    /// first only if THIS clause were absent) and mutating only
    /// `fee_authorization_mode`.
    ///
    /// Mutation this detects: neutralising `ensure(call.fee_authorization_mode
    /// == AUTHORIZATION_MODE_NONE, Check::DirectEthFeeAuthorizationNotNone, ..)`.
    #[test]
    fn direct_eth_rejects_a_present_fee_authorization_mode() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.intent.fee_token = [0u8; 20];
        f.intent.fee_authorization_mode = AUTHORIZATION_MODE_NONE;
        f.intent.fee_authorization_digest = [0u8; 32];
        f.intent.fee_quote_hash = [0u8; 32];
        f.intent.max_fee = 0;
        f.intent.fee_token_config_hash = [0u8; 32];
        f.quote = FeeQuote {
            quote_id: [0u8; 32],
            action_type: [0u8; 32],
            action_core_hash: [0u8; 32],
            deployment_manifest_hash: [0u8; 32],
            fee_token_config_hash: [0u8; 32],
            fee_schedule_hash: [0u8; 32],
            payer: [0u8; 20],
            fee_token: [0u8; 20],
            fee_amount: 0,
            fee_recipient: [0u8; 20],
            valid_after: 0,
            valid_until: 0,
        };
        f.quote_sig = String::new();
        f.fee_authorization_mode = AUTHORIZATION_MODE_EIP2612; // the mutation
        f.resign_sponsor();
        assert_rejects(&f, &st, Check::DirectEthFeeAuthorizationNotNone);
    }

    /// Task 5, item 2: `Check::LinkSecondaryEqualsRoot`
    /// (`WalletSponsorshipRegistry.sol:190`). Only reachable when
    /// `intent.root == intent.secondary` — nothing upstream of it forbids
    /// that on its own (check 4 only requires `link.root`/`link.secondary`
    /// to equal `intent.root`/`intent.secondary`, not that the two differ).
    /// Builds a self-referential cluster (root == secondary) to reach it.
    ///
    /// Mutation this detects: neutralising `ensure(call.link.secondary !=
    /// call.link.root, Check::LinkSecondaryEqualsRoot, ..)`.
    #[test]
    fn effects_reject_a_link_secondary_that_equals_its_own_root() {
        let self_addr = addr(SECONDARY_KEY);
        let chain = wired_chain();
        let cfg_hash = fee_token_config_hash(&token_cfg());
        // `wired_chain()` only wires (GATEWAY, ROOT, secondary, FEE_TOKEN);
        // register the self-referential (root, secondary) pair separately.
        chain.set_nonce_snapshot(GATEWAY, self_addr, self_addr, FEE_TOKEN, snapshot(cfg_hash));

        let mut f = fixture();
        f.intent.root = self_addr;
        f.link.root = self_addr;
        let new_link_digest = link_secondary_digest(&f.link, CHAIN_ID, SPONSORSHIP);
        f.intent.link_digest = new_link_digest;
        f.link_sig = sign(SECONDARY_KEY, new_link_digest);
        f.rebind_quote();

        let st = read_live_preflight_state(&chain, &manifest(), self_addr, self_addr)
            .expect("self-referential state read must succeed");
        assert_rejects(&f, &st, Check::LinkSecondaryEqualsRoot);
    }

    /// Task 5, item 3: `Check::ZeroQuoteSigner` (`:705`) — checked against
    /// `manifest.quote_signer`, not against a chain read (see
    /// `UNVERIFIED_CHECKS`). Mutating only the manifest, with the fixture's
    /// otherwise-valid call untouched, isolates it.
    ///
    /// Mutation this detects: neutralising `ensure(manifest.quote_signer !=
    /// [0u8; 20], Check::ZeroQuoteSigner, ..)`.
    #[test]
    fn check_17_rejects_a_manifest_with_a_zero_quote_signer() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut zero_signer_manifest = manifest();
        zero_signer_manifest.quote_signer = [0u8; 20];
        let err = preflight_sponsored_enrollment(&fixture().call(), &st, &zero_signer_manifest)
            .expect_err("zero quoteSigner must reject");
        assert_eq!(err.code(), ERR_PREFLIGHT_WOULD_REVERT, "{err}");
        assert_eq!(err.check(), Some(Check::ZeroQuoteSigner), "{err}");
    }

    /// Task 5, item 4: `Check::ZeroQuoteId` (`:706`). Fires before the
    /// core-hash/signature checks later in `preflight_quote`, so mutating
    /// `quote.quoteId` alone (no rebind) isolates it.
    ///
    /// Mutation this detects: neutralising `ensure(quote.quote_id !=
    /// [0u8; 32], Check::ZeroQuoteId, ..)`.
    #[test]
    fn check_17_rejects_a_zero_quote_id() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.quote.quote_id = [0u8; 32]; // deliberately NOT rebound
        assert_rejects(&f, &st, Check::ZeroQuoteId);
    }

    /// Task 5, item 5: `Check::QuoteFeeTokenMismatch` (`:711`). Mutates
    /// `intent.feeToken` only, leaving `quote.feeToken` equal to
    /// `state.queried_fee_token` — otherwise the `StateMisbound` check right
    /// after `:711` would fire on `quote.feeToken` instead and this
    /// wouldn't discriminate the `:711` clause specifically.
    ///
    /// Mutation this detects: neutralising `ensure(quote.fee_token ==
    /// intent.fee_token && quote.fee_token != [0u8; 20],
    /// Check::QuoteFeeTokenMismatch, ..)`.
    #[test]
    fn check_17_rejects_a_quote_fee_token_that_disagrees_with_the_intent() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.intent.fee_token = [0x35; 20]; // quote.fee_token (FEE_TOKEN) unchanged
        f.rebind_quote();
        assert_rejects(&f, &st, Check::QuoteFeeTokenMismatch);
    }

    /// Task 5, item 6: the `intent.deploymentManifestHash != liveManifest`
    /// clause of `Check::ManifestHashMismatch` (`:716-719`). The existing
    /// `check_17_manifest_hash_comes_from_the_live_active_manifest_hash_read`
    /// and `check_17_rejects_a_manifest_hash_the_chain_has_replaced` tests
    /// only exercise the FIRST ensure on that line range (`live_manifest ==
    /// snapshot.deployment_manifest_hash()`); this one keeps that ensure
    /// satisfied and mutates only the intent's own field, isolating the
    /// second ensure's intent-side clause.
    ///
    /// Mutation this detects: neutralising `ensure(intent.deployment_manifest_hash
    /// == live_manifest && quote.deployment_manifest_hash == live_manifest,
    /// Check::ManifestHashMismatch, ..)`.
    #[test]
    fn check_17_rejects_an_intent_deployment_manifest_hash_that_disagrees_with_the_live_read() {
        let chain = wired_chain();
        let st = state(&chain);
        let mut f = fixture();
        f.intent.deployment_manifest_hash = [0x36; 32]; // NOT rebound: live
                                                        // activeManifestHash() and the
                                                        // snapshot's own copy both still say
                                                        // MANIFEST_HASH; only the intent's
                                                        // own field disagrees
        assert_rejects(&f, &st, Check::ManifestHashMismatch);
    }

    /// A `Fixture` on the direct-ETH branch with every `FeeQuote` field
    /// zero — the baseline
    /// `direct_eth_rejects_each_non_zero_quote_field_independently` mutates
    /// one field of at a time.
    fn direct_eth_zeroed_fixture() -> Fixture {
        let mut f = fixture();
        f.intent.fee_token = [0u8; 20];
        f.intent.fee_authorization_mode = AUTHORIZATION_MODE_NONE;
        f.intent.fee_authorization_digest = [0u8; 32];
        f.intent.fee_quote_hash = [0u8; 32];
        f.intent.max_fee = 0;
        f.intent.fee_token_config_hash = [0u8; 32];
        f.quote = FeeQuote {
            quote_id: [0u8; 32],
            action_type: [0u8; 32],
            action_core_hash: [0u8; 32],
            deployment_manifest_hash: [0u8; 32],
            fee_token_config_hash: [0u8; 32],
            fee_schedule_hash: [0u8; 32],
            payer: [0u8; 20],
            fee_token: [0u8; 20],
            fee_amount: 0,
            fee_recipient: [0u8; 20],
            valid_after: 0,
            valid_until: 0,
        };
        f.quote_sig = String::new();
        f.fee_authorization_mode = AUTHORIZATION_MODE_NONE;
        f.resign_sponsor();
        f
    }

    /// Fixes verifier §9.2 (a weaker overclaim, not a vacuous test): the doc
    /// comment on `direct_eth_rejects_a_non_zeroed_quote` claims "every one
    /// of the twelve `FeeQuote` fields must be zero", but that test only
    /// ever exercises the FIRST field (it leaves the quote fully populated
    /// as a single combined mutation) — it detects deletion of the whole
    /// `:381-389` check, not of any individual clause. This test mutates
    /// one field at a time, closing the gap the comment claimed was already
    /// closed.
    ///
    /// Mutation this detects: deleting any ONE of the twelve `&&`-joined
    /// clauses inside `fee_quote_is_all_zero`.
    #[test]
    fn direct_eth_rejects_each_non_zero_quote_field_independently() {
        let chain = wired_chain();
        let st = state(&chain);

        type Mutation = Box<dyn Fn(&mut FeeQuote)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|q: &mut FeeQuote| q.quote_id = [0x40; 32]),
            Box::new(|q: &mut FeeQuote| q.action_type = [0x40; 32]),
            Box::new(|q: &mut FeeQuote| q.action_core_hash = [0x40; 32]),
            Box::new(|q: &mut FeeQuote| q.deployment_manifest_hash = [0x40; 32]),
            Box::new(|q: &mut FeeQuote| q.fee_token_config_hash = [0x40; 32]),
            Box::new(|q: &mut FeeQuote| q.fee_schedule_hash = [0x40; 32]),
            Box::new(|q: &mut FeeQuote| q.payer = [0x40; 20]),
            Box::new(|q: &mut FeeQuote| q.fee_token = [0x40; 20]),
            Box::new(|q: &mut FeeQuote| q.fee_amount = 1),
            Box::new(|q: &mut FeeQuote| q.fee_recipient = [0x40; 20]),
            Box::new(|q: &mut FeeQuote| q.valid_after = 1),
            Box::new(|q: &mut FeeQuote| q.valid_until = 1),
        ];

        for (idx, mutate) in mutations.iter().enumerate() {
            let mut f = direct_eth_zeroed_fixture();
            mutate(&mut f.quote);
            let err = preflight_sponsored_enrollment(&f.call(), &st, &manifest())
                .err()
                .unwrap_or_else(|| panic!("FeeQuote field mutation {idx} must be rejected"));
            assert_eq!(err.code(), ERR_PREFLIGHT_WOULD_REVERT, "{err}");
            assert_eq!(
                err.check(),
                Some(Check::DirectEthQuoteNotZeroed),
                "mutation {idx} fired the wrong check: {err}"
            );
        }

        // Control: with all twelve fields zero, this precondition passes.
        assert!(preflight_sponsored_enrollment(
            &direct_eth_zeroed_fixture().call(),
            &st,
            &manifest()
        )
        .is_ok());
    }

    /// Every `Check` must name a real Solidity error and a real site — a
    /// typo'd revert name would send the desktop chasing an error that does
    /// not exist (the `StaleNonce` incident).
    #[test]
    fn every_check_names_a_real_revert_and_site() {
        use Check::*;
        let all = [
            ExpiredDeadline,
            ZeroRootOrSecondary,
            LinkFieldsMismatch,
            V1WalletMismatch,
            ControllerUnset,
            ControllerMismatch,
            EpochMismatch,
            EnrollDigestMismatch,
            BadV1Signature,
            LinkDigestMismatch,
            BadLinkSignature,
            NonZeroRootAuthorizationDigest,
            NonZeroRootAuthorization,
            DirectEthQuoteSignaturePresent,
            DirectEthQuoteNotZeroed,
            DirectEthFeeAuthorizationNotNone,
            ZeroQuoteSigner,
            ZeroQuoteId,
            QuoteActionTypeMismatch,
            QuotePayerMismatch,
            QuoteFeeRecipientMismatch,
            QuoteFeeTokenMismatch,
            ZeroQuoteFeeAmount,
            FeeExceedsMax,
            QuoteWindow,
            ManifestHashMismatch,
            FeeScheduleHashMismatch,
            TokenNotAuthorized,
            FeeTokenConfigHashMismatch,
            QuoteActionCoreHashMismatch,
            BadQuoteSignature,
            FeeQuoteHashMismatch,
            UnsupportedFeeMode,
            BadSponsorSignature,
            ZeroIntentId,
            BadActionNonce,
            V1EnrollNonceUnusable,
            FeeAuthorizationModeNotEip2612,
            Eip2612FeeFieldsMismatch,
            LinkSecondaryEqualsRoot,
            LinkDeadlineExpired,
            LinkNonceMismatch,
        ];
        // Transcribed from the `error` declarations at
        // GoatRelayGateway.sol:26-61 and WalletSponsorshipRegistry.sol.
        let known = [
            "ZeroAddress",
            "NotActivated",
            "Paused",
            "IntentAlreadyUsed",
            "ZeroIntentId",
            "BadActionNonce",
            "ExpiredDeadline",
            "RootNotRegistered",
            "ClusterSuspended",
            "ConfigHashMismatch",
            "TokenNotAuthorized",
            "BadSponsorSignature",
            "BadQuoteSignature",
            "BadLinkSignature",
            "BadV1Signature",
            "InvalidFeeFields",
            "InvalidQuote",
            "QuoteAlreadyUsed",
            "ControllerMismatch",
            "EpochMismatch",
            "NotController",
            "InvalidV1Enrollment",
            "FeeExceedsMax",
            "UnsupportedFeeMode",
            "InvalidRootAuthorization",
            "ExpiredSignature",
        ];
        for c in all {
            assert!(
                known.contains(&c.revert()),
                "{c:?} names {:?}, which is not a declared Solidity error",
                c.revert()
            );
            assert!(c.site().contains(".sol:"), "{c:?} has no file:line site");
        }
        assert!(
            !UNVERIFIED_CHECKS.is_empty(),
            "the disclosure list must not silently empty out"
        );
    }
}
