//! Stream G quote-lifecycle shared types (Task 6a/6b) — on-chain `FeeQuote`
//! mirror, EIP-712 signing machinery, action-type constants, and the
//! request/response DTOs `quotes.rs` (6a) and `preflight.rs`/submit (6b)
//! both build on.
//!
//! ## Ground truth
//! Every constant and field order below is copied from the Task 6a design
//! brief, itself extracted
//! directly from `contracts/src/StreamGTypes.sol` and
//! `contracts/src/GoatRelayGateway.sol` by the architect. Every TYPEHASH
//! string and every action-type string was additionally, independently
//! re-verified in this task via `cast keccak "<literal>"` (Foundry's
//! `cast`, not this module's own `keccak256` call) — see
//! `quotes::tests::fee_quote_typehash_matches_streamg_types_sol`,
//! `quotes::tests::action_type_constants_pinned`, and friends. Do not
//! hand-edit any TYPEHASH/action-string constant without re-reading the
//! Solidity and recomputing with `cast keccak`.
//!
//! (All Stream G test functions for this task live in `quotes.rs`, not
//! here, so that `cargo test stream_g::quotes` — the brief's mandated
//! verification command — actually runs every pin, including the ones that
//! only exercise this file's pure functions.)
//!
//! ## EIP-712 domain: `GoatRelayGateway`, NOT `GoatWalletSponsorship`
//! `FeeQuote` is signed under `EIP712("GoatRelayGateway", "1")`
//! (`GoatRelayGateway.sol:138`), with `verifyingContract` = the deployed
//! `GoatRelayGateway` address (manifest `goatRelayGateway` key). This is a
//! **different** domain from `root_authorization.rs`'s `RootAuthorization`
//! (`"GoatWalletSponsorship"`, the `WalletSponsorshipRegistry` address) —
//! see `quotes::tests::fee_quote_domain_is_not_root_authorization_domain`
//! for the regression pin. `LinkSecondary` (used for the nested
//! enrollment-bearer signature, §3.4) is a *third*, distinct struct signed
//! under the *same* `"GoatWalletSponsorship"`/`"1"` domain as
//! `RootAuthorization` — both are verified by
//! `WalletSponsorshipRegistry`, just via different typehashes/structs.
//!
//! ## Only `SponsorEnrollmentCore` is fully implemented here
//! `StreamGTypes.sol` declares four `*Core` structs/typehashes (enrollment,
//! sell, GOAT transfer, USDT transfer) that each action's quote path hashes
//! into `FeeQuote.actionCoreHash`. This task (6a) only wires the
//! **sponsored-enrollment** quote path end to end — the plan's mandated
//! nested-bearer-signature test is enrollment-specific, and
//! `GoatRelayGateway.sol` itself marks `executeSponsoredSell` /
//! `executeGoatTransfer` / `executeUsdtTransfer` as later contracts-side
//! work ("Task 8" in that file's own section comments). Their TYPEHASH
//! strings are pinned here (cheap, directly ground-truth-sourced, and ready
//! for whichever later task implements them) but their `*Core` struct and
//! struct-hash function are **not** implemented — do not treat the pinned
//! strings as evidence those quote paths are wired up. Report: this is a
//! deliberate scope boundary, not an oversight.
//!
//! ## Live chain state (honesty note — this repo's "claims ≤ code" rule)
//! The values a real quote must bind to that cannot come from the request
//! body are still **caller-supplied** on [`EnrollmentQuoteContext`], but the
//! two types that carry them, [`token_manifest::LiveTokenReading`] and
//! [`LiveEnrollmentNonces`], have private fields and, outside
//! `#[cfg(test)]`, exactly one constructor each —
//! [`token_manifest::read_live_token_state`] (which performs the
//! `eth_getCode` / `getTokenConfig` / `getTokenConfigHash` reads and binds
//! them together) and [`LiveEnrollmentNonces::read_live`] (which performs
//! the `secondaryEnrollmentNonceSnapshot` read itself and validates its
//! `presentMask`) — each taking a [`token_manifest::TrustedChain`] rather
//! than an already-decoded value or a bare `&dyn ChainClient`.
//! `LiveEnrollmentNonces` used to have a `pub fn
//! from_snapshot(&NonceSnapshotView)` production constructor, and
//! `NonceSnapshotView` was a `pub`, all-`pub`-field, `Default`-deriving
//! struct — so `NonceSnapshotView { present_mask: ..., ..Default::default() }`
//! followed by `LiveEnrollmentNonces::from_snapshot(&fake)` compiled and
//! succeeded as ordinary public API, no chain, mock, or test hatch
//! involved. `from_snapshot` is now `pub(crate)` and `NonceSnapshotView`'s
//! fields are `pub(crate)`, so that literal no longer compiles outside this
//! crate.
//!
//! A caller can still choose *which* block and *which* addresses to read,
//! and this module verifies neither. What it can no longer do **at all in a
//! release build** is hand either constructor a `ChainClient` this crate did
//! not itself vouch for: both `read_live_token_state` and
//! [`LiveEnrollmentNonces::read_live`] require a
//! [`token_manifest::TrustedChain`], whose only non-`#[cfg(test)]`
//! constructor (`TrustedChain::live`) takes the *concrete*
//! [`crate::rpc_chain::RpcChain`] type by reference — not a trait object —
//! so neither a hand-written `ChainClient` impl that answers from config nor
//! this crate's own [`crate::chain::MockChain`] (`pub`, **not**
//! `#[cfg(test)]`-gated; it also backs `GOAT_ATTESTOR_MOCK=1`) can be
//! converted into one outside a test build. This is a compile-time refusal,
//! not a runtime distinction one constructor could get right and the other
//! wrong — see [`token_manifest::TrustedChain`]'s own doc, and the
//! source-scan tripwires
//! ([`tests::live_enrollment_nonces_read_live_takes_a_trusted_chain_not_a_bare_chain_client`]
//! here,
//! [`token_manifest::tests::trusted_chain_has_no_release_build_conversion_from_an_arbitrary_chain_client`]
//! for the type itself) that fail loudly if either regresses.
//!
//! **Before this task** (independent verifier, 2026-07-24, following up on
//! Task 6b Wave D): `read_live` alone still took a bare `&dyn ChainClient`,
//! and [`EnrollmentQuoteContext::live_nonces`] is a `pub` field the caller
//! fills in — so in a release build a caller could hand
//! `create_sponsored_enrollment_quote` mock-sourced `v1EnrollNonce` /
//! `linkNonce` even though `live_token` was provably live, with only
//! `quotes.rs`'s STEP 0 `fee_token_config_hash` cross-check (R3) standing in
//! the way — and a caller controlling the mock satisfies that cross-check
//! trivially. The verifier reproduced this compiling cleanly in a
//! **non-test** build via a temporary probe function
//! (`__probe_nonces_from_mock`, deleted after confirming the fix). Closed
//! here by gating `read_live` the same way `read_live_token_state` already
//! was.
//!
//! `EnrollmentQuoteContext::live_nonces` stays a `pub` field rather than
//! being wrapped further: the guarantee lives in the *value*, not in field
//! visibility, exactly as [`EnrollmentQuoteContext::live_token`] (a `&`
//! reference, freely readable) already demonstrates — a `LiveEnrollmentNonces`
//! cannot be fabricated regardless of how freely the field holding it can be
//! read or copied, because its own fields are private and its only
//! production constructor is gated.
//!
//! Read those two types' own docs for the precise "not guaranteed" lists —
//! in particular neither proves freshness, and the nonce snapshot is
//! explicitly advisory and reserves nothing.
//!
//! `deploymentManifestHash` and `feeScheduleHash` are **not** deferred the
//! same way: they come from `token_manifest::load_deployment_manifest`, a
//! real (already-implemented, Task 4) file read of
//! `contracts/deployments/31337.stream-g.json`, not a live RPC call.
//!
//! ### `feeScheduleHash` — CORRECTED 2026-07-27, where the premise was seeded
//!
//! What stood here said that `feeScheduleHash` "has no independently-derivable
//! hashing rule to verify against at all (it is an opaque governance-set tag,
//! confirmed by reading `contracts/script/DeployStreamG.s.sol`, not a hash of
//! any canonical fee-schedule encoding)", and forwarded the reader to the
//! `quotes` module doc for the reasoning. **Every clause of that was wrong**,
//! and it is quoted rather than deleted because this is the sentence the rest
//! of the workstream inherited: it is the origin of the "opaque tag" premise
//! that later justified treating the value as an unverifiable pass-through.
//!
//! The rule existed the whole time. It is published verbatim in
//! the "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring" spec, §8.1
//! "Quote construction" — two days before this paragraph was written:
//!
//! > "feeScheduleHash = keccak256(UTF8(RFC8785(schedulePayload)))."
//!
//! over a named, deny-unknown-fields, eleven-field payload. The mistake was
//! not a misreading of `DeployStreamG.s.sol`; that file was read correctly and
//! genuinely says nothing about derivation. The mistake was inferring a global
//! absence from one file's silence — a deploy script is where a value is
//! *supplied* (`DeployStreamG.run()`'s `Params` initializer sets
//! `feeScheduleHash` from `vm.envBytes32("STREAM_G_FEE_SCHEDULE_HASH")`), never
//! where its derivation is *specified*.
//!
//! What is true now, in code rather than in prose:
//! [`super::quotes::FeeSchedule::from_json`] computes
//! `keccak256(UTF8(RFC8785(payload)))` over the file's `payload` object via
//! [`crate::canonical_hash`], and [`super::runtime::StreamGState::start`]
//! refuses to start unless that digest equals **both** the hash the file
//! declares (`StreamGStartupError::FeeScheduleHashSelfMismatch`) and the hash
//! the deployment manifest carries (`StreamGStartupError::FeeScheduleHashMismatch`),
//! and additionally unless the payload's `chainId` and `feeToken` equal the
//! manifest's (`FeeScheduleChainMismatch` / `FeeScheduleFeeTokenMismatch`).
//! So the `feeScheduleHash` a quote signs is an attestation about the tariff
//! *values* this process loaded, from a schedule authored for this deployment
//! — not about a label an operator typed. Read
//! [`super::quotes::FeeSchedule::load`]'s doc for the exact list of what is and
//! is not covered at startup. `payload.decimals` is **not** on that list any
//! more: it is compared on the quote path, against the registry's
//! `FeeTokenConfig.decimals`, by
//! `super::quotes::assert_schedule_decimals_match_live_token` — startup has no
//! chain read with which to compare it. The validity window and the three
//! ceiling maps are still hashed and compared to nothing.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::base_fee::WeiCeiling;
use super::token_manifest::{self, DeploymentManifest, LiveTokenReading, TrustedChain};
use crate::chain::{
    NonceSnapshotView, SNAP_CONFIG_HASHES, SNAP_FEE_TOKEN_PERMIT_NONCE, SNAP_LINK_NONCE,
    SNAP_V1_ENROLL_NONCE,
};
use crate::merkle::keccak256;

// ---------------------------------------------------------------------------
// Action type constants — StreamGTypes.sol:28-32.
// ---------------------------------------------------------------------------

pub const ACTION_SPONSORED_ENROLLMENT_STR: &str = "GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1";
pub const ACTION_SPONSORED_SELL_STR: &str = "GOAT_STREAM_G_SPONSORED_SELL_V1";
pub const ACTION_GOAT_TRANSFER_STR: &str = "GOAT_STREAM_G_GOAT_TRANSFER_V1";
pub const ACTION_USDT_TRANSFER_STR: &str = "GOAT_STREAM_G_USDT_TRANSFER_V1";

/// One of the four Stream G action types (`StreamGTypes.sol:28-32`).
/// Deliberately an enum, not a raw `[u8; 32]` or a bare integer — see
/// [`ActionType::digest`]. Only [`ActionType::SponsoredEnrollment`] has a
/// wired-up quote path in this task; see module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionType {
    SponsoredEnrollment,
    SponsoredSell,
    GoatTransfer,
    UsdtTransfer,
}

impl ActionType {
    /// The literal string `StreamGTypes.sol` hashes to produce the on-chain
    /// `bytes32` constant.
    pub const fn as_str(self) -> &'static str {
        match self {
            ActionType::SponsoredEnrollment => ACTION_SPONSORED_ENROLLMENT_STR,
            ActionType::SponsoredSell => ACTION_SPONSORED_SELL_STR,
            ActionType::GoatTransfer => ACTION_GOAT_TRANSFER_STR,
            ActionType::UsdtTransfer => ACTION_USDT_TRANSFER_STR,
        }
    }

    /// `keccak256(as_str())` — the on-chain `bytes32` action-type constant
    /// (`ACTION_SPONSORED_ENROLLMENT` etc.).
    pub fn digest(self) -> [u8; 32] {
        keccak256(self.as_str().as_bytes())
    }
}

// ---------------------------------------------------------------------------
// FeeQuote — StreamGTypes.sol:107-120 / GoatRelayGateway._feeQuoteStructHash.
// Field order below is the EIP-712 encoding order; do not reorder.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeQuote {
    pub quote_id: [u8; 32],
    pub action_type: [u8; 32],
    pub action_core_hash: [u8; 32],
    pub deployment_manifest_hash: [u8; 32],
    pub fee_token_config_hash: [u8; 32],
    pub fee_schedule_hash: [u8; 32],
    pub payer: [u8; 20],
    pub fee_token: [u8; 20],
    /// `uint256` on-chain; `u128` here — same convention `base_fee.rs`'s
    /// money-path newtypes and `token_manifest.rs`'s `capability_mask`
    /// already use in this crate: wide enough for any realistic USDT
    /// amount, without pretending to fully emulate `uint256`.
    pub fee_amount: u128,
    pub fee_recipient: [u8; 20],
    /// `uint48` on-chain, stored as `u64` — same convention
    /// `root_authorization.rs`'s `deadline` uses.
    pub valid_after: u64,
    pub valid_until: u64,
}

/// `StreamGTypes.FEE_QUOTE_TYPEHASH` (`StreamGTypes.sol:38-40`).
pub const FEE_QUOTE_TYPEHASH_STR: &str = "FeeQuote(bytes32 quoteId,bytes32 actionType,bytes32 actionCoreHash,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,bytes32 feeScheduleHash,address payer,address feeToken,uint256 feeAmount,address feeRecipient,uint48 validAfter,uint48 validUntil)";

/// `GoatRelayGateway.sol:138` — `EIP712("GoatRelayGateway", "1")`. NOT
/// `root_authorization.rs`'s `"GoatWalletSponsorship"` domain — see module
/// doc.
pub const FEE_QUOTE_DOMAIN_NAME: &str = "GoatRelayGateway";
pub const FEE_QUOTE_DOMAIN_VERSION: &str = "1";

/// `WalletSponsorshipRegistry` domain (`WalletSponsorshipRegistry.sol`
/// constructor: `EIP712("GoatWalletSponsorship", "1")`) —
/// `root_authorization.rs`'s `RootAuthorization` AND this module's
/// [`LinkSecondary`] are both signed under this domain, over two different
/// structs/typehashes.
pub const WALLET_SPONSORSHIP_DOMAIN_NAME: &str = "GoatWalletSponsorship";
pub const WALLET_SPONSORSHIP_DOMAIN_VERSION: &str = "1";

fn eip712_domain_typehash() -> [u8; 32] {
    keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
}

fn fee_quote_typehash() -> [u8; 32] {
    keccak256(FEE_QUOTE_TYPEHASH_STR.as_bytes())
}

pub(crate) fn address_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

pub(crate) fn u256_be(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

pub(crate) fn u256_be_u8(v: u8) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[31] = v;
    w
}

pub(crate) fn eip712_digest(domain: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 66];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(domain);
    buf[34..66].copy_from_slice(struct_hash);
    keccak256(&buf)
}

/// General EIP-712 domain separator — shared by [`fee_quote_domain_separator`]
/// (`"GoatRelayGateway"`/`"1"`) and [`link_secondary_digest`]
/// (`"GoatWalletSponsorship"`/`"1"`).
pub fn eip712_domain_separator(
    name: &str,
    version: &str,
    chain_id: u64,
    verifying_contract: [u8; 20],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 5);
    buf.extend_from_slice(&eip712_domain_typehash());
    buf.extend_from_slice(&keccak256(name.as_bytes()));
    buf.extend_from_slice(&keccak256(version.as_bytes()));
    buf.extend_from_slice(&u256_be(u128::from(chain_id)));
    buf.extend_from_slice(&address_word(&verifying_contract));
    keccak256(&buf)
}

pub fn fee_quote_domain_separator(chain_id: u64, verifying_contract: [u8; 20]) -> [u8; 32] {
    eip712_domain_separator(
        FEE_QUOTE_DOMAIN_NAME,
        FEE_QUOTE_DOMAIN_VERSION,
        chain_id,
        verifying_contract,
    )
}

/// `keccak256(abi.encode(FEE_QUOTE_TYPEHASH, quoteId, actionType,
/// actionCoreHash, deploymentManifestHash, feeTokenConfigHash,
/// feeScheduleHash, payer, feeToken, feeAmount, feeRecipient, validAfter,
/// validUntil))` — `GoatRelayGateway._feeQuoteStructHash`, field order
/// exactly as declared/encoded there.
pub fn fee_quote_struct_hash(q: &FeeQuote) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 13);
    buf.extend_from_slice(&fee_quote_typehash());
    buf.extend_from_slice(&q.quote_id);
    buf.extend_from_slice(&q.action_type);
    buf.extend_from_slice(&q.action_core_hash);
    buf.extend_from_slice(&q.deployment_manifest_hash);
    buf.extend_from_slice(&q.fee_token_config_hash);
    buf.extend_from_slice(&q.fee_schedule_hash);
    buf.extend_from_slice(&address_word(&q.payer));
    buf.extend_from_slice(&address_word(&q.fee_token));
    buf.extend_from_slice(&u256_be(q.fee_amount));
    buf.extend_from_slice(&address_word(&q.fee_recipient));
    buf.extend_from_slice(&u256_be(u128::from(q.valid_after)));
    buf.extend_from_slice(&u256_be(u128::from(q.valid_until)));
    keccak256(&buf)
}

/// The digest `GoatRelayGateway.quoteSigner` must sign (and
/// `_validateAndConsumeQuoteGeneric` recovers against).
pub fn fee_quote_digest(q: &FeeQuote, chain_id: u64, verifying_contract: [u8; 20]) -> [u8; 32] {
    let domain = fee_quote_domain_separator(chain_id, verifying_contract);
    let struct_hash = fee_quote_struct_hash(q);
    eip712_digest(&domain, &struct_hash)
}

// ---------------------------------------------------------------------------
// Action-core typehashes (StreamGTypes.sol). Only SponsorEnrollmentCore's
// struct + hash function is implemented — see module doc.
// ---------------------------------------------------------------------------

pub const SPONSOR_ENROLLMENT_CORE_TYPEHASH_STR: &str = "SponsorEnrollmentCore(bytes32 intentId,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,address root,address controller,uint256 controllerEpoch,address secondary,bytes32 enrollDigest,bytes32 linkDigest,bytes32 rootAuthorizationDigest,address feeToken,uint8 feeAuthorizationMode,uint256 maxFee,uint256 nonce,uint48 deadline)";
pub const SELL_CORE_TYPEHASH_STR: &str = "SellCore(bytes32 intentId,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,address seller,address expectedRoot,address desk,uint256 goatAmount,uint256 minNetUsdtOut,bytes32 goatPermitDigest,uint256 maxFee,uint256 nonce,uint48 deadline)";
pub const GOAT_TRANSFER_CORE_TYPEHASH_STR: &str = "GoatTransferCore(bytes32 intentId,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,address owner,address expectedRoot,address recipient,uint256 amount,bytes32 goatPermitDigest,address feeToken,uint8 feeAuthorizationMode,uint256 maxFee,uint256 nonce,uint48 deadline)";
pub const USDT_TRANSFER_CORE_TYPEHASH_STR: &str = "UsdtTransferCore(bytes32 intentId,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,address owner,address expectedRoot,address token,address recipient,uint256 amount,uint8 authorizationMode,uint256 maxFee,uint256 nonce,uint48 deadline)";
pub const LINK_SECONDARY_TYPEHASH_STR: &str =
    "LinkSecondary(address root,address secondary,uint256 nonce,uint48 deadline)";

fn sponsor_enrollment_core_typehash() -> [u8; 32] {
    keccak256(SPONSOR_ENROLLMENT_CORE_TYPEHASH_STR.as_bytes())
}

fn link_secondary_typehash() -> [u8; 32] {
    keccak256(LINK_SECONDARY_TYPEHASH_STR.as_bytes())
}

/// `StreamGTypes.SponsorEnrollmentCore` — the only `*Core` struct this task
/// implements; see module doc. Field order exactly as declared in
/// `StreamGTypes.sol` / encoded in
/// `GoatRelayGateway._validateAndConsumeQuote`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SponsorEnrollmentCore {
    pub intent_id: [u8; 32],
    pub deployment_manifest_hash: [u8; 32],
    pub fee_token_config_hash: [u8; 32],
    pub root: [u8; 20],
    pub controller: [u8; 20],
    /// `uint256` on-chain, `u64` here (an epoch counter never realistically
    /// needs more).
    pub controller_epoch: u64,
    pub secondary: [u8; 20],
    pub enroll_digest: [u8; 32],
    pub link_digest: [u8; 32],
    pub root_authorization_digest: [u8; 32],
    pub fee_token: [u8; 20],
    pub fee_authorization_mode: u8,
    pub max_fee: u128,
    pub nonce: u64,
    pub deadline: u64,
}

/// `keccak256(abi.encode(SPONSOR_ENROLLMENT_CORE_TYPEHASH, intentId,
/// deploymentManifestHash, feeTokenConfigHash, root, controller,
/// controllerEpoch, secondary, enrollDigest, linkDigest,
/// rootAuthorizationDigest, feeToken, feeAuthorizationMode, maxFee, nonce,
/// deadline))` — `GoatRelayGateway._validateAndConsumeQuote`'s `coreHash`.
pub fn sponsor_enrollment_core_hash(c: &SponsorEnrollmentCore) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 16);
    buf.extend_from_slice(&sponsor_enrollment_core_typehash());
    buf.extend_from_slice(&c.intent_id);
    buf.extend_from_slice(&c.deployment_manifest_hash);
    buf.extend_from_slice(&c.fee_token_config_hash);
    buf.extend_from_slice(&address_word(&c.root));
    buf.extend_from_slice(&address_word(&c.controller));
    buf.extend_from_slice(&u256_be(u128::from(c.controller_epoch)));
    buf.extend_from_slice(&address_word(&c.secondary));
    buf.extend_from_slice(&c.enroll_digest);
    buf.extend_from_slice(&c.link_digest);
    buf.extend_from_slice(&c.root_authorization_digest);
    buf.extend_from_slice(&address_word(&c.fee_token));
    buf.extend_from_slice(&u256_be_u8(c.fee_authorization_mode));
    buf.extend_from_slice(&u256_be(c.max_fee));
    buf.extend_from_slice(&u256_be(u128::from(c.nonce)));
    buf.extend_from_slice(&u256_be(u128::from(c.deadline)));
    keccak256(&buf)
}

/// `StreamGTypes.LinkSecondary`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkSecondary {
    pub root: [u8; 20],
    pub secondary: [u8; 20],
    pub nonce: u64,
    pub deadline: u64,
}

fn link_secondary_struct_hash(link: &LinkSecondary) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 5);
    buf.extend_from_slice(&link_secondary_typehash());
    buf.extend_from_slice(&address_word(&link.root));
    buf.extend_from_slice(&address_word(&link.secondary));
    buf.extend_from_slice(&u256_be(u128::from(link.nonce)));
    buf.extend_from_slice(&u256_be(u128::from(link.deadline)));
    keccak256(&buf)
}

/// `GoatRelayGateway._linkDigest` — EIP-712 digest under the
/// `WalletSponsorshipRegistry` domain (see module doc: same domain
/// `root_authorization.rs` uses, different struct/typehash).
pub fn link_secondary_digest(
    link: &LinkSecondary,
    chain_id: u64,
    wallet_sponsorship_registry: [u8; 20],
) -> [u8; 32] {
    let domain = eip712_domain_separator(
        WALLET_SPONSORSHIP_DOMAIN_NAME,
        WALLET_SPONSORSHIP_DOMAIN_VERSION,
        chain_id,
        wallet_sponsorship_registry,
    );
    let struct_hash = link_secondary_struct_hash(link);
    eip712_digest(&domain, &struct_hash)
}

// ---------------------------------------------------------------------------
// Nested bearer signatures (enrollment quotes, brief §3.4).
// ---------------------------------------------------------------------------

pub const ERR_SNAPSHOT_FIELD_NOT_PRESENT: &str = "SNAPSHOT_FIELD_NOT_PRESENT";
pub const ERR_SNAPSHOT_NONCE_OUT_OF_RANGE: &str = "SNAPSHOT_NONCE_OUT_OF_RANGE";
pub const ERR_SNAPSHOT_CHAIN_READ_FAILED: &str = "SNAPSHOT_CHAIN_READ_FAILED";

/// Why a `secondaryEnrollmentNonceSnapshot` return could not be turned into
/// a [`LiveEnrollmentNonces`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LiveNoncesError {
    /// [`LiveEnrollmentNonces::read_live`]'s own
    /// `secondaryEnrollmentNonceSnapshot` chain read failed. Fail closed:
    /// there is no "assume the previous nonces" fallback, mirroring
    /// `token_manifest::TokenManifestError::ChainRead`.
    #[error("live nonce snapshot read failed: {detail}")]
    ChainRead { detail: String },
    /// Sourcing contract §3 R3: a cleared `presentMask` bit means the field
    /// was never populated and the zero sitting in it is meaningless. Fail
    /// closed rather than reading it.
    #[error(
        "nonce snapshot presentMask 0x{present_mask:08x} has bit 0x{bit:08x} clear: \
         {field} was never populated (live-chain sourcing contract R3)"
    )]
    FieldNotPresent {
        field: &'static str,
        bit: u32,
        present_mask: u32,
    },
    /// A cleared `SNAP_FEE_TOKEN_PERMIT_NONCE` is not a missing field in the
    /// ordinary sense: `GoatRelayGateway._snapshot` (`:288-296`) skips that
    /// bit precisely when the fee token is **not** authorized for
    /// `CAP_EIP2612`. It is therefore an independent on-chain statement that
    /// the token is unauthorized, and it collapses to the same public code
    /// as every other token-authorization failure
    /// ([`token_manifest::ERR_TOKEN_UNSUPPORTED`]).
    #[error(
        "nonce snapshot presentMask 0x{present_mask:08x} has SNAP_FEE_TOKEN_PERMIT_NONCE clear: \
         the gateway reports the fee token is not authorized for EIP-2612"
    )]
    FeeTokenUnauthorizedBySnapshot { present_mask: u32 },
    /// `uint256` on-chain, `u64` here. Reject, never truncate — the
    /// precedent `chain.rs`'s own `u256 → u128` narrowing sets.
    #[error("nonce snapshot {field} = {value} does not fit in u64")]
    NonceOutOfRange { field: &'static str, value: u128 },
}

impl LiveNoncesError {
    pub fn code(&self) -> &'static str {
        match self {
            LiveNoncesError::ChainRead { .. } => ERR_SNAPSHOT_CHAIN_READ_FAILED,
            LiveNoncesError::FieldNotPresent { .. } => ERR_SNAPSHOT_FIELD_NOT_PRESENT,
            LiveNoncesError::FeeTokenUnauthorizedBySnapshot { .. } => {
                token_manifest::ERR_TOKEN_UNSUPPORTED
            }
            LiveNoncesError::NonceOutOfRange { .. } => ERR_SNAPSHOT_NONCE_OUT_OF_RANGE,
        }
    }

    /// HTTP status for the shared Stream G error envelope
    /// (`super::http_error`). Wildcard-free on purpose — see
    /// [`super::base_fee::BaseFeeError::status`].
    ///
    /// Note the deliberate agreement with `token_manifest`:
    /// [`LiveNoncesError::FeeTokenUnauthorizedBySnapshot`] already collapses
    /// to [`token_manifest::ERR_TOKEN_UNSUPPORTED`] in [`Self::code`], so it
    /// must also carry the same **status** as
    /// `TokenManifestError::TokenNotAuthorized`, or one public code would
    /// mean two different things on the wire.
    /// `http_error::tests::every_error_code_maps_to_exactly_one_status` is
    /// the check.
    pub fn status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            LiveNoncesError::ChainRead { .. } => StatusCode::BAD_GATEWAY,
            // The chain state cannot support this call: the gateway never
            // populated the word, or it says the fee token is unauthorized.
            LiveNoncesError::FieldNotPresent { .. }
            | LiveNoncesError::FeeTokenUnauthorizedBySnapshot { .. } => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            // A `uint256` the chain reported that this build cannot
            // represent. That is this build's limit, not the caller's error.
            LiveNoncesError::NonceOutOfRange { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

fn require_bit(present_mask: u32, bit: u32, field: &'static str) -> Result<(), LiveNoncesError> {
    if present_mask & bit == 0 {
        return Err(LiveNoncesError::FieldNotPresent {
            field,
            bit,
            present_mask,
        });
    }
    Ok(())
}

fn narrow_nonce(value: u128, field: &'static str) -> Result<u64, LiveNoncesError> {
    u64::try_from(value).map_err(|_| LiveNoncesError::NonceOutOfRange { field, value })
}

/// The subset of `StreamGTypes.NonceSnapshot`
/// (`GoatRelayGateway.secondaryEnrollmentNonceSnapshot`) the nested
/// bearer-signature check needs: the two nonces a stale/mixed signed
/// payload could disagree with.
///
/// Fields are private and the only non-`cfg(test)` constructor is
/// [`LiveEnrollmentNonces::read_live`], so
/// `LiveEnrollmentNonces { v1_enroll_nonce: 0, link_nonce: 0 }` — a
/// fabricated pair that would make any stale bearer signature look fresh —
/// no longer compiles outside this module's tests.
///
/// **What this guarantees:** outside `#[cfg(test)]`, reaching a value of
/// this type requires going through [`LiveEnrollmentNonces::read_live`],
/// which calls `ChainClient::secondary_enrollment_nonce_snapshot` and
/// validates `presentMask` before trusting any field (R3) — there is no
/// bare-struct-literal path any more (see module doc). It does **not**
/// guarantee the `ChainClient` behind that call was a genuine RPC
/// connection: a deliberately fake implementation, or this crate's own
/// [`crate::chain::MockChain`] (`pub`, not `#[cfg(test)]`-gated), can still
/// answer from config. What is closed is *accidental* fabrication, not
/// deliberate `ChainClient` substitution — see module doc.
///
/// **What it does NOT guarantee:** freshness or reservation. The snapshot is
/// explicitly advisory (`GoatRelayGateway.sol:199` — "not execution
/// authority"); it reserves nothing, so between quote and submit another
/// party can consume the same nonce. This type proves nonce *consistency at
/// the snapshot's block*, nothing more. Nor does it compare
/// [`LiveEnrollmentNonces::fee_token_config_hash`] against the fee token
/// registry's hash itself, or the snapshot's manifest/fee-schedule hashes
/// against the deployment manifest — the former (R3's anti-TOCTOU binding)
/// is the caller's job (see `quotes::create_sponsored_enrollment_quote`'s
/// STEP 0 gate), and the latter is still owed to the submit path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveEnrollmentNonces {
    v1_enroll_nonce: u64,
    link_nonce: u64,
    block_number: u64,
    fee_token_config_hash: [u8; 32],
}

impl LiveEnrollmentNonces {
    /// The only production constructor. Performs the R3
    /// `secondaryEnrollmentNonceSnapshot` read itself against `chain`,
    /// pinned to `block` (R4), then validates `presentMask` via
    /// [`Self::from_snapshot`] before trusting any field.
    ///
    /// Before this existed, `from_snapshot` was `pub` and took an
    /// already-built `&NonceSnapshotView` — an all-`pub`-field,
    /// `Default`-deriving struct any caller could construct from a bare
    /// struct literal with no chain, mock, or test hatch involved (see
    /// module doc). `from_snapshot` is now `pub(crate)` and
    /// `NonceSnapshotView`'s fields are `pub(crate)`, so this is the only
    /// way to reach a [`LiveEnrollmentNonces`] from outside this crate's
    /// tests.
    ///
    /// `chain: impl Into<TrustedChain<'c>>`, not `&dyn ChainClient` — see
    /// module doc's "Before this task" note. Exactly the same fail-closed
    /// chain-honesty gate [`token_manifest::read_live_token_state`] uses: in
    /// a release build the only value satisfying `Into<TrustedChain>` is a
    /// `TrustedChain` built by `TrustedChain::live(&RpcChain)`, so a
    /// `MockChain` — or any other `ChainClient` implementor — cannot reach
    /// this function at all.
    pub fn read_live<'c>(
        chain: impl Into<TrustedChain<'c>>,
        gateway: [u8; 20],
        root: [u8; 20],
        secondary: [u8; 20],
        fee_token: [u8; 20],
        block: u64,
    ) -> Result<Self, LiveNoncesError> {
        let chain = chain.into().client();
        let snap = chain
            .secondary_enrollment_nonce_snapshot(gateway, root, secondary, fee_token, block)
            .map_err(|e| LiveNoncesError::ChainRead {
                detail: e.to_string(),
            })?;
        Self::from_snapshot(&snap)
    }

    /// Crate-internal: validates `presentMask` before reading any field
    /// (sourcing contract §3 R3) — including `SNAP_FEE_TOKEN_PERMIT_NONCE`,
    /// whose cleared state is an on-chain statement that the fee token is
    /// unauthorized. `pub(crate)`, not `pub`: reachable in production only
    /// via [`Self::read_live`] (the sole caller outside this crate's own
    /// tests, which use it directly to exercise the presentMask branches
    /// without standing up a `ChainClient`).
    pub(crate) fn from_snapshot(snap: &NonceSnapshotView) -> Result<Self, LiveNoncesError> {
        let mask = snap.present_mask;
        if mask & SNAP_FEE_TOKEN_PERMIT_NONCE == 0 {
            return Err(LiveNoncesError::FeeTokenUnauthorizedBySnapshot { present_mask: mask });
        }
        require_bit(mask, SNAP_V1_ENROLL_NONCE, "v1EnrollNonce")?;
        require_bit(mask, SNAP_LINK_NONCE, "linkNonce")?;
        // The three config hashes travel together under one bit; a cleared
        // bit means `feeTokenConfigHash` is a meaningless zero, which would
        // silently pass the submit-path binding it exists to support.
        require_bit(
            mask,
            SNAP_CONFIG_HASHES,
            "feeTokenConfigHash/manifest hashes",
        )?;

        Ok(Self {
            v1_enroll_nonce: narrow_nonce(snap.v1_enroll_nonce, "v1EnrollNonce")?,
            link_nonce: narrow_nonce(snap.link_nonce, "linkNonce")?,
            block_number: snap.block_number,
            fee_token_config_hash: snap.fee_token_config_hash,
        })
    }

    /// `EnrollmentRegistry.nonces(secondary)` at the snapshot's block.
    pub fn v1_enroll_nonce(&self) -> u64 {
        self.v1_enroll_nonce
    }

    /// `WalletSponsorshipRegistry.linkNonces(secondary)` at the snapshot's
    /// block.
    pub fn link_nonce(&self) -> u64 {
        self.link_nonce
    }

    /// The block the snapshot was taken at. No staleness bound is enforced
    /// here — see the type doc.
    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    /// The gateway's view of `getTokenConfigHash(feeToken)` at the same
    /// block, for the anti-TOCTOU comparison against
    /// [`token_manifest::LiveTokenReading::fee_token_config_hash`]. This
    /// module does not perform that comparison itself — R3 requires the two
    /// values to be compared alongside `assert_token_authorized`, so
    /// `quotes::create_sponsored_enrollment_quote`'s STEP 0 gate is where it
    /// actually happens (both values are available there, on
    /// `EnrollmentQuoteContext`).
    pub fn fee_token_config_hash(&self) -> [u8; 32] {
        self.fee_token_config_hash
    }

    /// Test-only escape hatch (same posture as
    /// `token_manifest::LiveTokenReading::for_test`). `fee_token_config_hash`
    /// is an explicit parameter, not a hardcoded zero: R3's anti-TOCTOU
    /// check (`quotes::create_sponsored_enrollment_quote`'s STEP 0 gate)
    /// compares this value against `LiveTokenReading::fee_token_config_hash`,
    /// so a test fixture that wants the happy path must supply a matching
    /// hash, and a test that wants to exercise the mismatch must be able to
    /// supply a deliberately different one.
    #[cfg(test)]
    pub fn for_test(
        v1_enroll_nonce: u64,
        link_nonce: u64,
        fee_token_config_hash: [u8; 32],
    ) -> Self {
        Self {
            v1_enroll_nonce,
            link_nonce,
            block_number: 0,
            fee_token_config_hash,
        }
    }
}

/// Everything `quotes::create_sponsored_enrollment_quote` needs that must
/// NEVER come from the request body — live/configured chain context,
/// resolved by the caller the same way `root_authorization.rs`'s
/// `IssuerSigningContext` is resolved: from `StreamGConfig` +
/// `token_manifest::load_deployment_manifest` + (for the fields this
/// module cannot itself obtain — see module doc) a live chain read.
pub struct EnrollmentQuoteContext<'a> {
    /// Real, file-loaded deployment manifest (`token_manifest::load_deployment_manifest`).
    /// Supplies `deploymentManifestHash`, `feeScheduleHash`, `feeSafe`
    /// (authoritative `feeRecipient`), `feeToken`, `goatRelayGateway`
    /// (EIP-712 verifying contract), `enrollmentRegistry`,
    /// `walletSponsorshipRegistry`, and `chainId`.
    pub manifest: &'a DeploymentManifest,
    /// `StreamGConfig::quote_signer_private_key`. Must correspond to the
    /// manifest's `quoteSigner` address for the resulting signature to
    /// verify on-chain — this module does not itself check that
    /// correspondence (no way to derive an address from a hex string
    /// without a live signer instantiation, which happens at sign time).
    pub quote_signer_private_key_hex: &'a str,
    /// The fee token's chain-sourced state: the `FeeTokenRegistry` config
    /// record, its registry-reported config hash, the live `EXTCODEHASH`,
    /// and the address actually queried — all read at one pinned block by
    /// [`token_manifest::read_live_token_state`], which is the only
    /// production way to obtain this type. Replaces the two separate
    /// caller-supplied `fee_token_capability` / `observed_fee_token_code_hash`
    /// fields this struct used to carry; see that module's "What
    /// `LiveTokenReading` does and does not guarantee".
    pub live_token: &'a LiveTokenReading,
    /// Bound to `StreamGConfig::max_native_exposure_wei` by the caller —
    /// see `base_fee.rs` module doc's "Binding `max_native_exposure_wei`"
    /// note; this is what completes that module's exposure guarantee.
    pub max_native_exposure_wei: WeiCeiling,
    /// Fresh `secondaryEnrollmentNonceSnapshot` read — see module doc.
    /// `pub` and by-value (not a private field or a further wrapper) is
    /// deliberate: the fabrication guard is [`LiveEnrollmentNonces`]'s own
    /// private fields and gated [`LiveEnrollmentNonces::read_live`]
    /// constructor, not this field's visibility — see module doc.
    pub live_nonces: LiveEnrollmentNonces,
}

// ---------------------------------------------------------------------------
// Request / response DTOs.
// ---------------------------------------------------------------------------

/// The wire shape of `POST /v1/stream-g/quotes`, mounted in `super::router`
/// and deserialized by `quotes::post_quote`. (The nested
/// `/v1/stream-g/quotes/sponsored-enrollment` this comment used to name was
/// never mounted; the founder ruling is the flat plural.)
/// Nothing here is trusted as authoritative on its own:
/// `quotes::create_sponsored_enrollment_quote` re-derives `actionCoreHash`
/// from these fields, re-verifies both nested bearer signatures against
/// digests it derives itself, and rejects outright every value that
/// `GoatRelayGateway` would hard-revert on (`rootAuthorizationDigestHex`
/// must be zero, `feeAuthorizationMode` must be
/// `AuthorizationMode.EIP2612`, `deadline`/`linkDeadline` must fit
/// `uint48`).
///
/// **Three fields the gateway cares about are absent by design**, because
/// the surest way to satisfy a precondition is to give the caller no way to
/// name the value at all:
/// - `feeRecipient` — the gateway requires `quote.feeRecipient == feeSafe`
///   (brief §2.4); it comes from `EnrollmentQuoteContext::manifest`.
/// - `enrollDigestHex` / `linkDigestHex` — the gateway re-derives both
///   (`GoatRelayGateway.sol:355-363`) and reverts `InvalidV1Enrollment` /
///   `BadLinkSignature` on any disagreement. They used to be accepted here
///   and copied verbatim into the signed `actionCoreHash` while the server
///   independently derived the real values and discarded them, so a client
///   whose digest was computed against (say) a stale `linkDeadline` got a
///   signed quote, a burnt idempotency key and a guaranteed on-chain
///   revert. Now derived server-side only.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSponsoredEnrollmentQuoteRequest {
    pub idempotency_key: String,
    pub intent_id_hex: String,
    pub root_address: String,
    pub controller_address: String,
    pub controller_epoch: u64,
    pub secondary_address: String,
    /// Must be `bytes32(0)` on this path — `GoatRelayGateway.sol:365`
    /// reverts `InvalidFeeFields` otherwise. `quotes.rs` rejects a
    /// non-zero value rather than signing a quote that can only revert.
    pub root_authorization_digest_hex: String,
    /// `StreamGTypes.AuthorizationMode` **ordinal** (`StreamGTypes.sol:12-17`:
    /// `NONE`=0, `EIP2612`=1, `EIP3009`=2, `PRIOR_ALLOWANCE`=3) for the fee
    /// authorization. Must be `EIP2612` = 1: `quotes.rs` validates it in
    /// STEP 1a (`QuoteError::UnsupportedFeeMode`) and
    /// `GoatRelayGateway.sol:395` independently reverts `UnsupportedFeeMode`
    /// at execution.
    ///
    /// This value is **not** checked by `token_manifest::assert_token_authorized`,
    /// which never reads it: that gate tests the *token's* `capability_mask`
    /// against the `CAP_*` **bitmask** (`StreamGTypes.sol:29-32`), an
    /// independent numbering scheme from these ordinals — exactly the
    /// conflation `token_manifest`'s module doc warns about under
    /// "`CAP_*` bits vs `AuthorizationMode` ordinals: independent numbering".
    /// A token authorized for `CAP_EIP2612` says nothing about what mode this
    /// request asked for.
    pub fee_authorization_mode: u8,
    /// Decimal `u128` string — the intent's `maxFee` ceiling (brief §2.4:
    /// `quote.feeAmount <= maxFee`).
    pub max_fee: String,
    pub nonce: u64,
    /// `SponsorEnrollmentCore.deadline` — `uint48` on-chain
    /// (`StreamGTypes.sol:137`). Range-checked by `quotes.rs`; dirty high
    /// bits would make the signed `actionCoreHash` unreproducible by any
    /// conforming intent.
    pub deadline: u64,
    /// Requested quote lifetime; server clamps to a TTL policy (see
    /// `quotes::QUOTE_TTL_SECONDS_MAX`) the same way
    /// `root_authorization.rs` clamps `deadline`.
    pub valid_for_seconds: u64,
    /// V1Enrollment bearer signature (`StreamGTypes.V1Enrollment`), signed
    /// by `secondary` off a fresh `secondaryEnrollmentNonceSnapshot` read.
    pub v1_nonce: u64,
    pub v1_deadline: u64,
    pub v1_signature_hex: String,
    /// LinkSecondary bearer signature ([`LinkSecondary`]), also signed by
    /// `secondary` off the same snapshot.
    pub link_nonce: u64,
    /// `LinkSecondary.deadline` — `uint48` on-chain
    /// (`StreamGTypes.sol:191`), range-checked by `quotes.rs` for the same
    /// reason as [`CreateSponsoredEnrollmentQuoteRequest::deadline`].
    pub link_deadline: u64,
    pub link_signature_hex: String,
    /// Native-exposure gate inputs (`base_fee::quote_exposure`) — a
    /// ceiling on gas units and unsigned-tx size, plus the caller's
    /// observed `maxFeePerGas`. NEVER used to compute `fee_amount` (see
    /// `quotes.rs` module doc's tariff/exposure separation).
    pub gas_unit_ceiling: u64,
    pub max_fee_per_gas_wei: String,
    pub unsigned_size_ceiling: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct QuoteResult {
    pub quote_id_hex: String,
    pub action_type_hex: String,
    pub action_core_hash_hex: String,
    pub deployment_manifest_hash_hex: String,
    pub fee_token_config_hash_hex: String,
    pub fee_schedule_hash_hex: String,
    pub payer: String,
    pub fee_token: String,
    /// Decimal `u128` string.
    pub fee_amount: String,
    pub fee_recipient: String,
    pub valid_after: u64,
    pub valid_until: u64,
    pub quote_signature_hex: String,
}

// ---------------------------------------------------------------------------
// Task 6b independent-verifier follow-up, Task 2 — structural tripwire.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    /// Structural tripwire mirroring
    /// `token_manifest::tests::trusted_chain_has_no_release_build_conversion_from_an_arbitrary_chain_client`,
    /// for the OTHER half of the same hazard: the property that
    /// [`super::LiveEnrollmentNonces::read_live`] takes a `TrustedChain`,
    /// not a bare `&dyn ChainClient`.
    ///
    /// The independent verifier compiled the following in a **non-test**
    /// build before this task, proving the hazard was real:
    ///
    /// ```text
    /// pub fn __probe_nonces_from_mock() -> Result<LiveEnrollmentNonces, LiveNoncesError> {
    ///     let m = crate::chain::MockChain::new();
    ///     LiveEnrollmentNonces::read_live(&m, [0u8;20], [0u8;20], [0u8;20], [0u8;20], 1)
    /// }
    /// ```
    ///
    /// That probe function was written, confirmed to compile with `cargo
    /// check --lib` (no `cfg(test)`), and then deleted as part of this
    /// task's own verification — see the task report, not this repo, for
    /// the transcript. This test exists so that a *future* regression back
    /// to `&dyn ChainClient` fails loudly here instead of requiring another
    /// manual probe.
    ///
    /// This cannot be proven by a runtime assertion — the property is the
    /// *absence* of a code path, which only the compiler enforces (a
    /// non-test build rejects `LiveEnrollmentNonces::read_live(&MockChain::new(), ..)`
    /// with `the trait bound TrustedChain<'_>: From<&MockChain> is not
    /// satisfied`). What this test does is scan this file's own raw source
    /// so that reverting `read_live`'s signature back to `&dyn ChainClient`
    /// fails loudly here, in the same file, rather than requiring another
    /// hand-run probe. Best-effort by construction: it is a source scan,
    /// not a parse, and would not catch an equivalent open constructor added
    /// under a different name. Needles are assembled at runtime from
    /// fragments so this test's own source does not satisfy the scan it
    /// performs (same discipline as the `token_manifest.rs` sibling test).
    #[test]
    fn live_enrollment_nonces_read_live_takes_a_trusted_chain_not_a_bare_chain_client() {
        let src = include_str!("models.rs");

        let new_sig_marker: String = ["chain: impl Into<Trust", "edChain<'c>>,"].concat();
        assert!(
            src.contains(&new_sig_marker),
            "LiveEnrollmentNonces::read_live must take `impl Into<TrustedChain<'c>>`, exactly \
             as token_manifest::read_live_token_state does — a bare `&dyn ChainClient` lets \
             crate::chain::MockChain (pub, not cfg(test)) supply the enrollment nonces in a \
             release build, defeating the anti-TOCTOU binding this type exists to support \
             (quotes.rs STEP 0, sourcing contract R3)"
        );

        let old_sig_marker: String = ["chain: &dyn cra", "te::chain::ChainClient,"].concat();
        assert!(
            !src.contains(&old_sig_marker),
            "models.rs must not declare any production live-chain constructor taking a bare \
             `&dyn ChainClient` — that is precisely the hazard this test exists to catch"
        );
    }
}
