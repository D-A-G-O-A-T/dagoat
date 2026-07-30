//! Sponsored-enrollment **submit** path — Stream G, Task 6b Wave C.
//!
//! `preflight.rs` answers "would this call revert?". This module answers
//! "may the attestor broadcast it, and what happened when it did?" — the
//! reservation, revalidation, leasing, broadcast, classification and
//! reconciliation around one `GoatRelayGateway.executeSponsoredEnrollment`.
//!
//! ## Hazard 2 — what is closed here, and what is not
//!
//! All three mechanisms the augmented brief §4.2 requires exist in this
//! module and are tested:
//!
//! 1. **Submit-side nonce reservation.** [`submit_sponsored_enrollment`]
//!    claims the on-chain action nonce exclusively in `nonce_allocations`
//!    under that table's `UNIQUE (chain_id, signer_address, nonce)`
//!    (`migrations/0001_stream_g.sql:157-166`), inside `write_tx`'s
//!    `BEGIN IMMEDIATE`. A second submit that would sign against the same
//!    `actionNonces[controller][ACTION_SPONSORED_ENROLLMENT]` is refused
//!    with [`SubmitError::NonceAlreadyReserved`] before it can reach the
//!    broadcaster. **Task 8 Wave B (Mandate 1): that transaction is no
//!    longer written here.** This module had its own copy of it —
//!    `reserve_action_nonce` — which claimed the nonce but wrote no
//!    `raw_tx_enc`/`raw_tx_hash`, so the rows the *production* path created
//!    were exactly the ones [`super::outbox::sweep_stuck_reservations`] could
//!    not resolve. The copy is deleted; this module calls
//!    [`super::outbox::reserve_and_persist_raw_tx`], the crate's only
//!    reservation, and every invariant listed above is enforced there.
//! 2. **Revalidation across both confirmations.** The submit path takes a
//!    *fresh* [`preflight::read_live_preflight_state`] at a newly pinned
//!    block and re-runs the whole of
//!    [`preflight::preflight_sponsored_enrollment`] against it. Both
//!    confirmations this call depends on — `_enrollV1OrAcceptFrontRun`'s
//!    `EnrollmentRegistry.nonces(secondary)` and `linkSecondary`'s
//!    `linkNonces(secondary)` — come from the same single
//!    `secondaryEnrollmentNonceSnapshot` call (sourcing contract R3) and are
//!    both re-checked, as are `controller`, `controllerEpoch` and the
//!    gateway action nonce. 🔴 **Wave C W3 changed how the quote half of
//!    that closure works.** It used to be a field-by-field comparison of the
//!    caller's inline quote against [`QuoteCommitment`]; the caller no longer
//!    sends a quote at all, so the quote is **reconstructed** from the sealed
//!    row ([`QuoteCommitment::to_fee_quote`]) and preflight re-derives its
//!    EIP-712 digest server-side, recovers the sealed signature against
//!    `manifest.quote_signer`, and re-checks the sealed validity window
//!    against the pinned block's clock. The chain is still closed end to end
//!    — stored quote ≡ signed intent ≡ live chain state — and it is now
//!    closed by cryptography rather than by `==`. The full accounting, one
//!    row per comparison the deleted `bind_call_to_commitment` performed, is
//!    on [`SubmitSponsoredEnrollmentRequest`].
//! 3. **Process-local signing lease.** [`SigningLeaseRegistry`] hands out an
//!    RAII [`SigningLease`] keyed by
//!    `(chainId, controller, actionType, actionNonce)`. It is acquired as
//!    the very first thing `submit_sponsored_enrollment` does — before any
//!    store read, chain read or reservation — and released on drop, so the
//!    whole revalidate → reserve → broadcast sequence for one nonce is
//!    serialized within the process even though the store's reservation row
//!    is only written part-way through it.
//!
//! **Hazard 2 is nevertheless NOT fully closed, and nothing here claims it
//! is.** `GoatRelayGateway.sol:199` labels the snapshot "advisory same-state
//! nonce snapshot (not execution authority)" and `_snapshot`'s own comment
//! says it "never consumes nonces/intents": it reserves nothing **on
//! chain**. Another party can therefore consume the same action nonce
//! between this module's revalidation read and the transaction's inclusion,
//! and no client-side mechanism can prevent that. What the three mechanisms
//! above close is the half that is ours: this attestor can no longer
//! broadcast against a nonce it has not revalidated at submit time, and two
//! in-process submits can no longer sign against the same reserved nonce.
//! The residual external race is *handled*, not prevented — `BadActionNonce`
//! is classified [`Retryability::Retryable`] so the caller can re-quote (see
//! [`OnChainRevert`]) once the reservation has been resolved.
//!
//! ## 🔴 Wave C W2 — this path no longer releases an action nonce at all
//!
//! Task 7 Wave C made the release *conditional* on
//! [`BroadcastError::tx_hash`]: `None` (nothing that could execute left this
//! process) released, `Some(h)` (a signed transaction may be live) held.
//!
//! [`submit_sponsored_enrollment`] now delegates the entire chain-touching
//! half to [`super::broadcaster::sign_persist_and_broadcast`], and
//! [`super::broadcaster::BroadcastOutcome`] **has no `tx_hash: None` shape**:
//! once bytes are signed the only two answers it gives are "a node took it"
//! and "we do not know". `as_broadcast_error`'s doc states that as
//! deliberate. So the releasing half is gone from this module — `record_failed`
//! is deleted — and every send failure is:
//!
//! | outcome | Row | Nonce | Classification |
//! |---|---|---|---|
//! | `Accepted` | `submitted`, `tx_hash` set | held | [`SubmitReceipt`] |
//! | `UnresolvedWithKnownHash` | `reserved`, `raw_tx_hash` + `intent_id_hex` + `lease_until` set | **held** | [`SubmitError::BroadcastUnresolved`] → [`Retryability::Ambiguous`] |
//!
//! Releasing is now exclusively
//! [`super::outbox::sweep_stuck_reservations`]' job, on chain evidence
//! (founder ruling F2). **Disclosed cost:** a client that would previously
//! have re-quoted within seconds of a refused send now waits for that sweep,
//! which cannot fire before the row's `lease_until` expires
//! ([`super::outbox::DEFAULT_LEASE_TTL_SECONDS`] seconds). That is the safe
//! direction — releasing under a live transaction is the 6b double-submit —
//! but it is a product decision and the API's retry guidance has to say so.
//!
//! The **broadcaster EOA** nonce is a different counter and is still released
//! on the two provably-safe paths (signing failed, or the reservation was
//! refused before any send), by `broadcaster.rs` rather than here.
//!
//! ## Revert names are the real ones
//!
//! There is no `StaleNonce` error anywhere in `contracts/src/`. The three
//! nonce-adjacent reverts, each read out of the Solidity directly:
//!
//! | Error | Declared | Raised | Class |
//! |---|---|---|---|
//! | `BadActionNonce` | `GoatRelayGateway.sol:34` | `:320` (`_markIntentAndNonce`) | retryable |
//! | `EpochMismatch` | `GoatRelayGateway.sol:48` | `:353` | terminal |
//! | `InvalidRootAuthorization` | `WalletSponsorshipRegistry.sol:26` | `:192` (`link.nonce != linkNonces[link.secondary]`) | ambiguous |
//!
//! `InvalidRootAuthorization` is deliberately **not** classified retryable:
//! `linkSecondary` raises that same selector from six distinct sites
//! (`WalletSponsorshipRegistry.sol:190`, `:192`, `:199`, `:200`, `:202`,
//! `:215`), including `link.secondary == link.root` and the whole
//! root-not-yet-registered branch, and a 4-byte selector cannot tell them
//! apart. Calling it retryable would produce a resubmit loop against a
//! permanently failing precondition; calling it terminal would stop a caller
//! whose only problem is a consumed link nonce. It is
//! [`Retryability::Ambiguous`] — re-run preflight against fresh state to find
//! out which precondition actually failed.
//!
//! ## Effects ordering the caller must expect
//!
//! `GoatRelayGateway.sol:404-420`, in order: `_markIntentAndNonce`
//! (the only place `intentUsed[intentId]` is consumed) →
//! `_enrollV1OrAcceptFrontRun` (tolerates a front-run) →
//! `sponsorship.linkSecondary` → **fee collected last** on the token path →
//! `SponsoredEnrollmentExecuted`. A successful fee collection therefore
//! implies the enrollment already succeeded, which is why reconciliation
//! keys on that event and not on a balance delta:
//! [`reconcile_sponsored_enrollment_executed`].
//!
//! ## What this module does NOT do
//!
//! - **It does not encode calldata, sign, allocate an EOA nonce, gate
//!   exposure, reserve, or send.** 🔴 Wave C W2 moved all six into
//!   [`super::broadcaster::sign_persist_and_broadcast`], whose production
//!   signer ([`super::broadcaster::RpcChainEnrollmentSigner`]) already
//!   exists. The seam this module keeps is
//!   [`super::broadcaster::SponsoredEnrollmentTxSigner`] — the key half only
//!   — and the local `SponsoredEnrollmentBroadcaster` trait, which had no
//!   production implementor anywhere in `src/` and could not correctly have
//!   one (its `sign_sponsored_enrollment(gateway, call)` took no transaction
//!   nonce), is **deleted**. What remains here is the lease, the quote
//!   reconstruction, the revalidation, and the classification of the outcome.
//! - **It does not accept a quote from the caller.** 🔴 Wave C W3.
//!   [`SubmitSponsoredEnrollmentRequest`] has no quote block and no
//!   `quote_signature_hex`, and [`SubmitCallParts`] — the type
//!   [`submit_sponsored_enrollment`] takes — has no field for either. Both
//!   are produced here from the sealed `quotes` row. That is what makes the
//!   deleted `bind_call_to_commitment` unnecessary rather than merely
//!   removed: there is no second copy of the quote to disagree with the
//!   sealed one.
//! - **It never queries `authorizations` by `intent_id`.** That table holds
//!   two undiscriminated row kinds (the issuer-signed `root_authorization`
//!   row and `quotes.rs`'s nested-bearer row) with no column telling them
//!   apart, so `SELECT … WHERE intent_id = ?` returns both. Everything this
//!   module needs is reachable from `intents` and `quotes` by deterministic
//!   id instead. For the same reason it does **not** transition
//!   `authorization_slots` — those rows hang off an `authorizations.id` this
//!   module cannot unambiguously identify; leaving them `'reserved'` is
//!   disclosed rather than guessed at.
//! - **It never looks an intent up by binding `intent_id_hex` directly.**
//!   `intents.id` is `deterministic_id(["stream_g_sponsored_enrollment_intent",
//!   profile_id, intent_id_hex])` (defect C2); [`intent_row_id`] is the only
//!   way this module addresses that row.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use thiserror::Error;

use super::base_fee::{BaseFeeError, WeiCeiling};
use super::crypto_store::{self, CryptoStoreError, DataKey, EnvelopeAad, SecretHex};
use super::broadcaster::{
    self, BroadcastOutcome, BroadcastPlan, BroadcasterError, SponsoredEnrollmentTxSigner,
};
use super::http_error::{ApiError, ApiJson};
use super::models::{ActionType, FeeQuote, LinkSecondary};
// 🔴 Wave C W2. `outbox`'s *functions* are no longer called from this
// module's production code — `broadcaster::sign_persist_and_broadcast` calls
// them now — so only the two items `submit_error_from_outbox` and the
// `BroadcastPlan` need are imported here. The test module re-imports the rest
// (`outbox::self`, `SignedRawTx`, `ReservationRequest`) for the fixtures that
// still drive the reservation directly.
use super::outbox::{OutboxError, DEFAULT_LEASE_TTL_SECONDS};
use super::preflight::{
    self, Check, Disposition, Eip2612Authorization, PreflightError, RootAuthorization,
    SponsorEnrollment, SponsoredEnrollmentCall, UnverifiedCheck, V1Enrollment,
};
use super::profile_auth::{AuthenticatedProfile, AuthenticatedProfileId};
use super::runtime::StreamGState;
use super::store::{StreamGStore, StreamGStoreError};
use super::token_manifest::{DeploymentManifest, TrustedChain};
use crate::chain::TxHash;

// ---------------------------------------------------------------------------
// Error codes (stable strings for logs / HTTP mapping).
// ---------------------------------------------------------------------------

pub const ERR_SUBMIT_STORE: &str = "SUBMIT_STORE_ERROR";
pub const ERR_SUBMIT_CRYPTO: &str = "SUBMIT_CRYPTO_ERROR";
pub const ERR_SUBMIT_MALFORMED_PAYLOAD: &str = "SUBMIT_MALFORMED_PAYLOAD";
pub const ERR_SUBMIT_INTENT_NOT_FOUND: &str = "SUBMIT_INTENT_NOT_FOUND";
pub const ERR_SUBMIT_QUOTE_NOT_FOUND: &str = "SUBMIT_QUOTE_NOT_FOUND";
/// 🔴 Wave C W3. Replaces `SUBMIT_QUOTE_BINDING_MISMATCH`, which is deleted
/// along with the function that raised it.
///
/// That code meant "the quote you posted is not the quote we signed", and it
/// is unrepresentable now: [`SubmitSponsoredEnrollmentRequest`] has no quote
/// field, so there is nothing to disagree. The equivalent refusal is
/// `PREFLIGHT_WOULD_REVERT` carrying `Check::FeeQuoteHashMismatch` or
/// `Check::BadQuoteSignature` — see [`SubmitSponsoredEnrollmentRequest`]'s
/// accounting table.
///
/// This code means something narrower and strictly caller-side: a request
/// field is not the hex/decimal shape it is declared as.
pub const ERR_SUBMIT_MALFORMED_REQUEST: &str = "SUBMIT_MALFORMED_REQUEST";
pub const ERR_SUBMIT_NOT_RELAYABLE: &str = "SUBMIT_NOT_RELAYABLE";
pub const ERR_SUBMIT_SIGNING_LEASE_HELD: &str = "SUBMIT_SIGNING_LEASE_HELD";
pub const ERR_SUBMIT_NONCE_ALREADY_RESERVED: &str = "SUBMIT_NONCE_ALREADY_RESERVED";
pub const ERR_SUBMIT_ALREADY_SUBMITTED: &str = "SUBMIT_ALREADY_SUBMITTED";
pub const ERR_SUBMIT_IN_FLIGHT: &str = "SUBMIT_IN_FLIGHT";
pub const ERR_SUBMIT_REVERTED: &str = "SUBMIT_REVERTED";
pub const ERR_SUBMIT_BROADCAST_FAILED: &str = "SUBMIT_BROADCAST_FAILED";
/// Distinct from [`ERR_SUBMIT_BROADCAST_FAILED`] on purpose (brief §5.3): a
/// receipt timeout is **outcome unknown**, and a client must never be told
/// "no fee was charged" on the strength of it.
pub const ERR_SUBMIT_BROADCAST_UNRESOLVED: &str = "SUBMIT_BROADCAST_UNRESOLVED";
pub const ERR_SUBMIT_RECONCILE_MISMATCH: &str = "SUBMIT_RECONCILE_MISMATCH";
/// Task 7 Wave D. Distinct from [`ERR_SUBMIT_RECONCILE_MISMATCH`], which says
/// "this event describes a *different* transaction than the one on file".
/// This one says "the row on file names **no** transaction at all, so the
/// event cannot be attributed to it either way" — the state a `reserved` row
/// is in by construction (`tx_hash` is written only by
/// `outbox::record_broadcast_accepted`).
pub const ERR_SUBMIT_RECONCILE_UNVERIFIABLE: &str = "SUBMIT_RECONCILE_UNVERIFIABLE";
pub const ERR_SUBMIT_NONCE_OUT_OF_RANGE: &str = "SUBMIT_NONCE_OUT_OF_RANGE";

// ---------------------------------------------------------------------------
// Row-id domains and status vocabularies.
// ---------------------------------------------------------------------------

/// Must stay byte-identical to `quotes.rs`'s `INTENT_ROW_ID_DOMAIN` — it is
/// the same row. See [`intent_row_id`].
const INTENT_ROW_ID_DOMAIN: &str = "stream_g_sponsored_enrollment_intent";
const NONCE_ALLOCATION_ID_DOMAIN: &str = "stream_g_action_nonce_allocation";
const TX_ATTEMPT_ID_DOMAIN: &str = "stream_g_sponsored_enrollment_tx_attempt";
const RECONCILIATION_ID_DOMAIN: &str = "stream_g_sponsored_enrollment_reconciliation";

/// `nonce_allocations.status`: the action nonce is claimed by a live
/// attempt. This is the value the `UNIQUE (chain_id, signer_address, nonce)`
/// row must carry for the claim to be exclusive.
pub const NONCE_STATUS_ALLOCATED: &str = "allocated";
/// The attempt that held it failed without consuming the nonce on chain
/// (a revert does not advance `actionNonces`), so the same nonce is
/// reusable by a re-quote.
pub const NONCE_STATUS_RELEASED: &str = "released";
/// Reconciliation observed `SponsoredEnrollmentExecuted`, so
/// `_markIntentAndNonce` really did increment the on-chain nonce.
pub const NONCE_STATUS_CONSUMED: &str = "consumed";

pub const TX_ATTEMPT_STATUS_RESERVED: &str = "reserved";
pub const TX_ATTEMPT_STATUS_SUBMITTED: &str = "submitted";
pub const TX_ATTEMPT_STATUS_CONFIRMED: &str = "confirmed";
pub const TX_ATTEMPT_STATUS_FAILED: &str = "failed";

pub const INTENT_STATUS_SUBMITTED: &str = "submitted";
pub const INTENT_STATUS_EXECUTED: &str = "executed";

/// `reconciliation_events.event_type` for the gateway's own success event.
pub const RECONCILIATION_EVENT_TYPE: &str = "SponsoredEnrollmentExecuted";

// ---------------------------------------------------------------------------
// Small self-contained helpers. Each `stream_g` module keeps its own copies
// by this tree's convention (see `root_authorization.rs`'s module doc).
// ---------------------------------------------------------------------------

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn deterministic_id(parts: &[&str]) -> String {
    hex::encode(Sha256::digest(parts.join("|").as_bytes()))
}

fn address_hex(a: [u8; 20]) -> String {
    format!("0x{}", hex::encode(a))
}

fn bytes32_hex(b: [u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

fn parse_address20(s: &str) -> Option<[u8; 20]> {
    let t = s.trim();
    let h = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if h.len() != 40 {
        return None;
    }
    let b = hex::decode(h).ok()?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&b);
    Some(out)
}

/// `pub(crate)` as of the wave that mounted
/// [`get_enrollment_status`]: that route receives the on-chain `intentId` as a
/// path segment and must turn it into the `[u8; 32]` [`intent_row_id`] takes.
///
/// Widened rather than duplicated on purpose. A second bytes32 parser in a
/// route module would be a second answer to "is this an intent id", and the
/// two would only have to disagree about a `0X` prefix or a trailing space for
/// the route to address a different row than every other reader of this table.
/// The alternative the handler must **not** take is binding the hex string
/// straight into a query — that is defect C2, recorded at [`intent_row_id`]:
/// `intents.id` is a global primary key, so an unnamespaced `intentId`
/// addresses either nobody's row or somebody else's.
///
/// Returns `Option`, not `Result`, matching [`parse_address20`] beside it; the
/// caller chooses the refusal (the route's is
/// [`SubmitError::IntentNotFound`] — see [`get_enrollment_status`]).
pub(crate) fn parse_bytes32(s: &str) -> Option<[u8; 32]> {
    let t = s.trim();
    let h = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if h.len() != 64 {
        return None;
    }
    let b = hex::decode(h).ok()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Some(out)
}

/// `intents.id` for a sponsored-enrollment intent.
///
/// Defect C2: `intents.id` is a **global** `TEXT PRIMARY KEY`
/// (`migrations/0001_stream_g.sql:104-106`), so `quotes.rs` namespaces the
/// caller-supplied on-chain `intentId` per profile before using it as a row
/// id. Binding `intent_id_hex` directly would address the wrong row (or
/// nobody's row) and would resurrect the cross-profile squat this scheme
/// exists to prevent.
pub fn intent_row_id(profile_id: &str, intent_id: [u8; 32]) -> String {
    deterministic_id(&[INTENT_ROW_ID_DOMAIN, profile_id, &bytes32_hex(intent_id)])
}

/// The `nonce_allocations.signer_address` value for one action nonce.
///
/// On chain the counter is `actionNonces[signer][actionType]`
/// (`GoatRelayGateway.sol:320`) — a **two-dimensional** key. The frozen
/// schema has a single `signer_address TEXT` column, so the action type is
/// folded into it. `migrations/0001_stream_g.sql` may not be edited, and a
/// bare controller address would make two different action types collide on
/// one nonce space.
pub fn action_nonce_signer_key(controller: [u8; 20], action: ActionType) -> String {
    format!("{}#{}", address_hex(controller), action.as_str())
}

/// `nonce_allocations.id` for one action nonce.
///
/// `pub` (Task 7): `outbox.rs` addresses the same rows and must derive the id
/// the same way. Duplicating this formula there instead would give the crate
/// two definitions of the same primary key, and a divergence between them
/// would silently split one nonce's exclusion into two independent claims.
pub fn nonce_allocation_row_id(chain_id: u64, signer_key: &str, nonce: u64) -> String {
    deterministic_id(&[
        NONCE_ALLOCATION_ID_DOMAIN,
        &chain_id.to_string(),
        signer_key,
        &nonce.to_string(),
    ])
}

/// `tx_attempts.id` for one (profile, on-chain intentId, attempt number).
///
/// `pub` for the same reason as [`nonce_allocation_row_id`]: `outbox.rs`
/// resolves these rows after a crash and must address exactly the rows this
/// module wrote.
///
/// # Why `attempt_number` is part of the key (architect assumption A4)
///
/// Until Task 7 Wave E this was one row per `(profile, intentId)`, and the
/// retry path *overwrote* it:
///
/// ```sql
/// UPDATE tx_attempts SET nonce_allocation_id = ?, status = ?, error_message = NULL,
///                        tx_hash = NULL, submitted_at = NULL, created_at = ?
///  WHERE id = ?
/// ```
///
/// That destroyed the previous attempt's evidence — its hash, its error, when
/// it was submitted — which made a **gas-bumped replacement** unrepresentable.
/// A replacement is a second transaction with a *different* hash against the
/// *same* EOA nonce, and either one can land. With one mutable row there is
/// nowhere to record that two payloads are outstanding, and after a crash
/// there is nothing left to resolve the survivor against.
///
/// Adding the attempt number to the preimage makes every attempt its own
/// immutable row: prior attempts become terminal, never rewritten.
///
/// # This does not weaken the single-use-intent invariant
///
/// `intentUsed[intentId]` is global and single-use
/// (`GoatRelayGateway.sol:315-323`), so **at most one attempt can ever land**.
/// That invariant is not enforced by the row id — it never was — it is enforced
/// by the reservation refusing to open attempt *N+1* while any attempt for the
/// intent is still live (`outbox::reserve_and_persist_raw_tx`'s `InFlight` /
/// `AlreadySubmitted` scan — since Task 8 Wave B the only such scan in the
/// crate). The row id only decides where an attempt is *recorded*.
///
/// # Disclosed compatibility break
///
/// Attempt 0's id under this deriver differs from the pre-Wave-E value: the
/// preimage gained a `|0` suffix rather than special-casing zero, so there is
/// exactly one rule. Nothing reads a pre-existing row by a *derived* id —
/// `outbox`'s sweeper and `reconcile`'s reverse lookup both select on columns
/// (`status`/`lease_until`, `intent_id_hex`, `intent_id`) — and a legacy row is
/// still found and correctly extended, because `0002` backfilled its
/// `attempt_number` to 0 and the next reservation opens attempt 1 beside it.
pub fn tx_attempt_row_id(profile_id: &str, intent_id: [u8; 32], attempt_number: i64) -> String {
    deterministic_id(&[
        TX_ATTEMPT_ID_DOMAIN,
        profile_id,
        &bytes32_hex(intent_id),
        &attempt_number.to_string(),
    ])
}

// ---------------------------------------------------------------------------
// Retryability + on-chain revert classification.
// ---------------------------------------------------------------------------

/// What a desktop client should do next. This is the whole point of typing
/// the reverts: "re-quote and resubmit" and "stop and tell the user" are
/// very different user experiences, and guessing wrong produces either a
/// resubmit loop against a permanent failure or a dead end the user could
/// have recovered from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retryability {
    /// Nothing was consumed on chain. Obtain a fresh quote (and fresh
    /// user-side signatures wherever the changed value is inside
    /// `actionCoreHash`) and submit again.
    Retryable,
    /// Stop. Surface to the user; do not resubmit automatically.
    Terminal,
    /// The Solidity error is raised from several distinct preconditions and
    /// its 4-byte selector cannot tell them apart. Re-run preflight against
    /// fresh state to find out which one failed before deciding.
    Ambiguous,
}

/// A Solidity `error` the gateway (or the registry it calls) can raise.
///
/// Every variant's name was read out of `contracts/src/` directly; the
/// declaration lines are in [`OnChainRevert::site`]. `Unrecognized` exists
/// because a node can report an error this build has never heard of — it is
/// classified [`Retryability::Terminal`], which is the fail-closed
/// direction: an unknown failure must never drive an automatic retry loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnChainRevert {
    // --- GoatRelayGateway.sol -----------------------------------------
    ZeroAddress,
    NotActivated,
    Paused,
    IntentAlreadyUsed,
    ZeroIntentId,
    BadActionNonce,
    ExpiredDeadline,
    RootNotRegistered,
    ClusterSuspended,
    ConfigHashMismatch,
    TokenNotAuthorized,
    BadSponsorSignature,
    BadQuoteSignature,
    BadLinkSignature,
    BadV1Signature,
    InvalidFeeFields,
    InvalidQuote,
    QuoteAlreadyUsed,
    ControllerMismatch,
    EpochMismatch,
    InvalidV1Enrollment,
    FeeExceedsMax,
    UnsupportedFeeMode,
    // --- WalletSponsorshipRegistry.sol --------------------------------
    ExpiredSignature,
    InvalidRootAuthorization,
    SecondaryAlreadyLinked,
    SecondaryIsRootController,
    NotV1Eligible,
    /// A revert name this build does not know.
    Unrecognized(String),
}

impl OnChainRevert {
    /// Map a decoded Solidity error name onto a variant. Unknown names are
    /// preserved verbatim in [`OnChainRevert::Unrecognized`] rather than
    /// being coerced into the nearest known one.
    pub fn parse(name: &str) -> Self {
        use OnChainRevert::*;
        match name.trim() {
            "ZeroAddress" => ZeroAddress,
            "NotActivated" => NotActivated,
            "Paused" => Paused,
            "IntentAlreadyUsed" => IntentAlreadyUsed,
            "ZeroIntentId" => ZeroIntentId,
            "BadActionNonce" => BadActionNonce,
            "ExpiredDeadline" => ExpiredDeadline,
            "RootNotRegistered" => RootNotRegistered,
            "ClusterSuspended" => ClusterSuspended,
            "ConfigHashMismatch" => ConfigHashMismatch,
            "TokenNotAuthorized" => TokenNotAuthorized,
            "BadSponsorSignature" => BadSponsorSignature,
            "BadQuoteSignature" => BadQuoteSignature,
            "BadLinkSignature" => BadLinkSignature,
            "BadV1Signature" => BadV1Signature,
            "InvalidFeeFields" => InvalidFeeFields,
            "InvalidQuote" => InvalidQuote,
            "QuoteAlreadyUsed" => QuoteAlreadyUsed,
            "ControllerMismatch" => ControllerMismatch,
            "EpochMismatch" => EpochMismatch,
            "InvalidV1Enrollment" => InvalidV1Enrollment,
            "FeeExceedsMax" => FeeExceedsMax,
            "UnsupportedFeeMode" => UnsupportedFeeMode,
            "ExpiredSignature" => ExpiredSignature,
            "InvalidRootAuthorization" => InvalidRootAuthorization,
            "SecondaryAlreadyLinked" => SecondaryAlreadyLinked,
            "SecondaryIsRootController" => SecondaryIsRootController,
            "NotV1Eligible" => NotV1Eligible,
            other => Unrecognized(other.to_string()),
        }
    }

    /// The Solidity name, round-tripping [`OnChainRevert::parse`].
    pub fn name(&self) -> &str {
        use OnChainRevert::*;
        match self {
            ZeroAddress => "ZeroAddress",
            NotActivated => "NotActivated",
            Paused => "Paused",
            IntentAlreadyUsed => "IntentAlreadyUsed",
            ZeroIntentId => "ZeroIntentId",
            BadActionNonce => "BadActionNonce",
            ExpiredDeadline => "ExpiredDeadline",
            RootNotRegistered => "RootNotRegistered",
            ClusterSuspended => "ClusterSuspended",
            ConfigHashMismatch => "ConfigHashMismatch",
            TokenNotAuthorized => "TokenNotAuthorized",
            BadSponsorSignature => "BadSponsorSignature",
            BadQuoteSignature => "BadQuoteSignature",
            BadLinkSignature => "BadLinkSignature",
            BadV1Signature => "BadV1Signature",
            InvalidFeeFields => "InvalidFeeFields",
            InvalidQuote => "InvalidQuote",
            QuoteAlreadyUsed => "QuoteAlreadyUsed",
            ControllerMismatch => "ControllerMismatch",
            EpochMismatch => "EpochMismatch",
            InvalidV1Enrollment => "InvalidV1Enrollment",
            FeeExceedsMax => "FeeExceedsMax",
            UnsupportedFeeMode => "UnsupportedFeeMode",
            ExpiredSignature => "ExpiredSignature",
            InvalidRootAuthorization => "InvalidRootAuthorization",
            SecondaryAlreadyLinked => "SecondaryAlreadyLinked",
            SecondaryIsRootController => "SecondaryIsRootController",
            NotV1Eligible => "NotV1Eligible",
            Unrecognized(s) => s,
        }
    }

    /// `file:line` of the `error` **declaration**, read out of the Solidity.
    pub fn site(&self) -> &'static str {
        use OnChainRevert::*;
        match self {
            ZeroAddress => "GoatRelayGateway.sol:27",
            NotActivated => "GoatRelayGateway.sol:29",
            Paused => "GoatRelayGateway.sol:30",
            IntentAlreadyUsed => "GoatRelayGateway.sol:32",
            ZeroIntentId => "GoatRelayGateway.sol:33",
            BadActionNonce => "GoatRelayGateway.sol:34",
            ExpiredDeadline => "GoatRelayGateway.sol:35",
            RootNotRegistered => "GoatRelayGateway.sol:36",
            ClusterSuspended => "GoatRelayGateway.sol:37",
            ConfigHashMismatch => "GoatRelayGateway.sol:38",
            TokenNotAuthorized => "GoatRelayGateway.sol:39",
            BadSponsorSignature => "GoatRelayGateway.sol:40",
            BadQuoteSignature => "GoatRelayGateway.sol:41",
            BadLinkSignature => "GoatRelayGateway.sol:42",
            BadV1Signature => "GoatRelayGateway.sol:43",
            InvalidFeeFields => "GoatRelayGateway.sol:44",
            InvalidQuote => "GoatRelayGateway.sol:45",
            QuoteAlreadyUsed => "GoatRelayGateway.sol:46",
            ControllerMismatch => "GoatRelayGateway.sol:47",
            EpochMismatch => "GoatRelayGateway.sol:48",
            InvalidV1Enrollment => "GoatRelayGateway.sol:50",
            FeeExceedsMax => "GoatRelayGateway.sol:51",
            UnsupportedFeeMode => "GoatRelayGateway.sol:52",
            ExpiredSignature => "WalletSponsorshipRegistry.sol:25",
            InvalidRootAuthorization => "WalletSponsorshipRegistry.sol:26",
            SecondaryAlreadyLinked => "WalletSponsorshipRegistry.sol:29",
            SecondaryIsRootController => "WalletSponsorshipRegistry.sol:30",
            NotV1Eligible => "WalletSponsorshipRegistry.sol:31",
            Unrecognized(_) => "unknown",
        }
    }

    /// What the caller should do. See the module doc's table for the three
    /// nonce-adjacent cases, which are the ones that matter.
    pub fn retryability(&self) -> Retryability {
        use OnChainRevert::*;
        match self {
            // Nothing consumed on chain; the state that failed is expected
            // to move on its own or with a fresh quote.
            //
            // `BadActionNonce` is the hazard-2 case: `_markIntentAndNonce`
            // reverts BEFORE `intentUsed[intentId] = true`
            // (`GoatRelayGateway.sol:319-322`), so neither the intent nor
            // the nonce is burned and a re-quote at the new nonce is the
            // correct response.
            BadActionNonce | ExpiredDeadline | ExpiredSignature | Paused | NotActivated => {
                Retryability::Retryable
            }

            // `EpochMismatch` (`:353`) means `controllerEpoch` moved — i.e.
            // the cluster deliberately rotated its controller. Re-quoting
            // under the new epoch would relay a bundle authorized by a
            // controller the cluster has since replaced, so this stops and
            // goes to the user even though it is mechanically "just" a
            // stale counter.
            EpochMismatch => Retryability::Terminal,

            // Overloaded selector — see module doc.
            InvalidRootAuthorization => Retryability::Ambiguous,

            // Everything else is a permanent property of this bundle, this
            // cluster or this configuration.
            ZeroAddress
            | IntentAlreadyUsed
            | ZeroIntentId
            | RootNotRegistered
            | ClusterSuspended
            | ConfigHashMismatch
            | TokenNotAuthorized
            | BadSponsorSignature
            | BadQuoteSignature
            | BadLinkSignature
            | BadV1Signature
            | InvalidFeeFields
            | InvalidQuote
            | QuoteAlreadyUsed
            | ControllerMismatch
            | InvalidV1Enrollment
            | FeeExceedsMax
            | UnsupportedFeeMode
            | SecondaryAlreadyLinked
            | SecondaryIsRootController
            | NotV1Eligible
            | Unrecognized(_) => Retryability::Terminal,
        }
    }
}

/// A preflight rejection carries strictly more information than a bare
/// revert selector does — preflight knows *which* precondition failed, not
/// just which error the chain would emit. Three checks are therefore
/// classified directly instead of being routed through
/// [`OnChainRevert::parse`], which would otherwise flatten them onto an
/// overloaded name.
fn retryability_for_check(check: Check) -> Retryability {
    match check {
        // Nonce/window drift between quote and submit: re-quote.
        Check::BadActionNonce
        | Check::V1EnrollNonceUnusable
        | Check::LinkNonceMismatch
        | Check::LinkDeadlineExpired
        | Check::ExpiredDeadline
        | Check::QuoteWindow => Retryability::Retryable,
        // Controller/epoch movement: stop, same reasoning as
        // `OnChainRevert::EpochMismatch`.
        Check::EpochMismatch | Check::ControllerMismatch | Check::ControllerUnset => {
            Retryability::Terminal
        }
        other => OnChainRevert::parse(other.revert()).retryability(),
    }
}

// ---------------------------------------------------------------------------
// Broadcaster seam.
// ---------------------------------------------------------------------------

/// Why a broadcast did not produce a *confirmed* transaction.
#[derive(Debug, Clone)]
pub struct BroadcastError {
    /// The Solidity `error` name the node decoded, when it decoded one
    /// (e.g. `"BadActionNonce"`). `None` for failures that are not reverts
    /// at all — transport errors, an EOA nonce problem, a rejected fee.
    pub revert: Option<String>,
    /// The hash of a transaction that **may be live on chain**, when one is
    /// known.
    ///
    /// 🔴 This field is the Task 7 Wave C fix for a latent double-submit
    /// hazard in shipped Task 6b code, and it is the only thing that tells
    /// the two failure shapes apart:
    ///
    /// * `None` — nothing that could execute ever left this process. The
    ///   node rejected the call outright, or the transport died before a
    ///   transaction existed. Nothing was consumed on chain, so the
    ///   reservation is **released** and the caller may re-quote.
    /// * `Some(h)` — a transaction with this hash was signed (and, on the
    ///   [`super::outbox`] path, durably persisted) and may already be
    ///   sitting in a mempool. A 60s receipt timeout is the canonical case:
    ///   `relayer.rs:871-873` says verbatim that such an `Err` "may mean the
    ///   tx was actually broadcast and lands later". Releasing the
    ///   reservation here would let a second transaction be signed against
    ///   an action nonce the first one is still racing for. The nonce is
    ///   **held**, the row keeps `raw_tx_hash` so the sweeper can resolve it
    ///   against chain evidence, and the failure is
    ///   [`Retryability::Ambiguous`], never `Retryable`.
    ///
    /// A broadcaster that has already signed a raw transaction must therefore
    /// never report `tx_hash: None` — the hash of a signed payload is
    /// `keccak256` of the exact bytes and is always computable, so "we signed
    /// it but cannot name it" is not a reachable state. See
    /// [`super::broadcaster`], whose every post-signing failure carries the
    /// hash.
    pub tx_hash: Option<TxHash>,
    pub detail: String,
}

impl BroadcastError {
    /// The node decoded a Solidity `error` while simulating/admitting the
    /// call, so no transaction entered a mempool. Nothing is live.
    ///
    /// 🔴 **Wave C W2 disclosure: nothing in this crate calls this, and no
    /// production path can produce the value it builds.** The submit path
    /// now goes through [`super::broadcaster::sign_persist_and_broadcast`],
    /// whose only send seam is `ChainClient::send_raw_transaction` —
    /// `Result<TxHash, ChainError>`, and `ChainError::Msg(String)` carries no
    /// decoded revert name. [`BroadcastOutcome::as_broadcast_error`]
    /// therefore builds every `Some` through [`Self::unresolved`], which
    /// leaves `revert: None`. Consequently
    /// [`SubmitError::Reverted`] is unconstructible on every path a request
    /// can reach, and so are `revert: Some(..)` values generally.
    ///
    /// Kept rather than deleted because the *classification* it feeds
    /// ([`OnChainRevert`] and its `Retryability`) is still the crate's
    /// ground truth about what each gateway revert means, and is what a
    /// future revert-decoding send seam would use. Read
    /// `revert()`/`Reverted` as "not currently produced", not as "produced
    /// and handled".
    pub fn reverted(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            revert: Some(name.into()),
            tx_hash: None,
            detail: detail.into(),
        }
    }

    /// The send failed before any transaction existed — a dial error, a
    /// rejected payload, an unreachable node. Nothing is live.
    pub fn transport(detail: impl Into<String>) -> Self {
        Self {
            revert: None,
            tx_hash: None,
            detail: detail.into(),
        }
    }

    /// A transaction was signed (and possibly accepted) and its hash is
    /// known, but its outcome is not. **This is the branch that must not
    /// release a nonce.**
    pub fn unresolved(tx_hash: TxHash, detail: impl Into<String>) -> Self {
        Self {
            revert: None,
            tx_hash: Some(tx_hash),
            detail: detail.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Process-local signing lease (hazard 2, mechanism 3).
// ---------------------------------------------------------------------------

/// Identity of one on-chain action nonce, as the gateway keys it:
/// `actionNonces[signer][actionType]`, plus the chain it lives on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NonceLeaseKey(String);

impl NonceLeaseKey {
    pub fn new(chain_id: u64, controller: [u8; 20], action: ActionType, nonce: u64) -> Self {
        NonceLeaseKey(format!(
            "{chain_id}|{}|{nonce}",
            action_nonce_signer_key(controller, action)
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// In-process exclusion over action nonces.
///
/// The store's `nonce_allocations` row is the durable claim; this is the
/// *live* one. They are not redundant: the reservation row is only written
/// part-way through a submit, so without this two tasks could both complete
/// revalidation against the same nonce before either reserved it, and the
/// loser would discover the collision only after paying for a full round of
/// chain reads. More importantly the lease is held **across the broadcast**,
/// so a reservation cannot be released and re-taken by another in-process
/// task while a transaction against it is still in flight.
///
/// Deliberately process-local and deliberately named as such. Two
/// `goat-attestor` processes cannot share it — but they cannot share the
/// store either (`StreamGStore::open` takes an exclusive `fs2` instance lock
/// first), so within one store there is exactly one process holding leases.
#[derive(Debug, Default)]
pub struct SigningLeaseRegistry {
    held: Mutex<HashSet<String>>,
}

impl SigningLeaseRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take the lease for `key`, or fail immediately. Never blocks: a
    /// blocking acquire would let a stuck broadcast stall every other
    /// submit for the same controller, and the caller can retry.
    pub fn try_acquire(&self, key: NonceLeaseKey) -> Result<SigningLease<'_>, SubmitError> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        if !held.insert(key.0.clone()) {
            return Err(SubmitError::SigningLeaseHeld { key: key.0.clone() });
        }
        Ok(SigningLease {
            registry: self,
            key: key.0,
        })
    }

    /// Test/introspection helper: is this key currently leased?
    pub fn is_held(&self, key: &NonceLeaseKey) -> bool {
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&key.0)
    }
}

/// RAII lease. Dropping it releases the key — including on an early `?`
/// return or a panic, which is the entire reason this is a guard rather
/// than a pair of `acquire`/`release` calls.
#[derive(Debug)]
pub struct SigningLease<'a> {
    registry: &'a SigningLeaseRegistry,
    key: String,
}

impl SigningLease<'_> {
    pub fn key(&self) -> &str {
        &self.key
    }
}

impl Drop for SigningLease<'_> {
    fn drop(&mut self) {
        self.registry
            .held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
    }
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SubmitError {
    #[error("store error: {0}")]
    Store(#[from] StreamGStoreError),
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoStoreError),
    #[error("preflight rejected the call: {0}")]
    Preflight(#[from] PreflightError),
    #[error("stored payload is malformed: {0}")]
    MalformedPayload(String),
    /// Deliberately raised both when no such intent row exists and when it
    /// exists under a different profile — `root_authorization.rs`'s
    /// litigated posture: an owner check whose failure is distinguishable
    /// from "not found" is an existence oracle.
    #[error("no sponsored-enrollment intent for this profile")]
    IntentNotFound,
    #[error("the intent's quote row is missing")]
    QuoteNotFound,
    /// 🔴 Wave C W3. A request field is not the shape it is declared as.
    ///
    /// Carries the **field name only**, never the offending value. That is
    /// not stylistic: `ApiError`'s `IntoResponse` logs `detail = %self.detail`
    /// for every refusal, and this shape's fields include an intent id and
    /// three ECDSA signatures — spec §9.3 payload bytes. The deleted
    /// `QuoteBindingMismatch` put both signature hexes into its `Display`, and
    /// not repeating that is the reason this variant exists rather than a
    /// reuse of [`SubmitError::MalformedPayload`] (which is 500, and means the
    /// *sealed* payload this process wrote is unreadable).
    #[error("malformed request: {0}")]
    MalformedRequest(String),
    /// `_isDirectEthEnrollment` is true, so `GoatRelayGateway.sol:379`
    /// requires `msg.sender == intent.controller`. A relayer can never
    /// satisfy that.
    #[error("this call is a direct-ETH enrollment; the client must submit it itself")]
    NotRelayable,
    #[error("another in-process submit holds the signing lease for {key}")]
    SigningLeaseHeld { key: String },
    #[error(
        "action nonce {nonce} for {signer} on chain {chain_id} is already reserved by attempt {holder}"
    )]
    NonceAlreadyReserved {
        chain_id: u64,
        signer: String,
        nonce: u64,
        holder: String,
    },
    #[error("this intent was already submitted as {tx_hash_hex}")]
    AlreadySubmitted { tx_hash_hex: String },
    /// A prior attempt reserved but never reached a terminal state — most
    /// likely the process died between the reservation and the broadcast.
    /// Reconciliation must decide before a resubmit is safe.
    #[error("a prior submit for this intent is still in flight (attempt {attempt_id})")]
    SubmitInFlight { attempt_id: String },
    /// 🔴 **Wave C W2: no path in this crate constructs this any more.** See
    /// [`BroadcastError::reverted`] for why — the production send seam
    /// returns a `ChainError` string with no decoded Solidity error name, so
    /// there is nothing to classify. It is retained (with its `code()`,
    /// `status()` and `retryability()` arms) rather than deleted because
    /// [`OnChainRevert`]'s per-revert classification is still the crate's
    /// ground truth and is what a revert-decoding seam would feed. Nothing
    /// here claims a client can receive `SUBMIT_REVERTED` today.
    #[error("transaction reverted {}() ({site}): {detail}", .revert.name())]
    Reverted {
        revert: OnChainRevert,
        site: &'static str,
        detail: String,
    },
    #[error("broadcast failed without a decodable revert: {0}")]
    BroadcastFailed(String),
    /// A transaction was signed and its hash is known, but whether it
    /// executed is not. The action nonce stays **held**; only chain evidence
    /// (`super::outbox::sweep_stuck_reservations`) may resolve it.
    ///
    /// Deliberately not [`SubmitError::BroadcastFailed`]: that variant is
    /// [`Retryability::Retryable`] and releases the reservation, which is
    /// correct only when nothing that could execute ever left this process.
    #[error("broadcast outcome is unknown for {tx_hash_hex}; the nonce stays reserved: {detail}")]
    BroadcastUnresolved { tx_hash_hex: String, detail: String },
    #[error("reconciliation event does not describe the stored intent ({field})")]
    ReconcileMismatch { field: &'static str },
    /// 🔴 Task 7 Wave D — the mis-attribution hole.
    ///
    /// The attempt row named by the event carries **no** `tx_hash`, so there
    /// is nothing to compare the event's hash against. Before this variant
    /// existed the tx-hash guard was *conditional* (`if let Some(stored)`) and
    /// such a row sailed through it: reconcile would stamp it `confirmed`
    /// with whatever hash the caller supplied and mark that row's action nonce
    /// `consumed`. A `reserved` row has `tx_hash NULL` **by construction** —
    /// only `outbox::record_broadcast_accepted` ever writes that column — so
    /// the hole was reachable by exactly the rows the sweeper exists to
    /// service.
    #[error("attempt {attempt_id} names no transaction, so this event cannot be attributed to it ({reason})")]
    ReconcileUnverifiable {
        attempt_id: String,
        reason: &'static str,
    },
    #[error("action nonce {0} does not fit the schema's INTEGER column")]
    NonceOutOfRange(u64),
    /// 🔴 Wave 2 — the native-ETH exposure gate (hazard 1) refused this
    /// submit.
    ///
    /// Raised **after** the transaction is signed and **before**
    /// [`outbox::reserve_and_persist_raw_tx`], so nothing is persisted,
    /// nothing is claimed and nothing is broadcast: the signed bytes are
    /// dropped unreferenced. There is no store cleanup to do on this path
    /// (that is true here and *not* on `broadcaster.rs`'s path, which owns
    /// an EOA nonce by this point and must release it).
    #[error("native exposure gate refused this submit: {0}")]
    NativeExposure(#[source] BaseFeeError),
    /// 🔴 Wave C W2 — the broadcaster path refused, and the refusal has no
    /// pre-existing name in this module.
    ///
    /// [`broadcaster_error_from`] maps **every other**
    /// [`BroadcasterError`] onto the variant this module already raised for
    /// the same store state, so this one carries only the two conditions
    /// that are genuinely new here:
    ///
    /// * [`BroadcasterError::Chain`] — `eth_getTransactionCount` for the
    ///   broadcaster EOA failed, so the nonce frontier is unknown and
    ///   nothing was allocated, signed or sent. Retryable.
    /// * [`BroadcasterError::NonceRowConflict`] — `nonce_allocations` holds
    ///   a non-broadcaster row at the EOA's next nonce. Skipping it would
    ///   gap the account's sequence forever, so it is refused loudly and an
    ///   operator has to look.
    ///
    /// Deliberately delegating [`Self::code`] to
    /// [`BroadcasterError::code`], for the same reason
    /// [`SubmitError::NativeExposure`] delegates to [`BaseFeeError::code`]:
    /// *which* broadcaster rule refused is the operator-facing fact, and a
    /// flat submit-level code would throw it away.
    #[error("the broadcaster refused this submit: {0}")]
    Broadcaster(#[source] BroadcasterError),
}

impl SubmitError {
    pub fn code(&self) -> &'static str {
        match self {
            SubmitError::Store(_) | SubmitError::Sqlx(_) => ERR_SUBMIT_STORE,
            SubmitError::Crypto(_) => ERR_SUBMIT_CRYPTO,
            SubmitError::Preflight(e) => e.code(),
            SubmitError::MalformedPayload(_) => ERR_SUBMIT_MALFORMED_PAYLOAD,
            SubmitError::IntentNotFound => ERR_SUBMIT_INTENT_NOT_FOUND,
            SubmitError::QuoteNotFound => ERR_SUBMIT_QUOTE_NOT_FOUND,
            SubmitError::MalformedRequest(_) => ERR_SUBMIT_MALFORMED_REQUEST,
            SubmitError::NotRelayable => ERR_SUBMIT_NOT_RELAYABLE,
            SubmitError::SigningLeaseHeld { .. } => ERR_SUBMIT_SIGNING_LEASE_HELD,
            SubmitError::NonceAlreadyReserved { .. } => ERR_SUBMIT_NONCE_ALREADY_RESERVED,
            SubmitError::AlreadySubmitted { .. } => ERR_SUBMIT_ALREADY_SUBMITTED,
            SubmitError::SubmitInFlight { .. } => ERR_SUBMIT_IN_FLIGHT,
            SubmitError::Reverted { .. } => ERR_SUBMIT_REVERTED,
            SubmitError::BroadcastFailed(_) => ERR_SUBMIT_BROADCAST_FAILED,
            SubmitError::BroadcastUnresolved { .. } => ERR_SUBMIT_BROADCAST_UNRESOLVED,
            SubmitError::ReconcileMismatch { .. } => ERR_SUBMIT_RECONCILE_MISMATCH,
            SubmitError::ReconcileUnverifiable { .. } => ERR_SUBMIT_RECONCILE_UNVERIFIABLE,
            SubmitError::NonceOutOfRange(_) => ERR_SUBMIT_NONCE_OUT_OF_RANGE,
            // Delegated deliberately: the operator-facing fact is *which*
            // exposure rule refused (`EXPOSURE_EXCEEDS_SCHEDULE` reads very
            // differently from `EXPOSURE_OVERFLOW`), and inventing one flat
            // submit-level code here would throw that away.
            SubmitError::NativeExposure(e) => e.code(),
            // Same delegation, same reason — see the variant's doc.
            SubmitError::Broadcaster(e) => e.code(),
        }
    }

    /// What the client should do. This is the value a desktop UI branches
    /// on; the string code is for logs.
    pub fn retryability(&self) -> Retryability {
        match self {
            // Transient, nothing consumed.
            SubmitError::Store(_)
            | SubmitError::Sqlx(_)
            | SubmitError::SigningLeaseHeld { .. }
            | SubmitError::BroadcastFailed(_) => Retryability::Retryable,

            SubmitError::Reverted { revert, .. } => revert.retryability(),

            SubmitError::Preflight(e) => match e {
                // A failed chain read says nothing about the call.
                PreflightError::ChainRead { .. } => Retryability::Retryable,
                PreflightError::WouldRevert { check, .. } => retryability_for_check(*check),
                _ => Retryability::Terminal,
            },

            // Someone else holds the nonce, or a prior attempt is unresolved:
            // both need an external decision (reconciliation / the other
            // attempt finishing) before anything can be retried.
            SubmitError::NonceAlreadyReserved { .. } | SubmitError::SubmitInFlight { .. } => {
                Retryability::Ambiguous
            }

            // 🔴 The 6b fix. A known transaction hash means a transaction
            // that could still execute exists; the caller must NOT be told
            // to re-quote (that is what `Retryable` means and what would
            // double-submit the action nonce), and must NOT be told it
            // failed. Reconciliation against chain evidence decides.
            SubmitError::BroadcastUnresolved { .. } => Retryability::Ambiguous,

            // Task 7 Wave D. Explicitly `Ambiguous`, NOT the `_` arm's
            // `Terminal`: the row was refused because we cannot say whether
            // the event belongs to it, and "terminal" would read as "this
            // attempt is over", which is the one thing the refusal does not
            // establish. The reservation is untouched and still held.
            SubmitError::ReconcileUnverifiable { .. } => Retryability::Ambiguous,

            // 🔴 Wave 2. An EXPLICIT arm, not the `_` below: this variant is
            // new and letting the catch-all classify it would have been a
            // decision made by omission. The two halves need opposite
            // answers, which is exactly why one blanket arm is wrong.
            SubmitError::NativeExposure(e) => match e {
                // A failed `GasPriceOracle` eth_call says nothing about the
                // call itself — the same posture as
                // `PreflightError::ChainRead` two arms up. Nothing was
                // reserved, persisted or sent, so a retry is free and is the
                // only thing that can succeed once the node answers.
                BaseFeeError::Chain(_) => Retryability::Retryable,
                // The reserve genuinely exceeds the configured ceiling (or
                // the inputs are degenerate). Retrying the identical call
                // against the identical ceiling produces the identical
                // refusal; an operator has to raise the ceiling or the
                // client has to re-quote smaller.
                BaseFeeError::ExposureExceedsSchedule { .. }
                | BaseFeeError::ExposureOverflow
                | BaseFeeError::TxSizeOverflow(_)
                | BaseFeeError::ZeroGasUnits
                | BaseFeeError::ZeroTxSizeCeiling
                | BaseFeeError::EmptyTransaction => Retryability::Terminal,
            },

            // 🔴 Wave C W2. Also an EXPLICIT arm rather than the catch-all,
            // and for the same reason: the two conditions this variant
            // carries need opposite answers. A failed
            // `eth_getTransactionCount` says nothing about the call — the
            // allocation fails closed, so nothing was allocated, signed,
            // persisted or sent and a retry is free. A nonce-row conflict
            // is a store state only an operator can clear.
            SubmitError::Broadcaster(e) => match e {
                BroadcasterError::Chain(_) => Retryability::Retryable,
                BroadcasterError::NonceRowConflict { .. }
                | BroadcasterError::Store(_)
                | BroadcasterError::Sqlx(_)
                | BroadcasterError::Outbox(_)
                | BroadcasterError::OutOfRange(_)
                | BroadcasterError::Signing(_)
                | BroadcasterError::NativeExposure(_) => Retryability::Terminal,
            },

            _ => Retryability::Terminal,
        }
    }

    /// HTTP status for the shared Stream G error envelope
    /// (`super::http_error`). Wildcard-free on purpose — see
    /// [`super::base_fee::BaseFeeError::status`]; both [`Self::code`] and
    /// [`Self::retryability`] above end in `_ =>` arms and therefore do not
    /// have that property.
    ///
    /// [`SubmitError::IntentNotFound`] is **404, never 403** — its own doc
    /// records that "no such intent" and "someone else's intent" are
    /// deliberately the same value, and the HTTP mapping must not re-open
    /// that. See the ownership-oracle rule in `super::http_error`.
    ///
    /// # Why [`SubmitError::BroadcastUnresolved`] is 409 and not 502
    ///
    /// A 5xx invites a client (and every retrying proxy between it and here)
    /// to resend. This variant means a signed transaction *whose hash is
    /// known* may still execute, and the action nonce stays held —
    /// [`Retryability::Ambiguous`], not `Retryable`. `CONFLICT` is the status
    /// whose ordinary reading ("the resource is in a state your request
    /// cannot be applied to") matches that, and it keeps the resend pressure
    /// off a nonce only reconciliation may release.
    pub fn status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            SubmitError::Store(_)
            | SubmitError::Sqlx(_)
            | SubmitError::Crypto(_)
            // The sealed payload this process wrote failed to open or parse.
            | SubmitError::MalformedPayload(_)
            // An action nonce that does not fit the schema's INTEGER column
            // is this build's limit, not a request value.
            | SubmitError::NonceOutOfRange(_) => StatusCode::INTERNAL_SERVER_ERROR,

            SubmitError::Preflight(e) => e.status(),
            SubmitError::NativeExposure(e) => e.status(),

            SubmitError::IntentNotFound | SubmitError::QuoteNotFound => StatusCode::NOT_FOUND,

            // 🔴 Wave C W3. 400, not 422: the body is not the declared shape
            // at all (a field is not hex, or not a decimal integer), which is
            // the condition `BAD_REQUEST` names. 422 is for a body that
            // deserialized and was then refused by a rule — the two arms
            // below.
            SubmitError::MalformedRequest(_) => StatusCode::BAD_REQUEST,

            // Well-formed, refused by a rule or by the chain.
            SubmitError::NotRelayable | SubmitError::Reverted { .. } => {
                StatusCode::UNPROCESSABLE_ENTITY
            }

            // Some other attempt, or an unresolved earlier one, owns state
            // this request needs. None of these may be resolved by resending.
            SubmitError::SigningLeaseHeld { .. }
            | SubmitError::NonceAlreadyReserved { .. }
            | SubmitError::AlreadySubmitted { .. }
            | SubmitError::SubmitInFlight { .. }
            | SubmitError::BroadcastUnresolved { .. }
            | SubmitError::ReconcileMismatch { .. }
            | SubmitError::ReconcileUnverifiable { .. } => StatusCode::CONFLICT,

            // The node refused the send outright, with no decodable revert
            // and no transaction hash: nothing left this process that could
            // execute.
            SubmitError::BroadcastFailed(_) => StatusCode::BAD_GATEWAY,

            // 🔴 Wave C W2. Wildcard-free like the rest of this function, so
            // a new `BroadcasterError` variant fails to compile here rather
            // than acquiring a status by omission.
            SubmitError::Broadcaster(e) => match e {
                // An upstream node did not answer a read this process needs.
                BroadcasterError::Chain(_) => StatusCode::BAD_GATEWAY,
                // Store state a request cannot be applied to.
                BroadcasterError::NonceRowConflict { .. } => StatusCode::CONFLICT,
                // Not produced by `broadcaster_error_from`, which maps each
                // of these onto a variant above. Reaching here means the
                // mapping grew a hole, which is this process's fault.
                BroadcasterError::Store(_)
                | BroadcasterError::Sqlx(_)
                | BroadcasterError::Outbox(_)
                | BroadcasterError::OutOfRange(_)
                | BroadcasterError::Signing(_)
                | BroadcasterError::NativeExposure(_) => StatusCode::INTERNAL_SERVER_ERROR,
            },
        }
    }

    /// The classified revert, when the failure came from the chain.
    pub fn revert(&self) -> Option<&OnChainRevert> {
        match self {
            SubmitError::Reverted { revert, .. } => Some(revert),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// What the quote committed to.
// ---------------------------------------------------------------------------

/// Deserialization mirror of `quotes.rs`'s private `QuotePayload`.
///
/// Only the fields this module binds against are declared; serde ignores the
/// rest. If `quotes.rs` ever renames one of these keys the `open` here fails
/// closed with a missing-field error rather than silently binding nothing —
/// and [`tests::stored_payload_field_names_match_quotes_rs`] turns that
/// runtime failure into a compile-time-ish test failure.
#[derive(Debug, Deserialize)]
struct StoredQuoteView {
    profile_id: String,
    quote_id_hex: String,
    action_core_hash_hex: String,
    deployment_manifest_hash_hex: String,
    fee_token_config_hash_hex: String,
    fee_schedule_hash_hex: String,
    payer_hex: String,
    fee_token_hex: String,
    fee_amount: String,
    fee_recipient_hex: String,
    valid_after: u64,
    valid_until: u64,
    quote_signature_hex: String,
}

/// Deserialization mirror of `quotes.rs`'s private `EnrollmentIntentPayload`.
#[derive(Debug, Deserialize)]
struct StoredIntentView {
    intent_id_hex: String,
    profile_id: String,
    quote_id_hex: String,
    action_core_hash_hex: String,
}

/// The keys [`StoredQuoteView`] requires of `quotes.rs`'s `QuotePayload`.
pub const QUOTE_PAYLOAD_REQUIRED_KEYS: &[&str] = &[
    "profile_id",
    "quote_id_hex",
    "action_core_hash_hex",
    "deployment_manifest_hash_hex",
    "fee_token_config_hash_hex",
    "fee_schedule_hash_hex",
    "payer_hex",
    "fee_token_hex",
    "fee_amount",
    "fee_recipient_hex",
    "valid_after",
    "valid_until",
    "quote_signature_hex",
];

/// The keys [`StoredIntentView`] requires of `quotes.rs`'s
/// `EnrollmentIntentPayload`.
pub const INTENT_PAYLOAD_REQUIRED_KEYS: &[&str] = &[
    "intent_id_hex",
    "profile_id",
    "quote_id_hex",
    "action_core_hash_hex",
];

/// The quote this attestor signed and stored, as the submit path must
/// re-verify the incoming call against it.
///
/// Fields are private and the only production constructor is
/// [`load_quote_commitment`], which opens the sealed `intents` and `quotes`
/// rows inside one transaction. A caller cannot hand the submit path a
/// commitment it assembled from the request body — which would turn every
/// binding check below into `x == x`, the same defect class the
/// `LiveTokenReading` / `LiveEnrollmentNonces` newtypes exist to prevent.
#[derive(Debug, Clone)]
pub struct QuoteCommitment {
    intent_row_id: String,
    quote_row_id: String,
    profile_id: String,
    intent_id: [u8; 32],
    quote_id: [u8; 32],
    action_core_hash: [u8; 32],
    deployment_manifest_hash: [u8; 32],
    fee_token_config_hash: [u8; 32],
    fee_schedule_hash: [u8; 32],
    payer: [u8; 20],
    fee_token: [u8; 20],
    fee_recipient: [u8; 20],
    fee_amount: u128,
    valid_after: u64,
    valid_until: u64,
    quote_signature_hex: String,
}

impl QuoteCommitment {
    pub fn intent_row_id(&self) -> &str {
        &self.intent_row_id
    }
    pub fn quote_row_id(&self) -> &str {
        &self.quote_row_id
    }
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
    pub fn intent_id(&self) -> [u8; 32] {
        self.intent_id
    }
    pub fn quote_id(&self) -> [u8; 32] {
        self.quote_id
    }
    pub fn action_core_hash(&self) -> [u8; 32] {
        self.action_core_hash
    }
    pub fn fee_amount(&self) -> u128 {
        self.fee_amount
    }
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }

    /// The quote signature this attestor sealed. `0x`-prefixed hex, exactly
    /// the bytes `quotes.rs` wrote — never normalised here, because it is
    /// about to be re-verified against a digest rather than string-compared.
    pub fn quote_signature_hex(&self) -> &str {
        &self.quote_signature_hex
    }

    /// 🔴 Wave C W3. Rebuild the [`FeeQuote`] this attestor signed **from
    /// sealed state alone** — no request field participates.
    ///
    /// Eleven of the twelve `FeeQuote` fields come from this commitment,
    /// which [`load_quote_commitment`] opened out of the sealed `quotes`
    /// envelope inside one transaction. The twelfth, `action_type`, is
    /// deliberately **not** read from that envelope even though
    /// `quotes.rs`'s `QuotePayload` carries an `action_type_hex`: it is
    /// pinned to `ActionType::SponsoredEnrollment` here.
    ///
    /// Two reasons, both load-bearing:
    ///
    /// 1. *Fail-closed either way.* If a sealed envelope somehow named a
    ///    different action type, pinning it produces a different
    ///    `models::fee_quote_digest` than the one the quote signer signed —
    ///    so [`Check::BadQuoteSignature`] refuses, and
    ///    [`Check::FeeQuoteHashMismatch`] refuses independently because the
    ///    controller's `intent.feeQuoteHash` commits to the real digest.
    ///    Reading the field could only ever make this path *accept* a quote
    ///    issued for another action.
    /// 2. *No migration risk.* Adding `action_type_hex` to `StoredQuoteView` /
    ///    [`QUOTE_PAYLOAD_REQUIRED_KEYS`] would make every envelope written
    ///    before that change fail to deserialize —
    ///    [`SubmitError::MalformedPayload`], a 500 — for no gain, since this
    ///    route only ever executes `executeSponsoredEnrollment`.
    pub fn to_fee_quote(&self) -> FeeQuote {
        FeeQuote {
            quote_id: self.quote_id,
            action_type: ActionType::SponsoredEnrollment.digest(),
            action_core_hash: self.action_core_hash,
            deployment_manifest_hash: self.deployment_manifest_hash,
            fee_token_config_hash: self.fee_token_config_hash,
            fee_schedule_hash: self.fee_schedule_hash,
            payer: self.payer,
            fee_token: self.fee_token,
            fee_amount: self.fee_amount,
            fee_recipient: self.fee_recipient,
            valid_after: self.valid_after,
            valid_until: self.valid_until,
        }
    }
}

fn need_bytes32(s: &str, field: &'static str) -> Result<[u8; 32], SubmitError> {
    parse_bytes32(s).ok_or_else(|| {
        SubmitError::MalformedPayload(format!("{field} is not a 32-byte hex string: {s}"))
    })
}

fn need_address(s: &str, field: &'static str) -> Result<[u8; 20], SubmitError> {
    parse_address20(s).ok_or_else(|| {
        SubmitError::MalformedPayload(format!("{field} is not a 20-byte hex string: {s}"))
    })
}

/// Open the stored `intents` + `quotes` rows for one (profile, intentId) and
/// return what the quote committed to.
///
/// Both reads happen inside a single `write_tx` — `store.rs:465-481`
/// documents that `read` gives no snapshot isolation, and these two rows
/// must be observed at one point in time or a concurrent supersede could
/// pair an old intent with a new quote.
pub async fn load_quote_commitment(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    profile: &AuthenticatedProfileId,
    intent_id: [u8; 32],
) -> Result<QuoteCommitment, SubmitError> {
    let data_key = DataKey::from_secret(data_key_hex);
    let profile_id = profile.as_str().to_string();
    let intent_row = intent_row_id(&profile_id, intent_id);

    // Store discipline: never call a store method inside its own `write_tx`
    // closure (single-connection pool → PoolTimedOut). Pull the two values
    // `envelope_aad` would have read and build the AAD by hand inside, as
    // `root_authorization.rs:687-688` / `:725-733` do.
    let db_uuid = store.db_uuid().to_string();
    // `envelope_aad_version()`, NOT `schema_version()` — see
    // `StreamGStore::envelope_aad_version`.
    let schema_version = store.envelope_aad_version();

    store
        .write_tx(move |tx| {
            Box::pin(async move {
                let irow = sqlx::query(
                    "SELECT profile_id, quote_id, intent_enc FROM intents WHERE id = ?",
                )
                .bind(&intent_row)
                .fetch_optional(&mut **tx)
                .await?;
                let Some(irow) = irow else {
                    return Err(SubmitError::IntentNotFound);
                };

                let row_profile: String = irow.try_get("profile_id")?;
                if row_profile != profile_id {
                    // Indistinguishable from "no such row" on purpose.
                    return Err(SubmitError::IntentNotFound);
                }
                let quote_row: Option<String> = irow.try_get("quote_id")?;
                let Some(quote_row) = quote_row else {
                    return Err(SubmitError::QuoteNotFound);
                };
                let intent_enc: Vec<u8> = irow.try_get("intent_enc")?;

                let intent_aad = EnvelopeAad {
                    db_uuid: &db_uuid,
                    schema_version,
                    table: "intents",
                    pk: &intent_row,
                    column: "intent_enc",
                };
                let opened = crypto_store::open(&data_key, &intent_aad, &intent_enc)?;
                let stored_intent: StoredIntentView = serde_json::from_slice(&opened)
                    .map_err(|e| SubmitError::MalformedPayload(e.to_string()))?;

                let qrow = sqlx::query("SELECT profile_id, quote_enc FROM quotes WHERE id = ?")
                    .bind(&quote_row)
                    .fetch_optional(&mut **tx)
                    .await?;
                let Some(qrow) = qrow else {
                    return Err(SubmitError::QuoteNotFound);
                };
                let qrow_profile: Option<String> = qrow.try_get("profile_id")?;
                if qrow_profile.as_deref() != Some(profile_id.as_str()) {
                    return Err(SubmitError::IntentNotFound);
                }
                let quote_enc: Vec<u8> = qrow.try_get("quote_enc")?;
                let quote_aad = EnvelopeAad {
                    db_uuid: &db_uuid,
                    schema_version,
                    table: "quotes",
                    pk: &quote_row,
                    column: "quote_enc",
                };
                let opened = crypto_store::open(&data_key, &quote_aad, &quote_enc)?;
                let stored_quote: StoredQuoteView = serde_json::from_slice(&opened)
                    .map_err(|e| SubmitError::MalformedPayload(e.to_string()))?;

                // Belt-and-braces, the same double-check `quotes.rs`'s replay
                // branch applies: the row ids are SHA-256 digests, so without
                // these the ownership claim rests solely on preimage
                // resistance.
                if stored_intent.profile_id != profile_id || stored_quote.profile_id != profile_id {
                    return Err(SubmitError::IntentNotFound);
                }
                if stored_intent.quote_id_hex != stored_quote.quote_id_hex {
                    return Err(SubmitError::MalformedPayload(
                        "intent and quote payloads disagree about quoteId".into(),
                    ));
                }
                if stored_intent.action_core_hash_hex != stored_quote.action_core_hash_hex {
                    return Err(SubmitError::MalformedPayload(
                        "intent and quote payloads disagree about actionCoreHash".into(),
                    ));
                }

                let stored_intent_id = need_bytes32(&stored_intent.intent_id_hex, "intentId")?;
                if stored_intent_id != intent_id {
                    // The row is addressed by a digest of the intentId, so
                    // this can only fire on a hash collision or a corrupted
                    // envelope — but "can only" is not "cannot".
                    return Err(SubmitError::IntentNotFound);
                }

                Ok(QuoteCommitment {
                    intent_row_id: intent_row.clone(),
                    quote_row_id: quote_row.clone(),
                    profile_id: profile_id.clone(),
                    intent_id: stored_intent_id,
                    quote_id: need_bytes32(&stored_quote.quote_id_hex, "quoteId")?,
                    action_core_hash: need_bytes32(
                        &stored_quote.action_core_hash_hex,
                        "actionCoreHash",
                    )?,
                    deployment_manifest_hash: need_bytes32(
                        &stored_quote.deployment_manifest_hash_hex,
                        "deploymentManifestHash",
                    )?,
                    fee_token_config_hash: need_bytes32(
                        &stored_quote.fee_token_config_hash_hex,
                        "feeTokenConfigHash",
                    )?,
                    fee_schedule_hash: need_bytes32(
                        &stored_quote.fee_schedule_hash_hex,
                        "feeScheduleHash",
                    )?,
                    payer: need_address(&stored_quote.payer_hex, "payer")?,
                    fee_token: need_address(&stored_quote.fee_token_hex, "feeToken")?,
                    fee_recipient: need_address(&stored_quote.fee_recipient_hex, "feeRecipient")?,
                    fee_amount: stored_quote
                        .fee_amount
                        .trim()
                        .parse::<u128>()
                        .map_err(|_| {
                            SubmitError::MalformedPayload(format!(
                                "feeAmount is not a u128: {}",
                                stored_quote.fee_amount
                            ))
                        })?,
                    valid_after: stored_quote.valid_after,
                    valid_until: stored_quote.valid_until,
                    quote_signature_hex: stored_quote.quote_signature_hex.clone(),
                })
            })
        })
        .await
}

fn signature_eq(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        let t = s.trim();
        t.strip_prefix("0x")
            .or_else(|| t.strip_prefix("0X"))
            .unwrap_or(t)
            .to_ascii_lowercase()
    };
    norm(a) == norm(b)
}

// ---------------------------------------------------------------------------
// 🔴 Wave C W3 — the wire shape, and where `bind_call_to_commitment` went.
// ---------------------------------------------------------------------------

/// # What `bind_call_to_commitment` did, and where each assurance now lives
///
/// Through Wave C W2 the caller posted the whole ten-argument call, quote
/// included, and a private `bind_call_to_commitment` compared the submitted
/// `FeeQuote` against the sealed one field by field — thirteen comparisons,
/// twelve fields plus the signature. **That function is deleted**, because
/// with the quote no longer on the wire every one of its comparisons would
/// have become `x == x` against a value this module had just produced itself:
/// the exact defect class its own doc warned about.
///
/// The assurance it provided is not dropped, it is **re-established from the
/// sealed side**. Comparison by comparison:
///
/// | old `bind!` | where the assurance comes from now |
/// |---|---|
/// | `intent.intentId` | [`load_quote_commitment`] addresses the row by [`intent_row_id`]`(profile, intent_id)` and then re-checks the sealed payload's own `intent_id_hex` against the id it was asked for. The caller's `intent_id_hex` selects the row; it cannot disagree with it. |
/// | `quote.quoteId` | sealed → [`QuoteCommitment::to_fee_quote`]. Covered on the wire by `Check::FeeQuoteHashMismatch`: `quoteId` is the first field of `fee_quote_struct_hash`, so a different `quoteId` yields a different digest than the controller's signed `intent.feeQuoteHash`. |
/// | `quote.actionCoreHash` | sealed. Independently re-derived from the **intent** by `Check::QuoteActionCoreHashMismatch`, which rebuilds `SponsorEnrollmentCore` from the fifteen intent fields and compares. |
/// | `quote.deploymentManifestHash` | sealed. Re-checked against the **live** `activeManifestHash()` at the pinned block by `Check::ManifestHashMismatch` — strictly stronger than a comparison against our own stored copy. |
/// | `quote.feeTokenConfigHash` | sealed. Re-checked against the live `getTokenConfigHash` by `Check::FeeTokenConfigHashMismatch`. |
/// | `quote.feeScheduleHash` | sealed. Re-checked against the gateway's own `feeScheduleHash` storage word by `Check::FeeScheduleHashMismatch`. |
/// | `quote.payer` | sealed. Re-checked against `intent.controller` by `Check::QuotePayerMismatch`, and `intent.controller` is itself re-checked against the live `controllerOf(root)`. |
/// | `quote.feeToken` | sealed. Re-checked against `intent.feeToken` (and non-zero) by `Check::QuoteFeeTokenMismatch`, and against the token the live state was read for. |
/// | `quote.feeRecipient` | sealed. Re-checked against `manifest.fee_safe` by `Check::QuoteFeeRecipientMismatch`. |
/// | `quote.feeAmount` | sealed. Re-checked non-zero and `<= intent.maxFee` by `Check::ZeroQuoteFeeAmount` / `Check::FeeExceedsMax`, and covered by the digest check below. |
/// | `quote.validAfter` / `quote.validUntil` | sealed. **Re-checked against chain time, not wall clock**: `Check::QuoteWindow` compares them against `state.chain_now`, the timestamp of the block this submit's revalidation was pinned to. This is the check the advisor called out — before W3 it read the *caller's* window, so a quote the quote path had already marked `'expired'` could still be submitted; now it reads the sealed one. |
/// | `quote` (all twelve, as one artifact) | `Check::FeeQuoteHashMismatch` recomputes `fee_quote_digest(reconstructed_quote, chain_id, gateway)` **server-side** and compares it against `intent.feeQuoteHash`, which is caller-supplied but is field 15 of `sponsor_enrollment_struct_hash` and therefore covered by the controller's `sponsor_signature_hex` (verified by preflight's check 20). One equality closes stored quote ≡ intent ≡ live state. |
/// | `quoteSignature` | sealed → the call. `Check::BadQuoteSignature` recovers it against `manifest.quote_signer` over that same recomputed digest — an ECDSA recovery, where the old code did a lowercase string compare. |
///
/// The net effect is that the two comparisons that were doing real work
/// (`feeAmount` drift and a foreign `quoteSignature`) are now enforced by
/// cryptography rather than by `==`, and the ten that could only ever restate
/// a preflight check are gone rather than duplicated.
///
/// # What is on the wire, and what is not
///
/// Absent by design, following `models::CreateSponsoredEnrollmentQuoteRequest`'s
/// rule that the surest way to satisfy a precondition is to give the caller no
/// way to name the value:
///
/// * **the whole `FeeQuote` and its signature** — reconstructed as above;
/// * **`v1Enrollment.wallet`** — must equal `intent.secondary`
///   (`Check::V1WalletMismatch`), and the controller signed
///   `intent.enrollDigest` over it, so a disagreement is caught by
///   `Check::EnrollDigestMismatch` regardless;
/// * **`link.root` / `link.secondary`** — must equal the intent's
///   (`Check::LinkFieldsMismatch`), and are covered by `intent.linkDigest`;
/// * **`feeAuthorization.eip2612.owner` / `.spender`** — must be
///   `intent.controller` and the gateway (`Check::Eip2612FeeFieldsMismatch`);
/// * **the calldata `feeAuthorization.mode`** — must be
///   `AuthorizationMode.EIP2612` on this branch
///   (`Check::FeeAuthorizationModeNotEip2612`); it is taken from
///   [`SubmitSponsoredEnrollmentRequest::fee_authorization_mode`], the same
///   value that goes into the signed intent, so the two cannot disagree.
///
/// Each of those five narrows a preflight check to a tautology **on this
/// route**. That is stated rather than hidden: the checks still discriminate
/// for `preflight_sponsored_enrollment`'s other callers (the direct-ETH
/// envelope builder and the live-node harness), which construct
/// [`SponsoredEnrollmentCall`] directly.
///
/// `root_authorization` and `root_authorization_signature_hex` are
/// `#[serde(default)]`: `GoatRelayGateway` requires all six fields zero and
/// the signature empty on this path (`Check::NonZeroRootAuthorization`), so
/// omitting them is the only correct client behaviour and the default is that
/// value. They remain *declarable* so a caller who sends them explicitly gets
/// the check rather than a `deny_unknown_fields` rejection that would not say
/// why.
///
/// # Size, against `super::STREAM_G_BODY_LIMIT_BYTES` (4096)
///
/// Measured, never hand-computed — `http_error::max_submit_request_json()`
/// builds the document and `super::tests::the_body_limit_clears_the_submit_dto`
/// asserts the byte counts. Worst case means every hex field at full on-chain
/// width (bytes32 → 68 quoted bytes, address → 44, 65-byte signature → 134),
/// every `u128` as a 39-digit decimal string (41 quoted), every `u64` as a
/// 20-digit JSON number.
///
/// | shape | fields | compact | pretty (2-space) |
/// |---|---|---|---|
/// | this DTO, every optional field present | 36 | **2745** | **2890** |
/// | this DTO, `root_authorization_*` omitted (a correct client) | 29 | **2099** | — |
/// | 1:1 mirror of `SponsoredEnrollmentCall`, quote inline, nothing derived | 54 | **4141 ✗** | **4358 ✗** |
///
/// The arithmetic behind 2745, so the shape of the saving is legible: 36
/// keys totalling 696 characters cost `696 + 36×3 = 804` bytes with their
/// quotes and colons; the 36 values total 1904; 35 commas and 2 braces add
/// 37. `804 + 1904 + 37 = 2745`. Omitting the seven `root_authorization_*`
/// fields removes 220 key characters (241 with quoting), 398 value bytes and
/// 7 commas — 646 in all — giving 2099.
///
/// **The last row is why the quote is reconstructed rather than posted.** It
/// does not fit, compact or indented, so that shape could not have shipped
/// without raising the limit. The limit was not raised.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitSponsoredEnrollmentRequest {
    // --- StreamGTypes.SponsorEnrollment, in EIP-712 field order ---------
    pub intent_id_hex: String,
    pub deployment_manifest_hash_hex: String,
    pub fee_token_config_hash_hex: String,
    pub root_address: String,
    pub controller_address: String,
    pub controller_epoch: u64,
    pub secondary_address: String,
    pub enroll_digest_hex: String,
    pub link_digest_hex: String,
    /// Must be `bytes32(0)` on this path — `Check::NonZeroRootAuthorizationDigest`.
    /// Kept on the wire (rather than pinned to zero here) because it is field
    /// 10 of the struct the controller signed: pinning it would let a
    /// `sponsor_signature_hex` over a *non*-zero digest verify against a
    /// rewritten intent.
    pub root_authorization_digest_hex: String,
    pub fee_token_address: String,
    /// `StreamGTypes.AuthorizationMode` **ordinal**, not a `CAP_*` bit. Must
    /// be `EIP2612` = 1 on the sponsored branch. Used for both
    /// `intent.feeAuthorizationMode` and the calldata `feeAuthorization.mode`
    /// — see the type doc.
    pub fee_authorization_mode: u8,
    pub fee_authorization_digest_hex: String,
    /// Decimal `u128` string, matching `CreateSponsoredEnrollmentQuoteRequest`.
    pub max_fee: String,
    /// The quote's **full EIP-712 digest**, not its `quoteId`. This is the one
    /// caller-supplied field the whole reconstruction is validated against —
    /// see the type doc's table.
    pub fee_quote_hash_hex: String,
    pub nonce: u64,
    pub deadline: u64,
    /// The controller's EIP-712 signature over the seventeen fields above.
    pub sponsor_signature_hex: String,

    // --- StreamGTypes.V1Enrollment (`wallet` derived) -------------------
    pub v1_nonce: u64,
    pub v1_deadline: u64,
    pub v1_signature_hex: String,

    // --- StreamGTypes.LinkSecondary (`root`/`secondary` derived) --------
    pub link_nonce: u64,
    pub link_deadline: u64,
    pub link_signature_hex: String,

    // --- TokenAuthorization.eip2612 (`owner`/`spender` derived) ---------
    /// Decimal `u128` string — the permit's `value`.
    pub fee_eip2612_value: String,
    pub fee_eip2612_deadline: u64,
    pub fee_eip2612_v: u8,
    pub fee_eip2612_r_hex: String,
    pub fee_eip2612_s_hex: String,

    // --- StreamGTypes.RootAuthorization — all-zero on this path ---------
    #[serde(default)]
    pub root_authorization_root_address: Option<String>,
    #[serde(default)]
    pub root_authorization_secondary_address: Option<String>,
    #[serde(default)]
    pub root_authorization_enroll_digest_hex: Option<String>,
    #[serde(default)]
    pub root_authorization_link_digest_hex: Option<String>,
    #[serde(default)]
    pub root_authorization_nonce: u64,
    #[serde(default)]
    pub root_authorization_deadline: u64,
    #[serde(default)]
    pub root_authorization_signature_hex: String,
}

/// Everything [`submit_sponsored_enrollment`] needs from the **caller**.
///
/// Deliberately has no `quote` and no `quote_signature_hex` field. That is
/// the type-level half of W3: the submit path cannot be handed a quote
/// because there is nowhere to put one. The [`SponsoredEnrollmentCall`]
/// preflight and the broadcaster see is assembled inside
/// [`submit_sponsored_enrollment`] from these parts plus
/// [`QuoteCommitment::to_fee_quote`].
#[derive(Debug, Clone)]
pub struct SubmitCallParts {
    pub intent: SponsorEnrollment,
    pub v1_enrollment: V1Enrollment,
    pub link: LinkSecondary,
    pub root_authorization: RootAuthorization,
    /// The calldata `TokenAuthorization.mode`, which the gateway checks
    /// independently of `intent.feeAuthorizationMode`
    /// (`Check::FeeAuthorizationModeNotEip2612` vs `Check::UnsupportedFeeMode`).
    ///
    /// A separate field even though
    /// [`SubmitSponsoredEnrollmentRequest::parse`] always fills it from the
    /// same wire value as the intent's: this struct is also built directly by
    /// tests (`tests::a_direct_eth_intent_is_refused_before_anything_is_read`
    /// sets the two to different values), and collapsing it into
    /// `intent.fee_authorization_mode` would make one of the contract's two
    /// checks unrepresentable rather than merely unreachable from the wire.
    pub fee_authorization_mode: u8,
    pub fee_eip2612_authorization: Eip2612Authorization,
    pub sponsor_signature_hex: String,
    pub link_signature_hex: String,
    pub root_authorization_signature_hex: String,
}

impl SubmitCallParts {
    /// Borrow these parts as the ten-argument call, against a quote and
    /// signature the **server** produced.
    ///
    /// The two quote arguments are positional and unlabelled on purpose:
    /// there is exactly one production caller, and it passes
    /// [`QuoteCommitment::to_fee_quote`] and
    /// [`QuoteCommitment::quote_signature_hex`] from the same commitment.
    pub fn with_quote<'a>(
        &'a self,
        quote: &'a FeeQuote,
        quote_signature_hex: &'a str,
    ) -> SponsoredEnrollmentCall<'a> {
        SponsoredEnrollmentCall {
            intent: &self.intent,
            quote,
            v1_enrollment: &self.v1_enrollment,
            link: &self.link,
            root_authorization: &self.root_authorization,
            fee_authorization_mode: self.fee_authorization_mode,
            fee_eip2612_authorization: &self.fee_eip2612_authorization,
            sponsor_signature_hex: &self.sponsor_signature_hex,
            quote_signature_hex,
            link_signature_hex: &self.link_signature_hex,
            root_authorization_signature_hex: &self.root_authorization_signature_hex,
        }
    }
}

/// Note the absent value: the message names the field and stops. See
/// [`SubmitError::MalformedRequest`] for why echoing it would be a leak.
fn need_u128(s: &str, field: &'static str) -> Result<u128, SubmitError> {
    s.trim()
        .parse::<u128>()
        .map_err(|_| SubmitError::MalformedRequest(format!("{field} is not a decimal u128 string")))
}

/// [`need_bytes32`]'s request-side sibling.
///
/// Two functions rather than one because the *source* differs and so must the
/// error: [`need_bytes32`] reads a value this process sealed, and a failure
/// there is [`SubmitError::MalformedPayload`] (500, our fault). This one reads
/// the request body, and a failure is [`SubmitError::MalformedRequest`] (400,
/// the caller's). Both go through [`parse_bytes32`] — the crate's single
/// answer to "is this an intent id" — rather than hand-rolling a second
/// parser, which is how a `0X` prefix or a trailing space ends up meaning two
/// different things in two places.
fn request_bytes32(s: &str, field: &'static str) -> Result<[u8; 32], SubmitError> {
    parse_bytes32(s).ok_or_else(|| {
        SubmitError::MalformedRequest(format!("{field} is not a 32-byte hex string"))
    })
}

fn request_address(s: &str, field: &'static str) -> Result<[u8; 20], SubmitError> {
    parse_address20(s).ok_or_else(|| {
        SubmitError::MalformedRequest(format!("{field} is not a 20-byte hex string"))
    })
}

impl SubmitSponsoredEnrollmentRequest {
    /// Turn the wire shape into [`SubmitCallParts`].
    ///
    /// Parsing only — every *semantic* rule is left to
    /// `preflight_sponsored_enrollment`, so there is one place that decides
    /// whether a call would revert. The errors this can raise are all
    /// [`SubmitError::MalformedRequest`] (400) and none of them echoes a
    /// value back: [`SubmitError::MalformedRequest`]'s `Display` names the
    /// field, never the bytes, because `ApiError`'s `IntoResponse` logs
    /// `detail` and a signature or intent id must not reach an operator log.
    ///
    /// `gateway` is `DeploymentManifest::goat_relay_gateway`, and it is a
    /// parameter rather than a hard-coded zero because the permit's `spender`
    /// is one of the fields this shape deliberately does not accept from the
    /// caller: `Check::Eip2612FeeFieldsMismatch` requires
    /// `spender == address(this)`, so the only correct value is the gateway
    /// the rest of this submit is addressed to. Taking it here keeps the
    /// derived value beside the derivation instead of leaving a placeholder
    /// for a later stage to remember to overwrite.
    pub fn parse(&self, gateway: [u8; 20]) -> Result<SubmitCallParts, SubmitError> {
        let root = request_address(&self.root_address, "root_address")?;
        let secondary = request_address(&self.secondary_address, "secondary_address")?;
        let controller = request_address(&self.controller_address, "controller_address")?;

        let intent = SponsorEnrollment {
            intent_id: request_bytes32(&self.intent_id_hex, "intent_id_hex")?,
            deployment_manifest_hash: request_bytes32(
                &self.deployment_manifest_hash_hex,
                "deployment_manifest_hash_hex",
            )?,
            fee_token_config_hash: request_bytes32(
                &self.fee_token_config_hash_hex,
                "fee_token_config_hash_hex",
            )?,
            root,
            controller,
            controller_epoch: self.controller_epoch,
            secondary,
            enroll_digest: request_bytes32(&self.enroll_digest_hex, "enroll_digest_hex")?,
            link_digest: request_bytes32(&self.link_digest_hex, "link_digest_hex")?,
            root_authorization_digest: request_bytes32(
                &self.root_authorization_digest_hex,
                "root_authorization_digest_hex",
            )?,
            fee_token: request_address(&self.fee_token_address, "fee_token_address")?,
            fee_authorization_mode: self.fee_authorization_mode,
            fee_authorization_digest: request_bytes32(
                &self.fee_authorization_digest_hex,
                "fee_authorization_digest_hex",
            )?,
            max_fee: need_u128(&self.max_fee, "max_fee")?,
            fee_quote_hash: request_bytes32(&self.fee_quote_hash_hex, "fee_quote_hash_hex")?,
            nonce: self.nonce,
            deadline: self.deadline,
        };

        // Derived, not accepted — see the request type's doc.
        let v1_enrollment = V1Enrollment {
            wallet: secondary,
            nonce: self.v1_nonce,
            deadline: self.v1_deadline,
            signature_hex: self.v1_signature_hex.clone(),
        };
        let link = LinkSecondary {
            root,
            secondary,
            nonce: self.link_nonce,
            deadline: self.link_deadline,
        };
        let fee_eip2612_authorization = Eip2612Authorization {
            owner: controller,
            spender: gateway,
            value: need_u128(&self.fee_eip2612_value, "fee_eip2612_value")?,
            deadline: self.fee_eip2612_deadline,
            v: self.fee_eip2612_v,
            r: request_bytes32(&self.fee_eip2612_r_hex, "fee_eip2612_r_hex")?,
            s: request_bytes32(&self.fee_eip2612_s_hex, "fee_eip2612_s_hex")?,
        };

        let root_authorization = RootAuthorization {
            root: self
                .root_authorization_root_address
                .as_deref()
                .map(|s| request_address(s, "root_authorization_root_address"))
                .transpose()?
                .unwrap_or([0u8; 20]),
            secondary: self
                .root_authorization_secondary_address
                .as_deref()
                .map(|s| request_address(s, "root_authorization_secondary_address"))
                .transpose()?
                .unwrap_or([0u8; 20]),
            enroll_digest: self
                .root_authorization_enroll_digest_hex
                .as_deref()
                .map(|s| request_bytes32(s, "root_authorization_enroll_digest_hex"))
                .transpose()?
                .unwrap_or([0u8; 32]),
            link_digest: self
                .root_authorization_link_digest_hex
                .as_deref()
                .map(|s| request_bytes32(s, "root_authorization_link_digest_hex"))
                .transpose()?
                .unwrap_or([0u8; 32]),
            nonce: self.root_authorization_nonce,
            deadline: self.root_authorization_deadline,
        };

        Ok(SubmitCallParts {
            intent,
            v1_enrollment,
            link,
            root_authorization,
            fee_authorization_mode: self.fee_authorization_mode,
            fee_eip2612_authorization,
            sponsor_signature_hex: self.sponsor_signature_hex.clone(),
            link_signature_hex: self.link_signature_hex.clone(),
            root_authorization_signature_hex: self.root_authorization_signature_hex.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Submit.
// ---------------------------------------------------------------------------

/// Everything the submit path needs that is not the call itself.
pub struct SubmitContext<'a> {
    pub store: &'a StreamGStore,
    /// Fail-closed chain-honesty gate — see
    /// [`super::token_manifest::TrustedChain`]. Not `&dyn ChainClient`: the
    /// submit path's revalidation is the last thing standing between a
    /// quote and a broadcast, and every check it makes is a comparison
    /// against something this client said. In a release build the only way
    /// to fill this field is `TrustedChain::live(&RpcChain)`, so
    /// `crate::chain::MockChain` — which is `pub`, not `#[cfg(test)]`, and
    /// can fabricate an authorized token reading in five lines — cannot be
    /// the thing being believed.
    pub chain: TrustedChain<'a>,
    /// 🔴 Wave C W2. Was `&dyn SponsoredEnrollmentBroadcaster` — a
    /// sign-**and**-send seam local to this module, with no production
    /// implementor anywhere in `src/`. This path now delegates the whole
    /// allocate → sign → gate → persist → send sequence to
    /// [`super::broadcaster::sign_persist_and_broadcast`], so the only thing
    /// left for a caller to supply is the key half.
    ///
    /// The EOA address the plan's nonce frontier is built on comes from
    /// [`SponsoredEnrollmentTxSigner::broadcaster_address`] on **this** value
    /// and from nowhere else, which is why there is no second address field
    /// here to disagree with it.
    pub signer: &'a dyn SponsoredEnrollmentTxSigner,
    pub leases: &'a SigningLeaseRegistry,
    pub data_key_hex: &'a SecretHex,
    pub manifest: &'a DeploymentManifest,
    /// Identifies the process/worker taking the reservation claim (spec §9.3
    /// compare-and-swap). Task 8 Wave B: the submit path no longer has a
    /// reservation of its own, so this is the value
    /// [`super::outbox::reserve_and_persist_raw_tx`] stamps on the row and the
    /// value [`super::outbox::record_broadcast_accepted`] compare-and-swaps
    /// against when the send comes back.
    pub claim_owner: &'a str,
    /// Ceiling for the native-ETH exposure gate (hazard 1), enforced
    /// between signing and reservation — see
    /// [`super::base_fee::submit_exposure_for_chain`].
    ///
    /// 🔴 Wave C W2: this module no longer calls that function itself. The
    /// value is copied verbatim into
    /// [`super::broadcaster::BroadcastPlan::max_native_exposure_wei`], and
    /// [`super::broadcaster::sign_persist_and_broadcast`] runs the gate at
    /// the same position (after the bytes exist, before anything is
    /// persisted or sent). The one behavioural difference is disclosed
    /// there: a refusal on that path has an EOA nonce to release, where a
    /// refusal here used to have nothing to clean up.
    /// [`tests::exposure_gate_refuses_between_signing_and_reservation`] is
    /// the pin that the copy actually happens.
    ///
    /// 🔴 **Wave C W4 — this field now has a production source.** It is
    /// [`StreamGState::max_native_exposure_wei`], i.e.
    /// `STREAM_G_MAX_NATIVE_EXPOSURE_WEI`, bound in exactly one place:
    /// [`submit_context`], called by [`post_submit`] and by nothing else. The
    /// remaining constructions of this struct are `#[cfg(test)]`
    /// (`anvil_harness.rs` ×2, `submit.rs` ×1).
    ///
    /// **What that closes, stated narrowly.** A request to
    /// `POST /v1/stream-g/submit` on a live chain that carries the OP-Stack
    /// `GasPriceOracle` predeploy is now gated against an operator-set
    /// ceiling, between signing and reservation. Two residues survive and are
    /// not claims of closure:
    ///
    /// * **chain 31337 enforces no ceiling at all.** The predeploy does not
    ///   exist there, so `base_fee::submit_exposure_for_chain` skips the gate
    ///   rather than failing every submit — see `preflight::UNVERIFIED_CHECKS`'
    ///   exposure entry, which is disclosed on every receipt.
    /// * the config field still defaults to `0`, which admits nothing.
    ///   [`post_submit`] refuses that with
    ///   `http_error::ApiError::exposure_ceiling_unset` (503) rather than
    ///   letting it present as `EXPOSURE_EXCEEDS_SCHEDULE` on every request,
    ///   which is the "surface an unset ceiling as such" obligation the
    ///   earlier waves recorded here.
    pub max_native_exposure_wei: WeiCeiling,
}

/// A broadcast that happened.
#[derive(Debug, Clone)]
pub struct SubmitReceipt {
    pub tx_hash_hex: String,
    pub tx_attempt_id: String,
    pub nonce_allocation_id: String,
    /// The block the *submit-time* revalidation was pinned to. Not the
    /// quote's block — the point of revalidation is that they differ.
    pub revalidated_at_block: u64,
    pub chain_now: u64,
    /// Carried straight through from [`preflight::PreflightReport`] so a
    /// receipt is never read as "this transaction will succeed".
    pub unverified: &'static [UnverifiedCheck],
}

/// 🔴 Wave C W3 — the **wire** shape of a receipt.
///
/// A separate type rather than `#[derive(Serialize)]` on [`SubmitReceipt`],
/// for three reasons that are each a rule this crate already keeps:
///
/// 1. **Internal row ids do not leave the process.** `tx_attempt_id` and
///    `nonce_allocation_id` are `deterministic_id` digests over
///    `(domain, profile_id, intentId, attempt_number)` and
///    `(domain, chain_id, signer_key, nonce)` respectively — primary keys of
///    this attestor's private store, useful to nobody outside it and a
///    cross-profile correlation handle if they were published. The caller
///    already has the two identifiers it needs: the `intentId` it sent, and
///    the transaction hash below.
/// 2. **No raw transaction bytes, ever.** `SubmitReceipt` carries none, and
///    keeping the wire type separate is what stops a later field addition to
///    the domain struct becoming a response field by default.
/// 3. **The disclosure survives, the prose does not.** `unverified` is
///    eleven [`UnverifiedCheck`] records whose `why` fields are multi-line
///    operator prose — roughly 4 KiB of it. Dropping the list entirely would
///    let a 200 be read as "this transaction will succeed", which
///    `preflight`'s module doc forbids; shipping the prose would make the
///    response an order of magnitude larger than the request. So the wire
///    type carries the **count** and the Solidity revert **names**, which are
///    short, stable, and enough for a client to say "eleven preconditions
///    were not evaluated, here they are".
#[derive(Debug, Clone, Serialize)]
pub struct SubmitReceiptResponse {
    /// The hash of the transaction a node accepted. `0x`-prefixed.
    pub tx_hash_hex: String,
    /// The block this submit's revalidation was pinned to.
    pub revalidated_at_block: u64,
    /// `block.timestamp` at that block — the clock every window check above
    /// was decided against.
    pub chain_now: u64,
    /// How many `executeSponsoredEnrollment` preconditions preflight could
    /// **not** evaluate. Never zero in this build; see
    /// `preflight::UNVERIFIED_CHECKS`.
    pub unverified_check_count: usize,
    /// The Solidity `error` names of those preconditions, in
    /// `preflight::UNVERIFIED_CHECKS` order. Names only — the `site` and
    /// `why` fields stay server-side.
    pub unverified_checks: Vec<&'static str>,
}

impl From<SubmitReceipt> for SubmitReceiptResponse {
    fn from(r: SubmitReceipt) -> Self {
        SubmitReceiptResponse {
            tx_hash_hex: r.tx_hash_hex,
            revalidated_at_block: r.revalidated_at_block,
            chain_now: r.chain_now,
            unverified_check_count: r.unverified.len(),
            unverified_checks: r.unverified.iter().map(|u| u.revert).collect(),
        }
    }
}

/// Translate the **one** reservation implementation's error vocabulary into
/// this module's.
///
/// Task 8 Wave B, Mandate 1. `submit::reserve_action_nonce` and
/// [`outbox::reserve_and_persist_raw_tx`] used to be two hand-synchronised
/// copies of the same `BEGIN IMMEDIATE`; the copy in this file is gone and
/// this function is all that is left of it. The mapping is total and
/// semantics-preserving — every arm lands on the variant 6b raised for the
/// same store state, so `code()` and `retryability()` are unchanged:
///
/// | outbox | submit | why |
/// |---|---|---|
/// | `IntentNotFound` | `IntentNotFound` | same non-oracle posture on both sides |
/// | `InFlight` | `SubmitInFlight` | 6b's name for "a live attempt already exists" |
/// | `AlreadySubmitted` | `AlreadySubmitted` | 6b returned this as an `Ok` outcome the caller turned into this error |
/// | `NonceAlreadyReserved` | `NonceAlreadyReserved` | field-for-field |
/// | `OutOfRange` | `NonceOutOfRange` | same `i64` column guard |
/// | `ClaimLost` | `SubmitInFlight` | the row now belongs to another owner; `Ambiguous`, never `Retryable` |
fn submit_error_from_outbox(e: OutboxError) -> SubmitError {
    match e {
        OutboxError::Store(e) => SubmitError::Store(e),
        OutboxError::Sqlx(e) => SubmitError::Sqlx(e),
        OutboxError::Crypto(e) => SubmitError::Crypto(e),
        OutboxError::IntentNotFound => SubmitError::IntentNotFound,
        OutboxError::InFlight { attempt_id } => SubmitError::SubmitInFlight { attempt_id },
        OutboxError::AlreadySubmitted { tx_hash_hex } => {
            SubmitError::AlreadySubmitted { tx_hash_hex }
        }
        OutboxError::NonceAlreadyReserved {
            chain_id,
            signer,
            nonce,
            holder,
        } => SubmitError::NonceAlreadyReserved {
            chain_id,
            signer,
            nonce,
            holder,
        },
        OutboxError::OutOfRange(v) => SubmitError::NonceOutOfRange(v),
        // Deliberately `SubmitInFlight` (→ `Ambiguous`) rather than
        // `BroadcastFailed` (→ `Retryable`): losing the compare-and-swap means
        // some other owner holds this attempt, which is exactly the state a
        // caller must not re-quote against.
        OutboxError::ClaimLost { attempt_id } => SubmitError::SubmitInFlight { attempt_id },
    }
}

/// Revalidate, then hand the whole chain-touching half to
/// [`broadcaster::sign_persist_and_broadcast`], then record.
///
/// Order is load-bearing and is the module doc's hazard-2 story in code:
///
/// 1. **Lease** (before anything else, so the whole sequence for one nonce
///    is serialized in-process).
/// 2. **Reconstruct** — open the sealed `intents` + `quotes` rows for this
///    (profile, intentId) and rebuild the [`FeeQuote`] and its signature from
///    them. 🔴 Wave C W3: this replaced `bind_call_to_commitment`, and the
///    ordering is the point — the reconstruction happens **before** step 3, so
///    the preflight below runs against the *sealed* quote and re-establishes
///    every comparison that function used to make. Reconstructing after
///    preflight would silently lose the expiry check; see
///    [`SubmitSponsoredEnrollmentRequest`]'s accounting table.
/// 3. **Revalidate** — a *fresh* pinned block, a fresh snapshot, a full
///    preflight re-run. `Disposition::ClientMustSubmitDirectly` is an error
///    here: the direct-ETH branch will not accept a relayer —
///    `StreamGEnroll.execute` reverts `NotController` unless
///    `msg.sender == intent.controller`
///    (`contracts/src/libraries/StreamGEnroll.sol:95`).
/// 4. **Broadcast** — one call to [`broadcaster::sign_persist_and_broadcast`],
///    which allocates the broadcaster EOA nonce, signs against exactly that
///    nonce, runs the native-ETH exposure gate (hazard 1), reserves and
///    persists the signed bytes in one `BEGIN IMMEDIATE`, and only then
///    calls `eth_sendRawTransaction`.
/// 5. **Record** — a receipt, or the unresolved stamp.
///
/// ## 🔴 Wave C W2 — this function no longer signs, gates or reserves
///
/// It used to do all three inline, against a `SponsoredEnrollmentBroadcaster`
/// seam local to this file that had **no** production implementor anywhere in
/// `src/`. Everything it did is now done by
/// [`broadcaster::sign_persist_and_broadcast`], which additionally does the
/// one thing this file structurally could not: allocate the broadcaster EOA's
/// **transaction** nonce contiguously before signing. The old seam's
/// signature (`sign_sponsored_enrollment(gateway, call)`) took no transaction
/// nonce, so any implementor of it had to source one itself — which is
/// exactly what [`broadcaster::allocate_broadcaster_nonce`]'s contiguity
/// guarantee forbids, and why that seam could never have been implemented for
/// production without being changed into this one.
///
/// The three things that moved rather than disappeared, each verified by a
/// test in this module rather than asserted here:
///
/// * the exposure gate (`base_fee::submit_exposure_for_chain`) is called at
///   `broadcaster.rs`'s equivalent position, from
///   [`BroadcastPlan::max_native_exposure_wei`], which this function fills
///   from [`SubmitContext::max_native_exposure_wei`] and nothing else;
/// * the reservation is still [`outbox::reserve_and_persist_raw_tx`], reached
///   through [`outbox::reserve_persist_and_send`], with the same
///   [`ReservationRequest`] fields;
/// * the signing failure still claims nothing *of this module's* — the action
///   nonce is untouched and no `tx_attempts` row is opened. What is new is
///   that a broadcaster EOA nonce is allocated and then **released** on that
///   path, which is visible as a `released` `kind='broadcaster'` row.
///
/// ## 🔴 DISCLOSED BEHAVIOUR CHANGE — a send failure no longer releases
///
/// Before this wave, a send failure that carried no transaction hash (the
/// node decoded a revert while admitting the call) hit `record_failed`, which
/// released the action nonce so the client could re-quote immediately.
///
/// [`BroadcastOutcome`] **has no such shape**: once bytes are signed the only
/// two answers it will give are "a node took it" and "we do not know", and
/// `as_broadcast_error` documents that as deliberate. So every send failure
/// now leaves the `tx_attempts` row `reserved` and the action nonce
/// `allocated` until either reconciliation resolves it or
/// [`outbox::sweep_stuck_reservations`] does, which cannot happen before the
/// row's `lease_until` expires — [`DEFAULT_LEASE_TTL_SECONDS`] seconds.
///
/// That is the *safe* direction (releasing a nonce whose transaction may
/// still be live is the 6b double-submit), but it is a product decision, not
/// a free one: a client that would previously have re-quoted in seconds must
/// now wait, and the API's retry guidance has to say so. The classification
/// already carries it — [`Retryability::Ambiguous`], never `Retryable`.
///
/// ## 🔴 Wave C W3 — the caller cannot supply a quote
///
/// The third parameter is [`SubmitCallParts`], which has no `quote` field and
/// no `quote_signature_hex` field. Both are produced here, from sealed state,
/// by [`QuoteCommitment::to_fee_quote`] and
/// [`QuoteCommitment::quote_signature_hex`]. That is a type-level guarantee
/// rather than a convention: there is no way to hand this function a quote.
pub async fn submit_sponsored_enrollment(
    ctx: &SubmitContext<'_>,
    profile: &AuthenticatedProfileId,
    parts: &SubmitCallParts,
) -> Result<SubmitReceipt, SubmitError> {
    let intent = &parts.intent;
    let chain_id = ctx.manifest.chain_id;

    // --- 1. Signing lease. --------------------------------------------
    let lease_key = NonceLeaseKey::new(
        chain_id,
        intent.controller,
        ActionType::SponsoredEnrollment,
        intent.nonce,
    );
    let _lease = ctx.leases.try_acquire(lease_key)?;

    // 🔴 Wave C W3. The direct-ETH refusal, raised HERE rather than being left
    // to fall out of preflight.
    //
    // `GoatRelayGateway` requires `msg.sender == intent.controller` on that
    // branch, so a relayer can never satisfy it — the honest answer is
    // `NotRelayable`, and it is the same answer step 3's disposition check
    // gives. Without this guard the refusal would still happen, but as
    // `Check::DirectEthQuoteNotZeroed`: a direct-ETH intent zeroes
    // `feeQuoteHash`, which no quote this attestor issued can hash to, so the
    // reconstruction below would produce a real (non-zero) quote and preflight
    // would reject it on the *quote* rather than on the branch. That is a
    // confusing error for a correct client on the wrong endpoint, and it costs
    // a store read and a round of chain reads to produce.
    if preflight::is_direct_eth_enrollment(intent) {
        return Err(SubmitError::NotRelayable);
    }

    // --- 2. Reconstruct the quote from sealed state. ------------------
    //
    // Nothing the caller sent participates: `load_quote_commitment` opens the
    // sealed `intents` and `quotes` envelopes for this (profile, intentId)
    // inside one transaction, and `to_fee_quote` rebuilds the twelve-field
    // `FeeQuote` out of them. The caller's `intent_id_hex` chose the row and
    // nothing else.
    let commitment =
        load_quote_commitment(ctx.store, ctx.data_key_hex, profile, intent.intent_id).await?;
    let quote = commitment.to_fee_quote();
    let call = parts.with_quote(&quote, commitment.quote_signature_hex());

    // --- 3. Revalidation at a FRESH block. ----------------------------
    // `read_live_preflight_state` pins `eth_blockNumber` itself, so this is
    // a new pin, not the quote's. Everything the two on-chain confirmations
    // depend on — v1EnrollNonce, linkNonce, controller, controllerEpoch,
    // actionNonce, and the three config hashes — is re-read in that one
    // snapshot call and re-checked by the preflight below.
    let state = preflight::read_live_preflight_state(
        ctx.chain,
        ctx.manifest,
        intent.root,
        intent.secondary,
    )?;
    // 🔴 Wave C W3. `call` here carries the RECONSTRUCTED quote, so this one
    // statement is where all three of the advisor's requirements are met, and
    // all three happen before any outbox reservation:
    //
    // * the EIP-712 digest is **recomputed server-side** and compared against
    //   the controller-signed `intent.feeQuoteHash` (`Check::FeeQuoteHashMismatch`);
    // * the sealed quote signature is **recovered**, not string-compared,
    //   against `manifest.quote_signer` (`Check::BadQuoteSignature`);
    // * the sealed validity window is compared against `state.chain_now` —
    //   the PINNED BLOCK's timestamp, not this process's wall clock
    //   (`Check::QuoteWindow`).
    let report = preflight::preflight_sponsored_enrollment(&call, &state, ctx.manifest)?;
    if report.disposition != Disposition::RelaySponsored {
        return Err(SubmitError::NotRelayable);
    }

    // --- 4. Allocate the EOA nonce, sign against it, gate, persist, send.
    //
    // 🔴 Wave C W2. Everything between "this call is relayable" and "a node
    // has been asked" is one call now. The ordering inside it is
    // `broadcaster.rs`'s and is documented there; what matters at this seam
    // is that all four things this function used to do inline are still
    // done, in the same order, against the same values:
    //
    // * **sign** — against the ALLOCATED transaction nonce, which is the
    //   part this file could not do: the deleted seam's
    //   `sign_sponsored_enrollment(gateway, call)` took no nonce, so any
    //   implementor had to pick one itself, which voids
    //   `allocate_broadcaster_nonce`'s contiguity guarantee;
    // * **gate** — `base_fee::submit_exposure_for_chain`, from
    //   `plan.max_native_exposure_wei` below, after the bytes exist and
    //   before anything is persisted or sent;
    // * **reserve and persist** — `outbox::reserve_and_persist_raw_tx`, the
    //   crate's only reservation, in one `BEGIN IMMEDIATE`, committed before
    //   the send;
    // * **send** — `eth_sendRawTransaction`, and never a receipt wait.
    //
    // `broadcaster` is taken from the signer itself rather than accepted as
    // a second context field: `RpcChainEnrollmentSigner`'s doc requires the
    // plan's address and the signing key to name one account, and
    // `SponsoredEnrollmentTxSigner::broadcaster_address` is what makes the
    // disagreement unconstructible here rather than merely undesirable.
    let plan = BroadcastPlan {
        profile_id: profile.as_str(),
        intent_id: intent.intent_id,
        chain_id,
        gateway: ctx.manifest.goat_relay_gateway,
        broadcaster: ctx.signer.broadcaster_address(),
        controller: intent.controller,
        action: ActionType::SponsoredEnrollment,
        action_nonce: intent.nonce,
        claim_owner: ctx.claim_owner,
        lease_ttl_seconds: DEFAULT_LEASE_TTL_SECONDS,
        // 🔴 Hazard 1. The ONLY source for this field on this path, and the
        // reason the gate survives the re-architecture. A literal, a
        // `Default`, or `WeiCeiling::new(u128::MAX)` here would disarm the
        // gate while leaving every call site looking identical — which is
        // why `exposure_gate_refuses_between_signing_and_reservation` drives
        // a real refusal through this struct rather than asserting on it.
        max_native_exposure_wei: ctx.max_native_exposure_wei,
    };
    let outcome = broadcaster::sign_persist_and_broadcast(
        ctx.store,
        ctx.data_key_hex,
        ctx.chain,
        ctx.signer,
        &plan,
        // 🔴 Wave C W3. The RECONSTRUCTED call — the same value preflight
        // just cleared, so the bytes that get signed encode the quote this
        // attestor sealed and not one a caller named.
        &call,
        now_unix_seconds(),
    )
    .await
    .map_err(broadcaster_error_from)?;

    // --- 5. Record. ---------------------------------------------------
    //
    // Two arms, and that is the whole set. [`BroadcastOutcome`] has no
    // "failed" variant, so the `tx_hash: None` arm this match used to carry
    // — the one that called `record_failed` and RELEASED the action nonce —
    // is unreachable and is not written. See this function's doc for the
    // disclosed consequence of that.
    match outcome {
        BroadcastOutcome::Accepted {
            attempt,
            tx_hash_hex,
            ..
        } => Ok(SubmitReceipt {
            tx_hash_hex,
            tx_attempt_id: attempt.attempt_id,
            nonce_allocation_id: attempt.allocation_id,
            revalidated_at_block: report.block,
            chain_now: report.chain_now,
            unverified: report.unverified,
        }),
        BroadcastOutcome::UnresolvedWithKnownHash {
            attempt,
            raw_tx_hash,
            detail,
            ..
        } => {
            // 🔴 Task 7 Wave C — the 6b double-submit fix, unchanged in
            // substance and now unconditional.
            //
            // A hash means a transaction exists that we cannot prove is
            // dead: `relayer::relay_gas_drip`'s send-failure arm
            // (`relayer.rs:869-871`) states verbatim that such an `Err` "may
            // mean the tx was actually broadcast and lands later". Before
            // that branch existed this fell through to `record_failed` and
            // RELEASED the action nonce while the transaction was still
            // live — so a re-quote would sign a second transaction against
            // the same `actionNonces[controller][action]`, and whichever
            // lost would burn relayer ETH reverting `BadActionNonce` in
            // `StreamGCommon.markIntentAndNonce`
            // (`contracts/src/libraries/StreamGCommon.sol:73`).
            //
            // The row therefore stays `reserved` — the nonce stays
            // `allocated` — with everything `outbox::sweep_stuck_reservations`
            // needs to resolve it from chain evidence.
            //
            // 🔴 W2 AMENDMENT, stated because the comment here used to claim
            // the opposite. This stamp writes the hash of the payload **this
            // process signed**, not one a node reported. `broadcaster.rs`
            // discards the node-reported hash on the one arm that has one
            // (`SendOutcome::BroadcastNotRecorded`'s `tx_hash_hex: _`) and
            // builds both unresolved shapes from `signed.hash()`. The
            // reservation already wrote exactly that value into
            // `raw_tx_hash`, so this statement no longer changes that column
            // at all. What it still contributes — and what the reservation
            // could not — is `error_message` and a refreshed `lease_until`,
            // without which the sweeper's `status='reserved' AND lease_until
            // < now` trigger has nothing to fire on.
            let tx_hash_hex = bytes32_hex(raw_tx_hash);
            record_broadcast_unresolved(
                ctx.store,
                attempt.attempt_id,
                bytes32_hex(intent.intent_id),
                tx_hash_hex.clone(),
                detail.clone(),
                now_unix_seconds().saturating_add(DEFAULT_LEASE_TTL_SECONDS),
            )
            .await?;
            Err(SubmitError::BroadcastUnresolved {
                tx_hash_hex,
                detail,
            })
        }
    }
}

/// Translate [`broadcaster::sign_persist_and_broadcast`]'s error vocabulary
/// into this module's.
///
/// 🔴 Wave C W2, and the sibling of [`submit_error_from_outbox`] — written the
/// same way and for the same reason. Every arm lands on the variant this
/// module already raised for the same store state, so no `code()`, `status()`
/// or `retryability()` a client could already observe changes. Exactly two
/// conditions have no pre-existing name here and get
/// [`SubmitError::Broadcaster`]; see that variant's doc.
///
/// | broadcaster | submit | why |
/// |---|---|---|
/// | `Store` / `Sqlx` | `Store` / `Sqlx` | field-for-field |
/// | `Outbox` | *(delegated to [`submit_error_from_outbox`])* | the reservation's vocabulary is already mapped once; mapping it a second time here is how two copies drift |
/// | `OutOfRange` | `NonceOutOfRange` | same `i64` column guard |
/// | `Signing` | `BroadcastFailed` | the shape the deleted `classify_unbroadcast_failure` produced for a signing failure |
/// | `NativeExposure` | `NativeExposure` | field-for-field, and both delegate `code()` to `BaseFeeError` |
/// | `Chain` | `Broadcaster` | new: the EOA nonce frontier read failed, fail-closed |
/// | `NonceRowConflict` | `Broadcaster` | new: the EOA's nonce row is held by another key space |
fn broadcaster_error_from(e: BroadcasterError) -> SubmitError {
    match e {
        BroadcasterError::Store(e) => SubmitError::Store(e),
        BroadcasterError::Sqlx(e) => SubmitError::Sqlx(e),
        BroadcasterError::Outbox(e) => submit_error_from_outbox(e),
        BroadcasterError::OutOfRange(v) => SubmitError::NonceOutOfRange(v),
        // Deliberately `BroadcastFailed` (→ `Retryable`, 502) rather than
        // `Broadcaster`: this is byte-for-byte the outcome the deleted
        // `classify_unbroadcast_failure` produced for a signing failure.
        // `BroadcastError::transport(..)` carried `revert: None`, so its
        // `None` arm returned `BroadcastFailed(detail)`. The broadcaster has
        // already released the EOA nonce it allocated, nothing was signed,
        // nothing was persisted and nothing was sent, so telling the client
        // to retry is the correct and unchanged answer.
        BroadcasterError::Signing(detail) => SubmitError::BroadcastFailed(detail),
        BroadcasterError::NativeExposure(e) => SubmitError::NativeExposure(e),
        e @ (BroadcasterError::Chain(_) | BroadcasterError::NonceRowConflict { .. }) => {
            SubmitError::Broadcaster(e)
        }
    }
}

/// The broadcast produced a transaction hash but no verdict.
///
/// Writes **no** `nonce_allocations` statement at all — that absence is the
/// fix. What it does write is the evidence the sweeper needs later:
/// `raw_tx_hash` (so `transaction_receipt` can be asked about a transaction
/// this attestor never got a `tx_hash` back for) and `intent_id_hex` (so
/// `intentUsed(intentId)` can be asked at all), plus `lease_until` so
/// `outbox::sweep_stuck_reservations`' trigger
/// (`status='reserved' AND lease_until < now`) eventually fires on the row.
///
/// `status` deliberately stays `reserved` rather than moving to `submitted`:
/// the sweeper only claims `reserved` rows, and "a node acknowledged this"
/// (which is what a non-NULL `tx_hash` means everywhere else in this crate)
/// is precisely the thing we do not know here. `intents.status` is left
/// alone for the same reason.
async fn record_broadcast_unresolved(
    store: &StreamGStore,
    attempt_id: String,
    intent_id_hex: String,
    raw_tx_hash_hex: String,
    detail: String,
    lease_until: i64,
) -> Result<(), SubmitError> {
    store
        .write_tx(move |tx| {
            Box::pin(async move {
                let r = sqlx::query(
                    "UPDATE tx_attempts \
                     SET raw_tx_hash = ?, intent_id_hex = ?, error_message = ?, lease_until = ? \
                     WHERE id = ? AND status = ?",
                )
                .bind(&raw_tx_hash_hex)
                .bind(&intent_id_hex)
                .bind(&detail)
                .bind(lease_until)
                .bind(&attempt_id)
                .bind(TX_ATTEMPT_STATUS_RESERVED)
                .execute(&mut **tx)
                .await?;
                if r.rows_affected() != 1 {
                    // Deliberately NOT an error. The invariant that matters
                    // here — the action nonce is not released — is satisfied
                    // by this function writing nothing at all, and raising a
                    // `SubmitError::Sqlx`/`Store` instead would reclassify
                    // the caller's failure as `Retryable`, i.e. would tell a
                    // client to re-quote against a nonce whose transaction
                    // may still be live. That is the exact hazard this whole
                    // branch exists to prevent.
                    tracing::warn!(
                        attempt_id = %attempt_id,
                        raw_tx_hash = %raw_tx_hash_hex,
                        "stream_g submit: could not stamp the unresolved broadcast onto its \
                         attempt row (it is no longer 'reserved'); the reservation is still \
                         held, but the sweeper may not be able to resolve this transaction"
                    );
                }
                Ok::<(), SubmitError>(())
            })
        })
        .await
}

// ---------------------------------------------------------------------------
// Reconciliation.
// ---------------------------------------------------------------------------

/// `GoatRelayGateway.SponsoredEnrollmentExecuted` (`:88-95`), as observed.
///
/// Reconciliation keys on this event and not on a token-balance delta
/// because of the effects ordering at `:404-420`: the fee is collected
/// **last** on the token path, so an observed fee transfer already implies
/// the enrollment and the link succeeded — while the converse (enrollment
/// without a fee) is unobservable from balances alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SponsoredEnrollmentExecuted {
    pub intent_id: [u8; 32],
    pub root: [u8; 20],
    pub secondary: [u8; 20],
    pub controller: [u8; 20],
    pub fee_token: [u8; 20],
    pub fee_amount: u128,
    pub tx_hash: [u8; 32],
    pub block: u64,
}

#[derive(Debug, Serialize)]
struct ReconciliationDetails {
    intent_id_hex: String,
    root_hex: String,
    secondary_hex: String,
    controller_hex: String,
    fee_token_hex: String,
    fee_amount: String,
    tx_hash_hex: String,
    block: u64,
}

/// Fold an observed `SponsoredEnrollmentExecuted` into the ledger.
///
/// Marks the attempt confirmed, the intent executed, the action nonce
/// **consumed** (`_markIntentAndNonce` really did increment it — this is the
/// one path where the reservation must not be released), and seals a
/// `reconciliation_events` row.
///
/// **Idempotent** (Task 11 Wave D). Folding the same event twice writes the
/// state transitions once: the `tx_attempts` UPDATE carries
/// `AND status != 'confirmed'` and the nonce UPDATE carries
/// `AND status != 'consumed'`, so a replay leaves `confirmed_at` byte-identical
/// and cannot re-consume a slot. This is a precondition of
/// `maintenance::run_reconcile`, whose cursor is advance-on-success-only and
/// therefore re-observes logs by design.
///
/// Deliberately does not touch `authorization_slots`: those rows hang off an
/// `authorizations.id` that cannot be identified unambiguously from
/// `intent_id` alone (two undiscriminated row kinds — see module doc), and
/// guessing would corrupt the other kind's slots.
pub async fn reconcile_sponsored_enrollment_executed(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    profile: &AuthenticatedProfileId,
    event: &SponsoredEnrollmentExecuted,
    now_wall: i64,
) -> Result<String, SubmitError> {
    reconcile_executed_for_profile_id(store, data_key_hex, profile.as_str(), event, now_wall).await
}

/// Same fold as [`reconcile_sponsored_enrollment_executed`], for a caller that
/// **resolved** the profile out of the store instead of authenticating it.
///
/// Task 7 Wave D added this so `reconcile.rs`'s log-driven reconciler is not a
/// second copy of the SQL below. The split is deliberate about authority:
/// [`AuthenticatedProfileId`] is a *proof of possession* and a log follower has
/// no credential to prove — it reads the owner off the `intents` row itself
/// (`reconcile::candidates_for_intent_id`), which is `fulfill`'s litigated
/// model: the intent row, not the caller, is the source of truth for who owns
/// the work. Keeping this `pub(crate)` and untyped-in-the-profile means no
/// HTTP body can ever reach it, because nothing outside this crate can call it
/// at all.
///
/// The ownership check is not lost by the split: `intent_row_id` is
/// `sha256(domain | profile_id | intentId)`, so a wrong `profile_id` addresses
/// a row id that does not exist and the `IntentNotFound` below fires.
///
/// `now_wall` is wall-clock unix seconds, **injected rather than read here**
/// (Task 11 Wave D), matching `reserve_and_persist_raw_tx`,
/// `reconcile::apply_disposition` and every other Stream G write path. It lands
/// in `tx_attempts.confirmed_at` and `reconciliation_events.created_at`. A
/// function that read its own clock could not be tested for the property that
/// matters most about it — that a second fold does **not** rewrite the first
/// fold's timestamp — because two calls a millisecond apart produce the same
/// second.
pub(crate) async fn reconcile_executed_for_profile_id(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    profile_id: &str,
    event: &SponsoredEnrollmentExecuted,
    now_wall: i64,
) -> Result<String, SubmitError> {
    let data_key = DataKey::from_secret(data_key_hex);
    let profile_id = profile_id.to_string();
    // Owned copy: the write closure is `move` and must not borrow `event`.
    let event_intent_id = event.intent_id;
    let intent_row = intent_row_id(&profile_id, event.intent_id);
    let event_row_id = deterministic_id(&[
        RECONCILIATION_ID_DOMAIN,
        &profile_id,
        &bytes32_hex(event.intent_id),
        &bytes32_hex(event.tx_hash),
    ]);

    let details = ReconciliationDetails {
        intent_id_hex: bytes32_hex(event.intent_id),
        root_hex: address_hex(event.root),
        secondary_hex: address_hex(event.secondary),
        controller_hex: address_hex(event.controller),
        fee_token_hex: address_hex(event.fee_token),
        fee_amount: event.fee_amount.to_string(),
        tx_hash_hex: bytes32_hex(event.tx_hash),
        block: event.block,
    };
    let details_bytes =
        serde_json::to_vec(&details).map_err(|e| SubmitError::MalformedPayload(e.to_string()))?;

    let db_uuid = store.db_uuid().to_string();
    // `envelope_aad_version()`, NOT `schema_version()` — see
    // `StreamGStore::envelope_aad_version`.
    let schema_version = store.envelope_aad_version();
    let now = now_wall;
    let tx_hash_hex = bytes32_hex(event.tx_hash);

    store
        .write_tx(move |tx| {
            Box::pin(async move {
                // Wave E (A4): the attempt row id can no longer be DERIVED from
                // (profile, intentId) alone — the attempt number is part of it,
                // and an intent may have several terminal attempts plus at most
                // one live one. The event's transaction hash is what selects
                // among them, which is sound for the same reason the §3.2
                // reverse lookup is: `intentUsed[intentId]` is global and
                // single-use (`GoatRelayGateway.sol:315-323`), so at most one
                // attempt can ever have executed.
                let arows = sqlx::query(
                    "SELECT id, nonce_allocation_id, tx_hash, status, attempt_number \
                     FROM tx_attempts WHERE intent_id = ? ORDER BY attempt_number ASC",
                )
                .bind(&intent_row)
                .fetch_all(&mut **tx)
                .await?;
                if arows.is_empty() {
                    return Err(SubmitError::IntentNotFound);
                }
                // The guard this replaces compared the row's `intent_id` column
                // to `intent_row`; selecting ON that column makes such a check
                // structurally true, i.e. an unkillable assertion (defect I7).
                // The real integrity property is that the row carries the id
                // the canonical deriver produces for its own attempt number —
                // so a row inserted with a hand-made id is refused instead of
                // silently reconciled.
                for arow in &arows {
                    let id: String = arow.try_get("id")?;
                    let number: i64 = arow.try_get("attempt_number")?;
                    if id != tx_attempt_row_id(&profile_id, event_intent_id, number) {
                        return Err(SubmitError::ReconcileMismatch { field: "intent_id" });
                    }
                }
                // 🔴 Task 7 Wave D — the guard is UNCONDITIONAL.
                //
                // It used to be `if let Some(stored) = ...`, which silently
                // exempted every row whose `tx_hash` is NULL. That is not a
                // rare row: `tx_hash` is written in exactly one place
                // (`outbox::record_broadcast_accepted`), so a `reserved` row —
                // the crash /
                // unresolved-broadcast state the whole outbox exists for — has
                // it NULL **by construction** and passed the guard unchecked.
                // Reconcile would then stamp that row `confirmed` with
                // whatever hash the caller supplied and mark ITS action nonce
                // `consumed`, i.e. attribute somebody else's on-chain
                // execution to an intent that never left this process.
                //
                // An independent verifier proved the hole live on 2026-07-25
                // by making this guard unconditional and observing that NO
                // existing test failed. `tests::
                // reconcile_rejects_a_null_tx_hash_row_it_cannot_verify` is
                // the coverage that was missing.
                //
                // The right handoff for a NULL-`tx_hash` row is
                // `outbox::sweep_stuck_reservations`, which resolves it from
                // chain evidence and writes a real `tx_hash` before anything
                // reconciles it (`outbox.rs`'s `Resolution::MinedOurs`).
                //
                // Wave E keeps the guard unconditional and generalises the row
                // selection: the attempt this event confirms is the one whose
                // stored `tx_hash` IS the event's hash. A row with a NULL
                // `tx_hash` can never be that row, so it is skipped here rather
                // than exempted — which is the same refusal, now expressed as
                // "no attempt matches" instead of "the attempt does not match".
                let matched = arows.iter().find(|arow| {
                    arow.try_get::<Option<String>, _>("tx_hash")
                        .ok()
                        .flatten()
                        .is_some_and(|stored| signature_eq(&stored, &tx_hash_hex))
                });
                let Some(arow) = matched else {
                    // Nothing matched. Distinguish "we have no chain evidence
                    // at all for any attempt" (recoverable — hand it to the
                    // sweeper) from "we have evidence and it is for a different
                    // transaction" (a mis-attributed event).
                    let any_hash = arows.iter().any(|r| {
                        r.try_get::<Option<String>, _>("tx_hash")
                            .ok()
                            .flatten()
                            .is_some()
                    });
                    if any_hash {
                        return Err(SubmitError::ReconcileMismatch { field: "tx_hash" });
                    }
                    let last: String = arows
                        .last()
                        .expect("non-empty checked above")
                        .try_get("id")?;
                    return Err(SubmitError::ReconcileUnverifiable {
                        attempt_id: last,
                        reason: "tx_hash is NULL; no node ever acknowledged a transaction for \
                                 this attempt, so chain evidence must resolve it first",
                    });
                };
                let attempt_id: String = arow.try_get("id")?;
                let allocation_id: Option<String> = arow.try_get("nonce_allocation_id")?;

                // 🔴 Task 11 Wave D — this fold is now IDEMPOTENT.
                //
                // They used to have no status predicate at all, which was
                // survivable only while this function had no production caller.
                // `maintenance::run_reconcile` is a POLLING observer: it advances
                // its cursor only after a whole window folds, so re-observing an
                // already-folded log is the NORMAL case, not an edge case. Under
                // the unguarded form every re-observation rewrote `confirmed_at`
                // with a fresh wall clock, silently turning "when this confirmed"
                // into "when we last rescanned" — with no evidence in
                // `reconciliation_events`, whose `INSERT OR IGNORE` is genuinely
                // idempotent and whose comment below used to read as if it
                // covered the whole function. It covers one row.
                //
                // The guard is `status != 'confirmed'` and NOT `status =
                // 'submitted'`: `reconcile::promote_verified_tx_hash` can leave a
                // chain-verified row `submitted`, and the sweeper can leave one
                // `reserved`, and both are legitimately foldable. Only "already
                // confirmed" is the replay we must not re-apply.
                //
                // Missing the row is SUCCESS, not an error: the caller asked for
                // this (intent, tx) to be recorded and it already is. Returning
                // `Err` would make a poller count a healthy replay as a failed
                // pass and retry the same window forever.
                let updated = sqlx::query(
                    "UPDATE tx_attempts SET status = ?, tx_hash = ?, confirmed_at = ? \
                     WHERE id = ? AND status != ?",
                )
                .bind(TX_ATTEMPT_STATUS_CONFIRMED)
                .bind(&tx_hash_hex)
                .bind(now)
                .bind(&attempt_id)
                .bind(TX_ATTEMPT_STATUS_CONFIRMED)
                .execute(&mut **tx)
                .await?;
                // `false` => already `confirmed`, i.e. an idempotent replay of
                // the same event. The two transitions below are skipped; the
                // `INSERT OR IGNORE` at the end still runs, so a row that was
                // confirmed by some other path (e.g.
                // `reconcile::apply_external_fulfillment`) still gains its
                // durable evidence row rather than losing it to an early return.
                let first_fold = updated.rows_affected() == 1;

                if first_fold {
                    sqlx::query("UPDATE intents SET status = ? WHERE id = ?")
                        .bind(INTENT_STATUS_EXECUTED)
                        .bind(&intent_row)
                        .execute(&mut **tx)
                        .await?;
                }

                if let (true, Some(allocation_id)) = (first_fold, allocation_id) {
                    // No `kind` predicate — same reason as `record_failed`'s
                    // release above: `nonce_allocations.id` is domain-separated
                    // per key space, so `WHERE id = ?` cannot reach a
                    // broadcaster row. The id derivation is the load-bearing
                    // invariant; see
                    // `broadcaster::tests::
                    // the_action_and_broadcaster_key_spaces_cannot_alias_one_row_id`.
                    //
                    // `AND status != 'consumed'` is the second half of the
                    // idempotency guard: a replay must not re-consume a slot.
                    //
                    // 🔴 `AND NOT EXISTS (…)` is a DIFFERENT guard, and it is
                    // here because the argument that used to stand in its place
                    // was false. That argument read: a slot that was released
                    // and later re-reserved REUSES this primary key
                    // (`nonce_allocation_row_id` is derived from
                    // `(chain_id, signer_key, nonce)`), so an unguarded UPDATE
                    // could stamp `consumed` on a row now owned by a different
                    // live attempt — but that is unreachable "because a released
                    // row has `tx_hash` NULL, so the `tx_hash` match above
                    // refuses it".
                    //
                    // It is not unreachable. This function's only production
                    // caller is `reconcile::reconcile_executed_log`, and on the
                    // line immediately before it calls this one it calls
                    // `reconcile::promote_verified_tx_hash`, whose entire job is
                    // to FILL that NULL `tx_hash` from the chain. The released
                    // row then matches, the fold proceeds, and the UPDATE
                    // reaches a slot the sweeper has since handed to a live
                    // replacement attempt.
                    //
                    // So the predicate states the property instead of arguing
                    // it: this statement transitions the slot only while no
                    // OTHER attempt holds it in a live status. It is the same
                    // holder test `outbox::reserve_and_persist_raw_tx` runs
                    // before it re-reserves a row, from the other side.
                    //
                    // `h.id != ?` excludes the attempt this fold just confirmed
                    // (it is `confirmed`, i.e. live, by the UPDATE above), or
                    // the guard would refuse every legitimate fold.
                    //
                    // A refusal is NOT an error: the on-chain nonce really was
                    // consumed, so the replacement attempt is already doomed,
                    // and resolving it needs chain evidence this function does
                    // not have. `outbox::sweep_stuck_reservations` is the
                    // component that holds that authority. Refusing here leaves
                    // the row exactly as the sweeper expects to find it, rather
                    // than silently transitioning a claim out from under it.
                    let nonce_update = sqlx::query(
                        "UPDATE nonce_allocations SET status = ? \
                         WHERE id = ? AND status != ? \
                           AND NOT EXISTS ( \
                             SELECT 1 FROM tx_attempts h \
                              WHERE h.nonce_allocation_id = ? \
                                AND h.id != ? \
                                AND h.status IN (?, ?, ?))",
                    )
                    .bind(NONCE_STATUS_CONSUMED)
                    .bind(&allocation_id)
                    .bind(NONCE_STATUS_CONSUMED)
                    .bind(&allocation_id)
                    .bind(&attempt_id)
                    .bind(TX_ATTEMPT_STATUS_RESERVED)
                    .bind(TX_ATTEMPT_STATUS_SUBMITTED)
                    .bind(TX_ATTEMPT_STATUS_CONFIRMED)
                    .execute(&mut **tx)
                    .await?;
                    if nonce_update.rows_affected() != 1 {
                        // Counts only, no ids: this line is on the ordinary log
                        // surface and spec §9.3 keeps row identifiers off it.
                        tracing::warn!(
                            "stream G fold did not stamp an action nonce consumed: the slot is \
                             already consumed, or it is held by another live attempt (released \
                             and re-reserved). Nothing was overwritten; chain evidence via \
                             outbox::sweep_stuck_reservations resolves the holder."
                        );
                    }
                }

                let aad = EnvelopeAad {
                    db_uuid: &db_uuid,
                    schema_version,
                    table: "reconciliation_events",
                    pk: &event_row_id,
                    column: "details_enc",
                };
                let sealed = crypto_store::seal(&data_key, &aad, &details_bytes)?;

                let re = sqlx::query(
                    "INSERT OR IGNORE INTO reconciliation_events \
                     (id, tx_attempt_id, event_type, status, details_enc, created_at) \
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(&event_row_id)
                .bind(&attempt_id)
                .bind(RECONCILIATION_EVENT_TYPE)
                .bind(TX_ATTEMPT_STATUS_CONFIRMED)
                .bind(&sealed)
                .bind(now)
                .execute(&mut **tx)
                .await?;
                // Idempotent: a replayed event for the same (intent, tx) hits
                // the same deterministic id and affects zero rows, which is
                // success, not a conflict.
                let _ = re.rows_affected();

                Ok(event_row_id.clone())
            })
        })
        .await
}

// ---------------------------------------------------------------------------
// `GET /v1/stream-g/status/:intentId` — the enrollment lane's status reader.
// ---------------------------------------------------------------------------

/// One sponsored-enrollment intent as its owner may read it.
///
/// **Why this module and not a shared one.** Founder ruling: this route serves
/// the *enrollment* machine. `super::onboarding::get_intent` is the onboarding
/// lane's reader — it answers `GET /v1/profile/primary-onboarding/:intentId`,
/// its status vocabulary is that module's five `STATE_*` constants, and it
/// knows nothing about `tx_attempts` or `reconciliation_events`. Reusing it
/// here would report an enrollment row through an onboarding-shaped view and,
/// worse, would silently drop [`latest_disposition`](Self::latest_disposition),
/// which is the only field on this view that can say "unknown".
///
/// Before writing this, the store layer was searched for an existing reader of
/// the enrollment `intents` row: the only one is [`load_quote_commitment`],
/// which is a *write-path binding* helper — it opens the sealed `intent_enc`
/// and `quote_enc` envelopes inside a `write_tx` and errors
/// [`SubmitError::QuoteNotFound`] when there is no quote row. Serving a status
/// read through it would decrypt two envelopes to answer a question about one
/// unencrypted `status` column, and would turn a legitimately quoteless intent
/// into a 404 for the wrong reason. Everything else that touches the table
/// (`outbox.rs:434`, `reconcile.rs`'s candidate queries) reads `profile_id`
/// alone, for ownership checks.
///
/// Library return value; the wire shape is [`EnrollmentStatusResponse`].
#[derive(Debug, Clone)]
pub struct EnrollmentIntentView {
    /// The **on-chain** `intentId`, normalized `0x…` — what the caller named,
    /// not `intents.id`. The row id is `intent_row_id(profile, intentId)`, a
    /// per-profile derivation (defect C2) that no caller has any use for.
    pub intent_id_hex: String,
    pub profile_id: String,
    /// `intents.status`. See [`EnrollmentStatusResponse::status`] for the
    /// vocabulary.
    pub status: String,
    pub created_at: i64,
    /// See [`EnrollmentStatusResponse::latest_disposition`].
    pub latest_disposition: Option<String>,
}

/// Read one sponsored-enrollment intent's status, scoped to its owner.
///
/// **Profile-scoped in the `SELECT`, not after it.** `WHERE id = ? AND
/// profile_id = ?` — the same posture as [`load_quote_commitment`]'s
/// `row_profile != profile_id` check and `super::onboarding::get_intent`'s
/// clause: an intent belonging to another profile is `None`, byte-identical to
/// one that does not exist, so this primitive cannot be used as a
/// cross-profile status oracle. `intent_id` is `[u8; 32]` rather than a string
/// for the reason [`parse_bytes32`]'s doc records.
///
/// **`intent_type` is deliberately not in the `WHERE` clause.** An onboarding
/// row is unreachable here without one: this function addresses rows only
/// through [`intent_row_id`], which is
/// `SHA-256("stream_g_sponsored_enrollment_intent" | profile | 0x<intentId>)`,
/// while `onboarding::start_intent` derives its ids from a different domain
/// string and a free-form idempotency key. Naming an onboarding row through
/// this path means producing a bytes32 whose SHA-256 collides with one — so
/// the separation is structural, and adding a filter would only introduce a
/// second copy of the `'sponsored_enrollment'` literal that
/// `quotes::create_sponsored_enrollment_quote_at`'s STEP 7 `write_tx` closure
/// writes, whose drift would 404 every real intent silently.
///
/// **The disposition is the newest `reconciliation_events.status` for any
/// attempt on this intent, passed through verbatim.** Not translated, not
/// bucketed — see [`EnrollmentStatusResponse::latest_disposition`]. Only that
/// one column is read; `details_enc` is a sealed envelope and stays where it
/// is, and `tx_attempts.error_message` is not read either (spec §9.3: no
/// payload bytes leave this crate through a read surface).
///
/// A single statement, so `read`'s documented lack of snapshot isolation
/// (the bullet at `store.rs:951`; `read` itself is `store.rs:969`) cannot
/// straddle the intent row and the subquery.
pub async fn get_enrollment_intent(
    store: &StreamGStore,
    profile: &AuthenticatedProfileId,
    intent_id: [u8; 32],
) -> Result<Option<EnrollmentIntentView>, SubmitError> {
    let profile_id = profile.as_str().to_string();
    let row_id = intent_row_id(&profile_id, intent_id);
    let intent_id_hex = bytes32_hex(intent_id);

    store
        .read(|handle| {
            Box::pin(async move {
                let row = handle
                    .fetch_optional(
                        sqlx::query(
                            "SELECT i.profile_id AS profile_id, i.status AS status, \
                                    i.created_at AS created_at, \
                                    (SELECT r.status FROM reconciliation_events r \
                                       JOIN tx_attempts a ON a.id = r.tx_attempt_id \
                                      WHERE a.intent_id = i.id \
                                      ORDER BY r.created_at DESC, r.id DESC \
                                      LIMIT 1) AS latest_disposition \
                             FROM intents i \
                             WHERE i.id = ? AND i.profile_id = ?",
                        )
                        .bind(&row_id)
                        .bind(&profile_id),
                    )
                    .await?;
                match row {
                    None => Ok::<Option<EnrollmentIntentView>, SubmitError>(None),
                    Some(row) => Ok(Some(EnrollmentIntentView {
                        intent_id_hex,
                        profile_id: row.try_get("profile_id")?,
                        status: row.try_get("status")?,
                        created_at: row.try_get("created_at")?,
                        latest_disposition: row.try_get("latest_disposition")?,
                    })),
                }
            })
        })
        .await
}

/// `GET /v1/stream-g/status/:intentId` response body.
///
/// A separate type from [`EnrollmentIntentView`], differing by one field:
/// `profile_id` is not on the wire. Same founder ruling and same reasoning as
/// `super::onboarding::IntentStatusResponse` — the caller authenticated as the
/// owning profile to get here, so echoing the id back tells it nothing it does
/// not hold while putting one more stable identifier into every intermediary's
/// logs.
///
/// snake_case, matching every other Stream G wire DTO
/// (`super::tests::stream_g_wire_dtos_are_snake_case`).
#[derive(Debug, Clone, Serialize)]
pub struct EnrollmentStatusResponse {
    /// The on-chain `intentId` the caller named, normalized.
    pub intent_id: String,
    /// The **enrollment** state machine, and only it:
    ///
    /// * `pending` — a quote was signed and the intent row written
    ///   (`quotes::create_sponsored_enrollment_quote_at`, STEP 7); nothing has
    ///   been broadcast.
    /// * [`INTENT_STATUS_SUBMITTED`] — a signed transaction was accepted by a
    ///   node (`outbox.rs:710`) or reconciliation re-observed it as in-flight.
    /// * [`INTENT_STATUS_EXECUTED`] — `SponsoredEnrollmentExecuted` was
    ///   observed for it, here or by [`reconcile_sponsored_enrollment_executed`].
    ///
    /// This is **not** the onboarding vocabulary
    /// (`super::onboarding::STATE_FULFILLED` and friends) and the two must not
    /// be merged: they are different machines over different rows.
    pub status: String,
    pub created_at: i64,
    /// The most recent `reconciliation_events.status` recorded against any
    /// attempt for this intent, **verbatim**, or `None` when reconciliation has
    /// concluded nothing yet.
    ///
    /// One of `confirmed` (`submit.rs`'s own success event),
    /// `super::reconcile::DISPOSITION_STATUS_REVERTED`,
    /// `..._DROPPED`, `..._REORGED`, or
    /// [`super::reconcile::DISPOSITION_STATUS_UNKNOWN`].
    ///
    /// # Why there is no mapping table here
    ///
    /// `receipt_timeout_unknown` is [`super::reconcile::AttemptDisposition::ReceiptTimeoutUnknown`]:
    /// no receipt, past the deadline, and nothing the chain said settles it.
    /// Any collapse of it into a `failed`-shaped value would tell a caller
    /// their fee was not collected when that is precisely what is not known —
    /// the opposite of what `mined_revert` licenses, which is the whole reason
    /// `reconcile::AttemptDisposition`'s `StillPending` / `MinedRevert` variants
    /// keep them as separate states with separate
    /// sentences. Passing the recorded string through unaltered is what makes
    /// that impossible to get wrong here: there is no translation to be wrong.
    /// `tests::a_receipt_timeout_reaches_the_status_route_as_unknown_never_failed`
    /// is the pin.
    ///
    /// Note that the *converging* `tx_attempts.status` is not exposed at all.
    /// All three concluding dispositions write `reserved` back to that column
    /// (`reconcile::apply_disposition`), so it cannot distinguish them and
    /// would read as "nothing has happened" for a transaction that reverted.
    pub latest_disposition: Option<String>,
}

impl From<EnrollmentIntentView> for EnrollmentStatusResponse {
    /// Drops `profile_id` deliberately — see [`EnrollmentStatusResponse`].
    fn from(view: EnrollmentIntentView) -> Self {
        Self {
            intent_id: view.intent_id_hex,
            status: view.status,
            created_at: view.created_at,
            latest_disposition: view.latest_disposition,
        }
    }
}

/// Assemble the [`SubmitContext`] `POST /v1/stream-g/submit` runs on, out of
/// process state and nothing else.
///
/// 🔴 **Wave C W4 — this function is where hazard 1 stops being wired and
/// starts being closed**, so it is a named function rather than a struct
/// literal inside [`post_submit`]: every field below is a value a handler
/// could plausibly have invented instead, and inventing any one of them is a
/// silent hole. Two in particular:
///
/// * `max_native_exposure_wei` — the ONLY production source of the ceiling
///   the native-ETH gate enforces. `submit_sponsored_enrollment` copies it
///   verbatim into `broadcaster::BroadcastPlan::max_native_exposure_wei`, and
///   `broadcaster::sign_persist_and_broadcast` hands that to
///   `base_fee::submit_exposure_for_chain`, which is the crate's only
///   non-test call site of the gate. A literal here — or a
///   `WeiCeiling::new(u128::MAX)` — disarms the gate on every request while
///   leaving this call site looking identical, which is exactly the mutation
///   [`tests::the_submit_route_context_carries_the_configured_exposure_ceiling`]
///   detects.
/// * `leases` and `claim_owner` — both must come from `state`, i.e. be
///   per-process and not per-request. A freshly built `SigningLeaseRegistry`
///   would let two concurrent submits sign against one action nonce
///   ([`StreamGState::leases`]); a freshly minted claim owner would leave
///   every row this request reserved un-releasable by this process
///   ([`StreamGState::claim_owner`]).
///
/// `signer` is a parameter rather than built here because
/// [`broadcaster::RpcChainEnrollmentSigner`] borrows the `RpcChain` and the
/// context borrows the signer, so the handler must own it for the duration of
/// the call.
fn submit_context<'a>(
    state: &'a StreamGState,
    chain: TrustedChain<'a>,
    signer: &'a dyn SponsoredEnrollmentTxSigner,
) -> SubmitContext<'a> {
    SubmitContext {
        store: state.store(),
        chain,
        signer,
        leases: state.leases(),
        data_key_hex: state.data_key_hex(),
        manifest: state.manifest(),
        claim_owner: state.claim_owner(),
        max_native_exposure_wei: state.max_native_exposure_wei(),
    }
}

/// `POST /v1/stream-g/submit` — broadcast one sponsored enrollment.
///
/// 🔴 **Wave C W4. This is the crate's first route that can cause a chain
/// write**, and the first production caller of
/// [`broadcaster::sign_persist_and_broadcast`], of
/// [`base_fee::submit_exposure_for_chain`](super::base_fee::submit_exposure_for_chain)
/// and of [`SubmitContext`]. Every module doc that said the pipeline's write
/// half had no HTTP entry point was true until this function existed and has
/// been corrected in the same change.
///
/// # What a caller can and cannot cause
///
/// It can cause **one** `eth_sendRawTransaction` of an
/// `executeSponsoredEnrollment` addressed to `manifest.goat_relay_gateway`,
/// signed by this process's broadcaster EOA, against a quote **this attestor
/// sealed** — never one the caller supplied, because
/// [`SubmitSponsoredEnrollmentRequest`] has no quote field. It cannot cause a
/// second transaction for the same action nonce (the signing lease, then the
/// `nonce_allocations` reservation), and it cannot cause any transaction at
/// all until [`preflight::preflight_sponsored_enrollment`] has cleared the
/// call against a freshly pinned block.
///
/// # The two refusals that precede everything
///
/// Both are deployment facts rather than request facts, both are 503, and
/// both are decided before the body is parsed, before the store is read and
/// before any chain call:
///
/// 1. **An unset exposure ceiling** →
///    [`ApiError::exposure_ceiling_unset`](super::http_error::ApiError::exposure_ceiling_unset).
///    `STREAM_G_MAX_NATIVE_EXPOSURE_WEI` defaults to `0`, and a ceiling of `0`
///    refuses every broadcast on any chain carrying the `GasPriceOracle`
///    predeploy. Without this check that presents as
///    `EXPOSURE_EXCEEDS_SCHEDULE` on every request — an outage wearing a
///    safety feature's clothes. It is checked **first**, before the live-chain
///    check, because it is the one of the two an operator can fix by setting a
///    variable, and because a process that is missing both should be told
///    about the fixable one. `broadcaster::BroadcastPlan::max_native_exposure_wei`,
///    `runtime::StreamGState::max_native_exposure_wei` and
///    `preflight::UNVERIFIED_CHECKS`' exposure entry all state that the route
///    mounting this path owes this refusal; this is it.
/// 2. **No live chain** →
///    [`ApiError::no_live_chain`](super::http_error::ApiError::no_live_chain),
///    the same 503 [`super::quotes::post_quote`] gives. Under
///    `GOAT_ATTESTOR_MOCK=1` there is no [`TrustedChain`] and no `RpcChain`,
///    so there is neither anything to revalidate against nor a key to sign
///    with. This is why the route tests in this module assert `NO_LIVE_CHAIN`:
///    `TrustedChain`'s only release-build constructor takes a concrete
///    `RpcChain`, so a test cannot fabricate a live-chain arm through the
///    router without building a `StreamGState` that cannot exist in
///    production. The accepting-side logic is exercised at the layer that can
///    hold a `MockChain` — [`submit_sponsored_enrollment`] directly — exactly
///    as `quotes.rs` does for the quote path.
///
/// # Extractor order is compiler-enforced
///
/// [`State`] and [`AuthenticatedProfile`] are `FromRequestParts`;
/// [`ApiJson`](super::http_error::ApiJson) is the `FromRequest` body extractor
/// and must therefore come last. `ApiJson` and not bare `axum::Json`: a bare
/// `Json<T>` answers a deserialize failure with axum's own body instead of the
/// [`ApiError`] envelope.
///
/// # 404, never 403
///
/// Nothing here needs to arrange that: [`load_quote_commitment`] answers
/// [`SubmitError::IntentNotFound`] for the missing row and the wrong-profile
/// row alike, so "not found" and "not yours" are one 404 and the ownership
/// oracle stays closed
/// (`super::http_error::tests::stream_g_error_mapping_never_emits_403`).
pub(crate) async fn post_submit(
    State(state): State<StreamGState>,
    caller: AuthenticatedProfile,
    ApiJson(req): ApiJson<SubmitSponsoredEnrollmentRequest>,
) -> Result<Json<SubmitReceiptResponse>, ApiError> {
    if state.max_native_exposure_wei().get() == 0 {
        return Err(ApiError::exposure_ceiling_unset());
    }
    let trusted = state.trusted_chain().ok_or_else(ApiError::no_live_chain)?;
    // The same `Option` as `trusted_chain()` — `Inner::chain` is the source of
    // both — but a separate call because `RpcChainEnrollmentSigner` needs the
    // concrete `RpcChain` (the signing key lives behind it) while the
    // revalidation needs the `TrustedChain` wrapper. Neither can be derived
    // from the other, and the second `ok_or_else` is unreachable rather than
    // redundant.
    let rpc = state.live_chain().ok_or_else(ApiError::no_live_chain)?;

    let parts = req.parse(state.manifest().goat_relay_gateway)?;

    // Reads the broadcaster EOA's address off the key. `state.broadcast_gas()`
    // is the validated policy `config::build_broadcast_gas_policy` produced at
    // startup — no gas number is chosen here.
    let signer = broadcaster::RpcChainEnrollmentSigner::new(rpc, state.broadcast_gas())
        .map_err(|e| SubmitError::Broadcaster(BroadcasterError::Chain(e.to_string())))?;

    let ctx = submit_context(&state, trusted, &signer);
    let receipt = submit_sponsored_enrollment(&ctx, caller.profile(), &parts).await?;
    Ok(Json(SubmitReceiptResponse::from(receipt)))
}

/// `GET /v1/stream-g/status/:intentId` — the caller's own enrollment intent.
///
/// **`:intentId`, not `{intentId}`.** axum 0.7 / matchit 0.7 treat `{` and `}`
/// as ordinary path characters, so `"/…/{intentId}"` compiles, does not panic,
/// and matches only the literal six-character segment — every real request
/// would 404. `tests::the_status_route_binds_the_intent_id_from_the_path` turns
/// that into a failing test rather than a silent outage, mirroring
/// `super::onboarding::tests::the_intent_route_binds_the_intent_id_from_the_path`.
///
/// **Three different "no" answers, one response.** A path segment that is not
/// 32 hex bytes, an intent that does not exist, and an intent under another
/// profile all produce [`SubmitError::IntentNotFound`] → **404**. Never 403:
/// [`get_enrollment_intent`]'s `AND profile_id = ?` closed the ownership
/// oracle in the store, and answering the third case differently on the wire
/// would re-open it (`super::http_error::tests::stream_g_error_mapping_never_emits_403`).
/// The malformed segment joins them rather than getting a code of its own
/// because it is true of it as well: a segment that is not an intent id names
/// no intent of anybody's.
///
/// **No chain dependency**, so mock mode does not affect it: this route reads
/// only `StreamGStore`, and a 200 from it under `GOAT_ATTESTOR_MOCK=1` is a
/// real answer (`runtime::StreamGState::trusted_chain`) rather than a stub —
/// which is what lets
/// the tests below assert an accepting arm at all.
///
/// Residual, same as `super::profile_auth::delete_session`'s: `Path<String>`'s
/// own rejection (a path segment whose percent-encoding is not valid UTF-8) is
/// axum's and answers in `text/plain`.
pub(crate) async fn get_enrollment_status(
    State(state): State<StreamGState>,
    caller: AuthenticatedProfile,
    Path(intent_id_hex): Path<String>,
) -> Result<Json<EnrollmentStatusResponse>, ApiError> {
    let intent_id = parse_bytes32(&intent_id_hex).ok_or(SubmitError::IntentNotFound)?;
    let view = get_enrollment_intent(state.store(), caller.profile(), intent_id)
        .await?
        .ok_or(SubmitError::IntentNotFound)?;
    Ok(Json(EnrollmentStatusResponse::from(view)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{
        FeeTokenConfigView, MockChain, NonceSnapshotView, SNAP_ACTION_NONCE, SNAP_CONFIG_HASHES,
        SNAP_CONTROLLER, SNAP_FEE_TOKEN_PERMIT_NONCE, SNAP_LINK_NONCE, SNAP_V1_ENROLL_NONCE,
    };
    use crate::merkle::keccak256;
    use crate::sig_verify;
    use crate::stream_g::base_fee::{GasUnits, MaxFeePerGas};
    // 🔴 Wave C W2. These three left the module's top-level imports when the
    // production path stopped calling `outbox` directly; the fixtures that
    // drive the reservation by hand still need them.
    use crate::stream_g::outbox::{self, ReservationRequest, SignedRawTx};
    use crate::stream_g::models::{
        fee_quote_digest, link_secondary_digest, sponsor_enrollment_core_hash, FeeQuote,
        LinkSecondary, SponsorEnrollmentCore,
    };
    use crate::stream_g::preflight::{
        sponsor_enrollment_digest, Eip2612Authorization, RootAuthorization, SponsorEnrollment,
        V1Enrollment, AUTHORIZATION_MODE_EIP2612,
    };
    use crate::stream_g::token_manifest::{fee_token_config_hash, TokenCapability, CAP_EIP2612};
    use alloy::primitives::B256;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use std::str::FromStr;

    // Anvil deterministic keys #1/#2/#3 — same three `preflight.rs` uses, so
    // a fixture that passes there passes here for the same reasons.
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
    /// Wave 2: **8453 (Base), not 31337.** This const used to be 31337, on
    /// which `base_fee::chain_carries_gas_price_oracle` is false and the
    /// native-exposure gate does not run at all — every test in this module
    /// would have exercised a dead gate and the position pin below would
    /// have proved nothing. Nothing else in this module depends on the
    /// value: every digest, lease key and row id is computed from this same
    /// const at run time (there is no hard-coded signature anywhere here),
    /// which is why the flip is a one-line change and why all 562 pre-Wave-2
    /// tests still pass under it. The live-node harness stays on 31337 and
    /// exercises the skip branch instead.
    const CHAIN_ID: u64 = 8453;
    /// Wave 2. The gas parameters [`FakeSigner`] asserts about
    /// [`RAW_TX`] — see `outbox::SignedRawTx`'s "asserted, not decoded"
    /// note. Nonzero so `l2_wei` is nonzero and the gate has something real
    /// to compare.
    const TEST_GAS_LIMIT: u64 = 500_000;
    const TEST_MAX_FEE_PER_GAS: u128 = 1_000_000_000;
    /// Wave 2. The ceiling every test that is *not* about the exposure gate
    /// runs under: 1 ETH, comfortably above `500_000 * 1 gwei = 5e14 wei`
    /// plus `wired_chain()`'s zero oracle values. The rejection arm builds
    /// its own context with a deliberately low ceiling.
    const TEST_MAX_NATIVE_EXPOSURE_WEI: u128 = 1_000_000_000_000_000_000;
    const MANIFEST_HASH: [u8; 32] = [0x31; 32];
    const FEE_SCHEDULE_HASH: [u8; 32] = [0x32; 32];
    const LIVE_ACTION_NONCE: u128 = 9;
    const LIVE_CONTROLLER_EPOCH: u128 = 5;
    const LIVE_V1_NONCE: u128 = 3;
    const LIVE_LINK_NONCE: u128 = 4;
    const INTENT_ID: [u8; 32] = [0x51; 32];
    const QUOTE_ID: [u8; 32] = [0x53; 32];
    const PROFILE: &str = "profile-submit-1";
    const TX_HASH: [u8; 32] = [0x99; 32];
    /// Who the submit path reserves as. Task 8 Wave B — the outbox
    /// reservation is a compare-and-swap, so the claim needs an owner.
    const CLAIM_OWNER: &str = "submit-test-worker";
    /// A wall-clock `lease_until` for tests that call the unresolved-broadcast
    /// stamp directly. Its value is never asserted on — only that the column
    /// is (or is not) written.
    const WALL_LEASE_UNTIL: i64 = 1_800_000_900;
    /// The wall clock every fold in this module is folded under. Deliberately
    /// far above [`CHAIN_NOW`], so a test that used chain time where wall time
    /// is required (or the reverse) produces a visibly different answer rather
    /// than an off-by-a-little one.
    const WALL_NOW: i64 = 1_800_000_000;

    fn data_key_hex() -> SecretHex {
        SecretHex::from_hex(&"cc".repeat(32)).expect("valid 32-byte test key")
    }

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
            fee_token_permit_nonce: 2,
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

    fn wired_chain() -> MockChain {
        let cfg = token_cfg();
        let cfg_hash = fee_token_config_hash(&cfg);
        let m = MockChain::new();
        m.set_now(CHAIN_NOW);
        // Task 8 Mandate 3: the preflight state read now takes its clock from
        // the PINNED block and reads the fee token's own ERC-2612 nonce,
        // which must agree with the snapshot's `feeTokenPermitNonce` (2).
        m.set_block_timestamp_at(BLOCK, CHAIN_NOW);
        m.set_erc2612_nonces(FEE_TOKEN, addr(CONTROLLER_KEY), 2);
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
        // 🔴 Wave C W2. The submit path now runs through
        // `broadcaster::sign_persist_and_broadcast`, which makes two chain
        // calls this module never used to make: `eth_getTransactionCount`
        // for the broadcaster EOA's nonce frontier, and
        // `eth_sendRawTransaction` for the send itself. Both are armed to
        // the happy path here; the tests that need a send failure re-arm it
        // with `Harness::arm_send_failure`.
        m.set_transaction_count(BROADCASTER_EOA, BROADCASTER_START_NONCE);
        m.set_send_raw_transaction(Ok(TX_HASH));
        m
    }

    /// The ten-argument call, owned.
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
        /// 🔴 Wave C W3. What [`submit_sponsored_enrollment`] now takes: the
        /// fixture **minus the quote and its signature**, which the submit
        /// path rebuilds from the sealed row [`seed_quote`] wrote.
        ///
        /// The `call()` this replaced — which handed the whole ten-argument
        /// [`SponsoredEnrollmentCall`], quote included, straight to submit —
        /// is deleted rather than kept beside it. Keeping it would have left
        /// this module one `&f.call()` away from a test that pretends a
        /// caller can still name a quote.
        fn parts(&self) -> SubmitCallParts {
            SubmitCallParts {
                intent: self.intent.clone(),
                v1_enrollment: self.v1.clone(),
                link: self.link,
                root_authorization: self.root_auth,
                fee_authorization_mode: self.fee_authorization_mode,
                fee_eip2612_authorization: self.eip2612,
                sponsor_signature_hex: self.sponsor_sig.clone(),
                link_signature_hex: self.link_sig.clone(),
                root_authorization_signature_hex: self.root_auth_sig.clone(),
            }
        }

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
            self.sponsor_sig = sign(
                CONTROLLER_KEY,
                sponsor_enrollment_digest(&self.intent, CHAIN_ID, GATEWAY),
            );
        }
    }

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
            intent_id: INTENT_ID,
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
            fee_quote_hash: [0u8; 32],
            nonce: LIVE_ACTION_NONCE as u64,
            deadline,
        };
        let quote = FeeQuote {
            quote_id: QUOTE_ID,
            action_type: ActionType::SponsoredEnrollment.digest(),
            action_core_hash: [0u8; 32],
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

    // --- store seeding -------------------------------------------------

    async fn open_store() -> (tempfile::TempDir, StreamGStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open store");
        (dir, store)
    }

    /// Write the rows `quotes::create_sponsored_enrollment_quote` would have
    /// written for `f`, with the same row ids, the same sealed payload
    /// shapes and the same AAD binding.
    async fn seed_quote(store: &StreamGStore, f: &Fixture, profile_id: &str) {
        let data_key = DataKey::from_secret(&data_key_hex());
        // One seeded quote row per (profile, intentId), so a test can seed a
        // second intent without colliding on the quotes PRIMARY KEY.
        let quote_row_id = deterministic_id(&[
            "stream_g_quote|v1",
            profile_id,
            &bytes32_hex(f.intent.intent_id),
        ]);
        let intent_row = intent_row_id(profile_id, f.intent.intent_id);

        let quote_payload = serde_json::json!({
            "profile_id": profile_id,
            "quote_id_hex": bytes32_hex(f.quote.quote_id),
            "action_type_hex": bytes32_hex(f.quote.action_type),
            "action_core_hash_hex": bytes32_hex(f.quote.action_core_hash),
            "deployment_manifest_hash_hex": bytes32_hex(f.quote.deployment_manifest_hash),
            "fee_token_config_hash_hex": bytes32_hex(f.quote.fee_token_config_hash),
            "fee_schedule_hash_hex": bytes32_hex(f.quote.fee_schedule_hash),
            "payer_hex": address_hex(f.quote.payer),
            "fee_token_hex": address_hex(f.quote.fee_token),
            "fee_amount": f.quote.fee_amount.to_string(),
            "fee_recipient_hex": address_hex(f.quote.fee_recipient),
            "valid_after": f.quote.valid_after,
            "valid_until": f.quote.valid_until,
            "quote_signature_hex": f.quote_sig,
            "body_hash": "seed",
        });
        let intent_payload = serde_json::json!({
            "intent_id_hex": bytes32_hex(f.intent.intent_id),
            "profile_id": profile_id,
            "quote_id_hex": bytes32_hex(f.quote.quote_id),
            "action_core_hash_hex": bytes32_hex(f.quote.action_core_hash),
        });

        let quote_enc = crypto_store::seal(
            &data_key,
            &store.envelope_aad("quotes", &quote_row_id, "quote_enc"),
            &serde_json::to_vec(&quote_payload).unwrap(),
        )
        .unwrap();
        let intent_enc = crypto_store::seal(
            &data_key,
            &store.envelope_aad("intents", &intent_row, "intent_enc"),
            &serde_json::to_vec(&intent_payload).unwrap(),
        )
        .unwrap();

        let profile_id = profile_id.to_string();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT OR IGNORE INTO profiles (id, created_at, status) VALUES (?, ?, ?)",
                    )
                    .bind(&profile_id)
                    .bind(0i64)
                    .bind("active")
                    .execute(&mut **tx)
                    .await?;
                    sqlx::query(
                        "INSERT INTO quotes (id, profile_id, base_asset, quote_asset, \
                         base_amount, quote_amount, status, quote_enc, created_at, expires_at) \
                         VALUES (?, ?, 'usdt', 'marker', '0', '500000', 'active', ?, 0, ?)",
                    )
                    .bind(&quote_row_id)
                    .bind(&profile_id)
                    .bind(&quote_enc)
                    .bind(9_999_999_999i64)
                    .execute(&mut **tx)
                    .await?;
                    sqlx::query(
                        "INSERT INTO intents (id, profile_id, quote_id, intent_type, amount, \
                         status, intent_enc, created_at, expires_at) \
                         VALUES (?, ?, ?, 'sponsored_enrollment', '500000', 'pending', ?, 0, ?)",
                    )
                    .bind(&intent_row)
                    .bind(&profile_id)
                    .bind(&quote_row_id)
                    .bind(&intent_enc)
                    .bind(9_999_999_999i64)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed");
    }

    // --- signer double ---------------------------------------------------

    /// The bytes [`FakeSigner`] "signs". Non-empty and fixed, so
    /// `raw_tx_hash` is `keccak256(RAW_TX)` in every test and a row that
    /// carries it can be told apart from one that carries the *node's*
    /// [`TX_HASH`].
    const RAW_TX: &[u8] = &[0x02, 0xf8, 0x6b, 0xAA, 0xBB, 0xCC];

    fn signed_raw() -> SignedRawTx {
        SignedRawTx::new(
            RAW_TX.to_vec(),
            GasUnits::new(TEST_GAS_LIMIT),
            MaxFeePerGas::new(TEST_MAX_FEE_PER_GAS),
        )
    }

    /// The broadcaster EOA every test in this module signs from.
    ///
    /// Deliberately not the controller, the root, the secondary or the
    /// gateway — a `nonce_allocations` assertion keyed on `signer_address`
    /// must not be satisfiable by the wrong account's row.
    const BROADCASTER_EOA: [u8; 20] = [0x7B; 20];

    /// `eth_getTransactionCount(BROADCASTER_EOA)`, i.e. the first EOA
    /// transaction nonce `allocate_broadcaster_nonce` will hand out.
    ///
    /// 🔴 Deliberately **not** [`LIVE_ACTION_NONCE`] (9). The two counters
    /// share the `nonce_allocations` table, and every SQL assertion in this
    /// module that reads `WHERE nonce = ?` is written against the *action*
    /// nonce. Keeping the two values distinct is what keeps those assertions
    /// unambiguous now that a broadcaster row exists alongside each of them.
    const BROADCASTER_START_NONCE: u64 = 77;

    /// 🔴 Wave C W2. Was `FakeBroadcaster`, a sign-**and**-send double for a
    /// seam that no longer exists. The send moved to the chain client
    /// (`broadcaster::sign_persist_and_broadcast` →
    /// `outbox::reserve_persist_and_send` → `ChainClient::send_raw_transaction`),
    /// so this double only signs and every "was anything broadcast?"
    /// assertion reads [`Harness::sends`] instead of a counter here.
    ///
    /// That is a strictly stronger arrangement for those assertions: the
    /// count they read is now taken at the real seam a transaction leaves
    /// this process through, not at a stub the production path does not use.
    struct FakeSigner {
        sign_result: Mutex<Result<SignedRawTx, String>>,
        sign_calls: Mutex<usize>,
        last_gateway: Mutex<Option<[u8; 20]>>,
        last_nonce: Mutex<Option<u64>>,
    }

    impl FakeSigner {
        fn ok() -> Self {
            Self {
                sign_result: Mutex::new(Ok(signed_raw())),
                sign_calls: Mutex::new(0),
                last_gateway: Mutex::new(None),
                last_nonce: Mutex::new(None),
            }
        }
        /// Signing itself fails: no bytes exist, so nothing can be reserved
        /// and nothing can be sent.
        fn cannot_sign() -> Self {
            let b = Self::ok();
            *b.sign_result.lock().unwrap() = Err("no key configured".to_string());
            b
        }
        fn sign_calls(&self) -> usize {
            *self.sign_calls.lock().unwrap()
        }
        fn last_nonce(&self) -> Option<u64> {
            *self.last_nonce.lock().unwrap()
        }
    }

    impl SponsoredEnrollmentTxSigner for FakeSigner {
        fn broadcaster_address(&self) -> [u8; 20] {
            BROADCASTER_EOA
        }

        fn sign_sponsored_enrollment_tx(
            &self,
            gateway: [u8; 20],
            broadcaster_nonce: u64,
            _call: &SponsoredEnrollmentCall<'_>,
        ) -> Result<SignedRawTx, String> {
            *self.sign_calls.lock().unwrap() += 1;
            *self.last_gateway.lock().unwrap() = Some(gateway);
            *self.last_nonce.lock().unwrap() = Some(broadcaster_nonce);
            match &*self.sign_result.lock().unwrap() {
                Ok(s) => Ok(s.clone()),
                Err(e) => Err(e.clone()),
            }
        }
    }

    fn profile() -> AuthenticatedProfileId {
        AuthenticatedProfileId::for_test(PROFILE)
    }

    struct Harness {
        _dir: tempfile::TempDir,
        store: StreamGStore,
        // Owned so `ctx` can hand out a `&SecretHex`; the type has no
        // `'static` form because it holds a `Zeroizing<String>`.
        data_key: SecretHex,
        chain: MockChain,
        leases: SigningLeaseRegistry,
        manifest: DeploymentManifest,
    }

    impl Harness {
        fn ctx<'a>(&'a self, signer: &'a dyn SponsoredEnrollmentTxSigner) -> SubmitContext<'a> {
            SubmitContext {
                store: &self.store,
                // `#[cfg(test)]`-only `From<&C: ChainClient>` conversion —
                // the release build has no such impl, which is the whole
                // point of the type. See `token_manifest::TrustedChain`.
                chain: (&self.chain).into(),
                signer,
                leases: &self.leases,
                data_key_hex: &self.data_key,
                manifest: &self.manifest,
                claim_owner: CLAIM_OWNER,
                max_native_exposure_wei: WeiCeiling::new(TEST_MAX_NATIVE_EXPOSURE_WEI),
            }
        }

        /// Wave 2. The same context with a different exposure ceiling, so
        /// the gate's rejection arm differs from every other test in this
        /// module in exactly one value.
        fn ctx_with_ceiling<'a>(
            &'a self,
            signer: &'a dyn SponsoredEnrollmentTxSigner,
            ceiling_wei: u128,
        ) -> SubmitContext<'a> {
            SubmitContext {
                max_native_exposure_wei: WeiCeiling::new(ceiling_wei),
                ..self.ctx(signer)
            }
        }

        /// 🔴 Wave C W2. How many raw transactions actually left this
        /// process, read off the chain client rather than off a double.
        ///
        /// **Cumulative across the whole harness**, which matters for the
        /// tests that run two submits: those capture a `before` and assert
        /// on the delta rather than on an absolute 0/1.
        fn sends(&self) -> usize {
            self.chain.raw_sends().len()
        }

        /// Arm `eth_sendRawTransaction` to fail. The node refused (or the
        /// dial did), which — per `outbox::reserve_persist_and_send` and
        /// `relayer.rs:871-873` — does **not** establish that the payload
        /// never reached a mempool, and is therefore the
        /// `SendOutcome::SendFailedStuckRecoverable` shape.
        fn arm_send_failure(&self, detail: &str) {
            self.chain.set_send_raw_transaction(Err(detail.to_string()));
        }

        /// 🔴 Wave C W2 — the sweeper, stood in for.
        ///
        /// `submit_sponsored_enrollment` has **no** arm that releases an
        /// action nonce any more: `record_failed` is deleted, because
        /// `BroadcastOutcome` cannot express "nothing entered a mempool".
        /// Releasing is now exclusively
        /// `outbox::sweep_stuck_reservations`' job, on chain evidence.
        ///
        /// The tests below that are about a **replacement attempt** — the
        /// second `tx_attempts` row for one intent — therefore cannot reach
        /// one by making the first submit fail. They need the first attempt
        /// resolved first, and that is what this applies: the two `UPDATE`s
        /// the sweeper's `SafeToRelease` branch writes, and nothing else.
        /// Deliberately no `INSERT` — see
        /// [`this_module_contains_no_reservation_of_its_own`], which this
        /// helper must not break.
        ///
        /// Using the real sweeper here instead would need
        /// `transaction_receipt` and `intentUsed` armed on `MockChain`, which
        /// would make these tests about the sweeper rather than about the
        /// replacement. `outbox`'s own tests cover the sweeper.
        async fn resolve_attempt_as_swept(&self, attempt_id: &str, detail: &str) {
            let attempt_id = attempt_id.to_string();
            let detail = detail.to_string();
            let now = now_unix_seconds();
            self.store
                .write_tx(move |tx| {
                    Box::pin(async move {
                        sqlx::query(
                            "UPDATE nonce_allocations SET status = ?, released_at = ? \
                             WHERE id = (SELECT nonce_allocation_id FROM tx_attempts WHERE id = ?)",
                        )
                        .bind(NONCE_STATUS_RELEASED)
                        .bind(now)
                        .bind(&attempt_id)
                        .execute(&mut **tx)
                        .await?;
                        sqlx::query(
                            "UPDATE tx_attempts SET status = ?, error_message = ?, \
                             claim_owner = NULL WHERE id = ?",
                        )
                        .bind(TX_ATTEMPT_STATUS_FAILED)
                        .bind(&detail)
                        .bind(&attempt_id)
                        .execute(&mut **tx)
                        .await?;
                        Ok::<(), StreamGStoreError>(())
                    })
                })
                .await
                .expect("sweeper stand-in");
        }
    }

    async fn harness(f: &Fixture) -> Harness {
        let (dir, store) = open_store().await;
        seed_quote(&store, f, PROFILE).await;
        Harness {
            _dir: dir,
            store,
            data_key: data_key_hex(),
            chain: wired_chain(),
            leases: SigningLeaseRegistry::new(),
            manifest: manifest(),
        }
    }

    async fn scalar_i64(store: &StreamGStore, sql: &'static str, bind: String) -> i64 {
        store
            .read(move |h| {
                Box::pin(async move {
                    let v: i64 = h.fetch_scalar(sqlx::query_scalar(sql).bind(bind)).await?;
                    Ok::<i64, StreamGStoreError>(v)
                })
            })
            .await
            .expect("scalar")
    }

    async fn text(store: &StreamGStore, sql: &'static str, bind: String) -> Option<String> {
        store
            .read(move |h| {
                Box::pin(async move {
                    let v: Option<String> =
                        h.fetch_scalar(sqlx::query_scalar(sql).bind(bind)).await?;
                    Ok::<Option<String>, StreamGStoreError>(v)
                })
            })
            .await
            .expect("text")
    }

    /// Run a two-bind statement and return `rows_affected()`, so a test can
    /// prove its own setup really moved a row before asserting on the result.
    async fn exec2(store: &StreamGStore, sql: &'static str, a: String, b: String) -> u64 {
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    let r = sqlx::query(sql).bind(a).bind(b).execute(&mut **tx).await?;
                    Ok::<u64, StreamGStoreError>(r.rows_affected())
                })
            })
            .await
            .expect("exec2")
    }

    // --- log capture -----------------------------------------------------
    //
    // One branch in this module is deliberately observable ONLY as a log line
    // (`record_broadcast_unresolved`'s `rows_affected() != 1` arm, which must
    // not raise an error — see its comment). Testing it therefore means
    // reading the trace output, not the database.

    #[derive(Clone, Default)]
    struct LogBuf(std::sync::Arc<Mutex<Vec<u8>>>);

    impl LogBuf {
        fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    impl std::io::Write for LogBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
        type Writer = LogBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Install a thread-local subscriber that writes into `buf`. `#[tokio::test]`
    /// uses a current-thread runtime, so every `.await` below is polled on the
    /// thread this guard belongs to.
    ///
    /// A thread-local subscriber is not enough on its own: `tracing` caches one
    /// `Interest` per callsite for the whole process, and a subscriber-less
    /// thread that reaches a callsite first caches it as `Interest::never()`,
    /// after which nothing this subscriber does can make that line fire. That is
    /// the race that made
    /// `http_error::tests::extractor_rejection_detail_goes_to_tracing_not_to_the_client`
    /// fail 6 times in 30 full runs. See `crate::stream_g::log_capture`.
    fn capture_logs(buf: &LogBuf) -> tracing::subscriber::DefaultGuard {
        crate::stream_g::log_capture::install_interest_keepalive();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        tracing::subscriber::set_default(subscriber)
    }

    // -------------------------------------------------------------------
    // Ground-truth pins.
    // -------------------------------------------------------------------

    /// The three revert names the brief names, verified against the Solidity
    /// declarations by hand (`GoatRelayGateway.sol:34`, `:48`,
    /// `WalletSponsorshipRegistry.sol:26`) and pinned here with their
    /// classification.
    ///
    /// Mutation this detects: flipping `BadActionNonce` to `Terminal`
    /// (which would strand every caller whose nonce was consumed by another
    /// party — exactly hazard 2's failure mode), or classifying
    /// `InvalidRootAuthorization` as `Retryable` (which would produce a
    /// resubmit loop against `secondary == root`).
    #[test]
    fn nonce_adjacent_reverts_are_classified_with_their_real_names() {
        assert_eq!(
            OnChainRevert::parse("BadActionNonce").retryability(),
            Retryability::Retryable
        );
        assert_eq!(
            OnChainRevert::parse("BadActionNonce").site(),
            "GoatRelayGateway.sol:34"
        );
        assert_eq!(
            OnChainRevert::parse("EpochMismatch").retryability(),
            Retryability::Terminal
        );
        assert_eq!(
            OnChainRevert::parse("EpochMismatch").site(),
            "GoatRelayGateway.sol:48"
        );
        assert_eq!(
            OnChainRevert::parse("InvalidRootAuthorization").retryability(),
            Retryability::Ambiguous
        );
        assert_eq!(
            OnChainRevert::parse("InvalidRootAuthorization").site(),
            "WalletSponsorshipRegistry.sol:26"
        );
        // There is no `StaleNonce` on chain. If someone adds a variant with
        // that name this pin says so.
        assert_eq!(
            OnChainRevert::parse("StaleNonce"),
            OnChainRevert::Unrecognized("StaleNonce".to_string())
        );
        assert_eq!(
            OnChainRevert::parse("StaleNonce").retryability(),
            Retryability::Terminal,
            "an unknown revert must never drive an automatic retry"
        );
    }

    /// `intents.id` must be byte-identical to what `quotes.rs` writes, or
    /// every lookup in this module silently addresses a row that does not
    /// exist.
    ///
    /// Mutation this detects: changing [`INTENT_ROW_ID_DOMAIN`], reordering
    /// the digest parts, or dropping the `0x` prefix from the intentId hex.
    #[test]
    fn intent_row_id_matches_the_quotes_module_scheme() {
        let expected = hex::encode(Sha256::digest(
            format!(
                "stream_g_sponsored_enrollment_intent|{}|0x{}",
                PROFILE,
                hex::encode(INTENT_ID)
            )
            .as_bytes(),
        ));
        assert_eq!(intent_row_id(PROFILE, INTENT_ID), expected);

        // And the domain string this module uses is the one quotes.rs
        // declares. A rename on either side breaks this.
        let quotes_src = include_str!("quotes.rs");
        assert!(
            quotes_src.contains(&format!(
                "const INTENT_ROW_ID_DOMAIN: &str = \"{INTENT_ROW_ID_DOMAIN}\""
            )),
            "quotes.rs no longer declares INTENT_ROW_ID_DOMAIN = {INTENT_ROW_ID_DOMAIN}"
        );
    }

    /// [`StoredQuoteView`] / [`StoredIntentView`] are hand-written mirrors of
    /// two structs that live in another file. A rename there would make this
    /// module fail closed at runtime with a missing-field error — correct,
    /// but only discovered in production.
    ///
    /// Mutation this detects: renaming any of `QuotePayload`'s or
    /// `EnrollmentIntentPayload`'s fields in `quotes.rs` (e.g.
    /// `quote_signature_hex` → `signature_hex`), **or** drifting either
    /// mirror struct here away from the struct it mirrors.
    ///
    /// The scan is scoped to the two struct **bodies**, not to the whole
    /// file: a whole-file `contains` matched unrelated identifiers
    /// elsewhere in `quotes.rs` and survived exactly the rename it is named
    /// for, which is how this test was found to be too weak.
    #[test]
    fn stored_payload_field_names_match_quotes_rs() {
        fn body<'a>(src: &'a str, decl: &str) -> &'a str {
            let start = src
                .find(decl)
                .unwrap_or_else(|| panic!("`{decl}` no longer exists in quotes.rs"));
            let rest = &src[start + decl.len()..];
            let end = rest.find("\n}").expect("unterminated struct in quotes.rs");
            &rest[..end]
        }
        let quotes_src = include_str!("quotes.rs");
        let quote_body = body(quotes_src, "struct QuotePayload {");
        for key in QUOTE_PAYLOAD_REQUIRED_KEYS {
            assert!(
                quote_body.contains(&format!("\n    {key}:")),
                "quotes.rs's QuotePayload no longer declares `{key}`; \
                 StoredQuoteView would fail to deserialize at runtime"
            );
        }
        let intent_body = body(quotes_src, "struct EnrollmentIntentPayload {");
        for key in INTENT_PAYLOAD_REQUIRED_KEYS {
            assert!(
                intent_body.contains(&format!("\n    {key}:")),
                "quotes.rs's EnrollmentIntentPayload no longer declares `{key}`; \
                 StoredIntentView would fail to deserialize at runtime"
            );
        }
    }

    /// The action-nonce reservation key must carry the action type, because
    /// the chain's counter is `actionNonces[signer][actionType]`.
    ///
    /// Mutation this detects: dropping the action component from
    /// [`action_nonce_signer_key`], which would let a sponsored-sell nonce
    /// and a sponsored-enrollment nonce collide in one reservation space.
    #[test]
    fn action_nonce_key_is_two_dimensional() {
        let c = [0xAB; 20];
        assert_ne!(
            action_nonce_signer_key(c, ActionType::SponsoredEnrollment),
            action_nonce_signer_key(c, ActionType::SponsoredSell)
        );
        assert!(action_nonce_signer_key(c, ActionType::SponsoredEnrollment)
            .contains(ActionType::SponsoredEnrollment.as_str()));
    }

    // -------------------------------------------------------------------
    // Signing lease (hazard 2, mechanism 3).
    // -------------------------------------------------------------------

    /// Mutation this detects: making [`SigningLeaseRegistry::try_acquire`]
    /// ignore an already-present key (e.g. `held.insert(..); Ok(..)`), or
    /// deleting the `Drop` impl's `remove`.
    #[test]
    fn signing_lease_is_exclusive_and_released_on_drop() {
        let reg = SigningLeaseRegistry::new();
        let key = || NonceLeaseKey::new(CHAIN_ID, [0x01; 20], ActionType::SponsoredEnrollment, 7);

        let lease = reg.try_acquire(key()).expect("first acquire");
        assert!(reg.is_held(&key()));

        let err = reg
            .try_acquire(key())
            .expect_err("second acquire must fail");
        assert_eq!(err.code(), ERR_SUBMIT_SIGNING_LEASE_HELD);
        assert_eq!(err.retryability(), Retryability::Retryable);

        // A DIFFERENT nonce for the same controller is a different lease.
        let other = NonceLeaseKey::new(CHAIN_ID, [0x01; 20], ActionType::SponsoredEnrollment, 8);
        let _other = reg.try_acquire(other).expect("different nonce is free");

        drop(lease);
        assert!(!reg.is_held(&key()));
        reg.try_acquire(key())
            .expect("released key is re-acquirable");
    }

    /// The submit path must actually consult the lease before doing anything
    /// else. Holding the lease for this call's nonce out-of-band must stop
    /// the submit **before** it reaches the broadcaster.
    ///
    /// Mutation this detects: deleting the `try_acquire` call at step 1 of
    /// [`submit_sponsored_enrollment`] (the send count would become
    /// 1 and the error would not be `SUBMIT_SIGNING_LEASE_HELD`).
    #[tokio::test]
    async fn submit_refuses_while_another_holds_the_signing_lease() {
        let f = fixture();
        let h = harness(&f).await;
        let b = FakeSigner::ok();

        let held = h
            .leases
            .try_acquire(NonceLeaseKey::new(
                CHAIN_ID,
                f.intent.controller,
                ActionType::SponsoredEnrollment,
                f.intent.nonce,
            ))
            .expect("take the lease first");

        let err = submit_sponsored_enrollment(&h.ctx(&b), &profile(), &f.parts())
            .await
            .expect_err("submit must refuse while the lease is held");
        assert_eq!(err.code(), ERR_SUBMIT_SIGNING_LEASE_HELD);
        assert_eq!(h.sends(), 0, "nothing may be broadcast without the lease");
        assert_eq!(
            b.sign_calls(),
            0,
            "nor may anything be signed: the lease is step 1, before the signer is reached"
        );

        drop(held);
        submit_sponsored_enrollment(&h.ctx(&b), &profile(), &f.parts())
            .await
            .expect("submit succeeds once the lease is free");
        assert_eq!(h.sends(), 1);
    }

    /// The lease must be released when the submit returns, or one failed
    /// submit would wedge that nonce for the life of the process.
    ///
    /// 🔴 Wave C W2 re-pointed this at a **send failure** rather than at a
    /// decoded revert. `BroadcastOutcome` has no `tx_hash: None` shape, so
    /// the "node decoded a revert, nothing entered a mempool" case this used
    /// to drive is no longer expressible on the production path — see
    /// [`a_failed_send_holds_the_reservation_for_the_sweeper`], which is
    /// where that behavioural change is asserted head-on. What this test is
    /// about is unchanged: the RAII guard, on the failing path.
    ///
    /// Mutation this detects: replacing the RAII guard with an explicit
    /// release on the success path only.
    #[tokio::test]
    async fn signing_lease_is_released_after_a_failed_submit() {
        let f = fixture();
        let h = harness(&f).await;
        h.arm_send_failure("connection reset by peer");
        let b = FakeSigner::ok();

        let key = NonceLeaseKey::new(
            CHAIN_ID,
            f.intent.controller,
            ActionType::SponsoredEnrollment,
            f.intent.nonce,
        );
        let err = submit_sponsored_enrollment(&h.ctx(&b), &profile(), &f.parts())
            .await
            .expect_err("failed send");
        assert_eq!(err.code(), ERR_SUBMIT_BROADCAST_UNRESOLVED);
        assert!(!h.leases.is_held(&key), "lease must not survive the call");
    }

    // -------------------------------------------------------------------
    // Wave 2 — the native-ETH exposure gate (hazard 1) on the submit path.
    // -------------------------------------------------------------------

    /// The three `GasPriceOracle` values `wired_chain()` does NOT set (it
    /// leaves all three at `MockChain`'s zero default). Every exposure test
    /// below arms them, because a gate evaluated against zeros is a gate
    /// that proves nothing: `max(0,0) + 0` reduces the reserve to `l2_wei`
    /// alone and the whole L1-data-availability + operator half of hazard 1
    /// — the half `base_fee.rs` exists for — never enters the arithmetic.
    ///
    /// With [`TEST_GAS_LIMIT`] / [`TEST_MAX_FEE_PER_GAS`]:
    /// `l2 = 500_000 * 1e9 = 5.0e14`; L1 term = `max(2.0e13, 2.5e13) = 2.5e13`
    /// (the pessimistic branch, so the *upper* bound wins here); operator =
    /// `1.0e12`. Reserve = **526_000_000_000_000 wei**.
    const EXPOSURE_L1_EXACT_WEI: u128 = 20_000_000_000_000;
    const EXPOSURE_L1_UPPER_WEI: u128 = 25_000_000_000_000;
    const EXPOSURE_OPERATOR_WEI: u128 = 1_000_000_000_000;
    const EXPOSURE_EXPECTED_RESERVE_WEI: u128 = 526_000_000_000_000;

    fn arm_gas_price_oracle(chain: &MockChain) {
        chain.set_l1_exact_fee_wei(EXPOSURE_L1_EXACT_WEI);
        chain.set_l1_upper_fee_wei(EXPOSURE_L1_UPPER_WEI);
        chain.set_operator_fee_wei(EXPOSURE_OPERATOR_WEI);
    }

    /// The arithmetic the arms below are built on, asserted in one place so
    /// a reader does not have to trust the comment. If this fails, those
    /// arms are testing something other than what they claim.
    #[test]
    fn exposure_fixture_reserve_is_what_the_gate_arms_assume() {
        let exposure = crate::stream_g::base_fee::NativeExposure {
            l2_wei: u128::from(TEST_GAS_LIMIT) * TEST_MAX_FEE_PER_GAS,
            l1_exact_wei: EXPOSURE_L1_EXACT_WEI,
            l1_upper_wei: EXPOSURE_L1_UPPER_WEI,
            operator_wei: EXPOSURE_OPERATOR_WEI,
        };
        assert_eq!(
            exposure.reserve_wei().expect("no overflow"),
            EXPOSURE_EXPECTED_RESERVE_WEI
        );
    }

    /// 🔴 **The Wave 2 gate, and its POSITION.**
    ///
    /// A ceiling one wei below the real reserve must refuse the submit —
    /// and must refuse it *between* signing and reservation, which is the
    /// only position at which the refusal is free. Four independent facts
    /// pin that position, and each fails for a different wrong placement:
    ///
    /// * `sign_calls() == 1` — the gate is **after** signing (it has to be:
    ///   `getL1Fee(bytes)` takes the real serialized transaction). A gate
    ///   moved before signing would read 0.
    /// * `h.sends() == 0` — nothing was broadcast. A gate moved after
    ///   the send would read 1: money already spent, then refused.
    /// * zero `tx_attempts` rows — the gate is **before**
    ///   `reserve_and_persist_raw_tx`. A gate moved after it would leave a
    ///   `reserved` row naming a transaction that will never exist, which
    ///   only the sweeper could clear.
    /// * zero `kind='action'` `nonce_allocations` rows — no action nonce was
    ///   claimed, so the controller's `actionNonces` sequence is untouched
    ///   and the client can re-quote immediately.
    ///
    /// The oracle values are nonzero ([`arm_gas_price_oracle`]) so the
    /// refusal is driven by a real three-term reserve rather than by
    /// `l2_wei` alone, and the ceiling is
    /// `EXPOSURE_EXPECTED_RESERVE_WEI - 1` rather than 0, so this cannot
    /// pass merely because "everything exceeds a zero ceiling".
    ///
    /// 🔴 **Wave C W2 — this is the hazard-1 survival test.** The gate call
    /// moved out of this module into
    /// `broadcaster::sign_persist_and_broadcast`, so what this test now pins
    /// is that `submit_sponsored_enrollment` still *supplies* the ceiling:
    /// the only path from `SubmitContext::max_native_exposure_wei` to the
    /// gate is `BroadcastPlan::max_native_exposure_wei`, and this test drives
    /// a real refusal through it. It also pins the **new** obligation the
    /// move creates: the broadcaster EOA nonce allocated before signing must
    /// be RELEASED on a refusal, or one refused submit gaps that account's
    /// nonce sequence forever.
    ///
    /// MUTATIONS DETECTED (each applied alone, run, and reverted
    /// 2026-07-27):
    /// 1. `max_native_exposure_wei: WeiCeiling::new(u128::MAX)` in the
    ///    `BroadcastPlan` this module builds — i.e. the gate is still called,
    ///    with a ceiling nothing can exceed. Result: **this test was the only
    ///    failure in the whole suite** (`685 passed; 1 failed`), at
    ///    `expect_err`. That is the mutation that matters: it is what "the
    ///    gate was bypassed" looks like after the re-architecture, and it is
    ///    invisible to every assertion in `broadcaster.rs`'s own tests,
    ///    because from there the plan is a fixture rather than something
    ///    `submit.rs` filled in.
    /// 2. Delete the `release_broadcaster_nonce` call from
    ///    `sign_persist_and_broadcast`'s exposure-refusal arm. Result:
    ///    `684 passed; 2 failed` — this test's last assertion, plus
    ///    `broadcaster::tests::an_exposure_rejection_releases_the_broadcaster_eoa_nonce`.
    #[tokio::test]
    async fn exposure_gate_refuses_between_signing_and_reservation() {
        let f = fixture();
        let h = harness(&f).await;
        arm_gas_price_oracle(&h.chain);
        let b = FakeSigner::ok();

        let err = submit_sponsored_enrollment(
            &h.ctx_with_ceiling(&b, EXPOSURE_EXPECTED_RESERVE_WEI - 1),
            &profile(),
            &f.parts(),
        )
        .await
        .expect_err("a reserve above the ceiling must refuse the submit");

        // (c) the specific variant, its inner numbers, and its code.
        match &err {
            SubmitError::NativeExposure(BaseFeeError::ExposureExceedsSchedule {
                reserve_wei,
                ceiling_wei,
            }) => {
                assert_eq!(
                    *reserve_wei, EXPOSURE_EXPECTED_RESERVE_WEI,
                    "the refusal must name the three-term reserve, not just l2_wei"
                );
                assert_eq!(*ceiling_wei, EXPOSURE_EXPECTED_RESERVE_WEI - 1);
            }
            other => panic!("expected NativeExposure(ExposureExceedsSchedule), got {other:?}"),
        }
        assert_eq!(
            err.code(),
            crate::stream_g::base_fee::ERR_EXPOSURE_EXCEEDS_SCHEDULE,
            "the operator-facing code must say WHICH exposure rule refused"
        );
        // An explicit `retryability()` arm, not the catch-all: identical
        // inputs against an identical ceiling can only refuse again.
        assert_eq!(err.retryability(), Retryability::Terminal);

        // (d) the position pin.
        assert_eq!(b.sign_calls(), 1, "the gate must run AFTER signing");
        assert_eq!(
            h.sends(),
            0,
            "THE HAZARD: the transaction was broadcast anyway"
        );
        assert_eq!(
            scalar_i64(
                &h.store,
                "SELECT COUNT(*) FROM tx_attempts WHERE intent_id = ?",
                intent_row_id(PROFILE, f.intent.intent_id),
            )
            .await,
            0,
            "the gate must run BEFORE reserve_and_persist_raw_tx: a refused submit left a row"
        );
        assert_eq!(
            scalar_i64(
                &h.store,
                "SELECT COUNT(*) FROM nonce_allocations WHERE nonce = ?",
                f.intent.nonce.to_string(),
            )
            .await,
            0,
            "a refused submit claimed the controller's action nonce"
        );

        // (e) 🔴 Wave C W2's new obligation. The broadcaster EOA nonce IS
        // allocated before signing on this path — that is the ordering
        // `sign_persist_and_broadcast` exists for — so the refusal must give
        // it back. A held nonce here is a permanent hole in the EOA's
        // sequence, which stalls every later transaction from that account.
        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM nonce_allocations WHERE kind = 'broadcaster' AND nonce = ?",
                BROADCASTER_START_NONCE.to_string(),
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_RELEASED),
            "a refused submit must not gap the broadcaster EOA's nonce sequence"
        );
    }

    /// The paired SUCCESS arm — deliberately **not** vacuous.
    ///
    /// The oracle returns the same nonzero values as the rejection arm and
    /// the ceiling is a real number: exactly the reserve, i.e. the
    /// boundary, because `enforce_exposure_gate` refuses on
    /// `reserve > ceiling` and equality must therefore pass. Without this
    /// arm the rejection above would be equally consistent with a gate that
    /// refuses everything — an outage wearing a safety feature's clothes.
    ///
    /// MUTATION DETECTED: `enforce_exposure_gate`'s `reserve > ceiling_wei`
    /// → `reserve >= ceiling_wei`. This arm starts failing while the
    /// rejection arm still passes, which is exactly why the ceiling here is
    /// the boundary value rather than a comfortable one.
    #[tokio::test]
    async fn exposure_gate_admits_a_submit_at_the_ceiling() {
        let f = fixture();
        let h = harness(&f).await;
        arm_gas_price_oracle(&h.chain);
        let b = FakeSigner::ok();

        let receipt = submit_sponsored_enrollment(
            &h.ctx_with_ceiling(&b, EXPOSURE_EXPECTED_RESERVE_WEI),
            &profile(),
            &f.parts(),
        )
        .await
        .expect("a reserve exactly at the ceiling must be admitted");

        assert_eq!(receipt.tx_hash_hex, bytes32_hex(TX_HASH));
        assert_eq!(b.sign_calls(), 1);
        assert_eq!(h.sends(), 1, "the admitted submit must actually broadcast");
        // The oracle really was consulted on this arm — otherwise "admitted"
        // would be indistinguishable from "skipped".
        assert_eq!(
            h.chain.l1_fee_call_count(),
            1,
            "the exact getL1Fee call is what makes this arm non-vacuous"
        );
    }

    /// `SubmitError::retryability()` ends in a catch-all that answers
    /// `Terminal`. `NativeExposure` therefore gets an **explicit** arm, and
    /// this test is what makes that arm non-decorative: a failed
    /// `GasPriceOracle` `eth_call` says nothing about the call itself —
    /// nothing was reserved, persisted or sent — so it must be `Retryable`,
    /// which is the one answer the catch-all cannot give.
    ///
    /// The refusal half (`ExposureExceedsSchedule` → `Terminal`) is
    /// asserted in `exposure_gate_refuses_between_signing_and_reservation`;
    /// both halves matter, because a variant that is uniformly `Terminal`
    /// tells an operator to give up on a transient RPC blip.
    ///
    /// MUTATION DETECTED: delete the explicit
    /// `SubmitError::NativeExposure(e) => match e { .. }` arm and let the
    /// `_ => Retryability::Terminal` catch-all classify it. This test fails;
    /// nothing else in the suite does.
    #[test]
    fn a_failed_oracle_read_is_retryable_not_terminal() {
        let transient = SubmitError::NativeExposure(BaseFeeError::Chain(
            crate::chain::ChainError::Msg("getL1Fee(): connection reset".into()),
        ));
        assert_eq!(
            transient.retryability(),
            Retryability::Retryable,
            "a failed oracle read must not be reported as a dead enrollment"
        );

        // Paired arm, same variant: the ceiling refusal really is terminal,
        // so the assertion above is about the INNER error and not about the
        // variant being blanket-Retryable.
        let refused = SubmitError::NativeExposure(BaseFeeError::ExposureExceedsSchedule {
            reserve_wei: 2,
            ceiling_wei: 1,
        });
        assert_eq!(refused.retryability(), Retryability::Terminal);
    }

    // The chain-guarded *skip* half of this gate is proved in two places
    // rather than here, for a reason worth recording: every digest in
    // `fixture()` (`enroll_digest`, `link_digest`, the quote and sponsor
    // signatures) is bound to `CHAIN_ID`, so a test that merely re-pointed
    // `manifest.chain_id` at 31337 would be rejected at preflight with
    // `EnrollDigestMismatch` long before reaching the gate — it would prove
    // nothing about the gate at all. The two real proofs are:
    //
    //   * `base_fee::tests::submit_exposure_for_chain_*` — the guard's own
    //     semantics: zero chain calls and no ceiling enforcement on 31337,
    //     refusal on 8453, from identical inputs.
    //   * `anvil_harness::tests::stream_g_anvil_nonce_drift_after_reservation_leaves_a_row_the_sweeper_resolves`
    //     — the integration proof, and a much stronger one than a mock
    //     could give: it runs `submit_sponsored_enrollment` against a REAL
    //     anvil node on chain 31337, which genuinely has no `GasPriceOracle`
    //     predeploy. RUN, not asserted about: with
    //     `chain_carries_gas_price_oracle` mutated to return `true` for
    //     every chain, that test fails against the live node with
    //
    //         expected BroadcastUnresolved, got NativeExposure(Chain(
    //           Msg("getL1Fee() return too short: 0 bytes (need 32)")))
    //
    //     which is ruling 1's outage observed rather than predicted: every
    //     sponsored enrollment on the default dev chain would terminate
    //     there. Guard restored; suite green. The same test is therefore
    //     also what would catch this module passing the gate a chain id
    //     other than `ctx.manifest.chain_id`.

    // -------------------------------------------------------------------
    // Reservation (hazard 2, mechanism 1).
    // -------------------------------------------------------------------

    /// Happy path: one `nonce_allocations` row in `allocated`, one
    /// `tx_attempts` row in `submitted` carrying the tx hash, the intent
    /// moved to `submitted`.
    #[tokio::test]
    async fn successful_submit_reserves_the_nonce_and_records_the_attempt() {
        let f = fixture();
        let h = harness(&f).await;
        let b = FakeSigner::ok();

        let receipt = submit_sponsored_enrollment(&h.ctx(&b), &profile(), &f.parts())
            .await
            .expect("submit");
        assert_eq!(receipt.tx_hash_hex, bytes32_hex(TX_HASH));
        assert_eq!(receipt.revalidated_at_block, BLOCK);
        assert_eq!(receipt.chain_now, CHAIN_NOW);
        assert!(!receipt.unverified.is_empty(), "honesty list must travel");

        let n = scalar_i64(
            &h.store,
            "SELECT COUNT(*) FROM nonce_allocations WHERE status = 'allocated' AND nonce = ?",
            f.intent.nonce.to_string(),
        )
        .await;
        assert_eq!(n, 1, "exactly one live reservation");

        let status = text(
            &h.store,
            "SELECT status FROM tx_attempts WHERE id = ?",
            receipt.tx_attempt_id.clone(),
        )
        .await;
        assert_eq!(status.as_deref(), Some(TX_ATTEMPT_STATUS_SUBMITTED));

        let intent_status = text(
            &h.store,
            "SELECT status FROM intents WHERE id = ?",
            intent_row_id(PROFILE, f.intent.intent_id),
        )
        .await;
        assert_eq!(intent_status.as_deref(), Some(INTENT_STATUS_SUBMITTED));

        // 🔴 Wave C W2. The half this module could not do before: a
        // broadcaster EOA transaction nonce was allocated from the live
        // frontier and the signer signed against **that** value. A signer
        // that picked its own would void
        // `allocate_broadcaster_nonce`'s contiguity guarantee, and the two
        // allocations must be distinguishable rows.
        assert_eq!(
            b.last_nonce(),
            Some(BROADCASTER_START_NONCE),
            "the signer must sign against the ALLOCATED EOA nonce"
        );
        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM nonce_allocations WHERE kind = 'broadcaster' AND nonce = ?",
                BROADCASTER_START_NONCE.to_string(),
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "a sent transaction's EOA nonce stays held until reconciliation consumes it"
        );
    }

    /// Hazard 2, mechanism 1, end to end: a *different* intent that would
    /// sign against the same `actionNonces[controller][SPONSORED_ENROLLMENT]`
    /// is refused, and never reaches the broadcaster.
    ///
    /// This is the assertion the durable reservation exists for.
    ///
    /// MUTATION DETECTED (re-pointed and re-run for Task 8 Wave B, because the
    /// function it used to name — `reserve_action_nonce` — no longer exists):
    /// delete the `if let Some(holder) = holder { return Err(NonceAlreadyReserved) }`
    /// exclusion in `outbox::reserve_and_persist_raw_tx`. The second submit
    /// then broadcasts, giving two in-flight transactions against one nonce,
    /// one of which is guaranteed to revert `BadActionNonce`. Run 2026-07-25:
    /// this test was the **only** failure in the suite — which is itself the
    /// proof that the submit path really does execute the outbox reservation
    /// now, because before the merge a mutation in `outbox.rs` could not have
    /// failed a `submit.rs` test at all. Reverted; suite green.
    #[tokio::test]
    async fn a_second_intent_cannot_reserve_an_already_held_action_nonce() {
        let f = fixture();
        let h = harness(&f).await;
        let b = FakeSigner::ok();

        submit_sponsored_enrollment(&h.ctx(&b), &profile(), &f.parts())
            .await
            .expect("first submit");
        assert_eq!(h.sends(), 1);

        // A second intent id — same controller, same action nonce.
        let mut g = fixture();
        g.intent.intent_id = [0x61; 32];
        g.rebind_quote();
        seed_quote(&h.store, &g, PROFILE).await;

        let err = submit_sponsored_enrollment(&h.ctx(&b), &profile(), &g.parts())
            .await
            .expect_err("the action nonce is already reserved");
        assert_eq!(err.code(), ERR_SUBMIT_NONCE_ALREADY_RESERVED);
        assert_eq!(err.retryability(), Retryability::Ambiguous);
        assert_eq!(h.sends(), 1, "the second call must not be broadcast");

        // 🔴 Wave C W2. The refusal happens in
        // `outbox::reserve_and_persist_raw_tx`, i.e. AFTER a second
        // broadcaster EOA nonce was allocated and signed against. That nonce
        // must come back — `sign_persist_and_broadcast`'s `Err` arm is
        // reachable only pre-send, which is exactly why releasing there is
        // safe and required.
        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM nonce_allocations WHERE kind = 'broadcaster' AND nonce = ?",
                (BROADCASTER_START_NONCE + 1).to_string(),
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_RELEASED),
            "a refused reservation must not gap the broadcaster EOA's nonce sequence"
        );
    }

    /// 🔴 **THE WAVE C W2 BEHAVIOURAL CHANGE, ASSERTED HEAD-ON.**
    ///
    /// This test replaces `a_reverting_broadcast_releases_the_reservation_so_a_requote_can_retry`,
    /// and it asserts the **opposite** of what that one did. The replacement
    /// is not a weakening; the behaviour genuinely changed, and pretending
    /// otherwise would have meant keeping a test that could no longer be made
    /// to pass without re-opening the 6b double-submit.
    ///
    /// **What changed.** The deleted test drove a `BroadcastError` with
    /// `revert: Some(..)` and `tx_hash: None` — "the node decoded a revert
    /// while admitting the call, so nothing entered a mempool" — through the
    /// old sign-and-send seam, and asserted that `record_failed` released the
    /// action nonce so a re-quote could retry immediately. The production
    /// path now runs through
    /// [`broadcaster::sign_persist_and_broadcast`], whose
    /// [`BroadcastOutcome`] has **no** `tx_hash: None` shape at all: once
    /// bytes are signed the only two answers it gives are "a node took it"
    /// and "we do not know". `as_broadcast_error`'s own doc says that is
    /// deliberate and says why — it is what makes the 6b double-submit
    /// unconstructible in that module.
    ///
    /// **So a send failure now HOLDS.** The row stays `reserved`, the action
    /// nonce stays `allocated`, and only chain evidence may resolve it:
    /// reconciliation, or `outbox::sweep_stuck_reservations` once
    /// `lease_until` expires. That is the safe direction — releasing a nonce
    /// whose transaction may still be live is the hazard — but it is a real
    /// cost, disclosed on [`submit_sponsored_enrollment`]: a client that
    /// would have re-quoted in seconds must now wait for the sweeper.
    /// [`Retryability::Ambiguous`] is what tells it so.
    ///
    /// The retry arm at the end is what makes that concrete rather than
    /// asserted: the *same* call, against a healthy chain, is refused —
    /// where the deleted test had it succeed.
    ///
    /// MUTATION DETECTED (applied, run and reverted 2026-07-27): map
    /// `UnresolvedWithKnownHash` to `SubmitError::BroadcastFailed(detail)` —
    /// the "a failed send is final, tell the client to re-quote"
    /// classification this whole test argues against. Result:
    /// `682 passed; 4 failed`, this test among them, failing on `code()`.
    /// See
    /// [`broadcast_timeout_with_known_hash_does_not_release_the_nonce`] for
    /// the full list.
    ///
    /// **Not** verified by mutation, and stated rather than implied: adding a
    /// release of the *action* nonce to `sign_persist_and_broadcast`'s
    /// `SendFailedStuckRecoverable` arm would flip the `allocated` assertion
    /// below to `released` and stop the retry being refused — but no such
    /// release exists to delete, so there was no one-line mutation to run.
    #[tokio::test]
    async fn a_failed_send_holds_the_reservation_for_the_sweeper() {
        let f = fixture();
        let h = harness(&f).await;
        h.arm_send_failure("execution reverted: BadActionNonce");
        let failing = FakeSigner::ok();

        let err = submit_sponsored_enrollment(&h.ctx(&failing), &profile(), &f.parts())
            .await
            .expect_err("a failed send is an error, not a receipt");
        assert_eq!(err.code(), ERR_SUBMIT_BROADCAST_UNRESOLVED);
        assert_eq!(
            err.retryability(),
            Retryability::Ambiguous,
            "NOT Retryable: a re-quote here is the 6b double-submit"
        );
        assert!(
            err.revert().is_none(),
            "there is no decoded revert to report on this path: the send seam \
             returns a ChainError string, and `BroadcastOutcome` carries no revert name"
        );

        let held = text(
            &h.store,
            "SELECT status FROM nonce_allocations WHERE nonce = ?",
            f.intent.nonce.to_string(),
        )
        .await;
        assert_eq!(
            held.as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "THE HAZARD: the action nonce was released while a transaction that may still \
             execute is outstanding"
        );

        let attempt0 = tx_attempt_row_id(PROFILE, f.intent.intent_id, 0);

        // `tx_hash` still means "a node acknowledged this", and nothing did.
        assert_eq!(
            text(
                &h.store,
                "SELECT tx_hash FROM tx_attempts WHERE id = ?",
                attempt0.clone()
            )
            .await,
            None,
            "a failed send must not leave an acknowledged transaction"
        );
        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM tx_attempts WHERE id = ?",
                attempt0.clone()
            )
            .await
            .as_deref(),
            Some(TX_ATTEMPT_STATUS_RESERVED),
            "only 'reserved' rows are claimed by outbox::sweep_stuck_reservations"
        );

        // Paired non-NULL arm: the signed payload IS on the row, because the
        // path persists before it broadcasts. Without this arm the assertion
        // above would pass just as well against a path that never signed
        // anything — the state Task 8 Wave B removed.
        assert_eq!(
            text(
                &h.store,
                "SELECT raw_tx_hash FROM tx_attempts WHERE id = ?",
                attempt0.clone()
            )
            .await
            .as_deref(),
            Some(signed_raw().hash_hex().as_str()),
            "the reservation must have persisted the signed payload's hash"
        );
        assert_eq!(
            scalar_i64(
                &h.store,
                "SELECT COUNT(*) FROM tx_attempts WHERE id = ? AND raw_tx_enc IS NOT NULL",
                attempt0.clone()
            )
            .await,
            1,
            "the sealed payload must survive on the row so the sweeper can resolve it"
        );

        // 🔴 The retry arm, inverted. Before this wave the same call against
        // a healthy broadcaster succeeded here. It cannot now: the action
        // nonce is still held by the unresolved attempt, and that is the
        // whole point.
        h.chain.set_send_raw_transaction(Ok(TX_HASH));
        let ok = FakeSigner::ok();
        let second = submit_sponsored_enrollment(&h.ctx(&ok), &profile(), &f.parts())
            .await
            .expect_err("a re-quote against an unresolved attempt must be refused");
        assert_eq!(second.code(), ERR_SUBMIT_IN_FLIGHT);
        assert_eq!(second.retryability(), Retryability::Ambiguous);
        assert_eq!(
            h.sends(),
            1,
            "only the first submit reached the wire; the retry never did"
        );
    }

    // -------------------------------------------------------------------
    // Task 8 Wave B (Mandate 1) — one reservation, and it persists first.
    // -------------------------------------------------------------------

    /// 🔴 The property the whole merge exists for.
    ///
    /// The pre-merge production submit path reserved the action nonce with a
    /// local copy of the outbox's transaction that wrote **no** `raw_tx_enc`
    /// and **no** `raw_tx_hash`. A process death (or, as here, a send that
    /// times out with the transaction possibly live) therefore left a row the
    /// sweeper could neither name nor decode: `outbox::sweep_stuck_reservations`
    /// resolves a stuck row by fetching a receipt for `raw_tx_hash`, and that
    /// column was NULL by construction for every row this path had ever
    /// written. The recovery mechanism built in Task 7 was blind to the only
    /// path production runs.
    ///
    /// This asserts the fix through the **real §3.2 reverse lookup** rather
    /// than a hand-written `SELECT`, so it is the function reconciliation
    /// actually calls that has to see the payload.
    ///
    /// MUTATION DETECTED: make the reservation omit the payload — bind
    /// `None::<Vec<u8>>` to `raw_tx_enc` and `None::<String>` to `raw_tx_hash`
    /// in `outbox.rs`'s attempt-row insert, i.e. exactly what the deleted 6b
    /// copy wrote. Run 2026-07-25: this test failed with `left: 0, right: 1`
    /// on the `raw_tx_enc IS NOT NULL` assertion, alongside 8 others;
    /// reverted, suite green.
    ///
    /// **Which assertion does the work, stated rather than implied.** The
    /// `raw_tx_enc` count is what proves the reservation persisted anything.
    ///
    /// 🔴 **Wave C W2 correction.** This doc used to say the `raw_tx_hash`
    /// assertion "survives that mutation, because on *this* path
    /// `record_broadcast_unresolved` re-stamps the column with the hash the
    /// node reported". That is no longer true and, on the new path, could not
    /// be: there is no node-reported hash on an unresolved outcome —
    /// `broadcaster.rs` builds both unresolved shapes from `signed.hash()`
    /// and explicitly discards the node's on the one arm that has one
    /// (`SendOutcome::BroadcastNotRecorded`'s `tx_hash_hex: _`). The stamp
    /// therefore rewrites the column with the value the reservation already
    /// put there, so the `raw_tx_hash` assertion below **does** die with the
    /// mutation, alongside the `raw_tx_enc` one. The companion pin on the
    /// same column is
    /// [`a_failed_send_holds_the_reservation_for_the_sweeper`].
    #[tokio::test]
    async fn the_production_submit_path_leaves_a_row_the_sweeper_can_resolve() {
        let f = fixture();
        let h = harness(&f).await;

        // The 6b hazard shape: the payload went out, the answer never came.
        h.arm_send_failure("get_receipt timed out after 60s");
        let stuck = FakeSigner::ok();
        let err = submit_sponsored_enrollment(&h.ctx(&stuck), &profile(), &f.parts())
            .await
            .expect_err("unresolved");
        assert_eq!(err.code(), ERR_SUBMIT_BROADCAST_UNRESOLVED);
        assert_eq!(err.retryability(), Retryability::Ambiguous);

        // Signing preceded the send, which is the ordering that makes the
        // persistence possible at all.
        assert_eq!(stuck.sign_calls(), 1);
        assert_eq!(h.sends(), 1);

        let candidates =
            crate::stream_g::reconcile::candidates_for_intent_id(&h.store, f.intent.intent_id)
                .await
                .expect("reverse lookup");
        assert_eq!(candidates.len(), 1, "{candidates:?}");
        let c = &candidates[0];
        assert_eq!(c.status, TX_ATTEMPT_STATUS_RESERVED);
        // The hash of the payload THIS PROCESS SIGNED — see the doc above.
        assert_eq!(
            c.raw_tx_hash.as_deref(),
            Some(signed_raw().hash_hex().as_str())
        );
        // Paired NULL arm on the *other* hash column: `tx_hash` still means
        // "a node acknowledged this", and nothing did. Without this arm the
        // assertion above could be satisfied by a path that wrongly reported
        // the send as accepted.
        assert_eq!(c.tx_hash, None);

        // The sealed payload is on the row too — the half a hash cannot
        // substitute for, because a rebroadcast needs the bytes.
        assert_eq!(
            scalar_i64(
                &h.store,
                "SELECT COUNT(*) FROM tx_attempts WHERE id = ? AND raw_tx_enc IS NOT NULL",
                c.attempt_id.clone()
            )
            .await,
            1,
            "the signed payload must be sealed on the row before the broadcast"
        );

        // And the nonce is still held — releasing it here is the double-submit.
        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM nonce_allocations WHERE nonce = ?",
                f.intent.nonce.to_string()
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_ALLOCATED)
        );
    }

    /// Signing happens **before** the reservation, so a signing failure must
    /// claim nothing: no `tx_attempts` row, no `nonce_allocations` row, and no
    /// send.
    ///
    /// This is the ordering's one liability and the reason it is safe: bytes
    /// first means a failure to produce bytes cannot strand a claim.
    ///
    /// MUTATION DETECTED: make [`submit_sponsored_enrollment`] take the claim
    /// even when no bytes exist — the observable shape of reserving before
    /// signing — by calling `outbox::reserve_and_persist_raw_tx` with an empty
    /// `SignedRawTx` in the signing-failure arm. Run 2026-07-25: this test was
    /// the only failure, `left: 1, right: 0`, "a failed signature must not
    /// open an attempt row"; reverted, suite green.
    ///
    /// 🔴 **Wave C W2 amendment.** One claim IS taken before signing now, and
    /// this test says so rather than eliding it: the broadcaster EOA's
    /// transaction nonce, which `sign_persist_and_broadcast` allocates first
    /// because a signature has to name one. Its signing-failure arm releases
    /// it, and the last assertion here is that release. The classification is
    /// unchanged — `ERR_SUBMIT_BROADCAST_FAILED`, `Retryable` — because
    /// `broadcaster_error_from` maps `BroadcasterError::Signing` onto exactly
    /// the variant the deleted `classify_unbroadcast_failure` produced.
    #[tokio::test]
    async fn a_signing_failure_claims_nothing_because_it_reserved_nothing() {
        let f = fixture();
        let h = harness(&f).await;

        let broken = FakeSigner::cannot_sign();
        let err = submit_sponsored_enrollment(&h.ctx(&broken), &profile(), &f.parts())
            .await
            .expect_err("signing failed");
        assert_eq!(err.code(), ERR_SUBMIT_BROADCAST_FAILED);
        assert_eq!(
            err.retryability(),
            Retryability::Retryable,
            "nothing was claimed, persisted or sent, so a retry is free"
        );
        assert_eq!(broken.sign_calls(), 1);
        assert_eq!(h.sends(), 0, "nothing may be sent without bytes");
        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM nonce_allocations WHERE kind = 'broadcaster' AND nonce = ?",
                BROADCASTER_START_NONCE.to_string(),
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_RELEASED),
            "a failed signature must give the broadcaster EOA nonce back"
        );

        let intent_row = intent_row_id(PROFILE, f.intent.intent_id);
        assert_eq!(
            scalar_i64(
                &h.store,
                "SELECT COUNT(*) FROM tx_attempts WHERE intent_id = ?",
                intent_row.clone()
            )
            .await,
            0,
            "a failed signature must not open an attempt row"
        );
        assert_eq!(
            scalar_i64(
                &h.store,
                "SELECT COUNT(*) FROM nonce_allocations WHERE nonce = ?",
                f.intent.nonce.to_string()
            )
            .await,
            0,
            "a failed signature must not claim the action nonce"
        );

        // Paired non-zero arm: the very same fixture, store and nonce DO
        // produce one of each once the signer works — so the zeros above are
        // the signing failure's doing, not an inert query.
        let ok = FakeSigner::ok();
        submit_sponsored_enrollment(&h.ctx(&ok), &profile(), &f.parts())
            .await
            .expect("submit");
        assert_eq!(
            scalar_i64(
                &h.store,
                "SELECT COUNT(*) FROM tx_attempts WHERE intent_id = ?",
                intent_row
            )
            .await,
            1
        );
        assert_eq!(
            scalar_i64(
                &h.store,
                "SELECT COUNT(*) FROM nonce_allocations WHERE nonce = ?",
                f.intent.nonce.to_string()
            )
            .await,
            1
        );
    }

    /// The reservation is a compare-and-swap, and the submit path is now one
    /// of its owners: the row is stamped with `ctx.claim_owner` and the
    /// post-send `record_broadcast_accepted` only succeeds against that same
    /// owner.
    ///
    /// MUTATION DETECTED: pass a literal `"someone-else"` instead of
    /// `ctx.claim_owner` to `outbox::record_broadcast_accepted` in
    /// [`submit_sponsored_enrollment`]. Run 2026-07-25: this test died at the
    /// paired arm's `expect("submit")` because the compare-and-swap no longer
    /// matches the row's `claim_owner`; 16 tests failed in total, which is the
    /// measure of how much of this module's behaviour now flows through that
    /// one call. Reverted, suite green.
    #[tokio::test]
    async fn the_reservation_records_the_submit_paths_claim_owner() {
        let f = fixture();
        let h = harness(&f).await;

        // A row that is still `reserved` keeps its claim, so use the
        // unresolved shape to observe it.
        h.arm_send_failure("get_receipt timed out after 60s");
        let stuck = FakeSigner::ok();
        submit_sponsored_enrollment(&h.ctx(&stuck), &profile(), &f.parts())
            .await
            .expect_err("unresolved");
        h.chain.set_send_raw_transaction(Ok(TX_HASH));
        let attempt0 = tx_attempt_row_id(PROFILE, f.intent.intent_id, 0);
        assert_eq!(
            text(
                &h.store,
                "SELECT claim_owner FROM tx_attempts WHERE id = ?",
                attempt0.clone()
            )
            .await
            .as_deref(),
            Some(CLAIM_OWNER),
            "the reservation must record who holds it"
        );

        // Paired arm on a *different* intent that completes: an accepted
        // broadcast hands the claim back, so `claim_owner` is NULL there. The
        // column therefore tracks the claim rather than merely being stamped.
        let mut g = fixture();
        g.intent.intent_id = [0x62; 32];
        g.intent.nonce = f.intent.nonce + 1;
        g.rebind_quote();
        seed_quote(&h.store, &g, PROFILE).await;
        h.chain
            .set_nonce_snapshot(GATEWAY, ROOT, addr(SECONDARY_KEY), FEE_TOKEN, {
                let mut s = snapshot(fee_token_config_hash(&token_cfg()));
                s.action_nonce = g.intent.nonce as u128;
                s
            });
        let ok = FakeSigner::ok();
        let receipt = submit_sponsored_enrollment(&h.ctx(&ok), &profile(), &g.parts())
            .await
            .expect("submit");
        assert_eq!(
            text(
                &h.store,
                "SELECT claim_owner FROM tx_attempts WHERE id = ?",
                receipt.tx_attempt_id
            )
            .await,
            None,
            "an accepted broadcast must hand the claim back"
        );
    }

    /// The structural guarantee that Mandate 1 cannot silently regress.
    ///
    /// `submit::reserve_action_nonce` was not made unreachable, it was
    /// **deleted**; this module now owns no statement that opens a
    /// `tx_attempts` row or claims a `nonce_allocations` row. A future edit
    /// that re-introduces a second reservation here — the exact way the two
    /// implementations drifted apart in the first place — fails this test
    /// before it can drift.
    ///
    /// Mutation this detects: pasting an `INSERT OR IGNORE` against either of
    /// those two tables back into this file. (The needles are assembled at
    /// runtime, and this doc deliberately does not spell either of them out,
    /// so the scan cannot match its own source.)
    #[test]
    fn this_module_contains_no_reservation_of_its_own() {
        let src = include_str!("submit.rs");
        for table in ["tx_attempts", "nonce_allocations"] {
            let needle = format!("INTO {table}");
            assert!(
                !src.contains(&needle),
                "submit.rs must not insert into `{table}`: \
                 `outbox::reserve_and_persist_raw_tx` is the crate's only reservation \
                 (Task 8 Wave B, Mandate 1)"
            );
        }
        // Paired positive arm: the scan is looking at the real source and the
        // needle shape does occur for tables this module legitimately writes,
        // so a green result above is not just a typo in the needle.
        assert!(
            src.contains(&format!("INTO {}", "reconciliation_events")),
            "the scan must be reading this module's real SQL"
        );
    }

    /// Task 7 Wave D. The **production** reservation must stamp the plaintext
    /// `intentId` onto the attempt row, on **both** of its branches, or the
    /// §3.2 reverse lookup is structurally blind to every row this path writes
    /// and the log-driven reconciler can never find real traffic.
    ///
    /// This drives the real [`submit_sponsored_enrollment`] rather than
    /// re-typing its SQL, so it is the actual statement under test.
    ///
    /// MUTATION DETECTED (re-pointed and re-run for Task 8 Wave B): bind
    /// `None::<String>` instead of `&intent_id_hex` in
    /// `outbox::reserve_and_persist_raw_tx`'s attempt insert. Asserted on
    /// attempt 0 AND on the retry's attempt 1 — Task 7 Wave E replaced the
    /// reuse `UPDATE` with a second `INSERT`, so "both branches" is now "both
    /// attempts", and a mutation that stamped only the first row would still
    /// fail here because the reverse lookup must return two rows. Run
    /// 2026-07-25: this test failed along with 17 others across `outbox` and
    /// `reconcile`; reverted, suite green.
    #[tokio::test]
    async fn the_production_reservation_stamps_intent_id_hex_on_every_attempt() {
        let f = fixture();
        let h = harness(&f).await;
        let attempt0 = tx_attempt_row_id(PROFILE, f.intent.intent_id, 0);
        let attempt1 = tx_attempt_row_id(PROFILE, f.intent.intent_id, 1);
        assert_ne!(attempt0, attempt1, "the attempt number must change the id");
        let expected = bytes32_hex(f.intent.intent_id);

        // Attempt 0. A failed send leaves this row `reserved`; the sweeper
        // stand-in then resolves it, which is what makes attempt 1 reachable
        // below. (Wave C W2: the submit path itself no longer releases.)
        h.arm_send_failure("execution reverted: BadActionNonce");
        let failing = FakeSigner::ok();
        submit_sponsored_enrollment(&h.ctx(&failing), &profile(), &f.parts())
            .await
            .expect_err("failed send");
        assert_eq!(
            text(
                &h.store,
                "SELECT intent_id_hex FROM tx_attempts WHERE id = ?",
                attempt0.clone()
            )
            .await
            .as_deref(),
            Some(expected.as_str()),
            "attempt 0 must write intent_id_hex"
        );
        h.resolve_attempt_as_swept(&attempt0, "execution reverted: BadActionNonce")
            .await;

        // Attempt 1 — a NEW row, not a rewrite of attempt 0.
        h.chain.set_send_raw_transaction(Ok(TX_HASH));
        let ok = FakeSigner::ok();
        submit_sponsored_enrollment(&h.ctx(&ok), &profile(), &f.parts())
            .await
            .expect("retry");
        assert_eq!(
            text(
                &h.store,
                "SELECT intent_id_hex FROM tx_attempts WHERE id = ?",
                attempt1.clone()
            )
            .await
            .as_deref(),
            Some(expected.as_str()),
            "attempt 1 must write intent_id_hex"
        );

        // And the reverse lookup really does find them — the property all of
        // this exists for, asserted against the live function rather than a
        // hand-written SELECT.
        let candidates =
            crate::stream_g::reconcile::candidates_for_intent_id(&h.store, f.intent.intent_id)
                .await
                .expect("reverse lookup");
        assert_eq!(candidates.len(), 2, "{candidates:?}");
        let ids: Vec<&str> = candidates.iter().map(|c| c.attempt_id.as_str()).collect();
        assert!(ids.contains(&attempt0.as_str()), "{ids:?}");
        assert!(ids.contains(&attempt1.as_str()), "{ids:?}");
        for c in &candidates {
            assert_eq!(c.profile_id, PROFILE);
        }
    }

    // -------------------------------------------------------------------
    // Task 7 Wave E (A4) — replacement support.
    // -------------------------------------------------------------------

    /// 🔴 The A4 property, on the **production** submit path.
    ///
    /// Before Wave E the retry path ran
    ///
    /// ```sql
    /// UPDATE tx_attempts SET nonce_allocation_id = ?, status = ?, error_message = NULL,
    ///                        tx_hash = NULL, submitted_at = NULL, created_at = ?
    ///  WHERE id = ?
    /// ```
    ///
    /// which erased why the previous attempt failed and what transaction it
    /// named. A gas-bumped replacement — a second signed payload against the
    /// same action nonce, **either of which can land** — was therefore
    /// unrepresentable, and after a crash there was nothing left to resolve the
    /// survivor against.
    ///
    /// MUTATION DETECTED (re-pointed and re-run for Task 8 Wave B): bind a
    /// constant `0` instead of `next_attempt_number` when deriving the attempt
    /// id in `outbox::reserve_and_persist_raw_tx`. The retry then addresses
    /// attempt 0's existing primary key, `INSERT OR IGNORE` affects zero rows,
    /// and the retry fails `InFlight`/`SubmitInFlight` instead of opening a
    /// replacement. Run 2026-07-25 against the merged path: this test failed
    /// along with 5 others; reverted, suite green.
    #[tokio::test]
    async fn a_replacement_attempt_preserves_the_prior_attempts_terminal_record() {
        let f = fixture();
        let h = harness(&f).await;
        let attempt0 = tx_attempt_row_id(PROFILE, f.intent.intent_id, 0);
        let attempt1 = tx_attempt_row_id(PROFILE, f.intent.intent_id, 1);

        // Wave C W2: a failed send leaves attempt 0 `reserved` with its
        // `error_message` written by `record_broadcast_unresolved`; the
        // sweeper stand-in then makes it terminal.
        h.arm_send_failure("execution reverted: BadActionNonce");
        let failing = FakeSigner::ok();
        submit_sponsored_enrollment(&h.ctx(&failing), &profile(), &f.parts())
            .await
            .expect_err("failed send");
        let err0 = text(
            &h.store,
            "SELECT error_message FROM tx_attempts WHERE id = ?",
            attempt0.clone(),
        )
        .await
        .expect("attempt 0 must record why it failed");
        assert!(err0.contains("BadActionNonce"), "{err0}");
        h.resolve_attempt_as_swept(&attempt0, &err0).await;

        h.chain.set_send_raw_transaction(Ok(TX_HASH));
        let ok = FakeSigner::ok();
        let receipt = submit_sponsored_enrollment(&h.ctx(&ok), &profile(), &f.parts())
            .await
            .expect("retry");
        assert_eq!(
            receipt.tx_attempt_id, attempt1,
            "the replacement must be attempt 1"
        );

        // Attempt 0 is untouched: same terminal status, same error text, still
        // no transaction hash.
        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM tx_attempts WHERE id = ?",
                attempt0.clone()
            )
            .await
            .as_deref(),
            Some(TX_ATTEMPT_STATUS_FAILED),
            "attempt 0 must stay terminal"
        );
        assert_eq!(
            text(
                &h.store,
                "SELECT error_message FROM tx_attempts WHERE id = ?",
                attempt0.clone()
            )
            .await,
            Some(err0),
            "attempt 0's evidence must survive its replacement"
        );
        assert_eq!(
            text(
                &h.store,
                "SELECT tx_hash FROM tx_attempts WHERE id = ?",
                attempt0.clone()
            )
            .await,
            None
        );
        // Paired non-zero arm: attempt 1 really is a DIFFERENT, live row — so
        // the assertions above are not just describing a table with one row in
        // it that nothing ever wrote twice.
        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM tx_attempts WHERE id = ?",
                attempt1.clone()
            )
            .await
            .as_deref(),
            Some(TX_ATTEMPT_STATUS_SUBMITTED)
        );
        assert_eq!(
            scalar_i64(
                &h.store,
                "SELECT COUNT(*) FROM tx_attempts WHERE intent_id = ?",
                intent_row_id(PROFILE, f.intent.intent_id)
            )
            .await,
            2,
            "one row per attempt"
        );
        assert_eq!(
            scalar_i64(
                &h.store,
                "SELECT attempt_number FROM tx_attempts WHERE id = ?",
                attempt1
            )
            .await,
            1
        );
    }

    /// `SubmitInFlight` must key on "is ANY attempt for this intent live",
    /// not on "does this one derived row id exist" — the two stopped being the
    /// same question the moment an intent could own several rows.
    ///
    /// MUTATION DETECTED (re-pointed and re-run for Task 8 Wave B): delete the
    /// `TX_ATTEMPT_STATUS_RESERVED` arm from
    /// `outbox::reserve_and_persist_raw_tx`'s scan. The second submit then no
    /// longer reports `SubmitInFlight` (it falls through to the
    /// `nonce_allocations` holder check and reports `NonceAlreadyReserved`),
    /// and this test fails on the error code. Run 2026-07-25: three failures —
    /// this one, `broadcast_timeout_with_known_hash_does_not_release_the_nonce`
    /// and `outbox::tests::a_retry_after_release_is_a_new_attempt_number`;
    /// reverted, suite green. That the nonce guard also catches it is defence
    /// in depth, not a reason to drop this one — that guard cannot name the
    /// live attempt, and `SubmitInFlight` is what a client polls on.
    #[tokio::test]
    async fn submit_in_flight_keys_on_any_live_attempt_and_names_it() {
        let f = fixture();
        let h = harness(&f).await;

        // An unresolved broadcast leaves attempt 0 `reserved` and holding the
        // nonce — the 6b state the outbox exists for.
        h.arm_send_failure("get_receipt timed out after 60s");
        let stuck = FakeSigner::ok();
        submit_sponsored_enrollment(&h.ctx(&stuck), &profile(), &f.parts())
            .await
            .expect_err("unresolved");

        h.chain.set_send_raw_transaction(Ok(TX_HASH));
        let ok = FakeSigner::ok();
        let err = submit_sponsored_enrollment(&h.ctx(&ok), &profile(), &f.parts())
            .await
            .expect_err("a live attempt must exclude a second one");
        assert_eq!(err.code(), ERR_SUBMIT_IN_FLIGHT);
        match err {
            SubmitError::SubmitInFlight { attempt_id } => assert_eq!(
                attempt_id,
                tx_attempt_row_id(PROFILE, f.intent.intent_id, 0),
                "it must name the LIVE attempt, not the one it was about to open"
            ),
            other => panic!("{other:?}"),
        }
        // Nothing was broadcast beyond the first submit, and no second row
        // was opened. (`h.sends()` is cumulative, so 1 is "the retry never
        // reached the wire".)
        assert_eq!(ok.sign_calls(), 1, "the retry did reach the signer");
        assert_eq!(h.sends(), 1);
        assert_eq!(
            scalar_i64(
                &h.store,
                "SELECT COUNT(*) FROM tx_attempts WHERE intent_id = ?",
                intent_row_id(PROFILE, f.intent.intent_id)
            )
            .await,
            1
        );

        // Paired non-`SubmitInFlight` arm: a TERMINAL prior attempt does not
        // block, so the guard is not simply "any prior row refuses".
        let g = fixture();
        let hg = harness(&g).await;
        hg.arm_send_failure("execution reverted: BadActionNonce");
        let failing = FakeSigner::ok();
        submit_sponsored_enrollment(&hg.ctx(&failing), &profile(), &g.parts())
            .await
            .expect_err("failed send");
        hg.resolve_attempt_as_swept(
            &tx_attempt_row_id(PROFILE, g.intent.intent_id, 0),
            "execution reverted: BadActionNonce",
        )
        .await;
        hg.chain.set_send_raw_transaction(Ok(TX_HASH));
        let ok2 = FakeSigner::ok();
        submit_sponsored_enrollment(&hg.ctx(&ok2), &profile(), &g.parts())
            .await
            .expect("a failed attempt must not block its replacement");
        assert_eq!(hg.sends(), 2, "the replacement really did broadcast");
    }

    /// The single-use-intent invariant survives A4.
    ///
    /// `intentUsed[intentId]` is global and single-use
    /// (`GoatRelayGateway.sol:315-323`), so at most one attempt can ever land.
    /// Allowing many attempt ROWS must not allow many attempt BROADCASTS.
    ///
    /// MUTATION DETECTED (re-pointed and re-run for Task 8 Wave B): delete the
    /// `SUBMITTED | CONFIRMED` arm from
    /// `outbox::reserve_and_persist_raw_tx`'s scan — a second broadcast is
    /// then attempted against an intent that already landed, which burns
    /// relayer ETH reverting `IntentAlreadyUsed`. Run 2026-07-25: this test
    /// and `resubmitting_a_landed_intent_is_refused_with_the_stored_tx_hash`
    /// failed; reverted, suite green.
    #[tokio::test]
    async fn a_landed_attempt_refuses_every_replacement() {
        let f = fixture();
        let h = harness(&f).await;
        let ok = FakeSigner::ok();
        submit_sponsored_enrollment(&h.ctx(&ok), &profile(), &f.parts())
            .await
            .expect("submit");

        let second = FakeSigner::ok();
        let err = submit_sponsored_enrollment(&h.ctx(&second), &profile(), &f.parts())
            .await
            .expect_err("a landed intent must not be replaced");
        assert_eq!(err.code(), ERR_SUBMIT_ALREADY_SUBMITTED);
        match err {
            SubmitError::AlreadySubmitted { tx_hash_hex } => {
                // Non-empty arm: it reports the REAL hash, not a default.
                assert_eq!(tx_hash_hex, bytes32_hex(TX_HASH));
                assert_ne!(tx_hash_hex, "");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(h.sends(), 1, "no second broadcast");
        assert_eq!(second.sign_calls(), 1, "but it did reach the signer");
        assert_eq!(
            scalar_i64(
                &h.store,
                "SELECT COUNT(*) FROM tx_attempts WHERE intent_id = ?",
                intent_row_id(PROFILE, f.intent.intent_id)
            )
            .await,
            1,
            "no replacement row may be opened for a landed intent"
        );
    }

    /// Reconcile can no longer DERIVE the attempt row id — the attempt number
    /// is part of it. It selects among an intent's attempts by transaction
    /// hash, which is sound because only one attempt can ever have executed.
    ///
    /// MUTATION DETECTED: replace the `find(|arow| tx_hash == event hash)` with
    /// `arows.first()`. Attempt 0 (terminal, `tx_hash` NULL) is then chosen and
    /// stamped `confirmed` with somebody else's hash, while the attempt that
    /// actually landed stays `submitted`. Verified: this test failed on both
    /// status assertions; reverted.
    #[tokio::test]
    async fn reconcile_selects_the_attempt_whose_tx_hash_matches_among_several() {
        let f = fixture();
        let h = harness(&f).await;
        let attempt0 = tx_attempt_row_id(PROFILE, f.intent.intent_id, 0);
        let attempt1 = tx_attempt_row_id(PROFILE, f.intent.intent_id, 1);

        h.arm_send_failure("execution reverted: BadActionNonce");
        let failing = FakeSigner::ok();
        submit_sponsored_enrollment(&h.ctx(&failing), &profile(), &f.parts())
            .await
            .expect_err("failed send");
        h.resolve_attempt_as_swept(&attempt0, "execution reverted: BadActionNonce")
            .await;
        h.chain.set_send_raw_transaction(Ok(TX_HASH));
        let ok = FakeSigner::ok();
        submit_sponsored_enrollment(&h.ctx(&ok), &profile(), &f.parts())
            .await
            .expect("retry");

        let event = SponsoredEnrollmentExecuted {
            intent_id: f.intent.intent_id,
            root: f.intent.root,
            secondary: f.intent.secondary,
            controller: f.intent.controller,
            fee_token: f.intent.fee_token,
            fee_amount: f.quote.fee_amount,
            tx_hash: TX_HASH,
            block: BLOCK + 1,
        };
        reconcile_sponsored_enrollment_executed(&h.store, &data_key_hex(), &profile(), &event, WALL_NOW)
            .await
            .expect("reconcile");

        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM tx_attempts WHERE id = ?",
                attempt1.clone()
            )
            .await
            .as_deref(),
            Some(TX_ATTEMPT_STATUS_CONFIRMED),
            "the attempt whose hash matches is the one that is confirmed"
        );
        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM tx_attempts WHERE id = ?",
                attempt0.clone()
            )
            .await
            .as_deref(),
            Some(TX_ATTEMPT_STATUS_FAILED),
            "a terminal sibling must not be dragged into the confirmation"
        );

        // Paired refusal arm: an event for a transaction none of the attempts
        // named is still a mismatch, so "find by hash" is not "find anything".
        let mut other = event;
        other.tx_hash = [0x7E; 32];
        let err =
            reconcile_sponsored_enrollment_executed(&h.store, &data_key_hex(), &profile(), &other, WALL_NOW)
                .await
                .expect_err("an unrelated transaction is not this intent's confirmation");
        assert!(
            matches!(err, SubmitError::ReconcileMismatch { field: "tx_hash" }),
            "{err:?}"
        );
    }

    /// 🔴 The Task 6b double-submit hazard, closed.
    ///
    /// `rpc_chain.rs`'s send path blocks 15s for the send and then 60s for
    /// the receipt (`:264-278`). A receipt timeout on a transaction that
    /// **did** reach the mempool used to arrive here as
    /// `revert: None` → `BroadcastFailed` → `Retryable` → `record_failed`,
    /// which released the action nonce while the transaction was still
    /// live. A re-quote would then sign a second transaction against the
    /// same `actionNonces[controller][SPONSORED_ENROLLMENT]`.
    ///
    /// 🔴 **Wave C W2 re-pointing.** The mutation this test used to name —
    /// deleting the `Err(err) if err.tx_hash.is_some()` arm so every `Err`
    /// fell through to `record_failed` — no longer exists to make: there is
    /// no `record_failed` and no no-hash arm.
    /// [`broadcaster::BroadcastOutcome`] cannot express the shape that used
    /// to release. What this test now pins is that the *outcome* mapping
    /// stayed on the safe side of that: `UnresolvedWithKnownHash` →
    /// `SubmitError::BroadcastUnresolved` → `Ambiguous`, nonce held.
    ///
    /// MUTATION DETECTED (applied, run and reverted 2026-07-27): map
    /// `UnresolvedWithKnownHash` to `SubmitError::BroadcastFailed(detail)` in
    /// this module's step-5 match — which is what "treat a failed send as
    /// final" looks like now. Result: `682 passed; 4 failed` — this test,
    /// [`a_failed_send_holds_the_reservation_for_the_sweeper`],
    /// [`signing_lease_is_released_after_a_failed_submit`] and
    /// [`the_production_submit_path_leaves_a_row_the_sweeper_can_resolve`].
    /// Here it fails on `retryability()` / `code()`, **not** on the row or
    /// nonce assertions — which stay green under the mutation. That is
    /// precisely why the classification is asserted separately from the store
    /// state: a client told `Retryable` will re-quote against a nonce whose
    /// transaction may still be live, and the store looks fine while it does.
    ///
    /// Paired non-zero arm (the I7 guard): a zero-assertion on sends is
    /// worthless on its own, so this test asserts a non-zero `h.sends() == 1`
    /// before asserting the resubmit adds none.
    #[tokio::test]
    async fn broadcast_timeout_with_known_hash_does_not_release_the_nonce() {
        let f = fixture();
        let h = harness(&f).await;
        h.arm_send_failure("get_receipt timed out after 60s");
        let timing_out = FakeSigner::ok();

        let err = submit_sponsored_enrollment(&h.ctx(&timing_out), &profile(), &f.parts())
            .await
            .expect_err("receipt timeout");
        assert_eq!(err.code(), ERR_SUBMIT_BROADCAST_UNRESOLVED);
        assert_eq!(
            err.retryability(),
            Retryability::Ambiguous,
            "an unknown outcome must never tell a client to re-quote"
        );
        assert_eq!(
            h.sends(),
            1,
            "non-zero arm: the transaction really did reach the wire once"
        );

        // (1) The nonce is HELD. This is the whole fix.
        let held = text(
            &h.store,
            "SELECT status FROM nonce_allocations WHERE nonce = ?",
            f.intent.nonce.to_string(),
        )
        .await;
        assert_eq!(
            held.as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "a transaction with a known hash may still execute; releasing its \
             action nonce is the 6b double-submit"
        );

        // (2) The row carries what the sweeper needs to resolve it.
        let attempt = tx_attempt_row_id(PROFILE, f.intent.intent_id, 0);
        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM tx_attempts WHERE id = ?",
                attempt.clone()
            )
            .await
            .as_deref(),
            Some(TX_ATTEMPT_STATUS_RESERVED),
            "only 'reserved' rows are claimed by outbox::sweep_stuck_reservations"
        );
        assert_eq!(
            text(
                &h.store,
                "SELECT raw_tx_hash FROM tx_attempts WHERE id = ?",
                attempt.clone()
            )
            .await,
            Some(signed_raw().hash_hex()),
            "without raw_tx_hash the sweeper cannot ask for a receipt"
        );
        assert_eq!(
            text(
                &h.store,
                "SELECT intent_id_hex FROM tx_attempts WHERE id = ?",
                attempt.clone()
            )
            .await,
            Some(bytes32_hex(f.intent.intent_id)),
            "without intent_id_hex the sweeper cannot ask intentUsed(intentId)"
        );
        let lease = scalar_i64(
            &h.store,
            "SELECT COUNT(*) FROM tx_attempts WHERE id = ? AND lease_until IS NOT NULL",
            attempt.clone(),
        )
        .await;
        assert_eq!(lease, 1, "the sweeper's trigger needs a lease_until");

        // (3) And the hold actually bites: a resubmit is refused without
        //     reaching the wire.
        h.chain.set_send_raw_transaction(Ok(TX_HASH));
        let ok = FakeSigner::ok();
        let again = submit_sponsored_enrollment(&h.ctx(&ok), &profile(), &f.parts())
            .await
            .expect_err("a live transaction must not be re-broadcast");
        assert_eq!(again.code(), ERR_SUBMIT_IN_FLIGHT);
        assert_eq!(h.sends(), 1, "no second transaction against this nonce");
    }

    /// Re-submitting an intent that already landed must return the stored
    /// hash, not broadcast a second transaction against a single-use
    /// `intentUsed[intentId]`.
    #[tokio::test]
    async fn resubmitting_a_landed_intent_is_refused_with_the_stored_tx_hash() {
        let f = fixture();
        let h = harness(&f).await;
        let b = FakeSigner::ok();

        submit_sponsored_enrollment(&h.ctx(&b), &profile(), &f.parts())
            .await
            .expect("first submit");
        let err = submit_sponsored_enrollment(&h.ctx(&b), &profile(), &f.parts())
            .await
            .expect_err("second submit");
        assert_eq!(err.code(), ERR_SUBMIT_ALREADY_SUBMITTED);
        assert!(matches!(
            err,
            SubmitError::AlreadySubmitted { ref tx_hash_hex } if *tx_hash_hex == bytes32_hex(TX_HASH)
        ));
        assert_eq!(h.sends(), 1, "no second broadcast");
    }

    // -------------------------------------------------------------------
    // Revalidation (hazard 2, mechanism 2).
    // -------------------------------------------------------------------

    /// The submit path must re-read the snapshot itself, not trust the
    /// quote's. Moving the live action nonce after the quote was stored must
    /// stop the submit before the broadcaster is reached.
    ///
    /// Mutation this detects: deleting the
    /// `read_live_preflight_state` + `preflight_sponsored_enrollment` block
    /// from [`submit_sponsored_enrollment`] — the drifted nonce would be
    /// broadcast and revert on chain.
    #[tokio::test]
    async fn submit_re_reads_the_snapshot_and_fails_closed_on_action_nonce_drift() {
        let f = fixture();
        let h = harness(&f).await;
        let b = FakeSigner::ok();

        // Someone else consumed the controller's action nonce between quote
        // and submit — precisely what the advisory snapshot cannot prevent.
        let cfg_hash = fee_token_config_hash(&token_cfg());
        let mut drifted = snapshot(cfg_hash);
        drifted.action_nonce = LIVE_ACTION_NONCE + 1;
        h.chain
            .set_nonce_snapshot(GATEWAY, ROOT, addr(SECONDARY_KEY), FEE_TOKEN, drifted);

        let err = submit_sponsored_enrollment(&h.ctx(&b), &profile(), &f.parts())
            .await
            .expect_err("drifted action nonce");
        assert_eq!(err.code(), preflight::ERR_PREFLIGHT_WOULD_REVERT);
        assert_eq!(
            err.retryability(),
            Retryability::Retryable,
            "a consumed action nonce is a re-quote, not a dead end"
        );
        assert_eq!(h.sends(), 0);

        let reserved = scalar_i64(
            &h.store,
            "SELECT COUNT(*) FROM nonce_allocations WHERE nonce = ?",
            f.intent.nonce.to_string(),
        )
        .await;
        assert_eq!(reserved, 0, "revalidation must run BEFORE the reservation");
    }

    /// The second of the two confirmations: `linkSecondary`'s
    /// `linkNonces[secondary]`. Drift there must also fail closed.
    ///
    /// Mutation this detects: reading the link nonce from the call instead
    /// of from the re-read snapshot.
    #[tokio::test]
    async fn submit_fails_closed_on_link_nonce_drift() {
        let f = fixture();
        let h = harness(&f).await;
        let b = FakeSigner::ok();

        let cfg_hash = fee_token_config_hash(&token_cfg());
        let mut drifted = snapshot(cfg_hash);
        drifted.link_nonce = LIVE_LINK_NONCE + 1;
        h.chain
            .set_nonce_snapshot(GATEWAY, ROOT, addr(SECONDARY_KEY), FEE_TOKEN, drifted);

        let err = submit_sponsored_enrollment(&h.ctx(&b), &profile(), &f.parts())
            .await
            .expect_err("drifted link nonce");
        assert_eq!(err.code(), preflight::ERR_PREFLIGHT_WOULD_REVERT);
        assert_eq!(err.retryability(), Retryability::Retryable);
        assert_eq!(h.sends(), 0);
    }

    /// Controller-epoch drift is the terminal case: the cluster rotated its
    /// controller, so a re-quote would relay a bundle authorized by a
    /// controller that has since been replaced.
    #[tokio::test]
    async fn controller_epoch_drift_is_terminal_not_retryable() {
        let f = fixture();
        let h = harness(&f).await;
        let b = FakeSigner::ok();

        let cfg_hash = fee_token_config_hash(&token_cfg());
        let mut drifted = snapshot(cfg_hash);
        drifted.controller_epoch = LIVE_CONTROLLER_EPOCH + 1;
        h.chain
            .set_nonce_snapshot(GATEWAY, ROOT, addr(SECONDARY_KEY), FEE_TOKEN, drifted);

        let err = submit_sponsored_enrollment(&h.ctx(&b), &profile(), &f.parts())
            .await
            .expect_err("drifted controller epoch");
        assert_eq!(err.code(), preflight::ERR_PREFLIGHT_WOULD_REVERT);
        assert_eq!(err.retryability(), Retryability::Terminal);
        assert_eq!(h.sends(), 0);
    }

    /// The check a `PreflightError::WouldRevert` named, or a panic naming
    /// what came instead. Used by the W3 revalidation tests below, all of
    /// which assert on a *specific* check rather than on the shared code.
    fn would_revert_check(err: &SubmitError) -> Check {
        match err {
            SubmitError::Preflight(PreflightError::WouldRevert { check, .. }) => *check,
            other => panic!("expected PreflightError::WouldRevert, got {other:?}"),
        }
    }

    // --- W3: the wire DTO --------------------------------------------------

    /// The request body a correct client sends for [`fixture`] — every
    /// field the DTO declares except the seven `#[serde(default)]`
    /// `root_authorization_*` ones, which the contract requires absent/zero.
    fn request_json_for(f: &Fixture) -> serde_json::Value {
        serde_json::json!({
            "intent_id_hex": bytes32_hex(f.intent.intent_id),
            "deployment_manifest_hash_hex": bytes32_hex(f.intent.deployment_manifest_hash),
            "fee_token_config_hash_hex": bytes32_hex(f.intent.fee_token_config_hash),
            "root_address": address_hex(f.intent.root),
            "controller_address": address_hex(f.intent.controller),
            "controller_epoch": f.intent.controller_epoch,
            "secondary_address": address_hex(f.intent.secondary),
            "enroll_digest_hex": bytes32_hex(f.intent.enroll_digest),
            "link_digest_hex": bytes32_hex(f.intent.link_digest),
            "root_authorization_digest_hex": bytes32_hex(f.intent.root_authorization_digest),
            "fee_token_address": address_hex(f.intent.fee_token),
            "fee_authorization_mode": f.intent.fee_authorization_mode,
            "fee_authorization_digest_hex": bytes32_hex(f.intent.fee_authorization_digest),
            "max_fee": f.intent.max_fee.to_string(),
            "fee_quote_hash_hex": bytes32_hex(f.intent.fee_quote_hash),
            "nonce": f.intent.nonce,
            "deadline": f.intent.deadline,
            "sponsor_signature_hex": f.sponsor_sig,
            "v1_nonce": f.v1.nonce,
            "v1_deadline": f.v1.deadline,
            "v1_signature_hex": f.v1.signature_hex,
            "link_nonce": f.link.nonce,
            "link_deadline": f.link.deadline,
            "link_signature_hex": f.link_sig,
            "fee_eip2612_value": f.eip2612.value.to_string(),
            "fee_eip2612_deadline": f.eip2612.deadline,
            "fee_eip2612_v": f.eip2612.v,
            "fee_eip2612_r_hex": bytes32_hex(f.eip2612.r),
            "fee_eip2612_s_hex": bytes32_hex(f.eip2612.s),
        })
    }

    /// The DTO really produces the call the rest of this module's tests
    /// drive, including the five values it deliberately does **not** accept
    /// (`v1.wallet`, `link.root`, `link.secondary`, `eip2612.owner`,
    /// `eip2612.spender`) and the all-zero `RootAuthorization` its seven
    /// optional fields default to.
    ///
    /// This is what makes every other test in this module evidence about the
    /// wire shape and not only about `SubmitCallParts`: the two are proved
    /// equal here.
    ///
    /// Mutation this detects: deriving any of the five from the wrong source
    /// (e.g. `v1.wallet = intent.root`), or giving one of the
    /// `root_authorization_*` defaults a non-zero value.
    #[test]
    fn the_wire_dto_parses_into_exactly_the_fixture_parts() {
        let f = fixture();
        let body = request_json_for(&f).to_string();

        let req: SubmitSponsoredEnrollmentRequest =
            serde_json::from_str(&body).expect("the fixture body must deserialize");
        let parsed = req.parse(GATEWAY).expect("the fixture body must parse");
        let expected = f.parts();

        assert_eq!(parsed.intent, expected.intent);
        assert_eq!(parsed.v1_enrollment, expected.v1_enrollment);
        assert_eq!(parsed.link, expected.link);
        assert_eq!(parsed.fee_authorization_mode, expected.fee_authorization_mode);
        assert_eq!(
            parsed.fee_eip2612_authorization,
            expected.fee_eip2612_authorization
        );
        assert_eq!(parsed.sponsor_signature_hex, expected.sponsor_signature_hex);
        assert_eq!(parsed.link_signature_hex, expected.link_signature_hex);

        // The omitted block defaults to the only value the contract accepts.
        assert!(
            parsed.root_authorization.is_all_zero(),
            "an omitted root_authorization block must default to all-zero"
        );
        assert!(
            parsed.root_authorization_signature_hex.is_empty(),
            "an omitted root_authorization signature must default to empty"
        );
        assert_eq!(parsed.root_authorization, expected.root_authorization);
    }

    /// The five derived fields are derived from the **intent**, not echoed
    /// from anywhere the caller controls independently.
    ///
    /// Driven by changing the intent and observing the derived values move
    /// with it, which is the only way to tell "derived" from "coincidentally
    /// equal in the fixture".
    ///
    /// Mutation this detects: hard-coding any of the five, or sourcing
    /// `spender` from something other than `parse`'s `gateway` argument.
    #[test]
    fn the_derived_call_fields_follow_the_intent_and_the_gateway() {
        let mut f = fixture();
        f.intent.root = [0x2f; 20];
        f.intent.secondary = [0x3f; 20];
        f.intent.controller = [0x4f; 20];
        let other_gateway = [0x5f; 20];

        let req: SubmitSponsoredEnrollmentRequest =
            serde_json::from_value(request_json_for(&f)).expect("deserialize");
        let parsed = req.parse(other_gateway).expect("parse");

        assert_eq!(parsed.v1_enrollment.wallet, [0x3f; 20]);
        assert_eq!(parsed.link.root, [0x2f; 20]);
        assert_eq!(parsed.link.secondary, [0x3f; 20]);
        assert_eq!(parsed.fee_eip2612_authorization.owner, [0x4f; 20]);
        assert_eq!(parsed.fee_eip2612_authorization.spender, other_gateway);
    }

    /// 🔴 The optimisation's whole premise, pinned at the extractor: a caller
    /// **cannot** name a quote.
    ///
    /// `#[serde(deny_unknown_fields)]` is what turns "we ignore the quote" —
    /// which would leave a client silently sending 1 KiB that does nothing —
    /// into "there is no such field". Each of the fourteen names below was a
    /// field of the pre-W3 shape.
    ///
    /// Mutation this detects: removing `deny_unknown_fields` from
    /// [`SubmitSponsoredEnrollmentRequest`].
    #[test]
    fn the_wire_dto_refuses_every_field_of_the_quote_block() {
        let f = fixture();
        for stale in [
            "quote_id_hex",
            "action_type_hex",
            "action_core_hash_hex",
            "quote_deployment_manifest_hash_hex",
            "quote_fee_token_config_hash_hex",
            "fee_schedule_hash_hex",
            "payer_address",
            "quote_fee_token_address",
            "fee_amount",
            "fee_recipient_address",
            "valid_after",
            "valid_until",
            "quote_signature_hex",
            "quote",
        ] {
            let mut body = request_json_for(&f);
            body.as_object_mut()
                .unwrap()
                .insert(stale.to_string(), serde_json::json!("0x00"));
            let err = serde_json::from_value::<SubmitSponsoredEnrollmentRequest>(body)
                .expect_err(&format!("`{stale}` must not be accepted on the submit body"));
            assert!(
                err.to_string().contains("unknown field"),
                "expected an unknown-field rejection for `{stale}`, got: {err}"
            );
        }
    }

    /// A malformed hex field is a 400 that names the field and **nothing
    /// else**.
    ///
    /// The second assertion is the rule-5 one: the deleted
    /// `QuoteBindingMismatch` put both signature hexes into its `Display`,
    /// and `ApiError::into_response` logs `detail`, so the value must not
    /// appear.
    ///
    /// Mutation this detects: formatting the offending value into
    /// [`SubmitError::MalformedRequest`]'s message.
    #[test]
    fn a_malformed_request_field_is_a_400_that_never_echoes_the_value() {
        let f = fixture();
        let mut body = request_json_for(&f);
        body.as_object_mut().unwrap().insert(
            "intent_id_hex".to_string(),
            serde_json::json!("0xLEAKMARKERnot-hex"),
        );
        let req: SubmitSponsoredEnrollmentRequest =
            serde_json::from_value(body).expect("still the declared shape");

        let err = req.parse(GATEWAY).expect_err("not a 32-byte hex string");
        assert_eq!(err.code(), ERR_SUBMIT_MALFORMED_REQUEST);
        assert_eq!(err.status(), axum::http::StatusCode::BAD_REQUEST);
        let rendered = err.to_string();
        assert!(
            rendered.contains("intent_id_hex"),
            "the refusal must name the field: {rendered}"
        );
        assert!(
            !rendered.contains("LEAKMARKER"),
            "the refusal must not echo the value: {rendered}"
        );
    }

    /// A signature field is carried verbatim (it is not parsed here — the
    /// recovery in `preflight` is what validates it), so nothing in `parse`
    /// may normalise, truncate or otherwise touch it.
    ///
    /// Mutation this detects: lower-casing or `0x`-stripping a signature in
    /// [`SubmitSponsoredEnrollmentRequest::parse`].
    #[test]
    fn signature_fields_survive_parsing_byte_for_byte() {
        let f = fixture();
        let req: SubmitSponsoredEnrollmentRequest =
            serde_json::from_value(request_json_for(&f)).expect("deserialize");
        let parsed = req.parse(GATEWAY).expect("parse");
        assert_eq!(parsed.sponsor_signature_hex, f.sponsor_sig);
        assert_eq!(parsed.v1_enrollment.signature_hex, f.v1.signature_hex);
        assert_eq!(parsed.link_signature_hex, f.link_sig);
    }

    // --- W3: reconstruction ------------------------------------------------

    /// [`QuoteCommitment::to_fee_quote`] rebuilds the quote `quotes.rs`
    /// sealed, field for field, through the real store path.
    ///
    /// The `action_type` assertion is the one worth reading: it is pinned to
    /// `ACTION_SPONSORED_ENROLLMENT` rather than read from the envelope, and
    /// this test shows the pinned value is the right one for a real sealed
    /// row.
    ///
    /// Mutation this detects: sourcing any field of `to_fee_quote` from
    /// somewhere other than the commitment.
    #[tokio::test]
    async fn the_reconstructed_quote_equals_the_sealed_one() {
        let f = fixture();
        let (_dir, store) = open_store().await;
        seed_quote(&store, &f, PROFILE).await;

        let c = load_quote_commitment(&store, &data_key_hex(), &profile(), f.intent.intent_id)
            .await
            .expect("commitment");

        assert_eq!(c.to_fee_quote(), f.quote);
        assert_eq!(c.quote_signature_hex(), f.quote_sig);
        assert_eq!(
            c.to_fee_quote().action_type,
            ActionType::SponsoredEnrollment.digest()
        );
        // And the digest the whole revalidation turns on is reproducible from
        // sealed state alone.
        assert_eq!(
            fee_quote_digest(&c.to_fee_quote(), CHAIN_ID, GATEWAY),
            f.intent.fee_quote_hash
        );
    }

    /// A direct-ETH intent is refused **before** the store is read and before
    /// any chain read, with the honest error.
    ///
    /// `sends() == 0` is not the interesting assertion here (nothing gets
    /// that far); the interesting one is that the refusal is `NotRelayable`
    /// and not a quote check, because a direct-ETH intent zeroes
    /// `feeQuoteHash` and no reconstructed quote can ever hash to zero.
    ///
    /// Mutation this detects: deleting the `is_direct_eth_enrollment` guard
    /// at the top of [`submit_sponsored_enrollment`] — the refusal then
    /// becomes `PREFLIGHT_WOULD_REVERT` after a full round of chain reads.
    #[tokio::test]
    async fn a_direct_eth_intent_is_refused_before_anything_is_read() {
        let f = fixture();
        let h = harness(&f).await;
        let b = FakeSigner::ok();

        // All six `_isDirectEthEnrollment` conditions.
        let mut parts = f.parts();
        parts.intent.fee_token = [0u8; 20];
        parts.intent.fee_authorization_mode = preflight::AUTHORIZATION_MODE_NONE;
        parts.intent.fee_authorization_digest = [0u8; 32];
        parts.intent.fee_quote_hash = [0u8; 32];
        parts.intent.max_fee = 0;
        parts.intent.fee_token_config_hash = [0u8; 32];

        let before = h.chain.pinned_block_number_call_count();
        let err = submit_sponsored_enrollment(&h.ctx(&b), &profile(), &parts)
            .await
            .expect_err("a relayer cannot submit the direct-ETH branch");
        assert_eq!(err.code(), ERR_SUBMIT_NOT_RELAYABLE);
        assert_eq!(h.sends(), 0);
        assert_eq!(
            b.sign_calls(),
            0,
            "nothing may be signed for a direct-ETH intent"
        );
        // "before anything is read" is the claim in this test's name, so it
        // is asserted rather than left to the reader: the revalidation's very
        // first chain call is `eth_blockNumber`, and it never happens.
        assert_eq!(
            h.chain.pinned_block_number_call_count(),
            before,
            "the direct-ETH refusal must precede the revalidation read"
        );
    }

    // --- W3: the response DTO ----------------------------------------------

    /// The wire receipt carries what a caller needs and nothing this
    /// attestor keeps to itself.
    ///
    /// The two `assert!(!json.contains(..))` lines are the point: the
    /// internal row ids are real values on the domain [`SubmitReceipt`] and
    /// are absent from the serialization, so the test fails if anyone
    /// derives `Serialize` on the domain type and returns that instead.
    ///
    /// Mutation this detects: adding `tx_attempt_id` or
    /// `nonce_allocation_id` to [`SubmitReceiptResponse`], or shipping the
    /// full `UnverifiedCheck` records.
    #[tokio::test]
    async fn the_wire_receipt_hides_internal_ids_and_keeps_the_disclosure() {
        let f = fixture();
        let h = harness(&f).await;
        let b = FakeSigner::ok();

        let receipt = submit_sponsored_enrollment(&h.ctx(&b), &profile(), &f.parts())
            .await
            .expect("submit");
        let attempt_id = receipt.tx_attempt_id.clone();
        let allocation_id = receipt.nonce_allocation_id.clone();
        assert!(!attempt_id.is_empty() && !allocation_id.is_empty());

        let wire = SubmitReceiptResponse::from(receipt);
        let json = serde_json::to_string(&wire).expect("serialize");

        assert!(
            !json.contains(&attempt_id),
            "the tx_attempts row id must not reach a client"
        );
        assert!(
            !json.contains(&allocation_id),
            "the nonce_allocations row id must not reach a client"
        );
        assert!(!json.contains("0x02f86b"), "no raw transaction bytes");

        // The disclosure survives, in its short form.
        assert_eq!(
            wire.unverified_check_count,
            preflight::UNVERIFIED_CHECKS.len()
        );
        assert_eq!(wire.unverified_checks.len(), wire.unverified_check_count);
        assert!(wire.unverified_check_count > 0, "a 200 must never read as \"this will succeed\"");
        for u in preflight::UNVERIFIED_CHECKS {
            // Names only: the multi-line `why` prose stays server-side.
            assert!(!json.contains(u.why), "unverified prose must not be shipped");
        }
        assert_eq!(wire.tx_hash_hex, bytes32_hex(TX_HASH));
    }

    /// 🔴 Wave C W3, replacing `a_call_carrying_a_quote_this_attestor_never_signed_is_refused`.
    ///
    /// That test posted a quote re-signed with the caller's own key and
    /// watched `bind_call_to_commitment`'s lowercase string compare reject
    /// it. **A caller can no longer post a quote at all** —
    /// [`SubmitCallParts`] has no field for one — so the equivalent hazard is
    /// now "the sealed row itself carries a signature that is not this
    /// attestor's quote signer's", and the refusal is an ECDSA recovery
    /// (`Check::BadQuoteSignature`) rather than a `!=`.
    ///
    /// The fixture is sealed with a signature over the *correct* digest by
    /// the *wrong* key, so every other quote check passes and only the
    /// recovery can fire.
    ///
    /// Mutation this detects: making [`QuoteCommitment::to_fee_quote`]'s
    /// signature companion (`quote_signature_hex`) come from anywhere but the
    /// sealed row — e.g. returning `""` — or dropping the reconstructed call
    /// from the `preflight_sponsored_enrollment` argument.
    #[tokio::test]
    async fn a_sealed_quote_signed_by_the_wrong_key_is_refused() {
        let mut g = fixture();
        g.quote_sig = sign(SECONDARY_KEY, fee_quote_digest(&g.quote, CHAIN_ID, GATEWAY));
        let h = harness(&g).await;
        let b = FakeSigner::ok();

        let err = submit_sponsored_enrollment(&h.ctx(&b), &profile(), &g.parts())
            .await
            .expect_err("sealed quote signature is not the quote signer's");
        assert_eq!(err.code(), preflight::ERR_PREFLIGHT_WOULD_REVERT);
        assert_eq!(would_revert_check(&err), Check::BadQuoteSignature);
        assert_eq!(h.sends(), 0);
    }

    /// 🔴 Wave C W3, replacing `a_call_with_a_mutated_fee_amount_is_refused`.
    ///
    /// The old test proved the `quote.feeAmount` `bind!` fired. The property
    /// that actually matters survives it: a sealed quote that is **not the
    /// one the controller's intent commits to** must be refused, and now it
    /// is refused by recomputing the EIP-712 digest server-side rather than
    /// by comparing a field.
    ///
    /// `g`'s quote is re-signed by the real quote signer after the mutation,
    /// so `Check::BadQuoteSignature` (which runs first) passes and only
    /// `Check::FeeQuoteHashMismatch` can fire — the same discipline the old
    /// test's own doc insisted on for the opposite reason.
    ///
    /// Mutation this detects: reconstructing the quote *after*
    /// `preflight_sponsored_enrollment` instead of before it, or passing
    /// `parts.with_quote(..)` a quote built from anything but the commitment.
    #[tokio::test]
    async fn a_sealed_quote_the_intent_does_not_commit_to_is_refused() {
        let mut g = fixture();
        // Drift the sealed quote, then re-sign it so the ONLY thing wrong is
        // that `intent.feeQuoteHash` (unchanged, and covered by the
        // controller's sponsor signature) names the original digest.
        g.quote.fee_amount += 1;
        g.quote_sig = sign(QUOTE_SIGNER_KEY, fee_quote_digest(&g.quote, CHAIN_ID, GATEWAY));
        let h = harness(&g).await;
        let b = FakeSigner::ok();

        let err = submit_sponsored_enrollment(&h.ctx(&b), &profile(), &g.parts())
            .await
            .expect_err("sealed quote drifted from the signed intent");
        assert_eq!(err.code(), preflight::ERR_PREFLIGHT_WOULD_REVERT);
        assert_eq!(would_revert_check(&err), Check::FeeQuoteHashMismatch);
        assert_eq!(h.sends(), 0);
    }

    /// 🔴 Wave C W3 — **the advisor's expiry hazard, pinned.**
    ///
    /// Before W3 the validity window was read off the *caller's* inline
    /// quote, so a quote whose window had closed could still be submitted by
    /// a client that kept posting the original values (and by one the quote
    /// path had already flipped to `status='expired'`, since
    /// `load_quote_commitment` selects neither `status` nor `expires_at`).
    /// The window now comes from the sealed row, and it is compared against
    /// `state.chain_now` — the PINNED BLOCK's `block.timestamp`, not this
    /// process's wall clock.
    ///
    /// Mutation this detects: reconstructing the quote after the preflight
    /// (the window check then reads whatever the caller's call carried), or
    /// hard-coding `valid_until` in [`QuoteCommitment::to_fee_quote`].
    #[tokio::test]
    async fn a_sealed_quote_whose_window_has_closed_is_refused_against_chain_time() {
        let mut g = fixture();
        // Closed one second before the pinned block's timestamp. Re-signed,
        // and `intent.fee_quote_hash` rebound, so the window is the only
        // thing wrong.
        g.quote.valid_until = CHAIN_NOW - 1;
        g.rebind_quote();
        let h = harness(&g).await;
        let b = FakeSigner::ok();

        let err = submit_sponsored_enrollment(&h.ctx(&b), &profile(), &g.parts())
            .await
            .expect_err("sealed quote window closed at the pinned block");
        assert_eq!(err.code(), preflight::ERR_PREFLIGHT_WOULD_REVERT);
        assert_eq!(would_revert_check(&err), Check::QuoteWindow);
        // Re-quote, not "stop": nothing was consumed on chain.
        assert_eq!(err.retryability(), Retryability::Retryable);
        assert_eq!(h.sends(), 0);
    }

    /// 🔴 Wave C W3, replacing `bind_call_to_commitment_rejects_each_field_independently`.
    ///
    /// That test mutated one field of the **submitted** quote at a time and
    /// named the `bind!` that caught it. With the quote no longer on the
    /// wire, the equivalent question is the mirror image: mutate one field of
    /// the **sealed** quote at a time, leaving the controller-signed intent
    /// alone, and check that each is independently refused and by which
    /// check.
    ///
    /// Every case re-signs the quote with the real `QUOTE_SIGNER_KEY` after
    /// the mutation. Without that, `Check::BadQuoteSignature` would catch all
    /// eleven and the table would prove nothing about the other ten checks —
    /// the same trap the deleted test's doc recorded (12 of 13 bindings
    /// survived deletion because every mutation also re-signed).
    ///
    /// `action_type` is absent from the table on purpose: it is the one
    /// `FeeQuote` field [`QuoteCommitment::to_fee_quote`] does **not** read
    /// from the envelope, so no sealed value can move it. That is stated in
    /// that method's doc rather than tested here, because there is nothing to
    /// drive.
    ///
    /// Mutation this detects: deleting any single field from
    /// [`QuoteCommitment::to_fee_quote`]'s construction (replacing it with a
    /// value taken from the intent, or a zero) — the corresponding row stops
    /// erroring, or errors with a different check, while the other ten pass.
    #[tokio::test]
    async fn each_sealed_quote_field_is_independently_revalidated() {
        type Mutation = Box<dyn Fn(&mut Fixture)>;
        let cases: Vec<(&str, Check, Mutation)> = vec![
            (
                "quote.quoteId",
                Check::FeeQuoteHashMismatch,
                Box::new(|g: &mut Fixture| g.quote.quote_id = [0x60; 32]),
            ),
            (
                "quote.actionCoreHash",
                Check::QuoteActionCoreHashMismatch,
                Box::new(|g: &mut Fixture| g.quote.action_core_hash = [0x60; 32]),
            ),
            (
                "quote.deploymentManifestHash",
                Check::ManifestHashMismatch,
                Box::new(|g: &mut Fixture| g.quote.deployment_manifest_hash = [0x60; 32]),
            ),
            (
                "quote.feeTokenConfigHash",
                Check::FeeTokenConfigHashMismatch,
                Box::new(|g: &mut Fixture| g.quote.fee_token_config_hash = [0x60; 32]),
            ),
            (
                "quote.feeScheduleHash",
                Check::FeeScheduleHashMismatch,
                Box::new(|g: &mut Fixture| g.quote.fee_schedule_hash = [0x60; 32]),
            ),
            (
                "quote.payer",
                Check::QuotePayerMismatch,
                Box::new(|g: &mut Fixture| g.quote.payer = [0x60; 20]),
            ),
            (
                "quote.feeToken",
                Check::QuoteFeeTokenMismatch,
                Box::new(|g: &mut Fixture| g.quote.fee_token = [0x60; 20]),
            ),
            (
                "quote.feeRecipient",
                Check::QuoteFeeRecipientMismatch,
                Box::new(|g: &mut Fixture| g.quote.fee_recipient = [0x60; 20]),
            ),
            (
                "quote.feeAmount",
                Check::FeeQuoteHashMismatch,
                Box::new(|g: &mut Fixture| g.quote.fee_amount += 1),
            ),
            (
                "quote.validAfter",
                Check::FeeQuoteHashMismatch,
                Box::new(|g: &mut Fixture| g.quote.valid_after += 1),
            ),
            (
                "quote.validUntil",
                Check::FeeQuoteHashMismatch,
                Box::new(|g: &mut Fixture| g.quote.valid_until += 1),
            ),
        ];

        for (field, expected, mutate) in &cases {
            let mut g = fixture();
            mutate(&mut g);
            // Re-sign the mutated quote with the REAL quote signer, so
            // `Check::BadQuoteSignature` cannot be what fires. The intent —
            // and therefore `intent.feeQuoteHash` — is left alone.
            g.quote_sig = sign(QUOTE_SIGNER_KEY, fee_quote_digest(&g.quote, CHAIN_ID, GATEWAY));
            let h = harness(&g).await;
            let b = FakeSigner::ok();

            let err = submit_sponsored_enrollment(&h.ctx(&b), &profile(), &g.parts())
                .await
                .err()
                .unwrap_or_else(|| panic!("mutation of sealed {field} must be refused"));
            assert_eq!(
                err.code(),
                preflight::ERR_PREFLIGHT_WOULD_REVERT,
                "mutation of sealed {field} produced {err}"
            );
            assert_eq!(
                would_revert_check(&err),
                *expected,
                "wrong check fired for a mutation of sealed {field}"
            );
            assert_eq!(h.sends(), 0, "nothing may be broadcast for {field}");
        }

        // Control: the unmutated fixture goes all the way through.
        let f = fixture();
        let h = harness(&f).await;
        let b = FakeSigner::ok();
        submit_sponsored_enrollment(&h.ctx(&b), &profile(), &f.parts())
            .await
            .expect("the unmutated fixture must submit");
        assert_eq!(h.sends(), 1);
    }

    /// Another profile may not submit this profile's intent, and the
    /// rejection is indistinguishable from "no such intent".
    ///
    /// **What this actually detects, stated precisely.** Two independent
    /// defences produce this outcome: the profile-namespaced row id (defect
    /// C2) makes a foreign caller address a different row, and the
    /// `profile_id` column check rejects it if it somehow finds one. A
    /// mutation run confirmed that removing **either one alone** leaves this
    /// test green, so it is a defence-in-depth test and nothing more — it
    /// detects the removal of *both*. Each defence is pinned individually
    /// elsewhere, and each of those pins was verified to fail under its own
    /// mutation:
    ///
    /// - namespacing → [`tests::intent_row_id_matches_the_quotes_module_scheme`]
    ///   (fails when `profile_id` is dropped from the digest);
    /// - column check → [`tests::a_row_whose_owner_column_disagrees_is_rejected`]
    ///   (fails when the `row_profile != profile_id` branch is deleted).
    ///
    /// This comment was rewritten after the mutation run; it originally
    /// claimed a discriminating power this test does not have.
    #[tokio::test]
    async fn a_foreign_profile_cannot_submit_this_intent() {
        let f = fixture();
        let h = harness(&f).await;
        let b = FakeSigner::ok();

        let other = AuthenticatedProfileId::for_test("profile-other");
        let err = submit_sponsored_enrollment(&h.ctx(&b), &other, &f.parts())
            .await
            .expect_err("foreign profile");
        assert_eq!(err.code(), ERR_SUBMIT_INTENT_NOT_FOUND);
        assert_eq!(h.sends(), 0);
    }

    // -------------------------------------------------------------------
    // Commitment loading.
    // -------------------------------------------------------------------

    /// Round-trip through the real sealed columns, addressed by the
    /// profile-namespaced row id.
    #[tokio::test]
    async fn commitment_loads_the_stored_quote_for_the_owning_profile() {
        let f = fixture();
        let (_dir, store) = open_store().await;
        seed_quote(&store, &f, PROFILE).await;

        let c = load_quote_commitment(&store, &data_key_hex(), &profile(), f.intent.intent_id)
            .await
            .expect("load");
        assert_eq!(c.intent_id(), f.intent.intent_id);
        assert_eq!(c.quote_id(), f.quote.quote_id);
        assert_eq!(c.action_core_hash(), f.quote.action_core_hash);
        assert_eq!(c.fee_amount(), f.quote.fee_amount);
        assert_eq!(c.valid_until(), f.quote.valid_until);
        assert_eq!(
            c.intent_row_id(),
            intent_row_id(PROFILE, f.intent.intent_id)
        );
        assert_eq!(c.profile_id(), PROFILE);
    }

    /// The belt-and-braces ownership check: a row sitting at the
    /// profile-namespaced id whose `profile_id` **column** names someone
    /// else must be refused, even though the sealed payload and the quote
    /// row both still say the caller owns it.
    ///
    /// This is the only test that reaches that check — the namespaced row id
    /// makes it unreachable by an ordinary foreign caller, which is exactly
    /// why `quotes.rs` calls its equivalent "should be unreachable, but
    /// 'should be' is not 'enforced'".
    ///
    /// Mutation this detects: deleting the `row_profile != profile_id`
    /// branch from [`load_quote_commitment`].
    #[tokio::test]
    async fn a_row_whose_owner_column_disagrees_is_rejected() {
        let f = fixture();
        let (_dir, store) = open_store().await;
        seed_quote(&store, &f, PROFILE).await;

        let row = intent_row_id(PROFILE, f.intent.intent_id);
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT OR IGNORE INTO profiles (id, created_at, status) \
                         VALUES ('profile-squatter', 0, 'active')",
                    )
                    .execute(&mut **tx)
                    .await?;
                    // Only the COLUMN is rewritten: the sealed payload still
                    // says PROFILE, and so does the quote row. If the column
                    // check is removed, this load succeeds.
                    sqlx::query("UPDATE intents SET profile_id = 'profile-squatter' WHERE id = ?")
                        .bind(&row)
                        .execute(&mut **tx)
                        .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("rewrite owner column");

        let err = load_quote_commitment(&store, &data_key_hex(), &profile(), f.intent.intent_id)
            .await
            .expect_err("owner column disagrees");
        assert_eq!(err.code(), ERR_SUBMIT_INTENT_NOT_FOUND);
    }

    /// An unknown intent id must be `IntentNotFound`, never a panic and
    /// never a partially-populated commitment.
    #[tokio::test]
    async fn commitment_load_rejects_an_unknown_intent() {
        let f = fixture();
        let (_dir, store) = open_store().await;
        seed_quote(&store, &f, PROFILE).await;

        let err = load_quote_commitment(&store, &data_key_hex(), &profile(), [0xEE; 32])
            .await
            .expect_err("unknown intent");
        assert_eq!(err.code(), ERR_SUBMIT_INTENT_NOT_FOUND);
    }

    // -------------------------------------------------------------------
    // Reconciliation.
    // -------------------------------------------------------------------

    /// The event the effects ordering says to key on. It must confirm the
    /// attempt, mark the intent executed, and flip the reservation from
    /// `allocated` to `consumed` — the one path where the nonce really was
    /// spent on chain.
    ///
    /// Mutation this detects: marking the allocation `released` instead of
    /// `consumed` on confirmation, which would let a later submit re-use a
    /// nonce the gateway has already incremented past.
    #[tokio::test]
    async fn reconciling_the_executed_event_confirms_and_consumes() {
        let f = fixture();
        let h = harness(&f).await;
        let b = FakeSigner::ok();
        let receipt = submit_sponsored_enrollment(&h.ctx(&b), &profile(), &f.parts())
            .await
            .expect("submit");

        let event = SponsoredEnrollmentExecuted {
            intent_id: f.intent.intent_id,
            root: f.intent.root,
            secondary: f.intent.secondary,
            controller: f.intent.controller,
            fee_token: f.intent.fee_token,
            fee_amount: f.quote.fee_amount,
            tx_hash: TX_HASH,
            block: BLOCK + 1,
        };
        let row_id =
            reconcile_sponsored_enrollment_executed(&h.store, &data_key_hex(), &profile(), &event, WALL_NOW)
                .await
                .expect("reconcile");

        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM tx_attempts WHERE id = ?",
                receipt.tx_attempt_id.clone()
            )
            .await
            .as_deref(),
            Some(TX_ATTEMPT_STATUS_CONFIRMED)
        );
        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM intents WHERE id = ?",
                intent_row_id(PROFILE, f.intent.intent_id)
            )
            .await
            .as_deref(),
            Some(INTENT_STATUS_EXECUTED)
        );
        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM nonce_allocations WHERE id = ?",
                receipt.nonce_allocation_id.clone()
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_CONSUMED)
        );
        assert_eq!(
            text(
                &h.store,
                "SELECT event_type FROM reconciliation_events WHERE id = ?",
                row_id
            )
            .await
            .as_deref(),
            Some(RECONCILIATION_EVENT_TYPE)
        );
    }

    /// An event carrying a different transaction hash than the one this
    /// attempt broadcast is somebody else's confirmation.
    ///
    /// Mutation this detects: dropping the `tx_hash` comparison from
    /// [`reconcile_sponsored_enrollment_executed`].
    #[tokio::test]
    async fn reconciliation_rejects_an_event_from_a_different_transaction() {
        let f = fixture();
        let h = harness(&f).await;
        let b = FakeSigner::ok();
        submit_sponsored_enrollment(&h.ctx(&b), &profile(), &f.parts())
            .await
            .expect("submit");

        let event = SponsoredEnrollmentExecuted {
            intent_id: f.intent.intent_id,
            root: f.intent.root,
            secondary: f.intent.secondary,
            controller: f.intent.controller,
            fee_token: f.intent.fee_token,
            fee_amount: f.quote.fee_amount,
            tx_hash: [0x77; 32],
            block: BLOCK + 1,
        };
        let err =
            reconcile_sponsored_enrollment_executed(&h.store, &data_key_hex(), &profile(), &event, WALL_NOW)
                .await
                .expect_err("foreign tx hash");
        assert_eq!(err.code(), ERR_SUBMIT_RECONCILE_MISMATCH);
    }

    /// Replaying the same event is a no-op, not a conflict — reconciliation
    /// runs from a log follower that will see the same event again.
    #[tokio::test]
    async fn reconciliation_is_idempotent() {
        let f = fixture();
        let h = harness(&f).await;
        let b = FakeSigner::ok();
        submit_sponsored_enrollment(&h.ctx(&b), &profile(), &f.parts())
            .await
            .expect("submit");

        let event = SponsoredEnrollmentExecuted {
            intent_id: f.intent.intent_id,
            root: f.intent.root,
            secondary: f.intent.secondary,
            controller: f.intent.controller,
            fee_token: f.intent.fee_token,
            fee_amount: f.quote.fee_amount,
            tx_hash: TX_HASH,
            block: BLOCK + 1,
        };
        let a =
            reconcile_sponsored_enrollment_executed(&h.store, &data_key_hex(), &profile(), &event, WALL_NOW)
                .await
                .expect("first");
        let b2 =
            reconcile_sponsored_enrollment_executed(&h.store, &data_key_hex(), &profile(), &event, WALL_NOW)
                .await
                .expect("replay");
        assert_eq!(a, b2);
        let count = scalar_i64(
            &h.store,
            "SELECT COUNT(*) FROM reconciliation_events WHERE id = ?",
            a,
        )
        .await;
        assert_eq!(count, 1, "one row per (intent, tx)");
    }

    /// The derived-id integrity check Wave E put in place of the old
    /// `field: "intent_id"` guard.
    ///
    /// The attempt rows are SELECTed **by** `intent_id`, so comparing a row's
    /// `intent_id` column back to the value we selected on is structurally
    /// true — an unkillable assertion (defect I7), which is why that guard was
    /// replaced. What is not structurally true is that a row's PRIMARY KEY is
    /// the value `tx_attempt_row_id` derives for that row's own
    /// `attempt_number`. A hand-made id is exactly the row that must never be
    /// silently confirmed: every other statement in this crate that addresses
    /// attempts re-derives the id (`outbox.rs`'s sweeper above all), so a row
    /// that does not carry its derived id is a row two code paths disagree
    /// about — one would confirm it here while the other keeps sweeping the
    /// id that does not exist.
    ///
    /// **Mutation this detects (GAP1, run and reverted):** neuter the check in
    /// `reconcile_executed_for_profile_id` — `if false && id !=
    /// tx_attempt_row_id(&profile_id, event_intent_id, number)`. The tampered
    /// row is then reconciled and `expect_err` below panics.
    ///
    /// Paired non-zero arm (I7): the identical fixture and event against a
    /// store whose id was left canonical reconciles and reaches `confirmed`,
    /// so the refusal above is a refusal and not a dead path.
    #[tokio::test]
    async fn reconcile_refuses_an_attempt_row_whose_id_is_not_the_canonical_derivation() {
        let f = fixture();
        let event = SponsoredEnrollmentExecuted {
            intent_id: f.intent.intent_id,
            root: f.intent.root,
            secondary: f.intent.secondary,
            controller: f.intent.controller,
            fee_token: f.intent.fee_token,
            fee_amount: f.quote.fee_amount,
            tx_hash: TX_HASH,
            block: BLOCK + 1,
        };

        // --- the tampered store ------------------------------------------
        let h = harness(&f).await;
        let b = FakeSigner::ok();
        let receipt = submit_sponsored_enrollment(&h.ctx(&b), &profile(), &f.parts())
            .await
            .expect("submit");
        let canonical = tx_attempt_row_id(PROFILE, f.intent.intent_id, 0);
        assert_eq!(
            receipt.tx_attempt_id, canonical,
            "the production writer must use the canonical deriver"
        );

        let hand_made = "attempt-row-made-by-hand".to_string();
        assert_eq!(
            exec2(
                &h.store,
                "UPDATE tx_attempts SET id = ? WHERE id = ?",
                hand_made.clone(),
                canonical.clone(),
            )
            .await,
            1,
            "the tamper really re-keyed the row"
        );

        let err =
            reconcile_sponsored_enrollment_executed(&h.store, &data_key_hex(), &profile(), &event, WALL_NOW)
                .await
                .expect_err("an attempt row that is not at its derived id must not reconcile");
        assert!(
            matches!(err, SubmitError::ReconcileMismatch { field: "intent_id" }),
            "{err:?}"
        );
        assert_eq!(err.code(), ERR_SUBMIT_RECONCILE_MISMATCH);

        // The refusal is total: no confirmation, no execution, no consumed
        // nonce, no sealed event. (These are the writes GAP1 lets through.)
        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM tx_attempts WHERE id = ?",
                hand_made.clone()
            )
            .await
            .as_deref(),
            Some(TX_ATTEMPT_STATUS_SUBMITTED),
            "the attempt must not be stamped confirmed"
        );
        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM intents WHERE id = ?",
                intent_row_id(PROFILE, f.intent.intent_id)
            )
            .await
            .as_deref(),
            Some(INTENT_STATUS_SUBMITTED),
            "the intent must not be stamped executed"
        );
        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM nonce_allocations WHERE id = ?",
                receipt.nonce_allocation_id.clone()
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "the action nonce must not be marked consumed off an unverifiable row"
        );
        assert_eq!(
            scalar_i64(
                &h.store,
                "SELECT COUNT(*) FROM reconciliation_events WHERE tx_attempt_id = ?",
                hand_made.clone(),
            )
            .await,
            0,
            "no sealed reconciliation row"
        );

        // --- paired non-zero arm: the untampered store -------------------
        let clean = harness(&f).await;
        let b2 = FakeSigner::ok();
        let receipt2 = submit_sponsored_enrollment(&clean.ctx(&b2), &profile(), &f.parts())
            .await
            .expect("submit");
        assert_eq!(receipt2.tx_attempt_id, canonical);
        reconcile_sponsored_enrollment_executed(
            &clean.store,
            &data_key_hex(),
            &profile(),
            &event,
            WALL_NOW,
        )
        .await
        .expect("a canonically-keyed row reconciles");
        assert_eq!(
            text(
                &clean.store,
                "SELECT status FROM tx_attempts WHERE id = ?",
                canonical.clone()
            )
            .await
            .as_deref(),
            Some(TX_ATTEMPT_STATUS_CONFIRMED)
        );
        assert_eq!(
            scalar_i64(
                &clean.store,
                "SELECT COUNT(*) FROM reconciliation_events WHERE tx_attempt_id = ?",
                canonical,
            )
            .await,
            1,
            "non-zero arm: the sealed event the tampered store did not get"
        );
    }

    /// `record_broadcast_unresolved`'s `rows_affected() != 1` arm.
    ///
    /// The function stamps the sweeper's evidence onto an attempt row that is
    /// still `reserved`. If it matches nothing — the row moved on, or was
    /// claimed by another process — that is deliberately **not** an error:
    /// raising one would reclassify the caller's failure as `Retryable` and
    /// tell a client to re-quote against a nonce whose transaction may still
    /// be live, which is the exact hazard the branch exists to prevent. So the
    /// only externally visible effect of the guard is the warning, and the
    /// only honest way to cover it is to read the trace output.
    ///
    /// **Mutation this detects (GAP2, run and reverted):**
    /// `if r.rows_affected() != 1 {` -> `if false {`. The operator warning for
    /// a transaction the sweeper may now be unable to resolve is never
    /// emitted, and the `logs.contains(...)` assertion in the second arm
    /// fails.
    ///
    /// Paired non-zero arm for the zero-assertion: the first arm, where the
    /// row IS `reserved`, asserts the stamp landed **and** that the warning is
    /// absent — so "warned" and "did not warn" are both observed through the
    /// same seam.
    #[tokio::test]
    async fn an_unresolved_broadcast_that_cannot_stamp_its_row_warns_instead_of_failing() {
        let f = fixture();
        let h = harness(&f).await;
        // Leaves attempt 0 `reserved` with the action nonce still `allocated`.
        h.arm_send_failure("get_receipt timed out after 60s");
        let timing_out = FakeSigner::ok();
        submit_sponsored_enrollment(&h.ctx(&timing_out), &profile(), &f.parts())
            .await
            .expect_err("receipt timeout");
        let attempt = tx_attempt_row_id(PROFILE, f.intent.intent_id, 0);
        assert_eq!(
            text(
                &h.store,
                "SELECT status FROM tx_attempts WHERE id = ?",
                attempt.clone()
            )
            .await
            .as_deref(),
            Some(TX_ATTEMPT_STATUS_RESERVED),
            "precondition: the row the stamp targets is reserved"
        );

        let buf = LogBuf::default();
        let guard = capture_logs(&buf);

        // --- arm 1: the row is `reserved`, so the stamp lands -------------
        record_broadcast_unresolved(
            &h.store,
            attempt.clone(),
            bytes32_hex(f.intent.intent_id),
            bytes32_hex([0xA1; 32]),
            "arm-one-detail".to_string(),
            WALL_LEASE_UNTIL,
        )
        .await
        .expect("a matching row is stamped without error");
        assert_eq!(
            text(
                &h.store,
                "SELECT error_message FROM tx_attempts WHERE id = ?",
                attempt.clone()
            )
            .await
            .as_deref(),
            Some("arm-one-detail"),
            "non-zero arm: rows_affected() really was 1"
        );
        assert_eq!(
            text(
                &h.store,
                "SELECT raw_tx_hash FROM tx_attempts WHERE id = ?",
                attempt.clone()
            )
            .await,
            Some(bytes32_hex([0xA1; 32]))
        );
        assert!(
            !buf.contents().contains(&attempt),
            "a stamp that landed must not warn; got: {}",
            buf.contents()
        );

        // --- arm 2: the row is no longer `reserved` -----------------------
        assert_eq!(
            exec2(
                &h.store,
                "UPDATE tx_attempts SET status = ? WHERE id = ?",
                TX_ATTEMPT_STATUS_SUBMITTED.to_string(),
                attempt.clone(),
            )
            .await,
            1,
            "the row really moved out of `reserved`"
        );
        record_broadcast_unresolved(
            &h.store,
            attempt.clone(),
            bytes32_hex(f.intent.intent_id),
            bytes32_hex([0xB2; 32]),
            "arm-two-detail".to_string(),
            WALL_LEASE_UNTIL,
        )
        .await
        .expect("a non-matching row must NOT be an error — that is the whole point");

        let logs = buf.contents();
        drop(guard);
        assert!(
            logs.contains(&attempt),
            "the unstampable attempt must be named in the operator warning; got: {logs}"
        );
        assert!(
            logs.contains(&bytes32_hex([0xB2; 32])),
            "and so must the transaction the sweeper may be unable to resolve; got: {logs}"
        );
        assert!(
            logs.contains("no longer 'reserved'"),
            "the warning must say why; got: {logs}"
        );

        // And it really wrote nothing: arm 1's values survive untouched.
        assert_eq!(
            text(
                &h.store,
                "SELECT error_message FROM tx_attempts WHERE id = ?",
                attempt.clone()
            )
            .await
            .as_deref(),
            Some("arm-one-detail"),
            "a non-matching UPDATE must not overwrite the prior evidence"
        );
        assert_eq!(
            text(
                &h.store,
                "SELECT raw_tx_hash FROM tx_attempts WHERE id = ?",
                attempt.clone()
            )
            .await,
            Some(bytes32_hex([0xA1; 32]))
        );
        // The invariant that actually matters on this path: the action nonce
        // is still held, so no re-quote can sign against it.
        assert_eq!(
            scalar_i64(
                &h.store,
                "SELECT COUNT(*) FROM nonce_allocations WHERE status = 'allocated' AND nonce = ?",
                f.intent.nonce.to_string(),
            )
            .await,
            1,
            "the reservation is still held"
        );
    }

    /// This module must never query `authorizations` by `intent_id` — that
    /// table holds two undiscriminated row kinds (brief §3).
    ///
    /// Mutation this detects: adding a
    /// `SELECT ... WHERE intent_id = ?` over the `authorizations` table to
    /// this file.
    #[test]
    fn module_never_selects_authorizations_by_intent_id() {
        let src = include_str!("submit.rs");
        // The needle is assembled at runtime so this test's own source does
        // not contain the string it searches for — otherwise the scan would
        // always match itself and could never fail.
        let needle = format!("FROM {}", "authorizations");
        assert!(
            !src.contains(&needle),
            "submit.rs must not query the `authorizations` table: it holds two \
             undiscriminated row kinds for one intent_id"
        );
    }

    // ===================================================================
    // `GET /v1/stream-g/status/:intentId` — the mounted route.
    //
    // ## Which arm these are on
    //
    // `runtime::test_support::enabled_map` inherits `GOAT_ATTESTOR_MOCK=1`
    // (`enabled_map` calls `Config::test_map`, which sets that key), so
    // `state.trusted_chain()` is `None` here. That
    // is not a limitation for this route: it reads only `StreamGStore` (no
    // `trusted_chain` / `live_chain` call appears in
    // [`get_enrollment_status`]), so every 200 below ran the real handler
    // against real rows rather than a stub.
    //
    // The `route_state` / `route_get` helpers are deliberate near-duplicates
    // of `onboarding::tests`' and `profile_auth::tests`', which are private to
    // those modules' own `mod tests` — same reason `http_error::tests::
    // CapturedLog` duplicates `mod.rs::tests::CapturedLog` rather than
    // sharing it.
    // ===================================================================

    use crate::stream_g::profile_auth::{
        create_profile, AUTH_SCHEME_CREDENTIAL, ERR_MISSING_CREDENTIAL,
    };
    use crate::stream_g::reconcile::{
        apply_disposition, AttemptDisposition, DISPOSITION_STATUS_UNKNOWN,
    };
    use crate::stream_g::{router, runtime};
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const ROUTE_ORIGIN: &str = "https://status.example";

    async fn route_state(dir: &std::path::Path) -> runtime::StreamGState {
        let mut map = runtime::test_support::enabled_map(dir);
        map.insert("STREAM_G_CORS_ORIGINS".into(), ROUTE_ORIGIN.into());
        let cfg = crate::config::load_from_map(&map).expect("stream G config must validate");
        let controller = runtime::ShutdownController::new();
        runtime::StreamGState::start(&cfg, controller.token())
            .await
            .expect("stream G startup")
    }

    async fn route_get(
        app: &Router,
        uri: &str,
        authorization: Option<&str>,
    ) -> (StatusCode, String) {
        let mut builder = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("origin", ROUTE_ORIGIN);
        if let Some(authorization) = authorization {
            builder = builder.header("authorization", authorization);
        }
        let res = app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    fn status_uri(intent_id_hex: &str) -> String {
        format!("/v1/stream-g/status/{intent_id_hex}")
    }

    /// A profile plus the `Authorization` header value that authenticates as
    /// it, and its proven id for library setup calls.
    async fn route_profile(
        state: &runtime::StreamGState,
        idempotency_key: &str,
    ) -> (AuthenticatedProfileId, String) {
        let created = create_profile(state.store(), state.data_key_hex(), idempotency_key)
            .await
            .expect("create profile");
        (
            AuthenticatedProfileId::for_test(&created.profile_id),
            format!("{AUTH_SCHEME_CREDENTIAL} {}", created.credential),
        )
    }

    /// One `intents` row of the shape
    /// `quotes::create_sponsored_enrollment_quote_at`'s STEP 7
    /// `INSERT OR IGNORE INTO intents … 'sponsored_enrollment'` writes, addressed
    /// by [`intent_row_id`] — the only way this module ever names that row.
    /// `intent_enc` is left NULL: this route never opens it (that is
    /// [`load_quote_commitment`]'s job), and seeding a sealed envelope here
    /// would imply otherwise.
    async fn seed_enrollment_intent(
        store: &StreamGStore,
        profile: &AuthenticatedProfileId,
        intent_id: [u8; 32],
        status: &str,
    ) {
        let row_for_tx = intent_row_id(profile.as_str(), intent_id);
        let profile_id = profile.as_str().to_string();
        let status = status.to_string();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO intents (id, profile_id, intent_type, amount, status, \
                         created_at, expires_at) \
                         VALUES (?, ?, 'sponsored_enrollment', '500000', ?, ?, ?)",
                    )
                    .bind(&row_for_tx)
                    .bind(&profile_id)
                    .bind(&status)
                    .bind(1_700_000_000i64)
                    .bind(9_999_999_999i64)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed enrollment intent");
    }

    /// One attempt row against a seeded intent, reserved through
    /// [`outbox::reserve_and_persist_raw_tx`] — the crate's **only**
    /// reservation (Task 8 Wave B, Mandate 1). Writing the row here with a
    /// hand-rolled `INSERT` is not merely discouraged, it is refused by
    /// `tests::this_module_contains_no_reservation_of_its_own`, which scans
    /// this file's source; the first draft of this helper did exactly that and
    /// that test caught it. Going through the production path also means the
    /// row under test carries what production's carries.
    async fn reserve_attempt(
        store: &StreamGStore,
        profile: &AuthenticatedProfileId,
        intent_id: [u8; 32],
    ) -> String {
        let signed = SignedRawTx::new(
            RAW_TX.to_vec(),
            GasUnits::new(TEST_GAS_LIMIT),
            MaxFeePerGas::new(TEST_MAX_FEE_PER_GAS),
        );
        let req = ReservationRequest {
            profile_id: profile.as_str(),
            intent_id,
            chain_id: CHAIN_ID,
            controller: addr(CONTROLLER_KEY),
            action: ActionType::SponsoredEnrollment,
            action_nonce: LIVE_ACTION_NONCE as u64,
            claim_owner: CLAIM_OWNER,
            lease_ttl_seconds: DEFAULT_LEASE_TTL_SECONDS,
        };
        outbox::reserve_and_persist_raw_tx(store, &data_key_hex(), &req, &signed, 1_700_000_000)
            .await
            .expect("reserve an attempt")
            .attempt_id
    }

    /// **The `:intentId` pin.** axum 0.7 / matchit 0.7 treat `{` and `}` as
    /// ordinary path characters, so `"/…/{intentId}"` compiles, does not
    /// panic, and matches only that literal segment — every real request 404s.
    /// `mod.rs`'s `stream_g_paths_never_fall_back_onto_the_pilot_relayer`
    /// would *confirm* that breakage rather than catch it, since it asserts
    /// unknown paths 404.
    ///
    /// Two intents of the **same** profile deliberately: a handler that
    /// ignored the path segment and answered with "an intent of yours" would
    /// pass a single-intent test.
    ///
    /// Mutations this detects:
    /// 1. `"/v1/stream-g/status/:intentId"` → `"…/{intentId}"` in
    ///    `super::super::router` — applied, run, reverted: this test failed
    ///    with `left: 404, right: 200`.
    /// 2. [`get_enrollment_status`] passing a constant instead of the `Path`
    ///    value — one of the two id assertions fails. (Not run: the two
    ///    intents belong to one profile precisely so that this mutation cannot
    ///    hide, and arm 1 already proves the segment reaches the handler.)
    #[tokio::test]
    async fn the_status_route_binds_the_intent_id_from_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let (profile, authorization) = route_profile(&state, "idem-b2-path").await;
        let a = [0xA1u8; 32];
        let b = [0xB2u8; 32];
        seed_enrollment_intent(state.store(), &profile, a, "pending").await;
        seed_enrollment_intent(state.store(), &profile, b, INTENT_STATUS_SUBMITTED).await;

        for expected in [a, b] {
            let hex = bytes32_hex(expected);
            let (status, body) = route_get(&app, &status_uri(&hex), Some(&authorization)).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "a GET naming a real intent must reach the handler (a `{{intentId}}` route would \
                 404): {body}"
            );
            let document: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(
                document["intent_id"].as_str(),
                Some(hex.as_str()),
                "the route answered with an intent other than the one named in the path: {body}"
            );
        }
    }

    /// **Unauthenticated access is 401.** The route is profile-scoped, and the
    /// scoping only means anything if there is a proven profile to scope to.
    ///
    /// Mutation this detects: removing the `AuthenticatedProfile` extractor —
    /// which does not compile, because [`get_enrollment_intent`] takes
    /// `&AuthenticatedProfileId` and there is no other way to obtain one
    /// outside `#[cfg(test)]`.
    #[tokio::test]
    async fn the_status_route_refuses_a_request_with_no_credential() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let (profile, authorization) = route_profile(&state, "idem-b2-noauth").await;
        seed_enrollment_intent(state.store(), &profile, INTENT_ID, "pending").await;
        let uri = status_uri(&bytes32_hex(INTENT_ID));

        let (status, body) = route_get(&app, &uri, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_MISSING_CREDENTIAL}\"}}"));

        let (status, body) = route_get(&app, &uri, Some("Basic dXNlcjpwYXNz")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_MISSING_CREDENTIAL}\"}}"));

        // Paired non-zero arm: the identical request with the credential is
        // served, so the refusals are about the credential and not a dead
        // route.
        let (status, body) = route_get(&app, &uri, Some(&authorization)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// **404, never 403 — for all three meanings of "no".**
    ///
    /// [`get_enrollment_intent`] returns `None` both for an intent that does
    /// not exist and for one under another profile, and
    /// [`get_enrollment_status`] gives a malformed path segment the same
    /// answer. This asserts all three are byte-identical on the wire. A 403
    /// for the foreign case would turn [`intent_row_id`] — SHA-256 over a
    /// domain string, the profile id and a 32-byte intent id — into a
    /// membership test over other people's intents.
    ///
    /// Mutation this detects (applied, run, reverted): mapping
    /// [`SubmitError::IntentNotFound`] to `StatusCode::FORBIDDEN` in
    /// [`SubmitError::status`] — this test failed with `left: 403, right: 404`
    /// and `http_error::tests::stream_g_error_mapping_never_emits_403` failed
    /// alongside it.
    #[tokio::test]
    async fn an_unknown_or_foreign_enrollment_intent_is_404_and_never_403() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let (mine, my_auth) = route_profile(&state, "idem-b2-mine").await;
        let (theirs, _) = route_profile(&state, "idem-b2-theirs").await;
        let shared_intent_id = [0xC3u8; 32];
        seed_enrollment_intent(state.store(), &mine, INTENT_ID, "pending").await;
        // The SAME on-chain intentId under another profile: per-profile
        // namespacing (defect C2) means these are two different rows, and the
        // caller must see only its own — which it does not have.
        seed_enrollment_intent(state.store(), &theirs, shared_intent_id, "pending").await;

        let unknown = route_get(
            &app,
            &status_uri(&bytes32_hex([0x00u8; 32])),
            Some(&my_auth),
        )
        .await;
        assert_eq!(unknown.0, StatusCode::NOT_FOUND);
        assert_eq!(
            unknown.1,
            format!("{{\"error\":\"{ERR_SUBMIT_INTENT_NOT_FOUND}\"}}")
        );

        let foreign = route_get(
            &app,
            &status_uri(&bytes32_hex(shared_intent_id)),
            Some(&my_auth),
        )
        .await;
        assert_ne!(foreign.0, StatusCode::FORBIDDEN);
        assert_eq!(
            foreign, unknown,
            "\"not yours\" and \"not found\" differ on the wire — the route is an ownership oracle"
        );

        // A segment that is not 32 hex bytes names no intent of anybody's.
        let malformed = route_get(&app, &status_uri("not-an-intent-id"), Some(&my_auth)).await;
        assert_eq!(
            malformed, unknown,
            "a malformed intent id must answer exactly as an unknown one does"
        );

        // Paired non-zero arm: the caller's own intent is served, so the three
        // 404s are about addressing and not about a route that finds nothing.
        let (status, body) =
            route_get(&app, &status_uri(&bytes32_hex(INTENT_ID)), Some(&my_auth)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// **A receipt timeout reaches the caller as `receipt_timeout_unknown`,
    /// never as anything failure-shaped.**
    ///
    /// Spec §8.2 and `reconcile::AttemptDisposition` (`StillPending` vs
    /// `MinedRevert`): a mined revert licenses "you were
    /// not charged"; a receipt timeout licenses nothing at all, because the
    /// transaction may still be mined. Collapsing the second into a `failed`
    /// bucket would tell a caller their money is gone when that is exactly
    /// what is not known. The route therefore passes
    /// `reconciliation_events.status` through verbatim — there is no
    /// translation table to get wrong.
    ///
    /// Note what the row itself looks like at this point:
    /// [`apply_disposition`] writes `tx_attempts.status` back to
    /// [`TX_ATTEMPT_STATUS_RESERVED`] for all three concluding dispositions,
    /// which is precisely why that column is not what this route reports.
    ///
    /// Mutations this detects:
    /// 1. bucketing anything that is not `confirmed` into `"failed"` in
    ///    `From<EnrollmentIntentView>` — applied, run, reverted: this test
    ///    failed with `left: Some("failed"), right: Some("receipt_timeout_unknown")`.
    /// 2. dropping the `latest_disposition` subquery from
    ///    [`get_enrollment_intent`] — the field would be `null` and the
    ///    verbatim assertion fails. (Not run: the first mutation already
    ///    exercises the same assertion, from the other end of the same path.)
    #[tokio::test]
    async fn a_receipt_timeout_reaches_the_status_route_as_unknown_never_failed() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let (profile, authorization) = route_profile(&state, "idem-b2-timeout").await;
        seed_enrollment_intent(state.store(), &profile, INTENT_ID, INTENT_STATUS_SUBMITTED).await;
        let attempt_id = reserve_attempt(state.store(), &profile, INTENT_ID).await;

        let uri = status_uri(&bytes32_hex(INTENT_ID));

        // Before reconciliation concludes anything, there is nothing to
        // report — and `null` is the honest value, not an invented state.
        let (status, body) = route_get(&app, &uri, Some(&authorization)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let document: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(
            document["latest_disposition"].is_null(),
            "an intent with no recorded disposition must report none: {body}"
        );

        let applied = apply_disposition(
            state.store(),
            &attempt_id,
            &AttemptDisposition::ReceiptTimeoutUnknown {
                tx_hash_hex: bytes32_hex(TX_HASH),
            },
            1_800_000_000,
        )
        .await
        .expect("record the timeout");
        assert_eq!(
            applied,
            crate::stream_g::reconcile::AppliedDisposition::HeldForSweeper
        );

        let (status, body) = route_get(&app, &uri, Some(&authorization)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let document: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            document["latest_disposition"].as_str(),
            Some(DISPOSITION_STATUS_UNKNOWN),
            "the recorded disposition must reach the caller verbatim: {body}"
        );
        assert!(
            !body.contains("failed"),
            "an unknown receipt outcome must never be reported as a failure: {body}"
        );
        // The intent's own status is untouched by a disposition that concludes
        // nothing: it is still what the pipeline last durably decided.
        assert_eq!(
            document["status"].as_str(),
            Some(INTENT_STATUS_SUBMITTED),
            "{body}"
        );
    }

    /// **Founder ruling: `profile_id` is not on the wire**, and the vocabulary
    /// is the enrollment machine's.
    ///
    /// Mutations this detects:
    /// 1. reporting a fixed `"pending"` instead of the row's status — applied,
    ///    run, reverted: the `executed` arm fails.
    /// 2. adding `profile_id` to [`EnrollmentStatusResponse`] (which is what
    ///    deriving `Serialize` on [`EnrollmentIntentView`] and returning it
    ///    directly would amount to) — both absence assertions fail. Not run as
    ///    a mutation because it is not a one-line edit: `EnrollmentIntentView`
    ///    has no `Serialize` derive to begin with, which is itself the reason
    ///    the two types are separate.
    #[tokio::test]
    async fn the_status_response_omits_profile_id_and_reports_the_enrollment_status() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let (profile, authorization) = route_profile(&state, "idem-b2-shape").await;
        seed_enrollment_intent(state.store(), &profile, INTENT_ID, "pending").await;
        let executed_id = [0xE4u8; 32];
        seed_enrollment_intent(state.store(), &profile, executed_id, INTENT_STATUS_EXECUTED).await;

        let (status, body) = route_get(
            &app,
            &status_uri(&bytes32_hex(INTENT_ID)),
            Some(&authorization),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("\"intent_id\""), "{body}");
        assert!(body.contains("\"created_at\""), "{body}");
        assert!(!body.contains("intentId"), "{body}");
        assert!(!body.contains("createdAt"), "{body}");
        assert!(
            !body.contains("profile_id"),
            "the response must not name profile_id: {body}"
        );
        assert!(
            !body.contains(profile.as_str()),
            "the response must not carry the profile id's value either: {body}"
        );
        let document: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(document["status"].as_str(), Some("pending"));

        // Read from the row, not from a constant.
        let (status, body) = route_get(
            &app,
            &status_uri(&bytes32_hex(executed_id)),
            Some(&authorization),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let document: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(document["status"].as_str(), Some(INTENT_STATUS_EXECUTED));
    }

    // ===================================================================
    // 🔴 `POST /v1/stream-g/submit` — the mounted route (Wave C W4).
    //
    // ## Which arm every route test below is on, stated up front
    //
    // `runtime::test_support::enabled_map` inherits `GOAT_ATTESTOR_MOCK=1`
    // (`enabled_map` calls `Config::test_map`, which sets that key), so
    // `state.trusted_chain()` and `state.live_chain()` are BOTH `None` in
    // every router fixture here, and the no-live-chain arm is the only
    // accepting-side arm a request can reach through `router()`. That is not
    // a gap being papered over — it is `token_manifest::TrustedChain`'s whole
    // design (in a release build its only constructor takes a concrete
    // `RpcChain`), and `RpcChainEnrollmentSigner::new` likewise takes an
    // `&RpcChain` because the broadcaster's private key lives behind it.
    // Faking a live chain through the router would mean building a
    // `StreamGState` that cannot exist in production.
    //
    // So the router tests prove: the route is bound at the path and method
    // claimed, the credential is required before anything else, and the two
    // deployment refusals are the ones claimed and in the order claimed.
    // Everything downstream of that — the whole of
    // `submit_sponsored_enrollment` — is exercised at the layer that CAN hold
    // a `MockChain`, which is every other test in this module, exactly as
    // `quotes.rs` splits its route tests from its library tests.
    //
    // The two tests that bridge the gap are
    // `the_submit_route_context_carries_the_configured_exposure_ceiling` and
    // `the_submit_route_context_refuses_a_sealed_quote_whose_window_has_closed`:
    // they take the fields `submit_context` sources from a REAL
    // `StreamGState` and drive them through a real submit against a
    // `MockChain`, so the handler's assembly and the library's behaviour are
    // joined by a value rather than by a comment.
    // ===================================================================

    use crate::stream_g::http_error::{
        max_submit_request_json, ERR_EXPOSURE_CEILING_UNSET, ERR_NO_LIVE_CHAIN,
    };

    const SUBMIT_PATH: &str = "/v1/stream-g/submit";

    /// [`route_state`] with `STREAM_G_MAX_NATIVE_EXPOSURE_WEI` actually set.
    ///
    /// `route_state` leaves it at the config default of `0`, which
    /// [`post_submit`] refuses outright — so every test that wants to reach
    /// past the first guard has to opt in to a ceiling, which is the point of
    /// the guard.
    async fn route_state_with_ceiling(
        dir: &std::path::Path,
        ceiling_wei: u128,
    ) -> runtime::StreamGState {
        let mut map = runtime::test_support::enabled_map(dir);
        map.insert("STREAM_G_CORS_ORIGINS".into(), ROUTE_ORIGIN.into());
        map.insert(
            "STREAM_G_MAX_NATIVE_EXPOSURE_WEI".into(),
            ceiling_wei.to_string(),
        );
        let cfg = crate::config::load_from_map(&map).expect("stream G config must validate");
        let controller = runtime::ShutdownController::new();
        runtime::StreamGState::start(&cfg, controller.token())
            .await
            .expect("stream G startup")
    }

    /// One request against a cloned app, with an optional `Authorization`.
    async fn route_send(
        app: &Router,
        method: Method,
        uri: &str,
        body: String,
        authorization: Option<&str>,
    ) -> (StatusCode, String) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("origin", ROUTE_ORIGIN)
            .header("content-type", "application/json");
        if let Some(authorization) = authorization {
            builder = builder.header("authorization", authorization);
        }
        let res = app
            .clone()
            .oneshot(builder.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn route_post(
        app: &Router,
        uri: &str,
        body: String,
        authorization: Option<&str>,
    ) -> (StatusCode, String) {
        route_send(app, Method::POST, uri, body, authorization).await
    }

    /// **Unauthenticated access is 401**, and it is 401 *before* either
    /// deployment refusal — which is the ordering that matters here rather
    /// than the status code itself.
    ///
    /// `AuthenticatedProfile` is `FromRequestParts`; the two 503s
    /// [`post_submit`] can raise are statements in its body. So an
    /// uncredentialed caller cannot learn whether this process has a live
    /// chain or an exposure ceiling — both are deployment facts, and neither
    /// is free to probe. The fixture is the **default-ceiling** state
    /// (`route_state`, no `STREAM_G_MAX_NATIVE_EXPOSURE_WEI`), so a handler
    /// that checked the ceiling first *outside* an extractor would show up
    /// here as a 503.
    ///
    /// Mutations this detects:
    /// 1. dropping the `caller: AuthenticatedProfile` parameter — does not
    ///    compile: [`submit_sponsored_enrollment`] takes
    ///    `&AuthenticatedProfileId`, and outside `#[cfg(test)]` there is no
    ///    other way to obtain one. That is the intended guarantee, so there is
    ///    no runtime mutation for it.
    /// 2. `get(post_submit)` instead of `post(..)` — covered by the method
    ///    arm in [`the_submit_route_is_bound_for_post_at_the_flat_path`].
    #[tokio::test]
    async fn the_submit_route_refuses_a_request_with_no_credential() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        assert_eq!(
            state.max_native_exposure_wei().get(),
            0,
            "this fixture must be the UNSET-ceiling state, or the ordering \
             assertion below proves nothing"
        );
        let app = router(state.clone());

        let (status, body) = route_post(&app, SUBMIT_PATH, max_submit_request_json(), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_MISSING_CREDENTIAL}\"}}"));

        // A syntactically valid but unusable scheme is the same refusal.
        let (status, body) = route_post(
            &app,
            SUBMIT_PATH,
            max_submit_request_json(),
            Some("Basic dXNlcjpwYXNz"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_MISSING_CREDENTIAL}\"}}"));

        // A body that would never deserialize gets the *same* 401: the
        // credential is checked first, so a caller cannot probe the DTO's
        // shape — or the process's configuration — without one.
        let (status, body) = route_post(&app, SUBMIT_PATH, "{\"nope\":1}".to_string(), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_MISSING_CREDENTIAL}\"}}"));
    }

    /// **The route is bound**, at `POST /v1/stream-g/submit` and nowhere else,
    /// and a mock-mode process refuses it with the Foundation's
    /// `NO_LIVE_CHAIN` (503).
    ///
    /// A 503 carrying that code can only have come from [`post_submit`]'s
    /// `trusted_chain()` line — nothing else in the crate constructs it on a
    /// `POST` to this path — so this is simultaneously the binding proof and
    /// the refusal proof.
    ///
    /// The body driven through is `http_error::max_submit_request_json()`, the
    /// maximum-width document `super::super::tests::the_body_limit_clears_the_submit_dto`
    /// measures, so this also demonstrates that the real DTO clears the 4 KiB
    /// `DefaultBodyLimit` **on the real route** and not only in that test's
    /// synthetic probe. The ceiling is set, so the first guard is passed
    /// rather than skipped.
    ///
    /// MUTATIONS DETECTED (applied, run, reverted 2026-07-27):
    /// 1. mounting `get(submit::post_submit)` instead of `post(..)` —
    ///    `698 passed; 3 failed`: this test (405 in place of the 503) plus
    ///    both sibling route tests, which stop reaching the handler at all.
    /// 2. deleting the `.route("/v1/stream-g/submit", ..)` line entirely —
    ///    `698 passed; 3 failed`, the same three, this one at
    ///    `left: 404, right: 503`. Note that `mod.rs`'s
    ///    `stream_g_paths_never_fall_back_onto_the_pilot_relayer` would
    ///    *confirm* that breakage rather than catch it, since it asserts
    ///    unknown Stream G paths 404.
    /// 3. resolving `state.trusted_chain()` with anything but
    ///    `ok_or_else(ApiError::no_live_chain)` — a panic or a different code.
    ///    (Not run: `trusted_chain()` returns `Option` and `TrustedChain` has
    ///    no `Default`, so there is no non-panicking one-line alternative.)
    #[tokio::test]
    async fn the_submit_route_is_bound_for_post_at_the_flat_path() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state_with_ceiling(dir.path(), TEST_MAX_NATIVE_EXPOSURE_WEI).await;
        let app = router(state.clone());
        assert!(
            state.trusted_chain().is_none(),
            "this fixture must be the mock-mode arm; see the section comment"
        );

        let (_profile, authorization) = route_profile(&state, "idem-w4-bound").await;

        let (status, body) = route_post(
            &app,
            SUBMIT_PATH,
            max_submit_request_json(),
            Some(&authorization),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body, format!("{{\"error\":\"{ERR_NO_LIVE_CHAIN}\"}}"));
        assert!(
            !body.contains('f'.to_string().repeat(40).as_str()),
            "a refusal must echo none of the request back: {body}"
        );

        // The method arm: the same path under `GET` is a 405, not a 404 and
        // not an answer.
        let (status, _) = route_send(
            &app,
            Method::GET,
            SUBMIT_PATH,
            String::new(),
            Some(&authorization),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "submit is a POST-only route"
        );

        // The path arm: flat and singular, matching `/v1/stream-g/quotes`'s
        // founder ruling. Nothing nested is mounted and there is no fallback.
        let (status, _) = route_post(
            &app,
            "/v1/stream-g/submit/sponsored-enrollment",
            max_submit_request_json(),
            Some(&authorization),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "only /v1/stream-g/submit is mounted"
        );
    }

    /// 🔴 **Hazard 1, at the route: an unset ceiling is a misconfiguration,
    /// not an outage.**
    ///
    /// `STREAM_G_MAX_NATIVE_EXPOSURE_WEI` defaults to `0`
    /// (`config.rs`'s `parse_u128(map, "STREAM_G_MAX_NATIVE_EXPOSURE_WEI", 0)`),
    /// and a ceiling of `0` is one every real reserve exceeds. Without
    /// [`post_submit`]'s first statement an operator who never set it would
    /// see `EXPOSURE_EXCEEDS_SCHEDULE` on every single request — after the
    /// store had been read, the chain pinned and a transaction signed — which
    /// reads as "your transaction is too expensive" rather than "this process
    /// was never given a budget".
    ///
    /// The `NO_LIVE_CHAIN` arm is what makes this a statement about
    /// **ordering** rather than a coincidence: the same fixture, same
    /// credential, same body, and the only difference is the configured
    /// ceiling. A process missing both is told about the one an operator can
    /// fix by setting a variable.
    ///
    /// MUTATIONS DETECTED (applied, run, reverted 2026-07-27):
    /// 1. deleting the `max_native_exposure_wei().get() == 0` guard from
    ///    [`post_submit`] — `700 passed; 1 failed`, this test the only
    ///    failure, at the first arm (`NO_LIVE_CHAIN` in place of
    ///    `EXPOSURE_CEILING_UNSET`).
    /// 2. checking it *after* `trusted_chain()` — the same failure on the
    ///    first arm, which is why the second arm exists: it proves the guard
    ///    is not simply unconditional. (Not run separately; mutation 1
    ///    produces the identical observable.)
    /// 3. comparing against anything but `0` (e.g. `<= 1`) — the second arm
    ///    would have to be re-tuned; as written it passes a real ceiling.
    #[tokio::test]
    async fn the_submit_route_refuses_an_unset_exposure_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let unset = route_state(dir.path()).await;
        assert_eq!(unset.max_native_exposure_wei().get(), 0);
        let app = router(unset.clone());
        let (_, authorization) = route_profile(&unset, "idem-w4-ceiling").await;

        let (status, body) = route_post(
            &app,
            SUBMIT_PATH,
            max_submit_request_json(),
            Some(&authorization),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(
            body,
            format!("{{\"error\":\"{ERR_EXPOSURE_CEILING_UNSET}\"}}"),
            "an unset ceiling must not present as EXPOSURE_EXCEEDS_SCHEDULE, \
             and must not be mistaken for mock mode"
        );

        // The ordering arm. Identical in every respect but the ceiling.
        let dir2 = tempfile::tempdir().unwrap();
        let set = route_state_with_ceiling(dir2.path(), TEST_MAX_NATIVE_EXPOSURE_WEI).await;
        let app2 = router(set.clone());
        let (_, authorization2) = route_profile(&set, "idem-w4-ceiling-set").await;

        let (status, body) = route_post(
            &app2,
            SUBMIT_PATH,
            max_submit_request_json(),
            Some(&authorization2),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(
            body,
            format!("{{\"error\":\"{ERR_NO_LIVE_CHAIN}\"}}"),
            "with a ceiling set, the next refusal is the mock-mode one"
        );
    }

    /// 🔴 **HAZARD 1 — the gate is on the request path, and the ceiling it
    /// enforces is the CONFIGURED one.**
    ///
    /// The chain of calls, each link opened and named rather than assumed:
    ///
    /// 1. `stream_g::router` mounts `post(submit::post_submit)` at
    ///    `/v1/stream-g/submit` (proved by
    ///    [`the_submit_route_is_bound_for_post_at_the_flat_path`]);
    /// 2. [`post_submit`] calls [`submit_context`], which is the **only**
    ///    production construction of [`SubmitContext`] and fills
    ///    `max_native_exposure_wei` from
    ///    `runtime::StreamGState::max_native_exposure_wei` — i.e. from
    ///    `STREAM_G_MAX_NATIVE_EXPOSURE_WEI`;
    /// 3. [`submit_sponsored_enrollment`] copies that field verbatim into
    ///    `broadcaster::BroadcastPlan::max_native_exposure_wei` (its step 4);
    /// 4. `broadcaster::sign_persist_and_broadcast` passes the plan's value to
    ///    `base_fee::submit_exposure_for_chain`, which is the crate's only
    ///    non-test call site of the gate, positioned after signing and before
    ///    `outbox::reserve_and_persist_raw_tx`.
    ///
    /// This test joins links 2 and 3-4 by a **value**: the ceiling is taken
    /// off a real [`runtime::StreamGState`] through [`submit_context`], then
    /// driven through a real submit against a `MockChain` with the gas-price
    /// oracle armed to nonzero values, so the refusal is produced by the
    /// three-term reserve rather than by `l2_wei` alone. The refusal's
    /// `ceiling_wei` is asserted to be the **configured** number, which is
    /// what a hard-coded ceiling anywhere in links 2-4 could not produce.
    ///
    /// Links 1 and 2 cannot be joined in one process here: `router()` needs a
    /// `StreamGState` whose store has no fixture rows, and `MockChain` cannot
    /// be reached through a `StreamGState` at all (see the section comment).
    ///
    /// MUTATIONS DETECTED (each applied alone, run, reverted 2026-07-27) —
    /// see also [`exposure_gate_refuses_between_signing_and_reservation`],
    /// which pins the gate's POSITION and names the mutations for links 3-4:
    /// 1. `max_native_exposure_wei: WeiCeiling::new(u128::MAX)` in
    ///    [`submit_context`] — i.e. the gate is still called, with a ceiling
    ///    nothing can exceed. `700 passed; 1 failed`, this test the **only**
    ///    failure, at `expect_err`.
    /// 2. `max_native_exposure_wei: WeiCeiling::new(0)` in [`submit_context`]
    ///    — `700 passed; 1 failed`, again the only failure. The submit still
    ///    refuses, so a "did it refuse?" test would miss this entirely; what
    ///    catches it is the assertion that `ceiling_wei` is the **configured**
    ///    number.
    /// 3. sourcing `claim_owner` from anywhere but the state — the equality
    ///    assertion fails. (Not run: `mint_submit_claim_owner` is the only
    ///    other producer and calling it here is the bug
    ///    `StreamGState::claim_owner`'s doc forbids in so many words.)
    #[tokio::test]
    async fn the_submit_route_context_carries_the_configured_exposure_ceiling() {
        // One wei below the fixture's real three-term reserve, so the refusal
        // is a genuine boundary decision rather than "everything exceeds 0".
        let configured = EXPOSURE_EXPECTED_RESERVE_WEI - 1;
        let dir = tempfile::tempdir().unwrap();
        let state = route_state_with_ceiling(dir.path(), configured).await;

        let f = fixture();
        let h = harness(&f).await;
        arm_gas_price_oracle(&h.chain);
        let b = FakeSigner::ok();

        // The handler's own assembly, called exactly as `post_submit` calls
        // it. `(&h.chain).into()` is the `#[cfg(test)]`-only `TrustedChain`
        // conversion — a release build has no such impl.
        let from_route = submit_context(&state, (&h.chain).into(), &b);
        assert_eq!(
            from_route.max_native_exposure_wei.get(),
            configured,
            "the route's context must carry the CONFIGURED ceiling"
        );
        assert_eq!(
            from_route.claim_owner,
            state.claim_owner(),
            "claim_owner must be the process's, never minted per request"
        );
        // Pointer equality, not value equality: a freshly built
        // `SigningLeaseRegistry` is *equal* to the state's in every observable
        // way and would pass any structural assertion, while silently ending
        // the exclusion `try_acquire` exists to provide — two concurrent
        // submits would each acquire "the" lease for one action nonce. Only
        // identity distinguishes the bug from the correct wiring. Without this,
        // substituting `SigningLeaseRegistry::new()` at the `submit_context`
        // seam compiles and the whole suite stays green, which is the mutation
        // `submit_context`'s own doc claims to guard against.
        assert!(
            std::ptr::eq(from_route.leases, state.leases()),
            "the route's context must borrow the process-wide lease registry, \
             never a per-request one"
        );

        // The store, manifest and leases stay the harness's — the fixture rows
        // live there — so the ONE thing crossing from the route's assembly
        // into this submit is the field under test.
        let ctx = SubmitContext {
            max_native_exposure_wei: from_route.max_native_exposure_wei,
            ..h.ctx(&b)
        };
        let err = submit_sponsored_enrollment(&ctx, &profile(), &f.parts())
            .await
            .expect_err("the configured ceiling is below the real reserve");

        match &err {
            SubmitError::NativeExposure(BaseFeeError::ExposureExceedsSchedule {
                reserve_wei,
                ceiling_wei,
            }) => {
                assert_eq!(*reserve_wei, EXPOSURE_EXPECTED_RESERVE_WEI);
                assert_eq!(
                    *ceiling_wei, configured,
                    "the gate must have enforced the CONFIGURED ceiling, not a literal"
                );
            }
            other => panic!("expected NativeExposure(ExposureExceedsSchedule), got {other:?}"),
        }
        assert_eq!(
            h.sends(),
            0,
            "THE HAZARD: a request-path submit broadcast above the ceiling"
        );

        // A second state at a different ceiling, to show the value tracks
        // configuration rather than happening to equal one constant.
        let dir2 = tempfile::tempdir().unwrap();
        let other = route_state_with_ceiling(dir2.path(), TEST_MAX_NATIVE_EXPOSURE_WEI).await;
        assert_eq!(
            submit_context(&other, (&h.chain).into(), &b)
                .max_native_exposure_wei
                .get(),
            TEST_MAX_NATIVE_EXPOSURE_WEI
        );
    }

    /// The sealed-quote revalidation still holds on the route's own context.
    ///
    /// The property is Wave C W3's and is pinned in depth by
    /// [`a_sealed_quote_whose_window_has_closed_is_refused_against_chain_time`],
    /// [`a_sealed_quote_the_intent_does_not_commit_to_is_refused`],
    /// [`a_sealed_quote_signed_by_the_wrong_key_is_refused`] and
    /// [`each_sealed_quote_field_is_independently_revalidated`]. What W4 adds
    /// is that mounting did not route around it: the context the handler
    /// assembles is the context those checks run under, and a quote whose
    /// sealed window closed before the pinned block's timestamp is still
    /// refused — with nothing signed, nothing reserved and nothing sent.
    ///
    /// Expiry is the case chosen here because it is the one that was *not*
    /// re-established by a comparison: it rides on `Check::QuoteWindow`
    /// reading the reconstructed quote, which only works because the
    /// reconstruction happens before the preflight. A handler that assembled
    /// its context correctly but reordered those two steps would still fail
    /// this.
    ///
    /// MUTATION DETECTED (applied, run, reverted 2026-07-27):
    /// `QuoteCommitment::to_fee_quote` returning `valid_until: u64::MAX`
    /// instead of the sealed value — `670 passed; 31 failed`, this test among
    /// them (the broad blast radius is expected: that field is part of the
    /// EIP-712 digest, so every fixture's `FeeQuoteHashMismatch` fires too).
    /// Reconstructing the quote *after* the preflight has the same effect on
    /// this test and is the mutation
    /// [`a_sealed_quote_whose_window_has_closed_is_refused_against_chain_time`]
    /// names.
    #[tokio::test]
    async fn the_submit_route_context_refuses_a_sealed_quote_whose_window_has_closed() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state_with_ceiling(dir.path(), TEST_MAX_NATIVE_EXPOSURE_WEI).await;

        let mut g = fixture();
        // Closed one second before the pinned block's timestamp, re-signed and
        // rebound so the window is the only thing wrong.
        g.quote.valid_until = CHAIN_NOW - 1;
        g.rebind_quote();
        let h = harness(&g).await;
        arm_gas_price_oracle(&h.chain);
        let b = FakeSigner::ok();

        let from_route = submit_context(&state, (&h.chain).into(), &b);
        let ctx = SubmitContext {
            max_native_exposure_wei: from_route.max_native_exposure_wei,
            claim_owner: from_route.claim_owner,
            ..h.ctx(&b)
        };

        let err = submit_sponsored_enrollment(&ctx, &profile(), &g.parts())
            .await
            .expect_err("sealed quote window closed at the pinned block");
        assert_eq!(err.code(), preflight::ERR_PREFLIGHT_WOULD_REVERT);
        assert_eq!(would_revert_check(&err), Check::QuoteWindow);
        // Re-quote, not "stop": nothing was consumed on chain.
        assert_eq!(err.retryability(), Retryability::Retryable);
        assert_eq!(b.sign_calls(), 0, "an expired quote must never be signed");
        assert_eq!(h.sends(), 0);
    }
}
