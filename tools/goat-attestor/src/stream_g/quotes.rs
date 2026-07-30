//! Stream G quote lifecycle (Task 6a) — fixed USDT tariff, hard token
//! capability gate, native exposure gate, EIP-712 `FeeQuote` signing.
//!
//! ## Fixed tariff vs. gas/oracle values — the separation this module
//! exists to prove (brief §3.1)
//! `fee_amount` comes **only** from [`FeeSchedule`], a fixed table keyed by
//! [`crate::stream_g::models::ActionType`] and loaded from
//! `StreamGConfig::fee_schedule_path`. There is no ETH/USD price feed
//! anywhere in this crate, and this module never introduces one — the
//! `quote_uses_fixed_usdt_tariff_not_eth_usd_oracle` test proves `fee_amount`
//! is byte-identical across wildly different `MockChain` gas-oracle values.
//!
//! [`base_fee::quote_exposure`] (Task 5) is consulted in the *same* call —
//! but strictly as a **gate**, never a price input: it computes how much
//! native ETH the eventual broadcast will need to reserve
//! (`GasPriceOracle.getL1FeeUpperBound` / `getOperatorFee`, both wei-typed
//! and both about the *native* gas cost of the future transaction) and
//! rejects the quote outright if that reserve exceeds
//! `StreamGConfig::max_native_exposure_wei`. Nothing about that check ever
//! flows into `fee_amount`, which is the USDT amount the payer will actually
//! be charged. Conflating the two — e.g. scaling `fee_amount` by a gas
//! price, or using the exposure reserve as a fee — is exactly the hazard
//! this module's first test guards against.
//!
//! ## Hazard 3 — the token gate runs first, before anything else
//! [`token_manifest::assert_token_authorized`] is the very first statement
//! in [`create_sponsored_enrollment_quote`]'s body — ahead of the data-key
//! parse (which used to precede it and made this claim false; see
//! `tests::token_gate_runs_before_the_data_key_is_even_parsed`), ahead of
//! the nested bearer signatures being parsed, ahead of
//! [`base_fee::quote_exposure`] touching the chain, and ahead of
//! [`FeeSchedule::fee_for`]. `stream_g` has no gas-drip
//! dependency at all (confirmed by the same structural source-scan
//! `token_manifest.rs`'s own analogous test uses — see
//! `tests::unsupported_token_quote_makes_zero_gas_drip_calls`), so there is
//! no real drip call site in this crate to test ordering against directly;
//! `tests::unsupported_token_quote_is_rejected_before_exposure_gate_or_signing`
//! uses [`crate::chain::MockChain`]'s call counters as the concrete,
//! non-tautological stand-in — if the token check were ever moved after
//! the exposure gate, those counts would go from `0` to non-zero and the
//! test would fail.
//!
//! ## Nothing the caller sends decides what gets signed (I1)
//! `actionCoreHash` is the binding between this quote and the intent that
//! will execute against it, and `GoatRelayGateway.sol:355-395` re-derives
//! or hard-constrains four of its fields. Each therefore has a
//! *server-side* answer here, never a caller-supplied one:
//! - `enrollDigest` — derived by [`sig_verify::enroll_digest`], the
//!   reproduction of `StreamGEnroll._v1EnrollDigest`;
//!   the V1 bearer signature is verified against that derived value.
//! - `linkDigest` — derived by [`link_secondary_digest`], the reproduction
//!   of `StreamGEnroll._linkDigest`; likewise.
//!
//!   Both request fields were **deleted** rather than validated, the same
//!   structural move `fee_recipient` uses: the gateway cannot disagree with
//!   a value the caller has no way to name. Before that, the module derived
//!   the LinkSecondary digest anyway, used it only for recovery, threw it
//!   away, and signed the caller's claim instead — and its own fixture
//!   passed `0x0101…01`/`0x0202…02` with all tests green.
//! - `rootAuthorizationDigest` — required to be zero (`:365` reverts
//!   `InvalidFeeFields`); a non-zero value is rejected here.
//! - `feeAuthorizationMode` — required to be
//!   [`AUTHORIZATION_MODE_EIP2612`] (`:395` reverts `UnsupportedFeeMode`).
//!   `PRIOR_ALLOWANCE` (3) is a valid ordinal of the same enum and a
//!   plausible client value, so this is a real rejection, not a formality.
//!
//! ## Chain time, not the host wall clock (I2)
//! `validAfter`/`validUntil` are compared to `block.timestamp`
//! (the `quote.validAfter <= block.timestamp && block.timestamp < quote.validUntil` line of `StreamGCommon.validateAndConsumeQuote`), so STEP 4 cuts the window from
//! `ChainClient::block_timestamp()` and **fails closed** if it cannot —
//! including on the trait default's `Ok(0)` "unknown". There is no
//! wall-clock fallback. The host clock survives only as the local
//! `created_at`/`authorized_at` bookkeeping value (see
//! [`create_sponsored_enrollment_quote_at`]).
//!
//! ## Live values this module does not read itself
//! [`EnrollmentQuoteContext`] still receives them from its caller, but the
//! two security-critical ones now arrive in types only a chain read can
//! build: `token_manifest::LiveTokenReading` (via
//! `token_manifest::read_live_token_state`) and
//! `models::LiveEnrollmentNonces` (via
//! `LiveEnrollmentNonces::read_live`). This module does not choose the
//! pinned block and does not check the reading against
//! `activeManifestHash()` (sourcing contract R2 step 2 — still owed to a
//! later task). It DOES compare the snapshot's `feeTokenConfigHash` against
//! the registry's (R3's anti-TOCTOU binding) — immediately after the STEP 0
//! gate, see [`QuoteError::FeeTokenConfigHashToctouMismatch`] — see those
//! types' docs for the exact "not guaranteed" list of everything else.
//!
//! ## `feeScheduleHash`: a digest of the schedule's own values
//! This used to be an opaque governance tag — an arbitrary `bytes32` knob
//! with no relationship to any file's contents — because no canonicalisation
//! rule existed to derive one from. **That is no longer true.**
//! The "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring" spec, §8.1,
//! publishes the rule verbatim:
//!
//! > "feeScheduleHash = keccak256(UTF8(RFC8785(schedulePayload)))."
//!
//! [`FeeSchedule::from_json`] now computes exactly that over the document's
//! `payload` object (see [`crate::canonical_json`] for the byte-producing
//! floor). It, not [`FeeSchedule::load`], is the entry point
//! `runtime::StreamGState::start` calls — `load` is the path-taking wrapper
//! and has zero production call sites. `start` then refuses to start unless
//! the digest equals **both** the hash the file declares and the hash the
//! deployment manifest carries. So a quote's `feeScheduleHash` is now an
//! attestation about the
//! tariff *values* this process actually loaded, not about a label an
//! operator typed.
//!
//! The on-chain value is operator-supplied, and `STREAM_G_FEE_SCHEDULE_HASH` is
//! now **required** at deploy: `contracts/script/DeployStreamG.s.sol` reads it
//! with `vm.envBytes32`, matching `contracts/script/PublishStreamG.s.sol:27`. It
//! used to fall back to `keccak256("stream-g-fee-schedule-g1")`, and that
//! default had to go — no payload hashes to it, so a deploy that never set the
//! variable published a value no file could produce, and the contradiction
//! surfaced here at service startup instead of at the deploy that caused it.
//! Publishing a schedule therefore means computing the payload digest and
//! passing it as `STREAM_G_FEE_SCHEDULE_HASH`.
//!
//! Changing that value on an already-deployed gateway is a **Policy Safe**
//! transaction — `GoatRelayGateway.setFeeScheduleHash` is `onlyPolicy`
//! (`contracts/src/GoatRelayGateway.sol:154-157`) and is the only writer of the
//! value `StreamGCommon.sol:122-124` checks each quote against.
//!
//! The quote path itself is unchanged: it signs
//! `EnrollmentQuoteContext::manifest`'s `fee_schedule_hash`, which startup has
//! already proven equal to the loaded schedule's digest.
//!
//! ## Store discipline
//! Idempotency is decided **inside** the same [`StreamGStore::write_tx`]
//! that acts on the decision — `SELECT quote_enc, profile_id FROM quotes
//! WHERE id = ?` is the closure's first statement, matching
//! `root_authorization.rs:692-743`. It used to be a plain
//! [`StreamGStore::read`] before the transaction, which `store.rs:465-472`
//! documents as giving no snapshot isolation: two concurrent *true* replays
//! both read empty, both signed, and the loser was told
//! `IDEMPOTENCY_KEY_CONFLICT` instead of being handed the stored quote.
//! (Nothing unsafe was ever released — signing is RFC 6979 deterministic,
//! so both tasks produce byte-identical signatures — but the idempotency
//! contract was wrong.) `BEGIN IMMEDIATE` takes SQLite's writer lock for
//! the whole closure, so no commit can now interleave between the check and
//! the inserts. Because the closure cannot borrow `store`
//! (`store.rs:419-424` re-entrancy hazard: one connection, a nested call
//! deadlocks to `PoolTimedOut`), `db_uuid`/`schema_version` are pulled into
//! owned locals first and the [`crypto_store::EnvelopeAad`] is built by hand
//! inside — again the pattern `root_authorization.rs:687-688` set.
//!
//! Signing still happens *before* the transaction opens, and that is still
//! sound for the same reason as before: it is a pure, deterministic ECDSA
//! operation over values already fixed, so it cannot desynchronize anything
//! the way `root_authorization.rs`'s nonce-then-sign ordering matters for a
//! *stateful* nonce allocator. On the replay path the freshly-computed
//! signature is simply discarded in favour of the stored one.
//!
//! The write itself (`quotes` + `intents` + `authorizations` +
//! `authorization_slots`, all four rows for one enrollment quote) happens in
//! that same single `write_tx`, every `INSERT OR IGNORE`'s
//! `rows_affected()` checked, per this repo's non-negotiable store
//! discipline.
//!
//! ## Idempotency: what the body hash covers, and what row ids are
//! The replay-vs-conflict body hash covers **caller-supplied request
//! parameters only**. Nothing derived from the server's clock may enter it:
//! `valid_after`/`valid_until` used to, which meant a byte-identical retry
//! one second later hashed differently and was rejected as a conflict, so
//! idempotency worked only within a single UNIX second and the one
//! documented recovery from a lost HTTP response was a permanent dead end.
//! See [`canonical_body_string`].
//!
//! `intents.id` is **profile-namespaced**
//! (`sha256(INTENT_ROW_ID_DOMAIN || "|" || profile_id || "|" ||
//! intent_id_hex)`), not the raw caller-supplied on-chain `intentId`.
//! `migrations/0001_stream_g.sql:104-106` makes that column a *global*
//! `TEXT PRIMARY KEY`, so binding the raw value there let any authenticated
//! profile permanently claim any 32-byte intentId for everybody — a
//! cross-profile denial of service with no recovery (the intentId is bound
//! into `actionCoreHash` and *is* the intent's identity), an existence
//! oracle for arbitrary intentIds, and a poisoned
//! `SELECT profile_id FROM intents WHERE id = ?` for
//! `root_authorization.rs`'s ownership check. `onboarding.rs`, the only
//! other writer of this table, already namespaced for the same reason.
//! Nothing is lost by not pre-empting the id server-side: the gateway
//! consumes `intentId` at *execution* (`intentUsed[intentId]`), not at
//! quote time. The raw value is carried in the sealed
//! `intents.intent_enc` payload ([`EnrollmentIntentPayload`]).
//!
//! ### Re-quoting an intent after expiry (Task 4 gap closure)
//! Namespacing makes `intents.id` unique per `(profile_id, intentId)`, so a
//! profile still gets exactly one `intents` row per on-chain intentId. One
//! consequence is deliberate and one used to be a dead end, now closed by
//! an explicit architect ruling:
//! - Deliberate, unchanged: the *same* profile submitting the *same*
//!   intentId under a *different* idempotency key, while the prior quote is
//!   still valid, is still rejected. That request genuinely asks for a
//!   second live quote against a single-use on-chain intent.
//! - **Closed:** once a quote expires ([`QuoteError::StoredQuoteExpired`]),
//!   the SAME profile CAN now obtain a fresh quote for that intentId under
//!   a NEW idempotency key. The prior dead end — the same key forever
//!   returning `QUOTE_EXPIRED`, a fresh key forever colliding on the
//!   still-present `intents` row and returning `IDEMPOTENCY_KEY_CONFLICT`
//!   — had no recovery for a legitimate caller, even though expiry exists
//!   precisely so they can retry. This is safe on-chain because the
//!   gateway consumes `intentId` only at *execution*
//!   (`intentUsed[intentId]`, `GoatRelayGateway.sol`'s
//!   `_markIntentAndNonce`), never at quote time, so an unexecuted, expired
//!   intentId is still fresh. The `intents` row is superseded IN PLACE
//!   inside the same `write_tx` (never deleted and reinserted, so C2's
//!   profile-namespaced id keeps doing its job): `quote_id`, `intent_enc`,
//!   `amount`, `created_at` and `expires_at` all move to the new quote, and
//!   the prior `quotes` row is marked `'expired'` so there are never two
//!   rows simultaneously readable as "the" live quote for one intent.
//!   Expiry is judged against CHAIN time (`chain.block_timestamp()`), the
//!   same I2 predicate the replay-expiry branch above uses, and superseding
//!   is scoped strictly to the row's OWN stored `profile_id` — a different
//!   profile computes a different (namespaced) `intents.id` and never even
//!   reaches this code path, so this does not reintroduce C2's cross-profile
//!   squat.
//!
//! ## Column mapping onto the frozen schema (schema is generic; this quote
//! shape is specific)
//! - `quotes.base_asset` = the fee token's `0x`-hex address;
//!   `quotes.quote_asset` = the fixed marker string
//!   [`QUOTES_TABLE_QUOTE_ASSET_MARKER`] (this is a flat fee quote, not a
//!   base/quote swap pair); `quotes.base_amount` = `"0"`;
//!   `quotes.quote_amount` = `fee_amount` as a decimal string;
//!   `quotes.fee_bps` = `NULL` (a flat USDT tariff, not a bps-of-notional
//!   fee). `quotes.quote_enc` seals the full [`FeeQuote`] + signature +
//!   idempotency body hash.
//! - `intents` gets one row per quote (`intent_type = "sponsored_enrollment"`,
//!   `quote_id` = the `quotes.id` FK, `id` = the profile-namespaced digest
//!   described above, `intent_enc` = the sealed
//!   [`EnrollmentIntentPayload`] carrying the raw on-chain `intentId`).
//! - `authorizations` gets one row per quote representing the **nested
//!   bearer-signature bundle** this module itself verified (V1Enrollment +
//!   LinkSecondary) — a different concept from `root_authorization.rs`'s
//!   *issuer*-signed `authorizations` rows, reusing the same table because
//!   it is the only schema-frozen home for a sealed signature payload tied
//!   to an intent. `authorizations.signature_enc` seals BOTH nested
//!   signatures (there is no signature-bearing column on
//!   `authorization_slots` itself — see next point).
//! - `authorization_slots` gets exactly two rows (`slot_index` 0 =
//!   V1Enrollment, `slot_index` 1 = LinkSecondary) — "reserving the nested
//!   slots" per brief §3.4. `authorization_slots` has no `_enc`/BLOB
//!   column of its own; the slot rows are the reservation ledger, the
//!   actual sealed content lives on the parent `authorizations` row.
//!   Consistent with that, and with the schema's own `'pending'` default,
//!   they are written `status = `[`SLOT_STATUS_RESERVED`]` / `filled_at =
//!   NULL` — quoting reserves a slot, it does not fill one. They were
//!   previously written `'filled'` with a non-NULL `filled_at` at quote
//!   time, which contradicted this paragraph and would have told 6b that
//!   work had happened which had not. 6b's submit path performs the
//!   transition to `'filled'`.
//!
//! No `nonce_allocations` or `budget_reservations` writes happen here —
//! brief §3.3: "No gateway-action nonce reservation at quote time...
//! Reservation happens at submit (6b)."

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Signature, B256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use thiserror::Error;

use super::base_fee::{self, BaseFeeError, GasUnits, MaxFeePerGas, TxSizeBytes};
use super::crypto_store::{self, CryptoStoreError, DataKey, EnvelopeAad, SecretHex};
use super::http_error::{ApiError, ApiJson};
use super::models::{
    fee_quote_digest, link_secondary_digest, sponsor_enrollment_core_hash, ActionType,
    CreateSponsoredEnrollmentQuoteRequest, EnrollmentQuoteContext, FeeQuote, LinkSecondary,
    LiveEnrollmentNonces, QuoteResult, SponsorEnrollmentCore,
};
use super::preflight::PreflightError;
use super::profile_auth::{AuthenticatedProfile, AuthenticatedProfileId};
use super::runtime::StreamGState;
use super::store::{StreamGStore, StreamGStoreError};
use super::token_manifest::{self, Capability, TokenManifestError, TrustedChain};
use crate::chain::ChainClient;
use crate::sig_verify;

/// See module doc's "Column mapping" section.
pub const QUOTES_TABLE_QUOTE_ASSET_MARKER: &str = "STREAM_G_SPONSORED_ENROLLMENT_FEE_QUOTE_V1";

/// Server-side cap on `valid_for_seconds` (brief §2.4:
/// `validAfter <= now < validUntil` must hold at execution time, so a quote
/// TTL that is too long just wastes the window uselessly and one that is
/// absurdly long is a footgun) — same 15-minute policy shape
/// `root_authorization.rs`'s `ROOT_AUTHORIZATION_TTL_SECONDS` uses for an
/// analogous bearer credential.
pub const QUOTE_TTL_SECONDS_MAX: u64 = 15 * 60;

/// `2^48 - 1` — `validAfter`/`validUntil` (`StreamGTypes.sol`'s `FeeQuote`),
/// `SponsorEnrollmentCore.deadline` (`:137`) and `LinkSecondary.deadline`
/// (`:191`) are all `uint48` on-chain.
const UINT48_MAX: u64 = (1u64 << 48) - 1;

/// `uint8(StreamGTypes.AuthorizationMode.EIP2612)`, read from
/// `contracts/src/StreamGTypes.sol:12-17` (`NONE`=0, `EIP2612`=1,
/// `EIP3009`=2, `PRIOR_ALLOWANCE`=3) — the only mode
/// `GoatRelayGateway.sol:395` will execute on the sponsored-enrollment fee
/// path.
///
/// This is an **enum ordinal**, deliberately NOT
/// [`token_manifest::CAP_EIP2612`], which is a bit in an independent
/// capability BITMASK (`StreamGTypes.sol:29-32`). They happen to share the
/// value `1`; that is a coincidence of two different numbering schemes and
/// `token_manifest`'s module doc — "`CAP_*` bits vs `AuthorizationMode`
/// ordinals: independent numbering" — warns explicitly against conflating
/// them.
const AUTHORIZATION_MODE_EIP2612: u8 = 1;

pub const ERR_FEE_SCHEDULE_IO: &str = "FEE_SCHEDULE_IO_ERROR";
pub const ERR_FEE_SCHEDULE_PARSE: &str = "FEE_SCHEDULE_PARSE_ERROR";
pub const ERR_MISSING_TARIFF: &str = "MISSING_TARIFF";
pub const ERR_ZERO_FEE_AMOUNT: &str = "ZERO_FEE_AMOUNT";
pub const ERR_FEE_EXCEEDS_MAX: &str = "FEE_EXCEEDS_MAX";
pub const ERR_BAD_ADDRESS: &str = "BAD_ADDRESS";
pub const ERR_BAD_DIGEST: &str = "BAD_DIGEST";
pub const ERR_BAD_AMOUNT: &str = "BAD_AMOUNT";
pub const ERR_BAD_V1_SIGNATURE: &str = "BAD_V1_SIGNATURE";
pub const ERR_BAD_LINK_SIGNATURE: &str = "BAD_LINK_SIGNATURE";
pub const ERR_STALE_OR_MIXED_NONCE: &str = "STALE_OR_MIXED_NONCE";
pub const ERR_VALIDITY_EXCEEDS_POLICY: &str = "VALIDITY_EXCEEDS_POLICY";
pub const ERR_VALIDITY_EXCEEDS_UINT48: &str = "VALIDITY_EXCEEDS_UINT48";
pub const ERR_DEADLINE_EXCEEDS_UINT48: &str = "DEADLINE_EXCEEDS_UINT48";
pub const ERR_NON_ZERO_ROOT_AUTHORIZATION_DIGEST: &str = "NON_ZERO_ROOT_AUTHORIZATION_DIGEST";
pub const ERR_UNSUPPORTED_FEE_MODE: &str = "UNSUPPORTED_FEE_MODE";
pub const ERR_CHAIN_TIME_UNAVAILABLE: &str = "CHAIN_TIME_UNAVAILABLE";
pub const ERR_IDEMPOTENCY_KEY_CONFLICT: &str = "IDEMPOTENCY_KEY_CONFLICT";
pub const ERR_QUOTE_EXPIRED: &str = "QUOTE_EXPIRED";
/// R3 anti-TOCTOU binding (sourcing contract §3): `ctx.live_token`'s and
/// `ctx.live_nonces`' `feeTokenConfigHash` values disagree, meaning the two
/// reads were not taken at the same chain state.
pub const ERR_FEE_TOKEN_CONFIG_HASH_TOCTOU_MISMATCH: &str = "FEE_TOKEN_CONFIG_HASH_TOCTOU_MISMATCH";
/// The loaded schedule payload's `decimals` disagrees with the `decimals` the
/// fee-token registry reports for this deployment's fee token — see
/// [`assert_schedule_decimals_match_live_token`].
pub const ERR_FEE_SCHEDULE_DECIMALS_MISMATCH: &str = "FEE_SCHEDULE_DECIMALS_MISMATCH";

/// C2: domain-separation tag for `intents.id`, which is
/// `sha256(INTENT_ROW_ID_DOMAIN || "|" || profile_id || "|" || intent_id_hex)`
/// rather than the raw caller-supplied on-chain `intentId`. Same shape as
/// `onboarding.rs`'s `sha256("primary_onboarding|" || profile_id || "|" ||
/// idempotency_key)` — the only other writer of this table — so the two
/// namespaces cannot collide with each other either.
const INTENT_ROW_ID_DOMAIN: &str = "stream_g_sponsored_enrollment_intent";

/// C2/M7: `authorization_slots.status` at quote time. The slot rows are a
/// *reservation* ledger (module doc "Column mapping"), and quoting reserves
/// slots — it does not fill them. They transition to `'filled'` with a
/// non-NULL `filled_at` when 6b actually submits.
const SLOT_STATUS_RESERVED: &str = "reserved";

#[derive(Debug, Error)]
pub enum QuoteError {
    #[error("store error: {0}")]
    Store(#[from] StreamGStoreError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoStoreError),
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("token authorization failed: {0}")]
    TokenUnauthorized(#[from] TokenManifestError),
    #[error("native exposure gate failed: {0}")]
    Exposure(#[from] BaseFeeError),
    #[error("failed to read fee schedule {path}: {detail}")]
    FeeScheduleIo { path: String, detail: String },
    #[error("failed to parse fee schedule {path}: {detail}")]
    FeeScheduleParse { path: String, detail: String },
    #[error("fee schedule has no tariff for action {0}")]
    MissingTariff(&'static str),
    #[error("fee schedule tariff for action {0} is zero")]
    ZeroFeeAmount(&'static str),
    #[error("quoted fee {fee_amount} exceeds the caller's maxFee {max_fee}")]
    FeeExceedsMax { fee_amount: u128, max_fee: u128 },
    /// **Carries the field name and the input's length, never the input.**
    ///
    /// These three variants used to hold `s.to_string()` — the caller's own
    /// untrimmed bytes — and `super::http_error::ApiError::into_response`
    /// renders an error's `Display` into a `tracing` field with `%`
    /// (`http_error.rs:249`, `:257`), which the default `fmt` visitor writes
    /// **unescaped**. JSON strings may contain newlines, so a caller could put
    /// `\n` in `root_address` / `secondary_address` / `intent_id_hex` and forge
    /// whole log lines (~1 KiB per request, `POST /v1/stream-g/quotes` being
    /// the first mounted route feeding free-form caller hex in here).
    ///
    /// For a fixed-width hex field the input is not diagnostic anyway: "which
    /// field, and how long was it" is the entire actionable content of "that
    /// was not 40 hex characters". Dropping the bytes also removes the
    /// per-request log amplification. Recording the detail with `?` instead of
    /// `%` would have escaped the control characters, but would have kept both
    /// the echo and the amplification — so it is the fallback, not the fix.
    /// `tests::a_newline_in_a_caller_hex_field_cannot_forge_a_log_line` is the
    /// pin.
    #[error("bad address in {field} ({len} bytes)")]
    BadAddress { field: &'static str, len: usize },
    #[error("bad digest in {field} ({len} bytes)")]
    BadDigest { field: &'static str, len: usize },
    #[error("bad decimal amount in {field} ({len} bytes)")]
    BadAmount { field: &'static str, len: usize },
    #[error("nested V1 enrollment bearer signature invalid: {0}")]
    BadV1Signature(String),
    #[error("nested link-secondary bearer signature invalid: {0}")]
    BadLinkSignature(String),
    #[error("nested bearer nonce is stale or mixed with a different snapshot")]
    StaleOrMixedNonce,
    #[error("valid_for_seconds exceeds the server-side quote TTL policy")]
    ValidityExceedsPolicy,
    #[error("computed validUntil does not fit in uint48")]
    ValidityExceedsUint48,
    /// M8. `SponsorEnrollmentCore.deadline` (`StreamGTypes.sol:137`) and
    /// `LinkSecondary.deadline` (`:191`) are both `uint48`. A value with
    /// dirty high bits produces a signed `actionCoreHash` no conforming
    /// on-chain intent can ever reproduce.
    #[error("{field} = {value} does not fit in uint48")]
    DeadlineExceedsUint48 { field: &'static str, value: u64 },
    /// I1. `GoatRelayGateway.sol:365` reverts `InvalidFeeFields` unless
    /// `intent.rootAuthorizationDigest == bytes32(0)` on this path.
    #[error("rootAuthorizationDigest must be zero for a sponsored enrollment")]
    NonZeroRootAuthorizationDigest,
    /// I1. `GoatRelayGateway.sol:395` reverts `UnsupportedFeeMode` unless
    /// `intent.feeAuthorizationMode == uint8(AuthorizationMode.EIP2612)`.
    #[error("feeAuthorizationMode {0} is not AuthorizationMode.EIP2612")]
    UnsupportedFeeMode(u8),
    /// I2. The validity window is cut from `block.timestamp`, never the
    /// host wall clock. If chain time cannot be read, no quote is issued —
    /// there is no wall-clock fallback.
    #[error("chain time unavailable, refusing to issue a quote: {0}")]
    ChainTimeUnavailable(String),
    /// R3 anti-TOCTOU binding (sourcing contract §3): the fee-token config
    /// the STEP 0 gate just authorized (`ctx.live_token`) and the nonces
    /// this quote is about to commit to (`ctx.live_nonces`) were observed
    /// in DIFFERENT chain states — their `feeTokenConfigHash` values
    /// disagree. Fail closed rather than sign a quote that binds nonces to
    /// a token configuration the gate never actually checked.
    #[error(
        "fee token config hash mismatch (anti-TOCTOU, sourcing contract R3): \
         live_token reported {live_token} but live_nonces snapshot reported {live_nonces}"
    )]
    FeeTokenConfigHashToctouMismatch {
        live_token: String,
        live_nonces: String,
    },
    /// The loaded fee schedule's `payload.decimals` is not the `decimals` the
    /// fee-token registry reports for this deployment's fee token — see
    /// [`assert_schedule_decimals_match_live_token`], which is the only
    /// producer.
    ///
    /// Both numbers are operator/deployment facts, so both are safe to name
    /// in the `Display` text (which goes to `tracing`, never to the body).
    #[error(
        "fee schedule declares payload.decimals {payload_decimals} but the fee-token registry \
         reports {live_decimals} for this deployment's fee token"
    )]
    FeeScheduleDecimalsMismatch {
        payload_decimals: u128,
        live_decimals: u8,
    },
    #[error("invalid quote-signer private key: {0}")]
    InvalidQuoteSignerKey(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("malformed sealed payload: {0}")]
    MalformedPayload(String),
    #[error("idempotency key already used with different request parameters")]
    IdempotencyKeyConflict,
    /// M6. A true replay whose stored quote's `validUntil` has already
    /// passed. Distinct from [`QuoteError::IdempotencyKeyConflict`] on
    /// purpose: the request was *correct*, it simply arrived too late, and
    /// conflating the two would tell the caller its parameters were wrong.
    #[error("the stored quote for this idempotency key has expired")]
    StoredQuoteExpired,
}

impl QuoteError {
    /// Stable string code for routes to surface. Delegates to the wrapped
    /// error's own `.code()` where one exists (`token_manifest`,
    /// `base_fee`), so a caller sees exactly the same code either module
    /// would have produced directly.
    pub fn code(&self) -> &'static str {
        match self {
            QuoteError::TokenUnauthorized(e) => e.code(),
            QuoteError::Exposure(e) => e.code(),
            QuoteError::FeeScheduleIo { .. } => ERR_FEE_SCHEDULE_IO,
            QuoteError::FeeScheduleParse { .. } => ERR_FEE_SCHEDULE_PARSE,
            QuoteError::MissingTariff(_) => ERR_MISSING_TARIFF,
            QuoteError::ZeroFeeAmount(_) => ERR_ZERO_FEE_AMOUNT,
            QuoteError::FeeExceedsMax { .. } => ERR_FEE_EXCEEDS_MAX,
            QuoteError::BadAddress { .. } => ERR_BAD_ADDRESS,
            QuoteError::BadDigest { .. } => ERR_BAD_DIGEST,
            QuoteError::BadAmount { .. } => ERR_BAD_AMOUNT,
            QuoteError::BadV1Signature(_) => ERR_BAD_V1_SIGNATURE,
            QuoteError::BadLinkSignature(_) => ERR_BAD_LINK_SIGNATURE,
            QuoteError::StaleOrMixedNonce => ERR_STALE_OR_MIXED_NONCE,
            QuoteError::ValidityExceedsPolicy => ERR_VALIDITY_EXCEEDS_POLICY,
            QuoteError::ValidityExceedsUint48 => ERR_VALIDITY_EXCEEDS_UINT48,
            QuoteError::DeadlineExceedsUint48 { .. } => ERR_DEADLINE_EXCEEDS_UINT48,
            QuoteError::NonZeroRootAuthorizationDigest => ERR_NON_ZERO_ROOT_AUTHORIZATION_DIGEST,
            QuoteError::UnsupportedFeeMode(_) => ERR_UNSUPPORTED_FEE_MODE,
            QuoteError::ChainTimeUnavailable(_) => ERR_CHAIN_TIME_UNAVAILABLE,
            QuoteError::FeeTokenConfigHashToctouMismatch { .. } => {
                ERR_FEE_TOKEN_CONFIG_HASH_TOCTOU_MISMATCH
            }
            QuoteError::FeeScheduleDecimalsMismatch { .. } => ERR_FEE_SCHEDULE_DECIMALS_MISMATCH,
            QuoteError::IdempotencyKeyConflict => ERR_IDEMPOTENCY_KEY_CONFLICT,
            QuoteError::StoredQuoteExpired => ERR_QUOTE_EXPIRED,
            _ => "INTERNAL",
        }
    }

    /// HTTP status for the shared Stream G error envelope
    /// (`super::http_error`). Wildcard-free on purpose — see
    /// [`super::base_fee::BaseFeeError::status`]; [`Self::code`] above ends in
    /// `_ => "INTERNAL"` and therefore does **not** have that property.
    ///
    /// # The fee schedule is 503, not 500
    ///
    /// [`QuoteError::MissingTariff`] and [`QuoteError::ZeroFeeAmount`] are the
    /// *shipped* state of this build: `fixtures/stream_g_fee_schedule.json`
    /// carries `"tariffs": {}` on purpose (Task 11 Wave 0), so every quote
    /// refuses until an operator publishes real amounts. That is a deployment
    /// that is not open for business yet, not a fault —
    /// [`StatusCode::SERVICE_UNAVAILABLE`] says exactly that and keeps it
    /// distinguishable from a genuine 500.
    ///
    /// # …but a decimals disagreement is 500, and the difference is the point
    ///
    /// [`QuoteError::FeeScheduleDecimalsMismatch`] is **not** 503. "No tariff
    /// published yet" is an absent input; "the published schedule prices this
    /// token in the wrong unit" is a *wrong* input, and the two must not share
    /// a status — 503 invites a retry, and every retry would hit the same
    /// mispriced file. It joins the two other "this process's own fee-schedule
    /// file" arms ([`QuoteError::FeeScheduleIo`],
    /// [`QuoteError::FeeScheduleParse`]) at 500, and matches what the closest
    /// comparable live-vs-configured refusal already returns:
    /// `preflight::PreflightError::EndpointChainMismatch` is 500 for the same
    /// stated reason — "this process is misconfigured … the caller did
    /// nothing". No request field can cause or cure it.
    pub fn status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            QuoteError::Store(_)
            | QuoteError::Crypto(_)
            | QuoteError::Sqlx(_)
            // This process's own fee-schedule file.
            | QuoteError::FeeScheduleIo { .. }
            | QuoteError::FeeScheduleParse { .. }
            | QuoteError::FeeScheduleDecimalsMismatch { .. }
            // This process's own quote signer.
            | QuoteError::InvalidQuoteSignerKey(_)
            | QuoteError::SigningFailed(_)
            // The sealed payload this process wrote failed to open or parse.
            | QuoteError::MalformedPayload(_) => StatusCode::INTERNAL_SERVER_ERROR,

            QuoteError::TokenUnauthorized(e) => e.status(),
            QuoteError::Exposure(e) => e.status(),

            // No tariff published for this action yet — see the doc above.
            QuoteError::MissingTariff(_) | QuoteError::ZeroFeeAmount(_) => {
                StatusCode::SERVICE_UNAVAILABLE
            }

            // Unparseable / unrepresentable caller values.
            QuoteError::BadAddress { .. }
            | QuoteError::BadDigest { .. }
            | QuoteError::BadAmount { .. }
            | QuoteError::ValidityExceedsUint48
            | QuoteError::DeadlineExceedsUint48 { .. } => StatusCode::BAD_REQUEST,

            // Well-formed, refused by a rule (policy, gateway precondition,
            // or a nested bearer signature that does not verify).
            //
            // The two signature arms collapse "malformed hex" and "does not
            // recover to the expected signer" into one 422 on purpose: a
            // status that told a caller *which* of the two happened would be
            // a signature-validity oracle, and no honest client can act on
            // the distinction.
            QuoteError::FeeExceedsMax { .. }
            | QuoteError::BadV1Signature(_)
            | QuoteError::BadLinkSignature(_)
            | QuoteError::ValidityExceedsPolicy
            | QuoteError::NonZeroRootAuthorizationDigest
            | QuoteError::UnsupportedFeeMode(_) => StatusCode::UNPROCESSABLE_ENTITY,

            QuoteError::ChainTimeUnavailable(_) => StatusCode::BAD_GATEWAY,

            // State moved, or a key is spent. Resolvable, but not by
            // resending the same bytes.
            QuoteError::StaleOrMixedNonce
            | QuoteError::FeeTokenConfigHashToctouMismatch { .. }
            | QuoteError::IdempotencyKeyConflict
            | QuoteError::StoredQuoteExpired => StatusCode::CONFLICT,
        }
    }
}

// ---------------------------------------------------------------------------
// USDT tariff schedule (brief §3.1) — loaded from
// `StreamGConfig::fee_schedule_path`.
//
// The shape is no longer this module's own invention. It is the one published
// in the "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring" spec, §8.1:
// an eleven-field `payload` object whose canonical digest IS `feeScheduleHash`.
// The declared hash and the operator note live OUTSIDE that object, because the
// same spec (§5.1 "FeeTokenRegistry") says "Approval metadata is outside the payload" —
// which is also what stops the hash having to reference itself.
//
// The action maps are keyed by the exact on-chain action-type string
// (`ActionType::as_str()`), so a key is independently checkable against
// `StreamGTypes.sol:28-32`.
// ---------------------------------------------------------------------------

/// The `schemaVersion` of the FILE CONTAINER — the `{schemaVersion,
/// feeScheduleHash, note, payload}` envelope this build reads.
///
/// Bumped 1 → 2 when the flat `tariffs` map became the spec's `payload`
/// object. `FeeScheduleFile` is `deny_unknown_fields`, so a v1 file is a hard
/// parse error either way; [`FeeSchedule::load`] checks this field *before*
/// the typed parse so the operator gets `FEE_SCHEDULE_V1_MIGRATION` instead
/// of a bare `unknown field \`tariffs\``.
pub const FEE_SCHEDULE_SCHEMA_VERSION: u64 = 2;

/// The `schemaVersion` INSIDE the payload — the schedule schema published by
/// the spec, and one of the eleven hashed fields.
///
/// Two different versions on purpose, and both are load-bearing: the container
/// version says how this process should read the file, the payload version is
/// part of what governance approved and therefore part of the digest. A payload
/// written against a future schedule schema must not be read under today's
/// rules, so this is pinned rather than echoed.
pub const SCHEDULE_PAYLOAD_SCHEMA_VERSION: &str = "1";

/// What an operator running a v1 file is told. Long on purpose: a shape change
/// behind `deny_unknown_fields` is otherwise indistinguishable from a typo, and
/// the migration is not one an operator can guess (the hash changes meaning).
const FEE_SCHEDULE_V1_MIGRATION: &str = concat!(
    "this is a schemaVersion 1 fee-schedule file, which this build no longer reads. ",
    "What changed: the flat `tariffs` map was replaced by a `payload` object carrying the ",
    "eleven fields the published schedule schema requires (schemaVersion, scheduleVersion, ",
    "chainId, feeToken, decimals, validAfter, validUntil, actionFeesRaw, gasUnitCeilings, ",
    "calldataByteCeilings, maxNativeExposureWei), and `feeScheduleHash` stopped being an ",
    "opaque governance tag: it is now keccak256(UTF8(RFC8785(payload))), a digest of the ",
    "values themselves. To regenerate: set schemaVersion to 2; move each tariff into ",
    "payload.actionFeesRaw, which must carry all four canonical actionType names (use null ",
    "for an action with no approved tariff); fill the remaining payload fields as decimal ",
    "strings with a lowercase 0x feeToken; then set feeScheduleHash to the payload's digest ",
    "and republish that same value on-chain as STREAM_G_FEE_SCHEDULE_HASH. ",
    "See tools/goat-attestor/fixtures/stream_g_fee_schedule.json for a worked file and ",
    "the Stream G USDT Gas Abstraction and Multi-Wallet Sponsoring spec, section 8.1, ",
    "for the rule"
);

/// The shipped placeholder fee schedule, compiled into the binary.
///
/// **Why this exists.** `config::build_stream_g_config` defaults
/// `STREAM_G_FEE_SCHEDULE_PATH` to `{STATE_DIR}/stream_g_fee_schedule.json` and
/// nothing ever shipped a file there, so a fresh clone with
/// `STREAM_G_ENABLED=1` died at startup with `FeeScheduleIo` before Stream G
/// could refuse anything on its merits. `runtime::StreamGState::start` now
/// falls through to these bytes when — and only when — nobody configured the
/// path and no file exists at the default (`config::PathSource::Default`).
///
/// **Zero-config STARTUP is not zero-config QUOTING, and this constant is the
/// clearest place to say so.** Every `actionFeesRaw` entry in this document is
/// `null`, so [`FeeSchedule::fee_for`] answers [`ERR_MISSING_TARIFF`] for all
/// four actions and the quote path refuses. That is not a gap in the fallback:
/// the Season-0 tariffs are a founder decision that has not been taken, and a
/// built-in that invented an amount would sign a price nobody approved into an
/// EIP-712 `FeeQuote` (`models::fee_quote_struct_hash`). The fallback buys a
/// process that *starts and then refuses honestly*; it does not buy a price.
/// `runtime::StreamGState::start` warns in exactly those terms.
///
/// It is the same bytes as `fixtures/stream_g_fee_schedule.json`, the file
/// `tests::shipped_placeholder_fee_schedule_is_published_and_serves_no_price`
/// already pins the canonical bytes and digest of — `include_str!` of that very
/// path, so the two cannot drift. That follows the crate's existing
/// `include_str!` precedent (`store.rs:69`, `store.rs:75`), which likewise
/// embeds a package-local file rather than reaching outside the package.
pub const BUILTIN_FEE_SCHEDULE_JSON: &str =
    include_str!("../../fixtures/stream_g_fee_schedule.json");

/// The file container. `camelCase` matches `token_manifest.rs`'s
/// `DeploymentManifest`, the other operator-authored **file** this crate reads.
/// It is deliberately NOT the Stream G **wire** format, which is snake_case
/// (see [`CreateSponsoredEnrollmentQuoteRequest`] and
/// `tests::request_json_body`) — two different surfaces, two separate
/// decisions.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FeeScheduleFile {
    /// Container version — [`FEE_SCHEDULE_SCHEMA_VERSION`].
    schema_version: u64,
    /// The digest the file **declares** for its own payload, as a
    /// `0x`-prefixed 32-byte hex string. Approval metadata, so it sits outside
    /// `payload` and is not hashed. `runtime::StreamGState::start` recomputes
    /// the digest and refuses to start unless the two agree — see
    /// [`FeeSchedule::load`].
    fee_schedule_hash: String,
    /// Free-text operator note. Optional, and outside `payload` for the same
    /// reason: it is metadata, so editing it must not move the digest. It
    /// exists because `deny_unknown_fields` plus JSON's lack of comments
    /// otherwise leaves an operator-authored file no room to explain itself,
    /// and `runtime::StreamGState::start` echoes it into the startup log —
    /// which is how the shipped placeholder schedule announces itself.
    #[serde(default)]
    note: Option<String>,
    /// The hashed object. Exactly the eleven fields of
    /// [`SchedulePayloadFile`], nothing else.
    payload: SchedulePayloadFile,
}

/// The eleven published fields, verbatim from the spec at `:808`:
/// "a deny-unknown-fields schema containing schemaVersion, scheduleVersion,
/// chainId, feeToken, decimals, validAfter, validUntil, actionFeesRaw,
/// gasUnitCeilings, calldataByteCeilings, and maxNativeExposureWei."
///
/// **Every value is a string, and that is the enforcement, not a style.**
/// `crate::canonical_json` refuses to hash a JSON number at all (RFC 8785
/// §3.2.2.3 mandates ECMAScript `Number::toString`, which `serde_json` does not
/// implement), so a numeric literal here would be unhashable — which is exactly
/// why the spec says "All integers/timestamps are decimal strings". Typing the
/// fields as `String` makes serde reject a number first, with a message that
/// names the field.
///
/// `actionFeesRaw` values are `Option<String>` — `null` means **no tariff is
/// set for this action**. The keys cannot simply be omitted (the spec requires
/// "exactly the four canonical actionType names"), and a zero or any other
/// parseable amount would be a placeholder PRICE, which
/// `models::fee_quote_struct_hash` would sign verbatim into a payer-facing
/// EIP-712 quote where nothing downstream could tell it from a real one. `null`
/// is the one encoding that is unmistakably "not an amount" in every JSON
/// implementation, and `canonical_json` hashes it losslessly.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SchedulePayloadFile {
    schema_version: String,
    schedule_version: String,
    chain_id: String,
    fee_token: String,
    decimals: String,
    valid_after: String,
    valid_until: String,
    action_fees_raw: HashMap<String, Option<String>>,
    gas_unit_ceilings: HashMap<String, String>,
    calldata_byte_ceilings: HashMap<String, String>,
    max_native_exposure_wei: String,
}

/// The four canonical action types, in `StreamGTypes.sol:28-32` order. Every
/// action map in a payload must carry exactly these four names as keys.
const CANONICAL_ACTION_TYPES: [ActionType; 4] = [
    ActionType::SponsoredEnrollment,
    ActionType::SponsoredSell,
    ActionType::GoatTransfer,
    ActionType::UsdtTransfer,
];

/// A canonical decimal string: ASCII digits only, no sign, no whitespace, no
/// leading zero unless the value *is* `"0"`, and in `u128` range.
///
/// Strictness is not pedantry here: `"07"` and `"7"` mean the same number but
/// hash differently, so accepting both would give one approved schedule two
/// legitimate digests. Rust's `str::parse::<u128>` accepts a leading `+` and
/// leading zeros, so it cannot be the rule on its own.
fn canonical_decimal(field: &str, s: &str) -> Result<u128, String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "{field} = {s:?} is not a decimal string; the schedule payload encodes every \
             integer and timestamp as ASCII digits"
        ));
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(format!(
            "{field} = {s:?} has a leading zero; {:?} and {s:?} would hash differently while \
             meaning the same amount, so only the shortest spelling is canonical",
            s.trim_start_matches('0')
        ));
    }
    s.parse::<u128>()
        .map_err(|_| format!("{field} = {s:?} does not fit in a u128"))
}

/// A lowercase `0x` address, per the spec's manifest rule at `:244-246`:
/// "addresses are lowercase 0x plus 40 hex digits".
///
/// Case matters because it is hashed: `0xDDc1…` and `0xddc1…` are the same
/// address and different bytes, so two operators could publish the same
/// schedule under two digests.
///
/// **Returns the decoded 20 bytes, and that return value is load-bearing.**
/// `runtime::StreamGState::start` compares `payload.feeToken` against
/// `token_manifest::DeploymentManifest::fee_token`, which is a `[u8; 20]`
/// decoded from a manifest that writes the SAME address checksummed
/// (`fixtures/31337.stream-g.json` carries `0xDDc10602…`). Comparing the two
/// as strings would therefore report a mismatch for one address spelled two
/// legal ways — the case-sensitivity bug this decode exists to prevent. The
/// spelling rule above still applies to the payload, because the payload's
/// spelling is hashed; the *comparison* is over bytes, which are not.
fn canonical_lowercase_address(field: &str, s: &str) -> Result<[u8; 20], String> {
    let ok = s.len() == 42
        && s.starts_with("0x")
        && s[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !ok {
        return Err(format!(
            "{field} = {s:?} is not a lowercase 0x-prefixed 20-byte address; the canonical \
             payload encoding hashes the address bytes as written, so a checksummed or \
             uppercase spelling would produce a second digest for one schedule"
        ));
    }
    // Infallible given the check above (40 lowercase hex digits), written as a
    // fallible decode rather than an `unwrap` so a future loosening of the
    // predicate cannot turn a bad address into a panic.
    let bytes = hex::decode(&s[2..])
        .map_err(|e| format!("{field} = {s:?} is not hex after the 0x prefix: {e}"))?;
    let mut out = [0u8; 20];
    if bytes.len() != out.len() {
        return Err(format!(
            "{field} = {s:?} decoded to {} bytes, not 20",
            bytes.len()
        ));
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Exactly the four canonical action names — no more, no fewer.
///
/// The "no more" half is the one that changed behaviour: under the v1 flat
/// `tariffs` map an unrecognised key was silently dropped, which turned a typo
/// into a late `MISSING_TARIFF`. A dropped key still changes the digest, so
/// under a value digest that same typo would become an unexplained startup
/// refusal — the operator would be told the schedule does not match the
/// deployment, with nothing pointing at the misspelling. Naming it here is the
/// only message that leads anywhere.
fn require_exact_action_map<T>(field: &str, map: &HashMap<String, T>) -> Result<(), String> {
    let mut missing: Vec<&str> = Vec::new();
    for action in CANONICAL_ACTION_TYPES {
        if !map.contains_key(action.as_str()) {
            missing.push(action.as_str());
        }
    }
    let mut unrecognised: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|k| !CANONICAL_ACTION_TYPES.iter().any(|a| a.as_str() == *k))
        .collect();
    unrecognised.sort_unstable();

    if missing.is_empty() && unrecognised.is_empty() {
        return Ok(());
    }
    let canonical: Vec<&str> = CANONICAL_ACTION_TYPES.iter().map(|a| a.as_str()).collect();
    Err(format!(
        "{field} must contain exactly the four canonical actionType names {canonical:?}; \
         missing {missing:?}, unrecognised {unrecognised:?}"
    ))
}

/// Fixed USDT-tariff table, keyed by [`ActionType`]. See module doc — this
/// is the ONLY source `fee_amount` ever comes from; nothing here scales
/// with gas price, oracle values, or the native-exposure reserve.
///
/// `Debug` carries no secret (a public tariff table) and is what lets
/// `Result<FeeSchedule, QuoteError>::unwrap_err()` be used in the M5 `load`
/// tests.
#[derive(Debug)]
pub struct FeeSchedule {
    tariffs: HashMap<&'static str, u128>,
    /// The digest the FILE declared — see
    /// [`FeeSchedule::declared_fee_schedule_hash`].
    declared_fee_schedule_hash: [u8; 32],
    /// The digest of the payload actually loaded — see
    /// [`FeeSchedule::computed_fee_schedule_hash`].
    computed_fee_schedule_hash: [u8; 32],
    /// `payload.chainId` — see [`FeeSchedule::payload_chain_id`].
    payload_chain_id: u128,
    /// `payload.feeToken`, decoded — see [`FeeSchedule::payload_fee_token`].
    payload_fee_token: [u8; 20],
    /// `payload.decimals` — see [`FeeSchedule::payload_decimals`].
    payload_decimals: u128,
    /// The file's operator note, echoed at startup. See [`FeeSchedule::note`].
    note: Option<String>,
}

impl FeeSchedule {
    /// Loads
    /// `{"schemaVersion": 2, "feeScheduleHash": "0x…", "note": "…",
    ///   "payload": {…eleven fields…}}`
    /// from `path` (`StreamGConfig::fee_schedule_path`).
    ///
    /// # `feeScheduleHash` is a digest of the payload's VALUES
    ///
    /// This is the reverse of what this doc used to say, and the reversal is
    /// the point. The previous version stated that the hash was a declared
    /// governance tag which "does not bind the tariff values", and that
    /// "content binding needs a canonicalisation rule that governance
    /// publishes; none exists". **The rule does exist**, published verbatim at
    /// the "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring" spec,
    /// §8.1 "Quote construction":
    ///
    /// > "The schedule payload uses the same RFC 8785/UTF-8 rules as the
    /// > deployment manifest and a deny-unknown-fields schema containing
    /// > schemaVersion, scheduleVersion, chainId, feeToken, decimals,
    /// > validAfter, validUntil, actionFeesRaw, gasUnitCeilings,
    /// > calldataByteCeilings, and maxNativeExposureWei. All
    /// > integers/timestamps are decimal strings; action maps contain exactly
    /// > the four canonical actionType names.
    /// > feeScheduleHash = keccak256(UTF8(RFC8785(schedulePayload)))."
    ///
    /// So the parser computes `keccak256(UTF8(RFC8785(payload)))` with
    /// [`crate::canonical_hash`] and keeps it alongside the hash the file
    /// declares. Editing any amount now changes the digest.
    ///
    /// # ⚠️ Where the parsing and the checking actually live
    ///
    /// **Corrected 2026-07-27.** This doc block used to describe every rule
    /// below as something `load` does, and to say that `start` "always goes
    /// through `FeeSchedule::load`". Neither is true, and the difference is not
    /// pedantic — a maintainer adding a startup check would have edited a
    /// function no production code calls:
    ///
    /// - `load` is a four-line wrapper: it reads `path` and delegates
    ///   everything else to [`FeeSchedule::from_json`]. Every validation rule
    ///   listed below is enforced by `from_json`.
    /// - `runtime::StreamGState::start` does **not** call `load`. It resolves
    ///   the document through `runtime::read_startup_document` (which may
    ///   answer with the built-in copy rather than a file, so there is no path
    ///   to hand `load`) and then calls `from_json` on the bytes.
    /// - `load` therefore has **zero** production call sites; the only callers
    ///   are `#[cfg(test)]`. It is kept because the tests below exercise the
    ///   real filesystem arm, and because a future non-startup consumer with a
    ///   genuine path is the case it exists for.
    ///
    /// The rules are documented here, on the public entry point a reader is
    /// most likely to land on, and `from_json`'s own doc points back at this
    /// block rather than restating it.
    ///
    /// # What the loader checks, and what `start` checks
    ///
    /// Neither `load` nor `from_json` compares the two hashes: they see only
    /// one document, and a schedule that fails the comparison is a *deployment*
    /// condition, not a parse error. `runtime::StreamGState::start` does both
    /// comparisons — see the `FeeScheduleHashSelfMismatch` and
    /// `FeeScheduleHashMismatch` returns in that function, immediately after
    /// its `FeeSchedule::from_json` call — and distinguishes them:
    ///
    /// - computed ≠ declared ⇒ `StreamGStartupError::FeeScheduleHashSelfMismatch`
    ///   — the payload was edited without republishing the hash;
    /// - computed ≠ manifest ⇒ `StreamGStartupError::FeeScheduleHashMismatch`
    ///   — this deployment did not publish this schedule.
    ///
    /// Pinned by `runtime::tests::start_refuses_a_fee_schedule_whose_payload_does_not_match_its_declared_hash`
    /// and `runtime::tests::start_refuses_a_fee_schedule_this_deployment_did_not_publish`.
    ///
    /// [`FeeSchedule::from_json`] itself refuses, with a message naming the
    /// field:
    /// - a container `schemaVersion` other than [`FEE_SCHEDULE_SCHEMA_VERSION`]
    ///   — a v1 file gets `FEE_SCHEDULE_V1_MIGRATION`, not a serde error;
    /// - a payload `schemaVersion` other than
    ///   [`SCHEDULE_PAYLOAD_SCHEMA_VERSION`];
    /// - any unknown field, at either level (`deny_unknown_fields`);
    /// - any action map that is not exactly the four canonical names
    ///   (`require_exact_action_map`) — under v1 an unrecognised key was
    ///   silently dropped;
    /// - any integer that is not a canonical decimal string, or a `feeToken`
    ///   that is not lowercase (`canonical_decimal`,
    ///   `canonical_lowercase_address`) — both are hash-affecting spellings;
    /// - an inverted validity window (`validAfter` > `validUntil`). Note that
    ///   `0`..`0` is accepted: that is the shipped placeholder's fail-closed
    ///   window, and nothing in this build enforces the window anyway.
    ///
    /// # Deployment agreement: `chainId` and `feeToken` are compared, by value
    ///
    /// This section used to claim that `chainId` and `feeToken` "still bind"
    /// because "a payload for another chain cannot match a manifest that
    /// published this one's digest". **That was false, and an auditor
    /// demonstrated it by running the binary**: a payload declaring
    /// `chainId "8453"`, an unrelated `feeToken` and `decimals "18"`, whose
    /// digest was written into *both* the schedule file and the deployment
    /// manifest, started cleanly on `CHAIN_ID=31337` and served prices. The
    /// digest binds a payload to ITSELF and to whatever the operator
    /// republished; it says nothing about the deployment the payload was
    /// authored for. Re-publishing a foreign schedule is one `forge script`
    /// away, and the harm is arithmetic: an 18-decimal `1000000000000000000`
    /// served against a 6-decimal fee token is 1e12 USDT, charged from the
    /// MANIFEST's `feeToken` because that is the address
    /// `models::fee_quote_struct_hash` signs.
    ///
    /// So the two fields the manifest also knows are now compared *by value*,
    /// in `runtime::StreamGState::start`, immediately after the two digest
    /// comparisons above and before anything mounts:
    ///
    /// - `payload.chainId` ≠ `manifest.chainId` ⇒
    ///   `StreamGStartupError::FeeScheduleChainMismatch`. (`manifest.chainId`
    ///   has itself already been proven equal to the configured `CHAIN_ID` by
    ///   `token_manifest::parse_deployment_manifest`, so this transitively
    ///   pins the payload to the chain this process is configured for.)
    /// - `payload.feeToken` ≠ `manifest.feeToken` ⇒
    ///   `StreamGStartupError::FeeScheduleFeeTokenMismatch`. Compared as
    ///   decoded bytes, not as text: the payload spells the address lowercase
    ///   (hashed that way) while the manifest spells it checksummed, and both
    ///   are the same address — see `canonical_lowercase_address`.
    ///
    /// Each is its own variant, distinct from
    /// `FeeScheduleHashSelfMismatch`/`FeeScheduleHashMismatch`, so an operator
    /// reads "wrong chain" / "wrong token" / "wrong digest" off the message
    /// without opening source.
    ///
    /// Pinned by
    /// `runtime::tests::start_refuses_a_fee_schedule_authored_for_another_chain`
    /// (the auditor's exact payload) and
    /// `runtime::tests::start_refuses_a_fee_schedule_naming_another_fee_token`;
    /// both carry a paired positive arm, and
    /// `runtime::tests::start_accepts_a_schedule_that_agrees_with_the_deployment`
    /// pins that the agreeing payload still starts, so neither check can
    /// degrade into a blanket refusal. The values this compares are exposed by
    /// [`FeeSchedule::payload_chain_id`] and [`FeeSchedule::payload_fee_token`],
    /// pinned by `tests::load_exposes_the_payload_fields_start_compares`.
    ///
    /// # What is still NOT covered, stated plainly
    /// - The `note` and the declared hash are outside the payload, so editing
    ///   them does not move the digest. That follows from the spec's rule at
    ///   the "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring"
    ///   spec, §8.1, which
    ///   fixes the schedule payload's field list at exactly eleven names
    ///   (neither `note` nor `feeScheduleHash` among them) and says the payload
    ///   "uses the same RFC 8785/UTF-8 rules as the deployment manifest" —
    ///   whose own passage, `:244`, is where the sentence "Approval metadata is
    ///   outside the payload" is literally written. (Corrected 2026-07-27: this
    ///   bullet used to cite `:244-246` alone for a rule about the *schedule*
    ///   payload; `:244-246` is the *deployment manifest* section, so `:808` is
    ///   the citation that governs here and `:244` is the inherited one.) It is
    ///   what lets the digest be free of self-reference, but it does mean the
    ///   note carries no authority.
    /// - It is **not** a signature. Nothing here proves *who* wrote the file;
    ///   the on-chain `feeScheduleHash` is what proves *which* payload the
    ///   deployment approved.
    /// - **`payload.decimals` is not compared at startup, and now IS compared
    ///   on the quote path.** (Rewritten 2026-07-27, for the second time. The
    ///   previous wording said a disagreeing `decimals` "is a claim about
    ///   *that* token, contradicted by the registry rather than by the file",
    ///   which a reader takes to mean "caught later". It was not caught later:
    ///   at the time it was written **nothing in the build compared the two
    ///   numbers at any point** in the quote, preflight or submit path, and an
    ///   auditor demonstrated that by running the binary. It is quoted rather
    ///   than deleted so the correction stays auditable.)
    ///
    ///   *Which comparison runs:* `payload.decimals` against
    ///   `token_manifest::TokenCapability::decimals` — i.e.
    ///   `FeeTokenConfig.decimals` as `FeeTokenRegistry.getTokenConfig`
    ///   reports it, bound to `getTokenConfigHash` at a pinned block. The
    ///   registry's `u8` is widened to `u128`; the payload's `u128` is never
    ///   narrowed.
    ///
    ///   *Where it runs:* the **quote path**, never startup —
    ///   [`assert_schedule_decimals_match_live_token`], called from
    ///   [`post_quote`] (immediately after the endpoint-chain-id agreement
    ///   check, before the nonce read) and again from
    ///   [`create_sponsored_enrollment_quote_at`] at STEP 0, next to the token
    ///   gate and before STEP 3 computes any fee amount.
    ///
    ///   *Why it cannot run at startup:* the only non-test producer of
    ///   `TokenCapability` is `token_manifest::read_live_token_state`, a live
    ///   chain read. Neither `token_manifest::DeploymentManifest` nor
    ///   `config::StreamGConfig` carries a `decimals` field, and
    ///   `runtime::StreamGState::start` performs no chain reads at all — it
    ///   builds the `RpcChain` only *after* every schedule check, and under
    ///   `GOAT_ATTESTOR_MOCK=1` it builds none. A startup comparison would
    ///   have to invent its own right-hand side.
    ///
    ///   *What an operator sees:* the process still starts — the file is
    ///   well-formed and its digest still agrees with the manifest — and every
    ///   quote is then refused with HTTP **500** and the body
    ///   `{"error":"FEE_SCHEDULE_DECIMALS_MISMATCH"}`. The `tracing` line
    ///   carries both numbers ("fee schedule declares payload.decimals 18 but
    ///   the fee-token registry reports 6 …"); the response body never does,
    ///   per `http_error`'s envelope rule. 500 rather than the 503 the
    ///   tariff-absence arms use, because a wrong price unit is a wrong input,
    ///   not an absent one — see [`QuoteError::status`].
    ///
    ///   *The pin:*
    ///   `tests::a_schedule_decimals_claim_the_live_token_contradicts_is_refused_before_any_fee_is_used`,
    ///   with `tests::a_schedule_whose_decimals_agree_with_the_live_token_still_quotes`
    ///   as the paired positive arm so this cannot degrade into a blanket
    ///   refusal.
    /// - The validity window and the three ceiling maps are validated and
    ///   hashed but enforced nowhere.
    pub fn load(path: &Path) -> Result<Self, QuoteError> {
        let raw = fs::read_to_string(path).map_err(|e| QuoteError::FeeScheduleIo {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        Self::from_json(&raw, &path.display().to_string())
    }

    /// The parse/validate half of [`FeeSchedule::load`], split out so the
    /// built-in [`BUILTIN_FEE_SCHEDULE_JSON`] is read by exactly the same code
    /// a file is — same version gates, same canonical-decimal rules, same
    /// digest. A fallback with its own parser would be a second, weaker loader.
    ///
    /// **This — not `load` — is what `runtime::StreamGState::start` calls**, and
    /// it is where every validation rule and the digest computation actually
    /// live. They are documented once, in [`FeeSchedule::load`]'s doc block
    /// (the entry point a reader lands on first); read that block rather than
    /// looking for a second copy here.
    ///
    /// `source` is only ever a label for error messages: a path for a real
    /// file, a `<built-in ...>` string for the embedded document. Nothing here
    /// opens it.
    pub fn from_json(raw: &str, source: &str) -> Result<Self, QuoteError> {
        let parse_err = |detail: String| QuoteError::FeeScheduleParse {
            path: source.to_string(),
            detail,
        };

        // Parsed as a `Value` first for two reasons: the container version has
        // to be read BEFORE `deny_unknown_fields` turns a v1 file into an
        // unactionable `unknown field \`tariffs\``, and the digest must be taken
        // over the payload exactly as written rather than over a re-serialised
        // Rust struct.
        let doc: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| parse_err(e.to_string()))?;

        // Peeked from the untyped document ONLY to give a v1 file the migration
        // text: `deny_unknown_fields` would otherwise answer
        // `unknown field \`tariffs\``, which names neither the shape change nor
        // the fact that `feeScheduleHash` changed meaning. The authoritative
        // version check is on the typed field below, so deleting this arm can
        // only degrade the message, never the refusal.
        if doc.get("schemaVersion").and_then(serde_json::Value::as_u64) == Some(1) {
            return Err(parse_err(FEE_SCHEDULE_V1_MIGRATION.to_string()));
        }

        // Canonicalised BEFORE the typed parse, because it is the better error
        // reporter for a wrong value *type*: `CanonicalJsonError` carries a
        // JSONPath breadcrumb (`$.decimals`, `$.gasUnitCeilings.bind`) whereas
        // `serde_json::from_value` reports only "invalid type: integer `6`,
        // expected a string" with no field name — `from_value` has no input
        // position to quote. It is also the right order in principle: a payload
        // that cannot be canonicalised has no digest, so it could not be
        // published whatever else is true of it.
        //
        // `None` only when `payload` is absent, which the typed parse below
        // reports as the missing field it is.
        let computed = match doc.get("payload") {
            Some(payload_value) => Some(crate::canonical_hash(payload_value).map_err(|e| {
                parse_err(format!(
                    "payload cannot be canonicalised, so no feeScheduleHash can be computed \
                     for it: {e}"
                ))
            })?),
            None => None,
        };

        let file: FeeScheduleFile =
            serde_json::from_value(doc.clone()).map_err(|e| parse_err(e.to_string()))?;
        let computed_fee_schedule_hash = computed.ok_or_else(|| {
            parse_err("payload is absent after a successful typed parse".to_string())
        })?;

        if file.schema_version != FEE_SCHEDULE_SCHEMA_VERSION {
            return Err(parse_err(format!(
                "unsupported schemaVersion {} (this build reads {FEE_SCHEDULE_SCHEMA_VERSION})",
                file.schema_version
            )));
        }
        let p = &file.payload;

        if p.schema_version != SCHEDULE_PAYLOAD_SCHEMA_VERSION {
            return Err(parse_err(format!(
                "payload.schemaVersion {:?} is not the schedule schema this build reads \
                 ({SCHEDULE_PAYLOAD_SCHEMA_VERSION:?})",
                p.schema_version
            )));
        }

        canonical_decimal("payload.scheduleVersion", &p.schedule_version).map_err(parse_err)?;
        let payload_chain_id = canonical_decimal("payload.chainId", &p.chain_id)
            .map_err(parse_err)?;
        let payload_decimals = canonical_decimal("payload.decimals", &p.decimals)
            .map_err(parse_err)?;
        canonical_decimal("payload.maxNativeExposureWei", &p.max_native_exposure_wei)
            .map_err(parse_err)?;
        let payload_fee_token =
            canonical_lowercase_address("payload.feeToken", &p.fee_token).map_err(parse_err)?;

        let valid_after = canonical_decimal("payload.validAfter", &p.valid_after)
            .map_err(parse_err)?;
        let valid_until = canonical_decimal("payload.validUntil", &p.valid_until)
            .map_err(parse_err)?;
        if valid_after > valid_until {
            return Err(parse_err(format!(
                "payload.validAfter {valid_after} is after payload.validUntil {valid_until}: \
                 the schedule's validity window is inverted. (Note that nothing in this build \
                 enforces the window yet — this only rejects a window no operator can have meant.)"
            )));
        }

        require_exact_action_map("payload.actionFeesRaw", &p.action_fees_raw)
            .map_err(parse_err)?;
        require_exact_action_map("payload.gasUnitCeilings", &p.gas_unit_ceilings)
            .map_err(parse_err)?;
        require_exact_action_map("payload.calldataByteCeilings", &p.calldata_byte_ceilings)
            .map_err(parse_err)?;

        let mut tariffs = HashMap::with_capacity(CANONICAL_ACTION_TYPES.len());
        for action in CANONICAL_ACTION_TYPES {
            let key = action.as_str();
            // `require_exact_action_map` above proves every key is present, so
            // these lookups cannot be `None`; they are still written as lookups
            // rather than indexing so a future edit cannot turn a missing key
            // into a panic.
            for (field, map) in [
                ("payload.gasUnitCeilings", &p.gas_unit_ceilings),
                ("payload.calldataByteCeilings", &p.calldata_byte_ceilings),
            ] {
                if let Some(value) = map.get(key) {
                    canonical_decimal(&format!("{field}[{key}]"), value).map_err(parse_err)?;
                }
            }
            // `None` (JSON `null`) means "no tariff set for this action" and is
            // NOT an error: it is how a schedule ships with the four required
            // keys present and no price. `fee_for` then answers
            // `MISSING_TARIFF` and the quote path refuses.
            if let Some(Some(raw_amount)) = p.action_fees_raw.get(key) {
                let amount = canonical_decimal(&format!("payload.actionFeesRaw[{key}]"), raw_amount)
                    .map_err(parse_err)?;
                tariffs.insert(key, amount);
            }
        }

        let declared_fee_schedule_hash = parse_bytes32("feeScheduleHash", &file.fee_schedule_hash)
            .map_err(|_| {
                parse_err(format!(
                    "feeScheduleHash {:?} is not a 32-byte hex string",
                    file.fee_schedule_hash
                ))
            })?;

        Ok(Self {
            tariffs,
            declared_fee_schedule_hash,
            computed_fee_schedule_hash,
            payload_chain_id,
            payload_fee_token,
            payload_decimals,
            note: file.note,
        })
    }

    /// The fixed USDT amount for `action`, or [`QuoteError::MissingTariff`]
    /// if the loaded schedule has no entry for it.
    pub fn fee_for(&self, action: ActionType) -> Result<u128, QuoteError> {
        self.tariffs
            .get(action.as_str())
            .copied()
            .ok_or(QuoteError::MissingTariff(action.as_str()))
    }

    /// Whether **any** of the four canonical actions has a tariff.
    ///
    /// `load` only inserts a key when `payload.actionFeesRaw[key]` is a
    /// non-null amount, so an empty table means every action answers
    /// [`QuoteError::MissingTariff`]. `runtime::StreamGState::start` calls this
    /// to say, in the startup log, whether the schedule it loaded can serve a
    /// price — measured from the loaded schedule rather than assumed from
    /// which source supplied it, so the line stays true if the shipped
    /// placeholder is ever given real numbers.
    pub fn has_any_tariff(&self) -> bool {
        !self.tariffs.is_empty()
    }

    /// The digest the file **declared** for its own payload.
    ///
    /// An operator's claim, nothing more. It is only trustworthy once
    /// `runtime::StreamGState::start` has checked it against
    /// [`FeeSchedule::computed_fee_schedule_hash`] — see [`FeeSchedule::load`].
    pub fn declared_fee_schedule_hash(&self) -> [u8; 32] {
        self.declared_fee_schedule_hash
    }

    /// `keccak256(UTF8(RFC8785(payload)))` over the payload actually loaded —
    /// the rule in the "Stream G — USDT Gas Abstraction and Multi-Wallet
    /// Sponsoring" spec, §8.1.
    ///
    /// This is the value that must equal both the file's declaration and the
    /// deployment manifest's `feeScheduleHash`; `runtime::StreamGState::start`
    /// enforces both and refuses to mount the quote route otherwise.
    pub fn computed_fee_schedule_hash(&self) -> [u8; 32] {
        self.computed_fee_schedule_hash
    }

    /// `payload.chainId`, as the number it parsed to.
    ///
    /// `u128` because that is what [`canonical_decimal`] answers and the field
    /// is a `uint256` on the wire; the manifest's `chain_id` is a `u64`, so the
    /// comparison in `runtime::StreamGState::start` widens the manifest side
    /// rather than narrowing this one — a payload declaring a chain id past
    /// `u64::MAX` must fail that comparison, not wrap into agreement with it.
    pub fn payload_chain_id(&self) -> u128 {
        self.payload_chain_id
    }

    /// `payload.feeToken`, decoded to the 20 address bytes.
    ///
    /// Bytes rather than the source text so it can be compared against
    /// `token_manifest::DeploymentManifest::fee_token` without either side's
    /// spelling mattering — see `canonical_lowercase_address`.
    pub fn payload_fee_token(&self) -> [u8; 20] {
        self.payload_fee_token
    }

    /// `payload.decimals`, as the number it parsed to.
    ///
    /// **This is compared — on the quote path, not at startup.**
    /// [`assert_schedule_decimals_match_live_token`] is the only reader, and
    /// it holds this against `token_manifest::TokenCapability::decimals` from
    /// the live registry reading. It stays a `u128` (what [`canonical_decimal`]
    /// answers) rather than being narrowed to the registry's `u8` at parse
    /// time, so a payload declaring a `decimals` past `u8::MAX` fails that
    /// comparison instead of wrapping into agreement with it.
    ///
    /// The startup path still cannot compare it: this deployment's decimals
    /// are only knowable from `FeeTokenRegistry.getTokenConfig`
    /// (`token_manifest::read_live_token_state`), and `StreamGState::start` is
    /// chain-free. See [`FeeSchedule::load`]'s "What is still NOT covered".
    pub fn payload_decimals(&self) -> u128 {
        self.payload_decimals
    }

    /// The file's free-text `note`, if it carried one.
    ///
    /// `runtime::StreamGState::start` logs this, which is how the shipped
    /// placeholder schedule tells an operator, at startup, that no tariff is
    /// set. It is operator-authored text and carries no authority: nothing
    /// branches on it.
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    /// Test-only convenience constructor. Both hashes are all-zero, which is
    /// the value `GoatRelayGateway.sol:184` rejects, so a `for_test` schedule
    /// can never accidentally satisfy the startup binding.
    #[cfg(test)]
    pub fn for_test(pairs: &[(ActionType, u128)]) -> Self {
        Self::for_test_with_hash(pairs, [0u8; 32])
    }

    /// [`FeeSchedule::for_test`] with an explicit hash.
    ///
    /// Sets the declared and the computed digest to the *same* value, which is
    /// sound only because these fixtures never reach the startup comparison:
    /// `runtime::StreamGState::start` builds its schedule by parsing a
    /// document ([`FeeSchedule::from_json`], via
    /// `runtime::read_startup_document`) and has no way to be handed a
    /// pre-built `FeeSchedule`, so every test of that comparison writes a real
    /// file. A fixture that could fake agreement between the two would make
    /// those tests vacuous, so this constructor is not used there.
    ///
    /// (Corrected 2026-07-27: this used to say `start` "always goes through
    /// [`FeeSchedule::load`]". It never does — `load` has zero production call
    /// sites. The conclusion survives, because what makes these fixtures
    /// harmless is that `start` parses a document rather than accepting a
    /// constructed value, not which of the two parser entry points it uses.)
    ///
    /// The same reasoning covers `payload_chain_id`/`payload_fee_token`, which
    /// are set to the 31337 lab deployment's values (the pair
    /// `fixtures/stream_g_fee_schedule.json` and `fixtures/31337.stream-g.json`
    /// agree on): they exist so the struct is constructible, not so a test can
    /// pass the startup agreement checks without a file.
    #[cfg(test)]
    pub fn for_test_with_hash(
        pairs: &[(ActionType, u128)],
        fee_schedule_hash: [u8; 32],
    ) -> Self {
        let mut tariffs = HashMap::new();
        for (action, amount) in pairs {
            tariffs.insert(action.as_str(), *amount);
        }
        let payload_fee_token = canonical_lowercase_address(
            "payload.feeToken",
            "0xddc10602782af652bb913f7bde1fd82981db7dd9",
        )
        .expect("the 31337 lab fee token is a canonical lowercase address");
        Self {
            tariffs,
            declared_fee_schedule_hash: fee_schedule_hash,
            computed_fee_schedule_hash: fee_schedule_hash,
            payload_chain_id: 31337,
            payload_fee_token,
            payload_decimals: 6,
            note: None,
        }
    }
}

/// The schedule payload's `decimals` claim, held against the only value that
/// can contradict it: `FeeTokenConfig.decimals` as the fee-token registry
/// reports it at a pinned block.
///
/// # What this closes
///
/// [`FeeSchedule::load`]'s deployment-agreement checks (run in
/// `runtime::StreamGState::start`) pin a payload to this deployment's `chainId`
/// and `feeToken`. They do not pin its `decimals`, and an auditor ran the
/// binary to prove the remaining hole is reachable rather than theoretical: a
/// payload naming **this** chain (`"31337"`) and **this** fee token
/// (`0xddc10602782af652bb913f7bde1fd82981db7dd9`), with `decimals "18"` and a
/// tariff of `1000000` on all four actions, its digest republished into both
/// the schedule file and the manifest, started cleanly and logged
/// `fee_schedule_has_tariff=true`. Nothing warned, and nothing downstream
/// disagreed. The harm is arithmetic and it is signed: `fee_amount` is served
/// verbatim into `models::fee_quote_struct_hash` against
/// `manifest.fee_token`, so an amount authored in 18-decimal units and
/// collected by a 6-decimal token is off by 10^12.
///
/// # Why the comparison lives on the quote path and cannot live at startup
///
/// This deployment's decimals exist in exactly one place —
/// `token_manifest::TokenCapability::decimals`, whose only non-test producer
/// is `token_manifest::read_live_token_state` (a `getTokenConfig` read bound
/// to `getTokenConfigHash` at a pinned block). Neither
/// `token_manifest::DeploymentManifest` nor `config::StreamGConfig` carries a
/// `decimals` field, and `runtime::StreamGState::start` performs no chain
/// reads at all — under `GOAT_ATTESTOR_MOCK=1` it does not even construct a
/// client (the `RpcChain` is built *after* every schedule check, see
/// `runtime.rs`'s `StreamGState::start`). A startup comparison would have to
/// invent its own right-hand side. The quote path is the first point where the
/// right-hand side genuinely exists, so this is where it is compared.
///
/// # Widening direction
///
/// The registry's `u8` is widened to `u128`; the payload's `u128` is never
/// narrowed. Same rule, and the same reason, as
/// [`FeeSchedule::payload_chain_id`]: a payload declaring a `decimals` past
/// `u8::MAX` must **fail** this comparison, not wrap into agreement with it.
///
/// # Called twice, deliberately
///
/// [`post_quote`] calls it while assembling the chain context — in the same
/// position, and for the same reason, as the endpoint-chain-id agreement check
/// directly above it: a hand-assembled [`EnrollmentQuoteContext`] skips any
/// check its assembler does not make, and refusing there costs the process one
/// fewer chain read (`LiveEnrollmentNonces::read_live`) and no store writes.
/// [`create_sponsored_enrollment_quote_at`] calls it again at STEP 0, next to
/// the token gate, because the library must not trust a check performed by its
/// caller — the same rule this module already applies to the root/secondary
/// address parse, which is likewise done in both places on purpose. The
/// second call is also the one tests can reach: `post_quote` refuses with
/// `NO_LIVE_CHAIN` before anything else under mock mode, and
/// `StreamGState`'s chain is a real `RpcChain` or nothing, so there is no
/// layer at or above the handler that can exercise this comparison.
///
/// Between them the two call sites cover the whole production surface, which
/// is checkable rather than asserted: [`FeeSchedule::fee_for`] has exactly one
/// non-test caller (STEP 3 of [`create_sponsored_enrollment_quote_at`]) and
/// `runtime::StreamGState::fee_schedule` exactly one ([`post_quote`]). No
/// other code path can turn a tariff into a signed amount.
///
/// Pinned by
/// `tests::a_schedule_decimals_claim_the_live_token_contradicts_is_refused_before_any_fee_is_used`,
/// its paired positive arm
/// `tests::a_schedule_whose_decimals_agree_with_the_live_token_still_quotes`,
/// and `tests::a_decimals_claim_past_u8_max_cannot_wrap_into_agreement` for
/// the widening rule.
fn assert_schedule_decimals_match_live_token(
    fee_schedule: &FeeSchedule,
    live_token: &token_manifest::LiveTokenReading,
) -> Result<(), QuoteError> {
    let live_decimals = live_token.capability().decimals;
    if fee_schedule.payload_decimals() != u128::from(live_decimals) {
        return Err(QuoteError::FeeScheduleDecimalsMismatch {
            payload_decimals: fee_schedule.payload_decimals(),
            live_decimals,
        });
    }
    Ok(())
}

/// The canonical bytes whose keccak256 **is** `feeScheduleHash`, extracted from
/// a fee-schedule file's `payload`.
///
/// # Why this is public and separate from [`FeeSchedule::from_json`]
///
/// `from_json` computes the digest and throws the bytes away, because a running
/// process only ever needs the 32 bytes. The **ops leg** of the three-way
/// fixture the spec requires — the "Stream G — USDT Gas Abstraction and
/// Multi-Wallet Sponsoring" spec, §8.1,
/// "Rust/JavaScript/ops fixtures pin the canonical bytes and hash before Policy
/// Safe approval" — needs the bytes themselves, so a founder computing the value
/// to publish as `STREAM_G_FEE_SCHEDULE_HASH` can see *what was hashed* and not
/// merely the result. `main.rs`'s `fee-schedule-hash` subcommand is that leg and
/// this function is what it calls.
///
/// It is a thin extractor on purpose: the canonicalisation is
/// [`crate::canonical_bytes`], the same function `from_json` hashes with, so
/// there is exactly one canonicaliser in this crate and the CLI cannot drift
/// from the loader. Pinned by
/// [`tests::canonical_schedule_payload_bytes_are_the_bytes_the_loader_hashes`].
///
/// `source` is only ever a label for error messages, matching
/// [`FeeSchedule::from_json`]'s parameter of the same name; nothing here opens
/// it.
pub fn canonical_schedule_payload_bytes(raw: &str, source: &str) -> Result<Vec<u8>, QuoteError> {
    let parse_err = |detail: String| QuoteError::FeeScheduleParse {
        path: source.to_string(),
        detail,
    };
    let doc: serde_json::Value = serde_json::from_str(raw).map_err(|e| parse_err(e.to_string()))?;
    let payload = doc.get("payload").ok_or_else(|| {
        parse_err(
            "the file has no `payload` object, so there is nothing to canonicalise; a \
             fee-schedule file is {schemaVersion, feeScheduleHash, note, payload}"
                .to_string(),
        )
    })?;
    crate::canonical_bytes(payload).map_err(|e| {
        parse_err(format!(
            "payload cannot be canonicalised, so no feeScheduleHash can be computed for it: {e}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Small self-contained helpers (this crate's stream_g modules are each
// self-contained by convention — see e.g. root_authorization.rs's module
// doc — rather than sharing private helpers cross-file).
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

fn quote_id_bytes(profile_id: &str, idempotency_key: &str) -> [u8; 32] {
    let digest =
        Sha256::digest(format!("stream_g_quote|v1|{profile_id}|{idempotency_key}").as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// `field` is a `&'static str` naming the DTO field, never anything derived
/// from `s` — see [`QuoteError::BadAddress`] for why the input itself is not
/// carried. The reported length is of the caller's **untrimmed** input, which
/// is what a client would have to change to fix the request.
fn parse_address20(field: &'static str, s: &str) -> Result<[u8; 20], QuoteError> {
    let bad = || QuoteError::BadAddress {
        field,
        len: s.len(),
    };
    let trimmed = s.trim();
    let h = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if h.len() != 40 {
        return Err(bad());
    }
    let bytes = hex::decode(h).map_err(|_| bad())?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// See [`parse_address20`] for the `field` convention.
fn parse_bytes32(field: &'static str, s: &str) -> Result<[u8; 32], QuoteError> {
    let bad = || QuoteError::BadDigest {
        field,
        len: s.len(),
    };
    let trimmed = s.trim();
    let h = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if h.len() != 64 {
        return Err(bad());
    }
    let bytes = hex::decode(h).map_err(|_| bad())?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// See [`parse_address20`] for the `field` convention.
fn parse_u128_decimal(field: &'static str, s: &str) -> Result<u128, QuoteError> {
    s.trim().parse::<u128>().map_err(|_| QuoteError::BadAmount {
        field,
        len: s.len(),
    })
}

fn address_hex(a: [u8; 20]) -> String {
    format!("0x{}", hex::encode(a))
}

fn bytes32_hex(b: [u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Generic ECDSA recover-and-compare — `sig_verify.rs` has the same logic
/// but keeps it private, and its two public wrappers
/// (`verify_bind_sig`/`verify_enroll_sig`) are struct-specific, so
/// [`LinkSecondary`] (which has no `sig_verify.rs` counterpart) needs its
/// own copy. Self-contained per this crate's stream_g convention.
fn recover_and_check(
    digest: [u8; 32],
    signature_hex: &str,
    expected: [u8; 20],
) -> Result<(), String> {
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
    let prehash = B256::from_slice(&digest);
    let recovered = sig
        .recover_address_from_prehash(&prehash)
        .map_err(|_| "ecrecover failed".to_string())?;
    if recovered.into_array() != expected {
        return Err(format!(
            "signer mismatch: expected 0x{}, got 0x{}",
            hex::encode(expected),
            hex::encode(recovered.into_array())
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sealed payload shapes.
// ---------------------------------------------------------------------------

/// Shape of the JSON payload sealed into `quotes.quote_enc`. `body_hash` is
/// what a replay is checked against — same idempotency-vs-conflict pattern
/// `root_authorization.rs`'s `AuthorizationPayload` uses.
#[derive(Debug, Serialize, Deserialize)]
struct QuotePayload {
    /// I3: the owning profile, sealed alongside the quote. `quotes.id` is
    /// `sha256("stream_g_quote|v1|" || profile_id || "|" || idempotency_key)`,
    /// so without this the replay branch's ownership claim rested *solely*
    /// on SHA-256 preimage resistance. The in-transaction replay check
    /// compares this against the authenticated caller, and against the
    /// row's own `profile_id` column, before returning a stored quote —
    /// the same belt-and-braces `root_authorization.rs:740-742` applies.
    profile_id: String,
    quote_id_hex: String,
    action_type_hex: String,
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
    body_hash: String,
}

/// What the single `write_tx` decided. I3: the idempotency lookup, the
/// conflict decision and the inserts all now happen inside one
/// `BEGIN IMMEDIATE` transaction, so the closure has to report back which
/// of the three cases it hit rather than the caller inferring it.
///
/// `ReplayOfExpiredQuote` is deliberately a successful `Ok` from the
/// closure's point of view: the transaction has a `quotes.status` update to
/// commit (M6), and returning `Err` there would roll that update back. The
/// typed error is raised by the caller once the transaction has committed.
enum QuoteTxOutcome {
    /// No conflicting prior `quotes` row for this idempotency key. Usually
    /// this call wrote all four rows fresh; if this profile's own prior
    /// quote for the same intentId had expired (Task 4 gap closure), the
    /// `intents` row was superseded in place instead of inserted, and the
    /// old `quotes` row was marked `'expired'`.
    Fresh,
    /// True replay of a still-valid quote; nothing was written.
    Replay(Box<QuotePayload>),
    /// True replay, but the stored quote's validity window has closed.
    ReplayOfExpiredQuote,
}

fn quote_result_from_payload(p: &QuotePayload) -> QuoteResult {
    QuoteResult {
        quote_id_hex: p.quote_id_hex.clone(),
        action_type_hex: p.action_type_hex.clone(),
        action_core_hash_hex: p.action_core_hash_hex.clone(),
        deployment_manifest_hash_hex: p.deployment_manifest_hash_hex.clone(),
        fee_token_config_hash_hex: p.fee_token_config_hash_hex.clone(),
        fee_schedule_hash_hex: p.fee_schedule_hash_hex.clone(),
        payer: p.payer_hex.clone(),
        fee_token: p.fee_token_hex.clone(),
        fee_amount: p.fee_amount.clone(),
        fee_recipient: p.fee_recipient_hex.clone(),
        valid_after: p.valid_after,
        valid_until: p.valid_until,
        quote_signature_hex: p.quote_signature_hex.clone(),
    }
}

/// Shape of the JSON payload sealed into `intents.intent_enc`.
///
/// C2: `intents.id` is a **profile-namespaced** digest, not the raw
/// on-chain `intentId` (see [`INTENT_ROW_ID_DOMAIN`]). The raw 32-byte
/// `intentId` is therefore not recoverable from the primary key, so it is
/// carried here instead — it is the identity of the on-chain intent, it is
/// bound into `actionCoreHash`, and 6b's submit path needs it verbatim.
#[derive(Debug, Serialize, Deserialize)]
struct EnrollmentIntentPayload {
    /// The raw caller-supplied on-chain `intentId`, canonical `0x…` hex.
    intent_id_hex: String,
    /// The owning profile, echoed for the same defence-in-depth reason
    /// `QuotePayload::profile_id` exists: the row id is a SHA-256 digest,
    /// and nothing but preimage resistance otherwise ties the sealed
    /// contents to an owner.
    profile_id: String,
    /// FK back to the `quotes` row this intent was quoted under.
    quote_id_hex: String,
    action_core_hash_hex: String,
}

/// Shape of the JSON payload sealed into `authorizations.signature_enc` for
/// an enrollment quote's nested bearer bundle — see module doc's "Column
/// mapping" section for why both nested signatures live on the parent
/// `authorizations` row rather than on `authorization_slots` itself.
#[derive(Debug, Serialize, Deserialize)]
struct NestedBearerPayload {
    v1_wallet_hex: String,
    v1_nonce: u64,
    v1_deadline: u64,
    v1_signature_hex: String,
    link_root_hex: String,
    link_secondary_hex: String,
    link_nonce: u64,
    link_deadline: u64,
    link_signature_hex: String,
}

// ---------------------------------------------------------------------------
// Nested bearer verification (brief §3.4).
// ---------------------------------------------------------------------------

struct ParsedEnrollmentFields {
    intent_id: [u8; 32],
    root: [u8; 20],
    controller: [u8; 20],
    secondary: [u8; 20],
    root_authorization_digest: [u8; 32],
}

fn parse_enrollment_fields(
    req: &CreateSponsoredEnrollmentQuoteRequest,
) -> Result<ParsedEnrollmentFields, QuoteError> {
    Ok(ParsedEnrollmentFields {
        intent_id: parse_bytes32("intent_id_hex", &req.intent_id_hex)?,
        root: parse_address20("root_address", &req.root_address)?,
        controller: parse_address20("controller_address", &req.controller_address)?,
        secondary: parse_address20("secondary_address", &req.secondary_address)?,
        root_authorization_digest: parse_bytes32(
            "root_authorization_digest_hex",
            &req.root_authorization_digest_hex,
        )?,
    })
}

/// I1: the two nested-bearer digests this server DERIVED, which are what go
/// into the signed `actionCoreHash`.
///
/// The request used to carry `enroll_digest_hex` / `link_digest_hex` and
/// those caller-supplied values were copied verbatim into
/// [`SponsorEnrollmentCore`] — while the module derived the real
/// LinkSecondary digest anyway, used it only for signature recovery, and
/// threw it away. A client that computed either digest against, say, a
/// stale `link_deadline` got a signed quote back, a persisted `intents`
/// row, a burnt idempotency key, and an on-chain revert
/// (`GoatRelayGateway.sol:356` `InvalidV1Enrollment` / `:361`
/// `BadLinkSignature`). Both request fields are now gone entirely — the
/// same structural approach `fee_recipient` already used — so the gateway
/// cannot disagree with the quote by construction.
struct DerivedNestedDigests {
    /// `_v1EnrollDigest(secondary, v1Nonce, v1Deadline)`
    /// (`StreamGEnroll._v1EnrollDigest`), reproduced by
    /// [`sig_verify::enroll_digest`].
    enroll_digest: [u8; 32],
    /// `_linkDigest(link)` (`StreamGEnroll._linkDigest`), reproduced by
    /// [`link_secondary_digest`].
    link_digest: [u8; 32],
}

/// Derives both nested bearer digests, verifies both signatures recover to
/// `secondary` **against the derived values**, AND that their embedded
/// nonces match `ctx.live_nonces` (a fresh
/// `secondaryEnrollmentNonceSnapshot` read) — rejecting stale OR mixed
/// nonces (brief hazard 2: a payload signed against nonces from two
/// different points in time, or against a snapshot that has since
/// advanced, must never be accepted).
fn verify_nested_enrollment_bearers(
    ctx: &EnrollmentQuoteContext<'_>,
    fields: &ParsedEnrollmentFields,
    req: &CreateSponsoredEnrollmentQuoteRequest,
) -> Result<DerivedNestedDigests, QuoteError> {
    if req.v1_nonce != ctx.live_nonces.v1_enroll_nonce()
        || req.link_nonce != ctx.live_nonces.link_nonce()
    {
        return Err(QuoteError::StaleOrMixedNonce);
    }

    // `sig_verify::verify_enroll_sig` would recompute exactly this digest
    // internally and then discard it; call the (already `pub`) digest
    // function directly so the value that authorised the signature is the
    // same one that goes into `actionCoreHash`.
    let enroll_digest = sig_verify::enroll_digest(
        fields.secondary,
        req.v1_nonce,
        req.v1_deadline,
        ctx.manifest.chain_id,
        ctx.manifest.enrollment_registry,
    );
    recover_and_check(enroll_digest, &req.v1_signature_hex, fields.secondary)
        .map_err(QuoteError::BadV1Signature)?;

    let link = LinkSecondary {
        root: fields.root,
        secondary: fields.secondary,
        nonce: req.link_nonce,
        deadline: req.link_deadline,
    };
    let link_digest = link_secondary_digest(
        &link,
        ctx.manifest.chain_id,
        ctx.manifest.wallet_sponsorship_registry,
    );
    recover_and_check(link_digest, &req.link_signature_hex, fields.secondary)
        .map_err(QuoteError::BadLinkSignature)?;

    Ok(DerivedNestedDigests {
        enroll_digest,
        link_digest,
    })
}

/// Canonical concatenation of everything a replay must match to be treated
/// as a true replay (as opposed to a conflicting reuse of the same
/// idempotency key) — same idempotency-vs-conflict shape
/// `root_authorization.rs` uses. Order is arbitrary but must stay stable.
///
/// **C1: nothing derived from the server's clock may appear here.** This
/// string hashes *caller-supplied request parameters only*. `valid_after`
/// and `valid_until` used to be arguments 14 and 15, which made the body
/// hash a function of the second in which the request happened to arrive:
/// a byte-identical retry one second later hashed differently and took the
/// **conflict** path instead of the stored-quote path, so idempotency
/// worked only within a single UNIX second and the documented recovery for
/// a lost HTTP response (retry with the same key) was a permanent dead end.
/// `root_authorization.rs:396-399`, the precedent this module claims parity
/// with, likewise hashes no server clock — its `deadline` comes from the
/// request. `req.deadline` / `req.v1_deadline` / `req.link_deadline` below
/// are caller-supplied and so legitimately belong here; the quote's own
/// validity window does not.
fn canonical_body_string(
    core: &SponsorEnrollmentCore,
    fee_amount: u128,
    req: &CreateSponsoredEnrollmentQuoteRequest,
) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        bytes32_hex(core.intent_id),
        address_hex(core.root),
        address_hex(core.controller),
        core.controller_epoch,
        address_hex(core.secondary),
        bytes32_hex(core.enroll_digest),
        bytes32_hex(core.link_digest),
        bytes32_hex(core.root_authorization_digest),
        core.fee_authorization_mode,
        core.max_fee,
        core.nonce,
        core.deadline,
        fee_amount,
        req.v1_nonce,
        req.v1_deadline,
        // NO `&` ON THESE TWO, and the reason is a CI red rather than taste.
        // clippy 1.97.0's `useless_borrows_in_formatting` rejects a borrow in a
        // format argument; 1.96.1 does not fire on this shape, so the local gate
        // was green while the runner failed to compile. `Display` for `String`
        // and for `&String` emit identical text, so this is byte-identical in a
        // path that feeds `body_hash_hex` and the idempotency key -- which is the
        // only reason it is safe to touch at all. Do not "tidy" a borrow back in.
        req.v1_signature_hex,
        req.link_nonce,
        req.link_signature_hex,
    )
}

fn body_hash_hex(body: &str) -> String {
    hex::encode(Sha256::digest(body.as_bytes()))
}

// ---------------------------------------------------------------------------
// Main entry point.
// ---------------------------------------------------------------------------

/// The body of the mounted `POST /v1/stream-g/quotes` route — flat and
/// plural, per the founder ruling; the nested
/// `/v1/stream-g/quotes/sponsored-enrollment` this comment used to name was
/// never mounted and 404s (asserted in
/// `tests::the_quote_route_refuses_a_mock_mode_process_with_no_live_chain`).
/// [`post_quote`] is the handler that reaches this function. See module doc
/// for the full step order and rationale.
///
/// **I3-style guarantee (matching every other Stream G quote/authorization
/// entry point in this crate — see `profile_auth.rs` module doc).**
/// `profile` is `&AuthenticatedProfileId`, obtainable only from
/// `profile_auth::authenticate_credential` or `profile_auth::validate_session`
/// (plus the `#[cfg(test)]` escape hatch) — never a bare string. A caller
/// cannot quote for a profile it has not authenticated as because there is
/// no code path that manufactures an `AuthenticatedProfileId` without
/// proving possession of a credential or session first, and every
/// `quotes`/`intents`/`authorizations` row this function writes is scoped
/// by `profile.as_str()`, never by anything the request body supplies (see
/// `tests::quote_idempotency_is_scoped_to_the_authenticated_profile_not_the_request`
/// for the runtime proof: two different authenticated profiles reusing the
/// same `idempotency_key` never collide).
pub async fn create_sponsored_enrollment_quote<'c>(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    chain: impl Into<TrustedChain<'c>>,
    profile: &AuthenticatedProfileId,
    ctx: &EnrollmentQuoteContext<'_>,
    fee_schedule: &FeeSchedule,
    req: CreateSponsoredEnrollmentQuoteRequest,
) -> Result<QuoteResult, QuoteError> {
    create_sponsored_enrollment_quote_at(
        store,
        data_key_hex,
        chain.into(),
        profile,
        ctx,
        fee_schedule,
        req,
        now_unix_seconds(),
    )
    .await
}

// ---------------------------------------------------------------------------
// The mounted HTTP route.
// ---------------------------------------------------------------------------

/// `POST /v1/stream-g/quotes` — sign a sponsored-enrollment fee quote for the
/// authenticated caller.
///
/// Founder ruling: the path is **`/v1/stream-g/quotes`**, plural, not the
/// nested `/v1/stream-g/quotes/sponsored-enrollment` that
/// [`create_sponsored_enrollment_quote`]'s and
/// `models::CreateSponsoredEnrollmentQuoteRequest`'s doc comments used to
/// write. Both were corrected in the documentation pass after this route was
/// mounted; the nested path was never mounted and, since the router has no
/// fallback, still 404s — which
/// `tests::the_quote_route_refuses_a_mock_mode_process_with_no_live_chain`
/// asserts directly rather than leaving to prose.
///
/// # This handler assembles the chain context, and the order is load-bearing
///
/// [`EnrollmentQuoteContext`] exists so that nothing the *request* supplies
/// can stand in for chain or manifest state (see
/// `models::EnrollmentQuoteContext`'s per-field docs). Building it
/// is therefore the handler's job, and it follows
/// `preflight::read_live_preflight_state` in the
/// same order and for the same reasons — with **one step of that sequence
/// deliberately not performed**, which is stated in full under "One R2 step
/// this handler does not perform" below rather than left to be discovered:
///
/// 1. `state.trusted_chain()` — `None` under `GOAT_ATTESTOR_MOCK=1`, which is
///    [`ApiError::no_live_chain`] (503). Resolved first: everything below is a
///    chain read.
/// 2. `pinned_block_number()` — **one** block, and every state read below is
///    pinned to it (sourcing contract R4). `ChainClient`'s trait default for
///    this method is an error, so an implementor that does not perform the
///    read fails closed rather than reporting block 0.
/// 3. `token_manifest::read_live_token_state` at that block — against
///    `manifest.fee_token_registry`. **Not `wallet_sponsorship_registry`**:
///    the registry that answers `getTokenConfig`/`getTokenConfigHash` for the
///    fee token is the fee-token registry, and passing the sponsorship
///    registry would read a contract that does not implement those calls —
///    fail-closed, but for a reason no operator could diagnose.
/// 4. **`live_chain_id()` vs `manifest.chain_id`.** Copied deliberately from
///    `preflight::read_live_preflight_state`'s own `EndpointChainMismatch`
///    arm rather than assumed: a hand-assembled context
///    skips this check unless the assembler makes it, and if the endpoint is
///    on a different chain than the manifest describes, every EIP-712 domain
///    separator the quote is signed under is wrong. The 500 this raises says
///    "this process is misconfigured", which is exactly what it is — the
///    caller did nothing.
/// 5. **The loaded schedule's `payload.decimals` vs the registry's
///    `FeeTokenConfig.decimals`** —
///    [`assert_schedule_decimals_match_live_token`]. Same shape and the same
///    500 as step 4, and present for the same reason: this is the first point
///    in the process's life where the registry's number exists at all
///    (`StreamGState::start` reads no chain), so a schedule that prices this
///    deployment's fee token in the wrong unit cannot be refused any earlier.
///    Placed before step 6 so it costs one chain read rather than two. The
///    library re-checks it at STEP 0 as well — see that function's doc.
/// 6. `LiveEnrollmentNonces::read_live` — one
///    `secondaryEnrollmentNonceSnapshot` at the same block (R3). `root` and
///    `secondary` are parsed from the request here *and* re-parsed inside
///    [`create_sponsored_enrollment_quote`]; the duplication is intended, as
///    the library must not trust a parse performed by its caller.
///
/// The quote then binds `ctx.live_token`'s and `ctx.live_nonces`'s
/// `feeTokenConfigHash` values against each other (STEP 0-adjacent, the R3
/// anti-TOCTOU check) — two reads at one pinned block, so a disagreement is
/// evidence, not a race.
///
/// # One R2 step this handler does not perform
///
/// **`FeeTokenRegistry.activeManifestHash()` — sourcing contract R2 step 2.**
/// Preflight reads it (`preflight::read_live_preflight_state`'s "R2 step 2"
/// block, which fills `LivePreflightState::active_manifest_hash`); this
/// handler never does. The
/// `deploymentManifestHash` a quote commits to comes from the manifest *file*
/// (`ctx.manifest.deployment_manifest_hash`, copied into the
/// `SponsorEnrollmentCore` literal at STEP 5 of
/// [`create_sponsored_enrollment_quote_at`] and into the `FeeQuote` at that
/// function's STEP 6), so it will
/// sign a quote carrying a hash the chain has already superseded. The module
/// doc says the same thing about the module ("Live values this module does not
/// read itself"); this section exists because the handler is where a reader
/// looking for the R2 sequence arrives.
///
/// **Why that is a liveness fact and not a forgeable one.** The gateway reads
/// `activeManifestHash()` itself, live, inside the submitting transaction and
/// refuses any quote that disagrees:
/// `contracts/src/libraries/StreamGCommon.sol:118-121`
/// (`validateAndConsumeQuote`) reverts `ConfigHashMismatch()` when either the
/// action core's or the quote's `deploymentManifestHash` differs from the live
/// value, and `contracts/src/GoatRelayGateway.sol:281` fills the nonce
/// snapshot from that same read. A superseded hash therefore buys nothing: it
/// cannot be spent, and a signature over it is worthless.
///
/// **What the caller observes.** The quote succeeds. The refusal moves to
/// submit, which runs a *fresh* `preflight::read_live_preflight_state` at a
/// newly pinned block (`submit.rs:1704`) — that one does perform R2 step 2 —
/// and `preflight::preflight_sponsored_enrollment` rejects with
/// `Check::ManifestHashMismatch` (its two `live_manifest` `ensure`s) before
/// anything is
/// broadcast. So the observable outcome is `PREFLIGHT_WOULD_REVERT` at submit
/// time rather than a reverted transaction and a spent gas bill;
/// `preflight::tests::check_17_manifest_hash_comes_from_the_live_active_manifest_hash_read`
/// is what pins that the live read, not the manifest file, decides it.
///
/// Reading it here would move that refusal earlier and save the caller a round
/// trip. It would not close a hole, so it is a UX improvement and is left
/// undone — with this paragraph rather than a claim that the sequences match.
///
/// # What this build actually answers, today
///
/// **503 `MISSING_TARIFF`, for every well-formed request**, on a process with
/// a live chain. The shipped `fixtures/stream_g_fee_schedule.json` carries
/// `"tariffs": {}` (Task 11 Wave 0), so `FeeSchedule::fee_for` refuses
/// ([`FeeSchedule::fee_for`]'s `ok_or(QuoteError::MissingTariff(..))`) and
/// `QuoteError::status` maps that to 503 rather than
/// 500 on purpose — the tariff table is a deployment input this build has not
/// been given, not a bug. That is the correct fail-closed answer and must not
/// be "fixed" with a placeholder price: a fabricated tariff is
/// indistinguishable downstream from a governed one, and it would be signed.
/// On a mock-mode process the refusal is the 503 from step 1 instead, which is
/// why the tests below assert `NO_LIVE_CHAIN` — see constraint in
/// `runtime::StreamGState::trusted_chain`.
///
/// # The request DTO is unchanged, and three fields stay absent
///
/// `feeRecipient`, `enrollDigestHex` and `linkDigestHex` are server-derived
/// (see `models::CreateSponsoredEnrollmentQuoteRequest`'s "Three fields the
/// gateway cares about are absent by design";
/// `quotes::verify_nested_enrollment_bearers` derives
/// both digests, and `feeRecipient` is `ctx.manifest.fee_safe`, set at the
/// STEP 6 `FeeQuote` build); accepting any of
/// them here would let a caller assert digests the gateway will re-derive and
/// revert on. The DTO is also the measurement
/// `super::tests::the_body_limit_clears_the_largest_real_dto` pins at 1347
/// bytes against [`super::STREAM_G_BODY_LIMIT_BYTES`], so growing it is not a
/// local decision.
///
/// # Extractor order is compiler-enforced
///
/// [`State`] and `AuthenticatedProfile` are `FromRequestParts`; [`ApiJson`] is
/// the `FromRequest` body extractor and must come last. `ApiJson` and not
/// `axum::Json`: a bare `Json<T>` answers a deserialize failure with axum's
/// own body instead of the `ApiError` envelope
/// (`impl From<JsonRejection> for ApiError`, `http_error.rs:307-333`).
pub(crate) async fn post_quote(
    State(state): State<StreamGState>,
    caller: AuthenticatedProfile,
    ApiJson(req): ApiJson<CreateSponsoredEnrollmentQuoteRequest>,
) -> Result<Json<QuoteResult>, ApiError> {
    let trusted = state.trusted_chain().ok_or_else(ApiError::no_live_chain)?;
    let manifest = state.manifest();

    let block = trusted
        .client()
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

    let endpoint_chain_id = live_token.live_chain_id().into_inner();
    if endpoint_chain_id != manifest.chain_id {
        return Err(PreflightError::EndpointChainMismatch {
            endpoint_chain_id,
            manifest_chain_id: manifest.chain_id,
        }
        .into());
    }

    // Step 5: the loaded schedule's `payload.decimals` against the registry's
    // `FeeTokenConfig.decimals` — the first point in the process's life where
    // the right-hand side of that comparison exists. Same shape and same
    // position as the chain-id agreement check above (a live reading, held
    // against a value this process was configured with, refused with a 500
    // that says "this process is misconfigured"), and placed before the nonce
    // read below so a mispriced schedule costs one chain read rather than two.
    // See `assert_schedule_decimals_match_live_token`.
    assert_schedule_decimals_match_live_token(state.fee_schedule(), &live_token)?;

    let live_nonces = LiveEnrollmentNonces::read_live(
        trusted,
        manifest.goat_relay_gateway,
        parse_address20("root_address", &req.root_address)?,
        parse_address20("secondary_address", &req.secondary_address)?,
        manifest.fee_token,
        block,
    )?;

    let ctx = EnrollmentQuoteContext {
        manifest,
        quote_signer_private_key_hex: state.quote_signer_key_hex().as_str(),
        live_token: &live_token,
        max_native_exposure_wei: state.max_native_exposure_wei(),
        live_nonces,
    };

    let quote = create_sponsored_enrollment_quote(
        state.store(),
        state.data_key_hex(),
        trusted,
        caller.profile(),
        &ctx,
        state.fee_schedule(),
        req,
    )
    .await?;
    Ok(Json(quote))
}

/// Clock-injected body of [`create_sponsored_enrollment_quote`].
///
/// **Two clocks, and which one owns what.** `now` is the host wall clock,
/// read once by the public entry point and passed here; it is the sole
/// source of the local bookkeeping columns (`quotes.created_at`,
/// `intents.created_at`, `authorizations.created_at`/`authorized_at`,
/// `authorization_slots.created_at`) and of nothing else. Every quantity
/// the *gateway* will compare against `block.timestamp` — `valid_after`,
/// `valid_until` (and therefore the `expires_at` columns derived from it),
/// plus the replay branch's expiry decision — comes from
/// `chain.block_timestamp()` instead (I2; see STEP 4).
///
/// Injecting `now` is still what makes C1's regression test possible: a
/// true replay has to be provably exercised at a *different* second from
/// the original call (T and T+5), and before this parameter existed the
/// only way to attempt that was to hope the two calls straddled a second
/// boundary — which is also precisely why the old replay test passed while
/// replay was in fact broken for every retry that did not land inside the
/// same UNIX second. Chain time is driven independently in those tests via
/// `MockChain::set_now`.
#[allow(clippy::too_many_arguments)]
async fn create_sponsored_enrollment_quote_at<'c>(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    chain: impl Into<TrustedChain<'c>>,
    profile: &AuthenticatedProfileId,
    ctx: &EnrollmentQuoteContext<'_>,
    fee_schedule: &FeeSchedule,
    req: CreateSponsoredEnrollmentQuoteRequest,
    now: i64,
) -> Result<QuoteResult, QuoteError> {
    // Fail-closed chain-honesty gate — see `token_manifest::TrustedChain`.
    // In a release build the only value satisfying `Into<TrustedChain>` is
    // `TrustedChain::live(&RpcChain)`, so quote creation cannot run against
    // `MockChain`. Resolved before STEP 0 because it is a *type* obligation,
    // not a runtime check: there is nothing here that can fail at run time.
    let chain: &dyn ChainClient = {
        let trusted: TrustedChain<'c> = chain.into();
        trusted.client()
    };

    // --- STEP 0 (HAZARD 3): token gate, strictly before ANY fee
    // computation, exposure-gate chain call, or (if this crate ever grows
    // one) drip-client consultation. See module doc. `ctx.live_token` is a
    // `LiveTokenReading`, so every value the gate compares was sourced by
    // `token_manifest::read_live_token_state` from the chain, not chosen
    // here.
    token_manifest::assert_token_authorized(ctx.live_token, Capability::EIP2612)?;

    // --- STEP 0b: the schedule's own claim about that token's decimals,
    // held against the registry reading the gate just authorized. Placed
    // here — not merely in `post_quote` — because this function is where
    // `fee_schedule.fee_for` is called (STEP 3), and a library must not
    // trust a check performed by its caller; the same rule this module
    // already applies to the root/secondary address parse. Every quantity
    // compared is chain- or file-sourced, so this is pure and cannot fail
    // for a request-shaped reason. See
    // `assert_schedule_decimals_match_live_token`.
    assert_schedule_decimals_match_live_token(fee_schedule, ctx.live_token)?;

    // --- R3 anti-TOCTOU binding (sourcing contract §3), run immediately
    // after the gate. `ctx.live_token` and `ctx.live_nonces` are two
    // INDEPENDENT chain reads (`token_manifest::read_live_token_state` and
    // `models::LiveEnrollmentNonces::read_live`, respectively) — nothing
    // above this point proves they were taken at the same chain state.
    // `secondaryEnrollmentNonceSnapshot`'s own `feeTokenConfigHash` word
    // (gated behind `SNAP_CONFIG_HASHES`, validated by
    // `LiveEnrollmentNonces::from_snapshot`) is the gateway's own view of
    // `getTokenConfigHash(feeToken)`; comparing it against the same value
    // the gate above just verified matches the registry's own hash (R2
    // step 1, inside `read_live_token_state`) proves the token config the
    // gate authorized and the nonces this quote is about to commit to were
    // observed in the SAME chain state. A mismatch means the two reads
    // straddled a config upsert or a reorg — fail closed rather than sign
    // a quote binding stale-relative-to-each-other values together.
    if ctx.live_token.fee_token_config_hash() != ctx.live_nonces.fee_token_config_hash() {
        return Err(QuoteError::FeeTokenConfigHashToctouMismatch {
            live_token: bytes32_hex(ctx.live_token.fee_token_config_hash()),
            live_nonces: bytes32_hex(ctx.live_nonces.fee_token_config_hash()),
        });
    }

    // Everything below this line is downstream of the gate — including the
    // data-key parse, which used to run first and made the module doc's
    // "very first operation" claim false (M9).
    let data_key = DataKey::from_secret(data_key_hex);

    // --- STEP 1: parse + verify the nested bearer signatures. No chain
    // calls, no fee computation yet.
    let fields = parse_enrollment_fields(&req)?;

    // --- STEP 1a (I1 + M8): gateway preconditions on request fields that
    // flow *verbatim* into the signed `actionCoreHash`. Each of these is a
    // hard on-chain revert, so signing a quote that carries one is signing
    // a credential that can only ever fail — and it burns the caller's
    // idempotency key and `intents` row on the way. Cheap, pure, and
    // therefore placed before the exposure gate's chain calls (but after
    // the hazard-3 token gate, which is unconditionally first).
    //
    // `feeAuthorizationMode` is a `StreamGTypes.AuthorizationMode` ORDINAL
    // (`StreamGTypes.sol:12-17`: NONE=0, EIP2612=1, EIP3009=2,
    // PRIOR_ALLOWANCE=3) — a different numbering scheme from the `CAP_*`
    // capability BITMASK (`:29-32`) the token gate above checks, exactly
    // the conflation `token_manifest`'s module doc warns about under
    // "`CAP_*` bits vs `AuthorizationMode` ordinals: independent numbering".
    // `1` here is the enum ordinal, read from the Solidity, not
    // `CAP_EIP2612`'s bit value.
    if fields.root_authorization_digest != [0u8; 32] {
        return Err(QuoteError::NonZeroRootAuthorizationDigest);
    }
    if req.fee_authorization_mode != AUTHORIZATION_MODE_EIP2612 {
        return Err(QuoteError::UnsupportedFeeMode(req.fee_authorization_mode));
    }
    if req.deadline > UINT48_MAX {
        return Err(QuoteError::DeadlineExceedsUint48 {
            field: "deadline",
            value: req.deadline,
        });
    }
    if req.link_deadline > UINT48_MAX {
        return Err(QuoteError::DeadlineExceedsUint48 {
            field: "link_deadline",
            value: req.link_deadline,
        });
    }

    let derived = verify_nested_enrollment_bearers(ctx, &fields, &req)?;

    // --- STEP 2: native exposure gate (base_fee, Task 5) — a GATE, never
    // a fee input. See module doc's tariff/exposure separation.
    let max_fee_per_gas = parse_u128_decimal("max_fee_per_gas_wei", &req.max_fee_per_gas_wei)?;
    let _gated = base_fee::quote_exposure(
        chain,
        GasUnits::new(req.gas_unit_ceiling),
        MaxFeePerGas::new(max_fee_per_gas),
        TxSizeBytes::new(req.unsigned_size_ceiling),
        ctx.max_native_exposure_wei,
    )?;

    // --- STEP 3: fixed USDT tariff (brief §3.1) + gateway precondition
    // pre-checks that are pre-checkable server-side (brief §2.4).
    let fee_amount = fee_schedule.fee_for(ActionType::SponsoredEnrollment)?;
    if fee_amount == 0 {
        return Err(QuoteError::ZeroFeeAmount(
            ActionType::SponsoredEnrollment.as_str(),
        ));
    }
    let max_fee = parse_u128_decimal("max_fee", &req.max_fee)?;
    if fee_amount > max_fee {
        return Err(QuoteError::FeeExceedsMax {
            fee_amount,
            max_fee,
        });
    }

    // --- STEP 4: validity window — CHAIN time + uint48 range + server TTL
    // policy clamp.
    //
    // I2: `StreamGCommon.validateAndConsumeQuote` evaluates
    // `quote.validAfter <= block.timestamp && block.timestamp <
    // quote.validUntil`, so both bounds are chain-clock quantities and are
    // cut from `chain.block_timestamp()`. They used to come from
    // `now_unix_seconds()` — the attestor host's wall clock — which meant
    // NTP drift ahead of the Base sequencer put every quote in the chain's
    // future, and drift beyond `valid_for_seconds` took sponsored
    // enrollment fully offline with every health check and unit test still
    // green (the window test compared against that same host clock, so it
    // was structurally incapable of noticing). Same bug class as this
    // project's already-fixed SD-1 wall-clock epoch bug.
    //
    // Fail CLOSED: there is deliberately no wall-clock fallback. A zero is
    // treated as unavailable too, because `ChainClient::block_timestamp`'s
    // trait default (`chain.rs:139`) is `Ok(0)` documented as
    // "0 = unknown" — issuing a 1970 `validAfter` off an unconfigured
    // implementor is exactly the silent-zero failure this crate's
    // "default bodies return Err, never Ok(0)" convention exists to avoid.
    if req.valid_for_seconds == 0 || req.valid_for_seconds > QUOTE_TTL_SECONDS_MAX {
        return Err(QuoteError::ValidityExceedsPolicy);
    }
    let chain_now = chain
        .block_timestamp()
        .map_err(|e| QuoteError::ChainTimeUnavailable(e.to_string()))?;
    if chain_now == 0 {
        return Err(QuoteError::ChainTimeUnavailable(
            "block_timestamp() returned 0, which this ChainClient documents as \"unknown\"".into(),
        ));
    }
    let valid_after = chain_now;
    let valid_until = valid_after.saturating_add(req.valid_for_seconds);
    if valid_until > UINT48_MAX {
        return Err(QuoteError::ValidityExceedsUint48);
    }

    // --- STEP 5: actionCoreHash — binds this quote to the specific
    // sponsored-enrollment intent it will later execute against.
    // The registry's OWN `getTokenConfigHash(feeToken)` value, proven equal
    // to this module's `_hashConfig` reproduction of the decoded struct
    // inside `read_live_token_state` — not recomputed here from a
    // caller-supplied struct.
    let fee_token_config_hash = ctx.live_token.fee_token_config_hash();
    let core = SponsorEnrollmentCore {
        intent_id: fields.intent_id,
        deployment_manifest_hash: ctx.manifest.deployment_manifest_hash,
        fee_token_config_hash,
        root: fields.root,
        controller: fields.controller,
        controller_epoch: req.controller_epoch,
        secondary: fields.secondary,
        // I1: SERVER-DERIVED, never the caller's claim — the request has no
        // field for either any more. See [`DerivedNestedDigests`].
        enroll_digest: derived.enroll_digest,
        link_digest: derived.link_digest,
        // Validated `== 0` / `== EIP2612` in STEP 1a above; both are hard
        // gateway reverts (`GoatRelayGateway.sol:365`, `:395`).
        root_authorization_digest: fields.root_authorization_digest,
        fee_token: ctx.manifest.fee_token,
        fee_authorization_mode: req.fee_authorization_mode,
        max_fee,
        nonce: req.nonce,
        deadline: req.deadline,
    };
    let action_core_hash = sponsor_enrollment_core_hash(&core);

    // --- STEP 6: build the unsigned FeeQuote. `fee_recipient` comes ONLY
    // from the manifest's `feeSafe` — brief §2.4's `feeRecipient == feeSafe`
    // precondition, enforced structurally (the request has no such field).
    let quote = FeeQuote {
        quote_id: quote_id_bytes(profile.as_str(), &req.idempotency_key),
        action_type: ActionType::SponsoredEnrollment.digest(),
        action_core_hash,
        deployment_manifest_hash: ctx.manifest.deployment_manifest_hash,
        fee_token_config_hash,
        fee_schedule_hash: ctx.manifest.fee_schedule_hash,
        payer: fields.controller,
        fee_token: ctx.manifest.fee_token,
        fee_amount,
        fee_recipient: ctx.manifest.fee_safe,
        valid_after,
        valid_until,
    };

    let body = canonical_body_string(&core, fee_amount, &req);
    let body_hash = body_hash_hex(&body);

    let profile_id = profile.as_str().to_string();
    let quote_row_id = hex::encode(quote.quote_id);

    // --- STEP 7 is now the FIRST statement inside the `write_tx` closure
    // below (I3). It used to live here, as a `store.read` — which
    // `store.rs:465-472` documents as offering no snapshot isolation — with
    // the actual conflict decision taken 70-odd lines later by
    // `rows_affected()` inside the transaction. Two concurrent *true*
    // replays therefore both read empty, both signed, and the loser got
    // `IDEMPOTENCY_KEY_CONFLICT` instead of the stored quote. Nothing
    // unsafe was ever released (signing is RFC 6979 deterministic, so both
    // tasks produce byte-identical signatures) but the idempotency contract
    // was wrong. `root_authorization.rs:692-743` established the in-tx
    // shape this now follows.

    // --- STEP 8: sign. Deterministic (RFC 6979) — safe outside a
    // transaction, see module doc.
    let signer = PrivateKeySigner::from_str(ctx.quote_signer_private_key_hex.trim())
        .map_err(|e| QuoteError::InvalidQuoteSignerKey(e.to_string()))?;
    let digest = fee_quote_digest(
        &quote,
        ctx.manifest.chain_id,
        ctx.manifest.goat_relay_gateway,
    );
    let signature = signer
        .sign_hash_sync(&B256::from(digest))
        .map_err(|e| QuoteError::SigningFailed(e.to_string()))?;
    let quote_signature_hex = format!("0x{}", hex::encode(signature.as_bytes()));

    let payload = QuotePayload {
        profile_id: profile_id.clone(),
        quote_id_hex: bytes32_hex(quote.quote_id),
        action_type_hex: bytes32_hex(quote.action_type),
        action_core_hash_hex: bytes32_hex(quote.action_core_hash),
        deployment_manifest_hash_hex: bytes32_hex(quote.deployment_manifest_hash),
        fee_token_config_hash_hex: bytes32_hex(quote.fee_token_config_hash),
        fee_schedule_hash_hex: bytes32_hex(quote.fee_schedule_hash),
        payer_hex: address_hex(quote.payer),
        fee_token_hex: address_hex(quote.fee_token),
        fee_amount: fee_amount.to_string(),
        fee_recipient_hex: address_hex(quote.fee_recipient),
        valid_after,
        valid_until,
        quote_signature_hex: quote_signature_hex.clone(),
        body_hash: body_hash.clone(),
    };
    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|e| QuoteError::MalformedPayload(e.to_string()))?;
    let quote_aad = store.envelope_aad("quotes", &quote_row_id, "quote_enc");
    let quote_enc = crypto_store::seal(&data_key, &quote_aad, &payload_bytes)?;

    let authorization_row_id = deterministic_id(&[
        "stream_g_enrollment_bearers",
        &profile_id,
        &req.idempotency_key,
    ]);
    let bearer_payload = NestedBearerPayload {
        v1_wallet_hex: address_hex(fields.secondary),
        v1_nonce: req.v1_nonce,
        v1_deadline: req.v1_deadline,
        v1_signature_hex: req.v1_signature_hex.clone(),
        link_root_hex: address_hex(fields.root),
        link_secondary_hex: address_hex(fields.secondary),
        link_nonce: req.link_nonce,
        link_deadline: req.link_deadline,
        link_signature_hex: req.link_signature_hex.clone(),
    };
    let bearer_bytes = serde_json::to_vec(&bearer_payload)
        .map_err(|e| QuoteError::MalformedPayload(e.to_string()))?;
    let auth_aad = store.envelope_aad("authorizations", &authorization_row_id, "signature_enc");
    let signature_enc = crypto_store::seal(&data_key, &auth_aad, &bearer_bytes)?;

    // C2: NOT `bytes32_hex(fields.intent_id)`. `intents.id` is a global
    // `TEXT PRIMARY KEY` (`migrations/0001_stream_g.sql:104-106`), so
    // binding the raw caller-supplied on-chain `intentId` to it let any
    // authenticated profile permanently claim any intentId for everybody.
    // Namespaced per profile, matching `onboarding.rs` — the other writer
    // of this table. See `INTENT_ROW_ID_DOMAIN` and
    // `tests::two_profiles_can_quote_the_same_onchain_intent_id_without_colliding`.
    let intent_row_id = deterministic_id(&[
        INTENT_ROW_ID_DOMAIN,
        &profile_id,
        &bytes32_hex(fields.intent_id),
    ]);
    let intent_payload = EnrollmentIntentPayload {
        intent_id_hex: bytes32_hex(fields.intent_id),
        profile_id: profile_id.clone(),
        quote_id_hex: bytes32_hex(quote.quote_id),
        action_core_hash_hex: bytes32_hex(action_core_hash),
    };
    let intent_bytes = serde_json::to_vec(&intent_payload)
        .map_err(|e| QuoteError::MalformedPayload(e.to_string()))?;
    let intent_aad = store.envelope_aad("intents", &intent_row_id, "intent_enc");
    let intent_enc = crypto_store::seal(&data_key, &intent_aad, &intent_bytes)?;

    let base_asset = address_hex(ctx.manifest.fee_token);
    let quote_amount = fee_amount.to_string();
    let fee_amount_str = fee_amount.to_string();
    let valid_until_i64 = valid_until as i64;
    let quote_row_id_for_tx = quote_row_id.clone();
    let intent_row_id_for_tx = intent_row_id.clone();
    let authorization_row_id_for_tx = authorization_row_id.clone();
    let profile_id_for_tx = profile_id.clone();

    // I3: `write_tx`'s closure cannot capture a borrow of `store`
    // (`store.rs:419-424` — single-connection pool, a nested `store` call
    // deadlocks to `PoolTimedOut`), so pull the two plain values
    // `envelope_aad` would have read out of `store` now and build the
    // `EnvelopeAad` by hand inside the closure. Exactly
    // `root_authorization.rs:687-688` / `:725-733`.
    let db_uuid_owned = store.db_uuid().to_string();
    // `envelope_aad_version()`, NOT `schema_version()` — see
    // `StreamGStore::envelope_aad_version`. Sealing under the live schema
    // version would make every envelope written before a migration
    // undecryptable after it.
    let schema_version = store.envelope_aad_version();

    let outcome = store
        .write_tx(move |tx| {
            Box::pin(async move {
                // --- STEP 7 (I3): idempotency, decided INSIDE the
                // transaction that will act on the decision. `BEGIN
                // IMMEDIATE` holds the writer lock for this whole closure,
                // so no concurrent call can commit between this read and
                // the inserts below.
                let existing = sqlx::query(
                    "SELECT quote_enc, profile_id FROM quotes WHERE id = ?",
                )
                .bind(&quote_row_id_for_tx)
                .fetch_optional(&mut **tx)
                .await?;

                if let Some(row) = existing {
                    let row_profile_id: Option<String> = row.try_get("profile_id")?;
                    let stored_enc: Vec<u8> = row.try_get("quote_enc")?;

                    let aad = EnvelopeAad {
                        db_uuid: &db_uuid_owned,
                        schema_version,
                        table: "quotes",
                        pk: &quote_row_id_for_tx,
                        column: "quote_enc",
                    };
                    let opened = crypto_store::open(&data_key, &aad, &stored_enc)?;
                    let stored: QuotePayload = serde_json::from_slice(&opened)
                        .map_err(|e| QuoteError::MalformedPayload(e.to_string()))?;

                    // Body hash AND ownership, both. The row id is only a
                    // SHA-256 digest of (profile_id, idempotency_key), so
                    // the profile equality checks are what make the
                    // ownership claim structural rather than a preimage
                    // argument.
                    let is_true_replay = stored.body_hash == body_hash
                        && stored.profile_id == profile_id_for_tx
                        && row_profile_id.as_deref() == Some(profile_id_for_tx.as_str());

                    if !is_true_replay {
                        return Err(QuoteError::IdempotencyKeyConflict);
                    }

                    // M6: a true replay of an EXPIRED quote must not hand
                    // back a dead credential. `valid_until` is the
                    // uint48 the gateway will compare against
                    // `block.timestamp`; once chain time has reached it the
                    // stored signature is unusable on-chain, so returning
                    // it would be a silent failure the caller only
                    // discovers when its transaction reverts. This branch
                    // was effectively unreachable before C1 landed.
                    //
                    // I2: compared against `chain_now`, not the host clock.
                    // `stored.valid_until` is a chain-clock quantity, so
                    // comparing a wall clock to it would reintroduce
                    // exactly the drift this module just removed — in the
                    // more dangerous direction, since a host clock running
                    // ahead would declare live quotes expired.
                    if chain_now >= stored.valid_until {
                        // Make the ledger honest too: nothing previously
                        // transitioned `quotes.status` off `'active'`.
                        // This is committed (the tx returns `Ok`) and the
                        // typed error is raised by the caller below.
                        sqlx::query("UPDATE quotes SET status = 'expired' WHERE id = ?")
                            .bind(&quote_row_id_for_tx)
                            .execute(&mut **tx)
                            .await?;
                        return Ok(QuoteTxOutcome::ReplayOfExpiredQuote);
                    }

                    return Ok(QuoteTxOutcome::Replay(Box::new(stored)));
                }

                let r1 = sqlx::query(
                    "INSERT OR IGNORE INTO quotes \
                     (id, profile_id, base_asset, quote_asset, base_amount, quote_amount, \
                      fee_bps, status, quote_enc, created_at, expires_at) \
                     VALUES (?, ?, ?, ?, ?, ?, NULL, 'active', ?, ?, ?)",
                )
                .bind(&quote_row_id_for_tx)
                .bind(&profile_id_for_tx)
                .bind(&base_asset)
                .bind(QUOTES_TABLE_QUOTE_ASSET_MARKER)
                .bind("0")
                .bind(&quote_amount)
                .bind(&quote_enc)
                .bind(now)
                .bind(valid_until_i64)
                .execute(&mut **tx)
                .await?;
                if r1.rows_affected() != 1 {
                    return Err(QuoteError::IdempotencyKeyConflict);
                }

                // --- Task 4 gap closure: re-quoting an expired intent.
                //
                // `intent_row_id_for_tx` is deterministic in (profile_id,
                // on-chain intentId) (C2), so a FRESH idempotency key on the
                // SAME intentId this profile has quoted before collides
                // here, not on the `quotes` row above. Two cases:
                //
                // - The prior quote for this intent is still valid: this is
                //   the DELIBERATE rejection the module doc describes (a
                //   second live quote against a single-use on-chain
                //   intent) — unchanged, still `IdempotencyKeyConflict`.
                // - The prior quote has genuinely expired (against CHAIN
                //   time — same predicate the M6 replay-expiry branch above
                //   uses) and was never executed: the gateway only
                //   consumes `intentId` at EXECUTION
                //   (`intentUsed[intentId]`), never at quote time, so an
                //   unexecuted, expired intentId is still fresh. The old
                //   "same key forever returns QUOTE_EXPIRED, any fresh key
                //   forever returns IDEMPOTENCY_KEY_CONFLICT" dead end had
                //   no recovery for a legitimate caller. Superseding the
                //   `intents` row IN PLACE (never delete+reinsert, so the
                //   profile-namespaced id keeps doing C2's job) reopens it,
                //   strictly scoped to THIS profile.
                let existing_intent = sqlx::query(
                    "SELECT profile_id, quote_id FROM intents WHERE id = ?",
                )
                .bind(&intent_row_id_for_tx)
                .fetch_optional(&mut **tx)
                .await?;

                let mut superseding_intent = false;
                if let Some(irow) = existing_intent {
                    let intent_owner: String = irow.try_get("profile_id")?;
                    let prior_quote_id: Option<String> = irow.try_get("quote_id")?;

                    // Belt-and-braces, matching the replay branch's
                    // ownership double-check above (`root_authorization.rs`
                    // precedent): `intent_row_id_for_tx` is already
                    // profile-namespaced, so this should be unreachable, but
                    // "should be" is not "enforced" — never supersede a row
                    // the STORED column says this profile does not own.
                    if intent_owner != profile_id_for_tx {
                        return Err(QuoteError::IdempotencyKeyConflict);
                    }

                    let prior_expires_at: Option<i64> = match &prior_quote_id {
                        Some(qid) => {
                            let qrow = sqlx::query("SELECT expires_at FROM quotes WHERE id = ?")
                                .bind(qid)
                                .fetch_optional(&mut **tx)
                                .await?;
                            match qrow {
                                Some(r) => Some(r.try_get("expires_at")?),
                                None => None,
                            }
                        }
                        None => None,
                    };

                    // Chain time, not the host wall clock — same I2
                    // discipline the M6 replay-expiry check above uses.
                    let prior_is_expired =
                        matches!(prior_expires_at, Some(exp) if chain_now as i64 >= exp);
                    if !prior_is_expired {
                        return Err(QuoteError::IdempotencyKeyConflict);
                    }

                    // Make the ledger honest: the prior quote this intent
                    // used to point at is no longer the live one — do not
                    // leave two rows both readable as "the" quote for this
                    // intent.
                    if let Some(qid) = &prior_quote_id {
                        sqlx::query(
                            "UPDATE quotes SET status = 'expired' WHERE id = ? AND status != 'expired'",
                        )
                        .bind(qid)
                        .execute(&mut **tx)
                        .await?;
                    }
                    superseding_intent = true;
                }

                let r2 = if superseding_intent {
                    sqlx::query(
                        "UPDATE intents SET quote_id = ?, amount = ?, status = 'pending', \
                         intent_enc = ?, created_at = ?, expires_at = ? \
                         WHERE id = ? AND profile_id = ?",
                    )
                    .bind(&quote_row_id_for_tx)
                    .bind(&fee_amount_str)
                    .bind(&intent_enc)
                    .bind(now)
                    .bind(valid_until_i64)
                    .bind(&intent_row_id_for_tx)
                    .bind(&profile_id_for_tx)
                    .execute(&mut **tx)
                    .await?
                } else {
                    sqlx::query(
                        "INSERT OR IGNORE INTO intents \
                         (id, profile_id, quote_id, intent_type, amount, status, intent_enc, \
                          created_at, expires_at) \
                         VALUES (?, ?, ?, 'sponsored_enrollment', ?, 'pending', ?, ?, ?)",
                    )
                    .bind(&intent_row_id_for_tx)
                    .bind(&profile_id_for_tx)
                    .bind(&quote_row_id_for_tx)
                    .bind(&fee_amount_str)
                    .bind(&intent_enc)
                    .bind(now)
                    .bind(valid_until_i64)
                    .execute(&mut **tx)
                    .await?
                };
                if r2.rows_affected() != 1 {
                    return Err(QuoteError::IdempotencyKeyConflict);
                }

                let r3 = sqlx::query(
                    "INSERT OR IGNORE INTO authorizations \
                     (id, intent_id, profile_id, status, signature_enc, created_at, authorized_at) \
                     VALUES (?, ?, ?, 'authorized', ?, ?, ?)",
                )
                .bind(&authorization_row_id_for_tx)
                .bind(&intent_row_id_for_tx)
                .bind(&profile_id_for_tx)
                .bind(&signature_enc)
                .bind(now)
                .bind(now)
                .execute(&mut **tx)
                .await?;
                if r3.rows_affected() != 1 {
                    return Err(QuoteError::IdempotencyKeyConflict);
                }

                // M7: `reserved` / `filled_at = NULL`. Quoting RESERVES the
                // two nested slots (brief §3.4, and this module's own
                // "reservation ledger" wording) — it does not fill them.
                // They were being written `'filled'` with a non-NULL
                // `filled_at` at quote time, which contradicted both the
                // module doc and the schema's own `'pending'` default and
                // would have told 6b that work already done which has not
                // been. 6b's submit path is what transitions them.
                for slot_index in [0i64, 1i64] {
                    let slot_id = format!("{authorization_row_id_for_tx}-slot-{slot_index}");
                    let rs = sqlx::query(
                        "INSERT OR IGNORE INTO authorization_slots \
                         (id, authorization_id, slot_index, amount, status, created_at, filled_at) \
                         VALUES (?, ?, ?, NULL, ?, ?, NULL)",
                    )
                    .bind(&slot_id)
                    .bind(&authorization_row_id_for_tx)
                    .bind(slot_index)
                    .bind(SLOT_STATUS_RESERVED)
                    .bind(now)
                    .execute(&mut **tx)
                    .await?;
                    if rs.rows_affected() != 1 {
                        return Err(QuoteError::IdempotencyKeyConflict);
                    }
                }

                Ok::<QuoteTxOutcome, QuoteError>(QuoteTxOutcome::Fresh)
            })
        })
        .await?;

    match outcome {
        QuoteTxOutcome::Fresh => Ok(quote_result_from_payload(&payload)),
        QuoteTxOutcome::Replay(stored) => Ok(quote_result_from_payload(&stored)),
        QuoteTxOutcome::ReplayOfExpiredQuote => Err(QuoteError::StoredQuoteExpired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::MockChain;
    use crate::stream_g::base_fee::WeiCeiling;
    use crate::stream_g::models::LiveEnrollmentNonces;
    use crate::stream_g::token_manifest::{
        DeploymentManifest, LiveTokenReading, TokenCapability, CAP_EIP2612,
    };

    const QUOTE_SIGNER_PK: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const SECONDARY_PK: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    /// I6: anvil key 2 — an attacker's key, used only to produce a nested
    /// bearer signature that recovers to somebody other than `secondary`.
    const WRONG_BEARER_PK: &str =
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

    async fn open_store() -> (tempfile::TempDir, StreamGStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open store");
        (dir, store)
    }

    fn data_key_hex() -> SecretHex {
        SecretHex::from_hex(&"cc".repeat(32)).expect("valid 32-byte test key")
    }

    fn manifest_fixture() -> DeploymentManifest {
        DeploymentManifest {
            schema_version: 1,
            chain_id: 31337,
            phase: "G1".to_string(),
            enrollment_registry: [0x10; 20],
            goat_coin: [0x11; 20],
            fee_token: [0x12; 20],
            fee_token_registry: [0x13; 20],
            wallet_sponsorship_registry: [0x14; 20],
            sponsored_buy_desk: [0x15; 20],
            goat_relay_gateway: [0x16; 20],
            policy_safe: [0x17; 20],
            fee_safe: [0x18; 20],
            recovery_safe: [0x19; 20],
            desk_owner: [0x1A; 20],
            // I5: this MUST be the address of `QUOTE_SIGNER_PK`, the key
            // `base_ctx` hands the module to sign with. It used to be a
            // `[0x1B; 20]` placeholder that corresponded to no key at all,
            // which made it impossible to write any test that recovered the
            // emitted signature — and so the module's entire output
            // artifact went unchecked. See
            // `emitted_quote_signature_recovers_to_the_manifest_quote_signer`.
            quote_signer: PrivateKeySigner::from_str(QUOTE_SIGNER_PK)
                .expect("QUOTE_SIGNER_PK is a valid secp256k1 key")
                .address()
                .into_array(),
            deployment_manifest_hash: [0xAA; 32],
            fee_schedule_hash: [0xBB; 32],
        }
    }

    fn code_hash_fixture() -> [u8; 32] {
        [0x22; 32]
    }

    fn authorized_token_capability(manifest: &DeploymentManifest) -> TokenCapability {
        TokenCapability {
            chain_id: manifest.chain_id,
            token_address: manifest.fee_token,
            runtime_code_hash: code_hash_fixture(),
            proxy_identity_hash: [0u8; 32],
            capability_mask: CAP_EIP2612,
            decimals: 6,
            domain_name_hash: [0u8; 32],
            domain_version_hash: [0u8; 32],
            built_in_mode_id: [0u8; 32],
            config_version: 1,
            active: true,
        }
    }

    async fn seed_profile(store: &StreamGStore, profile_id: &str) {
        let profile_id = profile_id.to_string();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO profiles (id, created_at, status) VALUES (?, 0, 'active')",
                    )
                    .bind(&profile_id)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed profile");
    }

    async fn quotes_count(store: &StreamGStore) -> i64 {
        store
            .read(|handle| {
                Box::pin(async move {
                    let c: i64 = handle
                        .fetch_scalar(sqlx::query_scalar("SELECT COUNT(*) FROM quotes"))
                        .await?;
                    Ok::<i64, StreamGStoreError>(c)
                })
            })
            .await
            .unwrap()
    }

    async fn intents_count(store: &StreamGStore) -> i64 {
        store
            .read(|handle| {
                Box::pin(async move {
                    let c: i64 = handle
                        .fetch_scalar(sqlx::query_scalar("SELECT COUNT(*) FROM intents"))
                        .await?;
                    Ok::<i64, StreamGStoreError>(c)
                })
            })
            .await
            .unwrap()
    }

    async fn authorization_slots_count(store: &StreamGStore) -> i64 {
        store
            .read(|handle| {
                Box::pin(async move {
                    let c: i64 = handle
                        .fetch_scalar(sqlx::query_scalar(
                            "SELECT COUNT(*) FROM authorization_slots",
                        ))
                        .await?;
                    Ok::<i64, StreamGStoreError>(c)
                })
            })
            .await
            .unwrap()
    }

    // -- M10: read-back helpers ------------------------------------------
    //
    // Before these existed, every persistence assertion in this suite was a
    // COUNT(*). That means no test could tell the difference between the
    // right values and the wrong ones in the right number of rows —
    // swapping the `.bind("0")` and `.bind(&quote_amount)` arguments on the
    // `quotes` insert persisted a zero fee with the whole suite green. Each
    // struct below mirrors one table's columns exactly so an assertion can
    // name a column rather than count rows.

    #[derive(Debug)]
    struct QuoteRow {
        profile_id: Option<String>,
        base_asset: String,
        quote_asset: String,
        base_amount: String,
        quote_amount: String,
        fee_bps: Option<i64>,
        status: String,
        created_at: i64,
        expires_at: i64,
    }

    /// The `quotes` primary key for a returned quote — `quotes.id` is the
    /// un-prefixed hex of `FeeQuote.quoteId`, while `QuoteResult` carries
    /// the canonical `0x…` form.
    fn hex_id_of(q: &QuoteResult) -> String {
        q.quote_id_hex
            .strip_prefix("0x")
            .unwrap_or(&q.quote_id_hex)
            .to_string()
    }

    async fn quote_row(store: &StreamGStore, id: &str) -> QuoteRow {
        let id = id.to_string();
        store
            .read(|handle| {
                Box::pin(async move {
                    let r = handle
                        .fetch_one(
                            sqlx::query(
                                "SELECT profile_id, base_asset, quote_asset, base_amount, \
                                 quote_amount, fee_bps, status, created_at, expires_at \
                                 FROM quotes WHERE id = ?",
                            )
                            .bind(id),
                        )
                        .await?;
                    Ok::<QuoteRow, StreamGStoreError>(QuoteRow {
                        profile_id: r.try_get("profile_id")?,
                        base_asset: r.try_get("base_asset")?,
                        quote_asset: r.try_get("quote_asset")?,
                        base_amount: r.try_get("base_amount")?,
                        quote_amount: r.try_get("quote_amount")?,
                        fee_bps: r.try_get("fee_bps")?,
                        status: r.try_get("status")?,
                        created_at: r.try_get("created_at")?,
                        expires_at: r.try_get("expires_at")?,
                    })
                })
            })
            .await
            .expect("quotes row must exist")
    }

    #[derive(Debug)]
    struct IntentRow {
        profile_id: String,
        quote_id: Option<String>,
        intent_type: String,
        amount: Option<String>,
        status: String,
        created_at: i64,
        expires_at: Option<i64>,
    }

    async fn intent_row(store: &StreamGStore, id: &str) -> IntentRow {
        let id = id.to_string();
        store
            .read(|handle| {
                Box::pin(async move {
                    let r = handle
                        .fetch_one(
                            sqlx::query(
                                "SELECT profile_id, quote_id, intent_type, amount, status, \
                                 created_at, expires_at FROM intents WHERE id = ?",
                            )
                            .bind(id),
                        )
                        .await?;
                    Ok::<IntentRow, StreamGStoreError>(IntentRow {
                        profile_id: r.try_get("profile_id")?,
                        quote_id: r.try_get("quote_id")?,
                        intent_type: r.try_get("intent_type")?,
                        amount: r.try_get("amount")?,
                        status: r.try_get("status")?,
                        created_at: r.try_get("created_at")?,
                        expires_at: r.try_get("expires_at")?,
                    })
                })
            })
            .await
            .expect("intents row must exist")
    }

    #[derive(Debug)]
    struct AuthorizationRow {
        intent_id: String,
        profile_id: String,
        status: String,
        created_at: i64,
        authorized_at: Option<i64>,
    }

    async fn authorization_row(store: &StreamGStore, id: &str) -> AuthorizationRow {
        let id = id.to_string();
        store
            .read(|handle| {
                Box::pin(async move {
                    let r = handle
                        .fetch_one(
                            sqlx::query(
                                "SELECT intent_id, profile_id, status, created_at, authorized_at \
                                 FROM authorizations WHERE id = ?",
                            )
                            .bind(id),
                        )
                        .await?;
                    Ok::<AuthorizationRow, StreamGStoreError>(AuthorizationRow {
                        intent_id: r.try_get("intent_id")?,
                        profile_id: r.try_get("profile_id")?,
                        status: r.try_get("status")?,
                        created_at: r.try_get("created_at")?,
                        authorized_at: r.try_get("authorized_at")?,
                    })
                })
            })
            .await
            .expect("authorizations row must exist")
    }

    #[derive(Debug)]
    struct SlotRow {
        slot_index: i64,
        amount: Option<String>,
        status: String,
        created_at: i64,
        filled_at: Option<i64>,
    }

    /// Every `authorization_slots` row for one authorization, ordered by
    /// `slot_index`.
    async fn slot_rows(store: &StreamGStore, authorization_id: &str) -> Vec<SlotRow> {
        let id = authorization_id.to_string();
        store
            .read(|handle| {
                Box::pin(async move {
                    let rows = handle
                        .fetch_all(
                            sqlx::query(
                                "SELECT slot_index, amount, status, created_at, filled_at \
                                 FROM authorization_slots WHERE authorization_id = ? \
                                 ORDER BY slot_index",
                            )
                            .bind(id),
                        )
                        .await?;
                    let mut out = Vec::new();
                    for r in rows {
                        out.push(SlotRow {
                            slot_index: r.try_get("slot_index")?,
                            amount: r.try_get("amount")?,
                            status: r.try_get("status")?,
                            created_at: r.try_get("created_at")?,
                            filled_at: r.try_get("filled_at")?,
                        });
                    }
                    Ok::<Vec<SlotRow>, StreamGStoreError>(out)
                })
            })
            .await
            .expect("slot rows")
    }

    /// I6. Signs the two nested bearer payloads over the digests for
    /// `secondary` — but each with its OWN signer, so a test can hand the
    /// V1Enrollment or the LinkSecondary payload a signature from the
    /// WRONG key while every other input (including the digest that was
    /// signed, which is still built over the real `secondary`) is exactly
    /// what the happy path builds. That is what makes
    /// `quote_rejects_a_*_signature_from_the_wrong_key` about the
    /// signature check specifically, rather than about a malformed digest.
    #[allow(clippy::too_many_arguments)]
    fn sign_nested_bearers_as(
        manifest: &DeploymentManifest,
        root: [u8; 20],
        secondary: [u8; 20],
        v1_signer: &PrivateKeySigner,
        link_signer: &PrivateKeySigner,
        v1_nonce: u64,
        v1_deadline: u64,
        link_nonce: u64,
        link_deadline: u64,
    ) -> (String, String) {
        let v1_digest = sig_verify::enroll_digest(
            secondary,
            v1_nonce,
            v1_deadline,
            manifest.chain_id,
            manifest.enrollment_registry,
        );
        let v1_sig = v1_signer.sign_hash_sync(&B256::from(v1_digest)).unwrap();
        let v1_sig_hex = format!("0x{}", hex::encode(v1_sig.as_bytes()));

        let link = LinkSecondary {
            root,
            secondary,
            nonce: link_nonce,
            deadline: link_deadline,
        };
        let link_digest = link_secondary_digest(
            &link,
            manifest.chain_id,
            manifest.wallet_sponsorship_registry,
        );
        let link_sig = link_signer
            .sign_hash_sync(&B256::from(link_digest))
            .unwrap();
        let link_sig_hex = format!("0x{}", hex::encode(link_sig.as_bytes()));

        (v1_sig_hex, link_sig_hex)
    }

    /// Signs the two nested bearer payloads (V1Enrollment + LinkSecondary)
    /// with `secondary_signer`'s key, off the given nonces/deadlines — the
    /// happy-path case, i.e. both signers are the secondary itself.
    fn sign_nested_bearers(
        manifest: &DeploymentManifest,
        root: [u8; 20],
        secondary_signer: &PrivateKeySigner,
        v1_nonce: u64,
        v1_deadline: u64,
        link_nonce: u64,
        link_deadline: u64,
    ) -> (String, String) {
        sign_nested_bearers_as(
            manifest,
            root,
            secondary_signer.address().into_array(),
            secondary_signer,
            secondary_signer,
            v1_nonce,
            v1_deadline,
            link_nonce,
            link_deadline,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn base_request(
        root: [u8; 20],
        controller: [u8; 20],
        secondary: [u8; 20],
        idempotency_key: &str,
        v1_nonce: u64,
        v1_deadline: u64,
        v1_sig: &str,
        link_nonce: u64,
        link_deadline: u64,
        link_sig: &str,
        max_fee: u128,
    ) -> CreateSponsoredEnrollmentQuoteRequest {
        CreateSponsoredEnrollmentQuoteRequest {
            idempotency_key: idempotency_key.to_string(),
            // Derived from idempotency_key (not a fixed constant): a real
            // client mints a fresh intentId per logical intent, and reuses
            // it only when genuinely retrying the same one (same
            // idempotency_key) -- matching that here means distinct test
            // scenarios naturally get distinct intent ids, while a true
            // replay (same idempotency_key) naturally reuses the same one,
            // exactly like production traffic.
            intent_id_hex: format!(
                "0x{}",
                hex::encode(Sha256::digest(
                    format!("test-intent|{idempotency_key}").as_bytes()
                ))
            ),
            root_address: address_hex(root),
            controller_address: address_hex(controller),
            controller_epoch: 1,
            secondary_address: address_hex(secondary),
            // I1: `enroll_digest_hex` / `link_digest_hex` used to live here
            // and this fixture passed `0x0101…01` / `0x0202…02` — garbage
            // that went straight into the signed `actionCoreHash` with the
            // whole suite green. The fields no longer exist; the server
            // derives both, so the happy path now signs real digests by
            // construction.
            root_authorization_digest_hex: format!("0x{}", hex::encode([0u8; 32])),
            fee_authorization_mode: 1, // AuthorizationMode.EIP2612
            max_fee: max_fee.to_string(),
            nonce: 0,
            deadline: 9_999_999_999,
            valid_for_seconds: 300,
            v1_nonce,
            v1_deadline,
            v1_signature_hex: v1_sig.to_string(),
            link_nonce,
            link_deadline,
            link_signature_hex: link_sig.to_string(),
            gas_unit_ceiling: 500_000,
            max_fee_per_gas_wei: "1000000000".to_string(),
            unsigned_size_ceiling: 2_000,
        }
    }

    /// A `#[cfg(test)]` stand-in for what
    /// `token_manifest::read_live_token_state` would return for `token_cap`
    /// — observed code hash matching the config, chain id and queried
    /// address taken from the manifest. `token_manifest`'s own Wave B tests
    /// exercise the REAL constructor against `MockChain`; these tests use
    /// the hatch because their subject is the quote pipeline, not the read.
    fn live_token_reading(
        manifest: &DeploymentManifest,
        token_cap: &TokenCapability,
    ) -> LiveTokenReading {
        LiveTokenReading::for_test(
            token_cap.clone(),
            code_hash_fixture(),
            manifest.chain_id,
            manifest.fee_token,
        )
    }

    fn base_ctx<'a>(
        manifest: &'a DeploymentManifest,
        live_token: &'a LiveTokenReading,
        max_native_exposure_wei: u128,
    ) -> EnrollmentQuoteContext<'a> {
        EnrollmentQuoteContext {
            manifest,
            quote_signer_private_key_hex: QUOTE_SIGNER_PK,
            live_token,
            max_native_exposure_wei: WeiCeiling::new(max_native_exposure_wei),
            // R3: matches `live_token`'s hash by construction, so the new
            // anti-TOCTOU check passes for every test that does not
            // deliberately override `live_nonces` to test a mismatch.
            live_nonces: LiveEnrollmentNonces::for_test(0, 0, live_token.fee_token_config_hash()),
        }
    }

    /// A **real** schedule, parsed by the production loader, authored for
    /// `manifest`'s chain and fee token — parameterised only on `decimals` and
    /// the sponsored-enrollment tariff.
    ///
    /// Deliberately not [`FeeSchedule::for_test`]: that constructor hard-codes
    /// `payload_decimals: 6`, so a test built on it could not express the
    /// auditor's payload at all, and a mutation that made `payload_decimals()`
    /// return a constant would survive it. Going through
    /// [`FeeSchedule::from_json`] means the number under test travelled the
    /// same `canonical_decimal` path a deployed file's would.
    fn schedule_for_this_deployment(
        manifest: &DeploymentManifest,
        decimals: &str,
        sponsored_enrollment_fee_raw: &str,
    ) -> FeeSchedule {
        let payload = super::super::runtime::test_support::schedule_payload_json_for(
            &manifest.chain_id.to_string(),
            &format!("0x{}", hex::encode(manifest.fee_token)),
            decimals,
            Some(sponsored_enrollment_fee_raw),
        );
        let file = super::super::runtime::test_support::fee_schedule_json(
            &super::super::runtime::test_support::schedule_hash_hex(&payload),
            &payload,
        );
        FeeSchedule::from_json(&file, "<decimals-agreement-test>")
            .expect("the fixture payload is well-formed")
    }

    /// **The auditor's payload, on the right chain and the right token.**
    ///
    /// `chainId` = the manifest's, `feeToken` = the manifest's, so both
    /// startup agreement checks
    /// (`runtime::StreamGState::start`'s `FeeScheduleChainMismatch` /
    /// `FeeScheduleFeeTokenMismatch`) would pass and the digest is republished
    /// over this very payload — exactly the state that started cleanly and
    /// logged `fee_schedule_has_tariff=true`. The only disagreement left is
    /// `decimals "18"` against the registry's 6, and a `1000000` tariff
    /// authored in the wrong unit.
    ///
    /// # Which layer this tests, and why
    ///
    /// `create_sponsored_enrollment_quote_at` — the function that actually
    /// consumes the tariff (STEP 3) — **not** the `POST /v1/stream-g/quotes`
    /// route. A route test proves nothing here: `post_quote`'s first statement
    /// is `state.trusted_chain().ok_or_else(ApiError::no_live_chain)?`, and
    /// `StreamGState`'s chain is `Some(Arc<RpcChain>)` or `None` with no test
    /// seam, so under `GOAT_ATTESTOR_MOCK=1` every route-level request answers
    /// `NO_LIVE_CHAIN` before the schedule is consulted at all, and without
    /// mock mode there is no chain to talk to. This layer takes a `MockChain`
    /// and a `LiveTokenReading`, so the comparison is genuinely executed.
    ///
    /// # Mutation this detects
    ///
    /// Deleting the `assert_schedule_decimals_match_live_token` call at STEP
    /// 0: the quote then succeeds and the `unwrap_err()` below panics. Making
    /// the comparison narrow the payload to `u8` instead of widening the
    /// registry value is covered by the third arm.
    #[tokio::test]
    async fn a_schedule_decimals_claim_the_live_token_contradicts_is_refused_before_any_fee_is_used()
    {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        assert_eq!(
            token_cap.decimals, 6,
            "the registry side of this comparison must be the 6-decimal fee token, \
             or the test is not the auditor's scenario"
        );
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-decimals-mismatch").await;
        let profile = AuthenticatedProfileId::for_test("profile-decimals-mismatch");
        let schedule = schedule_for_this_deployment(&manifest, "18", "1000000");
        assert_eq!(schedule.payload_decimals(), 18);
        assert_eq!(
            schedule.payload_fee_token(),
            manifest.fee_token,
            "this payload must name THIS deployment's fee token, or the refusal \
             under test could be attributed to the wrong token instead"
        );
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-decimals-mismatch",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );

        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(
                err,
                QuoteError::FeeScheduleDecimalsMismatch {
                    payload_decimals: 18,
                    live_decimals: 6,
                }
            ),
            "expected a decimals disagreement naming both numbers, got: {err:?}"
        );
        assert_eq!(err.code(), ERR_FEE_SCHEDULE_DECIMALS_MISMATCH);
        assert_eq!(
            err.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "a mispriced schedule is this process's fault, not the caller's — and \
             deliberately not the 503 the tariff-absence arms use"
        );

        // Fail-closed: refused at STEP 0, so nothing was signed and nothing
        // was written. Without this the check could sit anywhere downstream
        // and still satisfy the assertions above.
        assert_eq!(quotes_count(&store).await, 0);
        assert_eq!(intents_count(&store).await, 0);
        assert_eq!(authorization_slots_count(&store).await, 0);
    }

    /// **The paired positive arm.** The same real payload, on the same chain
    /// and token, differing only in `decimals "6"` — which agrees with the
    /// registry — still produces a quote.
    ///
    /// Without this the refusal above is satisfiable by a blanket "no schedule
    /// from `from_json` may ever quote", which is the failure mode the
    /// startup-side chain/token checks were explicitly given positive arms to
    /// rule out (`runtime::tests::start_accepts_a_schedule_that_agrees_with_the_deployment`).
    ///
    /// **Mutation this detects:** making
    /// `assert_schedule_decimals_match_live_token` return
    /// `FeeScheduleDecimalsMismatch` unconditionally — this test fails while
    /// the one above still passes.
    #[tokio::test]
    async fn a_schedule_whose_decimals_agree_with_the_live_token_still_quotes() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-decimals-agree").await;
        let profile = AuthenticatedProfileId::for_test("profile-decimals-agree");
        let schedule = schedule_for_this_deployment(&manifest, "6", "1000000");
        assert_eq!(schedule.payload_decimals(), 6);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-decimals-agree",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );

        let quote = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .expect("an agreeing schedule must still quote");
        assert_eq!(
            quote.fee_amount, "1000000",
            "the agreeing tariff must be served verbatim"
        );
        assert_eq!(quotes_count(&store).await, 1);
    }

    /// A `decimals` past `u8::MAX` must **fail** the comparison, not wrap into
    /// agreement with it.
    ///
    /// `FeeTokenConfig.decimals` is a `uint8` on chain and a `u8` in
    /// [`token_manifest::TokenCapability`], while `payload.decimals` is
    /// whatever [`canonical_decimal`] parsed — a `u128`. `256` truncates to
    /// `0` and `262` truncates to `6`, so a comparison written as
    /// `payload as u8 == live` would accept `"262"` against a 6-decimal token.
    /// This is the same widening rule [`FeeSchedule::payload_chain_id`]'s doc
    /// states for `chainId`, asserted rather than assumed.
    ///
    /// Tested through [`assert_schedule_decimals_match_live_token`] directly
    /// rather than the full pipeline: the property is about the arithmetic of
    /// the comparison, and the pipeline arms above already prove the call site
    /// is reached.
    ///
    /// **Mutation this detects:** rewriting the comparison as
    /// `fee_schedule.payload_decimals() as u8 != live_decimals`.
    #[test]
    fn a_decimals_claim_past_u8_max_cannot_wrap_into_agreement() {
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);

        for wrapping in ["262", "518"] {
            let schedule = schedule_for_this_deployment(&manifest, wrapping, "1000000");
            let err = super::assert_schedule_decimals_match_live_token(&schedule, &live_token)
                .expect_err("a decimals claim that only agrees modulo 256 must be refused");
            assert!(
                matches!(
                    err,
                    QuoteError::FeeScheduleDecimalsMismatch {
                        live_decimals: 6,
                        ..
                    }
                ),
                "unexpected: {err:?}"
            );
        }

        // Paired non-zero arm: the helper is not simply refusing everything.
        let agreeing = schedule_for_this_deployment(&manifest, "6", "1000000");
        super::assert_schedule_decimals_match_live_token(&agreeing, &live_token)
            .expect("6 against a 6-decimal token must agree");
    }

    // -- 1. TDD-mandated first test: fixed tariff, not an oracle -----------

    #[tokio::test]
    async fn quote_uses_fixed_usdt_tariff_not_eth_usd_oracle() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-tariff").await;
        let profile = AuthenticatedProfileId::for_test("profile-tariff");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);

        // Low-oracle chain.
        let chain_low = MockChain::new();
        chain_low.set_l1_upper_fee_wei(1);
        chain_low.set_operator_fee_wei(1);
        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req1 = base_request(
            root,
            controller,
            secondary,
            "idem-tariff-1",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        let result1 = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain_low,
            &profile,
            &ctx,
            &schedule,
            req1,
        )
        .await
        .expect("low-oracle quote must succeed");

        // Wildly different (extreme) oracle chain, still within the u128::MAX exposure ceiling.
        let chain_high = MockChain::new();
        chain_high.set_l1_upper_fee_wei(50_000_000_000_000_000_000);
        chain_high.set_operator_fee_wei(50_000_000_000_000_000_000);
        let (v1_sig2, link_sig2) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req2 = base_request(
            root,
            controller,
            secondary,
            "idem-tariff-2",
            0,
            9_999_999_999,
            &v1_sig2,
            0,
            9_999_999_999,
            &link_sig2,
            1_000_000,
        );
        let result2 = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain_high,
            &profile,
            &ctx,
            &schedule,
            req2,
        )
        .await
        .expect("high-oracle quote must also succeed (still under the exposure ceiling)");

        assert_eq!(result1.fee_amount, "500000");
        assert_eq!(
            result2.fee_amount, "500000",
            "feeAmount must not scale with gas-oracle values -- fixed USDT tariff, not an ETH/USD oracle"
        );

        // No exotic calls beyond the expected exposure-gate oracle reads --
        // proves nothing resembling a price-feed call happened either.
        for op in chain_high.ops() {
            assert!(
                matches!(
                    op,
                    crate::chain::MockOp::L1FeeUpperBound { .. }
                        | crate::chain::MockOp::OperatorFee { .. }
                ),
                "unexpected chain op while quoting a fixed-tariff fee: {op:?}"
            );
        }
    }

    // -- 2. L1 DA spike rejected; broadcast/send path never invoked --------

    #[tokio::test]
    async fn quote_rejects_on_l1_da_spike() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-spike").await;
        let profile = AuthenticatedProfileId::for_test("profile-spike");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        // Tight 1-ETH exposure ceiling.
        let ctx = base_ctx(&manifest, &live_token, 1_000_000_000_000_000_000);

        let chain = MockChain::new();
        chain.set_l1_upper_fee_wei(10_000_000_000_000_000_000); // 10 ETH -- dwarfs the ceiling
        chain.set_operator_fee_wei(1_000_000_000_000);

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-spike-1",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );

        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), base_fee::ERR_EXPOSURE_EXCEEDS_SCHEDULE);
        assert!(
            chain.sent_native().is_empty(),
            "a rejected quote must never reach a broadcast/send path"
        );
        assert_eq!(
            quotes_count(&store).await,
            0,
            "rejected quote must not be persisted"
        );
    }

    // -- 3. nested bearer nonces from snapshot ------------------------------

    #[tokio::test]
    async fn enrollment_quote_verifies_nested_bearer_nonces_from_snapshot() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-nonce-ok").await;
        let profile = AuthenticatedProfileId::for_test("profile-nonce-ok");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);

        let mut ctx = base_ctx(&manifest, &live_token, u128::MAX);
        ctx.live_nonces = LiveEnrollmentNonces::for_test(3, 5, live_token.fee_token_config_hash());
        let chain = MockChain::new();
        chain.set_l1_upper_fee_wei(1);
        chain.set_operator_fee_wei(1);

        // Nonces embedded in the bearer signatures match the fresh snapshot.
        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            3,
            9_999_999_999,
            5,
            9_999_999_999,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-nonce-ok",
            3,
            9_999_999_999,
            &v1_sig,
            5,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );

        let result = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .expect("matching nonces + valid signatures must succeed");
        assert_eq!(result.fee_amount, "500000");
    }

    #[tokio::test]
    async fn enrollment_quote_rejects_stale_or_mixed_nested_bearer_nonces() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-nonce-stale").await;
        let profile = AuthenticatedProfileId::for_test("profile-nonce-stale");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);

        let mut ctx = base_ctx(&manifest, &live_token, u128::MAX);
        // Fresh snapshot has ADVANCED past what the bearer signatures below
        // were signed against.
        ctx.live_nonces = LiveEnrollmentNonces::for_test(4, 5, live_token.fee_token_config_hash());
        let chain = MockChain::new();

        // Signed against v1_nonce=3 (stale -- live snapshot says 4), and a
        // link_nonce that matches (5) -- i.e. genuinely MIXED: one field
        // fresh, one stale.
        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            3,
            9_999_999_999,
            5,
            9_999_999_999,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-nonce-stale",
            3,
            9_999_999_999,
            &v1_sig,
            5,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );

        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), ERR_STALE_OR_MIXED_NONCE);
        assert!(matches!(err, QuoteError::StaleOrMixedNonce));
        // Fails before ever touching the exposure gate.
        assert_eq!(chain.l1_fee_upper_bound_call_count(), 0);
        assert_eq!(quotes_count(&store).await, 0);
    }

    // -- 4. FeeQuote EIP-712 pins -------------------------------------------

    #[test]
    fn fee_quote_typehash_matches_streamg_types_sol() {
        // Independently re-verified via `cast keccak` against
        // `contracts/src/StreamGTypes.sol:38-40` -- see task report.
        assert_eq!(
            super::super::models::FEE_QUOTE_TYPEHASH_STR,
            "FeeQuote(bytes32 quoteId,bytes32 actionType,bytes32 actionCoreHash,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,bytes32 feeScheduleHash,address payer,address feeToken,uint256 feeAmount,address feeRecipient,uint48 validAfter,uint48 validUntil)"
        );
        assert_eq!(
            hex::encode(crate::merkle::keccak256(
                super::super::models::FEE_QUOTE_TYPEHASH_STR.as_bytes()
            )),
            "eaeb044887c8cf8cd0fa7dcbfa981c25dd31ffebc55f4eca160b680c34ff4169",
            "typehash bytes drifted from the pinned literal (cast keccak cross-check)"
        );
    }

    /// I4. Fixed-input digest regression, **pinned to literals derived
    /// independently of this Rust** with `cast keccak` / `cast abi-encode`
    /// against `contracts/src/StreamGTypes.sol:38-40` and
    /// `GoatRelayGateway.sol:138` (`EIP712("GoatRelayGateway", "1")`) and
    /// `:1170-1188` (`_feeQuoteStructHash`'s field order). The pin
    /// therefore proves **cross-language equivalence**, not merely
    /// self-consistency.
    ///
    /// This test previously claimed in its own doc comment that "field
    /// order [and] word-packing must change this output" and to take the
    /// "same posture `root_authorization.rs`'s
    /// `root_authorization_digest_regression_fixed_inputs`" takes. Both
    /// were false: **no pin existed**. Its four assertions (non-zero,
    /// deterministic, varies with chainId, varies with verifyingContract)
    /// are every one of them invariant under an arbitrary permutation of
    /// the twelve `buf.extend_from_slice` lines in
    /// `models::fee_quote_struct_hash`.
    ///
    /// **Mutations these three pins detect** (none of which the old
    /// assertions could see):
    /// - swapping `payer` and `fee_token` (the two adjacent `address_word`
    ///   lines in `models::fee_quote_struct_hash`), or moving
    ///   `fee_recipient` before `fee_amount`, or any other field
    ///   permutation → STRUCT_HASH pin fails (the payer/feeToken swap was
    ///   checked with `cast`: it yields `0x5e40d3ba…`, not the pin);
    /// - `u256_be` → a differently-padded word for `fee_amount`,
    ///   `valid_after` or `valid_until` → STRUCT_HASH pin fails;
    /// - editing `FEE_QUOTE_TYPEHASH_STR` → STRUCT_HASH pin fails;
    /// - changing `FEE_QUOTE_DOMAIN_NAME`/`_VERSION`, or the
    ///   `EIP712Domain` typehash string, or the order of the five domain
    ///   words → DOMAIN pin fails;
    /// - dropping the `\x19\x01` prefix or transposing domain and struct
    ///   hash in `eip712_digest` → DIGEST pin fails while the other two
    ///   still hold.
    ///
    /// The three are pinned separately on purpose: a single digest pin
    /// tells you something drifted, these tell you *which layer*.
    #[test]
    fn fee_quote_digest_regression_fixed_inputs() {
        use super::super::models::{fee_quote_domain_separator, fee_quote_struct_hash};

        let q = FeeQuote {
            quote_id: [0x01u8; 32],
            action_type: [0x02u8; 32],
            action_core_hash: [0x03u8; 32],
            deployment_manifest_hash: [0x04u8; 32],
            fee_token_config_hash: [0x05u8; 32],
            fee_schedule_hash: [0x06u8; 32],
            payer: [0x07u8; 20],
            fee_token: [0x08u8; 20],
            fee_amount: 500_000,
            fee_recipient: [0x09u8; 20],
            valid_after: 2_000_000_000,
            valid_until: 2_000_000_300,
        };

        // cast keccak $(cast abi-encode "f(bytes32,bytes32,bytes32,uint256,address)" \
        //   $(cast keccak "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)") \
        //   $(cast keccak "GoatRelayGateway") $(cast keccak "1") 31337 0x1010…10)
        assert_eq!(
            hex::encode(fee_quote_domain_separator(31337, [0x10u8; 20])),
            "5c9e2040dd5b30c28be6d5a4742785cf7a77e870d7ef411104dfe3aecd0eca60",
            "FeeQuote domain separator drift: name, version, EIP712Domain typehash or word order changed"
        );

        // cast keccak $(cast abi-encode "f(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,address,address,uint256,address,uint48,uint48)" \
        //   $FEE_QUOTE_TYPEHASH 0x01…01 0x02…02 0x03…03 0x04…04 0x05…05 0x06…06 \
        //   0x07…07 0x08…08 500000 0x09…09 2000000000 2000000300)
        assert_eq!(
            hex::encode(fee_quote_struct_hash(&q)),
            "6cd18e6e3d505795b3c1f47735731eb67c0c8ce72a8dc1a4dcfd286580c2c9c4",
            "FeeQuote struct hash drift: typehash string, FIELD ORDER or word packing changed"
        );

        // keccak256(0x1901 || domainSeparator || structHash)
        let digest = fee_quote_digest(&q, 31337, [0x10u8; 20]);
        assert_eq!(
            hex::encode(digest),
            "0ddf83131e514d4868ed12dc965bffa737c12504e949ae525cb5b8964ce28d4f",
            "FeeQuote digest drift: domain, typehash, field order or word packing changed"
        );

        // Retained from the original test: cheap, and they localize a
        // domain-separation regression to the domain rather than the struct.
        assert_ne!(
            digest,
            fee_quote_digest(&q, 1, [0x10u8; 20]),
            "digest must depend on chain_id (domain separation)"
        );
        assert_ne!(
            digest,
            fee_quote_digest(&q, 31337, [0x11u8; 20]),
            "digest must depend on verifying_contract (domain separation)"
        );
    }

    /// I4, second half. `sponsor_enrollment_core_hash` is the
    /// `actionCoreHash` — the value that binds a signed quote to the intent
    /// it will execute against — and it had **no pinned-output test at
    /// all**, only relative comparisons.
    ///
    /// Pin derived independently of this Rust with
    /// `cast keccak $(cast abi-encode …)` against
    /// `StreamGTypes.sol`'s `SPONSOR_ENROLLMENT_CORE_TYPEHASH` and
    /// `GoatRelayGateway._validateAndConsumeQuote`'s inline `abi.encode`
    /// field order.
    ///
    /// **Mutations this detects:** any permutation of the fifteen fields in
    /// `models::sponsor_enrollment_core_hash` — notably the
    /// three adjacent `bytes32` digests `enrollDigest` / `linkDigest` /
    /// `rootAuthorizationDigest`, which are indistinguishable to every
    /// other test in this file; and any edit to
    /// `SPONSOR_ENROLLMENT_CORE_TYPEHASH_STR`. Swapping `enrollDigest` and
    /// `linkDigest` was checked with `cast`: it yields
    /// `0x4fe2ac88…`, not the pin.
    ///
    /// **What it does NOT detect, stated so nobody assumes otherwise:**
    /// `u256_be_u8(mode)` → `u256_be(mode as u128)` produces a
    /// byte-identical right-aligned word, so that particular swap is
    /// invisible here (and on-chain, correctly so — `abi.encode` pads a
    /// `uint8` the same way).
    ///
    /// Every field value below is distinct, so no permutation of two
    /// same-typed neighbours can preserve the hash.
    #[test]
    fn sponsor_enrollment_core_hash_regression_fixed_inputs() {
        let fixed_core = SponsorEnrollmentCore {
            intent_id: [0x11u8; 32],
            deployment_manifest_hash: [0x12u8; 32],
            fee_token_config_hash: [0x13u8; 32],
            root: [0x14u8; 20],
            controller: [0x15u8; 20],
            controller_epoch: 7,
            secondary: [0x16u8; 20],
            enroll_digest: [0x17u8; 32],
            link_digest: [0x18u8; 32],
            root_authorization_digest: [0u8; 32],
            fee_token: [0x19u8; 20],
            fee_authorization_mode: AUTHORIZATION_MODE_EIP2612,
            max_fee: 1_000_000,
            nonce: 42,
            deadline: 2_000_000_300,
        };
        assert_eq!(
            hex::encode(sponsor_enrollment_core_hash(&fixed_core)),
            "ff3179f8d478f9a2401a324dc583710d95c2d7854f3ca272a6d0659294fe3cc9",
            "actionCoreHash drift: SponsorEnrollmentCore typehash, FIELD ORDER or word \
             packing changed -- every quote this module signs would bind to a different intent"
        );
    }

    #[test]
    fn fee_quote_domain_is_not_root_authorization_domain() {
        use super::super::models::{
            eip712_domain_separator, fee_quote_domain_separator, FEE_QUOTE_DOMAIN_NAME,
            WALLET_SPONSORSHIP_DOMAIN_NAME,
        };
        assert_eq!(FEE_QUOTE_DOMAIN_NAME, "GoatRelayGateway");
        assert_ne!(FEE_QUOTE_DOMAIN_NAME, "GoatWalletSponsorship");

        let gateway_domain = fee_quote_domain_separator(31337, [0x11u8; 20]);
        let wallet_domain =
            eip712_domain_separator(WALLET_SPONSORSHIP_DOMAIN_NAME, "1", 31337, [0x11u8; 20]);
        assert_ne!(
            gateway_domain, wallet_domain,
            "FeeQuote's domain must differ from RootAuthorization/LinkSecondary's domain \
             even for the same chain_id + verifying_contract"
        );
    }

    // -- 5. Action-type constants pinned ------------------------------------

    #[test]
    fn action_type_constants_pinned() {
        // Every string AND digest independently re-verified via
        // `cast keccak "<literal>"` (Foundry) -- see task report.
        assert_eq!(
            super::super::models::ACTION_SPONSORED_ENROLLMENT_STR,
            "GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1"
        );
        assert_eq!(
            hex::encode(ActionType::SponsoredEnrollment.digest()),
            "bcd123c051cd9b628e040adc5b6509f0a172883d597875aa799b30bfe9a82807"
        );

        assert_eq!(
            super::super::models::ACTION_SPONSORED_SELL_STR,
            "GOAT_STREAM_G_SPONSORED_SELL_V1"
        );
        assert_eq!(
            hex::encode(ActionType::SponsoredSell.digest()),
            "6f7ac0f006de89edaf4192214c6c936d6ef4dbce7578cdf6170e940951f7c70b"
        );

        assert_eq!(
            super::super::models::ACTION_GOAT_TRANSFER_STR,
            "GOAT_STREAM_G_GOAT_TRANSFER_V1"
        );
        assert_eq!(
            hex::encode(ActionType::GoatTransfer.digest()),
            "e9498be71efc42260a15d9f04ea164355b48ecaa45b528ed16bfd858e815486a"
        );

        assert_eq!(
            super::super::models::ACTION_USDT_TRANSFER_STR,
            "GOAT_STREAM_G_USDT_TRANSFER_V1"
        );
        assert_eq!(
            hex::encode(ActionType::UsdtTransfer.digest()),
            "7155e5f8a6c539fe86bb0eda9c0f21ddd9b9a9e2e658b504814f6c38c50f19e8"
        );
    }

    #[test]
    fn action_core_typehash_strings_pinned() {
        // Independently re-verified via `cast keccak` -- see task report.
        // Only SponsorEnrollmentCore has a struct-hash function
        // implemented (see models.rs module doc); the other three strings
        // are pinned for whichever later task implements them.
        assert_eq!(
            hex::encode(crate::merkle::keccak256(
                super::super::models::SPONSOR_ENROLLMENT_CORE_TYPEHASH_STR.as_bytes()
            )),
            "1eed3561f8deb1be9863b6ba6959db364a4910bd36991fb749cb4ae27e1246f4"
        );
        assert_eq!(
            hex::encode(crate::merkle::keccak256(
                super::super::models::SELL_CORE_TYPEHASH_STR.as_bytes()
            )),
            "dd499adc08234f245bc49190ddc05db708d00416618804888f6008474053c48b"
        );
        assert_eq!(
            hex::encode(crate::merkle::keccak256(
                super::super::models::GOAT_TRANSFER_CORE_TYPEHASH_STR.as_bytes()
            )),
            "687407d21675516e0ebc0717744f90b6aa94822f44742e4280f2ed74c224ac1b"
        );
        assert_eq!(
            hex::encode(crate::merkle::keccak256(
                super::super::models::USDT_TRANSFER_CORE_TYPEHASH_STR.as_bytes()
            )),
            "9a45be4c9d4ac5de4d9d01bbe3c29264314a25e96648a9d9589e1c03f62e601f"
        );
        assert_eq!(
            hex::encode(crate::merkle::keccak256(
                super::super::models::LINK_SECONDARY_TYPEHASH_STR.as_bytes()
            )),
            "d13c2b44c281e3e64f71fefdd22c0981a18181362d0596732c5432c20c0c275b"
        );
    }

    // -- 6. Gateway precondition rejections ---------------------------------

    #[tokio::test]
    async fn quote_rejects_zero_fee_amount_from_schedule() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-zero-fee").await;
        let profile = AuthenticatedProfileId::for_test("profile-zero-fee");
        // Schedule configured with a ZERO tariff.
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 0)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-zero-fee",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );

        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), ERR_ZERO_FEE_AMOUNT);
    }

    #[tokio::test]
    async fn quote_rejects_fee_amount_exceeding_max_fee() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-max-fee").await;
        let profile = AuthenticatedProfileId::for_test("profile-max-fee");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        // maxFee (100) is far below the fixed tariff (500_000).
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-max-fee",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            100,
        );

        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), ERR_FEE_EXCEEDS_MAX);
        assert!(matches!(
            err,
            QuoteError::FeeExceedsMax {
                fee_amount: 500_000,
                max_fee: 100
            }
        ));
    }

    #[tokio::test]
    async fn quote_rejects_valid_for_seconds_exceeding_ttl_policy() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-ttl").await;
        let profile = AuthenticatedProfileId::for_test("profile-ttl");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let mut req = base_request(
            root,
            controller,
            secondary,
            "idem-ttl",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        req.valid_for_seconds = QUOTE_TTL_SECONDS_MAX + 1;

        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), ERR_VALIDITY_EXCEEDS_POLICY);
    }

    #[tokio::test]
    async fn successful_quote_has_valid_after_le_now_lt_valid_until_and_fee_recipient_from_manifest(
    ) {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-window").await;
        let profile = AuthenticatedProfileId::for_test("profile-window");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-window",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );

        // I2: the reference clock is the CHAIN's, not the host's — this
        // used to read `now_unix_seconds()` on both sides, which made the
        // test structurally incapable of noticing that `valid_after` was a
        // wall-clock value being compared on-chain to `block.timestamp`.
        let chain_before = chain.block_timestamp().unwrap();
        let result = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .unwrap();
        let chain_after = chain.block_timestamp().unwrap();

        assert!(result.valid_after >= chain_before && result.valid_after <= chain_after);
        assert!(chain_after < result.valid_until);
        assert_eq!(
            result.fee_recipient,
            address_hex(manifest.fee_safe),
            "feeRecipient must come from the manifest's feeSafe, never a request field \
             (CreateSponsoredEnrollmentQuoteRequest has no such field at all)"
        );
    }

    /// A complete, VALID request body, plus whatever `extra` appends (a
    /// leading `,` and one more key).
    ///
    /// NOTE the field names are snake_case:
    /// `CreateSponsoredEnrollmentQuoteRequest` carries no
    /// `#[serde(rename_all = "camelCase")]`. This body used to be written
    /// camelCase, which made every "unknown field is rejected" assertion
    /// below vacuous — serde failed on the FIRST key (`idempotencyKey`) and
    /// never reached the field actually under test. The `control` assertion
    /// in each test is what keeps that from silently recurring.
    fn request_json_body(extra: &str) -> String {
        format!(
            r#"{{
                "idempotency_key": "x",
                "intent_id_hex": "0x00",
                "root_address": "0x00",
                "controller_address": "0x00",
                "controller_epoch": 0,
                "secondary_address": "0x00",
                "root_authorization_digest_hex": "0x00",
                "fee_authorization_mode": 1,
                "max_fee": "1",
                "nonce": 0,
                "deadline": 0,
                "valid_for_seconds": 1,
                "v1_nonce": 0,
                "v1_deadline": 0,
                "v1_signature_hex": "0x00",
                "link_nonce": 0,
                "link_deadline": 0,
                "link_signature_hex": "0x00",
                "gas_unit_ceiling": 1,
                "max_fee_per_gas_wei": "1",
                "unsigned_size_ceiling": 1{extra}
            }}"#
        )
    }

    #[test]
    fn create_request_rejects_unknown_fields_including_a_fee_recipient_override_attempt() {
        // Structural proof that a caller cannot even ATTEMPT to name
        // feeRecipient: deny_unknown_fields rejects the extra key outright.
        let control: Result<CreateSponsoredEnrollmentQuoteRequest, _> =
            serde_json::from_str(&request_json_body(""));
        assert!(
            control.is_ok(),
            "control: the same body WITHOUT feeRecipient must parse, otherwise the \
             rejection below proves nothing -- {control:?}"
        );

        let result: Result<CreateSponsoredEnrollmentQuoteRequest, _> =
            serde_json::from_str(&request_json_body(r#", "fee_recipient": "0xattacker""#));
        let err = result.expect_err(
            "an unknown fee_recipient field must be rejected, not silently accepted or ignored",
        );
        // M4: the error must name the field actually under test. Without
        // this, the assertion passes for ANY parse failure — which is
        // exactly how the previous camelCase version of this fixture stayed
        // green while failing on `idempotencyKey` and never reaching
        // `feeRecipient` at all. Mutation detected: deleting
        // `#[serde(deny_unknown_fields)]` from
        // `CreateSponsoredEnrollmentQuoteRequest` (the extra key would then
        // be ignored and `result` would be `Ok`), and, separately, any
        // re-casing of the struct that makes serde fail on an earlier key.
        let msg = err.to_string();
        assert!(
            msg.contains("fee_recipient"),
            "the rejection must be ABOUT fee_recipient, not about some earlier key: {msg}"
        );
    }

    /// I1, structural half. `enrollDigest` and `linkDigest` are re-derived
    /// by `GoatRelayGateway.sol:355-363`, which reverts
    /// `InvalidV1Enrollment` / `BadLinkSignature` on any disagreement — so
    /// the request type simply has no field for either, the same move
    /// `feeRecipient` uses. This is the rejection test for those two
    /// conditions: a caller cannot supply a digest at all, therefore cannot
    /// supply one that disagrees.
    ///
    /// Non-tautological: the same JSON *without* the extra keys must
    /// deserialize successfully, so this cannot be satisfied by a body that
    /// is simply malformed.
    #[test]
    fn a_caller_cannot_supply_enroll_or_link_digests_at_all() {
        let control: Result<CreateSponsoredEnrollmentQuoteRequest, _> =
            serde_json::from_str(&request_json_body(""));
        assert!(
            control.is_ok(),
            "control: the same body without the digest keys must parse -- {control:?}"
        );

        for (extra, field) in [
            (
                r#", "enroll_digest_hex": "0x0101010101010101010101010101010101010101010101010101010101010101""#,
                "enroll_digest_hex",
            ),
            (
                r#", "link_digest_hex": "0x0202020202020202020202020202020202020202020202020202020202020202""#,
                "link_digest_hex",
            ),
        ] {
            let result: Result<CreateSponsoredEnrollmentQuoteRequest, _> =
                serde_json::from_str(&request_json_body(extra));
            let err = result.expect_err(&format!(
                "a caller must not be able to name a nested-bearer digest: {extra}"
            ));
            // Same M4 lesson as the sibling test: assert the rejection is
            // ABOUT this key, so a body that merely fails to parse for some
            // unrelated reason cannot satisfy it.
            let msg = err.to_string();
            assert!(
                msg.contains(field),
                "the rejection must name {field}, got: {msg}"
            );
        }
    }

    // -- 6b. Wave B: LiveEnrollmentNonces presentMask fail-closed ----------

    /// A snapshot with every relevant bit set, for mutation below.
    fn full_snapshot() -> crate::chain::NonceSnapshotView {
        crate::chain::NonceSnapshotView {
            block_number: 4242,
            action_nonce: 1,
            v1_enroll_nonce: 3,
            link_nonce: 5,
            root_registration_nonce: 0,
            rotation_nonce: 0,
            controller_epoch: 1,
            controller: [0x34; 20],
            goat_permit_nonce: 0,
            fee_token_permit_nonce: 7,
            present_mask: crate::chain::SNAP_V1_ENROLL_NONCE
                | crate::chain::SNAP_LINK_NONCE
                | crate::chain::SNAP_FEE_TOKEN_PERMIT_NONCE
                | crate::chain::SNAP_CONFIG_HASHES,
            deployment_manifest_hash: [0xAA; 32],
            fee_token_config_hash: [0xC0; 32],
            fee_schedule_hash: [0xBB; 32],
        }
    }

    /// Sourcing contract §3 R3: a cleared `presentMask` bit means the field
    /// was never populated, so the zero sitting in it is meaningless and
    /// must not be read. Each case below clears exactly one bit and leaves
    /// the field VALUES untouched — so nothing but the mask distinguishes a
    /// pass from a failure, which is what makes this non-tautological.
    #[test]
    fn live_enrollment_nonces_fail_closed_on_cleared_present_mask_bit() {
        use crate::stream_g::models::{LiveNoncesError, ERR_SNAPSHOT_FIELD_NOT_PRESENT};

        // Control: the untouched snapshot constructs fine.
        let ok = LiveEnrollmentNonces::from_snapshot(&full_snapshot())
            .expect("all required bits set must construct");
        assert_eq!(ok.v1_enroll_nonce(), 3);
        assert_eq!(ok.link_nonce(), 5);
        assert_eq!(ok.block_number(), 4242);
        assert_eq!(ok.fee_token_config_hash(), [0xC0; 32]);

        for (bit, field) in [
            (crate::chain::SNAP_V1_ENROLL_NONCE, "v1EnrollNonce"),
            (crate::chain::SNAP_LINK_NONCE, "linkNonce"),
            (
                crate::chain::SNAP_CONFIG_HASHES,
                "feeTokenConfigHash/manifest hashes",
            ),
        ] {
            let mut snap = full_snapshot();
            snap.present_mask &= !bit;
            let err = LiveEnrollmentNonces::from_snapshot(&snap).unwrap_err();
            assert_eq!(
                err.code(),
                ERR_SNAPSHOT_FIELD_NOT_PRESENT,
                "clearing {field} ({bit:#x}) must fail closed, got {err:?}"
            );
            assert!(matches!(
                err,
                LiveNoncesError::FieldNotPresent { field: f, .. } if f == field
            ));
        }
    }

    /// A cleared `SNAP_FEE_TOKEN_PERMIT_NONCE` is not an ordinary missing
    /// field: `GoatRelayGateway._snapshot` skips that bit precisely when the
    /// fee token is unauthorized for `CAP_EIP2612`. It is an independent
    /// on-chain second opinion on hazard 3 and collapses to the same public
    /// code as the token gate's own failures.
    #[test]
    fn live_enrollment_nonces_fail_closed_when_gateway_says_fee_token_unauthorized() {
        use crate::stream_g::models::LiveNoncesError;

        let mut snap = full_snapshot();
        snap.present_mask &= !crate::chain::SNAP_FEE_TOKEN_PERMIT_NONCE;
        let err = LiveEnrollmentNonces::from_snapshot(&snap).unwrap_err();
        assert_eq!(err.code(), token_manifest::ERR_TOKEN_UNSUPPORTED);
        assert!(matches!(
            err,
            LiveNoncesError::FeeTokenUnauthorizedBySnapshot { .. }
        ));
    }

    /// `uint256` on-chain, `u64` here — reject, never truncate.
    #[test]
    fn live_enrollment_nonces_reject_nonces_that_do_not_fit_u64() {
        use crate::stream_g::models::{LiveNoncesError, ERR_SNAPSHOT_NONCE_OUT_OF_RANGE};

        let mut snap = full_snapshot();
        snap.v1_enroll_nonce = u128::from(u64::MAX) + 1;
        let err = LiveEnrollmentNonces::from_snapshot(&snap).unwrap_err();
        assert_eq!(err.code(), ERR_SNAPSHOT_NONCE_OUT_OF_RANGE);
        assert!(matches!(err, LiveNoncesError::NonceOutOfRange { .. }));
    }

    // -- 7. Unsupported token: typed rejection + zero further calls --------

    #[tokio::test]
    async fn unsupported_token_quote_is_rejected_before_exposure_gate_or_signing() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let mut token_cap = authorized_token_capability(&manifest);
        token_cap.active = false; // never-configured / deactivated -- see token_manifest module doc
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-unsupported").await;
        let profile = AuthenticatedProfileId::for_test("profile-unsupported");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-unsupported",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );

        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), token_manifest::ERR_TOKEN_UNSUPPORTED);

        // Non-tautological: the exposure gate is the only external
        // "resource" a valid quote would go on to consult. If the
        // token-authorization check were ever moved AFTER the exposure
        // gate, these counts would go from 0 to non-zero and this
        // assertion would fail.
        assert_eq!(chain.l1_fee_upper_bound_call_count(), 0);
        assert_eq!(chain.operator_fee_call_count(), 0);
        assert!(chain.ops().is_empty());
        assert_eq!(quotes_count(&store).await, 0);
        assert_eq!(intents_count(&store).await, 0);
    }

    /// **Hazard 3, obligation 3 (`att-t6a-findings.md` §8(b), brief §4.3):
    /// ordering, proven *discriminatingly*.**
    ///
    /// The sibling test above asserts only the zero half. A bare
    /// zero-assertion cannot tell "the gate rejected before the oracle was
    /// consulted" apart from "nothing in this function ever consults an
    /// oracle" — delete `base_fee::quote_exposure` from
    /// `create_sponsored_enrollment_quote_at` entirely and every one of those
    /// `== 0` assertions still passes. That is the shape of deleted defect
    /// I7 and it is why this test runs **both** arms, against the same
    /// request, the same fee schedule and the same manifest, differing in
    /// exactly one bit: `token_cap.active`.
    ///
    /// Counters are read off the `MockChain` instance production code
    /// actually receives (the third argument), never off a test-local
    /// stand-in.
    ///
    /// Mutations this detects, each verified to fail before this test was
    /// considered done:
    ///
    /// 1. **Delete the STEP 0 `assert_token_authorized` call** (or move it
    ///    below STEP 2): the unauthorized arm then reaches the exposure gate,
    ///    so `operator_fee_call_count()` becomes 1, not 0, and rows are
    ///    written. Caught by the `unauthorized` assertions.
    /// 2. **Delete the STEP 2 `base_fee::quote_exposure` call**: the
    ///    authorized arm's oracle counts drop to 0, so the `> 0` assertions
    ///    fail. Caught by the `authorized` assertions — this is the arm the
    ///    zero-only version of this test structurally could not have.
    #[tokio::test]
    async fn token_gate_ordering_is_discriminating_not_a_zero_versus_zero_assertion() {
        let manifest = manifest_fixture();
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );

        // --- Arm A: authorized token. -----------------------------------
        let (_dir_ok, store_ok) = open_store().await;
        seed_profile(&store_ok, "profile-discriminating").await;
        let profile_ok = AuthenticatedProfileId::for_test("profile-discriminating");
        let authorized_cap = authorized_token_capability(&manifest);
        let live_token_ok = live_token_reading(&manifest, &authorized_cap);
        let ctx_ok = base_ctx(&manifest, &live_token_ok, u128::MAX);
        let chain_ok = MockChain::new();
        chain_ok.set_l1_upper_fee_wei(1);
        chain_ok.set_operator_fee_wei(1);

        create_sponsored_enrollment_quote(
            &store_ok,
            &data_key_hex(),
            &chain_ok,
            &profile_ok,
            &ctx_ok,
            &schedule,
            base_request(
                root,
                controller,
                secondary,
                "idem-discriminating",
                0,
                9_999_999_999,
                &v1_sig,
                0,
                9_999_999_999,
                &link_sig,
                1_000_000,
            ),
        )
        .await
        .expect("the authorized arm must produce a quote");

        // The oracle IS consulted, and rows ARE written, when the gate
        // passes. Without this arm the zero-assertions below prove nothing.
        assert_eq!(
            chain_ok.l1_fee_upper_bound_call_count(),
            1,
            "the exposure gate must actually consult the L1-fee oracle on the happy path"
        );
        assert_eq!(
            chain_ok.operator_fee_call_count(),
            1,
            "the exposure gate must actually consult the operator-fee oracle on the happy path"
        );
        assert_eq!(quotes_count(&store_ok).await, 1);
        assert_eq!(intents_count(&store_ok).await, 1);

        // --- Arm B: the SAME everything, with `active = false`. ---------
        let (_dir_bad, store_bad) = open_store().await;
        seed_profile(&store_bad, "profile-discriminating").await;
        let profile_bad = AuthenticatedProfileId::for_test("profile-discriminating");
        let mut unauthorized_cap = authorized_token_capability(&manifest);
        unauthorized_cap.active = false;
        let live_token_bad = live_token_reading(&manifest, &unauthorized_cap);
        let ctx_bad = base_ctx(&manifest, &live_token_bad, u128::MAX);
        let chain_bad = MockChain::new();
        chain_bad.set_l1_upper_fee_wei(1);
        chain_bad.set_operator_fee_wei(1);

        let err = create_sponsored_enrollment_quote(
            &store_bad,
            &data_key_hex(),
            &chain_bad,
            &profile_bad,
            &ctx_bad,
            &schedule,
            base_request(
                root,
                controller,
                secondary,
                "idem-discriminating",
                0,
                9_999_999_999,
                &v1_sig,
                0,
                9_999_999_999,
                &link_sig,
                1_000_000,
            ),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), token_manifest::ERR_TOKEN_UNSUPPORTED);
        assert!(matches!(err, QuoteError::TokenUnauthorized(_)));
        assert_eq!(
            chain_bad.l1_fee_upper_bound_call_count(),
            0,
            "an unauthorized token must be rejected BEFORE the exposure gate's oracle reads"
        );
        assert_eq!(chain_bad.operator_fee_call_count(), 0);
        assert!(
            chain_bad.ops().is_empty(),
            "no chain op of any kind may be recorded for an unauthorized token"
        );
        assert_eq!(
            quotes_count(&store_bad).await,
            0,
            "no quote row may be persisted for an unauthorized token"
        );
        assert_eq!(intents_count(&store_bad).await, 0);
        assert_eq!(authorization_slots_count(&store_bad).await, 0);
    }

    /// M9: the module doc claims the token gate is the "very first
    /// operation". `DataKey::from_hex(data_key_hex)` used to run before it,
    /// which made that claim false.
    ///
    /// **Task 11 Wave 0 weakened this test, deliberately, and here is
    /// exactly how.** It used to pass a malformed key (`"deadbeef"`) together
    /// with an unauthorized token and assert the caller saw
    /// `TOKEN_UNSUPPORTED` rather than `QuoteError::Crypto` — a genuine
    /// two-outcome discriminator between "gate first" and "parse first".
    /// That input is now **unrepresentable**: the parameter is `&SecretHex`,
    /// and `SecretHex::from_hex("deadbeef")` fails at construction, so no
    /// malformed key can reach this function from anywhere. The first
    /// assertion below pins that at its new home.
    ///
    /// What remains of the ordering claim is therefore weaker than what this
    /// test used to assert: with a well-formed key there is no longer any
    /// key-parse failure mode to lose a race against, so the surviving arms
    /// detect *removal* of the STEP 0 token gate, not its *reordering*
    /// relative to the key parse. Stated rather than papered over.
    #[tokio::test]
    async fn token_gate_runs_before_the_data_key_is_even_parsed() {
        // The hazard this test was written for is now a construction error,
        // not a runtime ordering question.
        assert!(
            SecretHex::from_hex("deadbeef").is_err(),
            "a malformed key must be unrepresentable, not merely mis-ordered"
        );

        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let mut token_cap = authorized_token_capability(&manifest);
        token_cap.active = false;
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-order").await;
        let profile = AuthenticatedProfileId::for_test("profile-order");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-order",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );

        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .unwrap_err();

        assert_eq!(
            err.code(),
            token_manifest::ERR_TOKEN_UNSUPPORTED,
            "the token gate must fire before the data key is parsed; got {err:?}"
        );
        assert!(matches!(err, QuoteError::TokenUnauthorized(_)));

        // Control: with a WELL-FORMED key and the same unauthorized token,
        // the outcome is identical -- so the assertion above is about
        // ordering, not about the malformed key being ignored.
        let (v1_sig2, link_sig2) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req2 = base_request(
            root,
            controller,
            secondary,
            "idem-order-2",
            0,
            9_999_999_999,
            &v1_sig2,
            0,
            9_999_999_999,
            &link_sig2,
            1_000_000,
        );
        let err2 = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req2,
        )
        .await
        .unwrap_err();
        assert_eq!(err2.code(), token_manifest::ERR_TOKEN_UNSUPPORTED);
    }

    /// I7. This test used to also build a test-local `FakeDripClient` and
    /// assert `drips.calls == 0` after an `if result.is_ok() { drips.drip() }`
    /// — three lines below an `assert!(result.is_err())`, so the
    /// incrementing branch was **statically dead** and no mutation of
    /// `quotes.rs` could make the assertion fail, including the ordering
    /// mutation the test is named for. Its comment claimed the opposite.
    /// Deleted; what remains is the part that carries information:
    ///
    /// - the REAL production call rejecting with `TOKEN_UNSUPPORTED`
    ///   (mutation detected: removing the STEP 0 gate, or moving it after
    ///   the point where an unsupported token stops mattering);
    /// - the structural source-scan, which is legitimate because
    ///   `crate::gas_drips` really does exist (`src/gas_drips.rs`) — the
    ///   markers would match a future dependency edge, and *that* is what
    ///   makes "zero drip calls" true today: there is no drip call site in
    ///   this file to make.
    ///
    /// Real ordering coverage lives in the sibling
    /// `unsupported_token_quote_is_rejected_before_exposure_gate_or_signing`,
    /// whose `MockChain` counters are on the instance production code
    /// actually receives.
    #[tokio::test]
    async fn unsupported_token_quote_makes_zero_gas_drip_calls() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let mut token_cap = authorized_token_capability(&manifest);
        token_cap.active = false;
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-unsupported-drip").await;
        let profile = AuthenticatedProfileId::for_test("profile-unsupported-drip");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-unsupported-drip",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );

        // The REAL production call -- not a test-local stand-in.
        let result = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            result.as_ref().unwrap_err().code(),
            token_manifest::ERR_TOKEN_UNSUPPORTED
        );

        // Structural half, same technique token_manifest.rs's own
        // analogous test uses: quotes.rs has zero dependency edges to the
        // gas-drip ledger module today.
        let this_file_source = include_str!("quotes.rs");
        let import_marker: String = ["gas_dr", "ips::"].concat();
        let use_marker: String = ["use crate::gas_dr", "ips"].concat();
        assert!(
            !this_file_source.contains(&import_marker) && !this_file_source.contains(&use_marker),
            "quotes.rs must not gain a dependency edge on the gas-drip ledger module without \
             re-strengthening this test at the real call site"
        );
    }

    // -- 8. Idempotency -------------------------------------------------------

    /// C1 regression. The two calls are explicitly at T and T+5, via the
    /// injected clock — not "whenever the test runner happened to get
    /// there", which is what made the previous version of this test pass
    /// against an idempotency implementation that was in fact broken for
    /// every retry landing in a later UNIX second (and genuinely flaky in
    /// CI under `synchronous=FULL` fsync commits).
    ///
    /// This is non-tautological in a second, stronger way now: `valid_after`
    /// and `valid_until` are still (correctly) part of the signed `FeeQuote`
    /// struct, so a *re-signature* at T+5 would necessarily produce a
    /// different digest and therefore a different signature. Asserting that
    /// the signature and the validity window at T+5 are byte-identical to
    /// the ones minted at T therefore proves the STORED quote came back and
    /// nothing was re-signed — it cannot be satisfied by any code path that
    /// signs again.
    #[tokio::test]
    async fn same_idempotency_key_and_body_returns_stored_quote_not_a_second_signature() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-replay").await;
        let profile = AuthenticatedProfileId::for_test("profile-replay");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req1 = base_request(
            root,
            controller,
            secondary,
            "idem-replay",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        let req2 = base_request(
            root,
            controller,
            secondary,
            "idem-replay",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );

        // T. Both clocks are driven: the injected host clock (bookkeeping
        // columns) and, since I2, the chain clock the validity window is
        // cut from.
        let t: i64 = 1_800_000_000;
        chain.set_now(t as u64);
        let first = create_sponsored_enrollment_quote_at(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req1,
            t,
        )
        .await
        .unwrap();
        // T+5 — a different second, the case a real retry hits. Advancing
        // CHAIN time here is what keeps the signature assertion below
        // non-tautological: a re-signature would now mint
        // `valid_after = T+5`.
        chain.set_now((t + 5) as u64);
        let replay = create_sponsored_enrollment_quote_at(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req2,
            t + 5,
        )
        .await
        .expect("a byte-identical retry 5 seconds later is a TRUE replay, not a conflict");

        assert_eq!(replay.quote_id_hex, first.quote_id_hex);
        assert_eq!(
            replay.quote_signature_hex, first.quote_signature_hex,
            "a true replay must return the STORED signature, not a second signature"
        );
        assert_eq!(
            (replay.valid_after, replay.valid_until),
            (first.valid_after, first.valid_until),
            "the stored validity window must come back verbatim; a re-signature at T+5 \
             would have produced valid_after = T+5"
        );
        assert_eq!(first.valid_after, t as u64);
        assert_eq!(
            quotes_count(&store).await,
            1,
            "replay must not create a second quote row"
        );
        assert_eq!(intents_count(&store).await, 1);
        assert_eq!(authorization_slots_count(&store).await, 2);
    }

    /// M10. Asserts the actual persisted VALUE of every column this module
    /// writes across all four tables — not row counts, which is all the
    /// suite checked before and which cannot distinguish correct data from
    /// transposed data.
    ///
    /// The specific mutation called out in review: swapping the
    /// `.bind("0")` and `.bind(&quote_amount)` arguments on the `quotes`
    /// insert would persist a zero fee and a fee-sized `base_amount`, and
    /// every test in this file still passed. The `base_amount` /
    /// `quote_amount` pair below is what closes that.
    ///
    /// Also pins M7: the two `authorization_slots` rows are a RESERVATION
    /// (`status = 'reserved'`, `filled_at IS NULL`) at quote time, not a
    /// fill.
    #[tokio::test]
    async fn every_persisted_column_has_the_expected_value_not_just_the_expected_row_count() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-columns").await;
        let profile = AuthenticatedProfileId::for_test("profile-columns");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let mut req = base_request(
            root,
            controller,
            secondary,
            "idem-columns",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        let on_chain_intent_id = [0xC0u8; 32];
        req.intent_id_hex = format!("0x{}", hex::encode(on_chain_intent_id));

        // Host clock and chain clock deliberately set to the same instant
        // so the `created_at` (host) vs `expires_at` (chain, I2)
        // assertions below can both be written against `t`.
        let t: i64 = 1_800_000_000;
        chain.set_now(t as u64);
        let result = create_sponsored_enrollment_quote_at(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
            t,
        )
        .await
        .unwrap();

        // -- quotes -------------------------------------------------------
        let q = quote_row(&store, &hex_id_of(&result)).await;
        assert_eq!(q.profile_id.as_deref(), Some("profile-columns"));
        assert_eq!(
            q.base_asset,
            address_hex(manifest.fee_token),
            "base_asset is the FEE TOKEN address"
        );
        assert_eq!(q.quote_asset, QUOTES_TABLE_QUOTE_ASSET_MARKER);
        assert_eq!(
            q.base_amount, "0",
            "base_amount is the literal \"0\" -- if this ever reads \"500000\" the two \
             amount binds have been transposed"
        );
        assert_eq!(
            q.quote_amount, "500000",
            "quote_amount carries the fee -- a zero here is the transposition M10 describes"
        );
        assert_eq!(q.fee_bps, None, "a flat USDT tariff has no bps");
        assert_eq!(q.status, "active");
        assert_eq!(q.created_at, t);
        assert_eq!(q.expires_at, result.valid_until as i64);
        assert_eq!(q.expires_at, t + 300);

        // -- intents ------------------------------------------------------
        let intent_id = deterministic_id(&[
            INTENT_ROW_ID_DOMAIN,
            "profile-columns",
            &bytes32_hex(on_chain_intent_id),
        ]);
        let i = intent_row(&store, &intent_id).await;
        assert_eq!(i.profile_id, "profile-columns");
        assert_eq!(
            i.quote_id.as_deref(),
            Some(hex_id_of(&result).as_str()),
            "the intent must FK back to the quote it was quoted under"
        );
        assert_eq!(i.intent_type, "sponsored_enrollment");
        assert_eq!(
            i.amount.as_deref(),
            Some("500000"),
            "intents.amount is the fee amount"
        );
        assert_eq!(i.status, "pending");
        assert_eq!(i.created_at, t);
        assert_eq!(i.expires_at, Some(t + 300));

        // -- authorizations -----------------------------------------------
        let auth_id = deterministic_id(&[
            "stream_g_enrollment_bearers",
            "profile-columns",
            "idem-columns",
        ]);
        let a = authorization_row(&store, &auth_id).await;
        assert_eq!(
            a.intent_id, intent_id,
            "the authorization must point at the namespaced intent row id"
        );
        assert_eq!(a.profile_id, "profile-columns");
        assert_eq!(a.status, "authorized");
        assert_eq!(a.created_at, t);
        assert_eq!(a.authorized_at, Some(t));

        // -- authorization_slots (M7) -------------------------------------
        let slots = slot_rows(&store, &auth_id).await;
        assert_eq!(slots.len(), 2);
        for (expected_index, s) in slots.iter().enumerate() {
            assert_eq!(s.slot_index, expected_index as i64);
            assert_eq!(s.amount, None);
            assert_eq!(
                s.status, SLOT_STATUS_RESERVED,
                "quoting RESERVES the nested slots; only 6b's submit fills them"
            );
            assert_eq!(
                s.filled_at, None,
                "a slot that has not been filled must not carry a filled_at timestamp"
            );
            assert_eq!(s.created_at, t);
        }
    }

    /// M6. The replay branch used to return the stored quote with no
    /// expiry check at all — `QuotePayload.valid_until` and
    /// `quotes.expires_at` were never consulted, and nothing ever moved
    /// `quotes.status` off `'active'`. A caller retrying an hour later got
    /// back a perfectly well-formed signature that the gateway would
    /// reject, discoverable only as an on-chain revert. (This branch was
    /// barely reachable before C1 landed, which is why it went unnoticed.)
    ///
    /// The boundary is pinned on both sides — `valid_until - 1` still
    /// replays, `valid_until` itself does not — so this cannot be
    /// satisfied by a check that simply rejects every replay.
    #[tokio::test]
    async fn replay_of_an_expired_stored_quote_is_refused_not_handed_back() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-expiry").await;
        let profile = AuthenticatedProfileId::for_test("profile-expiry");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let mk = || {
            base_request(
                root,
                controller,
                secondary,
                "idem-expiry",
                0,
                9_999_999_999,
                &v1_sig,
                0,
                9_999_999_999,
                &link_sig,
                1_000_000,
            )
        };

        // I2: expiry is a CHAIN-clock question — `stored.valid_until` is
        // the uint48 the gateway compares against `block.timestamp` — so
        // it is chain time that gets advanced across the three calls here.
        let t: i64 = 1_800_000_000;
        chain.set_now(t as u64);
        let first = create_sponsored_enrollment_quote_at(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            mk(),
            t,
        )
        .await
        .unwrap();
        // `base_request` uses valid_for_seconds = 300.
        assert_eq!(first.valid_until, (t + 300) as u64);

        // One second inside the window: still a good replay.
        chain.set_now((t + 299) as u64);
        let inside = create_sponsored_enrollment_quote_at(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            mk(),
            t + 299,
        )
        .await
        .expect("a replay strictly inside the validity window must still return the quote");
        assert_eq!(inside.quote_signature_hex, first.quote_signature_hex);

        // At `validUntil` exactly the gateway's `block.timestamp <
        // validUntil` no longer holds, so the stored signature is dead.
        chain.set_now((t + 300) as u64);
        let err = create_sponsored_enrollment_quote_at(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            mk(),
            t + 300,
        )
        .await
        .expect_err("a replay at validUntil must not hand back an unusable signature");
        assert_eq!(err.code(), ERR_QUOTE_EXPIRED);
        assert!(matches!(err, QuoteError::StoredQuoteExpired));
        assert_ne!(
            err.code(),
            ERR_IDEMPOTENCY_KEY_CONFLICT,
            "expiry is not a parameter conflict; the caller's request was correct"
        );

        // The ledger was told, too — and the update survived the
        // transaction rather than being rolled back with the error.
        let status = quote_row(&store, &hex_id_of(&first)).await.status;
        assert_eq!(status, "expired");
        assert_eq!(quotes_count(&store).await, 1);
    }

    /// C2 regression — the squat scenario, run end to end.
    ///
    /// `intents.id` used to be `bytes32_hex(fields.intent_id)`: the raw,
    /// caller-supplied 32-byte on-chain `intentId` on a **global** `TEXT
    /// PRIMARY KEY`. Any authenticated profile could therefore permanently
    /// claim any intentId for everybody — a cross-profile denial of service
    /// (the victim's `INSERT OR IGNORE` affects 0 rows, the whole
    /// transaction rolls back, and it can never succeed because the
    /// intentId is bound into `actionCoreHash` and *is* the identity of the
    /// on-chain intent), plus a clean existence oracle for arbitrary
    /// intentIds via an `IDEMPOTENCY_KEY_CONFLICT` on a provably-never-used
    /// key, plus poisoning of `root_authorization.rs`'s
    /// `SELECT profile_id FROM intents WHERE id = ?` ownership check.
    ///
    /// Row ids are now namespaced per profile, matching `onboarding.rs`'s
    /// existing pattern in this same table. Note the gateway consumes
    /// `intentId` at *execution* (`intentUsed[intentId]`), not at quote
    /// time, so nothing is lost by not pre-empting it server-side.
    #[tokio::test]
    async fn two_profiles_can_quote_the_same_onchain_intent_id_without_colliding() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-squatter").await;
        seed_profile(&store, "profile-victim").await;
        let squatter = AuthenticatedProfileId::for_test("profile-squatter");
        let victim = AuthenticatedProfileId::for_test("profile-victim");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );

        // The single contested on-chain intentId.
        let contested_intent_id = [0x5Cu8; 32];
        let contested_hex = format!("0x{}", hex::encode(contested_intent_id));

        let mut req_squat = base_request(
            root,
            controller,
            secondary,
            "squatter-key",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        req_squat.intent_id_hex = contested_hex.clone();

        // The victim's own, legitimate request for the SAME on-chain
        // intentId, under a fresh idempotency key it has provably never
        // used before.
        let mut req_victim = base_request(
            root,
            controller,
            secondary,
            "victim-key-never-used-before",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        req_victim.intent_id_hex = contested_hex.clone();

        create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &squatter,
            &ctx,
            &schedule,
            req_squat,
        )
        .await
        .expect("first profile's quote must succeed");

        let victim_result = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &victim,
            &ctx,
            &schedule,
            req_victim,
        )
        .await
        .expect(
            "a squatted intents row belonging to another profile must NOT deny this profile \
             a quote for the same on-chain intentId",
        );

        assert_eq!(quotes_count(&store).await, 2);
        assert_eq!(
            intents_count(&store).await,
            2,
            "each profile must get its own intents row for the same on-chain intentId"
        );

        // The row id must be namespaced, not the raw intentId.
        let raw_id_rows: i64 = store
            .read(|handle| {
                let raw = bytes32_hex(contested_intent_id);
                Box::pin(async move {
                    let c: i64 = handle
                        .fetch_scalar(
                            sqlx::query_scalar("SELECT COUNT(*) FROM intents WHERE id = ?")
                                .bind(raw),
                        )
                        .await?;
                    Ok::<i64, StreamGStoreError>(c)
                })
            })
            .await
            .unwrap();
        assert_eq!(
            raw_id_rows, 0,
            "the raw caller-supplied intentId must never itself be an `intents` primary key"
        );

        // Both rows exist under their own owner, and each resolves to the
        // right profile under the exact ownership predicate
        // `root_authorization.rs` uses.
        for (profile_id, expected) in [
            ("profile-squatter", "profile-squatter"),
            ("profile-victim", "profile-victim"),
        ] {
            let row_id = deterministic_id(&[
                INTENT_ROW_ID_DOMAIN,
                profile_id,
                &bytes32_hex(contested_intent_id),
            ]);
            let owner: Option<String> = store
                .read(|handle| {
                    Box::pin(async move {
                        let o: Option<String> = handle
                            .fetch_optional(
                                sqlx::query("SELECT profile_id FROM intents WHERE id = ?")
                                    .bind(row_id),
                            )
                            .await?
                            .map(|r| r.try_get("profile_id"))
                            .transpose()?;
                        Ok::<Option<String>, StreamGStoreError>(o)
                    })
                })
                .await
                .unwrap();
            assert_eq!(owner.as_deref(), Some(expected));
        }

        // The raw on-chain intentId is not lost: it is carried inside the
        // sealed `intents.intent_enc` payload.
        let victim_row_id = deterministic_id(&[
            INTENT_ROW_ID_DOMAIN,
            "profile-victim",
            &bytes32_hex(contested_intent_id),
        ]);
        let sealed: Vec<u8> = store
            .read(|handle| {
                let id = victim_row_id.clone();
                Box::pin(async move {
                    let row = handle
                        .fetch_one(
                            sqlx::query("SELECT intent_enc FROM intents WHERE id = ?").bind(id),
                        )
                        .await?;
                    Ok::<Vec<u8>, StreamGStoreError>(row.try_get("intent_enc")?)
                })
            })
            .await
            .unwrap();
        let data_key = DataKey::from_secret(&data_key_hex());
        let aad = store.envelope_aad("intents", &victim_row_id, "intent_enc");
        let opened = crypto_store::open(&data_key, &aad, &sealed).expect("open intent payload");
        let payload: EnrollmentIntentPayload = serde_json::from_slice(&opened).unwrap();
        assert_eq!(
            payload.intent_id_hex,
            bytes32_hex(contested_intent_id),
            "the raw on-chain intentId must survive inside the sealed intent payload"
        );
        assert_eq!(payload.profile_id, "profile-victim");
        assert_eq!(payload.quote_id_hex, victim_result.quote_id_hex);
    }

    #[tokio::test]
    async fn same_idempotency_key_different_body_is_rejected_as_conflict() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-conflict").await;
        let profile = AuthenticatedProfileId::for_test("profile-conflict");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req1 = base_request(
            root,
            controller,
            secondary,
            "idem-conflict",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        // SAME idempotency key, DIFFERENT body (maxFee differs).
        let req2 = base_request(
            root,
            controller,
            secondary,
            "idem-conflict",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            2_000_000,
        );

        create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req1,
        )
        .await
        .unwrap();
        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req2,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), ERR_IDEMPOTENCY_KEY_CONFLICT);
        assert!(matches!(err, QuoteError::IdempotencyKeyConflict));
        assert_eq!(
            quotes_count(&store).await,
            1,
            "a conflicting replay must not create a second signature/quote"
        );
    }

    // -- 9. A caller cannot quote for a profile it has not authenticated as -

    #[tokio::test]
    async fn quote_idempotency_is_scoped_to_the_authenticated_profile_not_the_request() {
        // Two DIFFERENT authenticated profiles reusing the SAME
        // idempotency key with otherwise-identical bodies must never
        // collide -- proving the profile identity (only obtainable via
        // authentication; `CreateSponsoredEnrollmentQuoteRequest` has no
        // `profile_id` field at all) is what scopes a quote, not anything
        // the request body supplies.
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-scope-a").await;
        seed_profile(&store, "profile-scope-b").await;
        let profile_a = AuthenticatedProfileId::for_test("profile-scope-a");
        let profile_b = AuthenticatedProfileId::for_test("profile-scope-b");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req_a = base_request(
            root,
            controller,
            secondary,
            "shared-idem-key",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        let mut req_b = base_request(
            root,
            controller,
            secondary,
            "shared-idem-key",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        // A real client generates a fresh, globally-unique intentId per
        // logical intent regardless of what idempotency_key text it
        // happens to reuse -- profile B's intent here is a genuinely
        // different intent from profile A's, just coincidentally sharing
        // an idempotency_key string. Give it a distinct intentId so this
        // test isolates PROFILE scoping specifically, not intentId
        // collision (a different, legitimate rejection this module also
        // enforces via `intents.id`'s implicit uniqueness).
        req_b.intent_id_hex = format!("0x{}", hex::encode([0x78u8; 32]));

        let result_a = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile_a,
            &ctx,
            &schedule,
            req_a,
        )
        .await
        .unwrap();
        let result_b = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile_b,
            &ctx,
            &schedule,
            req_b,
        )
        .await
        .unwrap();

        assert_ne!(
            result_a.quote_id_hex, result_b.quote_id_hex,
            "different (authenticated) profiles using the same idempotency key must not collide"
        );
        assert_eq!(quotes_count(&store).await, 2);
    }

    // -- 10. Wave D ---------------------------------------------------------

    /// A `ChainClient` whose only interesting behaviour is what
    /// `block_timestamp()` returns. The two gas-oracle methods are given
    /// trivial `Ok` bodies so the STEP 2 exposure gate passes and execution
    /// actually reaches the STEP 4 validity window; everything else uses the
    /// trait's default bodies.
    struct BlockTimestampChain {
        block_timestamp: Result<u64, &'static str>,
    }

    impl crate::chain::ChainClient for BlockTimestampChain {
        fn propose_batch(
            &self,
            _epoch: u64,
            _merkle_root: [u8; 32],
            _evidence_ref: [u8; 32],
            _bond_wei: u128,
        ) -> Result<crate::chain::TxHash, crate::chain::ChainError> {
            unreachable!("quotes.rs never proposes a batch")
        }
        fn challenge_batch(
            &self,
            _epoch: u64,
            _counter_evidence_ref: [u8; 32],
            _bond_wei: u128,
        ) -> Result<crate::chain::TxHash, crate::chain::ChainError> {
            unreachable!("quotes.rs never challenges a batch")
        }
        fn confirm_epoch(
            &self,
            _epoch: u64,
        ) -> Result<crate::chain::TxHash, crate::chain::ChainError> {
            unreachable!("quotes.rs never confirms an epoch")
        }
        fn get_batch(
            &self,
            _epoch: u64,
        ) -> Result<crate::chain::BatchView, crate::chain::ChainError> {
            unreachable!("quotes.rs never reads a batch")
        }
        fn bind_with_signature(
            &self,
            _wallet: [u8; 20],
            _username: &str,
            _deadline: u64,
            _signature: &[u8],
        ) -> Result<crate::chain::TxHash, crate::chain::ChainError> {
            unreachable!("quotes.rs never binds")
        }
        fn enroll_self_with_signature(
            &self,
            _wallet: [u8; 20],
            _deadline: u64,
            _signature: &[u8],
        ) -> Result<crate::chain::TxHash, crate::chain::ChainError> {
            unreachable!("quotes.rs never enrolls")
        }
        fn gas_oracle_l1_fee_upper_bound(
            &self,
            _unsigned_tx_size: u64,
        ) -> Result<u128, crate::chain::ChainError> {
            Ok(1)
        }
        fn gas_oracle_operator_fee(
            &self,
            _gas_limit: u64,
        ) -> Result<u128, crate::chain::ChainError> {
            Ok(1)
        }
        fn block_timestamp(&self) -> Result<u64, crate::chain::ChainError> {
            self.block_timestamp
                .map_err(|m| crate::chain::ChainError::Msg(m.to_string()))
        }
    }

    /// I1. `enrollDigest`/`linkDigest` are no longer taken from the request
    /// at all; the module derives both and puts the derived values into the
    /// signed `actionCoreHash`. Non-tautological: the expected hash below is
    /// built in the test from `sig_verify::enroll_digest` /
    /// `link_secondary_digest` over the SAME inputs the bearer signatures
    /// were signed with, so if the production path ever went back to copying
    /// a caller-supplied digest (or derived one from different inputs) this
    /// equality would break.
    #[tokio::test]
    async fn action_core_hash_embeds_the_server_derived_nested_digests() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-derived").await;
        let profile = AuthenticatedProfileId::for_test("profile-derived");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-derived",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        let intent_id = parse_bytes32("intent_id_hex", &req.intent_id_hex).unwrap();

        let result = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .unwrap();

        let expected_enroll_digest = sig_verify::enroll_digest(
            secondary,
            0,
            9_999_999_999,
            manifest.chain_id,
            manifest.enrollment_registry,
        );
        let expected_link_digest = link_secondary_digest(
            &LinkSecondary {
                root,
                secondary,
                nonce: 0,
                deadline: 9_999_999_999,
            },
            manifest.chain_id,
            manifest.wallet_sponsorship_registry,
        );
        let expected_core = SponsorEnrollmentCore {
            intent_id,
            deployment_manifest_hash: manifest.deployment_manifest_hash,
            fee_token_config_hash: live_token.fee_token_config_hash(),
            root,
            controller,
            controller_epoch: 1,
            secondary,
            enroll_digest: expected_enroll_digest,
            link_digest: expected_link_digest,
            root_authorization_digest: [0u8; 32],
            fee_token: manifest.fee_token,
            fee_authorization_mode: 1,
            max_fee: 1_000_000,
            nonce: 0,
            deadline: 9_999_999_999,
        };
        assert_eq!(
            result.action_core_hash_hex,
            bytes32_hex(sponsor_enrollment_core_hash(&expected_core)),
            "the signed actionCoreHash must embed the digests this server derived, \
             so `GoatRelayGateway.sol:356/:361` cannot disagree with it"
        );
    }

    /// I1. `GoatRelayGateway.sol:365` — `intent.rootAuthorizationDigest !=
    /// bytes32(0)` is a hard `InvalidFeeFields` revert on this path.
    #[tokio::test]
    async fn quote_rejects_a_non_zero_root_authorization_digest() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-rootauth").await;
        let profile = AuthenticatedProfileId::for_test("profile-rootauth");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let mut req = base_request(
            root,
            controller,
            secondary,
            "idem-rootauth",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        req.root_authorization_digest_hex = format!("0x{}", hex::encode([0x77u8; 32]));

        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .expect_err("a non-zero rootAuthorizationDigest reverts InvalidFeeFields on-chain");
        assert_eq!(err.code(), ERR_NON_ZERO_ROOT_AUTHORIZATION_DIGEST);
        assert_eq!(quotes_count(&store).await, 0);
    }

    /// I1. `GoatRelayGateway.sol:395` requires
    /// `intent.feeAuthorizationMode == uint8(AuthorizationMode.EIP2612)`.
    /// `3` is `PRIOR_ALLOWANCE` — a perfectly valid ordinal of the same
    /// enum, and exactly the kind of value a client could plausibly send.
    #[tokio::test]
    async fn quote_rejects_a_fee_authorization_mode_other_than_eip2612() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-feemode").await;
        let profile = AuthenticatedProfileId::for_test("profile-feemode");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let mut req = base_request(
            root,
            controller,
            secondary,
            "idem-feemode",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        req.fee_authorization_mode = 3; // AuthorizationMode.PRIOR_ALLOWANCE

        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .expect_err("only AuthorizationMode.EIP2612 (=1) is executable on this path");
        assert_eq!(err.code(), ERR_UNSUPPORTED_FEE_MODE);
        assert_eq!(quotes_count(&store).await, 0);
    }

    /// M8. `SponsorEnrollmentCore.deadline` is `uint48`
    /// (`StreamGTypes.sol:137`); dirty high bits make the signed
    /// `actionCoreHash` unreproducible by any conforming intent.
    #[tokio::test]
    async fn quote_rejects_a_deadline_that_does_not_fit_uint48() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-deadline48").await;
        let profile = AuthenticatedProfileId::for_test("profile-deadline48");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let mut req = base_request(
            root,
            controller,
            secondary,
            "idem-deadline48",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        req.deadline = UINT48_MAX + 1;

        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .expect_err("a deadline above uint48 cannot round-trip through the on-chain struct");
        assert_eq!(err.code(), ERR_DEADLINE_EXCEEDS_UINT48);

        // Boundary, so this cannot be satisfied by rejecting every deadline.
        let (v1_sig2, link_sig2) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let mut ok_req = base_request(
            root,
            controller,
            secondary,
            "idem-deadline48-ok",
            0,
            9_999_999_999,
            &v1_sig2,
            0,
            9_999_999_999,
            &link_sig2,
            1_000_000,
        );
        ok_req.deadline = UINT48_MAX;
        create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            ok_req,
        )
        .await
        .expect("uint48::MAX itself is representable and must be accepted");
    }

    /// M8. `LinkSecondary.deadline` is `uint48` (`StreamGTypes.sol:191`).
    #[tokio::test]
    async fn quote_rejects_a_link_deadline_that_does_not_fit_uint48() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-linkdeadline48").await;
        let profile = AuthenticatedProfileId::for_test("profile-linkdeadline48");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let bad_link_deadline = UINT48_MAX + 1;
        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            bad_link_deadline,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-linkdeadline48",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            bad_link_deadline,
            &link_sig,
            1_000_000,
        );

        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .expect_err("a link_deadline above uint48 cannot round-trip through LinkSecondary");
        assert_eq!(err.code(), ERR_DEADLINE_EXCEEDS_UINT48);
    }

    /// I2. `StreamGCommon.validateAndConsumeQuote` compares `quote.validAfter` against
    /// `block.timestamp`, so the window must be cut from CHAIN time. This
    /// test drives `MockChain`'s block timestamp far behind the host wall
    /// clock; with the old `now_unix_seconds()` implementation
    /// `valid_after` would be the host clock (roughly 2.7 years ahead of
    /// the chain here) and both assertions below would fail.
    #[tokio::test]
    async fn valid_after_comes_from_chain_time_not_the_host_wall_clock() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-chaintime").await;
        let profile = AuthenticatedProfileId::for_test("profile-chaintime");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);

        // Deliberately behind the host clock, the NTP-drift direction that
        // takes sponsored enrollment offline.
        let chain_now: u64 = 1_700_000_000;
        let chain = MockChain::new();
        chain.set_now(chain_now);
        assert!(
            chain_now < now_unix_seconds() as u64,
            "fixture precondition: the mock chain must be BEHIND the host clock"
        );

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-chaintime",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );

        let result = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .unwrap();

        assert_eq!(
            result.valid_after, chain_now,
            "validAfter must be block.timestamp, not SystemTime::now()"
        );
        assert!(
            result.valid_after <= chain.block_timestamp().unwrap(),
            "validAfter must never be in the chain's future"
        );
        assert_eq!(result.valid_until, chain_now + 300);
    }

    /// I2. Fail closed: an RPC error reading chain time must refuse the
    /// quote, never silently fall back to the host wall clock.
    #[tokio::test]
    async fn quote_fails_closed_when_chain_time_is_unavailable() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-notime").await;
        let profile = AuthenticatedProfileId::for_test("profile-notime");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let mk = |key: &str| {
            base_request(
                root,
                controller,
                secondary,
                key,
                0,
                9_999_999_999,
                &v1_sig,
                0,
                9_999_999_999,
                &link_sig,
                1_000_000,
            )
        };

        // (a) the RPC errors.
        let erroring = BlockTimestampChain {
            block_timestamp: Err("eth_getBlockByNumber failed"),
        };
        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &erroring,
            &profile,
            &ctx,
            &schedule,
            mk("idem-notime-err"),
        )
        .await
        .expect_err("an unreadable chain clock must refuse the quote, not use the host clock");
        assert_eq!(err.code(), ERR_CHAIN_TIME_UNAVAILABLE);

        // (b) `ChainClient::block_timestamp`'s trait DEFAULT is `Ok(0)` —
        // documented as "0 = unknown". An unknown clock is not a valid
        // `validAfter` of 1970; it must fail closed identically.
        let unknown = BlockTimestampChain {
            block_timestamp: Ok(0),
        };
        let err0 = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &unknown,
            &profile,
            &ctx,
            &schedule,
            mk("idem-notime-zero"),
        )
        .await
        .expect_err("block_timestamp() == 0 means 'unknown', which must fail closed");
        assert_eq!(err0.code(), ERR_CHAIN_TIME_UNAVAILABLE);

        assert_eq!(
            quotes_count(&store).await,
            0,
            "no quote may be signed or persisted without a chain clock"
        );
    }

    // -- 11. Wave E --------------------------------------------------------

    // Fee-schedule file fixtures.
    //
    // These reuse `runtime::test_support`'s payload rather than growing a
    // second one: a second literal would be a second thing to keep in step
    // with the eleven published fields, and the runtime fixture is already
    // pinned to a known-answer digest by
    // `runtime::tests::fixture_schedule_payload_hashes_to_the_pinned_manifest_value`.

    /// The standard payload with `mutate` applied, as JSON text.
    ///
    /// Mutating a parsed `Value` rather than string-splicing so a malformed
    /// case is malformed in exactly the one way the test names.
    fn payload_with(mutate: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>)) -> String {
        let mut value: serde_json::Value =
            serde_json::from_str(&super::super::runtime::test_support::schedule_payload_json(None))
                .expect("the fixture payload must be JSON");
        mutate(value.as_object_mut().expect("the payload is an object"));
        value.to_string()
    }

    /// Sets one `actionFeesRaw` entry: `Some` publishes an amount, `None`
    /// writes the JSON `null` that means "no tariff set".
    fn set_action_fee(
        payload: &mut serde_json::Map<String, serde_json::Value>,
        action: ActionType,
        raw: Option<&str>,
    ) {
        let fees = payload
            .get_mut("actionFeesRaw")
            .and_then(serde_json::Value::as_object_mut)
            .expect("actionFeesRaw is an object");
        fees.insert(
            action.as_str().to_string(),
            match raw {
                Some(v) => serde_json::Value::String(v.to_string()),
                None => serde_json::Value::Null,
            },
        );
    }

    /// Writes a schedule file that declares its own payload's digest — the
    /// only combination `runtime::StreamGState::start` accepts, so a fixture
    /// that is about `load` alone still cannot drift into an unstartable
    /// shape by accident.
    fn write_schedule(path: &std::path::Path, payload_json: &str) {
        let hash = super::super::runtime::test_support::schedule_hash_hex(payload_json);
        fs::write(
            path,
            super::super::runtime::test_support::fee_schedule_json(&hash, payload_json),
        )
        .unwrap();
    }

    /// M5. `FeeSchedule::load` had ZERO call sites and ZERO tests — all
    /// thirteen fixtures in this file use `for_test` — and `FeeScheduleFile`
    /// carried no `#[serde(rename_all = "camelCase")]`, so the file format
    /// this module's own doc comment documents could not deserialize at all:
    /// serde demanded `schema_version`. The loader could not load its own
    /// documented format.
    ///
    /// **Mutation this detects:** deleting
    /// `#[serde(rename_all = "camelCase")]` from `FeeScheduleFile` or from
    /// `SchedulePayloadFile` makes this fail with a `missing field` parse
    /// error.
    ///
    /// (This is the FILE format, and camelCase matches
    /// `DeploymentManifest`'s. It is deliberately NOT the same decision as
    /// the Stream G *wire* format, which is snake_case — see
    /// `request_json_body`.)
    #[test]
    fn fee_schedule_load_reads_the_documented_camel_case_file_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fee_schedule.json");
        let payload = payload_with(|p| {
            set_action_fee(p, ActionType::SponsoredEnrollment, Some("500000"));
            set_action_fee(p, ActionType::UsdtTransfer, Some("1"));
        });
        write_schedule(&path, &payload);

        let schedule = FeeSchedule::load(&path)
            .expect("the file format this module documents must actually load");
        assert_eq!(
            schedule.fee_for(ActionType::SponsoredEnrollment).unwrap(),
            500_000
        );
        assert_eq!(schedule.fee_for(ActionType::UsdtTransfer).unwrap(), 1);
        // Every payload field is camelCase inside the hashed object too, and
        // the digest is over the payload as the operator wrote it.
        assert_eq!(
            schedule.computed_fee_schedule_hash(),
            schedule.declared_fee_schedule_hash(),
            "write_schedule declares the digest it computes"
        );
    }

    /// I5. The module's entire output artifact — the signature a payer
    /// hands to `GoatRelayGateway` — was unchecked by the whole suite. The
    /// only assertion that touched `quote_signature_hex` compared two
    /// invocations of the same deterministic code path, which holds even if
    /// the replay short-circuit is deleted. And a real check was impossible
    /// by construction: `QUOTE_SIGNER_PK` (anvil key 0) did not correspond
    /// to `manifest_fixture()`'s `quote_signer`, which was `[0x1B; 20]`.
    ///
    /// **Mutations this detects** (each makes the recovery below yield some
    /// other address, exactly as `_validateAndConsumeQuoteGeneric` would
    /// on-chain):
    /// - signing `fee_quote_struct_hash(&quote)` instead of the full
    ///   EIP-712 digest (pinned as negative control (b) below);
    /// - passing `ctx.manifest.wallet_sponsorship_registry` (or any other
    ///   address) as the verifying contract (control (c));
    /// - using the wrong chain id in the domain (control (a));
    /// - any drift in `FeeQuote`'s field order or word packing, because the
    ///   digest is rebuilt here from the RETURNED `QuoteResult` fields.
    #[tokio::test]
    async fn emitted_quote_signature_recovers_to_the_manifest_quote_signer() {
        use super::super::models::fee_quote_struct_hash;

        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();

        // Fixture pin: without this the recovery below could never hold,
        // and the whole test would be unwritable (which is why it did not
        // exist).
        assert_eq!(
            address_hex(manifest.quote_signer),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "manifest.quote_signer must be QUOTE_SIGNER_PK's own address (anvil key 0)"
        );

        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-sig").await;
        let profile = AuthenticatedProfileId::for_test("profile-sig");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-sig",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );

        let result = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .unwrap();

        // Rebuilt from the RETURNED result only — nothing is borrowed from
        // the production call's internals.
        let expected = FeeQuote {
            quote_id: parse_bytes32("quote_id_hex", &result.quote_id_hex).unwrap(),
            action_type: parse_bytes32("action_type_hex", &result.action_type_hex).unwrap(),
            action_core_hash: parse_bytes32("action_core_hash_hex", &result.action_core_hash_hex)
                .unwrap(),
            deployment_manifest_hash: parse_bytes32(
                "deployment_manifest_hash_hex",
                &result.deployment_manifest_hash_hex,
            )
            .unwrap(),
            fee_token_config_hash: parse_bytes32(
                "fee_token_config_hash_hex",
                &result.fee_token_config_hash_hex,
            )
            .unwrap(),
            fee_schedule_hash: parse_bytes32(
                "fee_schedule_hash_hex",
                &result.fee_schedule_hash_hex,
            )
            .unwrap(),
            payer: parse_address20("payer", &result.payer).unwrap(),
            fee_token: parse_address20("fee_token", &result.fee_token).unwrap(),
            fee_amount: parse_u128_decimal("fee_amount", &result.fee_amount).unwrap(),
            fee_recipient: parse_address20("fee_recipient", &result.fee_recipient).unwrap(),
            valid_after: result.valid_after,
            valid_until: result.valid_until,
        };
        let digest = fee_quote_digest(&expected, manifest.chain_id, manifest.goat_relay_gateway);
        recover_and_check(digest, &result.quote_signature_hex, manifest.quote_signer).expect(
            "the emitted signature must recover to manifest.quote_signer over \
             fee_quote_digest(quote, chainId, goatRelayGateway)",
        );

        // Negative controls — each proves the assertion above is
        // discriminating rather than something ecrecover would accept for
        // any prehash at all.
        // (a) wrong chain id in the domain.
        assert!(recover_and_check(
            fee_quote_digest(&expected, 1, manifest.goat_relay_gateway),
            &result.quote_signature_hex,
            manifest.quote_signer,
        )
        .is_err());
        // (b) the bare struct hash instead of the `\x19\x01`-prefixed digest.
        assert!(recover_and_check(
            fee_quote_struct_hash(&expected),
            &result.quote_signature_hex,
            manifest.quote_signer,
        )
        .is_err());
        // (c) a different verifying contract.
        assert!(recover_and_check(
            fee_quote_digest(
                &expected,
                manifest.chain_id,
                manifest.wallet_sponsorship_registry
            ),
            &result.quote_signature_hex,
            manifest.quote_signer,
        )
        .is_err());
    }

    // -- I6: the nested-bearer ECDSA checks --------------------------------
    //
    // Before these two tests, EVERY request in this file was built by
    // `sign_nested_bearers` with valid signatures — even the negative nonce
    // test signs correctly and relies on the snapshot to trigger rejection —
    // so `ERR_BAD_V1_SIGNATURE` and `ERR_BAD_LINK_SIGNATURE` appeared
    // nowhere in the module and both `recover_and_check` calls in
    // `verify_nested_enrollment_bearers` could be DELETED with the whole
    // suite green. Production would then have signed and persisted a quote
    // binding an arbitrary victim's `secondary`/`root` pair on nothing but
    // the caller's say-so.

    /// **Mutation this detects:** deleting (or weakening to a no-op) the
    /// `recover_and_check(enroll_digest, &req.v1_signature_hex,
    /// fields.secondary)` call in `verify_nested_enrollment_bearers` — the
    /// quote would then be issued and this `expect_err` would panic.
    ///
    /// Non-vacuous by construction: the nonces MATCH `ctx.live_nonces` (so
    /// `StaleOrMixedNonce` cannot fire first), the digest signed is the
    /// real one for the real `secondary`, and the control at the end shows
    /// the identical request with a correctly-keyed V1 signature succeeds.
    /// The only difference between rejection and success is which key held
    /// the pen.
    #[tokio::test]
    async fn quote_rejects_a_v1_enrollment_signature_from_the_wrong_key() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let wrong_signer = PrivateKeySigner::from_str(WRONG_BEARER_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        assert_ne!(wrong_signer.address().into_array(), secondary);
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-badv1").await;
        let profile = AuthenticatedProfileId::for_test("profile-badv1");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        // V1Enrollment signed by the WRONG key; LinkSecondary signed
        // correctly; both over the correct digests, both nonces matching.
        let (bad_v1_sig, good_link_sig) = sign_nested_bearers_as(
            &manifest,
            root,
            secondary,
            &wrong_signer,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-badv1",
            0,
            9_999_999_999,
            &bad_v1_sig,
            0,
            9_999_999_999,
            &good_link_sig,
            1_000_000,
        );

        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .expect_err(
            "a V1Enrollment signature that does not recover to `secondary` must be refused",
        );
        assert_eq!(err.code(), ERR_BAD_V1_SIGNATURE);
        assert!(matches!(err, QuoteError::BadV1Signature(_)));
        // Rejected before the exposure gate's chain calls and before anything
        // is persisted.
        assert_eq!(chain.l1_fee_upper_bound_call_count(), 0);
        assert_eq!(quotes_count(&store).await, 0);

        // Control: byte-for-byte the same request except the V1 signature is
        // the secondary's own. Proves the rejection above is about the KEY.
        let (good_v1_sig, good_link_sig2) = sign_nested_bearers_as(
            &manifest,
            root,
            secondary,
            &secondary_signer,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let ok_req = base_request(
            root,
            controller,
            secondary,
            "idem-badv1-control",
            0,
            9_999_999_999,
            &good_v1_sig,
            0,
            9_999_999_999,
            &good_link_sig2,
            1_000_000,
        );
        create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            ok_req,
        )
        .await
        .expect("the same request signed by `secondary` itself must succeed");
    }

    /// **Mutation this detects:** deleting the
    /// `recover_and_check(link_digest, &req.link_signature_hex,
    /// fields.secondary)` call in `verify_nested_enrollment_bearers`.
    ///
    /// Note the V1 signature here is VALID, so this reaches the link check
    /// specifically — the V1 check runs first and would otherwise mask it.
    #[tokio::test]
    async fn quote_rejects_a_link_secondary_signature_from_the_wrong_key() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let wrong_signer = PrivateKeySigner::from_str(WRONG_BEARER_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-badlink").await;
        let profile = AuthenticatedProfileId::for_test("profile-badlink");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (good_v1_sig, bad_link_sig) = sign_nested_bearers_as(
            &manifest,
            root,
            secondary,
            &secondary_signer,
            &wrong_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-badlink",
            0,
            9_999_999_999,
            &good_v1_sig,
            0,
            9_999_999_999,
            &bad_link_sig,
            1_000_000,
        );

        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .expect_err(
            "a LinkSecondary signature that does not recover to `secondary` must be refused",
        );
        assert_eq!(err.code(), ERR_BAD_LINK_SIGNATURE);
        assert!(matches!(err, QuoteError::BadLinkSignature(_)));
        assert_eq!(chain.l1_fee_upper_bound_call_count(), 0);
        assert_eq!(quotes_count(&store).await, 0);

        // Control: same request, link signature from `secondary` itself.
        let (good_v1_sig2, good_link_sig) = sign_nested_bearers_as(
            &manifest,
            root,
            secondary,
            &secondary_signer,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let ok_req = base_request(
            root,
            controller,
            secondary,
            "idem-badlink-control",
            0,
            9_999_999_999,
            &good_v1_sig2,
            0,
            9_999_999_999,
            &good_link_sig,
            1_000_000,
        );
        create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            ok_req,
        )
        .await
        .expect("the same request signed by `secondary` itself must succeed");
    }

    // -- M5: the rest of the FeeSchedule::load surface ---------------------

    /// **A typo'd action key is now a load error, and this test changed
    /// meaning.** It used to be
    /// `fee_schedule_load_drops_an_unrecognised_tariff_key_so_a_typo_surfaces_as_missing_tariff`,
    /// pinning that `load` copied only the four keys it recognised and
    /// silently discarded the rest, so a misspelling surfaced much later as
    /// `MISSING_TARIFF`.
    ///
    /// Under a value digest that behaviour became actively dangerous in a new
    /// way: a dropped key is still *inside* the hashed payload, so a typo
    /// changes `feeScheduleHash`. The operator would no longer get a late
    /// `MISSING_TARIFF` — they would get a startup refusal saying this
    /// deployment did not publish this schedule, with nothing anywhere
    /// pointing at the misspelling. So `load` refuses, and the message names
    /// the offending key and the four canonical names.
    ///
    /// This is also what the spec requires independently: action maps
    /// "contain exactly the four canonical actionType names"
    /// (the "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring"
    /// spec, §8.1).
    ///
    /// **Mutation this detects (applied, run, reverted):** dropping the
    /// `unrecognised` half of `require_exact_action_map` (keeping only the
    /// missing-key half) — the file is still refused, because the correctly
    /// spelled key is now absent, but the message names only what is missing
    /// and never the key that was mistyped, so the "must be shown the key they
    /// mistyped" assertion fails. That is the whole point: the refusal is easy,
    /// the actionable message is not.
    #[test]
    fn fee_schedule_load_refuses_an_unrecognised_action_key_rather_than_dropping_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fee_schedule.json");
        // Single-L "ENROLMENT" — the real key is GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1.
        let typo = payload_with(|p| {
            let fees = p
                .get_mut("actionFeesRaw")
                .and_then(serde_json::Value::as_object_mut)
                .unwrap();
            fees.remove(ActionType::SponsoredEnrollment.as_str());
            fees.insert(
                "GOAT_STREAM_G_SPONSORED_ENROLMENT_V1".to_string(),
                serde_json::Value::String("500000".to_string()),
            );
        });
        write_schedule(&path, &typo);

        let err = FeeSchedule::load(&path)
            .expect_err("a misspelled action key must not be silently dropped");
        assert_eq!(err.code(), ERR_FEE_SCHEDULE_PARSE);
        let rendered = err.to_string();
        assert!(
            rendered.contains("GOAT_STREAM_G_SPONSORED_ENROLMENT_V1"),
            "the operator must be shown the key they mistyped: {rendered}"
        );
        assert!(
            rendered.contains("GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1"),
            "and the spelling that was meant: {rendered}"
        );
        assert!(
            rendered.contains("actionFeesRaw"),
            "and which map it was in: {rendered}"
        );

        // Paired positive arm: the same file with the key spelled correctly
        // loads, so the refusal is about the typo and not about the fixture.
        let ok = payload_with(|p| set_action_fee(p, ActionType::SponsoredEnrollment, Some("500000")));
        write_schedule(&path, &ok);
        assert_eq!(
            FeeSchedule::load(&path)
                .unwrap()
                .fee_for(ActionType::SponsoredEnrollment)
                .unwrap(),
            500_000
        );
    }

    /// A key is missing from an action map altogether. Same refusal, opposite
    /// half of `require_exact_action_map` — the spec's "exactly the four"
    /// forbids omission as well as addition, and an omitted key would leave
    /// two payloads meaning the same schedule with different digests.
    ///
    /// **Mutation this detects (applied, run, reverted):** dropping the
    /// `missing` half of `require_exact_action_map` — the short map then loads
    /// and the `panic!` on the `Ok` arm fires.
    #[test]
    fn fee_schedule_load_refuses_an_action_map_that_omits_a_canonical_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fee_schedule.json");

        for field in ["actionFeesRaw", "gasUnitCeilings", "calldataByteCeilings"] {
            let short = payload_with(|p| {
                p.get_mut(field)
                    .and_then(serde_json::Value::as_object_mut)
                    .unwrap()
                    .remove(ActionType::UsdtTransfer.as_str());
            });
            write_schedule(&path, &short);
            let err = match FeeSchedule::load(&path) {
                Ok(_) => panic!("{field} is missing an action key and must not load"),
                Err(e) => e,
            };
            assert_eq!(err.code(), ERR_FEE_SCHEDULE_PARSE);
            let rendered = err.to_string();
            assert!(rendered.contains(field), "{rendered}");
            assert!(
                rendered.contains(ActionType::UsdtTransfer.as_str()),
                "the missing key must be named: {rendered}"
            );
        }
    }

    /// `null` in `actionFeesRaw` means "no tariff set for this action" — the
    /// v2 replacement for v1's "omit the key".
    ///
    /// The key cannot be omitted any more (the spec requires all four), and it
    /// must not carry `"0"` either: a zero is a parseable PRICE, and
    /// `models::fee_quote_struct_hash` would sign it verbatim into a
    /// payer-facing quote. `null` is the only encoding that is unmistakably
    /// not an amount.
    ///
    /// **Mutation this detects (applied, run, reverted):** treating `None` as
    /// `0` in `load` (`entry.as_ref().unwrap_or(&"0".to_string())`) — the
    /// `MISSING_TARIFF` assertions below fail, and so does
    /// `shipped_placeholder_fee_schedule_is_published_and_serves_no_price`,
    /// because the shipped placeholder would start serving a zero price. At
    /// request time an operator would see `ZERO_FEE_AMOUNT` from a
    /// *configuration* state, with a misleading code.
    #[test]
    fn fee_schedule_load_reads_a_null_action_fee_as_no_tariff() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fee_schedule.json");
        let payload = payload_with(|p| set_action_fee(p, ActionType::GoatTransfer, Some("3")));
        write_schedule(&path, &payload);

        let schedule = FeeSchedule::load(&path).unwrap();
        assert_eq!(schedule.fee_for(ActionType::GoatTransfer).unwrap(), 3);
        for absent in [
            ActionType::SponsoredEnrollment,
            ActionType::SponsoredSell,
            ActionType::UsdtTransfer,
        ] {
            assert_eq!(
                schedule.fee_for(absent).unwrap_err().code(),
                ERR_MISSING_TARIFF,
                "{absent:?} is null in the file and must not resolve to anything"
            );
        }

        // Discriminating control: `"0"` is NOT null. It loads as a real
        // zero tariff, which the quote path rejects with a different code —
        // proving `null` is a distinct state and not just "falsy".
        let zeroed = payload_with(|p| set_action_fee(p, ActionType::SponsoredSell, Some("0")));
        write_schedule(&path, &zeroed);
        assert_eq!(
            FeeSchedule::load(&path)
                .unwrap()
                .fee_for(ActionType::SponsoredSell)
                .unwrap(),
            0
        );
    }

    /// M5. Every malformed-input path of `load`, each with its own typed
    /// code.
    ///
    /// **Mutations this detects:** deleting
    /// `#[serde(deny_unknown_fields)]` from `FeeScheduleFile` (case (c)
    /// would parse `Ok`) or from `SchedulePayloadFile` (case (e)); dropping
    /// the `canonical_decimal` check on an action fee (case (b)); and
    /// collapsing the distinct `FeeScheduleIo` / `FeeScheduleParse` variants
    /// into one (case (d) vs the rest).
    #[test]
    fn fee_schedule_load_reports_typed_errors_for_every_malformed_input() {
        let dir = tempfile::tempdir().unwrap();

        // (a) not JSON at all.
        let a = dir.path().join("a.json");
        fs::write(&a, "this is not json").unwrap();
        assert_eq!(
            FeeSchedule::load(&a).unwrap_err().code(),
            ERR_FEE_SCHEDULE_PARSE
        );

        // (b) an action fee that is not a decimal string.
        let b = dir.path().join("b.json");
        write_schedule(
            &b,
            &payload_with(|p| set_action_fee(p, ActionType::SponsoredEnrollment, Some("500_000"))),
        );
        let err_b = FeeSchedule::load(&b).unwrap_err();
        assert_eq!(err_b.code(), ERR_FEE_SCHEDULE_PARSE);
        assert!(
            err_b
                .to_string()
                .contains("payload.actionFeesRaw[GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1]"),
            "the parse error must say WHICH tariff is unusable: {err_b}"
        );

        // (c) an unknown TOP-LEVEL field (deny_unknown_fields).
        let c = dir.path().join("c.json");
        let payload = super::super::runtime::test_support::schedule_payload_json(None);
        let hash = super::super::runtime::test_support::schedule_hash_hex(&payload);
        fs::write(
            &c,
            format!(
                r#"{{"schemaVersion": 2, "feeScheduleHash": "{hash}", "payload": {payload},
                     "feeRecipient": "0xattacker"}}"#
            ),
        )
        .unwrap();
        assert_eq!(
            FeeSchedule::load(&c).unwrap_err().code(),
            ERR_FEE_SCHEDULE_PARSE,
            "an operator-authored file must not be able to smuggle extra keys past the loader"
        );

        // (d) the file does not exist — an IO error, not a parse error.
        let d = dir.path().join("does-not-exist.json");
        let err_d = FeeSchedule::load(&d).unwrap_err();
        assert_eq!(err_d.code(), ERR_FEE_SCHEDULE_IO);
        assert!(matches!(err_d, QuoteError::FeeScheduleIo { .. }));

        // (e) an unknown field INSIDE the payload. This one is not cosmetic:
        // an unknown payload field would be hashed, so accepting it would let
        // one approved schedule have unlimited digests, and would let a field
        // no reviewer looked at ride along inside an approved hash.
        let e = dir.path().join("e.json");
        write_schedule(
            &e,
            &payload_with(|p| {
                p.insert(
                    "feeRecipient".to_string(),
                    serde_json::Value::String("0xattacker".to_string()),
                );
            }),
        );
        let err_e = FeeSchedule::load(&e).unwrap_err();
        assert_eq!(err_e.code(), ERR_FEE_SCHEDULE_PARSE);
        assert!(
            err_e.to_string().contains("feeRecipient"),
            "the unknown payload field must be named: {err_e}"
        );

        // Control: the same directory, a well-formed file, loads.
        let ok = dir.path().join("ok.json");
        write_schedule(
            &ok,
            &payload_with(|p| set_action_fee(p, ActionType::SponsoredEnrollment, Some("500000"))),
        );
        assert_eq!(
            FeeSchedule::load(&ok)
                .unwrap()
                .fee_for(ActionType::SponsoredEnrollment)
                .unwrap(),
            500_000
        );
    }

    /// Every hash-affecting spelling rule, each with the field named.
    ///
    /// These are not style rules. `"07"` and `"7"` are the same amount and
    /// different bytes; `0xDDc1…` and `0xddc1…` are the same address and
    /// different bytes. Accepting either pair would give one approved schedule
    /// two legitimate digests, which is precisely the ambiguity
    /// `feeScheduleHash` exists to remove.
    ///
    /// **Mutations this detects (both applied, run, reverted):** dropping
    /// `canonical_decimal`'s digits-only guard so it falls back on
    /// `str::parse::<u128>`, which accepts `"+31337"` and `" 0"`; and
    /// widening `canonical_lowercase_address` to `is_ascii_hexdigit`, which
    /// accepts the checksummed `0xDDc1…` spelling of the same address.
    #[test]
    fn fee_schedule_load_refuses_non_canonical_spellings_of_the_same_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fee_schedule.json");

        let cases: [(&str, serde_json::Value, &str); 6] = [
            // (field, value, the substring the operator needs to see)
            ("decimals", "06".into(), "leading zero"),
            ("chainId", "+31337".into(), "decimal string"),
            ("maxNativeExposureWei", " 0".into(), "decimal string"),
            ("scheduleVersion", "".into(), "decimal string"),
            (
                "feeToken",
                "0xDDc10602782af652bB913f7bdE1fD82981Db7dd9".into(),
                "lowercase",
            ),
            ("feeToken", "ddc10602782af652bb913f7bde1fd82981db7dd9".into(), "lowercase"),
        ];
        for (field, value, needle) in cases {
            write_schedule(
                &path,
                &payload_with(|p| {
                    p.insert(field.to_string(), value);
                }),
            );
            let err = match FeeSchedule::load(&path) {
                Ok(_) => panic!("a non-canonical {field} must not load"),
                Err(e) => e,
            };
            assert_eq!(err.code(), ERR_FEE_SCHEDULE_PARSE);
            let rendered = err.to_string();
            assert!(rendered.contains(field), "must name the field: {rendered}");
            assert!(
                rendered.contains(needle),
                "must say what is wrong ({needle}): {rendered}"
            );
        }

        // A JSON number is refused too, by the type rather than by a check —
        // the canonicaliser cannot hash one at all (RFC 8785 §3.2.2.3), which
        // is why the spec says "All integers/timestamps are decimal strings".
        //
        // Written with an arbitrary declared hash rather than through
        // `write_schedule`, because there is no hash to declare: a payload
        // carrying a number has no canonical bytes, so an operator could not
        // publish this file even if `load` accepted it.
        fs::write(
            &path,
            super::super::runtime::test_support::fee_schedule_json(
                &format!("0x{}", "ea".repeat(32)),
                &payload_with(|p| {
                    p.insert("decimals".to_string(), serde_json::json!(6));
                }),
            ),
        )
        .unwrap();
        let err = FeeSchedule::load(&path).expect_err("a JSON number is not a decimal string");
        assert_eq!(err.code(), ERR_FEE_SCHEDULE_PARSE);
        assert!(
            err.to_string().contains("$.decimals"),
            "the numeric field must be named — this is why the canonicaliser runs before the \
             typed parse, whose message is only \"invalid type: integer `6`, expected a \
             string\" with no field: {err}"
        );

        // An inverted validity window: not a spelling, but the same class of
        // "no operator can have meant this".
        write_schedule(
            &path,
            &payload_with(|p| {
                p.insert("validAfter".to_string(), "100".into());
                p.insert("validUntil".to_string(), "99".into());
            }),
        );
        let err = FeeSchedule::load(&path).expect_err("an inverted validity window must not load");
        assert!(
            err.to_string().contains("validAfter") && err.to_string().contains("validUntil"),
            "{err}"
        );

        // Paired positive arm: the canonical spellings load.
        write_schedule(
            &path,
            &super::super::runtime::test_support::schedule_payload_json(None),
        );
        FeeSchedule::load(&path).expect("the canonical fixture must load");
    }

    /// The digest is over the payload's VALUES, not over the file's bytes:
    /// reordering members or reflowing whitespace must not move it, and
    /// changing any amount must.
    ///
    /// This is the property the whole task turns on, and it is the one thing
    /// the old declared-tag design could not offer. It is also what makes the
    /// operator note safe to edit: metadata lives outside `payload`.
    ///
    /// **Which spec passage governs.** §8.1 of the
    /// "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring" spec — the *fee
    /// schedule* paragraph — is the citation for this claim:
    /// it fixes the schedule payload's field list at exactly eleven
    /// names (neither `note` nor `feeScheduleHash` among them) and says that
    /// payload "uses the same RFC 8785/UTF-8 rules as the deployment manifest".
    /// `:244` is the *deployment manifest* paragraph, and is only where the
    /// sentence "Approval metadata is outside the payload" happens to be
    /// written; it is inherited here, not governing. (Corrected 2026-07-27 —
    /// this doc previously cited `:244-246` alone, the same mix-up
    /// `FeeSchedule::load`'s "What is still NOT covered" bullet had.)
    ///
    /// **Mutation this detects (applied, run, reverted):** folding the
    /// approval metadata into the hashed object — inserting the file's `note`
    /// into the payload before `canonical_hash` — after which the reflowed
    /// file with a different note hashes differently and the first assertion
    /// fails with "the operator note is not part of the digest".
    #[test]
    fn fee_schedule_digest_covers_payload_values_not_file_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fee_schedule.json");
        let payload = payload_with(|p| set_action_fee(p, ActionType::SponsoredEnrollment, Some("500000")));
        write_schedule(&path, &payload);
        let baseline = FeeSchedule::load(&path).unwrap().computed_fee_schedule_hash();

        // Same members, different order and whitespace, and a different note
        // — none of which is part of the payload's value.
        let reordered = format!(
            "{{ \"note\"  : \"a completely different note\",\n  \"payload\": {payload},\n \
             \"feeScheduleHash\": \"{}\",\n\t\"schemaVersion\": 2 }}",
            super::super::runtime::test_support::schedule_hash_hex(&payload)
        );
        fs::write(&path, reordered).unwrap();
        assert_eq!(
            FeeSchedule::load(&path).unwrap().computed_fee_schedule_hash(),
            baseline,
            "member order, whitespace and the operator note are not part of the digest"
        );

        // One digit of one tariff, and the digest must move. This is the edit
        // the previous design accepted in silence.
        let bumped = payload_with(|p| set_action_fee(p, ActionType::SponsoredEnrollment, Some("500001")));
        write_schedule(&path, &bumped);
        assert_ne!(
            FeeSchedule::load(&path).unwrap().computed_fee_schedule_hash(),
            baseline,
            "an edited tariff MUST change feeScheduleHash"
        );

        // And so must a ceiling nobody in this build reads yet: everything in
        // the payload is approved, so everything in the payload binds.
        let ceiling = payload_with(|p| {
            set_action_fee(p, ActionType::SponsoredEnrollment, Some("500000"));
            p.get_mut("gasUnitCeilings")
                .and_then(serde_json::Value::as_object_mut)
                .unwrap()
                .insert(
                    ActionType::SponsoredEnrollment.as_str().to_string(),
                    "120000".into(),
                );
        });
        write_schedule(&path, &ceiling);
        assert_ne!(
            FeeSchedule::load(&path).unwrap().computed_fee_schedule_hash(),
            baseline,
            "an edited gas ceiling MUST change feeScheduleHash"
        );
    }

    // -- Task 11 Wave 0: schema version, governance tag, shipped file ------

    /// `schemaVersion` was parsed and thrown away (`#[allow(dead_code)]`), so
    /// a file written for a *future* format loaded silently under today's
    /// rules — tariffs read with the wrong semantics, and no operator signal.
    ///
    /// Both versions are checked, because there are two: the container's
    /// ([`FEE_SCHEDULE_SCHEMA_VERSION`], "how this process reads the file")
    /// and the payload's ([`SCHEDULE_PAYLOAD_SCHEMA_VERSION`], one of the
    /// eleven hashed fields, "which schedule schema governance approved").
    ///
    /// **Mutations this detects:** deleting the
    /// `file.schema_version != FEE_SCHEDULE_SCHEMA_VERSION` check from `load`
    /// — version `3` then loads, because nothing else in the file is wrong
    /// (this half is inherited from the version of this test that predates the
    /// payload, where it was applied, run and reverted); and, **applied, run
    /// and reverted here**, deleting the
    /// `p.schema_version != SCHEDULE_PAYLOAD_SCHEMA_VERSION` check — the future
    /// payload then loads and its `expect_err` panics.
    #[test]
    fn fee_schedule_load_refuses_an_unsupported_schema_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fee_schedule.json");
        let payload = super::super::runtime::test_support::schedule_payload_json(None);
        let hash = super::super::runtime::test_support::schedule_hash_hex(&payload);
        let body = |v: u64| {
            format!(r#"{{"schemaVersion": {v}, "feeScheduleHash": "{hash}", "payload": {payload}}}"#)
        };

        fs::write(&path, body(3)).unwrap();
        let err = FeeSchedule::load(&path).expect_err("schemaVersion 3 is not this build's format");
        assert_eq!(err.code(), ERR_FEE_SCHEDULE_PARSE);
        assert!(
            err.to_string().contains("unsupported schemaVersion 3"),
            "the operator must be told which version was found: {err}"
        );

        // A future PAYLOAD schema, inside a container this build does read.
        write_schedule(
            &path,
            &payload_with(|p| {
                p.insert("schemaVersion".to_string(), "2".into());
            }),
        );
        let err = FeeSchedule::load(&path).expect_err("a future payload schema must not load");
        assert!(
            err.to_string().contains("payload.schemaVersion"),
            "the operator must be told WHICH version is unsupported: {err}"
        );

        // Paired positive arm: the supported versions load, so the refusals
        // above are about the versions and not about the rest of the file.
        fs::write(&path, body(FEE_SCHEDULE_SCHEMA_VERSION)).unwrap();
        FeeSchedule::load(&path).expect("this build's own format must load");
    }

    /// **A v1 file must not produce a bare serde error.**
    ///
    /// `deny_unknown_fields` turns the v1 → v2 shape change into
    /// `unknown field \`tariffs\``, which tells an operator nothing about what
    /// changed, that `feeScheduleHash` now means something else, or how to
    /// regenerate the file. `load` therefore reads `schemaVersion` before the
    /// typed parse and answers with the migration text.
    ///
    /// **Mutation this detects (applied, run, reverted):** deleting the
    /// `Some(1)` peek from `load` — the file then falls through to serde,
    /// which answers `unknown field \`tariffs\`, expected one of
    /// \`schemaVersion\`, \`feeScheduleHash\`, \`note\`, \`payload\``, and the
    /// assertions on the migration text fail. That message is not wrong; it is
    /// just useless to the person holding the file.
    #[test]
    fn fee_schedule_load_tells_an_operator_how_to_migrate_a_v1_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fee_schedule.json");
        // The exact SHAPE this repo shipped before the change: `schemaVersion:
        // 1`, a flat `tariffs` map, and no `payload`. The declared hash is a
        // deliberately synthetic `0x1111…`, not the retired
        // `keccak256("stream-g-fee-schedule-g1")` tag the shipped v1 file
        // actually carried. Two reasons: nothing below reads the value (the
        // assertions are all about the migration *text*, and `load` rejects the
        // file on `schemaVersion` before it looks at any other field), and the
        // retired tag is now absent from this repository — a grep for it should
        // return nothing rather than one hit in a test that does not depend on
        // it.
        fs::write(
            &path,
            r#"{
                "schemaVersion": 1,
                "feeScheduleHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "note": "the shipped v1 placeholder",
                "tariffs": {}
            }"#,
        )
        .unwrap();

        let err = FeeSchedule::load(&path).expect_err("a v1 file is not this build's format");
        assert_eq!(err.code(), ERR_FEE_SCHEDULE_PARSE);
        let rendered = err.to_string();
        for needle in [
            // what it is
            "schemaVersion 1",
            // what changed, in both directions
            "tariffs",
            "payload",
            "actionFeesRaw",
            // that the meaning of the hash changed, not just its shape
            "keccak256(UTF8(RFC8785(payload)))",
            // how to represent "no tariff" now that keys cannot be omitted
            "null",
            // what to do about the deployment
            "STREAM_G_FEE_SCHEDULE_HASH",
            // where to look
            "fixtures/stream_g_fee_schedule.json",
        ] {
            assert!(
                rendered.contains(needle),
                "the migration message must mention {needle:?}: {rendered}"
            );
        }
        assert!(
            !rendered.contains("unknown field"),
            "a bare serde error is what this arm exists to prevent: {rendered}"
        );
    }

    /// The declared `feeScheduleHash` is **required** and must be a 32-byte
    /// hex string.
    ///
    /// A declaration that could be absent or malformed-but-accepted would
    /// defeat the binding: `runtime::StreamGState::start`'s comparison would be
    /// against a value no operator chose.
    ///
    /// Note what `load` does NOT do here: it does not check the declaration
    /// against the payload's digest. Case (c) below loads a file that declares
    /// `0xeaea…` for a payload that hashes to something else, and that is
    /// deliberate — the comparison belongs to `start`, which alone can also
    /// weigh the manifest and tell the two failures apart.
    ///
    /// **Mutation this detects (applied, run, reverted):** making a malformed
    /// declaration non-fatal —
    /// `parse_bytes32(&file.fee_schedule_hash).unwrap_or([0u8; 32])` — after
    /// which case (b) loads and its `expect_err` panics.
    ///
    /// **Mutation this does NOT detect, checked rather than assumed:** adding
    /// `#[serde(default)]` to `FeeScheduleFile::fee_schedule_hash`. That was
    /// the mutation originally claimed here, and running it showed the test
    /// still passes — `default` yields `""`, which `parse_bytes32` rejects, so
    /// an omitted value is *still* refused and the security property survives.
    /// Case (a) below therefore pins "an omitted declaration does not load",
    /// which is true under both spellings, and does **not** pin the
    /// `deny_unknown_fields` / required-field spelling specifically.
    #[test]
    fn fee_schedule_load_requires_a_well_formed_declared_hash() {
        let dir = tempfile::tempdir().unwrap();
        let payload = super::super::runtime::test_support::schedule_payload_json(None);

        // (a) omitted entirely.
        let a = dir.path().join("a.json");
        fs::write(
            &a,
            format!(r#"{{"schemaVersion": 2, "payload": {payload}}}"#),
        )
        .unwrap();
        let err_a = FeeSchedule::load(&a).expect_err("feeScheduleHash is not optional");
        assert_eq!(err_a.code(), ERR_FEE_SCHEDULE_PARSE);

        // (b) present but not 32 bytes.
        let b = dir.path().join("b.json");
        fs::write(
            &b,
            format!(
                r#"{{"schemaVersion": 2, "feeScheduleHash": "0xdeadbeef", "payload": {payload}}}"#
            ),
        )
        .unwrap();
        let err_b = FeeSchedule::load(&b).expect_err("a short hash is not a bytes32");
        assert_eq!(err_b.code(), ERR_FEE_SCHEDULE_PARSE);
        assert!(
            err_b.to_string().contains("feeScheduleHash"),
            "the error must name the field: {err_b}"
        );

        // Paired positive arm: a well-formed declaration round-trips verbatim,
        // and is kept apart from the computed digest.
        let c = dir.path().join("c.json");
        fs::write(
            &c,
            format!(
                r#"{{"schemaVersion": 2, "feeScheduleHash": "0x{}", "payload": {payload}}}"#,
                "ea".repeat(32)
            ),
        )
        .unwrap();
        let schedule = FeeSchedule::load(&c).unwrap();
        assert_eq!(schedule.declared_fee_schedule_hash(), [0xEAu8; 32]);
        assert_ne!(
            schedule.computed_fee_schedule_hash(),
            [0xEAu8; 32],
            "the computed digest must be a function of the payload, not an echo of the \
             declaration — otherwise `start`'s comparison could never fail"
        );
    }

    /// **Ruling 5 / the Season-0 placeholder, pinned as an artifact test.**
    ///
    /// `fixtures/stream_g_fee_schedule.json` is the schedule this repo ships.
    /// Four properties, all load-bearing:
    ///
    /// 1. it loads (so it is a real file in the real format, not prose);
    /// 2. its payload hashes to the `feeScheduleHash` it declares — it is a
    ///    *published* file, self-consistent under the rule at
    ///    the "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring"
    ///    spec, §8.1, and
    ///    the hex below is the known-answer fixture later phases need;
    /// 3. it yields **no tariff for any action**, so the quote path refuses
    ///    with `MISSING_TARIFF` until the founder sets the numbers;
    /// 4. its note tells an operator all of that.
    ///
    /// Property 3 is why every `actionFeesRaw` entry is `null` rather than a
    /// stand-in amount: any parseable number — `"0"` included — would be
    /// signed verbatim into the EIP-712 `FeeQuote`
    /// (`models::fee_quote_struct_hash`), where nothing downstream could tell a
    /// placeholder price from a real one. The keys themselves cannot be
    /// omitted, because the spec requires all four to be present.
    ///
    /// **What this test deliberately no longer asserts:** that the declared
    /// hash equals `keccak256("stream-g-fee-schedule-g1")`. That tag is a label,
    /// and `feeScheduleHash` is now a digest of the payload; no payload hashes
    /// to it, so asserting it here would be asserting a value this file can no
    /// longer legitimately carry. The tag is now retired everywhere it was
    /// pinned: `contracts/deployments/31337.stream-g.json` carries the value
    /// below, `contracts/script/DeployStreamG.s.sol` no longer defaults
    /// `STREAM_G_FEE_SCHEDULE_HASH` at all (`vm.envBytes32`, required), and
    /// `contracts/test/DeployStreamG.t.sol`'s `SHIPPED_FEE_SCHEDULE_HASH` — the
    /// params that *rewrite* that artifact on every `forge test` — is the value
    /// below too.
    ///
    /// Re-pointing an **already-deployed** gateway at a new schedule is not a
    /// redeploy: it is a `setFeeScheduleHash` transaction from the Policy Safe
    /// (`contracts/src/GoatRelayGateway.sol:154-157`, `onlyPolicy`), because
    /// that is the only writer of the value each quote is checked against at
    /// `contracts/src/libraries/StreamGCommon.sol:122-124`.
    ///
    /// **Mutation this detects (applied, run, reverted):** putting
    /// `"GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1": "999999999"` into the shipped
    /// file — assertions 2 and 3 both fail.
    #[test]
    fn shipped_placeholder_fee_schedule_is_published_and_serves_no_price() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("stream_g_fee_schedule.json");

        let schedule = FeeSchedule::load(&path)
            .expect("the shipped fee schedule must load with the shipped loader");

        // The known-answer BYTES of the shipped payload — the spec asks
        // fixtures to pin these, not only the hash, because the bytes are what
        // a JavaScript or ops implementation has to reproduce before the hash
        // can agree. Sorted per RFC 8785 §3.2.3, no whitespace. Note
        // "scheduleVersion" before "schemaVersion": at index 4, 'd' (0x64) <
        // 'm' (0x6D). That is not the order a human sorts those two by eye.
        const SHIPPED_CANONICAL_BYTES: &str = concat!(
            r#"{"actionFeesRaw":{"GOAT_STREAM_G_GOAT_TRANSFER_V1":null,"#,
            r#""GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1":null,"#,
            r#""GOAT_STREAM_G_SPONSORED_SELL_V1":null,"#,
            r#""GOAT_STREAM_G_USDT_TRANSFER_V1":null},"#,
            r#""calldataByteCeilings":{"GOAT_STREAM_G_GOAT_TRANSFER_V1":"0","#,
            r#""GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1":"0","#,
            r#""GOAT_STREAM_G_SPONSORED_SELL_V1":"0","#,
            r#""GOAT_STREAM_G_USDT_TRANSFER_V1":"0"},"#,
            r#""chainId":"31337","decimals":"6","#,
            r#""feeToken":"0xddc10602782af652bb913f7bde1fd82981db7dd9","#,
            r#""gasUnitCeilings":{"GOAT_STREAM_G_GOAT_TRANSFER_V1":"0","#,
            r#""GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1":"0","#,
            r#""GOAT_STREAM_G_SPONSORED_SELL_V1":"0","#,
            r#""GOAT_STREAM_G_USDT_TRANSFER_V1":"0"},"#,
            r#""maxNativeExposureWei":"0","scheduleVersion":"1","schemaVersion":"1","#,
            r#""validAfter":"0","validUntil":"0"}"#
        );
        let file: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            String::from_utf8(crate::canonical_bytes(&file["payload"]).unwrap()).unwrap(),
            SHIPPED_CANONICAL_BYTES,
            "the canonical bytes are the fixture a JavaScript/ops implementation reproduces"
        );
        assert_eq!(
            SHIPPED_CANONICAL_BYTES.len(),
            728,
            "canonical byte length is part of the fixture"
        );

        // The known-answer hash of those bytes. Later phases (the JavaScript
        // and ops fixtures the spec requires, and the on-chain publication)
        // need this exact value. Cross-checked against an independent keccak
        // implementation — foundry `cast keccak` over the bytes above supplied
        // as hex — so it is not merely self-consistent with our own
        // tiny-keccak call.
        const SHIPPED_FEE_SCHEDULE_HASH: &str =
            "1c663d43fccc550dd95ef9dcd469eb12ac98006d355fea4ce9fcdc002ff8d952";
        assert_eq!(
            hex::encode(schedule.computed_fee_schedule_hash()),
            SHIPPED_FEE_SCHEDULE_HASH,
            "the shipped payload's digest moved; this constant is what an operator publishes \
             as STREAM_G_FEE_SCHEDULE_HASH, so it may only change with a deliberate republish"
        );
        assert_eq!(
            schedule.declared_fee_schedule_hash(),
            schedule.computed_fee_schedule_hash(),
            "the shipped file must declare its own payload's digest, or `start` would refuse it"
        );

        // No action may serve a price.
        for action in [
            ActionType::SponsoredEnrollment,
            ActionType::SponsoredSell,
            ActionType::GoatTransfer,
            ActionType::UsdtTransfer,
        ] {
            let err = match schedule.fee_for(action) {
                Ok(amount) => panic!(
                    "{action:?} must have no tariff in the placeholder schedule, but it served \
                     {amount}: the Season-0 tariffs are NOT decided numbers"
                ),
                Err(e) => e,
            };
            assert_eq!(err.code(), ERR_MISSING_TARIFF, "{action:?}");
        }

        // The file must say so in words an operator will see: `start` logs
        // this note.
        let note = schedule.note().expect("the placeholder must carry a note");
        assert!(
            note.contains("PLACEHOLDER"),
            "the note must be unmistakable: {note}"
        );
        assert!(
            note.contains("STREAM_G_FEE_SCHEDULE_HASH"),
            "the note must tell an operator how to publish the digest: {note}"
        );
    }

    /// The ops leg: [`super::canonical_schedule_payload_bytes`] must answer the
    /// SAME bytes the loader hashes, so `main.rs`'s `fee-schedule-hash`
    /// subcommand cannot print a digest the running process would disagree
    /// with.
    ///
    /// The "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring" spec,
    /// §8.1,
    /// asks for "Rust/JavaScript/ops fixtures". The Rust leg is
    /// `shipped_placeholder_fee_schedule_is_published_and_serves_no_price` and
    /// the JavaScript leg is `contracts/test/StreamGManifest.test.mjs`; this
    /// pins that the ops leg is not a THIRD canonicaliser but a view onto the
    /// first one. The claim is made by recomputing the digest from the bytes
    /// the function returned and comparing it to
    /// [`FeeSchedule::computed_fee_schedule_hash`], which `from_json` produced
    /// independently — so a second implementation that agreed on the hash but
    /// not on the bytes, or vice versa, fails here.
    ///
    /// The two refusals matter as much as the agreement: the function must
    /// route through `crate::canonical_bytes`, which REFUSES a JSON number
    /// (RFC 8785 §3.2.2.3 mandates ECMAScript `Number::toString`, which
    /// serde_json does not implement). A CLI that quietly hashed a number would
    /// hand a founder a digest JavaScript cannot reproduce, which is precisely
    /// the failure the three-way fixture exists to prevent.
    ///
    /// **Mutation this detects:** replacing the `crate::canonical_bytes` call
    /// with `serde_json::to_vec` — the number payload is then accepted and the
    /// `expect_err` panics.
    #[test]
    fn canonical_schedule_payload_bytes_are_the_bytes_the_loader_hashes() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("stream_g_fee_schedule.json");
        let raw = fs::read_to_string(&path).expect("the shipped schedule must be readable");

        let bytes = super::canonical_schedule_payload_bytes(&raw, &path.display().to_string())
            .expect("the shipped payload must canonicalise");
        assert_eq!(
            bytes.len(),
            728,
            "the ops leg must produce the same 728 canonical bytes the Rust and JavaScript \
             fixtures pin"
        );

        let schedule = FeeSchedule::load(&path).expect("the shipped schedule must load");
        assert_eq!(
            crate::merkle::keccak256(&bytes),
            schedule.computed_fee_schedule_hash(),
            "the bytes the CLI prints must be the bytes the loader hashed, or the printed \
             digest is a claim about a document the process never read"
        );
        assert_eq!(
            hex::encode(crate::merkle::keccak256(&bytes)),
            "1c663d43fccc550dd95ef9dcd469eb12ac98006d355fea4ce9fcdc002ff8d952",
            "the value an operator publishes as STREAM_G_FEE_SCHEDULE_HASH"
        );

        // A file with no `payload` is told what a fee-schedule file looks like,
        // rather than being handed the digest of `null`.
        let err = super::canonical_schedule_payload_bytes(
            r#"{"schemaVersion":2,"feeScheduleHash":"0x00"}"#,
            "<test>",
        )
        .expect_err("a file with no payload has no digest");
        assert!(
            format!("{err}").contains("no `payload` object"),
            "unexpected: {err}"
        );

        // Routed through `crate::canonical_bytes`, so its refusals apply.
        let err = super::canonical_schedule_payload_bytes(r#"{"payload":{"chainId":31337}}"#, "<test>")
            .expect_err("a JSON number is unhashable on both sides of the parity pair");
        assert!(
            format!("{err}").contains("JSON number at $.chainId"),
            "unexpected: {err}"
        );
    }

    /// The three payload fields `runtime::StreamGState::start` compares
    /// against the deployment come out of `load` as the values the file
    /// declared — and the fee token comes out as BYTES, not as the text.
    ///
    /// Without this, the startup comparison could be satisfied by an accessor
    /// that returned a constant: the runtime tests would still pass, because
    /// the fixture and the manifest agree on these values anyway. Reading the
    /// SHIPPED file (31337 / `0xddc1…` / 6) and separately a payload that
    /// disagrees on all three is what makes the accessors non-constant.
    ///
    /// The byte-vs-text half is the case-sensitivity guard from the other
    /// side: `token_manifest::DeploymentManifest::fee_token` is a `[u8; 20]`
    /// decoded from a checksummed spelling, so an accessor returning the
    /// payload's lowercase text could never equal it.
    ///
    /// **Mutation this detects:** having `payload_chain_id` return a constant,
    /// or `payload_fee_token` return the source text's bytes — the second
    /// schedule's assertions fail.
    #[test]
    fn load_exposes_the_payload_fields_start_compares() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("stream_g_fee_schedule.json");
        let shipped = FeeSchedule::load(&path).expect("the shipped schedule must load");
        assert_eq!(shipped.payload_chain_id(), 31337);
        assert_eq!(
            hex::encode(shipped.payload_fee_token()),
            "ddc10602782af652bb913f7bde1fd82981db7dd9",
            "the accessor must answer the 20 decoded bytes, with no 0x and no case"
        );
        assert_eq!(shipped.payload_decimals(), 6);

        // A payload that disagrees on all three, so none of the assertions
        // above can be satisfied by a hard-coded accessor.
        let foreign = super::super::runtime::test_support::schedule_payload_json_for(
            "8453",
            "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "18",
            Some("1000000000000000000"),
        );
        let foreign_file = super::super::runtime::test_support::fee_schedule_json(
            &super::super::runtime::test_support::schedule_hash_hex(&foreign),
            &foreign,
        );
        let other = FeeSchedule::from_json(&foreign_file, "<test>")
            .expect("a foreign payload is well-formed; it is refused at startup, not at parse");
        assert_eq!(other.payload_chain_id(), 8453);
        assert_eq!(
            hex::encode(other.payload_fee_token()),
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        );
        assert_eq!(other.payload_decimals(), 18);
    }

    /// [`BUILTIN_FEE_SCHEDULE_JSON`] is the shipped fixture, and it loads
    /// through the same parser a file does.
    ///
    /// The `include_str!` makes the first half true by construction, so this
    /// asserts the part that is not: that the embedded bytes go through
    /// [`FeeSchedule::from_json`] to the same digest
    /// `shipped_placeholder_fee_schedule_is_published_and_serves_no_price`
    /// pins from the file's side, and set no tariff. Together those two are
    /// what `runtime::StreamGState::start` relies on when nobody configured a
    /// path: it starts, and it still refuses every quote.
    ///
    /// **Mutation this detects (applied, run, reverted):** pointing
    /// `BUILTIN_FEE_SCHEDULE_JSON` at a different file — the byte comparison
    /// and the digest assertion both fail.
    #[test]
    fn builtin_fee_schedule_is_the_shipped_fixture_and_sets_no_tariff() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("stream_g_fee_schedule.json");
        assert_eq!(
            BUILTIN_FEE_SCHEDULE_JSON,
            fs::read_to_string(&path).unwrap(),
            "the built-in must be the shipped fixture verbatim"
        );

        let embedded = FeeSchedule::from_json(BUILTIN_FEE_SCHEDULE_JSON, "<test>")
            .expect("the built-in must load through the file loader, not a second parser");
        let from_file = FeeSchedule::load(&path).unwrap();
        assert_eq!(
            embedded.computed_fee_schedule_hash(),
            from_file.computed_fee_schedule_hash(),
            "reading the bytes from memory and from disk must yield one digest"
        );
        assert_eq!(
            embedded.declared_fee_schedule_hash(),
            embedded.computed_fee_schedule_hash(),
            "a self-inconsistent built-in could never start"
        );
        assert!(
            !embedded.has_any_tariff(),
            "the built-in must set NO tariff: zero-config STARTUP is not zero-config QUOTING, \
             and an invented amount would be signed verbatim into an EIP-712 FeeQuote"
        );
    }

    // -- M11: parser edge cases -------------------------------------------

    /// M11. `parse_bytes32`'s length guard is `h.len() != 64`. Relaxing it
    /// to `h.len() > 64` — a plausible "be lenient about short hex" edit —
    /// turns every short input into a `copy_from_slice` **PANIC** (length
    /// mismatch, `out` is `[u8; 32]`) instead of a typed `BAD_DIGEST`. In
    /// an HTTP handler that is a 500 and a poisoned task, from a one-line
    /// request field.
    ///
    /// **Mutation this detects:** `!=` → `>` (or `>=`, or deleting the
    /// guard) in `parse_bytes32`. Every short case below panics under it.
    #[test]
    fn parse_bytes32_rejects_every_wrong_length_without_panicking() {
        let too_short = ["", "0x", "0x00", "abcd"];
        let odd_and_long: [String; 3] = [
            format!("0x{}", "ab".repeat(31)), // 62 chars
            format!("0x{}", "ab".repeat(33)), // 66 chars
            "0x".to_string() + &"a".repeat(63),
        ];
        for s in too_short
            .iter()
            .map(|s| s.to_string())
            .chain(odd_and_long.iter().cloned())
        {
            // A `>` guard would panic inside `copy_from_slice` here rather
            // than reaching this line at all.
            let err = parse_bytes32("intent_id_hex", &s).unwrap_err();
            assert_eq!(err.code(), ERR_BAD_DIGEST, "input {s:?}");
            assert!(matches!(
                err,
                QuoteError::BadDigest {
                    field: "intent_id_hex",
                    ..
                }
            ));
        }

        // Right length, not hex.
        let not_hex = "z".repeat(64);
        assert_eq!(
            parse_bytes32("intent_id_hex", &not_hex).unwrap_err().code(),
            ERR_BAD_DIGEST
        );

        // Controls, so this cannot be satisfied by rejecting everything:
        // 0x-prefixed, 0X-prefixed, bare, and surrounded by whitespace.
        let body = "ab".repeat(32);
        for good in [
            format!("0x{body}"),
            format!("0X{body}"),
            body.clone(),
            format!("  0x{body}  "),
        ] {
            assert_eq!(
                parse_bytes32("intent_id_hex", &good).unwrap(),
                [0xABu8; 32],
                "input {good:?}"
            );
        }
    }

    /// M11. Same class for the 20-byte address parser: the `h.len() != 40`
    /// guard is the only thing between a short input and a
    /// `copy_from_slice` panic on a `[u8; 20]`.
    #[test]
    fn parse_address20_rejects_every_wrong_length_without_panicking() {
        let bads: [String; 5] = [
            String::new(),
            "0x".to_string(),
            "0x1234".to_string(),
            format!("0x{}", "ab".repeat(19)),
            format!("0x{}", "ab".repeat(21)),
        ];
        for s in bads {
            // A `>` guard would panic inside `copy_from_slice` here.
            let err = parse_address20("root_address", &s).unwrap_err();
            assert_eq!(err.code(), ERR_BAD_ADDRESS, "input {s:?}");
            assert!(matches!(
                err,
                QuoteError::BadAddress {
                    field: "root_address",
                    ..
                }
            ));
        }

        let not_hex = "z".repeat(40);
        assert_eq!(
            parse_address20("root_address", &not_hex)
                .unwrap_err()
                .code(),
            ERR_BAD_ADDRESS
        );

        let body = "ab".repeat(20);
        for good in [format!("0x{body}"), format!("0X{body}"), body.clone()] {
            assert_eq!(
                parse_address20("root_address", &good).unwrap(),
                [0xABu8; 20]
            );
        }
    }

    /// M11. `parse_u128_decimal` is the only thing standing between a
    /// request string and the `maxFee` / `maxFeePerGas` arithmetic.
    ///
    /// **Mutation this detects:** widening to `parse::<u128>().unwrap_or(0)`
    /// — every case below would silently become `0`, which for `max_fee`
    /// means `FeeExceedsMax` on a request that was actually garbage, and
    /// for `max_fee_per_gas_wei` means an exposure gate computed against a
    /// zero gas price (i.e. always passing).
    #[test]
    fn parse_u128_decimal_rejects_everything_that_is_not_a_plain_u128() {
        for bad in [
            "",
            "abc",
            "-1",
            "1.5",
            "0x10",
            "1e6",
            "1_000",
            // u128::MAX + 1
            "340282366920938463463374607431768211456",
        ] {
            let err = parse_u128_decimal("max_fee", bad).unwrap_err();
            assert_eq!(err.code(), ERR_BAD_AMOUNT, "input {bad:?}");
            assert!(matches!(
                err,
                QuoteError::BadAmount {
                    field: "max_fee",
                    ..
                }
            ));
        }

        assert_eq!(parse_u128_decimal("max_fee", "0").unwrap(), 0);
        assert_eq!(parse_u128_decimal("max_fee", " 42 ").unwrap(), 42);
        assert_eq!(
            parse_u128_decimal("max_fee", "340282366920938463463374607431768211455").unwrap(),
            u128::MAX
        );
    }

    /// **Log-line forgery, closed at the source.**
    ///
    /// `super::http_error::ApiError::into_response` renders an error's
    /// `Display` into a `tracing` field with `%` (`http_error.rs:249`,
    /// `:257`), and the default `fmt` visitor writes that **unescaped**. JSON
    /// strings may contain newlines, so while these three parsers carried
    /// `s.to_string()` a caller could forge whole log lines through
    /// `root_address` / `secondary_address` / `intent_id_hex` on
    /// `POST /v1/stream-g/quotes` — the first mounted route that feeds
    /// free-form caller hex into them.
    ///
    /// The error is rendered through the real `IntoResponse` rather than by
    /// inspecting `Display`, because the response path is where the escaping
    /// decision actually lives; asserting on `to_string()` alone would pass
    /// even if `into_response` reintroduced the input from somewhere else.
    ///
    /// Mutation this detects (applied, run, reverted): giving
    /// [`parse_address20`] back a variant that carries `raw: s.to_string()`
    /// with an `#[error("bad address in {field}: {raw}")]` string. The captured
    /// log then reads, verbatim and unescaped,
    /// `detail=bad address in root_address: 0xdeadbeef` followed by a real
    /// newline and `level=ERROR forged: …` — and the line-count assertion
    /// fails with 2 where 1 was expected.
    #[tokio::test]
    async fn a_newline_in_a_caller_hex_field_cannot_forge_a_log_line() {
        use axum::response::IntoResponse;
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        // Same shape as `http_error::tests::CapturedLog` and
        // `mod.rs::tests::CapturedLog`, duplicated for the same reason those
        // two are: each is private to its own `mod tests`.
        #[derive(Clone)]
        struct CapturedLog(Arc<Mutex<Vec<u8>>>);

        impl Write for CapturedLog {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::writer::MakeWriter<'a> for CapturedLog {
            type Writer = CapturedLog;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        // Without this the `tracing::warn!` at `http_error.rs:257` can already
        // be cached process-wide as `Interest::never()` by a subscriber-less
        // test that rendered an `ApiError` first, and the capture below reads
        // empty — see `crate::stream_g::log_capture`.
        crate::stream_g::log_capture::install_interest_keepalive();

        // A well-formed JSON string value: `serde_json` accepts `\n` and hands
        // the handler a real newline, so this is exactly what arrives from the
        // wire.
        let injected: String = serde_json::from_str(
            r#""0xdeadbeef\nlevel=ERROR forged: the operator log now says whatever I want""#,
        )
        .expect("a JSON string may carry a newline — that is the whole attack");
        assert!(injected.contains('\n'), "the fixture must carry a newline");

        let err = parse_address20("root_address", &injected)
            .expect_err("a newline-bearing address must be refused");

        let buf = CapturedLog(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        {
            let _guard = tracing::subscriber::set_default(subscriber);
            let _ = crate::stream_g::http_error::ApiError::from(err).into_response();
        }

        let log = String::from_utf8_lossy(
            &buf.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
        .into_owned();

        // Paired non-zero arm first: something really was logged, so the
        // counts below are not counting an empty buffer.
        assert!(
            log.contains(ERR_BAD_ADDRESS),
            "the refusal must still reach the operator: {log:?}"
        );
        assert_eq!(
            log.lines().count(),
            1,
            "the caller's newline produced a second log line: {log:?}"
        );
        assert!(
            !log.contains("forged"),
            "caller bytes reached the operator log: {log:?}"
        );
        assert!(
            log.contains("root_address"),
            "the field name is the diagnostic that replaced the echo: {log:?}"
        );
    }

    /// M11, end to end. The three parse errors above were dead in the suite
    /// as *pipeline* outcomes too: no test ever fed
    /// `create_sponsored_enrollment_quote` a malformed field. Each case
    /// mutates exactly ONE field of an otherwise-valid request, so the code
    /// asserted is attributable to that field.
    ///
    /// **Mutation this detects:** dropping any of the three `?`s
    /// (`parse_enrollment_fields`, `parse_u128_decimal(&req.max_fee_per_gas_wei)`,
    /// `parse_u128_decimal(&req.max_fee)`) in favour of a lenient default.
    #[tokio::test]
    async fn malformed_request_fields_surface_as_typed_codes_not_panics() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-malformed").await;
        let profile = AuthenticatedProfileId::for_test("profile-malformed");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let mk = |key: &str| {
            base_request(
                root,
                controller,
                secondary,
                key,
                0,
                9_999_999_999,
                &v1_sig,
                0,
                9_999_999_999,
                &link_sig,
                1_000_000,
            )
        };

        // A truncated intentId -> BAD_DIGEST.
        let mut bad_digest = mk("idem-bad-digest");
        bad_digest.intent_id_hex = "0x1234".to_string();
        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            bad_digest,
        )
        .await
        .expect_err("a truncated intentId must be rejected");
        assert_eq!(err.code(), ERR_BAD_DIGEST);

        // A non-hex root address -> BAD_ADDRESS.
        let mut bad_address = mk("idem-bad-address");
        bad_address.root_address = format!("0x{}", "z".repeat(40));
        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            bad_address,
        )
        .await
        .expect_err("a non-hex address must be rejected");
        assert_eq!(err.code(), ERR_BAD_ADDRESS);

        // A non-numeric maxFeePerGas -> BAD_AMOUNT.
        let mut bad_gas_price = mk("idem-bad-gasprice");
        bad_gas_price.max_fee_per_gas_wei = "one gwei".to_string();
        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            bad_gas_price,
        )
        .await
        .expect_err("a non-numeric maxFeePerGas must be rejected");
        assert_eq!(err.code(), ERR_BAD_AMOUNT);

        // A non-numeric maxFee -> BAD_AMOUNT (STEP 3, past the exposure gate).
        let mut bad_max_fee = mk("idem-bad-maxfee");
        bad_max_fee.max_fee = "lots".to_string();
        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            bad_max_fee,
        )
        .await
        .expect_err("a non-numeric maxFee must be rejected");
        assert_eq!(err.code(), ERR_BAD_AMOUNT);

        assert_eq!(
            quotes_count(&store).await,
            0,
            "no malformed request may leave a row behind"
        );
    }

    /// M11. `req.valid_for_seconds == 0` was never tested. A zero-length
    /// window is not merely useless: `validAfter == validUntil` fails
    /// `StreamGCommon.validateAndConsumeQuote`'s `block.timestamp < quote.validUntil`
    /// for every possible block, so the quote is dead on arrival.
    ///
    /// **Mutation this detects:** deleting the `req.valid_for_seconds == 0`
    /// disjunct from the STEP 4 policy guard — the call would then succeed
    /// and hand back an unusable signature. The `1` control below shows the
    /// guard is `== 0` and not an over-broad lower bound.
    #[tokio::test]
    async fn quote_rejects_a_zero_length_validity_window() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-zerottl").await;
        let profile = AuthenticatedProfileId::for_test("profile-zerottl");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let mk = |key: &str| {
            base_request(
                root,
                controller,
                secondary,
                key,
                0,
                9_999_999_999,
                &v1_sig,
                0,
                9_999_999_999,
                &link_sig,
                1_000_000,
            )
        };

        let mut zero = mk("idem-zerottl");
        zero.valid_for_seconds = 0;
        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            zero,
        )
        .await
        .expect_err("a zero-length window can never satisfy validAfter <= t < validUntil");
        assert_eq!(err.code(), ERR_VALIDITY_EXCEEDS_POLICY);
        assert_eq!(quotes_count(&store).await, 0);

        // Boundary control: one second IS accepted, so the guard is `== 0`.
        let mut one = mk("idem-onettl");
        one.valid_for_seconds = 1;
        let ok = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            one,
        )
        .await
        .expect("a one-second window is short but representable");
        assert_eq!(ok.valid_until, ok.valid_after + 1);
    }

    /// M11. `ERR_VALIDITY_EXCEEDS_UINT48` was dead in the suite.
    /// `FeeQuote.validUntil` is `uint48` on-chain, so a window that spills
    /// past `2^48 - 1` would be silently truncated by the ABI and the
    /// gateway would recover a different quote hash entirely.
    ///
    /// **Mutation this detects:** deleting the `valid_until > UINT48_MAX`
    /// check (or changing it to `>=`, which the boundary control catches
    /// from the other side).
    #[tokio::test]
    async fn quote_rejects_a_validity_window_that_spills_past_uint48() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-uint48").await;
        let profile = AuthenticatedProfileId::for_test("profile-uint48");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let mk = |key: &str| {
            base_request(
                root,
                controller,
                secondary,
                key,
                0,
                9_999_999_999,
                &v1_sig,
                0,
                9_999_999_999,
                &link_sig,
                1_000_000,
            )
        };

        // Chain time one second short of uint48::MAX; a 300-second window
        // therefore ends 299 seconds past it.
        chain.set_now(UINT48_MAX - 1);
        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            mk("idem-uint48"),
        )
        .await
        .expect_err("a validUntil above uint48::MAX cannot round-trip through FeeQuote");
        assert_eq!(err.code(), ERR_VALIDITY_EXCEEDS_UINT48);
        assert!(matches!(err, QuoteError::ValidityExceedsUint48));
        assert_eq!(quotes_count(&store).await, 0);

        // Boundary control: validUntil == uint48::MAX exactly is
        // representable and must be accepted, so this cannot be satisfied
        // by rejecting every large window.
        chain.set_now(UINT48_MAX - 300);
        let ok = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            mk("idem-uint48-ok"),
        )
        .await
        .expect("validUntil == uint48::MAX is representable");
        assert_eq!(ok.valid_until, UINT48_MAX);
    }

    // =========================================================================
    // -- 12. Independent-verifier fix wave: residual gap closure
    //
    // Task 1: `LiveEnrollmentNonces::read_live` is now the only production
    // constructor. Task 2: R3 anti-TOCTOU binding between `live_token` and
    // `live_nonces`. Task 4: re-quoting an expired intent, per architect
    // ruling.
    // =========================================================================

    // -- 12a. Task 1: LiveEnrollmentNonces::read_live -----------------------

    /// `from_snapshot` used to be `pub` and took an already-built
    /// `&NonceSnapshotView` — an all-`pub`-field, `Default`-deriving struct
    /// any caller could construct from a bare struct literal, no chain, no
    /// mock, no test hatch (the independent verifier proved this compiles
    /// and is accepted: `NonceSnapshotView { present_mask: ..,
    /// ..Default::default() }` then `LiveEnrollmentNonces::from_snapshot(&fake)`
    /// — `Ok`). `read_live` is now the only production constructor and
    /// performs the chain read itself.
    ///
    /// Mutation this test detects: if `read_live` were changed to build a
    /// fixed snapshot instead of calling
    /// `chain.secondary_enrollment_nonce_snapshot`, the
    /// `secondary_enrollment_nonce_snapshot_call_count()` assertion below
    /// would read 0 instead of 1. Verified directly: temporarily replacing
    /// `read_live`'s `chain.secondary_enrollment_nonce_snapshot(..)` call
    /// with a hardcoded literal `NonceSnapshotView` (bypassing `chain`
    /// entirely) made both this test AND the sibling `..._fails_closed_..`
    /// test below fail (this one on the call-count assertion, the sibling
    /// on `unwrap_err()` panicking on an `Ok`); the mutation was then
    /// reverted.
    #[test]
    fn live_enrollment_nonces_read_live_performs_the_real_chain_call() {
        let chain = MockChain::new();
        let gateway = [0x16u8; 20];
        let root = [0x33u8; 20];
        let secondary = [0x77u8; 20];
        let fee_token = [0x12u8; 20];
        let block = 999u64;

        chain.set_nonce_snapshot(gateway, root, secondary, fee_token, full_snapshot());

        let nonces =
            LiveEnrollmentNonces::read_live(&chain, gateway, root, secondary, fee_token, block)
                .expect("full_snapshot() has every relevant bit set");

        assert_eq!(nonces.v1_enroll_nonce(), 3);
        assert_eq!(nonces.link_nonce(), 5);
        assert_eq!(nonces.block_number(), 4242);
        assert_eq!(nonces.fee_token_config_hash(), [0xC0; 32]);
        assert_eq!(
            chain.secondary_enrollment_nonce_snapshot_call_count(),
            1,
            "read_live must perform exactly one secondaryEnrollmentNonceSnapshot call"
        );
    }

    /// Fail-closed chain-read path: no snapshot armed for this
    /// (gateway, root, secondary, feeToken) key at all.
    ///
    /// Mutation this test detects: if `read_live` swallowed the chain
    /// error and used a valid literal snapshot instead of propagating it
    /// via `?`, this would return `Ok` instead of `Err`. Verified by the
    /// same mutation as the sibling test above (`read_live` short-circuited
    /// to a hardcoded literal `NonceSnapshotView` instead of calling
    /// `chain`): this test failed with "called `Result::unwrap_err()` on
    /// an `Ok` value"; the mutation was then reverted.
    #[test]
    fn live_enrollment_nonces_read_live_fails_closed_when_the_chain_read_fails() {
        use crate::stream_g::models::{LiveNoncesError, ERR_SNAPSHOT_CHAIN_READ_FAILED};

        let chain = MockChain::new();
        let gateway = [0x16u8; 20];
        let root = [0x33u8; 20];
        let secondary = [0x77u8; 20];
        let fee_token = [0x12u8; 20];

        // Deliberately never call `set_nonce_snapshot` -- MockChain fails
        // closed on an unarmed key.
        let err = LiveEnrollmentNonces::read_live(&chain, gateway, root, secondary, fee_token, 1)
            .unwrap_err();
        assert_eq!(err.code(), ERR_SNAPSHOT_CHAIN_READ_FAILED);
        assert!(matches!(err, LiveNoncesError::ChainRead { .. }));
    }

    // -- 12b. Task 2: R3 anti-TOCTOU binding --------------------------------

    /// Sourcing contract §3 R3: `ctx.live_token` and `ctx.live_nonces` are
    /// two independent chain reads. Before this task, nothing compared
    /// their `feeTokenConfigHash` values, so a caller (or a future 6b/7/8
    /// wiring bug) could hand the quote path a token-gate reading from one
    /// chain state and a nonce snapshot from another.
    ///
    /// Mutation this test detects: neutralising the STEP-0-adjacent
    /// `if ctx.live_token.fee_token_config_hash() != ctx.live_nonces.fee_token_config_hash()`
    /// check (replacing the condition with `false`) makes this quote
    /// succeed instead of being rejected. Verified directly: with the
    /// check disabled, this test failed (`unwrap_err()` panicked on an
    /// `Ok`); the mutation was then reverted.
    #[tokio::test]
    async fn quote_rejects_a_fee_token_config_hash_mismatch_between_live_token_and_live_nonces() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-toctou").await;
        let profile = AuthenticatedProfileId::for_test("profile-toctou");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);

        let mut ctx = base_ctx(&manifest, &live_token, u128::MAX);
        // Deliberately DIFFERENT from live_token's real feeTokenConfigHash
        // -- simulating a nonce snapshot taken at a different chain state
        // (e.g. straddling a config upsert or a reorg).
        assert_ne!(
            live_token.fee_token_config_hash(),
            [0xEEu8; 32],
            "fixture precondition: the mismatch value must actually differ"
        );
        ctx.live_nonces = LiveEnrollmentNonces::for_test(0, 0, [0xEEu8; 32]);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let req = base_request(
            root,
            controller,
            secondary,
            "idem-toctou",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );

        let err = create_sponsored_enrollment_quote(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), ERR_FEE_TOKEN_CONFIG_HASH_TOCTOU_MISMATCH);
        assert!(matches!(
            err,
            QuoteError::FeeTokenConfigHashToctouMismatch { .. }
        ));
        // Fails before ever touching the exposure gate or the store.
        assert_eq!(chain.l1_fee_upper_bound_call_count(), 0);
        assert_eq!(quotes_count(&store).await, 0);
    }

    // -- 12c. Task 4: re-quoting an expired intent (architect ruling) ------

    /// (a) The SAME profile, after its quote for an intentId has expired
    /// (chain time), can obtain a FRESH quote for that same intentId under
    /// a NEW idempotency key. Before this task the same key returned
    /// `QUOTE_EXPIRED` forever and a fresh key collided on the
    /// still-present `intents` row and returned `IDEMPOTENCY_KEY_CONFLICT`
    /// forever — a dead end for a legitimate caller.
    ///
    /// Mutation this test detects: forcing `superseding_intent` to always
    /// be `false` (equivalent to deleting the whole intents-conflict/
    /// supersede block and always falling through to the plain
    /// `INSERT OR IGNORE`) makes the second call return
    /// `IdempotencyKeyConflict` instead of `Ok`. Verified directly: with
    /// `superseding_intent` hardcoded to `false` after the detection block,
    /// this test failed on `.expect(..)`; the mutation was then reverted.
    #[tokio::test]
    async fn same_profile_can_re_quote_an_expired_intent_with_a_fresh_idempotency_key() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-requote").await;
        let profile = AuthenticatedProfileId::for_test("profile-requote");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );

        let contested_intent_id = [0x9Au8; 32];
        let contested_hex = format!("0x{}", hex::encode(contested_intent_id));

        let mut req1 = base_request(
            root,
            controller,
            secondary,
            "requote-key-1",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        req1.intent_id_hex = contested_hex.clone();

        let t: i64 = 1_900_000_000;
        chain.set_now(t as u64);
        let first = create_sponsored_enrollment_quote_at(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req1,
            t,
        )
        .await
        .expect("first quote must succeed");
        assert_eq!(first.valid_until, (t + 300) as u64);

        // Advance CHAIN time past validUntil -- the same I2 predicate the
        // replay-expiry branch (M6) uses.
        chain.set_now((t + 300) as u64);

        let mut req2 = base_request(
            root,
            controller,
            secondary,
            "requote-key-2",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        req2.intent_id_hex = contested_hex.clone();

        let second = create_sponsored_enrollment_quote_at(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req2,
            t + 300,
        )
        .await
        .expect(
            "the same profile must be able to re-quote the same intentId once the prior \
             quote has genuinely expired",
        );

        assert_ne!(
            second.quote_id_hex, first.quote_id_hex,
            "the re-quote must be a genuinely NEW signed quote, not the stale one"
        );
        assert_eq!(
            quotes_count(&store).await,
            2,
            "both the expired quote and the fresh one must exist in the ledger"
        );
        assert_eq!(
            intents_count(&store).await,
            1,
            "the intents row must be superseded IN PLACE, never duplicated"
        );

        let first_status = quote_row(&store, &hex_id_of(&first)).await.status;
        assert_eq!(
            first_status, "expired",
            "the superseded quote must be marked expired, not left 'active'"
        );
        let second_status = quote_row(&store, &hex_id_of(&second)).await.status;
        assert_eq!(second_status, "active");

        let intent_id = deterministic_id(&[
            INTENT_ROW_ID_DOMAIN,
            "profile-requote",
            &bytes32_hex(contested_intent_id),
        ]);
        let i = intent_row(&store, &intent_id).await;
        assert_eq!(
            i.quote_id.as_deref(),
            Some(hex_id_of(&second).as_str()),
            "the intent must now point at the NEW quote"
        );
        assert_eq!(i.expires_at, Some(second.valid_until as i64));
    }

    /// (c) A FRESH idempotency key for the SAME intentId while the prior
    /// quote is STILL VALID must still be rejected as a conflict — the
    /// deliberate case the module doc describes, unchanged by the new
    /// supersede logic.
    ///
    /// Mutation this test detects: replacing the
    /// `if !prior_is_expired { return Err(..) }` guard with a no-op (i.e.
    /// treating every prior quote as expired regardless of its actual
    /// `expires_at`) makes this call wrongly succeed by superseding a row
    /// it must not touch. Verified directly: with that guard disabled,
    /// this test failed (`unwrap_err()` panicked on an `Ok`); the mutation
    /// was then reverted.
    #[tokio::test]
    async fn a_fresh_idempotency_key_for_a_still_valid_intent_is_still_rejected_as_conflict() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-requote-live").await;
        let profile = AuthenticatedProfileId::for_test("profile-requote-live");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );

        let contested_intent_id = [0x9Bu8; 32];
        let contested_hex = format!("0x{}", hex::encode(contested_intent_id));

        let mut req1 = base_request(
            root,
            controller,
            secondary,
            "requote-live-key-1",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        req1.intent_id_hex = contested_hex.clone();

        let t: i64 = 1_900_000_000;
        chain.set_now(t as u64);
        create_sponsored_enrollment_quote_at(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req1,
            t,
        )
        .await
        .expect("first quote must succeed");

        // Still well inside the validity window -- valid_for_seconds is 300.
        chain.set_now((t + 50) as u64);

        let mut req2 = base_request(
            root,
            controller,
            secondary,
            "requote-live-key-2",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        req2.intent_id_hex = contested_hex.clone();

        let err = create_sponsored_enrollment_quote_at(
            &store,
            &data_key_hex(),
            &chain,
            &profile,
            &ctx,
            &schedule,
            req2,
            t + 50,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), ERR_IDEMPOTENCY_KEY_CONFLICT);
        assert!(matches!(err, QuoteError::IdempotencyKeyConflict));
        assert_eq!(
            quotes_count(&store).await,
            1,
            "the still-valid quote must not be touched, and no second one created"
        );
        assert_eq!(intents_count(&store).await, 1);
    }

    /// (b) Two DIFFERENT profiles quoting the SAME on-chain intentId still
    /// get independent `intents` rows (C2's profile-namespacing),
    /// unaffected by the new supersede code path: profile A's
    /// expired-and-superseded history must not leak into or block profile
    /// B's own fresh quote.
    ///
    /// This is a regression check, not itself mutation-discriminated for
    /// the isolation property — that property is C2's, already
    /// mutation-verified by
    /// `two_profiles_can_quote_the_same_onchain_intent_id_without_colliding`
    /// (reverting `intent_row_id` to the raw intentId fails that test).
    /// This test's job is only to confirm the new Task 4 code path does
    /// not disturb it; the Task-4-specific defense-in-depth guard is
    /// exercised on its own by
    /// `defense_in_depth_refuses_to_supersede_an_intents_row_whose_stored_owner_disagrees`
    /// below.
    #[tokio::test]
    async fn a_different_profile_quoting_the_same_onchain_intent_id_is_unaffected_by_anothers_expired_supersede(
    ) {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-isolation-a").await;
        seed_profile(&store, "profile-isolation-b").await;
        let profile_a = AuthenticatedProfileId::for_test("profile-isolation-a");
        let profile_b = AuthenticatedProfileId::for_test("profile-isolation-b");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );

        let contested_intent_id = [0x9Cu8; 32];
        let contested_hex = format!("0x{}", hex::encode(contested_intent_id));

        let mut req_a = base_request(
            root,
            controller,
            secondary,
            "isolation-a-key1",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        req_a.intent_id_hex = contested_hex.clone();
        let t: i64 = 1_900_000_000;
        chain.set_now(t as u64);
        create_sponsored_enrollment_quote_at(
            &store,
            &data_key_hex(),
            &chain,
            &profile_a,
            &ctx,
            &schedule,
            req_a,
            t,
        )
        .await
        .expect("profile A's first quote must succeed");

        // Expire profile A's quote before profile B ever touches the
        // contested intentId.
        chain.set_now((t + 300) as u64);
        let mut req_b = base_request(
            root,
            controller,
            secondary,
            "isolation-b-key1",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        req_b.intent_id_hex = contested_hex.clone();
        create_sponsored_enrollment_quote_at(
            &store,
            &data_key_hex(),
            &chain,
            &profile_b,
            &ctx,
            &schedule,
            req_b,
            t + 300,
        )
        .await
        .expect(
            "profile B must get its OWN quote for the same on-chain intentId, unaffected \
             by profile A's expired row",
        );

        assert_eq!(
            intents_count(&store).await,
            2,
            "each profile must have its own intents row"
        );
        let intent_id_a = deterministic_id(&[
            INTENT_ROW_ID_DOMAIN,
            "profile-isolation-a",
            &bytes32_hex(contested_intent_id),
        ]);
        let a_row = intent_row(&store, &intent_id_a).await;
        assert_eq!(a_row.profile_id, "profile-isolation-a");
    }

    /// (b) Defense in depth: superseding must be refused if the STORED
    /// `intents.profile_id` column ever disagrees with the requesting
    /// profile, even though production code never produces that condition
    /// on its own (the id is a hash of `(domain, profile_id, intentId)`,
    /// so two different profiles never compute the same id). This test
    /// manufactures the otherwise-unreachable condition directly via raw
    /// SQL to exercise the belt-and-braces ownership check in isolation.
    ///
    /// Mutation this test detects: this check turned out to be fully
    /// redundant with the superseding `UPDATE intents ... WHERE id = ? AND
    /// profile_id = ?`'s own ownership filter — verified empirically:
    /// neutralising ONLY the `if intent_owner != profile_id_for_tx { .. }`
    /// guard left this test passing (the `UPDATE` still matches 0 rows and
    /// the caller still gets `IdempotencyKeyConflict`). Removing BOTH the
    /// guard AND the `UPDATE`'s `AND profile_id = ?` together is what
    /// flips this test to a false `Ok` that wrongly supersedes the
    /// corrupted row — verified directly, then both were restored. Kept
    /// as intentional belt-and-braces (same redundant-checks posture the
    /// M6 replay branch above already uses), not because either guard is
    /// independently load-bearing on its own.
    #[tokio::test]
    async fn defense_in_depth_refuses_to_supersede_an_intents_row_whose_stored_owner_disagrees() {
        let (_dir, store) = open_store().await;
        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        seed_profile(&store, "profile-corrupt-a").await;
        seed_profile(&store, "profile-corrupt-b").await;
        let profile_a = AuthenticatedProfileId::for_test("profile-corrupt-a");
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, u128::MAX);
        let chain = MockChain::new();
        chain.set_now(1_900_000_000);

        let corrupted_intent_id = [0x9Du8; 32];
        let corrupted_row_id = deterministic_id(&[
            INTENT_ROW_ID_DOMAIN,
            "profile-corrupt-a",
            &bytes32_hex(corrupted_intent_id),
        ]);
        let corrupted_quote_id = "corrupted-quote-row-id".to_string();

        // Seed a row whose id is exactly what profile A's OWN request
        // would compute for `corrupted_intent_id`, but whose STORED
        // `profile_id` says it belongs to profile B.
        {
            let corrupted_row_id = corrupted_row_id.clone();
            let corrupted_quote_id = corrupted_quote_id.clone();
            store
                .write_tx(move |tx| {
                    Box::pin(async move {
                        sqlx::query(
                            "INSERT INTO quotes \
                             (id, profile_id, base_asset, quote_asset, base_amount, \
                              quote_amount, status, created_at, expires_at) \
                             VALUES (?, 'profile-corrupt-b', '0x00', 'X', '0', '0', \
                                     'expired', 0, 0)",
                        )
                        .bind(&corrupted_quote_id)
                        .execute(&mut **tx)
                        .await?;
                        sqlx::query(
                            "INSERT INTO intents \
                             (id, profile_id, quote_id, intent_type, status, created_at, \
                              expires_at) \
                             VALUES (?, 'profile-corrupt-b', ?, 'sponsored_enrollment', \
                                     'pending', 0, 0)",
                        )
                        .bind(&corrupted_row_id)
                        .bind(&corrupted_quote_id)
                        .execute(&mut **tx)
                        .await?;
                        Ok::<(), StreamGStoreError>(())
                    })
                })
                .await
                .expect("seed corrupted row");
        }

        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );
        let mut req = base_request(
            root,
            controller,
            secondary,
            "corrupt-a-key",
            0,
            9_999_999_999,
            &v1_sig,
            0,
            9_999_999_999,
            &link_sig,
            1_000_000,
        );
        req.intent_id_hex = format!("0x{}", hex::encode(corrupted_intent_id));

        let err = create_sponsored_enrollment_quote_at(
            &store,
            &data_key_hex(),
            &chain,
            &profile_a,
            &ctx,
            &schedule,
            req,
            1_900_000_000,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), ERR_IDEMPOTENCY_KEY_CONFLICT);
        assert!(matches!(err, QuoteError::IdempotencyKeyConflict));

        // The corrupted row must be completely untouched, and the
        // rejected attempt's own `quotes` insert must have rolled back.
        let row = intent_row(&store, &corrupted_row_id).await;
        assert_eq!(row.profile_id, "profile-corrupt-b");
        assert_eq!(row.quote_id.as_deref(), Some(corrupted_quote_id.as_str()));
        assert_eq!(
            quotes_count(&store).await,
            1,
            "no new quote row may survive a rejected supersede attempt"
        );
    }

    // =====================================================================
    // Task 9 Wave C — hazard 1 at the QUOTE ROUTE, against a live node.
    //
    // `quote_rejects_on_l1_da_spike` above already proves the route
    // propagates a `base_fee` rejection, but it does so against `MockChain`,
    // which returns whatever the test told it to and never encodes or
    // decodes anything. The test below is the same claim with the oracle
    // replaced by a real `eth_call` to a real contract at the real OP-Stack
    // predeploy address on a real node — i.e. it also covers the calldata
    // encode, the `eth_call` round-trip and alloy's decode, none of which
    // `MockChain` can exercise. And unlike the MockChain test, which spikes
    // only the L1-DA term, this one spikes each of the three §8.1 terms on
    // its own.
    // =====================================================================

    /// **Hazard 1, route level: `create_sponsored_enrollment_quote` refuses
    /// to issue a quote when any ONE of the three exposure terms spikes on a
    /// live `GasPriceOracle`, and issues one when none of them has.**
    ///
    /// Why a plain `#[test]` with a hand-built runtime rather than
    /// `#[tokio::test]`: `AnvilHarness` and its raw JSON-RPC are blocking
    /// (`reqwest::blocking`), and `RpcChain` bridges to alloy with
    /// `block_in_place` + the current `Handle` whenever one exists. So the
    /// node/oracle manipulation is deliberately done **outside**
    /// `rt.block_on`, and the runtime is multi-threaded because
    /// `block_in_place` is only legal there. A `flavor = "current_thread"`
    /// test would panic inside `RpcChain`, not fail an assertion.
    ///
    /// Arms, in order — every spiked arm is bracketed by a successful one so
    /// no rejection can be inherited from the previous arm's node state:
    ///
    /// | arm | what moves | expected |
    /// |-----|-----------|----------|
    /// | 0 | nothing | quote ISSUED and persisted |
    /// | 1 | `getL1FeeUpperBound` → 9 ETH | `EXPOSURE_EXCEEDS_SCHEDULE`, nothing persisted |
    /// | 2 | `getOperatorFee` → 4 ETH | `EXPOSURE_EXCEEDS_SCHEDULE`, nothing persisted |
    /// | 3 | request `maxFeePerGas` → 5e12 (oracle untouched) | `EXPOSURE_EXCEEDS_SCHEDULE`, nothing persisted |
    /// | 4 | nothing | quote ISSUED again |
    ///
    /// The `quotes_count` assertion after each rejection is the half that
    /// matters operationally: a rejected quote must leave no row behind, or
    /// the idempotency key is burned and the caller can never retry it.
    ///
    /// Mutation this detects: deleting the `base_fee::quote_exposure` call
    /// from STEP 2 (the "quote is a fixed tariff, so the oracle does not
    /// matter" refactor) — arms 1-3 then all issue quotes and their
    /// `unwrap_err` panics. Note that `quotes.rs`'s own MockChain tests
    /// would still catch that one; what only this test catches is a break in
    /// the live encode/round-trip/decode path between `quote_exposure` and
    /// the predeploy.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn stream_g_anvil_quote_route_rejects_each_oracle_fee_term_spiked_independently() {
        use crate::stream_g::anvil_harness::AnvilHarness;

        // Same numbers as `anvil_harness`'s Wave C arms; `base_request`
        // already uses a 500_000 gas ceiling at 1 gwei, so the honest L2
        // term is 5e14 wei.
        const NORMAL_L1_EXACT_WEI: u128 = 2_000_000_000_000;
        const NORMAL_L1_UPPER_WEI: u128 = 3_000_000_000_000;
        const NORMAL_OPERATOR_WEI: u128 = 1_000_000_000;
        const SPIKED_L1_UPPER_WEI: u128 = 9_000_000_000_000_000_000;
        const SPIKED_OPERATOR_WEI: u128 = 4_000_000_000_000_000_000;
        const SPIKED_MAX_FEE_PER_GAS_WEI: &str = "5000000000000";
        const EXPOSURE_CEILING_WEI: u128 = 1_000_000_000_000_000_000; // 1 ETH

        // --- Blocking setup, deliberately outside any runtime. -----------
        let h = AnvilHarness::start();
        h.etch_gas_price_oracle();
        h.set_oracle_fees(
            NORMAL_L1_EXACT_WEI,
            NORMAL_L1_UPPER_WEI,
            NORMAL_OPERATOR_WEI,
        );
        let chain = h.rpc_chain(31337);

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("multi-thread runtime (block_in_place is illegal on current_thread)");

        let manifest = manifest_fixture();
        let token_cap = authorized_token_capability(&manifest);
        let live_token = live_token_reading(&manifest, &token_cap);
        let secondary_signer = PrivateKeySigner::from_str(SECONDARY_PK).unwrap();
        let secondary = secondary_signer.address().into_array();
        let root = [0x33u8; 20];
        let controller = [0x34u8; 20];
        let schedule = FeeSchedule::for_test(&[(ActionType::SponsoredEnrollment, 500_000)]);
        let ctx = base_ctx(&manifest, &live_token, EXPOSURE_CEILING_WEI);
        let (v1_sig, link_sig) = sign_nested_bearers(
            &manifest,
            root,
            &secondary_signer,
            0,
            9_999_999_999,
            0,
            9_999_999_999,
        );

        let (_dir, store) = rt.block_on(open_store());
        rt.block_on(seed_profile(&store, "profile-live-fee"));
        let profile = AuthenticatedProfileId::for_test("profile-live-fee");

        let quote_once = |idempotency_key: &str, max_fee_per_gas_wei: Option<&str>| {
            let mut req = base_request(
                root,
                controller,
                secondary,
                idempotency_key,
                0,
                9_999_999_999,
                &v1_sig,
                0,
                9_999_999_999,
                &link_sig,
                1_000_000,
            );
            if let Some(v) = max_fee_per_gas_wei {
                req.max_fee_per_gas_wei = v.to_string();
            }
            rt.block_on(create_sponsored_enrollment_quote(
                &store,
                &data_key_hex(),
                &chain,
                &profile,
                &ctx,
                &schedule,
                req,
            ))
        };
        let rows = || rt.block_on(quotes_count(&store));

        // --- ARM 0: honest fees -> a quote is really issued. -------------
        // This is the brief's mandatory negative arm: without it, a route
        // that rejected everything (e.g. because the predeploy read errored)
        // would satisfy arms 1-3.
        let issued = quote_once("idem-live-fee-ok-1", None)
            .expect("arm 0: at normal live fees the route MUST issue a quote");
        assert!(!issued.quote_signature_hex.is_empty());
        assert_eq!(rows(), 1, "arm 0 must persist exactly one quote");

        // --- ARM 1: L1-DA term alone. -----------------------------------
        h.set_oracle_fees(
            NORMAL_L1_EXACT_WEI,
            SPIKED_L1_UPPER_WEI,
            NORMAL_OPERATOR_WEI,
        );
        let err = quote_once("idem-live-fee-l1-spike", None)
            .expect_err("arm 1: a live L1-DA spike must refuse the quote");
        assert_eq!(err.code(), base_fee::ERR_EXPOSURE_EXCEEDS_SCHEDULE);
        assert_eq!(rows(), 1, "a refused quote must not be persisted");

        // --- ARM 2: operator-fee term alone. ----------------------------
        h.set_oracle_fees(
            NORMAL_L1_EXACT_WEI,
            NORMAL_L1_UPPER_WEI,
            SPIKED_OPERATOR_WEI,
        );
        let err = quote_once("idem-live-fee-op-spike", None)
            .expect_err("arm 2: a live operator-fee spike must refuse the quote");
        assert_eq!(err.code(), base_fee::ERR_EXPOSURE_EXCEEDS_SCHEDULE);
        assert_eq!(rows(), 1, "a refused quote must not be persisted");

        // --- ARM 3: L2 execution term alone; the oracle is NOT touched. --
        h.set_oracle_fees(
            NORMAL_L1_EXACT_WEI,
            NORMAL_L1_UPPER_WEI,
            NORMAL_OPERATOR_WEI,
        );
        let err = quote_once("idem-live-fee-l2-spike", Some(SPIKED_MAX_FEE_PER_GAS_WEI))
            .expect_err("arm 3: an L2 execution spike must refuse the quote");
        assert_eq!(err.code(), base_fee::ERR_EXPOSURE_EXCEEDS_SCHEDULE);
        assert_eq!(rows(), 1, "a refused quote must not be persisted");

        // --- ARM 4: back to honest fees -> quotes are issued again. ------
        let issued2 = quote_once("idem-live-fee-ok-2", None)
            .expect("arm 4: with the spikes reverted the route MUST issue quotes again");
        assert_ne!(
            issued2.quote_id_hex, issued.quote_id_hex,
            "arm 4 must be a genuinely new quote, not the arm-0 replay"
        );
        assert_eq!(rows(), 2, "arm 4 must persist a second quote");
        println!(
            "route arms: 0 issued {}, 1/2/3 refused with {}, 4 issued {}",
            issued.quote_id_hex,
            base_fee::ERR_EXPOSURE_EXCEEDS_SCHEDULE,
            issued2.quote_id_hex
        );
    }

    // ===================================================================
    // `POST /v1/stream-g/quotes` — the mounted route.
    //
    // ## Which arm every test below is on, stated up front
    //
    // `runtime::test_support::enabled_map` inherits `GOAT_ATTESTOR_MOCK=1`
    // (`enabled_map` calls `Config::test_map`, which sets that key), so
    // `state.trusted_chain()` is `None` in every
    // fixture here and the **no-live-chain arm is the only accepting-side arm
    // reachable**. That is not a gap being papered over: it is
    // `TrustedChain`'s whole design (`token_manifest::TrustedChain` — in a
    // release build its only constructor, `TrustedChain::live`, takes a
    // concrete `RpcChain`), and
    // faking a live chain here would mean building a `StreamGState` that
    // cannot exist in production. The signed-quote path is covered above,
    // against the library entry point, with a `MockChain` behind the
    // `#[cfg(test)]` conversion.
    //
    // What these tests can therefore prove, and do: the route is bound at the
    // path and method claimed, the credential is required before anything
    // else, and the refusal a mock-mode process gives is the Foundation's
    // `NO_LIVE_CHAIN` rather than a 500 or a stub 200.
    // ===================================================================

    use crate::stream_g::http_error::{max_quote_request_json, ERR_NO_LIVE_CHAIN};
    use crate::stream_g::profile_auth::{
        create_profile, AUTH_SCHEME_CREDENTIAL, ERR_MISSING_CREDENTIAL,
    };
    use crate::stream_g::{router, runtime};
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const ROUTE_ORIGIN: &str = "https://quote.example";
    const QUOTE_PATH: &str = "/v1/stream-g/quotes";

    async fn route_state(dir: &std::path::Path) -> runtime::StreamGState {
        let mut map = runtime::test_support::enabled_map(dir);
        map.insert("STREAM_G_CORS_ORIGINS".into(), ROUTE_ORIGIN.into());
        let cfg = crate::config::load_from_map(&map).expect("stream G config must validate");
        let controller = runtime::ShutdownController::new();
        runtime::StreamGState::start(&cfg, controller.token())
            .await
            .expect("stream G startup")
    }

    /// One `POST` against a cloned app, with an optional `Authorization`.
    async fn post_json(
        app: &Router,
        uri: &str,
        body: String,
        authorization: Option<&str>,
    ) -> (StatusCode, String) {
        let mut builder = Request::builder()
            .method(Method::POST)
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

    /// The `Authorization` header value that authenticates as a fresh profile.
    async fn credential_for(state: &runtime::StreamGState, idempotency_key: &str) -> String {
        let created = create_profile(state.store(), state.data_key_hex(), idempotency_key)
            .await
            .expect("create profile");
        format!("{AUTH_SCHEME_CREDENTIAL} {}", created.credential)
    }

    /// **Unauthenticated access is 401**, and the refusal happens before the
    /// body is looked at — `AuthenticatedProfile` is `FromRequestParts` and
    /// `ApiJson` is the body extractor, so axum runs them in that order (which
    /// is also why the handler's parameter order is compiler-enforced).
    ///
    /// Mutations this detects:
    /// 1. dropping the `caller: AuthenticatedProfile` parameter — does not
    ///    compile, because [`create_sponsored_enrollment_quote`] takes
    ///    `&AuthenticatedProfileId` and outside `#[cfg(test)]` there is no
    ///    other way to obtain one. That is the intended guarantee, so there is
    ///    no runtime mutation to run for it.
    /// 2. mounting the handler for `GET` rather than `POST` — applied, run,
    ///    reverted (as part of the sibling test's method mutation): this test
    ///    failed too, with 405 in place of both 401s.
    #[tokio::test]
    async fn the_quote_route_refuses_a_request_with_no_credential() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let (status, body) = post_json(&app, QUOTE_PATH, max_quote_request_json(), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_MISSING_CREDENTIAL}\"}}"));

        // A syntactically valid but unusable scheme is the same refusal.
        let (status, body) = post_json(
            &app,
            QUOTE_PATH,
            max_quote_request_json(),
            Some("Basic dXNlcjpwYXNz"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_MISSING_CREDENTIAL}\"}}"));

        // A body that would never deserialize gets the *same* 401: the
        // credential is checked first, so a caller cannot probe the DTO's
        // shape without one.
        let (status, body) = post_json(&app, QUOTE_PATH, "{\"nope\":1}".to_string(), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_MISSING_CREDENTIAL}\"}}"));
    }

    /// **Mock mode refuses with the Foundation's `NO_LIVE_CHAIN` (503)**, and
    /// this is simultaneously the proof that the route is mounted at
    /// `/v1/stream-g/quotes` for `POST`: a 503 carrying that code can only
    /// have come from [`post_quote`]'s first statement, because nothing else
    /// in the crate constructs it.
    ///
    /// The body driven through is `http_error::max_quote_request_json()` — the
    /// same maximum-width document `super::super::tests::the_body_limit_clears_the_largest_real_dto`
    /// measures at 1347 bytes — so this also demonstrates that the real DTO
    /// clears the 4 KiB router limit on the real route rather than only in
    /// that test's synthetic probe.
    ///
    /// Mutations this detects:
    /// 1. mounting the nested path the pre-mount doc comments named
    ///    (`"/v1/stream-g/quotes/sponsored-enrollment"`) instead — applied,
    ///    run, reverted: this test failed with `left: 404, right: 503`.
    /// 2. `get(post_quote)` instead of `post(..)` — applied, run, reverted:
    ///    failed with `left: 405, right: 503`.
    /// 3. resolving `state.trusted_chain()` with anything other than
    ///    `ok_or_else(ApiError::no_live_chain)` — a panic or a different code
    ///    on the wire. (Not run: there is no non-panicking one-line
    ///    alternative, since `trusted_chain()` returns `Option` and
    ///    `TrustedChain` has no `Default`.)
    #[tokio::test]
    async fn the_quote_route_refuses_a_mock_mode_process_with_no_live_chain() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());
        assert!(
            state.trusted_chain().is_none(),
            "this fixture must be the mock-mode arm; see the section comment"
        );

        let authorization = credential_for(&state, "idem-b1-no-chain").await;
        let (status, body) = post_json(
            &app,
            QUOTE_PATH,
            max_quote_request_json(),
            Some(&authorization),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body, format!("{{\"error\":\"{ERR_NO_LIVE_CHAIN}\"}}"));
        assert!(
            !body.contains('f'.to_string().repeat(40).as_str()),
            "a refusal must echo none of the request back: {body}"
        );

        // Founder ruling: the path is the flat plural. The nested path
        // `quotes.rs`'s and `models.rs`'s doc comments named before the mount
        // is not mounted, and there is no fallback, so it 404s.
        let (status, _) = post_json(
            &app,
            "/v1/stream-g/quotes/sponsored-enrollment",
            max_quote_request_json(),
            Some(&authorization),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "only /v1/stream-g/quotes is mounted"
        );
    }
}
