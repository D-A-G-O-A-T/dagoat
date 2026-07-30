//! Free-primary onboarding intent state machine (hazard SG-6) — Stream G.
//!
//! This module owns two things:
//!
//! 1. **The free-primary entitlement primitive**
//!    ([`claim_free_primary_wallet`] / [`claim_free_primary_wallet_in_tx`]):
//!    exactly one `profile_wallets` row with `is_primary = 1` may ever exist
//!    per `profile_id`. Enforcement is a single atomic conditional INSERT —
//!    `INSERT ... SELECT ... WHERE NOT EXISTS (...)` — with rows-affected
//!    checked inside one `write_tx`; there is no separate "read the current
//!    primary, then decide" step, so nothing about the ordering of two
//!    concurrent callers can produce two primaries (see
//!    `only_one_free_primary_per_profile` /
//!    `two_concurrent_primary_claims_for_one_profile_exactly_one_succeeds`
//!    below). The entitlement is keyed on `profile_id` alone — the function
//!    signature has no device id, install id, or session/challenge token
//!    parameter at all, which is the strongest available proof that a local
//!    reinstall (which regenerates all of those) cannot reset it; see
//!    `local_reinstall_does_not_reset_server_entitlement`.
//!
//! 2. **The onboarding intent state machine**
//!    ([`start_intent`] / [`get_intent`] / [`mark_authorized`] /
//!    [`mark_submitted`] / [`fulfill`]): explicit states
//!    `pending -> authorized -> submitted -> fulfilled | failed`, stored in
//!    the existing `intents` table (`intent_type = "primary_onboarding"`,
//!    `status` = the state). Every transition is a single conditional
//!    `UPDATE ... WHERE id = ? AND status = ?` inside `write_tx`; an
//!    unexpected current state means 0 rows affected, which is surfaced as
//!    [`OnboardingError::IllegalTransition`] rather than silently
//!    overwriting whatever state the row was actually in.
//!
//! ## Idempotency without a new table (augmented brief §4)
//!
//! `start_intent` takes an `idempotency_key` and derives the intent's row
//! `id` deterministically as `sha256("primary_onboarding|" || profile_id ||
//! "|" || idempotency_key)`. A replay of the same (profile_id,
//! idempotency_key) pair collides on that PRIMARY KEY: the `INSERT OR
//! IGNORE` affects 0 rows, and the existing row's current status is
//! returned instead of resetting it back to `pending` — so a replay can
//! never fabricate a second intent, and can never regress an
//! already-advanced intent's state. The idempotency key itself is sealed
//! (via `crypto_store::seal`) into `intents.intent_enc`, which is the
//! pre-existing JSON payload column this table already has — no schema
//! change.
//!
//! This module deliberately does not share helper functions with
//! `profile_auth.rs` / `root_authorization.rs`: each of the three files in
//! this task is self-contained (its own tiny `now_unix_seconds` /
//! `random_hex` / `deterministic_id`), so the modules can be implemented,
//! tested, and reasoned about independently. The duplication is a handful
//! of lines per file. The one deliberate exception is
//! `profile_auth::AuthenticatedProfileId`, imported via
//! `super::profile_auth::AuthenticatedProfileId` -- see below.
//!
//! ## I3 fix: `profile_id` is proven, never merely asserted
//!
//! Every profile-scoped entry point in this module --
//! [`start_intent`], [`get_intent`], [`mark_authorized`],
//! [`mark_submitted`], and [`claim_free_primary_wallet`] -- takes
//! `&profile_auth::AuthenticatedProfileId`, not a bare `String`/`&str`.
//! [`StartOnboardingRequest`] (the `#[serde(deny_unknown_fields)]`
//! deserializable request body for `POST /v1/profile/primary-onboarding`)
//! has **no `profile_id` field at all anymore** -- only `idempotency_key`.
//! The profile arrives as a separate `&AuthenticatedProfileId` parameter
//! that Task 8 can only obtain from `profile_auth::authenticate_credential`
//! or `profile_auth::validate_session`, so a raw `String` decoded straight
//! out of the JSON body cannot type-check into `start_intent` at all. See
//! `profile_auth`'s module doc ("I3 fix" section) for the full newtype
//! rationale and the exhaustive list of mint points.
//!
//! `get_intent`, `mark_authorized`, and `mark_submitted` did not even take
//! a `profile_id` parameter before this fix -- they operated purely on
//! `intent_id`, with no ownership check at all. Adding the
//! `AuthenticatedProfileId` parameter is paired with an actual ownership
//! check, not just a type change: `transition_in_tx`'s guarded UPDATE now
//! carries `AND profile_id = ?`, and its 0-rows-affected fallback read is
//! *also* scoped to that `profile_id`, so a caller acting on an intent it
//! does not own gets [`OnboardingError::IntentNotFound`] -- indistinguishable
//! from a genuinely nonexistent intent -- rather than
//! [`OnboardingError::IllegalTransition`], which would leak the intent's
//! *actual* status to a non-owner. `get_intent`'s `SELECT` carries the same
//! `AND profile_id = ?` predicate for the same reason.
//!
//! `fulfill` also takes `&AuthenticatedProfileId` (round-2 fix), but its
//! model is different from the functions above: `profile_id` is still
//! resolved from the intent row it transitions, and *that* resolved value
//! -- never the parameter -- is what gets credited and what gets passed to
//! `transition_in_tx`. The parameter is used only as a predicate: a caller
//! authenticated as anyone other than the resolved owner is rejected with
//! [`OnboardingError::IntentNotFound`] before any entitlement claim is
//! attempted. An earlier version of this fix dropped the parameter
//! entirely, reasoning that made the cross-profile mismatch this hazard
//! depends on "unrepresentable"; that achieved consistency but also deleted
//! the only caller-identity input `fulfill` had, turning `intent_id` (which
//! travels in a URL path) into a bearer capability that could spend a
//! victim's one-time entitlement. See `fulfill`'s own doc below, and
//! `profile_auth`'s module doc ("I3 fix" section), for the full writeup.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqliteTransaction;
use sqlx::Row;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use axum::extract::{Path, State};
use axum::Json;

use super::crypto_store::{self, CryptoStoreError, DataKey, SecretHex};
use super::http_error::ApiError;
use super::profile_auth::{AuthenticatedProfile, AuthenticatedProfileId};
use super::runtime::StreamGState;
use super::store::{StreamGStore, StreamGStoreError};

/// Typed error code surfaced to callers when a profile has already used its
/// one free primary root (hazard SG-6). Not a silent no-op, not a 500 — see
/// module doc.
pub const ERR_ENTITLEMENT_EXHAUSTED: &str = "ENTITLEMENT_EXHAUSTED";
pub const ERR_ILLEGAL_TRANSITION: &str = "ILLEGAL_TRANSITION";
pub const ERR_INTENT_NOT_FOUND: &str = "INTENT_NOT_FOUND";
/// I4: the address failed 20-byte hex parsing and was rejected before it
/// could ever be bound into a query unnormalized.
pub const ERR_BAD_ADDRESS: &str = "BAD_ADDRESS";
/// M3: the (chain_id, normalized address) pair already backs a different
/// profile's primary wallet — the reinstall/re-import path this task is
/// named for, surfaced as a typed terminal outcome rather than a 500.
pub const ERR_WALLET_ALREADY_BOUND: &str = "WALLET_ALREADY_BOUND";

pub const INTENT_TYPE_PRIMARY_ONBOARDING: &str = "primary_onboarding";

pub const STATE_PENDING: &str = "pending";
pub const STATE_AUTHORIZED: &str = "authorized";
pub const STATE_SUBMITTED: &str = "submitted";
pub const STATE_FULFILLED: &str = "fulfilled";
pub const STATE_FAILED: &str = "failed";

#[derive(Debug, Error)]
pub enum OnboardingError {
    #[error("store error: {0}")]
    Store(#[from] StreamGStoreError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoStoreError),
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("intent not found")]
    IntentNotFound,
    #[error("illegal state transition from {from} to {to}")]
    IllegalTransition { from: String, to: String },
    #[error("free-primary entitlement already used for this profile")]
    EntitlementExhausted,
    #[error("malformed sealed payload: {0}")]
    MalformedPayload(String),
    #[error("wallet address is not a valid 20-byte hex address: {0}")]
    BadAddress(String),
    #[error("wallet address already backs a different profile on this chain")]
    WalletAlreadyBound,
}

impl OnboardingError {
    /// Stable string code for routes to surface (Task 8). Falls back to
    /// `"INTERNAL"` for variants that are not meant to be a specific typed
    /// API error (store/crypto/sqlx plumbing failures).
    pub fn code(&self) -> &'static str {
        match self {
            OnboardingError::IntentNotFound => ERR_INTENT_NOT_FOUND,
            OnboardingError::IllegalTransition { .. } => ERR_ILLEGAL_TRANSITION,
            OnboardingError::EntitlementExhausted => ERR_ENTITLEMENT_EXHAUSTED,
            OnboardingError::BadAddress(_) => ERR_BAD_ADDRESS,
            OnboardingError::WalletAlreadyBound => ERR_WALLET_ALREADY_BOUND,
            _ => "INTERNAL",
        }
    }

    /// HTTP status for the shared Stream G error envelope
    /// (`super::http_error`). Wildcard-free on purpose — see
    /// [`super::base_fee::BaseFeeError::status`]; note that [`Self::code`]
    /// above *does* end in `_ => "INTERNAL"`, so a variant added later would
    /// silently take that code while failing to compile here.
    ///
    /// [`OnboardingError::IntentNotFound`] is **404, never 403** — see the
    /// ownership-oracle rule in `super::http_error`. This variant is raised
    /// both for an intent that does not exist and for one that exists under a
    /// different profile (its own doc says so), and the mapping must not
    /// re-open on the wire the distinction the enum closed in the store.
    pub fn status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            OnboardingError::Store(_)
            | OnboardingError::Crypto(_)
            | OnboardingError::Sqlx(_)
            // The sealed payload this process wrote failed to open or parse.
            | OnboardingError::MalformedPayload(_) => StatusCode::INTERNAL_SERVER_ERROR,
            OnboardingError::IntentNotFound => StatusCode::NOT_FOUND,
            OnboardingError::IllegalTransition { .. }
            | OnboardingError::EntitlementExhausted
            | OnboardingError::WalletAlreadyBound => StatusCode::CONFLICT,
            // Not a 20-byte hex address at all: unparseable, not merely
            // refused.
            OnboardingError::BadAddress(_) => StatusCode::BAD_REQUEST,
        }
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Deterministic row id for idempotent creates: plain SHA-256 over
/// `parts.join("|")`. Plain (unkeyed) SHA-256 is fine here — unlike the
/// alias blind index in `profile_auth.rs`, this is not indexing a
/// low-entropy guessable value; it is combining a route name, a profile id,
/// and a caller-supplied idempotency key into a stable primary key so a
/// replay collides on the row instead of duplicating it.
fn deterministic_id(parts: &[&str]) -> String {
    hex::encode(Sha256::digest(parts.join("|").as_bytes()))
}

/// I4: parse `s` as a (possibly `0x`/`0X`-prefixed, possibly
/// whitespace-padded, any-cased) 20-byte hex address and re-emit it as a
/// canonical lowercase `0x…` string, rejecting anything that doesn't parse
/// as exactly 20 bytes. `profile_wallets.address` is bound to this
/// normalized form — never the raw caller input — so
/// `UNIQUE(chain_id, address)` (`migrations/0001_stream_g.sql:81-84`)
/// actually enforces "one wallet backs at most one profile per chain"
/// instead of being defeated by presentation differences (mixed-case
/// EIP-55, all-lowercase, a stray leading space, a missing `0x`).
///
/// `root_authorization.rs` already has an equivalent
/// `parse_address20`/`wallet_hex` pair, but that file is owned by a
/// concurrent fix lane for this task — see the module doc's note on why
/// each file here keeps its own tiny helpers. De-duplicating the two into
/// one shared helper is a follow-up once all three lanes land.
fn normalize_address20(s: &str) -> Result<String, OnboardingError> {
    let trimmed = s.trim();
    let hex_part = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex_part.len() != 40 {
        return Err(OnboardingError::BadAddress(s.to_string()));
    }
    let bytes = hex::decode(hex_part).map_err(|_| OnboardingError::BadAddress(s.to_string()))?;
    Ok(format!("0x{}", hex::encode(bytes)))
}

// --- Free-primary entitlement (SG-6) ---------------------------------

/// Outcome of attempting to claim the one free primary root for a profile,
/// distinct from an error: used internally by [`fulfill`], which treats
/// "already exhausted" as a normal terminal state (`failed`) rather than an
/// exceptional condition that should abort the whole onboarding intent
/// transaction. The public [`claim_free_primary_wallet`] entry point
/// converts `Exhausted` into `Err(OnboardingError::EntitlementExhausted)`,
/// matching the brief's "typed error, not a silent no-op" requirement for
/// direct callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletClaimOutcome {
    Claimed {
        wallet_id: String,
    },
    Exhausted,
    /// M3: the normalized address already backs a different profile's
    /// primary wallet on this chain (`UNIQUE(chain_id, address)`
    /// conflict). Modeled as an outcome, not folded into the `execute()`
    /// error, so [`fulfill`] can treat it exactly like [`Exhausted`] —
    /// commit the intent to `failed` in the same transaction — instead of
    /// unwinding the whole transaction on a raw `sqlx::Error`.
    AlreadyBound,
}

/// Transaction-scoped primitive: atomically claim the free primary root for
/// `profile_id`, or discover it is already claimed. Must be called from
/// inside an existing `write_tx` closure (never opens its own transaction),
/// per the store's single-connection re-entrancy rule.
///
/// The whole check-and-insert is one SQL statement — `INSERT ... SELECT
/// ... WHERE NOT EXISTS (...)` — specifically so there is no
/// select-then-insert window between "is there already a primary" and
/// "insert one": with a plain SELECT followed by an INSERT, two concurrent
/// transactions could both observe "no primary yet" before either commits.
/// Folding the check into the INSERT's own WHERE clause means SQLite
/// evaluates the NOT EXISTS check and performs the insert as a single
/// atomic operation on this connection.
///
/// `address` is normalized (I4, [`normalize_address20`]) before it is
/// bound into the query — parsed to 20 bytes and re-emitted lowercase, or
/// rejected as [`OnboardingError::BadAddress`] — so `UNIQUE(chain_id,
/// address)` cannot be defeated by presentation differences.
///
/// `idempotency_key`, when present (M8), makes `wallet_id` a deterministic
/// function of `(profile_id, idempotency_key)` instead of random, and — if
/// the profile already has a primary — this function distinguishes a true
/// replay of the *same* claim (the existing primary row's id equals the
/// id this call would have produced) from genuine exhaustion (some other
/// claim already won). [`fulfill`] does not have a client-supplied
/// idempotency key to thread through here; it passes `None` and relies on
/// the intent state machine's own `write_tx`-guarded transitions for its
/// replay safety instead.
pub(crate) async fn claim_free_primary_wallet_in_tx(
    tx: &mut SqliteTransaction<'static>,
    profile_id: &str,
    chain_id: i64,
    address: &str,
    wallet_type: &str,
    idempotency_key: Option<&str>,
) -> Result<WalletClaimOutcome, OnboardingError> {
    let normalized_address = normalize_address20(address)?;
    let wallet_id = match idempotency_key {
        Some(key) => deterministic_id(&["free_primary", profile_id, key]),
        None => random_hex(16),
    };
    let now = now_unix_seconds();

    let insert = sqlx::query(
        "INSERT INTO profile_wallets (id, profile_id, chain_id, address, wallet_type, is_primary, created_at) \
         SELECT ?, ?, ?, ?, ?, 1, ? \
         WHERE NOT EXISTS ( \
             SELECT 1 FROM profile_wallets WHERE profile_id = ? AND is_primary = 1 \
         )",
    )
    .bind(&wallet_id)
    .bind(profile_id)
    .bind(chain_id)
    .bind(&normalized_address)
    .bind(wallet_type)
    .bind(now)
    .bind(profile_id)
    .execute(&mut **tx)
    .await;

    let result = match insert {
        Ok(result) => result,
        // M3: the NOT EXISTS predicate above only guards *this* profile's
        // primary slot — it says nothing about whether `normalized_address`
        // already backs a *different* profile's primary, which is exactly
        // what `UNIQUE(chain_id, address)` catches here. Surface it as a
        // typed outcome instead of letting SQLITE_CONSTRAINT fall through
        // `OnboardingError::Sqlx` -> `code() == "INTERNAL"`.
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            return Ok(WalletClaimOutcome::AlreadyBound);
        }
        Err(other) => return Err(other.into()),
    };

    if result.rows_affected() == 1 {
        return Ok(WalletClaimOutcome::Claimed { wallet_id });
    }

    // This profile already has a primary. With an idempotency key, check
    // whether it's *this exact* claim replaying (M8) before reporting
    // exhaustion.
    if idempotency_key.is_some() {
        let row =
            sqlx::query("SELECT id FROM profile_wallets WHERE profile_id = ? AND is_primary = 1")
                .bind(profile_id)
                .fetch_one(&mut **tx)
                .await?;
        let existing_id: String = row.try_get("id")?;
        if existing_id == wallet_id {
            return Ok(WalletClaimOutcome::Claimed { wallet_id });
        }
    }

    Ok(WalletClaimOutcome::Exhausted)
}

/// Public entry point: claim the free primary root wallet for `profile_id`
/// in its own `write_tx`. Returns the new wallet's row id on success,
/// `Err(OnboardingError::EntitlementExhausted)` (code
/// [`ERR_ENTITLEMENT_EXHAUSTED`]) if this profile already has one and
/// `idempotency_key` does not match that existing claim, or
/// `Err(OnboardingError::WalletAlreadyBound)` (code
/// [`ERR_WALLET_ALREADY_BOUND`], M3) if the address already backs a
/// different profile — never a silent no-op, never a 500.
///
/// `idempotency_key` (M8) makes an honest client retry (lost response,
/// network blip) distinguishable from a second claim attempt: replaying
/// the same key against an already-claimed profile returns the same
/// `wallet_id` again instead of `EntitlementExhausted`.
///
/// **I3 fix.** `profile` is `&AuthenticatedProfileId` — see module doc.
pub async fn claim_free_primary_wallet(
    store: &StreamGStore,
    profile: &AuthenticatedProfileId,
    chain_id: i64,
    address: &str,
    wallet_type: &str,
    idempotency_key: &str,
) -> Result<String, OnboardingError> {
    let profile_id = profile.as_str().to_string();
    let address = address.to_string();
    let wallet_type = wallet_type.to_string();
    let idempotency_key = idempotency_key.to_string();

    let outcome = store
        .write_tx(move |tx| {
            Box::pin(async move {
                claim_free_primary_wallet_in_tx(
                    tx,
                    &profile_id,
                    chain_id,
                    &address,
                    &wallet_type,
                    Some(&idempotency_key),
                )
                .await
            })
        })
        .await?;

    match outcome {
        WalletClaimOutcome::Claimed { wallet_id } => Ok(wallet_id),
        WalletClaimOutcome::Exhausted => Err(OnboardingError::EntitlementExhausted),
        WalletClaimOutcome::AlreadyBound => Err(OnboardingError::WalletAlreadyBound),
    }
}

// --- Onboarding intent state machine ----------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct IntentView {
    pub intent_id: String,
    pub profile_id: String,
    pub status: String,
    pub created_at: i64,
}

/// **I3 fix.** `profile_id` was removed from this request body entirely --
/// see module doc. The only state-changing field a caller can name here is
/// the idempotency key; the profile comes from a separate, already-proven
/// `&AuthenticatedProfileId` parameter to [`start_intent`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartOnboardingRequest {
    pub idempotency_key: String,
}

/// `POST /v1/profile/primary-onboarding` (Task 8 mounts the route). Starts
/// (or, on a replay of the same idempotency key, returns) the caller's
/// primary-onboarding intent. Never creates a second intent for the same
/// `(profile_id, idempotency_key)` pair — see module doc.
///
/// **I3 fix.** `profile` is `&AuthenticatedProfileId`, obtainable only from
/// `profile_auth::authenticate_credential` or
/// `profile_auth::validate_session` — see module doc.
pub async fn start_intent(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    profile: &AuthenticatedProfileId,
    req: StartOnboardingRequest,
) -> Result<IntentView, OnboardingError> {
    let data_key = DataKey::from_secret(data_key_hex);
    let intent_id =
        deterministic_id(&["primary_onboarding", profile.as_str(), &req.idempotency_key]);
    let now = now_unix_seconds();

    let payload = serde_json::to_vec(&serde_json::json!({
        "idempotency_key": req.idempotency_key,
    }))
    .map_err(|e| OnboardingError::MalformedPayload(e.to_string()))?;
    let aad = store.envelope_aad("intents", &intent_id, "intent_enc");
    let intent_enc = crypto_store::seal(&data_key, &aad, &payload)?;

    let profile_id = profile.as_str().to_string();
    let intent_id_for_tx = intent_id.clone();

    let status = store
        .write_tx(move |tx| {
            Box::pin(async move {
                let result = sqlx::query(
                    "INSERT OR IGNORE INTO intents \
                     (id, profile_id, intent_type, status, intent_enc, created_at) \
                     VALUES (?, ?, ?, 'pending', ?, ?)",
                )
                .bind(&intent_id_for_tx)
                .bind(&profile_id)
                .bind(INTENT_TYPE_PRIMARY_ONBOARDING)
                .bind(&intent_enc)
                .bind(now)
                .execute(&mut **tx)
                .await?;

                if result.rows_affected() == 1 {
                    Ok::<String, OnboardingError>(STATE_PENDING.to_string())
                } else {
                    // Replay of the same (profile_id, idempotency_key):
                    // report the existing row's *current* status rather
                    // than assuming it is still pending.
                    let row = sqlx::query("SELECT status FROM intents WHERE id = ?")
                        .bind(&intent_id_for_tx)
                        .fetch_one(&mut **tx)
                        .await?;
                    let status: String = row.try_get("status")?;
                    Ok::<String, OnboardingError>(status)
                }
            })
        })
        .await?;

    Ok(IntentView {
        intent_id,
        profile_id: profile.as_str().to_string(),
        status,
        created_at: now,
    })
}

/// `GET /v1/profile/primary-onboarding/:intentId` — the library half; the
/// mounted route is [`get_primary_onboarding_intent`].
///
/// **I3 fix.** `profile` is `&AuthenticatedProfileId` and the `SELECT`
/// carries `AND profile_id = ?`: an intent belonging to a different
/// profile is indistinguishable from a nonexistent one (`None`), so this
/// primitive cannot be used as a cross-profile intent-status oracle.
///
/// **`AND intent_type = ?` too.** `intents` is shared by several flows —
/// `quotes::create_sponsored_enrollment_quote_at`'s STEP 7 `write_tx` closure
/// writes `intent_type = 'sponsored_enrollment'` rows into the same table —
/// and this was the one accessor in this module whose SQL omitted the
/// predicate ([`transition_in_tx`] and [`fulfill`] both carry it in their own
/// `SELECT`s). Since the route passes its path segment
/// through verbatim and a caller knows both inputs to a row id of its own
/// (`POST /v1/profile` returns the `profile_id`; the caller chose the
/// idempotency key), it could compute the id of its **own** enrollment row and
/// receive a 200 from `GET /v1/profile/primary-onboarding/:intentId` carrying
/// the enrollment vocabulary (`pending`/`submitted`/`executed`) out of a route
/// whose [`IntentStatusResponse`] documents the onboarding one
/// (`pending`/`authorized`/`submitted`/`fulfilled`/`failed`). Not a
/// cross-profile leak — the `SELECT` was already profile-scoped — but a broken
/// contract and a gap in a defence this module closes everywhere else. A
/// non-onboarding row now yields `None`, i.e. the *same* 404 as a nonexistent
/// one, which keeps the ownership-oracle rule intact.
/// `tests::the_intent_route_404s_the_callers_own_non_onboarding_intent` is the
/// pin.
pub async fn get_intent(
    store: &StreamGStore,
    profile: &AuthenticatedProfileId,
    intent_id: &str,
) -> Result<Option<IntentView>, OnboardingError> {
    let intent_id_owned = intent_id.to_string();
    let profile_id_owned = profile.as_str().to_string();
    store
        .read(|handle| {
            Box::pin(async move {
                let row = handle
                    .fetch_optional(
                        sqlx::query(
                            "SELECT id, profile_id, status, created_at FROM intents \
                             WHERE id = ? AND profile_id = ? AND intent_type = ?",
                        )
                        .bind(&intent_id_owned)
                        .bind(&profile_id_owned)
                        .bind(INTENT_TYPE_PRIMARY_ONBOARDING),
                    )
                    .await?;
                match row {
                    None => Ok::<Option<IntentView>, OnboardingError>(None),
                    Some(row) => {
                        let intent_id: String = row.try_get("id")?;
                        let profile_id: String = row.try_get("profile_id")?;
                        let status: String = row.try_get("status")?;
                        let created_at: i64 = row.try_get("created_at")?;
                        Ok(Some(IntentView {
                            intent_id,
                            profile_id,
                            status,
                            created_at,
                        }))
                    }
                }
            })
        })
        .await
}

// --- The mounted HTTP route ---------------------------------------------

/// `GET /v1/profile/primary-onboarding/:intentId` response body.
///
/// **A separate type from [`IntentView`], and the difference is one field:
/// `profile_id` is not on the wire.** Founder decision, applied here rather
/// than by annotating `IntentView`, for two reasons. First, `IntentView` is a
/// library return value — [`start_intent`] and [`get_intent`] both hand one
/// back and this module's own tests read `profile_id` off it (see
/// `tests::start_intent_is_idempotent_per_profile_and_key`) — so a
/// `#[serde(skip)]` there would silently change a shape that is not this
/// route's to change. Second, a `Serialize`-only struct with a skipped field is
/// a shape you have to read an attribute to know; a named response type states
/// it.
///
/// Why the field is dropped at all: the caller reached this handler through
/// [`super::profile_auth::AuthenticatedProfile`], so it is *already* proven to
/// be the owning profile — [`get_intent`]'s `SELECT` carries
/// `AND profile_id = ?` and returns `None` otherwise, which is what makes the
/// 404 below not an ownership oracle. Echoing the id back therefore tells the
/// caller only something it supplied the credential for, while putting one more
/// stable identifier on the wire and into every intermediary's logs. Same
/// posture as `super::http_error::ApiErrorBody` carrying a code and nothing
/// else.
///
/// snake_case, matching every other Stream G wire DTO.
#[derive(Debug, Clone, Serialize)]
pub struct IntentStatusResponse {
    pub intent_id: String,
    /// One of [`STATE_PENDING`] / [`STATE_AUTHORIZED`] / [`STATE_SUBMITTED`] /
    /// [`STATE_FULFILLED`] / [`STATE_FAILED`] — the **onboarding** state
    /// machine, which is this route's vocabulary and not the
    /// broadcast/reconcile one.
    pub status: String,
    pub created_at: i64,
}

impl From<IntentView> for IntentStatusResponse {
    /// Drops `profile_id` deliberately — see [`IntentStatusResponse`]'s doc.
    /// Written as a `From` rather than a field-by-field build at the call site
    /// so the drop happens in exactly one place that carries the reason.
    fn from(view: IntentView) -> Self {
        Self {
            intent_id: view.intent_id,
            status: view.status,
            created_at: view.created_at,
        }
    }
}

/// `GET /v1/profile/primary-onboarding/:intentId` — the caller's own intent.
///
/// **`:intentId`, not `{intentId}`.** This crate runs axum 0.7 / matchit 0.7,
/// where `{` and `}` are ordinary path characters: `"/…/{intentId}"` compiles,
/// does not panic, and matches only the literal segment `{intentId}`, so every
/// real request would 404. In-crate prose that used to write the brace form —
/// this module's own included — was rewritten to `:intentId` in the
/// documentation pass after this route was mounted, precisely so a reader does
/// not copy a template the router cannot serve; the only braces left in this
/// crate's route prose are the ones (like this paragraph) that name the trap.
/// `tests::the_intent_route_binds_the_intent_id_from_the_path` is what makes
/// that a failing test rather than a silent outage, mirroring
/// `super::profile_auth::tests::the_delete_route_binds_the_session_id_from_the_path`.
///
/// **`None` is 404 and never 403.** [`get_intent`] collapses "no such intent"
/// and "an intent under a different profile" into the same `None` on purpose
/// (its own doc), and [`OnboardingError::IntentNotFound`] is 404 — mapping the
/// second case to 403 would re-open on the wire the oracle the `SELECT` closed
/// in the store. See `super::http_error`'s ownership-oracle rule and
/// `super::http_error::tests::stream_g_error_mapping_never_emits_403`.
///
/// **No chain dependency.** Like the three `profile_auth` routes, this one
/// touches only `StreamGStore`; there is no `trusted_chain()` call here, so a
/// 200 from this route in a `GOAT_ATTESTOR_MOCK=1` process is a real answer and
/// not a stub — which is what lets the tests below assert an accepting arm at
/// all (`runtime::StreamGState::trusted_chain`).
///
/// Residual, same as [`super::profile_auth::delete_session`]'s: `Path<String>`'s
/// own rejection (a path segment whose percent-encoding is not valid UTF-8) is
/// axum's and answers in `text/plain`. Every other failure here goes through
/// [`ApiError`].
pub(crate) async fn get_primary_onboarding_intent(
    State(state): State<StreamGState>,
    caller: AuthenticatedProfile,
    Path(intent_id): Path<String>,
) -> Result<Json<IntentStatusResponse>, ApiError> {
    let view = get_intent(state.store(), caller.profile(), &intent_id)
        .await?
        .ok_or(OnboardingError::IntentNotFound)?;
    Ok(Json(IntentStatusResponse::from(view)))
}

/// Guarded state transition. `intent_type` is included in the UPDATE's own
/// WHERE clause (C2) — belt-and-suspenders alongside [`fulfill`]'s
/// intent-type check on the row it reads, so this primitive can never
/// silently transition a non-onboarding intent even if some future caller
/// mismatches ids.
///
/// On 0 rows affected (M5), distinguishes "no such intent" from "wrong
/// prior state" with a read inside the same transaction instead of
/// reporting `IllegalTransition` with the *expected* `from` regardless of
/// what the row actually held.
///
/// **I3 fix.** `profile_id` is now a required parameter and is part of
/// both the guarded UPDATE's WHERE clause *and* the 0-rows-affected
/// fallback SELECT. Scoping only the UPDATE would still let a non-owner
/// distinguish "wrong profile" from "wrong state" by reading the *actual*
/// status of someone else's intent off the `IllegalTransition` error;
/// scoping the fallback SELECT too means a foreign intent reports
/// `IntentNotFound` — indistinguishable from a genuinely nonexistent one —
/// same as [`get_intent`]'s reasoning.
async fn transition_in_tx(
    tx: &mut SqliteTransaction<'static>,
    intent_id: &str,
    profile_id: &str,
    intent_type: &str,
    from: &str,
    to: &str,
) -> Result<(), OnboardingError> {
    let result = sqlx::query(
        "UPDATE intents SET status = ? WHERE id = ? AND profile_id = ? AND status = ? AND intent_type = ?",
    )
    .bind(to)
    .bind(intent_id)
    .bind(profile_id)
    .bind(from)
    .bind(intent_type)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() == 1 {
        return Ok(());
    }

    let row = sqlx::query("SELECT status FROM intents WHERE id = ? AND profile_id = ?")
        .bind(intent_id)
        .bind(profile_id)
        .fetch_optional(&mut **tx)
        .await?;
    match row {
        None => Err(OnboardingError::IntentNotFound),
        Some(row) => {
            let actual: String = row.try_get("status")?;
            Err(OnboardingError::IllegalTransition {
                from: actual,
                to: to.to_string(),
            })
        }
    }
}

/// `pending -> authorized`.
///
/// **I3 fix.** `profile` is `&AuthenticatedProfileId` — see module doc.
pub async fn mark_authorized(
    store: &StreamGStore,
    profile: &AuthenticatedProfileId,
    intent_id: &str,
) -> Result<(), OnboardingError> {
    let intent_id = intent_id.to_string();
    let profile_id = profile.as_str().to_string();
    store
        .write_tx(move |tx| {
            Box::pin(async move {
                transition_in_tx(
                    tx,
                    &intent_id,
                    &profile_id,
                    INTENT_TYPE_PRIMARY_ONBOARDING,
                    STATE_PENDING,
                    STATE_AUTHORIZED,
                )
                .await
            })
        })
        .await
}

/// `authorized -> submitted`.
///
/// **I3 fix.** `profile` is `&AuthenticatedProfileId` — see module doc.
pub async fn mark_submitted(
    store: &StreamGStore,
    profile: &AuthenticatedProfileId,
    intent_id: &str,
) -> Result<(), OnboardingError> {
    let intent_id = intent_id.to_string();
    let profile_id = profile.as_str().to_string();
    store
        .write_tx(move |tx| {
            Box::pin(async move {
                transition_in_tx(
                    tx,
                    &intent_id,
                    &profile_id,
                    INTENT_TYPE_PRIMARY_ONBOARDING,
                    STATE_AUTHORIZED,
                    STATE_SUBMITTED,
                )
                .await
            })
        })
        .await
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FulfillOutcome {
    Fulfilled {
        wallet_id: String,
    },
    /// M6: carries the specific reason (e.g. [`ERR_ENTITLEMENT_EXHAUSTED`],
    /// [`ERR_WALLET_ALREADY_BOUND`]) so a Task 8 route wired on `fulfill`
    /// — the module doc's "real flow" — can surface hazard SG-6's mandated
    /// typed error instead of an unqualified `"failed"` status.
    Failed {
        code: &'static str,
    },
}

/// `submitted -> fulfilled | failed`. Claims the free primary wallet and
/// the final state transition happen in the *same* `write_tx`: if the
/// entitlement is already exhausted, or the address already backs a
/// different profile (M3), that is a normal business outcome (`failed`),
/// committed like any other state, not an error unwound out of the
/// transaction.
///
/// **Important-1 fix (round 2).** `profile` is `&AuthenticatedProfileId`,
/// but it is a *predicate*, not the credit authority. `profile_id` is still
/// resolved inside this same transaction from the intent row itself
/// (`SELECT profile_id, intent_type FROM intents WHERE id = ?`) — exactly
/// as before this fix — and that resolved value, never the parameter, is
/// what gets credited and what gets passed into `transition_in_tx`.
/// `profile.as_str()` is compared against the resolved owner and any
/// disagreement is rejected as [`OnboardingError::IntentNotFound`] *before*
/// the entitlement claim is attempted.
///
/// This closes a bearer-capability hole an earlier fix (lane B's C2 fix)
/// introduced: dropping `profile_id` from this function's parameters
/// entirely made a cross-profile *mismatch* unrepresentable, but it also
/// deleted the only caller-identity input this function had, so `fulfill`
/// authorized purely on knowledge of `intent_id` — a value that travels in
/// a URL path (`GET /v1/profile/primary-onboarding/:intentId` — the `:name`
/// form this axum version actually matches; see
/// [`get_primary_onboarding_intent`]'s doc). An
/// attacker who merely obtained a victim's `intent_id` could spend the
/// victim's one-time entitlement and permanently strand the victim's own
/// later attempt at `ENTITLEMENT_EXHAUSTED`.
///
/// This does **not** reintroduce C2. C2's bug was using an unvalidated
/// caller-supplied value as the *authority* for who gets credited; this
/// uses the caller-supplied value only as a *check* against an authority
/// (the intent row) that is resolved independently and never overridden by
/// it — see `profile_auth`'s module doc ("I3 fix" section) for the
/// cross-file writeup, and
/// `fulfill_rejects_a_caller_who_is_not_the_intents_owner` below for the
/// regression proof.
pub async fn fulfill(
    store: &StreamGStore,
    profile: &AuthenticatedProfileId,
    intent_id: &str,
    chain_id: i64,
    address: &str,
    wallet_type: &str,
) -> Result<FulfillOutcome, OnboardingError> {
    let caller_profile_id = profile.as_str().to_string();
    let intent_id = intent_id.to_string();
    let address = address.to_string();
    let wallet_type = wallet_type.to_string();

    store
        .write_tx(move |tx| {
            Box::pin(async move {
                let row = sqlx::query("SELECT profile_id, intent_type FROM intents WHERE id = ?")
                    .bind(&intent_id)
                    .fetch_optional(&mut **tx)
                    .await?;
                let (profile_id, intent_type): (String, String) = match row {
                    None => return Err(OnboardingError::IntentNotFound),
                    Some(row) => (row.try_get("profile_id")?, row.try_get("intent_type")?),
                };
                if intent_type != INTENT_TYPE_PRIMARY_ONBOARDING {
                    // Not an onboarding intent at all — from this
                    // function's perspective there is nothing to fulfill.
                    // (This is also now unreachable via the guarded UPDATE
                    // below, which carries the same predicate; checked
                    // here too so the rejection happens before any
                    // entitlement claim is attempted.)
                    return Err(OnboardingError::IntentNotFound);
                }
                // Important-1 fix: the caller must be authenticated as the
                // intent's real owner. `profile_id` (resolved above from
                // the row) remains the sole authority credited below —
                // `caller_profile_id` is never substituted in, it is only
                // compared. A mismatch is indistinguishable from a
                // nonexistent intent, same reasoning as `transition_in_tx`
                // / `get_intent`.
                if caller_profile_id != profile_id {
                    return Err(OnboardingError::IntentNotFound);
                }

                let claim = claim_free_primary_wallet_in_tx(
                    tx,
                    &profile_id,
                    chain_id,
                    &address,
                    &wallet_type,
                    None,
                )
                .await?;
                match claim {
                    WalletClaimOutcome::Claimed { wallet_id } => {
                        transition_in_tx(
                            tx,
                            &intent_id,
                            &profile_id,
                            INTENT_TYPE_PRIMARY_ONBOARDING,
                            STATE_SUBMITTED,
                            STATE_FULFILLED,
                        )
                        .await?;
                        Ok(FulfillOutcome::Fulfilled { wallet_id })
                    }
                    WalletClaimOutcome::Exhausted => {
                        transition_in_tx(
                            tx,
                            &intent_id,
                            &profile_id,
                            INTENT_TYPE_PRIMARY_ONBOARDING,
                            STATE_SUBMITTED,
                            STATE_FAILED,
                        )
                        .await?;
                        Ok(FulfillOutcome::Failed {
                            code: ERR_ENTITLEMENT_EXHAUSTED,
                        })
                    }
                    WalletClaimOutcome::AlreadyBound => {
                        transition_in_tx(
                            tx,
                            &intent_id,
                            &profile_id,
                            INTENT_TYPE_PRIMARY_ONBOARDING,
                            STATE_SUBMITTED,
                            STATE_FAILED,
                        )
                        .await?;
                        Ok(FulfillOutcome::Failed {
                            code: ERR_WALLET_ALREADY_BOUND,
                        })
                    }
                }
            })
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn open_store() -> (tempfile::TempDir, StreamGStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open store");
        (dir, store)
    }

    /// Test-only helper: seed a `profiles` row directly (this module does
    /// not own profile creation — that's `profile_auth.rs`), satisfying the
    /// `profile_wallets.profile_id` / `intents.profile_id` foreign keys.
    async fn seed_profile(store: &StreamGStore, profile_id: &str) {
        let profile_id = profile_id.to_string();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO profiles (id, created_at, status) VALUES (?, ?, 'active')",
                    )
                    .bind(&profile_id)
                    .bind(0i64)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed profile");
    }

    async fn count_primary_wallets(store: &StreamGStore, profile_id: &str) -> i64 {
        let profile_id = profile_id.to_string();
        store
            .read(|handle| {
                Box::pin(async move {
                    let count: i64 = handle
                        .fetch_scalar(
                            sqlx::query_scalar(
                                "SELECT COUNT(*) FROM profile_wallets \
                                 WHERE profile_id = ? AND is_primary = 1",
                            )
                            .bind(&profile_id),
                        )
                        .await?;
                    Ok::<i64, StreamGStoreError>(count)
                })
            })
            .await
            .expect("count primary wallets")
    }

    #[tokio::test]
    async fn only_one_free_primary_per_profile() {
        let (_dir, store) = open_store().await;
        seed_profile(&store, "profile-1").await;

        claim_free_primary_wallet(
            &store,
            &AuthenticatedProfileId::for_test("profile-1"),
            1,
            "0xaaaa00000000000000000000000000000000aaaa",
            "eoa",
            "idem-only-primary-1",
        )
        .await
        .expect("first claim succeeds");

        let err = claim_free_primary_wallet(
            &store,
            &AuthenticatedProfileId::for_test("profile-1"),
            1,
            "0xbbbb00000000000000000000000000000000bbbb",
            "eoa",
            "idem-only-primary-2",
        )
        .await
        .expect_err("second claim must be refused");
        assert!(matches!(err, OnboardingError::EntitlementExhausted));
        assert_eq!(err.code(), ERR_ENTITLEMENT_EXHAUSTED);

        assert_eq!(
            count_primary_wallets(&store, "profile-1").await,
            1,
            "exactly one primary wallet row must exist after the refused second attempt"
        );
    }

    #[tokio::test]
    async fn local_reinstall_does_not_reset_server_entitlement() {
        let (_dir, store) = open_store().await;
        seed_profile(&store, "profile-reinstall").await;

        // "Install A": claim the free primary.
        claim_free_primary_wallet(
            &store,
            &AuthenticatedProfileId::for_test("profile-reinstall"),
            1,
            "0xaaaa00000000000000000000000000000000aaaa",
            "eoa",
            "idem-reinstall-a",
        )
        .await
        .expect("install A claims the free primary");

        // "Install B" — simulates a fresh local reinstall: a brand new
        // client context with no shared local state whatsoever with
        // install A (no session token, no challenge, no device/install id
        // is even a parameter this function accepts — see module doc).
        // The only thing carried over is the *server-side* profile_id,
        // which is exactly what the entitlement must be keyed on.
        let err = claim_free_primary_wallet(
            &store,
            &AuthenticatedProfileId::for_test("profile-reinstall"),
            1,
            "0xcccc00000000000000000000000000000000cccc",
            "eoa",
            "idem-reinstall-b",
        )
        .await
        .expect_err("a fresh client context presenting the same profile must still be refused");
        assert!(matches!(err, OnboardingError::EntitlementExhausted));

        assert_eq!(
            count_primary_wallets(&store, "profile-reinstall").await,
            1,
            "reinstall must not be able to mint a second free primary"
        );
    }

    #[tokio::test]
    async fn two_concurrent_primary_claims_for_one_profile_exactly_one_succeeds() {
        // True concurrent tokio tasks; the single-connection write_tx
        // discipline (BEGIN IMMEDIATE) serializes them at the SQLite level,
        // so this proves the atomic-INSERT guard holds even when both
        // attempts are genuinely in flight at once, not just sequential
        // calls from one task.
        let (_dir, store) = open_store().await;
        seed_profile(&store, "profile-race").await;
        let store = std::sync::Arc::new(store);

        let s1 = store.clone();
        let t1 = tokio::spawn(async move {
            claim_free_primary_wallet(
                &s1,
                &AuthenticatedProfileId::for_test("profile-race"),
                1,
                "0xaaaa00000000000000000000000000000000aaaa",
                "eoa",
                "idem-race-1",
            )
            .await
        });
        let s2 = store.clone();
        let t2 = tokio::spawn(async move {
            claim_free_primary_wallet(
                &s2,
                &AuthenticatedProfileId::for_test("profile-race"),
                1,
                "0xbbbb00000000000000000000000000000000bbbb",
                "eoa",
                "idem-race-2",
            )
            .await
        });

        let (r1, r2) = tokio::join!(t1, t2);
        let r1 = r1.unwrap();
        let r2 = r2.unwrap();

        let successes = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
        let exhausted = [&r1, &r2]
            .iter()
            .filter(|r| matches!(r, Err(OnboardingError::EntitlementExhausted)))
            .count();
        assert_eq!(successes, 1, "exactly one concurrent claim must succeed");
        assert_eq!(exhausted, 1, "the other must see ENTITLEMENT_EXHAUSTED");

        assert_eq!(count_primary_wallets(&store, "profile-race").await, 1);
    }

    #[tokio::test]
    async fn onboarding_intent_is_idempotent_per_key() {
        let (_dir, store) = open_store().await;
        seed_profile(&store, "profile-onboard").await;
        let data_key_hex = SecretHex::from_hex(&"aa".repeat(32)).expect("valid test key");

        let first = start_intent(
            &store,
            &data_key_hex,
            &AuthenticatedProfileId::for_test("profile-onboard"),
            StartOnboardingRequest {
                idempotency_key: "idem-1".to_string(),
            },
        )
        .await
        .expect("start intent");
        assert_eq!(first.status, STATE_PENDING);

        // Advance the intent so a naive replay-resets-to-pending bug would
        // be visible.
        mark_authorized(
            &store,
            &AuthenticatedProfileId::for_test("profile-onboard"),
            &first.intent_id,
        )
        .await
        .expect("mark authorized");

        let replay = start_intent(
            &store,
            &data_key_hex,
            &AuthenticatedProfileId::for_test("profile-onboard"),
            StartOnboardingRequest {
                idempotency_key: "idem-1".to_string(),
            },
        )
        .await
        .expect("replay start intent");

        assert_eq!(
            replay.intent_id, first.intent_id,
            "same idempotency key must yield the same intent"
        );
        assert_eq!(
            replay.status, STATE_AUTHORIZED,
            "replay must report the *current* status, not reset it"
        );

        let count: i64 = store
            .read(|handle| {
                Box::pin(async move {
                    let count: i64 = handle
                        .fetch_scalar(sqlx::query_scalar(
                            "SELECT COUNT(*) FROM intents WHERE intent_type = 'primary_onboarding'",
                        ))
                        .await?;
                    Ok::<i64, StreamGStoreError>(count)
                })
            })
            .await
            .expect("count intents");
        assert_eq!(count, 1, "replay must not create a second intent row");
    }

    #[tokio::test]
    async fn onboarding_state_machine_rejects_illegal_jumps() {
        let (_dir, store) = open_store().await;
        seed_profile(&store, "profile-illegal").await;
        let data_key_hex = SecretHex::from_hex(&"bb".repeat(32)).expect("valid test key");

        let intent = start_intent(
            &store,
            &data_key_hex,
            &AuthenticatedProfileId::for_test("profile-illegal"),
            StartOnboardingRequest {
                idempotency_key: "idem-illegal".to_string(),
            },
        )
        .await
        .expect("start intent");

        // pending -> submitted directly is illegal; must go through
        // authorized first.
        let err = mark_submitted(
            &store,
            &AuthenticatedProfileId::for_test("profile-illegal"),
            &intent.intent_id,
        )
        .await
        .expect_err("pending -> submitted must be rejected");
        assert!(matches!(err, OnboardingError::IllegalTransition { .. }));
        assert_eq!(err.code(), ERR_ILLEGAL_TRANSITION);

        mark_authorized(
            &store,
            &AuthenticatedProfileId::for_test("profile-illegal"),
            &intent.intent_id,
        )
        .await
        .expect("pending -> authorized");
        mark_submitted(
            &store,
            &AuthenticatedProfileId::for_test("profile-illegal"),
            &intent.intent_id,
        )
        .await
        .expect("authorized -> submitted");

        let view = get_intent(
            &store,
            &AuthenticatedProfileId::for_test("profile-illegal"),
            &intent.intent_id,
        )
        .await
        .expect("get intent")
        .expect("intent exists");
        assert_eq!(view.status, STATE_SUBMITTED);
    }

    #[tokio::test]
    async fn fulfill_marks_failed_without_erroring_when_entitlement_already_exhausted() {
        let (_dir, store) = open_store().await;
        seed_profile(&store, "profile-fulfill").await;

        claim_free_primary_wallet(
            &store,
            &AuthenticatedProfileId::for_test("profile-fulfill"),
            1,
            "0xaaaa00000000000000000000000000000000aaaa",
            "eoa",
            "idem-prefulfill",
        )
        .await
        .expect("pre-claim the primary directly, outside the intent flow");

        let data_key_hex = SecretHex::from_hex(&"cc".repeat(32)).expect("valid test key");
        let intent = start_intent(
            &store,
            &data_key_hex,
            &AuthenticatedProfileId::for_test("profile-fulfill"),
            StartOnboardingRequest {
                idempotency_key: "idem-fulfill".to_string(),
            },
        )
        .await
        .expect("start intent");
        mark_authorized(
            &store,
            &AuthenticatedProfileId::for_test("profile-fulfill"),
            &intent.intent_id,
        )
        .await
        .unwrap();
        mark_submitted(
            &store,
            &AuthenticatedProfileId::for_test("profile-fulfill"),
            &intent.intent_id,
        )
        .await
        .unwrap();

        let outcome = fulfill(
            &store,
            &AuthenticatedProfileId::for_test("profile-fulfill"),
            &intent.intent_id,
            1,
            "0xdddd00000000000000000000000000000000dddd",
            "eoa",
        )
        .await
        .expect("fulfill must not error out on exhaustion — it is a normal terminal state");
        assert_eq!(
            outcome,
            FulfillOutcome::Failed {
                code: ERR_ENTITLEMENT_EXHAUSTED
            },
            "M6: the typed exhaustion code must reach the caller through fulfill, not a reasonless Failed"
        );

        let view = get_intent(
            &store,
            &AuthenticatedProfileId::for_test("profile-fulfill"),
            &intent.intent_id,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(view.status, STATE_FAILED);
    }

    #[tokio::test]
    async fn fulfill_resolves_profile_from_the_intent_and_never_touches_another_profile() {
        // C2 regression, updated for the Important-1 round-2 fix.
        // `fulfill` again takes an `&AuthenticatedProfileId`, but only as a
        // predicate checked against the intent's real owner — the row
        // itself remains the sole authority for who gets credited (the
        // parameter is compared, never substituted in as the credited
        // value). This test proves the *effect*: fulfilling profile A's own
        // intent, called as A, credits A and leaves an unrelated profile B
        // completely untouched. (The complementary property — a caller who
        // is NOT the owner gets rejected and credits nobody — is
        // `fulfill_rejects_a_caller_who_is_not_the_intents_owner` below.)
        let (_dir, store) = open_store().await;
        seed_profile(&store, "profile-c2-a").await;
        seed_profile(&store, "profile-c2-b").await;

        let data_key_hex = SecretHex::from_hex(&"11".repeat(32)).expect("valid test key");
        let intent = start_intent(
            &store,
            &data_key_hex,
            &AuthenticatedProfileId::for_test("profile-c2-a"),
            StartOnboardingRequest {
                idempotency_key: "idem-c2".to_string(),
            },
        )
        .await
        .expect("start intent for profile-c2-a");
        mark_authorized(
            &store,
            &AuthenticatedProfileId::for_test("profile-c2-a"),
            &intent.intent_id,
        )
        .await
        .unwrap();
        mark_submitted(
            &store,
            &AuthenticatedProfileId::for_test("profile-c2-a"),
            &intent.intent_id,
        )
        .await
        .unwrap();

        let outcome = fulfill(
            &store,
            &AuthenticatedProfileId::for_test("profile-c2-a"),
            &intent.intent_id,
            1,
            "0xeeee00000000000000000000000000000000eeee",
            "eoa",
        )
        .await
        .expect("fulfilling profile-c2-a's own intent must succeed");
        assert!(matches!(outcome, FulfillOutcome::Fulfilled { .. }));

        assert_eq!(
            count_primary_wallets(&store, "profile-c2-a").await,
            1,
            "profile-c2-a (the intent's real owner) must receive the primary"
        );
        assert_eq!(
            count_primary_wallets(&store, "profile-c2-b").await,
            0,
            "an unrelated profile's entitlement must be untouched by fulfilling someone else's intent"
        );
    }

    #[tokio::test]
    async fn fulfill_rejects_a_non_onboarding_intent_type() {
        // C2: the guarded UPDATE (and the SELECT that resolves profile_id)
        // must not match a `submitted` row belonging to some other intent
        // flow that happens to share the `intents` table.
        let (_dir, store) = open_store().await;
        seed_profile(&store, "profile-c2-wrong-type").await;

        let intent_id = "some-other-flow-intent".to_string();
        store
            .write_tx({
                let intent_id = intent_id.clone();
                move |tx| {
                    Box::pin(async move {
                        sqlx::query(
                            "INSERT INTO intents (id, profile_id, intent_type, status, intent_enc, created_at) \
                             VALUES (?, ?, 'some_other_flow', 'submitted', ?, ?)",
                        )
                        .bind(&intent_id)
                        .bind("profile-c2-wrong-type")
                        .bind(Vec::<u8>::new())
                        .bind(0i64)
                        .execute(&mut **tx)
                        .await?;
                        Ok::<(), StreamGStoreError>(())
                    })
                }
            })
            .await
            .expect("seed a non-onboarding intent row directly");

        let err = fulfill(
            &store,
            &AuthenticatedProfileId::for_test("profile-c2-wrong-type"),
            &intent_id,
            1,
            "0xffff00000000000000000000000000000000ffff",
            "eoa",
        )
        .await
        .expect_err("fulfill must reject an intent that is not primary_onboarding");
        assert!(matches!(err, OnboardingError::IntentNotFound));

        assert_eq!(
            count_primary_wallets(&store, "profile-c2-wrong-type").await,
            0
        );
    }

    /// Important-1 (round 2). Before this fix, `fulfill` authorized purely
    /// on knowledge of `intent_id` — a value that travels in a URL path
    /// (`GET /v1/profile/primary-onboarding/:intentId`). An attacker who
    /// obtained a victim's `intent_id` could call `fulfill` with their own
    /// wallet address and consume the victim's one-time entitlement,
    /// permanently stranding the victim's own later attempt at
    /// `ENTITLEMENT_EXHAUSTED`. This proves the fix: a caller authenticated
    /// as anyone other than the intent's real owner is rejected before any
    /// entitlement claim is attempted, and the owner's entitlement is left
    /// completely intact (count stays 0) — then the real owner can still
    /// fulfill their own intent afterward.
    #[tokio::test]
    async fn fulfill_rejects_a_caller_who_is_not_the_intents_owner() {
        let (_dir, store) = open_store().await;
        seed_profile(&store, "profile-i1-owner").await;
        seed_profile(&store, "profile-i1-attacker").await;

        let data_key_hex = SecretHex::from_hex(&"77".repeat(32)).expect("valid test key");
        let intent = start_intent(
            &store,
            &data_key_hex,
            &AuthenticatedProfileId::for_test("profile-i1-owner"),
            StartOnboardingRequest {
                idempotency_key: "idem-i1-fulfill".to_string(),
            },
        )
        .await
        .expect("start intent for the real owner");
        mark_authorized(
            &store,
            &AuthenticatedProfileId::for_test("profile-i1-owner"),
            &intent.intent_id,
        )
        .await
        .unwrap();
        mark_submitted(
            &store,
            &AuthenticatedProfileId::for_test("profile-i1-owner"),
            &intent.intent_id,
        )
        .await
        .unwrap();

        // The attacker knows the (URL-path) intent_id but is authenticated
        // as a completely different profile.
        let err = fulfill(
            &store,
            &AuthenticatedProfileId::for_test("profile-i1-attacker"),
            &intent.intent_id,
            1,
            "0xbad1bad1bad1bad1bad1bad1bad1bad1bad1bad1",
            "eoa",
        )
        .await
        .expect_err("a non-owner caller must not be able to fulfill someone else's intent");
        assert!(
            matches!(err, OnboardingError::IntentNotFound),
            "a foreign intent must report IntentNotFound, not leak state to a non-owner"
        );
        assert_eq!(err.code(), ERR_INTENT_NOT_FOUND);

        assert_eq!(
            count_primary_wallets(&store, "profile-i1-owner").await,
            0,
            "the real owner's entitlement must be untouched by the rejected attempt"
        );
        assert_eq!(
            count_primary_wallets(&store, "profile-i1-attacker").await,
            0
        );

        let view = get_intent(
            &store,
            &AuthenticatedProfileId::for_test("profile-i1-owner"),
            &intent.intent_id,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            view.status, STATE_SUBMITTED,
            "the rejected attempt must not have silently advanced the intent"
        );

        // The true owner must still be able to fulfill their own intent
        // afterward — the rejection above is ownership-specific, not a
        // general break of `fulfill`.
        let outcome = fulfill(
            &store,
            &AuthenticatedProfileId::for_test("profile-i1-owner"),
            &intent.intent_id,
            1,
            "0xcafecafecafecafecafecafecafecafecafecafe",
            "eoa",
        )
        .await
        .expect("the true owner must still be able to fulfill their own intent");
        assert!(matches!(outcome, FulfillOutcome::Fulfilled { .. }));
        assert_eq!(count_primary_wallets(&store, "profile-i1-owner").await, 1);
    }

    #[tokio::test]
    async fn wallet_address_casing_variants_normalize_and_collide() {
        // I4: `profile_wallets.address` must be normalized before it is
        // bound, so `UNIQUE(chain_id, address)` enforces "one wallet backs
        // at most one profile per chain" regardless of how a client
        // presents the address.
        let (_dir, store) = open_store().await;
        seed_profile(&store, "profile-casing-1").await;
        seed_profile(&store, "profile-casing-2").await;

        claim_free_primary_wallet(
            &store,
            &AuthenticatedProfileId::for_test("profile-casing-1"),
            1,
            "0xAbCdEf000000000000000000000000000000AbCd",
            "eoa",
            "idem-casing-1",
        )
        .await
        .expect("first claim with mixed-case address succeeds");

        let err = claim_free_primary_wallet(
            &store,
            &AuthenticatedProfileId::for_test("profile-casing-2"),
            1,
            "0xabcdef000000000000000000000000000000abcd",
            "eoa",
            "idem-casing-2",
        )
        .await
        .expect_err(
            "same address under a different casing must collide on UNIQUE(chain_id, address)",
        );
        assert!(matches!(err, OnboardingError::WalletAlreadyBound));
        assert_eq!(err.code(), ERR_WALLET_ALREADY_BOUND);

        assert_eq!(
            count_primary_wallets(&store, "profile-casing-2").await,
            0,
            "the casing-variant claim must not have inserted a row"
        );
    }

    #[tokio::test]
    async fn malformed_address_is_rejected_as_bad_address() {
        // I4: unparseable input must be rejected with a typed error
        // instead of being stored verbatim.
        let (_dir, store) = open_store().await;
        seed_profile(&store, "profile-bad-address").await;

        let err = claim_free_primary_wallet(
            &store,
            &AuthenticatedProfileId::for_test("profile-bad-address"),
            1,
            "not-an-address",
            "eoa",
            "idem-bad-address",
        )
        .await
        .expect_err("malformed address must be rejected");
        assert!(matches!(err, OnboardingError::BadAddress(_)));
        assert_eq!(err.code(), ERR_BAD_ADDRESS);

        assert_eq!(
            count_primary_wallets(&store, "profile-bad-address").await,
            0
        );
    }

    #[tokio::test]
    async fn fulfill_treats_wallet_already_bound_as_a_terminal_failure_not_a_500() {
        // M3: this is the reinstall path the task is named for — a user
        // who lost their credential creates a fresh profile and
        // re-imports the same wallet address that already backs a
        // different profile. Must land on a typed terminal `failed`
        // state, never an untyped Sqlx/INTERNAL error that strands the
        // intent at `submitted` forever.
        let (_dir, store) = open_store().await;
        seed_profile(&store, "profile-m3-owner").await;
        seed_profile(&store, "profile-m3-reinstaller").await;

        let shared_address = "0x999900000000000000000000000000000000dead";
        claim_free_primary_wallet(
            &store,
            &AuthenticatedProfileId::for_test("profile-m3-owner"),
            1,
            shared_address,
            "eoa",
            "idem-m3-owner",
        )
        .await
        .expect("profile-m3-owner claims the address first");

        let data_key_hex = SecretHex::from_hex(&"22".repeat(32)).expect("valid test key");
        let intent = start_intent(
            &store,
            &data_key_hex,
            &AuthenticatedProfileId::for_test("profile-m3-reinstaller"),
            StartOnboardingRequest {
                idempotency_key: "idem-m3-reinstall".to_string(),
            },
        )
        .await
        .expect("start intent");
        mark_authorized(
            &store,
            &AuthenticatedProfileId::for_test("profile-m3-reinstaller"),
            &intent.intent_id,
        )
        .await
        .unwrap();
        mark_submitted(
            &store,
            &AuthenticatedProfileId::for_test("profile-m3-reinstaller"),
            &intent.intent_id,
        )
        .await
        .unwrap();

        let outcome = fulfill(
            &store,
            &AuthenticatedProfileId::for_test("profile-m3-reinstaller"),
            &intent.intent_id,
            1,
            shared_address,
            "eoa",
        )
        .await
        .expect("fulfill must not 500 on a wallet-already-bound conflict");
        assert_eq!(
            outcome,
            FulfillOutcome::Failed {
                code: ERR_WALLET_ALREADY_BOUND
            }
        );

        let view = get_intent(
            &store,
            &AuthenticatedProfileId::for_test("profile-m3-reinstaller"),
            &intent.intent_id,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            view.status, STATE_FAILED,
            "the intent must reach a terminal state, not strand at submitted"
        );
    }

    #[tokio::test]
    async fn mark_authorized_on_unknown_intent_reports_intent_not_found() {
        // M5: a missing row must report IntentNotFound (404-shaped), not
        // IllegalTransition (409-shaped) for a resource that doesn't exist.
        let (_dir, store) = open_store().await;

        let err = mark_authorized(
            &store,
            &AuthenticatedProfileId::for_test("no-such-profile"),
            "no-such-intent",
        )
        .await
        .expect_err("unknown intent must be rejected");
        assert!(matches!(err, OnboardingError::IntentNotFound));
        assert_eq!(err.code(), ERR_INTENT_NOT_FOUND);
    }

    #[tokio::test]
    async fn illegal_transition_reports_the_actual_prior_state_not_the_expected_one() {
        // M5: `from` in IllegalTransition must be the row's *actual*
        // status, not just an echo of the caller's expected prior state.
        let (_dir, store) = open_store().await;
        seed_profile(&store, "profile-m5-actual").await;
        let data_key_hex = SecretHex::from_hex(&"33".repeat(32)).expect("valid test key");

        let intent = start_intent(
            &store,
            &data_key_hex,
            &AuthenticatedProfileId::for_test("profile-m5-actual"),
            StartOnboardingRequest {
                idempotency_key: "idem-m5".to_string(),
            },
        )
        .await
        .expect("start intent");
        // Intent is `pending`. mark_submitted expects `authorized`, so this
        // is 0 rows affected: the actual status is `pending`, not the
        // `authorized` the transition expected.
        let err = mark_submitted(
            &store,
            &AuthenticatedProfileId::for_test("profile-m5-actual"),
            &intent.intent_id,
        )
        .await
        .expect_err("pending -> submitted must be rejected");
        match err {
            OnboardingError::IllegalTransition { from, to } => {
                assert_eq!(from, STATE_PENDING, "from must be the row's actual status");
                assert_eq!(to, STATE_SUBMITTED);
            }
            other => panic!("expected IllegalTransition, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn claim_free_primary_wallet_replay_with_same_idempotency_key_returns_same_wallet_id() {
        // M8: an honest client retry (lost response, network blip) must be
        // distinguishable from a genuine second claim attempt — replaying
        // the same idempotency key must return the same wallet, not
        // ENTITLEMENT_EXHAUSTED.
        let (_dir, store) = open_store().await;
        seed_profile(&store, "profile-m8").await;

        let first = claim_free_primary_wallet(
            &store,
            &AuthenticatedProfileId::for_test("profile-m8"),
            1,
            "0x111100000000000000000000000000000000cafe",
            "eoa",
            "idem-m8",
        )
        .await
        .expect("first claim");

        let replay = claim_free_primary_wallet(
            &store,
            &AuthenticatedProfileId::for_test("profile-m8"),
            1,
            "0x111100000000000000000000000000000000cafe",
            "eoa",
            "idem-m8",
        )
        .await
        .expect("replay of the same idempotency key must succeed, not report exhaustion");
        assert_eq!(
            replay, first,
            "replay must return the same wallet_id as the original claim"
        );

        // A genuinely new attempt (different idempotency key) against an
        // already-claimed profile must still be refused.
        let err = claim_free_primary_wallet(
            &store,
            &AuthenticatedProfileId::for_test("profile-m8"),
            1,
            "0x222200000000000000000000000000000000cafe",
            "eoa",
            "idem-m8-second",
        )
        .await
        .expect_err("a genuinely new claim attempt for an already-claimed profile must be refused");
        assert!(matches!(err, OnboardingError::EntitlementExhausted));

        assert_eq!(count_primary_wallets(&store, "profile-m8").await, 1);
    }

    // --- I3: profile-scoped entry points reject a non-owner ----------------

    /// A caller authenticated as a *different* profile than the intent's
    /// real owner must not be able to advance, or read, that intent. Before
    /// this fix, `mark_authorized`/`mark_submitted`/`get_intent` took only
    /// `intent_id` — no profile parameter, no ownership check at all — so
    /// this scenario was not merely unguarded, it was unrepresentable as a
    /// negative test at all. `IntentNotFound` (not `IllegalTransition`) is
    /// the expected error: see `transition_in_tx`'s doc for why a foreign
    /// intent must be indistinguishable from a nonexistent one.
    #[tokio::test]
    async fn mark_authorized_and_mark_submitted_reject_a_caller_not_authenticated_as_the_owner() {
        let (_dir, store) = open_store().await;
        seed_profile(&store, "profile-i3-owner").await;
        seed_profile(&store, "profile-i3-attacker").await;
        let data_key_hex = SecretHex::from_hex(&"55".repeat(32)).expect("valid test key");

        let intent = start_intent(
            &store,
            &data_key_hex,
            &AuthenticatedProfileId::for_test("profile-i3-owner"),
            StartOnboardingRequest {
                idempotency_key: "idem-i3-mark".to_string(),
            },
        )
        .await
        .expect("start intent for the real owner");

        let attacker = AuthenticatedProfileId::for_test("profile-i3-attacker");
        let err = mark_authorized(&store, &attacker, &intent.intent_id)
            .await
            .expect_err("a non-owner must not be able to advance someone else's intent");
        assert!(
            matches!(err, OnboardingError::IntentNotFound),
            "a foreign intent must report IntentNotFound, not leak IllegalTransition status"
        );
        assert_eq!(err.code(), ERR_INTENT_NOT_FOUND);

        // The true owner can still advance it -- the rejection above is
        // ownership-specific, not a general break.
        let owner = AuthenticatedProfileId::for_test("profile-i3-owner");
        mark_authorized(&store, &owner, &intent.intent_id)
            .await
            .expect("the true owner must still be able to advance its own intent");

        let err = mark_submitted(&store, &attacker, &intent.intent_id)
            .await
            .expect_err("a non-owner must not be able to advance someone else's intent");
        assert!(matches!(err, OnboardingError::IntentNotFound));

        mark_submitted(&store, &owner, &intent.intent_id)
            .await
            .expect("the true owner must still be able to advance its own intent");
    }

    /// `get_intent` must not leak another profile's intent status: a
    /// non-owner sees `None` (indistinguishable from "no such intent"),
    /// while the true owner sees the real row.
    #[tokio::test]
    async fn get_intent_hides_a_different_profiles_intent() {
        let (_dir, store) = open_store().await;
        seed_profile(&store, "profile-i3-get-owner").await;
        seed_profile(&store, "profile-i3-get-attacker").await;
        let data_key_hex = SecretHex::from_hex(&"66".repeat(32)).expect("valid test key");

        let intent = start_intent(
            &store,
            &data_key_hex,
            &AuthenticatedProfileId::for_test("profile-i3-get-owner"),
            StartOnboardingRequest {
                idempotency_key: "idem-i3-get".to_string(),
            },
        )
        .await
        .expect("start intent for the real owner");

        let as_attacker = get_intent(
            &store,
            &AuthenticatedProfileId::for_test("profile-i3-get-attacker"),
            &intent.intent_id,
        )
        .await
        .expect("read must not error");
        assert!(
            as_attacker.is_none(),
            "a non-owner must not be able to read another profile's intent"
        );

        let as_owner = get_intent(
            &store,
            &AuthenticatedProfileId::for_test("profile-i3-get-owner"),
            &intent.intent_id,
        )
        .await
        .expect("read must not error")
        .expect("the true owner must be able to read its own intent");
        assert_eq!(as_owner.intent_id, intent.intent_id);
    }

    // ===================================================================
    // `GET /v1/profile/primary-onboarding/:intentId` — the mounted route.
    //
    // ## Which arm every test below is on (the mock-mode question)
    //
    // `runtime::test_support::enabled_map` inherits `GOAT_ATTESTOR_MOCK=1`, so
    // `state.trusted_chain()` is `None` in every fixture here. That is the trap
    // that makes a "the route is mounted" assertion pass against a stub which
    // refuses unconditionally — and it does not apply: this route reads only
    // `StreamGStore` (`grep -n 'trusted_chain\|live_chain' src/stream_g/onboarding.rs`
    // finds nothing), so every 200 below ran the real handler.
    //
    // The `send` / `route_state` helpers are deliberate near-duplicates of
    // `profile_auth::tests`'. Those are private to that module's own
    // `mod tests`, the same reason `http_error::tests::CapturedLog` duplicates
    // `mod.rs::tests::CapturedLog` rather than sharing it.
    // ===================================================================

    use crate::stream_g::profile_auth::{
        create_profile, AUTH_SCHEME_CREDENTIAL, ERR_MISSING_CREDENTIAL,
    };
    use crate::stream_g::{router, runtime};
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const ROUTE_ORIGIN: &str = "https://a.example";

    async fn route_state(dir: &std::path::Path) -> runtime::StreamGState {
        let mut map = runtime::test_support::enabled_map(dir);
        map.insert("STREAM_G_CORS_ORIGINS".into(), ROUTE_ORIGIN.into());
        let cfg = crate::config::load_from_map(&map).expect("stream G config must validate");
        let controller = runtime::ShutdownController::new();
        runtime::StreamGState::start(&cfg, controller.token())
            .await
            .expect("stream G startup")
    }

    /// One `GET` against a cloned app, with an optional `Authorization` value.
    async fn get(app: &Router, uri: &str, authorization: Option<&str>) -> (StatusCode, String) {
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

    fn intent_uri(intent_id: &str) -> String {
        format!("/v1/profile/primary-onboarding/{intent_id}")
    }

    /// A profile plus the `Authorization` header value that authenticates as
    /// it, and its proven id for library setup calls.
    async fn profile_with_credential(
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

    async fn start(
        state: &runtime::StreamGState,
        profile: &AuthenticatedProfileId,
        idempotency_key: &str,
    ) -> IntentView {
        start_intent(
            state.store(),
            state.data_key_hex(),
            profile,
            StartOnboardingRequest {
                idempotency_key: idempotency_key.to_string(),
            },
        )
        .await
        .expect("start intent")
    }

    /// **The `:intentId` pin.** axum 0.7 / matchit 0.7 treat `{` and `}` as
    /// ordinary path characters, so `"/…/{intentId}"` compiles, does not panic,
    /// and matches only the literal segment `{intentId}` — every real request
    /// 404s. `mod.rs`'s `stream_g_paths_never_fall_back_onto_the_pilot_relayer`
    /// would *confirm* that breakage rather than catch it, because it asserts
    /// unknown paths 404. Mirrors
    /// `profile_auth::tests::the_delete_route_binds_the_session_id_from_the_path`.
    ///
    /// Two intents of the **same** profile are used deliberately: a handler
    /// that ignored the path segment and answered with "an intent of yours"
    /// would pass a single-intent test.
    ///
    /// Mutations this detects (each applied alone, run, reverted):
    /// 1. `"/v1/profile/primary-onboarding/:intentId"` →
    ///    `"…/{intentId}"` in `super::super::router` — both GETs 404.
    /// 2. `get_primary_onboarding_intent` passing a constant instead of the
    ///    `Path` value — one of the two id assertions fails.
    #[tokio::test]
    async fn the_intent_route_binds_the_intent_id_from_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let (profile, authorization) = profile_with_credential(&state, "idem-a2-path").await;
        let a = start(&state, &profile, "intent-a").await;
        let b = start(&state, &profile, "intent-b").await;
        assert_ne!(
            a.intent_id, b.intent_id,
            "two distinct intents are required"
        );

        for expected in [&a, &b] {
            let (status, body) =
                get(&app, &intent_uri(&expected.intent_id), Some(&authorization)).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "a GET naming a real intent must reach the handler (a `{{intentId}}` route would \
                 404): {body}"
            );
            let document: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(
                document["intent_id"].as_str(),
                Some(expected.intent_id.as_str()),
                "the route answered with an intent other than the one named in the path: {body}"
            );
        }
    }

    /// **Unauthenticated access is 401.** The route is profile-scoped, and the
    /// scoping is only meaningful if there is a proven profile to scope to.
    ///
    /// Mutation this detects (applied, run, reverted): swapping the
    /// `AuthenticatedProfile` extractor for a `PresentedOrigin` plus
    /// `AuthenticatedProfileId::for_test(..)` — impossible in a non-test build,
    /// which is the point; approximating it by removing the extractor fails to
    /// compile, because `get_intent` takes `&AuthenticatedProfileId` and there
    /// is no other way to obtain one.
    #[tokio::test]
    async fn the_intent_route_refuses_a_request_with_no_credential() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let (profile, authorization) = profile_with_credential(&state, "idem-a2-noauth").await;
        let intent = start(&state, &profile, "intent-noauth").await;

        let (status, body) = get(&app, &intent_uri(&intent.intent_id), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_MISSING_CREDENTIAL}\"}}"));
        assert!(
            !body.contains(&intent.intent_id),
            "an unauthenticated refusal must echo nothing back: {body}"
        );

        // An unusable header is the same refusal, not a different one.
        let (status, body) = get(
            &app,
            &intent_uri(&intent.intent_id),
            Some("Basic dXNlcjpwYXNz"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_MISSING_CREDENTIAL}\"}}"));

        // Paired non-zero arm: the identical request with the credential
        // succeeds, so the refusals above are about the credential and not a
        // dead route.
        let (status, body) = get(&app, &intent_uri(&intent.intent_id), Some(&authorization)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// **404, never 403 — for both meanings of "not yours".**
    ///
    /// [`get_intent`] returns `None` for an intent that does not exist *and*
    /// for one that exists under another profile, and this asserts the two are
    /// byte-identical on the wire. A 403 for the second would turn
    /// [`deterministic_id`] — `("primary_onboarding", profile_id,
    /// idempotency_key)`, all three guessable — into a membership test over
    /// other people's intents. See `super::super::http_error`'s
    /// ownership-oracle rule.
    ///
    /// Mutation this detects (applied, run, reverted): mapping
    /// `OnboardingError::IntentNotFound` to `StatusCode::FORBIDDEN` — both
    /// refusal arms fail here, and
    /// `http_error::tests::stream_g_error_mapping_never_emits_403` fails too.
    #[tokio::test]
    async fn an_unknown_or_foreign_intent_is_404_and_never_403() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let (mine, my_auth) = profile_with_credential(&state, "idem-a2-mine").await;
        let (theirs, _) = profile_with_credential(&state, "idem-a2-theirs").await;
        let my_intent = start(&state, &mine, "intent-mine").await;
        let their_intent = start(&state, &theirs, "intent-theirs").await;
        assert_ne!(my_intent.intent_id, their_intent.intent_id);

        let unknown = get(&app, &intent_uri(&"0".repeat(64)), Some(&my_auth)).await;
        assert_eq!(unknown.0, StatusCode::NOT_FOUND);
        assert_eq!(
            unknown.1,
            format!("{{\"error\":\"{ERR_INTENT_NOT_FOUND}\"}}")
        );

        let foreign = get(&app, &intent_uri(&their_intent.intent_id), Some(&my_auth)).await;
        assert_eq!(
            foreign.0,
            StatusCode::NOT_FOUND,
            "another profile's intent must answer exactly as a nonexistent one does, not 403"
        );
        assert_ne!(foreign.0, StatusCode::FORBIDDEN);
        assert_eq!(
            foreign, unknown,
            "\"not yours\" and \"not found\" differ on the wire — the route is an ownership oracle"
        );

        // Paired non-zero arm: the caller's own intent is served, so the two
        // 404s are about ownership and not about a route that finds nothing.
        let (status, body) = get(&app, &intent_uri(&my_intent.intent_id), Some(&my_auth)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// **Founder decision: `profile_id` is not on the wire**, and the status
    /// vocabulary is the onboarding state machine.
    ///
    /// The caller is already authenticated as the owning profile — that is what
    /// [`get_intent`]'s `AND profile_id = ?` scoping means — so echoing the id
    /// back adds nothing it does not already hold while putting one more stable
    /// identifier into every intermediary's logs.
    ///
    /// Mutations this detects (each applied alone, run, reverted):
    /// 1. serializing [`IntentView`] directly instead of
    ///    [`IntentStatusResponse`] — `profile_id` reappears and both absence
    ///    assertions fail.
    /// 2. reporting a fixed `"pending"` instead of the row's status — the
    ///    `authorized` arm fails.
    #[tokio::test]
    async fn the_intent_response_omits_profile_id_and_reports_the_onboarding_status() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let (profile, authorization) = profile_with_credential(&state, "idem-a2-shape").await;
        let intent = start(&state, &profile, "intent-shape").await;

        let (status, body) = get(&app, &intent_uri(&intent.intent_id), Some(&authorization)).await;
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
        assert_eq!(document["status"].as_str(), Some(STATE_PENDING));

        // The status is read from the row, not from a constant: move the
        // intent through the onboarding machine and the route follows.
        mark_authorized(state.store(), &profile, &intent.intent_id)
            .await
            .expect("pending -> authorized");
        let (status, body) = get(&app, &intent_uri(&intent.intent_id), Some(&authorization)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let document: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(document["status"].as_str(), Some(STATE_AUTHORIZED));
    }

    /// **The route serves onboarding intents and nothing else — including the
    /// caller's own rows from another flow.**
    ///
    /// `intents` is shared: `quotes::create_sponsored_enrollment_quote_at`'s
    /// STEP 7 `write_tx` closure writes `sponsored_enrollment` rows
    /// into it. Ownership scoping does not help here, because the row *is* the
    /// caller's; what was missing was `AND intent_type = ?` in [`get_intent`]'s
    /// `SELECT` (the only accessor in this module that lacked it — compare
    /// `transition_in_tx` and `fulfill`, which both carry it). Without it a
    /// caller who computed its own
    /// enrollment row id got a 200 carrying the enrollment vocabulary out of a
    /// route documented to speak the onboarding one.
    ///
    /// Same shape as `tests::fulfill_rejects_a_non_onboarding_intent_type`,
    /// lifted to the route: the row is seeded directly
    /// for the **caller's own** profile, so a 404 can only come from the
    /// `intent_type` predicate.
    ///
    /// Mutation this detects (applied, run, reverted): dropping
    /// `AND intent_type = ?` from `get_intent` — the enrollment row then
    /// answers 200 with `"status":"executed"`, a value
    /// [`IntentStatusResponse`] does not document.
    #[tokio::test]
    async fn the_intent_route_404s_the_callers_own_non_onboarding_intent() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let (profile, authorization) = profile_with_credential(&state, "idem-a2-wrong-type").await;

        // An enrollment row of this very caller's, seeded the way
        // `create_sponsored_enrollment_quote` writes one: same table, same
        // profile, a status from the *other* state machine.
        let foreign_flow_intent = "enrollment-row-of-my-own".to_string();
        state
            .store()
            .write_tx({
                let intent_id = foreign_flow_intent.clone();
                let profile_id = profile.as_str().to_string();
                move |tx| {
                    Box::pin(async move {
                        sqlx::query(
                            "INSERT INTO intents (id, profile_id, intent_type, status, created_at) \
                             VALUES (?, ?, 'sponsored_enrollment', 'executed', ?)",
                        )
                        .bind(&intent_id)
                        .bind(&profile_id)
                        .bind(0i64)
                        .execute(&mut **tx)
                        .await?;
                        Ok::<(), StreamGStoreError>(())
                    })
                }
            })
            .await
            .expect("seed a sponsored_enrollment row for the caller's own profile");

        let seen = get(
            &app,
            &intent_uri(&foreign_flow_intent),
            Some(&authorization),
        )
        .await;
        assert_eq!(
            seen.0,
            StatusCode::NOT_FOUND,
            "an enrollment row was served by the onboarding route: {}",
            seen.1
        );
        assert_eq!(seen.1, format!("{{\"error\":\"{ERR_INTENT_NOT_FOUND}\"}}"));
        assert!(
            !seen.1.contains("executed"),
            "the enrollment vocabulary reached the wire: {}",
            seen.1
        );

        // It is byte-identical to a nonexistent id, so the new predicate did
        // not introduce a "this exists but is the wrong kind" oracle.
        let unknown = get(&app, &intent_uri(&"7".repeat(64)), Some(&authorization)).await;
        assert_eq!(
            seen, unknown,
            "\"wrong intent_type\" and \"not found\" differ on the wire"
        );

        // Paired non-zero arm: a real onboarding intent of the same caller is
        // still served, so the 404 is about `intent_type` and not about a
        // filter that matches nothing.
        let mine = start(&state, &profile, "intent-right-type").await;
        let (status, body) = get(&app, &intent_uri(&mine.intent_id), Some(&authorization)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let document: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(document["status"].as_str(), Some(STATE_PENDING));
    }
}
