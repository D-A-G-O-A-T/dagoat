//! Stream G profile authentication: opaque issuer credentials, single-use
//! origin-bound challenges, sessions, and the alias blind index.
//!
//! ## Schema-frozen design notes (read before touching SQL here)
//!
//! - **Opaque credential, no KYC (5.2).** `credential_aliases` doubles as
//!   the profile's credential-hash store: at profile creation, the opaque
//!   issuer credential is registered as an alias row with
//!   `alias_type = "issuer_credential"`, `alias_hash` = the keyed HMAC of
//!   the credential bytes, and `alias_enc` left `NULL` -- the credential
//!   itself is never persisted, only its hash. This reuses the table's
//!   existing `UNIQUE(alias_type, alias_hash)` constraint rather than
//!   adding a dedicated credentials table.
//! - **Origin-bound challenges without an origin column (5.3, brief section 4).**
//!   `auth_challenges` has no column to hold the bound origin. The origin
//!   captured at issuance is sealed together with the plaintext nonce into
//!   a small JSON payload (`crypto_store::seal`), and the *ciphertext*
//!   (hex-encoded) is what actually lives in the `nonce` TEXT column -- the
//!   plaintext nonce handed to the caller at issuance is never itself
//!   persisted anywhere. The column name still reads `nonce`; its on-disk
//!   content is an opaque sealed envelope. This is the "sealed payloads"
//!   technique the augmented brief calls for to carry data the frozen
//!   schema has no column for.
//! - **Single-use, not read-then-write (5.3).** Redemption always attempts
//!   the same conditional `UPDATE ... WHERE status='pending' AND
//!   consumed_at IS NULL AND expires_at > ?` and checks rows-affected; nothing
//!   about whether the update runs is decided by an earlier read. The
//!   earlier read exists only to fetch+decrypt the sealed nonce/origin
//!   payload for *content* verification (wrong guesses must not burn a
//!   valid challenge) -- the actual single-use enforcement is 100% the
//!   guarded UPDATE.
//! - **HMAC key derivation bypasses `DataKey` (5.1/5.2/5.4).**
//!   `crypto_store::DataKey`'s byte field is private by design and
//!   `crypto_store.rs` is frozen for this task, so there is no accessor to
//!   pull the raw 32 bytes back out of a `DataKey` for use as an HMAC key.
//!   Every derived HMAC key in this module is therefore produced by
//!   `hex::decode`-ing `data_key_hex` directly, independently of the
//!   `DataKey` value built (separately) for `seal`/`open` calls. Both code
//!   paths parse the exact same hex string, so they always agree on what
//!   the "data key" is; they just reach it through two different,
//!   non-interfering routes.
//! - **Idempotency (brief section 4, rule #1).** `create_profile` derives its
//!   profile id as a **keyed** HMAC-SHA256 of the caller-supplied
//!   idempotency key, under a dedicated `PROFILE_ID_DOMAIN`-derived key --
//!   never a bare (unkeyed) hash of a value an unauthenticated client fully
//!   controls (see fix-lane report item I2: a bare hash is offline
//!   enumerable, and this crate has no per-caller scope to bind the
//!   idempotency namespace to before a profile/credential exists). It uses
//!   `INSERT OR IGNORE` + rows-affected to detect a replay, but unlike
//!   `onboarding.rs`/`root_authorization.rs` a replay here does NOT
//!   silently return the existing row: because the opaque credential is a
//!   single-disclosure secret (5.2: never store the plaintext, only its
//!   hash), there is nothing to safely re-disclose, and because no
//!   identity exists yet at profile-creation time (§5.2's no-KYC rule)
//!   there is no way to tell a legitimate retry apart from a different
//!   caller trying to adopt someone else's profile. `create_profile`
//!   therefore returns a typed `IdempotencyKeyConflict` on any collision --
//!   see `CreateProfileOutcome`'s doc.
//! - **Deferred: no index on `profile_sessions.session_token_hash`.** The
//!   frozen schema (`migrations/0001_stream_g.sql`) indexes
//!   `profile_sessions` only on `profile_id`; `validate_session`'s `WHERE
//!   session_token_hash = ?` lookup is therefore a full table scan. Adding
//!   the index needs a migration, which this task may not touch (schema is
//!   frozen) -- fix in the next migration. [`prune_expired`] bounds how
//!   large that scan can get in the meantime by sweeping expired/consumed
//!   challenges and expired/revoked sessions.
//! - **I3 fix: `profile_id` is proven, never merely asserted.** Before this
//!   fix, `issue_challenge` took `profile_id: Option<&str>` straight from
//!   the caller and wrote it into the challenge row; `create_session` then
//!   adopted that column as the session's subject with no credential ever
//!   presented. An attacker who merely *knew* a victim's `profile_id` (not
//!   a secret -- returned in plaintext by `create_profile`, and computable
//!   offline pre-I2) could run both halves of the ceremony himself and mint
//!   a 24-hour session for a profile he never authenticated into. See
//!   [`AuthenticatedProfileId`] below for the fix.
//!
//! ## I3 fix: `AuthenticatedProfileId` -- a profile id that has been proven
//!
//! [`AuthenticatedProfileId`] wraps a `profile_id` that some function in
//! this module has already verified the caller possesses a credential or
//! session for. Its inner `String` is **private** and the type has **no
//! public constructor from a bare string** anywhere in this crate. The only
//! two ways to obtain one, anywhere in this task, are:
//! - [`authenticate_credential`] -- presenting the opaque issuer credential
//!   (5.2's single-disclosure secret), or
//! - [`validate_session`] -- presenting a previously-minted session token
//!   that is unexpired, unrevoked, and origin-matched.
//!
//! Both require proving possession of something a bare `profile_id` string
//! does not give an attacker: the credential itself, or a session that
//! could only have been minted by redeeming a challenge already bound to
//! that profile through [`issue_challenge_for_profile`] (itself only
//! callable with an `AuthenticatedProfileId`).
//!
//! **This is a compile-time property, not a convention.** Every
//! profile-scoped entry point across all three files in this task --
//! [`issue_challenge_for_profile`], [`revoke_session`], [`attach_alias`],
//! `onboarding::start_intent`, `onboarding::mark_authorized`,
//! `onboarding::mark_submitted`, `onboarding::get_intent`,
//! `onboarding::claim_free_primary_wallet`, `onboarding::fulfill`, and
//! `root_authorization::create_root_authorization` -- takes
//! `&AuthenticatedProfileId`, not `&str` or `String`. `StartOnboardingRequest`
//! and `CreateRootAuthorizationRequest` (the two `#[serde(deny_unknown_fields)]`
//! deserializable request bodies in this task) have **no `profile_id` field
//! at all**. A raw `String` decoded from a JSON body therefore cannot
//! type-check into any of these calls: there is no `From<String>`, no
//! `TryFrom<&str>`, nothing -- the only non-test path to a value of this
//! type runs through a function that verifies possession first. The one
//! escape hatch, [`AuthenticatedProfileId::for_test`], is
//! `#[cfg(test)]`-gated and does not exist in a non-test build; it exists
//! purely so tests can construct fixtures without running a full
//! challenge/session ceremony for every setup step.
//!
//! `onboarding.rs` and `root_authorization.rs` import this type via
//! `super::profile_auth::AuthenticatedProfileId` -- no `pub use` re-export
//! in `mod.rs` is needed since both are already sibling `pub mod`s of
//! `profile_auth` under `stream_g`.
//!
//! **`fulfill`'s model is not the same as the others above, even though it
//! now takes the same type (round-2 fix).** An earlier version of this fix
//! dropped `profile_id` from `fulfill` entirely, reasoning that removing
//! the only caller-identity input made a cross-profile *mismatch*
//! unrepresentable -- which is true, but conflates two different
//! properties. Consistency (no representable mismatch) is not
//! authentication (proof the caller is who they claim): dropping the
//! parameter also deleted the only caller-identity input, so `fulfill`
//! authorized purely on knowledge of `intent_id` -- a value that travels in
//! a URL path (`GET /v1/profile/primary-onboarding/:intentId` — `:name`, not
//! the brace form, for the axum 0.7.9 / matchit 0.7.3 reason recorded at
//! `super::mod`'s `router` doc), making it
//! a bearer capability that could spend a victim's one-time entitlement.
//!
//! The corrected model: `fulfill` takes `&AuthenticatedProfileId` like the
//! others, but uses it only as a *predicate*, never as an *authority*. The
//! intent row, read inside the same transaction, remains the sole source of
//! truth for who gets credited -- `fulfill` still resolves `profile_id`
//! from `SELECT profile_id FROM intents WHERE id = ?` and credits *that*
//! value, exactly as before the round-2 fix. The parameter is compared
//! against the resolved owner and a disagreement is rejected
//! (`OnboardingError::IntentNotFound`) *before* any entitlement claim is
//! attempted -- it is never substituted in as the value that gets credited.
//! This is what keeps the fix from reintroducing C2: C2's bug was treating
//! an unvalidated caller-supplied value as the authority for who gets
//! credited; this treats it only as a check on an authority the row
//! already establishes independently. See `onboarding::fulfill`'s own doc
//! for the full writeup and
//! `onboarding::tests::fulfill_rejects_a_caller_who_is_not_the_intents_owner`
//! for the regression proof.
//!
//! `create_session` is also not in the list above: it resolves `profile_id`
//! from the *challenge* row it consumes (which can only have been bound to
//! a profile via `issue_challenge_for_profile`), not from a caller-supplied
//! parameter, so there is nothing for a caller to supply that needs
//! type-level gating.
//!
//! This module is intentionally self-contained (its own tiny
//! `now_unix_seconds` / `random_hex` / `deterministic_id`, distinct from
//! the copies in `onboarding.rs` and `root_authorization.rs`) -- see those
//! modules' docs for why.
//!
//! ## Wave B1: the HTTP surface, and the credential transport it chose
//!
//! Everything above this line is a library. Wave B1 adds the first
//! *authenticated* HTTP routes this crate has ever had -- see
//! [`post_challenge`], [`post_session`], [`delete_session`], mounted by
//! [`super::router`] at
//!
//! ```text
//! POST   /v1/profile/challenges
//! POST   /v1/profile/sessions
//! DELETE /v1/profile/sessions/:id
//! ```
//!
//! Before this wave [`validate_session`] had **zero production call sites**
//! and no mounted route could mint a credential, so nothing downstream of
//! authentication was reachable at all.
//!
//! The handler wave after B1 added the one route that is deliberately *not*
//! authenticated -- [`post_profile`], `POST /v1/profile` -- because it is what
//! issues the opaque credential the three routes above authenticate with. Its
//! only bound is the global rate-limit bucket; see its doc for why the
//! per-profile bucket is not merely omitted there but unavailable.
//!
//! That same wave stopped this being a `/v1/profile/`-only story. The
//! [`AuthenticatedProfile`] extractor below now also guards
//! `GET /v1/profile/primary-onboarding/:intentId`
//! ([`super::onboarding::get_primary_onboarding_intent`]),
//! `POST /v1/stream-g/quotes` ([`super::quotes::post_quote`]) and
//! `GET /v1/stream-g/status/:intentId`
//! ([`super::submit::get_enrollment_status`]) -- six authenticated routes in
//! total, all reaching authentication through this one extractor, which is why
//! adding a route cannot accidentally add an unauthenticated one.
//!
//! ### Transport: `Authorization`, two schemes, and why that matches
//!
//! [`super::stream_g_cors_layer`] already allows the `authorization` request
//! header, and its doc records the reason: "`profile_auth::validate_session`
//! takes a bearer `session_token` and `Authorization: Bearer <token>` is that
//! credential's standard carriage". That is checked, not assumed:
//! `validate_session`'s `session_token: &str` is the opaque
//! `CreatedSession::session_token` (`random_hex(32)`), a value that
//! authenticates by *possession alone* -- the definition of a bearer token.
//! So the CORS allowlist and the transport agree, and no CORS change is
//! needed for this wave.
//!
//! One thing the CORS doc did not anticipate: `validate_session` is not the
//! only mint point. [`authenticate_credential`] is the other, and it consumes
//! a *different* bearer secret (the opaque issuer credential from
//! [`create_profile`]). Both are needed, because a caller with no session yet
//! cannot obtain one: `POST /v1/profile/sessions` redeems a challenge, and
//! only [`issue_challenge_for_profile`] -- which requires an
//! [`AuthenticatedProfileId`] -- can bind a challenge to a profile. The
//! credential is therefore the bootstrap, and the session is the renewal.
//!
//! Two secrets, one header, so the **scheme token disambiguates**:
//!
//! ```text
//! Authorization: Bearer     <session_token>        -> validate_session
//! Authorization: Credential <issuer_credential>    -> authenticate_credential
//! ```
//!
//! Deliberately **not** "try one, then the other": guessing which secret a
//! caller sent would cost two table scans per request and would make the
//! refusal code depend on which guess ran last. The scheme is compared
//! case-insensitively (RFC 7235 says scheme names are). Anything else --
//! absent header, no scheme/value split, empty value, an unrecognized scheme
//! -- is one refusal, [`ERR_MISSING_CREDENTIAL`], 401. That code says only
//! "this request carried no `Authorization` header I can use", which the
//! client already knows; it names no resource, so it is not an oracle.
//!
//! ### `presented_origin`, and what an absent `Origin` means
//!
//! [`validate_session`] enforces `presented_origin` against the origin sealed
//! at mint time, and [`create_session`] seals whatever it is handed. Both
//! sides of that comparison are produced here by one helper,
//! [`presented_origin`], reading the `Origin` **request header** -- so a
//! session minted through these routes is bound to the origin the minting
//! request declared, and validates only from that same origin.
//!
//! A non-browser client sends no `Origin` at all. The decision, stated so it
//! is not an accident: **an absent `Origin` is represented by the distinct
//! value [`NO_ORIGIN`] (the empty string), not by skipping the check.** The
//! consequences, both directions:
//!
//! * A session minted for `https://a.example` **cannot** be used by a request
//!   that omits `Origin` -- `"" != "https://a.example"`, so it is refused
//!   exactly as a foreign origin would be. Omitting the header is not a
//!   bypass.
//! * A ceremony run entirely without `Origin` (challenge, session, use) is
//!   self-consistent and works, so a CLI or daemon client is not locked out.
//!   Its sessions are bound to "no origin" and are refused the moment a
//!   request declares one.
//!
//! The residual, stated rather than hidden: origin binding is a defence
//! against a *browser* on the wrong origin, because a browser cannot forge or
//! suppress `Origin` on these requests. It is not a defence against someone
//! who has stolen a token and can set headers freely -- such an attacker can
//! always replay the origin the token was minted for. Nothing here claims
//! otherwise. An `Origin` header whose bytes are not valid ASCII cannot be
//! compared at all and is refused as [`ProfileAuthError::OriginMismatch`],
//! the same code and status the store-level comparison produces.
//!
//! ### The extractor is what makes an unauthenticated route unrepresentable
//!
//! [`AuthenticatedProfile`] is the *only* way a handler in this module
//! obtains an [`AuthenticatedProfileId`], and it is an axum extractor, so the
//! check runs before the handler body exists. It adds **no** new constructor
//! for `AuthenticatedProfileId`: it holds a value one of the two existing
//! mint points returned. The compile-time property recorded in the "I3 fix"
//! section above is therefore preserved exactly -- `grep -n 'AuthenticatedProfileId('`
//! still finds only `authenticate_credential`, `validate_session` and the
//! `#[cfg(test)]` `for_test`.

use std::sync::PoisonError;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::async_trait;
use axum::extract::{FromRequestParts, Path, State};
use axum::http::header::{AUTHORIZATION, ORIGIN};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqliteTransaction;
use sqlx::Row;
use thiserror::Error;
use zeroize::Zeroizing;

use super::crypto_store::{self, CryptoStoreError, DataKey, SecretHex};
use super::http_error::{ApiError, ApiJson};
use super::runtime::StreamGState;
use super::store::{StreamGStore, StreamGStoreError};

type HmacSha256 = Hmac<Sha256>;

/// Challenge TTL (brief 5.3): 5 minutes.
pub const CHALLENGE_TTL_SECONDS: i64 = 5 * 60;
/// Session TTL (brief 5.4): 24 hours.
pub const SESSION_TTL_SECONDS: i64 = 24 * 60 * 60;

/// Domain-separation strings for the derived HMAC keys this module mints
/// from the raw data key (brief 5.1: "derive the index key ... by domain
/// separation"). Each MUST stay distinct from the others (and from any
/// other module's own domain strings) -- that is what makes "sealed/keyed
/// under key A" fail to open/verify under a value derived for purpose B,
/// even though both ultimately trace back to the same underlying data key.
const ALIAS_INDEX_DOMAIN: &[u8] = b"goat.stream-g.alias-index.v1";
const CREDENTIAL_INDEX_DOMAIN: &[u8] = b"goat.stream-g.credential-index.v1";
const SESSION_INDEX_DOMAIN: &[u8] = b"goat.stream-g.session-index.v1";
/// I2 fix: domain separator for the keyed HMAC that derives `profile_id`
/// from a caller-supplied idempotency key. See module doc.
const PROFILE_ID_DOMAIN: &[u8] = b"goat.stream-g.profile-id.v1";

/// M1 fix: the challenge type `create_session` requires. Other challenge
/// types (e.g. a future `wallet_link`) must never redeem into a session --
/// see `fetch_and_verify_challenge`'s type check.
pub const CHALLENGE_TYPE_SESSION: &str = "session";

pub const ERR_CHALLENGE_NOT_FOUND: &str = "CHALLENGE_NOT_FOUND";
pub const ERR_CHALLENGE_EXPIRED: &str = "CHALLENGE_EXPIRED";
pub const ERR_NONCE_MISMATCH: &str = "NONCE_MISMATCH";
pub const ERR_ORIGIN_MISMATCH: &str = "ORIGIN_MISMATCH";
pub const ERR_CHALLENGE_ALREADY_CONSUMED: &str = "CHALLENGE_ALREADY_CONSUMED";
pub const ERR_CHALLENGE_NOT_BOUND_TO_PROFILE: &str = "CHALLENGE_NOT_BOUND_TO_PROFILE";
pub const ERR_CHALLENGE_TYPE_MISMATCH: &str = "CHALLENGE_TYPE_MISMATCH";
pub const ERR_CREDENTIAL_NOT_FOUND: &str = "CREDENTIAL_NOT_FOUND";
pub const ERR_SESSION_NOT_FOUND: &str = "SESSION_NOT_FOUND";
pub const ERR_SESSION_EXPIRED: &str = "SESSION_EXPIRED";
pub const ERR_SESSION_REVOKED: &str = "SESSION_REVOKED";
pub const ERR_IDEMPOTENCY_KEY_CONFLICT: &str = "IDEMPOTENCY_KEY_CONFLICT";
pub const ERR_ALIAS_ALREADY_ATTACHED: &str = "ALIAS_ALREADY_ATTACHED";

#[derive(Debug, Error)]
pub enum ProfileAuthError {
    #[error("store error: {0}")]
    Store(#[from] StreamGStoreError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoStoreError),
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("invalid data key: {0}")]
    InvalidDataKey(String),
    #[error("challenge not found")]
    ChallengeNotFound,
    #[error("challenge expired")]
    ChallengeExpired,
    #[error("challenge nonce mismatch")]
    NonceMismatch,
    #[error("challenge origin mismatch")]
    OriginMismatch,
    #[error("challenge already consumed")]
    ChallengeAlreadyConsumed,
    #[error("challenge is not bound to a profile")]
    ChallengeNotBoundToProfile,
    #[error("challenge type mismatch")]
    ChallengeTypeMismatch,
    #[error("credential not recognized")]
    CredentialNotFound,
    #[error("session not found")]
    SessionNotFound,
    #[error("session expired")]
    SessionExpired,
    #[error("session revoked")]
    SessionRevoked,
    #[error("malformed sealed payload: {0}")]
    MalformedPayload(String),
    #[error("idempotency key already used by a prior request that this call cannot prove it owns")]
    IdempotencyKeyConflict,
    #[error("alias already attached to a different profile")]
    AliasAlreadyAttached,
}

impl ProfileAuthError {
    /// Stable string code for routes to surface (Task 8).
    pub fn code(&self) -> &'static str {
        match self {
            ProfileAuthError::ChallengeNotFound => ERR_CHALLENGE_NOT_FOUND,
            ProfileAuthError::ChallengeExpired => ERR_CHALLENGE_EXPIRED,
            ProfileAuthError::NonceMismatch => ERR_NONCE_MISMATCH,
            ProfileAuthError::OriginMismatch => ERR_ORIGIN_MISMATCH,
            ProfileAuthError::ChallengeAlreadyConsumed => ERR_CHALLENGE_ALREADY_CONSUMED,
            ProfileAuthError::ChallengeNotBoundToProfile => ERR_CHALLENGE_NOT_BOUND_TO_PROFILE,
            ProfileAuthError::ChallengeTypeMismatch => ERR_CHALLENGE_TYPE_MISMATCH,
            ProfileAuthError::CredentialNotFound => ERR_CREDENTIAL_NOT_FOUND,
            ProfileAuthError::SessionNotFound => ERR_SESSION_NOT_FOUND,
            ProfileAuthError::SessionExpired => ERR_SESSION_EXPIRED,
            ProfileAuthError::SessionRevoked => ERR_SESSION_REVOKED,
            ProfileAuthError::IdempotencyKeyConflict => ERR_IDEMPOTENCY_KEY_CONFLICT,
            ProfileAuthError::AliasAlreadyAttached => ERR_ALIAS_ALREADY_ATTACHED,
            _ => "INTERNAL",
        }
    }

    /// HTTP status for the shared Stream G error envelope
    /// (`super::http_error`). Wildcard-free on purpose — see
    /// [`super::base_fee::BaseFeeError::status`].
    ///
    /// # Every credential-shaped failure is 401, and none of them is 403
    ///
    /// Challenges, credentials and sessions are all *presented* capabilities.
    /// "You presented one and it did not authenticate" is a fact about the
    /// request, so it is [`StatusCode::UNAUTHORIZED`]. A 403 would mean "this
    /// exists, and it is not yours" — the exact ownership oracle
    /// `super::http_error`'s rule forbids — so this enum never produces one.
    ///
    /// # The residual leak, stated rather than hidden
    ///
    /// The 401 arms are **not** collapsed to one another: the *code* in the
    /// body still distinguishes `CHALLENGE_NOT_FOUND` from
    /// `CHALLENGE_TYPE_MISMATCH` from `NONCE_MISMATCH`, so a caller holding a
    /// challenge id but not its nonce learns that the id exists. That is
    /// accepted here for one reason and it is a quantitative one:
    /// `issue_challenge_impl` mints `challenge_id` as `random_hex(16)` (128
    /// bits) and the session token likewise, so the identifier space is not
    /// enumerable and the oracle has no population to range over. It is
    /// *not* accepted because the distinction is harmless in principle — it
    /// is a leak whose exploitation requires already holding the secret. If a
    /// future identifier is ever derived from anything guessable (the way
    /// `onboarding`/`root_authorization` intent ids are derived from
    /// `(profile_id, idempotency_key)`), these codes must collapse the way
    /// `IntentNotFound` already does.
    pub fn status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            ProfileAuthError::Store(_)
            | ProfileAuthError::Crypto(_)
            | ProfileAuthError::Sqlx(_)
            // This process's own at-rest key failed to derive an index key.
            | ProfileAuthError::InvalidDataKey(_)
            // The sealed payload this process wrote failed to open or parse.
            | ProfileAuthError::MalformedPayload(_) => StatusCode::INTERNAL_SERVER_ERROR,

            ProfileAuthError::ChallengeNotFound
            | ProfileAuthError::ChallengeExpired
            | ProfileAuthError::NonceMismatch
            | ProfileAuthError::OriginMismatch
            | ProfileAuthError::ChallengeAlreadyConsumed
            | ProfileAuthError::ChallengeNotBoundToProfile
            | ProfileAuthError::ChallengeTypeMismatch
            | ProfileAuthError::CredentialNotFound
            | ProfileAuthError::SessionNotFound
            | ProfileAuthError::SessionExpired
            | ProfileAuthError::SessionRevoked => StatusCode::UNAUTHORIZED,

            ProfileAuthError::IdempotencyKeyConflict
            | ProfileAuthError::AliasAlreadyAttached => StatusCode::CONFLICT,
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

/// Deterministic row id for idempotent creates -- see module doc.
fn deterministic_id(parts: &[&str]) -> String {
    hex::encode(Sha256::digest(parts.join("|").as_bytes()))
}

/// Manual constant-time equality for fixed-shape secret comparisons
/// (challenge nonces, session token hashes). No `subtle` dependency is
/// available in this crate (see brief 5.4), so this compares byte-by-byte
/// with a running OR-accumulator instead of `==`, which keeps the number of
/// operations independent of *where* a mismatch occurs, rather than
/// short-circuiting on the first differing byte. This is not a
/// hardware-level guarantee against every timing side channel (allocation
/// and memory-access patterns are out of scope for a hand-rolled loop like
/// this), but it removes the most obvious byte-position leak from a plain
/// `==`.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Derive a domain-separated HMAC-SHA256 key from the raw data key --
/// `HMAC-SHA256(key = data_key_bytes, message = domain)`. See module doc
/// for why this decodes `data_key_hex` directly instead of going through
/// `crypto_store::DataKey`.
///
/// **This is one of exactly two `SecretHex::as_str` call sites in the crate**
/// (the other is `DataKey::from_secret`). It is the reason the escape hatch
/// exists: `DataKey` has no byte accessor by design, and `HmacSha256` needs
/// the raw key material, so this function cannot be expressed in terms of
/// `DataKey`. See `SecretHex::as_str`'s own doc.
///
/// The length/charset re-check below is now unreachable — `SecretHex` cannot
/// hold anything `hex::decode` rejects or anything that is not 32 bytes — and
/// is kept as a belt-and-braces guard rather than deleted, because it is the
/// only thing standing between a future second `SecretHex` constructor and a
/// silently short HMAC key.
fn derive_domain_key(
    data_key_hex: &SecretHex,
    domain: &[u8],
) -> Result<Zeroizing<[u8; 32]>, ProfileAuthError> {
    let raw = Zeroizing::new(
        hex::decode(data_key_hex.as_str())
            .map_err(|e| ProfileAuthError::InvalidDataKey(e.to_string()))?,
    );
    if raw.len() != 32 {
        return Err(ProfileAuthError::InvalidDataKey(format!(
            "expected 32 bytes, got {}",
            raw.len()
        )));
    }
    let mut mac = HmacSha256::new_from_slice(&raw)
        .map_err(|e| ProfileAuthError::InvalidDataKey(e.to_string()))?;
    mac.update(domain);
    let result = mac.finalize().into_bytes();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&result);
    Ok(key)
}

fn hmac_hex(key: &[u8], message: &[u8]) -> Result<String, ProfileAuthError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| ProfileAuthError::InvalidDataKey(e.to_string()))?;
    mac.update(message);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

// --- Authenticated profile id (I3) --------------------------------------

/// A `profile_id` that has been proven, not merely asserted -- see the
/// module doc's "I3 fix" section for the full rationale and the exhaustive
/// list of functions that can mint one.
///
/// The inner `String` is intentionally private. There is no `From<String>`,
/// `TryFrom<&str>`, `FromStr`, or any other public constructor from a bare
/// string anywhere in this crate. The only two mint points are
/// [`authenticate_credential`] and [`validate_session`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedProfileId(String);

impl AuthenticatedProfileId {
    /// Read accessor. Binding this into a query is fine -- the point of
    /// this type is not to hide the string, it is to make sure nothing can
    /// *construct* one without proving possession first.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The single sanctioned escape hatch (see module doc): lets tests
    /// build a fixture `AuthenticatedProfileId` directly, without running a
    /// full challenge/session ceremony for every setup step. `#[cfg(test)]`
    /// means this constructor does not exist in a non-test build -- it
    /// cannot be reached from production request-handling code no matter
    /// how a route is wired.
    #[cfg(test)]
    pub fn for_test(profile_id: impl Into<String>) -> Self {
        AuthenticatedProfileId(profile_id.into())
    }
}

// --- Alias blind index (5.1) -------------------------------------------

/// Normalize an alias before hashing/sealing: trim, lowercase. Aliases are
/// email-shaped; normalization is part of the index's contract -- two
/// strings that normalize the same MUST hash the same.
pub fn normalize_alias(raw: &str) -> String {
    raw.trim().to_lowercase()
}

/// The alias blind index primitive: keyed HMAC-SHA256 of the *normalized*
/// alias, hex-encoded. Never a bare (unkeyed) SHA-256 -- see brief 5.1 and
/// the migration's own schema comment on `credential_aliases.alias_hash`.
pub fn alias_hash_hex(
    data_key_hex: &SecretHex,
    normalized_alias: &str,
) -> Result<String, ProfileAuthError> {
    let key = derive_domain_key(data_key_hex, ALIAS_INDEX_DOMAIN)?;
    hmac_hex(key.as_slice(), normalized_alias.as_bytes())
}

/// Attach an optional alias (e.g. an email) to an existing profile. Not a
/// credential -- see `create_profile` for the opaque issuer credential this
/// crate actually authenticates with.
///
/// M4 fix: idempotent and profile-scoped. The row id folds in `profile_id`
/// (`["alias", profile_id, alias_type, alias_hash]`), so a retry by the
/// SAME profile of the SAME normalized alias derives the SAME row id and
/// collides on the table's `PRIMARY KEY`. A DIFFERENT profile attaching the
/// SAME normalized alias derives a DIFFERENT row id but still collides on
/// `credential_aliases`'s `UNIQUE(alias_type, alias_hash)` constraint.
/// Both collisions are absorbed by `INSERT OR IGNORE` (so neither ever
/// surfaces as a raw SQLITE_CONSTRAINT / 500), and then disambiguated by
/// re-reading whichever row actually owns `(alias_type, alias_hash)`: if
/// its id is ours, this was a true replay (`Ok`); otherwise a different
/// profile already attached this alias (`Err(AliasAlreadyAttached)`).
///
/// **I3 fix.** `profile_id` is now `&AuthenticatedProfileId` -- obtainable
/// only from [`authenticate_credential`] or [`validate_session`] -- so a
/// caller can only attach an alias to a profile it has proven possession
/// of; see the module doc's "I3 fix" section.
pub async fn attach_alias(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    profile_id: &AuthenticatedProfileId,
    alias_type: &str,
    raw_alias: &str,
) -> Result<(), ProfileAuthError> {
    let data_key = DataKey::from_secret(data_key_hex);
    let normalized = normalize_alias(raw_alias);
    let alias_hash = alias_hash_hex(data_key_hex, &normalized)?;
    let alias_id = deterministic_id(&["alias", profile_id.as_str(), alias_type, &alias_hash]);
    let aad = store.envelope_aad("credential_aliases", &alias_id, "alias_enc");
    let alias_enc = crypto_store::seal(&data_key, &aad, normalized.as_bytes())?;

    let profile_id = profile_id.as_str().to_string();
    let alias_type = alias_type.to_string();
    let now = now_unix_seconds();
    let alias_id_for_tx = alias_id.clone();
    let alias_hash_for_tx = alias_hash.clone();
    let alias_type_for_tx = alias_type.clone();

    store
        .write_tx(move |tx| {
            Box::pin(async move {
                let result = sqlx::query(
                    "INSERT OR IGNORE INTO credential_aliases \
                     (id, profile_id, alias_type, alias_hash, alias_enc, created_at) \
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(&alias_id_for_tx)
                .bind(&profile_id)
                .bind(&alias_type_for_tx)
                .bind(&alias_hash_for_tx)
                .bind(&alias_enc)
                .bind(now)
                .execute(&mut **tx)
                .await?;

                if result.rows_affected() == 1 {
                    return Ok::<(), ProfileAuthError>(());
                }

                // 0 rows: either a true replay (our own row is already
                // there) or a different profile already owns this
                // (alias_type, alias_hash) pair -- `UNIQUE(alias_type,
                // alias_hash)` guarantees at most one row for that pair, so
                // this lookup is unambiguous.
                let existing_id: String = sqlx::query_scalar(
                    "SELECT id FROM credential_aliases WHERE alias_type = ? AND alias_hash = ?",
                )
                .bind(&alias_type_for_tx)
                .bind(&alias_hash_for_tx)
                .fetch_one(&mut **tx)
                .await?;

                if existing_id == alias_id_for_tx {
                    Ok::<(), ProfileAuthError>(())
                } else {
                    Err(ProfileAuthError::AliasAlreadyAttached)
                }
            })
        })
        .await
}

// --- Opaque issuer credential / profile creation (5.2) ------------------

/// Result of a *successful* [`create_profile`] call -- i.e. the call that
/// actually created the row. A replay of the same idempotency key (whether
/// a legitimate client retry or a different caller who observed/guessed
/// the key) never produces this: see I2 in the fix report and
/// `create_profile`'s doc for why the collision path is a typed error
/// rather than a second `Ok` with the credential omitted.
#[derive(Debug, Clone, Serialize)]
pub struct CreateProfileOutcome {
    pub profile_id: String,
    pub credential: String,
}

/// `POST /v1/profile` — **now mounted**, by [`post_profile`]. Wave B1 mounted
/// the three session-auth routes and left this one unreachable; the handler
/// wave that followed closed that gap, so a caller can obtain a credential over
/// HTTP rather than only by calling this function directly. Read
/// [`post_profile`] for the two things the route adds that this function does
/// not have: the registration rate limit (this is the only `/v1/profile/`
/// route that takes no credential, and it spends a budget of its own rather
/// than the global one — see [`RegistrationRateLimit`]) and the guarantee that
/// a replayer's 409 cannot carry a credential. It is not the only
/// credential-free route in the crate — `GET /v1/stream-g/ready` and
/// `GET /v1/stream-g/metrics` take none either; the router doc
/// (`mod.rs:18-64`) lists all nine, and [`AuthenticatedProfile`]'s
/// `FromRequestParts` impl (`profile_auth.rs:1663-1671`) is the one place a
/// credential is read.
///
/// No email/identity/KYC required: the profile is identified purely by the
/// opaque, high-entropy credential returned once here. Only a keyed hash of
/// the credential is ever persisted (`credential_aliases`,
/// `alias_type = "issuer_credential"`).
///
/// **I2 fix.** `profile_id` is a **keyed** HMAC-SHA256 of `idempotency_key`
/// (under a dedicated `PROFILE_ID_DOMAIN`-derived key), not a bare SHA-256
/// of a value an unauthenticated caller fully controls: a bare hash is
/// offline-enumerable for any candidate list of idempotency keys, with no
/// server interaction needed. On a collision (`rows_affected() == 0`) this
/// now returns `Err(ProfileAuthError::IdempotencyKeyConflict)` instead of
/// disclosing/adopting the existing `profile_id` -- there is no per-caller
/// identity yet at profile-creation time (§5.2's no-KYC rule) to tell a
/// legitimate retry apart from a second caller trying to walk into a
/// profile it holds no credential for, so the safe answer on any collision
/// is a typed conflict, never a silent `Ok`.
pub async fn create_profile(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    idempotency_key: &str,
) -> Result<CreateProfileOutcome, ProfileAuthError> {
    let credential_domain_key = derive_domain_key(data_key_hex, CREDENTIAL_INDEX_DOMAIN)?;
    let profile_id_domain_key = derive_domain_key(data_key_hex, PROFILE_ID_DOMAIN)?;

    let profile_id = hmac_hex(profile_id_domain_key.as_slice(), idempotency_key.as_bytes())?;
    let credential = random_hex(32); // >= 32 bytes, per 5.2
    let credential_hash = hmac_hex(credential_domain_key.as_slice(), credential.as_bytes())?;
    let alias_id = deterministic_id(&["profile-credential", &profile_id]);
    let now = now_unix_seconds();

    let profile_id_for_tx = profile_id.clone();
    let created = store
        .write_tx(move |tx| {
            Box::pin(async move {
                let result = sqlx::query(
                    "INSERT OR IGNORE INTO profiles (id, created_at, status) VALUES (?, ?, 'active')",
                )
                .bind(&profile_id_for_tx)
                .bind(now)
                .execute(&mut **tx)
                .await?;

                if result.rows_affected() == 1 {
                    sqlx::query(
                        "INSERT INTO credential_aliases \
                         (id, profile_id, alias_type, alias_hash, created_at) \
                         VALUES (?, ?, 'issuer_credential', ?, ?)",
                    )
                    .bind(&alias_id)
                    .bind(&profile_id_for_tx)
                    .bind(&credential_hash)
                    .bind(now)
                    .execute(&mut **tx)
                    .await?;
                }
                Ok::<u64, ProfileAuthError>(result.rows_affected())
            })
        })
        .await?;

    if created == 1 {
        Ok(CreateProfileOutcome {
            profile_id,
            credential,
        })
    } else {
        Err(ProfileAuthError::IdempotencyKeyConflict)
    }
}

/// Look up the profile that registered `credential` at creation. Used by
/// Task 8's "present your credential to get a profile-scoped challenge"
/// flow.
///
/// **I3 fix.** Returns [`AuthenticatedProfileId`], not a bare `String` --
/// this is one of exactly two functions in this crate that can mint one
/// (the other is [`validate_session`]), because presenting the correct
/// opaque credential is itself the proof of possession the newtype exists
/// to require. See the module doc's "I3 fix" section.
pub async fn authenticate_credential(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    credential: &str,
) -> Result<AuthenticatedProfileId, ProfileAuthError> {
    let credential_domain_key = derive_domain_key(data_key_hex, CREDENTIAL_INDEX_DOMAIN)?;
    let credential_hash = hmac_hex(credential_domain_key.as_slice(), credential.as_bytes())?;

    store
        .read(|handle| {
            Box::pin(async move {
                let row = handle
                    .fetch_optional(
                        sqlx::query(
                            "SELECT profile_id FROM credential_aliases \
                             WHERE alias_type = 'issuer_credential' AND alias_hash = ?",
                        )
                        .bind(&credential_hash),
                    )
                    .await?;
                match row {
                    None => Err(ProfileAuthError::CredentialNotFound),
                    Some(row) => {
                        let profile_id: String = row.try_get("profile_id")?;
                        Ok(AuthenticatedProfileId(profile_id))
                    }
                }
            })
        })
        .await
}

// --- Challenges (5.3) ----------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct ChallengePayload {
    nonce: String,
    origin: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssuedChallenge {
    pub challenge_id: String,
    pub nonce: String,
    pub expires_at: i64,
}

/// `POST /v1/profile/challenges` -- shared implementation.
///
/// **I3 fix.** This function is private and takes a plain
/// `Option<&str>` precisely because it is no longer the public surface: it
/// used to be, and that was the defect (a caller-supplied `profile_id`
/// with no proof of possession behind it -- see module doc). The two
/// public wrappers below, [`issue_challenge_anonymous`] and
/// [`issue_challenge_for_profile`], are the only callers, and only the
/// latter can ever pass `Some`, and only by unwrapping an already-proven
/// [`AuthenticatedProfileId`].
async fn issue_challenge_impl(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    profile_id: Option<&str>,
    challenge_type: &str,
    origin: &str,
) -> Result<IssuedChallenge, ProfileAuthError> {
    let data_key = DataKey::from_secret(data_key_hex);
    let challenge_id = random_hex(16);
    let nonce = random_hex(32);
    let now = now_unix_seconds();
    let expires_at = now + CHALLENGE_TTL_SECONDS;

    let payload = ChallengePayload {
        nonce: nonce.clone(),
        origin: origin.to_string(),
    };
    let payload_json = serde_json::to_vec(&payload)
        .map_err(|e| ProfileAuthError::MalformedPayload(e.to_string()))?;
    let aad = store.envelope_aad("auth_challenges", &challenge_id, "nonce");
    let sealed = crypto_store::seal(&data_key, &aad, &payload_json)?;
    let sealed_hex = hex::encode(sealed);

    let challenge_type = challenge_type.to_string();
    let profile_id_owned = profile_id.map(|s| s.to_string());
    let challenge_id_for_tx = challenge_id.clone();

    store
        .write_tx(move |tx| {
            Box::pin(async move {
                sqlx::query(
                    "INSERT INTO auth_challenges \
                     (id, profile_id, challenge_type, nonce, status, created_at, expires_at) \
                     VALUES (?, ?, ?, ?, 'pending', ?, ?)",
                )
                .bind(&challenge_id_for_tx)
                .bind(&profile_id_owned)
                .bind(&challenge_type)
                .bind(&sealed_hex)
                .bind(now)
                .bind(expires_at)
                .execute(&mut **tx)
                .await?;
                Ok::<(), ProfileAuthError>(())
            })
        })
        .await?;

    Ok(IssuedChallenge {
        challenge_id,
        nonce,
        expires_at,
    })
}

/// The **anonymous** challenge variant. The resulting challenge's
/// `auth_challenges.profile_id` column is always `NULL`.
///
/// ⚠️ **No production caller, and specifically not the mounted route.**
/// Wave B1's `POST /v1/profile/challenges` ([`post_challenge`]) requires an
/// authenticated caller and always calls
/// [`issue_challenge_for_profile`] — there is no way to reach this function
/// over HTTP. It is kept because the schema's nullable `profile_id` column is
/// for it, but nothing today issues an unauthenticated challenge.
///
/// **I3 fix.** This is the genuinely-anonymous path the schema's nullable
/// `auth_challenges.profile_id` exists for (brief §4): first-time
/// enrollment, before any credential exists to authenticate with. It is a
/// distinct, explicitly-named function -- not an `Option<&str>` parameter a
/// caller could pass `None` *or* an attacker-chosen `Some(..)` into -- so
/// there is no single call site where a foreign profile id could be
/// smuggled through the same path a legitimate anonymous caller uses. Redeem
/// with `create_session`; because `profile_id` is `NULL`, redemption will
/// fail with [`ProfileAuthError::ChallengeNotBoundToProfile`] unless the
/// caller's flow does not need a session bound to a profile at all.
pub async fn issue_challenge_anonymous(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    challenge_type: &str,
    origin: &str,
) -> Result<IssuedChallenge, ProfileAuthError> {
    issue_challenge_impl(store, data_key_hex, None, challenge_type, origin).await
}

/// `POST /v1/profile/challenges` -- **authenticated** variant, and the only
/// one the mounted route reaches ([`post_challenge`], Wave B1). The resulting
/// challenge's `auth_challenges.profile_id` column is set to
/// `profile.as_str()`.
///
/// **I3 fix.** `profile` must be an [`AuthenticatedProfileId`], obtainable
/// only from [`authenticate_credential`] or [`validate_session`] (see
/// module doc). This closes the exploit where an attacker who merely
/// *knew* (never authenticated as) a victim's `profile_id` could call the
/// old challenge-issuing function -- which took `profile_id: Option<&str>`
/// straight from the caller -- with the victim's id, then redeem it via
/// `create_session` using the nonce and origin he controls both ends of,
/// walking away with a 24-hour session for a profile he never presented a
/// credential for.
pub async fn issue_challenge_for_profile(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    profile: &AuthenticatedProfileId,
    challenge_type: &str,
    origin: &str,
) -> Result<IssuedChallenge, ProfileAuthError> {
    issue_challenge_impl(
        store,
        data_key_hex,
        Some(profile.as_str()),
        challenge_type,
        origin,
    )
    .await
}

struct VerifiedChallenge {
    profile_id: Option<String>,
}

/// Phase 1 of redemption: fetch the (immutable-once-inserted) sealed
/// payload and verify its *content* -- nonce, origin, expiry. Deliberately
/// **not** inside a `write_tx`: `store.write_tx`'s closure type cannot
/// itself capture a borrow of `store` (its `for<'t> FnOnce(...) ->
/// WriteTxFuture<'t, ..>` bound requires the returned future to be valid
/// for an arbitrary/unbounded `'t`, which a borrow of `store` tied to this
/// function's own lifetime cannot satisfy). It also does not need to be:
/// the `nonce` column's ciphertext never changes after `issue_challenge`
/// inserts it (only `status`/`consumed_at` do), so reading it via
/// `store.read` outside any transaction is a perfectly consistent read of
/// an otherwise-immutable value. This phase makes *no* state-changing
/// decision -- see `consume_challenge_in_tx` for that.
async fn fetch_and_verify_challenge(
    store: &StreamGStore,
    data_key: &DataKey,
    challenge_id: &str,
    presented_nonce: &str,
    presented_origin: &str,
    expected_challenge_type: &str,
    now: i64,
) -> Result<VerifiedChallenge, ProfileAuthError> {
    let challenge_id_owned = challenge_id.to_string();
    let row = store
        .read(|handle| {
            Box::pin(async move {
                let row = handle
                    .fetch_optional(
                        sqlx::query(
                            "SELECT profile_id, challenge_type, nonce, expires_at \
                             FROM auth_challenges WHERE id = ?",
                        )
                        .bind(&challenge_id_owned),
                    )
                    .await?;
                Ok::<_, StreamGStoreError>(row)
            })
        })
        .await?
        .ok_or(ProfileAuthError::ChallengeNotFound)?;

    let profile_id: Option<String> = row.try_get("profile_id")?;
    let challenge_type: String = row.try_get("challenge_type")?;
    let sealed_hex: String = row.try_get("nonce")?;
    let expires_at: i64 = row.try_get("expires_at")?;

    // M1 fix: purpose-fitness check. A challenge minted for one purpose
    // (e.g. a future lower-privilege `wallet_link` type) must never redeem
    // through a *different* type's flow (here, a full session). This is
    // independent of the sealed nonce/origin payload -- `challenge_type`
    // comes straight off the row -- so it runs before spending a decrypt on
    // a challenge that could never redeem here regardless of what it opens
    // to.
    if challenge_type != expected_challenge_type {
        return Err(ProfileAuthError::ChallengeTypeMismatch);
    }

    let sealed =
        hex::decode(&sealed_hex).map_err(|e| ProfileAuthError::MalformedPayload(e.to_string()))?;
    let aad = store.envelope_aad("auth_challenges", challenge_id, "nonce");
    let opened = crypto_store::open(data_key, &aad, &sealed)?;
    let payload: ChallengePayload = serde_json::from_slice(&opened)
        .map_err(|e| ProfileAuthError::MalformedPayload(e.to_string()))?;

    // Content checks: a wrong guess must not burn a valid challenge, so
    // these run before any write is even attempted.
    if !constant_time_eq(payload.nonce.as_bytes(), presented_nonce.as_bytes()) {
        return Err(ProfileAuthError::NonceMismatch);
    }
    if payload.origin != presented_origin {
        return Err(ProfileAuthError::OriginMismatch);
    }
    if now >= expires_at {
        return Err(ProfileAuthError::ChallengeExpired);
    }

    Ok(VerifiedChallenge { profile_id })
}

/// Phase 2 of redemption, transaction-scoped: the single-use enforcement.
/// Pure SQL, no `store`/`DataKey` capture -- called from inside
/// `create_session`'s `write_tx` closure alongside the session INSERT, so
/// both are atomic. The *only* thing that decides whether this redemption
/// "counts" is this guarded UPDATE's rows-affected, independent of
/// whatever `fetch_and_verify_challenge` observed earlier: a second,
/// concurrent redemption racing this one sees 0 rows affected here
/// regardless of what its own read saw.
async fn consume_challenge_in_tx(
    tx: &mut SqliteTransaction<'static>,
    challenge_id: &str,
    expected_challenge_type: &str,
    now: i64,
) -> Result<(), ProfileAuthError> {
    // M1 fix: `AND challenge_type = ?` on the guarded UPDATE itself, as a
    // second line of defense alongside `fetch_and_verify_challenge`'s
    // earlier check -- the single-use guard stays one conditional UPDATE
    // with rows-affected checked, never a read-then-write.
    let result = sqlx::query(
        "UPDATE auth_challenges SET status = 'consumed', consumed_at = ? \
         WHERE id = ? AND status = 'pending' AND consumed_at IS NULL AND expires_at > ? \
           AND challenge_type = ?",
    )
    .bind(now)
    .bind(challenge_id)
    .bind(now)
    .bind(expected_challenge_type)
    .execute(&mut **tx)
    .await?;

    if result.rows_affected() != 1 {
        return Err(ProfileAuthError::ChallengeAlreadyConsumed);
    }
    Ok(())
}

// --- Sessions (5.4) -------------------------------------------------------

/// Shape of the JSON payload sealed into `profile_sessions.context_enc` at
/// mint time (see `create_session`) and re-opened by `validate_session`
/// (M7) to enforce that a session only validates from the origin it was
/// minted for.
#[derive(Debug, Serialize, Deserialize)]
struct SessionContextPayload {
    origin: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreatedSession {
    pub session_id: String,
    pub session_token: String,
    pub profile_id: String,
    pub expires_at: i64,
}

/// `POST /v1/profile/sessions` (mounted by [`post_session`], Wave B1):
/// redeems `challenge_id` and, on success, mints a session. The state-changing part
/// -- consuming the challenge and inserting the session -- happens in one
/// `write_tx`: if the session insert fails for any reason, the challenge's
/// consumption rolls back with it (the challenge is not burned for
/// nothing). Content verification (nonce/origin/expiry) happens first, as
/// a separate read -- see `fetch_and_verify_challenge`.
pub async fn create_session(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    challenge_id: &str,
    presented_nonce: &str,
    origin: &str,
) -> Result<CreatedSession, ProfileAuthError> {
    let data_key = DataKey::from_secret(data_key_hex);
    let session_domain_key = derive_domain_key(data_key_hex, SESSION_INDEX_DOMAIN)?;
    let session_token = random_hex(32);
    let session_token_hash = hmac_hex(session_domain_key.as_slice(), session_token.as_bytes())?;
    let session_id = random_hex(16);
    let now = now_unix_seconds();
    let expires_at = now + SESSION_TTL_SECONDS;

    let context_payload = serde_json::to_vec(&serde_json::json!({ "origin": origin }))
        .map_err(|e| ProfileAuthError::MalformedPayload(e.to_string()))?;
    let aad = store.envelope_aad("profile_sessions", &session_id, "context_enc");
    let context_enc = crypto_store::seal(&data_key, &aad, &context_payload)?;

    let verified = fetch_and_verify_challenge(
        store,
        &data_key,
        challenge_id,
        presented_nonce,
        origin,
        CHALLENGE_TYPE_SESSION,
        now,
    )
    .await?;
    let profile_id = verified
        .profile_id
        .ok_or(ProfileAuthError::ChallengeNotBoundToProfile)?;

    let challenge_id = challenge_id.to_string();
    let session_id_for_tx = session_id.clone();
    let profile_id_for_tx = profile_id.clone();

    store
        .write_tx(move |tx| {
            Box::pin(async move {
                consume_challenge_in_tx(tx, &challenge_id, CHALLENGE_TYPE_SESSION, now).await?;

                sqlx::query(
                    "INSERT INTO profile_sessions \
                     (id, profile_id, session_token_hash, context_enc, created_at, expires_at) \
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(&session_id_for_tx)
                .bind(&profile_id_for_tx)
                .bind(&session_token_hash)
                .bind(&context_enc)
                .bind(now)
                .bind(expires_at)
                .execute(&mut **tx)
                .await?;

                Ok::<(), ProfileAuthError>(())
            })
        })
        .await?;

    Ok(CreatedSession {
        session_id,
        session_token,
        profile_id,
        expires_at,
    })
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: String,
    /// **I3 fix.** `AuthenticatedProfileId`, not a bare `String` -- a
    /// successfully validated session is one of exactly two proofs of
    /// possession this crate recognizes (the other is presenting the
    /// credential itself to [`authenticate_credential`]). See the module
    /// doc's "I3 fix" section.
    pub profile_id: AuthenticatedProfileId,
}

/// Session validation helper (brief 5.4): rejects expired, revoked,
/// unknown, or wrong-origin tokens.
///
/// **First production call site landed in Wave B1.** Until then this had
/// none — `grep -rn 'validate_session' src/` found only this module's own
/// tests. It is now called by [`AuthenticatedProfile`], the extractor behind
/// every authenticated `/v1/profile/` route, for the `Bearer` scheme.
///
/// **M2 fix (equality).** This used to *also* run
/// `constant_time_eq(stored_hash, token_hash)` after selecting the row
/// `WHERE session_token_hash = ?` bound to that very `token_hash` -- a
/// tautology comparing the value to itself; the branch was unreachable and
/// the real equality decision was always SQLite's own (non-constant-time)
/// string comparison inside the lookup. That dead compare is removed. The
/// choice made here (see fix report M2 for the alternative considered):
/// equality is delegated entirely to the indexed `WHERE session_token_hash
/// = ?` lookup over a **keyed HMAC** of the presented token
/// (`derive_domain_key` + `SESSION_INDEX_DOMAIN`) -- an attacker cannot
/// choose ciphertext to steer that lookup's timing the way they could
/// against a raw secret compare, because they do not control the HMAC
/// output, only its high-entropy random preimage. No dependency change was
/// needed either way; this option was simpler and avoids a full-table
/// re-scan given `profile_sessions.session_token_hash` has no index yet
/// (deferred -- see module doc).
///
/// **M7 fix (origin binding).** The origin captured at session-mint time
/// (`create_session`, sealed into `context_enc`) is opened here and
/// compared against `presented_origin`. Previously nothing ever read
/// `context_enc` back, so a session minted for one origin validated
/// unchanged from any other origin for its full 24h TTL -- the one-shot
/// challenge redemption's origin check (5.3) never carried forward to the
/// long-lived session it produced. This closes that gap at the
/// session-validation primitive itself, rather than punting entirely to
/// Task 8's CORS layer.
pub async fn validate_session(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    session_token: &str,
    presented_origin: &str,
) -> Result<SessionInfo, ProfileAuthError> {
    let data_key = DataKey::from_secret(data_key_hex);
    let domain_key = derive_domain_key(data_key_hex, SESSION_INDEX_DOMAIN)?;
    let token_hash = hmac_hex(domain_key.as_slice(), session_token.as_bytes())?;
    let now = now_unix_seconds();

    let (id, profile_id, context_enc, expires_at, revoked_at) = store
        .read(|handle| {
            Box::pin(async move {
                let row = handle
                    .fetch_optional(
                        sqlx::query(
                            "SELECT id, profile_id, context_enc, expires_at, revoked_at \
                             FROM profile_sessions WHERE session_token_hash = ?",
                        )
                        .bind(&token_hash),
                    )
                    .await?
                    .ok_or(ProfileAuthError::SessionNotFound)?;

                let id: String = row.try_get("id")?;
                let profile_id: String = row.try_get("profile_id")?;
                let context_enc: Option<Vec<u8>> = row.try_get("context_enc")?;
                let expires_at: i64 = row.try_get("expires_at")?;
                let revoked_at: Option<i64> = row.try_get("revoked_at")?;
                Ok::<_, ProfileAuthError>((id, profile_id, context_enc, expires_at, revoked_at))
            })
        })
        .await?;

    if revoked_at.is_some() {
        return Err(ProfileAuthError::SessionRevoked);
    }
    if now >= expires_at {
        return Err(ProfileAuthError::SessionExpired);
    }

    let context_enc = context_enc.ok_or_else(|| {
        ProfileAuthError::MalformedPayload(
            "profile_sessions row has no context_enc -- every row this module inserts seals one"
                .to_string(),
        )
    })?;
    let aad = store.envelope_aad("profile_sessions", &id, "context_enc");
    let opened = crypto_store::open(&data_key, &aad, &context_enc)?;
    let context: SessionContextPayload = serde_json::from_slice(&opened)
        .map_err(|e| ProfileAuthError::MalformedPayload(e.to_string()))?;
    if context.origin != presented_origin {
        return Err(ProfileAuthError::OriginMismatch);
    }

    Ok(SessionInfo {
        session_id: id,
        profile_id: AuthenticatedProfileId(profile_id),
    })
}

/// `DELETE /v1/profile/sessions/:id` (mounted by [`delete_session`], Wave
/// B1). Idempotent: revoking an already-revoked (or unknown, or
/// not-owned-by-`profile_id`) session id is not an error.
///
/// **I6 fix.** `profile_id` is now a required parameter and the guarded
/// UPDATE carries `AND profile_id = ?`: revocation authority derives from
/// the caller's own (already-authenticated, e.g. via `validate_session`)
/// profile, not from mere knowledge of `session_id` -- which is not a
/// secret and travels in a URL path (`DELETE
/// /v1/profile/sessions/:sessionId`), landing in reverse-proxy access
/// logs, browser history, and `Referer` headers.
///
/// **I3 fix.** `profile_id` is now `&AuthenticatedProfileId` rather than
/// `&str`, closing the gap I6 left open ("Task 8 must resolve `profile_id`
/// from an authenticated session/credential" was previously only a
/// convention): the type itself now makes it impossible to call this with
/// a profile id read straight out of a request body or path segment.
pub async fn revoke_session(
    store: &StreamGStore,
    profile_id: &AuthenticatedProfileId,
    session_id: &str,
) -> Result<(), ProfileAuthError> {
    let now = now_unix_seconds();
    let profile_id = profile_id.as_str().to_string();
    let session_id = session_id.to_string();
    store
        .write_tx(move |tx| {
            Box::pin(async move {
                sqlx::query(
                    "UPDATE profile_sessions SET revoked_at = ? \
                     WHERE id = ? AND profile_id = ? AND revoked_at IS NULL",
                )
                .bind(now)
                .bind(&session_id)
                .bind(&profile_id)
                .execute(&mut **tx)
                .await?;
                Ok::<(), ProfileAuthError>(())
            })
        })
        .await
}

/// Prune expired/consumed `auth_challenges` and expired/revoked
/// `profile_sessions` rows (M10).
///
/// Challenge issuance (`issue_challenge_anonymous`) is unauthenticated and
/// uncapped,
/// and nothing else in this module ever deletes a row from either table, so
/// without a periodic sweep both grow forever on this store's single
/// connection -- directly worsening `validate_session`'s already-unindexed
/// `WHERE session_token_hash = ?` scan (see module doc's "Deferred" note).
/// **Scheduled since Task 8 Wave D.** This used to say "wiring it to a
/// recurring background job is Task 8's job, not this task's". It now has a
/// production caller: [`super::maintenance::run_prune`], invoked from every
/// pass of the background maintenance loop that `main.rs` spawns when
/// `STREAM_G_ENABLED=1` (default cadence 900s, `STREAM_G_SWEEP_INTERVAL_SECONDS`).
/// It remains directly callable, and its own test still exercises it that way.
/// A failing prune is logged and counted as a failed step; it never aborts the
/// pass, because unbounded table growth is a performance problem and the sweep
/// in the same pass is a correctness one.
pub async fn prune_expired(store: &StreamGStore) -> Result<PruneCounts, ProfileAuthError> {
    let now = now_unix_seconds();
    store
        .write_tx(move |tx| {
            Box::pin(async move {
                let challenges = sqlx::query(
                    "DELETE FROM auth_challenges WHERE expires_at <= ? OR consumed_at IS NOT NULL",
                )
                .bind(now)
                .execute(&mut **tx)
                .await?;
                let sessions = sqlx::query(
                    "DELETE FROM profile_sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL",
                )
                .bind(now)
                .execute(&mut **tx)
                .await?;
                Ok::<PruneCounts, ProfileAuthError>(PruneCounts {
                    challenges_deleted: challenges.rows_affected(),
                    sessions_deleted: sessions.rows_affected(),
                })
            })
        })
        .await
}

/// Row counts deleted by [`prune_expired`], returned for observability
/// (e.g. logging/metrics in whatever later task wires this to a scheduler).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PruneCounts {
    pub challenges_deleted: u64,
    pub sessions_deleted: u64,
}

// --- HTTP surface (Wave B1) ---------------------------------------------
//
// See the module doc's "Wave B1" section for the transport decision, the
// absent-`Origin` rule, and why the extractor below adds no constructor for
// `AuthenticatedProfileId`.

/// `Authorization` scheme carrying a **session token** — the value
/// [`create_session`] returned as `CreatedSession::session_token`, resolved by
/// [`validate_session`].
pub const AUTH_SCHEME_SESSION: &str = "Bearer";

/// `Authorization` scheme carrying the **opaque issuer credential** —
/// [`create_profile`]'s single-disclosure secret, resolved by
/// [`authenticate_credential`]. Not `Bearer`, because two different secrets
/// travelling under one scheme would have to be told apart by guessing.
pub const AUTH_SCHEME_CREDENTIAL: &str = "Credential";

/// No usable `Authorization` header: absent, unparseable, empty, or naming a
/// scheme this crate does not implement.
///
/// Deliberately distinct from [`ERR_CREDENTIAL_NOT_FOUND`] /
/// [`ERR_SESSION_NOT_FOUND`], and that is not an oracle: it reports only a
/// property of the caller's own request, which the caller already knows. It
/// names no profile, session or challenge, so it cannot answer "does X
/// exist".
pub const ERR_MISSING_CREDENTIAL: &str = "MISSING_CREDENTIAL";

/// The origin value a request with **no `Origin` header** presents.
///
/// Not a skipped check — a value. It is unequal to every real origin (a
/// browser origin is a scheme+host, never empty, and an opaque origin is the
/// literal `"null"`), so a session minted for a real origin can never be used
/// by a request that omits the header. See the module doc.
pub const NO_ORIGIN: &str = "";

/// The single constructor for every [`ERR_MISSING_CREDENTIAL`] refusal.
///
/// `pub(crate)` only so `super::http_error::tests::census` can list this code
/// among the route-reachable ones. That census is hand-maintained
/// (`http_error.rs:428`), and [`ERR_MISSING_CREDENTIAL`] was missing from it
/// while being reachable on three of the four mounted profile routes — so it
/// was exempt from both `every_error_code_maps_to_exactly_one_status` and
/// `stream_g_error_mapping_never_emits_403`. Calling this function from the
/// census rather than rebuilding an equivalent `ApiError::new` there is
/// deliberate: a census entry that is a *copy* of the production value can
/// drift from it silently, which is the failure mode a census exists to
/// prevent.
pub(crate) fn missing_credential(detail: &'static str) -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        ERR_MISSING_CREDENTIAL,
        "profile_auth::AuthenticatedProfile",
        detail,
    )
}

/// Which of the two bearer secrets the caller presented.
///
/// Neither variant's `String` is ever placed in an [`ApiError`] detail: the
/// detail is written to `tracing`, and both of these values authenticate by
/// possession alone.
enum PresentedCredential {
    Session(String),
    Credential(String),
}

/// Parse `Authorization: <scheme> <value>` into one of the two schemes.
///
/// Every failure collapses to [`ERR_MISSING_CREDENTIAL`]; see its doc.
fn presented_credential(headers: &HeaderMap) -> Result<PresentedCredential, ApiError> {
    let raw = headers
        .get(AUTHORIZATION)
        .ok_or_else(|| missing_credential("no Authorization header"))?
        .to_str()
        .map_err(|_| missing_credential("Authorization header is not valid ASCII"))?;

    let (scheme, value) = raw
        .split_once(' ')
        .ok_or_else(|| missing_credential("Authorization header has no <scheme> <value> split"))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(missing_credential(
            "Authorization header carries an empty value",
        ));
    }

    if scheme.eq_ignore_ascii_case(AUTH_SCHEME_SESSION) {
        Ok(PresentedCredential::Session(value.to_string()))
    } else if scheme.eq_ignore_ascii_case(AUTH_SCHEME_CREDENTIAL) {
        Ok(PresentedCredential::Credential(value.to_string()))
    } else {
        Err(missing_credential(
            "Authorization scheme is neither Bearer nor Credential",
        ))
    }
}

/// The request's `Origin`, with absence represented as [`NO_ORIGIN`].
///
/// **One helper for both sides of the comparison.** Minting (`post_challenge`
/// / `post_session`) and validating (`AuthenticatedProfile`) both read the
/// origin through this function, so "the origin a session is bound to" and
/// "the origin a later request presents" are computed identically. A helper
/// used on only one side would silently bind every session to a value the
/// other side could never reproduce.
fn presented_origin(headers: &HeaderMap) -> Result<String, ApiError> {
    match headers.get(ORIGIN) {
        None => Ok(NO_ORIGIN.to_string()),
        // An `Origin` that is not valid ASCII cannot be compared with the
        // sealed one at all. Refusing with `OriginMismatch` reuses the code
        // and status the store-level comparison already produces, rather than
        // inventing a second way to say the same thing.
        Some(value) => value
            .to_str()
            .map(str::to_string)
            .map_err(|_| ProfileAuthError::OriginMismatch.into()),
    }
}

/// Extractor: one token from the process-wide global bucket, and nothing
/// else.
///
/// The global bucket is keyed on nothing and costs O(1) memory
/// (`super::rate_limit`'s module doc), which is exactly why it is safe to
/// consult before anything about the request has been checked. It runs in an
/// extractor rather than in a handler body so it precedes [`ApiJson`]'s body
/// buffering — an unauthenticated `POST` must not be able to make this process
/// buffer 4 KiB per request without spending a token first.
///
/// **[`post_profile`] does not use this extractor**, and that is the fix for a
/// starvation channel rather than an oversight. `POST /v1/profile` is
/// unauthenticated by necessity, so while it spent a *global* token one
/// unauthenticated client could keep this bucket empty and every authenticated
/// route — which reaches this extractor through [`AuthenticatedProfile`] →
/// [`PresentedOrigin`], **before** any credential is read — answered 429 to
/// legitimate callers holding valid credentials. Registration now spends
/// [`RegistrationRateLimit`]'s separate budget instead; see
/// `super::rate_limit`'s "Why registration has a budget of its own".
///
/// [`PresentedOrigin`] delegates here rather than repeating the lock/verdict
/// dance, so there is exactly one place in the crate that spends a global
/// token.
pub struct GlobalRateLimit;

#[async_trait]
impl FromRequestParts<StreamGState> for GlobalRateLimit {
    type Rejection = ApiError;

    async fn from_request_parts(
        _parts: &mut Parts,
        state: &StreamGState,
    ) -> Result<Self, Self::Rejection> {
        // Scoped so the `std::sync` guard is dropped before the `?` and long
        // before any `.await` — see `StreamGState::rate_limiter`'s doc.
        let verdict = {
            let mut limiter = state
                .rate_limiter()
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            limiter.check_global(Instant::now())
        };
        verdict?;
        Ok(GlobalRateLimit)
    }
}

/// Extractor: one token from the process-wide **registration** bucket, and
/// nothing else. [`post_profile`]'s only bound.
///
/// # Why registration does not spend the global bucket
///
/// It used to, and that made unauthenticated registration a denial-of-service
/// lever over every authenticated route. Both checks run in extractors, and
/// [`GlobalRateLimit`] is reached from [`AuthenticatedProfile`] via
/// [`PresentedOrigin`] *before* the credential is even read — so a caller
/// sending ~2 req/s to `POST /v1/profile` drained the one process-wide bucket
/// and every legitimate authenticated request was refused 429 at a point where
/// holding a valid credential could not help.
///
/// The per-profile bucket cannot stand in here:
/// [`StreamGRateLimiter::check_profile`](super::rate_limit::StreamGRateLimiter::check_profile)
/// takes an [`AuthenticatedProfileId`] and at profile-creation time no profile
/// exists to key on. So the fix is a second keyless bucket, sized for what
/// registration actually is — see
/// [`STREAM_G_REGISTRATION_PER_MIN`](super::rate_limit::STREAM_G_REGISTRATION_PER_MIN).
/// A drained registration budget can now refuse only more registrations.
///
/// Reusing [`PresentedOrigin`] here would additionally have imported an
/// `ORIGIN_MISMATCH` refusal into a route with no origin semantics at all —
/// [`create_profile`] captures no origin, so there is nothing for a later
/// request to be compared against.
///
/// Like [`GlobalRateLimit`] it runs as an extractor rather than in the handler
/// body so it precedes [`ApiJson`]'s body buffering: an unauthenticated `POST`
/// must not be able to make this process buffer 4 KiB per request without
/// spending a token first.
///
/// Two tests hold this in place:
/// `tests::profile_creation_spends_a_registration_rate_limit_token` makes
/// deleting this parameter from [`post_profile`]'s signature a failure rather
/// than a silently unlimited registration endpoint, and
/// `tests::exhausting_registration_does_not_429_an_authenticated_route` fails
/// if it is ever swapped back to [`GlobalRateLimit`].
pub struct RegistrationRateLimit;

#[async_trait]
impl FromRequestParts<StreamGState> for RegistrationRateLimit {
    type Rejection = ApiError;

    async fn from_request_parts(
        _parts: &mut Parts,
        state: &StreamGState,
    ) -> Result<Self, Self::Rejection> {
        // Scoped so the `std::sync` guard is dropped before the `?` and long
        // before any `.await` — see `StreamGState::rate_limiter`'s doc.
        let verdict = {
            let mut limiter = state
                .rate_limiter()
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            limiter.check_registration(Instant::now())
        };
        verdict?;
        Ok(RegistrationRateLimit)
    }
}

/// Extractor: the **pre-authentication** work every origin-bound Stream G
/// profile route does — spend one token from the process-wide global bucket
/// (via [`GlobalRateLimit`]), then resolve the request's origin.
pub struct PresentedOrigin(String);

impl PresentedOrigin {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[async_trait]
impl FromRequestParts<StreamGState> for PresentedOrigin {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &StreamGState,
    ) -> Result<Self, Self::Rejection> {
        // Spend the global token first; the extractor's value carries nothing,
        // so it is discarded rather than bound.
        GlobalRateLimit::from_request_parts(parts, state).await?;
        Ok(PresentedOrigin(presented_origin(&parts.headers)?))
    }
}

/// Extractor: a caller who has **proven** possession of a profile's session
/// token or opaque credential, plus the origin the request declared.
///
/// This is the single place headers become an [`AuthenticatedProfileId`], so
/// no handler can forget the check — an unauthenticated profile-scoped route
/// is not expressible, because the only value of the required parameter type
/// comes from here (or from the two library mint points directly).
///
/// **It introduces no new constructor for [`AuthenticatedProfileId`].** It
/// holds the value [`validate_session`] or [`authenticate_credential`]
/// returned; the newtype's inner `String` is never touched. The compile-time
/// property in the module doc's "I3 fix" section is preserved unchanged.
///
/// Order of work, and why: global rate limit (O(1), pre-auth) → origin →
/// credential resolution → per-profile rate limit. The per-profile bucket is
/// keyed on the authenticated profile id, so it cannot be consulted before
/// authentication, which is precisely the ordering
/// `super::rate_limit`'s module doc requires.
pub struct AuthenticatedProfile {
    profile: AuthenticatedProfileId,
    origin: String,
}

impl AuthenticatedProfile {
    /// The proven profile. Pass this straight into
    /// [`issue_challenge_for_profile`] / [`revoke_session`] / any other
    /// `&AuthenticatedProfileId` entry point.
    pub fn profile(&self) -> &AuthenticatedProfileId {
        &self.profile
    }

    /// The origin this request declared, already enforced against the
    /// session's binding when the `Bearer` scheme was used.
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

#[async_trait]
impl FromRequestParts<StreamGState> for AuthenticatedProfile {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &StreamGState,
    ) -> Result<Self, Self::Rejection> {
        let PresentedOrigin(origin) = PresentedOrigin::from_request_parts(parts, state).await?;
        let presented = presented_credential(&parts.headers)?;

        let profile = match presented {
            // `presented_origin` is passed through, not dropped: a session
            // validates only from the origin it was minted for (M7).
            PresentedCredential::Session(token) => {
                validate_session(state.store(), state.data_key_hex(), &token, &origin)
                    .await?
                    .profile_id
            }
            // The opaque credential carries no origin binding — none was ever
            // captured for it (`create_profile` takes no origin), so there is
            // nothing here to check and nothing is silently skipped.
            PresentedCredential::Credential(credential) => {
                authenticate_credential(state.store(), state.data_key_hex(), &credential).await?
            }
        };

        let verdict = {
            let mut limiter = state
                .rate_limiter()
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            limiter.check_profile(&profile, Instant::now())
        };
        verdict?;

        Ok(AuthenticatedProfile { profile, origin })
    }
}

/// `POST /v1/profile/sessions` request body.
///
/// snake_case on the wire (founder ruling; `super::tests::stream_g_wire_dtos_are_snake_case`
/// pins the same rule for the readiness/metrics documents) and
/// `deny_unknown_fields`, matching [`super::onboarding::StartOnboardingRequest`]
/// and [`super::root_authorization::CreateRootAuthorizationRequest`] exactly.
///
/// There is **no `profile_id` field**, for the same reason those two have
/// none: the profile is resolved from the challenge row `create_session`
/// consumes, never from anything a caller can name.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSessionRequest {
    pub challenge_id: String,
    pub nonce: String,
}

/// `POST /v1/profile` request body.
///
/// snake_case and `deny_unknown_fields`, matching [`CreateSessionRequest`],
/// [`super::onboarding::StartOnboardingRequest`] and
/// [`super::root_authorization::CreateRootAuthorizationRequest`].
///
/// One field, and it is the only one there could be. [`create_profile`] takes
/// exactly one input; §5.2's no-KYC rule means there is no email, no identity
/// and no contact detail to accept, and `profile_id` is *derived* from this key
/// (keyed HMAC, I2) rather than named by the caller.
///
/// Well inside [`super::STREAM_G_BODY_LIMIT_BYTES`]: one key at
/// [`super::IDEMPOTENCY_KEY_BUDGET_CHARS`] is ~150 bytes of JSON against a
/// 4096-byte ceiling, so `super::tests::the_body_limit_clears_the_largest_real_dto`'s
/// measurement of the quote DTO remains the binding one.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateProfileRequest {
    pub idempotency_key: String,
}

/// `POST /v1/profile` — open registration. **The one Stream G route that
/// *writes* without a credential**, because it is where a credential comes
/// from.
///
/// Not the only credential-free route, and the difference matters to anyone
/// auditing the perimeter: `GET /v1/stream-g/ready` and
/// `GET /v1/stream-g/metrics` take no credential either — they name neither
/// [`AuthenticatedProfile`] nor [`GlobalRateLimit`], so they are also outside
/// [`super::rate_limit`] entirely (that module's "Nothing else is
/// rate-limited" section says the same, and `stream_g`'s module doc
/// enumerates all ten). What is exclusive to this route is that it is the only
/// uncredentialed one that changes durable state: it inserts a `profiles`
/// row. The two `GET`s read process counters and store health.
///
/// # Why it is unauthenticated, and what stands in for authentication
///
/// [`create_profile`]'s doc records the design: no email, no identity, no KYC —
/// the profile is identified purely by the opaque high-entropy credential
/// returned once, and only a keyed hash of it is ever persisted. Requiring a
/// credential here would make the first one unobtainable, exactly as requiring
/// a session to mint a session would (see [`post_session`]).
///
/// So the only bound this route has is [`RegistrationRateLimit`] — a
/// process-wide bucket of its own, spent in an extractor so it precedes body
/// buffering. It is deliberately **not** [`GlobalRateLimit`]: sharing that
/// bucket let an unauthenticated caller drain the budget every authenticated
/// route spends from first, so registration traffic could 429 callers holding
/// valid credentials. See [`RegistrationRateLimit`]'s doc for the full
/// accounting. The per-profile bucket is not merely omitted, it is
/// **unavailable**: `StreamGRateLimiter::check_profile` takes an
/// [`AuthenticatedProfileId`], and no profile exists yet to key on. That is the
/// whole of the enforcement, and `super::rate_limit`'s module doc is the place
/// that must stay true to it.
///
/// This process has no per-IP bound at all — that is a **deployment
/// requirement** on the reverse proxy in front of it, recorded in
/// `super::rate_limit`'s module doc.
///
/// # A replayer never receives a credential
///
/// [`create_profile`] returns [`ProfileAuthError::IdempotencyKeyConflict`] on
/// any collision rather than a second `Ok` — see its doc and the I2 note in the
/// module doc for why re-disclosure is not an option for a single-disclosure
/// secret. That maps to **409** through `ProfileAuthError::status`, and the
/// [`ApiError`] envelope carries the code and nothing else, so the conflict
/// response has nowhere to put a credential even by accident.
/// `tests::profile_creation_discloses_a_credential_exactly_once` is the pin.
///
/// # Extractor order is compiler-enforced
///
/// [`RegistrationRateLimit`] and [`State`] are `FromRequestParts`; [`ApiJson`]
/// is the `FromRequest` body extractor and must therefore come last.
pub(crate) async fn post_profile(
    State(state): State<StreamGState>,
    _rate_limit: RegistrationRateLimit,
    ApiJson(req): ApiJson<CreateProfileRequest>,
) -> Result<Json<CreateProfileOutcome>, ApiError> {
    let outcome = create_profile(state.store(), state.data_key_hex(), &req.idempotency_key).await?;
    Ok(Json(outcome))
}

/// `POST /v1/profile/challenges` — mint a single-use, origin-bound challenge
/// for the authenticated caller.
///
/// **No request body, deliberately.** The only two things a caller could name
/// here are `profile_id`, which must be proven rather than asserted (see the
/// module doc's "I3 fix"), and `challenge_type`, which is policy: this route
/// mints [`CHALLENGE_TYPE_SESSION`] challenges, the one type
/// [`create_session`] will redeem. Letting a caller name a type would only
/// let them fill `auth_challenges` with rows nothing can redeem.
pub(crate) async fn post_challenge(
    State(state): State<StreamGState>,
    caller: AuthenticatedProfile,
) -> Result<Json<IssuedChallenge>, ApiError> {
    let issued = issue_challenge_for_profile(
        state.store(),
        state.data_key_hex(),
        caller.profile(),
        CHALLENGE_TYPE_SESSION,
        caller.origin(),
    )
    .await?;
    Ok(Json(issued))
}

/// `POST /v1/profile/sessions` — redeem a challenge into a session.
///
/// **Takes no `Authorization` header, and that is the design rather than an
/// omission.** The credential this route checks is the `(challenge_id,
/// nonce)` pair in the body: the nonce is a 32-byte secret that only the
/// caller who minted the challenge ever saw (it is never persisted in the
/// clear — see the module doc's sealed-payload note), and `create_session`
/// resolves the subject profile from the challenge row rather than from
/// anything presented here. Requiring a session to mint a session would make
/// the first one unobtainable.
pub(crate) async fn post_session(
    State(state): State<StreamGState>,
    origin: PresentedOrigin,
    ApiJson(req): ApiJson<CreateSessionRequest>,
) -> Result<Json<CreatedSession>, ApiError> {
    let created = create_session(
        state.store(),
        state.data_key_hex(),
        &req.challenge_id,
        &req.nonce,
        origin.as_str(),
    )
    .await?;
    Ok(Json(created))
}

/// `DELETE /v1/profile/sessions/:id` — revoke one of the caller's own
/// sessions.
///
/// **`:id`, not `{id}`.** This crate runs axum 0.7 / matchit 0.7, where `{`
/// and `}` are ordinary path characters: `"/v1/profile/sessions/{id}"`
/// compiles, does not panic, and matches only the literal segment `{id}`, so
/// every real request would 404.
/// `tests::the_delete_route_binds_the_session_id_from_the_path` is what makes
/// that a failing test rather than a silent outage.
///
/// **204 whether or not anything was revoked, on purpose.** [`revoke_session`]
/// is a guarded `UPDATE ... AND profile_id = ?` whose rows-affected is not
/// inspected, so an unknown id, an already-revoked session and *another
/// profile's* session all produce the identical response an owner's
/// successful revocation produces — same status, same (empty) body. That is
/// `super::http_error`'s ownership-oracle rule applied here: Stream G emits no
/// 403, and a caller learns nothing about sessions it does not own.
///
/// Residual, stated rather than implied: `Path<String>`'s own rejection (a
/// path segment whose percent-encoding is not valid UTF-8) is axum's, and
/// answers in `text/plain` rather than the Stream G envelope. Every other
/// failure on this route goes through [`ApiError`].
pub(crate) async fn delete_session(
    State(state): State<StreamGState>,
    caller: AuthenticatedProfile,
    Path(session_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    revoke_session(state.store(), caller.profile(), &session_id).await?;
    Ok(StatusCode::NO_CONTENT)
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

    fn data_key_hex() -> SecretHex {
        SecretHex::from_hex(&"aa".repeat(32)).expect("valid 32-byte test key")
    }

    async fn challenge_row_exists(store: &StreamGStore, id: &str) -> bool {
        let id = id.to_string();
        let count: i64 = store
            .read(|handle| {
                Box::pin(async move {
                    let count: i64 = handle
                        .fetch_scalar(
                            sqlx::query_scalar("SELECT COUNT(*) FROM auth_challenges WHERE id = ?")
                                .bind(&id),
                        )
                        .await?;
                    Ok::<i64, StreamGStoreError>(count)
                })
            })
            .await
            .unwrap();
        count == 1
    }

    async fn session_row_exists(store: &StreamGStore, id: &str) -> bool {
        let id = id.to_string();
        let count: i64 = store
            .read(|handle| {
                Box::pin(async move {
                    let count: i64 = handle
                        .fetch_scalar(
                            sqlx::query_scalar(
                                "SELECT COUNT(*) FROM profile_sessions WHERE id = ?",
                            )
                            .bind(&id),
                        )
                        .await?;
                    Ok::<i64, StreamGStoreError>(count)
                })
            })
            .await
            .unwrap();
        count == 1
    }

    // --- alias blind index (test #6) ---

    #[test]
    fn alias_hash_is_stable_for_same_normalized_alias_and_differs_for_different_alias() {
        let key = data_key_hex();
        let h1 = alias_hash_hex(&key, &normalize_alias("  Foo@Bar.com ")).unwrap();
        let h2 = alias_hash_hex(&key, &normalize_alias("foo@bar.com")).unwrap();
        assert_eq!(h1, h2, "same normalized alias must hash the same");

        let h3 = alias_hash_hex(&key, &normalize_alias("other@bar.com")).unwrap();
        assert_ne!(h1, h3, "different alias must hash differently");
    }

    #[test]
    fn alias_hash_index_key_is_not_the_raw_data_key_and_is_not_a_bare_sha256() {
        let key = data_key_hex();
        let normalized = normalize_alias("someone@example.com");
        let alias_hash = alias_hash_hex(&key, &normalized).unwrap();

        assert_ne!(
            alias_hash,
            key.as_str(),
            "alias_hash must not equal the raw data key hex"
        );

        let bare_sha256 = hex::encode(Sha256::digest(normalized.as_bytes()));
        assert_ne!(
            alias_hash, bare_sha256,
            "alias_hash must not equal a plain unkeyed SHA-256 of the alias (proves keying)"
        );

        // Different data keys must derive different index keys, hence
        // different alias hashes for the same alias.
        let other_key = SecretHex::from_hex(&"bb".repeat(32)).expect("valid test key");
        let alias_hash_other_key = alias_hash_hex(&other_key, &normalized).unwrap();
        assert_ne!(alias_hash, alias_hash_other_key);
    }

    // --- alias attach: M4 (idempotent, profile-scoped, DB round trip) ---

    #[tokio::test]
    async fn attach_alias_round_trips_alias_enc_under_the_rows_own_aad() {
        let (_dir, store) = open_store().await;
        let key = data_key_hex();
        let profile = create_profile(&store, &key, "idem-alias-1").await.unwrap();

        attach_alias(
            &store,
            &key,
            &AuthenticatedProfileId::for_test(&profile.profile_id),
            "email",
            "  Someone@Example.com ",
        )
        .await
        .expect("attach alias");

        let (row_id, alias_enc): (String, Vec<u8>) = store
            .read(|handle| {
                Box::pin(async move {
                    let row = handle
                        .fetch_one(sqlx::query(
                            "SELECT id, alias_enc FROM credential_aliases WHERE alias_type = 'email'",
                        ))
                        .await?;
                    let row_id: String = row.try_get("id")?;
                    let alias_enc: Option<Vec<u8>> = row.try_get("alias_enc")?;
                    Ok::<_, StreamGStoreError>((row_id, alias_enc.expect("alias_enc must be set")))
                })
            })
            .await
            .unwrap();

        let data_key = DataKey::from_secret(&key);
        let aad = store.envelope_aad("credential_aliases", &row_id, "alias_enc");
        let opened = crypto_store::open(&data_key, &aad, &alias_enc)
            .expect("alias_enc must open under its own row's AAD");
        assert_eq!(
            &opened[..],
            normalize_alias("  Someone@Example.com ").as_bytes()
        );
    }

    #[tokio::test]
    async fn attach_alias_replay_by_same_profile_is_idempotent_not_an_error() {
        let (_dir, store) = open_store().await;
        let key = data_key_hex();
        let profile = create_profile(&store, &key, "idem-alias-2").await.unwrap();

        attach_alias(
            &store,
            &key,
            &AuthenticatedProfileId::for_test(&profile.profile_id),
            "email",
            "dup@example.com",
        )
        .await
        .unwrap();
        attach_alias(
            &store,
            &key,
            &AuthenticatedProfileId::for_test(&profile.profile_id),
            "email",
            "DUP@EXAMPLE.COM ",
        )
        .await
        .expect(
            "a true replay (same profile, same normalized alias) must be a no-op, not an error",
        );

        let count: i64 = store
            .read(|handle| {
                Box::pin(async move {
                    let c: i64 = handle
                        .fetch_scalar(sqlx::query_scalar(
                            "SELECT COUNT(*) FROM credential_aliases WHERE alias_type = 'email'",
                        ))
                        .await?;
                    Ok::<i64, StreamGStoreError>(c)
                })
            })
            .await
            .unwrap();
        assert_eq!(count, 1, "replay must not create a second row");
    }

    #[tokio::test]
    async fn attach_alias_rejects_a_different_profile_attaching_the_same_alias() {
        let (_dir, store) = open_store().await;
        let key = data_key_hex();
        let profile_a = create_profile(&store, &key, "idem-alias-3a").await.unwrap();
        let profile_b = create_profile(&store, &key, "idem-alias-3b").await.unwrap();

        attach_alias(
            &store,
            &key,
            &AuthenticatedProfileId::for_test(&profile_a.profile_id),
            "email",
            "shared@example.com",
        )
        .await
        .unwrap();

        let err = attach_alias(
            &store,
            &key,
            &AuthenticatedProfileId::for_test(&profile_b.profile_id),
            "email",
            "shared@example.com",
        )
        .await
        .expect_err("a different profile attaching the same alias must be refused");
        assert!(matches!(err, ProfileAuthError::AliasAlreadyAttached));
        assert_eq!(err.code(), ERR_ALIAS_ALREADY_ATTACHED);

        let count: i64 = store
            .read(|handle| {
                Box::pin(async move {
                    let c: i64 = handle
                        .fetch_scalar(sqlx::query_scalar(
                            "SELECT COUNT(*) FROM credential_aliases WHERE alias_type = 'email'",
                        ))
                        .await?;
                    Ok::<i64, StreamGStoreError>(c)
                })
            })
            .await
            .unwrap();
        assert_eq!(count, 1, "the rejected attempt must not create a row");
    }

    // --- opaque credential / profile creation ---

    #[tokio::test]
    async fn create_profile_never_stores_the_plaintext_credential() {
        let (dir, store) = open_store().await;
        let key = data_key_hex();
        let outcome = create_profile(&store, &key, "idem-create-1").await.unwrap();
        let credential = outcome.credential.clone();

        let profile_id = authenticate_credential(&store, &key, &credential)
            .await
            .expect("credential must resolve back to the profile");
        assert_eq!(profile_id.as_str(), outcome.profile_id);

        // M9(b) round 2: the previous fix scanned `hex(profile_enc)` /
        // `hex(alias_enc)` over `profiles` / `credential_aliases`, but
        // `create_profile` never populates either column -- it only ever
        // inserts `(id, created_at, status)` into `profiles` and
        // `(id, profile_id, alias_type, alias_hash, created_at)` into
        // `credential_aliases` (see above). Every scanned cell is NULL, so
        // `group_concat` returns NULL, `COALESCE(...,'')` turns that into
        // `""`, and the assertion `!"".contains(credential)` was true
        // regardless of what the implementation actually does -- the proof
        // was vacuous even though the implementation is correct.
        //
        // Scan the whole on-disk SQLite file instead of hand-picked
        // columns, so the proof does not depend on this test's author
        // correctly enumerating every column the implementation could ever
        // write the credential into. This store is WAL-mode: a committed
        // write can still be sitting only in the `-wal` file rather than
        // the main database file, so checkpoint first (`TRUNCATE`, via the
        // one pooled connection, with no other transaction open) to
        // guarantee every page the implementation could have touched has
        // been folded into the single file this test then reads back.
        store
            .read(|handle| {
                Box::pin(async move {
                    handle
                        .fetch_optional(sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)"))
                        .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("checkpoint the WAL before scanning the raw database file");

        let db_path = dir.path().join("stream_g.sqlite");
        let raw = std::fs::read(&db_path).expect("read the raw database file");
        let credential_bytes = credential.as_bytes();
        let found = raw
            .windows(credential_bytes.len())
            .any(|window| window == credential_bytes);
        assert!(
            !found,
            "plaintext credential must never be persisted anywhere in the database file"
        );
    }

    #[tokio::test]
    async fn create_profile_replay_of_same_idempotency_key_returns_conflict_not_a_second_profile() {
        let (_dir, store) = open_store().await;
        let key = data_key_hex();

        let first = create_profile(&store, &key, "idem-create-2").await.unwrap();

        // I2: a second call with the same idempotency key must NOT
        // silently succeed and hand back `profile_id` with no credential --
        // there is no way, at profile-creation time, to tell a legitimate
        // client retry apart from a different caller who guessed/observed
        // the key, so the only safe response to any collision is a typed
        // conflict, never a disclosed/adopted profile.
        let err = create_profile(&store, &key, "idem-create-2")
            .await
            .expect_err("a replay must be a typed conflict, not a disclosed/adopted profile");
        assert!(matches!(err, ProfileAuthError::IdempotencyKeyConflict));
        assert_eq!(err.code(), ERR_IDEMPOTENCY_KEY_CONFLICT);

        let count: i64 = store
            .read(|handle| {
                Box::pin(async move {
                    let c: i64 = handle
                        .fetch_scalar(sqlx::query_scalar("SELECT COUNT(*) FROM profiles"))
                        .await?;
                    Ok::<i64, StreamGStoreError>(c)
                })
            })
            .await
            .unwrap();
        assert_eq!(
            count, 1,
            "the conflicting attempt must not create a second profile row"
        );

        // The first call's credential must remain the only thing that
        // authenticates into this profile.
        let resolved = authenticate_credential(&store, &key, &first.credential)
            .await
            .unwrap();
        assert_eq!(resolved.as_str(), first.profile_id);
    }

    #[tokio::test]
    async fn profile_id_is_a_keyed_hmac_not_offline_computable_from_the_idempotency_key_alone() {
        let (_dir, store) = open_store().await;
        let key = data_key_hex();
        let idempotency_key = "predictable-low-entropy-value";

        let outcome = create_profile(&store, &key, idempotency_key).await.unwrap();

        // I2: profile_id must not equal the old unkeyed derivation this
        // module used before the fix (a bare SHA-256 anyone could
        // precompute offline for a candidate key list, no server
        // interaction or data key required).
        let bare_sha256 = hex::encode(Sha256::digest(
            format!("profile|{idempotency_key}").as_bytes(),
        ));
        assert_ne!(
            outcome.profile_id, bare_sha256,
            "profile_id must not equal a plain unkeyed SHA-256 of the idempotency key (proves keying)"
        );

        // A different data key must derive a different profile_id for the
        // SAME idempotency key -- proves the derivation is actually keyed
        // by the data key, not merely a differently-shaped public formula.
        let (_dir2, store2) = open_store().await;
        let other_key = SecretHex::from_hex(&"bb".repeat(32)).expect("valid test key");
        let outcome_other_key = create_profile(&store2, &other_key, idempotency_key)
            .await
            .unwrap();
        assert_ne!(outcome.profile_id, outcome_other_key.profile_id);
    }

    // --- challenges (test #3 plan-mandated name + test #4 concurrency) ---

    #[tokio::test]
    async fn challenge_is_single_use_and_origin_bound() {
        let (_dir, store) = open_store().await;
        let key = data_key_hex();
        let profile = create_profile(&store, &key, "idem-challenge-1")
            .await
            .unwrap();

        let issued = issue_challenge_for_profile(
            &store,
            &key,
            &AuthenticatedProfileId::for_test(&profile.profile_id),
            CHALLENGE_TYPE_SESSION,
            "https://a.example",
        )
        .await
        .unwrap();

        // Half 1: redemption from a different origin must fail.
        let err = create_session(
            &store,
            &key,
            &issued.challenge_id,
            &issued.nonce,
            "https://b.example",
        )
        .await
        .expect_err("redemption from a different origin must fail");
        assert!(matches!(err, ProfileAuthError::OriginMismatch));
        assert_eq!(err.code(), ERR_ORIGIN_MISMATCH);

        // Correct origin: succeeds.
        let session = create_session(
            &store,
            &key,
            &issued.challenge_id,
            &issued.nonce,
            "https://a.example",
        )
        .await
        .expect("redemption from the bound origin must succeed");
        assert_eq!(session.profile_id, profile.profile_id);

        // Half 2: a second redemption (even with the right nonce/origin) must fail.
        let err = create_session(
            &store,
            &key,
            &issued.challenge_id,
            &issued.nonce,
            "https://a.example",
        )
        .await
        .expect_err("second redemption of the same challenge must fail");
        assert!(matches!(err, ProfileAuthError::ChallengeAlreadyConsumed));
        assert_eq!(err.code(), ERR_CHALLENGE_ALREADY_CONSUMED);
    }

    // --- I3: proof of possession ------------------------------------------

    /// I3's core exploit scenario, proven impossible at runtime as strongly
    /// as this crate can prove it without a `trybuild`-style compile-fail
    /// test (no new dependency is allowed -- see module doc's "I3 fix"
    /// section for the accompanying compile-time argument).
    ///
    /// Before the fix: `issue_challenge(profile_id: Option<&str>, ..)` took
    /// the profile id straight from the caller with no credential
    /// presented anywhere, so an attacker who merely *knew* the victim's
    /// `profile_id` (not a secret -- returned in plaintext by
    /// `create_profile`) could call `issue_challenge(Some(victim_id), ..)`
    /// himself, then `create_session` with the nonce/origin he controls
    /// both ends of, and walk away with a 24-hour session for a profile he
    /// never authenticated into.
    ///
    /// After the fix: the only function that can bind a challenge to a
    /// profile is `issue_challenge_for_profile`, which requires an
    /// `AuthenticatedProfileId` -- a type with no public constructor from a
    /// bare string. The attacker's *only* avenue to obtain one for the
    /// victim is to present the victim's actual credential to
    /// `authenticate_credential`. This test proves that knowing the
    /// (non-secret) `profile_id` does not let him do that: presenting it
    /// where the (secret) credential is required is rejected exactly like
    /// any other unrecognized credential, and separately proves the
    /// legitimate owner's *actual* credential does succeed, so the
    /// rejection above is not just "credentials never work here".
    #[tokio::test]
    async fn attacker_who_knows_victim_profile_id_cannot_authenticate_as_the_victim() {
        let (_dir, store) = open_store().await;
        let key = data_key_hex();
        let victim = create_profile(&store, &key, "idem-i3-victim")
            .await
            .unwrap();

        // The attacker knows victim.profile_id (it was returned in
        // plaintext at creation, to whoever created the profile) but does
        // NOT know victim.credential (disclosed once, only to the real
        // owner). Trying to authenticate with the profile_id in place of
        // the credential -- the only "value" an attacker who merely knows
        // the id actually has -- must fail exactly like any other unknown
        // credential.
        let attacker_attempt = authenticate_credential(&store, &key, &victim.profile_id).await;
        assert!(
            matches!(attacker_attempt, Err(ProfileAuthError::CredentialNotFound)),
            "knowing a profile_id must not be sufficient to authenticate as that profile"
        );

        // Control: the real credential DOES resolve to an
        // AuthenticatedProfileId for that profile, proving the rejection
        // above is specifically about the attacker's lack of proof, not a
        // broken `authenticate_credential`.
        let legit = authenticate_credential(&store, &key, &victim.credential)
            .await
            .expect("the true credential must still authenticate");
        assert_eq!(legit.as_str(), victim.profile_id);
    }

    /// End-to-end proof that the *legitimate* authenticated path this fix
    /// introduces still works: present the real credential, obtain an
    /// `AuthenticatedProfileId`, use it to issue a profile-bound challenge,
    /// and redeem that challenge into a session for the correct profile.
    /// This is the realistic flow `issue_challenge_for_profile` exists
    /// for -- exercised here via the real `authenticate_credential` call
    /// rather than the `#[cfg(test)]` escape hatch used elsewhere in this
    /// suite, so at least one test in the file proves the whole
    /// proof-of-possession chain end to end.
    #[tokio::test]
    async fn authenticated_profile_id_from_real_credential_can_issue_a_bound_challenge_and_session()
    {
        let (_dir, store) = open_store().await;
        let key = data_key_hex();
        let profile = create_profile(&store, &key, "idem-i3-e2e").await.unwrap();

        let authenticated = authenticate_credential(&store, &key, &profile.credential)
            .await
            .expect("real credential must authenticate");

        let issued = issue_challenge_for_profile(
            &store,
            &key,
            &authenticated,
            CHALLENGE_TYPE_SESSION,
            "https://a.example",
        )
        .await
        .expect("an authenticated profile can issue a profile-bound challenge");

        let session = create_session(
            &store,
            &key,
            &issued.challenge_id,
            &issued.nonce,
            "https://a.example",
        )
        .await
        .expect("redeeming a legitimately-bound challenge must succeed");
        assert_eq!(session.profile_id, profile.profile_id);
    }

    /// The genuinely-anonymous path (brief §4's nullable
    /// `auth_challenges.profile_id`, for first-time enrollment before any
    /// credential exists) stays expressible after the I3 fix: a distinct,
    /// explicitly-named function that never requires an
    /// `AuthenticatedProfileId`, always producing a `NULL`-profile
    /// challenge that -- correctly -- cannot redeem into a profile-bound
    /// session.
    #[tokio::test]
    async fn issue_challenge_anonymous_produces_a_null_profile_challenge_that_cannot_bind_a_session(
    ) {
        let (_dir, store) = open_store().await;
        let key = data_key_hex();

        let issued =
            issue_challenge_anonymous(&store, &key, CHALLENGE_TYPE_SESSION, "https://a.example")
                .await
                .expect("anonymous challenge issuance requires no authentication");

        let challenge_id_for_read = issued.challenge_id.clone();
        let profile_id: Option<String> = store
            .read(|handle| {
                Box::pin(async move {
                    let row = handle
                        .fetch_one(
                            sqlx::query("SELECT profile_id FROM auth_challenges WHERE id = ?")
                                .bind(&challenge_id_for_read),
                        )
                        .await?;
                    let profile_id: Option<String> = row.try_get("profile_id")?;
                    Ok::<_, StreamGStoreError>(profile_id)
                })
            })
            .await
            .unwrap();
        assert_eq!(
            profile_id, None,
            "an anonymously-issued challenge must have NULL profile_id"
        );

        let err = create_session(
            &store,
            &key,
            &issued.challenge_id,
            &issued.nonce,
            "https://a.example",
        )
        .await
        .expect_err("a NULL-profile challenge must not redeem into a session");
        assert!(matches!(err, ProfileAuthError::ChallengeNotBoundToProfile));
        assert_eq!(err.code(), ERR_CHALLENGE_NOT_BOUND_TO_PROFILE);
    }

    #[tokio::test]
    async fn concurrent_double_redeem_of_one_challenge_exactly_one_succeeds() {
        let (_dir, store) = open_store().await;
        let key = data_key_hex();
        let profile = create_profile(&store, &key, "idem-challenge-race")
            .await
            .unwrap();
        let issued = issue_challenge_for_profile(
            &store,
            &key,
            &AuthenticatedProfileId::for_test(&profile.profile_id),
            CHALLENGE_TYPE_SESSION,
            "https://a.example",
        )
        .await
        .unwrap();

        let store = std::sync::Arc::new(store);
        let key1 = data_key_hex();
        let challenge_id1 = issued.challenge_id.clone();
        let nonce1 = issued.nonce.clone();
        let s1 = store.clone();
        let t1 = tokio::spawn(async move {
            create_session(&s1, &key1, &challenge_id1, &nonce1, "https://a.example").await
        });

        let key2 = data_key_hex();
        let challenge_id2 = issued.challenge_id.clone();
        let nonce2 = issued.nonce.clone();
        let s2 = store.clone();
        let t2 = tokio::spawn(async move {
            create_session(&s2, &key2, &challenge_id2, &nonce2, "https://a.example").await
        });

        let (r1, r2) = tokio::join!(t1, t2);
        let r1 = r1.unwrap();
        let r2 = r2.unwrap();
        let successes = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            successes, 1,
            "exactly one concurrent redemption must succeed"
        );
    }

    #[tokio::test]
    async fn challenge_expiry_is_enforced() {
        let (_dir, store) = open_store().await;
        let key = data_key_hex();
        let profile = create_profile(&store, &key, "idem-challenge-expiry")
            .await
            .unwrap();
        let issued = issue_challenge_for_profile(
            &store,
            &key,
            &AuthenticatedProfileId::for_test(&profile.profile_id),
            CHALLENGE_TYPE_SESSION,
            "https://a.example",
        )
        .await
        .unwrap();

        // Force-expire directly (this module has no clock injection --
        // exercising real elapsed time in a unit test isn't practical, so
        // this reaches into the row the same way a production TTL sweep
        // eventually would).
        store
            .write_tx(|tx| {
                Box::pin(async move {
                    sqlx::query("UPDATE auth_challenges SET expires_at = 0")
                        .execute(&mut **tx)
                        .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .unwrap();

        let err = create_session(
            &store,
            &key,
            &issued.challenge_id,
            &issued.nonce,
            "https://a.example",
        )
        .await
        .expect_err("expired challenge must be rejected");
        assert!(matches!(err, ProfileAuthError::ChallengeExpired));
        assert_eq!(err.code(), ERR_CHALLENGE_EXPIRED);
    }

    // --- challenge type binding: M1 ---

    #[tokio::test]
    async fn create_session_rejects_challenge_type_mismatch() {
        let (_dir, store) = open_store().await;
        let key = data_key_hex();
        let profile = create_profile(&store, &key, "idem-type-mismatch")
            .await
            .unwrap();

        // Issued for a *different* purpose than "session".
        let issued = issue_challenge_for_profile(
            &store,
            &key,
            &AuthenticatedProfileId::for_test(&profile.profile_id),
            "wallet_link",
            "https://a.example",
        )
        .await
        .unwrap();

        let err = create_session(
            &store,
            &key,
            &issued.challenge_id,
            &issued.nonce,
            "https://a.example",
        )
        .await
        .expect_err("a non-session-typed challenge must not redeem into a session");
        assert!(matches!(err, ProfileAuthError::ChallengeTypeMismatch));
        assert_eq!(err.code(), ERR_CHALLENGE_TYPE_MISMATCH);

        // The rejected attempt must not have burned the challenge -- the
        // type check is a phase-1 *content* check that runs before the
        // single-use UPDATE, so a retry sees the SAME error again, not
        // `ChallengeAlreadyConsumed`.
        let err_again = create_session(
            &store,
            &key,
            &issued.challenge_id,
            &issued.nonce,
            "https://a.example",
        )
        .await
        .expect_err("still type-mismatched on retry");
        assert!(matches!(err_again, ProfileAuthError::ChallengeTypeMismatch));
    }

    // --- sessions (test #7) ---

    #[tokio::test]
    async fn session_lifecycle_valid_expired_revoked_unknown_double_revoke() {
        let (_dir, store) = open_store().await;
        let key = data_key_hex();
        let profile = create_profile(&store, &key, "idem-session-lifecycle")
            .await
            .unwrap();

        // unknown token
        let err = validate_session(&store, &key, "not-a-real-token", "https://a.example")
            .await
            .unwrap_err();
        assert!(matches!(err, ProfileAuthError::SessionNotFound));
        assert_eq!(err.code(), ERR_SESSION_NOT_FOUND);

        // valid -> validates
        let issued = issue_challenge_for_profile(
            &store,
            &key,
            &AuthenticatedProfileId::for_test(&profile.profile_id),
            CHALLENGE_TYPE_SESSION,
            "https://a.example",
        )
        .await
        .unwrap();
        let session = create_session(
            &store,
            &key,
            &issued.challenge_id,
            &issued.nonce,
            "https://a.example",
        )
        .await
        .unwrap();
        let info = validate_session(&store, &key, &session.session_token, "https://a.example")
            .await
            .unwrap();
        assert_eq!(info.profile_id.as_str(), profile.profile_id);
        assert_eq!(info.session_id, session.session_id);

        // expired -> rejected
        store
            .write_tx({
                let session_id = session.session_id.clone();
                move |tx| {
                    Box::pin(async move {
                        sqlx::query("UPDATE profile_sessions SET expires_at = 0 WHERE id = ?")
                            .bind(&session_id)
                            .execute(&mut **tx)
                            .await?;
                        Ok::<(), StreamGStoreError>(())
                    })
                }
            })
            .await
            .unwrap();
        let err = validate_session(&store, &key, &session.session_token, "https://a.example")
            .await
            .unwrap_err();
        assert!(matches!(err, ProfileAuthError::SessionExpired));
        assert_eq!(err.code(), ERR_SESSION_EXPIRED);

        // un-expire, then revoke -> rejected
        store
            .write_tx({
                let session_id = session.session_id.clone();
                move |tx| {
                    Box::pin(async move {
                        sqlx::query(
                            "UPDATE profile_sessions SET expires_at = 9999999999 WHERE id = ?",
                        )
                        .bind(&session_id)
                        .execute(&mut **tx)
                        .await?;
                        Ok::<(), StreamGStoreError>(())
                    })
                }
            })
            .await
            .unwrap();
        validate_session(&store, &key, &session.session_token, "https://a.example")
            .await
            .expect("un-expired session should validate again before revoke");

        revoke_session(
            &store,
            &AuthenticatedProfileId::for_test(&profile.profile_id),
            &session.session_id,
        )
        .await
        .unwrap();
        let err = validate_session(&store, &key, &session.session_token, "https://a.example")
            .await
            .unwrap_err();
        assert!(matches!(err, ProfileAuthError::SessionRevoked));
        assert_eq!(err.code(), ERR_SESSION_REVOKED);

        // double revoke -> still OK (idempotent)
        revoke_session(
            &store,
            &AuthenticatedProfileId::for_test(&profile.profile_id),
            &session.session_id,
        )
        .await
        .expect("double revoke must not error");
    }

    // --- session origin binding: M7 ---

    #[tokio::test]
    async fn validate_session_rejects_a_different_origin_than_it_was_minted_for() {
        let (_dir, store) = open_store().await;
        let key = data_key_hex();
        let profile = create_profile(&store, &key, "idem-session-origin")
            .await
            .unwrap();

        let issued = issue_challenge_for_profile(
            &store,
            &key,
            &AuthenticatedProfileId::for_test(&profile.profile_id),
            CHALLENGE_TYPE_SESSION,
            "https://a.example",
        )
        .await
        .unwrap();
        let session = create_session(
            &store,
            &key,
            &issued.challenge_id,
            &issued.nonce,
            "https://a.example",
        )
        .await
        .unwrap();

        // The one-shot challenge redemption was bound to https://a.example;
        // the long-lived session it produced must carry that binding
        // forward for its own full TTL, not just for the redemption itself.
        let err = validate_session(&store, &key, &session.session_token, "https://evil.example")
            .await
            .expect_err(
                "a session must not validate from a different origin than it was minted for",
            );
        assert!(matches!(err, ProfileAuthError::OriginMismatch));
        assert_eq!(err.code(), ERR_ORIGIN_MISMATCH);

        // The bound origin still works.
        validate_session(&store, &key, &session.session_token, "https://a.example")
            .await
            .expect("the originally-bound origin must still validate");
    }

    // --- session revocation ownership: I6 ---

    #[tokio::test]
    async fn revoke_session_requires_the_owning_profile_id() {
        let (_dir, store) = open_store().await;
        let key = data_key_hex();
        let victim = create_profile(&store, &key, "idem-revoke-victim")
            .await
            .unwrap();
        let attacker = create_profile(&store, &key, "idem-revoke-attacker")
            .await
            .unwrap();

        let issued = issue_challenge_for_profile(
            &store,
            &key,
            &AuthenticatedProfileId::for_test(&victim.profile_id),
            CHALLENGE_TYPE_SESSION,
            "https://a.example",
        )
        .await
        .unwrap();
        let session = create_session(
            &store,
            &key,
            &issued.challenge_id,
            &issued.nonce,
            "https://a.example",
        )
        .await
        .unwrap();

        // The attacker knows the victim's session_id (e.g. read off a log
        // line, since it travels in a URL path) but is not the owning
        // profile -- revocation must be a silent no-op, not a wildcard
        // revoke keyed on the bare id.
        revoke_session(
            &store,
            &AuthenticatedProfileId::for_test(&attacker.profile_id),
            &session.session_id,
        )
        .await
        .expect("revoke is idempotent/no-op for a non-owner, not an error");

        let info = validate_session(&store, &key, &session.session_token, "https://a.example")
            .await
            .expect("a non-owner's revoke attempt must not actually revoke the session");
        assert_eq!(info.profile_id.as_str(), victim.profile_id);

        // The true owner can still revoke it.
        revoke_session(
            &store,
            &AuthenticatedProfileId::for_test(&victim.profile_id),
            &session.session_id,
        )
        .await
        .expect("the owning profile must still be able to revoke its own session");
        let err = validate_session(&store, &key, &session.session_token, "https://a.example")
            .await
            .unwrap_err();
        assert!(matches!(err, ProfileAuthError::SessionRevoked));
    }

    // --- prune: M10 ---

    #[tokio::test]
    async fn prune_expired_removes_stale_rows_and_spares_live_ones() {
        let (_dir, store) = open_store().await;
        let key = data_key_hex();
        let profile = create_profile(&store, &key, "idem-prune-1").await.unwrap();

        // Live, unconsumed, unexpired challenge -- must survive.
        let live_challenge = issue_challenge_for_profile(
            &store,
            &key,
            &AuthenticatedProfileId::for_test(&profile.profile_id),
            CHALLENGE_TYPE_SESSION,
            "https://a.example",
        )
        .await
        .unwrap();

        // Force-expired, never-consumed challenge -- must be pruned.
        let stale_challenge = issue_challenge_for_profile(
            &store,
            &key,
            &AuthenticatedProfileId::for_test(&profile.profile_id),
            CHALLENGE_TYPE_SESSION,
            "https://a.example",
        )
        .await
        .unwrap();
        store
            .write_tx({
                let id = stale_challenge.challenge_id.clone();
                move |tx| {
                    Box::pin(async move {
                        sqlx::query("UPDATE auth_challenges SET expires_at = 0 WHERE id = ?")
                            .bind(&id)
                            .execute(&mut **tx)
                            .await?;
                        Ok::<(), StreamGStoreError>(())
                    })
                }
            })
            .await
            .unwrap();

        // Redeemed (consumed) challenge whose resulting session stays live
        // -- the challenge must be pruned (consumed), the session must not.
        let redeemed_challenge = issue_challenge_for_profile(
            &store,
            &key,
            &AuthenticatedProfileId::for_test(&profile.profile_id),
            CHALLENGE_TYPE_SESSION,
            "https://a.example",
        )
        .await
        .unwrap();
        let live_session = create_session(
            &store,
            &key,
            &redeemed_challenge.challenge_id,
            &redeemed_challenge.nonce,
            "https://a.example",
        )
        .await
        .unwrap();

        // Another redeemed challenge whose resulting session gets revoked
        // -- both the challenge (consumed) and the session (revoked) must
        // be pruned.
        let doomed_challenge = issue_challenge_for_profile(
            &store,
            &key,
            &AuthenticatedProfileId::for_test(&profile.profile_id),
            CHALLENGE_TYPE_SESSION,
            "https://a.example",
        )
        .await
        .unwrap();
        let doomed_session = create_session(
            &store,
            &key,
            &doomed_challenge.challenge_id,
            &doomed_challenge.nonce,
            "https://a.example",
        )
        .await
        .unwrap();
        revoke_session(
            &store,
            &AuthenticatedProfileId::for_test(&profile.profile_id),
            &doomed_session.session_id,
        )
        .await
        .unwrap();

        let counts = prune_expired(&store).await.expect("prune");
        assert_eq!(
            counts.challenges_deleted, 3,
            "the expired challenge plus both consumed (redeemed) challenges must be pruned"
        );
        assert_eq!(
            counts.sessions_deleted, 1,
            "only the revoked session must be pruned"
        );

        assert!(
            challenge_row_exists(&store, &live_challenge.challenge_id).await,
            "unconsumed, unexpired challenge must survive"
        );
        assert!(
            !challenge_row_exists(&store, &stale_challenge.challenge_id).await,
            "expired challenge must be pruned"
        );
        assert!(
            !challenge_row_exists(&store, &redeemed_challenge.challenge_id).await,
            "consumed challenge must be pruned"
        );
        assert!(
            !challenge_row_exists(&store, &doomed_challenge.challenge_id).await,
            "consumed challenge must be pruned"
        );

        assert!(
            session_row_exists(&store, &live_session.session_id).await,
            "live, unrevoked session must survive"
        );
        assert!(
            !session_row_exists(&store, &doomed_session.session_id).await,
            "revoked session must be pruned"
        );
    }

    // ===================================================================
    // Wave B1 — the mounted HTTP routes.
    //
    // ## Which arm every test below is on (the mock-mode question)
    //
    // `runtime::test_support::enabled_map` inherits `GOAT_ATTESTOR_MOCK=1`,
    // so `state.trusted_chain()` and `state.live_chain()` are both `None` in
    // every fixture here — the trap that makes a "the route is mounted"
    // assertion pass against a stub that refuses unconditionally.
    //
    // **These three routes have no chain dependency at all.** `profile_auth`
    // touches only `StreamGStore` and the at-rest data key; there is no
    // `trusted_chain()` / `live_chain()` call anywhere in this module. So
    // there is no no-chain refusal arm to be stuck on: every test below that
    // asserts a 200/204 has run the whole production pipeline — extractor,
    // rate limiter, HMAC index lookup, sealed-payload open, guarded UPDATE —
    // and every refusal is a refusal the store logic actually decided. Each
    // test still carries paired arms regardless, because a route that
    // refuses everything and a route that accepts everything are both
    // indistinguishable from a correct one when only half is checked.
    // ===================================================================

    use crate::stream_g::{router, runtime};
    use axum::body::Body;
    use axum::http::{Method, Request};
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const ORIGIN_A: &str = "https://a.example";
    const ORIGIN_B: &str = "https://b.example";

    async fn route_state(dir: &std::path::Path) -> runtime::StreamGState {
        let mut map = runtime::test_support::enabled_map(dir);
        map.insert("STREAM_G_CORS_ORIGINS".into(), ORIGIN_A.into());
        let cfg = crate::config::load_from_map(&map).expect("stream G config must validate");
        let controller = runtime::ShutdownController::new();
        runtime::StreamGState::start(&cfg, controller.token())
            .await
            .expect("stream G startup")
    }

    /// One request against a cloned app. `content-type: application/json` is
    /// added exactly when a body is sent, so callers never have to remember.
    async fn send(
        app: &Router,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> (StatusCode, String) {
        let mut builder = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let request = match body {
            None => builder.body(Body::empty()).unwrap(),
            Some(json) => builder
                .header("content-type", "application/json")
                .body(Body::from(json.to_string()))
                .unwrap(),
        };
        let res = app.clone().oneshot(request).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// `Authorization` + optional `Origin`, in the shape [`send`] wants.
    fn auth_headers<'a>(
        authorization: &'a str,
        origin: Option<&'a str>,
    ) -> Vec<(&'a str, &'a str)> {
        let mut headers = vec![("authorization", authorization)];
        if let Some(origin) = origin {
            headers.push(("origin", origin));
        }
        headers
    }

    fn origin_headers(origin: Option<&str>) -> Vec<(&str, &str)> {
        match origin {
            Some(origin) => vec![("origin", origin)],
            None => Vec::new(),
        }
    }

    /// The whole ceremony over HTTP: `POST /challenges` with the opaque
    /// credential, then `POST /sessions` with the challenge it returned.
    /// Returns the parsed session document.
    async fn mint_session_over_http(
        app: &Router,
        credential: &str,
        origin: Option<&str>,
    ) -> serde_json::Value {
        let authorization = format!("{AUTH_SCHEME_CREDENTIAL} {credential}");
        let (status, body) = send(
            app,
            Method::POST,
            "/v1/profile/challenges",
            &auth_headers(&authorization, origin),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "challenge issuance failed: {body}");
        let issued: serde_json::Value = serde_json::from_str(&body).unwrap();

        let request = serde_json::json!({
            "challenge_id": issued["challenge_id"],
            "nonce": issued["nonce"],
        })
        .to_string();
        let (status, body) = send(
            app,
            Method::POST,
            "/v1/profile/sessions",
            &origin_headers(origin),
            Some(&request),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "session creation failed: {body}");
        serde_json::from_str(&body).unwrap()
    }

    fn field(document: &serde_json::Value, key: &str) -> String {
        document[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} missing from {document}"))
            .to_string()
    }

    /// **The end-to-end proof that all three routes are real.** Credential →
    /// challenge → session → revoke, entirely over HTTP, with the library
    /// consulted only to create the profile (`POST /v1/profile` is not one of
    /// this wave's three routes) and to observe the session's state
    /// afterwards.
    ///
    /// Every assertion here is on the accepting arm; the refusing arms live
    /// in the tests below. Together they rule out both a route that refuses
    /// everything and a route that accepts everything.
    ///
    /// Mutation this detects (applied, run, reverted): deleting the
    /// `revoke_session(..)` call from `delete_session` so it returns 204
    /// without doing anything — the final `SessionRevoked` assertion fails
    /// while the 204 still arrives, which is exactly the stub this test
    /// exists to catch.
    #[tokio::test]
    async fn the_three_profile_routes_complete_a_real_challenge_session_revoke_ceremony_over_http()
    {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let profile = create_profile(state.store(), state.data_key_hex(), "idem-b1-e2e")
            .await
            .unwrap();

        let session = mint_session_over_http(&app, &profile.credential, Some(ORIGIN_A)).await;
        assert_eq!(
            field(&session, "profile_id"),
            profile.profile_id,
            "the session must be minted for the profile that presented the credential"
        );
        let session_id = field(&session, "session_id");
        let session_token = field(&session, "session_token");
        assert!(
            session["expires_at"].as_i64().is_some(),
            "expires_at must be an integer: {session}"
        );

        // The token the route handed back is a real one: the library
        // primitive accepts it, for the right profile, at the bound origin.
        let info = validate_session(
            state.store(),
            state.data_key_hex(),
            &session_token,
            ORIGIN_A,
        )
        .await
        .expect("the minted token must validate at the origin it was minted for");
        assert_eq!(info.profile_id.as_str(), profile.profile_id);
        assert_eq!(info.session_id, session_id);

        // The session token authenticates the DELETE (the `Bearer` scheme, as
        // distinct from the `Credential` scheme used above).
        let authorization = format!("{AUTH_SCHEME_SESSION} {session_token}");
        let (status, body) = send(
            &app,
            Method::DELETE,
            &format!("/v1/profile/sessions/{session_id}"),
            &auth_headers(&authorization, Some(ORIGIN_A)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        assert!(body.is_empty(), "204 must carry no body: {body}");

        let err = validate_session(
            state.store(),
            state.data_key_hex(),
            &session_token,
            ORIGIN_A,
        )
        .await
        .expect_err("the revoked session must no longer validate");
        assert!(matches!(err, ProfileAuthError::SessionRevoked), "{err}");
    }

    /// **The paired arms the whole wave rests on.** A request with no
    /// credential is refused on every authenticated route, and the identical
    /// request with a valid credential succeeds.
    ///
    /// The refusal is also proven to happen *before* the handler: the DELETE
    /// arm names a real session id, and that session is still valid
    /// afterwards.
    ///
    /// Mutation this detects (applied, run, reverted): making
    /// `presented_credential` return `Ok(PresentedCredential::Credential(String::new()))`
    /// when the header is absent — the refusal then arrives as
    /// `CREDENTIAL_NOT_FOUND` from the store lookup instead of
    /// `MISSING_CREDENTIAL`, and both code assertions fail.
    #[tokio::test]
    async fn a_profile_route_refuses_a_request_with_no_credential_and_accepts_one_with_a_valid_credential(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let profile = create_profile(state.store(), state.data_key_hex(), "idem-b1-nocred")
            .await
            .unwrap();
        let session = mint_session_over_http(&app, &profile.credential, Some(ORIGIN_A)).await;
        let session_id = field(&session, "session_id");
        let session_token = field(&session, "session_token");

        // --- REFUSED: no Authorization header at all. ---
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile/challenges",
            &origin_headers(Some(ORIGIN_A)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_MISSING_CREDENTIAL}\"}}"));

        let (status, body) = send(
            &app,
            Method::DELETE,
            &format!("/v1/profile/sessions/{session_id}"),
            &origin_headers(Some(ORIGIN_A)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_MISSING_CREDENTIAL}\"}}"));

        // An unusable Authorization header is the same refusal: an unknown
        // scheme, and a scheme with no value.
        for header in [
            "Basic dXNlcjpwYXNz",
            "Bearer",
            "Bearer ",
            &format!("Nonsense {session_token}"),
        ] {
            let (status, body) = send(
                &app,
                Method::POST,
                "/v1/profile/challenges",
                &auth_headers(header, Some(ORIGIN_A)),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{header}: {body}");
            assert_eq!(
                body,
                format!("{{\"error\":\"{ERR_MISSING_CREDENTIAL}\"}}"),
                "{header}"
            );
        }

        // The refusals above happened before the handler: nothing was revoked.
        validate_session(
            state.store(),
            state.data_key_hex(),
            &session_token,
            ORIGIN_A,
        )
        .await
        .expect("an uncredentialed DELETE must not have revoked anything");

        // --- ACCEPTED: the same two requests, with a valid credential. ---
        let credential_auth = format!("{AUTH_SCHEME_CREDENTIAL} {}", profile.credential);
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile/challenges",
            &auth_headers(&credential_auth, Some(ORIGIN_A)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("\"challenge_id\""), "{body}");

        let session_auth = format!("{AUTH_SCHEME_SESSION} {session_token}");
        let (status, body) = send(
            &app,
            Method::DELETE,
            &format!("/v1/profile/sessions/{session_id}"),
            &auth_headers(&session_auth, Some(ORIGIN_A)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }

    /// **Origin binding survives the transport.** `validate_session` enforces
    /// `presented_origin` (M7); this proves the route actually hands it the
    /// request's `Origin` header rather than a constant.
    ///
    /// Mutation this detects (applied, run, reverted): making
    /// `presented_origin` ignore the header and always return `NO_ORIGIN` —
    /// mint and validate then agree on `""` for every request, so `ORIGIN_B`
    /// is accepted and the refusal assertion fails. (Note that a mutation
    /// affecting only one side would be caught too, by the accepting arm.)
    #[tokio::test]
    async fn a_session_is_refused_from_an_origin_it_was_not_minted_for() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let profile = create_profile(state.store(), state.data_key_hex(), "idem-b1-origin")
            .await
            .unwrap();
        let session = mint_session_over_http(&app, &profile.credential, Some(ORIGIN_A)).await;
        let session_id = field(&session, "session_id");
        let session_token = field(&session, "session_token");
        let authorization = format!("{AUTH_SCHEME_SESSION} {session_token}");

        // --- REFUSED: a different origin than the session was minted for. ---
        let (status, body) = send(
            &app,
            Method::DELETE,
            &format!("/v1/profile/sessions/{session_id}"),
            &auth_headers(&authorization, Some(ORIGIN_B)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_ORIGIN_MISMATCH}\"}}"));

        // Same on the challenge route — the check is in the extractor, so it
        // is not a property of one handler.
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile/challenges",
            &auth_headers(&authorization, Some(ORIGIN_B)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_ORIGIN_MISMATCH}\"}}"));

        // The refused request revoked nothing.
        validate_session(
            state.store(),
            state.data_key_hex(),
            &session_token,
            ORIGIN_A,
        )
        .await
        .expect("a wrong-origin DELETE must not have revoked the session");

        // --- ACCEPTED: the origin the session was minted for. ---
        let (status, body) = send(
            &app,
            Method::DELETE,
            &format!("/v1/profile/sessions/{session_id}"),
            &auth_headers(&authorization, Some(ORIGIN_A)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }

    /// **The documented absent-`Origin` rule, both directions.** See the
    /// module doc: a missing `Origin` is the distinct value [`NO_ORIGIN`],
    /// never a skipped check.
    ///
    /// Mutation this detects (applied, run, reverted): changing
    /// `presented_origin`'s `None` arm to
    /// `Err(ProfileAuthError::OriginMismatch.into())`, i.e. refusing outright
    /// when the header is absent — the second half (a whole ceremony run
    /// without `Origin`) then fails, which is the behavioural difference
    /// between the two candidate policies.
    #[tokio::test]
    async fn an_absent_origin_header_is_a_distinct_origin_that_never_matches_a_bound_session() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let profile = create_profile(state.store(), state.data_key_hex(), "idem-b1-noorigin")
            .await
            .unwrap();

        // Half 1: a session bound to a real origin is NOT usable by a request
        // that omits the header. Omission is not a bypass.
        let bound = mint_session_over_http(&app, &profile.credential, Some(ORIGIN_A)).await;
        let bound_token = field(&bound, "session_token");
        let bound_auth = format!("{AUTH_SCHEME_SESSION} {bound_token}");
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile/challenges",
            &auth_headers(&bound_auth, None),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_ORIGIN_MISMATCH}\"}}"));

        // Half 2: a non-browser client that never sends `Origin` can still
        // run the whole ceremony, because "no origin" is self-consistent.
        let headless = mint_session_over_http(&app, &profile.credential, None).await;
        let headless_id = field(&headless, "session_id");
        let headless_token = field(&headless, "session_token");
        let headless_auth = format!("{AUTH_SCHEME_SESSION} {headless_token}");

        // Half 3, and it must be asserted *before* the revoke below:
        // `validate_session` checks `revoked_at` ahead of the origin, so a
        // revoked session answers `SESSION_REVOKED` no matter what origin is
        // presented, and this assertion would pass for the wrong reason.
        // A no-origin session is equally unusable from a real origin — the
        // binding runs both ways, it is not "absent means unrestricted".
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile/challenges",
            &auth_headers(&headless_auth, Some(ORIGIN_A)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body, format!("{{\"error\":\"{ERR_ORIGIN_MISMATCH}\"}}"));

        // Accepting arm: the headless client can use its own session, so the
        // refusals above are about the origin and not about a session that
        // never worked.
        let (status, body) = send(
            &app,
            Method::DELETE,
            &format!("/v1/profile/sessions/{headless_id}"),
            &auth_headers(&headless_auth, None),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }

    /// **I6 over HTTP, plus the ownership-oracle rule.** One profile cannot
    /// revoke another's session, and — the part that is easy to get wrong —
    /// it receives a response byte-identical to the owner's success, so it
    /// learns nothing about a session it does not own. Stream G emits no 403
    /// and no 404 here.
    ///
    /// Mutation this detects (applied, run, reverted): dropping
    /// `AND profile_id = ?` from `revoke_session`'s guarded UPDATE — the
    /// attacker's revoke then really revokes, and the "still valid"
    /// assertion fails. (`revoke_session_requires_the_owning_profile_id`
    /// fails alongside it, which is the same defect seen from the library
    /// side; this test is what proves the route did not re-open it.)
    #[tokio::test]
    async fn one_profile_cannot_revoke_another_profiles_session_and_cannot_tell_that_it_failed() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let victim = create_profile(state.store(), state.data_key_hex(), "idem-b1-victim")
            .await
            .unwrap();
        let attacker = create_profile(state.store(), state.data_key_hex(), "idem-b1-attacker")
            .await
            .unwrap();

        let victim_session = mint_session_over_http(&app, &victim.credential, Some(ORIGIN_A)).await;
        let victim_session_id = field(&victim_session, "session_id");
        let victim_token = field(&victim_session, "session_token");

        let attacker_session =
            mint_session_over_http(&app, &attacker.credential, Some(ORIGIN_A)).await;
        let attacker_token = field(&attacker_session, "session_token");
        let attacker_auth = format!("{AUTH_SCHEME_SESSION} {attacker_token}");

        // The attacker authenticates perfectly well as *itself* and names the
        // victim's session id (not a secret — it travels in a URL path).
        let attacker_response = send(
            &app,
            Method::DELETE,
            &format!("/v1/profile/sessions/{victim_session_id}"),
            &auth_headers(&attacker_auth, Some(ORIGIN_A)),
            None,
        )
        .await;
        assert_eq!(attacker_response.0, StatusCode::NO_CONTENT);

        // Nothing happened.
        let info = validate_session(state.store(), state.data_key_hex(), &victim_token, ORIGIN_A)
            .await
            .expect("a foreign profile must not be able to revoke this session");
        assert_eq!(info.profile_id.as_str(), victim.profile_id);

        // The owner does the same request and succeeds — and the two
        // responses are indistinguishable.
        let victim_auth = format!("{AUTH_SCHEME_SESSION} {victim_token}");
        let owner_response = send(
            &app,
            Method::DELETE,
            &format!("/v1/profile/sessions/{victim_session_id}"),
            &auth_headers(&victim_auth, Some(ORIGIN_A)),
            None,
        )
        .await;
        assert_eq!(owner_response.0, StatusCode::NO_CONTENT);
        assert_eq!(
            attacker_response, owner_response,
            "a non-owner's revoke must be answered exactly as the owner's is, \
             or the status/body is an ownership oracle"
        );

        let err = validate_session(state.store(), state.data_key_hex(), &victim_token, ORIGIN_A)
            .await
            .expect_err("the owner's revoke must actually revoke");
        assert!(matches!(err, ProfileAuthError::SessionRevoked), "{err}");
    }

    /// **The path parameter really binds — the single most likely silent
    /// break in this wave.**
    ///
    /// axum 0.7 / matchit 0.7 treat `{` and `}` as ordinary path characters,
    /// so `"/v1/profile/sessions/{id}"` compiles, does not panic, and matches
    /// only the literal segment `{id}`; every real request 404s. The existing
    /// `stream_g_paths_never_fall_back_onto_the_pilot_relayer` would *confirm*
    /// that breakage rather than catch it, because it asserts unknown paths
    /// 404.
    ///
    /// Two sessions of the **same** profile are used deliberately: the DELETE
    /// is authenticated with session B's token while naming session A's id.
    /// A handler that revoked "the session you authenticated with", or that
    /// ignored the path segment and revoked everything, kills the wrong row
    /// and fails here.
    ///
    /// Mutations this detects (each applied alone, run, reverted):
    /// 1. `"/v1/profile/sessions/:id"` → `"/v1/profile/sessions/{id}"` in
    ///    `super::router` — the DELETE 404s and the first assertion fails.
    /// 2. `delete_session` revoking `caller`'s own session id instead of the
    ///    `Path` one — session B dies, session A lives, both assertions fail.
    #[tokio::test]
    async fn the_delete_route_binds_the_session_id_from_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let profile = create_profile(state.store(), state.data_key_hex(), "idem-b1-path")
            .await
            .unwrap();
        let session_a = mint_session_over_http(&app, &profile.credential, Some(ORIGIN_A)).await;
        let session_b = mint_session_over_http(&app, &profile.credential, Some(ORIGIN_A)).await;
        let a_id = field(&session_a, "session_id");
        let a_token = field(&session_a, "session_token");
        let b_id = field(&session_b, "session_id");
        let b_token = field(&session_b, "session_token");
        assert_ne!(a_id, b_id, "two distinct sessions are required");

        let b_auth = format!("{AUTH_SCHEME_SESSION} {b_token}");

        // An id nobody owns: 204 (the oracle rule) and nothing is touched.
        let (status, _) = send(
            &app,
            Method::DELETE,
            "/v1/profile/sessions/0000000000000000000000000000000000000000",
            &auth_headers(&b_auth, Some(ORIGIN_A)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        validate_session(state.store(), state.data_key_hex(), &a_token, ORIGIN_A)
            .await
            .expect("an unknown id must revoke nothing");
        validate_session(state.store(), state.data_key_hex(), &b_token, ORIGIN_A)
            .await
            .expect("an unknown id must revoke nothing");

        // Now the real id — authenticated as B, naming A.
        let (status, body) = send(
            &app,
            Method::DELETE,
            &format!("/v1/profile/sessions/{a_id}"),
            &auth_headers(&b_auth, Some(ORIGIN_A)),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "a DELETE to a real session id must reach the handler (a `{{id}}` route would 404): \
             {body}"
        );

        let err = validate_session(state.store(), state.data_key_hex(), &a_token, ORIGIN_A)
            .await
            .expect_err("the session named in the path must be the one revoked");
        assert!(matches!(err, ProfileAuthError::SessionRevoked), "{err}");
        validate_session(state.store(), state.data_key_hex(), &b_token, ORIGIN_A)
            .await
            .expect("the authenticating session must NOT have been revoked");
    }

    /// Every refusal these routes can produce lands in the shared
    /// `http_error` envelope — `{"error":"CODE"}` and nothing else — and no
    /// caller-supplied byte is echoed back.
    ///
    /// Mutation this detects (applied, run, reverted): changing
    /// `post_session`'s extractor from `ApiJson<CreateSessionRequest>` to
    /// bare `Json<CreateSessionRequest>` — the malformed-JSON and
    /// unknown-shape arms then answer with axum's `text/plain` default and
    /// the body assertions fail.
    #[tokio::test]
    async fn profile_route_errors_use_the_shared_envelope_and_carry_no_internal_detail() {
        const MARKER: &str = "LEAKMARKERB1";

        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let profile = create_profile(state.store(), state.data_key_hex(), "idem-b1-envelope")
            .await
            .unwrap();

        // (a) An unrecognized session token.
        let bogus = format!("{AUTH_SCHEME_SESSION} {MARKER}");
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile/challenges",
            &auth_headers(&bogus, Some(ORIGIN_A)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_SESSION_NOT_FOUND}\"}}"));
        assert!(!body.contains(MARKER), "{body}");

        // (b) An unrecognized credential.
        let bogus = format!("{AUTH_SCHEME_CREDENTIAL} {MARKER}");
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile/challenges",
            &auth_headers(&bogus, Some(ORIGIN_A)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            body,
            format!("{{\"error\":\"{ERR_CREDENTIAL_NOT_FOUND}\"}}")
        );
        assert!(!body.contains(MARKER), "{body}");

        // (c) A real challenge redeemed with the wrong nonce.
        let credential_auth = format!("{AUTH_SCHEME_CREDENTIAL} {}", profile.credential);
        let (_, body) = send(
            &app,
            Method::POST,
            "/v1/profile/challenges",
            &auth_headers(&credential_auth, Some(ORIGIN_A)),
            None,
        )
        .await;
        let issued: serde_json::Value = serde_json::from_str(&body).unwrap();
        let challenge_id = field(&issued, "challenge_id");
        let real_nonce = field(&issued, "nonce");

        let wrong =
            serde_json::json!({ "challenge_id": challenge_id, "nonce": MARKER }).to_string();
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile/sessions",
            &origin_headers(Some(ORIGIN_A)),
            Some(&wrong),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, format!("{{\"error\":\"{ERR_NONCE_MISMATCH}\"}}"));
        assert!(!body.contains(MARKER), "{body}");
        assert!(!body.contains(&challenge_id), "{body}");

        // (d) Not JSON at all — the extractor rejection must use the same
        // envelope, which is why the route takes `ApiJson`.
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile/sessions",
            &origin_headers(Some(ORIGIN_A)),
            Some(&format!("{{not json {MARKER}")),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body,
            format!(
                "{{\"error\":\"{}\"}}",
                crate::stream_g::http_error::ERR_INVALID_JSON
            )
        );
        assert!(!body.contains(MARKER), "{body}");

        // Paired non-zero arm: the wrong nonce did not burn the challenge, so
        // the *right* nonce still redeems. Without this, every assertion
        // above would pass equally well against a route that refuses
        // everything.
        let right =
            serde_json::json!({ "challenge_id": challenge_id, "nonce": real_nonce }).to_string();
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile/sessions",
            &origin_headers(Some(ORIGIN_A)),
            Some(&right),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// snake_case on the wire, in **both** directions, plus
    /// `deny_unknown_fields` — the founder ruling every Stream G DTO follows
    /// (`super::tests::stream_g_wire_dtos_are_snake_case` pins the readiness
    /// and metrics documents; this pins the profile routes').
    ///
    /// Mutations this detects (each applied alone, run, reverted):
    /// 1. adding `#[serde(rename_all = "camelCase")]` to
    ///    `CreateSessionRequest` — the snake_case body is then rejected and
    ///    the accepting arm fails.
    /// 2. deleting `#[serde(deny_unknown_fields)]` from
    ///    `CreateSessionRequest` — the extra-key body is then accepted (200)
    ///    and that assertion fails.
    #[tokio::test]
    async fn profile_route_wire_dtos_are_snake_case_and_reject_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let profile = create_profile(state.store(), state.data_key_hex(), "idem-b1-snake")
            .await
            .unwrap();
        let credential_auth = format!("{AUTH_SCHEME_CREDENTIAL} {}", profile.credential);

        // Response shape: the challenge document.
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile/challenges",
            &auth_headers(&credential_auth, Some(ORIGIN_A)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("\"challenge_id\""), "{body}");
        assert!(body.contains("\"expires_at\""), "{body}");
        assert!(!body.contains("challengeId"), "{body}");
        assert!(!body.contains("expiresAt"), "{body}");
        let issued: serde_json::Value = serde_json::from_str(&body).unwrap();
        let challenge_id = field(&issued, "challenge_id");
        let nonce = field(&issued, "nonce");

        // Request shape, refused arm 1: camelCase keys.
        let camel =
            serde_json::json!({ "challengeId": challenge_id, "nonce": nonce.clone() }).to_string();
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile/sessions",
            &origin_headers(Some(ORIGIN_A)),
            Some(&camel),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body,
            format!(
                "{{\"error\":\"{}\"}}",
                crate::stream_g::http_error::ERR_INVALID_REQUEST_SHAPE
            )
        );

        // Request shape, refused arm 2: every correct field plus one extra.
        let extra = serde_json::json!({
            "challenge_id": challenge_id,
            "nonce": nonce.clone(),
            "profile_id": profile.profile_id,
        })
        .to_string();
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile/sessions",
            &origin_headers(Some(ORIGIN_A)),
            Some(&extra),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "deny_unknown_fields must refuse a body that names an extra key — and this key in \
             particular, because a caller must never be able to name a profile_id: {body}"
        );
        assert_eq!(
            body,
            format!(
                "{{\"error\":\"{}\"}}",
                crate::stream_g::http_error::ERR_INVALID_REQUEST_SHAPE
            )
        );

        // Accepted arm: snake_case, exactly the declared fields. The refusals
        // above are about the shape, not about a route that refuses
        // everything — and the challenge survived both, proving neither
        // rejected body reached `create_session`.
        let good = serde_json::json!({ "challenge_id": challenge_id, "nonce": nonce }).to_string();
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile/sessions",
            &origin_headers(Some(ORIGIN_A)),
            Some(&good),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("\"session_id\""), "{body}");
        assert!(body.contains("\"session_token\""), "{body}");
        assert!(body.contains("\"profile_id\""), "{body}");
        assert!(body.contains("\"expires_at\""), "{body}");
        assert!(!body.contains("sessionId"), "{body}");
        assert!(!body.contains("sessionToken"), "{body}");
        assert!(!body.contains("profileId"), "{body}");
    }

    // ===================================================================
    // `POST /v1/profile` — the unauthenticated registration route.
    //
    // Same mock-mode note as the block above: `profile_auth` makes no
    // `trusted_chain()` / `live_chain()` call, so every 200 below is the real
    // store pipeline and not a no-chain stub.
    // ===================================================================

    fn create_profile_body(idempotency_key: &str) -> String {
        serde_json::json!({ "idempotency_key": idempotency_key }).to_string()
    }

    /// **The route takes no credential — and the credential it hands back is a
    /// real one.**
    ///
    /// The second half is what makes this more than "a 200 arrived": the
    /// returned value is fed straight back through the *other* mounted routes,
    /// so a handler that invented a plausible-looking string, or returned some
    /// other profile's, fails here rather than passing silently.
    ///
    /// Mutations this detects (each applied alone, run, reverted):
    /// 1. adding an `AuthenticatedProfile` extractor to `post_profile` — the
    ///    uncredentialed POST then 401s and the first assertion fails.
    /// 2. `post_profile` returning `CreateProfileOutcome { profile_id,
    ///    credential: random_hex(32) }` (a fresh secret rather than the one
    ///    `create_profile` registered) — the 200 still arrives, and the
    ///    challenge request with that credential fails.
    #[tokio::test]
    async fn profile_creation_needs_no_credential_and_returns_one_that_authenticates() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        // No `authorization` header anywhere in this request.
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile",
            &origin_headers(Some(ORIGIN_A)),
            Some(&create_profile_body("idem-a1-open")),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "registration must not require a credential — it is where credentials come from: \
             {body}"
        );

        let created: serde_json::Value = serde_json::from_str(&body).unwrap();
        let profile_id = field(&created, "profile_id");
        let credential = field(&created, "credential");
        assert!(!credential.is_empty(), "{body}");
        assert_ne!(
            credential, profile_id,
            "the credential must not be the (publicly returned) profile id"
        );
        // snake_case on the wire, like every other Stream G DTO.
        assert!(body.contains("\"profile_id\""), "{body}");
        assert!(!body.contains("profileId"), "{body}");

        // The credential is real: it authenticates the challenge route, for
        // this profile, and redeems into a session.
        let session = mint_session_over_http(&app, &credential, Some(ORIGIN_A)).await;
        assert_eq!(
            field(&session, "profile_id"),
            profile_id,
            "the credential the route returned must belong to the profile it named"
        );

        // And the library agrees the row exists under that id.
        let resolved = authenticate_credential(state.store(), state.data_key_hex(), &credential)
            .await
            .expect("the returned credential must resolve to a profile");
        assert_eq!(resolved.as_str(), profile_id);
    }

    /// **A replayer never receives a credential.** The idempotency-key
    /// collision path is `IdempotencyKeyConflict` → 409, and the shared
    /// envelope has nowhere to put a secret.
    ///
    /// This is the I2 decision enforced at the transport: a second `Ok` that
    /// merely omitted the credential would let whoever guessed the key learn
    /// that the key is taken *and* adopt the resulting `profile_id`; a 409 with
    /// a code and nothing else discloses neither.
    ///
    /// Mutations this detects (each applied alone, run, reverted):
    /// 1. `create_profile` returning `Ok` with the existing row on collision —
    ///    the replay then answers 200 and the status assertion fails.
    /// 2. widening `ApiErrorBody` to carry the originating `Display` — the
    ///    conflict body then stops being exactly `{"error":"…"}`.
    #[tokio::test]
    async fn profile_creation_discloses_a_credential_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        let (status, first) = send(
            &app,
            Method::POST,
            "/v1/profile",
            &origin_headers(Some(ORIGIN_A)),
            Some(&create_profile_body("idem-a1-replay")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{first}");
        let created: serde_json::Value = serde_json::from_str(&first).unwrap();
        let credential = field(&created, "credential");
        let profile_id = field(&created, "profile_id");

        // The identical request again — a client retry and a stranger who
        // guessed the key are indistinguishable, which is precisely why this
        // cannot be an `Ok`.
        let (status, replay) = send(
            &app,
            Method::POST,
            "/v1/profile",
            &origin_headers(Some(ORIGIN_A)),
            Some(&create_profile_body("idem-a1-replay")),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            replay,
            format!("{{\"error\":\"{ERR_IDEMPOTENCY_KEY_CONFLICT}\"}}")
        );
        assert!(
            !replay.contains(&credential),
            "the replay disclosed the first caller's credential: {replay}"
        );
        assert!(
            !replay.contains("credential"),
            "the replay body must not carry a credential field at all: {replay}"
        );
        assert!(
            !replay.contains(&profile_id),
            "the replay disclosed the profile the key already owns: {replay}"
        );

        // Paired non-zero arm: a *different* key still succeeds, so the 409
        // above is about the collision and not a route that refuses
        // everything.
        let (status, other) = send(
            &app,
            Method::POST,
            "/v1/profile",
            &origin_headers(Some(ORIGIN_A)),
            Some(&create_profile_body("idem-a1-replay-other")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{other}");
        assert_ne!(
            field(&serde_json::from_str(&other).unwrap(), "credential"),
            credential
        );
    }

    /// **The registering route is rate limited.** It has no per-profile bucket
    /// available (no profile exists yet), so the registration bucket is the
    /// entire perimeter for this route and must actually be consulted. "The
    /// unauthenticated route" would be the wrong phrase: `GET
    /// /v1/stream-g/ready` and `GET /v1/stream-g/metrics` are uncredentialed
    /// too and have no bucket at all (`rate_limit`'s "Nothing else is
    /// rate-limited"). This test covers `POST /v1/profile` only.
    ///
    /// The bucket is drained through the limiter directly rather than by
    /// sending [`super::rate_limit::STREAM_G_REGISTRATION_PER_MIN`] real
    /// requests: the state's limiter is the same value the router holds, and
    /// the extra store writes would buy nothing this does not already prove.
    ///
    /// Mutation this detects (applied, run, reverted): deleting the
    /// `_rate_limit: RegistrationRateLimit` parameter from `post_profile` — the
    /// drained-bucket request then answers 200 and registration is unbounded.
    #[tokio::test]
    async fn profile_creation_spends_a_registration_rate_limit_token() {
        use crate::stream_g::rate_limit::ERR_RATE_LIMITED_REGISTRATION;

        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        // Accepting arm first, with the bucket full.
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile",
            &origin_headers(Some(ORIGIN_A)),
            Some(&create_profile_body("idem-a1-rl-open")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // Drain every remaining registration token.
        {
            let mut limiter = state
                .rate_limiter()
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            while limiter.check_registration(Instant::now()).is_ok() {}
        }

        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile",
            &origin_headers(Some(ORIGIN_A)),
            Some(&create_profile_body("idem-a1-rl-refused")),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "an unauthenticated registration route with no bound is an open faucet: {body}"
        );
        assert_eq!(
            body,
            format!("{{\"error\":\"{ERR_RATE_LIMITED_REGISTRATION}\"}}")
        );

        // The refusal happened before the handler: the idempotency key it
        // named is still free, so nothing was written.
        create_profile(state.store(), state.data_key_hex(), "idem-a1-rl-refused")
            .await
            .expect("a rate-limited request must not have created a profile");
    }

    /// **The starvation channel, at the route level.**
    ///
    /// `POST /v1/profile` is unauthenticated, and while it spent a *global*
    /// token, emptying that bucket refused every authenticated route too — the
    /// spend happens inside `AuthenticatedProfile` → `PresentedOrigin` →
    /// [`GlobalRateLimit`], **before** the credential is read, so presenting a
    /// valid one could not help. One client at ~2 req/s was enough to take the
    /// whole authenticated surface offline.
    ///
    /// This drains the registration budget the way an attacker would — through
    /// the real route, until it refuses — and then asserts an authenticated
    /// route still answers. `POST /v1/profile/challenges` is the authenticated
    /// route used because it needs no chain (`state.trusted_chain()` is `None`
    /// under `GOAT_ATTESTOR_MOCK=1`), so its 200 is a real answer.
    ///
    /// Mutation this detects (applied, run, reverted): changing
    /// `post_profile`'s parameter back to `_rate_limit: GlobalRateLimit`. The
    /// flood then drains the *global* bucket instead, and the loop's inner
    /// assertion fails with `RATE_LIMITED_GLOBAL` where
    /// `RATE_LIMITED_REGISTRATION` was expected — i.e. the test names the
    /// defect (registration is spending the shared budget) rather than merely
    /// going red. That is why the loop is bounded by
    /// [`STREAM_G_GLOBAL_PER_MIN`](super::rate_limit::STREAM_G_GLOBAL_PER_MIN)
    /// and not by the registration figure: a tighter bound would exit before
    /// the mutated build refused anything, and the failure would point at the
    /// loop instead of at the budget.
    #[tokio::test]
    async fn exhausting_registration_does_not_429_an_authenticated_route() {
        use crate::stream_g::rate_limit::{ERR_RATE_LIMITED_REGISTRATION, STREAM_G_GLOBAL_PER_MIN};

        let dir = tempfile::tempdir().unwrap();
        let state = route_state(dir.path()).await;
        let app = router(state.clone());

        // A legitimate caller who registered before the flood and holds a
        // valid credential.
        let victim = create_profile(state.store(), state.data_key_hex(), "idem-a1-starve-victim")
            .await
            .expect("create the victim profile");
        let victim_auth = format!("{AUTH_SCHEME_CREDENTIAL} {}", victim.credential);

        // Paired arm before the flood: the authenticated route works.
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile/challenges",
            &auth_headers(&victim_auth, Some(ORIGIN_A)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // The flood: hammer the unauthenticated route until it refuses.
        let mut refused = false;
        for i in 0..=STREAM_G_GLOBAL_PER_MIN {
            let (status, body) = send(
                &app,
                Method::POST,
                "/v1/profile",
                &origin_headers(Some(ORIGIN_A)),
                Some(&create_profile_body(&format!("idem-a1-starve-{i}"))),
            )
            .await;
            if status == StatusCode::TOO_MANY_REQUESTS {
                assert_eq!(
                    body,
                    format!("{{\"error\":\"{ERR_RATE_LIMITED_REGISTRATION}\"}}"),
                    "the flood must be refused by the registration budget, not another one"
                );
                refused = true;
                break;
            }
            assert_eq!(status, StatusCode::OK, "{body}");
        }
        assert!(
            refused,
            "the registration budget never refused, so the drain below proves nothing"
        );

        // The point: the authenticated caller is unaffected.
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/profile/challenges",
            &auth_headers(&victim_auth, Some(ORIGIN_A)),
            None,
        )
        .await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "unauthenticated registration traffic starved an authenticated route: {body}"
        );
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}
