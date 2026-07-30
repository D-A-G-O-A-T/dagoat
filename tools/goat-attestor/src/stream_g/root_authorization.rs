//! Issuer-signed RootAuthorization: nonce reservation strictly before
//! signing (brief 5.6) -- Stream G.
//!
//! ## CORRECTED: this typehash/domain matches the deployed contract
//!
//! An earlier version of this module defined its own unverified
//! `RootAuthorization` struct/typehash, with a doc comment claiming "no
//! on-chain contract in this tree defines a RootAuthorization ABI/typehash".
//! **That grep was simply wrong**, not the string itself unverifiable --
//! see `contracts/src/StreamGTypes.sol` (`ROOT_AUTHORIZATION_TYPEHASH`) and
//! `contracts/src/WalletSponsorshipRegistry.sol` (`EIP712("GoatWalletSponsorship",
//! "1")`, `_hashRootAuthorization`, `registerPrimary`). Every field below is
//! pinned against those two files (see
//! [`ROOT_AUTHORIZATION_TYPEHASH_STR`] and [`root_authorization_digest`]),
//! and [`root_authorization_typehash_matches_streamg_types_sol`] pins the
//! typehash string byte-for-byte so any future drift between this module
//! and the Solidity source fails loudly.
//!
//! Ground truth, in full:
//! - Domain: name `"GoatWalletSponsorship"`, version `"1"`, `chainId` and
//!   `verifyingContract` = the `WalletSponsorshipRegistry` address.
//!   `chainId` lives in the EIP-712 *domain*, not the struct.
//! - Struct (six fields, this exact order): `root` (address),
//!   `secondary` (address), `enrollDigest` (bytes32), `linkDigest`
//!   (bytes32), `nonce` (uint256), `deadline` (uint48, right-aligned in a
//!   32-byte word like any other uint).
//! - `registerPrimary` (the only entry point this module's output is for)
//!   requires the *standalone root registration* shape: `root !=
//!   address(0)` (`WalletSponsorshipRegistry.sol:159` reverts
//!   `ZeroAddress()`), `secondary == address(0)` AND `linkDigest ==
//!   bytes32(0)`, `enrollDigest != bytes32(0)`, and `nonce ==
//!   rootRegistrationNonces[root]` (a per-root counter starting at 0,
//!   advanced by exactly 1 per successful registration). This module
//!   validates and enforces every one of those shape constraints
//!   server-side before ever calling the issuer key -- see
//!   `RootAuthorizationError::ZeroRoot` / `NonStandaloneSecondary` /
//!   `NonStandaloneLinkDigest` / `ZeroEnrollDigest` -- so it can never emit
//!   a signature the contract will certainly reject.
//!
//! ## Ordering (the actual requirement, brief 5.6)
//!
//! `create_root_authorization` reserves the root-registration nonce as a
//! real row insert into `nonce_allocations`, *then*, still inside the same
//! `write_tx`, parses the issuer key and produces the EIP-712 signature.
//! Both steps live in one transaction: if key-parsing or signing fails,
//! returning `Err` from the closure rolls the *whole* transaction back --
//! including the nonce reservation insert. A `#[cfg(test)]` fault-injection
//! hook (`test_hooks`) lets a test observe, via a side channel outside the
//! transaction, that the reservation INSERT genuinely executed
//! (`rows_affected() == 1`) strictly before the injected failure aborts --
//! see `root_authorization_reservation_genuinely_executes_before_signing`.
//! The original ordering test only asserted "both tables end up empty",
//! which passes even if reservation were accidentally moved *after*
//! signing (both would still roll back together); the side channel is what
//! actually distinguishes "reserved, then rolled back" from "never
//! reserved".
//!
//! ## Idempotency vs. conflict (fix for a Critical defect)
//!
//! An earlier version derived `reservation_id`, `authorization_id` *and*
//! the nonce **value** purely from `(profile_id, idempotency_key)`, and
//! never checked `rows_affected()` on either `INSERT OR IGNORE`. That let a
//! second call with the *same* idempotency key but a *different* body
//! (different wallet, different deadline, ...) collide on the primary key,
//! get silently ignored, and then fall through to the signer anyway --
//! producing a live issuer signature for a payload with no reservation row
//! and no audit row anywhere.
//!
//! The fix has two parts:
//!
//! 1. **Every `INSERT OR IGNORE` binds its `rows_affected()` and never
//!    falls through to the signer on an ignored insert.** This alone closes
//!    the "signs after a silently-ignored write" hole.
//! 2. **A hash of the full canonical signed body is folded into the
//!    persisted record**, and used to distinguish a true replay from a
//!    conflicting one. Concretely: `authorizations.signature_enc`'s sealed
//!    JSON payload carries `body_hash` = `sha256("root|secondary|enrollDigest|
//!    linkDigest|deadline|chainId|verifyingContract|intentId")`. Before
//!    reserving anything, `create_root_authorization` looks up the
//!    `authorizations` row for this `(profile_id, idempotency_key)` first:
//!    if found, it opens the envelope and compares the stored `body_hash`
//!    (plus `intent_id`/`profile_id`) against the current request. Equal ->
//!    true replay -> return the **stored** signature/nonce, no new DB
//!    writes, no new signing call. Different -> typed
//!    `IdempotencyKeyConflict` (`IDEMPOTENCY_KEY_CONFLICT`), and nothing is
//!    reserved or signed.
//!
//!    Note on why the body hash is folded into the *stored payload* rather
//!    than literally concatenated into the SQL primary key text: folding it
//!    into the key itself would make a *conflicting* replay (same key,
//!    different body) produce a **different** id, which would never
//!    collide on the primary key at all -- defeating detection rather than
//!    enabling it. Comparing the stored body hash against the incoming
//!    request (after a lookup keyed on `(profile_id, idempotency_key)`
//!    alone) is what actually lets a conflicting replay be recognized and
//!    rejected before any signature is produced. `nonce_allocations` has no
//!    spare column to carry a body hash at all (id, chain_id,
//!    signer_address, nonce, status, allocated_at, released_at only), which
//!    is the other reason the comparison lives on the `authorizations` side:
//!    the upfront lookup there gates whether `nonce_allocations` is ever
//!    touched for this call, so a conflicting replay never reaches
//!    reservation, let alone signing. `reservation_id` keeps its original,
//!    unchanged `(profile_id, idempotency_key)`-only derivation (matching
//!    the "keep the deterministic row id for idempotency" instruction for
//!    the nonce row); `rows_affected()` on its insert is still checked as a
//!    defense-in-depth invariant check, not as the primary conflict path.
//!
//! ## Nonce semantics (fix for an Important defect)
//!
//! An earlier version derived the *nonce value* itself from
//! `keccak256("root-authorization-nonce|{profile_id}|{idempotency_key}")` --
//! a pseudo-random 63-bit integer with no relationship whatsoever to
//! `WalletSponsorshipRegistry.rootRegistrationNonces[root]`, the actual
//! on-chain per-root counter (`registerPrimary` reverts with
//! `InvalidRootAuthorization` unless `auth.nonce == rootRegistrationNonces[root]`,
//! and that counter starts at 0 and advances by exactly 1 per successful
//! registration).
//!
//! **There is no RPC/chain client wired into `stream_g` yet** -- that
//! arrives in Task 5/6. So this module cannot read
//! `rootRegistrationNonces` on-chain, and does not pretend to: it
//! implements a per-`(chain_id, root)` **monotonic local allocator**,
//! reserved inside the same `write_tx` as everything else, via
//! `SELECT COALESCE(MAX(nonce), -1) + 1 FROM nonce_allocations WHERE
//! chain_id = ? AND signer_address = ?` -- which yields `0` for a
//! never-before-seen root (pinned by
//! `root_authorization_nonce_is_zero_for_first_time_root`) and increments
//! by exactly 1 per new reservation for that root thereafter. This is a
//! **local sequence, not a verified mirror of chain state**, and it
//! diverges far more easily than "a root registered through another
//! channel, or the database reset" suggests (that framing understated the
//! defect under this repo's "claims ≤ code" honesty rule). `MAX(nonce)+1`
//! here advances on every authorization this module *issues*, while
//! `rootRegistrationNonces[root]` on-chain advances only on every
//! authorization actually *redeemed*. A single abandoned or TTL-expired
//! request (15-minute deadline cap, `ROOT_AUTHORIZATION_TTL_SECONDS`) -- or
//! even an honest client retry under a fresh idempotency key -- is enough
//! to desynchronize the two counters for that root through this module
//! alone: divergence begins at the first *unredeemed* authorization, not
//! only at some out-of-band registration or a database reset. After that,
//! every subsequent authorization this module issues for that root is
//! unredeemable on-chain (fail-closed: the chain simply reverts, no funds
//! move); the module's own
//! `root_authorization_nonce_increments_per_root_across_idempotency_keys`
//! test enshrines this by asserting the second request for the same root
//! gets nonce 1 regardless of whether the first was ever redeemed.
//! **Reconciling this allocator against the live `rootRegistrationNonces(root)`
//! value is an explicit Task 5/6 dependency** once the RPC client exists;
//! this module does not fake that read. That deferral stands and is not
//! being re-litigated here.
//!
//! One consequence in the meantime: `nonce_allocations`'s own `UNIQUE
//! (chain_id, signer_address, nonce)` constraint (schema-frozen) never
//! actually fires through this module, because `MAX(nonce)+1` never
//! reproduces a value already allocated for that root -- so a second
//! *live* (unredeemed) authorization for one root is never detected by
//! this module. I1's original rationale for that index is not yet
//! realized; it will only start firing once Task 5/6 wires the constraint
//! into a chain-state-aware reservation path.
//!
//! On replay of an already-reserved `(profile_id, idempotency_key)`, the
//! nonce value is **not** recomputed -- it is read back from the stored
//! `authorizations` row (see above), never re-derived.
//!
//! ## Deadline: uint48 range + server-side TTL clamp (I5)
//!
//! `deadline` is `uint48` on-chain (`registerPrimary` reverts with
//! `ExpiredSignature` once `block.timestamp >= auth.deadline`, and that is
//! the *only* expiry an issuer signature has -- there is no revocation path
//! for an unspent authorization short of the nonce being consumed). Two
//! independent checks run before signing:
//! 1. **Structural**: `deadline <= 2^48 - 1`, or `DeadlineExceedsUint48`.
//! 2. **Policy**: `deadline <= now + ROOT_AUTHORIZATION_TTL_SECONDS`
//!    (15 minutes, a named constant), or `DeadlineExceedsPolicy`. Without
//!    this, a caller could request a `uint48::MAX` deadline (year ~10889)
//!    and receive a bearer credential that authorizes registering a root
//!    essentially forever with no way to revoke it.
//!
//! `chain_id` and `verifying_contract` are **not** request fields at all --
//! see [`IssuerSigningContext`] below. A caller cannot name the EIP-712
//! domain the issuer key signs in; that is resolved entirely from
//! configuration.
//!
//! ## `IssuerSigningContext` (I5): the domain and the key come from
//! configuration, never from a request body
//!
//! `chain_id`, `verifying_contract` and the issuer private key used to live
//! partly in the request struct and partly as a separate loose function
//! parameter. Both are now a single [`IssuerSigningContext`] that the
//! *caller* (Task 8) constructs from `StreamGConfig::issuer_private_key`
//! plus the deployment manifest's `WalletSponsorshipRegistry` address and
//! the configured chain id -- never deserialized from a request body. This
//! makes "a request cannot name the domain the issuer signs in" a property
//! of the function signature, not a convention Task 8 has to remember.
//!
//! ## Coupling to `intents` (schema-frozen)
//!
//! The only encrypted payload column this schema gives an authorization a
//! home in is `authorizations.signature_enc`, and `authorizations.intent_id`
//! is `NOT NULL REFERENCES intents(id)`. This module therefore takes an
//! `intent_id` as an input (assumed to already exist -- typically an
//! `onboarding.rs` intent row) rather than creating one itself; this file
//! never writes to `intents`.
//!
//! Self-contained like `onboarding.rs` / `profile_auth.rs`: its own tiny
//! `now_unix_seconds` / `deterministic_id`, not shared across files. The
//! one deliberate exception is `profile_auth::AuthenticatedProfileId`,
//! imported via `super::profile_auth::AuthenticatedProfileId` -- see below.
//!
//! ## I3 fix: `profile_id` is proven, never merely asserted
//!
//! `CreateRootAuthorizationRequest` used to have a `pub profile_id: String`
//! field -- an unauthenticated client could name any profile in the JSON
//! body, exactly the defect this task's I3 finding is about (see
//! `profile_auth`'s module doc for the full writeup). That field is now
//! gone; [`create_root_authorization`] instead takes a separate
//! `&profile_auth::AuthenticatedProfileId` parameter, obtainable only from
//! `profile_auth::authenticate_credential` or
//! `profile_auth::validate_session`. Every other use of "the profile" in
//! this module -- the `reservation_id`/`authorization_id` derivation, the
//! `authorizations.profile_id` column, the replay/conflict check -- reads
//! `profile.as_str()` instead of a request field. This makes it impossible
//! for two different (correctly authenticated) profiles using the *same*
//! idempotency key to collide, adopt, or read back each other's
//! authorization -- see
//! `create_root_authorization_scopes_idempotency_by_the_authenticated_profile`.
//!
//! **Important-2 fix (round 2).** This module *does* now verify that
//! `req.intent_id` belongs to `profile`, inside the same `write_tx`, before
//! step (0) below: `SELECT profile_id FROM intents WHERE id = ?`; `None`
//! and a mismatched owner both map to
//! [`RootAuthorizationError::IntentNotFound`] rather than a distinguishable
//! "wrong owner", so the endpoint cannot be used to probe whether a given
//! `intent_id` exists. An earlier version of this module argued the check
//! was out of scope for I3 because the signed EIP-712 payload does not
//! depend on `intent_id` -- true, but the wrong test: signature-safety is
//! not the property at risk here. `authorizations.intent_id` and
//! `authorizations.profile_id` are both foreign keys, and without this
//! check they could disagree about who owns the row, which corrupts any
//! later "the authorization for intent X" lookup
//! (`idx_authorizations_intent_id` exists precisely for that lookup shape)
//! with a row belonging to a different profile, for an attacker-chosen
//! root, in unbounded quantity (once per idempotency key). Row-level
//! integrity is a different property from signature-safety, and the
//! argument that the signed payload does not depend on `intent_id` proves
//! too much: it was equally true of C2's original `profile_wallets`
//! insert, and that was still the hazard this whole task exists to fix.

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::B256;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use thiserror::Error;

use super::crypto_store::{self, CryptoStoreError, DataKey, EnvelopeAad, SecretHex};
use super::profile_auth::AuthenticatedProfileId;
use super::store::{StreamGStore, StreamGStoreError};
use crate::merkle::keccak256;

/// Verified against `contracts/src/StreamGTypes.sol`'s
/// `ROOT_AUTHORIZATION_TYPEHASH` -- see module doc's "CORRECTED" section.
/// Pinned byte-for-byte by
/// [`root_authorization_typehash_matches_streamg_types_sol`].
pub const ROOT_AUTHORIZATION_TYPEHASH_STR: &str =
    "RootAuthorization(address root,address secondary,bytes32 enrollDigest,bytes32 linkDigest,uint256 nonce,uint48 deadline)";

/// `contracts/src/WalletSponsorshipRegistry.sol` constructor:
/// `EIP712("GoatWalletSponsorship", "1")`.
const DOMAIN_NAME: &str = "GoatWalletSponsorship";
const DOMAIN_VERSION: &str = "1";

/// `2^48 - 1` -- `deadline` is `uint48` on-chain.
const UINT48_MAX: u64 = (1u64 << 48) - 1;

/// Server-side cap (I5) on how far in the future a caller may push
/// `deadline`. 15 minutes: comfortably longer than a normal request round
/// trip, while keeping the blast radius of a leaked signature bounded --
/// there is no other revocation path for an unspent `RootAuthorization`.
const ROOT_AUTHORIZATION_TTL_SECONDS: i64 = 15 * 60;

pub const ERR_IDEMPOTENCY_KEY_CONFLICT: &str = "IDEMPOTENCY_KEY_CONFLICT";
pub const ERR_NON_STANDALONE_SECONDARY: &str = "NON_STANDALONE_SECONDARY";
pub const ERR_NON_STANDALONE_LINK_DIGEST: &str = "NON_STANDALONE_LINK_DIGEST";
pub const ERR_ZERO_ENROLL_DIGEST: &str = "ZERO_ENROLL_DIGEST";
/// Minor-2 fix (round 2): `root == address(0)` rejected before the issuer
/// key is ever touched -- see module doc's "CORRECTED" ground-truth list.
pub const ERR_ZERO_ROOT: &str = "ZERO_ROOT";
pub const ERR_DEADLINE_EXCEEDS_UINT48: &str = "DEADLINE_EXCEEDS_UINT48";
pub const ERR_DEADLINE_EXCEEDS_POLICY: &str = "DEADLINE_EXCEEDS_POLICY";
pub const ERR_BAD_WALLET: &str = "BAD_WALLET";
pub const ERR_BAD_DIGEST: &str = "BAD_DIGEST";
/// Important-2 fix (round 2): `req.intent_id` not found, or found but
/// belonging to a different profile than `profile` -- the two cases are
/// deliberately indistinguishable, same reasoning as
/// `onboarding::OnboardingError::IntentNotFound`.
pub const ERR_INTENT_NOT_FOUND: &str = "INTENT_NOT_FOUND";

#[derive(Debug, Error)]
pub enum RootAuthorizationError {
    #[error("store error: {0}")]
    Store(#[from] StreamGStoreError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoStoreError),
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("invalid issuer private key: {0}")]
    InvalidIssuerKey(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("malformed sealed payload: {0}")]
    MalformedPayload(String),
    #[error("bad wallet address: {0}")]
    BadWallet(String),
    #[error("bad digest: {0}")]
    BadDigest(String),
    #[error("root must not be the zero address")]
    ZeroRoot,
    #[error("intent not found")]
    IntentNotFound,
    #[error("secondary must be the zero address for standalone root registration")]
    NonStandaloneSecondary,
    #[error("linkDigest must be zero for standalone root registration")]
    NonStandaloneLinkDigest,
    #[error("enrollDigest must be non-zero")]
    ZeroEnrollDigest,
    #[error("deadline does not fit in uint48")]
    DeadlineExceedsUint48,
    #[error("deadline exceeds the server-side authorization TTL policy")]
    DeadlineExceedsPolicy,
    #[error("idempotency key already used with different request parameters")]
    IdempotencyKeyConflict,
    /// Fault-injection hook for
    /// `root_authorization_reservation_genuinely_executes_before_signing` --
    /// see `test_hooks` / module doc's ordering section. Never constructed
    /// outside `#[cfg(test)]`.
    #[cfg(test)]
    #[error("injected test failure (fault-injection hook)")]
    InjectedTestFailure,
}

impl RootAuthorizationError {
    /// Stable string code for routes to surface (Task 8). Falls back to
    /// `"INTERNAL"` for variants that are not meant to be a specific typed
    /// API error (store/crypto/sqlx plumbing failures, signer plumbing).
    pub fn code(&self) -> &'static str {
        match self {
            RootAuthorizationError::BadWallet(_) => ERR_BAD_WALLET,
            RootAuthorizationError::BadDigest(_) => ERR_BAD_DIGEST,
            RootAuthorizationError::ZeroRoot => ERR_ZERO_ROOT,
            RootAuthorizationError::IntentNotFound => ERR_INTENT_NOT_FOUND,
            RootAuthorizationError::NonStandaloneSecondary => ERR_NON_STANDALONE_SECONDARY,
            RootAuthorizationError::NonStandaloneLinkDigest => ERR_NON_STANDALONE_LINK_DIGEST,
            RootAuthorizationError::ZeroEnrollDigest => ERR_ZERO_ENROLL_DIGEST,
            RootAuthorizationError::DeadlineExceedsUint48 => ERR_DEADLINE_EXCEEDS_UINT48,
            RootAuthorizationError::DeadlineExceedsPolicy => ERR_DEADLINE_EXCEEDS_POLICY,
            RootAuthorizationError::IdempotencyKeyConflict => ERR_IDEMPOTENCY_KEY_CONFLICT,
            _ => "INTERNAL",
        }
    }

    /// HTTP status for the shared Stream G error envelope
    /// (`super::http_error`). Wildcard-free on purpose — see
    /// [`super::base_fee::BaseFeeError::status`].
    ///
    /// [`RootAuthorizationError::IntentNotFound`] is **404, never 403**: its
    /// own doc records that "not found" and "found but owned by another
    /// profile" are deliberately indistinguishable, and that decision only
    /// holds if the HTTP mapping keeps them indistinguishable too. See the
    /// ownership-oracle rule in `super::http_error`.
    pub fn status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            RootAuthorizationError::Store(_)
            | RootAuthorizationError::Crypto(_)
            | RootAuthorizationError::Sqlx(_)
            // This process's own issuer key and signer.
            | RootAuthorizationError::InvalidIssuerKey(_)
            | RootAuthorizationError::SigningFailed(_)
            // The sealed payload this process wrote failed to open or parse.
            | RootAuthorizationError::MalformedPayload(_) => StatusCode::INTERNAL_SERVER_ERROR,

            // Unparseable values, as opposed to well-formed values a rule
            // refuses.
            RootAuthorizationError::BadWallet(_)
            | RootAuthorizationError::BadDigest(_)
            | RootAuthorizationError::DeadlineExceedsUint48 => StatusCode::BAD_REQUEST,

            // Well-formed, refused by this module's standalone-path rules.
            RootAuthorizationError::ZeroRoot
            | RootAuthorizationError::NonStandaloneSecondary
            | RootAuthorizationError::NonStandaloneLinkDigest
            | RootAuthorizationError::ZeroEnrollDigest
            | RootAuthorizationError::DeadlineExceedsPolicy => StatusCode::UNPROCESSABLE_ENTITY,

            RootAuthorizationError::IntentNotFound => StatusCode::NOT_FOUND,
            RootAuthorizationError::IdempotencyKeyConflict => StatusCode::CONFLICT,

            #[cfg(test)]
            RootAuthorizationError::InjectedTestFailure => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Deterministic row id -- see module doc's idempotency section.
/// Unchanged formula: `(profile_id, idempotency_key)` only. Body content is
/// *not* folded into this text -- see module doc for why that would defeat
/// conflict detection rather than enable it.
fn deterministic_id(parts: &[&str]) -> String {
    hex::encode(Sha256::digest(parts.join("|").as_bytes()))
}

/// Canonical concatenation of everything the issuer actually signs over
/// (plus the coupling `intent_id`), used only as the input to
/// [`body_hash_hex`]. Order is arbitrary but must stay stable.
#[allow(clippy::too_many_arguments)]
fn canonical_body_string(
    root_hex: &str,
    secondary_hex: &str,
    enroll_digest_hex: &str,
    link_digest_hex: &str,
    deadline: u64,
    chain_id: u64,
    verifying_contract_hex: &str,
    intent_id: &str,
) -> String {
    format!(
        "{root_hex}|{secondary_hex}|{enroll_digest_hex}|{link_digest_hex}|{deadline}|{chain_id}|{verifying_contract_hex}|{intent_id}"
    )
}

fn body_hash_hex(body: &str) -> String {
    hex::encode(Sha256::digest(body.as_bytes()))
}

fn parse_address20(s: &str) -> Result<[u8; 20], RootAuthorizationError> {
    let s = s.trim();
    let h = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if h.len() != 40 {
        return Err(RootAuthorizationError::BadWallet(s.to_string()));
    }
    let bytes = hex::decode(h).map_err(|_| RootAuthorizationError::BadWallet(s.to_string()))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_bytes32(s: &str) -> Result<[u8; 32], RootAuthorizationError> {
    let s = s.trim();
    let h = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if h.len() != 64 {
        return Err(RootAuthorizationError::BadDigest(s.to_string()));
    }
    let bytes = hex::decode(h).map_err(|_| RootAuthorizationError::BadDigest(s.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn address_hex(a: [u8; 20]) -> String {
    format!("0x{}", hex::encode(a))
}

fn bytes32_hex(b: [u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

fn address_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

fn u256_be(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn eip712_domain_typehash() -> [u8; 32] {
    keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
}

fn root_authorization_typehash() -> [u8; 32] {
    keccak256(ROOT_AUTHORIZATION_TYPEHASH_STR.as_bytes())
}

fn domain_separator(chain_id: u64, verifying_contract: [u8; 20]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 5);
    buf.extend_from_slice(&eip712_domain_typehash());
    buf.extend_from_slice(&keccak256(DOMAIN_NAME.as_bytes()));
    buf.extend_from_slice(&keccak256(DOMAIN_VERSION.as_bytes()));
    buf.extend_from_slice(&u256_be(chain_id as u128));
    buf.extend_from_slice(&address_word(&verifying_contract));
    keccak256(&buf)
}

fn eip712_digest(domain: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 66];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(domain);
    buf[34..66].copy_from_slice(struct_hash);
    keccak256(&buf)
}

/// `keccak256(abi.encode(ROOT_AUTHORIZATION_TYPEHASH, root, secondary,
/// enrollDigest, linkDigest, nonce, deadline))` -- field order exactly as
/// declared in `StreamGTypes.sol` / hashed in
/// `WalletSponsorshipRegistry._hashRootAuthorization`. `enrollDigest` and
/// `linkDigest` are already 32-byte words (Solidity `bytes32`), so they are
/// used as-is with no further padding.
#[allow(clippy::too_many_arguments)]
fn root_authorization_struct_hash(
    root: [u8; 20],
    secondary: [u8; 20],
    enroll_digest: [u8; 32],
    link_digest: [u8; 32],
    nonce: u64,
    deadline: u64,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 7);
    buf.extend_from_slice(&root_authorization_typehash());
    buf.extend_from_slice(&address_word(&root));
    buf.extend_from_slice(&address_word(&secondary));
    buf.extend_from_slice(&enroll_digest);
    buf.extend_from_slice(&link_digest);
    buf.extend_from_slice(&u256_be(nonce as u128));
    // uint48, right-aligned in a 32-byte word same as any other uint --
    // correction item 3/6.
    buf.extend_from_slice(&u256_be(deadline as u128));
    keccak256(&buf)
}

#[allow(clippy::too_many_arguments)]
fn root_authorization_digest(
    root: [u8; 20],
    secondary: [u8; 20],
    enroll_digest: [u8; 32],
    link_digest: [u8; 32],
    nonce: u64,
    deadline: u64,
    chain_id: u64,
    verifying_contract: [u8; 20],
) -> [u8; 32] {
    let domain = domain_separator(chain_id, verifying_contract);
    let struct_hash = root_authorization_struct_hash(
        root,
        secondary,
        enroll_digest,
        link_digest,
        nonce,
        deadline,
    );
    eip712_digest(&domain, &struct_hash)
}

/// Everything the issuer signs *in* -- resolved by the caller from
/// `StreamGConfig::issuer_private_key` plus the deployment manifest's
/// `WalletSponsorshipRegistry` address and the configured chain id (I5).
/// **Never** constructed from a request body: a `CreateRootAuthorizationRequest`
/// has no `chain_id` or `verifying_contract` field at all, so a request
/// literally cannot name the EIP-712 domain the issuer signs in. Task 8
/// owns building this from configuration.
pub struct IssuerSigningContext {
    pub chain_id: u64,
    pub verifying_contract: [u8; 20],
    pub issuer_private_key_hex: String,
}

/// `POST /v1/profile/root-authorizations` request body (Task 8 mounts the
/// route). `secondary_address` and `link_digest_hex` are present because
/// they are genuine fields of the on-chain struct, but this module only
/// implements the *standalone* root-registration shape `registerPrimary`
/// requires -- see module doc -- so both are validated to be zero before
/// signing, and `enroll_digest_hex` is validated to be non-zero.
///
/// **I3 fix.** `profile_id` was removed from this request body entirely --
/// see module doc. The profile comes from a separate, already-proven
/// `&AuthenticatedProfileId` parameter to [`create_root_authorization`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRootAuthorizationRequest {
    /// Existing `intents` row this authorization is for -- see module doc.
    pub intent_id: String,
    pub root_address: String,
    /// MUST be the zero address for the standalone path this module
    /// implements.
    pub secondary_address: String,
    /// MUST be non-zero.
    pub enroll_digest_hex: String,
    /// MUST be zero for the standalone path this module implements.
    pub link_digest_hex: String,
    pub deadline: u64,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RootAuthorizationResult {
    pub authorization_id: String,
    pub nonce: i64,
    pub signature_hex: String,
}

/// Shape of the JSON payload sealed into `authorizations.signature_enc`.
/// `body_hash` is what a replay is checked against -- see module doc's
/// "Idempotency vs. conflict" section.
#[derive(Debug, Serialize, Deserialize)]
struct AuthorizationPayload {
    signature: String,
    nonce: i64,
    root: String,
    secondary: String,
    enroll_digest: String,
    link_digest: String,
    deadline: u64,
    chain_id: u64,
    verifying_contract: String,
    intent_id: String,
    body_hash: String,
}

/// `POST /v1/profile/root-authorizations` (Task 8 mounts the route).
///
/// **I3 fix.** `profile` is `&profile_auth::AuthenticatedProfileId`,
/// obtainable only from `profile_auth::authenticate_credential` or
/// `profile_auth::validate_session` -- see module doc.
pub async fn create_root_authorization(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    ctx: &IssuerSigningContext,
    profile: &AuthenticatedProfileId,
    req: CreateRootAuthorizationRequest,
) -> Result<RootAuthorizationResult, RootAuthorizationError> {
    let data_key = DataKey::from_secret(data_key_hex);

    let root = parse_address20(&req.root_address)?;
    if root == [0u8; 20] {
        // Minor-2 fix (round 2): `WalletSponsorshipRegistry.sol:159`
        // reverts `ZeroAddress()` for a zero root -- reject it here,
        // before ever calling the issuer key, instead of signing a
        // payload that would burn nonce slot 0 for
        // `signer_address = 0x000...0` for nothing.
        return Err(RootAuthorizationError::ZeroRoot);
    }
    let root_hex = address_hex(root);

    let secondary = parse_address20(&req.secondary_address)?;
    if secondary != [0u8; 20] {
        return Err(RootAuthorizationError::NonStandaloneSecondary);
    }
    let secondary_hex = address_hex(secondary);

    let link_digest = parse_bytes32(&req.link_digest_hex)?;
    if link_digest != [0u8; 32] {
        return Err(RootAuthorizationError::NonStandaloneLinkDigest);
    }
    let link_digest_hex = bytes32_hex(link_digest);

    let enroll_digest = parse_bytes32(&req.enroll_digest_hex)?;
    if enroll_digest == [0u8; 32] {
        return Err(RootAuthorizationError::ZeroEnrollDigest);
    }
    let enroll_digest_hex = bytes32_hex(enroll_digest);

    if req.deadline > UINT48_MAX {
        return Err(RootAuthorizationError::DeadlineExceedsUint48);
    }
    let now = now_unix_seconds();
    if (req.deadline as i64) > now.saturating_add(ROOT_AUTHORIZATION_TTL_SECONDS) {
        return Err(RootAuthorizationError::DeadlineExceedsPolicy);
    }
    let deadline = req.deadline;

    let chain_id = ctx.chain_id;
    let verifying_contract = ctx.verifying_contract;
    let verifying_contract_hex = address_hex(verifying_contract);
    let issuer_private_key_hex = ctx.issuer_private_key_hex.clone();

    let intent_id = req.intent_id.clone();
    let profile_id = profile.as_str().to_string();

    let body = canonical_body_string(
        &root_hex,
        &secondary_hex,
        &enroll_digest_hex,
        &link_digest_hex,
        deadline,
        chain_id,
        &verifying_contract_hex,
        &intent_id,
    );
    let body_hash = body_hash_hex(&body);

    // Both unchanged (profile_id, idempotency_key)-only formulas -- see
    // module doc for why the body hash is *not* folded into this text.
    // I3: `profile_id` here is `profile.as_str()` (an already-authenticated
    // value), not a request field -- see this module's "I3 fix" doc
    // section.
    let reservation_id = deterministic_id(&[
        "root_authorization_nonce",
        &profile_id,
        &req.idempotency_key,
    ]);
    let authorization_id =
        deterministic_id(&["root_authorization", &profile_id, &req.idempotency_key]);

    // `write_tx`'s closure cannot itself capture a borrow of `store` (see
    // `profile_auth.rs`'s `fetch_and_verify_challenge` doc for why) -- pull
    // the two plain values `envelope_aad` would read out of `store` now,
    // and build `EnvelopeAad` by hand inside the closure.
    let db_uuid_owned = store.db_uuid().to_string();
    // `envelope_aad_version()`, NOT `schema_version()` — see
    // `StreamGStore::envelope_aad_version`.
    let schema_version = store.envelope_aad_version();
    let authorization_id_for_tx = authorization_id.clone();

    let (nonce, signature_hex) = store
        .write_tx(move |tx| {
            Box::pin(async move {
                // (-1) Important-2 fix (round 2): verify `intent_id`
                // actually belongs to `profile_id` before touching
                // anything else. `None` (no such intent) and "exists but
                // belongs to someone else" both map to the same typed
                // error -- see module doc -- so this check cannot be used
                // as an oracle for whether a given `intent_id` exists.
                let intent_owner: Option<String> =
                    sqlx::query_scalar("SELECT profile_id FROM intents WHERE id = ?")
                        .bind(&intent_id)
                        .fetch_optional(&mut **tx)
                        .await?;
                match intent_owner {
                    Some(owner) if owner == profile_id => {}
                    _ => return Err(RootAuthorizationError::IntentNotFound),
                }

                // (0) Has this (profile_id, idempotency_key) already
                // produced an authorization? Checked *before* touching
                // `nonce_allocations` at all, so a conflicting replay never
                // reaches reservation, let alone signing.
                let existing = sqlx::query(
                    "SELECT intent_id, profile_id, signature_enc FROM authorizations WHERE id = ?",
                )
                .bind(&authorization_id_for_tx)
                .fetch_optional(&mut **tx)
                .await?;

                if let Some(row) = existing {
                    let row_intent_id: String = row.try_get("intent_id")?;
                    let row_profile_id: String = row.try_get("profile_id")?;
                    let signature_enc: Vec<u8> = row.try_get("signature_enc")?;

                    let aad = EnvelopeAad {
                        db_uuid: &db_uuid_owned,
                        schema_version,
                        table: "authorizations",
                        pk: &authorization_id_for_tx,
                        column: "signature_enc",
                    };
                    let opened = crypto_store::open(&data_key, &aad, &signature_enc)?;
                    let stored: AuthorizationPayload = serde_json::from_slice(&opened)
                        .map_err(|e| RootAuthorizationError::MalformedPayload(e.to_string()))?;

                    let is_true_replay = stored.body_hash == body_hash
                        && row_intent_id == intent_id
                        && row_profile_id == profile_id;

                    if is_true_replay {
                        return Ok::<(i64, String), RootAuthorizationError>((
                            stored.nonce,
                            stored.signature,
                        ));
                    }
                    return Err(RootAuthorizationError::IdempotencyKeyConflict);
                }

                // (a) Fresh call. Reserve the root-registration nonce
                // FIRST -- a per-(chain_id, root) monotonic local
                // allocator (see module doc's nonce-semantics section),
                // strictly before the issuer key is ever touched.
                let next_nonce: i64 = sqlx::query_scalar(
                    "SELECT COALESCE(MAX(nonce), -1) + 1 FROM nonce_allocations \
                     WHERE chain_id = ? AND signer_address = ?",
                )
                .bind(chain_id as i64)
                .bind(&root_hex)
                .fetch_one(&mut **tx)
                .await?;

                let reservation_result = sqlx::query(
                    "INSERT OR IGNORE INTO nonce_allocations \
                     (id, chain_id, signer_address, nonce, status, allocated_at) \
                     VALUES (?, ?, ?, ?, 'allocated', ?)",
                )
                .bind(&reservation_id)
                .bind(chain_id as i64)
                .bind(&root_hex)
                .bind(next_nonce)
                .bind(now)
                .execute(&mut **tx)
                .await?;

                #[cfg(test)]
                {
                    test_hooks::RESERVATION_ROWS_AFFECTED
                        .with(|c| c.set(reservation_result.rows_affected()));
                    if test_hooks::FAIL_AFTER_RESERVATION.with(|c| c.get()) {
                        return Err(RootAuthorizationError::InjectedTestFailure);
                    }
                }

                if reservation_result.rows_affected() != 1 {
                    // Anomaly: step (0) found no authorization row for this
                    // key, yet the reservation row already exists. Never
                    // fall through to the signer on an ignored insert.
                    return Err(RootAuthorizationError::IdempotencyKeyConflict);
                }

                // (b) THEN parse the issuer key and sign -- strictly after
                // (a) has executed in this transaction. Any failure here
                // returns Err, which rolls back the *whole* transaction,
                // undoing (a): the reservation is never left dangling as
                // usable. See
                // `root_authorization_nonce_reserved_before_signature_and_rolls_back_on_signing_failure`
                // and, for a genuine fault-injection proof of the
                // ordering, `root_authorization_reservation_genuinely_executes_before_signing`.
                let signer = PrivateKeySigner::from_str(issuer_private_key_hex.trim())
                    .map_err(|e| RootAuthorizationError::InvalidIssuerKey(e.to_string()))?;
                let digest = root_authorization_digest(
                    root,
                    secondary,
                    enroll_digest,
                    link_digest,
                    next_nonce as u64,
                    deadline,
                    chain_id,
                    verifying_contract,
                );
                let signature = signer
                    .sign_hash_sync(&B256::from(digest))
                    .map_err(|e| RootAuthorizationError::SigningFailed(e.to_string()))?;
                let signature_hex = format!("0x{}", hex::encode(signature.as_bytes()));

                // (c) Persist, tied to the caller-supplied intent.
                let payload = AuthorizationPayload {
                    signature: signature_hex.clone(),
                    nonce: next_nonce,
                    root: root_hex.clone(),
                    secondary: secondary_hex.clone(),
                    enroll_digest: enroll_digest_hex.clone(),
                    link_digest: link_digest_hex.clone(),
                    deadline,
                    chain_id,
                    verifying_contract: verifying_contract_hex.clone(),
                    intent_id: intent_id.clone(),
                    body_hash: body_hash.clone(),
                };
                let payload_bytes = serde_json::to_vec(&payload)
                    .map_err(|e| RootAuthorizationError::MalformedPayload(e.to_string()))?;
                let aad = EnvelopeAad {
                    db_uuid: &db_uuid_owned,
                    schema_version,
                    table: "authorizations",
                    pk: &authorization_id_for_tx,
                    column: "signature_enc",
                };
                let signature_enc = crypto_store::seal(&data_key, &aad, &payload_bytes)?;

                let auth_result = sqlx::query(
                    "INSERT OR IGNORE INTO authorizations \
                     (id, intent_id, profile_id, status, signature_enc, created_at, authorized_at) \
                     VALUES (?, ?, ?, 'authorized', ?, ?, ?)",
                )
                .bind(&authorization_id_for_tx)
                .bind(&intent_id)
                .bind(&profile_id)
                .bind(&signature_enc)
                .bind(now)
                .bind(now)
                .execute(&mut **tx)
                .await?;

                if auth_result.rows_affected() != 1 {
                    // Never fall through to "success" here either --
                    // returning Err rolls back (a) too, so a signature can
                    // never end up recorded nowhere while a nonce sits
                    // reserved.
                    return Err(RootAuthorizationError::IdempotencyKeyConflict);
                }

                Ok::<(i64, String), RootAuthorizationError>((next_nonce, signature_hex))
            })
        })
        .await?;

    Ok(RootAuthorizationResult {
        authorization_id,
        nonce,
        signature_hex,
    })
}

/// Fault-injection hook for
/// `root_authorization_reservation_genuinely_executes_before_signing` (M9a)
/// -- see module doc's ordering section. `RESERVATION_ROWS_AFFECTED` is a
/// side channel that survives the transaction rollback the injected
/// failure triggers, so a test can prove the reservation INSERT genuinely
/// executed even though its transaction never commits.
///
/// **Thread-local, not a process-global `static`.** `cargo test` runs each
/// `#[tokio::test]` function on its own OS thread in parallel, and
/// `#[tokio::test]`'s default `current_thread` runtime keeps a given call's
/// entire async task (including everything inside `write_tx`'s future) on
/// that same thread with no work-stealing. A process-global `AtomicBool`
/// would leak one test's injected failure into every other test running
/// concurrently in the same process (observed directly during development:
/// unrelated tests started failing with `InjectedTestFailure`) -- a
/// thread-local confines the flag to the one test that set it.
#[cfg(test)]
mod test_hooks {
    use std::cell::Cell;

    thread_local! {
        pub(crate) static FAIL_AFTER_RESERVATION: Cell<bool> = const { Cell::new(false) };
        /// `u64::MAX` means "not observed in this call yet".
        pub(crate) static RESERVATION_ROWS_AFFECTED: Cell<u64> = const { Cell::new(u64::MAX) };
    }

    pub(crate) fn reset() {
        FAIL_AFTER_RESERVATION.with(|c| c.set(false));
        RESERVATION_ROWS_AFFECTED.with(|c| c.set(u64::MAX));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Anvil account #0 -- same key `src/sig_verify.rs`'s tests use.
    const VALID_ISSUER_PK: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    fn zero_address_hex() -> String {
        format!("0x{}", "00".repeat(20))
    }

    fn zero_digest_hex() -> String {
        format!("0x{}", "00".repeat(32))
    }

    /// Built from `[byte; 20]`/`[byte; 32]` rather than hand-typed hex
    /// literals -- a hand-typed address string one character short of 40
    /// hex chars silently exercises a *different* code path (`BadWallet`
    /// from `parse_address20`) than the one the test claims to be
    /// exercising, which is exactly the kind of test-fixture bug this
    /// module's own review caught during development.
    fn nonzero_address_hex(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 20]))
    }

    fn nonzero_digest_hex(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 32]))
    }

    async fn open_store() -> (tempfile::TempDir, StreamGStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open store");
        (dir, store)
    }

    fn data_key_hex() -> SecretHex {
        SecretHex::from_hex(&"dd".repeat(32)).expect("valid 32-byte test key")
    }

    fn issuer_ctx() -> IssuerSigningContext {
        IssuerSigningContext {
            chain_id: 31337,
            verifying_contract: [0x11; 20],
            issuer_private_key_hex: VALID_ISSUER_PK.to_string(),
        }
    }

    fn issuer_ctx_with_key(key: &str) -> IssuerSigningContext {
        IssuerSigningContext {
            chain_id: 31337,
            verifying_contract: [0x11; 20],
            issuer_private_key_hex: key.to_string(),
        }
    }

    /// Seed a `profiles` row and an `intents` row directly (this module
    /// does not own either -- `profile_auth.rs` / `onboarding.rs` do),
    /// satisfying `authorizations`' NOT NULL foreign keys.
    async fn seed_profile_and_intent(store: &StreamGStore, profile_id: &str, intent_id: &str) {
        let profile_id = profile_id.to_string();
        let intent_id = intent_id.to_string();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO profiles (id, created_at, status) VALUES (?, 0, 'active')",
                    )
                    .bind(&profile_id)
                    .execute(&mut **tx)
                    .await?;
                    sqlx::query(
                        "INSERT INTO intents (id, profile_id, intent_type, status, created_at) \
                         VALUES (?, ?, 'primary_onboarding', 'submitted', 0)",
                    )
                    .bind(&intent_id)
                    .bind(&profile_id)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed profile + intent");
    }

    /// **I3 fix.** No longer takes `profile_id` -- `CreateRootAuthorizationRequest`
    /// has no such field anymore. Call sites pass the profile separately as
    /// `&AuthenticatedProfileId::for_test(..)` to [`create_root_authorization`].
    ///
    /// Minor-4 fix (round 2): `deadline` is folded into `body_hash` (C1),
    /// so a test that needs the *same* body to hash identically across
    /// multiple calls (e.g. a true replay) must reuse one `deadline`
    /// rather than letting each call compute a fresh
    /// `now_unix_seconds() + 60` -- two calls straddling a clock-second
    /// boundary would otherwise get different deadlines, different
    /// `body_hash`es, and a spuriously-flaky `IdempotencyKeyConflict`. This
    /// helper takes the deadline explicitly for exactly that reason;
    /// [`request`] below is the convenience wrapper for call sites that
    /// only ever build one request and don't care.
    fn request_with_deadline(
        intent_id: &str,
        idempotency_key: &str,
        deadline: u64,
    ) -> CreateRootAuthorizationRequest {
        CreateRootAuthorizationRequest {
            intent_id: intent_id.to_string(),
            root_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            secondary_address: zero_address_hex(),
            enroll_digest_hex: nonzero_digest_hex(0xAB),
            link_digest_hex: zero_digest_hex(),
            deadline,
            idempotency_key: idempotency_key.to_string(),
        }
    }

    fn request(intent_id: &str, idempotency_key: &str) -> CreateRootAuthorizationRequest {
        request_with_deadline(intent_id, idempotency_key, (now_unix_seconds() + 60) as u64)
    }

    async fn nonce_count(store: &StreamGStore) -> i64 {
        store
            .read(|handle| {
                Box::pin(async move {
                    let c: i64 = handle
                        .fetch_scalar(sqlx::query_scalar("SELECT COUNT(*) FROM nonce_allocations"))
                        .await?;
                    Ok::<i64, StreamGStoreError>(c)
                })
            })
            .await
            .unwrap()
    }

    async fn auth_count(store: &StreamGStore) -> i64 {
        store
            .read(|handle| {
                Box::pin(async move {
                    let c: i64 = handle
                        .fetch_scalar(sqlx::query_scalar("SELECT COUNT(*) FROM authorizations"))
                        .await?;
                    Ok::<i64, StreamGStoreError>(c)
                })
            })
            .await
            .unwrap()
    }

    // --- Typehash correction ---------------------------------------------

    /// Pins [`ROOT_AUTHORIZATION_TYPEHASH_STR`] byte-for-byte against the
    /// literal in `contracts/src/StreamGTypes.sol` -- copied here
    /// independently (not by referencing the constant's own source) so any
    /// future edit to the constant that drifts from the Solidity source
    /// fails this test loudly.
    #[test]
    fn root_authorization_typehash_matches_streamg_types_sol() {
        assert_eq!(
            ROOT_AUTHORIZATION_TYPEHASH_STR,
            "RootAuthorization(address root,address secondary,bytes32 enrollDigest,bytes32 linkDigest,uint256 nonce,uint48 deadline)"
        );
    }

    /// Fixed-input digest regression: any future change to the domain,
    /// typehash string, field order, or word-packing must change this
    /// output, so a silent encoding drift fails loudly instead of only
    /// being caught by an on-chain rejection.
    #[test]
    fn root_authorization_digest_regression_fixed_inputs() {
        let root = [0x11u8; 20];
        let secondary = [0u8; 20];
        let enroll_digest = [0x22u8; 32];
        let link_digest = [0u8; 32];
        let nonce = 7u64;
        let deadline = 2_000_000_000u64;
        let chain_id = 31337u64;
        let verifying_contract = [0x33u8; 20];

        let digest = root_authorization_digest(
            root,
            secondary,
            enroll_digest,
            link_digest,
            nonce,
            deadline,
            chain_id,
            verifying_contract,
        );
        assert_eq!(
            hex::encode(digest),
            "1e3a7b56a8099822843435f9efe31f57d87504e6e5423fdf962c80dc614ad2dc",
            "digest changed -- if this is an intentional encoding change, \
             recompute and re-pin; if not, the EIP-712 output just drifted \
             from what the deployed contract expects"
        );
    }

    // --- C1: replay vs. conflict ------------------------------------------

    #[tokio::test]
    async fn root_authorization_good_path_signs_after_reserving_nonce() {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-root-1", "intent-root-1").await;

        let result = create_root_authorization(
            &store,
            &data_key_hex(),
            &issuer_ctx(),
            &AuthenticatedProfileId::for_test("profile-root-1"),
            request("intent-root-1", "idem-root-1"),
        )
        .await
        .expect("good path must succeed");

        assert!(!result.signature_hex.is_empty());
        assert_eq!(
            nonce_count(&store).await,
            1,
            "the nonce must actually have been reserved"
        );
        assert_eq!(
            auth_count(&store).await,
            1,
            "the authorization must have been persisted"
        );
    }

    /// Plan-mandated proof of ordering (brief 5.6): if signing fails (here:
    /// a malformed issuer key), the nonce reservation attempted earlier in
    /// the *same* transaction must not survive -- rollback, not a dangling
    /// usable row.
    #[tokio::test]
    async fn root_authorization_nonce_reserved_before_signature_and_rolls_back_on_signing_failure()
    {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-root-2", "intent-root-2").await;

        let err = create_root_authorization(
            &store,
            &data_key_hex(),
            &issuer_ctx_with_key("not-a-valid-private-key"),
            &AuthenticatedProfileId::for_test("profile-root-2"),
            request("intent-root-2", "idem-root-2"),
        )
        .await
        .expect_err("malformed issuer key must fail signing");
        assert!(matches!(err, RootAuthorizationError::InvalidIssuerKey(_)));

        assert_eq!(
            nonce_count(&store).await,
            0,
            "a reservation attempted earlier in the same failed transaction must not persist"
        );
        assert_eq!(auth_count(&store).await, 0);
    }

    #[tokio::test]
    async fn root_authorization_replay_of_same_idempotency_key_does_not_double_reserve() {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-root-3", "intent-root-3").await;

        // Minor-4 fix (round 2): one deadline reused for both calls -- see
        // `request_with_deadline`'s doc for why two independently-computed
        // `now_unix_seconds() + 60` deadlines would make this test flaky
        // across a clock-second boundary.
        let deadline = (now_unix_seconds() + 60) as u64;
        let req = request_with_deadline("intent-root-3", "idem-root-3", deadline);
        let req2 = request_with_deadline("intent-root-3", "idem-root-3", deadline);
        let profile = AuthenticatedProfileId::for_test("profile-root-3");

        let first =
            create_root_authorization(&store, &data_key_hex(), &issuer_ctx(), &profile, req)
                .await
                .unwrap();
        let replay =
            create_root_authorization(&store, &data_key_hex(), &issuer_ctx(), &profile, req2)
                .await
                .unwrap();

        assert_eq!(replay.authorization_id, first.authorization_id);
        assert_eq!(replay.nonce, first.nonce);
        assert_eq!(
            replay.signature_hex, first.signature_hex,
            "same inputs -> byte-identical signature"
        );
        assert_eq!(
            nonce_count(&store).await,
            1,
            "replay must not reserve a second nonce"
        );
        assert_eq!(
            auth_count(&store).await,
            1,
            "replay must not create a second authorization"
        );
    }

    /// C1's core failure scenario: same `(profile_id, idempotency_key,
    /// intent_id)` but a *different* signed body (here: a different root
    /// wallet). Must be rejected as a typed conflict, not silently signed
    /// over a payload with no matching reservation.
    #[tokio::test]
    async fn root_authorization_replay_with_different_body_is_rejected_as_conflict() {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-root-4", "intent-root-4").await;

        let profile = AuthenticatedProfileId::for_test("profile-root-4");

        // Minor-4 fix (round 2): one deadline computed once and reused
        // across all three calls below. `body_hash` folds `deadline` in
        // (C1), so building each request from a fresh
        // `now_unix_seconds() + 60` made the final "replay of the
        // original" call spuriously hash-mismatch (and hit
        // `IdempotencyKeyConflict` instead of replaying cleanly) whenever a
        // clock-second boundary was crossed between calls -- not a real
        // defect, just test flakiness. See `request_with_deadline`'s doc.
        let deadline = (now_unix_seconds() + 60) as u64;

        let first = create_root_authorization(
            &store,
            &data_key_hex(),
            &issuer_ctx(),
            &profile,
            request_with_deadline("intent-root-4", "idem-root-4", deadline),
        )
        .await
        .expect("first call succeeds");

        let mut conflicting = request_with_deadline("intent-root-4", "idem-root-4", deadline);
        conflicting.root_address = nonzero_address_hex(0xBB);

        let err = create_root_authorization(
            &store,
            &data_key_hex(),
            &issuer_ctx(),
            &profile,
            conflicting,
        )
        .await
        .expect_err("a different body under the same idempotency key must be rejected");
        assert!(matches!(
            err,
            RootAuthorizationError::IdempotencyKeyConflict
        ));
        assert_eq!(err.code(), ERR_IDEMPOTENCY_KEY_CONFLICT);

        // No second nonce, no second authorization, and the *original*
        // record must be unchanged -- nothing was ever signed for the
        // conflicting body.
        assert_eq!(nonce_count(&store).await, 1);
        assert_eq!(auth_count(&store).await, 1);

        let replay_of_original = create_root_authorization(
            &store,
            &data_key_hex(),
            &issuer_ctx(),
            &profile,
            request_with_deadline("intent-root-4", "idem-root-4", deadline),
        )
        .await
        .expect("the original body must still replay cleanly");
        assert_eq!(replay_of_original.signature_hex, first.signature_hex);
    }

    // --- I1: nonce semantics -----------------------------------------------

    #[tokio::test]
    async fn root_authorization_nonce_is_zero_for_first_time_root() {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-root-5", "intent-root-5").await;

        let result = create_root_authorization(
            &store,
            &data_key_hex(),
            &issuer_ctx(),
            &AuthenticatedProfileId::for_test("profile-root-5"),
            request("intent-root-5", "idem-root-5"),
        )
        .await
        .unwrap();
        assert_eq!(
            result.nonce, 0,
            "a never-before-seen root must start at nonce 0"
        );
    }

    #[tokio::test]
    async fn root_authorization_nonce_increments_per_root_across_idempotency_keys() {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-root-6a", "intent-root-6a").await;
        seed_profile_and_intent(&store, "profile-root-6b", "intent-root-6b").await;

        // Same root, two different (profile_id, idempotency_key) pairs ->
        // two distinct reservations against the same per-root counter.
        let first = create_root_authorization(
            &store,
            &data_key_hex(),
            &issuer_ctx(),
            &AuthenticatedProfileId::for_test("profile-root-6a"),
            request("intent-root-6a", "idem-root-6a"),
        )
        .await
        .unwrap();
        let second = create_root_authorization(
            &store,
            &data_key_hex(),
            &issuer_ctx(),
            &AuthenticatedProfileId::for_test("profile-root-6b"),
            request("intent-root-6b", "idem-root-6b"),
        )
        .await
        .unwrap();

        assert_eq!(first.nonce, 0);
        assert_eq!(
            second.nonce, 1,
            "the per-root counter must advance by exactly 1"
        );
    }

    // --- Minor-2 (round 2): zero-root rejection -----------------------------

    /// Minor-2: `root == address(0)` must be rejected before the issuer key
    /// is ever touched -- `WalletSponsorshipRegistry.sol:159` reverts
    /// `ZeroAddress()` on-chain, so signing over a zero root would burn
    /// nonce slot 0 for `signer_address = 0x000...0` for nothing.
    #[tokio::test]
    async fn root_authorization_rejects_zero_root() {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-root-zero", "intent-root-zero").await;

        let mut req = request("intent-root-zero", "idem-root-zero");
        let profile = AuthenticatedProfileId::for_test("profile-root-zero");
        req.root_address = zero_address_hex();

        let err = create_root_authorization(&store, &data_key_hex(), &issuer_ctx(), &profile, req)
            .await
            .expect_err("a zero root address must be rejected");
        assert!(matches!(err, RootAuthorizationError::ZeroRoot));
        assert_eq!(err.code(), ERR_ZERO_ROOT);
        assert_eq!(
            nonce_count(&store).await,
            0,
            "nothing must be reserved before validation"
        );
        assert_eq!(auth_count(&store).await, 0);
    }

    // --- Correction item 4 / item 6 rejections ------------------------------

    #[tokio::test]
    async fn root_authorization_rejects_non_zero_secondary() {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-root-7", "intent-root-7").await;

        let mut req = request("intent-root-7", "idem-root-7");
        let profile = AuthenticatedProfileId::for_test("profile-root-7");
        req.secondary_address = nonzero_address_hex(0xCC);

        let err = create_root_authorization(&store, &data_key_hex(), &issuer_ctx(), &profile, req)
            .await
            .expect_err("non-zero secondary must be rejected");
        assert!(matches!(
            err,
            RootAuthorizationError::NonStandaloneSecondary
        ));
        assert_eq!(err.code(), ERR_NON_STANDALONE_SECONDARY);
        assert_eq!(
            nonce_count(&store).await,
            0,
            "nothing must be reserved before validation"
        );
    }

    #[tokio::test]
    async fn root_authorization_rejects_non_zero_link_digest() {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-root-8", "intent-root-8").await;

        let mut req = request("intent-root-8", "idem-root-8");
        let profile = AuthenticatedProfileId::for_test("profile-root-8");
        req.link_digest_hex = nonzero_digest_hex(0xCD);

        let err = create_root_authorization(&store, &data_key_hex(), &issuer_ctx(), &profile, req)
            .await
            .expect_err("non-zero linkDigest must be rejected");
        assert!(matches!(
            err,
            RootAuthorizationError::NonStandaloneLinkDigest
        ));
        assert_eq!(err.code(), ERR_NON_STANDALONE_LINK_DIGEST);
    }

    #[tokio::test]
    async fn root_authorization_rejects_zero_enroll_digest() {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-root-9", "intent-root-9").await;

        let mut req = request("intent-root-9", "idem-root-9");
        let profile = AuthenticatedProfileId::for_test("profile-root-9");
        req.enroll_digest_hex = zero_digest_hex();

        let err = create_root_authorization(&store, &data_key_hex(), &issuer_ctx(), &profile, req)
            .await
            .expect_err("zero enrollDigest must be rejected");
        assert!(matches!(err, RootAuthorizationError::ZeroEnrollDigest));
        assert_eq!(err.code(), ERR_ZERO_ENROLL_DIGEST);
    }

    #[tokio::test]
    async fn root_authorization_rejects_deadline_exceeding_uint48() {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-root-10", "intent-root-10").await;

        let mut req = request("intent-root-10", "idem-root-10");
        let profile = AuthenticatedProfileId::for_test("profile-root-10");
        req.deadline = UINT48_MAX + 1;

        let err = create_root_authorization(&store, &data_key_hex(), &issuer_ctx(), &profile, req)
            .await
            .expect_err("deadline exceeding uint48 must be rejected");
        assert!(matches!(err, RootAuthorizationError::DeadlineExceedsUint48));
        assert_eq!(err.code(), ERR_DEADLINE_EXCEEDS_UINT48);
    }

    // --- I5: deadline TTL clamp + domain isolation -------------------------

    #[tokio::test]
    async fn root_authorization_rejects_deadline_exceeding_ttl_policy() {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-root-11", "intent-root-11").await;

        // Within uint48 range, but far beyond the server's TTL policy.
        let mut req = request("intent-root-11", "idem-root-11");
        let profile = AuthenticatedProfileId::for_test("profile-root-11");
        req.deadline = (now_unix_seconds() + ROOT_AUTHORIZATION_TTL_SECONDS + 3600) as u64;

        let err = create_root_authorization(&store, &data_key_hex(), &issuer_ctx(), &profile, req)
            .await
            .expect_err("a far-future caller deadline must be rejected, not silently signed");
        assert!(matches!(err, RootAuthorizationError::DeadlineExceedsPolicy));
        assert_eq!(err.code(), ERR_DEADLINE_EXCEEDS_POLICY);
        assert_eq!(
            nonce_count(&store).await,
            0,
            "nothing must be reserved before validation"
        );
    }

    #[tokio::test]
    async fn root_authorization_accepts_deadline_within_ttl_policy() {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-root-12", "intent-root-12").await;

        let mut req = request("intent-root-12", "idem-root-12");
        let profile = AuthenticatedProfileId::for_test("profile-root-12");
        req.deadline = (now_unix_seconds() + ROOT_AUTHORIZATION_TTL_SECONDS - 1) as u64;

        create_root_authorization(&store, &data_key_hex(), &issuer_ctx(), &profile, req)
            .await
            .expect("a deadline just inside the TTL policy must be accepted");
    }

    // --- M9(a): genuine failure injection between reservation and signing --

    /// Fixes the mandated test that could not fail on the defect it was
    /// named for: the original version only asserted "both tables are
    /// empty after a bad-key failure", which is also true if reservation
    /// were accidentally moved *after* signing. This test injects a
    /// failure strictly between the reservation INSERT and signing, and
    /// proves via a side channel (`test_hooks::RESERVATION_ROWS_AFFECTED`,
    /// which survives the transaction rollback) that the reservation INSERT
    /// genuinely executed with `rows_affected() == 1` before the injected
    /// failure aborted the transaction -- distinguishing "reserved, then
    /// rolled back" from "never reserved" in a way the table-emptiness
    /// check alone cannot.
    #[tokio::test]
    async fn root_authorization_reservation_genuinely_executes_before_signing() {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-root-13", "intent-root-13").await;

        test_hooks::reset();
        test_hooks::FAIL_AFTER_RESERVATION.with(|c| c.set(true));

        let err = create_root_authorization(
            &store,
            &data_key_hex(),
            &issuer_ctx(),
            &AuthenticatedProfileId::for_test("profile-root-13"),
            request("intent-root-13", "idem-root-13"),
        )
        .await
        .expect_err("the injected fault must abort the call");
        assert!(matches!(err, RootAuthorizationError::InjectedTestFailure));

        assert_eq!(
            test_hooks::RESERVATION_ROWS_AFFECTED.with(|c| c.get()),
            1,
            "the reservation INSERT must have genuinely executed (rows_affected == 1) \
             strictly before the injected failure -- if reservation ran after signing \
             (or after this hook), this would still be u64::MAX"
        );

        // And the transaction must still have rolled back -- the row does
        // not persist.
        assert_eq!(
            nonce_count(&store).await,
            0,
            "the aborted transaction must not persist the reservation"
        );
        assert_eq!(auth_count(&store).await, 0);

        test_hooks::reset();
    }

    // --- I3: profile id is proven, never merely asserted -------------------

    /// **I3.** Before this fix, `CreateRootAuthorizationRequest` had a
    /// `pub profile_id: String` field an unauthenticated client could set
    /// to anything. After the fix, `profile_id` is no longer a request
    /// field at all -- see this module's doc and `CreateRootAuthorizationRequest`'s
    /// doc for the compile-time argument (the struct literal below simply
    /// has nowhere to put a `profile_id` even if a caller wanted to).
    ///
    /// This test proves the accompanying runtime property: two different
    /// *authenticated* profiles using the exact same `idempotency_key`
    /// (and, artificially, the same `intent_id` shape) never collide, never
    /// adopt each other's signature, and never read back each other's
    /// authorization row -- `reservation_id`/`authorization_id` are keyed
    /// by `profile.as_str()`, an already-proven value, not by anything the
    /// request body could have named.
    #[tokio::test]
    async fn create_root_authorization_scopes_idempotency_by_the_authenticated_profile() {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-i3-a", "intent-i3-a").await;
        seed_profile_and_intent(&store, "profile-i3-b", "intent-i3-b").await;

        let result_a = create_root_authorization(
            &store,
            &data_key_hex(),
            &issuer_ctx(),
            &AuthenticatedProfileId::for_test("profile-i3-a"),
            request("intent-i3-a", "idem-i3-shared"),
        )
        .await
        .expect("profile A's authorization must succeed");

        let result_b = create_root_authorization(
            &store,
            &data_key_hex(),
            &issuer_ctx(),
            &AuthenticatedProfileId::for_test("profile-i3-b"),
            request("intent-i3-b", "idem-i3-shared"),
        )
        .await
        .expect(
            "profile B's authorization, under the SAME idempotency_key, must independently succeed",
        );

        assert_ne!(
            result_a.authorization_id, result_b.authorization_id,
            "different authenticated profiles must get independent authorization rows even under the same idempotency key"
        );
        assert_eq!(
            auth_count(&store).await,
            2,
            "both profiles' authorizations must be persisted, not merged"
        );
    }

    // --- Important-2 (round 2): intent ownership ----------------------------

    /// **Important-2.** Before this fix, `authorizations.intent_id` and
    /// `authorizations.profile_id` could disagree about the owner: nothing
    /// stopped a caller authenticated as one profile from naming an
    /// `intent_id` that actually belongs to a completely different profile.
    /// Both are foreign keys, and `idx_authorizations_intent_id` exists
    /// precisely so later stages can resolve "the authorization for intent
    /// X" -- a disagreeing row corrupts that lookup. This proves the fix: a
    /// caller authenticated as a different profile than the intent's real
    /// owner is rejected, nothing is reserved or signed, and the row's real
    /// owner can still use their own intent normally afterward.
    #[tokio::test]
    async fn create_root_authorization_rejects_an_intent_belonging_to_another_profile() {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-root-owner", "intent-root-owner").await;
        seed_profile_and_intent(&store, "profile-root-attacker", "intent-root-attacker").await;

        let attacker = AuthenticatedProfileId::for_test("profile-root-attacker");
        let req = request("intent-root-owner", "idem-root-cross-owner");

        let err = create_root_authorization(&store, &data_key_hex(), &issuer_ctx(), &attacker, req)
            .await
            .expect_err("an intent belonging to a different profile must be rejected");
        assert!(matches!(err, RootAuthorizationError::IntentNotFound));
        assert_eq!(err.code(), ERR_INTENT_NOT_FOUND);

        assert_eq!(
            nonce_count(&store).await,
            0,
            "nothing must be reserved when the intent-ownership check fails"
        );
        assert_eq!(auth_count(&store).await, 0);

        // The real owner must still be able to use their own intent
        // normally -- the rejection above is ownership-specific, not a
        // general break.
        let owner = AuthenticatedProfileId::for_test("profile-root-owner");
        create_root_authorization(
            &store,
            &data_key_hex(),
            &issuer_ctx(),
            &owner,
            request("intent-root-owner", "idem-root-owner-ok"),
        )
        .await
        .expect("the true owner must still be able to authorize against its own intent");
    }

    /// **Important-2.** A nonexistent `intent_id` used to fall through to
    /// the `authorizations` INSERT and fail as a raw FK-constraint
    /// violation (`RootAuthorizationError::Sqlx`, surfaced as the
    /// undifferentiated `"INTERNAL"` code). The ownership check now catches
    /// it earlier, before anything is reserved, with the exact same typed
    /// `IntentNotFound` a wrong-owner intent gets -- the two cases stay
    /// deliberately indistinguishable so this cannot be used as an
    /// existence oracle either.
    #[tokio::test]
    async fn create_root_authorization_rejects_a_nonexistent_intent_as_a_typed_not_found() {
        let (_dir, store) = open_store().await;
        seed_profile_and_intent(&store, "profile-root-noint", "intent-root-noint-unused").await;

        let profile = AuthenticatedProfileId::for_test("profile-root-noint");
        let req = request("no-such-intent-at-all", "idem-root-noint");

        let err = create_root_authorization(&store, &data_key_hex(), &issuer_ctx(), &profile, req)
            .await
            .expect_err("a nonexistent intent_id must be rejected");
        assert!(matches!(err, RootAuthorizationError::IntentNotFound));
        assert_eq!(err.code(), ERR_INTENT_NOT_FOUND);
        assert_eq!(nonce_count(&store).await, 0);
        assert_eq!(auth_count(&store).await, 0);
    }
}
