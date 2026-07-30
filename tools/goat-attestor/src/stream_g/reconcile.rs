//! Stream G â€” chain-verified reconciliation (Task 7, Wave D).
//!
//! Before this module the attestor could represent **exactly one** post-submit
//! transition: `submitted â†’ confirmed`, in
//! [`super::submit::reconcile_sponsored_enrollment_executed`], and even that
//! one was unreachable from production â€” its only callers were tests. Every
//! other outcome a transaction can have (mined revert, drop, reorg, somebody
//! else fulfilling the intent, a receipt that never arrives) was
//! *unrepresentable*, which in practice meant "silently indistinguishable from
//! still in flight".
//!
//! # The hole this module closes
//!
//! `reconcile_sponsored_enrollment_executed` compared the event's transaction
//! hash against `tx_attempts.tx_hash` **only when that column was non-NULL**.
//! A `reserved` row has `tx_hash NULL` *by construction* â€” the column is
//! written in exactly one place, `outbox::record_broadcast_accepted` (Task 8
//! Wave B merged `submit::record_submitted` into it) â€” so the crash /
//! unresolved-broadcast rows, the very ones the outbox exists to service,
//! passed the guard unchecked. Reconcile then stamped such a row `confirmed`
//! with whatever hash the caller supplied and marked **that row's** action
//! nonce `consumed`: somebody else's on-chain execution attributed to an intent
//! that may never have left this process.
//!
//! An independent verifier proved on 2026-07-25 that the hole was not merely
//! theoretical but *entirely uncovered*: making the guard unconditional broke
//! **no** existing test. Wave D therefore ships two things, not one â€” the fix
//! (the guard is unconditional now, and a NULL-`tx_hash` row is refused with
//! [`super::submit::SubmitError::ReconcileUnverifiable`]) and the coverage that
//! was missing.
//!
//! Reconcile also used to trust the caller's event struct completely: it never
//! asked a node whether the transaction existed, succeeded, or was in the block
//! the event claimed. [`reconcile_executed_log`] does all three before it
//! writes anything.
//!
//! # The five states, plus the sixth the spec insists on
//!
//! | State | Detection | Durable action |
//! |---|---|---|
//! | **Success** | [`ExecutedLog`] backed by a matching successful receipt at â‰¥ [`FinalityPolicy`] confirmations | `confirmed`, nonce `consumed` |
//! | **Revert** | receipt `status == 0` | **holds** the nonce; re-queued for the evidence sweeper. Never `failed` + released here |
//! | **Drop** | no receipt, and the broadcaster's mined nonce frontier has moved past this transaction's nonce | holds the nonce; the *intent* payload is still executable until it expires |
//! | **Reorg** | `log.removed`, or a block hash that is no longer canonical | a `confirmed` row goes back to `submitted` and its nonce back to `allocated` |
//! | **External fulfillment** | an `ExecutedLog` for our `intentId` whose transaction hash is not ours | marked fulfilled, **never** rebroadcast |
//! | **Receipt timeout** | no receipt past the caller's deadline, frontier says nothing | outcome **UNKNOWN** â€” its own state, and the user is never told no fee was charged |
//!
//! ## Why revert / drop / receipt-timeout converge on one durable action
//!
//! Stated rather than hidden: all three write the *same* rows â€” the attempt
//! goes back to `reserved` with a lease that makes it immediately visible to
//! [`super::outbox::sweep_stuck_reservations`], and **nothing at all is written
//! to `nonce_allocations`**. That is not the three states collapsing into one.
//! It is that the *safe* action is identical in all three (spec Â§8.2: the
//! signed payload stays executable until the intent expires, so the nonce slot
//! must be held), while what we may honestly *say* differs completely â€” see
//! [`AttemptDisposition::user_message`]. Releasing the nonce is delegated to
//! the sweeper because the sweeper already implements the one condition under
//! which releasing is provably safe: `intentUsed(intentId) == false` **and**
//! the intent expired on the **chain** clock. Reimplementing that here would be
//! a second, untested copy of the only decision in this subsystem that can burn
//! relayer ETH.
//!
//! This is also why a mined revert is **not** routed through
//! `submit::record_failed`. `record_failed` releases the reservation
//! immediately, which is correct for a *broadcast* failure â€” nothing that could
//! execute ever left the process â€” and wrong for a *mined* revert, where a
//! signed payload is loose in the world.
//!
//! # Where it runs: [`super::maintenance`]'s pass, since Task 11 Wave D
//!
//! **Corrected 2026-07-27 (Task 11 Wave D).** This section used to open: "This
//! module is still a callable, tested primitive with **no production caller** â€”
//! `grep -rn` finds its observers referenced only from `mod tests`." Recorded
//! rather than deleted, same discipline as the corrections below.
//!
//! [`reconcile_executed_log`] now has exactly one production caller:
//! [`super::maintenance::run_reconcile`], the third step of every maintenance
//! pass. Wave C mounting `POST /v1/stream-g/submit` is what made the gap
//! urgent â€” a successfully broadcast enrollment had no path to `executed` at
//! all, and the sweeper could not release its row until the parent intent
//! expired on the chain clock.
//!
//! What that caller does **not** do, and why, is stated on its own doc: it never
//! calls [`super::submit::reconcile_executed_for_profile_id`] directly (the fold
//! performs no chain read and would confirm at depth 0), it never constructs an
//! `AuthenticatedProfileId` (a background worker has no credential to prove, so
//! [`super::submit::reconcile_sponsored_enrollment_executed`] remains unused by
//! production), and it cannot reach [`apply_reorg`] (see that function â€” a
//! polling `eth_getLogs` never returns `removed: true`, so **confirmation depth
//! is the entire reorg protection**).
//!
//! **Corrected 2026-07-25 (Task 8).** The three supporting claims that used to
//! appear here were true when written and are now false; they are recorded
//! rather than quietly deleted, because a stale "nothing is wired" doc is
//! exactly how a reader concludes more is disabled than actually is:
//!
//! * `tokio::spawn` **does** now appear in production â€” in
//!   `main::cmd_serve_relayer`'s Stream-G arm, which spawns
//!   `stream_g::runtime::terminate_signal` as the shutdown-signal handler â€”
//!   and in [`super::maintenance`]'s loop.
//! * `axum::serve` **is** now called with `.with_graceful_shutdown(..)`, but
//!   only on the Stream-G-enabled arm; the pilot arm is byte-identical to what
//!   it was.
//! * Stream G **does** mount routes. At the time of that correction there
//!   were two, `GET /v1/stream-g/ready` and `GET /v1/stream-g/metrics`; the
//!   router now has ten (this line said "nine" until `POST /v1/stream-g/submit`
//!   mounted â€” [`super`]'s module doc is the authority and already said ten),
//!   including the pipeline's first two entry points
//!   (`POST /v1/stream-g/quotes` and `GET /v1/stream-g/status/:intentId`).
//!   **No HTTP route reaches this module**, and that is still true after Wave
//!   D: quoting signs and persists, the status route only reads rows, and the
//!   submit route stops at the broadcast. Reconciliation is reached from the
//!   background pass and from nowhere else, so no request body can steer it.
//!
//! Nothing here reads an env var at call time â€” [`FinalityPolicy`] is
//! constructed from a caller-supplied map, or (in the background pass) from the
//! already-validated `StreamGConfig` value via
//! [`FinalityPolicy::from_confirmations`].
//!
//! **Corrected 2026-07-26 (Wave 3).** This paragraph used to continue:
//! "**`STREAM_G_CONFIRMATIONS` is not yet threaded through `config.rs`** (Task
//! 8 added `STREAM_G_SWEEP_*` but not this one), so ratified decision A3 â€” 1
//! confirmation on `31337`, 12 remote, env-tunable â€” has no production path
//! today." Recorded rather than deleted, same discipline as the correction
//! below. The first clause is now false: [`crate::config::StreamGConfig`] has
//! a `confirmations` field, parsed from [`ENV_CONFIRMATIONS`], defaulted per A3
//! from the configured `CHAIN_ID`, and refusing `0` by calling
//! [`FinalityPolicy::from_map`] rather than reimplementing the bound.
//!
//! **Corrected 2026-07-27 (Task 11 Wave D): A3 is now CLOSED for this lane.**
//! The paragraph here used to read "**What did NOT change: A3 remains OPEN.**
//! The config field is parsed and **consumed by nothing.**", and listed three
//! reasons the wiring stopped: no production caller of
//! [`reconcile_executed_log`], no production caller of
//! `ChainClient::sponsored_enrollment_logs`, and no durable block cursor
//! (`store_meta` being a `CHECK (id = 1)` singleton and `0001` frozen, so a
//! cursor meant "a new additive migration â€” a founder-level scope decision
//! nobody has taken"). All three are now false, in that order:
//!
//! * [`super::maintenance::run_reconcile`] calls [`reconcile_executed_log`]
//!   with a policy built from `StreamGConfig::confirmations`, so
//!   `STREAM_G_CONFIRMATIONS` changes what this attestor will act on rather than
//!   only whether config load succeeds;
//! * that same function is the production caller of
//!   `sponsored_enrollment_logs`;
//! * the migration was taken. `migrations/0003_stream_g_scan_cursor.sql` adds
//!   `stream_g_scan_cursors` â€” a new table, deliberately not a widened
//!   `store_meta` â€” and `store::SCHEMA_VERSION` moved 2 â†’ 3.
//!
//! âš ï¸ **What closing A3 does NOT mean.** Depth is now enforced; reorg *recovery*
//! is not, and cannot be under polling. [`apply_reorg`] is unreachable from the
//! observer, nothing persists a confirmed row's block hash, and the durable
//! event id is `sha256(domain | profile | intentId | txHash)` with no block
//! number in it. So a reorg deeper than the configured depth leaves a
//! permanently wrong `confirmed` row with no detector. Do not describe this
//! subsystem as handling reorgs. See
//! [`super::maintenance::MaintenancePolicy::confirmations`] for why `2` is not a
//! safe number on a live L2 under this design and `12` is.
//!
//! `crate::config::Config::confirmation_depth` â€” the *pilot* relayer's
//! confirmation knob â€” is still threaded through `config.rs`, documented in
//! `.env.example`, and read by nothing. That one is untouched by this wave and
//! remains an open defect.
//!
//! # Store discipline
//!
//! Chain reads happen **between** transactions, never inside one: the store's
//! pool has a single connection and a hanging RPC must not hold SQLite's writer
//! lock. Every function below either reads the chain and returns, or writes the
//! store and returns â€” none does both inside a `write_tx` closure.

use std::collections::HashMap;

use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use thiserror::Error;

use super::crypto_store::{self, DataKey, EnvelopeAad, SecretHex};
use super::models::ActionType;
use super::outbox::NONCE_KIND_ACTION;
use super::store::{StreamGStore, StreamGStoreError};
use super::submit::{
    action_nonce_signer_key, reconcile_executed_for_profile_id, SponsoredEnrollmentExecuted,
    SubmitError, INTENT_STATUS_EXECUTED, INTENT_STATUS_SUBMITTED, NONCE_STATUS_ALLOCATED,
    NONCE_STATUS_CONSUMED, NONCE_STATUS_RELEASED, TX_ATTEMPT_STATUS_CONFIRMED,
    TX_ATTEMPT_STATUS_RESERVED, TX_ATTEMPT_STATUS_SUBMITTED,
};
use super::token_manifest::TrustedChain;
use crate::chain::ExecutedLog;

// ---------------------------------------------------------------------------
// Error codes (stable strings for logs / HTTP mapping), same convention as
// `submit.rs` and `outbox.rs`.
// ---------------------------------------------------------------------------

pub const ERR_RECONCILE_STORE: &str = "RECONCILE_STORE_ERROR";
pub const ERR_RECONCILE_CHAIN: &str = "RECONCILE_CHAIN_ERROR";
/// The chain's durable state **contradicts** the log. Permanent; this is the
/// code a quarantine row carries.
///
/// The string is deliberately the one the pre-2026-07-27 single `UnverifiedLog`
/// variant used, so quarantine rows already written keep their meaning: every
/// row that carries it was, and still is, a log the observer stepped over.
pub const ERR_RECONCILE_UNVERIFIED_LOG: &str = "RECONCILE_UNVERIFIED_LOG";
/// The chain has **not yet** corroborated the log. Transient; never quarantined,
/// so this code can never appear in a `reconciliation_events` quarantine row â€”
/// only in a log line and in the `reconcile_stalled_logs` counter.
pub const ERR_RECONCILE_UNCORROBORATED_LOG: &str = "RECONCILE_UNCORROBORATED_LOG";
pub const ERR_RECONCILE_AMBIGUOUS: &str = "RECONCILE_AMBIGUOUS_CANDIDATES";
pub const ERR_RECONCILE_CONFIG: &str = "RECONCILE_CONFIG_ERROR";
pub const ERR_RECONCILE_SUBMIT: &str = "RECONCILE_SUBMIT_ERROR";

/// `reconciliation_events.event_type` for a disposition this module recorded
/// from a **receipt**, as opposed to `submit.rs`'s
/// [`super::submit::RECONCILIATION_EVENT_TYPE`], which records the gateway's
/// own success event. Distinct on purpose: one is "the chain emitted this",
/// the other is "we concluded this".
pub const DISPOSITION_EVENT_TYPE: &str = "AttemptDisposition";

/// `reconciliation_events.event_type` for a reorg that removed a log we had
/// already acted on.
pub const REORG_EVENT_TYPE: &str = "SponsoredEnrollmentExecuted.removed";

/// `reconciliation_events.event_type` for a log the observer could **not**
/// fold and has therefore stepped over permanently. See
/// [`quarantine_unfoldable_log`].
pub const QUARANTINE_EVENT_TYPE: &str = "SponsoredEnrollmentExecuted.quarantined";

const DISPOSITION_ID_DOMAIN: &str = "stream_g_sponsored_enrollment_disposition";
const REORG_ID_DOMAIN: &str = "stream_g_sponsored_enrollment_reorg";
const QUARANTINE_ID_DOMAIN: &str = "stream_g_sponsored_enrollment_quarantine";

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ReconcileError {
    #[error("store error: {0}")]
    Store(#[from] StreamGStoreError),
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("submit error: {0}")]
    Submit(#[from] SubmitError),
    /// An RPC could not be asked. **Never** downgraded to "the answer was no":
    /// every caller of a chain read in this module propagates this rather than
    /// treating a failure as evidence.
    #[error("chain read failed: {0}")]
    Chain(String),
    /// The chain's durable state **contradicts** this log: a receipt sitting in
    /// exactly the block *and* block hash the log names, reporting `status == 0`.
    /// Both readings are then of the same block, so they cannot be two views of
    /// two forks â€” a transaction that reverted in a block cannot have emitted a
    /// success event in that same block. No retry can change that, because the
    /// block is already buried below the confirmation depth by the time the
    /// window contains it. **This is the only chain-corroboration failure that
    /// may be quarantined**; see [`ReconcileErrorScope`].
    ///
    /// Refused before any row is touched.
    #[error("this log is contradicted by the chain: {reason}")]
    ContradictedLog { reason: String },
    /// The chain has **not yet** corroborated this log â€” and has not
    /// contradicted it either. Three readings produce this, and none of them is
    /// a property of durable state:
    ///
    /// * `eth_getTransactionReceipt` returned `null`. The ordinary cause is a
    ///   replica behind the one that served `eth_getLogs`; the next pass, or the
    ///   next replica, has it.
    /// * the receipt's block number, or its block hash, is not the one the log
    ///   claims. Under a reorg deeper than `confirmations` â€” or simply with the
    ///   log and the receipt answered by two replicas mid-reorg â€” the two
    ///   readings straddle a fork. Which one survives is not knowable from here,
    ///   and `confirmations` is operator-set, so "deeper than the configured
    ///   depth" is not a hypothetical.
    ///
    /// ðŸ”´ **Never quarantined.** Quarantining advances the cursor, nothing
    /// re-reads behind the cursor, and this failure class provably *can* succeed
    /// on a later pass â€” an auditor demonstrated exactly that on 2026-07-27 by
    /// arming a receipt between two passes over identical input. Holding the
    /// cursor is a stall; stepping over it is a lost confirmation, and only one
    /// of those is recoverable by an operator.
    #[error("this log is not corroborated by the chain yet: {reason}")]
    UncorroboratedLog { reason: String },
    /// More than one stored attempt claims the same transaction hash. Impossible
    /// through `tx_hash` (partial UNIQUE index) but reachable through
    /// `raw_tx_hash`, which has no such index, e.g. if two rows were ever
    /// seeded with the same signed payload. Fail closed rather than pick one.
    #[error("{count} stored attempts claim transaction {tx_hash_hex}; refusing to guess")]
    AmbiguousCandidates { count: usize, tx_hash_hex: String },
    #[error("{key}={value} is not a usable finality setting: {reason}")]
    BadConfig {
        key: &'static str,
        value: String,
        reason: &'static str,
    },
}

/// What a per-log `Err` licenses the scan window to do with its cursor.
///
/// ðŸ”´ **This is a durability decision, not a classification nicety**, and it is
/// three-valued rather than two-valued because the two-valued version shipped a
/// defect: a boolean forced "this log failed" and "this log failed *forever*"
/// into one answer, and every chain-corroboration failure was filed under
/// *forever*.
///
/// The rule that orders the three, stated once so no arm has to re-derive it:
/// **never silently drop a confirmation.** A held cursor is a stall an operator
/// can see and clear; a quarantined-and-skipped log is gone, because nothing
/// ever re-reads history behind the cursor. When in doubt an arm is
/// [`LogTransient`](Self::LogTransient).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileErrorScope {
    /// This log, and it cannot succeed on any future pass â€” the answer is a
    /// pure function of durable state (stored rows, or chain history at a block
    /// already buried below the confirmation depth).
    ///
    /// `maintenance::scan_and_fold` quarantines it and **advances the cursor
    /// past it**. That is the one arm that accepts permanent loss of whatever
    /// the log would have said, and it is why the membership below is spelled
    /// out variant by variant rather than as a catch-all.
    LogPermanent,
    /// This log, but the failure is a reading of a chain that has not settled
    /// (or of a replica that has not caught up). The identical input can, and in
    /// the ordinary case will, succeed on a later pass.
    ///
    /// `scan_and_fold` **holds the cursor** and keeps folding the rest of the
    /// window â€” the stall is scoped to the blocks at and after this log, not to
    /// the other logs in it. Counted as `reconcile_stalled_logs` and warned on
    /// every pass, so "stalled and retrying" is distinguishable from "dropped
    /// and never coming back" from the metrics alone.
    LogTransient,
    /// Not about this log at all â€” an RPC that could not be asked, a store that
    /// could not be written, a configuration that is unusable. Every log in the
    /// window would fail identically, so the window is aborted and the cursor
    /// left where it was.
    Environment,
}

impl ReconcileError {
    pub fn code(&self) -> &'static str {
        match self {
            ReconcileError::Store(_) | ReconcileError::Sqlx(_) => ERR_RECONCILE_STORE,
            ReconcileError::Submit(_) => ERR_RECONCILE_SUBMIT,
            ReconcileError::Chain(_) => ERR_RECONCILE_CHAIN,
            ReconcileError::ContradictedLog { .. } => ERR_RECONCILE_UNVERIFIED_LOG,
            ReconcileError::UncorroboratedLog { .. } => ERR_RECONCILE_UNCORROBORATED_LOG,
            ReconcileError::AmbiguousCandidates { .. } => ERR_RECONCILE_AMBIGUOUS,
            ReconcileError::BadConfig { .. } => ERR_RECONCILE_CONFIG,
        }
    }

    /// Which of the three things a scan window may do about this error.
    ///
    /// Deliberately **not** derived from [`code`](Self::code): the two answer
    /// different questions, and a `Submit` error is one code but two scopes.
    ///
    /// âš ï¸ **Corrected 2026-07-27.** This was `is_log_attributable() -> bool`,
    /// and it answered `true` for *every* `UnverifiedLog`, which at the time
    /// covered a missing receipt and both block-identity mismatches. An auditor
    /// proved by execution that those are retryable: with the fixture's receipt
    /// set to `Ok(None)` a pass reported `quarantined: 1, cursor_advanced:
    /// true` and left the attempt `submitted`; arming the receipt and re-running
    /// the *same* input reported `quarantined: 0` and `confirmed`. So the
    /// invariant [`quarantine_unfoldable_log`] rests on â€” "only failures that
    /// provably cannot succeed on a retry may reach it" â€” was false as
    /// implemented, and the wedge fix had traded a visible stall for silent
    /// data loss. Splitting `UnverifiedLog` into
    /// [`ReconcileError::ContradictedLog`] and
    /// [`ReconcileError::UncorroboratedLog`] is what makes it true.
    pub fn scope(&self) -> ReconcileErrorScope {
        match self {
            // The receipt sits in exactly the block and block hash this log
            // names and says the transaction reverted. One block, two readings,
            // and they contradict: no later pass can reconcile them.
            ReconcileError::ContradictedLog { .. } => ReconcileErrorScope::LogPermanent,
            // Two stored rows claim one transaction hash. A pure function of
            // rows this observer never writes; only an operator can resolve it.
            // Quarantining does not lose a confirmation an operator could
            // otherwise have had â€” the ambiguity survives the retry, and the
            // durable quarantine row is how the operator learns of it.
            ReconcileError::AmbiguousCandidates { .. } => ReconcileErrorScope::LogPermanent,
            // ðŸ”´ No receipt yet, or a receipt from a different block than the
            // log. A lagging replica and a reorg deeper than the configured
            // `confirmations` both produce this, and both clear. Hold.
            ReconcileError::UncorroboratedLog { .. } => ReconcileErrorScope::LogTransient,
            // The node could not be asked. NOT this log's fault.
            ReconcileError::Chain(_) => ReconcileErrorScope::Environment,
            // Our own database. NOT this log's fault, and stepping over a log
            // because SQLite was busy would be data loss.
            ReconcileError::Store(_) | ReconcileError::Sqlx(_) => ReconcileErrorScope::Environment,
            // A refusal by the fold. Split, because `SubmitError` spans two
            // scopes: the deterministic refusals are about this event and this
            // intent's rows, while store/crypto/lease failures are about the
            // process.
            ReconcileError::Submit(e) => {
                if matches!(
                    e,
                    SubmitError::IntentNotFound
                        | SubmitError::QuoteNotFound
                        | SubmitError::ReconcileMismatch { .. }
                        | SubmitError::MalformedPayload(_)
                        | SubmitError::NonceOutOfRange(_)
                ) {
                    ReconcileErrorScope::LogPermanent
                } else if matches!(e, SubmitError::ReconcileUnverifiable { .. }) {
                    // ðŸ”´ NOT permanent, and the fold that raises it says so in
                    // two places. `submit.rs` distinguishes "no `tx_hash` at
                    // all for any attempt" â€” which its own comment calls
                    // *recoverable, hand it to the sweeper* â€” from "we have
                    // evidence and it is for a different transaction", which
                    // is `ReconcileMismatch` and IS permanent. This variant is
                    // the first case, its `reason` string ends "so chain
                    // evidence must resolve it first", and
                    // `SubmitError::retryability` returns `Ambiguous`, not a
                    // terminal verdict.
                    //
                    // It was classified `LogPermanent` until this change,
                    // which quarantined it and advanced the cursor past a
                    // confirmation the sweeper was about to make foldable â€”
                    // the same silent-loss shape that `UncorroboratedLog` was
                    // split out to stop, in a second place. Holding the cursor
                    // costs a repeated scan; quarantining costs the
                    // confirmation, permanently, because nothing reads behind
                    // the cursor.
                    ReconcileErrorScope::LogTransient
                } else {
                    ReconcileErrorScope::Environment
                }
            }
            // `STREAM_G_CONFIRMATIONS` is unusable. Every log in every window
            // fails identically, so quarantining them one by one would empty
            // the chain into the quarantine table.
            ReconcileError::BadConfig { .. } => ReconcileErrorScope::Environment,
        }
    }
}

// ---------------------------------------------------------------------------
// Small helpers (this tree's convention: each `stream_g` module keeps its own).
// ---------------------------------------------------------------------------

fn deterministic_id(parts: &[&str]) -> String {
    hex::encode(Sha256::digest(parts.join("|").as_bytes()))
}

fn bytes32_hex(b: [u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Case- and `0x`-insensitive hex comparison, the same normalisation
/// `submit.rs`'s `signature_eq` performs. A stored hash and an RPC-supplied
/// hash routinely differ only in case, and a byte-for-byte `==` on the strings
/// would silently classify our own transaction as somebody else's.
fn hash_eq(a: &str, b: &str) -> bool {
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
// Finality (architect assumption A3).
// ---------------------------------------------------------------------------

/// Anvil / the local dev chain. Mirrors the in-tree `chain_id`-conditional
/// precedent at `rpc_chain.rs`'s genesis-scan refusal rather than inventing a
/// second policy shape.
pub const ANVIL_CHAIN_ID: u64 = 31337;

/// Confirmations required on [`ANVIL_CHAIN_ID`]. Anvil mines on demand and does
/// not reorg, so the containing block is the only confirmation there is.
pub const ANVIL_CONFIRMATIONS: u64 = 1;

/// Confirmations required everywhere else (A3).
pub const DEFAULT_CONFIRMATIONS: u64 = 12;

/// Env key Task 8 wires through `config.rs`. Read from a caller-supplied map,
/// never from `std::env` inside this module â€” a security-relevant depth that a
/// library function silently sources from the ambient process environment is a
/// setting nobody can see at the call site.
pub const ENV_CONFIRMATIONS: &str = "STREAM_G_CONFIRMATIONS";

/// How deep a log must be buried before this attestor will act on it.
///
/// Nothing in the contracts encodes finality â€” the only reorg anchor on chain
/// is `NonceSnapshot.blockNumber` â€” so this is a policy, and it is stated as
/// one rather than hidden in a comparison somewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityPolicy {
    confirmations: u64,
}

impl FinalityPolicy {
    /// A3's default for a chain id.
    pub fn for_chain(chain_id: u64) -> Self {
        Self {
            confirmations: if chain_id == ANVIL_CHAIN_ID {
                ANVIL_CONFIRMATIONS
            } else {
                DEFAULT_CONFIRMATIONS
            },
        }
    }

    /// [`for_chain`](Self::for_chain), with [`ENV_CONFIRMATIONS`] overriding it
    /// when the map carries a usable value.
    ///
    /// **Zero is refused.** "0 confirmations" means "act on a log before any
    /// block has buried it", i.e. treat an unmined event as settled, which is
    /// the one setting that makes every reorg check below a no-op. An operator
    /// who wants the loosest safe setting writes `1`.
    pub fn from_map(map: &HashMap<String, String>, chain_id: u64) -> Result<Self, ReconcileError> {
        let Some(raw) = map.get(ENV_CONFIRMATIONS) else {
            return Ok(Self::for_chain(chain_id));
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(Self::for_chain(chain_id));
        }
        let parsed: u64 = trimmed.parse().map_err(|_| ReconcileError::BadConfig {
            key: ENV_CONFIRMATIONS,
            value: raw.clone(),
            reason: "not a non-negative integer",
        })?;
        if parsed == 0 {
            return Err(ReconcileError::BadConfig {
                key: ENV_CONFIRMATIONS,
                value: raw.clone(),
                reason: "0 would accept an unmined log as final; the minimum is 1",
            });
        }
        Ok(Self {
            confirmations: parsed,
        })
    }

    /// Rebuild a policy from a confirmation count that has **already** been
    /// validated â€” in practice [`crate::config::StreamGConfig::confirmations`],
    /// which is itself produced by [`FinalityPolicy::from_map`] and therefore
    /// cannot be `0`.
    ///
    /// This is the constructor that finally makes `STREAM_G_CONFIRMATIONS`
    /// *consumed* (ratified decision A3) rather than merely parsed:
    /// `maintenance::MaintenancePolicy::from_config` carries the config value
    /// through to `maintenance::run_reconcile`, which rebuilds the policy here.
    ///
    /// **Do not use this to bypass [`from_map`](Self::from_map).** It takes a
    /// number, not an operator string, so it cannot produce the refusal an
    /// operator is entitled to see for `0`; the `.max(1)` below is a
    /// belt-and-braces floor for a caller that skipped validation, never a
    /// silent rewrite of a value a human typed. Prefer `from_map` at every
    /// boundary that reads an environment.
    pub fn from_confirmations(confirmations: u64) -> Self {
        Self {
            confirmations: confirmations.max(1),
        }
    }

    pub fn confirmations(self) -> u64 {
        self.confirmations
    }

    /// How many confirmations a log mined in `log_block` has when the head is
    /// `head`. **The containing block counts as the first confirmation**, so a
    /// log in the head block has depth 1, not 0.
    ///
    /// `None` when `head < log_block`: a log from the future is not "zero
    /// confirmations", it is an inconsistent pair of readings, and collapsing
    /// it to 0 with a `saturating_sub` would hide that.
    pub fn depth(log_block: u64, head: u64) -> Option<u64> {
        head.checked_sub(log_block).map(|d| d + 1)
    }

    pub fn is_final(self, log_block: u64, head: u64) -> bool {
        Self::depth(log_block, head).is_some_and(|d| d >= self.confirmations)
    }
}

// ---------------------------------------------------------------------------
// Reverse lookup (brief Â§3.2).
// ---------------------------------------------------------------------------

/// One stored attempt that *might* be the one an observed log belongs to.
///
/// "Might" is the whole point. A log carries only the on-chain `intentId`, and
/// both `intents.id` and `tx_attempts.id` are SHA-256 **over the profile id**,
/// with no plaintext intentId column on `intents` at all â€” so there is no
/// function from an intentId back to a row. `0002` added the non-unique,
/// indexed `tx_attempts.intent_id_hex` to make the lookup possible without
/// making it *unique*: two profiles quoting the same on-chain intentId is a
/// deliberate security property (a global binding would let any authenticated
/// profile squat any 32-byte intentId for everybody â€” defect C2, guarded by
/// `quotes::tests::two_profiles_can_quote_the_same_onchain_intent_id_without_colliding`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptCandidate {
    pub attempt_id: String,
    /// Read off the joined `intents` row, never supplied by a caller. This is
    /// `fulfill`'s litigated model: the intent row is the sole authority on who
    /// owns the work.
    pub profile_id: String,
    pub intent_row_id: String,
    pub allocation_id: Option<String>,
    /// `nonce_allocations.signer_address` for the `kind='action'` row â€” the
    /// `"<0xcontroller>#<ACTION>"` synthetic key. Used to decide whether an
    /// externally-fulfilled intent actually advanced *this* candidate's
    /// on-chain action nonce.
    pub signer_address: Option<String>,
    pub status: String,
    /// Set only once a node acknowledged the transaction.
    pub tx_hash: Option<String>,
    /// Set as soon as the payload was signed, before any broadcast.
    pub raw_tx_hash: Option<String>,
}

impl AttemptCandidate {
    /// Does this candidate name `tx_hash_hex`, by either hash column?
    pub fn claims_tx_hash(&self, tx_hash_hex: &str) -> bool {
        [self.tx_hash.as_deref(), self.raw_tx_hash.as_deref()]
            .into_iter()
            .flatten()
            .any(|h| hash_eq(h, tx_hash_hex))
    }
}

/// The Â§3.2 reverse lookup: every stored attempt for this on-chain `intentId`,
/// across all profiles. A **candidate set**, not an answer.
pub async fn candidates_for_intent_id(
    store: &StreamGStore,
    intent_id: [u8; 32],
) -> Result<Vec<AttemptCandidate>, ReconcileError> {
    let intent_id_hex = bytes32_hex(intent_id);
    store
        .read(move |h| {
            Box::pin(async move {
                // The JOIN onto `intents` is the ownership boundary: an attempt
                // whose parent intent row is gone is not a candidate for
                // anything. The nonce join is LEFT and `kind`-filtered â€” a
                // broadcaster-EOA row must never be mistaken for an action
                // nonce (brief Â§3.3).
                let rows = h
                    .fetch_all(
                        sqlx::query(
                            "SELECT a.id AS attempt_id, \
                                    i.profile_id AS profile_id, \
                                    a.intent_id AS intent_row_id, \
                                    a.nonce_allocation_id AS allocation_id, \
                                    n.signer_address AS signer_address, \
                                    a.status AS status, \
                                    a.tx_hash AS tx_hash, \
                                    a.raw_tx_hash AS raw_tx_hash \
                             FROM tx_attempts a \
                             JOIN intents i ON i.id = a.intent_id \
                             LEFT JOIN nonce_allocations n \
                                    ON n.id = a.nonce_allocation_id AND n.kind = ? \
                             WHERE a.intent_id_hex = ? \
                             ORDER BY a.id ASC",
                        )
                        .bind(NONCE_KIND_ACTION)
                        .bind(&intent_id_hex),
                    )
                    .await?;

                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    out.push(AttemptCandidate {
                        attempt_id: row.try_get("attempt_id")?,
                        profile_id: row.try_get("profile_id")?,
                        intent_row_id: row.try_get("intent_row_id")?,
                        allocation_id: row.try_get("allocation_id")?,
                        signer_address: row.try_get("signer_address")?,
                        status: row.try_get("status")?,
                        tx_hash: row.try_get("tx_hash")?,
                        raw_tx_hash: row.try_get("raw_tx_hash")?,
                    });
                }
                Ok::<Vec<AttemptCandidate>, ReconcileError>(out)
            })
        })
        .await
}

/// Pick the one candidate that claims `tx_hash`, or none.
///
/// This is the disambiguation the non-unique `intent_id_hex` index makes
/// necessary. On chain at most one candidate can ever have executed, because
/// `intentUsed[intentId]` is global and single-use â€” so a set of candidates
/// plus the winning transaction hash is a unique answer or an empty one.
///
/// Two matches is [`ReconcileError::AmbiguousCandidates`], not a coin flip.
pub fn disambiguate_by_tx_hash(
    candidates: &[AttemptCandidate],
    tx_hash: [u8; 32],
) -> Result<Option<&AttemptCandidate>, ReconcileError> {
    let tx_hash_hex = bytes32_hex(tx_hash);
    let matches: Vec<&AttemptCandidate> = candidates
        .iter()
        .filter(|c| c.claims_tx_hash(&tx_hash_hex))
        .collect();
    match matches.len() {
        0 => Ok(None),
        1 => Ok(Some(matches[0])),
        count => Err(ReconcileError::AmbiguousCandidates { count, tx_hash_hex }),
    }
}

// ---------------------------------------------------------------------------
// Log-driven reconciliation.
// ---------------------------------------------------------------------------

/// What [`reconcile_executed_log`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogOutcome {
    /// Our transaction, corroborated by a receipt, buried deep enough.
    Confirmed {
        attempt_id: String,
        profile_id: String,
        event_row_id: String,
        tx_hash_hex: String,
        block_number: u64,
    },
    /// The intent executed under a transaction hash none of our candidates
    /// claims. The gateway tolerates this (`_enrollV1OrAcceptFrontRun`), and
    /// `intentUsed[intentId]` is now globally true, so **no** candidate's
    /// payload can ever execute. Nothing is rebroadcast.
    ExternallyFulfilled {
        tx_hash_hex: String,
        /// Candidates marked fulfilled, and whether each one's own action nonce
        /// really was advanced on chain (the log's `controller` matched).
        consumed: Vec<String>,
        released: Vec<String>,
    },
    /// The node says this log was removed by a reorganisation. Every candidate
    /// that had been confirmed goes back to reconciliation.
    Reorged {
        block_hash_hex: String,
        rolled_back: Vec<String>,
    },
    /// Corroborated, but not buried deep enough yet. **Nothing was written.**
    NotFinalYet {
        depth: Option<u64>,
        required: u64,
        block_number: u64,
        head: u64,
    },
    /// No stored attempt has this `intentId` at all â€” a log for somebody else's
    /// intent. Not an error; a log follower sees the whole gateway.
    NoCandidates { intent_id_hex: String },
}

/// Fold one observed `SponsoredEnrollmentExecuted` log into the ledger, after
/// proving to ourselves that the chain actually says what the log claims.
///
/// Order matters and is load-bearing:
///
/// 1. **`removed` first.** A removed log has no receipt to corroborate, so
///    checking the chain before honouring `removed` would turn every reorg into
///    an [`ReconcileError::UncorroboratedLog`] error and leave the stale
///    `confirmed` row in place.
/// 2. **Candidates before chain reads.** A log for an intent we never quoted
///    costs zero RPCs.
/// 3. **Corroborate, then apply finality, then write.** The receipt must exist,
///    must have succeeded, and must sit in the block and block hash the log
///    claims. This is the check that was missing entirely: reconcile used to
///    trust the caller's struct.
///
/// `now_wall` is **wall-clock unix seconds**, threaded in rather than read here
/// so a whole scan window shares one timestamp and so a test can inject one.
/// It is used for `*_at` bookkeeping columns ONLY â€” no release, confirmation or
/// expiry decision in this module reads it. Every such decision reads chain
/// evidence (the receipt, the head, `intentUsed`), which is founder ruling F2.
pub async fn reconcile_executed_log(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    chain: TrustedChain<'_>,
    policy: FinalityPolicy,
    log: &ExecutedLog,
    now_wall: i64,
) -> Result<LogOutcome, ReconcileError> {
    let intent_id_hex = bytes32_hex(log.intent_id);
    let tx_hash_hex = bytes32_hex(log.tx_hash);
    let candidates = candidates_for_intent_id(store, log.intent_id).await?;

    if log.removed {
        let rolled_back = apply_reorg(store, &candidates, log, now_wall).await?;
        return Ok(LogOutcome::Reorged {
            block_hash_hex: bytes32_hex(log.block_hash),
            rolled_back,
        });
    }

    if candidates.is_empty() {
        return Ok(LogOutcome::NoCandidates { intent_id_hex });
    }

    // --- corroborate against chain (outside any transaction) --------------
    let client = chain.client();
    let receipt = client
        .transaction_receipt(log.tx_hash)
        .map_err(|e| ReconcileError::Chain(format!("transaction_receipt({tx_hash_hex}): {e}")))?;
    // ðŸ”´ ORDER IS LOAD-BEARING, and it is not the order this block shipped
    // with. Block **identity** is established before `status` is read, because
    // that is exactly what separates a contradiction from a stale reading:
    //
    //   * a receipt that is absent, or that sits in a different block than the
    //     log, is a reading of a chain (or a replica) that has not settled â€”
    //     `UncorroboratedLog`, hold the cursor, try again;
    //   * a receipt in *this* block and *this* block hash reporting `status ==
    //     0` is two readings of one block that cannot both be true â€”
    //     `ContradictedLog`, and the only one of the four that may be
    //     quarantined.
    //
    // Reading `status` first, as this block used to, made the status-0 case
    // indistinguishable from "the losing side of a fork reverted it", and
    // filing all four under one variant is what let a lagging replica's `null`
    // receipt advance the cursor past a real confirmation.
    let Some(receipt) = receipt else {
        return Err(ReconcileError::UncorroboratedLog {
            reason: format!(
                "no receipt for {tx_hash_hex} yet; this node has not indexed it (a replica behind \
                 the one that served the log is the ordinary cause)"
            ),
        });
    };
    if receipt.block_number != log.block_number {
        return Err(ReconcileError::UncorroboratedLog {
            reason: format!(
                "receipt for {tx_hash_hex} is in block {} but the log claims block {}; the two \
                 readings straddle a fork or two replicas",
                receipt.block_number, log.block_number
            ),
        });
    }
    if receipt.block_hash != log.block_hash {
        return Err(ReconcileError::UncorroboratedLog {
            reason: format!(
                "receipt for {tx_hash_hex} is in block hash {} but the log claims {}; the two \
                 readings straddle a fork or two replicas",
                bytes32_hex(receipt.block_hash),
                bytes32_hex(log.block_hash)
            ),
        });
    }
    if !receipt.success {
        return Err(ReconcileError::ContradictedLog {
            reason: format!(
                "receipt for {tx_hash_hex} is in the very block and block hash this log claims and \
                 has status 0, so no success event could have been emitted by it"
            ),
        });
    }

    let head = client
        .pinned_block_number()
        .map_err(|e| ReconcileError::Chain(format!("pinned_block_number: {e}")))?;
    if !policy.is_final(log.block_number, head) {
        return Ok(LogOutcome::NotFinalYet {
            depth: FinalityPolicy::depth(log.block_number, head),
            required: policy.confirmations(),
            block_number: log.block_number,
            head,
        });
    }

    // --- apply -------------------------------------------------------------
    match disambiguate_by_tx_hash(&candidates, log.tx_hash)? {
        Some(winner) => {
            // A candidate matched by `raw_tx_hash` alone still has
            // `tx_hash NULL`, and `reconcile_executed_for_profile_id`'s
            // unconditional guard rightly refuses such a row. Promote it
            // first â€” but ONLY here, after the receipt above proved this
            // transaction exists, succeeded, and is in the block the log
            // claims. That ordering is the entire difference between the fix
            // and the hole it replaces: the hole let a *caller* supply the
            // hash, this lets the *chain* supply it.
            if winner.tx_hash.is_none() {
                promote_verified_tx_hash(store, &winner.attempt_id, &tx_hash_hex, now_wall).await?;
            }
            let event = SponsoredEnrollmentExecuted {
                intent_id: log.intent_id,
                root: log.root,
                secondary: log.secondary,
                controller: log.controller,
                fee_token: log.fee_token,
                fee_amount: log.fee_amount,
                tx_hash: log.tx_hash,
                block: log.block_number,
            };
            let event_row_id =
                reconcile_executed_for_profile_id(
                    store,
                    data_key_hex,
                    &winner.profile_id,
                    &event,
                    now_wall,
                )
                .await?;
            Ok(LogOutcome::Confirmed {
                attempt_id: winner.attempt_id.clone(),
                profile_id: winner.profile_id.clone(),
                event_row_id,
                tx_hash_hex,
                block_number: log.block_number,
            })
        }
        None => {
            let (consumed, released) =
                apply_external_fulfillment(store, &candidates, log, now_wall).await?;
            Ok(LogOutcome::ExternallyFulfilled {
                tx_hash_hex,
                consumed,
                released,
            })
        }
    }
}

/// The sealed body of one quarantine row. Every field is a **public chain
/// coordinate** plus a stable error code â€” no signed bytes, no session token,
/// no error *message*. It is sealed anyway because `reconciliation_events` has
/// exactly one place to put a body and that place is an `_enc` column with an
/// AAD contract; writing plaintext into it would be the first exception to that
/// contract in the crate.
#[derive(Debug, Serialize)]
struct QuarantineDetails {
    intent_id_hex: String,
    tx_hash_hex: String,
    block_number: u64,
    block_hash_hex: String,
    log_index: u64,
    /// `ReconcileError::code()`, e.g. `RECONCILE_UNVERIFIED_LOG`. The stable
    /// code and **not** the `Display` string, which renders SQL, node text and
    /// stored hashes (spec Â§9.3).
    error_code: String,
}

/// Record that one observed log could not be folded and is being **stepped
/// over permanently**.
///
/// # Why this exists at all
///
/// `maintenance::scan_and_fold` used to propagate the first per-log `Err` out
/// of the whole window, which skipped `save_scan_cursor`. Several `Err`
/// variants are pure functions of durable state
/// ([`ReconcileErrorScope::LogPermanent`]), so that log returned `Err` again
/// on every subsequent pass, forever: the cursor never moved past its block and
/// reconciliation stopped progressing for every profile and every later block,
/// with no self-healing path and nothing on `GET /v1/stream-g/metrics` to
/// distinguish it from "nothing to reconcile".
///
/// The fix advances the cursor past such a log. ðŸ”´ **What that costs, stated
/// plainly: this log is never observed again.** Nothing behind the cursor is
/// ever re-read, so whatever the log would have confirmed stays unconfirmed
/// until an operator acts. That is why the skip is not silent â€” it is a durable
/// row here plus a `reconcile_log_errors` count â€” and why
/// [`ReconcileError::scope`] is deliberately narrow: only failures that
/// provably cannot succeed on a retry are allowed to reach this function.
///
/// âš ï¸ **Corrected 2026-07-27, and the correction is the reason this doc can be
/// trusted now.** The sentence above was written when the classifier was
/// `is_log_attributable() -> bool`, and it was **false as implemented**: every
/// `UnverifiedLog` answered `true`, including a receipt the node simply had not
/// indexed yet. An auditor demonstrated the loss by execution â€” `Ok(None)`
/// receipt â†’ `quarantined: 1, cursor_advanced: true`, attempt left `submitted`;
/// arm the receipt, same input, next pass â†’ `quarantined: 0`, `confirmed`. The
/// confirmation was recoverable and had been thrown away. Only
/// [`ReconcileErrorScope::LogPermanent`] reaches this function now;
/// [`ReconcileErrorScope::LogTransient`] holds the cursor and stalls loudly
/// instead (see `maintenance::scan_and_fold`).
///
/// # Idempotent
///
/// `INSERT OR IGNORE` on a deterministic id over the log's chain coordinates
/// (`block_hash`, `log_index`), which identify a log uniquely on a canonical
/// chain. A window that overlaps an already-quarantined block writes nothing,
/// so the table cannot grow by re-observation.
///
/// `tx_attempt_id` is **NULL**: the whole point of a quarantined log is that we
/// could not attribute it to an attempt. Naming one here would be a guess
/// recorded as evidence.
pub async fn quarantine_unfoldable_log(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    log: &ExecutedLog,
    error_code: &'static str,
    now_wall: i64,
) -> Result<String, ReconcileError> {
    let block_hash_hex = bytes32_hex(log.block_hash);
    let event_row_id = deterministic_id(&[
        QUARANTINE_ID_DOMAIN,
        &block_hash_hex,
        &log.log_index.to_string(),
        &bytes32_hex(log.tx_hash),
    ]);

    let details = QuarantineDetails {
        intent_id_hex: bytes32_hex(log.intent_id),
        tx_hash_hex: bytes32_hex(log.tx_hash),
        block_number: log.block_number,
        block_hash_hex,
        log_index: log.log_index,
        error_code: error_code.to_string(),
    };
    let details_bytes = serde_json::to_vec(&details)
        .map_err(|e| ReconcileError::Submit(SubmitError::MalformedPayload(e.to_string())))?;

    let data_key = DataKey::from_secret(data_key_hex);
    let aad = EnvelopeAad {
        db_uuid: store.db_uuid(),
        schema_version: store.envelope_aad_version(),
        table: "reconciliation_events",
        pk: &event_row_id,
        column: "details_enc",
    };
    let sealed = crypto_store::seal(&data_key, &aad, &details_bytes)
        .map_err(|e| ReconcileError::Submit(SubmitError::from(e)))?;

    let row_id = event_row_id.clone();
    store
        .write_tx(move |tx| {
            Box::pin(async move {
                sqlx::query(
                    "INSERT OR IGNORE INTO reconciliation_events \
                     (id, tx_attempt_id, event_type, status, details_enc, created_at) \
                     VALUES (?, NULL, ?, ?, ?, ?)",
                )
                .bind(&row_id)
                .bind(QUARANTINE_EVENT_TYPE)
                .bind(error_code)
                .bind(&sealed)
                .bind(now_wall)
                .execute(&mut **tx)
                .await?;
                Ok::<(), ReconcileError>(())
            })
        })
        .await?;
    Ok(event_row_id)
}

/// Stamp the chain-verified transaction hash onto a row that never got one, so
/// the unconditional guard in `submit.rs` has something to compare against.
///
/// Guarded on `tx_hash IS NULL` so it can only ever fill a hole, never
/// overwrite a hash a node actually returned.
///
/// âš ï¸ **This function is what falsified a safety argument in `submit.rs`.**
/// The fold's nonce UPDATE used to carry a comment saying the
/// released-then-re-reserved hazard was unreachable "because a released row has
/// `tx_hash` NULL, so the fold refuses it". This call sits on the line
/// immediately before the fold in [`reconcile_executed_log`], and filling that
/// NULL is its entire purpose â€” so the premise does not hold for the fold's only
/// production caller. The hazard is now removed by a predicate on that UPDATE
/// (`AND NOT EXISTS (â€¦ another live attempt holds this slot â€¦)`) rather than by
/// the argument. Do not re-derive the old reasoning from this function's
/// `tx_hash IS NULL` guard: that guard is about not overwriting a node's answer,
/// not about who owns a nonce.
///
/// `now_wall` is **wall-clock unix seconds**, not a block number. Every `*_at`
/// column in `migrations/0001_stream_g.sql` is unix seconds; this used to bind
/// `receipt.block_number` into `submitted_at`, which on Base is ~3Ã—10â· against
/// a real timestamp of ~1.8Ã—10â¹ â€” two orders of magnitude apart, and therefore
/// silently orderable against genuine timestamps in the wrong direction. The
/// block number is still recorded, in the sealed `details_enc` JSON the fold
/// writes.
///
/// âš ï¸ **No `status` or `claim_owner` predicate.** If a sweep has claimed this
/// row and is mid-resolution (its chain reads run outside any transaction, by
/// design), this write takes the row out from under it. The cost is bounded â€”
/// `outbox::update_attempt`'s three-way CAS then matches nothing and the
/// sweeper's apply is a safe no-op, so no nonce is released â€” but the sweep
/// decision is lost and its RPC round trip wasted. `maintenance::run_pass`
/// makes the interleaving structurally impossible by running the sweep and this
/// module's observer as sequential steps of one task; do not move either into a
/// separate `tokio::spawn`.
async fn promote_verified_tx_hash(
    store: &StreamGStore,
    attempt_id: &str,
    tx_hash_hex: &str,
    now_wall: i64,
) -> Result<(), ReconcileError> {
    let attempt_id = attempt_id.to_string();
    let tx_hash_hex = tx_hash_hex.to_string();
    let submitted_at = now_wall;
    store
        .write_tx(move |tx| {
            Box::pin(async move {
                sqlx::query(
                    "UPDATE tx_attempts \
                     SET status = ?, tx_hash = ?, submitted_at = COALESCE(submitted_at, ?), \
                         claim_owner = NULL, lease_until = NULL \
                     WHERE id = ? AND tx_hash IS NULL",
                )
                .bind(TX_ATTEMPT_STATUS_SUBMITTED)
                .bind(&tx_hash_hex)
                .bind(submitted_at)
                .bind(&attempt_id)
                .execute(&mut **tx)
                .await?;
                Ok::<(), ReconcileError>(())
            })
        })
        .await
}

/// Someone else's transaction fulfilled this `intentId`.
///
/// Every candidate is marked fulfilled â€” `intentUsed[intentId]` is global and
/// single-use, so once this log exists no candidate's signed payload can
/// execute, ever.
///
/// The nonce, however, is **not** the same story for every candidate. The
/// gateway advances `actionNonces[signer][actionType]` for the *signer of the
/// winning transaction's intent* only. So a candidate whose action-nonce row
/// belongs to the log's `controller` really did have its nonce consumed on
/// chain; a candidate under a different controller did not, and holding that
/// nonce forever would strand it. The two are told apart by rebuilding the
/// synthetic signer key from the log and comparing.
///
/// `now_wall` is wall-clock unix seconds and is what lands in `confirmed_at` /
/// `released_at`. Both used to receive `log.block_number`, which is not a
/// timestamp: `migrations/0001_stream_g.sql` declares every `*_at` column as
/// INTEGER unix seconds, and a Base block number (~3Ã—10â·) sorts below every
/// real timestamp (~1.8Ã—10â¹). The block number survives in the human-readable
/// `detail` string, which is where it belongs.
async fn apply_external_fulfillment(
    store: &StreamGStore,
    candidates: &[AttemptCandidate],
    log: &ExecutedLog,
    now_wall: i64,
) -> Result<(Vec<String>, Vec<String>), ReconcileError> {
    let winner_key = action_nonce_signer_key(log.controller, ActionType::SponsoredEnrollment);
    let detail = format!(
        "intentUsed({}) is true under transaction {} in block {}, which this attestor did not \
         broadcast (external fulfillment). Not rebroadcast.",
        bytes32_hex(log.intent_id),
        bytes32_hex(log.tx_hash),
        log.block_number
    );
    let rows: Vec<AttemptCandidate> = candidates.to_vec();

    store
        .write_tx(move |tx| {
            Box::pin(async move {
                let mut consumed = Vec::new();
                let mut released = Vec::new();
                for row in rows {
                    let updated = sqlx::query(
                        "UPDATE tx_attempts \
                         SET status = ?, error_message = ?, confirmed_at = ?, \
                             claim_owner = NULL, lease_until = NULL \
                         WHERE id = ? AND status != ?",
                    )
                    .bind(TX_ATTEMPT_STATUS_CONFIRMED)
                    .bind(&detail)
                    .bind(now_wall)
                    .bind(&row.attempt_id)
                    .bind(TX_ATTEMPT_STATUS_CONFIRMED)
                    .execute(&mut **tx)
                    .await?;
                    if updated.rows_affected() != 1 {
                        // Already confirmed: idempotent replay of the same log.
                        continue;
                    }

                    sqlx::query("UPDATE intents SET status = ? WHERE id = ?")
                        .bind(INTENT_STATUS_EXECUTED)
                        .bind(&row.intent_row_id)
                        .execute(&mut **tx)
                        .await?;

                    let Some(allocation_id) = row.allocation_id.as_deref() else {
                        continue;
                    };
                    let ours = row
                        .signer_address
                        .as_deref()
                        .is_some_and(|s| s.eq_ignore_ascii_case(&winner_key));
                    let (status, released_at) = if ours {
                        (NONCE_STATUS_CONSUMED, None)
                    } else {
                        (NONCE_STATUS_RELEASED, Some(now_wall))
                    };
                    sqlx::query(
                        "UPDATE nonce_allocations \
                         SET status = ?, released_at = ?, claim_owner = NULL, lease_until = NULL \
                         WHERE id = ? AND kind = ?",
                    )
                    .bind(status)
                    .bind(released_at)
                    .bind(allocation_id)
                    .bind(NONCE_KIND_ACTION)
                    .execute(&mut **tx)
                    .await?;
                    if ours {
                        consumed.push(row.attempt_id);
                    } else {
                        released.push(row.attempt_id);
                    }
                }
                Ok::<(Vec<String>, Vec<String>), ReconcileError>((consumed, released))
            })
        })
        .await
}

/// A reorg took back a log we had already acted on.
///
/// Every candidate currently `confirmed` returns to `submitted` and its action
/// nonce from `consumed` back to `allocated`. `released` is deliberately not a
/// destination: the transaction may be re-mined in the new canonical chain, so
/// the slot must stay held â€” a reorg is a reason to *stop being sure*, never a
/// reason to free a nonce.
/// ðŸ”´ `now_wall` is wall-clock unix seconds, and binding it to
/// `reconciliation_events.created_at` is **not cosmetic**. That column used to
/// receive `log.block_number`, and it is the column
/// `submit::get_enrollment_intent` orders by
/// (`ORDER BY r.created_at DESC, r.id DESC`) to pick the disposition
/// `GET /v1/stream-g/status/:intentId` reports. A Base block number (~3Ã—10â·)
/// can never outrank a real unix timestamp (~1.8Ã—10â¹), so a `reorg_removed`
/// event recorded after a `confirmed` one lost the comparison every time and
/// the status route kept reporting `confirmed` for an intent whose confirmation
/// had been rolled back â€”
/// `EnrollmentStatusResponse::latest_disposition`'s own doc promises
/// `DISPOSITION_STATUS_REORGED` is reachable.
///
/// âš ï¸ **Unreachable under polling.** The only trigger for this function is
/// `log.removed`, which `RpcChain::sponsored_enrollment_logs` carries straight
/// through from the RPC response. A historical `eth_getLogs` range query
/// returns canonical logs only; `removed: true` is a filter/subscription
/// artefact. `maintenance::run_reconcile` polls ranges, so it can never reach
/// this path â€” a reorged-out log simply stops being returned. Confirmation
/// depth, not this function, is what protects a polling observer, which is why
/// `MaintenancePolicy::confirmations` is the whole safety mechanism there.
async fn apply_reorg(
    store: &StreamGStore,
    candidates: &[AttemptCandidate],
    log: &ExecutedLog,
    now_wall: i64,
) -> Result<Vec<String>, ReconcileError> {
    let detail = format!(
        "the node reported log {} in block {} (hash {}) as REMOVED by a chain reorganisation; \
         this attempt is back under reconciliation and its outcome is not known",
        log.log_index,
        log.block_number,
        bytes32_hex(log.block_hash)
    );
    let rows: Vec<AttemptCandidate> = candidates.to_vec();
    let event_ids: Vec<String> = rows
        .iter()
        .map(|r| {
            deterministic_id(&[
                REORG_ID_DOMAIN,
                &r.attempt_id,
                &bytes32_hex(log.block_hash),
                &log.log_index.to_string(),
            ])
        })
        .collect();

    store
        .write_tx(move |tx| {
            Box::pin(async move {
                let mut rolled_back = Vec::new();
                for (row, event_id) in rows.into_iter().zip(event_ids) {
                    let updated = sqlx::query(
                        "UPDATE tx_attempts \
                         SET status = ?, confirmed_at = NULL, error_message = ? \
                         WHERE id = ? AND status = ?",
                    )
                    .bind(TX_ATTEMPT_STATUS_SUBMITTED)
                    .bind(&detail)
                    .bind(&row.attempt_id)
                    .bind(TX_ATTEMPT_STATUS_CONFIRMED)
                    .execute(&mut **tx)
                    .await?;
                    if updated.rows_affected() != 1 {
                        continue;
                    }

                    sqlx::query("UPDATE intents SET status = ? WHERE id = ?")
                        .bind(INTENT_STATUS_SUBMITTED)
                        .bind(&row.intent_row_id)
                        .execute(&mut **tx)
                        .await?;

                    if let Some(allocation_id) = row.allocation_id.as_deref() {
                        sqlx::query(
                            "UPDATE nonce_allocations \
                             SET status = ?, released_at = NULL \
                             WHERE id = ? AND kind = ? AND status = ?",
                        )
                        .bind(NONCE_STATUS_ALLOCATED)
                        .bind(allocation_id)
                        .bind(NONCE_KIND_ACTION)
                        .bind(NONCE_STATUS_CONSUMED)
                        .execute(&mut **tx)
                        .await?;
                    }

                    sqlx::query(
                        "INSERT OR IGNORE INTO reconciliation_events \
                         (id, tx_attempt_id, event_type, status, created_at) \
                         VALUES (?, ?, ?, ?, ?)",
                    )
                    .bind(&event_id)
                    .bind(&row.attempt_id)
                    .bind(REORG_EVENT_TYPE)
                    .bind(DISPOSITION_STATUS_REORGED)
                    .bind(now_wall)
                    .execute(&mut **tx)
                    .await?;

                    rolled_back.push(row.attempt_id);
                }
                Ok::<Vec<String>, ReconcileError>(rolled_back)
            })
        })
        .await
}

// ---------------------------------------------------------------------------
// Receipt-driven classification: revert / drop / receipt timeout.
// ---------------------------------------------------------------------------

/// `reconciliation_events.status` values this module records. They are the
/// durable record of *which* of the converging states a row is in, since all
/// three write the same `tx_attempts` columns.
pub const DISPOSITION_STATUS_REVERTED: &str = "mined_revert";
pub const DISPOSITION_STATUS_DROPPED: &str = "dropped";
pub const DISPOSITION_STATUS_UNKNOWN: &str = "receipt_timeout_unknown";
pub const DISPOSITION_STATUS_REORGED: &str = "reorg_removed";

/// One in-flight attempt, as the caller knows it.
///
/// `broadcaster` / `eoa_nonce` are `Option` because the schema cannot supply
/// them: `tx_attempts.nonce_allocation_id` points at the *action* nonce, and
/// the broadcaster EOA nonce lives in a separate `kind='broadcaster'` row with
/// no column joining the two. The caller that broadcast the transaction does
/// know them ([`super::broadcaster::BroadcastOutcome::Accepted`] hands back a
/// `BroadcasterNonce`), so it passes them through. When they are absent, the
/// **drop** state is simply unreachable and classification falls through to
/// the honest "unknown" â€” never to a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAttempt<'a> {
    pub attempt_id: &'a str,
    /// The hash a node acknowledged, or failing that the hash of the signed
    /// payload â€” both identify the same bytes.
    pub tx_hash: [u8; 32],
    pub broadcaster: Option<[u8; 20]>,
    pub eoa_nonce: Option<u64>,
    /// Wall-clock second past which "no receipt yet" stops meaning "slow".
    pub receipt_deadline_wall: i64,
}

/// What the chain says about one in-flight attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptDisposition {
    /// Mined and succeeded. Confirmation still goes through the **event**
    /// ([`reconcile_executed_log`]), never through the receipt alone: the
    /// gateway collects the fee last and emits the event after it, so the event
    /// is the only thing that proves which enrollment actually landed.
    MinedSuccess {
        tx_hash_hex: String,
        block_number: u64,
        block_hash_hex: String,
    },
    /// Mined with status 0. Nothing on chain was consumed â€” `_markIntentAndNonce`
    /// rolled back with the rest of the transaction â€” but the signed intent
    /// payload is still executable by anybody until it expires.
    MinedRevert {
        tx_hash_hex: String,
        block_number: u64,
    },
    /// No receipt, and the broadcaster's **mined** nonce frontier has already
    /// moved past this transaction's nonce, so some other transaction took that
    /// slot and this raw transaction can never be mined.
    Dropped {
        tx_hash_hex: String,
        eoa_nonce: u64,
        frontier: u64,
    },
    /// No receipt, past the deadline, and nothing else the chain said settles
    /// it. **The outcome is unknown.**
    ReceiptTimeoutUnknown { tx_hash_hex: String },
    /// No receipt, but not past the deadline either. Still legitimately in
    /// flight.
    StillPending { tx_hash_hex: String },
}

impl AttemptDisposition {
    /// The honest sentence for a user, and the reason receipt-timeout is a
    /// state of its own rather than a flavour of "failed".
    ///
    /// Spec Â§8.2: on a receipt timeout the service must **not** tell the user
    /// no fee was charged. On a *mined revert* it may, and should â€” a revert
    /// rolls back the fee transfer along with everything else, so that user
    /// really was not charged. Those two sentences are opposites, which is
    /// exactly why the two states cannot share one.
    pub fn user_message(&self) -> &'static str {
        match self {
            AttemptDisposition::MinedSuccess { .. } => {
                "Your enrollment transaction was mined successfully. Waiting for the on-chain \
                 event before it is marked complete."
            }
            AttemptDisposition::MinedRevert { .. } => {
                "The transaction was mined but reverted, so nothing took effect and no fee was \
                 collected from you. You can request a new quote once the previous one expires."
            }
            AttemptDisposition::Dropped { .. } => {
                "The transaction never made it into a block and can no longer be mined. Whether \
                 the enrollment itself still lands is not yet decided, so the request is being \
                 re-checked against the chain."
            }
            // Worded with care. An earlier draft of this string said "do not
            // assume no fee was charged", which reads correctly to a human and
            // is a disaster for anything that scans copy for the claim â€” the
            // literal phrase "no fee was charged" is present in it. The test
            // `a_receipt_timeout_is_unknown_and_never_reported_as_no_fee_charged`
            // caught exactly that on the first run. The claim is now absent,
            // not merely negated.
            AttemptDisposition::ReceiptTimeoutUnknown { .. } => {
                "The outcome of this transaction is not known yet â€” it may still be mined. \
                 Whether it took effect, and whether you were charged, cannot be stated until \
                 this is resolved against the chain."
            }
            AttemptDisposition::StillPending { .. } => {
                "The transaction has been broadcast and is waiting to be mined."
            }
        }
    }

    /// The `reconciliation_events.status` this disposition is recorded under,
    /// or `None` for the two that record nothing because nothing is concluded.
    pub fn recorded_status(&self) -> Option<&'static str> {
        match self {
            AttemptDisposition::MinedRevert { .. } => Some(DISPOSITION_STATUS_REVERTED),
            AttemptDisposition::Dropped { .. } => Some(DISPOSITION_STATUS_DROPPED),
            AttemptDisposition::ReceiptTimeoutUnknown { .. } => Some(DISPOSITION_STATUS_UNKNOWN),
            AttemptDisposition::MinedSuccess { .. } | AttemptDisposition::StillPending { .. } => {
                None
            }
        }
    }
}

/// Ask the chain what happened to one in-flight attempt.
///
/// Fails closed at every step: an RPC error is [`ReconcileError::Chain`] and
/// never a disposition. There is no path from "we could not ask" to any answer
/// at all, which matters because two of the answers below stop a nonce from
/// being held.
pub fn classify_pending_attempt(
    chain: TrustedChain<'_>,
    pending: &PendingAttempt<'_>,
    now_wall: i64,
) -> Result<AttemptDisposition, ReconcileError> {
    let client = chain.client();
    let tx_hash_hex = bytes32_hex(pending.tx_hash);

    let receipt = client
        .transaction_receipt(pending.tx_hash)
        .map_err(|e| ReconcileError::Chain(format!("transaction_receipt({tx_hash_hex}): {e}")))?;

    if let Some(receipt) = receipt {
        return Ok(if receipt.success {
            AttemptDisposition::MinedSuccess {
                tx_hash_hex,
                block_number: receipt.block_number,
                block_hash_hex: bytes32_hex(receipt.block_hash),
            }
        } else {
            AttemptDisposition::MinedRevert {
                tx_hash_hex,
                block_number: receipt.block_number,
            }
        });
    }

    // No receipt. Can the broadcaster's nonce frontier settle it?
    if let (Some(broadcaster), Some(eoa_nonce)) = (pending.broadcaster, pending.eoa_nonce) {
        // `pending = false`: the MINED count. The pending count includes this
        // very transaction while it sits in a mempool, so comparing against it
        // would report a live transaction as dropped.
        let frontier = client
            .transaction_count(broadcaster, false)
            .map_err(|e| ReconcileError::Chain(format!("transaction_count: {e}")))?;
        if frontier > eoa_nonce {
            return Ok(AttemptDisposition::Dropped {
                tx_hash_hex,
                eoa_nonce,
                frontier,
            });
        }
    }

    if now_wall >= pending.receipt_deadline_wall {
        return Ok(AttemptDisposition::ReceiptTimeoutUnknown { tx_hash_hex });
    }
    Ok(AttemptDisposition::StillPending { tx_hash_hex })
}

/// What [`apply_disposition`] wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppliedDisposition {
    /// The attempt was re-queued for the evidence sweeper and its action nonce
    /// was **left held**.
    HeldForSweeper,
    /// Nothing was written â€” the disposition concludes nothing durable.
    NothingToDo,
}

/// Persist a disposition.
///
/// The three concluding states write identical `tx_attempts` columns â€” back to
/// `reserved`, with a lease in the past so the very next
/// [`super::outbox::sweep_stuck_reservations`] pass claims the row â€” and write
/// **nothing whatsoever** to `nonce_allocations`. That absence is the fix, in
/// the same way `submit::record_broadcast_unresolved`'s absence is: the nonce
/// stays held, and only the sweeper's chain-evidence test
/// (`intentUsed == false` **and** the intent expired on the chain clock) may
/// ever release it.
///
/// Compare `submit::record_failed`, which releases immediately. That is correct
/// for a broadcast failure, where nothing that could execute ever left this
/// process, and wrong for every state below, where a signed payload is loose.
pub async fn apply_disposition(
    store: &StreamGStore,
    attempt_id: &str,
    disposition: &AttemptDisposition,
    now_wall: i64,
) -> Result<AppliedDisposition, ReconcileError> {
    let Some(status) = disposition.recorded_status() else {
        return Ok(AppliedDisposition::NothingToDo);
    };
    let attempt_id = attempt_id.to_string();
    let detail = format!("{}: {}", status, disposition.user_message());
    let event_id = deterministic_id(&[DISPOSITION_ID_DOMAIN, &attempt_id, status]);
    // One second in the past, so the row is claimable by the very next sweep
    // rather than after another full TTL. The sweeper's trigger is
    // `lease_until < now`, so "now" itself would not qualify.
    let lease_until = now_wall.saturating_sub(1);

    store
        .write_tx(move |tx| {
            Box::pin(async move {
                // `AND status != 'confirmed'` â€” the same guard
                // `apply_external_fulfillment` and `apply_reorg` already carry,
                // and which this writer was missing. Without it a stale
                // `Dropped` / `ReceiptTimeoutUnknown` classification demotes a
                // `confirmed` row back to `reserved` with a lease in the past
                // and hands it to the sweeper. Narrow today â€” `MinedSuccess` and
                // `StillPending` never get here, because `recorded_status()`
                // returns `None` for them and the caller returned above â€” but
                // the same defect class as the fold's, closed in the same pass.
                sqlx::query(
                    "UPDATE tx_attempts \
                     SET status = ?, error_message = ?, confirmed_at = NULL, \
                         claim_owner = NULL, lease_until = ? \
                     WHERE id = ? AND status != ?",
                )
                .bind(TX_ATTEMPT_STATUS_RESERVED)
                .bind(&detail)
                .bind(lease_until)
                .bind(&attempt_id)
                .bind(TX_ATTEMPT_STATUS_CONFIRMED)
                .execute(&mut **tx)
                .await?;

                sqlx::query(
                    "INSERT OR IGNORE INTO reconciliation_events \
                     (id, tx_attempt_id, event_type, status, created_at) \
                     VALUES (?, ?, ?, ?, ?)",
                )
                .bind(&event_id)
                .bind(&attempt_id)
                .bind(DISPOSITION_EVENT_TYPE)
                .bind(status)
                .bind(now_wall)
                .execute(&mut **tx)
                .await?;

                Ok::<AppliedDisposition, ReconcileError>(AppliedDisposition::HeldForSweeper)
            })
        })
        .await
}

// ---------------------------------------------------------------------------
// Durable scan cursor (migration 0003).
// ---------------------------------------------------------------------------

/// `stream_g_scan_cursors.name` for the `SponsoredEnrollmentExecuted` observer.
///
/// A name rather than a singleton row, so a second observer for a different
/// event can be added without another migration.
pub const SCAN_CURSOR_ENROLLMENT_EXECUTED: &str = "sponsored_enrollment_executed";

/// Highest block **fully folded** by `name`, or `None` when the observer has
/// never run against this database.
///
/// `None` is not `Some(0)`: block 0 is a legitimate cursor value on a lab
/// chain, and collapsing "never scanned" into "scanned up to genesis" would
/// make the seeding decision â€” start at the gateway deploy block â€” unexpressible.
pub async fn load_scan_cursor(
    store: &StreamGStore,
    name: &'static str,
) -> Result<Option<u64>, ReconcileError> {
    let stored: Option<i64> = store
        .read(move |h| {
            Box::pin(async move {
                let v: Option<i64> = h
                    .fetch_optional(
                        sqlx::query("SELECT last_scanned_block FROM stream_g_scan_cursors \
                                     WHERE name = ?")
                        .bind(name),
                    )
                    .await?
                    .map(|row| row.try_get("last_scanned_block"))
                    .transpose()?;
                Ok::<Option<i64>, ReconcileError>(v)
            })
        })
        .await?;
    // A negative value cannot be produced by `save_scan_cursor` (it takes a
    // `u64`), so this can only come from a hand-edited database. Treat it as
    // "no cursor" rather than panicking or saturating to 0 â€” the caller then
    // seeds from the configured deploy block, which is the fail-safe direction.
    Ok(stored.and_then(|v| u64::try_from(v).ok()))
}

/// Record that every log up to and including `last_scanned_block` has been
/// folded.
///
/// **Call this only after the whole window completed without a
/// *window-level* error.** The cursor is the only thing standing between a
/// transient RPC failure and a silently skipped block: leaving it where it was
/// costs one repeated scan (which the idempotent fold absorbs), advancing it
/// past an unfolded block loses that block's confirmations forever, because
/// nothing re-reads history.
///
/// âš ï¸ **Corrected, and it narrows the sentence above.** This doc â€” and
/// `migrations/0003_stream_g_scan_cursor.sql`'s comment, which is frozen and
/// cannot be edited â€” used to say the cursor advances only after every log in
/// the window folded *without error*. Taken literally that is what wedged
/// reconciliation: one log whose `Err` is a pure function of durable state held
/// the cursor for the whole deployment, forever, with no self-healing path.
/// `maintenance::scan_and_fold` now advances past such a log after
/// [`quarantine_unfoldable_log`] records it durably. The invariant that
/// survives, and the one this function's contract actually rests on, is the
/// narrower one: **the cursor never advances past a block whose logs were not
/// accounted for** â€” folded, refused as `NotFinalYet` (which still holds it),
/// stalled as [`ReconcileErrorScope::LogTransient`] (which also holds it), or
/// quarantined. See [`ReconcileError::scope`] for the three-way split.
///
/// `updated_at` is wall-clock unix seconds and is diagnostic only â€” nothing
/// compares it to anything.
///
/// **Monotonic.** The `ON CONFLICT â€¦ DO UPDATE â€¦ WHERE excluded.â€¦ > stored.â€¦`
/// clause makes a lower value a no-op rather than a rewind. Rewinding is the
/// one edit that can lose data here: it would re-scan blocks the fold has
/// already absorbed (harmless) but, if it were ever driven from a value derived
/// from a chain read, it could also move the window off blocks already counted.
/// Refusing to go backwards is cheaper than proving no caller ever tries.
pub async fn save_scan_cursor(
    store: &StreamGStore,
    name: &'static str,
    last_scanned_block: u64,
    now_wall: i64,
) -> Result<(), ReconcileError> {
    let block = i64::try_from(last_scanned_block).unwrap_or(i64::MAX);
    store
        .write_tx(move |tx| {
            Box::pin(async move {
                sqlx::query(
                    "INSERT INTO stream_g_scan_cursors (name, last_scanned_block, updated_at) \
                     VALUES (?, ?, ?) \
                     ON CONFLICT(name) DO UPDATE SET \
                         last_scanned_block = excluded.last_scanned_block, \
                         updated_at = excluded.updated_at \
                     WHERE excluded.last_scanned_block > \
                           stream_g_scan_cursors.last_scanned_block",
                )
                .bind(name)
                .bind(block)
                .bind(now_wall)
                .execute(&mut **tx)
                .await?;
                Ok::<(), ReconcileError>(())
            })
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use crate::chain::{BatchView, ChainClient, ChainError, TxHash as ChainTxHash, TxReceiptView};
    use crate::stream_g::base_fee::{GasUnits, MaxFeePerGas};
    use crate::stream_g::outbox::{
        reserve_and_persist_raw_tx, ReservationRequest, SignedRawTx, DEFAULT_LEASE_TTL_SECONDS,
    };
    use crate::stream_g::submit::{
        intent_row_id, nonce_allocation_row_id, tx_attempt_row_id, TX_ATTEMPT_STATUS_FAILED,
    };

    const PROFILE_A: &str = "profile-reconcile-a";
    const PROFILE_B: &str = "profile-reconcile-b";
    const CHAIN_ID: u64 = 8453;
    const CONTROLLER_A: [u8; 20] = [0xA1; 20];
    const CONTROLLER_B: [u8; 20] = [0xB2; 20];
    const INTENT_ID: [u8; 32] = [0x33; 32];
    const ROOT: [u8; 20] = [0x44; 20];
    const SECONDARY: [u8; 20] = [0x55; 20];
    const FEE_TOKEN: [u8; 20] = [0x66; 20];
    const BLOCK_HASH: [u8; 32] = [0x99; 32];
    const LOG_BLOCK: u64 = 1_000;
    const WALL_NOW: i64 = 1_800_000_000;
    /// The **chain** clock, deliberately far below `WALL_NOW` so that any test
    /// which accidentally used the wall clock where chain time is required
    /// would produce a visibly different answer.
    const CHAIN_NOW: u64 = 1_700_000_000;

    fn data_key_hex() -> SecretHex {
        SecretHex::from_hex(&"cc".repeat(32)).expect("valid 32-byte test key")
    }

    /// ðŸ”´ The classifier that decides whether a scan cursor may step over a
    /// log. All three scopes are asserted, because every mistake is a defect
    /// with no detector: `LogPermanent` on a transient failure loses a real
    /// confirmation permanently; `LogTransient`/`Environment` on a permanent
    /// one restores the wedge that stopped reconciliation for the whole
    /// deployment; `Environment` on a log-scoped transient failure aborts the
    /// window and stops the *other* logs in it folding.
    ///
    /// Mutation this detects: `ReconcileError::scope` returning `LogPermanent`
    /// for `Chain(_)` (the shape a "just skip everything that fails" edit
    /// produces) â€” the RPC arm below then fails. And, the reason this test was
    /// rewritten: returning `LogPermanent` for `UncorroboratedLog`, which is
    /// what shipped until 2026-07-27 and is silent data loss.
    #[test]
    fn only_permanently_unfoldable_logs_are_quarantinable() {
        use ReconcileErrorScope::*;

        // Permanent: a pure function of durable state. Retrying cannot help.
        assert_eq!(
            ReconcileError::ContradictedLog {
                reason: "status 0 in the very block the log claims".into()
            }
            .scope(),
            LogPermanent
        );
        assert_eq!(
            ReconcileError::AmbiguousCandidates {
                count: 2,
                tx_hash_hex: "0xdead".into()
            }
            .scope(),
            LogPermanent
        );
        assert_eq!(
            ReconcileError::Submit(SubmitError::ReconcileMismatch { field: "tx_hash" }).scope(),
            LogPermanent
        );
        assert_eq!(
            ReconcileError::Submit(SubmitError::IntentNotFound).scope(),
            LogPermanent
        );

        // ðŸ”´ Transient BUT log-scoped: hold the cursor, keep folding the rest
        // of the window, never quarantine. This is the arm that did not exist.
        assert_eq!(
            ReconcileError::UncorroboratedLog {
                reason: "no receipt yet".into()
            }
            .scope(),
            LogTransient,
            "a receipt the node has not indexed yet is retryable; quarantining it advances the \
             cursor past a confirmation nothing will ever read again"
        );
        // The second place the same silent-loss shape was hiding. `submit`'s
        // fold raises this from the branch its OWN comment calls "recoverable â€”
        // hand it to the sweeper" (the sibling branch, where a tx_hash exists
        // and disagrees, is `ReconcileMismatch` and is permanent above). Its
        // `reason` ends "so chain evidence must resolve it first", and
        // `SubmitError::retryability` answers `Ambiguous`. It was `LogPermanent`
        // until this assertion existed, and NOTHING failed when that was
        // changed â€” the classification was entirely unpinned, which is how it
        // survived the wave that split `UncorroboratedLog` out for exactly this
        // reason.
        assert_eq!(
            ReconcileError::Submit(SubmitError::ReconcileUnverifiable {
                attempt_id: "att-1".into(),
                reason: "tx_hash is NULL; no node ever acknowledged a transaction for \
                         this attempt, so chain evidence must resolve it first",
            })
            .scope(),
            LogTransient,
            "the sweeper is about to make this foldable; quarantining it drops the confirmation \
             permanently because nothing reads behind the cursor"
        );

        // Environmental: not about any one log, so the whole window waits.
        assert_eq!(
            ReconcileError::Chain("connection refused".into()).scope(),
            Environment
        );
        assert_eq!(
            ReconcileError::Sqlx(sqlx::Error::RowNotFound).scope(),
            Environment
        );
        assert_eq!(
            ReconcileError::Submit(SubmitError::Sqlx(sqlx::Error::RowNotFound)).scope(),
            Environment
        );
        assert_eq!(
            ReconcileError::BadConfig {
                key: ENV_CONFIRMATIONS,
                value: "0".into(),
                reason: "zero confirmations"
            }
            .scope(),
            Environment
        );

        // The two log-scoped codes must stay distinguishable on the wire: the
        // quarantine row's `status` column is `code()`, and only the permanent
        // one can ever appear there.
        assert_eq!(
            ReconcileError::ContradictedLog {
                reason: String::new()
            }
            .code(),
            ERR_RECONCILE_UNVERIFIED_LOG
        );
        assert_eq!(
            ReconcileError::UncorroboratedLog {
                reason: String::new()
            }
            .code(),
            ERR_RECONCILE_UNCORROBORATED_LOG
        );
        assert_ne!(
            ERR_RECONCILE_UNVERIFIED_LOG, ERR_RECONCILE_UNCORROBORATED_LOG,
            "one code for both would make a stall indistinguishable from a drop in the logs"
        );
    }

    // --- chain double ----------------------------------------------------
    //
    // This IS the instance production code receives (threaded in through
    // `TrustedChain`), so every counter asserted below is read off the object
    // the code under test actually called â€” never a test-local stand-in.

    #[derive(Default)]
    struct FakeChainInner {
        receipt: Option<Result<Option<TxReceiptView>, String>>,
        head: Option<Result<u64, String>>,
        tx_count: Option<Result<u64, String>>,
        intent_used: Option<Result<bool, String>>,
        block_timestamp: Option<Result<u64, String>>,
        receipt_calls: usize,
        tx_count_calls: usize,
    }

    struct FakeChain {
        inner: Mutex<FakeChainInner>,
    }

    impl FakeChain {
        /// A chain that corroborates `tx` as a successful mined transaction in
        /// `LOG_BLOCK`/`BLOCK_HASH`, with a head far past finality.
        fn corroborating(tx: [u8; 32]) -> Self {
            Self {
                inner: Mutex::new(FakeChainInner {
                    receipt: Some(Ok(Some(TxReceiptView {
                        tx_hash: tx,
                        block_number: LOG_BLOCK,
                        block_hash: BLOCK_HASH,
                        success: true,
                        gas_used: 21_000,
                    }))),
                    head: Some(Ok(LOG_BLOCK + 100)),
                    tx_count: Some(Ok(0)),
                    intent_used: Some(Ok(false)),
                    block_timestamp: Some(Ok(CHAIN_NOW)),
                    ..FakeChainInner::default()
                }),
            }
        }

        fn set_block_timestamp(&self, v: Result<u64, String>) {
            self.inner.lock().unwrap().block_timestamp = Some(v);
        }

        fn set_receipt(&self, v: Result<Option<TxReceiptView>, String>) {
            self.inner.lock().unwrap().receipt = Some(v);
        }
        fn set_head(&self, v: Result<u64, String>) {
            self.inner.lock().unwrap().head = Some(v);
        }
        fn set_tx_count(&self, v: Result<u64, String>) {
            self.inner.lock().unwrap().tx_count = Some(v);
        }
        fn receipt_calls(&self) -> usize {
            self.inner.lock().unwrap().receipt_calls
        }
        fn tx_count_calls(&self) -> usize {
            self.inner.lock().unwrap().tx_count_calls
        }
    }

    fn unset(what: &str) -> ChainError {
        ChainError::Msg(format!("FakeChain: {what} not armed"))
    }

    impl ChainClient for FakeChain {
        fn propose_batch(
            &self,
            _e: u64,
            _r: [u8; 32],
            _v: [u8; 32],
            _b: u128,
        ) -> Result<ChainTxHash, ChainError> {
            Err(unset("propose_batch"))
        }
        fn challenge_batch(
            &self,
            _e: u64,
            _c: [u8; 32],
            _b: u128,
        ) -> Result<ChainTxHash, ChainError> {
            Err(unset("challenge_batch"))
        }
        fn confirm_epoch(&self, _e: u64) -> Result<ChainTxHash, ChainError> {
            Err(unset("confirm_epoch"))
        }
        fn get_batch(&self, _e: u64) -> Result<BatchView, ChainError> {
            Err(unset("get_batch"))
        }
        fn bind_with_signature(
            &self,
            _w: [u8; 20],
            _u: &str,
            _d: u64,
            _s: &[u8],
        ) -> Result<ChainTxHash, ChainError> {
            Err(unset("bind_with_signature"))
        }
        fn enroll_self_with_signature(
            &self,
            _w: [u8; 20],
            _d: u64,
            _s: &[u8],
        ) -> Result<ChainTxHash, ChainError> {
            Err(unset("enroll_self_with_signature"))
        }

        fn transaction_receipt(
            &self,
            _hash: ChainTxHash,
        ) -> Result<Option<TxReceiptView>, ChainError> {
            let mut g = self.inner.lock().unwrap();
            g.receipt_calls += 1;
            match &g.receipt {
                Some(Ok(r)) => Ok(r.clone()),
                Some(Err(e)) => Err(ChainError::Msg(e.clone())),
                None => Err(unset("transaction_receipt")),
            }
        }

        fn pinned_block_number(&self) -> Result<u64, ChainError> {
            let g = self.inner.lock().unwrap();
            match &g.head {
                Some(Ok(b)) => Ok(*b),
                Some(Err(e)) => Err(ChainError::Msg(e.clone())),
                None => Err(unset("pinned_block_number")),
            }
        }

        fn transaction_count(&self, _a: [u8; 20], _p: bool) -> Result<u64, ChainError> {
            let mut g = self.inner.lock().unwrap();
            g.tx_count_calls += 1;
            match &g.tx_count {
                Some(Ok(n)) => Ok(*n),
                Some(Err(e)) => Err(ChainError::Msg(e.clone())),
                None => Err(unset("transaction_count")),
            }
        }

        fn intent_used(&self, _g: [u8; 20], _i: [u8; 32], _b: u64) -> Result<bool, ChainError> {
            let g = self.inner.lock().unwrap();
            match &g.intent_used {
                Some(Ok(v)) => Ok(*v),
                Some(Err(e)) => Err(ChainError::Msg(e.clone())),
                None => Err(unset("intent_used")),
            }
        }

        fn block_timestamp(&self) -> Result<u64, ChainError> {
            let g = self.inner.lock().unwrap();
            match &g.block_timestamp {
                Some(Ok(t)) => Ok(*t),
                Some(Err(e)) => Err(ChainError::Msg(e.clone())),
                None => Err(unset("block_timestamp")),
            }
        }
    }

    // --- store seeding ---------------------------------------------------

    async fn open_store() -> (tempfile::TempDir, StreamGStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open store");
        (dir, store)
    }

    async fn seed_intent(store: &StreamGStore, profile_id: &str, expires_at: i64) {
        let intent_row = intent_row_id(profile_id, INTENT_ID);
        let profile_id = profile_id.to_string();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT OR IGNORE INTO profiles (id, created_at, status) \
                         VALUES (?, ?, 'active')",
                    )
                    .bind(&profile_id)
                    .bind(0i64)
                    .execute(&mut **tx)
                    .await?;
                    sqlx::query(
                        "INSERT INTO intents (id, profile_id, intent_type, status, \
                         created_at, expires_at) \
                         VALUES (?, ?, 'sponsored_enrollment', 'pending', 0, ?)",
                    )
                    .bind(&intent_row)
                    .bind(&profile_id)
                    .bind(expires_at)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed intent");
    }

    /// Reserve one attempt through the real outbox path, so the row under test
    /// is the row production writes â€” `intent_id_hex`, `raw_tx_hash`,
    /// `raw_tx_enc` and the nonce allocation all included.
    async fn reserve(
        store: &StreamGStore,
        profile_id: &str,
        controller: [u8; 20],
        action_nonce: u64,
        raw: Vec<u8>,
    ) -> (String, String, [u8; 32]) {
        let signed = SignedRawTx::new(
            raw,
            GasUnits::new(500_000),
            MaxFeePerGas::new(1_000_000_000),
        );
        let req = ReservationRequest {
            profile_id,
            intent_id: INTENT_ID,
            chain_id: CHAIN_ID,
            controller,
            action: ActionType::SponsoredEnrollment,
            action_nonce,
            claim_owner: "test-owner",
            lease_ttl_seconds: DEFAULT_LEASE_TTL_SECONDS,
        };
        let reserved = reserve_and_persist_raw_tx(store, &data_key_hex(), &req, &signed, WALL_NOW)
            .await
            .expect("reserve");
        (reserved.attempt_id, reserved.allocation_id, signed.hash())
    }

    /// Move a reserved row into the `submitted` state a node acknowledgement
    /// produces, which is what reconcile's guard expects to compare against.
    async fn mark_submitted(store: &StreamGStore, attempt_id: &str, tx_hash: [u8; 32]) {
        let attempt_id = attempt_id.to_string();
        let hex = bytes32_hex(tx_hash);
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    let r = sqlx::query(
                        "UPDATE tx_attempts SET status = ?, tx_hash = ?, submitted_at = ? \
                         WHERE id = ?",
                    )
                    .bind(TX_ATTEMPT_STATUS_SUBMITTED)
                    .bind(&hex)
                    .bind(WALL_NOW)
                    .bind(&attempt_id)
                    .execute(&mut **tx)
                    .await?;
                    assert_eq!(r.rows_affected(), 1, "mark_submitted must hit a row");
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("mark submitted");
    }

    fn log_for(tx_hash: [u8; 32], controller: [u8; 20]) -> ExecutedLog {
        ExecutedLog {
            intent_id: INTENT_ID,
            root: ROOT,
            secondary: SECONDARY,
            controller,
            fee_token: FEE_TOKEN,
            fee_amount: 1_234,
            block_number: LOG_BLOCK,
            block_hash: BLOCK_HASH,
            log_index: 3,
            tx_hash,
            removed: false,
        }
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

    async fn count(store: &StreamGStore, sql: &'static str, bind: String) -> i64 {
        store
            .read(move |h| {
                Box::pin(async move {
                    let v: i64 = h.fetch_scalar(sqlx::query_scalar(sql).bind(bind)).await?;
                    Ok::<i64, StreamGStoreError>(v)
                })
            })
            .await
            .expect("count")
    }

    const ATTEMPT_STATUS_SQL: &str = "SELECT status FROM tx_attempts WHERE id = ?";
    const ATTEMPT_TX_HASH_SQL: &str = "SELECT tx_hash FROM tx_attempts WHERE id = ?";
    const NONCE_STATUS_SQL: &str = "SELECT status FROM nonce_allocations WHERE id = ?";
    const INTENT_STATUS_SQL: &str = "SELECT status FROM intents WHERE id = ?";

    // -------------------------------------------------------------------
    // ðŸ”´ The mis-attribution hole (required test 1).
    // -------------------------------------------------------------------

    /// A `reserved` row has `tx_hash NULL` by construction. Reconcile must
    /// refuse to attribute an event to it â€” and, critically, must NOT mark its
    /// action nonce `consumed`.
    ///
    /// Mutation this detects: restoring the conditional guard in
    /// `submit::reconcile_executed_for_profile_id`, i.e. changing
    /// `let Some(stored) = ... else { return Err(ReconcileUnverifiable) }` back
    /// to `if let Some(stored) = ... { ... }`. Under that mutation the call
    /// below succeeds, the attempt is stamped `confirmed` with the attacker's
    /// hash and the nonce goes `consumed`.
    ///
    /// The paired positive arm is the second half: the SAME event against the
    /// SAME row, once a node acknowledgement has given it a matching
    /// `tx_hash`, must succeed. Without that half this test would also pass if
    /// reconcile simply rejected everything.
    #[tokio::test]
    async fn reconcile_rejects_a_null_tx_hash_row_it_cannot_verify() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE_A, WALL_NOW + 600).await;
        let (attempt_id, allocation_id, _raw_hash) =
            reserve(&store, PROFILE_A, CONTROLLER_A, 7, vec![0x02, 0xAA]).await;

        // Precondition: this is the shape the hole lived in.
        assert_eq!(
            text(&store, ATTEMPT_TX_HASH_SQL, attempt_id.clone()).await,
            None,
            "a reserved row must have NULL tx_hash â€” that is the whole premise"
        );

        let foreign_tx = [0xEE; 32];
        let event = SponsoredEnrollmentExecuted {
            intent_id: INTENT_ID,
            root: ROOT,
            secondary: SECONDARY,
            controller: CONTROLLER_A,
            fee_token: FEE_TOKEN,
            fee_amount: 1_234,
            tx_hash: foreign_tx,
            block: LOG_BLOCK,
        };

        let err = reconcile_executed_for_profile_id(&store, &data_key_hex(), PROFILE_A, &event, WALL_NOW)
            .await
            .expect_err("a row that names no transaction must not be confirmable");
        assert_eq!(err.code(), "SUBMIT_RECONCILE_UNVERIFIABLE", "got {err}");

        assert_eq!(
            text(&store, ATTEMPT_STATUS_SQL, attempt_id.clone())
                .await
                .as_deref(),
            Some(TX_ATTEMPT_STATUS_RESERVED),
            "the refused attempt must be untouched"
        );
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, allocation_id.clone())
                .await
                .as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "the wrong nonce must NOT have been consumed"
        );

        // --- paired positive arm ---------------------------------------
        // Same row, same event, once the chain-verified hash is on the row.
        mark_submitted(&store, &attempt_id, foreign_tx).await;
        reconcile_executed_for_profile_id(&store, &data_key_hex(), PROFILE_A, &event, WALL_NOW)
            .await
            .expect("with a matching tx_hash on the row the SAME event must reconcile");
        assert_eq!(
            text(&store, ATTEMPT_STATUS_SQL, attempt_id)
                .await
                .as_deref(),
            Some(TX_ATTEMPT_STATUS_CONFIRMED)
        );
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, allocation_id)
                .await
                .as_deref(),
            Some(NONCE_STATUS_CONSUMED)
        );
    }

    // -------------------------------------------------------------------
    // Reorg (required test 2).
    // -------------------------------------------------------------------

    /// A log the node reports as `removed` un-does a confirmation: the attempt
    /// goes back to `submitted`, the intent back to `submitted`, and the action
    /// nonce from `consumed` back to `allocated` â€” never to `released`, because
    /// the transaction may be re-mined on the new canonical chain.
    ///
    /// Mutation this detects: ignoring `log.removed` in
    /// [`reconcile_executed_log`] (deleting the `if log.removed` branch). The
    /// chain double still corroborates the transaction, so under that mutation
    /// the call re-confirms instead of rolling back and the row stays
    /// `confirmed`.
    ///
    /// Paired non-zero arm: the first, non-removed reconcile must genuinely
    /// have produced `confirmed` + `consumed`, asserted before the rollback â€”
    /// so this cannot pass by nothing ever having been confirmed.
    #[tokio::test]
    async fn reorg_removed_log_returns_to_reconciliation() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE_A, WALL_NOW + 600).await;
        let (attempt_id, allocation_id, raw_hash) =
            reserve(&store, PROFILE_A, CONTROLLER_A, 7, vec![0x02, 0xAA]).await;
        mark_submitted(&store, &attempt_id, raw_hash).await;

        let chain = FakeChain::corroborating(raw_hash);
        let policy = FinalityPolicy::for_chain(CHAIN_ID);
        let log = log_for(raw_hash, CONTROLLER_A);

        let outcome =
            reconcile_executed_log(&store, &data_key_hex(), (&chain).into(), policy, &log, WALL_NOW)
                .await
                .expect("first reconcile");
        assert!(
            matches!(outcome, LogOutcome::Confirmed { .. }),
            "expected Confirmed, got {outcome:?}"
        );
        assert_eq!(
            text(&store, ATTEMPT_STATUS_SQL, attempt_id.clone())
                .await
                .as_deref(),
            Some(TX_ATTEMPT_STATUS_CONFIRMED),
            "paired non-zero arm: the row really was confirmed first"
        );
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, allocation_id.clone())
                .await
                .as_deref(),
            Some(NONCE_STATUS_CONSUMED),
            "paired non-zero arm: the nonce really was consumed first"
        );

        let mut removed = log.clone();
        removed.removed = true;
        let outcome =
            reconcile_executed_log(&store, &data_key_hex(), (&chain).into(), policy, &removed, WALL_NOW)
                .await
                .expect("reorg reconcile");
        match outcome {
            LogOutcome::Reorged { rolled_back, .. } => {
                assert_eq!(rolled_back, vec![attempt_id.clone()]);
            }
            other => panic!("expected Reorged, got {other:?}"),
        }

        assert_eq!(
            text(&store, ATTEMPT_STATUS_SQL, attempt_id.clone())
                .await
                .as_deref(),
            Some(TX_ATTEMPT_STATUS_SUBMITTED),
            "a removed log must take the confirmation back"
        );
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, allocation_id.clone())
                .await
                .as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "the nonce goes back to HELD, never to released"
        );
        assert_eq!(
            text(
                &store,
                INTENT_STATUS_SQL,
                intent_row_id(PROFILE_A, INTENT_ID)
            )
            .await
            .as_deref(),
            Some(INTENT_STATUS_SUBMITTED)
        );
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM reconciliation_events \
                 WHERE tx_attempt_id = ? AND status = 'reorg_removed'",
                attempt_id
            )
            .await,
            1,
            "the reorg must be recorded, not just applied"
        );
    }

    /// ðŸ”´ The units fix, asserted where a user can see it.
    ///
    /// `reconciliation_events.created_at` is INTEGER **unix seconds**
    /// (`migrations/0001_stream_g.sql`), and `submit::get_enrollment_intent`
    /// picks the disposition it reports with
    /// `ORDER BY r.created_at DESC, r.id DESC`. `apply_reorg` used to bind
    /// `log.block_number` there. A Base block number (~3Ã—10â·) can never outrank
    /// a real timestamp (~1.8Ã—10â¹), so a `reorg_removed` event recorded *after*
    /// a `confirmed` one lost that comparison every time and
    /// `GET /v1/stream-g/status/:intentId` kept reporting `confirmed` for an
    /// intent whose confirmation had been rolled back.
    ///
    /// Mutation this detects: restoring the `.bind(block)` in `apply_reorg`'s
    /// `INSERT OR IGNORE INTO reconciliation_events`. `latest_disposition` then
    /// reads back `confirmed` and this test fails on the final assertion.
    ///
    /// Paired non-zero arm: the confirmation is asserted to be visible through
    /// the same reader first, so the final assertion cannot pass merely because
    /// the view reports nothing.
    #[tokio::test]
    async fn a_reorg_after_a_confirmation_is_what_the_status_route_reports() {
        use crate::stream_g::profile_auth::AuthenticatedProfileId;

        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE_A, WALL_NOW + 600).await;
        let (attempt_id, _allocation_id, raw_hash) =
            reserve(&store, PROFILE_A, CONTROLLER_A, 7, vec![0x02, 0xAA]).await;
        mark_submitted(&store, &attempt_id, raw_hash).await;

        let chain = FakeChain::corroborating(raw_hash);
        let policy = FinalityPolicy::for_chain(CHAIN_ID);
        let log = log_for(raw_hash, CONTROLLER_A);
        let profile = AuthenticatedProfileId::for_test(PROFILE_A);

        reconcile_executed_log(&store, &data_key_hex(), (&chain).into(), policy, &log, WALL_NOW)
            .await
            .expect("first reconcile");

        let view = crate::stream_g::submit::get_enrollment_intent(&store, &profile, INTENT_ID)
            .await
            .expect("status read")
            .expect("the intent exists");
        assert_eq!(
            view.latest_disposition.as_deref(),
            Some(TX_ATTEMPT_STATUS_CONFIRMED),
            "paired non-zero arm: the confirmation really is visible through this reader"
        );

        // The reorg lands one second later on the wall clock â€” the smallest gap
        // that must still order correctly.
        let mut removed = log.clone();
        removed.removed = true;
        reconcile_executed_log(
            &store,
            &data_key_hex(),
            (&chain).into(),
            policy,
            &removed,
            WALL_NOW + 1,
        )
        .await
        .expect("reorg reconcile");

        let view = crate::stream_g::submit::get_enrollment_intent(&store, &profile, INTENT_ID)
            .await
            .expect("status read")
            .expect("the intent exists");
        assert_eq!(
            view.latest_disposition.as_deref(),
            Some(DISPOSITION_STATUS_REORGED),
            "the newest disposition is the reorg; reporting `confirmed` here tells a user their \
             enrollment succeeded when the chain took it back"
        );
    }

    // -------------------------------------------------------------------
    // Reverse lookup (required test 3).
    // -------------------------------------------------------------------

    /// Two profiles legitimately quote the same on-chain `intentId` (defect C2
    /// is what happens when that is forbidden). The reverse lookup must return
    /// **both** as candidates and the transaction hash must pick the winner.
    ///
    /// Mutation this detects: making `tx_attempts.intent_id_hex` UNIQUE in
    /// `0002_stream_g_outbox.sql`. The second profile's reservation then fails
    /// its INSERT and this test dies at the second `reserve(...)` â€” reproducing
    /// exactly the cross-profile squat C2 was filed for.
    ///
    /// It also detects deleting the disambiguation: if
    /// [`disambiguate_by_tx_hash`] returned the first candidate regardless, the
    /// asserted winner would be whichever row sorts first by id rather than the
    /// one that actually claims the hash.
    #[tokio::test]
    async fn two_profiles_same_intent_id_reverse_lookup_disambiguates_by_tx_hash() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE_A, WALL_NOW + 600).await;
        seed_intent(&store, PROFILE_B, WALL_NOW + 600).await;

        let (attempt_a, _alloc_a, hash_a) =
            reserve(&store, PROFILE_A, CONTROLLER_A, 7, vec![0x02, 0xAA]).await;
        let (attempt_b, _alloc_b, hash_b) =
            reserve(&store, PROFILE_B, CONTROLLER_B, 9, vec![0x02, 0xBB]).await;
        assert_ne!(attempt_a, attempt_b, "per-profile row ids must differ");
        assert_ne!(hash_a, hash_b, "the two profiles signed different payloads");

        let candidates = candidates_for_intent_id(&store, INTENT_ID)
            .await
            .expect("reverse lookup");
        assert_eq!(
            candidates.len(),
            2,
            "both profiles must survive the lookup: {candidates:?}"
        );
        let mut profiles: Vec<&str> = candidates.iter().map(|c| c.profile_id.as_str()).collect();
        profiles.sort_unstable();
        assert_eq!(profiles, vec![PROFILE_A, PROFILE_B]);

        // The hash is what resolves the ambiguity, in both directions.
        let winner_b = disambiguate_by_tx_hash(&candidates, hash_b)
            .expect("not ambiguous")
            .expect("B's payload must match exactly one candidate");
        assert_eq!(winner_b.attempt_id, attempt_b);
        assert_eq!(winner_b.profile_id, PROFILE_B);

        let winner_a = disambiguate_by_tx_hash(&candidates, hash_a)
            .expect("not ambiguous")
            .expect("A's payload must match exactly one candidate");
        assert_eq!(winner_a.attempt_id, attempt_a);
        assert_eq!(winner_a.profile_id, PROFILE_A);

        // A hash neither of them signed is nobody's â€” the external-fulfillment
        // signal, and the paired zero-arm for the two non-zero ones above.
        assert!(
            disambiguate_by_tx_hash(&candidates, [0x77; 32])
                .expect("not ambiguous")
                .is_none(),
            "a foreign transaction must match no candidate"
        );
    }

    // -------------------------------------------------------------------
    // Chain corroboration â€” the other half of the mis-attribution fix.
    // -------------------------------------------------------------------

    /// Reconcile used to trust the caller's event struct outright. A log the
    /// node has no receipt for must be refused before any row is touched.
    ///
    /// Mutation this detects: deleting the `Ok(None) => UncorroboratedLog` arm
    /// in [`reconcile_executed_log`] (or the whole receipt read). The row would
    /// then be confirmed on the strength of a struct anybody can build.
    ///
    /// It also pins the **classification** of each refusal, not just that a
    /// refusal happened, because since 2026-07-27 the four refusals below do
    /// two opposite things to the scan cursor: one is quarantinable and three
    /// are not. Asserting only `code()` on a single shared variant, as this
    /// test used to, is what let three retryable readings be filed as permanent
    /// and stepped over.
    ///
    /// Paired non-zero arm: the same call against a chain that DOES corroborate
    /// the log must confirm, so this is not passing because reconcile refuses
    /// everything.
    #[tokio::test]
    async fn a_log_the_chain_does_not_corroborate_is_refused() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE_A, WALL_NOW + 600).await;
        let (attempt_id, allocation_id, raw_hash) =
            reserve(&store, PROFILE_A, CONTROLLER_A, 7, vec![0x02, 0xAA]).await;
        mark_submitted(&store, &attempt_id, raw_hash).await;

        let chain = FakeChain::corroborating(raw_hash);
        let policy = FinalityPolicy::for_chain(CHAIN_ID);
        let log = log_for(raw_hash, CONTROLLER_A);

        chain.set_receipt(Ok(None));
        let err = reconcile_executed_log(&store, &data_key_hex(), (&chain).into(), policy, &log, WALL_NOW)
            .await
            .expect_err("no receipt means no confirmation");
        assert_eq!(err.code(), ERR_RECONCILE_UNCORROBORATED_LOG, "got {err}");
        assert_eq!(
            err.scope(),
            ReconcileErrorScope::LogTransient,
            "a receipt the node has not indexed yet must NOT be quarantinable"
        );
        assert_eq!(
            text(&store, ATTEMPT_STATUS_SQL, attempt_id.clone())
                .await
                .as_deref(),
            Some(TX_ATTEMPT_STATUS_SUBMITTED)
        );
        assert!(
            chain.receipt_calls() >= 1,
            "the chain must actually be asked"
        );

        // A receipt that says the transaction REVERTED **in the very block and
        // block hash the log claims** cannot have emitted a success event: one
        // block, two readings, and they contradict. This is the only
        // chain-corroboration refusal that is permanent.
        chain.set_receipt(Ok(Some(TxReceiptView {
            tx_hash: raw_hash,
            block_number: LOG_BLOCK,
            block_hash: BLOCK_HASH,
            success: false,
            gas_used: 21_000,
        })));
        let err = reconcile_executed_log(&store, &data_key_hex(), (&chain).into(), policy, &log, WALL_NOW)
            .await
            .expect_err("a status-0 receipt cannot back a success log");
        assert_eq!(err.code(), ERR_RECONCILE_UNVERIFIED_LOG, "got {err}");
        assert_eq!(
            err.scope(),
            ReconcileErrorScope::LogPermanent,
            "a self-contradicting block is the one thing here that no retry can fix"
        );

        // A receipt in a different block than the log claims â€” two readings
        // that straddle a fork or two replicas. TRANSIENT: which side survives
        // is not knowable from here.
        chain.set_receipt(Ok(Some(TxReceiptView {
            tx_hash: raw_hash,
            block_number: LOG_BLOCK + 1,
            block_hash: BLOCK_HASH,
            success: true,
            gas_used: 21_000,
        })));
        let err = reconcile_executed_log(&store, &data_key_hex(), (&chain).into(), policy, &log, WALL_NOW)
            .await
            .expect_err("block number mismatch");
        assert_eq!(err.code(), ERR_RECONCILE_UNCORROBORATED_LOG, "got {err}");
        assert_eq!(err.scope(), ReconcileErrorScope::LogTransient);

        // Same block number, different block hash â€” the same fork straddle,
        // caught one field later. Also transient.
        chain.set_receipt(Ok(Some(TxReceiptView {
            tx_hash: raw_hash,
            block_number: LOG_BLOCK,
            block_hash: [0x11; 32],
            success: true,
            gas_used: 21_000,
        })));
        let err = reconcile_executed_log(&store, &data_key_hex(), (&chain).into(), policy, &log, WALL_NOW)
            .await
            .expect_err("block hash mismatch");
        assert_eq!(err.code(), ERR_RECONCILE_UNCORROBORATED_LOG, "got {err}");
        assert_eq!(err.scope(), ReconcileErrorScope::LogTransient);

        // ðŸ”´ And a status-0 receipt from the OTHER side of a fork must not be
        // mistaken for the self-contradiction above: block identity is checked
        // first precisely so this stays transient. Mutation this detects:
        // moving the `!receipt.success` check back above the two block-identity
        // checks â€” this assertion then reads LogPermanent.
        chain.set_receipt(Ok(Some(TxReceiptView {
            tx_hash: raw_hash,
            block_number: LOG_BLOCK,
            block_hash: [0x11; 32],
            success: false,
            gas_used: 21_000,
        })));
        let err = reconcile_executed_log(&store, &data_key_hex(), (&chain).into(), policy, &log, WALL_NOW)
            .await
            .expect_err("a status-0 receipt in a block the log does not claim");
        assert_eq!(
            err.scope(),
            ReconcileErrorScope::LogTransient,
            "a revert on a losing fork is not a contradiction of this log"
        );

        // --- paired non-zero arm ---------------------------------------
        chain.set_receipt(Ok(Some(TxReceiptView {
            tx_hash: raw_hash,
            block_number: LOG_BLOCK,
            block_hash: BLOCK_HASH,
            success: true,
            gas_used: 21_000,
        })));
        let outcome =
            reconcile_executed_log(&store, &data_key_hex(), (&chain).into(), policy, &log, WALL_NOW)
                .await
                .expect("a corroborated log must reconcile");
        assert!(
            matches!(outcome, LogOutcome::Confirmed { .. }),
            "{outcome:?}"
        );
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, allocation_id)
                .await
                .as_deref(),
            Some(NONCE_STATUS_CONSUMED)
        );
    }

    /// An RPC that cannot be reached is never "the chain says no".
    ///
    /// Mutation this detects: mapping the `transaction_receipt` `Err` to
    /// `Ok(None)`/`UncorroboratedLog` and continuing, or â€” worse â€” treating it
    /// as corroboration. Either way the assertion on the error code fails.
    ///
    /// The distinction survives the 2026-07-27 split and is worth restating,
    /// because the two now differ only in *scope*, not in what they refuse: an
    /// unreachable node is [`ReconcileErrorScope::Environment`] and aborts the
    /// whole window, while an uncorroborated log is
    /// [`ReconcileErrorScope::LogTransient`] and holds the cursor while the
    /// window's other logs keep folding.
    #[tokio::test]
    async fn a_failed_chain_read_is_an_error_not_a_verdict() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE_A, WALL_NOW + 600).await;
        let (attempt_id, _alloc, raw_hash) =
            reserve(&store, PROFILE_A, CONTROLLER_A, 7, vec![0x02, 0xAA]).await;
        mark_submitted(&store, &attempt_id, raw_hash).await;

        let chain = FakeChain::corroborating(raw_hash);
        chain.set_receipt(Err("connection refused".to_string()));
        let err = reconcile_executed_log(
            &store,
            &data_key_hex(),
            (&chain).into(),
            FinalityPolicy::for_chain(CHAIN_ID),
            &log_for(raw_hash, CONTROLLER_A),
            WALL_NOW,
        )
        .await
        .expect_err("an unreachable node decides nothing");
        assert_eq!(err.code(), ERR_RECONCILE_CHAIN, "got {err}");

        // Paired non-zero arm: the head read failing is also an error, not a
        // silent "not final yet".
        chain.set_receipt(Ok(Some(TxReceiptView {
            tx_hash: raw_hash,
            block_number: LOG_BLOCK,
            block_hash: BLOCK_HASH,
            success: true,
            gas_used: 21_000,
        })));
        chain.set_head(Err("timeout".to_string()));
        let err = reconcile_executed_log(
            &store,
            &data_key_hex(),
            (&chain).into(),
            FinalityPolicy::for_chain(CHAIN_ID),
            &log_for(raw_hash, CONTROLLER_A),
            WALL_NOW,
        )
        .await
        .expect_err("head read failure decides nothing either");
        assert_eq!(err.code(), ERR_RECONCILE_CHAIN, "got {err}");
    }

    // -------------------------------------------------------------------
    // Finality (A3).
    // -------------------------------------------------------------------

    /// A3: anvil needs one confirmation, everything else twelve, and the
    /// containing block counts as the first.
    ///
    /// Mutation this detects: dropping the `chain_id == 31337` special case
    /// (anvil would then need 12 confirmations and `is_final` at depth 1 fails),
    /// or changing `depth` to `head - log_block` (the anvil head-block case
    /// then reports depth 0 and stops being final).
    #[test]
    fn finality_depth_counts_the_containing_block() {
        assert_eq!(
            FinalityPolicy::for_chain(ANVIL_CHAIN_ID).confirmations(),
            ANVIL_CONFIRMATIONS
        );
        assert_eq!(
            FinalityPolicy::for_chain(8453).confirmations(),
            DEFAULT_CONFIRMATIONS
        );

        assert_eq!(FinalityPolicy::depth(100, 100), Some(1));
        assert_eq!(FinalityPolicy::depth(100, 111), Some(12));
        assert_eq!(
            FinalityPolicy::depth(100, 99),
            None,
            "a log ahead of the head is inconsistent, not zero-depth"
        );

        let anvil = FinalityPolicy::for_chain(ANVIL_CHAIN_ID);
        assert!(anvil.is_final(100, 100), "anvil: the head block is enough");

        let mainnet = FinalityPolicy::for_chain(8453);
        assert!(!mainnet.is_final(100, 110), "11 confirmations is not 12");
        assert!(mainnet.is_final(100, 111));
        assert!(
            !mainnet.is_final(100, 99),
            "an inconsistent reading is never final"
        );
    }

    /// The env override parses, and refuses the one value that would disable
    /// every reorg check below it.
    ///
    /// Mutation this detects: accepting `0` (deleting the `parsed == 0` guard).
    /// The paired non-zero arm is the accepted `3`, so this cannot pass by
    /// rejecting everything.
    #[test]
    fn confirmations_override_parses_and_refuses_zero() {
        let mut map = HashMap::new();
        assert_eq!(
            FinalityPolicy::from_map(&map, ANVIL_CHAIN_ID).unwrap(),
            FinalityPolicy::for_chain(ANVIL_CHAIN_ID),
            "an absent key leaves the A3 default alone"
        );

        map.insert(ENV_CONFIRMATIONS.to_string(), "3".to_string());
        assert_eq!(
            FinalityPolicy::from_map(&map, 8453)
                .unwrap()
                .confirmations(),
            3
        );

        map.insert(ENV_CONFIRMATIONS.to_string(), "0".to_string());
        let err =
            FinalityPolicy::from_map(&map, 8453).expect_err("0 confirmations is not a policy");
        assert_eq!(err.code(), ERR_RECONCILE_CONFIG, "got {err}");

        map.insert(ENV_CONFIRMATIONS.to_string(), "twelve".to_string());
        let err = FinalityPolicy::from_map(&map, 8453).expect_err("garbage is not a policy");
        assert_eq!(err.code(), ERR_RECONCILE_CONFIG, "got {err}");
    }

    /// A corroborated log that is not buried deep enough writes **nothing**.
    ///
    /// Mutation this detects: deleting the `is_final` gate. The row would be
    /// confirmed at depth 1 on a 12-confirmation chain.
    #[tokio::test]
    async fn a_log_below_the_confirmation_depth_writes_nothing() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE_A, WALL_NOW + 600).await;
        let (attempt_id, allocation_id, raw_hash) =
            reserve(&store, PROFILE_A, CONTROLLER_A, 7, vec![0x02, 0xAA]).await;
        mark_submitted(&store, &attempt_id, raw_hash).await;

        let chain = FakeChain::corroborating(raw_hash);
        chain.set_head(Ok(LOG_BLOCK)); // depth 1 on a 12-confirmation chain
        let policy = FinalityPolicy::for_chain(8453);
        let log = log_for(raw_hash, CONTROLLER_A);

        let outcome =
            reconcile_executed_log(&store, &data_key_hex(), (&chain).into(), policy, &log, WALL_NOW)
                .await
                .expect("not final is not an error");
        match outcome {
            LogOutcome::NotFinalYet {
                depth, required, ..
            } => {
                assert_eq!(depth, Some(1));
                assert_eq!(required, DEFAULT_CONFIRMATIONS);
            }
            other => panic!("expected NotFinalYet, got {other:?}"),
        }
        assert_eq!(
            text(&store, ATTEMPT_STATUS_SQL, attempt_id.clone())
                .await
                .as_deref(),
            Some(TX_ATTEMPT_STATUS_SUBMITTED),
            "nothing may be written below the confirmation depth"
        );
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, allocation_id.clone())
                .await
                .as_deref(),
            Some(NONCE_STATUS_ALLOCATED)
        );

        // Paired non-zero arm: the very same log, deep enough, does write.
        chain.set_head(Ok(LOG_BLOCK + DEFAULT_CONFIRMATIONS));
        let outcome =
            reconcile_executed_log(&store, &data_key_hex(), (&chain).into(), policy, &log, WALL_NOW)
                .await
                .expect("deep enough");
        assert!(
            matches!(outcome, LogOutcome::Confirmed { .. }),
            "{outcome:?}"
        );
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, allocation_id)
                .await
                .as_deref(),
            Some(NONCE_STATUS_CONSUMED)
        );
    }

    // -------------------------------------------------------------------
    // External fulfillment.
    // -------------------------------------------------------------------

    /// Somebody else's transaction fulfilled the intent. Nothing is
    /// rebroadcast; the candidate whose controller signed the winning intent
    /// has its action nonce `consumed`, and a candidate under a *different*
    /// controller â€” whose on-chain nonce was never touched â€” has its released
    /// rather than stranded.
    ///
    /// Mutation this detects: dropping the `signer_address` comparison and
    /// consuming unconditionally. Profile B's nonce would then read `consumed`
    /// and the `released` assertion fails. (Consuming a nonce the gateway never
    /// incremented permanently wedges that controller for this attestor.)
    #[tokio::test]
    async fn an_externally_fulfilled_intent_is_never_rebroadcast() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE_A, WALL_NOW + 600).await;
        seed_intent(&store, PROFILE_B, WALL_NOW + 600).await;
        let (attempt_a, alloc_a, hash_a) =
            reserve(&store, PROFILE_A, CONTROLLER_A, 7, vec![0x02, 0xAA]).await;
        let (attempt_b, alloc_b, _hash_b) =
            reserve(&store, PROFILE_B, CONTROLLER_B, 9, vec![0x02, 0xBB]).await;
        mark_submitted(&store, &attempt_a, hash_a).await;

        let foreign_tx = [0x77; 32];
        let chain = FakeChain::corroborating(foreign_tx);
        // The winning transaction carried CONTROLLER_A's intent.
        let log = log_for(foreign_tx, CONTROLLER_A);

        let outcome = reconcile_executed_log(
            &store,
            &data_key_hex(),
            (&chain).into(),
            FinalityPolicy::for_chain(CHAIN_ID),
            &log,
            WALL_NOW,
        )
        .await
        .expect("external fulfillment");

        match outcome {
            LogOutcome::ExternallyFulfilled {
                consumed, released, ..
            } => {
                assert_eq!(consumed, vec![attempt_a.clone()], "A's controller won");
                assert_eq!(released, vec![attempt_b.clone()], "B's nonce was untouched");
            }
            other => panic!("expected ExternallyFulfilled, got {other:?}"),
        }

        assert_eq!(
            text(&store, NONCE_STATUS_SQL, alloc_a).await.as_deref(),
            Some(NONCE_STATUS_CONSUMED)
        );
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, alloc_b).await.as_deref(),
            Some(NONCE_STATUS_RELEASED),
            "a nonce the gateway never advanced must not be stranded"
        );
        for id in [attempt_a, attempt_b] {
            assert_eq!(
                text(&store, ATTEMPT_STATUS_SQL, id).await.as_deref(),
                Some(TX_ATTEMPT_STATUS_CONFIRMED)
            );
        }
    }

    /// A log for an intent this attestor never quoted costs no RPC and writes
    /// nothing â€” a log follower sees the whole gateway, not just our traffic.
    #[tokio::test]
    async fn a_log_for_an_unknown_intent_is_not_an_error() {
        let (_dir, store) = open_store().await;
        let chain = FakeChain::corroborating([0x77; 32]);
        let outcome = reconcile_executed_log(
            &store,
            &data_key_hex(),
            (&chain).into(),
            FinalityPolicy::for_chain(CHAIN_ID),
            &log_for([0x77; 32], CONTROLLER_A),
            WALL_NOW,
        )
        .await
        .expect("unknown intent");
        assert!(
            matches!(outcome, LogOutcome::NoCandidates { .. }),
            "{outcome:?}"
        );
        assert_eq!(
            chain.receipt_calls(),
            0,
            "candidates are checked before any RPC is spent"
        );
    }

    // -------------------------------------------------------------------
    // Revert / drop / receipt timeout.
    // -------------------------------------------------------------------

    /// ðŸ”´ Spec Â§8.2. A **mined revert** must not be routed through
    /// `record_failed`: the action nonce stays held until the signed payload
    /// can no longer execute, and only the evidence sweeper may release it.
    ///
    /// Mutation this detects: making [`apply_disposition`] release the nonce
    /// (adding an `UPDATE nonce_allocations SET status='released'`, i.e. giving
    /// it `record_failed`'s body). The `allocated` assertion below fails.
    ///
    /// Note this is the *opposite* requirement to
    /// `submit::tests::a_reverting_broadcast_releases_the_reservation_so_a_requote_can_retry`,
    /// which covers a BROADCAST failure â€” nothing that could execute ever left
    /// the process there, so releasing is correct. Both must hold at once.
    #[tokio::test]
    async fn a_mined_revert_holds_the_nonce_instead_of_releasing_it() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE_A, WALL_NOW + 600).await;
        let (attempt_id, allocation_id, raw_hash) =
            reserve(&store, PROFILE_A, CONTROLLER_A, 7, vec![0x02, 0xAA]).await;
        mark_submitted(&store, &attempt_id, raw_hash).await;

        let chain = FakeChain::corroborating(raw_hash);
        chain.set_receipt(Ok(Some(TxReceiptView {
            tx_hash: raw_hash,
            block_number: LOG_BLOCK,
            block_hash: BLOCK_HASH,
            success: false,
            gas_used: 21_000,
        })));

        let pending = PendingAttempt {
            attempt_id: &attempt_id,
            tx_hash: raw_hash,
            broadcaster: None,
            eoa_nonce: None,
            receipt_deadline_wall: WALL_NOW,
        };
        let disposition =
            classify_pending_attempt((&chain).into(), &pending, WALL_NOW).expect("classify");
        assert!(
            matches!(disposition, AttemptDisposition::MinedRevert { .. }),
            "{disposition:?}"
        );

        let applied = apply_disposition(&store, &attempt_id, &disposition, WALL_NOW)
            .await
            .expect("apply");
        assert_eq!(applied, AppliedDisposition::HeldForSweeper);

        assert_eq!(
            text(&store, NONCE_STATUS_SQL, allocation_id.clone())
                .await
                .as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "a MINED revert holds the nonce; only the sweeper's chain-time test may release it"
        );
        let status = text(&store, ATTEMPT_STATUS_SQL, attempt_id.clone())
            .await
            .expect("status");
        assert_ne!(
            status, TX_ATTEMPT_STATUS_FAILED,
            "a mined revert is not the same state as a failed broadcast"
        );
        assert_eq!(
            status, TX_ATTEMPT_STATUS_RESERVED,
            "the row goes back into the sweeper's queue"
        );
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM reconciliation_events \
                 WHERE tx_attempt_id = ? AND status = 'mined_revert'",
                attempt_id
            )
            .await,
            1
        );
    }

    /// ðŸ”´ Spec Â§8.2. A receipt that never arrives is **unknown**, and the user
    /// must not be told no fee was charged.
    ///
    /// This is an honesty assertion with the paired positive arm the I7 rule
    /// demands: the negative claim ("the unknown message must not say no fee
    /// was charged") sits next to a positive one over the SAME predicate ("the
    /// mined-revert message must say exactly that"). A mutation that emptied
    /// every message, or that made the two states share one message, fails one
    /// arm or the other.
    #[tokio::test]
    async fn a_receipt_timeout_is_unknown_and_never_reported_as_no_fee_charged() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE_A, WALL_NOW + 600).await;
        let (attempt_id, allocation_id, raw_hash) =
            reserve(&store, PROFILE_A, CONTROLLER_A, 7, vec![0x02, 0xAA]).await;
        mark_submitted(&store, &attempt_id, raw_hash).await;

        let chain = FakeChain::corroborating(raw_hash);
        chain.set_receipt(Ok(None));

        // Before the deadline it is merely pending â€” not a timeout.
        let pending = PendingAttempt {
            attempt_id: &attempt_id,
            tx_hash: raw_hash,
            broadcaster: None,
            eoa_nonce: None,
            receipt_deadline_wall: WALL_NOW + 60,
        };
        let early = classify_pending_attempt((&chain).into(), &pending, WALL_NOW).expect("early");
        assert!(
            matches!(early, AttemptDisposition::StillPending { .. }),
            "{early:?}"
        );
        assert_eq!(early.recorded_status(), None);
        assert_eq!(
            apply_disposition(&store, &attempt_id, &early, WALL_NOW)
                .await
                .expect("apply pending"),
            AppliedDisposition::NothingToDo
        );
        assert_eq!(
            text(&store, ATTEMPT_STATUS_SQL, attempt_id.clone())
                .await
                .as_deref(),
            Some(TX_ATTEMPT_STATUS_SUBMITTED),
            "a still-pending attempt is not disturbed"
        );

        // Past the deadline it becomes its own state.
        let late =
            classify_pending_attempt((&chain).into(), &pending, WALL_NOW + 61).expect("late");
        assert!(
            matches!(late, AttemptDisposition::ReceiptTimeoutUnknown { .. }),
            "{late:?}"
        );
        assert_eq!(late.recorded_status(), Some(DISPOSITION_STATUS_UNKNOWN));

        // The honesty contract, both arms over the same predicate.
        let revert = AttemptDisposition::MinedRevert {
            tx_hash_hex: bytes32_hex(raw_hash),
            block_number: LOG_BLOCK,
        };
        let claims_no_fee =
            |d: &AttemptDisposition| d.user_message().to_ascii_lowercase().contains("no fee was");
        assert!(
            claims_no_fee(&revert),
            "positive arm: a mined revert really did charge nothing, and must say so"
        );
        assert!(
            !claims_no_fee(&late),
            "negative arm: an unknown outcome must NOT claim no fee was charged"
        );
        assert_ne!(
            revert.user_message(),
            late.user_message(),
            "the two states must not share one sentence"
        );

        apply_disposition(&store, &attempt_id, &late, WALL_NOW + 61)
            .await
            .expect("apply timeout");
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, allocation_id)
                .await
                .as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "an unknown outcome holds the nonce"
        );
        assert_ne!(
            text(&store, ATTEMPT_STATUS_SQL, attempt_id.clone())
                .await
                .as_deref(),
            Some(TX_ATTEMPT_STATUS_FAILED),
            "unknown is not failed"
        );
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM reconciliation_events \
                 WHERE tx_attempt_id = ? AND status = 'receipt_timeout_unknown'",
                attempt_id
            )
            .await,
            1
        );
    }

    /// ðŸ”´ The load-bearing claim of the whole revert design, proved end to end
    /// rather than asserted by construction.
    ///
    /// [`apply_disposition`] does not release a nonce; it hands the row to
    /// [`super::outbox::sweep_stuck_reservations`], whose chain-evidence test
    /// is the only place a release may happen. That is only true if the row it
    /// writes is actually one the sweeper claims. This test runs the real
    /// sweeper against the real row and checks BOTH directions:
    ///
    /// * intent still valid on the **chain** clock â†’ the sweep HOLDS it
    ///   (`held_intent_still_valid`, nonce still `allocated`);
    /// * intent expired on the chain clock â†’ the sweep releases it.
    ///
    /// Without the second arm this would pass if the handoff never worked at
    /// all (a row nobody claims is also a row nobody releases); without the
    /// first it would pass if the sweeper released everything on sight.
    ///
    /// Mutation this detects: making [`apply_disposition`] leave `lease_until`
    /// alone (or set it to `now_wall + ttl`). The sweeper's trigger is
    /// `lease_until IS NOT NULL AND lease_until < now`, so the row is never
    /// claimed, `claimed` comes back 0 and both arms fail.
    #[tokio::test]
    async fn a_mined_revert_is_released_only_by_the_sweepers_chain_time_test() {
        use crate::stream_g::outbox::{
            sweep_stuck_reservations, SweepPolicy, DEFAULT_SWEEP_MAX_ROWS,
        };

        // The intent's deadline is a CHAIN-clock value (`quotes.rs` cuts it
        // from `block_timestamp()`), so it is compared against CHAIN_NOW.
        let intent_expires_at = i64::try_from(CHAIN_NOW).unwrap() + 600;

        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE_A, intent_expires_at).await;
        let (attempt_id, allocation_id, raw_hash) =
            reserve(&store, PROFILE_A, CONTROLLER_A, 7, vec![0x02, 0xAA]).await;
        mark_submitted(&store, &attempt_id, raw_hash).await;

        let chain = FakeChain::corroborating(raw_hash);
        let reverted = Ok(Some(TxReceiptView {
            tx_hash: raw_hash,
            block_number: LOG_BLOCK,
            block_hash: BLOCK_HASH,
            success: false,
            gas_used: 21_000,
        }));
        chain.set_receipt(reverted.clone());

        let pending = PendingAttempt {
            attempt_id: &attempt_id,
            tx_hash: raw_hash,
            broadcaster: None,
            eoa_nonce: None,
            receipt_deadline_wall: WALL_NOW,
        };
        let d = classify_pending_attempt((&chain).into(), &pending, WALL_NOW).expect("classify");
        apply_disposition(&store, &attempt_id, &d, WALL_NOW)
            .await
            .expect("apply");

        let policy = SweepPolicy {
            claim_owner: "sweeper-under-test",
            lease_ttl_seconds: DEFAULT_LEASE_TTL_SECONDS,
            max_rows: DEFAULT_SWEEP_MAX_ROWS,
            gateway: [0x11; 20],
        };

        // --- arm 1: the intent is still chain-time valid â†’ HOLD ----------
        let report = sweep_stuck_reservations(&store, (&chain).into(), &policy, WALL_NOW)
            .await
            .expect("sweep");
        assert_eq!(
            report.claimed, 1,
            "the sweeper must actually claim the row apply_disposition wrote: {report:?}"
        );
        assert_eq!(report.held_intent_still_valid, 1, "{report:?}");
        assert_eq!(report.released, 0, "{report:?}");
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, allocation_id.clone())
                .await
                .as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "a payload that can still execute keeps its nonce"
        );

        // --- arm 2: chain time passes the intent's deadline â†’ RELEASE ----
        chain.set_block_timestamp(Ok(u64::try_from(intent_expires_at).unwrap() + 1));
        let later = WALL_NOW + DEFAULT_LEASE_TTL_SECONDS + 1;
        let report = sweep_stuck_reservations(&store, (&chain).into(), &policy, later)
            .await
            .expect("sweep");
        assert_eq!(report.claimed, 1, "{report:?}");
        assert_eq!(report.released, 1, "{report:?}");
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, allocation_id)
                .await
                .as_deref(),
            Some(NONCE_STATUS_RELEASED),
            "once the payload can no longer execute the nonce comes back"
        );
        assert_eq!(
            text(&store, ATTEMPT_STATUS_SQL, attempt_id)
                .await
                .as_deref(),
            Some(TX_ATTEMPT_STATUS_FAILED),
            "and only THEN is the attempt terminal"
        );
    }

    /// A transaction the broadcaster's mined nonce frontier has already passed
    /// can never be mined â€” but the *intent* payload is still executable, so
    /// the nonce is held, not released.
    ///
    /// Mutation this detects: comparing against the PENDING transaction count
    /// (`transaction_count(addr, true)`) instead of the mined one, which counts
    /// the in-flight transaction itself and reports every live transaction as
    /// dropped. The `StillPending` arm below then fails.
    #[tokio::test]
    async fn a_transaction_the_frontier_passed_is_dropped_not_pending() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE_A, WALL_NOW + 600).await;
        let (attempt_id, allocation_id, raw_hash) =
            reserve(&store, PROFILE_A, CONTROLLER_A, 7, vec![0x02, 0xAA]).await;
        mark_submitted(&store, &attempt_id, raw_hash).await;

        let chain = FakeChain::corroborating(raw_hash);
        chain.set_receipt(Ok(None));
        chain.set_tx_count(Ok(6)); // frontier has NOT passed nonce 6

        let pending = PendingAttempt {
            attempt_id: &attempt_id,
            tx_hash: raw_hash,
            broadcaster: Some(CONTROLLER_A),
            eoa_nonce: Some(6),
            receipt_deadline_wall: WALL_NOW + 60,
        };
        let d = classify_pending_attempt((&chain).into(), &pending, WALL_NOW).expect("classify");
        assert!(
            matches!(d, AttemptDisposition::StillPending { .. }),
            "frontier at the tx's own nonce means it is still next up: {d:?}"
        );

        chain.set_tx_count(Ok(7)); // some other transaction took nonce 6
        let d = classify_pending_attempt((&chain).into(), &pending, WALL_NOW).expect("classify");
        match d {
            AttemptDisposition::Dropped {
                eoa_nonce,
                frontier,
                ..
            } => {
                assert_eq!(eoa_nonce, 6);
                assert_eq!(frontier, 7);
            }
            other => panic!("expected Dropped, got {other:?}"),
        }
        assert!(chain.tx_count_calls() >= 2);

        apply_disposition(&store, &attempt_id, &d, WALL_NOW)
            .await
            .expect("apply");
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, allocation_id)
                .await
                .as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "the signed INTENT can still be executed by anybody, so the slot stays held"
        );
    }

    /// Without a broadcaster/nonce pair the drop state is unreachable, and the
    /// classifier must fall through to the honest "unknown" rather than guess.
    ///
    /// Mutation this detects: defaulting `eoa_nonce` to 0 (or `frontier` to
    /// `u64::MAX`) when the caller did not supply one â€” the classifier would
    /// then report `Dropped` for a transaction it knows nothing about.
    #[tokio::test]
    async fn an_unknown_eoa_nonce_can_never_produce_a_drop_verdict() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE_A, WALL_NOW + 600).await;
        let (attempt_id, _alloc, raw_hash) =
            reserve(&store, PROFILE_A, CONTROLLER_A, 7, vec![0x02, 0xAA]).await;

        let chain = FakeChain::corroborating(raw_hash);
        chain.set_receipt(Ok(None));
        chain.set_tx_count(Ok(u64::MAX));

        let pending = PendingAttempt {
            attempt_id: &attempt_id,
            tx_hash: raw_hash,
            broadcaster: None,
            eoa_nonce: None,
            receipt_deadline_wall: WALL_NOW,
        };
        let d = classify_pending_attempt((&chain).into(), &pending, WALL_NOW).expect("classify");
        assert!(
            matches!(d, AttemptDisposition::ReceiptTimeoutUnknown { .. }),
            "{d:?}"
        );
        assert_eq!(
            chain.tx_count_calls(),
            0,
            "no EOA nonce means the frontier is never even asked about"
        );

        // Paired non-zero arm: supplying the pair DOES reach the drop verdict.
        let known = PendingAttempt {
            broadcaster: Some(CONTROLLER_A),
            eoa_nonce: Some(0),
            ..pending
        };
        let d = classify_pending_attempt((&chain).into(), &known, WALL_NOW).expect("classify");
        assert!(matches!(d, AttemptDisposition::Dropped { .. }), "{d:?}");
    }

    // -------------------------------------------------------------------
    // Reverse-lookup coverage of the LEGACY submit path.
    // -------------------------------------------------------------------

    /// The reverse lookup must find rows written by the **deleted** Task 6b
    /// reservation, `submit::reserve_action_nonce`.
    ///
    /// Task 8 Wave B removed that function â€” `submit_sponsored_enrollment` now
    /// reserves through `outbox::reserve_and_persist_raw_tx` like everything
    /// else â€” but the rows it wrote are still in databases the previous binary
    /// touched: `raw_tx_enc NULL`, `raw_tx_hash NULL`, `claim_owner NULL`,
    /// `intent_id_hex` set. This test hand-writes that exact legacy shape (it
    /// can no longer be produced by calling any live function) and proves the
    /// Â§3.2 lookup still returns it, so an upgrade does not orphan the rows a
    /// crashed predecessor left behind.
    ///
    /// Mutation this detects: narrowing `candidates_for_intent_id` to rows with
    /// a non-NULL `raw_tx_enc` (the shape the merged path always writes) â€” the
    /// candidate set comes back empty and the assertion below fails.
    #[tokio::test]
    async fn attempts_written_by_the_legacy_submit_path_are_reverse_lookupable() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE_A, WALL_NOW + 600).await;

        // Mimic the exact row the deleted `submit::reserve_action_nonce`
        // INSERTed, including its column list. This is now the only way to
        // produce that shape at all â€” the function is gone.
        let attempt_id = tx_attempt_row_id(PROFILE_A, INTENT_ID, 0);
        let signer_key = action_nonce_signer_key(CONTROLLER_A, ActionType::SponsoredEnrollment);
        let allocation_id = nonce_allocation_row_id(CHAIN_ID, &signer_key, 7);
        let intent_row = intent_row_id(PROFILE_A, INTENT_ID);
        let intent_id_hex = bytes32_hex(INTENT_ID);
        {
            let (attempt_id, allocation_id, intent_row, signer_key, intent_id_hex) = (
                attempt_id.clone(),
                allocation_id.clone(),
                intent_row.clone(),
                signer_key.clone(),
                intent_id_hex.clone(),
            );
            store
                .write_tx(move |tx| {
                    Box::pin(async move {
                        sqlx::query(
                            "INSERT INTO nonce_allocations \
                             (id, chain_id, signer_address, nonce, status, allocated_at, kind) \
                             VALUES (?, ?, ?, ?, ?, ?, ?)",
                        )
                        .bind(&allocation_id)
                        .bind(CHAIN_ID as i64)
                        .bind(&signer_key)
                        .bind(7i64)
                        .bind(NONCE_STATUS_ALLOCATED)
                        .bind(WALL_NOW)
                        .bind(NONCE_KIND_ACTION)
                        .execute(&mut **tx)
                        .await?;
                        sqlx::query(
                            "INSERT INTO tx_attempts \
                             (id, intent_id, nonce_allocation_id, chain_id, status, created_at, \
                              intent_id_hex) \
                             VALUES (?, ?, ?, ?, ?, ?, ?)",
                        )
                        .bind(&attempt_id)
                        .bind(&intent_row)
                        .bind(&allocation_id)
                        .bind(CHAIN_ID as i64)
                        .bind(TX_ATTEMPT_STATUS_RESERVED)
                        .bind(WALL_NOW)
                        .bind(&intent_id_hex)
                        .execute(&mut **tx)
                        .await?;
                        Ok::<(), StreamGStoreError>(())
                    })
                })
                .await
                .expect("seed legacy row");
        }

        let candidates = candidates_for_intent_id(&store, INTENT_ID)
            .await
            .expect("reverse lookup");
        assert_eq!(candidates.len(), 1, "{candidates:?}");
        assert_eq!(candidates[0].attempt_id, attempt_id);
        assert_eq!(candidates[0].profile_id, PROFILE_A);
        assert_eq!(
            candidates[0].signer_address.as_deref(),
            Some(signer_key.as_str()),
            "the action-nonce join must survive the kind filter"
        );
        assert_eq!(
            candidates[0].allocation_id.as_deref(),
            Some(allocation_id.as_str())
        );
    }

    /// The `kind` filter on the nonce join is load-bearing: a broadcaster-EOA
    /// row must never be picked up as an attempt's action nonce.
    ///
    /// Mutation this detects: dropping `AND n.kind = ?` from
    /// [`candidates_for_intent_id`]'s LEFT JOIN. The broadcaster row shares the
    /// attempt's `nonce_allocation_id` in this fixture, so the join would then
    /// return it and `signer_address` would read back as the bare address.
    #[tokio::test]
    async fn the_nonce_join_refuses_a_broadcaster_row() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE_A, WALL_NOW + 600).await;
        let (attempt_id, allocation_id, _hash) =
            reserve(&store, PROFILE_A, CONTROLLER_A, 7, vec![0x02, 0xAA]).await;

        // Rewrite the attempt's allocation row as a BROADCASTER row, keeping
        // the same id: the only thing that can tell them apart is `kind`.
        {
            let allocation_id = allocation_id.clone();
            store
                .write_tx(move |tx| {
                    Box::pin(async move {
                        let r = sqlx::query(
                            "UPDATE nonce_allocations SET kind = 'broadcaster', \
                             signer_address = '0xdeadbeef' WHERE id = ?",
                        )
                        .bind(&allocation_id)
                        .execute(&mut **tx)
                        .await?;
                        assert_eq!(r.rows_affected(), 1);
                        Ok::<(), StreamGStoreError>(())
                    })
                })
                .await
                .expect("rewrite kind");
        }

        let candidates = candidates_for_intent_id(&store, INTENT_ID)
            .await
            .expect("reverse lookup");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].attempt_id, attempt_id);
        assert_eq!(
            candidates[0].signer_address, None,
            "a kind='broadcaster' row must not answer for an action nonce"
        );
    }

    /// Two candidates claiming the same transaction hash is refused, not
    /// resolved by picking the first.
    ///
    /// Mutation this detects: replacing the `count => Err(..)` arm with
    /// `_ => Ok(Some(matches[0]))`.
    #[test]
    fn two_candidates_claiming_one_hash_is_refused() {
        let mk = |id: &str, hash: &str| AttemptCandidate {
            attempt_id: id.to_string(),
            profile_id: "p".to_string(),
            intent_row_id: "i".to_string(),
            allocation_id: None,
            signer_address: None,
            status: TX_ATTEMPT_STATUS_RESERVED.to_string(),
            tx_hash: None,
            raw_tx_hash: Some(hash.to_string()),
        };
        let hash = bytes32_hex([0x5A; 32]);
        // Deliberately different letter case: the comparison must normalise,
        // or this test would silently degrade into "one match".
        let dupes = vec![mk("a", &hash), mk("b", &hash.to_ascii_uppercase())];
        let err = disambiguate_by_tx_hash(&dupes, [0x5A; 32])
            .expect_err("two rows claiming one hash is not a winner");
        assert_eq!(err.code(), ERR_RECONCILE_AMBIGUOUS, "got {err}");
    }
}
