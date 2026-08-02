//! Stream G background maintenance — the single loop that owns every recurring
//! Stream G job, its cadence, its cancellation, and its counters.
//!
//! Two primitives were shipped by earlier tasks as *callable but unscheduled*
//! functions, each with a doc comment naming Task 8 as the owner of its
//! scheduling:
//!
//! * [`super::outbox::sweep_stuck_reservations`] — "`sweep_stuck_reservations`
//!   is a **callable, tested primitive — not a spawned task** … Task 8 owns the
//!   scheduling, the HTTP surface and the `STREAM_G_OUTBOX_LEASE_TTL_SECONDS`
//!   env key" (`outbox.rs`'s module doc);
//! * [`super::profile_auth::prune_expired`] — "wiring it to a recurring
//!   background job is Task 8's job, not this task's".
//!
//! This module is that job. Both doc comments have been updated to point here
//! rather than left to rot into false claims.
//!
//! # A2 is not weakened by mounting it
//!
//! The ratified A2 ruling is that the **wall clock is only the trigger** and the
//! **release authority reads chain time**. Both halves live below this module
//! and this module must not, and does not, add a third path:
//!
//! * the trigger is [`MaintenancePolicy::interval`] (default 900s) plus the
//!   `lease_until < now_wall` predicate inside `claim_stale_reservations`;
//! * the decision is `resolve_against_chain`'s `block_timestamp()` guard;
//! * **an `Err` is never a release.** Every RPC failure already becomes
//!   `Resolution::Stuck` inside the sweeper, and this module's own error
//!   handling for a *whole pass* that fails ([`run_sweep`]) is to count it and
//!   log it — it never touches a row. There is no code path from here to a
//!   `nonce_allocations` write.
//!
//! `a_failing_rpc_never_releases_a_nonce_through_the_mounted_loop` proves the
//! per-row half through this module's entry point, and
//! `the_mounted_loop_leaves_every_row_reserved_when_the_rpc_is_unreachable`
//! proves it end-to-end through the spawned loop against a **real**
//! [`crate::rpc_chain::RpcChain`] pointed at a dead endpoint.
//!
//! # Mock mode has no release authority at all
//!
//! [`super::runtime::StreamGState::trusted_chain`] is `None` when
//! `GOAT_ATTESTOR_MOCK=1`, so [`run_pass`] skips the sweep entirely rather than
//! resolving rows without chain evidence. A skipped sweep is **not** counted as
//! a pass (`StreamGMetrics::record_sweep` is not called), so
//! `sweep_passes` never claims work that did not happen. Pruning still runs: it
//! reads no chain state.
//!
//! # Cancellation
//!
//! The loop shares [`super::runtime::ShutdownToken`] with `axum`'s graceful
//! shutdown, so one Ctrl-C/SIGTERM stops the server and this loop together.
//!
//! Cancellation is raced **against the sleep only**, never against a pass. Once
//! [`run_pass`] starts it runs to completion, because both steps below it commit
//! through `StreamGStore::write_tx` and dropping such a future mid-statement is
//! how you get a half-applied resolution. The cost is bounded: a cancel that
//! lands during a pass waits for that pass, and a pass is a bounded batch
//! (`max_rows`, default 64) of bounded chain reads. A cancel that lands during
//! the sleep — the overwhelmingly common case, since the loop is asleep for 900
//! of every 900-and-a-bit seconds — is observed immediately.
//!
//! The `select!` is `biased` with the token first, so a token that is already
//! latched when the loop reaches the top wins over a zero-length sleep rather
//! than racing it.
//!
//! # Blocking chain reads
//!
//! `ChainClient` is a **synchronous** trait and `RpcChain` services it with
//! `tokio::task::block_in_place`, so a sweep pass blocks the worker thread it
//! runs on for the duration of its RPC round-trips. That is why
//! `serve-relayer` builds a multi-threaded runtime (`main`'s
//! `Commands::ServeRelayer` arm — `tokio::runtime::Builder::new_multi_thread`
//! with `thread_name("goat-attestor-serve")`), and it is
//! the same posture every mounted pilot handler already has. It is recorded
//! here because it is load-bearing: on a current-thread runtime
//! `block_in_place` panics, so this loop must never be spawned onto one.
//!
//! # Reconciliation (Task 11 Wave D)
//!
//! **Corrected.** This module doc used to end: "`reconcile`'s log observers and
//! `broadcaster`'s paths are still unscheduled … nothing in the brief assigns
//! reconciliation scheduling to any wave." The first half of that is now false
//! and is recorded rather than deleted, same discipline `reconcile.rs` uses: a
//! stale "nothing is wired" doc is exactly how a reader concludes more is
//! disabled than actually is.
//!
//! [`run_reconcile`] is now the third step of every pass. It exists because
//! mounting `POST /v1/stream-g/submit` in Wave C made a hole live:
//! `submit::reconcile_sponsored_enrollment_executed` had **zero** non-test
//! callers, so a successfully broadcast enrollment could never reach
//! `executed`, and the sweeper could not release the row until the parent
//! intent expired on the chain clock.
//!
//! Four properties of that step are load-bearing and are stated here because no
//! single function below carries all four:
//!
//! 1. **It is a step, not a second task.** `reconcile::promote_verified_tx_hash`
//!    has no `status`/`claim_owner` predicate, so a `tokio::spawn`ed observer
//!    could take a row out from under a sweep that had claimed it and was
//!    mid-resolution (the sweeper's chain reads run outside its transaction, by
//!    design). Running both as sequential steps of one task makes that
//!    interleaving structurally impossible rather than merely unlikely. The
//!    store's pool has a single connection, so a concurrent observer would buy
//!    no throughput anyway.
//! 2. **It runs LAST**, after prune. [`run_pass`] handles an `Err` from every
//!    step but nothing catches an unwind, and `main.rs` joins the loop's handle
//!    without respawning it — so a panic anywhere in a pass kills the sweeper
//!    for the life of the process. Ordering the newest, least-exercised step
//!    after the two proven ones bounds what a panic in it can skip. It is
//!    written to the same shape as its siblings for the `Err` case: an outcome
//!    enum, never a `Result`, so [`run_pass`] keeps returning an infallible
//!    [`PassReport`].
//! 3. **Confirmation depth is the entire safety mechanism**, not a
//!    latency/safety trade. See [`MaintenancePolicy::confirmations`].
//! 4. **The cursor advances only on a completed window**, which makes
//!    re-observation the normal case. That is why
//!    `submit::reconcile_executed_for_profile_id` carries an explicit
//!    idempotency guard, and why it is a *precondition* of this step rather
//!    than a nicety.
//!
//!    **Corrected (per-log isolation).** "Advance-on-success-only" used to mean
//!    *every* log, which made one unfoldable log a permanent wedge for the
//!    whole deployment: the `Err` aborted the window, the cursor never passed
//!    that block, and the reachable `Err` variants that are pure functions of
//!    durable state reproduced themselves on every retry. A completed window
//!    may now contain quarantined logs — see
//!    [`reconcile::quarantine_unfoldable_log`] and
//!    [`super::reconcile::ReconcileError::scope`] for what is stepped over, what
//!    is retried, and what stepping over costs.
//!
//!    **Corrected again 2026-07-27.** That classifier was two-valued, and the
//!    "pure function of durable state" claim above was *false* for three of its
//!    four chain-corroboration sites: a receipt a replica had not indexed yet,
//!    and both block-identity mismatches, are readings of an unsettled chain,
//!    not durable facts. They were being quarantined and stepped over — the
//!    wedge fix had traded a visible stall for silent, unrecoverable loss of
//!    real confirmations. The classifier is three-valued now
//!    ([`super::reconcile::ReconcileErrorScope`]) and those three hold the
//!    cursor instead.
//!
//! `broadcaster`'s send path remains unscheduled. Its
//! `consume_broadcaster_nonce` is still uncalled, and that function's own doc
//! now says why this wave could not wire it (there is no durable link from an
//! attempt to its broadcaster-EOA allocation row) instead of naming a wave.

use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::StreamGConfig;

use super::crypto_store::SecretHex;
use super::metrics::StreamGMetrics;
use super::outbox::{self, SweepPolicy, SweepReport};
use super::profile_auth::{self, PruneCounts};
use super::reconcile::{
    self, FinalityPolicy, LogOutcome, ReconcileError, ReconcileErrorScope,
    SCAN_CURSOR_ENROLLMENT_EXECUTED,
};
use super::runtime::StreamGState;
use super::store::StreamGStore;
use super::token_manifest::{DeploymentManifest, TrustedChain};

// ---------------------------------------------------------------------------
// Cadence bounds. Every knob is clamped rather than rejected — see
// `config::parse_u64_clamped`.
// ---------------------------------------------------------------------------

/// Seconds between maintenance passes, default. A2's ratified trigger period.
pub const DEFAULT_SWEEP_INTERVAL_SECONDS: u64 = 900;
/// One minute is the tightest cadence an operator can ask for. A pass takes one
/// chain round-trip per claimed row, so a sub-minute cadence would spend more
/// time sweeping than waiting.
pub const MIN_SWEEP_INTERVAL_SECONDS: u64 = 60;
/// One day. Beyond this the sweeper stops being a recovery mechanism.
pub const MAX_SWEEP_INTERVAL_SECONDS: u64 = 86_400;

pub const MIN_LEASE_TTL_SECONDS: u64 = 30;
pub const MAX_LEASE_TTL_SECONDS: u64 = 86_400;

pub const MIN_SWEEP_MAX_ROWS: u64 = 1;
pub const MAX_SWEEP_MAX_ROWS: u64 = 1_000;

/// Widest block span one [`run_reconcile`] pass will ask a node for, as an
/// **offset added to `from`** — not as a count of blocks. Read the arithmetic
/// below before quoting a number from this constant.
///
/// `RpcChain::sponsored_enrollment_logs` pages internally
/// (`eth_get_logs_chunk`, default 2000 blocks) but bounds **nothing** about the
/// total: `to - from` of ten million becomes five thousand and one sequential
/// `eth_getLogs` round trips inside one `block_in_place`, i.e. a single blocking
/// call of unbounded duration inside a maintenance pass. This constant is that
/// missing bound.
///
/// # What the default actually produces (corrected)
///
/// `scan_and_fold` computes `to = frontier.min(from + max_scan_span)` and the
/// scan window is **`from..=to`, inclusive on both ends** — `eth_getLogs`'
/// `fromBlock`/`toBlock` are inclusive, and `rpc_chain::block_log_ranges`
/// pages it inclusively (`block_log_ranges_splits_inclusive_chunks`). So at the
/// default the widest window is
///
/// * `to - from == 10_000`, therefore **10,001 blocks**, not 10,000; and
/// * `ceil(10_001 / 2_000)` = **6** `eth_getLogs` pages at the default chunk,
///   not 5 — the sixth page is the single block `to`.
///
/// This doc claimed "five chunks per pass" and an implied span of 10,000
/// blocks. Both were wrong by the same off-by-one, and the off-by-one is in
/// **this constant's use, not only in the prose**: a value named
/// `..._SPAN_BLOCKS` that is added to an inclusive lower bound yields one more
/// block than its name says. It is left as-is deliberately — the bound exists
/// to stop an unbounded pass, one extra block and one short page cost nothing,
/// and changing the arithmetic would move the window boundary for every
/// existing deployment cursor. What is fixed here is the claim. If the
/// arithmetic is ever changed to `from + max_scan_span - 1`,
/// `the_cursor_bounds_the_next_window_and_the_span_is_clamped` pins the current
/// boundary (`to == from + DEFAULT_MAX_SCAN_SPAN_BLOCKS`, and the exact
/// `log_ranges` the chain was asked for) and will fail — that is the intended
/// alarm, not a nuisance.
///
/// A cold cursor therefore catches up over several passes instead of one
/// enormous one, and the loop's cadence stays the thing that decides how long a
/// pass takes.
pub const DEFAULT_MAX_SCAN_SPAN_BLOCKS: u64 = 10_000;

/// The `claim_owner` every sweep in this process claims rows as.
///
/// A constant rather than a per-process uuid, deliberately: the OS-level
/// instance lock (`runtime::StreamGState::start`) already guarantees exactly one
/// attestor per Stream G database, so a second *sweeper* identity could only
/// come from a second process that cannot exist. What the value must do is stay
/// **distinct from any submit path's `claim_owner`**, so that the sweeper's
/// compare-and-swap genuinely transfers ownership of a row instead of silently
/// matching whoever reserved it. It contains a character no address-shaped or
/// session-shaped owner string uses.
pub const SWEEPER_CLAIM_OWNER: &str = "stream-g:sweeper";

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Policy.
// ---------------------------------------------------------------------------

/// Everything the loop needs that is not in [`StreamGState`].
///
/// Built once at startup from the validated config and the deployment manifest;
/// there is no path that re-reads env inside the loop, so a running attestor's
/// cadence cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenancePolicy {
    /// Time between passes. See the module doc: this is A2's *trigger*, not any
    /// part of the release decision.
    pub interval: Duration,
    pub lease_ttl_seconds: i64,
    pub max_rows: i64,
    pub claim_owner: String,
    /// `GoatRelayGateway`, taken from the **loaded deployment manifest** rather
    /// than from an env string, so the address `intentUsed(intentId)` is read
    /// from — and, now, the address whose `SponsoredEnrollmentExecuted` logs are
    /// scanned — is the one whose `chainId`/`phase` startup already verified.
    pub gateway: [u8; 20],

    // --- reconciliation (Task 11 Wave D) --------------------------------
    /// How deep a `SponsoredEnrollmentExecuted` log must be buried before
    /// [`run_reconcile`] will fold it. Ratified decision A3, from
    /// [`crate::config::StreamGConfig::confirmations`] — **this field is what
    /// finally makes `STREAM_G_CONFIRMATIONS` a consumed setting rather than a
    /// parsed one.** Built from the operator's configured value via
    /// [`FinalityPolicy::from_confirmations`], deliberately *not* from
    /// `FinalityPolicy::for_chain(chain_id)`, which would silently ignore it.
    ///
    /// 🔴 **This number is the entire reorg protection, not a tuning knob.**
    /// An advisor asked for `2`. Two is not safe on a live L2 under this
    /// design, and the reason is structural rather than a matter of taste:
    ///
    /// * The only undo path in the tree is `reconcile::apply_reorg`, whose sole
    ///   trigger is `ExecutedLog::removed`. That flag is carried straight
    ///   through from the RPC response, and a historical `eth_getLogs` range
    ///   query — which is what this observer issues — returns canonical logs
    ///   only. So **`apply_reorg` is unreachable from here**; a reorged-out log
    ///   simply stops being returned.
    ///
    /// * Nothing persists a confirmed row's block hash. The fold downgrades
    ///   `ExecutedLog` (11 fields) to `submit::SponsoredEnrollmentExecuted` (8),
    ///   dropping `block_hash`, `log_index` and `removed`, so the durable record
    ///   cannot be matched against the canonical chain later even if something
    ///   wanted to.
    ///
    /// Therefore a reorg deeper than this number leaves a permanently wrong
    /// `confirmed` row, a permanently `consumed` nonce, and a status route
    /// reporting success — with **no detector**. The shipped defaults stand:
    /// `reconcile::DEFAULT_CONFIRMATIONS` (12) off anvil,
    /// `reconcile::ANVIL_CONFIRMATIONS` (1) on 31337, where anvil does not reorg
    /// and the containing block is the only confirmation there is.
    /// `STREAM_G_CONFIRMATIONS` remains the operator's tuning surface, and
    /// lowering it is a founder-level risk acceptance, not a configuration
    /// change.
    ///
    /// Counting: `FinalityPolicy::depth(b, head) = head - b + 1`, so the
    /// containing block is confirmation **1** and `2` means "the log's block
    /// plus one more". `0` is refused at config load.
    pub confirmations: u64,
    /// First block [`run_reconcile`] will ever scan, and the seed value when no
    /// cursor row exists yet (`STREAM_G_GATEWAY_DEPLOY_BLOCK`).
    ///
    /// ⚠️ Defaults to `0`, and on every chain but 31337
    /// `RpcChain::sponsored_enrollment_logs` **refuses** an unset pin rather
    /// than asking a managed RPC to scan from genesis (G-B1). So on Base this
    /// step cannot run at all until a deployer supplies the gateway's create
    /// block; the refusal surfaces as [`ReconcileStepOutcome::Failed`] with the
    /// node-side reason logged, and `reconcile_errors` counts it, which is the
    /// visible-failure direction rather than a silent no-op.
    pub gateway_deploy_block: u64,
    /// Widest `to - from` one pass will request. See
    /// [`DEFAULT_MAX_SCAN_SPAN_BLOCKS`].
    pub max_scan_span: u64,
}

impl MaintenancePolicy {
    /// The production constructor: validated config for the knobs, the verified
    /// manifest for the gateway.
    pub fn from_config(cfg: &StreamGConfig, manifest: &DeploymentManifest) -> Self {
        Self {
            interval: Duration::from_secs(cfg.sweep_interval_seconds),
            lease_ttl_seconds: cfg.outbox_lease_ttl_seconds,
            max_rows: cfg.sweep_max_rows,
            claim_owner: SWEEPER_CLAIM_OWNER.to_string(),
            gateway: manifest.goat_relay_gateway,
            confirmations: cfg.confirmations,
            gateway_deploy_block: cfg.gateway_deploy_block,
            max_scan_span: DEFAULT_MAX_SCAN_SPAN_BLOCKS,
        }
    }

    /// The finality policy [`run_reconcile`] applies, rebuilt from the
    /// operator's configured depth.
    fn finality_policy(&self) -> FinalityPolicy {
        FinalityPolicy::from_confirmations(self.confirmations)
    }

    fn sweep_policy(&self) -> SweepPolicy<'_> {
        SweepPolicy {
            claim_owner: &self.claim_owner,
            lease_ttl_seconds: self.lease_ttl_seconds,
            max_rows: self.max_rows,
            gateway: self.gateway,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-pass outcomes.
// ---------------------------------------------------------------------------

/// What the sweep step of one pass did. `Skipped` and `Failed` are distinct
/// from `Swept(SweepReport::default())`: "did not run", "ran and broke" and "ran
/// and found nothing" are three different operational states and collapsing
/// them is how a wedged sweeper looks healthy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SweepStepOutcome {
    /// No live chain client (mock mode). The sweep did not run: without chain
    /// evidence there is no release authority, so skipping is the fail-closed
    /// direction.
    #[default]
    SkippedNoChain,
    /// The pass completed. Rows may still be stuck — see
    /// [`SweepReport::stuck_recoverable`] — which is a *successful* pass
    /// reporting an unresolvable row, not a failed one.
    Swept(SweepReport),
    /// The pass itself returned `Err` (a store failure; RPC failures never get
    /// this far — they become per-row `Stuck`). No row was modified by this
    /// module as a result.
    Failed,
}

/// What the prune step of one pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PruneStepOutcome {
    #[default]
    Failed,
    Pruned(PruneCounts),
}

/// What the reconciliation step of one pass did.
///
/// Same three-way distinction [`SweepStepOutcome`] draws, for the same reason:
/// "did not run", "ran and broke" and "ran and found nothing" are different
/// operational states, and collapsing them is how a wedged observer looks
/// healthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReconcileStepOutcome {
    /// No live chain client (mock mode). Nothing was read and nothing was
    /// written. Not counted as a pass, exactly as
    /// [`SweepStepOutcome::SkippedNoChain`] is not.
    #[default]
    SkippedNoChain,
    /// The head has not moved far enough past the cursor for any block to have
    /// reached the confirmation depth yet, so no `eth_getLogs` was issued. A
    /// completed pass over an empty window — counted.
    NothingToScan { from: u64, head: u64 },
    /// `[from, to]` was scanned. `logs` is how many were observed; the other two
    /// counts are the two ways a log can fail to fold, and they are separate
    /// fields because **they have opposite durability**:
    ///
    /// * `quarantined` — permanently unfoldable
    ///   ([`ReconcileErrorScope::LogPermanent`]), recorded durably by
    ///   [`reconcile::quarantine_unfoldable_log`] and **stepped over**.
    ///   `quarantined > 0` is a *successful pass with data loss in it*: those
    ///   logs will never be observed again. It is a field rather than an `Err`
    ///   because the alternative — failing the pass — is precisely the wedge
    ///   Wave D removed.
    /// * `stalled` — not corroborated *yet*
    ///   ([`ReconcileErrorScope::LogTransient`]). **Nothing is lost and nothing
    ///   is stepped over**; the cursor is held and the log is retried on the
    ///   next pass. `stalled > 0` therefore always implies `!cursor_advanced`.
    ///
    /// Collapsing the two would be the defect this wave fixed, in the reporting
    /// layer instead of the classifier: an operator cannot act on "a log did not
    /// fold" without knowing whether it is coming back.
    ///
    /// The cursor advanced to `to` unless `cursor_advanced` is `false`, which
    /// happens when a second head reading put a log back below the depth, or
    /// when a log stalled (see [`run_reconcile`]).
    Scanned {
        from: u64,
        to: u64,
        logs: usize,
        quarantined: usize,
        stalled: usize,
        cursor_advanced: bool,
    },
    /// The pass returned `Err` — a chain read, a store write or a quarantine
    /// record failed. **The cursor was not advanced**, so the same window is
    /// retried on the next pass; the idempotent fold absorbs whatever already
    /// landed.
    ///
    /// Note what is *not* here any more: a single unfoldable log. That used to
    /// land on this variant and hold the cursor forever.
    Failed,
}

/// One maintenance pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PassReport {
    pub sweep: SweepStepOutcome,
    pub prune: PruneStepOutcome,
    pub reconcile: ReconcileStepOutcome,
}

// ---------------------------------------------------------------------------
// Steps.
// ---------------------------------------------------------------------------

/// One sweep, with its outcome folded into the counters.
///
/// **This function is where the fail-closed contract is preserved across the
/// mount.** `sweep_stuck_reservations` already guarantees that no `Err` from an
/// RPC releases a nonce; the risk mounting introduces is a caller that "handles"
/// a failed pass by doing something itself. This one does exactly two things
/// with an `Err`: increments `sweep_errors` and logs it. It issues no SQL.
///
/// The error is logged *here* rather than inside
/// [`StreamGMetrics::record_sweep_error`], whose doc explicitly says "the caller
/// is the right place to log the error itself, at its own level" — the metrics
/// module refuses to take an error argument because an `OutboxError` renders SQL
/// and chain-resolution detail.
pub async fn run_sweep(
    store: &StreamGStore,
    chain: TrustedChain<'_>,
    metrics: &StreamGMetrics,
    policy: &MaintenancePolicy,
    now_wall: i64,
) -> SweepStepOutcome {
    match outbox::sweep_stuck_reservations(store, chain, &policy.sweep_policy(), now_wall).await {
        Ok(report) => {
            metrics.record_sweep(&report);
            if report.stuck_recoverable() > 0 {
                // Count only. The per-row `StuckAttempt::reason` quotes chain
                // resolution detail and names a specific reserved row, and spec
                // §9.3's rule for this crate is that nothing carrying that kind
                // of detail reaches an ordinary log line. DISCLOSED GAP: the
                // reason is therefore visible only to a caller holding the
                // `SweepReport` in memory — `defer_attempt` does not persist it
                // to `error_message` either. Making a stuck row's reason durable
                // is a write-path change in `outbox.rs` and is not this wave's.
                tracing::warn!(
                    stuck = report.stuck_recoverable(),
                    claimed = report.claimed,
                    "stream G sweep left rows reserved (stuck-recoverable); they keep their raw \
                     transaction and will be retried on the next pass"
                );
            }
            SweepStepOutcome::Swept(report)
        }
        Err(e) => {
            metrics.record_sweep_error();
            tracing::error!(
                error = %e,
                "stream G sweep pass failed; no reservation was released or resolved by this pass"
            );
            SweepStepOutcome::Failed
        }
    }
}

/// One `profile_auth::prune_expired`, logged.
///
/// Failure is non-fatal and does not abort the pass: an unprunable
/// `auth_challenges` table is a growth problem, not a correctness one, and it
/// must not stop the sweeper from running.
pub async fn run_prune(store: &StreamGStore) -> PruneStepOutcome {
    match profile_auth::prune_expired(store).await {
        Ok(counts) => {
            if counts.challenges_deleted > 0 || counts.sessions_deleted > 0 {
                tracing::debug!(
                    challenges_deleted = counts.challenges_deleted,
                    sessions_deleted = counts.sessions_deleted,
                    "stream G pruned expired auth rows"
                );
            }
            PruneStepOutcome::Pruned(counts)
        }
        Err(e) => {
            tracing::error!(error = %e, "stream G prune of expired auth rows failed");
            PruneStepOutcome::Failed
        }
    }
}

/// One reconciliation scan, with its outcome folded into the counters.
///
/// # What this does that the fold cannot
///
/// Every log goes through [`reconcile::reconcile_executed_log`], **never**
/// through `submit::reconcile_executed_for_profile_id` directly. That is not a
/// stylistic preference:
///
/// * the fold performs **no chain read of any kind**, so a caller that invokes
///   it directly confirms at depth 0 by construction;
/// * `reconcile_executed_log` is what corroborates the receipt (it exists, it
///   succeeded, it is in the block *and* the block hash the log claims), applies
///   the finality policy, and safely fills a NULL `tx_hash` from the chain
///   rather than from a caller;
/// * it resolves the owning profile out of the store
///   (`candidates_for_intent_id` reads `intents.profile_id`), which is the only
///   thing a background worker can do — `AuthenticatedProfileId` is a proof of
///   possession and has no non-test constructor, so
///   `submit::reconcile_sponsored_enrollment_executed` is unusable from here and
///   stays unused.
///
/// # The window
///
/// `from` is `cursor + 1`, floored at the gateway deploy block. `to` is the
/// deepest block that already carries [`MaintenancePolicy::confirmations`]
/// confirmations at this head — `head - (confirmations - 1)` — clamped to
/// [`MaintenancePolicy::max_scan_span`]. Both bounds matter: the first is the
/// only reorg protection this design has, the second is the only bound on how
/// many `eth_getLogs` round trips one blocking pass can make.
///
/// The window is `from..=to` — **inclusive on both ends**, so the widest one is
/// `max_scan_span + 1` blocks (10,001 at the default, six pages at the default
/// 2000-block chunk, the last of them one block wide). See
/// [`DEFAULT_MAX_SCAN_SPAN_BLOCKS`] for why the name says one thing and the
/// arithmetic another, and why the arithmetic was left alone.
///
/// # The cursor
///
/// Advanced to `to` in its own transaction, after the window's logs have been
/// processed. Three distinct things can stop it, and keeping them distinct is
/// the whole design:
///
/// * a **window-level** `Err` — the node could not be asked, the store could
///   not be written, a quarantine record could not be made durable. The cursor
///   is left alone and the entire window is retried next pass. An RPC failure
///   fetching the logs is this, and is emphatically **not** a poisoned log.
/// * a **`NotFinalYet`** log. `reconcile_executed_log` re-reads the head
///   itself, so a node that reports a *lower* head than the one this window was
///   computed from can put a log back below the depth; that writes nothing, and
///   this function then declines to advance at all rather than stepping over
///   the block.
/// * a **per-log** `Err` that [`ReconcileError::scope`] calls
///   [`ReconcileErrorScope::LogTransient`] — the receipt is not on this replica
///   yet, or it is on the other side of a fork. Holds the cursor, keeps folding
///   the rest of the window, counted in `reconcile_stalled_logs` and **warned
///   on every pass**. Nothing is lost; the stall is deliberately unbounded and
///   deliberately loud.
/// * a **per-log** `Err` that [`ReconcileError::scope`] calls
///   [`ReconcileErrorScope::LogPermanent`]. This one does **not** stop the
///   cursor. The log is quarantined (a durable `reconciliation_events` row),
///   counted in `reconcile_log_errors`, logged, and stepped over — because
///   holding the cursor for it wedges reconciliation for the entire deployment
///   forever, which is what this function used to do. 🔴 The cost is real and
///   is not hidden: that log is never observed again. Which is exactly why the
///   `LogTransient` arm above exists — until 2026-07-27 it did not, and every
///   uncorroborated log took *this* arm.
///
/// # Failure shape
///
/// Returns an outcome, never a `Result` — [`run_pass`] contains no `?` and must
/// keep returning an infallible [`PassReport`]. There is no `unwrap`, `expect`
/// or indexing on anything derived from chain data anywhere below, because
/// nothing catches an unwind: a panic here would kill the sweeper for the life
/// of the process.
///
/// The error is logged *here* rather than in
/// [`StreamGMetrics::record_reconcile_error`], for the reason that function's
/// doc gives: a `ReconcileError` renders SQL, chain-resolution detail and
/// transaction hashes, and this crate's rule (spec §9.3) is that nothing
/// carrying that kind of detail reaches a counter. Per-log detail is not logged
/// at all — only the counted transition.
pub async fn run_reconcile(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    chain: TrustedChain<'_>,
    metrics: &StreamGMetrics,
    policy: &MaintenancePolicy,
    now_wall: i64,
) -> ReconcileStepOutcome {
    match scan_and_fold(store, data_key_hex, chain, metrics, policy, now_wall).await {
        Ok(outcome) => outcome,
        Err(e) => {
            metrics.record_reconcile_error();
            tracing::error!(
                error = %e,
                "stream G reconciliation pass failed; the scan cursor was NOT advanced and this \
                 window will be retried on the next pass"
            );
            ReconcileStepOutcome::Failed
        }
    }
}

/// The fallible body of [`run_reconcile`]. Split out so the `Err` handling has
/// exactly one place to live and cannot be forgotten on a new early return.
async fn scan_and_fold(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    chain: TrustedChain<'_>,
    metrics: &StreamGMetrics,
    policy: &MaintenancePolicy,
    now_wall: i64,
) -> Result<ReconcileStepOutcome, ReconcileError> {
    let finality = policy.finality_policy();
    let head = chain
        .client()
        .pinned_block_number()
        .map_err(|e| ReconcileError::Chain(format!("pinned_block_number: {e}")))?;

    let cursor = reconcile::load_scan_cursor(store, SCAN_CURSOR_ENROLLMENT_EXECUTED).await?;
    // `None` (never scanned) seeds at the deploy block itself; a stored cursor
    // means that block is already folded, so the next one is `+ 1`. The floor
    // is re-applied either way so that raising `STREAM_G_GATEWAY_DEPLOY_BLOCK`
    // cannot make the window start below the pin the node will accept.
    let from = match cursor {
        Some(c) => c.saturating_add(1).max(policy.gateway_deploy_block),
        None => policy.gateway_deploy_block,
    };

    // The deepest block that already has `confirmations` confirmations:
    // `depth(b, head) = head - b + 1 >= confirmations`  <=>  `b <= head - (confirmations - 1)`.
    // `checked_sub` rather than `saturating_sub`: on a chain whose head is still
    // below the depth, "block 0 is final" is wrong, and saturating would say it.
    let frontier = match head.checked_sub(policy.confirmations.saturating_sub(1)) {
        Some(f) => f,
        None => {
            metrics.record_reconcile_pass(0);
            return Ok(ReconcileStepOutcome::NothingToScan { from, head });
        }
    };
    if frontier < from {
        metrics.record_reconcile_pass(0);
        return Ok(ReconcileStepOutcome::NothingToScan { from, head });
    }
    let to = frontier.min(from.saturating_add(policy.max_scan_span));

    let logs = chain
        .client()
        .sponsored_enrollment_logs(policy.gateway, from, to)
        .map_err(|e| {
            ReconcileError::Chain(format!("sponsored_enrollment_logs({from}..={to}): {e}"))
        })?;
    let observed = logs.len();

    let mut cursor_advanced = true;
    let mut quarantined = 0usize;
    let mut stalled = 0usize;
    for log in &logs {
        match reconcile::reconcile_executed_log(store, data_key_hex, chain, finality, log, now_wall)
            .await
        {
            Ok(outcome) => {
                metrics.record_log_outcome(&outcome);
                if matches!(outcome, LogOutcome::NotFinalYet { .. }) {
                    // Nothing was written for this log. The window was computed
                    // from an earlier head reading; a node that has since
                    // reported a lower head (a lagging replica behind a load
                    // balancer is the ordinary cause) can put a log back below
                    // the depth. Advancing over it would lose its confirmation
                    // permanently, because nothing re-reads history.
                    cursor_advanced = false;
                }
            }
            // 🔴 PER-LOG ISOLATION. This `match` replaces a `?`, and the `?` was
            // the wedge: one log's `Err` aborted the window, which skipped
            // `save_scan_cursor`, which meant the cursor never passed that
            // block — for every profile and every later block — and several
            // reachable `Err` variants are pure functions of durable state, so
            // the next pass reproduced it exactly. It did not self-heal.
            //
            // THREE classes, and the split is `ReconcileError::scope`, not a
            // guess here. It was two classes until 2026-07-27, and the missing
            // third is what turned this wedge fix into silent data loss: a
            // receipt a lagging replica had not indexed yet was filed as
            // "permanently unfoldable", quarantined, and stepped over — an
            // auditor confirmed the identical input succeeded on the very next
            // pass once the receipt was armed.
            Err(e) if e.scope() == ReconcileErrorScope::LogPermanent => {
                // (a) THIS LOG is unfoldable and always will be. Count it,
                //     record it durably, step over it. The durable row is what
                //     makes this a quarantine rather than a silent skip: the
                //     cursor is about to move past a log that will never be
                //     observed again, and an operator has to be able to find
                //     out which one.
                //
                //     The quarantine write is `?` on purpose: if the record
                //     cannot be made durable, the skip would be silent, and a
                //     silent skip is a different failure mode rather than a
                //     fix. So a failed quarantine write becomes a WINDOW
                //     failure — the cursor stays put and the whole window is
                //     retried, which is the fail-closed direction.
                metrics.record_reconcile_log_error();
                quarantined = quarantined.saturating_add(1);
                tracing::error!(
                    error = %e,
                    code = e.code(),
                    block = log.block_number,
                    "stream G reconciliation could not fold one log; it is being QUARANTINED and \
                     the cursor will advance past it, so it will NEVER be observed again — see \
                     the reconciliation_events row of type \
                     'SponsoredEnrollmentExecuted.quarantined'"
                );
                reconcile::quarantine_unfoldable_log(store, data_key_hex, log, e.code(), now_wall)
                    .await?;
            }
            Err(e) if e.scope() == ReconcileErrorScope::LogTransient => {
                // (b) THIS LOG is not corroborated *yet* — no receipt on this
                //     replica, or a receipt from the other side of a fork.
                //     Identical input can succeed on the next pass, so
                //     quarantining it would throw away a recoverable
                //     confirmation, and nothing reads behind the cursor to get
                //     it back.
                //
                //     Hold the cursor — the same mechanism `NotFinalYet` uses,
                //     deliberately, because the durable requirement is
                //     identical. The loop does NOT break: every other log in
                //     this window still folds, so one stalled log costs a
                //     repeated scan rather than the deployment's progress. The
                //     re-fold is idempotent.
                //
                //     🔴 THE STALL IS UNBOUNDED, AND THAT IS THE CHOSEN FAILURE
                //     MODE. If a receipt never appears, this cursor never
                //     advances. That is the visible half of the trade the wedge
                //     fix got backwards: an operator can see a stall on
                //     `reconcile_stalled_logs` and in this WARN and clear it;
                //     nobody can recover a confirmation that was quarantined
                //     and stepped over. See
                //     `StreamGMetrics::record_reconcile_stalled_log` for the
                //     three-counter table an operator reads this off.
                metrics.record_reconcile_stalled_log();
                stalled = stalled.saturating_add(1);
                cursor_advanced = false;
                tracing::warn!(
                    error = %e,
                    code = e.code(),
                    block = log.block_number,
                    "stream G reconciliation could not corroborate one log YET; the scan cursor is \
                     being HELD at this block and the log will be retried on every pass. Nothing \
                     was dropped. If this does not clear, the cursor is stuck and needs an \
                     operator — see the reconcile_stalled_logs counter"
                );
            }
            Err(e) => {
                // (c) THE ENVIRONMENT failed — an RPC that could not be asked,
                //     a store that could not be written. That is not a poisoned
                //     log and it must NOT advance the cursor: the same window
                //     is retried and the idempotent fold absorbs whatever
                //     already landed. Propagating is exactly the old behaviour,
                //     kept deliberately for this class only.
                return Err(e);
            }
        }
    }

    if cursor_advanced {
        reconcile::save_scan_cursor(store, SCAN_CURSOR_ENROLLMENT_EXECUTED, to, now_wall).await?;
    }
    metrics.record_reconcile_pass(observed as u64);
    Ok(ReconcileStepOutcome::Scanned {
        from,
        to,
        logs: observed,
        quarantined,
        stalled,
        cursor_advanced,
    })
}

/// One full pass: sweep (if there is a chain), then prune, then reconcile.
///
/// The sweep is first because it is the recovery mechanism and the prune is
/// housekeeping; a prune failure must never delay a sweep.
///
/// Reconciliation is **last**, and deliberately not between the two. Two
/// reasons, in order:
///
/// * *Isolation.* Every step handles its own `Err`, but nothing here catches an
///   unwind and `main.rs` joins the loop's handle without respawning it, so a
///   panic in any step kills the sweeper for the life of the process. The newest
///   and least-exercised step therefore runs after the two proven ones, which
///   bounds what a panic in it can skip to itself.
/// * *Race elimination.* `reconcile::promote_verified_tx_hash` has no `status`
///   or `claim_owner` predicate and can take a row out from under a sweep that
///   claimed it. Sequencing the two as steps of one task — in either order —
///   makes that interleaving impossible; what matters is that neither is
///   `tokio::spawn`ed.
pub async fn run_pass(
    state: &StreamGState,
    policy: &MaintenancePolicy,
    now_wall: i64,
) -> PassReport {
    let sweep = match state.trusted_chain() {
        Some(chain) => run_sweep(state.store(), chain, state.metrics(), policy, now_wall).await,
        None => {
            tracing::debug!(
                "stream G maintenance: no live chain client (GOAT_ATTESTOR_MOCK=1), so the \
                 sweeper has no release authority and is skipped this pass"
            );
            SweepStepOutcome::SkippedNoChain
        }
    };
    let prune = run_prune(state.store()).await;
    // Same `match` on `trusted_chain()` as the sweep, and for the same reason —
    // this is not a flag check. `StreamGState::start` sets the client to `None`
    // when `GOAT_ATTESTOR_MOCK=1`, and `trusted_chain()` can only wrap the
    // concrete `RpcChain`, so no value of this state can hand a `MockChain` to a
    // live-read path. A reconciliation with no chain would be a fold with no
    // receipt, no head and therefore no confirmation depth.
    let reconcile = match state.trusted_chain() {
        Some(chain) => {
            run_reconcile(
                state.store(),
                state.data_key_hex(),
                chain,
                state.metrics(),
                policy,
                now_wall,
            )
            .await
        }
        None => {
            tracing::debug!(
                "stream G maintenance: no live chain client (GOAT_ATTESTOR_MOCK=1), so there is \
                 no way to corroborate a log or measure its confirmation depth; reconciliation \
                 is skipped this pass"
            );
            ReconcileStepOutcome::SkippedNoChain
        }
    };
    PassReport {
        sweep,
        prune,
        reconcile,
    }
}

// ---------------------------------------------------------------------------
// The loop.
// ---------------------------------------------------------------------------

/// Run maintenance passes until the state's shutdown token is cancelled.
/// Returns the number of **completed** passes.
///
/// Sleeps *before* the first pass rather than sweeping at startup: nothing is
/// more stale one millisecond after the store opens than it was one millisecond
/// before, and a boot-time burst of RPC would be the worst moment for it. The
/// lease TTL, not the loop, is what decides a row is stale.
pub async fn run_maintenance_loop(state: StreamGState, policy: MaintenancePolicy) -> u64 {
    let token = state.shutdown().clone();
    let mut passes: u64 = 0;

    tracing::info!(
        interval_seconds = policy.interval.as_secs(),
        lease_ttl_seconds = policy.lease_ttl_seconds,
        max_rows = policy.max_rows,
        confirmations = policy.confirmations,
        gateway_deploy_block = policy.gateway_deploy_block,
        max_scan_span = policy.max_scan_span,
        live_chain = state.live_chain().is_some(),
        "stream G maintenance loop started"
    );

    loop {
        tokio::select! {
            // `biased`: an already-latched token must win over a sleep that is
            // also immediately ready, rather than racing it.
            biased;
            _ = token.cancelled() => break,
            _ = tokio::time::sleep(policy.interval) => {}
        }

        // A pass is never raced against cancellation (module doc), so the last
        // chance to *not* start one is here.
        if token.is_cancelled() {
            break;
        }

        let report = run_pass(&state, &policy, now_unix_seconds()).await;
        passes = passes.saturating_add(1);

        // Per-pass metrics report (Wave C's counters). Every field below is a
        // `u64` out of `MetricsSnapshot`, which has no `String` field — there is
        // nowhere for a signed payload or a session token to appear in this
        // line.
        let snapshot = state.metrics().snapshot();
        tracing::info!(
            pass = passes,
            sweep_ran = matches!(report.sweep, SweepStepOutcome::Swept(_)),
            sweep_passes = snapshot.sweep_passes,
            sweep_errors = snapshot.sweep_errors,
            sweep_claimed = snapshot.sweep_claimed,
            sweep_released = snapshot.sweep_released,
            sweep_executed = snapshot.sweep_executed,
            sweep_held_intent_still_valid = snapshot.sweep_held_intent_still_valid,
            sweep_stuck = snapshot.sweep_stuck,
            reconcile_ran = matches!(report.reconcile, ReconcileStepOutcome::Scanned { .. }),
            reconcile_passes = snapshot.reconcile_passes,
            reconcile_errors = snapshot.reconcile_errors,
            // A non-zero value here means at least one log was stepped over and
            // will never be observed again. It is on the pass line rather than
            // only on the metrics route so it appears in the operator's log at
            // the moment it happens.
            reconcile_log_errors = snapshot.reconcile_log_errors,
            // And its opposite: a value that RISES pass over pass here means the
            // cursor is being HELD for a log the chain has not corroborated
            // yet — nothing was dropped, but nothing past it is progressing
            // either. The two must be side by side, because reading one without
            // the other is how an operator mistakes a stall for a drop.
            reconcile_stalled_logs = snapshot.reconcile_stalled_logs,
            reconcile_logs_observed = snapshot.reconcile_logs_observed,
            reconcile_confirmed = snapshot.reconcile_confirmed,
            reconcile_externally_fulfilled = snapshot.reconcile_externally_fulfilled,
            reconcile_not_final_yet = snapshot.reconcile_not_final_yet,
            reconcile_no_candidates = snapshot.reconcile_no_candidates,
            "stream G maintenance pass complete"
        );
    }

    tracing::info!(
        passes,
        "stream G maintenance loop stopped (shutdown token cancelled)"
    );
    passes
}

/// Spawn [`run_maintenance_loop`] onto the current runtime.
///
/// The task owns a `StreamGState` clone, which owns an `Arc` to the SQLite pool
/// and to the `fs2` instance lock. `main.rs` therefore **joins** this handle
/// before returning from `serve-relayer`, so the lock is released deliberately
/// rather than by process death.
///
/// Must be spawned on a multi-threaded runtime — see the module doc's note on
/// `block_in_place`.
pub fn spawn(state: StreamGState, policy: MaintenancePolicy) -> tokio::task::JoinHandle<u64> {
    tokio::spawn(run_maintenance_loop(state, policy))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::Mutex;

    use crate::chain::{
        BatchView, ChainClient, ChainError, ExecutedLog, TxHash as ChainTxHash, TxReceiptView,
    };
    use crate::config;
    use crate::stream_g::base_fee::{GasUnits, MaxFeePerGas};
    use crate::stream_g::crypto_store::SecretHex;
    use crate::stream_g::models::ActionType;
    use crate::stream_g::outbox::{
        reserve_and_persist_raw_tx, ReservationRequest, ReservedAttempt, SignedRawTx,
        DEFAULT_LEASE_TTL_SECONDS, DEFAULT_SWEEP_MAX_ROWS,
    };
    use crate::stream_g::runtime::{ShutdownController, StreamGState};
    use crate::stream_g::store::StreamGStoreError;
    use crate::stream_g::submit::{
        NONCE_STATUS_ALLOCATED, NONCE_STATUS_CONSUMED, TX_ATTEMPT_STATUS_CONFIRMED,
        TX_ATTEMPT_STATUS_RESERVED,
    };

    const PROFILE: &str = "profile-maintenance-1";
    const CHAIN_ID: u64 = 31337;
    const GATEWAY: [u8; 20] = [0x11; 20];
    const CONTROLLER: [u8; 20] = [0x22; 20];
    const INTENT_ID: [u8; 32] = [0x33; 32];
    const ACTION_NONCE: u64 = 7;

    /// Chain clock, deliberately far below the wall clock so the two can never
    /// be confused for one another.
    const CHAIN_NOW: u64 = 1_700_000_000;
    const WALL_NOW: i64 = 1_800_000_000;

    fn data_key_hex() -> SecretHex {
        SecretHex::from_hex(&hex::encode([0x42u8; 32])).expect("valid 32-byte test key")
    }

    // --- chain double ----------------------------------------------------
    //
    // `outbox`'s own `FakeChain` lives inside its private `mod tests`, so this
    // module has its own rather than making that one `pub(crate)` (which would
    // put a test double on the crate surface). Only six `ChainClient` methods
    // have no default body; everything else the sweeper does not call inherits
    // the trait's `Err` default, which is the correct answer for a double
    // anyway.

    #[derive(Default)]
    struct FakeChainInner {
        receipt: Option<Result<Option<TxReceiptView>, String>>,
        /// Per-transaction override, consulted before `receipt`.
        ///
        /// A real node answers `eth_getTransactionReceipt` per hash, and the
        /// hash-blind `receipt` field cannot express the one window this
        /// module's whole per-log isolation design is about: **two logs in one
        /// window with different fates**. Without this, arming a permanently
        /// contradicted log also contradicts the healthy log beside it, and a
        /// test for "the poisoned one is stepped over and the good one still
        /// folds" cannot be written at all.
        receipt_by_tx: std::collections::HashMap<[u8; 32], Result<Option<TxReceiptView>, String>>,
        intent_used: Option<Result<bool, String>>,
        block_timestamp: Option<Result<u64, String>>,
        pinned_block: Option<Result<u64, String>>,
        /// Answered for **any** `[from, to]`. Deliberately range-blind: a fake
        /// that filtered by block would silently make the window arithmetic in
        /// `scan_and_fold` untestable, because a log outside the window would be
        /// absent for two different reasons that look identical.
        logs: Option<Result<Vec<ExecutedLog>, String>>,
        log_ranges: Vec<(u64, u64)>,
    }

    struct FakeChain {
        inner: Mutex<FakeChainInner>,
    }

    impl FakeChain {
        /// Answers every read the sweeper makes: not mined, intent not used,
        /// chain time `CHAIN_NOW`.
        fn healthy() -> Self {
            Self {
                inner: Mutex::new(FakeChainInner {
                    receipt: Some(Ok(None)),
                    intent_used: Some(Ok(false)),
                    block_timestamp: Some(Ok(CHAIN_NOW)),
                    pinned_block: Some(Ok(4242)),
                    // Unarmed: `sponsored_enrollment_logs` errors rather than
                    // returning `Ok(vec![])`. "The chain says nothing executed
                    // in this range" is a positive claim a reconciler acts on,
                    // and a default that made it for free would let every
                    // reconcile test pass without ever arming a chain.
                    ..FakeChainInner::default()
                }),
            }
        }

        fn set_intent_used(&self, v: Result<bool, String>) {
            self.inner.lock().unwrap().intent_used = Some(v);
        }

        fn set_pinned_block(&self, v: Result<u64, String>) {
            self.inner.lock().unwrap().pinned_block = Some(v);
        }

        fn set_receipt(&self, v: Result<Option<TxReceiptView>, String>) {
            self.inner.lock().unwrap().receipt = Some(v);
        }

        /// Arm `eth_getTransactionReceipt` for **one** hash, leaving every other
        /// hash on whatever [`set_receipt`](Self::set_receipt) armed.
        fn set_receipt_for(&self, tx: [u8; 32], v: Result<Option<TxReceiptView>, String>) {
            self.inner.lock().unwrap().receipt_by_tx.insert(tx, v);
        }

        fn set_logs(&self, v: Result<Vec<ExecutedLog>, String>) {
            self.inner.lock().unwrap().logs = Some(v);
        }

        /// Every `[from, to]` this chain was asked for, in order. This is what
        /// makes the cursor observable without reading the table.
        fn log_ranges(&self) -> Vec<(u64, u64)> {
            self.inner.lock().unwrap().log_ranges.clone()
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

        fn block_timestamp(&self) -> Result<u64, ChainError> {
            match &self.inner.lock().unwrap().block_timestamp {
                Some(Ok(t)) => Ok(*t),
                Some(Err(e)) => Err(ChainError::Msg(e.clone())),
                None => Err(unset("block_timestamp")),
            }
        }
        fn pinned_block_number(&self) -> Result<u64, ChainError> {
            match &self.inner.lock().unwrap().pinned_block {
                Some(Ok(b)) => Ok(*b),
                Some(Err(e)) => Err(ChainError::Msg(e.clone())),
                None => Err(unset("pinned_block_number")),
            }
        }
        fn transaction_receipt(
            &self,
            hash: ChainTxHash,
        ) -> Result<Option<TxReceiptView>, ChainError> {
            let g = self.inner.lock().unwrap();
            match g.receipt_by_tx.get(&hash).or(g.receipt.as_ref()) {
                Some(Ok(r)) => Ok(r.clone()),
                Some(Err(e)) => Err(ChainError::Msg(e.clone())),
                None => Err(unset("transaction_receipt")),
            }
        }
        fn intent_used(
            &self,
            _gateway: [u8; 20],
            _intent_id: [u8; 32],
            _block: u64,
        ) -> Result<bool, ChainError> {
            match &self.inner.lock().unwrap().intent_used {
                Some(Ok(v)) => Ok(*v),
                Some(Err(e)) => Err(ChainError::Msg(e.clone())),
                None => Err(unset("intent_used")),
            }
        }
        fn sponsored_enrollment_logs(
            &self,
            _g: [u8; 20],
            f: u64,
            t: u64,
        ) -> Result<Vec<ExecutedLog>, ChainError> {
            let mut g = self.inner.lock().unwrap();
            g.log_ranges.push((f, t));
            match &g.logs {
                Some(Ok(v)) => Ok(v.clone()),
                Some(Err(e)) => Err(ChainError::Msg(e.clone())),
                None => Err(unset("sponsored_enrollment_logs")),
            }
        }
    }

    // --- fixtures --------------------------------------------------------

    fn test_policy(interval: Duration) -> MaintenancePolicy {
        MaintenancePolicy {
            interval,
            lease_ttl_seconds: DEFAULT_LEASE_TTL_SECONDS,
            max_rows: DEFAULT_SWEEP_MAX_ROWS,
            claim_owner: SWEEPER_CLAIM_OWNER.to_string(),
            gateway: GATEWAY,
            // 31337's A3 default. Every reconcile test below picks its own head
            // relative to this, so a change here is visible rather than silent.
            confirmations: reconcile::ANVIL_CONFIRMATIONS,
            gateway_deploy_block: 0,
            max_scan_span: DEFAULT_MAX_SCAN_SPAN_BLOCKS,
        }
    }

    /// A started state over a fresh temp dir. `mock_mode` stays on, so
    /// `trusted_chain()` is `None`.
    async fn mock_state(dir: &Path) -> (ShutdownController, StreamGState) {
        let cfg = crate::stream_g::runtime::test_support::enabled_cfg(dir);
        let controller = ShutdownController::new();
        let state = StreamGState::start(&cfg, controller.token())
            .await
            .expect("stream G startup");
        (controller, state)
    }

    /// A started state with a **real** `RpcChain` pointed at a dead endpoint:
    /// `trusted_chain()` is `Some`, and every RPC call fails fast with a
    /// connection error. This is the production shape of the loop, with the
    /// node down.
    async fn live_but_unreachable_state(dir: &Path) -> (ShutdownController, StreamGState) {
        let mut map: HashMap<String, String> =
            crate::stream_g::runtime::test_support::enabled_map(dir);
        map.insert("GOAT_ATTESTOR_MOCK".into(), "0".into());
        // Port 1, literal loopback IP: refused immediately, no DNS.
        map.insert("RPC_URL".into(), "http://127.0.0.1:1".into());
        let cfg = config::load_from_map(&map).expect("config");
        assert!(!cfg.mock_mode);
        let controller = ShutdownController::new();
        let state = StreamGState::start(&cfg, controller.token())
            .await
            .expect("stream G startup");
        assert!(
            state.trusted_chain().is_some(),
            "this fixture exists to give the loop a live chain client"
        );
        (controller, state)
    }

    async fn seed_intent(store: &StreamGStore, intent_expires_at: i64) {
        seed_intent_id(store, INTENT_ID, intent_expires_at).await
    }

    /// [`seed_intent`] for an explicit on-chain intent id, so a test can own two
    /// intents that legitimately contend for one action-nonce slot.
    async fn seed_intent_id(store: &StreamGStore, intent_id: [u8; 32], intent_expires_at: i64) {
        let intent_row = crate::stream_g::submit::intent_row_id(PROFILE, intent_id);
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT OR IGNORE INTO profiles (id, created_at, status) \
                         VALUES (?, ?, 'active')",
                    )
                    .bind(PROFILE)
                    .bind(0i64)
                    .execute(&mut **tx)
                    .await?;
                    sqlx::query(
                        "INSERT INTO intents (id, profile_id, intent_type, status, \
                         created_at, expires_at) \
                         VALUES (?, ?, 'sponsored_enrollment', 'pending', 0, ?)",
                    )
                    .bind(&intent_row)
                    .bind(PROFILE)
                    .bind(intent_expires_at)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed intent");
    }

    /// Reserve a row through the production reservation, then age its lease so
    /// the very next sweep sees it as stale. `intent_expires_at` is a
    /// **chain-clock** deadline already in the past, so nothing but the error
    /// handling can hold the row.
    async fn reserve_stale(store: &StreamGStore) -> ReservedAttempt {
        seed_intent(store, (CHAIN_NOW as i64) - 600).await;
        let req = ReservationRequest {
            profile_id: PROFILE,
            intent_id: INTENT_ID,
            chain_id: CHAIN_ID,
            controller: CONTROLLER,
            action: ActionType::SponsoredEnrollment,
            action_nonce: ACTION_NONCE,
            claim_owner: "submit-path-owner",
            lease_ttl_seconds: DEFAULT_LEASE_TTL_SECONDS,
        };
        let signed = SignedRawTx::new(
            vec![0x02, 0xf8, 0x6b, 0xAA, 0xBB, 0xCC],
            GasUnits::new(500_000),
            MaxFeePerGas::new(1_000_000_000),
        );
        let attempt = reserve_and_persist_raw_tx(store, &data_key_hex(), &req, &signed, WALL_NOW)
            .await
            .expect("reserve");
        let attempt_id = attempt.attempt_id.clone();
        // Aged against the **real** wall clock, not `WALL_NOW`: the mounted loop
        // reads `now_unix_seconds()` itself, and `WALL_NOW` is a synthetic
        // future timestamp, so a lease of `WALL_NOW - 1` would still be in the
        // future for the loop and the row would never look stale. This value is
        // also strictly below `WALL_NOW`, so the tests that inject `WALL_NOW`
        // directly see the same stale row.
        let aged = now_unix_seconds() - 1;
        assert!(aged < WALL_NOW, "the injected-clock tests need this too");
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "UPDATE tx_attempts SET lease_until = ?, claim_owner = NULL WHERE id = ?",
                    )
                    .bind(aged)
                    .bind(&attempt_id)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("age the lease");
        attempt
    }

    async fn scalar_text(store: &StreamGStore, sql: &'static str, bind: String) -> Option<String> {
        store
            .read(move |h| {
                Box::pin(async move {
                    let v: Option<String> =
                        h.fetch_scalar(sqlx::query_scalar(sql).bind(bind)).await?;
                    Ok::<Option<String>, StreamGStoreError>(v)
                })
            })
            .await
            .expect("scalar")
    }

    async fn count_all(store: &StreamGStore, sql: &'static str) -> i64 {
        store
            .read(move |h| {
                Box::pin(async move {
                    let v: i64 = h.fetch_scalar(sqlx::query_scalar(sql)).await?;
                    Ok::<i64, StreamGStoreError>(v)
                })
            })
            .await
            .expect("count")
    }

    const ATTEMPT_STATUS_SQL: &str = "SELECT status FROM tx_attempts WHERE id = ?";
    const NONCE_STATUS_SQL: &str = "SELECT status FROM nonce_allocations WHERE id = ?";
    /// Rows where the attempt reached a terminal `failed` but its nonce was NOT
    /// released — the exact shape of a half-applied resolution, since the
    /// sweeper writes both in one `write_tx`.
    const HALF_APPLIED_SQL: &str = "SELECT COUNT(*) FROM tx_attempts a \
         JOIN nonce_allocations n ON n.id = a.nonce_allocation_id \
         WHERE a.status = 'failed' AND n.status != 'released'";

    // -------------------------------------------------------------------
    // A2 — the release authority survives the mount.
    // -------------------------------------------------------------------

    /// **A2, per-row half, through this module's entry point.** Mounting the
    /// sweeper must not introduce a caller that "recovers" from an RPC failure
    /// by resolving the row itself. An armed `Err` must leave the attempt
    /// `reserved`, its nonce `allocated`, and must be *reported* rather than
    /// swallowed.
    ///
    /// Mutation this detects: in `outbox::resolve_against_chain`, replacing the
    /// `intent_used` `Err(e) => return Resolution::Stuck { .. }` arm with
    /// `Err(_) => {}` (fall through to the release branch). Verified: this test
    /// then fails on `released == 0` with `released` = 1.
    ///
    /// Paired non-zero arm: the identical setup with a healthy chain DOES
    /// release, so the assertions above are not passing because the sweeper is
    /// inert.
    #[tokio::test]
    async fn a_failing_rpc_never_releases_a_nonce_through_the_mounted_loop() {
        // --- arm 1: RPC errors ------------------------------------------
        let dir = tempfile::tempdir().unwrap();
        let (_controller, state) = mock_state(dir.path()).await;
        let attempt = reserve_stale(state.store()).await;
        let chain = FakeChain::healthy();
        chain.set_intent_used(Err("node down".into()));
        let policy = test_policy(Duration::from_secs(900));

        let outcome = run_sweep(
            state.store(),
            (&chain).into(),
            state.metrics(),
            &policy,
            WALL_NOW,
        )
        .await;

        let SweepStepOutcome::Swept(report) = outcome else {
            panic!("a per-row RPC error must be a completed pass, got {outcome:?}");
        };
        assert_eq!(report.claimed, 1);
        assert_eq!(
            report.released, 0,
            "an RPC error must never release a nonce through the mounted path"
        );
        assert_eq!(report.executed, 0);
        assert_eq!(report.stuck_recoverable(), 1);
        assert_eq!(
            scalar_text(
                state.store(),
                ATTEMPT_STATUS_SQL,
                attempt.attempt_id.clone()
            )
            .await,
            Some(TX_ATTEMPT_STATUS_RESERVED.to_string())
        );
        assert_eq!(
            scalar_text(
                state.store(),
                NONCE_STATUS_SQL,
                attempt.allocation_id.clone()
            )
            .await,
            Some(NONCE_STATUS_ALLOCATED.to_string())
        );

        // The counters an operator would look at say the same thing.
        let m = state.metrics().snapshot();
        assert_eq!(m.sweep_passes, 1);
        assert_eq!(m.sweep_stuck, 1);
        assert_eq!(m.sweep_released, 0);
        assert_eq!(
            m.sweep_errors, 0,
            "a per-row stuck resolution is not a failed pass"
        );

        // --- arm 2 (the pair): healthy chain, same rows -> released ------
        let dir2 = tempfile::tempdir().unwrap();
        let (_c2, state2) = mock_state(dir2.path()).await;
        let attempt2 = reserve_stale(state2.store()).await;
        let healthy = FakeChain::healthy();

        let outcome2 = run_sweep(
            state2.store(),
            (&healthy).into(),
            state2.metrics(),
            &policy,
            WALL_NOW,
        )
        .await;
        let SweepStepOutcome::Swept(report2) = outcome2 else {
            panic!("expected a completed pass, got {outcome2:?}");
        };
        assert_eq!(report2.released, 1);
        assert_eq!(report2.stuck_recoverable(), 0);
        assert_eq!(
            scalar_text(
                state2.store(),
                NONCE_STATUS_SQL,
                attempt2.allocation_id.clone()
            )
            .await,
            Some("released".to_string())
        );
        assert_eq!(state2.metrics().snapshot().sweep_released, 1);
    }

    /// A pass that fails outright must be counted as an **error**, not as a
    /// successful pass — otherwise a permanently broken sweeper reads as
    /// healthy on `/v1/stream-g/metrics`. The store failure is forced by
    /// dropping the table the claim query reads.
    ///
    /// Mutation this detects: `run_sweep`'s `Err` arm calling
    /// `metrics.record_sweep(&SweepReport::default())` instead of
    /// `record_sweep_error()` — `sweep_errors` then stays 0 and `sweep_passes`
    /// becomes 1, failing both assertions.
    #[tokio::test]
    async fn a_failed_sweep_pass_is_counted_as_an_error_not_as_a_pass() {
        let dir = tempfile::tempdir().unwrap();
        let (_controller, state) = mock_state(dir.path()).await;
        let policy = test_policy(Duration::from_secs(900));

        // Paired healthy arm FIRST, so the failing arm below is a change of one
        // variable rather than a fresh unknown.
        let healthy = FakeChain::healthy();
        let ok = run_sweep(
            state.store(),
            (&healthy).into(),
            state.metrics(),
            &policy,
            WALL_NOW,
        )
        .await;
        assert!(matches!(ok, SweepStepOutcome::Swept(_)), "{ok:?}");
        assert_eq!(state.metrics().snapshot().sweep_passes, 1);
        assert_eq!(state.metrics().snapshot().sweep_errors, 0);

        state
            .store()
            .write_tx(|tx| {
                Box::pin(async move {
                    sqlx::query("DROP TABLE tx_attempts")
                        .execute(&mut **tx)
                        .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("drop the table the sweep reads");

        let failed = run_sweep(
            state.store(),
            (&healthy).into(),
            state.metrics(),
            &policy,
            WALL_NOW,
        )
        .await;
        assert_eq!(failed, SweepStepOutcome::Failed);
        let m = state.metrics().snapshot();
        assert_eq!(m.sweep_errors, 1, "a failed pass must be counted");
        assert_eq!(
            m.sweep_passes, 1,
            "a failed pass must not also look like a successful one"
        );
    }

    /// Mock mode has no chain client, therefore no release authority: the sweep
    /// must be **skipped**, and a skipped sweep must not be counted as a pass.
    /// Pruning still runs — it reads no chain state.
    ///
    /// Mutation this detects: `run_pass`'s `None` arm calling `run_sweep` with
    /// some substitute client, or returning `Swept(SweepReport::default())` —
    /// `sweep_passes` becomes 1 and the outcome assertion fails.
    #[tokio::test]
    async fn mock_mode_skips_the_sweep_but_still_prunes() {
        let dir = tempfile::tempdir().unwrap();
        let (_controller, state) = mock_state(dir.path()).await;
        assert!(state.trusted_chain().is_none());

        let report = run_pass(&state, &test_policy(Duration::from_secs(900)), WALL_NOW).await;

        assert_eq!(report.sweep, SweepStepOutcome::SkippedNoChain);
        assert_eq!(
            state.metrics().snapshot().sweep_passes,
            0,
            "a skipped sweep must never be counted as a pass"
        );
        // Reconciliation skips on exactly the same condition, and for a stronger
        // reason: with no chain there is no receipt to corroborate a log and no
        // head to measure its confirmation depth against, so a fold would be a
        // depth-0 confirmation on a caller-supplied struct.
        assert_eq!(report.reconcile, ReconcileStepOutcome::SkippedNoChain);
        let m = state.metrics().snapshot();
        assert_eq!(
            m.reconcile_passes, 0,
            "a skipped reconciliation must never be counted as a pass"
        );
        assert_eq!(
            m.reconcile_errors, 0,
            "and must not be counted as a failure either"
        );
        // Paired non-zero arm: the prune half of the same pass really ran.
        assert!(
            matches!(report.prune, PruneStepOutcome::Pruned(_)),
            "{:?}",
            report.prune
        );
    }

    // -------------------------------------------------------------------
    // Cancellation.
    // -------------------------------------------------------------------

    /// The loop must stop on the shared token, not on its own timer: with a
    /// 15-minute cadence a cancel has to be observed in milliseconds.
    ///
    /// Mutation this detects: dropping the `token.cancelled()` branch from the
    /// `select!` (i.e. `tokio::time::sleep(policy.interval).await;` alone) —
    /// the join then times out.
    #[tokio::test]
    async fn the_loop_stops_promptly_when_the_token_is_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let (controller, state) = mock_state(dir.path()).await;
        let policy = test_policy(Duration::from_secs(900));

        let mut handle = spawn(state, policy);

        // Paired arm, on the SAME loop, proving the timeout below is meaningful:
        // while it is not cancelled it does not finish. Without this, a loop
        // that exited immediately for any reason would pass the assertion after
        // it.
        assert!(
            tokio::time::timeout(Duration::from_millis(150), &mut handle)
                .await
                .is_err(),
            "an uncancelled loop with a 900s cadence must still be running"
        );

        controller.cancel();
        let passes = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("a cancelled loop must stop promptly, not after its cadence")
            .expect("loop task must not panic");
        assert_eq!(
            passes, 0,
            "cancelling before the first cadence must not force a pass"
        );
    }

    /// **Cancellation leaves no half-applied row.** The loop is driven at a
    /// millisecond cadence against a *real* `RpcChain` whose endpoint is dead,
    /// so every pass claims the stale row, fails every chain read, and re-defers
    /// it. Cancelling mid-flight must leave the store consistent: no attempt is
    /// `failed` while its nonce is still held, and the fail-closed row is still
    /// exactly where it was.
    ///
    /// This is also the end-to-end half of A2: it is the mounted loop, the
    /// production `TrustedChain`, and a node that cannot answer.
    ///
    /// Mutation this detects: racing the pass against cancellation — i.e.
    /// replacing the loop body's `run_pass(..).await` with
    /// `tokio::select! { _ = token.cancelled() => break, _ = run_pass(..) => {} }`.
    /// Verified separately: with that mutation the loop can drop a `write_tx`
    /// future mid-transaction. (SQLite rolls such a transaction back, so the
    /// `HALF_APPLIED_SQL` count stays 0 — this test does **not** kill that
    /// mutation, and saying so is more useful than pretending it does. What it
    /// does kill is a mounting that leaks a release on an unreachable RPC.)
    ///
    /// Multi-threaded runtime is required: `RpcChain` services the synchronous
    /// `ChainClient` trait with `block_in_place`, which panics on a
    /// current-thread runtime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_mounted_loop_leaves_every_row_reserved_when_the_rpc_is_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let (controller, state) = live_but_unreachable_state(dir.path()).await;
        let attempt = reserve_stale(state.store()).await;

        let probe = state.clone();
        let handle = spawn(state, test_policy(Duration::from_millis(10)));

        // Wait for at least one real pass rather than sleeping a fixed time.
        let waited = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if probe.metrics().snapshot().sweep_passes >= 1 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            waited.is_ok(),
            "the mounted loop never completed a sweep pass"
        );

        controller.cancel();
        let passes = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("the loop must stop on cancel")
            .expect("loop task must not panic");
        assert!(passes >= 1, "expected at least one completed pass");

        // Fail-closed, through the production client: nothing moved.
        assert_eq!(
            scalar_text(
                probe.store(),
                ATTEMPT_STATUS_SQL,
                attempt.attempt_id.clone()
            )
            .await,
            Some(TX_ATTEMPT_STATUS_RESERVED.to_string()),
            "an unreachable node must leave the attempt reserved"
        );
        assert_eq!(
            scalar_text(
                probe.store(),
                NONCE_STATUS_SQL,
                attempt.allocation_id.clone()
            )
            .await,
            Some(NONCE_STATUS_ALLOCATED.to_string()),
            "an unreachable node must never release the nonce"
        );
        assert_eq!(
            count_all(probe.store(), HALF_APPLIED_SQL).await,
            0,
            "a half-applied resolution survived the cancel"
        );

        // Paired non-zero arms: the loop really did work, and really did report
        // the row as stuck-recoverable rather than silently doing nothing.
        let m = probe.metrics().snapshot();
        assert!(m.sweep_passes >= 1, "{m:?}");
        assert!(
            m.sweep_stuck >= 1,
            "an unreachable node must be reported stuck-recoverable: {m:?}"
        );
        assert_eq!(m.sweep_released, 0, "{m:?}");
        assert_eq!(m.sweep_executed, 0, "{m:?}");
    }

    // -------------------------------------------------------------------
    // `profile_auth::prune_expired`, the other unwired primitive.
    // -------------------------------------------------------------------

    /// `prune_expired` is now actually scheduled: the running loop deletes an
    /// expired challenge and an expired session without anyone calling it.
    ///
    /// Mutation this detects: deleting the `run_prune(state.store()).await` call
    /// from `run_pass` — the expired rows survive and the wait below times out.
    ///
    /// Paired non-zero arm: a *live* challenge and a *live* session in the same
    /// tables are still there afterwards, so this proves scheduling rather than
    /// "the loop empties the tables".
    #[tokio::test]
    async fn the_loop_schedules_prune_expired() {
        let dir = tempfile::tempdir().unwrap();
        let (controller, state) = mock_state(dir.path()).await;
        let far_future = now_unix_seconds() + 86_400;

        state
            .store()
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO profiles (id, created_at, status) \
                         VALUES (?, ?, 'active')",
                    )
                    .bind(PROFILE)
                    .bind(0i64)
                    .execute(&mut **tx)
                    .await?;
                    for (id, expires_at) in [("chal-expired", 1i64), ("chal-live", far_future)] {
                        sqlx::query(
                            "INSERT INTO auth_challenges \
                             (id, profile_id, challenge_type, nonce, created_at, expires_at) \
                             VALUES (?, ?, 'login', ?, 0, ?)",
                        )
                        .bind(id)
                        .bind(PROFILE)
                        .bind(format!("0x{}", hex::encode([0x01u8; 32])))
                        .bind(expires_at)
                        .execute(&mut **tx)
                        .await?;
                    }
                    for (id, expires_at) in [("sess-expired", 1i64), ("sess-live", far_future)] {
                        sqlx::query(
                            "INSERT INTO profile_sessions \
                             (id, profile_id, session_token_hash, created_at, expires_at) \
                             VALUES (?, ?, ?, 0, ?)",
                        )
                        .bind(id)
                        .bind(PROFILE)
                        .bind(format!("hash-{id}"))
                        .bind(expires_at)
                        .execute(&mut **tx)
                        .await?;
                    }
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed auth rows");

        assert_eq!(
            count_all(state.store(), "SELECT COUNT(*) FROM auth_challenges").await,
            2
        );
        assert_eq!(
            count_all(state.store(), "SELECT COUNT(*) FROM profile_sessions").await,
            2
        );

        let probe = state.clone();
        let handle = spawn(state, test_policy(Duration::from_millis(10)));

        let waited = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let challenges =
                    count_all(probe.store(), "SELECT COUNT(*) FROM auth_challenges").await;
                let sessions =
                    count_all(probe.store(), "SELECT COUNT(*) FROM profile_sessions").await;
                if challenges == 1 && sessions == 1 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;

        controller.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(10), handle).await;

        assert!(
            waited.is_ok(),
            "the loop never pruned: challenges={}, sessions={}",
            count_all(probe.store(), "SELECT COUNT(*) FROM auth_challenges").await,
            count_all(probe.store(), "SELECT COUNT(*) FROM profile_sessions").await
        );
        // Paired non-zero arms: the unexpired rows are untouched.
        assert_eq!(
            scalar_text(
                probe.store(),
                "SELECT id FROM auth_challenges WHERE id = ?",
                "chal-live".into()
            )
            .await,
            Some("chal-live".to_string())
        );
        assert_eq!(
            scalar_text(
                probe.store(),
                "SELECT id FROM profile_sessions WHERE id = ?",
                "sess-live".into()
            )
            .await,
            Some("sess-live".to_string())
        );
    }

    // -------------------------------------------------------------------
    // Policy / config.
    // -------------------------------------------------------------------

    /// The ratified default cadence is 900s, the knob is real, and both ends of
    /// the range are clamped rather than accepted.
    ///
    /// Mutation this detects: changing `DEFAULT_SWEEP_INTERVAL_SECONDS`, or
    /// dropping the clamp in `config::parse_u64_clamped` (a `0` cadence would
    /// then produce a spin loop).
    #[test]
    fn the_cadence_defaults_to_900_seconds_and_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let base = crate::stream_g::runtime::test_support::enabled_map(dir.path());

        let default_cfg = config::load_from_map(&base).unwrap();
        assert_eq!(default_cfg.stream_g.sweep_interval_seconds, 900);
        assert_eq!(
            default_cfg.stream_g.outbox_lease_ttl_seconds,
            DEFAULT_LEASE_TTL_SECONDS
        );
        assert_eq!(default_cfg.stream_g.sweep_max_rows, DEFAULT_SWEEP_MAX_ROWS);

        // Honoured in range (the non-clamped arm — without this the clamp
        // assertions below would also pass if the knob were ignored entirely).
        let mut tuned = base.clone();
        tuned.insert("STREAM_G_SWEEP_INTERVAL_SECONDS".into(), "120".into());
        tuned.insert("STREAM_G_OUTBOX_LEASE_TTL_SECONDS".into(), "300".into());
        tuned.insert("STREAM_G_SWEEP_MAX_ROWS".into(), "8".into());
        let tuned_cfg = config::load_from_map(&tuned).unwrap();
        assert_eq!(tuned_cfg.stream_g.sweep_interval_seconds, 120);
        assert_eq!(tuned_cfg.stream_g.outbox_lease_ttl_seconds, 300);
        assert_eq!(tuned_cfg.stream_g.sweep_max_rows, 8);

        // Clamped at both ends.
        let mut absurd = base.clone();
        absurd.insert("STREAM_G_SWEEP_INTERVAL_SECONDS".into(), "0".into());
        absurd.insert("STREAM_G_SWEEP_MAX_ROWS".into(), "0".into());
        let low = config::load_from_map(&absurd).unwrap();
        assert_eq!(
            low.stream_g.sweep_interval_seconds, MIN_SWEEP_INTERVAL_SECONDS,
            "a 0-second cadence would be a spin loop"
        );
        assert_eq!(low.stream_g.sweep_max_rows, MIN_SWEEP_MAX_ROWS as i64);

        let mut huge = base;
        huge.insert("STREAM_G_SWEEP_INTERVAL_SECONDS".into(), "99999999".into());
        huge.insert("STREAM_G_SWEEP_MAX_ROWS".into(), "99999999".into());
        let high = config::load_from_map(&huge).unwrap();
        assert_eq!(
            high.stream_g.sweep_interval_seconds,
            MAX_SWEEP_INTERVAL_SECONDS
        );
        assert_eq!(high.stream_g.sweep_max_rows, MAX_SWEEP_MAX_ROWS as i64);
    }

    /// The gateway the sweeper reads `intentUsed(intentId)` from must come from
    /// the **verified deployment manifest**, not from a config string: startup
    /// already checked that manifest's `chainId`/`phase`.
    ///
    /// Mutation this detects: `from_config` filling `gateway` with
    /// `[0u8; 20]`, or with `manifest.enrollment_registry`.
    #[tokio::test]
    async fn the_policy_takes_its_gateway_from_the_verified_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::stream_g::runtime::test_support::enabled_cfg(dir.path());
        let controller = ShutdownController::new();
        let state = StreamGState::start(&cfg, controller.token())
            .await
            .expect("start");

        let policy = MaintenancePolicy::from_config(&cfg.stream_g, state.manifest());
        assert_eq!(policy.gateway, state.manifest().goat_relay_gateway);
        assert_ne!(
            policy.gateway, [0u8; 20],
            "the manifest gateway is not zero"
        );
        assert_ne!(
            policy.gateway,
            state.manifest().enrollment_registry,
            "gateway and registry are different addresses in the fixture manifest"
        );
        assert_eq!(policy.claim_owner, SWEEPER_CLAIM_OWNER);
        assert_eq!(policy.interval, Duration::from_secs(900));
    }

    /// The sweeper's `claim_owner` must differ from any submit path's, or its
    /// compare-and-swap would match rather than transfer.
    #[test]
    fn the_sweeper_claims_rows_under_its_own_owner() {
        assert!(SWEEPER_CLAIM_OWNER.contains(':'));
        assert_ne!(SWEEPER_CLAIM_OWNER, "submit-path-owner");
        assert!(
            !SWEEPER_CLAIM_OWNER.starts_with("0x"),
            "must not collide with an address-shaped owner"
        );
    }

    // ===================================================================
    // Reconciliation (Task 11 Wave D).
    // ===================================================================

    const LOG_BLOCK: u64 = 1_000;
    const BLOCK_HASH: [u8; 32] = [0x99; 32];
    const ROOT: [u8; 20] = [0x44; 20];
    const SECONDARY: [u8; 20] = [0x55; 20];
    const FEE_TOKEN: [u8; 20] = [0x66; 20];

    const ATTEMPT_CONFIRMED_AT_SQL: &str = "SELECT confirmed_at FROM tx_attempts WHERE id = ?";
    const INTENT_STATUS_SQL: &str = "SELECT status FROM intents WHERE id = ?";

    /// Reserve through the production outbox path and then move the row into the
    /// `submitted` state a node acknowledgement produces — the shape reconcile's
    /// unconditional `tx_hash` guard expects to compare against.
    ///
    /// The intent's `expires_at` is far in the **chain** future, so the sweeper
    /// legitimately holds this row rather than releasing it, and neither test
    /// below is passing because the sweeper quietly cleared the table.
    async fn reserve_submitted(store: &StreamGStore) -> ReservedAttempt {
        seed_intent(store, (CHAIN_NOW as i64) + 3_600).await;
        let req = ReservationRequest {
            profile_id: PROFILE,
            intent_id: INTENT_ID,
            chain_id: CHAIN_ID,
            controller: CONTROLLER,
            action: ActionType::SponsoredEnrollment,
            action_nonce: ACTION_NONCE,
            claim_owner: "submit-path-owner",
            lease_ttl_seconds: DEFAULT_LEASE_TTL_SECONDS,
        };
        let signed = SignedRawTx::new(
            vec![0x02, 0xf8, 0x6b, 0xAA, 0xBB, 0xCC],
            GasUnits::new(500_000),
            MaxFeePerGas::new(1_000_000_000),
        );
        let attempt = reserve_and_persist_raw_tx(store, &data_key_hex(), &req, &signed, WALL_NOW)
            .await
            .expect("reserve");
        let attempt_id = attempt.attempt_id.clone();
        let hex = format!("0x{}", hex::encode(signed.hash()));
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    let r = sqlx::query(
                        "UPDATE tx_attempts SET status = 'submitted', tx_hash = ?, \
                         submitted_at = ?, claim_owner = NULL, lease_until = NULL WHERE id = ?",
                    )
                    .bind(&hex)
                    .bind(WALL_NOW)
                    .bind(&attempt_id)
                    .execute(&mut **tx)
                    .await?;
                    assert_eq!(r.rows_affected(), 1, "mark submitted must hit a row");
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("mark submitted");
        attempt
    }

    /// The signed payload's hash — what `reserve_submitted` wrote into
    /// `tx_hash`, and therefore what a log must carry to be attributed to it.
    fn submitted_tx_hash() -> [u8; 32] {
        SignedRawTx::new(
            vec![0x02, 0xf8, 0x6b, 0xAA, 0xBB, 0xCC],
            GasUnits::new(500_000),
            MaxFeePerGas::new(1_000_000_000),
        )
        .hash()
    }

    fn executed_log(tx_hash: [u8; 32]) -> ExecutedLog {
        ExecutedLog {
            intent_id: INTENT_ID,
            root: ROOT,
            secondary: SECONDARY,
            controller: CONTROLLER,
            fee_token: FEE_TOKEN,
            fee_amount: 1_234,
            block_number: LOG_BLOCK,
            block_hash: BLOCK_HASH,
            log_index: 3,
            tx_hash,
            removed: false,
        }
    }

    /// A chain that corroborates `tx` as a successful transaction in
    /// `LOG_BLOCK`/`BLOCK_HASH` and returns its log for any range.
    fn reconciling_chain(tx: [u8; 32], head: u64) -> FakeChain {
        let chain = FakeChain::healthy();
        chain.set_pinned_block(Ok(head));
        chain.set_receipt(Ok(Some(TxReceiptView {
            tx_hash: tx,
            block_number: LOG_BLOCK,
            block_hash: BLOCK_HASH,
            success: true,
            gas_used: 21_000,
        })));
        chain.set_logs(Ok(vec![executed_log(tx)]));
        chain
    }

    async fn scalar_i64(store: &StreamGStore, sql: &'static str, bind: String) -> Option<i64> {
        store
            .read(move |h| {
                Box::pin(async move {
                    let v: Option<i64> = h.fetch_scalar(sqlx::query_scalar(sql).bind(bind)).await?;
                    Ok::<Option<i64>, StreamGStoreError>(v)
                })
            })
            .await
            .expect("scalar i64")
    }

    fn reconcile_policy(confirmations: u64) -> MaintenancePolicy {
        MaintenancePolicy {
            confirmations,
            ..test_policy(Duration::from_secs(900))
        }
    }

    /// 🔴 **The required transition, asserted on the literal status strings.**
    ///
    /// attempt `submitted → confirmed`; intent `submitted → executed`; action
    /// nonce `allocated → CONSUMED`. Not "not released" — the literal value,
    /// because `_markIntentAndNonce` really did increment that nonce on chain
    /// and handing the slot back out would sign a second transaction against a
    /// nonce the gateway has already used.
    ///
    /// Mutation this detects: binding `NONCE_STATUS_RELEASED` in
    /// `submit::reconcile_executed_for_profile_id`'s `nonce_allocations` UPDATE.
    /// Every other assertion here still passes under that mutation.
    ///
    /// It also pins the cursor: the window really was recorded, so the next pass
    /// starts after it rather than at the deploy block.
    #[tokio::test]
    async fn a_reconciled_log_confirms_the_attempt_and_marks_the_nonce_consumed() {
        let dir = tempfile::tempdir().unwrap();
        let (_controller, state) = mock_state(dir.path()).await;
        let attempt = reserve_submitted(state.store()).await;
        let tx = submitted_tx_hash();
        let head = LOG_BLOCK + 10;
        let chain = reconciling_chain(tx, head);
        let policy = reconcile_policy(1);

        let outcome = run_reconcile(
            state.store(),
            state.data_key_hex(),
            (&chain).into(),
            state.metrics(),
            &policy,
            WALL_NOW,
        )
        .await;

        match outcome {
            ReconcileStepOutcome::Scanned {
                from,
                to,
                logs,
                quarantined,
                stalled,
                cursor_advanced,
            } => {
                assert_eq!(from, 0, "no cursor yet, so the window starts at the pin");
                assert_eq!(to, head, "1 confirmation means the head itself is foldable");
                assert_eq!(logs, 1);
                assert_eq!(quarantined, 0, "a healthy window quarantines nothing");
                assert_eq!(stalled, 0, "and stalls nothing");
                assert!(cursor_advanced);
            }
            other => panic!("expected Scanned, got {other:?}"),
        }

        assert_eq!(
            scalar_text(
                state.store(),
                ATTEMPT_STATUS_SQL,
                attempt.attempt_id.clone()
            )
            .await
            .as_deref(),
            Some(TX_ATTEMPT_STATUS_CONFIRMED)
        );
        assert_eq!(
            scalar_text(
                state.store(),
                NONCE_STATUS_SQL,
                attempt.allocation_id.clone()
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_CONSUMED),
            "the gateway incremented this nonce on chain; releasing it would hand the same nonce \
             out twice"
        );
        assert_eq!(
            scalar_text(
                state.store(),
                INTENT_STATUS_SQL,
                crate::stream_g::submit::intent_row_id(PROFILE, INTENT_ID)
            )
            .await
            .as_deref(),
            Some(crate::stream_g::submit::INTENT_STATUS_EXECUTED)
        );

        let m = state.metrics().snapshot();
        assert_eq!(m.reconcile_passes, 1);
        assert_eq!(m.reconcile_errors, 0);
        assert_eq!(m.reconcile_logs_observed, 1);
        assert_eq!(m.reconcile_confirmed, 1);

        assert_eq!(
            reconcile::load_scan_cursor(state.store(), SCAN_CURSOR_ENROLLMENT_EXECUTED)
                .await
                .expect("cursor read"),
            Some(head),
            "the cursor must persist, or the next pass rescans from the deploy block"
        );
    }

    /// 🔴 **Double fold is a no-op, not a second write.**
    ///
    /// A polling observer whose cursor only advances on success re-observes
    /// events by construction, so this is the normal case rather than an edge
    /// case. The second fold happens under a *different* wall clock and a
    /// *later* window, which is what makes the `confirmed_at` assertion
    /// meaningful.
    ///
    /// Mutation this detects: dropping `AND status != ?` from the `tx_attempts`
    /// UPDATE in `submit::reconcile_executed_for_profile_id`. `confirmed_at`
    /// then becomes `WALL_NOW + 1_000` and this test fails — the silent
    /// corruption is that the column stops meaning "when this confirmed" and
    /// starts meaning "when we last rescanned", with nothing in
    /// `reconciliation_events` to show it happened.
    #[tokio::test]
    async fn folding_the_same_log_twice_writes_once() {
        let dir = tempfile::tempdir().unwrap();
        let (_controller, state) = mock_state(dir.path()).await;
        let attempt = reserve_submitted(state.store()).await;
        let tx = submitted_tx_hash();
        let chain = reconciling_chain(tx, LOG_BLOCK + 10);
        let policy = reconcile_policy(1);

        let first = run_reconcile(
            state.store(),
            state.data_key_hex(),
            (&chain).into(),
            state.metrics(),
            &policy,
            WALL_NOW,
        )
        .await;
        assert!(
            matches!(first, ReconcileStepOutcome::Scanned { logs: 1, .. }),
            "{first:?}"
        );
        let confirmed_at_after_first = scalar_i64(
            state.store(),
            ATTEMPT_CONFIRMED_AT_SQL,
            attempt.attempt_id.clone(),
        )
        .await;
        assert_eq!(
            confirmed_at_after_first,
            Some(WALL_NOW),
            "paired non-zero arm: the first fold really did stamp the INJECTED confirmation time, \
             so the comparison below is against a known value rather than whatever the process \
             clock happened to say"
        );

        // The head advances, so the second window is non-empty and the
        // range-blind fake serves the same log again — exactly what a real node
        // does when a scan window overlaps an already-folded block.
        chain.set_pinned_block(Ok(LOG_BLOCK + 20));
        let second = run_reconcile(
            state.store(),
            state.data_key_hex(),
            (&chain).into(),
            state.metrics(),
            &policy,
            WALL_NOW + 1_000,
        )
        .await;
        assert!(
            matches!(second, ReconcileStepOutcome::Scanned { logs: 1, .. }),
            "the same log really was observed a second time: {second:?}"
        );

        assert_eq!(
            scalar_i64(
                state.store(),
                ATTEMPT_CONFIRMED_AT_SQL,
                attempt.attempt_id.clone()
            )
            .await,
            confirmed_at_after_first,
            "a replayed fold must not rewrite confirmed_at"
        );
        assert_eq!(
            scalar_text(
                state.store(),
                ATTEMPT_STATUS_SQL,
                attempt.attempt_id.clone()
            )
            .await
            .as_deref(),
            Some(TX_ATTEMPT_STATUS_CONFIRMED)
        );
        assert_eq!(
            scalar_text(
                state.store(),
                NONCE_STATUS_SQL,
                attempt.allocation_id.clone()
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_CONSUMED),
            "still consumed exactly once, never bounced through another status"
        );
        assert_eq!(
            count_all(
                state.store(),
                "SELECT COUNT(*) FROM reconciliation_events WHERE event_type = \
                 'SponsoredEnrollmentExecuted'"
            )
            .await,
            1,
            "the deterministic event id must collapse the replay to one row"
        );

        let m = state.metrics().snapshot();
        assert_eq!(m.reconcile_passes, 2);
        assert_eq!(m.reconcile_confirmed, 2, "observed twice, written once");
        assert_eq!(m.reconcile_errors, 0);
    }

    /// 🔴 **A log below the confirmation depth is NOT folded, and the cursor
    /// does not step over it.**
    ///
    /// Two independent halves, both required:
    ///
    /// * the scan window ends at the finality frontier, so a shallow block is
    ///   not even requested (`log_ranges` proves the `to` that was asked for);
    /// * `reconcile_executed_log`'s own depth check refuses the log the
    ///   range-blind fake returns anyway, writing nothing.
    ///
    /// The second half is what protects a real deployment against a lagging
    /// replica: the window is computed from one head reading and the fold
    /// re-reads it, so a node that reports a lower head must not cause a skip.
    ///
    /// Mutation this detects: replacing `head.checked_sub(confirmations - 1)`
    /// with `head` in `scan_and_fold`, i.e. scanning to the tip. The row is then
    /// confirmed at depth 1 under a 50-confirmation policy and every assertion
    /// below fails.
    ///
    /// Paired non-zero arm: the identical setup with `confirmations = 1` DOES
    /// confirm, so these assertions are not passing because reconciliation is
    /// inert.
    #[tokio::test]
    async fn a_log_below_the_confirmation_depth_is_not_folded() {
        let dir = tempfile::tempdir().unwrap();
        let (_controller, state) = mock_state(dir.path()).await;
        let attempt = reserve_submitted(state.store()).await;
        let tx = submitted_tx_hash();
        // Depth of the log at this head is 11; the policy demands 50.
        let head = LOG_BLOCK + 10;
        let chain = reconciling_chain(tx, head);
        let policy = reconcile_policy(50);

        let outcome = run_reconcile(
            state.store(),
            state.data_key_hex(),
            (&chain).into(),
            state.metrics(),
            &policy,
            WALL_NOW,
        )
        .await;

        match outcome {
            ReconcileStepOutcome::Scanned {
                to,
                cursor_advanced,
                ..
            } => {
                assert_eq!(
                    to,
                    head - 49,
                    "the window must stop at the finality frontier, not at the head"
                );
                assert!(
                    !cursor_advanced,
                    "a NotFinalYet log inside the window must hold the cursor rather than let it \
                     step over the block"
                );
            }
            other => panic!("expected Scanned, got {other:?}"),
        }
        assert_eq!(
            chain.log_ranges(),
            vec![(0, head - 49)],
            "the node was never asked for the shallow blocks"
        );

        assert_eq!(
            scalar_text(
                state.store(),
                ATTEMPT_STATUS_SQL,
                attempt.attempt_id.clone()
            )
            .await
            .as_deref(),
            Some(crate::stream_g::submit::TX_ATTEMPT_STATUS_SUBMITTED),
            "a shallow log must not confirm anything"
        );
        assert_eq!(
            scalar_text(
                state.store(),
                NONCE_STATUS_SQL,
                attempt.allocation_id.clone()
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "and must not consume a nonce"
        );
        assert_eq!(
            count_all(state.store(), "SELECT COUNT(*) FROM reconciliation_events").await,
            0,
            "nothing durable may be recorded for a log we refused to act on"
        );
        assert_eq!(
            reconcile::load_scan_cursor(state.store(), SCAN_CURSOR_ENROLLMENT_EXECUTED)
                .await
                .expect("cursor read"),
            None,
            "the cursor must not advance past a block whose log was not folded"
        );

        let m = state.metrics().snapshot();
        assert_eq!(m.reconcile_not_final_yet, 1);
        assert_eq!(m.reconcile_confirmed, 0);

        // --- paired non-zero arm: same rows, 1 confirmation -> confirmed ---
        let dir2 = tempfile::tempdir().unwrap();
        let (_c2, state2) = mock_state(dir2.path()).await;
        let attempt2 = reserve_submitted(state2.store()).await;
        let chain2 = reconciling_chain(tx, head);
        run_reconcile(
            state2.store(),
            state2.data_key_hex(),
            (&chain2).into(),
            state2.metrics(),
            &reconcile_policy(1),
            WALL_NOW,
        )
        .await;
        assert_eq!(
            scalar_text(state2.store(), ATTEMPT_STATUS_SQL, attempt2.attempt_id)
                .await
                .as_deref(),
            Some(TX_ATTEMPT_STATUS_CONFIRMED),
            "the fixture really is confirmable when the depth allows it"
        );
    }

    /// 🔴 **A failing reconciliation pass must not stop the sweeper or the
    /// prune, this pass or the next.**
    ///
    /// The chain is healthy for everything the sweeper reads and errors only on
    /// `sponsored_enrollment_logs`.
    ///
    /// Mutation this detects: propagating the error out of `run_reconcile`
    /// instead of converting it (e.g. making `run_pass` `?` on it). The second
    /// pass's sweep then never happens.
    #[tokio::test]
    async fn a_failing_reconciliation_pass_leaves_the_sweeper_and_prune_running() {
        let dir = tempfile::tempdir().unwrap();
        let (_controller, state) = mock_state(dir.path()).await;
        let attempt = reserve_stale(state.store()).await;
        let chain = FakeChain::healthy();
        chain.set_logs(Err("eth_getLogs: node exploded".into()));
        let policy = reconcile_policy(1);

        let first = run_reconcile(
            state.store(),
            state.data_key_hex(),
            (&chain).into(),
            state.metrics(),
            &policy,
            WALL_NOW,
        )
        .await;
        assert_eq!(first, ReconcileStepOutcome::Failed);
        assert_eq!(
            state.metrics().snapshot().reconcile_errors,
            1,
            "a wedged observer must be visible on the metrics route, not look like `nothing to \
             reconcile`"
        );
        assert_eq!(
            state.metrics().snapshot().reconcile_passes,
            0,
            "a failed pass must not be counted as a pass"
        );

        // The sweeper, in the same process, over the same store, still works —
        // and still works a second time, which is the "the loop is not wedged"
        // half.
        for pass in 1..=2 {
            let outcome = run_sweep(
                state.store(),
                (&chain).into(),
                state.metrics(),
                &policy,
                WALL_NOW,
            )
            .await;
            assert!(
                matches!(outcome, SweepStepOutcome::Swept(_)),
                "sweep pass {pass} must still run after a failed reconciliation: {outcome:?}"
            );
            let prune = run_prune(state.store()).await;
            assert!(matches!(prune, PruneStepOutcome::Pruned(_)), "{prune:?}");
        }
        // Paired non-zero arm: the sweep did real work rather than no-oping.
        assert_eq!(
            state.metrics().snapshot().sweep_released,
            1,
            "the stale row really was resolved by the sweeper"
        );
        assert_eq!(
            scalar_text(state.store(), NONCE_STATUS_SQL, attempt.allocation_id)
                .await
                .as_deref(),
            Some("released")
        );
        assert_eq!(
            reconcile::load_scan_cursor(state.store(), SCAN_CURSOR_ENROLLMENT_EXECUTED)
                .await
                .expect("cursor read"),
            None,
            "a failed pass must leave the cursor alone so the window is retried"
        );
    }

    /// The window advances past what has already been folded rather than
    /// rescanning from the deploy block, and it is clamped to
    /// [`DEFAULT_MAX_SCAN_SPAN_BLOCKS`].
    ///
    /// Mutation this detects: dropping the `min(from + max_scan_span)` clamp.
    /// The second range then reaches the head, which on a real node is an
    /// unbounded number of sequential `eth_getLogs` round trips inside one
    /// blocking pass.
    #[tokio::test]
    async fn the_cursor_bounds_the_next_window_and_the_span_is_clamped() {
        let dir = tempfile::tempdir().unwrap();
        let (_controller, state) = mock_state(dir.path()).await;
        let _attempt = reserve_submitted(state.store()).await;
        let chain = reconciling_chain(submitted_tx_hash(), LOG_BLOCK + 10);
        let policy = reconcile_policy(1);

        run_reconcile(
            state.store(),
            state.data_key_hex(),
            (&chain).into(),
            state.metrics(),
            &policy,
            WALL_NOW,
        )
        .await;

        // Head jumps far beyond one span.
        let far_head = LOG_BLOCK + 10 + 5 * DEFAULT_MAX_SCAN_SPAN_BLOCKS;
        chain.set_pinned_block(Ok(far_head));
        chain.set_logs(Ok(Vec::new()));
        let outcome = run_reconcile(
            state.store(),
            state.data_key_hex(),
            (&chain).into(),
            state.metrics(),
            &policy,
            WALL_NOW + 1,
        )
        .await;

        let expected_from = LOG_BLOCK + 11;
        match outcome {
            ReconcileStepOutcome::Scanned { from, to, .. } => {
                assert_eq!(from, expected_from, "the cursor, plus one");
                assert_eq!(
                    to,
                    expected_from + DEFAULT_MAX_SCAN_SPAN_BLOCKS,
                    "one pass must never ask for an unbounded span"
                );
                assert!(to < far_head, "and must therefore not reach the head");
            }
            other => panic!("expected Scanned, got {other:?}"),
        }
        assert_eq!(
            chain.log_ranges(),
            vec![
                (0, LOG_BLOCK + 10),
                (expected_from, expected_from + DEFAULT_MAX_SCAN_SPAN_BLOCKS)
            ]
        );
    }

    /// The head has not moved far enough for anything to be final: a completed
    /// pass over an empty window, with no `eth_getLogs` issued at all.
    #[tokio::test]
    async fn a_head_below_the_confirmation_depth_scans_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (_controller, state) = mock_state(dir.path()).await;
        let chain = FakeChain::healthy();
        chain.set_pinned_block(Ok(3));
        chain.set_logs(Ok(Vec::new()));

        let outcome = run_reconcile(
            state.store(),
            state.data_key_hex(),
            (&chain).into(),
            state.metrics(),
            &reconcile_policy(100),
            WALL_NOW,
        )
        .await;

        assert!(
            matches!(outcome, ReconcileStepOutcome::NothingToScan { .. }),
            "{outcome:?}"
        );
        assert!(
            chain.log_ranges().is_empty(),
            "a window with no final block must not cost an RPC"
        );
        let m = state.metrics().snapshot();
        assert_eq!(m.reconcile_passes, 1, "it ran; it just found nothing");
        assert_eq!(m.reconcile_errors, 0);
    }

    // ===================================================================
    // Per-log isolation (Task 11 Wave D — the unfoldable-log wedge).
    // ===================================================================

    const QUARANTINE_COUNT_SQL: &str = "SELECT COUNT(*) FROM reconciliation_events \
         WHERE event_type = 'SponsoredEnrollmentExecuted.quarantined'";

    const POISON_TX: [u8; 32] = [0xEE; 32];
    const STALL_TX: [u8; 32] = [0xDD; 32];

    /// A log the chain **contradicts**: `arm_poison` gives its transaction a
    /// receipt in exactly the block and block hash this log names, reporting
    /// `status == 0`. One block, two readings, and they cannot both be true —
    /// so it returns `Err` on this pass and on every future pass, forever.
    ///
    /// ⚠️ **Corrected 2026-07-27, and the correction is the whole point of this
    /// wave.** This helper used to build a log claiming `LOG_BLOCK + 1` against
    /// a receipt in `LOG_BLOCK` — a block-number *mismatch*, which is NOT
    /// permanent: a reorg deeper than `confirmations`, or a log and a receipt
    /// answered by two replicas mid-reorg, produces it and it clears. The
    /// quarantine tests were therefore pinning silent data loss as correct
    /// behaviour. It is now the one shape that genuinely cannot succeed on a
    /// retry; `a_log_the_chain_has_not_indexed_yet_holds_the_cursor_instead_of\
    /// _being_quarantined` covers the shape that was moved out.
    fn poisoned_log() -> ExecutedLog {
        ExecutedLog {
            tx_hash: POISON_TX,
            log_index: 9,
            ..executed_log(POISON_TX)
        }
    }

    /// Arm [`poisoned_log`]'s contradiction on `chain`, leaving every other
    /// transaction's receipt alone.
    fn arm_poison(chain: &FakeChain) {
        chain.set_receipt_for(
            POISON_TX,
            Ok(Some(TxReceiptView {
                tx_hash: POISON_TX,
                block_number: LOG_BLOCK,
                block_hash: BLOCK_HASH,
                success: false,
                gas_used: 21_000,
            })),
        );
    }

    /// A log whose receipt this node has simply not indexed yet — the auditor's
    /// scenario, and the one that must NEVER be quarantined.
    fn stalling_log() -> ExecutedLog {
        ExecutedLog {
            tx_hash: STALL_TX,
            log_index: 11,
            ..executed_log(STALL_TX)
        }
    }

    /// 🔴 **One unfoldable log must not wedge the deployment.**
    ///
    /// Before this wave `scan_and_fold` did
    /// `let outcome = reconcile_executed_log(..).await?;` inside the loop. The
    /// `?` aborted the window, which skipped `save_scan_cursor`, which meant the
    /// cursor never passed that block — for **every** profile and **every**
    /// later block — and because the error is a pure function of durable state
    /// the next pass reproduced it exactly. There was no per-log skip, no
    /// quarantine, no retry bound and no test.
    ///
    /// Four properties, all required, in one test because they are one
    /// behaviour:
    ///
    /// 1. the poisoned log does not stop the *later* log in the same window
    ///    being folded (it is deliberately first in the vec);
    /// 2. the cursor advances past it — otherwise the wedge persists;
    /// 3. the skip is not silent: a durable `reconciliation_events` row records
    ///    which log, at which chain coordinate, and why;
    /// 4. it is visible on `GET /v1/stream-g/metrics` as `reconcile_log_errors`,
    ///    and is NOT counted as `reconcile_errors` (a failed pass), because the
    ///    two demand opposite operator responses.
    ///
    /// Mutation this detects: restoring the `?` — the pass then returns
    /// `Failed`, the good attempt stays `submitted`, and the cursor stays
    /// `None`. Also detects dropping the `quarantine_unfoldable_log` call
    /// (assertion 3 fails while everything else still passes, which is exactly
    /// the "silently skipped log" this design refuses).
    #[tokio::test]
    async fn a_poisoned_log_neither_stops_the_window_nor_holds_the_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let (_controller, state) = mock_state(dir.path()).await;
        let attempt = reserve_submitted(state.store()).await;
        let tx = submitted_tx_hash();
        let head = LOG_BLOCK + 10;
        let chain = reconciling_chain(tx, head);
        arm_poison(&chain);
        // The poisoned log FIRST: a per-log failure must not abort what follows
        // it, and putting it second would let a `break` pass this test.
        chain.set_logs(Ok(vec![poisoned_log(), executed_log(tx)]));
        let policy = reconcile_policy(1);

        let outcome = run_reconcile(
            state.store(),
            state.data_key_hex(),
            (&chain).into(),
            state.metrics(),
            &policy,
            WALL_NOW,
        )
        .await;

        match outcome {
            ReconcileStepOutcome::Scanned {
                logs,
                quarantined,
                stalled,
                cursor_advanced,
                ..
            } => {
                assert_eq!(logs, 2, "both logs were observed");
                assert_eq!(quarantined, 1, "exactly one of them was unfoldable");
                assert_eq!(
                    stalled, 0,
                    "a contradicted log is not a stalled one — nothing here is coming back"
                );
                assert!(
                    cursor_advanced,
                    "the cursor MUST pass a permanently unfoldable log, or reconciliation never \
                     progresses again for any profile"
                );
            }
            other => panic!("expected Scanned, got {other:?}"),
        }

        // (1) the log after the poisoned one really was folded.
        assert_eq!(
            scalar_text(
                state.store(),
                ATTEMPT_STATUS_SQL,
                attempt.attempt_id.clone()
            )
            .await
            .as_deref(),
            Some(TX_ATTEMPT_STATUS_CONFIRMED),
            "a poisoned log must not stop later logs in the same window"
        );
        assert_eq!(
            scalar_text(
                state.store(),
                NONCE_STATUS_SQL,
                attempt.allocation_id.clone()
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_CONSUMED)
        );

        // (2) the cursor advanced past the poisoned block.
        assert_eq!(
            reconcile::load_scan_cursor(state.store(), SCAN_CURSOR_ENROLLMENT_EXECUTED)
                .await
                .expect("cursor read"),
            Some(head),
            "the whole point: the window completed and was recorded"
        );

        // (3) the skip is durable and self-describing, and names no attempt.
        assert_eq!(count_all(state.store(), QUARANTINE_COUNT_SQL).await, 1);
        assert_eq!(
            count_all(
                state.store(),
                "SELECT COUNT(*) FROM reconciliation_events \
                 WHERE event_type = 'SponsoredEnrollmentExecuted.quarantined' \
                   AND status = 'RECONCILE_UNVERIFIED_LOG' \
                   AND tx_attempt_id IS NULL \
                   AND details_enc IS NOT NULL"
            )
            .await,
            1,
            "the quarantine row must carry the stable error code and a sealed body, and must not \
             guess an attempt id"
        );

        // (4) visible, and visible as the RIGHT thing.
        let m = state.metrics().snapshot();
        assert_eq!(m.reconcile_log_errors, 1);
        assert_eq!(
            m.reconcile_errors, 0,
            "a quarantined log is not a failed pass — the pass completed"
        );
        assert_eq!(
            m.reconcile_stalled_logs, 0,
            "and it is not a stall either: an operator reading only the metrics must be able to \
             tell 'dropped and never coming back' from 'held and retrying'"
        );
        assert_eq!(m.reconcile_passes, 1);
        assert_eq!(m.reconcile_logs_observed, 2);
        assert_eq!(m.reconcile_confirmed, 1);

        // The quarantine row is idempotent under re-observation: the
        // range-blind fake serves both logs again, the count stays 1, and the
        // counter (which is a lifetime total of observations, not of rows)
        // moves. A growing table under a polling observer would be its own
        // defect.
        chain.set_pinned_block(Ok(head + 10));
        let second = run_reconcile(
            state.store(),
            state.data_key_hex(),
            (&chain).into(),
            state.metrics(),
            &policy,
            WALL_NOW + 1,
        )
        .await;
        assert!(
            matches!(second, ReconcileStepOutcome::Scanned { quarantined: 1, .. }),
            "{second:?}"
        );
        assert_eq!(
            count_all(state.store(), QUARANTINE_COUNT_SQL).await,
            1,
            "the deterministic id must collapse a re-observation to one row"
        );
        assert_eq!(state.metrics().snapshot().reconcile_log_errors, 2);
    }

    /// 🔴 **THE AUDITOR'S SCENARIO, AS A PERMANENT REGRESSION TEST.**
    ///
    /// On 2026-07-27 an auditor set this fixture's receipt to `Ok(None)`, ran a
    /// pass, and got `quarantined: 1, cursor_advanced: true` with the attempt
    /// left at `submitted`. They then armed the receipt — **identical input
    /// otherwise** — re-ran, and got `quarantined: 0` and `confirmed`. The log
    /// the first pass threw away was recoverable, and nothing reads behind the
    /// cursor to get it back: a lagging RPC replica silently destroyed a real
    /// confirmation.
    ///
    /// So this test is the two passes, in that order, in one function. Pass 1
    /// must NOT quarantine and must NOT advance the cursor; pass 2, over the
    /// same window, must confirm.
    ///
    /// Mutation this detects: classifying `ReconcileError::UncorroboratedLog`
    /// as `ReconcileErrorScope::LogPermanent` — i.e. the code as it shipped.
    /// Pass 1 then reports `quarantined: 1, cursor_advanced: true`, writes a
    /// quarantine row, and pass 2 finds nothing left to confirm because its
    /// window starts past the log.
    #[tokio::test]
    async fn a_receipt_that_arrives_on_the_second_pass_confirms_instead_of_being_quarantined() {
        let dir = tempfile::tempdir().unwrap();
        let (_controller, state) = mock_state(dir.path()).await;
        let attempt = reserve_submitted(state.store()).await;
        let tx = submitted_tx_hash();
        let head = LOG_BLOCK + 10;
        let chain = reconciling_chain(tx, head);
        let policy = reconcile_policy(1);

        // --- pass 1: the replica that served the log has not indexed the
        //     receipt. Everything else about the input is what pass 2 sees.
        chain.set_receipt(Ok(None));
        let first = run_reconcile(
            state.store(),
            state.data_key_hex(),
            (&chain).into(),
            state.metrics(),
            &policy,
            WALL_NOW,
        )
        .await;

        match first {
            ReconcileStepOutcome::Scanned {
                logs,
                quarantined,
                stalled,
                cursor_advanced,
                ..
            } => {
                assert_eq!(logs, 1);
                assert_eq!(
                    quarantined, 0,
                    "a receipt the node has not indexed YET must never be quarantined — this is \
                     the exact assertion the shipped classifier failed"
                );
                assert_eq!(stalled, 1, "it must be counted as a stall instead");
                assert!(
                    !cursor_advanced,
                    "and the cursor must be HELD, or the log is gone whether or not a quarantine \
                     row was written"
                );
            }
            other => panic!("expected Scanned, got {other:?}"),
        }
        assert_eq!(
            count_all(state.store(), QUARANTINE_COUNT_SQL).await,
            0,
            "nothing durable may record this log as abandoned"
        );
        assert_eq!(
            reconcile::load_scan_cursor(state.store(), SCAN_CURSOR_ENROLLMENT_EXECUTED)
                .await
                .expect("cursor read"),
            None,
            "the cursor must not have moved past the stalled block"
        );
        assert_eq!(
            scalar_text(
                state.store(),
                ATTEMPT_STATUS_SQL,
                attempt.attempt_id.clone()
            )
            .await
            .as_deref(),
            Some(crate::stream_g::submit::TX_ATTEMPT_STATUS_SUBMITTED),
            "nothing was written for a log we could not corroborate"
        );
        let m = state.metrics().snapshot();
        assert_eq!(m.reconcile_stalled_logs, 1);
        assert_eq!(
            m.reconcile_log_errors, 0,
            "an operator reading the metrics must not be told a log was dropped"
        );
        assert_eq!(
            m.reconcile_errors, 0,
            "nor that the pass failed — the pass completed, one log is waiting"
        );

        // --- pass 2: the receipt is there now. NOTHING ELSE CHANGED.
        chain.set_receipt(Ok(Some(TxReceiptView {
            tx_hash: tx,
            block_number: LOG_BLOCK,
            block_hash: BLOCK_HASH,
            success: true,
            gas_used: 21_000,
        })));
        let second = run_reconcile(
            state.store(),
            state.data_key_hex(),
            (&chain).into(),
            state.metrics(),
            &policy,
            WALL_NOW + 1,
        )
        .await;

        match second {
            ReconcileStepOutcome::Scanned {
                quarantined,
                stalled,
                cursor_advanced,
                ..
            } => {
                assert_eq!(quarantined, 0);
                assert_eq!(stalled, 0, "the stall cleared, exactly as designed");
                assert!(cursor_advanced);
            }
            other => panic!("expected Scanned, got {other:?}"),
        }
        assert_eq!(
            scalar_text(
                state.store(),
                ATTEMPT_STATUS_SQL,
                attempt.attempt_id.clone()
            )
            .await
            .as_deref(),
            Some(TX_ATTEMPT_STATUS_CONFIRMED),
            "🔴 the confirmation the shipped code threw away"
        );
        assert_eq!(
            scalar_text(
                state.store(),
                NONCE_STATUS_SQL,
                attempt.allocation_id.clone()
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_CONSUMED)
        );
        assert_eq!(
            reconcile::load_scan_cursor(state.store(), SCAN_CURSOR_ENROLLMENT_EXECUTED)
                .await
                .expect("cursor read"),
            Some(head),
            "and only now may the cursor move"
        );
        assert_eq!(
            count_all(state.store(), QUARANTINE_COUNT_SQL).await,
            0,
            "no quarantine row was ever justified in this scenario"
        );
        assert_eq!(state.metrics().snapshot().reconcile_confirmed, 1);
    }

    /// 🔴 **A block-identity mismatch must not be quarantined on first sight.**
    ///
    /// A log and a receipt can straddle a fork — under a reorg deeper than the
    /// configured `confirmations` (operator-set via `STREAM_G_CONFIRMATIONS`,
    /// and `FinalityPolicy::from_map` refuses only *unusable* values, not
    /// shallow ones), or simply because a load balancer answered the two reads
    /// from two replicas. Which side survives is not knowable from here, so the
    /// safe answer is to wait.
    ///
    /// Both fields are exercised, because they are two separate `if`s and a fix
    /// applied to one is not a fix applied to the other.
    ///
    /// Mutation this detects: either block-identity `if` constructing
    /// `ContradictedLog` instead of `UncorroboratedLog`. The pass then reports
    /// `quarantined: 1` and writes a durable row.
    #[tokio::test]
    async fn a_block_identity_mismatch_is_not_quarantined_on_first_sight() {
        let dir = tempfile::tempdir().unwrap();
        let (_controller, state) = mock_state(dir.path()).await;
        let attempt = reserve_submitted(state.store()).await;
        let tx = submitted_tx_hash();
        let head = LOG_BLOCK + 10;
        let chain = reconciling_chain(tx, head);
        let policy = reconcile_policy(1);

        for (label, receipt) in [
            (
                "block number",
                TxReceiptView {
                    tx_hash: tx,
                    block_number: LOG_BLOCK + 1,
                    block_hash: BLOCK_HASH,
                    success: true,
                    gas_used: 21_000,
                },
            ),
            (
                "block hash",
                TxReceiptView {
                    tx_hash: tx,
                    block_number: LOG_BLOCK,
                    block_hash: [0x11; 32],
                    success: true,
                    gas_used: 21_000,
                },
            ),
        ] {
            chain.set_receipt(Ok(Some(receipt)));
            let outcome = run_reconcile(
                state.store(),
                state.data_key_hex(),
                (&chain).into(),
                state.metrics(),
                &policy,
                WALL_NOW,
            )
            .await;
            match outcome {
                ReconcileStepOutcome::Scanned {
                    quarantined,
                    stalled,
                    cursor_advanced,
                    ..
                } => {
                    assert_eq!(quarantined, 0, "{label} mismatch was quarantined on sight");
                    assert_eq!(stalled, 1, "{label} mismatch was not counted as a stall");
                    assert!(!cursor_advanced, "{label} mismatch let the cursor advance");
                }
                other => panic!("expected Scanned for {label}, got {other:?}"),
            }
            assert_eq!(
                count_all(state.store(), QUARANTINE_COUNT_SQL).await,
                0,
                "{label} mismatch wrote a durable abandonment record"
            );
            assert_eq!(
                reconcile::load_scan_cursor(state.store(), SCAN_CURSOR_ENROLLMENT_EXECUTED)
                    .await
                    .expect("cursor read"),
                None,
                "{label} mismatch moved the cursor"
            );
        }

        // --- paired positive arm: the fork resolves in the log's favour and
        //     the very same log confirms, so the two assertions above are not
        //     passing because this observer refuses everything.
        chain.set_receipt(Ok(Some(TxReceiptView {
            tx_hash: tx,
            block_number: LOG_BLOCK,
            block_hash: BLOCK_HASH,
            success: true,
            gas_used: 21_000,
        })));
        let ok = run_reconcile(
            state.store(),
            state.data_key_hex(),
            (&chain).into(),
            state.metrics(),
            &policy,
            WALL_NOW,
        )
        .await;
        assert!(
            matches!(
                ok,
                ReconcileStepOutcome::Scanned {
                    quarantined: 0,
                    stalled: 0,
                    cursor_advanced: true,
                    ..
                }
            ),
            "{ok:?}"
        );
        assert_eq!(
            scalar_text(state.store(), ATTEMPT_STATUS_SQL, attempt.attempt_id)
                .await
                .as_deref(),
            Some(TX_ATTEMPT_STATUS_CONFIRMED)
        );
    }

    /// 🔴 **The boundary of the chosen stall design: there isn't one, and that
    /// is deliberate.**
    ///
    /// Option (b) from the brief — hold the cursor and make the stall loud —
    /// was chosen over (a) a bounded retry, because a bounded retry ends in a
    /// quarantine, and a quarantine is unrecoverable: nothing reads behind the
    /// cursor. Option (a) also needs durable per-log attempt state, which needs
    /// a new migration, a freeze row in `store::MIGRATION_SHA256` **and** in
    /// `run-full-gate.ps1` — scope this lane cannot verify.
    ///
    /// So the boundary worth pinning is the absence of a silent one: after many
    /// passes an uncorroborated log must *still* be stalled, never converted
    /// into a quarantine by an attempt counter, an age, or a retry budget
    /// somebody adds later without reading this.
    ///
    /// The second property is the isolation boundary: a stalled log holds the
    /// **cursor**, not the **window**. A healthy log sitting after it in the
    /// same window must still fold on the very first pass, or one stuck receipt
    /// would freeze every other profile's confirmations too — the original
    /// wedge in a new costume.
    ///
    /// Mutation this detects: adding any bound that quarantines after N passes
    /// (the `quarantined` assertion fails), or `break`ing / `return`ing out of
    /// the per-log loop on a stall instead of continuing (the healthy attempt
    /// stays `submitted`).
    #[tokio::test]
    async fn an_uncorroborated_log_stalls_indefinitely_and_never_becomes_a_quarantine() {
        let dir = tempfile::tempdir().unwrap();
        let (_controller, state) = mock_state(dir.path()).await;
        let attempt = reserve_submitted(state.store()).await;
        let tx = submitted_tx_hash();
        let head = LOG_BLOCK + 10;
        let chain = reconciling_chain(tx, head);
        // The stalling log FIRST, the healthy one after it.
        chain.set_logs(Ok(vec![stalling_log(), executed_log(tx)]));
        // `STALL_TX` has no receipt on this node and never gets one.
        chain.set_receipt_for(STALL_TX, Ok(None));
        let policy = reconcile_policy(1);

        const PASSES: usize = 5;
        for pass in 1..=PASSES {
            let outcome = run_reconcile(
                state.store(),
                state.data_key_hex(),
                (&chain).into(),
                state.metrics(),
                &policy,
                WALL_NOW + pass as i64,
            )
            .await;
            match outcome {
                ReconcileStepOutcome::Scanned {
                    logs,
                    quarantined,
                    stalled,
                    cursor_advanced,
                    ..
                } => {
                    assert_eq!(logs, 2, "pass {pass}");
                    assert_eq!(
                        quarantined, 0,
                        "pass {pass}: the stall degraded into a permanent drop"
                    );
                    assert_eq!(stalled, 1, "pass {pass}");
                    assert!(!cursor_advanced, "pass {pass}: the cursor escaped");
                }
                other => panic!("pass {pass}: expected Scanned, got {other:?}"),
            }
        }

        assert_eq!(
            count_all(state.store(), QUARANTINE_COUNT_SQL).await,
            0,
            "after {PASSES} passes the uncorroborated log must still not be abandoned"
        );
        assert_eq!(
            reconcile::load_scan_cursor(state.store(), SCAN_CURSOR_ENROLLMENT_EXECUTED)
                .await
                .expect("cursor read"),
            None,
            "the cursor is held for as long as the stall lasts — that is the accepted cost"
        );

        // 🔴 Isolation: the healthy log AFTER the stalled one folded anyway, on
        // pass 1. A stall costs a repeated scan, not the deployment's progress.
        assert_eq!(
            scalar_text(state.store(), ATTEMPT_STATUS_SQL, attempt.attempt_id)
                .await
                .as_deref(),
            Some(TX_ATTEMPT_STATUS_CONFIRMED),
            "a stalled log must not stop the other logs in its window from folding"
        );

        let m = state.metrics().snapshot();
        assert_eq!(
            m.reconcile_stalled_logs, PASSES as u64,
            "the stall must be re-counted on every pass, so a stuck cursor shows up as a RISING \
             counter rather than a single old blip"
        );
        assert_eq!(m.reconcile_log_errors, 0, "nothing was dropped");
        assert_eq!(m.reconcile_errors, 0, "and no pass failed");
        // The counter is a lifetime total of *observations*, not of rows (the
        // quarantine test states the same for `reconcile_log_errors`), so the
        // held cursor re-serves and re-folds the healthy log every pass. What
        // must NOT multiply is the durable effect: the fold's deterministic
        // event id collapses all five observations onto one row. That is the
        // property the repeated scan actually depends on.
        assert_eq!(m.reconcile_confirmed, PASSES as u64);
        assert_eq!(
            count_all(
                state.store(),
                "SELECT COUNT(*) FROM reconciliation_events \
                 WHERE event_type = 'SponsoredEnrollmentExecuted'"
            )
            .await,
            1,
            "re-folding the same log on every held-cursor pass must stay idempotent — otherwise \
             holding the cursor would be its own defect"
        );
    }

    /// 🔴 **An RPC failure fetching the logs is NOT a poisoned log.**
    ///
    /// The distinction is the whole safety property of the per-log isolation
    /// above: if a window-level failure advanced the cursor, one flaky
    /// `eth_getLogs` would silently drop every confirmation in that range, since
    /// nothing ever re-reads history behind the cursor.
    ///
    /// The existing coverage asserts the cursor is `None` after a failed pass,
    /// which is satisfied by an observer that never wrote a cursor at all. This
    /// test sets a cursor first and asserts it is **unchanged**, which is not.
    ///
    /// Mutation this detects: making the `Err(e)` arm of `scan_and_fold`'s
    /// per-log `match` quarantine instead of return, or moving
    /// `save_scan_cursor` above the loop. The cursor then becomes
    /// `Some(head + 100)` and every assertion below fails.
    #[tokio::test]
    async fn a_window_level_fetch_error_does_not_advance_an_established_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let (_controller, state) = mock_state(dir.path()).await;
        let _attempt = reserve_submitted(state.store()).await;
        let head = LOG_BLOCK + 10;
        let chain = reconciling_chain(submitted_tx_hash(), head);
        let policy = reconcile_policy(1);

        // Paired arm FIRST: a healthy pass establishes a real cursor, so the
        // assertion below is "unchanged" rather than "never written".
        let ok = run_reconcile(
            state.store(),
            state.data_key_hex(),
            (&chain).into(),
            state.metrics(),
            &policy,
            WALL_NOW,
        )
        .await;
        assert!(matches!(ok, ReconcileStepOutcome::Scanned { .. }), "{ok:?}");
        assert_eq!(
            reconcile::load_scan_cursor(state.store(), SCAN_CURSOR_ENROLLMENT_EXECUTED)
                .await
                .expect("cursor read"),
            Some(head)
        );

        // Now the node breaks on the fetch itself.
        chain.set_pinned_block(Ok(head + 100));
        chain.set_logs(Err("eth_getLogs: connection reset".into()));
        let failed = run_reconcile(
            state.store(),
            state.data_key_hex(),
            (&chain).into(),
            state.metrics(),
            &policy,
            WALL_NOW + 1,
        )
        .await;

        assert_eq!(failed, ReconcileStepOutcome::Failed);
        assert_eq!(
            reconcile::load_scan_cursor(state.store(), SCAN_CURSOR_ENROLLMENT_EXECUTED)
                .await
                .expect("cursor read"),
            Some(head),
            "an RPC failure must leave the cursor exactly where it was, so the window is retried"
        );
        let m = state.metrics().snapshot();
        assert_eq!(m.reconcile_errors, 1, "counted as a failed PASS");
        assert_eq!(
            m.reconcile_log_errors, 0,
            "and never as a quarantined log — nothing was stepped over"
        );
        assert_eq!(
            count_all(state.store(), QUARANTINE_COUNT_SQL).await,
            0,
            "a node failure must not put a log in quarantine"
        );
    }

    /// 🔴 **A stale fold cannot stamp a re-reserved nonce slot `consumed`.**
    ///
    /// The hazard, which `submit.rs` used to argue was unreachable:
    /// `nonce_allocation_row_id` is derived from `(chain_id, signer_key, nonce)`,
    /// so a slot that is released and later re-reserved REUSES one primary key.
    /// The old argument was "a released row has `tx_hash` NULL, so the fold
    /// refuses it" — falsified by the fold's only production caller, which calls
    /// `reconcile::promote_verified_tx_hash` to FILL that NULL on the
    /// immediately preceding line.
    ///
    /// This test does not need `promote_verified_tx_hash` to reach the hazard —
    /// the swept attempt below keeps the `tx_hash` its acknowledgement wrote —
    /// which makes the reachability argument moot rather than merely disputed.
    ///
    /// Setup is the production shape throughout: the second attempt takes the
    /// slot through `outbox::reserve_and_persist_raw_tx`, i.e. through the same
    /// re-reservation branch a real replacement submit takes.
    ///
    /// Mutation this detects: deleting the `AND NOT EXISTS (…)` predicate from
    /// the `nonce_allocations` UPDATE in
    /// `submit::reconcile_executed_for_profile_id`. Arm 1's slot then reads
    /// `consumed` — the live replacement's claim silently transitioned out from
    /// under it — while every other assertion in the suite still passes.
    #[tokio::test]
    async fn a_stale_fold_cannot_consume_a_slot_a_live_attempt_re_reserved() {
        const INTENT_ID_2: [u8; 32] = [0x34; 32];

        // --- arm 1: the slot has been re-reserved by a LIVE attempt --------
        let dir = tempfile::tempdir().unwrap();
        let (_controller, state) = mock_state(dir.path()).await;
        let first = reserve_submitted(state.store()).await;

        // The sweeper's resolution, as `submit.rs`'s own stand-in writes it:
        // the attempt is terminal and its action nonce goes back.
        release_slot_as_swept(state.store(), &first.attempt_id, &first.allocation_id).await;

        // A replacement submit for a DIFFERENT intent takes the freed slot —
        // same controller, same action nonce, therefore the same row id.
        seed_intent_id(state.store(), INTENT_ID_2, (CHAIN_NOW as i64) + 3_600).await;
        let replacement = reserve_and_persist_raw_tx(
            state.store(),
            &data_key_hex(),
            &ReservationRequest {
                profile_id: PROFILE,
                intent_id: INTENT_ID_2,
                chain_id: CHAIN_ID,
                controller: CONTROLLER,
                action: ActionType::SponsoredEnrollment,
                action_nonce: ACTION_NONCE,
                claim_owner: "submit-path-owner",
                lease_ttl_seconds: DEFAULT_LEASE_TTL_SECONDS,
            },
            &SignedRawTx::new(
                vec![0x02, 0xf8, 0x6b, 0x11, 0x22, 0x33],
                GasUnits::new(500_000),
                MaxFeePerGas::new(1_000_000_000),
            ),
            WALL_NOW,
        )
        .await
        .expect("the freed slot must be re-reservable, or this test proves nothing");
        assert_eq!(
            replacement.allocation_id, first.allocation_id,
            "the two attempts must contend for ONE row — that reuse is the hazard"
        );
        assert_eq!(
            scalar_text(state.store(), NONCE_STATUS_SQL, first.allocation_id.clone())
                .await
                .as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "paired non-zero arm: the row really is live again before the fold runs"
        );

        // The stale log for the FIRST attempt arrives now.
        let chain = reconciling_chain(submitted_tx_hash(), LOG_BLOCK + 10);
        let outcome = run_reconcile(
            state.store(),
            state.data_key_hex(),
            (&chain).into(),
            state.metrics(),
            &reconcile_policy(1),
            WALL_NOW,
        )
        .await;
        assert!(
            matches!(
                outcome,
                ReconcileStepOutcome::Scanned { quarantined: 0, .. }
            ),
            "the fold itself must succeed; only the nonce transition is refused: {outcome:?}"
        );

        assert_eq!(
            scalar_text(state.store(), ATTEMPT_STATUS_SQL, first.attempt_id.clone())
                .await
                .as_deref(),
            Some(TX_ATTEMPT_STATUS_CONFIRMED),
            "the confirmation itself is still recorded"
        );
        assert_eq!(
            scalar_text(state.store(), NONCE_STATUS_SQL, first.allocation_id.clone())
                .await
                .as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "the slot belongs to the live replacement attempt and must NOT be stamped consumed by \
             a fold for the attempt that gave it up"
        );
        assert_eq!(
            scalar_text(
                state.store(),
                ATTEMPT_STATUS_SQL,
                replacement.attempt_id.clone()
            )
            .await
            .as_deref(),
            Some(TX_ATTEMPT_STATUS_RESERVED),
            "and the replacement is untouched"
        );

        // --- arm 2 (the pair): identical, minus the live re-reservation ----
        //
        // Without a live holder the same fold DOES consume the slot, so arm 1
        // is not passing because the UPDATE is inert.
        let dir2 = tempfile::tempdir().unwrap();
        let (_c2, state2) = mock_state(dir2.path()).await;
        let solo = reserve_submitted(state2.store()).await;
        release_slot_as_swept(state2.store(), &solo.attempt_id, &solo.allocation_id).await;
        let chain2 = reconciling_chain(submitted_tx_hash(), LOG_BLOCK + 10);
        run_reconcile(
            state2.store(),
            state2.data_key_hex(),
            (&chain2).into(),
            state2.metrics(),
            &reconcile_policy(1),
            WALL_NOW,
        )
        .await;
        assert_eq!(
            scalar_text(state2.store(), NONCE_STATUS_SQL, solo.allocation_id)
                .await
                .as_deref(),
            Some(NONCE_STATUS_CONSUMED),
            "with nobody holding the slot the fold must still record what the chain did"
        );
    }

    /// The two UPDATEs `outbox::sweep_stuck_reservations`' `SafeToRelease`
    /// branch writes, and nothing else — the same stand-in `submit.rs`'s test
    /// harness uses, for the same reason: driving the real sweeper here would
    /// need `transaction_receipt` and `intentUsed` armed and would make these
    /// tests about the sweeper.
    async fn release_slot_as_swept(store: &StreamGStore, attempt_id: &str, allocation_id: &str) {
        let attempt_id = attempt_id.to_string();
        let allocation_id = allocation_id.to_string();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    let n = sqlx::query(
                        "UPDATE nonce_allocations SET status = 'released', released_at = ?, \
                         claim_owner = NULL, lease_until = NULL WHERE id = ?",
                    )
                    .bind(WALL_NOW)
                    .bind(&allocation_id)
                    .execute(&mut **tx)
                    .await?;
                    assert_eq!(n.rows_affected(), 1, "release must hit the slot");
                    let a = sqlx::query(
                        "UPDATE tx_attempts SET status = 'failed', claim_owner = NULL, \
                         lease_until = NULL WHERE id = ?",
                    )
                    .bind(&attempt_id)
                    .execute(&mut **tx)
                    .await?;
                    assert_eq!(a.rows_affected(), 1, "and must terminate the attempt");
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("sweeper stand-in");
    }
}
