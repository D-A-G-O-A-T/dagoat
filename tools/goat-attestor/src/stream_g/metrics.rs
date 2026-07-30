//! Stream G counters — sweeper outcomes, reconciliation transitions and
//! broadcast outcomes — plus the one rule that shapes the whole module.
//!
//! # The rule: counts only, never the thing that was counted
//!
//! Spec §9.3: *"Signed intent/permit/authorization bytes are executable bearer
//! capabilities until expiry even though they are not private keys. They are
//! never written to ordinary logs or metrics."* A metric that recorded which
//! intent was swept, or a log line that echoed a stuck row's reason string,
//! would put a replayable payload — or a fragment of one — somewhere it is
//! neither encrypted nor access-controlled.
//!
//! So every recorder in this module takes the *rich* domain value
//! ([`SweepReport`], [`LogOutcome`], [`BroadcastOutcome`], …) and extracts
//! nothing from it but a discriminant and a count. That is enforced
//! structurally rather than by convention: each `match` arm below uses `..`
//! and binds **no field**, so there is no name in scope that a future edit
//! could accidentally interpolate into a counter label or a log line. The
//! counters themselves are `AtomicU64` — a type that cannot carry a payload.
//!
//! `no_metric_or_log_surface_carries_payload_bytes` is the standing proof: it
//! records outcomes whose id/reason/hash fields contain distinctive markers,
//! then asserts the exported snapshot and the captured `tracing` output
//! contain neither, while the counters did move.
//!
//! # Not a Prometheus registry
//!
//! Deliberately a hand-rolled struct rather than a metrics crate: this crate
//! has no metrics dependency, Stream G is disabled by default, and the export
//! surface is one JSON document (`GET /v1/stream-g/metrics`) rather than a
//! scrape endpoint with a text exposition format. If a scrape format is wanted
//! later it can be rendered from [`MetricsSnapshot`] without touching any
//! recorder.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

use super::broadcaster::BroadcastOutcome;
use super::outbox::SweepReport;
use super::reconcile::{AppliedDisposition, LogOutcome};

/// Process-wide Stream G counters. Held in `runtime::StreamGState` behind the
/// same `Arc` as the store, so handlers and background tasks share one set.
///
/// Every counter is monotonic and saturating: these are lifetime totals for a
/// process, and a wrapped counter would silently look like a reset.
#[derive(Debug, Default)]
pub struct StreamGMetrics {
    // --- sweeper (outbox::sweep_stuck_reservations) ---------------------
    sweep_passes: AtomicU64,
    sweep_errors: AtomicU64,
    sweep_claimed: AtomicU64,
    sweep_released: AtomicU64,
    sweep_executed: AtomicU64,
    sweep_held_intent_still_valid: AtomicU64,
    sweep_stuck: AtomicU64,

    // --- reconciliation passes (maintenance::run_reconcile) -------------
    reconcile_passes: AtomicU64,
    reconcile_errors: AtomicU64,
    reconcile_log_errors: AtomicU64,
    reconcile_stalled_logs: AtomicU64,
    reconcile_logs_observed: AtomicU64,

    // --- reconciliation transitions ------------------------------------
    reconcile_confirmed: AtomicU64,
    reconcile_externally_fulfilled: AtomicU64,
    reconcile_reorged: AtomicU64,
    reconcile_not_final_yet: AtomicU64,
    reconcile_no_candidates: AtomicU64,
    reconcile_held_for_sweeper: AtomicU64,
    reconcile_nothing_to_do: AtomicU64,

    // --- broadcast outcomes --------------------------------------------
    broadcast_accepted: AtomicU64,
    broadcast_unresolved: AtomicU64,
}

fn bump(counter: &AtomicU64, by: u64) {
    // `fetch_update` rather than `fetch_add` so the saturating claim in the
    // struct doc is true rather than aspirational.
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_add(by))
    });
}

fn read(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

impl StreamGMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one sweeper pass into the counters.
    ///
    /// Binds nothing out of `report` but its five integer/length fields —
    /// notably **not** `report.stuck[..].attempt_id` or `.reason`, which name
    /// a specific reserved row and quote whatever the chain resolution said
    /// about it.
    pub fn record_sweep(&self, report: &SweepReport) {
        bump(&self.sweep_passes, 1);
        bump(&self.sweep_claimed, report.claimed as u64);
        bump(&self.sweep_released, report.released as u64);
        bump(&self.sweep_executed, report.executed as u64);
        bump(
            &self.sweep_held_intent_still_valid,
            report.held_intent_still_valid as u64,
        );
        bump(&self.sweep_stuck, report.stuck_recoverable() as u64);

        tracing::debug!(
            claimed = report.claimed,
            released = report.released,
            executed = report.executed,
            held_intent_still_valid = report.held_intent_still_valid,
            stuck = report.stuck_recoverable(),
            "stream_g sweep pass recorded"
        );
    }

    /// A sweep that returned `Err` — the pass itself failed, so there are no
    /// outcome counts to fold in. Counted separately so "the sweeper is
    /// running" and "the sweeper is working" are distinguishable.
    ///
    /// Takes no error argument on purpose: an `OutboxError` renders SQL and
    /// chain-resolution detail, and this module's contract is that nothing
    /// with a payload in it can reach a counter or a log line from here. The
    /// caller is the right place to log the error itself, at its own level.
    pub fn record_sweep_error(&self) {
        bump(&self.sweep_errors, 1);
        tracing::debug!("stream_g sweep pass failed (error detail logged by the caller)");
    }

    /// One completed reconciliation scan, and how many logs it observed.
    ///
    /// Counted apart from the per-log transitions below for the same reason
    /// [`record_sweep_error`](Self::record_sweep_error) exists: "the observer is
    /// running" and "the observer is finding things" are different questions,
    /// and a window that legitimately contained no logs must not be
    /// indistinguishable from an observer that never ran.
    ///
    /// `logs` is a count, never a log's contents — same rule as everything else
    /// in this module.
    pub fn record_reconcile_pass(&self, logs: u64) {
        bump(&self.reconcile_passes, 1);
        bump(&self.reconcile_logs_observed, logs);
        tracing::debug!(logs, "stream_g reconcile pass recorded");
    }

    /// A reconciliation pass that returned `Err` — the scan or a fold failed, so
    /// its cursor was **not** advanced and the same window is retried.
    ///
    /// Before this counter existed a wedged reconciliation was invisible on
    /// `GET /v1/stream-g/metrics`: it looked exactly like "nothing to
    /// reconcile". Takes no error argument, for the reason
    /// [`record_sweep_error`](Self::record_sweep_error) states — a
    /// `ReconcileError` renders SQL, chain-resolution detail and transaction
    /// hashes. The caller logs the error itself, at its own level.
    pub fn record_reconcile_error(&self) {
        bump(&self.reconcile_errors, 1);
        tracing::debug!("stream_g reconcile pass failed (error detail logged by the caller)");
    }

    /// **One log** in an otherwise healthy window could not be folded, was
    /// quarantined (`reconcile::quarantine_unfoldable_log`) and was stepped
    /// over. The pass itself completed and its cursor advanced.
    ///
    /// Counted apart from [`record_reconcile_error`](Self::record_reconcile_error)
    /// because the two demand opposite operator responses. A pass error means
    /// "the same window is retried, watch for it clearing itself". A log error
    /// means "this log will NEVER be retried — read the quarantine row". Folding
    /// them into one counter would hide the second behind the first, and a
    /// zero-valued `reconcile_log_errors` is the only thing on
    /// `GET /v1/stream-g/metrics` that says no log was silently abandoned.
    ///
    /// Takes no error argument, same rule as every other recorder here.
    pub fn record_reconcile_log_error(&self) {
        bump(&self.reconcile_log_errors, 1);
        tracing::debug!("stream_g reconcile log quarantined (error detail logged by the caller)");
    }

    /// **One log** could not be corroborated *yet*
    /// (`ReconcileErrorScope::LogTransient`): the cursor is being **held** for
    /// it, the rest of the window still folded, and the same log will be
    /// re-observed on the next pass.
    ///
    /// 🔴 This is the third of three reconciliation failure counters, and the
    /// three exist so an operator can tell the states apart **from the metrics
    /// alone** — which is the whole operational contract of this subsystem:
    ///
    /// | counter | what happened | is it coming back? |
    /// |---|---|---|
    /// | `reconcile_errors` | the *pass* failed (node down, store unwritable) | yes — whole window retried |
    /// | `reconcile_stalled_logs` | one *log* is not corroborated yet | yes — cursor held, log retried |
    /// | `reconcile_log_errors` | one *log* was quarantined | **no — it is gone** |
    ///
    /// A rising `reconcile_stalled_logs` with a flat `reconcile_passes` delta is
    /// the shape of a permanently stuck cursor, and it is the shape an operator
    /// is expected to act on: this design deliberately has **no bound** on how
    /// long it stalls, because a visible stall is recoverable and a dropped
    /// confirmation is not. The paired `WARN` in `maintenance::scan_and_fold`
    /// names the block on every pass.
    ///
    /// Takes no error argument, same rule as every other recorder here.
    pub fn record_reconcile_stalled_log(&self) {
        bump(&self.reconcile_stalled_logs, 1);
        tracing::debug!(
            "stream_g reconcile log not corroborated yet; cursor held (error detail logged by the \
             caller)"
        );
    }

    /// Fold one reconciliation outcome in. Every arm is `..`: the variants
    /// carry attempt ids, profile ids, transaction hashes and block hashes,
    /// and none of them belongs in a counter label.
    pub fn record_log_outcome(&self, outcome: &LogOutcome) {
        let (counter, name) = match outcome {
            LogOutcome::Confirmed { .. } => (&self.reconcile_confirmed, "confirmed"),
            LogOutcome::ExternallyFulfilled { .. } => {
                (&self.reconcile_externally_fulfilled, "externally_fulfilled")
            }
            LogOutcome::Reorged { .. } => (&self.reconcile_reorged, "reorged"),
            LogOutcome::NotFinalYet { .. } => (&self.reconcile_not_final_yet, "not_final_yet"),
            LogOutcome::NoCandidates { .. } => (&self.reconcile_no_candidates, "no_candidates"),
        };
        bump(counter, 1);
        tracing::debug!(transition = name, "stream_g reconcile transition recorded");
    }

    /// Fold in what `reconcile::apply_disposition` wrote.
    pub fn record_applied_disposition(&self, applied: &AppliedDisposition) {
        let (counter, name) = match applied {
            AppliedDisposition::HeldForSweeper => {
                (&self.reconcile_held_for_sweeper, "held_for_sweeper")
            }
            AppliedDisposition::NothingToDo => (&self.reconcile_nothing_to_do, "nothing_to_do"),
        };
        bump(counter, 1);
        tracing::debug!(transition = name, "stream_g reconcile disposition recorded");
    }

    /// Fold in one broadcast. `Accepted` and `UnresolvedWithKnownHash` both
    /// carry the signed attempt and its transaction hash; neither is read.
    pub fn record_broadcast(&self, outcome: &BroadcastOutcome) {
        let (counter, name) = match outcome {
            BroadcastOutcome::Accepted { .. } => (&self.broadcast_accepted, "accepted"),
            BroadcastOutcome::UnresolvedWithKnownHash { .. } => {
                (&self.broadcast_unresolved, "unresolved")
            }
        };
        bump(counter, 1);
        tracing::debug!(outcome = name, "stream_g broadcast outcome recorded");
    }

    /// Point-in-time copy of every counter — the only way out of this type.
    ///
    /// There is no accessor for an individual counter and no `Serialize` on
    /// `StreamGMetrics` itself, so the exported document is exactly this
    /// struct and reviewing "what can leave the process" means reviewing
    /// [`MetricsSnapshot`]'s fields.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            sweep_passes: read(&self.sweep_passes),
            sweep_errors: read(&self.sweep_errors),
            sweep_claimed: read(&self.sweep_claimed),
            sweep_released: read(&self.sweep_released),
            sweep_executed: read(&self.sweep_executed),
            sweep_held_intent_still_valid: read(&self.sweep_held_intent_still_valid),
            sweep_stuck: read(&self.sweep_stuck),
            reconcile_passes: read(&self.reconcile_passes),
            reconcile_errors: read(&self.reconcile_errors),
            reconcile_log_errors: read(&self.reconcile_log_errors),
            reconcile_stalled_logs: read(&self.reconcile_stalled_logs),
            reconcile_logs_observed: read(&self.reconcile_logs_observed),
            reconcile_confirmed: read(&self.reconcile_confirmed),
            reconcile_externally_fulfilled: read(&self.reconcile_externally_fulfilled),
            reconcile_reorged: read(&self.reconcile_reorged),
            reconcile_not_final_yet: read(&self.reconcile_not_final_yet),
            reconcile_no_candidates: read(&self.reconcile_no_candidates),
            reconcile_held_for_sweeper: read(&self.reconcile_held_for_sweeper),
            reconcile_nothing_to_do: read(&self.reconcile_nothing_to_do),
            broadcast_accepted: read(&self.broadcast_accepted),
            broadcast_unresolved: read(&self.broadcast_unresolved),
        }
    }
}

/// The wire shape of `GET /v1/stream-g/metrics`.
///
/// snake_case (founder ruling on Stream G wire DTOs) — which is serde's
/// default for these field names, so there is deliberately **no**
/// `#[serde(rename_all = ..)]` here. `stream_g_wire_dtos_are_snake_case`
/// asserts it rather than trusting the absence of an attribute.
///
/// Every field is a `u64` count. That is the leak-proofing: there is no
/// `String` in this struct for a payload to hide in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct MetricsSnapshot {
    pub sweep_passes: u64,
    pub sweep_errors: u64,
    pub sweep_claimed: u64,
    pub sweep_released: u64,
    pub sweep_executed: u64,
    pub sweep_held_intent_still_valid: u64,
    pub sweep_stuck: u64,

    pub reconcile_passes: u64,
    pub reconcile_errors: u64,
    pub reconcile_log_errors: u64,
    pub reconcile_stalled_logs: u64,
    pub reconcile_logs_observed: u64,

    pub reconcile_confirmed: u64,
    pub reconcile_externally_fulfilled: u64,
    pub reconcile_reorged: u64,
    pub reconcile_not_final_yet: u64,
    pub reconcile_no_candidates: u64,
    pub reconcile_held_for_sweeper: u64,
    pub reconcile_nothing_to_do: u64,

    pub broadcast_accepted: u64,
    pub broadcast_unresolved: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_g::outbox::StuckAttempt;

    #[test]
    fn sweep_report_folds_into_every_sweep_counter() {
        let m = StreamGMetrics::new();
        assert_eq!(m.snapshot(), MetricsSnapshot::default());

        m.record_sweep(&SweepReport {
            claimed: 4,
            released: 1,
            executed: 2,
            held_intent_still_valid: 1,
            stuck: vec![StuckAttempt {
                attempt_id: "attempt-1".into(),
                reason: "rpc down".into(),
            }],
        });

        let s = m.snapshot();
        assert_eq!(s.sweep_passes, 1);
        assert_eq!(s.sweep_claimed, 4);
        assert_eq!(s.sweep_released, 1);
        assert_eq!(s.sweep_executed, 2);
        assert_eq!(s.sweep_held_intent_still_valid, 1);
        assert_eq!(s.sweep_stuck, 1);
        // Paired zero arm: a sweep must not touch a broadcast or reconcile
        // counter.
        assert_eq!(s.broadcast_accepted, 0);
        assert_eq!(s.reconcile_confirmed, 0);

        // A second pass accumulates rather than replaces.
        m.record_sweep(&SweepReport {
            claimed: 1,
            ..SweepReport::default()
        });
        assert_eq!(m.snapshot().sweep_passes, 2);
        assert_eq!(m.snapshot().sweep_claimed, 5);
    }

    #[test]
    fn sweep_errors_are_counted_apart_from_sweep_passes() {
        let m = StreamGMetrics::new();
        m.record_sweep_error();
        let s = m.snapshot();
        assert_eq!(s.sweep_errors, 1);
        assert_eq!(
            s.sweep_passes, 0,
            "a failed pass must not look like a successful one"
        );
    }

    #[test]
    fn every_reconcile_transition_has_its_own_counter() {
        let m = StreamGMetrics::new();
        m.record_log_outcome(&LogOutcome::Confirmed {
            attempt_id: "a".into(),
            profile_id: "p".into(),
            event_row_id: "e".into(),
            tx_hash_hex: "0x00".into(),
            block_number: 1,
        });
        m.record_log_outcome(&LogOutcome::ExternallyFulfilled {
            tx_hash_hex: "0x01".into(),
            consumed: vec![],
            released: vec![],
        });
        m.record_log_outcome(&LogOutcome::Reorged {
            block_hash_hex: "0x02".into(),
            rolled_back: vec![],
        });
        m.record_log_outcome(&LogOutcome::NotFinalYet {
            depth: Some(3),
            required: 12,
            block_number: 9,
            head: 12,
        });
        m.record_log_outcome(&LogOutcome::NoCandidates {
            intent_id_hex: "0x03".into(),
        });
        m.record_applied_disposition(&AppliedDisposition::HeldForSweeper);
        m.record_applied_disposition(&AppliedDisposition::NothingToDo);

        let s = m.snapshot();
        assert_eq!(s.reconcile_confirmed, 1);
        assert_eq!(s.reconcile_externally_fulfilled, 1);
        assert_eq!(s.reconcile_reorged, 1);
        assert_eq!(s.reconcile_not_final_yet, 1);
        assert_eq!(s.reconcile_no_candidates, 1);
        assert_eq!(s.reconcile_held_for_sweeper, 1);
        assert_eq!(s.reconcile_nothing_to_do, 1);
        // Paired zero arm: five distinct transitions must not all land on one
        // counter (which is what a copy-pasted `match` arm would produce).
        assert_eq!(s.sweep_passes, 0);
    }

    /// A quarantined log and a failed pass are different operational states
    /// and must not share a counter: one window is retried, the other log
    /// never is.
    ///
    /// Mutation this detects: making `record_reconcile_log_error` bump
    /// `reconcile_errors` (the counter that already existed) instead of its
    /// own. Both `assert_eq!(…, 0)` arms below then fail, which is the point —
    /// they are the arms that say the two are still distinguishable.
    #[test]
    fn a_quarantined_log_is_counted_apart_from_a_failed_pass() {
        let m = StreamGMetrics::new();
        m.record_reconcile_log_error();
        let s = m.snapshot();
        assert_eq!(s.reconcile_log_errors, 1);
        assert_eq!(
            s.reconcile_errors, 0,
            "one unfoldable log is not a failed pass — the pass completed and advanced its cursor"
        );
        assert_eq!(
            s.reconcile_passes, 0,
            "and recording the log error must not invent a pass either"
        );

        m.record_reconcile_error();
        let s = m.snapshot();
        assert_eq!(s.reconcile_errors, 1);
        assert_eq!(
            s.reconcile_log_errors, 1,
            "a failed pass must not inflate the per-log counter"
        );
    }

    /// 🔴 **"Stalled and retrying" and "dropped and never coming back" must be
    /// readable off the metrics alone.**
    ///
    /// That is the operational contract of the three-way classifier: a held
    /// cursor is recoverable and a quarantined log is not, so an operator who
    /// only has `GET /v1/stream-g/metrics` still has to be able to tell which
    /// one is happening. One counter for both would make the recoverable case
    /// look like the unrecoverable one and vice versa.
    ///
    /// Mutation this detects: pointing `record_reconcile_stalled_log` at
    /// `reconcile_log_errors` (or at `reconcile_errors`) — the two `assert_eq!(…,
    /// 0)` arms in the first half then fail.
    #[test]
    fn a_stalled_log_is_counted_apart_from_a_quarantined_one_and_a_failed_pass() {
        let m = StreamGMetrics::new();
        m.record_reconcile_stalled_log();
        let s = m.snapshot();
        assert_eq!(s.reconcile_stalled_logs, 1);
        assert_eq!(
            s.reconcile_log_errors, 0,
            "a stall must not be reported as a log that was dropped forever"
        );
        assert_eq!(
            s.reconcile_errors, 0,
            "nor as a failed pass — the pass completed, the cursor is simply held"
        );
        assert_eq!(s.reconcile_passes, 0, "and it must not invent a pass");

        // Paired non-zero arm: the other two still move independently, so this
        // is not passing because `record_reconcile_stalled_log` bumps nothing.
        m.record_reconcile_log_error();
        m.record_reconcile_error();
        let s = m.snapshot();
        assert_eq!(s.reconcile_stalled_logs, 1, "and is not inflated by them");
        assert_eq!(s.reconcile_log_errors, 1);
        assert_eq!(s.reconcile_errors, 1);
    }

    /// snake_case wire DTO (founder ruling). Asserted, not left to the
    /// absence of a `rename_all` attribute.
    #[test]
    fn metrics_snapshot_serializes_snake_case() {
        let json = serde_json::to_string(&MetricsSnapshot::default()).unwrap();
        assert!(json.contains("\"sweep_held_intent_still_valid\""), "{json}");
        assert!(
            json.contains("\"reconcile_externally_fulfilled\""),
            "{json}"
        );
        assert!(
            !json.contains("sweepHeldIntentStillValid"),
            "camelCase leaked into a Stream G wire DTO: {json}"
        );
    }

    /// 🔴 **The three reconciliation failure counters must reach the WIRE, not
    /// just the snapshot struct.**
    ///
    /// `maintenance::tests::a_poisoned_log_neither_stops_the_window_nor_holds_the_cursor`
    /// documents, as property (4), that a quarantined log "is visible on
    /// `GET /v1/stream-g/metrics` as `reconcile_log_errors`" — but it reads
    /// [`MetricsSnapshot`] directly, and so does every other reconcile test.
    /// Until this test existed, a single `#[serde(skip)]` on
    /// `reconcile_log_errors` would have left the entire suite green while the
    /// only signal that a confirmation was permanently dropped silently stopped
    /// being served. `metrics_snapshot_serializes_snake_case` did not cover it
    /// either: it names `sweep_held_intent_still_valid` and
    /// `reconcile_externally_fulfilled` and nothing else.
    ///
    /// The three are asserted together because they are the three-way
    /// distinction an operator makes from the metrics alone (see
    /// [`StreamGMetrics::record_reconcile_stalled_log`]'s table): "window being
    /// retried", "cursor held, log retried", "log gone forever".
    ///
    /// Non-default values, deliberately: a zero-valued snapshot would still
    /// serialize the keys under a `skip_serializing_if = "is_zero"`, and the
    /// value is asserted too, so pointing a field at the wrong counter in the
    /// serialized form is caught as well.
    ///
    /// Mutation this detects: `#[serde(skip)]` on any of the three fields.
    #[test]
    fn the_reconcile_failure_counters_are_on_the_metrics_wire() {
        let m = StreamGMetrics::new();
        m.record_reconcile_error();
        m.record_reconcile_log_error();
        m.record_reconcile_log_error();
        m.record_reconcile_stalled_log();
        m.record_reconcile_stalled_log();
        m.record_reconcile_stalled_log();

        let json = serde_json::to_string(&m.snapshot()).unwrap();

        assert!(
            json.contains("\"reconcile_errors\":1"),
            "the pass-failure counter must be served, and with its own value: {json}"
        );
        assert!(
            json.contains("\"reconcile_log_errors\":2"),
            "the ONLY wire signal that a log was quarantined and will never be retried must be \
             served: {json}"
        );
        assert!(
            json.contains("\"reconcile_stalled_logs\":3"),
            "the held-cursor counter must be served, or a stuck cursor is invisible to an \
             operator who only has this route: {json}"
        );
    }
}
