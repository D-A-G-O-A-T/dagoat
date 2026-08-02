//! Session lifecycle, and who owns the kill switch.
//!
//! # Ownership, stated once
//!
//! **The sidecar owns the kill switch. The desktop shell may engage it and may
//! never clear it.** Both halves matter and they are enforced separately:
//!
//! * [`TunnelLifecycle::engage_kill_switch`] accepts either origin. A shell
//!   that can only ask nicely is a shell whose stop button is decorative.
//! * [`TunnelLifecycle::clear_halt`] refuses [`ControlOrigin::Shell`] **before
//!   it looks at anything else**, halted or not. The origin check being first
//!   is the whole rule: a check that runs after "is it halted?" is a check
//!   that a future edit can reorder into irrelevance.
//! * A heartbeat is a shell message too, and it never clears a halt. That is
//!   the quiet half — an implementation that treats "the shell is alive again"
//!   as "resume" hands the shell the clear verb through the back door.
//!
//! # A stale heartbeat is not a halt
//!
//! The spec's state diagram maps *indicator stale* onto `Halting`. Task 23
//! asks for something narrower and this file implements the narrower rule: a
//! stale heartbeat **stops new streams and leaves the carriage up**. The two
//! statements disagree and the narrower one wins here, because dropping a
//! carriage costs a full post-quantum handshake to rebuild and a shell that
//! was merely slow for four seconds has not withdrawn anything. In-flight
//! streams are not torn down either; only new ones are refused.
//!
//! # The deadline is measured, and a missing measurement is not zero
//!
//! [`KILL_DEADLINE_MS`] is 5 000 and [`KILL_DEADLINE`] is the same number as a
//! [`Duration`]; a test pins both, because two spellings of one constant is
//! how a five-second rule becomes a five-millisecond one. A halt that has been
//! engaged but not observed to complete reports [`HaltOutcome::Unverified`] —
//! never `Completed`, and never a zero elapsed time. That mirrors the
//! socket-census rule this lane already holds: a number the reporter assigns
//! to itself is not evidence.
//!
//! Design authority: the "Residential Proxy Network — Worker & Tunnel Spec
//! (Tasks 18-36, 44, 45, 47)", Task 23, §4.1 (the `KILL_DEADLINE_MS`
//! reconciliation row) and §2 (INV-9, INV-10, INV-20).
//!
//! Honesty tagging: **[TARGET]**. Nothing here has ever halted a real socket;
//! the operating-system census that turns a halt into evidence lives in the
//! sidecar and is a later task's.

use std::time::Duration;

use crate::error::TunnelError;
use crate::mux::Mux;
use crate::state::{step, TunnelEvent, TunnelState};

/// The kill switch's deadline in milliseconds.
///
/// The canonical spelling, per the spec's §4.1 naming reconciliation, which
/// retires three competing names for this one number. Declared here, in the
/// module whose subject is kill-switch ownership; every other lane **imports**
/// it and must not redeclare it.
pub const KILL_DEADLINE_MS: u64 = 5_000;

/// The kill switch's deadline as a [`Duration`].
pub const KILL_DEADLINE: Duration = Duration::from_millis(KILL_DEADLINE_MS);

/// How long a heartbeat stays fresh, in milliseconds.
///
/// Three seconds, matching the shipped freshness claim for the operator's
/// egress surface: the polled authority runs at one second and the rest of the
/// shell at three, so three is what the copy promises and three is therefore
/// the longest a stale indicator may go unnoticed here. A tighter window would
/// stop streams on ordinary scheduler jitter; a looser one would outlive the
/// claim.
pub const HEARTBEAT_TTL_MS: u64 = 3_000;

/// Where a control message came from.
///
/// The distinction exists so that "the sidecar owns the kill switch" is a
/// parameter of the code rather than a sentence in a comment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ControlOrigin {
    /// The sidecar itself: the process that holds the sockets.
    Sidecar,
    /// The desktop shell. May engage a halt; may never clear one.
    Shell,
}

/// What was recorded when the kill switch was engaged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HaltRecord {
    /// Who engaged it. The **first** origin, kept across later engagements.
    pub origin: ControlOrigin,
    /// The monotonic millisecond reading at engagement.
    pub engaged_at_ms: u64,
    /// The monotonic millisecond reading when the halt was observed complete,
    /// or `None` while it has not been.
    pub completed_at_ms: Option<u64>,
    /// How many open streams the halt dropped.
    pub streams_dropped: usize,
}

/// Whether a halt met its deadline.
///
/// There is no variant that means "probably fine". An unobserved halt is
/// [`HaltOutcome::Unverified`], which is not a success and is not a zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HaltOutcome {
    /// Observed complete within [`KILL_DEADLINE`].
    Completed { elapsed_ms: u64 },
    /// Observed complete, but past [`KILL_DEADLINE`]. Not a success.
    DeadlineMissed { elapsed_ms: u64 },
    /// Engaged, and no completion has been observed.
    Unverified,
}

impl HaltOutcome {
    /// Whether this outcome is a halt that met its deadline.
    #[inline]
    pub fn is_completed_in_time(self) -> bool {
        matches!(self, HaltOutcome::Completed { .. })
    }
}

/// One tunnel session's lifecycle: its state, its streams, its liveness and
/// its halt.
///
/// The clock is a **parameter**, not a call to `Instant::now` inside the type.
/// A deadline rule tested against the wall clock is a deadline rule tested by
/// sleeping, and a suite that sleeps past five seconds per case is a suite
/// nobody runs. The one test that must observe real elapsed time takes it from
/// outside.
#[derive(Clone, Debug)]
pub struct TunnelLifecycle {
    state: TunnelState,
    mux: Mux,
    halt: Option<HaltRecord>,
    last_heartbeat_ms: Option<u64>,
}

impl Default for TunnelLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelLifecycle {
    /// A fresh lifecycle in [`TunnelState::Idle`] with no heartbeat yet.
    ///
    /// No heartbeat means not live: liveness is something the shell asserts,
    /// never something a constructor assumes.
    pub fn new() -> Self {
        Self {
            state: TunnelState::Idle,
            mux: Mux::new(),
            halt: None,
            last_heartbeat_ms: None,
        }
    }

    /// The current state.
    #[inline]
    pub fn state(&self) -> TunnelState {
        self.state
    }

    /// The stream multiplexer.
    #[inline]
    pub fn mux(&self) -> &Mux {
        &self.mux
    }

    /// Drive the state machine.
    ///
    /// Delegates to [`crate::state::step`] and keeps the result. Stickiness is
    /// not re-implemented here: `Halting` and `Closed` have no edge back to a
    /// data-carrying state, so a halted lifecycle cannot walk to `Ready`
    /// however many events it is fed.
    pub fn on_event(&mut self, event: TunnelEvent) -> Result<TunnelState, TunnelError> {
        let next = step(self.state, event)?;
        self.state = next;
        Ok(next)
    }

    /// Record a liveness beat at `now_ms`.
    ///
    /// **Never clears a halt.** A shell that starts beating again after a halt
    /// has not withdrawn the halt; it has only proved it is running.
    pub fn heartbeat(&mut self, now_ms: u64) {
        self.last_heartbeat_ms = Some(now_ms);
    }

    /// Whether the session is live at `now_ms`: not halted, and beaten within
    /// [`HEARTBEAT_TTL_MS`].
    pub fn is_live(&self, now_ms: u64) -> bool {
        if self.halt.is_some() {
            return false;
        }
        match self.last_heartbeat_ms {
            None => false,
            Some(last) => now_ms.saturating_sub(last) <= HEARTBEAT_TTL_MS,
        }
    }

    /// Whether the kill switch has been engaged.
    #[inline]
    pub fn is_halted(&self) -> bool {
        self.halt.is_some()
    }

    /// What was recorded at engagement, if anything was.
    #[inline]
    pub fn halt_record(&self) -> Option<HaltRecord> {
        self.halt
    }

    /// Engage the kill switch, from either origin.
    ///
    /// Drops every open stream, moves the state machine to
    /// [`TunnelState::Halting`], and returns the record. Engaging an engaged
    /// kill switch keeps the **first** origin and the **first** timestamp: the
    /// deadline is measured from when the halt was first demanded, not from
    /// the last time somebody repeated the demand.
    pub fn engage_kill_switch(&mut self, origin: ControlOrigin, now_ms: u64) -> HaltRecord {
        if let Some(existing) = self.halt {
            // Idempotent. The state machine accepts the event from every
            // state, so this cannot fail.
            let _ = self.on_event(TunnelEvent::KillSwitchEngaged);
            return existing;
        }
        let streams_dropped = self.mux.drop_all();
        let record = HaltRecord {
            origin,
            engaged_at_ms: now_ms,
            completed_at_ms: None,
            streams_dropped,
        };
        self.halt = Some(record);
        let _ = self.on_event(TunnelEvent::KillSwitchEngaged);
        record
    }

    /// Clear a halt. Refused, in two different ways, for two different
    /// reasons.
    ///
    /// The origin check is **first**, so the shell is refused whether or not
    /// anything is halted. The sticky check is second. The `Ok` branch —
    /// sidecar, nothing halted — is what proves the verb works at all, so that
    /// the two refusals are refusals rather than a method that always fails.
    pub fn clear_halt(&mut self, origin: ControlOrigin) -> Result<(), TunnelError> {
        if origin == ControlOrigin::Shell {
            return Err(TunnelError::HaltNotClearableByShell);
        }
        if self.halt.is_some() {
            return Err(TunnelError::HaltIsSticky);
        }
        Ok(())
    }

    /// Observe the halt complete at `now_ms`.
    ///
    /// Returns the outcome. Calling it on a lifecycle that was never halted is
    /// `None`: there is nothing to complete.
    pub fn complete_halt(&mut self, now_ms: u64) -> Option<HaltOutcome> {
        let record = self.halt.as_mut()?;
        if record.completed_at_ms.is_none() {
            record.completed_at_ms = Some(now_ms);
        }
        self.halt_outcome()
    }

    /// The current halt outcome, or `None` if never halted.
    pub fn halt_outcome(&self) -> Option<HaltOutcome> {
        let record = self.halt?;
        let Some(done) = record.completed_at_ms else {
            return Some(HaltOutcome::Unverified);
        };
        let elapsed_ms = done.saturating_sub(record.engaged_at_ms);
        Some(if elapsed_ms <= KILL_DEADLINE_MS {
            HaltOutcome::Completed { elapsed_ms }
        } else {
            HaltOutcome::DeadlineMissed { elapsed_ms }
        })
    }

    /// Whether a new stream may be opened at `now_ms`.
    ///
    /// Three conditions, each with its own refusal: not halted, live, and in
    /// [`TunnelState::Ready`].
    pub fn may_open_stream(&self, now_ms: u64) -> Result<(), TunnelError> {
        if self.is_halted() {
            return Err(TunnelError::TunnelHalted);
        }
        if !self.is_live(now_ms) {
            return Err(TunnelError::HeartbeatStale);
        }
        if !self.state.may_carry_stream_data() {
            return Err(TunnelError::IllegalTransition {
                from: self.state.name(),
                event: TunnelEvent::StreamOpened.name(),
            });
        }
        Ok(())
    }

    /// Open a stream, if the lifecycle permits one and the mux has room.
    pub fn open_stream(&mut self, stream_id: u32, now_ms: u64) -> Result<(), TunnelError> {
        self.may_open_stream(now_ms)?;
        self.mux.open(stream_id)?;
        // The state machine's own accounting. `Ready + StreamOpened` stays
        // `Ready`, so this cannot move the phase; it is here so that a state
        // machine edit that made it illegal would red this path too.
        match self.on_event(TunnelEvent::StreamOpened) {
            Ok(_) => Ok(()),
            Err(e) => {
                // Roll back, so a refused open leaves no trace.
                let _ = self.mux.close(stream_id);
                Err(e)
            }
        }
    }

    /// Close a stream.
    ///
    /// Not gated on liveness: a stale heartbeat stops **new** streams and must
    /// never strand the ones already open.
    pub fn close_stream(&mut self, stream_id: u32) -> Result<(), TunnelError> {
        self.mux.close(stream_id)?;
        let _ = self.on_event(TunnelEvent::StreamClosed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Walk a fresh lifecycle to `Ready` with a heartbeat at `now_ms`.
    fn ready_at(now_ms: u64) -> TunnelLifecycle {
        let mut life = TunnelLifecycle::new();
        for event in [
            TunnelEvent::CarriageConnected,
            TunnelEvent::HelloSent,
            TunnelEvent::PeerConfirmed,
            TunnelEvent::PeerConfirmed,
        ] {
            life.on_event(event).expect("handshake walk");
        }
        assert_eq!(life.state(), TunnelState::Ready);
        life.heartbeat(now_ms);
        life
    }

    /// **Mutations this detects:** changing either spelling of the deadline
    /// without the other — the exact drift the spec's naming reconciliation
    /// row exists to prevent, and the one that turns five seconds into five
    /// milliseconds with no test noticing.
    #[test]
    fn the_kill_deadline_is_five_seconds_in_both_forms() {
        assert_eq!(KILL_DEADLINE_MS, 5_000);
        assert_eq!(KILL_DEADLINE, Duration::from_millis(5_000));
        assert_eq!(KILL_DEADLINE, Duration::from_millis(KILL_DEADLINE_MS));
        assert_eq!(KILL_DEADLINE.as_millis() as u64, KILL_DEADLINE_MS);
        // And the liveness window is a different, smaller number: collapsing
        // the two would make a slow shell look like a halt.
        assert_eq!(HEARTBEAT_TTL_MS, 3_000);
        assert_eq!(
            KILL_DEADLINE_MS.checked_sub(HEARTBEAT_TTL_MS),
            Some(2_000),
            "the liveness window must sit strictly inside the halt deadline"
        );
    }

    /// **Mutations this detects:** moving the origin check below the
    /// is-halted check (the shell would then clear nothing but *succeed* when
    /// nothing is halted, which is the first step to succeeding when something
    /// is), or letting the sidecar clear a halt.
    #[test]
    fn kill_switch_state_is_owned_by_the_sidecar_not_the_ui() {
        // Positive control: the verb works. Sidecar, nothing halted, `Ok`.
        let mut life = ready_at(0);
        assert_eq!(life.clear_halt(ControlOrigin::Sidecar), Ok(()));

        // The shell is refused even with nothing halted, because clearing a
        // halt is not a shell verb in any state.
        assert_eq!(
            life.clear_halt(ControlOrigin::Shell),
            Err(TunnelError::HaltNotClearableByShell)
        );

        life.engage_kill_switch(ControlOrigin::Sidecar, 10);
        assert!(life.is_halted());

        // Both origins refused once halted, and refused for *different*
        // reasons — a single refusal cause would pass against a method that
        // refuses everything.
        assert_eq!(
            life.clear_halt(ControlOrigin::Shell),
            Err(TunnelError::HaltNotClearableByShell)
        );
        assert_eq!(
            life.clear_halt(ControlOrigin::Sidecar),
            Err(TunnelError::HaltIsSticky)
        );
        assert_ne!(
            TunnelError::HaltNotClearableByShell,
            TunnelError::HaltIsSticky
        );
        assert!(life.is_halted(), "a clear attempt cleared the halt");
    }

    /// **Mutations this detects:** treating a heartbeat as evidence of
    /// intent-to-resume — the back door through which the shell would get the
    /// clear verb it is refused at the front.
    #[test]
    fn a_shell_heartbeat_cannot_resurrect_a_halted_tunnel() {
        let mut life = ready_at(0);
        // Positive control: before the halt, a beat does make it live.
        assert!(life.is_live(100));

        life.engage_kill_switch(ControlOrigin::Shell, 200);
        assert!(life.is_halted());
        assert!(!life.is_live(200));

        for t in [300u64, 400, 500] {
            life.heartbeat(t);
            assert!(!life.is_live(t), "a heartbeat made a halted tunnel live");
            assert!(life.is_halted());
            assert_eq!(life.may_open_stream(t), Err(TunnelError::TunnelHalted));
        }
    }

    /// **Mutations this detects:** clearing the halt flag on a carriage
    /// rebuild, or a state machine edit that lets `Halting`/`Closed` walk back
    /// to `Ready` — either of which makes the kill switch a reconnect delay.
    #[test]
    fn a_halt_is_sticky_across_a_carriage_reconnect() {
        let mut life = ready_at(0);
        life.open_stream(1, 0).expect("open");

        life.engage_kill_switch(ControlOrigin::Sidecar, 50);
        assert_eq!(life.state(), TunnelState::Halting);

        // The carriage drops and something tries to rebuild the session.
        assert_eq!(
            life.on_event(TunnelEvent::CarriageLost),
            Ok(TunnelState::Closed)
        );
        for event in [
            TunnelEvent::CarriageConnected,
            TunnelEvent::HelloSent,
            TunnelEvent::PeerConfirmed,
        ] {
            assert!(
                life.on_event(event).is_err(),
                "{event:?} was accepted after a halt"
            );
        }
        assert_eq!(life.state(), TunnelState::Closed);
        assert!(life.is_halted());
        life.heartbeat(60);
        assert_eq!(life.may_open_stream(60), Err(TunnelError::TunnelHalted));

        // Positive control: the same walk on a lifecycle that was NOT halted
        // does rebuild, so the refusals above are the halt's doing.
        let mut fresh = ready_at(0);
        assert_eq!(
            fresh.on_event(TunnelEvent::CarriageLost),
            Ok(TunnelState::Idle)
        );
        assert_eq!(
            fresh.on_event(TunnelEvent::CarriageConnected),
            Ok(TunnelState::CarriageUp)
        );
    }

    /// **Mutations this detects:** escalating a stale heartbeat into a halt
    /// (which throws away the carriage and a full post-quantum handshake
    /// because the shell was slow), or ignoring staleness entirely so a dead
    /// shell keeps new streams flowing.
    #[test]
    fn a_stale_heartbeat_stops_new_streams_without_dropping_the_carriage() {
        let mut life = ready_at(1_000);
        life.open_stream(1, 1_000).expect("open inside the window");

        // Positive control: inside the window, a new stream opens.
        life.open_stream(2, 1_000 + HEARTBEAT_TTL_MS)
            .expect("open at the boundary");

        let stale = 1_000 + HEARTBEAT_TTL_MS + 1;
        assert!(!life.is_live(stale));
        assert_eq!(
            life.may_open_stream(stale),
            Err(TunnelError::HeartbeatStale)
        );
        assert_eq!(life.open_stream(3, stale), Err(TunnelError::HeartbeatStale));

        // The carriage is untouched and the in-flight streams are untouched.
        assert_eq!(life.state(), TunnelState::Ready);
        assert!(!life.is_halted());
        assert_eq!(life.mux().open_count(), 2);
        assert_eq!(life.mux().open_ids(), vec![1, 2]);
        // Closing an in-flight stream still works with a stale heartbeat.
        life.close_stream(1).expect("close while stale");

        // And a fresh beat restores new streams without any other action.
        life.heartbeat(stale);
        assert!(life.is_live(stale));
        life.open_stream(3, stale).expect("open after a fresh beat");
    }

    /// **Mutations this detects:** widening the deadline comparison, or
    /// measuring elapsed time from the last repeat of the halt demand rather
    /// than from the first.
    #[test]
    fn a_halt_completed_inside_the_deadline_reports_completed() {
        let mut life = ready_at(0);
        life.engage_kill_switch(ControlOrigin::Sidecar, 1_000);
        assert_eq!(life.halt_outcome(), Some(HaltOutcome::Unverified));

        let outcome = life
            .complete_halt(1_000 + KILL_DEADLINE_MS)
            .expect("outcome");
        assert_eq!(
            outcome,
            HaltOutcome::Completed {
                elapsed_ms: KILL_DEADLINE_MS
            },
            "exactly at the deadline is inside it"
        );
        assert!(outcome.is_completed_in_time());
        assert_eq!(
            life.halt_record().and_then(|r| r.completed_at_ms),
            Some(1_000 + KILL_DEADLINE_MS)
        );
    }

    /// **Mutations this detects:** reporting a missed deadline as a success —
    /// the failure this whole outcome type exists to make impossible to
    /// express by accident.
    #[test]
    fn a_halt_completed_past_the_deadline_reports_deadline_missed_not_completed() {
        let mut life = ready_at(0);
        life.engage_kill_switch(ControlOrigin::Sidecar, 1_000);
        let outcome = life
            .complete_halt(1_000 + KILL_DEADLINE_MS + 1)
            .expect("outcome");
        assert_eq!(
            outcome,
            HaltOutcome::DeadlineMissed {
                elapsed_ms: KILL_DEADLINE_MS + 1
            }
        );
        assert!(!outcome.is_completed_in_time());
        assert_ne!(
            outcome,
            HaltOutcome::Completed {
                elapsed_ms: KILL_DEADLINE_MS + 1
            }
        );
    }

    /// **Mutations this detects:** defaulting an unobserved halt to a zero
    /// elapsed time and a `Completed` verdict — the same class of self-assigned
    /// number that INV-10 forbids in a halt receipt's socket count.
    #[test]
    fn a_halt_with_no_completion_reports_unverified_never_zero() {
        let mut life = ready_at(0);
        assert_eq!(
            life.halt_outcome(),
            None,
            "an unhalted lifecycle has no outcome"
        );

        life.engage_kill_switch(ControlOrigin::Sidecar, 7_000);
        assert_eq!(life.halt_outcome(), Some(HaltOutcome::Unverified));
        assert_ne!(
            life.halt_outcome(),
            Some(HaltOutcome::Completed { elapsed_ms: 0 })
        );
        assert!(!life.halt_outcome().expect("outcome").is_completed_in_time());
        assert_eq!(life.halt_record().and_then(|r| r.completed_at_ms), None);

        // Positive control: an observation does move it off `Unverified`.
        life.complete_halt(7_001);
        assert_eq!(
            life.halt_outcome(),
            Some(HaltOutcome::Completed { elapsed_ms: 1 })
        );
    }

    /// The wall-clock half. Everything above uses an injected clock; this one
    /// measures the real in-process halt path.
    ///
    /// **Mutations this detects:** anything that makes the in-process halt
    /// path block — a sleep, a lock held across the drop, a per-stream
    /// teardown that waits on I/O. Inserting a six-second stall anywhere
    /// between `Instant::now()` and the assertion reds this test and only
    /// this test.
    #[test]
    fn the_in_process_halt_path_completes_within_the_kill_deadline() {
        let mut life = ready_at(0);
        for id in 1..=8u32 {
            life.open_stream(id, 0).expect("open");
        }
        assert_eq!(life.mux().open_count(), 8);

        let started = Instant::now();
        let record = life.engage_kill_switch(ControlOrigin::Sidecar, 0);
        let elapsed = started.elapsed();

        assert!(life.is_halted());
        assert_eq!(record.streams_dropped, 8);
        assert_eq!(life.mux().open_count(), 0, "a stream survived the halt");
        assert_eq!(life.state(), TunnelState::Halting);
        assert!(
            elapsed < KILL_DEADLINE,
            "the in-process halt path took {elapsed:?}, past the {KILL_DEADLINE:?} deadline"
        );

        // The measured elapsed time is also what the outcome reports, in the
        // units the outcome uses.
        let outcome = life
            .complete_halt(elapsed.as_millis() as u64)
            .expect("outcome");
        assert!(
            outcome.is_completed_in_time(),
            "the measured halt did not report as completed in time: {outcome:?}"
        );
    }

    /// **Mutations this detects:** letting a repeat engagement overwrite the
    /// first origin or restart the clock, which would let a shell that keeps
    /// pressing stop push the deadline out indefinitely.
    #[test]
    fn engaging_the_kill_switch_twice_keeps_the_first_origin_and_the_first_clock() {
        let mut life = ready_at(0);
        let first = life.engage_kill_switch(ControlOrigin::Shell, 100);
        assert_eq!(first.origin, ControlOrigin::Shell);
        assert_eq!(first.engaged_at_ms, 100);

        let second = life.engage_kill_switch(ControlOrigin::Sidecar, 9_999);
        assert_eq!(second, first, "a repeat engagement rewrote the halt record");
        assert_eq!(life.halt_record(), Some(first));
        assert_eq!(life.state(), TunnelState::Halting);

        // And the deadline is still measured from the first demand.
        assert_eq!(
            life.complete_halt(100 + KILL_DEADLINE_MS + 1),
            Some(HaltOutcome::DeadlineMissed {
                elapsed_ms: KILL_DEADLINE_MS + 1
            })
        );
    }

    /// **Mutations this detects:** a halt that leaves streams in the mux while
    /// reporting a drop count — the receipt would then name a number nothing
    /// observed.
    #[test]
    fn a_halt_drops_every_open_stream_and_reports_how_many() {
        let mut life = ready_at(0);
        for id in [3u32, 1, 2] {
            life.open_stream(id, 0).expect("open");
        }
        // Positive control: they really are open first.
        assert_eq!(life.mux().open_ids(), vec![1, 2, 3]);

        let record = life.engage_kill_switch(ControlOrigin::Sidecar, 0);
        assert_eq!(record.streams_dropped, 3);
        assert!(life.mux().open_ids().is_empty());

        // A halt with nothing open reports zero, which is a real zero and not
        // an unverified one.
        let mut empty = ready_at(0);
        assert_eq!(
            empty
                .engage_kill_switch(ControlOrigin::Sidecar, 0)
                .streams_dropped,
            0
        );
    }

    /// **Mutations this detects:** dropping the origin distinction entirely by
    /// refusing the shell's *engage* as well as its *clear* — which would make
    /// the desktop stop button decorative and is the opposite failure from the
    /// one the ownership rule guards.
    #[test]
    fn either_origin_may_engage_a_halt() {
        for origin in [ControlOrigin::Shell, ControlOrigin::Sidecar] {
            let mut life = ready_at(0);
            let record = life.engage_kill_switch(origin, 42);
            assert_eq!(record.origin, origin);
            assert!(life.is_halted());
            assert_eq!(life.state(), TunnelState::Halting);
        }
    }

    /// **Mutations this detects:** checking liveness or state before the halt,
    /// so a halted-but-live-and-Ready lifecycle reports the wrong refusal and
    /// a caller retries instead of stopping.
    #[test]
    fn no_stream_opens_while_halted_and_the_halt_is_the_reason_given() {
        let mut life = ready_at(0);
        // Positive control: before the halt, in `Ready`, live, a stream opens.
        life.open_stream(1, 0).expect("open");

        life.engage_kill_switch(ControlOrigin::Sidecar, 0);
        life.heartbeat(0);
        // Halted, and the heartbeat is fresh, and the mux has room: the halt
        // must still be the answer, and it must be first.
        assert_eq!(life.may_open_stream(0), Err(TunnelError::TunnelHalted));
        assert_eq!(life.open_stream(2, 0), Err(TunnelError::TunnelHalted));
        assert_eq!(life.mux().open_count(), 0);
    }

    /// **Mutations this detects:** a liveness window that is exclusive at the
    /// boundary (stopping streams one millisecond early on every session) or
    /// one that treats "never beaten" as live.
    #[test]
    fn heartbeat_liveness_expires_one_millisecond_past_the_window() {
        let life = TunnelLifecycle::new();
        assert!(
            !life.is_live(0),
            "a lifecycle with no heartbeat is not live"
        );

        let mut life = TunnelLifecycle::new();
        life.heartbeat(1_000);
        assert!(life.is_live(1_000));
        assert!(life.is_live(1_000 + HEARTBEAT_TTL_MS));
        assert!(!life.is_live(1_000 + HEARTBEAT_TTL_MS + 1));
        // A clock that goes backwards must not read as stale-forever.
        assert!(life.is_live(999));
    }

    /// **Mutations this detects:** an `open_stream` that leaves the id in the
    /// mux after the state machine refuses it, which would leak a slot per
    /// refusal until the concurrency cap locks the session out.
    #[test]
    fn a_stream_refused_by_the_mux_or_the_state_machine_leaves_no_trace() {
        let mut life = ready_at(0);
        life.open_stream(1, 0).expect("open");
        assert_eq!(
            life.open_stream(1, 0),
            Err(TunnelError::DuplicateStreamId(1))
        );
        assert_eq!(life.mux().open_count(), 1);
        assert_eq!(
            life.open_stream(0, 0),
            Err(TunnelError::ZeroStreamId(
                crate::frame::FrameKind::StreamOpen
            ))
        );
        assert_eq!(life.mux().open_count(), 1);

        // Outside `Ready` the refusal names the state machine, not the mux.
        let mut idle = TunnelLifecycle::new();
        idle.heartbeat(0);
        assert_eq!(
            idle.open_stream(1, 0),
            Err(TunnelError::IllegalTransition {
                from: "Idle",
                event: "StreamOpened",
            })
        );
        assert_eq!(idle.mux().open_count(), 0);
    }
}
