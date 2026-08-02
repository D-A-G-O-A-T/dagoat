//! What a node can take, and the gateway-side bound on how many nodes may
//! take it.
//!
//! # The capacity report carries four numbers and nothing else
//!
//! [`CapacityReport`] is what a node tells the gateway about itself. Every
//! field is a byte count, a rate, a boolean or a stream count. There is no
//! hostname, no address, no allowlist entry, no destination of any kind — this
//! structure crosses the tunnel on every scheduling decision and is exactly
//! the place a future task will reach for when it wants to say *which* origin
//! a node is good for. INV-11 says it may not, and a test destructures the
//! struct exhaustively so that adding such a field is a compile error.
//!
//! # De-scheduling is not throttling
//!
//! Outside its consented schedule window a node is **de-scheduled**: it is not
//! offered work at all. It is not given a throttle of zero, because a rate is
//! not an on/off switch and a component that reads the rate would be one
//! rounding error away from resuming egress the operator did not consent to.
//! [`CapacityReport::throttle_bytes_per_sec`] therefore takes no part in the
//! scheduling decision at any value, and a test asserts that across the whole
//! range of the field.
//!
//! # `MAX_CONCURRENT_NODES = 1` is a safety control, not a placeholder
//!
//! The shipped allowlist points at five named third-party research services
//! that publish polite-pool and rate-limit terms, and the one abuse class this
//! lane concedes it cannot bound — a distributed layer-7 flood — is precisely
//! the one the shipped scope aims at real victims. Per-node caps cannot bound
//! an aggregate; a pilot that cannot exceed one node's rate does not need them
//! to. Raising the constant is gated on §1 criterion 5, the global
//! per-destination ceiling, and the constant is the thing that gate raises.
//!
//! # Named gap, carried forward unchanged
//!
//! [`GatewayScheduler`] is a **stub** of the gateway's real scheduler. It
//! proves the de-scheduling rule and the concurrency bound. It does **not**
//! implement assignment, the global per-destination ceiling, or fairness
//! across nodes. Those belong to the gateway lane and are not started here.
//!
//! Design authority: the "Residential Proxy Network — Worker & Tunnel Spec
//! (Tasks 18-36, 44, 45, 47)", Task 24, §1 and its Hazard → fix map row for
//! layer-7 flooding; and the "Residential Proxy Network (P3) Implementation
//! Plan", §2 (INV-9, INV-11) and §3.
//!
//! Honesty tagging: **[RESEARCH]** for the scheduler, **[TARGET]** for the
//! report. No gateway schedules anything today.

use crate::mux::Mux;

/// An opaque node identifier.
///
/// Thirty-two bytes the gateway assigns or derives from the node's ML-DSA-65
/// identity key. Deliberately not a hostname, not an address and not anything
/// an operator's network can be recognised by: INV-11 governs this structure
/// as much as it governs a receipt.
pub type NodeId = [u8; 32];

/// How many nodes the gateway may have scheduled at once, for the whole pilot.
///
/// **A safety control, not a placeholder.** See this module's header for why
/// one, and §1 criterion 5 — the global per-destination ceiling — for what
/// raises it.
pub const MAX_CONCURRENT_NODES: usize = 1;

/// Why a node is not being offered work.
///
/// Each variant is a distinct cause. A scheduler that answered "not now" for
/// all of them would pass a refusal test while telling an operator nothing
/// about which of their own settings stopped the work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeScheduleReason {
    /// The gateway has never received a capacity report from this node.
    NoCapacityReport,
    /// The node is outside its consented schedule window.
    OutOfSchedule,
    /// The node's daily byte ceiling is spent.
    DailyBytesExhausted,
    /// Every one of the node's concurrent stream slots is in use.
    NoStreamsFree,
    /// The node's kill switch is engaged.
    Halted,
    /// The node's shell has not beaten inside the liveness window.
    HeartbeatStale,
}

/// What one node can take right now.
///
/// Four fields, all of them counts. The exhaustive-destructure test is the
/// guard on that, because a struct-shape rule cannot be enforced any other
/// way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityReport {
    /// Bytes left against the operator's consented daily ceiling.
    pub remaining_daily_bytes: u64,
    /// The operator's configured rate limit. **Takes no part in the
    /// scheduling decision** — a rate is not an on/off switch.
    pub throttle_bytes_per_sec: u64,
    /// Whether the node is inside a consented schedule window.
    pub in_schedule: bool,
    /// How many more concurrent streams the node can hold.
    pub streams_free: usize,
}

impl CapacityReport {
    /// A report from a live mux and the operator's three consented bounds.
    ///
    /// `streams_free` is taken from the multiplexer rather than passed in,
    /// because a stream count a node computes for itself is a number nothing
    /// observed.
    pub fn from_mux(
        mux: &Mux,
        remaining_daily_bytes: u64,
        throttle_bytes_per_sec: u64,
        in_schedule: bool,
    ) -> Self {
        Self {
            remaining_daily_bytes,
            throttle_bytes_per_sec,
            in_schedule,
            streams_free: mux.streams_free(),
        }
    }

    /// Whether this node may be offered work, and if not, why not.
    ///
    /// Check order is the operator's consent first (`in_schedule`), then their
    /// ceiling, then the mechanical limit. An operator who closed their
    /// schedule window should be told that, not told their slots are full.
    pub fn schedulability(&self) -> Result<(), DeScheduleReason> {
        if !self.in_schedule {
            return Err(DeScheduleReason::OutOfSchedule);
        }
        if self.remaining_daily_bytes == 0 {
            return Err(DeScheduleReason::DailyBytesExhausted);
        }
        if self.streams_free == 0 {
            return Err(DeScheduleReason::NoStreamsFree);
        }
        Ok(())
    }

    /// Whether this node may be offered work.
    #[inline]
    pub fn is_schedulable(&self) -> bool {
        self.schedulability().is_ok()
    }
}

/// The gateway's scheduler — a **stub**, as described in this module's header.
///
/// Behind the `gateway` feature so that a node build cannot link it. The node
/// has no business holding the gateway's scheduling state, and a node binary
/// that carries it is a node binary that could be talked into acting like one.
#[cfg(feature = "gateway")]
#[derive(Clone, Debug, Default)]
pub struct GatewayScheduler {
    scheduled: std::collections::BTreeSet<NodeId>,
    reports: std::collections::BTreeMap<NodeId, CapacityReport>,
    de_scheduled_because: std::collections::BTreeMap<NodeId, DeScheduleReason>,
}

#[cfg(feature = "gateway")]
impl GatewayScheduler {
    /// A scheduler with nothing scheduled and nothing reported.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record what a node says it can take.
    ///
    /// If the node is currently scheduled and the new report says it cannot
    /// take work, it is de-scheduled **here** — before anything asks it to do
    /// anything. Returns the reason, if it was de-scheduled.
    pub fn record_capacity(
        &mut self,
        node_id: NodeId,
        report: CapacityReport,
    ) -> Option<DeScheduleReason> {
        self.reports.insert(node_id, report);
        match report.schedulability() {
            Ok(()) => None,
            Err(reason) => {
                self.de_schedule(node_id, reason);
                Some(reason)
            }
        }
    }

    /// Stop offering work to a node, for a stated reason.
    ///
    /// Idempotent, and it frees the concurrency slot. Returns whether the node
    /// had been scheduled.
    pub fn de_schedule(&mut self, node_id: NodeId, reason: DeScheduleReason) -> bool {
        self.de_scheduled_because.insert(node_id, reason);
        self.scheduled.remove(&node_id)
    }

    /// Offer work to a node, if it can take it and the pilot has room.
    ///
    /// Order is deliberate: what the *node* can do is checked before the
    /// gateway's own concurrency bound, so a node that cannot take work never
    /// consumes the single slot even for the duration of one refusal.
    pub fn try_schedule(&mut self, node_id: NodeId) -> Result<(), crate::error::TunnelError> {
        if self.scheduled.contains(&node_id) {
            return Ok(());
        }
        let report = self.reports.get(&node_id).copied().ok_or(
            crate::error::TunnelError::NodeNotSchedulable(DeScheduleReason::NoCapacityReport),
        )?;
        if let Err(reason) = report.schedulability() {
            self.de_scheduled_because.insert(node_id, reason);
            return Err(crate::error::TunnelError::NodeNotSchedulable(reason));
        }
        if self.scheduled.len() >= MAX_CONCURRENT_NODES {
            return Err(crate::error::TunnelError::SchedulerAtCapacity {
                max: MAX_CONCURRENT_NODES,
            });
        }
        self.scheduled.insert(node_id);
        self.de_scheduled_because.remove(&node_id);
        Ok(())
    }

    /// How many nodes are scheduled.
    #[inline]
    pub fn scheduled_count(&self) -> usize {
        self.scheduled.len()
    }

    /// Whether this node is scheduled.
    #[inline]
    pub fn is_scheduled(&self, node_id: &NodeId) -> bool {
        self.scheduled.contains(node_id)
    }

    /// Why this node was last de-scheduled, if it was.
    #[inline]
    pub fn de_schedule_reason(&self, node_id: &NodeId) -> Option<DeScheduleReason> {
        self.de_scheduled_because.get(node_id).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full(in_schedule: bool) -> CapacityReport {
        CapacityReport {
            remaining_daily_bytes: 10_000_000,
            throttle_bytes_per_sec: 1_000_000,
            in_schedule,
            streams_free: 4,
        }
    }

    /// **Mutations this detects:** raising the pilot's aggregate node bound
    /// without the gate that authorises it.
    #[test]
    fn max_concurrent_nodes_is_one_until_the_aggregate_ceiling_ships() {
        assert_eq!(
            MAX_CONCURRENT_NODES, 1,
            "the pilot's aggregate node bound moved. It is a safety control, not a placeholder: \
             per-node caps cannot bound a distributed layer-7 flood, and raising this is gated on \
             §1 criterion 5 — the global per-destination ceiling — which is not delivered"
        );
    }

    /// INV-11's capacity half.
    ///
    /// **Mutations this detects:** adding a hostname, address, allowlist entry
    /// or any other destination-identifying field to the structure that
    /// crosses the tunnel on every scheduling decision.
    #[test]
    fn a_capacity_report_carries_no_destination_identifying_field() {
        let report = full(true);
        // Exhaustive destructure: a fifth field is a compile error here.
        let CapacityReport {
            remaining_daily_bytes,
            throttle_bytes_per_sec,
            in_schedule,
            streams_free,
        } = report;
        assert_eq!(remaining_daily_bytes, 10_000_000);
        assert_eq!(throttle_bytes_per_sec, 1_000_000);
        assert!(in_schedule);
        assert_eq!(streams_free, 4);

        // Everything the report can say is a count, a rate or a flag, so the
        // whole of its rendered form is digits and field names.
        let rendered = format!("{report:?}");
        for token in ["remaining_daily_bytes", "throttle_bytes_per_sec"] {
            assert!(rendered.contains(token), "the render lost {token}");
        }
    }

    /// **Mutations this detects:** letting the throttle express the schedule
    /// window — the "de-scheduled, not throttled" rule, asserted across the
    /// whole range of the field rather than at one convenient value.
    #[test]
    fn a_node_out_of_schedule_is_de_scheduled_not_throttled() {
        for throttle in [0u64, 1, 64_000, u64::MAX] {
            let mut out = full(false);
            out.throttle_bytes_per_sec = throttle;
            assert_eq!(
                out.schedulability(),
                Err(DeScheduleReason::OutOfSchedule),
                "a node outside its window was schedulable at throttle {throttle}"
            );

            // Positive control: the same report inside the window is
            // schedulable at every one of those throttles, so the refusal is
            // the schedule bit's doing and the throttle plays no part.
            let mut inside = out;
            inside.in_schedule = true;
            assert_eq!(
                inside.schedulability(),
                Ok(()),
                "the throttle {throttle} took part in the scheduling decision"
            );
        }
    }

    /// **Mutations this detects:** ordering the ceiling check after the
    /// mechanical stream check, which would tell an operator whose day is
    /// spent that their slots are full.
    #[test]
    fn a_node_with_zero_remaining_bytes_is_de_scheduled_before_it_is_offered_work() {
        let mut spent = full(true);
        spent.remaining_daily_bytes = 0;
        assert_eq!(
            spent.schedulability(),
            Err(DeScheduleReason::DailyBytesExhausted)
        );
        assert!(!spent.is_schedulable());

        // Positive control: one byte left is still schedulable. The ceiling is
        // a ceiling, not a low-water mark.
        spent.remaining_daily_bytes = 1;
        assert_eq!(spent.schedulability(), Ok(()));

        // And the operator's own consent outranks their ceiling: a node that
        // is both out of schedule and spent is told about the window.
        let mut both = full(false);
        both.remaining_daily_bytes = 0;
        assert_eq!(both.schedulability(), Err(DeScheduleReason::OutOfSchedule));
    }

    /// **Mutations this detects:** a `streams_free` that does not come from
    /// the multiplexer, so the number the gateway schedules against is one the
    /// node asserted rather than one anything observed.
    #[test]
    fn streams_free_is_the_mux_headroom_and_zero_headroom_is_not_schedulable() {
        let mut mux = Mux::new();
        let report = CapacityReport::from_mux(&mux, 1_000, 1_000, true);
        assert_eq!(report.streams_free, mux.streams_free());
        assert_eq!(report.schedulability(), Ok(()));

        for id in 1..=crate::mux::MAX_CONCURRENT_STREAMS as u32 {
            mux.open(id).expect("fill the mux");
        }
        let full_mux = CapacityReport::from_mux(&mux, 1_000, 1_000, true);
        assert_eq!(full_mux.streams_free, 0);
        assert_eq!(
            full_mux.schedulability(),
            Err(DeScheduleReason::NoStreamsFree)
        );

        // Positive control: freeing one slot makes it schedulable again.
        mux.close(1).expect("close");
        assert_eq!(
            CapacityReport::from_mux(&mux, 1_000, 1_000, true).schedulability(),
            Ok(())
        );
    }

    /// **Mutations this detects:** collapsing two de-schedule causes onto one
    /// variant, which would let a refusal test pass against a scheduler that
    /// refuses everything for one stated reason.
    #[test]
    fn every_de_schedule_reason_is_a_distinct_comparable_variant() {
        let all = [
            DeScheduleReason::NoCapacityReport,
            DeScheduleReason::OutOfSchedule,
            DeScheduleReason::DailyBytesExhausted,
            DeScheduleReason::NoStreamsFree,
            DeScheduleReason::Halted,
            DeScheduleReason::HeartbeatStale,
        ];
        // Positive control: a variant equals itself.
        assert_eq!(all[0], all[0]);
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "reasons {i} and {j} compare equal");
                }
            }
        }
    }

    #[cfg(feature = "gateway")]
    mod gateway {
        use super::*;
        use crate::error::TunnelError;

        const NODE_A: NodeId = [0xAA; 32];
        const NODE_B: NodeId = [0xBB; 32];

        /// **Mutations this detects:** raising the concurrency bound, checking
        /// it with `>` instead of `>=`, or failing to free the slot on a
        /// de-schedule. The positive control — de-schedule the first, then the
        /// second is accepted — is what makes the refusal meaningful rather
        /// than the answer of a scheduler that refuses everything.
        #[test]
        fn the_scheduler_refuses_a_second_concurrent_node() {
            let mut sched = GatewayScheduler::new();
            assert_eq!(sched.record_capacity(NODE_A, full(true)), None);
            assert_eq!(sched.record_capacity(NODE_B, full(true)), None);

            sched.try_schedule(NODE_A).expect("the first node");
            assert_eq!(sched.scheduled_count(), 1);
            assert!(sched.is_scheduled(&NODE_A));

            for _ in 0..3 {
                assert_eq!(
                    sched.try_schedule(NODE_B),
                    Err(TunnelError::SchedulerAtCapacity {
                        max: MAX_CONCURRENT_NODES
                    })
                );
            }
            assert!(!sched.is_scheduled(&NODE_B));
            assert_eq!(sched.scheduled_count(), 1);

            // Re-scheduling the node that already holds the slot is not a
            // second node and is not refused.
            sched.try_schedule(NODE_A).expect("idempotent");
            assert_eq!(sched.scheduled_count(), 1);

            // The positive control.
            assert!(sched.de_schedule(NODE_A, DeScheduleReason::OutOfSchedule));
            assert_eq!(sched.scheduled_count(), 0);
            sched
                .try_schedule(NODE_B)
                .expect("the freed slot must be usable, or the refusal above proves nothing");
            assert!(sched.is_scheduled(&NODE_B));
        }

        /// **Mutations this detects:** de-scheduling only at assignment time,
        /// so a node whose ceiling ran out mid-window keeps its slot until
        /// something tries to give it work.
        #[test]
        fn a_node_whose_report_turns_unschedulable_loses_its_slot_at_report_time() {
            let mut sched = GatewayScheduler::new();
            sched.record_capacity(NODE_A, full(true));
            sched.try_schedule(NODE_A).expect("scheduled");
            assert_eq!(sched.scheduled_count(), 1);

            let mut spent = full(true);
            spent.remaining_daily_bytes = 0;
            assert_eq!(
                sched.record_capacity(NODE_A, spent),
                Some(DeScheduleReason::DailyBytesExhausted)
            );
            assert_eq!(sched.scheduled_count(), 0, "the slot was not freed");
            assert_eq!(
                sched.de_schedule_reason(&NODE_A),
                Some(DeScheduleReason::DailyBytesExhausted)
            );
            assert_eq!(
                sched.try_schedule(NODE_A),
                Err(TunnelError::NodeNotSchedulable(
                    DeScheduleReason::DailyBytesExhausted
                ))
            );

            // Positive control: a fresh healthy report schedules it again.
            sched.record_capacity(NODE_A, full(true));
            sched.try_schedule(NODE_A).expect("rescheduled");
            assert_eq!(sched.de_schedule_reason(&NODE_A), None);
        }

        /// **Mutations this detects:** scheduling a node the gateway has never
        /// heard a capacity report from — which is how an unknown node's
        /// consent, ceiling and schedule window all get assumed rather than
        /// read.
        #[test]
        fn a_node_with_no_capacity_report_is_never_scheduled() {
            let mut sched = GatewayScheduler::new();
            assert_eq!(
                sched.try_schedule(NODE_A),
                Err(TunnelError::NodeNotSchedulable(
                    DeScheduleReason::NoCapacityReport
                ))
            );
            assert_eq!(sched.scheduled_count(), 0);

            // Positive control: with a report, the same call succeeds.
            sched.record_capacity(NODE_A, full(true));
            sched.try_schedule(NODE_A).expect("with a report");
        }

        /// **Mutations this detects:** a de-schedule that does not free the
        /// slot on the second call, or one that forgets the reason it was
        /// given.
        #[test]
        fn de_scheduling_is_idempotent_and_records_the_reason_it_was_given() {
            let mut sched = GatewayScheduler::new();
            sched.record_capacity(NODE_A, full(true));
            sched.try_schedule(NODE_A).expect("scheduled");

            assert!(sched.de_schedule(NODE_A, DeScheduleReason::Halted));
            assert_eq!(
                sched.de_schedule_reason(&NODE_A),
                Some(DeScheduleReason::Halted)
            );
            // The second call reports that there was nothing to free, and does
            // not resurrect anything.
            assert!(!sched.de_schedule(NODE_A, DeScheduleReason::HeartbeatStale));
            assert_eq!(sched.scheduled_count(), 0);
            assert_eq!(
                sched.de_schedule_reason(&NODE_A),
                Some(DeScheduleReason::HeartbeatStale)
            );
        }
    }
}
