//! The operator-visible liveness indicator, as a **gate**.
//!
//! # Why a stale indicator closes egress
//!
//! INV-20 says every egress is visible to the operator. A visibility promise
//! that keeps its promise only while the surface happens to be running is not a
//! promise; so the indicator is not a light the daemon switches on, it is a
//! **freshness stamp the daemon requires** before it will evaluate a request.
//! When nothing has refreshed it inside [`INDICATOR_TTL_SECS`], egress closes.
//!
//! The direction is the one that costs: it fails **closed**. A default of "live"
//! would make this a control that reads as present and is not — the exact shape
//! the `robots` / `budget` / `indicator` seams were left absent rather than
//! stubbed to avoid. [`Indicator::new`] therefore starts **not live**, and a
//! sidecar that nobody ever told to go live refuses every request.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Tasks 31-33 (the `indicator` seam in `EgressPolicy::evaluate`) and its
//! Security invariants section (INV-20).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// How long a liveness stamp is good for.
///
/// INV-20's shipped claim is that the operator surface reconciles at 3 s. This
/// is deliberately longer than that so an ordinary refresh cycle never closes
/// egress, and deliberately short enough that a surface which has stopped
/// refreshing is noticed within seconds rather than minutes.
pub const INDICATOR_TTL_SECS: u64 = 10;

/// A liveness flag with an expiry, plus the sticky kill switch.
#[derive(Debug)]
pub struct Indicator {
    live: AtomicBool,
    stamped_at_unix: AtomicU64,
    /// One way. Once engaged this is never cleared, and no heartbeat, restamp
    /// or `set_live(true, ..)` can re-open the gate — a kill switch that can be
    /// un-engaged from inside the process it kills is not a kill switch.
    halted: AtomicBool,
}

impl Default for Indicator {
    fn default() -> Self {
        Self::new()
    }
}

impl Indicator {
    /// **Not live.** See the module header: a default of live is a gate that is
    /// not a gate.
    pub fn new() -> Self {
        Self {
            live: AtomicBool::new(false),
            stamped_at_unix: AtomicU64::new(0),
            halted: AtomicBool::new(false),
        }
    }

    /// Set the flag and stamp it. Called by whatever owns the operator surface.
    pub fn set_live(&self, live: bool, now_unix: u64) {
        self.live.store(live, Ordering::SeqCst);
        self.stamped_at_unix.store(now_unix, Ordering::SeqCst);
    }

    /// When the flag was last stamped.
    pub fn stamped_at_unix(&self) -> u64 {
        self.stamped_at_unix.load(Ordering::SeqCst)
    }

    /// Engage the kill switch. One way.
    ///
    /// Clears liveness in the same move, so the gate closes on the next
    /// evaluation rather than at the next expiry.
    pub fn engage_kill_switch(&self) {
        self.halted.store(true, Ordering::SeqCst);
        self.live.store(false, Ordering::SeqCst);
    }

    /// Whether the kill switch has been engaged. Never returns to `false`.
    pub fn is_halted(&self) -> bool {
        self.halted.load(Ordering::SeqCst)
    }

    /// Live **and** stamped inside the TTL **and** not halted.
    ///
    /// A stamp in the future is not fresh either: a clock that moved backwards
    /// would otherwise buy an unbounded extension.
    pub fn is_fresh(&self, now_unix: u64) -> bool {
        if self.is_halted() {
            return false;
        }
        if !self.live.load(Ordering::SeqCst) {
            return false;
        }
        let stamped = self.stamped_at_unix();
        if stamped == 0 || stamped > now_unix {
            return false;
        }
        now_unix - stamped <= INDICATOR_TTL_SECS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutations this detects: `AtomicBool::new(true)` in `new`, which is a gate
    /// that opens before anybody has said anything; the freshness check reduced
    /// to reading the flag, which makes the stamp decorative.
    #[test]
    fn a_fresh_indicator_is_required_and_starts_closed() {
        let i = Indicator::new();
        assert!(
            !i.is_fresh(1_000),
            "a brand-new indicator must not be fresh"
        );

        // POSITIVE CONTROL: stamped live, it is fresh.
        i.set_live(true, 1_000);
        assert!(i.is_fresh(1_000));
        assert!(i.is_fresh(1_000 + INDICATOR_TTL_SECS));

        // One second past the TTL: stale.
        assert!(!i.is_fresh(1_000 + INDICATOR_TTL_SECS + 1));

        // Explicitly set not-live: stale even at the same instant.
        i.set_live(false, 2_000);
        assert!(!i.is_fresh(2_000));

        // A stamp in the FUTURE is not freshness.
        i.set_live(true, 9_000);
        assert!(!i.is_fresh(8_000));
    }

    /// INV-10's indicator half.
    ///
    /// Mutations this detects: `engage_kill_switch` writing only the liveness
    /// flag, which the very next `set_live(true, ..)` undoes; `is_fresh`
    /// reading the stamp before the halt flag, so a halted daemon stays open
    /// until the TTL expires; `halted` cleared anywhere.
    #[test]
    fn kill_switch_is_sticky_and_clears_liveness() {
        let i = Indicator::new();

        // POSITIVE CONTROL: the gate really does open before it is killed.
        i.set_live(true, 1_000);
        assert!(i.is_fresh(1_000));
        assert!(!i.is_halted());

        i.engage_kill_switch();
        assert!(i.is_halted());
        assert!(!i.is_fresh(1_000), "a halted indicator reported freshness");

        // A heartbeat cannot re-open it, at any time, ever.
        i.set_live(true, 1_000);
        assert!(i.is_halted(), "the kill switch was cleared by a heartbeat");
        assert!(!i.is_fresh(1_000));
        i.set_live(true, 1_000_000);
        assert!(!i.is_fresh(1_000_000));
        assert!(i.is_halted());
    }
}
