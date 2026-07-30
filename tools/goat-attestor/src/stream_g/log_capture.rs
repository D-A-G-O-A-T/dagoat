//! Test-only plumbing that makes `tracing`-asserting tests race-free.
//!
//! # Why this module exists
//!
//! Five sites in this crate assert on `tracing` output by installing a
//! *thread-local* subscriber with [`tracing::subscriber::set_default`] and then
//! reading a captured buffer. This list is the maintenance contract: a sixth
//! capture site must call [`install_interest_keepalive`] too, or it inherits
//! the race described below.
//!
//! * `http_error::tests::stream_g_error_bodies_carry_the_code_and_nothing_else`
//! * `http_error::tests::extractor_rejection_detail_goes_to_tracing_not_to_the_client`
//! * `stream_g::tests::no_metric_or_log_surface_carries_payload_bytes`
//! * `quotes::tests::a_newline_in_a_caller_hex_field_cannot_forge_a_log_line`
//! * every `submit.rs` test that goes through `submit::tests::capture_logs`
//!
//! (Named by test, not by line: these lists rotted three times before this
//! comment was written, once per file that grew above them.)
//!
//! A thread-local subscriber does *not* give a thread-local view of whether an
//! event fires. `tracing` caches one `Interest` per **callsite**, process-wide,
//! and that cache is computed exactly once — the first time that source line
//! executes anywhere in the process. `tracing-core-0.1.36`
//! `src/callsite.rs:308` (`DefaultCallsite::register`) computes it as:
//!
//! ```text
//! rebuild_callsite_interest(self, &DISPATCHERS.rebuilder())
//! ```
//!
//! and `Dispatchers::rebuilder` (`src/callsite.rs:544`) returns
//! `Rebuilder::JustOne` while at most one dispatcher is registered, whose
//! `for_each` (`src/callsite.rs:565`) consults `dispatcher::get_default` — the
//! **registering thread's** current subscriber. With no subscriber on that
//! thread that is `NoSubscriber`, which answers `Interest::never()`
//! (`src/subscriber.rs:676`), and `rebuild_callsite_interest`
//! (`src/callsite.rs:490`) writes that verdict into the process-wide cache.
//!
//! So when a test with no subscriber wins the race to be the first to execute
//! `ApiError::into_response`'s `tracing::warn!` (`src/stream_g/http_error.rs:257`),
//! that callsite is cached as "never interested" and is silently skipped
//! afterwards — including inside the guard of a test that *is* capturing. The
//! capture buffer comes back empty and the assertion fails with no other
//! symptom. Measured on this crate before the fix: **6 failures in 30 full
//! `cargo test --lib` runs (20%)**, always
//! `extractor_rejection_detail_goes_to_tracing_not_to_the_client`, always with
//! an empty log; the same test run alone passed 40/40. A diagnostic build
//! confirmed the mechanism precisely: at the moment of failure
//! `LevelFilter::current()` was still `INFO` (so it is *not* the max-level
//! hint collapsing) and a canary `tracing::warn!` emitted from inside the same
//! guard — a callsite first registered on the capturing thread — *was*
//! recorded while the `into_response` callsite was not. Per-callsite, not
//! per-level: the interest cache.
//!
//! # The fix
//!
//! [`install_interest_keepalive`] installs a process-wide global subscriber
//! that is interested in everything ([`Interest::sometimes`]) and enables
//! nothing ([`Subscriber::enabled`] is always `false`). It makes
//! `Interest::never()` unreachable for every callsite in the test binary:
//!
//! * It is registered through `Dispatch::new`, and `set_global_default`
//!   (`tracing-core-0.1.36 src/dispatcher.rs:299`) leaks the `Arc`, so its
//!   entry in the dispatcher registry is immortal. Every later
//!   `Rebuilder::Read` union therefore contains it and can never be the empty
//!   union that `rebuild_callsite_interest` turns into `Interest::never()`.
//! * While `Rebuilder::JustOne` is still in force (only the keepalive is
//!   registered) no thread can have a scoped default yet — installing one goes
//!   through `Dispatch::new`, which pushes a second registrar first — so
//!   `get_default` returns the keepalive and answers `sometimes`.
//! * Registering it re-runs `Callsites::rebuild_interest` over every callsite
//!   already in the registry, repairing any that a subscriber-less thread had
//!   already poisoned.
//!
//! `Interest::sometimes` is the load-bearing choice: it forces `tracing` to ask
//! the *current* dispatcher's `enabled` at event time, so each capturing test
//! still gets exactly its own subscriber's filtering, and threads with no
//! subscriber pay one `enabled` call that returns `false` and record nothing.
//! Returning `Interest::always` instead would push events at capture
//! subscribers past their own level filter; returning `Interest::never` would
//! reintroduce the bug.
//!
//! This is deliberately *not* a mutex around the capturing tests: the thread
//! that poisons the callsite is any one of the ~630 tests that renders an
//! `ApiError`, not another capturing test, so serialising the four capturing
//! tests would not have closed the race.

use std::sync::Once;

use tracing::level_filters::LevelFilter;
use tracing::span;
use tracing::subscriber::Interest;
use tracing::{Event, Metadata, Subscriber};

/// The process-wide global subscriber described in the module docs: interested
/// in every callsite, enabling none of them.
///
/// Modelled on `tracing_core::subscriber::NoSubscriber`
/// (`tracing-core-0.1.36 src/subscriber.rs:674`) with two deliberate
/// differences — `register_callsite` answers `sometimes` instead of `never`,
/// and `max_level_hint` answers `TRACE` so the global max-level hint can never
/// gate an event out from under a capturing test either.
#[derive(Debug)]
struct InterestKeepalive;

impl Subscriber for InterestKeepalive {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::TRACE)
    }

    fn enabled(&self, _: &Metadata<'_>) -> bool {
        false
    }

    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        // `Id::from_u64` panics on zero; the value is otherwise arbitrary
        // because this subscriber never stores span data.
        span::Id::from_u64(0xDEAD)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, _: &Event<'_>) {}

    fn enter(&self, _: &span::Id) {}

    fn exit(&self, _: &span::Id) {}
}

static KEEPALIVE: Once = Once::new();

/// Install the keepalive subscriber, once per test process.
///
/// Call this *before* building a capture subscriber in any test that asserts on
/// `tracing` output. Idempotent and cheap after the first call. The
/// `set_global_default` result is ignored on purpose: the only way it can fail
/// is that a global subscriber already exists, and any global subscriber at all
/// is enough to keep `Interest::never()` off the callsites this crate asserts
/// on.
pub(crate) fn install_interest_keepalive() {
    KEEPALIVE.call_once(|| {
        let _ = tracing::subscriber::set_global_default(InterestKeepalive);
    });
}
