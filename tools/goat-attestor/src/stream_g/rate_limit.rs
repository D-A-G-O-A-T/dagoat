//! Stream G's rate limiter — **not** `crate::rate_limit`.
//!
//! # Status: live on eight of the ten mounted routes, and nowhere else
//!
//! Wave B1 gave this module its first production callers. All three checks run
//! in `profile_auth`'s extractors — [`StreamGRateLimiter::check_registration`]
//! in `profile_auth::RegistrationRateLimit`,
//! [`StreamGRateLimiter::check_global`] in `profile_auth::GlobalRateLimit`
//! (which `profile_auth::PresentedOrigin` delegates to, so there is exactly one
//! place a global token is spent) and [`StreamGRateLimiter::check_profile`] in
//! `profile_auth::AuthenticatedProfile`, in that order.
//!
//! Every request to `POST /v1/profile/challenges`,
//! `POST /v1/profile/sessions`, `DELETE /v1/profile/sessions/:id`,
//! `GET /v1/profile/primary-onboarding/:intentId`,
//! `POST /v1/stream-g/quotes`, `POST /v1/stream-g/submit` and
//! `GET /v1/stream-g/status/:intentId` spends a
//! global token, and every *authenticated* one — every route taking
//! `profile_auth::AuthenticatedProfile`, i.e. all of those but
//! `POST /v1/profile/sessions` — also spends a per-profile token.
//! `POST /v1/profile` spends **neither**; it spends a registration token, and
//! the next section is why.
//!
//! The last three arrived with the pipeline surface (🔴 `submit` in Wave C W4)
//! and are covered for the
//! structural reason rather than by a second registration: they take
//! `profile_auth::AuthenticatedProfile` as an extractor, and that extractor is
//! where [`StreamGRateLimiter::check_profile`] runs, so a `/v1/stream-g/`
//! route cannot be authenticated and unlimited at the same time. That matters
//! most for `POST /v1/stream-g/submit`, the one route whose requests can spend
//! the broadcaster EOA's ETH.
//!
//! # Why registration has a budget of its own
//!
//! `POST /v1/profile` is unauthenticated by necessity — it issues the
//! credential the others authenticate with — and
//! [`StreamGRateLimiter::check_profile`] takes an `AuthenticatedProfileId`,
//! which does not exist at profile-creation time. So it cannot be bounded by
//! the per-caller bucket, and until this change it spent the **global** one
//! instead.
//!
//! That was a starvation channel rather than a bound. Both checks run inside
//! extractors, and [`STREAM_G_GLOBAL_PER_MIN`] is one process-wide budget every
//! authenticated route spends from *first* (`profile_auth::AuthenticatedProfile`
//! → `profile_auth::PresentedOrigin` → `profile_auth::GlobalRateLimit`, before
//! any credential is read). One unauthenticated client at ~2 req/s to
//! `POST /v1/profile` therefore kept that bucket empty and every authenticated
//! caller — holding a perfectly valid credential — got 429 from the extractor
//! before authentication was even attempted.
//!
//! [`STREAM_G_REGISTRATION_PER_MIN`] is a separate bucket, so draining it can
//! refuse only more registrations. The two budgets never touch:
//! `tests::draining_registration_leaves_the_global_budget_alone` and
//! `profile_auth::tests::exhausting_registration_does_not_429_an_authenticated_route`
//! are what make re-pointing `post_profile` at `check_global` a failing test
//! rather than a silent regression.
//!
//! ## What this does *not* close, stated rather than implied
//!
//! Splitting the budget removes `POST /v1/profile` as a starvation lever. It
//! does **not** make the global bucket unreachable without a credential,
//! because the global token is still spent *before* authentication on every
//! route that requires one: `profile_auth::AuthenticatedProfile` calls
//! [`StreamGRateLimiter::check_global`] (through
//! `profile_auth::PresentedOrigin`) and only then reads the `Authorization`
//! header. An unauthenticated flood at `POST /v1/profile/challenges` — no
//! header at all, every response a 401 — therefore drains the same bucket at
//! the same rate, and `POST /v1/profile/sessions` is unauthenticated outright
//! (it spends its token in the extractor, before the challenge/nonce pair in
//! the body is checked).
//!
//! That ordering is not a mistake to be fixed here: a bucket consulted *after*
//! authentication cannot bound the cost of authentication itself, which is a
//! store read plus an HMAC. The residual is genuinely the one the
//! DEPLOYMENT REQUIREMENT below covers — it needs a per-source bound, which
//! this process cannot compute — so this section must not be read as "the
//! starvation channel is closed". One route's version of it is.
//!
//! # DEPLOYMENT REQUIREMENT: per-IP limiting is not done here
//!
//! Stated because the buckets above are easy to mistake for a perimeter and
//! they are not one. **This crate has no per-IP bound of any kind** —
//! `grep -rn 'governor\|per_ip\|ConnectInfo\|x-forwarded-for' src/` finds
//! nothing, and neither the socket address nor any forwarding header is read
//! anywhere in the request path. Every bucket here is either process-wide
//! (global, registration) or keyed on a *server-issued* profile id, so a single
//! unauthenticated host can still consume the whole registration budget, and a
//! distributed source is indistinguishable from a single one.
//!
//! An operator running this process on a public network is therefore required
//! to place a reverse proxy in front of it that enforces a per-source-IP rate
//! and connection limit. Nothing in this crate can detect that the requirement
//! was skipped; the residual is deployment-shaped, not code-shaped.
//!
//! **Nothing else is rate-limited.** The two remaining mounted routes,
//! `GET /v1/stream-g/ready` and `GET /v1/stream-g/metrics`, use neither
//! extractor and are not bounded by this limiter. Stating that here
//! rather than letting the module's existence imply a perimeter:
//! `grep -rn 'check_global\|check_profile\|check_registration' src/` is the
//! check, and the extractors it finds are the whole of the enforcement.
//!
//! # The key, and why
//!
//! **The per-caller key is the authenticated profile id**, because it is
//! server-issued: an attacker cannot mint unbounded distinct keys without
//! first passing authentication, which is exactly the property the pilot's
//! caller-supplied `wallet` string lacks.
//!
//! That is enforced by the type, not by a convention.
//! [`StreamGRateLimiter::check_profile`] takes
//! `&profile_auth::AuthenticatedProfileId`, whose inner `String` is private
//! and which has exactly two production mint points
//! (`profile_auth::authenticate_credential` and
//! `profile_auth::validate_session`). There is no way to call it with a
//! profile id read out of a request body or a path segment, so "key **after**
//! validation" cannot be got wrong by a future route the way it can with a
//! `&str` parameter.
//!
//! # The defect this does not reproduce
//!
//! `crate::rate_limit::RateLimiter::check` is called from `relay_bind` /
//! `relay_enroll` / `relay_gas_drip` as step 1, **before**
//! `validate_bind_request` (`relayer.rs:493-499`), keyed on
//! `req.wallet.to_ascii_lowercase()` — any bytes the caller sent. Its
//! `wallets: HashMap<String, Bucket>` has no bound and no eviction, so a
//! single unauthenticated client can grow it without limit by varying that
//! field. Two changes here:
//!
//! 1. the per-caller bucket is keyed on a value the caller cannot choose
//!    (above), and
//! 2. the map is bounded by [`MAX_TRACKED_PROFILES`], with
//!    [`StreamGRateLimitError::TrackingCapacity`] rather than growth when the
//!    bound is reached.
//!
//! The pre-authentication traffic that has no key at all is handled by
//! [`StreamGRateLimiter::check_global`] and
//! [`StreamGRateLimiter::check_registration`], one bucket each — O(1) memory,
//! so both are safe to consult before anything about the request has been
//! validated.
//!
//! ## What capacity-exhaustion costs, stated plainly
//!
//! Refusing at the bound is the fail-closed direction and it is not free: a
//! caller who controls [`MAX_TRACKED_PROFILES`] *authenticated* profiles and
//! keeps every one of their buckets drained can make new profiles see
//! `TrackingCapacity` until a bucket refills. The alternative — evicting some
//! other profile's partially-drained bucket to make room — hands the evicted
//! key a full bucket back, i.e. lets an attacker reset other callers' limits,
//! which is worse. Fully-refilled buckets *are* evicted first
//! ([`StreamGRateLimiter::prune_refilled`]): a bucket at capacity is
//! observationally identical to an absent one, so dropping it costs nothing.
//!
//! # Restart resets the buckets
//!
//! Same residual as the pilot's (`crate::rate_limit`'s module doc): these are
//! in-memory token buckets, so a process restart hands everyone a full one.
//! Nothing here is a durable spend bound.

use std::collections::HashMap;
use std::time::Instant;

use thiserror::Error;

use super::profile_auth::AuthenticatedProfileId;

/// Requests per minute across all callers, authenticated or not.
///
/// Matches `crate::rate_limit::DEFAULT_GLOBAL_PER_MIN`. Deliberately the same
/// number: Stream G's routes are strictly more expensive per call than the
/// pilot's (a quote costs several `eth_call`s and an EIP-712 signature), so
/// there is no argument for a *looser* global bound, and inventing a tighter
/// one without a measurement would be a number pulled out of the air.
pub const STREAM_G_GLOBAL_PER_MIN: u32 = 120;

/// Requests per minute for `POST /v1/profile`, and **only** that route.
///
/// Deliberately not [`STREAM_G_GLOBAL_PER_MIN`] and deliberately much tighter,
/// on three grounds that are about registration specifically rather than about
/// picking a smaller number:
///
/// 1. **An honest client calls it once.** `create_profile` mints a
///    single-disclosure credential a caller then keeps; there is no legitimate
///    client loop that registers repeatedly. Even a fleet onboarding several
///    devices at once is a handful of calls, not a sustained rate. 10/min is a
///    burst of ten plus one every six seconds sustained — an order of magnitude
///    above any first-run pattern and an order of magnitude below the global
///    figure.
/// 2. **It is the only bucket whose spend leaves durable state behind.** Every
///    accepted call writes a `profiles` row that is never garbage-collected.
///    At 10/min that is ~14,400 rows/day worst case, a number an operator can
///    reason about; at the global figure it would be ~172,800.
/// 3. **Nothing legitimate is starved by getting this wrong low.** A refused
///    registration is retried seconds later by a client that has not yet
///    invested anything; a refused *authenticated* request interrupts work in
///    progress. When the two budgets have to be sized against each other, the
///    asymmetry says spend the generosity on the authenticated side.
///
/// The figure is a policy choice, not a measurement, and is stated as such —
/// same honesty as [`STREAM_G_GLOBAL_PER_MIN`]'s own doc.
pub const STREAM_G_REGISTRATION_PER_MIN: u32 = 10;

/// Requests per minute per authenticated profile. Matches
/// `crate::rate_limit::DEFAULT_WALLET_PER_MIN`, for the same reason.
pub const STREAM_G_PROFILE_PER_MIN: u32 = 30;

/// Hard bound on distinct profiles tracked at once — the thing the pilot's
/// limiter does not have.
///
/// At 4096 entries the map costs on the order of a few hundred kilobytes
/// (a `String` profile id plus a 4-field bucket each), which is a bound an
/// operator can reason about, and it is comfortably above any plausible
/// concurrent-profile count for a pilot deployment.
pub const MAX_TRACKED_PROFILES: usize = 4096;

pub const ERR_RATE_LIMITED_GLOBAL: &str = "RATE_LIMITED_GLOBAL";
/// Distinct from [`ERR_RATE_LIMITED_GLOBAL`] on purpose: the two budgets are
/// separate, so a caller that cannot tell them apart cannot tell whether
/// backing off will help. It is also not an oracle — it reports only which of
/// this caller's own requests was refused, and names nothing stored.
pub const ERR_RATE_LIMITED_REGISTRATION: &str = "RATE_LIMITED_REGISTRATION";
pub const ERR_RATE_LIMITED_PROFILE: &str = "RATE_LIMITED_PROFILE";
pub const ERR_RATE_LIMIT_CAPACITY: &str = "RATE_LIMIT_CAPACITY_EXHAUSTED";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StreamGRateLimitError {
    #[error("global request rate limit exceeded")]
    Global,
    /// The `POST /v1/profile` budget only — see
    /// [`STREAM_G_REGISTRATION_PER_MIN`] and the module doc's "Why registration
    /// has a budget of its own".
    #[error("registration request rate limit exceeded")]
    Registration,
    #[error("per-profile request rate limit exceeded")]
    Profile,
    /// [`MAX_TRACKED_PROFILES`] distinct profiles are already being tracked
    /// and none of their buckets has refilled. See the module doc for why
    /// this refuses rather than evicting.
    #[error("rate-limiter tracking capacity exhausted ({MAX_TRACKED_PROFILES} profiles)")]
    TrackingCapacity,
}

impl StreamGRateLimitError {
    pub fn code(&self) -> &'static str {
        match self {
            StreamGRateLimitError::Global => ERR_RATE_LIMITED_GLOBAL,
            StreamGRateLimitError::Registration => ERR_RATE_LIMITED_REGISTRATION,
            StreamGRateLimitError::Profile => ERR_RATE_LIMITED_PROFILE,
            StreamGRateLimitError::TrackingCapacity => ERR_RATE_LIMIT_CAPACITY,
        }
    }

    /// HTTP status for the shared Stream G error envelope
    /// (`super::http_error`). Wildcard-free on purpose — see
    /// [`super::base_fee::BaseFeeError::status`].
    ///
    /// [`StreamGRateLimitError::TrackingCapacity`] is **503, not 429**: 429
    /// says "you are asking too often", which is a statement about the
    /// caller, and this refusal is not about the caller at all — the caller
    /// may be making its very first request. 503 says "this server cannot
    /// take the request right now", which is exactly what happened.
    pub fn status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            StreamGRateLimitError::Global
            | StreamGRateLimitError::Registration
            | StreamGRateLimitError::Profile => StatusCode::TOO_MANY_REQUESTS,
            StreamGRateLimitError::TrackingCapacity => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// A token bucket. Same arithmetic as `crate::rate_limit::Bucket`, which is
/// private to that module; duplicated rather than made `pub(crate)` because
/// this wave's task scope is the Stream G surface and widening a pilot type's
/// visibility is a change to the pilot.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
    capacity: f64,
    refill_per_sec: f64,
}

impl Bucket {
    fn new(per_min: u32, now: Instant) -> Self {
        let cap = f64::from(per_min);
        Self {
            tokens: cap,
            last: now,
            capacity: cap,
            refill_per_sec: f64::from(per_min) / 60.0,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.last = now;
        }
    }

    /// Refill, then take one token if there is one.
    fn try_take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// True when this bucket is back at capacity — i.e. carries no
    /// information a fresh bucket would not.
    fn is_refilled(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= self.capacity
    }
}

/// Two keyless buckets — global and registration — plus a bounded map of
/// per-profile buckets.
#[derive(Debug)]
pub struct StreamGRateLimiter {
    global: Bucket,
    /// `POST /v1/profile` only. A **separate** `Bucket` value rather than a
    /// share of `global`, which is the entire point: see the module doc's "Why
    /// registration has a budget of its own".
    registration: Bucket,
    profiles: HashMap<String, Bucket>,
    profile_per_min: u32,
    max_tracked: usize,
}

impl StreamGRateLimiter {
    pub fn new(
        global_per_min: u32,
        registration_per_min: u32,
        profile_per_min: u32,
        max_tracked: usize,
    ) -> Self {
        let now = Instant::now();
        Self {
            global: Bucket::new(global_per_min, now),
            registration: Bucket::new(registration_per_min, now),
            profiles: HashMap::new(),
            profile_per_min,
            max_tracked,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(
            STREAM_G_GLOBAL_PER_MIN,
            STREAM_G_REGISTRATION_PER_MIN,
            STREAM_G_PROFILE_PER_MIN,
            MAX_TRACKED_PROFILES,
        )
    }

    /// The pre-authentication bound. Keyed on nothing, so it costs O(1)
    /// memory no matter what a caller sends; safe to consult as the first
    /// thing a handler does.
    pub fn check_global(&mut self, now: Instant) -> Result<(), StreamGRateLimitError> {
        if self.global.try_take(now) {
            Ok(())
        } else {
            Err(StreamGRateLimitError::Global)
        }
    }

    /// The `POST /v1/profile` bound. Also keyless and O(1), for the same
    /// reason [`Self::check_global`] is — registration happens before any
    /// server-issued identifier exists, so there is nothing safe to key on.
    ///
    /// A route must spend **this or** [`Self::check_global`], never both:
    /// spending both would put unauthenticated registration back into the
    /// budget every authenticated route depends on, which is the starvation
    /// channel this method exists to close.
    pub fn check_registration(&mut self, now: Instant) -> Result<(), StreamGRateLimitError> {
        if self.registration.try_take(now) {
            Ok(())
        } else {
            Err(StreamGRateLimitError::Registration)
        }
    }

    /// The per-caller bound. Takes a proven profile id — see the module doc.
    pub fn check_profile(
        &mut self,
        profile: &AuthenticatedProfileId,
        now: Instant,
    ) -> Result<(), StreamGRateLimitError> {
        let key = profile.as_str();
        if !self.profiles.contains_key(key) {
            if self.profiles.len() >= self.max_tracked {
                self.prune_refilled(now);
            }
            if self.profiles.len() >= self.max_tracked {
                return Err(StreamGRateLimitError::TrackingCapacity);
            }
            self.profiles
                .insert(key.to_string(), Bucket::new(self.profile_per_min, now));
        }
        let bucket = self.profiles.get_mut(key).expect("inserted above");
        if bucket.try_take(now) {
            Ok(())
        } else {
            Err(StreamGRateLimitError::Profile)
        }
    }

    /// Drop every bucket that is back at capacity. Such a bucket permits
    /// exactly what a freshly created one would, so forgetting it changes no
    /// caller's allowance — this is reclamation, not eviction.
    fn prune_refilled(&mut self, now: Instant) {
        self.profiles.retain(|_, b| !b.is_refilled(now));
    }

    /// How many profiles are currently tracked. Exposed so a route (or a
    /// test) can observe the bound instead of assuming it.
    pub fn tracked_profiles(&self) -> usize {
        self.profiles.len()
    }
}

impl Default for StreamGRateLimiter {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn profile(n: usize) -> AuthenticatedProfileId {
        AuthenticatedProfileId::for_test(format!("profile-{n}"))
    }

    /// The global bucket refuses past its capacity and refills with time.
    #[test]
    fn the_global_bucket_bounds_unauthenticated_traffic() {
        let mut rl = StreamGRateLimiter::new(2, 100, 100, 16);
        let t0 = Instant::now();
        rl.check_global(t0).unwrap();
        rl.check_global(t0).unwrap();
        assert_eq!(rl.check_global(t0), Err(StreamGRateLimitError::Global));
        // Paired arm: a minute later it is open again, so the refusal above
        // is a rate bound and not a permanent close.
        rl.check_global(t0 + Duration::from_secs(61)).unwrap();
    }

    /// Per-profile buckets are independent, and draining one does not drain
    /// another.
    #[test]
    fn per_profile_buckets_are_independent() {
        let mut rl = StreamGRateLimiter::new(1000, 1000, 1, 16);
        let t0 = Instant::now();
        rl.check_profile(&profile(1), t0).unwrap();
        assert_eq!(
            rl.check_profile(&profile(1), t0),
            Err(StreamGRateLimitError::Profile)
        );
        rl.check_profile(&profile(2), t0).unwrap();
    }

    /// **The pilot's defect, not reproduced.** The tracked-profile map is
    /// bounded: past [`MAX_TRACKED_PROFILES`] it refuses rather than growing.
    ///
    /// `crate::rate_limit::RateLimiter` has no equivalent — its `wallets` map
    /// grows once per distinct caller-supplied string, forever.
    ///
    /// Mutation this detects: deleting the `TrackingCapacity` guard from
    /// `check_profile` (the map then grows to 9 and the length assertion
    /// fails).
    #[test]
    fn the_tracked_profile_map_is_bounded_rather_than_unbounded() {
        const MAX: usize = 8;
        let mut rl = StreamGRateLimiter::new(100_000, 100_000, 1, MAX);
        let t0 = Instant::now();

        // Fill and drain every slot, so nothing is prunable.
        for i in 0..MAX {
            rl.check_profile(&profile(i), t0).unwrap();
        }
        assert_eq!(rl.tracked_profiles(), MAX);

        // One more distinct profile is refused, and — the point — is not
        // recorded.
        assert_eq!(
            rl.check_profile(&profile(MAX), t0),
            Err(StreamGRateLimitError::TrackingCapacity)
        );
        assert_eq!(
            rl.tracked_profiles(),
            MAX,
            "a refused profile was still tracked — the map is not actually bounded"
        );

        // Paired non-zero arm: an already-tracked profile is unaffected by
        // the capacity refusal (it takes the `contains_key` fast path), so the
        // bound does not turn into a total outage for existing callers.
        assert_eq!(
            rl.check_profile(&profile(0), t0),
            Err(StreamGRateLimitError::Profile),
            "profile 0 is drained, not evicted"
        );
    }

    /// A refilled bucket is reclaimed to make room, because it grants exactly
    /// what a fresh one would.
    ///
    /// Mutation this detects: removing the `prune_refilled` call from
    /// `check_profile` — the new profile then gets `TrackingCapacity` even
    /// though every tracked bucket is idle.
    #[test]
    fn refilled_buckets_are_reclaimed_before_the_bound_refuses() {
        const MAX: usize = 4;
        let mut rl = StreamGRateLimiter::new(100_000, 100_000, 1, MAX);
        let t0 = Instant::now();
        for i in 0..MAX {
            rl.check_profile(&profile(i), t0).unwrap();
        }
        assert_eq!(rl.tracked_profiles(), MAX);

        // Immediately, nothing has refilled: the bound bites.
        assert_eq!(
            rl.check_profile(&profile(MAX), t0),
            Err(StreamGRateLimitError::TrackingCapacity)
        );

        // A minute later every bucket is back at capacity, so they are
        // reclaimed and the new profile is admitted.
        let t1 = t0 + Duration::from_secs(61);
        rl.check_profile(&profile(MAX), t1).unwrap();
        assert_eq!(
            rl.tracked_profiles(),
            1,
            "the four idle buckets should have been reclaimed, leaving only the new one"
        );
    }

    /// The global and per-profile bounds are separate budgets: draining the
    /// global one does not touch a profile's, and vice versa. A route is
    /// expected to consult both (global first, profile after
    /// authentication), spending one token from each.
    #[test]
    fn the_two_budgets_are_independent() {
        let mut rl = StreamGRateLimiter::new(1, 1, 1, 16);
        let t0 = Instant::now();
        rl.check_global(t0).unwrap();
        assert_eq!(rl.check_global(t0), Err(StreamGRateLimitError::Global));
        // The profile budget is untouched by the global refusal.
        rl.check_profile(&profile(1), t0).unwrap();
        assert_eq!(
            rl.check_profile(&profile(1), t0),
            Err(StreamGRateLimitError::Profile)
        );
    }

    /// **The starvation channel, at the limiter level.** Registration and the
    /// global budget are two `Bucket` values, so emptying the one an
    /// unauthenticated caller can reach leaves the one every authenticated
    /// route spends from completely full.
    ///
    /// The route-level half of this is
    /// `profile_auth::tests::exhausting_registration_does_not_429_an_authenticated_route`;
    /// this arm pins the arithmetic so a failure there is unambiguous about
    /// which layer broke.
    ///
    /// Mutation this detects: making `check_registration` delegate to
    /// `self.global.try_take(now)` — the `check_global` assertions below then
    /// see an empty bucket and fail.
    #[test]
    fn draining_registration_leaves_the_global_budget_alone() {
        const REGISTRATIONS: u32 = 3;
        let mut rl = StreamGRateLimiter::new(2, REGISTRATIONS, 1, 16);
        let t0 = Instant::now();

        for _ in 0..REGISTRATIONS {
            rl.check_registration(t0).unwrap();
        }
        assert_eq!(
            rl.check_registration(t0),
            Err(StreamGRateLimitError::Registration),
            "the registration budget must actually bound registration"
        );

        // The point: the global budget never noticed.
        rl.check_global(t0).unwrap();
        rl.check_global(t0).unwrap();
        assert_eq!(
            rl.check_global(t0),
            Err(StreamGRateLimitError::Global),
            "the global bucket held exactly its own 2 tokens, so registration spent none of them"
        );

        // Paired arm in the other direction: a drained global budget does not
        // close registration either, once it has refilled.
        rl.check_registration(t0 + Duration::from_secs(61)).unwrap();
    }

    /// The four verdicts carry distinct codes and the statuses the module
    /// doc claims.
    #[test]
    fn rate_limit_verdicts_map_to_429_and_503() {
        use axum::http::StatusCode;
        assert_eq!(
            StreamGRateLimitError::Global.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            StreamGRateLimitError::Registration.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            StreamGRateLimitError::Profile.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            StreamGRateLimitError::TrackingCapacity.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            StreamGRateLimitError::Global.code(),
            ERR_RATE_LIMITED_GLOBAL
        );
        assert_eq!(
            StreamGRateLimitError::Registration.code(),
            ERR_RATE_LIMITED_REGISTRATION
        );
        assert_eq!(
            StreamGRateLimitError::Profile.code(),
            ERR_RATE_LIMITED_PROFILE
        );
        assert_eq!(
            StreamGRateLimitError::TrackingCapacity.code(),
            ERR_RATE_LIMIT_CAPACITY
        );
    }
}
