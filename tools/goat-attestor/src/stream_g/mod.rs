//! Stream G — TARGET/post-pilot. **Disabled by default** (`STREAM_G_ENABLED=0`).
//!
//! `config::StreamGConfig` parses and validates the env (fail-closed when
//! enabled — see `config.rs`). The module tree below implements the quote →
//! preflight → submit → outbox → broadcast → reconcile pipeline through
//! Task 7.
//!
//! **What is reachable at runtime, precisely (claims ≤ code):**
//!
//! * When `STREAM_G_ENABLED=1`, `main.rs` calls
//!   [`runtime::StreamGState::start`] **before** it binds the listener. That
//!   is the production call site `store::StreamGStore::open` did not have
//!   until Task 8 Wave A: it takes the OS-level exclusive lock on
//!   `STREAM_G_LOCK_PATH`, verifies the WAL/FK/FULL/bounded-busy-timeout
//!   pragmas by reading them back, runs migrations 1 → 3 (`0003` added the
//!   reconciliation scan cursor; `store::SCHEMA_VERSION` is 3 and
//!   `store::MIGRATIONS` has three entries — this line said "1 → 2" until the
//!   scan cursor shipped), parses the at-rest data key and loads the
//!   deployment manifest. Any of those failing is a startup refusal, not a
//!   warning.
//! * This router exposes ten routes. Two are operational, under
//!   `/v1/stream-g/`: `GET /v1/stream-g/ready` (Wave C: [`readiness`], four
//!   real checks that fail closed — no longer the hardcoded 503 it was
//!   through Wave B) and `GET /v1/stream-g/metrics` ([`metrics`], counts
//!   only). Three are the **session-auth surface** (Task 11 Wave B1), under
//!   `/v1/profile/`: `POST /v1/profile/challenges`,
//!   `POST /v1/profile/sessions` and `DELETE /v1/profile/sessions/:id`, all
//!   served by [`profile_auth`] — these are the crate's first authenticated
//!   routes, and the first production call site
//!   [`profile_auth::validate_session`] has ever had. Read `profile_auth`'s
//!   module doc for the credential transport and the absent-`Origin` rule.
//!   The remaining two arrived in the wave after B1 and reuse readers that
//!   already existed: `POST /v1/profile` ([`profile_auth::post_profile`]),
//!   the crate's **only unauthenticated route that mutates state** and the one
//!   that issues the credential the three above authenticate with, bounded
//!   solely by the **registration** rate-limit bucket — deliberately not the
//!   global one the authenticated routes share, see `rate_limit`'s "Why
//!   registration has a budget of its own". It is **not** the only route that
//!   takes no credential: the two operational routes named at the top of this
//!   bullet, `GET /v1/stream-g/ready` and `GET /v1/stream-g/metrics`, take
//!   none either, and are additionally not rate limited at all (`rate_limit`'s
//!   "Nothing else is rate-limited"). Where the perimeter actually is:
//!   [`profile_auth::AuthenticatedProfile`]'s `FromRequestParts`
//!   (`profile_auth.rs:1663-1671`) is the **only** place an `Authorization`
//!   header is read, so the routes naming that extractor are the credentialed
//!   ones; `POST /v1/profile/sessions` is the one route that proves
//!   possession without it (the challenge nonce in its body), and `ready` /
//!   `metrics` prove nothing at all. This list is where to check which route
//!   is which; and
//!   `GET /v1/profile/primary-onboarding/:intentId`
//!   ([`onboarding::get_primary_onboarding_intent`]), profile-scoped and
//!   read-only. **None of those seven touches the chain**, so none of them is
//!   affected by mock mode.
//! * The remaining three are the **pipeline** surface, under `/v1/stream-g/`,
//!   and they are the routes in this crate for which mock mode is a
//!   material fact. `POST /v1/stream-g/quotes` ([`quotes::post_quote`])
//!   assembles the live [`models::EnrollmentQuoteContext`] — pinned block,
//!   fee-token state, endpoint-chain-id agreement, nonce snapshot — and then
//!   signs; under `GOAT_ATTESTOR_MOCK=1` it refuses with
//!   [`http_error::ERR_NO_LIVE_CHAIN`] (503) before any of that, and on a live
//!   process the shipped empty fee schedule makes `MISSING_TARIFF` (503) the
//!   honest answer to every well-formed request. 🔴 **Wave C W4 added
//!   `POST /v1/stream-g/submit`** ([`submit::post_submit`]) — see the bullet
//!   below, which used to say this surface did not exist. `GET
//!   /v1/stream-g/status/:intentId` ([`submit::get_enrollment_status`]) is
//!   profile-scoped, store-only and chain-free; it reports the **enrollment**
//!   vocabulary (`pending`/`submitted`/`executed`) plus the verbatim
//!   reconciliation disposition, which is how `receipt_timeout_unknown`
//!   reaches a caller as itself rather than as a fabricated "failed".
//! * **Three background primitives now have production callers.** Task 8
//!   Wave D mounted the first two; the reconciliation step added the third,
//!   and this bullet still said "two" until that was corrected.
//!   [`maintenance::run_maintenance_loop`] is spawned by `main.rs` when
//!   `STREAM_G_ENABLED=1`, sharing the graceful-shutdown token, and each pass
//!   runs three steps in this order:
//!   1. [`outbox::sweep_stuck_reservations`] — only when a live chain client
//!      exists; mock mode has no release authority, so the sweep is skipped
//!      rather than run without chain evidence;
//!   2. [`profile_auth::prune_expired`] — reads no chain state, so it runs in
//!      mock mode too;
//!   3. [`maintenance::run_reconcile`], which is the production call site
//!      [`reconcile::reconcile_executed_log`] did not have. Live chain only,
//!      for the same reason as the sweep. It scans
//!      `SponsoredEnrollmentExecuted` logs over a confirmation-depth-bounded
//!      window and folds each one; the window and the cursor rules are in
//!      [`maintenance::run_reconcile`]'s own doc, and the reason one
//!      unfoldable log no longer wedges the whole deployment is in
//!      [`reconcile::quarantine_unfoldable_log`].
//!      It runs last on purpose (nothing catches an unwind, so the newest step
//!      is ordered after the two proven ones) — see `maintenance`'s module doc.
//! * 🔴 **Wave C W4 — the pipeline's *write* half now HAS an HTTP entry
//!   point, and this bullet said the opposite until this change.**
//!   `POST /v1/stream-g/submit` ([`submit::post_submit`]) calls
//!   `submit::submit_sponsored_enrollment`, which calls
//!   `broadcaster::sign_persist_and_broadcast`, which signs with the
//!   broadcaster EOA and calls `eth_sendRawTransaction`. **A request a client
//!   sends can now reach a chain write.** Said as narrowly as it is true:
//!   * it reaches one, at most — the per-nonce signing lease and the
//!     `nonce_allocations` reservation each refuse a second;
//!   * only after a fresh `preflight::preflight_sponsored_enrollment` at a
//!     newly pinned block clears it, against a `FeeQuote` **this attestor
//!     sealed** rather than one the caller sent (Wave C W3);
//!   * only under the native-ETH exposure ceiling
//!     (`STREAM_G_MAX_NATIVE_EXPOSURE_WEI`, hazard 1) — which the route
//!     refuses to serve at all while it is unset;
//!   * and not at all in mock mode, where the route answers
//!     `NO_LIVE_CHAIN` (503).
//!
//!   What still has **no** route, stated precisely because the looser version
//!   of this sentence ("`reconcile`'s observers … are invoked only from their
//!   own `mod tests`") is now false: `reconcile`'s **fold** observer
//!   [`reconcile::reconcile_executed_log`] does have a production caller — not
//!   a route, the background loop's third step above, together with
//!   [`reconcile::load_scan_cursor`], [`reconcile::save_scan_cursor`] and
//!   [`reconcile::quarantine_unfoldable_log`]. What genuinely still has no
//!   non-test caller of any kind is [`reconcile::classify_pending_attempt`] /
//!   [`reconcile::apply_disposition`] (the *pending-attempt* observer, a
//!   different job from folding an executed log) and
//!   `direct_eth::prepare_direct_eth_enrollment`. Task 8 Wave C mounted the *operational* surface
//!   (readiness + metrics), Wave D the background loop, Task 11 Wave B1 the
//!   session-auth surface, the wave after it the quote and status routes, and
//!   Wave C W4 the submit route above.
//!
//! The pilot relayer routes (`/v1/relay/*`, including `/v1/relay/gas-drip`)
//! are untouched and Stream G never falls back to them —
//! `mounting_stream_g_leaves_the_pilot_surface_unchanged` and
//! `stream_g_paths_never_fall_back_onto_the_pilot_relayer` in this file's
//! tests are the proof, not the claim. There is no `gas_drips` / `send_native`
//! call site anywhere under `stream_g` — the direct-ETH path prepares a call
//! the *controller* submits itself, because `GoatRelayGateway.sol:379`
//! rejects any sender that is not the controller.
//!
//! # CORS isolation (Wave C)
//!
//! Stream G and the pilot relayer have **separate, non-overlapping** origin
//! allowlists, and each layer is attached to its own routes rather than to the
//! merged application:
//!
//! * the pilot keeps `relayer::build_cors_layer` — `RELAY_CORS_ORIGINS` unioned
//!   with the built-in Vite/Tauri defaults, plus the two `cf-access-*` request
//!   headers;
//! * Stream G uses [`stream_g_cors_layer`] over `STREAM_G_CORS_ORIGINS` only,
//!   with **no** defaults unioned in — unset means the empty allowlist, which
//!   means no cross-origin request is honoured at all.
//!
//! `axum::Router::layer` wraps the routes present on *that* router, so merging
//! cannot move either layer onto the other's paths. The load-bearing test is
//! `pilot_cors_headers_are_byte_identical_whether_or_not_stream_g_is_mounted`,
//! which sends real `Origin`/preflight requests at the pilot with and without
//! Stream G mounted and compares the responses byte for byte; its counterpart
//! `stream_g_and_the_pilot_do_not_honour_each_others_origins` proves the two
//! allowlists are actually disjoint in effect rather than merely configured
//! that way.
//!
//! **Seam closed in Task 8 Wave B (Mandate 1).** Two reservation
//! implementations used to coexist — `submit::reserve_action_nonce` (Task 6b)
//! and [`outbox::reserve_and_persist_raw_tx`] (Task 7), kept in sync by hand.
//! Only the latter writes `raw_tx_enc`/`raw_tx_hash` before the broadcast,
//! which is the sweeper's only recovery evidence, so the 6b copy was
//! **deleted** rather than left unreachable: `grep -rn "reserve_action_nonce"
//! src/` finds no definition and no call. `submit::submit_sponsored_enrollment`
//! now signs first (the broadcaster seam is sign-then-send) and reserves
//! through the outbox, so every row the production path creates is one the
//! sweeper can resolve.

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use tower_http::cors::CorsLayer;

/// Live-Anvil integration harness (Task 9). `#[cfg(test)]` on purpose: it
/// spawns processes and shells out to Foundry, neither of which belongs in a
/// shipped binary.
#[cfg(test)]
pub(crate) mod anvil_harness;
pub mod base_fee;
pub mod broadcaster;
pub mod crypto_store;
/// The document `deploymentManifestHash` is the digest **of** —
/// `keccak256(UTF8(RFC8785(payload)))` over the deployment's role-keyed
/// addresses and runtime code hashes, per the spec at `:244-246`. Until this
/// module existed the value was a literal tag that hashed nothing.
pub mod deployment_payload;
pub mod direct_eth;
pub mod http_error;
/// Shared `tracing`-capture plumbing for tests. `#[cfg(test)]` on purpose: it
/// installs a process-wide global subscriber, which has no business existing in
/// a shipped binary. See the module docs for the callsite-interest race it
/// exists to close.
#[cfg(test)]
pub(crate) mod log_capture;
pub mod maintenance;
pub mod metrics;
pub mod models;
pub mod onboarding;
pub mod outbox;
pub mod preflight;
pub mod profile_auth;
/// Read-only operator view of the quarantined-log rows `reconcile` writes.
/// Library-side on purpose: `main.rs` holds only the clap arm and the printing,
/// so every rule this reader enforces is reachable from `#[cfg(test)]`.
pub mod quarantine_report;
pub mod quotes;
pub mod rate_limit;
pub mod readiness;
pub mod reconcile;
pub mod root_authorization;
pub mod runtime;
pub mod store;
pub mod submit;
pub mod token_manifest;

// ---------------------------------------------------------------------------
// Transport limits (Task 11 Wave 1).
// ---------------------------------------------------------------------------

/// Width the [`STREAM_G_BODY_LIMIT_BYTES`] arithmetic budgets for the one
/// free-form field any Stream G request DTO has (`idempotency_key`).
///
/// ⚠️ **Nothing enforces this number.** No DTO validates the length of an
/// idempotency key, and this constant is not a check — it is the assumption
/// the body-limit arithmetic is computed under. A longer key is not rejected
/// for being long; it simply eats headroom, and is bounded in the end only by
/// the body limit itself.
pub const IDEMPOTENCY_KEY_BUDGET_CHARS: usize = 128;

/// Maximum Stream G request body, in bytes.
///
/// # The arithmetic, not a copied constant
///
/// The pilot uses 8 KiB (`relayer::RELAY_BODY_LIMIT_BYTES`). This is **half
/// that**, and the reason the intuition "Stream G carries signed intents and
/// permits, so it needs more" is wrong here is worth stating: every signature
/// a Stream G request DTO carries is a fixed-width 65-byte ECDSA signature
/// (132 hex characters), and no request DTO in this crate carries a permit
/// blob or any variable-length payload at all — `quotes.rs` reconstructs the
/// EIP-2612 permit server-side from typed fields, and `submit.rs` does the
/// same for the whole `FeeQuote`.
///
/// The `Deserialize` request shapes are `onboarding::StartOnboardingRequest`
/// (one field), `profile_auth::CreateSessionRequest` (two hex fields, under
/// 200 bytes), `root_authorization::CreateRootAuthorizationRequest` (seven),
/// `models::CreateSponsoredEnrollmentQuoteRequest` (21) and — 🔴 added in Wave
/// C W3 — `submit::SubmitSponsoredEnrollmentRequest` (36, the largest).
/// **Three sit behind a mounted route today**: `CreateSessionRequest` on
/// `POST /v1/profile/sessions`, `CreateSponsoredEnrollmentQuoteRequest` on
/// `POST /v1/stream-g/quotes` and — 🔴 since Wave C W4 —
/// `SubmitSponsoredEnrollmentRequest` on `POST /v1/stream-g/submit`. So
/// neither worst case below is hypothetical: each is what its route buffers,
/// and
/// `quotes::tests::the_quote_route_refuses_a_mock_mode_process_with_no_live_chain`
/// and `submit::tests::the_submit_route_refuses_a_mock_mode_process_with_no_live_chain`
/// drive `http_error::max_quote_request_json()` and
/// `http_error::max_submit_request_json()` through the real router, which is
/// what shows the limit is cleared on the production routes and not only in
/// the synthetic probe below.
///
/// With **every** numeric field at its type's maximum decimal width, every
/// hex field at full on-chain width, and `idempotency_key` at
/// [`IDEMPOTENCY_KEY_BUDGET_CHARS`], the quote request's compact JSON
/// encoding measures **1347 bytes** — a figure
/// `tests::the_body_limit_clears_the_largest_real_dto` recomputes from
/// `http_error::max_quote_request_json()` rather than trusting this comment,
/// and which it also asserts really deserializes into the DTO. (The first
/// number written here was 1454, from hand arithmetic; the test is what
/// corrected it.)
///
/// 🔴 **Wave C W3 — the submit shape, and why the quote is not on its wire.**
/// Under the same convention `submit::SubmitSponsoredEnrollmentRequest`
/// measures **2745 bytes** compact with every optional field present,
/// **2890** pretty-printed, and **2099** compact in the shape a correct
/// client sends (the seven `#[serde(default)]` `root_authorization_*` fields
/// omitted, because the contract requires that block all-zero on this path).
/// `tests::the_body_limit_clears_the_submit_dto` recomputes all three.
///
/// Those figures are what they are because the twelve-field `FeeQuote` and
/// its 65-byte signature are **not** on that wire — they are reconstructed
/// from sealed storage. The counterfactual is measured, not asserted:
/// `http_error::max_submit_request_json_with_inline_quote()` builds the 1:1
/// mirror of `SponsoredEnrollmentCall` (54 flat fields — the quote block
/// inline, plus the five values W3 derives) and it measures **4141 bytes
/// compact and 4358 pretty-printed**. Both are over this limit, so that shape
/// could not have been shipped at all without raising it. Dropping the quote
/// block is therefore a correctness requirement of this limit, not an
/// optimisation of it, and the limit was not raised to accommodate the
/// mirror.
///
/// One caveat on that pair of numbers, because it is naming-sensitive rather
/// than structural: the mirror uses **flat, collision-free** keys, so the six
/// fields whose names the intent already owns carry a `quote_` prefix
/// (`quote_deployment_manifest_hash_hex`, and so on). A nested
/// `{"quote": {...}}` encoding of the same values would be shorter by roughly
/// the prefix bytes and might clear the compact limit. It would not clear the
/// pretty-printed one by much, and none of it changes the conclusion — but
/// "4141" is a measurement of *this* encoding, not a property of the concept.
///
/// 4096 leaves a factor of ~3.0 over the quote request and ~1.4 over the
/// submit request, which covers pretty-printed JSON (the quote body with
/// two-space indentation is 1432 bytes, also asserted) without leaving a
/// caller room to spend real memory.
///
/// **This is a ceiling on bytes buffered, not a validity check.** A body under
/// the limit that is nonsense is still rejected — by the extractor, through
/// `http_error::ApiJson`.
pub const STREAM_G_BODY_LIMIT_BYTES: usize = 4 * 1024;

/// Stream G's own CORS layer — **not** `relayer::build_cors_layer`.
///
/// Applied inside [`router`] via [`stream_g_layers`], so it covers Stream G's
/// routes and only those.
///
/// # Widened in Task 11 Wave 1, and what that fixed
///
/// Through Wave 0 this layer allowed `GET`/`POST`/`OPTIONS` and the single
/// request header `content-type`. Task 11's routes are all authenticated, so
/// the credential travels in a request header, which makes every browser call
/// a **preflight naming that header** — and a preflight naming a header this
/// list does not contain is refused before the request is ever made. The
/// session-revocation route is `DELETE`
/// (`profile_auth::revoke_session`'s own doc), which the method list also did
/// not contain.
///
/// Added: [`Method::DELETE`], and `authorization` as an allowed request
/// header. `authorization` and not an invented `x-stream-g-*` name because
/// `profile_auth::validate_session` takes a bearer `session_token` and
/// `Authorization: Bearer <token>` is that credential's standard carriage; no
/// wave has specified a custom header, and putting a name in this allowlist
/// that nothing else in the crate uses would be a guess dressed as a
/// decision. **If Task 11 chooses a different header, this list must grow with
/// it** — `stream_g_preflight_allows_the_methods_and_headers_it_claims_to`
/// pins the current contents, so that change cannot happen silently.
///
/// Deliberately **not** added: `allow_credentials`. The session token is an
/// explicit bearer value, not a cookie; nothing in this crate reads one.
///
/// # Three deliberate differences from the pilot's, unchanged
///
/// 1. **No built-in origins.** `relayer::parse_cors_origins` unions
///    `RELAY_CORS_ORIGINS` with a hardcoded Vite/Tauri list because the pilot
///    desktop app needs them. Stream G takes `STREAM_G_CORS_ORIGINS` verbatim
///    (`config::parse_comma_list`, no defaults), so an operator who enables
///    Stream G without naming an origin gets the empty allowlist — every
///    cross-origin request is unhonoured, which is the fail-closed direction.
/// 2. **No `cf-access-*` request headers.** Those exist for the pilot's
///    Cloudflare Access deployment; Stream G's perimeter is its own.
/// 3. **Never `Any`.** An empty `Vec<HeaderValue>` becomes an empty
///    `AllowOrigin` list, which matches nothing. It does not degrade to `*`.
pub fn stream_g_cors_layer(origins: &[String]) -> CorsLayer {
    let origin_values: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(origin_values)
        .allow_methods(STREAM_G_ALLOWED_METHODS.to_vec())
        .allow_headers(
            STREAM_G_ALLOWED_REQUEST_HEADERS
                .iter()
                .map(|h| HeaderName::from_static(h))
                .collect::<Vec<_>>(),
        )
}

/// Methods [`stream_g_cors_layer`] answers a preflight for. Named rather than
/// inlined so the test that pins them cannot drift from the layer that sets
/// them.
pub const STREAM_G_ALLOWED_METHODS: &[Method] =
    &[Method::GET, Method::POST, Method::DELETE, Method::OPTIONS];

/// Request headers [`stream_g_cors_layer`] answers a preflight for. Lowercase:
/// `HeaderName::from_static` panics on anything else.
pub const STREAM_G_ALLOWED_REQUEST_HEADERS: &[&str] = &["content-type", "authorization"];

/// The layer stack every Stream G route gets, in one place.
///
/// Generic over the router's state type for one reason that matters: it lets a
/// test drive **this function** — the production one — over a `POST` route
/// with a body, at an exact byte count. That closes the gap `DefaultBodyLimit`
/// would otherwise leave untested, because `DefaultBodyLimit` is not a
/// middleware that reads anything: it inserts an extension that
/// `Bytes::from_request` consults, so a route that never reads a body never
/// enforces it.
///
/// Until Wave B1 that was the *only* way to exercise it at all — every
/// mounted route was a `GET`. `POST /v1/profile/sessions` now buffers a body
/// through `http_error::ApiJson`, so the limit is live on a real route; the
/// synthetic probe below is kept because it is what pins the exact
/// off-by-one boundary, which no real DTO sits near.
///
/// The composition argument, stated so it can be checked: the CORS tests run
/// against the real [`router`] and would fail if `router` stopped calling this
/// function, while `the_body_limit_rejects_one_byte_over` runs against this
/// function and would fail if the body limit left it. Neither test alone
/// proves the production router has a body limit; together they do.
pub(crate) fn stream_g_layers<S>(router: Router<S>, origins: &[String]) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router
        .layer(stream_g_cors_layer(origins))
        .layer(DefaultBodyLimit::max(STREAM_G_BODY_LIMIT_BYTES))
}

/// `GET /v1/stream-g/ready` — real checks, fail-closed. See [`readiness`] for
/// what each one asks of the live store and, just as importantly, for the
/// spec §9.8 dependencies this build does not check yet (they are listed in
/// the response so a 200 cannot be over-read).
async fn ready(
    State(state): State<runtime::StreamGState>,
) -> (StatusCode, Json<readiness::ReadinessReport>) {
    let report = readiness::evaluate(&state).await;
    (report.status(), Json(report))
}

/// `GET /v1/stream-g/metrics` — sweeper / reconciliation / broadcast counts.
///
/// Counts only: [`metrics::MetricsSnapshot`] has no `String` field, so there is
/// nowhere for a signed payload, a session token or a permit signature to
/// appear (spec §9.3 — signed intents are executable bearer capabilities until
/// expiry). `no_metric_or_log_surface_carries_payload_bytes` is the proof.
async fn stream_g_metrics(
    State(state): State<runtime::StreamGState>,
) -> Json<metrics::MetricsSnapshot> {
    Json(state.metrics().snapshot())
}

/// Build the Stream G router over the startup state.
///
/// Callers must only mount this when `StreamGConfig::enabled` is true and
/// [`runtime::StreamGState::start`] has succeeded — see `main.rs`. Taking the
/// state by value rather than reading globals is what makes "one process, one
/// locked store" a type-level fact: there is no way to build this router
/// without having opened the store first.
///
/// Every path registered here is under `/v1/stream-g/` or `/v1/profile/`;
/// nothing under `/v1/relay/` is claimed, and there is **no fallback**, so an
/// unknown path is a 404 rather than a request that drifts onto a pilot
/// handler.
///
/// # The `:name` in every path parameter here is load-bearing
///
/// This crate runs axum 0.7.9 / matchit 0.7.3, where `{` and `}` are ordinary
/// path characters — `"/v1/profile/sessions/{id}"` compiles, does not panic,
/// and matches only the literal segment `{id}`. Every path parameter here is
/// therefore `:name`, and each of the three has its own binding test, so
/// "modernising" any one of them to the brace form axum 0.8 introduced is a
/// failing test rather than a silent outage:
/// `profile_auth::tests::the_delete_route_binds_the_session_id_from_the_path`
/// (`/v1/profile/sessions/:id`),
/// `onboarding::tests::the_intent_route_binds_the_intent_id_from_the_path`
/// (`/v1/profile/primary-onboarding/:intentId`) and
/// `submit::tests::the_status_route_binds_the_intent_id_from_the_path`
/// (`/v1/stream-g/status/:intentId`). This paragraph is the explanation the
/// rest of the crate, and the G1 plan document, point at.
pub fn router(state: runtime::StreamGState) -> Router {
    let routes = Router::new()
        .route("/v1/stream-g/ready", get(ready))
        .route("/v1/stream-g/metrics", get(stream_g_metrics))
        // Where a credential comes from, so it cannot require one. It is *not*
        // the crate's only credential-free route, and saying so here once
        // stopped a reader concluding the rest of the surface is closed:
        // `GET /v1/stream-g/ready` and `GET /v1/stream-g/metrics` above take no
        // credential either (and are not rate-limited at all), and
        // `POST /v1/profile/sessions` below takes no `Authorization` header —
        // see its own doc. Five of the six routes below take
        // `caller: AuthenticatedProfile`; `post_session` is the exception.
        // What is true of *this* route alone is narrower: it is the only
        // unauthenticated route that mutates durable state for a caller the
        // crate has never seen before.
        // Its only bound is the *registration* rate-limit bucket, which is a
        // separate budget from the global one every authenticated route spends
        // from — see [`profile_auth::RegistrationRateLimit`] for why sharing
        // the global bucket let unauthenticated traffic 429 authenticated
        // callers, and [`profile_auth::post_profile`] for why the per-profile
        // bucket is unavailable rather than merely omitted here.
        .route("/v1/profile", post(profile_auth::post_profile))
        // Task 11 Wave B1 — the crate's first authenticated routes. The
        // credential transport, the absent-`Origin` rule and the extractor
        // that makes an unauthenticated profile route unrepresentable are all
        // documented in `profile_auth`'s module doc.
        .route("/v1/profile/challenges", post(profile_auth::post_challenge))
        .route("/v1/profile/sessions", post(profile_auth::post_session))
        .route(
            "/v1/profile/sessions/:id",
            delete(profile_auth::delete_session),
        )
        // Read-only, profile-scoped, store-only. `:intentId` — not
        // `{intentId}`; see the `:name` note above and
        // `onboarding::get_primary_onboarding_intent`'s own doc.
        .route(
            "/v1/profile/primary-onboarding/:intentId",
            get(onboarding::get_primary_onboarding_intent),
        )
        // The **pipeline's** first two HTTP entry points. The quote route is
        // also the first route in this crate that reads the chain at all — the
        // status route below does not, and neither do the seven above.
        //
        // `quotes` is plural and flat (founder ruling), not the nested
        // `/v1/stream-g/quotes/sponsored-enrollment` that
        // `create_sponsored_enrollment_quote`'s and
        // `models::CreateSponsoredEnrollmentQuoteRequest`'s docs named before
        // this route existed; both now name the mounted path.
        // [`quotes::post_quote`] assembles the
        // `EnrollmentQuoteContext` itself — the one part of the quote path
        // that had no caller — and its doc is where the read order and the
        // shipped-fixture `MISSING_TARIFF` refusal are recorded.
        //
        // The status route serves the **enrollment** state machine
        // (`submitted`/`executed`), which is a different machine over
        // different rows than the onboarding route above; see
        // [`submit::get_enrollment_status`]. `:intentId`, for the reason in
        // the `:name` note above.
        .route("/v1/stream-g/quotes", post(quotes::post_quote))
        // 🔴 Wave C W4 — the pipeline's **write** half. This is the only route
        // in the crate a request to which can end in
        // `eth_sendRawTransaction`, and the first production caller of
        // `broadcaster::sign_persist_and_broadcast`,
        // `base_fee::submit_exposure_for_chain` (hazard 1's gate) and
        // `submit::SubmitContext`.
        //
        // No path parameter: the `intentId` is a body field here, because the
        // body carries the seventeen-field signed intent anyway and a path
        // segment would be a second place for it to disagree with itself. The
        // `:name` note above therefore does not apply to this line — it does
        // apply to the status route below.
        //
        // Refuses with 503 before parsing the body when this process has no
        // exposure ceiling or no live chain; see `submit::post_submit`.
        .route("/v1/stream-g/submit", post(submit::post_submit))
        .route(
            "/v1/stream-g/status/:intentId",
            get(submit::get_enrollment_status),
        );
    stream_g_layers(routes, state.cors_origins()).with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::MockChain;
    use crate::relayer::{self, RelayerConfig};
    use crate::stream_g::broadcaster::{BroadcastOutcome, BroadcasterNonce};
    use crate::stream_g::outbox::{ReservedAttempt, StuckAttempt, SweepReport};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    /// An origin only Stream G allows.
    const STREAM_G_ORIGIN: &str = "https://stream-g.example";
    /// An origin only the pilot allows (one of `default_cors_origins`).
    const PILOT_ORIGIN: &str = "http://localhost:5173";

    async fn state_for(dir: &std::path::Path) -> runtime::StreamGState {
        let mut map = runtime::test_support::enabled_map(dir);
        map.insert("STREAM_G_CORS_ORIGINS".into(), STREAM_G_ORIGIN.into());
        let cfg = crate::config::load_from_map(&map).expect("stream G config must validate");
        let controller = runtime::ShutdownController::new();
        runtime::StreamGState::start(&cfg, controller.token())
            .await
            .expect("stream G startup")
    }

    async fn body_string(res: axum::response::Response) -> String {
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn ready_endpoint_is_200_on_a_healthy_store() {
        let dir = tempfile::tempdir().unwrap();
        let app = router(state_for(dir.path()).await);
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/stream-g/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = body_string(res).await;
        assert!(body.contains("\"ready\":true"), "{body}");
        assert!(body.contains("instance_lock_held"), "{body}");
    }

    /// The route must serve what [`readiness::evaluate`] decided, not a
    /// constant. Wave B's `ready` was a hardcoded 503; a hardcoded 200 would
    /// be the worse version of the same bug — the degraded-store 200 spec
    /// §9.3 forbids — and `readiness`'s own tests cannot see it, because they
    /// call `evaluate` directly.
    ///
    /// Mutation this detects: `ready` returning `StatusCode::OK` (or any
    /// constant) instead of `report.status()`.
    #[tokio::test]
    async fn the_ready_route_serves_503_on_a_degraded_store() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_for(dir.path()).await;
        let app = router(state.clone());

        // Healthy first, through the route (non-zero arm).
        assert_eq!(
            probe(&app, Method::GET, "/v1/stream-g/ready").await.0,
            StatusCode::OK
        );

        state
            .store()
            .write_tx(|tx| {
                Box::pin(async move {
                    sqlx::query("UPDATE store_meta SET schema_version = 1")
                        .execute(&mut **tx)
                        .await?;
                    Ok::<(), crate::stream_g::store::StreamGStoreError>(())
                })
            })
            .await
            .expect("downgrade schema_version");

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/stream-g/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_string(res).await;
        assert!(body.contains("\"ready\":false"), "{body}");
        assert!(body.contains("schema_version"), "{body}");
    }

    /// snake_case Stream G wire DTOs (founder ruling), asserted on the bytes
    /// that actually leave the process rather than on the absence of a
    /// `#[serde(rename_all)]` attribute.
    ///
    /// Mutation this detects: adding `#[serde(rename_all = "camelCase")]` to
    /// `ReadinessReport` or `MetricsSnapshot`.
    #[tokio::test]
    async fn stream_g_wire_dtos_are_snake_case() {
        let dir = tempfile::tempdir().unwrap();
        let app = router(state_for(dir.path()).await);

        let ready_body = body_string(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/v1/stream-g/ready")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert!(ready_body.contains("\"not_yet_checked\""), "{ready_body}");
        assert!(
            ready_body.contains("\"instance_lock_held\""),
            "{ready_body}"
        );
        assert!(!ready_body.contains("notYetChecked"), "{ready_body}");
        assert!(!ready_body.contains("instanceLockHeld"), "{ready_body}");

        let metrics_body = body_string(
            app.oneshot(
                Request::builder()
                    .uri("/v1/stream-g/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
        )
        .await;
        assert!(
            metrics_body.contains("\"sweep_held_intent_still_valid\""),
            "{metrics_body}"
        );
        assert!(
            !metrics_body.contains("sweepHeldIntentStillValid"),
            "{metrics_body}"
        );
    }

    /// Exactly the pilot router `main.rs` builds for `serve-relayer`, over a
    /// `MockChain` (which is what the Stream B pilot itself runs with when
    /// `GOAT_ATTESTOR_MOCK=1`).
    fn pilot_app() -> Router {
        relayer::router_with_relayer_config(Arc::new(MockChain::new()), RelayerConfig::default())
    }

    /// `(status, sorted headers)` for one request against a cloned app.
    async fn probe(app: &Router, method: Method, uri: &str) -> (StatusCode, Vec<(String, String)>) {
        probe_with_headers(app, method, uri, &[]).await
    }

    /// As [`probe`], with extra request headers — the CORS tests need real
    /// `Origin` / `Access-Control-Request-*` headers, because a `CorsLayer`
    /// emits nothing at all for a request that has no `Origin`.
    async fn probe_with_headers(
        app: &Router,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
    ) -> (StatusCode, Vec<(String, String)>) {
        let mut builder = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let res = app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let mut headers: Vec<(String, String)> = res
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        headers.sort();
        (status, headers)
    }

    fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }

    /// The four pilot surfaces every isolation test sweeps.
    const PILOT_ROUTES: &[(Method, &str)] = &[
        (Method::GET, "/health"),
        (Method::POST, "/v1/relay/bind"),
        (Method::POST, "/v1/relay/enroll"),
        (Method::POST, "/v1/relay/gas-drip"),
    ];

    /// **Pilot safety, route half.** Merging the Stream G router onto the
    /// pilot app must not change the status or the response headers of any
    /// `/v1/relay/*` route (or `/health`) — the pilot's CORS/body-limit layers
    /// are attached to the pilot's own routes, and Stream G must not widen or
    /// narrow them. The shutdown half of pilot safety is
    /// `runtime::tests::serve_mode_is_plain_for_the_pilot_and_graceful_only_for_stream_g`.
    ///
    /// Mutation this detects: `router()` claiming a path that belongs to the
    /// pilot — verified by adding `.route("/health", get(ready))`, after which
    /// `Router::merge` panics on the overlap and this test fails.
    ///
    /// What it does **not** prove: this variant sends no `Origin`, so it says
    /// nothing about CORS. That is
    /// `pilot_cors_headers_are_byte_identical_whether_or_not_stream_g_is_mounted`.
    #[tokio::test]
    async fn mounting_stream_g_leaves_the_pilot_surface_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let pilot_only = pilot_app();
        let with_stream_g = pilot_app().merge(router(state_for(dir.path()).await));

        for (method, uri) in PILOT_ROUTES {
            let before = probe(&pilot_only, method.clone(), uri).await;
            let after = probe(&with_stream_g, method.clone(), uri).await;
            assert_eq!(
                before, after,
                "pilot route {method} {uri} changed when Stream G was mounted"
            );
            assert_ne!(
                before.0,
                StatusCode::NOT_FOUND,
                "{method} {uri} must exist on the pilot app for this comparison to mean anything"
            );
        }

        // Paired arms in the other direction: the Stream G route is absent
        // from the pilot-only app and present (a real readiness answer, not a
        // relayer fallback) once mounted.
        assert_eq!(
            probe(&pilot_only, Method::GET, "/v1/stream-g/ready")
                .await
                .0,
            StatusCode::NOT_FOUND,
            "Stream G must not exist on the pilot app"
        );
        assert_eq!(
            probe(&with_stream_g, Method::GET, "/v1/stream-g/ready")
                .await
                .0,
            StatusCode::OK
        );
    }

    /// **CORS isolation, the required assertion.** A pilot route's response
    /// headers must be *byte-identical* whether or not Stream G is mounted —
    /// for a plain request, for an allowed `Origin`, for a foreign `Origin`,
    /// and for a preflight.
    ///
    /// Mutation this detects: widening [`stream_g_cors_layer`] to
    /// `CorsLayer::permissive()` (or `.allow_origin(Any)`). Verified: with
    /// that mutation **this test still passes** — which is the point, it is
    /// the isolation half — while
    /// `stream_g_and_the_pilot_do_not_honour_each_others_origins` fails,
    /// proving the layer is real and that this test is not passing because
    /// Stream G has no CORS layer at all.
    #[tokio::test]
    async fn pilot_cors_headers_are_byte_identical_whether_or_not_stream_g_is_mounted() {
        let dir = tempfile::tempdir().unwrap();
        let pilot_only = pilot_app();
        let with_stream_g = pilot_app().merge(router(state_for(dir.path()).await));

        let mut saw_allow_origin = false;
        for (method, uri) in PILOT_ROUTES {
            for headers in [
                vec![("origin", PILOT_ORIGIN)],
                vec![("origin", STREAM_G_ORIGIN)],
                vec![("origin", "https://unrelated.example")],
            ] {
                let before = probe_with_headers(&pilot_only, method.clone(), uri, &headers).await;
                let after = probe_with_headers(&with_stream_g, method.clone(), uri, &headers).await;
                assert_eq!(
                    before, after,
                    "pilot {method} {uri} with {headers:?} changed when Stream G was mounted"
                );
                if header_value(&before.1, "access-control-allow-origin").is_some() {
                    saw_allow_origin = true;
                }
            }

            // Preflight, where a CORS layer does the most work.
            let pre = [
                ("origin", PILOT_ORIGIN),
                ("access-control-request-method", method.as_str()),
                ("access-control-request-headers", "content-type"),
            ];
            let before = probe_with_headers(&pilot_only, Method::OPTIONS, uri, &pre).await;
            let after = probe_with_headers(&with_stream_g, Method::OPTIONS, uri, &pre).await;
            assert_eq!(
                before, after,
                "pilot preflight for {method} {uri} changed when Stream G was mounted"
            );
            assert!(
                header_value(&before.1, "access-control-allow-origin").is_some(),
                "the pilot must answer its own preflight, or this comparison compares nothing: \
                 {before:?}"
            );
        }

        // Paired non-zero arm: the pilot really did emit CORS headers on at
        // least one plain request, so "byte-identical" is not "identically
        // empty".
        assert!(
            saw_allow_origin,
            "no pilot route emitted access-control-allow-origin — the comparison above is vacuous"
        );
    }

    /// **CORS isolation, the other direction.** The two allowlists are
    /// disjoint *in effect*: Stream G does not honour a pilot origin, and the
    /// pilot does not honour Stream G's.
    ///
    /// Mutation this detects: widening [`stream_g_cors_layer`] to
    /// `CorsLayer::permissive()` — the first assertion below then finds
    /// `access-control-allow-origin: *` for `PILOT_ORIGIN` and fails, while
    /// `pilot_cors_headers_are_byte_identical_whether_or_not_stream_g_is_mounted`
    /// keeps passing.
    #[tokio::test]
    async fn stream_g_and_the_pilot_do_not_honour_each_others_origins() {
        let dir = tempfile::tempdir().unwrap();
        let app = pilot_app().merge(router(state_for(dir.path()).await));

        // Stream G's own origin is honoured on a Stream G route (non-zero arm
        // — without this the "no header" assertions could pass on a route with
        // no CORS layer at all).
        let mine = probe_with_headers(
            &app,
            Method::GET,
            "/v1/stream-g/ready",
            &[("origin", STREAM_G_ORIGIN)],
        )
        .await;
        assert_eq!(
            header_value(&mine.1, "access-control-allow-origin").as_deref(),
            Some(STREAM_G_ORIGIN),
            "{mine:?}"
        );

        // A pilot origin is NOT honoured on a Stream G route.
        let theirs = probe_with_headers(
            &app,
            Method::GET,
            "/v1/stream-g/ready",
            &[("origin", PILOT_ORIGIN)],
        )
        .await;
        assert_eq!(
            header_value(&theirs.1, "access-control-allow-origin"),
            None,
            "Stream G honoured a pilot origin — the allowlists are not isolated: {theirs:?}"
        );

        // And Stream G's origin is NOT honoured on a pilot route.
        let crossed = probe_with_headers(
            &app,
            Method::POST,
            "/v1/relay/enroll",
            &[("origin", STREAM_G_ORIGIN)],
        )
        .await;
        assert_eq!(
            header_value(&crossed.1, "access-control-allow-origin"),
            None,
            "the pilot honoured a Stream G origin — Stream G widened the pilot: {crossed:?}"
        );
        // Non-zero arm for the pilot side: it does honour its own origin.
        let pilot_own = probe_with_headers(
            &app,
            Method::POST,
            "/v1/relay/enroll",
            &[("origin", PILOT_ORIGIN)],
        )
        .await;
        assert_eq!(
            header_value(&pilot_own.1, "access-control-allow-origin").as_deref(),
            Some(PILOT_ORIGIN),
            "{pilot_own:?}"
        );
    }

    /// An unset `STREAM_G_CORS_ORIGINS` is the empty allowlist, not `*`.
    #[tokio::test]
    async fn an_empty_stream_g_allowlist_honours_no_origin() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = runtime::test_support::enabled_cfg(dir.path());
        assert!(
            cfg.stream_g.cors_origins.is_empty(),
            "STREAM_G_CORS_ORIGINS defaults to empty"
        );
        let controller = runtime::ShutdownController::new();
        let state = runtime::StreamGState::start(&cfg, controller.token())
            .await
            .unwrap();
        let app = router(state);

        for origin in [STREAM_G_ORIGIN, PILOT_ORIGIN, "*"] {
            let res = probe_with_headers(
                &app,
                Method::GET,
                "/v1/stream-g/ready",
                &[("origin", origin)],
            )
            .await;
            assert_eq!(
                header_value(&res.1, "access-control-allow-origin"),
                None,
                "empty allowlist honoured {origin}: {res:?}"
            );
            // Paired non-zero arm: the request itself still succeeded, so the
            // absence above is about CORS and not about a dead route.
            assert_eq!(res.0, StatusCode::OK);
        }
    }

    // -------------------------------------------------------------------
    // Task 11 Wave 1 — the transport surface. Before this block,
    // `grep -rn 'access-control-request' src/ tests/` returned exactly two
    // lines, both inside `PILOT_ROUTES` above: there was **no** assertion
    // anywhere on `stream_g_cors_layer`'s allowed methods or headers, so the
    // layer could be changed in any direction with the suite staying green.
    // (`stream_g_and_the_pilot_do_not_honour_each_others_origins`'s own doc
    // records that widening it to `CorsLayer::permissive()` left
    // `pilot_cors_headers_are_byte_identical_…` passing.)
    // -------------------------------------------------------------------

    /// As [`probe_with_headers`], but with a request **body**.
    ///
    /// Written as a sibling rather than folded into `probe_with_headers`
    /// because that helper always sends `Body::empty()` and every existing
    /// caller depends on it doing so (the CORS comparisons above compare whole
    /// header maps and would change shape if a content-length appeared). A
    /// body limit cannot be tested through it at all: with no bytes to buffer,
    /// `DefaultBodyLimit` — which is an extension consulted by
    /// `Bytes::from_request`, not a middleware that inspects anything — never
    /// comes into play.
    async fn probe_with_body(
        app: &Router,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> (StatusCode, String) {
        let mut builder = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let res = app
            .clone()
            .oneshot(builder.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = res.status();
        (status, body_string(res).await)
    }

    /// **The first preflight assertion Stream G has ever had.**
    ///
    /// A preflight names one method and one header, and a CORS layer answers
    /// it only if both are allowed. This walks every entry of
    /// [`STREAM_G_ALLOWED_METHODS`] and [`STREAM_G_ALLOWED_REQUEST_HEADERS`]
    /// against the real [`router`], and then walks values that must **not** be
    /// allowed — which is the half that makes it a pin rather than a
    /// rubber stamp.
    ///
    /// Mutations this detects (each verified alone, reverted, re-greened):
    /// dropping `Method::DELETE` from the method list; dropping
    /// `authorization` from the header list; widening the layer to
    /// `CorsLayer::permissive()` (the negative arms then find `PUT` and
    /// `x-not-allowed` accepted).
    #[tokio::test]
    async fn stream_g_preflight_allows_the_methods_and_headers_it_claims_to() {
        let dir = tempfile::tempdir().unwrap();
        let app = router(state_for(dir.path()).await);

        // Literal expectations FIRST. The loops below iterate the same
        // constants the layer is built from, so on their own they would pass
        // just as happily if `DELETE` or `authorization` were deleted from the
        // list — the loop would simply stop checking them. These two lines are
        // what make this a pin on the two values Task 11 actually needs rather
        // than a tautology over whatever the list happens to contain.
        assert!(
            STREAM_G_ALLOWED_METHODS.contains(&Method::DELETE),
            "DELETE is required: profile_auth::revoke_session is a DELETE route"
        );
        assert!(
            STREAM_G_ALLOWED_REQUEST_HEADERS.contains(&"authorization"),
            "an authenticated route needs its credential header allowed, or every browser \
             preflight is refused before the request is made"
        );

        for method in STREAM_G_ALLOWED_METHODS {
            let res = probe_with_headers(
                &app,
                Method::OPTIONS,
                "/v1/stream-g/ready",
                &[
                    ("origin", STREAM_G_ORIGIN),
                    ("access-control-request-method", method.as_str()),
                ],
            )
            .await;
            let allowed = header_value(&res.1, "access-control-allow-methods")
                .unwrap_or_else(|| panic!("no allow-methods for preflight {method}: {res:?}"));
            assert!(
                allowed.contains(method.as_str()),
                "preflight for {method} was not honoured: {allowed}"
            );
        }

        for header in STREAM_G_ALLOWED_REQUEST_HEADERS {
            let res = probe_with_headers(
                &app,
                Method::OPTIONS,
                "/v1/stream-g/ready",
                &[
                    ("origin", STREAM_G_ORIGIN),
                    ("access-control-request-method", "POST"),
                    ("access-control-request-headers", header),
                ],
            )
            .await;
            let allowed = header_value(&res.1, "access-control-allow-headers")
                .unwrap_or_else(|| panic!("no allow-headers for preflight {header}: {res:?}"));
            assert!(
                allowed.contains(header),
                "preflight naming request header {header} was not honoured: {allowed}"
            );
        }

        // Negative arms: the allowlist is a list, not a wildcard.
        let res = probe_with_headers(
            &app,
            Method::OPTIONS,
            "/v1/stream-g/ready",
            &[
                ("origin", STREAM_G_ORIGIN),
                ("access-control-request-method", "PUT"),
            ],
        )
        .await;
        let allowed = header_value(&res.1, "access-control-allow-methods").unwrap_or_default();
        assert!(
            !allowed.contains("PUT") && !allowed.contains('*'),
            "PUT is not a Stream G method but the layer allowed it: {allowed}"
        );

        let res = probe_with_headers(
            &app,
            Method::OPTIONS,
            "/v1/stream-g/ready",
            &[
                ("origin", STREAM_G_ORIGIN),
                ("access-control-request-method", "POST"),
                ("access-control-request-headers", "x-not-allowed"),
            ],
        )
        .await;
        let allowed = header_value(&res.1, "access-control-allow-headers").unwrap_or_default();
        assert!(
            !allowed.contains("x-not-allowed") && !allowed.contains('*'),
            "an unlisted request header was allowed: {allowed}"
        );

        // The isolation property the pilot tests pin is untouched by the
        // widening: a foreign origin still gets nothing, even for an allowed
        // method.
        let res = probe_with_headers(
            &app,
            Method::OPTIONS,
            "/v1/stream-g/ready",
            &[
                ("origin", PILOT_ORIGIN),
                ("access-control-request-method", "DELETE"),
            ],
        )
        .await;
        assert_eq!(
            header_value(&res.1, "access-control-allow-origin"),
            None,
            "widening the method list must not widen the origin list: {res:?}"
        );
    }

    /// A route wired through the production [`stream_g_layers`] rejects a body
    /// one byte over [`STREAM_G_BODY_LIMIT_BYTES`] and accepts one exactly at
    /// it.
    ///
    /// This drives `stream_g_layers` rather than [`router`] because the exact
    /// boundary needs a body of a chosen byte length that still parses, which
    /// no real DTO gives; `DefaultBodyLimit` is only enforced by an extractor
    /// that actually buffers one — see that function's doc for the composition
    /// argument that connects this test to the production router.
    ///
    /// Mutation this detects: deleting the `DefaultBodyLimit` layer from
    /// `stream_g_layers` (the over-limit body is then accepted and the first
    /// assertion fails).
    #[tokio::test]
    async fn the_body_limit_rejects_one_byte_over() {
        use crate::stream_g::http_error::{ApiJson, ERR_BODY_TOO_LARGE};

        /// Reads the body as raw bytes so the limit, not the JSON shape, is
        /// what decides. `ApiJson<serde_json::Value>` accepts any valid JSON.
        async fn sink(ApiJson(_): ApiJson<serde_json::Value>) -> StatusCode {
            StatusCode::OK
        }

        let app = stream_g_layers(
            Router::new().route("/probe", axum::routing::post(sink)),
            &[STREAM_G_ORIGIN.to_string()],
        )
        .with_state(());
        let json = [("content-type", "application/json")];

        // A syntactically valid JSON string padded to an exact byte count:
        // `"aaa…"` is 2 quotes + n filler.
        let exact = format!("\"{}\"", "a".repeat(STREAM_G_BODY_LIMIT_BYTES - 2));
        assert_eq!(exact.len(), STREAM_G_BODY_LIMIT_BYTES);
        let (status, _) = probe_with_body(
            &app,
            Method::POST,
            "/probe",
            &json,
            exact.clone().into_bytes(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a body exactly at the limit must be accepted, or the limit is off by one"
        );

        let over = format!("\"{}\"", "a".repeat(STREAM_G_BODY_LIMIT_BYTES - 1));
        assert_eq!(over.len(), STREAM_G_BODY_LIMIT_BYTES + 1);
        let (status, body) =
            probe_with_body(&app, Method::POST, "/probe", &json, over.into_bytes()).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            body,
            format!("{{\"error\":\"{ERR_BODY_TOO_LARGE}\"}}"),
            "an over-limit body must land in the Stream G envelope, not axum's text/plain default"
        );
    }

    /// The number in [`STREAM_G_BODY_LIMIT_BYTES`]'s doc is recomputed here
    /// rather than trusted, from a body that is asserted to actually
    /// deserialize into the DTO it claims to measure.
    ///
    /// Mutation this detects: lowering `STREAM_G_BODY_LIMIT_BYTES` to a value
    /// the largest real request cannot fit through (e.g. 1024).
    #[test]
    fn the_body_limit_clears_the_largest_real_dto() {
        let json = crate::stream_g::http_error::max_quote_request_json();

        // The measurement is of a body the DTO really accepts — otherwise it
        // would be measuring an arbitrary string.
        serde_json::from_str::<crate::stream_g::models::CreateSponsoredEnrollmentQuoteRequest>(
            &json,
        )
        .expect("the maximum-width body must deserialize into the DTO it measures");

        assert_eq!(
            json.len(),
            1347,
            "the largest real Stream G request body changed size; \
             STREAM_G_BODY_LIMIT_BYTES's doc quotes this number"
        );
        assert!(
            json.len() < STREAM_G_BODY_LIMIT_BYTES,
            "the largest real request ({} bytes) does not fit under the body limit ({})",
            json.len(),
            STREAM_G_BODY_LIMIT_BYTES
        );

        // Pretty-printed, the same body is larger; the limit must clear that
        // too, because nothing stops a client from sending it.
        let pretty = serde_json::to_string_pretty(
            &serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        )
        .unwrap();
        assert_eq!(pretty.len(), 1432, "the doc quotes this number too");
        assert!(
            pretty.len() < STREAM_G_BODY_LIMIT_BYTES,
            "pretty-printed ({} bytes) does not fit under {}",
            pretty.len(),
            STREAM_G_BODY_LIMIT_BYTES
        );
    }

    /// 🔴 Wave C W3. The same measurement for the **submit** DTO, which
    /// overtook the quote request as the crate's largest wire shape (36
    /// declared fields vs 21).
    ///
    /// Three numbers, all recomputed here and none of them hand-arithmetic:
    /// the compact worst case with every optional field present, the same
    /// body pretty-printed, and the compact worst case a **correct** client
    /// sends (the `root_authorization_*` block omitted, because the contract
    /// requires it all-zero on this path).
    ///
    /// The pretty-printed figure is the one that matters and is why the quote
    /// block is not on the wire: a 1:1 mirror of `SponsoredEnrollmentCall`
    /// with the twelve-field quote and its signature inline does **not** fit
    /// this limit once indented, so an operator posting an indented file would
    /// get a 413 for a valid request.
    ///
    /// Mutation this detects: putting the quote block back on
    /// `SubmitSponsoredEnrollmentRequest`, or lowering
    /// `STREAM_G_BODY_LIMIT_BYTES` below what this shape needs.
    #[test]
    fn the_body_limit_clears_the_submit_dto() {
        use crate::stream_g::submit::SubmitSponsoredEnrollmentRequest;

        let json = crate::stream_g::http_error::max_submit_request_json();
        serde_json::from_str::<SubmitSponsoredEnrollmentRequest>(&json)
            .expect("the maximum-width submit body must deserialize into the DTO it measures");

        let pretty = serde_json::to_string_pretty(
            &serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        )
        .unwrap();

        let minimal =
            crate::stream_g::http_error::max_submit_request_json_without_root_authorization();
        serde_json::from_str::<SubmitSponsoredEnrollmentRequest>(&minimal).expect(
            "omitting the root_authorization block must still deserialize — those fields are \
             #[serde(default)]",
        );

        assert_eq!(
            (json.len(), pretty.len(), minimal.len()),
            (2745, 2890, 2099),
            "the submit DTO changed size; SubmitSponsoredEnrollmentRequest's doc \
             and the W3 report quote these numbers"
        );
        for (what, n) in [
            ("compact, all fields", json.len()),
            ("pretty-printed", pretty.len()),
            ("compact, correct client", minimal.len()),
        ] {
            assert!(
                n < STREAM_G_BODY_LIMIT_BYTES,
                "the submit DTO ({what}) is {n} bytes and does not fit under {}",
                STREAM_G_BODY_LIMIT_BYTES
            );
        }

        // 🔴 The counterfactual, measured rather than asserted: the 1:1
        // mirror of `SponsoredEnrollmentCall` (quote inline, nothing derived)
        // clears this limit compact by a margin thinner than one signature,
        // and does not clear it at all once indented.
        let mirror = crate::stream_g::http_error::max_submit_request_json_with_inline_quote();
        let mirror_pretty = serde_json::to_string_pretty(
            &serde_json::from_str::<serde_json::Value>(&mirror).unwrap(),
        )
        .unwrap();
        assert_eq!(
            (mirror.len(), mirror_pretty.len()),
            (4141, 4358),
            "the 1:1 mirror changed size; STREAM_G_BODY_LIMIT_BYTES's doc quotes \
             these numbers as the reason the quote block is not on the wire"
        );
        assert!(
            mirror.len() > STREAM_G_BODY_LIMIT_BYTES
                && mirror_pretty.len() > STREAM_G_BODY_LIMIT_BYTES,
            "the inline-quote mirror was expected NOT to fit ({} compact / {} \
             pretty vs {}); if it now fits, the claim in \
             STREAM_G_BODY_LIMIT_BYTES's doc is stale",
            mirror.len(),
            mirror_pretty.len(),
            STREAM_G_BODY_LIMIT_BYTES
        );
    }

    /// Stream G must never fall back onto `/v1/relay/*`.
    ///
    /// Mutation this detects: giving the Stream G router a `.fallback(..)`
    /// that forwards, or registering a path outside `/v1/stream-g/`.
    #[tokio::test]
    async fn stream_g_paths_never_fall_back_onto_the_pilot_relayer() {
        let dir = tempfile::tempdir().unwrap();
        let stream_g_only = router(state_for(dir.path()).await);

        // The Stream G router alone claims nothing the pilot owns.
        for (method, uri) in PILOT_ROUTES {
            let res = probe(&stream_g_only, method.clone(), uri).await;
            assert_eq!(
                res.0,
                StatusCode::NOT_FOUND,
                "Stream G answered pilot route {method} {uri}"
            );
        }

        // Unknown Stream G paths 404 rather than drifting anywhere, both alone
        // and merged.
        let dir2 = tempfile::tempdir().unwrap();
        let merged = pilot_app().merge(router(state_for(dir2.path()).await));
        for uri in [
            "/v1/stream-g/",
            "/v1/stream-g/quote",
            "/v1/stream-g/relay/enroll",
            "/v1/stream-g/../v1/relay/enroll",
        ] {
            assert_eq!(
                probe(&merged, Method::POST, uri).await.0,
                StatusCode::NOT_FOUND,
                "POST {uri} was not a 404"
            );
        }

        // Paired non-zero arm: the two paths that DO exist answer.
        assert_eq!(
            probe(&merged, Method::GET, "/v1/stream-g/ready").await.0,
            StatusCode::OK
        );
        assert_eq!(
            probe(&merged, Method::GET, "/v1/stream-g/metrics").await.0,
            StatusCode::OK
        );
    }

    /// Capture buffer for `tracing` output on this thread.
    #[derive(Clone)]
    struct CapturedLog(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::writer::MakeWriter<'a> for CapturedLog {
        type Writer = CapturedLog;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// **Spec §9.3.** Signed intent/permit bytes, session tokens and permit
    /// signatures are executable bearer capabilities until expiry: they must
    /// never reach a metric or an ordinary log.
    ///
    /// The outcomes recorded below carry markers in every field that *could*
    /// leak — a stuck row's `attempt_id` and `reason`, a broadcast's `detail`
    /// and `raw_tx_hash`, a reservation's `raw_tx_hash_hex`. The exported
    /// metrics document and the captured `tracing` output must contain none of
    /// them, while the counters must show the outcomes really were recorded.
    ///
    /// Mutation this detects: adding any field carrying one of those values to
    /// a recorder's log line or to `MetricsSnapshot` — verified by adding
    /// `reason = ?report.stuck.first()` to `record_sweep`'s `tracing::debug!`,
    /// after which the log assertion fails.
    #[tokio::test]
    async fn no_metric_or_log_surface_carries_payload_bytes() {
        const ATTEMPT_MARKER: &str = "ATTEMPTIDMARKER";
        const REASON_MARKER: &str = "STUCKREASONMARKER";
        const DETAIL_MARKER: &str = "BROADCASTDETAILMARKER";
        const RAW_TX_MARKER: &str = "0xRAWTXHASHMARKER";

        let dir = tempfile::tempdir().unwrap();
        let state = state_for(dir.path()).await;

        // Same latent race as
        // `http_error::tests::extractor_rejection_detail_goes_to_tracing_not_to_the_client`:
        // the recorder callsites this test reads are cached process-wide the
        // first time they run, and a subscriber-less thread caches them as
        // `Interest::never()`. See `crate::stream_g::log_capture`.
        crate::stream_g::log_capture::install_interest_keepalive();
        let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(CapturedLog(buffer.clone()))
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            state.metrics().record_sweep(&SweepReport {
                claimed: 2,
                released: 1,
                executed: 0,
                held_intent_still_valid: 0,
                stuck: vec![StuckAttempt {
                    attempt_id: ATTEMPT_MARKER.into(),
                    reason: REASON_MARKER.into(),
                }],
            });
            state
                .metrics()
                .record_broadcast(&BroadcastOutcome::UnresolvedWithKnownHash {
                    nonce: BroadcasterNonce {
                        allocation_id: ATTEMPT_MARKER.into(),
                        nonce: 7,
                        signer_address: "0xdeadbeef".into(),
                        refilled_gap: false,
                    },
                    attempt: ReservedAttempt {
                        attempt_id: ATTEMPT_MARKER.into(),
                        allocation_id: ATTEMPT_MARKER.into(),
                        attempt_number: 1,
                        raw_tx_hash_hex: RAW_TX_MARKER.into(),
                        lease_until: 0,
                    },
                    raw_tx_hash: [0xAB; 32],
                    detail: DETAIL_MARKER.into(),
                });
        });

        let logged = String::from_utf8_lossy(
            &buffer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
        .into_owned();

        let app = router(state.clone());
        let exported = body_string(
            app.oneshot(
                Request::builder()
                    .uri("/v1/stream-g/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
        )
        .await;

        for marker in [ATTEMPT_MARKER, REASON_MARKER, DETAIL_MARKER, RAW_TX_MARKER] {
            assert!(
                !exported.contains(marker),
                "metrics export leaked {marker}: {exported}"
            );
            assert!(!logged.contains(marker), "log leaked {marker}: {logged}");
        }
        assert!(
            !exported.contains("abababab"),
            "metrics export leaked the raw tx hash bytes: {exported}"
        );

        // Paired non-zero arms. Without these the assertions above would pass
        // on an empty log and an all-zero document.
        assert!(
            logged.contains("stream_g sweep pass recorded"),
            "nothing was logged at all, so the log assertions proved nothing: {logged}"
        );
        assert!(
            logged.contains("stream_g broadcast outcome recorded"),
            "{logged}"
        );
        assert!(exported.contains("\"sweep_claimed\":2"), "{exported}");
        assert!(exported.contains("\"sweep_stuck\":1"), "{exported}");
        assert!(
            exported.contains("\"broadcast_unresolved\":1"),
            "{exported}"
        );
        assert!(exported.contains("\"broadcast_accepted\":0"), "{exported}");
    }
}
