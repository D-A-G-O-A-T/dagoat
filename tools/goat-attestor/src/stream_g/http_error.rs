//! The Stream G HTTP error surface: one envelope, one `IntoResponse`, one
//! extractor.
//!
//! Before Task 11 Wave 1 this crate had **no** `impl IntoResponse for` any
//! error type at all (`grep -rn 'IntoResponse for' src/` found none), and the
//! pilot relayer hand-built `(StatusCode, Json<..>)` tuples inside each
//! handler. Every Stream G module already carried a `code()` returning a
//! stable `&'static str`; what was missing was (a) a status for each variant,
//! (b) a body shape, and (c) the one place that turns the two into a response.
//!
//! # The body carries a machine code and nothing else
//!
//! [`ApiErrorBody`] has exactly one field. There is no `message`, no
//! `detail`, no `path`, no `hint`. That is not minimalism for its own sake —
//! it is the only shape that makes the leak question answerable by
//! construction rather than by auditing ~120 `Display` impls one at a time.
//! Those `Display` strings are genuinely useful and genuinely dangerous: they
//! name database paths (`QuoteError::FeeScheduleIo`), signer addresses
//! (`SubmitError::NonceAlreadyReserved`), attempt ids, transaction hashes,
//! and the internal `reason` strings of the on-chain authorization checks.
//! Every one of them goes to [`tracing`] — the operator's channel — and none
//! of them goes to the client.
//!
//! `stream_g_error_bodies_carry_the_code_and_nothing_else` is the check, and
//! it is modelled on `readiness::tests::
//! the_readiness_document_never_echoes_payload_or_key_material`: build the
//! error with a distinctive marker in **every** string field, render it, and
//! assert the marker is absent from the body and present in the log.
//!
//! # The ownership-oracle rule
//!
//! > **A resource the caller names but does not own is answered exactly as if
//! > it did not exist: same status, same code, same body. Stream G therefore
//! > emits no 403 at all.**
//!
//! Three enums already close this in their *store* logic —
//! `onboarding::OnboardingError::IntentNotFound`,
//! `root_authorization::RootAuthorizationError::IntentNotFound` and
//! `submit::SubmitError::IntentNotFound` each document that "no such row" and
//! "a row under a different profile" are deliberately the same value. That
//! decision is worth nothing if the HTTP mapping then splits them into 404
//! and 403, so the rule is stated once here and enforced uniformly: the only
//! authorization-shaped status Stream G produces is **401**, which says "the
//! credential you presented did not authenticate" — a fact about the request,
//! not about anything stored.
//!
//! Why this matters concretely: `onboarding::deterministic_id` derives an
//! intent id from `("primary_onboarding", profile_id, idempotency_key)`, all
//! three of which a peer may know or guess. A 404-vs-403 split would turn
//! that derivation into a membership test over other people's intents.
//!
//! `stream_g_error_mapping_never_emits_403` is the tripwire. If a future
//! variant genuinely means "this exists but is not yours", it must map to the
//! same 404 as "unknown" — or the rule has been abandoned and the test should
//! be the thing that says so.
//!
//! **What this rule does not cover, stated rather than implied:**
//! `profile_auth`'s challenge and session codes are *not* collapsed to one
//! another — see `ProfileAuthError::status`, which records both the residual
//! leak and the 128-bit identifier entropy that is the whole reason it is
//! tolerated.
//!
//! # `INTERNAL` is not a code, and that is visible on the wire
//!
//! Every module's `code()` predates this wave and ends in `_ => "INTERNAL"`.
//! That fallback identifies nothing, and this wave classifies the conditions
//! behind it differently: `QuoteError::Store` is a 500 and
//! `BaseFeeError::Chain` a 502, and both send `{"error": "INTERNAL"}`. So for
//! that one string the **status**, not the code, is what a client can act on.
//! `every_error_code_maps_to_exactly_one_status` carves `INTERNAL` out by name
//! and asserts it is the only carve-out, so a *real* code drifting into two
//! meanings still fails. Tightening those fallbacks is not this wave's scope —
//! several existing tests assert the current strings.
//!
//! # Extractor rejections land in the same envelope
//!
//! `grep -rn 'JsonRejection|FromRequest' src/` returned nothing before this
//! module: the pilot takes `Json(req): Json<T>` bare (`relayer.rs:493`), so
//! the most common client error on any POST — malformed JSON, a missing
//! field, a key `deny_unknown_fields` refuses, a missing `Content-Type`, a
//! body over the limit — was answered by axum with a `text/plain` body and a
//! status no API contract described, without ever reaching a handler. Stream
//! G routes take [`ApiJson<T>`] instead, whose `Rejection` **is** [`ApiError`],
//! so those five failures produce the same `{"error": "..."}` document as
//! every other refusal.

use axum::async_trait;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::de::DeserializeOwned;
use serde::Serialize;

// ---------------------------------------------------------------------------
// Transport-level codes. Everything else delegates to a module's own `code()`.
// ---------------------------------------------------------------------------

/// The request body was not syntactically valid JSON.
pub const ERR_INVALID_JSON: &str = "INVALID_JSON";
/// The body was valid JSON but not this route's shape: a missing field, a
/// wrong type, or a key rejected by `#[serde(deny_unknown_fields)]`. One code
/// for all three — naming the offending field would put caller-controlled
/// text in the body, which is the thing [`ApiErrorBody`] exists to prevent.
pub const ERR_INVALID_REQUEST_SHAPE: &str = "INVALID_REQUEST_SHAPE";
/// No `Content-Type: application/json`.
pub const ERR_UNSUPPORTED_MEDIA_TYPE: &str = "UNSUPPORTED_MEDIA_TYPE";
/// The body exceeded [`super::STREAM_G_BODY_LIMIT_BYTES`].
pub const ERR_BODY_TOO_LARGE: &str = "REQUEST_BODY_TOO_LARGE";
/// The body could not be buffered for a reason that is neither a length limit
/// nor a parse failure (a dropped connection mid-body, for instance).
pub const ERR_UNREADABLE_BODY: &str = "UNREADABLE_REQUEST_BODY";

/// This process has no live chain client, so a route that must read the chain
/// cannot answer at all.
///
/// Not a transport code and not any module's code: no enum in the crate means
/// it. `QuoteError`'s 29 variants (the `pub enum QuoteError` block in
/// `quotes.rs`) all describe something about a *request* or about state that
/// was read; the condition here is that
/// [`super::runtime::StreamGState::trusted_chain`] returned `None`, which
/// happens when and only when the process was
/// started with `GOAT_ATTESTOR_MOCK=1`. That is a deployment fact, decided
/// before any caller existed.
pub const ERR_NO_LIVE_CHAIN: &str = "NO_LIVE_CHAIN";

/// 🔴 Wave C W4 (hazard 1). `STREAM_G_MAX_NATIVE_EXPOSURE_WEI` is `0`, so the
/// native-ETH exposure ceiling every broadcast is gated against admits
/// nothing.
///
/// Like [`ERR_NO_LIVE_CHAIN`] this is a **deployment fact**, not a request
/// fact, and it belongs to no module's error enum. It exists because `0` is
/// the config default (`config.rs`'s
/// `parse_u128(map, "STREAM_G_MAX_NATIVE_EXPOSURE_WEI", 0)`) *and* a
/// syntactically legal ceiling: without this code an operator who never set
/// the variable would see `EXPOSURE_EXCEEDS_SCHEDULE` on every single
/// request — a refusal that reads as "your transaction is too expensive"
/// when the truth is "this process was never given a budget". Three separate
/// docs in this crate
/// (`broadcaster::BroadcastPlan::max_native_exposure_wei`,
/// `runtime::StreamGState::max_native_exposure_wei`,
/// `preflight::UNVERIFIED_CHECKS`' exposure entry) state that the route
/// mounting the submit path must surface an unset ceiling as such; this is
/// that surface.
///
/// **A deliberate `0` is not expressible, and that is the trade.** An
/// operator who genuinely wants "broadcast nothing" has `STREAM_G_ENABLED=0`
/// and mock mode; conflating the two would cost the diagnosis this code
/// exists to give.
pub const ERR_EXPOSURE_CEILING_UNSET: &str = "EXPOSURE_CEILING_UNSET";

/// Fallback code. Deliberately identical to the string every module's
/// `code()` already falls back to, so "the server broke" reads the same
/// wherever it came from.
pub const ERR_INTERNAL: &str = "INTERNAL";

// ---------------------------------------------------------------------------
// The envelope.
// ---------------------------------------------------------------------------

/// The **entire** client-facing error document.
///
/// snake_case by default, matching the founder ruling on Stream G wire DTOs
/// that `readiness::ReadinessReport` and `metrics::MetricsSnapshot` follow.
/// `error` is always one of the `ERR_*` constants — a `&'static str`, so no
/// request-derived or store-derived byte can reach this struct even by
/// accident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiErrorBody {
    pub error: &'static str,
}

/// A refusal on its way out: a status, a stable code, and the operator-facing
/// detail that will be logged and **not** sent.
///
/// Build one from any Stream G error via `?`/`.into()` (the `From` impls
/// below), from a [`JsonRejection`], or directly with [`ApiError::new`] for
/// conditions a route decides itself.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    /// Where the failure came from, for the log line only. `&'static str`.
    source: &'static str,
    /// The full `Display` of the originating error.
    ///
    /// Private, with **no accessor at all**: the only code that may read it is
    /// [`ApiError::into_response`], which writes it to `tracing`. There is
    /// deliberately no getter for a well-meaning route to reach for when it
    /// wants to "just include the message" — that is the failure mode this
    /// whole module exists to make unavailable.
    detail: String,
}

impl ApiError {
    /// A refusal with no originating error — for conditions a route decides
    /// on its own (a rate-limit verdict, an unset ceiling). `detail` is still
    /// operator-facing only.
    pub fn new(
        status: StatusCode,
        code: &'static str,
        source: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code,
            source,
            detail: detail.into(),
        }
    }

    /// The refusal for a route that needs the chain in a process that has
    /// none: [`super::runtime::StreamGState::trusted_chain`] is `None`
    /// (mock mode).
    ///
    /// **503, not 500 and not 4xx.** The caller did nothing wrong — the same
    /// request against a non-mock process would be served — so a 4xx would
    /// blame them for an operator's `GOAT_ATTESTOR_MOCK=1`. And nothing is
    /// broken: `start` succeeded, the store is open, this process is simply not
    /// configured to answer chain-backed routes. 503 is the one status that
    /// says "not available here, do not treat this as your bug", and it is what
    /// the pilot relayer already uses for its own "this deployment cannot serve
    /// that" conditions (`relayer.rs:725` `GasDripDisabled`).
    ///
    /// Takes no arguments so a handler can write
    /// `state.trusted_chain().ok_or_else(ApiError::no_live_chain)?` — the whole
    /// condition is one boolean and there is nothing request-derived to carry
    /// (constraint: no payload bytes reach a log, pinned by
    /// `super::tests::no_metric_or_log_surface_carries_payload_bytes`).
    pub fn no_live_chain() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_NO_LIVE_CHAIN,
            "stream_g::runtime::StreamGState::trusted_chain",
            "no live chain client in this process (GOAT_ATTESTOR_MOCK=1): every chain-backed \
             Stream G route is unserviceable here",
        )
    }

    /// 🔴 Wave C W4. The refusal for a process whose native-ETH exposure
    /// ceiling is `0` — see [`ERR_EXPOSURE_CEILING_UNSET`].
    ///
    /// **503, and for exactly [`ApiError::no_live_chain`]'s reason**: the
    /// caller did nothing wrong, the same request against a configured
    /// process would be served, and nothing is broken. A 500 would call it a
    /// bug in this code, which it is not.
    ///
    /// Takes no arguments and carries no number. The ceiling is `0` by
    /// definition on this path (that is the whole condition), and the env key
    /// an operator must set is a `&'static str` in the detail rather than
    /// anything request-derived.
    pub fn exposure_ceiling_unset() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_EXPOSURE_CEILING_UNSET,
            "stream_g::runtime::StreamGState::max_native_exposure_wei",
            "STREAM_G_MAX_NATIVE_EXPOSURE_WEI is 0 (the config default): the native-ETH \
             exposure gate would refuse every broadcast, so the submit route is \
             unserviceable until an operator sets a real ceiling",
        )
    }

    /// Build from an error's own `status()`/`code()` plus its `Display`.
    pub fn from_source(
        status: StatusCode,
        code: &'static str,
        source: &'static str,
        err: &dyn std::fmt::Display,
    ) -> Self {
        Self::new(status, code, source, err.to_string())
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    /// The body this error will serialize to. Exposed so a test can assert on
    /// the document without going through a full response.
    pub fn body(&self) -> ApiErrorBody {
        ApiErrorBody { error: self.code }
    }
}

/// The crate's only `IntoResponse for` an error type.
///
/// Logging happens here rather than at each `?` so that no path can produce a
/// Stream G error response without the detail reaching an operator: 5xx is
/// `error!` (this process is at fault), everything else `warn!`.
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!(
                status = self.status.as_u16(),
                error_code = self.code,
                source = self.source,
                detail = %self.detail,
                "stream G request failed"
            );
        } else {
            tracing::warn!(
                status = self.status.as_u16(),
                error_code = self.code,
                source = self.source,
                detail = %self.detail,
                "stream G request refused"
            );
        }
        (self.status, Json(self.body())).into_response()
    }
}

// ---------------------------------------------------------------------------
// Module errors -> ApiError.
// ---------------------------------------------------------------------------

/// One `From` per route-reachable error enum. A blanket
/// `impl<E: SomeTrait> From<E> for ApiError` is not usable here — it collides
/// with core's reflexive `impl<T> From<T> for T` — and enumerating the types
/// is better anyway: this list *is* the answer to "which errors can reach a
/// client", and it is one grep away from the reader.
macro_rules! api_error_from {
    ($($ty:path),+ $(,)?) => {
        $(
            impl From<$ty> for ApiError {
                fn from(err: $ty) -> Self {
                    ApiError::from_source(err.status(), err.code(), stringify!($ty), &err)
                }
            }
        )+
    };
}

api_error_from!(
    super::quotes::QuoteError,
    super::submit::SubmitError,
    super::profile_auth::ProfileAuthError,
    super::root_authorization::RootAuthorizationError,
    super::onboarding::OnboardingError,
    super::preflight::PreflightError,
    super::token_manifest::TokenManifestError,
    super::base_fee::BaseFeeError,
    super::models::LiveNoncesError,
    super::rate_limit::StreamGRateLimitError,
);

// ---------------------------------------------------------------------------
// Extractor rejections -> ApiError.
// ---------------------------------------------------------------------------

impl From<JsonRejection> for ApiError {
    /// axum's own status is kept (`422` for a shape failure, `415` for the
    /// content type, `413` for the length limit, `400` for a syntax error),
    /// because those are the statuses the HTTP specification already assigns
    /// to exactly these conditions. Only the **body** changes.
    ///
    /// `JsonRejection` is `#[non_exhaustive]`, so the `_` arm is mandatory
    /// rather than a choice; it keys off the status axum computed, which is
    /// the only thing a future variant is guaranteed to have.
    fn from(rejection: JsonRejection) -> Self {
        let status = rejection.status();
        let code = match &rejection {
            JsonRejection::JsonSyntaxError(_) => ERR_INVALID_JSON,
            JsonRejection::JsonDataError(_) => ERR_INVALID_REQUEST_SHAPE,
            JsonRejection::MissingJsonContentType(_) => ERR_UNSUPPORTED_MEDIA_TYPE,
            // `BytesRejection` is `FailedToBufferBody`, which is
            // `LengthLimitError` (413) or `UnknownBodyError` (400). The
            // variant is private to axum-core; the status distinguishes them.
            _ if status == StatusCode::PAYLOAD_TOO_LARGE => ERR_BODY_TOO_LARGE,
            _ => ERR_UNREADABLE_BODY,
        };
        // `body_text()` is axum's operator-facing prose. It can name the
        // offending field, so it goes to the log and not to the client — the
        // same rule every other arm of this module follows.
        ApiError::new(status, code, "axum::extract::Json", rejection.body_text())
    }
}

/// `axum::Json` with [`ApiError`] as its rejection.
///
/// Deserialization behaviour is byte-for-byte axum's — this delegates to
/// `Json::<T>::from_request` and only rewrites the failure. Use this in place
/// of `Json<T>` on every Stream G route that takes a body; a route that takes
/// bare `Json<T>` silently opts out of the whole envelope.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApiJson<T>(pub T);

#[async_trait]
impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state).await?;
        Ok(ApiJson(value))
    }
}

/// The maximum-width body every field of the crate's largest wire DTO
/// (`models::CreateSponsoredEnrollmentQuoteRequest`, 21 fields) can carry.
/// This is the measurement `super::STREAM_G_BODY_LIMIT_BYTES` is derived
/// from; `super::tests::the_body_limit_clears_the_largest_real_dto`
/// re-derives it rather than trusting a comment.
///
/// Every numeric field is at its type's maximum decimal width, every hex
/// field at its full on-chain width (32-byte digest, 20-byte address, 65-byte
/// signature), and the one free-form field at
/// [`super::IDEMPOTENCY_KEY_BUDGET_CHARS`].
#[cfg(test)]
pub(crate) fn max_quote_request_json() -> String {
    let bytes32 = format!("0x{}", "f".repeat(64));
    let address = format!("0x{}", "f".repeat(40));
    let signature = format!("0x{}", "f".repeat(130));
    serde_json::json!({
        "idempotency_key": "k".repeat(super::IDEMPOTENCY_KEY_BUDGET_CHARS),
        "intent_id_hex": bytes32,
        "root_address": address,
        "controller_address": address,
        "controller_epoch": u64::MAX,
        "secondary_address": address,
        "root_authorization_digest_hex": bytes32,
        "fee_authorization_mode": u8::MAX,
        "max_fee": u128::MAX.to_string(),
        "nonce": u64::MAX,
        "deadline": u64::MAX,
        "valid_for_seconds": u64::MAX,
        "v1_nonce": u64::MAX,
        "v1_deadline": u64::MAX,
        "v1_signature_hex": signature,
        "link_nonce": u64::MAX,
        "link_deadline": u64::MAX,
        "link_signature_hex": signature,
        "gas_unit_ceiling": u64::MAX,
        "max_fee_per_gas_wei": u128::MAX.to_string(),
        "unsigned_size_ceiling": u64::MAX,
    })
    .to_string()
}

/// 🔴 Wave C W3. The same measurement for
/// `submit::SubmitSponsoredEnrollmentRequest`, which is now the crate's
/// largest wire DTO by field count (36 vs the quote request's 21).
///
/// Same convention as [`max_quote_request_json`]: every numeric field at its
/// type's maximum decimal width, every hex field at full on-chain width
/// (32-byte digest, 20-byte address, 65-byte signature), every `u128` as a
/// 39-digit decimal string. The seven `root_authorization_*` fields are
/// `#[serde(default)]` on the DTO but are **included here**, because
/// `DefaultBodyLimit` is a ceiling on what a caller may send and a caller may
/// send them.
///
/// `super::tests::the_body_limit_clears_the_largest_real_dto` and
/// `crate::stream_g::submit::tests::the_submit_dto_fits_the_body_limit`
/// recompute the byte counts from this function rather than trusting any
/// comment; the last hand-computed figure in this crate (1454) was wrong and a
/// test corrected it to 1347, which is why no number is written here.
#[cfg(test)]
pub(crate) fn max_submit_request_json() -> String {
    max_submit_request_value().to_string()
}

/// The same document with the seven optional `root_authorization_*` fields
/// omitted — the shape a **correct** client sends, since the contract
/// requires that block all-zero and empty on this path.
#[cfg(test)]
pub(crate) fn max_submit_request_json_without_root_authorization() -> String {
    let mut v = max_submit_request_value();
    let obj = v.as_object_mut().expect("object");
    for k in [
        "root_authorization_root_address",
        "root_authorization_secondary_address",
        "root_authorization_enroll_digest_hex",
        "root_authorization_link_digest_hex",
        "root_authorization_nonce",
        "root_authorization_deadline",
        "root_authorization_signature_hex",
    ] {
        obj.remove(k).expect("field present in the full document");
    }
    v.to_string()
}

/// 🔴 Wave C W3 — the shape that was **rejected**, kept so the rejection can
/// be measured rather than asserted.
///
/// A 1:1 mirror of `preflight::SponsoredEnrollmentCall`: the 36 fields of
/// [`max_submit_request_json`] plus the thirteen the quote block would need
/// (twelve `FeeQuote` fields and `quote_signature_hex`) plus the five values
/// W3 derives server-side rather than accepting (`v1Enrollment.wallet`,
/// `link.root`, `link.secondary`, the permit's `owner` and `spender`) — 54
/// fields.
///
/// `super::tests::the_body_limit_clears_the_submit_dto` shows this shape does
/// not fit `super::STREAM_G_BODY_LIMIT_BYTES` once pretty-printed, which is
/// the evidence behind that constant's doc.
#[cfg(test)]
pub(crate) fn max_submit_request_json_with_inline_quote() -> String {
    let bytes32 = format!("0x{}", "f".repeat(64));
    let address = format!("0x{}", "f".repeat(40));
    let signature = format!("0x{}", "f".repeat(130));
    let mut v = max_submit_request_value();
    let obj = v.as_object_mut().expect("object");
    for (k, val) in [
        // --- the FeeQuote the caller used to send ---------------------
        ("quote_id_hex", serde_json::json!(bytes32)),
        ("action_type_hex", serde_json::json!(bytes32)),
        ("action_core_hash_hex", serde_json::json!(bytes32)),
        (
            "quote_deployment_manifest_hash_hex",
            serde_json::json!(bytes32),
        ),
        (
            "quote_fee_token_config_hash_hex",
            serde_json::json!(bytes32),
        ),
        ("fee_schedule_hash_hex", serde_json::json!(bytes32)),
        ("payer_address", serde_json::json!(address)),
        ("quote_fee_token_address", serde_json::json!(address)),
        ("fee_amount", serde_json::json!(u128::MAX.to_string())),
        ("fee_recipient_address", serde_json::json!(address)),
        ("valid_after", serde_json::json!(u64::MAX)),
        ("valid_until", serde_json::json!(u64::MAX)),
        ("quote_signature_hex", serde_json::json!(signature)),
        // --- the five W3 derives instead of accepting ------------------
        ("v1_wallet_address", serde_json::json!(address)),
        ("link_root_address", serde_json::json!(address)),
        ("link_secondary_address", serde_json::json!(address)),
        ("fee_eip2612_owner_address", serde_json::json!(address)),
        ("fee_eip2612_spender_address", serde_json::json!(address)),
    ] {
        assert!(
            obj.insert(k.to_string(), val).is_none(),
            "`{k}` is already a field of the real submit DTO; the mirror would \
             under-count by one field"
        );
    }
    v.to_string()
}

#[cfg(test)]
fn max_submit_request_value() -> serde_json::Value {
    let bytes32 = format!("0x{}", "f".repeat(64));
    let address = format!("0x{}", "f".repeat(40));
    let signature = format!("0x{}", "f".repeat(130));
    serde_json::json!({
        // --- SponsorEnrollment ---------------------------------------
        "intent_id_hex": bytes32,
        "deployment_manifest_hash_hex": bytes32,
        "fee_token_config_hash_hex": bytes32,
        "root_address": address,
        "controller_address": address,
        "controller_epoch": u64::MAX,
        "secondary_address": address,
        "enroll_digest_hex": bytes32,
        "link_digest_hex": bytes32,
        "root_authorization_digest_hex": bytes32,
        "fee_token_address": address,
        "fee_authorization_mode": u8::MAX,
        "fee_authorization_digest_hex": bytes32,
        "max_fee": u128::MAX.to_string(),
        "fee_quote_hash_hex": bytes32,
        "nonce": u64::MAX,
        "deadline": u64::MAX,
        "sponsor_signature_hex": signature,
        // --- V1Enrollment (wallet derived) ---------------------------
        "v1_nonce": u64::MAX,
        "v1_deadline": u64::MAX,
        "v1_signature_hex": signature,
        // --- LinkSecondary (root/secondary derived) ------------------
        "link_nonce": u64::MAX,
        "link_deadline": u64::MAX,
        "link_signature_hex": signature,
        // --- Eip2612Authorization (owner/spender derived) ------------
        "fee_eip2612_value": u128::MAX.to_string(),
        "fee_eip2612_deadline": u64::MAX,
        "fee_eip2612_v": u8::MAX,
        "fee_eip2612_r_hex": bytes32,
        "fee_eip2612_s_hex": bytes32,
        // --- RootAuthorization (serde(default), all-zero on this path)
        "root_authorization_root_address": address,
        "root_authorization_secondary_address": address,
        "root_authorization_enroll_digest_hex": bytes32,
        "root_authorization_link_digest_hex": bytes32,
        "root_authorization_nonce": u64::MAX,
        "root_authorization_deadline": u64::MAX,
        "root_authorization_signature_hex": signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_g::base_fee::BaseFeeError;
    use crate::stream_g::models::LiveNoncesError;
    use crate::stream_g::onboarding::OnboardingError;
    use crate::stream_g::preflight::PreflightError;
    use crate::stream_g::profile_auth::ProfileAuthError;
    use crate::stream_g::quotes::QuoteError;
    use crate::stream_g::rate_limit::StreamGRateLimitError;
    use crate::stream_g::root_authorization::RootAuthorizationError;
    use crate::stream_g::submit::SubmitError;
    use crate::stream_g::token_manifest::TokenManifestError;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::post;
    use axum::Router;
    use http_body_util::BodyExt;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    /// Every string field of every error below is filled with this, so a
    /// single `contains` answers "did any internal text escape".
    const MARKER: &str = "LEAKMARKER";

    /// A census of route-reachable error values, one per variant wherever the
    /// variant can be built here.
    ///
    /// **Hand-maintained, and that is stated rather than implied.** The
    /// compiler guarantee that a newly added variant is *considered* comes
    /// from every `status()` being wildcard-free — adding a variant fails to
    /// compile there — not from this list. What this list gives is the two
    /// properties a `match` cannot: that the rendered body is clean, and that
    /// no code maps to two statuses.
    fn census() -> Vec<(&'static str, ApiError)> {
        let m = MARKER.to_string();
        let mut out: Vec<(&'static str, ApiError)> = Vec::new();

        macro_rules! push {
            ($name:literal, $e:expr) => {
                out.push(($name, ApiError::from($e)));
            };
        }

        // --- QuoteError ------------------------------------------------
        push!(
            "QuoteError::Store",
            QuoteError::Store(crate::stream_g::store::StreamGStoreError::SamePath {
                path: std::path::PathBuf::from(format!("C:/{MARKER}/g.db")),
            })
        );
        push!(
            "QuoteError::Crypto",
            QuoteError::Crypto(crate::stream_g::crypto_store::CryptoStoreError::DecryptionFailed)
        );
        push!(
            "QuoteError::Sqlx",
            QuoteError::Sqlx(sqlx::Error::RowNotFound)
        );
        push!(
            "QuoteError::TokenUnauthorized",
            QuoteError::TokenUnauthorized(TokenManifestError::TokenNotAuthorized {
                reason: "inactive",
            })
        );
        push!(
            "QuoteError::Exposure",
            QuoteError::Exposure(BaseFeeError::ExposureExceedsSchedule {
                reserve_wei: 2,
                ceiling_wei: 1,
            })
        );
        push!(
            "QuoteError::FeeScheduleIo",
            QuoteError::FeeScheduleIo {
                path: format!("C:/{MARKER}/schedule.json"),
                detail: m.clone(),
            }
        );
        push!(
            "QuoteError::FeeScheduleParse",
            QuoteError::FeeScheduleParse {
                path: format!("C:/{MARKER}/schedule.json"),
                detail: m.clone(),
            }
        );
        push!(
            "QuoteError::MissingTariff",
            QuoteError::MissingTariff("SPONSORED_ENROLLMENT")
        );
        push!(
            "QuoteError::ZeroFeeAmount",
            QuoteError::ZeroFeeAmount("SPONSORED_ENROLLMENT")
        );
        push!(
            "QuoteError::FeeExceedsMax",
            QuoteError::FeeExceedsMax {
                fee_amount: 2,
                max_fee: 1,
            }
        );
        // No `MARKER` in these three: they carry a `&'static str` field name
        // and a length, never the caller's bytes — see
        // `QuoteError::BadAddress`'s doc and
        // `quotes::tests::a_newline_in_a_caller_hex_field_cannot_forge_a_log_line`.
        // The marker-absence assertion below is therefore vacuous for them,
        // which is the strongest possible outcome: there is no string field to
        // leak.
        push!(
            "QuoteError::BadAddress",
            QuoteError::BadAddress {
                field: "root_address",
                len: 7,
            }
        );
        push!(
            "QuoteError::BadDigest",
            QuoteError::BadDigest {
                field: "intent_id_hex",
                len: 7,
            }
        );
        push!(
            "QuoteError::BadAmount",
            QuoteError::BadAmount {
                field: "max_fee",
                len: 7,
            }
        );
        push!(
            "QuoteError::BadV1Signature",
            QuoteError::BadV1Signature(m.clone())
        );
        push!(
            "QuoteError::BadLinkSignature",
            QuoteError::BadLinkSignature(m.clone())
        );
        push!(
            "QuoteError::StaleOrMixedNonce",
            QuoteError::StaleOrMixedNonce
        );
        push!(
            "QuoteError::ValidityExceedsPolicy",
            QuoteError::ValidityExceedsPolicy
        );
        push!(
            "QuoteError::ValidityExceedsUint48",
            QuoteError::ValidityExceedsUint48
        );
        push!(
            "QuoteError::DeadlineExceedsUint48",
            QuoteError::DeadlineExceedsUint48 {
                field: "deadline",
                value: u64::MAX,
            }
        );
        push!(
            "QuoteError::NonZeroRootAuthorizationDigest",
            QuoteError::NonZeroRootAuthorizationDigest
        );
        push!(
            "QuoteError::UnsupportedFeeMode",
            QuoteError::UnsupportedFeeMode(3)
        );
        push!(
            "QuoteError::ChainTimeUnavailable",
            QuoteError::ChainTimeUnavailable(m.clone())
        );
        push!(
            "QuoteError::FeeTokenConfigHashToctouMismatch",
            QuoteError::FeeTokenConfigHashToctouMismatch {
                live_token: m.clone(),
                live_nonces: m.clone(),
            }
        );
        // No `MARKER`: two numbers, no string field — the same
        // deliberately-vacuous case as the three `Bad*` variants above.
        push!(
            "QuoteError::FeeScheduleDecimalsMismatch",
            QuoteError::FeeScheduleDecimalsMismatch {
                payload_decimals: 18,
                live_decimals: 6,
            }
        );
        push!(
            "QuoteError::InvalidQuoteSignerKey",
            QuoteError::InvalidQuoteSignerKey(m.clone())
        );
        push!(
            "QuoteError::SigningFailed",
            QuoteError::SigningFailed(m.clone())
        );
        push!(
            "QuoteError::MalformedPayload",
            QuoteError::MalformedPayload(m.clone())
        );
        push!(
            "QuoteError::IdempotencyKeyConflict",
            QuoteError::IdempotencyKeyConflict
        );
        push!(
            "QuoteError::StoredQuoteExpired",
            QuoteError::StoredQuoteExpired
        );

        // --- SubmitError -----------------------------------------------
        push!(
            "SubmitError::Sqlx",
            SubmitError::Sqlx(sqlx::Error::RowNotFound)
        );
        push!(
            "SubmitError::Crypto",
            SubmitError::Crypto(crate::stream_g::crypto_store::CryptoStoreError::DecryptionFailed)
        );
        push!(
            "SubmitError::Preflight",
            SubmitError::Preflight(PreflightError::ChainRead {
                what: "eth_call",
                detail: m.clone(),
            })
        );
        push!(
            "SubmitError::MalformedPayload",
            SubmitError::MalformedPayload(m.clone())
        );
        push!("SubmitError::IntentNotFound", SubmitError::IntentNotFound);
        push!("SubmitError::QuoteNotFound", SubmitError::QuoteNotFound);
        // 🔴 Wave C W3. Replaces `SubmitError::QuoteBindingMismatch`, deleted
        // with `bind_call_to_commitment`. This census is hand-maintained, so
        // the swap is recorded rather than implied.
        push!(
            "SubmitError::MalformedRequest",
            SubmitError::MalformedRequest(m.clone())
        );
        push!("SubmitError::NotRelayable", SubmitError::NotRelayable);
        push!(
            "SubmitError::SigningLeaseHeld",
            SubmitError::SigningLeaseHeld { key: m.clone() }
        );
        push!(
            "SubmitError::NonceAlreadyReserved",
            SubmitError::NonceAlreadyReserved {
                chain_id: 31337,
                signer: m.clone(),
                nonce: 1,
                holder: m.clone(),
            }
        );
        push!(
            "SubmitError::AlreadySubmitted",
            SubmitError::AlreadySubmitted {
                tx_hash_hex: m.clone(),
            }
        );
        push!(
            "SubmitError::SubmitInFlight",
            SubmitError::SubmitInFlight {
                attempt_id: m.clone(),
            }
        );
        push!(
            "SubmitError::BroadcastFailed",
            SubmitError::BroadcastFailed(m.clone())
        );
        push!(
            "SubmitError::BroadcastUnresolved",
            SubmitError::BroadcastUnresolved {
                tx_hash_hex: m.clone(),
                detail: m.clone(),
            }
        );
        push!(
            "SubmitError::ReconcileMismatch",
            SubmitError::ReconcileMismatch { field: "intent_id" }
        );
        push!(
            "SubmitError::ReconcileUnverifiable",
            SubmitError::ReconcileUnverifiable {
                attempt_id: m.clone(),
                reason: "no tx_hash",
            }
        );
        push!(
            "SubmitError::NonceOutOfRange",
            SubmitError::NonceOutOfRange(u64::MAX)
        );
        push!(
            "SubmitError::NativeExposure",
            SubmitError::NativeExposure(BaseFeeError::ExposureOverflow)
        );
        // 🔴 Wave C W2. `SubmitError::Broadcaster` delegates `code()` to
        // `BroadcasterError::code()`, so it is not one code but two, and each
        // one needs its own row here or the "no code maps to two statuses"
        // check has nothing to compare. `broadcaster_error_from` produces
        // exactly these two inner variants and no other.
        push!(
            "SubmitError::Broadcaster(Chain)",
            SubmitError::Broadcaster(crate::stream_g::broadcaster::BroadcasterError::Chain(
                m.clone()
            ))
        );
        push!(
            "SubmitError::Broadcaster(NonceRowConflict)",
            SubmitError::Broadcaster(
                crate::stream_g::broadcaster::BroadcasterError::NonceRowConflict {
                    chain_id: 8453,
                    signer: m.clone(),
                    nonce: u64::MAX,
                }
            )
        );

        // --- ProfileAuthError ------------------------------------------
        push!(
            "ProfileAuthError::Sqlx",
            ProfileAuthError::Sqlx(sqlx::Error::RowNotFound)
        );
        push!(
            "ProfileAuthError::InvalidDataKey",
            ProfileAuthError::InvalidDataKey(m.clone())
        );
        push!(
            "ProfileAuthError::ChallengeNotFound",
            ProfileAuthError::ChallengeNotFound
        );
        push!(
            "ProfileAuthError::ChallengeExpired",
            ProfileAuthError::ChallengeExpired
        );
        push!(
            "ProfileAuthError::NonceMismatch",
            ProfileAuthError::NonceMismatch
        );
        push!(
            "ProfileAuthError::OriginMismatch",
            ProfileAuthError::OriginMismatch
        );
        push!(
            "ProfileAuthError::ChallengeAlreadyConsumed",
            ProfileAuthError::ChallengeAlreadyConsumed
        );
        push!(
            "ProfileAuthError::ChallengeNotBoundToProfile",
            ProfileAuthError::ChallengeNotBoundToProfile
        );
        push!(
            "ProfileAuthError::ChallengeTypeMismatch",
            ProfileAuthError::ChallengeTypeMismatch
        );
        push!(
            "ProfileAuthError::CredentialNotFound",
            ProfileAuthError::CredentialNotFound
        );
        push!(
            "ProfileAuthError::SessionNotFound",
            ProfileAuthError::SessionNotFound
        );
        push!(
            "ProfileAuthError::SessionExpired",
            ProfileAuthError::SessionExpired
        );
        push!(
            "ProfileAuthError::SessionRevoked",
            ProfileAuthError::SessionRevoked
        );
        push!(
            "ProfileAuthError::MalformedPayload",
            ProfileAuthError::MalformedPayload(m.clone())
        );
        push!(
            "ProfileAuthError::IdempotencyKeyConflict",
            ProfileAuthError::IdempotencyKeyConflict
        );
        push!(
            "ProfileAuthError::AliasAlreadyAttached",
            ProfileAuthError::AliasAlreadyAttached
        );

        // --- RootAuthorizationError ------------------------------------
        push!(
            "RootAuthorizationError::Sqlx",
            RootAuthorizationError::Sqlx(sqlx::Error::RowNotFound)
        );
        push!(
            "RootAuthorizationError::InvalidIssuerKey",
            RootAuthorizationError::InvalidIssuerKey(m.clone())
        );
        push!(
            "RootAuthorizationError::SigningFailed",
            RootAuthorizationError::SigningFailed(m.clone())
        );
        push!(
            "RootAuthorizationError::MalformedPayload",
            RootAuthorizationError::MalformedPayload(m.clone())
        );
        push!(
            "RootAuthorizationError::BadWallet",
            RootAuthorizationError::BadWallet(m.clone())
        );
        push!(
            "RootAuthorizationError::BadDigest",
            RootAuthorizationError::BadDigest(m.clone())
        );
        push!(
            "RootAuthorizationError::ZeroRoot",
            RootAuthorizationError::ZeroRoot
        );
        push!(
            "RootAuthorizationError::IntentNotFound",
            RootAuthorizationError::IntentNotFound
        );
        push!(
            "RootAuthorizationError::NonStandaloneSecondary",
            RootAuthorizationError::NonStandaloneSecondary
        );
        push!(
            "RootAuthorizationError::NonStandaloneLinkDigest",
            RootAuthorizationError::NonStandaloneLinkDigest
        );
        push!(
            "RootAuthorizationError::ZeroEnrollDigest",
            RootAuthorizationError::ZeroEnrollDigest
        );
        push!(
            "RootAuthorizationError::DeadlineExceedsUint48",
            RootAuthorizationError::DeadlineExceedsUint48
        );
        push!(
            "RootAuthorizationError::DeadlineExceedsPolicy",
            RootAuthorizationError::DeadlineExceedsPolicy
        );
        push!(
            "RootAuthorizationError::IdempotencyKeyConflict",
            RootAuthorizationError::IdempotencyKeyConflict
        );
        push!(
            "RootAuthorizationError::InjectedTestFailure",
            RootAuthorizationError::InjectedTestFailure
        );

        // --- OnboardingError -------------------------------------------
        push!(
            "OnboardingError::Sqlx",
            OnboardingError::Sqlx(sqlx::Error::RowNotFound)
        );
        push!(
            "OnboardingError::IntentNotFound",
            OnboardingError::IntentNotFound
        );
        push!(
            "OnboardingError::IllegalTransition",
            OnboardingError::IllegalTransition {
                from: m.clone(),
                to: m.clone(),
            }
        );
        push!(
            "OnboardingError::EntitlementExhausted",
            OnboardingError::EntitlementExhausted
        );
        push!(
            "OnboardingError::MalformedPayload",
            OnboardingError::MalformedPayload(m.clone())
        );
        push!(
            "OnboardingError::BadAddress",
            OnboardingError::BadAddress(m.clone())
        );
        push!(
            "OnboardingError::WalletAlreadyBound",
            OnboardingError::WalletAlreadyBound
        );

        // --- PreflightError --------------------------------------------
        push!(
            "PreflightError::TokenState",
            PreflightError::TokenState(TokenManifestError::ChainRead {
                what: "eth_getCode",
                detail: m.clone(),
            })
        );
        push!(
            "PreflightError::Nonces",
            PreflightError::Nonces(LiveNoncesError::ChainRead { detail: m.clone() })
        );
        push!(
            "PreflightError::EndpointChainMismatch",
            PreflightError::EndpointChainMismatch {
                endpoint_chain_id: 1,
                manifest_chain_id: 31337,
            }
        );
        push!(
            "PreflightError::StateMisbound",
            PreflightError::StateMisbound {
                what: "root",
                read_for: m.clone(),
                intent: m.clone(),
            }
        );
        push!(
            "PreflightError::SnapshotToctouMismatch",
            PreflightError::SnapshotToctouMismatch {
                live_token: m.clone(),
                snapshot: m.clone(),
            }
        );
        push!(
            "PreflightError::PermitWouldRevert",
            PreflightError::PermitWouldRevert {
                site: "StreamGCommon.sol:200 (collectEip2612)",
                detail: m.clone(),
            }
        );
        push!(
            "PreflightError::PermitNonceMisbound",
            PreflightError::PermitNonceMisbound {
                owner: m.clone(),
                token_nonce: 1,
                snapshot_nonce: 2,
                block: 3,
            }
        );

        // --- Leaf enums reached only by delegation ---------------------
        push!(
            "TokenManifestError::ZeroRequiredCapability",
            TokenManifestError::ZeroRequiredCapability
        );
        push!(
            "TokenManifestError::ProxyIdentityUnsupported",
            TokenManifestError::ProxyIdentityUnsupported
        );
        push!(
            "TokenManifestError::ManifestChainMismatch",
            TokenManifestError::ManifestChainMismatch {
                manifest_chain_id: 1,
                configured_chain_id: 31337,
            }
        );
        push!(
            "TokenManifestError::ManifestPhaseMismatch",
            TokenManifestError::ManifestPhaseMismatch {
                manifest_phase: m.clone(),
            }
        );
        push!(
            "TokenManifestError::Io",
            TokenManifestError::Io {
                path: format!("C:/{MARKER}/manifest.json"),
                detail: m.clone(),
            }
        );
        push!(
            "TokenManifestError::Parse",
            TokenManifestError::Parse {
                path: format!("C:/{MARKER}/manifest.json"),
                detail: m.clone(),
            }
        );
        push!(
            "TokenManifestError::FeeTokenConfigHashMismatch",
            TokenManifestError::FeeTokenConfigHashMismatch {
                computed: m.clone(),
                registry: m.clone(),
            }
        );
        push!(
            "BaseFeeError::Chain",
            BaseFeeError::Chain(crate::chain::ChainError::Msg(m.clone()))
        );
        push!(
            "BaseFeeError::TxSizeOverflow",
            BaseFeeError::TxSizeOverflow(1)
        );
        push!("BaseFeeError::ZeroGasUnits", BaseFeeError::ZeroGasUnits);
        push!(
            "BaseFeeError::ZeroTxSizeCeiling",
            BaseFeeError::ZeroTxSizeCeiling
        );
        push!(
            "BaseFeeError::EmptyTransaction",
            BaseFeeError::EmptyTransaction
        );
        push!(
            "LiveNoncesError::FieldNotPresent",
            LiveNoncesError::FieldNotPresent {
                field: "SNAP_CONTROLLER",
                bit: 1,
                present_mask: 0,
            }
        );
        push!(
            "LiveNoncesError::FeeTokenUnauthorizedBySnapshot",
            LiveNoncesError::FeeTokenUnauthorizedBySnapshot { present_mask: 0 }
        );
        push!(
            "LiveNoncesError::NonceOutOfRange",
            LiveNoncesError::NonceOutOfRange {
                field: "actionNonce",
                value: u128::MAX,
            }
        );

        // --- Rate limiting ---------------------------------------------
        push!(
            "StreamGRateLimitError::Global",
            StreamGRateLimitError::Global
        );
        push!(
            "StreamGRateLimitError::Registration",
            StreamGRateLimitError::Registration
        );
        push!(
            "StreamGRateLimitError::Profile",
            StreamGRateLimitError::Profile
        );
        push!(
            "StreamGRateLimitError::TrackingCapacity",
            StreamGRateLimitError::TrackingCapacity
        );

        // --- Route-decided refusals ------------------------------------
        //
        // Not `push!`: these have no originating enum, so there is no
        // `ApiError::from` to call. They belong in the census all the same —
        // it is the list of everything that can reach a client, not the list
        // of everything with a `From` impl.
        out.push(("ApiError::no_live_chain", ApiError::no_live_chain()));
        // 🔴 Wave C W4. Route-reachable on `POST /v1/stream-g/submit` only —
        // `submit::post_submit`'s first statement. Same reason as the entry
        // above: no enum means this condition, so `push!` has nothing to call.
        out.push((
            "ApiError::exposure_ceiling_unset",
            ApiError::exposure_ceiling_unset(),
        ));
        // `MISSING_CREDENTIAL` is route-reachable on `POST /v1/profile/challenges`,
        // `DELETE /v1/profile/sessions/:id`,
        // `GET /v1/profile/primary-onboarding/:intentId`,
        // `POST /v1/stream-g/quotes` and `GET /v1/stream-g/status/:intentId` —
        // every route taking `profile_auth::AuthenticatedProfile` — but was
        // absent here, so it escaped both `every_error_code_maps_to_exactly_one_status`
        // and `stream_g_error_mapping_never_emits_403`. The production
        // constructor is called rather than an equivalent `ApiError::new`, so
        // this entry cannot drift from what the routes actually emit.
        out.push((
            "profile_auth::missing_credential",
            crate::stream_g::profile_auth::missing_credential(MARKER),
        ));

        out
    }

    /// Capture buffer for `tracing` output on this thread. Same shape as
    /// `mod.rs::tests::CapturedLog`, duplicated rather than shared because
    /// that one is private to its own `mod tests`.
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

    async fn body_string(res: Response) -> String {
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// **The leak test.** Every route-reachable error, rendered, must produce
    /// exactly `{"error":"CODE"}` — no path, no address, no attempt id, no
    /// nested `Display` prose — while the marker-laden detail *does* reach
    /// `tracing`.
    ///
    /// Modelled on
    /// `readiness::tests::the_readiness_document_never_echoes_payload_or_key_material`:
    /// plant a marker in every string field, then assert absence in the
    /// document and presence in the operator channel. The log half is the
    /// paired non-zero arm — without it, deleting the `detail` field from
    /// both the body and the log would still pass.
    ///
    /// Mutation this detects: adding a `detail: String` field to
    /// [`ApiErrorBody`] and populating it from `ApiError::detail`.
    #[tokio::test]
    async fn stream_g_error_bodies_carry_the_code_and_nothing_else() {
        // Without this the `tracing::warn!` at line 257 can already be cached
        // process-wide as `Interest::never()` by a subscriber-less test that
        // rendered an `ApiError` first, and the log half below reads empty.
        // See `crate::stream_g::log_capture`.
        crate::stream_g::log_capture::install_interest_keepalive();
        let buf = CapturedLog(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();

        let mut rendered: Vec<(&'static str, &'static str, String)> = Vec::new();
        {
            let _guard = tracing::subscriber::set_default(subscriber);
            for (name, err) in census() {
                let code = err.code();
                let body = body_string(err.into_response()).await;
                rendered.push((name, code, body));
            }
        }

        for (name, code, body) in &rendered {
            assert_eq!(
                body,
                &format!("{{\"error\":\"{code}\"}}"),
                "{name} rendered an unexpected body"
            );
            assert!(
                !body.contains(MARKER),
                "{name} leaked internal text into the response body: {body}"
            );
        }

        // Paired non-zero arm: the detail exists and went to the operator.
        let log = String::from_utf8_lossy(
            &buf.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
        .into_owned();
        assert!(
            log.contains(MARKER),
            "no marker reached tracing — the assertions above are about an \
             error type that carries no detail at all, which proves nothing: {log}"
        );
        assert!(
            log.contains("stream G request failed") && log.contains("stream G request refused"),
            "both the 5xx and the non-5xx log arms must have been exercised: {log}"
        );
    }

    /// **The ownership-oracle tripwire.** No route-reachable error may map to
    /// 403. See the module doc: a 403 is by definition "this exists and is not
    /// yours", which is the distinction three enums deliberately erase in the
    /// store and which the HTTP layer must not put back.
    ///
    /// Mutation this detects: mapping any `IntentNotFound` to
    /// `StatusCode::FORBIDDEN`.
    #[test]
    fn stream_g_error_mapping_never_emits_403() {
        for (name, err) in census() {
            assert_ne!(
                err.status(),
                StatusCode::FORBIDDEN,
                "{name} maps to 403, which tells a caller a resource exists that is not theirs"
            );
        }

        // Paired non-zero arm: the census really does contain the three
        // "not found or not yours" variants, and they all answer 404.
        for name in [
            "SubmitError::IntentNotFound",
            "OnboardingError::IntentNotFound",
            "RootAuthorizationError::IntentNotFound",
        ] {
            let found = census()
                .into_iter()
                .find(|(n, _)| *n == name)
                .unwrap_or_else(|| panic!("{name} missing from the census"));
            assert_eq!(found.1.status(), StatusCode::NOT_FOUND, "{name}");
        }
    }

    /// One public code, one meaning — with **one named exception this test
    /// found rather than assumed**.
    ///
    /// `LiveNoncesError::FeeTokenUnauthorizedBySnapshot` deliberately reuses
    /// `token_manifest::ERR_TOKEN_UNSUPPORTED`, and `SubmitError`/`QuoteError`
    /// delegate to their wrapped errors' codes, so the same string genuinely
    /// arrives from several enums. If two of them chose different statuses the
    /// code would mean two things on the wire.
    ///
    /// # The exception: [`ERR_INTERNAL`]
    ///
    /// Every module's pre-existing `code()` ends in `_ => "INTERNAL"` (they
    /// predate this wave and are not changed by it). That fallback is not a
    /// code that identifies a condition — it is the *absence* of one — and it
    /// is reached from conditions this wave classifies differently:
    /// `QuoteError::Store` is 500 while `BaseFeeError::Chain` is 502, and both
    /// say `INTERNAL`. So `INTERNAL` is carved out here, by name, and the
    /// carve-out is asserted to be the **only** one: a real code that becomes
    /// ambiguous still fails this test.
    ///
    /// The second assertion below fails if `INTERNAL` ever stops being
    /// ambiguous. That is deliberate — it means the `_ =>` fallbacks were
    /// tightened, and this carve-out should be deleted rather than left
    /// quietly excusing nothing.
    ///
    /// Mutation this detects: changing
    /// `LiveNoncesError::FeeTokenUnauthorizedBySnapshot` to any status other
    /// than `TokenManifestError::TokenNotAuthorized`'s.
    #[test]
    fn every_error_code_maps_to_exactly_one_status() {
        let mut seen: BTreeMap<&'static str, (StatusCode, &'static str)> = BTreeMap::new();
        let mut ambiguous: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
        for (name, err) in census() {
            let (code, status) = (err.code(), err.status());
            match seen.get(code) {
                Some((prior_status, prior_name)) if *prior_status != status => {
                    ambiguous
                        .entry(code)
                        .or_default()
                        .push(format!("{prior_name}={prior_status}, {name}={status}"));
                }
                Some(_) => {}
                None => {
                    seen.insert(code, (status, name));
                }
            }
        }

        let unexpected: Vec<_> = ambiguous
            .keys()
            .copied()
            .filter(|c| *c != ERR_INTERNAL)
            .collect();
        assert!(
            unexpected.is_empty(),
            "these codes mean two different things on the wire: {unexpected:?} ({ambiguous:?})"
        );
        assert!(
            ambiguous.contains_key(ERR_INTERNAL),
            "INTERNAL is no longer ambiguous — the `_ => \"INTERNAL\"` fallbacks were tightened, \
             so delete the carve-out in this test rather than leaving it excusing nothing"
        );

        // Paired non-zero arm: at least one *real* code was produced by two
        // different enums, so the loop above compared something other than the
        // carve-out.
        let shared = census()
            .into_iter()
            .filter(|(_, e)| e.code() == crate::stream_g::token_manifest::ERR_TOKEN_UNSUPPORTED)
            .count();
        assert!(
            shared >= 2,
            "expected TOKEN_UNSUPPORTED from both token_manifest and models; saw {shared}"
        );
    }

    // -----------------------------------------------------------------
    // Extractor rejections.
    // -----------------------------------------------------------------

    /// A synthetic route that exists only to drive [`ApiJson`] in isolation.
    /// Not part of `super::super::router`; the production router now mounts
    /// two `ApiJson` bodies of its own (`POST /v1/profile` and
    /// `POST /v1/stream-g/quotes`, the latter carrying this very DTO), and
    /// this probe is kept because it reaches the extractor without an
    /// authentication or live-chain refusal getting there first. The DTO is
    /// the real production one (`CreateSponsoredEnrollmentQuoteRequest`, the
    /// crate's largest and the only one with `deny_unknown_fields` on a wire
    /// shape).
    fn extractor_app() -> Router {
        async fn ok(
            ApiJson(_): ApiJson<crate::stream_g::models::CreateSponsoredEnrollmentQuoteRequest>,
        ) -> StatusCode {
            StatusCode::OK
        }
        Router::new().route("/probe", post(ok))
    }

    async fn probe_body(headers: &[(&str, &str)], body: &str) -> (StatusCode, String) {
        let mut builder = Request::builder().method("POST").uri("/probe");
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let res = extractor_app()
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = res.status();
        (status, body_string(res).await)
    }

    /// **Item 2.** All four extractor rejections answer with the Stream G
    /// envelope, not axum's `text/plain` default.
    ///
    /// Mutation this detects: changing `ApiJson`'s handler signature back to
    /// `Json<T>` — every arm below then returns axum's plain-text body and the
    /// JSON assertions fail.
    #[tokio::test]
    async fn extractor_rejections_use_the_same_json_envelope() {
        let json = [("content-type", "application/json")];

        // (a) Not JSON at all.
        let (status, body) = probe_body(&json, "{not json").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, format!("{{\"error\":\"{ERR_INVALID_JSON}\"}}"));

        // (b) Valid JSON, wrong shape (missing every field).
        let (status, body) = probe_body(&json, "{}").await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body,
            format!("{{\"error\":\"{ERR_INVALID_REQUEST_SHAPE}\"}}")
        );

        // (c) `deny_unknown_fields` — a complete, otherwise-valid body plus one
        // extra key. This is the arm that proves the DTO's own attribute is
        // reachable through the extractor, not merely that `{}` fails.
        let mut value: serde_json::Value = serde_json::from_str(&max_quote_request_json()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("feeRecipient".into(), serde_json::json!("0x00"));
        let (status, body) = probe_body(&json, &value.to_string()).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body,
            format!("{{\"error\":\"{ERR_INVALID_REQUEST_SHAPE}\"}}")
        );

        // (d) No `Content-Type: application/json`.
        let (status, body) = probe_body(&[], "{}").await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            body,
            format!("{{\"error\":\"{ERR_UNSUPPORTED_MEDIA_TYPE}\"}}")
        );

        // Paired non-zero arm: the same route accepts a well-formed body, so
        // the four refusals above are about the rejection mapping and not
        // about a route that refuses everything.
        let (status, _) = probe_body(&json, &max_quote_request_json()).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// The rejection's own prose (which can name the offending field) must not
    /// travel to the client, and must reach the operator.
    ///
    /// The `install_interest_keepalive` call is not decoration: without it this
    /// test failed 6 times in 30 full `cargo test --lib` runs (20%) at the log
    /// assertion below, because whichever of the ~630 tests first rendered an
    /// `ApiError` on a subscriber-less thread cached line 257's `tracing::warn!`
    /// callsite as `Interest::never()` for the whole process. It passed 40/40
    /// when run alone, which is the signature of that race rather than of
    /// anything in this test. See `crate::stream_g::log_capture`.
    #[tokio::test]
    async fn extractor_rejection_detail_goes_to_tracing_not_to_the_client() {
        crate::stream_g::log_capture::install_interest_keepalive();
        let buf = CapturedLog(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();

        let body = {
            let _guard = tracing::subscriber::set_default(subscriber);
            probe_body(&[("content-type", "application/json")], "{}")
                .await
                .1
        };

        assert_eq!(
            body,
            format!("{{\"error\":\"{ERR_INVALID_REQUEST_SHAPE}\"}}")
        );
        assert!(!body.contains("idempotency_key"), "{body}");

        let log = String::from_utf8_lossy(
            &buf.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
        .into_owned();
        assert!(
            log.contains("Failed to deserialize"),
            "axum's rejection prose must reach the operator: {log}"
        );
    }

    /// "This process has no chain" is a **503**, and the status is the whole
    /// point of the code — see [`ApiError::no_live_chain`]. A 4xx would tell a
    /// caller their request was wrong when the identical request against a
    /// non-mock process is served; a 500 would say this process is broken when
    /// it started cleanly and is merely not configured for chain-backed routes.
    ///
    /// Mutation this detects: changing the constructor's status to
    /// `INTERNAL_SERVER_ERROR` or to any 4xx.
    #[test]
    fn no_live_chain_is_a_503_and_not_the_callers_fault() {
        let err = ApiError::no_live_chain();
        assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.code(), ERR_NO_LIVE_CHAIN);
        assert!(
            !err.status().is_client_error(),
            "a mock-mode deployment is not the caller's fault"
        );
        assert_eq!(
            err.body(),
            ApiErrorBody {
                error: "NO_LIVE_CHAIN"
            }
        );
    }
}
