//! HTTP surface for the fetch-network revenue lane. Three routes, all
//! fail-closed.
//!
//! `GET  /v1/proxy/ready`          -- four live checks, no "unknown" state.
//! `POST /v1/proxy/receipts`       -- submit one bundle; runs the ten
//!                                    verification stages and either stores or
//!                                    returns a typed refusal naming the stage.
//! `GET  /v1/proxy/meter/:epochId` -- the proposer's view of the gateway meter
//!                                    commitment it fetched, for a challenger
//!                                    that wants to see what the proposer saw.
//!                                    It is NOT the authority: a challenger
//!                                    fetches the gateway's endpoint directly
//!                                    and compares.
//!
//! # The lane is off by default and this file must not change that
//!
//! [`ProxyConfig::enabled`] is false unless `PROXY_ENABLED` is explicitly
//! truthy, and the whole capability is [TARGET]. Mounting a router is exactly
//! the edit that can make a disabled lane reachable, so the gate is not a
//! comment in `main.rs`: it is [`mount`], a function whose two arms are driven
//! by `the_lane_is_unreachable_while_it_is_disabled` and
//! `the_three_routes_bind_when_the_lane_is_enabled`. Delete the gate and the
//! first of those goes red on a 404 that became a 503.
//!
//! # What is NOT here
//!
//! No store handle, no party directory and no allowlist manifest is injected on
//! this state yet, so [`RECEIPT_INTAKE_WIRED`] is false and the two data routes
//! refuse with [`ProxyRefusal`] rather than pretending. `/v1/proxy/ready`
//! reports that as a *failed named check*, never as an absent or unknown one --
//! a readiness report that omits what it could not do is a report that reads
//! green for the wrong reason.
//!
//! Nothing in this module issues supply and nothing in it destroys supply. It
//! answers three HTTP requests.
//!
//! # `:epochId` (colon), not `{epochId}`
//!
//! This crate runs axum 0.7 / matchit 0.7, where `{` and `}` are ordinary path
//! characters: `"/v1/proxy/meter/{epochId}"` compiles, does not panic, and
//! matches only the literal segment `{epochId}`. Every path parameter in this
//! crate is therefore `:name`, and
//! `the_meter_route_binds_the_epoch_id_from_the_path` is what makes
//! "modernising" this one to the brace form a failing test rather than a silent
//! outage.

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::config::ProxyConfig;
use crate::proxy::proxy_merkle::is_proxy_epoch;
use crate::proxy::PROXY_CHAIN_ALLOWLIST;

/// Whether a submitted bundle can reach the ten verification stages.
///
/// **False, and it is a constant rather than a `TODO` for a reason.** The stages
/// need a store handle, a `ProxyPartyDirectory` and the in-force allowlist
/// manifest; none of the three is injected on [`ProxyState`] yet. A route that
/// verified against a directory that knows nobody would return "accepted" for a
/// bundle no party had signed, which is worse than a refusal.
///
/// When the wiring lands, flipping this to `true` reds
/// `an_unwired_lane_refuses_a_submission_instead_of_accepting_it`, which is the
/// point: the test that pins today's refusal is what forces the next
/// implementer to state the new behaviour rather than inherit it.
pub const RECEIPT_INTAKE_WIRED: bool = false;

/// Largest accepted `POST /v1/proxy/receipts` body, in bytes.
///
/// Arithmetic, not a copied constant. One bundle is a 16-field receipt, an
/// 11-field intent, a 5-field witness and three 65-byte secp256k1 signatures.
/// Every integer crosses the canonical boundary as a decimal STRING and every
/// identifier as `0x` + 64 hex, so the widest honest encoding is under 3 KiB;
/// 16 KiB leaves room for whitespace-formatted submissions without leaving room
/// for a body that is doing something else.
///
/// The limit is live rather than decorative because [`post_receipt`] takes
/// `axum::body::Bytes`: `DefaultBodyLimit` inserts an extension that
/// `Bytes::from_request` consults, so a route that never reads a body never
/// enforces it. `a_submission_over_the_body_limit_is_refused_by_the_transport`
/// drives a real oversize request through the real router.
pub const PROXY_BODY_LIMIT_BYTES: usize = 16 * 1024;

/// Everything the three handlers read.
///
/// Taken by value at wiring time rather than read from globals, so there is no
/// way to build this router without having resolved the lane's configuration
/// first.
#[derive(Clone, Debug)]
pub struct ProxyState {
    pub config: ProxyConfig,
    // The store handle, gateway registry and allowlist manifest are injected by
    // `main.rs` at wiring time, so a request never opens a file. None of the
    // three exists yet -- see `RECEIPT_INTAKE_WIRED`.
}

impl ProxyState {
    pub fn new(config: ProxyConfig) -> Self {
        Self { config }
    }
}

/// One named readiness check. `passed` is always a decision; there is no third
/// state and no absent check.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ProxyCheck {
    pub name: &'static str,
    pub passed: bool,
    /// Structural only: "configured" or "absent". **Never** a configured
    /// endpoint, address or digest; the test
    /// `the_readiness_report_never_echoes_a_configured_endpoint` sweeps
    /// this field with a negative control, because an operator-facing report is
    /// the easiest place for a destination to leak back out of a lane whose
    /// whole design keeps them out.
    pub detail: &'static str,
}

/// `GET /v1/proxy/ready`'s body.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ProxyReadiness {
    pub lane: &'static str,
    /// `TARGET`. Every capability on this lane is a design target, and a
    /// readiness route that did not say so would be read as a shipped one.
    pub maturity: &'static str,
    pub checks: Vec<ProxyCheck>,
    /// True only when every check passed.
    pub ready: bool,
}

impl ProxyReadiness {
    /// 200 when every check passed, 503 otherwise. Fail-closed: a report with
    /// no checks at all is not ready.
    pub fn status(&self) -> StatusCode {
        if self.ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

/// Why a request was refused. Byte counts, integer identifiers and fixed
/// constants only -- the same rule the verification refusals are held to.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ProxyRefusal {
    /// A stable machine-readable token, not prose.
    pub refusal: &'static str,
    pub detail: String,
}

/// The four checks, evaluated against the live configuration.
///
/// Ordered from "could this lane name a deployment at all" outwards, so the
/// first failure is the most fundamental one.
pub fn evaluate(config: &ProxyConfig) -> ProxyReadiness {
    let chain_permitted = config
        .chain_id
        .is_some_and(|id| PROXY_CHAIN_ALLOWLIST.contains(&id));
    let settlement_configured =
        config.settlement_address.is_some() && config.consumer_registry_address.is_some();
    let gateway_configured = config.gateway_id.is_some() && config.meter_endpoint.is_some();

    let checks = vec![
        ProxyCheck {
            name: "chain_permitted",
            passed: chain_permitted,
            detail: if chain_permitted {
                "resolved to a permitted chain"
            } else {
                "unset, or not a chain this lane may settle on"
            },
        },
        ProxyCheck {
            name: "settlement_configured",
            passed: settlement_configured,
            detail: if settlement_configured {
                "settlement and consumer registry configured"
            } else {
                "settlement or consumer registry absent"
            },
        },
        ProxyCheck {
            name: "gateway_configured",
            passed: gateway_configured,
            detail: if gateway_configured {
                "gateway id and meter origin configured"
            } else {
                "gateway id or meter origin absent"
            },
        },
        ProxyCheck {
            name: "receipt_intake_wired",
            passed: RECEIPT_INTAKE_WIRED,
            detail: if RECEIPT_INTAKE_WIRED {
                "store, party directory and allowlist manifest injected"
            } else {
                "no store, party directory or allowlist manifest is injected"
            },
        },
    ];
    let ready = checks.iter().all(|c| c.passed);
    ProxyReadiness {
        lane: "proxy-revenue",
        maturity: "TARGET",
        checks,
        ready,
    }
}

/// `GET /v1/proxy/ready` -- four live checks, fail-closed, no unknown state.
async fn ready(State(state): State<ProxyState>) -> (StatusCode, Json<ProxyReadiness>) {
    let report = evaluate(&state.config);
    (report.status(), Json(report))
}

/// `POST /v1/proxy/receipts` -- one bundle, ten stages, store or typed refusal.
///
/// Refuses `LaneNotWired` today; see [`RECEIPT_INTAKE_WIRED`] for why that is a
/// refusal rather than a partial acceptance. The body is buffered (and
/// therefore length-limited) before the refusal so the transport bound is real.
async fn post_receipt(
    State(_state): State<ProxyState>,
    body: axum::body::Bytes,
) -> (StatusCode, Json<ProxyRefusal>) {
    let submitted = body.len();
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ProxyRefusal {
            refusal: "LaneNotWired",
            detail: format!(
                "the ten verification stages have no store, party directory or allowlist \
                 manifest to run against; {submitted} submitted byte(s) were not read"
            ),
        }),
    )
}

/// `GET /v1/proxy/meter/:epochId` -- the proposer's view of the commitment it
/// fetched, never the authority.
///
/// The epoch id is checked against the fetch-network id space **before** the
/// wiring refusal, so a malformed or out-of-space id is a 400 and a well-formed
/// one is a 503. That difference is what proves the path parameter binds at all.
async fn get_meter(
    State(_state): State<ProxyState>,
    Path(epoch_id): Path<String>,
) -> (StatusCode, Json<ProxyRefusal>) {
    let parsed = epoch_id
        .parse::<u64>()
        .ok()
        .filter(|id| is_proxy_epoch(*id));
    match parsed {
        None => (
            StatusCode::BAD_REQUEST,
            Json(ProxyRefusal {
                refusal: "EpochOutsideProxySpace",
                detail: format!(
                    "{} character(s) of path parameter do not name an epoch in the \
                     fetch-network id space",
                    epoch_id.chars().count()
                ),
            }),
        ),
        Some(id) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ProxyRefusal {
                refusal: "LaneNotWired",
                detail: format!(
                    "epoch {id} is in the fetch-network id space, but no store is injected to \
                     read a commitment from"
                ),
            }),
        ),
    }
}

/// Build the lane's router over the startup state.
///
/// Callers must only mount this when [`ProxyConfig::enabled`] is true -- use
/// [`mount`], which is the gate itself rather than a rule about one.
pub fn router(state: ProxyState) -> Router {
    Router::new()
        .route("/v1/proxy/ready", get(ready))
        .route("/v1/proxy/receipts", post(post_receipt))
        .route("/v1/proxy/meter/:epochId", get(get_meter))
        .layer(DefaultBodyLimit::max(PROXY_BODY_LIMIT_BYTES))
        .with_state(state)
}

/// Merge the lane's routes onto `app` **only** when the lane is enabled.
///
/// This is the whole mount decision, in the library where a test can drive both
/// arms, rather than an `if` in `main.rs` that nothing can reach. Config
/// validation already ran unconditionally (`ProxyConfig::validate`), so reaching
/// the enabled arm means the values are sound.
pub fn mount(app: Router, config: &ProxyConfig) -> Router {
    if config.enabled {
        app.merge(router(ProxyState::new(config.clone())))
    } else {
        app
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// A configuration with every optional field set to something well-shaped,
    /// so a readiness failure in a test is about the check under test and not
    /// about a field nobody filled in.
    fn wired_config(enabled: bool) -> ProxyConfig {
        ProxyConfig {
            enabled,
            settlement_address: Some(format!("0x{}", "11".repeat(20))),
            consumer_registry_address: Some(format!("0x{}", "22".repeat(20))),
            gateway_id: Some(format!("0x{}", "33".repeat(32))),
            meter_endpoint: Some("https://gateway.invalid/v1/meter".to_string()),
            chain_id: Some(31_337),
            verifying_contract: Some(format!("0x{}", "11".repeat(20))),
            protocol_take_bps: 1_000,
            epoch_byte_ceiling: crate::proxy::MAX_EPOCH_BYTE_CEILING,
            pair_concentration_bps: 2_500,
            price_goat_wei_per_mebibyte: 1_000_000_000_000,
            allowlist_manifest_digest: Some(format!("0x{}", "44".repeat(32))),
            meter_min_request_interval_ms: crate::proxy::DEFAULT_METER_MIN_REQUEST_INTERVAL_MS,
            receipt_page_size: crate::proxy::DEFAULT_RECEIPT_PAGE_SIZE,
        }
    }

    /// The pilot surface this lane is merged onto, standing in for the relayer
    /// router `main.rs` actually builds. It carries one route so the "disabled"
    /// assertion below cannot pass against an app that is empty for some other
    /// reason.
    fn host_app() -> Router {
        Router::new().route("/v1/host/probe", get(|| async { "probe" }))
    }

    async fn status_of(app: Router, method: &str, uri: &str) -> StatusCode {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .expect("request builds");
        app.oneshot(req).await.expect("router responds").status()
    }

    /// The gate, from the outside: with `PROXY_ENABLED` false every one of the
    /// three paths is a 404, and the host surface still answers.
    ///
    /// Mutations this detects: deleting the `if config.enabled` arm of
    /// [`mount`]; inverting it; `main.rs` calling [`router`] directly instead of
    /// [`mount`]. Each turns at least one 404 below into a 503 or a 400.
    #[tokio::test]
    async fn the_lane_is_unreachable_while_it_is_disabled() {
        let cfg = wired_config(false);
        assert!(!cfg.enabled, "this test is about the disabled lane");

        // POSITIVE CONTROL: the host surface is mounted and answering, so the
        // 404s below are about the proxy routes and not about a dead app.
        assert_eq!(
            status_of(mount(host_app(), &cfg), "GET", "/v1/host/probe").await,
            StatusCode::OK
        );

        for (method, uri) in [
            ("GET", "/v1/proxy/ready"),
            ("POST", "/v1/proxy/receipts"),
            ("GET", "/v1/proxy/meter/8000000020664"),
        ] {
            assert_eq!(
                status_of(mount(host_app(), &cfg), method, uri).await,
                StatusCode::NOT_FOUND,
                "{method} {uri} answered while the lane is disabled"
            );
        }
    }

    /// The other arm: enabled, every path binds, and none of them 404s.
    #[tokio::test]
    async fn the_three_routes_bind_when_the_lane_is_enabled() {
        let cfg = wired_config(true);
        for (method, uri) in [
            ("GET", "/v1/proxy/ready"),
            ("POST", "/v1/proxy/receipts"),
            ("GET", "/v1/proxy/meter/8000000020664"),
        ] {
            let got = status_of(mount(host_app(), &cfg), method, uri).await;
            assert_ne!(
                got,
                StatusCode::NOT_FOUND,
                "{method} {uri} did not bind on the enabled lane"
            );
        }
        // The host surface survives the merge.
        assert_eq!(
            status_of(mount(host_app(), &cfg), "GET", "/v1/host/probe").await,
            StatusCode::OK
        );
        // A path this lane does not claim is still a 404 -- the merge adds three
        // routes, not a fallback.
        assert_eq!(
            status_of(mount(host_app(), &cfg), "GET", "/v1/proxy/nothing").await,
            StatusCode::NOT_FOUND
        );
    }

    /// Readiness is fail-closed and names every check, including the one that
    /// fails. There is no unknown state.
    ///
    /// Mutations this detects: dropping the `receipt_intake_wired` check from
    /// the list instead of reporting it false; computing `ready` from anything
    /// other than "every check passed"; returning 200 with a failed check.
    #[tokio::test]
    async fn readiness_names_four_checks_and_fails_closed_on_the_unwired_one() {
        let cfg = wired_config(true);
        let report = evaluate(&cfg);
        assert_eq!(report.checks.len(), 4, "four checks, no more and no fewer");
        assert_eq!(report.maturity, "TARGET");

        let names: Vec<&str> = report.checks.iter().map(|c| c.name).collect();
        assert_eq!(
            names,
            vec![
                "chain_permitted",
                "settlement_configured",
                "gateway_configured",
                "receipt_intake_wired",
            ]
        );

        // POSITIVE CONTROL: three of the four DO pass on a fully-configured
        // lane, so the 503 below is the fourth check firing and not a report
        // that fails everything.
        let passed = report.checks.iter().filter(|c| c.passed).count();
        assert_eq!(passed, 3, "checks: {:?}", report.checks);
        assert!(!report.ready);
        assert_eq!(report.status(), StatusCode::SERVICE_UNAVAILABLE);

        // ...and the same report over the wire.
        let req = Request::builder()
            .uri("/v1/proxy/ready")
            .body(Body::empty())
            .unwrap();
        let res = mount(host_app(), &cfg).oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["ready"], serde_json::json!(false));
        assert_eq!(parsed["checks"].as_array().unwrap().len(), 4);
    }

    /// A misconfigured lane fails the checks that describe the misconfiguration
    /// and no others -- the complement of the test above, so neither can pass
    /// against a report that is constant.
    #[tokio::test]
    async fn readiness_fails_exactly_the_checks_whose_configuration_is_absent() {
        let mut cfg = wired_config(true);
        cfg.chain_id = None;
        cfg.gateway_id = None;
        let report = evaluate(&cfg);
        let failed: Vec<&str> = report
            .checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.name)
            .collect();
        assert_eq!(
            failed,
            vec![
                "chain_permitted",
                "gateway_configured",
                "receipt_intake_wired"
            ]
        );

        // A chain id outside the allowlist is a failed check, not an accepted
        // one: `Some(1)` must not read as "configured".
        cfg.chain_id = Some(1);
        assert!(
            !evaluate(&cfg).checks[0].passed,
            "mainnet is not a chain this lane may settle on"
        );
        cfg.chain_id = Some(84_532);
        assert!(evaluate(&cfg).checks[0].passed, "Base Sepolia is permitted");
    }

    /// INV-11 at the operator-facing seam: the readiness body carries structural
    /// words and integers, never a configured destination.
    ///
    /// Mutations this detects: a `detail` widened to `format!("{endpoint}")`;
    /// `ProxyCheck::detail` changed from `&'static str` to `String` and filled
    /// from config; the whole `ProxyConfig` serialised into the report (it
    /// derives `Serialize`, so that is one line away).
    #[tokio::test]
    async fn the_readiness_report_never_echoes_a_configured_endpoint() {
        let cfg = wired_config(true);
        let body = serde_json::to_string(&evaluate(&cfg)).unwrap();

        // NEGATIVE CONTROL: prove the scanner can find a planted value, or an
        // empty result below proves nothing.
        let tainted = format!("{body} {}", cfg.meter_endpoint.clone().unwrap());
        let planted: Vec<&str> = ["gateway.invalid", "https://", "/v1/meter"]
            .into_iter()
            .filter(|t| tainted.contains(t))
            .collect();
        assert_eq!(planted.len(), 3, "the scanner failed its own control");

        let gateway_id = cfg.gateway_id.clone().unwrap();
        let settlement = cfg.settlement_address.clone().unwrap();
        let digest = cfg.allowlist_manifest_digest.clone().unwrap();
        let leaked: Vec<&str> = [
            "gateway.invalid",
            "https://",
            "/v1/meter",
            gateway_id.as_str(),
            settlement.as_str(),
            digest.as_str(),
        ]
        .into_iter()
        .filter(|t| body.contains(t))
        .collect();
        assert!(leaked.is_empty(), "readiness leaked {leaked:?}: {body}");
    }

    /// The submission route refuses rather than accepting, and says why in a
    /// machine-readable token.
    ///
    /// Mutations this detects: flipping [`RECEIPT_INTAKE_WIRED`] without wiring
    /// anything; changing the refusal to a 202/200 "queued".
    #[tokio::test]
    async fn an_unwired_lane_refuses_a_submission_instead_of_accepting_it() {
        let cfg = wired_config(true);
        // The precondition, read back through the readiness report rather than
        // asserted against the constant directly: a `assert!(!CONST)` is a
        // constant assertion clippy refuses, and reading it through `evaluate`
        // also proves the report and the handler agree about the same fact.
        let intake = evaluate(&cfg)
            .checks
            .into_iter()
            .find(|c| c.name == "receipt_intake_wired")
            .expect("the readiness report names the intake check");
        assert!(
            !intake.passed,
            "the intake is wired -- this test pins the UNWIRED behaviour and must be rewritten"
        );
        let req = Request::builder()
            .method("POST")
            .uri("/v1/proxy/receipts")
            .body(Body::from("{\"receipt\":{}}"))
            .unwrap();
        let res = mount(host_app(), &cfg).oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["refusal"], serde_json::json!("LaneNotWired"));
    }

    /// The path parameter binds, and the binding is observable: an id inside the
    /// fetch-network space and one outside it take different arms.
    ///
    /// Mutations this detects: `":epochId"` rewritten as `"{epochId}"` (every
    /// case below becomes a 404); the space check deleted (the 400 becomes a
    /// 503); `Path<String>` swapped for a typed extractor that 400s before the
    /// handler runs (the well-formed case stops reaching the 503).
    #[tokio::test]
    async fn the_meter_route_binds_the_epoch_id_from_the_path() {
        let cfg = wired_config(true);
        let cases: [(&str, StatusCode); 5] = [
            // In the fetch-network space: reaches the handler's wiring refusal.
            ("8000000000000", StatusCode::SERVICE_UNAVAILABLE),
            ("8000000020664", StatusCode::SERVICE_UNAVAILABLE),
            // A daily epoch id, an enrolment-space id, and a non-number.
            ("20260731", StatusCode::BAD_REQUEST),
            ("9000000000000", StatusCode::BAD_REQUEST),
            ("not-a-number", StatusCode::BAD_REQUEST),
        ];
        for (segment, expected) in cases {
            let uri = format!("/v1/proxy/meter/{segment}");
            assert_eq!(
                status_of(mount(host_app(), &cfg), "GET", &uri).await,
                expected,
                "{uri}"
            );
        }
    }

    /// The transport bound is live on the route that buffers a body.
    ///
    /// Mutations this detects: dropping the `DefaultBodyLimit` layer from
    /// [`router`]; changing [`post_receipt`] to take no body extractor, which
    /// silently disables the limit because nothing consults the extension.
    #[tokio::test]
    async fn a_submission_over_the_body_limit_is_refused_by_the_transport() {
        let cfg = wired_config(true);

        // POSITIVE CONTROL: one byte under the limit reaches the handler.
        let under = "a".repeat(PROXY_BODY_LIMIT_BYTES);
        let req = Request::builder()
            .method("POST")
            .uri("/v1/proxy/receipts")
            .body(Body::from(under))
            .unwrap();
        let res = mount(host_app(), &cfg).oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);

        let over = "a".repeat(PROXY_BODY_LIMIT_BYTES + 1);
        let req = Request::builder()
            .method("POST")
            .uri("/v1/proxy/receipts")
            .body(Body::from(over))
            .unwrap();
        let res = mount(host_app(), &cfg).oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
