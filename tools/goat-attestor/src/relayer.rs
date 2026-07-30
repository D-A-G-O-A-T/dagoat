//! Gas-sponsorship relayer HTTP API: bindWithSignature / enrollSelfWithSignature /
//! gas-drip (gasless-sell native-gas top-up).
//!
//! Perimeter (P4 + H1): free checks before any broadcast —
//! rate limit → shape validate → EIP-712 sig verify → spend ceiling → send → record.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

use crate::chain::ChainClient;
use crate::gas_drips::{compute_drip_wei, is_over_cap, utc_today, DripConfig, DripLedger};
use crate::merkle::parse_address;
use crate::rate_limit::{RateLimitError, RateLimiter};
use crate::sig_verify::{verify_bind_sig, verify_enroll_sig};
use crate::spend_ledger::{
    SpendError, SpendLedger, DEFAULT_DAILY_CEILING_WEI, DEFAULT_DRIP_BUDGET_WEI,
};

/// Fixed gas estimate used for H2 ceiling checks on bind/enroll (not an on-chain
/// estimate — a conservative pilot constant so the ceiling has a wei unit).
const BIND_ENROLL_GAS_ESTIMATE: u128 = 500_000;
const DEFAULT_GAS_PRICE_WEI: u128 = 1_000_000_000; // 1 gwei

/// H5 — max request body size (all relay bodies are small JSON).
pub const RELAY_BODY_LIMIT_BYTES: usize = 8 * 1024;

/// H4 — built-in CORS origins for local Vite + Tauri desktop.
pub fn default_cors_origins() -> Vec<&'static str> {
    vec![
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://tauri.localhost",
        "https://tauri.localhost",
        "tauri://localhost",
    ]
}

/// H4 — union `RELAY_CORS_ORIGINS` extras (comma-separated) with
/// [`default_cors_origins`]. Duplicates are dropped; order is defaults first,
/// then extras in the order they appear.
pub fn parse_cors_origins(extra: Option<&str>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for o in default_cors_origins() {
        if seen.insert(o.to_string()) {
            out.push(o.to_string());
        }
    }
    if let Some(extra) = extra {
        for part in extra.split(',') {
            let t = part.trim();
            if t.is_empty() {
                continue;
            }
            if seen.insert(t.to_string()) {
                out.push(t.to_string());
            }
        }
    }
    out
}

/// Env truthy values for `RELAY_ALLOW_NON_LOOPBACK` (container / cloud escape hatch).
pub fn env_allow_non_loopback() -> bool {
    match std::env::var("RELAY_ALLOW_NON_LOOPBACK") {
        Ok(v) => {
            let t = v.trim();
            t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
        }
        Err(_) => false,
    }
}

/// H6 — refuse non-loopback bind addresses so the origin is only reachable via
/// loopback (e.g. cloudflared → 127.0.0.1). Accepts `127.0.0.1` and `::1` by default;
/// rejects `0.0.0.0` and LAN unless `allow_non_loopback` is true (Docker/K8s/VPS
/// behind a tunnel — set `RELAY_ALLOW_NON_LOOPBACK=1`).
pub fn require_loopback_bind(bind: &str) -> Result<(), String> {
    require_loopback_bind_ex(bind, env_allow_non_loopback())
}

/// Testable H6 gate. Prefer [`require_loopback_bind`] at call sites so the env
/// override is always consulted.
pub fn require_loopback_bind_ex(bind: &str, allow_non_loopback: bool) -> Result<(), String> {
    let addr: SocketAddr = bind.parse().map_err(|e| {
        format!(
            "invalid relayer bind address {bind:?}: {e} (expected host:port, e.g. 127.0.0.1:8787)"
        )
    })?;
    if addr.ip().is_loopback() {
        return Ok(());
    }
    if allow_non_loopback {
        tracing::warn!(
            bind = %bind,
            "H6: RELAY_ALLOW_NON_LOOPBACK set — binding non-loopback; ensure only a tunnel/proxy can reach this port"
        );
        return Ok(());
    }
    Err(format!(
        "H6: relayer bind must be loopback (127.0.0.1 or ::1), got {bind} — \
         refusing non-loopback so the process is not LAN/WAN reachable without a tunnel. \
         For Docker/K8s/cloud behind a reverse proxy or Cloudflare Tunnel, set RELAY_ALLOW_NON_LOOPBACK=1"
    ))
}

/// H4 — CORS layer: origin allowlist + fixed methods/headers for desktop + CF Access.
pub fn build_cors_layer() -> CorsLayer {
    let origins = parse_cors_origins(std::env::var("RELAY_CORS_ORIGINS").ok().as_deref());
    let origin_values: Vec<HeaderValue> = origins
        .into_iter()
        .filter_map(|s| HeaderValue::from_str(&s).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(origin_values)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            HeaderName::from_static("content-type"),
            HeaderName::from_static("cf-access-client-id"),
            HeaderName::from_static("cf-access-client-secret"),
        ])
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BindRelayRequest {
    pub wallet: String,
    pub username: String,
    pub deadline: u64,
    /// Hex signature (0x-prefixed or bare).
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnrollRelayRequest {
    pub wallet: String,
    pub deadline: u64,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GasDripRequest {
    pub wallet: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    BadUsername(String),
    EmptySignature,
    BadWallet(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadUsername(u) => write!(f, "username must start with \"GOAT-\", got {u}"),
            Self::EmptySignature => write!(f, "signature must be non-empty"),
            Self::BadWallet(w) => write!(f, "wallet must be 0x + 40 hex, got {w}"),
        }
    }
}

/// Username must start with `GOAT-`, signature non-empty, wallet `0x` + 40 hex.
pub fn validate_bind_request(req: &BindRelayRequest) -> Result<(), ValidationError> {
    if !req.username.starts_with("GOAT-") {
        return Err(ValidationError::BadUsername(req.username.clone()));
    }
    if req.signature.is_empty() || req.signature == "0x" {
        return Err(ValidationError::EmptySignature);
    }
    validate_wallet(&req.wallet)?;
    Ok(())
}

pub fn validate_enroll_request(req: &EnrollRelayRequest) -> Result<(), ValidationError> {
    if req.signature.is_empty() || req.signature == "0x" {
        return Err(ValidationError::EmptySignature);
    }
    validate_wallet(&req.wallet)?;
    Ok(())
}

fn validate_wallet(wallet: &str) -> Result<(), ValidationError> {
    if !wallet.starts_with("0x") && !wallet.starts_with("0X") {
        return Err(ValidationError::BadWallet(wallet.to_string()));
    }
    let hex_part = &wallet[2..];
    if hex_part.len() != 40 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValidationError::BadWallet(wallet.to_string()));
    }
    Ok(())
}

fn decode_sig(sig: &str) -> Result<Vec<u8>, String> {
    let h = sig
        .strip_prefix("0x")
        .or_else(|| sig.strip_prefix("0X"))
        .unwrap_or(sig);
    hex::decode(h).map_err(|e| e.to_string())
}

/// EIP-712 domain parameters for off-chain Bind / Enroll verification (H1).
#[derive(Debug, Clone)]
pub struct Eip712Config {
    pub chain_id: u64,
    pub worker_binding: [u8; 20],
    pub enrollment_registry: [u8; 20],
}

impl Default for Eip712Config {
    fn default() -> Self {
        // Safe defaults for mock tests that never hit H1 success path.
        // Handlers always run H1; garbage sigs still reject before broadcast.
        Self {
            chain_id: 31337,
            worker_binding: [0u8; 20],
            enrollment_registry: [0u8; 20],
        }
    }
}

/// Bundled construction args for the relayer router (avoids arg explosion).
#[derive(Debug, Clone)]
pub struct RelayerConfig {
    pub registry_json: Option<PathBuf>,
    pub gas_drips_json: Option<PathBuf>,
    pub goat_coin: String,
    pub drip_cfg: DripConfig,
    pub eip712: Eip712Config,
    pub spend_ledger_path: Option<PathBuf>,
    pub spend_ceiling_wei: u128,
    pub drip_budget_wei: u128,
}

impl Default for RelayerConfig {
    fn default() -> Self {
        Self {
            registry_json: None,
            gas_drips_json: None,
            goat_coin: String::new(),
            drip_cfg: DripConfig::default(),
            eip712: Eip712Config::default(),
            spend_ledger_path: None,
            spend_ceiling_wei: DEFAULT_DAILY_CEILING_WEI,
            drip_budget_wei: DEFAULT_DRIP_BUDGET_WEI,
        }
    }
}

/// Shared chain handle. `ChainClient` implementations use interior mutability
/// (e.g. `MockChain`), so `Arc<dyn ChainClient>` is sufficient.
#[derive(Clone)]
pub struct AppState {
    pub chain: Arc<dyn ChainClient>,
    /// When set, successful gasless bind upserts this registry immediately.
    pub registry_json: Option<PathBuf>,
    /// When set, enables `POST /v1/relay/gas-drip` (disabled → 503 when `None`).
    pub gas_drips_json: Option<PathBuf>,
    /// GoatCoin ERC-20 token address (gas-drip eligibility check).
    pub goat_coin: String,
    /// Gas-drip amount-calculation config.
    pub drip_cfg: Arc<DripConfig>,
    /// Wallets (lowercase) with a gas-drip request currently in flight —
    /// guards against double-submit races on the same wallet.
    pub inflight: Arc<Mutex<HashSet<String>>>,
    /// EIP-712 domain (chain_id + verifying contracts) for H1.
    pub eip712: Eip712Config,
    /// H2/H2b spend ledger. `None` = no H2 enforcement (tests that don't care).
    pub spend: Option<Arc<Mutex<SpendLedger>>>,
    /// H3 in-memory rate limiter (per-wallet + global).
    pub rate: Arc<Mutex<RateLimiter>>,
}

/// Build axum router for the relayer over any `ChainClient`.
///
/// Accepts `Arc<C>` or anything convertible to `Arc<dyn ChainClient>`.
///
/// CORS is an origin allowlist (H4: Vite + Tauri defaults, plus `RELAY_CORS_ORIGINS`);
/// request bodies are capped at [`RELAY_BODY_LIMIT_BYTES`] (H5).
pub fn router(chain: Arc<dyn ChainClient>) -> Router {
    router_with_registry(chain, None)
}

/// Relayer + optional live auto-register of binds into `registry.json`.
/// Gas-drip stays disabled (`gas_drips_json = None`) so existing callers/tests
/// keep compiling and behaving unchanged; use `router_with_config` to enable it.
pub fn router_with_registry(chain: Arc<dyn ChainClient>, registry_json: Option<PathBuf>) -> Router {
    router_with_config(
        chain,
        registry_json,
        None,
        String::new(),
        DripConfig::default(),
    )
}

/// Full relayer router: bind/enroll + optional gas-drip (gasless-sell native-gas top-up).
/// Thin wrapper: default EIP-712 domain + no spend ledger (H2 off). Prefer
/// [`router_with_relayer_config`] when wiring production ServeRelayer.
pub fn router_with_config(
    chain: Arc<dyn ChainClient>,
    registry_json: Option<PathBuf>,
    gas_drips_json: Option<PathBuf>,
    goat_coin: String,
    drip_cfg: DripConfig,
) -> Router {
    router_with_relayer_config(
        chain,
        RelayerConfig {
            registry_json,
            gas_drips_json,
            goat_coin,
            drip_cfg,
            ..RelayerConfig::default()
        },
    )
}

/// Full router from a [`RelayerConfig`] (H1 + optional H2 + H3).
pub fn router_with_relayer_config(chain: Arc<dyn ChainClient>, cfg: RelayerConfig) -> Router {
    let spend = cfg.spend_ledger_path.map(|path| {
        Arc::new(Mutex::new(SpendLedger::new(
            path,
            cfg.spend_ceiling_wei,
            cfg.drip_budget_wei,
        )))
    });
    let state = AppState {
        chain,
        registry_json: cfg.registry_json,
        gas_drips_json: cfg.gas_drips_json,
        goat_coin: cfg.goat_coin,
        drip_cfg: Arc::new(cfg.drip_cfg),
        inflight: Arc::new(Mutex::new(HashSet::new())),
        eip712: cfg.eip712,
        spend,
        rate: Arc::new(Mutex::new(RateLimiter::with_defaults())),
    };
    Router::new()
        .route("/health", get(health))
        .route("/v1/relay/bind", post(relay_bind))
        .route("/v1/relay/enroll", post(relay_enroll))
        .route("/v1/relay/gas-drip", post(relay_gas_drip))
        .layer(DefaultBodyLimit::max(RELAY_BODY_LIMIT_BYTES))
        .layer(build_cors_layer())
        .with_state(state)
}

/// Convenience: wrap a concrete client in `Arc` and erase to dyn.
pub fn router_for<C: ChainClient + 'static>(chain: C) -> Router {
    router(Arc::new(chain))
}

fn rate_limit_wallet(state: &AppState, wallet: &str) -> Result<(), (StatusCode, String)> {
    let mut g = state
        .rate
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    g.check(wallet, Instant::now()).map_err(|e| {
        let msg = match e {
            RateLimitError::Wallet => "RateLimited: wallet",
            RateLimitError::Global => "RateLimited: global",
        };
        tracing::warn!(wallet = %wallet, "{msg}");
        (StatusCode::TOO_MANY_REQUESTS, msg.to_string())
    })
}

fn estimate_bind_enroll_wei(state: &AppState) -> u128 {
    let gas_price = state.chain.gas_price().unwrap_or(DEFAULT_GAS_PRICE_WEI);
    let gp = if gas_price == 0 {
        DEFAULT_GAS_PRICE_WEI
    } else {
        gas_price
    };
    BIND_ENROLL_GAS_ESTIMATE.saturating_mul(gp)
}

fn spend_check_total(state: &AppState, amount_wei: u128) -> Result<(), (StatusCode, String)> {
    let Some(spend) = state.spend.as_ref() else {
        return Ok(());
    };
    let g = spend
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    g.can_spend(amount_wei, 0).map_err(spend_err_response)
}

fn spend_record_total(state: &AppState, amount_wei: u128) {
    let Some(spend) = state.spend.as_ref() else {
        return;
    };
    let g = spend
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Err(e) = g.try_record_total(amount_wei) {
        tracing::error!("spend_ledger try_record_total after successful send failed: {e}");
    }
}

fn spend_check_drip(state: &AppState, amount_wei: u128) -> Result<(), (StatusCode, String)> {
    let Some(spend) = state.spend.as_ref() else {
        return Ok(());
    };
    let g = spend
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    g.can_spend(amount_wei, amount_wei)
        .map_err(spend_err_response)
}

fn spend_record_drip(state: &AppState, amount_wei: u128) {
    let Some(spend) = state.spend.as_ref() else {
        return;
    };
    let g = spend
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Err(e) = g.try_record_drip(amount_wei) {
        tracing::error!("spend_ledger try_record_drip after successful send failed: {e}");
    }
}

fn spend_err_response(e: SpendError) -> (StatusCode, String) {
    match e {
        SpendError::CeilingReached => {
            tracing::error!("SpendCeilingReached");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "SpendCeilingReached".to_string(),
            )
        }
        SpendError::DripBudgetExhausted => {
            tracing::error!("DripBudgetExhausted");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "DripBudgetExhausted".to_string(),
            )
        }
        SpendError::Unavailable(msg) => {
            tracing::error!("spend ledger unavailable: {msg}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("SpendLedgerUnavailable: {msg}"),
            )
        }
    }
}

fn bad_request(msg: String) -> (StatusCode, Json<RelayResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(RelayResponse {
            ok: false,
            tx_hash: None,
            error: Some(msg),
        }),
    )
}

fn status_msg(code: StatusCode, msg: String) -> (StatusCode, Json<RelayResponse>) {
    (
        code,
        Json(RelayResponse {
            ok: false,
            tx_hash: None,
            error: Some(msg),
        }),
    )
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true, "service": "goat-attestor-relayer" }))
}

async fn relay_bind(
    State(state): State<AppState>,
    Json(req): Json<BindRelayRequest>,
) -> impl IntoResponse {
    // 1. Rate limit (H3) — before any other work.
    if let Err((code, msg)) = rate_limit_wallet(&state, &req.wallet) {
        return status_msg(code, msg);
    }
    // 2. Shape validate (existing).
    if let Err(e) = validate_bind_request(&req) {
        return bad_request(e.to_string());
    }
    // 3. Decode wallet + sig.
    let wallet = match parse_address(&req.wallet) {
        Ok(w) => w,
        Err(e) => return bad_request(e),
    };
    let sig = match decode_sig(&req.signature) {
        Ok(s) => s,
        Err(e) => return bad_request(e),
    };
    // 4. On-chain nonce for EIP-712 struct.
    let nonce = match state.chain.binding_nonce(&req.wallet) {
        Ok(n) => n,
        Err(e) => {
            return status_msg(StatusCode::BAD_GATEWAY, format!("binding_nonce: {e}"));
        }
    };
    // 5. H1 — recover signer before any broadcast.
    if let Err(e) = verify_bind_sig(
        &req.wallet,
        &req.username,
        nonce,
        req.deadline,
        state.eip712.chain_id,
        state.eip712.worker_binding,
        &req.signature,
    ) {
        tracing::warn!(wallet = %req.wallet, "bind H1 reject: {e}");
        return bad_request(e.to_string());
    }
    // 6. H2 ceiling check (record only after success).
    let est = estimate_bind_enroll_wei(&state);
    if let Err((code, msg)) = spend_check_total(&state, est) {
        return status_msg(code, msg);
    }
    // 7. Chain send.
    let result = state
        .chain
        .bind_with_signature(wallet, &req.username, req.deadline, &sig);
    match result {
        Ok(tx) => {
            // 8. Record spend after success only.
            spend_record_total(&state, est);
            // Auto-register every successful bind into attestor registry.json.
            if let Some(path) = state.registry_json.as_ref() {
                let mut reg = crate::registry::WorkerRegistry::load(path).unwrap_or_default();
                let is_new = reg.register_bind(&req.wallet, &req.username);
                if let Err(e) = reg.save(path) {
                    tracing::warn!("bind ok but registry save failed: {e}");
                } else if is_new {
                    tracing::info!(
                        "auto-registered new bind {} → {} in {:?}",
                        req.wallet,
                        req.username,
                        path
                    );
                }
            }
            (
                StatusCode::OK,
                Json(RelayResponse {
                    ok: true,
                    tx_hash: Some(format!("0x{}", hex::encode(tx))),
                    error: None,
                }),
            )
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(RelayResponse {
                ok: false,
                tx_hash: None,
                error: Some(e.to_string()),
            }),
        ),
    }
}

async fn relay_enroll(
    State(state): State<AppState>,
    Json(req): Json<EnrollRelayRequest>,
) -> impl IntoResponse {
    if let Err((code, msg)) = rate_limit_wallet(&state, &req.wallet) {
        return status_msg(code, msg);
    }
    if let Err(e) = validate_enroll_request(&req) {
        return bad_request(e.to_string());
    }
    let wallet = match parse_address(&req.wallet) {
        Ok(w) => w,
        Err(e) => return bad_request(e),
    };
    let sig = match decode_sig(&req.signature) {
        Ok(s) => s,
        Err(e) => return bad_request(e),
    };
    let nonce = match state.chain.enrollment_nonce(&req.wallet) {
        Ok(n) => n,
        Err(e) => {
            return status_msg(StatusCode::BAD_GATEWAY, format!("enrollment_nonce: {e}"));
        }
    };
    if let Err(e) = verify_enroll_sig(
        &req.wallet,
        nonce,
        req.deadline,
        state.eip712.chain_id,
        state.eip712.enrollment_registry,
        &req.signature,
    ) {
        tracing::warn!(wallet = %req.wallet, "enroll H1 reject: {e}");
        return bad_request(e.to_string());
    }
    let est = estimate_bind_enroll_wei(&state);
    if let Err((code, msg)) = spend_check_total(&state, est) {
        return status_msg(code, msg);
    }
    let result = state
        .chain
        .enroll_self_with_signature(wallet, req.deadline, &sig);
    match result {
        Ok(tx) => {
            spend_record_total(&state, est);
            (
                StatusCode::OK,
                Json(RelayResponse {
                    ok: true,
                    tx_hash: Some(format!("0x{}", hex::encode(tx))),
                    error: None,
                }),
            )
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(RelayResponse {
                ok: false,
                tx_hash: None,
                error: Some(e.to_string()),
            }),
        ),
    }
}

/// RAII guard: removes `key` from the shared in-flight set on drop, on every
/// return path (early 4xx/5xx or the final 200), so a wallet can never get
/// stuck "in progress" after a single request.
struct InflightGuard {
    set: Arc<Mutex<HashSet<String>>>,
    key: String,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        // Recover from poisoning rather than skip the removal: the guarded
        // state is a plain `HashSet<String>` with no invariant a panic while
        // holding the lock could corrupt, so treating a poisoned lock as
        // unusable here would leak `key` permanently (FIX-B).
        let mut g = self
            .set
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.remove(&self.key);
    }
}

/// Next UTC midnight (00:00:00Z) as an ISO-8601 string, for `DailyLimitReached`'s
/// `resets_at`. Self-contained `civil_from_days` copy (same Howard Hinnant
/// algorithm as `gas_drips::civil_from_days` / `proposer::civil_from_days`) —
/// mirrors this crate's existing convention of one private copy per module
/// rather than a shared dependency, so this HTTP-layer concern stays decoupled
/// from the gas_drips ledger module's wall-clock date math.
fn next_midnight_utc_iso() -> String {
    let unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let next_day = (unix_secs / 86_400) as i64 + 1;
    let (y, m, d) = civil_from_days(next_day);
    format!("{y:04}-{m:02}-{d:02}T00:00:00Z")
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

/// `POST /v1/relay/gas-drip` — gasless-sell native-gas top-up.
///
/// Order (spec §2.1, reserve-before-send as of FIX-A): validate wallet →
/// gas-drip enabled? → in-flight guard → holds GOAT? → under daily cap? →
/// compute drip → relayer funded? → **reserve quota (ledger commit)** → send.
/// A failed reservation fails closed (no send, 503 `GasDripLedgerUnavailable`).
/// A failed send after a successful reservation leaves the quota consumed
/// (502 `DripSendFailed`, no refund) — see the `send_native` match arm below
/// for why.
async fn relay_gas_drip(
    State(state): State<AppState>,
    Json(req): Json<GasDripRequest>,
) -> impl IntoResponse {
    if let Err(e) = validate_wallet(&req.wallet) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        );
    }

    let Some(gas_drips_json) = state.gas_drips_json.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "GasDripDisabled" })),
        );
    };

    let key = req.wallet.to_ascii_lowercase();
    {
        // Recover from poisoning instead of 500ing (FIX-B): a panic while
        // holding this lock can't leave the `HashSet<String>` in a broken
        // state, so refusing every wallet forever over one prior panic would
        // be strictly worse than just carrying on with the recovered guard.
        let mut g = state
            .inflight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if g.contains(&key) {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": "DripInProgress" })),
            );
        }
        g.insert(key.clone());
    }
    let _guard = InflightGuard {
        set: state.inflight.clone(),
        key: key.clone(),
    };

    match state.chain.erc20_balance_of(&state.goat_coin, &req.wallet) {
        Ok(0) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "NoGoatToSell" })),
            );
        }
        Ok(_) => {}
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("erc20_balance_of: {e}") })),
            );
        }
    }

    let today = utc_today();
    let ledger = DripLedger::new(gas_drips_json);
    let count = ledger.load_count(&req.wallet, &today);
    let daily_cap = state.drip_cfg.daily_cap;
    if is_over_cap(count, daily_cap) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "DailyLimitReached",
                "limit": daily_cap,
                "resets_at": next_midnight_utc_iso(),
            })),
        );
    }

    let gas_price = match state.chain.gas_price() {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("gas_price: {e}") })),
            );
        }
    };
    let drip = compute_drip_wei(gas_price, &state.drip_cfg);

    // H2 + H2b check (read-only) before reserve/send; record only after success.
    if let Err((code, msg)) = spend_check_drip(&state, drip) {
        return (code, Json(serde_json::json!({ "error": msg })));
    }

    let relayer_addr = match state.chain.relayer_address() {
        Ok(a) => a,
        Err(e) => {
            // Distinct from the balance-check arms below (FIX-E): this means
            // the relayer has no usable signer/address at all — an operator
            // misconfiguration (e.g. missing relayer private key), not a
            // "top up the wallet" situation. Same response shape either way
            // so the client can't distinguish; the operator can, from logs.
            tracing::error!(
                "gas-drip: relayer_address() failed (relayer signer/key not configured?): {e}"
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "RelayerUnderfunded", "detail": e.to_string() })),
            );
        }
    };
    let relayer_balance = match state.chain.eth_balance(&relayer_addr) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                "gas-drip: eth_balance({relayer_addr}) lookup failed (RPC/transport issue): {e}"
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "RelayerUnderfunded", "detail": e.to_string() })),
            );
        }
    };
    if relayer_balance < drip {
        tracing::error!(
            "gas-drip: relayer {relayer_addr} balance {relayer_balance} wei < drip {drip} wei — top up the relayer wallet"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "RelayerUnderfunded" })),
        );
    }

    // Reserve BEFORE sending (spec G4, revised — FIX-A). `commit` persists
    // the day's quota; only a successful reservation is followed by a real
    // native send. If the ledger can't be written, fail closed: do NOT send.
    let new_count = match ledger.commit(&req.wallet, &today) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                "gas-drip: ledger commit (reserve) failed for {}, refusing to send: {e}",
                req.wallet
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "GasDripLedgerUnavailable" })),
            );
        }
    };

    match state.chain.send_native(&req.wallet, drip) {
        Ok(tx) => {
            // H2/H2b record after successful send only (G4 drip quota already reserved).
            spend_record_drip(&state, drip);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "tx_hash": format!("0x{}", hex::encode(tx)),
                    "amount_wei": drip.to_string(),
                    "remaining_today": daily_cap.saturating_sub(new_count),
                })),
            )
        }
        Err(e) => {
            // Quota stays consumed (reserve-before-send, FIX-A): `send_native`
            // (via `RpcChain::send_tx`) awaits the receipt, so an `Err` here
            // may mean the tx was actually broadcast and lands later.
            // Releasing quota on error would grant a free retry; with
            // cap=1/day a wrongly-burned quota is a next-day annoyance, a
            // wrongly-granted drip is real ETH.
            tracing::error!(
                "gas-drip: send_native to {} failed after quota reserved (count={new_count}), quota NOT released: {e}",
                req.wallet
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "DripSendFailed",
                    "detail": e.to_string(),
                    // N-1: disclose the no-refund fact on the wire. Without
                    // this, a desktop client's natural "send failed → try
                    // again" retry produces a 429 DailyLimitReached that
                    // reads as a second, unrelated bug rather than the
                    // direct consequence of this response.
                    "quota_consumed": true,
                })),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::MockChain;
    use crate::gas_drips::DEFAULT_DAILY_CAP;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[test]
    fn validate_bind_rejects_bad_username() {
        let req = BindRelayRequest {
            wallet: "0x00000000000000000000000000000000000000A1".into(),
            username: "alice".into(),
            deadline: 1,
            signature: "0xab".into(),
        };
        assert!(matches!(
            validate_bind_request(&req),
            Err(ValidationError::BadUsername(_))
        ));
    }

    #[test]
    fn validate_bind_rejects_empty_sig() {
        let req = BindRelayRequest {
            wallet: "0x00000000000000000000000000000000000000A1".into(),
            username: "GOAT-alice".into(),
            deadline: 1,
            signature: "".into(),
        };
        assert_eq!(
            validate_bind_request(&req),
            Err(ValidationError::EmptySignature)
        );
    }

    #[test]
    fn validate_bind_rejects_bad_wallet() {
        let req = BindRelayRequest {
            wallet: "not-an-address".into(),
            username: "GOAT-alice".into(),
            deadline: 1,
            signature: "0xab".into(),
        };
        assert!(matches!(
            validate_bind_request(&req),
            Err(ValidationError::BadWallet(_))
        ));
    }

    #[test]
    fn validate_bind_ok() {
        let req = BindRelayRequest {
            wallet: "0x00000000000000000000000000000000000000A1".into(),
            username: "GOAT-alice".into(),
            deadline: 1,
            signature: "0xdead".into(),
        };
        assert!(validate_bind_request(&req).is_ok());
    }

    // --- H4 CORS / H5 body / H6 loopback ---

    #[test]
    fn default_cors_includes_vite_and_tauri() {
        let o = default_cors_origins();
        assert!(o.contains(&"http://localhost:5173"));
        assert!(o.contains(&"http://127.0.0.1:5173"));
        assert!(o.contains(&"http://tauri.localhost"));
        assert!(o.contains(&"https://tauri.localhost"));
        assert!(o.contains(&"tauri://localhost"));
    }

    #[test]
    fn parse_cors_unions_extras_with_defaults() {
        let o = parse_cors_origins(Some(
            "https://app.example.com, http://localhost:5173,  https://extra.example ",
        ));
        assert!(o.contains(&"http://localhost:5173".to_string()));
        assert!(o.contains(&"https://app.example.com".to_string()));
        assert!(o.contains(&"https://extra.example".to_string()));
        // defaults still present
        assert!(o.contains(&"tauri://localhost".to_string()));
        // no duplicate of the default that was also listed as extra
        assert_eq!(
            o.iter().filter(|s| *s == "http://localhost:5173").count(),
            1
        );
    }

    #[test]
    fn parse_cors_none_is_defaults_only() {
        let o = parse_cors_origins(None);
        assert_eq!(o.len(), default_cors_origins().len());
        for d in default_cors_origins() {
            assert!(o.contains(&d.to_string()));
        }
    }

    #[test]
    fn body_limit_is_8kib() {
        assert_eq!(RELAY_BODY_LIMIT_BYTES, 8 * 1024);
    }

    #[test]
    fn default_cors_includes_tauri_webview_schemes() {
        // Packaged Tauri does not use Vite origins — H4 must carry these by default.
        let d = default_cors_origins();
        for need in [
            "http://tauri.localhost",
            "https://tauri.localhost",
            "tauri://localhost",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ] {
            assert!(d.contains(&need), "default CORS missing {need:?}: {d:?}");
        }
    }

    #[test]
    fn require_loopback_accepts_127_and_v6() {
        assert!(require_loopback_bind_ex("127.0.0.1:8787", false).is_ok());
        assert!(require_loopback_bind_ex("[::1]:8787", false).is_ok());
        assert!(require_loopback_bind_ex("127.0.0.1:0", false).is_ok());
    }

    #[test]
    fn require_loopback_rejects_wildcard_and_lan_without_override() {
        assert!(require_loopback_bind_ex("0.0.0.0:8787", false).is_err());
        assert!(require_loopback_bind_ex("192.168.1.10:8787", false).is_err());
        assert!(require_loopback_bind_ex("[::]:8787", false).is_err());
        assert!(require_loopback_bind_ex("not-an-addr", false).is_err());
    }

    #[test]
    fn require_loopback_allows_non_loopback_with_explicit_override() {
        // Docker/K8s: bind 0.0.0.0 inside the netns; tunnel/proxy is the outer gate.
        assert!(require_loopback_bind_ex("0.0.0.0:8787", true).is_ok());
        assert!(require_loopback_bind_ex("192.168.1.10:8787", true).is_ok());
        // Override does not paper over garbage addresses.
        assert!(require_loopback_bind_ex("not-an-addr", true).is_err());
    }

    #[test]
    fn build_cors_layer_constructs() {
        // Smoke: layer builds without panic (reads RELAY_CORS_ORIGINS if set).
        let _ = build_cors_layer();
    }

    #[tokio::test]
    async fn health_endpoint() {
        let app = router_for(MockChain::new());
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["ok"], true);
    }

    #[tokio::test]
    async fn bind_validation_via_http() {
        let app = router_for(MockChain::new());
        let body = serde_json::json!({
            "wallet": "0x00000000000000000000000000000000000000A1",
            "username": "bad",
            "deadline": 1,
            "signature": "0xab"
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relay/bind")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    // --- Gas-drip (GD5) ---

    const RELAYER_ADDR: &str = crate::chain::DEFAULT_MOCK_RELAYER_ADDRESS;
    const GOAT: &str = "0x00000000000000000000000000000000000000C0";
    const ALICE: &str = "0x00000000000000000000000000000000000000A1";

    struct TestResp {
        status: StatusCode,
        body: serde_json::Value,
    }

    async fn post_json(app: &Router, path: &str, body: serde_json::Value) -> TestResp {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        TestResp { status, body }
    }

    /// Builds a `router_with_config` router over a fresh temp-dir ledger
    /// (cap = `DEFAULT_DAILY_CAP` = 1), and also returns the ledger path so
    /// tests can inspect `DripLedger::load_count` / file existence directly
    /// (FIX-D). The temp dir is intentionally leaked (test-only, one tiny
    /// JSON file) so the ledger survives for the life of the returned
    /// `Router`, which callers may `.clone()` across multiple requests
    /// within one test — matching how axum `oneshot` consumes a router per
    /// call.
    fn router_for_test_with_ledger(chain: MockChain, goat_coin: &str) -> (Router, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let gas_drips_json = dir.path().join("gas_drips.json");
        std::mem::forget(dir);
        let router = router_with_config(
            Arc::new(chain),
            None,
            Some(gas_drips_json.clone()),
            goat_coin.to_string(),
            DripConfig::default(),
        );
        (router, gas_drips_json)
    }

    fn router_for_test(chain: MockChain, goat_coin: &str) -> Router {
        router_for_test_with_ledger(chain, goat_coin).0
    }

    #[tokio::test]
    async fn gas_drip_happy_then_cap() {
        let m = MockChain::new();
        m.set_eth_balance(RELAYER_ADDR, u128::MAX); // relayer funded
        m.set_gas_price(1_000_000_000);
        m.set_erc20_balance(GOAT, ALICE, 100);
        let app = router_for_test(m, GOAT);

        let r = post_json(
            &app,
            "/v1/relay/gas-drip",
            serde_json::json!({ "wallet": ALICE }),
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::OK,
            "first drip of the day: {:?}",
            r.body
        );
        assert_eq!(r.body["ok"], true);
        assert!(r.body["tx_hash"].as_str().unwrap().starts_with("0x"));
        assert_eq!(r.body["remaining_today"], 0);

        let r = post_json(
            &app,
            "/v1/relay/gas-drip",
            serde_json::json!({ "wallet": ALICE }),
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::TOO_MANY_REQUESTS,
            "second drip same day blocked"
        );
        assert_eq!(r.body["error"], "DailyLimitReached");
        assert_eq!(r.body["limit"], DEFAULT_DAILY_CAP);
        assert!(r.body["resets_at"]
            .as_str()
            .unwrap()
            .ends_with("T00:00:00Z"));
    }

    /// GD task 8: the handler must read the CONFIGURED `daily_cap` from
    /// `DripConfig`, not the `DEFAULT_DAILY_CAP` constant. A cap of 3 must
    /// allow 3 drips and only then block, with `limit`/`remaining_today`
    /// reflecting 3 — not the default of 1.
    #[tokio::test]
    async fn gas_drip_honors_configured_daily_cap_not_default_constant() {
        let m = MockChain::new();
        m.set_eth_balance(RELAYER_ADDR, u128::MAX);
        m.set_gas_price(1_000_000_000);
        m.set_erc20_balance(GOAT, ALICE, 100);
        let dir = tempfile::tempdir().unwrap();
        let gas_drips_json = dir.path().join("gas_drips.json");
        std::mem::forget(dir);
        let cfg = DripConfig {
            daily_cap: 3,
            ..DripConfig::default()
        };
        assert_ne!(
            cfg.daily_cap, DEFAULT_DAILY_CAP,
            "test must exercise a non-default cap"
        );
        let app = router_with_config(
            Arc::new(m),
            None,
            Some(gas_drips_json),
            GOAT.to_string(),
            cfg,
        );

        for i in 1..=3 {
            let r = post_json(
                &app,
                "/v1/relay/gas-drip",
                serde_json::json!({ "wallet": ALICE }),
            )
            .await;
            assert_eq!(
                r.status,
                StatusCode::OK,
                "drip {i} of 3 should succeed: {:?}",
                r.body
            );
            assert_eq!(r.body["remaining_today"], 3 - i);
        }

        let r = post_json(
            &app,
            "/v1/relay/gas-drip",
            serde_json::json!({ "wallet": ALICE }),
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::TOO_MANY_REQUESTS,
            "4th drip must be blocked at cap=3"
        );
        assert_eq!(r.body["error"], "DailyLimitReached");
        assert_eq!(
            r.body["limit"], 3,
            "limit in the 429 body must reflect the configured cap"
        );
    }

    #[tokio::test]
    async fn gas_drip_rejects_zero_goat_and_underfunded() {
        // erc20 balance 0 → 400 NoGoatToSell
        let m = MockChain::new();
        m.set_eth_balance(RELAYER_ADDR, u128::MAX);
        m.set_gas_price(1_000_000_000);
        // no set_erc20_balance call → defaults to 0
        let app = router_for_test(m, GOAT);
        let r = post_json(
            &app,
            "/v1/relay/gas-drip",
            serde_json::json!({ "wallet": ALICE }),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert_eq!(r.body["error"], "NoGoatToSell");

        // M-6: the in-flight guard must have released after that early 400 —
        // a second request for the same wallet must hit the same NoGoatToSell
        // branch again, not a stale 409 DripInProgress from a leaked guard.
        let r_again = post_json(
            &app,
            "/v1/relay/gas-drip",
            serde_json::json!({ "wallet": ALICE }),
        )
        .await;
        assert_eq!(
            r_again.status,
            StatusCode::BAD_REQUEST,
            "guard must release after an error response, not leave the wallet stuck: {:?}",
            r_again.body
        );
        assert_eq!(r_again.body["error"], "NoGoatToSell");

        // relayer eth_balance < drip (non-zero, but insufficient — M-4: using
        // exactly 0 here would also pass for a chain client that silently
        // resolved a wrong/empty address to a 0 balance, masking a real bug)
        // → 503 RelayerUnderfunded
        let m2 = MockChain::new();
        m2.set_eth_balance(RELAYER_ADDR, 1);
        m2.set_gas_price(1_000_000_000);
        m2.set_erc20_balance(GOAT, ALICE, 100);
        let app2 = router_for_test(m2, GOAT);
        let r2 = post_json(
            &app2,
            "/v1/relay/gas-drip",
            serde_json::json!({ "wallet": ALICE }),
        )
        .await;
        assert_eq!(r2.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(r2.body["error"], "RelayerUnderfunded");
    }

    #[tokio::test]
    async fn gas_drip_disabled_when_ledger_not_configured() {
        // router_with_registry keeps gas-drip disabled — existing callers unaffected.
        let app = router_for(MockChain::new());
        let r = post_json(
            &app,
            "/v1/relay/gas-drip",
            serde_json::json!({ "wallet": ALICE }),
        )
        .await;
        assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(r.body["error"], "GasDripDisabled");
    }

    #[tokio::test]
    async fn gas_drip_bad_wallet_rejected_before_touching_ledger() {
        let (app, ledger_path) = router_for_test_with_ledger(MockChain::new(), GOAT);
        let r = post_json(
            &app,
            "/v1/relay/gas-drip",
            serde_json::json!({ "wallet": "not-an-address" }),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        // M-5: "before touching the ledger" is a claim about I/O, not just
        // response shape — assert the ledger file was genuinely never
        // created.
        assert!(
            !ledger_path.exists(),
            "bad-wallet request must not create the ledger file"
        );
    }

    #[tokio::test]
    async fn gas_drip_send_fails_leaves_quota_reserved() {
        // FIX-A / FIX-D (M-6-adjacent): reserve-before-send means a failed
        // native send must NOT refund the day's quota. Simulate a broadcast
        // failure via the injectable `send_native` error and confirm both the
        // HTTP response and the ledger's own view of the count agree.
        let m = MockChain::new();
        m.set_eth_balance(RELAYER_ADDR, u128::MAX);
        m.set_gas_price(1_000_000_000);
        m.set_erc20_balance(GOAT, ALICE, 100);
        m.set_send_native_error(Some("simulated broadcast timeout".to_string()));
        let (app, ledger_path) = router_for_test_with_ledger(m, GOAT);

        let r = post_json(
            &app,
            "/v1/relay/gas-drip",
            serde_json::json!({ "wallet": ALICE }),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_GATEWAY, "{:?}", r.body);
        assert_eq!(r.body["error"], "DripSendFailed");
        // N-1: the wire contract must disclose the no-refund fact so a
        // desktop client doesn't render a bare "try again" that then trips
        // an unrelated-looking 429 DailyLimitReached.
        assert_eq!(r.body["quota_consumed"], true);

        let ledger = DripLedger::new(ledger_path);
        assert_eq!(
            ledger.load_count(ALICE, &utc_today()),
            1,
            "quota must stay consumed after a failed send (reserve-before-send)"
        );
    }

    #[tokio::test]
    async fn gas_drip_ledger_unwritable_fails_closed_no_send() {
        // FIX-C/FIX-D: point the ledger at a path that can never be created —
        // a *file* occupies where a parent directory component must be, so
        // `create_dir_all` inside `save_map` fails deterministically on every
        // platform. `commit` (the reservation) must therefore fail, and the
        // handler must fail closed: 503 GasDripLedgerUnavailable, no send.
        let m = Arc::new(MockChain::new());
        m.set_eth_balance(RELAYER_ADDR, u128::MAX);
        m.set_gas_price(1_000_000_000);
        m.set_erc20_balance(GOAT, ALICE, 100);

        let dir = tempfile::tempdir().unwrap();
        let blocker_file = dir.path().join("blocker");
        std::fs::write(&blocker_file, b"not a directory").unwrap();
        let gas_drips_json = blocker_file.join("gas_drips.json"); // parent is a FILE
        std::mem::forget(dir);

        let chain_dyn: Arc<dyn ChainClient> = m.clone();
        let app = router_with_config(
            chain_dyn,
            None,
            Some(gas_drips_json),
            GOAT.to_string(),
            DripConfig::default(),
        );

        let r = post_json(
            &app,
            "/v1/relay/gas-drip",
            serde_json::json!({ "wallet": ALICE }),
        )
        .await;
        assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{:?}", r.body);
        assert_eq!(r.body["error"], "GasDripLedgerUnavailable");
        assert!(
            m.sent_native().is_empty(),
            "must not send native ETH when the quota reservation itself failed"
        );
    }

    #[tokio::test]
    async fn gas_drip_amount_wei_is_decimal_string() {
        // Wire-contract pin (M-2): `amount_wei` must serialize as a decimal
        // STRING, not a bare JSON number. Default `max_wei` is 0.02 ETH
        // (2e16 wei), which exceeds JS's `Number.MAX_SAFE_INTEGER` (2^53-1
        // ≈ 9.007e15) — a bare number would silently lose precision for any
        // JS/desktop consumer (GD6/GD7). This test pins the string
        // representation so a future refactor can't regress it silently.
        let m = MockChain::new();
        m.set_eth_balance(RELAYER_ADDR, u128::MAX);
        m.set_gas_price(1_000_000_000);
        m.set_erc20_balance(GOAT, ALICE, 100);
        let app = router_for_test(m, GOAT);

        let r = post_json(
            &app,
            "/v1/relay/gas-drip",
            serde_json::json!({ "wallet": ALICE }),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        let amount = r.body["amount_wei"]
            .as_str()
            .expect("amount_wei must be a JSON string, not a number");
        assert!(
            !amount.is_empty() && amount.chars().all(|c| c.is_ascii_digit()),
            "amount_wei must be all-decimal-digits: {amount:?}"
        );
        assert!(amount.parse::<u128>().unwrap() > 0);
    }

    #[tokio::test]
    async fn gas_drip_inflight_guard_blocks_duplicate() {
        // Deterministic coverage of the in-flight guard's initial check: seed
        // the shared set directly rather than racing two real concurrent
        // requests. Calls the handler function directly (same module — no
        // HTTP layer needed to exercise this branch).
        let m = MockChain::new();
        m.set_eth_balance(RELAYER_ADDR, u128::MAX);
        m.set_gas_price(1_000_000_000);
        m.set_erc20_balance(GOAT, ALICE, 100);
        let dir = tempfile::tempdir().unwrap();
        let state = AppState {
            chain: Arc::new(m),
            registry_json: None,
            gas_drips_json: Some(dir.path().join("gas_drips.json")),
            goat_coin: GOAT.to_string(),
            drip_cfg: Arc::new(DripConfig::default()),
            inflight: Arc::new(Mutex::new(HashSet::new())),
            eip712: Eip712Config::default(),
            spend: None,
            rate: Arc::new(Mutex::new(RateLimiter::with_defaults())),
        };
        state
            .inflight
            .lock()
            .unwrap()
            .insert(ALICE.to_ascii_lowercase());

        let resp = relay_gas_drip(
            State(state),
            Json(GasDripRequest {
                wallet: ALICE.to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "DripInProgress");
    }

    // --- H1 perimeter regression ---

    /// Critical: valid shape + garbage signature must never reach MockChain.bind.
    #[tokio::test]
    async fn bind_garbage_signature_never_broadcasts() {
        let m = Arc::new(MockChain::new());
        let app =
            router_with_relayer_config(m.clone() as Arc<dyn ChainClient>, RelayerConfig::default());

        let body = serde_json::json!({
            "wallet": "0x00000000000000000000000000000000000000A1",
            "username": "GOAT-alice",
            "deadline": 2_000_000_000u64,
            "signature": "0xdeadbeef"
        });
        let r = post_json(&app, "/v1/relay/bind", body).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
        let err = r.body["error"].as_str().unwrap_or("");
        assert!(
            err.contains("BadSignature") || err.contains("malformed"),
            "error must surface BadSignature, got: {err}"
        );
        assert!(
            m.ops().is_empty(),
            "garbage sig must not produce any MockOp (got {:?})",
            m.ops()
        );
    }

    #[tokio::test]
    async fn enroll_garbage_signature_never_broadcasts() {
        let m = Arc::new(MockChain::new());
        let app =
            router_with_relayer_config(m.clone() as Arc<dyn ChainClient>, RelayerConfig::default());
        let body = serde_json::json!({
            "wallet": "0x00000000000000000000000000000000000000A1",
            "deadline": 2_000_000_000u64,
            "signature": "0xdeadbeef"
        });
        let r = post_json(&app, "/v1/relay/enroll", body).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
        assert!(
            m.ops().is_empty(),
            "garbage enroll sig must not produce MockOp (got {:?})",
            m.ops()
        );
    }

    #[tokio::test]
    async fn bind_valid_sig_succeeds_and_increments_nonce() {
        use crate::sig_verify::bind_digest;
        use alloy::primitives::B256;
        use alloy::signers::local::PrivateKeySigner;
        use alloy::signers::SignerSync;
        use std::str::FromStr;

        const PK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        const WALLET: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
        let binding = [0x11u8; 20];
        let chain_id = 31337u64;
        let username = "GOAT-alice";
        let deadline = 2_000_000_000u64;

        let m = Arc::new(MockChain::new());
        m.set_gas_price(1_000_000_000);
        let app = router_with_relayer_config(
            m.clone() as Arc<dyn ChainClient>,
            RelayerConfig {
                eip712: Eip712Config {
                    chain_id,
                    worker_binding: binding,
                    enrollment_registry: [0u8; 20],
                },
                ..RelayerConfig::default()
            },
        );

        let nonce = m.binding_nonce(WALLET).unwrap();
        assert_eq!(nonce, 0);
        let wallet20 = crate::merkle::parse_address(WALLET).unwrap();
        let digest = bind_digest(wallet20, username, nonce, deadline, chain_id, binding);
        let signer = PrivateKeySigner::from_str(PK).unwrap();
        let sig = signer.sign_hash_sync(&B256::from(digest)).unwrap();
        let sig_hex = format!("0x{}", hex::encode(sig.as_bytes()));

        let r = post_json(
            &app,
            "/v1/relay/bind",
            serde_json::json!({
                "wallet": WALLET,
                "username": username,
                "deadline": deadline,
                "signature": sig_hex,
            }),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        assert_eq!(m.binding_nonce(WALLET).unwrap(), 1);
        assert_eq!(m.ops().len(), 1);
    }
}
