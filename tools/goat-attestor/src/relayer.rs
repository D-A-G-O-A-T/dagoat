//! Gas-sponsorship relayer HTTP API: bindWithSignature / enrollSelfWithSignature.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

use crate::chain::ChainClient;
use crate::merkle::parse_address;

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

/// Shared chain handle. `ChainClient` implementations use interior mutability
/// (e.g. `MockChain`), so `Arc<dyn ChainClient>` is sufficient.
#[derive(Clone)]
pub struct AppState {
    pub chain: Arc<dyn ChainClient>,
    /// When set, successful gasless bind upserts this registry immediately.
    pub registry_json: Option<std::path::PathBuf>,
}

/// Build axum router for the relayer over any `ChainClient`.
///
/// Accepts `Arc<C>` or anything convertible to `Arc<dyn ChainClient>`.
///
/// CORS is open for local pilot: desktop Vite (`http://localhost:5173`) and Tauri fetch
/// `http://127.0.0.1:8787` — without this, browsers report generic "Failed to fetch".
pub fn router(chain: Arc<dyn ChainClient>) -> Router {
    router_with_registry(chain, None)
}

/// Relayer + optional live auto-register of binds into `registry.json`.
pub fn router_with_registry(
    chain: Arc<dyn ChainClient>,
    registry_json: Option<std::path::PathBuf>,
) -> Router {
    let state = AppState {
        chain,
        registry_json,
    };
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);
    Router::new()
        .route("/health", get(health))
        .route("/v1/relay/bind", post(relay_bind))
        .route("/v1/relay/enroll", post(relay_enroll))
        .layer(cors)
        .with_state(state)
}

/// Convenience: wrap a concrete client in `Arc` and erase to dyn.
pub fn router_for<C: ChainClient + 'static>(chain: C) -> Router {
    router(Arc::new(chain))
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true, "service": "goat-attestor-relayer" }))
}

async fn relay_bind(
    State(state): State<AppState>,
    Json(req): Json<BindRelayRequest>,
) -> impl IntoResponse {
    if let Err(e) = validate_bind_request(&req) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RelayResponse {
                ok: false,
                tx_hash: None,
                error: Some(e.to_string()),
            }),
        );
    }
    let wallet = match parse_address(&req.wallet) {
        Ok(w) => w,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(RelayResponse {
                    ok: false,
                    tx_hash: None,
                    error: Some(e),
                }),
            );
        }
    };
    let sig = match decode_sig(&req.signature) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(RelayResponse {
                    ok: false,
                    tx_hash: None,
                    error: Some(e),
                }),
            );
        }
    };
    let result =
        state
            .chain
            .bind_with_signature(wallet, &req.username, req.deadline, &sig);
    match result {
        Ok(tx) => {
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
    if let Err(e) = validate_enroll_request(&req) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RelayResponse {
                ok: false,
                tx_hash: None,
                error: Some(e.to_string()),
            }),
        );
    }
    let wallet = match parse_address(&req.wallet) {
        Ok(w) => w,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(RelayResponse {
                    ok: false,
                    tx_hash: None,
                    error: Some(e),
                }),
            );
        }
    };
    let sig = match decode_sig(&req.signature) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(RelayResponse {
                    ok: false,
                    tx_hash: None,
                    error: Some(e),
                }),
            );
        }
    };
    let result = state
        .chain
        .enroll_self_with_signature(wallet, req.deadline, &sig);
    match result {
        Ok(tx) => (
            StatusCode::OK,
            Json(RelayResponse {
                ok: true,
                tx_hash: Some(format!("0x{}", hex::encode(tx))),
                error: None,
            }),
        ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::MockChain;
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
}
