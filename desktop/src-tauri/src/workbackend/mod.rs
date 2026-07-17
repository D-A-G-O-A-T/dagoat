//! WorkBackend plugin plane — Task S5.
//!
//! This is the universal-Miner architecture law of GoatCoin Season 0 (design §3,
//! `docs/superpowers/specs/2026-07-11-season0-fullsystem-design.md`): the Miner UI never talks
//! to a device- or vendor-specific backend directly, only to this trait and the `catalog`
//! module. A backend is a pluggable source of public-good work — Folding@home today, an NGO
//! partner tomorrow — and the mint basis is always the beneficiary's own credit accounting,
//! never GPU model, TFLOPS, uptime, or power level (design §4).
//!
//! - `catalog` is what the UI renders (selector cards, enabled/disabled, honesty tags).
//! - `rehearsal` is a deterministic fake adapter for CI/anvil e2e only, gated behind
//!   `GOAT_REHEARSAL=1`.
//! - `fah` is the real Folding@home adapter (Task S6): WebSocket control of the FAHClient v8 local
//!   API + stats-delta completions from `https://api.foldingathome.org/user/{username}`. It
//!   reports "not installed" honestly when no client is present and never fabricates progress.

pub mod catalog;
pub mod fah;
pub mod rehearsal;

use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Install/attach state for a backend, as reported by `detect_install`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallState {
    Missing,
    Installed,
    Running,
}

/// Managed-engine lifecycle state (P3-direct). Distinct from `InstallState`: covers
/// provisioning, external attach, and actionable errors for one-product Contribute UX.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineState {
    Missing,
    Provisioning,
    Ready,
    Running,
    External,
    Error,
}

/// Result of `ensure_engine` / `start_engine` — honest detail, never fabricated progress.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EngineReport {
    pub state: EngineState,
    pub detail: String,
    /// True when Goat manages/starts the engine process; false for in-process fakes or pure attach.
    pub managed: bool,
}

/// Resource-control power level (e.g. FAH folding power). Design §4: this is resource control
/// only and never affects the mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerLevel {
    Low,
    Medium,
    Full,
}

/// Live progress for a single in-flight unit of work, as shown in the Miner tab.
/// Progress fields mirror FAH Web Control (`unit.js` → `wu_progress` / `progress`):
/// `progress` is 0..1; `progress_pct` is the same value as the web UI string (e.g. `"25.5"`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UnitProgress {
    pub id: String,
    /// Short FAH work-unit number (UI label); full `id` stays for title/tooltip.
    pub number: Option<u64>,
    pub project: String,
    /// 0.0..=1.0 (prefer `wu_progress` over `progress`, same as FAH Web Control).
    pub progress: f32,
    /// One-decimal percent string matching FAH web (`toFixed(1)`), e.g. `"25.5"`.
    pub progress_pct: String,
    /// `"GPU"` or `"CPU"` (from assignment resources).
    pub resource: String,
    /// FAH unit state token (`RUN`, `PAUSE`, …).
    pub state: String,
}

/// Snapshot of a backend's current run state.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BackendStatus {
    pub state: String,
    pub units: Vec<UnitProgress>,
    pub detail: String,
    /// True when the underlying client is bound to the beneficiary's own account and therefore
    /// ignores local resource-config commands (e.g. a Folding@home account-linked FAHClient). The
    /// UI uses this to avoid claiming Goat applied CPU/GPU settings it could not actually change.
    #[serde(default)]
    pub linked: bool,
    /// Live FAH `config.team` when known (stringified number). None if not in the state tree yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    /// Live FAH client version from `info.version` (e.g. `"8.5.5"`). None until WS snapshot lands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
}

/// One field of a backend's `configure()` form, declared by the adapter itself so the UI
/// renders the config form from the catalog entry rather than hardcoding field names per
/// backend. `secret` marks fields (e.g. a passkey) that the UI must render as a password input.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConfigField {
    pub key: &'static str,
    pub label: &'static str,
    pub secret: bool,
}

/// A single accepted/credited unit of work, normalized across backends.
///
/// `weight` is always 1 for Season 0 — the published formula is "1 credited work unit = 1 GOAT"
/// (design §4). `evidence` is a beneficiary-side accounting reference (e.g. a stats snapshot
/// hash), never a locally-fabricated value.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WorkUnit {
    pub unit_id: String,
    pub weight: u64,
    pub backend_ref: String,
    pub at: u64,
    pub evidence: String,
}

/// A pluggable source of public-good work.
///
/// Every method is intentionally beneficiary-agnostic: nothing here names a device type or
/// inspects work content (the same layering discipline `goat-neutrality` enforces on
/// `goat-protocol` in the root spine). Backend-specific detail lives entirely inside the
/// implementer.
#[async_trait]
pub trait WorkBackend: Send + Sync {
    /// Stable catalog id, e.g. `"folding_at_home"`.
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    /// Who the work actually benefits — shown verbatim in the Miner job card.
    fn beneficiary(&self) -> &'static str;
    /// Sandbox/trust tier disclosure, e.g. "Class C — host runs the official FAHClient".
    fn isolation_class(&self) -> &'static str;
    /// Honesty-rule copy fragments (formula, isolation caveats, rehearsal warnings, ...).
    fn honesty_tags(&self) -> Vec<String>;

    /// Best-effort local detection of the backend client (never assumes; reports `Missing`
    /// honestly when unsure).
    fn detect_install(&self) -> InstallState;
    /// Human-readable "how to install/attach" copy shown when `detect_install` != `Running`.
    fn install_hint(&self) -> String;

    /// Whether this backend supports managed engine lifecycle (download/start under Goat).
    fn supports_managed_engine(&self) -> bool;

    /// Current managed-engine lifecycle state (maps from `detect_install` at minimum).
    fn engine_state(&self) -> EngineState;

    /// Richer managed-engine snapshot: the current `EngineState` plus an honest human-readable
    /// detail string (e.g. live download/EULA progress while `ensure_engine` runs). The default
    /// derives from `engine_state` with no detail; managed adapters override it so the UI can
    /// poll provisioning progress concurrently with a long-running `ensure_engine`. Never
    /// fabricates progress — an unknown phase yields an empty detail, not an invented percentage.
    fn engine_report(&self) -> EngineReport {
        EngineReport {
            state: self.engine_state(),
            detail: String::new(),
            managed: self.supports_managed_engine(),
        }
    }

    /// Ensure the engine is provisioned and ready: detect → start if installed → or open
    /// official install path when missing. Never fabricates progress.
    async fn ensure_engine(&self) -> Result<EngineReport, String>;

    /// Start the managed engine process/service when possible (may alias `ensure_engine`).
    async fn start_engine(&self) -> Result<EngineReport, String>;

    /// Best-effort stop. Safe to be a no-op when the engine is user-owned (e.g. external FAH).
    async fn stop_engine(&self) -> Result<(), String>;

    async fn connect(&self) -> Result<(), String>;
    async fn disconnect(&self) -> Result<(), String>;

    async fn start(&self) -> Result<(), String>;
    async fn stop(&self) -> Result<(), String>;
    async fn pause(&self) -> Result<(), String>;

    /// Dump (discard) one stuck work unit by FAH unit id. FAH v8 WebSocket `cmd: dump`.
    /// Default: unsupported. FAH adapter implements this for Assign/Download stuck recovery.
    async fn dump_unit(&self, unit_id: &str) -> Result<(), String> {
        let _ = unit_id;
        Err("dump not supported for this backend".into())
    }

    async fn status(&self) -> BackendStatus;
    /// Newly accepted/credited units since the last call (delta, not cumulative history).
    ///
    /// At-most-once delivery: returned units advance the adapter's durable baseline and are
    /// NEVER redelivered. The caller MUST durably record returned units (pending journal) before
    /// using them for any accept/mint flow. (S9 hard contract.)
    async fn list_completions(&self) -> Vec<WorkUnit>;

    async fn set_power(&self, level: PowerLevel) -> Result<(), String>;

    /// Backend-local config (e.g. FAH username/team/passkey). Never logged, never in git.
    fn configure(&self, key: &str, value: &str) -> Result<(), String>;

    /// Declares the config form the UI should render for `configure()` — key, label, and
    /// whether the field is secret (password input). Empty for backends with nothing to
    /// configure (e.g. the rehearsal fixture).
    fn config_fields(&self) -> Vec<ConfigField>;
}

/// Trait-object registry keyed by backend id, held as Tauri managed state.
///
/// Deliberately separate from `catalog`: the catalog is what the UI renders (including rows
/// with no backend behind them yet, like the disabled NGO placeholder); the registry only ever
/// holds ids that have a real `WorkBackend` implementation wired up.
pub struct Registry(pub HashMap<&'static str, Box<dyn WorkBackend>>);

impl Registry {
    pub fn get(&self, id: &str) -> Result<&dyn WorkBackend, String> {
        self.0
            .get(id)
            .map(|backend| backend.as_ref())
            .ok_or_else(|| format!("unknown backend id: {id}"))
    }
}

/// Builds the runtime registry. The real Folding@home adapter (`fah::FahBackend`) is always
/// present; the rehearsal adapter is added only when `GOAT_REHEARSAL=1` is set at startup,
/// matching the gating in `catalog::catalog_entries`.
pub fn build_registry() -> Registry {
    let mut map: HashMap<&'static str, Box<dyn WorkBackend>> = HashMap::new();
    map.insert("folding_at_home", Box::new(fah::FahBackend::new()));
    if rehearsal::rehearsal_enabled() {
        map.insert("rehearsal", Box::new(rehearsal::RehearsalBackend::new()));
    }
    Registry(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn registry_dispatches_through_trait_object() {
        let registry = build_registry();
        let backend = registry
            .get("folding_at_home")
            .expect("FAH stub is always registered");

        assert_eq!(backend.id(), "folding_at_home");
        assert!(backend.supports_managed_engine());
        // engine_state maps from detect_install on this host (FAH may or may not be present).
        let install = backend.detect_install();
        match install {
            InstallState::Missing => assert_eq!(backend.engine_state(), EngineState::Missing),
            InstallState::Installed => assert_eq!(backend.engine_state(), EngineState::Ready),
            InstallState::Running => assert_eq!(backend.engine_state(), EngineState::Running),
        }

        let status = backend.status().await;
        assert!(!status.state.is_empty());
        if install == InstallState::Missing {
            assert_eq!(status.state, "not_installed");
            assert!(status.units.is_empty());
        }

        assert!(backend.list_completions().await.is_empty());
    }

    // The `env_lock` guard is intentionally held across the `ensure_engine().await` below: it
    // serializes the process-global `GOAT_REHEARSAL` mutation for the whole test (set → build →
    // assert → await → remove) so a parallel test never observes our env var. The rehearsal
    // future is in-process and cannot deadlock on this std Mutex.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn engine_lifecycle_dispatch_fah_and_rehearsal() {
        let registry = build_registry();
        let fah = registry.get("folding_at_home").expect("FAH always present");
        assert!(fah.supports_managed_engine());
        match fah.detect_install() {
            InstallState::Missing => assert_eq!(fah.engine_state(), EngineState::Missing),
            InstallState::Installed => assert_eq!(fah.engine_state(), EngineState::Ready),
            InstallState::Running => assert_eq!(fah.engine_state(), EngineState::Running),
        }

        let _guard = rehearsal::env_lock();
        std::env::set_var("GOAT_REHEARSAL", "1");
        let registry_r = build_registry();
        let re = registry_r.get("rehearsal").expect("rehearsal with env");
        assert!(!re.supports_managed_engine());
        assert_eq!(re.engine_state(), EngineState::Ready);
        let report = re.ensure_engine().await.expect("ensure");
        assert_eq!(report.state, EngineState::Ready);
        assert!(!report.managed);
        assert!(report.detail.contains("in-process fake"));
        std::env::remove_var("GOAT_REHEARSAL");
    }

    #[test]
    fn unknown_backend_id_errors() {
        let registry = build_registry();
        match registry.get("does_not_exist") {
            Ok(_) => panic!("expected an error for an unregistered backend id"),
            Err(err) => assert!(err.contains("does_not_exist")),
        }
    }

    #[tokio::test]
    async fn rehearsal_absent_from_registry_without_env() {
        let _guard = rehearsal::env_lock();
        std::env::remove_var("GOAT_REHEARSAL");

        let registry = build_registry();
        assert!(registry.get("rehearsal").is_err());
    }

    #[tokio::test]
    async fn rehearsal_present_in_registry_with_env() {
        let _guard = rehearsal::env_lock();
        std::env::set_var("GOAT_REHEARSAL", "1");

        let registry = build_registry();
        let backend = registry.get("rehearsal").expect("must be registered");
        assert_eq!(backend.id(), "rehearsal");

        std::env::remove_var("GOAT_REHEARSAL");
    }
}
