//! Deterministic REHEARSAL adapter — CI/anvil e2e only, never the founder demo path.
//!
//! Gated behind `GOAT_REHEARSAL=1`, checked once when the registry is built at startup
//! (`super::build_registry`) and mirrored by `catalog::catalog_entries` so the UI never shows a
//! selector card for a backend id that isn't actually registered. Its catalog row always carries
//! the honesty tag "REHEARSAL — CI only, not a founder demo".

use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;

use super::{
    BackendStatus, ConfigField, EngineReport, EngineState, InstallState, PowerLevel, UnitProgress,
    WorkBackend, WorkUnit,
};

/// Progress advance (percentage points) per `status()` poll.
const PROGRESS_STEP_PCT: u64 = 20;
/// A poll count that's an exact multiple of this rolls the fake unit over and yields one
/// completed `WorkUnit` — "completion every N polls".
const POLLS_PER_COMPLETION: u64 = 100 / PROGRESS_STEP_PCT;
/// Base epoch-looking value for the deterministic `WorkUnit::at` field (kept deterministic —
/// not `SystemTime::now()` — so repeated CI runs assert exact values).
const REHEARSAL_EPOCH_BASE: u64 = 1_700_000_000;

pub(crate) fn rehearsal_enabled() -> bool {
    std::env::var("GOAT_REHEARSAL").as_deref() == Ok("1")
}

/// Env-var mutation is process-global; only test code touches `GOAT_REHEARSAL` at runtime (real
/// startup reads it exactly once in `super::build_registry`), so this lock — and the tests that
/// use it across `workbackend` submodules — only exists under `#[cfg(test)]`. It serializes any
/// test that reads/writes the var so parallel `cargo test` runs can't race each other, and
/// recovers from poisoning so one panicking test doesn't cascade.
#[cfg(test)]
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Deterministic fake `WorkBackend`: each `status()` poll advances one fake unit's progress by
/// a fixed step; every `POLLS_PER_COMPLETION`th poll rolls the unit over and mints one
/// completion. `list_completions()` returns only the units newly completed since the last call
/// (delta semantics, matching the real FAH stats-delta model in design §3).
pub(crate) struct RehearsalBackend {
    polls: AtomicU64,
    completions: AtomicU64,
    reported: AtomicU64,
}

impl RehearsalBackend {
    pub(crate) fn new() -> Self {
        Self {
            polls: AtomicU64::new(0),
            completions: AtomicU64::new(0),
            reported: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl WorkBackend for RehearsalBackend {
    fn id(&self) -> &'static str {
        "rehearsal"
    }

    fn display_name(&self) -> &'static str {
        "Rehearsal (fake)"
    }

    fn beneficiary(&self) -> &'static str {
        "None — deterministic CI fixture, no real work is performed"
    }

    fn isolation_class(&self) -> &'static str {
        "N/A — in-process fake, no host process involved"
    }

    fn honesty_tags(&self) -> Vec<String> {
        vec!["REHEARSAL — CI only, not a founder demo".to_string()]
    }

    fn detect_install(&self) -> InstallState {
        InstallState::Running
    }

    fn install_hint(&self) -> String {
        "Rehearsal adapter is always \"installed\" — it is an in-process fake.".to_string()
    }

    fn supports_managed_engine(&self) -> bool {
        false
    }

    fn engine_state(&self) -> EngineState {
        EngineState::Ready
    }

    async fn ensure_engine(&self) -> Result<EngineReport, String> {
        Ok(EngineReport {
            state: EngineState::Ready,
            detail: "in-process fake".to_string(),
            managed: false,
        })
    }

    async fn start_engine(&self) -> Result<EngineReport, String> {
        self.ensure_engine().await
    }

    async fn stop_engine(&self) -> Result<(), String> {
        Ok(())
    }

    async fn connect(&self) -> Result<(), String> {
        Ok(())
    }

    async fn disconnect(&self) -> Result<(), String> {
        Ok(())
    }

    async fn start(&self) -> Result<(), String> {
        Ok(())
    }

    async fn stop(&self) -> Result<(), String> {
        Ok(())
    }

    async fn pause(&self) -> Result<(), String> {
        Ok(())
    }

    async fn status(&self) -> BackendStatus {
        let poll = self.polls.fetch_add(1, Ordering::SeqCst) + 1;
        let step_in_cycle = poll % POLLS_PER_COMPLETION;
        let progress_pct = if step_in_cycle == 0 {
            100
        } else {
            step_in_cycle * PROGRESS_STEP_PCT
        };

        if step_in_cycle == 0 {
            self.completions.fetch_add(1, Ordering::SeqCst);
        }

        // progress is 0..1 (same as FAH wu_progress); progress_pct matches Web Control style.
        let frac = (progress_pct as f32 / 100.0).clamp(0.0, 1.0);
        BackendStatus {
            state: "running".to_string(),
            units: vec![UnitProgress {
                id: "rehearsal-wu-current".to_string(),
                number: Some(poll),
                project: "rehearsal".to_string(),
                progress: frac,
                progress_pct: format!("{:.1}", progress_pct as f32),
                resource: "CPU".to_string(),
                state: "RUN".to_string(),
            }],
            detail: format!("poll #{poll}"),
            linked: false,
            team: None,
            client_version: None,
        }
    }

    async fn list_completions(&self) -> Vec<WorkUnit> {
        let total = self.completions.load(Ordering::SeqCst);
        let already_reported = self.reported.swap(total, Ordering::SeqCst);

        (already_reported + 1..=total)
            .map(|i| WorkUnit {
                unit_id: format!("rehearsal-wu-{i}"),
                weight: 1,
                backend_ref: "rehearsal".to_string(),
                at: REHEARSAL_EPOCH_BASE + i,
                evidence: format!("rehearsal-evidence-{i}"),
            })
            .collect()
    }

    async fn set_power(&self, _level: PowerLevel) -> Result<(), String> {
        Ok(())
    }

    fn configure(&self, _key: &str, _value: &str) -> Result<(), String> {
        Ok(())
    }

    fn config_fields(&self) -> Vec<ConfigField> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn progress_advances_per_poll_and_wraps_at_100() {
        let backend = RehearsalBackend::new();

        let s1 = backend.status().await;
        // progress is 0..1 (FAH wu_progress scale); progress_pct is "20.0".
        assert!((s1.units[0].progress - 0.2).abs() < 1e-6);
        assert_eq!(s1.units[0].progress_pct, "20.0");
        assert_eq!(s1.state, "running");

        for _ in 0..3 {
            backend.status().await;
        }
        let s5 = backend.status().await;
        assert!(
            (s5.units[0].progress - 1.0).abs() < 1e-6,
            "5th poll completes the cycle"
        );

        let s6 = backend.status().await;
        assert!(
            (s6.units[0].progress - 0.2).abs() < 1e-6,
            "6th poll starts a new cycle"
        );
    }

    #[tokio::test]
    async fn completion_every_n_polls_is_deterministic() {
        let backend = RehearsalBackend::new();

        // 4 polls: no completion yet.
        for _ in 0..4 {
            backend.status().await;
        }
        assert!(backend.list_completions().await.is_empty());

        // 5th poll rolls the cycle over -> exactly one completion.
        backend.status().await;
        let first_batch = backend.list_completions().await;
        assert_eq!(first_batch.len(), 1);
        assert_eq!(
            first_batch[0],
            WorkUnit {
                unit_id: "rehearsal-wu-1".to_string(),
                weight: 1,
                backend_ref: "rehearsal".to_string(),
                at: REHEARSAL_EPOCH_BASE + 1,
                evidence: "rehearsal-evidence-1".to_string(),
            }
        );

        // Already-reported completions are never returned twice.
        assert!(backend.list_completions().await.is_empty());

        // 10 more polls -> exactly two more completions (rollovers at polls 10 and 15).
        for _ in 0..10 {
            backend.status().await;
        }
        let second_batch = backend.list_completions().await;
        assert_eq!(second_batch.len(), 2);
        assert_eq!(second_batch[0].unit_id, "rehearsal-wu-2");
        assert_eq!(second_batch[1].unit_id, "rehearsal-wu-3");
    }

    #[test]
    fn env_gate_reads_exact_value() {
        let _guard = env_lock();

        std::env::remove_var("GOAT_REHEARSAL");
        assert!(!rehearsal_enabled());

        std::env::set_var("GOAT_REHEARSAL", "true");
        assert!(!rehearsal_enabled(), "only the literal \"1\" enables it");

        std::env::set_var("GOAT_REHEARSAL", "1");
        assert!(rehearsal_enabled());

        std::env::remove_var("GOAT_REHEARSAL");
    }

    #[tokio::test]
    async fn honesty_tags_carry_the_ci_only_disclosure() {
        let backend = RehearsalBackend::new();
        assert!(backend
            .honesty_tags()
            .contains(&"REHEARSAL — CI only, not a founder demo".to_string()));
        assert_eq!(backend.id(), "rehearsal");
        assert!(backend.beneficiary().contains("no real work is performed"));
    }

    #[tokio::test]
    async fn engine_state_is_ready_unmanaged_fake() {
        let backend = RehearsalBackend::new();
        assert!(!backend.supports_managed_engine());
        assert_eq!(backend.engine_state(), EngineState::Ready);
        let report = backend.ensure_engine().await.unwrap();
        assert_eq!(report.state, EngineState::Ready);
        assert!(!report.managed);
        assert_eq!(report.detail, "in-process fake");
        assert!(backend.stop_engine().await.is_ok());
    }
}
