//! Global daily spend ceiling (H2) + drip sub-budget (H2b).
//!
//! Fail-CLOSED on corrupt/unreadable state (opposite of `DripLedger` fail-open):
//! this ledger exists only to bound operator loss, so a corrupt file must not
//! grant unlimited spend.
//!
//! Do **not** merge this into `gas_drips.rs` — different shape (one global wei
//! total vs per-wallet counts) and different fail policy.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::gas_drips::utc_today;

/// H2: 0.05 ETH/day global ceiling (founder-ratified 2026-07-20).
pub const DEFAULT_DAILY_CEILING_WEI: u128 = 50_000_000_000_000_000;
/// H2b: 0.005 ETH/day drip sub-budget (founder-ratified 2026-07-20).
pub const DEFAULT_DRIP_BUDGET_WEI: u128 = 5_000_000_000_000_000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SpendError {
    #[error("SpendCeilingReached")]
    CeilingReached,
    #[error("DripBudgetExhausted")]
    DripBudgetExhausted,
    #[error("spend ledger unavailable: {0}")]
    Unavailable(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpendState {
    date: String,
    /// Decimal string to keep full u128 range under serde_json.
    total_wei: String,
    drip_wei: String,
}

impl SpendState {
    fn empty_today(today: &str) -> Self {
        Self {
            date: today.to_string(),
            total_wei: "0".into(),
            drip_wei: "0".into(),
        }
    }

    fn total(&self) -> Result<u128, SpendError> {
        self.total_wei
            .parse::<u128>()
            .map_err(|e| SpendError::Unavailable(format!("bad total_wei: {e}")))
    }

    fn drip(&self) -> Result<u128, SpendError> {
        self.drip_wei
            .parse::<u128>()
            .map_err(|e| SpendError::Unavailable(format!("bad drip_wei: {e}")))
    }
}

/// File-backed global UTC-daily spend counters.
pub struct SpendLedger {
    pub path: PathBuf,
    pub ceiling_wei: u128,
    pub drip_budget_wei: u128,
}

impl SpendLedger {
    pub fn new(path: PathBuf, ceiling_wei: u128, drip_budget_wei: u128) -> Self {
        Self {
            path,
            ceiling_wei,
            drip_budget_wei,
        }
    }

    pub fn with_defaults(path: PathBuf) -> Self {
        Self::new(path, DEFAULT_DAILY_CEILING_WEI, DEFAULT_DRIP_BUDGET_WEI)
    }

    /// Read-only check: would `total_add` (and optional drip sub-add) fit under ceilings?
    /// `drip_add == 0` skips the H2b check.
    ///
    /// **Pilot residual (consultant #2):** handlers use check → send → `try_record_*`.
    /// Concurrent binds can slightly overshoot 0.05 ETH before records land. OK at
    /// 1–5 testers; mainnet needs reserve-before-send under a mutex.
    pub fn can_spend(&self, total_add: u128, drip_add: u128) -> Result<(), SpendError> {
        let today = utc_today();
        let state = self.load_for_today(&today)?;
        let total = state.total()?;
        let drip = state.drip()?;
        if total.saturating_add(total_add) > self.ceiling_wei {
            return Err(SpendError::CeilingReached);
        }
        if drip_add > 0 && drip.saturating_add(drip_add) > self.drip_budget_wei {
            return Err(SpendError::DripBudgetExhausted);
        }
        Ok(())
    }

    /// Check total+amount ≤ ceiling, then persist. Counts only against H2 total.
    pub fn try_record_total(&self, amount_wei: u128) -> Result<(), SpendError> {
        self.mutate(|total, drip| {
            let new_total = total.saturating_add(amount_wei);
            if new_total > self.ceiling_wei {
                return Err(SpendError::CeilingReached);
            }
            Ok((new_total, drip))
        })
    }

    /// Check against H2 total AND H2b drip budget, then persist both counters.
    pub fn try_record_drip(&self, amount_wei: u128) -> Result<(), SpendError> {
        self.mutate(|total, drip| {
            let new_total = total.saturating_add(amount_wei);
            let new_drip = drip.saturating_add(amount_wei);
            if new_total > self.ceiling_wei {
                return Err(SpendError::CeilingReached);
            }
            if new_drip > self.drip_budget_wei {
                return Err(SpendError::DripBudgetExhausted);
            }
            Ok((new_total, new_drip))
        })
    }

    fn mutate(
        &self,
        f: impl FnOnce(u128, u128) -> Result<(u128, u128), SpendError>,
    ) -> Result<(), SpendError> {
        let today = utc_today();
        let state = self.load_for_today(&today)?;
        let total = state.total()?;
        let drip = state.drip()?;
        let (new_total, new_drip) = f(total, drip)?;
        let next = SpendState {
            date: today,
            total_wei: new_total.to_string(),
            drip_wei: new_drip.to_string(),
        };
        self.save(&next)
    }

    /// Load state for `today`. Missing file → zeros. Corrupt/unreadable → Unavailable.
    /// Stale date → zeros (UTC day rollover).
    fn load_for_today(&self, today: &str) -> Result<SpendState, SpendError> {
        if !self.path.exists() {
            return Ok(SpendState::empty_today(today));
        }
        let bytes = std::fs::read(&self.path).map_err(|e| {
            tracing::error!(
                path = %self.path.display(),
                error = %e,
                "spend_ledger: unreadable (fail-closed)"
            );
            SpendError::Unavailable(format!("read: {e}"))
        })?;
        let state: SpendState = serde_json::from_slice(&bytes).map_err(|e| {
            tracing::error!(
                path = %self.path.display(),
                error = %e,
                "spend_ledger: corrupt (fail-closed)"
            );
            SpendError::Unavailable(format!("corrupt: {e}"))
        })?;
        if state.date != today {
            return Ok(SpendState::empty_today(today));
        }
        // Validate numeric fields early.
        let _ = state.total()?;
        let _ = state.drip()?;
        Ok(state)
    }

    fn save(&self, state: &SpendState) -> Result<(), SpendError> {
        atomic_write_json(&self.path, state).map_err(|e| {
            tracing::error!(
                path = %self.path.display(),
                error = %e,
                "spend_ledger: write failed (fail-closed)"
            );
            SpendError::Unavailable(e)
        })
    }
}

fn atomic_write_json(path: &Path, state: &SpendState) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create_dir_all: {e}"))?;
    }
    let bytes = serde_json::to_vec(state).map_err(|e| format!("serialize: {e}"))?;
    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    let tmp_path = PathBuf::from(tmp_os);
    std::fs::write(&tmp_path, &bytes).map_err(|e| format!("write tmp: {e}"))?;
    std::fs::rename(&tmp_path, path).map_err(|e| format!("rename: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_ledger(ceiling: u128, drip_budget: u128) -> (SpendLedger, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spend_ledger.json");
        (SpendLedger::new(path, ceiling, drip_budget), dir)
    }

    #[test]
    fn accumulate_total() {
        let (led, _dir) = tmp_ledger(1_000, 500);
        led.try_record_total(100).unwrap();
        led.try_record_total(200).unwrap();
        assert!(led.can_spend(700, 0).is_ok());
        assert_eq!(led.can_spend(701, 0), Err(SpendError::CeilingReached));
    }

    #[test]
    fn ceiling_refuse() {
        let (led, _dir) = tmp_ledger(100, 50);
        led.try_record_total(100).unwrap();
        assert_eq!(led.try_record_total(1), Err(SpendError::CeilingReached));
    }

    #[test]
    fn drip_budget_refuse() {
        let (led, _dir) = tmp_ledger(10_000, 50);
        led.try_record_drip(50).unwrap();
        assert_eq!(led.try_record_drip(1), Err(SpendError::DripBudgetExhausted));
        // Total still has room; drip sub-budget is the limit.
        assert_eq!(led.can_spend(1, 1), Err(SpendError::DripBudgetExhausted));
        assert!(led.can_spend(1, 0).is_ok());
    }

    #[test]
    fn drip_counts_against_total() {
        let (led, _dir) = tmp_ledger(100, 1_000);
        led.try_record_drip(60).unwrap();
        // 60 already spent; total ceiling 100 → only 40 left.
        assert_eq!(led.try_record_total(41), Err(SpendError::CeilingReached));
        led.try_record_total(40).unwrap();
    }

    #[test]
    fn day_rollover_zeros_counters() {
        let (led, _dir) = tmp_ledger(100, 50);
        // Write a stale-date file directly.
        let stale = SpendState {
            date: "1970-01-01".into(),
            total_wei: "99".into(),
            drip_wei: "49".into(),
        };
        atomic_write_json(&led.path, &stale).unwrap();
        // Today is not 1970-01-01 → treat as empty.
        assert!(led.can_spend(100, 50).is_ok());
        led.try_record_total(1).unwrap();
        // Persist should show today's date.
        let bytes = std::fs::read(&led.path).unwrap();
        let state: SpendState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(state.date, utc_today());
        assert_eq!(state.total_wei, "1");
        assert_eq!(state.drip_wei, "0");
    }

    #[test]
    fn corrupt_fail_closed() {
        let (led, _dir) = tmp_ledger(100, 50);
        std::fs::write(&led.path, b"not-json{{{").unwrap();
        assert!(matches!(
            led.can_spend(1, 0),
            Err(SpendError::Unavailable(_))
        ));
        assert!(matches!(
            led.try_record_total(1),
            Err(SpendError::Unavailable(_))
        ));
    }

    #[test]
    fn missing_file_is_empty_not_error() {
        let (led, _dir) = tmp_ledger(100, 50);
        assert!(!led.path.exists());
        assert!(led.can_spend(100, 50).is_ok());
        led.try_record_total(1).unwrap();
        assert!(led.path.exists());
    }

    #[test]
    fn defaults_match_founder_ratified() {
        assert_eq!(DEFAULT_DAILY_CEILING_WEI, 50_000_000_000_000_000);
        assert_eq!(DEFAULT_DRIP_BUDGET_WEI, 5_000_000_000_000_000);
    }
}
