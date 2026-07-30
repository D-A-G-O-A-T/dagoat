//! Pure per-wallet daily drip-counter ledger for the gasless-sell gas-drip
//! feature (GD task 3).
//!
//! The gas-drip relayer endpoint (GD5) enforces "N drips per wallet per UTC
//! day" using this counter. This module is intentionally pure/persisted-only:
//! the reserve/commit boundary (check-before-send, **reserve-before-send** as
//! of the FIX-A revision — `commit` runs BEFORE the native send, and a
//! `commit` failure fails the request closed with no send) lives in the GD5
//! handler, NOT here — see `DripLedger::commit` docs.
//!
//! **Wall-clock vs chain-time**: `utc_today()` is deliberately WALL-CLOCK
//! UTC, not chain time — this is an off-chain testnet budget control, unlike
//! `proposer::daily_epoch_id` / `chain_or_wall_now`, which derive on-chain
//! epoch ids from chain time with wall-clock fallback. Conflating the two
//! caused a prior bug (see T31: chain-time day-rollover vs wall-clock-cached
//! reads). Do not route this module's "today" through chain time.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Default daily drip cap per wallet (testnet default; spec G-series).
pub const DEFAULT_DAILY_CAP: u32 = 1;

/// Persisted counter entry for a single wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DripEntry {
    date: String,
    count: u32,
}

/// Pure, file-backed per-wallet daily drip counter.
///
/// Storage is a single JSON file at `path`:
/// `{ "<wallet-lowercase>": { "date": "YYYY-MM-DD", "count": N } }`.
pub struct DripLedger {
    pub path: PathBuf,
}

impl DripLedger {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load the persisted map, tolerating a missing or corrupt file.
    ///
    /// Fail-open on read is a deliberate TESTNET-ONLY choice (spec §3): a
    /// missing or corrupt ledger file is treated as empty (all wallets at 0
    /// drips today) rather than blocking sells. This means a corrupt counter
    /// *grants* drips instead of denying them — acceptable for a testnet
    /// budget cap, but must be revisited (fail-closed) before mainnet.
    fn load_map(&self) -> HashMap<String, DripEntry> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HashMap::new(),
            Err(e) => {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %e,
                    "gas_drips: ledger file unreadable, treating as empty (fail-open, testnet-only)"
                );
                return HashMap::new();
            }
        };
        match serde_json::from_slice(&bytes) {
            Ok(map) => map,
            Err(e) => {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %e,
                    "gas_drips: ledger file corrupt/unparseable, treating as empty (fail-open, testnet-only)"
                );
                HashMap::new()
            }
        }
    }

    /// Write `map` atomically: serialize to a sibling `.tmp` file, then
    /// `rename` it over `self.path`. A plain truncating `fs::write` leaves a
    /// window where a concurrent reader can observe a partially-written (or
    /// zero-length) file and fail-open to "count 0" — granting a free drip.
    /// `std::fs::rename` on POSIX is `rename(2)`, which atomically replaces
    /// an existing destination, so POSIX readers only ever see the old
    /// complete file or the new complete file. On Windows, `std::fs::rename`
    /// is backed by `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING` — NOT
    /// `ReplaceFile` — and unlike POSIX it can **fail** (returning `Err`,
    /// which this function propagates) with a sharing violation if the
    /// destination is open in another process. It is not guaranteed to
    /// succeed the way POSIX `rename` is; a caller must not assume this
    /// write always lands.
    fn save_map(&self, map: &HashMap<String, DripEntry>) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("gas_drips: create_dir_all: {e}"))?;
        }
        let bytes = serde_json::to_vec(map).map_err(|e| format!("gas_drips: serialize: {e}"))?;
        let mut tmp_os = self.path.as_os_str().to_os_string();
        tmp_os.push(".tmp");
        let tmp_path = PathBuf::from(tmp_os);
        std::fs::write(&tmp_path, bytes).map_err(|e| format!("gas_drips: write tmp: {e}"))?;
        std::fs::rename(&tmp_path, &self.path).map_err(|e| format!("gas_drips: rename: {e}"))
    }

    /// Drips already committed for `wallet` on `today` (0 if the wallet has
    /// no entry, or its stored entry is dated a different day). Wallet
    /// lookup is case-insensitive (keyed lowercase).
    pub fn load_count(&self, wallet: &str, today: &str) -> u32 {
        let map = self.load_map();
        match map.get(&wallet.to_lowercase()) {
            Some(entry) if entry.date == today => entry.count,
            _ => 0,
        }
    }

    /// Record one more drip for `wallet` on `today` and persist; returns the
    /// new count.
    ///
    /// Reserve/commit boundary (spec G4, **reserve-before-send** as revised):
    /// the caller (GD5 handler) must check `load_count(..) < cap` BEFORE
    /// calling `commit`, and must call `commit` BEFORE sending the drip —
    /// `commit` reserves the day's quota; only a successful reservation is
    /// followed by a native send. If `commit` fails, the handler must fail
    /// closed (no send). This is the opposite of "commit only after a
    /// successful send": a failed persist here is treated as fail-closed,
    /// not fail-open, because `fs::write`/`fs::rename` failures (read-only
    /// volume, disk full, file held open) are typically persistent, and
    /// silently granting a drip per request on a broken ledger is an
    /// unbounded ETH drain, whereas failing the request is just an
    /// unavailable feature.
    ///
    /// Serialized process-wide via `COMMIT_LOCK` so two concurrent commits
    /// (even for different wallets, even across different `DripLedger`
    /// instances/paths in the same process) can't interleave
    /// read-map/mutate/write-map and lose an increment. The critical section
    /// does no chain calls, so this is a short hold. This module has no
    /// per-wallet in-flight guard; that belongs to GD5 (relayer.rs).
    pub fn commit(&self, wallet: &str, today: &str) -> Result<u32, String> {
        let _lock = COMMIT_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = wallet.to_lowercase();
        let mut map = self.load_map();
        let new_count = match map.get(&key) {
            Some(entry) if entry.date == today => entry.count + 1,
            _ => 1,
        };
        map.insert(
            key,
            DripEntry {
                date: today.to_string(),
                count: new_count,
            },
        );
        self.save_map(&map)?;
        Ok(new_count)
    }
}

/// Process-wide lock serializing the read-modify-write critical section in
/// `DripLedger::commit` (FIX-C). A per-wallet in-flight guard (relayer.rs)
/// prevents the same wallet from racing itself, but does NOT serialize two
/// *different* wallets committing concurrently against the same (or a
/// different) ledger file — this static does. `Mutex::new` is `const fn`,
/// so this needs no lazy-init wrapper.
static COMMIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Today's date (`YYYY-MM-DD`) from WALL-CLOCK UTC.
///
/// Deliberately wall-clock, NOT chain-time — see module docs. Do not
/// replace this with `proposer::chain_or_wall_now`/`daily_epoch_id`: those
/// are for on-chain epoch bookkeeping and derive "today" from chain time
/// when available, which is the wrong clock for this off-chain budget cap.
pub fn utc_today() -> String {
    let unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (unix_secs / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Howard Hinnant `civil_from_days` (proleptic Gregorian). Self-contained
/// copy for this module (mirrors `proposer::civil_from_days`) so gas_drips
/// carries no dependency on the chain-time epoch code — keeping the
/// wall-clock/chain-time split explicit rather than sharing a code path
/// that could later be tempted into chain-time use.
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

/// Whether `count` has reached or exceeded `cap`.
pub fn is_over_cap(count: u32, cap: u32) -> bool {
    count >= cap
}

/// Configuration for gas drip amount calculation + the daily cap.
#[derive(Debug, Clone)]
pub struct DripConfig {
    pub approve_gas: u64,
    pub sell_gas: u64,
    pub buffer_num: u64,
    pub buffer_den: u64,
    pub max_wei: u128,
    /// Drips allowed per wallet per UTC day. Configurable (GD task 8); the
    /// handler must read this rather than the `DEFAULT_DAILY_CAP` constant so
    /// an operator override actually takes effect. A value of 0 has no
    /// sensible runtime meaning here (`is_over_cap(0, 0)` would block every
    /// wallet on request 1) — config loading (`config::build_drip_config`)
    /// treats env `GAS_DRIP_DAILY_CAP=0` as "disable the endpoint" instead of
    /// ever constructing a `DripConfig` with `daily_cap: 0`.
    pub daily_cap: u32,
}

impl Default for DripConfig {
    fn default() -> Self {
        // Task #13 (consultant 2026-07-21 / founder-aligned): match desktop
        // Market.jsx APPROVE_GAS=68k / SELL_GAS=170k so 1.5× buffer covers a
        // cold factory sell (~147k in-call) + L1 DA headroom. Old 60k/120k
        // only gave ~1.13× and underfunded on mild fee spikes.
        Self {
            approve_gas: 68_000,
            sell_gas: 170_000,
            buffer_num: 3,
            buffer_den: 2,
            max_wei: 20_000_000_000_000_000, // 0.02 ETH
            daily_cap: DEFAULT_DAILY_CAP,
        }
    }
}

/// Compute the gas drip amount in wei.
///
/// Result = `((approve_gas + sell_gas) * gas_price_wei * buffer_num / buffer_den)`,
/// clamped to `max_wei`. Uses saturating arithmetic to prevent overflow panics on
/// extreme gas prices.
pub fn compute_drip_wei(gas_price_wei: u128, cfg: &DripConfig) -> u128 {
    let total_gas = (cfg.approve_gas + cfg.sell_gas) as u128;
    let numerator = total_gas
        .saturating_mul(gas_price_wei)
        .saturating_mul(cfg.buffer_num as u128);
    let result = numerator / (cfg.buffer_den as u128);
    result.min(cfg.max_wei)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ledger is per-directory state, so the directory must be unique per
    /// TEST PROCESS, not merely per wall-clock second.
    ///
    /// This used to be `std::env::temp_dir().join(format!("drip-{}", unix_now()))`
    /// with `unix_now()` at one-second granularity, and the first assertion
    /// below is `load_count(...) == 0` — i.e. "this ledger starts empty". Two
    /// test processes starting inside the same second therefore shared one
    /// directory: A wrote `gas_drips.json` with count 2 and removed the
    /// directory on the way out, B read A's file and saw 2 (or read it
    /// mid-write and saw 1). Measured on this machine at three concurrent
    /// copies of the compiled test binary, six rounds: **6 failures in 18
    /// runs**, all `assertion left == right failed, left: 1/2, right: 0` at
    /// this test's first assertion. Sequentially it never fired — 30 runs
    /// clean — which is why it read as a mystery gate failure rather than as a
    /// test defect.
    ///
    /// `tempfile::tempdir()` is what every other test in this crate already
    /// uses; it takes a fresh randomly-named directory and removes it on drop,
    /// including on panic. Nothing else in this module is timing-dependent, so
    /// the `unix_now` helper went with it.
    #[test]
    fn ledger_counts_per_wallet_and_resets_next_day() {
        let dir = tempfile::tempdir().unwrap();
        let l = DripLedger {
            path: dir.path().join("gas_drips.json"),
        };
        assert_eq!(l.load_count("0xA", "2026-07-19"), 0);
        assert_eq!(l.commit("0xA", "2026-07-19").unwrap(), 1);
        assert_eq!(l.commit("0xA", "2026-07-19").unwrap(), 2);
        assert_eq!(l.load_count("0xa", "2026-07-19"), 2); // case-insensitive
        assert_eq!(l.load_count("0xB", "2026-07-19"), 0); // per-wallet
        assert_eq!(l.load_count("0xA", "2026-07-20"), 0); // new day resets
    }

    #[test]
    fn over_cap_at_one() {
        assert_eq!(DEFAULT_DAILY_CAP, 1);
        assert!(!is_over_cap(0, DEFAULT_DAILY_CAP));
        assert!(is_over_cap(1, DEFAULT_DAILY_CAP));
        assert!(!is_over_cap(2, 3));
        assert!(is_over_cap(3, 3));
    }

    #[test]
    fn drip_scales_and_clamps() {
        let cfg = DripConfig {
            approve_gas: 68_000,
            sell_gas: 170_000,
            buffer_num: 3,
            buffer_den: 2,
            max_wei: 10_000_000_000_000_000,
            daily_cap: DEFAULT_DAILY_CAP,
        };
        // (238_000 * 1_000_000_000) * 3/2 = 357_000_000_000_000  (1.5× margin)
        assert_eq!(compute_drip_wei(1_000_000_000, &cfg), 357_000_000_000_000);
        // gas spike clamps to max
        assert_eq!(compute_drip_wei(1_000_000_000_000, &cfg), cfg.max_wei);
    }

    #[test]
    fn default_gas_units_match_desktop_market_constants() {
        let d = DripConfig::default();
        assert_eq!(d.approve_gas, 68_000, "align Market.jsx APPROVE_GAS");
        assert_eq!(d.sell_gas, 170_000, "align Market.jsx SELL_GAS");
        assert_eq!(d.approve_gas + d.sell_gas, 238_000);
    }
}
