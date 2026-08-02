//! Operator caps. The UI writes intent; THIS is where the ceiling lives.
//!
//! Everything here survives the UI process being killed, because it is a file the
//! sidecar re-reads and a clamp applied on every write AND on every read -- not React
//! state. And the clamp is not the whole story: the ceiling and the throttle are also
//! inside the SIGNED consent preimage, so [`effective_ceiling_bytes`] takes
//! `min(consented, configured)` and configuration may only ever lower. A cap a killed
//! UI can defeat is not a cap; neither is one a file edit can raise.
//!
//! Design authority: the "The No-Ponzi Invariant — GoatCoin's load-bearing economic
//! rule" spec, §1 and §8.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const MIN_DAILY_CAP_GB: u32 = 1;
pub const MAX_DAILY_CAP_GB: u32 = 200;
pub const DEFAULT_DAILY_CAP_GB: u32 = 5;
pub const MIN_THROTTLE_KBPS: u32 = 64;
pub const MAX_THROTTLE_KBPS: u32 = 100_000;
pub const DEFAULT_THROTTLE_KBPS: u32 = 2_048;
pub const MAX_WINDOWS: usize = 7;
pub const LIMITS_SCHEMA: u32 = 1;

/// GB on the control, bytes in the record.
pub const BYTES_PER_GB: u64 = 1_000_000_000;
/// kbps on the control, bytes per second in the record: 1000 bits / 8 = 125 bytes.
pub const BYTES_PER_KBPS: u64 = 125;

fn default_cap_gb() -> u32 {
    DEFAULT_DAILY_CAP_GB
}
fn default_throttle() -> u32 {
    DEFAULT_THROTTLE_KBPS
}
fn default_schema() -> u32 {
    LIMITS_SCHEMA
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleWindow {
    #[serde(default)]
    pub start_min_local: u16,
    #[serde(default)]
    pub end_min_local: u16,
    /// Bit 0 = Monday ... bit 6 = Sunday.
    #[serde(default)]
    pub days_mask: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyLimits {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cap_gb")]
    pub daily_cap_gb: u32,
    #[serde(default = "default_throttle")]
    pub throttle_kbps: u32,
    #[serde(default)]
    pub windows: Vec<ScheduleWindow>,
    #[serde(default = "default_schema")]
    pub schema: u32,
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            enabled: false,
            daily_cap_gb: DEFAULT_DAILY_CAP_GB,
            throttle_kbps: DEFAULT_THROTTLE_KBPS,
            windows: Vec::new(),
            schema: LIMITS_SCHEMA,
        }
    }
}

pub fn clamp(mut l: ProxyLimits) -> ProxyLimits {
    l.schema = LIMITS_SCHEMA;
    l.daily_cap_gb = l.daily_cap_gb.clamp(MIN_DAILY_CAP_GB, MAX_DAILY_CAP_GB);
    l.throttle_kbps = l.throttle_kbps.clamp(MIN_THROTTLE_KBPS, MAX_THROTTLE_KBPS);
    l.windows.retain(|w| {
        w.end_min_local > w.start_min_local && w.end_min_local <= 1_440 && w.days_mask & 0x7f != 0
    });
    l.windows.truncate(MAX_WINDOWS);
    l
}

/// `minute_of_week` = weekday_index * 1440 + minute_of_day, Monday = 0.
/// An empty schedule admits everything; that is the documented default, not a bypass.
pub fn admits(l: &ProxyLimits, minute_of_week: u16) -> bool {
    if l.windows.is_empty() {
        return true;
    }
    let day = (minute_of_week / 1_440) as u8;
    let minute = minute_of_week % 1_440;
    l.windows.iter().any(|w| {
        (w.days_mask >> day) & 1 == 1 && minute >= w.start_min_local && minute < w.end_min_local
    })
}

pub fn configured_ceiling_bytes(l: &ProxyLimits) -> u64 {
    u64::from(clamp(l.clone()).daily_cap_gb) * BYTES_PER_GB
}

pub fn configured_throttle_bytes_per_sec(l: &ProxyLimits) -> u64 {
    u64::from(clamp(l.clone()).throttle_kbps) * BYTES_PER_KBPS
}

/// `min(consented, configured)`. Configuration may only lower.
///
/// This mirrors the sidecar's own `effective_daily_ceiling`, and it is the reason the
/// ceiling lives inside the signed preimage: a ceiling outside the signature could be
/// raised by editing `proxy-limits.json` while the signature still verified.
pub fn effective_ceiling_bytes(consented_bytes: u64, l: &ProxyLimits) -> u64 {
    consented_bytes.min(configured_ceiling_bytes(l))
}

/// `min(consented, configured)`. Configuration may only lower.
pub fn effective_throttle_bytes_per_sec(consented_bytes_per_sec: u64, l: &ProxyLimits) -> u64 {
    consented_bytes_per_sec.min(configured_throttle_bytes_per_sec(l))
}

pub fn limits_path(dir: &Path) -> PathBuf {
    dir.join("proxy-limits.json")
}

pub fn load(dir: &Path) -> Option<ProxyLimits> {
    let raw = std::fs::read_to_string(limits_path(dir)).ok()?;
    serde_json::from_str::<ProxyLimits>(&raw).ok().map(clamp)
}

pub fn store(dir: &Path, l: &ProxyLimits) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tmp = dir.join("proxy-limits.json.tmp");
    let body = serde_json::to_string_pretty(l).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, limits_path(dir)).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutations this detects: dropping the daily-cap clamp, which lets a hand-crafted
    /// `invoke` or a hand-edited file name any ceiling it likes.
    #[test]
    fn clamp_holds_the_daily_cap_ceiling_against_a_hand_crafted_invoke() {
        let l = clamp(ProxyLimits {
            daily_cap_gb: 99_999,
            ..Default::default()
        });
        assert_eq!(l.daily_cap_gb, MAX_DAILY_CAP_GB);
        let l = clamp(ProxyLimits {
            daily_cap_gb: 0,
            ..Default::default()
        });
        assert_eq!(l.daily_cap_gb, MIN_DAILY_CAP_GB);
        // POSITIVE CONTROL: an in-range value is not touched.
        let l = clamp(ProxyLimits {
            daily_cap_gb: 12,
            ..Default::default()
        });
        assert_eq!(l.daily_cap_gb, 12);
    }

    #[test]
    fn clamp_holds_the_throttle_bounds() {
        assert_eq!(
            clamp(ProxyLimits {
                throttle_kbps: 1,
                ..Default::default()
            })
            .throttle_kbps,
            MIN_THROTTLE_KBPS
        );
        assert_eq!(
            clamp(ProxyLimits {
                throttle_kbps: 10_000_000,
                ..Default::default()
            })
            .throttle_kbps,
            MAX_THROTTLE_KBPS
        );
    }

    #[test]
    fn clamp_drops_windows_beyond_seven_and_inverted_windows() {
        let mut l = ProxyLimits {
            windows: (0..12)
                .map(|i| ScheduleWindow {
                    start_min_local: i * 60,
                    end_min_local: i * 60 + 30,
                    days_mask: 0x7f,
                })
                .collect(),
            ..Default::default()
        };
        l.windows.push(ScheduleWindow {
            start_min_local: 600,
            end_min_local: 600,
            days_mask: 0x7f,
        });
        let c = clamp(l);
        assert_eq!(c.windows.len(), MAX_WINDOWS);
        assert!(c
            .windows
            .iter()
            .all(|w| w.end_min_local > w.start_min_local));
    }

    #[test]
    fn an_empty_schedule_admits_every_minute() {
        let l = clamp(ProxyLimits::default());
        assert!(admits(&l, 0));
        assert!(admits(&l, 10_079));
    }

    /// Mutations this detects: `<=` on the end bound (one minute of egress past the
    /// window), or dropping the day-mask test (the same clock hour every day).
    #[test]
    fn schedule_window_boundary_closes_egress() {
        let l = clamp(ProxyLimits {
            windows: vec![ScheduleWindow {
                start_min_local: 60,
                end_min_local: 120,
                days_mask: 0x01,
            }],
            ..Default::default()
        });
        assert!(!admits(&l, 59));
        assert!(admits(&l, 60));
        assert!(admits(&l, 119));
        assert!(!admits(&l, 120));
        assert!(!admits(&l, 1_500)); // same clock time, different day bit
    }

    #[test]
    fn persisted_limits_round_trip_survives_missing_and_unknown_fields() {
        let parsed: ProxyLimits =
            serde_json::from_str("{\"daily_cap_gb\":7,\"an_unknown_future_field\":true}").unwrap();
        assert_eq!(parsed.daily_cap_gb, 7);
        assert_eq!(parsed.throttle_kbps, DEFAULT_THROTTLE_KBPS);
        assert!(!parsed.enabled);
        assert!(parsed.windows.is_empty());
    }

    #[test]
    fn store_then_load_is_identity() {
        let dir = std::env::temp_dir().join(format!("goat-proxy-limits-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let l = clamp(ProxyLimits {
            enabled: true,
            daily_cap_gb: 12,
            throttle_kbps: 4_096,
            windows: vec![],
            schema: 1,
        });
        store(&dir, &l).unwrap();
        assert_eq!(load(&dir).unwrap(), l);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Mutations this detects: `max` instead of `min`, or returning the configured
    /// value outright. THIS is the property that makes the switch a control rather
    /// than a suggestion: raising the number in this window must move the daemon's
    /// ceiling by nothing at all.
    #[test]
    fn a_cap_raised_in_the_ui_alone_cannot_raise_the_consented_ceiling() {
        let consented = 5 * BYTES_PER_GB;
        let raised = ProxyLimits {
            daily_cap_gb: MAX_DAILY_CAP_GB,
            ..Default::default()
        };
        assert_eq!(effective_ceiling_bytes(consented, &raised), consented);
        // Lowering, on the other hand, takes effect immediately.
        let lowered = ProxyLimits {
            daily_cap_gb: 2,
            ..Default::default()
        };
        assert_eq!(
            effective_ceiling_bytes(consented, &lowered),
            2 * BYTES_PER_GB
        );
        // Same rule for the throttle.
        let consented_bps = 256_000;
        assert_eq!(
            effective_throttle_bytes_per_sec(
                consented_bps,
                &ProxyLimits {
                    throttle_kbps: MAX_THROTTLE_KBPS,
                    ..Default::default()
                }
            ),
            consented_bps
        );
    }

    /// Mutations this detects: a byte conversion changed on one side of the IPC bridge
    /// only. The JavaScript mirror declares the same two constants.
    #[test]
    fn byte_conversions_are_the_ones_the_signed_record_carries() {
        assert_eq!(
            configured_ceiling_bytes(&ProxyLimits {
                daily_cap_gb: 5,
                ..Default::default()
            }),
            5_000_000_000
        );
        assert_eq!(
            configured_throttle_bytes_per_sec(&ProxyLimits {
                throttle_kbps: 2_048,
                ..Default::default()
            }),
            256_000
        );
    }
}
