//! The durable byte budget: a UTC-daily ceiling that survives a restart and
//! fails **closed**.
//!
//! # Why this is a file and not a counter
//!
//! A cap that lives only in memory is a cap the operator defeats by restarting
//! the process, and a cap that lives in the shell is a cap the operator defeats
//! by killing the shell. The number that bounds a day's egress is therefore
//! written to a file the **daemon** owns, re-read on every debit, and re-derived
//! from the wall clock's UTC day rather than from anything the caller passes in
//! as "the current total".
//!
//! # A corrupt ledger is a refusal, never a zero
//!
//! This is the whole point of the module and it is the direction that is easy to
//! get backwards. `serde_json::from_str(..).unwrap_or_default()` on a truncated
//! file yields `spent = 0`, which reads as "nothing has been used today" and
//! hands out the entire ceiling again — so the failure mode of a corrupt ledger
//! would be an **unbounded** cap. Every unreadable, unparseable, wrong-schema,
//! wrong-day-shape or out-of-range state is [`CapError::Unavailable`], and every
//! caller treats that as a refusal. The shape is
//! `tools/goat-attestor/src/spend_ledger.rs`'s, which fails closed for the same
//! reason and says so in its own header.
//!
//! # The day boundary is an integer, not a formatted date
//!
//! `utc_day = now_unix / 86_400` is the number of whole days since the Unix
//! epoch. It rolls over at 00:00:00 UTC by construction, needs no calendar
//! arithmetic, and cannot be made to disagree with itself by a locale, a leap
//! year or a time zone. A `YYYY-MM-DD` string is a second representation of the
//! same fact, and two representations of one fact is how a reset lands an hour
//! early in one place and an hour late in another.
//!
//! # The throttle does not drop bytes
//!
//! [`TokenBucket`] is a **rate**, not a budget: [`EgressLedger::spend`] always
//! records the bytes and returns how long the caller should wait before moving
//! more. A bucket that refused would turn a throttle into a silent truncation of
//! the response, which the consumer cannot distinguish from a short origin.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Task 31 and its Security invariants section (INV-9); and the
//! "Residential Proxy Network (P3) Implementation Plan", §4.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Seconds in a UTC day. The only place this number is written.
pub const SECONDS_PER_UTC_DAY: u64 = 86_400;

/// The default daily ceiling: 10 GiB.
pub const DEFAULT_DAILY_BYTE_CAP: u64 = 10_737_418_240;

/// The operator-adjustable band for the daily ceiling, from the Global
/// Constraints' "Adjustable vs immutable" row: 1 GB to 200 GB. A value outside
/// it is clamped **into** it on read, so a hand-edited limits file cannot raise
/// the ceiling past what the band permits.
pub const MIN_DAILY_BYTE_CAP: u64 = 1_000_000_000;
/// See [`MIN_DAILY_BYTE_CAP`].
pub const MAX_DAILY_BYTE_CAP: u64 = 200_000_000_000;

/// How many bytes the throttle may release in one burst before the rate binds.
///
/// One second of the default throttle. A capacity much larger than that turns
/// the first second of every transfer into an unthrottled one, which is what an
/// operator on a metered line notices first.
pub const DEFAULT_BUCKET_CAPACITY_BYTES: u64 = 12_500_000;

/// The schema tag the ledger file must carry. A file without it is corrupt, not
/// empty.
const LEDGER_SCHEMA_ID: &str = "GOAT_PROXY_EGRESS_LEDGER_V1";

/// Why a debit was refused.
///
/// [`CapError::Unavailable`] carries an operator-facing *diagnostic* — a parse
/// error kind or an I/O error kind. It never carries a URL, a path, a query
/// string or a header, and nothing in this module has access to any of those:
/// `spend` is handed a byte count and a timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CapError {
    /// The ledger could not be read, parsed or written. **A refusal**, never a
    /// reset counter.
    #[error("the byte ledger is unavailable, which is a refusal and not a reset: {0}")]
    Unavailable(String),
    /// Today's ceiling is spent.
    #[error("the daily byte ceiling is reached")]
    DailyCeilingReached,
    /// The current time is outside every consented schedule window. Produced by
    /// the limits file that owns the schedule, which lands with the startup gate
    /// and the supervisor; declared here because it is a refusal of the same
    /// kind and every caller already matches it.
    #[error("the current time is outside every consented schedule window")]
    OutsideSchedule,
}

/// A rate, in bytes per second, with a burst allowance.
///
/// `capacity_bytes` is the burst; `rate_bytes_per_sec` is the sustained rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBucket {
    pub rate_bytes_per_sec: u64,
    pub capacity_bytes: u64,
}

impl TokenBucket {
    /// The throttle band from the Global Constraints: 64 to 100 000 kbps,
    /// converted to bytes per second.
    pub const MIN_RATE_BYTES_PER_SEC: u64 = 8_000;
    /// See [`TokenBucket::MIN_RATE_BYTES_PER_SEC`].
    pub const MAX_RATE_BYTES_PER_SEC: u64 = 12_500_000;

    /// A bucket at `rate`, clamped into the band, with a one-second burst.
    pub fn at_rate(rate_bytes_per_sec: u64) -> Self {
        let rate =
            rate_bytes_per_sec.clamp(Self::MIN_RATE_BYTES_PER_SEC, Self::MAX_RATE_BYTES_PER_SEC);
        Self {
            rate_bytes_per_sec: rate,
            capacity_bytes: rate,
        }
    }
}

/// The on-disk state. Deliberately tiny, and deliberately typed.
///
/// `#[serde(deny_unknown_fields)]` so that a renamed key is a refusal rather
/// than a silently defaulted field, and the byte total is a **string** so a
/// `u64` near the top of its range survives a JSON round trip through a reader
/// that promotes numbers to `f64`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LedgerState {
    schema_id: String,
    /// Whole days since the Unix epoch. See the module header.
    utc_day: u64,
    /// Decimal, so no reader can round it.
    spent_bytes: String,
}

impl LedgerState {
    fn spent(&self) -> Result<u64, CapError> {
        // Not `parse().unwrap_or(0)`: a garbled total is unavailable, and
        // unavailable is a refusal.
        self.spent_bytes
            .parse::<u64>()
            .map_err(|e| CapError::Unavailable(format!("spent_bytes is not a u64: {e}")))
    }
}

/// The in-memory half of the throttle.
#[derive(Debug, Clone, Copy)]
struct BucketState {
    tokens: u64,
    last_refill_unix: u64,
}

/// A file-backed UTC-daily byte ceiling plus an in-memory throttle.
///
/// The ceiling is durable because it bounds a **consented term**; the throttle
/// is not, because a rate has no meaning across a restart.
pub struct EgressLedger {
    path: PathBuf,
    ceiling_bytes: u64,
    bucket: TokenBucket,
    /// Serialises the read-modify-write. Two debits racing on one file is how a
    /// ceiling is overshot by exactly the concurrency.
    gate: Mutex<BucketState>,
}

impl EgressLedger {
    /// `ceiling_bytes` is clamped into the operator band. A hand-edited limits
    /// file naming 5 TB gets 200 GB, not 5 TB.
    pub fn new(path: PathBuf, ceiling_bytes: u64, bucket: TokenBucket) -> Self {
        Self {
            path,
            ceiling_bytes: ceiling_bytes.clamp(MIN_DAILY_BYTE_CAP, MAX_DAILY_BYTE_CAP),
            bucket,
            gate: Mutex::new(BucketState {
                tokens: bucket.capacity_bytes,
                last_refill_unix: 0,
            }),
        }
    }

    /// The ceiling actually in force, after clamping.
    pub fn ceiling_bytes(&self) -> u64 {
        self.ceiling_bytes
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whole days since the Unix epoch for a timestamp in seconds.
    pub fn utc_day(now_unix: u64) -> u64 {
        now_unix / SECONDS_PER_UTC_DAY
    }

    /// Today's state, or a refusal.
    ///
    /// An **absent** file is today's zero: nothing has been spent because
    /// nothing has ever run. An **unreadable or corrupt** file is
    /// [`CapError::Unavailable`]. The two are not the same and conflating them
    /// is what turns a corruption into a fresh allowance.
    pub fn load_for_today(&self, now_unix: u64) -> Result<u64, CapError> {
        let today = Self::utc_day(now_unix);
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
            Err(e) => {
                return Err(CapError::Unavailable(format!(
                    "the ledger exists and cannot be read: {}",
                    e.kind()
                )))
            }
        };
        let state: LedgerState = serde_json::from_str(&text)
            .map_err(|e| CapError::Unavailable(format!("the ledger is not valid state: {e}")))?;
        if state.schema_id != LEDGER_SCHEMA_ID {
            return Err(CapError::Unavailable(format!(
                "the ledger names schema {:?}, expected {LEDGER_SCHEMA_ID:?}",
                state.schema_id
            )));
        }
        // A ledger dated in the FUTURE is not a fresh day; it is a clock that
        // moved backwards or a file somebody edited, and either way this process
        // cannot prove it is under the ceiling.
        if state.utc_day > today {
            return Err(CapError::Unavailable(format!(
                "the ledger is dated {} and today is {today}; a future-dated ledger is a \
                 refusal, because a clock that moved backwards would otherwise grant a \
                 second day's allowance",
                state.utc_day
            )));
        }
        if state.utc_day < today {
            // A previous UTC day. Today starts at zero — and this is the ONLY
            // path on which a zero is produced from a file that exists.
            return Ok(0);
        }
        state.spent()
    }

    /// Bytes already spent today, or a refusal.
    pub fn spent_today(&self, now_unix: u64) -> Result<u64, CapError> {
        let _guard = self.lock();
        self.load_for_today(now_unix)
    }

    /// Bytes still available today, or a refusal.
    pub fn remaining_today(&self, now_unix: u64) -> Result<u64, CapError> {
        Ok(self
            .ceiling_bytes
            .saturating_sub(self.spent_today(now_unix)?))
    }

    /// Debit `bytes` against today's ceiling and the throttle.
    ///
    /// Returns how long the caller should wait before moving more bytes, which
    /// is `ZERO` whenever the bucket had tokens. The bytes are **always**
    /// recorded on the success path: a throttle that dropped bytes would
    /// truncate a response.
    ///
    /// On the ceiling path the day is closed at exactly the ceiling and
    /// [`CapError::DailyCeilingReached`] is returned. Closing it is deliberate:
    /// the bytes that provoked the refusal have already crossed the socket, and
    /// a ledger that forgot them would let the same overshoot recur on every
    /// subsequent request.
    pub fn spend(&self, bytes: u64, now_unix: u64) -> Result<Duration, CapError> {
        let mut bucket = self.lock();

        let spent = self.load_for_today(now_unix)?;
        let new_total = spent.saturating_add(bytes);
        if new_total > self.ceiling_bytes {
            self.persist(self.ceiling_bytes, now_unix)?;
            return Err(CapError::DailyCeilingReached);
        }
        self.persist(new_total, now_unix)?;

        Ok(self.charge_bucket(&mut bucket, bytes, now_unix))
    }

    /// Refill by elapsed wall-clock seconds, then take `bytes`, allowing the
    /// balance to go negative in the form of a wait.
    fn charge_bucket(&self, bucket: &mut BucketState, bytes: u64, now_unix: u64) -> Duration {
        if self.bucket.rate_bytes_per_sec == 0 {
            return Duration::ZERO;
        }
        if bucket.last_refill_unix == 0 {
            bucket.last_refill_unix = now_unix;
        }
        let elapsed = now_unix.saturating_sub(bucket.last_refill_unix);
        bucket.last_refill_unix = now_unix;
        bucket.tokens = bucket
            .tokens
            .saturating_add(elapsed.saturating_mul(self.bucket.rate_bytes_per_sec))
            .min(self.bucket.capacity_bytes);

        if bucket.tokens >= bytes {
            bucket.tokens -= bytes;
            return Duration::ZERO;
        }
        let deficit = bytes - bucket.tokens;
        bucket.tokens = 0;
        // Rounded up in milliseconds so a sub-second deficit is still a wait.
        let millis = deficit
            .saturating_mul(1_000)
            .div_ceil(self.bucket.rate_bytes_per_sec);
        Duration::from_millis(millis)
    }

    /// Write today's total atomically: temp file in the same directory, then
    /// rename over the target.
    ///
    /// Same directory because a rename across a filesystem boundary is a copy,
    /// and a copy is not atomic. A partial write is exactly the corruption this
    /// module refuses to read, so producing one would be self-inflicted.
    fn persist(&self, total: u64, now_unix: u64) -> Result<(), CapError> {
        let state = LedgerState {
            schema_id: LEDGER_SCHEMA_ID.to_string(),
            utc_day: Self::utc_day(now_unix),
            spent_bytes: total.to_string(),
        };
        let body = serde_json::to_string(&state)
            .map_err(|e| CapError::Unavailable(format!("cannot render the ledger: {e}")))?;

        let dir = self.path.parent().unwrap_or(Path::new("."));
        fs::create_dir_all(dir).map_err(|e| {
            CapError::Unavailable(format!("cannot create the state dir: {}", e.kind()))
        })?;
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, body.as_bytes())
            .map_err(|e| CapError::Unavailable(format!("cannot write the ledger: {}", e.kind())))?;
        fs::rename(&tmp, &self.path).map_err(|e| {
            CapError::Unavailable(format!("cannot commit the ledger: {}", e.kind()))
        })?;
        Ok(())
    }

    /// The debit gate.
    ///
    /// A poisoned lock means a previous debit panicked. The authoritative total
    /// is re-read from the file on every call, so the guarded state cannot be
    /// left inconsistent by that panic and recovering the guard is sound;
    /// refusing here would strand the daemon on a transient.
    fn lock(&self) -> std::sync::MutexGuard<'_, BucketState> {
        self.gate.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger(dir: &tempfile::TempDir, ceiling: u64) -> EgressLedger {
        EgressLedger::new(
            dir.path().join("egress.json"),
            ceiling,
            TokenBucket {
                rate_bytes_per_sec: 1_000_000_000,
                capacity_bytes: 1_000_000_000,
            },
        )
    }

    /// A timestamp at 00:00:00 UTC on day `d`.
    fn midnight(day: u64) -> u64 {
        day * SECONDS_PER_UTC_DAY
    }

    /// THE test this module exists for.
    ///
    /// Mutations this detects: `serde_json::from_str(..).unwrap_or_default()`,
    /// `read_to_string(..).unwrap_or_default()`, or any `Err(_) => Ok(0)` arm in
    /// `load_for_today`. Each of those turns a corrupt ledger into a fresh
    /// allowance, which is an UNBOUNDED cap wearing a cap's name.
    #[test]
    fn corrupt_state_file_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = ledger(&dir, 1_000_000_000);

        for body in [
            // Truncated mid-object: the shape a crash during a non-atomic write
            // leaves behind.
            r#"{"schema_id":"GOAT_PROXY_EGRESS_LEDGER_V1","utc_day":20000,"spent_by"#,
            // Valid JSON, wrong schema tag.
            r#"{"schema_id":"SOMETHING_ELSE","utc_day":20000,"spent_bytes":"5"}"#,
            // Valid JSON, wrong shape.
            r#"{"utc_day":20000,"spent_bytes":"5"}"#,
            r#"[]"#,
            r#""#,
            // A total that is not a number.
            r#"{"schema_id":"GOAT_PROXY_EGRESS_LEDGER_V1","utc_day":20000,"spent_bytes":"lots"}"#,
            // A negative total, which `u64` cannot hold and which a permissive
            // parser would clamp to zero.
            r#"{"schema_id":"GOAT_PROXY_EGRESS_LEDGER_V1","utc_day":20000,"spent_bytes":"-1"}"#,
            // An unknown key: how a renamed field silently defaults.
            r#"{"schema_id":"GOAT_PROXY_EGRESS_LEDGER_V1","utc_day":20000,"spent_bytes":"5","spent":"0"}"#,
        ] {
            fs::write(l.path(), body).expect("write corrupt ledger");
            let now = midnight(20_000) + 60;

            let err = l
                .load_for_today(now)
                .expect_err("a corrupt ledger must refuse");
            assert!(
                matches!(err, CapError::Unavailable(_)),
                "body {body:?} gave {err:?}"
            );
            // And the refusal reaches `spend`, which is what callers use.
            assert!(
                matches!(l.spend(1, now), Err(CapError::Unavailable(_))),
                "spend read {body:?} as something other than unavailable"
            );
        }

        // POSITIVE CONTROL: the same reader, given a well-formed ledger, reads
        // the number back. Without this the loop above also passes against a
        // loader that refuses everything.
        fs::write(
            l.path(),
            r#"{"schema_id":"GOAT_PROXY_EGRESS_LEDGER_V1","utc_day":20000,"spent_bytes":"4096"}"#,
        )
        .expect("write good ledger");
        assert_eq!(l.load_for_today(midnight(20_000) + 60), Ok(4_096));
    }

    /// Mutations this detects: an absent ledger mapped onto `Unavailable`, which
    /// would make a first run impossible; or a previous day's ledger read as
    /// today's, which would carry yesterday's spend forward forever.
    #[test]
    fn an_absent_ledger_is_a_fresh_day_and_a_stale_one_is_too() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = ledger(&dir, 1_000_000_000);
        assert_eq!(l.load_for_today(midnight(20_000)), Ok(0));

        fs::write(
            l.path(),
            r#"{"schema_id":"GOAT_PROXY_EGRESS_LEDGER_V1","utc_day":19999,"spent_bytes":"900000000"}"#,
        )
        .expect("write yesterday");
        assert_eq!(l.load_for_today(midnight(20_000)), Ok(0));

        // NEGATIVE CONTROL: a ledger dated in the FUTURE is not a fresh day. It
        // is a clock that moved backwards, and reading it as zero would hand out
        // a second day's allowance.
        fs::write(
            l.path(),
            r#"{"schema_id":"GOAT_PROXY_EGRESS_LEDGER_V1","utc_day":20001,"spent_bytes":"0"}"#,
        )
        .expect("write tomorrow");
        assert!(matches!(
            l.load_for_today(midnight(20_000)),
            Err(CapError::Unavailable(_))
        ));
    }

    /// INV-9's boundary, exactly.
    ///
    /// Mutations this detects: a reset keyed on process start, on local
    /// midnight, or on a rolling 24 hours since the first spend — each of which
    /// gives an operator a second allowance somewhere inside the same UTC day.
    #[test]
    fn cap_resets_only_on_utc_day_boundary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = ledger(&dir, 1_000_000_000);
        let day = 20_000;

        assert!(l.spend(1_000_000_000, midnight(day)).is_ok());

        // 23:59:59 UTC of the SAME day: still refused.
        let end_of_day = midnight(day) + SECONDS_PER_UTC_DAY - 1;
        assert_eq!(l.spend(1, end_of_day), Err(CapError::DailyCeilingReached));
        assert_eq!(l.spent_today(end_of_day), Ok(1_000_000_000));

        // One second past UTC midnight: allowed.
        let next = midnight(day + 1);
        assert_eq!(l.spent_today(next), Ok(0));
        assert!(l.spend(1, next + 1).is_ok());
    }

    /// Mutations this detects: `>=` in place of `>` in the ceiling comparison,
    /// which loses the last byte of every operator's day; or `saturating_add`
    /// replaced by a wrapping add, under which a huge debit wraps to a small one
    /// and passes.
    #[test]
    fn daily_ceiling_is_exact_at_the_boundary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = ledger(&dir, 1_500_000_000);
        let now = midnight(20_000);

        assert!(l.spend(1_000_000_000, now).is_ok());
        // Exactly the remainder: allowed.
        assert!(l.spend(500_000_000, now).is_ok());
        assert_eq!(l.spent_today(now), Ok(1_500_000_000));
        // One more byte: refused.
        assert_eq!(l.spend(1, now), Err(CapError::DailyCeilingReached));

        // A debit near `u64::MAX` must refuse rather than wrap into a small
        // total that fits.
        let dir2 = tempfile::tempdir().expect("tempdir");
        let l2 = ledger(&dir2, 1_000_000_000);
        assert_eq!(
            l2.spend(u64::MAX, now),
            Err(CapError::DailyCeilingReached),
            "an overflowing debit must refuse, not wrap"
        );
    }

    /// The property the caller relies on when a killed UI cannot be trusted.
    ///
    /// Mutations this detects: the total held in a field instead of in the file,
    /// so a fresh `EgressLedger` over the same path starts from zero.
    #[test]
    fn the_ledger_survives_a_simulated_process_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let now = midnight(20_000) + 3_600;

        {
            let first = ledger(&dir, 2_000_000_000);
            assert!(first.spend(1_900_000_000, now).is_ok());
            assert_eq!(first.spent_today(now), Ok(1_900_000_000));
        } // the "process" exits here

        // A brand-new ledger object over the same path: the same day, the same
        // total, and the remainder is what is left rather than the whole cap.
        let second = ledger(&dir, 2_000_000_000);
        assert_eq!(second.spent_today(now), Ok(1_900_000_000));
        assert_eq!(second.remaining_today(now), Ok(100_000_000));

        // POSITIVE CONTROL first, because a refusal CLOSES the day (see below):
        // the restarted ledger is not simply refusing everything, and exactly
        // what remains is still spendable.
        assert!(second.spend(100_000_000, now).is_ok());
        assert_eq!(second.remaining_today(now), Ok(0));

        // And now the refusal, from a third object over the same file.
        let third = ledger(&dir, 2_000_000_000);
        assert_eq!(
            third.spend(1, now),
            Err(CapError::DailyCeilingReached),
            "a restart handed back an allowance a previous process had already spent"
        );
    }

    /// The clamp on the refusal path, stated as its own property.
    ///
    /// Mutations this detects: an over-ask REFUSED WITHOUT RECORDING. The bytes
    /// a `BudgetSink` debit reports have already crossed the socket, so a
    /// refusal that forgot them would let the same overshoot recur on every
    /// request — an unbounded cap reached one over-ask at a time.
    #[test]
    fn an_over_ask_closes_the_day_rather_than_being_forgotten() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = ledger(&dir, 1_000_000_000);
        let now = midnight(20_000);

        assert!(l.spend(900_000_000, now).is_ok());
        assert_eq!(
            l.spend(200_000_000, now),
            Err(CapError::DailyCeilingReached)
        );
        assert_eq!(
            l.spent_today(now),
            Ok(1_000_000_000),
            "the over-ask went unrecorded, so the next request gets the same overshoot again"
        );
        assert_eq!(l.remaining_today(now), Ok(0));

        // POSITIVE CONTROL: the next UTC day opens again, so the close is a
        // day's close and not a permanent one.
        assert!(l.spend(1, midnight(20_001)).is_ok());
    }

    /// Mutations this detects: a bucket that REFUSES when it is empty instead of
    /// returning a wait, which turns a throttle into a truncated response the
    /// consumer cannot distinguish from a short origin.
    #[test]
    fn the_token_bucket_rate_limits_without_dropping_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = EgressLedger::new(
            dir.path().join("egress.json"),
            10_000_000_000,
            TokenBucket {
                rate_bytes_per_sec: 1_000,
                capacity_bytes: 1_000,
            },
        );
        let now = midnight(20_000);

        // The burst is free.
        assert_eq!(l.spend(1_000, now), Ok(Duration::ZERO));
        // The next second's worth is not: it is a WAIT, not a refusal.
        let wait = l
            .spend(2_000, now)
            .expect("a throttled debit is not a refusal");
        assert_eq!(wait, Duration::from_millis(2_000));

        // Every byte was still recorded: nothing was dropped.
        assert_eq!(l.spent_today(now), Ok(3_000));

        // POSITIVE CONTROL: after enough wall-clock seconds the bucket refills
        // and the wait is zero again.
        assert_eq!(l.spend(1_000, now + 10), Ok(Duration::ZERO));
        assert_eq!(l.spent_today(now + 10), Ok(4_000));
    }

    /// Mutations this detects: the ceiling taken from the caller verbatim, so a
    /// hand-edited limits file naming 5 TB gets 5 TB.
    #[test]
    fn a_hand_edited_ceiling_is_clamped_into_the_operator_band() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(ledger(&dir, u64::MAX).ceiling_bytes(), MAX_DAILY_BYTE_CAP);
        assert_eq!(ledger(&dir, 1).ceiling_bytes(), MIN_DAILY_BYTE_CAP);
        assert_eq!(ledger(&dir, 0).ceiling_bytes(), MIN_DAILY_BYTE_CAP);

        // POSITIVE CONTROL: a value inside the band is kept exactly.
        assert_eq!(
            ledger(&dir, DEFAULT_DAILY_BYTE_CAP).ceiling_bytes(),
            DEFAULT_DAILY_BYTE_CAP
        );

        // And the throttle band, the same way.
        assert_eq!(
            TokenBucket::at_rate(u64::MAX).rate_bytes_per_sec,
            TokenBucket::MAX_RATE_BYTES_PER_SEC
        );
        assert_eq!(
            TokenBucket::at_rate(1).rate_bytes_per_sec,
            TokenBucket::MIN_RATE_BYTES_PER_SEC
        );
        assert_eq!(TokenBucket::at_rate(100_000).rate_bytes_per_sec, 100_000);
    }

    /// Mutations this detects: a non-atomic write (`fs::write` straight onto the
    /// live path), which leaves a truncated ledger behind on a crash — and a
    /// truncated ledger is the refusal this module then cannot get out of.
    #[test]
    fn the_ledger_is_written_atomically_and_leaves_no_partial_file_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = ledger(&dir, 2_000_000_000);
        let now = midnight(20_000);
        assert!(l.spend(4_096, now).is_ok());

        let entries: Vec<String> = fs::read_dir(dir.path())
            .expect("read state dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            entries.contains(&"egress.json".to_string()),
            "the ledger was not committed: {entries:?}"
        );
        assert!(
            !entries.iter().any(|n| n.ends_with(".tmp")),
            "a temp file survived the commit: {entries:?}"
        );
        // The committed file parses as exactly one complete state.
        assert_eq!(l.load_for_today(now), Ok(4_096));
    }

    /// Mutations this detects: `SECONDS_PER_UTC_DAY` written as 86_000 or
    /// 84_600, both of which are day-length typos that drift a reset by minutes
    /// per day until it lands inside the operator's evening.
    #[test]
    fn the_utc_day_index_is_whole_days_since_the_epoch() {
        assert_eq!(SECONDS_PER_UTC_DAY, 60 * 60 * 24);
        assert_eq!(EgressLedger::utc_day(0), 0);
        assert_eq!(EgressLedger::utc_day(SECONDS_PER_UTC_DAY - 1), 0);
        assert_eq!(EgressLedger::utc_day(SECONDS_PER_UTC_DAY), 1);
        // 2026-07-31T00:00:00Z is day 20_665.
        assert_eq!(EgressLedger::utc_day(1_785_456_000), 20_665);
        assert_eq!(EgressLedger::utc_day(1_785_456_000 + 86_399), 20_665);
        assert_eq!(EgressLedger::utc_day(1_785_456_000 + 86_400), 20_666);
    }
}
