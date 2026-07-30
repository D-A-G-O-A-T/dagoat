//! Read the `reconciliation_events` rows the reconciler **quarantined** — the
//! observed `SponsoredEnrollmentExecuted` logs it could not fold and stepped
//! over permanently.
//!
//! # Why a whole module exists to run four SELECTs
//!
//! [`super::reconcile::quarantine_unfoldable_log`] is the one place in this
//! crate that accepts permanent loss: it writes a row, and then
//! `maintenance::scan_and_fold` **advances the scan cursor past the log**.
//! Nothing ever reads behind that cursor, so the log is never observed again
//! and the quarantine row is the only durable record that it happened. Until
//! this module existed nothing could read those rows: the operator learned
//! from the `reconcile_log_errors` counter that *a* log had been dropped and
//! had to open the SQLite file by hand to learn *which*. That gap is the
//! difference between a recorded incident and a lost one.
//!
//! # What this module refuses to do, and why each refusal is load-bearing
//!
//! Every rule below exists to stop the same failure: **a report that reads as
//! "all clear" when the truth is "I could not tell".**
//!
//! * It **never creates a database.** A mistyped `--db` under
//!   `create_if_missing(true)` mints an empty file and then truthfully reports
//!   zero quarantine rows — about a file that has never held one. See
//!   [`open_read_only`].
//! * It **never reports an empty list for a key problem.** No key supplied, or
//!   the wrong key, still lists every row at the always-visible tier and says
//!   so, with a non-zero exit code. See [`ReportStatus`].
//! * It **never states a capped listing as a complete one.** `shown`,
//!   `matched` and `total` are three separate numbers, and `total` comes from
//!   its own `COUNT(*)`, not from `rows.len()`.
//! * It **never accepts a file that is not a Stream G database.** `store_meta`
//!   and `reconciliation_events` are probed through `sqlite_master` first, so
//!   a wrong-but-valid SQLite file is an error rather than a zero.
//! * It **never calls a newer-schema listing complete.** A file migrated past
//!   this build exits `4` and says the listing may be partial — the one signal
//!   meaning "I may not be able to see everything" cannot render as a clean
//!   run. See [`ReportStatus::SchemaNewerThanBuild`].
//! * It **never measures the `-wal` sidecar after opening the database.**
//!   Opening creates one, so measuring afterwards made the truncated-copy
//!   warning permanently unreachable. See step 0 of [`load_report`].
//! * It **never blames the file for a directory-permission failure.**
//!   `SQLITE_CANTOPEN` on a file this process can read is reported as what it
//!   is. See [`QuarantineReportError::CannotOpenSidecars`].
//! * It **never migrates, never writes, and never takes the instance lock.**
//!   See [`open_read_only`] for why the lock bypass is sound.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::Row;
use thiserror::Error;

use super::crypto_store::{self, DataKey, EnvelopeAad, SecretHex};
use super::reconcile::{
    ERR_RECONCILE_AMBIGUOUS, ERR_RECONCILE_CHAIN, ERR_RECONCILE_CONFIG, ERR_RECONCILE_STORE,
    ERR_RECONCILE_SUBMIT, ERR_RECONCILE_UNCORROBORATED_LOG, ERR_RECONCILE_UNVERIFIED_LOG,
    QUARANTINE_EVENT_TYPE,
};
use super::store::{supported_schema_version, ENVELOPE_AAD_SCHEMA_VERSION};

/// Rows listed when `--limit` is not given.
///
/// 100 rather than "all": a quarantine table with thousands of rows is itself
/// the finding, and an operator who pipes an unbounded dump into a terminal
/// during an incident loses the header — which is where the "is this even the
/// right file" evidence lives. Truncation is never silent (see
/// [`QuarantineReport::truncated`]), so the cap costs an operator one flag and
/// can never cost them a wrong conclusion.
pub const DEFAULT_LIMIT: u32 = 100;

/// The column this module unseals, and the table it lives in. Both are half of
/// the envelope AAD, so they are consts rather than literals at the use site:
/// a typo here is a `DecryptionFailed` on every row, not a compile error.
const TABLE: &str = "reconciliation_events";
const COLUMN: &str = "details_enc";

// ---------------------------------------------------------------------------
// Errors. Every variant names the path — a diagnostic that says "failed" but
// not "which file" sends the operator back to guessing.
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum QuarantineReportError {
    /// `--db` looked like a SQLite URI rather than a filesystem path.
    ///
    /// sqlx sets `SQLITE_OPEN_URI` unconditionally, so a value beginning
    /// `file:` or containing `?` is parsed as a URI and its query parameters
    /// take effect. `mode=` cannot elevate past our `SQLITE_OPEN_READONLY`,
    /// but `immutable=1` can — and `immutable=1` against a *live* database
    /// tells SQLite the file cannot change, which is precisely how a
    /// stale-or-corrupt read gets served during an incident. Refused at the
    /// boundary rather than sanitised.
    #[error(
        "--db must be a filesystem path, not a SQLite URI: {path}\n\
         URI parameters (immutable=1, vfs=) change how the file is read and can \
         silently serve a stale view of a live database. Pass a plain path."
    )]
    UriPath { path: String },

    /// The file could not be opened read-only. **The overwhelmingly common
    /// cause is that it does not exist**, and the message says so, because the
    /// alternative — creating it and reporting zero rows — is the exact
    /// false-all-clear this module exists to prevent.
    #[error(
        "cannot open Stream G database at {path}: {source}\n\
         This tool opens read-only and NEVER creates a database. If the file is \
         missing the path is wrong; a missing file is never reported as \
         \"0 quarantine rows\"."
    )]
    Open {
        path: PathBuf,
        #[source]
        source: sqlx::Error,
    },

    /// Opened, but `sqlite_master` has no such table. A valid SQLite file that
    /// is not *this* database would otherwise answer every query with zero.
    #[error(
        "{path} is not a Stream G database: table `{table}` does not exist.\n\
         Refusing to report \"no quarantine rows\" about a file that has never \
         held one."
    )]
    NotStreamGDatabase { path: PathBuf, table: &'static str },

    /// `store_meta` exists but its singleton row does not, so there is no
    /// `db_uuid` — and without the `db_uuid` no envelope in the file can be
    /// opened, because it is half the AAD.
    #[error(
        "{path} has a `store_meta` table but no singleton row (id = 1). \
         Without `db_uuid` no sealed column in this file can be authenticated."
    )]
    NoStoreMetaRow { path: PathBuf },

    /// Any SELECT failing. Includes the "file is not a database" (SQLite code
    /// 26) case, which surfaces on the first statement rather than at open.
    #[error("query failed against {path}: {source}")]
    Query {
        path: PathBuf,
        #[source]
        source: sqlx::Error,
    },

    /// SQLite answered `SQLITE_CANTOPEN` (primary code 14) about a file that
    /// **exists and this process can read**. Raised in place of [`Self::Open`]
    /// / [`Self::Query`] because the bare SQLite string — "unable to open
    /// database file" — reads to an operator as "wrong path, or corrupt file",
    /// which is the wrong conclusion and an expensive one to chase during an
    /// incident.
    ///
    /// The real cause is the **directory**, not the file: opening a WAL-mode
    /// database requires creating `<db>-shm` (and possibly `<db>-wal`) beside
    /// it, and `SQLITE_OPEN_READONLY` does not exempt that. Read-only media, a
    /// preserved evidence directory, or a `/deny ...(WD,AD)` ACL therefore
    /// fails here — and a copy "at an ad-hoc path" is exactly what this
    /// command's own `--help` steers operators toward.
    #[error(
        "cannot read {path}: the file exists and is readable, but SQLite refused to open it \
         (SQLITE_CANTOPEN, code {code}): {source}\n\
         The database file is NOT the problem and the path is NOT wrong. Opening a WAL-mode \
         SQLite database — even read-only — requires CREATING `<db>-shm` in the DIRECTORY that \
         holds it, so that directory must be writable. Read-only media, or an evidence \
         directory with write denied, fails exactly here.\n\
         observed beside the database: {sidecars}\n\
         Remedy: copy the database TOGETHER WITH its `-wal` and `-shm` into a directory you can \
         write to, and point --db at the copy. Copying the `.db` alone also silently drops the \
         most recently quarantined rows, which is what the `-wal` holds.\n\
         Do NOT work around this with a `file:...?immutable=1` URI: against a live database that \
         serves a stale view instead of an error, which is why this tool refuses URI paths."
    )]
    CannotOpenSidecars {
        path: PathBuf,
        /// SQLite's extended result code, verbatim.
        code: String,
        /// Which sidecars were present when the failure was classified.
        sidecars: String,
        #[source]
        source: sqlx::Error,
    },
}

/// Which `map_sqlx_error` fallback to use when the failure is *not* the
/// directory-permission case.
#[derive(Debug, Clone, Copy)]
enum Stage {
    Open,
    Query,
}

/// SQLite's primary result code, if this is a database error at all.
///
/// `SqliteError::code()` reports the **extended** code (`SQLITE_CANTOPEN_*`
/// are `14 | (n << 8)`), so the low byte is what has to be compared. Matching
/// the string `"14"` alone would miss every extended variant, and matching a
/// substring would collide with `1038`, `140`, …
///
/// Both forms are real and both were observed: a write-denied directory
/// reports plain `14`, while a `<db>-shm` name occupied by a directory reports
/// `526` (`SQLITE_CANTOPEN_ISDIR`). Dropping the `& 0xFF` makes the reader
/// fall back to the opaque `Query { .. "unable to open database file" }` for
/// the second — mutation-proven by
/// `cantopen_on_a_readable_file_blames_the_directory_not_the_file`.
fn sqlite_primary_code(e: &sqlx::Error) -> Option<i64> {
    let code = e.as_database_error()?.code()?;
    let extended: i64 = code.parse().ok()?;
    Some(extended & 0xFF)
}

const SQLITE_CANTOPEN: i64 = 14;

/// Classify one sqlx failure against the file it was about.
///
/// The only reclassification made here is `SQLITE_CANTOPEN` **on a file this
/// process just proved it can open for reading**. The read probe is what makes
/// the reclassification honest: without it a genuinely missing or unreadable
/// file would be blamed on the directory. It is a plain `File::open` — no
/// creation, no truncation, nothing written — so it does not weaken this
/// module's read-only guarantee.
fn map_sqlx_error(db_path: &Path, source: sqlx::Error, stage: Stage) -> QuarantineReportError {
    if sqlite_primary_code(&source) == Some(SQLITE_CANTOPEN) && std::fs::File::open(db_path).is_ok()
    {
        return QuarantineReportError::CannotOpenSidecars {
            path: db_path.to_path_buf(),
            code: source
                .as_database_error()
                .and_then(|e| e.code())
                .map(|c| c.into_owned())
                .unwrap_or_else(|| SQLITE_CANTOPEN.to_string()),
            sidecars: describe_sidecars(db_path),
            source,
        };
    }
    match stage {
        Stage::Open => QuarantineReportError::Open {
            path: db_path.to_path_buf(),
            source,
        },
        Stage::Query => QuarantineReportError::Query {
            path: db_path.to_path_buf(),
            source,
        },
    }
}

fn describe_sidecars(db_path: &Path) -> String {
    let one = |suffix: &str| match sidecar_len(db_path, suffix) {
        Some(n) => format!("{suffix} present ({n} bytes)"),
        None => format!("{suffix} ABSENT"),
    };
    format!("{}, {}", one("-wal"), one("-shm"))
}

// ---------------------------------------------------------------------------
// Query.
// ---------------------------------------------------------------------------

/// Which quarantine rows to list. Filters narrow the **listing**; they never
/// narrow [`QuarantineReport::total`], so a filter can never manufacture a
/// zero.
#[derive(Debug, Clone)]
pub struct QuarantineQuery {
    /// Maximum rows to render. See [`DEFAULT_LIMIT`].
    pub limit: u32,
    /// Only rows with `created_at >= since`, in **UNIX seconds**.
    ///
    /// Deliberately not a date string. `created_at` is stored as UNIX seconds,
    /// this crate has no date-parsing dependency, and a hand-rolled parser that
    /// silently mis-reads a timezone would filter away the very rows the
    /// operator came for. The rendered `created_at_utc` on every row gives them
    /// the number to paste back in.
    pub since: Option<i64>,
    /// Only rows whose cleartext `status` column equals this error code.
    ///
    /// ⚠️ `status` is **not** authenticated (the sealed `error_code` inside the
    /// envelope is). A row whose plaintext status was edited out of band would
    /// escape this filter, which is why `total` is always reported unfiltered
    /// and why [`QuarantineRow::status_mismatch`] exists.
    pub error_code: Option<String>,
    /// Render exactly one row, by `reconciliation_events.id`.
    pub id: Option<String>,
}

impl Default for QuarantineQuery {
    fn default() -> Self {
        Self {
            limit: DEFAULT_LIMIT,
            since: None,
            error_code: None,
            id: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Report.
// ---------------------------------------------------------------------------

/// How a run ended. The three non-zero variants exist so that
/// `--format json | jq` in an incident script cannot mistake an unreadable
/// table for a healthy one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    /// Opened, read, and every listed row rendered — including a legitimate
    /// zero rows.
    Complete,
    /// At least one row was listed but could not be decrypted: wrong key, or a
    /// tampered envelope.
    DecryptFailures,
    /// Rows were listed with no data key supplied. Not an error, but not
    /// success either: the chain coordinates are still sealed.
    Sealed,
    /// `store_meta.schema_version` is **higher than this build supports**, so
    /// the listing may not be the whole table. See
    /// [`QuarantineReport::schema_version_newer_than_build`].
    ///
    /// 🔴 This variant exists because the alternative was a demonstrated false
    /// all-clear: a database written by a newer build that had renamed the
    /// quarantine `event_type` answered `"status": "complete"`, `"total": 0`,
    /// `"exit_code": 0` while a real quarantine row sat in the table. The
    /// warning was printed in *text* mode only, so every incident script
    /// reading `--format json | jq '.status'` — the exact usage `main.rs`
    /// names as the reason non-zero exits exist — saw a clean run.
    SchemaNewerThanBuild,
}

impl ReportStatus {
    /// Process exit code. `0` complete, `2` decrypt failures, `3` sealed,
    /// `4` schema newer than this build.
    /// `1` is reserved for [`QuarantineReportError`] — could not read at all.
    pub fn exit_code(self) -> i32 {
        match self {
            ReportStatus::Complete => 0,
            ReportStatus::DecryptFailures => 2,
            ReportStatus::Sealed => 3,
            ReportStatus::SchemaNewerThanBuild => 4,
        }
    }
}

/// What this build believes about a `status` value it found in a quarantine
/// row.
///
/// This is not decoration. `ReconcileError::scope()` routes only
/// [`ReconcileErrorScope::LogPermanent`](super::reconcile::ReconcileErrorScope::LogPermanent)
/// errors to the quarantine writer, so most of the `ERR_RECONCILE_*` codes can
/// never legitimately appear in one of these rows. Finding one means the
/// classifier is broken — a fact worth surfacing at the moment an operator is
/// already reading the table, rather than leaving it to look like every other
/// row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusClass {
    /// A code the classifier can legitimately quarantine.
    Quarantinable,
    /// A code this build knows, but which `scope()` never routes to the
    /// quarantine writer. Its presence is itself a defect report.
    ImpossibleHere,
    /// Not an `ERR_RECONCILE_*` code this build knows at all — an older or
    /// newer writer, or an out-of-band edit.
    Unknown,
    /// The `status` column was NULL. The writer always binds a code, so this
    /// is an anomaly too.
    Missing,
}

/// The codes `ReconcileError::scope()` can actually route to
/// `quarantine_unfoldable_log`. Pinned here and cross-checked against the real
/// classifier by
/// `the_quarantinable_code_set_matches_the_real_classifier`, so this list
/// cannot silently drift away from the code it describes.
const QUARANTINABLE_CODES: &[&str] = &[
    ERR_RECONCILE_UNVERIFIED_LOG,
    ERR_RECONCILE_AMBIGUOUS,
    ERR_RECONCILE_SUBMIT,
];

/// `ERR_RECONCILE_*` codes this build knows but which cannot reach a
/// quarantine row.
const IMPOSSIBLE_CODES: &[&str] = &[
    ERR_RECONCILE_UNCORROBORATED_LOG,
    ERR_RECONCILE_STORE,
    ERR_RECONCILE_CHAIN,
    ERR_RECONCILE_CONFIG,
];

fn classify_status(status: Option<&str>) -> StatusClass {
    match status {
        None => StatusClass::Missing,
        Some(s) if QUARANTINABLE_CODES.contains(&s) => StatusClass::Quarantinable,
        Some(s) if IMPOSSIBLE_CODES.contains(&s) => StatusClass::ImpossibleHere,
        Some(_) => StatusClass::Unknown,
    }
}

/// The sealed body of a quarantine row, as this reader deserializes it.
///
/// A deliberate **mirror** of `reconcile::QuarantineDetails`, not a reuse of
/// it: that struct is private to `reconcile` and derives `Serialize` only. The
/// duplication is pinned by every test in this module that plants a row
/// through the real writer and reads it back here — a field renamed on the
/// writing side fails deserialization loudly, it does not decode to defaults.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct QuarantineDetailsView {
    pub intent_id_hex: String,
    pub tx_hash_hex: String,
    pub block_number: u64,
    pub block_hash_hex: String,
    pub log_index: u64,
    pub error_code: String,
}

/// The state of one row's `details_enc` column.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DetailsState {
    /// A key was supplied and the envelope opened.
    Opened(QuarantineDetailsView),
    /// No `--data-key-hex`. The row is still listed in full at the
    /// always-visible tier.
    Sealed,
    /// A key was supplied and the envelope refused it, or the JSON inside did
    /// not parse. Never collapsed into "no details".
    Failed { error: String },
    /// The column itself was NULL. The writer always seals a body, so this is
    /// an anomaly.
    Absent,
}

/// One quarantined log.
#[derive(Debug, Clone, Serialize)]
pub struct QuarantineRow {
    pub id: String,
    pub event_type: String,
    /// Raw `created_at`, UNIX seconds — the value to paste into `--since`.
    pub created_at: i64,
    /// The same instant rendered UTC, for a human reading a terminal.
    pub created_at_utc: String,
    /// Always NULL for a genuine quarantine row: the whole point is that the
    /// log could not be attributed to an attempt. See
    /// [`Self::tx_attempt_id_anomaly`].
    pub tx_attempt_id: Option<String>,
    /// `true` when `tx_attempt_id` is **not** NULL — i.e. something wrote an
    /// attribution into a row that by construction has none.
    pub tx_attempt_id_anomaly: bool,
    /// The cleartext, **unauthenticated** error code column.
    pub status: Option<String>,
    pub status_class: StatusClass,
    /// Set when the cleartext `status` disagrees with the `error_code` inside
    /// the authenticated envelope. The envelope is the trustworthy one; a
    /// disagreement means the plaintext column was edited out of band. This is
    /// the only tamper signal available without re-deriving anything.
    pub status_mismatch: Option<String>,
    pub details_enc_len: usize,
    pub decrypted: bool,
    pub details: DetailsState,
}

/// One run of the reader.
#[derive(Debug, Clone, Serialize)]
pub struct QuarantineReport {
    /// The path as opened. A "0 rows" answer must name the file it is 0 rows
    /// about.
    pub db_path: String,
    /// Size of `<db>-wal`, when present. An operator who copies `stream_g.db`
    /// off a live machine and leaves the `-wal` behind gets a consistent but
    /// **stale** view — and the most recently quarantined logs, the ones they
    /// came for, may live entirely in that `-wal`. That is a silent wrong
    /// answer, so its absence is stated on the first screen of output.
    pub db_wal_bytes: Option<u64>,
    /// Size of `<db>-shm`, when present. Same reason.
    pub db_shm_bytes: Option<u64>,
    pub db_uuid: String,
    /// `store_meta.schema_version` — the highest migration this file records.
    pub store_meta_schema_version: i64,
    /// The **pinned** AAD version, [`ENVELOPE_AAD_SCHEMA_VERSION`]. Reported
    /// next to the one above precisely because they are different numbers and
    /// confusing them makes every unseal fail.
    pub envelope_aad_schema_version: u32,
    pub build_supported_schema_version: i64,
    /// `true` when this file was migrated by a newer build than this one.
    ///
    /// 🔴 Still a **read, not a refusal**, and that is a deliberate divergence
    /// from `StreamGStore::open`, which fails outright with
    /// `StreamGStoreError::SchemaVersionTooNew`. Refusing is right for a
    /// *writer*: it would otherwise write rows against tables it cannot
    /// describe. It is wrong for a diagnostic reader, because a half-applied
    /// or newer-build migration is itself a plausible incident, and refusing
    /// then makes the tool useless at exactly the moment it is wanted. Every
    /// row this build *can* see is still listed. Do not "fix" this into a
    /// refusal.
    ///
    /// 🔴 But it is **never a clean run**: when this is `true` the report's
    /// [`ReportStatus`] is [`ReportStatus::SchemaNewerThanBuild`] and the exit
    /// code is `4`. The earlier version of this module printed a warning
    /// banner in text mode and left `status` at `complete`, and that was a
    /// demonstrated false all-clear — a newer build that renamed the
    /// quarantine `event_type` produced `"total": 0, "status": "complete",
    /// "exit_code": 0` with a real quarantine row in the table. The premise
    /// that "the tables come from migration 0001 and cannot have moved" is
    /// exactly what a newer schema puts in doubt, and a missed quarantine row
    /// is unrecoverable by construction. Do not "fix" this back into a
    /// text-only warning.
    pub schema_version_newer_than_build: bool,
    /// Derived, non-secret identifier of the supplied data key. `None` when no
    /// key was supplied.
    pub key_id: Option<String>,
    /// Every quarantine row in the file, filters ignored.
    pub total: u64,
    /// Rows matching the filters, `--limit` ignored.
    pub matched: u64,
    /// Rows actually rendered.
    pub shown: usize,
    /// `shown < matched`.
    pub truncated: bool,
    pub decrypt_failures: usize,
    pub sealed_rows: usize,
    pub status: ReportStatus,
    pub exit_code: i32,
    pub rows: Vec<QuarantineRow>,
}

// ---------------------------------------------------------------------------
// Open.
// ---------------------------------------------------------------------------

/// Open `db_path` **read-only**: no instance lock, no migration, no
/// create-if-missing.
///
/// # Bypassing the instance lock here is sound, not an oversight
///
/// `StreamGStore::open`'s `fs2::try_lock_exclusive` on `lock_path` enforces a
/// single-**writer** invariant — it is what keeps two processes from
/// interleaving `BEGIN IMMEDIATE` transactions against one file. This path
/// opens with `SQLITE_OPEN_READONLY` and issues only SELECTs; SQLite itself
/// refuses any write on this handle (`code: 8, attempt to write a readonly
/// database`). There is no writer to serialise, so there is nothing for the
/// lock to protect. Taking it would instead guarantee the tool fails whenever
/// the attestor is running — i.e. exactly during the incident it exists to
/// diagnose. **Do not add the lock. Do not swap in `StreamGStore::open`.**
///
/// # The other two things `StreamGStore::open` does that are disqualifying here
///
/// * `create_if_missing(true)` — a mistyped path would mint an empty database
///   and the tool would then truthfully report zero quarantine rows about it.
///   `read_only(true)` alone already suppresses `SQLITE_OPEN_CREATE` (see the
///   exclusive flag composition in `sqlx-sqlite`'s `establish.rs`);
///   `create_if_missing(false)` is kept as documentation of intent.
/// * `apply_migration_if_needed` — a read-only diagnostic must never migrate
///   the operator's database, least of all one it was pointed at because
///   something had already gone wrong with it.
///
/// # Not `store::PRAGMA_SQL` either
///
/// `journal_mode=WAL` is a header **write**; it is a no-op only because the
/// file already happens to be WAL, and against a DELETE-mode file on a
/// read-only handle it fails outright. `foreign_keys` and `synchronous` are
/// meaningless for SELECTs. Only `busy_timeout` earns its place — set through
/// the typed builder, not by executing a pragma — so that a writer in the
/// middle of a WAL checkpoint yields a short wait instead of an instant
/// `SQLITE_BUSY`.
pub async fn open_read_only(db_path: &Path) -> Result<SqlitePool, QuarantineReportError> {
    reject_uri(db_path)?;

    let opts = SqliteConnectOptions::new()
        .filename(db_path)
        .read_only(true)
        .create_if_missing(false)
        .busy_timeout(Duration::from_millis(5_000));

    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .map_err(|source| map_sqlx_error(db_path, source, Stage::Open))
}

/// See [`QuarantineReportError::UriPath`].
fn reject_uri(db_path: &Path) -> Result<(), QuarantineReportError> {
    let s = db_path.to_string_lossy();
    if s.starts_with("file:") || s.contains('?') {
        return Err(QuarantineReportError::UriPath {
            path: s.into_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Load.
// ---------------------------------------------------------------------------

/// Bind `event_type` and then whichever filters [`filter_sql`] appended, **in
/// the same order it appended them**.
///
/// A macro rather than a function because sqlx's `Query` and `QueryScalar` are
/// unrelated types with no shared binding trait: the count and the listing
/// would otherwise need two copies of this body, and two copies of one
/// bind-order contract is how a filter ends up bound to the wrong `?`.
macro_rules! bind_filters {
    ($q:expr, $query:expr) => {{
        let mut q = $q.bind(QUARANTINE_EVENT_TYPE);
        if let Some(since) = $query.since {
            q = q.bind(since);
        }
        if let Some(code) = $query.error_code.clone() {
            q = q.bind(code);
        }
        if let Some(id) = $query.id.clone() {
            q = q.bind(id);
        }
        q
    }};
}

/// Open `db_path` read-only and build the report.
///
/// `data_key` absent is a **supported mode**, not an error: every row is still
/// listed, each marked [`DetailsState::Sealed`], and the run reports
/// [`ReportStatus::Sealed`].
pub async fn load_report(
    db_path: &Path,
    data_key: Option<&SecretHex>,
    query: &QuarantineQuery,
) -> Result<QuarantineReport, QuarantineReportError> {
    // 0. Measure the sidecars BEFORE touching the database.
    //
    //    🔴 Order is the whole assertion here, not tidiness. Reading a
    //    WAL-mode database makes SQLite materialise a zero-byte `<db>-wal`
    //    (and a `-shm`) beside it; `SQLITE_OPEN_READONLY` does not prevent
    //    that. Measuring at report-construction time, as this module first
    //    did, therefore ALWAYS found `Some(0)` — which made the
    //    "⚠ no -wal sidecar" warning in [`render_text`] unreachable for every
    //    real Stream G file. That warning is the only thing that tells an
    //    operator their forensic copy is truncated: copy a live `.db` without
    //    its `-wal` and the most recently quarantined rows — the ones they
    //    came for — are simply absent, while the report renders complete and
    //    clean.
    //
    //    Measured here rather than just after `open_read_only` because the
    //    connect alone does not yet create the `-wal`; the first read does.
    //    "Before the open" is the only placement that cannot drift back into
    //    the bug. Do NOT move these two calls down.
    let db_wal_bytes = sidecar_len(db_path, "-wal");
    let db_shm_bytes = sidecar_len(db_path, "-shm");

    let pool = open_read_only(db_path).await?;

    // 1. Preflight. A valid SQLite file that is not this database must be an
    //    error, never a zero. Probed in this order because `store_meta` is what
    //    makes the file identifiable at all.
    for table in ["store_meta", TABLE] {
        if !table_exists(&pool, db_path, table).await? {
            return Err(QuarantineReportError::NotStreamGDatabase {
                path: db_path.to_path_buf(),
                table,
            });
        }
    }

    // 2. Identity. `db_uuid` is half the envelope AAD; the schema version goes
    //    in the header so a stale-build read is visible.
    let meta = sqlx::query("SELECT db_uuid, schema_version FROM store_meta WHERE id = 1")
        .fetch_optional(&pool)
        .await
        .map_err(|source| map_sqlx_error(db_path, source, Stage::Query))?;
    let meta = meta.ok_or_else(|| QuarantineReportError::NoStoreMetaRow {
        path: db_path.to_path_buf(),
    })?;
    let db_uuid: String = row_get(&meta, "db_uuid", db_path)?;
    let store_meta_schema_version: i64 = row_get(&meta, "schema_version", db_path)?;

    // 3. Counts, before the rows, so truncation is stated rather than implied.
    //    `total` ignores every filter: a `--since` or `--error-code` that
    //    happens to match nothing must not read as an empty table.
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {TABLE} WHERE event_type = ?"
    ))
    .bind(QUARANTINE_EVENT_TYPE)
    .fetch_one(&pool)
    .await
    .map_err(|source| map_sqlx_error(db_path, source, Stage::Query))?;

    let where_clause = filter_sql(query);
    let matched_sql = format!("SELECT COUNT(*) FROM {TABLE} WHERE event_type = ?{where_clause}");
    let matched: i64 = bind_filters!(sqlx::query_scalar(&matched_sql), query)
        .fetch_one(&pool)
        .await
        .map_err(|source| map_sqlx_error(db_path, source, Stage::Query))?;

    // 4. The rows. `created_at` is not unique (INSERT OR IGNORE, same second),
    //    so `id` breaks the tie and the order is total.
    //
    //    `event_type = ?` bound to the writer's own `pub const` — never a
    //    literal, and never a `LIKE` prefix: `submit::RECONCILIATION_EVENT_TYPE`
    //    is `"SponsoredEnrollmentExecuted"` and the quarantine type is that
    //    exact string plus `".quarantined"`, so a prefix match would swallow
    //    both classes of row and then try to deserialize a body shape that row
    //    never had.
    //
    //    `event_type` has no index (`0001` creates only
    //    `idx_reconciliation_events_tx_attempt_id`), so this is a full table
    //    scan. That is acceptable for a diagnostic, and a read-only tool must
    //    not "fix" it by creating one.
    let sql = format!(
        "SELECT id, tx_attempt_id, event_type, status, details_enc, created_at \
         FROM {TABLE} WHERE event_type = ?{where_clause} \
         ORDER BY created_at ASC, id ASC LIMIT ?"
    );
    let raw_rows = bind_filters!(sqlx::query(&sql), query)
        .bind(i64::from(query.limit))
        .fetch_all(&pool)
        .await
        .map_err(|source| map_sqlx_error(db_path, source, Stage::Query))?;

    // 🔴 The AAD schema version is the PINNED constant, NOT
    // `store_meta.schema_version`. They are 1 and 3 today. Feeding the live
    // schema version in would make every unseal in this module fail with
    // `DecryptionFailed`, and the report would then look exactly like a wrong
    // key. `store.rs`'s own doc for `ENVELOPE_AAD_SCHEMA_VERSION` explains
    // why the envelope stays pinned to what it can be re-derived from.
    let key = data_key.map(DataKey::from_secret);

    let mut rows = Vec::with_capacity(raw_rows.len());
    let mut decrypt_failures = 0usize;
    let mut sealed_rows = 0usize;

    for r in &raw_rows {
        let id: String = row_get(r, "id", db_path)?;
        let event_type: String = row_get(r, "event_type", db_path)?;
        let created_at: i64 = row_get(r, "created_at", db_path)?;
        let tx_attempt_id: Option<String> = row_get(r, "tx_attempt_id", db_path)?;
        let status: Option<String> = row_get(r, "status", db_path)?;
        let envelope: Option<Vec<u8>> = row_get(r, "details_enc", db_path)?;

        let details_enc_len = envelope.as_ref().map_or(0, Vec::len);
        let details = match (&envelope, key.as_ref()) {
            (None, _) => DetailsState::Absent,
            (Some(_), None) => {
                sealed_rows += 1;
                DetailsState::Sealed
            }
            (Some(bytes), Some(key)) => {
                let aad = EnvelopeAad {
                    db_uuid: &db_uuid,
                    schema_version: ENVELOPE_AAD_SCHEMA_VERSION,
                    table: TABLE,
                    pk: &id,
                    column: COLUMN,
                };
                match crypto_store::open(key, &aad, bytes) {
                    Ok(plain) => match serde_json::from_slice::<QuarantineDetailsView>(&plain) {
                        Ok(view) => DetailsState::Opened(view),
                        Err(e) => {
                            decrypt_failures += 1;
                            DetailsState::Failed {
                                error: format!("envelope opened but its body did not parse: {e}"),
                            }
                        }
                    },
                    Err(e) => {
                        decrypt_failures += 1;
                        DetailsState::Failed {
                            error: e.to_string(),
                        }
                    }
                }
            }
        };

        let status_mismatch = match (&status, &details) {
            (Some(s), DetailsState::Opened(view)) if *s != view.error_code => Some(format!(
                "cleartext status is {s:?} but the authenticated envelope says {:?}; \
                 the plaintext column was edited out of band",
                view.error_code
            )),
            _ => None,
        };

        rows.push(QuarantineRow {
            id,
            event_type,
            created_at,
            created_at_utc: format_unix_utc(created_at),
            tx_attempt_id_anomaly: tx_attempt_id.is_some(),
            tx_attempt_id,
            status_class: classify_status(status.as_deref()),
            status,
            status_mismatch,
            details_enc_len,
            decrypted: matches!(details, DetailsState::Opened(_)),
            details,
        });
    }

    let shown = rows.len();
    let schema_version_newer_than_build = store_meta_schema_version > supported_schema_version();

    // 🔴 Precedence: "I may not be able to see everything" outranks everything
    // below it. A newer schema is the only condition here that puts the
    // COMPLETENESS of the listing in doubt — the other two describe rows that
    // were listed and merely could not be opened. `decrypt_failures` and
    // `sealed_rows` stay on the report as their own fields, so nothing is
    // hidden by the ordering; only the single-word summary is.
    let status = if schema_version_newer_than_build {
        ReportStatus::SchemaNewerThanBuild
    } else if decrypt_failures > 0 {
        ReportStatus::DecryptFailures
    } else if sealed_rows > 0 {
        ReportStatus::Sealed
    } else {
        ReportStatus::Complete
    };

    Ok(QuarantineReport {
        db_path: db_path.display().to_string(),
        db_wal_bytes,
        db_shm_bytes,
        db_uuid,
        // Reported exactly as the column holds it — no clamping. A negative or
        // absurd value here is a finding, and rounding it into range would
        // erase the only evidence of it.
        store_meta_schema_version,
        envelope_aad_schema_version: ENVELOPE_AAD_SCHEMA_VERSION,
        build_supported_schema_version: supported_schema_version(),
        schema_version_newer_than_build,
        key_id: data_key.map(SecretHex::key_id),
        total: total.max(0) as u64,
        matched: matched.max(0) as u64,
        shown,
        truncated: (shown as u64) < matched.max(0) as u64,
        decrypt_failures,
        sealed_rows,
        status,
        exit_code: status.exit_code(),
        rows,
    })
}

fn filter_sql(query: &QuarantineQuery) -> String {
    let mut s = String::new();
    if query.since.is_some() {
        s.push_str(" AND created_at >= ?");
    }
    if query.error_code.is_some() {
        s.push_str(" AND status = ?");
    }
    if query.id.is_some() {
        s.push_str(" AND id = ?");
    }
    s
}

async fn table_exists(
    pool: &SqlitePool,
    db_path: &Path,
    name: &str,
) -> Result<bool, QuarantineReportError> {
    let found: Option<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' AND name = ?")
            .bind(name)
            .fetch_optional(pool)
            .await
            .map_err(|source| map_sqlx_error(db_path, source, Stage::Query))?;
    Ok(found.is_some())
}

fn row_get<'r, T>(
    row: &'r sqlx::sqlite::SqliteRow,
    column: &str,
    db_path: &Path,
) -> Result<T, QuarantineReportError>
where
    T: sqlx::Decode<'r, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite>,
{
    row.try_get(column)
        .map_err(|source| QuarantineReportError::Query {
            path: db_path.to_path_buf(),
            source,
        })
}

fn sidecar_len(db_path: &Path, suffix: &str) -> Option<u64> {
    let mut name = db_path.as_os_str().to_os_string();
    name.push(suffix);
    std::fs::metadata(PathBuf::from(name)).ok().map(|m| m.len())
}

// ---------------------------------------------------------------------------
// Time.
//
// No `chrono`/`time` dependency in this crate, and adding one to print a
// timestamp would be a poor trade. `created_at` is always reported raw as well,
// so this rendering is a convenience layered on top of the authoritative value
// — never the only form the operator sees.
// ---------------------------------------------------------------------------

/// UNIX seconds → `YYYY-MM-DDTHH:MM:SSZ`.
pub fn format_unix_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 → (year, month,
/// day) in the proleptic Gregorian calendar. Exact for every value in range,
/// with no lookup tables and no leap-year special cases to get wrong.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

// ---------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------

/// Machine-readable form. Deliberately **not** `canonical_json`: that module
/// exists for consensus payload hashing, not operator output.
pub fn render_json(report: &QuarantineReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

/// Human form. Every key-dependent fact is in a clearly separate tier from the
/// always-visible one, so a key-less run reads as "listed but not decrypted"
/// rather than as a shorter version of a healthy run.
pub fn render_text(report: &QuarantineReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    let _ = writeln!(out, "Stream G quarantine report");
    let _ = writeln!(out, "  database:                  {}", report.db_path);
    let _ = writeln!(
        out,
        "  <db>-wal:                  {}",
        sidecar_line(report.db_wal_bytes)
    );
    let _ = writeln!(
        out,
        "  <db>-shm:                  {}",
        sidecar_line(report.db_shm_bytes)
    );
    if report.db_wal_bytes.is_none() {
        let _ = writeln!(
            out,
            "    ⚠ no -wal sidecar. If this file was copied off a running machine, the most \
             recently quarantined logs may have been left behind in it."
        );
    }
    let _ = writeln!(out, "  db_uuid:                   {}", report.db_uuid);
    let _ = writeln!(
        out,
        "  store_meta.schema_version: {}  (this build supports {})",
        report.store_meta_schema_version, report.build_supported_schema_version
    );
    if report.schema_version_newer_than_build {
        let _ = writeln!(
            out,
            "    ⚠ this database was migrated by a NEWER build than this one. Reading anyway, \
             because refusing would make this tool useless during exactly the kind of incident \
             that produces a half-applied migration — but everything below is what THIS build \
             can see, which is not necessarily everything. See the verdict at the end."
        );
    }
    let _ = writeln!(
        out,
        "  envelope AAD version:      {} (pinned; deliberately NOT the schema version above)",
        report.envelope_aad_schema_version
    );
    match &report.key_id {
        Some(key_id) => {
            let _ = writeln!(out, "  data key:                  key_id={key_id}");
        }
        None => {
            let _ = writeln!(
                out,
                "  data key:                  NONE SUPPLIED (rows are listed, bodies stay sealed)"
            );
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "showing {} of {} quarantined logs matching the filters ({} in this database)",
        report.shown, report.matched, report.total
    );
    if report.truncated {
        let _ = writeln!(
            out,
            "  ⚠ TRUNCATED by --limit. This is NOT the complete list; raise --limit to see the rest."
        );
    }
    let _ = writeln!(out);

    for (i, row) in report.rows.iter().enumerate() {
        let _ = writeln!(out, "--- row {} of {} ---", i + 1, report.shown);
        let _ = writeln!(out, "  id:            {}", row.id);
        let _ = writeln!(
            out,
            "  created_at:    {} ({})",
            row.created_at, row.created_at_utc
        );
        let _ = writeln!(out, "  event_type:    {}", row.event_type);
        let _ = writeln!(
            out,
            "  status:        {}  [{}]",
            row.status.as_deref().unwrap_or("NULL"),
            status_class_note(row.status_class)
        );
        if row.status_class == StatusClass::ImpossibleHere {
            let _ = writeln!(
                out,
                "    🔴 ANOMALY: `ReconcileError::scope()` never routes this code to the \
                 quarantine writer, so no correct build can have written this row. The \
                 classifier, or this row, is wrong."
            );
        }
        match &row.tx_attempt_id {
            None => {
                let _ = writeln!(
                    out,
                    "  tx_attempt_id: NULL (by design — the log could not be attributed)"
                );
            }
            Some(id) => {
                let _ = writeln!(
                    out,
                    "  tx_attempt_id: {id}\n    🔴 ANOMALY: quarantine rows are written with NULL here."
                );
            }
        }
        let _ = writeln!(out, "  details_enc:   {} bytes", row.details_enc_len);
        match &row.details {
            DetailsState::Sealed => {
                let _ = writeln!(out, "  details:       SEALED (no --data-key-hex supplied)");
            }
            DetailsState::Absent => {
                let _ = writeln!(
                    out,
                    "  details:       ABSENT (the details_enc column is NULL — the writer always \
                     seals a body, so this row is malformed)"
                );
            }
            DetailsState::Failed { error } => {
                let _ = writeln!(out, "  details:       DECRYPT FAILED ({error})");
            }
            DetailsState::Opened(v) => {
                let _ = writeln!(out, "  details:       intent_id:   {}", v.intent_id_hex);
                let _ = writeln!(out, "                 tx_hash:     {}", v.tx_hash_hex);
                let _ = writeln!(out, "                 block:       {}", v.block_number);
                let _ = writeln!(out, "                 block_hash:  {}", v.block_hash_hex);
                let _ = writeln!(out, "                 log_index:   {}", v.log_index);
                let _ = writeln!(out, "                 error_code:  {}", v.error_code);
            }
        }
        if let Some(m) = &row.status_mismatch {
            let _ = writeln!(out, "    🔴 TAMPER SIGNAL: {m}");
        }
        let _ = writeln!(out);
    }

    match report.status {
        ReportStatus::Complete => {}
        ReportStatus::Sealed => {
            let _ = writeln!(
                out,
                "🔴 {} rows were listed but NOT decrypted (no --data-key-hex supplied). \
                 Pass the daemon's at-rest key — preferably via STREAM_G_DATA_KEY_HEX, so it \
                 does not land in shell history — to see which logs these were. Exit code {}.",
                report.sealed_rows, report.exit_code
            );
        }
        ReportStatus::DecryptFailures => {
            let _ = writeln!(
                out,
                "🔴 {} of {} rows could not be decrypted (wrong key, or a tampered envelope). \
                 The rows above are real; their bodies could not be authenticated. Exit code {}.",
                report.decrypt_failures, report.shown, report.exit_code
            );
        }
        ReportStatus::SchemaNewerThanBuild => {
            let _ = writeln!(
                out,
                "🔴 THIS LISTING MAY BE INCOMPLETE. store_meta.schema_version is {} but this \
                 build supports {}: the file was written by a NEWER build, which may have \
                 renamed, moved or added quarantine rows this build cannot see. The {} row(s) \
                 listed above are real, but \"{} in this database\" is what THIS build can find, \
                 NOT a clean bill of health — a newer writer that renamed the quarantine \
                 event_type would produce exactly this zero. Re-run with a build at schema {} or \
                 later before concluding anything. Exit code {}.",
                report.store_meta_schema_version,
                report.build_supported_schema_version,
                report.shown,
                report.total,
                report.store_meta_schema_version,
                report.exit_code
            );
            if report.decrypt_failures > 0 || report.sealed_rows > 0 {
                let _ = writeln!(
                    out,
                    "    (also: {} row(s) failed to decrypt, {} row(s) left sealed — this exit \
                     code reports the incompleteness, which outranks both.)",
                    report.decrypt_failures, report.sealed_rows
                );
            }
        }
    }
    out
}

fn sidecar_line(bytes: Option<u64>) -> String {
    match bytes {
        Some(n) => format!("present ({n} bytes)"),
        None => "ABSENT".to_string(),
    }
}

fn status_class_note(class: StatusClass) -> &'static str {
    match class {
        StatusClass::Quarantinable => "quarantinable",
        StatusClass::ImpossibleHere => "IMPOSSIBLE HERE",
        StatusClass::Unknown => "UNKNOWN CODE",
        StatusClass::Missing => "MISSING",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use crate::chain::ExecutedLogFields;
    use crate::stream_g::reconcile::{
        quarantine_unfoldable_log, ReconcileError, ReconcileErrorScope,
    };
    use crate::stream_g::store::{StreamGStore, StreamGStoreError};
    use crate::stream_g::submit::RECONCILIATION_EVENT_TYPE;

    const WALL_NOW: i64 = 1_800_000_000;

    fn key_a() -> SecretHex {
        SecretHex::from_hex(&"aa".repeat(32)).expect("valid 32-byte test key")
    }

    fn key_b() -> SecretHex {
        SecretHex::from_hex(&"bb".repeat(32)).expect("valid 32-byte test key")
    }

    /// A live writer store, kept alive by the caller for the whole test body —
    /// the instance lock is held exactly as it is while the attestor runs.
    async fn live_store() -> (tempfile::TempDir, StreamGStore, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open store");
        (dir, store, db, lock)
    }

    /// Plant one quarantine row through the **real** writer, so every test
    /// reads what production writes (id derivation, AAD, body shape included).
    async fn plant(
        store: &StreamGStore,
        key: &SecretHex,
        block_number: u64,
        block_hash: u8,
        log_index: u64,
        error_code: &'static str,
        created_at: i64,
    ) -> String {
        let log = ExecutedLogFields {
            intent_id: [0x33; 32],
            root: [0x44; 20],
            secondary: [0x55; 20],
            controller: [0xA1; 20],
            fee_token: [0x66; 20],
            fee_amount: 1_000,
        }
        .with_metadata(block_number, [block_hash; 32], log_index, [0x77; 32], false);
        quarantine_unfoldable_log(store, key, &log, error_code, created_at)
            .await
            .expect("plant quarantine row")
    }

    // -----------------------------------------------------------------------
    // 1. The false all-clear this module exists to prevent.
    // -----------------------------------------------------------------------

    /// Mutation proof: replace `.read_only(true).create_if_missing(false)` in
    /// [`open_read_only`] with `.create_if_missing(true)` — the
    /// `StreamGStore::open` recipe — and this test goes red on TWO independent
    /// assertions: `unwrap_err` panics because the open succeeded, and the
    /// database file now exists.
    #[tokio::test]
    async fn missing_db_is_a_loud_error_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("absent.sqlite");
        assert!(!absent.exists(), "precondition: the file must not exist");

        let err = open_read_only(&absent)
            .await
            .expect_err("a missing database must be an error, never an empty report");
        let msg = err.to_string();
        assert!(
            msg.contains(&absent.display().to_string()),
            "the error must NAME the path it could not open; got: {msg}"
        );
        assert!(
            msg.contains("NEVER creates"),
            "the error must say the tool does not create databases; got: {msg}"
        );
        assert!(
            !absent.exists(),
            "a read-only reader must not have created {}",
            absent.display()
        );

        // And the whole report path refuses too — no row count is ever
        // reported about a file that does not exist.
        let report = load_report(&absent, Some(&key_a()), &QuarantineQuery::default()).await;
        assert!(report.is_err(), "load_report must not report rows here");
        assert!(
            !absent.exists(),
            "load_report must not have created the file"
        );
    }

    // -----------------------------------------------------------------------
    // 2. The tool works during an incident, i.e. while the attestor is running.
    // -----------------------------------------------------------------------

    /// Mutation proof: build the reader on `StreamGStore::open(db, lock)`
    /// instead of the read-only pool and this test goes red with
    /// `StreamGStoreError::InstanceLock`, whose Display contains
    /// "instance lock".
    #[tokio::test]
    async fn reader_opens_while_the_instance_lock_is_held() {
        // `store` stays alive for the WHOLE body: the fs2 exclusive lock is
        // held exactly as it is while the daemon runs.
        let (_dir, store, db, lock) = live_store().await;
        plant(
            &store,
            &key_a(),
            1_000,
            0x99,
            0,
            ERR_RECONCILE_UNVERIFIED_LOG,
            WALL_NOW,
        )
        .await;

        // Prove the lock really is held, so this test cannot pass vacuously
        // against a store that quietly released it.
        let second = StreamGStore::open(&db, &lock).await;
        assert!(
            matches!(second, Err(StreamGStoreError::InstanceLock { .. })),
            "precondition: a second writer must be refused, else this test proves nothing"
        );

        let report = load_report(&db, Some(&key_a()), &QuarantineQuery::default())
            .await
            .expect("the reader must open while the writer holds the instance lock");
        assert_eq!(report.total, 1);
        assert_eq!(report.shown, 1);
        assert_eq!(report.status, ReportStatus::Complete);
    }

    // -----------------------------------------------------------------------
    // 3. The AAD schema version is the pinned constant, not store_meta's.
    // -----------------------------------------------------------------------

    /// Mutation proof: change the AAD in [`load_report`] to
    /// `schema_version: store_meta_schema_version as u32` and every row fails
    /// with `CryptoStoreError::DecryptionFailed`.
    #[tokio::test]
    async fn aad_schema_version_is_the_pinned_constant_not_store_meta() {
        let (_dir, store, db, _lock) = live_store().await;
        plant(
            &store,
            &key_a(),
            1_000,
            0x99,
            0,
            ERR_RECONCILE_UNVERIFIED_LOG,
            WALL_NOW,
        )
        .await;

        let report = load_report(&db, Some(&key_a()), &QuarantineQuery::default())
            .await
            .expect("read");

        // 🔴 Assert the inequality FIRST. The mutation this test detects is
        // only detectable while the two numbers differ; if a future re-seal
        // migration ever makes them equal, this test would silently stop
        // proving anything, and a vacuous test is worse than no test.
        assert_ne!(
            report.store_meta_schema_version,
            i64::from(report.envelope_aad_schema_version),
            "THIS TEST HAS GONE VACUOUS: store_meta.schema_version and \
             ENVELOPE_AAD_SCHEMA_VERSION are now equal ({}), so feeding the wrong one into the \
             AAD would no longer fail. Re-pin this test against whatever now distinguishes them.",
            report.store_meta_schema_version
        );

        assert_eq!(report.decrypt_failures, 0, "{:#?}", report.rows);
        assert!(matches!(report.rows[0].details, DetailsState::Opened(_)));
    }

    // -----------------------------------------------------------------------
    // 4. The AAD is pinned to the row id, and tampering is detected.
    // -----------------------------------------------------------------------

    /// Mutation proof: hardcode the AAD `pk` to a constant (or to the first
    /// row's id) and this test goes red — the untampered rows stop opening,
    /// and the swapped pair can no longer be distinguished from a healthy
    /// read.
    #[tokio::test]
    async fn aad_is_pinned_to_the_row_id_and_tampering_is_detected() {
        let (_dir, store, db, _lock) = live_store().await;
        let id_a = plant(
            &store,
            &key_a(),
            1_000,
            0x99,
            0,
            ERR_RECONCILE_UNVERIFIED_LOG,
            WALL_NOW,
        )
        .await;
        let id_b = plant(
            &store,
            &key_a(),
            1_001,
            0xAB,
            7,
            ERR_RECONCILE_AMBIGUOUS,
            WALL_NOW + 1,
        )
        .await;
        assert_ne!(id_a, id_b, "the two logs must derive distinct row ids");

        // Healthy baseline: both open, and each carries ITS OWN coordinates.
        let healthy = load_report(&db, Some(&key_a()), &QuarantineQuery::default())
            .await
            .expect("read");
        assert_eq!(healthy.decrypt_failures, 0);
        let opened: Vec<_> = healthy
            .rows
            .iter()
            .map(|r| match &r.details {
                DetailsState::Opened(v) => v.block_number,
                other => panic!("expected an opened body, got {other:?}"),
            })
            .collect();
        assert_eq!(opened, vec![1_000, 1_001]);

        // Now swap the two envelopes through the still-live writer.
        let (a, b) = (id_a.clone(), id_b.clone());
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    let blob_a: Vec<u8> = sqlx::query_scalar(
                        "SELECT details_enc FROM reconciliation_events WHERE id = ?",
                    )
                    .bind(&a)
                    .fetch_one(&mut **tx)
                    .await?;
                    let blob_b: Vec<u8> = sqlx::query_scalar(
                        "SELECT details_enc FROM reconciliation_events WHERE id = ?",
                    )
                    .bind(&b)
                    .fetch_one(&mut **tx)
                    .await?;
                    sqlx::query("UPDATE reconciliation_events SET details_enc = ? WHERE id = ?")
                        .bind(&blob_b)
                        .bind(&a)
                        .execute(&mut **tx)
                        .await?;
                    sqlx::query("UPDATE reconciliation_events SET details_enc = ? WHERE id = ?")
                        .bind(&blob_a)
                        .bind(&b)
                        .execute(&mut **tx)
                        .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("swap the two envelopes");

        let tampered = load_report(&db, Some(&key_a()), &QuarantineQuery::default())
            .await
            .expect("read");
        assert_eq!(
            tampered.decrypt_failures, 2,
            "moving an envelope to another row must be refused by the AAD, not decoded"
        );
        assert_eq!(tampered.status, ReportStatus::DecryptFailures);
        assert_eq!(
            tampered.exit_code, 2,
            "a tampered table is not a clean read"
        );
        for row in &tampered.rows {
            match &row.details {
                DetailsState::Failed { error } => assert!(
                    error.contains("decryption failed"),
                    "expected an authentication failure, got {error}"
                ),
                other => panic!("a moved envelope must NOT open: {other:?}"),
            }
        }
        let text = render_text(&tampered);
        assert!(text.contains("DECRYPT FAILED"), "{text}");
        assert!(
            !text.contains("block:       1000") && !text.contains("block:       1001"),
            "no row may render the other row's chain coordinates:\n{text}"
        );
    }

    // -----------------------------------------------------------------------
    // 5. No key at all: every row still listed, and it is not success.
    // -----------------------------------------------------------------------

    /// Mutation proof: change the no-key branch to `return Ok(Vec::new())` —
    /// the tempting "nothing renderable, render nothing" — and this test goes
    /// red on `shown == 2`. Dropping the `Sealed` marker / reporting exit 0
    /// reds the marker and exit-status assertions independently.
    #[tokio::test]
    async fn absent_data_key_lists_every_row_and_never_pretends_it_is_empty() {
        let (_dir, store, db, _lock) = live_store().await;
        plant(
            &store,
            &key_a(),
            1_000,
            0x99,
            0,
            ERR_RECONCILE_UNVERIFIED_LOG,
            WALL_NOW,
        )
        .await;
        plant(
            &store,
            &key_a(),
            1_001,
            0xAB,
            7,
            ERR_RECONCILE_AMBIGUOUS,
            WALL_NOW + 1,
        )
        .await;

        let report = load_report(&db, None, &QuarantineQuery::default())
            .await
            .expect("a key-less read is a supported mode, not an error");

        assert_eq!(report.shown, 2, "every row must still be listed");
        assert_eq!(report.total, 2);
        assert_eq!(report.matched, 2);
        assert_eq!(report.sealed_rows, 2);
        assert_eq!(report.key_id, None);
        for row in &report.rows {
            assert!(
                matches!(row.details, DetailsState::Sealed),
                "each row must carry an explicit sealed marker: {row:?}"
            );
            assert!(!row.decrypted);
            assert!(
                row.details_enc_len > 0,
                "the always-visible tier includes the byte length"
            );
            assert!(row.status.is_some(), "the error code needs no key");
            assert!(row.tx_attempt_id.is_none());
        }
        assert_eq!(report.status, ReportStatus::Sealed);
        assert_eq!(report.exit_code, 3, "a sealed listing must not exit 0");

        let text = render_text(&report);
        assert!(
            text.contains("SEALED (no --data-key-hex supplied)"),
            "{text}"
        );
        assert!(
            text.contains("2 rows were listed but NOT decrypted"),
            "{text}"
        );
    }

    // -----------------------------------------------------------------------
    // 6. Wrong key: per-row, loud, and not success.
    // -----------------------------------------------------------------------

    /// Mutation proof: change the unseal arm to
    /// `crypto_store::open(..).ok()` with an empty-details fallback and this
    /// test goes red — `decrypt_failures` becomes 0, rows report success, and
    /// the exit code becomes 0.
    #[tokio::test]
    async fn wrong_data_key_is_reported_per_row_and_is_not_success() {
        let (_dir, store, db, _lock) = live_store().await;
        plant(
            &store,
            &key_a(),
            1_000,
            0x99,
            0,
            ERR_RECONCILE_UNVERIFIED_LOG,
            WALL_NOW,
        )
        .await;
        plant(
            &store,
            &key_a(),
            1_001,
            0xAB,
            7,
            ERR_RECONCILE_AMBIGUOUS,
            WALL_NOW + 1,
        )
        .await;

        let report = load_report(&db, Some(&key_b()), &QuarantineQuery::default())
            .await
            .expect("read");

        assert_eq!(report.total, 2, "the rows are still LISTED");
        assert_eq!(report.shown, 2);
        assert_eq!(report.decrypt_failures, 2);
        assert_eq!(report.status, ReportStatus::DecryptFailures);
        assert_eq!(report.exit_code, 2);
        assert_eq!(
            report.key_id,
            Some(key_b().key_id()),
            "the header must name the key that was actually used"
        );
        assert_ne!(
            key_a().key_id(),
            key_b().key_id(),
            "precondition: the two test keys must be distinguishable"
        );
        for row in &report.rows {
            assert!(
                matches!(row.details, DetailsState::Failed { .. }),
                "{row:?}"
            );
        }

        let text = render_text(&report);
        assert!(
            text.contains("2 of 2 rows could not be decrypted"),
            "{text}"
        );
    }

    // -----------------------------------------------------------------------
    // 7. A valid SQLite file that is not a Stream G database.
    // -----------------------------------------------------------------------

    /// Mutation proof: delete the `sqlite_master` preflight and swallow the
    /// `COUNT(*)` error with `.unwrap_or(0)` — this test goes red, because the
    /// reader then returns a successful zero-row report about a database that
    /// has never held a Stream G row.
    #[tokio::test]
    async fn a_valid_sqlite_file_that_is_not_a_stream_g_db_is_refused() {
        let dir = tempfile::tempdir().unwrap();

        // A real SQLite file with one unrelated table.
        let other = dir.path().join("something_else.sqlite");
        {
            let pool = SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(
                    SqliteConnectOptions::new()
                        .filename(&other)
                        .create_if_missing(true),
                )
                .await
                .expect("create an unrelated sqlite file");
            sqlx::query("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
                .execute(&pool)
                .await
                .expect("create table");
            pool.close().await;
        }
        let err = load_report(&other, Some(&key_a()), &QuarantineQuery::default())
            .await
            .expect_err("a non-Stream-G database must be an error, never Ok(0 rows)");
        let msg = err.to_string();
        assert!(
            msg.contains("store_meta"),
            "the refusal must name the missing table; got: {msg}"
        );
        assert!(
            msg.contains(&other.display().to_string()),
            "the refusal must name the file; got: {msg}"
        );

        // A file that is not SQLite at all.
        let junk = dir.path().join("junk.sqlite");
        std::fs::write(&junk, b"this is definitely not a database").unwrap();
        let err = load_report(&junk, Some(&key_a()), &QuarantineQuery::default())
            .await
            .expect_err("a junk file must be an error, never Ok(0 rows)");
        let msg = err.to_string();
        assert!(
            msg.contains("not a database"),
            "SQLite's own code-26 message must survive to the operator, not be flattened to \
             zero; got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // 8. Only quarantine event types are listed.
    // -----------------------------------------------------------------------

    /// Mutation proof: drop the `WHERE event_type = ?` clause, or relax it to
    /// `LIKE 'SponsoredEnrollmentExecuted%'`, and this test goes red with two
    /// rows — the second sealed by a different writer under a different body
    /// shape.
    #[tokio::test]
    async fn only_quarantine_event_types_are_listed() {
        let (_dir, store, db, _lock) = live_store().await;
        plant(
            &store,
            &key_a(),
            1_000,
            0x99,
            0,
            ERR_RECONCILE_UNVERIFIED_LOG,
            WALL_NOW,
        )
        .await;

        // The quarantine type is `RECONCILIATION_EVENT_TYPE` + ".quarantined",
        // so a prefix/LIKE predicate would swallow both.
        assert!(
            QUARANTINE_EVENT_TYPE.starts_with(RECONCILIATION_EVENT_TYPE),
            "precondition: without the superstring relationship this test proves nothing"
        );
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO reconciliation_events \
                         (id, tx_attempt_id, event_type, status, details_enc, created_at) \
                         VALUES ('not-a-quarantine-row', NULL, ?, 'OK', X'00', ?)",
                    )
                    .bind(RECONCILIATION_EVENT_TYPE)
                    .bind(WALL_NOW)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed a non-quarantine reconciliation event");

        let report = load_report(&db, Some(&key_a()), &QuarantineQuery::default())
            .await
            .expect("read");
        assert_eq!(report.total, 1, "{:#?}", report.rows);
        assert_eq!(report.shown, 1);
        assert_eq!(report.rows[0].event_type, QUARANTINE_EVENT_TYPE);
    }

    // -----------------------------------------------------------------------
    // 9. Truncation is stated, never silent.
    // -----------------------------------------------------------------------

    /// Mutation proof: report `rows.len()` as the total instead of running the
    /// separate `COUNT(*)` and this test goes red — `showing 2 of 2`,
    /// `truncated: false`, which an operator would read as "I have seen every
    /// dropped log".
    #[tokio::test]
    async fn limit_truncation_is_stated_not_silent() {
        let (_dir, store, db, _lock) = live_store().await;
        for (i, block) in [1_000u64, 1_001, 1_002].into_iter().enumerate() {
            plant(
                &store,
                &key_a(),
                block,
                0x90 + i as u8,
                i as u64,
                ERR_RECONCILE_UNVERIFIED_LOG,
                WALL_NOW + i as i64,
            )
            .await;
        }

        let query = QuarantineQuery {
            limit: 2,
            ..QuarantineQuery::default()
        };
        let report = load_report(&db, Some(&key_a()), &query)
            .await
            .expect("read");
        assert_eq!(report.shown, 2);
        assert_eq!(report.matched, 3);
        assert_eq!(report.total, 3);
        assert!(report.truncated);

        let text = render_text(&report);
        assert!(text.contains("showing 2 of 3"), "{text}");
        assert!(text.contains("TRUNCATED"), "{text}");

        let json: serde_json::Value = serde_json::from_str(&render_json(&report).unwrap()).unwrap();
        assert_eq!(json["shown"], 2);
        assert_eq!(json["total"], 3);
        assert_eq!(json["truncated"], true);
    }

    // -----------------------------------------------------------------------
    // 10. A code that can never be quarantined is flagged.
    // -----------------------------------------------------------------------

    /// Mutation proof: render `status` verbatim with no classification (i.e.
    /// [`classify_status`] always returning `Quarantinable`) and this test
    /// goes red — a row that proves the classifier is broken would render
    /// identically to a normal one.
    #[tokio::test]
    async fn a_code_that_can_never_be_quarantined_is_flagged() {
        let (_dir, store, db, _lock) = live_store().await;
        // Legitimate row.
        plant(
            &store,
            &key_a(),
            1_000,
            0x99,
            0,
            ERR_RECONCILE_UNVERIFIED_LOG,
            WALL_NOW,
        )
        .await;
        // A row carrying a code `scope()` can never route here.
        plant(
            &store,
            &key_a(),
            1_001,
            0xAB,
            7,
            ERR_RECONCILE_UNCORROBORATED_LOG,
            WALL_NOW + 1,
        )
        .await;

        let report = load_report(&db, Some(&key_a()), &QuarantineQuery::default())
            .await
            .expect("read");
        assert_eq!(report.shown, 2);
        assert_eq!(report.rows[0].status_class, StatusClass::Quarantinable);
        assert_eq!(
            report.rows[1].status_class,
            StatusClass::ImpossibleHere,
            "a transient-only code in a quarantine row means the classifier is broken and must \
             not render as an ordinary row"
        );
        let text = render_text(&report);
        assert!(text.contains("IMPOSSIBLE HERE"), "{text}");
        assert!(text.contains("ANOMALY"), "{text}");
    }

    // -----------------------------------------------------------------------
    // 11. The impossible-code set is derived from the real classifier.
    // -----------------------------------------------------------------------

    /// The classifier above is only trustworthy if its idea of "quarantinable"
    /// is the same as `ReconcileError::scope()`'s. Asserting that by
    /// construction — one `ReconcileError` per code, run through the real
    /// `scope()` — is what stops [`QUARANTINABLE_CODES`] drifting into a stale
    /// literal list that flags healthy rows or silences broken ones.
    ///
    /// Mutation proof: move `ERR_RECONCILE_UNCORROBORATED_LOG` from
    /// [`IMPOSSIBLE_CODES`] into [`QUARANTINABLE_CODES`] and this test goes
    /// red, because `scope()` answers `LogTransient` for it.
    #[test]
    fn the_quarantinable_code_set_matches_the_real_classifier() {
        use crate::stream_g::submit::SubmitError;

        // One representative error per `ERR_RECONCILE_*` code, so the pairing
        // of code → scope comes from production code, not from this list.
        let samples: Vec<ReconcileError> = vec![
            ReconcileError::ContradictedLog {
                reason: String::new(),
            },
            ReconcileError::AmbiguousCandidates {
                count: 2,
                tx_hash_hex: String::new(),
            },
            ReconcileError::Submit(SubmitError::IntentNotFound),
            ReconcileError::UncorroboratedLog {
                reason: String::new(),
            },
            ReconcileError::Sqlx(sqlx::Error::RowNotFound),
            ReconcileError::Chain(String::new()),
            ReconcileError::BadConfig {
                key: "STREAM_G_CONFIRMATIONS",
                value: String::new(),
                reason: "test",
            },
        ];

        for e in &samples {
            let code = e.code();
            let reachable = e.scope() == ReconcileErrorScope::LogPermanent;
            let class = classify_status(Some(code));
            if reachable {
                assert_eq!(
                    class,
                    StatusClass::Quarantinable,
                    "{code} CAN be quarantined (scope() = LogPermanent) but this module would \
                     flag it as an anomaly"
                );
            } else {
                assert_eq!(
                    class,
                    StatusClass::ImpossibleHere,
                    "{code} cannot be quarantined (scope() = {:?}) but this module would render \
                     it as an ordinary row",
                    e.scope()
                );
            }
        }

        assert_eq!(
            classify_status(Some("SOMETHING_A_LATER_BUILD_WROTE")),
            StatusClass::Unknown
        );
        assert_eq!(classify_status(None), StatusClass::Missing);
    }

    // -----------------------------------------------------------------------
    // 12. Filters narrow the listing without hiding the true total.
    // -----------------------------------------------------------------------

    /// Mutation proof: compute `total` with the filters applied (i.e. reuse
    /// `matched`) and this test goes red — `--since` that skips a row would
    /// then report a smaller table than exists, which is a filtered
    /// false-all-clear.
    #[tokio::test]
    async fn filters_narrow_the_listing_but_never_the_reported_total() {
        let (_dir, store, db, _lock) = live_store().await;
        let old = plant(
            &store,
            &key_a(),
            1_000,
            0x99,
            0,
            ERR_RECONCILE_UNVERIFIED_LOG,
            WALL_NOW,
        )
        .await;
        let new = plant(
            &store,
            &key_a(),
            1_001,
            0xAB,
            7,
            ERR_RECONCILE_AMBIGUOUS,
            WALL_NOW + 10_000,
        )
        .await;

        // --since
        let r = load_report(
            &db,
            Some(&key_a()),
            &QuarantineQuery {
                since: Some(WALL_NOW + 1),
                ..QuarantineQuery::default()
            },
        )
        .await
        .expect("read");
        assert_eq!(r.shown, 1);
        assert_eq!(r.matched, 1);
        assert_eq!(r.total, 2, "a filter must never shrink the reported total");
        assert_eq!(r.rows[0].id, new);

        // --error-code
        let r = load_report(
            &db,
            Some(&key_a()),
            &QuarantineQuery {
                error_code: Some(ERR_RECONCILE_UNVERIFIED_LOG.to_string()),
                ..QuarantineQuery::default()
            },
        )
        .await
        .expect("read");
        assert_eq!(r.shown, 1);
        assert_eq!(r.total, 2);
        assert_eq!(r.rows[0].id, old);

        // --id
        let r = load_report(
            &db,
            Some(&key_a()),
            &QuarantineQuery {
                id: Some(new.clone()),
                ..QuarantineQuery::default()
            },
        )
        .await
        .expect("read");
        assert_eq!(r.shown, 1);
        assert_eq!(r.total, 2);
        assert_eq!(r.rows[0].id, new);

        // A filter that matches nothing is still not an empty table.
        let r = load_report(
            &db,
            Some(&key_a()),
            &QuarantineQuery {
                error_code: Some("NO_SUCH_CODE".to_string()),
                ..QuarantineQuery::default()
            },
        )
        .await
        .expect("read");
        assert_eq!(r.shown, 0);
        assert_eq!(r.matched, 0);
        assert_eq!(
            r.total, 2,
            "0 matching rows must not read as 0 quarantined logs"
        );
    }

    // -----------------------------------------------------------------------
    // 13. Timestamps.
    // -----------------------------------------------------------------------

    /// Mutation proof: change the epoch offset in [`civil_from_days`] from
    /// `719_468` to `719_469` and this test goes red on every case.
    #[test]
    fn unix_seconds_render_as_utc_civil_time() {
        assert_eq!(format_unix_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_utc(1), "1970-01-01T00:00:01Z");
        // WALL_NOW, the value the rest of this module's tests plant.
        assert_eq!(format_unix_utc(1_800_000_000), "2027-01-15T08:00:00Z");
        // A leap day, so an off-by-one in the leap-year arithmetic shows up.
        assert_eq!(format_unix_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        // Before the epoch: the writer binds a wall clock, and a machine with
        // a broken clock is exactly the kind of thing this report is read
        // during. It must render, not panic.
        assert_eq!(format_unix_utc(-1), "1969-12-31T23:59:59Z");
    }

    // -----------------------------------------------------------------------
    // 14. SQLite URIs are refused.
    // -----------------------------------------------------------------------

    /// sqlx sets `SQLITE_OPEN_URI` unconditionally, so `immutable=1` in a
    /// `--db` value would be honoured — and against a live database that
    /// serves a stale view instead of an error.
    ///
    /// Mutation proof: delete the [`reject_uri`] call from
    /// [`open_read_only`] and this test goes red (`expect_err` panics, because
    /// the open then either succeeds or fails with a different error).
    #[tokio::test]
    async fn sqlite_uri_paths_are_refused() {
        for candidate in [
            "file:stream_g.sqlite?immutable=1",
            "file:/tmp/stream_g.sqlite",
            "stream_g.sqlite?vfs=unix-none",
        ] {
            let err = open_read_only(Path::new(candidate))
                .await
                .expect_err("a SQLite URI must be refused");
            assert!(
                matches!(err, QuarantineReportError::UriPath { .. }),
                "{candidate} produced {err:?}"
            );
            assert!(
                err.to_string().contains("filesystem path"),
                "the refusal must explain itself: {err}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // 15. The empty table is a legitimate, clean zero.
    // -----------------------------------------------------------------------

    /// The counterpart to every test above: when the database really is a
    /// Stream G database and really has no quarantine rows, that must be a
    /// clean exit 0 — otherwise the non-zero codes carry no information.
    #[tokio::test]
    async fn a_real_stream_g_database_with_no_quarantine_rows_is_a_clean_zero() {
        // `store` stays bound for the whole body: the writer is running, as it
        // is in production when an operator runs this.
        let (_dir, _store, db, _lock) = live_store().await;

        let report = load_report(&db, Some(&key_a()), &QuarantineQuery::default())
            .await
            .expect("read");
        assert_eq!(report.total, 0);
        assert_eq!(report.shown, 0);
        assert!(!report.truncated);
        assert_eq!(report.status, ReportStatus::Complete);
        assert_eq!(report.exit_code, 0);
        assert!(
            !report.db_uuid.is_empty(),
            "the header must identify the file"
        );
        assert_eq!(
            report.build_supported_schema_version, report.store_meta_schema_version,
            "a freshly migrated file is at this build's version"
        );
        assert!(!report.schema_version_newer_than_build);

        let text = render_text(&report);
        assert!(text.contains("showing 0 of 0"), "{text}");
        assert!(
            text.contains(&report.db_uuid),
            "a zero must name the file it is a zero about:\n{text}"
        );
    }

    // -----------------------------------------------------------------------
    // 16. The cleartext status column is compared against the sealed one.
    // -----------------------------------------------------------------------

    /// `reconciliation_events.status` is plaintext and unauthenticated;
    /// `QuarantineDetails.error_code` is inside the AEAD envelope. If they
    /// disagree the plaintext was edited out of band, and that is the only
    /// tamper signal available on the unsealed tier.
    ///
    /// Mutation proof: drop the `status_mismatch` computation (always `None`)
    /// and this test goes red — an edited status column renders as an ordinary
    /// row.
    #[tokio::test]
    async fn an_edited_status_column_is_flagged_against_the_sealed_error_code() {
        let (_dir, store, db, _lock) = live_store().await;
        let id = plant(
            &store,
            &key_a(),
            1_000,
            0x99,
            0,
            ERR_RECONCILE_UNVERIFIED_LOG,
            WALL_NOW,
        )
        .await;

        let target = id.clone();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query("UPDATE reconciliation_events SET status = ? WHERE id = ?")
                        .bind(ERR_RECONCILE_AMBIGUOUS)
                        .bind(&target)
                        .execute(&mut **tx)
                        .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("edit the plaintext status column");

        let report = load_report(&db, Some(&key_a()), &QuarantineQuery::default())
            .await
            .expect("read");
        assert_eq!(report.shown, 1);
        let row = &report.rows[0];
        assert!(
            row.status_mismatch.is_some(),
            "an edited plaintext status must be flagged against the authenticated body: {row:?}"
        );
        assert!(render_text(&report).contains("TAMPER SIGNAL"));
    }

    // -----------------------------------------------------------------------
    // 17. A newer-schema database is never a clean run — in JSON as well as
    //     text.
    // -----------------------------------------------------------------------

    /// The demonstrated false all-clear this variant exists for: a database
    /// migrated by a newer build that also renamed the quarantine
    /// `event_type`. This build then matches zero rows while a real quarantine
    /// row sits in the table, and the earlier code reported
    /// `"total": 0, "status": "complete", "exit_code": 0`. The text-mode
    /// warning banner did print — but `--format json | jq '.status'`, the
    /// exact usage `main.rs` names as the reason non-zero exits exist, saw
    /// `complete`.
    ///
    /// Mutation proof: delete the `schema_version_newer_than_build` arm from
    /// the `let status = ...` chain in [`load_report`] and this test goes red
    /// on `status`, on `exit_code`, on the JSON `status`/`exit_code`, and on
    /// the text footer — five independent assertions, because the JSON
    /// contract is the one that was silently healthy.
    #[tokio::test]
    async fn a_newer_schema_version_is_never_reported_as_a_clean_run() {
        let (_dir, store, db, _lock) = live_store().await;
        plant(
            &store,
            &key_a(),
            1_000,
            0x99,
            0,
            ERR_RECONCILE_UNVERIFIED_LOG,
            WALL_NOW,
        )
        .await;

        // Simulate a future build: it migrated past this one AND renamed the
        // quarantine event type, so this build's `WHERE event_type = ?` finds
        // nothing. Both halves matter — the rename is what turns "newer" into
        // a wrong answer rather than a cosmetic difference.
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query("UPDATE store_meta SET schema_version = 99")
                        .execute(&mut **tx)
                        .await?;
                    sqlx::query(
                        "UPDATE reconciliation_events SET event_type = \
                         'SponsoredEnrollmentExecuted.quarantined.v2'",
                    )
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("simulate a newer build");

        assert!(
            supported_schema_version() < 99,
            "THIS TEST HAS GONE VACUOUS: this build now supports schema {} >= 99, so the file \
             below is no longer 'newer'. Raise the planted version.",
            supported_schema_version()
        );

        let report = load_report(&db, Some(&key_a()), &QuarantineQuery::default())
            .await
            .expect("a newer schema is read, not refused");

        // The setup really is the false-all-clear shape: zero visible rows.
        assert!(report.schema_version_newer_than_build);
        assert_eq!(report.store_meta_schema_version, 99);
        assert_eq!(
            report.total, 0,
            "precondition: this build must be BLIND to the renamed row, else the test proves \
             nothing about false all-clears"
        );
        assert_eq!(report.shown, 0);

        // …and it must still not read as healthy.
        assert_eq!(
            report.status,
            ReportStatus::SchemaNewerThanBuild,
            "a zero from a database this build may not be able to read fully is not `complete`"
        );
        assert_eq!(
            report.exit_code, 4,
            "a possibly-incomplete listing must not exit 0"
        );

        // The machine-readable contract is the one that was broken.
        let json: serde_json::Value = serde_json::from_str(&render_json(&report).unwrap()).unwrap();
        assert_eq!(
            json["status"], "schema_newer_than_build",
            "`--format json | jq '.status'` is the documented incident-script usage; it must \
             not say `complete` here"
        );
        assert_eq!(json["exit_code"], 4);
        assert_eq!(json["total"], 0);
        assert_eq!(json["schema_version_newer_than_build"], true);

        // And the human form ends with a verdict rather than trailing off.
        let text = render_text(&report);
        assert!(text.contains("MAY BE INCOMPLETE"), "{text}");
        assert!(text.contains("Exit code 4"), "{text}");
    }

    /// The counterpart, so the variant above cannot be a blanket. Reuses the
    /// same planted row WITHOUT bumping the schema: identical data, exit 0.
    #[tokio::test]
    async fn a_current_schema_version_still_exits_zero() {
        let (_dir, store, db, _lock) = live_store().await;
        plant(
            &store,
            &key_a(),
            1_000,
            0x99,
            0,
            ERR_RECONCILE_UNVERIFIED_LOG,
            WALL_NOW,
        )
        .await;

        let report = load_report(&db, Some(&key_a()), &QuarantineQuery::default())
            .await
            .expect("read");
        assert!(!report.schema_version_newer_than_build);
        assert_eq!(report.status, ReportStatus::Complete);
        assert_eq!(report.exit_code, 0);
    }

    // -----------------------------------------------------------------------
    // 18. The stale-forensic-copy warning can actually fire.
    // -----------------------------------------------------------------------

    /// The `⚠ no -wal sidecar` warning was unreachable: [`load_report`] used to
    /// measure the sidecars at report-construction time, i.e. *after*
    /// `open_read_only` had already created a zero-byte `-wal`. Every real
    /// WAL-mode database therefore reported `db_wal_bytes: Some(0)` and the
    /// warning never printed — while the rows that lived only in the
    /// left-behind `-wal`, the most recent ones, were silently absent.
    ///
    /// Mutation proof: move the two `sidecar_len` calls from step 0 of
    /// [`load_report`] back down into the `QuarantineReport { .. }` literal and
    /// this test goes red on `db_wal_bytes` (`Some(0)`, not `None`) and on the
    /// missing warning line.
    #[tokio::test]
    async fn a_forensic_copy_without_its_wal_is_warned_about() {
        let (dir, store, db, lock) = live_store().await;

        // Five rows, then close the store so SQLite checkpoints and removes
        // the -wal. These five are inside the .db file itself.
        for i in 0..5u64 {
            plant(
                &store,
                &key_a(),
                100 + i,
                0x90 + i as u8,
                i,
                ERR_RECONCILE_UNVERIFIED_LOG,
                WALL_NOW + i as i64,
            )
            .await;
        }
        drop(store);

        // Three more, left hot in the -wal.
        let store = StreamGStore::open(&db, &lock).await.expect("reopen");
        for i in 5..8u64 {
            plant(
                &store,
                &key_a(),
                100 + i,
                0x90 + i as u8,
                i,
                ERR_RECONCILE_UNVERIFIED_LOG,
                WALL_NOW + i as i64,
            )
            .await;
        }

        let src_wal = sidecar_len(&db, "-wal");
        assert!(
            src_wal.is_some_and(|n| n > 0),
            "precondition: the live database must have a non-empty -wal, else this test cannot \
             model a truncated copy; got {src_wal:?}"
        );

        // The documented mistake: copy the .db alone off a running machine.
        let copy_dir = dir.path().join("evidence");
        std::fs::create_dir_all(&copy_dir).unwrap();
        let copy = copy_dir.join("stream_g.sqlite");
        std::fs::copy(&db, &copy).expect("copy the .db alone");
        assert!(
            sidecar_len(&copy, "-wal").is_none(),
            "precondition: the copy must start with no -wal"
        );

        let report = load_report(&copy, Some(&key_a()), &QuarantineQuery::default())
            .await
            .expect("read the copy");

        // The copy really is short — this is why the warning is load-bearing
        // rather than cosmetic.
        assert_eq!(
            report.total, 5,
            "precondition: the copy must be missing the rows that lived in the -wal, else the \
             warning would be warning about nothing"
        );
        let live = load_report(&db, Some(&key_a()), &QuarantineQuery::default())
            .await
            .expect("read the live database");
        assert_eq!(live.total, 8, "the original still holds all eight rows");

        assert_eq!(
            report.db_wal_bytes, None,
            "the -wal must be measured BEFORE the open that creates one"
        );
        let text = render_text(&report);
        assert!(
            text.contains("⚠ no -wal sidecar"),
            "a truncated forensic copy must say so on the first screen:\n{text}"
        );

        // And prove the trap is real: the read just performed HAS created a
        // -wal, so a measurement taken afterwards would have found `Some(_)`
        // and suppressed the warning. (Observed: the pre-fix code reported
        // `db_wal_bytes: Some(0)` here.)
        assert!(
            sidecar_len(&copy, "-wal").is_some(),
            "if reading no longer creates a -wal this test has gone vacuous — the ordering it \
             pins would no longer matter"
        );
    }

    // -----------------------------------------------------------------------
    // 19. A write-denied directory is not blamed on the file.
    // -----------------------------------------------------------------------

    /// `SQLITE_CANTOPEN` used to surface as the bare `Query` variant —
    /// "unable to open database file" — about a file that exists and is
    /// perfectly readable. An operator reads that as "wrong path / corrupt
    /// file" and chases the wrong thing during an incident. The real cause is
    /// that opening a WAL-mode database, even read-only, must CREATE `<db>-shm`
    /// in the directory beside it.
    ///
    /// Modelled here without ACLs by putting a **directory** where the `-shm`
    /// file has to go.
    ///
    /// **Corrected 2026-07-30 — this doc used to end "which is the same refusal
    /// from SQLite's point of view and is deterministic on every platform", and
    /// the first CI run on ubuntu-latest refuted it.** The behaviour is
    /// deterministic *per platform* and the platforms disagree:
    ///
    /// * **Windows VFS**: the open touches the `-shm` eagerly and fails
    ///   `SQLITE_CANTOPEN` — the behaviour this test was written against, on the
    ///   machine it was written on.
    /// * **unix VFS**: a read-only open of a WAL database whose `-wal` is
    ///   absent (checkpointed away when the store shut down) never needs the
    ///   WAL-index, so the blocked `-shm` name is simply never opened and the
    ///   report **succeeds** — run 30512647063 reported `status: Complete,
    ///   total: 1`, the row decrypted, and `db_shm_bytes: Some(4096)`, the
    ///   sidecar probe measuring the planted *directory's* metadata length.
    ///
    /// Both branches below pin their platform's measured behaviour, so the test
    /// is vacuous on neither and a bundled-SQLite version bump that changes
    /// either VFS's behaviour turns it red instead of passing silently
    /// (`libsqlite3-sys` is bundled, so both platforms compile the same SQLite).
    ///
    /// **The unix branch was written from the CI dump above, could not be run on
    /// the dev machine (no Linux, no container runtime), and is now VERIFIED**:
    /// the first Actions run carrying it reported `781 passed; 5 failed`, up from
    /// `780 passed; 6 failed`, with this test absent from the failure list and the
    /// remaining five being the accepted published-checkout audit tests. So the
    /// premise — that a read-only open with no `-wal` present never touches the
    /// WAL-index on unix — held in practice and not merely in the error dump it
    /// was inferred from.
    ///
    /// Mutation proof (Windows): delete the `SQLITE_CANTOPEN` branch from
    /// [`map_sqlx_error`] and this test goes red — the error becomes
    /// `Query`/`Open` again and carries none of the four explanatory strings
    /// asserted below. On unix that mapping is unreachable from this scenario,
    /// so the mutation coverage is Windows-only; the gate runs on Windows.
    #[tokio::test]
    async fn cantopen_on_a_readable_file_blames_the_directory_not_the_file() {
        let (dir, store, db, _lock) = live_store().await;
        plant(
            &store,
            &key_a(),
            1_000,
            0x99,
            0,
            ERR_RECONCILE_UNVERIFIED_LOG,
            WALL_NOW,
        )
        .await;
        drop(store);

        // Baseline: these exact bytes read cleanly. Without this control the
        // test could pass because the database is broken rather than because
        // the directory refuses the sidecar.
        let ok = load_report(&db, Some(&key_a()), &QuarantineQuery::default())
            .await
            .expect("baseline read");
        assert_eq!(ok.total, 1);

        // The same bytes, in a directory where `<db>-shm` cannot be created.
        let blocked_dir = dir.path().join("blocked");
        std::fs::create_dir_all(&blocked_dir).unwrap();
        let blocked = blocked_dir.join("stream_g.sqlite");
        std::fs::copy(&db, &blocked).expect("copy the database");
        let mut shm = blocked.as_os_str().to_os_string();
        shm.push("-shm");
        std::fs::create_dir(PathBuf::from(shm)).expect("occupy the -shm name with a directory");

        assert!(
            std::fs::File::open(&blocked).is_ok(),
            "precondition: the database file itself must be readable, else this error would \
             legitimately be about the file"
        );

        let outcome = load_report(&blocked, Some(&key_a()), &QuarantineQuery::default()).await;

        // Windows VFS: the -shm is touched eagerly, so this MUST fail, and the
        // failure must blame the directory rather than the file. Measured here.
        #[cfg(windows)]
        {
            let err = outcome.expect_err("SQLite cannot open the -shm, so this must fail");
            assert!(
                matches!(err, QuarantineReportError::CannotOpenSidecars { .. }),
                "a CANTOPEN about a readable file must not surface as a bare Open/Query: {err:?}"
            );
            let msg = err.to_string();
            for needle in [
                "exists and is readable",
                "DIRECTORY",
                "-shm",
                "Remedy:",
                "immutable=1",
            ] {
                assert!(
                    msg.contains(needle),
                    "the error must explain the real cause and the remedy; missing {needle:?} in:\n\
                     {msg}"
                );
            }
            assert!(
                msg.contains(&blocked.display().to_string()),
                "and it must still name the path: {msg}"
            );
        }

        // unix VFS: a read-only open with no -wal present never opens the
        // WAL-index, so the blocked -shm name is never even touched and the
        // report MUST succeed — pinned from CI run 30512647063 (2026-07-30),
        // whose dump showed `status: Complete, total: 1` with the row
        // decrypted. If a bundled-SQLite bump makes unix touch the -shm here,
        // this branch goes red and the change is reviewed instead of slipping
        // through as a silently-different error surface.
        #[cfg(unix)]
        {
            let ok = outcome.expect(
                "unix reads a checkpointed WAL database read-only without its -shm; a failure \
                 here means the bundled SQLite's unix VFS changed behaviour",
            );
            assert_eq!(ok.total, 1, "the same single planted row must be visible");
            assert_eq!(ok.decrypt_failures, 0, "and it must decrypt");
        }
    }
}
