//! WAL-mode SQLite store for Stream G, gated by an OS-level instance lock.
//!
//! [`StreamGStore::open`] is the only supported way to get at the Stream G
//! database: it takes an exclusive `fs2` lock on a dedicated lock file
//! before touching SQLite at all, so two `goat-attestor` processes can
//! never open the same store concurrently. It then opens a single
//! connection (`SqlitePoolOptions::max_connections(1)`) with a fixed
//! `journal_mode=WAL / foreign_keys=ON / synchronous=FULL /
//! busy_timeout=5000` pragma set, and applies the embedded schema
//! migration (`migrations/0001_stream_g.sql`) exactly once — idempotent
//! across repeated `open` calls against the same file.
//!
//! All later Stream G write paths must go through [`StreamGStore::write_tx`],
//! which starts every write transaction with `BEGIN IMMEDIATE` instead of
//! sqlx's default deferred `BEGIN`: that reserves SQLite's writer lock the
//! instant the transaction opens, so a write never discovers a conflicting
//! writer partway through. Combined with the single-connection pool this
//! makes the whole process a serialized single writer even though sqlx's
//! pool API is nominally concurrent. Read paths that don't need a
//! transaction go through [`StreamGStore::read`] instead of a raw pool
//! accessor (there isn't one, on purpose): the closure only ever sees an
//! opaque [`ReadHandle`], which exposes read entry points and nothing
//! that can write or open a transaction.
//!
//! Only runtime queries (`sqlx::query`, `sqlx::query_scalar`) are used
//! anywhere in this module — never the compile-time `sqlx::query!` family,
//! since this crate has no `DATABASE_URL` at build time.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use rand::RngCore;
use sqlx::sqlite::{
    SqliteConnectOptions, SqlitePool, SqlitePoolOptions, SqliteRow, SqliteTransaction,
};
use sqlx::{Executor, FromRow, IntoArguments};
use thiserror::Error;

use super::crypto_store::EnvelopeAad;

/// One embedded schema migration.
///
/// Migrations are `include_str!`-ed at compile time so the binary never
/// depends on the migration files being present on disk at runtime.
struct Migration {
    /// Recorded in `schema_migrations.version` and mirrored into
    /// `store_meta.schema_version` once applied.
    version: i64,
    description: &'static str,
    sql: &'static str,
}

/// Every migration this build knows about, in **ascending version order**.
/// `apply_pending_migrations` walks this list and applies each entry whose
/// `version` exceeds the version recorded in `store_meta`, one
/// `BEGIN IMMEDIATE` transaction per entry.
///
/// **Applied migrations are frozen.** Editing the SQL of a version that has
/// already shipped would silently give two databases the same recorded
/// version and different schemas; `every_migration_is_byte_identical` turns
/// that into a test failure for **every** entry in this list, not just `0001`
/// (it was `migration_0001_is_byte_identical`, covering `0001` alone, which is
/// how `0003` shipped unfrozen). It also asserts
/// `MIGRATIONS.len() == MIGRATION_SHA256.len()`, so adding a migration without
/// adding its hash is a red test rather than an unfrozen file. New work is a
/// new file.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        description: "initial Stream G schema (profiles/quotes/intents/authorizations/tx pipeline)",
        sql: include_str!("../../migrations/0001_stream_g.sql"),
    },
    Migration {
        version: 2,
        description: "Stream G outbox (tx_attempts claim/lease/raw_tx_hash/intent_id_hex, \
                      nonce_allocations kind discriminator)",
        sql: include_str!("../../migrations/0002_stream_g_outbox.sql"),
    },
    Migration {
        version: 3,
        description: "Stream G reconciliation scan cursor (stream_g_scan_cursors)",
        sql: include_str!("../../migrations/0003_stream_g_scan_cursor.sql"),
    },
];

/// SHA-256 of every file in [`MIGRATIONS`], by version, pinned so an edit to a
/// migration that has already been applied somewhere fails a test instead of
/// silently forking the schema of every database that already recorded that
/// version. See `every_migration_is_byte_identical`.
///
/// Every entry, not just `0001`: the hazard is a property of "some database out
/// there already recorded version N and will therefore never re-run N", which
/// is true of `0002` and `0003` the moment either is applied once. Freezing
/// only the oldest migration protects the one file least likely to be edited.
///
/// A deliberate change to a migration means a NEW numbered file, never a new
/// hash here. This table changes only when a migration is ADDED, and the added
/// row is the new file's hash.
#[cfg(test)]
const MIGRATION_SHA256: &[(i64, &str)] = &[
    (
        1,
        "b4cc6a3dd60de02bf75d57f1528d13cf61b489f182b4b8dab788f8d82edf607b",
    ),
    (
        2,
        "d4f3ef94cb3c60f8972717c73cfa24aabea18fcffe6c2f87947083c9797a2bac",
    ),
    (
        3,
        "c9797c54380685434fe649bf083552ae49a9ff17dc6a51169f64b8420cc4668e",
    ),
];

/// Highest migration version this build can apply — i.e. the version it
/// writes into `store_meta.schema_version` once every pending migration has
/// run. Bump alongside a new entry in [`MIGRATIONS`].
///
/// ⚠️ **Bumping this is forward-only and operationally visible.**
/// `readiness::check_schema_version` fails closed in BOTH directions: a
/// database this build has not migrated yet reports 503, and a database this
/// build migrated then reopened with an OLDER binary is refused outright by
/// [`StreamGStoreError::SchemaVersionTooNew`]. There is no down migration.
/// `2 → 3` (the reconciliation scan cursor) was taken deliberately, because the
/// alternative — a background log observer with no durable cursor — rescans
/// from the gateway deploy block on every pass.
///
/// This does **not** touch [`ENVELOPE_AAD_SCHEMA_VERSION`], which stays pinned
/// at 1. See that constant: coupling the two would make every `_enc` column
/// sealed before the upgrade permanently undecryptable.
const SCHEMA_VERSION: i64 = 3;

/// Version stamped into every [`EnvelopeAad`] this store hands out.
///
/// **Deliberately pinned, and deliberately NOT [`SCHEMA_VERSION`].** The AAD
/// is authenticated, not stored: it is recomputed at `open` time and must
/// reproduce byte-for-byte what `seal` used, or XChaCha20-Poly1305 rejects
/// the envelope. Feeding the *live* schema version into it would mean that
/// the moment a migration bumps `store_meta.schema_version`, every `_enc`
/// column sealed before the upgrade — `profile_enc`, `alias_enc`,
/// `context_enc`, `quote_enc`, `intent_enc`, `signature_enc`, `raw_tx_enc`,
/// `details_enc` — fails to decrypt for the rest of that database's life.
/// An in-place upgrade would look successful and quietly destroy every
/// sealed payload in the file.
///
/// The envelope stays pinned to whatever it can actually be re-derived from.
/// The rest of the AAD (`db_uuid|table|pk|column|key_id`) still binds an
/// envelope to one row, one column, one database file and one key, which is
/// what the AAD exists for; the schema version never contributed to that
/// binding, because a database's schema version is not a property an
/// individual envelope can be moved between.
///
/// This constant may only change together with a documented re-seal
/// migration that rewrites every `_enc` column under the new AAD.
pub const ENVELOPE_AAD_SCHEMA_VERSION: u32 = 1;

/// Applied in this exact order on every new pooled connection — see module
/// docs for why each pragma is here.
const PRAGMA_SQL: &str = "PRAGMA journal_mode=WAL; \
     PRAGMA foreign_keys=ON; \
     PRAGMA synchronous=FULL; \
     PRAGMA busy_timeout=5000;";

/// The integer SQLite reports for `PRAGMA synchronous=FULL`. (`0`=OFF,
/// `1`=NORMAL, `2`=FULL, `3`=EXTRA.)
const SYNCHRONOUS_FULL: i64 = 2;

/// Upper bound accepted by [`StreamGStore::verify_pragmas`] for
/// `busy_timeout`. [`PRAGMA_SQL`] sets 5s; anything above a minute is
/// treated as unbounded-in-practice and refused, because a busy timeout that
/// long turns "another writer is stuck" into "this request hangs" instead of
/// into an error the caller can act on.
const MAX_BUSY_TIMEOUT_MS: i64 = 60_000;

#[derive(Debug, Error)]
pub enum StreamGStoreError {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Returned by `open` when another process (or another still-live
    /// `StreamGStore`) already holds the instance lock. Display
    /// deliberately contains the phrase "instance lock" — depended on by
    /// callers that want to distinguish this from other IO failures.
    #[error("failed to acquire Stream G instance lock at {path}: {source}")]
    InstanceLock {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// `open` refuses to run when `db_path` and `lock_path` point at the
    /// same file. This is a footgun guard, not a real same-file
    /// invariant: the comparison is a lexical `Path` equality check, so
    /// `state/g.db` vs `./state/g.db`, Windows case differences, and
    /// symlink/hardlink pairs that resolve to the same inode all slip
    /// past it undetected. It only catches the literal-same-string case,
    /// which is the mistake this is meant to prevent: the lock file is
    /// never meant to be the database file, and letting them collide
    /// would mean `acquire_instance_lock`'s `OpenOptions`
    /// (`create + write + no truncate`) is opened against the actual
    /// SQLite file before SQLite ever gets to it.
    #[error("db_path and lock_path must not be the same file: {path}")]
    SamePath { path: PathBuf },

    /// Returned by `open` when the database on disk was migrated by a
    /// *newer* build than this one — `store_meta.schema_version` exceeds
    /// this build's [`SCHEMA_VERSION`]. Opening it anyway would let an
    /// older build silently misinterpret tables/columns a later migration
    /// added.
    #[error(
        "stored schema_version {stored} is newer than this build supports (max {supported}); \
         refusing to open with an older build"
    )]
    SchemaVersionTooNew { stored: i64, supported: i64 },

    /// `store_meta.schema_version` is trusted to hold a small
    /// non-negative version number; this only fires if that invariant was
    /// violated out-of-band (e.g. a hand-edited row).
    #[error("stored schema_version {0} does not fit in a u32")]
    SchemaVersionOutOfRange(i64),

    /// Returned by [`StreamGStore::verify_pragmas`] when SQLite reports a
    /// different value than [`PRAGMA_SQL`] asked for — e.g. `journal_mode`
    /// stuck at `delete` because the database lives on a filesystem that
    /// cannot do WAL. Startup refuses rather than running Stream G's
    /// single-writer discipline on a store that isn't actually configured
    /// for it.
    #[error("pragma {pragma}: expected {expected}, SQLite reports {actual}")]
    PragmaMismatch {
        pragma: &'static str,
        expected: String,
        actual: String,
    },
}

/// The four pragmas [`PRAGMA_SQL`] sets, read back off the live connection by
/// [`StreamGStore::read_pragmas`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PragmaSnapshot {
    /// Expected `"wal"` (SQLite reports it lowercase).
    pub journal_mode: String,
    /// Expected `1`.
    pub foreign_keys: i64,
    /// Expected [`SYNCHRONOUS_FULL`].
    pub synchronous: i64,
    /// Expected `1..=`[`MAX_BUSY_TIMEOUT_MS`].
    pub busy_timeout_ms: i64,
}

/// Highest migration version this build can apply — the value
/// [`StreamGStore::schema_version`] must equal after a successful `open`.
///
/// A function over the private [`SCHEMA_VERSION`] rather than a second public
/// constant, so the two cannot drift apart.
pub const fn supported_schema_version() -> i64 {
    SCHEMA_VERSION
}

/// The `store_meta` singleton, read live off the file rather than from the
/// values [`StreamGStore::open`] cached at startup. Readiness compares the two
/// (see `readiness::check_store_reachable`): they diverge when the database
/// file underneath a running process has been swapped — a restore from a
/// different database, or a second writer that migrated it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMeta {
    pub db_uuid: String,
    pub schema_version: i64,
}

/// Result of [`instance_lock_probe`] — whether a **fresh** file handle can
/// take the exclusive lock at a lock path.
///
/// The polarity is deliberately inverted from what reads naturally: a probe
/// that *succeeds* in locking is the bad outcome, because it proves nobody
/// (including this process's own [`StreamGStore`]) is holding the lock any
/// more. See [`instance_lock_probe`] for the platform detail that makes this
/// work inside a single process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceLockProbe {
    /// The lock could **not** be taken — some handle holds it. In a process
    /// whose `StreamGStore` is alive, that handle is ours.
    HeldBySomeone,
    /// The lock was free and this probe took it (and immediately released it).
    /// For a live Stream G process this means the instance lock has been lost:
    /// the lock file was deleted and recreated, or the store handle is gone.
    Free,
}

/// Ask whether *anything* currently holds the exclusive lock at `lock_path`.
///
/// This is the readiness half of the spec §9.3 requirement that startup
/// "acquire an OS-level exclusive lock … and fail readiness if another owner
/// holds it". Startup already refuses to run without the lock
/// (`runtime::StreamGState::start`); this re-asks the question per readiness
/// probe, because a lock taken at startup is not evidence that it is still
/// held minutes later.
///
/// **Why a same-process probe is meaningful.** `fs2` uses `flock` on unix and
/// `LockFileEx` on Windows; both associate the lock with the *open file
/// description* / *handle*, not with the process, so a second `open` +
/// `try_lock_exclusive` inside the same process conflicts with the first. That
/// is not a theoretical claim here — `runtime::tests::
/// start_holds_the_os_instance_lock_for_the_life_of_the_state` already proves
/// a second `StreamGStore::open` in this process is refused.
///
/// **What it does not prove.** It cannot tell *whose* handle holds the lock:
/// [`InstanceLockProbe::HeldBySomeone`] from inside a live Stream G process is
/// strong evidence that it is ours (a second Stream G process could not have
/// started against the same path — its own `open` would have been refused),
/// but a hostile or unrelated process holding the file would look identical.
/// The check is a liveness guard against losing the lock, not an ownership
/// proof.
///
/// The probe opens with `create(true)` deliberately: a *missing* lock file is
/// itself a failure (whatever our handle holds no longer guards this path), and
/// recreating it makes that show up as [`InstanceLockProbe::Free`] rather than
/// as an unrelated IO error.
pub fn instance_lock_probe(lock_path: &Path) -> Result<InstanceLockProbe, StreamGStoreError> {
    ensure_parent_dir(lock_path)?;

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|source| StreamGStoreError::Io {
            path: lock_path.to_path_buf(),
            source,
        })?;

    match file.try_lock_exclusive() {
        // We took it, so nobody was holding it. Release immediately — holding
        // a second lock on our own lock file would be its own hazard — and
        // report the failure to the caller.
        Ok(()) => {
            let _ = fs2::FileExt::unlock(&file);
            drop(file);
            Ok(InstanceLockProbe::Free)
        }
        Err(_) => {
            drop(file);
            Ok(InstanceLockProbe::HeldBySomeone)
        }
    }
}

/// How one sealed column stores its [`super::crypto_store::seal`] envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedEncoding {
    /// A `BLOB` column holding the envelope bytes directly.
    Blob,
    /// A `TEXT` column holding `hex::encode(envelope)` — `auth_challenges.nonce`
    /// is declared `TEXT NOT NULL` by migration `0001`, so `profile_auth`
    /// hex-encodes the envelope into it.
    HexText,
}

/// One `(table, column)` pair whose contents are `crypto_store` envelopes.
///
/// `pk` is always `"id"`: every table in `0001_stream_g.sql` that carries a
/// sealed column declares `id TEXT PRIMARY KEY`, and every AAD call site
/// (`store.envelope_aad(table, id, column)`) passes that id. Readiness rebuilds
/// the AAD from these three fields, so an entry that names the wrong pk column
/// would fail to decrypt a perfectly good row — which is why this list is a
/// const in the store module next to the schema rather than a literal inside
/// the readiness handler.
#[derive(Debug, Clone, Copy)]
pub struct SealedColumn {
    pub table: &'static str,
    pub pk: &'static str,
    pub column: &'static str,
    pub encoding: SealedEncoding,
}

/// Every sealed column in the schema, in migration order.
///
/// Kept exhaustive by `sealed_columns_cover_every_enc_column_in_the_schema`,
/// which parses `0001_stream_g.sql` rather than trusting this list.
pub const SEALED_COLUMNS: &[SealedColumn] = &[
    SealedColumn {
        table: "profiles",
        pk: "id",
        column: "profile_enc",
        encoding: SealedEncoding::Blob,
    },
    SealedColumn {
        table: "credential_aliases",
        pk: "id",
        column: "alias_enc",
        encoding: SealedEncoding::Blob,
    },
    SealedColumn {
        table: "auth_challenges",
        pk: "id",
        column: "nonce",
        encoding: SealedEncoding::HexText,
    },
    SealedColumn {
        table: "profile_sessions",
        pk: "id",
        column: "context_enc",
        encoding: SealedEncoding::Blob,
    },
    SealedColumn {
        table: "quotes",
        pk: "id",
        column: "quote_enc",
        encoding: SealedEncoding::Blob,
    },
    SealedColumn {
        table: "intents",
        pk: "id",
        column: "intent_enc",
        encoding: SealedEncoding::Blob,
    },
    SealedColumn {
        table: "authorizations",
        pk: "id",
        column: "signature_enc",
        encoding: SealedEncoding::Blob,
    },
    SealedColumn {
        table: "tx_attempts",
        pk: "id",
        column: "raw_tx_enc",
        encoding: SealedEncoding::Blob,
    },
    SealedColumn {
        table: "reconciliation_events",
        pk: "id",
        column: "details_enc",
        encoding: SealedEncoding::Blob,
    },
];

/// A future boxed by hand — this crate does not depend on the `futures`
/// crate directly, so `write_tx`/`read` name their own boxed-future
/// aliases instead of `futures::future::BoxFuture`. Callers pass
/// `Box::pin(async move { .. })`, the same shape sqlx itself uses for
/// `after_connect` (see `open`).
///
/// `+ Send` is required: axum handlers and `tokio::spawn` both require the
/// futures they poll to be `Send`, and `write_tx` is the mandated single
/// write path every Stream G handler goes through — a non-`Send` future
/// here would make it impossible to call from any real handler.
type WriteTxFuture<'t, T, E> = Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send + 't>>;

/// Same shape as [`WriteTxFuture`] but over a [`ReadHandle`] instead of a
/// `&mut SqliteTransaction` — see [`StreamGStore::read`].
type ReadFuture<'p, T, E> = Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send + 'p>>;

/// Opaque handle to [`StreamGStore`]'s pool, handed to [`StreamGStore::read`]
/// closures in place of a raw `&SqlitePool`.
///
/// This type deliberately has no public field, `pool()` accessor, or
/// `Deref` to the wrapped pool. It exposes only read entry points
/// (`fetch_one`/`fetch_optional`/`fetch_all`/`fetch_scalar`), each
/// delegating straight to the wrapped pool — there is no `execute` and no
/// `begin`, so a `read` closure cannot run a write statement or open a
/// (deferred-`BEGIN`) transaction against the store. See [`StreamGStore::read`]
/// for the remaining contract this does *not* enforce at compile time
/// (autocommit semantics, no cross-statement snapshot).
pub struct ReadHandle<'p>(&'p SqlitePool);

impl<'p> ReadHandle<'p> {
    /// Delegates to [`sqlx::query::Query::fetch_one`] against the wrapped
    /// pool.
    pub async fn fetch_one<'q, A>(
        &self,
        query: sqlx::query::Query<'q, sqlx::Sqlite, A>,
    ) -> Result<SqliteRow, sqlx::Error>
    where
        A: 'q + Send + IntoArguments<'q, sqlx::Sqlite>,
    {
        query.fetch_one(self.0).await
    }

    /// Delegates to [`sqlx::query::Query::fetch_optional`] against the
    /// wrapped pool.
    pub async fn fetch_optional<'q, A>(
        &self,
        query: sqlx::query::Query<'q, sqlx::Sqlite, A>,
    ) -> Result<Option<SqliteRow>, sqlx::Error>
    where
        A: 'q + Send + IntoArguments<'q, sqlx::Sqlite>,
    {
        query.fetch_optional(self.0).await
    }

    /// Delegates to [`sqlx::query::Query::fetch_all`] against the wrapped
    /// pool.
    pub async fn fetch_all<'q, A>(
        &self,
        query: sqlx::query::Query<'q, sqlx::Sqlite, A>,
    ) -> Result<Vec<SqliteRow>, sqlx::Error>
    where
        A: 'q + Send + IntoArguments<'q, sqlx::Sqlite>,
    {
        query.fetch_all(self.0).await
    }

    /// Delegates to [`sqlx::query::QueryScalar::fetch_one`] against the
    /// wrapped pool — the shape `sqlx::query_scalar(..)` call sites want
    /// (single column, mapped straight to `O` instead of a raw row).
    pub async fn fetch_scalar<'q, O, A>(
        &self,
        query: sqlx::query::QueryScalar<'q, sqlx::Sqlite, O, A>,
    ) -> Result<O, sqlx::Error>
    where
        O: Send + Unpin,
        A: 'q + Send + IntoArguments<'q, sqlx::Sqlite>,
        (O,): Send + Unpin + for<'r> FromRow<'r, SqliteRow>,
    {
        query.fetch_one(self.0).await
    }
}

/// Open, WAL-mode, single-writer, instance-locked Stream G database.
pub struct StreamGStore {
    /// Held for the store's whole lifetime. The OS releases the `fs2`
    /// exclusive lock when this handle closes/drops — exactly when a
    /// second `open` against the same `lock_path` should start succeeding
    /// again.
    _lock_file: File,
    pool: SqlitePool,
    db_uuid: String,
    schema_version: u32,
}

impl StreamGStore {
    /// Take the instance lock, open (creating if needed) the WAL SQLite
    /// database at `db_path`, and apply the embedded migration if it has
    /// not already run against this file.
    ///
    /// The lock is acquired *before* anything touches `db_path`: a second
    /// `open` against the same `lock_path` while the first store is still
    /// alive fails fast with [`StreamGStoreError::InstanceLock`] rather
    /// than racing SQLite's own file locking.
    pub async fn open(db_path: &Path, lock_path: &Path) -> Result<Self, StreamGStoreError> {
        if db_path == lock_path {
            return Err(StreamGStoreError::SamePath {
                path: db_path.to_path_buf(),
            });
        }

        let lock_file = Self::acquire_instance_lock(lock_path)?;

        ensure_parent_dir(db_path)?;

        let connect_options = SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    conn.execute(PRAGMA_SQL).await?;
                    Ok(())
                })
            })
            .connect_with(connect_options)
            .await?;

        let (db_uuid, schema_version) = Self::apply_migration_if_needed(&pool).await?;

        Ok(Self {
            _lock_file: lock_file,
            pool,
            db_uuid,
            schema_version,
        })
    }

    fn acquire_instance_lock(lock_path: &Path) -> Result<File, StreamGStoreError> {
        ensure_parent_dir(lock_path)?;

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            // The lock file's contents are never meaningful (fs2 locks the
            // handle, not the bytes) — `truncate(false)` so re-opening an
            // existing lock file across process restarts never touches it.
            .truncate(false)
            .open(lock_path)
            .map_err(|source| StreamGStoreError::Io {
                path: lock_path.to_path_buf(),
                source,
            })?;

        file.try_lock_exclusive()
            .map_err(|source| StreamGStoreError::InstanceLock {
                path: lock_path.to_path_buf(),
                source,
            })?;

        Ok(file)
    }

    /// Idempotent bootstrap: apply every migration in [`MIGRATIONS`] this
    /// database file has not already recorded, then return the (possibly
    /// freshly-generated, possibly cached-from-a-prior-run) `db_uuid` +
    /// `schema_version`.
    ///
    /// Three cases, all handled by the same loop:
    ///
    /// - **Fresh file** — nothing recorded, so every migration is pending.
    ///   `0001` creates `store_meta`; the singleton row is minted in that
    ///   same transaction.
    /// - **Already current** — `store_meta.schema_version` equals
    ///   [`SCHEMA_VERSION`], nothing is pending, no SQL runs.
    /// - **Upgrade in place** — a database an older build migrated to some
    ///   `v < SCHEMA_VERSION`. Every migration `> v` is applied in ascending
    ///   order, each in its own `BEGIN IMMEDIATE` transaction that also bumps
    ///   `store_meta.schema_version` and inserts the `schema_migrations` row,
    ///   so a crash mid-way leaves the file at a version that was actually
    ///   applied — never half of one.
    ///
    /// The forward-compat refusal (`stored_version > SCHEMA_VERSION`) is
    /// checked **before** anything is applied: an older build must not open a
    /// database a newer build already migrated, because it has no idea what
    /// the later migration's tables/columns look like.
    async fn apply_migration_if_needed(
        pool: &SqlitePool,
    ) -> Result<(String, u32), StreamGStoreError> {
        let (db_uuid, mut current_version) = match Self::stored_meta(pool).await? {
            Some((db_uuid, stored_version)) => {
                if stored_version > SCHEMA_VERSION {
                    return Err(StreamGStoreError::SchemaVersionTooNew {
                        stored: stored_version,
                        supported: SCHEMA_VERSION,
                    });
                }
                (db_uuid, stored_version)
            }
            None => {
                // Nothing recorded yet: mint the id this file will keep for
                // the rest of its life. Written inside the first migration's
                // transaction below, so a failed migration leaves no row.
                let mut uuid_bytes = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut uuid_bytes);
                (hex::encode(uuid_bytes), 0)
            }
        };

        // Snapshot the starting version for the filter: `current_version` is
        // reassigned inside the loop, and MIGRATIONS is ascending, so
        // "everything above where we started" and "everything still pending"
        // are the same set.
        let start_version = current_version;
        for migration in MIGRATIONS.iter().filter(|m| m.version > start_version) {
            // Same BEGIN IMMEDIATE discipline as `write_tx`: this is itself a
            // write to the database.
            let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
            tx.execute(migration.sql).await?;

            sqlx::query(
                "INSERT INTO schema_migrations (version, applied_at, description) \
                 VALUES (?, ?, ?)",
            )
            .bind(migration.version)
            .bind(now_unix_seconds())
            .bind(migration.description)
            .execute(&mut *tx)
            .await?;

            if current_version == 0 {
                // `store_meta` did not exist before this migration created it.
                sqlx::query(
                    "INSERT INTO store_meta (id, db_uuid, schema_version) VALUES (1, ?, ?)",
                )
                .bind(&db_uuid)
                .bind(migration.version)
                .execute(&mut *tx)
                .await?;
            } else {
                sqlx::query("UPDATE store_meta SET schema_version = ? WHERE id = 1")
                    .bind(migration.version)
                    .execute(&mut *tx)
                    .await?;
            }

            tx.commit().await?;
            current_version = migration.version;
        }

        let schema_version = u32::try_from(current_version)
            .map_err(|_| StreamGStoreError::SchemaVersionOutOfRange(current_version))?;
        Ok((db_uuid, schema_version))
    }

    /// `(db_uuid, schema_version)` from the `store_meta` singleton, or `None`
    /// when this file has never been migrated (no `store_meta` table at all).
    ///
    /// Deliberately keyed on the presence of the **row**, not on
    /// `schema_migrations` containing this build's `SCHEMA_VERSION`: the old
    /// one-shot check asked "has version N been applied?", which answers
    /// "no" for a database sitting at N-1 and would send it back through
    /// `0001` — straight into `table already exists`.
    async fn stored_meta(pool: &SqlitePool) -> Result<Option<(String, i64)>, StreamGStoreError> {
        let table_exists: Option<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'store_meta'",
        )
        .fetch_optional(pool)
        .await?;
        if table_exists.is_none() {
            return Ok(None);
        }

        let row: Option<SqliteRow> =
            sqlx::query("SELECT db_uuid, schema_version FROM store_meta WHERE id = 1")
                .fetch_optional(pool)
                .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let db_uuid: String = sqlx::Row::try_get(&row, "db_uuid")?;
        let schema_version: i64 = sqlx::Row::try_get(&row, "schema_version")?;
        Ok(Some((db_uuid, schema_version)))
    }

    /// Current `journal_mode` as SQLite reports it (expected: `"wal"`).
    pub async fn pragma_journal_mode(&self) -> Result<String, StreamGStoreError> {
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&self.pool)
            .await?;
        Ok(mode)
    }

    /// Read back all four pragmas [`PRAGMA_SQL`] sets, as SQLite reports
    /// them on the pool's live connection.
    ///
    /// Reading them back is not the same as setting them: `journal_mode=WAL`
    /// silently stays `delete` on a filesystem that cannot support WAL (some
    /// network mounts), and a pragma applied by `after_connect` is per
    /// *connection* — a future change to the pool would apply it to a
    /// connection this handle never sees. So the values are re-read here
    /// rather than assumed from the string that was executed.
    pub async fn read_pragmas(&self) -> Result<PragmaSnapshot, StreamGStoreError> {
        let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&self.pool)
            .await?;
        let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&self.pool)
            .await?;
        let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(&self.pool)
            .await?;
        let busy_timeout_ms: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(&self.pool)
            .await?;
        Ok(PragmaSnapshot {
            journal_mode,
            foreign_keys,
            synchronous,
            busy_timeout_ms,
        })
    }

    /// [`read_pragmas`](Self::read_pragmas) plus a fail-closed check of every
    /// value: `journal_mode=WAL`, `foreign_keys=ON`, `synchronous=FULL`, and a
    /// **bounded** `busy_timeout` (strictly positive — `0` means "never wait,
    /// return SQLITE_BUSY immediately" — and no larger than
    /// [`MAX_BUSY_TIMEOUT_MS`], because an effectively-unbounded busy timeout
    /// converts a stuck writer into a hung request instead of an error).
    ///
    /// Called once at startup by `runtime::StreamGState::start`; a mismatch is
    /// a refusal to run, not a warning.
    pub async fn verify_pragmas(&self) -> Result<PragmaSnapshot, StreamGStoreError> {
        let snapshot = self.read_pragmas().await?;

        if !snapshot.journal_mode.eq_ignore_ascii_case("wal") {
            return Err(StreamGStoreError::PragmaMismatch {
                pragma: "journal_mode",
                expected: "wal".to_string(),
                actual: snapshot.journal_mode,
            });
        }
        if snapshot.foreign_keys != 1 {
            return Err(StreamGStoreError::PragmaMismatch {
                pragma: "foreign_keys",
                expected: "1 (ON)".to_string(),
                actual: snapshot.foreign_keys.to_string(),
            });
        }
        if snapshot.synchronous != SYNCHRONOUS_FULL {
            return Err(StreamGStoreError::PragmaMismatch {
                pragma: "synchronous",
                expected: format!("{SYNCHRONOUS_FULL} (FULL)"),
                actual: snapshot.synchronous.to_string(),
            });
        }
        if snapshot.busy_timeout_ms <= 0 || snapshot.busy_timeout_ms > MAX_BUSY_TIMEOUT_MS {
            return Err(StreamGStoreError::PragmaMismatch {
                pragma: "busy_timeout",
                expected: format!("1..={MAX_BUSY_TIMEOUT_MS} ms"),
                actual: snapshot.busy_timeout_ms.to_string(),
            });
        }

        Ok(snapshot)
    }

    /// The `store_meta` singleton as it is **on disk right now**.
    ///
    /// `None` when the row is absent, which for an opened store means the file
    /// changed underneath us — `open` cannot return without it existing.
    /// Readiness uses this to catch a swapped/restored database file; ordinary
    /// call sites should keep using the cached [`db_uuid`](Self::db_uuid) and
    /// [`schema_version`](Self::schema_version), which are what the AAD and the
    /// migration gate were built from.
    pub async fn read_stored_meta(&self) -> Result<Option<StoredMeta>, StreamGStoreError> {
        Ok(Self::stored_meta(&self.pool)
            .await?
            .map(|(db_uuid, schema_version)| StoredMeta {
                db_uuid,
                schema_version,
            }))
    }

    /// Up to `limit` non-NULL envelopes from one sealed column, oldest pk
    /// first, as `(pk, envelope_bytes)`.
    ///
    /// `column.table`/`column.column` are interpolated into the SQL rather
    /// than bound, because SQLite cannot bind identifiers. That is safe here
    /// and only here: the values come from [`SEALED_COLUMNS`], which is a
    /// `const` of `&'static str` literals — no caller-supplied string can
    /// reach this. The signature takes `&SealedColumn` (not two `&str`s)
    /// specifically so there is no way to call it with anything else.
    ///
    /// A [`SealedEncoding::HexText`] cell that is not valid hex yields
    /// `(pk, None)` — the row is corrupt, and readiness must treat that as a
    /// canary failure rather than silently skipping it.
    pub async fn sample_sealed_envelopes(
        &self,
        column: &SealedColumn,
        limit: i64,
    ) -> Result<Vec<(String, Option<Vec<u8>>)>, StreamGStoreError> {
        let sql = format!(
            "SELECT {pk} AS pk, {col} AS envelope FROM {table} \
             WHERE {col} IS NOT NULL ORDER BY {pk} ASC LIMIT ?",
            pk = column.pk,
            col = column.column,
            table = column.table,
        );
        let rows: Vec<SqliteRow> = sqlx::query(&sql).bind(limit).fetch_all(&self.pool).await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let pk: String = sqlx::Row::try_get(&row, "pk")?;
            let envelope = match column.encoding {
                SealedEncoding::Blob => {
                    let bytes: Vec<u8> = sqlx::Row::try_get(&row, "envelope")?;
                    Some(bytes)
                }
                SealedEncoding::HexText => {
                    let text: String = sqlx::Row::try_get(&row, "envelope")?;
                    hex::decode(text.trim()).ok()
                }
            };
            out.push((pk, envelope));
        }
        Ok(out)
    }

    /// Random id minted into `store_meta` the first time this database
    /// file was migrated; stable across every later `open` of that file.
    pub fn db_uuid(&self) -> &str {
        &self.db_uuid
    }

    /// Schema version recorded in `store_meta` — the highest migration this
    /// file has applied. **Not** the value that goes into an envelope AAD;
    /// see [`StreamGStore::envelope_aad_version`].
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Version to stamp into an [`EnvelopeAad`].
    ///
    /// Call sites that cannot use [`envelope_aad`](Self::envelope_aad) —
    /// because they must build the AAD by hand *inside* a `write_tx` closure,
    /// where calling back into the store would deadlock the single-connection
    /// pool — must read the version from **here**, never from
    /// [`schema_version`](Self::schema_version). Using the live schema
    /// version would make every envelope sealed before a migration
    /// undecryptable after it. See [`ENVELOPE_AAD_SCHEMA_VERSION`].
    pub fn envelope_aad_version(&self) -> u32 {
        ENVELOPE_AAD_SCHEMA_VERSION
    }

    /// Build the [`EnvelopeAad`] for one encrypted column, filling
    /// `db_uuid` from this store's own cached value and the version from
    /// [`envelope_aad_version`](Self::envelope_aad_version). Call sites
    /// should always go through this rather than constructing an
    /// `EnvelopeAad` by hand, so an envelope can never end up bound to the
    /// wrong database (e.g. a stale hand-copied `db_uuid` literal).
    pub fn envelope_aad<'a>(
        &'a self,
        table: &'a str,
        pk: &'a str,
        column: &'a str,
    ) -> EnvelopeAad<'a> {
        EnvelopeAad {
            db_uuid: &self.db_uuid,
            schema_version: self.envelope_aad_version(),
            table,
            pk,
            column,
        }
    }

    /// Run `f` inside a `BEGIN IMMEDIATE` write transaction — the only
    /// write path Stream G business logic should use (later tasks depend
    /// on this). `BEGIN IMMEDIATE` grabs SQLite's writer lock as soon as
    /// the transaction starts, instead of sqlx's default deferred `BEGIN`
    /// which only acquires it on the first actual write statement; that
    /// removes the window where a transaction can discover a conflicting
    /// writer after it has already done other work.
    ///
    /// `f` returning `Ok` commits; `Err` rolls back and the original error
    /// is propagated unchanged — a *failed rollback* is logged via
    /// `tracing::warn!` rather than silently swallowed, but never replaces
    /// the original error. The error type `E` is generic so callers can
    /// thread their own domain error through the closure: `write_tx`'s own
    /// internal sqlx failures (opening/committing the transaction) are
    /// converted into `E` via `E: From<StreamGStoreError>`. Call as:
    /// `store.write_tx(|tx| Box::pin(async move { Ok::<(), StreamGStoreError>(()) })).await`
    /// — the explicit `E` annotation is required for the compiler to infer
    /// the closure's return type; without it, type inference has nothing
    /// to pin `E` to and the call fails to compile.
    ///
    /// # Re-entrancy
    ///
    /// Never call `write_tx` (or [`read`](Self::read)) from *inside*
    /// a `write_tx` closure. The pool backing this store has exactly one
    /// connection (`max_connections(1)`, see module docs) and the outer
    /// transaction holds it for the whole closure, so a nested call blocks
    /// waiting for a connection that will not free up until the outer
    /// transaction finishes — which it can't, because it's waiting on the
    /// nested call. That deadlock resolves only when sqlx's pool
    /// acquisition times out with `sqlx::Error::PoolTimedOut`.
    pub async fn write_tx<F, T, E>(&self, f: F) -> Result<T, E>
    where
        F: for<'t> FnOnce(&'t mut SqliteTransaction<'static>) -> WriteTxFuture<'t, T, E> + Send,
        T: Send,
        E: From<StreamGStoreError> + Send,
    {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(StreamGStoreError::from)?;
        match f(&mut tx).await {
            Ok(value) => {
                tx.commit().await.map_err(StreamGStoreError::from)?;
                Ok(value)
            }
            Err(err) => {
                if let Err(rollback_err) = tx.rollback().await {
                    tracing::warn!(
                        error = %rollback_err,
                        "stream_g write_tx: rollback failed after an original error; \
                         propagating the original error, but the connection's \
                         transaction state may now be inconsistent"
                    );
                }
                Err(err)
            }
        }
    }

    /// Read-only counterpart to [`write_tx`](Self::write_tx): runs `f`
    /// against a [`ReadHandle`] over the store's pool rather than opening
    /// a transaction. This exists so read paths never need a raw pool
    /// accessor — exposing one would make it trivially easy to issue a
    /// write outside the `write_tx` discipline this module exists to
    /// enforce. The `_tx` suffix was deliberately dropped from this
    /// method's name: unlike `write_tx`, this does not open a SQLite
    /// transaction at all, and the old name advertised isolation
    /// guarantees this method does not provide.
    ///
    /// Two properties to keep in mind:
    ///
    /// - **No snapshot isolation.** Each statement `f` issues through the
    ///   [`ReadHandle`] runs in SQLite's autocommit mode against the pool's
    ///   single connection. Two reads inside the same `f` are *not* a
    ///   consistent snapshot — a concurrent `write_tx` can commit between
    ///   them and change what the second read sees. Callers that need
    ///   several reads to observe one consistent point in time must do
    ///   those reads inside `write_tx` instead (even if nothing is being
    ///   written there).
    /// - **Writes are structurally unavailable, not just discouraged.**
    ///   [`ReadHandle`] exposes only `fetch_one`/`fetch_optional`/
    ///   `fetch_all`/`fetch_scalar`, each delegating straight to the
    ///   wrapped pool. There is no `execute` and no `begin` reachable from
    ///   `f`, so `f` cannot run a write statement or open a
    ///   deferred-`BEGIN` transaction against the store — by construction,
    ///   not by convention.
    ///
    /// Same re-entrancy hazard as `write_tx` applies: do not call
    /// `write_tx` or `read` from inside a `write_tx` closure.
    pub async fn read<F, T, E>(&self, f: F) -> Result<T, E>
    where
        F: for<'p> FnOnce(ReadHandle<'p>) -> ReadFuture<'p, T, E> + Send,
        T: Send,
        E: From<StreamGStoreError> + Send,
    {
        f(ReadHandle(&self.pool)).await
    }
}

/// Create `path`'s parent directory (and any missing ancestors) if it
/// doesn't already exist.
///
/// On Unix, newly created directories are created `0o700` (owner-only)
/// directly via `DirBuilder::mode`, rather than being created with the
/// default mode and tightened afterward, so there is no window where a
/// directory this call creates is briefly group-/world-readable. This
/// only covers directories `DirBuilder::create` actually creates: if the
/// parent (or an ancestor) already exists — the common deployment case
/// where an operator pre-creates the state directory — its existing mode
/// is left untouched, so `0o700` is not a guarantee about the resulting
/// directory tree, only about what this call itself creates. On Windows
/// (and any other non-Unix target) there is no POSIX mode bit to set here
/// — a freshly created directory inherits its parent's ACL, so operators
/// who need the Stream G state directory locked down to a single account
/// are responsible for setting that ACL on the parent themselves.
fn ensure_parent_dir(path: &Path) -> Result<(), StreamGStoreError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|source| StreamGStoreError::Io {
                path: parent.to_path_buf(),
                source,
            })
    }

    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(parent).map_err(|source| StreamGStoreError::Io {
            path: parent.to_path_buf(),
            source,
        })
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time `Send` assertion. `write_tx`'s `+ Send` bound on the
    /// closure's *future* only constrains what callers can pass in — the
    /// `Send`-ness of `write_tx` (and `read`)'s own *returned* future is
    /// inferred from every local it holds across an `.await`, so a later
    /// non-`Send` local added inside either method would silently drop
    /// `Send` again without any test failing on its own. Applying this to
    /// the future *before* awaiting it, in the tests below, turns that
    /// silent regression into a compile error.
    fn assert_send<T: Send>(_: &T) {}

    #[tokio::test]
    async fn migrates_sqlite_wal_and_enforces_instance_lock() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open");
        assert!(store
            .pragma_journal_mode()
            .await
            .unwrap()
            .eq_ignore_ascii_case("wal"));

        // Prove foreign_keys=ON actually landed on this connection (not
        // just that the pragma string was sent) — `write_tx_rolls_back_on_error`
        // below additionally proves it is *enforced*, not just reported.
        let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&store.pool)
            .await
            .expect("read foreign_keys pragma");
        assert_eq!(foreign_keys, 1, "foreign_keys pragma must be ON");

        let busy_timeout: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(&store.pool)
            .await
            .expect("read busy_timeout pragma");
        assert_eq!(busy_timeout, 5000, "busy_timeout pragma must be 5000ms");

        // Prove synchronous=FULL (2) actually landed too, same reasoning
        // as the foreign_keys/busy_timeout checks above.
        let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(&store.pool)
            .await
            .expect("read synchronous pragma");
        assert_eq!(synchronous, 2, "synchronous pragma must be FULL (2)");

        let err = StreamGStore::open(&db, &lock)
            .await
            .err()
            .expect("second owner");
        assert!(format!("{err}").contains("instance lock"));
    }

    /// `verify_pragmas` must be a *check*, not a restatement of
    /// [`PRAGMA_SQL`]: it re-reads what SQLite actually reports on the live
    /// connection. The positive arm is the freshly-opened store; the negative
    /// arm degrades `busy_timeout` to `0` — "never wait, return SQLITE_BUSY
    /// immediately" — and shows the check catching it.
    ///
    /// `busy_timeout` is the pragma used for the negative arm because it is
    /// the only one of the four SQLite lets a live connection change:
    /// `journal_mode`, `foreign_keys` and `synchronous` are all refusals or
    /// no-ops once a connection is up and inside a transaction.
    ///
    /// Mutation this detects: relaxing the lower bound in `verify_pragmas`
    /// from `busy_timeout_ms <= 0` to `busy_timeout_ms < 0` (i.e. accepting
    /// the no-wait setting as "bounded").
    #[tokio::test]
    async fn verify_pragmas_accepts_a_fresh_store_and_refuses_a_zero_busy_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open");

        let snapshot = store
            .verify_pragmas()
            .await
            .expect("a freshly opened store must pass");
        assert!(snapshot.journal_mode.eq_ignore_ascii_case("wal"));
        assert_eq!(snapshot.foreign_keys, 1);
        assert_eq!(snapshot.synchronous, SYNCHRONOUS_FULL);
        assert_eq!(snapshot.busy_timeout_ms, 5000);

        // Degrade the live connection. `max_connections(1)` guarantees the
        // next read lands on this same connection.
        store
            .write_tx(|tx| {
                Box::pin(async move {
                    tx.execute("PRAGMA busy_timeout=0").await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("set busy_timeout=0");

        let err = store
            .verify_pragmas()
            .await
            .expect_err("busy_timeout=0 is not a bounded timeout and must be refused");
        assert!(
            matches!(
                &err,
                StreamGStoreError::PragmaMismatch { pragma, actual, .. }
                    if *pragma == "busy_timeout" && actual == "0"
            ),
            "expected a busy_timeout PragmaMismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn migration_is_idempotent_across_sequential_opens() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");

        let first_uuid = {
            let store = StreamGStore::open(&db, &lock).await.expect("first open");
            assert_eq!(store.schema_version(), SCHEMA_VERSION as u32);
            store.db_uuid().to_string()
        }; // store dropped here: releases the instance lock.

        let store = StreamGStore::open(&db, &lock).await.expect("second open");
        assert_eq!(store.db_uuid(), first_uuid, "db_uuid must be stable");
        assert_eq!(store.schema_version(), SCHEMA_VERSION as u32);

        // The migration SQL has no `IF NOT EXISTS` guards, so re-running any
        // of it against a second `open` would fail with "table already
        // exists" / "duplicate column name". Getting this far, plus exactly
        // one recorded row per known migration, proves the second open
        // skipped them all.
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM schema_migrations")
            .fetch_one(&store.pool)
            .await
            .expect("count migrations");
        assert_eq!(
            count, 3,
            "each migration must record exactly one row, not be reapplied"
        );

        // Paired non-zero arm for the count above: assert the *identity* of
        // the recorded versions, not just how many there are. A loop that
        // inserted the same version twice, or recorded `SCHEMA_VERSION` for
        // every migration, would keep the count right and fail here.
        //
        // ⚠️ WRITTEN AS A LITERAL ON PURPOSE. `MIGRATIONS.iter().map(|m|
        // m.version)` reads as tighter and is strictly weaker: the loop in
        // `apply_migration_if_needed` binds `migration.version` into
        // `schema_migrations`, so comparing the rows back to `MIGRATIONS` is
        // true by construction for ANY contents of that list — `[1, 2, 2]`,
        // `[1, 3]`, `[1, 2, 7]` all pass. The literal is what makes a wrong
        // `version:` field in `MIGRATIONS` fail a test. Adding a migration
        // means editing this list, in the same commit, on purpose.
        let versions: Vec<i64> =
            sqlx::query_scalar("SELECT version FROM schema_migrations ORDER BY version")
                .fetch_all(&store.pool)
                .await
                .expect("list migration versions");
        assert_eq!(
            versions,
            vec![1, 2, 3],
            "schema_migrations must record every applied version exactly once"
        );
    }

    #[tokio::test]
    async fn open_rejects_stored_schema_version_newer_than_this_build() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");

        {
            let store = StreamGStore::open(&db, &lock).await.expect("first open");
            sqlx::query("UPDATE store_meta SET schema_version = ? WHERE id = 1")
                .bind(SCHEMA_VERSION + 1)
                .execute(&store.pool)
                .await
                .expect("bump schema_version");
        } // store dropped here: releases the instance lock.

        let err = StreamGStore::open(&db, &lock)
            .await
            .err()
            .expect("a newer-than-build schema_version must be rejected");
        assert!(matches!(
            err,
            StreamGStoreError::SchemaVersionTooNew { stored, supported }
                if stored == SCHEMA_VERSION + 1 && supported == SCHEMA_VERSION
        ));
    }

    #[tokio::test]
    async fn open_rejects_identical_db_path_and_lock_path() {
        let dir = tempfile::tempdir().unwrap();
        let same_path = dir.path().join("stream_g.sqlite");

        let err = StreamGStore::open(&same_path, &same_path)
            .await
            .err()
            .expect("identical db_path/lock_path must be rejected");
        assert!(matches!(err, StreamGStoreError::SamePath { .. }));
    }

    #[tokio::test]
    async fn write_tx_uses_begin_immediate_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open");

        let write_fut = store.write_tx(|tx| {
            Box::pin(async move {
                sqlx::query("INSERT INTO profiles (id, created_at, status) VALUES (?, ?, ?)")
                    .bind("profile-1")
                    .bind(0i64)
                    .bind("active")
                    .execute(&mut **tx)
                    .await?;
                Ok::<(), StreamGStoreError>(())
            })
        });
        assert_send(&write_fut);
        write_fut.await.expect("write_tx");

        let status: String = sqlx::query_scalar("SELECT status FROM profiles WHERE id = ?")
            .bind("profile-1")
            .fetch_one(&store.pool)
            .await
            .expect("read back");
        assert_eq!(status, "active");
    }

    #[tokio::test]
    async fn write_tx_rolls_back_on_error() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open");

        let result: Result<(), StreamGStoreError> = store
            .write_tx(|tx| {
                Box::pin(async move {
                    sqlx::query("INSERT INTO profiles (id, created_at, status) VALUES (?, ?, ?)")
                        .bind("profile-rollback")
                        .bind(0i64)
                        .bind("active")
                        .execute(&mut **tx)
                        .await?;
                    // Force a failure after the insert to prove rollback
                    // undoes it rather than partially committing. This
                    // specifically violates the
                    // `credential_aliases.profile_id` foreign key
                    // (referencing a profile that does not exist) instead
                    // of e.g. inserting into a nonexistent table, because
                    // an FK violation only fails at all when
                    // `PRAGMA foreign_keys=ON` is actually in effect on
                    // this connection — proving enforcement, not just that
                    // *some* error can roll back a transaction.
                    sqlx::query(
                        "INSERT INTO credential_aliases \
                         (id, profile_id, alias_type, alias_hash, created_at) \
                         VALUES (?, ?, ?, ?, ?)",
                    )
                    .bind("alias-rollback")
                    .bind("profile-does-not-exist")
                    .bind("email")
                    .bind("deadbeef")
                    .bind(0i64)
                    .execute(&mut **tx)
                    .await?;
                    Ok(())
                })
            })
            .await;
        assert!(result.is_err());

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM profiles WHERE id = ?")
            .bind("profile-rollback")
            .fetch_one(&store.pool)
            .await
            .expect("count profiles");
        assert_eq!(count, 0, "failed write_tx must not persist any rows");

        let alias_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM credential_aliases WHERE id = ?")
                .bind("alias-rollback")
                .fetch_one(&store.pool)
                .await
                .expect("count credential_aliases");
        assert_eq!(
            alias_count, 0,
            "failed write_tx must not persist any rows, including the row \
             that triggered the FK violation"
        );
    }

    #[tokio::test]
    async fn read_runs_read_only_queries_against_a_read_handle() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open");

        store
            .write_tx(|tx| {
                Box::pin(async move {
                    sqlx::query("INSERT INTO profiles (id, created_at, status) VALUES (?, ?, ?)")
                        .bind("profile-read")
                        .bind(0i64)
                        .bind("active")
                        .execute(&mut **tx)
                        .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("write_tx");

        let read_fut = store.read(|handle| {
            Box::pin(async move {
                let status: String = handle
                    .fetch_scalar(
                        sqlx::query_scalar("SELECT status FROM profiles WHERE id = ?")
                            .bind("profile-read"),
                    )
                    .await?;
                Ok::<String, StreamGStoreError>(status)
            })
        });
        assert_send(&read_fut);
        let status = read_fut.await.expect("read");
        assert_eq!(status, "active");
    }

    #[tokio::test]
    async fn envelope_aad_uses_the_stores_own_db_uuid_and_the_pinned_aad_version() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open");

        let aad = store.envelope_aad("profiles", "profile-1", "profile_enc");
        assert_eq!(aad.db_uuid, store.db_uuid());
        assert_eq!(aad.schema_version, store.envelope_aad_version());
        assert_eq!(aad.table, "profiles");
        assert_eq!(aad.pk, "profile-1");
        assert_eq!(aad.column, "profile_enc");

        // ⚠️ THE LITERAL `1` BELOW IS THE TEST. Do not "clean it up" into
        // `ENVELOPE_AAD_SCHEMA_VERSION`.
        //
        // `envelope_aad_version()` returns that constant verbatim, so
        // `assert_eq!(store.envelope_aad_version(), ENVELOPE_AAD_SCHEMA_VERSION)`
        // is `X == X`: it holds for EVERY value the constant could ever take,
        // including the one value that must never be taken. Bumping
        // `ENVELOPE_AAD_SCHEMA_VERSION` makes every `_enc` column ever sealed
        // by this database permanently undecryptable (see that constant's doc);
        // this literal is the only thing in the crate that turns that edit into
        // a red test instead of a silent, irreversible data loss. A change to
        // it is only legitimate alongside a re-seal migration that rewrites
        // every `_enc` column under the new AAD — at which point updating this
        // number is the deliberate act it is supposed to be.
        assert_eq!(
            store.envelope_aad_version(),
            1,
            "ENVELOPE_AAD_SCHEMA_VERSION must stay pinned at 1 — bumping it \
             makes every previously sealed `_enc` column undecryptable"
        );

        // The schema version is pinned by a literal for the same reason, but a
        // weaker one: bumping it is legitimate (it is how a migration ships),
        // it just must not happen by accident. Note this is NOT `X == X`:
        // `schema_version()` is read back out of `store_meta`, which
        // `apply_migration_if_needed` writes from `MIGRATIONS`' last entry and
        // never from `SCHEMA_VERSION` — so the pair below also catches
        // `SCHEMA_VERSION` drifting away from the migration list.
        assert_eq!(store.schema_version(), 3, "current schema is v3 (0003)");
        assert_eq!(
            SCHEMA_VERSION, 3,
            "SCHEMA_VERSION must match what a freshly opened store reports"
        );

        // The two versions are genuinely different values on this build, so the
        // `aad.schema_version` assertion above is not `x == x` in disguise: a
        // fresh store is at 3 (migration 0003 added the reconciliation scan
        // cursor) while envelopes are still stamped 1. If a later build ever
        // makes these equal again, this fails and forces a conscious re-read of
        // `ENVELOPE_AAD_SCHEMA_VERSION`'s doc comment rather than letting the
        // distinction silently stop being tested.
        assert_ne!(
            store.schema_version(),
            store.envelope_aad_version(),
            "the AAD version must stay decoupled from the live schema version"
        );
    }

    // ---------------------------------------------------------------
    // Task 7 Wave A — migration list (1 → 2), 0002 outbox schema.
    // ---------------------------------------------------------------

    /// Frozen-migration guard, over EVERY migration.
    ///
    /// Mutation this detects: **any** edit to any file in `migrations/` — adding
    /// a column, changing a default, even reflowing a comment. Verified by
    /// appending a single `-- x` line to each of `0001`, `0002` and `0003` in
    /// turn, watching this test fail with the two hashes, and reverting.
    ///
    /// Why a hash and not a spot-check: databases in the field already recorded
    /// `schema_migrations.version = N`, so an edited `000N` never re-runs there.
    /// Two deployments would claim the same schema version and have different
    /// schemas, and nothing else in the suite would notice.
    ///
    /// The version/length assertions are what keep this from degrading into a
    /// hash of whatever happens to be in the list: a migration added without a
    /// row in [`MIGRATION_SHA256`] is unfrozen, and that is the state this
    /// test refuses to let the crate reach.
    #[test]
    fn every_migration_is_byte_identical() {
        use sha2::{Digest, Sha256};

        assert_eq!(
            MIGRATIONS.len(),
            MIGRATION_SHA256.len(),
            "every migration must be frozen — a new migration needs a new \
             MIGRATION_SHA256 row in the same commit"
        );
        assert_eq!(
            MIGRATIONS[0].version, 1,
            "MIGRATIONS[0] must be the initial migration"
        );

        for (m, (version, expected)) in MIGRATIONS.iter().zip(MIGRATION_SHA256) {
            assert_eq!(
                m.version, *version,
                "MIGRATION_SHA256 is keyed by version and must stay aligned \
                 with MIGRATIONS' ascending order"
            );
            let actual = hex::encode(Sha256::digest(m.sql.as_bytes()));
            assert_eq!(
                &actual, expected,
                "migration {version} is FROZEN — add a new numbered migration \
                 instead of editing it"
            );
        }
    }

    /// Build a v1 database by hand: apply only `MIGRATIONS[0]` and record it
    /// exactly the way the pre-Task-7 one-shot migrator did. Returns the
    /// `db_uuid` it minted.
    ///
    /// This is what makes the upgrade tests below real rather than
    /// hypothetical — this build can no longer *create* a v1 database, so
    /// without this helper "upgrade in place" could only ever be asserted
    /// against a database that was already v2.
    async fn seed_v1_database(db: &Path) -> String {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(db)
                    .create_if_missing(true),
            )
            .await
            .expect("open raw pool");

        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await.expect("begin");
        tx.execute(MIGRATIONS[0].sql).await.expect("apply 0001");

        let mut uuid_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut uuid_bytes);
        let db_uuid = hex::encode(uuid_bytes);

        sqlx::query(
            "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)",
        )
        .bind(1i64)
        .bind(0i64)
        .bind(MIGRATIONS[0].description)
        .execute(&mut *tx)
        .await
        .expect("record migration 1");
        sqlx::query("INSERT INTO store_meta (id, db_uuid, schema_version) VALUES (1, ?, 1)")
            .bind(&db_uuid)
            .execute(&mut *tx)
            .await
            .expect("mint store_meta");
        tx.commit().await.expect("commit");
        pool.close().await;
        db_uuid
    }

    /// Mutation this detects: dropping the `for migration in MIGRATIONS…`
    /// loop back to a one-shot "already applied? return early" check — the
    /// pre-Task-7 shape. Verified by restoring the early return (`if
    /// stored_meta.is_some() { return Ok(...) }` before the loop): this test
    /// then fails at `schema_version` (left 1, right 2) and the `0002`
    /// columns are absent.
    ///
    /// Also detects a loop that applies migrations against a fresh file only:
    /// this database is created at v1 by [`seed_v1_database`], never by this
    /// build.
    #[tokio::test]
    async fn an_existing_v1_database_upgrades_in_place_to_the_current_schema() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");

        let seeded_uuid = seed_v1_database(&db).await;

        // Pre-condition (paired non-zero arm): the seeded file really is at
        // v1 and really does NOT have the 0002 columns yet, so the
        // post-conditions below cannot be satisfied by a no-op.
        {
            let pool = SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(SqliteConnectOptions::new().filename(&db))
                .await
                .expect("reopen raw");
            let v: i64 = sqlx::query_scalar("SELECT schema_version FROM store_meta WHERE id = 1")
                .fetch_one(&pool)
                .await
                .expect("read version");
            assert_eq!(v, 1, "seed must produce a v1 database");
            let err = sqlx::query("SELECT claim_owner FROM tx_attempts")
                .fetch_all(&pool)
                .await
                .err()
                .expect("0002 columns must NOT exist before the upgrade");
            assert!(
                err.to_string().contains("claim_owner"),
                "unexpected error: {err}"
            );
            pool.close().await;
        }

        let store = StreamGStore::open(&db, &lock).await.expect("open upgrades");
        assert_eq!(
            store.schema_version(),
            SCHEMA_VERSION as u32,
            "must upgrade in place to the version this build supports"
        );
        assert_eq!(
            store.db_uuid(),
            seeded_uuid,
            "an in-place upgrade must NOT mint a new db_uuid — every existing \
             envelope's AAD is bound to the old one"
        );

        // Every 0002 column is now present and queryable.
        for sql in [
            "SELECT attempt_number, claim_owner, lease_until, raw_tx_hash, intent_id_hex \
             FROM tx_attempts",
            "SELECT kind, claim_owner, lease_until FROM nonce_allocations",
        ] {
            sqlx::query(sql)
                .fetch_all(&store.pool)
                .await
                .unwrap_or_else(|e| panic!("0002 column missing after upgrade ({sql}): {e}"));
        }

        // 0003's table is present too. Named explicitly rather than folded into
        // the loop above so that a future migration cannot make this test pass
        // by accident.
        sqlx::query("SELECT name, last_scanned_block, updated_at FROM stream_g_scan_cursors")
            .fetch_all(&store.pool)
            .await
            .expect("0003 scan-cursor table missing after upgrade");

        // Every migration is recorded, in order — an upgrade must not
        // rewrite history for `0001`.
        //
        // Literal for the same reason as the sibling assertion in
        // `migration_is_idempotent_across_sequential_opens`: derived from
        // `MIGRATIONS`, this holds for any numbering that list happens to
        // contain. Written out, it fails when the list is wrong.
        let versions: Vec<i64> =
            sqlx::query_scalar("SELECT version FROM schema_migrations ORDER BY version")
                .fetch_all(&store.pool)
                .await
                .expect("list versions");
        assert_eq!(versions, vec![1, 2, 3]);
    }

    /// The reason `ENVELOPE_AAD_SCHEMA_VERSION` exists.
    ///
    /// Mutation this detects: changing `envelope_aad` (and
    /// `envelope_aad_version`) back to `self.schema_version`. Verified by
    /// making that exact edit — this test then fails with
    /// `CryptoStoreError::DecryptionFailed`, i.e. the upgrade silently
    /// destroyed a sealed payload, while every other test in the crate still
    /// passed.
    #[tokio::test]
    async fn a_payload_sealed_at_v1_still_opens_after_the_schema_upgrade() {
        use super::super::crypto_store::{self, DataKey};

        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");

        let key = DataKey::from_hex(&hex::encode([0x5Au8; 32])).expect("key");
        let plaintext = b"sealed before the migration ran";

        let db_uuid = seed_v1_database(&db).await;

        // Seal exactly as a v1 build would have: AAD version 1.
        let sealed = {
            let aad = EnvelopeAad {
                db_uuid: &db_uuid,
                schema_version: 1,
                table: "profiles",
                pk: "profile-v1",
                column: "profile_enc",
            };
            crypto_store::seal(&key, &aad, plaintext).expect("seal")
        };

        {
            let pool = SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(SqliteConnectOptions::new().filename(&db))
                .await
                .expect("reopen raw");
            sqlx::query(
                "INSERT INTO profiles (id, created_at, status, profile_enc) VALUES (?, ?, ?, ?)",
            )
            .bind("profile-v1")
            .bind(0i64)
            .bind("active")
            .bind(&sealed)
            .execute(&pool)
            .await
            .expect("store sealed payload");
            pool.close().await;
        }

        // Upgrade to v2 and read it back through the store's own AAD.
        let store = StreamGStore::open(&db, &lock).await.expect("open upgrades");
        assert_eq!(
            store.schema_version(),
            SCHEMA_VERSION as u32,
            "the upgrade must have happened"
        );
        assert_ne!(
            store.schema_version(),
            1,
            "…and must actually have moved off v1, or the AAD assertions below prove nothing"
        );

        let stored: Vec<u8> = sqlx::query_scalar("SELECT profile_enc FROM profiles WHERE id = ?")
            .bind("profile-v1")
            .fetch_one(&store.pool)
            .await
            .expect("read back");
        assert_eq!(stored, sealed, "the migration must not rewrite _enc blobs");

        let aad = store.envelope_aad("profiles", "profile-v1", "profile_enc");
        let opened = crypto_store::open(&key, &aad, &stored)
            .expect("a payload sealed before the migration must still open after it");
        assert_eq!(&opened[..], &plaintext[..]);

        // Paired negative arm: the AAD really is authenticated here — an
        // envelope opened under the *live* schema version (2) must fail. If
        // this arm ever starts succeeding, the positive arm above has stopped
        // proving anything.
        let live_version_aad = EnvelopeAad {
            db_uuid: store.db_uuid(),
            schema_version: store.schema_version(),
            table: "profiles",
            pk: "profile-v1",
            column: "profile_enc",
        };
        assert!(
            crypto_store::open(&key, &live_version_aad, &stored).is_err(),
            "AAD version must be authenticated — otherwise this test proves nothing"
        );
    }

    /// §3.3 namespace collision: the broadcaster EOA tx nonce and the gateway
    /// action nonce now share `nonce_allocations`.
    ///
    /// Mutation this detects: deleting the
    /// `ALTER TABLE nonce_allocations ADD COLUMN kind …` statement from
    /// `0002`. Verified by removing that line — every statement below that
    /// names `kind` then fails with `no such column: kind`.
    #[tokio::test]
    async fn broadcaster_eoa_nonce_does_not_alias_a_controller_action_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open");

        // Same address, same chain, same nonce number — the worst case. One
        // row is the controller's gateway ACTION nonce (synthetic
        // "<addr>#<ACTION>" key), the other is that same EOA acting as the
        // Stream G broadcaster (bare address).
        let addr = "0x00000000000000000000000000000000000000aa";
        for (id, signer, kind) in [
            (
                "alloc-action",
                format!("{addr}#SPONSORED_ENROLLMENT"),
                "action",
            ),
            ("alloc-broadcaster", addr.to_string(), "broadcaster"),
        ] {
            sqlx::query(
                "INSERT INTO nonce_allocations \
                 (id, chain_id, signer_address, nonce, status, allocated_at, kind) \
                 VALUES (?, ?, ?, ?, 'allocated', 0, ?)",
            )
            .bind(id)
            .bind(84532i64)
            .bind(&signer)
            .bind(5i64)
            .bind(kind)
            .execute(&store.pool)
            .await
            .unwrap_or_else(|e| panic!("insert {id}: {e}"));
        }

        // Non-zero arm: both rows really are in the table.
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nonce_allocations")
            .fetch_one(&store.pool)
            .await
            .expect("count all");
        assert_eq!(total, 2, "both rows must coexist");

        // Kind-scoped lookups each see exactly their own row.
        for (kind, expected_id) in [
            ("broadcaster", "alloc-broadcaster"),
            ("action", "alloc-action"),
        ] {
            let ids: Vec<String> = sqlx::query_scalar(
                "SELECT id FROM nonce_allocations WHERE chain_id = ? AND nonce = ? AND kind = ?",
            )
            .bind(84532i64)
            .bind(5i64)
            .bind(kind)
            .fetch_all(&store.pool)
            .await
            .expect("kind-scoped lookup");
            assert_eq!(
                ids,
                vec![expected_id.to_string()],
                "kind='{kind}' must select exactly one row"
            );
        }
    }

    /// `DEFAULT 'action'` is the backfill for every pre-0002 row, all of
    /// which are gateway action nonces.
    ///
    /// Mutation this detects: changing `0002`'s
    /// `kind TEXT NOT NULL DEFAULT 'action'` to `DEFAULT 'broadcaster'`.
    /// Verified — the first assertion then reports `left: "broadcaster"`,
    /// meaning every legacy row would have been silently reclassified into
    /// the broadcaster key space.
    #[tokio::test]
    async fn nonce_allocations_kind_backfills_legacy_rows_as_action() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");

        seed_v1_database(&db).await;

        // A row written by a pre-0002 build: no `kind` column existed.
        {
            let pool = SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(SqliteConnectOptions::new().filename(&db))
                .await
                .expect("reopen raw");
            sqlx::query(
                "INSERT INTO nonce_allocations \
                 (id, chain_id, signer_address, nonce, status, allocated_at) \
                 VALUES ('legacy', 84532, '0xaa#SPONSORED_ENROLLMENT', 1, 'allocated', 0)",
            )
            .execute(&pool)
            .await
            .expect("legacy insert");
            pool.close().await;
        }

        let store = StreamGStore::open(&db, &lock).await.expect("upgrade");
        let kind: String = sqlx::query_scalar("SELECT kind FROM nonce_allocations WHERE id = ?")
            .bind("legacy")
            .fetch_one(&store.pool)
            .await
            .expect("read backfilled kind");
        assert_eq!(
            kind, "action",
            "0002 must backfill pre-existing rows as action nonces"
        );

        // Paired non-zero arm: an explicit broadcaster row is still possible
        // and is NOT swept up by the default.
        sqlx::query(
            "INSERT INTO nonce_allocations \
             (id, chain_id, signer_address, nonce, status, allocated_at, kind) \
             VALUES ('bcast', 84532, '0xaa', 1, 'allocated', 0, 'broadcaster')",
        )
        .execute(&store.pool)
        .await
        .expect("broadcaster insert");
        let broadcasters: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM nonce_allocations WHERE kind = 'broadcaster'")
                .fetch_one(&store.pool)
                .await
                .expect("count broadcaster rows");
        assert_eq!(broadcasters, 1, "exactly the explicitly-marked row");
    }

    /// §3.2 reverse lookup: `tx_attempts.intent_id_hex` must be indexed but
    /// **not unique**, and the winner is disambiguated by transaction hash.
    ///
    /// Mutation this detects: making `idx_tx_attempts_intent_id_hex` a
    /// `UNIQUE INDEX`. Verified — the second profile's insert then fails with
    /// `UNIQUE constraint failed: tx_attempts.intent_id_hex`, which is
    /// exactly the cross-profile squat defect C2 reappearing.
    #[tokio::test]
    async fn two_profiles_same_intent_id_reverse_lookup_disambiguates_by_tx_hash() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open");

        let shared_intent = format!("0x{}", "11".repeat(32));
        let ours = format!("0x{}", "ab".repeat(32));

        for (id, tx_hash) in [
            ("attempt-profile-a", Some(ours.clone())),
            ("attempt-profile-b", None),
        ] {
            sqlx::query(
                "INSERT INTO tx_attempts \
                 (id, chain_id, status, created_at, intent_id_hex, tx_hash) \
                 VALUES (?, ?, 'reserved', 0, ?, ?)",
            )
            .bind(id)
            .bind(84532i64)
            .bind(&shared_intent)
            .bind(tx_hash)
            .execute(&store.pool)
            .await
            .unwrap_or_else(|e| panic!("insert {id}: {e}"));
        }

        // Non-unique: the candidate set for one on-chain intentId has two rows.
        let candidates: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM tx_attempts WHERE intent_id_hex = ?")
                .bind(&shared_intent)
                .fetch_one(&store.pool)
                .await
                .expect("count candidates");
        assert_eq!(
            candidates, 2,
            "per-profile namespacing means the reverse lookup is one-to-many"
        );

        // Disambiguated by the observed transaction hash: exactly one row.
        let winners: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM tx_attempts WHERE intent_id_hex = ? AND tx_hash = ?",
        )
        .bind(&shared_intent)
        .bind(&ours)
        .fetch_all(&store.pool)
        .await
        .expect("disambiguate");
        assert_eq!(winners, vec!["attempt-profile-a".to_string()]);
    }

    /// The partial unique index on `tx_attempts.tx_hash`.
    ///
    /// Mutation this detects: dropping `CREATE UNIQUE INDEX
    /// idx_tx_attempts_hash …` from `0002`. Verified — the duplicate-hash
    /// insert then succeeds and `expect_err` panics, meaning two attempt rows
    /// could claim the same on-chain transaction.
    #[tokio::test]
    async fn tx_hash_is_unique_when_present_and_unconstrained_when_null() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open");

        let insert = |id: &'static str, hash: Option<String>| {
            let pool = store.pool.clone();
            async move {
                sqlx::query(
                    "INSERT INTO tx_attempts (id, chain_id, status, created_at, tx_hash) \
                     VALUES (?, 84532, 'reserved', 0, ?)",
                )
                .bind(id)
                .bind(hash)
                .execute(&pool)
                .await
            }
        };

        let hash = format!("0x{}", "cd".repeat(32));

        // Zero arm: many not-yet-broadcast rows all carry NULL tx_hash.
        insert("null-a", None).await.expect("first NULL");
        insert("null-b", None)
            .await
            .expect("second NULL must be allowed");

        // Non-zero arm: a concrete hash may be claimed exactly once.
        insert("hash-a", Some(hash.clone()))
            .await
            .expect("first concrete hash");
        let err = insert("hash-b", Some(hash.clone()))
            .await
            .expect_err("a second row must not claim the same tx_hash");
        assert!(
            err.to_string().to_lowercase().contains("unique"),
            "expected a UNIQUE violation, got: {err}"
        );
    }
}
