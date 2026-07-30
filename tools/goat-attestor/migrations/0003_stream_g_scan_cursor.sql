-- Stream G persistence schema (v3) — reconciliation scan cursor.
--
-- ADDITIVE ONLY, same discipline `0002_stream_g_outbox.sql` states and for the
-- same reason: `0001_stream_g.sql` is frozen and byte-identical (asserted by
-- `store::tests::migration_0001_is_byte_identical`), and an applied migration
-- may never be edited — editing one would give two databases the same recorded
-- `schema_version` and different schemas. New work is a new file.
--
-- Nothing in this file changes an existing column, constraint or index.
--
-- Why a new table and NOT `ALTER TABLE store_meta ADD COLUMN`:
--
--   * `store_meta` is the `CHECK (id = 1)` singleton that `readiness::
--     check_schema_version` and `StreamGStore::envelope_aad` both read. Its
--     three columns describe the *database file* (its uuid, its schema
--     version). A block cursor describes a *background job's progress* and has
--     nothing to do with either, so widening the readiness singleton to carry
--     it would couple two unrelated lifetimes.
--   * A `name`-keyed table also lets a second observer (a future log follower
--     for another event) get its own cursor without another migration.
--
-- Semantics of the one row `stream_g::maintenance::run_reconcile` writes
-- (`name = 'sponsored_enrollment_executed'`), stated here because the column
-- name alone does not carry them:
--
--   * `last_scanned_block` is the highest block whose logs have been FULLY
--     folded. The next scan starts at `last_scanned_block + 1`.
--   * It is advanced ONLY after every log in the scanned window folded without
--     error, in its own transaction, after the folds. On any error the cursor
--     is left where it was and the same window is retried on the next pass.
--     That makes the observer AT-LEAST-ONCE — re-observation is the NORMAL
--     case, not an edge case, which is why the fold in
--     `submit::reconcile_executed_for_profile_id` carries an explicit
--     idempotency guard.
--   * A window is never scanned past the confirmation depth
--     (`STREAM_G_CONFIRMATIONS`), so a block that would yield
--     `LogOutcome::NotFinalYet` is never inside a scanned window and can never
--     be skipped by an advancing cursor.
--   * `updated_at` is WALL-clock unix seconds — a diagnostic only. Nothing
--     compares it against anything, and no release, confirmation or expiry
--     decision reads it. (Every such decision in Stream G reads chain time;
--     founder ruling F2.)
--
-- The block numbers stored here are public chain positions. Nothing sealed,
-- signed, or bearer-capable is written to this table, so there is no `_enc`
-- column and none may be added without the AAD discipline in
-- `store::ENVELOPE_AAD_SCHEMA_VERSION`.

CREATE TABLE stream_g_scan_cursors (
    -- Logical name of the observer whose progress this row records.
    name               TEXT PRIMARY KEY,
    -- Highest block fully folded, inclusive. NOT the next block to scan.
    last_scanned_block INTEGER NOT NULL,
    -- Wall-clock unix seconds of the last advance. Diagnostic only.
    updated_at         INTEGER NOT NULL
);
