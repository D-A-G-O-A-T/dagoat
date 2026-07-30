-- Stream G persistence schema (v2) — outbox / broadcaster / reconcile.
--
-- ADDITIVE ONLY. `0001_stream_g.sql` is frozen and byte-identical (asserted
-- by `store::tests::migration_0001_is_byte_identical`); every later change
-- arrives as a new numbered file applied by `store::apply_pending_migrations`
-- inside its own `BEGIN IMMEDIATE` transaction.
--
-- Design notes:
--   * SQLite `ALTER TABLE ... ADD COLUMN` can only append a column with a
--     constant default, which is why every NOT NULL column here carries one.
--     That is also what makes the upgrade of an existing v1 database
--     lossless: pre-existing rows are backfilled with the default rather
--     than rewritten.
--   * `claim_owner` / `lease_until` are the spec §9.3 compare-and-swap pair:
--     which process currently holds a row, and when that hold expires. The
--     lease clock is WALL clock (it is only the sweeper's *trigger*); the
--     decision to release anything is made from chain evidence, never from
--     this column (founder ruling F2).
--   * Nothing in this file changes an existing column, constraint or index.

-- ---------------------------------------------------------------------------
-- tx_attempts — durable attempt lifecycle
-- ---------------------------------------------------------------------------

-- A4: many ordered attempts per nonce allocation (replacement transactions).
-- Existing rows are attempt 0.
ALTER TABLE tx_attempts ADD COLUMN attempt_number INTEGER NOT NULL DEFAULT 0;

-- Spec §9.3 CAS: which process/worker currently holds this row. NULL = free.
ALTER TABLE tx_attempts ADD COLUMN claim_owner TEXT;

-- Spec §9.3 CAS: wall-clock unix seconds at which `claim_owner`'s hold
-- expires. NULL = not claimed.
ALTER TABLE tx_attempts ADD COLUMN lease_until INTEGER;

-- Hash of the SIGNED RAW transaction, known BEFORE broadcast (founder ruling
-- F2). Deliberately distinct from `tx_hash`, which is only written once a
-- node has ACCEPTED the transaction (`record_submitted`): a row that has a
-- `raw_tx_hash` but no `tx_hash` is exactly the "we signed it, we do not know
-- whether it reached a mempool" state that a time-only sweeper cannot resolve.
ALTER TABLE tx_attempts ADD COLUMN raw_tx_hash TEXT;

-- Reverse lookup for a log-driven reconciler, which observes only the
-- on-chain `intentId` and has no way back to a profile: both `intents.id` and
-- `tx_attempts.id` are SHA-256 over the profile id, and `intents` has no
-- plaintext intent id column at all (the raw value lives only inside the
-- sealed `intent_enc` blob).
--
-- DELIBERATELY NOT UNIQUE. Per-profile intentId namespacing is a security
-- fix, not an accident: a globally-unique binding would let any authenticated
-- profile permanently claim any 32-byte intentId for everybody (defect C2,
-- guarded by `quotes::tests::
-- two_profiles_can_quote_the_same_onchain_intent_id_without_colliding`).
-- Reverse lookup therefore returns a CANDIDATE SET; the winner is
-- disambiguated by transaction hash. On chain only one candidate can ever
-- have executed, because `intentUsed[intentId]` is global and single-use.
ALTER TABLE tx_attempts ADD COLUMN intent_id_hex TEXT;

-- The TTL sweep selects on (status, lease_until). Without this index that is
-- a full table scan on a pool with exactly one connection.
CREATE INDEX idx_tx_attempts_status_lease ON tx_attempts(status, lease_until);

-- Reverse lookup (non-unique, see `intent_id_hex` above).
CREATE INDEX idx_tx_attempts_intent_id_hex ON tx_attempts(intent_id_hex);

-- Spec §9.3 uniqueness: a transaction hash identifies at most one attempt.
-- PARTIAL (`WHERE tx_hash IS NOT NULL`) so the many rows that have not been
-- broadcast yet — all of which carry a NULL `tx_hash` — do not collide with
-- each other. SQLite treats NULLs as distinct in a plain UNIQUE index too,
-- but the partial form states the intent and keeps the index small.
CREATE UNIQUE INDEX idx_tx_attempts_hash ON tx_attempts(tx_hash) WHERE tx_hash IS NOT NULL;

-- ---------------------------------------------------------------------------
-- nonce_allocations — explicit row-kind discriminator
-- ---------------------------------------------------------------------------

-- Two different key spaces now share this table:
--
--   kind='action'      — the GATEWAY ACTION nonce `actionNonces[signer][type]`,
--                        whose 2-D on-chain key is folded into the single
--                        `signer_address` column as "<0xcontroller>#<ACTION>".
--   kind='broadcaster' — the BROADCASTER EOA transaction nonce, whose
--                        `signer_address` is a BARE "0x…" address.
--
-- The two are mechanically disjoint today (a synthetic key contains '#', a
-- bare address does not) but relying on that implicit discrimination is
-- exactly the shape that produced Critical C2. This column makes it explicit.
-- EVERY query against this table must filter on `kind`.
--
-- `DEFAULT 'action'` is load-bearing, not cosmetic: it backfills every
-- pre-0002 row — all of which are gateway action nonces — correctly. A row
-- inserted without an explicit `kind` must never read back as a broadcaster
-- row.
ALTER TABLE nonce_allocations ADD COLUMN kind TEXT NOT NULL DEFAULT 'action';

-- Spec §9.3 CAS, same contract as the `tx_attempts` pair above.
ALTER TABLE nonce_allocations ADD COLUMN claim_owner TEXT;
ALTER TABLE nonce_allocations ADD COLUMN lease_until INTEGER;

-- Kind-scoped lookup, so the common "which nonces does this signer hold, of
-- this kind" query never has to consider the other key space at all.
CREATE INDEX idx_nonce_allocations_kind_signer ON nonce_allocations(kind, chain_id, signer_address);
