-- Attestor persistence schema (v4) — the allowlisted fetch network's receipts.
--
-- ADDITIVE ONLY, and asserted so: `migration_0004_is_frozen_and_additive`
-- refuses this file if it ever contains a table alteration, a table or index
-- removal, or a row rewrite. Five new tables and four new indexes, nothing
-- touched. Same discipline `0003_stream_g_scan_cursor.sql` states and for the
-- same reason: a database that already recorded `schema_migrations.version = N`
-- never re-runs N, so editing an applied migration gives two deployments the
-- same recorded schema version and different schemas. New work is a new file.
--
-- ============================================================================
-- WHAT A ROW HERE MAY CONTAIN, AND WHAT IT MAY NEVER
-- ============================================================================
--
-- Zero content logging is an invariant of this lane, not a preference, and this
-- schema is one of the four places it is enforced by construction rather than
-- by review. Every column below is a byte count, an integer identifier, a
-- fixed-width hash, a signature or a timestamp.
--
-- The destination is an **allowlist entry id** — an integer index into a
-- curated manifest, itself pinned by `allowlist_manifest_digest_hex` — and
-- nothing else. There is no column here for a hostname, an address, a locator,
-- a request line, a query string, a request or response header, a cookie or a
-- payload byte, and none may be added:
-- `the_proxy_schema_contains_no_destination_identifying_column` sweeps every
-- column name in this file against that list, with a floor on the number of
-- columns swept so a broken parser cannot pass it.
--
-- One naming note, because the column and the quantity are deliberately not
-- spelled the same. `witnessed_bytes_to_consumer` holds the quantity this lane
-- calls `body_bytes_to_consumer`: response payload bytes, after the node has
-- stripped HTTP framing and decoded any chunked transfer-encoding, as they are
-- handed into the tunnel. It is a COUNT of those bytes and never one of them.
-- The column carries the `witnessed_` prefix instead so that the schema sweep
-- named above needs no exception — an exception is how the next column that
-- really does name payload content gets waved through.
--
-- ============================================================================
-- THE TWO UNIQUE INDEXES ARE THE REPLAY DEFENCE, NOT A HINT
-- ============================================================================
--
-- `epoch_id` is inside the operator's signed struct, which stops a receipt
-- being replayed into a different settlement window. That is the first of three
-- independent layers. The other two are here:
--
--   * `proxy_receipts_session_chunk  UNIQUE (session_id_hex, chunk_seq)` — one
--     row per chunk of a session, so the same chunk cannot be submitted twice
--     even under two different receipt hashes.
--   * `proxy_receipts_operator_counter  UNIQUE (operator_wallet, gateway_id_hex,
--     counter)` — the per-(operator, gateway) monotonic counter can be spent
--     once, so an operator cannot re-issue a fresh-looking receipt over the
--     same work by changing a field the first index does not cover.
--
-- Nothing downstream reads a receipt that is not a row here, so a receipt that
-- cannot be inserted cannot be settled. That is why these are constraints in
-- the schema and not checks in the caller: a caller can be bypassed by the next
-- caller, and the aggregation lane reads rows, not submissions.
--
-- ============================================================================
-- WHY DECIMAL STRINGS FOR SOME INTEGERS
-- ============================================================================
--
-- SQLite's INTEGER is a signed 64-bit value. Wei-denominated quantities in this
-- lane are `u128` (a price of one whole GOAT per mebibyte is already 1e18, and
-- an epoch total is a multiple of that), so every wei column is TEXT holding a
-- canonical decimal string — the same encoding the receipt's canonical JSON
-- uses, for the same reason. Counts and timestamps that genuinely fit are
-- INTEGER, and the store refuses a value that would not fit rather than letting
-- it wrap into a negative.
--
-- Nothing sealed, bearer-capable or secret is written to any table here — the
-- signatures are over public structs and are evidence, not credentials — so
-- there is no `_enc` column and none may be added without the envelope-AAD
-- discipline in `store::ENVELOPE_AAD_SCHEMA_VERSION`.

-- ---------------------------------------------------------------------------
-- What the two parties agreed to before any byte moved.
-- ---------------------------------------------------------------------------
CREATE TABLE proxy_session_intents (
    -- keccak256 of the EIP-712 struct. Receipts reference this.
    intent_hash_hex               TEXT PRIMARY KEY,
    epoch_id                      INTEGER NOT NULL,
    session_id_hex                TEXT    NOT NULL,
    operator_wallet               TEXT    NOT NULL,
    consumer_id_hex               TEXT    NOT NULL,
    gateway_id_hex                TEXT    NOT NULL,
    -- The destination, in full: an index into the curated manifest below.
    allowlist_entry_id            INTEGER NOT NULL,
    allowlist_manifest_digest_hex TEXT    NOT NULL,
    -- Ceiling the session may not exceed, agreed in advance.
    max_bytes                     INTEGER NOT NULL,
    valid_from_unix               INTEGER NOT NULL,
    valid_to_unix                 INTEGER NOT NULL,
    -- Decimal string; see the header.
    price_goat_wei_per_mebibyte   TEXT    NOT NULL,
    consumer_signature_hex        TEXT    NOT NULL,
    -- The address recovered from that signature, not the one submitted.
    consumer_signer               TEXT    NOT NULL,
    recorded_at_unix              INTEGER NOT NULL,

    CHECK (epoch_id >= 0),
    CHECK (max_bytes > 0),
    CHECK (valid_to_unix > valid_from_unix)
);

-- ---------------------------------------------------------------------------
-- One 10-MiB-or-smaller slice of one session, signed by all three parties.
-- ---------------------------------------------------------------------------
CREATE TABLE proxy_receipts (
    -- keccak256 of the receipt's canonical JSON bytes. NOT the EIP-712 digest.
    receipt_hash_hex              TEXT PRIMARY KEY,
    epoch_id                      INTEGER NOT NULL,
    session_id_hex                TEXT    NOT NULL,
    chunk_seq                     INTEGER NOT NULL,
    chunk_kind                    TEXT    NOT NULL,
    operator_wallet               TEXT    NOT NULL,
    consumer_id_hex               TEXT    NOT NULL,
    gateway_id_hex                TEXT    NOT NULL,
    allowlist_entry_id            INTEGER NOT NULL,
    allowlist_manifest_digest_hex TEXT    NOT NULL,
    -- The operator's CLAIM.
    bytes_transferred             INTEGER NOT NULL,
    -- Per-(operator, gateway) monotonic counter; see the replay indexes.
    counter                       INTEGER NOT NULL,
    intent_hash_hex               TEXT    NOT NULL
                                      REFERENCES proxy_session_intents (intent_hash_hex),
    consent_record_hash_hex       TEXT    NOT NULL,
    valid_from_unix               INTEGER NOT NULL,
    valid_to_unix                 INTEGER NOT NULL,
    price_goat_wei_per_mebibyte   TEXT    NOT NULL,
    -- The gateway's WITNESSED count. Verification already required this to
    -- equal `bytes_transferred` exactly, in both directions; it is stored
    -- because a stored equality can be re-checked by anybody reading the file.
    witnessed_bytes_to_consumer   INTEGER NOT NULL,
    -- RE-SIGNED BY THE GATEWAY, NEVER WITNESSED BY IT. Nothing in this system
    -- observes the origin leg, so this is a node assertion the gateway relayed.
    -- It is never a settlement basis and nothing compares it to anything.
    node_reported_from_origin     INTEGER NOT NULL,
    witnessed_at_unix             INTEGER NOT NULL,
    operator_signature_hex        TEXT    NOT NULL,
    consumer_signature_hex        TEXT    NOT NULL,
    gateway_signature_hex         TEXT    NOT NULL,
    -- Recovered addresses, not submitted ones.
    operator_signer               TEXT    NOT NULL,
    consumer_signer               TEXT    NOT NULL,
    gateway_signer                TEXT    NOT NULL,
    -- The deployment the three digests were bound to.
    chain_id                      INTEGER NOT NULL,
    verifying_contract            TEXT    NOT NULL,
    recorded_at_unix              INTEGER NOT NULL,

    CHECK (chunk_kind IN ('INTERIM', 'FINAL')),
    CHECK (bytes_transferred > 0),
    CHECK (bytes_transferred <= 10485760),
    CHECK (witnessed_bytes_to_consumer = bytes_transferred),
    CHECK (chunk_seq >= 0),
    CHECK (counter >= 0),
    CHECK (epoch_id >= 0)
);

-- Replay defence, layer 2: one row per chunk of a session.
CREATE UNIQUE INDEX proxy_receipts_session_chunk
    ON proxy_receipts (session_id_hex, chunk_seq);

-- Replay defence, layer 3: a counter is spent once per (operator, gateway).
CREATE UNIQUE INDEX proxy_receipts_operator_counter
    ON proxy_receipts (operator_wallet, gateway_id_hex, counter);

-- The aggregation read pattern: every receipt of one epoch, by operator.
CREATE INDEX proxy_receipts_by_epoch
    ON proxy_receipts (epoch_id, operator_wallet);

-- ---------------------------------------------------------------------------
-- The gateway's own per-session totals, retrievable independently of whoever
-- proposes an epoch. This is what replaces the public oracle bandwidth does not
-- have: a contemporaneous second counter held by a party that is not settled
-- per byte.
-- ---------------------------------------------------------------------------
CREATE TABLE proxy_meter_commitments (
    gateway_id_hex              TEXT    NOT NULL,
    epoch_id                    INTEGER NOT NULL,
    session_id_hex              TEXT    NOT NULL,
    -- The witnessed quantity, summed over the session.
    witnessed_bytes_to_consumer INTEGER NOT NULL,
    -- Re-signed, never witnessed. See `proxy_receipts`.
    node_reported_from_origin   INTEGER NOT NULL,
    commitment_hash_hex         TEXT    NOT NULL,
    gateway_signature_hex       TEXT    NOT NULL,
    observed_at_unix            INTEGER NOT NULL,
    recorded_at_unix            INTEGER NOT NULL,

    PRIMARY KEY (gateway_id_hex, epoch_id, session_id_hex),
    CHECK (witnessed_bytes_to_consumer >= 0),
    CHECK (epoch_id >= 0)
);

-- ---------------------------------------------------------------------------
-- Per-operator epoch totals: what the aggregation lane folds into one Merkle
-- leaf each. Written once an epoch's receipts are complete.
-- ---------------------------------------------------------------------------
CREATE TABLE proxy_epoch_totals (
    epoch_id               INTEGER NOT NULL,
    operator_wallet        TEXT    NOT NULL,
    total_bytes            INTEGER NOT NULL,
    receipt_count          INTEGER NOT NULL,
    -- Decimal strings; all three are wei-denominated u128 quantities.
    gross_goat_wei         TEXT    NOT NULL,
    operator_goat_wei      TEXT    NOT NULL,
    protocol_take_goat_wei TEXT    NOT NULL,
    -- The take in force when these totals were folded, so a later policy change
    -- cannot silently re-interpret a settled epoch.
    take_bps               INTEGER NOT NULL,
    recorded_at_unix       INTEGER NOT NULL,

    PRIMARY KEY (epoch_id, operator_wallet),
    CHECK (total_bytes >= 0),
    CHECK (receipt_count >= 0),
    CHECK (take_bps >= 0 AND take_bps <= 10000)
);

-- ---------------------------------------------------------------------------
-- One row per proposed epoch: the root, and the totals it commits to.
-- ---------------------------------------------------------------------------
CREATE TABLE proxy_epoch_batches (
    epoch_id                     INTEGER PRIMARY KEY,
    merkle_root_hex              TEXT    NOT NULL,
    operator_count               INTEGER NOT NULL,
    total_bytes                  INTEGER NOT NULL,
    total_operator_goat_wei      TEXT    NOT NULL,
    total_protocol_take_goat_wei TEXT    NOT NULL,
    take_bps                     INTEGER NOT NULL,
    status                       TEXT    NOT NULL,
    proposed_at_unix             INTEGER,
    recorded_at_unix             INTEGER NOT NULL,

    CHECK (operator_count >= 0),
    CHECK (total_bytes >= 0),
    CHECK (take_bps >= 0 AND take_bps <= 10000)
);

CREATE INDEX proxy_epoch_batches_by_status
    ON proxy_epoch_batches (status, epoch_id);
