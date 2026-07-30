-- Stream G persistence schema (v1) — see src/stream_g/store.rs.
--
-- Design notes:
--   * Primary keys are TEXT (opaque ids minted by the application layer —
--     no AUTOINCREMENT; id generation belongs to later Stream G tasks, not
--     this schema).
--   * `*_at` timestamp columns are INTEGER unix seconds.
--   * Amount/quantity columns are TEXT (decimal string). SQLite INTEGER is
--     64-bit signed, which is not wide enough for on-chain wei amounts
--     (u128 on the Rust side elsewhere in this crate — see
--     `Config::proposer_bond_wei`); TEXT avoids silent truncation.
--   * Columns ending `_enc` are opaque BLOBs sealed by
--     `stream_g::crypto_store::seal` (XChaCha20-Poly1305) — application
--     code only, never queried or filtered on directly by SQL.
--   * Every column whose name implies a parent row has an explicit FK;
--     `StreamGStore::open` sets `PRAGMA foreign_keys=ON`. Tables are
--     ordered so each FK target is created before the table that
--     references it.
--   * Later tasks own the exact business columns for each pipeline stage;
--     this migration is deliberately conservative (nullable, loosely
--     typed) where the brief calls for it rather than guessing constraints
--     that later work would have to migrate away from.

CREATE TABLE profiles (
    id            TEXT PRIMARY KEY,
    created_at    INTEGER NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',
    profile_enc   BLOB
);

CREATE TABLE credential_aliases (
    id            TEXT PRIMARY KEY,
    profile_id    TEXT NOT NULL REFERENCES profiles(id),
    alias_type    TEXT NOT NULL,
    -- Blind index for lookup ("does this email already have a profile?")
    -- without decrypting every row. MUST be a keyed HMAC (e.g. HMAC-SHA256
    -- under a dedicated index key derived from the data key) over the
    -- normalized alias value — never a plain/unkeyed hash (e.g. bare
    -- SHA-256) of the alias, since email-shaped inputs are trivially
    -- rainbow-tabled. T3 implements the derivation.
    alias_hash    TEXT NOT NULL,
    alias_enc     BLOB,
    created_at    INTEGER NOT NULL,
    UNIQUE (alias_type, alias_hash)
);
CREATE INDEX idx_credential_aliases_profile_id ON credential_aliases(profile_id);

CREATE TABLE auth_challenges (
    id               TEXT PRIMARY KEY,
    -- Nullable: a challenge can be issued before the profile it will
    -- authenticate into is known (e.g. first-time enrollment).
    profile_id       TEXT REFERENCES profiles(id),
    challenge_type   TEXT NOT NULL,
    nonce            TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending',
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    consumed_at      INTEGER
);
CREATE INDEX idx_auth_challenges_profile_id ON auth_challenges(profile_id);

CREATE TABLE profile_sessions (
    id                   TEXT PRIMARY KEY,
    profile_id           TEXT NOT NULL REFERENCES profiles(id),
    session_token_hash   TEXT NOT NULL,
    context_enc          BLOB,
    created_at           INTEGER NOT NULL,
    expires_at           INTEGER NOT NULL,
    revoked_at           INTEGER
);
CREATE INDEX idx_profile_sessions_profile_id ON profile_sessions(profile_id);

CREATE TABLE profile_wallets (
    id            TEXT PRIMARY KEY,
    profile_id    TEXT NOT NULL REFERENCES profiles(id),
    chain_id      INTEGER NOT NULL,
    address       TEXT NOT NULL,
    wallet_type   TEXT,
    is_primary    INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    -- Mirrors the on-chain flat-star invariant (WalletSponsorshipRegistry.
    -- primaryOf binds a wallet to exactly one cluster): a wallet address
    -- may back at most one profile per chain.
    UNIQUE (chain_id, address)
);
CREATE INDEX idx_profile_wallets_profile_id ON profile_wallets(profile_id);

CREATE TABLE quotes (
    id             TEXT PRIMARY KEY,
    -- Nullable: a quote can be generated for an anonymous/pre-auth caller.
    profile_id     TEXT REFERENCES profiles(id),
    base_asset     TEXT NOT NULL,
    quote_asset    TEXT NOT NULL,
    base_amount    TEXT NOT NULL,
    quote_amount   TEXT NOT NULL,
    fee_bps        INTEGER,
    status         TEXT NOT NULL DEFAULT 'active',
    quote_enc      BLOB,
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL
);
CREATE INDEX idx_quotes_profile_id ON quotes(profile_id);

CREATE TABLE intents (
    id            TEXT PRIMARY KEY,
    profile_id    TEXT NOT NULL REFERENCES profiles(id),
    quote_id      TEXT REFERENCES quotes(id),
    intent_type   TEXT NOT NULL,
    amount        TEXT,
    status        TEXT NOT NULL DEFAULT 'pending',
    intent_enc    BLOB,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER
);
CREATE INDEX idx_intents_profile_id ON intents(profile_id);
CREATE INDEX idx_intents_quote_id ON intents(quote_id);

CREATE TABLE authorizations (
    id               TEXT PRIMARY KEY,
    intent_id        TEXT NOT NULL REFERENCES intents(id),
    profile_id       TEXT NOT NULL REFERENCES profiles(id),
    status           TEXT NOT NULL DEFAULT 'pending',
    signature_enc    BLOB,
    created_at       INTEGER NOT NULL,
    authorized_at    INTEGER,
    expires_at       INTEGER
);
CREATE INDEX idx_authorizations_intent_id ON authorizations(intent_id);
CREATE INDEX idx_authorizations_profile_id ON authorizations(profile_id);

CREATE TABLE authorization_slots (
    id                  TEXT PRIMARY KEY,
    authorization_id    TEXT NOT NULL REFERENCES authorizations(id),
    slot_index          INTEGER NOT NULL,
    amount              TEXT,
    status              TEXT NOT NULL DEFAULT 'pending',
    created_at          INTEGER NOT NULL,
    filled_at           INTEGER,
    UNIQUE (authorization_id, slot_index)
);
CREATE INDEX idx_authorization_slots_authorization_id ON authorization_slots(authorization_id);

CREATE TABLE budget_reservations (
    id            TEXT PRIMARY KEY,
    profile_id    TEXT NOT NULL REFERENCES profiles(id),
    intent_id     TEXT REFERENCES intents(id),
    asset         TEXT NOT NULL,
    amount        TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'held',
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER,
    released_at   INTEGER
);
CREATE INDEX idx_budget_reservations_profile_id ON budget_reservations(profile_id);
CREATE INDEX idx_budget_reservations_intent_id ON budget_reservations(intent_id);

CREATE TABLE nonce_allocations (
    id               TEXT PRIMARY KEY,
    chain_id         INTEGER NOT NULL,
    signer_address   TEXT NOT NULL,
    nonce            INTEGER NOT NULL,
    status           TEXT NOT NULL DEFAULT 'allocated',
    allocated_at     INTEGER NOT NULL,
    released_at      INTEGER,
    UNIQUE (chain_id, signer_address, nonce)
);
CREATE INDEX idx_nonce_allocations_signer ON nonce_allocations(chain_id, signer_address);

CREATE TABLE tx_attempts (
    id                     TEXT PRIMARY KEY,
    intent_id              TEXT REFERENCES intents(id),
    authorization_id       TEXT REFERENCES authorizations(id),
    nonce_allocation_id    TEXT REFERENCES nonce_allocations(id),
    chain_id               INTEGER NOT NULL,
    tx_hash                TEXT,
    status                 TEXT NOT NULL DEFAULT 'pending',
    raw_tx_enc             BLOB,
    error_message          TEXT,
    created_at             INTEGER NOT NULL,
    submitted_at           INTEGER,
    confirmed_at           INTEGER
);
CREATE INDEX idx_tx_attempts_intent_id ON tx_attempts(intent_id);
CREATE INDEX idx_tx_attempts_authorization_id ON tx_attempts(authorization_id);
CREATE INDEX idx_tx_attempts_nonce_allocation_id ON tx_attempts(nonce_allocation_id);

CREATE TABLE reconciliation_events (
    id               TEXT PRIMARY KEY,
    tx_attempt_id    TEXT REFERENCES tx_attempts(id),
    event_type       TEXT NOT NULL,
    status           TEXT,
    details_enc      BLOB,
    created_at       INTEGER NOT NULL
);
CREATE INDEX idx_reconciliation_events_tx_attempt_id ON reconciliation_events(tx_attempt_id);

CREATE TABLE schema_migrations (
    version        INTEGER PRIMARY KEY,
    applied_at     INTEGER NOT NULL,
    description    TEXT
);

-- Singleton row (enforced by the CHECK) recording the random per-file id
-- and the currently-applied schema version. `StreamGStore::open` generates
-- `db_uuid` once, on the migration that creates this table, and caches
-- both values for the life of the store.
CREATE TABLE store_meta (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    db_uuid           TEXT NOT NULL,
    schema_version    INTEGER NOT NULL
);
