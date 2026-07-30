//! Stream G — durable submit outbox (Task 7, Wave B).
//!
//! This module owns the half of the submit pipeline that has to survive a
//! process death: the signed raw transaction is **persisted before it is
//! broadcast**, and a stale reservation is resolved **against chain evidence**
//! rather than against a clock.
//!
//! ## Why this exists — the state that was unrecoverable by construction
//!
//! `submit.rs`'s reservation commits at `submit.rs:1300` and the broadcast
//! happens at `:1307`. A process death in between leaves a `tx_attempts` row
//! with `status='reserved'`, `tx_hash NULL`, `submitted_at NULL` **and
//! `raw_tx_enc NULL`** — nothing in the crate wrote `raw_tx_enc` before this
//! module (`grep -rn raw_tx_enc src/` was 0 hits outside the schema). That row
//! wedges the intent forever: the reservation refuses a resubmit with
//! [`super::submit::SubmitError::SubmitInFlight`], and there is no hash to
//! look the transaction up by, so no amount of chain reading can decide
//! whether it landed.
//!
//! **Task 8 Wave B (Mandate 1) removed the last way to reach that state.**
//! `submit.rs` used to carry its own copy of this reservation,
//! `reserve_action_nonce`, which wrote neither `raw_tx_enc` nor
//! `raw_tx_hash` — so the *production* submit path was precisely the one this
//! module could not recover. That copy is deleted;
//! [`reserve_and_persist_raw_tx`] is now the crate's only reservation, and
//! `submit::submit_sponsored_enrollment` calls it.
//!
//! ## Founder ruling F2 — time is the trigger, chain state is the authority
//!
//! A duplicate broadcast is **safe but expensive**: `_markIntentAndNonce`
//! (`GoatRelayGateway.sol:315-323`) reverts with `IntentAlreadyUsed` /
//! `BadActionNonce`, and a revert persists nothing — so correctness survives,
//! but the relayer pays gas every time. That is why a *timer* may never
//! release a reservation on its own. The sweeper here:
//!
//! 1. **triggers** on wall clock (`status='reserved' AND lease_until < now`),
//! 2. **refuses** to release anything whose parent intent is still valid on the
//!    **chain** clock,
//! 3. **resolves** against the chain — receipt by `raw_tx_hash`, then
//!    `intentUsed(intentId)`,
//! 4. **fails closed** — every `Err` from an RPC leaves the row `reserved` and
//!    is reported as *stuck-recoverable*. There is no path from an `Err` to a
//!    release.
//!
//! ### The one place this module synthesises two sections of the brief
//!
//! Brief §5.1 step 3a says a **mined revert** is "`failed` + release"; brief
//! §5.3 says a mined revert "holds the signed nonce slots until the old payload
//! expires" (spec §8.2). Those disagree. This module takes the strictly safer
//! reading: a mined revert is treated as *evidence of non-consumption*, but the
//! release still has to pass the chain-time guard in step 2 — so the nonce is
//! held while the signed payload could still be replayed by anybody, and is
//! released once it can no longer execute. See [`Resolution`]. This divergence
//! is disclosed rather than silently chosen.
//!
//! ## Where the sweeper runs: [`super::maintenance`], since Task 8 Wave D
//!
//! This section used to say "nowhere yet, deliberately" —
//! [`sweep_stuck_reservations`] was a callable, tested primitive with no
//! spawner, because `tokio::spawn` appeared nowhere in `src/` and `axum::serve`
//! was mounted without graceful shutdown, so a task started here would have had
//! no owner and no way to stop. Task 8 supplied both halves: Wave A the
//! shutdown token and the single locked store handle, Wave D the loop.
//!
//! It is now called from [`super::maintenance::run_sweep`], once per pass of
//! the background loop `main.rs` spawns when `STREAM_G_ENABLED=1` — cadence
//! `STREAM_G_SWEEP_INTERVAL_SECONDS` (default 900, A2's trigger period), lease
//! TTL `STREAM_G_OUTBOX_LEASE_TTL_SECONDS` (the env key this module named,
//! default [`DEFAULT_LEASE_TTL_SECONDS`]), batch `STREAM_G_SWEEP_MAX_ROWS`
//! (default [`DEFAULT_SWEEP_MAX_ROWS`]). The loop **skips the sweep entirely**
//! when there is no live chain client (`GOAT_ATTESTOR_MOCK=1`): without chain
//! evidence there is no release authority, and skipping is the fail-closed
//! direction. It remains directly callable, which is how every test here runs
//! it.
//!
//! ## Store discipline
//!
//! [`super::store::StreamGStore`]'s pool has exactly one connection, so calling
//! a store method from inside a `write_tx` closure deadlocks until
//! `sqlx::Error::PoolTimedOut`. Every value the closures here need out of the
//! store — `db_uuid`, the envelope AAD version — is pulled into an owned local
//! *first* and the [`EnvelopeAad`] is built by hand inside the closure, the
//! same shape as `root_authorization.rs:687-733`. Chain reads likewise happen
//! **between** transactions, never inside one: an RPC that hangs must not hold
//! SQLite's writer lock.
//!
//! ## Profile-ownership boundary
//!
//! The first statement of `submit.rs`'s reservation is an ownership re-check,
//! `SELECT profile_id FROM intents WHERE id = ?` → `IntentNotFound`
//! (`submit.rs:1383-1393`). [`reserve_and_persist_raw_tx`] keeps it verbatim.
//! The sweeper has no requesting profile — it acts as the attestor — so it
//! preserves the boundary the only way it can: it only ever touches an attempt
//! that still joins to an existing `intents` row, it carries that row's
//! `profile_id` through the claim, and its apply-phase `UPDATE`s re-assert the
//! same `(intent, profile)` pairing so a row cannot be resolved against a
//! parent it no longer belongs to.

use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::Row;
use thiserror::Error;

use super::base_fee::{GasUnits, MaxFeePerGas};
use super::crypto_store::{self, CryptoStoreError, DataKey, EnvelopeAad, SecretHex};
use super::models::ActionType;
use super::store::{StreamGStore, StreamGStoreError};
use super::submit::{
    action_nonce_signer_key, intent_row_id, nonce_allocation_row_id, tx_attempt_row_id,
    INTENT_STATUS_SUBMITTED, NONCE_STATUS_ALLOCATED, NONCE_STATUS_CONSUMED, NONCE_STATUS_RELEASED,
    TX_ATTEMPT_STATUS_CONFIRMED, TX_ATTEMPT_STATUS_FAILED, TX_ATTEMPT_STATUS_RESERVED,
    TX_ATTEMPT_STATUS_SUBMITTED,
};
use super::token_manifest::TrustedChain;
use crate::chain::TxHash;
use crate::merkle::keccak256;

// ---------------------------------------------------------------------------
// Error codes (stable strings for logs / HTTP mapping), same convention as
// `submit.rs`.
// ---------------------------------------------------------------------------

pub const ERR_OUTBOX_STORE: &str = "OUTBOX_STORE_ERROR";
pub const ERR_OUTBOX_CRYPTO: &str = "OUTBOX_CRYPTO_ERROR";
pub const ERR_OUTBOX_INTENT_NOT_FOUND: &str = "OUTBOX_INTENT_NOT_FOUND";
pub const ERR_OUTBOX_IN_FLIGHT: &str = "OUTBOX_IN_FLIGHT";
pub const ERR_OUTBOX_ALREADY_SUBMITTED: &str = "OUTBOX_ALREADY_SUBMITTED";
pub const ERR_OUTBOX_NONCE_ALREADY_RESERVED: &str = "OUTBOX_NONCE_ALREADY_RESERVED";
pub const ERR_OUTBOX_NONCE_OUT_OF_RANGE: &str = "OUTBOX_NONCE_OUT_OF_RANGE";
pub const ERR_OUTBOX_CLAIM_LOST: &str = "OUTBOX_CLAIM_LOST";

/// `nonce_allocations.kind` for the **gateway action nonce**
/// (`actionNonces[signer][actionType]`), whose `signer_address` is the
/// `"<0xcontroller>#<ACTION>"` synthetic key.
///
/// `0002_stream_g_outbox.sql` added this discriminator because the same table
/// now also holds broadcaster-EOA rows (`kind='broadcaster'`, bare `0x…`
/// address). **Every** query in this module filters on it; relying on "a
/// synthetic key contains `#` and an address does not" is the implicit
/// discrimination that produced defect C2.
pub const NONCE_KIND_ACTION: &str = "action";

/// Wall-clock seconds a claim/lease is good for, and therefore how long a
/// `reserved` row waits before the sweeper will look at it (architect
/// assumption A2 — the trigger is wall clock, the *decision* is chain time).
///
/// Env override (`STREAM_G_OUTBOX_LEASE_TTL_SECONDS`) is Task 8's wiring, not
/// this wave's: nothing schedules the sweeper yet, so a config key for its
/// period would be a key no code reads.
pub const DEFAULT_LEASE_TTL_SECONDS: i64 = 900;

/// Default cap on rows one sweep claims. A sweep does one chain round-trip per
/// row, so an unbounded batch would hold the claim on rows it cannot service
/// for as long as the slowest RPC in the batch takes.
pub const DEFAULT_SWEEP_MAX_ROWS: i64 = 64;

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum OutboxError {
    #[error("store error: {0}")]
    Store(#[from] StreamGStoreError),
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoStoreError),
    /// Raised both when no such intent row exists and when it exists under a
    /// different profile — `root_authorization.rs`'s litigated posture: an
    /// owner check whose failure is distinguishable from "not found" is an
    /// existence oracle.
    #[error("no sponsored-enrollment intent for this profile")]
    IntentNotFound,
    #[error("a prior submit for this intent is still in flight (attempt {attempt_id})")]
    InFlight { attempt_id: String },
    #[error("this intent was already submitted as {tx_hash_hex}")]
    AlreadySubmitted { tx_hash_hex: String },
    #[error("action nonce {nonce} for {signer} on chain {chain_id} is already reserved by attempt {holder}")]
    NonceAlreadyReserved {
        chain_id: u64,
        signer: String,
        nonce: u64,
        holder: String,
    },
    #[error("value {0} does not fit the schema's INTEGER column")]
    OutOfRange(u64),
    /// The compare-and-swap lost: between reading the row and writing it, some
    /// other worker took the claim. Never an error the caller can "fix" — the
    /// row now belongs to whoever holds the lease.
    #[error("lost the claim on attempt {attempt_id}")]
    ClaimLost { attempt_id: String },
}

impl OutboxError {
    pub fn code(&self) -> &'static str {
        match self {
            OutboxError::Store(_) | OutboxError::Sqlx(_) => ERR_OUTBOX_STORE,
            OutboxError::Crypto(_) => ERR_OUTBOX_CRYPTO,
            OutboxError::IntentNotFound => ERR_OUTBOX_INTENT_NOT_FOUND,
            OutboxError::InFlight { .. } => ERR_OUTBOX_IN_FLIGHT,
            OutboxError::AlreadySubmitted { .. } => ERR_OUTBOX_ALREADY_SUBMITTED,
            OutboxError::NonceAlreadyReserved { .. } => ERR_OUTBOX_NONCE_ALREADY_RESERVED,
            OutboxError::OutOfRange(_) => ERR_OUTBOX_NONCE_OUT_OF_RANGE,
            OutboxError::ClaimLost { .. } => ERR_OUTBOX_CLAIM_LOST,
        }
    }
}

// ---------------------------------------------------------------------------
// Small helpers (each `stream_g` module keeps its own copies by this tree's
// convention — see `root_authorization.rs`'s module doc).
// ---------------------------------------------------------------------------

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn bytes32_hex(b: [u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

fn parse_bytes32(s: &str) -> Option<[u8; 32]> {
    let t = s.trim();
    let h = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if h.len() != 64 {
        return None;
    }
    let b = hex::decode(h).ok()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Some(out)
}

// ---------------------------------------------------------------------------
// The signed payload.
// ---------------------------------------------------------------------------

/// A signed, RLP-encoded transaction plus the hash a node will know it by,
/// plus the two gas parameters the native-exposure gate needs.
///
/// The hash is **derived here, not supplied**: an Ethereum transaction hash is
/// `keccak256` of exactly the bytes that go on the wire, so letting a caller
/// pass a hash alongside the bytes would allow a row whose `raw_tx_hash` does
/// not identify its own `raw_tx_enc` — and that row is precisely the one the
/// sweeper would then look up the wrong transaction for.
///
/// ## `gas_limit` / `max_fee_per_gas` are ASSERTED, not decoded
///
/// The two gas fields exist because `base_fee::submit_exposure` needs
/// `gas_limit * max_fee_per_gas` and there was previously **nowhere on the
/// submit path** those values lived — not here, not on
/// `SponsoredEnrollmentCall`, not on `QuoteCommitment`, not in the
/// database. They are required at construction ([`SignedRawTx::new`] takes
/// them positionally as `base_fee`'s no-`From`-impl newtypes, so a call
/// site can neither omit nor transpose them), and they are `Copy` scalars
/// carried alongside `raw`.
///
/// **They are the signer's claim about the bytes, not a fact read out of
/// them.** Nothing here parses `raw` as EIP-2718; a signer that reported a
/// gas limit different from the one it actually signed would yield a wrong
/// exposure figure that no code in this crate could detect. Decoding the
/// payload instead is not currently implementable — every `SignedRawTx`
/// outside a real signer is a six-byte sentinel (`0xf8 0x6b` is an RLP
/// long-list header declaring 0x6b payload bytes with three present:
/// truncated by construction), and neither signing seam has a production
/// implementor yet. When one exists, decoding `raw` and *comparing* it
/// against these fields is the strictly stronger move; this doc is the
/// note that it has not been made.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedRawTx {
    raw: Vec<u8>,
    hash: TxHash,
    gas_limit: GasUnits,
    max_fee_per_gas: MaxFeePerGas,
}

/// Manual `Debug`: a signed transaction is not secret, but it is large and
/// dumping it into a log line is never what the reader wanted.
impl std::fmt::Debug for SignedRawTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedRawTx")
            .field("hash", &bytes32_hex(self.hash))
            .field("len", &self.raw.len())
            .field("gas_limit", &self.gas_limit.get())
            .field("max_fee_per_gas", &self.max_fee_per_gas.get())
            .finish()
    }
}

impl SignedRawTx {
    /// `gas_limit` and `max_fee_per_gas` are what the signer signed
    /// against; see the type doc — they are asserted, not verified.
    pub fn new(raw: Vec<u8>, gas_limit: GasUnits, max_fee_per_gas: MaxFeePerGas) -> Self {
        let hash = keccak256(&raw);
        Self {
            raw,
            hash,
            gas_limit,
            max_fee_per_gas,
        }
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn hash(&self) -> TxHash {
        self.hash
    }

    pub fn hash_hex(&self) -> String {
        bytes32_hex(self.hash)
    }

    /// The signer's asserted gas limit — see the type doc.
    pub fn gas_limit(&self) -> GasUnits {
        self.gas_limit
    }

    /// The signer's asserted max fee per gas, in wei — see the type doc.
    pub fn max_fee_per_gas(&self) -> MaxFeePerGas {
        self.max_fee_per_gas
    }
}

// ---------------------------------------------------------------------------
// Reservation — persist BEFORE broadcast.
// ---------------------------------------------------------------------------

/// Everything the reservation needs that is not the signed payload.
pub struct ReservationRequest<'a> {
    /// Already-authenticated profile id. Not a request field.
    pub profile_id: &'a str,
    /// The on-chain `intentId`. Namespaced per profile before it is used as a
    /// row id (defect C2) — see [`intent_row_id`].
    pub intent_id: [u8; 32],
    pub chain_id: u64,
    pub controller: [u8; 20],
    pub action: ActionType,
    /// `actionNonces[controller][action]` this attempt signed against.
    pub action_nonce: u64,
    /// Identifies the process/worker taking the claim (spec §9.3 CAS).
    pub claim_owner: &'a str,
    pub lease_ttl_seconds: i64,
}

/// What the reservation wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedAttempt {
    pub attempt_id: String,
    pub allocation_id: String,
    /// A4: attempts are ordered per intent, so a replacement transaction is a
    /// new attempt number on the same row rather than an untracked overwrite.
    pub attempt_number: i64,
    pub raw_tx_hash_hex: String,
    pub lease_until: i64,
}

/// Reserve the action nonce **and durably persist the signed transaction**,
/// in one `BEGIN IMMEDIATE` transaction, before anything is broadcast.
///
/// This is the plan's `reserve_before_broadcast_and_persist_raw_tx`, and since
/// Task 8 Wave B (Mandate 1) it is **the crate's only reservation**: both
/// [`super::submit::submit_sponsored_enrollment`] and
/// [`super::broadcaster::sign_persist_and_broadcast`] execute this function
/// and no other. It performs the exclusion `submit.rs`'s deleted
/// `reserve_action_nonce` used to duplicate — ownership re-check,
/// prior-attempt check, `UNIQUE (chain_id, signer_address, nonce)` claim —
/// plus the four things that make a crash recoverable:
///
/// * `raw_tx_enc` — the signed payload, sealed under the row's own AAD;
/// * `raw_tx_hash` — what a node will know it by, so a receipt can be fetched
///   for a transaction we never got a `tx_hash` back for;
/// * `intent_id_hex` — the §3.2 reverse lookup, non-unique by design;
/// * `claim_owner` / `lease_until` — the spec §9.3 compare-and-swap pair.
///
/// `raw_tx_enc` and `raw_tx_hash` are written in the **same** transaction as
/// the reservation, so there is no window in which a nonce is claimed by a row
/// that cannot be resolved.
pub async fn reserve_and_persist_raw_tx(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    req: &ReservationRequest<'_>,
    signed: &SignedRawTx,
    now_wall: i64,
) -> Result<ReservedAttempt, OutboxError> {
    let data_key = DataKey::from_secret(data_key_hex);

    let signer_key = action_nonce_signer_key(req.controller, req.action);
    let allocation_id = nonce_allocation_row_id(req.chain_id, &signer_key, req.action_nonce);
    let intent_row = intent_row_id(req.profile_id, req.intent_id);
    let nonce_i64 =
        i64::try_from(req.action_nonce).map_err(|_| OutboxError::OutOfRange(req.action_nonce))?;
    let chain_id_i64 =
        i64::try_from(req.chain_id).map_err(|_| OutboxError::OutOfRange(req.chain_id))?;
    let lease_until = now_wall.saturating_add(req.lease_ttl_seconds);

    // Store discipline: pull everything `envelope_aad` would have read out of
    // the store into owned locals now, and build the AAD by hand inside the
    // closure. Calling `store.envelope_aad(..)` from in there is a call back
    // into the store on a one-connection pool — `PoolTimedOut`, not a
    // compile error. Precedent: `root_authorization.rs:687-733`.
    let db_uuid = store.db_uuid().to_string();
    // `envelope_aad_version()`, NOT `schema_version()`: the live schema version
    // moved to 2 with `0002`, and feeding it into the AAD would make every
    // envelope sealed under version 1 undecryptable.
    let aad_version = store.envelope_aad_version();

    let raw_tx = signed.raw.clone();
    let raw_tx_hash_hex = signed.hash_hex();
    let intent_id_hex = bytes32_hex(req.intent_id);
    let profile_id = req.profile_id.to_string();
    let claim_owner = req.claim_owner.to_string();
    // Wave E (A4): the attempt row id is derived INSIDE the writing
    // transaction, because the attempt number depends on rows this caller
    // cannot read without racing. Both inputs travel in instead.
    let profile_id_tx = profile_id.clone();
    let intent_id_bytes = req.intent_id;
    let allocation_id_tx = allocation_id.clone();
    let signer_key_tx = signer_key.clone();
    let raw_tx_hash_hex_tx = raw_tx_hash_hex.clone();

    let (attempt_id, attempt_number) = store
        .write_tx(move |tx| {
            Box::pin(async move {
                // (1) Ownership boundary, verbatim from `submit.rs:1383-1393`.
                // Re-checked inside the writing transaction even if a caller
                // checked it earlier: that was a different transaction.
                let irow = sqlx::query("SELECT profile_id FROM intents WHERE id = ?")
                    .bind(&intent_row)
                    .fetch_optional(&mut **tx)
                    .await?;
                let Some(irow) = irow else {
                    return Err(OutboxError::IntentNotFound);
                };
                let owner: String = irow.try_get("profile_id")?;
                if owner != profile_id {
                    return Err(OutboxError::IntentNotFound);
                }

                // (2) Wave E (A4): is ANY attempt for this intent still live?
                //
                // Not "does THE row exist" — an intent now owns an ordered
                // ledger of attempts. `intent_id` is the FK to `intents.id`,
                // itself `sha256(domain | profile | intentId)`, so this
                // predicate is already per-profile namespaced.
                //
                // `intentUsed[intentId]` is global and single-use
                // (`GoatRelayGateway.sol:315-323`), so at most one attempt can
                // ever land; the two early returns below are what keep at most
                // one outstanding at a time.
                let arows = sqlx::query(
                    "SELECT id, status, tx_hash, attempt_number FROM tx_attempts \
                     WHERE intent_id = ? ORDER BY attempt_number ASC",
                )
                .bind(&intent_row)
                .fetch_all(&mut **tx)
                .await?;
                let mut next_attempt_number = 0i64;
                for arow in &arows {
                    let status: String = arow.try_get("status")?;
                    let number: i64 = arow.try_get("attempt_number")?;
                    next_attempt_number = next_attempt_number.max(number.saturating_add(1));
                    match status.as_str() {
                        TX_ATTEMPT_STATUS_SUBMITTED | TX_ATTEMPT_STATUS_CONFIRMED => {
                            let tx_hash: Option<String> = arow.try_get("tx_hash")?;
                            return Err(OutboxError::AlreadySubmitted {
                                tx_hash_hex: tx_hash.unwrap_or_default(),
                            });
                        }
                        TX_ATTEMPT_STATUS_RESERVED => {
                            let id: String = arow.try_get("id")?;
                            return Err(OutboxError::InFlight { attempt_id: id });
                        }
                        // `failed`: that attempt released the nonce and is a
                        // terminal record. The replacement becomes attempt N+1
                        // BESIDE it, never an overwrite OF it.
                        _ => {}
                    }
                }
                let attempt_id_tx =
                    tx_attempt_row_id(&profile_id_tx, intent_id_bytes, next_attempt_number);

                // (3) Claim the action nonce. `kind` is filtered explicitly —
                // the broadcaster-EOA rows live in this same table now.
                let nrow =
                    sqlx::query("SELECT status FROM nonce_allocations WHERE id = ? AND kind = ?")
                        .bind(&allocation_id_tx)
                        .bind(NONCE_KIND_ACTION)
                        .fetch_optional(&mut **tx)
                        .await?;
                if let Some(nrow) = nrow {
                    let status: String = nrow.try_get("status")?;
                    if status == NONCE_STATUS_ALLOCATED || status == NONCE_STATUS_CONSUMED {
                        let holder = sqlx::query(
                            "SELECT id FROM tx_attempts \
                             WHERE nonce_allocation_id = ? AND id != ? AND status IN (?, ?, ?)",
                        )
                        .bind(&allocation_id_tx)
                        .bind(&attempt_id_tx)
                        .bind(TX_ATTEMPT_STATUS_RESERVED)
                        .bind(TX_ATTEMPT_STATUS_SUBMITTED)
                        .bind(TX_ATTEMPT_STATUS_CONFIRMED)
                        .fetch_optional(&mut **tx)
                        .await?;
                        if let Some(holder) = holder {
                            let holder_id: String = holder.try_get("id")?;
                            return Err(OutboxError::NonceAlreadyReserved {
                                chain_id: chain_id_i64 as u64,
                                signer: signer_key_tx.clone(),
                                nonce: nonce_i64 as u64,
                                holder: holder_id,
                            });
                        }
                    }
                    let ru = sqlx::query(
                        "UPDATE nonce_allocations \
                         SET status = ?, allocated_at = ?, released_at = NULL, \
                             claim_owner = ?, lease_until = ? \
                         WHERE id = ? AND kind = ?",
                    )
                    .bind(NONCE_STATUS_ALLOCATED)
                    .bind(now_wall)
                    .bind(&claim_owner)
                    .bind(lease_until)
                    .bind(&allocation_id_tx)
                    .bind(NONCE_KIND_ACTION)
                    .execute(&mut **tx)
                    .await?;
                    if ru.rows_affected() != 1 {
                        return Err(OutboxError::NonceAlreadyReserved {
                            chain_id: chain_id_i64 as u64,
                            signer: signer_key_tx.clone(),
                            nonce: nonce_i64 as u64,
                            holder: "unknown".to_string(),
                        });
                    }
                } else {
                    // `INSERT OR IGNORE` + `rows_affected()`, the crate-wide
                    // shape: the UNIQUE (chain_id, signer_address, nonce)
                    // index is what makes the claim exclusive, and a silently
                    // ignored insert must be an error, not a success.
                    let ri = sqlx::query(
                        "INSERT OR IGNORE INTO nonce_allocations \
                         (id, chain_id, signer_address, nonce, status, allocated_at, \
                          kind, claim_owner, lease_until) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(&allocation_id_tx)
                    .bind(chain_id_i64)
                    .bind(&signer_key_tx)
                    .bind(nonce_i64)
                    .bind(NONCE_STATUS_ALLOCATED)
                    .bind(now_wall)
                    .bind(NONCE_KIND_ACTION)
                    .bind(&claim_owner)
                    .bind(lease_until)
                    .execute(&mut **tx)
                    .await?;
                    if ri.rows_affected() != 1 {
                        return Err(OutboxError::NonceAlreadyReserved {
                            chain_id: chain_id_i64 as u64,
                            signer: signer_key_tx.clone(),
                            nonce: nonce_i64 as u64,
                            holder: "unknown".to_string(),
                        });
                    }
                }

                // (4) Seal the signed transaction. This is the step whose
                // ORDER is the point of the whole module: it happens here,
                // inside the reservation, and the caller only gets to
                // broadcast after this transaction has committed.
                let aad = EnvelopeAad {
                    db_uuid: &db_uuid,
                    schema_version: aad_version,
                    table: "tx_attempts",
                    pk: &attempt_id_tx,
                    column: "raw_tx_enc",
                };
                let raw_tx_enc = crypto_store::seal(&data_key, &aad, &raw_tx)?;

                // Wave E (A4): ALWAYS an INSERT. The `UPDATE` that used to run
                // on the retry path rewrote `tx_hash`, `raw_tx_enc`,
                // `raw_tx_hash`, `submitted_at` and `error_message` of the
                // PREVIOUS attempt. For a gas-bumped replacement — a second
                // signed payload against the same action nonce, either of
                // which can still land — that erased the very evidence the
                // sweeper needs to decide which one won. Prior attempts are now
                // terminal rows this statement cannot reach: the attempt number
                // is part of the primary key.
                let rt = sqlx::query(
                    "INSERT OR IGNORE INTO tx_attempts \
                     (id, intent_id, nonce_allocation_id, chain_id, status, created_at, \
                      attempt_number, raw_tx_enc, raw_tx_hash, intent_id_hex, \
                      claim_owner, lease_until) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&attempt_id_tx)
                .bind(&intent_row)
                .bind(&allocation_id_tx)
                .bind(chain_id_i64)
                .bind(TX_ATTEMPT_STATUS_RESERVED)
                .bind(now_wall)
                .bind(next_attempt_number)
                .bind(&raw_tx_enc)
                .bind(&raw_tx_hash_hex_tx)
                .bind(&intent_id_hex)
                .bind(&claim_owner)
                .bind(lease_until)
                .execute(&mut **tx)
                .await?;
                if rt.rows_affected() != 1 {
                    return Err(OutboxError::InFlight {
                        attempt_id: attempt_id_tx.clone(),
                    });
                }

                Ok::<(String, i64), OutboxError>((attempt_id_tx, next_attempt_number))
            })
        })
        .await?;

    Ok(ReservedAttempt {
        attempt_id,
        allocation_id,
        attempt_number,
        raw_tx_hash_hex,
        lease_until,
    })
}

// Test-only fault injection for the POST-SEND window.
//
// The only realistic way `record_broadcast_accepted` fails in production is a
// `sqlx` I/O error, or `OutboxError::ClaimLost` when a concurrent sweep steals
// the claim between the send and the stamp — neither of which a single-threaded
// test can arrange, because the reservation and the stamp use the same
// `claim_owner` by construction. `thread_local` rather than a process-global
// `AtomicBool` so concurrent tests cannot leak into each other; that exact bug
// was found and fixed once already in `root_authorization`, and this follows
// the same precedent.
#[cfg(test)]
thread_local! {
    static FAIL_NEXT_RECORD_AFTER_SEND: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arms exactly one [`record_broadcast_accepted`] failure on this thread.
#[cfg(test)]
pub(crate) fn fail_next_record_after_send() {
    FAIL_NEXT_RECORD_AFTER_SEND.with(|f| f.set(true));
}

/// The node accepted the transaction: record the hash it gave us and drop the
/// claim.
///
/// Kept separate from the reservation on purpose — this is the *only* place
/// `tx_hash` becomes non-NULL, which is what makes "we have a `tx_hash`" mean
/// "a node acknowledged this", as distinct from `raw_tx_hash`, which only
/// means "we signed this".
///
/// A failure here is a POST-SEND failure. See
/// [`SendOutcome::BroadcastNotRecorded`] — the caller must not treat it as
/// "nothing was sent".
pub async fn record_broadcast_accepted(
    store: &StreamGStore,
    claim_owner: &str,
    attempt_id: &str,
    tx_hash: TxHash,
) -> Result<(), OutboxError> {
    #[cfg(test)]
    if FAIL_NEXT_RECORD_AFTER_SEND.with(|f| f.replace(false)) {
        return Err(OutboxError::ClaimLost {
            attempt_id: attempt_id.to_string(),
        });
    }
    let now = now_unix_seconds();
    let claim_owner = claim_owner.to_string();
    let attempt_id = attempt_id.to_string();
    let tx_hash_hex = bytes32_hex(tx_hash);
    store
        .write_tx(move |tx| {
            Box::pin(async move {
                let r = sqlx::query(
                    "UPDATE tx_attempts \
                     SET status = ?, tx_hash = ?, submitted_at = ?, \
                         claim_owner = NULL, lease_until = NULL \
                     WHERE id = ? AND status = ? AND claim_owner = ?",
                )
                .bind(TX_ATTEMPT_STATUS_SUBMITTED)
                .bind(&tx_hash_hex)
                .bind(now)
                .bind(&attempt_id)
                .bind(TX_ATTEMPT_STATUS_RESERVED)
                .bind(&claim_owner)
                .execute(&mut **tx)
                .await?;
                if r.rows_affected() != 1 {
                    return Err(OutboxError::ClaimLost {
                        attempt_id: attempt_id.clone(),
                    });
                }
                sqlx::query(
                    "UPDATE intents SET status = ? \
                     WHERE id = (SELECT intent_id FROM tx_attempts WHERE id = ?)",
                )
                .bind(INTENT_STATUS_SUBMITTED)
                .bind(&attempt_id)
                .execute(&mut **tx)
                .await?;
                Ok::<(), OutboxError>(())
            })
        })
        .await
}

/// What [`reserve_persist_and_send`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// A node accepted the raw transaction and returned this hash.
    Broadcast {
        attempt: ReservedAttempt,
        tx_hash_hex: String,
    },
    /// `eth_sendRawTransaction` failed. The row stays `reserved` **and keeps
    /// its `raw_tx_enc`/`raw_tx_hash`**, because a send error does not mean
    /// the transaction never reached a mempool — `relayer.rs:871-873` says so
    /// verbatim about this crate's own send path. Only the sweeper, with chain
    /// evidence, may decide what happened.
    SendFailedStuckRecoverable {
        attempt: ReservedAttempt,
        detail: String,
    },
    /// `eth_sendRawTransaction` **SUCCEEDED** and returned this hash, but the
    /// follow-up `record_broadcast_accepted` write failed — a `sqlx` error, or
    /// [`OutboxError::ClaimLost`] if a sweep stole the claim in between.
    ///
    /// This variant exists so the post-send failure is impossible to confuse
    /// with a pre-send one at the type level. It used to propagate as a bare
    /// `Err` out of [`reserve_persist_and_send`], and
    /// `broadcaster::sign_persist_and_broadcast`'s `Err` arm would then
    /// **release the broadcaster EOA nonce for a transaction that is already in
    /// a mempool** — the next caller would sign a different transaction at the
    /// same nonce and one of the two would be evicted, non-deterministically.
    /// The row is left exactly as a `Broadcast` row would be minus the stamp,
    /// so the sweeper resolves it from chain evidence per founder ruling F2.
    /// **A caller must never release a nonce on this outcome.**
    BroadcastNotRecorded {
        attempt: ReservedAttempt,
        tx_hash_hex: String,
        detail: String,
    },
}

/// Persist, then broadcast — in that order, which is the whole point.
///
/// The reservation transaction has **committed** before
/// `eth_sendRawTransaction` is called, so every observable ordering of a crash
/// leaves a row that either does not exist or can be resolved from chain
/// evidence. There is deliberately no path here that releases a nonce on a
/// send failure.
pub async fn reserve_persist_and_send(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    chain: TrustedChain<'_>,
    req: &ReservationRequest<'_>,
    signed: &SignedRawTx,
    now_wall: i64,
) -> Result<SendOutcome, OutboxError> {
    let attempt = reserve_and_persist_raw_tx(store, data_key_hex, req, signed, now_wall).await?;

    match chain.client().send_raw_transaction(signed.raw()) {
        Ok(tx_hash) => {
            // NOT `?`. Past this point the transaction is in a mempool at this
            // EOA nonce, so a failure to stamp the row must NOT surface as a
            // bare `Err` — a caller holding an EOA nonce allocation would read
            // that as "nothing was sent" and release it. See
            // `SendOutcome::BroadcastNotRecorded`.
            match record_broadcast_accepted(store, req.claim_owner, &attempt.attempt_id, tx_hash)
                .await
            {
                Ok(()) => Ok(SendOutcome::Broadcast {
                    attempt,
                    tx_hash_hex: bytes32_hex(tx_hash),
                }),
                Err(e) => Ok(SendOutcome::BroadcastNotRecorded {
                    attempt,
                    tx_hash_hex: bytes32_hex(tx_hash),
                    detail: e.to_string(),
                }),
            }
        }
        Err(e) => Ok(SendOutcome::SendFailedStuckRecoverable {
            attempt,
            detail: e.to_string(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Sweeper — the F2 four-step contract.
// ---------------------------------------------------------------------------

/// Knobs for one [`sweep_stuck_reservations`] pass.
pub struct SweepPolicy<'a> {
    /// Who this sweep claims rows as. Two sweepers with different owners
    /// cannot both service the same row — the CAS decides.
    pub claim_owner: &'a str,
    /// How long the sweep's own claim lasts, and how long a re-deferred row
    /// waits before the next pass looks at it again.
    pub lease_ttl_seconds: i64,
    pub max_rows: i64,
    /// The gateway `intentUsed(intentId)` is read from.
    pub gateway: [u8; 20],
}

/// One row that could not be resolved. **Not** a failure of the sweep: it is
/// the fail-closed outcome, and the row is still `reserved` with its raw
/// transaction intact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StuckAttempt {
    pub attempt_id: String,
    pub reason: String,
}

/// Outcome counts for one sweep.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Rows the CAS actually claimed this pass.
    pub claimed: usize,
    /// Chain proved non-consumption **and** the intent can no longer execute:
    /// nonce released, attempt `failed`.
    pub released: usize,
    /// Chain proved the intent landed: nonce `consumed`, never rebroadcast.
    pub executed: usize,
    /// Chain proved non-consumption but the intent is still chain-time valid,
    /// so the signed payload could still execute. Held.
    pub held_intent_still_valid: usize,
    /// Could not be resolved (RPC error, or no `raw_tx_hash`/`intent_id_hex`
    /// to resolve *with*). Left `reserved`.
    pub stuck: Vec<StuckAttempt>,
}

impl SweepReport {
    /// Rows still `reserved` after this pass for a reason that needs an
    /// operator or a healthier RPC, not more time.
    pub fn stuck_recoverable(&self) -> usize {
        self.stuck.len()
    }
}

/// A claimed row, with everything the chain resolution needs.
#[derive(Debug, Clone)]
struct ClaimedAttempt {
    attempt_id: String,
    allocation_id: Option<String>,
    profile_id: String,
    raw_tx_hash: Option<String>,
    intent_id_hex: Option<String>,
    intent_expires_at: Option<i64>,
}

/// What the chain said about one claimed row.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Resolution {
    /// Our own transaction is mined and succeeded.
    MinedOurs { tx_hash_hex: String },
    /// `intentUsed[intentId]` is true but the winning transaction is not one
    /// we can name — an external fulfillment, which the gateway explicitly
    /// tolerates (`_enrollV1OrAcceptFrontRun`). Must never be rebroadcast.
    ExecutedExternally,
    /// The chain proves nothing was consumed, and the parent intent can no
    /// longer execute: safe to release.
    SafeToRelease { reason: String },
    /// The chain proves nothing was consumed, but the intent is still valid on
    /// the **chain** clock, so the already-signed payload could still be
    /// broadcast by anybody and succeed. Hold.
    HoldIntentStillValid,
    /// Fail closed.
    Stuck { reason: String },
}

/// Resolve stale `reserved` attempts against chain evidence (founder ruling
/// F2). See the module doc for the four-step contract.
///
/// `now_wall` is injected rather than read from the clock so a test can place
/// the wall clock and the chain clock at deliberately different points — which
/// is the only way to prove the chain-time guard is the one doing the work.
pub async fn sweep_stuck_reservations(
    store: &StreamGStore,
    chain: TrustedChain<'_>,
    policy: &SweepPolicy<'_>,
    now_wall: i64,
) -> Result<SweepReport, OutboxError> {
    // --- 1. Trigger + CAS claim (one write transaction). ------------------
    let claimed = claim_stale_reservations(store, policy, now_wall).await?;

    // --- 2/3. Resolve against chain, OUTSIDE any transaction. -------------
    // A hanging RPC must not hold SQLite's writer lock.
    let mut resolutions: Vec<(ClaimedAttempt, Resolution)> = Vec::with_capacity(claimed.len());
    for row in claimed {
        let resolution = resolve_against_chain(chain, policy.gateway, &row);
        resolutions.push((row, resolution));
    }

    // --- 4. Apply (one write transaction). --------------------------------
    apply_resolutions(store, policy, now_wall, resolutions).await
}

async fn claim_stale_reservations(
    store: &StreamGStore,
    policy: &SweepPolicy<'_>,
    now_wall: i64,
) -> Result<Vec<ClaimedAttempt>, OutboxError> {
    let claim_owner = policy.claim_owner.to_string();
    let lease_until = now_wall.saturating_add(policy.lease_ttl_seconds);
    let max_rows = policy.max_rows;

    store
        .write_tx(move |tx| {
            Box::pin(async move {
                // The JOIN is the profile boundary: an attempt whose parent
                // intent row is gone is never touched at all.
                let rows = sqlx::query(
                    "SELECT a.id AS attempt_id, \
                            a.nonce_allocation_id AS allocation_id, \
                            a.raw_tx_hash AS raw_tx_hash, \
                            a.intent_id_hex AS intent_id_hex, \
                            i.profile_id AS profile_id, \
                            i.expires_at AS intent_expires_at \
                     FROM tx_attempts a \
                     JOIN intents i ON i.id = a.intent_id \
                     WHERE a.status = ? AND a.lease_until IS NOT NULL AND a.lease_until < ? \
                     ORDER BY a.lease_until ASC \
                     LIMIT ?",
                )
                .bind(TX_ATTEMPT_STATUS_RESERVED)
                .bind(now_wall)
                .bind(max_rows)
                .fetch_all(&mut **tx)
                .await?;

                let mut claimed = Vec::with_capacity(rows.len());
                for row in rows {
                    let attempt_id: String = row.try_get("attempt_id")?;
                    // Compare-and-swap (spec §9.3).
                    //
                    // MEASURED REDUNDANCY, stated rather than implied: the
                    // `lease_until < ?` predicate here and the identical one
                    // in the SELECT above are redundant *with each other*.
                    // Both statements run inside one `BEGIN IMMEDIATE`
                    // transaction, on a pool with exactly one connection, in a
                    // process holding an exclusive `fs2` instance lock, so no
                    // writer can interleave between them. Mutation-tested,
                    // both directions: deleting EITHER predicate alone fails
                    // no test; deleting BOTH makes `a_fresh_reservation_is_
                    // not_swept` fail (a healthy in-flight reservation gets
                    // claimed out from under the submit that is still
                    // running). So this is a real guard with a redundant
                    // partner — not a cosmetic one — and it is kept because it
                    // is what keeps the statement correct on its own if the
                    // read and the write are ever split apart.
                    let r = sqlx::query(
                        "UPDATE tx_attempts SET claim_owner = ?, lease_until = ? \
                         WHERE id = ? AND status = ? \
                           AND lease_until IS NOT NULL AND lease_until < ?",
                    )
                    .bind(&claim_owner)
                    .bind(lease_until)
                    .bind(&attempt_id)
                    .bind(TX_ATTEMPT_STATUS_RESERVED)
                    .bind(now_wall)
                    .execute(&mut **tx)
                    .await?;
                    if r.rows_affected() != 1 {
                        continue;
                    }
                    claimed.push(ClaimedAttempt {
                        attempt_id,
                        allocation_id: row.try_get("allocation_id")?,
                        profile_id: row.try_get("profile_id")?,
                        raw_tx_hash: row.try_get("raw_tx_hash")?,
                        intent_id_hex: row.try_get("intent_id_hex")?,
                        intent_expires_at: row.try_get("intent_expires_at")?,
                    });
                }
                Ok::<Vec<ClaimedAttempt>, OutboxError>(claimed)
            })
        })
        .await
}

/// Step 3 of the F2 contract. **Every** `Err` returns [`Resolution::Stuck`];
/// there is no branch from an RPC failure to a release.
fn resolve_against_chain(
    chain: TrustedChain<'_>,
    gateway: [u8; 20],
    row: &ClaimedAttempt,
) -> Resolution {
    let client = chain.client();

    // (a) A receipt for the transaction we signed, if we know its hash.
    if let Some(raw_hash_hex) = row.raw_tx_hash.as_deref() {
        let Some(raw_hash) = parse_bytes32(raw_hash_hex) else {
            return Resolution::Stuck {
                reason: format!("raw_tx_hash {raw_hash_hex:?} is not a 32-byte hex string"),
            };
        };
        match client.transaction_receipt(raw_hash) {
            Err(e) => {
                return Resolution::Stuck {
                    reason: format!("transaction_receipt failed: {e}"),
                }
            }
            Ok(Some(receipt)) if receipt.success => {
                return Resolution::MinedOurs {
                    tx_hash_hex: bytes32_hex(receipt.tx_hash),
                }
            }
            // A mined revert consumed nothing on chain (`_markIntentAndNonce`
            // rolls back with the rest of the transaction), so this is
            // evidence of NON-consumption — but the release still has to pass
            // the chain-time guard below, because the signed payload stays
            // executable until the intent expires (spec §8.2). See the module
            // doc's note on reconciling brief §5.1 with §5.3.
            Ok(Some(_reverted)) => {}
            // Not mined yet. Not a failure, and not permission to release.
            Ok(None) => {}
        }
    }

    // (b) Did this intent land at all — including by somebody else's hand?
    let Some(intent_id_hex) = row.intent_id_hex.as_deref() else {
        return Resolution::Stuck {
            reason: "no intent_id_hex on this attempt: cannot ask intentUsed(intentId)".to_string(),
        };
    };
    let Some(intent_id) = parse_bytes32(intent_id_hex) else {
        return Resolution::Stuck {
            reason: format!("intent_id_hex {intent_id_hex:?} is not a 32-byte hex string"),
        };
    };
    let block = match client.pinned_block_number() {
        Ok(b) => b,
        Err(e) => {
            return Resolution::Stuck {
                reason: format!("pinned_block_number failed: {e}"),
            }
        }
    };
    match client.intent_used(gateway, intent_id, block) {
        Err(e) => {
            return Resolution::Stuck {
                reason: format!("intent_used failed: {e}"),
            }
        }
        Ok(true) => return Resolution::ExecutedExternally,
        Ok(false) => {}
    }

    // (c) The chain proves non-consumption. Guard on CHAIN time (A2): a nonce
    // is never released while its parent intent could still execute.
    let Some(expires_at) = row.intent_expires_at else {
        return Resolution::Stuck {
            reason: "intent has no expires_at: cannot evaluate the chain-time guard".to_string(),
        };
    };
    let chain_now = match client.block_timestamp() {
        Ok(t) => t,
        Err(e) => {
            return Resolution::Stuck {
                reason: format!("block_timestamp failed: {e}"),
            }
        }
    };
    if chain_now == 0 {
        // `ChainClient::block_timestamp`'s trait default is `Ok(0)`,
        // documented as "0 = unknown" (`chain.rs:139-141`), so any client that
        // does not override it reaches this line — this is not a hypothetical
        // state.
        //
        // **What removing this guard would actually do, corrected 2026-07-25.**
        // An earlier revision of this comment claimed a 0 timestamp would be
        // read as "1970, so everything has expired" and would *release* every
        // reservation. That is directionally wrong and is recorded here rather
        // than quietly deleted. Three lines below, the chain-time guard is
        // `if chain_now_i64 < expires_at { HoldIntentStillValid }`; with
        // `chain_now = 0` that is `0 < expires_at`, true for every positive
        // expiry, so without this guard the row would be **held**, not
        // released. The failure mode is a wedge, not a leak.
        //
        // The guard is kept anyway, and the reason is diagnostic rather than
        // safety: a silent `Hold` repeats on every sweep forever with nothing
        // in the report naming the misconfiguration, whereas `Stuck` puts the
        // unconfigured client in `SweepReport::stuck` where an operator sees
        // it. Both outcomes keep the nonce allocated; only one is debuggable.
        // Covered by `block_timestamp_zero_is_stuck_not_a_silent_hold`.
        return Resolution::Stuck {
            reason: "block_timestamp() returned 0, which ChainClient documents as \"unknown\""
                .to_string(),
        };
    }
    let chain_now_i64 = i64::try_from(chain_now).unwrap_or(i64::MAX);
    if chain_now_i64 < expires_at {
        return Resolution::HoldIntentStillValid;
    }
    Resolution::SafeToRelease {
        reason: format!(
            "chain proves intentUsed=false and the intent expired at {expires_at} \
             (chain time {chain_now_i64})"
        ),
    }
}

async fn apply_resolutions(
    store: &StreamGStore,
    policy: &SweepPolicy<'_>,
    now_wall: i64,
    resolutions: Vec<(ClaimedAttempt, Resolution)>,
) -> Result<SweepReport, OutboxError> {
    let claim_owner = policy.claim_owner.to_string();
    // A row we could not resolve, or must hold, goes back to waiting: the
    // claim is dropped and the lease is pushed one TTL into the future so the
    // next pass picks it up rather than spinning on it.
    let deferred_lease = now_wall.saturating_add(policy.lease_ttl_seconds);
    let claimed_count = resolutions.len();

    store
        .write_tx(move |tx| {
            Box::pin(async move {
                let mut report = SweepReport {
                    claimed: claimed_count,
                    ..SweepReport::default()
                };

                for (row, resolution) in resolutions {
                    match resolution {
                        Resolution::MinedOurs { tx_hash_hex } => {
                            // Hand to reconcile with a NON-NULL tx_hash: a
                            // `reserved` row's NULL `tx_hash` is exactly what
                            // lets reconcile stamp the wrong row.
                            let updated = update_attempt(
                                &mut **tx,
                                AttemptUpdate {
                                    attempt_id: &row.attempt_id,
                                    profile_id: &row.profile_id,
                                    claim_owner: &claim_owner,
                                    status: TX_ATTEMPT_STATUS_SUBMITTED,
                                    tx_hash: Some(&tx_hash_hex),
                                    submitted_at: Some(now_wall),
                                    confirmed_at: None,
                                    error_message: None,
                                    next_lease: None,
                                },
                            )
                            .await?;
                            if updated {
                                consume_nonce(&mut **tx, row.allocation_id.as_deref()).await?;
                                report.executed += 1;
                            }
                        }
                        Resolution::ExecutedExternally => {
                            let updated = update_attempt(
                                &mut **tx,
                                AttemptUpdate {
                                    attempt_id: &row.attempt_id,
                                    profile_id: &row.profile_id,
                                    claim_owner: &claim_owner,
                                    status: TX_ATTEMPT_STATUS_CONFIRMED,
                                    tx_hash: None,
                                    submitted_at: None,
                                    confirmed_at: Some(now_wall),
                                    error_message: Some(
                                        "intentUsed(intentId) is true; this intent executed \
                                         on chain under a transaction hash this attestor does \
                                         not know (external fulfillment). Not rebroadcast.",
                                    ),
                                    next_lease: None,
                                },
                            )
                            .await?;
                            if updated {
                                consume_nonce(&mut **tx, row.allocation_id.as_deref()).await?;
                                report.executed += 1;
                            }
                        }
                        Resolution::SafeToRelease { reason } => {
                            let updated = update_attempt(
                                &mut **tx,
                                AttemptUpdate {
                                    attempt_id: &row.attempt_id,
                                    profile_id: &row.profile_id,
                                    claim_owner: &claim_owner,
                                    status: TX_ATTEMPT_STATUS_FAILED,
                                    tx_hash: None,
                                    submitted_at: None,
                                    confirmed_at: None,
                                    error_message: Some(&reason),
                                    next_lease: None,
                                },
                            )
                            .await?;
                            if updated {
                                if let Some(allocation_id) = row.allocation_id.as_deref() {
                                    sqlx::query(
                                        "UPDATE nonce_allocations \
                                         SET status = ?, released_at = ?, \
                                             claim_owner = NULL, lease_until = NULL \
                                         WHERE id = ? AND kind = ?",
                                    )
                                    .bind(NONCE_STATUS_RELEASED)
                                    .bind(now_wall)
                                    .bind(allocation_id)
                                    .bind(NONCE_KIND_ACTION)
                                    .execute(&mut **tx)
                                    .await?;
                                }
                                report.released += 1;
                            }
                        }
                        Resolution::HoldIntentStillValid => {
                            defer_attempt(&mut **tx, &row.attempt_id, &claim_owner, deferred_lease)
                                .await?;
                            report.held_intent_still_valid += 1;
                        }
                        Resolution::Stuck { reason } => {
                            defer_attempt(&mut **tx, &row.attempt_id, &claim_owner, deferred_lease)
                                .await?;
                            report.stuck.push(StuckAttempt {
                                attempt_id: row.attempt_id.clone(),
                                reason,
                            });
                        }
                    }
                }

                Ok::<SweepReport, OutboxError>(report)
            })
        })
        .await
}

struct AttemptUpdate<'a> {
    attempt_id: &'a str,
    profile_id: &'a str,
    claim_owner: &'a str,
    status: &'a str,
    tx_hash: Option<&'a str>,
    submitted_at: Option<i64>,
    confirmed_at: Option<i64>,
    error_message: Option<&'a str>,
    next_lease: Option<i64>,
}

/// Terminal-ish transition of one claimed attempt.
///
/// Guarded three ways: the row must still be `reserved`, must still be claimed
/// by **us**, and must still belong to the profile we claimed it under. The
/// last one is the sweeper's version of the reservation's ownership re-check
/// (`submit.rs:1383-1393`) — without it, a row whose parent intent changed
/// hands between the claim and the apply would be resolved against the wrong
/// owner.
async fn update_attempt<'e, E>(executor: E, u: AttemptUpdate<'_>) -> Result<bool, OutboxError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let r = sqlx::query(
        "UPDATE tx_attempts \
         SET status = ?, tx_hash = COALESCE(?, tx_hash), \
             submitted_at = COALESCE(?, submitted_at), \
             confirmed_at = COALESCE(?, confirmed_at), \
             error_message = ?, claim_owner = NULL, lease_until = ? \
         WHERE id = ? AND status = ? AND claim_owner = ? \
           AND EXISTS (SELECT 1 FROM intents i \
                       WHERE i.id = tx_attempts.intent_id AND i.profile_id = ?)",
    )
    .bind(u.status)
    .bind(u.tx_hash)
    .bind(u.submitted_at)
    .bind(u.confirmed_at)
    .bind(u.error_message)
    .bind(u.next_lease)
    .bind(u.attempt_id)
    .bind(TX_ATTEMPT_STATUS_RESERVED)
    .bind(u.claim_owner)
    .bind(u.profile_id)
    .execute(executor)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// Put a row back in the queue: still `reserved`, no longer claimed, visible
/// again one lease TTL from now.
async fn defer_attempt<'e, E>(
    executor: E,
    attempt_id: &str,
    claim_owner: &str,
    next_lease: i64,
) -> Result<(), OutboxError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query(
        "UPDATE tx_attempts SET claim_owner = NULL, lease_until = ? \
         WHERE id = ? AND status = ? AND claim_owner = ?",
    )
    .bind(next_lease)
    .bind(attempt_id)
    .bind(TX_ATTEMPT_STATUS_RESERVED)
    .bind(claim_owner)
    .execute(executor)
    .await?;
    Ok(())
}

async fn consume_nonce<'e, E>(executor: E, allocation_id: Option<&str>) -> Result<(), OutboxError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let Some(allocation_id) = allocation_id else {
        return Ok(());
    };
    sqlx::query(
        "UPDATE nonce_allocations \
         SET status = ?, released_at = NULL, claim_owner = NULL, lease_until = NULL \
         WHERE id = ? AND kind = ?",
    )
    .bind(NONCE_STATUS_CONSUMED)
    .bind(allocation_id)
    .bind(NONCE_KIND_ACTION)
    .execute(executor)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use crate::chain::{
        BatchView, ChainClient, ChainError, ExecutedLog, TxHash as ChainTxHash, TxReceiptView,
    };

    const PROFILE: &str = "profile-outbox-1";
    const CHAIN_ID: u64 = 8453;
    const GATEWAY: [u8; 20] = [0x11; 20];
    const CONTROLLER: [u8; 20] = [0x22; 20];
    const INTENT_ID: [u8; 32] = [0x33; 32];
    const ACTION_NONCE: u64 = 7;
    const OWNER: &str = "sweeper-a";

    /// Chain clock used by every test here. Deliberately far below any
    /// plausible wall clock so the two can be told apart.
    const CHAIN_NOW: u64 = 1_700_000_000;
    /// Wall clock used by every test here. Deliberately far ABOVE `CHAIN_NOW`.
    const WALL_NOW: i64 = 1_800_000_000;

    fn data_key_hex() -> SecretHex {
        SecretHex::from_hex(&"cc".repeat(32)).expect("valid 32-byte test key")
    }

    // --- chain double ---------------------------------------------------
    //
    // `MockChain` predates Task 7 and has no knobs for `intent_used` /
    // `transaction_receipt`, so the tests here use their own `ChainClient`.
    // This IS the instance production code receives (it is threaded in via
    // `TrustedChain`), so every counter asserted below is read off the object
    // the code under test actually called.

    #[derive(Default)]
    struct FakeChainInner {
        receipt: Option<Result<Option<TxReceiptView>, String>>,
        intent_used: Option<Result<bool, String>>,
        block_timestamp: Option<Result<u64, String>>,
        pinned_block: Option<Result<u64, String>>,
        send_result: Option<Result<ChainTxHash, String>>,
        receipt_calls: usize,
        intent_used_calls: usize,
        send_calls: usize,
        last_send_raw: Option<Vec<u8>>,
        last_intent_used_args: Option<([u8; 20], [u8; 32], u64)>,
    }

    struct FakeChain {
        inner: Mutex<FakeChainInner>,
    }

    impl FakeChain {
        /// A chain that answers every Task-7 read successfully: no receipt,
        /// intent not used, chain time `CHAIN_NOW`.
        fn healthy() -> Self {
            Self {
                inner: Mutex::new(FakeChainInner {
                    receipt: Some(Ok(None)),
                    intent_used: Some(Ok(false)),
                    block_timestamp: Some(Ok(CHAIN_NOW)),
                    pinned_block: Some(Ok(4242)),
                    send_result: Some(Ok([0xEE; 32])),
                    ..FakeChainInner::default()
                }),
            }
        }

        fn set_intent_used(&self, v: Result<bool, String>) {
            self.inner.lock().unwrap().intent_used = Some(v);
        }
        fn set_receipt(&self, v: Result<Option<TxReceiptView>, String>) {
            self.inner.lock().unwrap().receipt = Some(v);
        }
        fn set_block_timestamp(&self, v: Result<u64, String>) {
            self.inner.lock().unwrap().block_timestamp = Some(v);
        }
        fn set_send_result(&self, v: Result<ChainTxHash, String>) {
            self.inner.lock().unwrap().send_result = Some(v);
        }
        fn intent_used_calls(&self) -> usize {
            self.inner.lock().unwrap().intent_used_calls
        }
        fn receipt_calls(&self) -> usize {
            self.inner.lock().unwrap().receipt_calls
        }
        fn send_calls(&self) -> usize {
            self.inner.lock().unwrap().send_calls
        }
        fn last_send_raw(&self) -> Option<Vec<u8>> {
            self.inner.lock().unwrap().last_send_raw.clone()
        }
        fn last_intent_used_args(&self) -> Option<([u8; 20], [u8; 32], u64)> {
            self.inner.lock().unwrap().last_intent_used_args
        }
    }

    fn unset(what: &str) -> ChainError {
        ChainError::Msg(format!("FakeChain: {what} not armed"))
    }

    impl ChainClient for FakeChain {
        fn propose_batch(
            &self,
            _e: u64,
            _r: [u8; 32],
            _v: [u8; 32],
            _b: u128,
        ) -> Result<ChainTxHash, ChainError> {
            Err(unset("propose_batch"))
        }
        fn challenge_batch(
            &self,
            _e: u64,
            _c: [u8; 32],
            _b: u128,
        ) -> Result<ChainTxHash, ChainError> {
            Err(unset("challenge_batch"))
        }
        fn confirm_epoch(&self, _e: u64) -> Result<ChainTxHash, ChainError> {
            Err(unset("confirm_epoch"))
        }
        fn get_batch(&self, _e: u64) -> Result<BatchView, ChainError> {
            Err(unset("get_batch"))
        }
        fn bind_with_signature(
            &self,
            _w: [u8; 20],
            _u: &str,
            _d: u64,
            _s: &[u8],
        ) -> Result<ChainTxHash, ChainError> {
            Err(unset("bind_with_signature"))
        }
        fn enroll_self_with_signature(
            &self,
            _w: [u8; 20],
            _d: u64,
            _s: &[u8],
        ) -> Result<ChainTxHash, ChainError> {
            Err(unset("enroll_self_with_signature"))
        }

        fn block_timestamp(&self) -> Result<u64, ChainError> {
            let g = self.inner.lock().unwrap();
            match &g.block_timestamp {
                Some(Ok(t)) => Ok(*t),
                Some(Err(e)) => Err(ChainError::Msg(e.clone())),
                None => Err(unset("block_timestamp")),
            }
        }

        fn pinned_block_number(&self) -> Result<u64, ChainError> {
            let g = self.inner.lock().unwrap();
            match &g.pinned_block {
                Some(Ok(b)) => Ok(*b),
                Some(Err(e)) => Err(ChainError::Msg(e.clone())),
                None => Err(unset("pinned_block_number")),
            }
        }

        fn send_raw_transaction(&self, raw: &[u8]) -> Result<ChainTxHash, ChainError> {
            let mut g = self.inner.lock().unwrap();
            g.send_calls += 1;
            g.last_send_raw = Some(raw.to_vec());
            match &g.send_result {
                Some(Ok(h)) => Ok(*h),
                Some(Err(e)) => Err(ChainError::Msg(e.clone())),
                None => Err(unset("send_raw_transaction")),
            }
        }

        fn transaction_receipt(
            &self,
            _hash: ChainTxHash,
        ) -> Result<Option<TxReceiptView>, ChainError> {
            let mut g = self.inner.lock().unwrap();
            g.receipt_calls += 1;
            match &g.receipt {
                Some(Ok(r)) => Ok(r.clone()),
                Some(Err(e)) => Err(ChainError::Msg(e.clone())),
                None => Err(unset("transaction_receipt")),
            }
        }

        fn intent_used(
            &self,
            gateway: [u8; 20],
            intent_id: [u8; 32],
            block: u64,
        ) -> Result<bool, ChainError> {
            let mut g = self.inner.lock().unwrap();
            g.intent_used_calls += 1;
            g.last_intent_used_args = Some((gateway, intent_id, block));
            match &g.intent_used {
                Some(Ok(v)) => Ok(*v),
                Some(Err(e)) => Err(ChainError::Msg(e.clone())),
                None => Err(unset("intent_used")),
            }
        }

        fn sponsored_enrollment_logs(
            &self,
            _g: [u8; 20],
            _f: u64,
            _t: u64,
        ) -> Result<Vec<ExecutedLog>, ChainError> {
            Err(unset("sponsored_enrollment_logs"))
        }
    }

    // --- store seeding ---------------------------------------------------

    async fn open_store() -> (tempfile::TempDir, StreamGStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open store");
        (dir, store)
    }

    /// Seed the `profiles` + `intents` rows the reservation requires.
    /// `intent_expires_at` is the intent's **chain-clock** deadline — it is
    /// `valid_until` in `quotes.rs`, which is cut from `block_timestamp()`,
    /// not from the host clock (`quotes::create_sponsored_enrollment_quote_at`
    /// STEP 4: `let valid_after = chain_now;`).
    async fn seed_intent(store: &StreamGStore, profile_id: &str, intent_expires_at: i64) {
        let intent_row = intent_row_id(profile_id, INTENT_ID);
        let profile_id = profile_id.to_string();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT OR IGNORE INTO profiles (id, created_at, status) \
                         VALUES (?, ?, 'active')",
                    )
                    .bind(&profile_id)
                    .bind(0i64)
                    .execute(&mut **tx)
                    .await?;
                    sqlx::query(
                        "INSERT INTO intents (id, profile_id, intent_type, status, \
                         created_at, expires_at) \
                         VALUES (?, ?, 'sponsored_enrollment', 'pending', 0, ?)",
                    )
                    .bind(&intent_row)
                    .bind(&profile_id)
                    .bind(intent_expires_at)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed intent");
    }

    fn request<'a>(profile_id: &'a str, claim_owner: &'a str) -> ReservationRequest<'a> {
        ReservationRequest {
            profile_id,
            intent_id: INTENT_ID,
            chain_id: CHAIN_ID,
            controller: CONTROLLER,
            action: ActionType::SponsoredEnrollment,
            action_nonce: ACTION_NONCE,
            claim_owner,
            lease_ttl_seconds: DEFAULT_LEASE_TTL_SECONDS,
        }
    }

    fn policy<'a>(claim_owner: &'a str) -> SweepPolicy<'a> {
        SweepPolicy {
            claim_owner,
            lease_ttl_seconds: DEFAULT_LEASE_TTL_SECONDS,
            max_rows: DEFAULT_SWEEP_MAX_ROWS,
            gateway: GATEWAY,
        }
    }

    fn signed() -> SignedRawTx {
        SignedRawTx::new(
            vec![0x02, 0xf8, 0x6b, 0xAA, 0xBB, 0xCC],
            GasUnits::new(500_000),
            MaxFeePerGas::new(1_000_000_000),
        )
    }

    async fn text(store: &StreamGStore, sql: &'static str, bind: String) -> Option<String> {
        store
            .read(move |h| {
                Box::pin(async move {
                    let v: Option<String> =
                        h.fetch_scalar(sqlx::query_scalar(sql).bind(bind)).await?;
                    Ok::<Option<String>, StreamGStoreError>(v)
                })
            })
            .await
            .expect("text")
    }

    async fn blob(store: &StreamGStore, sql: &'static str, bind: String) -> Option<Vec<u8>> {
        store
            .read(move |h| {
                Box::pin(async move {
                    let v: Option<Vec<u8>> =
                        h.fetch_scalar(sqlx::query_scalar(sql).bind(bind)).await?;
                    Ok::<Option<Vec<u8>>, StreamGStoreError>(v)
                })
            })
            .await
            .expect("blob")
    }

    async fn count(store: &StreamGStore, sql: &'static str, bind: String) -> i64 {
        store
            .read(move |h| {
                Box::pin(async move {
                    let v: i64 = h.fetch_scalar(sqlx::query_scalar(sql).bind(bind)).await?;
                    Ok::<i64, StreamGStoreError>(v)
                })
            })
            .await
            .expect("count")
    }

    const ATTEMPT_STATUS_SQL: &str = "SELECT status FROM tx_attempts WHERE id = ?";
    const ATTEMPT_TX_HASH_SQL: &str = "SELECT tx_hash FROM tx_attempts WHERE id = ?";
    const ATTEMPT_RAW_HASH_SQL: &str = "SELECT raw_tx_hash FROM tx_attempts WHERE id = ?";
    const ATTEMPT_RAW_ENC_SQL: &str = "SELECT raw_tx_enc FROM tx_attempts WHERE id = ?";
    const NONCE_STATUS_SQL: &str = "SELECT status FROM nonce_allocations WHERE id = ?";
    const RAW_ENC_PRESENT_SQL: &str =
        "SELECT COUNT(*) FROM tx_attempts WHERE id = ? AND raw_tx_enc IS NOT NULL";

    /// Reserve a row and then force its lease into the past so the very next
    /// sweep sees it as stale.
    async fn reserve_stale(
        store: &StreamGStore,
        profile_id: &str,
        intent_expires_at: i64,
    ) -> ReservedAttempt {
        seed_intent(store, profile_id, intent_expires_at).await;
        let req = request(profile_id, OWNER);
        let attempt = reserve_and_persist_raw_tx(store, &data_key_hex(), &req, &signed(), WALL_NOW)
            .await
            .expect("reserve");
        let attempt_id = attempt.attempt_id.clone();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "UPDATE tx_attempts SET lease_until = ?, claim_owner = NULL WHERE id = ?",
                    )
                    .bind(WALL_NOW - 1)
                    .bind(&attempt_id)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("age the lease");
        attempt
    }

    // -------------------------------------------------------------------
    // §8.1 — required mutation-detecting tests.
    // -------------------------------------------------------------------

    /// **Founder ruling F2, the core case.** When the chain says
    /// `intentUsed[intentId]` is true, the reservation must NOT be released —
    /// the intent landed (possibly by somebody else's transaction) and
    /// re-releasing the nonce would authorize a duplicate broadcast that burns
    /// relayer ETH on a guaranteed `IntentAlreadyUsed` revert.
    ///
    /// Mutation this detects: flip the `Ok(true)` arm of `intent_used` in
    /// [`resolve_against_chain`] to fall through to the release branch (or
    /// arm the chain with `Ok(false)`) — the nonce is then `released` and the
    /// attempt `failed`.
    ///
    /// Paired arms, so neither assertion is a tautology: the SAME setup with
    /// `intent_used = false` and an already-expired intent DOES release. The
    /// only difference between the two arms is the chain's answer.
    #[tokio::test]
    async fn sweeper_refuses_to_release_when_chain_says_intent_used() {
        // --- arm 1: chain says the intent was consumed -> held. ---------
        let (_dir, store) = open_store().await;
        // Expired on the chain clock, so the chain-time guard is NOT what
        // holds this row; only the `intentUsed` evidence is.
        let attempt = reserve_stale(&store, PROFILE, (CHAIN_NOW as i64) - 600).await;
        let chain = FakeChain::healthy();
        chain.set_intent_used(Ok(true));

        let report = sweep_stuck_reservations(&store, (&chain).into(), &policy(OWNER), WALL_NOW)
            .await
            .expect("sweep");

        assert_eq!(report.claimed, 1);
        assert_eq!(report.executed, 1);
        assert_eq!(
            report.released, 0,
            "a chain-proven-used intent must never release its nonce"
        );
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, attempt.allocation_id.clone()).await,
            Some(NONCE_STATUS_CONSUMED.to_string())
        );
        assert_eq!(
            text(&store, ATTEMPT_STATUS_SQL, attempt.attempt_id.clone()).await,
            Some(TX_ATTEMPT_STATUS_CONFIRMED.to_string())
        );
        // The read really was made against the gateway and intentId we hold.
        assert_eq!(chain.intent_used_calls(), 1);
        assert_eq!(
            chain.last_intent_used_args(),
            Some((GATEWAY, INTENT_ID, 4242))
        );

        // --- arm 2 (the non-tautology pair): same everything, chain says
        // the intent was NOT consumed -> released. ------------------------
        let (_dir2, store2) = open_store().await;
        let attempt2 = reserve_stale(&store2, PROFILE, (CHAIN_NOW as i64) - 600).await;
        let chain2 = FakeChain::healthy();
        chain2.set_intent_used(Ok(false));

        let report2 = sweep_stuck_reservations(&store2, (&chain2).into(), &policy(OWNER), WALL_NOW)
            .await
            .expect("sweep 2");

        assert_eq!(report2.released, 1);
        assert_eq!(report2.executed, 0);
        assert_eq!(
            text(&store2, NONCE_STATUS_SQL, attempt2.allocation_id.clone()).await,
            Some(NONCE_STATUS_RELEASED.to_string())
        );
    }

    /// **Fail closed.** An RPC that cannot answer is not evidence of
    /// anything. Every chain read the sweeper makes must leave the row
    /// `reserved` when it errors.
    ///
    /// Mutation this detects: make any of the three reads return `Ok(false)` /
    /// `Ok(None)` / `Ok(0)` instead of propagating the `Err` into
    /// [`Resolution::Stuck`] — the row is then released. Arm 2 below is
    /// literally that mutation applied from the outside (the chain returns
    /// `Ok(false)`), and it releases, which is what proves arm 1's assertion
    /// is load-bearing rather than vacuous.
    #[tokio::test]
    async fn sweeper_stays_reserved_when_rpc_errors() {
        for (label, armed) in [
            ("receipt", 0usize),
            ("intent_used", 1usize),
            ("block_timestamp", 2usize),
        ] {
            let (_dir, store) = open_store().await;
            // Chain-time-expired, so nothing but the error handling can be
            // holding this row.
            let attempt = reserve_stale(&store, PROFILE, (CHAIN_NOW as i64) - 600).await;
            let chain = FakeChain::healthy();
            match armed {
                0 => chain.set_receipt(Err("node down".into())),
                1 => chain.set_intent_used(Err("node down".into())),
                _ => chain.set_block_timestamp(Err("node down".into())),
            }

            let report =
                sweep_stuck_reservations(&store, (&chain).into(), &policy(OWNER), WALL_NOW)
                    .await
                    .unwrap_or_else(|e| panic!("sweep ({label}) must not fail: {e}"));

            assert_eq!(report.claimed, 1, "{label}");
            assert_eq!(
                report.released, 0,
                "{label}: an RPC error must never release a nonce"
            );
            assert_eq!(report.executed, 0, "{label}");
            assert_eq!(
                report.stuck_recoverable(),
                1,
                "{label}: the row must be reported stuck-recoverable"
            );
            assert!(
                report.stuck[0].reason.contains("node down"),
                "{label}: the operator needs the underlying RPC error, got {:?}",
                report.stuck[0].reason
            );
            assert_eq!(
                text(&store, ATTEMPT_STATUS_SQL, attempt.attempt_id.clone()).await,
                Some(TX_ATTEMPT_STATUS_RESERVED.to_string()),
                "{label}"
            );
            assert_eq!(
                text(&store, NONCE_STATUS_SQL, attempt.allocation_id.clone()).await,
                Some(NONCE_STATUS_ALLOCATED.to_string()),
                "{label}"
            );
            // The raw transaction is still there, which is what makes the row
            // recoverable on the next pass rather than merely stuck.
            assert!(
                blob(&store, ATTEMPT_RAW_ENC_SQL, attempt.attempt_id.clone())
                    .await
                    .is_some_and(|b| !b.is_empty()),
                "{label}"
            );
        }

        // --- the paired non-zero arm: the SAME sweep, with the errors
        // replaced by successful "nothing happened" answers, DOES release.
        let (_dir, store) = open_store().await;
        let attempt = reserve_stale(&store, PROFILE, (CHAIN_NOW as i64) - 600).await;
        let chain = FakeChain::healthy();
        chain.set_receipt(Ok(None));
        chain.set_intent_used(Ok(false));
        chain.set_block_timestamp(Ok(CHAIN_NOW));

        let report = sweep_stuck_reservations(&store, (&chain).into(), &policy(OWNER), WALL_NOW)
            .await
            .expect("sweep");
        assert_eq!(report.released, 1);
        assert_eq!(report.stuck_recoverable(), 0);
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, attempt.allocation_id.clone()).await,
            Some(NONCE_STATUS_RELEASED.to_string())
        );
    }

    /// **A2 — the trigger is the wall clock, the decision is the chain
    /// clock.** A reservation whose lease expired long ago on the host clock
    /// must still NOT be released while the parent intent could still execute
    /// on chain: the signed payload is out there and anybody can broadcast it.
    ///
    /// The two clocks are deliberately 100 million seconds apart here, so the
    /// guard cannot pass by coincidence.
    ///
    /// Mutation this detects: compare `intent.expires_at` against `now_wall`
    /// instead of `block_timestamp()` in [`resolve_against_chain`] — the guard
    /// then stops firing (wall clock `1_800_000_000` > `expires_at`) and the
    /// row is released.
    #[tokio::test]
    async fn sweeper_never_releases_a_chain_time_valid_intent() {
        // --- arm 1: still valid on the CHAIN clock, long expired on the
        // WALL clock -> held. --------------------------------------------
        let still_valid_on_chain = (CHAIN_NOW as i64) + 600;
        assert!(
            still_valid_on_chain < WALL_NOW,
            "the fixture must have the wall clock past the deadline, or this \
             test cannot distinguish the two clocks"
        );

        let (_dir, store) = open_store().await;
        let attempt = reserve_stale(&store, PROFILE, still_valid_on_chain).await;
        let chain = FakeChain::healthy();

        let report = sweep_stuck_reservations(&store, (&chain).into(), &policy(OWNER), WALL_NOW)
            .await
            .expect("sweep");

        assert_eq!(report.claimed, 1);
        assert_eq!(report.held_intent_still_valid, 1);
        assert_eq!(report.released, 0);
        assert_eq!(
            text(&store, ATTEMPT_STATUS_SQL, attempt.attempt_id.clone()).await,
            Some(TX_ATTEMPT_STATUS_RESERVED.to_string())
        );
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, attempt.allocation_id.clone()).await,
            Some(NONCE_STATUS_ALLOCATED.to_string())
        );

        // --- arm 2 (the pair): move the deadline one second BEFORE chain
        // time and nothing else changes -> released. ----------------------
        let (_dir2, store2) = open_store().await;
        let attempt2 = reserve_stale(&store2, PROFILE, (CHAIN_NOW as i64) - 1).await;
        let chain2 = FakeChain::healthy();

        let report2 = sweep_stuck_reservations(&store2, (&chain2).into(), &policy(OWNER), WALL_NOW)
            .await
            .expect("sweep 2");

        assert_eq!(report2.held_intent_still_valid, 0);
        assert_eq!(report2.released, 1);
        assert_eq!(
            text(&store2, NONCE_STATUS_SQL, attempt2.allocation_id.clone()).await,
            Some(NONCE_STATUS_RELEASED.to_string())
        );
    }

    /// **The persistence ordering.** The signed transaction must be sealed
    /// into `raw_tx_enc` (and its hash into `raw_tx_hash`) by a transaction
    /// that has already COMMITTED when `eth_sendRawTransaction` is called.
    ///
    /// The send is armed to fail, which is this test's crash simulation: if
    /// the seal happened after the broadcast, the early return on the send
    /// error would leave `raw_tx_enc` NULL and the row unrecoverable by
    /// construction — exactly the pre-Task-7 state.
    ///
    /// Mutation this detects: move the `crypto_store::seal` + the
    /// `raw_tx_enc`/`raw_tx_hash` binds out of
    /// [`reserve_and_persist_raw_tx`]'s `write_tx` and into
    /// [`reserve_persist_and_send`] after the `send_raw_transaction` call.
    #[tokio::test]
    async fn raw_tx_is_persisted_before_broadcast() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE, (CHAIN_NOW as i64) + 600).await;

        let chain = FakeChain::healthy();
        chain.set_send_result(Err("connection reset by peer".into()));

        let raw = signed();
        let req = request(PROFILE, OWNER);
        let outcome = reserve_persist_and_send(
            &store,
            &data_key_hex(),
            (&chain).into(),
            &req,
            &raw,
            WALL_NOW,
        )
        .await
        .expect("send path");

        let SendOutcome::SendFailedStuckRecoverable { attempt, detail } = outcome else {
            panic!("a failed send must report stuck-recoverable, not success");
        };
        assert!(detail.contains("connection reset"));

        // The broadcaster really was called, with the bytes we persisted.
        assert_eq!(chain.send_calls(), 1);
        assert_eq!(chain.last_send_raw().as_deref(), Some(raw.raw()));

        // ...and the payload survived the failure.
        let enc = blob(&store, ATTEMPT_RAW_ENC_SQL, attempt.attempt_id.clone()).await;
        assert!(
            enc.as_ref().is_some_and(|b| !b.is_empty()),
            "raw_tx_enc must be non-NULL after a failed broadcast"
        );
        assert_eq!(
            text(&store, ATTEMPT_RAW_HASH_SQL, attempt.attempt_id.clone()).await,
            Some(raw.hash_hex()),
            "raw_tx_hash must be the keccak256 of the persisted bytes"
        );
        // A failed send must NOT look like an accepted one.
        assert_eq!(
            text(&store, ATTEMPT_TX_HASH_SQL, attempt.attempt_id.clone()).await,
            None,
            "tx_hash means 'a node accepted this'; a failed send never did"
        );
        assert_eq!(
            text(&store, ATTEMPT_STATUS_SQL, attempt.attempt_id.clone()).await,
            Some(TX_ATTEMPT_STATUS_RESERVED.to_string())
        );
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, attempt.allocation_id.clone()).await,
            Some(NONCE_STATUS_ALLOCATED.to_string()),
            "F2: a send failure is not evidence, so the nonce stays held"
        );

        // --- the paired ZERO arm: a store where the reservation never ran
        // has no sealed row at all, which proves the assertion above counts
        // something the reservation actually did. -------------------------
        let (_dir2, store2) = open_store().await;
        seed_intent(&store2, PROFILE, (CHAIN_NOW as i64) + 600).await;
        assert_eq!(
            count(&store2, RAW_ENC_PRESENT_SQL, attempt.attempt_id.clone()).await,
            0,
            "no reservation ran against this store"
        );
        assert_eq!(
            count(&store, RAW_ENC_PRESENT_SQL, attempt.attempt_id.clone()).await,
            1,
            "the same query returns 1 where the reservation DID run"
        );

        // ...and the successful send DOES record a tx_hash, so the
        // `tx_hash == None` assertion above is not vacuous either.
        let (_dir3, store3) = open_store().await;
        seed_intent(&store3, PROFILE, (CHAIN_NOW as i64) + 600).await;
        let chain3 = FakeChain::healthy();
        let req3 = request(PROFILE, OWNER);
        let ok = reserve_persist_and_send(
            &store3,
            &data_key_hex(),
            (&chain3).into(),
            &req3,
            &raw,
            WALL_NOW,
        )
        .await
        .expect("send path 3");
        let SendOutcome::Broadcast {
            attempt: a3,
            tx_hash_hex,
        } = ok
        else {
            panic!("an accepted send must report Broadcast");
        };
        assert_eq!(tx_hash_hex, bytes32_hex([0xEE; 32]));
        assert_eq!(
            text(&store3, ATTEMPT_TX_HASH_SQL, a3.attempt_id.clone()).await,
            Some(bytes32_hex([0xEE; 32]))
        );
        assert_eq!(
            text(&store3, ATTEMPT_STATUS_SQL, a3.attempt_id.clone()).await,
            Some(TX_ATTEMPT_STATUS_SUBMITTED.to_string())
        );
    }

    // -------------------------------------------------------------------
    // Supporting behaviour.
    // -------------------------------------------------------------------

    /// A mined **success** for the transaction we ourselves signed is handed
    /// to reconciliation with a NON-NULL `tx_hash`, and consumes the nonce.
    ///
    /// Mutation this detects: drop the `tx_hash` bind in the `MinedOurs` arm —
    /// the row goes back to reconcile with a NULL `tx_hash`, which is the very
    /// hole brief §5.3 documents (reconcile's hash guard is skipped for NULL).
    #[tokio::test]
    async fn a_mined_receipt_consumes_the_nonce_and_records_the_hash() {
        let (_dir, store) = open_store().await;
        let attempt = reserve_stale(&store, PROFILE, (CHAIN_NOW as i64) - 600).await;
        let raw_hash = signed().hash();
        let chain = FakeChain::healthy();
        chain.set_receipt(Ok(Some(TxReceiptView {
            tx_hash: raw_hash,
            block_number: 4200,
            block_hash: [0x77; 32],
            success: true,
            gas_used: 21_000,
        })));
        // Armed to `false` on purpose: a receipt must be sufficient on its
        // own, and this proves the success did not come from `intentUsed`.
        chain.set_intent_used(Ok(false));

        let report = sweep_stuck_reservations(&store, (&chain).into(), &policy(OWNER), WALL_NOW)
            .await
            .expect("sweep");

        assert_eq!(report.executed, 1);
        assert_eq!(report.released, 0);
        assert_eq!(
            chain.intent_used_calls(),
            0,
            "a decisive receipt must short-circuit before intentUsed"
        );
        assert_eq!(
            text(&store, ATTEMPT_TX_HASH_SQL, attempt.attempt_id.clone()).await,
            Some(bytes32_hex(raw_hash)),
            "reconcile must never receive this row with a NULL tx_hash"
        );
        assert_eq!(
            text(&store, ATTEMPT_STATUS_SQL, attempt.attempt_id.clone()).await,
            Some(TX_ATTEMPT_STATUS_SUBMITTED.to_string())
        );
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, attempt.allocation_id.clone()).await,
            Some(NONCE_STATUS_CONSUMED.to_string())
        );
    }

    /// A **mined revert** consumed nothing on chain, but the signed payload
    /// stays executable until the intent expires (spec §8.2), so the release
    /// still has to pass the chain-time guard.
    ///
    /// Mutation this detects: return `SafeToRelease` directly from the
    /// reverted-receipt arm (brief §5.1's literal wording) — arm 1 then
    /// releases a nonce whose payload can still land.
    #[tokio::test]
    async fn a_mined_revert_waits_for_the_intent_to_expire_before_releasing() {
        let reverted = |hash| {
            Ok(Some(TxReceiptView {
                tx_hash: hash,
                block_number: 4200,
                block_hash: [0x77; 32],
                success: false,
                gas_used: 21_000,
            }))
        };

        // arm 1: intent still chain-time valid -> held.
        let (_dir, store) = open_store().await;
        let attempt = reserve_stale(&store, PROFILE, (CHAIN_NOW as i64) + 600).await;
        let chain = FakeChain::healthy();
        chain.set_receipt(reverted(signed().hash()));
        let report = sweep_stuck_reservations(&store, (&chain).into(), &policy(OWNER), WALL_NOW)
            .await
            .expect("sweep");
        assert_eq!(report.held_intent_still_valid, 1);
        assert_eq!(report.released, 0);
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, attempt.allocation_id.clone()).await,
            Some(NONCE_STATUS_ALLOCATED.to_string())
        );

        // arm 2: same revert, intent expired -> released.
        let (_dir2, store2) = open_store().await;
        let attempt2 = reserve_stale(&store2, PROFILE, (CHAIN_NOW as i64) - 1).await;
        let chain2 = FakeChain::healthy();
        chain2.set_receipt(reverted(signed().hash()));
        let report2 = sweep_stuck_reservations(&store2, (&chain2).into(), &policy(OWNER), WALL_NOW)
            .await
            .expect("sweep 2");
        assert_eq!(report2.released, 1);
        assert_eq!(
            text(&store2, ATTEMPT_STATUS_SQL, attempt2.attempt_id.clone()).await,
            Some(TX_ATTEMPT_STATUS_FAILED.to_string())
        );
    }

    /// Spec §9.3 lease discipline. Two sweepers cannot both service one row:
    /// the first pass pushes `lease_until` one TTL into the future, so the
    /// second sweeper's trigger predicate matches nothing until that lease
    /// runs out.
    ///
    /// Mutation this detects: make the deferral in `apply_resolutions` reuse
    /// `now_wall` (i.e. `deferred_lease = now_wall - 1`) instead of
    /// `now_wall + lease_ttl_seconds` — sweeper B then claims the row sweeper
    /// A is still holding, and `claimed` is 1 in both passes.
    ///
    /// **Disclosed:** the `lease_until < ?` predicate on the claiming `UPDATE`
    /// is NOT what this test kills — it is redundant with the identical
    /// predicate in the SELECT (see the comment on that statement). What this
    /// test kills is the *deferral* pushing the lease forward.
    #[tokio::test]
    async fn a_second_sweeper_cannot_claim_a_row_the_first_one_holds() {
        let (_dir, store) = open_store().await;
        // Chain-time valid, so the first sweep HOLDS the row (it stays
        // `reserved`) instead of finishing it — otherwise the second sweeper
        // would find nothing for the uninteresting reason that the row is
        // already terminal.
        let attempt = reserve_stale(&store, PROFILE, (CHAIN_NOW as i64) + 600).await;
        let chain = FakeChain::healthy();

        let first =
            sweep_stuck_reservations(&store, (&chain).into(), &policy("sweeper-a"), WALL_NOW)
                .await
                .expect("sweep a");
        assert_eq!(first.claimed, 1);
        assert_eq!(first.held_intent_still_valid, 1);

        // Same wall-clock instant: sweeper A's lease is now in the future.
        let second =
            sweep_stuck_reservations(&store, (&chain).into(), &policy("sweeper-b"), WALL_NOW)
                .await
                .expect("sweep b");
        assert_eq!(
            second.claimed, 0,
            "the CAS must exclude a second sweeper for the whole lease"
        );

        // ...and once the lease has expired, it IS claimable again — so the
        // exclusion above is a lease, not a permanent lock.
        let later = WALL_NOW + DEFAULT_LEASE_TTL_SECONDS + 1;
        let third = sweep_stuck_reservations(&store, (&chain).into(), &policy("sweeper-b"), later)
            .await
            .expect("sweep c");
        assert_eq!(third.claimed, 1);
        assert_eq!(
            text(&store, ATTEMPT_STATUS_SQL, attempt.attempt_id.clone()).await,
            Some(TX_ATTEMPT_STATUS_RESERVED.to_string())
        );
    }

    /// The profile-ownership boundary (`submit.rs:1383-1393`) survives into
    /// the outbox: a reservation whose intent row exists but belongs to
    /// somebody else is `IntentNotFound` — the same error as "no such row", so
    /// it is not an existence oracle.
    ///
    /// **Reaching the comparison at all takes deliberate setup, and that is
    /// the point.** `intents.id` is `deterministic_id([domain, profile_id,
    /// intent_id_hex])` (defect C2), so a foreign profile normally addresses a
    /// row id that simply does not exist and is refused by the `None` branch
    /// three lines earlier. A test that only did *that* would assert nothing
    /// whatsoever about ownership while looking like it did — the I7 defect
    /// shape. So this test seeds a row AT the id the caller derives, owned by
    /// a different profile, which is the only input that reaches the
    /// comparison.
    ///
    /// Mutation this detects: delete the `owner != profile_id` comparison in
    /// [`reserve_and_persist_raw_tx`] — the foreign caller then reserves a
    /// nonce against an intent row it does not own. (Verified: with the
    /// comparison removed this test fails; with the naive "just ask as another
    /// profile" setup it would have passed either way.)
    #[tokio::test]
    async fn reservation_refuses_an_intent_row_owned_by_another_profile() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE, (CHAIN_NOW as i64) + 600).await;

        let squatter = "profile-outbox-2";
        // The row id `squatter` will derive — but owned by PROFILE.
        let contested_row = intent_row_id(squatter, INTENT_ID);
        let squatter_owned = squatter.to_string();
        let contested = contested_row.clone();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT OR IGNORE INTO profiles (id, created_at, status) \
                         VALUES (?, 0, 'active')",
                    )
                    .bind(&squatter_owned)
                    .execute(&mut **tx)
                    .await?;
                    sqlx::query(
                        "INSERT INTO intents (id, profile_id, intent_type, status, \
                         created_at, expires_at) \
                         VALUES (?, ?, 'sponsored_enrollment', 'pending', 0, 0)",
                    )
                    .bind(&contested)
                    .bind(PROFILE)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed contested row");

        let req = ReservationRequest {
            profile_id: squatter,
            ..request(PROFILE, OWNER)
        };
        let err = reserve_and_persist_raw_tx(&store, &data_key_hex(), &req, &signed(), WALL_NOW)
            .await
            .expect_err("a non-owner must not reserve against this row");
        assert!(matches!(err, OutboxError::IntentNotFound));
        assert_eq!(err.code(), ERR_OUTBOX_INTENT_NOT_FOUND);
        // Nothing was written for the refused caller.
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM tx_attempts WHERE id = ?",
                tx_attempt_row_id(squatter, INTENT_ID, 0)
            )
            .await,
            0
        );

        // Paired positive arm: the owner of its own row reserves fine, so the
        // refusal above is about ownership and not about the module being
        // unable to reserve at all.
        let ok_req = request(PROFILE, OWNER);
        let ok = reserve_and_persist_raw_tx(&store, &data_key_hex(), &ok_req, &signed(), WALL_NOW)
            .await
            .expect("the owner may reserve");
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM tx_attempts WHERE id = ?",
                ok.attempt_id.clone()
            )
            .await,
            1
        );
    }

    /// 🔴 The `UNIQUE (chain_id, signer_address, nonce)` + `INSERT OR IGNORE`
    /// + `rows_affected()` exclusivity, on the branch nothing reached before.
    ///
    /// **Found by a Task 8 Wave B coverage probe.** Changing
    /// `if ri.rows_affected() != 1` to `if ri.rows_affected() == u64::MAX` on
    /// the `nonce_allocations` insert left the whole suite green (525 passed),
    /// so that guard — one of the invariants Mandate 1 requires the surviving
    /// reservation to enforce — was **untested**. This test closes it.
    ///
    /// Reaching the branch takes the same deliberate setup
    /// `reservation_refuses_an_intent_row_owned_by_another_profile` needs, and
    /// for the same reason. `nonce_allocations.id` is
    /// `sha256(domain | chain | signer_key | nonce)` — deterministic in
    /// *exactly* the UNIQUE key — so an ordinary collision always carries our
    /// own id and is caught by the `SELECT … WHERE id = ? AND kind = ?` above,
    /// which takes the `UPDATE` branch instead. The one input that reaches the
    /// `INSERT` with the index already occupied is a row at the same
    /// `(chain_id, signer_address, nonce)` whose `kind` is **not** `'action'`:
    /// the `kind` predicate hides it from the `SELECT`, and then `INSERT OR
    /// IGNORE` is silently swallowed by the UNIQUE index. Without the
    /// `rows_affected()` check the reservation would report success while
    /// holding no claim at all, and the `tx_attempts` row it goes on to write
    /// would point at somebody else's allocation.
    ///
    /// MUTATION DETECTED: `if ri.rows_affected() != 1` →
    /// `if ri.rows_affected() == u64::MAX`. Run 2026-07-25: with the guard
    /// live the suite is green; with it neutered this test fails at
    /// `expect_err`. Re-verified after this test existed.
    #[tokio::test]
    async fn a_swallowed_nonce_insert_is_refused_not_reported_as_a_claim() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE, (CHAIN_NOW as i64) + 600).await;

        // A foreign-kind row squatting this action nonce's UNIQUE slot. Its
        // primary key is deliberately NOT the action row id, which is what
        // makes it invisible to the kind-filtered lookup.
        let signer_key = action_nonce_signer_key(CONTROLLER, ActionType::SponsoredEnrollment);
        let squatter_id = "not-the-derived-action-row-id".to_string();
        let signer_for_tx = signer_key.clone();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO nonce_allocations \
                         (id, chain_id, signer_address, nonce, status, allocated_at, kind) \
                         VALUES (?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(&squatter_id)
                    .bind(CHAIN_ID as i64)
                    .bind(&signer_for_tx)
                    .bind(ACTION_NONCE as i64)
                    .bind(NONCE_STATUS_ALLOCATED)
                    .bind(WALL_NOW)
                    .bind(super::super::broadcaster::NONCE_KIND_BROADCASTER)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed the squatting row");

        let req = request(PROFILE, OWNER);
        let err = reserve_and_persist_raw_tx(&store, &data_key_hex(), &req, &signed(), WALL_NOW)
            .await
            .expect_err("a swallowed INSERT must not be reported as a claim");
        assert_eq!(err.code(), ERR_OUTBOX_NONCE_ALREADY_RESERVED);

        // Nothing was written: no attempt row may reference a claim that was
        // never taken.
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM tx_attempts WHERE id = ?",
                tx_attempt_row_id(PROFILE, INTENT_ID, 0)
            )
            .await,
            0
        );

        // Paired non-zero arm: the SAME nonce on a different chain id — where
        // the UNIQUE slot is free — reserves fine and writes its row. The
        // refusal above is therefore about the occupied index, not about this
        // fixture being unable to reserve at all.
        let free_req = ReservationRequest {
            chain_id: CHAIN_ID + 1,
            ..request(PROFILE, OWNER)
        };
        let ok =
            reserve_and_persist_raw_tx(&store, &data_key_hex(), &free_req, &signed(), WALL_NOW)
                .await
                .expect("a free UNIQUE slot reserves");
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM tx_attempts WHERE id = ?",
                ok.attempt_id.clone()
            )
            .await,
            1
        );
    }

    /// A live reservation refuses a second one (the `SubmitInFlight` shape
    /// `submit.rs:1412-1416` uses), and a released one is retried as attempt
    /// N+1 rather than silently overwriting attempt N (A4).
    ///
    /// Mutation this detects: replace `next_attempt_number =
    /// next_attempt_number.max(number + 1)` with a constant `0` — the retry
    /// then derives attempt 0's row id, its `INSERT OR IGNORE` hits the
    /// existing primary key, `rows_affected()` is 0 and the reservation fails
    /// `InFlight`, so a replacement transaction is impossible.
    ///
    /// Wave E (A4) strengthened this test: the retry must be a **new row**, and
    /// attempt 0's evidence — its `raw_tx_hash`, i.e. the payload that may
    /// still be sitting in a mempool — must survive untouched.
    #[tokio::test]
    async fn a_retry_after_release_is_a_new_attempt_number() {
        let (_dir, store) = open_store().await;
        let attempt = reserve_stale(&store, PROFILE, (CHAIN_NOW as i64) - 600).await;
        assert_eq!(attempt.attempt_number, 0);

        // While it is live, a second reservation is refused.
        let req = request(PROFILE, OWNER);
        let err = reserve_and_persist_raw_tx(&store, &data_key_hex(), &req, &signed(), WALL_NOW)
            .await
            .expect_err("a live reservation must exclude a second one");
        assert!(matches!(err, OutboxError::InFlight { .. }));

        // Release it through the sweeper (chain proves non-consumption and the
        // intent has expired), then retry.
        let chain = FakeChain::healthy();
        let report = sweep_stuck_reservations(&store, (&chain).into(), &policy(OWNER), WALL_NOW)
            .await
            .expect("sweep");
        assert_eq!(report.released, 1);

        let retry = reserve_and_persist_raw_tx(
            &store,
            &data_key_hex(),
            &req,
            &SignedRawTx::new(
                vec![0x02, 0x99, 0x88],
                GasUnits::new(500_000),
                MaxFeePerGas::new(1_000_000_000),
            ),
            WALL_NOW + 1,
        )
        .await
        .expect("retry after release");
        assert_eq!(retry.attempt_number, 1, "A4: attempts are ordered");
        assert_ne!(
            retry.attempt_id, attempt.attempt_id,
            "A4: a replacement is a NEW row, not an overwrite of attempt 0"
        );
        assert_eq!(
            retry.attempt_id,
            tx_attempt_row_id(PROFILE, INTENT_ID, 1),
            "the new row must carry the canonical id for its attempt number"
        );
        assert_eq!(
            text(&store, ATTEMPT_RAW_HASH_SQL, retry.attempt_id.clone()).await,
            Some(retry.raw_tx_hash_hex.clone()),
            "the retry's raw_tx_hash must be the RETRY's payload, not the old one"
        );
        assert_ne!(retry.raw_tx_hash_hex, attempt.raw_tx_hash_hex);

        // 🔴 The A4 property. Attempt 0 is a gas-bumped replacement's
        // predecessor: its payload is signed, may still be in a mempool, and is
        // the only thing that can identify it if it lands. The pre-Wave-E
        // `UPDATE` overwrote exactly this column.
        assert_eq!(
            text(&store, ATTEMPT_RAW_HASH_SQL, attempt.attempt_id.clone()).await,
            Some(attempt.raw_tx_hash_hex.clone()),
            "attempt 0's evidence must survive its replacement"
        );
        // Two rows, not one — the ledger really did grow.
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM tx_attempts WHERE intent_id = ?",
                intent_row_id(PROFILE, INTENT_ID)
            )
            .await,
            2,
            "one row per attempt"
        );
    }

    /// `SignedRawTx` derives the hash from the bytes; it is never supplied.
    ///
    /// Mutation this detects: hash something other than the exact wire bytes
    /// (e.g. `keccak256(&raw[1..])`) — the pin below fails, and with it every
    /// receipt lookup the sweeper makes.
    #[test]
    fn signed_raw_tx_hash_is_keccak256_of_the_wire_bytes() {
        let bytes = vec![0x02u8, 0xf8, 0x6b, 0x01];
        let s = SignedRawTx::new(
            bytes.clone(),
            GasUnits::new(500_000),
            MaxFeePerGas::new(1_000_000_000),
        );
        assert_eq!(s.hash(), keccak256(&bytes));
        assert_eq!(
            s.hash_hex(),
            format!("0x{}", hex::encode(keccak256(&bytes)))
        );
        // Different bytes, different hash — so the assertion above is not
        // satisfied by a constant.
        assert_ne!(
            SignedRawTx::new(
                vec![0x02u8, 0xf8, 0x6b, 0x02],
                GasUnits::new(500_000),
                MaxFeePerGas::new(1_000_000_000),
            )
            .hash(),
            s.hash()
        );
    }

    /// The `Debug` impl must not dump the signed payload into a log line.
    ///
    /// Mutation this detects: replace the manual impl's `len` field with the
    /// derived shape's `raw` field (`hex::encode(&self.raw)`) — a signed
    /// transaction then lands in every `{:?}` of a [`ReservationRequest`]
    /// error path.
    #[test]
    fn signed_raw_tx_debug_does_not_print_the_payload() {
        let s = SignedRawTx::new(
            vec![0xDEu8, 0xAD, 0xBE, 0xEF],
            GasUnits::new(500_000),
            MaxFeePerGas::new(1_000_000_000),
        );
        let rendered = format!("{s:?}");
        assert!(rendered.contains(&s.hash_hex()));
        assert!(!rendered.contains("deadbeef"));
        assert!(!rendered.contains("222"), "no raw byte array in Debug");
    }

    /// A row with no `raw_tx_hash` and no `intent_id_hex` — the shape every
    /// pre-Task-7 `reserved` row has — cannot be resolved, so it must be
    /// reported stuck rather than guessed at.
    ///
    /// Mutation this detects: treat a missing `intent_id_hex` as "not used"
    /// and fall through to the release branch — a legacy row's nonce is then
    /// released with no evidence whatsoever.
    #[tokio::test]
    async fn a_legacy_row_with_no_evidence_columns_is_stuck_not_released() {
        let (_dir, store) = open_store().await;
        let attempt = reserve_stale(&store, PROFILE, (CHAIN_NOW as i64) - 600).await;
        // Strip the Task-7 columns back to their pre-0002 state.
        let attempt_id = attempt.attempt_id.clone();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "UPDATE tx_attempts \
                         SET raw_tx_hash = NULL, intent_id_hex = NULL, raw_tx_enc = NULL \
                         WHERE id = ?",
                    )
                    .bind(&attempt_id)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("strip columns");

        let chain = FakeChain::healthy();
        let report = sweep_stuck_reservations(&store, (&chain).into(), &policy(OWNER), WALL_NOW)
            .await
            .expect("sweep");

        assert_eq!(report.released, 0);
        assert_eq!(report.stuck_recoverable(), 1);
        assert!(report.stuck[0].reason.contains("intent_id_hex"));
        assert_eq!(
            chain.intent_used_calls(),
            0,
            "there is nothing to ask intentUsed about"
        );
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, attempt.allocation_id.clone()).await,
            Some(NONCE_STATUS_ALLOCATED.to_string())
        );
    }

    /// **The `chain_now == 0` guard.** `ChainClient::block_timestamp`'s trait
    /// default is `Ok(0)` (`chain.rs:139-141`), so a client that does not
    /// override it reaches [`resolve_against_chain`]'s chain-time guard with a
    /// zero clock. The sweeper must surface that as `Stuck` — the operator has
    /// to be told the client is unconfigured.
    ///
    /// **Mutation this detects (run and reverted, GAP4):** replace
    /// `if chain_now == 0 {` with `if false {`. The row is then **held**, not
    /// released — `0 < expires_at` is true for every positive expiry — so
    /// `held_intent_still_valid` becomes 1 and `stuck_recoverable()` becomes 0,
    /// and both assertions below fail. That direction is the corrected version
    /// of the rationale in the guard's own comment, which used to claim the
    /// unguarded code would release.
    ///
    /// The fixture's intent is already expired on the chain clock, so nothing
    /// but this guard can be producing the `Stuck`; the paired arm proves it by
    /// replacing only the timestamp with a real one and observing a release.
    #[tokio::test]
    async fn block_timestamp_zero_is_stuck_not_a_silent_hold() {
        let (_dir, store) = open_store().await;
        let attempt = reserve_stale(&store, PROFILE, (CHAIN_NOW as i64) - 600).await;
        let chain = FakeChain::healthy();
        chain.set_block_timestamp(Ok(0));

        let report = sweep_stuck_reservations(&store, (&chain).into(), &policy(OWNER), WALL_NOW)
            .await
            .expect("sweep");

        assert_eq!(report.claimed, 1);
        assert_eq!(report.released, 0);
        assert_eq!(
            report.held_intent_still_valid, 0,
            "a zero clock must not be laundered into a silent hold: an unguarded \
             `0 < expires_at` holds this row forever with no diagnostic"
        );
        assert_eq!(
            report.stuck_recoverable(),
            1,
            "an unconfigured client has to reach the operator"
        );
        assert!(
            report.stuck[0].reason.contains("unknown"),
            "the reason must name what 0 means, got {:?}",
            report.stuck[0].reason
        );
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, attempt.allocation_id.clone()).await,
            Some(NONCE_STATUS_ALLOCATED.to_string())
        );
        assert_eq!(
            text(&store, ATTEMPT_STATUS_SQL, attempt.attempt_id.clone()).await,
            Some(TX_ATTEMPT_STATUS_RESERVED.to_string())
        );

        // --- paired arm: the ONLY change is a real chain clock. ----------
        let (_dir2, store2) = open_store().await;
        let attempt2 = reserve_stale(&store2, PROFILE, (CHAIN_NOW as i64) - 600).await;
        let chain2 = FakeChain::healthy();
        chain2.set_block_timestamp(Ok(CHAIN_NOW));

        let report2 = sweep_stuck_reservations(&store2, (&chain2).into(), &policy(OWNER), WALL_NOW)
            .await
            .expect("sweep 2");
        assert_eq!(report2.released, 1);
        assert_eq!(report2.stuck_recoverable(), 0);
        assert_eq!(
            text(&store2, NONCE_STATUS_SQL, attempt2.allocation_id.clone()).await,
            Some(NONCE_STATUS_RELEASED.to_string())
        );
    }

    /// **F2, fail closed on corrupt evidence.** A `raw_tx_hash` that is not a
    /// 32-byte hex string is the one piece of evidence this row has, and it is
    /// unreadable. The sweep must stop there.
    ///
    /// **Mutation this detects (run and reverted, GAP9):** replace the
    /// `let … else { return Stuck }` at the top of [`resolve_against_chain`]
    /// with `parse_bytes32(raw_hash_hex).unwrap_or([0u8; 32])`. The corrupt
    /// hash silently becomes the zero hash, `transaction_receipt(0x00…00)`
    /// answers `Ok(None)`, and the row walks on to the `intentUsed` /
    /// chain-time path having thrown its evidence away — then releases on
    /// evidence it never obtained. Under that mutation `released` is 1 and
    /// `receipt_calls` is 1, so both assertions below fail.
    ///
    /// The sibling `intent_id_hex` guard is covered by
    /// [`a_legacy_row_with_no_evidence_columns_is_stuck_not_released`]; this is
    /// the `raw_tx_hash` half, which was uncovered.
    ///
    /// Paired arm: the identical fixture with the hash left well-formed DOES
    /// release, so the refusal is the corrupt hash and not the setup.
    #[tokio::test]
    async fn a_malformed_raw_tx_hash_is_stuck_not_released() {
        let (_dir, store) = open_store().await;
        // Expired on the chain clock and `intentUsed=false`, so every other
        // gate in `resolve_against_chain` says "release".
        let attempt = reserve_stale(&store, PROFILE, (CHAIN_NOW as i64) - 600).await;
        let attempt_id = attempt.attempt_id.clone();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query("UPDATE tx_attempts SET raw_tx_hash = ? WHERE id = ?")
                        .bind("0xnot-a-32-byte-hex-string")
                        .bind(&attempt_id)
                        .execute(&mut **tx)
                        .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("corrupt the hash");

        let chain = FakeChain::healthy();
        let report = sweep_stuck_reservations(&store, (&chain).into(), &policy(OWNER), WALL_NOW)
            .await
            .expect("sweep");

        assert_eq!(report.claimed, 1);
        assert_eq!(
            report.released, 0,
            "a nonce must never be released on evidence that could not be read"
        );
        assert_eq!(report.stuck_recoverable(), 1);
        assert!(
            report.stuck[0].reason.contains("raw_tx_hash"),
            "the operator needs the column that is corrupt, got {:?}",
            report.stuck[0].reason
        );
        assert_eq!(
            chain.receipt_calls(),
            0,
            "an unreadable hash must not be turned into a lookup for some other \
             transaction"
        );
        assert_eq!(
            chain.intent_used_calls(),
            0,
            "the sweep must stop at the corrupt column, not walk past it"
        );
        assert_eq!(
            text(&store, NONCE_STATUS_SQL, attempt.allocation_id.clone()).await,
            Some(NONCE_STATUS_ALLOCATED.to_string())
        );
        assert_eq!(
            text(&store, ATTEMPT_STATUS_SQL, attempt.attempt_id.clone()).await,
            Some(TX_ATTEMPT_STATUS_RESERVED.to_string())
        );

        // --- paired arm: same fixture, hash left intact -> released. -----
        let (_dir2, store2) = open_store().await;
        let attempt2 = reserve_stale(&store2, PROFILE, (CHAIN_NOW as i64) - 600).await;
        let chain2 = FakeChain::healthy();
        let report2 = sweep_stuck_reservations(&store2, (&chain2).into(), &policy(OWNER), WALL_NOW)
            .await
            .expect("sweep 2");
        assert_eq!(report2.released, 1);
        assert_eq!(
            chain2.receipt_calls(),
            1,
            "non-zero arm: the lookup happens"
        );
        assert_eq!(
            text(&store2, NONCE_STATUS_SQL, attempt2.allocation_id.clone()).await,
            Some(NONCE_STATUS_RELEASED.to_string())
        );
    }

    /// A reservation that has NOT yet timed out is invisible to the sweeper —
    /// the trigger really is `lease_until < now`, not "every reserved row".
    ///
    /// Mutation this detects: drop the `lease_until < ?` predicate from
    /// **both** statements in [`claim_stale_reservations`] (the SELECT and the
    /// claiming UPDATE) — a healthy in-flight reservation is then claimed and
    /// resolved out from under the submit that is still running. The two
    /// predicates are redundant with each other, so removing only one is not
    /// observable; that redundancy is documented at the UPDATE rather than
    /// left for a later reader to trip over.
    #[tokio::test]
    async fn a_fresh_reservation_is_not_swept() {
        let (_dir, store) = open_store().await;
        seed_intent(&store, PROFILE, (CHAIN_NOW as i64) - 600).await;
        let req = request(PROFILE, OWNER);
        let attempt =
            reserve_and_persist_raw_tx(&store, &data_key_hex(), &req, &signed(), WALL_NOW)
                .await
                .expect("reserve");

        let chain = FakeChain::healthy();
        let report = sweep_stuck_reservations(&store, (&chain).into(), &policy(OWNER), WALL_NOW)
            .await
            .expect("sweep");
        assert_eq!(report.claimed, 0);
        assert_eq!(report.released, 0);

        // Paired arm: one second past the lease, the very same row IS swept.
        let later = attempt.lease_until + 1;
        let report2 = sweep_stuck_reservations(&store, (&chain).into(), &policy(OWNER), later)
            .await
            .expect("sweep 2");
        assert_eq!(report2.claimed, 1);
        assert_eq!(report2.released, 1);
    }
}
