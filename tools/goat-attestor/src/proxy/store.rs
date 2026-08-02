//! Persistence for the allowlisted fetch network's settlement lane, on top of
//! [`StreamGStore`].
//!
//! A second SQLite file was rejected: the WAL pragmas, the `fs2` instance lock,
//! the single-writer `BEGIN IMMEDIATE` rule in `StreamGStore::write_tx` and the
//! envelope AAD discipline are already correct there, and duplicating them
//! would create a second place for every one of them to be wrong. This module
//! adds five tables and no new discipline.
//!
//! # What may be inserted
//!
//! [`insert_verified_receipt`] takes a [`VerifiedReceipt`] and nothing else,
//! and `super::verify::verify_receipt_bundle` is that type's only constructor.
//! There is deliberately no "insert this receipt, trust me" entry point: a row
//! here is a receipt that cleared all ten stages, so everything downstream can
//! read rows instead of re-verifying submissions.
//!
//! # The two UNIQUE indexes are the replay defence, not a hint
//!
//! `proxy_receipts_session_chunk (session_id_hex, chunk_seq)` and
//! `proxy_receipts_operator_counter (operator_wallet, gateway_id_hex, counter)`
//! are declared in migration `0004`, and every duplicate refusal in this module
//! is one of them surfacing — never a check this module performs first. That is
//! deliberate: a pre-check in the caller is bypassed by the next caller, and
//! the constraint is what the file itself enforces. [`classify`] is the one
//! place that turns a constraint violation into a typed refusal, and
//! `a_replayed_receipt_is_a_duplicate_key_violation_not_an_addition` pins the
//! exact message SQLite produces so a change in that text reds a test instead
//! of silently degrading every duplicate into a generic store error.
//!
//! # Hex, and where the `0x` lives
//!
//! Every `*_hex` column and field holds **un-prefixed** lowercase hex, exactly
//! what `hex::encode` produces, so a reader round-trips through `hex::decode`
//! with no stripping step. The `0x` appears in exactly one place — the
//! [`ProxyStoreError`] messages — and nowhere else.
//!
//! # Privacy
//!
//! No column here can hold a destination: see the header of `0004` and
//! `the_proxy_schema_contains_no_destination_identifying_column`. The
//! destination is an integer `allowlist_entry_id` into a digest-pinned curated
//! manifest, and that is the whole of it.

use sqlx::Row;
use thiserror::Error;

use super::receipt::ChunkKind;
use super::verify::VerifiedReceipt;
use crate::stream_g::store::{StreamGStore, StreamGStoreError};

#[derive(Debug, Error)]
pub enum ProxyStoreError {
    #[error("DuplicateReceipt: session 0x{session_id_hex} chunk {chunk_seq} is already recorded")]
    DuplicateReceipt {
        session_id_hex: String,
        chunk_seq: u64,
    },

    #[error(
        "DuplicateCounter: operator 0x{operator} already used counter {counter} at this gateway"
    )]
    DuplicateCounter { operator: String, counter: u64 },

    /// A `u64`/`u128` that will not survive SQLite's signed 64-bit INTEGER.
    ///
    /// Not in the original interface list, and added deliberately. Without it
    /// a counter above `i64::MAX` binds as a **negative** integer: the row goes
    /// in, the UNIQUE index is satisfied by a value nobody can reproduce, and
    /// the receipt is silently unfindable. A refusal is the only honest
    /// outcome, and `a_counter_that_cannot_survive_sqlite_is_refused_not_wrapped`
    /// proves the wrap is what would otherwise happen.
    #[error("ValueOutOfRange: {field} = {value} does not fit SQLite's signed 64-bit INTEGER")]
    ValueOutOfRange { field: &'static str, value: u128 },

    /// A row that came back in a shape this module cannot have written.
    #[error("MalformedRow: column {column} holds {detail}")]
    MalformedRow {
        column: &'static str,
        detail: String,
    },

    #[error("store: {0}")]
    Store(#[from] StreamGStoreError),
}

/// One row of `proxy_receipts`, in the shape the aggregation lane reads.
///
/// A projection, not the whole row: everything the settlement arithmetic needs
/// and nothing it does not. The signatures stay in the table as evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReceipt {
    pub receipt_hash_hex: String,
    pub epoch_id: u64,
    pub session_id_hex: String,
    pub chunk_seq: u64,
    pub operator_wallet: String,
    pub consumer_id_hex: String,
    pub bytes_transferred: u64,
    pub chunk_kind: ChunkKind,
    pub gateway_id_hex: String,
    pub price_goat_wei_per_mebibyte: u128,
}

/// One row of `proxy_meter_commitments`.
///
/// A persistence shape, deliberately **not** the signed commitment object: the
/// gateway's signed struct and its canonicalisation belong to the meter module,
/// and this table stores what was accepted, not what was parsed. The two counts
/// keep their asymmetry — `witnessed_bytes_to_consumer` is observed,
/// `node_reported_from_origin` is re-signed and is never a settlement basis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeterCommitmentRow {
    pub gateway_id_hex: String,
    pub epoch_id: u64,
    pub session_id_hex: String,
    pub witnessed_bytes_to_consumer: u64,
    pub node_reported_from_origin: u64,
    pub commitment_hash_hex: String,
    pub gateway_signature_hex: String,
    pub observed_at_unix: u64,
    pub recorded_at_unix: u64,
}

/// One row of `proxy_epoch_totals` — one operator's whole epoch, which becomes
/// one Merkle leaf.
///
/// This module stores the numbers; it does not compute them and it does not
/// check the split. The 90/10 arithmetic and the solvency refusal belong to the
/// aggregation lane, and putting a second implementation of either here would
/// give the lane two answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochTotalRow {
    pub epoch_id: u64,
    pub operator_wallet: String,
    pub total_bytes: u64,
    pub receipt_count: u64,
    pub gross_goat_wei: u128,
    pub operator_goat_wei: u128,
    pub protocol_take_goat_wei: u128,
    pub take_bps: u32,
    pub recorded_at_unix: u64,
}

/// Every refusal in this module is a constraint declared in `0004`, so the
/// schema and the code cannot disagree about what a duplicate is.
///
/// SQLite names the **columns** of a violated unique index, not the index, and
/// when a row violates several it names only the first one it happened to
/// check — which for an exact replay is the counter index, not the session/chunk
/// one. Index-checking order is an implementation detail of SQLite and not
/// something a refusal's *name* may depend on, so [`disambiguate`] asks the
/// file which constraint the row actually collides with and this function is
/// the fallback for everything that is not a unique violation.
fn classify(err: sqlx::Error, v: &VerifiedReceipt) -> ProxyStoreError {
    let text = err.to_string();
    if text.contains("proxy_receipts.operator_wallet") && text.contains("proxy_receipts.counter") {
        return ProxyStoreError::DuplicateCounter {
            operator: hex::encode(v.receipt.operator_wallet),
            counter: v.receipt.counter,
        };
    }
    if (text.contains("proxy_receipts.session_id_hex") && text.contains("proxy_receipts.chunk_seq"))
        || text.contains("proxy_receipts.receipt_hash_hex")
    {
        return ProxyStoreError::DuplicateReceipt {
            session_id_hex: hex::encode(v.receipt.session_id),
            chunk_seq: v.receipt.chunk_seq,
        };
    }
    ProxyStoreError::Store(StreamGStoreError::from(err))
}

/// Name the constraint a refused insert actually collides with.
///
/// The constraint is still what refused the write — this runs *after* the
/// transaction rolled back, and it reads rather than writes. All it decides is
/// which of the two typed refusals to hand back, and it decides it by looking
/// at the committed rows rather than at SQLite's choice of which index to
/// mention. Receipt identity is checked first: an exact replay violates both
/// indexes, and "this chunk of this session is already recorded" is the more
/// specific of the two true statements.
async fn disambiguate(
    store: &StreamGStore,
    err: sqlx::Error,
    v: &VerifiedReceipt,
) -> ProxyStoreError {
    if !err.to_string().contains("UNIQUE constraint failed") {
        return classify(err, v);
    }

    let session_id_hex = hex::encode(v.receipt.session_id);
    let operator_wallet = hex::encode(v.receipt.operator_wallet);
    let gateway_id_hex = hex::encode(v.receipt.gateway_id);
    let (chunk_seq, counter) = (v.receipt.chunk_seq, v.receipt.counter);
    // Both already survived `as_i64` on the insert path — an out-of-range value
    // returns before the statement runs. `-1` is a value no row can hold (the
    // schema CHECKs both `>= 0`), so a hypothetical overflow degrades to
    // `classify` instead of matching the wrong row.
    let chunk_seq_i = i64::try_from(chunk_seq).unwrap_or(-1);
    let counter_i = i64::try_from(counter).unwrap_or(-1);

    let (session_clash, counter_clash) = {
        let session_id_hex = session_id_hex.clone();
        let operator_wallet = operator_wallet.clone();
        let probe: Result<(i64, i64), ProxyStoreError> = store
            .read(move |h| {
                Box::pin(async move {
                    let by_chunk = h
                        .fetch_scalar(
                            sqlx::query_scalar::<_, i64>(
                                "SELECT COUNT(*) FROM proxy_receipts \
                                 WHERE session_id_hex = ? AND chunk_seq = ?",
                            )
                            .bind(&session_id_hex)
                            .bind(chunk_seq_i),
                        )
                        .await
                        .map_err(|e| ProxyStoreError::Store(StreamGStoreError::from(e)))?;
                    let by_counter = h
                        .fetch_scalar(
                            sqlx::query_scalar::<_, i64>(
                                "SELECT COUNT(*) FROM proxy_receipts \
                                 WHERE operator_wallet = ? AND gateway_id_hex = ? \
                                   AND counter = ?",
                            )
                            .bind(&operator_wallet)
                            .bind(&gateway_id_hex)
                            .bind(counter_i),
                        )
                        .await
                        .map_err(|e| ProxyStoreError::Store(StreamGStoreError::from(e)))?;
                    Ok::<(i64, i64), ProxyStoreError>((by_chunk, by_counter))
                })
            })
            .await;
        match probe {
            Ok(pair) => pair,
            // The probe itself failed; fall back to the message.
            Err(_) => return classify(err, v),
        }
    };

    if session_clash > 0 {
        return ProxyStoreError::DuplicateReceipt {
            session_id_hex,
            chunk_seq,
        };
    }
    if counter_clash > 0 {
        return ProxyStoreError::DuplicateCounter {
            operator: operator_wallet,
            counter,
        };
    }
    classify(err, v)
}

/// A `u64` that must survive SQLite's signed 64-bit INTEGER, or a refusal.
fn as_i64(field: &'static str, value: u64) -> Result<i64, ProxyStoreError> {
    i64::try_from(value).map_err(|_| ProxyStoreError::ValueOutOfRange {
        field,
        value: u128::from(value),
    })
}

/// Owned, already-encoded copy of everything one `INSERT` binds.
///
/// Built before `write_tx` so the closure moves owned data rather than
/// borrowing across the transaction's higher-ranked lifetime.
struct ReceiptRow {
    receipt_hash_hex: String,
    epoch_id: i64,
    session_id_hex: String,
    chunk_seq: i64,
    chunk_kind: String,
    operator_wallet: String,
    consumer_id_hex: String,
    gateway_id_hex: String,
    allowlist_entry_id: i64,
    allowlist_manifest_digest_hex: String,
    bytes_transferred: i64,
    counter: i64,
    intent_hash_hex: String,
    consent_record_hash_hex: String,
    valid_from_unix: i64,
    valid_to_unix: i64,
    price_goat_wei_per_mebibyte: String,
    witnessed_bytes_to_consumer: i64,
    node_reported_from_origin: i64,
    witnessed_at_unix: i64,
    operator_signature_hex: String,
    consumer_signature_hex: String,
    gateway_signature_hex: String,
    operator_signer: String,
    consumer_signer: String,
    gateway_signer: String,
    chain_id: i64,
    verifying_contract: String,
    recorded_at_unix: i64,
}

/// Owned copy of the intent columns, for the same reason as [`ReceiptRow`].
struct IntentRow {
    intent_hash_hex: String,
    epoch_id: i64,
    session_id_hex: String,
    operator_wallet: String,
    consumer_id_hex: String,
    gateway_id_hex: String,
    allowlist_entry_id: i64,
    allowlist_manifest_digest_hex: String,
    max_bytes: i64,
    valid_from_unix: i64,
    valid_to_unix: i64,
    price_goat_wei_per_mebibyte: String,
    consumer_signature_hex: String,
    consumer_signer: String,
    recorded_at_unix: i64,
}

/// Record a verified receipt and the intent it binds to, in one transaction.
///
/// The intent is `INSERT OR IGNORE`: one intent covers every chunk of its
/// session, so the second chunk of a session finds it already there. The
/// receipt is a plain `INSERT`, because a second identical receipt is a replay
/// and must surface as one.
pub async fn insert_verified_receipt(
    store: &StreamGStore,
    v: &VerifiedReceipt,
    recorded_at_unix: u64,
) -> Result<(), ProxyStoreError> {
    let r = &v.receipt;
    let i = &v.intent;
    let recorded_at = as_i64("recorded_at_unix", recorded_at_unix)?;

    let intent_row = IntentRow {
        intent_hash_hex: hex::encode(v.intent_struct_hash),
        epoch_id: as_i64("intent.epoch_id", i.epoch_id)?,
        session_id_hex: hex::encode(i.session_id),
        operator_wallet: hex::encode(i.operator_wallet),
        consumer_id_hex: hex::encode(i.consumer_id),
        gateway_id_hex: hex::encode(i.gateway_id),
        allowlist_entry_id: as_i64("intent.allowlist_entry_id", i.allowlist_entry_id)?,
        allowlist_manifest_digest_hex: hex::encode(i.allowlist_manifest_digest),
        max_bytes: as_i64("intent.max_bytes", i.max_bytes)?,
        valid_from_unix: as_i64("intent.valid_from_unix", i.valid_from_unix)?,
        valid_to_unix: as_i64("intent.valid_to_unix", i.valid_to_unix)?,
        price_goat_wei_per_mebibyte: i.price_goat_wei_per_mebibyte.to_string(),
        consumer_signature_hex: hex::encode(&v.consumer_sig),
        consumer_signer: hex::encode(v.consumer_signer),
        recorded_at_unix: recorded_at,
    };

    let receipt_row = ReceiptRow {
        receipt_hash_hex: hex::encode(v.receipt_hash),
        epoch_id: as_i64("epoch_id", r.epoch_id)?,
        session_id_hex: hex::encode(r.session_id),
        chunk_seq: as_i64("chunk_seq", r.chunk_seq)?,
        chunk_kind: r.chunk_kind.as_token().to_string(),
        operator_wallet: hex::encode(r.operator_wallet),
        consumer_id_hex: hex::encode(r.consumer_id),
        gateway_id_hex: hex::encode(r.gateway_id),
        allowlist_entry_id: as_i64("allowlist_entry_id", r.allowlist_entry_id)?,
        allowlist_manifest_digest_hex: hex::encode(r.allowlist_manifest_digest),
        bytes_transferred: as_i64("bytes_transferred", r.bytes_transferred)?,
        counter: as_i64("counter", r.counter)?,
        intent_hash_hex: hex::encode(r.intent_hash),
        consent_record_hash_hex: hex::encode(r.consent_record_hash),
        valid_from_unix: as_i64("valid_from_unix", r.valid_from_unix)?,
        valid_to_unix: as_i64("valid_to_unix", r.valid_to_unix)?,
        price_goat_wei_per_mebibyte: r.price_goat_wei_per_mebibyte.to_string(),
        witnessed_bytes_to_consumer: as_i64(
            "witnessed_bytes_to_consumer",
            v.witness.body_bytes_to_consumer,
        )?,
        node_reported_from_origin: as_i64(
            "node_reported_from_origin",
            v.witness.node_reported_from_origin,
        )?,
        witnessed_at_unix: as_i64("witnessed_at_unix", v.witness.witnessed_at_unix)?,
        operator_signature_hex: hex::encode(&v.operator_sig),
        consumer_signature_hex: hex::encode(&v.consumer_sig),
        gateway_signature_hex: hex::encode(&v.gateway_sig),
        operator_signer: hex::encode(v.operator_signer),
        consumer_signer: hex::encode(v.consumer_signer),
        gateway_signer: hex::encode(v.gateway_signer),
        chain_id: as_i64("chain_id", v.chain_id)?,
        verifying_contract: hex::encode(v.verifying_contract),
        recorded_at_unix: recorded_at,
    };

    // The closure cannot return a `ProxyStoreError` built from `v`, because
    // `classify` needs the receipt and the closure owns nothing but rows. The
    // raw `sqlx::Error` is carried out and classified here, where `v` is in
    // scope.
    let outcome: Result<(), StoreInsertError> = store
        .write_tx(move |tx| {
            Box::pin(async move {
                sqlx::query(
                    "INSERT OR IGNORE INTO proxy_session_intents (\
                       intent_hash_hex, epoch_id, session_id_hex, operator_wallet, \
                       consumer_id_hex, gateway_id_hex, allowlist_entry_id, \
                       allowlist_manifest_digest_hex, max_bytes, valid_from_unix, \
                       valid_to_unix, price_goat_wei_per_mebibyte, consumer_signature_hex, \
                       consumer_signer, recorded_at_unix) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&intent_row.intent_hash_hex)
                .bind(intent_row.epoch_id)
                .bind(&intent_row.session_id_hex)
                .bind(&intent_row.operator_wallet)
                .bind(&intent_row.consumer_id_hex)
                .bind(&intent_row.gateway_id_hex)
                .bind(intent_row.allowlist_entry_id)
                .bind(&intent_row.allowlist_manifest_digest_hex)
                .bind(intent_row.max_bytes)
                .bind(intent_row.valid_from_unix)
                .bind(intent_row.valid_to_unix)
                .bind(&intent_row.price_goat_wei_per_mebibyte)
                .bind(&intent_row.consumer_signature_hex)
                .bind(&intent_row.consumer_signer)
                .bind(intent_row.recorded_at_unix)
                .execute(&mut **tx)
                .await
                .map_err(StoreInsertError::Sqlx)?;

                sqlx::query(
                    "INSERT INTO proxy_receipts (\
                       receipt_hash_hex, epoch_id, session_id_hex, chunk_seq, chunk_kind, \
                       operator_wallet, consumer_id_hex, gateway_id_hex, allowlist_entry_id, \
                       allowlist_manifest_digest_hex, bytes_transferred, counter, \
                       intent_hash_hex, consent_record_hash_hex, valid_from_unix, \
                       valid_to_unix, price_goat_wei_per_mebibyte, \
                       witnessed_bytes_to_consumer, node_reported_from_origin, \
                       witnessed_at_unix, operator_signature_hex, consumer_signature_hex, \
                       gateway_signature_hex, operator_signer, consumer_signer, \
                       gateway_signer, chain_id, verifying_contract, recorded_at_unix) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                             ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&receipt_row.receipt_hash_hex)
                .bind(receipt_row.epoch_id)
                .bind(&receipt_row.session_id_hex)
                .bind(receipt_row.chunk_seq)
                .bind(&receipt_row.chunk_kind)
                .bind(&receipt_row.operator_wallet)
                .bind(&receipt_row.consumer_id_hex)
                .bind(&receipt_row.gateway_id_hex)
                .bind(receipt_row.allowlist_entry_id)
                .bind(&receipt_row.allowlist_manifest_digest_hex)
                .bind(receipt_row.bytes_transferred)
                .bind(receipt_row.counter)
                .bind(&receipt_row.intent_hash_hex)
                .bind(&receipt_row.consent_record_hash_hex)
                .bind(receipt_row.valid_from_unix)
                .bind(receipt_row.valid_to_unix)
                .bind(&receipt_row.price_goat_wei_per_mebibyte)
                .bind(receipt_row.witnessed_bytes_to_consumer)
                .bind(receipt_row.node_reported_from_origin)
                .bind(receipt_row.witnessed_at_unix)
                .bind(&receipt_row.operator_signature_hex)
                .bind(&receipt_row.consumer_signature_hex)
                .bind(&receipt_row.gateway_signature_hex)
                .bind(&receipt_row.operator_signer)
                .bind(&receipt_row.consumer_signer)
                .bind(&receipt_row.gateway_signer)
                .bind(receipt_row.chain_id)
                .bind(&receipt_row.verifying_contract)
                .bind(receipt_row.recorded_at_unix)
                .execute(&mut **tx)
                .await
                .map_err(StoreInsertError::Sqlx)?;

                Ok::<(), StoreInsertError>(())
            })
        })
        .await;

    match outcome {
        Ok(()) => Ok(()),
        Err(StoreInsertError::Sqlx(err)) => Err(disambiguate(store, err, v).await),
        Err(StoreInsertError::Store(err)) => Err(ProxyStoreError::Store(err)),
    }
}

/// Carries the raw `sqlx::Error` out of the transaction closure so
/// [`classify`] can see it with the receipt still in scope.
#[derive(Debug, Error)]
enum StoreInsertError {
    #[error("sqlx: {0}")]
    Sqlx(sqlx::Error),
    #[error("store: {0}")]
    Store(StreamGStoreError),
}

impl From<StreamGStoreError> for StoreInsertError {
    fn from(err: StreamGStoreError) -> Self {
        StoreInsertError::Store(err)
    }
}

/// Every receipt of one epoch, ordered so the aggregation lane sees a session's
/// chunks in sequence.
pub async fn load_epoch_receipts(
    store: &StreamGStore,
    epoch_id: u64,
) -> Result<Vec<StoredReceipt>, ProxyStoreError> {
    let epoch = as_i64("epoch_id", epoch_id)?;
    let rows = store
        .read(move |h| {
            Box::pin(async move {
                h.fetch_all(
                    sqlx::query(
                        "SELECT receipt_hash_hex, epoch_id, session_id_hex, chunk_seq, \
                                operator_wallet, consumer_id_hex, bytes_transferred, \
                                chunk_kind, gateway_id_hex, price_goat_wei_per_mebibyte \
                         FROM proxy_receipts WHERE epoch_id = ? \
                         ORDER BY operator_wallet, session_id_hex, chunk_seq",
                    )
                    .bind(epoch),
                )
                .await
                .map_err(|e| ProxyStoreError::Store(StreamGStoreError::from(e)))
            })
        })
        .await?;

    rows.into_iter()
        .map(|row| {
            let chunk_kind_token: String = column(&row, "chunk_kind")?;
            let chunk_kind = match chunk_kind_token.as_str() {
                "INTERIM" => ChunkKind::Interim,
                "FINAL" => ChunkKind::Final,
                other => {
                    return Err(ProxyStoreError::MalformedRow {
                        column: "chunk_kind",
                        detail: format!("{other:?}, which is neither INTERIM nor FINAL"),
                    })
                }
            };
            let price_text: String = column(&row, "price_goat_wei_per_mebibyte")?;
            let price_goat_wei_per_mebibyte =
                price_text
                    .parse::<u128>()
                    .map_err(|_| ProxyStoreError::MalformedRow {
                        column: "price_goat_wei_per_mebibyte",
                        detail: format!("{price_text:?}, which is not a decimal string"),
                    })?;

            Ok(StoredReceipt {
                receipt_hash_hex: column(&row, "receipt_hash_hex")?,
                epoch_id: unsigned(&row, "epoch_id")?,
                session_id_hex: column(&row, "session_id_hex")?,
                chunk_seq: unsigned(&row, "chunk_seq")?,
                operator_wallet: column(&row, "operator_wallet")?,
                consumer_id_hex: column(&row, "consumer_id_hex")?,
                bytes_transferred: unsigned(&row, "bytes_transferred")?,
                chunk_kind,
                gateway_id_hex: column(&row, "gateway_id_hex")?,
                price_goat_wei_per_mebibyte,
            })
        })
        .collect()
}

/// Record the gateway's own per-session count, or refresh it in place.
///
/// An upsert rather than an insert because a gateway may publish a running
/// total more than once for a live session. The primary key is
/// `(gateway_id, epoch_id, session_id)`, so one gateway has exactly one answer
/// per session per epoch and a second gateway's answer never overwrites it.
pub async fn upsert_meter_commitment(
    store: &StreamGStore,
    row: &MeterCommitmentRow,
) -> Result<(), ProxyStoreError> {
    let gateway_id_hex = row.gateway_id_hex.clone();
    let session_id_hex = row.session_id_hex.clone();
    let commitment_hash_hex = row.commitment_hash_hex.clone();
    let gateway_signature_hex = row.gateway_signature_hex.clone();
    let epoch_id = as_i64("epoch_id", row.epoch_id)?;
    let witnessed = as_i64(
        "witnessed_bytes_to_consumer",
        row.witnessed_bytes_to_consumer,
    )?;
    let from_origin = as_i64("node_reported_from_origin", row.node_reported_from_origin)?;
    let observed_at = as_i64("observed_at_unix", row.observed_at_unix)?;
    let recorded_at = as_i64("recorded_at_unix", row.recorded_at_unix)?;

    store
        .write_tx(move |tx| {
            Box::pin(async move {
                sqlx::query(
                    "INSERT INTO proxy_meter_commitments (\
                       gateway_id_hex, epoch_id, session_id_hex, witnessed_bytes_to_consumer, \
                       node_reported_from_origin, commitment_hash_hex, gateway_signature_hex, \
                       observed_at_unix, recorded_at_unix) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
                     ON CONFLICT (gateway_id_hex, epoch_id, session_id_hex) DO \
                     UPDATE SET witnessed_bytes_to_consumer = excluded.witnessed_bytes_to_consumer, \
                                node_reported_from_origin = excluded.node_reported_from_origin, \
                                commitment_hash_hex = excluded.commitment_hash_hex, \
                                gateway_signature_hex = excluded.gateway_signature_hex, \
                                observed_at_unix = excluded.observed_at_unix, \
                                recorded_at_unix = excluded.recorded_at_unix",
                )
                .bind(&gateway_id_hex)
                .bind(epoch_id)
                .bind(&session_id_hex)
                .bind(witnessed)
                .bind(from_origin)
                .bind(&commitment_hash_hex)
                .bind(&gateway_signature_hex)
                .bind(observed_at)
                .bind(recorded_at)
                .execute(&mut **tx)
                .await
                .map_err(|e| ProxyStoreError::Store(StreamGStoreError::from(e)))?;
                Ok::<(), ProxyStoreError>(())
            })
        })
        .await
}

/// Record every operator's totals for one epoch, in one transaction.
///
/// All-or-nothing on purpose: a half-written epoch is an epoch whose Merkle
/// root commits to operators the file does not list.
pub async fn record_epoch_totals(
    store: &StreamGStore,
    totals: &[EpochTotalRow],
) -> Result<(), ProxyStoreError> {
    struct Bound {
        epoch_id: i64,
        operator_wallet: String,
        total_bytes: i64,
        receipt_count: i64,
        gross_goat_wei: String,
        operator_goat_wei: String,
        protocol_take_goat_wei: String,
        take_bps: i64,
        recorded_at_unix: i64,
    }

    let mut bound = Vec::with_capacity(totals.len());
    for t in totals {
        bound.push(Bound {
            epoch_id: as_i64("epoch_id", t.epoch_id)?,
            operator_wallet: t.operator_wallet.clone(),
            total_bytes: as_i64("total_bytes", t.total_bytes)?,
            receipt_count: as_i64("receipt_count", t.receipt_count)?,
            gross_goat_wei: t.gross_goat_wei.to_string(),
            operator_goat_wei: t.operator_goat_wei.to_string(),
            protocol_take_goat_wei: t.protocol_take_goat_wei.to_string(),
            take_bps: i64::from(t.take_bps),
            recorded_at_unix: as_i64("recorded_at_unix", t.recorded_at_unix)?,
        });
    }

    store
        .write_tx(move |tx| {
            Box::pin(async move {
                for b in &bound {
                    sqlx::query(
                        "INSERT INTO proxy_epoch_totals (\
                           epoch_id, operator_wallet, total_bytes, receipt_count, \
                           gross_goat_wei, operator_goat_wei, protocol_take_goat_wei, \
                           take_bps, recorded_at_unix) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(b.epoch_id)
                    .bind(&b.operator_wallet)
                    .bind(b.total_bytes)
                    .bind(b.receipt_count)
                    .bind(&b.gross_goat_wei)
                    .bind(&b.operator_goat_wei)
                    .bind(&b.protocol_take_goat_wei)
                    .bind(b.take_bps)
                    .bind(b.recorded_at_unix)
                    .execute(&mut **tx)
                    .await
                    .map_err(|e| ProxyStoreError::Store(StreamGStoreError::from(e)))?;
                }
                Ok::<(), ProxyStoreError>(())
            })
        })
        .await
}

fn column(row: &sqlx::sqlite::SqliteRow, name: &'static str) -> Result<String, ProxyStoreError> {
    row.try_get::<String, _>(name)
        .map_err(|e| ProxyStoreError::MalformedRow {
            column: name,
            detail: e.to_string(),
        })
}

fn unsigned(row: &sqlx::sqlite::SqliteRow, name: &'static str) -> Result<u64, ProxyStoreError> {
    let raw: i64 = row
        .try_get(name)
        .map_err(|e| ProxyStoreError::MalformedRow {
            column: name,
            detail: e.to_string(),
        })?;
    u64::try_from(raw).map_err(|_| ProxyStoreError::MalformedRow {
        column: name,
        detail: format!("{raw}, a negative integer where a count belongs"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::Path;
    use std::str::FromStr;

    use alloy::primitives::B256;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;

    use crate::proxy::receipt::{BytesTransferredReceipt, ProxySessionIntent, PROXY_EPOCH_BASE};
    use crate::proxy::verify::{
        verify_receipt_bundle, GatewayWitness, ProxyPartyDirectory, ProxyReceiptBundle,
        VerifyContext,
    };

    /// The migration this module's tables come from, compiled in so a deleted
    /// file is a build failure rather than a skipped sweep.
    const MIGRATION_0004: &str = include_str!("../../migrations/0004_proxy_receipts.sql");

    const OPERATOR_PK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const CONSUMER_PK: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    const GATEWAY_PK: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

    const CONSUMER_ID: [u8; 32] = [0xC2; 32];
    const GATEWAY_ID: [u8; 32] = [0x67; 32];
    const MANIFEST_DIGEST: [u8; 32] = [0xD3; 32];
    const VERIFYING_CONTRACT: [u8; 20] = [0x11; 20];

    #[derive(Default)]
    struct TestDirectory {
        consumer_signers: HashMap<[u8; 32], [u8; 20]>,
        gateway_signers: HashMap<[u8; 32], [u8; 20]>,
    }

    impl ProxyPartyDirectory for TestDirectory {
        fn consumer_signer(&self, consumer_id: &[u8; 32]) -> Option<[u8; 20]> {
            self.consumer_signers.get(consumer_id).copied()
        }
        fn gateway_signer(&self, gateway_id: &[u8; 32]) -> Option<[u8; 20]> {
            self.gateway_signers.get(gateway_id).copied()
        }
        fn operator_cluster_root(&self, _operator_wallet: &[u8; 20]) -> Option<[u8; 32]> {
            None
        }
        fn consumer_cluster_root(&self, _consumer_id: &[u8; 32]) -> Option<[u8; 32]> {
            None
        }
    }

    fn signer(pk: &str) -> PrivateKeySigner {
        PrivateKeySigner::from_str(pk).expect("a fixed test key must parse")
    }

    fn sign(pk: &str, digest: [u8; 32]) -> Vec<u8> {
        signer(pk)
            .sign_hash_sync(&B256::from(digest))
            .expect("signing a 32-byte prehash cannot fail")
            .as_bytes()
            .to_vec()
    }

    fn address(pk: &str) -> [u8; 20] {
        signer(pk).address().into_array()
    }

    /// A verified receipt for `(epoch, session, chunk_seq, counter)`, built
    /// through the real ten-stage verification so nothing here can insert a row
    /// the verifier would have refused.
    fn verified(
        epoch_id: u64,
        session_id: [u8; 32],
        chunk_seq: u64,
        counter: u64,
        bytes: u64,
    ) -> VerifiedReceipt {
        let valid_from = 1_800_000_000u64;
        let valid_to = valid_from + 3_600;
        let operator = address(OPERATOR_PK);

        let intent = ProxySessionIntent {
            epoch_id,
            session_id,
            operator_wallet: operator,
            consumer_id: CONSUMER_ID,
            gateway_id: GATEWAY_ID,
            allowlist_entry_id: 7,
            allowlist_manifest_digest: MANIFEST_DIGEST,
            max_bytes: 104_857_600,
            valid_from_unix: valid_from,
            valid_to_unix: valid_to,
            price_goat_wei_per_mebibyte: 1_000_000_000_000,
        };
        let receipt = BytesTransferredReceipt {
            epoch_id,
            session_id,
            chunk_seq,
            chunk_kind: ChunkKind::Final,
            operator_wallet: operator,
            consumer_id: CONSUMER_ID,
            gateway_id: GATEWAY_ID,
            allowlist_entry_id: 7,
            allowlist_manifest_digest: MANIFEST_DIGEST,
            bytes_transferred: bytes,
            counter,
            intent_hash: intent.intent_struct_hash(),
            consent_record_hash: [0x2C; 32],
            valid_from_unix: valid_from,
            valid_to_unix: valid_to,
            price_goat_wei_per_mebibyte: 1_000_000_000_000,
        };
        let witness = GatewayWitness {
            receipt_struct_hash: receipt.receipt_struct_hash(),
            gateway_id: GATEWAY_ID,
            body_bytes_to_consumer: bytes,
            node_reported_from_origin: bytes + 4_096,
            witnessed_at_unix: valid_from + 10,
        };

        let bundle = ProxyReceiptBundle {
            operator_sig: sign(
                OPERATOR_PK,
                receipt.receipt_digest(31_337, VERIFYING_CONTRACT),
            ),
            consumer_sig: sign(
                CONSUMER_PK,
                intent.intent_digest(31_337, VERIFYING_CONTRACT),
            ),
            gateway_sig: sign(
                GATEWAY_PK,
                witness.witness_digest(31_337, VERIFYING_CONTRACT),
            ),
            receipt,
            intent,
            witness,
        };

        let mut dir = TestDirectory::default();
        dir.consumer_signers
            .insert(CONSUMER_ID, address(CONSUMER_PK));
        dir.gateway_signers.insert(GATEWAY_ID, address(GATEWAY_PK));

        let ctx = VerifyContext {
            chain_id: 31_337,
            verifying_contract: VERIFYING_CONTRACT,
            epoch_id,
            now_unix: valid_from + 60,
            allowlist_manifest_digest: MANIFEST_DIGEST,
            allowlist_entry_count: 12,
            directory: &dir,
        };
        verify_receipt_bundle(&bundle, &ctx).expect("the fixture must verify")
    }

    async fn open_store(dir: &Path) -> StreamGStore {
        StreamGStore::open(&dir.join("g.db"), &dir.join("g.lock"))
            .await
            .expect("a fresh store must open and migrate")
    }

    async fn count(store: &StreamGStore, table: &'static str) -> i64 {
        store
            .read(move |h| {
                Box::pin(async move {
                    h.fetch_scalar(sqlx::query_scalar::<_, i64>(match table {
                        "proxy_receipts" => "SELECT COUNT(*) FROM proxy_receipts",
                        "proxy_session_intents" => "SELECT COUNT(*) FROM proxy_session_intents",
                        "proxy_meter_commitments" => "SELECT COUNT(*) FROM proxy_meter_commitments",
                        "proxy_epoch_totals" => "SELECT COUNT(*) FROM proxy_epoch_totals",
                        other => panic!("no count query for {other}"),
                    }))
                    .await
                    .map_err(|e| ProxyStoreError::Store(StreamGStoreError::from(e)))
                })
            })
            .await
            .expect("count")
    }

    /// Every column name declared in `0004`, parsed out of the migration.
    ///
    /// Deliberately a real parser rather than a regex over the whole file: a
    /// sweep that matched the file text would also "find" column names inside
    /// the header comment, which would let a comment satisfy the floor while
    /// the schema underneath carried anything at all.
    fn declared_columns(sql: &str) -> Vec<String> {
        let mut columns = Vec::new();
        let mut inside_table = false;
        for raw in sql.lines() {
            let line = raw.split("--").next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.to_ascii_uppercase().starts_with("CREATE TABLE") {
                inside_table = true;
                continue;
            }
            if !inside_table {
                continue;
            }
            if line.starts_with(')') {
                inside_table = false;
                continue;
            }
            let first = line
                .split(|c: char| c.is_whitespace() || c == '(')
                .next()
                .unwrap_or("");
            let upper = first.to_ascii_uppercase();
            if matches!(
                upper.as_str(),
                "CHECK" | "PRIMARY" | "FOREIGN" | "UNIQUE" | "CONSTRAINT" | "REFERENCES" | ""
            ) {
                continue;
            }
            if first.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                columns.push(first.to_ascii_lowercase());
            }
        }
        columns
    }

    /// INV-11 in the schema. No column may name or imply a destination — the
    /// destination is an integer `allowlist_entry_id` and nothing else.
    ///
    /// Mutations this detects: adding any destination-shaped column to any of
    /// the five tables; renaming `allowlist_entry_id` to something that carries
    /// a locator; a parser regression that stops seeing columns (the floor
    /// catches it).
    #[test]
    fn the_proxy_schema_contains_no_destination_identifying_column() {
        let columns = declared_columns(MIGRATION_0004);

        // FLOOR, on columns and on bytes. A parser that returned nothing would
        // otherwise pass this test by sweeping nothing.
        assert!(
            columns.len() > 30,
            "column floor: only {} columns parsed out of `0004`",
            columns.len()
        );
        assert!(
            MIGRATION_0004.len() > 5_000,
            "byte floor: `0004` is only {} bytes",
            MIGRATION_0004.len()
        );

        // The parser really found the columns it claims to.
        for expected in [
            "receipt_hash_hex",
            "bytes_transferred",
            "allowlist_entry_id",
            "witnessed_bytes_to_consumer",
            "take_bps",
        ] {
            assert!(
                columns.iter().any(|c| c == expected),
                "the parser did not find {expected}; it is not reading the schema"
            );
        }
        // ...and did NOT pick up constraint keywords or comment prose.
        for never in ["check", "primary", "foreign", "the", "destination"] {
            assert!(
                !columns.iter().any(|c| c == never),
                "the parser is picking up {never}, so its output is not a column list"
            );
        }

        // Assembled at runtime, so this file does not itself contain the
        // tokens it forbids as literals.
        let forbidden: Vec<String> = vec![
            ["ho", "st"].concat(),
            ["u", "rl"].concat(),
            ["pa", "th"].concat(),
            ["qu", "ery"].concat(),
            ["s", "ni"].concat(),
            ["do", "main"].concat(),
            ["end", "point"].concat(),
            ["hea", "der"].concat(),
            ["bo", "dy"].concat(),
        ];

        for column in &columns {
            for token in &forbidden {
                assert!(
                    !column.contains(token.as_str()),
                    "column {column} names or implies a destination ({token})"
                );
            }
        }

        // POSITIVE CONTROL: the same detector, over a synthetic schema that
        // really does carry a destination, must fire. Without this the loop
        // above passes against a forbidden list that matches nothing.
        let planted = declared_columns(&format!(
            "CREATE TABLE t (\n    id INTEGER,\n    request_{} TEXT\n);\n",
            ["u", "rl"].concat()
        ));
        assert_eq!(planted.len(), 2, "the control schema has two columns");
        assert!(
            planted
                .iter()
                .any(|c| forbidden.iter().any(|t| c.contains(t.as_str()))),
            "the detector cannot see a destination column; its silence proves nothing"
        );
    }

    /// POSITIVE CONTROL for every store test below, and the round trip the
    /// aggregation lane depends on.
    ///
    /// Mutations this detects: binding the insert's columns out of declaration
    /// order (every value lands in the wrong column and the read-back
    /// disagrees); storing the EIP-712 digest where the canonical hash belongs;
    /// dropping the intent insert, which makes the receipt's foreign key fail.
    #[tokio::test]
    async fn a_verified_receipt_round_trips_through_the_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(dir.path()).await;
        let epoch = PROXY_EPOCH_BASE + 20_664;

        let v = verified(epoch, [0x5E; 32], 0, 42, 10_485_759);
        insert_verified_receipt(&store, &v, 1_800_000_100)
            .await
            .expect("a verified receipt must insert");

        assert_eq!(count(&store, "proxy_receipts").await, 1);
        assert_eq!(count(&store, "proxy_session_intents").await, 1);

        let rows = load_epoch_receipts(&store, epoch).await.expect("load");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.receipt_hash_hex, hex::encode(v.receipt_hash));
        assert_eq!(row.epoch_id, epoch);
        assert_eq!(row.session_id_hex, hex::encode([0x5Eu8; 32]));
        assert_eq!(row.chunk_seq, 0);
        assert_eq!(row.operator_wallet, hex::encode(address(OPERATOR_PK)));
        assert_eq!(row.consumer_id_hex, hex::encode(CONSUMER_ID));
        assert_eq!(row.bytes_transferred, 10_485_759);
        assert_eq!(row.chunk_kind, ChunkKind::Final);
        assert_eq!(row.gateway_id_hex, hex::encode(GATEWAY_ID));
        assert_eq!(row.price_goat_wei_per_mebibyte, 1_000_000_000_000);

        // The stored hash is the CANONICAL hash, not the EIP-712 struct hash —
        // two different 32-byte values, and confusing them would key the store
        // on something no second implementation reproduces from the JSON.
        assert_ne!(
            row.receipt_hash_hex,
            hex::encode(v.receipt_struct_hash),
            "the store must key on the canonical hash"
        );

        // A second chunk of the SAME session reuses the one intent row.
        let v2 = verified(epoch, [0x5E; 32], 1, 43, 1_024);
        insert_verified_receipt(&store, &v2, 1_800_000_200)
            .await
            .expect("a second chunk must insert");
        assert_eq!(count(&store, "proxy_receipts").await, 2);
        assert_eq!(
            count(&store, "proxy_session_intents").await,
            1,
            "one intent covers every chunk of its session"
        );
    }

    /// Replay defence, layer 2. A receipt already recorded is a duplicate-key
    /// violation, and the row count does not move.
    ///
    /// The row-count assertion is the load-bearing half: an `INSERT OR IGNORE`
    /// would also leave the count unchanged but would report success, and a
    /// caller that treats success as "this was recorded now" would settle the
    /// same chunk twice.
    ///
    /// Mutations this detects: relaxing `proxy_receipts_session_chunk` to a
    /// non-unique index; softening the receipt insert to `INSERT OR IGNORE`;
    /// a `classify` that stops recognising the constraint (the refusal then
    /// degrades to `Store` and this fails on the variant).
    #[tokio::test]
    async fn a_replayed_receipt_is_a_duplicate_key_violation_not_an_addition() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(dir.path()).await;
        let epoch = PROXY_EPOCH_BASE + 20_664;

        let v = verified(epoch, [0x5E; 32], 0, 42, 10_485_759);
        insert_verified_receipt(&store, &v, 1_800_000_100)
            .await
            .expect("first insert");
        let before = count(&store, "proxy_receipts").await;
        assert_eq!(before, 1);

        let err = insert_verified_receipt(&store, &v, 1_800_000_300)
            .await
            .expect_err("the same receipt twice is a replay");
        assert!(
            matches!(
                err,
                ProxyStoreError::DuplicateReceipt {
                    ref session_id_hex,
                    chunk_seq: 0
                } if *session_id_hex == hex::encode([0x5Eu8; 32])
            ),
            "expected DuplicateReceipt, got {err:?}"
        );
        assert_eq!(
            count(&store, "proxy_receipts").await,
            before,
            "a refused insert must not have added a row"
        );

        // A DIFFERENT chunk_seq of the same session is not a duplicate, so the
        // index above discriminates rather than refusing everything.
        let v2 = verified(epoch, [0x5E; 32], 1, 43, 1_024);
        insert_verified_receipt(&store, &v2, 1_800_000_400)
            .await
            .expect("a different chunk is not a replay");
        assert_eq!(count(&store, "proxy_receipts").await, 2);
    }

    /// Replay defence, layer 3. The per-(operator, gateway) counter is spent
    /// once, so re-issuing a fresh-looking receipt over the same work by
    /// changing a field the session/chunk index does not cover is refused too.
    ///
    /// Mutations this detects: dropping `proxy_receipts_operator_counter`;
    /// making it cover only `(operator_wallet, counter)` or only
    /// `(gateway_id_hex, counter)`; a `classify` that reports the wrong
    /// duplicate (the two variants are distinguished here).
    #[tokio::test]
    async fn a_counter_reused_at_the_same_gateway_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(dir.path()).await;
        let epoch = PROXY_EPOCH_BASE + 20_664;

        insert_verified_receipt(
            &store,
            &verified(epoch, [0x5E; 32], 0, 42, 10_485_759),
            1_800_000_100,
        )
        .await
        .expect("first insert");

        // A different session and a different chunk — but the same operator,
        // the same gateway and the same counter.
        let replay = verified(epoch, [0x6F; 32], 0, 42, 2_048);
        let err = insert_verified_receipt(&store, &replay, 1_800_000_200)
            .await
            .expect_err("a spent counter must be refused");
        assert!(
            matches!(
                err,
                ProxyStoreError::DuplicateCounter { counter: 42, ref operator }
                    if *operator == hex::encode(address(OPERATOR_PK))
            ),
            "expected DuplicateCounter, got {err:?}"
        );
        assert_eq!(count(&store, "proxy_receipts").await, 1);

        // The next counter, same operator and gateway, is accepted — so the
        // index discriminates on the counter and not on the pair.
        insert_verified_receipt(
            &store,
            &verified(epoch, [0x6F; 32], 0, 43, 2_048),
            1_800_000_300,
        )
        .await
        .expect("a fresh counter is not a replay");
        assert_eq!(count(&store, "proxy_receipts").await, 2);
    }

    /// A counter above `i64::MAX` must be refused, not wrapped.
    ///
    /// SQLite's INTEGER is signed. Binding `u64::MAX` as `i64` yields `-1`: the
    /// row goes in, the UNIQUE index is satisfied by a value nobody can
    /// reproduce, and the receipt becomes unfindable. This test proves the wrap
    /// is real (second half) and that the store refuses instead (first half).
    ///
    /// Mutations this detects: replacing `as_i64` with `as` casts anywhere in
    /// the insert path; dropping [`ProxyStoreError::ValueOutOfRange`].
    #[tokio::test]
    async fn a_counter_that_cannot_survive_sqlite_is_refused_not_wrapped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(dir.path()).await;
        let epoch = PROXY_EPOCH_BASE + 20_664;

        let v = verified(epoch, [0x5E; 32], 0, u64::MAX, 4_096);
        let err = insert_verified_receipt(&store, &v, 1_800_000_100)
            .await
            .expect_err("a counter SQLite cannot hold must be refused");
        assert!(
            matches!(
                err,
                ProxyStoreError::ValueOutOfRange {
                    field: "counter",
                    value
                } if value == u128::from(u64::MAX)
            ),
            "expected ValueOutOfRange, got {err:?}"
        );
        assert_eq!(
            count(&store, "proxy_receipts").await,
            0,
            "nothing may be written before the refusal"
        );

        // The hazard, demonstrated rather than asserted about: the naive cast
        // this refusal exists to prevent turns the largest counter into -1.
        assert_eq!(u64::MAX as i64, -1);
        assert!(i64::try_from(u64::MAX).is_err());

        // Negative control: `i64::MAX` itself is accepted, so the refusal is a
        // boundary and not a blanket.
        let ok = verified(epoch, [0x5E; 32], 0, i64::MAX as u64, 4_096);
        insert_verified_receipt(&store, &ok, 1_800_000_200)
            .await
            .expect("the largest representable counter must be accepted");
        assert_eq!(count(&store, "proxy_receipts").await, 1);
    }

    /// An epoch load returns that epoch and nothing else — the aggregation lane
    /// settles one window at a time, and a leak across windows would pay an
    /// epoch out of another epoch's pool.
    ///
    /// Mutations this detects: dropping the `WHERE epoch_id = ?` filter;
    /// binding the wrong parameter; ordering that interleaves sessions so a
    /// chunk-sequence check downstream sees a false gap.
    #[tokio::test]
    async fn an_epoch_load_returns_only_that_epochs_receipts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(dir.path()).await;
        let a = PROXY_EPOCH_BASE + 20_664;
        let b = PROXY_EPOCH_BASE + 20_665;

        for (epoch, session, seq, counter) in [
            (a, [0x5Eu8; 32], 0u64, 1u64),
            (a, [0x5Eu8; 32], 1, 2),
            (b, [0x6Fu8; 32], 0, 3),
        ] {
            insert_verified_receipt(
                &store,
                &verified(epoch, session, seq, counter, 4_096),
                1_800_000_100,
            )
            .await
            .expect("insert");
        }

        let from_a = load_epoch_receipts(&store, a).await.expect("load a");
        assert_eq!(from_a.len(), 2);
        assert!(from_a.iter().all(|r| r.epoch_id == a));
        // Ordered by (operator, session, chunk_seq).
        assert_eq!(
            from_a.iter().map(|r| r.chunk_seq).collect::<Vec<_>>(),
            vec![0, 1]
        );

        let from_b = load_epoch_receipts(&store, b).await.expect("load b");
        assert_eq!(from_b.len(), 1);
        assert_eq!(from_b[0].epoch_id, b);

        // An epoch with nothing in it is empty, not an error — and the two
        // non-empty loads above prove this is a real filter rather than a query
        // that always returns nothing.
        let empty = load_epoch_receipts(&store, PROXY_EPOCH_BASE + 99_999)
            .await
            .expect("load empty");
        assert!(empty.is_empty());
    }

    /// The gateway's own count is upserted per `(gateway, epoch, session)`, and
    /// a second gateway's answer never overwrites the first's.
    ///
    /// Mutations this detects: a primary key missing `gateway_id_hex` (one
    /// gateway then silently overwrites another's evidence); an `INSERT OR
    /// REPLACE` that drops columns it does not name; an upsert that inserts a
    /// second row instead of refreshing.
    #[tokio::test]
    async fn a_meter_commitment_upserts_per_gateway_epoch_and_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(dir.path()).await;

        let base = MeterCommitmentRow {
            gateway_id_hex: hex::encode(GATEWAY_ID),
            epoch_id: PROXY_EPOCH_BASE + 20_664,
            session_id_hex: hex::encode([0x5Eu8; 32]),
            witnessed_bytes_to_consumer: 1_024,
            node_reported_from_origin: 2_048,
            commitment_hash_hex: hex::encode([0x01u8; 32]),
            gateway_signature_hex: hex::encode([0x02u8; 65]),
            observed_at_unix: 1_800_000_010,
            recorded_at_unix: 1_800_000_020,
        };
        upsert_meter_commitment(&store, &base)
            .await
            .expect("insert");
        assert_eq!(count(&store, "proxy_meter_commitments").await, 1);

        // A running total for the same session refreshes the row in place.
        let mut grown = base.clone();
        grown.witnessed_bytes_to_consumer = 4_096;
        upsert_meter_commitment(&store, &grown)
            .await
            .expect("upsert");
        assert_eq!(count(&store, "proxy_meter_commitments").await, 1);

        // A second gateway's answer for the SAME session is its own row.
        let mut other = base.clone();
        other.gateway_id_hex = hex::encode([0x68u8; 32]);
        upsert_meter_commitment(&store, &other)
            .await
            .expect("second gateway");
        assert_eq!(
            count(&store, "proxy_meter_commitments").await,
            2,
            "one gateway's commitment must never overwrite another's"
        );
    }

    /// Epoch totals are wei-denominated `u128`s, so they round-trip as decimal
    /// strings. A value above `i64::MAX` is the normal case, not an edge one:
    /// one whole GOAT is already 1e18.
    ///
    /// Mutations this detects: storing a wei quantity in an INTEGER column
    /// (values above ~9.2e18 wrap); formatting with separators or in hex;
    /// writing only some of a batch's rows.
    #[tokio::test]
    async fn epoch_totals_round_trip_as_decimal_strings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(dir.path()).await;
        let epoch = PROXY_EPOCH_BASE + 20_664;

        // 1e30 wei: far above i64::MAX, and the reason these columns are TEXT.
        let huge: u128 = 1_000_000_000_000_000_000_000_000_000_000;
        assert!(huge > u128::from(u64::MAX));

        let rows = vec![
            EpochTotalRow {
                epoch_id: epoch,
                operator_wallet: hex::encode(address(OPERATOR_PK)),
                total_bytes: 20_971_520,
                receipt_count: 2,
                gross_goat_wei: huge,
                operator_goat_wei: huge / 10 * 9,
                protocol_take_goat_wei: huge - (huge / 10 * 9),
                take_bps: 1_000,
                recorded_at_unix: 1_800_000_500,
            },
            EpochTotalRow {
                epoch_id: epoch,
                operator_wallet: hex::encode([0xB1u8; 20]),
                total_bytes: 1_024,
                receipt_count: 1,
                gross_goat_wei: 1,
                operator_goat_wei: 0,
                protocol_take_goat_wei: 1,
                take_bps: 1_000,
                recorded_at_unix: 1_800_000_500,
            },
        ];
        record_epoch_totals(&store, &rows).await.expect("record");
        assert_eq!(count(&store, "proxy_epoch_totals").await, 2);

        let stored: String = store
            .read(move |h| {
                Box::pin(async move {
                    h.fetch_scalar(sqlx::query_scalar::<_, String>(
                        "SELECT gross_goat_wei FROM proxy_epoch_totals \
                         ORDER BY total_bytes DESC LIMIT 1",
                    ))
                    .await
                    .map_err(|e| ProxyStoreError::Store(StreamGStoreError::from(e)))
                })
            })
            .await
            .expect("read back");
        assert_eq!(stored, huge.to_string());
        assert_eq!(stored.parse::<u128>().expect("decimal"), huge);
        assert!(
            stored.bytes().all(|b| b.is_ascii_digit()),
            "a wei quantity must be a plain decimal string, got {stored:?}"
        );

        // All-or-nothing: a batch whose second row violates the primary key
        // leaves the first row unwritten too.
        let clash = vec![
            EpochTotalRow {
                epoch_id: epoch + 1,
                operator_wallet: hex::encode([0xC1u8; 20]),
                total_bytes: 1,
                receipt_count: 1,
                gross_goat_wei: 1,
                operator_goat_wei: 0,
                protocol_take_goat_wei: 1,
                take_bps: 1_000,
                recorded_at_unix: 1,
            },
            EpochTotalRow {
                epoch_id: epoch,
                operator_wallet: hex::encode([0xB1u8; 20]),
                total_bytes: 1,
                receipt_count: 1,
                gross_goat_wei: 1,
                operator_goat_wei: 0,
                protocol_take_goat_wei: 1,
                take_bps: 1_000,
                recorded_at_unix: 1,
            },
        ];
        assert!(record_epoch_totals(&store, &clash).await.is_err());
        assert_eq!(
            count(&store, "proxy_epoch_totals").await,
            2,
            "a partially-applied batch would commit to operators the file does not list"
        );
    }

    /// INV-11, over the live database rather than the schema text. Every value
    /// in every column of every proxy table is a count, an identifier, a hash,
    /// a signature or a timestamp — never a destination.
    ///
    /// The schema test above proves no column is *named* for a destination;
    /// this proves none *holds* one, which is the property that actually keeps
    /// the lane out of data-controller territory.
    ///
    /// Mutations this detects: smuggling a destination through an existing TEXT
    /// column (a hostname in `session_id_hex`, a locator in
    /// `commitment_hash_hex`); a future writer that packs extra context into a
    /// hex field.
    #[tokio::test]
    async fn no_stored_row_carries_a_destination_identifying_value() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(dir.path()).await;
        let epoch = PROXY_EPOCH_BASE + 20_664;

        insert_verified_receipt(
            &store,
            &verified(epoch, [0x5E; 32], 0, 42, 10_485_759),
            1_800_000_100,
        )
        .await
        .expect("insert");
        upsert_meter_commitment(
            &store,
            &MeterCommitmentRow {
                gateway_id_hex: hex::encode(GATEWAY_ID),
                epoch_id: epoch,
                session_id_hex: hex::encode([0x5Eu8; 32]),
                witnessed_bytes_to_consumer: 10_485_759,
                node_reported_from_origin: 10_489_855,
                commitment_hash_hex: hex::encode([0x01u8; 32]),
                gateway_signature_hex: hex::encode([0x02u8; 65]),
                observed_at_unix: 1_800_000_010,
                recorded_at_unix: 1_800_000_020,
            },
        )
        .await
        .expect("commitment");

        // Every TEXT value in the two populated tables, concatenated.
        let dumped: Vec<String> = store
            .read(move |h| {
                Box::pin(async move {
                    let mut out = Vec::new();
                    for query in [
                        "SELECT * FROM proxy_receipts",
                        "SELECT * FROM proxy_session_intents",
                        "SELECT * FROM proxy_meter_commitments",
                    ] {
                        for row in h
                            .fetch_all(sqlx::query(query))
                            .await
                            .map_err(|e| ProxyStoreError::Store(StreamGStoreError::from(e)))?
                        {
                            for i in 0..row.len() {
                                if let Ok(text) = row.try_get::<String, _>(i) {
                                    out.push(text);
                                }
                            }
                        }
                    }
                    Ok::<Vec<String>, ProxyStoreError>(out)
                })
            })
            .await
            .expect("dump");

        // FLOOR, and an EXACT one: 17 TEXT columns in `proxy_receipts`, 9 in
        // `proxy_session_intents`, 4 in `proxy_meter_commitments`, one row
        // each. A `>=` written for the finished lane would be unsatisfiable
        // today and a shrinking dump would pass it tomorrow; the task that adds
        // a TEXT column raises this number in the same commit.
        assert_eq!(
            dumped.len(),
            30,
            "text-value floor: {} swept, expected 17 + 9 + 4",
            dumped.len()
        );
        let swept_bytes: usize = dumped.iter().map(String::len).sum();
        assert!(swept_bytes > 1_000, "byte floor: {swept_bytes} bytes swept");

        let forbidden: Vec<String> = vec![
            ["ht", "tp"].concat(),
            ["//", ""].concat(),
            ["?", "="].concat(),
            [".", "com"].concat(),
            [".", "net"].concat(),
            ["Ho", "st:"].concat().to_ascii_lowercase(),
        ];
        for value in &dumped {
            let lower = value.to_ascii_lowercase();
            for token in &forbidden {
                assert!(
                    !lower.contains(token.as_str()),
                    "a stored value carries a destination-shaped token: {value}"
                );
            }
        }

        // POSITIVE CONTROL: the same detector over a value that really is a
        // destination must fire.
        let planted = [
            ["ht", "tp"].concat(),
            "s://example.invalid/a?b=c".to_string(),
        ]
        .concat();
        assert!(
            forbidden
                .iter()
                .any(|t| planted.to_ascii_lowercase().contains(t.as_str())),
            "the sweep cannot detect a destination; its silence proves nothing"
        );
    }
}
