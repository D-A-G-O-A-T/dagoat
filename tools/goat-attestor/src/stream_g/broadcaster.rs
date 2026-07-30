//! Stream G — the broadcaster EOA (Task 7, Wave C).
//!
//! Two jobs, both of which the crate previously had no way to do:
//!
//! 1. **A contiguous transaction-nonce frontier** for the dedicated
//!    broadcaster account, sourced from `eth_getTransactionCount` and held
//!    durably in `nonce_allocations` under `kind='broadcaster'`.
//! 2. **A non-blocking send.** [`sign_persist_and_broadcast`] signs, persists
//!    the signed bytes (via [`super::outbox`]), calls
//!    [`crate::chain::ChainClient::send_raw_transaction`] and returns. It
//!    never waits for a receipt.
//!
//! ## Why "non-blocking" is the safety property, not a performance one
//!
//! The pilot send path blocks: `rpc_chain.rs:264-278` does
//! `send_transaction` (15s) and then `pending.get_receipt()` (60s), and
//! `relayer.rs:871-873` states verbatim that the resulting `Err` "may mean the
//! tx was actually broadcast and lands later". Fed into `submit.rs`'s 6b
//! classification that timeout became `BroadcastFailed` → `Retryable` →
//! `record_failed`, which **released the action nonce while the transaction
//! was still live** — a double-submit of `actionNonces[controller][action]`.
//!
//! This module cannot produce that shape. Every failure after the payload is
//! signed carries the payload's hash — an Ethereum transaction hash is
//! `keccak256` of exactly the bytes that go on the wire, so a signer that has
//! produced bytes can always name them — and
//! [`BroadcastOutcome::as_broadcast_error`] hands `submit.rs` a
//! [`BroadcastError`] whose `tx_hash` is `Some`, which that module now refuses
//! to classify `Retryable`. Receipt observation belongs to reconciliation
//! (Wave D) and to `outbox::sweep_stuck_reservations`, which resolve against
//! chain evidence rather than a clock (founder ruling F2).
//!
//! ## The `kind` discriminator is not decoration
//!
//! `nonce_allocations` now holds two key spaces (brief §3.3):
//!
//! | `kind` | `signer_address` | Counter |
//! |---|---|---|
//! | `'action'` | `"<0xcontroller>#<ACTION_TYPE>"` | `actionNonces[signer][actionType]` on the gateway |
//! | `'broadcaster'` | bare `"0x…"` | the EOA's own transaction nonce |
//!
//! **Every** statement here filters on `kind`, including the `INSERT`, which
//! names the column explicitly. That last part is the one that bites hardest:
//! `0002_stream_g_outbox.sql` gives the column `DEFAULT 'action'`, so a writer
//! that merely *omits* it silently files a broadcaster row in the action key
//! space — after which the frontier query can no longer see the nonce it just
//! handed out and hands the same one out again. See
//! [`tests::broadcaster_eoa_nonce_does_not_alias_a_controller_action_nonce`].
//!
//! ## What this module deliberately does not do
//!
//! * **[`sign_persist_and_broadcast`] does not sign.** The private key lives
//!   behind `RpcChain` (`Role::Broadcaster`) and `ChainClient` exposes no
//!   signing method — only `send_raw_transaction`. Signing (and the
//!   ten-argument `executeSponsoredEnrollment` ABI encoding) is therefore
//!   behind the [`SponsoredEnrollmentTxSigner`] seam, whose production
//!   implementor is [`RpcChainEnrollmentSigner`] at the bottom of this file,
//!   built on [`crate::rpc_chain::RpcChain::sign_broadcaster_eip1559`].
//!
//! ## 🔴 Wave C W2 — this IS the submit path now
//!
//! `submit::submit_sponsored_enrollment` calls
//! [`sign_persist_and_broadcast`]. The rival seam it used to sign and send
//! through, `submit::SponsoredEnrollmentBroadcaster`, is **deleted**: its
//! `sign_sponsored_enrollment(gateway, call)` took no transaction nonce, so
//! any implementor had to source the EOA nonce itself — precisely what
//! [`allocate_broadcaster_nonce`]'s contiguity guarantee forbids — and it
//! consequently never had a production implementor in `src/` at all. There is
//! now exactly one signing path, one reservation
//! ([`super::outbox::reserve_and_persist_raw_tx`]) and one send in this crate.
//!
//! 🔴 **Wave C W4 — this path is now REACHABLE FROM THE NETWORK.** The bullet
//! that used to stand here said the opposite ("no route calls anything on this
//! path — `POST /v1/stream-g/submit` is unmounted"), and it was true until W4.
//! `stream_g::router` mounts `POST /v1/stream-g/submit`
//! (`submit::post_submit`), so a client request can reach
//! [`sign_persist_and_broadcast`] and therefore
//! [`crate::rpc_chain::RpcChain::sign_broadcaster_eip1559`] and
//! `eth_sendRawTransaction`. What bounds it is upstream of this module and is
//! not weakened by the mount: the per-nonce signing lease, the fresh
//! submit-time preflight, the `nonce_allocations` reservation, and the
//! exposure ceiling in [`BroadcastPlan::max_native_exposure_wei`] — which that
//! route refuses to serve at all while it is unset.
//!
//! One disclosure that was attached to that sentence and is **still true**:
//!
//! * [`BroadcastGasPolicy`] *is* now sourced from config
//!   (`StreamGConfig::broadcast_gas`, Wave C W1c), but its three numbers are
//!   still [`BroadcastGasPolicy::starting_values_pending_founder_review`] by
//!   default and none of them has been measured against a live
//!   `executeSponsoredEnrollment`.
//!
//! [`BroadcastOutcome::as_broadcast_error`] remains the documented
//! classification bridge; `submit.rs` matches the two outcome variants
//! directly, because that match is total and needs no `Option` round-trip.

use sha2::{Digest, Sha256};
use sqlx::Row;
use thiserror::Error;

use super::base_fee::{self, BaseFeeError, GasUnits, MaxFeePerGas, WeiCeiling};
use super::crypto_store::SecretHex;
use super::direct_eth;
use super::models::ActionType;
use super::outbox::{
    self, OutboxError, ReservationRequest, ReservedAttempt, SendOutcome, SignedRawTx,
};
use super::preflight::{self, SponsoredEnrollmentCall};
use super::store::{StreamGStore, StreamGStoreError};
use super::submit::{
    BroadcastError, NONCE_STATUS_ALLOCATED, NONCE_STATUS_CONSUMED, NONCE_STATUS_RELEASED,
};
use super::token_manifest::TrustedChain;
use crate::chain::TxHash;
use crate::rpc_chain::{Eip1559Request, RpcChain};

// ---------------------------------------------------------------------------
// Error codes (stable strings for logs / HTTP mapping), same convention as
// `submit.rs` and `outbox.rs`.
// ---------------------------------------------------------------------------

pub const ERR_BROADCASTER_STORE: &str = "BROADCASTER_STORE_ERROR";
pub const ERR_BROADCASTER_CHAIN: &str = "BROADCASTER_CHAIN_ERROR";
pub const ERR_BROADCASTER_NONCE_ROW_CONFLICT: &str = "BROADCASTER_NONCE_ROW_CONFLICT";
pub const ERR_BROADCASTER_OUT_OF_RANGE: &str = "BROADCASTER_OUT_OF_RANGE";
pub const ERR_BROADCASTER_SIGNING: &str = "BROADCASTER_SIGNING_ERROR";
pub const ERR_BROADCASTER_OUTBOX: &str = "BROADCASTER_OUTBOX_ERROR";

/// `nonce_allocations.kind` for a **broadcaster EOA transaction nonce**.
///
/// The counterpart is [`super::outbox::NONCE_KIND_ACTION`]. The two key spaces
/// share one table and one `UNIQUE (chain_id, signer_address, nonce)` index;
/// the discriminator is what keeps them from being read as each other.
pub const NONCE_KIND_BROADCASTER: &str = "broadcaster";

/// Row-id domain for broadcaster allocations.
///
/// Deliberately **not** `submit.rs`'s `stream_g_action_nonce_allocation`: two
/// different counters must not share a row-id preimage space, so that even a
/// future change to how either signer key is spelled cannot make one address
/// the other's row.
const BROADCASTER_NONCE_ID_DOMAIN: &str = "stream_g_broadcaster_eoa_nonce_allocation";

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum BroadcasterError {
    #[error("store error: {0}")]
    Store(#[from] StreamGStoreError),
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// A chain read failed. **Fail closed**: no nonce is allocated, nothing is
    /// signed, nothing is sent. A frontier guessed without
    /// `eth_getTransactionCount` is a frontier that re-issues a live nonce.
    #[error("chain read failed: {0}")]
    Chain(String),
    #[error("outbox error: {0}")]
    Outbox(#[from] OutboxError),
    /// `UNIQUE (chain_id, signer_address, nonce)` already holds a row at this
    /// coordinate that is **not** one of ours (a different `kind`, i.e. a row
    /// that was written without an explicit `kind` and so defaulted to
    /// `'action'`).
    ///
    /// Refused loudly on purpose. Skipping to the next free nonce instead
    /// would leave a permanent hole in the EOA's nonce sequence, and a hole
    /// stalls **every** later transaction from that account in the mempool
    /// until it is filled.
    #[error(
        "nonce_allocations already holds a non-broadcaster row for {signer} nonce {nonce} \
         on chain {chain_id}; refusing to skip it and leave a gap in the EOA nonce sequence"
    )]
    NonceRowConflict {
        chain_id: u64,
        signer: String,
        nonce: u64,
    },
    #[error("value {0} does not fit the schema's INTEGER column")]
    OutOfRange(u64),
    #[error("signing the transaction failed: {0}")]
    Signing(String),
    /// 🔴 Wave 2 — the native-ETH exposure gate (hazard 1) refused this
    /// broadcast, after the EOA nonce was allocated and the bytes were
    /// signed but before anything was persisted or sent.
    ///
    /// **The EOA nonce is released before this is returned.** Unlike
    /// `submit.rs`'s equivalent refusal, which holds no nonce at that
    /// point, a refusal here that did not release would leave the
    /// broadcaster account's nonce sequence permanently gapped — the same
    /// reason the `Err` arm of `reserve_persist_and_send` releases.
    #[error("native exposure gate refused this broadcast: {0}")]
    NativeExposure(#[source] BaseFeeError),
}

impl BroadcasterError {
    pub fn code(&self) -> &'static str {
        match self {
            // Delegated for the same reason `submit.rs` delegates: *which*
            // exposure rule refused is the operator-facing fact.
            BroadcasterError::NativeExposure(e) => e.code(),
            BroadcasterError::Store(_) | BroadcasterError::Sqlx(_) => ERR_BROADCASTER_STORE,
            BroadcasterError::Chain(_) => ERR_BROADCASTER_CHAIN,
            BroadcasterError::Outbox(_) => ERR_BROADCASTER_OUTBOX,
            BroadcasterError::NonceRowConflict { .. } => ERR_BROADCASTER_NONCE_ROW_CONFLICT,
            BroadcasterError::OutOfRange(_) => ERR_BROADCASTER_OUT_OF_RANGE,
            BroadcasterError::Signing(_) => ERR_BROADCASTER_SIGNING,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers (each `stream_g` module keeps its own copies by this tree's
// convention — see `root_authorization.rs`'s module doc).
// ---------------------------------------------------------------------------

fn deterministic_id(parts: &[&str]) -> String {
    hex::encode(Sha256::digest(parts.join("|").as_bytes()))
}

/// Canonical, lowercase, `0x`-prefixed. Deliberately derived from the 20 raw
/// bytes rather than accepted as a string: `RpcChain::broadcaster_address`
/// returns alloy's **EIP-55 checksummed** rendering, and a checksummed string
/// stored in `signer_address` would not compare equal to a lowercase one,
/// silently splitting one account's nonce sequence in two.
fn address_hex(a: [u8; 20]) -> String {
    format!("0x{}", hex::encode(a))
}

fn bytes32_hex(b: [u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

/// `nonce_allocations.id` for one broadcaster EOA transaction nonce.
pub fn broadcaster_nonce_row_id(chain_id: u64, broadcaster: [u8; 20], nonce: u64) -> String {
    deterministic_id(&[
        BROADCASTER_NONCE_ID_DOMAIN,
        &chain_id.to_string(),
        &address_hex(broadcaster),
        &nonce.to_string(),
    ])
}

// ---------------------------------------------------------------------------
// The nonce frontier.
// ---------------------------------------------------------------------------

/// One claimed broadcaster EOA transaction nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcasterNonce {
    pub allocation_id: String,
    pub nonce: u64,
    /// The bare, lowercase `0x…` address this nonce belongs to.
    pub signer_address: String,
    /// True when this allocation refilled a hole left by a previously
    /// released nonce rather than extending the frontier. Surfaced because
    /// "we are refilling a gap" is exactly the state an operator wants to see
    /// when transactions from this account have stopped confirming.
    pub refilled_gap: bool,
}

/// Claim the next broadcaster EOA transaction nonce, contiguously.
///
/// "Contiguously" is the whole contract. An Ethereum account's transactions
/// execute in nonce order, so a nonce that is allocated and then abandoned
/// stalls every later transaction from that account until something fills it.
/// The frontier is therefore:
///
/// 1. **the lowest released hole at or above the mined count**, if there is
///    one — refilling comes before extending;
/// 2. otherwise `max(mined_count, highest_live_local_nonce + 1)`.
///
/// `mined_count` is `eth_getTransactionCount(addr, "latest")` — the **mined**
/// count, not `"pending"`. `rpc_chain.rs`'s own `send_lock` doc records why:
/// on this service's deploy target the `pending` tag updates on a ~200ms
/// Flashblocks cadence rather than synchronously, and Base's guidance is to
/// track nonces in the application rather than refetch `pending` per
/// submission. The local rows are that application-level tracking; the mined
/// count is the floor that survives a lost database.
///
/// Fails closed: if the chain read fails, nothing is allocated at all.
pub async fn allocate_broadcaster_nonce(
    store: &StreamGStore,
    chain: TrustedChain<'_>,
    chain_id: u64,
    broadcaster: [u8; 20],
    claim_owner: &str,
    lease_ttl_seconds: i64,
    now_wall: i64,
) -> Result<BroadcasterNonce, BroadcasterError> {
    // Chain read happens BETWEEN transactions, never inside one: the store's
    // pool has a single connection and a hanging RPC must not hold SQLite's
    // writer lock (`outbox.rs`'s store discipline).
    let mined_count = chain
        .client()
        .transaction_count(broadcaster, false)
        .map_err(|e| BroadcasterError::Chain(format!("transaction_count: {e}")))?;

    let chain_id_i64 =
        i64::try_from(chain_id).map_err(|_| BroadcasterError::OutOfRange(chain_id))?;
    let mined_i64 =
        i64::try_from(mined_count).map_err(|_| BroadcasterError::OutOfRange(mined_count))?;
    let signer_address = address_hex(broadcaster);
    let claim_owner = claim_owner.to_string();
    let lease_until = now_wall.saturating_add(lease_ttl_seconds);
    let signer_for_tx = signer_address.clone();

    let (allocation_id, nonce_i64, refilled_gap) = store
        .write_tx(move |tx| {
            Box::pin(async move {
                // (1) Refill the lowest hole at or above the mined count.
                //     `kind` filtered: an action row must never be mistaken
                //     for a hole in this account's transaction sequence.
                let hole = sqlx::query(
                    "SELECT id, nonce FROM nonce_allocations \
                     WHERE kind = ? AND chain_id = ? AND signer_address = ? \
                       AND status = ? AND nonce >= ? \
                     ORDER BY nonce ASC LIMIT 1",
                )
                .bind(NONCE_KIND_BROADCASTER)
                .bind(chain_id_i64)
                .bind(&signer_for_tx)
                .bind(NONCE_STATUS_RELEASED)
                .bind(mined_i64)
                .fetch_optional(&mut **tx)
                .await?;

                if let Some(hole) = hole {
                    let id: String = hole.try_get("id")?;
                    let nonce: i64 = hole.try_get("nonce")?;
                    // The `kind = ?` and `status = ?` predicates below are a
                    // compare-and-swap against the SELECT above, which is the
                    // only statement in this function that reaches a row by
                    // `(chain_id, signer_address)` instead of by primary key —
                    // i.e. the only place a foreign row can be *found*. If that
                    // SELECT's own `kind` filter is ever weakened, this UPDATE
                    // is what turns "we picked up somebody else's row" into a
                    // loud `NonceRowConflict` instead of a silent hijack of an
                    // action nonce. Both halves are exercised by
                    // `tests::a_released_kindless_bare_address_row_is_not_taken_as_a_gap`.
                    let r = sqlx::query(
                        "UPDATE nonce_allocations \
                         SET status = ?, allocated_at = ?, released_at = NULL, \
                             claim_owner = ?, lease_until = ? \
                         WHERE id = ? AND kind = ? AND status = ?",
                    )
                    .bind(NONCE_STATUS_ALLOCATED)
                    .bind(now_wall)
                    .bind(&claim_owner)
                    .bind(lease_until)
                    .bind(&id)
                    .bind(NONCE_KIND_BROADCASTER)
                    .bind(NONCE_STATUS_RELEASED)
                    .execute(&mut **tx)
                    .await?;
                    if r.rows_affected() != 1 {
                        return Err(BroadcasterError::NonceRowConflict {
                            chain_id: chain_id_i64 as u64,
                            signer: signer_for_tx.clone(),
                            nonce: nonce as u64,
                        });
                    }
                    return Ok::<(String, i64, bool), BroadcasterError>((id, nonce, true));
                }

                // (2) Extend the frontier. `MAX(nonce)` over rows this
                //     account still owns — `allocated` (in flight) or
                //     `consumed` (landed). A `released` row is not live and
                //     was already considered as a hole above.
                let high = sqlx::query(
                    "SELECT MAX(nonce) AS high FROM nonce_allocations \
                     WHERE kind = ? AND chain_id = ? AND signer_address = ? \
                       AND status IN (?, ?)",
                )
                .bind(NONCE_KIND_BROADCASTER)
                .bind(chain_id_i64)
                .bind(&signer_for_tx)
                .bind(NONCE_STATUS_ALLOCATED)
                .bind(NONCE_STATUS_CONSUMED)
                .fetch_one(&mut **tx)
                .await?;
                let high: Option<i64> = high.try_get("high")?;

                let next = match high {
                    Some(h) => mined_i64.max(h.saturating_add(1)),
                    None => mined_i64,
                };
                let id = broadcaster_nonce_row_id(chain_id_i64 as u64, broadcaster, next as u64);

                // `kind` is named EXPLICITLY. `0002`'s `DEFAULT 'action'`
                // means omitting it here would file this row in the action
                // key space, where the frontier query above cannot see it —
                // and the next call would hand out the same nonce again.
                let ri = sqlx::query(
                    "INSERT OR IGNORE INTO nonce_allocations \
                     (id, chain_id, signer_address, nonce, status, allocated_at, \
                      kind, claim_owner, lease_until) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&id)
                .bind(chain_id_i64)
                .bind(&signer_for_tx)
                .bind(next)
                .bind(NONCE_STATUS_ALLOCATED)
                .bind(now_wall)
                .bind(NONCE_KIND_BROADCASTER)
                .bind(&claim_owner)
                .bind(lease_until)
                .execute(&mut **tx)
                .await?;
                if ri.rows_affected() != 1 {
                    // `INSERT OR IGNORE` swallowed it: the UNIQUE
                    // (chain_id, signer_address, nonce) index already holds a
                    // row here that the kind-filtered reads above could not
                    // see. Refuse rather than skip — see `NonceRowConflict`.
                    return Err(BroadcasterError::NonceRowConflict {
                        chain_id: chain_id_i64 as u64,
                        signer: signer_for_tx.clone(),
                        nonce: next as u64,
                    });
                }
                Ok((id, next, false))
            })
        })
        .await?;

    Ok(BroadcasterNonce {
        allocation_id,
        nonce: nonce_i64 as u64,
        signer_address,
        refilled_gap,
    })
}

/// Give a broadcaster nonce back, so the next allocation refills the hole
/// rather than leaving the EOA's sequence with a permanent gap.
///
/// Only ever correct when **nothing signed against this nonce can reach a
/// node** — see the call site in [`sign_persist_and_broadcast`], which
/// releases only when signing itself failed or the reservation was refused
/// before any send. Returns whether a row moved.
pub async fn release_broadcaster_nonce(
    store: &StreamGStore,
    allocation_id: &str,
    now_wall: i64,
) -> Result<bool, BroadcasterError> {
    let allocation_id = allocation_id.to_string();
    store
        .write_tx(move |tx| {
            Box::pin(async move {
                let r = sqlx::query(
                    "UPDATE nonce_allocations \
                     SET status = ?, released_at = ?, claim_owner = NULL, lease_until = NULL \
                     WHERE id = ? AND kind = ? AND status = ?",
                )
                .bind(NONCE_STATUS_RELEASED)
                .bind(now_wall)
                .bind(&allocation_id)
                .bind(NONCE_KIND_BROADCASTER)
                .bind(NONCE_STATUS_ALLOCATED)
                .execute(&mut **tx)
                .await?;
                Ok::<bool, BroadcasterError>(r.rows_affected() == 1)
            })
        })
        .await
}

/// Mark a broadcaster nonce as spent on chain — a mined transaction consumes
/// its EOA nonce whether it succeeded or reverted.
///
/// 🔴 **ZERO callers. Not production, not test.** This doc used to say
/// "Reconciliation's to call (Wave D)". Wave D has happened
/// (`maintenance::run_reconcile` is mounted and folds
/// `SponsoredEnrollmentExecuted` logs), and it does **not** call this. Naming a
/// wave that is already over is how a dangling primitive reads as scheduled
/// work, so here is the actual reason, which is structural rather than an
/// oversight:
///
/// **The reconciler cannot name this row.** It starts from a chain log, finds
/// the `tx_attempts` row that claims the log's transaction hash, and takes
/// `tx_attempts.nonce_allocation_id` — which is the gateway **action** nonce
/// (`kind='action'`), by construction: `outbox::reserve_and_persist_raw_tx` is
/// what writes that column. The broadcaster-EOA allocation id produced by
/// [`allocate_broadcaster_nonce`] lives only in the in-memory
/// [`BroadcasterNonce`] that [`sign_persist_and_broadcast`] returns, and
/// `0001`/`0002`/`0003` have no column that persists it. It cannot be derived
/// from chain evidence either: the row id is
/// `broadcaster_nonce_row_id(chain_id, broadcaster, nonce)` and
/// [`crate::chain::TxReceiptView`] carries neither the sender nor the
/// transaction nonce (`tx_hash`, `block_number`, `block_hash`, `success`,
/// `gas_used`), and `ChainClient` has no `eth_getTransactionByHash`.
///
/// So wiring it needs a schema change — a `broadcaster_allocation_id` column on
/// `tx_attempts`, written where the attempt row is written, in a `0004`
/// migration — plus threading the id through `ReservationRequest`. That is a
/// change to the **broadcast write path**, not to reconciliation, and it is not
/// this wave's.
///
/// **What the gap costs, plainly:** every broadcaster-EOA allocation for a
/// transaction that actually mines stays `allocated` forever. The frontier
/// (`MAX(nonce)` over `allocated`/`consumed`) still hands out the next nonce
/// correctly, so no nonce is reused and no gap opens — the sequence keeps
/// working. What is lost is the distinction between "in flight" and "landed" in
/// this table, so nothing can tell a genuinely stuck broadcast from a long-since
/// mined one by reading `nonce_allocations` alone.
///
/// Kept rather than deleted because it is the correct statement to run the
/// moment that link exists, and its `kind` predicate is the guard that keeps it
/// off an action row.
pub async fn consume_broadcaster_nonce(
    store: &StreamGStore,
    allocation_id: &str,
) -> Result<bool, BroadcasterError> {
    let allocation_id = allocation_id.to_string();
    store
        .write_tx(move |tx| {
            Box::pin(async move {
                let r = sqlx::query(
                    "UPDATE nonce_allocations \
                     SET status = ?, released_at = NULL, claim_owner = NULL, lease_until = NULL \
                     WHERE id = ? AND kind = ?",
                )
                .bind(NONCE_STATUS_CONSUMED)
                .bind(&allocation_id)
                .bind(NONCE_KIND_BROADCASTER)
                .execute(&mut **tx)
                .await?;
                Ok::<bool, BroadcasterError>(r.rows_affected() == 1)
            })
        })
        .await
}

// ---------------------------------------------------------------------------
// The send path.
// ---------------------------------------------------------------------------

/// Builds and signs the outer transaction for one
/// `executeSponsoredEnrollment`.
///
/// The **only** signing seam in this crate since Wave C W2 (`submit.rs`'s
/// rival `SponsoredEnrollmentBroadcaster` is deleted). Signing and sending
/// are separate because only one of the two halves needs a private key: this
/// produces bytes, the chain client puts them on the wire.
///
/// Implementors **must** sign against exactly `broadcaster_nonce` — the
/// frontier's contiguity guarantee is void if the signer picks its own —
/// and [`Self::broadcaster_address`] must name the account whose key they
/// sign with.
pub trait SponsoredEnrollmentTxSigner: Send + Sync {
    fn sign_sponsored_enrollment_tx(
        &self,
        gateway: [u8; 20],
        broadcaster_nonce: u64,
        call: &SponsoredEnrollmentCall<'_>,
    ) -> Result<SignedRawTx, String>;

    /// The 20 address bytes of the account this implementor signs with.
    ///
    /// 🔴 Wave C W2. Added so a caller that holds only a
    /// `&dyn SponsoredEnrollmentTxSigner` can still source
    /// [`BroadcastPlan::broadcaster`] **from the signer itself** rather than
    /// from a second, independently-supplied address. The type doc on
    /// [`RpcChainEnrollmentSigner`] states the hazard this closes: the plan's
    /// address drives the nonce frontier while the signer's key drives the
    /// signature, and `sign_sponsored_enrollment_tx` (`gateway, nonce, call`
    /// — no address) gives an implementor no way to detect a disagreement.
    /// `submit::submit_sponsored_enrollment` builds the plan from this method,
    /// which makes the disagreement unconstructible on that path.
    ///
    /// Deliberately **not** asserted against `plan.broadcaster` inside
    /// [`sign_persist_and_broadcast`]. That function's own tests build plans
    /// whose `broadcaster` is chosen for what it proves about the *allocation*
    /// table (`plan_with_ceiling` names `BOTH_HATS`, the address whose action
    /// and broadcaster rows must not alias), independently of whichever
    /// `FakeSigner` is passed alongside; an equality assertion there would
    /// couple two fixtures that are deliberately independent. The guarantee
    /// this method provides is at the *call site*: a caller that only ever
    /// writes `broadcaster: signer.broadcaster_address()` cannot express the
    /// disagreement in the first place.
    fn broadcaster_address(&self) -> [u8; 20];
}

/// Everything [`sign_persist_and_broadcast`] needs that is not the call.
pub struct BroadcastPlan<'a> {
    /// Already-authenticated profile id. Not a request field.
    pub profile_id: &'a str,
    /// The on-chain `intentId`.
    pub intent_id: [u8; 32],
    pub chain_id: u64,
    pub gateway: [u8; 20],
    /// The broadcaster EOA's 20 raw address bytes.
    pub broadcaster: [u8; 20],
    pub controller: [u8; 20],
    pub action: ActionType,
    /// `actionNonces[controller][action]` this attempt signs against.
    pub action_nonce: u64,
    pub claim_owner: &'a str,
    pub lease_ttl_seconds: i64,
    /// Ceiling for the native-ETH exposure gate (hazard 1), enforced
    /// between signing and `reserve_persist_and_send`.
    ///
    /// 🔴 **Wave C W2 amends this.** There is now exactly one caller of
    /// [`sign_persist_and_broadcast`] — `submit::submit_sponsored_enrollment`
    /// — and it binds this field from `SubmitContext::max_native_exposure_wei`
    /// and from nothing else.
    /// `submit::tests::exposure_gate_refuses_between_signing_and_reservation`
    /// drives a real refusal through that binding, and names replacing this
    /// field with `WeiCeiling::new(u128::MAX)` as the mutation it detects.
    ///
    /// 🔴 **Wave C W4 — a request now reaches this field**, and the two
    /// sentences that used to stand here ("no route calls
    /// `submit_sponsored_enrollment`, so no request reaches this struct" and
    /// "the route that mounts this path must surface an unset ceiling as
    /// such") are respectively false and discharged.
    /// `POST /v1/stream-g/submit` (`submit::post_submit`) fills
    /// `SubmitContext::max_native_exposure_wei` from
    /// `runtime::StreamGState::max_native_exposure_wei`, i.e. from
    /// `STREAM_G_MAX_NATIVE_EXPOSURE_WEI`, and refuses the request with
    /// `http_error::ERR_EXPOSURE_CEILING_UNSET` (503) when that value is the
    /// `0` default — so an operator who never set it sees a
    /// misconfiguration, not `EXPOSURE_EXCEEDS_SCHEDULE` on every request.
    ///
    /// **What is still open, stated as narrowly as it is true**: chain 31337
    /// carries no `GasPriceOracle` predeploy, so
    /// [`base_fee::submit_exposure_for_chain`] skips the gate there and no
    /// ceiling of any kind is enforced. That residue is disclosed on every
    /// receipt through `preflight::UNVERIFIED_CHECKS`.
    pub max_native_exposure_wei: WeiCeiling,
}

/// What one broadcast attempt ended as. **There is no "failed" variant**:
/// once bytes are signed, the only two honest answers are "a node took it"
/// and "we do not know".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastOutcome {
    /// A node accepted the raw transaction and returned this hash.
    Accepted {
        nonce: BroadcasterNonce,
        attempt: ReservedAttempt,
        tx_hash_hex: String,
    },
    /// `eth_sendRawTransaction` returned an error — which does **not** mean
    /// the payload never reached a mempool. Both nonces stay held and the
    /// signed transaction stays persisted; only chain evidence may resolve
    /// this (`outbox::sweep_stuck_reservations`).
    UnresolvedWithKnownHash {
        nonce: BroadcasterNonce,
        attempt: ReservedAttempt,
        raw_tx_hash: TxHash,
        detail: String,
    },
}

impl BroadcastOutcome {
    /// The bridge to `submit.rs`'s classification.
    ///
    /// `None` for [`BroadcastOutcome::Accepted`]; otherwise a
    /// [`BroadcastError`] carrying the signed payload's hash, which
    /// `submit_sponsored_enrollment` refuses to classify
    /// [`super::submit::Retryability::Retryable`] and refuses to release a
    /// nonce for. This is why this module can never produce the 6b
    /// double-submit: it has no path that yields `tx_hash: None` after
    /// signing.
    pub fn as_broadcast_error(&self) -> Option<BroadcastError> {
        match self {
            BroadcastOutcome::Accepted { .. } => None,
            BroadcastOutcome::UnresolvedWithKnownHash {
                raw_tx_hash,
                detail,
                ..
            } => Some(BroadcastError::unresolved(*raw_tx_hash, detail.clone())),
        }
    }

    /// The transaction hash either way — accepted or merely signed.
    pub fn tx_hash_hex(&self) -> String {
        match self {
            BroadcastOutcome::Accepted { tx_hash_hex, .. } => tx_hash_hex.clone(),
            BroadcastOutcome::UnresolvedWithKnownHash { raw_tx_hash, .. } => {
                bytes32_hex(*raw_tx_hash)
            }
        }
    }
}

/// Allocate → sign → persist → send, and **never** wait for a receipt.
///
/// Ordering is the point:
///
/// 1. the EOA nonce is claimed durably before anything is signed, so two
///    concurrent sends cannot sign against one transaction nonce;
/// 2. the signed bytes are persisted (with the action-nonce reservation, in
///    one `BEGIN IMMEDIATE`) before `eth_sendRawTransaction` is called, so a
///    crash anywhere after this point leaves a row that names its own
///    transaction;
/// 3. the send returns the hash immediately and reconciliation observes the
///    receipt later.
///
/// The only two releases here are both provably safe: signing failed (no
/// bytes exist), or the action-nonce reservation was refused (bytes exist but
/// were never persisted and never sent, so nothing outside this process has
/// ever seen them). After the send is attempted, nothing is released.
pub async fn sign_persist_and_broadcast(
    store: &StreamGStore,
    data_key_hex: &SecretHex,
    chain: TrustedChain<'_>,
    signer: &dyn SponsoredEnrollmentTxSigner,
    plan: &BroadcastPlan<'_>,
    call: &SponsoredEnrollmentCall<'_>,
    now_wall: i64,
) -> Result<BroadcastOutcome, BroadcasterError> {
    let nonce = allocate_broadcaster_nonce(
        store,
        chain,
        plan.chain_id,
        plan.broadcaster,
        plan.claim_owner,
        plan.lease_ttl_seconds,
        now_wall,
    )
    .await?;

    let signed = match signer.sign_sponsored_enrollment_tx(plan.gateway, nonce.nonce, call) {
        Ok(signed) => signed,
        Err(detail) => {
            // No bytes exist, so no transaction can ever carry this nonce.
            // Releasing keeps the sequence contiguous.
            release_broadcaster_nonce(store, &nonce.allocation_id, now_wall).await?;
            return Err(BroadcasterError::Signing(detail));
        }
    };

    // Native-ETH exposure gate (hazard 1). Same position as `submit.rs`'s:
    // after the bytes exist, before anything is persisted or sent.
    //
    // 🔴 THE DIFFERENCE FROM `submit.rs`: an EOA nonce is already allocated
    // here. `submit.rs`'s comment that "a refusal has nothing to clean up"
    // is true only there. Copying it into this arm would gap the
    // broadcaster account's nonce sequence forever — the identical failure
    // the `Err(e)` arm of `reserve_persist_and_send` below exists to
    // prevent, and the reason this release is a third call rather than two.
    // Releasing is provably safe here for the same reason it is safe in the
    // signing-failure arm above: the bytes were never persisted and never
    // sent, so nothing outside this process has ever seen them and no
    // transaction can ever carry this nonce.
    if let Err(e) = base_fee::submit_exposure_for_chain(
        chain.client(),
        plan.chain_id,
        signed.gas_limit(),
        signed.max_fee_per_gas(),
        signed.raw(),
        plan.max_native_exposure_wei,
    ) {
        release_broadcaster_nonce(store, &nonce.allocation_id, now_wall).await?;
        return Err(BroadcasterError::NativeExposure(e));
    }

    let req = ReservationRequest {
        profile_id: plan.profile_id,
        intent_id: plan.intent_id,
        chain_id: plan.chain_id,
        controller: plan.controller,
        action: plan.action,
        action_nonce: plan.action_nonce,
        claim_owner: plan.claim_owner,
        lease_ttl_seconds: plan.lease_ttl_seconds,
    };

    match outbox::reserve_persist_and_send(store, data_key_hex, chain, &req, &signed, now_wall)
        .await
    {
        Ok(SendOutcome::Broadcast {
            attempt,
            tx_hash_hex,
        }) => Ok(BroadcastOutcome::Accepted {
            nonce,
            attempt,
            tx_hash_hex,
        }),
        Ok(SendOutcome::SendFailedStuckRecoverable { attempt, detail }) => {
            // NOTHING is released here. The payload is signed, persisted and
            // may be in a mempool.
            Ok(BroadcastOutcome::UnresolvedWithKnownHash {
                nonce,
                attempt,
                raw_tx_hash: signed.hash(),
                detail,
            })
        }
        Ok(SendOutcome::BroadcastNotRecorded {
            attempt,
            tx_hash_hex: _,
            detail,
        }) => {
            // 🔴 NOTHING IS RELEASED. `eth_sendRawTransaction` SUCCEEDED; the
            // transaction is in a mempool at this EOA nonce. Releasing here
            // would hand the same nonce to the next caller, which would sign a
            // *different* transaction at it, and one of the two would be
            // evicted non-deterministically.
            //
            // This arm exists because the `Err(e)` arm below used to catch this
            // case. Its premise — "the reservation was refused, so the send
            // never happened" — is true of `reserve_and_persist_raw_tx`
            // failing, and FALSE of `record_broadcast_accepted` failing, which
            // runs after the send. `SendOutcome::BroadcastNotRecorded` makes
            // that distinction a type rather than a comment.
            Ok(BroadcastOutcome::UnresolvedWithKnownHash {
                nonce,
                attempt,
                raw_tx_hash: signed.hash(),
                detail,
            })
        }
        Err(e) => {
            // Reachable only PRE-SEND now: `reserve_persist_and_send`'s single
            // remaining `?` is `reserve_and_persist_raw_tx`, which runs before
            // `send_raw_transaction`. The signed bytes never left this process
            // and are dropped here, so this EOA nonce is unreachable and must
            // go back — otherwise one refused reservation gaps the account
            // forever. Post-send failures take the `BroadcastNotRecorded` arm
            // above and release nothing.
            release_broadcaster_nonce(store, &nonce.allocation_id, now_wall).await?;
            Err(BroadcasterError::Outbox(e))
        }
    }
}

// ---------------------------------------------------------------------------
// THE PRODUCTION SIGNER (Wave B2; wired to the submit path in Wave C W2).
//
// Everything below is the only non-test implementor of
// [`SponsoredEnrollmentTxSigner`]. Wave C W2 deleted the rival seam it used
// to be contrasted with (`submit::SponsoredEnrollmentBroadcaster`), so the
// contrast that stood here is now history rather than a live caveat: that
// trait's `sign_sponsored_enrollment(gateway, call)` took no transaction
// nonce, an implementor would have had to source the EOA nonce itself, and
// [`allocate_broadcaster_nonce`]'s contiguity guarantee forbids exactly that.
// It never had a production implementor, and now it does not exist.
// ---------------------------------------------------------------------------

/// A priority fee (the EIP-1559 tip) per gas unit, in wei.
///
/// A newtype for the same reason `base_fee`'s four exist and for one more
/// specific to this pair: `max_fee_per_gas` and `max_priority_fee_per_gas` are
/// both `u128`, they are adjacent in every EIP-1559 constructor, and swapping
/// them produces a transaction that either overpays enormously or is rejected
/// outright. Deliberately **not** a second [`MaxFeePerGas`], and deliberately
/// with no `From`/`Into` impls, so the compiler refuses the transposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriorityFeePerGas(u128);

impl PriorityFeePerGas {
    pub const fn new(wei_per_gas: u128) -> Self {
        Self(wei_per_gas)
    }

    pub const fn get(self) -> u128 {
        self.0
    }
}

/// The EVM's base cost for any transaction, in gas. A `gas_limit` below this
/// cannot pay for the transaction's own existence and is rejected by every
/// node before execution begins.
pub const MIN_TRANSACTION_GAS: u64 = 21_000;

/// EIP-2028 calldata cost: gas per **non-zero** calldata byte.
const CALLDATA_GAS_PER_NONZERO_BYTE: u64 = 16;
/// EIP-2028 calldata cost: gas per **zero** calldata byte.
const CALLDATA_GAS_PER_ZERO_BYTE: u64 = 4;

/// A **lower bound** on the gas a transaction carrying `calldata` must be
/// given: the base cost plus EIP-2028's per-byte calldata cost. Execution is
/// on top of this and is not modelled here.
///
/// 🔴 **This is a floor, not an estimate, and it is the *pre-Prague* floor.**
/// EIP-7623 raises the effective minimum for calldata-heavy transactions above
/// this figure; that rule is **not** implemented. So passing this check is
/// necessary, never sufficient — it catches a `gas_limit` that is absurd,
/// not one that is merely too small for `executeSponsoredEnrollment`'s
/// execution. Nothing in this crate establishes the latter; see
/// [`BroadcastGasPolicy`].
fn intrinsic_gas_floor(calldata: &[u8]) -> u64 {
    let nonzero = calldata.iter().filter(|b| **b != 0).count() as u64;
    let zero = calldata.len() as u64 - nonzero;
    MIN_TRANSACTION_GAS
        .saturating_add(nonzero.saturating_mul(CALLDATA_GAS_PER_NONZERO_BYTE))
        .saturating_add(zero.saturating_mul(CALLDATA_GAS_PER_ZERO_BYTE))
}

pub const ERR_BROADCASTER_GAS_POLICY: &str = "BROADCASTER_GAS_POLICY_INVALID";

/// A [`BroadcastGasPolicy`] that would produce a transaction no node can
/// accept. Refused at construction, i.e. at wiring time.
///
/// Deliberately **not** carrying a `status()`: this is not an HTTP outcome. A
/// policy is built once when the signer is constructed, long before any
/// request exists, and a bad one is an operator misconfiguration that must
/// stop startup rather than turn into a per-request 5xx.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GasPolicyError {
    #[error(
        "gas_limit {got} is below the EVM's base transaction cost ({MIN_TRANSACTION_GAS}); \
         no node can execute it"
    )]
    GasLimitBelowBaseCost { got: u64 },
    #[error("max_fee_per_gas must be greater than zero")]
    ZeroMaxFeePerGas,
    #[error(
        "max_priority_fee_per_gas ({priority}) exceeds max_fee_per_gas ({max}); EIP-1559 \
         forbids this"
    )]
    PriorityAboveMax { priority: u128, max: u128 },
}

impl GasPolicyError {
    pub fn code(&self) -> &'static str {
        match self {
            GasPolicyError::GasLimitBelowBaseCost { .. }
            | GasPolicyError::ZeroMaxFeePerGas
            | GasPolicyError::PriorityAboveMax { .. } => ERR_BROADCASTER_GAS_POLICY,
        }
    }
}

/// The three fee/gas numbers every Stream G broadcast is signed against.
///
/// # There was no gas policy in this crate before this type
///
/// `base_fee.rs` consumes a `gas_limit` and a `max_fee_per_gas` to compute the
/// native-ETH *reserve*; it never decides them. `quotes.rs` takes
/// `gas_unit_ceiling` / `max_fee_per_gas_wei` **from the request**, for the
/// exposure gate only. `rpc_chain.rs`'s pilot `send_tx` delegates both to
/// alloy's fillers (and pins `21_000` for a plain value transfer, which is not
/// this call). So these numbers are new, and they are stated here rather than
/// spread across call sites.
///
/// # 🔴 THE NUMBERS ARE STARTING VALUES AND NEED FOUNDER REVIEW
///
/// [`Self::starting_values_pending_founder_review`] is named for what it is.
/// Nothing in this repository has measured any of the three against a live
/// `executeSponsoredEnrollment`, and this crate's honesty rule ("claims ≤
/// code") makes that disclosure part of the API surface rather than a comment
/// someone can skip.
///
/// **`gas_limit = 500_000`.** Not invented and not copied from the pilot: it is
/// the figure this tree already uses as the gas ceiling *for this same call*
/// when computing hazard 1's reserve (`stream_g::maintenance`,
/// `base_fee`'s worked example, the Anvil harness's `WAVE_C_GAS_CEILING`).
/// Reusing it keeps the reserve the exposure gate checks and the limit the
/// transaction actually carries in agreement — if they disagreed, the gate
/// would be gating a different transaction than the one being signed. The
/// error is deliberately biased high, because the two directions are not
/// symmetric: an over-sized limit costs only a larger up-front reserve (unused
/// gas is refunded), while an under-sized one is burned in full on an
/// out-of-gas revert *and* leaves the intent unexecuted. What is **not**
/// established: that 500_000 is enough. That needs a measured
/// `eth_estimateGas` against a deployed gateway.
///
/// **`max_fee_per_gas = 1 gwei`.** Same provenance
/// (`WAVE_C_NORMAL_MAX_FEE_PER_GAS`), and far above Base's typical L2 base
/// fee. It is a **static ceiling**, which has a named consequence: if the base
/// fee rises above it, the transaction does not mine. It is then *stuck, not
/// lost* — the EOA nonce stays held, the raw payload stays persisted, and
/// `outbox::sweep_stuck_reservations` resolves it against chain evidence
/// (founder ruling F2). That is survivable, and it is why a static value is
/// tolerable at pilot scale, but the correct long-term answer is a policy that
/// tracks the live base fee (`eth_feeHistory` / `eth_gasPrice`). **That is not
/// implemented here**, and implementing it means adding a chain read to the
/// signing path, which today makes no RPC at all.
///
/// **`max_priority_fee_per_gas = 0.001 gwei` (1_000_000 wei).** This one has
/// **no in-tree precedent at all** — it is an invented starting value. Base
/// runs a single sequencer rather than a priority-fee auction, so a small tip
/// is normal there, but no measurement in this repository supports this
/// figure. Founder review required before any mainnet use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BroadcastGasPolicy {
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
}

impl BroadcastGasPolicy {
    /// Construct and validate. The three newtypes are mutually
    /// non-interchangeable, so no argument can be passed in another's position.
    pub fn new(
        gas_limit: GasUnits,
        max_fee_per_gas: MaxFeePerGas,
        max_priority_fee_per_gas: PriorityFeePerGas,
    ) -> Result<Self, GasPolicyError> {
        if gas_limit.get() < MIN_TRANSACTION_GAS {
            return Err(GasPolicyError::GasLimitBelowBaseCost {
                got: gas_limit.get(),
            });
        }
        if max_fee_per_gas.get() == 0 {
            return Err(GasPolicyError::ZeroMaxFeePerGas);
        }
        if max_priority_fee_per_gas.get() > max_fee_per_gas.get() {
            return Err(GasPolicyError::PriorityAboveMax {
                priority: max_priority_fee_per_gas.get(),
                max: max_fee_per_gas.get(),
            });
        }
        Ok(Self {
            gas_limit: gas_limit.get(),
            max_fee_per_gas: max_fee_per_gas.get(),
            max_priority_fee_per_gas: max_priority_fee_per_gas.get(),
        })
    }

    /// The three starting values defended in the type doc. Named so that every
    /// call site reads as "these have not been reviewed", because they have
    /// not been.
    ///
    /// 🔴 **No production caller binds this yet**, and nothing reads it from
    /// config: `StreamGConfig` has no gas fields. Same disclosure shape as
    /// [`BroadcastPlan::max_native_exposure_wei`] carried before Wave 2.
    pub fn starting_values_pending_founder_review() -> Self {
        Self::new(
            GasUnits::new(500_000),
            MaxFeePerGas::new(1_000_000_000),
            PriorityFeePerGas::new(1_000_000),
        )
        .expect("the starting values satisfy their own invariants")
    }

    pub fn gas_limit(&self) -> GasUnits {
        GasUnits::new(self.gas_limit)
    }

    pub fn max_fee_per_gas(&self) -> MaxFeePerGas {
        MaxFeePerGas::new(self.max_fee_per_gas)
    }

    pub fn max_priority_fee_per_gas(&self) -> PriorityFeePerGas {
        PriorityFeePerGas::new(self.max_priority_fee_per_gas)
    }
}

/// The production [`SponsoredEnrollmentTxSigner`]: ABI-encode the call, sign it
/// with the dedicated Stream G broadcaster key, return the bytes.
///
/// # What it does not have, on purpose
///
/// * **No key material of its own.** The private key stays behind
///   [`RpcChain`], reached only through
///   [`RpcChain::sign_broadcaster_eip1559`]. Wave A deliberately kept the
///   Stream G signer keys out of `StreamGState` — `StreamGConfig` derives
///   `Debug` and holds them as bare `Option<String>`, so a `state.config()`
///   accessor would put a secret-leaking `{:?}` one call from every handler —
///   and this type respects that: it takes an `&RpcChain` (which
///   `StreamGState::live_chain()` already returns) and never sees a key string.
/// * **No network access.** Signing makes no RPC. The chain reads on the
///   broadcast path (`transaction_count`, the `GasPriceOracle` trio,
///   `eth_sendRawTransaction`) all belong to
///   [`sign_persist_and_broadcast`] and stay there.
/// * **No nonce of its own.** The transaction nonce is the one
///   [`allocate_broadcaster_nonce`] handed out, passed in by the caller. That
///   is the trait's stated contract and the whole basis of the frontier's
///   contiguity.
///
/// # The address is resolved once, at construction
///
/// [`Self::new`] fails closed if no broadcaster key is configured, so "there is
/// no key" surfaces at wiring time instead of as a first-request signing
/// failure. It also exposes [`Self::broadcaster`], and **callers must build
/// `BroadcastPlan::broadcaster` from it**: the plan's address drives the nonce
/// frontier while this signer's key drives the signature, and the trait's
/// method signature (`gateway, nonce, call` — no address) gives this type no
/// way to detect a disagreement. Sourcing both from here makes the
/// disagreement unconstructible instead.
pub struct RpcChainEnrollmentSigner<'a> {
    chain: &'a RpcChain,
    broadcaster: [u8; 20],
    gas: BroadcastGasPolicy,
}

impl<'a> RpcChainEnrollmentSigner<'a> {
    /// Fails closed when `STREAM_G_BROADCASTER_PRIVATE_KEY` is unset — which
    /// is the default, since Stream G is disabled by default.
    pub fn new(
        chain: &'a RpcChain,
        gas: BroadcastGasPolicy,
    ) -> Result<Self, crate::chain::ChainError> {
        let broadcaster = chain.broadcaster_address_bytes()?;
        Ok(Self {
            chain,
            broadcaster,
            gas,
        })
    }

    /// The 20 address bytes of the key this signer will actually sign with.
    /// See the type doc: this is the value a caller must use for
    /// [`BroadcastPlan::broadcaster`].
    pub fn broadcaster(&self) -> [u8; 20] {
        self.broadcaster
    }

    pub fn gas_policy(&self) -> BroadcastGasPolicy {
        self.gas
    }
}

impl SponsoredEnrollmentTxSigner for RpcChainEnrollmentSigner<'_> {
    /// The same value [`Self::broadcaster`] returns — resolved once at
    /// construction from the key itself, never re-derived per call.
    fn broadcaster_address(&self) -> [u8; 20] {
        self.broadcaster
    }

    fn sign_sponsored_enrollment_tx(
        &self,
        gateway: [u8; 20],
        broadcaster_nonce: u64,
        call: &SponsoredEnrollmentCall<'_>,
    ) -> Result<SignedRawTx, String> {
        // 🔴 The direct-ETH branch is unsignable by this account, not merely
        // unwise. `GoatRelayGateway.sol:379` reverts `NotController` unless
        // `msg.sender == intent.controller`, and the broadcaster EOA is by
        // definition not the controller — see `direct_eth`'s module doc. A
        // transaction signed here would be a guaranteed revert that still
        // burns the EOA nonce and the gas. Refusing before any bytes exist
        // puts the caller on `sign_persist_and_broadcast`'s signing-failure
        // arm, which releases the EOA nonce; the client's actual remedy is
        // `direct_eth::prepare_direct_eth_enrollment`.
        if preflight::is_direct_eth_enrollment(call.intent) {
            return Err(format!(
                "refusing to sign the direct-ETH branch: GoatRelayGateway.sol:379 reverts \
                 NotController unless msg.sender is intent.controller (0x{}), which the \
                 broadcaster EOA is not; the client must submit this call itself",
                hex::encode(call.intent.controller)
            ));
        }

        // One encoder, pinned against `cast calldata` in `direct_eth`'s tests.
        let calldata = direct_eth::sponsored_enrollment_calldata(call)
            .map_err(|e| format!("{}: {e}", e.code()))?;

        // Cheap absurdity check only — read [`intrinsic_gas_floor`]'s
        // disclosure before reading this as "the gas limit is sufficient".
        let floor = intrinsic_gas_floor(&calldata);
        if self.gas.gas_limit < floor {
            return Err(format!(
                "{ERR_BROADCASTER_GAS_POLICY}: gas_limit {} is below the intrinsic floor {} for \
                 {} calldata bytes",
                self.gas.gas_limit,
                floor,
                calldata.len()
            ));
        }

        let signed = self
            .chain
            .sign_broadcaster_eip1559(&Eip1559Request {
                to: gateway,
                nonce: broadcaster_nonce,
                gas_limit: self.gas.gas_limit,
                max_fee_per_gas: self.gas.max_fee_per_gas,
                max_priority_fee_per_gas: self.gas.max_priority_fee_per_gas,
                calldata,
            })
            .map_err(|e| format!("{ERR_BROADCASTER_SIGNING}: {e}"))?;

        // `SignedRawTx::new` recomputes `keccak256(raw)`, which is by
        // construction the same value `SignedEip1559::hash()` carries — both
        // are the hash of these exact bytes. Pinned by
        // `tests::the_outbox_hash_is_the_real_transaction_hash` rather than
        // re-checked here.
        //
        // The two gas fields are the ones this signer just signed against, so
        // for THIS implementor `outbox::SignedRawTx`'s "asserted, not
        // verified" caveat is discharged in fact — proven by decoding the
        // bytes in `tests::the_signed_transaction_carries_the_policys_gas_and_fees`.
        // The type still does not enforce it, and a different implementor
        // could still lie.
        Ok(SignedRawTx::new(
            signed.into_raw(),
            GasUnits::new(self.gas.gas_limit),
            MaxFeePerGas::new(self.gas.max_fee_per_gas),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use crate::chain::{
        BatchView, ChainClient, ChainError, ExecutedLog, TxHash as ChainTxHash, TxReceiptView,
    };
    use crate::stream_g::base_fee::{GasUnits, MaxFeePerGas};
    use crate::stream_g::models::{FeeQuote, LinkSecondary};
    use crate::stream_g::outbox::NONCE_KIND_ACTION;
    use crate::stream_g::preflight::{
        Eip2612Authorization, RootAuthorization, SponsorEnrollment, V1Enrollment,
    };
    use crate::stream_g::submit::{
        action_nonce_signer_key, intent_row_id, nonce_allocation_row_id,
    };

    const CHAIN_ID: u64 = 8453;
    /// Wave 2. The gas parameters the fake signer asserts about its bytes,
    /// and the ceiling the exposure gate is given. `CHAIN_ID` is 8453, not
    /// 31337, so the gate genuinely runs in this module's tests; `FakeChain`
    /// returns 0 from all three `gas_oracle_*` methods, so the reserve is
    /// `500_000 * 1 gwei = 5e14 wei` and this 1-ETH ceiling passes. The
    /// rejection arm overrides the ceiling instead of the oracle values.
    const TEST_GAS_LIMIT: u64 = 500_000;
    const TEST_MAX_FEE_PER_GAS: u128 = 1_000_000_000;
    const TEST_MAX_NATIVE_EXPOSURE_WEI: u128 = 1_000_000_000_000_000_000;
    /// One address wearing both hats: it is the broadcaster EOA **and** a
    /// controller with a gateway action nonce. That overlap is the whole
    /// point of the aliasing test below.
    const BOTH_HATS: [u8; 20] = [0x5B; 20];
    const GATEWAY: [u8; 20] = [0x11; 20];
    const PROFILE: &str = "profile-broadcaster-1";
    const INTENT_ID: [u8; 32] = [0x33; 32];
    const ACTION_NONCE: u64 = 7;
    const OWNER: &str = "broadcaster-a";
    const WALL_NOW: i64 = 1_800_000_000;
    const LEASE: i64 = 900;

    fn data_key_hex() -> SecretHex {
        SecretHex::from_hex(&"cc".repeat(32)).expect("valid 32-byte test key")
    }

    // --- chain double ---------------------------------------------------
    //
    // This IS the instance production code receives (threaded in via
    // `TrustedChain`), so every counter asserted below is read off the object
    // the code under test actually called.

    #[derive(Default)]
    struct FakeChainInner {
        tx_count: Option<Result<u64, String>>,
        send_result: Option<Result<ChainTxHash, String>>,
        tx_count_calls: usize,
        receipt_calls: usize,
        send_calls: usize,
        last_tx_count_args: Option<([u8; 20], bool)>,
        // --- Wave 2: the GasPriceOracle predeploy's three reads. ---------
        //
        // Armed NONZERO by `with_tx_count` on purpose. With zeros the
        // exposure gate would compute `l2_wei` and nothing else, and the
        // whole L1-data-availability/operator half of hazard 1 would never
        // appear in any number this module asserts on.
        l1_exact_fee_wei: u128,
        l1_upper_fee_wei: u128,
        operator_fee_wei: u128,
        gas_oracle_calls: usize,
    }

    struct FakeChain {
        inner: Mutex<FakeChainInner>,
    }

    /// Wave 2. `FakeChain::with_tx_count`'s armed oracle values, and the
    /// reserve they imply together with [`TEST_GAS_LIMIT`] /
    /// [`TEST_MAX_FEE_PER_GAS`]:
    ///
    /// `l2 = 500_000 * 1e9 = 5.0e14`, L1 term = `max(2.0e13, 2.5e13) = 2.5e13`,
    /// operator = `1.0e12` → **`reserve = 526_000_000_000_000` wei**.
    ///
    /// Spelled out as a const so the rejection test's ceiling can sit one
    /// wei below it rather than being an unexplained magic number.
    const TEST_L1_EXACT_FEE_WEI: u128 = 20_000_000_000_000;
    const TEST_L1_UPPER_FEE_WEI: u128 = 25_000_000_000_000;
    const TEST_OPERATOR_FEE_WEI: u128 = 1_000_000_000_000;
    const TEST_EXPECTED_RESERVE_WEI: u128 = 526_000_000_000_000;

    impl FakeChain {
        fn with_tx_count(n: u64) -> Self {
            Self {
                inner: Mutex::new(FakeChainInner {
                    tx_count: Some(Ok(n)),
                    send_result: Some(Ok([0xEE; 32])),
                    l1_exact_fee_wei: TEST_L1_EXACT_FEE_WEI,
                    l1_upper_fee_wei: TEST_L1_UPPER_FEE_WEI,
                    operator_fee_wei: TEST_OPERATOR_FEE_WEI,
                    ..FakeChainInner::default()
                }),
            }
        }
        /// How many of the three `GasPriceOracle` reads were made. Zero
        /// proves the gate never ran.
        fn gas_oracle_calls(&self) -> usize {
            self.inner.lock().unwrap().gas_oracle_calls
        }
        fn set_tx_count(&self, v: Result<u64, String>) {
            self.inner.lock().unwrap().tx_count = Some(v);
        }
        fn set_send_result(&self, v: Result<ChainTxHash, String>) {
            self.inner.lock().unwrap().send_result = Some(v);
        }
        fn tx_count_calls(&self) -> usize {
            self.inner.lock().unwrap().tx_count_calls
        }
        fn receipt_calls(&self) -> usize {
            self.inner.lock().unwrap().receipt_calls
        }
        fn send_calls(&self) -> usize {
            self.inner.lock().unwrap().send_calls
        }
        fn last_tx_count_args(&self) -> Option<([u8; 20], bool)> {
            self.inner.lock().unwrap().last_tx_count_args
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

        fn transaction_count(&self, addr: [u8; 20], pending: bool) -> Result<u64, ChainError> {
            let mut g = self.inner.lock().unwrap();
            g.tx_count_calls += 1;
            g.last_tx_count_args = Some((addr, pending));
            match &g.tx_count {
                Some(Ok(n)) => Ok(*n),
                Some(Err(e)) => Err(ChainError::Msg(e.clone())),
                None => Err(unset("transaction_count")),
            }
        }

        // Wave 2 — the three GasPriceOracle predeploy reads the
        // native-exposure gate makes. Deliberately overridden here rather
        // than left on the trait's default (which returns
        // `Err("not supported")`): with the default this module's tests
        // would all fail closed through the gate and prove nothing about
        // the send path.
        fn gas_oracle_l1_fee(&self, _unsigned_tx: &[u8]) -> Result<u128, ChainError> {
            let mut g = self.inner.lock().unwrap();
            g.gas_oracle_calls += 1;
            Ok(g.l1_exact_fee_wei)
        }

        fn gas_oracle_l1_fee_upper_bound(&self, _size: u64) -> Result<u128, ChainError> {
            let mut g = self.inner.lock().unwrap();
            g.gas_oracle_calls += 1;
            Ok(g.l1_upper_fee_wei)
        }

        fn gas_oracle_operator_fee(&self, _gas_limit: u64) -> Result<u128, ChainError> {
            let mut g = self.inner.lock().unwrap();
            g.gas_oracle_calls += 1;
            Ok(g.operator_fee_wei)
        }

        fn send_raw_transaction(&self, _raw: &[u8]) -> Result<ChainTxHash, ChainError> {
            let mut g = self.inner.lock().unwrap();
            g.send_calls += 1;
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
            Err(unset("transaction_receipt"))
        }

        fn intent_used(
            &self,
            _gateway: [u8; 20],
            _intent_id: [u8; 32],
            _block: u64,
        ) -> Result<bool, ChainError> {
            Err(unset("intent_used"))
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

    // --- signer double ---------------------------------------------------

    struct FakeSigner {
        result: Mutex<Result<Vec<u8>, String>>,
        calls: Mutex<usize>,
        last_nonce: Mutex<Option<u64>>,
    }

    impl FakeSigner {
        fn ok() -> Self {
            Self {
                result: Mutex::new(Ok(vec![0x02, 0xf8, 0x6b, 0xAA, 0xBB, 0xCC])),
                calls: Mutex::new(0),
                last_nonce: Mutex::new(None),
            }
        }
        fn failing() -> Self {
            Self {
                result: Mutex::new(Err("no key configured".to_string())),
                calls: Mutex::new(0),
                last_nonce: Mutex::new(None),
            }
        }
        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
        fn last_nonce(&self) -> Option<u64> {
            *self.last_nonce.lock().unwrap()
        }
        fn signed_hash(&self) -> TxHash {
            match &*self.result.lock().unwrap() {
                Ok(raw) => SignedRawTx::new(
                    raw.clone(),
                    GasUnits::new(TEST_GAS_LIMIT),
                    MaxFeePerGas::new(TEST_MAX_FEE_PER_GAS),
                )
                .hash(),
                Err(_) => panic!("signer is armed to fail"),
            }
        }
    }

    impl SponsoredEnrollmentTxSigner for FakeSigner {
        /// [`BOTH_HATS`] — the address every `plan_with_ceiling` fixture in
        /// this module already names, so a plan built from this method is the
        /// plan those tests were already asserting against.
        fn broadcaster_address(&self) -> [u8; 20] {
            BOTH_HATS
        }

        fn sign_sponsored_enrollment_tx(
            &self,
            _gateway: [u8; 20],
            broadcaster_nonce: u64,
            _call: &SponsoredEnrollmentCall<'_>,
        ) -> Result<SignedRawTx, String> {
            *self.calls.lock().unwrap() += 1;
            *self.last_nonce.lock().unwrap() = Some(broadcaster_nonce);
            match &*self.result.lock().unwrap() {
                Ok(raw) => Ok(SignedRawTx::new(
                    raw.clone(),
                    GasUnits::new(TEST_GAS_LIMIT),
                    MaxFeePerGas::new(TEST_MAX_FEE_PER_GAS),
                )),
                Err(e) => Err(e.clone()),
            }
        }
    }

    // --- store helpers ----------------------------------------------------

    async fn open_store() -> (tempfile::TempDir, StreamGStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open store");
        (dir, store)
    }

    async fn seed_intent(store: &StreamGStore) {
        let intent_row = intent_row_id(PROFILE, INTENT_ID);
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT OR IGNORE INTO profiles (id, created_at, status) \
                         VALUES (?, ?, 'active')",
                    )
                    .bind(PROFILE)
                    .bind(0i64)
                    .execute(&mut **tx)
                    .await?;
                    sqlx::query(
                        "INSERT INTO intents (id, profile_id, intent_type, status, \
                         created_at, expires_at) \
                         VALUES (?, ?, 'sponsored_enrollment', 'pending', 0, ?)",
                    )
                    .bind(&intent_row)
                    .bind(PROFILE)
                    .bind(9_999_999_999i64)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed intent");
    }

    /// Insert a gateway **action** allocation exactly as `submit.rs` and
    /// `outbox.rs` write one: the `"<0xaddr>#<ACTION>"` synthetic signer key,
    /// `kind='action'`.
    async fn seed_action_allocation(
        store: &StreamGStore,
        controller: [u8; 20],
        nonce: i64,
    ) -> String {
        let signer_key = action_nonce_signer_key(controller, ActionType::SponsoredEnrollment);
        let id = nonce_allocation_row_id(CHAIN_ID, &signer_key, nonce as u64);
        let id_c = id.clone();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO nonce_allocations \
                         (id, chain_id, signer_address, nonce, status, allocated_at, kind) \
                         VALUES (?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(&id_c)
                    .bind(CHAIN_ID as i64)
                    .bind(&signer_key)
                    .bind(nonce)
                    .bind(NONCE_STATUS_ALLOCATED)
                    .bind(WALL_NOW)
                    .bind(NONCE_KIND_ACTION)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed action allocation");
        id
    }

    /// Insert a row the way a writer that **forgot the `kind` column** would:
    /// a bare EOA address, no `kind`, so `0002`'s `DEFAULT 'action'` files it
    /// in the wrong key space. This is the state the migration's own comment
    /// warns about ("a row inserted without an explicit `kind` must never
    /// read back as a broadcaster row"), and it is reachable from any future
    /// caller that copies an older INSERT.
    async fn seed_kindless_bare_address_row(store: &StreamGStore, addr: [u8; 20], nonce: i64) {
        let signer = address_hex(addr);
        let id = format!("legacy-{nonce}");
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO nonce_allocations \
                         (id, chain_id, signer_address, nonce, status, allocated_at) \
                         VALUES (?, ?, ?, ?, ?, ?)",
                    )
                    .bind(&id)
                    .bind(CHAIN_ID as i64)
                    .bind(&signer)
                    .bind(nonce)
                    .bind(NONCE_STATUS_ALLOCATED)
                    .bind(WALL_NOW)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed kindless row");
    }

    /// Same shape as [`seed_kindless_bare_address_row`] but `released`, and at
    /// a nonce the broadcaster frontier does **not** want — so the row is only
    /// reachable through the gap-refill SELECT, never through the frontier
    /// INSERT's UNIQUE index. That separation is what lets a test tell the
    /// gap-refill `kind` filter apart from the INSERT conflict.
    async fn seed_released_kindless_bare_address_row(
        store: &StreamGStore,
        addr: [u8; 20],
        nonce: i64,
    ) -> String {
        let signer = address_hex(addr);
        let id = format!("legacy-released-{nonce}");
        let id_c = id.clone();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO nonce_allocations \
                         (id, chain_id, signer_address, nonce, status, allocated_at, released_at) \
                         VALUES (?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(&id_c)
                    .bind(CHAIN_ID as i64)
                    .bind(&signer)
                    .bind(nonce)
                    .bind(NONCE_STATUS_RELEASED)
                    .bind(WALL_NOW)
                    .bind(WALL_NOW)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed released kindless row");
        id
    }

    /// A genuine broadcaster row, written the way
    /// [`allocate_broadcaster_nonce`]'s own INSERT writes one (canonical id,
    /// bare signer address, explicit `kind`), so the frontier's `MAX(nonce)`
    /// can be positioned without going through the allocator.
    async fn seed_broadcaster_allocation(
        store: &StreamGStore,
        addr: [u8; 20],
        nonce: i64,
    ) -> String {
        let signer = address_hex(addr);
        let id = broadcaster_nonce_row_id(CHAIN_ID, addr, nonce as u64);
        let id_c = id.clone();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO nonce_allocations \
                         (id, chain_id, signer_address, nonce, status, allocated_at, kind) \
                         VALUES (?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(&id_c)
                    .bind(CHAIN_ID as i64)
                    .bind(&signer)
                    .bind(nonce)
                    .bind(NONCE_STATUS_ALLOCATED)
                    .bind(WALL_NOW)
                    .bind(NONCE_KIND_BROADCASTER)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed broadcaster allocation");
        id
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

    async fn allocate(
        store: &StreamGStore,
        chain: &FakeChain,
    ) -> Result<BroadcasterNonce, BroadcasterError> {
        allocate_broadcaster_nonce(
            store,
            chain.into(),
            CHAIN_ID,
            BOTH_HATS,
            OWNER,
            LEASE,
            WALL_NOW,
        )
        .await
    }

    // -------------------------------------------------------------------
    // The frontier.
    // -------------------------------------------------------------------

    /// The two key spaces share one table, one UNIQUE index and — in this
    /// test — one address. They must stay separate rows, and the broadcaster
    /// frontier must count only its own.
    ///
    /// **Mutation this detects (run and reverted, M-C2):** drop `kind` from
    /// the `INSERT OR IGNORE` column list in [`allocate_broadcaster_nonce`],
    /// so `0002`'s `DEFAULT 'action'` applies. The row this call just wrote is
    /// then filed in the action key space, where the frontier's `MAX(nonce)`
    /// (which filters `kind='broadcaster'`) cannot see it — so the next
    /// allocation hands out the same nonce again, i.e. two different
    /// transactions signed against one EOA nonce. Observed here:
    /// `left: Some("action"), right: Some("broadcaster")` at the `kind`
    /// assertion below (six of this module's seven tests fail under it).
    ///
    /// **Mutation this does NOT detect, disclosed rather than glossed:**
    /// deleting `kind = ?` from the `MAX(nonce)` *SELECT* (the brief's
    /// literally-worded mutation). Under the current key encoding an action
    /// row's `signer_address` always carries the `#<ACTION>` suffix, so it can
    /// never equal a bare EOA address and the `signer_address` predicate
    /// alone already excludes it. That mutation is caught by
    /// [`a_kindless_bare_address_row_is_refused_not_silently_skipped`]
    /// instead, which constructs the reachable collision.
    ///
    /// Non-zero arm for every zero-assertion below: the same query that must
    /// return 1 broadcaster row after the first allocation must return 2
    /// after the second, and the action row's count is asserted non-zero (1)
    /// rather than only "not ours".
    #[tokio::test]
    async fn broadcaster_eoa_nonce_does_not_alias_a_controller_action_nonce() {
        let (_dir, store) = open_store().await;
        // The same 20 bytes already hold a gateway action nonce 5.
        let action_id = seed_action_allocation(&store, BOTH_HATS, 5).await;
        let chain = FakeChain::with_tx_count(5);

        let first = allocate(&store, &chain).await.expect("first allocation");
        assert_eq!(first.nonce, 5, "the EOA's own mined count is the floor");
        assert_eq!(first.signer_address, address_hex(BOTH_HATS));
        assert!(!first.refilled_gap);
        assert_ne!(
            first.allocation_id, action_id,
            "the two counters must not share a row id"
        );
        assert_eq!(
            chain.last_tx_count_args(),
            Some((BOTH_HATS, false)),
            "the frontier floor is the MINED count, not the pending one"
        );

        // Both rows exist, at the same nonce, under one UNIQUE index.
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM nonce_allocations WHERE nonce = ? AND chain_id = 8453",
                "5".to_string()
            )
            .await,
            2,
            "one action row and one broadcaster row, both at nonce 5"
        );
        assert_eq!(
            text(
                &store,
                "SELECT kind FROM nonce_allocations WHERE id = ?",
                first.allocation_id.clone()
            )
            .await
            .as_deref(),
            Some(NONCE_KIND_BROADCASTER)
        );
        assert_eq!(
            text(
                &store,
                "SELECT signer_address FROM nonce_allocations WHERE id = ?",
                first.allocation_id.clone()
            )
            .await,
            Some(address_hex(BOTH_HATS)),
            "a broadcaster row's signer_address is the BARE address"
        );
        // The action row is untouched: same kind, same status, and its
        // signer key still carries the '#' fold of the 2-D on-chain key.
        assert_eq!(
            text(
                &store,
                "SELECT kind FROM nonce_allocations WHERE id = ?",
                action_id.clone()
            )
            .await
            .as_deref(),
            Some(NONCE_KIND_ACTION)
        );
        assert_eq!(
            text(
                &store,
                "SELECT status FROM nonce_allocations WHERE id = ?",
                action_id.clone()
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "allocating a broadcaster nonce must not disturb an action nonce"
        );

        // The frontier advances over the broadcaster's OWN rows only.
        let second = allocate(&store, &chain).await.expect("second allocation");
        assert_eq!(
            second.nonce, 6,
            "the frontier must count the nonce it just handed out"
        );
        assert_ne!(first.allocation_id, second.allocation_id);

        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM nonce_allocations WHERE kind = ?",
                NONCE_KIND_BROADCASTER.to_string()
            )
            .await,
            2,
            "non-zero arm: two broadcaster rows"
        );
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM nonce_allocations WHERE kind = ?",
                NONCE_KIND_ACTION.to_string()
            )
            .await,
            1,
            "non-zero arm: the one action row is still there and still an action row"
        );
    }

    /// A bare-address row that is **not** ours — because it was written
    /// without an explicit `kind` and so defaulted to `'action'` — occupies
    /// the UNIQUE `(chain_id, signer_address, nonce)` coordinate the frontier
    /// wants. It must be refused loudly, never skipped.
    ///
    /// Skipping is the dangerous behaviour: an EOA's transactions execute in
    /// nonce order, so handing out 6 while 5 was never sent stalls every
    /// later transaction from that account in the mempool indefinitely.
    ///
    /// **Mutation this detects (run and reverted, M-C3):** delete `kind = ?`
    /// from the `MAX(nonce)` frontier query in
    /// [`allocate_broadcaster_nonce`]. The mislabeled row is then counted as
    /// the account's high-water mark and the allocation silently returns 6,
    /// stranding nonce 5. Observed verbatim: `nonce 5 is occupied by a row
    /// that is not ours: BroadcasterNonce { allocation_id: "9f1a0cfc…",
    /// nonce: 6, signer_address: "0x5b5b…", refilled_gap: false }`.
    ///
    /// This is the test that makes the `kind` filter load-bearing, and it is
    /// the reachable form of the brief's §3.3 requirement. `0002`'s
    /// `DEFAULT 'action'` is what makes the mislabeled row reachable at all.
    #[tokio::test]
    async fn a_kindless_bare_address_row_is_refused_not_silently_skipped() {
        let (_dir, store) = open_store().await;
        seed_kindless_bare_address_row(&store, BOTH_HATS, 5).await;
        let chain = FakeChain::with_tx_count(5);

        let err = allocate(&store, &chain)
            .await
            .expect_err("nonce 5 is occupied by a row that is not ours");
        assert_eq!(err.code(), ERR_BROADCASTER_NONCE_ROW_CONFLICT);
        assert!(
            matches!(err, BroadcasterError::NonceRowConflict { nonce, .. } if nonce == 5),
            "the conflict must name the nonce that is blocked, not the next free one"
        );
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM nonce_allocations WHERE kind = ?",
                NONCE_KIND_BROADCASTER.to_string()
            )
            .await,
            0,
            "a refused allocation must not leave a row behind"
        );

        // Paired non-zero arm: with the coordinate free, the very same call
        // allocates nonce 5 and writes exactly one broadcaster row — so the
        // zero above is a refusal, not an inert code path.
        let (_dir2, clean) = open_store().await;
        let ok = allocate(&clean, &chain)
            .await
            .expect("clean store allocates");
        assert_eq!(ok.nonce, 5);
        assert_eq!(
            count(
                &clean,
                "SELECT COUNT(*) FROM nonce_allocations WHERE kind = ?",
                NONCE_KIND_BROADCASTER.to_string()
            )
            .await,
            1
        );
    }

    /// The gap-refill SELECT is the **only** statement in
    /// [`allocate_broadcaster_nonce`] that reaches a row by
    /// `(chain_id, signer_address)` rather than by primary key, so it is the
    /// only place a foreign row can be picked up at all. A `released` row that
    /// is not ours — bare EOA address, `kind` defaulted to `'action'` by
    /// `0002` — must not be read as a hole in this account's transaction
    /// sequence.
    ///
    /// The nonce layout is chosen so the gap path is the *only* thing under
    /// test: the mislabeled row sits at 6, the account already owns 7, and the
    /// mined count is 5, so the healthy frontier extends to 8 and never touches
    /// the UNIQUE `(chain_id, signer_address, nonce)` coordinate the foreign
    /// row occupies. (The existing
    /// [`a_kindless_bare_address_row_is_refused_not_silently_skipped`] covers
    /// the INSERT-conflict case; this one cannot be confused with it.)
    ///
    /// **Mutation this detects (GAP10, run and reverted):** replace
    /// `kind = ?` with `? IS NOT NULL` in the gap-refill SELECT
    /// (`allocate_broadcaster_nonce` step 1). The action row at nonce 6 is then
    /// the lowest "hole" at or above the mined count, the refill UPDATE's own
    /// `kind = ?` compare-and-swap matches nothing, and the call returns
    /// `NonceRowConflict { nonce: 6 }` instead of allocating 8 — the
    /// `.expect("frontier extends")` below fails.
    ///
    /// **Second mutation this detects (GAP10 on the refill UPDATE, run and
    /// reverted together with the one above):** with the SELECT's filter
    /// already neutralised, also replace `kind = ?` with `? IS NOT NULL` in the
    /// refill UPDATE. Nothing then refuses the hijack: the call returns nonce 6
    /// with `refilled_gap == true` and the controller's action nonce silently
    /// becomes a broadcaster allocation. Both the nonce assertion and the
    /// "untouched" assertions below fail.
    ///
    /// **Disclosed, not glossed:** that second mutation applied *alone* — with
    /// the SELECT's `kind` filter intact — is not detectable by any test, and
    /// deliberately so. The SELECT hands the UPDATE a row it has already
    /// filtered on `kind`, and the UPDATE addresses it by primary key, so no
    /// input can make the two disagree. The predicate is defence-in-depth for
    /// the SELECT, which is what the comment at that statement records.
    ///
    /// Paired non-zero arm for every "untouched" zero-assertion: the second
    /// half of this test releases a real broadcaster nonce and proves the gap
    /// path is live — it refills 8, not the lower foreign 6.
    #[tokio::test]
    async fn a_released_kindless_bare_address_row_is_not_taken_as_a_gap() {
        let (_dir, store) = open_store().await;
        // The account already owns nonce 7 …
        seed_broadcaster_allocation(&store, BOTH_HATS, 7).await;
        // … and a row that is NOT ours sits released at nonce 6.
        let foreign = seed_released_kindless_bare_address_row(&store, BOTH_HATS, 6).await;
        let chain = FakeChain::with_tx_count(5);

        let next = allocate(&store, &chain).await.expect("frontier extends");
        assert_eq!(
            next.nonce, 8,
            "the frontier must extend past its own high-water mark, not refill a \
             hole that belongs to the action key space"
        );
        assert!(!next.refilled_gap, "nothing was refilled");
        assert_ne!(next.allocation_id, foreign);

        // The foreign row is exactly as it was: still an action row, still
        // released, still unclaimed.
        assert_eq!(
            text(
                &store,
                "SELECT kind FROM nonce_allocations WHERE id = ?",
                foreign.clone()
            )
            .await
            .as_deref(),
            Some(NONCE_KIND_ACTION)
        );
        assert_eq!(
            text(
                &store,
                "SELECT status FROM nonce_allocations WHERE id = ?",
                foreign.clone()
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_RELEASED),
            "a broadcaster allocation must not resurrect an action allocation"
        );
        assert_eq!(
            text(
                &store,
                "SELECT claim_owner FROM nonce_allocations WHERE id = ?",
                foreign.clone()
            )
            .await,
            None,
            "and must not put its own claim on it"
        );

        // Non-zero arm: the gap path is not dead code. Release the broadcaster
        // row we just took and the very next call refills it — 8, the hole
        // that IS ours, and not the numerically lower 6 that is not.
        assert!(
            release_broadcaster_nonce(&store, &next.allocation_id, WALL_NOW)
                .await
                .expect("release"),
            "the release really moved a row"
        );
        let refill = allocate(&store, &chain).await.expect("refill");
        assert_eq!(refill.nonce, 8, "our own hole, not the foreign one");
        assert!(refill.refilled_gap);
        assert_eq!(refill.allocation_id, next.allocation_id);
    }

    /// The two nonce key spaces share one table, so several statements in
    /// `submit.rs` address an action allocation by `WHERE id = ?` with **no**
    /// `kind` predicate (`submit.rs`'s reservation SELECT/UPDATE,
    /// `record_failed`'s release, and reconcile's consume). That omission is
    /// only safe because a broadcaster row can never carry an action row's id.
    /// This test is that claim, made falsifiable.
    ///
    /// The separation is doubled, and each half is asserted on its own so that
    /// neither can hide the other's removal — a bare
    /// `assert_ne!(action_id, broadcaster_id)` would survive either mutation
    /// alone and is therefore not the coverage here.
    ///
    /// **Mutation 1 (run and reverted):** make
    /// [`super::super::submit::action_nonce_signer_key`] return
    /// `address_hex(controller)` — dropping the `#<ACTION>` suffix. The action
    /// signer key becomes the bare address a broadcaster row uses, and the
    /// `action_key != bare` assertion below fails (as does the
    /// same-key-space id assertion built on it).
    ///
    /// **Mutation 2 (run and reverted):** set
    /// `BROADCASTER_NONCE_ID_DOMAIN` to `"stream_g_action_nonce_allocation"`,
    /// `submit.rs`'s domain. The two derivations then agree on every input
    /// except the signer key, and the `same_key_different_domain` assertion —
    /// which feeds *identical* signer text to both — fails.
    #[tokio::test]
    async fn the_action_and_broadcaster_key_spaces_cannot_alias_one_row_id() {
        let bare = address_hex(BOTH_HATS);
        let action_key = action_nonce_signer_key(BOTH_HATS, ActionType::SponsoredEnrollment);

        // Half 1: the signer-key spellings are disjoint.
        assert_ne!(
            action_key, bare,
            "an action signer key folds the 2-D on-chain key into the column and \
             must never equal the bare address a broadcaster row stores"
        );
        assert!(
            action_key.starts_with(&bare) && action_key.len() > bare.len(),
            "the fold is a suffix on the same address, not a different address: {action_key}"
        );

        // Half 2: even given IDENTICAL signer text, the id domains differ.
        for nonce in [0u64, 5, 8, u64::MAX] {
            let same_key_different_domain = nonce_allocation_row_id(CHAIN_ID, &bare, nonce);
            assert_ne!(
                same_key_different_domain,
                broadcaster_nonce_row_id(CHAIN_ID, BOTH_HATS, nonce),
                "the two row-id derivations must not share a preimage space at nonce {nonce}"
            );
            // The property the `WHERE id = ?` statements actually rely on,
            // held up by both halves above.
            assert_ne!(
                nonce_allocation_row_id(CHAIN_ID, &action_key, nonce),
                broadcaster_nonce_row_id(CHAIN_ID, BOTH_HATS, nonce),
                "one address must not produce one row id for two counters at nonce {nonce}"
            );
        }

        // Non-zero arm: both derivations are real functions of their inputs,
        // so `assert_ne!` above is discrimination and not a constant.
        assert_eq!(
            nonce_allocation_row_id(CHAIN_ID, &action_key, 5),
            nonce_allocation_row_id(CHAIN_ID, &action_key, 5),
            "deterministic"
        );
        assert_ne!(
            broadcaster_nonce_row_id(CHAIN_ID, BOTH_HATS, 5),
            broadcaster_nonce_row_id(CHAIN_ID, BOTH_HATS, 6),
        );

        // And the store agrees: both rows coexist at one (chain, address,
        // nonce)-adjacent coordinate without either overwriting the other.
        let (_dir, store) = open_store().await;
        let action_id = seed_action_allocation(&store, BOTH_HATS, 8).await;
        let broadcaster_id = seed_broadcaster_allocation(&store, BOTH_HATS, 8).await;
        assert_ne!(action_id, broadcaster_id);
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM nonce_allocations WHERE nonce = ? AND chain_id = 8453",
                "8".to_string()
            )
            .await,
            2,
            "two rows, two key spaces, one nonce value"
        );
    }

    /// A released nonce is a hole in the account's sequence, and holes must
    /// be refilled before the frontier extends.
    ///
    /// Mutation this detects: delete the hole query (step 1) from
    /// [`allocate_broadcaster_nonce`] — the third allocation then returns 7
    /// instead of 6, permanently stranding nonce 6.
    #[tokio::test]
    async fn a_released_nonce_is_refilled_before_the_frontier_extends() {
        let (_dir, store) = open_store().await;
        let chain = FakeChain::with_tx_count(5);

        let a = allocate(&store, &chain).await.expect("a");
        let b = allocate(&store, &chain).await.expect("b");
        let c = allocate(&store, &chain).await.expect("c");
        assert_eq!((a.nonce, b.nonce, c.nonce), (5, 6, 7));

        assert!(
            release_broadcaster_nonce(&store, &b.allocation_id, WALL_NOW)
                .await
                .expect("release"),
            "non-zero arm: the release really moved a row"
        );

        let refill = allocate(&store, &chain).await.expect("refill");
        assert_eq!(refill.nonce, 6, "the hole comes before the frontier");
        assert!(refill.refilled_gap);
        assert_eq!(refill.allocation_id, b.allocation_id, "same row, reused");

        // And once there is no hole, the frontier extends again.
        let after = allocate(&store, &chain).await.expect("after");
        assert_eq!(after.nonce, 8);
        assert!(!after.refilled_gap);
    }

    /// Fail closed: a frontier that cannot be sourced from the chain is not
    /// guessed at.
    ///
    /// Mutation this detects: replace the `?` on `transaction_count` with
    /// `.unwrap_or(0)` — the allocation would then hand out nonce 0 against a
    /// live account, and every transaction it signs would be rejected as
    /// already-used (or, worse, replace a pending one).
    #[tokio::test]
    async fn a_failed_transaction_count_allocates_nothing() {
        let (_dir, store) = open_store().await;
        let chain = FakeChain::with_tx_count(5);
        chain.set_tx_count(Err("connection refused".to_string()));

        let err = allocate(&store, &chain).await.expect_err("chain is down");
        assert_eq!(err.code(), ERR_BROADCASTER_CHAIN);
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM nonce_allocations WHERE kind = ?",
                NONCE_KIND_BROADCASTER.to_string()
            )
            .await,
            0,
            "nothing may be allocated on an unanswerable frontier"
        );

        // Paired non-zero arm: the same store, the same call, a healthy
        // chain — one row.
        chain.set_tx_count(Ok(5));
        allocate(&store, &chain).await.expect("healthy");
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM nonce_allocations WHERE kind = ?",
                NONCE_KIND_BROADCASTER.to_string()
            )
            .await,
            1
        );
    }

    // -------------------------------------------------------------------
    // The send path.
    // -------------------------------------------------------------------

    fn plan<'a>(claim_owner: &'a str) -> BroadcastPlan<'a> {
        plan_with_ceiling(claim_owner, TEST_MAX_NATIVE_EXPOSURE_WEI)
    }

    /// Wave 2. Same plan with an explicit exposure ceiling, so the gate's
    /// rejection arm differs from every other test in exactly one value.
    fn plan_with_ceiling(claim_owner: &str, ceiling_wei: u128) -> BroadcastPlan<'_> {
        BroadcastPlan {
            max_native_exposure_wei: WeiCeiling::new(ceiling_wei),
            profile_id: PROFILE,
            intent_id: INTENT_ID,
            chain_id: CHAIN_ID,
            gateway: GATEWAY,
            broadcaster: BOTH_HATS,
            controller: [0x22; 20],
            action: ActionType::SponsoredEnrollment,
            action_nonce: ACTION_NONCE,
            claim_owner,
            lease_ttl_seconds: LEASE,
        }
    }

    /// `SponsoredEnrollmentCall` is a bundle of borrowed structs.
    /// [`sign_persist_and_broadcast`] never inspects any of them — it forwards
    /// the bundle to the signer seam and nothing else — so the fixture is a
    /// zero-valued placeholder, and no assertion in the `FakeSigner` tests
    /// depends on any field of it.
    ///
    /// 🔴 **Wave B2 note.** All-zero *is* a shape:
    /// `preflight::is_direct_eth_enrollment` reads exactly the six fields this
    /// fixture leaves zero, so [`CallFixture::new`] is the **direct-ETH**
    /// branch — the one the production signer must refuse. Use
    /// [`CallFixture::sponsored`] for anything that is supposed to be signable.
    struct CallFixture {
        intent: SponsorEnrollment,
        quote: FeeQuote,
        v1: V1Enrollment,
        link: LinkSecondary,
        root_auth: RootAuthorization,
        eip2612: Eip2612Authorization,
    }

    impl CallFixture {
        fn new() -> Self {
            Self {
                intent: SponsorEnrollment {
                    intent_id: INTENT_ID,
                    deployment_manifest_hash: [0u8; 32],
                    fee_token_config_hash: [0u8; 32],
                    root: [0u8; 20],
                    controller: [0x22; 20],
                    controller_epoch: 0,
                    secondary: [0u8; 20],
                    enroll_digest: [0u8; 32],
                    link_digest: [0u8; 32],
                    root_authorization_digest: [0u8; 32],
                    fee_token: [0u8; 20],
                    fee_authorization_mode: 0,
                    fee_authorization_digest: [0u8; 32],
                    max_fee: 0,
                    fee_quote_hash: [0u8; 32],
                    nonce: ACTION_NONCE,
                    deadline: 0,
                },
                quote: FeeQuote {
                    quote_id: [0u8; 32],
                    action_type: [0u8; 32],
                    action_core_hash: [0u8; 32],
                    deployment_manifest_hash: [0u8; 32],
                    fee_token_config_hash: [0u8; 32],
                    fee_schedule_hash: [0u8; 32],
                    payer: [0u8; 20],
                    fee_token: [0u8; 20],
                    fee_amount: 0,
                    fee_recipient: [0u8; 20],
                    valid_after: 0,
                    valid_until: 0,
                },
                v1: V1Enrollment {
                    wallet: [0u8; 20],
                    nonce: 0,
                    deadline: 0,
                    signature_hex: String::new(),
                },
                link: LinkSecondary {
                    root: [0u8; 20],
                    secondary: [0u8; 20],
                    nonce: 0,
                    deadline: 0,
                },
                root_auth: RootAuthorization::default(),
                eip2612: Eip2612Authorization {
                    owner: [0u8; 20],
                    spender: [0u8; 20],
                    value: 0,
                    deadline: 0,
                    v: 0,
                    r: [0u8; 32],
                    s: [0u8; 32],
                },
            }
        }

        /// A **relayable** (token-fee) call — the only branch the broadcaster
        /// EOA may sign. Differs from [`Self::new`] in exactly the six fields
        /// `preflight::is_direct_eth_enrollment` reads, plus signature bytes
        /// so the encoded calldata is not degenerate.
        fn sponsored() -> Self {
            let mut f = Self::new();
            f.intent.fee_token = [0x77; 20];
            f.intent.fee_authorization_mode = 1;
            f.intent.fee_authorization_digest = [0x88; 32];
            f.intent.fee_quote_hash = [0x99; 32];
            f.intent.max_fee = 1_000;
            f.intent.fee_token_config_hash = [0xAA; 32];
            f
        }

        fn call(&self) -> SponsoredEnrollmentCall<'_> {
            SponsoredEnrollmentCall {
                intent: &self.intent,
                quote: &self.quote,
                v1_enrollment: &self.v1,
                link: &self.link,
                root_authorization: &self.root_auth,
                fee_authorization_mode: 0,
                fee_eip2612_authorization: &self.eip2612,
                sponsor_signature_hex: "0x",
                quote_signature_hex: "0x",
                link_signature_hex: "0x",
                root_authorization_signature_hex: "0x",
            }
        }
    }

    /// 🔴 **Wave 2 — the exposure gate on THIS path, and the release that
    /// `submit.rs`'s equivalent does not need.**
    ///
    /// `submit.rs` can refuse an over-exposed submit and simply return: it
    /// holds no nonce at that point. This path does — `allocate_broadcaster_nonce`
    /// has already run — so a refusal that did not release would leave the
    /// broadcaster EOA's transaction-nonce sequence permanently gapped, and
    /// a gap stalls **every later transaction from that account** in the
    /// mempool until it is filled. The `released` assertion below is the
    /// whole point of this test; `Accepted`-vs-`Err` is not.
    ///
    /// The gate is also pinned in position: the frontier read happened
    /// (`tx_count_calls() == 1`), the oracle was really consulted
    /// (`gas_oracle_calls() == 3`, against `FakeChain`'s NONZERO armed
    /// values), and **nothing was sent** (`send_calls() == 0`) and nothing
    /// was reserved (zero `tx_attempts` rows).
    ///
    /// MUTATIONS DETECTED:
    /// 1. Delete the `release_broadcaster_nonce(...)` call from the
    ///    exposure-rejection arm — the allocation stays `allocated` and the
    ///    `released` assertion fails. (This is the mutation the architect's
    ///    ruling 3 exists to force: copying `submit.rs`'s "a rejection needs
    ///    no store cleanup" comment into this arm produces exactly it.)
    /// 2. Delete the whole `base_fee::submit_exposure_for_chain(...)` call
    ///    from `sign_persist_and_broadcast` — the broadcast succeeds and
    ///    `expect_err` panics.
    #[tokio::test]
    async fn an_exposure_rejection_releases_the_broadcaster_eoa_nonce() {
        let (_dir, store) = open_store().await;
        seed_intent(&store).await;
        let chain = FakeChain::with_tx_count(5);
        let signer = FakeSigner::ok();

        let fx = CallFixture::new();
        let err = sign_persist_and_broadcast(
            &store,
            &data_key_hex(),
            (&chain).into(),
            &signer,
            // One wei below the real three-term reserve — see
            // `TEST_EXPECTED_RESERVE_WEI`.
            &plan_with_ceiling(OWNER, TEST_EXPECTED_RESERVE_WEI - 1),
            &fx.call(),
            WALL_NOW,
        )
        .await
        .expect_err("a reserve above the ceiling must refuse the broadcast");

        match &err {
            BroadcasterError::NativeExposure(BaseFeeError::ExposureExceedsSchedule {
                reserve_wei,
                ceiling_wei,
            }) => {
                assert_eq!(
                    *reserve_wei, TEST_EXPECTED_RESERVE_WEI,
                    "the refusal must name the three-term reserve, not just l2_wei"
                );
                assert_eq!(*ceiling_wei, TEST_EXPECTED_RESERVE_WEI - 1);
            }
            other => panic!("expected NativeExposure(ExposureExceedsSchedule), got {other:?}"),
        }
        assert_eq!(
            err.code(),
            crate::stream_g::base_fee::ERR_EXPOSURE_EXCEEDS_SCHEDULE
        );

        // 🔴 THE ASSERTION. `released`, never `allocated`.
        let allocation_id = broadcaster_nonce_row_id(CHAIN_ID, BOTH_HATS, 5);
        assert_eq!(
            text(
                &store,
                "SELECT status FROM nonce_allocations WHERE id = ?",
                allocation_id.clone()
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_RELEASED),
            "THE HAZARD: one refused reservation gaps the broadcaster EOA forever"
        );

        // Position pins. The frontier was read and the oracle was consulted,
        // so the zero-assertions below cannot pass by the code never running.
        assert_eq!(chain.tx_count_calls(), 1, "non-zero arm: frontier was read");
        assert_eq!(
            chain.gas_oracle_calls(),
            3,
            "non-zero arm: all three GasPriceOracle reads really happened"
        );
        assert_eq!(
            chain.send_calls(),
            0,
            "THE HAZARD: the transaction was broadcast anyway"
        );
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM tx_attempts WHERE intent_id = ?",
                intent_row_id(PROFILE, INTENT_ID),
            )
            .await,
            0,
            "the gate must run BEFORE reserve_persist_and_send"
        );
    }

    /// The send returns as soon as the node has the bytes. Waiting for a
    /// receipt here is what turned a slow-but-landing transaction into a
    /// "failed" broadcast whose nonce got released underneath it.
    ///
    /// Mutation this detects: add a `chain.client().transaction_receipt(..)`
    /// call to [`sign_persist_and_broadcast`] after the send —
    /// `receipt_calls()` becomes 1.
    ///
    /// The zero-assertion (`receipt_calls() == 0`) is paired with two
    /// non-zero ones on the same object (`send_calls() == 1`,
    /// `tx_count_calls() == 1`), so it cannot pass by the code never running.
    #[tokio::test]
    async fn broadcast_returns_the_hash_without_waiting_for_a_receipt() {
        let (_dir, store) = open_store().await;
        seed_intent(&store).await;
        let chain = FakeChain::with_tx_count(5);
        let signer = FakeSigner::ok();

        let fx = CallFixture::new();
        let outcome = sign_persist_and_broadcast(
            &store,
            &data_key_hex(),
            (&chain).into(),
            &signer,
            &plan(OWNER),
            &fx.call(),
            WALL_NOW,
        )
        .await
        .expect("broadcast");

        assert!(matches!(outcome, BroadcastOutcome::Accepted { .. }));
        assert_eq!(outcome.tx_hash_hex(), bytes32_hex([0xEE; 32]));
        assert_eq!(
            outcome.as_broadcast_error().map(|e| e.detail),
            None,
            "an accepted broadcast is not an error"
        );
        assert_eq!(chain.send_calls(), 1, "non-zero arm: it really did send");
        assert_eq!(chain.tx_count_calls(), 1, "non-zero arm: frontier was read");
        assert_eq!(
            chain.receipt_calls(),
            0,
            "the send path must not block on a receipt"
        );
        assert_eq!(
            signer.last_nonce(),
            Some(5),
            "the signer must sign against the allocated frontier nonce"
        );
    }

    /// The 6b hazard at its source: `eth_sendRawTransaction` failed, but the
    /// payload is signed and may already be in a mempool. Both nonces stay
    /// held and the failure carries the hash.
    ///
    /// Mutation this detects: make the `SendFailedStuckRecoverable` arm
    /// release the broadcaster nonce (or report `BroadcastError::transport`
    /// instead of `::unresolved`) — the `Some(hash)` assertion fails and the
    /// allocation flips to `released`, which is exactly what lets a second
    /// transaction be signed against a live nonce.
    #[tokio::test]
    async fn a_send_failure_after_signing_keeps_both_nonces_and_names_the_transaction() {
        let (_dir, store) = open_store().await;
        seed_intent(&store).await;
        let chain = FakeChain::with_tx_count(5);
        chain.set_send_result(Err("connection reset by peer".to_string()));
        let signer = FakeSigner::ok();

        let fx = CallFixture::new();
        let outcome = sign_persist_and_broadcast(
            &store,
            &data_key_hex(),
            (&chain).into(),
            &signer,
            &plan(OWNER),
            &fx.call(),
            WALL_NOW,
        )
        .await
        .expect("a send failure is an outcome, not an error");

        let BroadcastOutcome::UnresolvedWithKnownHash {
            ref nonce,
            ref raw_tx_hash,
            ..
        } = outcome
        else {
            panic!("expected UnresolvedWithKnownHash, got {outcome:?}");
        };
        assert_eq!(*raw_tx_hash, signer.signed_hash());

        // The `BroadcastError` this hands `submit.rs` carries the hash, which
        // is what stops that module releasing the ACTION nonce.
        let bridged = outcome
            .as_broadcast_error()
            .expect("an unresolved send is an error for submit.rs");
        assert_eq!(
            bridged.tx_hash,
            Some(signer.signed_hash()),
            "a signed payload can always be named; reporting None here IS the 6b hazard"
        );
        assert_eq!(bridged.revert, None);

        // The broadcaster EOA nonce is still held.
        assert_eq!(
            text(
                &store,
                "SELECT status FROM nonce_allocations WHERE id = ?",
                nonce.allocation_id.clone()
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "a signed transaction may be in a mempool; its EOA nonce is not free"
        );
        // And so is the gateway action nonce, with the signed payload kept.
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM nonce_allocations WHERE kind = 'action' AND status = ?",
                NONCE_STATUS_ALLOCATED.to_string()
            )
            .await,
            1,
            "non-zero arm: the action nonce is held too"
        );
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM tx_attempts WHERE status = ? AND raw_tx_enc IS NOT NULL",
                "reserved".to_string()
            )
            .await,
            1,
            "the signed payload stays persisted so the sweeper can resolve it"
        );
    }

    /// CRITICAL 5. `eth_sendRawTransaction` SUCCEEDED and the follow-up stamp
    /// failed. The transaction is in a mempool at this EOA nonce, so the nonce
    /// must NOT go back to the pool.
    ///
    /// Before the fix, `record_broadcast_accepted`'s error propagated out of
    /// `reserve_persist_and_send` as a bare `Err`, landed in the `Err(e)` arm of
    /// `sign_persist_and_broadcast`, and released the nonce on the strength of a
    /// comment asserting "the reservation was refused, so the send never
    /// happened". That premise is true of `reserve_and_persist_raw_tx` failing
    /// and FALSE of `record_broadcast_accepted` failing, which runs after the
    /// send. The next caller would then sign a DIFFERENT transaction at nonce N
    /// and one of the two would be evicted, non-deterministically.
    ///
    /// Mutation this detects: in `outbox::reserve_persist_and_send`, restore
    /// `record_broadcast_accepted(..).await?` (i.e. propagate as `Err` instead
    /// of returning `SendOutcome::BroadcastNotRecorded`). The nonce then flips
    /// to `released` and this test fails on the status assertion.
    #[tokio::test]
    async fn a_record_failure_after_a_successful_send_never_releases_the_eoa_nonce() {
        let (_dir, store) = open_store().await;
        seed_intent(&store).await;
        // The send SUCCEEDS here — that is the whole point of the test.
        let chain = FakeChain::with_tx_count(5);
        let signer = FakeSigner::ok();
        super::super::outbox::fail_next_record_after_send();

        let fx = CallFixture::new();
        let outcome = sign_persist_and_broadcast(
            &store,
            &data_key_hex(),
            (&chain).into(),
            &signer,
            &plan(OWNER),
            &fx.call(),
            WALL_NOW,
        )
        .await
        .expect("a post-send stamp failure is an outcome, not an error");

        let BroadcastOutcome::UnresolvedWithKnownHash {
            ref nonce,
            ref raw_tx_hash,
            ..
        } = outcome
        else {
            panic!("expected UnresolvedWithKnownHash, got {outcome:?}");
        };
        assert_eq!(
            *raw_tx_hash,
            signer.signed_hash(),
            "the transaction is nameable — that is what lets the sweeper resolve it"
        );

        assert_eq!(
            text(
                &store,
                "SELECT status FROM nonce_allocations WHERE id = ?",
                nonce.allocation_id.clone()
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "THE POINT OF CRITICAL 5: the send succeeded, so this EOA nonce is \
             NOT free — releasing it hands the same nonce to the next caller \
             while the first transaction is live in a mempool"
        );
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM tx_attempts WHERE status = ? AND raw_tx_enc IS NOT NULL",
                "reserved".to_string()
            )
            .await,
            1,
            "the signed payload stays persisted so the sweeper can resolve it \
             against chain evidence (founder ruling F2)"
        );
    }

    /// The paired PRE-send arm, so the fix above cannot be "never release
    /// anything", which would gap the account forever on a refused reservation.
    /// Signing failed, so no bytes exist and no transaction can ever carry
    /// this nonce. Holding it would gap the account for nothing.
    ///
    /// Mutation this detects: delete the `release_broadcaster_nonce` call
    /// from the signing-failure arm — the nonce stays `allocated` and the
    /// next allocation extends past it, stranding it.
    #[tokio::test]
    async fn a_signing_failure_gives_the_nonce_back() {
        let (_dir, store) = open_store().await;
        seed_intent(&store).await;
        let chain = FakeChain::with_tx_count(5);
        let signer = FakeSigner::failing();

        let fx = CallFixture::new();
        let err = sign_persist_and_broadcast(
            &store,
            &data_key_hex(),
            (&chain).into(),
            &signer,
            &plan(OWNER),
            &fx.call(),
            WALL_NOW,
        )
        .await
        .expect_err("signing failed");
        assert_eq!(err.code(), ERR_BROADCASTER_SIGNING);
        assert_eq!(signer.calls(), 1, "non-zero arm: the signer was reached");
        assert_eq!(chain.send_calls(), 0, "nothing may be sent unsigned");

        // Released, so the very next allocation refills 5 rather than
        // stranding it.
        let again = allocate(&store, &chain).await.expect("re-allocate");
        assert_eq!(again.nonce, 5);
        assert!(again.refilled_gap);
    }

    // -------------------------------------------------------------------
    // WAVE B2 — the production signer.
    //
    // Reading discipline for everything below:
    //
    // * The **EIP-1559 envelope encoding and the signature** are not proven
    //   here. They are pinned byte-for-byte against `cast mktx` in
    //   `rpc_chain::tests::broadcaster_signed_bytes_are_the_cast_reference_transaction`,
    //   which is the only honest place to prove them: `cast` is an independent
    //   implementation, and checking alloy's encoder with alloy's decoder would
    //   be `x == x`.
    // * The **calldata layout** is not proven here either. It is pinned against
    //   `cast calldata` in
    //   `direct_eth::tests::the_broadcast_calldata_helper_is_the_cast_pinned_encoder`.
    // * What IS proven here is the **composition**: that this signer feeds the
    //   caller's gateway, the caller's allocated nonce and its own gas policy
    //   into those two pinned pieces, refuses the branch it must not sign, and
    //   leaves the EOA nonce accounting of `sign_persist_and_broadcast`
    //   untouched. Decoding is used only to read back which values were passed.
    // -------------------------------------------------------------------

    use alloy::consensus::{SignableTransaction, TxEnvelope};
    use alloy::eips::eip2718::Decodable2718;

    /// Anvil account #9 — the same key `rpc_chain`'s `cast` fixtures use, so a
    /// failure here and a failure there point at the same account.
    /// `cast wallet address --private-key <this>` = the constant below.
    const SIGNER_KEY: &str = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";
    /// `0xa0Ee7A142d267C1f36714E4a8F75612F20a79720`, lowercased — the EIP-55
    /// checksum casing is a rendering of these bytes, not part of them.
    const SIGNER_ADDR: [u8; 20] = [
        0xa0, 0xee, 0x7a, 0x14, 0x2d, 0x26, 0x7c, 0x1f, 0x36, 0x71, 0x4e, 0x4a, 0x8f, 0x75, 0x61,
        0x2f, 0x20, 0xa7, 0x97, 0x20,
    ];

    /// An `RpcChain` holding `SIGNER_KEY` as the Stream G broadcaster, on
    /// [`CHAIN_ID`] — the *same* chain id the `BroadcastPlan` fixtures use, so
    /// the transaction is signed for the chain whose nonce rows it is
    /// allocated against. (Nothing in the code enforces that agreement; see
    /// the wave report.) The RPC URL is never contacted: signing makes no
    /// network call.
    fn signing_chain() -> RpcChain {
        let mut m = std::collections::HashMap::new();
        m.insert("RPC_URL".to_string(), "http://127.0.0.1:8545".to_string());
        m.insert("CHAIN_ID".to_string(), CHAIN_ID.to_string());
        m.insert(
            "EPOCH_SETTLEMENT_ADDRESS".to_string(),
            "0x0000000000000000000000000000000000000001".to_string(),
        );
        m.insert(
            "WORKER_BINDING_ADDRESS".to_string(),
            "0x0000000000000000000000000000000000000002".to_string(),
        );
        m.insert(
            "ENROLLMENT_REGISTRY_ADDRESS".to_string(),
            "0x0000000000000000000000000000000000000003".to_string(),
        );
        m.insert("REGISTRY_JSON".to_string(), "./registry.json".to_string());
        m.insert("STREAM_G_ENABLED".to_string(), "1".to_string());
        m.insert(
            "STREAM_G_BROADCASTER_PRIVATE_KEY".to_string(),
            SIGNER_KEY.to_string(),
        );
        m.insert(
            "STREAM_G_QUOTE_SIGNER_PRIVATE_KEY".to_string(),
            "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a".to_string(),
        );
        m.insert(
            "STREAM_G_ISSUER_PRIVATE_KEY".to_string(),
            "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6".to_string(),
        );
        m.insert(
            "STREAM_G_DATA_KEY_HEX".to_string(),
            hex::encode([0x11u8; 32]),
        );
        let cfg = crate::config::load_from_map(&m).expect("config must load");
        RpcChain::from_config(&cfg).expect("RpcChain must construct")
    }

    /// Decode `raw` back into its EIP-1559 fields **and recover the signing
    /// address from the signature** — the same recovery primitive
    /// `sig_verify.rs`, `preflight.rs` and `quotes.rs` already use in this
    /// crate.
    fn decode_signed(raw: &[u8]) -> (alloy::consensus::TxEip1559, [u8; 20]) {
        let envelope =
            TxEnvelope::decode_2718(&mut &raw[..]).expect("a well-formed EIP-2718 payload");
        let TxEnvelope::Eip1559(signed) = envelope else {
            panic!("expected an EIP-1559 (type 0x02) transaction");
        };
        let recovered = signed
            .signature()
            .recover_address_from_prehash(&signed.tx().signature_hash())
            .expect("the signature must recover");
        (signed.tx().clone(), recovered.into_array())
    }

    /// The gas policy the signer tests use. Deliberately the documented
    /// starting values, so a change to those numbers shows up here.
    fn policy() -> BroadcastGasPolicy {
        BroadcastGasPolicy::starting_values_pending_founder_review()
    }

    /// Everything about the produced transaction that this seam is responsible
    /// for choosing: the destination, the nonce it was told to use, the gas
    /// policy's three numbers, a zero value, and a signature that recovers to
    /// the configured broadcaster key.
    ///
    /// The `SignedRawTx` the outbox will persist reports the *same* gas limit
    /// and max fee as the bytes actually carry. `outbox::SignedRawTx`'s type
    /// doc says those two fields are "the signer's claim about the bytes, not
    /// a fact read out of them" and that decoding and comparing "has not been
    /// made" — for **this** implementor it now has. The type still does not
    /// enforce it and a different implementor could still lie; that caveat is
    /// unchanged.
    ///
    /// MUTATIONS DETECTED (each run alone and reverted):
    /// 1. `nonce: 0` instead of `nonce: broadcaster_nonce` in
    ///    `sign_sponsored_enrollment_tx` — the nonce assertions fail. This is
    ///    the mutation that matters most: a signer that picks its own nonce
    ///    voids `allocate_broadcaster_nonce`'s entire contiguity guarantee.
    /// 2. `gas_limit: MIN_TRANSACTION_GAS` instead of `self.gas.gas_limit` —
    ///    the decoded-gas assertion fails and so does the
    ///    `SignedRawTx::gas_limit()` agreement.
    #[test]
    fn the_signed_transaction_carries_the_gateway_the_allocated_nonce_and_the_policy() {
        let chain = signing_chain();
        let signer = RpcChainEnrollmentSigner::new(&chain, policy()).expect("key is configured");
        assert_eq!(
            signer.broadcaster(),
            SIGNER_ADDR,
            "the address a caller must put in BroadcastPlan::broadcaster"
        );

        let fx = CallFixture::sponsored();
        for nonce in [0u64, 5, 6, u64::MAX] {
            let out = signer
                .sign_sponsored_enrollment_tx(GATEWAY, nonce, &fx.call())
                .expect("a relayable call must sign");
            let (tx, from) = decode_signed(out.raw());

            assert_eq!(from, SIGNER_ADDR, "signed by the broadcaster key");
            assert_eq!(tx.nonce, nonce, "the signer must use the ALLOCATED nonce");
            assert_eq!(
                tx.to,
                alloy::primitives::TxKind::Call(alloy::primitives::Address::from(GATEWAY))
            );
            assert_eq!(tx.chain_id, CHAIN_ID);
            assert!(
                tx.value.is_zero(),
                "executeSponsoredEnrollment is not payable"
            );
            assert_eq!(tx.gas_limit, policy().gas_limit().get());
            assert_eq!(tx.max_fee_per_gas, policy().max_fee_per_gas().get());
            assert_eq!(
                tx.max_priority_fee_per_gas,
                policy().max_priority_fee_per_gas().get()
            );
            assert!(tx.access_list.is_empty());

            // The outbox's two asserted fields really describe these bytes.
            assert_eq!(out.gas_limit().get(), tx.gas_limit);
            assert_eq!(out.max_fee_per_gas().get(), tx.max_fee_per_gas);
            // And the calldata is the shared, `cast`-pinned encoding — not a
            // second one built here.
            assert_eq!(
                tx.input.as_ref(),
                direct_eth::sponsored_enrollment_calldata(&fx.call())
                    .unwrap()
                    .as_slice()
            );
        }
    }

    /// The hash the outbox persists and the hash a node will report are the
    /// same number.
    ///
    /// This is the foundation of the module doc's claim that "a signer that has
    /// produced bytes can always name them", which is in turn why
    /// [`BroadcastOutcome`] has no `tx_hash: None` path and why `submit.rs`
    /// refuses to classify these failures `Retryable`. If `SignedRawTx::hash()`
    /// were not the real transaction hash, every one of those refusals would be
    /// naming a transaction that does not exist.
    ///
    /// MUTATION DETECTED (run and reverted): in
    /// `rpc_chain::sign_broadcaster_eip1559`, return
    /// `signed.signature_hash()` (the pre-signature digest) as the hash — the
    /// `SignedEip1559::hash()` arm below fails while the `SignedRawTx` arm,
    /// which recomputes from the bytes, still passes. That is the whole point
    /// of asserting both.
    #[test]
    fn the_outbox_hash_is_the_real_transaction_hash() {
        let chain = signing_chain();
        let signer = RpcChainEnrollmentSigner::new(&chain, policy()).expect("key is configured");
        let fx = CallFixture::sponsored();
        let out = signer
            .sign_sponsored_enrollment_tx(GATEWAY, 5, &fx.call())
            .expect("a relayable call must sign");

        let envelope =
            TxEnvelope::decode_2718(&mut out.raw()).expect("a well-formed EIP-2718 payload");
        assert_eq!(
            out.hash(),
            envelope.tx_hash().0,
            "SignedRawTx's hash must be the transaction hash a node reports"
        );

        // The primitive agrees too, by a second route: the raw bytes the
        // primitive returns hash to the same value.
        let primitive = chain
            .sign_broadcaster_eip1559(&Eip1559Request {
                to: GATEWAY,
                nonce: 5,
                gas_limit: policy().gas_limit().get(),
                max_fee_per_gas: policy().max_fee_per_gas().get(),
                max_priority_fee_per_gas: policy().max_priority_fee_per_gas().get(),
                calldata: direct_eth::sponsored_enrollment_calldata(&fx.call()).unwrap(),
            })
            .expect("primitive signs");
        assert_eq!(primitive.raw(), out.raw(), "one signing path, not two");
        assert_eq!(primitive.hash(), out.hash());
        assert_eq!(primitive.from(), SIGNER_ADDR);

        // Non-zero arm: the hash is a function of the bytes, so a different
        // nonce is a different transaction.
        let other = signer
            .sign_sponsored_enrollment_tx(GATEWAY, 6, &fx.call())
            .expect("signs");
        assert_ne!(other.hash(), out.hash());
    }

    /// 🔴 The branch this account may never sign.
    ///
    /// `GoatRelayGateway.sol:379` reverts `NotController` unless
    /// `msg.sender == intent.controller`. A broadcaster that signed it would
    /// produce a guaranteed revert that still consumes the EOA nonce and burns
    /// the gas — and, because the revert happens on chain, the intent would
    /// stay unexecuted with the client none the wiser.
    ///
    /// Driven through the **whole** `sign_persist_and_broadcast` path rather
    /// than the trait method alone, because the second half of the property is
    /// about nonce accounting: this is a PRE-send failure, so the EOA nonce
    /// must go **back**. Holding it would gap the account forever (the
    /// module doc's "one refused reservation gaps the account forever"), and
    /// releasing it after a *send* would be the opposite bug — which
    /// `a_record_failure_after_a_successful_send_never_releases_the_eoa_nonce`
    /// pins and this test must not disturb.
    ///
    /// MUTATIONS DETECTED (each run alone and reverted):
    /// 1. Delete the `is_direct_eth_enrollment` guard from
    ///    `sign_sponsored_enrollment_tx` — the direct-ETH arm returns
    ///    `Ok(Accepted)` and `expect_err` panics, i.e. the crate signed a
    ///    transaction that can only revert.
    /// 2. Invert it to `if !preflight::is_direct_eth_enrollment(..)` — the
    ///    paired sponsored arm below fails instead, so the guard cannot
    ///    degenerate into "refuse everything".
    #[tokio::test(flavor = "multi_thread")]
    async fn the_production_signer_refuses_the_direct_eth_branch_and_returns_the_nonce() {
        let (_dir, store) = open_store().await;
        seed_intent(&store).await;
        let chain = FakeChain::with_tx_count(5);
        let rpc = signing_chain();
        let signer = RpcChainEnrollmentSigner::new(&rpc, policy()).expect("key is configured");

        // REFUSAL ARM. `CallFixture::new()` is all-zero, which is exactly the
        // six-condition direct-ETH shape.
        let direct = CallFixture::new();
        assert!(
            preflight::is_direct_eth_enrollment(&direct.intent),
            "fixture precondition: this really is the direct-ETH branch"
        );
        let err = sign_persist_and_broadcast(
            &store,
            &data_key_hex(),
            (&chain).into(),
            &signer,
            &plan(OWNER),
            &direct.call(),
            WALL_NOW,
        )
        .await
        .expect_err("the direct-ETH branch must not be signed");
        assert_eq!(err.code(), ERR_BROADCASTER_SIGNING);
        assert!(
            err.to_string().contains("NotController"),
            "the refusal must name the revert it is avoiding: {err}"
        );
        assert_eq!(chain.send_calls(), 0, "nothing may be sent");

        // The EOA nonce went back — this is a PRE-send failure.
        assert_eq!(
            text(
                &store,
                "SELECT status FROM nonce_allocations WHERE id = ?",
                broadcaster_nonce_row_id(CHAIN_ID, BOTH_HATS, 5)
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_RELEASED),
            "a refused signature must not gap the broadcaster EOA's sequence"
        );

        // PAIRED NON-REFUSAL ARM, same signer, same store, same chain: a
        // relayable call signs, sends, and holds nonce 5 (refilling the hole
        // the refusal above left, which is the frontier behaving correctly).
        let sponsored = CallFixture::sponsored();
        let outcome = sign_persist_and_broadcast(
            &store,
            &data_key_hex(),
            (&chain).into(),
            &signer,
            &plan(OWNER),
            &sponsored.call(),
            WALL_NOW,
        )
        .await
        .expect("a relayable call must broadcast");
        assert!(matches!(outcome, BroadcastOutcome::Accepted { .. }));
        assert_eq!(chain.send_calls(), 1, "non-zero arm: it really did send");
        assert_eq!(
            text(
                &store,
                "SELECT status FROM nonce_allocations WHERE id = ?",
                broadcaster_nonce_row_id(CHAIN_ID, BOTH_HATS, 5)
            )
            .await
            .as_deref(),
            Some(NONCE_STATUS_ALLOCATED),
            "a sent transaction's EOA nonce is held"
        );
    }

    /// The frontier's nonce is the one that ends up in the signed bytes, all
    /// the way through `sign_persist_and_broadcast` — not just when the trait
    /// method is called directly.
    ///
    /// Arranged on the send-failure arm because that is the only outcome that
    /// surfaces the *real* payload hash (`Accepted` reports whatever the node
    /// returned, which for `FakeChain` is a constant). Two runs at two
    /// different frontier positions, cross-checked against bytes signed
    /// independently at those nonces.
    ///
    /// MUTATION DETECTED (run and reverted): pass `broadcaster_nonce` as `0` in
    /// `sign_sponsored_enrollment_tx`. **Which assertion fires is the
    /// interesting part.** The per-run `raw_tx_hash == expected.hash()` check
    /// keeps passing — the cross-check signs through the same mutated function,
    /// so both sides move together, and on its own that check is worth less
    /// than it looks. What fails is the closing `assert_ne!`: the two frontier
    /// positions collapse onto one transaction hash
    /// (`ca01de8b…` on both runs), which is the observable form of "two
    /// transactions signed against one EOA nonce". That is why the loop runs
    /// twice and why the final comparison is here at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_broadcast_path_signs_against_the_frontier_nonce_it_allocated() {
        let rpc = signing_chain();
        let signer = RpcChainEnrollmentSigner::new(&rpc, policy()).expect("key is configured");
        let fx = CallFixture::sponsored();

        let mut hashes = Vec::new();
        for mined in [5u64, 9] {
            let (_dir, store) = open_store().await;
            seed_intent(&store).await;
            let chain = FakeChain::with_tx_count(mined);
            chain.set_send_result(Err("connection reset by peer".to_string()));

            let outcome = sign_persist_and_broadcast(
                &store,
                &data_key_hex(),
                (&chain).into(),
                &signer,
                &plan(OWNER),
                &fx.call(),
                WALL_NOW,
            )
            .await
            .expect("a send failure is an outcome, not an error");

            let BroadcastOutcome::UnresolvedWithKnownHash {
                ref nonce,
                ref raw_tx_hash,
                ..
            } = outcome
            else {
                panic!("expected UnresolvedWithKnownHash, got {outcome:?}");
            };
            assert_eq!(nonce.nonce, mined, "the frontier floor is the mined count");

            // Independently signed at the nonce the frontier says it used.
            let expected = signer
                .sign_sponsored_enrollment_tx(GATEWAY, mined, &fx.call())
                .expect("signs");
            assert_eq!(
                *raw_tx_hash,
                expected.hash(),
                "the broadcast payload must be the one signed at the allocated nonce"
            );

            // And the EOA nonce is still held: the payload may be in a mempool.
            assert_eq!(
                text(
                    &store,
                    "SELECT status FROM nonce_allocations WHERE id = ?",
                    nonce.allocation_id.clone()
                )
                .await
                .as_deref(),
                Some(NONCE_STATUS_ALLOCATED)
            );
            hashes.push(*raw_tx_hash);
        }
        assert_ne!(
            hashes[0], hashes[1],
            "two frontier positions must not produce one transaction"
        );
    }

    /// The gas policy refuses its own impossible values at construction, and
    /// the signer refuses a policy that cannot pay for the calldata it is about
    /// to carry.
    ///
    /// Note what is NOT claimed: nothing here shows 500_000 gas is *enough* for
    /// `executeSponsoredEnrollment`. [`intrinsic_gas_floor`] is the pre-Prague
    /// base+calldata floor and EIP-7623's higher calldata floor is not
    /// implemented, so passing this check is necessary and not sufficient. See
    /// [`BroadcastGasPolicy`].
    ///
    /// MUTATIONS DETECTED (each run alone and reverted):
    /// 1. Change `if gas_limit.get() < MIN_TRANSACTION_GAS` to `== 0` — the
    ///    `GasLimitBelowBaseCost` assertion fails
    ///    (`right: Err(GasLimitBelowBaseCost { got: 20999 })`).
    /// 2. Delete the `self.gas.gas_limit < floor` check in
    ///    `sign_sponsored_enrollment_tx` — the last `expect_err` panics, i.e.
    ///    a transaction is signed that cannot pay for its own calldata.
    #[test]
    fn the_gas_policy_refuses_values_no_node_would_accept() {
        assert_eq!(
            BroadcastGasPolicy::new(
                GasUnits::new(MIN_TRANSACTION_GAS - 1),
                MaxFeePerGas::new(1),
                PriorityFeePerGas::new(1),
            ),
            Err(GasPolicyError::GasLimitBelowBaseCost {
                got: MIN_TRANSACTION_GAS - 1
            })
        );
        assert_eq!(
            BroadcastGasPolicy::new(
                GasUnits::new(MIN_TRANSACTION_GAS),
                MaxFeePerGas::new(0),
                PriorityFeePerGas::new(0),
            ),
            Err(GasPolicyError::ZeroMaxFeePerGas)
        );
        assert_eq!(
            BroadcastGasPolicy::new(
                GasUnits::new(MIN_TRANSACTION_GAS),
                MaxFeePerGas::new(10),
                PriorityFeePerGas::new(11),
            ),
            Err(GasPolicyError::PriorityAboveMax {
                priority: 11,
                max: 10
            })
        );
        // Paired accept arm, one wei/one gas away from each refusal above.
        let ok = BroadcastGasPolicy::new(
            GasUnits::new(MIN_TRANSACTION_GAS),
            MaxFeePerGas::new(10),
            PriorityFeePerGas::new(10),
        )
        .expect("the boundary values are legal");
        assert_eq!(ok.gas_limit().get(), MIN_TRANSACTION_GAS);
        assert_eq!(
            GasPolicyError::ZeroMaxFeePerGas.code(),
            ERR_BROADCASTER_GAS_POLICY
        );

        // The documented starting values are self-consistent.
        let starting = BroadcastGasPolicy::starting_values_pending_founder_review();
        assert_eq!(starting.gas_limit().get(), 500_000);
        assert_eq!(starting.max_fee_per_gas().get(), 1_000_000_000);
        assert_eq!(starting.max_priority_fee_per_gas().get(), 1_000_000);

        // …but a *legal* policy can still be too small for this call's
        // calldata, and that is caught at signing time rather than signed.
        let fx = CallFixture::sponsored();
        let calldata = direct_eth::sponsored_enrollment_calldata(&fx.call()).unwrap();
        let floor = intrinsic_gas_floor(&calldata);
        assert!(
            floor > MIN_TRANSACTION_GAS,
            "non-zero arm: the calldata really does cost gas ({} bytes)",
            calldata.len()
        );
        assert!(
            floor < starting.gas_limit().get(),
            "the starting gas limit must at least clear its own calldata floor"
        );

        let rpc = signing_chain();
        let too_small = RpcChainEnrollmentSigner::new(
            &rpc,
            BroadcastGasPolicy::new(
                GasUnits::new(floor - 1),
                MaxFeePerGas::new(1_000_000_000),
                PriorityFeePerGas::new(1_000_000),
            )
            .expect("legal in isolation"),
        )
        .expect("key is configured");
        let err = too_small
            .sign_sponsored_enrollment_tx(GATEWAY, 5, &fx.call())
            .expect_err("a limit below the intrinsic floor must not be signed");
        assert!(
            err.contains(ERR_BROADCASTER_GAS_POLICY),
            "unexpected: {err}"
        );

        // Paired arm: exactly the floor signs.
        let exact = RpcChainEnrollmentSigner::new(
            &rpc,
            BroadcastGasPolicy::new(
                GasUnits::new(floor),
                MaxFeePerGas::new(1_000_000_000),
                PriorityFeePerGas::new(1_000_000),
            )
            .unwrap(),
        )
        .expect("key is configured");
        assert!(exact
            .sign_sponsored_enrollment_tx(GATEWAY, 5, &fx.call())
            .is_ok());
    }

    /// No broadcaster key configured → the signer refuses to be **built**,
    /// naming the env var, rather than existing and failing on the first
    /// request (which would allocate and then release an EOA nonce for
    /// nothing, once per request, forever).
    ///
    /// MUTATION DETECTED (run and reverted): make `RpcChainEnrollmentSigner::new`
    /// return `Self { broadcaster: [0u8; 20], .. }` when the address lookup
    /// fails instead of propagating — `expect_err` panics, and every
    /// `BroadcastPlan` built from `broadcaster()` would then name the zero
    /// address, whose nonce frontier belongs to no key at all.
    #[test]
    fn the_signer_refuses_to_exist_without_its_dedicated_key() {
        let mut m = std::collections::HashMap::new();
        m.insert("RPC_URL".to_string(), "http://127.0.0.1:8545".to_string());
        m.insert("CHAIN_ID".to_string(), CHAIN_ID.to_string());
        m.insert(
            "EPOCH_SETTLEMENT_ADDRESS".to_string(),
            "0x0000000000000000000000000000000000000001".to_string(),
        );
        m.insert(
            "WORKER_BINDING_ADDRESS".to_string(),
            "0x0000000000000000000000000000000000000002".to_string(),
        );
        m.insert(
            "ENROLLMENT_REGISTRY_ADDRESS".to_string(),
            "0x0000000000000000000000000000000000000003".to_string(),
        );
        m.insert("REGISTRY_JSON".to_string(), "./registry.json".to_string());
        // A relayer key IS present, and must not be borrowed.
        m.insert("RELAYER_PRIVATE_KEY".to_string(), SIGNER_KEY.to_string());
        let cfg = crate::config::load_from_map(&m).expect("config loads");
        let rpc = RpcChain::from_config(&cfg).expect("constructs");

        let err = RpcChainEnrollmentSigner::new(&rpc, policy())
            .err()
            .expect("no broadcaster key must refuse")
            .to_string();
        assert!(
            err.contains("STREAM_G_BROADCASTER_PRIVATE_KEY"),
            "unexpected err: {err}"
        );

        // Paired arm: with the dedicated key present, the same call succeeds
        // and resolves the address the key really has.
        let rpc = signing_chain();
        assert_eq!(
            RpcChainEnrollmentSigner::new(&rpc, policy())
                .expect("constructs")
                .broadcaster(),
            SIGNER_ADDR
        );
    }
}
