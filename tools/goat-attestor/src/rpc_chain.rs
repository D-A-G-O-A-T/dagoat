//! Live `ChainClient` over alloy HTTP JSON-RPC (anvil / any EVM RPC).

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use alloy::consensus::{SignableTransaction, TxEip1559};
use alloy::eips::eip2718::Encodable2718;
use alloy::network::{TransactionBuilder, TxSignerSync};
use alloy::primitives::{keccak256, Address, Bytes, TxKind, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{Filter, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use tokio::sync::Mutex;
use url::Url;

/// Stream G G1 live-chain sourcing (Task 6 Wave A) — ABI encoders, decoders
/// and view types for the block-pinned reads that feed
/// `EnrollmentQuoteContext`. Grouped separately from the settlement/registry
/// imports above because they belong to a different contract surface
/// (`FeeTokenRegistry` / `GoatRelayGateway`, not `EpochSettlement`).
use crate::chain::{
    code_hash_from_get_code, decode_fee_token_config_return, decode_nonce_snapshot_return,
    encode_active_manifest_hash, encode_get_token_config, encode_get_token_config_hash,
    encode_secondary_enrollment_nonce_snapshot, FeeTokenConfigView, NonceSnapshotView,
};
use crate::chain::{
    decode_batch_return, encode_batches, encode_bind_with_signature, encode_challenge_batch,
    encode_claim_payout, encode_confirm_epoch, encode_enroll_self_with_signature,
    encode_finalize_batch, encode_has_baseline, encode_last_claimed_cumulative, encode_nonces,
    encode_propose_batch, parse_address20, selector, u128_from_word, BatchView, BoundWorker,
    ChainClient, ChainError, TxHash,
};
/// Stream G G1 outbox / broadcaster / reconcile (Task 7 Wave A). A separate
/// `use` rather than an extra line inside the group above, so this task's
/// change to this file stays purely additive.
use crate::chain::{
    decode_bool_return, decode_sponsored_enrollment_executed, decode_u64_return,
    encode_erc2612_nonces, encode_intent_used, event_topic0, ExecutedLog, TxReceiptView,
    SIG_SPONSORED_ENROLLMENT_EXECUTED,
};
use crate::config::Config;
use crate::stream_g::base_fee;

/// Bound on the RPC round-trip that fills (including the pending-nonce lookup) and
/// broadcasts a transaction, held under `send_lock` (see its doc comment). This is pure
/// request/response latency to the node, not chain confirmation, so it should normally
/// complete in well under a second; 15s gives generous headroom for a slow RPC endpoint
/// without letting one stuck request starve every other signer sharing the lock for long.
const SEND_TX_TIMEOUT: Duration = Duration::from_secs(15);

/// Bound on waiting for the mined receipt — also held under `send_lock` (see its doc
/// comment: FIX ROUND 1 reverted narrowing this out from under the lock, so this
/// constant is no longer just "how long one caller waits," it is the nonce-safety
/// bound for every other signer queued behind it. Read that doc comment before
/// changing this value.
///
/// Base (this service's live target — see `send_native`) runs a single sequencer with
/// Flashblocks-enabled public endpoints, where the `pending` tag updates on a ~200ms
/// cadence rather than synchronously on submission — a prior version of this constant's
/// reasoning (30 blocks of margin at Base Sepolia's ~2s block time) is *not* a safe
/// argument for how long a tx can plausibly stay unmined here, because op-stack
/// sequencers commonly keep an underpriced-but-valid tx alive in their local txpool far
/// longer than any short timeout (txpool `lifetime` is frequently configured in hours,
/// not seconds) before evicting it — it is not necessarily dead just because 60s have
/// passed. 60s is kept for now per the round-1 review, but is a compromise, not a proof
/// of "almost certainly not landing"; see the FIX ROUND 1 entry in
/// the P2 round-1 review for the case to raise this further, which is the
/// founder's call, not this file's.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Bound on **one** JSON-RPC round-trip that only *reads* chain state
/// (`eth_call`, `eth_blockNumber`, `eth_getCode`, `eth_getTransactionReceipt`,
/// `eth_getTransactionCount`, `eth_getLogs`, `eth_chainId`, …).
///
/// # Why this constant has to exist at all
///
/// Every read below builds its provider with
/// `ProviderBuilder::new().connect_http(url)`. alloy's HTTP transport wraps
/// `reqwest::Client::new()`, whose default has **no** connect, read or request
/// timeout — so a node that accepts the TCP connection and then answers
/// nothing leaves the caller parked on `.await` *forever*. That is not a
/// hypothetical: a suspended local anvil reproduces it on demand, and it is
/// the mechanism behind the hazard suite's intermittent ≥1200s stall
/// (`run-full-gate.ps1` STEP 3's "WHERE THE OBSERVED HANG WAS" note, which
/// records the investigation). The harness's own second-source client already
/// sets a 15s `reqwest` timeout, which is exactly why a stall surfaced inside
/// an `RpcChain` read and never inside a harness read.
///
/// # Why a deadline is the right answer here and not a papered-over symptom
///
/// The peer is an **external process reachable only over a socket**. There is
/// no lock to unwind and no ordering to fix inside this crate (a live socket
/// with zero CPU burn is what a stalled peer looks like, not what a deadlock
/// looks like): "the node stopped answering" is a legitimate state of the
/// world, and the only thing this side gets to choose is whether it notices.
/// Without a bound it never notices. **The error must therefore name both the
/// operation and the budget** — see [`with_deadline`] — so the next
/// investigation starts from "`eth_getTransactionReceipt` got no answer in
/// 30s" rather than from a killed process tree.
///
/// # Why 30 seconds
///
/// These are single request/response round-trips carrying no chain wait, so a
/// healthy endpoint answers in milliseconds. 30s is deliberately generous:
/// 2× the 15s the sibling blocking client allows, and half of
/// [`RECEIPT_TIMEOUT`] — comfortably above any plausible slow-but-alive public
/// RPC, while turning a wedged peer into a named error inside one step's
/// budget instead of a watchdog kill 40× later.
const RPC_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Run one JSON-RPC round-trip under `budget`, and on expiry return an error
/// that names **the operation** and **the budget it exceeded**.
///
/// The naming is the point, not decoration. A bare
/// `tokio::time::timeout(..).await?` would turn a wedged node into an
/// anonymous "timed out", which is only marginally better than the hang it
/// replaces; `ChainError` messages in this file already carry operation names
/// (`"eth_getTransactionReceipt"`,
/// `"GoatRelayGateway.secondaryEnrollmentNonceSnapshot"`) and a timeout must
/// not be the one failure mode that drops them.
async fn with_deadline<T, F>(op: &str, budget: Duration, fut: F) -> Result<T, ChainError>
where
    F: std::future::Future<Output = Result<T, ChainError>>,
{
    match tokio::time::timeout(budget, fut).await {
        Ok(inner) => inner,
        Err(_) => Err(ChainError::Msg(format!(
            "{op}: no answer from the node within {budget:?} (RPC read deadline exceeded; \
             the endpoint accepted the request and never replied)"
        ))),
    }
}

/// Role used when selecting which private key signs a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Proposer,
    Watcher,
    Challenger,
    Relayer,
    /// Stream G's dedicated broadcaster EOA. Config already refuses to let
    /// this be the pilot `RELAYER_PRIVATE_KEY`; this variant is the wiring
    /// that makes the refusal mean something at the signer level.
    Broadcaster,
}

/// Live chain client: per-role signers + alloy HTTP.
///
/// Does **not** own a nested `tokio::Runtime`. Owning one broke `serve-relayer`: dropping
/// RpcChain inside the outer `rt.block_on(axum::serve…)` panics with
/// "Cannot drop a runtime in a context where blocking is not allowed".
///
/// - Inside an async runtime (axum handlers): `block_in_place` + current `Handle::block_on`.
/// - Sync CLI (once-propose / run): a **temporary** current-thread runtime per call.
pub struct RpcChain {
    rpc_url: Url,
    epoch_settlement: Address,
    worker_binding: Address,
    enrollment_registry: Address,
    chain_id: u64,
    /// G-B1: start block for Bound log scans (WorkerBinding deploy block).
    worker_binding_deploy_block: u64,
    /// G-B1: max blocks per eth_getLogs page.
    eth_get_logs_chunk: u64,
    proposer_bond_wei: u128,
    challenger_bond_wei: u128,
    /// G-B1 (Stream G edition): start block for
    /// `SponsoredEnrollmentExecuted` log scans (GoatRelayGateway deploy
    /// block). Same unset-pin refusal as `worker_binding_deploy_block`.
    stream_g_gateway_deploy_block: u64,
    proposer: Option<PrivateKeySigner>,
    watcher: Option<PrivateKeySigner>,
    challenger: Option<PrivateKeySigner>,
    relayer: Option<PrivateKeySigner>,
    /// Stream G's dedicated broadcaster key (`STREAM_G_BROADCASTER_PRIVATE_KEY`).
    /// `None` whenever Stream G is disabled — which is the default.
    broadcaster: Option<PrivateKeySigner>,
    /// Serializes an entire send in `send_tx` — provider fill (including the pending
    /// nonce lookup), broadcast, *and* the receipt wait — so nonce fillers do not race
    /// across roles on shared accounts. A fresh `Provider` (and therefore a fresh,
    /// uncached `NonceFiller`) is built per call, so each call queries the node's live
    /// "pending" nonce; transaction N's nonce must be fully resolved on-chain before
    /// transaction N+1 fetches "pending" again, or N+1 can fetch a stale value.
    ///
    /// FIX ROUND 1 (2026-07-20): an earlier version of this fix narrowed the lock to
    /// just the fill+broadcast step, releasing it before the receipt wait, reasoning
    /// that a shared JSON-RPC endpoint's "pending" tag reflects mempool-queued
    /// transactions immediately on broadcast. That reasoning does not hold for this
    /// service's actual deploy target: Base runs a single sequencer with no public
    /// mempool, and its Flashblocks-enabled public endpoints update the `pending` tag on
    /// a ~200ms cadence rather than synchronously — Base's own agent guidance warns that
    /// submitting in quick succession is prone to nonce collisions for exactly this
    /// reason and recommends application-level nonce tracking instead of refetching per
    /// submission (which is this code's pattern). The narrowed window (one RPC
    /// round-trip) was plausibly inside a single Flashblock. Reverted: the lock is wide
    /// again, at the cost of serializing every relayer operation (bind/enroll/gas-drip/
    /// claim) behind whichever send is currently in flight — acceptable at pilot scale
    /// (1-5 testers), where nonce correctness matters far more than throughput.
    ///
    /// Consequence: `RECEIPT_TIMEOUT` (see its doc comment) is no longer just "how long
    /// one caller waits" — it is now the nonce-safety bound for every signer queued
    /// behind this lock, and every other relayer request head-of-line-blocks behind it
    /// too. Do not narrow this again without the same live-anvil-cannot-prove-it caveat
    /// the round-1 review raised: anvil is single-process and auto-mining, the best
    /// possible case, and cannot exercise Flashblock-cadence propagation delay.
    ///
    /// `tokio::sync::Mutex`, taken with `.lock().await` *inside* the async block passed
    /// to `block_on`, so a contended waiter yields to the runtime instead of parking an
    /// OS worker thread. Taking a *blocking* `std::sync::Mutex` outside of `block_on` (the
    /// original P2 bug) blocks the thread before `block_in_place` has told tokio to add
    /// a replacement worker, so every waiter silently eats into the worker pool until the
    /// whole service — including unrelated routes like `/health` — stalls. That part of
    /// the fix is unaffected by round 1: the lock type/placement stays, only its scope
    /// widened back out.
    send_lock: Mutex<()>,
    /// Budget for one *read* round-trip — always [`RPC_READ_TIMEOUT`] in
    /// production (`from_config` is the only constructor and hard-codes it).
    ///
    /// A field rather than a bare constant reference at each call site so that
    /// [`Self::with_read_timeout`] can shrink it under test. Without that, the
    /// regression test proving the deadline actually fires would have to spend
    /// the full production budget wall-clock, and a 30-second unit test is a
    /// test people delete.
    read_timeout: Duration,
}

/// Every field of one EIP-1559 transaction that
/// [`RpcChain::sign_broadcaster_eip1559`] does not derive for itself.
///
/// A named-field struct rather than six positional parameters, for the reason
/// `stream_g::base_fee`'s newtypes and `stream_g::direct_eth::EncodeArgs`
/// already record in this tree: `gas_limit`/`nonce` are both `u64` and
/// `max_fee_per_gas`/`max_priority_fee_per_gas` are both `u128`, so a
/// positional call has two transposable pairs and both transpositions compile.
/// `value` is deliberately **absent**, not defaulted — see the method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip1559Request {
    /// `to`. Contract-call only: this type cannot express a contract creation.
    pub to: [u8; 20],
    /// The signer's transaction nonce. Supplied, never filled — see the
    /// method doc.
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub calldata: Vec<u8>,
}

/// The output of [`RpcChain::sign_broadcaster_eip1559`]: the EIP-2718 bytes
/// that go on the wire, the hash a node will report for them, and the address
/// they recover to.
///
/// Fields are private with accessors so that `raw` and `hash` cannot be set
/// independently by anything outside this module — the whole value of the
/// pair is that the hash names *these* bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEip1559 {
    raw: Vec<u8>,
    hash: TxHash,
    from: [u8; 20],
}

impl SignedEip1559 {
    /// The EIP-2718 typed-transaction bytes (`0x02 || rlp([...])`), exactly as
    /// `eth_sendRawTransaction` wants them.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// `keccak256(raw)` — the transaction hash.
    pub fn hash(&self) -> TxHash {
        self.hash
    }

    /// The signing EOA's 20 address bytes. Returned so a caller can assert the
    /// key it got is the account it planned against, rather than assuming it.
    pub fn from(&self) -> [u8; 20] {
        self.from
    }

    /// Consume into the raw bytes.
    pub fn into_raw(self) -> Vec<u8> {
        self.raw
    }
}

impl RpcChain {
    pub fn from_config(cfg: &Config) -> Result<Self, ChainError> {
        let rpc_url =
            Url::parse(&cfg.rpc_url).map_err(|e| ChainError::Msg(format!("RPC_URL parse: {e}")))?;
        let epoch_settlement = parse_alloy_address(&cfg.epoch_settlement_address)?;
        let worker_binding = parse_alloy_address(&cfg.worker_binding_address)?;
        let enrollment_registry = parse_alloy_address(&cfg.enrollment_registry_address)?;

        Ok(Self {
            rpc_url,
            epoch_settlement,
            worker_binding,
            enrollment_registry,
            chain_id: cfg.chain_id,
            worker_binding_deploy_block: cfg.worker_binding_deploy_block,
            eth_get_logs_chunk: cfg.eth_get_logs_chunk.max(1),
            proposer_bond_wei: cfg.proposer_bond_wei,
            challenger_bond_wei: cfg.challenger_bond_wei,
            proposer: parse_key_opt(cfg.proposer_private_key.as_deref())?,
            watcher: parse_key_opt(cfg.watcher_private_key.as_deref())?,
            challenger: parse_key_opt(cfg.challenger_private_key.as_deref())?,
            relayer: parse_key_opt(cfg.relayer_private_key.as_deref())?,
            broadcaster: parse_key_opt(cfg.stream_g.broadcaster_private_key.as_deref())?,
            stream_g_gateway_deploy_block: cfg.stream_g.gateway_deploy_block,
            send_lock: Mutex::new(()),
            read_timeout: RPC_READ_TIMEOUT,
        })
    }

    /// Shrink the read deadline (see [`Self::read_timeout`]). **Test-only** —
    /// production always runs [`RPC_READ_TIMEOUT`].
    #[cfg(test)]
    pub(crate) fn with_read_timeout(mut self, budget: Duration) -> Self {
        self.read_timeout = budget;
        self
    }

    fn block_on<T>(&self, fut: impl std::future::Future<Output = T>) -> T {
        match tokio::runtime::Handle::try_current() {
            // Already on a runtime (axum serve-relayer): never create/drop a nested Runtime.
            Ok(handle) => tokio::task::block_in_place(|| handle.block_on(fut)),
            // Sync CLI path: short-lived runtime for this call only, dropped after return.
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio current_thread runtime");
                rt.block_on(fut)
            }
        }
    }

    fn signer(&self, role: Role) -> Result<&PrivateKeySigner, ChainError> {
        let (slot, name) = match role {
            Role::Proposer => (&self.proposer, "PROPOSER_PRIVATE_KEY"),
            Role::Watcher => (&self.watcher, "WATCHER_PRIVATE_KEY"),
            Role::Challenger => (&self.challenger, "CHALLENGER_PRIVATE_KEY"),
            Role::Relayer => (&self.relayer, "RELAYER_PRIVATE_KEY"),
            Role::Broadcaster => (&self.broadcaster, "STREAM_G_BROADCASTER_PRIVATE_KEY"),
        };
        slot.as_ref()
            .ok_or_else(|| ChainError::Msg(format!("missing {name} for live RPC")))
    }

    /// Address of Stream G's dedicated broadcaster EOA, `0x`-prefixed.
    ///
    /// The outbox needs this to ask for its own nonce frontier
    /// (`transaction_count`) and to sign raw transactions; exposing the
    /// address is deliberately the only thing that leaves this type. Errors
    /// with the env var's name when `STREAM_G_BROADCASTER_PRIVATE_KEY` is
    /// unset, which is the default (Stream G disabled).
    pub fn broadcaster_address(&self) -> Result<String, ChainError> {
        let signer = self.signer(Role::Broadcaster)?;
        Ok(signer.address().to_string())
    }

    /// The same address as [`Self::broadcaster_address`], as **raw bytes**.
    ///
    /// Not a convenience. [`Self::broadcaster_address`] returns alloy's EIP-55
    /// *checksummed* rendering, and `stream_g::broadcaster::address_hex`'s doc
    /// records what happens when that string reaches a store column that
    /// elsewhere holds a lowercase one: the same account's nonce sequence
    /// silently splits in two. Every consumer that needs the account's
    /// identity rather than a label should take these 20 bytes and format them
    /// itself.
    pub fn broadcaster_address_bytes(&self) -> Result<[u8; 20], ChainError> {
        Ok(self.signer(Role::Broadcaster)?.address().into_array())
    }

    /// `gas_limit`: `None` lets alloy's `GasFiller` estimate via `eth_estimateGas` against
    /// `to` (required for contract calls, which legitimately need far more than 21,000 gas
    /// and whose `to` is a known, trusted contract). `Some(n)` pins the limit and skips
    /// estimation entirely — used by `send_native`, where `to` is caller-supplied and
    /// therefore untrusted; see call site for why 21,000 is the correct, deliberately
    /// insufficient value for a plain value transfer.
    fn send_tx(
        &self,
        role: Role,
        to: Address,
        value: U256,
        calldata: Vec<u8>,
        gas_limit: Option<u64>,
    ) -> Result<TxHash, ChainError> {
        let signer = self.signer(role)?.clone();
        let url = self.rpc_url.clone();
        let chain_id = self.chain_id;

        self.block_on(async move {
            let mut tx = TransactionRequest::default()
                .with_to(to)
                .with_value(value)
                .with_input(Bytes::from(calldata));
            if let Some(gas_limit) = gas_limit {
                tx = tx.with_gas_limit(gas_limit);
            }
            if chain_id != 0 {
                tx = tx.with_chain_id(chain_id);
            }

            // FIX ROUND 1: held across fill+broadcast *and* the receipt wait (see
            // `send_lock` doc comment) — every other relayer call (bind/enroll/gas-drip/
            // claim) queues behind this one until it resolves. A caller whose own
            // request is not the one sending experiences this as ordinary added
            // latency; if `RECEIPT_TIMEOUT` fires, the guard is dropped (below) and the
            // next-queued caller proceeds, but the timed-out send itself surfaces as a
            // plain `ChainError` to its own caller — see `send_native`'s call site in
            // `relayer.rs` for why that must stay indistinguishable from any other send
            // failure (G4: quota already reserved stays consumed, no refund on timeout).
            let _guard = self.send_lock.lock().await;
            let provider = ProviderBuilder::new().wallet(signer).connect_http(url);

            let pending = tokio::time::timeout(SEND_TX_TIMEOUT, provider.send_transaction(tx))
                .await
                .map_err(|_| {
                    ChainError::Msg(format!(
                        "send_transaction timed out after {SEND_TX_TIMEOUT:?}"
                    ))
                })?
                .map_err(|e| ChainError::Msg(format!("send_transaction: {e}")))?;

            let receipt = tokio::time::timeout(RECEIPT_TIMEOUT, pending.get_receipt())
                .await
                .map_err(|_| {
                    ChainError::Msg(format!("get_receipt timed out after {RECEIPT_TIMEOUT:?}"))
                })?
                .map_err(|e| ChainError::Msg(format!("get_receipt: {e}")))?;

            if !receipt.status() {
                return Err(ChainError::Msg(format!(
                    "transaction reverted: 0x{}",
                    hex::encode(receipt.transaction_hash)
                )));
            }

            let h = receipt.transaction_hash;
            Ok(h.0)
        })
    }

    /// Sign one EIP-1559 transaction with the **Stream G broadcaster key** and
    /// return the raw bytes — **without sending it anywhere**.
    ///
    /// # Why this is a separate method and not a flag on [`Self::send_tx`]
    ///
    /// `send_tx` builds a wallet-bearing alloy `Provider` and calls
    /// `provider.send_transaction(..)`, which fills, signs *and* broadcasts in
    /// one round-trip: the raw signed payload never surfaces to the caller and
    /// the nonce is chosen by alloy's `NonceFiller` from `eth_getTransactionCount`
    /// at send time. Stream G's outbox needs the exact opposite of both halves —
    /// it **persists the raw transaction before broadcast**
    /// (`outbox::reserve_persist_and_send`, test
    /// `raw_tx_is_persisted_before_broadcast`) and it allocates the EOA nonce
    /// itself, durably and contiguously
    /// (`stream_g::broadcaster::allocate_broadcaster_nonce`). A signer that
    /// picked its own nonce would void that contiguity guarantee outright.
    ///
    /// So this method does **no** filling, no estimation and no RPC of any
    /// kind: every field is supplied by the caller and the signature is
    /// produced locally.
    ///
    /// # No runtime, no `block_on`
    ///
    /// Deliberately **not** `async` and deliberately not routed through
    /// [`Self::block_on`]. `alloy::network::TxSignerSync::sign_transaction_sync`
    /// is a synchronous local ECDSA signature over
    /// `keccak256(0x02 || rlp(unsigned fields))`; it touches no network and no
    /// executor. That matters beyond tidiness: `block_on` uses
    /// `tokio::task::block_in_place`, which **panics** on a current-thread
    /// runtime, so every caller of a `block_on`-based signer would have to be
    /// on a multi-thread runtime. This one has no such requirement.
    ///
    /// # Refusals (fail closed, before any bytes exist)
    ///
    /// * `chain_id == 0` — an EIP-1559 transaction has no "unset" chain id;
    ///   `send_tx` may omit `with_chain_id` and let alloy fill it, but there is
    ///   nothing here to fill it from, and signing a payload with chain id 0
    ///   would produce a transaction replayable wherever it is accepted.
    /// * `max_priority_fee_per_gas > max_fee_per_gas` — invalid per EIP-1559;
    ///   every node rejects it. Refusing locally means the caller's pre-send
    ///   failure arm runs (which releases the EOA nonce) instead of a live
    ///   payload existing that nothing will ever mine.
    ///
    /// # 🔴 The signed chain id is the **configured** one, unverified
    ///
    /// `self.chain_id` is `CHAIN_ID` from config, exactly as `send_tx` uses it.
    /// Nothing here checks it against a live `eth_chainId`, so if the endpoint
    /// this process is pointed at is a different chain than `CHAIN_ID` says,
    /// this method signs a valid transaction **for the wrong chain** and the
    /// node will simply reject it. That is not a new hazard introduced here —
    /// [`ChainClient::chain_id`]'s doc records the deliberate split between the
    /// configured value and the live round-trip, and the live read is what
    /// `stream_g::token_manifest`'s gate uses. It is a hazard this method does
    /// not close, and no caller in this crate closes it for the signing path
    /// today.
    pub fn sign_broadcaster_eip1559(
        &self,
        req: &Eip1559Request,
    ) -> Result<SignedEip1559, ChainError> {
        let signer = self.signer(Role::Broadcaster)?;

        if self.chain_id == 0 {
            return Err(ChainError::Msg(
                "refusing to sign an EIP-1559 transaction with CHAIN_ID=0: the chain id is a \
                 signed field, and 0 signs a transaction that is replayable on any chain that \
                 accepts it"
                    .to_string(),
            ));
        }
        if req.max_priority_fee_per_gas > req.max_fee_per_gas {
            return Err(ChainError::Msg(format!(
                "max_priority_fee_per_gas ({}) exceeds max_fee_per_gas ({}); EIP-1559 forbids \
                 this and every node rejects it",
                req.max_priority_fee_per_gas, req.max_fee_per_gas
            )));
        }

        let mut tx = TxEip1559 {
            chain_id: self.chain_id,
            nonce: req.nonce,
            gas_limit: req.gas_limit,
            max_fee_per_gas: req.max_fee_per_gas,
            max_priority_fee_per_gas: req.max_priority_fee_per_gas,
            to: TxKind::Call(Address::from(req.to)),
            // `executeSponsoredEnrollment` is not `payable`
            // (`GoatRelayGateway.sol:329-340`) — see `stream_g::direct_eth`'s
            // module doc. Any non-zero value reverts on the compiler-generated
            // non-payable guard, so this field is not a parameter.
            value: U256::ZERO,
            access_list: Default::default(),
            input: Bytes::from(req.calldata.clone()),
        };

        let signature = signer
            .sign_transaction_sync(&mut tx)
            .map_err(|e| ChainError::Msg(format!("sign_transaction_sync: {e}")))?;
        let from = signer.address();
        let signed = tx.into_signed(signature);
        // `Signed::hash()` is `keccak256` of exactly the EIP-2718 bytes below,
        // which is the transaction hash a node will report. Taken from alloy
        // rather than recomputed so the two cannot drift; `SignedRawTx::new`
        // recomputes it from `raw` and
        // `stream_g::broadcaster::tests::the_outbox_hash_is_the_real_transaction_hash`
        // pins that the two agree.
        let hash = *signed.hash();
        let raw = signed.encoded_2718();

        Ok(SignedEip1559 {
            raw,
            hash: hash.0,
            from: from.into_array(),
        })
    }

    /// **Test-only.** The `CHAIN_ID` *config* value this struct holds — i.e.
    /// exactly the thing [`ChainClient::chain_id`] must **not** return.
    ///
    /// Exists so the Stream G Anvil harness
    /// (`stream_g::anvil_harness`) can state its precondition from outside
    /// this module: it configures 84532, points the client at a node that is
    /// 31337, and needs to assert that an `Ok(self.chain_id)` implementation
    /// really would have answered 84532. Without this the positive arm could
    /// only say "we passed 84532 in", which is one indirection weaker.
    /// Never compiled into a release build.
    #[cfg(test)]
    pub(crate) fn configured_chain_id(&self) -> u64 {
        self.chain_id
    }

    fn eth_call(&self, to: Address, calldata: Vec<u8>) -> Result<Bytes, ChainError> {
        let url = self.rpc_url.clone();
        let budget = self.read_timeout;
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            let tx = TransactionRequest::default()
                .with_to(to)
                .with_input(Bytes::from(calldata));
            with_deadline(&format!("eth_call {to}"), budget, async {
                provider
                    .call(tx)
                    .await
                    .map_err(|e| ChainError::Msg(format!("eth_call: {e}")))
            })
            .await
        })
    }

    /// `eth_call` pinned to an explicit block number rather than `"latest"`
    /// (Stream G G1, live-chain sourcing contract §3 R4). Reading `"latest"`
    /// once per value lets a reorg or a config upsert land between two reads,
    /// so the token-capability gate can authorize one chain state while the
    /// quote commits to another.
    fn eth_call_at_block(
        &self,
        to: Address,
        calldata: Vec<u8>,
        block: u64,
    ) -> Result<Bytes, ChainError> {
        let url = self.rpc_url.clone();
        let budget = self.read_timeout;
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            let tx = TransactionRequest::default()
                .with_to(to)
                .with_input(Bytes::from(calldata));
            with_deadline(&format!("eth_call {to} @ block {block}"), budget, async {
                provider
                    .call(tx)
                    .number(block)
                    .await
                    .map_err(|e| ChainError::Msg(format!("eth_call @ block {block}: {e}")))
            })
            .await
        })
    }
}

impl ChainClient for RpcChain {
    fn propose_batch(
        &self,
        epoch: u64,
        merkle_root: [u8; 32],
        evidence_ref: [u8; 32],
        bond_wei: u128,
    ) -> Result<TxHash, ChainError> {
        if bond_wei != self.proposer_bond_wei {
            return Err(ChainError::BondMismatch {
                expected: self.proposer_bond_wei,
                got: bond_wei,
            });
        }
        let data = encode_propose_batch(epoch, merkle_root, evidence_ref);
        self.send_tx(
            Role::Proposer,
            self.epoch_settlement,
            U256::from(bond_wei),
            data,
            None,
        )
    }

    fn challenge_batch(
        &self,
        epoch: u64,
        counter_evidence_ref: [u8; 32],
        bond_wei: u128,
    ) -> Result<TxHash, ChainError> {
        if bond_wei != self.challenger_bond_wei {
            return Err(ChainError::BondMismatch {
                expected: self.challenger_bond_wei,
                got: bond_wei,
            });
        }
        let data = encode_challenge_batch(epoch, counter_evidence_ref);
        self.send_tx(
            Role::Challenger,
            self.epoch_settlement,
            U256::from(bond_wei),
            data,
            None,
        )
    }

    fn confirm_epoch(&self, epoch: u64) -> Result<TxHash, ChainError> {
        let data = encode_confirm_epoch(epoch);
        self.send_tx(Role::Watcher, self.epoch_settlement, U256::ZERO, data, None)
    }

    fn get_batch(&self, epoch: u64) -> Result<BatchView, ChainError> {
        let data = encode_batches(epoch);
        let out = self.eth_call(self.epoch_settlement, data)?;
        decode_batch_return(out.as_ref())
    }

    fn bind_with_signature(
        &self,
        wallet: [u8; 20],
        username: &str,
        deadline: u64,
        signature: &[u8],
    ) -> Result<TxHash, ChainError> {
        let data = encode_bind_with_signature(wallet, username, deadline, signature);
        self.send_tx(Role::Relayer, self.worker_binding, U256::ZERO, data, None)
    }

    fn enroll_self_with_signature(
        &self,
        wallet: [u8; 20],
        deadline: u64,
        signature: &[u8],
    ) -> Result<TxHash, ChainError> {
        let data = encode_enroll_self_with_signature(wallet, deadline, signature);
        self.send_tx(
            Role::Relayer,
            self.enrollment_registry,
            U256::ZERO,
            data,
            None,
        )
    }

    fn binding_nonce(&self, wallet: &str) -> Result<u64, ChainError> {
        let addr20 = parse_address20(wallet)?;
        let data = encode_nonces(addr20);
        let out = self.eth_call(self.worker_binding, data)?;
        decode_nonce_u64(out.as_ref())
    }

    fn enrollment_nonce(&self, wallet: &str) -> Result<u64, ChainError> {
        let addr20 = parse_address20(wallet)?;
        let data = encode_nonces(addr20);
        let out = self.eth_call(self.enrollment_registry, data)?;
        decode_nonce_u64(out.as_ref())
    }

    fn has_baseline(&self, wallet: &str) -> Result<Option<bool>, ChainError> {
        let addr20 = parse_address20(wallet)?;
        let data = encode_has_baseline(addr20);
        let out = self.eth_call(self.epoch_settlement, data)?;
        if out.is_empty() {
            return Ok(None);
        }
        // bool ABI: last byte of 32-byte word
        let word = if out.len() >= 32 {
            &out[out.len() - 32..]
        } else {
            out.as_ref()
        };
        let flag = word.iter().any(|&b| b != 0);
        Ok(Some(flag))
    }

    fn last_claimed_cumulative(&self, wallet: &str) -> Result<Option<u128>, ChainError> {
        let addr20 = parse_address20(wallet)?;
        let data = encode_last_claimed_cumulative(addr20);
        let out = self.eth_call(self.epoch_settlement, data)?;
        if out.is_empty() {
            return Ok(None);
        }
        let word = if out.len() >= 32 {
            &out[out.len() - 32..]
        } else {
            return Ok(None);
        };
        Ok(Some(u128_from_word(word)?))
    }

    fn finalize_batch(&self, epoch: u64) -> Result<TxHash, ChainError> {
        // Anyone may finalize after window; try watcher then proposer (both funded in lab).
        let data = encode_finalize_batch(epoch);
        match self.send_tx(
            Role::Watcher,
            self.epoch_settlement,
            U256::ZERO,
            data.clone(),
            None,
        ) {
            Ok(h) => Ok(h),
            Err(_) => self.send_tx(
                Role::Proposer,
                self.epoch_settlement,
                U256::ZERO,
                data,
                None,
            ),
        }
    }

    fn claim_payout(
        &self,
        epoch: u64,
        worker: [u8; 20],
        proven_score: u128,
        proof: &[[u8; 32]],
    ) -> Result<TxHash, ChainError> {
        let data = encode_claim_payout(epoch, worker, proven_score, proof);
        // Permissionless — relayer/proposer pays gas for pilot auto-claim.
        match self.send_tx(
            Role::Relayer,
            self.epoch_settlement,
            U256::ZERO,
            data.clone(),
            None,
        ) {
            Ok(h) => Ok(h),
            Err(_) => self.send_tx(
                Role::Proposer,
                self.epoch_settlement,
                U256::ZERO,
                data,
                None,
            ),
        }
    }

    fn increase_time(&self, seconds: u64) -> Result<(), ChainError> {
        if seconds == 0 {
            return Ok(());
        }
        let url = self.rpc_url.clone();
        let budget = self.read_timeout;
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            // anvil_increaseTime
            with_deadline("anvil_increaseTime", budget, async {
                let _: serde_json::Value = provider
                    .raw_request("anvil_increaseTime".into(), [serde_json::json!(seconds)])
                    .await
                    .map_err(|e| ChainError::Msg(format!("anvil_increaseTime: {e}")))?;
                Ok(())
            })
            .await?;
            with_deadline("anvil_mine", budget, async {
                let _: serde_json::Value = provider
                    .raw_request("anvil_mine".into(), [serde_json::json!(1)])
                    .await
                    .map_err(|e| ChainError::Msg(format!("anvil_mine: {e}")))?;
                Ok(())
            })
            .await
        })
    }

    fn block_timestamp(&self) -> Result<u64, ChainError> {
        let url = self.rpc_url.clone();
        let budget = self.read_timeout;
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            let block = with_deadline("eth_getBlockByNumber(latest)", budget, async {
                provider
                    .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
                    .await
                    .map_err(|e| ChainError::Msg(format!("eth_getBlock: {e}")))
            })
            .await?
            .ok_or_else(|| ChainError::Msg("latest block missing".into()))?;
            Ok(block.header.timestamp)
        })
    }

    /// `eth_getBlockByNumber(block).timestamp` — the pinned-block sibling of
    /// [`Self::block_timestamp`] (Task 8 Mandate 3).
    ///
    /// Deliberately `BlockNumberOrTag::Number(block)` and not `Latest`: the
    /// whole point is that the clock comes from the SAME block the state
    /// reads were pinned to. A block the node cannot serve (pruned, or ahead
    /// of its head) is an `Err`, never a 0 — see the trait doc.
    fn block_timestamp_at(&self, block: u64) -> Result<u64, ChainError> {
        let url = self.rpc_url.clone();
        let budget = self.read_timeout;
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            let b = with_deadline(&format!("eth_getBlockByNumber({block})"), budget, async {
                provider
                    .get_block_by_number(alloy::eips::BlockNumberOrTag::Number(block))
                    .await
                    .map_err(|e| ChainError::Msg(format!("eth_getBlockByNumber({block}): {e}")))
            })
            .await?
            .ok_or_else(|| {
                ChainError::Msg(format!(
                    "eth_getBlockByNumber({block}): node has no such block"
                ))
            })?;
            Ok(b.header.timestamp)
        })
    }

    fn list_bound_workers(&self) -> Result<Vec<BoundWorker>, ChainError> {
        // G-B1: never scan from genesis on a live L2. Anvil (31337) may use deploy
        // block 0; every other chain requires WORKER_BINDING_DEPLOY_BLOCK.
        let from = self.worker_binding_deploy_block;
        if self.chain_id != 31337 && from == 0 {
            return Err(ChainError::Msg(
                "G-B1: WORKER_BINDING_DEPLOY_BLOCK must be set (WorkerBinding create block) \
                 on non-anvil chains; refusing eth_getLogs from block 0"
                    .into(),
            ));
        }
        let url = self.rpc_url.clone();
        let binding = self.worker_binding;
        let chunk = self.eth_get_logs_chunk.max(1);
        // WorkerBinding.Bound(address indexed wallet, string username)
        let topic0: B256 = keccak256(b"Bound(address,string)");
        let budget = self.read_timeout;
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            let latest = with_deadline("eth_blockNumber", budget, async {
                provider
                    .get_block_number()
                    .await
                    .map_err(|e| ChainError::Msg(format!("eth_blockNumber: {e}")))
            })
            .await?;
            if from > latest {
                tracing::warn!(
                    from,
                    latest,
                    "WORKER_BINDING_DEPLOY_BLOCK is past latest head; Bound list empty"
                );
                return Ok(Vec::new());
            }
            let ranges = block_log_ranges(from, latest, chunk);
            tracing::debug!(
                from,
                latest,
                chunk,
                pages = ranges.len(),
                "list_bound_workers paged eth_getLogs"
            );
            let mut ordered = Vec::new();
            for (page_from, page_to) in ranges {
                let filter = Filter::new()
                    .address(binding)
                    .event_signature(topic0)
                    .from_block(page_from)
                    .to_block(page_to);
                // Per PAGE, not per scan: each page is one request, so a
                // 4,000-page backfill gets 4,000 chances to answer within
                // budget rather than one deadline covering all of them.
                let logs = with_deadline(
                    &format!("eth_getLogs Bound [{page_from},{page_to}]"),
                    budget,
                    async {
                        provider.get_logs(&filter).await.map_err(|e| {
                            ChainError::Msg(format!(
                                "eth_getLogs Bound [{page_from},{page_to}]: {e}"
                            ))
                        })
                    },
                )
                .await?;
                for log in logs {
                    let topics = log.topics();
                    if topics.len() < 2 {
                        continue;
                    }
                    // topic1 = left-padded address
                    let wallet_bytes = &topics[1].as_slice()[12..];
                    let wallet = format!("0x{}", hex::encode(wallet_bytes));
                    let username = decode_abi_string(log.data().data.as_ref()).unwrap_or_default();
                    if username.is_empty() {
                        continue;
                    }
                    ordered.push(BoundWorker { wallet, username });
                }
            }
            // Chronological pages → last Bound wins per wallet.
            Ok(merge_bound_workers_last_wins(ordered))
        })
    }

    fn eth_balance(&self, wallet: &str) -> Result<u128, ChainError> {
        let address = parse_alloy_address(wallet)?;
        let url = self.rpc_url.clone();
        let budget = self.read_timeout;
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            let balance = with_deadline(&format!("eth_getBalance({address})"), budget, async {
                provider
                    .get_balance(address)
                    .await
                    .map_err(|e| ChainError::Msg(format!("get_balance: {e}")))
            })
            .await?;
            u128_from_word(&balance.to_be_bytes::<32>())
        })
    }

    fn gas_price(&self) -> Result<u128, ChainError> {
        let url = self.rpc_url.clone();
        let budget = self.read_timeout;
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            with_deadline("eth_gasPrice", budget, async {
                provider
                    .get_gas_price()
                    .await
                    .map_err(|e| ChainError::Msg(format!("get_gas_price: {e}")))
            })
            .await
        })
    }

    fn send_native(&self, to: &str, amount_wei: u128) -> Result<TxHash, ChainError> {
        // Plain value transfer — empty calldata, relayer pays gas (matches
        // bind/enroll's relayer-funded pattern via `send_tx`).
        //
        // Gas limit is pinned to 21,000 (the intrinsic cost of a value transfer to an
        // EOA) rather than left to `eth_estimateGas`. Unlike bind/enroll, `to` here is
        // supplied by an unauthenticated caller (the gas-drip endpoint), not a known
        // contract — `GAS_DRIP_MAX_WEI` caps the wei transferred but does nothing to cap
        // gas if `to` is a contract with an expensive `receive()`/`fallback()`, which
        // would otherwise let an attacker-chosen recipient set the operator's gas spend
        // up to the block gas limit. Pinning 21,000 is deliberately *insufficient* for
        // any such contract recipient, so the transfer reverts fast and cheap instead of
        // burning attacker-chosen gas — that's the intended behaviour, not a bug. This
        // does not affect correctness for a normal EOA recipient, which needs exactly
        // 21,000 gas. (On OP Stack chains, e.g. Base Sepolia, the L1 data-availability
        // fee is billed separately from `gas_limit` — this is an empty-calldata transfer,
        // so there is no calldata to inflate that fee either.)
        let to_addr = parse_alloy_address(to)?;
        self.send_tx(
            Role::Relayer,
            to_addr,
            U256::from(amount_wei),
            Vec::new(),
            Some(21_000),
        )
    }

    fn erc20_balance_of(&self, token: &str, wallet: &str) -> Result<u128, ChainError> {
        let token_addr = parse_alloy_address(token)?;
        let wallet20 = parse_address20(wallet)?;
        let data = encode_erc20_balance_of(wallet20);
        let out = self.eth_call(token_addr, data)?;
        if out.len() < 32 {
            return Err(ChainError::Msg(format!(
                "balanceOf() return too short: {} bytes (need 32)",
                out.len()
            )));
        }
        let word = &out[out.len() - 32..];
        u128_from_word(word)
    }

    /// Derived from the relayer role's own signer (same key `send_native` /
    /// `bind_with_signature` sign with) — no separate config needed.
    fn relayer_address(&self) -> Result<String, ChainError> {
        let signer = self.signer(Role::Relayer)?;
        Ok(signer.address().to_string())
    }

    /// `GasPriceOracle.getL1Fee(bytes)` (Base fee decomposition, hazard 1 —
    /// see `stream_g::base_fee` module doc for the real-vs-mock signature
    /// divergence and the "claims ≤ code" honesty note: this has not been
    /// validated against a real Base network).
    fn gas_oracle_l1_fee(&self, unsigned_tx: &[u8]) -> Result<u128, ChainError> {
        let to = Address::from(base_fee::GAS_PRICE_ORACLE_ADDRESS);
        let data = base_fee::encode_get_l1_fee(unsigned_tx);
        let out = self.eth_call(to, data)?;
        decode_gas_oracle_u256(out.as_ref(), "getL1Fee")
    }

    /// `GasPriceOracle.getL1FeeUpperBound(uint256)` (Base fee decomposition,
    /// hazard 1). Real predeploy signature takes a tx SIZE, not calldata —
    /// see `stream_g::base_fee` module doc.
    fn gas_oracle_l1_fee_upper_bound(&self, unsigned_tx_size: u64) -> Result<u128, ChainError> {
        let to = Address::from(base_fee::GAS_PRICE_ORACLE_ADDRESS);
        let data = base_fee::encode_get_l1_fee_upper_bound(unsigned_tx_size);
        let out = self.eth_call(to, data)?;
        decode_gas_oracle_u256(out.as_ref(), "getL1FeeUpperBound")
    }

    /// `GasPriceOracle.getOperatorFee(uint256)` (Base fee decomposition,
    /// hazard 1).
    fn gas_oracle_operator_fee(&self, gas_limit: u64) -> Result<u128, ChainError> {
        let to = Address::from(base_fee::GAS_PRICE_ORACLE_ADDRESS);
        let data = base_fee::encode_get_operator_fee(gas_limit);
        let out = self.eth_call(to, data)?;
        decode_gas_oracle_u256(out.as_ref(), "getOperatorFee")
    }

    // -- Stream G G1 live-chain sourcing (Task 6 Wave A) ------------------
    //
    // All five contract reads below go through `eth_call_at_block`, and the
    // code read goes through a block-pinned `eth_getCode`, so a caller that
    // takes one `pinned_block_number()` and passes it to all of them gets a
    // single-chain-state view (contract §3 R4). Nothing here validates the
    // returned values against a manifest — that is R2/R3's job at the call
    // site, and deliberately not this layer's.

    /// `eth_getCode(token, block)` → `keccak256(code)` (contract §3 R1).
    /// Empty code fails closed via [`code_hash_from_get_code`].
    fn fee_token_code_hash(&self, token: [u8; 20], block: u64) -> Result<[u8; 32], ChainError> {
        let addr = Address::from(token);
        let url = self.rpc_url.clone();
        let budget = self.read_timeout;
        let code =
            self.block_on(async move {
                let provider = ProviderBuilder::new().connect_http(url);
                with_deadline(
                    &format!("eth_getCode {addr} @ block {block}"),
                    budget,
                    async {
                        provider.get_code_at(addr).number(block).await.map_err(|e| {
                            ChainError::Msg(format!("eth_getCode @ block {block}: {e}"))
                        })
                    },
                )
                .await
            })?;
        code_hash_from_get_code(code.as_ref())
    }

    /// `FeeTokenRegistry.getTokenConfig(address)` at `block`.
    fn fee_token_config(
        &self,
        registry: [u8; 20],
        token: [u8; 20],
        block: u64,
    ) -> Result<FeeTokenConfigView, ChainError> {
        let data = encode_get_token_config(token);
        let out = self.eth_call_at_block(Address::from(registry), data, block)?;
        decode_fee_token_config_return(out.as_ref())
    }

    /// `FeeTokenRegistry.getTokenConfigHash(address)` at `block`.
    fn fee_token_config_hash(
        &self,
        registry: [u8; 20],
        token: [u8; 20],
        block: u64,
    ) -> Result<[u8; 32], ChainError> {
        let data = encode_get_token_config_hash(token);
        let out = self.eth_call_at_block(Address::from(registry), data, block)?;
        decode_bytes32_return(out.as_ref(), "getTokenConfigHash")
    }

    /// `FeeTokenRegistry.activeManifestHash()` at `block`.
    fn active_manifest_hash(&self, registry: [u8; 20], block: u64) -> Result<[u8; 32], ChainError> {
        let data = encode_active_manifest_hash();
        let out = self.eth_call_at_block(Address::from(registry), data, block)?;
        decode_bytes32_return(out.as_ref(), "activeManifestHash")
    }

    /// `GoatRelayGateway.secondaryEnrollmentNonceSnapshot(address,address,address)`
    /// at `block` — ONE call, so the nonces it returns are same-state
    /// (contract §3 R3). Advisory only: it reserves nothing (§3 R5).
    fn secondary_enrollment_nonce_snapshot(
        &self,
        gateway: [u8; 20],
        root: [u8; 20],
        secondary: [u8; 20],
        fee_token: [u8; 20],
        block: u64,
    ) -> Result<NonceSnapshotView, ChainError> {
        let data = encode_secondary_enrollment_nonce_snapshot(root, secondary, fee_token);
        let out = self.eth_call_at_block(Address::from(gateway), data, block)?;
        decode_nonce_snapshot_return(out.as_ref())
    }

    /// `eth_blockNumber` — the block to pin every read above to (§3 R4).
    fn pinned_block_number(&self) -> Result<u64, ChainError> {
        let url = self.rpc_url.clone();
        let budget = self.read_timeout;
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            with_deadline("eth_blockNumber", budget, async {
                provider
                    .get_block_number()
                    .await
                    .map_err(|e| ChainError::Msg(format!("eth_blockNumber: {e}")))
            })
            .await
        })
    }

    /// `eth_chainId` — a **live round-trip to the node**, deliberately NOT
    /// `self.chain_id` (the `CHAIN_ID` config value this struct already
    /// holds, used only to stamp outgoing transactions in `send_tx`).
    ///
    /// Returning the configured field here would compile, would look
    /// correct, and would silently re-create the degenerate comparison this
    /// read exists to remove: `token_manifest` already checks the manifest's
    /// chain id against the configured one, so a config-sourced answer makes
    /// gate check 3 self-referential again, one indirection further out. The
    /// question this method answers is "which chain is the endpoint we are
    /// actually talking to on?", and only the endpoint can answer it.
    ///
    /// Issued as a `raw_request` rather than alloy's `get_chain_id()`
    /// helper so the hex-QUANTITY decode is a pure function
    /// ([`decode_eth_chain_id_result`]) that can be pinned by test over
    /// hand-built response bytes. Six sibling `RpcChain` reads have no
    /// coverage precisely because their decode is buried inside alloy and
    /// needs a live node to reach; this one does not have to join them.
    fn chain_id(&self) -> Result<u64, ChainError> {
        let url = self.rpc_url.clone();
        let budget = self.read_timeout;
        let raw: serde_json::Value = self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            with_deadline("eth_chainId", budget, async {
                provider
                    .raw_request("eth_chainId".into(), Vec::<serde_json::Value>::new())
                    .await
                    .map_err(|e| ChainError::Msg(format!("eth_chainId: {e}")))
            })
            .await
        })?;
        decode_eth_chain_id_result(&raw)
    }

    // -----------------------------------------------------------------
    // Stream G G1 — outbox / broadcaster / reconcile (Task 7 Wave A).
    // -----------------------------------------------------------------

    /// `eth_sendRawTransaction` — **non-blocking on purpose**.
    ///
    /// Unlike [`RpcChain::send_tx`], this does NOT take `send_lock` and does
    /// NOT wait for a receipt. Both omissions are the point:
    ///
    /// - the broadcaster owns its own nonce (it signed the payload before
    ///   getting here), so it does not need the shared fill-race lock that
    ///   exists for alloy's `NonceFiller`; taking it would put every Stream G
    ///   send behind whatever pilot relayer call is mid-flight;
    /// - blocking for the receipt is exactly the shipped 6b hazard: a
    ///   `get_receipt` timeout on a transaction that DID reach the mempool
    ///   surfaces as a broadcast error, and a broadcast error releases the
    ///   reserved action nonce while the transaction is still live.
    ///   Reconciliation observes the receipt later, from the hash this
    ///   returns.
    fn send_raw_transaction(&self, raw: &[u8]) -> Result<TxHash, ChainError> {
        let url = self.rpc_url.clone();
        let raw = raw.to_vec();
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            let pending =
                tokio::time::timeout(SEND_TX_TIMEOUT, provider.send_raw_transaction(&raw))
                    .await
                    .map_err(|_| {
                        ChainError::Msg(format!(
                            "send_raw_transaction timed out after {SEND_TX_TIMEOUT:?}"
                        ))
                    })?
                    .map_err(|e| ChainError::Msg(format!("send_raw_transaction: {e}")))?;
            Ok(pending.tx_hash().0)
        })
    }

    /// `eth_getTransactionReceipt`. `Ok(None)` = accepted-but-not-yet-mined.
    fn transaction_receipt(&self, hash: TxHash) -> Result<Option<TxReceiptView>, ChainError> {
        let url = self.rpc_url.clone();
        let budget = self.read_timeout;
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            let receipt = with_deadline(
                &format!("eth_getTransactionReceipt(0x{})", hex::encode(hash)),
                budget,
                async {
                    provider
                        .get_transaction_receipt(B256::from(hash))
                        .await
                        .map_err(|e| ChainError::Msg(format!("eth_getTransactionReceipt: {e}")))
                },
            )
            .await?;
            let Some(receipt) = receipt else {
                return Ok(None);
            };
            // A receipt without a block is a malformed answer, not a pending
            // transaction (pending is `None` above). Fail rather than invent
            // block 0, which a confirmation-depth check would read as
            // "buried very deep".
            let (Some(block_number), Some(block_hash)) = (receipt.block_number, receipt.block_hash)
            else {
                return Err(ChainError::Msg(format!(
                    "eth_getTransactionReceipt 0x{}: receipt has no block number/hash",
                    hex::encode(hash)
                )));
            };
            Ok(Some(TxReceiptView {
                tx_hash: receipt.transaction_hash.0,
                block_number,
                block_hash: block_hash.0,
                success: receipt.status(),
                gas_used: u128::from(receipt.gas_used),
            }))
        })
    }

    /// `eth_getTransactionCount(addr, pending|latest)`.
    fn transaction_count(&self, addr: [u8; 20], pending: bool) -> Result<u64, ChainError> {
        let url = self.rpc_url.clone();
        let address = Address::from(addr);
        let budget = self.read_timeout;
        let tag = if pending { "pending" } else { "latest" };
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            let call = provider.get_transaction_count(address);
            let call = if pending {
                call.pending()
            } else {
                call.latest()
            };
            with_deadline(
                &format!("eth_getTransactionCount({address}, {tag})"),
                budget,
                async {
                    call.await.map_err(|e| {
                        ChainError::Msg(format!("eth_getTransactionCount({address}, {tag}): {e}"))
                    })
                },
            )
            .await
        })
    }

    /// `GoatRelayGateway.intentUsed(bytes32)`, pinned to `block`.
    fn intent_used(
        &self,
        gateway: [u8; 20],
        intent_id: [u8; 32],
        block: u64,
    ) -> Result<bool, ChainError> {
        let out =
            self.eth_call_at_block(Address::from(gateway), encode_intent_used(intent_id), block)?;
        decode_bool_return(
            out.as_ref(),
            &format!("intentUsed(0x{})", hex::encode(intent_id)),
        )
    }

    /// ERC-2612 `nonces(address)` on a fee token, pinned to `block`.
    fn erc2612_nonces(
        &self,
        token: [u8; 20],
        owner: [u8; 20],
        block: u64,
    ) -> Result<u64, ChainError> {
        let out =
            self.eth_call_at_block(Address::from(token), encode_erc2612_nonces(owner), block)?;
        decode_u64_return(out.as_ref(), &format!("nonces(0x{})", hex::encode(owner)))
    }

    /// Paged `eth_getLogs` for `SponsoredEnrollmentExecuted`, following
    /// `list_bound_workers`' scaffolding (G-B1 refusal → chunked ranges →
    /// filter by address + topic0 → decode).
    ///
    /// Two deliberate differences from that precedent:
    ///
    /// - every log keeps its chain position (`block_number`, `block_hash`,
    ///   `log_index`, `tx_hash`, `removed`), because reorg detection and
    ///   "was this ours" are impossible without them;
    /// - a log missing any of that position metadata is an ERROR, not a
    ///   skipped row. A pending log (all-`None`) has no confirmations and
    ///   must never be reconciled as if it did; dropping it silently would
    ///   look identical to "the intent did not execute".
    fn sponsored_enrollment_logs(
        &self,
        gateway: [u8; 20],
        from: u64,
        to: u64,
    ) -> Result<Vec<ExecutedLog>, ChainError> {
        // G-B1: never scan from genesis on a live L2. Anvil (31337) may use
        // deploy block 0; every other chain requires the pin.
        let pin = self.stream_g_gateway_deploy_block;
        if self.chain_id != 31337 && pin == 0 {
            return Err(ChainError::Msg(
                "G-B1: STREAM_G_GATEWAY_DEPLOY_BLOCK must be set (GoatRelayGateway create \
                 block) on non-anvil chains; refusing eth_getLogs from block 0"
                    .into(),
            ));
        }
        // Nothing can have been emitted before the gateway existed, so
        // clamping the scan start UP to the pin is loss-free; clamping down
        // would not be. An inverted range after clamping needs no special
        // case here — `block_log_ranges` returns no pages for `from > to`
        // (`block_log_ranges_empty_when_from_past_to`), so the loop below
        // simply does not run and no request is issued. An explicit early
        // return would be indistinguishable from this by any test.
        let from = from.max(pin);

        let url = self.rpc_url.clone();
        let address = Address::from(gateway);
        let chunk = self.eth_get_logs_chunk.max(1);
        let topic0: B256 = B256::from(event_topic0(SIG_SPONSORED_ENROLLMENT_EXECUTED));
        let budget = self.read_timeout;
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            let ranges = block_log_ranges(from, to, chunk);
            tracing::debug!(
                from,
                to,
                chunk,
                pages = ranges.len(),
                "sponsored_enrollment_logs paged eth_getLogs"
            );
            let mut out = Vec::new();
            for (page_from, page_to) in ranges {
                let filter = Filter::new()
                    .address(address)
                    .event_signature(topic0)
                    .from_block(page_from)
                    .to_block(page_to);
                // Per PAGE — see the sibling scan in `list_bound_workers`.
                let logs = with_deadline(
                    &format!("eth_getLogs SponsoredEnrollmentExecuted [{page_from},{page_to}]"),
                    budget,
                    async {
                        provider.get_logs(&filter).await.map_err(|e| {
                            ChainError::Msg(format!(
                                "eth_getLogs SponsoredEnrollmentExecuted \
                                 [{page_from},{page_to}]: {e}"
                            ))
                        })
                    },
                )
                .await?;
                for log in logs {
                    let topics: Vec<[u8; 32]> = log.topics().iter().map(|t| t.0).collect();
                    let fields =
                        decode_sponsored_enrollment_executed(&topics, log.data().data.as_ref())?;
                    let (Some(block_number), Some(block_hash), Some(log_index), Some(tx_hash)) = (
                        log.block_number,
                        log.block_hash,
                        log.log_index,
                        log.transaction_hash,
                    ) else {
                        return Err(ChainError::Msg(format!(
                            "SponsoredEnrollmentExecuted log in [{page_from},{page_to}] is \
                             missing chain-position metadata (block/log_index/tx_hash); \
                             refusing to reconcile a log that cannot be confirmed or \
                             reorg-checked"
                        )));
                    };
                    out.push(fields.with_metadata(
                        block_number,
                        block_hash.0,
                        log_index,
                        tx_hash.0,
                        log.removed,
                    ));
                }
            }
            Ok(out)
        })
    }
}

/// Decode the `result` member of an `eth_chainId` JSON-RPC response.
///
/// The response is a hex QUANTITY string (`"0x2105"`), not a number and not a
/// 32-byte ABI word — `eth_chainId` is a node method, not a contract call, so
/// none of the `decode_*_return` helpers apply.
///
/// Strict on purpose, because the value feeds `token_manifest`'s gate check 3:
///
/// - a non-string result is rejected rather than coerced (some nodes have
///   historically answered with a JSON number; accepting both silently would
///   mean two decode paths, only one of which is tested);
/// - the `0x` prefix is required, and every remaining character must be an
///   ASCII hex digit — `u64::from_str_radix` on its own accepts a leading
///   `+`, so `"0x+1"` would otherwise decode to chain 1;
/// - more than 16 hex digits is an error rather than a wrap or a truncation,
///   matching the "reject, never truncate" rule the ABI narrowers in
///   `chain.rs` follow;
/// - **zero is rejected.** Chain 0 is not an assigned EIP-155 chain id, and
///   it is exactly the value that would compare equal to an unset
///   `FeeTokenConfig.chainId`. Fail closed instead of authorizing on a pair
///   of zeros.
fn decode_eth_chain_id_result(result: &serde_json::Value) -> Result<u64, ChainError> {
    let raw = result.as_str().ok_or_else(|| {
        ChainError::Msg(format!(
            "eth_chainId returned a non-string result ({result}); \
             the JSON-RPC spec requires a hex QUANTITY string"
        ))
    })?;
    let hex = raw.strip_prefix("0x").ok_or_else(|| {
        ChainError::Msg(format!(
            "eth_chainId result {raw:?} is not an 0x-prefixed QUANTITY"
        ))
    })?;
    if hex.is_empty() {
        return Err(ChainError::Msg(
            "eth_chainId result \"0x\" has no digits".into(),
        ));
    }
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ChainError::Msg(format!(
            "eth_chainId result {raw:?} contains a non-hex character"
        )));
    }
    if hex.len() > 16 {
        return Err(ChainError::Msg(format!(
            "eth_chainId result {raw:?} does not fit in u64 (refusing to truncate)"
        )));
    }
    let chain_id = u64::from_str_radix(hex, 16)
        .map_err(|e| ChainError::Msg(format!("eth_chainId result {raw:?} parse: {e}")))?;
    if chain_id == 0 {
        return Err(ChainError::Msg(
            "eth_chainId returned 0, which is not a valid EIP-155 chain id; \
             refusing to feed a zero into the token-capability chain-id check"
                .into(),
        ));
    }
    Ok(chain_id)
}

/// Decode a single `bytes32` `eth_call` return (`getTokenConfigHash`,
/// `activeManifestHash`), which is encoded inline at offset 0.
///
/// A short return is an error rather than a zero hash: `eth_call` to an
/// address with no deployed contract returns `0x`, and a zero-filled hash
/// would be indistinguishable from a real one in the equality checks these
/// values feed. `what` names the call for the error message only.
fn decode_bytes32_return(data: &[u8], what: &str) -> Result<[u8; 32], ChainError> {
    if data.len() < 32 {
        return Err(ChainError::Msg(format!(
            "{what}() return too short: {} bytes (need 32)",
            data.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data[..32]);
    Ok(out)
}

/// Decode a single `uint256` `eth_call` return from the `GasPriceOracle`
/// predeploy (Base fee decomposition, hazard 1 — see `stream_g::base_fee`
/// module doc). `what` names the call for the error message only.
fn decode_gas_oracle_u256(data: &[u8], what: &str) -> Result<u128, ChainError> {
    if data.len() < 32 {
        return Err(ChainError::Msg(format!(
            "{what}() return too short: {} bytes (need 32)",
            data.len()
        )));
    }
    let word = &data[data.len() - 32..];
    u128_from_word(word)
}

/// G-B1 pure helper: inclusive block ranges `[from, to]` split into pages of at
/// most `chunk` blocks each. Empty if `from > to`. `chunk == 0` is treated as 1.
///
/// Example: `block_log_ranges(100, 250, 100)` → `[(100,199), (200,250)]`.
pub fn block_log_ranges(from: u64, to: u64, chunk: u64) -> Vec<(u64, u64)> {
    if from > to {
        return Vec::new();
    }
    let chunk = chunk.max(1);
    let mut out = Vec::new();
    let mut start = from;
    loop {
        let end = start.saturating_add(chunk.saturating_sub(1)).min(to);
        out.push((start, end));
        if end >= to {
            break;
        }
        start = end.saturating_add(1);
        if start == 0 {
            // end was u64::MAX; nothing further.
            break;
        }
    }
    out
}

/// G-B1 pure helper: fold Bound log rows in chronological order into one row
/// per wallet (lowercase), **last write wins**.
pub fn merge_bound_workers_last_wins(ordered: Vec<BoundWorker>) -> Vec<BoundWorker> {
    let mut map: HashMap<String, String> = HashMap::new();
    for w in ordered {
        map.insert(w.wallet.to_ascii_lowercase(), w.username);
    }
    let mut out: Vec<BoundWorker> = map
        .into_iter()
        .map(|(wallet, username)| BoundWorker { wallet, username })
        .collect();
    out.sort_by(|a, b| a.wallet.cmp(&b.wallet));
    out
}

/// Calldata for ERC-20 `balanceOf(address)`.
fn encode_erc20_balance_of(wallet: [u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&selector("balanceOf(address)"));
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&wallet);
    out.extend_from_slice(&word);
    out
}

/// Decode `nonces(address)` eth_call return: last 8 bytes of the 32-byte word as u64.
fn decode_nonce_u64(data: &[u8]) -> Result<u64, ChainError> {
    if data.len() < 32 {
        return Err(ChainError::Msg(format!(
            "nonces() return too short: {} bytes (need 32)",
            data.len()
        )));
    }
    let word = &data[data.len() - 32..];
    let mut b = [0u8; 8];
    b.copy_from_slice(&word[24..]);
    Ok(u64::from_be_bytes(b))
}

/// ABI-decode a single non-indexed `string` from event data.
fn decode_abi_string(data: &[u8]) -> Result<String, ChainError> {
    if data.len() < 64 {
        return Err(ChainError::Msg("Bound username data too short".into()));
    }
    let offset = U256::from_be_slice(&data[0..32]);
    let off = offset
        .try_into()
        .map_err(|_| ChainError::Msg("Bound string offset overflow".into()))?;
    let off: usize = off;
    if data.len() < off.saturating_add(32) {
        return Err(ChainError::Msg("Bound string length OOB".into()));
    }
    let len = U256::from_be_slice(&data[off..off + 32]);
    let n: usize = len
        .try_into()
        .map_err(|_| ChainError::Msg("Bound string len overflow".into()))?;
    let start = off + 32;
    let end = start.saturating_add(n);
    if data.len() < end {
        return Err(ChainError::Msg("Bound string bytes OOB".into()));
    }
    String::from_utf8(data[start..end].to_vec())
        .map_err(|e| ChainError::Msg(format!("Bound username utf8: {e}")))
}

fn parse_alloy_address(s: &str) -> Result<Address, ChainError> {
    // Prefer checksummed when provided; fall back to plain FromStr.
    Address::parse_checksummed(s, None).or_else(|_| {
        Address::from_str(s).map_err(|e| ChainError::Msg(format!("bad address {s}: {e}")))
    })
}

fn parse_key_opt(key: Option<&str>) -> Result<Option<PrivateKeySigner>, ChainError> {
    match key {
        None | Some("") => Ok(None),
        Some(k) => {
            let signer = PrivateKeySigner::from_str(k.trim())
                .map_err(|e| ChainError::Msg(format!("private key parse: {e}")))?;
            Ok(Some(signer))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn block_log_ranges_empty_when_from_past_to() {
        assert!(block_log_ranges(10, 9, 100).is_empty());
    }

    #[test]
    fn block_log_ranges_single_page() {
        assert_eq!(block_log_ranges(100, 150, 100), vec![(100, 150)]);
        assert_eq!(block_log_ranges(0, 0, 2000), vec![(0, 0)]);
    }

    #[test]
    fn block_log_ranges_splits_inclusive_chunks() {
        // chunk=100 → 100 blocks per page: [100,199], [200,250]
        assert_eq!(
            block_log_ranges(100, 250, 100),
            vec![(100, 199), (200, 250)]
        );
        // exact multiple
        assert_eq!(block_log_ranges(0, 199, 100), vec![(0, 99), (100, 199)]);
    }

    #[test]
    fn block_log_ranges_zero_chunk_becomes_one() {
        assert_eq!(block_log_ranges(5, 7, 0), vec![(5, 5), (6, 6), (7, 7)]);
    }

    #[test]
    fn merge_bound_workers_last_wins_case_insensitive() {
        let rows = vec![
            BoundWorker {
                wallet: "0xAbC".into(),
                username: "GOAT-first".into(),
            },
            BoundWorker {
                wallet: "0xabc".into(),
                username: "GOAT-second".into(),
            },
            BoundWorker {
                wallet: "0xdef".into(),
                username: "GOAT-only".into(),
            },
        ];
        let out = merge_bound_workers_last_wins(rows);
        assert_eq!(out.len(), 2);
        let abc = out.iter().find(|w| w.wallet == "0xabc").unwrap();
        assert_eq!(abc.username, "GOAT-second");
        let def = out.iter().find(|w| w.wallet == "0xdef").unwrap();
        assert_eq!(def.username, "GOAT-only");
    }

    #[test]
    fn list_bound_workers_refuses_unpinned_non_anvil() {
        let mut m = HashMap::new();
        m.insert("RPC_URL".into(), "http://127.0.0.1:8545".into());
        m.insert("CHAIN_ID".into(), "84532".into());
        m.insert(
            "EPOCH_SETTLEMENT_ADDRESS".into(),
            "0x0000000000000000000000000000000000000001".into(),
        );
        m.insert(
            "WORKER_BINDING_ADDRESS".into(),
            "0x0000000000000000000000000000000000000002".into(),
        );
        m.insert(
            "ENROLLMENT_REGISTRY_ADDRESS".into(),
            "0x0000000000000000000000000000000000000003".into(),
        );
        m.insert("REGISTRY_JSON".into(), "./registry.json".into());
        // WORKER_BINDING_DEPLOY_BLOCK unset → 0
        let cfg = crate::config::load_from_map(&m).unwrap();
        let rpc = RpcChain::from_config(&cfg).unwrap();
        let err = rpc.list_bound_workers().unwrap_err().to_string();
        assert!(
            err.contains("WORKER_BINDING_DEPLOY_BLOCK") || err.contains("G-B1"),
            "unexpected err: {err}"
        );
    }

    #[test]
    fn from_config_parses_addresses_without_keys() {
        // No mock flag, no keys — constructs RpcChain; propose fails before network.
        let mut m = HashMap::new();
        m.insert("RPC_URL".into(), "http://127.0.0.1:8545".into());
        m.insert("CHAIN_ID".into(), "31337".into());
        m.insert(
            "EPOCH_SETTLEMENT_ADDRESS".into(),
            "0x0000000000000000000000000000000000000001".into(),
        );
        m.insert(
            "WORKER_BINDING_ADDRESS".into(),
            "0x0000000000000000000000000000000000000002".into(),
        );
        m.insert(
            "ENROLLMENT_REGISTRY_ADDRESS".into(),
            "0x0000000000000000000000000000000000000003".into(),
        );
        m.insert("REGISTRY_JSON".into(), "./registry.json".into());
        let cfg = crate::config::load_from_map(&m).unwrap();
        assert!(!cfg.mock_mode);
        let chain = RpcChain::from_config(&cfg).unwrap();
        assert_eq!(chain.chain_id, 31337);
        let err = chain
            .propose_batch(1, [0u8; 32], [0u8; 32], cfg.proposer_bond_wei)
            .unwrap_err();
        assert!(err.to_string().contains("PROPOSER_PRIVATE_KEY"), "{err}");
    }

    // -- Stream G G1 live-chain sourcing (Task 6 Wave A) ------------------

    #[test]
    fn stream_g_decode_bytes32_return_reads_the_whole_word() {
        // `getTokenConfigHash(address)` / `activeManifestHash()` each return
        // a single `bytes32`, encoded inline at offset 0.
        let mut data = [0u8; 32];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        let out = decode_bytes32_return(&data, "getTokenConfigHash").unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn stream_g_decode_bytes32_return_rejects_short_return() {
        // An `eth_call` to an address with no contract returns `0x`; a
        // zero-filled 32-byte hash would be indistinguishable from a real
        // (if unset) one, so a short return must be an error.
        let err = decode_bytes32_return(&[], "activeManifestHash").unwrap_err();
        assert!(err.to_string().contains("activeManifestHash"), "{err}");
        assert!(decode_bytes32_return(&[0u8; 31], "getTokenConfigHash").is_err());
    }

    // -- eth_chainId decode (Task 6 Wave A, gate check 3) -----------------
    //
    // These run over HAND-BUILT JSON-RPC response bytes: the exact bytes a
    // node would put on the wire are written out as a byte-string literal,
    // parsed with `serde_json`, and the `result` member handed to the decoder
    // — the same value `raw_request` yields. No production encoder helps
    // build the input, so a change to the decoder cannot also move the
    // expectation.

    /// Pull the `result` member out of hand-built JSON-RPC response bytes,
    /// exactly as the transport layer would before calling the decoder.
    fn chain_id_result_from_response_bytes(bytes: &[u8]) -> serde_json::Value {
        let response: serde_json::Value =
            serde_json::from_slice(bytes).expect("hand-built response must be valid JSON");
        response
            .get("result")
            .expect("hand-built response must carry a result member")
            .clone()
    }

    #[test]
    fn stream_g_decode_eth_chain_id_over_hand_built_response_bytes() {
        // Mutation this detects: decoding the QUANTITY as decimal instead of
        // hex (`"0x2105".parse::<u64>()` / radix 10). 0x2105 is Base mainnet
        // 8453 and 0x7a69 is anvil 31337 — neither is a hex/decimal
        // coincidence, so a radix slip changes the answer rather than
        // reading the same. It also detects dropping or mis-slicing the `0x`
        // prefix (0x2105 would become an error or a different number).
        let base =
            chain_id_result_from_response_bytes(br#"{"jsonrpc":"2.0","id":1,"result":"0x2105"}"#);
        assert_eq!(decode_eth_chain_id_result(&base).unwrap(), 8453);

        let anvil =
            chain_id_result_from_response_bytes(br#"{"jsonrpc":"2.0","id":1,"result":"0x7a69"}"#);
        assert_eq!(decode_eth_chain_id_result(&anvil).unwrap(), 31337);

        // Upper-case digits and a minimal one-digit quantity are both legal
        // QUANTITY spellings a node may emit.
        let sepolia =
            chain_id_result_from_response_bytes(br#"{"jsonrpc":"2.0","id":1,"result":"0x14A34"}"#);
        assert_eq!(decode_eth_chain_id_result(&sepolia).unwrap(), 84532);

        let mainnet =
            chain_id_result_from_response_bytes(br#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#);
        assert_eq!(decode_eth_chain_id_result(&mainnet).unwrap(), 1);

        // Largest value that still fits: 16 hex digits.
        let max = chain_id_result_from_response_bytes(
            br#"{"jsonrpc":"2.0","id":1,"result":"0xffffffffffffffff"}"#,
        );
        assert_eq!(decode_eth_chain_id_result(&max).unwrap(), u64::MAX);
    }

    #[test]
    fn stream_g_decode_eth_chain_id_rejects_zero() {
        // Mutation this detects: deleting the `chain_id == 0` guard. Chain 0
        // is not an assigned EIP-155 chain id, and it is the one value that
        // would compare EQUAL to a zeroed `FeeTokenConfig.chainId`, letting
        // gate check 3 pass on a pair of zeros.
        let zero =
            chain_id_result_from_response_bytes(br#"{"jsonrpc":"2.0","id":1,"result":"0x0"}"#);
        let err = decode_eth_chain_id_result(&zero).unwrap_err();
        assert!(
            err.to_string().contains("not a valid EIP-155 chain id"),
            "expected the zero-chain-id message, got: {err}"
        );
    }

    #[test]
    fn stream_g_decode_eth_chain_id_rejects_oversized_quantity() {
        // Mutation this detects: replacing the length check + `from_str_radix`
        // with anything that wraps or truncates (e.g. taking the low 16 hex
        // digits). 17 digits `0x1` + sixteen `0` would truncate to 0 — which
        // the zero guard would then also catch — so the assertion is on the
        // *truncation* message specifically, not merely on being an error.
        let too_big = chain_id_result_from_response_bytes(
            br#"{"jsonrpc":"2.0","id":1,"result":"0x10000000000000000"}"#,
        );
        let err = decode_eth_chain_id_result(&too_big).unwrap_err();
        assert!(
            err.to_string().contains("refusing to truncate"),
            "expected the u64-overflow message, got: {err}"
        );
    }

    #[test]
    fn stream_g_decode_eth_chain_id_rejects_malformed_quantities() {
        // Mutation this detects: dropping the `is_ascii_hexdigit` scan.
        // `u64::from_str_radix` accepts a leading `+`, so without that scan
        // `"0x+1"` decodes to chain 1 — a malformed response silently
        // becoming Ethereum mainnet.
        let plus =
            chain_id_result_from_response_bytes(br#"{"jsonrpc":"2.0","id":1,"result":"0x+1"}"#);
        let err = decode_eth_chain_id_result(&plus).unwrap_err();
        assert!(
            err.to_string().contains("non-hex character"),
            "expected the non-hex message, got: {err}"
        );

        // Mutation this detects: making the `0x` prefix optional. A bare
        // "2105" is not a QUANTITY; accepting it would decode a decimal-looking
        // string as hex.
        let unprefixed =
            chain_id_result_from_response_bytes(br#"{"jsonrpc":"2.0","id":1,"result":"2105"}"#);
        let err = decode_eth_chain_id_result(&unprefixed).unwrap_err();
        assert!(
            err.to_string().contains("not an 0x-prefixed QUANTITY"),
            "expected the prefix message, got: {err}"
        );

        let empty =
            chain_id_result_from_response_bytes(br#"{"jsonrpc":"2.0","id":1,"result":"0x"}"#);
        let err = decode_eth_chain_id_result(&empty).unwrap_err();
        assert!(
            err.to_string().contains("no digits"),
            "expected the empty-quantity message, got: {err}"
        );

        // Mutation this detects: coercing a JSON number (via `as_u64()` or a
        // `to_string()` fallback). A node answering `8453` rather than
        // `"0x2105"` is off-spec; accepting it would create a second decode
        // path that nothing above exercises.
        let numeric =
            chain_id_result_from_response_bytes(br#"{"jsonrpc":"2.0","id":1,"result":8453}"#);
        let err = decode_eth_chain_id_result(&numeric).unwrap_err();
        assert!(
            err.to_string().contains("non-string result"),
            "expected the non-string message, got: {err}"
        );
    }

    #[test]
    fn stream_g_rpc_chain_id_is_read_from_the_node_not_from_config() {
        // The single most likely wrong implementation of `RpcChain::chain_id`
        // is `Ok(self.chain_id)` — the `CHAIN_ID` config value the struct
        // already holds. It compiles, it looks right, and it would silently
        // re-create the self-comparison that makes `token_manifest`'s gate
        // check 3 unreachable.
        //
        // Mutation this detects: exactly that. Point the client at a port
        // nothing can be listening on (port 1 is reserved and requires
        // privilege to bind) while configuring CHAIN_ID=31337. A live read
        // must fail with a transport error tagged `eth_chainId`; a
        // config-sourced one would cheerfully return Ok(31337).
        let mut m = HashMap::new();
        m.insert("RPC_URL".into(), "http://127.0.0.1:1".into());
        m.insert("CHAIN_ID".into(), "31337".into());
        m.insert(
            "EPOCH_SETTLEMENT_ADDRESS".into(),
            "0x0000000000000000000000000000000000000001".into(),
        );
        m.insert(
            "WORKER_BINDING_ADDRESS".into(),
            "0x0000000000000000000000000000000000000002".into(),
        );
        m.insert(
            "ENROLLMENT_REGISTRY_ADDRESS".into(),
            "0x0000000000000000000000000000000000000003".into(),
        );
        m.insert("REGISTRY_JSON".into(), "./registry.json".into());
        let cfg = crate::config::load_from_map(&m).unwrap();
        let chain = RpcChain::from_config(&cfg).unwrap();
        // Precondition: the config value really is 31337, so an `Ok(31337)`
        // below would be indistinguishable from the config-sourced bug.
        assert_eq!(chain.chain_id, 31337);

        let result = chain.chain_id();
        let err = result.expect_err(
            "chain_id() must issue a live eth_chainId round-trip; returning the \
             configured CHAIN_ID would make token_manifest gate check 3 degenerate",
        );
        assert!(
            err.to_string().contains("eth_chainId"),
            "expected an eth_chainId transport error, got: {err}"
        );
    }

    #[test]
    fn parse_alloy_address_accepts_plain_hex() {
        let a = parse_alloy_address("0x00000000000000000000000000000000000000Ab").unwrap();
        assert!(format!("{a:?}").to_lowercase().contains("ab"));
    }

    /// Smoke against a bare local anvil at `RPC_URL` — three live round-trips.
    ///
    /// **Correction, Wave 1 (2026-07-25).** This test used to end
    /// `let _ = chain.get_batch(0);` with the `Result` discarded and no
    /// assertion anywhere in the body, so it passed with **nothing listening**
    /// — verified by running it against `RPC_URL=http://127.0.0.1:1`, which
    /// reported `ok`. It was nonetheless one of the three `#[ignore]`d tests
    /// cited as precedent by `stream_g::anvil_harness`'s module doc, so it was
    /// lending that precedent credibility it did not have. The body below is
    /// the repair; the old text is recorded here rather than deleted so the
    /// gap is auditable.
    ///
    /// Mutation this detects (and the one that proved the old body vacuous):
    /// point `RPC_URL` at a port with no node. Each of the three assertions
    /// below then fails — `chain_id()`/`pinned_block_number()` on the transport
    /// error, `get_batch` because it never reaches the decoder.
    ///
    /// The three placeholder contract addresses are pinned rather than read
    /// from the environment: the `get_batch` assertion depends on
    /// `EPOCH_SETTLEMENT_ADDRESS` being **code-less** on the node, which is
    /// what makes the observed error the decode-length rejection rather than a
    /// revert. This is a bare-anvil smoke, not a smoke against a deployment.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn rpc_chain_anvil_smoke() {
        let rpc = std::env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".into());
        let mut m = HashMap::new();
        m.insert("RPC_URL".into(), rpc);
        m.insert("CHAIN_ID".into(), "31337".into());
        m.insert(
            "EPOCH_SETTLEMENT_ADDRESS".into(),
            "0x0000000000000000000000000000000000000001".into(),
        );
        m.insert(
            "WORKER_BINDING_ADDRESS".into(),
            "0x0000000000000000000000000000000000000002".into(),
        );
        m.insert(
            "ENROLLMENT_REGISTRY_ADDRESS".into(),
            "0x0000000000000000000000000000000000000003".into(),
        );
        m.insert("REGISTRY_JSON".into(), "./registry.json".into());
        m.insert(
            "PROPOSER_PRIVATE_KEY".into(),
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        );
        let cfg = crate::config::load_from_map(&m).unwrap();
        let chain = RpcChain::from_config(&cfg).unwrap();

        // 1. `eth_chainId`. `chain_id()` deliberately does *not* return the
        //    configured `CHAIN_ID` field (see its doc comment), so this is the
        //    node's own answer and is unobtainable with nothing listening.
        let live_chain_id = chain
            .chain_id()
            .expect("eth_chainId must round-trip against the anvil at RPC_URL");
        assert_eq!(
            live_chain_id, 31337,
            "RPC_URL must point at an anvil started with --chain-id 31337"
        );

        // 2. `eth_blockNumber`, the other read whose decode lives inside alloy.
        chain
            .pinned_block_number()
            .expect("eth_blockNumber must round-trip against the anvil at RPC_URL");

        // 3. `get_batch` really does issue the `eth_call` *and* really does run
        //    the answer through `decode_batch_return`. The settlement address
        //    above is code-less on a bare anvil, so the node returns zero bytes
        //    of call data and the decoder rejects it on length. With nothing
        //    listening the call fails in transport instead and the message is
        //    `eth_call: …`, so this specific string is what makes the
        //    assertion node-dependent rather than vacuous.
        let err = chain
            .get_batch(0)
            .expect_err("batches() against a code-less address must not decode");
        assert!(
            err.to_string()
                .contains("batches() return too short: 0 bytes (need 320)"),
            "expected the decode-length rejection (proving the eth_call round-tripped \
             and reached the decoder), got: {err}"
        );
    }

    /// Proves `send_native` actually pins gas to 21,000 rather than estimating it, by
    /// deploying a tiny contract that executes an `SSTORE` on *any* call (there is no
    /// Solidity-style calldata dispatcher at the raw-bytecode level, so the plain value
    /// transfer `send_native` issues reaches it too). 21,000 is exactly the intrinsic
    /// cost of the transaction itself, so a contract recipient is left with 0 gas to run
    /// that `SSTORE` — the call must fail. A plain EOA recipient needs exactly 21,000 and
    /// must still succeed, proving the failure above is specific to the gas-hungry
    /// contract, not a broken pin.
    ///
    /// This is a genuine regression check: with the fix reverted (gas left to
    /// `eth_estimateGas`), the contract-recipient send would be sized correctly and
    /// succeed, so `expect_err` below would fail the test.
    ///
    /// Optional smoke against local anvil — skipped in default CI.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn send_native_pins_gas_limit_rejects_gas_hungry_recipient() {
        let rpc = std::env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".into());
        let mut m = HashMap::new();
        m.insert("RPC_URL".into(), rpc.clone());
        m.insert("CHAIN_ID".into(), "31337".into());
        m.insert(
            "EPOCH_SETTLEMENT_ADDRESS".into(),
            "0x0000000000000000000000000000000000000001".into(),
        );
        m.insert(
            "WORKER_BINDING_ADDRESS".into(),
            "0x0000000000000000000000000000000000000002".into(),
        );
        m.insert(
            "ENROLLMENT_REGISTRY_ADDRESS".into(),
            "0x0000000000000000000000000000000000000003".into(),
        );
        m.insert("REGISTRY_JSON".into(), "./registry.json".into());
        // anvil's well-known default account #0 — funded at genesis; used both to deploy
        // the gas-hog contract below and (as RELAYER_PRIVATE_KEY) to send the drip itself.
        let deployer_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        m.insert("RELAYER_PRIVATE_KEY".into(), deployer_key.into());
        let cfg = crate::config::load_from_map(&m).unwrap();
        let chain = RpcChain::from_config(&cfg).unwrap();

        // Runtime code: PUSH1 1 PUSH1 0 SSTORE STOP — writes slot 0 on every call.
        // A cold SSTORE from zero to nonzero costs far more than the 0 gas left over
        // after a 21,000-gas-limit transfer's own 21,000 intrinsic cost.
        let runtime_code: [u8; 6] = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
        // Minimal init code: copy `runtime_code` (appended after it) into memory and
        // return it as the deployed contract's code.
        let mut init_code: Vec<u8> = vec![
            0x60, 0x06, // PUSH1 6    (runtime code length)
            0x80, //       DUP1
            0x60, 0x0b, // PUSH1 11   (offset of runtime code within this init code)
            0x60, 0x00, // PUSH1 0    (destOffset in memory)
            0x39, //       CODECOPY
            0x60, 0x00, // PUSH1 0    (return offset)
            0xf3, //       RETURN
        ];
        init_code.extend_from_slice(&runtime_code);
        assert_eq!(
            init_code.len(),
            17,
            "hand-assembled init code length sanity check"
        );

        let deployer = PrivateKeySigner::from_str(deployer_key).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let deploy_receipt = rt.block_on(async {
            let provider = ProviderBuilder::new()
                .wallet(deployer)
                .connect_http(Url::parse(&rpc).unwrap());
            let tx = TransactionRequest::default()
                .with_deploy_code(init_code)
                .with_chain_id(31337);
            let pending = provider
                .send_transaction(tx)
                .await
                .expect("deploy send_transaction");
            pending.get_receipt().await.expect("deploy get_receipt")
        });
        assert!(
            deploy_receipt.status(),
            "gas-hog contract deployment reverted"
        );
        let gas_hog = deploy_receipt
            .contract_address
            .expect("deploy receipt missing contract_address");

        // Contract recipient: 0 gas left after the 21,000 intrinsic cost — must fail.
        chain
            .send_native(&gas_hog.to_string(), 1_000)
            .expect_err("gas-hungry contract recipient must fail at pinned 21,000 gas");

        // Plain EOA recipient (anvil default account #1): needs exactly 21,000 — must
        // still succeed.
        let eoa = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
        chain
            .send_native(eoa, 1_000)
            .expect("plain EOA transfer must succeed at pinned 21,000 gas");
    }

    /// P2 regression, updated for FIX ROUND 1: `send_lock` now serializes each send
    /// *completely* — fill, broadcast, and receipt wait all happen one signer at a time,
    /// not just the nonce-consuming step — so `N` concurrent `send_native` calls from
    /// the same signer must land with `N` distinct nonces/tx hashes with **zero**
    /// overlap between them, and, independently, a waiter contending for the lock must
    /// yield the tokio worker thread back to the runtime instead of parking it —
    /// otherwise concurrent callers exhaust the worker pool and unrelated routes (e.g.
    /// `/health`) stop answering, which is the original P2 defect. This test proves
    /// serialization, not parallelism: it no longer distinguishes the round-1 narrowed
    /// scope from the reverted wide one (anvil can't — see the round-1 report entry —
    /// so this is a nonce-distinctness/no-deadlock check, not a proof the lock scope is
    /// right for Base's Flashblock cadence).
    ///
    /// `worker_threads = 2` with `N = 6` concurrent `send_native` calls deliberately
    /// oversubscribes the runtime's core worker threads relative to in-flight sends, and
    /// each call is issued directly from an async task the way an axum handler calls
    /// `ChainClient` methods (synchronously, not via `spawn_blocking`). The whole run is
    /// wrapped in a 30s `tokio::time::timeout` — comfortable margin even though the 6
    /// sends are now fully sequential (each including its own receipt wait) rather than
    /// pipelined, since anvil auto-mines near-instantly.  This reliably deadlocks (times
    /// out) on the pre-P2-fix code, where `send_lock` was a blocking `std::sync::Mutex`
    /// acquired *before* `block_in_place`: with only 2 core worker threads, the first two
    /// callers block one worker thread each waiting on that mutex without ever entering
    /// `block_in_place`, so tokio never learns it needs a replacement thread — the
    /// remaining 4 tasks then have no worker thread left to run on, forever.
    ///
    /// Optional smoke against local anvil — skipped in default CI.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires local anvil at RPC_URL"]
    async fn rpc_chain_concurrent_sends_serialize_nonces_without_deadlock() {
        let rpc = std::env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".into());
        let mut m = HashMap::new();
        m.insert("RPC_URL".into(), rpc);
        m.insert("CHAIN_ID".into(), "31337".into());
        m.insert(
            "EPOCH_SETTLEMENT_ADDRESS".into(),
            "0x0000000000000000000000000000000000000001".into(),
        );
        m.insert(
            "WORKER_BINDING_ADDRESS".into(),
            "0x0000000000000000000000000000000000000002".into(),
        );
        m.insert(
            "ENROLLMENT_REGISTRY_ADDRESS".into(),
            "0x0000000000000000000000000000000000000003".into(),
        );
        m.insert("REGISTRY_JSON".into(), "./registry.json".into());
        // anvil's well-known default account #0 — funded at genesis.
        m.insert(
            "RELAYER_PRIVATE_KEY".into(),
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        );
        let cfg = crate::config::load_from_map(&m).unwrap();
        let chain = std::sync::Arc::new(RpcChain::from_config(&cfg).unwrap());

        // anvil default account #1 — plain EOA recipient, needs no special funding.
        let recipient = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

        const N: usize = 6; // > worker_threads (2): forces real contention on send_lock.
        let mut tasks = Vec::with_capacity(N);
        for _ in 0..N {
            let chain = chain.clone();
            tasks.push(tokio::spawn(
                async move { chain.send_native(recipient, 1_000) },
            ));
        }

        let results = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let mut out = Vec::with_capacity(N);
            for t in tasks {
                out.push(t.await.expect("send_native task panicked"));
            }
            out
        })
        .await
        .expect(
            "deadlocked: concurrent send_native calls did not finish within 30s \
             (worker pool likely starved — see send_lock doc comment)",
        );

        let mut hashes = std::collections::HashSet::new();
        for r in results {
            let h = r.expect("send_native must succeed for a plain EOA recipient");
            assert!(
                hashes.insert(h),
                "duplicate tx hash — implies a collided/replaced nonce, i.e. \
                 serialization broke"
            );
        }
        assert_eq!(
            hashes.len(),
            N,
            "all N concurrent sends must land as distinct txs"
        );
    }

    // -- Stream G G1 outbox / broadcaster (Task 7 Wave A) ------------------

    /// Minimal non-anvil env map, mirroring
    /// `list_bound_workers_refuses_unpinned_non_anvil`'s.
    fn base_env(chain_id: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("RPC_URL".into(), "http://127.0.0.1:8545".into());
        m.insert("CHAIN_ID".into(), chain_id.into());
        m.insert(
            "EPOCH_SETTLEMENT_ADDRESS".into(),
            "0x0000000000000000000000000000000000000001".into(),
        );
        m.insert(
            "WORKER_BINDING_ADDRESS".into(),
            "0x0000000000000000000000000000000000000002".into(),
        );
        m.insert(
            "ENROLLMENT_REGISTRY_ADDRESS".into(),
            "0x0000000000000000000000000000000000000003".into(),
        );
        m.insert("REGISTRY_JSON".into(), "./registry.json".into());
        m
    }

    /// A TCP endpoint that completes the handshake and then answers
    /// **nothing**, holding every accepted socket open forever.
    ///
    /// This is the whole "the node stopped answering" hazard reduced to
    /// twelve lines and made deterministic: no anvil, no suspended process, no
    /// timing window. It is deliberately *not* a closed port — a refused
    /// connection errors immediately even with no deadline, so it would prove
    /// nothing. The accepted-and-silent case is the one that used to park an
    /// `.await` forever.
    fn black_hole_endpoint() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind black hole");
        let addr = listener.local_addr().expect("black hole local_addr");
        std::thread::spawn(move || {
            // Accepted sockets are PARKED, never answered and never dropped:
            // dropping would close the connection and the client would see a
            // clean EOF, i.e. a fast error rather than the stall being tested.
            let mut held = Vec::new();
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => held.push(s),
                    Err(_) => break,
                }
            }
        });
        format!("http://{addr}")
    }

    /// A port with nothing listening: `connect` is refused at once.
    fn closed_endpoint() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind then close");
        let addr = listener.local_addr().expect("closed local_addr");
        drop(listener);
        format!("http://{addr}")
    }

    /// Build an `RpcChain` pointed at `url` with a deliberately tiny read
    /// budget (see [`RpcChain::with_read_timeout`]).
    fn chain_against(url: &str, budget: Duration) -> RpcChain {
        let mut m = base_env("31337");
        m.insert("RPC_URL".into(), url.to_string());
        let cfg = crate::config::load_from_map(&m).expect("black-hole env must validate");
        RpcChain::from_config(&cfg)
            .expect("RpcChain::from_config")
            .with_read_timeout(budget)
    }

    /// Every read this type performs, as `(operation name asserted, call)`.
    /// One list, driven twice below — once against a silent node and once
    /// against a refused port — so neither arm can quietly cover fewer
    /// operations than the other.
    #[allow(clippy::type_complexity)]
    fn every_read(chain: &RpcChain) -> Vec<(&'static str, Box<dyn Fn() -> String + '_>)> {
        vec![
            (
                "eth_blockNumber",
                Box::new(|| chain.pinned_block_number().unwrap_err().to_string()),
            ),
            (
                "eth_chainId",
                Box::new(|| chain.chain_id().unwrap_err().to_string()),
            ),
            (
                "eth_gasPrice",
                Box::new(|| chain.gas_price().unwrap_err().to_string()),
            ),
            (
                "eth_getBalance(",
                Box::new(|| {
                    chain
                        .eth_balance("0x0000000000000000000000000000000000000009")
                        .unwrap_err()
                        .to_string()
                }),
            ),
            (
                "eth_getBlockByNumber(latest)",
                Box::new(|| chain.block_timestamp().unwrap_err().to_string()),
            ),
            (
                "eth_getBlockByNumber(7)",
                Box::new(|| chain.block_timestamp_at(7).unwrap_err().to_string()),
            ),
            (
                "eth_getTransactionCount(",
                Box::new(|| {
                    chain
                        .transaction_count([9u8; 20], true)
                        .unwrap_err()
                        .to_string()
                }),
            ),
            (
                "eth_getTransactionReceipt(0x",
                Box::new(|| {
                    chain
                        .transaction_receipt([7u8; 32])
                        .unwrap_err()
                        .to_string()
                }),
            ),
            (
                "eth_getCode",
                Box::new(|| {
                    chain
                        .fee_token_code_hash([3u8; 20], 12)
                        .unwrap_err()
                        .to_string()
                }),
            ),
            (
                // `eth_call` (unpinned) — reached through `get_batch`.
                "eth_call 0x",
                Box::new(|| chain.get_batch(1).unwrap_err().to_string()),
            ),
            (
                // `eth_call_at_block` — the pinned sibling.
                "@ block 12",
                Box::new(|| {
                    chain
                        .active_manifest_hash([4u8; 20], 12)
                        .unwrap_err()
                        .to_string()
                }),
            ),
            (
                "eth_getLogs SponsoredEnrollmentExecuted",
                Box::new(|| {
                    chain
                        .sponsored_enrollment_logs([5u8; 20], 0, 0)
                        .unwrap_err()
                        .to_string()
                }),
            ),
            (
                "anvil_increaseTime",
                Box::new(|| chain.increase_time(1).unwrap_err().to_string()),
            ),
            (
                // `list_bound_workers` opens with `eth_blockNumber`; the paged
                // `eth_getLogs Bound [..]` beneath it is unreachable without a
                // node that answers, and is covered by the sibling scan above.
                "eth_blockNumber",
                Box::new(|| chain.list_bound_workers().unwrap_err().to_string()),
            ),
        ]
    }

    /// **The regression this file's `RPC_READ_TIMEOUT` exists for.**
    ///
    /// A node that accepts the connection and then never replies must produce
    /// a bounded error that NAMES the operation and the budget — not an
    /// unbounded `.await`.
    ///
    /// Reverting the fix does not make this test fail; it makes it **hang**,
    /// which is the whole point and was verified before the fix landed: with
    /// `pinned_block_number`'s `with_deadline` removed, this test ran for
    /// 150s+ with no output and had to be killed. That is the same signature
    /// the gate's watchdog reported at 1200s.
    #[test]
    fn a_node_that_accepts_and_never_answers_fails_with_a_named_deadline_not_a_hang() {
        const BUDGET: Duration = Duration::from_millis(150);
        let chain = chain_against(&black_hole_endpoint(), BUDGET);

        for (op, call) in every_read(&chain) {
            let started = std::time::Instant::now();
            let err = call();
            let elapsed = started.elapsed();

            assert!(
                err.contains("RPC read deadline exceeded"),
                "{op}: a silent node must surface as the read deadline, got: {err}"
            );
            assert!(
                err.contains(op),
                "{op}: the timeout error must name the operation, got: {err}"
            );
            assert!(
                err.contains("150ms"),
                "{op}: the timeout error must name the budget it exceeded, got: {err}"
            );
            // Bounded, and bounded *at the budget* — an error returned in ~0ms
            // would mean the call never reached the network and the assertions
            // above were passing for the wrong reason.
            assert!(
                elapsed >= BUDGET,
                "{op}: returned in {elapsed:?}, before the {BUDGET:?} budget could elapse — \
                 this error did not come from the deadline"
            );
            assert!(
                elapsed < Duration::from_secs(10),
                "{op}: took {elapsed:?} — the deadline did not bound the call"
            );
        }
    }

    /// Control arm for the test above: against a **refused** port the same
    /// reads still fail, but with a transport error rather than the deadline,
    /// and they fail well inside a 30s budget rather than by exhausting it.
    ///
    /// Without this, `contains("RPC read deadline exceeded")` would also pass
    /// for an implementation that stamped that phrase onto every failure, and
    /// the silent-node test would no longer be evidence of anything.
    ///
    /// The probes run **concurrently**. A refused loopback connect costs a
    /// measured ~2.04s on this platform (uniformly, for all fourteen), so
    /// serially this control would add ~29s to the suite for no extra
    /// coverage — and a 29s test is a test people delete.
    #[test]
    fn a_refused_port_fails_as_a_transport_error_not_as_the_read_deadline() {
        let url = closed_endpoint();
        // Taken from `every_read` itself, so this arm cannot silently cover
        // fewer operations than the deadline arm does.
        let probe = chain_against(&url, Duration::from_secs(30));
        let n = every_read(&probe).len();
        drop(probe);

        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..n)
                .map(|i| {
                    let url = url.clone();
                    scope.spawn(move || {
                        let chain = chain_against(&url, Duration::from_secs(30));
                        let mut reads = every_read(&chain);
                        let (op, call) = reads.remove(i);
                        let started = std::time::Instant::now();
                        let err = call();
                        (op, started.elapsed(), err)
                    })
                })
                .collect();
            for handle in handles {
                let (op, elapsed, err) = handle.join().expect("control probe panicked");
                assert!(
                    !err.contains("RPC read deadline exceeded"),
                    "{op}: a refused connection is not a deadline expiry, got: {err}"
                );
                assert!(
                    elapsed < Duration::from_secs(10),
                    "{op}: a refused connection took {elapsed:?} — it must fail on the \
                     transport, not by burning the 30s read budget"
                );
            }
        });
    }

    /// G-B1, gateway edition.
    ///
    /// Mutation this detects: deleting the
    /// `if self.chain_id != 31337 && pin == 0` guard from
    /// `sponsored_enrollment_logs`. Verified — the call then falls through to
    /// `provider.get_logs` and fails with a connection error instead of the
    /// G-B1 message, i.e. it really would have asked a managed RPC to scan
    /// from genesis.
    #[test]
    fn sponsored_enrollment_logs_refuses_unpinned_non_anvil() {
        // STREAM_G_GATEWAY_DEPLOY_BLOCK unset → 0.
        let cfg = crate::config::load_from_map(&base_env("84532")).unwrap();
        let rpc = RpcChain::from_config(&cfg).unwrap();
        let err = rpc
            .sponsored_enrollment_logs([0u8; 20], 0, 100)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("STREAM_G_GATEWAY_DEPLOY_BLOCK") && err.contains("G-B1"),
            "unexpected err: {err}"
        );

        // Paired arm: with the pin set, the refusal no longer fires — the
        // call gets far enough to attempt a network round-trip, which fails
        // with a transport error rather than the G-B1 message. This is what
        // proves the guard is keyed on the pin and not simply always-on.
        let mut m = base_env("84532");
        m.insert("STREAM_G_GATEWAY_DEPLOY_BLOCK".into(), "1000".into());
        let cfg = crate::config::load_from_map(&m).unwrap();
        let rpc = RpcChain::from_config(&cfg).unwrap();
        let err = rpc
            .sponsored_enrollment_logs([0u8; 20], 1000, 1001)
            .unwrap_err()
            .to_string();
        assert!(
            !err.contains("G-B1"),
            "the pin must satisfy the refusal, got: {err}"
        );
    }

    /// The scan start is clamped UP to the configured deploy block, so a
    /// caller asking for a range that predates the gateway never widens the
    /// scan below the pin.
    ///
    /// Mutation this detects: deleting `let from = from.max(pin);`. Verified
    /// — the `(0, 500)` call below then pages `[0,500]`, reaches
    /// `provider.get_logs` against a dead endpoint and errors instead of
    /// returning an empty vec.
    ///
    /// (An earlier draft of this test asserted an explicit
    /// `if to < from { return Ok(vec![]) }` early return instead. That
    /// mutation SURVIVED — `block_log_ranges` already yields no pages for an
    /// inverted range — so the redundant guard was removed rather than left
    /// in place with a test that could not detect its absence.)
    #[test]
    fn sponsored_enrollment_logs_clamps_the_scan_start_up_to_the_deploy_block() {
        let mut m = base_env("84532");
        m.insert("STREAM_G_GATEWAY_DEPLOY_BLOCK".into(), "1000".into());
        let cfg = crate::config::load_from_map(&m).unwrap();
        let rpc = RpcChain::from_config(&cfg).unwrap();

        // Asked for [0, 500]; the pin moves the start to 1000, which is past
        // the end, so there is nothing to page and no request is made.
        let logs = rpc
            .sponsored_enrollment_logs([0u8; 20], 0, 500)
            .expect("a range entirely below the deploy block needs no network");
        assert!(logs.is_empty());

        // Paired arm: a range at/above the pin really does reach the network
        // (and fails, since no node is listening here), proving the empty
        // result above comes from the clamp and not from the method being
        // inert.
        assert!(
            rpc.sponsored_enrollment_logs([0u8; 20], 1000, 1001)
                .is_err(),
            "a range above the pin must actually attempt the RPC"
        );
    }

    /// `Role::Broadcaster` wiring: config already refuses to let the pilot
    /// relayer key double as the broadcaster; this proves the two roles
    /// resolve to genuinely different signers rather than both falling back
    /// to the relayer slot.
    ///
    /// Mutation this detects: pointing `Role::Broadcaster` at `&self.relayer`
    /// in `signer`. Verified — `assert_ne!` on the two addresses then fails.
    #[test]
    fn broadcaster_role_resolves_to_its_own_key_not_the_relayer() {
        let mut m = base_env("31337");
        // Unset: asking for the broadcaster names the missing env var rather
        // than silently borrowing another role's key.
        let cfg = crate::config::load_from_map(&m).unwrap();
        let rpc = RpcChain::from_config(&cfg).unwrap();
        let err = rpc.broadcaster_address().unwrap_err().to_string();
        assert!(
            err.contains("STREAM_G_BROADCASTER_PRIVATE_KEY"),
            "unexpected err: {err}"
        );

        // Anvil accounts #0 and #1 — distinct keys, as config demands.
        m.insert(
            "RELAYER_PRIVATE_KEY".into(),
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        );
        m.insert("STREAM_G_ENABLED".into(), "1".into());
        m.insert(
            "STREAM_G_BROADCASTER_PRIVATE_KEY".into(),
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".into(),
        );
        m.insert(
            "STREAM_G_QUOTE_SIGNER_PRIVATE_KEY".into(),
            "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a".into(),
        );
        m.insert(
            "STREAM_G_ISSUER_PRIVATE_KEY".into(),
            "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6".into(),
        );
        m.insert("STREAM_G_DATA_KEY_HEX".into(), hex::encode([0x11u8; 32]));

        let cfg = crate::config::load_from_map(&m).expect("distinct keys must validate");
        let rpc = RpcChain::from_config(&cfg).unwrap();
        let broadcaster = rpc.broadcaster_address().expect("broadcaster key parses");
        let relayer = rpc.relayer_address().expect("relayer key parses");
        assert_ne!(
            broadcaster.to_lowercase(),
            relayer.to_lowercase(),
            "the broadcaster must not resolve to the pilot relayer signer"
        );
    }

    // -------------------------------------------------------------------
    // `sign_broadcaster_eip1559` — the production signing seam.
    //
    // GROUND TRUTH IS `cast`, NOT ALLOY. Decoding alloy's own output with
    // alloy would be `x == x`: one library's encoder checked against the same
    // library's decoder cannot catch a wrong field order, a wrong type byte or
    // a wrong signature hash, because both halves would be wrong together.
    // Every constant below is verbatim output of foundry `cast` 1.7.1
    // (a standalone binary, not this crate) -- an independent implementation:
    //
    //   $ cast wallet address --private-key 0x2a87…09c6
    //   0xa0Ee7A142d267C1f36714E4a8F75612F20a79720
    //
    //   $ cast mktx 0x0000000000000000000000000000000000000e01 0x90945f08deadbeef \
    //       --private-key 0x2a87…09c6 --nonce 5 --gas-limit 500000 \
    //       --gas-price 1000000000 --priority-gas-price 1000000 \
    //       --chain 31337 --value 0
    //   0x02f874827a69…d7d181
    //
    //   $ cast keccak 0x02f874827a69…d7d181
    //   0x2bcee7d089c6c37a411d428dbbd23b30e7d52046797e17f5c2d68555f040a1c1
    //
    // and the same three with `--chain 84532`. `cast mktx` needs no node: the
    // whole transaction is built and signed offline, which is precisely the
    // property `sign_broadcaster_eip1559` exists to have.
    // -------------------------------------------------------------------

    /// Anvil account #9. Chosen so it is neither the relayer key nor the
    /// broadcaster key used by
    /// [`broadcaster_role_resolves_to_its_own_key_not_the_relayer`] above —
    /// a shared key would let a wrong-role bug pass.
    const CAST_KEY: &str = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";
    /// `cast wallet address --private-key $CAST_KEY`, lowercased.
    const CAST_ADDRESS: &str = "a0ee7a142d267c1f36714e4a8f75612f20a79720";
    const CAST_TO: [u8; 20] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x0e, 0x01,
    ];
    const CAST_NONCE: u64 = 5;
    const CAST_GAS_LIMIT: u64 = 500_000;
    const CAST_MAX_FEE: u128 = 1_000_000_000;
    const CAST_PRIORITY_FEE: u128 = 1_000_000;
    /// `cast mktx … --chain 31337`, `0x` stripped.
    const CAST_RAW_31337: &str = "02f874827a6905830f4240843b9aca008307a1209400000000000000000000\
00000000000000000e01808890945f08deadbeefc080a004754eb39c24ce7792b1d59bf5db1aec35ccf45dd6625a11770\
d2f69dfee7427a048a1f4cf380e735a939ba14c8b65a031eeeb1847f1260d09845c6cb409d7d181";
    /// `cast keccak` of the constant above, `0x` stripped.
    const CAST_HASH_31337: &str =
        "2bcee7d089c6c37a411d428dbbd23b30e7d52046797e17f5c2d68555f040a1c1";
    /// `cast mktx … --chain 84532`, `0x` stripped. Identical in every input
    /// except the chain id.
    const CAST_RAW_84532: &str = "02f87583014a3405830f4240843b9aca008307a12094000000000000000000\
0000000000000000000e01808890945f08deadbeefc001a0c117d4d7d4c879cdea0af08d1386a986b283b16c71363fbb1\
0f081620837df9ea0586f3287c21c3d108b178cdd232cd5a8cb846dfc3b621124f75d9a7e4985e067";
    const CAST_HASH_84532: &str =
        "7b0b7531d66892304734b9ace363f1fd132bf0e448a66d63f4ecec750c9acc56";

    /// `CAST_KEY` wired in as the Stream G broadcaster, with the full set of
    /// dedicated keys `STREAM_G_ENABLED=1` demands.
    fn cast_key_chain(chain_id: u64) -> RpcChain {
        let mut m = HashMap::new();
        m.insert("RPC_URL".into(), "http://127.0.0.1:8545".into());
        m.insert("CHAIN_ID".into(), chain_id.to_string());
        m.insert(
            "EPOCH_SETTLEMENT_ADDRESS".into(),
            "0x0000000000000000000000000000000000000001".into(),
        );
        m.insert(
            "WORKER_BINDING_ADDRESS".into(),
            "0x0000000000000000000000000000000000000002".into(),
        );
        m.insert(
            "ENROLLMENT_REGISTRY_ADDRESS".into(),
            "0x0000000000000000000000000000000000000003".into(),
        );
        m.insert("REGISTRY_JSON".into(), "./registry.json".into());
        m.insert("STREAM_G_ENABLED".into(), "1".into());
        m.insert("STREAM_G_BROADCASTER_PRIVATE_KEY".into(), CAST_KEY.into());
        m.insert(
            "STREAM_G_QUOTE_SIGNER_PRIVATE_KEY".into(),
            "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a".into(),
        );
        m.insert(
            "STREAM_G_ISSUER_PRIVATE_KEY".into(),
            "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6".into(),
        );
        m.insert("STREAM_G_DATA_KEY_HEX".into(), hex::encode([0x11u8; 32]));
        let cfg = crate::config::load_from_map(&m).expect("config must load");
        RpcChain::from_config(&cfg).expect("RpcChain must construct")
    }

    fn cast_request() -> Eip1559Request {
        Eip1559Request {
            to: CAST_TO,
            nonce: CAST_NONCE,
            gas_limit: CAST_GAS_LIMIT,
            max_fee_per_gas: CAST_MAX_FEE,
            max_priority_fee_per_gas: CAST_PRIORITY_FEE,
            calldata: hex::decode("90945f08deadbeef").unwrap(),
        }
    }

    /// The signed bytes are a well-formed EIP-1559 transaction: byte-identical
    /// to what `cast mktx` produces from the same key and the same six fields,
    /// which means the type byte, the RLP field order, the signature hash and
    /// the `y_parity/r/s` encoding all agree with an independent
    /// implementation. Because the bytes match, the signature in them recovers
    /// to `CAST_ADDRESS` — that is what `cast` signed with.
    ///
    /// The hash is pinned separately against `cast keccak`, so
    /// `SignedEip1559::hash()` is proven to be `keccak256` of *these* bytes and
    /// not, say, the signature hash (the pre-signature digest), which is the
    /// mistake that would make every "we can always name the transaction we
    /// signed" claim in `stream_g::broadcaster` false.
    ///
    /// **MUTATION DETECTED (run and reverted, one at a time):**
    /// 1. swap `max_fee_per_gas` and `max_priority_fee_per_gas` in the
    ///    `TxEip1559` literal — raw bytes diverge at the two fee fields
    ///    (`left: "02f874827a6905843b9aca00830f4240…"`).
    /// 2. `let hash = signed.signature_hash();` instead of `*signed.hash()` —
    ///    the hash assertion fails while the raw-bytes assertion still passes,
    ///    which is exactly the pairing that makes the hash claim falsifiable.
    #[test]
    fn broadcaster_signed_bytes_are_the_cast_reference_transaction() {
        let rpc = cast_key_chain(31337);
        let signed = rpc
            .sign_broadcaster_eip1559(&cast_request())
            .expect("signing needs no network");

        assert_eq!(
            hex::encode(signed.raw()),
            CAST_RAW_31337,
            "raw EIP-2718 bytes diverged from `cast mktx` ground truth"
        );
        assert_eq!(
            hex::encode(signed.hash()),
            CAST_HASH_31337,
            "the reported hash is not `cast keccak` of the reported bytes"
        );
        assert_eq!(
            hex::encode(signed.from()),
            CAST_ADDRESS,
            "the bytes must be signed by the configured broadcaster key"
        );
        // …and that address is the one this type already exposes, so `from()`
        // is not a second, independently-drifting notion of "the broadcaster".
        assert_eq!(
            rpc.broadcaster_address().unwrap().to_lowercase(),
            format!("0x{CAST_ADDRESS}")
        );

        // Shape assertions that do not depend on the byte pin: typed
        // transaction envelope, EIP-1559.
        assert_eq!(signed.raw()[0], 0x02, "EIP-2718 type byte for EIP-1559");
        assert!(
            signed.raw().len() > 100,
            "non-zero arm: real bytes, not a sentinel"
        );
    }

    /// The chain id is a **signed field**, so the same request on a different
    /// chain must be a different transaction. Pinned against a second
    /// `cast mktx` run whose only changed input is `--chain`.
    ///
    /// This is what makes `CHAIN_ID` load-bearing rather than decorative: a
    /// signer that dropped it (or hard-coded one) would produce a payload
    /// replayable on the other chain.
    ///
    /// **MUTATION DETECTED (run and reverted):** hard-code
    /// `chain_id: 31337` in the `TxEip1559` literal — the 84532 assertions
    /// fail (`left: "02f874827a69…"`, right: `"02f87583014a34…"`) while the
    /// 31337 test above still passes.
    #[test]
    fn the_signed_chain_id_is_the_configured_one() {
        let signed = cast_key_chain(84532)
            .sign_broadcaster_eip1559(&cast_request())
            .expect("signing needs no network");
        assert_eq!(hex::encode(signed.raw()), CAST_RAW_84532);
        assert_eq!(hex::encode(signed.hash()), CAST_HASH_84532);
        assert_eq!(hex::encode(signed.from()), CAST_ADDRESS, "same key");

        // The discrimination is real, not two names for one string.
        assert_ne!(CAST_RAW_84532, CAST_RAW_31337);
        assert_ne!(CAST_HASH_84532, CAST_HASH_31337);
    }

    /// `CHAIN_ID=0` is a loadable config (`parse_u64(map, "CHAIN_ID", 0)`), and
    /// `send_tx` tolerates it by simply not calling `with_chain_id` and letting
    /// alloy fill it from the node. There is no node here to fill it from, and
    /// chain id 0 in a signed EIP-1559 payload is a transaction replayable
    /// wherever it is accepted. Refuse, before any bytes exist.
    ///
    /// **MUTATION DETECTED (run and reverted):** delete the `chain_id == 0`
    /// guard — `expect_err` panics with a `SignedEip1559`, i.e. the crate
    /// happily produced a chain-agnostic signed transaction.
    #[test]
    fn signing_refuses_a_zero_chain_id() {
        let err = cast_key_chain(0)
            .sign_broadcaster_eip1559(&cast_request())
            .expect_err("chain id 0 must not be signed")
            .to_string();
        assert!(err.contains("CHAIN_ID=0"), "unexpected err: {err}");

        // Paired non-refusal arm on the identical request: the guard rejects
        // the chain id, not the request.
        assert!(cast_key_chain(31337)
            .sign_broadcaster_eip1559(&cast_request())
            .is_ok());
    }

    /// EIP-1559 requires `maxPriorityFeePerGas <= maxFeePerGas`. Refusing here
    /// rather than at the node matters for the caller's nonce accounting: a
    /// signing failure is `stream_g::broadcaster`'s **pre-send** arm, which
    /// releases the broadcaster EOA nonce, whereas bytes that exist but no node
    /// will ever accept would sit against a held nonce until a sweeper
    /// resolved them.
    ///
    /// **MUTATION DETECTED (run and reverted):** delete the priority-fee guard
    /// — `expect_err` panics, and the produced payload is one every node
    /// rejects.
    #[test]
    fn signing_refuses_a_priority_fee_above_the_max_fee() {
        let rpc = cast_key_chain(31337);
        let mut req = cast_request();
        req.max_priority_fee_per_gas = req.max_fee_per_gas + 1;
        let err = rpc
            .sign_broadcaster_eip1559(&req)
            .expect_err("an inverted fee pair must not be signed")
            .to_string();
        assert!(
            err.contains("max_priority_fee_per_gas"),
            "unexpected: {err}"
        );

        // Paired arm: equality is legal (a "no tip above base fee" send), so
        // the guard is `>` and not `>=`.
        req.max_priority_fee_per_gas = req.max_fee_per_gas;
        assert!(
            rpc.sign_broadcaster_eip1559(&req).is_ok(),
            "priority == max is a valid EIP-1559 transaction"
        );
    }

    /// No broadcaster key configured — the refusal names the env var, and
    /// nothing is signed. Same fail-closed shape as
    /// [`RpcChain::broadcaster_address`], and it must not silently fall back to
    /// another role's key.
    ///
    /// **MUTATION DETECTED (run and reverted):** point `Role::Broadcaster` at
    /// `&self.relayer` in `signer` — with `RELAYER_PRIVATE_KEY` set below,
    /// `expect_err` panics instead, i.e. the pilot relayer would have signed a
    /// Stream G transaction.
    #[test]
    fn signing_without_a_broadcaster_key_refuses_and_never_borrows_another_role() {
        let mut m = HashMap::new();
        m.insert("RPC_URL".into(), "http://127.0.0.1:8545".into());
        m.insert("CHAIN_ID".into(), "31337".into());
        m.insert(
            "EPOCH_SETTLEMENT_ADDRESS".into(),
            "0x0000000000000000000000000000000000000001".into(),
        );
        m.insert(
            "WORKER_BINDING_ADDRESS".into(),
            "0x0000000000000000000000000000000000000002".into(),
        );
        m.insert(
            "ENROLLMENT_REGISTRY_ADDRESS".into(),
            "0x0000000000000000000000000000000000000003".into(),
        );
        m.insert("REGISTRY_JSON".into(), "./registry.json".into());
        // A relayer key IS present — the only key present.
        m.insert("RELAYER_PRIVATE_KEY".into(), CAST_KEY.into());
        let cfg = crate::config::load_from_map(&m).unwrap();
        let rpc = RpcChain::from_config(&cfg).unwrap();

        let err = rpc
            .sign_broadcaster_eip1559(&cast_request())
            .expect_err("no broadcaster key must refuse")
            .to_string();
        assert!(
            err.contains("STREAM_G_BROADCASTER_PRIVATE_KEY"),
            "unexpected err: {err}"
        );
        // Non-zero arm: the relayer key really is loaded and usable, so the
        // refusal above is about the *role*, not about an empty config.
        assert_eq!(
            rpc.relayer_address().unwrap().to_lowercase(),
            format!("0x{CAST_ADDRESS}")
        );
    }
}
