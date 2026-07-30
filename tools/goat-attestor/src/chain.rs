//! Chain client trait + MockChain + ABI call encoding helpers (selectors via keccak).

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use thiserror::Error;

use crate::merkle::keccak256;

/// Transaction hash (32 bytes).
pub type TxHash = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum BatchStatus {
    #[default]
    None = 0,
    Proposed = 1,
    Challenged = 2,
    ProposerWon = 3,
    ChallengerWon = 4,
    Finalized = 5,
}

/// True when `proposeBatch` is expected to be accepted for `status` — mirrors
/// `EpochSettlement.proposeBatch`'s `status ∈ {None, ChallengerWon}` gate
/// (contracts/src/EpochSettlement.sol). Callers should check this BEFORE
/// firing `propose_batch` so an already-consumed epoch (e.g. Finalized) never
/// triggers a blind revert loop (T31 Fix 2).
pub fn epoch_open_for_propose(status: BatchStatus) -> bool {
    matches!(status, BatchStatus::None | BatchStatus::ChallengerWon)
}

#[derive(Debug, Clone, Default)]
pub struct BatchView {
    pub proposer: [u8; 20],
    pub proposer_bond: u128,
    pub challenger: [u8; 20],
    pub challenger_bond: u128,
    pub merkle_root: [u8; 32],
    pub rate: u128,
    pub evidence_ref: [u8; 32],
    pub challenge_deadline: u64,
    pub watcher_confirmed_at: u64,
    pub status: BatchStatus,
}

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("chain error: {0}")]
    Msg(String),
    #[error("wrong status for epoch {epoch}")]
    WrongStatus { epoch: u64 },
    #[error("batch not found: epoch {0}")]
    NotFound(u64),
    #[error("live RPC not configured in this build — set GOAT_ATTESTOR_MOCK=1 or await Phase 2.1 alloy RPC")]
    LiveRpcNotConfigured,
    #[error("bond mismatch: expected {expected}, got {got}")]
    BondMismatch { expected: u128, got: u128 },
}

/// Minimal surface the attestor needs against EpochSettlement / WorkerBinding / Registry.
pub trait ChainClient: Send + Sync {
    fn propose_batch(
        &self,
        epoch: u64,
        merkle_root: [u8; 32],
        evidence_ref: [u8; 32],
        bond_wei: u128,
    ) -> Result<TxHash, ChainError>;

    fn challenge_batch(
        &self,
        epoch: u64,
        counter_evidence_ref: [u8; 32],
        bond_wei: u128,
    ) -> Result<TxHash, ChainError>;

    fn confirm_epoch(&self, epoch: u64) -> Result<TxHash, ChainError>;

    fn get_batch(&self, epoch: u64) -> Result<BatchView, ChainError>;

    fn bind_with_signature(
        &self,
        wallet: [u8; 20],
        username: &str,
        deadline: u64,
        signature: &[u8],
    ) -> Result<TxHash, ChainError>;

    fn enroll_self_with_signature(
        &self,
        wallet: [u8; 20],
        deadline: u64,
        signature: &[u8],
    ) -> Result<TxHash, ChainError>;

    /// On-chain `EpochSettlement.hasBaseline(worker)` when available.
    /// `Ok(None)` = unknown (use registry flags only).
    fn has_baseline(&self, _wallet: &str) -> Result<Option<bool>, ChainError> {
        Ok(None)
    }

    /// On-chain `EpochSettlement.lastClaimedCumulative(worker)` when available.
    /// `Ok(None)` = unknown (do not gas-skip).
    fn last_claimed_cumulative(&self, _wallet: &str) -> Result<Option<u128>, ChainError> {
        Ok(None)
    }

    /// All wallets that have emitted `WorkerBinding.Bound(wallet, username)`.
    /// Used to auto-fill `registry.json` so ops need not hand-edit new workers.
    /// Default: empty (mock/unconfigured may override).
    fn list_bound_workers(&self) -> Result<Vec<BoundWorker>, ChainError> {
        Ok(Vec::new())
    }

    /// `EpochSettlement.finalizeBatch(epoch)` after challenge window + watcher confirm.
    fn finalize_batch(&self, _epoch: u64) -> Result<TxHash, ChainError> {
        Err(ChainError::Msg("finalize_batch not implemented".into()))
    }

    /// Permissionless `claimPayout` (anyone can submit; worker receives mint).
    fn claim_payout(
        &self,
        _epoch: u64,
        _worker: [u8; 20],
        _proven_score: u128,
        _proof: &[[u8; 32]],
    ) -> Result<TxHash, ChainError> {
        Err(ChainError::Msg("claim_payout not implemented".into()))
    }

    /// Anvil-only: jump clock so challenge window can close in lab automation.
    fn increase_time(&self, _seconds: u64) -> Result<(), ChainError> {
        Ok(())
    }

    /// Current chain timestamp (for warp math). Default: 0 = unknown.
    fn block_timestamp(&self) -> Result<u64, ChainError> {
        Ok(0)
    }

    /// Native ETH balance of `wallet`, in wei. Default: not supported
    /// (`RpcChain`, Task 2, overrides via live RPC).
    fn eth_balance(&self, _wallet: &str) -> Result<u128, ChainError> {
        Err(ChainError::Msg("eth_balance not supported".into()))
    }

    /// Current gas price, in wei/gas. Default: not supported.
    fn gas_price(&self) -> Result<u128, ChainError> {
        Err(ChainError::Msg("gas_price not supported".into()))
    }

    /// Send native ETH (testnet gas drip) to `to`. Default: not supported.
    fn send_native(&self, _to: &str, _amount_wei: u128) -> Result<TxHash, ChainError> {
        Err(ChainError::Msg("send_native not supported".into()))
    }

    /// ERC-20 `balanceOf(wallet)` for `token`. Default: not supported.
    fn erc20_balance_of(&self, _token: &str, _wallet: &str) -> Result<u128, ChainError> {
        Err(ChainError::Msg("erc20_balance_of not supported".into()))
    }

    /// Address of the relayer's own funding wallet (used by the gas-drip
    /// handler to check its own balance before sending). Default: not
    /// supported (`MockChain` and `RpcChain` override).
    fn relayer_address(&self) -> Result<String, ChainError> {
        Err(ChainError::Msg("relayer_address not supported".into()))
    }

    /// `WorkerBinding.nonces(wallet)` — EIP-712 Bind replay counter.
    /// Default `Ok(0)` so mock/unconfigured paths can still exercise H1
    /// without a live registry.
    fn binding_nonce(&self, _wallet: &str) -> Result<u64, ChainError> {
        Ok(0)
    }

    /// `EnrollmentRegistry.nonces(wallet)` — EIP-712 Enroll replay counter.
    fn enrollment_nonce(&self, _wallet: &str) -> Result<u64, ChainError> {
        Ok(0)
    }

    /// `GasPriceOracle.getL1Fee(bytes)` (Base fee decomposition, hazard 1 —
    /// see `stream_g::base_fee` module doc). Exact L1 data-availability fee
    /// for the given unsigned/serialized transaction bytes, in wei. Default:
    /// not supported (`RpcChain` overrides; `MockChain` overrides for tests).
    fn gas_oracle_l1_fee(&self, _unsigned_tx: &[u8]) -> Result<u128, ChainError> {
        Err(ChainError::Msg("gas_oracle_l1_fee not supported".into()))
    }

    /// `GasPriceOracle.getL1FeeUpperBound(uint256)` (Base fee decomposition,
    /// hazard 1). Pessimistic L1 fee bound from a transaction **size**, not
    /// calldata — see `stream_g::base_fee` module doc for the real-vs-mock
    /// signature divergence this differs from. Default: not supported.
    fn gas_oracle_l1_fee_upper_bound(&self, _unsigned_tx_size: u64) -> Result<u128, ChainError> {
        Err(ChainError::Msg(
            "gas_oracle_l1_fee_upper_bound not supported".into(),
        ))
    }

    /// `GasPriceOracle.getOperatorFee(uint256)` (Base fee decomposition,
    /// hazard 1). Per-tx operator fee from a gas quantity, in wei. Default:
    /// not supported.
    fn gas_oracle_operator_fee(&self, _gas_limit: u64) -> Result<u128, ChainError> {
        Err(ChainError::Msg(
            "gas_oracle_operator_fee not supported".into(),
        ))
    }

    // -----------------------------------------------------------------
    // Stream G G1 — live chain sourcing (Task 6 Wave A).
    //
    // These six reads exist so `EnrollmentQuoteContext`'s security-critical
    // fields can be sourced from the chain instead of from a caller. See
    // the "Stream G — Live Chain Sourcing Contract for `EnrollmentQuoteContext`"
    // spec:
    // §2 pins the selectors and decode layouts, §3 R1-R5 the binding rules.
    //
    // Every default body returns `Err`, never `Ok(0)` / `Ok([0u8; 32])`, so
    // an existing pilot implementor that has not been taught these reads
    // keeps compiling but can never silently feed a zero into the token
    // capability gate (Task 5 precedent).
    // -----------------------------------------------------------------

    /// `eth_getCode(token, block)` → `keccak256(code)`.
    ///
    /// R1: this is the **only** permitted derivation of
    /// `observed_fee_token_code_hash`. Deriving it from a manifest entry, a
    /// config file or a request body turns Task 4's EXTCODEHASH gate into
    /// `x == x`.
    ///
    /// Empty returned code must be an `Err`, never `keccak256("")` — see
    /// [`code_hash_from_get_code`] for why. Default: not supported.
    fn fee_token_code_hash(&self, _token: [u8; 20], _block: u64) -> Result<[u8; 32], ChainError> {
        Err(ChainError::Msg("fee_token_code_hash not supported".into()))
    }

    /// `FeeTokenRegistry.getTokenConfig(address)` at `block`
    /// (selector `0xcb67e3b1`). R2: the only permitted source of the fee
    /// token capability record. The caller must additionally bind the
    /// decoded struct to [`ChainClient::fee_token_config_hash`] before
    /// trusting it. Default: not supported.
    fn fee_token_config(
        &self,
        _registry: [u8; 20],
        _token: [u8; 20],
        _block: u64,
    ) -> Result<FeeTokenConfigView, ChainError> {
        Err(ChainError::Msg("fee_token_config not supported".into()))
    }

    /// `FeeTokenRegistry.getTokenConfigHash(address)` at `block`
    /// (selector `0x7e221f83`). R2 step 1: proves the struct decoded by
    /// [`ChainClient::fee_token_config`] is the struct the registry
    /// actually holds. Default: not supported.
    fn fee_token_config_hash(
        &self,
        _registry: [u8; 20],
        _token: [u8; 20],
        _block: u64,
    ) -> Result<[u8; 32], ChainError> {
        Err(ChainError::Msg(
            "fee_token_config_hash not supported".into(),
        ))
    }

    /// `FeeTokenRegistry.activeManifestHash()` at `block`
    /// (selector `0xcc4d2a5e`). R2 step 2: a mismatch against the loaded
    /// deployment manifest means the chain has replaced the manifest this
    /// attestor is running against → fail closed, do not quote.
    /// Default: not supported.
    fn active_manifest_hash(
        &self,
        _registry: [u8; 20],
        _block: u64,
    ) -> Result<[u8; 32], ChainError> {
        Err(ChainError::Msg("active_manifest_hash not supported".into()))
    }

    /// `GoatRelayGateway.secondaryEnrollmentNonceSnapshot(address,address,address)`
    /// at `block` (selector `0x0a6c2870`).
    ///
    /// R3: enrollment nonces must come from **one** snapshot call, not from
    /// two independent `enrollment_nonce` / `linkNonces` reads — atomicity
    /// at a single block is the entire point. R5: the returned snapshot is
    /// **advisory** (`GoatRelayGateway.sol:199` — "not execution
    /// authority"); it reserves nothing, so it proves nonce *consistency at
    /// a past block*, not nonce freshness at submit time.
    ///
    /// The caller must validate `present_mask` before reading any nonce: a
    /// cleared bit means the field was never populated and is a meaningless
    /// zero. Default: not supported.
    fn secondary_enrollment_nonce_snapshot(
        &self,
        _gateway: [u8; 20],
        _root: [u8; 20],
        _secondary: [u8; 20],
        _fee_token: [u8; 20],
        _block: u64,
    ) -> Result<NonceSnapshotView, ChainError> {
        Err(ChainError::Msg(
            "secondary_enrollment_nonce_snapshot not supported".into(),
        ))
    }

    /// `eth_blockNumber` — the block every read above should then be pinned
    /// to (R4). Reading `"latest"` five times across a reorg or a config
    /// upsert lets the gate authorize one chain state while the quote
    /// commits to another. Default: not supported.
    fn pinned_block_number(&self) -> Result<u64, ChainError> {
        Err(ChainError::Msg("pinned_block_number not supported".into()))
    }

    /// `eth_chainId` — the chain the RPC endpoint is **actually** on.
    ///
    /// (The block comment above this group says "six reads"; it was written
    /// when there were six. This is the seventh, added by Task 6 Wave A for
    /// the reason below.)
    ///
    /// This read exists to close a specific degenerate check.
    /// `stream_g::token_manifest`'s gate mirrors `_isAuthorized`, whose check
    /// 3 is `config.chainId == <the chain we are on>`. Until now the attestor
    /// had no way to observe the right-hand side, so
    /// `read_live_token_state` sourced `live_chain_id` from
    /// `getTokenConfig(...).chainId` — i.e. from the very config the gate is
    /// supposed to check — making check 3 an `x == x` comparison that cannot
    /// fail outside a `#[cfg(test)]` reading. Sourcing it here instead makes
    /// the check able to fail when the attestor is pointed at the wrong RPC
    /// endpoint, or when a registry on chain A declares a config for chain B.
    ///
    /// **This must be a live `eth_chainId` round-trip, not a configured
    /// value.** An implementor that answers from its own `CHAIN_ID` config
    /// re-creates exactly the self-comparison this read exists to remove:
    /// the manifest chain id is already checked against the configured chain
    /// id by `token_manifest::assert_manifest_matches_config`, so an
    /// implementation returning config would make gate check 3 degenerate a
    /// second time, one indirection further away.
    ///
    /// Default: not supported — `Err`, never `Ok(0)`. An `Ok(0)` default
    /// would make every non-overriding implementor silently claim to be on
    /// chain 0, which is not a valid EIP-155 chain id and would turn a
    /// security check into a comparison against a fabricated constant.
    fn chain_id(&self) -> Result<u64, ChainError> {
        Err(ChainError::Msg("chain_id not supported".into()))
    }

    // -----------------------------------------------------------------
    // Stream G G1 — outbox / broadcaster / reconcile (Task 7 Wave A).
    //
    // Six reads/writes the durable outbox needs and the trait did not have:
    // there was no raw-tx send, no receipt read, no EOA nonce count, no
    // `intentUsed` read and no log scan anywhere on `ChainClient`.
    //
    // Same Task 5 precedent as the group above: EVERY default body returns
    // `Err`, never `Ok(0)` / `Ok(false)` / `Ok(None)` / `Ok(vec![])`. These
    // feed a sweeper whose whole contract is "release a reserved nonce only
    // when the chain PROVES non-consumption" (founder ruling F2) — a
    // silently-successful default would be read as exactly that proof and
    // would re-release a nonce whose transaction is still live, double-
    // submitting the action nonce.
    // -----------------------------------------------------------------

    /// `eth_sendRawTransaction(raw)` → the transaction hash, **without**
    /// waiting for a receipt.
    ///
    /// The broadcaster signs and persists the raw transaction before it is
    /// ever sent (F2), so it must be able to hand the node a pre-signed
    /// payload and learn the hash immediately. Receipt observation is
    /// reconciliation's job, not the send path's: blocking here is what
    /// turns a slow-but-landing transaction into a "failed" broadcast whose
    /// nonce gets released underneath it.
    ///
    /// Default: not supported.
    fn send_raw_transaction(&self, _raw: &[u8]) -> Result<TxHash, ChainError> {
        Err(ChainError::Msg("send_raw_transaction not supported".into()))
    }

    /// `eth_getTransactionReceipt(hash)`.
    ///
    /// `Ok(None)` means **not mined yet**, which is NOT a failure and NOT
    /// permission to release anything — a transaction can sit in a
    /// sequencer's txpool far longer than any client-side timeout. `Err`
    /// means the question could not be asked at all; the caller must stay
    /// fail-closed on it rather than treating it as `None`.
    ///
    /// Default: not supported — deliberately `Err` and not `Ok(None)`, since
    /// `Ok(None)` is a *substantive answer* the sweeper acts on.
    fn transaction_receipt(&self, _hash: TxHash) -> Result<Option<TxReceiptView>, ChainError> {
        Err(ChainError::Msg("transaction_receipt not supported".into()))
    }

    /// `eth_getTransactionCount(addr, pending|latest)` — the broadcaster's
    /// contiguous nonce frontier.
    ///
    /// `pending = true` asks for the mempool-inclusive count, `false` for
    /// the mined one; the gap between them is what tells a reconciler that a
    /// transaction was dropped rather than merely slow.
    ///
    /// Default: not supported — `Err`, never `Ok(0)`. An `Ok(0)` default
    /// would claim a fresh account for every implementor and make the
    /// broadcaster re-issue nonce 0 forever.
    fn transaction_count(&self, _addr: [u8; 20], _pending: bool) -> Result<u64, ChainError> {
        Err(ChainError::Msg("transaction_count not supported".into()))
    }

    /// `GoatRelayGateway.intentUsed(bytes32)` at `block`
    /// (selector `0xa4532c02`).
    ///
    /// **Required by founder ruling F2.** After a crash this is the only way
    /// to decide whether an intent actually landed: `intentUsed[intentId]` is
    /// set inside `_markIntentAndNonce`, in the same transaction as every
    /// other effect, so it is `true` if and only if some transaction carrying
    /// this intent succeeded — including one somebody *else* broadcast.
    ///
    /// Default: not supported — `Err`, never `Ok(false)`. `Ok(false)` is the
    /// literal statement "the chain proves this intent was not consumed",
    /// i.e. the one answer that authorizes releasing a reserved nonce.
    fn intent_used(
        &self,
        _gateway: [u8; 20],
        _intent_id: [u8; 32],
        _block: u64,
    ) -> Result<bool, ChainError> {
        Err(ChainError::Msg("intent_used not supported".into()))
    }

    /// ERC-2612 `nonces(address owner)` on a fee token at `block`
    /// (selector `0x7ecebe00`).
    ///
    /// Lets a permit be checked for the stale-nonce and expired-deadline
    /// cases before it is paid for. It does **not** make a permit fully
    /// verifiable: a bad `v/r/s` still cannot be checked without the token's
    /// `DOMAIN_SEPARATOR`, which nothing in this crate reads. This shrinks
    /// `UNVERIFIED_CHECKS` entry 10; it does not remove it.
    ///
    /// Default: not supported — `Err`, never `Ok(0)`, which would read as
    /// "this owner has never permitted anything" and pass a replayed permit.
    fn erc2612_nonces(
        &self,
        _token: [u8; 20],
        _owner: [u8; 20],
        _block: u64,
    ) -> Result<u64, ChainError> {
        Err(ChainError::Msg("erc2612_nonces not supported".into()))
    }

    /// Paged `eth_getLogs` for `GoatRelayGateway.SponsoredEnrollmentExecuted`
    /// over the inclusive block range `[from, to]`.
    ///
    /// Reconciliation keys on this event, never on a balance delta: the
    /// gateway collects the fee LAST and emits this event after it, so a
    /// successful fee implies a successful enrollment while the converse
    /// (enrollment without fee, on the direct-ETH branch) is unobservable
    /// from balances.
    ///
    /// Every returned [`ExecutedLog`] carries `block_number`, `block_hash`,
    /// `log_index`, `tx_hash` and `removed` — without all five, reorg
    /// detection and "was this OUR transaction or somebody else's" are both
    /// impossible.
    ///
    /// Default: not supported — `Err`, never `Ok(Vec::new())`. An empty
    /// vector means "the chain says nothing executed in this range", which
    /// is a positive claim a sweeper acts on.
    fn sponsored_enrollment_logs(
        &self,
        _gateway: [u8; 20],
        _from: u64,
        _to: u64,
    ) -> Result<Vec<ExecutedLog>, ChainError> {
        Err(ChainError::Msg(
            "sponsored_enrollment_logs not supported".into(),
        ))
    }

    /// `eth_getBlockByNumber(block).timestamp` — the chain clock **of a
    /// named block**, as opposed to [`ChainClient::block_timestamp`]'s
    /// floating `latest`.
    ///
    /// Task 8 Mandate 3. Every deadline/window comparison in Stream G is a
    /// chain-clock comparison against state that was pinned to one block
    /// (live-chain sourcing contract R4: "one block, every read"). Reading
    /// the clock from `latest` instead breaks that pin: the nonces,
    /// controller and token config come from block `N` while the timestamp
    /// comes from block `N + k`, so a deadline falling inside that window is
    /// judged against a clock the pinned state never saw. On a fast L2 that
    /// window is seconds wide and is exactly where a just-expired permit or
    /// quote lives.
    ///
    /// Default: not supported — `Err`, **never `Ok(0)`**. This is the Task 5
    /// precedent applied to the one place in this trait where the older
    /// sibling breaks it: `block_timestamp`'s default IS `Ok(0)`
    /// ("unknown"), which is why every one of its callers carries a
    /// hand-written `== 0` guard. A silent zero here is 1970, and 1970
    /// satisfies *every* `now < deadline` comparison in the crate — it would
    /// turn an expiry check into an unconditional pass.
    fn block_timestamp_at(&self, _block: u64) -> Result<u64, ChainError> {
        Err(ChainError::Msg("block_timestamp_at not supported".into()))
    }
}

/// One on-chain binding from `WorkerBinding.Bound`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundWorker {
    /// 0x-prefixed lowercase address.
    pub wallet: String,
    pub username: String,
}

// ---------------------------------------------------------------------------
// Stream G G1 — live chain sourcing types + ABI (Task 6 Wave A).
//
// Ground truth is the Solidity source, never a grep: `FeeTokenConfig` is
// `contracts/src/StreamGTypes.sol:292`, `NonceSnapshot` is `:351`, and the
// `SNAP_*` bits are `:369-377`. Selectors were re-derived with `cast sig` on
// 2026-07-24 and are pinned by literal in the `stream_g_selector_pin_*` tests.
// ---------------------------------------------------------------------------

/// `FeeTokenRegistry.getTokenConfig(address)` — selector `0xcb67e3b1`.
pub const SIG_GET_TOKEN_CONFIG: &str = "getTokenConfig(address)";
/// `FeeTokenRegistry.getTokenConfigHash(address)` — selector `0x7e221f83`.
pub const SIG_GET_TOKEN_CONFIG_HASH: &str = "getTokenConfigHash(address)";
/// `FeeTokenRegistry.activeManifestHash()` — selector `0xcc4d2a5e`.
pub const SIG_ACTIVE_MANIFEST_HASH: &str = "activeManifestHash()";
/// `GoatRelayGateway.secondaryEnrollmentNonceSnapshot(address,address,address)`
/// — selector `0x0a6c2870`.
pub const SIG_SECONDARY_ENROLLMENT_NONCE_SNAPSHOT: &str =
    "secondaryEnrollmentNonceSnapshot(address,address,address)";

// `NonceSnapshot.presentMask` bits. These are `uint32 internal constant` in
// `contracts/src/StreamGTypes.sol:369-377`, so they are NOT ABI-visible and
// cannot be read from the chain — they are hard-pinned here, transcribed from
// that source, and asserted in `stream_g_snap_bit_constants_pin`.
//
// A CLEARED bit means the corresponding snapshot field was never populated and
// is a meaningless zero; it must not be read (contract §3 R3).

/// `1 << 0` — `actionNonce` populated.
pub const SNAP_ACTION_NONCE: u32 = 1 << 0;
/// `1 << 1` — `v1EnrollNonce` populated.
pub const SNAP_V1_ENROLL_NONCE: u32 = 1 << 1;
/// `1 << 2` — `linkNonce` populated (only when a secondary is involved).
pub const SNAP_LINK_NONCE: u32 = 1 << 2;
/// `1 << 3` — `rootRegistrationNonce` populated.
pub const SNAP_ROOT_REG_NONCE: u32 = 1 << 3;
/// `1 << 4` — `rotationNonce` populated.
pub const SNAP_ROTATION_NONCE: u32 = 1 << 4;
/// `1 << 5` — `controllerEpoch` / `controller` populated.
pub const SNAP_CONTROLLER: u32 = 1 << 5;
/// `1 << 6` — `goatPermitNonce` populated.
pub const SNAP_GOAT_PERMIT_NONCE: u32 = 1 << 6;
/// `1 << 7` — `feeTokenPermitNonce` / `feeTokenConfigHash` populated.
///
/// A cleared bit is an independent **on-chain statement that the fee token is
/// not authorized for `CAP_EIP2612`**: `GoatRelayGateway._snapshot` (`:288-296`)
/// zeroes both fields and skips this bit in that branch. Fail closed on it.
pub const SNAP_FEE_TOKEN_PERMIT_NONCE: u32 = 1 << 7;
/// `1 << 8` — `deploymentManifestHash` / `feeScheduleHash` populated.
pub const SNAP_CONFIG_HASHES: u32 = 1 << 8;

/// Byte length of the `getTokenConfig` return: 11 static fields, encoded
/// inline from offset 0 (no head/tail indirection, because an all-static
/// struct is an all-static tuple).
pub const FEE_TOKEN_CONFIG_RETURN_LEN: usize = 11 * 32;

/// Byte length of the `secondaryEnrollmentNonceSnapshot` return: 14 static
/// fields, inline from offset 0.
pub const NONCE_SNAPSHOT_RETURN_LEN: usize = 14 * 32;

/// Decoded `StreamGTypes.FeeTokenConfig` (`StreamGTypes.sol:292`), field for
/// field, in declaration order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FeeTokenConfigView {
    pub chain_id: u64,
    pub token: [u8; 20],
    pub runtime_code_hash: [u8; 32],
    /// G1 constraint: the caller must reject a non-zero value here.
    pub proxy_identity_hash: [u8; 32],
    /// `uint256` on chain — **not** a `u64`. Narrowed to `u128` only after
    /// rejecting any non-zero high bits; never truncated.
    pub capability_mask: u128,
    pub decimals: u8,
    pub domain_name_hash: [u8; 32],
    pub domain_version_hash: [u8; 32],
    pub built_in_mode_id: [u8; 32],
    pub config_version: u64,
    pub active: bool,
}

/// Decoded `StreamGTypes.NonceSnapshot` (`StreamGTypes.sol:351`), field for
/// field, **in declaration order**.
///
/// Note that `present_mask` is declared BEFORE the three hashes — that is not
/// the order a reader guesses from the field names, and it is the reason
/// `stream_g_decode_nonce_snapshot_field_order_fixture` exists.
///
/// Advisory only (`GoatRelayGateway.sol:199`): a snapshot reserves nothing.
///
/// Fields are `pub(crate)`, not `pub` — this used to be an all-`pub`-field,
/// `Default`-deriving struct, which made
/// `NonceSnapshotView { present_mask: ..., ..Default::default() }` ordinary
/// public API: eight lines, no chain, no mock, no test hatch, and the
/// result was accepted by (the then-`pub`)
/// `stream_g::models::LiveEnrollmentNonces::from_snapshot`. Construction is
/// now possible only from within this crate — [`decode_nonce_snapshot_return`],
/// this module's own `MockChain`, and `stream_g`'s test fixtures — and the
/// only production way to obtain one via a real chain read is
/// [`ChainClient::secondary_enrollment_nonce_snapshot`], consumed by
/// `stream_g::models::LiveEnrollmentNonces::read_live`. Read access to an
/// already-obtained value stays public via the accessors below; there is no
/// `Default` impl, since nothing legitimate needs a zeroed snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceSnapshotView {
    pub(crate) block_number: u64,
    pub(crate) action_nonce: u128,
    pub(crate) v1_enroll_nonce: u128,
    pub(crate) link_nonce: u128,
    pub(crate) root_registration_nonce: u128,
    pub(crate) rotation_nonce: u128,
    pub(crate) controller_epoch: u128,
    pub(crate) controller: [u8; 20],
    pub(crate) goat_permit_nonce: u128,
    pub(crate) fee_token_permit_nonce: u128,
    pub(crate) present_mask: u32,
    pub(crate) deployment_manifest_hash: [u8; 32],
    pub(crate) fee_token_config_hash: [u8; 32],
    pub(crate) fee_schedule_hash: [u8; 32],
}

impl NonceSnapshotView {
    pub fn block_number(&self) -> u64 {
        self.block_number
    }
    pub fn action_nonce(&self) -> u128 {
        self.action_nonce
    }
    pub fn v1_enroll_nonce(&self) -> u128 {
        self.v1_enroll_nonce
    }
    pub fn link_nonce(&self) -> u128 {
        self.link_nonce
    }
    pub fn root_registration_nonce(&self) -> u128 {
        self.root_registration_nonce
    }
    pub fn rotation_nonce(&self) -> u128 {
        self.rotation_nonce
    }
    pub fn controller_epoch(&self) -> u128 {
        self.controller_epoch
    }
    pub fn controller(&self) -> [u8; 20] {
        self.controller
    }
    pub fn goat_permit_nonce(&self) -> u128 {
        self.goat_permit_nonce
    }
    pub fn fee_token_permit_nonce(&self) -> u128 {
        self.fee_token_permit_nonce
    }
    pub fn present_mask(&self) -> u32 {
        self.present_mask
    }
    pub fn deployment_manifest_hash(&self) -> [u8; 32] {
        self.deployment_manifest_hash
    }
    pub fn fee_token_config_hash(&self) -> [u8; 32] {
        self.fee_token_config_hash
    }
    pub fn fee_schedule_hash(&self) -> [u8; 32] {
        self.fee_schedule_hash
    }
}

/// keccak256 of the bytes returned by `eth_getCode`, with the fail-closed rule
/// from the live-chain sourcing contract §3 R1: **empty code is an error,
/// never `keccak256("")`**.
///
/// On-chain `EXTCODEHASH` distinguishes a non-existent account (`bytes32(0)`)
/// from an existing account with empty code
/// (`keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`).
/// `eth_getCode` collapses both to `0x`, so the attestor cannot tell them
/// apart and must treat either as unauthorized rather than hashing the empty
/// string and handing it to a comparison a manifest could be made to satisfy.
pub fn code_hash_from_get_code(code: &[u8]) -> Result<[u8; 32], ChainError> {
    if code.is_empty() {
        return Err(ChainError::Msg(
            "eth_getCode returned empty code: the address has no deployed bytecode \
             (or self-destructed); refusing to hash the empty string \
             (live-chain sourcing contract R1)"
                .into(),
        ));
    }
    Ok(keccak256(code))
}

/// First 4 bytes of keccak256(signature).
pub fn selector(sig: &str) -> [u8; 4] {
    let h = keccak256(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

pub fn encode_propose_batch(epoch: u64, merkle_root: [u8; 32], evidence_ref: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 3);
    out.extend_from_slice(&selector("proposeBatch(uint256,bytes32,bytes32)"));
    out.extend_from_slice(&u256_be(epoch as u128));
    out.extend_from_slice(&merkle_root);
    out.extend_from_slice(&evidence_ref);
    out
}

pub fn encode_challenge_batch(epoch: u64, counter_evidence_ref: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 2);
    out.extend_from_slice(&selector("challengeBatch(uint256,bytes32)"));
    out.extend_from_slice(&u256_be(epoch as u128));
    out.extend_from_slice(&counter_evidence_ref);
    out
}

pub fn encode_confirm_epoch(epoch: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&selector("confirmEpoch(uint256)"));
    out.extend_from_slice(&u256_be(epoch as u128));
    out
}

pub fn encode_bind_with_signature(
    wallet: [u8; 20],
    username: &str,
    deadline: u64,
    signature: &[u8],
) -> Vec<u8> {
    // Full ABI: bindWithSignature(address,string,uint256,bytes)
    let mut out = Vec::new();
    out.extend_from_slice(&selector("bindWithSignature(address,string,uint256,bytes)"));
    // Head: address, offset(string), deadline, offset(bytes)
    out.extend_from_slice(&address_word(&wallet));
    // 4 head words → string data starts at 0x80
    out.extend_from_slice(&u256_be(0x80));
    out.extend_from_slice(&u256_be(deadline as u128));
    let string_tail = abi_encode_bytes(username.as_bytes());
    // bytes offset = 0x80 + string_tail.len()
    out.extend_from_slice(&u256_be((0x80 + string_tail.len()) as u128));
    out.extend_from_slice(&string_tail);
    out.extend_from_slice(&abi_encode_bytes(signature));
    out
}

pub fn encode_enroll_self_with_signature(
    wallet: [u8; 20],
    deadline: u64,
    signature: &[u8],
) -> Vec<u8> {
    // Full ABI: enrollSelfWithSignature(address,uint256,bytes)
    let mut out = Vec::new();
    out.extend_from_slice(&selector("enrollSelfWithSignature(address,uint256,bytes)"));
    out.extend_from_slice(&address_word(&wallet));
    out.extend_from_slice(&u256_be(deadline as u128));
    // 3 head words → bytes data at 0x60
    out.extend_from_slice(&u256_be(0x60));
    out.extend_from_slice(&abi_encode_bytes(signature));
    out
}

/// Calldata for `batches(uint256)` public getter.
pub fn encode_batches(epoch: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&selector("batches(uint256)"));
    out.extend_from_slice(&u256_be(epoch as u128));
    out
}

/// Calldata for `hasBaseline(address)`.
pub fn encode_has_baseline(wallet: [u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&selector("hasBaseline(address)"));
    out.extend_from_slice(&address_word(&wallet));
    out
}

/// Calldata for `lastClaimedCumulative(address)`.
pub fn encode_last_claimed_cumulative(wallet: [u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&selector("lastClaimedCumulative(address)"));
    out.extend_from_slice(&address_word(&wallet));
    out
}

/// Calldata for `nonces(address)` (WorkerBinding / EnrollmentRegistry).
pub fn encode_nonces(wallet: [u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&selector("nonces(address)"));
    out.extend_from_slice(&address_word(&wallet));
    out
}

pub fn encode_finalize_batch(epoch: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&selector("finalizeBatch(uint256)"));
    out.extend_from_slice(&u256_be(epoch as u128));
    out
}

/// `claimPayout(uint256 epoch, address worker, uint256 provenCumulativeScore, bytes32[] proof)`
pub fn encode_claim_payout(
    epoch: u64,
    worker: [u8; 20],
    proven_score: u128,
    proof: &[[u8; 32]],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&selector("claimPayout(uint256,address,uint256,bytes32[])"));
    // Head: epoch, worker, score, offset → proof data at 0x80
    out.extend_from_slice(&u256_be(epoch as u128));
    out.extend_from_slice(&address_word(&worker));
    out.extend_from_slice(&u256_be(proven_score));
    out.extend_from_slice(&u256_be(0x80));
    // Dynamic bytes32[]: length + elements
    out.extend_from_slice(&u256_be(proof.len() as u128));
    for p in proof {
        out.extend_from_slice(p);
    }
    out
}

/// Calldata for `FeeTokenRegistry.getTokenConfig(address)` (Stream G G1).
pub fn encode_get_token_config(token: [u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&selector(SIG_GET_TOKEN_CONFIG));
    out.extend_from_slice(&address_word(&token));
    out
}

/// Calldata for `FeeTokenRegistry.getTokenConfigHash(address)` (Stream G G1).
pub fn encode_get_token_config_hash(token: [u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&selector(SIG_GET_TOKEN_CONFIG_HASH));
    out.extend_from_slice(&address_word(&token));
    out
}

/// Calldata for `FeeTokenRegistry.activeManifestHash()` (Stream G G1).
/// No arguments — the calldata is exactly the 4 selector bytes.
pub fn encode_active_manifest_hash() -> Vec<u8> {
    selector(SIG_ACTIVE_MANIFEST_HASH).to_vec()
}

/// Calldata for
/// `GoatRelayGateway.secondaryEnrollmentNonceSnapshot(address root, address secondary, address feeToken)`
/// (Stream G G1). Argument order matches the Solidity declaration
/// (`GoatRelayGateway.sol:201`) and is pinned by calldata-body test.
pub fn encode_secondary_enrollment_nonce_snapshot(
    root: [u8; 20],
    secondary: [u8; 20],
    fee_token: [u8; 20],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 3);
    out.extend_from_slice(&selector(SIG_SECONDARY_ENROLLMENT_NONCE_SNAPSHOT));
    out.extend_from_slice(&address_word(&root));
    out.extend_from_slice(&address_word(&secondary));
    out.extend_from_slice(&address_word(&fee_token));
    out
}

fn address_word(wallet: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(wallet);
    w
}

/// ABI-encode a dynamic `bytes` / `string` tail (length word + data + right-pad to 32).
fn abi_encode_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + data.len() + 32);
    out.extend_from_slice(&u256_be(data.len() as u128));
    out.extend_from_slice(data);
    let pad = (32 - (data.len() % 32)) % 32;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

fn u256_be(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

/// Decode `batches(uint256)` return: 10 static fields × 32 bytes.
pub fn decode_batch_return(data: &[u8]) -> Result<BatchView, ChainError> {
    if data.len() < 320 {
        return Err(ChainError::Msg(format!(
            "batches() return too short: {} bytes (need 320)",
            data.len()
        )));
    }
    let word = |i: usize| &data[i * 32..(i + 1) * 32];
    let mut proposer = [0u8; 20];
    proposer.copy_from_slice(&word(0)[12..]);
    let proposer_bond = u128_from_word(word(1))?;
    let mut challenger = [0u8; 20];
    challenger.copy_from_slice(&word(2)[12..]);
    let challenger_bond = u128_from_word(word(3))?;
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(word(4));
    let rate = u128_from_word(word(5))?;
    let mut evidence_ref = [0u8; 32];
    evidence_ref.copy_from_slice(word(6));
    let challenge_deadline = u64_from_word(word(7));
    let watcher_confirmed_at = u64_from_word(word(8));
    let status = match word(9)[31] {
        0 => BatchStatus::None,
        1 => BatchStatus::Proposed,
        2 => BatchStatus::Challenged,
        3 => BatchStatus::ProposerWon,
        4 => BatchStatus::ChallengerWon,
        5 => BatchStatus::Finalized,
        other => {
            return Err(ChainError::Msg(format!(
                "unknown batch status byte {other}"
            )));
        }
    };
    Ok(BatchView {
        proposer,
        proposer_bond,
        challenger,
        challenger_bond,
        merkle_root,
        rate,
        evidence_ref,
        challenge_deadline,
        watcher_confirmed_at,
        status,
    })
}

// ---------------------------------------------------------------------------
// Stream G G1 — ABI word narrowers.
//
// Every one of these REJECTS an out-of-range value rather than truncating it
// (the precedent `u128_from_word` / `stream_g::base_fee` already set). These
// words feed the token-capability gate: a silently truncated `capabilityMask`
// or a masked-off dirty address word would defeat the very check they exist
// to supply. `what` names the field for the error message only.
// ---------------------------------------------------------------------------

fn sg_u128_from_word(w: &[u8], what: &str) -> Result<u128, ChainError> {
    if w[..16].iter().any(|&b| b != 0) {
        return Err(ChainError::Msg(format!(
            "{what}: uint256 value does not fit in u128 (refusing to truncate)"
        )));
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(&w[16..]);
    Ok(u128::from_be_bytes(b))
}

fn sg_u64_from_word(w: &[u8], what: &str) -> Result<u64, ChainError> {
    if w[..24].iter().any(|&b| b != 0) {
        return Err(ChainError::Msg(format!(
            "{what}: value does not fit in u64 (refusing to truncate)"
        )));
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&w[24..]);
    Ok(u64::from_be_bytes(b))
}

fn sg_u32_from_word(w: &[u8], what: &str) -> Result<u32, ChainError> {
    if w[..28].iter().any(|&b| b != 0) {
        return Err(ChainError::Msg(format!(
            "{what}: value does not fit in u32 (refusing to truncate)"
        )));
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&w[28..]);
    Ok(u32::from_be_bytes(b))
}

fn sg_u8_from_word(w: &[u8], what: &str) -> Result<u8, ChainError> {
    if w[..31].iter().any(|&b| b != 0) {
        return Err(ChainError::Msg(format!(
            "{what}: value does not fit in u8 (refusing to truncate)"
        )));
    }
    Ok(w[31])
}

fn sg_bool_from_word(w: &[u8], what: &str) -> Result<bool, ChainError> {
    if w[..31].iter().any(|&b| b != 0) || w[31] > 1 {
        return Err(ChainError::Msg(format!(
            "{what}: not a canonical ABI bool (word is neither 0 nor 1)"
        )));
    }
    Ok(w[31] == 1)
}

fn sg_address_from_word(w: &[u8], what: &str) -> Result<[u8; 20], ChainError> {
    if w[..12].iter().any(|&b| b != 0) {
        return Err(ChainError::Msg(format!(
            "{what}: address word has non-zero bytes above the low 20 (refusing to mask)"
        )));
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&w[12..]);
    Ok(a)
}

fn sg_bytes32_from_word(w: &[u8]) -> [u8; 32] {
    let mut b = [0u8; 32];
    b.copy_from_slice(w);
    b
}

/// Decode a `FeeTokenRegistry.getTokenConfig(address)` return
/// (`StreamGTypes.FeeTokenConfig`, `StreamGTypes.sol:292`): 11 static fields
/// × 32 bytes, encoded inline from offset 0.
pub fn decode_fee_token_config_return(data: &[u8]) -> Result<FeeTokenConfigView, ChainError> {
    if data.len() < FEE_TOKEN_CONFIG_RETURN_LEN {
        return Err(ChainError::Msg(format!(
            "getTokenConfig() return too short: {} bytes (need {FEE_TOKEN_CONFIG_RETURN_LEN})",
            data.len()
        )));
    }
    let word = |i: usize| &data[i * 32..(i + 1) * 32];
    Ok(FeeTokenConfigView {
        chain_id: sg_u64_from_word(word(0), "FeeTokenConfig.chainId")?,
        token: sg_address_from_word(word(1), "FeeTokenConfig.token")?,
        runtime_code_hash: sg_bytes32_from_word(word(2)),
        proxy_identity_hash: sg_bytes32_from_word(word(3)),
        capability_mask: sg_u128_from_word(word(4), "FeeTokenConfig.capabilityMask")?,
        decimals: sg_u8_from_word(word(5), "FeeTokenConfig.decimals")?,
        domain_name_hash: sg_bytes32_from_word(word(6)),
        domain_version_hash: sg_bytes32_from_word(word(7)),
        built_in_mode_id: sg_bytes32_from_word(word(8)),
        config_version: sg_u64_from_word(word(9), "FeeTokenConfig.configVersion")?,
        active: sg_bool_from_word(word(10), "FeeTokenConfig.active")?,
    })
}

/// Decode a `GoatRelayGateway.secondaryEnrollmentNonceSnapshot(...)` return
/// (`StreamGTypes.NonceSnapshot`, `StreamGTypes.sol:351`): 14 static fields ×
/// 32 bytes, inline from offset 0.
///
/// The field order below is the Solidity **declaration** order, in which
/// `presentMask` (word 10) comes BEFORE the three hashes (words 11-13).
pub fn decode_nonce_snapshot_return(data: &[u8]) -> Result<NonceSnapshotView, ChainError> {
    if data.len() < NONCE_SNAPSHOT_RETURN_LEN {
        return Err(ChainError::Msg(format!(
            "secondaryEnrollmentNonceSnapshot() return too short: {} bytes \
             (need {NONCE_SNAPSHOT_RETURN_LEN})",
            data.len()
        )));
    }
    let word = |i: usize| &data[i * 32..(i + 1) * 32];
    Ok(NonceSnapshotView {
        block_number: sg_u64_from_word(word(0), "NonceSnapshot.blockNumber")?,
        action_nonce: sg_u128_from_word(word(1), "NonceSnapshot.actionNonce")?,
        v1_enroll_nonce: sg_u128_from_word(word(2), "NonceSnapshot.v1EnrollNonce")?,
        link_nonce: sg_u128_from_word(word(3), "NonceSnapshot.linkNonce")?,
        root_registration_nonce: sg_u128_from_word(word(4), "NonceSnapshot.rootRegistrationNonce")?,
        rotation_nonce: sg_u128_from_word(word(5), "NonceSnapshot.rotationNonce")?,
        controller_epoch: sg_u128_from_word(word(6), "NonceSnapshot.controllerEpoch")?,
        controller: sg_address_from_word(word(7), "NonceSnapshot.controller")?,
        goat_permit_nonce: sg_u128_from_word(word(8), "NonceSnapshot.goatPermitNonce")?,
        fee_token_permit_nonce: sg_u128_from_word(word(9), "NonceSnapshot.feeTokenPermitNonce")?,
        present_mask: sg_u32_from_word(word(10), "NonceSnapshot.presentMask")?,
        deployment_manifest_hash: sg_bytes32_from_word(word(11)),
        fee_token_config_hash: sg_bytes32_from_word(word(12)),
        fee_schedule_hash: sg_bytes32_from_word(word(13)),
    })
}

pub(crate) fn u128_from_word(w: &[u8]) -> Result<u128, ChainError> {
    // Reject non-zero high 128 bits so we never silently truncate.
    if w[..16].iter().any(|&b| b != 0) {
        return Err(ChainError::Msg(
            "uint256 value does not fit in u128 (bond/rate too large)".into(),
        ));
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(&w[16..]);
    Ok(u128::from_be_bytes(b))
}

fn u64_from_word(w: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&w[24..]);
    u64::from_be_bytes(b)
}

/// Parse 0x-hex address string into 20 bytes (used by callers before RPC).
pub fn parse_address20(s: &str) -> Result<[u8; 20], ChainError> {
    let s = s.trim();
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.len() != 40 {
        return Err(ChainError::Msg(format!(
            "address must be 20 bytes (40 hex chars), got len {}",
            hex.len()
        )));
    }
    let bytes = hex::decode(hex).map_err(|e| ChainError::Msg(format!("bad address hex: {e}")))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Recorded mock operation for assertions.
#[derive(Debug, Clone)]
pub enum MockOp {
    Propose {
        epoch: u64,
        merkle_root: [u8; 32],
        evidence_ref: [u8; 32],
        bond_wei: u128,
    },
    Challenge {
        epoch: u64,
        counter_evidence_ref: [u8; 32],
        bond_wei: u128,
    },
    Confirm {
        epoch: u64,
    },
    Bind {
        wallet: [u8; 20],
        username: String,
        deadline: u64,
    },
    Enroll {
        wallet: [u8; 20],
        deadline: u64,
    },
    Claim {
        epoch: u64,
        worker: [u8; 20],
        proven_score: u128,
    },
    /// `gas_oracle_l1_fee` call (Base fee decomposition, hazard 1 —
    /// Task 5). Records the queried tx length, not its contents.
    L1Fee {
        unsigned_tx_len: usize,
    },
    /// `gas_oracle_l1_fee_upper_bound` call (Task 5).
    L1FeeUpperBound {
        unsigned_tx_size: u64,
    },
    /// `gas_oracle_operator_fee` call (Task 5).
    OperatorFee {
        gas_limit: u64,
    },
    /// `fee_token_code_hash` call (Stream G G1, Task 6 Wave A). Recorded on
    /// every attempt, including ones that fail closed.
    FeeTokenCodeHash {
        token: [u8; 20],
        block: u64,
    },
    /// `fee_token_config` call (Stream G G1).
    FeeTokenConfig {
        registry: [u8; 20],
        token: [u8; 20],
        block: u64,
    },
    /// `fee_token_config_hash` call (Stream G G1).
    FeeTokenConfigHash {
        registry: [u8; 20],
        token: [u8; 20],
        block: u64,
    },
    /// `active_manifest_hash` call (Stream G G1).
    ActiveManifestHash {
        registry: [u8; 20],
        block: u64,
    },
    /// `secondary_enrollment_nonce_snapshot` call (Stream G G1).
    SecondaryEnrollmentNonceSnapshot {
        gateway: [u8; 20],
        root: [u8; 20],
        secondary: [u8; 20],
        fee_token: [u8; 20],
        block: u64,
    },
    /// `pinned_block_number` call (Stream G G1).
    PinnedBlockNumber,
    /// `erc2612_nonces` call (Stream G G1, Task 8 Mandate 3). Recorded with
    /// its `block` so `state_read_pins_every_read_to_one_block` covers this
    /// read too — a state read that pinned four of its five calls and let one
    /// float would defeat sourcing contract R4 while every other test passed.
    Erc2612Nonces {
        token: [u8; 20],
        owner: [u8; 20],
        block: u64,
    },
    /// `chain_id` (`eth_chainId`) call (Stream G G1, Task 6 Wave A).
    /// Recorded on every attempt, including ones that fail closed, so a test
    /// can prove the value came from a chain read rather than from config.
    ChainId,
}

/// `MockChain` key for a stored `secondaryEnrollmentNonceSnapshot` return:
/// `(gateway, root, secondary, fee_token)`.
type MockSnapshotKey = ([u8; 20], [u8; 20], [u8; 20], [u8; 20]);

/// `MockChain` key for a stored per-token registry read: `(registry, token)`.
type MockRegistryTokenKey = ([u8; 20], [u8; 20]);

/// `MockChain` key for a stored ERC-2612 `nonces(owner)` read on a token:
/// `(token, owner)`. Structurally identical to [`MockRegistryTokenKey`] but
/// deliberately a distinct alias — the two are indexed by different things
/// and a shared name is how a test ends up arming the wrong map.
type MockTokenOwnerKey = ([u8; 20], [u8; 20]);

#[derive(Debug, Default)]
struct MockInner {
    batches: HashMap<u64, BatchView>,
    /// wallet lowercase hex → hasBaseline
    baselines: HashMap<String, bool>,
    /// wallet lowercase hex → lastClaimedCumulative
    last_claimed: HashMap<String, u128>,
    /// wallet lowercase 0x-hex → username (from bind_with_signature)
    bounds: HashMap<String, String>,
    /// Force has_baseline to return Err for these wallets (lowercase keys).
    force_baseline_err: HashSet<String>,
    /// Force last_claimed_cumulative to return Err for these wallets (lowercase keys).
    force_last_claimed_err: HashSet<String>,
    ops: Vec<MockOp>,
    tx_counter: u64,
    now: u64,
    proposer_bond: u128,
    challenger_bond: u128,
    challenge_window: u64,
    /// wallet (as given) → native ETH/wei balance.
    eth_balances: HashMap<String, u128>,
    /// wei/gas.
    gas_price_wei: u128,
    /// Recorded `send_native(to, amount_wei)` calls, in call order.
    sent: Vec<(String, u128)>,
    /// (token, wallet) → ERC-20 balanceOf.
    erc20_balances: HashMap<(String, String), u128>,
    /// Override for `relayer_address()`. `None` → `DEFAULT_MOCK_RELAYER_ADDRESS`.
    relayer_address: Option<String>,
    /// When `Some`, `send_native` returns `Err(ChainError::Msg(_))` with this
    /// message instead of recording a send. `None` (default) → succeeds.
    send_native_error: Option<String>,
    /// wallet lowercase 0x-hex → WorkerBinding.nonces
    binding_nonces: HashMap<String, u64>,
    /// wallet lowercase 0x-hex → EnrollmentRegistry.nonces
    enrollment_nonces: HashMap<String, u64>,
    /// Deterministic `GasPriceOracle.getL1Fee` return (Task 5).
    l1_exact_fee_wei: u128,
    /// Deterministic `GasPriceOracle.getL1FeeUpperBound` return (Task 5).
    l1_upper_fee_wei: u128,
    /// Deterministic `GasPriceOracle.getOperatorFee` return (Task 5).
    operator_fee_wei: u128,
    /// When `Some`, all three `gas_oracle_*` methods return
    /// `Err(ChainError::Msg(_))` with this message instead of a reserve
    /// value (Task 5 hardening M5 — exercises `BaseFeeError::Chain`, the
    /// fail-closed-on-RPC-failure path, which previously had zero
    /// coverage since these methods could never return `Err`).
    gas_oracle_error: Option<String>,
    // -- Stream G G1 live-chain sourcing (Task 6 Wave A) ------------------
    // Every one of these is keyed, and a MISSING key produces `Err`, never a
    // zeroed struct — same fail-closed reasoning as the trait's `Err`
    // defaults: a test that forgets to arm a read must not silently see a
    // zero capability mask or a zero nonce.
    /// token → deployed bytecode as `eth_getCode` would return it. An empty
    /// `Vec` is deliberately storable so tests can exercise R1's fail-closed
    /// empty-code path.
    fee_token_code: HashMap<[u8; 20], Vec<u8>>,
    /// (registry, token) → `getTokenConfig` return.
    fee_token_configs: HashMap<MockRegistryTokenKey, FeeTokenConfigView>,
    /// (registry, token) → `getTokenConfigHash` return.
    fee_token_config_hashes: HashMap<MockRegistryTokenKey, [u8; 32]>,
    /// registry → `activeManifestHash` return.
    active_manifest_hashes: HashMap<[u8; 20], [u8; 32]>,
    /// (gateway, root, secondary, fee_token) → snapshot return.
    nonce_snapshots: HashMap<MockSnapshotKey, NonceSnapshotView>,
    /// `eth_blockNumber`. `None` → `Err`, never a silent block 0 (block 0 is
    /// a real, valid block number, so `0` cannot double as "unset").
    pinned_block: Option<u64>,
    /// `eth_chainId`. `None` → `Err`, never a silent chain 0. Deliberately an
    /// `Option<u64>` rather than a plain `u64` for the same reason as
    /// `pinned_block`: a test that forgets to arm this read must fail loudly,
    /// not feed a zero into the token-capability gate's chain-id check.
    chain_id: Option<u64>,
    // -- Stream G G1 (Task 8 Mandate 3) -----------------------------------
    /// block number → `eth_getBlockByNumber(n).timestamp`. A MISSING key is
    /// an `Err`, never `Ok(0)`: 0 is 1970 and 1970 passes every deadline
    /// comparison in the crate. Deliberately keyed by block rather than a
    /// single scalar, so a test can arm the PINNED block with one value and
    /// leave `now` (the floating `block_timestamp()`) at another — which is
    /// how `state_read_takes_chain_time_from_the_pinned_block` proves the
    /// preflight state read is pinned and not floating.
    block_timestamps: HashMap<u64, u64>,
    /// (token, owner) → ERC-2612 `nonces(owner)`. A MISSING key is an `Err`,
    /// never `Ok(0)` — `Ok(0)` reads as "this owner has never permitted
    /// anything", which is a positive claim a permit check acts on.
    erc2612_nonces: HashMap<MockTokenOwnerKey, u64>,
    // -- Stream G broadcast path (Wave C W2) -------------------------------
    /// `eth_sendRawTransaction`. `None` (the default) keeps the
    /// [`ChainClient`] trait's own "not supported" `Err`, so arming this is
    /// opt-in and no existing test's behaviour changes by this field
    /// existing. `Some(Err(msg))` is the send-failed shape
    /// `outbox::reserve_persist_and_send` turns into
    /// `SendOutcome::SendFailedStuckRecoverable`.
    raw_send_result: Option<Result<TxHash, String>>,
    /// Every payload handed to `send_raw_transaction`, in call order. The
    /// count is what "was anything broadcast?" assertions read now that the
    /// send belongs to the chain client rather than to a broadcaster double.
    raw_sends: Vec<Vec<u8>>,
    /// address → `eth_getTransactionCount(addr, _)`. A MISSING key is an
    /// `Err`, never `Ok(0)`: `0` is a real nonce for a fresh account, so it
    /// cannot double as "unset", and `broadcaster::allocate_broadcaster_nonce`
    /// fails closed on the `Err` rather than guessing a frontier.
    transaction_counts: HashMap<[u8; 20], u64>,
}

/// Default relayer wallet address returned by `MockChain::relayer_address()`
/// when not overridden via `set_relayer_address`. Arbitrary but stable —
/// tests can reference it directly (e.g. `set_eth_balance(RELAYER_ADDR, ..)`)
/// without having to call the setter first.
pub const DEFAULT_MOCK_RELAYER_ADDRESS: &str = "0x00000000000000000000000000000000000000aa";

/// In-memory chain used by unit tests and `GOAT_ATTESTOR_MOCK=1`.
#[derive(Debug, Default)]
pub struct MockChain {
    inner: Mutex<MockInner>,
}

impl MockChain {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(MockInner {
                now: 1_700_000_000,
                proposer_bond: 1_000_000_000_000_000_000,
                challenger_bond: 1_000_000_000_000_000_000,
                challenge_window: 3600,
                ..Default::default()
            }),
        }
    }

    pub fn with_bonds(self, proposer: u128, challenger: u128) -> Self {
        let mut g = self.inner.lock().unwrap();
        g.proposer_bond = proposer;
        g.challenger_bond = challenger;
        drop(g);
        self
    }

    pub fn ops(&self) -> Vec<MockOp> {
        self.inner.lock().unwrap().ops.clone()
    }

    pub fn set_now(&self, now: u64) {
        self.inner.lock().unwrap().now = now;
    }

    /// Test helper: mark on-chain baseline status for a wallet (0x-hex).
    pub fn set_has_baseline(&self, wallet: &str, has: bool) {
        let key = wallet.to_ascii_lowercase();
        self.inner.lock().unwrap().baselines.insert(key, has);
    }

    /// Test helper: set on-chain lastClaimedCumulative for a wallet (0x-hex).
    pub fn set_last_claimed_cumulative(&self, wallet: &str, value: u128) {
        let key = wallet.to_ascii_lowercase();
        self.inner.lock().unwrap().last_claimed.insert(key, value);
    }

    /// Test helper: force `has_baseline` to return Err for this wallet.
    pub fn set_force_has_baseline_err(&self, wallet: &str, force: bool) {
        let key = wallet.to_ascii_lowercase();
        let mut g = self.inner.lock().unwrap();
        if force {
            g.force_baseline_err.insert(key);
        } else {
            g.force_baseline_err.remove(&key);
        }
    }

    /// Test helper: force `last_claimed_cumulative` to return Err for this wallet.
    pub fn set_force_last_claimed_err(&self, wallet: &str, force: bool) {
        let key = wallet.to_ascii_lowercase();
        let mut g = self.inner.lock().unwrap();
        if force {
            g.force_last_claimed_err.insert(key);
        } else {
            g.force_last_claimed_err.remove(&key);
        }
    }

    /// Test helper: set native ETH/wei balance for `wallet`.
    pub fn set_eth_balance(&self, wallet: &str, balance_wei: u128) {
        self.inner
            .lock()
            .unwrap()
            .eth_balances
            .insert(wallet.to_ascii_lowercase(), balance_wei);
    }

    /// Test helper: set the gas price (wei/gas) returned by `gas_price`.
    pub fn set_gas_price(&self, price_wei: u128) {
        self.inner.lock().unwrap().gas_price_wei = price_wei;
    }

    /// Test helper: set ERC-20 `balanceOf(wallet)` for `token`.
    pub fn set_erc20_balance(&self, token: &str, wallet: &str, balance: u128) {
        self.inner.lock().unwrap().erc20_balances.insert(
            (token.to_ascii_lowercase(), wallet.to_ascii_lowercase()),
            balance,
        );
    }

    /// Test helper: `(to, amount_wei)` pairs recorded by `send_native`, in call order.
    pub fn sent_native(&self) -> Vec<(String, u128)> {
        self.inner.lock().unwrap().sent.clone()
    }

    /// Test helper: override the address returned by `relayer_address()`
    /// (default: `DEFAULT_MOCK_RELAYER_ADDRESS`).
    pub fn set_relayer_address(&self, addr: &str) {
        self.inner.lock().unwrap().relayer_address = Some(addr.to_string());
    }

    /// Test helper: force `send_native` to fail with `ChainError::Msg(msg)`
    /// (pass `None` to clear the override and let sends succeed again).
    /// Lets tests exercise the "quota reserved but send failed" path (FIX-A)
    /// without a real chain.
    pub fn set_send_native_error(&self, msg: Option<String>) {
        self.inner.lock().unwrap().send_native_error = msg;
    }

    /// Test helper: set `WorkerBinding.nonces(wallet)`.
    pub fn set_binding_nonce(&self, wallet: &str, nonce: u64) {
        let key = wallet.to_ascii_lowercase();
        self.inner.lock().unwrap().binding_nonces.insert(key, nonce);
    }

    /// Test helper: set `EnrollmentRegistry.nonces(wallet)`.
    pub fn set_enrollment_nonce(&self, wallet: &str, nonce: u64) {
        let key = wallet.to_ascii_lowercase();
        self.inner
            .lock()
            .unwrap()
            .enrollment_nonces
            .insert(key, nonce);
    }

    /// Test helper: set the deterministic `getL1Fee` return (Task 5, hazard 1).
    pub fn set_l1_exact_fee_wei(&self, wei: u128) {
        self.inner.lock().unwrap().l1_exact_fee_wei = wei;
    }

    /// Test helper: set the deterministic `getL1FeeUpperBound` return (Task 5).
    pub fn set_l1_upper_fee_wei(&self, wei: u128) {
        self.inner.lock().unwrap().l1_upper_fee_wei = wei;
    }

    /// Test helper: set the deterministic `getOperatorFee` return (Task 5).
    pub fn set_operator_fee_wei(&self, wei: u128) {
        self.inner.lock().unwrap().operator_fee_wei = wei;
    }

    /// Test helper: force all three `gas_oracle_*` methods to return
    /// `Err(ChainError::Msg(msg))` (pass `None` to clear the override and
    /// let them succeed again). Exercises the fail-closed-on-RPC-failure
    /// path (Task 5 hardening M5) without a real chain.
    pub fn set_gas_oracle_error(&self, msg: Option<String>) {
        self.inner.lock().unwrap().gas_oracle_error = msg;
    }

    /// Test helper: number of `gas_oracle_l1_fee` calls recorded so far.
    pub fn l1_fee_call_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap()
            .ops
            .iter()
            .filter(|op| matches!(op, MockOp::L1Fee { .. }))
            .count()
    }

    /// Test helper: number of `gas_oracle_l1_fee_upper_bound` calls recorded so far.
    pub fn l1_fee_upper_bound_call_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap()
            .ops
            .iter()
            .filter(|op| matches!(op, MockOp::L1FeeUpperBound { .. }))
            .count()
    }

    /// Test helper: number of `gas_oracle_operator_fee` calls recorded so far.
    pub fn operator_fee_call_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap()
            .ops
            .iter()
            .filter(|op| matches!(op, MockOp::OperatorFee { .. }))
            .count()
    }

    // -- Stream G G1 live-chain sourcing setters (Task 6 Wave A) ----------

    /// Test helper: set the bytes `eth_getCode(token)` returns. Pass `&[]` to
    /// simulate an address with no deployed bytecode (which must then fail
    /// closed, per the live-chain sourcing contract R1).
    pub fn set_fee_token_code(&self, token: [u8; 20], code: &[u8]) {
        self.inner
            .lock()
            .unwrap()
            .fee_token_code
            .insert(token, code.to_vec());
    }

    /// Test helper: set the `getTokenConfig(token)` return for `registry`.
    pub fn set_fee_token_config(
        &self,
        registry: [u8; 20],
        token: [u8; 20],
        config: FeeTokenConfigView,
    ) {
        self.inner
            .lock()
            .unwrap()
            .fee_token_configs
            .insert((registry, token), config);
    }

    /// Test helper: set the `getTokenConfigHash(token)` return for `registry`.
    pub fn set_fee_token_config_hash(
        &self,
        registry: [u8; 20],
        token: [u8; 20],
        config_hash: [u8; 32],
    ) {
        self.inner
            .lock()
            .unwrap()
            .fee_token_config_hashes
            .insert((registry, token), config_hash);
    }

    /// Test helper: set the `activeManifestHash()` return for `registry`.
    pub fn set_active_manifest_hash(&self, registry: [u8; 20], manifest_hash: [u8; 32]) {
        self.inner
            .lock()
            .unwrap()
            .active_manifest_hashes
            .insert(registry, manifest_hash);
    }

    /// Test helper: set the `secondaryEnrollmentNonceSnapshot` return.
    pub fn set_nonce_snapshot(
        &self,
        gateway: [u8; 20],
        root: [u8; 20],
        secondary: [u8; 20],
        fee_token: [u8; 20],
        snapshot: NonceSnapshotView,
    ) {
        self.inner
            .lock()
            .unwrap()
            .nonce_snapshots
            .insert((gateway, root, secondary, fee_token), snapshot);
    }

    /// Test helper: set the `eth_blockNumber` return. Until this is called,
    /// `pinned_block_number()` returns `Err` rather than block 0.
    pub fn set_pinned_block_number(&self, block: u64) {
        self.inner.lock().unwrap().pinned_block = Some(block);
    }

    /// Test helper: set the `eth_chainId` return. Until this is called,
    /// `chain_id()` returns `Err` rather than chain 0 — so a test that wants
    /// to exercise the token gate's chain-id check has to state which chain
    /// the mock endpoint claims to be, and a test that forgets cannot
    /// accidentally satisfy the check with a zero on both sides.
    pub fn set_chain_id(&self, chain_id: u64) {
        self.inner.lock().unwrap().chain_id = Some(chain_id);
    }

    /// Test helper: set the `eth_getBlockByNumber(block).timestamp` return
    /// for ONE block (Task 8 Mandate 3). Until this is called for a given
    /// block, `block_timestamp_at(block)` returns `Err` rather than 0.
    ///
    /// This is intentionally not the same storage as [`MockChain::set_now`],
    /// which arms the floating `block_timestamp()`. Keeping them separate is
    /// what lets a test set them to DIFFERENT values and assert which one a
    /// caller actually consulted.
    pub fn set_block_timestamp_at(&self, block: u64, timestamp: u64) {
        self.inner
            .lock()
            .unwrap()
            .block_timestamps
            .insert(block, timestamp);
    }

    /// Test helper: set the ERC-2612 `nonces(owner)` return for `token`.
    /// Until this is called, `erc2612_nonces` returns `Err` rather than 0.
    pub fn set_erc2612_nonces(&self, token: [u8; 20], owner: [u8; 20], nonce: u64) {
        self.inner
            .lock()
            .unwrap()
            .erc2612_nonces
            .insert((token, owner), nonce);
    }

    /// Test helper (Wave C W2): arm `eth_sendRawTransaction`.
    ///
    /// Unarmed, `send_raw_transaction` keeps the [`ChainClient`] default's
    /// `Err`, so a test that forgets to arm it sees a send failure rather
    /// than a fabricated success.
    pub fn set_send_raw_transaction(&self, result: Result<TxHash, String>) {
        self.inner.lock().unwrap().raw_send_result = Some(result);
    }

    /// Test helper (Wave C W2): the raw payloads handed to
    /// `send_raw_transaction`, in call order. `.len()` is the send count.
    pub fn raw_sends(&self) -> Vec<Vec<u8>> {
        self.inner.lock().unwrap().raw_sends.clone()
    }

    /// Test helper (Wave C W2): arm `eth_getTransactionCount` for one
    /// address. Keyed by address rather than global, so a test cannot get the
    /// broadcaster EOA's frontier from an arming intended for some other
    /// account.
    pub fn set_transaction_count(&self, addr: [u8; 20], count: u64) {
        self.inner
            .lock()
            .unwrap()
            .transaction_counts
            .insert(addr, count);
    }

    fn stream_g_op_count(&self, pred: fn(&MockOp) -> bool) -> usize {
        self.inner
            .lock()
            .unwrap()
            .ops
            .iter()
            .filter(|op| pred(op))
            .count()
    }

    /// Test helper: number of `fee_token_code_hash` calls attempted so far.
    pub fn fee_token_code_hash_call_count(&self) -> usize {
        self.stream_g_op_count(|op| matches!(op, MockOp::FeeTokenCodeHash { .. }))
    }

    /// Test helper: number of `fee_token_config` calls attempted so far.
    pub fn fee_token_config_call_count(&self) -> usize {
        self.stream_g_op_count(|op| matches!(op, MockOp::FeeTokenConfig { .. }))
    }

    /// Test helper: number of `fee_token_config_hash` calls attempted so far.
    pub fn fee_token_config_hash_call_count(&self) -> usize {
        self.stream_g_op_count(|op| matches!(op, MockOp::FeeTokenConfigHash { .. }))
    }

    /// Test helper: number of `active_manifest_hash` calls attempted so far.
    pub fn active_manifest_hash_call_count(&self) -> usize {
        self.stream_g_op_count(|op| matches!(op, MockOp::ActiveManifestHash { .. }))
    }

    /// Test helper: number of `secondary_enrollment_nonce_snapshot` calls
    /// attempted so far. R3 requires exactly ONE per quote — this counter is
    /// how a test proves the two-independent-reads shape did not creep back.
    pub fn secondary_enrollment_nonce_snapshot_call_count(&self) -> usize {
        self.stream_g_op_count(|op| matches!(op, MockOp::SecondaryEnrollmentNonceSnapshot { .. }))
    }

    /// Test helper: number of `pinned_block_number` calls so far.
    pub fn pinned_block_number_call_count(&self) -> usize {
        self.stream_g_op_count(|op| matches!(op, MockOp::PinnedBlockNumber))
    }

    /// Test helper: number of `chain_id` (`eth_chainId`) calls so far. This
    /// counter is what lets a test assert the chain id the gate compared
    /// against was *read*, rather than lifted out of the config or out of the
    /// `FeeTokenConfig` the gate is checking.
    pub fn chain_id_call_count(&self) -> usize {
        self.stream_g_op_count(|op| matches!(op, MockOp::ChainId))
    }

    fn next_tx(inner: &mut MockInner) -> TxHash {
        inner.tx_counter += 1;
        let mut h = [0u8; 32];
        h[24..].copy_from_slice(&inner.tx_counter.to_be_bytes());
        h
    }
}

impl ChainClient for MockChain {
    fn propose_batch(
        &self,
        epoch: u64,
        merkle_root: [u8; 32],
        evidence_ref: [u8; 32],
        bond_wei: u128,
    ) -> Result<TxHash, ChainError> {
        let mut g = self.inner.lock().unwrap();
        if bond_wei != g.proposer_bond {
            return Err(ChainError::BondMismatch {
                expected: g.proposer_bond,
                got: bond_wei,
            });
        }
        let existing = g.batches.get(&epoch);
        if let Some(b) = existing {
            if !epoch_open_for_propose(b.status) {
                return Err(ChainError::WrongStatus { epoch });
            }
        }
        let view = BatchView {
            proposer: [0xAA; 20],
            proposer_bond: bond_wei,
            challenger: [0u8; 20],
            challenger_bond: 0,
            merkle_root,
            rate: 1,
            evidence_ref,
            challenge_deadline: g.now + g.challenge_window,
            watcher_confirmed_at: 0,
            status: BatchStatus::Proposed,
        };
        g.batches.insert(epoch, view);
        g.ops.push(MockOp::Propose {
            epoch,
            merkle_root,
            evidence_ref,
            bond_wei,
        });
        Ok(Self::next_tx(&mut g))
    }

    fn challenge_batch(
        &self,
        epoch: u64,
        counter_evidence_ref: [u8; 32],
        bond_wei: u128,
    ) -> Result<TxHash, ChainError> {
        let mut g = self.inner.lock().unwrap();
        if bond_wei != g.challenger_bond {
            return Err(ChainError::BondMismatch {
                expected: g.challenger_bond,
                got: bond_wei,
            });
        }
        let batch = g
            .batches
            .get_mut(&epoch)
            .ok_or(ChainError::NotFound(epoch))?;
        if batch.status != BatchStatus::Proposed {
            return Err(ChainError::WrongStatus { epoch });
        }
        batch.status = BatchStatus::Challenged;
        batch.challenger = [0xCC; 20];
        batch.challenger_bond = bond_wei;
        g.ops.push(MockOp::Challenge {
            epoch,
            counter_evidence_ref,
            bond_wei,
        });
        Ok(Self::next_tx(&mut g))
    }

    fn confirm_epoch(&self, epoch: u64) -> Result<TxHash, ChainError> {
        let mut g = self.inner.lock().unwrap();
        let now = g.now;
        let batch = g
            .batches
            .get_mut(&epoch)
            .ok_or(ChainError::NotFound(epoch))?;
        if batch.status != BatchStatus::Proposed {
            return Err(ChainError::WrongStatus { epoch });
        }
        batch.watcher_confirmed_at = now;
        g.ops.push(MockOp::Confirm { epoch });
        Ok(Self::next_tx(&mut g))
    }

    fn get_batch(&self, epoch: u64) -> Result<BatchView, ChainError> {
        let g = self.inner.lock().unwrap();
        Ok(g.batches.get(&epoch).cloned().unwrap_or_default())
    }

    fn bind_with_signature(
        &self,
        wallet: [u8; 20],
        username: &str,
        deadline: u64,
        _signature: &[u8],
    ) -> Result<TxHash, ChainError> {
        let mut g = self.inner.lock().unwrap();
        let key = format!("0x{}", hex::encode(wallet));
        g.bounds.insert(key.clone(), username.to_string());
        // Mirror on-chain: nonces[wallet]++ on successful bind meta-tx.
        let n = g.binding_nonces.entry(key).or_insert(0);
        *n = n.saturating_add(1);
        g.ops.push(MockOp::Bind {
            wallet,
            username: username.to_string(),
            deadline,
        });
        Ok(Self::next_tx(&mut g))
    }

    fn list_bound_workers(&self) -> Result<Vec<BoundWorker>, ChainError> {
        let g = self.inner.lock().unwrap();
        Ok(g.bounds
            .iter()
            .map(|(wallet, username)| BoundWorker {
                wallet: wallet.clone(),
                username: username.clone(),
            })
            .collect())
    }

    fn enroll_self_with_signature(
        &self,
        wallet: [u8; 20],
        deadline: u64,
        _signature: &[u8],
    ) -> Result<TxHash, ChainError> {
        let mut g = self.inner.lock().unwrap();
        let key = format!("0x{}", hex::encode(wallet));
        let n = g.enrollment_nonces.entry(key).or_insert(0);
        *n = n.saturating_add(1);
        g.ops.push(MockOp::Enroll { wallet, deadline });
        Ok(Self::next_tx(&mut g))
    }

    fn binding_nonce(&self, wallet: &str) -> Result<u64, ChainError> {
        let key = wallet.to_ascii_lowercase();
        let g = self.inner.lock().unwrap();
        Ok(g.binding_nonces.get(&key).copied().unwrap_or(0))
    }

    fn enrollment_nonce(&self, wallet: &str) -> Result<u64, ChainError> {
        let key = wallet.to_ascii_lowercase();
        let g = self.inner.lock().unwrap();
        Ok(g.enrollment_nonces.get(&key).copied().unwrap_or(0))
    }

    fn has_baseline(&self, wallet: &str) -> Result<Option<bool>, ChainError> {
        let key = wallet.to_ascii_lowercase();
        let g = self.inner.lock().unwrap();
        if g.force_baseline_err.contains(&key) {
            return Err(ChainError::Msg(format!(
                "forced has_baseline error for {wallet}"
            )));
        }
        Ok(g.baselines.get(&key).copied())
    }

    fn last_claimed_cumulative(&self, wallet: &str) -> Result<Option<u128>, ChainError> {
        let key = wallet.to_ascii_lowercase();
        let g = self.inner.lock().unwrap();
        if g.force_last_claimed_err.contains(&key) {
            return Err(ChainError::Msg(format!(
                "forced last_claimed_cumulative error for {wallet}"
            )));
        }
        Ok(g.last_claimed.get(&key).copied())
    }

    fn finalize_batch(&self, epoch: u64) -> Result<TxHash, ChainError> {
        let mut g = self.inner.lock().unwrap();
        let batch = g
            .batches
            .get_mut(&epoch)
            .ok_or(ChainError::NotFound(epoch))?;
        if batch.status != BatchStatus::Proposed && batch.status != BatchStatus::ProposerWon {
            return Err(ChainError::WrongStatus { epoch });
        }
        batch.status = BatchStatus::Finalized;
        Ok(Self::next_tx(&mut g))
    }

    fn claim_payout(
        &self,
        epoch: u64,
        worker: [u8; 20],
        proven_score: u128,
        _proof: &[[u8; 32]],
    ) -> Result<TxHash, ChainError> {
        let mut g = self.inner.lock().unwrap();
        let batch = g.batches.get(&epoch).ok_or(ChainError::NotFound(epoch))?;
        if batch.status != BatchStatus::Finalized {
            return Err(ChainError::WrongStatus { epoch });
        }
        let key = format!("0x{}", hex::encode(worker));
        // First claim stamps baseline (mint 0).
        if !g.baselines.get(&key).copied().unwrap_or(false) {
            g.baselines.insert(key, true);
        }
        g.ops.push(MockOp::Claim {
            epoch,
            worker,
            proven_score,
        });
        Ok(Self::next_tx(&mut g))
    }

    fn increase_time(&self, seconds: u64) -> Result<(), ChainError> {
        let mut g = self.inner.lock().unwrap();
        g.now = g.now.saturating_add(seconds);
        Ok(())
    }

    fn block_timestamp(&self) -> Result<u64, ChainError> {
        Ok(self.inner.lock().unwrap().now)
    }

    fn eth_balance(&self, wallet: &str) -> Result<u128, ChainError> {
        let key = wallet.to_ascii_lowercase();
        let g = self.inner.lock().unwrap();
        Ok(g.eth_balances.get(&key).copied().unwrap_or(0))
    }

    fn gas_price(&self) -> Result<u128, ChainError> {
        Ok(self.inner.lock().unwrap().gas_price_wei)
    }

    fn send_native(&self, to: &str, amount_wei: u128) -> Result<TxHash, ChainError> {
        let mut g = self.inner.lock().unwrap();
        if let Some(msg) = g.send_native_error.clone() {
            return Err(ChainError::Msg(msg));
        }
        g.sent.push((to.to_string(), amount_wei));
        Ok(Self::next_tx(&mut g))
    }

    /// Wave C W2. The payload is recorded **before** the armed result is
    /// consulted, so a test asserting "nothing was broadcast" is asserting
    /// about the call and not about its outcome.
    fn send_raw_transaction(&self, raw: &[u8]) -> Result<TxHash, ChainError> {
        let mut g = self.inner.lock().unwrap();
        g.raw_sends.push(raw.to_vec());
        match g.raw_send_result.clone() {
            Some(Ok(h)) => Ok(h),
            Some(Err(msg)) => Err(ChainError::Msg(msg)),
            None => Err(ChainError::Msg(
                "MockChain: send_raw_transaction not armed (set_send_raw_transaction)".into(),
            )),
        }
    }

    /// Wave C W2. `pending` is deliberately ignored: this mock has one
    /// counter per address, and `broadcaster::allocate_broadcaster_nonce`
    /// reads the **mined** count for the reason its own doc gives.
    fn transaction_count(&self, addr: [u8; 20], _pending: bool) -> Result<u64, ChainError> {
        self.inner
            .lock()
            .unwrap()
            .transaction_counts
            .get(&addr)
            .copied()
            .ok_or_else(|| {
                ChainError::Msg(format!(
                    "MockChain: transaction_count not armed for 0x{} (set_transaction_count)",
                    hex::encode(addr)
                ))
            })
    }

    fn erc20_balance_of(&self, token: &str, wallet: &str) -> Result<u128, ChainError> {
        let key = (token.to_ascii_lowercase(), wallet.to_ascii_lowercase());
        let g = self.inner.lock().unwrap();
        Ok(g.erc20_balances.get(&key).copied().unwrap_or(0))
    }

    fn relayer_address(&self) -> Result<String, ChainError> {
        let g = self.inner.lock().unwrap();
        Ok(g.relayer_address
            .clone()
            .unwrap_or_else(|| DEFAULT_MOCK_RELAYER_ADDRESS.to_string()))
    }

    fn gas_oracle_l1_fee(&self, unsigned_tx: &[u8]) -> Result<u128, ChainError> {
        let mut g = self.inner.lock().unwrap();
        if let Some(msg) = g.gas_oracle_error.clone() {
            return Err(ChainError::Msg(msg));
        }
        g.ops.push(MockOp::L1Fee {
            unsigned_tx_len: unsigned_tx.len(),
        });
        Ok(g.l1_exact_fee_wei)
    }

    fn gas_oracle_l1_fee_upper_bound(&self, unsigned_tx_size: u64) -> Result<u128, ChainError> {
        let mut g = self.inner.lock().unwrap();
        if let Some(msg) = g.gas_oracle_error.clone() {
            return Err(ChainError::Msg(msg));
        }
        g.ops.push(MockOp::L1FeeUpperBound { unsigned_tx_size });
        Ok(g.l1_upper_fee_wei)
    }

    fn gas_oracle_operator_fee(&self, gas_limit: u64) -> Result<u128, ChainError> {
        let mut g = self.inner.lock().unwrap();
        if let Some(msg) = g.gas_oracle_error.clone() {
            return Err(ChainError::Msg(msg));
        }
        g.ops.push(MockOp::OperatorFee { gas_limit });
        Ok(g.operator_fee_wei)
    }

    // -- Stream G G1 live-chain sourcing (Task 6 Wave A) ------------------

    fn fee_token_code_hash(&self, token: [u8; 20], block: u64) -> Result<[u8; 32], ChainError> {
        let mut g = self.inner.lock().unwrap();
        g.ops.push(MockOp::FeeTokenCodeHash { token, block });
        let code = g.fee_token_code.get(&token).cloned().ok_or_else(|| {
            ChainError::Msg(format!(
                "mock: no eth_getCode set for token 0x{}",
                hex::encode(token)
            ))
        })?;
        // Same fail-closed rule the live path uses — including empty code.
        code_hash_from_get_code(&code)
    }

    fn fee_token_config(
        &self,
        registry: [u8; 20],
        token: [u8; 20],
        block: u64,
    ) -> Result<FeeTokenConfigView, ChainError> {
        let mut g = self.inner.lock().unwrap();
        g.ops.push(MockOp::FeeTokenConfig {
            registry,
            token,
            block,
        });
        g.fee_token_configs
            .get(&(registry, token))
            .cloned()
            .ok_or_else(|| {
                ChainError::Msg(format!(
                    "mock: no getTokenConfig set for registry 0x{} token 0x{}",
                    hex::encode(registry),
                    hex::encode(token)
                ))
            })
    }

    fn fee_token_config_hash(
        &self,
        registry: [u8; 20],
        token: [u8; 20],
        block: u64,
    ) -> Result<[u8; 32], ChainError> {
        let mut g = self.inner.lock().unwrap();
        g.ops.push(MockOp::FeeTokenConfigHash {
            registry,
            token,
            block,
        });
        g.fee_token_config_hashes
            .get(&(registry, token))
            .copied()
            .ok_or_else(|| {
                ChainError::Msg(format!(
                    "mock: no getTokenConfigHash set for registry 0x{} token 0x{}",
                    hex::encode(registry),
                    hex::encode(token)
                ))
            })
    }

    fn active_manifest_hash(&self, registry: [u8; 20], block: u64) -> Result<[u8; 32], ChainError> {
        let mut g = self.inner.lock().unwrap();
        g.ops.push(MockOp::ActiveManifestHash { registry, block });
        g.active_manifest_hashes
            .get(&registry)
            .copied()
            .ok_or_else(|| {
                ChainError::Msg(format!(
                    "mock: no activeManifestHash set for registry 0x{}",
                    hex::encode(registry)
                ))
            })
    }

    fn secondary_enrollment_nonce_snapshot(
        &self,
        gateway: [u8; 20],
        root: [u8; 20],
        secondary: [u8; 20],
        fee_token: [u8; 20],
        block: u64,
    ) -> Result<NonceSnapshotView, ChainError> {
        let mut g = self.inner.lock().unwrap();
        g.ops.push(MockOp::SecondaryEnrollmentNonceSnapshot {
            gateway,
            root,
            secondary,
            fee_token,
            block,
        });
        g.nonce_snapshots
            .get(&(gateway, root, secondary, fee_token))
            .cloned()
            .ok_or_else(|| {
                ChainError::Msg(format!(
                    "mock: no secondaryEnrollmentNonceSnapshot set for gateway 0x{} \
                     root 0x{} secondary 0x{} feeToken 0x{}",
                    hex::encode(gateway),
                    hex::encode(root),
                    hex::encode(secondary),
                    hex::encode(fee_token)
                ))
            })
    }

    fn pinned_block_number(&self) -> Result<u64, ChainError> {
        let mut g = self.inner.lock().unwrap();
        g.ops.push(MockOp::PinnedBlockNumber);
        g.pinned_block.ok_or_else(|| {
            ChainError::Msg(
                "mock: pinned block number not set (call set_pinned_block_number)".into(),
            )
        })
    }

    /// Deterministic `eth_chainId`. Unset is an `Err`, never `Ok(0)` — see
    /// [`MockChain::set_chain_id`].
    fn chain_id(&self) -> Result<u64, ChainError> {
        let mut g = self.inner.lock().unwrap();
        g.ops.push(MockOp::ChainId);
        g.chain_id
            .ok_or_else(|| ChainError::Msg("mock: chain id not set (call set_chain_id)".into()))
    }

    /// Deterministic `eth_getBlockByNumber(block).timestamp` (Task 8
    /// Mandate 3). An unarmed block is an `Err`, never `Ok(0)` — see
    /// [`MockChain::set_block_timestamp_at`]. Note that this does NOT fall
    /// back to `now`: a test that means "the clock at the pinned block" must
    /// say which block, or it is silently back on the floating clock this
    /// method exists to replace.
    fn block_timestamp_at(&self, block: u64) -> Result<u64, ChainError> {
        let g = self.inner.lock().unwrap();
        g.block_timestamps.get(&block).copied().ok_or_else(|| {
            ChainError::Msg(format!(
                "mock: no block timestamp set for block {block} \
                 (call set_block_timestamp_at)"
            ))
        })
    }

    /// Deterministic ERC-2612 `nonces(owner)` (Task 8 Mandate 3). An unarmed
    /// (token, owner) pair is an `Err`, never `Ok(0)`.
    fn erc2612_nonces(
        &self,
        token: [u8; 20],
        owner: [u8; 20],
        block: u64,
    ) -> Result<u64, ChainError> {
        let mut g = self.inner.lock().unwrap();
        g.ops.push(MockOp::Erc2612Nonces {
            token,
            owner,
            block,
        });
        g.erc2612_nonces
            .get(&(token, owner))
            .copied()
            .ok_or_else(|| {
                ChainError::Msg(format!(
                    "mock: no ERC-2612 nonces set for token 0x{} owner 0x{}",
                    hex::encode(token),
                    hex::encode(owner)
                ))
            })
    }
}

/// Stub that always errors for live RPC (Phase 2.1).
#[derive(Debug, Default)]
pub struct UnconfiguredRpc;

impl ChainClient for UnconfiguredRpc {
    fn propose_batch(
        &self,
        _: u64,
        _: [u8; 32],
        _: [u8; 32],
        _: u128,
    ) -> Result<TxHash, ChainError> {
        Err(ChainError::LiveRpcNotConfigured)
    }
    fn challenge_batch(&self, _: u64, _: [u8; 32], _: u128) -> Result<TxHash, ChainError> {
        Err(ChainError::LiveRpcNotConfigured)
    }
    fn confirm_epoch(&self, _: u64) -> Result<TxHash, ChainError> {
        Err(ChainError::LiveRpcNotConfigured)
    }
    fn get_batch(&self, _: u64) -> Result<BatchView, ChainError> {
        Err(ChainError::LiveRpcNotConfigured)
    }
    fn bind_with_signature(
        &self,
        _: [u8; 20],
        _: &str,
        _: u64,
        _: &[u8],
    ) -> Result<TxHash, ChainError> {
        Err(ChainError::LiveRpcNotConfigured)
    }
    fn enroll_self_with_signature(
        &self,
        _: [u8; 20],
        _: u64,
        _: &[u8],
    ) -> Result<TxHash, ChainError> {
        Err(ChainError::LiveRpcNotConfigured)
    }
}

// ---------------------------------------------------------------------------
// Stream G G1 — outbox / broadcaster / reconcile types + ABI (Task 7 Wave A).
//
// Ground truth is the Solidity source, never a grep:
// `SponsoredEnrollmentExecuted` is `contracts/src/GoatRelayGateway.sol:88-95`,
// `intentUsed` is `:80`. The selector and topic0 literals below were derived
// with Foundry's `cast sig` / `cast sig-event` on 2026-07-25 and are pinned by
// the `stream_g_outbox_*_pin` tests — never by running this module's own
// `selector` / `event_topic0`, which would make the pin a tautology.
// ---------------------------------------------------------------------------

/// `GoatRelayGateway.intentUsed(bytes32)` — selector `0xa4532c02`.
pub const SIG_INTENT_USED: &str = "intentUsed(bytes32)";

/// ERC-2612 `nonces(address)` on a fee token — selector `0x7ecebe00`.
///
/// Byte-identical on the wire to [`encode_nonces`] (WorkerBinding /
/// EnrollmentRegistry), and deliberately kept as its own constant + encoder
/// anyway: these are different contract surfaces that happen to agree today,
/// and a shared helper would let a change to one silently retarget the other.
pub const SIG_ERC2612_NONCES: &str = "nonces(address)";

/// `GoatRelayGateway.SponsoredEnrollmentExecuted` — the canonical event
/// signature that is hashed to `topic0`.
///
/// Indexed (topics 1-3, in order): `intentId`, `root`, `secondary`.
/// Non-indexed data (in order): `controller`, `feeToken`, `feeAmount`.
pub const SIG_SPONSORED_ENROLLMENT_EXECUTED: &str =
    "SponsoredEnrollmentExecuted(bytes32,address,address,address,address,uint256)";

/// `keccak256(event_signature)` — the full 32-byte `topic0`, as opposed to
/// [`selector`]'s leading 4 bytes.
pub fn event_topic0(sig: &str) -> [u8; 32] {
    keccak256(sig.as_bytes())
}

/// A mined transaction receipt, reduced to what reconciliation needs.
///
/// `success` is the receipt's `status` field: `true` = status 1 (the
/// transaction's effects persisted), `false` = status 0 (it reverted and
/// consumed nothing on chain except gas). The distinction matters because a
/// mined revert and a broadcast failure demand opposite handling — see
/// `ExecutedLog` and the reconcile spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxReceiptView {
    pub tx_hash: TxHash,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub success: bool,
    pub gas_used: u128,
}

/// The six ABI fields of one `SponsoredEnrollmentExecuted` event, decoded
/// from its topics + data with no reference to where the log was found.
///
/// Kept separate from [`ExecutedLog`] so the decode is a pure function that
/// can be unit-tested without a node; `RpcChain` supplies the chain-position
/// metadata via [`ExecutedLogFields::with_metadata`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutedLogFields {
    pub intent_id: [u8; 32],
    pub root: [u8; 20],
    pub secondary: [u8; 20],
    pub controller: [u8; 20],
    pub fee_token: [u8; 20],
    pub fee_amount: u128,
}

impl ExecutedLogFields {
    /// Attach the chain position this log was observed at.
    pub fn with_metadata(
        self,
        block_number: u64,
        block_hash: [u8; 32],
        log_index: u64,
        tx_hash: TxHash,
        removed: bool,
    ) -> ExecutedLog {
        ExecutedLog {
            intent_id: self.intent_id,
            root: self.root,
            secondary: self.secondary,
            controller: self.controller,
            fee_token: self.fee_token,
            fee_amount: self.fee_amount,
            block_number,
            block_hash,
            log_index,
            tx_hash,
            removed,
        }
    }
}

/// One observed `SponsoredEnrollmentExecuted` log: the event's own fields
/// **plus** where on the chain it was seen.
///
/// The five metadata fields are not optional garnish. `BoundWorker`, the
/// existing log type in this module, keeps only the decoded event and is
/// therefore useless for reconciliation:
///
/// - `block_number` — needed to apply a confirmation depth before trusting it;
/// - `block_hash` + `removed` — the only way to notice a reorg took the log
///   back out from under a row already marked confirmed;
/// - `log_index` — disambiguates two logs in one transaction and gives a
///   stable total order with `block_number`;
/// - `tx_hash` — distinguishes "our broadcast landed" from "somebody else
///   fulfilled this intent", which must NOT be rebroadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutedLog {
    pub intent_id: [u8; 32],
    pub root: [u8; 20],
    pub secondary: [u8; 20],
    pub controller: [u8; 20],
    pub fee_token: [u8; 20],
    pub fee_amount: u128,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub log_index: u64,
    pub tx_hash: TxHash,
    /// `true` when the node is reporting that this log was removed by a
    /// chain reorganisation.
    pub removed: bool,
}

/// Calldata for `GoatRelayGateway.intentUsed(bytes32)` (Stream G G1).
pub fn encode_intent_used(intent_id: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&selector(SIG_INTENT_USED));
    out.extend_from_slice(&intent_id);
    out
}

/// Calldata for ERC-2612 `nonces(address)` on a fee token (Stream G G1).
pub fn encode_erc2612_nonces(owner: [u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&selector(SIG_ERC2612_NONCES));
    out.extend_from_slice(&address_word(&owner));
    out
}

/// Decode an ABI `bool` return word, **fail-closed**.
///
/// The ABI says a `bool` is a 32-byte word that is exactly 0 or 1. Anything
/// else — a short return, a dirty high word, a last byte of 2 — is rejected
/// rather than coerced, because the only consumer is
/// [`ChainClient::intent_used`], where a wrong `false` authorizes releasing a
/// nonce whose transaction may still be live.
pub fn decode_bool_return(data: &[u8], what: &str) -> Result<bool, ChainError> {
    if data.len() < 32 {
        return Err(ChainError::Msg(format!(
            "{what}: expected a 32-byte bool word, got {} bytes",
            data.len()
        )));
    }
    let word = &data[..32];
    if word[..31].iter().any(|&b| b != 0) {
        return Err(ChainError::Msg(format!(
            "{what}: non-canonical bool word (high bytes set); refusing to coerce"
        )));
    }
    match word[31] {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(ChainError::Msg(format!(
            "{what}: non-canonical bool value {other}; refusing to coerce"
        ))),
    }
}

/// Decode an ABI `uint256` return word into a `u64`, **fail-closed**.
///
/// Rejects anything that does not fit rather than truncating: a truncated
/// nonce compares equal to a completely different on-chain value.
pub fn decode_u64_return(data: &[u8], what: &str) -> Result<u64, ChainError> {
    if data.len() < 32 {
        return Err(ChainError::Msg(format!(
            "{what}: expected a 32-byte uint256 word, got {} bytes",
            data.len()
        )));
    }
    let wide = u128_from_word(&data[..32]).map_err(|e| ChainError::Msg(format!("{what}: {e}")))?;
    u64::try_from(wide).map_err(|_| {
        ChainError::Msg(format!(
            "{what}: uint256 value {wide} does not fit in u64; refusing to truncate"
        ))
    })
}

/// Read a left-padded `address` out of a 32-byte word (a topic or a data
/// word), **fail-closed** on a non-canonical encoding.
///
/// A conforming encoder zeroes the leading 12 bytes. When they are not zero
/// the word is not an address — silently taking its low 20 bytes would
/// fabricate an address that no participant ever signed for.
fn address_from_word(word: &[u8], what: &str) -> Result<[u8; 20], ChainError> {
    if word.len() != 32 {
        return Err(ChainError::Msg(format!(
            "{what}: expected a 32-byte word, got {} bytes",
            word.len()
        )));
    }
    if word[..12].iter().any(|&b| b != 0) {
        return Err(ChainError::Msg(format!(
            "{what}: non-canonical address word (leading 12 bytes are not zero)"
        )));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&word[12..]);
    Ok(out)
}

/// Decode one `SponsoredEnrollmentExecuted` log's topics + data.
///
/// Strict on purpose — every rejection below is a case where accepting the
/// log would attribute an on-chain execution to the wrong party:
///
/// - exactly four topics (`topic0` + the three indexed fields). A different
///   count is a different event;
/// - `topics[0]` must equal this event's `topic0`, re-checked here even
///   though the `eth_getLogs` filter already asked for it — a mis-wired
///   filter would otherwise hand this decoder some other event's words;
/// - exactly three data words (`controller`, `feeToken`, `feeAmount`), in
///   that order — note the sibling `GoatTransferExecuted` orders its data
///   `root, amount, feeToken, feeAmount`, which is easy to get backwards;
/// - every address word canonically left-padded.
pub fn decode_sponsored_enrollment_executed(
    topics: &[[u8; 32]],
    data: &[u8],
) -> Result<ExecutedLogFields, ChainError> {
    if topics.len() != 4 {
        return Err(ChainError::Msg(format!(
            "SponsoredEnrollmentExecuted: expected 4 topics, got {}",
            topics.len()
        )));
    }
    let expected_topic0 = event_topic0(SIG_SPONSORED_ENROLLMENT_EXECUTED);
    if topics[0] != expected_topic0 {
        return Err(ChainError::Msg(format!(
            "SponsoredEnrollmentExecuted: topic0 mismatch (got 0x{}, expected 0x{})",
            hex::encode(topics[0]),
            hex::encode(expected_topic0)
        )));
    }
    if data.len() != 96 {
        return Err(ChainError::Msg(format!(
            "SponsoredEnrollmentExecuted: expected 96 data bytes (3 words), got {}",
            data.len()
        )));
    }

    let intent_id = topics[1];
    let root = address_from_word(&topics[2], "SponsoredEnrollmentExecuted.root")?;
    let secondary = address_from_word(&topics[3], "SponsoredEnrollmentExecuted.secondary")?;
    let controller = address_from_word(&data[0..32], "SponsoredEnrollmentExecuted.controller")?;
    let fee_token = address_from_word(&data[32..64], "SponsoredEnrollmentExecuted.feeToken")?;
    let fee_amount = u128_from_word(&data[64..96])
        .map_err(|e| ChainError::Msg(format!("SponsoredEnrollmentExecuted.feeAmount: {e}")))?;

    Ok(ExecutedLogFields {
        intent_id,
        root,
        secondary,
        controller,
        fee_token,
        fee_amount,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_are_four_bytes_stable() {
        let s = selector("proposeBatch(uint256,bytes32,bytes32)");
        assert_eq!(s, selector("proposeBatch(uint256,bytes32,bytes32)"));
        assert_ne!(s, selector("challengeBatch(uint256,bytes32)"));
    }

    #[test]
    fn mock_propose_and_confirm() {
        let chain = MockChain::new();
        let root = [1u8; 32];
        let evid = [2u8; 32];
        let bond = 1_000_000_000_000_000_000;
        chain.propose_batch(20260714, root, evid, bond).unwrap();
        let b = chain.get_batch(20260714).unwrap();
        assert_eq!(b.status, BatchStatus::Proposed);
        assert_eq!(b.merkle_root, root);
        chain.confirm_epoch(20260714).unwrap();
        let b2 = chain.get_batch(20260714).unwrap();
        assert!(b2.watcher_confirmed_at > 0);
        let ops = chain.ops();
        assert_eq!(ops.len(), 2);
        assert!(matches!(
            ops[0],
            MockOp::Propose {
                epoch: 20260714,
                ..
            }
        ));
        assert!(matches!(ops[1], MockOp::Confirm { epoch: 20260714 }));
    }

    #[test]
    fn encode_propose_starts_with_selector() {
        let data = encode_propose_batch(1, [0u8; 32], [0u8; 32]);
        assert_eq!(
            &data[..4],
            &selector("proposeBatch(uint256,bytes32,bytes32)")
        );
        assert_eq!(data.len(), 4 + 96);
    }

    #[test]
    fn encode_bind_abi_layout() {
        let wallet = [0xABu8; 20];
        let data = encode_bind_with_signature(wallet, "GOAT-alice", 99, &[0x01, 0x02]);
        assert_eq!(
            &data[..4],
            &selector("bindWithSignature(address,string,uint256,bytes)")
        );
        // head offsets
        assert_eq!(&data[4 + 32..4 + 64], &u256_be(0x80));
        // string at 0x80 relative to head start (byte 4)
        let str_off = 4 + 0x80;
        assert_eq!(&data[str_off..str_off + 32], &u256_be(10)); // "GOAT-alice".len()
        assert_eq!(&data[str_off + 32..str_off + 42], b"GOAT-alice");
    }

    #[test]
    fn decode_batch_zeros_is_none() {
        let data = [0u8; 320];
        let v = decode_batch_return(&data).unwrap();
        assert_eq!(v.status, BatchStatus::None);
        assert_eq!(v.proposer_bond, 0);
    }

    #[test]
    fn mock_last_claimed_cumulative() {
        let chain = MockChain::new();
        let wallet = "0x00000000000000000000000000000000000000a1";
        assert_eq!(chain.last_claimed_cumulative(wallet).unwrap(), None);
        chain.set_last_claimed_cumulative(wallet, 42);
        assert_eq!(chain.last_claimed_cumulative(wallet).unwrap(), Some(42));
        assert_eq!(
            chain
                .last_claimed_cumulative("0x00000000000000000000000000000000000000A1")
                .unwrap(),
            Some(42)
        );
    }

    #[test]
    fn encode_last_claimed_starts_with_selector() {
        let data = encode_last_claimed_cumulative([0xABu8; 20]);
        assert_eq!(&data[..4], &selector("lastClaimedCumulative(address)"));
        assert_eq!(data.len(), 4 + 32);
    }

    #[test]
    fn mock_native_send_and_balances() {
        let m = MockChain::new();
        m.set_eth_balance("0xabc", 5_000);
        m.set_gas_price(7);
        m.set_erc20_balance("0xToken", "0xabc", 42);
        assert_eq!(m.eth_balance("0xabc").unwrap(), 5_000);
        assert_eq!(m.gas_price().unwrap(), 7);
        assert_eq!(m.erc20_balance_of("0xToken", "0xabc").unwrap(), 42);
        let h = m.send_native("0xdef", 1_000).unwrap();
        assert!(!format!("{h:?}").is_empty());
        assert_eq!(m.sent_native(), vec![("0xdef".to_string(), 1_000)]);
    }

    #[test]
    fn mock_relayer_address_default_and_override() {
        let m = MockChain::new();
        assert_eq!(
            m.relayer_address().unwrap(),
            DEFAULT_MOCK_RELAYER_ADDRESS.to_string()
        );
        m.set_relayer_address("0xabc123");
        assert_eq!(m.relayer_address().unwrap(), "0xabc123".to_string());
    }

    // =====================================================================
    // Stream G G1 — live chain sourcing reads (Task 6 Wave A)
    //
    // Contract: the "Stream G — Live Chain Sourcing Contract for
    // `EnrollmentQuoteContext`" spec, §2 (selectors +
    // decode layouts) and §3 (binding rules R1-R5).
    // =====================================================================

    // -- 1. selector pins ------------------------------------------------
    //
    // Every expected value below was re-derived independently with Foundry's
    // `cast sig` on 2026-07-24 (not by running this module's `selector`), so
    // a typo in a `SIG_*` string or drift in the keccak wiring fails here.

    #[test]
    fn stream_g_selector_pin_get_token_config() {
        assert_eq!(SIG_GET_TOKEN_CONFIG, "getTokenConfig(address)");
        assert_eq!(
            selector(SIG_GET_TOKEN_CONFIG),
            [0xcb, 0x67, 0xe3, 0xb1],
            "cast sig 'getTokenConfig(address)' = 0xcb67e3b1"
        );
    }

    #[test]
    fn stream_g_selector_pin_get_token_config_hash() {
        assert_eq!(SIG_GET_TOKEN_CONFIG_HASH, "getTokenConfigHash(address)");
        assert_eq!(
            selector(SIG_GET_TOKEN_CONFIG_HASH),
            [0x7e, 0x22, 0x1f, 0x83],
            "cast sig 'getTokenConfigHash(address)' = 0x7e221f83"
        );
    }

    #[test]
    fn stream_g_selector_pin_active_manifest_hash() {
        assert_eq!(SIG_ACTIVE_MANIFEST_HASH, "activeManifestHash()");
        assert_eq!(
            selector(SIG_ACTIVE_MANIFEST_HASH),
            [0xcc, 0x4d, 0x2a, 0x5e],
            "cast sig 'activeManifestHash()' = 0xcc4d2a5e"
        );
    }

    #[test]
    fn stream_g_selector_pin_secondary_enrollment_nonce_snapshot() {
        assert_eq!(
            SIG_SECONDARY_ENROLLMENT_NONCE_SNAPSHOT,
            "secondaryEnrollmentNonceSnapshot(address,address,address)"
        );
        assert_eq!(
            selector(SIG_SECONDARY_ENROLLMENT_NONCE_SNAPSHOT),
            [0x0a, 0x6c, 0x28, 0x70],
            "cast sig 'secondaryEnrollmentNonceSnapshot(address,address,address)' = 0x0a6c2870"
        );
    }

    // -- 2. calldata BODY pins -------------------------------------------
    //
    // Selector-only assertions are not enough: `MockChain` never decodes
    // calldata, so a malformed body would ship with every test green (this
    // is the Task 5 hardening finding, restated for these five reads).
    // Every byte of `expected` below is written out BY HAND from the ABI
    // rules — no `selector`, `address_word` or `u256_be` call participates
    // in building it, so an edit to any of those still fails here.

    #[test]
    fn stream_g_encode_get_token_config_calldata_pin() {
        // getTokenConfig(address) with token
        //   = 0x00112233445566778899aabbccddeeff00112233
        // Layout: selector(4) | 12 zero pad bytes | 20 address bytes = 36 bytes
        let token: [u8; 20] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
        ];
        let mut expected = vec![0xcb, 0x67, 0xe3, 0xb1]; // getTokenConfig(address)
        expected.extend_from_slice(&[0u8; 12]); // left pad of the address word
        expected.extend_from_slice(&token);

        let actual = encode_get_token_config(token);
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 36); // 4 + 32
    }

    #[test]
    fn stream_g_encode_get_token_config_hash_calldata_pin() {
        // getTokenConfigHash(address) with token = 0xAB repeated 20 times.
        let token = [0xABu8; 20];
        let mut expected = vec![0x7e, 0x22, 0x1f, 0x83]; // getTokenConfigHash(address)
        expected.extend_from_slice(&[0u8; 12]);
        expected.extend_from_slice(&[0xABu8; 20]);

        let actual = encode_get_token_config_hash(token);
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 36);
    }

    #[test]
    fn stream_g_encode_active_manifest_hash_calldata_pin() {
        // activeManifestHash() takes no arguments: the calldata is exactly
        // the 4 selector bytes and nothing else.
        let expected = vec![0xcc, 0x4d, 0x2a, 0x5e];
        let actual = encode_active_manifest_hash();
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 4);
    }

    #[test]
    fn stream_g_encode_secondary_enrollment_nonce_snapshot_calldata_pin() {
        // secondaryEnrollmentNonceSnapshot(address root, address secondary,
        //                                  address feeToken)
        // Layout: selector(4) | root word(32) | secondary word(32) |
        //         feeToken word(32) = 100 bytes.
        // The three fill bytes are distinct so a transposed argument order
        // fails this test rather than sailing through as three addresses.
        let root = [0x11u8; 20];
        let secondary = [0x22u8; 20];
        let fee_token = [0x33u8; 20];

        let mut expected = vec![0x0a, 0x6c, 0x28, 0x70];
        expected.extend_from_slice(&[0u8; 12]);
        expected.extend_from_slice(&[0x11u8; 20]); // root
        expected.extend_from_slice(&[0u8; 12]);
        expected.extend_from_slice(&[0x22u8; 20]); // secondary
        expected.extend_from_slice(&[0u8; 12]);
        expected.extend_from_slice(&[0x33u8; 20]); // feeToken

        let actual = encode_secondary_enrollment_nonce_snapshot(root, secondary, fee_token);
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 100); // 4 + 32*3
    }

    // -- 3. return-decode fixtures ---------------------------------------

    /// Test-only big-endian `uint256` word builder. Deliberately *not*
    /// `u256_be` (the production helper) so these fixtures stay independent
    /// of the code they exercise.
    fn fixture_word_u128(v: u128) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..].copy_from_slice(&v.to_be_bytes());
        w
    }

    /// Test-only left-padded address word builder.
    fn fixture_word_address(a: [u8; 20]) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&a);
        w
    }

    /// 11-word `getTokenConfig` return with a DISTINCT value in every field,
    /// so any transposition of two fields fails the assertions.
    fn fee_token_config_fixture() -> Vec<u8> {
        let token: [u8; 20] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
        ];
        let mut out = Vec::with_capacity(352);
        out.extend_from_slice(&fixture_word_u128(8453)); // 0 chainId (Base)
        out.extend_from_slice(&fixture_word_address(token)); // 1 token
        out.extend_from_slice(&[0xA1u8; 32]); // 2 runtimeCodeHash
        out.extend_from_slice(&[0xA2u8; 32]); // 3 proxyIdentityHash
        out.extend_from_slice(&fixture_word_u128(0x1234)); // 4 capabilityMask
        out.extend_from_slice(&fixture_word_u128(6)); // 5 decimals
        out.extend_from_slice(&[0xB1u8; 32]); // 6 domainNameHash
        out.extend_from_slice(&[0xB2u8; 32]); // 7 domainVersionHash
        out.extend_from_slice(&[0xB3u8; 32]); // 8 builtInModeId
        out.extend_from_slice(&fixture_word_u128(7)); // 9 configVersion
        out.extend_from_slice(&fixture_word_u128(1)); // 10 active
        out
    }

    #[test]
    fn stream_g_decode_fee_token_config_field_order_fixture() {
        let data = fee_token_config_fixture();
        assert_eq!(data.len(), 352, "11 static words, inline from offset 0");
        let cfg = decode_fee_token_config_return(&data).unwrap();

        assert_eq!(cfg.chain_id, 8453);
        assert_eq!(
            cfg.token,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
            ]
        );
        assert_eq!(cfg.runtime_code_hash, [0xA1u8; 32]);
        assert_eq!(cfg.proxy_identity_hash, [0xA2u8; 32]);
        assert_eq!(cfg.capability_mask, 0x1234);
        assert_eq!(cfg.decimals, 6);
        assert_eq!(cfg.domain_name_hash, [0xB1u8; 32]);
        assert_eq!(cfg.domain_version_hash, [0xB2u8; 32]);
        assert_eq!(cfg.built_in_mode_id, [0xB3u8; 32]);
        assert_eq!(cfg.config_version, 7);
        assert!(cfg.active);
    }

    #[test]
    fn stream_g_decode_fee_token_config_rejects_short_return() {
        // 351 bytes: one byte short of the 11-word struct. An `eth_call` to
        // a non-existent registry returns `0x`, which lands here too.
        let err = decode_fee_token_config_return(&[0u8; 351]).unwrap_err();
        assert!(err.to_string().contains("getTokenConfig"), "{err}");
        assert!(decode_fee_token_config_return(&[]).is_err());
    }

    #[test]
    fn stream_g_decode_fee_token_config_rejects_capability_mask_high_bits() {
        // capabilityMask is uint256, NOT uint64 — a value with any bit above
        // 128 set must be REJECTED, never truncated into a mask that happens
        // to look authorized (`base_fee.rs` sets this precedent).
        let mut data = fee_token_config_fixture();
        data[4 * 32] = 0x01; // most-significant byte of word 4
        let err = decode_fee_token_config_return(&data).unwrap_err();
        assert!(err.to_string().contains("capabilityMask"), "{err}");
    }

    #[test]
    fn stream_g_decode_fee_token_config_rejects_dirty_address_word() {
        // Non-zero bytes above the low 20 of the `token` word mean the node
        // returned something that is not an address — fail, do not mask.
        let mut data = fee_token_config_fixture();
        data[32] = 0x01; // most-significant byte of word 1 (`token`)
        let err = decode_fee_token_config_return(&data).unwrap_err();
        assert!(err.to_string().contains("token"), "{err}");
    }

    #[test]
    fn stream_g_decode_fee_token_config_rejects_non_boolean_active() {
        let mut data = fee_token_config_fixture();
        data[10 * 32 + 31] = 0x02; // neither 0 nor 1
        let err = decode_fee_token_config_return(&data).unwrap_err();
        assert!(err.to_string().contains("active"), "{err}");
    }

    /// 14-word `secondaryEnrollmentNonceSnapshot` return with a DISTINCT
    /// value in every field. `StreamGTypes.sol:351` declares `presentMask`
    /// BEFORE the three hashes, which is not the order a reader guesses from
    /// the field names — this fixture is the regression pin for that.
    fn nonce_snapshot_fixture() -> Vec<u8> {
        let mut out = Vec::with_capacity(448);
        out.extend_from_slice(&fixture_word_u128(1001)); // 0  blockNumber
        out.extend_from_slice(&fixture_word_u128(1002)); // 1  actionNonce
        out.extend_from_slice(&fixture_word_u128(1003)); // 2  v1EnrollNonce
        out.extend_from_slice(&fixture_word_u128(1004)); // 3  linkNonce
        out.extend_from_slice(&fixture_word_u128(1005)); // 4  rootRegistrationNonce
        out.extend_from_slice(&fixture_word_u128(1006)); // 5  rotationNonce
        out.extend_from_slice(&fixture_word_u128(1007)); // 6  controllerEpoch
                                                         // 7 controller: 0x...03e8 == 1000, distinct from every numeric above
                                                         // and below, so swapping it with any of them fails.
        out.extend_from_slice(&fixture_word_u128(1000));
        out.extend_from_slice(&fixture_word_u128(1009)); // 8  goatPermitNonce
        out.extend_from_slice(&fixture_word_u128(1010)); // 9  feeTokenPermitNonce
        out.extend_from_slice(&fixture_word_u128(0x1FF)); // 10 presentMask (all 9 bits)
        out.extend_from_slice(&[0xD1u8; 32]); // 11 deploymentManifestHash
        out.extend_from_slice(&[0xD2u8; 32]); // 12 feeTokenConfigHash
        out.extend_from_slice(&[0xD3u8; 32]); // 13 feeScheduleHash
        out
    }

    #[test]
    fn stream_g_decode_nonce_snapshot_field_order_fixture() {
        let data = nonce_snapshot_fixture();
        assert_eq!(data.len(), 448, "14 static words, inline from offset 0");
        let snap = decode_nonce_snapshot_return(&data).unwrap();

        assert_eq!(snap.block_number, 1001);
        assert_eq!(snap.action_nonce, 1002);
        assert_eq!(snap.v1_enroll_nonce, 1003);
        assert_eq!(snap.link_nonce, 1004);
        assert_eq!(snap.root_registration_nonce, 1005);
        assert_eq!(snap.rotation_nonce, 1006);
        assert_eq!(snap.controller_epoch, 1007);
        let mut expected_controller = [0u8; 20];
        expected_controller[18] = 0x03;
        expected_controller[19] = 0xe8;
        assert_eq!(snap.controller, expected_controller);
        assert_eq!(snap.goat_permit_nonce, 1009);
        assert_eq!(snap.fee_token_permit_nonce, 1010);
        assert_eq!(snap.present_mask, 0x1FF);
        assert_eq!(snap.deployment_manifest_hash, [0xD1u8; 32]);
        assert_eq!(snap.fee_token_config_hash, [0xD2u8; 32]);
        assert_eq!(snap.fee_schedule_hash, [0xD3u8; 32]);

        // Every decoded scalar is distinct, which is what makes the
        // assertions above transposition-sensitive rather than decorative.
        let scalars = [
            u128::from(snap.block_number),
            snap.action_nonce,
            snap.v1_enroll_nonce,
            snap.link_nonce,
            snap.root_registration_nonce,
            snap.rotation_nonce,
            snap.controller_epoch,
            snap.goat_permit_nonce,
            snap.fee_token_permit_nonce,
            u128::from(snap.present_mask),
        ];
        let unique: HashSet<u128> = scalars.iter().copied().collect();
        assert_eq!(unique.len(), scalars.len());
    }

    #[test]
    fn stream_g_decode_nonce_snapshot_present_mask_bit_positions() {
        // presentMask semantics, decoded against the hard-pinned SNAP_*
        // constants: the fixture sets all nine declared bits.
        let snap = decode_nonce_snapshot_return(&nonce_snapshot_fixture()).unwrap();
        for bit in [
            SNAP_ACTION_NONCE,
            SNAP_V1_ENROLL_NONCE,
            SNAP_LINK_NONCE,
            SNAP_ROOT_REG_NONCE,
            SNAP_ROTATION_NONCE,
            SNAP_CONTROLLER,
            SNAP_GOAT_PERMIT_NONCE,
            SNAP_FEE_TOKEN_PERMIT_NONCE,
            SNAP_CONFIG_HASHES,
        ] {
            assert_ne!(snap.present_mask & bit, 0, "bit {bit} must be set");
        }
        // Bit 9 and above are undeclared and must read as clear.
        assert_eq!(snap.present_mask & !0x1FFu32, 0);
    }

    #[test]
    fn stream_g_snap_bit_constants_pin() {
        // Hard-pinned: `SNAP_*` are `internal` in Solidity, therefore NOT
        // ABI-visible and NOT derivable at runtime. Values transcribed from
        // `contracts/src/StreamGTypes.sol:369-377`.
        assert_eq!(SNAP_ACTION_NONCE, 1);
        assert_eq!(SNAP_V1_ENROLL_NONCE, 2);
        assert_eq!(SNAP_LINK_NONCE, 4);
        assert_eq!(SNAP_ROOT_REG_NONCE, 8);
        assert_eq!(SNAP_ROTATION_NONCE, 16);
        assert_eq!(SNAP_CONTROLLER, 32);
        assert_eq!(SNAP_GOAT_PERMIT_NONCE, 64);
        assert_eq!(SNAP_FEE_TOKEN_PERMIT_NONCE, 128);
        assert_eq!(SNAP_CONFIG_HASHES, 256);
    }

    #[test]
    fn stream_g_decode_nonce_snapshot_rejects_short_return() {
        let err = decode_nonce_snapshot_return(&[0u8; 447]).unwrap_err();
        assert!(
            err.to_string().contains("secondaryEnrollmentNonceSnapshot"),
            "{err}"
        );
        assert!(decode_nonce_snapshot_return(&[]).is_err());
    }

    #[test]
    fn stream_g_decode_nonce_snapshot_rejects_oversized_present_mask() {
        // presentMask is uint32; a word with bit 32 set is not a valid mask.
        let mut data = nonce_snapshot_fixture();
        data[10 * 32 + 27] = 0x01;
        let err = decode_nonce_snapshot_return(&data).unwrap_err();
        assert!(err.to_string().contains("presentMask"), "{err}");
    }

    #[test]
    fn stream_g_decode_nonce_snapshot_rejects_oversized_block_number() {
        // blockNumber is uint64.
        let mut data = nonce_snapshot_fixture();
        data[23] = 0x01; // byte just above the low 8 of word 0
        let err = decode_nonce_snapshot_return(&data).unwrap_err();
        assert!(err.to_string().contains("blockNumber"), "{err}");
    }

    // -- 4. eth_getCode → code hash, fail-closed on empty (R1) -----------

    #[test]
    fn stream_g_code_hash_from_get_code_rejects_empty_code() {
        // R1: a token address with no deployed bytecode must fail closed.
        // The failure mode this guards against is returning
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        // (`cast keccak ""`), which a manifest could be made to match.
        let keccak_of_empty: [u8; 32] =
            hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
                .unwrap()
                .try_into()
                .unwrap();
        // Sanity: the raw hasher really does produce that value for empty
        // input, so the assertion below is about the guard, not the hasher.
        assert_eq!(keccak256(&[]), keccak_of_empty);

        let result = code_hash_from_get_code(&[]);
        assert!(
            result.is_err(),
            "empty eth_getCode must be Err, got {result:?}"
        );
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn stream_g_code_hash_from_get_code_hashes_non_empty_code() {
        let code = [0x60u8, 0x01, 0x60, 0x00, 0x55, 0x00];
        assert_eq!(code_hash_from_get_code(&code).unwrap(), keccak256(&code));
    }

    // -- 5. MockChain support --------------------------------------------

    #[test]
    fn stream_g_mock_live_reads_and_call_counters() {
        let m = MockChain::new();
        let token = [0x11u8; 20];
        let registry = [0x22u8; 20];
        let gateway = [0x33u8; 20];
        let root = [0x44u8; 20];
        let secondary = [0x55u8; 20];

        let code = [0xDEu8, 0xAD, 0xBE, 0xEF];
        m.set_fee_token_code(token, &code);
        m.set_pinned_block_number(4242);
        let cfg = decode_fee_token_config_return(&fee_token_config_fixture()).unwrap();
        m.set_fee_token_config(registry, token, cfg.clone());
        m.set_fee_token_config_hash(registry, token, [0xC0u8; 32]);
        m.set_active_manifest_hash(registry, [0xA9u8; 32]);
        let snap = decode_nonce_snapshot_return(&nonce_snapshot_fixture()).unwrap();
        m.set_nonce_snapshot(gateway, root, secondary, token, snap.clone());

        assert_eq!(m.pinned_block_number().unwrap(), 4242);
        assert_eq!(
            m.fee_token_code_hash(token, 4242).unwrap(),
            keccak256(&code)
        );
        assert_eq!(m.fee_token_config(registry, token, 4242).unwrap(), cfg);
        assert_eq!(
            m.fee_token_config_hash(registry, token, 4242).unwrap(),
            [0xC0u8; 32]
        );
        assert_eq!(
            m.secondary_enrollment_nonce_snapshot(gateway, root, secondary, token, 4242)
                .unwrap(),
            snap
        );

        assert_eq!(m.fee_token_code_hash_call_count(), 1);
        assert_eq!(m.fee_token_config_call_count(), 1);
        assert_eq!(m.fee_token_config_hash_call_count(), 1);
        assert_eq!(m.secondary_enrollment_nonce_snapshot_call_count(), 1);
        assert_eq!(m.pinned_block_number_call_count(), 1);
    }

    #[test]
    fn stream_g_mock_empty_code_is_err_not_a_hash() {
        let m = MockChain::new();
        let token = [0x99u8; 20];
        m.set_fee_token_code(token, &[]);
        let err = m.fee_token_code_hash(token, 1).unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");
        // The call still counted: the read was attempted and failed closed.
        assert_eq!(m.fee_token_code_hash_call_count(), 1);
    }

    #[test]
    fn stream_g_mock_unset_reads_are_err_never_a_zero_value() {
        let m = MockChain::new();
        assert!(m.pinned_block_number().is_err());
        assert!(m.fee_token_code_hash([0u8; 20], 1).is_err());
        assert!(m.fee_token_config([0u8; 20], [0u8; 20], 1).is_err());
        assert!(m.fee_token_config_hash([0u8; 20], [0u8; 20], 1).is_err());
        assert!(m.active_manifest_hash([0u8; 20], 1).is_err());
        assert!(m
            .secondary_enrollment_nonce_snapshot([0u8; 20], [0u8; 20], [0u8; 20], [0u8; 20], 1)
            .is_err());
    }

    // -- 6. default trait bodies fail closed ------------------------------

    #[test]
    fn stream_g_default_chain_client_reads_err_never_ok_zero() {
        // `UnconfiguredRpc` implements only the required methods, so these
        // exercise the trait's DEFAULT bodies. Every one must be `Err` — an
        // `Ok(0)` / `Ok([0u8;32])` default would let a pilot implementor
        // silently report a zero into the security gate these reads feed.
        let c = UnconfiguredRpc;
        assert!(c.fee_token_code_hash([0u8; 20], 1).is_err());
        assert!(c.fee_token_config([0u8; 20], [0u8; 20], 1).is_err());
        assert!(c.fee_token_config_hash([0u8; 20], [0u8; 20], 1).is_err());
        assert!(c.active_manifest_hash([0u8; 20], 1).is_err());
        assert!(c
            .secondary_enrollment_nonce_snapshot([0u8; 20], [0u8; 20], [0u8; 20], [0u8; 20], 1)
            .is_err());
        assert!(c.pinned_block_number().is_err());
    }

    // -- 7. eth_chainId (Task 6 Wave A, gate check 3) ---------------------
    //
    // Context: `stream_g::token_manifest`'s gate check 3 compares the
    // registry config's `chainId` against `LiveTokenReading::live_chain_id()`.
    // Today both sides come from `getTokenConfig(...).chainId`, so the check
    // is `x == x` and cannot fail in production. `ChainClient::chain_id` is
    // the missing right-hand side. These tests pin the two properties the
    // check's future soundness rests on: the value is *read* (counted), and
    // an unread/unsupported chain id is an error rather than a zero that
    // would compare equal to an unset config field.

    #[test]
    fn stream_g_mock_chain_id_returns_the_set_value_and_counts_the_read() {
        // Mutation this detects: replacing `MockChain::chain_id`'s
        // `g.chain_id.ok_or_else(..)` with `Ok(g.chain_id.unwrap_or(0))`, or
        // with any constant — the first `assert_eq` then sees 0 (or the
        // constant) instead of 8453. Setting a SECOND, different value and
        // re-reading is what rules out "returns a hardcoded 8453".
        // Separately, deleting the `g.ops.push(MockOp::ChainId)` line makes
        // the call-count assertions fail, which is the property a caller-side
        // test needs in order to prove the gate compared against a chain READ
        // rather than against config.
        let m = MockChain::new();
        assert_eq!(m.chain_id_call_count(), 0);

        m.set_chain_id(8453); // Base mainnet
        assert_eq!(m.chain_id().unwrap(), 8453);
        assert_eq!(m.chain_id_call_count(), 1);

        m.set_chain_id(31337); // anvil
        assert_eq!(m.chain_id().unwrap(), 31337);
        assert_eq!(m.chain_id_call_count(), 2);

        // The chain-id read is its own op: it must not be miscounted as one
        // of the other Stream G reads (a copy-paste of the wrong `MockOp`
        // variant in either the impl or the counter fails here).
        assert_eq!(m.pinned_block_number_call_count(), 0);
        assert_eq!(m.fee_token_config_call_count(), 0);
    }

    #[test]
    fn stream_g_mock_unset_chain_id_is_err_not_ok_zero() {
        // Mutation this detects: `unwrap_or(0)` (or `unwrap_or_default()`) in
        // `MockChain::chain_id`. Chain 0 is not a valid EIP-155 chain id, and
        // a zeroed `FeeTokenConfig.chainId` would compare EQUAL to it — so an
        // unset mock must never be able to satisfy gate check 3 by accident.
        // Asserted on the message, not bare `is_err()`, so a *different*
        // failure (e.g. a poisoned mutex) cannot pass for this one.
        let m = MockChain::new();
        let err = m.chain_id().unwrap_err();
        assert!(
            err.to_string().contains("chain id not set"),
            "expected the unset-chain-id message, got: {err}"
        );
        // The read was still attempted and counted even though it failed
        // closed — same posture as `fee_token_code_hash` on empty code.
        assert_eq!(m.chain_id_call_count(), 1);
    }

    #[test]
    fn stream_g_default_chain_id_is_err_never_ok_zero() {
        // `UnconfiguredRpc` implements only the trait's REQUIRED methods, so
        // this exercises the default body.
        //
        // Mutation this detects: changing that default from
        // `Err(ChainError::Msg("chain_id not supported"))` to `Ok(0)` — which
        // is precisely the shape that would make every non-overriding
        // implementor silently claim chain 0 and hand a fabricated constant
        // to a security check. The message assertion also fails if the
        // default is changed to some *other* error, which matters because the
        // caller distinguishes "this client cannot read chain id" from a
        // transport failure.
        let c = UnconfiguredRpc;
        let err = c.chain_id().unwrap_err();
        assert!(
            err.to_string().contains("chain_id not supported"),
            "expected the not-supported default message, got: {err}"
        );
    }

    // -- Stream G G1 outbox / reconcile (Task 7 Wave A) --------------------
    //
    // Every expected constant below was derived independently with Foundry
    // `cast` on 2026-07-25 (cast 1.7.1), NOT by running this module's own
    // `selector` / `event_topic0` — a pin computed the same way as the code
    // it pins proves nothing:
    //
    //   $ cast sig       "intentUsed(bytes32)"
    //   0xa4532c02
    //   $ cast sig       "nonces(address)"
    //   0x7ecebe00
    //   $ cast sig-event "SponsoredEnrollmentExecuted(bytes32,address,address,address,address,uint256)"
    //   0x63e0225eb6605a32564a4e3be3f8e8b0be21aa79ba973779d40c72bcd5f6d1aa

    #[test]
    fn stream_g_outbox_selector_pin_intent_used() {
        assert_eq!(SIG_INTENT_USED, "intentUsed(bytes32)");
        assert_eq!(
            selector(SIG_INTENT_USED),
            [0xa4, 0x53, 0x2c, 0x02],
            "cast sig 'intentUsed(bytes32)' = 0xa4532c02"
        );
    }

    #[test]
    fn stream_g_outbox_selector_pin_erc2612_nonces() {
        assert_eq!(SIG_ERC2612_NONCES, "nonces(address)");
        assert_eq!(
            selector(SIG_ERC2612_NONCES),
            [0x7e, 0xce, 0xbe, 0x00],
            "cast sig 'nonces(address)' = 0x7ecebe00"
        );
    }

    /// Mutation this detects: any typo in
    /// [`SIG_SPONSORED_ENROLLMENT_EXECUTED`] — a reordered parameter, a
    /// missing `address`, a stray space. Verified by swapping the last two
    /// params to `…,uint256,address)`: topic0 changes completely and this
    /// fails.
    #[test]
    fn stream_g_outbox_topic0_pin_sponsored_enrollment_executed() {
        assert_eq!(
            SIG_SPONSORED_ENROLLMENT_EXECUTED,
            "SponsoredEnrollmentExecuted(bytes32,address,address,address,address,uint256)"
        );
        assert_eq!(
            hex::encode(event_topic0(SIG_SPONSORED_ENROLLMENT_EXECUTED)),
            "63e0225eb6605a32564a4e3be3f8e8b0be21aa79ba973779d40c72bcd5f6d1aa",
            "cast sig-event '{SIG_SPONSORED_ENROLLMENT_EXECUTED}'"
        );
    }

    /// Selector-only pins are not enough — the argument words matter too.
    ///
    /// Mutation this detects: encoding the `bytes32` intent id through
    /// `address_word` (left-padding it), or the address through a raw copy.
    #[test]
    fn stream_g_outbox_calldata_body_pins() {
        let intent_id = [0x11u8; 32];
        let calldata = encode_intent_used(intent_id);
        assert_eq!(calldata.len(), 36);
        assert_eq!(&calldata[..4], &[0xa4, 0x53, 0x2c, 0x02]);
        assert_eq!(&calldata[4..], &intent_id[..], "bytes32 is NOT left-padded");

        let mut owner = [0u8; 20];
        owner[19] = 0xAA;
        let calldata = encode_erc2612_nonces(owner);
        assert_eq!(calldata.len(), 36);
        assert_eq!(&calldata[..4], &[0x7e, 0xce, 0xbe, 0x00]);
        assert_eq!(&calldata[4..16], &[0u8; 12], "address is left-padded");
        assert_eq!(&calldata[16..], &owner[..]);
    }

    /// The Task 5 precedent, applied to all six Task 7 reads at once.
    ///
    /// Mutation this detects: changing ANY of the six default bodies from
    /// `Err(..)` to a substantive answer — `Ok(0)`, `Ok(false)`, `Ok(None)`,
    /// `Ok(Vec::new())`. Verified on `intent_used` by returning `Ok(false)`:
    /// this test fails, and that is precisely the value that would tell an
    /// evidence-based sweeper the chain had PROVEN non-consumption and let it
    /// release a nonce whose transaction is still live.
    #[test]
    fn stream_g_outbox_defaults_are_err_never_a_substantive_answer() {
        let c = UnconfiguredRpc;
        let gateway = [0u8; 20];

        for (label, err) in [
            (
                "send_raw_transaction",
                c.send_raw_transaction(&[0u8; 4]).err(),
            ),
            (
                "transaction_receipt",
                c.transaction_receipt([0u8; 32]).err(),
            ),
            (
                "transaction_count",
                c.transaction_count([0u8; 20], true).err(),
            ),
            ("intent_used", c.intent_used(gateway, [0u8; 32], 1).err()),
            (
                "erc2612_nonces",
                c.erc2612_nonces([0u8; 20], [0u8; 20], 1).err(),
            ),
            (
                "sponsored_enrollment_logs",
                c.sponsored_enrollment_logs(gateway, 1, 2).err(),
            ),
        ] {
            let err = err
                .unwrap_or_else(|| panic!("{label} default must be Err, never a substantive Ok"));
            assert!(
                err.to_string().contains(label),
                "{label}: expected the not-supported default message, got: {err}"
            );
        }
    }

    /// Mutation this detects: relaxing `decode_bool_return` to
    /// `Ok(word[31] != 0)`. Verified — the `0x02` case below then returns
    /// `Ok(true)` instead of `Err` and the assertion fails.
    #[test]
    fn decode_bool_return_is_canonical_or_error() {
        let mut word = [0u8; 32];
        assert!(!decode_bool_return(&word, "t").expect("false decodes"));

        // Paired non-zero arm: the canonical `true` really does decode.
        word[31] = 1;
        assert!(decode_bool_return(&word, "t").expect("true decodes"));

        word[31] = 2;
        let err = decode_bool_return(&word, "intentUsed").unwrap_err();
        assert!(
            err.to_string().contains("non-canonical bool value 2"),
            "got: {err}"
        );

        // Dirty high word: last byte still says 1.
        let mut dirty = [0u8; 32];
        dirty[0] = 0xFF;
        dirty[31] = 1;
        let err = decode_bool_return(&dirty, "intentUsed").unwrap_err();
        assert!(
            err.to_string().contains("non-canonical bool word"),
            "got: {err}"
        );

        let err = decode_bool_return(&[0u8; 31], "intentUsed").unwrap_err();
        assert!(err.to_string().contains("got 31 bytes"), "got: {err}");
    }

    /// Mutation this detects: replacing the `u64::try_from` in
    /// `decode_u64_return` with an `as u64` cast. Verified — the oversized
    /// word below then decodes to a wrapped value instead of erroring.
    #[test]
    fn decode_u64_return_refuses_to_truncate() {
        let mut word = [0u8; 32];
        word[31] = 7;
        assert_eq!(decode_u64_return(&word, "nonces").expect("small"), 7);

        // 2^64 exactly: fits in u128, does not fit in u64.
        let mut big = [0u8; 32];
        big[23] = 1;
        let err = decode_u64_return(&big, "nonces").unwrap_err();
        assert!(
            err.to_string().contains("does not fit in u64"),
            "got: {err}"
        );

        // Above u128 too: rejected one layer earlier.
        let huge = [0xFFu8; 32];
        assert!(decode_u64_return(&huge, "nonces").is_err());
    }

    /// Mutation this detects: swapping the `controller` / `feeToken` data
    /// words in `decode_sponsored_enrollment_executed`. Verified — the
    /// `fields.controller` assertion then reports the fee token's address.
    /// (The sibling `GoatTransferExecuted` really does order its data
    /// differently, so this is a live hazard, not a hypothetical one.)
    #[test]
    fn decode_sponsored_enrollment_executed_roundtrip_and_rejections() {
        fn addr_word(last: u8) -> [u8; 32] {
            let mut w = [0u8; 32];
            w[31] = last;
            w
        }
        fn addr(last: u8) -> [u8; 20] {
            let mut a = [0u8; 20];
            a[19] = last;
            a
        }

        let topics = [
            event_topic0(SIG_SPONSORED_ENROLLMENT_EXECUTED),
            [0x11u8; 32],
            addr_word(0xA1),
            addr_word(0xB2),
        ];
        let mut data = Vec::new();
        data.extend_from_slice(&addr_word(0xC3)); // controller
        data.extend_from_slice(&addr_word(0xD4)); // feeToken
        let mut amount = [0u8; 32];
        amount[31] = 0x2A; // 42
        data.extend_from_slice(&amount);

        let fields = decode_sponsored_enrollment_executed(&topics, &data).expect("decode");
        assert_eq!(fields.intent_id, [0x11u8; 32]);
        assert_eq!(fields.root, addr(0xA1));
        assert_eq!(fields.secondary, addr(0xB2));
        assert_eq!(fields.controller, addr(0xC3));
        assert_eq!(fields.fee_token, addr(0xD4));
        assert_eq!(fields.fee_amount, 42);

        // Wrong topic0 (some other event routed here by a mis-wired filter).
        let mut wrong = topics;
        wrong[0] = event_topic0("Bound(address,string)");
        let err = decode_sponsored_enrollment_executed(&wrong, &data).unwrap_err();
        assert!(err.to_string().contains("topic0 mismatch"), "got: {err}");

        // Anonymous / differently-indexed event: three topics.
        let err = decode_sponsored_enrollment_executed(&topics[..3], &data).unwrap_err();
        assert!(err.to_string().contains("expected 4 topics"), "got: {err}");

        // Truncated data (2 words instead of 3).
        let err = decode_sponsored_enrollment_executed(&topics, &data[..64]).unwrap_err();
        assert!(
            err.to_string().contains("expected 96 data bytes"),
            "got: {err}"
        );

        // Non-canonical address word: high bytes set.
        let mut dirty_data = data.clone();
        dirty_data[0] = 0xFF;
        let err = decode_sponsored_enrollment_executed(&topics, &dirty_data).unwrap_err();
        assert!(
            err.to_string().contains("non-canonical address word"),
            "got: {err}"
        );

        // feeAmount wider than u128.
        let mut wide_data = data.clone();
        wide_data[64] = 0x01;
        let err = decode_sponsored_enrollment_executed(&topics, &wide_data).unwrap_err();
        assert!(err.to_string().contains("feeAmount"), "got: {err}");
    }

    /// Mutation this detects: dropping `removed` (or `block_hash`) from
    /// `ExecutedLog`, i.e. reverting it to `BoundWorker`'s
    /// event-fields-only shape. Verified by deleting the field — this stops
    /// compiling, which is the intended failure mode: without it a reorg is
    /// undetectable and the compiler is the right place to say so.
    #[test]
    fn executed_log_carries_the_reorg_metadata_bound_worker_discards() {
        let fields = ExecutedLogFields {
            intent_id: [0x11u8; 32],
            root: [0xA1u8; 20],
            secondary: [0xB2u8; 20],
            controller: [0xC3u8; 20],
            fee_token: [0xD4u8; 20],
            fee_amount: 42,
        };
        let log = fields
            .clone()
            .with_metadata(1234, [0x99u8; 32], 7, [0x77u8; 32], true);

        assert_eq!(log.block_number, 1234);
        assert_eq!(log.block_hash, [0x99u8; 32]);
        assert_eq!(log.log_index, 7);
        assert_eq!(log.tx_hash, [0x77u8; 32]);
        assert!(
            log.removed,
            "a reorg-removed log must survive decoding as such"
        );

        // Paired non-removed arm, so `removed` is read as data and not as a
        // constant that happens to be true.
        let canonical = fields.with_metadata(1234, [0x99u8; 32], 7, [0x77u8; 32], false);
        assert!(!canonical.removed);
        assert_eq!(canonical.intent_id, log.intent_id);
    }
}
