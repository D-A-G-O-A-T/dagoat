//! Base L2 fee decomposition (release-blocking hazard 1) — Stream G.
//!
//! Before a Stream G broadcaster ever fires a Base transaction it must
//! reserve enough native ETH to cover *every* component of that
//! transaction's cost, not just L2 execution gas. Base runs on the OP
//! Stack: on top of ordinary L2 execution gas (`gas_limit *
//! max_fee_per_gas`), a transaction also pays an **L1 data-availability
//! fee** (Base posts its calldata/blobs back to L1) and, since Isthmus, a
//! separate **operator fee**. Under-reserving any one of those three
//! components is exactly hazard 1: the broadcaster fires, the tx reverts
//! or the operator eats an uncovered fee, and the shortfall is silent
//! until it is real money.
//!
//! `reserve_wei = l2_wei + max(l1_exact_wei, l1_upper_wei) + operator_wei`
//! (see [`NativeExposure::reserve_wei`]). The L1 term is deliberately the
//! **pessimistic** branch — `max`, not `l1_exact` alone — so that whichever
//! of the two oracle calls the caller has available, the reserve never
//! comes out lower than the true cost.
//!
//! ## Hard rules (restated from the plan)
//! - **Never treat a target contract's `eth_call` as a fee estimate.** The
//!   only fee source is the `GasPriceOracle` predeploy's three methods
//!   below.
//! - **Never use `getL1GasUsed`.** It reports a gas quantity, not a wei
//!   fee, and this module does not call it, expose it, or convert its
//!   output into money anywhere.
//!
//! ## ARCHITECT RULING — `ChainClient` is synchronous
//! This module calls [`crate::chain::ChainClient`] directly and takes
//! `&dyn ChainClient`, matching every existing method on that trait
//! (`fn ... -> Result<T, ChainError>`, e.g. `block_timestamp`,
//! `eth_balance`, `gas_price`). It is deliberately **not** `async` —
//! `RpcChain` (`src/rpc_chain.rs`) bridges to the async alloy provider
//! internally via `block_on`, the same way it already does for every other
//! trait method; `base_fee.rs` itself has no alloy dependency at all.
//!
//! ## ARCHITECT RULING — real Base `GasPriceOracle` signatures, not the mock
//! Predeploy address `0x420000000000000000000000000000000000000F` is a
//! fixed OP-Stack predeploy, identical on every OP-Stack chain (Base, Base
//! Sepolia, OP Mainnet, ...) — it is not read from config.
//!
//! **Resolved mock divergence (2026-07-24).** This module implements the
//! real predeploy signature `getL1FeeUpperBound(uint256 _unsignedTxSize)`
//! (added in Fjord — a **size**, not calldata), confirmed against
//! `ethereum-optimism/optimism`'s `packages/contracts-bedrock/src/L2/GasPriceOracle.sol`
//! and independently cross-checked against the public 4byte.directory
//! selector registry — see the `base_fee_selector_pin_*` tests below.
//! `../../contracts/test/mocks/MockGasPriceOracle.sol` (path relative to
//! this crate, `tools/goat-attestor`) previously declared the `bytes`
//! variant, which is a **different selector** (`0x3e02a766` vs the real
//! `0xf1c7a58b`) and would have made any Anvil integration test fail to
//! decode this call. The mock was fixed contracts-side to the real
//! `uint256` signature, and
//! `StreamGMocksTest.test_gas_price_oracle_selectors_match_op_stack_predeploy`
//! now pins all three selectors literally on that side, so Rust and
//! Solidity can no longer drift apart silently. `getL1Fee(bytes)` and
//! `getOperatorFee(uint256)` (added in Isthmus) always matched.
//!
//! **Honesty note (this repo's "claims ≤ code" rule):** none of this has
//! been validated against a real Base network. The signatures above are
//! taken from the upstream OP Stack source and from a public selector
//! registry, not from a live call against Base or Base Sepolia. The only
//! thing exercised by the tests in this file is [`MockChain`]
//! (`src/chain.rs`), which returns whatever a test tells it to.
//!
//! ## Quote vs. submit — and why both query the same oracle a slightly
//! different way
//! [`quote_exposure`] runs before a real transaction exists: there is no
//! serialized tx to hash, only a *ceiling* on its eventual size and gas
//! usage, so it can only call the size-based `getL1FeeUpperBound` (and
//! passes `0` for `l1_exact_wei` — there is nothing to query yet).
//! [`submit_exposure`] runs once the real EIP-2718 bytes exist: it calls
//! the exact `getL1Fee` on those bytes, and *also* calls
//! `getL1FeeUpperBound` on their real size, so `reserve_wei`'s `max()`
//! stays meaningful (defense in depth against the two oracle calls
//! disagreeing at the same block) rather than degenerating into "trust the
//! exact call alone." Neither entry point can know the transaction's
//! actual post-execution gas usage before it runs — `getOperatorFee` is
//! therefore always called with the caller's known gas ceiling/limit, a
//! conservative proxy consistent with this being a pre-flight *reserve*
//! check, not a post-execution reconciliation.
//!
//! Both entry points take `max_native_exposure_wei` (from
//! `StreamGConfig::max_native_exposure_wei`, Task 1) and enforce the
//! exposure gate themselves — fail closed, never clamp-and-proceed —
//! returning a [`GatedExposure`], not a bare [`NativeExposure`]. Both of
//! `GatedExposure`'s fields are private and set only inside the gate
//! function, so there is no code path that can produce one from this
//! module without the gate having already been checked against it.
//! (Hardening note: this claim was previously made about
//! [`NativeExposure`] itself, which is false — `NativeExposure` is `pub`
//! with all-`pub` fields, so any caller can construct one directly and
//! never gate it. `NativeExposure` stays public, as the raw wei
//! decomposition; `GatedExposure` is the new type that actually carries
//! the guarantee.) Binding `max_native_exposure_wei` to
//! `StreamGConfig::max_native_exposure_wei` at the Task 6a integration
//! point is what completes the guarantee — this module only proves the
//! gate ran against whatever ceiling it was given.
//!
//! ## Correctness bar: checked arithmetic only
//! Every arithmetic step in [`NativeExposure::reserve_wei`] and in the
//! `l2_wei` computation in [`quote_exposure`] / [`submit_exposure`] uses
//! `checked_mul` / `checked_add` and returns [`BaseFeeError::ExposureOverflow`]
//! on overflow. No `as` cast, no wrapping arithmetic, no saturating
//! arithmetic appears anywhere in this fee path — a silent wrap would
//! understate the reserve, which is precisely hazard 1.
//!
//! ## Money-path parameter newtypes
//! [`quote_exposure`] / [`submit_exposure`] used to take two bare `u64`s
//! and two bare `u128`s in one call; transposing either same-typed pair
//! compiled cleanly and silently understated the reserve (hardening
//! Important 1). [`GasUnits`], [`TxSizeBytes`], [`MaxFeePerGas`], and
//! [`WeiCeiling`] are private-field newtypes with explicit named
//! constructors (`GasUnits::new(500_000)`) and deliberately **no**
//! `From`/`Into` impls, so the compiler refuses the swap instead of an
//! `.into()` silently permitting it.
//!
//! ## Wave 2 wiring — three things this module does NOT establish
//!
//! [`submit_exposure_for_chain`] is called immediately after signing and
//! strictly before anything is persisted or sent.
//!
//! 🔴 **Wave C W2: there is now exactly ONE such call site**,
//! `broadcaster::sign_persist_and_broadcast`.
//! `submit::submit_sponsored_enrollment` no longer calls it itself — it
//! routes through the broadcaster and supplies the ceiling via
//! `BroadcastPlan::max_native_exposure_wei`. (Two call sites was a hazard in
//! itself: nothing at the type level stopped both running, which is what
//! would have happened had the submit path been left half-cut.)
//!
//! Three limits of that wiring are stated here rather than left for a reader
//! to discover:
//!
//! 1. **`gas_limit` / `max_fee_per_gas` are the signer's assertion, not a
//!    fact decoded out of the signed bytes.** They travel on
//!    [`super::outbox::SignedRawTx`], which requires them at construction
//!    ([`super::outbox::SignedRawTx::new`] takes them as
//!    [`GasUnits`]/[`MaxFeePerGas`], so no call site can omit or transpose
//!    them) — but *requiring* a value is not *verifying* one. Nothing here
//!    parses the EIP-2718 payload; a signer that reports a gas limit
//!    different from the one it signed would produce an exposure figure
//!    that is wrong and this module could not tell. Decoding the real
//!    bytes instead is still not implemented here. Note that
//!    [`super::broadcaster::RpcChainEnrollmentSigner`] (Wave B2) *is* a
//!    production signer and does report the policy values it signed with, so
//!    "every `SignedRawTx` is a six-byte sentinel" is now true only of test
//!    doubles — what is unchanged is that this module verifies neither.
//! 2. **The ceiling now HAS a production source** — 🔴 Wave C W4, and this
//!    entry said the opposite until then.
//!    [`super::broadcaster::BroadcastPlan::max_native_exposure_wei`] is filled
//!    from [`super::submit::SubmitContext::max_native_exposure_wei`] by
//!    non-test code (Wave C W2), and that field is now filled by
//!    `submit::submit_context` from
//!    `runtime::StreamGState::max_native_exposure_wei`, i.e. from
//!    `STREAM_G_MAX_NATIVE_EXPOSURE_WEI`, for the mounted route
//!    `POST /v1/stream-g/submit`. That config value still defaults to `0`,
//!    which admits nothing — so the route refuses the request outright
//!    (`http_error::ERR_EXPOSURE_CEILING_UNSET`, 503) rather than letting an
//!    unset budget present as `ExposureExceedsSchedule` on every call.
//!    **Hazard 1 is CLOSED on the submit path for every chain that carries
//!    the predeploy**, and open on those that do not — which is limit 3.
//! 3. **On the local dev chain the gate does not run at all** — see
//!    [`chain_carries_gas_price_oracle`]. That skip is disclosed through
//!    `preflight::UNVERIFIED_CHECKS`, not swallowed.

use crate::chain::{ChainClient, ChainError};
use crate::merkle::keccak256;

// ---------------------------------------------------------------------------
// GasPriceOracle ABI table — SINGLE POINT OF CHANGE.
//
// | Solidity signature          | OP Stack fork | Selector (keccak256-derived) |
// |------------------------------|----------------|--------------------------------|
// | getL1Fee(bytes)              | Bedrock        | `oracle_selector(SIG_GET_L1_FEE)` = 0x49948e0e |
// | getL1FeeUpperBound(uint256)  | Fjord          | `oracle_selector(SIG_GET_L1_FEE_UPPER_BOUND)` = 0xf1c7a58b |
// | getOperatorFee(uint256)      | Isthmus        | `oracle_selector(SIG_GET_OPERATOR_FEE)` = 0x275aedd2 |
//
// Selectors are NEVER hard-coded into calldata: every `encode_get_*`
// function below derives its selector at call time via `oracle_selector`,
// which hashes the signature string through `crate::merkle::keccak256` —
// the same primitive `chain::selector` uses for every other ABI selector
// in this crate. The three literal values in the table above exist only
// as documentation and as the independently-sourced expected values in
// `base_fee_selector_pin_*` below (sourced from the public
// 4byte.directory selector registry, not derived from this module's own
// `oracle_selector`) — so a typo or drift in a `SIG_*` string fails a
// test loudly instead of silently miscalling the predeploy.
// ---------------------------------------------------------------------------

/// `getL1Fee(bytes)` — exact L1 data-availability fee for the given
/// unsigned/serialized transaction bytes. Matches
/// `../../contracts/test/mocks/MockGasPriceOracle.sol`.
pub const SIG_GET_L1_FEE: &str = "getL1Fee(bytes)";

/// `getL1FeeUpperBound(uint256)` — pessimistic L1 fee bound from a tx
/// **size**, not calldata (Fjord+). This is the real predeploy signature;
/// see the module doc for the divergence from this repo's mock, which
/// declares a `bytes` parameter instead.
pub const SIG_GET_L1_FEE_UPPER_BOUND: &str = "getL1FeeUpperBound(uint256)";

/// `getOperatorFee(uint256)` — per-tx operator fee from a gas quantity
/// (Isthmus+). Matches `../../contracts/test/mocks/MockGasPriceOracle.sol`.
pub const SIG_GET_OPERATOR_FEE: &str = "getOperatorFee(uint256)";

/// The local development chain id (Anvil / Hardhat default) — the same
/// value `rpc_chain.rs`'s two existing chain-id conditionals exempt
/// (`if self.chain_id != 31337 && from == 0`, in `list_bound_workers` and
/// `sponsored_enrollment_logs`). Declared here rather than spelled as a
/// bare literal a third time.
pub const LOCAL_DEV_CHAIN_ID: u64 = 31337;

/// Does this chain carry the OP-Stack `GasPriceOracle` predeploy?
///
/// **This is a chain-shape question, not a fee question, and getting it
/// wrong is an outage rather than an under-reserve.**
/// [`GAS_PRICE_ORACLE_ADDRESS`] is a *predeploy*: it exists because the
/// OP-Stack genesis puts it there, not because anything deploys it. The
/// local development chain has no such genesis —
/// `contracts/script/DeployStreamG.s.sol` neither deploys nor `vm.etch`es
/// it (verified: zero hits), and the only thing in this repository that
/// ever places code at that address is the `pub(crate)` test helper
/// `anvil_harness::etch_gas_price_oracle`, called from three test sites,
/// none of them a submit test. An `eth_call` to an address with no code
/// returns empty, `rpc_chain::decode_gas_oracle_u256` turns that into a
/// hard `Err`, and `SubmitError::retryability()` would classify the
/// resulting failure `Terminal` — so a submit path that treated that `Err`
/// as a gate verdict would make every sponsored enrollment on chain
/// [`LOCAL_DEV_CHAIN_ID`] a *permanently dead* enrollment.
///
/// So [`submit_exposure_for_chain`] **skips** rather than fails on such a
/// chain — and says so out loud: see `preflight::UNVERIFIED_CHECKS`'s
/// "native exposure gate" entry, this crate's established mechanism for "a
/// check that did not run". A silently-skipped gate would be worse than
/// either alternative.
///
/// The predicate deliberately mirrors `rpc_chain.rs`'s existing shape
/// (`chain_id != 31337`) rather than introducing a second,
/// differently-spelled chain policy: everything that is not the local dev
/// chain is assumed to be the OP-Stack chain this crate targets. That
/// assumption is stated, not hidden — pointed at a non-OP-Stack chain the
/// oracle call is still made and still fails closed, which is the right
/// posture for "this is not the chain you think it is".
pub const fn chain_carries_gas_price_oracle(chain_id: u64) -> bool {
    chain_id != LOCAL_DEV_CHAIN_ID
}

/// Fixed OP-Stack `GasPriceOracle` predeploy address — identical on every
/// OP-Stack chain (Base, Base Sepolia, OP Mainnet, ...); not read from
/// config. `0x420000000000000000000000000000000000000F`.
pub const GAS_PRICE_ORACLE_ADDRESS: [u8; 20] = [
    0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0F,
];

/// First 4 bytes of `keccak256(sig.as_bytes())` — the ABI selector for
/// `sig`. Deliberately re-derived here (rather than importing
/// `chain::selector`) so this file's oracle ABI table is fully
/// self-contained; both ultimately hash through
/// [`crate::merkle::keccak256`].
pub fn oracle_selector(sig: &str) -> [u8; 4] {
    let h = keccak256(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// Calldata for `getL1Fee(bytes)`: selector, then the dynamic `bytes` ABI
/// tail (offset word, length word, data, right-padded to 32 bytes).
pub fn encode_get_l1_fee(unsigned_tx: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 + 32 + unsigned_tx.len());
    out.extend_from_slice(&oracle_selector(SIG_GET_L1_FEE));
    // One head word (the bytes offset) → dynamic tail starts at 0x20.
    out.extend_from_slice(&u256_be(32));
    out.extend_from_slice(&abi_encode_dynamic_bytes(unsigned_tx));
    out
}

/// Calldata for `getL1FeeUpperBound(uint256)` — a plain `uint256` size
/// parameter, **not** ABI-encoded `bytes`. This is the point of
/// divergence from `../../contracts/test/mocks/MockGasPriceOracle.sol`'s
/// `getL1FeeUpperBound(bytes)` — see module doc.
pub fn encode_get_l1_fee_upper_bound(unsigned_tx_size: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&oracle_selector(SIG_GET_L1_FEE_UPPER_BOUND));
    out.extend_from_slice(&u256_be(u128::from(unsigned_tx_size)));
    out
}

/// Calldata for `getOperatorFee(uint256)`.
pub fn encode_get_operator_fee(gas_limit: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&oracle_selector(SIG_GET_OPERATOR_FEE));
    out.extend_from_slice(&u256_be(u128::from(gas_limit)));
    out
}

fn u256_be(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

/// ABI-encode a dynamic `bytes` tail (length word + data + right-pad to 32).
fn abi_encode_dynamic_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + data.len() + 32);
    out.extend_from_slice(&u256_be(usize_to_u128(data.len())));
    out.extend_from_slice(data);
    let pad = (32 - (data.len() % 32)) % 32;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// Losslessly widen a `usize` byte length to `u128` without an `as` cast
/// (hardening M1 — this was the only `as` in the file, on the money path).
/// `u128::try_from(usize)` can only fail on a hypothetical target where
/// `usize` is wider than 128 bits; no such Rust target exists, so the
/// fallback branch below is unreachable in practice. It exists only so
/// this function needs neither `.unwrap()` nor `.expect()` (both are
/// banned outside `#[cfg(test)]` in this module).
fn usize_to_u128(n: usize) -> u128 {
    u128::try_from(n).unwrap_or(u128::MAX)
}

/// Typed error code surfaced to callers when the checked reserve
/// computation would overflow `u128`. Never produced by a wrap — see
/// [`NativeExposure::reserve_wei`].
pub const ERR_EXPOSURE_OVERFLOW: &str = "EXPOSURE_OVERFLOW";
/// Typed error code for the fail-closed exposure gate
/// (`StreamGConfig::max_native_exposure_wei`).
pub const ERR_EXPOSURE_EXCEEDS_SCHEDULE: &str = "EXPOSURE_EXCEEDS_SCHEDULE";
/// Typed error code for an unsigned tx whose byte length does not fit in
/// a `u64` (cannot happen on any real transaction; guarded rather than
/// cast away).
pub const ERR_TX_SIZE_OVERFLOW: &str = "TX_SIZE_OVERFLOW";
/// Typed error code for `quote_exposure` called with a zero gas-unit
/// ceiling (hardening M2 — a zero ceiling can never fund any transaction).
pub const ERR_ZERO_GAS_UNITS: &str = "ZERO_GAS_UNITS";
/// Typed error code for `quote_exposure` called with a zero tx-size
/// ceiling (hardening M2).
pub const ERR_ZERO_TX_SIZE_CEILING: &str = "ZERO_TX_SIZE_CEILING";
/// Typed error code for `submit_exposure` called with empty transaction
/// bytes — a real EIP-2718 transaction is never empty (hardening M2).
pub const ERR_EMPTY_TRANSACTION: &str = "EMPTY_TRANSACTION";

#[derive(Debug, thiserror::Error)]
pub enum BaseFeeError {
    #[error("chain error: {0}")]
    Chain(#[from] ChainError),
    #[error("native exposure reserve calculation overflowed u128")]
    ExposureOverflow,
    #[error(
        "computed reserve {reserve_wei} wei exceeds configured schedule ceiling {ceiling_wei} wei"
    )]
    ExposureExceedsSchedule {
        reserve_wei: u128,
        ceiling_wei: u128,
    },
    #[error("unsigned tx length {0} bytes does not fit in u64")]
    TxSizeOverflow(usize),
    #[error("gas unit ceiling must be nonzero (a zero ceiling can never fund any transaction)")]
    ZeroGasUnits,
    #[error("unsigned tx size ceiling must be nonzero")]
    ZeroTxSizeCeiling,
    #[error("unsigned EIP-2718 transaction bytes must not be empty")]
    EmptyTransaction,
}

impl BaseFeeError {
    /// Stable string code for routes/logs to surface.
    pub fn code(&self) -> &'static str {
        match self {
            BaseFeeError::ExposureOverflow => ERR_EXPOSURE_OVERFLOW,
            BaseFeeError::ExposureExceedsSchedule { .. } => ERR_EXPOSURE_EXCEEDS_SCHEDULE,
            BaseFeeError::TxSizeOverflow(_) => ERR_TX_SIZE_OVERFLOW,
            BaseFeeError::ZeroGasUnits => ERR_ZERO_GAS_UNITS,
            BaseFeeError::ZeroTxSizeCeiling => ERR_ZERO_TX_SIZE_CEILING,
            BaseFeeError::EmptyTransaction => ERR_EMPTY_TRANSACTION,
            BaseFeeError::Chain(_) => "INTERNAL",
        }
    }

    /// HTTP status for the shared Stream G error envelope
    /// (`super::http_error`). See that module for the category rules and for
    /// the ownership-oracle clause.
    ///
    /// Deliberately **wildcard-free**, unlike [`BaseFeeError::code`] above:
    /// `code` ends in `Chain(_) => "INTERNAL"` but a `_ =>` arm anywhere in a
    /// mapping like this means a variant added later is classified by
    /// accident. Every `status` in this crate matches every variant by name so
    /// that adding one is a compile error here.
    pub fn status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            // A live chain read failed. The pilot's own precedent for an
            // upstream RPC failure is `BAD_GATEWAY` (`relayer.rs`'s
            // `binding_nonce` arm), and this is the same condition.
            BaseFeeError::Chain(_) => StatusCode::BAD_GATEWAY,
            // Well-formed caller inputs that the exposure gate refuses.
            BaseFeeError::ExposureOverflow
            | BaseFeeError::ExposureExceedsSchedule { .. }
            | BaseFeeError::TxSizeOverflow(_)
            | BaseFeeError::ZeroGasUnits
            | BaseFeeError::ZeroTxSizeCeiling => StatusCode::UNPROCESSABLE_ENTITY,
            // Not caller-reachable: the bytes come from this process's own
            // signer, so an empty transaction is this process's bug.
            BaseFeeError::EmptyTransaction => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

// ---------------------------------------------------------------------------
// Money-path parameter newtypes (hardening Important 1) — private fields,
// explicit named constructors, deliberately NO `From`/`Into` impls. Task 4's
// `token_manifest` newtypes added blanket `From` impls and its reviewer
// found that still permits a transposed-argument call via an explicit
// `.into()`; these newtypes close that gap: there is no implicit or
// one-call-site conversion path at all, only `Xxx::new(value)`.
// ---------------------------------------------------------------------------

/// A gas quantity, in gas units (not wei) — `gas_limit` / `gas_unit_ceiling`.
/// Private field; construct via [`GasUnits::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GasUnits(u64);

impl GasUnits {
    pub const fn new(units: u64) -> Self {
        Self(units)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A serialized/unsigned transaction size ceiling, in bytes —
/// `unsigned_size_ceiling`. Private field; construct via
/// [`TxSizeBytes::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxSizeBytes(u64);

impl TxSizeBytes {
    pub const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A max fee per gas unit, in wei — `max_fee_per_gas`. Private field;
/// construct via [`MaxFeePerGas::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxFeePerGas(u128);

impl MaxFeePerGas {
    pub const fn new(wei_per_gas: u128) -> Self {
        Self(wei_per_gas)
    }

    pub const fn get(self) -> u128 {
        self.0
    }
}

/// A native-ETH exposure ceiling, in wei — `max_native_exposure_wei`
/// (`StreamGConfig::max_native_exposure_wei`, Task 1). Private field;
/// construct via [`WeiCeiling::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeiCeiling(u128);

impl WeiCeiling {
    pub const fn new(wei: u128) -> Self {
        Self(wei)
    }

    pub const fn get(self) -> u128 {
        self.0
    }
}

/// The four wei components of a Base transaction's native-ETH cost.
/// `l1_exact_wei` is `0` when it was never queried (e.g. at quote time,
/// before a real transaction exists) — [`reserve_wei`](Self::reserve_wei)'s
/// `max()` degrades gracefully to the other term in that case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NativeExposure {
    /// L2 execution cost: `gas_limit * max_fee_per_gas`.
    pub l2_wei: u128,
    /// `GasPriceOracle.getL1Fee(bytes)` on the real serialized tx, or `0`
    /// if not queried.
    pub l1_exact_wei: u128,
    /// `GasPriceOracle.getL1FeeUpperBound(uint256)` on a tx size (real or
    /// ceiling), or `0` if not queried.
    pub l1_upper_wei: u128,
    /// `GasPriceOracle.getOperatorFee(uint256)` on a gas quantity (real
    /// limit or ceiling).
    pub operator_wei: u128,
}

impl NativeExposure {
    /// `reserve = l2 + max(l1_exact, l1_upper) + operator`, entirely in
    /// checked `u128` arithmetic. The `max()` is the deliberately
    /// pessimistic branch (see module doc) — swapping it for `min()`
    /// would understate the reserve, exactly hazard 1; the
    /// `reserve_uses_l1_*_when_it_exceeds_*` tests below exercise both
    /// directions of the comparison so a swap cannot pass silently.
    pub fn reserve_wei(&self) -> Result<u128, BaseFeeError> {
        let l1_term = self.l1_exact_wei.max(self.l1_upper_wei);
        let l2_plus_l1 = self
            .l2_wei
            .checked_add(l1_term)
            .ok_or(BaseFeeError::ExposureOverflow)?;
        l2_plus_l1
            .checked_add(self.operator_wei)
            .ok_or(BaseFeeError::ExposureOverflow)
    }
}

/// A [`NativeExposure`] that has already passed [`enforce_exposure_gate`]
/// against a caller-supplied ceiling (hardening M6). Both fields are
/// private and set only inside the gate function, so the only way to hold
/// a `GatedExposure` is to have gone through [`quote_exposure`] or
/// [`submit_exposure`] successfully — this is what makes the module doc's
/// "gate already checked" claim structurally true. [`NativeExposure`]
/// stays public with public fields as the raw wei decomposition (useful
/// for logging/diagnostics on its own); `GatedExposure` is the type a
/// caller should hold onto as proof the gate ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatedExposure {
    exposure: NativeExposure,
    reserve_wei: u128,
}

impl GatedExposure {
    /// The raw wei decomposition that was gated.
    pub fn exposure(&self) -> NativeExposure {
        self.exposure
    }

    /// `self.exposure().reserve_wei()`, precomputed at gate time. Returns
    /// `u128` directly (not a `Result`): the gate already computed and
    /// validated this exact value against the ceiling, so recomputing it
    /// here cannot fail.
    pub fn reserve_wei(&self) -> u128 {
        self.reserve_wei
    }
}

/// Fail-closed exposure gate: computes `exposure.reserve_wei()`, then
/// rejects (never clamps) if it exceeds `max_native_exposure_wei`
/// (`StreamGConfig::max_native_exposure_wei`, Task 1).
fn enforce_exposure_gate(
    exposure: NativeExposure,
    max_native_exposure_wei: WeiCeiling,
) -> Result<GatedExposure, BaseFeeError> {
    let reserve = exposure.reserve_wei()?;
    let ceiling_wei = max_native_exposure_wei.get();
    if reserve > ceiling_wei {
        return Err(BaseFeeError::ExposureExceedsSchedule {
            reserve_wei: reserve,
            ceiling_wei,
        });
    }
    Ok(GatedExposure {
        exposure,
        reserve_wei: reserve,
    })
}

/// Pre-flight exposure quote, before a real transaction exists: works
/// from a gas-unit ceiling and a tx-size ceiling (not real bytes). Calls
/// only the size-based `getL1FeeUpperBound` oracle method — never
/// `getL1Fee`, since there are no real bytes yet to hash. Enforces the
/// exposure gate itself; a rejected quote never reaches any
/// state-changing chain call (this module makes none).
pub fn quote_exposure(
    chain: &dyn ChainClient,
    gas_unit_ceiling: GasUnits,
    max_fee_per_gas: MaxFeePerGas,
    unsigned_size_ceiling: TxSizeBytes,
    max_native_exposure_wei: WeiCeiling,
) -> Result<GatedExposure, BaseFeeError> {
    // Degenerate-input guards (hardening M2) — fail before any chain call,
    // same fail-fast posture as the overflow checks below. A zero gas-unit
    // or zero size ceiling can never correspond to a real transaction.
    if gas_unit_ceiling.get() == 0 {
        return Err(BaseFeeError::ZeroGasUnits);
    }
    if unsigned_size_ceiling.get() == 0 {
        return Err(BaseFeeError::ZeroTxSizeCeiling);
    }
    let l2_wei = u128::from(gas_unit_ceiling.get())
        .checked_mul(max_fee_per_gas.get())
        .ok_or(BaseFeeError::ExposureOverflow)?;
    let l1_upper_wei = chain.gas_oracle_l1_fee_upper_bound(unsigned_size_ceiling.get())?;
    let operator_wei = chain.gas_oracle_operator_fee(gas_unit_ceiling.get())?;
    let exposure = NativeExposure {
        l2_wei,
        l1_exact_wei: 0,
        l1_upper_wei,
        operator_wei,
    };
    enforce_exposure_gate(exposure, max_native_exposure_wei)
}

/// Exposure check at submit time, once the real EIP-2718 transaction
/// bytes exist: calls the exact `getL1Fee` on those bytes, and also
/// `getL1FeeUpperBound` on their real size (defense in depth — see module
/// doc), plus `getOperatorFee` on the real gas limit. Enforces the
/// exposure gate itself; a rejected submit never reaches any
/// state-changing chain call (this module makes none — broadcasting is
/// the caller's responsibility, strictly after this returns `Ok`).
pub fn submit_exposure(
    chain: &dyn ChainClient,
    gas_limit: GasUnits,
    max_fee_per_gas: MaxFeePerGas,
    unsigned_eip2718: &[u8],
    max_native_exposure_wei: WeiCeiling,
) -> Result<GatedExposure, BaseFeeError> {
    // Degenerate-input guard (hardening M2) — fail before any chain call.
    // A real EIP-2718 transaction is never empty.
    if unsigned_eip2718.is_empty() {
        return Err(BaseFeeError::EmptyTransaction);
    }
    let l2_wei = u128::from(gas_limit.get())
        .checked_mul(max_fee_per_gas.get())
        .ok_or(BaseFeeError::ExposureOverflow)?;
    let l1_exact_wei = chain.gas_oracle_l1_fee(unsigned_eip2718)?;
    let size = u64::try_from(unsigned_eip2718.len())
        .map_err(|_| BaseFeeError::TxSizeOverflow(unsigned_eip2718.len()))?;
    let l1_upper_wei = chain.gas_oracle_l1_fee_upper_bound(size)?;
    let operator_wei = chain.gas_oracle_operator_fee(gas_limit.get())?;
    let exposure = NativeExposure {
        l2_wei,
        l1_exact_wei,
        l1_upper_wei,
        operator_wei,
    };
    enforce_exposure_gate(exposure, max_native_exposure_wei)
}

/// What [`submit_exposure_for_chain`] concluded. **There is no "failed"
/// variant** — a failure is the `Err` arm; this enum only distinguishes
/// "the gate ran and passed" from "the gate could not run here".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitExposure {
    /// The oracle was queried and [`enforce_exposure_gate`] passed.
    Gated(GatedExposure),
    /// The chain does not carry the `GasPriceOracle` predeploy, so no
    /// oracle call was made and **no ceiling was enforced**. Disclosed via
    /// `preflight::UNVERIFIED_CHECKS`; see
    /// [`chain_carries_gas_price_oracle`].
    SkippedNoGasPriceOracle { chain_id: u64 },
}

impl SubmitExposure {
    /// The gated decomposition, or `None` when the gate was skipped.
    /// Deliberately an `Option` rather than a defaulted zero: "no exposure
    /// was computed" and "the exposure was zero" are different facts and a
    /// caller that logs money must not conflate them.
    pub fn gated(&self) -> Option<GatedExposure> {
        match self {
            SubmitExposure::Gated(g) => Some(*g),
            SubmitExposure::SkippedNoGasPriceOracle { .. } => None,
        }
    }

    /// True when no ceiling was enforced. Named so a reader of the call
    /// site cannot mistake this for a pass.
    pub fn gate_was_skipped(&self) -> bool {
        matches!(self, SubmitExposure::SkippedNoGasPriceOracle { .. })
    }
}

/// [`submit_exposure`] with the chain-shape guard applied — **the entry
/// point both broadcast paths call**, so the skip policy exists exactly
/// once (`submit::submit_sponsored_enrollment` and
/// `broadcaster::sign_persist_and_broadcast`).
///
/// On a chain that does not carry the predeploy this makes **no chain call
/// at all** and returns [`SubmitExposure::SkippedNoGasPriceOracle`]; the
/// disclosure obligation is the caller's, discharged by
/// `preflight::UNVERIFIED_CHECKS`. Everywhere else it is exactly
/// [`submit_exposure`].
pub fn submit_exposure_for_chain(
    chain: &dyn ChainClient,
    chain_id: u64,
    gas_limit: GasUnits,
    max_fee_per_gas: MaxFeePerGas,
    unsigned_eip2718: &[u8],
    max_native_exposure_wei: WeiCeiling,
) -> Result<SubmitExposure, BaseFeeError> {
    if !chain_carries_gas_price_oracle(chain_id) {
        return Ok(SubmitExposure::SkippedNoGasPriceOracle { chain_id });
    }
    submit_exposure(
        chain,
        gas_limit,
        max_fee_per_gas,
        unsigned_eip2718,
        max_native_exposure_wei,
    )
    .map(SubmitExposure::Gated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{MockChain, MockOp};

    // -- 1. plan-mandated exact numbers (brief §8.1) -----------------------

    #[test]
    fn reserve_is_l2_plus_max_l1_plus_operator() {
        let gas_limit: u128 = 500_000;
        let max_fee_per_gas: u128 = 1_000_000_000;
        let l1_exact = 20_000_000_000_000u128;
        let l1_upper = 25_000_000_000_000u128;
        let operator = 1_000_000_000_000u128;

        let exposure = NativeExposure {
            l2_wei: gas_limit.checked_mul(max_fee_per_gas).unwrap(),
            l1_exact_wei: l1_exact,
            l1_upper_wei: l1_upper,
            operator_wei: operator,
        };

        let expected = gas_limit * max_fee_per_gas + l1_upper + operator;
        assert_eq!(exposure.reserve_wei().unwrap(), expected);
        assert_eq!(expected, 526_000_000_000_000u128);
    }

    // -- 2. exposure gate (brief §8.2) --------------------------------------

    #[test]
    fn quote_rejects_when_exposure_exceeds_schedule() {
        let chain = MockChain::new();
        chain.set_l1_upper_fee_wei(25_000_000_000_000);
        chain.set_operator_fee_wei(1_000_000_000_000);

        // l2 alone (500_000 * 1_000_000_000 = 5e14) already exceeds this
        // ceiling — the gate must reject, not clamp.
        let ceiling = 100_000_000_000_000u128; // 1e14
        let err = quote_exposure(
            &chain,
            GasUnits::new(500_000),
            MaxFeePerGas::new(1_000_000_000),
            TxSizeBytes::new(1_000),
            WeiCeiling::new(ceiling),
        )
        .unwrap_err();
        match err {
            BaseFeeError::ExposureExceedsSchedule {
                reserve_wei,
                ceiling_wei,
            } => {
                assert_eq!(ceiling_wei, ceiling);
                assert!(reserve_wei > ceiling_wei);
            }
            other => panic!("expected ExposureExceedsSchedule, got {other:?}"),
        }
        assert_eq!(err.code(), ERR_EXPOSURE_EXCEEDS_SCHEDULE);
    }

    // -- 3. max() exercised in both directions ------------------------------

    #[test]
    fn reserve_uses_l1_exact_when_it_exceeds_upper() {
        let exposure = NativeExposure {
            l2_wei: 1_000,
            l1_exact_wei: 9_000,
            l1_upper_wei: 500,
            operator_wei: 10,
        };
        // If max() were swapped for min(), this would compute 1_510, not 10_010.
        assert_eq!(exposure.reserve_wei().unwrap(), 1_000 + 9_000 + 10);
    }

    #[test]
    fn reserve_uses_l1_upper_when_it_exceeds_exact() {
        let exposure = NativeExposure {
            l2_wei: 1_000,
            l1_exact_wei: 500,
            l1_upper_wei: 9_000,
            operator_wei: 10,
        };
        // If max() were swapped for min(), this would compute 1_510, not 10_010.
        assert_eq!(exposure.reserve_wei().unwrap(), 1_000 + 9_000 + 10);
    }

    // -- 4. overflow: checked, never wrapped ---------------------------------

    #[test]
    fn reserve_wei_overflow_on_l2_plus_l1_max_add() {
        let exposure = NativeExposure {
            l2_wei: u128::MAX,
            l1_exact_wei: 0,
            l1_upper_wei: 1,
            operator_wei: 0,
        };
        let err = exposure.reserve_wei().unwrap_err();
        assert!(matches!(err, BaseFeeError::ExposureOverflow));
        assert_eq!(err.code(), ERR_EXPOSURE_OVERFLOW);
    }

    #[test]
    fn reserve_wei_overflow_on_operator_add() {
        // l2 + max(l1_exact, l1_upper) lands exactly on u128::MAX — no
        // overflow there — but adding `operator_wei` must still overflow,
        // proving the SECOND checked_add is guarded independently of the
        // first.
        let exposure = NativeExposure {
            l2_wei: u128::MAX - 1,
            l1_exact_wei: 0,
            l1_upper_wei: 1,
            operator_wei: 1,
        };
        let err = exposure.reserve_wei().unwrap_err();
        assert!(matches!(err, BaseFeeError::ExposureOverflow));
    }

    #[test]
    fn quote_exposure_rejects_gas_times_price_multiply_overflow() {
        let chain = MockChain::new();
        chain.set_l1_upper_fee_wei(1);
        chain.set_operator_fee_wei(1);

        let err = quote_exposure(
            &chain,
            GasUnits::new(u64::MAX),
            MaxFeePerGas::new(u128::MAX),
            TxSizeBytes::new(1_000),
            WeiCeiling::new(u128::MAX),
        )
        .unwrap_err();
        assert!(matches!(err, BaseFeeError::ExposureOverflow));
        // Fails fast, before ever touching the chain — no oracle call, no
        // wrapped-and-silently-wrong value reaches MockChain's counters.
        assert_eq!(chain.l1_fee_upper_bound_call_count(), 0);
        assert_eq!(chain.operator_fee_call_count(), 0);
    }

    #[test]
    fn submit_exposure_rejects_gas_times_price_multiply_overflow() {
        // Hardening M5 — the analogous overflow test existed for
        // quote_exposure but not submit_exposure; submit's checked_mul is a
        // separate call site and needs its own coverage.
        let chain = MockChain::new();
        chain.set_l1_exact_fee_wei(1);
        chain.set_l1_upper_fee_wei(1);
        chain.set_operator_fee_wei(1);

        let tx = vec![0xAAu8; 10];
        let err = submit_exposure(
            &chain,
            GasUnits::new(u64::MAX),
            MaxFeePerGas::new(u128::MAX),
            &tx,
            WeiCeiling::new(u128::MAX),
        )
        .unwrap_err();
        assert!(matches!(err, BaseFeeError::ExposureOverflow));
        // Fails fast, before ever touching the chain.
        assert_eq!(chain.l1_fee_call_count(), 0);
        assert_eq!(chain.l1_fee_upper_bound_call_count(), 0);
        assert_eq!(chain.operator_fee_call_count(), 0);
    }

    // -- 4b. degenerate inputs rejected, not silently accepted (M2) ---------

    #[test]
    fn quote_exposure_rejects_zero_gas_unit_ceiling() {
        let chain = MockChain::new();
        let err = quote_exposure(
            &chain,
            GasUnits::new(0),
            MaxFeePerGas::new(1_000_000_000),
            TxSizeBytes::new(500),
            WeiCeiling::new(u128::MAX),
        )
        .unwrap_err();
        assert!(matches!(err, BaseFeeError::ZeroGasUnits));
        assert_eq!(err.code(), ERR_ZERO_GAS_UNITS);
        // Fails fast, before ever touching the chain.
        assert_eq!(chain.l1_fee_upper_bound_call_count(), 0);
        assert_eq!(chain.operator_fee_call_count(), 0);
    }

    #[test]
    fn quote_exposure_rejects_zero_tx_size_ceiling() {
        let chain = MockChain::new();
        let err = quote_exposure(
            &chain,
            GasUnits::new(500_000),
            MaxFeePerGas::new(1_000_000_000),
            TxSizeBytes::new(0),
            WeiCeiling::new(u128::MAX),
        )
        .unwrap_err();
        assert!(matches!(err, BaseFeeError::ZeroTxSizeCeiling));
        assert_eq!(err.code(), ERR_ZERO_TX_SIZE_CEILING);
        assert_eq!(chain.l1_fee_upper_bound_call_count(), 0);
        assert_eq!(chain.operator_fee_call_count(), 0);
    }

    #[test]
    fn submit_exposure_rejects_empty_transaction() {
        let chain = MockChain::new();
        let err = submit_exposure(
            &chain,
            GasUnits::new(500_000),
            MaxFeePerGas::new(1_000_000_000),
            &[],
            WeiCeiling::new(u128::MAX),
        )
        .unwrap_err();
        assert!(matches!(err, BaseFeeError::EmptyTransaction));
        assert_eq!(err.code(), ERR_EMPTY_TRANSACTION);
        assert_eq!(chain.l1_fee_call_count(), 0);
        assert_eq!(chain.l1_fee_upper_bound_call_count(), 0);
        assert_eq!(chain.operator_fee_call_count(), 0);
    }

    // -- 4c. GatedExposure API surface (hardening M6) ------------------------

    #[test]
    fn gated_exposure_exposes_reserve_and_raw_decomposition() {
        let chain = MockChain::new();
        chain.set_l1_upper_fee_wei(25_000_000_000_000);
        chain.set_operator_fee_wei(1_000_000_000_000);

        let gated = quote_exposure(
            &chain,
            GasUnits::new(500_000),
            MaxFeePerGas::new(1_000_000_000),
            TxSizeBytes::new(1_000),
            WeiCeiling::new(u128::MAX),
        )
        .unwrap();

        let expected_l2 = 500_000u128 * 1_000_000_000u128;
        assert_eq!(gated.exposure().l2_wei, expected_l2);
        assert_eq!(gated.exposure().l1_upper_wei, 25_000_000_000_000);
        assert_eq!(gated.exposure().operator_wei, 1_000_000_000_000);
        // The precomputed reserve must agree with recomputing it from the
        // raw decomposition — GatedExposure must not drift from NativeExposure.
        assert_eq!(gated.reserve_wei(), gated.exposure().reserve_wei().unwrap());
        assert_eq!(
            gated.reserve_wei(),
            expected_l2 + 25_000_000_000_000 + 1_000_000_000_000
        );
    }

    // -- 5. selector/signature pins (brief §3) -------------------------------
    //
    // Expected values are sourced independently from the public
    // 4byte.directory selector registry (not derived from `oracle_selector`
    // itself), so this test catches drift in either the signature string or
    // this module's keccak wiring.

    #[test]
    fn base_fee_selector_pin_get_l1_fee() {
        assert_eq!(SIG_GET_L1_FEE, "getL1Fee(bytes)");
        assert_eq!(oracle_selector(SIG_GET_L1_FEE), [0x49, 0x94, 0x8e, 0x0e]);
    }

    #[test]
    fn base_fee_selector_pin_get_l1_fee_upper_bound() {
        assert_eq!(SIG_GET_L1_FEE_UPPER_BOUND, "getL1FeeUpperBound(uint256)");
        assert_eq!(
            oracle_selector(SIG_GET_L1_FEE_UPPER_BOUND),
            [0xf1, 0xc7, 0xa5, 0x8b]
        );
    }

    #[test]
    fn base_fee_selector_pin_get_operator_fee() {
        assert_eq!(SIG_GET_OPERATOR_FEE, "getOperatorFee(uint256)");
        assert_eq!(
            oracle_selector(SIG_GET_OPERATOR_FEE),
            [0x27, 0x5a, 0xed, 0xd2]
        );
    }

    #[test]
    fn gas_price_oracle_address_matches_documented_hex() {
        let expected = hex::decode("420000000000000000000000000000000000000F").unwrap();
        assert_eq!(GAS_PRICE_ORACLE_ADDRESS.to_vec(), expected);
    }

    // -- 6. L1-DA spike rejected; broadcaster/send path never invoked -------

    #[test]
    fn l1_da_spike_pushes_reserve_over_schedule_and_send_path_untouched() {
        let chain = MockChain::new();
        // A pathological L1-DA spike dwarfs everything else.
        chain.set_l1_upper_fee_wei(10_000_000_000_000_000_000); // 10 ETH
        chain.set_operator_fee_wei(1_000_000_000_000);

        let ceiling = 1_000_000_000_000_000_000u128; // 1 ETH
        let err = quote_exposure(
            &chain,
            GasUnits::new(100_000),
            MaxFeePerGas::new(1_000_000_000),
            TxSizeBytes::new(1_000),
            WeiCeiling::new(ceiling),
        )
        .unwrap_err();
        assert!(matches!(err, BaseFeeError::ExposureExceedsSchedule { .. }));

        // The oracle *read* calls (upper-bound, operator) are expected —
        // computing the reserve requires them. What must NEVER happen on a
        // rejected quote is any state-changing broadcaster/send op: no
        // Propose/Challenge/Confirm/Bind/Enroll/Claim, and no send_native.
        let state_changing_ops = chain
            .ops()
            .into_iter()
            .filter(|op| {
                !matches!(
                    op,
                    MockOp::L1Fee { .. }
                        | MockOp::L1FeeUpperBound { .. }
                        | MockOp::OperatorFee { .. }
                )
            })
            .count();
        assert_eq!(state_changing_ops, 0);
        assert!(chain.sent_native().is_empty());
    }

    // -- 7. quote uses upper-bound; submit uses exact — copy-paste-proof ----

    #[test]
    fn quote_exposure_uses_upper_bound_not_exact_oracle_call() {
        let chain = MockChain::new();
        chain.set_l1_upper_fee_wei(1);
        chain.set_operator_fee_wei(1);

        quote_exposure(
            &chain,
            GasUnits::new(100_000),
            MaxFeePerGas::new(1),
            TxSizeBytes::new(500),
            WeiCeiling::new(u128::MAX),
        )
        .unwrap();

        assert_eq!(
            chain.l1_fee_call_count(),
            0,
            "quote_exposure must never call the exact getL1Fee — no real tx bytes exist yet"
        );
        assert_eq!(chain.l1_fee_upper_bound_call_count(), 1);
        assert_eq!(chain.operator_fee_call_count(), 1);
    }

    #[test]
    fn submit_exposure_uses_exact_oracle_call() {
        let chain = MockChain::new();
        chain.set_l1_exact_fee_wei(1);
        chain.set_l1_upper_fee_wei(1);
        chain.set_operator_fee_wei(1);

        submit_exposure(
            &chain,
            GasUnits::new(100_000),
            MaxFeePerGas::new(1),
            &[0xAA, 0xBB, 0xCC],
            WeiCeiling::new(u128::MAX),
        )
        .unwrap();

        assert_eq!(
            chain.l1_fee_call_count(),
            1,
            "submit_exposure must call the exact getL1Fee on the real serialized tx"
        );
        // Hardening M4: submit's defense-in-depth upper-bound call was
        // uncovered — this bound call is silent if it's ever accidentally
        // dropped, since reserve_wei() would still compute (against a
        // stale/zero l1_upper_wei) without erroring.
        assert_eq!(chain.l1_fee_upper_bound_call_count(), 1);
        assert_eq!(chain.operator_fee_call_count(), 1);
    }

    // -- 8. RPC/oracle failure is fail-closed, never a reserve (M5) ---------

    #[test]
    fn quote_exposure_chain_error_is_fail_closed_not_a_reserve() {
        let chain = MockChain::new();
        chain.set_gas_oracle_error(Some("rpc unavailable".to_string()));

        let err = quote_exposure(
            &chain,
            GasUnits::new(100_000),
            MaxFeePerGas::new(1_000_000_000),
            TxSizeBytes::new(500),
            WeiCeiling::new(u128::MAX),
        )
        .unwrap_err();
        assert!(
            matches!(err, BaseFeeError::Chain(_)),
            "an oracle RPC failure must surface as BaseFeeError::Chain, not a computed reserve; got {err:?}"
        );
        assert_eq!(err.code(), "INTERNAL");
    }

    #[test]
    fn submit_exposure_chain_error_is_fail_closed_not_a_reserve() {
        let chain = MockChain::new();
        chain.set_gas_oracle_error(Some("rpc unavailable".to_string()));

        let err = submit_exposure(
            &chain,
            GasUnits::new(100_000),
            MaxFeePerGas::new(1),
            &[0xAA, 0xBB, 0xCC],
            WeiCeiling::new(u128::MAX),
        )
        .unwrap_err();
        assert!(
            matches!(err, BaseFeeError::Chain(_)),
            "an oracle RPC failure must surface as BaseFeeError::Chain, not a computed reserve; got {err:?}"
        );
        assert_eq!(err.code(), "INTERNAL");
    }

    // -- 8b. Wave 2: the chain-shape guard ---------------------------------
    //
    // Both arms below run from the SAME armed oracle values and the SAME
    // impossible ceiling of zero. The only thing that differs is the chain
    // id, so neither arm can pass for an incidental reason.

    /// Nonzero on purpose: with zeros the reserve collapses to `l2_wei` and
    /// "the oracle was not called" would be indistinguishable from "the
    /// oracle returned nothing interesting".
    fn arm(chain: &MockChain) {
        chain.set_l1_exact_fee_wei(20_000_000_000_000);
        chain.set_l1_upper_fee_wei(25_000_000_000_000);
        chain.set_operator_fee_wei(1_000_000_000_000);
    }

    /// On the local dev chain the predeploy does not exist, so the gate
    /// must make **no chain call at all** and enforce **no ceiling** —
    /// asserted against a ceiling of zero, which every other chain would
    /// refuse instantly.
    ///
    /// If this instead called the oracle, `rpc_chain`'s
    /// `decode_gas_oracle_u256` would turn the empty return into a hard
    /// `Err`, `SubmitError::retryability()` would classify it `Terminal`,
    /// and every sponsored enrollment on chain 31337 would be permanently
    /// dead. That is the outage this guard exists to prevent.
    ///
    /// MUTATION DETECTED: `chain_carries_gas_price_oracle` → `|_| true`.
    /// The `Ok` becomes `Err(ExposureExceedsSchedule)` and the op count
    /// becomes 3.
    #[test]
    fn submit_exposure_for_chain_skips_without_calling_the_oracle_on_the_local_dev_chain() {
        let chain = MockChain::new();
        arm(&chain);

        let outcome = submit_exposure_for_chain(
            &chain,
            LOCAL_DEV_CHAIN_ID,
            GasUnits::new(500_000),
            MaxFeePerGas::new(1_000_000_000),
            &[0x02, 0xAA, 0xBB],
            // Impossible on any oracle-carrying chain.
            WeiCeiling::new(0),
        )
        .expect("the guard must skip, not fail, where the predeploy does not exist");

        assert_eq!(
            outcome,
            SubmitExposure::SkippedNoGasPriceOracle {
                chain_id: LOCAL_DEV_CHAIN_ID
            }
        );
        assert!(outcome.gate_was_skipped());
        assert_eq!(
            outcome.gated(),
            None,
            "a skipped gate must not hand back a GatedExposure — that type IS the proof the \
             ceiling was checked"
        );
        assert_eq!(
            chain.ops().len(),
            0,
            "the guard made a chain call on a chain that carries no GasPriceOracle"
        );
    }

    /// The paired arm: identical inputs, an oracle-carrying chain id, and
    /// the gate both calls the oracle (all three methods) and refuses.
    /// Without this the arm above would be equally consistent with a guard
    /// that skips everywhere — i.e. with the gate being decorative.
    ///
    /// MUTATION DETECTED: `chain_carries_gas_price_oracle` → `|_| false`
    /// (this arm's `expect_err` panics and the op count drops to 0).
    #[test]
    fn submit_exposure_for_chain_runs_the_gate_on_an_oracle_carrying_chain() {
        const BASE_MAINNET: u64 = 8453;
        let chain = MockChain::new();
        arm(&chain);

        let err = submit_exposure_for_chain(
            &chain,
            BASE_MAINNET,
            GasUnits::new(500_000),
            MaxFeePerGas::new(1_000_000_000),
            &[0x02, 0xAA, 0xBB],
            WeiCeiling::new(0),
        )
        .expect_err("a nonzero reserve against a zero ceiling must be refused");

        match err {
            BaseFeeError::ExposureExceedsSchedule {
                reserve_wei,
                ceiling_wei,
            } => {
                // 5.0e14 + max(2.0e13, 2.5e13) + 1.0e12.
                assert_eq!(reserve_wei, 526_000_000_000_000);
                assert_eq!(ceiling_wei, 0);
            }
            other => panic!("expected ExposureExceedsSchedule, got {other:?}"),
        }
        assert_eq!(
            chain.l1_fee_call_count(),
            1,
            "the exact getL1Fee call is what makes this arm non-vacuous"
        );
        assert_eq!(chain.operator_fee_call_count(), 1);
        assert_eq!(
            chain.ops().len(),
            3,
            "all three oracle methods must be read"
        );
    }

    /// A pass on an oracle-carrying chain yields a [`GatedExposure`] — the
    /// type whose private fields are the structural proof that the ceiling
    /// really was compared — and it is the *same* reserve the refusal arm
    /// reported. So "admitted" and "refused" differ only in the ceiling.
    #[test]
    fn submit_exposure_for_chain_admits_at_the_boundary_and_reports_the_reserve() {
        const BASE_MAINNET: u64 = 8453;
        let chain = MockChain::new();
        arm(&chain);

        let outcome = submit_exposure_for_chain(
            &chain,
            BASE_MAINNET,
            GasUnits::new(500_000),
            MaxFeePerGas::new(1_000_000_000),
            &[0x02, 0xAA, 0xBB],
            // Exactly the reserve: the gate refuses on `>`, so this passes.
            WeiCeiling::new(526_000_000_000_000),
        )
        .expect("a reserve exactly at the ceiling must be admitted");

        let gated = outcome.gated().expect("an admitted gate must be Gated");
        assert!(!outcome.gate_was_skipped());
        assert_eq!(gated.reserve_wei(), 526_000_000_000_000);
        assert_eq!(chain.ops().len(), 3);
    }

    // -- 9. calldata BODY pins (hardening Important 2) -----------------------
    //
    // Every byte below is derived BY HAND from the ABI rules (selector,
    // head offset word, length word, data, right-pad-to-32), independently
    // of `u256_be`/`oracle_selector`/`abi_encode_dynamic_bytes` — none of
    // those functions are called to build `expected`. The four selector
    // bytes in each `expected` are the same independently-sourced
    // (4byte.directory / `cast sig`) literals already pinned in section 5
    // above, not a call to `oracle_selector`. This is deliberate: if these
    // pins were generated by calling the code under test, an edit to
    // `u256_be`'s byte range or the `0x20` head offset would still pass
    // silently. `MockChain` never decodes calldata, so without these pins
    // only code review stands between a broken encoder and production.

    #[test]
    fn encode_get_l1_fee_pin_empty_bytes() {
        // getL1Fee(bytes) with unsigned_tx = &[] (0 bytes).
        // Layout: selector(4) | offset=0x20(32) | length=0(32) | data(0) | pad(0)
        // pad = (32 - 0 % 32) % 32 = 0 -- a zero-length `bytes` needs no padding.
        let mut expected = vec![0x49, 0x94, 0x8e, 0x0e]; // getL1Fee(bytes)
        expected.extend_from_slice(&[0u8; 31]);
        expected.push(0x20); // head word: dynamic tail starts at byte 0x20
        expected.extend_from_slice(&[0u8; 32]); // length word: 0

        let actual = encode_get_l1_fee(&[]);
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 68); // 4 + 32 + 32
    }

    #[test]
    fn encode_get_l1_fee_pin_non_32_multiple_length_exercises_padding() {
        // getL1Fee(bytes) with unsigned_tx = [0xAA, 0xBB, 0xCC] (3 bytes,
        // not a multiple of 32) -- exercises the right-pad arithmetic.
        // Layout: selector(4) | offset=0x20(32) | length=3(32) | data(3) | pad(29)
        // pad = (32 - 3 % 32) % 32 = 29.
        let mut expected = vec![0x49, 0x94, 0x8e, 0x0e]; // getL1Fee(bytes)
        expected.extend_from_slice(&[0u8; 31]);
        expected.push(0x20); // head word
        expected.extend_from_slice(&[0u8; 31]);
        expected.push(0x03); // length word: 3
        expected.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // data
        expected.extend_from_slice(&[0u8; 29]); // right-pad to the next 32-byte boundary

        let actual = encode_get_l1_fee(&[0xAA, 0xBB, 0xCC]);
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 100); // 4 + 32 + 32 + 3 + 29
    }

    #[test]
    fn encode_get_l1_fee_upper_bound_pin() {
        // getL1FeeUpperBound(uint256) with unsigned_tx_size = 12_345.
        // 12_345 decimal = 0x3039 hex (2 significant bytes).
        // Layout: selector(4) | size as a plain uint256 word(32)
        let mut expected = vec![0xf1, 0xc7, 0xa5, 0x8b]; // getL1FeeUpperBound(uint256)
        expected.extend_from_slice(&[0u8; 30]);
        expected.push(0x30);
        expected.push(0x39);

        let actual = encode_get_l1_fee_upper_bound(12_345);
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 36); // 4 + 32
    }

    #[test]
    fn encode_get_operator_fee_pin() {
        // getOperatorFee(uint256) with gas_limit = 500_000.
        // 500_000 decimal = 0x07A120 hex (3 significant bytes).
        let mut expected = vec![0x27, 0x5a, 0xed, 0xd2]; // getOperatorFee(uint256)
        expected.extend_from_slice(&[0u8; 29]);
        expected.extend_from_slice(&[0x07, 0xA1, 0x20]);

        let actual = encode_get_operator_fee(500_000);
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 36); // 4 + 32
    }
}
