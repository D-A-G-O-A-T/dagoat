//! Token capability manifest hard gate (release-blocking hazard 3) --
//! Stream G.
//!
//! Fail-closed Rust mirror of the deployed `FeeTokenRegistry`
//! authorization predicate
//! (`contracts/src/FeeTokenRegistry.sol::_isAuthorized`), plus a loader for
//! the G1 deployment manifest
//! (`contracts/deployments/31337.stream-g.json`, written by
//! `script/DeployStreamG.s.sol::writeManifest`).
//!
//! ## Ground truth
//!
//! Every constant, field order, and check order below is taken from the
//! Task 4 design brief, which was
//! independently re-confirmed by reading `contracts/src/StreamGTypes.sol`
//! and `contracts/src/FeeTokenRegistry.sol` directly, and cross-checked
//! with `forge script` / `cast keccak` before this module was written --
//! see [`fee_token_config_hash_matches_contract_encoding`] for how the
//! struct-hash regression fixture was derived (not a self-referential
//! Rust-only pin). Do not hand-edit anything here without re-reading the
//! Solidity.
//!
//! ### `feeTokenConfigHash` is NOT a struct field
//! On-chain, `feeTokenConfigHash` is the keccak256 hash *of* a
//! `FeeTokenConfig`, stored separately in `FeeTokenRegistry`
//! (`mapping(address => bytes32) _tokenConfigHashes`, exposed via
//! `getTokenConfigHash`). [`TokenCapability`] therefore has no such field;
//! [`fee_token_config_hash`] computes it from a config the caller supplies,
//! so a mismatch against the on-chain `getTokenConfigHash` value detects a
//! config that does not match what the chain actually hashed.
//!
//! ### `capabilityMask` is `uint256`
//! Represented here as `u128`, not `u64` -- current values fit in far
//! fewer bits, but the type must not silently lie about the on-chain
//! width. See [`TokenCapability::capability_mask`].
//!
//! ### `CAP_*` bits vs `AuthorizationMode` ordinals: independent numbering
//! `StreamGTypes.AuthorizationMode` has ordinals `NONE=0, EIP2612=1,
//! EIP3009=2, PRIOR_ALLOWANCE=3`. The `CAP_*` bitmask constants are a
//! *different* numbering scheme entirely: `CAP_SELL_SPLIT = 1 << 3 = 8`,
//! not `3`. This module never defines an `AuthorizationMode` type and never
//! casts between the two schemes -- see
//! [`cap_constants_do_not_match_authorization_mode_ordinals`], which pins
//! the trap the same way `FeeTokenRegistry.t.sol`'s
//! `test_capability_mask_sell_split_independent_of_mode_ordinal` does.
//! [`assert_token_authorized`]'s `required_capability` parameter is the
//! [`Capability`] newtype, not a bare `u128` -- it can only be built from
//! the four `Capability::EIP2612` / `EIP3009` / `PRIOR_ALLOWANCE` /
//! `SELL_SPLIT` associated constants (combined with `|` or
//! [`Capability::required`]), so a bare integer literal like the
//! `AuthorizationMode` ordinal `3` no longer type-checks in that position.
//!
//! ### `proxyIdentityHash`: rejected at admission, not at the read path
//! `FeeTokenRegistry.upsertTokenConfig` reverts `ProxyIdentityUnsupported()`
//! for any non-zero `proxyIdentityHash` and always stores `bytes32(0)`
//! regardless of what was passed in; `_isAuthorized` never reads the field
//! at all. So this module implements BOTH halves:
//! [`validate_proxy_identity_admissible`]
//! mirrors the write-time revert (call it before treating any config as
//! admitted), and [`assert_token_authorized`] additionally treats a
//! non-zero `live.proxy_identity_hash` as impossible-state defense in
//! depth -- on-chain this should be unreachable (the write path always
//! zeroes it), but since the read path itself never checks it, a config
//! that somehow slipped past admission with a non-zero value would
//! otherwise sail through the read-side check unnoticed.
//!
//! ### Unknown vs inactive token: indistinguishable on-chain
//! A never-configured token has Solidity's zero-default
//! `StreamGTypes.FeeTokenConfig`, so `!cfg.active` fails `_isAuthorized`'s
//! first check -- the exact same outcome as an explicitly deactivated
//! token. `assertTokenAuthorized` reverts the same `TokenNotAuthorized()`
//! either way; there is no `TokenNotConfigured()` on the authorization read
//! path (that error is reachable only from `deactivateToken`). This module
//! mirrors that by mapping every failure of [`assert_token_authorized`]'s
//! five-check block to the same [`TokenManifestError::TokenNotAuthorized`]
//! variant, whose [`TokenManifestError::code`] is always
//! [`ERR_TOKEN_UNSUPPORTED`] -- see
//! [`rejects_inactive_or_unknown_token`].
//!
//! ### `runtimeCodeHash` vs the live EXTCODEHASH
//! The contract never computes `token.codehash` itself; the chain supplies
//! it as part of the `CALL` context and compares it against the stored
//! `cfg.runtimeCodeHash`. Here the two sides come from two *different* RPC
//! reads performed by [`read_live_token_state`]:
//! `keccak256(eth_getCode(token, block))` on one side and
//! `getTokenConfig(token).runtimeCodeHash` on the other. See
//! [`live_reading_rejects_code_hash_that_differs_from_configured_runtime_code_hash`]
//! -- replacing the deployed bytecode while leaving the config alone must
//! (and does) fail the gate.
//!
//! ### What [`LiveTokenReading`] does and does not guarantee (Wave B)
//! Before Wave B, [`assert_token_authorized`] took the configured record,
//! the observed code hash, the chain id and the queried address as four
//! separate caller-supplied parameters. `TokenCapability` has all-`pub`
//! fields and the three newtypes had `From` impls, so
//! `assert_token_authorized(&cfg, cfg.runtime_code_hash.into(), ...)`
//! compiled and reduced the whole gate to `x == x`. That is now
//! unrepresentable: the gate takes a [`LiveTokenReading`], whose fields are
//! private and whose only non-`cfg(test)` constructor is
//! [`read_live_token_state`]. The `From` impls are gone and the newtypes'
//! `new` constructors are `pub(crate)`.
//!
//! Stated precisely, so this does not become another overstated claim:
//!
//! **Guaranteed.** Outside tests, every value the five checks compare was
//! produced by [`read_live_token_state`] from a `ChainClient` read at one
//! caller-pinned block; the decoded `FeeTokenConfig` provably hashes to the
//! same registry's `getTokenConfigHash` at that block; empty deployed code
//! fails closed rather than hashing `""`; and `active == false` or a
//! non-zero `proxyIdentityHash` is rejected before a reading exists.
//!
//! Gate check 3 in particular is a real check as of Task 6 Wave B:
//! [`LiveTokenReading::live_chain_id`] is `ChainClient::chain_id`
//! (`eth_chainId`), read by [`read_live_token_state`] itself, so
//! `config.chainId != <the chain we are on>` now rejects -- see
//! [`live_reading_rejects_chain_id_the_endpoint_disagrees_with`], which
//! mutates only the endpoint's answer and leaves the config, its registry
//! hash and the manifest untouched.
//!
//! **NOT guaranteed.**
//! - *Freshness / liveness.* `block` is whatever the caller passed. This
//!   module never calls `pinned_block_number()` itself and enforces no
//!   staleness bound. A reading proves consistency **at that block**, not
//!   that the block is recent or canonical, and reorgs are not considered.
//!   `eth_chainId` in particular takes no block parameter, so the chain-id
//!   read is not pinned to `block` at all.
//! - *That the endpoint on the other end of the socket is honest.*
//!   [`read_live_token_state`] now takes a [`TrustedChain`], so in a release
//!   build the reads provably came from [`crate::rpc_chain::RpcChain`] and
//!   **not** from [`crate::chain::MockChain`] (which is `pub`, not
//!   `#[cfg(test)]`, and five lines of which used to fabricate an authorized
//!   reading) — that substitution is closed, by construction, at compile
//!   time. What is *not* closed is a genuine RPC endpoint that lies: if the
//!   node `RpcChain` is pointed at returns fabricated `eth_getCode` /
//!   `getTokenConfig` answers, every check here still compares two of its
//!   answers. That is a trust-the-endpoint assumption, not a code defect, and
//!   it is not something this module can close.
//!   In `#[cfg(test)]` builds the `From<&C>` conversion accepts any
//!   `ChainClient`, which is what every test in this tree relies on.
//! - *Manifest agreement.* [`read_live_token_state`] does not call
//!   `activeManifestHash()` (sourcing contract R2 step 2); it is given no
//!   manifest to compare against. The caller still owes that check.
//! - *Any statement about the submit path.* Nothing here proves a production
//!   handler calls this gate before spending -- that binding is still owed to
//!   the integration suite.
//!
//! ### Divergence: `required_capability == 0`
//! On-chain, `(mask & 0) == 0` always holds, so a required capability of
//! zero trivially authorizes any active, correctly-identified token. This
//! module deliberately diverges: "authorize me for nothing" is never a
//! legitimate call, so [`assert_token_authorized`] rejects a
//! [`Capability`] whose [`Capability::bits`] is zero outright with
//! [`TokenManifestError::ZeroRequiredCapability`] before ever touching the
//! five-check mirror -- see [`Capability::required`] (an empty slice
//! yields the zero mask) for the one sanctioned way to construct it. This
//! is a Rust-only guard with no on-chain equivalent -- documented here per
//! the brief rather than silently diverging.

use std::fs;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

use crate::merkle::keccak256;

// ---------------------------------------------------------------------------
// Capability bitmask -- StreamGTypes.sol:19-22. Independent numbering from
// `AuthorizationMode`'s ordinals -- see module doc.
// ---------------------------------------------------------------------------

pub const CAP_EIP2612: u128 = 1 << 0;
pub const CAP_EIP3009: u128 = 1 << 1;
pub const CAP_PRIOR_ALLOWANCE: u128 = 1 << 2;
pub const CAP_SELL_SPLIT: u128 = 1 << 3;

// ---------------------------------------------------------------------------
// Zero-cost newtypes for `assert_token_authorized`'s parameters -- see
// module doc "`runtimeCodeHash` vs the live EXTCODEHASH" and "`CAP_*` bits
// vs `AuthorizationMode` ordinals". Each wraps exactly the primitive type
// the matching `TokenCapability` field uses, but as a distinct Rust type,
// so a value read from a `TokenCapability` (the *configured* state) cannot
// be passed where a freshly-observed *live* value is expected without an
// explicit, visible conversion.
// ---------------------------------------------------------------------------

/// The live EXTCODEHASH the caller observed on-chain for [`QueriedToken`] --
/// see module doc. Distinct from `TokenCapability::runtime_code_hash`
/// (the configured value) even though both are `[u8; 32]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedCodeHash([u8; 32]);

impl ObservedCodeHash {
    /// Crate-internal: reaching the gate now requires a [`LiveTokenReading`],
    /// which only [`read_live_token_state`] can build, so wrapping a
    /// hand-picked `[u8; 32]` here no longer gets a value into
    /// [`assert_token_authorized`].
    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn into_inner(self) -> [u8; 32] {
        self.0
    }
}

/// The chain ID the caller is actually running on, observed live -- not
/// trusted from `TokenCapability::chain_id` (the configured value). See
/// module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveChainId(u64);

impl LiveChainId {
    /// Crate-internal -- see [`ObservedCodeHash::new`].
    pub(crate) const fn new(chain_id: u64) -> Self {
        Self(chain_id)
    }

    pub const fn into_inner(self) -> u64 {
        self.0
    }
}

/// The token address the caller is actually querying against -- kept a
/// distinct type from `TokenCapability::token_address` (the configured
/// value) so the two can never be silently swapped. See module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueriedToken([u8; 20]);

impl QueriedToken {
    /// Crate-internal -- see [`ObservedCodeHash::new`].
    pub(crate) const fn new(address: [u8; 20]) -> Self {
        Self(address)
    }

    pub const fn into_inner(self) -> [u8; 20] {
        self.0
    }
}

/// A required capability mask, buildable only from the four named `CAP_*`
/// bits below (individually or combined) -- never from a bare `u128`. This
/// is what closes the brief's headline trap: the `AuthorizationMode`
/// ordinal `3` is a plain integer literal, and plain integer literals no
/// longer type-check as `Capability`. See module doc "`CAP_*` bits vs
/// `AuthorizationMode` ordinals".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability(u128);

impl Capability {
    pub const EIP2612: Capability = Capability(CAP_EIP2612);
    pub const EIP3009: Capability = Capability(CAP_EIP3009);
    pub const PRIOR_ALLOWANCE: Capability = Capability(CAP_PRIOR_ALLOWANCE);
    pub const SELL_SPLIT: Capability = Capability(CAP_SELL_SPLIT);

    /// The raw `uint256`-domain bitmask, for comparison against
    /// `TokenCapability::capability_mask`.
    pub const fn bits(self) -> u128 {
        self.0
    }

    /// Combine capabilities into the mask required to hold ALL of them,
    /// e.g. `Capability::required(&[Capability::EIP2612,
    /// Capability::SELL_SPLIT])`. `Capability::required(&[])` yields the
    /// zero mask -- the one sanctioned way to construct it, since
    /// [`assert_token_authorized`] rejects it outright (see module doc
    /// "Divergence: required_capability == 0").
    pub fn required(caps: &[Capability]) -> Capability {
        Capability(caps.iter().fold(0u128, |acc, c| acc | c.0))
    }
}

impl std::ops::BitOr for Capability {
    type Output = Capability;

    fn bitor(self, rhs: Capability) -> Capability {
        Capability(self.0 | rhs.0)
    }
}

/// Mirrors `StreamGTypes.FeeTokenConfig` (StreamGTypes.sol:292-304), field
/// order frozen -- [`fee_token_config_hash`]'s encoding depends on this
/// exact order matching the Solidity struct declaration. Deliberately has
/// no `fee_token_config_hash` field -- see module doc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenCapability {
    pub chain_id: u64,
    pub token_address: [u8; 20],
    pub runtime_code_hash: [u8; 32],
    pub proxy_identity_hash: [u8; 32],
    /// `uint256` on-chain. `u128`, not `u64` -- see module doc.
    pub capability_mask: u128,
    pub decimals: u8,
    pub domain_name_hash: [u8; 32],
    pub domain_version_hash: [u8; 32],
    pub built_in_mode_id: [u8; 32],
    pub config_version: u64,
    pub active: bool,
}

pub const ERR_TOKEN_UNSUPPORTED: &str = "TOKEN_UNSUPPORTED";
pub const ERR_ZERO_REQUIRED_CAPABILITY: &str = "ZERO_REQUIRED_CAPABILITY";
pub const ERR_PROXY_IDENTITY_UNSUPPORTED: &str = "PROXY_IDENTITY_UNSUPPORTED";
pub const ERR_MANIFEST_CHAIN_MISMATCH: &str = "MANIFEST_CHAIN_MISMATCH";
pub const ERR_MANIFEST_PHASE_MISMATCH: &str = "MANIFEST_PHASE_MISMATCH";
pub const ERR_MANIFEST_IO: &str = "MANIFEST_IO_ERROR";
pub const ERR_MANIFEST_PARSE: &str = "MANIFEST_PARSE_ERROR";
pub const ERR_CHAIN_READ: &str = "CHAIN_READ_FAILED";
pub const ERR_FEE_TOKEN_CONFIG_HASH_MISMATCH: &str = "FEE_TOKEN_CONFIG_HASH_MISMATCH";

#[derive(Debug, Error)]
pub enum TokenManifestError {
    /// Mirrors `FeeTokenRegistry.TokenNotAuthorized()`. On-chain,
    /// `_isAuthorized`'s five checks (inactive/unknown, wrong token, wrong
    /// chain, code-hash mismatch, missing capability) all collapse to this
    /// single revert reason -- `reason` is diagnostic-only (for logs), not
    /// a distinct public code. See module doc "unknown vs inactive".
    #[error("token not authorized: {reason}")]
    TokenNotAuthorized { reason: &'static str },
    /// Rust-only guard, no on-chain equivalent -- see module doc
    /// "Divergence: required_capability == 0".
    #[error("required_capability must not be zero")]
    ZeroRequiredCapability,
    /// Mirrors `FeeTokenRegistry.ProxyIdentityUnsupported()`
    /// (`upsertTokenConfig`, write-time only -- see module doc).
    #[error("proxyIdentityHash must be zero (G1 rejects proxy tokens)")]
    ProxyIdentityUnsupported,
    /// Deployment-manifest `chainId` does not match the chain this process
    /// is configured for. Never special-cases Base Sepolia (84532) --
    /// `DeployStreamG.s.sol::_assertChainAllowed` hard-gates it out of G1
    /// entirely, and this loader treats a mismatch on that chain the same
    /// as any other: a plain error, never fabricated behavior.
    #[error(
        "manifest chainId {manifest_chain_id} does not match configured chain {configured_chain_id}"
    )]
    ManifestChainMismatch {
        manifest_chain_id: u64,
        configured_chain_id: u64,
    },
    /// Deployment-manifest `phase` is not `"G1"` -- see Minor 5 of the
    /// hardening pass: `phase` was loaded and never checked, so a
    /// misconfigured process pointed at a manifest from a different phase
    /// (or a hand-edited/corrupted manifest) would otherwise pass every
    /// other check. This is an absolute anchor, not a comparison against
    /// `configured_chain_id` like [`TokenManifestError::ManifestChainMismatch`].
    #[error("manifest phase {manifest_phase:?} does not match expected phase \"G1\"")]
    ManifestPhaseMismatch { manifest_phase: String },
    #[error("failed to read deployment manifest {path}: {detail}")]
    Io { path: String, detail: String },
    #[error("failed to parse deployment manifest {path}: {detail}")]
    Parse { path: String, detail: String },
    /// A live chain read required by [`read_live_token_state`] failed. Fail
    /// closed: there is no "assume the previous value" path -- an unreadable
    /// chain means no quote. Also covers `eth_getCode` returning empty code
    /// (live-chain sourcing contract R1), which
    /// `chain::code_hash_from_get_code` turns into an `Err` rather than
    /// hashing the empty string.
    #[error("live chain read failed ({what}): {detail}")]
    ChainRead { what: &'static str, detail: String },
    /// The `getTokenConfig` struct we decoded does not hash to the
    /// `getTokenConfigHash` the same registry reports at the same block
    /// (sourcing contract R2 step 1) -- i.e. the struct in hand is not the
    /// struct the registry holds, so nothing derived from it may be trusted.
    #[error("decoded FeeTokenConfig hashes to 0x{computed} but the registry reports 0x{registry}")]
    FeeTokenConfigHashMismatch { computed: String, registry: String },
}

impl TokenManifestError {
    /// Stable string code. Every authorization-read failure returns
    /// [`ERR_TOKEN_UNSUPPORTED`] regardless of which of the five checks
    /// failed -- see module doc "unknown vs inactive". Admission and
    /// manifest-loading failures get their own distinct codes.
    pub fn code(&self) -> &'static str {
        match self {
            TokenManifestError::TokenNotAuthorized { .. } => ERR_TOKEN_UNSUPPORTED,
            TokenManifestError::ZeroRequiredCapability => ERR_ZERO_REQUIRED_CAPABILITY,
            TokenManifestError::ProxyIdentityUnsupported => ERR_PROXY_IDENTITY_UNSUPPORTED,
            TokenManifestError::ManifestChainMismatch { .. } => ERR_MANIFEST_CHAIN_MISMATCH,
            TokenManifestError::ManifestPhaseMismatch { .. } => ERR_MANIFEST_PHASE_MISMATCH,
            TokenManifestError::Io { .. } => ERR_MANIFEST_IO,
            TokenManifestError::Parse { .. } => ERR_MANIFEST_PARSE,
            TokenManifestError::ChainRead { .. } => ERR_CHAIN_READ,
            TokenManifestError::FeeTokenConfigHashMismatch { .. } => {
                ERR_FEE_TOKEN_CONFIG_HASH_MISMATCH
            }
        }
    }

    /// HTTP status for the shared Stream G error envelope
    /// (`super::http_error`). Wildcard-free on purpose — see
    /// [`super::base_fee::BaseFeeError::status`].
    ///
    /// The manifest-loading arms are **500, not 4xx**: the deployment
    /// manifest is an operator-authored file this process reads at startup,
    /// so a caller can neither cause nor fix any of those failures.
    pub fn status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            // The chain refuses this token for this call. Well-formed
            // request, refused by a rule.
            TokenManifestError::TokenNotAuthorized { .. }
            | TokenManifestError::ProxyIdentityUnsupported => StatusCode::UNPROCESSABLE_ENTITY,
            // Server-side: a zero required-capability is a programming error
            // in the caller *inside this process*, never a request value.
            TokenManifestError::ZeroRequiredCapability => StatusCode::INTERNAL_SERVER_ERROR,
            // Operator configuration / this process's own files.
            TokenManifestError::ManifestChainMismatch { .. }
            | TokenManifestError::ManifestPhaseMismatch { .. }
            | TokenManifestError::Io { .. }
            | TokenManifestError::Parse { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            TokenManifestError::ChainRead { .. } => StatusCode::BAD_GATEWAY,
            // The registry moved under the read (R2 step 1). Retrying against
            // fresh state is the resolution, so this is a conflict rather
            // than either party's error.
            TokenManifestError::FeeTokenConfigHashMismatch { .. } => StatusCode::CONFLICT,
        }
    }
}

// ---------------------------------------------------------------------------
// LiveTokenReading -- the gate's only admissible input (Wave B).
// ---------------------------------------------------------------------------

/// The four values [`assert_token_authorized`] compares, bundled together
/// and **constructible in production only by [`read_live_token_state`]**,
/// which obtains each of them from a chain read at one pinned block.
///
/// This is the `GatedExposure` treatment from `base_fee.rs` applied to the
/// token gate: the fields are private and there is no `From`, no public
/// literal constructor, and no setter, so a caller cannot hand the gate a
/// record it assembled from a manifest, a config file or a request body.
/// See the module doc's "What this type does and does not guarantee".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveTokenReading {
    capability: TokenCapability,
    observed_code_hash: ObservedCodeHash,
    live_chain_id: LiveChainId,
    queried_token: QueriedToken,
    registry_config_hash: [u8; 32],
    block: u64,
}

impl LiveTokenReading {
    /// The `FeeTokenRegistry.getTokenConfig` record, already proven to hash
    /// to the registry's own `getTokenConfigHash` at the same block.
    pub fn capability(&self) -> &TokenCapability {
        &self.capability
    }

    /// `keccak256(eth_getCode(token, block))` -- an *independent* read from
    /// the one that produced [`LiveTokenReading::capability`].
    pub fn observed_code_hash(&self) -> ObservedCodeHash {
        self.observed_code_hash
    }

    /// The chain the RPC endpoint reports for itself
    /// (`ChainClient::chain_id`, i.e. `eth_chainId`) -- an *independent*
    /// read from the registry config, so gate check 3
    /// (`config.chainId == <the chain we are on>`) compares two
    /// differently-sourced values. Before Task 6 Wave B this was
    /// `capability.chain_id`, which made that check `x == x`; see the
    /// module doc.
    pub fn live_chain_id(&self) -> LiveChainId {
        self.live_chain_id
    }

    /// The address actually passed to the RPC calls, not `cfg.token`.
    pub fn queried_token(&self) -> QueriedToken {
        self.queried_token
    }

    /// `FeeTokenRegistry.getTokenConfigHash(token)` as the registry reported
    /// it (equal, by construction, to
    /// [`fee_token_config_hash`]`(self.capability())`). This is the value a
    /// quote must commit to, and the one a
    /// `secondaryEnrollmentNonceSnapshot` must agree with for the R3
    /// anti-TOCTOU binding.
    pub fn fee_token_config_hash(&self) -> [u8; 32] {
        self.registry_config_hash
    }

    /// The block every read above was pinned to (R4).
    pub fn block(&self) -> u64 {
        self.block
    }

    /// Test-only escape hatch, mirroring
    /// `profile_auth::AuthenticatedProfileId::for_test` and
    /// `base_fee`'s test constructors: lets tests drive
    /// [`assert_token_authorized`] into each of its five branches without
    /// standing up a chain. Never compiled into a release build.
    #[cfg(test)]
    pub fn for_test(
        capability: TokenCapability,
        observed_code_hash: [u8; 32],
        live_chain_id: u64,
        queried_token: [u8; 20],
    ) -> Self {
        let registry_config_hash = fee_token_config_hash(&capability);
        Self {
            capability,
            observed_code_hash: ObservedCodeHash::new(observed_code_hash),
            live_chain_id: LiveChainId::new(live_chain_id),
            queried_token: QueriedToken::new(queried_token),
            registry_config_hash,
            block: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// TrustedChain -- Stream G's fail-closed refusal to run against a mock.
// ---------------------------------------------------------------------------

/// A [`crate::chain::ChainClient`] whose answers Stream G is willing to treat
/// as chain truth.
///
/// ## The hazard this closes
///
/// [`crate::chain::MockChain`] is `pub` and **not** `#[cfg(test)]`
/// (`chain.rs:1121`) — it ships in release builds because
/// `GOAT_ATTESTOR_MOCK=1` constructs one for the Stream B / B-live pilot —
/// `main::main`'s config-fallback arm and `main::open_chain`'s
/// `if cfg.mock_mode` branch each build a `MockChain`.
/// Five lines of it (`set_chain_id`, `set_fee_token_code`,
/// `set_fee_token_config`, `set_fee_token_config_hash`, then the read)
/// fabricate a [`LiveTokenReading`] that sails through
/// [`assert_token_authorized`], because every one of that gate's five
/// comparisons is between two values the `ChainClient` supplied. The gate is
/// only as honest as the client behind it.
///
/// Feature-gating `MockChain` itself was considered and **rejected**: it would
/// break the live pilot, which depends on that construction path, and
/// `chain.rs` is outside this wave's scope in any case. So the refusal is
/// narrowed to Stream G, whose security gates are the ones that depend on
/// `ChainClient` honesty.
///
/// ## Why this is a type and not a boolean
///
/// A `trusted: bool` on a config struct would be advisory: anything that can
/// build the config can set it. This is the same `GatedExposure` /
/// [`LiveTokenReading`] posture the rest of this module tree uses — the field
/// is private, there is no setter, no `Default`, no public literal
/// constructor, and outside `#[cfg(test)]` exactly **one** way to obtain a
/// value: [`TrustedChain::live`], which takes the concrete
/// [`crate::rpc_chain::RpcChain`] — a live JSON-RPC endpoint — by reference.
/// A `MockChain`, or any other `ChainClient` implementor, therefore cannot be
/// threaded into [`read_live_token_state`],
/// [`super::preflight::read_live_preflight_state`],
/// [`super::quotes::create_sponsored_enrollment_quote`] or
/// [`super::submit::SubmitContext`] at all in a release build. This is a
/// compile-time refusal rather than a runtime `Err`, which is strictly
/// stronger: there is no code path to test because there is no code path.
///
/// ## What it does NOT claim
///
/// - It says nothing about whether the endpoint `RpcChain` is pointed at is
///   the *right* chain, is honest, or is in sync. Chain-identity checking is
///   `_isAuthorized` check 3's job ([`LiveTokenReading::live_chain_id`]) and
///   the manifest/`activeManifestHash()` cross-check's job, not this type's.
/// - `models::LiveEnrollmentNonces::read_live` still takes a bare
///   `&dyn ChainClient`. `models.rs` is outside this wave's file scope, so a
///   caller that builds `EnrollmentQuoteContext::live_nonces` itself can still
///   source the *nonces* from a mock. The token reading — the input to the
///   hazard-3 gate — cannot be, since [`read_live_token_state`] is the only
///   production constructor of [`LiveTokenReading`] and now requires this
///   type. Closing the nonce half needs a follow-up wave that may edit
///   `models.rs`.
#[derive(Clone, Copy)]
pub struct TrustedChain<'a> {
    inner: &'a dyn crate::chain::ChainClient,
}

impl<'a> TrustedChain<'a> {
    /// The **only** non-test constructor. Takes the concrete
    /// [`crate::rpc_chain::RpcChain`], not `&dyn ChainClient`, so no other
    /// implementor — `MockChain` included — can be converted.
    pub fn live(rpc: &'a crate::rpc_chain::RpcChain) -> Self {
        Self { inner: rpc }
    }

    /// The client itself, for the reads Stream G performs. `pub(crate)`: the
    /// point of the type is that the crate's *own* Stream G modules are the
    /// only things allowed to unwrap it.
    pub(crate) fn client(self) -> &'a dyn crate::chain::ChainClient {
        self.inner
    }
}

impl std::fmt::Debug for TrustedChain<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately opaque: a `ChainClient` is not `Debug` and its
        // contents (RPC URL, signer) must not leak into logs.
        f.write_str("TrustedChain(<live rpc client>)")
    }
}

/// **Test-only**, and the reason every existing Stream G test keeps working:
/// in a `cfg(test)` build any `ChainClient` (in practice
/// [`crate::chain::MockChain`]) converts. Removing the `#[cfg(test)]` from
/// this impl would silently reopen the exact hazard the type exists to close,
/// which is why
/// [`tests::trusted_chain_has_no_release_build_path_from_an_arbitrary_chain_client`]
/// scans for it.
#[cfg(test)]
impl<'a, C: crate::chain::ChainClient> From<&'a C> for TrustedChain<'a> {
    fn from(chain: &'a C) -> Self {
        Self { inner: chain }
    }
}

/// The **only** production constructor of [`LiveTokenReading`]. Performs the
/// live-chain sourcing contract's R1/R2 reads against `chain`, all pinned to
/// `block` (R4), and refuses to produce a reading unless they agree:
///
/// 0. `eth_chainId` via [`crate::chain::ChainClient::chain_id`] -- the
///    right-hand side of `_isAuthorized` check 3. Deliberately NOT taken
///    from the config being checked (Task 6 Wave B); unpinned because
///    `eth_chainId` has no block parameter.
/// 1. `eth_getCode(token, block)` -> `keccak256` via
///    [`crate::chain::ChainClient::fee_token_code_hash`]. Empty code is an
///    `Err`, never `keccak256("")` (R1).
/// 2. `FeeTokenRegistry.getTokenConfig(token)` at `block` -> the capability
///    record (R2).
/// 3. `FeeTokenRegistry.getTokenConfigHash(token)` at `block`, compared
///    against this module's own `_hashConfig` reproduction
///    ([`fee_token_config_hash`]) of the struct decoded in step 2. A
///    mismatch is [`TokenManifestError::FeeTokenConfigHashMismatch`] -- this
///    is what proves the struct in hand is the struct the registry holds.
/// 4. G1 admission constraints: `proxyIdentityHash` must be zero
///    ([`validate_proxy_identity_admissible`]) and `active` must be true.
///
/// It does **not** call `activeManifestHash()` (R2 step 2) or
/// `secondaryEnrollmentNonceSnapshot` (R3): those bind a reading to a
/// *manifest* and to *nonces*, neither of which this function is given. The
/// caller still owes both -- see the module doc.
pub fn read_live_token_state<'c>(
    chain: impl Into<TrustedChain<'c>>,
    registry: [u8; 20],
    token: [u8; 20],
    block: u64,
) -> Result<LiveTokenReading, TokenManifestError> {
    // Fail-closed chain-honesty gate: in a release build the ONLY value that
    // satisfies `Into<TrustedChain>` is a `TrustedChain` built by
    // `TrustedChain::live(&RpcChain)`. A `MockChain` cannot reach this
    // function at all. See [`TrustedChain`].
    let chain = chain.into().client();

    // The chain the RPC endpoint says it is on (`eth_chainId`). This is the
    // right-hand side of `_isAuthorized` check 3, and it must NOT come from
    // the config the check is about: sourcing it from
    // `getTokenConfig(...).chainId` (what this function did before Task 6
    // Wave B) reduced check 3 to `x == x`. `ChainClient::chain_id`'s trait
    // default is `Err`, never `Ok(0)`, so an implementor that does not
    // perform the read fails closed here rather than claiming chain 0.
    //
    // Not pinned to `block`: `eth_chainId` takes no block parameter, and a
    // chain id that differed between blocks would be a hard fork, not a
    // reorg. R4's single-block pinning applies to the state reads below.
    let live_chain_id = chain
        .chain_id()
        .map_err(|e| TokenManifestError::ChainRead {
            what: "eth_chainId",
            detail: e.to_string(),
        })?;

    // R1 -- independent of everything the registry says.
    let observed_code_hash =
        chain
            .fee_token_code_hash(token, block)
            .map_err(|e| TokenManifestError::ChainRead {
                what: "eth_getCode/keccak256(feeToken)",
                detail: e.to_string(),
            })?;

    // R2 -- the registry's own record for the address we actually queried.
    let view = chain
        .fee_token_config(registry, token, block)
        .map_err(|e| TokenManifestError::ChainRead {
            what: "FeeTokenRegistry.getTokenConfig",
            detail: e.to_string(),
        })?;
    let capability = TokenCapability {
        chain_id: view.chain_id,
        token_address: view.token,
        runtime_code_hash: view.runtime_code_hash,
        proxy_identity_hash: view.proxy_identity_hash,
        capability_mask: view.capability_mask,
        decimals: view.decimals,
        domain_name_hash: view.domain_name_hash,
        domain_version_hash: view.domain_version_hash,
        built_in_mode_id: view.built_in_mode_id,
        config_version: view.config_version,
        active: view.active,
    };

    // R2 step 1 -- bind the decoded struct to the hash the registry stores.
    let registry_config_hash = chain
        .fee_token_config_hash(registry, token, block)
        .map_err(|e| TokenManifestError::ChainRead {
            what: "FeeTokenRegistry.getTokenConfigHash",
            detail: e.to_string(),
        })?;
    let computed = fee_token_config_hash(&capability);
    if computed != registry_config_hash {
        return Err(TokenManifestError::FeeTokenConfigHashMismatch {
            computed: hex::encode(computed),
            registry: hex::encode(registry_config_hash),
        });
    }

    // R2 step 3 -- G1 constraints, rejected before a reading exists at all.
    validate_proxy_identity_admissible(&capability)?;
    if !capability.active {
        return Err(TokenManifestError::TokenNotAuthorized {
            reason: "inactive or unknown",
        });
    }

    Ok(LiveTokenReading {
        // NOT `capability.token_address`: the address we actually asked the
        // RPC about, so gate check 2 compares two independently-sourced
        // values instead of a field against itself.
        queried_token: QueriedToken::new(token),
        // NOT `capability.chain_id`: the endpoint's own `eth_chainId`
        // answer, read above, so gate check 3 compares the registry's
        // declared chain against the chain we are actually talking to.
        live_chain_id: LiveChainId::new(live_chain_id),
        observed_code_hash: ObservedCodeHash::new(observed_code_hash),
        capability,
        registry_config_hash,
        block,
    })
}

/// Mirrors `FeeTokenRegistry._isAuthorized`
/// (FeeTokenRegistry.sol:202-214) -- same five checks, same order, same
/// short-circuit on first failure:
///
/// 1. `!cfg.active`
/// 2. `cfg.token != token`
/// 3. `cfg.chainId != block.chainid`
/// 4. `token.codehash != cfg.runtimeCodeHash`
/// 5. `(cfg.capabilityMask & requiredCapability) != requiredCapability`
///
/// Two Rust-only guards run first, both documented divergences from the
/// chain (see module doc): a [`Capability`] whose bits are zero is
/// rejected outright, and a non-zero `live.proxy_identity_hash` is treated
/// as an impossible-state defense-in-depth failure (the chain's read path
/// never reads that field at all, so this is the only place a corrupted
/// config with a non-zero value would ever be caught on the read side).
///
/// `reading` is a [`LiveTokenReading`], which outside `#[cfg(test)]` can
/// only have come from [`read_live_token_state`] -- so the configured
/// record, the observed EXTCODEHASH, the chain id and the queried address
/// are each sourced by that function rather than chosen by this function's
/// caller. `required_capability` is a [`Capability`], buildable only from
/// the named `CAP_*` constants -- see module doc "`CAP_*` bits vs
/// `AuthorizationMode` ordinals".
pub fn assert_token_authorized(
    reading: &LiveTokenReading,
    required_capability: Capability,
) -> Result<(), TokenManifestError> {
    let live = reading.capability();
    if required_capability.bits() == 0 {
        return Err(TokenManifestError::ZeroRequiredCapability);
    }
    if live.proxy_identity_hash != [0u8; 32] {
        return Err(TokenManifestError::TokenNotAuthorized {
            reason: "proxyIdentityHash non-zero (impossible on-chain state; defense in depth)",
        });
    }

    // --- exact mirror of _isAuthorized, same order, same short-circuit ---
    if !live.active {
        return Err(TokenManifestError::TokenNotAuthorized {
            reason: "inactive or unknown",
        });
    }
    if live.token_address != reading.queried_token().into_inner() {
        return Err(TokenManifestError::TokenNotAuthorized {
            reason: "configured token address mismatch",
        });
    }
    if live.chain_id != reading.live_chain_id().into_inner() {
        return Err(TokenManifestError::TokenNotAuthorized {
            reason: "configured chainId does not match live chain",
        });
    }
    if reading.observed_code_hash().into_inner() != live.runtime_code_hash {
        return Err(TokenManifestError::TokenNotAuthorized {
            reason: "observed EXTCODEHASH does not match configured runtimeCodeHash",
        });
    }
    if (live.capability_mask & required_capability.bits()) != required_capability.bits() {
        return Err(TokenManifestError::TokenNotAuthorized {
            reason: "capabilityMask does not grant the required capability",
        });
    }
    Ok(())
}

/// Mirrors `FeeTokenRegistry.upsertTokenConfig`'s `ProxyIdentityUnsupported()`
/// revert (FeeTokenRegistry.sol:94) -- run this on any config before
/// treating it as admitted into a manifest/registry. This is the only
/// on-chain place `proxyIdentityHash` is validated; see module doc. Named
/// for exactly what it checks (renamed from `validate_config_admissible`,
/// which implied a broader admission check than the single
/// `proxyIdentityHash` mirror this actually is).
pub fn validate_proxy_identity_admissible(cfg: &TokenCapability) -> Result<(), TokenManifestError> {
    if cfg.proxy_identity_hash != [0u8; 32] {
        return Err(TokenManifestError::ProxyIdentityUnsupported);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// feeTokenConfigHash recomputation (FeeTokenRegistry.sol:183-200 / _hashConfig)
// ---------------------------------------------------------------------------

/// `StreamGTypes.FEE_TOKEN_CONFIG_TYPEHASH` (StreamGTypes.sol:89-91),
/// copied here independently so a future edit that drifts from the
/// Solidity source fails
/// [`fee_token_config_hash_matches_contract_encoding`] loudly.
pub const FEE_TOKEN_CONFIG_TYPEHASH_STR: &str = "FeeTokenConfig(uint256 chainId,address token,bytes32 runtimeCodeHash,bytes32 proxyIdentityHash,uint256 capabilityMask,uint8 decimals,bytes32 domainNameHash,bytes32 domainVersionHash,bytes32 builtInModeId,uint64 configVersion,bool active)";

fn fee_token_config_typehash() -> [u8; 32] {
    keccak256(FEE_TOKEN_CONFIG_TYPEHASH_STR.as_bytes())
}

fn address_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

fn u256_be_u128(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn u256_be_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn u256_be_u8(v: u8) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[31] = v;
    w
}

fn bool_word(v: bool) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[31] = u8::from(v);
    w
}

/// `keccak256(abi.encode(FEE_TOKEN_CONFIG_TYPEHASH, chainId, token,
/// runtimeCodeHash, proxyIdentityHash, capabilityMask, decimals,
/// domainNameHash, domainVersionHash, builtInModeId, configVersion,
/// active))` -- `FeeTokenRegistry._hashConfig`, field order exactly as
/// declared in `StreamGTypes.FeeTokenConfig`. `abi.encode` left-pads every
/// value to a 32-byte word (including `uint8`/`uint64`/`bool`); this is a
/// bare struct hash with NO EIP-712 domain separator applied (unlike
/// `root_authorization.rs`'s digest). `feeTokenConfigHash` is stored
/// separately on-chain (`_tokenConfigHashes[token]`, exposed via
/// `getTokenConfigHash`) -- this recomputes it from a config the caller
/// supplies, so callers can detect a config that does not match what the
/// chain actually hashed.
pub fn fee_token_config_hash(cfg: &TokenCapability) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 12);
    buf.extend_from_slice(&fee_token_config_typehash());
    buf.extend_from_slice(&u256_be_u64(cfg.chain_id));
    buf.extend_from_slice(&address_word(&cfg.token_address));
    buf.extend_from_slice(&cfg.runtime_code_hash);
    buf.extend_from_slice(&cfg.proxy_identity_hash);
    buf.extend_from_slice(&u256_be_u128(cfg.capability_mask));
    buf.extend_from_slice(&u256_be_u8(cfg.decimals));
    buf.extend_from_slice(&cfg.domain_name_hash);
    buf.extend_from_slice(&cfg.domain_version_hash);
    buf.extend_from_slice(&cfg.built_in_mode_id);
    buf.extend_from_slice(&u256_be_u64(cfg.config_version));
    buf.extend_from_slice(&bool_word(cfg.active));
    keccak256(&buf)
}

// ---------------------------------------------------------------------------
// Deployment manifest (contracts/deployments/31337.stream-g.json)
// ---------------------------------------------------------------------------

/// Parses a `0x`-prefixed hex string into a fixed-size byte array,
/// rejecting empty strings, missing `0x` prefixes, wrong lengths, and
/// non-hex characters. `key` is the JSON key this value came from, folded
/// into the error message so a malformed manifest field names itself
/// rather than surfacing a bare "invalid hex" message. Used only via
/// `deserialize_with` below, at manifest-parse time -- reuses the `hex`
/// crate this module already depends on (`fee_token_config_hash_matches_
/// contract_encoding` uses `hex::encode`); no new dependency.
fn parse_hex_fixed<const N: usize>(key: &'static str, raw: &str) -> Result<[u8; N], String> {
    let hex_part = raw
        .strip_prefix("0x")
        .ok_or_else(|| format!("{key}: expected a \"0x\"-prefixed hex string, got {raw:?}"))?;
    if hex_part.len() != N * 2 {
        return Err(format!(
            "{key}: expected {} hex chars after \"0x\" ({N} bytes), got {} in {raw:?}",
            N * 2,
            hex_part.len()
        ));
    }
    let bytes =
        hex::decode(hex_part).map_err(|e| format!("{key}: invalid hex digits ({e}) in {raw:?}"))?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Generates a `deserialize_with` function that parses a manifest field's
/// `0x`-prefixed hex string into a `[u8; $len]` at deserialize time via
/// [`parse_hex_fixed`], naming `$key` (the JSON key) in any error --
/// closes Important 2 of the hardening pass: these fields used to be
/// unvalidated `String`s, so `""`, a truncated address, or a non-hex value
/// all loaded successfully.
macro_rules! hex_field_deserializer {
    ($fn_name:ident, $len:literal, $key:literal) => {
        fn $fn_name<'de, D>(deserializer: D) -> Result<[u8; $len], D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let raw = String::deserialize(deserializer)?;
            parse_hex_fixed::<$len>($key, &raw).map_err(serde::de::Error::custom)
        }
    };
}

hex_field_deserializer!(de_enrollment_registry, 20, "enrollmentRegistry");
hex_field_deserializer!(de_goat_coin, 20, "goatCoin");
hex_field_deserializer!(de_fee_token, 20, "feeToken");
hex_field_deserializer!(de_fee_token_registry, 20, "feeTokenRegistry");
hex_field_deserializer!(
    de_wallet_sponsorship_registry,
    20,
    "walletSponsorshipRegistry"
);
hex_field_deserializer!(de_sponsored_buy_desk, 20, "sponsoredBuyDesk");
hex_field_deserializer!(de_goat_relay_gateway, 20, "goatRelayGateway");
hex_field_deserializer!(de_policy_safe, 20, "policySafe");
hex_field_deserializer!(de_fee_safe, 20, "feeSafe");
hex_field_deserializer!(de_recovery_safe, 20, "recoverySafe");
hex_field_deserializer!(de_desk_owner, 20, "deskOwner");
hex_field_deserializer!(de_quote_signer, 20, "quoteSigner");
hex_field_deserializer!(de_deployment_manifest_hash, 32, "deploymentManifestHash");
hex_field_deserializer!(de_fee_schedule_hash, 32, "feeScheduleHash");

/// `contracts/deployments/31337.stream-g.json`, written by
/// `script/DeployStreamG.s.sol::writeManifest` -- 17 keys. No
/// `#[serde(deny_unknown_fields)]`: the manifest may gain keys this loader
/// does not consume yet. Every field declared here IS required, though --
/// a missing key surfaces as a `serde_json` error (mapped to
/// [`TokenManifestError::Parse`]), never a silently-defaulted value (brief
/// §2.8: "a missing address is a fail-closed error, never a default").
/// The 12 address fields and 2 hash fields are parsed into `[u8; 20]` /
/// `[u8; 32]` at deserialize time (see [`parse_hex_fixed`]) rather than
/// left as unvalidated `String`s -- a malformed value is a
/// [`TokenManifestError::Parse`] naming the offending key, never a value
/// that silently loads as `Ok`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentManifest {
    pub schema_version: u64,
    pub chain_id: u64,
    pub phase: String,
    #[serde(deserialize_with = "de_enrollment_registry")]
    pub enrollment_registry: [u8; 20],
    #[serde(deserialize_with = "de_goat_coin")]
    pub goat_coin: [u8; 20],
    #[serde(deserialize_with = "de_fee_token")]
    pub fee_token: [u8; 20],
    #[serde(deserialize_with = "de_fee_token_registry")]
    pub fee_token_registry: [u8; 20],
    #[serde(deserialize_with = "de_wallet_sponsorship_registry")]
    pub wallet_sponsorship_registry: [u8; 20],
    #[serde(deserialize_with = "de_sponsored_buy_desk")]
    pub sponsored_buy_desk: [u8; 20],
    #[serde(deserialize_with = "de_goat_relay_gateway")]
    pub goat_relay_gateway: [u8; 20],
    #[serde(deserialize_with = "de_policy_safe")]
    pub policy_safe: [u8; 20],
    #[serde(deserialize_with = "de_fee_safe")]
    pub fee_safe: [u8; 20],
    #[serde(deserialize_with = "de_recovery_safe")]
    pub recovery_safe: [u8; 20],
    #[serde(deserialize_with = "de_desk_owner")]
    pub desk_owner: [u8; 20],
    #[serde(deserialize_with = "de_quote_signer")]
    pub quote_signer: [u8; 20],
    #[serde(deserialize_with = "de_deployment_manifest_hash")]
    pub deployment_manifest_hash: [u8; 32],
    #[serde(deserialize_with = "de_fee_schedule_hash")]
    pub fee_schedule_hash: [u8; 32],
}

/// Load and parse the deployment manifest at `path`, rejecting a `chainId`
/// that does not match `configured_chain_id` and a `phase` that is not
/// `"G1"`. Never fabricates Base Sepolia (84532) behavior -- see
/// [`TokenManifestError::ManifestChainMismatch`] docs. The `phase` check
/// is an absolute anchor (Minor 5 of the hardening pass): `phase` used to
/// be loaded and never checked, so a misconfigured process pointed at a
/// manifest from a different phase could otherwise pass this gate.
pub fn load_deployment_manifest(
    path: &Path,
    configured_chain_id: u64,
) -> Result<DeploymentManifest, TokenManifestError> {
    let raw = fs::read_to_string(path).map_err(|e| TokenManifestError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    parse_deployment_manifest(&raw, &path.display().to_string(), configured_chain_id)
}

/// The 31337 lab deployment manifest, compiled into the binary.
///
/// **Why this exists.** `config::build_stream_g_config` defaults
/// `STREAM_G_DEPLOYMENT_MANIFEST_PATH` to `{STATE_DIR}/stream_g_deployment_manifest.json`,
/// and nothing ever shipped a file there. A fresh clone with
/// `STREAM_G_ENABLED=1` therefore died at startup with an *IO* error before
/// Stream G could refuse anything on its merits, so CI and local dev could not
/// run Stream G at all without hand-wiring two paths.
/// `runtime::StreamGState::start` now falls through to these bytes when — and
/// only when — nobody configured the path and no file exists at the default
/// (`config::PathSource::Default`).
///
/// **It is chain 31337 and that is the whole of its authority.** This is the
/// only deployment manifest this repository ships. On any other `CHAIN_ID`
/// the fall-through still reaches [`parse_deployment_manifest`]'s chain gate
/// and fails with [`TokenManifestError::ManifestChainMismatch`] — an honest
/// refusal naming both ids, not the IO error the operator used to get. Nothing
/// here fabricates a manifest for a chain nobody deployed.
///
/// **It is a copy, and the copy is checked.** `include_str!` cannot reach out
/// of this package (the sibling `contracts/` tree is excluded from the Docker
/// build context and this package is its own workspace — `Cargo.toml:9`), and
/// every other `include_str!` in this crate stays inside it too
/// (`store.rs:69`, `store.rs:75`). `tests::builtin_manifest_is_byte_identical_to_the_committed_deployment_artifact`
/// pins these bytes against `contracts/deployments/31337.stream-g.json`, which
/// `DeployStreamG.writeManifest` rewrites on every `forge test` run — so a
/// redeploy that moves an address fails that test instead of leaving a stale
/// built-in behind.
pub const BUILTIN_DEPLOYMENT_MANIFEST_JSON: &str =
    include_str!("../../fixtures/31337.stream-g.json");

/// The `chainId` [`BUILTIN_DEPLOYMENT_MANIFEST_JSON`] carries, stated as a
/// constant so an operator-facing message can name it without re-parsing the
/// document. Pinned by
/// `tests::builtin_manifest_parses_on_31337_and_is_refused_on_every_other_chain`.
pub const BUILTIN_DEPLOYMENT_MANIFEST_CHAIN_ID: u64 = 31337;

/// The parse/validate half of [`load_deployment_manifest`], split out so the
/// built-in [`BUILTIN_DEPLOYMENT_MANIFEST_JSON`] goes through byte-for-byte
/// the same gates a file does — including the chain and phase checks. A
/// fallback that skipped them would be a second, weaker loader.
///
/// `source` is what error messages name. It is a path for a real file and a
/// `<built-in ...>` label for the embedded document; it is never used to open
/// anything, so the two cannot be confused by a caller.
pub fn parse_deployment_manifest(
    raw: &str,
    source: &str,
    configured_chain_id: u64,
) -> Result<DeploymentManifest, TokenManifestError> {
    let manifest: DeploymentManifest =
        serde_json::from_str(raw).map_err(|e| TokenManifestError::Parse {
            path: source.to_string(),
            detail: e.to_string(),
        })?;
    if manifest.chain_id != configured_chain_id {
        return Err(TokenManifestError::ManifestChainMismatch {
            manifest_chain_id: manifest.chain_id,
            configured_chain_id,
        });
    }
    if manifest.phase != "G1" {
        return Err(TokenManifestError::ManifestPhaseMismatch {
            manifest_phase: manifest.phase.clone(),
        });
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_token() -> [u8; 20] {
        [0x11; 20]
    }

    fn sample_code_hash() -> [u8; 32] {
        [0x22; 32]
    }

    /// Active, correctly-configured token: chain 31337, capabilities
    /// EIP2612 + SELL_SPLIT, code hash / token address matching
    /// [`sample_code_hash`] / [`sample_token`].
    fn active_cfg() -> TokenCapability {
        TokenCapability {
            chain_id: 31337,
            token_address: sample_token(),
            runtime_code_hash: sample_code_hash(),
            proxy_identity_hash: [0u8; 32],
            capability_mask: CAP_EIP2612 | CAP_SELL_SPLIT,
            decimals: 6,
            domain_name_hash: [0x33; 32],
            domain_version_hash: [0x44; 32],
            built_in_mode_id: [0x55; 32],
            config_version: 1,
            active: true,
        }
    }

    /// Solidity's zero-default `FeeTokenConfig` for a token that was never
    /// passed to `upsertTokenConfig` -- see module doc "unknown vs
    /// inactive".
    fn never_configured() -> TokenCapability {
        TokenCapability {
            chain_id: 0,
            token_address: [0u8; 20],
            runtime_code_hash: [0u8; 32],
            proxy_identity_hash: [0u8; 32],
            capability_mask: 0,
            decimals: 0,
            domain_name_hash: [0u8; 32],
            domain_version_hash: [0u8; 32],
            built_in_mode_id: [0u8; 32],
            config_version: 0,
            active: false,
        }
    }

    /// A `#[cfg(test)]`-only [`LiveTokenReading`] standing in for what
    /// [`read_live_token_state`] would have produced -- the hatch exists so
    /// these tests can drive each of the five gate branches individually
    /// without standing up a chain. The Wave B tests further down use the
    /// REAL constructor against `MockChain`.
    fn reading(
        cfg: &TokenCapability,
        observed: [u8; 32],
        chain_id: u64,
        token: [u8; 20],
    ) -> LiveTokenReading {
        LiveTokenReading::for_test(cfg.clone(), observed, chain_id, token)
    }

    /// The happy-path reading for [`active_cfg`].
    fn ok_reading(cfg: &TokenCapability) -> LiveTokenReading {
        reading(cfg, sample_code_hash(), 31337, sample_token())
    }

    /// Minor 2 of the hardening pass: the five checks collapse to one
    /// error code by design (module doc "unknown vs inactive"), but the
    /// diagnostic `reason` strings exist and nothing asserted them --
    /// meaning nothing pinned WHICH check actually fired. Asserts the
    /// `reason` on a [`TokenManifestError::TokenNotAuthorized`].
    fn assert_reason(err: &TokenManifestError, expected: &str) {
        match err {
            TokenManifestError::TokenNotAuthorized { reason } => {
                assert_eq!(*reason, expected, "unexpected check fired first");
            }
            other => {
                panic!("expected TokenNotAuthorized {{ reason: {expected:?} }}, got {other:?}")
            }
        }
    }

    // --- Plan-mandated tests (brief §4, items 1-4) --------------------------

    #[test]
    fn accepts_active_manifest_tuple() {
        let cfg = active_cfg();
        let result = assert_token_authorized(&ok_reading(&cfg), Capability::EIP2612);
        assert!(result.is_ok(), "expected authorized, got {result:?}");
    }

    #[test]
    fn rejects_mismatched_codehash() {
        let cfg = active_cfg();
        let live = reading(&cfg, [0x99; 32], 31337, sample_token());
        let err = assert_token_authorized(&live, Capability::EIP2612).unwrap_err();
        assert_eq!(err.code(), ERR_TOKEN_UNSUPPORTED);
        assert_reason(
            &err,
            "observed EXTCODEHASH does not match configured runtimeCodeHash",
        );
    }

    #[test]
    fn rejects_inactive_or_unknown_token() {
        let mut deactivated = active_cfg();
        deactivated.active = false;
        let err_deactivated =
            assert_token_authorized(&ok_reading(&deactivated), Capability::EIP2612).unwrap_err();

        let unknown = never_configured();
        let err_unknown =
            assert_token_authorized(&ok_reading(&unknown), Capability::EIP2612).unwrap_err();

        assert_eq!(err_deactivated.code(), ERR_TOKEN_UNSUPPORTED);
        assert_eq!(err_unknown.code(), ERR_TOKEN_UNSUPPORTED);
        assert_eq!(
            err_deactivated.code(),
            err_unknown.code(),
            "deactivated and never-configured must be indistinguishable on-chain (brief §2.5)"
        );
        assert_reason(&err_deactivated, "inactive or unknown");
        assert_reason(&err_unknown, "inactive or unknown");
    }

    /// Important 1 of the hardening pass: check 2 (`cfg.token != token`,
    /// `:230-234` at the time of the finding) had zero test coverage --
    /// every other test either sets `active: false` (caught by check 1
    /// first) or matches the token address, so a regression that removed
    /// or inverted check 2 shipped 12 green tests. This isolates it: an
    /// active, correctly chain/codehash/capability-matched config queried
    /// with a DIFFERENT token address must still be rejected.
    #[test]
    fn rejects_token_address_mismatch() {
        let cfg = active_cfg();
        let live = reading(&cfg, sample_code_hash(), 31337, [0x99; 20]);
        let err = assert_token_authorized(&live, Capability::EIP2612).unwrap_err();
        assert_eq!(err.code(), ERR_TOKEN_UNSUPPORTED);
        assert_reason(&err, "configured token address mismatch");
    }

    /// Hazard-3 test (brief §4 item 4). There is no quote path yet (Task 6)
    /// and no gas-drip client reachable from `stream_g` yet, so this cannot
    /// wire an end-to-end "the real quote handler calls the real drip
    /// client" assertion without inventing structure the brief explicitly
    /// forbids. What this test actually proves: (1) the REAL
    /// `assert_token_authorized` rejects an unsupported token, exercised
    /// end-to-end, and (2) a call site built in this exact shape --
    /// authorize-then-`?`-then-drip -- cannot reach the drip client on
    /// that rejection, because `?` unwinds before `drips.drip()` is
    /// reached. That second point is a property of THIS TEST'S OWN 8-line
    /// `quote_for` helper, not of any real handler; it says nothing about
    /// whether a future Task 6/9 handler actually calls
    /// `assert_token_authorized` before touching the real `gas_drips`
    /// ledger, or whether it drips before authorizing. That binding is
    /// still owed to Tasks 6 and 9 -- see the module doc and task report.
    #[test]
    fn unsupported_token_quote_makes_zero_gas_drip_calls() {
        use std::cell::Cell;

        // Stand-in for "the smallest honest shape a future quote handler
        // must take": a call-counting fake in the position a real drip
        // client would occupy, wired behind this module's REAL
        // `assert_token_authorized` (not a mock of it). If this shape is
        // followed, an unsupported token can provably never reach the
        // drip client -- because the drip call happens only after `?`
        // on a real, exercised authorization check.
        struct FakeDripClient {
            calls: Cell<u32>,
        }
        impl FakeDripClient {
            fn drip(&self) {
                self.calls.set(self.calls.get() + 1);
            }
        }

        fn quote_for(
            reading: &LiveTokenReading,
            required_capability: Capability,
            drips: &FakeDripClient,
        ) -> Result<(), TokenManifestError> {
            assert_token_authorized(reading, required_capability)?;
            drips.drip();
            Ok(())
        }

        let drips = FakeDripClient {
            calls: Cell::new(0),
        };
        let unsupported = never_configured();

        let err = quote_for(&ok_reading(&unsupported), Capability::EIP2612, &drips).unwrap_err();

        assert_eq!(err.code(), ERR_TOKEN_UNSUPPORTED);
        assert_eq!(
            drips.calls.get(),
            0,
            "an unsupported token must never reach the drip client"
        );

        // Structural half: this module has zero dependency edges to the
        // gas-drip ledger module today. Scans this file's own raw source
        // (not the compiled output) so the check fails loudly the moment
        // anyone adds a real import without also strengthening this test.
        // The needle is assembled at runtime from two literals so this
        // very line does not itself contain the contiguous marker text
        // (which would make the scan trivially self-match). Best-effort
        // only: this is a substring scan, not a parse, so an aliased
        // import (`use crate::{gas_drips as g};` ... `g::...`) would not
        // be caught. If that ever slips through, the real backstop is
        // still Tasks 6/9 wiring a genuine integration test at the call
        // site -- this scan is a cheap tripwire for the common case, not
        // a substitute for that binding assertion.
        let this_file_source = include_str!("token_manifest.rs");
        let import_marker: String = ["gas_dr", "ips::"].concat();
        let use_marker: String = ["use crate::gas_dr", "ips"].concat();
        assert!(
            !this_file_source.contains(&import_marker) && !this_file_source.contains(&use_marker),
            "token_manifest.rs must not gain a dependency edge on the gas-drip \
             ledger module without Task 6/9 wiring a real integration test at \
             the call site (see this test's doc comment for what is/isn't proved)"
        );
    }

    // --- Additionally-required tests (brief §4, items 5-10) -----------------

    #[test]
    fn capability_mask_is_subset_test() {
        let mut cfg = active_cfg();
        cfg.capability_mask = 0b1010; // CAP_EIP3009 | CAP_SELL_SPLIT

        for required in [
            Capability::EIP3009,
            Capability::SELL_SPLIT,
            Capability::EIP3009 | Capability::SELL_SPLIT,
        ] {
            let result = assert_token_authorized(&ok_reading(&cfg), required);
            assert!(
                result.is_ok(),
                "mask 0b1010 must grant required {:#06b}, got {result:?}",
                required.bits()
            );
        }

        let err = assert_token_authorized(
            &ok_reading(&cfg),
            Capability::EIP3009 | Capability::PRIOR_ALLOWANCE,
        )
        .unwrap_err();
        assert_eq!(
            err.code(),
            ERR_TOKEN_UNSUPPORTED,
            "EIP3009|PRIOR_ALLOWANCE (0b0110) is not a subset of mask 0b1010 (needs bit \
             0b0100, which the mask lacks)"
        );
        assert_reason(
            &err,
            "capabilityMask does not grant the required capability",
        );
    }

    /// Minor 1 of the hardening pass: the `required_capability == 0` guard
    /// (`ERR_ZERO_REQUIRED_CAPABILITY`) had zero test coverage -- deleting
    /// it would silently regress toward chain-permissive behavior with no
    /// test catching it. `Capability::required(&[])` is the one sanctioned
    /// way to build a zero-bits `Capability` (see [`Capability::required`]
    /// docs).
    #[test]
    fn rejects_zero_required_capability() {
        let cfg = active_cfg();
        let err =
            assert_token_authorized(&ok_reading(&cfg), Capability::required(&[])).unwrap_err();
        assert_eq!(err.code(), ERR_ZERO_REQUIRED_CAPABILITY);
        assert!(matches!(err, TokenManifestError::ZeroRequiredCapability));
    }

    #[test]
    fn cap_constants_do_not_match_authorization_mode_ordinals() {
        // AuthorizationMode ordinals: NONE=0, EIP2612=1, EIP3009=2,
        // PRIOR_ALLOWANCE=3 -- these are NOT the CAP_* values.
        assert_eq!(CAP_EIP2612, 1);
        assert_eq!(CAP_EIP3009, 2);
        assert_eq!(
            CAP_PRIOR_ALLOWANCE, 4,
            "CAP_PRIOR_ALLOWANCE is bit 2 (1<<2) == 4, not AuthorizationMode's ordinal 3"
        );
        assert_eq!(
            CAP_SELL_SPLIT, 8,
            "CAP_SELL_SPLIT is bit 3 (1<<3) == 8, not 3 -- it has no AuthorizationMode ordinal at all"
        );
    }

    #[test]
    fn fee_token_config_hash_matches_contract_encoding() {
        assert_eq!(
            FEE_TOKEN_CONFIG_TYPEHASH_STR,
            "FeeTokenConfig(uint256 chainId,address token,bytes32 runtimeCodeHash,bytes32 proxyIdentityHash,uint256 capabilityMask,uint8 decimals,bytes32 domainNameHash,bytes32 domainVersionHash,bytes32 builtInModeId,uint64 configVersion,bool active)"
        );

        // Cross-checked with `cast keccak "FeeTokenConfig(...)"` against
        // the literal string above -- see task report for the exact
        // command and output.
        assert_eq!(
            hex::encode(keccak256(FEE_TOKEN_CONFIG_TYPEHASH_STR.as_bytes())),
            "df3f4881a773320188104db0a63dab7043eb60cac6c8e7eea34993ccf6e77b36",
            "typehash bytes drifted from the pinned literal"
        );

        // Fixed fixture, independently cross-checked against a real `forge
        // script` run of the exact `keccak256(abi.encode(FEE_TOKEN_CONFIG_TYPEHASH,
        // ...))` line from FeeTokenRegistry._hashConfig (see task report)
        // -- NOT a self-referential Rust-only pin.
        let cfg = TokenCapability {
            chain_id: 31337,
            token_address: [0x11; 20],
            runtime_code_hash: [0x22; 32],
            proxy_identity_hash: [0u8; 32],
            capability_mask: 15,
            decimals: 6,
            domain_name_hash: [0x33; 32],
            domain_version_hash: [0x44; 32],
            built_in_mode_id: [0x55; 32],
            config_version: 3,
            active: true,
        };
        assert_eq!(
            hex::encode(fee_token_config_hash(&cfg)),
            "f524761eec64afaa1722c657712aa16ea2de204bf143bab1a71c5b4f5b6ce097",
            "struct-hash encoding drifted from FeeTokenRegistry._hashConfig -- \
             if this is an intentional encoding change, recompute via forge \
             and re-pin; if not, this diverges from the deployed contract"
        );
    }

    #[test]
    fn rejects_non_zero_proxy_identity_at_admission() {
        let mut cfg = active_cfg();
        cfg.proxy_identity_hash = [0x01; 32];
        let err = validate_proxy_identity_admissible(&cfg).unwrap_err();
        assert_eq!(err.code(), ERR_PROXY_IDENTITY_UNSUPPORTED);

        let ok_cfg = active_cfg();
        assert!(validate_proxy_identity_admissible(&ok_cfg).is_ok());

        // Defense-in-depth half: a non-zero value that somehow slipped
        // past admission is also rejected at the read path, even though
        // the real chain's read path never checks it -- see module doc.
        let mut corrupted = active_cfg();
        corrupted.proxy_identity_hash = [0x01; 32];
        let read_err =
            assert_token_authorized(&ok_reading(&corrupted), Capability::EIP2612).unwrap_err();
        assert_eq!(read_err.code(), ERR_TOKEN_UNSUPPORTED);
    }

    #[test]
    fn rejects_chain_id_mismatch() {
        // Half 1: config-vs-live, inside assert_token_authorized, driven
        // through the `#[cfg(test)]` hatch. As of Task 6 Wave B this branch
        // is ALSO reachable from a real chain read -- see
        // `live_reading_rejects_chain_id_the_endpoint_disagrees_with`, which
        // is the non-degenerate version of this assertion; what follows just
        // pins the branch's behavior cheaply.
        let cfg = active_cfg();
        let live = reading(&cfg, sample_code_hash(), 1, sample_token());
        let err = assert_token_authorized(&live, Capability::EIP2612).unwrap_err();
        assert_eq!(err.code(), ERR_TOKEN_UNSUPPORTED);
        assert_reason(&err, "configured chainId does not match live chain");

        // Half 2: manifest-vs-configured-chain, inside load_deployment_manifest.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        fs::write(&path, sample_manifest_json(1)).unwrap();
        let err2 = load_deployment_manifest(&path, 31337).unwrap_err();
        assert_eq!(err2.code(), ERR_MANIFEST_CHAIN_MISMATCH);
    }

    /// Real-shaped fixture matching `contracts/deployments/31337.stream-g.json`
    /// (17 keys, same field names/casing `writeManifest` emits).
    ///
    /// `feeScheduleHash` here is the digest of the schedule this repo ships
    /// (`fixtures/stream_g_fee_schedule.json`), the same value
    /// `runtime::test_support::FIXTURE_FEE_SCHEDULE_HASH` carries and the same
    /// value the committed artifact now carries. It used to be
    /// `keccak256("stream-g-fee-schedule-g1")`, the retired governance tag; that
    /// tag is a label and no schedule payload hashes to it, so a fixture
    /// claiming to be "real-shaped" could not keep carrying it. Nothing in this
    /// module compares the field against a schedule — `runtime::StreamGState::start`
    /// does that — so the value is here for fidelity to the artifact, not because
    /// a `load_deployment_manifest` assertion reads it.
    fn sample_manifest_json(chain_id: u64) -> String {
        format!(
            r#"{{
                "schemaVersion": 1,
                "chainId": {chain_id},
                "phase": "G1",
                "enrollmentRegistry": "0x104fBc016F4bb334D775a19E8A6510109AC63E00",
                "goatCoin": "0x037eDa3aDB1198021A9b2e88C22B464fD38db3f3",
                "feeToken": "0xDDc10602782af652bB913f7bdE1fD82981Db7dd9",
                "feeTokenRegistry": "0x7FdB3132Ff7D02d8B9e221c61cC895ce9a4bb773",
                "walletSponsorshipRegistry": "0xfD07C974e33dd1626640bA3a5acF0418FaacCA7a",
                "sponsoredBuyDesk": "0xD76ffbd1eFF76C510C3a509fE22864688aC3A588",
                "goatRelayGateway": "0x4ff05a443250A64a18C68CEdd2122cFDf3872140",
                "policySafe": "0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496",
                "feeSafe": "0xD1CCc21678e1B7015A472216B2F501f421645b43",
                "recoverySafe": "0xb8705214E170151048Eff0A1eDE1824FfF19CB9C",
                "deskOwner": "0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496",
                "quoteSigner": "0xeBD5a85005dCC98dabB7a2888De82D43c5A6957E",
                "deploymentManifestHash": "0xc1326e2474495792874c6baba322d9562e530c0c2a8defe037ff432c890aba65",
                "feeScheduleHash": "0x1c663d43fccc550dd95ef9dcd469eb12ac98006d355fea4ce9fcdc002ff8d952"
            }}"#
        )
    }

    /// Test-only convenience wrapping [`parse_hex_fixed`] -- lets tests
    /// express expected addresses/hashes as the same hex literals the
    /// fixture JSON uses, rather than hand-transcribed byte arrays.
    fn addr(hex_str: &str) -> [u8; 20] {
        parse_hex_fixed::<20>("test", hex_str).unwrap()
    }

    fn hash32(hex_str: &str) -> [u8; 32] {
        parse_hex_fixed::<32>("test", hex_str).unwrap()
    }

    #[test]
    fn loads_deployment_manifest_from_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        fs::write(&path, sample_manifest_json(31337)).unwrap();

        let manifest = load_deployment_manifest(&path, 31337).expect("valid manifest must load");
        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.chain_id, 31337);
        assert_eq!(manifest.phase, "G1");
        assert_eq!(
            manifest.fee_token_registry,
            addr("0x7FdB3132Ff7D02d8B9e221c61cC895ce9a4bb773")
        );
        assert_eq!(
            manifest.wallet_sponsorship_registry,
            addr("0xfD07C974e33dd1626640bA3a5acF0418FaacCA7a")
        );
        // The digest of the shipped deployment payload
        // (`fixtures/stream_g_deployment_payload.json`), not an arbitrary
        // opaque value. These fixtures used to carry
        // `keccak256("stream-g-manifest-g1")` = `0x1b374be1…`, the retired tag
        // that hashed nothing; leaving it here would have kept a
        // copy-pasteable manifest in the tree that `StreamGState::start` now
        // refuses (`DeploymentManifestHashMismatch`). This parser sees the
        // field as opaque bytes either way — the binding is enforced in
        // `runtime::StreamGState::start`, not here.
        assert_eq!(
            manifest.deployment_manifest_hash,
            hash32("0xc1326e2474495792874c6baba322d9562e530c0c2a8defe037ff432c890aba65")
        );
    }

    /// Important 2 of the hardening pass: the 12 address fields and 2 hash
    /// fields used to be unvalidated `String`s -- `""`, a truncated
    /// address, a non-hex value, and a value missing its `0x` prefix all
    /// loaded successfully and returned `Ok`. Now each must be a
    /// well-formed fixed-length hex string or the whole manifest fails to
    /// parse.
    #[test]
    fn rejects_malformed_address_fields() {
        let cases = [
            "",                                           // empty
            "0x7Fdb",                                     // truncated
            "not-an-address",                             // non-hex, no 0x prefix
            "7FdB3132Ff7D02d8B9e221c61cC895ce9a4bb773",   // missing 0x prefix, otherwise valid
            "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", // 0x-prefixed, correct length, non-hex
        ];
        for bad in cases {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("manifest.json");
            fs::write(&path, manifest_json_with_fee_token_registry(bad)).unwrap();
            let err = load_deployment_manifest(&path, 31337).unwrap_err();
            assert_eq!(
                err.code(),
                ERR_MANIFEST_PARSE,
                "expected parse error for feeTokenRegistry = {bad:?}, got {err:?}"
            );
        }
    }

    /// Minor 5 of the hardening pass: `phase` was loaded and never
    /// checked, so a misconfigured process pointed at a manifest from a
    /// different phase would otherwise pass every other check. This pins
    /// the absolute anchor.
    #[test]
    fn rejects_non_g1_phase() {
        let json = sample_manifest_json(31337).replace("\"phase\": \"G1\"", "\"phase\": \"G2\"");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        fs::write(&path, json).unwrap();

        let err = load_deployment_manifest(&path, 31337).unwrap_err();
        assert_eq!(err.code(), ERR_MANIFEST_PHASE_MISMATCH);
        assert!(matches!(
            err,
            TokenManifestError::ManifestPhaseMismatch { manifest_phase } if manifest_phase == "G2"
        ));
    }

    /// Manifest fixture with `feeTokenRegistry` overridden to `value` --
    /// used by [`rejects_malformed_address_fields`] to exercise the hex
    /// parser's failure modes without duplicating the whole 17-key fixture
    /// per case.
    fn manifest_json_with_fee_token_registry(value: &str) -> String {
        format!(
            r#"{{
                "schemaVersion": 1,
                "chainId": 31337,
                "phase": "G1",
                "enrollmentRegistry": "0x104fBc016F4bb334D775a19E8A6510109AC63E00",
                "goatCoin": "0x037eDa3aDB1198021A9b2e88C22B464fD38db3f3",
                "feeToken": "0xDDc10602782af652bB913f7bdE1fD82981Db7dd9",
                "feeTokenRegistry": "{value}",
                "walletSponsorshipRegistry": "0xfD07C974e33dd1626640bA3a5acF0418FaacCA7a",
                "sponsoredBuyDesk": "0xD76ffbd1eFF76C510C3a509fE22864688aC3A588",
                "goatRelayGateway": "0x4ff05a443250A64a18C68CEdd2122cFDf3872140",
                "policySafe": "0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496",
                "feeSafe": "0xD1CCc21678e1B7015A472216B2F501f421645b43",
                "recoverySafe": "0xb8705214E170151048Eff0A1eDE1824FfF19CB9C",
                "deskOwner": "0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496",
                "quoteSigner": "0xeBD5a85005dCC98dabB7a2888De82D43c5A6957E",
                "deploymentManifestHash": "0xc1326e2474495792874c6baba322d9562e530c0c2a8defe037ff432c890aba65",
                "feeScheduleHash": "0x1c663d43fccc550dd95ef9dcd469eb12ac98006d355fea4ce9fcdc002ff8d952"
            }}"#
        )
    }

    #[test]
    fn missing_manifest_key_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest_missing.json");
        // "feeTokenRegistry" omitted entirely -- must be a fail-closed
        // error, never a defaulted/omitted field (brief §2.8).
        let json = r#"{
            "schemaVersion": 1,
            "chainId": 31337,
            "phase": "G1",
            "enrollmentRegistry": "0x104fBc016F4bb334D775a19E8A6510109AC63E00",
            "goatCoin": "0x037eDa3aDB1198021A9b2e88C22B464fD38db3f3",
            "feeToken": "0xDDc10602782af652bB913f7bdE1fD82981Db7dd9",
            "walletSponsorshipRegistry": "0xfD07C974e33dd1626640bA3a5acF0418FaacCA7a",
            "sponsoredBuyDesk": "0xD76ffbd1eFF76C510C3a509fE22864688aC3A588",
            "goatRelayGateway": "0x4ff05a443250A64a18C68CEdd2122cFDf3872140",
            "policySafe": "0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496",
            "feeSafe": "0xD1CCc21678e1B7015A472216B2F501f421645b43",
            "recoverySafe": "0xb8705214E170151048Eff0A1eDE1824FfF19CB9C",
            "deskOwner": "0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496",
            "quoteSigner": "0xeBD5a85005dCC98dabB7a2888De82D43c5A6957E",
            "deploymentManifestHash": "0xc1326e2474495792874c6baba322d9562e530c0c2a8defe037ff432c890aba65",
            "feeScheduleHash": "0x1c663d43fccc550dd95ef9dcd469eb12ac98006d355fea4ce9fcdc002ff8d952"
        }"#;
        fs::write(&path, json).unwrap();

        let err = load_deployment_manifest(&path, 31337).unwrap_err();
        assert_eq!(err.code(), ERR_MANIFEST_PARSE);
    }

    // --- Wave B: live-chain sourcing of the gate's inputs -------------------

    /// Builds a `MockChain` whose Stream G reads all agree, for
    /// `registry` / `token`: deployed code hashing to `code_hash`, a
    /// `getTokenConfig` return equal to `cfg`, a `getTokenConfigHash`
    /// return equal to `fee_token_config_hash(cfg)`, and an `eth_chainId`
    /// answer equal to `cfg.chain_id`.
    ///
    /// The chain id is armed from `cfg.chain_id` *here, in the fixture* --
    /// deliberately not inside `read_live_token_state`, which is the whole
    /// point of Wave B's change. A test that wants to exercise gate check 3
    /// overrides it with a second `set_chain_id` call after this returns
    /// (see [`live_reading_rejects_chain_id_the_endpoint_disagrees_with`]).
    fn wired_chain(
        registry: [u8; 20],
        token: [u8; 20],
        code: &[u8],
        cfg: &TokenCapability,
    ) -> crate::chain::MockChain {
        let m = crate::chain::MockChain::new();
        m.set_pinned_block_number(1234);
        m.set_chain_id(cfg.chain_id);
        m.set_fee_token_code(token, code);
        m.set_fee_token_config(registry, token, view_of(cfg));
        m.set_fee_token_config_hash(registry, token, fee_token_config_hash(cfg));
        m
    }

    /// **The mutation that distinguishes gate check 3 from `x == x`.** Only
    /// the endpoint's `eth_chainId` answer changes: the `FeeTokenConfig`
    /// struct, its registry-reported `getTokenConfigHash`, the deployed
    /// bytecode and the deployment manifest are all byte-identical between
    /// the accepted control and the rejected case. Before Wave B,
    /// `live_chain_id` was `capability.chain_id`, so this mutation was
    /// invisible and the check could not fail outside a `#[cfg(test)]`
    /// reading.
    ///
    /// Mutation verified: reverting `read_live_token_state`'s
    /// `live_chain_id: LiveChainId::new(live_chain_id)` to
    /// `LiveChainId::new(capability.chain_id)` makes this test fail (the
    /// `unwrap_err` panics on an `Ok`), while every other test in this
    /// module still passes.
    #[test]
    fn live_reading_rejects_chain_id_the_endpoint_disagrees_with() {
        let registry = [0x77u8; 20];
        let token = sample_token();
        let code = b"runtime".to_vec();
        let mut cfg = active_cfg(); // chain_id == 31337
        cfg.runtime_code_hash = keccak256(&code);

        // Control: endpoint agrees with the config -> authorized.
        let chain_ok = wired_chain(registry, token, &code, &cfg);
        let live_ok = read_live_token_state(&chain_ok, registry, token, 1234).unwrap();
        assert_eq!(live_ok.live_chain_id().into_inner(), 31337);
        assert!(assert_token_authorized(&live_ok, Capability::EIP2612).is_ok());
        assert_eq!(
            chain_ok.chain_id_call_count(),
            1,
            "the chain id must have been READ, not lifted out of the config"
        );

        // Mutation: the SAME config, the SAME registry hash, the SAME
        // bytecode -- only the endpoint now says it is Base mainnet.
        let chain_bad = wired_chain(registry, token, &code, &cfg);
        chain_bad.set_chain_id(8453);
        let live_bad = read_live_token_state(&chain_bad, registry, token, 1234)
            .expect("the config is still well-formed and hash-bound; only the gate must reject");
        assert_eq!(live_bad.live_chain_id().into_inner(), 8453);
        assert_eq!(
            live_bad.capability(),
            live_ok.capability(),
            "the config side of the comparison must be unchanged by the mutation"
        );
        assert_eq!(
            live_bad.fee_token_config_hash(),
            live_ok.fee_token_config_hash(),
            "the registry's config hash must be unchanged by the mutation"
        );

        let err = assert_token_authorized(&live_bad, Capability::EIP2612).unwrap_err();
        assert_eq!(err.code(), ERR_TOKEN_UNSUPPORTED);
        assert_reason(&err, "configured chainId does not match live chain");
    }

    /// `ChainClient::chain_id`'s default body is `Err`, never `Ok(0)`. A
    /// `MockChain` that was never armed must therefore fail the whole read
    /// closed rather than produce a reading claiming chain 0.
    ///
    /// Mutation verified: making the `chain.chain_id()` call in
    /// `read_live_token_state` fall back to `unwrap_or(0)` makes this test
    /// fail.
    #[test]
    fn live_reading_fails_closed_when_the_endpoint_cannot_report_its_chain_id() {
        let registry = [0x77u8; 20];
        let token = sample_token();
        let code = b"runtime".to_vec();
        let mut cfg = active_cfg();
        cfg.runtime_code_hash = keccak256(&code);

        let chain = crate::chain::MockChain::new();
        chain.set_pinned_block_number(1234);
        chain.set_fee_token_code(token, &code);
        chain.set_fee_token_config(registry, token, view_of(&cfg));
        chain.set_fee_token_config_hash(registry, token, fee_token_config_hash(&cfg));
        // Deliberately no `set_chain_id`.

        let err = read_live_token_state(&chain, registry, token, 1234).unwrap_err();
        assert_eq!(err.code(), ERR_CHAIN_READ);
        assert!(
            err.to_string().contains("eth_chainId"),
            "the failing read must name itself, got: {err}"
        );
    }

    /// `TokenCapability` -> the chain-layer `FeeTokenConfigView` the RPC
    /// decoder produces, field for field.
    fn view_of(cfg: &TokenCapability) -> crate::chain::FeeTokenConfigView {
        crate::chain::FeeTokenConfigView {
            chain_id: cfg.chain_id,
            token: cfg.token_address,
            runtime_code_hash: cfg.runtime_code_hash,
            proxy_identity_hash: cfg.proxy_identity_hash,
            capability_mask: cfg.capability_mask,
            decimals: cfg.decimals,
            domain_name_hash: cfg.domain_name_hash,
            domain_version_hash: cfg.domain_version_hash,
            built_in_mode_id: cfg.built_in_mode_id,
            config_version: cfg.config_version,
            active: cfg.active,
        }
    }

    /// THE mutation that distinguishes a real gate from `x == x`: the token's
    /// deployed bytecode was replaced, so `eth_getCode` hashes to something
    /// other than the registry's stored `runtimeCodeHash`, while the config
    /// itself (and therefore its registry hash) is untouched. A reading built
    /// by self-comparison would still authorize; this must not.
    #[test]
    fn live_reading_rejects_code_hash_that_differs_from_configured_runtime_code_hash() {
        let registry = [0x77u8; 20];
        let token = sample_token();
        let cfg = active_cfg(); // runtime_code_hash == sample_code_hash()

        // Deployed code whose keccak256 is NOT sample_code_hash().
        let replaced_code = b"replaced runtime bytecode".to_vec();
        assert_ne!(keccak256(&replaced_code), cfg.runtime_code_hash);
        let chain = wired_chain(registry, token, &replaced_code, &cfg);

        let live = read_live_token_state(&chain, registry, token, 1234)
            .expect("the config itself is well-formed and hash-bound; the read must succeed");

        let err = assert_token_authorized(&live, Capability::EIP2612).unwrap_err();
        assert_eq!(err.code(), ERR_TOKEN_UNSUPPORTED);
        assert_reason(
            &err,
            "observed EXTCODEHASH does not match configured runtimeCodeHash",
        );

        // Control: the SAME config with matching deployed code authorizes,
        // so the rejection above is caused by the code-hash mutation alone.
        let matching_code = b"the real runtime bytecode".to_vec();
        let mut cfg_ok = active_cfg();
        cfg_ok.runtime_code_hash = keccak256(&matching_code);
        let chain_ok = wired_chain(registry, token, &matching_code, &cfg_ok);
        let live_ok = read_live_token_state(&chain_ok, registry, token, 1234).unwrap();
        assert!(assert_token_authorized(&live_ok, Capability::EIP2612).is_ok());
    }

    /// R2 step 1: the decoded struct must hash to `getTokenConfigHash`. This
    /// is what proves the struct we decoded is the struct the registry
    /// actually holds.
    #[test]
    fn live_reading_rejects_config_that_does_not_hash_to_registry_config_hash() {
        let registry = [0x77u8; 20];
        let token = sample_token();
        let cfg = active_cfg();
        let code = b"runtime".to_vec();
        let mut cfg_with_code = cfg.clone();
        cfg_with_code.runtime_code_hash = keccak256(&code);

        let chain = wired_chain(registry, token, &code, &cfg_with_code);
        // Registry reports a DIFFERENT config hash than the struct it returned.
        chain.set_fee_token_config_hash(registry, token, [0xEE; 32]);

        let err = read_live_token_state(&chain, registry, token, 1234).unwrap_err();
        assert_eq!(err.code(), ERR_FEE_TOKEN_CONFIG_HASH_MISMATCH);
    }

    /// Empty deployed code must fail closed (R1) rather than hashing the
    /// empty string into the comparison.
    #[test]
    fn live_reading_fails_closed_on_empty_deployed_code() {
        let registry = [0x77u8; 20];
        let token = sample_token();
        let cfg = active_cfg();
        let chain = wired_chain(registry, token, &[], &cfg);
        let err = read_live_token_state(&chain, registry, token, 1234).unwrap_err();
        assert_eq!(err.code(), ERR_CHAIN_READ);
    }

    /// G1 constraints rejected at the read, before a caller ever holds a
    /// `LiveTokenReading`.
    #[test]
    fn live_reading_rejects_inactive_and_proxy_configs() {
        let registry = [0x77u8; 20];
        let token = sample_token();
        let code = b"runtime".to_vec();

        let mut inactive = active_cfg();
        inactive.runtime_code_hash = keccak256(&code);
        inactive.active = false;
        let chain = wired_chain(registry, token, &code, &inactive);
        let err = read_live_token_state(&chain, registry, token, 1234).unwrap_err();
        assert_eq!(err.code(), ERR_TOKEN_UNSUPPORTED);

        let mut proxied = active_cfg();
        proxied.runtime_code_hash = keccak256(&code);
        proxied.proxy_identity_hash = [0x01; 32];
        let chain2 = wired_chain(registry, token, &code, &proxied);
        let err2 = read_live_token_state(&chain2, registry, token, 1234).unwrap_err();
        assert_eq!(err2.code(), ERR_PROXY_IDENTITY_UNSUPPORTED);
    }

    /// The queried address is the one the caller asked the RPC about, NOT
    /// `cfg.token` — so gate check 2 compares two independent values.
    #[test]
    fn live_reading_queries_the_address_it_was_asked_about_not_the_configured_one() {
        let registry = [0x77u8; 20];
        let asked = [0x99u8; 20];
        let code = b"runtime".to_vec();
        // Registry returns a config naming a DIFFERENT token address.
        let mut cfg = active_cfg(); // token_address == sample_token()
        cfg.runtime_code_hash = keccak256(&code);
        let chain = wired_chain(registry, asked, &code, &cfg);

        let live = read_live_token_state(&chain, registry, asked, 1234).unwrap();
        assert_eq!(live.queried_token().into_inner(), asked);
        let err = assert_token_authorized(&live, Capability::EIP2612).unwrap_err();
        assert_reason(&err, "configured token address mismatch");
    }

    /// Loads the REAL committed manifest at
    /// `contracts/deployments/31337.stream-g.json` (repo-relative from
    /// `tools/goat-attestor`), proving this loader parses what
    /// `DeployStreamG.s.sol::writeManifest` actually produces -- not just a
    /// hand-written fixture shaped like it. Skips (does not fail) if the
    /// path is absent, since a checkout of only this crate would not
    /// include the sibling `contracts/` tree; in this repository the file
    /// exists, so this genuinely runs rather than skips.
    #[test]
    fn loads_real_committed_stream_g_manifest_if_present() {
        let path = Path::new("../../contracts/deployments/31337.stream-g.json");
        if !path.exists() {
            eprintln!("skipping: {path:?} not found in this checkout");
            return;
        }
        let manifest = load_deployment_manifest(path, 31337)
            .expect("the real committed manifest must parse with every required key present");
        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.phase, "G1");
        assert_eq!(manifest.chain_id, 31337);
    }

    /// **The anti-drift guard for [`BUILTIN_DEPLOYMENT_MANIFEST_JSON`].**
    ///
    /// `fixtures/31337.stream-g.json` is a copy of
    /// `contracts/deployments/31337.stream-g.json`, and
    /// `DeployStreamG.writeManifest` rewrites the latter on every `forge test`
    /// run (`contracts/test/DeployStreamG.t.sol`'s
    /// `test_writes_only_31337_stream_g_json`). A redeploy that moves an
    /// address, or a change to `SHIPPED_FEE_SCHEDULE_HASH`, must therefore
    /// fail here rather than leave a stale built-in that a zero-config start
    /// would silently load.
    ///
    /// Byte-identical, not merely field-equal: the copy exists so the two can
    /// be diffed by eye, and a reformat is exactly the kind of drift that makes
    /// that impossible.
    ///
    /// Skips (does not fail) when `contracts/` is absent, matching
    /// [`loads_real_committed_stream_g_manifest_if_present`] — a checkout of
    /// only this package has nothing to compare against, which is also why the
    /// built-in is a package-local copy rather than an `include_str!` reaching
    /// into a sibling tree that would not compile there.
    #[test]
    fn builtin_manifest_is_byte_identical_to_the_committed_deployment_artifact() {
        let path = Path::new("../../contracts/deployments/31337.stream-g.json");
        if !path.exists() {
            eprintln!("skipping: {path:?} not found in this checkout");
            return;
        }
        let committed = fs::read_to_string(path).expect("read the committed artifact");
        assert_eq!(
            BUILTIN_DEPLOYMENT_MANIFEST_JSON, committed,
            "fixtures/31337.stream-g.json has drifted from \
             contracts/deployments/31337.stream-g.json. The built-in is what a zero-config \
             `STREAM_G_ENABLED=1` start loads, so copy the committed artifact over the fixture \
             rather than editing either by hand"
        );
    }

    /// The built-in loads on the chain it was deployed to, and is refused —
    /// on its chain id, not on a missing file — on every other.
    ///
    /// This is what makes zero-config startup honest: it is available on 31337
    /// and nowhere else, and the "nowhere else" is a
    /// [`TokenManifestError::ManifestChainMismatch`] naming both ids.
    ///
    /// **Mutation this detects (applied, run, reverted):** deleting the
    /// `manifest.chain_id != configured_chain_id` guard in
    /// [`parse_deployment_manifest`] — the 84532 arm then returns `Ok` and its
    /// `expect_err` panics.
    #[test]
    fn builtin_manifest_parses_on_31337_and_is_refused_on_every_other_chain() {
        let manifest = parse_deployment_manifest(
            BUILTIN_DEPLOYMENT_MANIFEST_JSON,
            "<test>",
            BUILTIN_DEPLOYMENT_MANIFEST_CHAIN_ID,
        )
        .expect("the built-in must parse under the same loader a file goes through");
        assert_eq!(manifest.chain_id, BUILTIN_DEPLOYMENT_MANIFEST_CHAIN_ID);
        assert_eq!(manifest.chain_id, 31337, "the constant must not drift");
        assert_eq!(manifest.phase, "G1");

        let err = parse_deployment_manifest(BUILTIN_DEPLOYMENT_MANIFEST_JSON, "<test>", 84532)
            .expect_err("the 31337 built-in is not a Base Sepolia deployment");
        assert!(
            matches!(err, TokenManifestError::ManifestChainMismatch { .. }),
            "the refusal must be about the chain, not about the bytes: {err}"
        );
    }

    // --- Hazard 3, obligation 1: the observed code hash is CHAIN-sourced ----

    /// **The mutation that distinguishes gate check 4 from `x == x`**, in its
    /// strictest single-variable form.
    ///
    /// [`live_reading_rejects_code_hash_that_differs_from_configured_runtime_code_hash`]
    /// above already mutates the deployed bytecode, but its control arm uses a
    /// *different* `TokenCapability` (it has to: no bytecode hashes to
    /// `active_cfg`'s hard-coded `[0x22; 32]`), so strictly speaking two
    /// things differ between its two arms. Here exactly **one** byte-string
    /// differs across the two arms — what `eth_getCode` returns. The
    /// `FeeTokenConfig` struct, its `runtimeCodeHash` field, the registry's
    /// `getTokenConfigHash` answer, the endpoint's `eth_chainId` answer and
    /// the queried address are asserted byte-identical between the accepted
    /// control and the rejected mutant.
    ///
    /// Mutation this detects, verified to fail before this test was
    /// considered done: change [`read_live_token_state`]'s
    /// `observed_code_hash: ObservedCodeHash::new(observed_code_hash)` to
    /// `ObservedCodeHash::new(capability.runtime_code_hash)` — i.e. source the
    /// "observed" hash from the very config it is meant to check. The gate
    /// then authorizes both arms and this test's `unwrap_err` panics on an
    /// `Ok`.
    #[test]
    fn live_reading_code_hash_is_read_from_the_chain_not_lifted_out_of_the_config() {
        let registry = [0x77u8; 20];
        let token = sample_token();
        let real_code = b"the genuinely deployed runtime bytecode".to_vec();
        let replaced_code = b"an attacker's replacement runtime bytecode".to_vec();
        assert_ne!(keccak256(&real_code), keccak256(&replaced_code));

        // ONE config, used verbatim by both arms. Its `runtimeCodeHash` is
        // the hash of `real_code`, so the control arm agrees and the mutant
        // arm does not — without the config itself changing at all.
        let mut cfg = active_cfg();
        cfg.runtime_code_hash = keccak256(&real_code);

        // Control: chain serves `real_code`.
        let chain_ok = wired_chain(registry, token, &real_code, &cfg);
        let live_ok = read_live_token_state(&chain_ok, registry, token, 1234).unwrap();
        assert_eq!(
            chain_ok.fee_token_code_hash_call_count(),
            1,
            "the observed code hash must have been READ (eth_getCode), not derived"
        );
        assert!(assert_token_authorized(&live_ok, Capability::EIP2612).is_ok());

        // Mutant: the ONLY difference is the bytecode `eth_getCode` returns.
        let chain_bad = wired_chain(registry, token, &replaced_code, &cfg);
        let live_bad = read_live_token_state(&chain_bad, registry, token, 1234)
            .expect("the config is still well-formed and hash-bound; only the GATE must reject");

        // Everything except the observed hash is provably unchanged, so the
        // rejection below cannot be attributed to anything else.
        assert_eq!(
            live_bad.capability(),
            live_ok.capability(),
            "the configured side of check 4 must be identical across the two arms"
        );
        assert_eq!(
            live_bad.fee_token_config_hash(),
            live_ok.fee_token_config_hash(),
            "the registry's config hash must be identical across the two arms"
        );
        assert_eq!(
            live_bad.live_chain_id().into_inner(),
            live_ok.live_chain_id().into_inner()
        );
        assert_eq!(
            live_bad.queried_token().into_inner(),
            live_ok.queried_token().into_inner()
        );
        assert_ne!(
            live_bad.observed_code_hash().into_inner(),
            live_ok.observed_code_hash().into_inner(),
            "the observed code hash is the one and only thing that differs; if these are \
             equal the reading is not sourcing it from eth_getCode"
        );
        assert_eq!(
            live_bad.observed_code_hash().into_inner(),
            keccak256(&replaced_code),
            "the observed hash must be keccak256 of what the chain actually returned"
        );

        let err = assert_token_authorized(&live_bad, Capability::EIP2612).unwrap_err();
        assert_eq!(err.code(), ERR_TOKEN_UNSUPPORTED);
        assert_reason(
            &err,
            "observed EXTCODEHASH does not match configured runtimeCodeHash",
        );
    }

    // --- TrustedChain: the MockChain refusal ------------------------------

    /// Structural tripwire for [`TrustedChain`]'s one load-bearing property:
    /// **in a release build there is no conversion from an arbitrary
    /// `ChainClient` into a `TrustedChain`.**
    ///
    /// This cannot be proven by a runtime assertion, because the property is
    /// the *absence* of a code path — the compiler is what enforces it (a
    /// non-test build rejects `read_live_token_state(&MockChain::new(), ..)`
    /// with `the trait bound TrustedChain<'_>: From<&MockChain> is not
    /// satisfied`, verified by hand during this wave). What this test does is
    /// the same job the sibling `include_str!` dependency-edge scan does:
    /// scan this file's own raw source so that deleting the `#[cfg(test)]`
    /// from the blanket conversion — which would silently reopen the hazard
    /// in release builds while every test stayed green — fails loudly here.
    ///
    /// Best-effort by construction: it is a source scan, not a parse. It
    /// would not catch a conversion added in a *different* file. Needles are
    /// assembled at runtime from fragments so this test's own source does not
    /// satisfy the scan it performs.
    #[test]
    fn trusted_chain_has_no_release_build_conversion_from_an_arbitrary_chain_client() {
        let src = include_str!("token_manifest.rs");
        let lines: Vec<&str> = src.lines().collect();

        // `impl std::fmt::Debug for TrustedChain<'_>` uses `'_`, so this
        // needle matches only conversions written against the named lifetime.
        let impl_marker: String = ["for Trusted", "Chain<'a> {"].concat();
        let impl_lines: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains(&impl_marker))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            impl_lines.len(),
            1,
            "expected exactly one `impl ... for TrustedChain<'a>` (the cfg(test) conversion); \
             found {} at lines {:?} — a second conversion is a release-build hole",
            impl_lines.len(),
            impl_lines.iter().map(|i| i + 1).collect::<Vec<_>>()
        );
        assert_eq!(
            lines[impl_lines[0] - 1].trim(),
            "#[cfg(test)]",
            "the blanket `From<&C: ChainClient>` conversion MUST stay test-only; without it \
             any ChainClient — including the release-shipped MockChain — becomes a TrustedChain"
        );

        // Both struct literals are accounted for: one in `live` (the only
        // production constructor) and one in the cfg(test) conversion.
        let ctor_marker: String = ["Self { in", "ner: "].concat();
        assert_eq!(
            src.matches(&ctor_marker).count(),
            2,
            "TrustedChain is constructed in exactly two places: `live` (production) and the \
             cfg(test) `From` impl. A third construction site is an unreviewed way in."
        );

        // ...and `live` takes the concrete RpcChain, never `&dyn ChainClient`.
        let live_marker: String = [
            "pub fn live(rpc: &'a crate::rpc_ch",
            "ain::RpcChain) -> Self",
        ]
        .concat();
        assert!(
            src.contains(&live_marker),
            "TrustedChain::live must take the concrete RpcChain by reference; widening it to \
             &dyn ChainClient would let MockChain straight through"
        );
    }
}
