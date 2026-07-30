//! Runtime configuration for goat-attestor.

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

use thiserror::Error;

use crate::gas_drips::{DripConfig, DEFAULT_DAILY_CAP};
use crate::stream_g::base_fee::{GasUnits, MaxFeePerGas};
use crate::stream_g::broadcaster::{BroadcastGasPolicy, GasPolicyError, PriorityFeePerGas};
use crate::stream_g::{maintenance, outbox, reconcile};

#[derive(Debug, Clone)]
pub struct Config {
    pub rpc_url: String,
    pub chain_id: u64,
    pub epoch_settlement_address: String,
    pub worker_binding_address: String,
    pub enrollment_registry_address: String,
    pub registry_json: PathBuf,
    pub fah_stats_base: String,
    pub team: String,
    pub poll_interval_s: u64,
    pub min_fah_interval_ms: u64,
    pub proposer_bond_wei: u128,
    pub challenger_bond_wei: u128,
    pub state_dir: PathBuf,
    pub evidence_dir: PathBuf,
    pub relayer_bind: String,
    pub confirmation_depth: u64,
    pub mock_mode: bool,
    /// Hex private keys (0x-prefixed) for live RPC roles. Unused when `mock_mode`.
    pub proposer_private_key: Option<String>,
    pub watcher_private_key: Option<String>,
    pub challenger_private_key: Option<String>,
    pub relayer_private_key: Option<String>,
    /// After propose: warp (anvil) → confirm → finalize → claim all leaves.
    pub auto_settle: bool,
    /// Use anvil_increaseTime to close challenge window in lab.
    pub auto_warp: bool,
    /// GoatCoin ERC-20 token address (gas-drip eligibility check). Synced from
    /// the desktop deployment JSON by `sync-env-from-desktop.ps1`; unset →
    /// gas-drip stays disabled regardless of `gas_drip_enabled` (GD task 8).
    pub goat_coin_address: Option<String>,
    /// Gas-drip amount-calculation config + configured daily cap, built from
    /// `GAS_DRIP_*` env with validation (see `build_drip_config`).
    pub gas_drip_cfg: DripConfig,
    /// Whether the gas-drip endpoint should be wired up at all. False when
    /// `GAS_DRIP_DAILY_CAP` resolves to 0 ("drips disabled" — see
    /// `build_drip_config`).
    pub gas_drip_enabled: bool,
    /// G-B1: first block to scan for `WorkerBinding.Bound` logs (deploy block of
    /// WorkerBinding). Default `0` is only safe on short lab chains (anvil).
    /// Non-anvil RpcChain refuses an unset pin (see `list_bound_workers`).
    pub worker_binding_deploy_block: u64,
    /// G-B1: max blocks per `eth_getLogs` page when listing Bound workers.
    /// Managed RPCs reject unbounded or huge ranges; default 2000.
    pub eth_get_logs_chunk: u64,
    /// Stream G (TARGET/post-pilot) scaffold config — see `stream_g` module
    /// doc. Disabled by default (`STREAM_G_ENABLED=0`); fail-closed
    /// validation (`build_stream_g_config`) only engages when enabled.
    pub stream_g: StreamGConfig,
}

/// Stream G (TARGET/post-pilot) config. `enabled` is false unless
/// `STREAM_G_ENABLED` is explicitly truthy; when true, `load_from_map`
/// requires the four dedicated keys below (never the pilot
/// `RELAYER_PRIVATE_KEY`) and rejects key reuse — see
/// `build_stream_g_config`.
#[derive(Debug, Clone)]
pub struct StreamGConfig {
    pub enabled: bool,
    pub db_path: PathBuf,
    pub lock_path: PathBuf,
    /// Dedicated broadcaster key. Must never equal `RELAYER_PRIVATE_KEY`.
    pub broadcaster_private_key: Option<String>,
    pub quote_signer_private_key: Option<String>,
    pub issuer_private_key: Option<String>,
    /// Hex symmetric key for at-rest data encryption (Stream G storage).
    pub data_key_hex: Option<String>,
    /// Where the USDT tariff schedule is read from.
    ///
    /// ⚠️ Paired with [`StreamGConfig::fee_schedule_path_source`], which is
    /// what decides whether a missing file here is a startup failure or a
    /// fall-through to the built-in
    /// [`crate::stream_g::quotes::BUILTIN_FEE_SCHEDULE_JSON`]. Never read one
    /// without the other.
    pub fee_schedule_path: PathBuf,
    /// Provenance of [`StreamGConfig::fee_schedule_path`] — see [`PathSource`].
    pub fee_schedule_path_source: PathSource,
    /// Where the deployment manifest is read from.
    ///
    /// ⚠️ Paired with [`StreamGConfig::deployment_manifest_path_source`], same
    /// rule as the fee schedule above; the built-in is
    /// [`crate::stream_g::token_manifest::BUILTIN_DEPLOYMENT_MANIFEST_JSON`].
    pub deployment_manifest_path: PathBuf,
    /// Provenance of [`StreamGConfig::deployment_manifest_path`] — see
    /// [`PathSource`].
    pub deployment_manifest_path_source: PathSource,
    /// Where the **deployment manifest payload** is read from — the document
    /// `deploymentManifestHash` is the digest of.
    ///
    /// ⚠️ Paired with [`StreamGConfig::deployment_payload_path_source`], same
    /// rule as the two documents above; the built-in is
    /// [`crate::stream_g::deployment_payload::BUILTIN_DEPLOYMENT_PAYLOAD_JSON`].
    ///
    /// This is a *third* document rather than a section of the manifest
    /// because the spec's payload is a five-key nested schema while the shipped
    /// manifest is a flat address map, and every existing reader of that flat
    /// map requires the fields it declares — see the `deployment_payload`
    /// module docs.
    pub deployment_payload_path: PathBuf,
    /// Provenance of [`StreamGConfig::deployment_payload_path`] — see
    /// [`PathSource`].
    pub deployment_payload_path_source: PathSource,
    pub cors_origins: Vec<String>,
    pub max_native_exposure_wei: u128,
    /// G-B1, Stream G edition: first block to scan for
    /// `GoatRelayGateway.SponsoredEnrollmentExecuted` logs (the gateway's
    /// deploy block). Exactly the same hazard as
    /// [`Config::worker_binding_deploy_block`] — default `0` is only safe on
    /// a short lab chain (anvil), and `RpcChain::sponsored_enrollment_logs`
    /// refuses an unset pin on every other chain rather than asking a managed
    /// RPC to scan from genesis.
    pub gateway_deploy_block: u64,
    /// Ratified decision A3's finality depth: how many confirmations a
    /// `SponsoredEnrollmentExecuted` log must have before this attestor may act
    /// on it. Default is derived from the **configured** `CHAIN_ID` —
    /// [`reconcile::ANVIL_CONFIRMATIONS`] (1) on [`reconcile::ANVIL_CHAIN_ID`]
    /// (31337), [`reconcile::DEFAULT_CONFIRMATIONS`] (12) everywhere else —
    /// and [`reconcile::ENV_CONFIRMATIONS`] (`STREAM_G_CONFIRMATIONS`)
    /// overrides it.
    ///
    /// **Why the configured id and not a live `eth_chainId`.** That is not the
    /// "live identity must come from the endpoint" rule being broken.
    /// `ChainClient::chain_id()` is a live round-trip that exists specifically
    /// for the token/manifest gate, where a config-sourced answer would make
    /// the check self-referential. This is a *policy default*, the same shape
    /// as `auto_settle` / `auto_warp` in [`load_from_map`], and it matches the
    /// in-tree `if self.chain_id != 31337` guards inside
    /// `rpc_chain::RpcChain::list_bound_workers` and
    /// `rpc_chain::RpcChain::sponsored_enrollment_logs` (both compare the
    /// configured `RpcChain::chain_id` field, not a live `eth_chainId`).
    ///
    /// **`STREAM_G_CONFIRMATIONS=0` is REJECTED, not clamped.** This is the
    /// first semantically-out-of-range numeric in this module that hard-fails
    /// the load rather than falling back — the direct opposite of the three
    /// sweep knobs below and of `eth_get_logs_chunk`, and the difference is
    /// deliberate. An absurd sweep cadence costs throughput; `0`
    /// confirmations means "treat a log no block has buried as final", which
    /// turns every reorg check in [`reconcile`] into a no-op. Rewriting that
    /// to `1` would silently delete a refusal the operator is entitled to see,
    /// so this field calls [`reconcile::FinalityPolicy::from_map`] — which
    /// already refuses `0` and has a dedicated test for it — instead of
    /// reimplementing the bound with a clamping parser. Validation is
    /// unconditional, like every other `STREAM_G_*` numeric: a bad value fails
    /// the load even with `STREAM_G_ENABLED=0`.
    ///
    /// **Consumed since Task 11 Wave D — A3 is closed for this lane.** This
    /// doc used to say "**Inert today — A3 remains OPEN.** This field is parsed
    /// and *consumed by nothing*", which was true and is now false; it is
    /// recorded rather than deleted, because a stale "this knob does nothing"
    /// doc is how an operator concludes a security-relevant setting is
    /// decorative.
    ///
    /// `crate::stream_g::maintenance::MaintenancePolicy::from_config` carries
    /// this value into the background reconciliation pass, which rebuilds a
    /// `reconcile::FinalityPolicy` from it — **not** from
    /// `FinalityPolicy::for_chain(chain_id)`, which would silently ignore what
    /// the operator set. Changing this changes how deep a
    /// `SponsoredEnrollmentExecuted` log must be buried before this attestor
    /// will confirm an enrollment against it.
    ///
    /// 🔴 It is the **entire** reorg protection, not a latency/safety trade:
    /// there is no reorg undo path a polling observer can reach. Lowering it is
    /// a founder-level risk acceptance. See
    /// `crate::stream_g::maintenance::MaintenancePolicy::confirmations`.
    pub confirmations: u64,

    // --- background maintenance loop (Task 8 Wave D) --------------------
    //
    // All three are read **only** by `stream_g::maintenance`, which is spawned
    // only when `enabled` is true, so they are inert with Stream G off. Each is
    // clamped rather than rejected: an out-of-range cadence is an operator typo,
    // and refusing to start over it would be worse than running at the nearest
    // sane value with a warning.
    /// Seconds between background maintenance passes (A2's *trigger*; the
    /// release authority is still chain time, inside the sweeper). Default
    /// [`crate::stream_g::maintenance::DEFAULT_SWEEP_INTERVAL_SECONDS`] (900),
    /// clamped to
    /// [`crate::stream_g::maintenance::MIN_SWEEP_INTERVAL_SECONDS`] ..=
    /// [`crate::stream_g::maintenance::MAX_SWEEP_INTERVAL_SECONDS`].
    pub sweep_interval_seconds: u64,
    /// How long the sweeper's own claim lasts, and how long a row it re-defers
    /// waits before the next pass looks at it. This is the env override
    /// `outbox.rs` named as Task 8's (`STREAM_G_OUTBOX_LEASE_TTL_SECONDS`);
    /// default [`crate::stream_g::outbox::DEFAULT_LEASE_TTL_SECONDS`].
    pub outbox_lease_ttl_seconds: i64,
    /// Cap on rows one sweep claims — one chain round-trip per row. Default
    /// [`crate::stream_g::outbox::DEFAULT_SWEEP_MAX_ROWS`].
    pub sweep_max_rows: i64,

    /// The three fee/gas numbers every Stream G broadcast is signed against
    /// ([`BroadcastGasPolicy`]), from [`ENV_BROADCAST_GAS_LIMIT`],
    /// [`ENV_BROADCAST_MAX_FEE_PER_GAS_WEI`] and
    /// [`ENV_BROADCAST_MAX_PRIORITY_FEE_PER_GAS_WEI`].
    ///
    /// 🔴 **THE DEFAULTS ARE STARTING VALUES AND STILL NEED FOUNDER REVIEW.**
    /// They are not invented here and no number in this module is new: the
    /// defaults are read straight off
    /// [`BroadcastGasPolicy::starting_values_pending_founder_review`], so the
    /// figures and the disclosure that owns them stay in one place. Read that
    /// constructor's type doc before setting any of the three — it states, per
    /// value, what evidence exists (`gas_limit` and `max_fee_per_gas` are the
    /// figures this tree already uses for this same call; the priority fee has
    /// **no in-tree precedent at all**) and what does not. Wiring them to env
    /// makes them *settable*; it does not make them reviewed.
    ///
    /// **Validation is unconditional**, like every other `STREAM_G_*` numeric:
    /// a combination [`BroadcastGasPolicy::new`] refuses fails the config load
    /// even with `STREAM_G_ENABLED=0`. That is deliberate and is what
    /// [`GasPolicyError`]'s own doc asks for — a bad policy is an operator
    /// misconfiguration that must stop startup rather than become a
    /// per-request 5xx, and it is built once at wiring time, long before any
    /// request exists. So this is the third `STREAM_G_*` knob that is
    /// **rejected rather than clamped**, alongside
    /// [`StreamGConfig::confirmations`] and the syntactic failure every
    /// numeric shares.
    pub broadcast_gas: BroadcastGasPolicy,
}

/// `gas_limit`, in gas units, for the outer sponsored-enrollment transaction.
pub const ENV_BROADCAST_GAS_LIMIT: &str = "STREAM_G_BROADCAST_GAS_LIMIT";
/// EIP-1559 `max_fee_per_gas`, in wei per gas.
pub const ENV_BROADCAST_MAX_FEE_PER_GAS_WEI: &str = "STREAM_G_BROADCAST_MAX_FEE_PER_GAS_WEI";
/// EIP-1559 `max_priority_fee_per_gas` (the tip), in wei per gas.
pub const ENV_BROADCAST_MAX_PRIORITY_FEE_PER_GAS_WEI: &str =
    "STREAM_G_BROADCAST_MAX_PRIORITY_FEE_PER_GAS_WEI";

/// Parse the three broadcast gas knobs and validate them **together** through
/// [`BroadcastGasPolicy::new`] — the `priority <= max` relation is a property
/// of the pair, so no per-key parse can catch it.
///
/// Defaults come from
/// [`BroadcastGasPolicy::starting_values_pending_founder_review`] rather than
/// from literals written here: duplicating 500_000 / 1 gwei / 0.001 gwei into
/// this module would be a second place to keep in step with a founder review
/// that has not happened yet.
///
/// Each [`GasPolicyError`] variant is reported against the key an operator
/// would have to change, so the message points at a variable rather than at a
/// type.
fn build_broadcast_gas_policy(
    map: &HashMap<String, String>,
) -> Result<BroadcastGasPolicy, ConfigError> {
    let defaults = BroadcastGasPolicy::starting_values_pending_founder_review();

    let gas_limit = parse_u64(map, ENV_BROADCAST_GAS_LIMIT, defaults.gas_limit().get())?;
    let max_fee = parse_u128(
        map,
        ENV_BROADCAST_MAX_FEE_PER_GAS_WEI,
        defaults.max_fee_per_gas().get(),
    )?;
    let priority_fee = parse_u128(
        map,
        ENV_BROADCAST_MAX_PRIORITY_FEE_PER_GAS_WEI,
        defaults.max_priority_fee_per_gas().get(),
    )?;

    BroadcastGasPolicy::new(
        GasUnits::new(gas_limit),
        MaxFeePerGas::new(max_fee),
        PriorityFeePerGas::new(priority_fee),
    )
    .map_err(|e| ConfigError::Invalid {
        key: match e {
            GasPolicyError::GasLimitBelowBaseCost { .. } => ENV_BROADCAST_GAS_LIMIT,
            GasPolicyError::ZeroMaxFeePerGas => ENV_BROADCAST_MAX_FEE_PER_GAS_WEI,
            GasPolicyError::PriorityAboveMax { .. } => ENV_BROADCAST_MAX_PRIORITY_FEE_PER_GAS_WEI,
        }
        .to_string(),
        msg: e.to_string(),
    })
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required env: {0}")]
    Missing(String),
    #[error("invalid value for {key}: {msg}")]
    Invalid { key: String, msg: String },
}

const REQUIRED: &[&str] = &[
    "RPC_URL",
    "CHAIN_ID",
    "EPOCH_SETTLEMENT_ADDRESS",
    "WORKER_BINDING_ADDRESS",
    "ENROLLMENT_REGISTRY_ADDRESS",
    "REGISTRY_JSON",
];

fn get_map<'a>(map: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    map.get(key).map(|s| s.as_str())
}

fn require(map: &HashMap<String, String>, key: &str) -> Result<String, ConfigError> {
    get_map(map, key)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| ConfigError::Missing(key.to_string()))
}

fn parse_u64(map: &HashMap<String, String>, key: &str, default: u64) -> Result<u64, ConfigError> {
    match get_map(map, key) {
        None | Some("") => Ok(default),
        Some(s) => s.parse::<u64>().map_err(|e| ConfigError::Invalid {
            key: key.to_string(),
            msg: e.to_string(),
        }),
    }
}

fn parse_u128(
    map: &HashMap<String, String>,
    key: &str,
    default: u128,
) -> Result<u128, ConfigError> {
    match get_map(map, key) {
        None | Some("") => Ok(default),
        Some(s) => s.parse::<u128>().map_err(|e| ConfigError::Invalid {
            key: key.to_string(),
            msg: e.to_string(),
        }),
    }
}

/// `parse_u64` followed by a clamp to `min..=max`, logging when the clamp
/// binds. Used for the Stream G maintenance knobs, where a semantically absurd
/// value (0-second cadence, 10-million-row batch) is an operator typo rather
/// than a reason to refuse to start. A *syntactically* bad value is still a
/// `ConfigError`, same as every other numeric knob in this module.
fn parse_u64_clamped(
    map: &HashMap<String, String>,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, ConfigError> {
    let raw = parse_u64(map, key, default)?;
    let clamped = raw.clamp(min, max);
    if clamped != raw {
        tracing::warn!("{key}={raw} is outside {min}..={max}; clamping to {clamped}");
    }
    Ok(clamped)
}

fn parse_u32(map: &HashMap<String, String>, key: &str, default: u32) -> Result<u32, ConfigError> {
    match get_map(map, key) {
        None | Some("") => Ok(default),
        Some(s) => s.parse::<u32>().map_err(|e| ConfigError::Invalid {
            key: key.to_string(),
            msg: e.to_string(),
        }),
    }
}

/// Ceiling clamp for `GAS_DRIP_APPROVE_GAS` / `GAS_DRIP_SELL_GAS`. Defensive
/// against hostile/typo'd env input: `compute_drip_wei` sums the two with a
/// plain `+` before the first `saturating_mul`, so an absurd `u64` here could
/// still overflow that initial addition. 5,000,000 gas is already ~100x a
/// normal ERC-20 approve+sell, so it can never bind in practice — it exists
/// purely as a backstop.
const GAS_KNOB_CEILING: u64 = 5_000_000;

/// Build the gas-drip `DripConfig` + "should the endpoint be wired up" flag
/// from env, falling back to `DripConfig::default()` per-field when a knob is
/// unset. Carries forward the GD4/GD8 review's required defensive handling
/// of semantically-invalid (as opposed to merely-unparseable) values:
///
/// - `GAS_DRIP_BUFFER_DEN=0` would panic `compute_drip_wei`'s division —
///   logged at error level and replaced with the default (2).
/// - `GAS_DRIP_APPROVE_GAS` / `GAS_DRIP_SELL_GAS` above `GAS_KNOB_CEILING` are
///   clamped with a logged warning (see `GAS_KNOB_CEILING` docs).
/// - `GAS_DRIP_DAILY_CAP=0` disables the endpoint entirely (logged at info)
///   rather than embedding a `daily_cap: 0` that would 429 every request —
///   see `DripConfig::daily_cap` docs.
///
/// A syntactically bad value (non-numeric) still surfaces as `ConfigError`,
/// same as every other numeric knob in this module.
fn build_drip_config(map: &HashMap<String, String>) -> Result<(DripConfig, bool), ConfigError> {
    let default = DripConfig::default();

    let mut approve_gas = parse_u64(map, "GAS_DRIP_APPROVE_GAS", default.approve_gas)?;
    if approve_gas > GAS_KNOB_CEILING {
        tracing::warn!(
            "GAS_DRIP_APPROVE_GAS={approve_gas} exceeds ceiling {GAS_KNOB_CEILING}; clamping"
        );
        approve_gas = GAS_KNOB_CEILING;
    }

    let mut sell_gas = parse_u64(map, "GAS_DRIP_SELL_GAS", default.sell_gas)?;
    if sell_gas > GAS_KNOB_CEILING {
        tracing::warn!("GAS_DRIP_SELL_GAS={sell_gas} exceeds ceiling {GAS_KNOB_CEILING}; clamping");
        sell_gas = GAS_KNOB_CEILING;
    }

    let buffer_num = parse_u64(map, "GAS_DRIP_BUFFER_NUM", default.buffer_num)?;

    let mut buffer_den = parse_u64(map, "GAS_DRIP_BUFFER_DEN", default.buffer_den)?;
    if buffer_den == 0 {
        tracing::error!(
            "GAS_DRIP_BUFFER_DEN=0 would panic compute_drip_wei's division; falling back to default ({})",
            default.buffer_den
        );
        buffer_den = default.buffer_den;
    }

    let max_wei = parse_u128(map, "GAS_DRIP_MAX_WEI", default.max_wei)?;

    let daily_cap = parse_u32(map, "GAS_DRIP_DAILY_CAP", DEFAULT_DAILY_CAP)?;
    let enabled = daily_cap != 0;
    if !enabled {
        tracing::info!("GAS_DRIP_DAILY_CAP=0; gas-drip endpoint disabled");
    }

    Ok((
        DripConfig {
            approve_gas,
            sell_gas,
            buffer_num,
            buffer_den,
            max_wei,
            daily_cap: if enabled {
                daily_cap
            } else {
                DEFAULT_DAILY_CAP
            },
        },
        enabled,
    ))
}

fn optional_key(map: &HashMap<String, String>, key: &str) -> Option<String> {
    get_map(map, key)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Where a configured path came from: the operator's env, or this crate's own
/// default for the key.
///
/// This distinction is load-bearing, not cosmetic. Two Stream G documents
/// ([`StreamGConfig::fee_schedule_path`] and
/// [`StreamGConfig::deployment_manifest_path`]) fall back to a **built-in**
/// copy when no file exists at the resolved path, and that fallback is only
/// safe when nobody chose the path. Silently falling back for an operator who
/// set `STREAM_G_FEE_SCHEDULE_PATH` and mistyped it would start the process
/// against a schedule they never selected — the same class of failure the
/// fallback exists to prevent at the other end. [`PathSource::Env`] therefore
/// means "read this file or fail", with no fallback arm at all; see
/// `stream_g::runtime::StreamGState::start` and its
/// `start_refuses_an_explicitly_configured_but_missing_fee_schedule` /
/// `start_refuses_an_explicitly_configured_but_missing_manifest` tests.
/// (Corrected 2026-07-27: both names were cited here without the `but_`, so
/// neither resolved to a real test.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSource {
    /// The key was present and non-empty in the env map — the operator chose
    /// this path, so nothing may substitute for it.
    Env,
    /// The key was unset or empty; the value is this crate's default for it.
    Default,
}

/// Path config with a default, matching the `state_dir`/`evidence_dir`
/// pattern above.
///
/// Returns the provenance alongside the path because a caller that substitutes
/// a built-in document for a missing file MUST NOT do so for a path the
/// operator chose — see [`PathSource`]. Callers with no fallback (`db_path`,
/// `lock_path`) discard the second element; a missing SQLite file is created
/// rather than substituted, so provenance changes nothing for them.
fn path_with_default(
    map: &HashMap<String, String>,
    key: &str,
    default: &str,
) -> (PathBuf, PathSource) {
    match get_map(map, key).filter(|s| !s.is_empty()) {
        Some(configured) => (PathBuf::from(configured), PathSource::Env),
        None => (PathBuf::from(default), PathSource::Default),
    }
}

/// Comma-separated list env var → `Vec<String>` (trims whitespace, drops
/// empty entries). Unset/empty → empty vec (no defaults unioned in, unlike
/// `relayer::parse_cors_origins` — Stream G is off by default so there is no
/// "built-in" origin to protect).
fn parse_comma_list(map: &HashMap<String, String>, key: &str) -> Vec<String> {
    match get_map(map, key) {
        None | Some("") => Vec::new(),
        Some(s) => s
            .split(',')
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .map(|p| p.to_string())
            .collect(),
    }
}

/// Build `StreamGConfig` from env, fail-closed: when `STREAM_G_ENABLED` is
/// truthy, all four dedicated keys (broadcaster/quote-signer/issuer/data)
/// must be present, and the broadcaster key must not equal
/// `RELAYER_PRIVATE_KEY` — the pilot relayer key must never double as a
/// Stream G signer. When disabled (the default), missing keys are fine and
/// this always returns `Ok`.
///
/// `state_dir` is the already-resolved `STATE_DIR` (or its own `./state`
/// default) so Stream G path defaults nest under it, same convention as
/// `evidence_dir`.
///
/// `chain_id` is the already-parsed `CHAIN_ID`, used **only** to pick decision
/// A3's default for [`StreamGConfig::confirmations`] — see that field's doc for
/// why a configured (not live) id is the right input for a policy default.
fn build_stream_g_config(
    map: &HashMap<String, String>,
    state_dir: &str,
    chain_id: u64,
) -> Result<StreamGConfig, ConfigError> {
    let enabled = parse_bool_default(map, "STREAM_G_ENABLED", false);

    let broadcaster_private_key = optional_key(map, "STREAM_G_BROADCASTER_PRIVATE_KEY");
    let quote_signer_private_key = optional_key(map, "STREAM_G_QUOTE_SIGNER_PRIVATE_KEY");
    let issuer_private_key = optional_key(map, "STREAM_G_ISSUER_PRIVATE_KEY");
    let data_key_hex = optional_key(map, "STREAM_G_DATA_KEY_HEX");

    if enabled {
        let mut missing: Vec<&str> = Vec::new();
        if broadcaster_private_key.is_none() {
            missing.push("STREAM_G_BROADCASTER_PRIVATE_KEY");
        }
        if quote_signer_private_key.is_none() {
            missing.push("STREAM_G_QUOTE_SIGNER_PRIVATE_KEY");
        }
        if issuer_private_key.is_none() {
            missing.push("STREAM_G_ISSUER_PRIVATE_KEY");
        }
        if data_key_hex.is_none() {
            missing.push("STREAM_G_DATA_KEY_HEX");
        }
        if !missing.is_empty() {
            return Err(ConfigError::Missing(missing.join(", ")));
        }

        // Never let the pilot relayer key double as a Stream G signer.
        let relayer_key = optional_key(map, "RELAYER_PRIVATE_KEY");
        if let (Some(broadcaster), Some(relayer)) = (&broadcaster_private_key, &relayer_key) {
            if broadcaster == relayer {
                return Err(ConfigError::Invalid {
                    key: "STREAM_G_BROADCASTER_PRIVATE_KEY".to_string(),
                    msg: "must not reuse RELAYER_PRIVATE_KEY — Stream G requires a dedicated key"
                        .to_string(),
                });
            }
        }
    }

    let default_db = format!("{state_dir}/stream_g.db");
    let default_lock = format!("{state_dir}/stream_g.lock");
    let default_fee_schedule = format!("{state_dir}/stream_g_fee_schedule.json");
    let default_manifest = format!("{state_dir}/stream_g_deployment_manifest.json");
    let default_deployment_payload = format!("{state_dir}/stream_g_deployment_payload.json");

    let (fee_schedule_path, fee_schedule_path_source) =
        path_with_default(map, "STREAM_G_FEE_SCHEDULE_PATH", &default_fee_schedule);
    let (deployment_manifest_path, deployment_manifest_path_source) =
        path_with_default(map, "STREAM_G_DEPLOYMENT_MANIFEST_PATH", &default_manifest);
    let (deployment_payload_path, deployment_payload_path_source) = path_with_default(
        map,
        "STREAM_G_DEPLOYMENT_PAYLOAD_PATH",
        &default_deployment_payload,
    );

    Ok(StreamGConfig {
        enabled,
        db_path: path_with_default(map, "STREAM_G_DB_PATH", &default_db).0,
        lock_path: path_with_default(map, "STREAM_G_LOCK_PATH", &default_lock).0,
        broadcaster_private_key,
        quote_signer_private_key,
        issuer_private_key,
        data_key_hex,
        fee_schedule_path,
        fee_schedule_path_source,
        deployment_manifest_path,
        deployment_manifest_path_source,
        deployment_payload_path,
        deployment_payload_path_source,
        cors_origins: parse_comma_list(map, "STREAM_G_CORS_ORIGINS"),
        max_native_exposure_wei: parse_u128(map, "STREAM_G_MAX_NATIVE_EXPOSURE_WEI", 0)?,
        gateway_deploy_block: parse_u64(map, "STREAM_G_GATEWAY_DEPLOY_BLOCK", 0)?,
        // A3. Delegated to `FinalityPolicy::from_map` rather than parsed here:
        // that function owns the `0 is refused, not clamped` rule and the
        // chain-id default, and a second copy of either would be a second thing
        // to keep in step. Its `BadConfig` is mapped into `ConfigError` so the
        // refusal surfaces as an ordinary config-load failure.
        confirmations: reconcile::FinalityPolicy::from_map(map, chain_id)
            .map_err(|e| ConfigError::Invalid {
                key: reconcile::ENV_CONFIRMATIONS.to_string(),
                msg: e.to_string(),
            })?
            .confirmations(),
        sweep_interval_seconds: parse_u64_clamped(
            map,
            "STREAM_G_SWEEP_INTERVAL_SECONDS",
            maintenance::DEFAULT_SWEEP_INTERVAL_SECONDS,
            maintenance::MIN_SWEEP_INTERVAL_SECONDS,
            maintenance::MAX_SWEEP_INTERVAL_SECONDS,
        )?,
        outbox_lease_ttl_seconds: i64::try_from(parse_u64_clamped(
            map,
            "STREAM_G_OUTBOX_LEASE_TTL_SECONDS",
            outbox::DEFAULT_LEASE_TTL_SECONDS as u64,
            maintenance::MIN_LEASE_TTL_SECONDS,
            maintenance::MAX_LEASE_TTL_SECONDS,
        )?)
        .unwrap_or(outbox::DEFAULT_LEASE_TTL_SECONDS),
        sweep_max_rows: i64::try_from(parse_u64_clamped(
            map,
            "STREAM_G_SWEEP_MAX_ROWS",
            outbox::DEFAULT_SWEEP_MAX_ROWS as u64,
            maintenance::MIN_SWEEP_MAX_ROWS,
            maintenance::MAX_SWEEP_MAX_ROWS,
        )?)
        .unwrap_or(outbox::DEFAULT_SWEEP_MAX_ROWS),
        broadcast_gas: build_broadcast_gas_policy(map)?,
    })
}

/// Load config from a key/value map (tests + programmatic use).
pub fn load_from_map(map: &HashMap<String, String>) -> Result<Config, ConfigError> {
    let mut missing: Vec<&str> = Vec::new();
    for k in REQUIRED {
        if get_map(map, k).filter(|s| !s.is_empty()).is_none() {
            missing.push(k);
        }
    }
    if !missing.is_empty() {
        return Err(ConfigError::Missing(missing.join(", ")));
    }

    let mock_mode = get_map(map, "GOAT_ATTESTOR_MOCK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let chain_id = parse_u64(map, "CHAIN_ID", 0)?;
    // Lab default: full auto settle on anvil; production must opt in explicitly.
    let auto_settle = parse_bool_default(map, "AUTO_SETTLE", chain_id == 31337 || mock_mode);
    let auto_warp = parse_bool_default(map, "AUTO_WARP", chain_id == 31337 || mock_mode);

    let (gas_drip_cfg, gas_drip_enabled) = build_drip_config(map)?;

    let state_dir_str = get_map(map, "STATE_DIR")
        .filter(|s| !s.is_empty())
        .unwrap_or("./state")
        .to_string();
    let stream_g = build_stream_g_config(map, &state_dir_str, chain_id)?;

    Ok(Config {
        rpc_url: require(map, "RPC_URL")?,
        chain_id,
        epoch_settlement_address: require(map, "EPOCH_SETTLEMENT_ADDRESS")?,
        worker_binding_address: require(map, "WORKER_BINDING_ADDRESS")?,
        enrollment_registry_address: require(map, "ENROLLMENT_REGISTRY_ADDRESS")?,
        registry_json: PathBuf::from(require(map, "REGISTRY_JSON")?),
        fah_stats_base: get_map(map, "FAH_STATS_BASE")
            .filter(|s| !s.is_empty())
            .unwrap_or("https://api.foldingathome.org")
            .to_string(),
        team: get_map(map, "TEAM")
            .filter(|s| !s.is_empty())
            .unwrap_or("1068318")
            .to_string(),
        poll_interval_s: parse_u64(map, "POLL_INTERVAL_S", 600)?,
        min_fah_interval_ms: parse_u64(map, "MIN_FAH_INTERVAL_MS", 1000)?,
        // Match DeployEpochSettlement default 0.01 ether unless overridden.
        proposer_bond_wei: parse_u128(map, "PROPOSER_BOND_WEI", 10_000_000_000_000_000)?,
        challenger_bond_wei: parse_u128(map, "CHALLENGER_BOND_WEI", 10_000_000_000_000_000)?,
        state_dir: PathBuf::from(&state_dir_str),
        evidence_dir: PathBuf::from(
            get_map(map, "EVIDENCE_DIR")
                .filter(|s| !s.is_empty())
                .unwrap_or("./evidence"),
        ),
        relayer_bind: get_map(map, "RELAYER_BIND")
            .filter(|s| !s.is_empty())
            .unwrap_or("127.0.0.1:8787")
            .to_string(),
        confirmation_depth: parse_u64(map, "CONFIRMATION_DEPTH", 1)?,
        mock_mode,
        proposer_private_key: optional_key(map, "PROPOSER_PRIVATE_KEY"),
        watcher_private_key: optional_key(map, "WATCHER_PRIVATE_KEY"),
        challenger_private_key: optional_key(map, "CHALLENGER_PRIVATE_KEY"),
        relayer_private_key: optional_key(map, "RELAYER_PRIVATE_KEY"),
        auto_settle,
        auto_warp,
        goat_coin_address: optional_key(map, "GOAT_COIN_ADDRESS"),
        gas_drip_cfg,
        gas_drip_enabled,
        worker_binding_deploy_block: parse_u64(map, "WORKER_BINDING_DEPLOY_BLOCK", 0)?,
        // Clamp 0 → default so a typo does not create an infinite loop of 0-width pages.
        eth_get_logs_chunk: {
            let c = parse_u64(map, "ETH_GETLOGS_CHUNK", 2_000)?;
            if c == 0 {
                2_000
            } else {
                c
            }
        },
        stream_g,
    })
}

fn parse_bool_default(map: &HashMap<String, String>, key: &str, default: bool) -> bool {
    match get_map(map, key) {
        None | Some("") => default,
        Some(s) => {
            s == "1"
                || s.eq_ignore_ascii_case("true")
                || s.eq_ignore_ascii_case("yes")
                || s.eq_ignore_ascii_case("on")
        }
    }
}

/// Load config from process environment.
pub fn load_from_env() -> Result<Config, ConfigError> {
    let mut map = HashMap::new();
    for (k, v) in env::vars() {
        map.insert(k, v);
    }
    load_from_map(&map)
}

impl Config {
    /// Convenience: build a HashMap of defaults suitable for unit tests.
    pub fn test_map() -> HashMap<String, String> {
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
        m.insert("GOAT_ATTESTOR_MOCK".into(), "1".into());
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gb1_log_scan_defaults() {
        let c = load_from_map(&Config::test_map()).unwrap();
        assert_eq!(c.worker_binding_deploy_block, 0, "anvil-safe default");
        assert_eq!(c.eth_get_logs_chunk, 2_000);
    }

    #[test]
    fn gb1_log_scan_reads_env_and_clamps_zero_chunk() {
        let mut m = Config::test_map();
        m.insert("WORKER_BINDING_DEPLOY_BLOCK".into(), "43964153".into());
        m.insert("ETH_GETLOGS_CHUNK".into(), "0".into());
        let c = load_from_map(&m).unwrap();
        assert_eq!(c.worker_binding_deploy_block, 43_964_153);
        assert_eq!(c.eth_get_logs_chunk, 2_000, "0 chunk must not survive");
        m.insert("ETH_GETLOGS_CHUNK".into(), "5000".into());
        let c2 = load_from_map(&m).unwrap();
        assert_eq!(c2.eth_get_logs_chunk, 5_000);
    }

    #[test]
    fn loads_complete_map() {
        let c = load_from_map(&Config::test_map()).unwrap();
        assert_eq!(c.chain_id, 31337);
        assert_eq!(c.team, "1068318");
        assert!(c.mock_mode);
        assert_eq!(c.poll_interval_s, 600);
        assert!(c.proposer_private_key.is_none());
    }

    #[test]
    fn loads_role_private_keys() {
        let mut m = Config::test_map();
        m.insert(
            "PROPOSER_PRIVATE_KEY".into(),
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        );
        m.insert(
            "RELAYER_PRIVATE_KEY".into(),
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".into(),
        );
        let c = load_from_map(&m).unwrap();
        assert!(c
            .proposer_private_key
            .as_ref()
            .unwrap()
            .starts_with("0xac09"));
        assert!(c.relayer_private_key.is_some());
        assert!(c.watcher_private_key.is_none());
    }

    #[test]
    fn missing_required_listed() {
        let mut m = Config::test_map();
        m.remove("RPC_URL");
        m.remove("CHAIN_ID");
        let err = load_from_map(&m).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("RPC_URL"), "{s}");
        assert!(s.contains("CHAIN_ID"), "{s}");
    }

    // --- Gas-drip env validation (GD task 8) ---

    #[test]
    fn gas_drip_defaults_when_unset() {
        let c = load_from_map(&Config::test_map()).unwrap();
        assert!(c.gas_drip_enabled);
        assert_eq!(c.gas_drip_cfg.approve_gas, 68_000);
        assert_eq!(c.gas_drip_cfg.sell_gas, 170_000);
        assert_eq!(c.gas_drip_cfg.buffer_num, 3);
        assert_eq!(c.gas_drip_cfg.buffer_den, 2);
        assert_eq!(c.gas_drip_cfg.max_wei, 20_000_000_000_000_000);
        assert_eq!(c.gas_drip_cfg.daily_cap, DEFAULT_DAILY_CAP);
        assert!(c.goat_coin_address.is_none());
    }

    #[test]
    fn gas_drip_reads_configured_knobs() {
        let mut m = Config::test_map();
        m.insert(
            "GOAT_COIN_ADDRESS".into(),
            "0x00000000000000000000000000000000000000C0".into(),
        );
        m.insert("GAS_DRIP_MAX_WEI".into(), "5000000000000000".into());
        m.insert("GAS_DRIP_BUFFER_NUM".into(), "4".into());
        m.insert("GAS_DRIP_BUFFER_DEN".into(), "3".into());
        m.insert("GAS_DRIP_DAILY_CAP".into(), "5".into());
        m.insert("GAS_DRIP_APPROVE_GAS".into(), "70000".into());
        m.insert("GAS_DRIP_SELL_GAS".into(), "130000".into());
        let c = load_from_map(&m).unwrap();
        assert!(c.gas_drip_enabled);
        assert_eq!(c.gas_drip_cfg.max_wei, 5_000_000_000_000_000);
        assert_eq!(c.gas_drip_cfg.buffer_num, 4);
        assert_eq!(c.gas_drip_cfg.buffer_den, 3);
        assert_eq!(c.gas_drip_cfg.daily_cap, 5);
        assert_eq!(c.gas_drip_cfg.approve_gas, 70_000);
        assert_eq!(c.gas_drip_cfg.sell_gas, 130_000);
        assert!(c.goat_coin_address.is_some());
    }

    /// `buffer_den=0` would panic `compute_drip_wei`'s division — must fall
    /// back to the default (2), not propagate the zero.
    #[test]
    fn gas_drip_buffer_den_zero_falls_back_to_default() {
        let mut m = Config::test_map();
        m.insert("GAS_DRIP_BUFFER_DEN".into(), "0".into());
        let c = load_from_map(&m).unwrap();
        assert_eq!(
            c.gas_drip_cfg.buffer_den, 2,
            "zero buffer_den must not survive into DripConfig"
        );
    }

    /// Absurd approve/sell gas must clamp to the ceiling, not overflow later
    /// arithmetic in `compute_drip_wei`.
    #[test]
    fn gas_drip_absurd_gas_knobs_clamped() {
        let mut m = Config::test_map();
        m.insert("GAS_DRIP_APPROVE_GAS".into(), "18446744073709551615".into()); // u64::MAX
        m.insert("GAS_DRIP_SELL_GAS".into(), "9999999999".into());
        let c = load_from_map(&m).unwrap();
        assert_eq!(c.gas_drip_cfg.approve_gas, GAS_KNOB_CEILING);
        assert_eq!(c.gas_drip_cfg.sell_gas, GAS_KNOB_CEILING);
    }

    /// `GAS_DRIP_DAILY_CAP=0` must disable the endpoint (not embed a
    /// `daily_cap: 0` that would 429 every single request confusingly).
    #[test]
    fn gas_drip_daily_cap_zero_disables_endpoint() {
        let mut m = Config::test_map();
        m.insert("GAS_DRIP_DAILY_CAP".into(), "0".into());
        let c = load_from_map(&m).unwrap();
        assert!(!c.gas_drip_enabled);
        assert_eq!(
            c.gas_drip_cfg.daily_cap, DEFAULT_DAILY_CAP,
            "disabled config must still carry a sane (non-zero) daily_cap, in case a caller wires it up anyway"
        );
    }

    /// A non-numeric knob is a syntactic config error, same as every other
    /// numeric env var in this module — it must not silently fall back.
    #[test]
    fn gas_drip_non_numeric_knob_is_config_error() {
        let mut m = Config::test_map();
        m.insert("GAS_DRIP_MAX_WEI".into(), "not-a-number".into());
        let err = load_from_map(&m).unwrap_err();
        assert!(err.to_string().contains("GAS_DRIP_MAX_WEI"), "{err}");
    }

    // --- Stream G (TARGET/post-pilot; disabled by default) ---

    #[test]
    fn stream_g_disabled_by_default() {
        let map = Config::test_map();
        let cfg = load_from_map(&map).expect("config");
        assert!(!cfg.stream_g.enabled);
    }

    /// The two document paths carry **provenance**, not just a value.
    ///
    /// `stream_g::runtime::read_startup_document` substitutes a built-in copy
    /// for a missing file under [`PathSource::Default`] and never under
    /// [`PathSource::Env`], so a load that reported only the resolved
    /// `PathBuf` would make the two cases indistinguishable — and silently
    /// falling back for an operator who mistyped their own path is a security
    /// failure, not a convenience.
    ///
    /// The empty-string arm matters as much as the unset one: every other
    /// getter in this module treats `""` as unset (`get_map(..).filter(|s|
    /// !s.is_empty())`), so `STREAM_G_FEE_SCHEDULE_PATH=` in a `.env` must
    /// resolve to the default *and say so*, not to `Env` with an empty path.
    ///
    /// **Mutation this detects (applied, run, reverted):** returning
    /// `PathSource::Env` unconditionally from `path_with_default` — the two
    /// default arms fail.
    #[test]
    fn stream_g_document_paths_record_whether_the_operator_chose_them() {
        let cfg = load_from_map(&Config::test_map()).expect("config");
        assert_eq!(cfg.stream_g.fee_schedule_path_source, PathSource::Default);
        assert_eq!(
            cfg.stream_g.deployment_manifest_path_source,
            PathSource::Default
        );
        assert_eq!(
            cfg.stream_g.fee_schedule_path,
            PathBuf::from("./state/stream_g_fee_schedule.json"),
            "the default still nests under STATE_DIR"
        );

        let mut m = Config::test_map();
        m.insert(
            "STREAM_G_FEE_SCHEDULE_PATH".into(),
            "/tmp/sched.json".into(),
        );
        // Empty is unset everywhere else in this module, and must be here too.
        m.insert("STREAM_G_DEPLOYMENT_MANIFEST_PATH".into(), "".into());
        let cfg = load_from_map(&m).expect("config");
        assert_eq!(cfg.stream_g.fee_schedule_path_source, PathSource::Env);
        assert_eq!(
            cfg.stream_g.fee_schedule_path,
            PathBuf::from("/tmp/sched.json")
        );
        assert_eq!(
            cfg.stream_g.deployment_manifest_path_source,
            PathSource::Default,
            "an empty value is unset, not a chosen empty path"
        );
    }

    #[test]
    fn stream_g_enabled_requires_dedicated_keys() {
        let mut m = Config::test_map();
        m.insert("STREAM_G_ENABLED".into(), "1".into());
        let err = load_from_map(&m).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("STREAM_G_BROADCASTER_PRIVATE_KEY"), "{s}");
        assert!(s.contains("STREAM_G_QUOTE_SIGNER_PRIVATE_KEY"), "{s}");
        assert!(s.contains("STREAM_G_ISSUER_PRIVATE_KEY"), "{s}");
        assert!(s.contains("STREAM_G_DATA_KEY_HEX"), "{s}");
    }

    #[test]
    fn stream_g_rejects_relayer_key_reuse() {
        let mut m = Config::test_map();
        let shared_key =
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".to_string();
        m.insert("RELAYER_PRIVATE_KEY".into(), shared_key.clone());
        m.insert("STREAM_G_ENABLED".into(), "1".into());
        m.insert(
            "STREAM_G_BROADCASTER_PRIVATE_KEY".into(),
            shared_key.clone(),
        );
        m.insert(
            "STREAM_G_QUOTE_SIGNER_PRIVATE_KEY".into(),
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        );
        m.insert(
            "STREAM_G_ISSUER_PRIVATE_KEY".into(),
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        );
        m.insert(
            "STREAM_G_DATA_KEY_HEX".into(),
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddee".into(),
        );
        let err = load_from_map(&m).unwrap_err();
        assert!(
            err.to_string().contains("STREAM_G_BROADCASTER_PRIVATE_KEY"),
            "{err}"
        );

        // Sanity: same map with a distinct broadcaster key must pass.
        m.insert(
            "STREAM_G_BROADCASTER_PRIVATE_KEY".into(),
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690e".into(),
        );
        let cfg = load_from_map(&m).expect("distinct dedicated key must validate");
        assert!(cfg.stream_g.enabled);
    }

    /// Task 7 Wave A: the gateway log-scan pin.
    ///
    /// Mutation this detects: giving `STREAM_G_GATEWAY_DEPLOY_BLOCK` a
    /// non-zero default (e.g. copying `eth_get_logs_chunk`'s `2_000`).
    /// Verified — the "unset" arm then reports 2000, and a non-zero default
    /// would silently satisfy `sponsored_enrollment_logs`' G-B1 refusal on a
    /// live chain while pointing the scan at an arbitrary block.
    #[test]
    fn stream_g_gateway_deploy_block_defaults_to_zero_and_parses() {
        let mut m = Config::test_map();
        let c = load_from_map(&m).unwrap();
        assert_eq!(
            c.stream_g.gateway_deploy_block, 0,
            "unset must stay 0 so the non-anvil refusal can fire"
        );

        // Paired non-zero arm: an explicit pin is read through.
        m.insert("STREAM_G_GATEWAY_DEPLOY_BLOCK".into(), "43964153".into());
        let c = load_from_map(&m).unwrap();
        assert_eq!(c.stream_g.gateway_deploy_block, 43_964_153);
    }

    /// Ratified decision A3's finality depth: the parse and the per-chain
    /// default.
    ///
    /// This doc used to end "and *only* threaded. Nothing consumes
    /// `stream_g.confirmations`". Since Task 11 Wave D it is consumed — by
    /// `stream_g::maintenance::MaintenancePolicy::from_config`, which carries it
    /// into the background reconciliation pass. This test still covers only the
    /// parse; the behaviour it now feeds is covered by
    /// `maintenance::tests::a_log_below_the_confirmation_depth_is_not_folded`.
    ///
    /// Mutation this detects: making A3's default a constant instead of a
    /// function of the configured chain id — e.g. passing
    /// `reconcile::ANVIL_CHAIN_ID` to `FinalityPolicy::from_map` instead of
    /// `chain_id`, or substituting `parse_u64(map, ENV_CONFIRMATIONS, 1)`.
    /// Verified: the 84532 arm then reports 1 instead of 12, i.e. a
    /// reorg-capable deployment silently inherits anvil's no-reorg assumption.
    #[test]
    fn stream_g_confirmations_a3_default_differs_by_chain_id() {
        assert_ne!(
            reconcile::ANVIL_CONFIRMATIONS,
            reconcile::DEFAULT_CONFIRMATIONS,
            "the two arms below only prove anything while these differ"
        );

        let mut m = Config::test_map();
        assert_eq!(
            m.get("CHAIN_ID").map(String::as_str),
            Some("31337"),
            "this test reads the anvil default off the shared test map"
        );
        let c = load_from_map(&m).unwrap();
        assert_eq!(
            c.stream_g.confirmations,
            reconcile::ANVIL_CONFIRMATIONS,
            "A3: anvil mines on demand and does not reorg"
        );

        m.insert("CHAIN_ID".into(), "84532".into());
        let c = load_from_map(&m).unwrap();
        assert_eq!(
            c.stream_g.confirmations,
            reconcile::DEFAULT_CONFIRMATIONS,
            "A3: a reorg-capable chain must not inherit anvil's depth"
        );

        // An explicit override beats the chain-id default on either chain.
        m.insert(reconcile::ENV_CONFIRMATIONS.into(), "3".into());
        assert_eq!(load_from_map(&m).unwrap().stream_g.confirmations, 3);
        m.insert("CHAIN_ID".into(), "31337".into());
        assert_eq!(load_from_map(&m).unwrap().stream_g.confirmations, 3);
    }

    /// `STREAM_G_CONFIRMATIONS=0` must FAIL the load. It is the one
    /// out-of-range numeric here that is refused rather than clamped, because
    /// 0 confirmations makes every reorg check in `reconcile` a no-op.
    ///
    /// Mutation this detects: replacing the `FinalityPolicy::from_map` call in
    /// `build_stream_g_config` with a clamping parser, e.g.
    /// `parse_u64(map, ENV_CONFIRMATIONS, for_chain(chain_id).confirmations())?
    /// .max(1)`. Verified: `load_from_map` then returns `Ok` with
    /// `confirmations == 1` and the documented refusal — which lives in
    /// `reconcile.rs` and has its own test there — is deleted from the only
    /// path an operator can actually reach it by.
    #[test]
    fn stream_g_confirmations_zero_is_rejected_not_clamped() {
        let mut m = Config::test_map();
        m.insert(reconcile::ENV_CONFIRMATIONS.into(), "0".into());
        let err = load_from_map(&m).unwrap_err();
        let s = err.to_string();
        assert!(s.contains(reconcile::ENV_CONFIRMATIONS), "{s}");
        assert!(
            s.contains("minimum is 1"),
            "the refusal must reach the operator, not just fail: {s}"
        );

        // Refusal is unconditional, like every other STREAM_G_* numeric:
        // Stream G being OFF (it is, on the bare test map) does not excuse it.
        assert!(
            !load_from_map(&Config::test_map()).unwrap().stream_g.enabled,
            "precondition: the bare test map has Stream G disabled"
        );

        // A syntactically bad value is refused too.
        m.insert(reconcile::ENV_CONFIRMATIONS.into(), "twelve".into());
        assert!(load_from_map(&m).is_err());

        // 1 is the loosest ACCEPTED value — the boundary, not a clamp target.
        m.insert(reconcile::ENV_CONFIRMATIONS.into(), "1".into());
        assert_eq!(load_from_map(&m).unwrap().stream_g.confirmations, 1);

        // Contrast with the sweep knob that sits directly below this one in
        // `.env.example`: that one really does clamp 0 away rather than refuse.
        let mut clamped = Config::test_map();
        clamped.insert("STREAM_G_SWEEP_MAX_ROWS".into(), "0".into());
        let c = load_from_map(&clamped).expect("sweep knobs clamp; they do not refuse");
        assert_eq!(
            c.stream_g.sweep_max_rows,
            maintenance::MIN_SWEEP_MAX_ROWS as i64,
            "the contrast this test asserts only holds while sweep knobs clamp"
        );
    }

    // -- Wave C W1c: broadcast gas policy --------------------------------

    /// Unset means the **named** starting values, and no number is duplicated
    /// into this module.
    ///
    /// The equality against
    /// `BroadcastGasPolicy::starting_values_pending_founder_review()` is the
    /// point: it holds only while `build_broadcast_gas_policy` reads its
    /// defaults off that constructor. If someone writes `500_000` (or any
    /// other figure) as a literal here, the constructor's own doc — the single
    /// place stating what evidence exists for each of the three — stops being
    /// the authority, and a founder review would have two places to update.
    ///
    /// The values are asserted individually too, so this cannot pass by both
    /// sides drifting together.
    #[test]
    fn broadcast_gas_defaults_are_the_named_starting_values() {
        let cfg = load_from_map(&Config::test_map()).expect("config");
        let policy = cfg.stream_g.broadcast_gas;
        assert_eq!(
            policy,
            BroadcastGasPolicy::starting_values_pending_founder_review()
        );
        assert_eq!(policy.gas_limit().get(), 500_000);
        assert_eq!(policy.max_fee_per_gas().get(), 1_000_000_000);
        assert_eq!(policy.max_priority_fee_per_gas().get(), 1_000_000);
        assert!(
            !cfg.stream_g.enabled,
            "precondition: parsing is unconditional, so this holds with Stream G off"
        );
    }

    /// All three keys are read, each into its own slot.
    ///
    /// Mutation this detects: transposing `max_fee` and `priority_fee` at the
    /// parse site. The newtypes make the transposition uncompilable at
    /// `BroadcastGasPolicy::new`, but not at `parse_u128`, so the three
    /// distinct values here are what pins the key→field mapping.
    #[test]
    fn broadcast_gas_reads_all_three_keys() {
        let mut m = Config::test_map();
        m.insert(ENV_BROADCAST_GAS_LIMIT.into(), "1234567".into());
        m.insert(
            ENV_BROADCAST_MAX_FEE_PER_GAS_WEI.into(),
            "7000000000".into(),
        );
        m.insert(
            ENV_BROADCAST_MAX_PRIORITY_FEE_PER_GAS_WEI.into(),
            "3000000".into(),
        );
        let policy = load_from_map(&m).expect("config").stream_g.broadcast_gas;
        assert_eq!(policy.gas_limit().get(), 1_234_567);
        assert_eq!(policy.max_fee_per_gas().get(), 7_000_000_000);
        assert_eq!(policy.max_priority_fee_per_gas().get(), 3_000_000);
    }

    /// **REJECTED, not clamped**, and rejected **unconditionally** — the same
    /// posture as `STREAM_G_CONFIRMATIONS` and the opposite of the sweep
    /// knobs. `GasPolicyError`'s own doc asks for this: the policy is built
    /// once at wiring time, so a bad one must stop startup rather than become
    /// a per-request 5xx.
    ///
    /// Every arm runs on the bare test map, i.e. with `STREAM_G_ENABLED=0`, so
    /// this also pins that the validation does not hide behind the flag.
    #[test]
    fn a_broadcast_gas_policy_no_node_could_accept_is_refused_at_config_load() {
        assert!(
            !load_from_map(&Config::test_map()).unwrap().stream_g.enabled,
            "precondition: these are all Stream-G-disabled loads"
        );

        // Below the EVM's 21,000-gas base transaction cost.
        let mut m = Config::test_map();
        m.insert(ENV_BROADCAST_GAS_LIMIT.into(), "20999".into());
        let err = load_from_map(&m).expect_err("a sub-base-cost gas limit must refuse");
        assert!(
            matches!(&err, ConfigError::Invalid { key, .. } if key == ENV_BROADCAST_GAS_LIMIT),
            "the error must name the key an operator has to change: {err}"
        );
        // 21,000 exactly is the boundary, and it is ACCEPTED.
        m.insert(ENV_BROADCAST_GAS_LIMIT.into(), "21000".into());
        assert_eq!(
            load_from_map(&m)
                .expect("21000 is the loosest accepted value")
                .stream_g
                .broadcast_gas
                .gas_limit()
                .get(),
            21_000
        );

        // A zero max fee cannot pay for anything.
        let mut m = Config::test_map();
        m.insert(ENV_BROADCAST_MAX_FEE_PER_GAS_WEI.into(), "0".into());
        let err = load_from_map(&m).expect_err("a zero max fee must refuse");
        assert!(
            matches!(&err, ConfigError::Invalid { key, .. }
                if key == ENV_BROADCAST_MAX_FEE_PER_GAS_WEI),
            "{err}"
        );

        // EIP-1559 forbids a tip above the cap. This one is a property of the
        // PAIR — neither key is out of range on its own — which is why the
        // three are validated together rather than per key.
        let mut m = Config::test_map();
        m.insert(ENV_BROADCAST_MAX_FEE_PER_GAS_WEI.into(), "1000".into());
        m.insert(
            ENV_BROADCAST_MAX_PRIORITY_FEE_PER_GAS_WEI.into(),
            "1001".into(),
        );
        let err = load_from_map(&m).expect_err("priority above max must refuse");
        assert!(
            matches!(&err, ConfigError::Invalid { key, .. }
                if key == ENV_BROADCAST_MAX_PRIORITY_FEE_PER_GAS_WEI),
            "{err}"
        );
        // Equal is legal (a tip that consumes the whole cap), so the boundary
        // is `>` and not `>=`.
        m.insert(
            ENV_BROADCAST_MAX_PRIORITY_FEE_PER_GAS_WEI.into(),
            "1000".into(),
        );
        assert!(load_from_map(&m).is_ok(), "priority == max is legal");

        // A syntactically bad value is refused too, same as every other
        // numeric knob in this module.
        let mut m = Config::test_map();
        m.insert(ENV_BROADCAST_GAS_LIMIT.into(), "lots".into());
        assert!(load_from_map(&m).is_err());
    }
}
