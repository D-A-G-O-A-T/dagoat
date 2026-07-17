//! Runtime configuration for goat-attestor.

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

use thiserror::Error;

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

fn parse_u128(map: &HashMap<String, String>, key: &str, default: u128) -> Result<u128, ConfigError> {
    match get_map(map, key) {
        None | Some("") => Ok(default),
        Some(s) => s.parse::<u128>().map_err(|e| ConfigError::Invalid {
            key: key.to_string(),
            msg: e.to_string(),
        }),
    }
}

fn optional_key(map: &HashMap<String, String>, key: &str) -> Option<String> {
    get_map(map, key)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
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
    let auto_settle = parse_bool_default(
        map,
        "AUTO_SETTLE",
        chain_id == 31337 || mock_mode,
    );
    let auto_warp = parse_bool_default(
        map,
        "AUTO_WARP",
        chain_id == 31337 || mock_mode,
    );

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
        state_dir: PathBuf::from(
            get_map(map, "STATE_DIR")
                .filter(|s| !s.is_empty())
                .unwrap_or("./state"),
        ),
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
        assert!(c.proposer_private_key.as_ref().unwrap().starts_with("0xac09"));
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
}
