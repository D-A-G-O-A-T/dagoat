//! `goatd.rs` — the GoatCoin production daemon (Phase 7 + DevOps config & data plane).
//!
//! An asynchronous `tokio` runtime that wraps the sealed `#![no_std]`, allocation-free, panic-free
//! core (`goat_core::{daemon, transport, gossip, state, crypto, types}`) in a UDP event loop. The
//! core's consensus pipelines (`fold`, `agree`, `validate_gossip_message`, cookie verification) are
//! **synchronous and total**; this binary is the *only* place `std`, `alloc`, and async live, and it
//! is engineered so the async boundary can never corrupt a consensus state transition.
//!
//! ## Async safety guardrails (external-review ARC follow-up)
//!
//! 1. **Bounded, decoupled ingress *and* egress.** A socket-reader task feeds a *bounded* ingress
//!    `mpsc`; a full queue drops the datagram at the socket layer (`try_send`) — backpressure, not
//!    amplification. Symmetrically, a detached egress-sender task ([`spawn_egress`]) is the *sole*
//!    owner of outbound `send_to`, fed by a *bounded* egress `mpsc` that the consensus loop
//!    `try_send`s into and **never awaits**. So awaiting up to `MAX_SESSIONS` sends can never
//!    head-of-line-block the actor and shed *inbound consensus* traffic; both queues shed *outbound*
//!    frames first and prioritize inbound consensus.
//! 2. **Cancellation-safe consensus.** A single consensus actor owns *all* mutable state and processes
//!    each packet **fully synchronously** — no `.await`/lock across a state transition.
//! 3. **Session garbage collection.** Idle per-peer sessions are swept on a GC-only tick; the session
//!    map is additionally LRU-bounded so a spoofed-address burst cannot bloat it between sweeps.
//! 4. **Deterministic, message-driven time.** The [`goat_core::transport::NetworkClock`] advances only
//!    on the *signed* timestamps of authenticated peers; no timer feeds consensus timekeeping.
//!
//! ## Config plane (operational)
//!
//! * **CLI** (`--listen`, `--bootstrap-peer`, `--seed`, `--genesis`, `--node-index`) — a lean
//!   `std::env::args` parser; accepts `--flag value` and `--flag=value` (the Compose form).
//! * **`genesis.json` loader** (`serde` / `serde_json`) — anchors the `NetworkClock` floor to
//!   `genesis_time_unix` and populates the [`KeyRegistry`] from the authorized-orchestrator set. A
//!   missing/invalid file is non-fatal (accept-all + compiled floor fallback).
//! * **Outbound bootstrap** — `--bootstrap-peer` transmits a [`HandshakeInitiation`] after binding and
//!   completes RECON-11 as the initiator.
//!
//! ## Data plane (this milestone — the mesh actually talks)
//!
//! * **ML-DSA-65 signer** ([`HostMlDsaSigner`]) — real FIPS-204 signing of context-bound preimages
//!   (cookie-echo initiation, capability records). Seed from `GOATD_SIGNING_SEED` or the deterministic
//!   testnet seed for `--node-index`.
//! * **Canonical gossip codec** ([`CanonicalGossipCodec`]) — the real wire *de*serializer.
//! * **Active exchange.** After RECON-11 cookie proof, the responder **ML-KEM-768-encapsulates** to
//!   the initiator's ephemeral key, emits a signed [`HandshakeResponse`], then gossips a signed
//!   `CapabilityRecord` under AES-256-GCM. Session keys come from the KEM shared secret + SHA3-256 KDF.
//! * **Epidemic re-broadcast** of novel, signature-valid, origin-authorized frames (RECON-11).
//!
//! ## Track C crypto (DEPLOY.md backend swap)
//!
//! Host backends live in [`host_crypto`]: real ML-DSA-65, ML-KEM-768, AES-256-GCM — same crates as the
//! `goatcoin-rs` C3 oracle, wrapped behind the frozen core traits (C-1).

#![forbid(unsafe_code)]

mod datagram_framing;
mod host_crypto;
mod isolation;

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use goat_core::crypto::{
    ByteSink, CanonicalSerialize, KeyRegistry, SliceSink, ACTIVE_CHAIN_ID,
    CAPABILITY_RECORD_MAX_BODY_LEN, CAPABILITY_RECORD_MAX_PREIMAGE_LEN,
};
use goat_core::daemon::{packet_tag, GoatNode, GossipCodec, IngressOutcome};
use goat_core::gossip::GossipMessage;
use goat_core::transport::{
    CookieChallenge, HandshakeInitiation, HandshakeResponse, SecureChannel, AES_256_GCM_TAG_LEN,
    HANDSHAKE_INITIATION_BODY_LEN, HANDSHAKE_INITIATION_MAX_PREIMAGE_LEN,
    HANDSHAKE_RESPONSE_BODY_LEN, HANDSHAKE_RESPONSE_MAX_PREIMAGE_LEN, ML_KEM_768_CIPHERTEXT_LEN,
    ML_KEM_768_ENCAPS_KEY_LEN, PEER_ADDR_LEN,
};
use goat_core::types::{
    BoundedVec, CapabilityRecord, ChainId, DeviceCapability, FrameHeader, NetworkDensityFrame,
    OpaqueTag, PowerThermalEnvelope, SignedRecord, CHAIN_ID_GOAT_MAINNET, MAX_CAPABILITIES,
    ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN, OPAQUE_TAG_CAP, PPM,
};

use datagram_framing::{
    expand_egress_batch, fragment_datagram, is_chunk, ReassemblyTable, MAX_UDP_DATAGRAM,
};
use host_crypto::{
    derive_session_key, generate_ephemeral_kem, kem_decapsulate, kem_encapsulate,
    testnet_signing_seed, Aes256GcmChannel, ChannelRole, EphemeralKem, HostMlDsaSigner,
    HostMlDsaVerifier,
};

// ===========================================================================
// Tunables
// ===========================================================================

/// Default bind address for the UDP transport (overridable via `--listen`).
const BIND_ADDR: &str = "0.0.0.0:4646";
/// Default genesis path (overridable via `--genesis` or `GOATD_GENESIS`); matches the Compose mount.
const DEFAULT_GENESIS_PATH: &str = "/etc/goatd/genesis.json";
/// Max UDP datagram we will read (bounds per-packet allocation).
const MAX_DATAGRAM: usize = 65_535;
/// Bounded ingress queue depth (guardrail 1). A full queue ⇒ drop at the socket layer.
const INGRESS_QUEUE_CAP: usize = 1024;
/// Bounded egress queue depth (guardrail 1). Sized to hold one full fan-out batch (≈ `MAX_SESSIONS`)
/// so a single broadcast never sheds; sustained overload beyond this drops outbound frames — safe for
/// a redundant gossip mesh — rather than stalling the consensus actor.
const EGRESS_QUEUE_CAP: usize = 8192;
/// Gossip epidemic-dedup window (`MessageCache<M>`).
const MESSAGE_CACHE: usize = 4096;
/// Single-use cookie window (`CookieCache<C>`).
const COOKIE_CACHE: usize = 4096;
/// A session with no authenticated traffic for this long is swept (guardrail 3).
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// How often the GC tick fires. GC only — never consensus timekeeping (guardrail 4).
const GC_INTERVAL: Duration = Duration::from_secs(30);
/// The active network (RECON-15) is the single source `goat_core::crypto::ACTIVE_CHAIN_ID` — a
/// build-time selection (default testnet; `--features mainnet`). `goatd` refuses to boot if the
/// loaded genesis declares a different chain (P4). There is no daemon-local chain-id constant.
///
/// Fallback genesis Unix timestamp — anchors the `NetworkClock` floor (ARC-01-M6) in **dev accept-all**
/// mode only, where no genesis is loaded. A real genesis always overrides it with `genesis_time_unix`.
const FALLBACK_GENESIS_TIME_UNIX: u64 = 1_751_846_400;

/// Hard cap on concurrently-tracked sessions (operational memory bound), enforced by synchronous LRU
/// eviction so the footprint is bounded at all times, not just after a GC sweep.
const MAX_SESSIONS: usize = 8192;

/// Warn if more than this many datagrams are shed in one GC interval (sustained flood visibility).
const DROPPED_WARNING_THRESHOLD: u64 = 500;

/// Egress wire tag for a cookie-challenge reply (daemon-local framing; distinct from ingress tags).
const REPLY_TAG_COOKIE_CHALLENGE: u8 = 0x81;

/// Gossip-frame variant tags (daemon-local wire framing for the `SecureChannel` payload).
const GOSSIP_VARIANT_NODE_CAPABILITY: u8 = 0x01;
const GOSSIP_VARIANT_TELEMETRY: u8 = 0x02;

/// Max serialized gossip frame: `variant(1) ‖ payload_body ‖ public_key ‖ signature`. The
/// `CapabilityRecord` body (`≤740` B) dominates the telemetry body, so it is the ceiling.
const GOSSIP_FRAME_MAX_LEN: usize =
    1 + CAPABILITY_RECORD_MAX_BODY_LEN + ML_DSA_65_PUBLIC_KEY_LEN + ML_DSA_65_SIGNATURE_LEN;

/// Best-effort outbound-bootstrap attempts (tolerates the seed still starting + UDP loss).
const BOOTSTRAP_ATTEMPTS: u32 = 10;
/// Delay between bootstrap attempts.
const BOOTSTRAP_RETRY_DELAY: Duration = Duration::from_secs(2);

// ===========================================================================
// CLI configuration (lean std::env::args parser)
// ===========================================================================

/// Parsed command-line configuration. Every field is optional at parse time; `main` resolves each
/// against its environment-variable fallback and compiled default. The parser is pure (no env, no
/// I/O) so it is deterministically testable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Config {
    listen: Option<String>,
    bootstrap_peer: Option<String>,
    seed: bool,
    genesis_path: Option<String>,
    node_index: Option<usize>,
    /// `--throttle-target <FRACTION>` — the Alpha-Pilot CPU-quota fraction (matching `GOATD_CPU_LIMIT`,
    /// e.g. `0.5`). **Advisory only**: the daemon logs it as a percentage and does NOT self-throttle;
    /// the real limit is OS-level (docker cgroups). Stored raw so `Config` stays `Eq`.
    throttle_target: Option<String>,
    /// `--dev-accept-all-registry` (P3) — the ONLY way to run without a valid genesis: an
    /// explicitly-opted-in, loudly-announced INSECURE mode that accepts unauthenticated gossip
    /// origins. Refused on non-loopback binds, under `GOATD_ENV=production`, and on mainnet.
    dev_accept_all: bool,
    /// `--node-secret-file <PATH>` (P3) — file holding the node's 64-hex cookie secret. Overrides the
    /// `GOATD_NODE_SECRET_FILE` env and the default mount path.
    node_secret_file: Option<String>,
}

/// Parse `args` (already excluding argv[0]) into a [`Config`]. Accepts both `--flag value` and
/// `--flag=value`; unrecognized arguments are logged and ignored. Pure: no env reads, no I/O.
fn parse_args<I: Iterator<Item = String>>(args: I) -> Config {
    let mut cfg = Config::default();
    let mut it = args;
    while let Some(arg) = it.next() {
        let (key, inline) = match arg.split_once('=') {
            Some((k, v)) => (k.to_string(), Some(v.to_string())),
            None => (arg.clone(), None),
        };
        match key.as_str() {
            "--listen" => cfg.listen = inline.or_else(|| it.next()),
            "--bootstrap-peer" => cfg.bootstrap_peer = inline.or_else(|| it.next()),
            "--genesis" => cfg.genesis_path = inline.or_else(|| it.next()),
            "--node-index" => {
                cfg.node_index = inline.or_else(|| it.next()).and_then(|v| v.parse().ok())
            }
            "--throttle-target" => cfg.throttle_target = inline.or_else(|| it.next()),
            "--node-secret-file" => cfg.node_secret_file = inline.or_else(|| it.next()),
            "--dev-accept-all-registry" => cfg.dev_accept_all = true,
            "--seed" => cfg.seed = true,
            other => eprintln!("goatd: ignoring unrecognized argument '{other}'"),
        }
    }
    cfg
}

// ===========================================================================
// genesis.json loader (serde/serde_json)
// ===========================================================================

/// The subset of `genesis.json` the daemon consumes; `serde` ignores every other field.
#[derive(Deserialize)]
struct RawGenesis {
    network: RawNetwork,
    key_registry: RawKeyRegistry,
}

#[derive(Deserialize)]
struct RawNetwork {
    genesis_time_unix: u64,
    /// Numeric wire chain id (P4). Present in real genesis so the string `chain_id` name cannot drift
    /// from the wire domain; `goatd` validates it against the compiled `ACTIVE_CHAIN_ID`. Optional at
    /// the parse layer so inline test fixtures stay terse; **required** by `main` outside dev mode.
    #[serde(default)]
    chain_id_u32: Option<u32>,
}

#[derive(Deserialize)]
struct RawKeyRegistry {
    genesis_orchestrators: Vec<RawOrchestrator>,
}

#[derive(Deserialize)]
struct RawOrchestrator {
    node_id: String,
    ml_dsa_65_public_key: String,
}

/// The daemon's resolved view of genesis: the `NetworkClock` floor and the authorized
/// `(node_id → ML-DSA-65 public key)` orchestrator set.
struct GenesisConfig {
    genesis_time_unix: u64,
    /// The numeric wire chain id declared by genesis, if present (P4). `main` requires it outside dev
    /// and refuses to boot unless it equals the compiled `ACTIVE_CHAIN_ID`.
    chain_id: Option<ChainId>,
    orchestrators: Vec<([u8; 32], [u8; ML_DSA_65_PUBLIC_KEY_LEN])>,
}

/// A genesis-loading failure. Total; surfaced (never panicked) so `main` can decide fail-closed.
#[derive(Debug, PartialEq, Eq)]
enum GenesisError {
    Io,
    Parse,
    BadNodeId(usize),
    /// Public key was not valid hex, or (in strict mode) not exactly 1952 bytes.
    BadPublicKey(usize),
}

impl fmt::Display for GenesisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenesisError::Io => write!(f, "unreadable file"),
            GenesisError::Parse => write!(f, "invalid JSON / schema"),
            GenesisError::BadNodeId(i) => write!(f, "orchestrator[{i}]: node_id not 32-byte hex"),
            GenesisError::BadPublicKey(i) => write!(
                f,
                "orchestrator[{i}]: ml_dsa_65_public_key not a valid ML-DSA-65 key \
                 (strict mode requires exactly 1952 bytes of hex)"
            ),
        }
    }
}

/// Decode a lowercase/uppercase hex string into bytes, or `None` on odd length / non-hex.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|c| Some((hex_val(c[0])? << 4) | hex_val(c[1])?))
        .collect()
}

/// One hex nibble → value, or `None`.
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parse a 32-byte node id from hex (exact length required).
fn parse_node_id_hex(s: &str) -> Option<[u8; 32]> {
    decode_hex(s)?.try_into().ok()
}

/// Parse an ML-DSA-65 public key from hex (P3 key-length discipline).
///
/// * `strict = true` (default / non-dev): the decoded key must be **exactly** 1952 bytes. No silent
///   zero-extension — a short dummy key is rejected so a public bind cannot run on truncated keys.
/// * `strict = false` (dev only): a `≤ 1952`-byte key is zero-extended, so short hex is tolerated for
///   local experimentation. Callers gate this behind `--dev-accept-all-registry`.
fn parse_pubkey_hex(s: &str, strict: bool) -> Option<[u8; ML_DSA_65_PUBLIC_KEY_LEN]> {
    let bytes = decode_hex(s)?;
    if strict {
        if bytes.len() != ML_DSA_65_PUBLIC_KEY_LEN {
            return None;
        }
    } else if bytes.len() > ML_DSA_65_PUBLIC_KEY_LEN {
        return None;
    }
    let mut pk = [0u8; ML_DSA_65_PUBLIC_KEY_LEN];
    pk[..bytes.len()].copy_from_slice(&bytes);
    Some(pk)
}

/// Parse a genesis document from its JSON text (filesystem-free, so it is unit-testable). `strict`
/// enforces exact 1952-byte keys (see [`parse_pubkey_hex`]).
fn parse_genesis_str(text: &str, strict: bool) -> Result<GenesisConfig, GenesisError> {
    let raw: RawGenesis = serde_json::from_str(text).map_err(|_| GenesisError::Parse)?;
    let mut orchestrators = Vec::with_capacity(raw.key_registry.genesis_orchestrators.len());
    for (i, o) in raw.key_registry.genesis_orchestrators.iter().enumerate() {
        let node_id = parse_node_id_hex(&o.node_id).ok_or(GenesisError::BadNodeId(i))?;
        let pk = parse_pubkey_hex(&o.ml_dsa_65_public_key, strict)
            .ok_or(GenesisError::BadPublicKey(i))?;
        orchestrators.push((node_id, pk));
    }
    Ok(GenesisConfig {
        genesis_time_unix: raw.network.genesis_time_unix,
        chain_id: raw.network.chain_id_u32,
        orchestrators,
    })
}

/// Read + parse the genesis file at `path` (`strict` ⇒ exact 1952-byte keys).
fn load_genesis(path: &str, strict: bool) -> Result<GenesisConfig, GenesisError> {
    let text = std::fs::read_to_string(path).map_err(|_| GenesisError::Io)?;
    parse_genesis_str(&text, strict)
}

// ===========================================================================
// Fail-closed startup discipline (Track A / P3 + P4)
// ===========================================================================

/// Default mount for the per-node cookie secret (P3); overridable by `--node-secret-file` or
/// `GOATD_NODE_SECRET_FILE`.
const DEFAULT_NODE_SECRET_PATH: &str = "/etc/goatd/node_secret";

/// Print a fatal misconfiguration reason and exit non-zero. Startup only (skipping destructors is
/// fine): the point is to REFUSE rather than silently run fail-open.
fn fatal(reason: impl AsRef<str>) -> ! {
    eprintln!("goatd: FATAL — {}", reason.as_ref());
    std::process::exit(1);
}

/// Whether `listen` resolves to a loopback address — the only place `--dev-accept-all-registry` is
/// permitted. An unparseable address is treated as non-loopback (fail-safe).
fn is_loopback(listen: &str) -> bool {
    listen
        .parse::<SocketAddr>()
        .map(|a| a.ip().is_loopback())
        .unwrap_or(false)
}

/// Parse a 32-byte node secret from exactly 64 hex chars.
fn parse_node_secret_hex(s: &str) -> Option<[u8; 32]> {
    decode_hex(s.trim())?.try_into().ok()
}

/// Return `Some(reason)` if `--dev-accept-all-registry` must be refused in this context, else `None`.
/// Refused off loopback, under `GOATD_ENV=production`, and on mainnet (P3).
fn dev_accept_all_refusal(listen: &str, is_production: bool, is_mainnet: bool) -> Option<String> {
    if !is_loopback(listen) {
        return Some(format!("bind address '{listen}' is not loopback"));
    }
    if is_production {
        return Some("GOATD_ENV=production".into());
    }
    if is_mainnet {
        return Some("active chain is mainnet".into());
    }
    None
}

/// Whether `GOATD_ALLOW_TESTNET_SEEDS=1` (case-insensitive) is set — the only non-loopback escape
/// for deterministic, publicly-derivable signing seeds (identity-hardening / H1).
fn allow_testnet_seeds_env() -> bool {
    std::env::var("GOATD_ALLOW_TESTNET_SEEDS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false)
}

/// Return `Some(reason)` if a **deterministic** `testnet_signing_seed` must be refused.
/// Always refused under production or mainnet (no override). Off loopback, refused unless
/// `GOATD_ALLOW_TESTNET_SEEDS=1` (identity-hardening / H1 — forgeable identities).
fn testnet_seed_refusal(
    listen: &str,
    is_production: bool,
    is_mainnet: bool,
    allow_testnet_seeds: bool,
) -> Option<String> {
    if is_production {
        return Some("GOATD_ENV=production forbids deterministic testnet signing seeds".into());
    }
    if is_mainnet {
        return Some("mainnet build forbids deterministic testnet signing seeds".into());
    }
    if !is_loopback(listen) && !allow_testnet_seeds {
        return Some(format!(
            "bind address '{listen}' is not loopback and GOATD_ALLOW_TESTNET_SEEDS is not set; \
             set GOATD_SIGNING_SEED (64 hex secret) for real per-node identity, or set \
             GOATD_ALLOW_TESTNET_SEEDS=1 only for lab use with forgeable identities"
        ));
    }
    None
}

/// Loud multi-line banner: deterministic seeds make ML-DSA node identities publicly forgeable.
fn print_forgeable_identity_banner(listen: &str, node_index: Option<usize>) {
    eprintln!("goatd: ============ FORGEABLE NODE IDENTITY (DEV/TESTNET SEEDS) ============");
    eprintln!(
        "goatd: This node is signing with a DETERMINISTIC testnet seed (node-index={idx}).",
        idx = node_index
            .map(|i| i.to_string())
            .unwrap_or_else(|| "?".into())
    );
    eprintln!(
        "goatd: Anyone who reads the committed repo can reconstruct this node's ML-DSA-65 secret"
    );
    eprintln!(
        "goatd: and forge signed gossip that honest verifiers accept. Identities are NOT secret."
    );
    eprintln!(
        "goatd: bind={listen}; for Alpha/off-host use GOATD_SIGNING_SEED (unique per node, never committed)."
    );
    eprintln!("goatd: =====================================================================");
}

/// P4 chain-id agreement: the genesis-declared chain must equal the compiled `ACTIVE_CHAIN_ID`. A
/// missing declaration is a fatal schema gap outside dev (so the string `chain_id` name can never
/// silently drift from the wire domain).
fn chain_id_ok(genesis_chain: Option<ChainId>, active: ChainId, dev: bool) -> Result<(), String> {
    match genesis_chain {
        Some(c) if c == active => Ok(()),
        Some(c) => Err(format!(
            "genesis declares chain_id_u32={c:#010x} but this binary is built for {active:#010x}; \
             rebuild with the matching network (default = testnet, `--features mainnet`)"
        )),
        None if dev => Ok(()),
        None => Err(format!(
            "genesis is missing the required numeric field `chain_id_u32` (expected {active:#010x})"
        )),
    }
}

/// Resolve the node cookie secret from, in priority order: `GOATD_NODE_SECRET` (64 hex),
/// `--node-secret-file` / `GOATD_NODE_SECRET_FILE`, then [`DEFAULT_NODE_SECRET_PATH`]. `Ok(None)` = no
/// source present (caller: fatal outside dev, zero-secret in dev). `Err` = present but malformed
/// (always fatal). Never returns a compiled-in default.
fn resolve_node_secret(cfg_file: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    if let Ok(hex) = std::env::var("GOATD_NODE_SECRET") {
        return parse_node_secret_hex(&hex)
            .map(Some)
            .ok_or_else(|| "GOATD_NODE_SECRET must be 64 hex chars (32 bytes)".to_string());
    }
    let path = cfg_file
        .map(str::to_string)
        .or_else(|| std::env::var("GOATD_NODE_SECRET_FILE").ok())
        .unwrap_or_else(|| DEFAULT_NODE_SECRET_PATH.to_string());
    match std::fs::read_to_string(&path) {
        Ok(contents) => parse_node_secret_hex(&contents).map(Some).ok_or_else(|| {
            format!("node secret file '{path}' must contain 64 hex chars (32 bytes)")
        }),
        Err(_) => Ok(None),
    }
}

// ===========================================================================
// Key registry (authorization plane) — crypto primitives live in host_crypto
// ===========================================================================

/// Staked `(node_id → ML-DSA-65 public key)` set loaded from `genesis.json`.
struct StaticKeyRegistry {
    keys: HashMap<[u8; 32], [u8; ML_DSA_65_PUBLIC_KEY_LEN]>,
}

impl StaticKeyRegistry {
    /// Empty registry with **accept-all** semantics (dev-only / loopback tests).
    fn accept_all() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    fn from_config(config: &GenesisConfig) -> Self {
        let mut keys = HashMap::with_capacity(config.orchestrators.len());
        for (node_id, pk) in &config.orchestrators {
            keys.insert(*node_id, *pk);
        }
        Self { keys }
    }
}

impl KeyRegistry for StaticKeyRegistry {
    fn is_authorized(
        &self,
        public_key: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
        node_id: &[u8; 32],
    ) -> bool {
        if self.keys.is_empty() {
            return true;
        }
        self.keys
            .get(node_id)
            .map(|k| k == public_key)
            .unwrap_or(false)
    }
}

// ===========================================================================
// Canonical gossip codec — the real wire *de*serializer (mirror of crypto.rs)
// ===========================================================================

/// A minimal bounds-checked forward cursor over a decrypted plaintext — fail-closed, no panics.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    #[inline]
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    #[inline]
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    #[inline]
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    #[inline]
    fn u16(&mut self) -> Option<u16> {
        let mut a = [0u8; 2];
        a.copy_from_slice(self.take(2)?);
        Some(u16::from_le_bytes(a))
    }
    #[inline]
    fn u32(&mut self) -> Option<u32> {
        let mut a = [0u8; 4];
        a.copy_from_slice(self.take(4)?);
        Some(u32::from_le_bytes(a))
    }
    #[inline]
    fn u64(&mut self) -> Option<u64> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Some(u64::from_le_bytes(a))
    }
    #[inline]
    fn array<const K: usize>(&mut self) -> Option<[u8; K]> {
        let s = self.take(K)?;
        let mut a = [0u8; K];
        a.copy_from_slice(s);
        Some(a)
    }
    #[inline]
    fn is_done(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// Parse an `OpaqueTag`: `len_u32 ‖ bytes` (§11.2). Bounded by [`OPAQUE_TAG_CAP`].
fn read_opaque_tag(r: &mut Reader) -> Option<OpaqueTag> {
    let len = r.u32()? as usize;
    if len > OPAQUE_TAG_CAP {
        return None;
    }
    OpaqueTag::from_bytes(r.take(len)?)
}

/// Parse a `DeviceCapability`: `task_class_id(OpaqueTag) ‖ measured_gcu(u64) ‖ det_ref[32]`.
fn read_device_capability(r: &mut Reader) -> Option<DeviceCapability> {
    Some(DeviceCapability {
        task_class_id: read_opaque_tag(r)?,
        measured_gcu_per_hour: r.u64()?,
        determinism_profile_ref: r.array::<32>()?,
    })
}

/// Parse the capabilities `BoundedVec`: `count_u32 ‖ [DeviceCapability]`, bounded by
/// [`MAX_CAPABILITIES`].
fn read_capabilities(r: &mut Reader) -> Option<BoundedVec<DeviceCapability, MAX_CAPABILITIES>> {
    let count = r.u32()? as usize;
    if count > MAX_CAPABILITIES {
        return None;
    }
    let mut caps = BoundedVec::new();
    for _ in 0..count {
        caps.try_push(read_device_capability(r)?).ok()?;
    }
    Some(caps)
}

/// Parse a `CapabilityRecord` body in canonical field order (mirror of `crypto.rs`).
fn read_capability_record(r: &mut Reader) -> Option<CapabilityRecord> {
    Some(CapabilityRecord {
        node_id: r.array::<32>()?,
        epoch: r.u64()?,
        beacon_nonce: r.array::<32>()?,
        prev_record: r.array::<32>()?,
        capabilities: read_capabilities(r)?,
        availability_ppm: r.u64()?,
        power_thermal_envelope: PowerThermalEnvelope {
            power_mw: r.u32()?,
            thermal_dk: r.u32()?,
        },
        density_witness_ppm: r.u64()?,
    })
}

/// Parse a `FrameHeader` in canonical field order.
fn read_frame_header(r: &mut Reader) -> Option<FrameHeader> {
    Some(FrameHeader {
        schema_version: r.u16()?,
        frame_type: r.u8()?,
        endpoint_pseudonym: r.array::<32>()?,
        identity_index: r.u16()?,
        epoch: r.u64()?,
        run_nonce: r.array::<32>()?,
        chain_id: r.u32()?,
    })
}

/// Parse a `NetworkDensityFrame` body in canonical field order.
fn read_network_density_frame(r: &mut Reader) -> Option<NetworkDensityFrame> {
    let header = read_frame_header(r)?;
    let tick_index = r.u16()?;
    let dl_bin = r.u8()?;
    let ul_bin = r.u8()?;
    let concurrent_flag = r.u8()?;
    let agg_dl_bin = r.u8()?;
    let agg_ul_bin = r.u8()?;
    let mut rtt_q = [0u16; 8];
    for slot in &mut rtt_q {
        *slot = r.u16()?;
    }
    Some(NetworkDensityFrame {
        header,
        tick_index,
        dl_bin,
        ul_bin,
        concurrent_flag,
        agg_dl_bin,
        agg_ul_bin,
        rtt_q,
        origin_change_count: r.u8()?,
        shared_origin_degree_bin: r.u8()?,
        xfer_bytes_bin: r.u8()?,
        morphology_id: r.u8()?,
        peak_micro_bin: r.u8()?,
        crest_eighth_oct: r.u8()?,
        duty_ppm: r.u32()?,
        throttle_onset_s: r.u8()?,
        pre_bin: r.u8()?,
        post_bin: r.u8()?,
    })
}

/// Parse a `SignedRecord<T>`: `payload ‖ public_key[1952] ‖ signature[3309]`.
fn read_signed<T, P: Fn(&mut Reader) -> Option<T>>(
    r: &mut Reader,
    parse: P,
) -> Option<SignedRecord<T>> {
    let payload = parse(r)?;
    Some(SignedRecord {
        payload,
        public_key: r.array::<ML_DSA_65_PUBLIC_KEY_LEN>()?,
        signature: r.array::<ML_DSA_65_SIGNATURE_LEN>()?,
    })
}

/// **The canonical gossip codec** (the real deserializer). A decrypted plaintext is
/// `variant(1) ‖ SignedRecord<payload>`; the whole buffer must be consumed (no ambiguous trailing
/// bytes). Fail-closed: any malformed input returns `None`, and the daemon drops the frame.
struct CanonicalGossipCodec;

impl GossipCodec for CanonicalGossipCodec {
    fn decode(&self, plaintext: &[u8]) -> Option<GossipMessage> {
        let mut r = Reader::new(plaintext);
        let msg = match r.u8()? {
            GOSSIP_VARIANT_NODE_CAPABILITY => {
                GossipMessage::NodeCapability(read_signed(&mut r, read_capability_record)?)
            }
            GOSSIP_VARIANT_TELEMETRY => {
                GossipMessage::TelemetryFrame(read_signed(&mut r, read_network_density_frame)?)
            }
            _ => return None,
        };
        r.is_done().then_some(msg) // reject trailing bytes (canonical framing is exact)
    }
}

/// Encode a [`GossipMessage`] to its wire frame `variant(1) ‖ payload_body ‖ public_key ‖ signature`.
/// The mirror of [`CanonicalGossipCodec::decode`].
fn encode_gossip_frame(msg: &GossipMessage) -> Option<Vec<u8>> {
    let mut buf = [0u8; GOSSIP_FRAME_MAX_LEN];
    let mut sink = SliceSink::new(&mut buf);
    match msg {
        GossipMessage::NodeCapability(rec) => {
            sink.put(&[GOSSIP_VARIANT_NODE_CAPABILITY]).ok()?;
            rec.payload.serialize_into(&mut sink).ok()?;
            sink.put(&rec.public_key).ok()?;
            sink.put(&rec.signature).ok()?;
        }
        GossipMessage::TelemetryFrame(rec) => {
            sink.put(&[GOSSIP_VARIANT_TELEMETRY]).ok()?;
            rec.payload.serialize_into(&mut sink).ok()?;
            sink.put(&rec.public_key).ok()?;
            sink.put(&rec.signature).ok()?;
        }
    }
    let len = sink.len();
    Some(buf[..len].to_vec())
}

/// Wrap a gossip plaintext in an encrypted `SecureFrame` packet:
/// `tag(0x04) ‖ encrypt(plaintext) (= ciphertext ‖ AEAD tag)`.
fn encode_secure_frame(channel: &mut Aes256GcmChannel, plaintext: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0u8; 1 + plaintext.len() + AES_256_GCM_TAG_LEN];
    out[0] = packet_tag::SECURE_FRAME;
    let n = channel.encrypt_frame(plaintext, &mut out[1..]).ok()?;
    out.truncate(1 + n);
    Some(out)
}

// ===========================================================================
// Session state (guardrail 3)
// ===========================================================================

/// A concrete per-peer secure session with a last-seen heartbeat (GC) and a one-shot capability flag.
struct Session {
    channel: Aes256GcmChannel,
    last_seen: Instant,
    /// Whether we have already sent this peer our signed `CapabilityRecord` (prevents gossip ping-pong
    /// on the direct exchange).
    sent_capability: bool,
}

impl Session {
    fn new(channel: Aes256GcmChannel) -> Self {
        Self {
            channel,
            last_seen: Instant::now(),
            sent_capability: false,
        }
    }

    #[allow(dead_code)]
    fn with_role(key: [u8; 32], role: ChannelRole) -> Self {
        Self::new(Aes256GcmChannel::new(key, role))
    }
    #[inline]
    fn touch(&mut self) {
        self.last_seen = Instant::now();
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Current wall-clock seconds. Handed to the core, which corrects it via the median `NetworkClock`.
#[inline]
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Deterministically fold a `SocketAddr` into the 16-byte peer-address the cookie MAC binds.
fn peer_addr_bytes(addr: &SocketAddr) -> [u8; PEER_ADDR_LEN] {
    let mut out = [0u8; PEER_ADDR_LEN];
    match addr {
        SocketAddr::V4(v4) => {
            out[..4].copy_from_slice(&v4.ip().octets());
            out[4..6].copy_from_slice(&v4.port().to_le_bytes());
        }
        SocketAddr::V6(v6) => {
            out.copy_from_slice(&v6.ip().octets());
        }
    }
    out
}

/// Parse the initiation embedded in a `COOKIE_ECHO` packet for ML-KEM encapsulation.
fn initiation_from_cookie_echo(raw: &[u8]) -> Option<HandshakeInitiation> {
    // tag(1) ‖ cookie(32) ‖ ts(8) ‖ initiation_body ‖ signature
    let need = 1 + 32 + 8 + HANDSHAKE_INITIATION_BODY_LEN + ML_DSA_65_SIGNATURE_LEN;
    if raw.len() != need || raw.first() != Some(&packet_tag::COOKIE_ECHO) {
        return None;
    }
    let body = &raw[1 + 32 + 8..1 + 32 + 8 + HANDSHAKE_INITIATION_BODY_LEN];
    let mut r = body;
    let mut take = |n: usize| -> Option<&[u8]> {
        if r.len() < n {
            return None;
        }
        let (a, b) = r.split_at(n);
        r = b;
        Some(a)
    };
    let mut initiator_identity = [0u8; ML_DSA_65_PUBLIC_KEY_LEN];
    initiator_identity.copy_from_slice(take(ML_DSA_65_PUBLIC_KEY_LEN)?);
    let mut ephemeral_kem_pk = [0u8; ML_KEM_768_ENCAPS_KEY_LEN];
    ephemeral_kem_pk.copy_from_slice(take(ML_KEM_768_ENCAPS_KEY_LEN)?);
    let mut e = [0u8; 8];
    e.copy_from_slice(take(8)?);
    let epoch = u64::from_le_bytes(e);
    let mut t = [0u8; 8];
    t.copy_from_slice(take(8)?);
    let local_time = u64::from_le_bytes(t);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(take(32)?);
    Some(HandshakeInitiation {
        initiator_identity,
        ephemeral_kem_pk,
        epoch,
        local_time,
        nonce,
    })
}

/// Parse a signed `RESPONSE` body for ML-KEM decapsulation.
fn response_from_raw(raw: &[u8]) -> Option<HandshakeResponse> {
    let need = 1 + HANDSHAKE_RESPONSE_BODY_LEN + ML_DSA_65_SIGNATURE_LEN;
    if raw.len() != need || raw.first() != Some(&packet_tag::RESPONSE) {
        return None;
    }
    let body = &raw[1..1 + HANDSHAKE_RESPONSE_BODY_LEN];
    let mut r = body;
    let mut take = |n: usize| -> Option<&[u8]> {
        if r.len() < n {
            return None;
        }
        let (a, b) = r.split_at(n);
        r = b;
        Some(a)
    };
    let mut responder_identity = [0u8; ML_DSA_65_PUBLIC_KEY_LEN];
    responder_identity.copy_from_slice(take(ML_DSA_65_PUBLIC_KEY_LEN)?);
    let mut kem_ciphertext = [0u8; ML_KEM_768_CIPHERTEXT_LEN];
    kem_ciphertext.copy_from_slice(take(ML_KEM_768_CIPHERTEXT_LEN)?);
    let mut e = [0u8; 8];
    e.copy_from_slice(take(8)?);
    let epoch = u64::from_le_bytes(e);
    let mut t = [0u8; 8];
    t.copy_from_slice(take(8)?);
    let local_time = u64::from_le_bytes(t);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(take(32)?);
    Some(HandshakeResponse {
        responder_identity,
        kem_ciphertext,
        epoch,
        local_time,
        nonce,
    })
}

/// Encode a cookie-challenge egress reply: `tag ‖ cookie(32) ‖ timestamp_le(8)`.
fn encode_cookie_reply(challenge: &CookieChallenge) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 8);
    out.push(REPLY_TAG_COOKIE_CHALLENGE);
    out.extend_from_slice(&challenge.cookie);
    out.extend_from_slice(&challenge.timestamp.to_le_bytes());
    out
}

/// Build an outbound `HandshakeInitiation` with a fresh ML-KEM-768 ephemeral keypair.
/// Returns the initiation plus the decapsulation key the initiator must keep until `RESPONSE`.
fn build_initiation(
    identity: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
    genesis_time: u64,
) -> (HandshakeInitiation, EphemeralKem) {
    let eph = generate_ephemeral_kem();
    let init = HandshakeInitiation {
        initiator_identity: identity,
        ephemeral_kem_pk: eph.ek_bytes,
        epoch: 0,
        local_time: unix_now().max(genesis_time),
        nonce: {
            // Anti-replay: mix wall clock into a 32-byte nonce (not secret).
            let mut n = [0u8; 32];
            let t = unix_now().to_le_bytes();
            n[..8].copy_from_slice(&t);
            n[8] = 0x33;
            n
        },
    };
    (init, eph)
}

/// Encode a signed `RESPONSE` packet: `tag(0x03) ‖ body ‖ signature`.
fn encode_response_packet(
    resp: &HandshakeResponse,
    signature: &[u8; ML_DSA_65_SIGNATURE_LEN],
) -> Vec<u8> {
    let mut buf = [0u8; 1 + HANDSHAKE_RESPONSE_BODY_LEN + ML_DSA_65_SIGNATURE_LEN];
    let mut sink = SliceSink::new(&mut buf);
    sink.put(&[packet_tag::RESPONSE]).expect("sized");
    resp.serialize_into(&mut sink).expect("sized");
    sink.put(signature).expect("sized");
    let len = sink.len();
    buf[..len].to_vec()
}

/// Encode an `INITIATION` packet: `tag(0x01) ‖ serialized HandshakeInitiation`.
fn encode_initiation_packet(init: &HandshakeInitiation) -> Vec<u8> {
    let mut buf = [0u8; 1 + HANDSHAKE_INITIATION_BODY_LEN];
    let mut sink = SliceSink::new(&mut buf);
    sink.put(&[packet_tag::INITIATION])
        .expect("buffer sized for the initiation tag");
    init.serialize_into(&mut sink)
        .expect("buffer sized for the initiation body");
    let len = sink.len();
    buf[..len].to_vec()
}

/// Encode a `COOKIE_ECHO` packet: `tag(0x02) ‖ cookie(32) ‖ ts_le(8) ‖ initiation ‖ signature`.
fn encode_cookie_echo_packet(
    cookie: &[u8; 32],
    timestamp: u64,
    init: &HandshakeInitiation,
    signature: &[u8; ML_DSA_65_SIGNATURE_LEN],
) -> Vec<u8> {
    let mut buf = [0u8; 1 + 32 + 8 + HANDSHAKE_INITIATION_BODY_LEN + ML_DSA_65_SIGNATURE_LEN];
    let mut sink = SliceSink::new(&mut buf);
    sink.put(&[packet_tag::COOKIE_ECHO]).expect("sized");
    sink.put(cookie).expect("sized");
    sink.put(&timestamp.to_le_bytes()).expect("sized");
    init.serialize_into(&mut sink).expect("sized");
    sink.put(signature).expect("sized");
    let len = sink.len();
    buf[..len].to_vec()
}

// ===========================================================================
// The consensus actor (guardrails 2, 3, 4)
// ===========================================================================

type Node = GoatNode<HostMlDsaVerifier, StaticKeyRegistry, MESSAGE_CACHE, COOKIE_CACHE>;

/// The single owner of all mutable consensus state. Never shared, never locked. The cache-heavy
/// `GoatNode` is boxed onto the heap; generic over the [`GossipCodec`] `G`.
struct ConsensusActor<G: GossipCodec> {
    node: Box<Node>,
    sessions: HashMap<SocketAddr, Session>,
    codec: G,
    signer: HostMlDsaSigner,
    /// This node's `(node_id, ML-DSA-65 public key)` — from genesis by `--node-index`. Stamped into
    /// every outbound `CapabilityRecord` so the receiving peer's registry authorizes it.
    node_id: [u8; 32],
    identity: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
    plaintext: Vec<u8>,
    /// The `HandshakeInitiation` broadcast at bootstrap (initiator role), retained to answer the
    /// seed's cookie challenge. `None` on seed/non-bootstrap nodes.
    pending_initiation: Option<HandshakeInitiation>,
    /// Ephemeral ML-KEM decapsulation key matching `pending_initiation.ephemeral_kem_pk`.
    pending_kem: Option<EphemeralKem>,
    /// MTU-chunking: MTU-safe reassembly of chunked UDP frames (bounded, pre-PQ).
    reassembly: ReassemblyTable,
    /// Monotonic msg_id for outbound chunking.
    next_msg_id: u32,
    accepted: u64,
    rejected: u64,
    evicted: u64,
}

impl<G: GossipCodec> ConsensusActor<G> {
    fn new(
        node_secret: [u8; 32],
        identity: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
        node_id: [u8; 32],
        registry: StaticKeyRegistry,
        genesis_time: u64,
        codec: G,
        signer: HostMlDsaSigner,
    ) -> Self {
        let node = Box::new(GoatNode::new(
            node_secret,
            identity,
            HostMlDsaVerifier,
            registry,
            genesis_time,
        ));
        Self {
            node,
            sessions: HashMap::new(),
            codec,
            signer,
            node_id,
            identity,
            plaintext: vec![0u8; MAX_DATAGRAM],
            pending_initiation: None,
            pending_kem: None,
            reassembly: ReassemblyTable::new(),
            next_msg_id: 1,
            accepted: 0,
            rejected: 0,
            evicted: 0,
        }
    }

    /// Insert a session, LRU-evicting the least-recently-seen if a **new** address would exceed
    /// [`MAX_SESSIONS`]. Re-handshakes (existing address) replace in place, no eviction.
    fn insert_session_bounded(&mut self, addr: SocketAddr, session: Session) {
        if !self.sessions.contains_key(&addr) && self.sessions.len() >= MAX_SESSIONS {
            if let Some(lru) = self
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(a, _)| *a)
            {
                self.sessions.remove(&lru);
                self.evicted += 1;
            }
        }
        self.sessions.insert(addr, session);
    }

    /// Sign `init`'s `CTX_GOAT_TRANSPORT_HS` preimage (Deliverable 1 — was an all-zero placeholder).
    fn sign_initiation(&self, init: &HandshakeInitiation) -> [u8; ML_DSA_65_SIGNATURE_LEN] {
        let mut buf = [0u8; HANDSHAKE_INITIATION_MAX_PREIMAGE_LEN];
        let mut sink = SliceSink::new(&mut buf);
        init.write_signing_preimage(&mut sink)
            .expect("initiation preimage within bound");
        self.signer.sign_ml_dsa_65(sink.written())
    }

    /// Build and **sign** this node's `CapabilityRecord`, returning the encoded gossip wire frame
    /// (Deliverable 1: signed before it reaches the network; Deliverable 2: canonical framing).
    fn build_signed_capability(&self) -> Vec<u8> {
        let cap = CapabilityRecord {
            node_id: self.node_id,
            epoch: 0,
            beacon_nonce: [0u8; 32],
            prev_record: [0u8; 32],
            capabilities: BoundedVec::new(),
            availability_ppm: PPM,
            power_thermal_envelope: PowerThermalEnvelope {
                power_mw: 0,
                thermal_dk: 0,
            },
            density_witness_ppm: PPM,
        };
        let mut buf = [0u8; CAPABILITY_RECORD_MAX_PREIMAGE_LEN];
        let mut sink = SliceSink::new(&mut buf);
        cap.write_signing_preimage(&mut sink)
            .expect("capability preimage within bound");
        let signature = self.signer.sign_ml_dsa_65(sink.written());
        let msg = GossipMessage::NodeCapability(SignedRecord {
            payload: cap,
            public_key: self.identity,
            signature,
        });
        encode_gossip_frame(&msg).expect("capability frame within GOSSIP_FRAME_MAX_LEN")
    }

    /// **Fully synchronous** consensus step (guardrail 2): demux + validate + state mutation, no
    /// `.await`, no lock. Returns a **batch** of `(destination, packet)` egress pairs; `consensus_loop`
    /// hands each to the detached egress worker via a non-blocking `try_send`, so no network `.await`
    /// ever runs on the consensus path. The batch lets one packet be a direct reply while others fan a
    /// novel gossip frame out to the mesh.
    fn process(&mut self, raw: &[u8], addr: SocketAddr) -> Vec<(SocketAddr, Vec<u8>)> {
        // MTU-chunking: reassemble MTU-safe chunks into a logical datagram before any demux/PQ.
        let owned: Vec<u8>;
        let logical: &[u8] = if is_chunk(raw) {
            match self.reassembly.ingest_chunk(addr, raw, Instant::now()) {
                Ok(Some(full)) => {
                    owned = full;
                    &owned
                }
                Ok(None) => return Vec::new(), // incomplete — no PQ work yet
                Err(_) => {
                    self.rejected += 1;
                    return Vec::new();
                }
            }
        } else {
            raw
        };

        // Initiator role (RECON-11, client side): a cookie-challenge reply to an initiation WE sent.
        if logical.first() == Some(&REPLY_TAG_COOKIE_CHALLENGE) {
            return self.handle_cookie_challenge_reply(logical, addr);
        }

        let peer_addr = peer_addr_bytes(&addr);
        let now = unix_now();

        let mut scratch = Aes256GcmChannel::scratch();
        let outcome = {
            let channel: &mut Aes256GcmChannel = match self.sessions.get_mut(&addr) {
                Some(s) => &mut s.channel,
                None => &mut scratch,
            };
            self.node.process_ingress_packet(
                logical,
                &peer_addr,
                now,
                channel,
                &self.codec,
                &mut self.plaintext,
            )
        };

        match outcome {
            Ok(IngressOutcome::ChallengeIssued(challenge)) => {
                self.accepted += 1;
                vec![(addr, encode_cookie_reply(&challenge))]
            }
            Ok(IngressOutcome::HandshakeEstablished) => {
                // Responder path: cookie+ML-DSA verified. Encapsulate to initiator's ephemeral KEM
                // key, emit signed RESPONSE, open AES session as Responder, gossip capability.
                let Some(init) = initiation_from_cookie_echo(logical) else {
                    self.rejected += 1;
                    return Vec::new();
                };
                let Ok((ct, shared)) = kem_encapsulate(&init.ephemeral_kem_pk) else {
                    self.rejected += 1;
                    return Vec::new();
                };
                let key = derive_session_key(&shared);
                let resp = HandshakeResponse {
                    responder_identity: self.identity,
                    kem_ciphertext: ct,
                    epoch: init.epoch,
                    local_time: unix_now().max(init.local_time),
                    nonce: init.nonce,
                };
                let mut pre = [0u8; HANDSHAKE_RESPONSE_MAX_PREIMAGE_LEN];
                let mut sink = SliceSink::new(&mut pre);
                resp.write_signing_preimage(&mut sink)
                    .expect("response preimage within bound");
                let resp_sig = self.signer.sign_ml_dsa_65(sink.written());
                let resp_pkt = encode_response_packet(&resp, &resp_sig);

                let mut session = Session::new(Aes256GcmChannel::new(key, ChannelRole::Responder));
                let gossip = self.build_signed_capability();
                let secure = encode_secure_frame(&mut session.channel, &gossip);
                session.sent_capability = true;
                self.insert_session_bounded(addr, session);
                self.accepted += 1;
                eprintln!(
                    "goatd: handshake established with {addr} → RESPONSE + signed CapabilityRecord \
                     (sessions={}/{MAX_SESSIONS})",
                    self.sessions.len()
                );
                let mut out = vec![(addr, resp_pkt)];
                if let Some(pkt) = secure {
                    out.push((addr, pkt));
                }
                out
            }
            Ok(IngressOutcome::ResponseVerified) => {
                // Initiator path: verify already passed in core; decapsulate and open session.
                let Some(resp) = response_from_raw(logical) else {
                    self.rejected += 1;
                    return Vec::new();
                };
                let Some(eph) = self.pending_kem.take() else {
                    self.rejected += 1;
                    return Vec::new();
                };
                let Ok(shared) = kem_decapsulate(&eph.dk, &resp.kem_ciphertext) else {
                    self.rejected += 1;
                    return Vec::new();
                };
                let key = derive_session_key(&shared);
                self.insert_session_bounded(
                    addr,
                    Session::new(Aes256GcmChannel::new(key, ChannelRole::Initiator)),
                );
                self.accepted += 1;
                eprintln!(
                    "goatd: RESPONSE accepted from {addr} → session open (initiator); waiting for gossip"
                );
                Vec::new()
            }
            Ok(IngressOutcome::GossipAccepted) => {
                self.accepted += 1;
                let seen = self.node.seen_messages();

                // The freshly-decrypted, validated, NOVEL gossip frame (RECON-11 guarantees novelty +
                // signature validity + origin authorization). Copy it out of the shared decrypt buffer
                // so it can be re-encrypted per peer without borrow conflicts.
                let n = logical.len().saturating_sub(1 + AES_256_GCM_TAG_LEN);
                let plaintext = self.plaintext[..n].to_vec();

                let mut egress: Vec<(SocketAddr, Vec<u8>)> = Vec::new();

                // (1) The Direct Reply — announce our own signed capability to the sender, once per
                //     session (bidirectional exchange, no ping-pong).
                let should_reply = self
                    .sessions
                    .get(&addr)
                    .map(|s| !s.sent_capability)
                    .unwrap_or(false);
                if should_reply {
                    let gossip = self.build_signed_capability();
                    if let Some(s) = self.sessions.get_mut(&addr) {
                        s.touch();
                        s.sent_capability = true;
                        if let Some(pkt) = encode_secure_frame(&mut s.channel, &gossip) {
                            egress.push((addr, pkt));
                        }
                    }
                } else if let Some(s) = self.sessions.get_mut(&addr) {
                    s.touch();
                }

                // (2) The Epidemic Fan-out (verify-before-forward) — relay the novel frame to every
                //     OTHER established session, re-encrypted under that peer's own channel. The
                //     sender is skipped (no echo-back); the RECON-11 dedup cache guarantees each node
                //     forwards a given frame at most once, so the epidemic terminates.
                let mut fanned = 0usize;
                for (peer_addr, session) in self.sessions.iter_mut() {
                    if *peer_addr == addr {
                        continue;
                    }
                    if let Some(pkt) = encode_secure_frame(&mut session.channel, &plaintext) {
                        egress.push((*peer_addr, pkt));
                        fanned += 1;
                    }
                }

                eprintln!(
                    "goatd: gossip accepted from {addr} (seen={seen}) → direct_reply={should_reply} \
                     fanned_out={fanned}"
                );
                egress
            }
            Err(_e) => {
                self.rejected += 1;
                Vec::new() // fail-closed: dropped, never forwarded (verify-before-forward).
            }
        }
    }

    /// Answer a seed's cookie challenge with a **signed** `COOKIE_ECHO`. The AES session is opened
    /// only after the signed ML-KEM `RESPONSE` arrives (initiator role). Only bootstrapping nodes
    /// (with a `pending_initiation`) respond.
    fn handle_cookie_challenge_reply(
        &mut self,
        raw: &[u8],
        addr: SocketAddr,
    ) -> Vec<(SocketAddr, Vec<u8>)> {
        let Some(init) = self.pending_initiation.clone() else {
            return Vec::new();
        };
        if raw.len() != 1 + 32 + 8 {
            self.rejected += 1;
            return Vec::new();
        }
        let mut cookie = [0u8; 32];
        cookie.copy_from_slice(&raw[1..33]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&raw[33..41]);
        let timestamp = u64::from_le_bytes(ts);
        let signature = self.sign_initiation(&init);
        self.accepted += 1;
        eprintln!("goatd: cookie challenge from {addr} → signed COOKIE_ECHO (awaiting RESPONSE)");
        vec![(
            addr,
            encode_cookie_echo_packet(&cookie, timestamp, &init, &signature),
        )]
    }

    /// Drop sessions idle beyond [`SESSION_IDLE_TIMEOUT`] (guardrail 3). Returns the count swept.
    fn sweep_dead_sessions(&mut self) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, s| s.last_seen.elapsed() < SESSION_IDLE_TIMEOUT);
        before - self.sessions.len()
    }
}

// ===========================================================================
// Runtime wiring
// ===========================================================================

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // ---- resolve CLI + environment ----
    let cfg = parse_args(std::env::args().skip(1));
    let listen = cfg.listen.clone().unwrap_or_else(|| BIND_ADDR.to_string());
    let genesis_path = cfg
        .genesis_path
        .clone()
        .or_else(|| std::env::var("GOATD_GENESIS").ok())
        .unwrap_or_else(|| DEFAULT_GENESIS_PATH.to_string());
    let node_index = cfg.node_index.or_else(|| {
        std::env::var("GOATD_NODE_ID")
            .ok()
            .and_then(|s| s.trim().parse().ok())
    });
    let dev = cfg.dev_accept_all;
    let is_mainnet = ACTIVE_CHAIN_ID == CHAIN_ID_GOAT_MAINNET;
    let is_production = std::env::var("GOATD_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false);

    eprintln!(
        "goatd: PQ host crypto ACTIVE (ML-DSA-65 + ML-KEM-768 + AES-256-GCM; crates ml-dsa 0.1.1 / \
         ml-kem 0.3.2 / aes-gcm 0.11.0) — chain_id={ACTIVE_CHAIN_ID:#010x} ({net})",
        net = if is_mainnet { "mainnet" } else { "testnet" }
    );

    // ---- Alpha Pilot: advisory power log (Deliverable 1) ----
    // The REAL CPU limit is OS-level (docker cgroups via `GOATD_CPU_LIMIT`); this only surfaces the
    // operator's chosen quota for reassurance. The daemon does NOT self-throttle `consensus_loop`.
    if let Some(t) = cfg.throttle_target.as_deref() {
        match t.parse::<f64>() {
            Ok(frac) => eprintln!(
                "goatd: Alpha Pilot — operating at {:.0}% CPU quota ({t} core(s)); OS-enforced via \
                 docker cgroups, not application throttling",
                frac * 100.0
            ),
            Err(_) => eprintln!(
                "goatd: Alpha Pilot — advisory --throttle-target '{t}' (unparsed); the real limit is \
                 OS-level via docker cgroups"
            ),
        }
    }

    // ---- P3: dev accept-all is opt-in, loopback-only, loud, and never on prod/mainnet ----
    if dev {
        if let Some(reason) = dev_accept_all_refusal(&listen, is_production, is_mainnet) {
            fatal(format!(
                "--dev-accept-all-registry refused: {reason}. This flag is loopback-dev only."
            ));
        }
        eprintln!("goatd: ================= INSECURE DEV MODE =================");
        eprintln!("goatd: --dev-accept-all-registry: the registry ACCEPTS ALL gossip origins;");
        eprintln!(
            "goatd: unauthenticated peers are trusted. NEVER use off localhost or in production."
        );
        eprintln!("goatd: =====================================================");
    }

    // ---- P3: genesis required by default (fail-closed); strict key lengths outside dev ----
    let genesis = match load_genesis(&genesis_path, !dev) {
        Ok(g) => Some(g),
        Err(e) => {
            if dev {
                eprintln!(
                    "goatd: WARN genesis load failed at '{genesis_path}' ({e}); dev accept-all → \
                     continuing without a registry"
                );
                None
            } else {
                fatal(format!(
                    "genesis required at '{genesis_path}' but load failed: {e}. Refusing to start \
                     fail-open — mount a valid genesis, or use --dev-accept-all-registry on a \
                     loopback --listen for local dev."
                ));
            }
        }
    };

    // ---- P4: the genesis chain must match the compiled network domain ----
    if let Some(g) = &genesis {
        if let Err(e) = chain_id_ok(g.chain_id, ACTIVE_CHAIN_ID, dev) {
            fatal(format!("chain-id: {e}"));
        }
    }

    // ---- registry + genesis-derived identity ----
    let (registry, genesis_time, identity, node_id) = match &genesis {
        Some(g) => {
            eprintln!(
                "goatd: loaded genesis '{genesis_path}' — {} orchestrator(s), genesis_time_unix={}, \
                 chain_id={:#010x}",
                g.orchestrators.len(),
                g.genesis_time_unix,
                g.chain_id.unwrap_or(ACTIVE_CHAIN_ID)
            );
            let (node_id, identity) = node_index
                .and_then(|i| g.orchestrators.get(i).map(|o| (o.0, o.1)))
                .unwrap_or(([0u8; 32], [0u8; ML_DSA_65_PUBLIC_KEY_LEN]));
            if let Some(i) = node_index {
                eprintln!("goatd: presenting genesis orchestrator identity #{i}");
            }
            (
                StaticKeyRegistry::from_config(g),
                g.genesis_time_unix,
                identity,
                node_id,
            )
        }
        None => {
            // Reachable ONLY in dev accept-all (the fail-closed branch above exits otherwise).
            (
                StaticKeyRegistry::accept_all(),
                FALLBACK_GENESIS_TIME_UNIX,
                [0u8; ML_DSA_65_PUBLIC_KEY_LEN],
                [0u8; 32],
            )
        }
    };

    // ---- P3: node secret required outside dev; never a compiled-in zero ----
    let node_secret = match resolve_node_secret(cfg.node_secret_file.as_deref()) {
        Ok(Some(s)) => {
            eprintln!("goatd: loaded 32-byte node secret from the configured source");
            s
        }
        Ok(None) => {
            if dev {
                eprintln!(
                    "goatd: WARN no node secret provided; dev → using an all-zero cookie secret \
                     (INSECURE)"
                );
                [0u8; 32]
            } else {
                fatal(
                    "node secret required: set GOATD_NODE_SECRET (64 hex), --node-secret-file, \
                     GOATD_NODE_SECRET_FILE, or mount /etc/goatd/node_secret. Refusing to run with a \
                     compiled-in zero secret.",
                );
            }
        }
        Err(e) => fatal(format!("node secret: {e}")),
    };

    // ---- ML-DSA signing key (Track C + identity-hardening) — BEFORE bind (fail-closed, no open port) ----
    // Priority: GOATD_SIGNING_SEED (64 hex secret) → gated deterministic testnet seed from
    // node_index / dev → fatal. Deterministic seeds are refuse-by-default off loopback.
    let signer = resolve_signer(
        node_index,
        identity,
        dev,
        &listen,
        is_production,
        is_mainnet,
    );

    let socket = Arc::new(UdpSocket::bind(&listen).await?);
    set_dont_fragment(&socket);
    eprintln!(
        "goatd: listening on {listen} (MTU-safe framing: max UDP datagram {MAX_UDP_DATAGRAM} B, DF preferred)"
    );

    // execution-isolation: execution isolation availability (fail-closed for payloads; mesh still runs).
    let iso_status = isolation::check_isolation();
    let iso_policy = isolation::ExecPolicy::default();
    match isolation::may_execute(&iso_status, &iso_policy) {
        Ok(()) => {
            if let isolation::IsolationStatus::Available { worker_path } = &iso_status {
                eprintln!(
                    "goatd: execution isolation AVAILABLE (worker={}) — payload exec permitted under sandbox",
                    worker_path.display()
                );
                if std::env::var("GOATD_ISO_SELFTEST")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
                {
                    match isolation::make_scratch("boot") {
                        Ok(scratch) => {
                            match isolation::run_probe(
                                worker_path,
                                &scratch,
                                "benign",
                                "-",
                                &iso_policy,
                            ) {
                                Ok(r) => eprintln!("goatd: isolation self-test: {r:?}"),
                                Err(e) => eprintln!("goatd: isolation self-test error: {e:?}"),
                            }
                            let _ = std::fs::remove_dir_all(scratch);
                        }
                        Err(e) => eprintln!("goatd: isolation self-test scratch error: {e:?}"),
                    }
                }
            }
        }
        Err(isolation::IsolationError::Unavailable(reason)) => {
            eprintln!(
                "goatd: execution isolation UNAVAILABLE — payload execution disabled (fail-closed): {reason}"
            );
        }
        Err(e) => {
            eprintln!("goatd: execution isolation error (fail-closed): {e:?}");
        }
    }

    // Guardrail 1 — a BOUNDED ingress queue.
    let (tx, rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(INGRESS_QUEUE_CAP);
    let dropped = Arc::new(AtomicU64::new(0));

    // Socket reader task — the only producer; never blocks the consensus actor.
    {
        let socket = Arc::clone(&socket);
        let dropped = Arc::clone(&dropped);
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((n, addr)) => {
                        if tx.try_send((buf[..n].to_vec(), addr)).is_err() {
                            dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(e) => eprintln!("goatd: recv error: {e}"),
                }
            }
        });
    }

    // ---- Deliverable 1: the detached egress worker ----
    // The sole owner of outbound `send_to`, fed by a bounded queue. Decoupling egress from the
    // consensus loop removes the head-of-line hazard where awaiting up to `MAX_SESSIONS` sends inline
    // would stall `rx.recv()` and shed inbound consensus traffic (mirrors the ingress reader task).
    let (egress_tx, egress_rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(EGRESS_QUEUE_CAP);
    spawn_egress(Arc::clone(&socket), egress_rx);

    // ---- outbound bootstrap ----
    let (pending_initiation, pending_kem) = if cfg.seed {
        eprintln!("goatd: --seed — genesis orchestrator; waiting passively for inbound handshakes");
        (None, None)
    } else if let Some(peer) = cfg.bootstrap_peer.clone() {
        let (init, eph) = build_initiation(identity, genesis_time);
        spawn_bootstrap(Arc::clone(&socket), peer, encode_initiation_packet(&init));
        (Some(init), Some(eph))
    } else {
        (None, None)
    };

    // The consensus actor is built and driven on a worker thread (large caches off the main stack).
    let consensus = tokio::spawn(consensus_loop(
        egress_tx,
        rx,
        dropped,
        node_secret,
        identity,
        node_id,
        registry,
        genesis_time,
        pending_initiation,
        pending_kem,
        signer,
    ));
    consensus.await.expect("consensus task panicked");
    Ok(())
}

/// Load or derive the ML-DSA-65 signer; refuse if the derived public key ≠ genesis identity.
///
/// Seed precedence (identity-hardening):
/// 1. `GOATD_SIGNING_SEED` (64 hex) — secret, non-derivable; preferred for Alpha / off-host.
/// 2. Deterministic `testnet_signing_seed(node_index)` — **forgeable**; gated by
///    [`testnet_seed_refusal`] (loopback free; non-loopback needs `GOATD_ALLOW_TESTNET_SEEDS=1`;
///    never allowed under production/mainnet).
fn resolve_signer(
    node_index: Option<usize>,
    identity: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
    dev: bool,
    listen: &str,
    is_production: bool,
    is_mainnet: bool,
) -> HostMlDsaSigner {
    let allow_det = allow_testnet_seeds_env();
    let (seed, used_deterministic) = if let Ok(hex) = std::env::var("GOATD_SIGNING_SEED") {
        let s = parse_node_secret_hex(&hex).unwrap_or_else(|| {
            fatal("GOATD_SIGNING_SEED must be 64 hex chars (32-byte ML-DSA seed)");
        });
        (s, false)
    } else if let Some(i) = node_index {
        if i > 255 {
            fatal("node-index too large for testnet seed derivation");
        }
        if let Some(reason) = testnet_seed_refusal(listen, is_production, is_mainnet, allow_det) {
            fatal(format!(
                "deterministic testnet signing seed refused: {reason}. Refusing forgeable identity \
                 on a public-facing bind."
            ));
        }
        (testnet_signing_seed(i as u8), true)
    } else if dev {
        if let Some(reason) = testnet_seed_refusal(listen, is_production, is_mainnet, allow_det) {
            fatal(format!(
                "deterministic testnet signing seed refused: {reason}. Refusing forgeable identity \
                 on a public-facing bind."
            ));
        }
        (testnet_signing_seed(0), true)
    } else {
        fatal(
            "signing seed required: set GOATD_SIGNING_SEED (64 hex secret per node). For lab-only \
             forgeable identities use --node-index with loopback bind, or GOATD_ALLOW_TESTNET_SEEDS=1 \
             on a non-loopback lab bind.",
        );
    };

    if used_deterministic {
        print_forgeable_identity_banner(listen, node_index);
    }

    let signer = HostMlDsaSigner::from_seed(seed);
    let pk = signer.public_key();
    // In accept-all / no-identity mode identity may be zeros — skip mismatch then.
    if identity != [0u8; ML_DSA_65_PUBLIC_KEY_LEN] && pk != identity {
        fatal(
            "signing seed does not match genesis orchestrator public key for this node-index. \
             Regenerate genesis with goat-keygen (random or testnet) or fix GOATD_SIGNING_SEED.",
        );
    }
    if used_deterministic {
        eprintln!(
            "goatd: ML-DSA-65 signing key loaded from DETERMINISTIC testnet seed (forgeable identity)"
        );
    } else {
        eprintln!("goatd: ML-DSA-65 signing key loaded from GOATD_SIGNING_SEED (secret seed)");
    }
    if identity != [0u8; ML_DSA_65_PUBLIC_KEY_LEN] {
        eprintln!("goatd: public key matches genesis identity");
    }
    signer
}

/// Best-effort outbound bootstrap: resolve `peer` (Docker DNS resolves service names) and transmit
/// the `INITIATION`, retrying a bounded number of times. Runs as its own task.
fn spawn_bootstrap(socket: Arc<UdpSocket>, peer: String, packet: Vec<u8>) {
    tokio::spawn(async move {
        // MTU-chunking: fragment the ~3 KB initiation into MTU-safe chunks (DF path).
        let frags = fragment_datagram(&packet, 0xB007_u32); // bootstrap msg id (ephemeral)
        for attempt in 1..=BOOTSTRAP_ATTEMPTS {
            match tokio::net::lookup_host(&peer).await {
                Ok(mut addrs) => match addrs.next() {
                    Some(addr) => {
                        let mut all_ok = true;
                        for frag in &frags {
                            if let Err(e) = socket.send_to(frag, addr).await {
                                eprintln!("goatd: bootstrap send error to {peer}: {e}");
                                all_ok = false;
                                break;
                            }
                        }
                        if all_ok {
                            eprintln!(
                                "goatd: bootstrap → sent HandshakeInitiation ({n} MTU-safe fragment(s)) \
                                 to {peer} ({addr}) [attempt {attempt}/{BOOTSTRAP_ATTEMPTS}]",
                                n = frags.len()
                            );
                            return;
                        }
                    }
                    None => eprintln!("goatd: bootstrap could not resolve {peer}"),
                },
                Err(e) => eprintln!("goatd: bootstrap DNS error for {peer}: {e}"),
            }
            tokio::time::sleep(BOOTSTRAP_RETRY_DELAY).await;
        }
        eprintln!("goatd: bootstrap gave up reaching {peer} after {BOOTSTRAP_ATTEMPTS} attempts");
    });
}

/// Prefer not to rely on IP fragmentation. Outbound logical datagrams are **application-chunked**
/// to ≤ [`MAX_UDP_DATAGRAM`] (MTU-chunking), so a 1500-byte path does not need OS-level fragments.
/// Explicit DF via `setsockopt` is intentionally not wired here (avoids libc/windows-sys deps);
/// the hard guarantee is the chunker + drop-if-oversize in the egress path.
fn set_dont_fragment(_socket: &UdpSocket) {
    // no-op by design — see doc comment.
}

/// The detached egress worker (Deliverable 1) — the **sole** owner of outbound `send_to`. It loops
/// over the bounded egress queue and sends each frame, logging and skipping on error before moving to
/// the next. Isolating every `.await` on the network here (mirroring the ingress socket-reader task)
/// is what lets the consensus loop stay non-blocking under an 8k-session fan-out.
fn spawn_egress(socket: Arc<UdpSocket>, mut egress_rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>) {
    tokio::spawn(async move {
        while let Some((dest, bytes)) = egress_rx.recv().await {
            if let Err(e) = socket.send_to(&bytes, dest).await {
                eprintln!("goatd: egress send error to {dest}: {e}");
            }
        }
    });
}

/// The single consensus actor task (guardrails 2–4). Owns all state; the only `.await`s are message
/// receipt and the GC tick — outbound egress is handed to the detached [`spawn_egress`] worker via a
/// bounded `try_send` (never awaited here), so this loop can never head-of-line-block on the network.
/// The cache-heavy actor is constructed here, on the worker thread, keeping large temporaries off the
/// main-thread stack.
#[allow(clippy::too_many_arguments)]
async fn consensus_loop(
    egress_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    mut rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    dropped: Arc<AtomicU64>,
    node_secret: [u8; 32],
    identity: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
    node_id: [u8; 32],
    registry: StaticKeyRegistry,
    genesis_time: u64,
    pending_initiation: Option<HandshakeInitiation>,
    pending_kem: Option<EphemeralKem>,
    signer: HostMlDsaSigner,
) {
    let mut actor = ConsensusActor::new(
        node_secret,
        identity,
        node_id,
        registry,
        genesis_time,
        CanonicalGossipCodec,
        signer,
    );
    actor.pending_initiation = pending_initiation;
    actor.pending_kem = pending_kem;

    let mut gc = tokio::time::interval(GC_INTERVAL);
    gc.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Aggregate count of outbound frames shed because the egress queue was saturated (surfaced on the
    // GC tick, mirroring the ingress `dropped` counter). Per-packet drops are silent by design.
    let mut egress_dropped: u64 = 0;

    loop {
        tokio::select! {
            biased;

            maybe = rx.recv() => {
                let Some((raw, addr)) = maybe else { break };
                // The consensus transition is fully synchronous (guardrail 2) and returns an egress
                // batch. We hand each packet to the detached egress worker via a bounded `try_send`
                // and NEVER await here, so draining `rx` (inbound consensus) is never blocked by the
                // network. If the egress queue is saturated we DROP the outbound frame: shedding
                // outbound gossip is structurally safe in a decentralized epidemic protocol — every
                // frame travels many redundant relay paths and nodes re-announce, so a lost copy is
                // self-healing — whereas stalling to guarantee delivery would shed *inbound consensus*
                // traffic instead, the head-of-line hazard this decoupling removes.
                // MTU-chunking: expand large logical egress into MTU-safe chunks before send.
                let batch = actor.process(&raw, addr);
                let batch = expand_egress_batch(batch, &mut actor.next_msg_id);
                for (dest, bytes) in batch {
                    debug_assert!(bytes.len() <= MAX_UDP_DATAGRAM || bytes[0] != datagram_framing::CHUNK_TAG);
                    // Unchunked small packets may still be ≤ MAX_UDP_DATAGRAM; chunks always are.
                    if bytes.len() > MAX_UDP_DATAGRAM {
                        // Should not happen after expand; drop rather than IP-fragment.
                        egress_dropped += 1;
                        continue;
                    }
                    if egress_tx.try_send((dest, bytes)).is_err() {
                        egress_dropped += 1;
                    }
                }
            }

            _ = gc.tick() => {
                actor.reassembly.gc(Instant::now());
                let swept = actor.sweep_dead_sessions();
                let dr = dropped.swap(0, Ordering::Relaxed);
                let edr = std::mem::take(&mut egress_dropped);
                if dr >= DROPPED_WARNING_THRESHOLD || edr >= DROPPED_WARNING_THRESHOLD {
                    eprintln!(
                        "goatd: WARN sustained backpressure — shed {dr} ingress + {edr} egress frames \
                         in the last {}s (threshold {DROPPED_WARNING_THRESHOLD}). sessions={} \
                         lru_evicted={} accepted={} rejected={}",
                        GC_INTERVAL.as_secs(),
                        actor.sessions.len(),
                        actor.evicted,
                        actor.accepted,
                        actor.rejected
                    );
                } else if swept > 0 || dr > 0 || edr > 0 || actor.evicted > 0 {
                    eprintln!(
                        "goatd: gc swept {swept} idle sessions; ingress_dropped={dr}; \
                         egress_shed={edr}; lru_evicted={}; sessions={} accepted={} rejected={}",
                        actor.evicted,
                        actor.sessions.len(),
                        actor.accepted,
                        actor.rejected
                    );
                }
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use goat_core::crypto::SignatureVerifier;
    use goat_core::transport::TransportError;
    use goat_core::types::{frame_type, morphology, CHAIN_ID_GOAT_TESTNET};

    /// Genesis anchor used across the actor tests (≤ every `now`, so the floor stays inert).
    const TEST_GENESIS_TIME: u64 = FALLBACK_GENESIS_TIME_UNIX;

    // ---- fixtures ----------------------------------------------------------

    fn actor_pair() -> (
        ConsensusActor<CanonicalGossipCodec>,
        ConsensusActor<CanonicalGossipCodec>,
    ) {
        let a_signer = HostMlDsaSigner::from_seed(testnet_signing_seed(10));
        let b_signer = HostMlDsaSigner::from_seed(testnet_signing_seed(11));
        let a_id = a_signer.public_key();
        let b_id = b_signer.public_key();
        let a = ConsensusActor::new(
            [0x01; 32],
            a_id,
            [0xAA; 32],
            StaticKeyRegistry::accept_all(),
            TEST_GENESIS_TIME,
            CanonicalGossipCodec,
            a_signer,
        );
        let b = ConsensusActor::new(
            [0x02; 32],
            b_id,
            [0xBB; 32],
            StaticKeyRegistry::accept_all(),
            TEST_GENESIS_TIME,
            CanonicalGossipCodec,
            b_signer,
        );
        (a, b)
    }

    fn sample_initiation_for(
        actor: &ConsensusActor<CanonicalGossipCodec>,
    ) -> (HandshakeInitiation, EphemeralKem) {
        let eph = generate_ephemeral_kem();
        let init = HandshakeInitiation {
            initiator_identity: actor.identity,
            ephemeral_kem_pk: eph.ek_bytes,
            epoch: 1,
            local_time: TEST_GENESIS_TIME + 10,
            nonce: [0x33; 32],
        };
        (init, eph)
    }

    fn initiation_packet_for(init: &HandshakeInitiation) -> Vec<u8> {
        encode_initiation_packet(init)
    }

    fn sample_capability_signed(signer: &HostMlDsaSigner, node_id: [u8; 32]) -> GossipMessage {
        let mut caps = BoundedVec::new();
        caps.try_push(DeviceCapability {
            task_class_id: OpaqueTag::from_bytes(b"cls.a.v1").unwrap(),
            measured_gcu_per_hour: 42,
            determinism_profile_ref: [3u8; 32],
        })
        .unwrap();
        let cap = CapabilityRecord {
            node_id,
            epoch: 3,
            beacon_nonce: [1u8; 32],
            prev_record: [2u8; 32],
            capabilities: caps,
            availability_ppm: PPM,
            power_thermal_envelope: PowerThermalEnvelope {
                power_mw: 5,
                thermal_dk: 6,
            },
            density_witness_ppm: PPM,
        };
        let mut buf = [0u8; CAPABILITY_RECORD_MAX_PREIMAGE_LEN];
        let mut sink = SliceSink::new(&mut buf);
        cap.write_signing_preimage(&mut sink).unwrap();
        let signature = signer.sign_ml_dsa_65(sink.written());
        GossipMessage::NodeCapability(SignedRecord {
            payload: cap,
            public_key: signer.public_key(),
            signature,
        })
    }

    fn sample_telemetry_signed(signer: &HostMlDsaSigner) -> GossipMessage {
        let frame = NetworkDensityFrame {
            header: FrameHeader {
                schema_version: 2,
                frame_type: frame_type::NDF,
                endpoint_pseudonym: [9u8; 32],
                identity_index: 0,
                epoch: 5,
                run_nonce: [0u8; 32],
                chain_id: ACTIVE_CHAIN_ID,
            },
            tick_index: 1,
            dl_bin: 10,
            ul_bin: 8,
            concurrent_flag: 1,
            agg_dl_bin: 12,
            agg_ul_bin: 9,
            rtt_q: [20; 8],
            origin_change_count: 0,
            shared_origin_degree_bin: 0,
            xfer_bytes_bin: 30,
            morphology_id: morphology::MORPH_P,
            peak_micro_bin: 14,
            crest_eighth_oct: 4,
            duty_ppm: 800_000,
            throttle_onset_s: 255,
            pre_bin: 0,
            post_bin: 0,
        };
        // Telemetry uses same encode path; sign payload body via encode_gossip_frame's fields.
        // NetworkDensityFrame signing is via the record's preimage in production gossip; for codec
        // tests we only need a well-formed frame — use a zero signature only if not verified.
        // Here we still attach a real signature over the capability-style path isn't available;
        // codec tests only decode bytes and do not verify ML-DSA.
        GossipMessage::TelemetryFrame(SignedRecord {
            payload: frame,
            public_key: signer.public_key(),
            signature: signer.sign_ml_dsa_65(b"telemetry-codec-fixture"),
        })
    }

    fn actor<G: GossipCodec>(codec: G) -> ConsensusActor<G> {
        let signer = HostMlDsaSigner::from_seed(testnet_signing_seed(0));
        let identity = signer.public_key();
        ConsensusActor::new(
            [0u8; 32],
            identity,
            [0u8; 32],
            StaticKeyRegistry::accept_all(),
            TEST_GENESIS_TIME,
            codec,
            signer,
        )
    }

    /// Assert an egress batch holds exactly one packet and return it.
    fn only(batch: Vec<(SocketAddr, Vec<u8>)>) -> (SocketAddr, Vec<u8>) {
        assert_eq!(batch.len(), 1, "expected exactly one egress packet");
        batch.into_iter().next().unwrap()
    }

    // ---- CLI parsing ------------------------------------------------------

    #[test]
    fn parse_args_handles_equals_and_space_forms() {
        let eq = parse_args(
            [
                "--listen=0.0.0.0:4646",
                "--bootstrap-peer=node-0:4646",
                "--node-index=3",
            ]
            .into_iter()
            .map(String::from),
        );
        assert_eq!(eq.listen.as_deref(), Some("0.0.0.0:4646"));
        assert_eq!(eq.bootstrap_peer.as_deref(), Some("node-0:4646"));
        assert_eq!(eq.node_index, Some(3));
        assert!(!eq.seed);

        let sp = parse_args(
            [
                "--listen",
                "127.0.0.1:5000",
                "--genesis",
                "/etc/goatd/genesis.json",
            ]
            .into_iter()
            .map(String::from),
        );
        assert_eq!(sp.listen.as_deref(), Some("127.0.0.1:5000"));
        assert_eq!(sp.genesis_path.as_deref(), Some("/etc/goatd/genesis.json"));
    }

    #[test]
    fn parse_args_seed_and_unknown() {
        let cfg = parse_args(
            ["--seed", "--listen=0.0.0.0:4646", "--frobnicate"]
                .into_iter()
                .map(String::from),
        );
        assert!(cfg.seed);
        assert!(cfg.bootstrap_peer.is_none());
        assert_eq!(cfg.listen.as_deref(), Some("0.0.0.0:4646"));
    }

    #[test]
    fn parse_args_throttle_target_is_captured_raw() {
        // Alpha Pilot advisory flag: captured verbatim (parsed to a percentage only for the log).
        let eq = parse_args(["--throttle-target=0.5"].into_iter().map(String::from));
        assert_eq!(eq.throttle_target.as_deref(), Some("0.5"));
        let sp = parse_args(["--throttle-target", "0.25"].into_iter().map(String::from));
        assert_eq!(sp.throttle_target.as_deref(), Some("0.25"));
    }

    // ---- hex + genesis parsing --------------------------------------------

    #[test]
    fn hex_decode_roundtrip_and_rejects_bad() {
        assert_eq!(decode_hex("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
        assert_eq!(decode_hex("ABcd").unwrap(), vec![0xab, 0xcd]);
        assert!(decode_hex("abc").is_none());
        assert!(decode_hex("zz").is_none());
    }

    #[test]
    fn pubkey_hex_strict_rejects_short_keys() {
        // dev (non-strict): short hex is zero-extended into the fixed buffer.
        let pk = parse_pubkey_hex("c0c0", false).unwrap();
        assert_eq!(&pk[..2], &[0xc0, 0xc0]);
        assert!(pk[2..].iter().all(|&b| b == 0));
        // strict (default / non-dev): short hex is REJECTED — no silent zero-extend (P3).
        assert!(parse_pubkey_hex("c0c0", true).is_none());
        // strict accepts an exactly-1952-byte key.
        assert!(parse_pubkey_hex(&"c0".repeat(ML_DSA_65_PUBLIC_KEY_LEN), true).is_some());
        // over-length is rejected in both modes.
        let too_long = "ab".repeat(ML_DSA_65_PUBLIC_KEY_LEN + 1);
        assert!(parse_pubkey_hex(&too_long, false).is_none());
        assert!(parse_pubkey_hex(&too_long, true).is_none());
    }

    #[test]
    fn node_id_hex_requires_exactly_32_bytes() {
        assert!(parse_node_id_hex(&"11".repeat(32)).is_some());
        assert!(parse_node_id_hex(&"11".repeat(31)).is_none());
        assert!(parse_node_id_hex(&"11".repeat(33)).is_none());
    }

    #[test]
    fn genesis_parses_and_populates_registry() {
        let json = r#"{
            "network": { "name": "x", "genesis_time_unix": 1751846400, "genesis_epoch": 0 },
            "cryptography": { "signature_suite": "ML-DSA-65" },
            "key_registry": {
                "genesis_orchestrators": [
                    { "node_id": "0000000000000000000000000000000000000000000000000000000000000000",
                      "ml_dsa_65_public_key": "c0c0", "stake_micro_usd": 1, "role": "genesis-orchestrator" },
                    { "node_id": "1111111111111111111111111111111111111111111111111111111111111111",
                      "ml_dsa_65_public_key": "c1c1", "role": "genesis-orchestrator" }
                ]
            }
        }"#;
        let g = parse_genesis_str(json, false).expect("valid genesis");
        assert_eq!(g.genesis_time_unix, 1_751_846_400);
        assert_eq!(g.orchestrators.len(), 2);

        let reg = StaticKeyRegistry::from_config(&g);
        let (id0, pk0) = g.orchestrators[0];
        assert!(reg.is_authorized(&pk0, &id0));
        assert!(!reg.is_authorized(&[0xFF; ML_DSA_65_PUBLIC_KEY_LEN], &id0));
        assert!(!reg.is_authorized(&pk0, &[0x99; 32]));
    }

    #[test]
    fn genesis_rejects_bad_pubkey_and_node_id() {
        let bad_id = r#"{ "network": { "genesis_time_unix": 1 },
            "key_registry": { "genesis_orchestrators": [ { "node_id": "00", "ml_dsa_65_public_key": "c0" } ] } }"#;
        assert!(matches!(
            parse_genesis_str(bad_id, true),
            Err(GenesisError::BadNodeId(0))
        ));

        let bad_pk = r#"{ "network": { "genesis_time_unix": 1 },
            "key_registry": { "genesis_orchestrators": [
                { "node_id": "0000000000000000000000000000000000000000000000000000000000000000",
                  "ml_dsa_65_public_key": "PLACEHOLDER" } ] } }"#;
        assert!(matches!(
            parse_genesis_str(bad_pk, true),
            Err(GenesisError::BadPublicKey(0))
        ));

        assert!(matches!(
            parse_genesis_str("{ not json", true),
            Err(GenesisError::Parse)
        ));
    }

    // ---- Track A / P3 + P4: fail-closed startup discipline ----

    #[test]
    fn strict_loader_rejects_short_keys_but_dev_tolerates() {
        let json = r#"{ "network": { "genesis_time_unix": 1, "chain_id_u32": 1621589591 },
            "key_registry": { "genesis_orchestrators": [
                { "node_id": "0000000000000000000000000000000000000000000000000000000000000000",
                  "ml_dsa_65_public_key": "c0c0" } ] } }"#;
        // Default / non-dev is strict: a short (zero-extended) key is rejected — no silent open.
        assert!(matches!(
            parse_genesis_str(json, true),
            Err(GenesisError::BadPublicKey(0))
        ));
        // Dev tolerates it (local experimentation only).
        assert!(parse_genesis_str(json, false).is_ok());
    }

    #[test]
    fn genesis_carries_numeric_chain_id() {
        let json = r#"{ "network": { "genesis_time_unix": 1, "chain_id_u32": 1621589591 },
            "key_registry": { "genesis_orchestrators": [] } }"#;
        assert_eq!(
            parse_genesis_str(json, false).unwrap().chain_id,
            Some(CHAIN_ID_GOAT_TESTNET)
        );
        // Absent when omitted (terse inline fixtures) — main requires it outside dev.
        let bare = r#"{ "network": { "genesis_time_unix": 1 },
            "key_registry": { "genesis_orchestrators": [] } }"#;
        assert_eq!(parse_genesis_str(bare, false).unwrap().chain_id, None);
    }

    #[test]
    fn is_loopback_classifies_bind_addresses() {
        assert!(is_loopback("127.0.0.1:4646"));
        assert!(is_loopback("[::1]:4646"));
        assert!(!is_loopback("0.0.0.0:4646"));
        assert!(!is_loopback("192.168.1.10:4646"));
        assert!(!is_loopback("not-an-addr"));
    }

    #[test]
    fn dev_accept_all_refused_off_the_safe_context() {
        assert!(dev_accept_all_refusal("127.0.0.1:4646", false, false).is_none()); // allowed
        assert!(dev_accept_all_refusal("0.0.0.0:4646", false, false).is_some()); // non-loopback
        assert!(dev_accept_all_refusal("127.0.0.1:4646", true, false).is_some()); // production
        assert!(dev_accept_all_refusal("127.0.0.1:4646", false, true).is_some());
        // mainnet
    }

    #[test]
    fn testnet_seed_refused_off_loopback_without_opt_in() {
        // Loopback + lab: allowed without opt-in.
        assert!(testnet_seed_refusal("127.0.0.1:4646", false, false, false).is_none());
        assert!(testnet_seed_refusal("[::1]:4646", false, false, false).is_none());
        // Non-loopback without opt-in: refused (identity-hardening live-smoke target).
        assert!(testnet_seed_refusal("0.0.0.0:4646", false, false, false).is_some());
        assert!(testnet_seed_refusal("192.168.1.10:4646", false, false, false).is_some());
        // Non-loopback with GOATD_ALLOW_TESTNET_SEEDS opt-in: allowed (lab only).
        assert!(testnet_seed_refusal("0.0.0.0:4646", false, false, true).is_none());
        // Production / mainnet: always refused even with opt-in.
        assert!(testnet_seed_refusal("127.0.0.1:4646", true, false, true).is_some());
        assert!(testnet_seed_refusal("127.0.0.1:4646", false, true, true).is_some());
        assert!(testnet_seed_refusal("0.0.0.0:4646", true, false, true).is_some());
    }

    #[test]
    fn chain_id_agreement_is_fail_closed() {
        let t = CHAIN_ID_GOAT_TESTNET;
        let m = CHAIN_ID_GOAT_MAINNET;
        assert!(chain_id_ok(Some(t), t, false).is_ok()); // genesis matches binary
        assert!(chain_id_ok(Some(m), t, false).is_err()); // testnet binary, mainnet genesis → refuse
        assert!(chain_id_ok(None, t, false).is_err()); // missing declaration outside dev → refuse
        assert!(chain_id_ok(None, t, true).is_ok()); // dev tolerates a missing declaration
    }

    #[test]
    fn node_secret_requires_exactly_32_bytes() {
        assert!(parse_node_secret_hex(&"ab".repeat(32)).is_some());
        assert!(parse_node_secret_hex(&"ab".repeat(31)).is_none());
        assert!(parse_node_secret_hex(&"ab".repeat(33)).is_none());
        assert!(parse_node_secret_hex("zz").is_none());
        // surrounding whitespace (file with trailing newline) is trimmed.
        assert!(parse_node_secret_hex(&format!("  {}\n", "cd".repeat(32))).is_some());
    }

    // ---- Track C: real ML-DSA + AES-GCM ------------------------------------

    #[test]
    fn host_signer_roundtrips_and_rejects_tamper() {
        let signer = HostMlDsaSigner::from_seed(testnet_signing_seed(7));
        let pk = signer.public_key();
        let msg = b"any preimage bytes";
        let sig = signer.sign_ml_dsa_65(msg);
        assert!(HostMlDsaVerifier.verify_ml_dsa_65(&pk, msg, &sig));
        let mut bad = sig;
        bad[0] ^= 0xFF;
        assert!(!HostMlDsaVerifier.verify_ml_dsa_65(&pk, msg, &bad));
        assert!(!HostMlDsaVerifier.verify_ml_dsa_65(&pk, b"other", &sig));
    }

    #[test]
    fn cookie_echo_is_signed_real_mldsa() {
        let mut initiator = actor(CanonicalGossipCodec);
        let (init, eph) = sample_initiation_for(&initiator);
        initiator.pending_initiation = Some(init);
        initiator.pending_kem = Some(eph);
        let mut reply = vec![REPLY_TAG_COOKIE_CHALLENGE];
        reply.extend_from_slice(&[0xAB; 32]);
        reply.extend_from_slice(&123u64.to_le_bytes());
        let addr: SocketAddr = "10.0.0.9:4646".parse().unwrap();

        let (dest, echo) = only(initiator.process(&reply, addr));
        assert_eq!(dest, addr);
        assert_eq!(echo[0], packet_tag::COOKIE_ECHO);
        // Trailing signature is a real ML-DSA-65 sig (not constant 0x42 fill).
        let sig = &echo[echo.len() - ML_DSA_65_SIGNATURE_LEN..];
        assert!(!sig.iter().all(|&b| b == 0x42));
        // Session opens only after RESPONSE (initiator does not open on cookie echo).
        assert!(initiator.sessions.is_empty());
    }

    // ---- Deliverable 2: the canonical codec -------------------------------

    #[test]
    fn codec_roundtrips_signed_capability() {
        let signer = HostMlDsaSigner::from_seed(testnet_signing_seed(3));
        let msg = sample_capability_signed(&signer, [7u8; 32]);
        let bytes = encode_gossip_frame(&msg).expect("encode");
        let decoded = CanonicalGossipCodec.decode(&bytes).expect("decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn codec_roundtrips_signed_telemetry() {
        let signer = HostMlDsaSigner::from_seed(testnet_signing_seed(3));
        let msg = sample_telemetry_signed(&signer);
        let bytes = encode_gossip_frame(&msg).expect("encode");
        let decoded = CanonicalGossipCodec.decode(&bytes).expect("decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn codec_rejects_empty_unknown_trailing_and_truncated() {
        assert!(CanonicalGossipCodec.decode(&[]).is_none());
        assert!(CanonicalGossipCodec.decode(&[0xFF, 0, 0, 0]).is_none()); // unknown variant
        let signer = HostMlDsaSigner::from_seed(testnet_signing_seed(3));
        let good = encode_gossip_frame(&sample_capability_signed(&signer, [1u8; 32])).unwrap();
        let mut trailing = good.clone();
        trailing.push(0); // one extra byte ⇒ ambiguous framing
        assert!(CanonicalGossipCodec.decode(&trailing).is_none());
        assert!(CanonicalGossipCodec
            .decode(&good[..good.len() - 10])
            .is_none()); // truncated
    }

    // ---- backend + session plumbing ---------------------------------------

    #[test]
    fn aes_channel_round_trips_and_rejects_tamper() {
        let key = [7u8; 32];
        let mut enc = Aes256GcmChannel::new(key, ChannelRole::Initiator);
        let mut dec = Aes256GcmChannel::new(key, ChannelRole::Responder);
        let pt = b"goatcoin secure frame";
        let mut framed = [0u8; 128];
        let n = enc.encrypt_frame(pt, &mut framed).unwrap();
        let mut back = [0u8; 128];
        let m = dec.decrypt_frame(&framed[..n], &mut back).unwrap();
        assert_eq!(&back[..m], pt);

        let mut dec2 = Aes256GcmChannel::new(key, ChannelRole::Responder);
        framed[n - 1] ^= 0xFF;
        assert_eq!(
            dec2.decrypt_frame(&framed[..n], &mut back),
            Err(TransportError::DecryptionFailed)
        );
    }

    #[test]
    fn peer_addr_bytes_distinguishes_ports() {
        let a: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let b: SocketAddr = "10.0.0.1:2000".parse().unwrap();
        assert_ne!(peer_addr_bytes(&a), peer_addr_bytes(&b));
    }

    #[test]
    fn initiation_yields_a_cookie_reply_and_no_session() {
        let mut act = actor(CanonicalGossipCodec);
        let (init, _) = sample_initiation_for(&act);
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let (dest, reply) = only(act.process(&initiation_packet_for(&init), addr));
        assert_eq!(dest, addr);
        assert_eq!(reply[0], REPLY_TAG_COOKIE_CHALLENGE);
        assert_eq!(reply.len(), 1 + 32 + 8);
        assert!(act.sessions.is_empty());
    }

    #[test]
    fn dead_session_is_swept() {
        let mut act = actor(CanonicalGossipCodec);
        let addr: SocketAddr = "127.0.0.1:6000".parse().unwrap();
        let mut s = Session::new(Aes256GcmChannel::scratch());
        s.last_seen = Instant::now() - SESSION_IDLE_TIMEOUT - Duration::from_secs(1);
        act.sessions.insert(addr, s);
        assert_eq!(act.sweep_dead_sessions(), 1);
        assert!(act.sessions.is_empty());
    }

    #[test]
    fn session_map_is_lru_bounded() {
        let mut act = actor(CanonicalGossipCodec);
        let base = Instant::now();
        for i in 0..MAX_SESSIONS {
            let addr: SocketAddr = format!("10.0.0.1:{}", 1000 + i).parse().unwrap();
            let mut s = Session::new(Aes256GcmChannel::scratch());
            s.last_seen = base + Duration::from_secs(i as u64);
            act.insert_session_bounded(addr, s);
        }
        assert_eq!(act.sessions.len(), MAX_SESSIONS);
        let lru: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        assert!(act.sessions.contains_key(&lru));

        let newcomer: SocketAddr = "10.0.0.2:9999".parse().unwrap();
        act.insert_session_bounded(newcomer, Session::new(Aes256GcmChannel::scratch()));
        assert_eq!(act.sessions.len(), MAX_SESSIONS);
        assert!(!act.sessions.contains_key(&lru));
        assert!(act.sessions.contains_key(&newcomer));
        assert_eq!(act.evicted, 1);
    }

    #[test]
    fn client_ignores_cookie_challenge_without_pending() {
        let mut seed = actor(CanonicalGossipCodec);
        let addr: SocketAddr = "127.0.0.1:4646".parse().unwrap();
        let mut reply = vec![REPLY_TAG_COOKIE_CHALLENGE];
        reply.extend_from_slice(&[0u8; 32]);
        reply.extend_from_slice(&0u64.to_le_bytes());
        assert!(seed.process(&reply, addr).is_empty());
        assert!(seed.sessions.is_empty());
    }

    // ---- full data plane: handshake + signed gossip exchange (two actors) --

    #[test]
    fn handshake_and_gossip_round_trip_api_contract() {
        full_data_plane_handshake_and_signed_gossip_exchange_body();
    }

    #[test]
    fn full_data_plane_handshake_and_signed_gossip_exchange() {
        full_data_plane_handshake_and_signed_gossip_exchange_body();
    }

    fn full_data_plane_handshake_and_signed_gossip_exchange_body() {
        let (mut initiator, mut responder) = actor_pair();
        let (init, eph) = sample_initiation_for(&initiator);
        initiator.pending_initiation = Some(init.clone());
        initiator.pending_kem = Some(eph);

        let a_addr: SocketAddr = "10.0.0.11:4646".parse().unwrap();
        let b_addr: SocketAddr = "10.0.0.10:4646".parse().unwrap();

        // (1) responder issues a stateless cookie for the initiation.
        let (d1, cookie_reply) = only(responder.process(&initiation_packet_for(&init), a_addr));
        assert_eq!(d1, a_addr);
        assert_eq!(cookie_reply[0], REPLY_TAG_COOKIE_CHALLENGE);

        // (2) initiator answers with a SIGNED cookie echo (session not yet open).
        let (d2, echo) = only(initiator.process(&cookie_reply, b_addr));
        assert_eq!(d2, b_addr);
        assert_eq!(echo[0], packet_tag::COOKIE_ECHO);
        assert!(initiator.sessions.is_empty());

        // (3) responder verifies, emits RESPONSE + SecureFrame capability.
        let batch = responder.process(&echo, a_addr);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].1[0], packet_tag::RESPONSE);
        assert_eq!(batch[1].1[0], packet_tag::SECURE_FRAME);
        assert_eq!(responder.sessions.len(), 1);

        // (4) initiator processes RESPONSE → opens session; then SecureFrame → caches + replies.
        assert!(initiator.process(&batch[0].1, b_addr).is_empty());
        assert_eq!(initiator.sessions.len(), 1);
        let seen0 = initiator.node.seen_messages();
        let (d4, init_gossip) = only(initiator.process(&batch[1].1, b_addr));
        assert_eq!(d4, b_addr);
        assert_eq!(init_gossip[0], packet_tag::SECURE_FRAME);
        assert_eq!(initiator.node.seen_messages(), seen0 + 1);

        // (5) responder decrypts initiator capability; already replied ⇒ empty batch.
        let seenr = responder.node.seen_messages();
        assert!(responder.process(&init_gossip, a_addr).is_empty());
        assert_eq!(responder.node.seen_messages(), seenr + 1);
    }

    /// MTU-chunking: handshake over **chunked** ingress (simulates ≤1200 B UDP path / 1500 MTU).
    #[test]
    fn handshake_survives_mtu_safe_chunking() {
        let (mut initiator, mut responder) = actor_pair();
        let (init, eph) = sample_initiation_for(&initiator);
        initiator.pending_initiation = Some(init.clone());
        initiator.pending_kem = Some(eph);

        let a_addr: SocketAddr = "10.0.0.21:4646".parse().unwrap();
        let b_addr: SocketAddr = "10.0.0.20:4646".parse().unwrap();

        let init_pkt = initiation_packet_for(&init);
        assert!(init_pkt.len() > MAX_UDP_DATAGRAM);
        let frags = fragment_datagram(&init_pkt, 7);
        assert!(frags.len() > 1);
        assert!(frags.iter().all(|f| f.len() <= MAX_UDP_DATAGRAM));

        let mut cookie_reply = None;
        for f in &frags {
            let batch = responder.process(f, a_addr);
            if !batch.is_empty() {
                cookie_reply = Some(only(batch));
            }
        }
        let (d1, cookie_reply) = cookie_reply.expect("cookie after full initiation reassembly");
        assert_eq!(d1, a_addr);
        assert_eq!(cookie_reply[0], REPLY_TAG_COOKIE_CHALLENGE);

        let (d2, echo) = only(initiator.process(&cookie_reply, b_addr));
        assert_eq!(d2, b_addr);
        let echo_frags = fragment_datagram(&echo, 8);
        assert!(echo_frags.len() > 1);

        let mut resp_batch = Vec::new();
        for f in &echo_frags {
            let b = responder.process(f, a_addr);
            if !b.is_empty() {
                resp_batch = b;
            }
        }
        assert_eq!(resp_batch.len(), 2);
        assert_eq!(resp_batch[0].1[0], packet_tag::RESPONSE);
        assert_eq!(resp_batch[1].1[0], packet_tag::SECURE_FRAME);

        let mut mid = 100u32;
        let expanded = expand_egress_batch(resp_batch, &mut mid);
        assert!(expanded.iter().all(|(_, p)| p.len() <= MAX_UDP_DATAGRAM));

        for (_dest, frag) in expanded {
            let _ = initiator.process(&frag, b_addr);
        }
        assert_eq!(initiator.sessions.len(), 1);
        assert!(initiator.node.seen_messages() >= 1);
    }

    // Unauthorized-origin gossip is dropped (fail-closed), not cached, when the registry is populated.
    #[test]
    fn gossip_from_unauthorized_origin_is_dropped() {
        let auth_signer = HostMlDsaSigner::from_seed(testnet_signing_seed(20));
        let bad_signer = HostMlDsaSigner::from_seed(testnet_signing_seed(21));
        let auth_pk = auth_signer.public_key();
        let mut g = GenesisConfig {
            genesis_time_unix: TEST_GENESIS_TIME,
            chain_id: None,
            orchestrators: Vec::new(),
        };
        g.orchestrators.push(([0xBB; 32], auth_pk));
        let registry = StaticKeyRegistry::from_config(&g);

        let mut node = ConsensusActor::new(
            [0x05; 32],
            auth_pk,
            [0xBB; 32],
            registry,
            TEST_GENESIS_TIME,
            CanonicalGossipCodec,
            auth_signer,
        );
        let addr: SocketAddr = "10.0.0.20:4646".parse().unwrap();
        let key = [0x5A; 32];
        node.sessions.insert(
            addr,
            Session::new(Aes256GcmChannel::new(key, ChannelRole::Responder)),
        );

        // Unauthorized: real signature under bad_signer's key, node_id 0x77 not in registry.
        let msg = sample_capability_signed(&bad_signer, [0x77; 32]);
        let plaintext = encode_gossip_frame(&msg).unwrap();
        let mut enc = Aes256GcmChannel::new(key, ChannelRole::Initiator);
        let secure = encode_secure_frame(&mut enc, &plaintext).unwrap();

        let before = node.node.seen_messages();
        assert!(node.process(&secure, addr).is_empty());
        assert_eq!(node.node.seen_messages(), before);
        assert_eq!(node.rejected, 1);
    }

    // ---- epidemic re-broadcast ------------------------------------------------

    #[test]
    fn epidemic_fanout_forwards_to_other_sessions_but_not_sender() {
        let fan_signer = HostMlDsaSigner::from_seed(testnet_signing_seed(30));
        let mut seed = ConsensusActor::new(
            [0x02; 32],
            fan_signer.public_key(),
            [0xBB; 32],
            StaticKeyRegistry::accept_all(),
            TEST_GENESIS_TIME,
            CanonicalGossipCodec,
            HostMlDsaSigner::from_seed(testnet_signing_seed(31)),
        );
        let node1: SocketAddr = "10.0.0.1:4646".parse().unwrap();
        let node2: SocketAddr = "10.0.0.2:4646".parse().unwrap();
        let node3: SocketAddr = "10.0.0.3:4646".parse().unwrap();

        // Seed is Responder toward all peers; each peer encrypts as Initiator with same key.
        // For fan-out re-encrypt, seed's sessions use Responder role. Crafted inbound from node1
        // uses Initiator encrypt so seed (Responder) can decrypt.
        let key = [0x5A; 32];
        for a in [node1, node2, node3] {
            let mut s = Session::new(Aes256GcmChannel::new(key, ChannelRole::Responder));
            s.sent_capability = true;
            seed.sessions.insert(a, s);
        }

        let msg = sample_capability_signed(&fan_signer, [0x11; 32]);
        let plaintext = encode_gossip_frame(&msg).unwrap();
        let mut enc = Aes256GcmChannel::new(key, ChannelRole::Initiator);
        let secure = encode_secure_frame(&mut enc, &plaintext).unwrap();

        let seen_before = seed.node.seen_messages();
        let batch = seed.process(&secure, node1);

        assert_eq!(seed.node.seen_messages(), seen_before + 1);
        assert_eq!(batch.len(), 2);
        let dests: Vec<SocketAddr> = batch.iter().map(|(d, _)| *d).collect();
        assert!(dests.contains(&node2));
        assert!(dests.contains(&node3));
        assert!(!dests.contains(&node1));

        let (_, fwd) = batch.iter().find(|(d, _)| *d == node2).unwrap();
        assert_eq!(fwd[0], packet_tag::SECURE_FRAME);
        // Peer node2 would decrypt as Initiator (seed encrypted as Responder).
        let mut dec = Aes256GcmChannel::new(key, ChannelRole::Initiator);
        let mut out = vec![0u8; MAX_DATAGRAM];
        let m = dec.decrypt_frame(&fwd[1..], &mut out).unwrap();
        assert_eq!(&out[..m], plaintext.as_slice());
        assert_eq!(CanonicalGossipCodec.decode(&out[..m]).unwrap(), msg);

        // Replay: nonce already consumed on node1's session → decrypt fails → rejected, not re-fanned.
        let batch2 = seed.process(&secure, node1);
        assert!(batch2.is_empty());
        assert_eq!(seed.node.seen_messages(), seen_before + 1);
    }
}
