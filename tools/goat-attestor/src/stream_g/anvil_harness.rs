//! Live-Anvil integration harness for Stream G (Task 9, Wave A).
//!
//! # Why this exists
//!
//! Before this module there was **no** Rust harness that talked to a real
//! node: `tests/integration.rs` drives [`crate::chain::MockChain`], and the
//! three pre-existing `#[ignore]`d tests in `rpc_chain.rs` each hand-roll a
//! config map and assume something is already listening on `RPC_URL`. (One of
//! those three, `rpc_chain_anvil_smoke`, turned out to assert nothing at all
//! and to pass with no node listening; Wave 1 gave it three live round-trip
//! assertions. Treat the "precedent" this paragraph cites accordingly.) Six
//! Stream G reads on [`RpcChain`] — `fee_token_code_hash`,
//! `fee_token_config`, `fee_token_config_hash`, `active_manifest_hash`,
//! `secondary_enrollment_nonce_snapshot`, `pinned_block_number` — therefore
//! had **zero** coverage of the half that only a node can exercise: the
//! `eth_call`/`eth_getCode` round-trip and alloy's decode of the answer.
//! `rpc_chain.rs`'s own doc says so in those words.
//!
//! This harness closes that: it starts its own Anvil, deploys Stream G onto
//! it with the repository's existing Foundry script, and hands back a real
//! [`RpcChain`] pointed at it.
//!
//! # Deliberate properties
//!
//! * **Its own node, on an ephemeral port.** [`AnvilHarness`] never uses
//!   `8545`; it asks the OS for a free port and asserts the result is not the
//!   default, so a running pilot/dev Anvil is neither required nor disturbed.
//!   Set `GOAT_ANVIL_RPC_URL` to attach to an already-running node instead
//!   (debugging only — the harness then does not own, and will not kill, it).
//! * **Reaped on drop.** The spawned child is killed and waited on in
//!   [`AnvilProcess::drop`], including when a test panics (the test profile
//!   unwinds), so a failed assertion does not leak an Anvil. Field order in
//!   [`AnvilHarness`] matters: the node is dropped *before* the process-wide
//!   lock is released.
//! * **Serialized.** All harness use takes [`HARNESS_LOCK`], because
//!   `forge script` writes shared paths under `contracts/` (`broadcast/`,
//!   `cache/`, `deployments/`) and `cargo test` runs tests concurrently.
//! * **Pilot artifacts never opened.** `DeployStreamG.run()` rewrites
//!   `contracts/deployments/31337.stream-g.json` and the payload document
//!   beside it — committed files that `forge test` and any operator-run
//!   `forge script` also write. [`deploy_stream_g`] therefore hands the deploy
//!   a private `STREAM_G_DEPLOYMENTS_DIR` (a `tempfile::TempDir`) and reads
//!   back from there. It used to snapshot-and-restore the committed pair
//!   instead, which is shared mutable state across processes that
//!   [`HARNESS_LOCK`] cannot serialise; the read-back silently returned the
//!   COMMITTED lab manifest in ~1 run of the suite in 4, and the tests then ran
//!   against addresses that do not exist on this node. See
//!   [`deploy_stream_g`]'s doc for the measurements. `broadcast/` and `cache/`
//!   are gitignored.
//! * **Real deployment, not a hand-rolled one.** The addresses come from
//!   `contracts/script/DeployStreamG.s.sol`, the same script the G1 plan
//!   documents, run with `--broadcast` against the harness node.
//!
//! # Two facts about the deploy that are not obvious
//!
//! 1. **`--disable-code-size-limit` was load-bearing, then wasn't, and is now
//!    gone.** The original text here (kept, not deleted, so the reasoning is
//!    auditable) read:
//!
//!    > **`--disable-code-size-limit` is no longer load-bearing.** It used to
//!    > be: `GoatRelayGateway`'s runtime was 33,914 bytes against EIP-170's
//!    > 24,576 (a margin of **-9,338**), so the gateway could not be deployed
//!    > to any EIP-170-enforcing chain and the flag was the only reason this
//!    > harness worked. The EIP-170 refactor moved the four `execute*` bodies
//!    > into `public` libraries reached by `DELEGATECALL`; the gateway is now
//!    > **12,944 bytes** (margin **+11,632**) and `forge build --sizes` exits
//!    > 0. The flag is kept because it only *lifts* a check — it can never
//!    > make a legal deployment fail — but the Base-Sepolia size blocker is
//!    > gone.
//!
//!    That is all still true as far as it goes, and it is **not** a
//!    claims-vs-code defect: lifting a check genuinely cannot make a legal
//!    deployment fail. But it left the *consequence* unstated. With the flag
//!    on, EIP-170 was unenforced on the harness node and unenforced in
//!    `forge script`, so a future edit pushing a Stream G contract back over
//!    24,576 bytes would have left all of the `#[ignore]`d tests **green**
//!    while shipping something Base Sepolia will refuse to accept. The safety
//!    the refactor bought was invisible to the only suite that exercises a
//!    real deploy.
//!
//!    **Wave 1 (2026-07-25) therefore dropped the flag from both call sites**
//!    — [`spawn_anvil`] and [`deploy_stream_g`] — turning this suite into a
//!    standing EIP-170 regression guard. Nothing needed to change to make that
//!    work: the largest runtime this harness actually deploys is `StreamGXfer`
//!    at 15,004 bytes, every `anvil_setCode` payload is ≤5,214 bytes, and all
//!    tests in this module pass unchanged against a node that enforces the
//!    limit. (Wave D2 added a seventeenth, which deploys nothing new.)
//!    Re-measure with `forge build --sizes` rather than trusting these
//!    numbers; `run-full-gate.ps1` asserts the gateway's size independently of
//!    that command's exit status.
//! 2. **`--sender` must match the broadcast key.** `run()` defaults
//!    `policySafe`/`deskOwner` to `msg.sender`, and the post-deploy
//!    configuration is gated on those addresses. Passing `--private-key`
//!    without `--sender` leaves `msg.sender` at Foundry's default sender and
//!    every gated call reverts `NotPolicySafe()`.
//!
//! # Not weakened for convenience
//!
//! Nothing here relaxes [`super::token_manifest::TrustedChain`]. Tests obtain
//! one the production way — `TrustedChain::live(&RpcChain)` — from the
//! harness's real [`RpcChain`].

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::chain::parse_address20;
use crate::rpc_chain::RpcChain;

/// Anvil's well-known dev account #0 — funded at genesis. Same key the
/// pre-existing `#[ignore]`d tests in `rpc_chain.rs` use.
pub(crate) const ANVIL_DEPLOYER_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Address of [`ANVIL_DEPLOYER_KEY`]. Passed as `--sender` so `run()`'s
/// `msg.sender`-derived `policySafe`/`deskOwner` match the broadcast wallet.
pub(crate) const ANVIL_DEPLOYER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

/// The port the harness must never take — a pilot or dev node may own it.
const DEFAULT_NODE_PORT: u16 = 8545;

/// How long [`AnvilHarness::receipt_when_mined`] waits for a broadcast
/// transaction to appear in a block, and how long it sleeps between asks.
///
/// 30s matches what [`AnvilHarness::send_from_deployer`] and
/// [`AnvilHarness::send_from`] have always used. It is a *ceiling on a bug*,
/// not an expected wait: on an idle machine the first poll wins. The number
/// exists because a gate step that hangs forever is strictly worse than one
/// that fails, and because the two failures this replaced happened while other
/// work was saturating the same machine — the interval has to survive a
/// scheduler that is not giving anvil a slice, and 600 asks at 50 ms is the
/// budget for that.
const RECEIPT_POLL_TIMEOUT: Duration = Duration::from_secs(30);
const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Ceiling on one `forge` invocation issued by this harness.
///
/// Same reasoning as [`RECEIPT_POLL_TIMEOUT`] — a ceiling on a bug, not an
/// expected duration — but with a specific bug in view. `forge script … --broadcast`
/// talks to the node, and a node that stops answering takes forge down with
/// it: with the harness's own anvil suspended mid-deploy, `forge` was measured
/// still running, burning **zero CPU and printing nothing, at 200.9s**, and it
/// resumed to exit 0 only when the node was unfrozen. `Command::output()` has
/// no timeout, so that state is indefinite, and the enclosing gate step's
/// watchdog reports it as an anonymous killed process tree
/// (`rustup / cargo / goat_attestor / anvil / forge`) rather than as a
/// diagnosis.
///
/// 300s is ~120× the slowest of 150 measured unwedged `forge script`
/// deploys (mean 1.00s, max 2.45s), leaves room for a cold `solc` build in a
/// standalone `cargo test -- --ignored` run, and is still 4× under the gate's
/// 1200s step budget — so the step fails with a named cause instead of being
/// killed from outside.
const FORGE_TIMEOUT: Duration = Duration::from_secs(300);

/// Ceiling on one `cast` invocation. `cast calldata` is pure local ABI
/// encoding — it opens no socket and takes no node — so unlike
/// [`FORGE_TIMEOUT`] this cannot be waiting on a wedged peer, and 60s is
/// already absurd for it. It is bounded anyway so that no `Command` in this
/// file is the one that can wait forever.
const CAST_TIMEOUT: Duration = Duration::from_secs(60);

/// Serializes harness use across the concurrently-run test binary; see the
/// module doc. Poison is deliberately ignored: a panicking test still leaves
/// the shared `contracts/` paths consistent, because [`deploy_stream_g`]
/// restores them before it can panic.
static HARNESS_LOCK: Mutex<()> = Mutex::new(());

/// `contracts/deployments/31337.stream-g.json` as `DeployStreamG.writeManifest`
/// emits it. Only the fields this harness actually hands to tests.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StreamGDeployment {
    pub chain_id: u64,
    pub phase: String,
    pub enrollment_registry: String,
    pub goat_coin: String,
    pub fee_token: String,
    pub fee_token_registry: String,
    pub goat_relay_gateway: String,
    pub deployment_manifest_hash: String,
    // -- Wave D ---------------------------------------------------------
    // Everything a real `DeploymentManifest` needs that Waves A-C did not.
    // All five are written by `DeployStreamG.writeManifest` already; they
    // were simply not deserialized before.
    pub wallet_sponsorship_registry: String,
    pub sponsored_buy_desk: String,
    pub policy_safe: String,
    pub fee_safe: String,
    pub recovery_safe: String,
    pub desk_owner: String,
    pub quote_signer: String,
    pub fee_schedule_hash: String,
}

/// Owns the spawned node so that `Drop` reaps it on every exit path,
/// including a panicking assertion.
struct AnvilProcess(Option<Child>);

impl Drop for AnvilProcess {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// A live Anvil with Stream G deployed onto it.
///
/// Field order is load-bearing, in **two** places. Rust drops fields in
/// declaration order, so:
///
/// 1. `_forensics` runs first, while the node is still alive — a probe taken
///    after `_node` reaped anvil would report NO ANSWER unconditionally and
///    would be worse than no probe at all, because it would look like evidence.
/// 2. The node is killed *before* [`HARNESS_LOCK`] is released, so the next
///    test cannot start against a half-dead node.
///
/// Moving `_forensics` below `_node` compiles, passes, and silently destroys
/// the only measurement this suite takes of the stall it is chasing.
pub(crate) struct AnvilHarness {
    /// Never read — held purely so its `Drop` runs, and only when the scope is
    /// left by an unwinding panic. See [`PanicForensics`].
    _forensics: PanicForensics,
    /// Never read — held purely so its `Drop` runs. Underscore-prefixed
    /// fields are ordinary fields (unlike a bare `_` binding), so this is
    /// still dropped, and still dropped *first*.
    _node: AnvilProcess,
    _lock: MutexGuard<'static, ()>,
    rpc_url: String,
    port: u16,
    deployment: Option<StreamGDeployment>,
}

impl AnvilHarness {
    /// Node + Stream G deployment. Panics with the captured `forge` output if
    /// anything fails — an integration test that silently degrades to a
    /// no-op is exactly the vacuous proof this suite exists to avoid.
    pub(crate) fn start() -> Self {
        let mut h = Self::start_node_only();
        h.deployment = Some(deploy_stream_g(&h.rpc_url));
        h
    }

    /// Node only — no `forge script`. Used by the harness's own lifecycle
    /// test, where a deploy would add ~10s and prove nothing extra.
    pub(crate) fn start_node_only() -> Self {
        let lock = HARNESS_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let (rpc_url, port, child) = match std::env::var("GOAT_ANVIL_RPC_URL") {
            Ok(url) if !url.is_empty() => (url, 0u16, None),
            _ => {
                let port = free_port();
                let child = spawn_anvil(port);
                (format!("http://127.0.0.1:{port}"), port, Some(child))
            }
        };

        let harness = Self {
            _forensics: PanicForensics::new(&rpc_url),
            _node: AnvilProcess(child),
            _lock: lock,
            rpc_url,
            port,
            deployment: None,
        };
        harness.wait_until_ready();
        harness
    }

    pub(crate) fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// 0 when attached to an external node via `GOAT_ANVIL_RPC_URL`.
    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn deployment(&self) -> &StreamGDeployment {
        self.deployment
            .as_ref()
            .expect("AnvilHarness::start_node_only() has no deployment; use start()")
    }

    /// A **real** [`RpcChain`] against this node.
    ///
    /// `chain_id` is the value written into `CHAIN_ID`, i.e. the config field
    /// `RpcChain` already holds — deliberately a caller's choice so a test can
    /// set it to something the node will *not* echo back and prove
    /// `RpcChain::chain_id()` is a live read rather than a config read.
    pub(crate) fn rpc_chain(&self, chain_id: u64) -> RpcChain {
        self.rpc_chain_inner(chain_id, None)
    }

    /// [`Self::rpc_chain`] **plus** `STREAM_G_BROADCASTER_PRIVATE_KEY`, so that
    /// the *production* signer — [`super::broadcaster::RpcChainEnrollmentSigner`]
    /// — can be constructed against this node.
    ///
    /// Every Wave D test before D2 used `WaveDSigner`, a double that returns
    /// deliberately invalid bytes so the node refuses the send. That is the
    /// right double for the outbox-coherence tests, and exactly the wrong one
    /// for a lifecycle proof: a transaction that never lands emits no
    /// `SponsoredEnrollmentExecuted`, so there is nothing for reconciliation to
    /// observe. This constructor is what lets a test sign with the real signer,
    /// broadcast through the real `eth_sendRawTransaction`, and have the gateway
    /// really execute.
    ///
    /// `STREAM_G_ENABLED` is **not** set here and must not be: `config.rs`'s
    /// `build_stream_g_config` only *requires* the four Stream G keys when the
    /// flag is on, and it accepts (and parses) the broadcaster key regardless.
    /// So this adds a signing key without turning any lane on — the flag stays
    /// the founder's.
    pub(crate) fn rpc_chain_with_broadcaster(&self, chain_id: u64, key: &str) -> RpcChain {
        self.rpc_chain_inner(chain_id, Some(key))
    }

    fn rpc_chain_inner(&self, chain_id: u64, broadcaster_key: Option<&str>) -> RpcChain {
        let d = self.deployment();
        let mut m = std::collections::HashMap::new();
        m.insert("RPC_URL".to_string(), self.rpc_url.clone());
        m.insert("CHAIN_ID".to_string(), chain_id.to_string());
        if let Some(key) = broadcaster_key {
            m.insert(
                "STREAM_G_BROADCASTER_PRIVATE_KEY".to_string(),
                key.to_string(),
            );
        }
        // The pilot's three addresses are not what Stream G reads; point them
        // at real deployed contracts anyway so nothing in `from_config` has to
        // tolerate a placeholder.
        m.insert(
            "EPOCH_SETTLEMENT_ADDRESS".to_string(),
            d.goat_relay_gateway.clone(),
        );
        m.insert("WORKER_BINDING_ADDRESS".to_string(), d.goat_coin.clone());
        m.insert(
            "ENROLLMENT_REGISTRY_ADDRESS".to_string(),
            d.enrollment_registry.clone(),
        );
        m.insert("REGISTRY_JSON".to_string(), "./registry.json".to_string());
        let cfg = crate::config::load_from_map(&m).expect("harness config must load");
        RpcChain::from_config(&cfg).expect("harness RpcChain must construct")
    }

    /// A JSON-RPC round-trip that does **not** go through [`RpcChain`].
    ///
    /// Every cross-check in this suite needs a second, independent source;
    /// re-reading a value through the code under test would be the `x == x`
    /// shape the whole task exists to avoid.
    pub(crate) fn raw_rpc(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        json_rpc(&self.rpc_url, method, params)
    }

    // -- Wave B: live-state manipulation + independent chain reads ---------
    //
    // Everything below issues raw JSON-RPC through [`Self::raw_rpc`], i.e.
    // `reqwest` + hand-built calldata, sharing no code path with `RpcChain`.
    // That is deliberate: these are the *second source* every assertion in
    // the hazard-3 tests is cross-checked against, and a second source that
    // reuses the decoder under test is not a second source.

    /// `eth_getCode(address, block)` — the raw bytes, not a hash.
    pub(crate) fn code_at(&self, address: &str, block: u64) -> Vec<u8> {
        let raw = self
            .raw_rpc(
                "eth_getCode",
                serde_json::json!([address, format!("0x{block:x}")]),
            )
            .unwrap_or_else(|e| panic!("independent eth_getCode({address} @ {block}): {e}"));
        hex_bytes(raw.as_str().expect("eth_getCode returns a hex string"))
    }

    /// `anvil_setCode` — etch `code` at `address`, leaving everything else
    /// (storage, balance, nonce, and every *configured* value anywhere) alone.
    ///
    /// This is the whole mechanism of the hazard-3 proof: it moves the
    /// **chain-returned** side of `EXTCODEHASH == runtimeCodeHash` and
    /// nothing else, which is what makes the resulting rejection
    /// non-tautological. Nothing here can reach the registry's stored
    /// `runtimeCodeHash`, and the tests assert that byte-for-byte.
    ///
    /// Note (verified on anvil 1.7.1, and the reason no test here asserts
    /// otherwise): `anvil_setCode` is **not** journalled per block — after
    /// an etch, `eth_getCode` at an *earlier* block number also reports the
    /// new code. Block pinning is still exercised by
    /// [`tests::stream_g_anvil_manifest_and_code_hash_reads_are_live_and_block_pinned`]
    /// via genesis, where the account genuinely did not exist.
    pub(crate) fn anvil_set_code(&self, address: &str, code: &[u8]) {
        self.raw_rpc(
            "anvil_setCode",
            serde_json::json!([address, format!("0x{}", hex::encode(code))]),
        )
        .unwrap_or_else(|e| panic!("anvil_setCode({address}): {e}"));
    }

    /// `anvil_setChainId` — move the chain the endpoint says it is on, while
    /// every *configured* chain id (the registry's `cfg.chainId`, the
    /// manifest's, `RpcChain`'s `CHAIN_ID`) stays exactly where it was.
    pub(crate) fn anvil_set_chain_id(&self, chain_id: u64) {
        self.raw_rpc("anvil_setChainId", serde_json::json!([chain_id]))
            .unwrap_or_else(|e| panic!("anvil_setChainId({chain_id}): {e}"));
    }

    /// `evm_mine` — one empty block, so a read taken afterwards is pinned to
    /// a block that did not exist when the positive arm ran.
    pub(crate) fn mine(&self) {
        self.raw_rpc("evm_mine", serde_json::json!([]))
            .expect("evm_mine");
    }

    /// Sends `calldata` to `to` from [`ANVIL_DEPLOYER_ADDRESS`] (anvil's
    /// unlocked dev account #0, which `DeployStreamG.run()` also makes the
    /// `policySafe`) and asserts the receipt reports success.
    ///
    /// A reverted policy call that was allowed to look like a success would
    /// leave the registry unconfigured and turn every "authorized" arm below
    /// into a silent no-op, so the status check is not optional.
    pub(crate) fn send_from_deployer(&self, to: &str, calldata: &[u8]) -> serde_json::Value {
        let tx_hash = self
            .raw_rpc(
                "eth_sendTransaction",
                serde_json::json!([{
                    "from": ANVIL_DEPLOYER_ADDRESS,
                    "to": to,
                    "input": format!("0x{}", hex::encode(calldata)),
                }]),
            )
            .unwrap_or_else(|e| panic!("eth_sendTransaction to {to}: {e}"));
        let tx_hash = tx_hash
            .as_str()
            .expect("eth_sendTransaction returns a hash")
            .to_string();

        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok(receipt) = self.raw_rpc(
                "eth_getTransactionReceipt",
                serde_json::json!([tx_hash.clone()]),
            ) {
                if !receipt.is_null() {
                    let status = receipt.get("status").and_then(|s| s.as_str());
                    assert_eq!(
                        status,
                        Some("0x1"),
                        "transaction {tx_hash} to {to} did not succeed: {receipt}"
                    );
                    return receipt;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("no receipt for {tx_hash} within 30s");
    }

    /// Registers `feeToken` in the deployed `FeeTokenRegistry` with the
    /// supplied `runtime_code_hash`, by really calling
    /// `upsertTokenConfig(FeeTokenConfig)` from the policy safe.
    ///
    /// `DeployStreamG.s.sol` deliberately does **not** do this (it configures
    /// role commitments, the manifest hash and the gateway, but never a token
    /// config), so without this call `read_live_token_state` would see
    /// Solidity's zero-default record and fail "inactive or unknown" — a
    /// rejection that proves nothing about the code-hash gate.
    pub(crate) fn upsert_fee_token_config(
        &self,
        runtime_code_hash: [u8; 32],
        capability_mask: u128,
        decimals: u8,
        active: bool,
    ) {
        let d = self.deployment();
        let calldata = encode_upsert_token_config(
            31337,
            addr20(&d.fee_token),
            runtime_code_hash,
            capability_mask,
            decimals,
            active,
        );
        self.send_from_deployer(&d.fee_token_registry, &calldata);
    }

    /// The eleven `abi.encode` words of `getTokenRegistry.getTokenConfig(feeToken)`
    /// at `block`, sliced out of the raw return data by hand.
    ///
    /// Independent of `RpcChain::fee_token_config` on **both** halves: the
    /// calldata is built here and the return is decoded here, so a test can
    /// say "the CONFIGURED `runtimeCodeHash` is still byte-for-byte what it
    /// was" without asking the decoder under test. The struct is fully
    /// static, so the return is exactly the eleven words with no head offset.
    /// Word order is `StreamGTypes.FeeTokenConfig`'s declaration order:
    /// 0 `chainId`, 1 `token`, 2 `runtimeCodeHash`, 3 `proxyIdentityHash`,
    /// 4 `capabilityMask`, 5 `decimals`, 6 `domainNameHash`,
    /// 7 `domainVersionHash`, 8 `builtInModeId`, 9 `configVersion`,
    /// 10 `active`.
    pub(crate) fn raw_token_config_words(&self, block: u64) -> Vec<[u8; 32]> {
        let d = self.deployment();
        let mut calldata = Vec::with_capacity(4 + 32);
        calldata.extend_from_slice(&crate::chain::selector(SIG_GET_TOKEN_CONFIG));
        calldata.extend_from_slice(&word_from_address(&addr20(&d.fee_token)));
        let raw = self
            .raw_rpc(
                "eth_call",
                serde_json::json!([
                    {"to": d.fee_token_registry, "input": format!("0x{}", hex::encode(calldata))},
                    format!("0x{block:x}")
                ]),
            )
            .expect("independent eth_call getTokenConfig");
        let bytes = hex_bytes(raw.as_str().expect("eth_call returns a hex string"));
        assert_eq!(
            bytes.len(),
            32 * 11,
            "getTokenConfig returned {} bytes, expected 11 static words",
            bytes.len()
        );
        bytes
            .chunks_exact(32)
            .map(|c| {
                let mut w = [0u8; 32];
                w.copy_from_slice(c);
                w
            })
            .collect()
    }

    /// `FeeTokenRegistry.isTokenAuthorized(token, capability)` at `block` —
    /// **the Solidity `_isAuthorized` the Rust gate mirrors**, asked of the
    /// chain directly.
    ///
    /// This is the strongest cross-check available to these tests: the two
    /// implementations share no code, so when the Rust gate and this one
    /// agree on both arms, "the Rust gate is a real gate" and "the Rust gate
    /// mirrors the contract" are the same observation.
    pub(crate) fn on_chain_is_token_authorized(&self, capability_mask: u128, block: u64) -> bool {
        let d = self.deployment();
        let calldata = encode_is_token_authorized(addr20(&d.fee_token), capability_mask);
        let raw = self
            .raw_rpc(
                "eth_call",
                serde_json::json!([
                    {"to": d.fee_token_registry, "input": format!("0x{}", hex::encode(calldata))},
                    format!("0x{block:x}")
                ]),
            )
            .expect("independent eth_call isTokenAuthorized");
        let word = hex_bytes(raw.as_str().expect("eth_call returns a hex string"));
        assert_eq!(word.len(), 32, "isTokenAuthorized must return one word");
        assert!(
            word[..31].iter().all(|b| *b == 0) && (word[31] == 0 || word[31] == 1),
            "isTokenAuthorized returned a non-boolean word 0x{}",
            hex::encode(&word)
        );
        word[31] == 1
    }

    // -- Wave C: the OP-Stack `GasPriceOracle` predeploy -------------------
    //
    // Anvil is a vanilla EVM chain — it has **no** OP-Stack predeploys, so
    // `0x42…0F` starts out with no code at all and every `gas_oracle_*` read
    // fails closed. That is not an inconvenience to work around; it is one
    // arm of the Wave C proof (see
    // `stream_g_anvil_gas_oracle_reads_fail_closed_until_the_predeploy_is_etched`),
    // because it shows the three reads really do target the predeploy
    // address and really do refuse rather than reporting a zero fee when
    // nothing answers.

    /// Etches `contracts/test/mocks/MockGasPriceOracle.sol`'s **compiled
    /// runtime** at [`GAS_PRICE_ORACLE_ADDRESS_HEX`].
    ///
    /// The bytecode is not hand-written or vendored: it comes from
    /// `forge inspect MockGasPriceOracle deployedBytecode`, i.e. the very
    /// artifact `StreamGMocks.t.sol` pins the three OP-Stack selectors
    /// against Solidity-side. If the mock's ABI ever drifts from
    /// [`super::base_fee`]'s encoders again (it did once — the pre-T6a
    /// `getL1FeeUpperBound(bytes)` variant is a genuinely different
    /// selector, `0x3e02a766` vs `0xf1c7a58b`), the etched dispatcher stops
    /// containing the selector Rust sends and the call falls through to the
    /// mock's fallback, which does not exist — so the read reverts instead
    /// of silently returning a stale word.
    ///
    /// Etching leaves storage untouched, so all three fee slots read zero
    /// afterwards; [`Self::set_oracle_fees`] is what puts values in them,
    /// through the mock's own `setFees` transaction rather than by writing
    /// storage behind its back.
    pub(crate) fn etch_gas_price_oracle(&self) -> Vec<u8> {
        let runtime = forge_inspect_deployed_bytecode("MockGasPriceOracle");
        assert!(
            !runtime.is_empty(),
            "forge inspect returned empty runtime for MockGasPriceOracle"
        );
        self.anvil_set_code(GAS_PRICE_ORACLE_ADDRESS_HEX, &runtime);

        // Independent read-back: the predeploy address now really holds the
        // bytes we asked for. Without this, a silently-ignored
        // `anvil_setCode` would turn every arm below into "the oracle was
        // never there", which is a different (and much weaker) test.
        let block = self.latest_block_number();
        let on_chain = self.code_at(GAS_PRICE_ORACLE_ADDRESS_HEX, block);
        assert_eq!(
            on_chain, runtime,
            "anvil_setCode did not put MockGasPriceOracle's runtime at {GAS_PRICE_ORACLE_ADDRESS_HEX}"
        );
        runtime
    }

    /// `MockGasPriceOracle.setFees(l1Fee, l1FeeUpperBound, operatorFee)` as
    /// a real transaction from the deployer.
    ///
    /// Deliberately **not** `anvil_setStorageAt`: going through the mock's
    /// own setter means the three values land in whatever slots the compiled
    /// contract actually uses, so a storage-layout assumption in this
    /// harness can never diverge from the contract the reads hit.
    pub(crate) fn set_oracle_fees(
        &self,
        l1_fee: u128,
        l1_fee_upper_bound: u128,
        operator_fee: u128,
    ) {
        let calldata = encode_set_fees(l1_fee, l1_fee_upper_bound, operator_fee);
        self.send_from_deployer(GAS_PRICE_ORACLE_ADDRESS_HEX, &calldata);
    }

    /// One `uint256` read off the etched oracle by raw `eth_call`, decoded
    /// here by hand.
    ///
    /// `calldata` is expected to come from one of the
    /// `raw_oracle_calldata_*` helpers below, whose selectors are verbatim
    /// `cast sig` output rather than [`super::base_fee::oracle_selector`] —
    /// so a value cross-checked through here shares neither its encoder nor
    /// its decoder with the code under test.
    pub(crate) fn oracle_raw_u256(&self, calldata: &[u8], what: &str) -> u128 {
        let raw = self
            .raw_rpc(
                "eth_call",
                serde_json::json!([
                    {"to": GAS_PRICE_ORACLE_ADDRESS_HEX, "input": format!("0x{}", hex::encode(calldata))},
                    "latest"
                ]),
            )
            .unwrap_or_else(|e| panic!("independent eth_call {what}: {e}"));
        let bytes = hex_bytes(raw.as_str().expect("eth_call returns a hex string"));
        assert_eq!(
            bytes.len(),
            32,
            "{what} returned {} bytes, expected one uint256 word",
            bytes.len()
        );
        assert!(
            bytes[..16].iter().all(|b| *b == 0),
            "{what} returned a value wider than u128: 0x{}",
            hex::encode(&bytes)
        );
        let mut low = [0u8; 16];
        low.copy_from_slice(&bytes[16..]);
        u128::from_be_bytes(low)
    }

    /// `eth_blockNumber` by raw JSON-RPC — used where a block number is
    /// needed for bookkeeping rather than as a value under test.
    pub(crate) fn latest_block_number(&self) -> u64 {
        let raw = self
            .raw_rpc("eth_blockNumber", serde_json::json!([]))
            .expect("independent eth_blockNumber");
        let s = raw.as_str().expect("eth_blockNumber returns a hex string");
        u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
            .unwrap_or_else(|e| panic!("bad block number {s}: {e}"))
    }

    // -- Wave D: cluster staging + independent state reads -----------------
    //
    // Mandate 3 needs three things Waves A-C never needed: transactions from
    // an address that is not anvil's dev account #0 (the gateway, so that
    // `onlyGateway` state transitions can be driven without a full sponsored
    // enrollment), `eth_call` against arbitrary contracts, and a way to move
    // the *chain* clock. All three go through [`Self::raw_rpc`], i.e. the
    // same `reqwest` path every other cross-check in this file uses.

    /// `eth_call(to, calldata, "latest")` — raw return bytes, decoded by the
    /// caller.
    ///
    /// Every Wave D value that is *not* the thing under test is read through
    /// here rather than through [`RpcChain`], so an assertion about "the nonce
    /// really did advance on chain" never rests on the decoder whose gate is
    /// being tested.
    pub(crate) fn call_latest(&self, to: &str, calldata: &[u8], what: &str) -> Vec<u8> {
        let raw = self
            .raw_rpc(
                "eth_call",
                serde_json::json!([
                    {"to": to, "input": format!("0x{}", hex::encode(calldata))},
                    "latest"
                ]),
            )
            .unwrap_or_else(|e| panic!("independent eth_call {what}: {e}"));
        hex_bytes(raw.as_str().expect("eth_call returns a hex string"))
    }

    /// One `uint256`/`uint64` word off `to`, by raw `eth_call`.
    pub(crate) fn call_u128(&self, to: &str, calldata: &[u8], what: &str) -> u128 {
        let bytes = self.call_latest(to, calldata, what);
        assert_eq!(
            bytes.len(),
            32,
            "{what} returned {} bytes, expected one word",
            bytes.len()
        );
        assert!(
            bytes[..16].iter().all(|b| *b == 0),
            "{what} returned a value wider than u128: 0x{}",
            hex::encode(&bytes)
        );
        let mut low = [0u8; 16];
        low.copy_from_slice(&bytes[16..]);
        u128::from_be_bytes(low)
    }

    /// One `bytes32` word off `to`, by raw `eth_call`.
    pub(crate) fn call_bytes32(&self, to: &str, calldata: &[u8], what: &str) -> [u8; 32] {
        let bytes = self.call_latest(to, calldata, what);
        assert_eq!(
            bytes.len(),
            32,
            "{what} returned {} bytes, expected one word",
            bytes.len()
        );
        let mut w = [0u8; 32];
        w.copy_from_slice(&bytes);
        w
    }

    /// One `address` word off `to`, by raw `eth_call`.
    pub(crate) fn call_address(&self, to: &str, calldata: &[u8], what: &str) -> [u8; 20] {
        let w = self.call_bytes32(to, calldata, what);
        assert!(
            w[..12].iter().all(|b| *b == 0),
            "{what} returned a non-address word 0x{}",
            hex::encode(w)
        );
        let mut a = [0u8; 20];
        a.copy_from_slice(&w[12..]);
        a
    }

    /// `anvil_impersonateAccount` + `anvil_setBalance`, so `from` can send a
    /// transaction even when it is a contract with no ether.
    ///
    /// Used for exactly one thing: driving
    /// `WalletSponsorshipRegistry.linkSecondary`, which is `onlyGateway`
    /// (`WalletSponsorshipRegistry.sol:188`). Impersonation is deliberately
    /// preferred over `anvil_setStorageAt`, because the state transition that
    /// advances `linkNonces` is then the **contract's own**
    /// (`:247 linkNonces[link.secondary] = link.nonce + 1`) rather than this
    /// harness's guess at a storage slot — and every one of `linkSecondary`'s
    /// preconditions, including the secondary's EIP-712 signature, still has
    /// to hold for the nonce to move at all.
    pub(crate) fn impersonate(&self, from: &str) {
        self.raw_rpc("anvil_impersonateAccount", serde_json::json!([from]))
            .unwrap_or_else(|e| panic!("anvil_impersonateAccount({from}): {e}"));
        self.raw_rpc(
            "anvil_setBalance",
            serde_json::json!([from, "0xde0b6b3a7640000"]), // 1 ETH
        )
        .unwrap_or_else(|e| panic!("anvil_setBalance({from}): {e}"));
    }

    pub(crate) fn stop_impersonating(&self, from: &str) {
        self.raw_rpc("anvil_stopImpersonatingAccount", serde_json::json!([from]))
            .unwrap_or_else(|e| panic!("anvil_stopImpersonatingAccount({from}): {e}"));
    }

    /// [`Self::send_from_deployer`], but from an arbitrary (unlocked or
    /// impersonated) `from`. Asserts the receipt reports success for the same
    /// reason: a silently reverted staging transaction would leave the cluster
    /// unstaged and make every arm below vacuous.
    pub(crate) fn send_from(&self, from: &str, to: &str, calldata: &[u8]) -> serde_json::Value {
        let tx_hash = self
            .raw_rpc(
                "eth_sendTransaction",
                serde_json::json!([{
                    "from": from,
                    "to": to,
                    "input": format!("0x{}", hex::encode(calldata)),
                    "gas": "0x1c9c380",
                }]),
            )
            .unwrap_or_else(|e| panic!("eth_sendTransaction {from} -> {to}: {e}"));
        let tx_hash = tx_hash
            .as_str()
            .expect("eth_sendTransaction returns a hash")
            .to_string();

        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok(receipt) = self.raw_rpc(
                "eth_getTransactionReceipt",
                serde_json::json!([tx_hash.clone()]),
            ) {
                if !receipt.is_null() {
                    let status = receipt.get("status").and_then(|s| s.as_str());
                    assert_eq!(
                        status,
                        Some("0x1"),
                        "transaction {tx_hash} ({from} -> {to}) did not succeed: {receipt}"
                    );
                    return receipt;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("no receipt for {tx_hash} within 30s");
    }

    /// `eth_getTransactionReceipt(hash)`, polled until the node actually has
    /// one, then returned. Panics with the poll count when the deadline passes.
    ///
    /// # Why this is a poll and not a read
    ///
    /// **A broadcast is not a mining event.** `eth_sendRawTransaction` returns
    /// as soon as the node has *accepted* the transaction into its pool;
    /// anvil then mines it on its own schedule. The gap is normally under a
    /// millisecond and a single read appears to work — which is exactly what
    /// makes this the worst shape of assertion, because it passes on an idle
    /// machine and fails on a busy one.
    ///
    /// Measured, and the reason this helper exists: five consecutive
    /// `run-full-gate.ps1` runs under concurrent load, of which **two** went
    /// red inside
    /// [`tests::stream_g_anvil_reconciliation_confirms_a_real_broadcast_once_it_is_deep_enough`]
    /// with `the node has no receipt for 0x16b1de… — the transaction was never
    /// mined`. The same test was 8/8 green in isolation and the same suite
    /// 6/6 green in isolation, so the failure was scheduling, not logic: the
    /// single unretried `eth_getTransactionReceipt` landed before anvil's
    /// miner got a slice.
    ///
    /// The two sibling senders on this type,
    /// [`Self::send_from_deployer`] and [`Self::send_from`], have always
    /// polled for exactly this reason. This is the same loop, extracted, so
    /// the read path a *test* uses cannot drift from the one the *harness*
    /// uses.
    ///
    /// # What it does NOT do
    ///
    /// It does not look at `status`. A reverted transaction has a receipt and
    /// is returned here; deciding what a revert means is the caller's job
    /// (the reconciliation test replays it through `eth_call` to name the
    /// selector, which a status assertion here would pre-empt). This waits for
    /// *minedness* and nothing else.
    ///
    /// A transport error is not fatal on its own — it is remembered and
    /// retried until the deadline, then quoted in the panic, because "the node
    /// refused the connection for 30s" and "the node answered null for 30s"
    /// are different bugs and the message has to distinguish them.
    pub(crate) fn receipt_when_mined(&self, tx_hash: &str, what: &str) -> serde_json::Value {
        let deadline = Instant::now() + RECEIPT_POLL_TIMEOUT;
        let mut polls = 0usize;
        // Deliberately uninitialized: every arm of the match below assigns it
        // before the deadline check reads it, and an initializer here would be
        // dead code that `-D warnings` rejects.
        let mut last_err: Option<String>;
        loop {
            // Poll FIRST, then test the deadline. The other order would let a
            // zero-length budget return without ever asking the node, which is
            // the unretried read this helper replaced.
            match self.raw_rpc(
                "eth_getTransactionReceipt",
                serde_json::json!([tx_hash.to_string()]),
            ) {
                Ok(v) if !v.is_null() => return v,
                Ok(_) => last_err = None,
                Err(e) => last_err = Some(e),
            }
            polls += 1;
            if Instant::now() >= deadline {
                let cause = match &last_err {
                    Some(e) => format!("last transport error: {e}"),
                    None => "the node answered null every time (accepted but never mined)".to_string(),
                };
                panic!(
                    "the node has no receipt for {tx_hash} ({what}) after {polls} poll(s) over \
                     {}s — the transaction was never mined. {cause}",
                    RECEIPT_POLL_TIMEOUT.as_secs()
                );
            }
            std::thread::sleep(RECEIPT_POLL_INTERVAL);
        }
    }

    /// `evm_increaseTime` + `evm_mine` — moves the **chain** clock, which is
    /// the clock `outbox::sweep_stuck_reservations`' release guard reads
    /// (`outbox.rs:965`, `client.block_timestamp()`). The wall clock the sweep
    /// takes as an argument is separately injectable, so a test can place the
    /// two at deliberately different points.
    pub(crate) fn increase_time(&self, seconds: u64) {
        self.raw_rpc("evm_increaseTime", serde_json::json!([seconds]))
            .unwrap_or_else(|e| panic!("evm_increaseTime({seconds}): {e}"));
        self.mine();
    }

    /// `eth_getBlockByNumber("latest", false).timestamp`.
    pub(crate) fn latest_block_timestamp(&self) -> u64 {
        let block = self
            .raw_rpc("eth_getBlockByNumber", serde_json::json!(["latest", false]))
            .expect("independent eth_getBlockByNumber");
        let s = block
            .get("timestamp")
            .and_then(|t| t.as_str())
            .expect("block has a timestamp");
        u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
            .unwrap_or_else(|e| panic!("bad block timestamp {s}: {e}"))
    }

    fn wait_until_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut last = String::from("(never polled)");
        while Instant::now() < deadline {
            match json_rpc(&self.rpc_url, "eth_chainId", serde_json::json!([])) {
                Ok(v) => {
                    assert_eq!(
                        v.as_str(),
                        Some("0x7a69"),
                        "harness node must report chain id 31337 (0x7a69), got {v}"
                    );
                    return;
                }
                Err(e) => last = e,
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "anvil at {} never became ready within 60s; last error: {last}",
            self.rpc_url
        );
    }
}

/// A JSON-RPC call issued with `reqwest`'s blocking client — deliberately not
/// alloy, so it shares no decode path with [`RpcChain`].
///
/// **Runtime-aware (Wave D).** `reqwest::blocking` builds and drops its own
/// runtime per call, and dropping a runtime inside an asynchronous context
/// panics with *"Cannot drop a runtime in a context where blocking is not
/// allowed"* — the identical hazard `rpc_chain.rs:85-92` documents for
/// `RpcChain`. Wave D's submit/sweeper tests call harness helpers from inside
/// `Runtime::block_on`, so the call is wrapped in `block_in_place` whenever a
/// runtime is ambient. That requires a **multi-thread** runtime, which is why
/// `wave_d_runtime` builds one.
pub(crate) fn json_rpc(
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    match tokio::runtime::Handle::try_current() {
        Ok(_) => tokio::task::block_in_place(|| json_rpc_blocking(rpc_url, method, params)),
        Err(_) => json_rpc_blocking(rpc_url, method, params),
    }
}

fn json_rpc_blocking(
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("build client: {e}"))?;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let resp = client
        .post(rpc_url)
        .json(&body)
        .send()
        .map_err(|e| format!("{method}: {e}"))?;
    let value: serde_json::Value = resp.json().map_err(|e| format!("{method} decode: {e}"))?;
    if let Some(err) = value.get("error") {
        return Err(format!("{method} rpc error: {err}"));
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| format!("{method}: response had no result member"))
}

/// An OS-assigned free port, asserted to differ from [`DEFAULT_NODE_PORT`].
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    assert_ne!(
        port, DEFAULT_NODE_PORT,
        "harness must never bind the default node port — a pilot node may own it"
    );
    port
}

fn spawn_anvil(port: u16) -> Child {
    let bin = tool_path("GOAT_ANVIL_BIN", "anvil");
    Command::new(&bin)
        .args([
            "--port",
            &port.to_string(),
            "--chain-id",
            "31337",
            // `--disable-code-size-limit` was DROPPED here in Wave 1 — see the
            // module doc. The node now enforces EIP-170, so a future edit that
            // pushes a Stream G contract back over 24,576 bytes fails this
            // harness's deploy instead of passing silently.
            "--silent",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn anvil ({}): {e}", bin.display()))
}

/// [`Command::output`] with a wall-clock ceiling.
///
/// `std::process::Command::output()` waits **forever**; there is no
/// `wait_timeout` in std. Every external tool this harness runs went through
/// it, so a wedged `forge` (see [`FORGE_TIMEOUT`]) had no bound at all and
/// could only be ended by the gate's watchdog killing the whole process tree.
///
/// Shape: both pipes are drained by their own thread *before* the wait, which
/// is not optional — `forge` emits far more than a pipe buffer holds, and a
/// parent that waits on exit while the child blocks writing to a full pipe
/// deadlocks the pair. (This is the same hazard the gate's own anvil launcher
/// documents for `BeginOutputReadLine`.) Exceeding the budget kills the child
/// and panics with the tool, the budget, and whatever it had already printed —
/// so the failure names itself instead of arriving as a killed pid list.
fn output_within(cmd: &mut Command, budget: Duration, what: &str) -> Output {
    output_within_probed(cmd, budget, what, None, FORENSICS_MIDFLIGHT_TRIGGER)
}

/// [`output_within`] plus a **mid-flight** node probe.
///
/// # Why the give-up probe was not enough
///
/// [`PanicForensics`] records the node's state when the harness gives up. That
/// only fires on a failure, and the stall being chased usually does **not**
/// fail: across 12 faithful step-3 runs taken while this was being written,
/// eleven finished in 25-27s and one took **46.4s** — a ~20s excursion with
/// the same signature as the one captured freeze — and it exited 0 with 19/19
/// passed. libtest discards a passing test's captured output, so nothing was
/// recorded and nothing could have been. An instrument that only fires on the
/// ~1-in-20 run that actually times out would have missed it, and has been
/// missing it.
///
/// So when the child is still running at `trigger`, the node is probed **while
/// the stall is still happening** — which is strictly better evidence than
/// probing after it has resolved. The probe runs on its own thread so that it
/// cannot delay the exit poll.
///
/// # Correction: the thread does NOT escape libtest's capture
///
/// The first revision of this probe reported through `eprintln!` on the belief
/// that libtest's output capture is thread-local and a spawned thread
/// therefore reaches the real stderr. **That is false** — the capture is
/// inherited by spawned threads, and the gate runs this step without
/// `--nocapture`, so on a passing run the reading was buffered and thrown
/// away. On the only kind of run this instrument exists for. It now reports
/// through [`record_forensics`], whose file sink is outside libtest
/// altogether; see [`forensics_log_path`].
fn output_within_probed(
    cmd: &mut Command,
    budget: Duration,
    what: &str,
    probe_url: Option<&str>,
    trigger: Duration,
) -> Output {
    // What the CALL SITE wired in, recorded so it can be asserted. The single
    // production argument that arms this instrument is `deploy_stream_g`
    // passing `Some(rpc_url)`; replacing it with `None` silently disables the
    // mid-flight probe and leaves every test green. One line, no test — which
    // is exactly the shape of the checks this project keeps finding cannot
    // fail. See `forensics_from_a_panicking_harness_scope_...`.
    #[cfg(test)]
    {
        *LAST_PROBE_URL.lock().unwrap_or_else(|e| e.into_inner()) = probe_url.map(str::to_string);
    }

    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to run {what}: {e}"));

    let mut out_pipe = child.stdout.take().expect("piped stdout");
    let mut err_pipe = child.stderr.take().expect("piped stderr");
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out_pipe.read_to_end(&mut buf);
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err_pipe.read_to_end(&mut buf);
        buf
    });

    // Mid-flight watchdog. Idle until `trigger`, then takes one forensics
    // reading and exits; cancelled the moment the child is reaped.
    let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Read HERE, on the test's own thread: libtest names that thread after the
    // test, and the watchdog thread it spawns is anonymous. Captured before the
    // spawn or the reading cannot say which test it belongs to.
    let who = std::thread::current().name().map(str::to_string);
    let watchdog = probe_url.map(|url| {
        let flag = std::sync::Arc::clone(&finished);
        let url = url.to_string();
        let what = what.to_string();
        std::thread::spawn(move || {
            let fire_at = Instant::now() + trigger;
            while Instant::now() < fire_at {
                if flag.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if flag.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            let report = format!(
                "--- MID-FLIGHT: {what} has been running for {trigger:?} against {url}. A \
                 healthy deploy here is ~1s (150 measured, max 2.45s), so this is the stall, \
                 caught WHILE IT IS HAPPENING rather than after it resolved. ---\n{}",
                node_forensics(&url, FORENSICS_PROBE_TIMEOUT)
            );
            record_forensics(FORENSICS_ARM_MIDFLIGHT, who.as_deref(), &report);
        })
    });

    let deadline = Instant::now() + budget;
    let status = loop {
        match child.try_wait().expect("try_wait on a spawned child") {
            Some(status) => break status,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    // The watchdog fired long ago (trigger << budget); collect
                    // it before panicking so its reading is already on stderr
                    // when the panic message lands.
                    finished.store(true, std::sync::atomic::Ordering::Relaxed);
                    if let Some(w) = watchdog {
                        let _ = w.join();
                    }
                    // Killing the child closes its pipes, so both readers now
                    // finish and hand over everything it managed to print.
                    let stdout = out_reader.join().unwrap_or_default();
                    let stderr = err_reader.join().unwrap_or_default();
                    panic!(
                        "{what} made no progress within {budget:?} and was killed. A tool that \
                         talks to the node stalls exactly like this when the node stops \
                         answering — whether it actually did is NOT a guess any more: the \
                         `--- node forensics ---` block printed by [`PanicForensics`] as this \
                         unwind passes back through [`AnvilHarness`] answers it.\
                         \n--- stdout so far ---\n{}\n--- stderr so far ---\n{}",
                        String::from_utf8_lossy(&stdout),
                        String::from_utf8_lossy(&stderr)
                    );
                }
                std::thread::sleep(RECEIPT_POLL_INTERVAL);
            }
        }
    };

    // Cancel the watchdog and wait for it, so a reading it is part-way through
    // cannot land after the next test has started and be read as that test's.
    finished.store(true, std::sync::atomic::Ordering::Relaxed);
    if let Some(w) = watchdog {
        let _ = w.join();
    }

    Output {
        status,
        stdout: out_reader.join().expect("stdout reader thread"),
        stderr: err_reader.join().expect("stderr reader thread"),
    }
}

// ===========================================================================
// NODE FORENSICS — what this suite records at the moment it gives up
// ===========================================================================
//
// # Why this exists
//
// The hazard suite intermittently stalls against its own local anvil. Two
// bounded-deadline rounds have made the stall *visible* (`rpc_chain.rs`'s
// `RPC_READ_TIMEOUT`, this file's [`FORGE_TIMEOUT`]) without making it
// *explained*: the failure now names an operation and a budget, and then
// stops — leaving the one question that actually splits the surviving
// hypotheses unanswered.
//
// That question is: **at the moment we gave up, was the node still serving?**
//
//   * Still serving  → the node was healthy; the stall lived in the
//     connection, or in the client that gave up, and the next investigation
//     belongs on the socket/HTTP-client side (~1,100 short-lived connections
//     per suite run, a fresh `reqwest::Client` per call site).
//   * Not serving    → anvil itself stopped answering, and the next
//     investigation belongs in the node.
//
// Nothing recorded so far distinguishes those, which is why five separate
// investigations have all ended at the same fork. Two facts are recorded
// beside it because they are the standing environmental suspicions and cost
// milliseconds to settle in the same breath: how many anvils were alive (an
// un-reaped predecessor would show as >2) and the host TCP census (ephemeral
// port / TIME_WAIT pressure).
//
// # What this is NOT
//
// It is not a fix and does not pretend to be one. The defect is not
// root-caused. This block converts "it stalled" into "it stalled AND the node
// was / was not reachable from a brand-new socket", which is a fact, and is
// the fact the next session should start from.

/// Budget for the single fresh-connection probe taken during forensics.
///
/// Applied to connect, write and read individually, so a pathological peer can
/// cost up to a small multiple of it. Deliberately short: this runs while a
/// panic is already unwinding, and a forensics helper that itself takes
/// minutes turns one bad run into a worse one. 5s is ~1,000× a healthy
/// loopback round-trip and comfortably longer than the ~1s the induced-wedge
/// calibration needed to declare a suspended node unreachable.
const FORENSICS_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a node-facing child may run before the forensics probe fires
/// **mid-flight**, while the stall is still in progress.
///
/// 15s is chosen against measurement, not taste: 150 recorded unwedged
/// `forge script` deploys against fresh anvils averaged 1.00s with a maximum of
/// 2.45s, so 15s is 6× the worst healthy case and cannot fire on a healthy
/// run. The one freeze ever captured under instrumentation ran ~19s, and a
/// 46.4s step-3 run (against a 25-27s norm) was observed while this was being
/// written — both above the trigger. It is also 20× under [`FORGE_TIMEOUT`],
/// so the probe happens early in the stall rather than at the end of it.
const FORENSICS_MIDFLIGHT_TRIGGER: Duration = Duration::from_secs(15);

/// Budget for one forensics shell-out (`tasklist` / `netstat`).
///
/// `netstat` has to walk the whole connection table, which this suite pushes
/// to ~5,000 rows, so it is the slow one; 20s is a ceiling on that going wrong,
/// not an expected duration.
const FORENSICS_TOOL_TIMEOUT: Duration = Duration::from_secs(20);

/// Where a forensics reading is written so that it survives a **passing** run.
///
/// # Why a file and not stderr
///
/// libtest captures stdout/stderr per test and **discards** the capture unless
/// the test fails. That capture is installed process-wide and is inherited by
/// threads the test spawns — an earlier revision of this file believed a
/// spawned thread escaped it and wrote the mid-flight reading with `eprintln!`
/// on that belief. It does not escape it. The gate runs the hazard suite
/// without `--nocapture`, so on a passing run the reading went nowhere.
///
/// That is precisely the case the mid-flight probe was built for: the run that
/// motivated it took 46.4s against a 25-27s norm and **exited 0 with every
/// test green**. The at-give-up arm records nothing then, because nothing gave
/// up. An instrument that can only report on a failure cannot report on this.
///
/// A file is outside libtest entirely, so it lands whatever the verdict.
///
/// Default: `<crate>/gate-logs/node-forensics.log`, appended, never rotated
/// here. `gate-logs/` is where the gate already writes its per-step logs, so
/// it is where the next investigator is already looking, and it is gitignored
/// (`tools/goat-attestor/.gitignore` line 11, `gate-logs/`) so an accumulating
/// diagnostic cannot be committed by accident. `GOAT_FORENSICS_LOG` overrides
/// the path, which is also how the sink is tested without writing to the real
/// one.
fn forensics_log_path() -> PathBuf {
    if let Ok(v) = std::env::var("GOAT_FORENSICS_LOG") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("gate-logs")
        .join("node-forensics.log")
}

/// `YYYY-MM-DDTHH:MM:SSZ` from the system clock.
///
/// Hand-rolled: this crate has no date dependency, and taking one on to
/// timestamp a diagnostic would be a poor trade. Civil-from-days is Hinnant's
/// `civil_from_days`. A reading with no timestamp cannot be lined up against
/// the gate's own step logs, which is the first thing anyone will try to do
/// with it.
fn utc_stamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (days, tod) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        tod / 3_600,
        (tod % 3_600) / 60,
        tod % 60
    )
}

/// Emit one forensics reading to every sink that can carry it.
///
/// `arm` names which instrument fired ([`FORENSICS_ARM_MIDFLIGHT`] or
/// [`FORENSICS_ARM_GIVE_UP`]); `who` is the test it belongs to, when that is
/// knowable — libtest names the test thread after the test, so the mid-flight
/// watchdog is handed its parent's name at spawn rather than reading its own.
///
/// The FILE is the sink that has to work (see [`forensics_log_path`]). stderr
/// is kept beside it because on a *failing* test libtest does print the
/// capture, and having the block adjacent to the panic message costs nothing.
///
/// Nothing in here may panic or fail the run: the give-up arm executes during
/// an unwind, where a second panic aborts the process outright.
fn record_forensics(arm: &str, who: Option<&str>, report: &str) {
    let entry = format!(
        "===== {} {arm} [{}] =====\n{report}\n",
        utc_stamp(),
        who.unwrap_or("<test name unavailable>")
    );

    let path = forensics_log_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    // Bounded, because nothing else bounds it. The gate rotates its per-run log
    // DIRECTORIES to 20; this file is outside that scheme and is appended to by
    // every arm of every run, so left alone it grows without limit on a machine
    // where the suite runs dozens of times a day.
    //
    // Rotation, not truncation, and one generation kept: a stall investigation
    // usually starts AFTER the interesting run, so discarding the older half at
    // the moment the file fills would throw away exactly the reading being
    // looked for. `rename` replaces any existing `.1`, so the on-disk cost is
    // bounded at 2x CAP.
    //
    // Every failure here is swallowed on purpose. This function runs during an
    // unwind on the AT-GIVE-UP arm, so a panic in the recorder would replace the
    // real failure with a confusing one -- the forensics must never become the
    // error being investigated.
    const FORENSICS_LOG_CAP_BYTES: u64 = 2 * 1024 * 1024;
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > FORENSICS_LOG_CAP_BYTES {
            let _ = std::fs::rename(&path, path.with_extension("1.log"));
        }
    }

    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(entry.as_bytes());
        let _ = f.flush();
    }

    #[cfg(test)]
    FORENSICS_SINK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(report.to_string());

    eprintln!("{entry}");
}

/// Fired by the watchdog while the child is **still running**. On a passing
/// run this reaches the file and nothing else.
const FORENSICS_ARM_MIDFLIGHT: &str = "MID-FLIGHT";

/// Fired by [`PanicForensics`] as a failing test unwinds. Reaches the file and
/// the step log both, the latter because libtest prints a failing test's
/// capture.
const FORENSICS_ARM_GIVE_UP: &str = "AT-GIVE-UP";

/// A JSON-RPC round-trip issued over a **brand-new TCP socket**, hand-rolled
/// on `std::net`.
///
/// Deliberately shares nothing with either RPC path already in the process:
/// not alloy (whose `reqwest` client is the thing under suspicion), and not
/// even [`json_rpc`]'s `reqwest::blocking` (which builds and drops a tokio
/// runtime per call — and `block_in_place` on a current-thread runtime panics,
/// which during an unwind aborts the process). A raw socket also answers a
/// strictly better question: it cannot be served by a pooled connection, so
/// "answered" here means the node accepted a *new* connection and served it.
///
/// `Ok((body, elapsed))` / `Err((why, elapsed))`.
fn probe_node_over_a_fresh_connection(
    rpc_url: &str,
    budget: Duration,
) -> Result<(String, Duration), (String, Duration)> {
    let started = Instant::now();
    let trimmed = rpc_url.trim();
    let authority = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    let authority = authority.split('/').next().unwrap_or(authority);

    let attempt = || -> std::io::Result<String> {
        let addr = authority.to_socket_addrs()?.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("{authority} resolved to no socket address"),
            )
        })?;
        let mut sock = TcpStream::connect_timeout(&addr, budget)?;
        sock.set_read_timeout(Some(budget))?;
        sock.set_write_timeout(Some(budget))?;
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}"#;
        // `Connection: close` so the reply is framed by EOF and this needs no
        // chunked/keep-alive parsing of its own.
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        sock.write_all(request.as_bytes())?;
        sock.flush()?;
        let mut raw = Vec::new();
        sock.read_to_end(&mut raw)?;
        Ok(String::from_utf8_lossy(&raw).into_owned())
    };

    match attempt() {
        Ok(raw) => {
            let elapsed = started.elapsed();
            match raw.split_once("\r\n\r\n") {
                Some((_, body)) if !body.trim().is_empty() => {
                    let body = body.trim();
                    let shown: String = body.chars().take(240).collect();
                    Ok((shown, elapsed))
                }
                _ => Err((
                    format!(
                        "connected, wrote the request, read {} bytes, and got no HTTP body back",
                        raw.len()
                    ),
                    elapsed,
                )),
            }
        }
        Err(e) => Err((format!("{e} (io kind: {:?})", e.kind()), started.elapsed())),
    }
}

/// [`Command::output`] with a ceiling that **returns `None`** instead of
/// panicking.
///
/// Not [`output_within`], and the difference is load-bearing: every caller
/// below runs while a panic is already unwinding, and a panic raised during an
/// unwind aborts the process — turning a diagnosable test failure into a
/// process abort with no output at all.
fn forensics_tool(exe: &str, args: &[&str], budget: Duration) -> Option<String> {
    let mut child = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut pipe = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + budget;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => {
                let _ = reader.join();
                return None;
            }
        }
    }
    let raw = reader.join().ok()?;
    Some(String::from_utf8_lossy(&raw).into_owned())
}

/// Count + pids of live `anvil` processes on this host.
///
/// More than 2 during a `--test-threads=1` run means a predecessor was not
/// reaped and the "one node per test" assumption this suite rests on is false.
/// (2 is the gate's own node plus this harness's; 1 between tests.)
#[cfg(windows)]
fn live_anvil_processes() -> String {
    match forensics_tool(
        "tasklist",
        &["/FI", "IMAGENAME eq anvil.exe", "/NH", "/FO", "CSV"],
        FORENSICS_TOOL_TIMEOUT,
    ) {
        Some(out) => {
            let pids: Vec<String> = out
                .lines()
                .filter(|l| l.to_ascii_lowercase().contains("anvil.exe"))
                .filter_map(|l| l.split(',').nth(1))
                .map(|p| p.trim().trim_matches('"').to_string())
                .collect();
            format!(
                "{} (pids: {})",
                pids.len(),
                if pids.is_empty() {
                    "none".to_string()
                } else {
                    pids.join(", ")
                }
            )
        }
        None => format!("(tasklist gave no answer within {FORENSICS_TOOL_TIMEOUT:?})"),
    }
}

#[cfg(not(windows))]
fn live_anvil_processes() -> String {
    match forensics_tool("ps", &["-A", "-o", "pid=,comm="], FORENSICS_TOOL_TIMEOUT) {
        Some(out) => {
            let pids: Vec<String> = out
                .lines()
                .filter(|l| {
                    l.split_whitespace()
                        .nth(1)
                        .is_some_and(|c| c.ends_with("anvil"))
                })
                .filter_map(|l| l.split_whitespace().next())
                .map(str::to_string)
                .collect();
            format!(
                "{} (pids: {})",
                pids.len(),
                if pids.is_empty() {
                    "none".to_string()
                } else {
                    pids.join(", ")
                }
            )
        }
        None => format!("(ps gave no answer within {FORENSICS_TOOL_TIMEOUT:?})"),
    }
}

/// Host-wide TCP census. TIME_WAIT is the standing environmental suspicion
/// (Windows holds it ~120s and the default dynamic range is 16,384 ports);
/// ESTABLISHED is carried beside it because a wedged node with sockets still
/// open looks different from one with none.
#[cfg(windows)]
fn tcp_socket_census() -> String {
    match forensics_tool("netstat", &["-ano", "-p", "tcp"], FORENSICS_TOOL_TIMEOUT) {
        Some(out) => {
            let time_wait = out.lines().filter(|l| l.contains("TIME_WAIT")).count();
            let established = out.lines().filter(|l| l.contains("ESTABLISHED")).count();
            format!("{time_wait} TIME_WAIT, {established} ESTABLISHED (netstat -ano -p tcp)")
        }
        None => format!("(netstat gave no answer within {FORENSICS_TOOL_TIMEOUT:?})"),
    }
}

#[cfg(not(windows))]
fn tcp_socket_census() -> String {
    match forensics_tool("ss", &["-tan"], FORENSICS_TOOL_TIMEOUT) {
        Some(out) => {
            let time_wait = out.lines().filter(|l| l.contains("TIME-WAIT")).count();
            let established = out.lines().filter(|l| l.contains("ESTAB")).count();
            format!("{time_wait} TIME-WAIT, {established} ESTAB (ss -tan)")
        }
        None => format!("(ss gave no answer within {FORENSICS_TOOL_TIMEOUT:?})"),
    }
}

/// The block printed when this harness gives up: probe verdict first, then the
/// two environmental counts.
///
/// The prose is part of the artefact on purpose. Every previous record of this
/// stall was read by someone who had not been present when it was taken, and
/// the recurring cost was not missing data but unlabelled data.
pub(crate) fn node_forensics(rpc_url: &str, probe_budget: Duration) -> String {
    let probe = match probe_node_over_a_fresh_connection(rpc_url, probe_budget) {
        Ok((body, took)) => format!("ANSWERED in {took:?} -> {body}"),
        Err((why, took)) => format!("NO ANSWER after {took:?} -> {why}"),
    };
    format!(
        // The header deliberately says only "a measurement". An earlier revision
        // read "(harness gave up; …)", which is true of the AT-GIVE-UP arm and
        // FALSE of the MID-FLIGHT one — that arm fires at 15s while the child is
        // still running and the test may still pass. The arm is already named on
        // the `=====` line `record_forensics` writes, so stating it here as well
        // only created a chance to state it wrongly.
        "--- node forensics (a measurement, not a root cause) ---\n\
         fresh-socket eth_blockNumber to {rpc_url}: {probe}\n\
         live anvil processes: {}\n\
         host TCP census: {}\n\
         HOW TO READ THIS: ANSWERED means the node was serving a brand-new connection at the \
         moment this gave up, so the stall was NOT the node — look at the connection and at the \
         client that gave up. NO ANSWER means the node itself had stopped serving — look at \
         anvil. That single bit is what five investigations lacked; record it, do not re-derive \
         it.\n\
         --- end node forensics ---",
        live_anvil_processes(),
        tcp_socket_census(),
    )
}

/// Prints [`node_forensics`] **iff** its scope is left by an unwinding panic.
///
/// Held as [`AnvilHarness`]'s **first** field, which is what makes it fire
/// while the node is still alive: Rust drops fields in declaration order, so
/// this runs before `_node`'s `Drop` kills anvil. Probing a node this harness
/// has already reaped would report NO ANSWER every time and prove nothing —
/// the ordering is the whole mechanism, not a style preference.
///
/// Being a field rather than an ad-hoc call at each failure site is also what
/// makes the coverage total: it fires for a [`FORGE_TIMEOUT`] kill, for an
/// `RPC_READ_TIMEOUT` error surfacing as a failed assertion, and for a plain
/// assertion failure — every way a hazard-suite test can end badly, including
/// ways not yet seen.
struct PanicForensics {
    rpc_url: String,
}

/// Set only under `cfg(test)`, so [`PanicForensics`]'s unwind behaviour can be
/// proved without capturing the process's stderr.
#[cfg(test)]
static FORENSICS_SINK: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Serializes the two tests that read [`FORENSICS_SINK`]. They live in
/// different `--ignore`d-ness classes and so never run together under the
/// gate — but `--include-ignored` would run both, and a shared sink read
/// concurrently is a flake waiting to be blamed on the defect this file is
/// chasing.
#[cfg(test)]
static FORENSICS_SINK_LOCK: Mutex<()> = Mutex::new(());

/// The `probe_url` the most recent [`output_within_probed`] call was given.
/// Exists so the deploy call site's wiring is an assertion, not a comment.
#[cfg(test)]
static LAST_PROBE_URL: Mutex<Option<String>> = Mutex::new(None);

impl PanicForensics {
    fn new(rpc_url: &str) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
        }
    }
}

impl Drop for PanicForensics {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let report = node_forensics(&self.rpc_url, FORENSICS_PROBE_TIMEOUT);
        record_forensics(
            FORENSICS_ARM_GIVE_UP,
            std::thread::current().name(),
            &report,
        );
    }
}

/// `$GOAT_<TOOL>_BIN`, else `~/.foundry/bin/<name>[.exe]`, else bare name
/// (PATH lookup).
fn tool_path(env_key: &str, name: &str) -> PathBuf {
    if let Ok(v) = std::env::var(env_key) {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .ok();
    if let Some(home) = home {
        for ext in ["", ".exe"] {
            let candidate = Path::new(&home)
                .join(".foundry")
                .join("bin")
                .join(format!("{name}{ext}"));
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from(name)
}

/// `tools/goat-attestor/../../contracts`, overridable with
/// `GOAT_CONTRACTS_DIR`.
fn contracts_dir() -> PathBuf {
    if let Ok(v) = std::env::var("GOAT_CONTRACTS_DIR") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("contracts")
}

/// A per-call scratch directory for `DeployStreamG`'s two output documents,
/// removed on drop — including on a panicking assertion.
///
/// # Why it lives under `contracts/deployments/` and not in `%TEMP%`
///
/// It was `tempfile::tempdir()` first, and every deploy failed:
/// `foundry.toml` declares
/// `fs_permissions = [{ access = "read-write", path = "./deployments" }]`, so
/// `vm.writeJson` to anything outside that subtree is refused by Foundry
/// itself. Widening `fs_permissions` to reach `%TEMP%` would trade a
/// deliberately narrow write capability for test convenience, which is the
/// wrong direction: that setting is what stops a cheatcode from writing
/// anywhere on the machine.
///
/// A uniquely-named child of the permitted directory keeps both properties —
/// the deploy writes only where it is allowed to, and this call is the only
/// thing that can name the path it writes to. The committed
/// `31337.stream-g.json` and `31337.stream-g.payload.json` are never opened.
///
/// The name carries the process id and a per-process counter, not a timestamp:
/// `gas_drips`'s flake in this same repair wave was a one-second-granularity
/// temp name that collided between processes, and repeating that here would
/// reintroduce the exact defect this type exists to remove.
struct ScratchDeploymentsDir {
    path: PathBuf,
    relative: String,
}

impl ScratchDeploymentsDir {
    fn create(contracts: &Path) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            ".harness-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let path = contracts.join("deployments").join(&name);
        // A leftover from a killed run would otherwise hand this call another
        // deploy's manifest — the precise failure mode being repaired.
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)
            .unwrap_or_else(|e| panic!("create scratch deployments dir {}: {e}", path.display()));
        Self {
            path,
            // Relative, because `vm.writeJson` resolves against the foundry
            // project root and this is handed to a `forge` whose working
            // directory is that root.
            relative: format!("./deployments/{name}"),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn relative(&self) -> &str {
        &self.relative
    }
}

impl Drop for ScratchDeploymentsDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Runs `DeployStreamG` against `rpc_url` and returns the manifest it wrote,
/// **into a private scratch directory this call owns**. See the module doc
/// for why each flag is there.
///
/// # Why this no longer touches `contracts/deployments/`
///
/// It used to. The sequence was: snapshot the committed bytes of
/// `31337.stream-g.json` (and, once the payload document existed,
/// `31337.stream-g.payload.json`), run `forge script --broadcast`, read the
/// files back for the addresses, restore the snapshots. That is shared mutable
/// repository state with no lock spanning the processes that touch it —
/// `forge test`'s two artifact tests write the same pair, and so does any
/// operator-run `forge script` — and [`HARNESS_LOCK`] is a *process*-local
/// `Mutex`, so it serialises nothing across them.
///
/// **The failure it produced was silent.** The read-back returned the COMMITTED
/// lab manifest instead of this run's deploy, and every hazard test then ran
/// against lab addresses that do not exist on the harness's node. Measured on
/// the pre-fix tree: 2 failures in 8 runs of the ignored suite, on two
/// different tests —
/// `…code_hash_gate_fails_closed_when_only_the_chain_returned_hash_moves`
/// ("precondition: DeployStreamG must have deployed a fee token with code",
/// because the committed `feeToken` has no code on a fresh node) and
/// `…v1_enroll_nonce_advance_invalidates_the_snapshot_and_fails_closed`
/// ("precondition: DeployStreamG must have made the deployer the quote signer",
/// left = `0xeBD5a850…`, the committed artifact's `quoteSigner`; right = the
/// anvil deployer). Both only went red because they happen to carry a
/// precondition assert. **The other fifteen would have passed vacuously against
/// the wrong deployment**, which is the part that mattered.
///
/// `DeployStreamG` now honours `STREAM_G_DEPLOYMENTS_DIR`
/// (`DeployStreamG.s.sol::_deploymentsDir`), so this function points the deploy
/// at a [`ScratchDeploymentsDir`] and reads back a file no other process can
/// name. There is nothing to save and nothing to restore, the committed
/// artifacts are never opened, and `forge test`'s regeneration loop is
/// untouched.
///
/// # The freshness assertions
///
/// A private directory makes a *stale* read impossible; the two assertions
/// after the parse make a *wrong* read impossible to ignore. `run()` defaults
/// `policySafe`, `deskOwner` and `quoteSigner` to `msg.sender`, which
/// `--sender` pins to [`ANVIL_DEPLOYER_ADDRESS`] — properties only a broadcast
/// deploy from this harness has, and exactly the properties the stale reads
/// violated. They are here rather than in the tests so the panic names the
/// deploy, not something a thousand lines downstream.
fn deploy_stream_g(rpc_url: &str) -> StreamGDeployment {
    let contracts = contracts_dir();
    assert!(
        contracts
            .join("script")
            .join("DeployStreamG.s.sol")
            .is_file(),
        "contracts dir {} has no script/DeployStreamG.s.sol; set GOAT_CONTRACTS_DIR",
        contracts.display()
    );
    let out_dir = ScratchDeploymentsDir::create(&contracts);
    let manifest_path = out_dir.path().join("31337.stream-g.json");
    let payload_path = out_dir.path().join("31337.stream-g.payload.json");

    let forge = tool_path("GOAT_FORGE_BIN", "forge");
    let mut deploy_cmd = Command::new(&forge);
    deploy_cmd
        .current_dir(&contracts)
        // `vm.writeJson` resolves a relative path against the foundry project
        // root, so this is handed over ABSOLUTE. `to_str` rather than
        // `display()` because a non-UTF-8 temp path would otherwise reach the
        // deploy as lossy bytes and write somewhere nobody named.
        .env("STREAM_G_DEPLOYMENTS_DIR", out_dir.relative())
        .args([
            "script",
            "script/DeployStreamG.s.sol:DeployStreamG",
            "--rpc-url",
            rpc_url,
            "--broadcast",
            "--sender",
            ANVIL_DEPLOYER_ADDRESS,
            "--private-key",
            ANVIL_DEPLOYER_KEY,
            // `--disable-code-size-limit` was DROPPED here in Wave 1 — see the
            // module doc. Forge's own size check is back on, so an over-size
            // contract is rejected before it is ever broadcast.
        ])
        .env("DEPLOYER_PRIVATE_KEY", ANVIL_DEPLOYER_KEY)
        // REQUIRED since `DeployStreamG.run()` stopped defaulting it: the field
        // is a digest of a schedule's tariff values, so there is no value the
        // script could invent. Without this the deploy aborts on
        // `vm.envBytes32: environment variable "STREAM_G_FEE_SCHEDULE_HASH" not
        // found` and every test in this module fails at `deploy_stream_g`.
        //
        // The value is the digest of the schedule this repo ships
        // (`fixtures/stream_g_fee_schedule.json`), which is what makes the
        // harness's gateway answer `feeScheduleHash()` with something a
        // `StreamGState::start` against this deployment would accept. It is the
        // same constant `runtime::test_support::FIXTURE_FEE_SCHEDULE_HASH`
        // carries and `quotes::tests::shipped_placeholder_fee_schedule_is_published_and_serves_no_price`
        // recomputes from the file, so a payload edit that moves the digest
        // fails that test rather than silently desynchronising this harness.
        .env(
            "STREAM_G_FEE_SCHEDULE_HASH",
            super::runtime::test_support::FIXTURE_FEE_SCHEDULE_HASH,
        )
        // REQUIRED since `DeployStreamG.run()` stopped defaulting it too
        // (2026-07-28). It used to fall back to
        // `keccak256("stream-g-manifest-g1")`, a tag that hashed nothing.
        //
        // **What this value is and is NOT, stated plainly.** It is the digest
        // of the committed lab payload, the one `runtime::test_support::
        // FIXTURE_DEPLOYMENT_MANIFEST_HASH` carries. Under `--broadcast` forge
        // prepends three library CREATE2 transactions, so every project
        // contract lands three nonces further along than under `forge test` —
        // which means the payload document THIS run writes names different
        // addresses than the one this digest was taken over. That is expected
        // and is not papered over: nothing in this harness calls
        // `StreamGState::start`, so no digest-vs-content check runs against
        // this deployment. `wave_d_manifest` builds a `DeploymentManifest`
        // struct directly from the deployed addresses, and the only manifest
        // assertion here is `activeManifestHash()` == the value Foundry wrote,
        // which this env var is exactly the source of.
        //
        // If a future test DOES start the attestor against a broadcast
        // deployment, this constant is the thing that must change: compute the
        // digest of the payload document that run wrote (`goat-attestor
        // deployment-manifest-hash --payload-json`) and republish it, rather
        // than loosening the startup check.
        .env(
            "STREAM_G_DEPLOYMENT_MANIFEST_HASH",
            super::runtime::test_support::FIXTURE_DEPLOYMENT_MANIFEST_HASH,
        );
    // The ONE call site that gets a probe URL: this is the only child in this
    // file that talks to the node, and it is where every recorded stall has
    // been seen.
    let output = output_within_probed(
        &mut deploy_cmd,
        FORGE_TIMEOUT,
        &format!(
            "forge script DeployStreamG --broadcast --rpc-url {rpc_url} ({})",
            forge.display()
        ),
        Some(rpc_url),
        FORENSICS_MIDFLIGHT_TRIGGER,
    );

    assert!(
        output.status.success(),
        "forge script DeployStreamG failed ({})\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let fresh = std::fs::read_to_string(&manifest_path).unwrap_or_else(|e| {
        panic!(
            "DeployStreamG reported success but {} is unreadable: {e}. This path is a private \
             temporary directory handed to the deploy as STREAM_G_DEPLOYMENTS_DIR, so a missing \
             file means the script did not honour it — check \
             DeployStreamG.s.sol::_deploymentsDir\n--- stdout ---\n{}",
            manifest_path.display(),
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert!(
        payload_path.is_file(),
        "DeployStreamG wrote {} but not the payload document beside it ({}); \
         writeManifest must call writeDeploymentPayload",
        manifest_path.display(),
        payload_path.display()
    );
    let deployment: StreamGDeployment = serde_json::from_str(&fresh)
        .unwrap_or_else(|e| panic!("stream-g manifest is not the expected shape: {e}\n{fresh}"));
    assert_eq!(deployment.chain_id, 31337, "manifest chain id");
    assert_eq!(deployment.phase, "G1", "manifest phase");

    // Freshness, asserted rather than assumed — see this function's doc. Both
    // of these are `msg.sender` in `DeployStreamG.run()`, and `--sender` pins
    // `msg.sender` to the harness deployer, so a document that disagrees is not
    // this deploy's.
    for (field, value) in [
        ("quoteSigner", &deployment.quote_signer),
        ("policySafe", &deployment.policy_safe),
        ("deskOwner", &deployment.desk_owner),
    ] {
        assert_eq!(
            addr20(value),
            addr20(ANVIL_DEPLOYER_ADDRESS),
            "the manifest at {} names {field} = {value}, but `run()` sets it from msg.sender and \
             --sender pins that to {ANVIL_DEPLOYER_ADDRESS}. This is not the document THIS deploy \
             wrote",
            manifest_path.display()
        );
    }
    deployment
}

// ---------------------------------------------------------------------------
// Wave B calldata — the two `FeeTokenRegistry` entry points this suite needs
// that no `ChainClient` method covers, because production never writes to the
// registry and never asks the registry to run its own gate.
//
// Both signature strings were confirmed with Foundry rather than read off the
// Solidity by eye; the four-byte selectors they hash to are pinned by
// `stream_g_anvil_wave_b_calldata_matches_foundrys_own_encoding`, which also
// pins the full `upsertTokenConfig` word layout against `cast calldata`
// output:
//
// ```text
// $ ~/.foundry/bin/cast sig \
//     "upsertTokenConfig((uint256,address,bytes32,bytes32,uint256,uint8,bytes32,bytes32,bytes32,uint64,bool))"
// 0xe3d57e3b
// $ ~/.foundry/bin/cast sig "isTokenAuthorized(address,uint256)"
// 0x66f41354
// ```
// ---------------------------------------------------------------------------

/// `FeeTokenRegistry.upsertTokenConfig(StreamGTypes.FeeTokenConfig)`. The
/// struct's eleven members are all static, so `abi.encode` inlines them as
/// eleven words immediately after the selector — no head/tail offset.
pub(crate) const SIG_UPSERT_TOKEN_CONFIG: &str =
    "upsertTokenConfig((uint256,address,bytes32,bytes32,uint256,uint8,bytes32,bytes32,bytes32,uint64,bool))";

/// `FeeTokenRegistry.isTokenAuthorized(address,uint256)` — the on-chain
/// `_isAuthorized` this crate's [`super::token_manifest::assert_token_authorized`]
/// mirrors.
pub(crate) const SIG_IS_TOKEN_AUTHORIZED: &str = "isTokenAuthorized(address,uint256)";

/// `FeeTokenRegistry.getTokenConfig(address)`. `crate::chain` has its own
/// encoder for this; the copy here exists so [`AnvilHarness::raw_token_config_words`]
/// is independent of the module whose decode it cross-checks.
///
/// ```text
/// $ ~/.foundry/bin/cast sig "getTokenConfig(address)"
/// 0xcb67e3b1
/// ```
pub(crate) const SIG_GET_TOKEN_CONFIG: &str = "getTokenConfig(address)";

fn word_from_u128(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn word_from_address(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// Calldata for [`SIG_UPSERT_TOKEN_CONFIG`]. `proxyIdentityHash`,
/// `domainNameHash`, `domainVersionHash` and `builtInModeId` are zero and
/// `configVersion` is zero on purpose: G1 rejects a non-zero
/// `proxyIdentityHash` outright, the three domain words are not read by
/// `_isAuthorized`, and the registry assigns `configVersion` itself
/// (`FeeTokenRegistry.sol:96`), so whatever is passed here is discarded.
pub(crate) fn encode_upsert_token_config(
    chain_id: u64,
    token: [u8; 20],
    runtime_code_hash: [u8; 32],
    capability_mask: u128,
    decimals: u8,
    active: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 11);
    out.extend_from_slice(&crate::chain::selector(SIG_UPSERT_TOKEN_CONFIG));
    out.extend_from_slice(&word_from_u128(u128::from(chain_id)));
    out.extend_from_slice(&word_from_address(&token));
    out.extend_from_slice(&runtime_code_hash);
    out.extend_from_slice(&[0u8; 32]); // proxyIdentityHash — G1: must be zero
    out.extend_from_slice(&word_from_u128(capability_mask));
    out.extend_from_slice(&word_from_u128(u128::from(decimals)));
    out.extend_from_slice(&[0u8; 32]); // domainNameHash
    out.extend_from_slice(&[0u8; 32]); // domainVersionHash
    out.extend_from_slice(&[0u8; 32]); // builtInModeId
    out.extend_from_slice(&[0u8; 32]); // configVersion — registry-assigned
    out.extend_from_slice(&word_from_u128(u128::from(active)));
    out
}

/// Calldata for [`SIG_IS_TOKEN_AUTHORIZED`].
pub(crate) fn encode_is_token_authorized(token: [u8; 20], capability_mask: u128) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 64);
    out.extend_from_slice(&crate::chain::selector(SIG_IS_TOKEN_AUTHORIZED));
    out.extend_from_slice(&word_from_address(&token));
    out.extend_from_slice(&word_from_u128(capability_mask));
    out
}

// ---------------------------------------------------------------------------
// Wave C calldata — `MockGasPriceOracle` (`contracts/test/mocks/`).
//
// Every four-byte value below is verbatim `cast sig` output, re-derived for
// this wave rather than copied from a doc comment:
//
// ```text
// $ ~/.foundry/bin/cast sig "getL1Fee(bytes)"
// 0x49948e0e
// $ ~/.foundry/bin/cast sig "getL1FeeUpperBound(uint256)"
// 0xf1c7a58b
// $ ~/.foundry/bin/cast sig "getOperatorFee(uint256)"
// 0x275aedd2
// $ ~/.foundry/bin/cast sig "setFees(uint256,uint256,uint256)"
// 0xcec10c11
// $ ~/.foundry/bin/cast sig "l1Fee()"
// 0x45ab82bf
// $ ~/.foundry/bin/cast sig "l1FeeUpperBound()"
// 0x549ce05f
// $ ~/.foundry/bin/cast sig "operatorFee()"
// 0x89afc0f1
// ```
//
// The first three are the OP-Stack predeploy methods `RpcChain` really
// calls; they are hard-coded HERE (and only here) precisely so that a
// cross-check taken through this module cannot inherit a bug in
// `base_fee::oracle_selector`. The last three are the mock's autogenerated
// public getters — a second source that reads the mock's STORAGE rather
// than re-entering the fee functions under test.
// ---------------------------------------------------------------------------

/// The fixed OP-Stack `GasPriceOracle` predeploy address, as the `0x`-hex
/// string JSON-RPC takes. Byte-identical to
/// [`super::base_fee::GAS_PRICE_ORACLE_ADDRESS`] (asserted in
/// [`tests::stream_g_anvil_wave_c_oracle_constants_match_foundrys_own_encoding`])
/// and the same address `contracts/test/StreamGMocks.t.sol:15` etches the
/// mock at.
pub(crate) const GAS_PRICE_ORACLE_ADDRESS_HEX: &str = "0x420000000000000000000000000000000000000F";

/// `MockGasPriceOracle.setFees(uint256,uint256,uint256)` — the mock's own
/// setter (`0xcec10c11`). Not an OP-Stack method: the real predeploy has no
/// such entry point, which is exactly why the mock is only ever etched onto
/// a harness-owned Anvil.
pub(crate) const SIG_SET_FEES: &str = "setFees(uint256,uint256,uint256)";

/// Calldata for [`SIG_SET_FEES`]. Three static `uint256` words in
/// declaration order: `l1Fee`, `l1FeeUpperBound`, `operatorFee`. Pinned
/// byte-for-byte against `cast calldata` output in
/// [`tests::stream_g_anvil_wave_c_oracle_constants_match_foundrys_own_encoding`],
/// because transposing two same-typed wei arguments here would silently
/// spike the wrong term and make every "independently spiked" claim in this
/// wave false.
pub(crate) fn encode_set_fees(
    l1_fee: u128,
    l1_fee_upper_bound: u128,
    operator_fee: u128,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 3);
    out.extend_from_slice(&crate::chain::selector(SIG_SET_FEES));
    out.extend_from_slice(&word_from_u128(l1_fee));
    out.extend_from_slice(&word_from_u128(l1_fee_upper_bound));
    out.extend_from_slice(&word_from_u128(operator_fee));
    out
}

/// `getL1Fee(bytes)` calldata built from the pasted `cast sig` selector and
/// hand-written ABI tail — deliberately duplicating
/// [`super::base_fee::encode_get_l1_fee`] so a cross-check through
/// [`AnvilHarness::oracle_raw_u256`] shares no code with it.
pub(crate) fn raw_oracle_calldata_l1_fee(unsigned_tx: &[u8]) -> Vec<u8> {
    let mut out = vec![0x49, 0x94, 0x8e, 0x0e];
    out.extend_from_slice(&word_from_u128(32)); // head: dynamic tail at 0x20
    out.extend_from_slice(&word_from_u128(unsigned_tx.len() as u128));
    out.extend_from_slice(unsigned_tx);
    let pad = (32 - (unsigned_tx.len() % 32)) % 32;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// `getL1FeeUpperBound(uint256)` calldata, selector pasted from `cast sig`.
pub(crate) fn raw_oracle_calldata_l1_fee_upper_bound(unsigned_tx_size: u64) -> Vec<u8> {
    let mut out = vec![0xf1, 0xc7, 0xa5, 0x8b];
    out.extend_from_slice(&word_from_u128(u128::from(unsigned_tx_size)));
    out
}

/// `getOperatorFee(uint256)` calldata, selector pasted from `cast sig`.
pub(crate) fn raw_oracle_calldata_operator_fee(gas_limit: u64) -> Vec<u8> {
    let mut out = vec![0x27, 0x5a, 0xed, 0xd2];
    out.extend_from_slice(&word_from_u128(u128::from(gas_limit)));
    out
}

/// `l1Fee()` — the mock's autogenerated public getter (`0x45ab82bf`).
pub(crate) fn raw_oracle_calldata_storage_l1_fee() -> Vec<u8> {
    vec![0x45, 0xab, 0x82, 0xbf]
}

/// `l1FeeUpperBound()` — autogenerated public getter (`0x549ce05f`).
pub(crate) fn raw_oracle_calldata_storage_l1_fee_upper_bound() -> Vec<u8> {
    vec![0x54, 0x9c, 0xe0, 0x5f]
}

/// `operatorFee()` — autogenerated public getter (`0x89afc0f1`).
pub(crate) fn raw_oracle_calldata_storage_operator_fee() -> Vec<u8> {
    vec![0x89, 0xaf, 0xc0, 0xf1]
}

/// `forge inspect <contract> deployedBytecode`, run in [`contracts_dir`].
///
/// `out/` and `cache/` are gitignored, so this is safe to run under the
/// "pilot artifacts left byte-identical" rule — unlike `forge script`, it
/// writes nothing under `deployments/` or `broadcast/`.
fn forge_inspect_deployed_bytecode(contract: &str) -> Vec<u8> {
    let contracts = contracts_dir();
    let forge = tool_path("GOAT_FORGE_BIN", "forge");
    let mut cmd = Command::new(&forge);
    cmd.current_dir(&contracts)
        .args(["inspect", contract, "deployedBytecode"]);
    let output = output_within(
        &mut cmd,
        FORGE_TIMEOUT,
        &format!(
            "forge inspect {contract} deployedBytecode ({})",
            forge.display()
        ),
    );
    assert!(
        output.status.success(),
        "forge inspect {contract} deployedBytecode failed ({})\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let hex_line = stdout
        .lines()
        .map(str::trim)
        .rfind(|l| l.starts_with("0x") && l.len() > 2)
        .unwrap_or_else(|| {
            panic!("forge inspect {contract} deployedBytecode printed no bytecode:\n{stdout}")
        });
    hex_bytes(hex_line)
}

// ---------------------------------------------------------------------------
// Wave D calldata — cluster staging on `EnrollmentRegistry` and
// `WalletSponsorshipRegistry`, plus the four state reads mandate 3 needs a
// second source for.
//
// **Read this before trusting any selector below.** Two of these methods take
// a `uint48` deadline, not a `uint256`, and the difference is a *different
// four-byte selector*. Hand-writing the signature strings from the Solidity by
// eye produced `registerPrimary(...uint256),bytes)` = `0x4eb4821e` and
// `linkSecondary(...uint256)...)` = `0x9c2d78a3`, both of which are wrong and
// would have made every staging transaction fall through to a non-existent
// fallback. The values used here come from the **compiled artifact**:
//
// ```text
// $ ~/.foundry/bin/forge inspect WalletSponsorshipRegistry methodIdentifiers
// | linkSecondary((address,address,uint256,uint48),bytes,(address,address,bytes32,bytes32,uint256,uint48),bytes) | 2970f8ad |
// | registerPrimary((address,address,bytes32,bytes32,uint256,uint48),bytes)                                      | c885a707 |
// | controllerEpoch(address)                                                                                     | ae8b568e |
// | controllerOf(address)                                                                                        | d3a2b210 |
// | linkNonces(address)                                                                                          | a777a0e6 |
// | primaryOf(address)                                                                                            | 64143788 |
// | setProfileIssuer(address,bool)                                                                               | fbaed208 |
// $ ~/.foundry/bin/forge inspect EnrollmentRegistry methodIdentifiers
// | enrollSelfWithSignature(address,uint256,bytes) | 9b125680 |
// | enrolled(address)                              | 10eb0e0e |
// | nonces(address)                                | 7ecebe00 |
// | setEnrolled(address,bool,bytes32)              | acb792dd |
// $ ~/.foundry/bin/forge inspect GoatRelayGateway methodIdentifiers
// | feeScheduleHash() | 74c223b9 |
// | intentUsed(bytes32) | a4532c02 |
// $ ~/.foundry/bin/forge inspect FeeTokenRegistry methodIdentifiers
// | getTokenConfigHash(address) | 7e221f83 |
// ```
//
// The two struct-taking methods are encoded by shelling out to
// [`cast_calldata`] rather than by hand: their arguments mix a static tuple
// with two dynamic `bytes`, and Foundry's own encoder cannot disagree with the
// contract it compiled.
// ---------------------------------------------------------------------------

/// `WalletSponsorshipRegistry.registerPrimary` — note `uint48`.
pub(crate) const SIG_REGISTER_PRIMARY: &str =
    "registerPrimary((address,address,bytes32,bytes32,uint256,uint48),bytes)";
/// `WalletSponsorshipRegistry.linkSecondary` — note both `uint48`s.
pub(crate) const SIG_LINK_SECONDARY: &str =
    "linkSecondary((address,address,uint256,uint48),bytes,(address,address,bytes32,bytes32,uint256,uint48),bytes)";
/// `EnrollmentRegistry.enrollSelfWithSignature` — `deadline` really is
/// `uint256` here (`EnrollmentRegistry.sol:59`).
pub(crate) const SIG_ENROLL_SELF_WITH_SIGNATURE: &str =
    "enrollSelfWithSignature(address,uint256,bytes)";

/// `EnrollmentRegistry.setEnrolled(address,bool,bytes32)` = `0xacb792dd`.
pub(crate) fn encode_set_enrolled(who: [u8; 20], status: bool, kyc_ref: [u8; 32]) -> Vec<u8> {
    let mut out = vec![0xac, 0xb7, 0x92, 0xdd];
    out.extend_from_slice(&word_from_address(&who));
    out.extend_from_slice(&word_from_u128(u128::from(status)));
    out.extend_from_slice(&kyc_ref);
    out
}

/// `WalletSponsorshipRegistry.setProfileIssuer(address,bool)` = `0xfbaed208`.
pub(crate) fn encode_set_profile_issuer(issuer: [u8; 20], allowed: bool) -> Vec<u8> {
    let mut out = vec![0xfb, 0xae, 0xd2, 0x08];
    out.extend_from_slice(&word_from_address(&issuer));
    out.extend_from_slice(&word_from_u128(u128::from(allowed)));
    out
}

/// `EnrollmentRegistry.nonces(address)` = `0x7ecebe00`. This is the
/// **`v1EnrollNonce` source** — `GoatRelayGateway.sol:258` fills
/// `NonceSnapshot.v1EnrollNonce` with literally
/// `enrollmentRegistry.nonces(v1Subject)`.
pub(crate) fn encode_enrollment_nonces(wallet: [u8; 20]) -> Vec<u8> {
    let mut out = vec![0x7e, 0xce, 0xbe, 0x00];
    out.extend_from_slice(&word_from_address(&wallet));
    out
}

/// `EnrollmentRegistry.enrolled(address)` = `0x10eb0e0e`.
pub(crate) fn encode_enrolled(wallet: [u8; 20]) -> Vec<u8> {
    let mut out = vec![0x10, 0xeb, 0x0e, 0x0e];
    out.extend_from_slice(&word_from_address(&wallet));
    out
}

/// `WalletSponsorshipRegistry.linkNonces(address)` = `0xa777a0e6`. This is the
/// **`linkNonce` source** — `GoatRelayGateway.sol:263` fills
/// `NonceSnapshot.linkNonce` with `sponsorship.linkNonces(secondary)`
/// (`WalletSponsorshipRegistry.sol:54`).
pub(crate) fn encode_link_nonces(secondary: [u8; 20]) -> Vec<u8> {
    let mut out = vec![0xa7, 0x77, 0xa0, 0xe6];
    out.extend_from_slice(&word_from_address(&secondary));
    out
}

/// `WalletSponsorshipRegistry.controllerOf(address)` = `0xd3a2b210`.
pub(crate) fn encode_controller_of(root: [u8; 20]) -> Vec<u8> {
    let mut out = vec![0xd3, 0xa2, 0xb2, 0x10];
    out.extend_from_slice(&word_from_address(&root));
    out
}

/// `WalletSponsorshipRegistry.controllerEpoch(address)` = `0xae8b568e`.
pub(crate) fn encode_controller_epoch(root: [u8; 20]) -> Vec<u8> {
    let mut out = vec![0xae, 0x8b, 0x56, 0x8e];
    out.extend_from_slice(&word_from_address(&root));
    out
}

/// `WalletSponsorshipRegistry.primaryOf(address)` = `0x64143788`.
pub(crate) fn encode_primary_of(who: [u8; 20]) -> Vec<u8> {
    let mut out = vec![0x64, 0x14, 0x37, 0x88];
    out.extend_from_slice(&word_from_address(&who));
    out
}

/// `FeeTokenRegistry.getTokenConfigHash(address)` = `0x7e221f83`.
pub(crate) fn encode_get_token_config_hash(token: [u8; 20]) -> Vec<u8> {
    let mut out = vec![0x7e, 0x22, 0x1f, 0x83];
    out.extend_from_slice(&word_from_address(&token));
    out
}

/// `GoatRelayGateway.feeScheduleHash()` = `0x74c223b9`.
pub(crate) fn encode_fee_schedule_hash() -> Vec<u8> {
    vec![0x74, 0xc2, 0x23, 0xb9]
}

/// `GoatRelayGateway.intentUsed(bytes32)` = `0xa4532c02`.
pub(crate) fn encode_intent_used(intent_id: [u8; 32]) -> Vec<u8> {
    let mut out = vec![0xa4, 0x53, 0x2c, 0x02];
    out.extend_from_slice(&intent_id);
    out
}

// ---------------------------------------------------------------------------
// Wave D2 calldata — the fee token (`PermitMockUSDT`, deployed by
// `DeployStreamG.s.sol:203`).
//
// Waves A-D never touched the fee token as a *token*: the hazard-3 gate reads
// its code hash and its registry config, and no earlier test needed a balance,
// an allowance or a permit. A lifecycle proof does — `StreamGEnroll.execute`
// collects the fee LAST (`StreamGCommon.collectEip2612`), so a payer with no
// balance or an unsigned permit turns the whole enrollment into a mined revert
// and there is no `SponsoredEnrollmentExecuted` to reconcile.
//
// Verbatim `cast sig` / `cast keccak` output, re-derived for this wave:
//
// ```text
// $ ~/.foundry/bin/cast sig "mint(address,uint256)"
// 0x40c10f19
// $ ~/.foundry/bin/cast sig "balanceOf(address)"
// 0x70a08231
// $ ~/.foundry/bin/cast sig "DOMAIN_SEPARATOR()"
// 0x3644e515
// $ ~/.foundry/bin/cast sig "nonces(address)"
// 0x7ecebe00
// $ ~/.foundry/bin/cast keccak "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
// 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9
// ```
//
// All five are pinned in
// [`tests::stream_g_anvil_wave_d2_fee_token_calldata_matches_foundrys_own_encoding`].
// ---------------------------------------------------------------------------

/// `PermitMockUSDT.mint(address,uint256)` = `0x40c10f19`.
///
/// The mock's `mint` is deliberately permissionless
/// (`contracts/test/mocks/PermitMockUSDT.sol:15`), so this needs no role; it is
/// still sent as a real transaction rather than by `anvil_setStorageAt` so the
/// balance lands in whatever slot the compiled ERC-20 actually uses.
pub(crate) fn encode_mint(to: [u8; 20], amount: u128) -> Vec<u8> {
    let mut out = vec![0x40, 0xc1, 0x0f, 0x19];
    out.extend_from_slice(&word_from_address(&to));
    out.extend_from_slice(&word_from_u128(amount));
    out
}

/// `GoatRelayGateway.setPaused(bool)` = `0x16c38b3c`, `onlyPolicy`.
///
/// 🔴 **Required before any Stream G action can execute, and nothing in this
/// crate knows it.** `GoatRelayGateway.sol:68` initialises `paused = true`, and
/// `DeployStreamG.s.sol:233-234` comments the consequence explicitly — "Activate
/// while paused remains true (default)" — so a freshly deployed gateway
/// activates *paused*, and `_requireLive` reverts `Paused()` (`0x9e87fac8`) on
/// every entry point.
///
/// `preflight::UNVERIFIED_CHECKS` already discloses this ("needs
/// `GoatRelayGateway.activated()/paused()`; no ChainClient read exists"), and
/// this wave is where the disclosed gap became an *observed* one: the first run
/// of [`tests::stream_g_anvil_reconciliation_confirms_a_real_broadcast_once_it_is_deep_enough`]
/// preflighted clean, signed, broadcast, and mined a `Paused()` revert. Nothing
/// here fixes that — adding the read is a `ChainClient` change, not a test
/// change — but the harness now names it rather than leaving the next reader to
/// decode a bare selector.
pub(crate) fn encode_set_paused(paused: bool) -> Vec<u8> {
    let mut out = vec![0x16, 0xc3, 0x8b, 0x3c];
    out.extend_from_slice(&word_from_u128(u128::from(paused)));
    out
}

/// `GoatRelayGateway.paused()` = `0x5c975abb`.
pub(crate) fn encode_paused() -> Vec<u8> {
    vec![0x5c, 0x97, 0x5a, 0xbb]
}

/// `IERC20.balanceOf(address)` = `0x70a08231`.
pub(crate) fn encode_balance_of(who: [u8; 20]) -> Vec<u8> {
    let mut out = vec![0x70, 0xa0, 0x82, 0x31];
    out.extend_from_slice(&word_from_address(&who));
    out
}

/// `IERC20Permit.DOMAIN_SEPARATOR()` = `0x3644e515`.
///
/// Read **live off the token** rather than recomputed from a name/version pair
/// guessed here. `PermitMockUSDT` is `ERC20Permit("Permit Mock USDT")`, i.e.
/// OpenZeppelin's `EIP712(name, "1")`; re-deriving that in Rust would put a
/// second copy of the token's domain in this file, and a permit signed under a
/// wrong domain does not fail loudly — it recovers *some other* address and the
/// enrollment reverts inside `permit()` with no indication that the domain was
/// the cause.
pub(crate) fn encode_domain_separator() -> Vec<u8> {
    vec![0x36, 0x44, 0xe5, 0x15]
}

/// `IERC20Permit.nonces(address)` = `0x7ecebe00`.
///
/// Byte-identical on the wire to [`encode_enrollment_nonces`] and kept separate
/// anyway, for the reason `crate::chain::SIG_ERC2612_NONCES` gives about its own
/// twin: these are different contract surfaces that happen to agree today, and a
/// shared helper would let a change to one silently retarget the other.
pub(crate) fn encode_permit_nonces(owner: [u8; 20]) -> Vec<u8> {
    let mut out = vec![0x7e, 0xce, 0xbe, 0x00];
    out.extend_from_slice(&word_from_address(&owner));
    out
}

/// `keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")`
/// — EIP-2612's typehash, as `cast keccak` prints it.
pub(crate) const EIP2612_PERMIT_TYPEHASH_HEX: &str =
    "0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9";

/// The EIP-2612 `Permit` struct hash, under the **token's** own domain.
///
/// `nonce` is the token's `nonces(owner)`, which is why it is an argument: it is
/// nowhere in `preflight::Eip2612Authorization`, and that absence is exactly the
/// residual entry 10 of `preflight::UNVERIFIED_CHECKS` records. This function is
/// the test-side counterpart — the one place in the crate that can produce a
/// permit a real `permit()` will accept.
pub(crate) fn eip2612_permit_struct_hash(
    owner: [u8; 20],
    spender: [u8; 20],
    value: u128,
    nonce: u128,
    deadline: u64,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 6);
    buf.extend_from_slice(&bytes32(EIP2612_PERMIT_TYPEHASH_HEX));
    buf.extend_from_slice(&word_from_address(&owner));
    buf.extend_from_slice(&word_from_address(&spender));
    buf.extend_from_slice(&word_from_u128(value));
    buf.extend_from_slice(&word_from_u128(nonce));
    buf.extend_from_slice(&word_from_u128(u128::from(deadline)));
    crate::merkle::keccak256(&buf)
}

/// `cast calldata <sig> <args...>`, run in [`contracts_dir`].
///
/// Foundry's own ABI encoder. Used only for the two struct-plus-`bytes`
/// staging calls, where a hand-rolled head/tail layout would be the single
/// most likely place for this file to be silently wrong.
pub(crate) fn cast_calldata(sig: &str, args: &[String]) -> Vec<u8> {
    let cast = tool_path("GOAT_CAST_BIN", "cast");
    let mut cmd = Command::new(&cast);
    cmd.current_dir(contracts_dir());
    cmd.arg("calldata").arg(sig);
    for a in args {
        cmd.arg(a);
    }
    let output = output_within(
        &mut cmd,
        CAST_TIMEOUT,
        &format!("cast calldata {sig} ({})", cast.display()),
    );
    assert!(
        output.status.success(),
        "cast calldata {sig} failed ({})\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let line = stdout
        .lines()
        .map(str::trim)
        .rfind(|l| l.starts_with("0x") && l.len() > 2)
        .unwrap_or_else(|| panic!("cast calldata {sig} printed no calldata:\n{stdout}"));
    hex_bytes(line)
}

/// `0x`-prefixed 20-byte hex → array, panicking with context.
pub(crate) fn addr20(s: &str) -> [u8; 20] {
    parse_address20(s).unwrap_or_else(|e| panic!("bad address {s}: {e}"))
}

/// `0x`-prefixed 32-byte hex → array, panicking with context.
pub(crate) fn bytes32(s: &str) -> [u8; 32] {
    let hex_body = s.strip_prefix("0x").unwrap_or(s);
    let raw = hex::decode(hex_body).unwrap_or_else(|e| panic!("bad bytes32 {s}: {e}"));
    assert_eq!(raw.len(), 32, "bytes32 {s} must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

/// `0x`-prefixed hex of arbitrary length → bytes, panicking with context.
pub(crate) fn hex_bytes(s: &str) -> Vec<u8> {
    let hex_body = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(hex_body).unwrap_or_else(|e| panic!("bad hex {s}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The regression [`output_within`] exists for.**
    ///
    /// A child that never finishes must be killed at the budget and reported
    /// with its own name and that budget — not waited on forever until the
    /// enclosing gate step's watchdog kills the whole tree and prints a list
    /// of pids.
    ///
    /// Reverting `output_within` to `Command::output()` does not make this
    /// test fail; it makes it **hang**, which is the point. The child is a
    /// real `anvil` on a free port (never 8545, via [`free_port`]): an
    /// unconditionally long-lived process, so the timeout is deterministic
    /// rather than a race. `#[ignore]`d and therefore run by the hazard-suite
    /// step, because the default `--lib` run must not require Foundry on PATH.
    ///
    /// **Also the proof of the MID-FLIGHT probe** (see
    /// [`output_within_probed`]). The trigger is compressed from
    /// [`FORENSICS_MIDFLIGHT_TRIGGER`] to 200ms so the whole thing fits inside
    /// the 750ms budget; nothing else about the path is faked. Overloading one
    /// test is deliberate — it needs exactly the same fixture (a real,
    /// deliberately never-exiting node-facing child) and a second copy of that
    /// fixture would add ~1s to the hazard suite to prove the same mechanism.
    ///
    /// Mutations this detects: never spawning the watchdog; a watchdog that
    /// fires only on the timeout path; a mid-flight block that does not name
    /// the endpoint it probed.
    #[test]
    #[ignore = "spawns a real anvil as a deliberately never-exiting child"]
    fn output_within_kills_a_child_that_never_finishes_and_names_the_budget() {
        let _sink_lock = FORENSICS_SINK_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        FORENSICS_SINK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();

        let port = free_port();
        let anvil = tool_path("GOAT_ANVIL_BIN", "anvil");
        let mut cmd = Command::new(&anvil);
        cmd.args([
            "--port",
            &port.to_string(),
            "--chain-id",
            "31337",
            "--silent",
        ]);
        let what = format!("anvil --port {port} (deliberate never-exiting child)");
        let budget = Duration::from_millis(750);
        let probe_url = format!("http://127.0.0.1:{port}");
        let trigger = Duration::from_millis(200);

        // The panic is expected, so its default report would be noise in the
        // gate log for a passing test. Restored immediately after.
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let started = Instant::now();
        let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            output_within_probed(&mut cmd, budget, &what, Some(&probe_url), trigger)
        }))
        .err();
        let elapsed = started.elapsed();
        std::panic::set_hook(previous_hook);

        let payload = payload.expect("a child that never exits must not return an Output");
        let msg = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_else(|| "<non-string panic payload>".to_string());

        assert!(
            msg.contains(&what),
            "the timeout must name the tool it killed, got: {msg}"
        );
        assert!(
            msg.contains("750ms"),
            "the timeout must name the budget it exceeded, got: {msg}"
        );
        // Bounded, and bounded AT the budget: returning before it elapsed
        // would mean the child died on its own and this proved nothing.
        assert!(
            elapsed >= budget,
            "returned in {elapsed:?}, before the {budget:?} budget elapsed"
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "took {elapsed:?} — the budget did not bound the wait"
        );

        // The mid-flight reading must exist, and must have been taken while the
        // child was STILL RUNNING — the watchdog is joined before the panic
        // precisely so it is here by now.
        let recorded = FORENSICS_SINK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(
            recorded.len(),
            1,
            "a child that outlived the {trigger:?} trigger must produce exactly one mid-flight \
             reading, got {}",
            recorded.len()
        );
        assert!(
            recorded[0].contains("--- MID-FLIGHT:"),
            "the reading must announce itself as mid-flight, got:\n{}",
            recorded[0]
        );
        assert!(
            recorded[0].contains(&probe_url),
            "the reading must name the endpoint it probed, got:\n{}",
            recorded[0]
        );
        assert!(
            recorded[0].contains("live anvil processes:"),
            "the reading must carry the environmental counts, got:\n{}",
            recorded[0]
        );
    }

    // -- node forensics -------------------------------------------------
    //
    // All four are node-free and non-`#[ignore]`d on purpose: the measurement
    // this suite takes when it gives up must itself be proved by the DEFAULT
    // `cargo test --lib` run, not by the very step whose intermittent stall it
    // exists to characterise. A probe that could only be exercised inside the
    // flaky step would be trusted on exactly the runs where it matters and
    // verified on none of them.

    /// The report's **verdict line**, isolated.
    ///
    /// Asserting on the whole block is a trap that this file walked into once
    /// and must not walk into again: the block's own "HOW TO READ THIS" prose
    /// spells out both `ANSWERED` and `NO ANSWER`, so a whole-report
    /// `contains("ANSWERED")` is true unconditionally and cannot fail. That
    /// vacuity was caught by mutation, not by review.
    fn probe_line(report: &str) -> &str {
        report
            .lines()
            .find(|l| l.starts_with("fresh-socket eth_blockNumber to "))
            .unwrap_or_else(|| panic!("report has no probe line:\n{report}"))
    }

    /// A fake JSON-RPC endpoint that answers exactly one request.
    ///
    /// Deliberately not an anvil: this test has to prove the ANSWERED arm
    /// deterministically, and "start a real node" is the dependency the three
    /// tests around it are avoiding.
    ///
    /// The accept is polled against a deadline rather than blocking, so a
    /// probe that never connects makes the caller **fail** instead of parking
    /// on `join()` forever. The join is still load-bearing — it is what proves
    /// the probe really opened a socket — but a hang is a worse failure report
    /// than an assertion.
    fn serve_one_json_rpc_reply(body: &'static str) -> (String, std::thread::JoinHandle<bool>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a fake JSON-RPC endpoint");
        let addr = listener
            .local_addr()
            .expect("local_addr of the fake endpoint");
        listener
            .set_nonblocking(true)
            .expect("non-blocking fake endpoint");
        let handle = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut sock = loop {
                if Instant::now() >= deadline {
                    return false;
                }
                match listener.accept() {
                    Ok((sock, _)) => break sock,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return false,
                }
            };
            sock.set_nonblocking(false)
                .expect("blocking accepted socket");
            sock.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read timeout on the accepted socket");
            let mut scratch = [0u8; 2048];
            let _ = sock.read(&mut scratch);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(response.as_bytes());
            let _ = sock.flush();
            true
        });
        (format!("http://{addr}"), handle)
    }

    /// The ANSWERED arm, plus the two environmental counts that ride with it.
    ///
    /// Mutations this detects: a probe hard-wired to report failure; dropping
    /// the `live anvil processes` or `host TCP census` line; reporting the
    /// counts as prose without an actual number behind them.
    #[test]
    fn node_forensics_reports_a_serving_endpoint_as_answering_and_names_the_environment() {
        let (url, server) = serve_one_json_rpc_reply(r#"{"jsonrpc":"2.0","id":1,"result":"0x2a"}"#);

        let report = node_forensics(&url, Duration::from_secs(5));
        let served = server.join().expect("fake endpoint thread");
        assert!(
            served,
            "the probe never opened a socket to the endpoint, so nothing about reachability was \
             measured"
        );

        let verdict = probe_line(&report);
        assert!(
            verdict.contains(": ANSWERED in "),
            "an endpoint that replied must be reported as answering, got: {verdict}"
        );
        assert!(
            verdict.contains("\"0x2a\""),
            "the verdict must carry what the node actually said, got: {verdict}"
        );
        assert!(
            verdict.contains(&url),
            "the verdict must name the endpoint it probed, got: {verdict}"
        );

        // Both counts must be real numbers, not decoration. `starts_with` a
        // digit is what fails if the count is dropped or replaced by prose.
        for label in ["live anvil processes: ", "host TCP census: "] {
            let line = report
                .lines()
                .find(|l| l.starts_with(label))
                .unwrap_or_else(|| panic!("report has no `{label}` line:\n{report}"));
            let value = &line[label.len()..];
            assert!(
                value.chars().next().is_some_and(|c| c.is_ascii_digit()),
                "`{label}` must carry a measured count, got `{value}`"
            );
        }
    }

    /// The FILE sink, which is the one that has to survive a passing test.
    ///
    /// This test itself passes, so libtest discards everything
    /// [`record_forensics`] wrote to stderr — and the assertions below still
    /// hold, because they read the file. That is the property, demonstrated
    /// rather than asserted in a comment: the previous revision's `eprintln!`
    /// could not have been checked this way from a green test at all.
    ///
    /// Mutations this detects: reverting the sink to stderr only; truncating
    /// instead of appending (so the last reading wins and every earlier one is
    /// lost); dropping the arm, the test name, or the timestamp from the
    /// header; writing the header without the report body.
    #[test]
    fn a_forensics_reading_lands_in_a_file_that_outlives_a_passing_test() {
        let _sink_lock = FORENSICS_SINK_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().expect("tempdir for the forensics sink");
        // A subdirectory that does NOT exist, so the sink is also proved to
        // create its parent — under the gate the very first reading of a fresh
        // checkout arrives before anything has made `gate-logs/`.
        let path = dir.path().join("gate-logs").join("node-forensics.log");
        let previous = std::env::var("GOAT_FORENSICS_LOG").ok();
        std::env::set_var("GOAT_FORENSICS_LOG", &path);

        record_forensics(FORENSICS_ARM_MIDFLIGHT, Some("a_named_test"), "REPORT-ONE");
        record_forensics(FORENSICS_ARM_GIVE_UP, None, "REPORT-TWO");

        match previous {
            Some(v) => std::env::set_var("GOAT_FORENSICS_LOG", v),
            None => std::env::remove_var("GOAT_FORENSICS_LOG"),
        }

        let written = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("the forensics sink wrote no file at {}: {e}", path.display())
        });

        // Both readings, in order: an append, not an overwrite.
        let first = written
            .find("REPORT-ONE")
            .expect("the first reading's body is missing from the sink");
        let second = written
            .find("REPORT-TWO")
            .expect("the second reading overwrote the first instead of appending");
        assert!(
            first < second,
            "readings must accumulate in the order they were taken, got:\n{written}"
        );

        assert!(
            written.contains(FORENSICS_ARM_MIDFLIGHT) && written.contains(FORENSICS_ARM_GIVE_UP),
            "each reading must name which arm fired, got:\n{written}"
        );
        assert!(
            written.contains("[a_named_test]"),
            "a reading must name the test it belongs to, got:\n{written}"
        );

        // A timestamp, and a real one: `YYYY-MM-DDTHH:MM:SSZ` with a plausible
        // year. A hard-coded or zeroed stamp cannot line a reading up against
        // the gate's step logs, which is the only thing it is for.
        let stamp = written
            .split_whitespace()
            .find(|t| t.len() == 20 && t.ends_with('Z') && t.as_bytes()[10] == b'T')
            .unwrap_or_else(|| panic!("no ISO-8601 timestamp in the sink:\n{written}"));
        let year: i64 = stamp[..4].parse().expect("a four-digit year");
        assert!(
            (2025..2100).contains(&year),
            "the stamp `{stamp}` is not a live clock reading"
        );
    }

    /// **The shape the whole block exists for.** A peer that completes the TCP
    /// handshake and then never says anything is precisely what a wedged anvil
    /// looks like from this side — and precisely what an unbounded client
    /// waits on forever. Nothing is ever `accept()`ed here; the listen backlog
    /// completes the handshake, so the connection is genuinely ESTABLISHED and
    /// genuinely silent.
    ///
    /// Mutation this detects: a probe that reports reachability from the
    /// connect alone (which would call this node healthy), or one whose read
    /// has no timeout (which would hang instead of failing).
    #[test]
    fn a_socket_that_accepts_and_never_replies_is_reported_as_no_answer() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a silent peer");
        let addr = listener
            .local_addr()
            .expect("local_addr of the silent peer");
        let budget = Duration::from_millis(700);

        let started = Instant::now();
        let outcome = probe_node_over_a_fresh_connection(&format!("http://{addr}"), budget);
        let elapsed = started.elapsed();

        let (why, _) =
            outcome.expect_err("a peer that never replies must not be reported as answering");

        // TWO CLOCKS, so this lower bound is deliberately not exact.
        // `elapsed` comes from `Instant` (QPC on Windows). The wait it is
        // measuring is ended by the socket's SO_RCVTIMEO, which the OS times on
        // the system tick — a different clock, free to disagree with QPC by a
        // fraction of a millisecond. The read has been observed returning
        // ~0.3ms early on the QPC scale, so `elapsed >= budget` is a
        // cross-clock race that fails the whole gate at random, not a property
        // of the probe. Forgive exactly that skew and no more.
        //
        // WHAT THE FLOOR STILL CATCHES, which is the entire reason it exists:
        // a probe that never waited on the read at all (reachability inferred
        // from the connect, or an early return) comes back in single-digit
        // milliseconds — a loopback connect to a listening socket is ~0ms. The
        // floor here is 675ms, two orders of magnitude above that, so an
        // instant return fails this assertion just as hard as `>= budget` did.
        // The tolerance buys an instant return nothing; it only forgives clock
        // disagreement measured in microseconds.
        const CROSS_CLOCK_SLOP: Duration = Duration::from_millis(25);
        assert!(
            elapsed + CROSS_CLOCK_SLOP >= budget,
            "gave up in {elapsed:?}, more than {CROSS_CLOCK_SLOP:?} short of the {budget:?} \
             budget — that is not clock skew, it cannot have waited on the read, so this proved \
             nothing"
        );
        assert!(
            elapsed < Duration::from_secs(15),
            "took {elapsed:?} — the budget did not bound the probe, which is the hang this \
             forensics block must never itself become"
        );
        assert!(
            !why.is_empty(),
            "the failure must say what happened, so the next reader does not have to guess"
        );
        drop(listener);
    }

    /// The control arm: nothing listening at all. Distinguishes "refused" from
    /// "accepted and silent", which are different diagnoses — the first cannot
    /// be a wedged node because there is no node.
    #[test]
    fn a_port_with_nothing_listening_is_reported_as_no_answer() {
        let port = free_port();
        let budget = Duration::from_secs(5);

        let outcome =
            probe_node_over_a_fresh_connection(&format!("http://127.0.0.1:{port}"), budget);

        let (why, took) = outcome.expect_err("a closed port must not be reported as answering");
        // 🔴 THIS ASSERTION USED TO BE `took < budget`, AND IT FLAKED THE GATE.
        // The reasoning was that the OS refuses a closed loopback port promptly
        // (~2.0s measured), so returning before the budget distinguished "closed"
        // from "wedged". The premise is not guaranteed: Windows does not always
        // answer a closed port with a prompt RST — a dropped SYN runs the connect
        // out to the full budget, and the test failed with `took 5.0001621s`
        // against a 5s budget.
        //
        // The fix is to assert on the DISCRIMINATOR ITSELF rather than on a proxy
        // for it. What separates a closed port from a wedged node is the error
        // KIND — `ConnectionRefused` vs a timeout — which is semantic and stable.
        // Timing was only ever a stand-in for that, and a stand-in that depends
        // on OS scheduling belongs in no gate.
        //
        // The lower bound is kept in spirit by the sibling test
        // (`a_socket_that_accepts_and_never_replies_is_reported_as_no_answer`),
        // which proves the budget IS honoured when the peer accepts and goes
        // silent. Together the two still draw the distinction; neither now
        // depends on how fast the kernel says no.
        assert!(
            took <= budget + Duration::from_millis(250),
            "a refused connection must not exceed the {budget:?} budget (took {took:?}) — the \
             probe is unbounded"
        );
        let refused = why.contains("refused")
            || why.contains("os error 10061")
            || why.contains("ConnectionRefused");
        assert!(
            refused,
            "a closed port must be reported as REFUSED, not as a timeout — otherwise it is \
             indistinguishable from a wedged node, which is the one distinction this pair of \
             tests exists to draw. got: {why}"
        );
        assert!(
            !why.is_empty(),
            "the failure must say what happened, got an empty reason"
        );
    }

    /// [`PanicForensics`] fires on an unwinding drop and stays silent on an
    /// ordinary one.
    ///
    /// This is the wiring that makes every hazard-suite failure
    /// self-diagnosing — a `forge` timeout, an `RPC_READ_TIMEOUT` surfacing as
    /// a failed assertion, or a plain assertion failure — so it is proved
    /// rather than asserted in a comment.
    ///
    /// Mutations this detects: removing the `std::thread::panicking()` guard
    /// (arm 1 then records on every passing test); never recording at all (arm
    /// 2 finds nothing); rendering a failed probe as ANSWERED.
    #[test]
    fn harness_forensics_are_recorded_only_when_the_scope_is_left_by_a_panic() {
        let _sink_lock = FORENSICS_SINK_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // A closed port, so the probe is fast and its verdict is known in
        // advance — this test is about the drop wiring, not about the probe.
        let port = free_port();
        let url = format!("http://127.0.0.1:{port}");

        FORENSICS_SINK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();

        // Arm 1 — an ordinary drop records nothing. A forensics block on every
        // passing test is noise, and noise is how a record gets ignored.
        {
            let _quiet = PanicForensics::new(&url);
        }
        assert!(
            FORENSICS_SINK
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "a scope left normally must record nothing"
        );

        // Arm 2 — an unwinding drop records the block.
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _loud = PanicForensics::new(&url);
            panic!("deliberate: stands in for a hazard-suite test failing against its node");
        }));
        std::panic::set_hook(previous_hook);
        assert!(unwound.is_err(), "the deliberate panic must have unwound");

        let recorded = FORENSICS_SINK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(
            recorded.len(),
            1,
            "exactly one forensics block per unwinding harness scope, got {recorded:?}"
        );
        let verdict = probe_line(&recorded[0]);
        assert!(
            verdict.contains(": NO ANSWER after "),
            "the probe of a closed port must be recorded as NO ANSWER, got: {verdict}"
        );
        assert!(
            verdict.contains(&url),
            "the block must name the endpoint, got: {verdict}"
        );
        assert!(
            recorded[0].contains("live anvil processes:"),
            "the block must carry the live-anvil count, got:\n{}",
            recorded[0]
        );
    }

    /// **Calibration against a real node, and the proof that
    /// [`AnvilHarness`]'s field order is what it claims to be.**
    ///
    /// The three tests above prove the instrument can say NO ANSWER. This one
    /// proves it says ANSWERED when a genuine anvil is genuinely serving *at
    /// the moment a hazard-suite test fails against it* — which is the whole
    /// point, because a field-recorded ANSWERED is only evidence if the probe
    /// runs before the harness reaps its own node.
    ///
    /// Mutations this detects, and the reason it is worth a slot in the
    /// hazard suite:
    ///
    /// * move `_forensics` below `_node` in [`AnvilHarness`] and the recorded
    ///   verdict flips to NO ANSWER — an instrument that would have blamed
    ///   anvil for every failure, on every run, forever;
    /// * change `deploy_stream_g`'s `Some(rpc_url)` to `None` and the
    ///   mid-flight probe is silently disarmed. That is one argument on one
    ///   line with nothing else watching it, which is why [`LAST_PROBE_URL`]
    ///   exists and why this test deploys rather than using
    ///   `start_node_only` — the deploy IS the wiring under test.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn forensics_from_a_panicking_harness_scope_find_the_live_node_still_answering() {
        let _sink_lock = FORENSICS_SINK_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        FORENSICS_SINK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        *LAST_PROBE_URL.lock().unwrap_or_else(|e| e.into_inner()) = None;

        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let h = AnvilHarness::start();
            // The node is genuinely up before the deliberate failure, so an
            // ANSWERED below cannot be an artefact of probing something else.
            assert_eq!(
                json_rpc(h.rpc_url(), "eth_chainId", serde_json::json!([])).ok(),
                Some(serde_json::json!("0x7a69")),
                "the node must be serving before this test fakes a failure"
            );
            h.rpc_url().to_string()
        }));
        std::panic::set_hook(previous_hook);
        let rpc_url = unwound.expect("the harness must start and deploy before the arms below");

        // ARM 1 — the deploy armed the mid-flight probe. Asserted separately
        // from the unwind arm because it is a different failure: this one
        // leaves the instrument silent rather than lying.
        assert_eq!(
            LAST_PROBE_URL
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_deref(),
            Some(rpc_url.as_str()),
            "deploy_stream_g did not hand output_within_probed this node's URL, so the mid-flight \
             forensics probe is disarmed on the one call site that talks to the node"
        );

        // ARM 2 — an unwinding harness scope records the give-up reading, and
        // records it while the node is still alive.
        FORENSICS_SINK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _h = AnvilHarness::start_node_only();
            panic!("deliberate: stands in for a hazard-suite assertion failing on a healthy node");
        }));
        std::panic::set_hook(previous_hook);
        assert!(unwound.is_err(), "the deliberate panic must have unwound");

        let recorded = FORENSICS_SINK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(
            recorded.len(),
            1,
            "a panicking harness scope must record exactly one forensics block, got {recorded:?}"
        );
        let report = &recorded[0];
        assert!(
            probe_line(report).contains(": ANSWERED in "),
            "the probe ran AFTER the harness reaped its own node (or the node really was \
             unreachable). If this fails on a healthy machine, check that `_forensics` is still \
             declared BEFORE `_node` in AnvilHarness. Got:\n{report}"
        );

        // The live-anvil counter must have seen the harness's own node. >1 is
        // normal and correct under the gate, which runs a node of its own.
        let label = "live anvil processes: ";
        let line = report
            .lines()
            .find(|l| l.starts_with(label))
            .unwrap_or_else(|| panic!("no `{label}` line in:\n{report}"));
        let count: usize = line[label.len()..]
            .split_whitespace()
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("`{label}` carried no number: {line}"));
        assert!(
            count >= 1,
            "the harness's own anvil was alive and answering, so the counter must see at least \
             one process; got {count} in: {line}"
        );
    }

    use crate::chain::ChainClient;
    use crate::merkle::keccak256;
    use crate::stream_g::base_fee::{
        self, BaseFeeError, GasUnits, MaxFeePerGas, TxSizeBytes, WeiCeiling,
    };
    use crate::stream_g::token_manifest::{
        assert_token_authorized, read_live_token_state, Capability, DeploymentManifest,
        TrustedChain, CAP_EIP2612,
    };
    // -- Wave D --------------------------------------------------------
    use crate::sig_verify;
    use crate::stream_g::crypto_store::{self, DataKey, SecretHex};
    use crate::stream_g::models::{
        eip712_digest, eip712_domain_separator, fee_quote_digest, link_secondary_digest,
        sponsor_enrollment_core_hash, ActionType, FeeQuote, LinkSecondary, SponsorEnrollmentCore,
        WALLET_SPONSORSHIP_DOMAIN_NAME, WALLET_SPONSORSHIP_DOMAIN_VERSION,
    };
    use crate::stream_g::outbox::{self, SignedRawTx, SweepPolicy};
    use crate::stream_g::preflight::{
        self, Check, Disposition, Eip2612Authorization, PreflightError, RootAuthorization,
        SponsorEnrollment, SponsoredEnrollmentCall, V1Enrollment, AUTHORIZATION_MODE_EIP2612,
    };
    use crate::stream_g::profile_auth::AuthenticatedProfileId;
    use crate::stream_g::root_authorization::ROOT_AUTHORIZATION_TYPEHASH_STR;
    use crate::stream_g::store::{StreamGStore, StreamGStoreError};
    use crate::stream_g::broadcaster::SponsoredEnrollmentTxSigner;
    use crate::stream_g::submit::{
        self, SigningLeaseRegistry, SubmitContext, SubmitError,
    };
    // -- Wave D2 (the reconciliation lifecycle proof) --------------------
    use crate::stream_g::broadcaster::{
        BroadcastGasPolicy, PriorityFeePerGas, RpcChainEnrollmentSigner,
    };
    use crate::stream_g::maintenance::{
        run_reconcile, MaintenancePolicy, ReconcileStepOutcome, DEFAULT_MAX_SCAN_SPAN_BLOCKS,
        SWEEPER_CLAIM_OWNER,
    };
    use crate::stream_g::metrics::StreamGMetrics;
    use crate::stream_g::reconcile::{self, SCAN_CURSOR_ENROLLMENT_EXECUTED};
    use crate::stream_g::submit::{
        INTENT_STATUS_EXECUTED, INTENT_STATUS_SUBMITTED, NONCE_STATUS_ALLOCATED,
        NONCE_STATUS_CONSUMED, TX_ATTEMPT_STATUS_CONFIRMED, TX_ATTEMPT_STATUS_SUBMITTED,
    };
    use alloy::primitives::B256;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use sha2::{Digest as _, Sha256};
    use std::str::FromStr;
    use std::sync::Mutex as StdMutex;

    /// Wave A harness lifecycle proof: the node is real, it is **not** on the
    /// default port, and it is gone once the harness is dropped.
    ///
    /// This is the "no orphan anvil processes on exit" requirement expressed
    /// as an assertion instead of a promise. `start_node_only` is used
    /// deliberately — a deploy would add ~10s and prove nothing about
    /// lifecycle.
    ///
    /// Mutation this detects: removing the `kill`/`wait` from
    /// [`AnvilProcess::drop`] — the post-drop poll then keeps answering and
    /// the final assertion fails.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn stream_g_anvil_harness_owns_a_non_default_port_and_reaps_its_node() {
        let (url, port) = {
            let h = AnvilHarness::start_node_only();
            let url = h.rpc_url().to_string();
            let port = h.port();
            assert_ne!(
                port, DEFAULT_NODE_PORT,
                "harness must not bind the default node port"
            );
            // Positive arm: the node really is answering while the harness
            // is alive, so the "gone" assertion below cannot pass vacuously.
            let id = h
                .raw_rpc("eth_chainId", serde_json::json!([]))
                .expect("live node must answer eth_chainId while the harness is alive");
            assert_eq!(id.as_str(), Some("0x7a69"), "harness node chain id");
            println!("harness node up at {url} (port {port}), eth_chainId = {id}");
            (url, port)
        };

        // Negative arm: after drop the node must stop answering.
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut last_ok = None;
        while Instant::now() < deadline {
            match json_rpc(&url, "eth_chainId", serde_json::json!([])) {
                Ok(v) => {
                    last_ok = Some(v);
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => {
                    println!("harness node at {url} (port {port}) is gone after drop");
                    return;
                }
            }
        }
        panic!(
            "anvil on port {port} was still answering 20s after the harness was dropped \
             (last successful result: {last_ok:?}) — AnvilProcess::drop is not reaping it"
        );
    }

    /// `RpcChain::chain_id()` is an `eth_chainId` round-trip, proven against a
    /// live node whose answer **differs** from the configured `CHAIN_ID`.
    ///
    /// The pre-existing coverage (`rpc_chain.rs`'s
    /// `stream_g_rpc_chain_id_is_read_from_the_node_not_from_config`) is the
    /// negative arm: it points at a dead port and asserts an error. It cannot
    /// show what a *successful* live read returns, so on its own it is
    /// satisfied by an implementation that errors on transport and otherwise
    /// returns the config value. This is the paired positive arm, and it is
    /// non-tautological because the configured value (84532) and the node's
    /// value (31337) are deliberately different — an `Ok(self.chain_id)`
    /// implementation returns 84532 here.
    ///
    /// This matters beyond `RpcChain`: `token_manifest::read_live_token_state`
    /// uses exactly this read as the right-hand side of `_isAuthorized` check
    /// 3, so a config-sourced answer would make that check `x == x`.
    ///
    /// Mutation this detects: `RpcChain::chain_id` → `Ok(self.chain_id)`.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn stream_g_anvil_rpc_chain_id_returns_the_nodes_answer_not_the_configured_one() {
        let h = AnvilHarness::start();

        // Deliberately wrong: Base Sepolia's id, on a node that is 31337.
        const CONFIGURED: u64 = 84532;
        let chain = h.rpc_chain(CONFIGURED);
        assert_eq!(
            chain.configured_chain_id(),
            CONFIGURED,
            "precondition: the struct really does hold the wrong id, so Ok(84532) \
             below would be indistinguishable from the config-sourced bug"
        );

        let live = chain
            .chain_id()
            .expect("live eth_chainId round-trip must succeed against the harness node");
        println!("configured CHAIN_ID = {CONFIGURED}, RpcChain::chain_id() = {live}");
        assert_eq!(
            live, 31337,
            "chain_id() must report the node's chain, not the configured one"
        );
        assert_ne!(
            live, CONFIGURED,
            "chain_id() returned the configured value — the read is not live"
        );

        // Independent source: a raw JSON-RPC call that shares no code with
        // RpcChain.
        let raw = h
            .raw_rpc("eth_chainId", serde_json::json!([]))
            .expect("independent eth_chainId");
        assert_eq!(
            raw.as_str(),
            Some("0x7a69"),
            "independent eth_chainId disagrees with the harness"
        );
    }

    /// End-to-end live coverage for two Stream G reads that had none:
    /// `active_manifest_hash` (an `eth_call` whose return decode lives inside
    /// alloy) and `fee_token_code_hash` (a block-pinned `eth_getCode` plus the
    /// R1 empty-code refusal).
    ///
    /// Every value is cross-checked against a source that does **not** go
    /// through `RpcChain`: the deployment manifest Foundry wrote, and raw
    /// `eth_call`/`eth_getCode` issued by the harness with `reqwest`.
    ///
    /// Zero/negative assertions are paired with non-zero arms throughout:
    /// the empty-code refusal is asserted next to a successful hash of the
    /// same shape, and the genesis-block refusal next to the same call at the
    /// pinned head.
    ///
    /// Mutation this detects: `RpcChain::fee_token_code_hash`'s
    /// `.number(block)` → `.number(0)` (i.e. dropping R4 block pinning). Only
    /// a live node can catch that; every existing test of this path is
    /// against `MockChain`, which ignores the block argument.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn stream_g_anvil_manifest_and_code_hash_reads_are_live_and_block_pinned() {
        let h = AnvilHarness::start();
        let d = h.deployment().clone();
        println!(
            "deployed: feeTokenRegistry={} feeToken={} goatCoin={} gateway={}",
            d.fee_token_registry, d.fee_token, d.goat_coin, d.goat_relay_gateway
        );

        let chain = h.rpc_chain(31337);
        let registry = addr20(&d.fee_token_registry);
        let fee_token = addr20(&d.fee_token);
        let goat_coin = addr20(&d.goat_coin);

        // --- eth_blockNumber -------------------------------------------
        let block = chain
            .pinned_block_number()
            .expect("pinned_block_number must succeed against the harness node");
        assert!(
            block >= 1,
            "the deploy must have advanced the chain past genesis, got block {block}"
        );
        println!("pinned block = {block}");

        // --- FeeTokenRegistry.activeManifestHash() ----------------------
        let observed = chain
            .active_manifest_hash(registry, block)
            .expect("active_manifest_hash must succeed against the harness node");
        let from_manifest = bytes32(&d.deployment_manifest_hash);
        assert_eq!(
            observed,
            from_manifest,
            "activeManifestHash() disagrees with the manifest Foundry wrote: \
             chain=0x{} manifest=0x{}",
            hex::encode(observed),
            hex::encode(from_manifest)
        );
        // Independent third source: raw eth_call, selector 0xcc4d2a5e
        // (`cast sig "activeManifestHash()"`).
        let raw = h
            .raw_rpc(
                "eth_call",
                serde_json::json!([
                    {"to": d.fee_token_registry, "input": "0xcc4d2a5e"},
                    format!("0x{block:x}")
                ]),
            )
            .expect("independent eth_call activeManifestHash");
        assert_eq!(
            hex_bytes(raw.as_str().expect("eth_call returns hex string")),
            observed.to_vec(),
            "independent eth_call disagrees with RpcChain::active_manifest_hash"
        );
        assert_ne!(
            observed, [0u8; 32],
            "a zero manifest hash would make the comparison above vacuous"
        );

        // --- eth_getCode + keccak256 (R1) -------------------------------
        let token_hash = chain
            .fee_token_code_hash(fee_token, block)
            .expect("fee_token_code_hash must succeed for a deployed token at the pinned block");
        let raw_code = h
            .raw_rpc(
                "eth_getCode",
                serde_json::json!([d.fee_token, format!("0x{block:x}")]),
            )
            .expect("independent eth_getCode");
        let raw_code = hex_bytes(raw_code.as_str().expect("eth_getCode returns hex string"));
        assert!(
            !raw_code.is_empty(),
            "precondition: the fee token must actually have code at the pinned block"
        );
        assert_eq!(
            token_hash,
            keccak256(&raw_code),
            "fee_token_code_hash is not keccak256(eth_getCode(token, block))"
        );
        println!(
            "feeToken code = {} bytes, hash = 0x{}",
            raw_code.len(),
            hex::encode(token_hash)
        );

        // Address-specific, not a constant: a different deployed contract
        // must hash differently.
        let goat_hash = chain
            .fee_token_code_hash(goat_coin, block)
            .expect("fee_token_code_hash must succeed for GoatCoin too");
        assert_ne!(
            token_hash, goat_hash,
            "two different contracts hashed identically — the read ignores its address argument"
        );

        // R1 fail-closed: an account with no code is an Err, never
        // keccak256(""). Paired with the successful arms above.
        let empty_err = chain
            .fee_token_code_hash(addr20(ANVIL_DEPLOYER_ADDRESS), block)
            .expect_err("an EOA has no code — R1 requires an Err, not keccak256(\"\")");
        assert!(
            empty_err.to_string().contains("empty code"),
            "unexpected empty-code error: {empty_err}"
        );
        assert_ne!(
            token_hash,
            keccak256(&[]),
            "the successful hash must not be keccak256(\"\")"
        );

        // R4 block pinning is real: at genesis nothing is deployed, so the
        // same call at block 0 must fail closed.
        let genesis_err = chain
            .fee_token_code_hash(fee_token, 0)
            .expect_err("the fee token does not exist at genesis — this must fail closed");
        assert!(
            genesis_err.to_string().contains("empty code"),
            "unexpected genesis error: {genesis_err}"
        );
    }

    // =====================================================================
    // Wave B — hazard 3's binding proof (brief §2, `att-t6a-findings.md`
    // §8(b) obligations 1 and 2).
    //
    // Shared shape of the three tests below, and why it is that shape:
    //
    //   * the fee token is the one `DeployStreamG.s.sol` really deployed,
    //     and the registry is configured through a real `upsertTokenConfig`
    //     transaction with that token's TRUE code hash — so the honest state
    //     is honest by construction, not by fixture;
    //   * the POSITIVE arm runs first and must SUCCEED. Every zero/negative
    //     assertion below is paired with it; without it "rejected" would be
    //     indistinguishable from "never accepted anything";
    //   * the mutation is applied to the LIVE NODE, never to the test's own
    //     inputs, and each test asserts *in its own body* that the configured
    //     side is byte-identical across both arms. That second assertion is
    //     the whole difference between a gate and `x == x`: without it a
    //     reader cannot tell which side moved;
    //   * `FeeTokenRegistry.isTokenAuthorized` — the Solidity the Rust gate
    //     mirrors — is asked the same question on both arms, from calldata
    //     this module builds and return data this module decodes.
    // =====================================================================

    /// Deterministic pin (runs in the default suite, no node needed) for the
    /// two Wave B selectors and the full `upsertTokenConfig` word layout.
    ///
    /// The lane rule is that an on-chain constant is never derived by
    /// grepping. These came from Foundry, and the expected bytes below are a
    /// verbatim paste of its output:
    ///
    /// ```text
    /// $ ~/.foundry/bin/cast sig "upsertTokenConfig((uint256,address,bytes32,bytes32,uint256,uint8,bytes32,bytes32,bytes32,uint64,bool))"
    /// 0xe3d57e3b
    /// $ ~/.foundry/bin/cast sig "isTokenAuthorized(address,uint256)"
    /// 0x66f41354
    /// $ ~/.foundry/bin/cast sig "getTokenConfig(address)"
    /// 0xcb67e3b1
    /// $ ~/.foundry/bin/cast calldata \
    ///     "upsertTokenConfig((uint256,address,bytes32,bytes32,uint256,uint8,bytes32,bytes32,bytes32,uint64,bool))" \
    ///     "(31337,0x9A9f2CCfdE556A7E9Ff0848998Aa4a0CFD8863AE,0x2425dc5ea1951f934d98867cb6cb21957436738c1a1364e70d4104aa74aa58df,0x0000000000000000000000000000000000000000000000000000000000000000,1,6,0x0000000000000000000000000000000000000000000000000000000000000000,0x0000000000000000000000000000000000000000000000000000000000000000,0x0000000000000000000000000000000000000000000000000000000000000000,0,true)"
    /// 0xe3d57e3b…0001
    /// ```
    ///
    /// Mutation this detects: any reordering of the eleven words in
    /// [`encode_upsert_token_config`] (e.g. swapping `capabilityMask` and
    /// `decimals`, which are both small integers and would otherwise still
    /// produce a transaction the registry accepts).
    #[test]
    fn stream_g_anvil_wave_b_calldata_matches_foundrys_own_encoding() {
        assert_eq!(
            hex::encode(crate::chain::selector(SIG_UPSERT_TOKEN_CONFIG)),
            "e3d57e3b",
            "upsertTokenConfig selector"
        );
        assert_eq!(
            hex::encode(crate::chain::selector(SIG_IS_TOKEN_AUTHORIZED)),
            "66f41354",
            "isTokenAuthorized selector"
        );
        assert_eq!(
            hex::encode(crate::chain::selector(SIG_GET_TOKEN_CONFIG)),
            "cb67e3b1",
            "getTokenConfig selector"
        );

        const CAST_CALLDATA: &str = concat!(
            "e3d57e3b",
            "0000000000000000000000000000000000000000000000000000000000007a69",
            "0000000000000000000000009a9f2ccfde556a7e9ff0848998aa4a0cfd8863ae",
            "2425dc5ea1951f934d98867cb6cb21957436738c1a1364e70d4104aa74aa58df",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000006",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000001",
        );
        let ours = encode_upsert_token_config(
            31337,
            addr20("0x9A9f2CCfdE556A7E9Ff0848998Aa4a0CFD8863AE"),
            bytes32("0x2425dc5ea1951f934d98867cb6cb21957436738c1a1364e70d4104aa74aa58df"),
            CAP_EIP2612,
            6,
            true,
        );
        assert_eq!(hex::encode(&ours), CAST_CALLDATA);
    }

    /// Configures the registry with the fee token's true code hash and
    /// returns `(RpcChain, registry, token, true_code_hash)`. Shared by the
    /// three hazard-3 tests; deliberately not a fixture of the *values* the
    /// gate compares — every one of those is read back off the chain by the
    /// test itself.
    fn configure_honest_fee_token(h: &AnvilHarness) -> (RpcChain, [u8; 20], [u8; 20], [u8; 32]) {
        let d = h.deployment().clone();
        let chain = h.rpc_chain(31337);
        let block = chain
            .pinned_block_number()
            .expect("pinned_block_number against the harness node");

        // The TRUE code hash, from raw `eth_getCode` + this crate's keccak —
        // never from the value we are about to configure.
        let real_code = h.code_at(&d.fee_token, block);
        assert!(
            !real_code.is_empty(),
            "precondition: DeployStreamG must have deployed a fee token with code"
        );
        let true_hash = keccak256(&real_code);

        h.upsert_fee_token_config(true_hash, CAP_EIP2612, 6, true);

        (
            chain,
            addr20(&d.fee_token_registry),
            addr20(&d.fee_token),
            true_hash,
        )
    }

    /// **Hazard 3, obligation 1 — the non-tautological code-hash proof, on a
    /// live node.** This is the proof the G1 programme has owed since Task 4.
    ///
    /// `assert_token_authorized`'s check 4 compares a **chain-returned**
    /// `EXTCODEHASH` against a **configured** `runtimeCodeHash`. A test that
    /// changes both proves nothing. Here the only thing that changes between
    /// the two arms is what the node answers to `eth_getCode`: `anvil_setCode`
    /// etches GoatCoin's runtime at the fee token's address, leaving the
    /// registry's stored config — and therefore the configured
    /// `runtimeCodeHash` — untouched. The test then asserts, in its own body,
    /// that the configured value is byte-identical across both arms and that
    /// the observed value is not, which is what lets a reader see which side
    /// moved.
    ///
    /// Cross-checks that share no code with `RpcChain`: raw `eth_getCode`
    /// (the etched bytes), raw `getTokenConfig` word 2 (the configured hash,
    /// decoded here by slicing), and `FeeTokenRegistry.isTokenAuthorized` —
    /// the Solidity `_isAuthorized` this gate mirrors — which must flip from
    /// true to false in lockstep with the Rust gate.
    ///
    /// Mutations this detects, each run one at a time against a live node and
    /// reverted before the next:
    ///
    /// 1. `assert_token_authorized`'s check 4 →
    ///    `if live.runtime_code_hash != live.runtime_code_hash` (the exact
    ///    `x == x` tautology hazard 3 is about): the etched arm is accepted
    ///    and `expect_err` panics.
    /// 2. `read_live_token_state`'s
    ///    `observed_code_hash: ObservedCodeHash::new(observed_code_hash)` →
    ///    `ObservedCodeHash::new(capability.runtime_code_hash)` (sourcing the
    ///    "observed" value from the config): same failure, and additionally
    ///    the `assert_ne!(observed_after, observed_before)` fires.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn stream_g_anvil_code_hash_gate_fails_closed_when_only_the_chain_returned_hash_moves() {
        let h = AnvilHarness::start();
        let d = h.deployment().clone();
        let (chain, registry, token, true_hash) = configure_honest_fee_token(&h);

        // --- POSITIVE ARM: honest chain state authorizes. ----------------
        let block_ok = chain.pinned_block_number().expect("block @ honest arm");
        let reading_ok =
            read_live_token_state(TrustedChain::live(&chain), registry, token, block_ok)
                .expect("read_live_token_state must succeed against honest chain state");
        assert_token_authorized(&reading_ok, Capability::EIP2612).expect(
            "the honest arm MUST be authorized — without it every rejection below is vacuous",
        );

        let configured_before = reading_ok.capability().runtime_code_hash;
        let observed_before = reading_ok.observed_code_hash().into_inner();
        let config_hash_before = reading_ok.fee_token_config_hash();
        assert_eq!(configured_before, true_hash, "configured runtimeCodeHash");
        assert_eq!(observed_before, true_hash, "observed EXTCODEHASH");
        assert!(
            h.on_chain_is_token_authorized(CAP_EIP2612, block_ok),
            "the chain's own _isAuthorized disagrees with the Rust gate on the honest arm"
        );
        println!(
            "honest arm: authorized; configured == observed == 0x{}",
            hex::encode(true_hash)
        );

        // --- MUTATE ONLY THE CHAIN-RETURNED VALUE. -----------------------
        // GoatCoin's real runtime, etched at the fee token's address: a
        // contract-swap an attacker (or a botched upgrade) could actually
        // perform, not a synthetic byte string.
        let impostor_code = h.code_at(&d.goat_coin, block_ok);
        assert!(!impostor_code.is_empty(), "GoatCoin must have runtime code");
        assert_ne!(
            keccak256(&impostor_code),
            true_hash,
            "precondition: the etched code must actually differ from the fee token's"
        );
        h.anvil_set_code(&d.fee_token, &impostor_code);
        h.mine();

        let block_bad = chain.pinned_block_number().expect("block @ etched arm");
        assert!(
            block_bad > block_ok,
            "the etched arm must be read at a later block ({block_bad} <= {block_ok})"
        );

        let reading_bad =
            read_live_token_state(TrustedChain::live(&chain), registry, token, block_bad)
                .expect("the reads themselves still succeed — it is the GATE that must reject");
        let err = assert_token_authorized(&reading_bad, Capability::EIP2612)
            .expect_err("etched code at the fee token address MUST fail the gate closed");
        assert_eq!(
            err.to_string(),
            "token not authorized: observed EXTCODEHASH does not match configured runtimeCodeHash",
            "the gate rejected, but for the wrong reason"
        );
        assert_eq!(
            err.code(),
            crate::stream_g::token_manifest::ERR_TOKEN_UNSUPPORTED
        );

        // --- THE ASSERTIONS THAT MAKE THIS NON-TAUTOLOGICAL. -------------
        let configured_after = reading_bad.capability().runtime_code_hash;
        let observed_after = reading_bad.observed_code_hash().into_inner();
        assert_eq!(
            configured_after, configured_before,
            "the CONFIGURED runtimeCodeHash moved between the arms — this proof would be x != x, \
             not a gate"
        );
        assert_eq!(
            reading_bad.fee_token_config_hash(),
            config_hash_before,
            "the registry's stored feeTokenConfigHash moved — the config was touched"
        );
        assert_ne!(
            observed_after, observed_before,
            "the CHAIN-RETURNED EXTCODEHASH did not move — the etch did nothing and the \
             rejection above came from somewhere else"
        );
        assert_eq!(
            observed_after,
            keccak256(&impostor_code),
            "the observed hash is not keccak256 of the code actually on chain"
        );

        // Independent of `RpcChain` on both halves: raw eth_getCode, and the
        // configured word sliced out of raw getTokenConfig return data.
        assert_eq!(
            h.code_at(&d.fee_token, block_bad),
            impostor_code,
            "independent eth_getCode does not report the etched code"
        );
        assert_eq!(
            h.raw_token_config_words(block_bad)[2],
            configured_before,
            "independent getTokenConfig reports a different configured runtimeCodeHash"
        );

        // The Solidity gate agrees, and it flipped for the same reason.
        assert!(
            !h.on_chain_is_token_authorized(CAP_EIP2612, block_bad),
            "FeeTokenRegistry._isAuthorized still authorizes the etched token — the two \
             implementations disagree"
        );
        println!(
            "etched arm: rejected; configured still 0x{} but observed now 0x{}",
            hex::encode(configured_after),
            hex::encode(observed_after)
        );
    }

    /// **Hazard 3, obligation 2 — the `LiveChainId` half, on a live node.**
    ///
    /// Check 3 compares the registry's declared `chainId` against
    /// `ChainClient::chain_id()`. Before Task 6 Wave B the right-hand side was
    /// `capability.chain_id`, i.e. the same field — `x == x`. This moves only
    /// the node (`anvil_setChainId`), leaving the registry's stored `chainId`
    /// word byte-identical, and asserts both facts in the test body.
    ///
    /// The code hash is deliberately left honest here so that check 4 cannot
    /// be what rejects: the error string is asserted exactly.
    ///
    /// Mutations this detects:
    ///
    /// 1. `read_live_token_state`'s `live_chain_id: LiveChainId::new(live_chain_id)`
    ///    → `LiveChainId::new(capability.chain_id)` (sourcing the live value
    ///    from the config being checked): the switched-chain arm is accepted.
    /// 2. `RpcChain::chain_id` → `Ok(self.chain_id)` (returning the `CHAIN_ID`
    ///    config field instead of the `eth_chainId` round-trip): same failure.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn stream_g_anvil_chain_id_gate_fails_closed_when_only_the_node_switches_chains() {
        let h = AnvilHarness::start();
        let (chain, registry, token, true_hash) = configure_honest_fee_token(&h);

        // --- POSITIVE ARM ------------------------------------------------
        let block_ok = chain.pinned_block_number().expect("block @ honest arm");
        let reading_ok =
            read_live_token_state(TrustedChain::live(&chain), registry, token, block_ok)
                .expect("honest chain state must produce a reading");
        assert_token_authorized(&reading_ok, Capability::EIP2612)
            .expect("the honest arm MUST be authorized");
        assert_eq!(reading_ok.live_chain_id().into_inner(), 31337);
        assert_eq!(reading_ok.capability().chain_id, 31337);
        let configured_chain_id_before = reading_ok.capability().chain_id;
        let configured_chain_word_before = h.raw_token_config_words(block_ok)[0];
        assert!(h.on_chain_is_token_authorized(CAP_EIP2612, block_ok));

        // --- MUTATE ONLY THE NODE ----------------------------------------
        const SWITCHED_TO: u64 = 84532; // Base Sepolia's id
        h.anvil_set_chain_id(SWITCHED_TO);
        h.mine();
        let block_bad = chain.pinned_block_number().expect("block @ switched arm");

        let reading_bad =
            read_live_token_state(TrustedChain::live(&chain), registry, token, block_bad)
                .expect("the reads still succeed — it is the GATE that must reject");
        let err = assert_token_authorized(&reading_bad, Capability::EIP2612)
            .expect_err("a node that switched chains MUST fail the gate closed");
        assert_eq!(
            err.to_string(),
            "token not authorized: configured chainId does not match live chain",
            "the gate rejected, but for the wrong reason"
        );

        // --- NON-TAUTOLOGY -----------------------------------------------
        assert_eq!(
            reading_bad.capability().chain_id,
            configured_chain_id_before,
            "the CONFIGURED chainId moved between the arms"
        );
        assert_eq!(
            h.raw_token_config_words(block_bad)[0],
            configured_chain_word_before,
            "independent getTokenConfig reports a different configured chainId word"
        );
        assert_eq!(
            reading_bad.live_chain_id().into_inner(),
            SWITCHED_TO,
            "the LIVE chain id did not move — anvil_setChainId did nothing, or chain_id() is \
             not a live read"
        );
        assert_ne!(
            reading_bad.live_chain_id().into_inner(),
            reading_ok.live_chain_id().into_inner()
        );
        // Independent second source for the live half.
        assert_eq!(
            h.raw_rpc("eth_chainId", serde_json::json!([]))
                .expect("independent eth_chainId")
                .as_str(),
            Some("0x14a34"),
            "independent eth_chainId disagrees"
        );
        // The code hash is untouched, so check 4 is not what rejected.
        assert_eq!(reading_bad.capability().runtime_code_hash, true_hash);
        assert_eq!(reading_bad.observed_code_hash().into_inner(), true_hash);
        assert!(
            !h.on_chain_is_token_authorized(CAP_EIP2612, block_bad),
            "FeeTokenRegistry._isAuthorized still authorizes on the switched chain"
        );
        println!(
            "switched arm: rejected; configured chainId still {configured_chain_id_before}, \
             live chain id now {SWITCHED_TO}"
        );

        // Leave the node on the chain the harness advertised, so nothing that
        // runs after this point inherits a surprise.
        h.anvil_set_chain_id(31337);
    }

    /// **Hazard 3, obligation 3 — check ORDER, proven discriminatingly on
    /// live chain state.**
    ///
    /// `assert_token_authorized` documents itself as an exact mirror of
    /// `FeeTokenRegistry._isAuthorized` (`FeeTokenRegistry.sol:202-214`):
    /// same five checks, same order, short-circuiting on the first failure.
    /// "Same order" is unobservable when only one check can fail, so this
    /// test breaks **chainId (check 3) and codehash (check 4) simultaneously
    /// on the node** and asserts which one is reported.
    ///
    /// Both arms use the same deployment, the same registry config and the
    /// same request; they differ in exactly one bit of live node state (the
    /// chain id), and the reported reason changes with it. A test that only
    /// asserted "some rejection happened" would pass against an
    /// implementation whose five checks ran in any order at all.
    ///
    /// The counters are the two production error reasons themselves, read off
    /// the value production actually returns — not a test-local recorder.
    ///
    /// **What this does NOT prove** (stated so the record is not overread):
    /// this is ordering *within* the gate. The separate claim that the token
    /// gate runs before the exposure gate / any fee-oracle call is proven
    /// against `MockChain` counters in
    /// `quotes.rs::token_gate_ordering_is_discriminating_not_a_zero_versus_zero_assertion`;
    /// no live-node equivalent exists yet, because `RpcChain` exposes no call
    /// counters and an `eth_call` leaves no chain-side trace to count.
    ///
    /// Mutation this detects: swapping the chainId and codehash blocks in
    /// `assert_token_authorized` — arm A then reports the EXTCODEHASH reason
    /// instead of the chainId one.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn stream_g_anvil_gate_check_order_mirrors_is_authorized_on_live_state() {
        let h = AnvilHarness::start();
        let d = h.deployment().clone();
        let (chain, registry, token, true_hash) = configure_honest_fee_token(&h);

        // --- POSITIVE ARM: nothing broken, gate passes. -------------------
        let block_ok = chain.pinned_block_number().expect("block @ honest arm");
        let reading_ok =
            read_live_token_state(TrustedChain::live(&chain), registry, token, block_ok)
                .expect("honest chain state must produce a reading");
        assert_token_authorized(&reading_ok, Capability::EIP2612)
            .expect("the honest arm MUST be authorized");
        assert_eq!(reading_ok.capability().runtime_code_hash, true_hash);

        // --- Break BOTH on the node: chainId AND codehash. ---------------
        let impostor_code = h.code_at(&d.goat_coin, block_ok);
        h.anvil_set_code(&d.fee_token, &impostor_code);
        h.anvil_set_chain_id(84532);
        h.mine();
        let block_both = chain
            .pinned_block_number()
            .expect("block @ both-broken arm");

        let reading_both =
            read_live_token_state(TrustedChain::live(&chain), registry, token, block_both)
                .expect("the reads still succeed");
        // Precondition: both checks really are violated, so the reason below
        // is a genuine choice between two available failures and not the only
        // one on offer.
        assert_ne!(
            reading_both.capability().chain_id,
            reading_both.live_chain_id().into_inner(),
            "precondition: check 3 must be violated"
        );
        assert_ne!(
            reading_both.observed_code_hash().into_inner(),
            reading_both.capability().runtime_code_hash,
            "precondition: check 4 must be violated"
        );
        let err_both = assert_token_authorized(&reading_both, Capability::EIP2612)
            .expect_err("both checks are violated — this must fail closed");
        assert_eq!(
            err_both.to_string(),
            "token not authorized: configured chainId does not match live chain",
            "check 3 (chainId) must short-circuit before check 4 (codehash), as \
             _isAuthorized does"
        );

        // --- Arm B: same state, one bit different — chain id restored. ---
        h.anvil_set_chain_id(31337);
        h.mine();
        let block_code_only = chain
            .pinned_block_number()
            .expect("block @ code-only-broken arm");
        let reading_code_only =
            read_live_token_state(TrustedChain::live(&chain), registry, token, block_code_only)
                .expect("the reads still succeed");
        assert_eq!(
            reading_code_only.capability().chain_id,
            reading_code_only.live_chain_id().into_inner(),
            "check 3 must now be satisfied"
        );
        let err_code_only = assert_token_authorized(&reading_code_only, Capability::EIP2612)
            .expect_err("the etched code alone must still fail closed");
        assert_eq!(
            err_code_only.to_string(),
            "token not authorized: observed EXTCODEHASH does not match configured runtimeCodeHash",
            "with check 3 satisfied the gate must fall through to check 4"
        );
        assert_ne!(
            err_both.to_string(),
            err_code_only.to_string(),
            "the two arms reported the same reason — this test is not discriminating anything"
        );
        println!("order proof: both-broken -> {err_both}; code-only -> {err_code_only}");
    }

    // =====================================================================
    // Wave C — hazard 1's binding proof (brief §3): Base L2 fee variance.
    //
    // Per spec §8.1 the native-ETH exposure bound is the SUM of three
    // independently obtained values:
    //
    //   reserve = (gas ceiling × maxFeePerGas)      <- L2 execution
    //           + max(getL1Fee, getL1FeeUpperBound) <- L1 data availability
    //           + getOperatorFee                    <- Isthmus operator fee
    //
    // A single combined spike cannot distinguish "all three terms are
    // load-bearing" from "one term is load-bearing and the other two are
    // silently dropped": both produce a rejection. So each term is spiked
    // ON ITS OWN, with the other terms left at their normal values, and
    // each arm asserts the FULL reserve equation rather than merely "it was
    // rejected". That equation is what pins which term moved — e.g. the
    // L1-DA arm's expected reserve contains the normal L2 and operator
    // values, so an implementation that had dropped either of those would
    // produce a different number and fail here.
    //
    // Every spike is reverted and the success arm re-asserted before the
    // next spike, so no rejection can be inherited from a previous arm.
    // =====================================================================

    /// L2 execution ceiling used by every Wave C arm (gas units).
    const WAVE_C_GAS_CEILING: u64 = 500_000;
    /// 1 gwei — the honest `maxFeePerGas`.
    const WAVE_C_NORMAL_MAX_FEE_PER_GAS: u128 = 1_000_000_000;
    /// The quote-time unsigned-size ceiling, in bytes.
    const WAVE_C_TX_SIZE_CEILING: u64 = 2_000;
    /// Honest `getL1Fee(bytes)` answer: 2e12 wei.
    const WAVE_C_NORMAL_L1_EXACT_WEI: u128 = 2_000_000_000_000;
    /// Honest `getL1FeeUpperBound(uint256)` answer: 3e12 wei. Deliberately
    /// larger than the exact fee so `reserve_wei`'s `max()` picks it at
    /// submit time in the honest arm.
    const WAVE_C_NORMAL_L1_UPPER_WEI: u128 = 3_000_000_000_000;
    /// Honest `getOperatorFee(uint256)` answer: 1e9 wei.
    const WAVE_C_NORMAL_OPERATOR_WEI: u128 = 1_000_000_000;
    /// `StreamGConfig::max_native_exposure_wei` for these arms: 1 ETH.
    const WAVE_C_EXPOSURE_CEILING_WEI: u128 = 1_000_000_000_000_000_000;

    /// 5e12 wei/gas — spikes L2 execution alone to 2.5 ETH.
    const WAVE_C_SPIKED_MAX_FEE_PER_GAS: u128 = 5_000_000_000_000;
    /// 7 ETH. Distinct from every other spiked constant on purpose: the
    /// reserve assertion then identifies which oracle call fed the `max()`.
    const WAVE_C_SPIKED_L1_EXACT_WEI: u128 = 7_000_000_000_000_000_000;
    /// 9 ETH.
    const WAVE_C_SPIKED_L1_UPPER_WEI: u128 = 9_000_000_000_000_000_000;
    /// 4 ETH.
    const WAVE_C_SPIKED_OPERATOR_WEI: u128 = 4_000_000_000_000_000_000;

    /// The EIP-2718 bytes the submit arms hash. Content is irrelevant to the
    /// mock (which ignores its arguments) but the LENGTH is not: it is what
    /// `submit_exposure` passes to `getL1FeeUpperBound`, and the independent
    /// cross-check re-reads with the same size.
    fn wave_c_unsigned_tx() -> Vec<u8> {
        (0..137u32).map(|i| (i % 251) as u8).collect()
    }

    /// Honest L2 term: `gas ceiling × maxFeePerGas`.
    const fn wave_c_normal_l2_wei() -> u128 {
        (WAVE_C_GAS_CEILING as u128) * WAVE_C_NORMAL_MAX_FEE_PER_GAS
    }

    /// Spiked L2 term.
    const fn wave_c_spiked_l2_wei() -> u128 {
        (WAVE_C_GAS_CEILING as u128) * WAVE_C_SPIKED_MAX_FEE_PER_GAS
    }

    /// Asserts the gate rejected for the exposure reason **and** that the
    /// reserve it computed is exactly `expected_reserve`.
    ///
    /// The second half is what makes each arm term-specific: "rejected" on
    /// its own is satisfied by a gate that ignores two of the three terms,
    /// whereas the exact reserve is only reproducible if every term was
    /// summed at the value the chain actually reported.
    fn assert_rejected_with_reserve(err: BaseFeeError, expected_reserve: u128, arm: &str) {
        match err {
            BaseFeeError::ExposureExceedsSchedule {
                reserve_wei,
                ceiling_wei,
            } => {
                assert_eq!(
                    ceiling_wei, WAVE_C_EXPOSURE_CEILING_WEI,
                    "{arm}: the gate was checked against a different ceiling"
                );
                assert_eq!(
                    reserve_wei, expected_reserve,
                    "{arm}: reserve {reserve_wei} != expected {expected_reserve} — the spiked \
                     term was not summed at the value the oracle reported, or another term moved"
                );
                assert!(
                    reserve_wei > ceiling_wei,
                    "{arm}: rejection with a reserve at or below the ceiling"
                );
            }
            other => panic!("{arm}: expected ExposureExceedsSchedule, got {other:?}"),
        }
    }

    /// Etches the mock predeploy and sets the three honest fee values,
    /// returning a real [`RpcChain`] against the harness node.
    fn oracle_at_normal_fees(h: &AnvilHarness) -> RpcChain {
        h.etch_gas_price_oracle();
        h.set_oracle_fees(
            WAVE_C_NORMAL_L1_EXACT_WEI,
            WAVE_C_NORMAL_L1_UPPER_WEI,
            WAVE_C_NORMAL_OPERATOR_WEI,
        );
        h.rpc_chain(31337)
    }

    /// Cross-checks the three fee values `RpcChain` would see against two
    /// sources that share no code with it: the mock's autogenerated public
    /// storage getters, and raw `eth_call`s to the three OP-Stack methods
    /// built from `cast sig` selector literals.
    fn assert_oracle_state_independently(
        h: &AnvilHarness,
        l1_exact: u128,
        l1_upper: u128,
        operator: u128,
        arm: &str,
    ) {
        assert_eq!(
            h.oracle_raw_u256(&raw_oracle_calldata_storage_l1_fee(), "l1Fee()"),
            l1_exact,
            "{arm}: mock storage l1Fee"
        );
        assert_eq!(
            h.oracle_raw_u256(
                &raw_oracle_calldata_storage_l1_fee_upper_bound(),
                "l1FeeUpperBound()"
            ),
            l1_upper,
            "{arm}: mock storage l1FeeUpperBound"
        );
        assert_eq!(
            h.oracle_raw_u256(&raw_oracle_calldata_storage_operator_fee(), "operatorFee()"),
            operator,
            "{arm}: mock storage operatorFee"
        );
        assert_eq!(
            h.oracle_raw_u256(
                &raw_oracle_calldata_l1_fee(&wave_c_unsigned_tx()),
                "getL1Fee(bytes)"
            ),
            l1_exact,
            "{arm}: getL1Fee does not return the configured storage value"
        );
        assert_eq!(
            h.oracle_raw_u256(
                &raw_oracle_calldata_l1_fee_upper_bound(WAVE_C_TX_SIZE_CEILING),
                "getL1FeeUpperBound(uint256)"
            ),
            l1_upper,
            "{arm}: getL1FeeUpperBound does not return the configured storage value"
        );
        assert_eq!(
            h.oracle_raw_u256(
                &raw_oracle_calldata_operator_fee(WAVE_C_GAS_CEILING),
                "getOperatorFee(uint256)"
            ),
            operator,
            "{arm}: getOperatorFee does not return the configured storage value"
        );
    }

    /// Deterministic pin (default suite, no node needed) for the Wave C
    /// constants: the predeploy address string, the `setFees` selector and
    /// its full word layout, and the three OP-Stack selectors this module
    /// hard-codes for its independent cross-checks.
    ///
    /// All expected values are verbatim Foundry output:
    ///
    /// ```text
    /// $ ~/.foundry/bin/cast sig "setFees(uint256,uint256,uint256)"
    /// 0xcec10c11
    /// $ ~/.foundry/bin/cast calldata "setFees(uint256,uint256,uint256)" 2000000000000 3000000000000 1000000000
    /// 0xcec10c11000000000000000000000000000000000000000000000000000001d1a94a2000000000000000000000000000000000000000000000000000000002ba7def3000000000000000000000000000000000000000000000000000000000003b9aca00
    /// $ ~/.foundry/bin/cast sig "getL1Fee(bytes)"
    /// 0x49948e0e
    /// $ ~/.foundry/bin/cast sig "getL1FeeUpperBound(uint256)"
    /// 0xf1c7a58b
    /// $ ~/.foundry/bin/cast sig "getOperatorFee(uint256)"
    /// 0x275aedd2
    /// $ ~/.foundry/bin/cast sig "l1Fee()"
    /// 0x45ab82bf
    /// $ ~/.foundry/bin/cast sig "l1FeeUpperBound()"
    /// 0x549ce05f
    /// $ ~/.foundry/bin/cast sig "operatorFee()"
    /// 0x89afc0f1
    /// ```
    ///
    /// The three OP-Stack selectors are asserted equal to
    /// [`base_fee::oracle_selector`]'s derivation as well — that is the
    /// point at which "what this module cross-checks with" and "what
    /// production sends" are proven to be the same four bytes, which is
    /// what entitles the raw reads below to be called a cross-check of the
    /// same call rather than of a different one.
    ///
    /// Mutation this detects: transposing two arguments of
    /// [`encode_set_fees`] (e.g. `l1_fee_upper_bound` and `operator_fee`,
    /// both `u128` wei) — the spike arms would then spike a different term
    /// than they claim.
    #[test]
    fn stream_g_anvil_wave_c_oracle_constants_match_foundrys_own_encoding() {
        assert_eq!(
            addr20(GAS_PRICE_ORACLE_ADDRESS_HEX).to_vec(),
            base_fee::GAS_PRICE_ORACLE_ADDRESS.to_vec(),
            "the harness etches somewhere other than the address production reads"
        );
        assert_eq!(
            hex::encode(crate::chain::selector(SIG_SET_FEES)),
            "cec10c11"
        );

        const CAST_SET_FEES: &str = concat!(
            "cec10c11",
            "000000000000000000000000000000000000000000000000000001d1a94a2000",
            "000000000000000000000000000000000000000000000000000002ba7def3000",
            "000000000000000000000000000000000000000000000000000000003b9aca00",
        );
        assert_eq!(
            hex::encode(encode_set_fees(
                WAVE_C_NORMAL_L1_EXACT_WEI,
                WAVE_C_NORMAL_L1_UPPER_WEI,
                WAVE_C_NORMAL_OPERATOR_WEI
            )),
            CAST_SET_FEES
        );

        // The hard-coded selectors in this module's raw cross-check calldata
        // are the same four bytes production derives.
        assert_eq!(
            raw_oracle_calldata_l1_fee(&[])[..4],
            base_fee::oracle_selector(base_fee::SIG_GET_L1_FEE)
        );
        assert_eq!(
            raw_oracle_calldata_l1_fee_upper_bound(0)[..4],
            base_fee::oracle_selector(base_fee::SIG_GET_L1_FEE_UPPER_BOUND)
        );
        assert_eq!(
            raw_oracle_calldata_operator_fee(0)[..4],
            base_fee::oracle_selector(base_fee::SIG_GET_OPERATOR_FEE)
        );
        // ...and the three storage getters are NOT any of them, so the
        // "second source" really is a different entry point.
        for getter in [
            raw_oracle_calldata_storage_l1_fee(),
            raw_oracle_calldata_storage_l1_fee_upper_bound(),
            raw_oracle_calldata_storage_operator_fee(),
        ] {
            assert_eq!(getter.len(), 4);
            assert!(!raw_oracle_calldata_l1_fee(&[]).starts_with(&getter));
            assert!(!raw_oracle_calldata_l1_fee_upper_bound(0).starts_with(&getter));
            assert!(!raw_oracle_calldata_operator_fee(0).starts_with(&getter));
        }

        // The arithmetic the spike arms rely on, pinned so a later edit to
        // the constants cannot quietly make an arm non-discriminating.
        assert_eq!(wave_c_normal_l2_wei(), 500_000_000_000_000);
        assert_eq!(wave_c_spiked_l2_wei(), 2_500_000_000_000_000_000);
        assert!(
            wave_c_normal_l2_wei() + WAVE_C_NORMAL_L1_UPPER_WEI + WAVE_C_NORMAL_OPERATOR_WEI
                <= WAVE_C_EXPOSURE_CEILING_WEI,
            "the honest arm must fit under the ceiling, or the positive arm is impossible"
        );
        for spiked in [
            wave_c_spiked_l2_wei(),
            WAVE_C_SPIKED_L1_EXACT_WEI,
            WAVE_C_SPIKED_L1_UPPER_WEI,
            WAVE_C_SPIKED_OPERATOR_WEI,
        ] {
            assert!(
                spiked > WAVE_C_EXPOSURE_CEILING_WEI,
                "each spiked term must exceed the ceiling ON ITS OWN, so the arm that spikes it \
                 cannot be passing because of some other term"
            );
        }
    }

    /// **Hazard 1, arm 0 — the reads really target the predeploy, and a
    /// missing oracle fails closed rather than reading as "no fee".**
    ///
    /// Anvil has no OP-Stack predeploys, so `0x42…0F` has no code until the
    /// harness etches one. An `eth_call` to a codeless account returns `0x`,
    /// and the whole hazard would be live if that decoded as `0` — the
    /// reserve would then omit the L1-DA and operator terms entirely and the
    /// gate would happily authorize. This asserts it does not: the read
    /// errors, `quote_exposure`/`submit_exposure` surface it as
    /// [`BaseFeeError::Chain`] (code `INTERNAL`), and no reserve is
    /// produced.
    ///
    /// Paired positive arm in the same test: after etching, the identical
    /// calls succeed and return the exact decomposition. Without it,
    /// "everything is rejected" would satisfy the negative half.
    ///
    /// It also asserts the etched runtime's dispatcher contains all three
    /// OP-Stack selectors Rust sends — the drift that the pre-T6a
    /// `getL1FeeUpperBound(bytes)` mock had, and which would otherwise
    /// surface only as a revert with a confusing message.
    ///
    /// Mutation this detects: `decode_gas_oracle_u256`'s
    /// `if data.len() < 32 { return Err(...) }` → returning `Ok(0)` for a
    /// short return. The pre-etch arms then succeed and their
    /// `expect_err` panics.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn stream_g_anvil_gas_oracle_reads_fail_closed_until_the_predeploy_is_etched() {
        let h = AnvilHarness::start();
        let chain = h.rpc_chain(31337);
        let tx = wave_c_unsigned_tx();

        // --- NEGATIVE ARM: nothing at the predeploy address. --------------
        let block = h.latest_block_number();
        assert!(
            h.code_at(GAS_PRICE_ORACLE_ADDRESS_HEX, block).is_empty(),
            "precondition: a vanilla Anvil must have no OP-Stack predeploy at {GAS_PRICE_ORACLE_ADDRESS_HEX}"
        );

        let quote_err = base_fee::quote_exposure(
            &chain,
            GasUnits::new(WAVE_C_GAS_CEILING),
            MaxFeePerGas::new(WAVE_C_NORMAL_MAX_FEE_PER_GAS),
            TxSizeBytes::new(WAVE_C_TX_SIZE_CEILING),
            WeiCeiling::new(WAVE_C_EXPOSURE_CEILING_WEI),
        )
        .expect_err("a missing GasPriceOracle must fail closed, never read as a zero fee");
        assert!(
            matches!(quote_err, BaseFeeError::Chain(_)),
            "expected a chain error, got {quote_err:?}"
        );
        assert_eq!(quote_err.code(), "INTERNAL");
        assert!(
            quote_err
                .to_string()
                .contains("getL1FeeUpperBound() return too short: 0 bytes"),
            "unexpected missing-oracle error: {quote_err}"
        );

        let submit_err = base_fee::submit_exposure(
            &chain,
            GasUnits::new(WAVE_C_GAS_CEILING),
            MaxFeePerGas::new(WAVE_C_NORMAL_MAX_FEE_PER_GAS),
            &tx,
            WeiCeiling::new(WAVE_C_EXPOSURE_CEILING_WEI),
        )
        .expect_err("a missing GasPriceOracle must fail closed at submit time too");
        assert!(
            submit_err
                .to_string()
                .contains("getL1Fee() return too short: 0 bytes"),
            "unexpected missing-oracle error: {submit_err}"
        );
        println!("pre-etch: quote -> {quote_err}; submit -> {submit_err}");

        // --- POSITIVE ARM: etch the mock, and the same calls succeed. -----
        let runtime = h.etch_gas_price_oracle();
        for (name, selector) in [
            ("getL1Fee(bytes)", [0x49u8, 0x94, 0x8e, 0x0e]),
            ("getL1FeeUpperBound(uint256)", [0xf1, 0xc7, 0xa5, 0x8b]),
            ("getOperatorFee(uint256)", [0x27, 0x5a, 0xed, 0xd2]),
        ] {
            assert!(
                runtime.windows(4).any(|w| w == selector),
                "the etched MockGasPriceOracle runtime contains no dispatcher entry for {name} \
                 (0x{}) — the mock's ABI has drifted from base_fee's encoders again",
                hex::encode(selector)
            );
        }
        h.set_oracle_fees(
            WAVE_C_NORMAL_L1_EXACT_WEI,
            WAVE_C_NORMAL_L1_UPPER_WEI,
            WAVE_C_NORMAL_OPERATOR_WEI,
        );
        assert_oracle_state_independently(
            &h,
            WAVE_C_NORMAL_L1_EXACT_WEI,
            WAVE_C_NORMAL_L1_UPPER_WEI,
            WAVE_C_NORMAL_OPERATOR_WEI,
            "post-etch",
        );

        let quoted = base_fee::quote_exposure(
            &chain,
            GasUnits::new(WAVE_C_GAS_CEILING),
            MaxFeePerGas::new(WAVE_C_NORMAL_MAX_FEE_PER_GAS),
            TxSizeBytes::new(WAVE_C_TX_SIZE_CEILING),
            WeiCeiling::new(WAVE_C_EXPOSURE_CEILING_WEI),
        )
        .expect("with the predeploy present the honest quote MUST succeed");
        assert_eq!(quoted.exposure().l2_wei, wave_c_normal_l2_wei());
        assert_eq!(
            quoted.exposure().l1_exact_wei,
            0,
            "quote time has no serialized tx, so getL1Fee must not have been called"
        );
        assert_eq!(quoted.exposure().l1_upper_wei, WAVE_C_NORMAL_L1_UPPER_WEI);
        assert_eq!(quoted.exposure().operator_wei, WAVE_C_NORMAL_OPERATOR_WEI);
        assert_eq!(
            quoted.reserve_wei(),
            wave_c_normal_l2_wei() + WAVE_C_NORMAL_L1_UPPER_WEI + WAVE_C_NORMAL_OPERATOR_WEI
        );

        let submitted = base_fee::submit_exposure(
            &chain,
            GasUnits::new(WAVE_C_GAS_CEILING),
            MaxFeePerGas::new(WAVE_C_NORMAL_MAX_FEE_PER_GAS),
            &tx,
            WeiCeiling::new(WAVE_C_EXPOSURE_CEILING_WEI),
        )
        .expect("with the predeploy present the honest submit MUST succeed");
        assert_eq!(
            submitted.exposure().l1_exact_wei,
            WAVE_C_NORMAL_L1_EXACT_WEI
        );
        assert_eq!(
            submitted.exposure().l1_upper_wei,
            WAVE_C_NORMAL_L1_UPPER_WEI
        );
        assert_eq!(
            submitted.exposure().operator_wei,
            WAVE_C_NORMAL_OPERATOR_WEI
        );
        assert_eq!(
            submitted.reserve_wei(),
            wave_c_normal_l2_wei() + WAVE_C_NORMAL_L1_UPPER_WEI + WAVE_C_NORMAL_OPERATOR_WEI,
            "the honest submit reserve must take max(exact, upper) = upper"
        );
        println!(
            "post-etch: quote reserve = {}, submit reserve = {}",
            quoted.reserve_wei(),
            submitted.reserve_wei()
        );
    }

    /// **Hazard 1, obligation 1 — quote generation rejects when ANY ONE of
    /// the three exposure terms spikes, proven one term at a time against a
    /// live oracle.**
    ///
    /// Structure (see the Wave C block comment above for why):
    ///
    /// | arm | what moves | everything else |
    /// |-----|------------|-----------------|
    /// | 0 | nothing | honest — quote SUCCEEDS |
    /// | 1 | `maxFeePerGas` (L2 execution) | oracle untouched |
    /// | 2 | `getL1FeeUpperBound` (L1 DA) | request untouched |
    /// | 3 | `getOperatorFee` | request untouched |
    ///
    /// Between every spiked arm the state is restored and arm 0 re-run, so a
    /// rejection can never be inherited. Each rejection asserts the exact
    /// reserve, which is what makes it term-specific rather than merely
    /// "something was over the ceiling".
    ///
    /// Mutations this detects, each run one at a time against a live node
    /// and reverted before the next:
    ///
    /// 1. `quote_exposure`'s `l1_upper_wei: chain.gas_oracle_l1_fee_upper_bound(..)?`
    ///    → `l1_upper_wei: 0` (dropping the L1-DA term): arm 2's
    ///    `expect_err` panics — the 9-ETH spike is ignored.
    /// 2. `quote_exposure`'s `operator_wei: chain.gas_oracle_operator_fee(..)?`
    ///    → `operator_wei: 0` (dropping the operator term): arm 3's
    ///    `expect_err` panics.
    /// 3. `enforce_exposure_gate`'s `if reserve > ceiling_wei` → clamping
    ///    instead of rejecting: all three spiked arms' `expect_err` panic.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn stream_g_anvil_quote_exposure_rejects_each_fee_term_spiked_independently() {
        let h = AnvilHarness::start();
        let chain = oracle_at_normal_fees(&h);

        // A quote at the honest fees, re-runnable between arms. Returns the
        // gate's verdict so each arm can assert on it.
        let quote_at = |max_fee_per_gas: u128| {
            base_fee::quote_exposure(
                &chain,
                GasUnits::new(WAVE_C_GAS_CEILING),
                MaxFeePerGas::new(max_fee_per_gas),
                TxSizeBytes::new(WAVE_C_TX_SIZE_CEILING),
                WeiCeiling::new(WAVE_C_EXPOSURE_CEILING_WEI),
            )
        };
        let honest_reserve =
            wave_c_normal_l2_wei() + WAVE_C_NORMAL_L1_UPPER_WEI + WAVE_C_NORMAL_OPERATOR_WEI;

        // --- ARM 0 (the honest negative arm the brief requires) ----------
        // Without this, a gate that rejected EVERYTHING would pass arms 1-3.
        assert_oracle_state_independently(
            &h,
            WAVE_C_NORMAL_L1_EXACT_WEI,
            WAVE_C_NORMAL_L1_UPPER_WEI,
            WAVE_C_NORMAL_OPERATOR_WEI,
            "arm 0",
        );
        let ok = quote_at(WAVE_C_NORMAL_MAX_FEE_PER_GAS)
            .expect("arm 0: at normal fees the quote MUST succeed");
        assert_eq!(ok.reserve_wei(), honest_reserve);
        println!("arm 0 (normal fees): quote OK, reserve = {honest_reserve}");

        // --- ARM 1: L2 execution alone. The oracle is NOT touched. -------
        let err = quote_at(WAVE_C_SPIKED_MAX_FEE_PER_GAS)
            .expect_err("arm 1: an L2 execution spike must be rejected");
        assert_rejected_with_reserve(
            err,
            wave_c_spiked_l2_wei() + WAVE_C_NORMAL_L1_UPPER_WEI + WAVE_C_NORMAL_OPERATOR_WEI,
            "arm 1 (L2 execution)",
        );
        // The oracle really was untouched — so arm 1 rejected on the L2 term
        // alone and not because some earlier arm left the node dirty.
        assert_oracle_state_independently(
            &h,
            WAVE_C_NORMAL_L1_EXACT_WEI,
            WAVE_C_NORMAL_L1_UPPER_WEI,
            WAVE_C_NORMAL_OPERATOR_WEI,
            "arm 1",
        );
        assert_eq!(
            quote_at(WAVE_C_NORMAL_MAX_FEE_PER_GAS)
                .expect("arm 1 restore: the honest quote must succeed again")
                .reserve_wei(),
            honest_reserve
        );
        println!("arm 1 (L2 spike): rejected, then honest quote succeeds again");

        // --- ARM 2: L1 DA alone (`getL1FeeUpperBound`). ------------------
        h.set_oracle_fees(
            WAVE_C_NORMAL_L1_EXACT_WEI,
            WAVE_C_SPIKED_L1_UPPER_WEI,
            WAVE_C_NORMAL_OPERATOR_WEI,
        );
        assert_oracle_state_independently(
            &h,
            WAVE_C_NORMAL_L1_EXACT_WEI,
            WAVE_C_SPIKED_L1_UPPER_WEI,
            WAVE_C_NORMAL_OPERATOR_WEI,
            "arm 2",
        );
        let err = quote_at(WAVE_C_NORMAL_MAX_FEE_PER_GAS)
            .expect_err("arm 2: an L1-DA spike must be rejected");
        assert_rejected_with_reserve(
            err,
            wave_c_normal_l2_wei() + WAVE_C_SPIKED_L1_UPPER_WEI + WAVE_C_NORMAL_OPERATOR_WEI,
            "arm 2 (L1 data availability)",
        );
        h.set_oracle_fees(
            WAVE_C_NORMAL_L1_EXACT_WEI,
            WAVE_C_NORMAL_L1_UPPER_WEI,
            WAVE_C_NORMAL_OPERATOR_WEI,
        );
        assert_eq!(
            quote_at(WAVE_C_NORMAL_MAX_FEE_PER_GAS)
                .expect("arm 2 restore: the honest quote must succeed again")
                .reserve_wei(),
            honest_reserve
        );
        println!("arm 2 (L1-DA spike): rejected, then honest quote succeeds again");

        // --- ARM 3: operator fee alone (`getOperatorFee`). ---------------
        h.set_oracle_fees(
            WAVE_C_NORMAL_L1_EXACT_WEI,
            WAVE_C_NORMAL_L1_UPPER_WEI,
            WAVE_C_SPIKED_OPERATOR_WEI,
        );
        assert_oracle_state_independently(
            &h,
            WAVE_C_NORMAL_L1_EXACT_WEI,
            WAVE_C_NORMAL_L1_UPPER_WEI,
            WAVE_C_SPIKED_OPERATOR_WEI,
            "arm 3",
        );
        let err = quote_at(WAVE_C_NORMAL_MAX_FEE_PER_GAS)
            .expect_err("arm 3: an operator-fee spike must be rejected");
        assert_rejected_with_reserve(
            err,
            wave_c_normal_l2_wei() + WAVE_C_NORMAL_L1_UPPER_WEI + WAVE_C_SPIKED_OPERATOR_WEI,
            "arm 3 (operator fee)",
        );
        h.set_oracle_fees(
            WAVE_C_NORMAL_L1_EXACT_WEI,
            WAVE_C_NORMAL_L1_UPPER_WEI,
            WAVE_C_NORMAL_OPERATOR_WEI,
        );
        assert_eq!(
            quote_at(WAVE_C_NORMAL_MAX_FEE_PER_GAS)
                .expect("arm 3 restore: the honest quote must succeed again")
                .reserve_wei(),
            honest_reserve
        );
        println!("arm 3 (operator spike): rejected, then honest quote succeeds again");
    }

    /// **Hazard 1, obligation 2 — the submit-time entry point rejects on the
    /// same spikes, and on the exact-`getL1Fee` term the quote path cannot
    /// see.**
    ///
    /// `submit_exposure` obtains FOUR values, not three: it also calls the
    /// exact `getL1Fee(bytes)` on the real serialized transaction, and
    /// `reserve_wei` takes `max(exact, upper)`. So this test spikes four
    /// terms independently, with `SPIKED_L1_EXACT` (7 ETH) and
    /// `SPIKED_L1_UPPER` (9 ETH) deliberately different — the asserted
    /// reserve therefore identifies WHICH oracle call fed the `max()`, which
    /// a same-valued spike could not.
    ///
    /// **Scope honesty (do not overread this test).** 🔴 Wave C W4 changed the
    /// first half of what stood here: `base_fee::submit_exposure_for_chain`
    /// now HAS a production call site
    /// (`broadcaster::sign_persist_and_broadcast`, reached from the mounted
    /// `POST /v1/stream-g/submit`), so the route IS exposure-gated — that is
    /// pinned by
    /// `submit::tests::the_submit_route_context_carries_the_configured_exposure_ceiling`
    /// and `submit::tests::exposure_gate_refuses_between_signing_and_reservation`,
    /// not by this test. What this test proves, and all it proves, is that the
    /// submit-time entry point's gate is real and term-specific **against a
    /// live oracle**; the two tests just named run against `MockChain`.
    ///
    /// Mutations this detects, each run one at a time and reverted:
    ///
    /// 1. `submit_exposure`'s `l1_exact_wei: chain.gas_oracle_l1_fee(..)?`
    ///    → `l1_exact_wei: 0`: arm 2's `expect_err` panics.
    /// 2. `NativeExposure::reserve_wei`'s
    ///    `self.l1_exact_wei.max(self.l1_upper_wei)` → `.min(..)`: arm 0's
    ///    honest reserve assertion fails (it would take the 2e12 exact fee
    ///    instead of the 3e12 bound), and arms 2 and 3 stop rejecting.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn stream_g_anvil_submit_exposure_rejects_each_fee_term_spiked_independently() {
        let h = AnvilHarness::start();
        let chain = oracle_at_normal_fees(&h);
        let tx = wave_c_unsigned_tx();

        let submit_at = |max_fee_per_gas: u128| {
            base_fee::submit_exposure(
                &chain,
                GasUnits::new(WAVE_C_GAS_CEILING),
                MaxFeePerGas::new(max_fee_per_gas),
                &tx,
                WeiCeiling::new(WAVE_C_EXPOSURE_CEILING_WEI),
            )
        };
        let honest_reserve =
            wave_c_normal_l2_wei() + WAVE_C_NORMAL_L1_UPPER_WEI + WAVE_C_NORMAL_OPERATOR_WEI;
        let restore = || {
            h.set_oracle_fees(
                WAVE_C_NORMAL_L1_EXACT_WEI,
                WAVE_C_NORMAL_L1_UPPER_WEI,
                WAVE_C_NORMAL_OPERATOR_WEI,
            )
        };

        // --- ARM 0: honest fees SUCCEED. --------------------------------
        let ok = submit_at(WAVE_C_NORMAL_MAX_FEE_PER_GAS)
            .expect("arm 0: at normal fees the submit check MUST succeed");
        assert_eq!(ok.exposure().l1_exact_wei, WAVE_C_NORMAL_L1_EXACT_WEI);
        assert_eq!(ok.exposure().l1_upper_wei, WAVE_C_NORMAL_L1_UPPER_WEI);
        assert_eq!(
            ok.reserve_wei(),
            honest_reserve,
            "the honest reserve must take max(exact, upper) = upper"
        );
        println!("submit arm 0 (normal fees): OK, reserve = {honest_reserve}");

        // --- ARM 1: L2 execution alone. ---------------------------------
        let err =
            submit_at(WAVE_C_SPIKED_MAX_FEE_PER_GAS).expect_err("submit arm 1: L2 spike rejected");
        assert_rejected_with_reserve(
            err,
            wave_c_spiked_l2_wei() + WAVE_C_NORMAL_L1_UPPER_WEI + WAVE_C_NORMAL_OPERATOR_WEI,
            "submit arm 1 (L2 execution)",
        );
        assert_eq!(
            submit_at(WAVE_C_NORMAL_MAX_FEE_PER_GAS)
                .expect("submit arm 1 restore")
                .reserve_wei(),
            honest_reserve
        );

        // --- ARM 2: exact L1 DA alone (`getL1Fee(bytes)`). ---------------
        h.set_oracle_fees(
            WAVE_C_SPIKED_L1_EXACT_WEI,
            WAVE_C_NORMAL_L1_UPPER_WEI,
            WAVE_C_NORMAL_OPERATOR_WEI,
        );
        assert_oracle_state_independently(
            &h,
            WAVE_C_SPIKED_L1_EXACT_WEI,
            WAVE_C_NORMAL_L1_UPPER_WEI,
            WAVE_C_NORMAL_OPERATOR_WEI,
            "submit arm 2",
        );
        let err = submit_at(WAVE_C_NORMAL_MAX_FEE_PER_GAS)
            .expect_err("submit arm 2: an exact-L1-fee spike must be rejected");
        assert_rejected_with_reserve(
            err,
            wave_c_normal_l2_wei() + WAVE_C_SPIKED_L1_EXACT_WEI + WAVE_C_NORMAL_OPERATOR_WEI,
            "submit arm 2 (exact L1 DA)",
        );
        restore();
        assert_eq!(
            submit_at(WAVE_C_NORMAL_MAX_FEE_PER_GAS)
                .expect("submit arm 2 restore")
                .reserve_wei(),
            honest_reserve
        );

        // --- ARM 3: upper-bound L1 DA alone. ----------------------------
        h.set_oracle_fees(
            WAVE_C_NORMAL_L1_EXACT_WEI,
            WAVE_C_SPIKED_L1_UPPER_WEI,
            WAVE_C_NORMAL_OPERATOR_WEI,
        );
        let err = submit_at(WAVE_C_NORMAL_MAX_FEE_PER_GAS)
            .expect_err("submit arm 3: an upper-bound spike must be rejected");
        assert_rejected_with_reserve(
            err,
            wave_c_normal_l2_wei() + WAVE_C_SPIKED_L1_UPPER_WEI + WAVE_C_NORMAL_OPERATOR_WEI,
            "submit arm 3 (upper-bound L1 DA)",
        );
        restore();
        assert_eq!(
            submit_at(WAVE_C_NORMAL_MAX_FEE_PER_GAS)
                .expect("submit arm 3 restore")
                .reserve_wei(),
            honest_reserve
        );

        // --- ARM 4: operator fee alone. ---------------------------------
        h.set_oracle_fees(
            WAVE_C_NORMAL_L1_EXACT_WEI,
            WAVE_C_NORMAL_L1_UPPER_WEI,
            WAVE_C_SPIKED_OPERATOR_WEI,
        );
        let err = submit_at(WAVE_C_NORMAL_MAX_FEE_PER_GAS)
            .expect_err("submit arm 4: an operator-fee spike must be rejected");
        assert_rejected_with_reserve(
            err,
            wave_c_normal_l2_wei() + WAVE_C_NORMAL_L1_UPPER_WEI + WAVE_C_SPIKED_OPERATOR_WEI,
            "submit arm 4 (operator fee)",
        );
        restore();
        assert_eq!(
            submit_at(WAVE_C_NORMAL_MAX_FEE_PER_GAS)
                .expect("submit arm 4 restore")
                .reserve_wei(),
            honest_reserve
        );
        println!("submit arms 1-4: each spiked term independently rejected, each restored to OK");
    }

    // =====================================================================
    // Wave D — hazard 2 (brief §4): nonce-snapshot invalidation, live.
    //
    // ## What these tests prove, and — stated first, because it is the part
    // ## most easily misread — what they do NOT
    //
    // `GoatRelayGateway.sol:199` labels the snapshot an "Advisory same-state
    // nonce snapshot ... Not an execution authorization", and `_snapshot`'s
    // own comment says it "never consumes nonces/intents". **It reserves
    // nothing on chain.** `submit.rs`'s module doc says the same thing in the
    // same words. Nothing below changes that, and **hazard 2 is not closed by
    // these tests.** Another party can still consume `EnrollmentRegistry
    // .nonces(secondary)` or `WalletSponsorshipRegistry.linkNonces(secondary)`
    // between the attestor's last read and the transaction's inclusion, and no
    // client-side mechanism can prevent it.
    //
    // What is proven is the half that is the attestor's own: when either nonce
    // moves under it between snapshot and submission, the attestor DETECTS the
    // move and FAILS CLOSED — in preflight and again in submit's independent
    // revalidation — and the outbox is left in a state that neither releases a
    // nonce while a transaction could still be live nor wedges the row against
    // later resolution. The external race is *handled*, not prevented.
    //
    // ## Shape shared by the three tests
    //
    // * A real cluster is staged on the harness node through the contracts'
    //   own entry points: `EnrollmentRegistry.setEnrolled`,
    //   `WalletSponsorshipRegistry.setProfileIssuer` and `registerPrimary`.
    //   Nothing is written with `anvil_setStorageAt`; no storage layout is
    //   assumed anywhere in this wave.
    // * The **positive arm runs first and must PASS** a full
    //   `preflight_sponsored_enrollment` against live state. Every rejection
    //   below is paired with it — without it, "rejected" would be
    //   indistinguishable from "this call was never acceptable".
    // * Only ONE nonce is advanced per test, by a real transaction, and the
    //   move is confirmed by a raw `eth_call` that shares no code with
    //   `RpcChain` (`EnrollmentRegistry.nonces` / `linkNonces` directly).
    // * The other nonce is asserted UNCHANGED across the same advance, so a
    //   rejection cannot be attributed to the wrong counter.
    // =====================================================================

    /// Anvil dev key #1. The cluster ROOT — and therefore also the
    /// **controller**, because `registerPrimary` sets
    /// `controllerOf[root] = root` (`WalletSponsorshipRegistry.sol:175`), so
    /// this key signs the `SponsorEnrollment` intent.
    const WAVE_D_ROOT_KEY: &str =
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    /// Anvil dev key #2. The SECONDARY being enrolled and linked; signs the
    /// V1 `Enroll` and the `LinkSecondary`.
    const WAVE_D_SECONDARY_KEY: &str =
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
    /// `DeployStreamG.run()` defaults `policySafe`/`feeSafe`/`quoteSigner` to
    /// `msg.sender`, which the harness sets to dev account #0 — so the same
    /// key is the enrollment registry's `safe`, the sponsorship registry's
    /// `policySafe`, the profile issuer this wave authorizes, and the quote
    /// signer whose signature preflight recovers.
    const WAVE_D_DEPLOYER_KEY: &str = ANVIL_DEPLOYER_KEY;

    const WAVE_D_PROFILE: &str = "wave-d-profile";
    const WAVE_D_CLAIM_OWNER: &str = "wave-d-worker";
    const WAVE_D_DATA_KEY_HEX: &str =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    fn wave_d_data_key() -> SecretHex {
        SecretHex::from_hex(WAVE_D_DATA_KEY_HEX).expect("valid 32-byte test key")
    }

    const WAVE_D_FEE_AMOUNT: u128 = 500_000;
    const WAVE_D_MAX_FEE: u128 = 1_000_000;
    /// Wave 2. The gas parameters [`WaveDBroadcaster`] asserts about its
    /// sentinel bytes — see `outbox::SignedRawTx`'s "asserted, not decoded"
    /// note. Only the native-exposure gate reads them, and on chain 31337
    /// that gate does not run (`base_fee::chain_carries_gas_price_oracle`),
    /// so on this harness they are carried and not consumed. They are
    /// nonzero anyway: a zero here would make the one arm that *could* tell
    /// the difference vacuous if the guard were ever changed.
    const WAVE_D_GAS_LIMIT: u64 = 500_000;
    const WAVE_D_MAX_FEE_PER_GAS: u128 = 1_000_000_000;
    /// Wave 2. Generous on purpose: these live-node tests are about the
    /// nonce/outbox invariants, not about the exposure ceiling, and on
    /// chain 31337 the gate is skipped before this value is ever compared
    /// against anything. `submit.rs`'s unit tests own the ceiling arms.
    const WAVE_D_MAX_NATIVE_EXPOSURE_WEI: u128 = 1_000_000_000_000_000_000;

    fn wave_d_signer(key: &str) -> PrivateKeySigner {
        PrivateKeySigner::from_str(key).expect("wave D key must parse")
    }

    fn wave_d_addr(key: &str) -> [u8; 20] {
        wave_d_signer(key).address().into_array()
    }

    fn wave_d_sign(key: &str, digest: [u8; 32]) -> String {
        let s = wave_d_signer(key)
            .sign_hash_sync(&B256::from(digest))
            .expect("sign");
        format!("0x{}", hex::encode(s.as_bytes()))
    }

    fn hex20(a: [u8; 20]) -> String {
        format!("0x{}", hex::encode(a))
    }

    fn hex32(b: [u8; 32]) -> String {
        format!("0x{}", hex::encode(b))
    }

    fn wave_d_deterministic_id(parts: &[&str]) -> String {
        hex::encode(Sha256::digest(parts.join("|").as_bytes()))
    }

    /// **Multi-thread on purpose.** `RpcChain::block_on` (`rpc_chain.rs:183`)
    /// detects an ambient runtime and uses `tokio::task::block_in_place`,
    /// which *panics* on a current-thread runtime. A live-node submit test
    /// therefore cannot use `new_current_thread`; `block_on` itself does not
    /// require `Send`, so the non-`Send` future is fine here.
    fn wave_d_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
    }

    /// The `RootAuthorization` EIP-712 digest `registerPrimary` recovers
    /// (`WalletSponsorshipRegistry._hashRootAuthorization`, `:363-381`).
    ///
    /// Deliberately re-derived here rather than reusing
    /// `root_authorization.rs`'s copy (which is private): if this is wrong the
    /// staging transaction reverts `BadIssuerSignature` and every test in this
    /// wave fails loudly at setup, so it cannot silently paper over anything.
    /// The typehash STRING is the crate's public constant, so the one thing
    /// that must not drift from Solidity is not duplicated.
    fn wave_d_root_authorization_digest(
        root: [u8; 20],
        enroll_digest: [u8; 32],
        nonce: u64,
        deadline: u64,
        chain_id: u64,
        sponsorship: [u8; 20],
    ) -> [u8; 32] {
        let mut buf = Vec::with_capacity(32 * 7);
        buf.extend_from_slice(&keccak256(ROOT_AUTHORIZATION_TYPEHASH_STR.as_bytes()));
        buf.extend_from_slice(&word_from_address(&root));
        buf.extend_from_slice(&[0u8; 32]); // secondary — standalone registration
        buf.extend_from_slice(&enroll_digest);
        buf.extend_from_slice(&[0u8; 32]); // linkDigest — standalone registration
        buf.extend_from_slice(&word_from_u128(u128::from(nonce)));
        buf.extend_from_slice(&word_from_u128(u128::from(deadline)));
        let struct_hash = keccak256(&buf);
        let domain = eip712_domain_separator(
            WALLET_SPONSORSHIP_DOMAIN_NAME,
            WALLET_SPONSORSHIP_DOMAIN_VERSION,
            chain_id,
            sponsorship,
        );
        eip712_digest(&domain, &struct_hash)
    }

    /// A `DeploymentManifest` whose every address is one Foundry actually
    /// deployed onto this node.
    fn wave_d_manifest(h: &AnvilHarness) -> DeploymentManifest {
        let d = h.deployment();
        DeploymentManifest {
            schema_version: 1,
            chain_id: 31337,
            phase: "G1".into(),
            enrollment_registry: addr20(&d.enrollment_registry),
            goat_coin: addr20(&d.goat_coin),
            fee_token: addr20(&d.fee_token),
            fee_token_registry: addr20(&d.fee_token_registry),
            wallet_sponsorship_registry: addr20(&d.wallet_sponsorship_registry),
            sponsored_buy_desk: addr20(&d.sponsored_buy_desk),
            goat_relay_gateway: addr20(&d.goat_relay_gateway),
            policy_safe: addr20(&d.policy_safe),
            fee_safe: addr20(&d.fee_safe),
            recovery_safe: addr20(&d.recovery_safe),
            desk_owner: addr20(&d.desk_owner),
            quote_signer: addr20(&d.quote_signer),
            deployment_manifest_hash: bytes32(&d.deployment_manifest_hash),
            fee_schedule_hash: bytes32(&d.fee_schedule_hash),
        }
    }

    /// A cluster staged far enough that a full sponsored enrollment
    /// preflights clean against live state.
    struct StagedCluster {
        manifest: DeploymentManifest,
        root: [u8; 20],
        secondary: [u8; 20],
        fee_token_config_hash: [u8; 32],
        fee_schedule_hash: [u8; 32],
        deployment_manifest_hash: [u8; 32],
    }

    /// Stage it. Every step is a real transaction through a real entry point;
    /// each one's receipt status is asserted by [`AnvilHarness::send_from`].
    ///
    /// `enroll_secondary` is a per-test choice and it matters:
    /// `linkSecondary` requires `_requireV1Eligible(secondary)`, but
    /// `enrollSelfWithSignature` — the only permissionless way to advance
    /// `EnrollmentRegistry.nonces(secondary)` — reverts `AlreadyEnrolled` on
    /// an enrolled wallet. So the link test pre-enrolls and the v1 test does
    /// not.
    fn stage_cluster(h: &AnvilHarness, enroll_secondary: bool) -> StagedCluster {
        let d = h.deployment().clone();
        let manifest = wave_d_manifest(h);
        let root = wave_d_addr(WAVE_D_ROOT_KEY);
        let secondary = wave_d_addr(WAVE_D_SECONDARY_KEY);
        let issuer = wave_d_addr(WAVE_D_DEPLOYER_KEY);
        assert_eq!(
            issuer,
            addr20(ANVIL_DEPLOYER_ADDRESS),
            "precondition: the deployer key must be dev account #0"
        );
        assert_eq!(
            manifest.quote_signer, issuer,
            "precondition: DeployStreamG must have made the deployer the quote signer"
        );

        // The fee token config the hazard-3 gate reads (Wave B's helper).
        let (_chain, _registry, _token, _hash) = configure_honest_fee_token(h);

        // V1 eligibility, from the registry's `safe` (= the deployer).
        h.send_from_deployer(
            &d.enrollment_registry,
            &encode_set_enrolled(root, true, [0u8; 32]),
        );
        if enroll_secondary {
            h.send_from_deployer(
                &d.enrollment_registry,
                &encode_set_enrolled(secondary, true, [0u8; 32]),
            );
        }
        assert_eq!(
            h.call_u128(
                &d.enrollment_registry,
                &encode_enrolled(root),
                "enrolled(root)"
            ),
            1,
            "root must be V1-eligible before registerPrimary"
        );

        // Authorize the deployer as a profile issuer, then register the root.
        h.send_from_deployer(
            &d.wallet_sponsorship_registry,
            &encode_set_profile_issuer(issuer, true),
        );

        let chain_now = h.latest_block_timestamp();
        let auth_deadline = chain_now + 3_600;
        // Any non-zero value: `registerPrimary` only requires
        // `auth.enrollDigest != 0` (`:161`) for a standalone registration.
        let auth_enroll_digest = keccak256(b"wave-d root eligibility attestation");
        let issuer_sig = wave_d_sign(
            WAVE_D_DEPLOYER_KEY,
            wave_d_root_authorization_digest(
                root,
                auth_enroll_digest,
                0,
                auth_deadline,
                31337,
                manifest.wallet_sponsorship_registry,
            ),
        );
        let calldata = cast_calldata(
            SIG_REGISTER_PRIMARY,
            &[
                format!(
                    "({},{},{},{},{},{})",
                    hex20(root),
                    hex20([0u8; 20]),
                    hex32(auth_enroll_digest),
                    hex32([0u8; 32]),
                    0,
                    auth_deadline
                ),
                issuer_sig,
            ],
        );
        h.send_from_deployer(&d.wallet_sponsorship_registry, &calldata);

        // The staging really took: read it back through the contract's own
        // getters, by raw `eth_call`.
        assert_eq!(
            h.call_address(
                &d.wallet_sponsorship_registry,
                &encode_controller_of(root),
                "controllerOf(root)"
            ),
            root,
            "registerPrimary must have set controllerOf[root] = root"
        );
        assert_eq!(
            h.call_address(
                &d.wallet_sponsorship_registry,
                &encode_primary_of(root),
                "primaryOf(root)"
            ),
            root,
            "registerPrimary must have set primaryOf[root] = root"
        );
        assert_eq!(
            h.call_u128(
                &d.wallet_sponsorship_registry,
                &encode_controller_epoch(root),
                "controllerEpoch(root)"
            ),
            0,
            "a freshly registered root starts at controllerEpoch 0 — every call built below \
             carries that value, so a non-zero epoch here would reject on check 10 instead of \
             on the nonce under test"
        );

        let fee_token_config_hash = h.call_bytes32(
            &d.fee_token_registry,
            &encode_get_token_config_hash(manifest.fee_token),
            "getTokenConfigHash(feeToken)",
        );
        let fee_schedule_hash = h.call_bytes32(
            &d.goat_relay_gateway,
            &encode_fee_schedule_hash(),
            "feeScheduleHash()",
        );
        let deployment_manifest_hash = h.call_bytes32(
            &d.fee_token_registry,
            &[0xcc, 0x4d, 0x2a, 0x5e],
            "activeManifestHash()",
        );
        assert_ne!(fee_token_config_hash, [0u8; 32], "config hash must be set");
        assert_ne!(
            fee_schedule_hash, [0u8; 32],
            "fee schedule hash must be set"
        );
        assert_eq!(
            deployment_manifest_hash, manifest.deployment_manifest_hash,
            "live activeManifestHash disagrees with the manifest Foundry wrote"
        );

        StagedCluster {
            manifest,
            root,
            secondary,
            fee_token_config_hash,
            fee_schedule_hash,
            deployment_manifest_hash,
        }
    }

    /// The ten-argument call plus its four signatures, owned.
    struct LiveCall {
        intent: SponsorEnrollment,
        quote: FeeQuote,
        v1: V1Enrollment,
        link: LinkSecondary,
        root_auth: RootAuthorization,
        eip2612: Eip2612Authorization,
        sponsor_sig: String,
        quote_sig: String,
        link_sig: String,
        root_auth_sig: String,
    }

    impl LiveCall {
        fn call(&self) -> SponsoredEnrollmentCall<'_> {
            SponsoredEnrollmentCall {
                intent: &self.intent,
                quote: &self.quote,
                v1_enrollment: &self.v1,
                link: &self.link,
                root_authorization: &self.root_auth,
                fee_authorization_mode: AUTHORIZATION_MODE_EIP2612,
                fee_eip2612_authorization: &self.eip2612,
                sponsor_signature_hex: &self.sponsor_sig,
                quote_signature_hex: &self.quote_sig,
                link_signature_hex: &self.link_sig,
                root_authorization_signature_hex: &self.root_auth_sig,
            }
        }

        /// 🔴 Wave C W3. `submit::submit_sponsored_enrollment` no longer
        /// accepts a quote — it rebuilds one from the sealed `quotes` row —
        /// so the live-node tests hand it these parts and let it do that.
        fn parts(&self) -> submit::SubmitCallParts {
            submit::SubmitCallParts {
                intent: self.intent.clone(),
                v1_enrollment: self.v1.clone(),
                link: self.link,
                root_authorization: self.root_auth,
                fee_authorization_mode: AUTHORIZATION_MODE_EIP2612,
                fee_eip2612_authorization: self.eip2612,
                sponsor_signature_hex: self.sponsor_sig.clone(),
                link_signature_hex: self.link_sig.clone(),
                root_authorization_signature_hex: self.root_auth_sig.clone(),
            }
        }
    }

    /// Build a call that is correct **for the nonces passed in**. Every hash
    /// and every signature is produced the way production would produce it;
    /// the only inputs a test varies are the three nonces, which is what makes
    /// "the nonce moved" the sole difference between the arms.
    #[allow(clippy::too_many_arguments)]
    fn build_live_call(
        c: &StagedCluster,
        chain_now: u64,
        v1_nonce: u64,
        link_nonce: u64,
        action_nonce: u64,
        controller_epoch: u64,
        intent_id: [u8; 32],
    ) -> LiveCall {
        let m = &c.manifest;
        let deadline = chain_now + 3_600;

        let enroll_digest = sig_verify::enroll_digest(
            c.secondary,
            v1_nonce,
            deadline,
            31337,
            m.enrollment_registry,
        );
        let v1 = V1Enrollment {
            wallet: c.secondary,
            nonce: v1_nonce,
            deadline,
            signature_hex: wave_d_sign(WAVE_D_SECONDARY_KEY, enroll_digest),
        };

        let link = LinkSecondary {
            root: c.root,
            secondary: c.secondary,
            nonce: link_nonce,
            deadline,
        };
        let link_digest = link_secondary_digest(&link, 31337, m.wallet_sponsorship_registry);
        let link_sig = wave_d_sign(WAVE_D_SECONDARY_KEY, link_digest);

        let mut intent = SponsorEnrollment {
            intent_id,
            deployment_manifest_hash: c.deployment_manifest_hash,
            fee_token_config_hash: c.fee_token_config_hash,
            root: c.root,
            controller: c.root,
            controller_epoch,
            secondary: c.secondary,
            enroll_digest,
            link_digest,
            root_authorization_digest: [0u8; 32],
            fee_token: m.fee_token,
            fee_authorization_mode: AUTHORIZATION_MODE_EIP2612,
            fee_authorization_digest: keccak256(b"wave-d fee authorization"),
            max_fee: WAVE_D_MAX_FEE,
            fee_quote_hash: [0u8; 32],
            nonce: action_nonce,
            deadline,
        };

        let mut quote = FeeQuote {
            quote_id: keccak256(&[b"wave-d quote".as_slice(), &intent_id].concat()),
            action_type: ActionType::SponsoredEnrollment.digest(),
            action_core_hash: [0u8; 32],
            deployment_manifest_hash: c.deployment_manifest_hash,
            fee_token_config_hash: c.fee_token_config_hash,
            fee_schedule_hash: c.fee_schedule_hash,
            payer: c.root,
            fee_token: m.fee_token,
            fee_amount: WAVE_D_FEE_AMOUNT,
            fee_recipient: m.fee_safe,
            valid_after: chain_now.saturating_sub(300),
            valid_until: chain_now + 3_000,
        };

        let core = SponsorEnrollmentCore {
            intent_id: intent.intent_id,
            deployment_manifest_hash: intent.deployment_manifest_hash,
            fee_token_config_hash: intent.fee_token_config_hash,
            root: intent.root,
            controller: intent.controller,
            controller_epoch: intent.controller_epoch,
            secondary: intent.secondary,
            enroll_digest: intent.enroll_digest,
            link_digest: intent.link_digest,
            root_authorization_digest: intent.root_authorization_digest,
            fee_token: intent.fee_token,
            fee_authorization_mode: intent.fee_authorization_mode,
            max_fee: intent.max_fee,
            nonce: intent.nonce,
            deadline: intent.deadline,
        };
        quote.action_core_hash = sponsor_enrollment_core_hash(&core);
        let quote_digest = fee_quote_digest(&quote, 31337, m.goat_relay_gateway);
        // The quote signer is the manifest's, which is the deployer, which is
        // what `DeployStreamG` also set as the gateway's on-chain quoteSigner.
        let quote_sig = wave_d_sign(WAVE_D_DEPLOYER_KEY, quote_digest);
        intent.fee_quote_hash = quote_digest;

        let sponsor_sig = wave_d_sign(
            WAVE_D_ROOT_KEY,
            preflight::sponsor_enrollment_digest(&intent, 31337, m.goat_relay_gateway),
        );

        LiveCall {
            eip2612: Eip2612Authorization {
                owner: intent.controller,
                spender: m.goat_relay_gateway,
                value: WAVE_D_FEE_AMOUNT,
                deadline,
                v: 27,
                r: [0x61; 32],
                s: [0x62; 32],
            },
            intent,
            quote,
            v1,
            link,
            root_auth: RootAuthorization::default(),
            sponsor_sig,
            quote_sig,
            link_sig,
            root_auth_sig: String::new(),
        }
    }

    /// `read_live_preflight_state` + `preflight_sponsored_enrollment` against
    /// the real node, in one call. The `TrustedChain` is obtained the
    /// production way; nothing here weakens it.
    fn preflight_live(
        chain: &RpcChain,
        c: &StagedCluster,
        lc: &LiveCall,
    ) -> Result<preflight::PreflightReport, PreflightError> {
        let state = preflight::read_live_preflight_state(
            TrustedChain::live(chain),
            &c.manifest,
            c.root,
            c.secondary,
        )?;
        preflight::preflight_sponsored_enrollment(&lc.call(), &state, &c.manifest)
    }

    // --- store side ------------------------------------------------------

    async fn wave_d_open_store() -> (tempfile::TempDir, StreamGStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("stream_g.sqlite");
        let lock = dir.path().join("stream_g.lock");
        let store = StreamGStore::open(&db, &lock).await.expect("open store");
        (dir, store)
    }

    /// The rows `quotes::create_sponsored_enrollment_quote` would have
    /// written, with the same row ids, sealed payload shapes and AAD binding.
    /// A verbatim structural copy of `submit.rs`'s own `seed_quote`, which is
    /// private to that module's test mod.
    async fn wave_d_seed_quote(store: &StreamGStore, lc: &LiveCall, expires_at: i64) {
        let data_key = DataKey::from_hex(WAVE_D_DATA_KEY_HEX).unwrap();
        let quote_row_id = wave_d_deterministic_id(&[
            "stream_g_quote|v1",
            WAVE_D_PROFILE,
            &hex32(lc.intent.intent_id),
        ]);
        let intent_row = submit::intent_row_id(WAVE_D_PROFILE, lc.intent.intent_id);

        let quote_payload = serde_json::json!({
            "profile_id": WAVE_D_PROFILE,
            "quote_id_hex": hex32(lc.quote.quote_id),
            "action_type_hex": hex32(lc.quote.action_type),
            "action_core_hash_hex": hex32(lc.quote.action_core_hash),
            "deployment_manifest_hash_hex": hex32(lc.quote.deployment_manifest_hash),
            "fee_token_config_hash_hex": hex32(lc.quote.fee_token_config_hash),
            "fee_schedule_hash_hex": hex32(lc.quote.fee_schedule_hash),
            "payer_hex": hex20(lc.quote.payer),
            "fee_token_hex": hex20(lc.quote.fee_token),
            "fee_amount": lc.quote.fee_amount.to_string(),
            "fee_recipient_hex": hex20(lc.quote.fee_recipient),
            "valid_after": lc.quote.valid_after,
            "valid_until": lc.quote.valid_until,
            "quote_signature_hex": lc.quote_sig,
            "body_hash": "wave-d",
        });
        let intent_payload = serde_json::json!({
            "intent_id_hex": hex32(lc.intent.intent_id),
            "profile_id": WAVE_D_PROFILE,
            "quote_id_hex": hex32(lc.quote.quote_id),
            "action_core_hash_hex": hex32(lc.quote.action_core_hash),
        });

        let quote_enc = crypto_store::seal(
            &data_key,
            &store.envelope_aad("quotes", &quote_row_id, "quote_enc"),
            &serde_json::to_vec(&quote_payload).unwrap(),
        )
        .unwrap();
        let intent_enc = crypto_store::seal(
            &data_key,
            &store.envelope_aad("intents", &intent_row, "intent_enc"),
            &serde_json::to_vec(&intent_payload).unwrap(),
        )
        .unwrap();

        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT OR IGNORE INTO profiles (id, created_at, status) VALUES (?, ?, ?)",
                    )
                    .bind(WAVE_D_PROFILE)
                    .bind(0i64)
                    .bind("active")
                    .execute(&mut **tx)
                    .await?;
                    sqlx::query(
                        "INSERT INTO quotes (id, profile_id, base_asset, quote_asset, \
                         base_amount, quote_amount, status, quote_enc, created_at, expires_at) \
                         VALUES (?, ?, 'usdt', 'marker', '0', '500000', 'active', ?, 0, ?)",
                    )
                    .bind(&quote_row_id)
                    .bind(WAVE_D_PROFILE)
                    .bind(&quote_enc)
                    .bind(expires_at)
                    .execute(&mut **tx)
                    .await?;
                    sqlx::query(
                        "INSERT INTO intents (id, profile_id, quote_id, intent_type, amount, \
                         status, intent_enc, created_at, expires_at) \
                         VALUES (?, ?, ?, 'sponsored_enrollment', '500000', 'pending', ?, 0, ?)",
                    )
                    .bind(&intent_row)
                    .bind(WAVE_D_PROFILE)
                    .bind(&quote_row_id)
                    .bind(&intent_enc)
                    .bind(expires_at)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("seed wave D quote/intent rows");
    }

    async fn wave_d_text(store: &StreamGStore, sql: &'static str, bind: String) -> Option<String> {
        store
            .read(move |h| {
                Box::pin(async move {
                    let v: Option<String> =
                        h.fetch_scalar(sqlx::query_scalar(sql).bind(bind)).await?;
                    Ok::<Option<String>, StreamGStoreError>(v)
                })
            })
            .await
            .expect("wave D text read")
    }

    async fn wave_d_count(store: &StreamGStore, sql: &'static str, bind: String) -> i64 {
        store
            .read(move |h| {
                Box::pin(async move {
                    let v: i64 = h.fetch_scalar(sqlx::query_scalar(sql).bind(bind)).await?;
                    Ok::<i64, StreamGStoreError>(v)
                })
            })
            .await
            .expect("wave D count read")
    }

    /// The bytes [`WaveDSigner`] "signs". Not a valid RLP transaction, which
    /// is the point: the real node refuses it, so
    /// `eth_sendRawTransaction` fails and the submit lands on the
    /// `SendOutcome::SendFailedStuckRecoverable` →
    /// `BroadcastOutcome::UnresolvedWithKnownHash` path this harness is about,
    /// **without** the harness having to fake a send seam.
    const WAVE_D_RAW_TX: &[u8] = &[0x02, 0xf8, 0x6b, 0xDA, 0x7A, 0x0D];

    fn wave_d_signed() -> SignedRawTx {
        SignedRawTx::new(
            WAVE_D_RAW_TX.to_vec(),
            GasUnits::new(WAVE_D_GAS_LIMIT),
            MaxFeePerGas::new(WAVE_D_MAX_FEE_PER_GAS),
        )
    }

    /// 🔴 Wave C W2. Was `WaveDBroadcaster`, a sign-**and**-send double for
    /// `submit::SponsoredEnrollmentBroadcaster` — a seam that no longer
    /// exists. The send is now the real `RpcChain`'s
    /// `eth_sendRawTransaction` against the live node, so this double only
    /// signs, and "was it sent?" is answered by the node refusing the payload
    /// rather than by a counter here.
    ///
    /// The production signer (`broadcaster::RpcChainEnrollmentSigner`) is not
    /// used here for one reason: it needs `STREAM_G_BROADCASTER_PRIVATE_KEY`
    /// on the `RpcChain` this harness builds, and these tests are about the
    /// *outbox coherence* of a submit whose send fails — not about signature
    /// production, which `broadcaster.rs`'s own tests pin against decoded
    /// transactions.
    struct WaveDSigner {
        signs: StdMutex<usize>,
        last_nonce: StdMutex<Option<u64>>,
    }

    impl WaveDSigner {
        fn new() -> Self {
            Self {
                signs: StdMutex::new(0),
                last_nonce: StdMutex::new(None),
            }
        }
        fn signs(&self) -> usize {
            *self.signs.lock().unwrap()
        }
    }

    impl SponsoredEnrollmentTxSigner for WaveDSigner {
        /// Anvil's account #0 — funded on every `anvil` boot, so
        /// `eth_getTransactionCount` against it answers a real number and the
        /// nonce frontier is read rather than guessed.
        fn broadcaster_address(&self) -> [u8; 20] {
            addr20("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
        }

        fn sign_sponsored_enrollment_tx(
            &self,
            _gateway: [u8; 20],
            broadcaster_nonce: u64,
            _call: &SponsoredEnrollmentCall<'_>,
        ) -> Result<SignedRawTx, String> {
            *self.signs.lock().unwrap() += 1;
            *self.last_nonce.lock().unwrap() = Some(broadcaster_nonce);
            Ok(wave_d_signed())
        }
    }

    /// Deterministic pin (default suite, no node needed) for every Wave D
    /// four-byte value, against Foundry's own output for the **compiled**
    /// contracts.
    ///
    /// This test exists because two of these were wrong on the first attempt:
    /// `registerPrimary` and `linkSecondary` take a `uint48` deadline, and the
    /// `uint256` spellings hash to entirely different selectors
    /// (`0x4eb4821e` / `0x9c2d78a3` instead of `0xc885a707` / `0x2970f8ad`).
    /// A wrong selector does not fail loudly — it falls through to a fallback
    /// — so the staging would have "succeeded" while doing nothing.
    ///
    /// Mutation this detects: changing any selector byte below, or restoring
    /// either `uint48` to `uint256` in [`SIG_REGISTER_PRIMARY`] /
    /// [`SIG_LINK_SECONDARY`].
    #[test]
    fn stream_g_anvil_wave_d_selectors_match_the_compiled_abis() {
        // forge inspect WalletSponsorshipRegistry methodIdentifiers
        assert_eq!(
            hex::encode(crate::chain::selector(SIG_REGISTER_PRIMARY)),
            "c885a707",
            "registerPrimary"
        );
        assert_eq!(
            hex::encode(crate::chain::selector(SIG_LINK_SECONDARY)),
            "2970f8ad",
            "linkSecondary"
        );
        assert_eq!(
            hex::encode(crate::chain::selector("setProfileIssuer(address,bool)")),
            "fbaed208"
        );
        assert_eq!(
            hex::encode(crate::chain::selector("linkNonces(address)")),
            "a777a0e6"
        );
        assert_eq!(
            hex::encode(crate::chain::selector("controllerOf(address)")),
            "d3a2b210"
        );
        assert_eq!(
            hex::encode(crate::chain::selector("controllerEpoch(address)")),
            "ae8b568e"
        );
        assert_eq!(
            hex::encode(crate::chain::selector("primaryOf(address)")),
            "64143788"
        );
        // forge inspect EnrollmentRegistry methodIdentifiers
        assert_eq!(
            hex::encode(crate::chain::selector(SIG_ENROLL_SELF_WITH_SIGNATURE)),
            "9b125680",
            "enrollSelfWithSignature"
        );
        assert_eq!(
            hex::encode(crate::chain::selector("setEnrolled(address,bool,bytes32)")),
            "acb792dd"
        );
        assert_eq!(
            hex::encode(crate::chain::selector("nonces(address)")),
            "7ecebe00"
        );
        assert_eq!(
            hex::encode(crate::chain::selector("enrolled(address)")),
            "10eb0e0e"
        );
        // forge inspect GoatRelayGateway / FeeTokenRegistry methodIdentifiers
        assert_eq!(
            hex::encode(crate::chain::selector("feeScheduleHash()")),
            "74c223b9"
        );
        assert_eq!(
            hex::encode(crate::chain::selector("intentUsed(bytes32)")),
            "a4532c02"
        );
        assert_eq!(
            hex::encode(crate::chain::selector("getTokenConfigHash(address)")),
            "7e221f83"
        );

        // The hand-rolled one-word encoders agree with those selectors and
        // right-align their address argument.
        let a = addr20("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
        assert_eq!(
            hex::encode(encode_link_nonces(a)),
            "a777a0e600000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8"
        );
        assert_eq!(
            hex::encode(encode_enrollment_nonces(a)),
            "7ecebe0000000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8"
        );
        assert_eq!(
            hex::encode(encode_set_profile_issuer(a, true)),
            concat!(
                "fbaed208",
                "00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8",
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
        );
    }

    /// Submits `lc` and returns the error, asserting on the way that the
    /// broadcaster was never asked to sign or send and that the outbox is
    /// completely empty for this intent.
    ///
    /// This is the "outbox is not corrupted" assertion for a drift detected at
    /// **revalidation** time: `submit_sponsored_enrollment` step 3 runs before
    /// step 5 reserves anything (`submit.rs:1556-1613`), so a nonce that moved
    /// before the submit leaves *no* `tx_attempts` row and *no*
    /// `nonce_allocations` row at all — there is nothing to be incoherent, and
    /// nothing was released because nothing was ever claimed. The
    /// after-reservation case, which is the one with rows in it, is
    /// [`stream_g_anvil_nonce_drift_after_reservation_leaves_a_row_the_sweeper_resolves`].
    fn submit_expecting_preflight_rejection(
        chain: &RpcChain,
        c: &StagedCluster,
        lc: &LiveCall,
        arm: &str,
    ) -> SubmitError {
        let rt = wave_d_runtime();
        rt.block_on(async {
            let (_dir, store) = wave_d_open_store().await;
            wave_d_seed_quote(&store, lc, 9_999_999_999).await;
            let leases = SigningLeaseRegistry::new();
            let signer = WaveDSigner::new();
            let ctx = SubmitContext {
                store: &store,
                chain: TrustedChain::live(chain),
                signer: &signer,
                leases: &leases,
                data_key_hex: &wave_d_data_key(),
                manifest: &c.manifest,
                claim_owner: WAVE_D_CLAIM_OWNER,
                // Wave 2. Never compared against anything on this harness:
                // chain 31337 carries no GasPriceOracle predeploy, so
                // `submit_exposure_for_chain` returns
                // `SkippedNoGasPriceOracle` without a chain call. That skip
                // is why these live-node tests still see sign==1/send==1.
                max_native_exposure_wei: WeiCeiling::new(WAVE_D_MAX_NATIVE_EXPOSURE_WEI),
            };
            let profile = AuthenticatedProfileId::for_test(WAVE_D_PROFILE);
            let err = submit::submit_sponsored_enrollment(&ctx, &profile, &lc.parts())
                .await
                .expect_err("{arm}: submit must fail closed on a nonce that moved");

            assert_eq!(
                signer.signs(),
                0,
                "{arm}: submit signed a transaction for a call whose nonce had already moved"
            );
            // Wave C W2: a preflight rejection returns before
            // `sign_persist_and_broadcast` is entered at all, so there is no
            // broadcaster-EOA allocation either — the stronger fact, and the
            // one a `sends()` counter on a double could never have given.
            assert_eq!(
                wave_d_count(
                    &store,
                    "SELECT COUNT(*) FROM nonce_allocations WHERE kind = ?",
                    "broadcaster".to_string(),
                )
                .await,
                0,
                "{arm}: submit allocated a broadcaster EOA nonce for a call it then rejected"
            );
            assert_eq!(
                wave_d_count(
                    &store,
                    "SELECT COUNT(*) FROM tx_attempts WHERE intent_id = ?",
                    submit::intent_row_id(WAVE_D_PROFILE, lc.intent.intent_id),
                )
                .await,
                0,
                "{arm}: a tx_attempts row exists for a submit that never reached the reservation"
            );
            assert_eq!(
                wave_d_count(
                    &store,
                    "SELECT COUNT(*) FROM nonce_allocations WHERE kind = ?",
                    "action".to_string(),
                )
                .await,
                0,
                "{arm}: an action-nonce allocation exists for a submit that never reserved one"
            );
            err
        })
    }

    /// **Hazard 2, nonce 1 of 2 — `NonceSnapshot.v1EnrollNonce`
    /// (`StreamGTypes.sol:354`, populated at `GoatRelayGateway.sol:258` from
    /// `enrollmentRegistry.nonces(v1Subject)`).**
    ///
    /// Three arms, in order, against one live node:
    ///
    /// 1. **Positive.** At the snapshot's own nonce (0) the full preflight
    ///    passes with `Disposition::RelaySponsored`. Without this every
    ///    rejection below would be indistinguishable from "this call was never
    ///    acceptable".
    /// 2. **Tolerated advance.** One real `enrollSelfWithSignature` moves the
    ///    live nonce 0 → 1 and preflight **still passes**. That is not a hole:
    ///    `StreamGEnroll._enrollV1OrAcceptFrontRun` accepts
    ///    `liveNonce == v1.nonce` *or* `v1.nonce + 1`, and preflight's
    ///    `Check::V1EnrollNonceUnusable` `ensure`
    ///    mirrors exactly that disjunction. Reporting "any advance fails
    ///    closed" would be a false claim, so this arm is asserted rather than
    ///    skipped.
    /// 3. **Fail closed.** A second real enrolment (after the safe un-enrols
    ///    the wallet, because `_enroll` reverts `AlreadyEnrolled` otherwise)
    ///    moves it 1 → 2, and preflight *and* submit both reject with
    ///    `Check::V1EnrollNonceUnusable`.
    ///
    /// `linkNonces(secondary)` is asserted **unchanged** across all of it, so
    /// the rejection cannot be attributed to the other counter. Both counters
    /// are read by raw `eth_call` against the contracts' own getters, which
    /// shares no code with `RpcChain`'s snapshot decoder.
    ///
    /// Mutation this detects: `preflight.rs`'s check
    /// `live_v1_nonce == call.v1_enrollment.nonce || live_v1_nonce ==
    /// call.v1_enrollment.nonce.saturating_add(1)` → `true` (arm 3's
    /// `expect_err` panics). Also detected: widening the tolerance to `+2`.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn stream_g_anvil_v1_enroll_nonce_advance_invalidates_the_snapshot_and_fails_closed() {
        let h = AnvilHarness::start();
        let d = h.deployment().clone();
        let c = stage_cluster(&h, false);
        let chain = h.rpc_chain(31337);

        let v1_nonce_of = |what: &str| {
            h.call_u128(
                &d.enrollment_registry,
                &encode_enrollment_nonces(c.secondary),
                what,
            )
        };
        let link_nonce_now = || {
            h.call_u128(
                &d.wallet_sponsorship_registry,
                &encode_link_nonces(c.secondary),
                "linkNonces(secondary)",
            )
        };

        let snapshot_v1 = v1_nonce_of("nonces(secondary) @ snapshot");
        let snapshot_link = link_nonce_now();
        assert_eq!(snapshot_v1, 0, "a fresh secondary starts at enroll nonce 0");
        assert_eq!(snapshot_link, 0, "and at link nonce 0");

        let chain_now = h.latest_block_timestamp();
        let lc = build_live_call(
            &c,
            chain_now,
            snapshot_v1 as u64,
            snapshot_link as u64,
            0,
            0,
            keccak256(b"wave-d v1-enroll-nonce intent"),
        );

        // --- ARM 1: POSITIVE. --------------------------------------------
        let report = preflight_live(&chain, &c, &lc)
            .expect("the honest arm MUST preflight clean — otherwise every rejection is vacuous");
        assert_eq!(report.disposition, Disposition::RelaySponsored);
        println!(
            "arm 1 (v1EnrollNonce = {snapshot_v1}): preflight OK at block {}, chain_now {}",
            report.block, report.chain_now
        );

        // --- ARM 2: advance by ONE — deliberately tolerated. -------------
        //
        // A real relayer-path enrolment of the secondary, signed by the
        // secondary itself. `EnrollmentRegistry.sol:66` does
        // `nonces[wallet]++` and then requires the recovered signer to be the
        // wallet, so this transaction landing at all is *also* a live
        // confirmation that `sig_verify::enroll_digest` reproduces the
        // contract's own `Enroll` digest.
        let enroll_deadline = h.latest_block_timestamp() + 3_600;
        let sig0 = wave_d_sign(
            WAVE_D_SECONDARY_KEY,
            sig_verify::enroll_digest(
                c.secondary,
                0,
                enroll_deadline,
                31337,
                c.manifest.enrollment_registry,
            ),
        );
        h.send_from_deployer(
            &d.enrollment_registry,
            &cast_calldata(
                SIG_ENROLL_SELF_WITH_SIGNATURE,
                &[hex20(c.secondary), enroll_deadline.to_string(), sig0],
            ),
        );
        assert_eq!(
            v1_nonce_of("nonces(secondary) after enrolment 1"),
            1,
            "the first enrolment did not advance EnrollmentRegistry.nonces"
        );
        assert_eq!(
            link_nonce_now(),
            snapshot_link,
            "the LINK nonce moved during a v1 enrolment — this test is no longer isolating one counter"
        );

        let tolerated = preflight_live(&chain, &c, &lc).expect(
            "a single advance is deliberately tolerated by _enrollV1OrAcceptFrontRun; if this \
             now rejects, preflight's Check::V1EnrollNonceUnusable ensure no longer mirrors \
             StreamGEnroll._enrollV1OrAcceptFrontRun's two accepted branches",
        );
        assert_eq!(tolerated.disposition, Disposition::RelaySponsored);
        println!("arm 2 (v1EnrollNonce = 1): still accepted — documented front-run tolerance");

        // --- ARM 3: advance by ONE MORE — must fail closed. --------------
        h.send_from_deployer(
            &d.enrollment_registry,
            &encode_set_enrolled(c.secondary, false, [0u8; 32]),
        );
        let enroll_deadline2 = h.latest_block_timestamp() + 3_600;
        let sig1 = wave_d_sign(
            WAVE_D_SECONDARY_KEY,
            sig_verify::enroll_digest(
                c.secondary,
                1,
                enroll_deadline2,
                31337,
                c.manifest.enrollment_registry,
            ),
        );
        h.send_from_deployer(
            &d.enrollment_registry,
            &cast_calldata(
                SIG_ENROLL_SELF_WITH_SIGNATURE,
                &[hex20(c.secondary), enroll_deadline2.to_string(), sig1],
            ),
        );
        let advanced = v1_nonce_of("nonces(secondary) after enrolment 2");
        assert_eq!(
            advanced, 2,
            "the second enrolment did not advance the nonce"
        );
        assert_eq!(
            link_nonce_now(),
            snapshot_link,
            "the LINK nonce moved — the rejection below could be the wrong counter's"
        );

        let err = preflight_live(&chain, &c, &lc)
            .expect_err("a v1EnrollNonce two ahead of the call MUST fail closed");
        match &err {
            PreflightError::WouldRevert { check, detail } => {
                assert_eq!(
                    *check,
                    Check::V1EnrollNonceUnusable,
                    "rejected, but for the wrong reason: {detail}"
                );
                assert!(
                    detail.contains("= 2"),
                    "the rejection does not name the live nonce it saw: {detail}"
                );
            }
            other => panic!("expected WouldRevert(V1EnrollNonceUnusable), got {other:?}"),
        }
        assert_eq!(
            err.check(),
            Some(Check::V1EnrollNonceUnusable),
            "the on-chain revert this maps to is InvalidV1Enrollment"
        );

        // --- SUBMIT fails closed on the same drift, reserving nothing. ---
        let submit_err =
            submit_expecting_preflight_rejection(&chain, &c, &lc, "v1EnrollNonce drift");
        match submit_err {
            SubmitError::Preflight(PreflightError::WouldRevert { check, .. }) => {
                assert_eq!(check, Check::V1EnrollNonceUnusable);
            }
            other => {
                panic!("expected SubmitError::Preflight(V1EnrollNonceUnusable), got {other:?}")
            }
        }
        println!(
            "arm 3 (v1EnrollNonce = {advanced}): preflight AND submit fail closed with \
             V1EnrollNonceUnusable; linkNonce still {snapshot_link}"
        );
    }

    /// **Hazard 2, nonce 2 of 2 — `NonceSnapshot.linkNonce`
    /// (`StreamGTypes.sol:355`, populated at `GoatRelayGateway.sol:263` from
    /// `sponsorship.linkNonces(secondary)`,
    /// `WalletSponsorshipRegistry.sol:54`).**
    ///
    /// Unlike the V1 nonce there is **no** front-run tolerance here:
    /// preflight's `Check::LinkNonceMismatch` `ensure` requires exact
    /// equality, mirroring `WalletSponsorshipRegistry.sol:192`
    /// (`if (link.nonce != linkNonces[link.secondary]) revert
    /// InvalidRootAuthorization()`). So a single advance must fail closed, and
    /// that is what is asserted.
    ///
    /// The advance is the *real* race, not a simulation of one: the very
    /// `LinkSecondary` struct and secondary signature the attestor is holding
    /// are consumed by somebody else first. `linkSecondary` is `onlyGateway`,
    /// so the gateway is impersonated (`anvil_impersonateAccount`) — but every
    /// one of the function's preconditions, including the secondary's EIP-712
    /// signature, still has to hold, and the counter is advanced by the
    /// contract's own `linkNonces[link.secondary] = link.nonce + 1` at `:247`.
    /// Nothing here writes storage behind the contract's back.
    ///
    /// Two independent confirmations that the rejection is the right one:
    /// raw `linkNonces(secondary)` moved 0 → 1 while
    /// `EnrollmentRegistry.nonces(secondary)` did not move at all, and a raw
    /// `eth_call` replaying the same `linkSecondary` now reverts with
    /// `InvalidRootAuthorization()` = `0xea3b9cd6`
    /// (`cast sig "InvalidRootAuthorization()"`).
    ///
    /// Mutation this detects: `preflight.rs`'s
    /// `call.link.nonce == state.live_nonces.link_nonce()` → `true`.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn stream_g_anvil_link_nonce_advance_invalidates_the_snapshot_and_fails_closed() {
        let h = AnvilHarness::start();
        let d = h.deployment().clone();
        let c = stage_cluster(&h, true);
        let chain = h.rpc_chain(31337);

        let link_nonce_now = || {
            h.call_u128(
                &d.wallet_sponsorship_registry,
                &encode_link_nonces(c.secondary),
                "linkNonces(secondary)",
            )
        };
        let v1_nonce_now = || {
            h.call_u128(
                &d.enrollment_registry,
                &encode_enrollment_nonces(c.secondary),
                "nonces(secondary)",
            )
        };

        let snapshot_link = link_nonce_now();
        let snapshot_v1 = v1_nonce_now();
        assert_eq!(snapshot_link, 0);
        assert_eq!(snapshot_v1, 0);

        let chain_now = h.latest_block_timestamp();
        let lc = build_live_call(
            &c,
            chain_now,
            snapshot_v1 as u64,
            snapshot_link as u64,
            0,
            0,
            keccak256(b"wave-d link-nonce intent"),
        );

        // --- POSITIVE ARM. -----------------------------------------------
        let report = preflight_live(&chain, &c, &lc).expect("the honest arm MUST preflight clean");
        assert_eq!(report.disposition, Disposition::RelaySponsored);
        println!("positive arm (linkNonce = {snapshot_link}): preflight OK");

        // --- THE RACE: somebody else lands this exact link first. --------
        let link_calldata = cast_calldata(
            SIG_LINK_SECONDARY,
            &[
                format!(
                    "({},{},{},{})",
                    hex20(lc.link.root),
                    hex20(lc.link.secondary),
                    lc.link.nonce,
                    lc.link.deadline
                ),
                lc.link_sig.clone(),
                format!(
                    "({},{},{},{},{},{})",
                    hex20([0u8; 20]),
                    hex20([0u8; 20]),
                    hex32([0u8; 32]),
                    hex32([0u8; 32]),
                    0,
                    0
                ),
                "0x".to_string(),
            ],
        );
        h.impersonate(&d.goat_relay_gateway);
        h.send_from(
            &d.goat_relay_gateway,
            &d.wallet_sponsorship_registry,
            &link_calldata,
        );

        let advanced = link_nonce_now();
        assert_eq!(
            advanced, 1,
            "linkSecondary did not advance linkNonces — the race never happened"
        );
        assert_eq!(
            v1_nonce_now(),
            snapshot_v1,
            "the V1 enroll nonce moved during a link — this test is no longer isolating one counter"
        );
        assert_eq!(
            h.call_address(
                &d.wallet_sponsorship_registry,
                &encode_primary_of(c.secondary),
                "primaryOf(secondary)"
            ),
            c.root,
            "the link did not actually take effect"
        );

        // The chain's own verdict on replaying the identical call, from the
        // gateway, now that the nonce has moved.
        let replay = h.raw_rpc(
            "eth_call",
            serde_json::json!([{
                "from": d.goat_relay_gateway,
                "to": d.wallet_sponsorship_registry,
                "input": format!("0x{}", hex::encode(&link_calldata)),
            }]),
        );
        let replay_err = replay.expect_err("a replayed link at a consumed nonce must revert");
        assert!(
            replay_err.contains("0xea3b9cd6"),
            "the replay reverted, but not with InvalidRootAuthorization(): {replay_err}"
        );
        h.stop_impersonating(&d.goat_relay_gateway);

        // --- NEGATIVE ARM. -----------------------------------------------
        let err =
            preflight_live(&chain, &c, &lc).expect_err("a linkNonce that moved MUST fail closed");
        match &err {
            PreflightError::WouldRevert { check, detail } => {
                assert_eq!(
                    *check,
                    Check::LinkNonceMismatch,
                    "rejected, but for the wrong reason: {detail}"
                );
                assert!(
                    detail.contains("link.nonce 0") && detail.contains("linkNonces(secondary) 1"),
                    "the rejection does not name both sides it compared: {detail}"
                );
            }
            other => panic!("expected WouldRevert(LinkNonceMismatch), got {other:?}"),
        }

        let submit_err = submit_expecting_preflight_rejection(&chain, &c, &lc, "linkNonce drift");
        match submit_err {
            SubmitError::Preflight(PreflightError::WouldRevert { check, .. }) => {
                assert_eq!(check, Check::LinkNonceMismatch);
            }
            other => panic!("expected SubmitError::Preflight(LinkNonceMismatch), got {other:?}"),
        }
        println!(
            "negative arm (linkNonce = {advanced}): preflight AND submit fail closed with \
             LinkNonceMismatch; the chain agrees (InvalidRootAuthorization 0xea3b9cd6); \
             v1EnrollNonce still {snapshot_v1}"
        );
    }

    /// **The half of mandate 3 that is easiest to forget: the outbox.**
    ///
    /// The two tests above cover drift detected at *revalidation*, which
    /// reserves nothing. This one covers the case that actually leaves rows
    /// behind — the reservation is taken, the broadcast comes back with a hash
    /// but no verdict, and only *then* does the nonce move under it — and
    /// asserts, in order:
    ///
    /// 1. `tx_attempts` is `reserved` with `raw_tx_hash` + `intent_id_hex` +
    ///    `lease_until` populated, and its `nonce_allocations` row is
    ///    `allocated`, not `released`. **The nonce is not released while a
    ///    transaction could still be live** — that is
    ///    `submit.rs:1637-1682`'s whole reason to exist.
    /// 2. The link nonce then advances on chain (the external race), a second
    ///    submit of the same intent fails closed at revalidation, and the
    ///    outbox is **unchanged**: still exactly one attempt, still `reserved`,
    ///    still `allocated`. A drift must not be able to strand or release a
    ///    live reservation.
    /// 3. `outbox::sweep_stuck_reservations` run against the **live node**
    ///    while the parent intent is still valid on the **chain** clock holds
    ///    the row (`held_intent_still_valid`) and leaves the nonce
    ///    `allocated`.
    /// 4. The chain clock is moved past the intent's expiry with
    ///    `evm_increaseTime`, the sweep is run again, and the row **resolves**:
    ///    attempt `failed`, nonce `released`. That is the "the sweeper can
    ///    subsequently resolve the row" obligation, executed rather than
    ///    asserted about.
    ///
    /// Every chain read the sweeper makes here is real: `transaction_receipt`
    /// for a hash the node has never seen, `intentUsed(intentId)` against the
    /// deployed gateway, and `block_timestamp()`.
    ///
    /// Mutations this detects:
    /// 1. `submit.rs`'s `Err(err) if err.tx_hash.is_some()` guard → `if false`
    ///    (the unresolved branch collapses into `record_failed`, which
    ///    releases the nonce; step 1's `allocated` assertion fails).
    /// 2. `outbox.rs`'s chain-time guard `if chain_now_i64 < expires_at` →
    ///    `if false` (step 3 releases instead of holding).
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn stream_g_anvil_nonce_drift_after_reservation_leaves_a_row_the_sweeper_resolves() {
        let h = AnvilHarness::start();
        let d = h.deployment().clone();
        let c = stage_cluster(&h, true);
        let chain = h.rpc_chain(31337);

        let chain_now = h.latest_block_timestamp();
        let lc = build_live_call(
            &c,
            chain_now,
            0,
            0,
            0,
            0,
            keccak256(b"wave-d outbox-coherence intent"),
        );
        let intent_row = submit::intent_row_id(WAVE_D_PROFILE, lc.intent.intent_id);
        // The intent expires 120 chain-seconds from now: still valid for the
        // first sweep, expired for the second.
        let intent_expires_at = i64::try_from(chain_now + 120).expect("chain clock fits i64");
        // A hash the node has never seen — `transaction_receipt` therefore
        // really answers `Ok(None)`, which is the branch the sweeper's
        // "not mined yet, and that is not permission to release" comment
        // (`outbox.rs:924-925`) is about.
        //
        // 🔴 Wave C W2: this is now derived rather than invented. It is
        // `keccak256(WAVE_D_RAW_TX)` — the hash of the payload
        // [`WaveDSigner`] produces — because `broadcaster.rs` builds every
        // unresolved outcome from `signed.hash()` and never from a
        // node-reported value. The node still refuses the payload (it is not
        // a valid transaction), so the hash is genuinely one the node has
        // never seen, which is the property this test needs.
        let unseen_tx_hash: [u8; 32] = wave_d_signed().hash();

        let rt = wave_d_runtime();
        rt.block_on(async {
            let (_dir, store) = wave_d_open_store().await;
            wave_d_seed_quote(&store, &lc, intent_expires_at).await;
            let leases = SigningLeaseRegistry::new();
            let signer = WaveDSigner::new();
            let profile = AuthenticatedProfileId::for_test(WAVE_D_PROFILE);
            let ctx = SubmitContext {
                store: &store,
                chain: TrustedChain::live(&chain),
                signer: &signer,
                leases: &leases,
                data_key_hex: &wave_d_data_key(),
                manifest: &c.manifest,
                claim_owner: WAVE_D_CLAIM_OWNER,
                // Wave 2. Never compared against anything on this harness:
                // chain 31337 carries no GasPriceOracle predeploy, so
                // `submit_exposure_for_chain` returns
                // `SkippedNoGasPriceOracle` without a chain call. That skip
                // is why these live-node tests still see sign==1/send==1.
                max_native_exposure_wei: WeiCeiling::new(WAVE_D_MAX_NATIVE_EXPOSURE_WEI),
            };

            // --- 1. Reserve, broadcast, come back with a hash and no verdict.
            let err = submit::submit_sponsored_enrollment(&ctx, &profile, &lc.parts())
                .await
                .expect_err("an unresolved broadcast is an error, not a receipt");
            match &err {
                SubmitError::BroadcastUnresolved { tx_hash_hex, .. } => assert_eq!(
                    tx_hash_hex,
                    &format!("0x{}", hex::encode(unseen_tx_hash)),
                    "the row was stamped with the signed payload's own hash"
                ),
                other => panic!("expected BroadcastUnresolved, got {other:?}"),
            }
            assert_eq!(signer.signs(), 1, "the call was never signed");

            let attempt_id = wave_d_text(
                &store,
                "SELECT id FROM tx_attempts WHERE intent_id = ?",
                intent_row.clone(),
            )
            .await
            .expect("the reservation must have written a tx_attempts row");
            let status = wave_d_text(
                &store,
                "SELECT status FROM tx_attempts WHERE id = ?",
                attempt_id.clone(),
            )
            .await;
            assert_eq!(
                status.as_deref(),
                Some("reserved"),
                "an unresolved broadcast must leave the attempt 'reserved'"
            );
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT raw_tx_hash FROM tx_attempts WHERE id = ?",
                    attempt_id.clone(),
                )
                .await
                .as_deref(),
                Some(format!("0x{}", hex::encode(unseen_tx_hash)).as_str()),
                "the sweeper has no hash to look the transaction up by"
            );
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT intent_id_hex FROM tx_attempts WHERE id = ?",
                    attempt_id.clone(),
                )
                .await
                .as_deref(),
                Some(hex32(lc.intent.intent_id).as_str()),
                "the sweeper cannot ask intentUsed(intentId) without this"
            );
            let allocation_id = wave_d_text(
                &store,
                "SELECT nonce_allocation_id FROM tx_attempts WHERE id = ?",
                attempt_id.clone(),
            )
            .await
            .expect("the attempt must name its nonce allocation");
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT status FROM nonce_allocations WHERE id = ?",
                    allocation_id.clone(),
                )
                .await
                .as_deref(),
                Some("allocated"),
                "THE HAZARD: the action nonce was released while a transaction that may still \
                 execute is outstanding"
            );
            println!(
                "step 1: attempt {} reserved, allocation {} allocated",
                &attempt_id[..12],
                &allocation_id[..12]
            );

            // --- 2. NOW the link nonce moves under the live reservation. --
            let link_calldata = cast_calldata(
                SIG_LINK_SECONDARY,
                &[
                    format!(
                        "({},{},{},{})",
                        hex20(lc.link.root),
                        hex20(lc.link.secondary),
                        lc.link.nonce,
                        lc.link.deadline
                    ),
                    lc.link_sig.clone(),
                    format!(
                        "({},{},{},{},{},{})",
                        hex20([0u8; 20]),
                        hex20([0u8; 20]),
                        hex32([0u8; 32]),
                        hex32([0u8; 32]),
                        0,
                        0
                    ),
                    "0x".to_string(),
                ],
            );
            h.impersonate(&d.goat_relay_gateway);
            h.send_from(
                &d.goat_relay_gateway,
                &d.wallet_sponsorship_registry,
                &link_calldata,
            );
            h.stop_impersonating(&d.goat_relay_gateway);
            assert_eq!(
                h.call_u128(
                    &d.wallet_sponsorship_registry,
                    &encode_link_nonces(c.secondary),
                    "linkNonces(secondary)",
                ),
                1,
                "the race never happened"
            );

            let second = submit::submit_sponsored_enrollment(&ctx, &profile, &lc.parts())
                .await
                .expect_err("a resubmit after the drift must fail closed");
            match &second {
                SubmitError::Preflight(PreflightError::WouldRevert { check, .. }) => {
                    assert_eq!(*check, Check::LinkNonceMismatch)
                }
                other => panic!("expected Preflight(LinkNonceMismatch), got {other:?}"),
            }
            assert_eq!(
                wave_d_count(
                    &store,
                    "SELECT COUNT(*) FROM tx_attempts WHERE intent_id = ?",
                    intent_row.clone(),
                )
                .await,
                1,
                "the failed resubmit created a second attempt row"
            );
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT status FROM tx_attempts WHERE id = ?",
                    attempt_id.clone(),
                )
                .await
                .as_deref(),
                Some("reserved"),
                "the failed resubmit moved the live attempt out of 'reserved'"
            );
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT status FROM nonce_allocations WHERE id = ?",
                    allocation_id.clone(),
                )
                .await
                .as_deref(),
                Some("allocated"),
                "the failed resubmit released a nonce whose transaction may still be live"
            );
            println!("step 2: drift detected; outbox unchanged (1 attempt, reserved/allocated)");

            // --- 3. Sweep while the intent is still valid on CHAIN time. --
            let policy = SweepPolicy {
                claim_owner: "wave-d-sweeper",
                lease_ttl_seconds: 60,
                max_rows: 16,
                gateway: c.manifest.goat_relay_gateway,
            };
            // Wall clock deliberately far ahead so the row's lease is stale
            // and the CAS claims it; the release decision below is the CHAIN
            // clock's, which is still inside the intent's validity.
            let wall_1 = intent_expires_at + 1_000_000;
            let chain_before_sweep = h.latest_block_timestamp();
            assert!(
                i64::try_from(chain_before_sweep).unwrap() < intent_expires_at,
                "precondition: the intent must still be chain-time valid for the hold arm"
            );
            // Independent of the sweeper: the gateway really does say this
            // intent never landed, so neither sweep below can be taking the
            // `ExecutedExternally` branch.
            assert_eq!(
                h.call_u128(
                    &d.goat_relay_gateway,
                    &encode_intent_used(lc.intent.intent_id),
                    "intentUsed(intentId)",
                ),
                0,
                "the gateway reports this intent as used — the sweep arms below would be \
                 resolving it for the wrong reason"
            );
            let held = outbox::sweep_stuck_reservations(
                &store,
                TrustedChain::live(&chain),
                &policy,
                wall_1,
            )
            .await
            .expect("sweep 1");
            assert_eq!(held.claimed, 1, "sweep 1 did not claim the row");
            assert_eq!(
                held.held_intent_still_valid, 1,
                "sweep 1 must HOLD: the signed payload can still execute"
            );
            assert_eq!(
                held.released, 0,
                "sweep 1 released a still-live reservation"
            );
            assert_eq!(held.executed, 0);
            assert_eq!(
                held.stuck_recoverable(),
                0,
                "sweep 1 stuck: {:?}",
                held.stuck
            );
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT status FROM nonce_allocations WHERE id = ?",
                    allocation_id.clone(),
                )
                .await
                .as_deref(),
                Some("allocated"),
                "sweep 1 released the nonce"
            );
            println!("step 3: sweep 1 held the row (intent still chain-time valid)");

            // --- 4. Move the CHAIN clock past the expiry and sweep again. -
            h.increase_time(600);
            let chain_after = h.latest_block_timestamp();
            assert!(
                i64::try_from(chain_after).unwrap() >= intent_expires_at,
                "evm_increaseTime did not move the chain past the intent expiry \
                 ({chain_after} < {intent_expires_at})"
            );
            let resolved = outbox::sweep_stuck_reservations(
                &store,
                TrustedChain::live(&chain),
                &policy,
                wall_1 + 1_000_000,
            )
            .await
            .expect("sweep 2");
            assert_eq!(resolved.claimed, 1, "sweep 2 did not claim the row");
            assert_eq!(
                resolved.released, 1,
                "sweep 2 could not resolve the row: {resolved:?}"
            );
            assert_eq!(
                resolved.stuck_recoverable(),
                0,
                "sweep 2 stuck: {:?}",
                resolved.stuck
            );
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT status FROM tx_attempts WHERE id = ?",
                    attempt_id.clone(),
                )
                .await
                .as_deref(),
                Some("failed"),
                "sweep 2 did not move the attempt to a terminal state"
            );
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT status FROM nonce_allocations WHERE id = ?",
                    allocation_id.clone(),
                )
                .await
                .as_deref(),
                Some("released"),
                "sweep 2 did not release the nonce it proved was never consumed"
            );
            println!(
                "step 4: chain clock {chain_after} >= expiry {intent_expires_at}; sweep 2 \
                 resolved the row (attempt failed, nonce released)"
            );
        });
    }

    // =====================================================================
    // Wave D2 — the reconciliation lifecycle, against a live node.
    //
    // Everything above stops at the broadcast. Wave D added
    // `maintenance::run_reconcile`, the first non-test caller of the fold, and
    // nothing had ever shown a stored intent reach `executed` from a real
    // `SponsoredEnrollmentExecuted` log. That is what this section adds, and it
    // needs three things no earlier wave needed:
    //
    //   * the PRODUCTION signer (`RpcChainEnrollmentSigner`), because
    //     `WaveDSigner`'s payload is deliberately invalid and a transaction the
    //     node refuses emits no log at all;
    //   * a fee the gateway can actually collect — a minted balance and a REAL
    //     EIP-2612 permit — because `StreamGEnroll.execute` collects it last and
    //     a revert there means no event;
    //   * a confirmation depth the node has NOT yet reached, so the negative arm
    //     distinguishes a working depth check from no depth check at all.
    // =====================================================================

    /// Anvil dev key #3 — the Stream G **broadcaster** EOA.
    ///
    /// Deliberately not dev account #0: that account is the deployer, the policy
    /// safe and the quote signer, and [`AnvilHarness::send_from_deployer`] moves
    /// its transaction count on every staging call. The broadcaster's nonce
    /// frontier is read from the chain by
    /// `broadcaster::allocate_broadcaster_nonce`, so sharing an account with the
    /// harness's own staging would make that frontier a moving target for
    /// reasons unrelated to anything under test. Not #1/#2 either: those are the
    /// cluster root and secondary.
    const WAVE_D2_BROADCASTER_KEY: &str =
        "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";
    /// Address of [`WAVE_D2_BROADCASTER_KEY`] — asserted, not assumed, in
    /// [`stream_g_anvil_wave_d2_fee_token_calldata_matches_foundrys_own_encoding`].
    const WAVE_D2_BROADCASTER_ADDRESS: &str = "0x90F79bf6EB2c4f870365E785982E1f101E93b906";

    /// Minted to the payer. Comfortably above [`WAVE_D_FEE_AMOUNT`] so that a
    /// balance shortfall can never be the reason an arm fails — the fee transfer
    /// is the LAST effect in `StreamGEnroll.execute`, so an underfunded payer
    /// reverts the whole enrollment after every state transition, which is a
    /// confusing failure to debug and proves nothing.
    const WAVE_D2_FEE_MINT: u128 = 10 * WAVE_D_FEE_AMOUNT;

    /// The confirmation depth the D2 test configures.
    ///
    /// **Three, not the anvil default of one, and that is the whole point of the
    /// negative arm.** At `reconcile::ANVIL_CONFIRMATIONS` (1) the log's own
    /// block is already final, so a test could never distinguish a working depth
    /// check from an absent one: every arm would fold. At 3 the scan frontier is
    /// `head - 2`, so immediately after the broadcast the log's block is
    /// provably outside the window, and it takes two more blocks to come inside.
    const WAVE_D2_CONFIRMATIONS: u64 = 3;

    /// Wall-clock seconds handed to reconciliation. A fixed value, not
    /// `SystemTime::now()`: `now_wall` reaches only `*_at` bookkeeping columns
    /// (`reconcile_executed_log`'s doc), so pinning it keeps the test's own
    /// clock out of every assertion below.
    const WAVE_D2_WALL_NOW: i64 = 1_800_000_000;

    /// The broadcaster's gas policy for the D2 test.
    ///
    /// `BroadcastGasPolicy::starting_values_pending_founder_review()` is NOT
    /// used: its 500,000 gas limit is below what one real
    /// `executeSponsoredEnrollment` costs (enrol + link + permit + transferFrom,
    /// three of them `DELEGATECALL`ed through `StreamGEnroll`), so the
    /// transaction would mine with `status: 0x0`, emit no event, and turn this
    /// proof into a test of out-of-gas handling. The fee fields are generous for
    /// the same "must not be the reason it failed" motive; anvil's genesis base
    /// fee is ~1 gwei.
    fn wave_d2_gas_policy() -> BroadcastGasPolicy {
        BroadcastGasPolicy::new(
            GasUnits::new(3_000_000),
            MaxFeePerGas::new(50_000_000_000),
            PriorityFeePerGas::new(1_000_000_000),
        )
        .expect("the D2 gas policy satisfies BroadcastGasPolicy's invariants")
    }

    /// A permit the payer really signed, under the fee token's **live** EIP-712
    /// domain.
    ///
    /// [`build_live_call`] fills `v`/`r`/`s` with sentinel bytes, which is
    /// correct for every earlier Wave D test: preflight checks only `owner`,
    /// `spender`, `value` and `deadline` (`Check::Eip2612FeeFieldsMismatch` plus
    /// `PreflightError::PermitWouldRevert`), and `Eip2612Authorization`'s own doc
    /// records that the signature is unverifiable here because EIP-2612's nonce
    /// is not in the struct and the token's `DOMAIN_SEPARATOR` is read by
    /// nothing in the crate. A transaction that must actually mine cannot use
    /// sentinels: `StreamGCommon.collectEip2612` calls `permit()` for real.
    ///
    /// So this reads both missing inputs off the chain — the domain separator
    /// and `nonces(owner)` — and signs. `owner`, `spender`, `value` and
    /// `deadline` are passed in and must be the ones the caller already built,
    /// because those four ARE covered by the controller's `SponsorEnrollment`
    /// signature path and by preflight; only the three signature bytes change.
    fn wave_d2_real_permit(
        h: &AnvilHarness,
        token: &str,
        owner_key: &str,
        spender: [u8; 20],
        value: u128,
        deadline: u64,
    ) -> Eip2612Authorization {
        let owner = wave_d_addr(owner_key);
        let domain = h.call_bytes32(token, &encode_domain_separator(), "DOMAIN_SEPARATOR()");
        assert_ne!(
            domain, [0u8; 32],
            "the fee token reported a zero EIP-712 domain separator; a permit signed under it \
             would recover an arbitrary address and revert inside permit() with no clue why"
        );
        let nonce = h.call_u128(token, &encode_permit_nonces(owner), "nonces(owner)");
        let digest = eip712_digest(
            &domain,
            &eip2612_permit_struct_hash(owner, spender, value, nonce, deadline),
        );
        let sig = wave_d_signer(owner_key)
            .sign_hash_sync(&B256::from(digest))
            .expect("sign the EIP-2612 permit");
        let bytes = sig.as_bytes();
        let mut r = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[32..64]);
        let v = bytes[64];
        assert!(
            v == 27 || v == 28,
            "alloy returned recovery id {v}; OpenZeppelin's ECDSA.recover requires 27/28"
        );
        Eip2612Authorization {
            owner,
            spender,
            value,
            deadline,
            v,
            r,
            s,
        }
    }

    /// Deterministic pin (default suite, no node needed) for every Wave D2
    /// four-byte value and for the EIP-2612 typehash, against Foundry's own
    /// output.
    ///
    /// The typehash is the one worth pinning: a permit signed over a wrong
    /// struct hash does not fail loudly — `ECDSA.recover` succeeds and returns
    /// *some* address, so `permit()` reverts `ERC2612InvalidSigner` and the whole
    /// enrollment becomes a mined revert with no indication that the typehash
    /// was the cause.
    ///
    /// Mutation this detects: any byte of [`EIP2612_PERMIT_TYPEHASH_HEX`], or a
    /// reordering of the five words in [`eip2612_permit_struct_hash`].
    #[test]
    fn stream_g_anvil_wave_d2_fee_token_calldata_matches_foundrys_own_encoding() {
        // cast sig "mint(address,uint256)" / "balanceOf(address)" /
        //          "DOMAIN_SEPARATOR()" / "nonces(address)"
        assert_eq!(
            hex::encode(crate::chain::selector("mint(address,uint256)")),
            "40c10f19"
        );
        assert_eq!(
            hex::encode(crate::chain::selector("balanceOf(address)")),
            "70a08231"
        );
        assert_eq!(
            hex::encode(crate::chain::selector("DOMAIN_SEPARATOR()")),
            "3644e515"
        );
        assert_eq!(
            hex::encode(crate::chain::selector("nonces(address)")),
            "7ecebe00"
        );

        // cast keccak "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        assert_eq!(
            format!(
                "0x{}",
                hex::encode(keccak256(
                    b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
                ))
            ),
            EIP2612_PERMIT_TYPEHASH_HEX,
            "the pinned EIP-2612 typehash is not keccak256 of the type string"
        );

        // cast calldata "mint(address,uint256)" 0x7099…79C8 500000
        assert_eq!(
            hex::encode(encode_mint(
                addr20("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
                500_000
            )),
            concat!(
                "40c10f19",
                "00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8",
                "000000000000000000000000000000000000000000000000000000000007a120",
            )
        );
        assert_eq!(
            hex::encode(encode_balance_of(addr20(
                "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
            ))),
            "70a0823100000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8"
        );
        assert_eq!(
            hex::encode(encode_permit_nonces(addr20(
                "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
            ))),
            "7ecebe0000000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8"
        );
        assert_eq!(hex::encode(encode_domain_separator()), "3644e515");

        // cast sig "setPaused(bool)" / "paused()"
        assert_eq!(
            hex::encode(crate::chain::selector("setPaused(bool)")),
            "16c38b3c"
        );
        assert_eq!(hex::encode(crate::chain::selector("paused()")), "5c975abb");
        assert_eq!(
            hex::encode(encode_set_paused(false)),
            concat!(
                "16c38b3c",
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
        );
        assert_eq!(hex::encode(encode_paused()), "5c975abb");

        // cast wallet address --private-key <WAVE_D2_BROADCASTER_KEY>
        assert_eq!(
            wave_d_addr(WAVE_D2_BROADCASTER_KEY),
            addr20(WAVE_D2_BROADCASTER_ADDRESS),
            "the D2 broadcaster constant and its key name different accounts"
        );
        // ...and it is none of the three accounts this wave already uses.
        for (other, what) in [
            (ANVIL_DEPLOYER_KEY, "deployer/#0"),
            (WAVE_D_ROOT_KEY, "root/#1"),
            (WAVE_D_SECONDARY_KEY, "secondary/#2"),
        ] {
            assert_ne!(
                wave_d_addr(WAVE_D2_BROADCASTER_KEY),
                wave_d_addr(other),
                "the broadcaster shares an account with {what}; its on-chain nonce frontier would \
                 then move for reasons unrelated to anything under test"
            );
        }
    }

    /// **The Wave D lifecycle, executed end to end against a live node:
    /// quote → submit → broadcast → RECONCILE TO EXECUTED.**
    ///
    /// Nothing before this had shown the last leg. `run_reconcile` is the first
    /// non-test caller of `submit::reconcile_executed_for_profile_id`, and until
    /// this test the only evidence it worked was unit tests driving a `FakeChain`
    /// with a hand-built `ExecutedLog`. Here every input is the node's:
    /// `GoatRelayGateway` really emits the event, `eth_getLogs` really returns
    /// it, `eth_getTransactionReceipt` really corroborates it, and
    /// `eth_blockNumber` really decides whether it is deep enough.
    ///
    /// # What makes each arm non-vacuous
    ///
    /// * **The broadcast is real.** `RpcChainEnrollmentSigner` — the production
    ///   signer — encodes and signs; `RpcChain::send_raw_transaction` sends. The
    ///   fee is real too: the payer is minted `PermitMockUSDT` and signs a real
    ///   EIP-2612 permit, because `StreamGEnroll.execute` collects the fee LAST,
    ///   so a sentinel permit would mine a revert and emit nothing. The
    ///   transaction's success, the gateway's `intentUsed`, the registry's
    ///   `primaryOf(secondary)` and the fee safe's balance delta are all read
    ///   back by raw `eth_call`/`eth_getTransactionReceipt`, sharing no code with
    ///   `RpcChain`.
    /// * **The negative arm precedes the positive one.** At
    ///   [`WAVE_D2_CONFIRMATIONS`] = 3 the scan frontier is `head - 2`, so
    ///   immediately after the broadcast the log's own block is outside the
    ///   window and the pass folds nothing: the intent is still `submitted`, the
    ///   attempt still `submitted`, the nonce still `allocated`, and
    ///   `reconciliation_events` is still empty. Without this arm a green
    ///   positive arm would be satisfied by an implementation with no depth check
    ///   at all.
    /// * **Only two blocks separate the arms.** The positive arm mines exactly
    ///   `WAVE_D2_CONFIRMATIONS - 1` empty blocks and changes nothing else — same
    ///   node, same store, same policy, same call — so the depth is the only
    ///   variable, and the terminal state is attributable to it.
    ///
    /// # The terminal state asserted
    ///
    /// The real vocabulary, on the literal strings: `tx_attempts.status =
    /// 'confirmed'`, `intents.status = 'executed'`, `nonce_allocations.status =
    /// 'consumed'` — the last being the fold's deliberate exception, since
    /// `_markIntentAndNonce` really did advance the action nonce on chain, so the
    /// reservation must NOT be released.
    ///
    /// Mutations this detects (none of which any unit test against a `FakeChain`
    /// can catch, because the window is computed from a real head):
    /// 1. `maintenance::scan_and_fold`'s `head.checked_sub(confirmations - 1)` →
    ///    `head` (i.e. scanning to the tip) — the negative arm's `to < log_block`
    ///    assertion fails and the intent is `executed` two blocks early.
    /// 2. `submit::reconcile_executed_for_profile_id` binding
    ///    `NONCE_STATUS_RELEASED` instead of `NONCE_STATUS_CONSUMED` — the
    ///    terminal nonce assertion fails.
    /// 3. Dropping the `UPDATE intents SET status = 'executed'` — the terminal
    ///    intent assertion fails, and so does `latest_disposition`'s pairing.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn stream_g_anvil_reconciliation_confirms_a_real_broadcast_once_it_is_deep_enough() {
        let h = AnvilHarness::start();
        let d = h.deployment().clone();
        // `false`: the secondary must NOT be pre-enrolled. `StreamGEnroll`'s
        // `_enrollV1OrAcceptFrontRun` takes the `enrollSelfWithSignature` branch
        // only when the wallet is un-enrolled AND its nonce equals the one signed
        // for; a pre-enrolled wallet at nonce 0 satisfies neither branch and
        // reverts `InvalidV1Enrollment`.
        let c = stage_cluster(&h, false);
        let chain = h.rpc_chain_with_broadcaster(31337, WAVE_D2_BROADCASTER_KEY);

        // --- unpause, because a deployed gateway is NOT live. --------------
        //
        // `DeployStreamG` activates while `paused` stays at its `true` default,
        // so every action reverts `Paused()` until policy unpauses. This is done
        // HERE and not inside `stage_cluster` on purpose: the Wave A-D tests all
        // assert about calls that must be REFUSED, and unpausing under them
        // would change what they are proving.
        assert_eq!(
            h.call_u128(&d.goat_relay_gateway, &encode_paused(), "paused() before"),
            1,
            "precondition: a freshly deployed gateway is paused; if this is already 0 the deploy \
             script changed and the unpause below is dead code"
        );
        h.send_from_deployer(&d.goat_relay_gateway, &encode_set_paused(false));
        assert_eq!(
            h.call_u128(&d.goat_relay_gateway, &encode_paused(), "paused() after"),
            0,
            "setPaused(false) did not take; every arm below would mine a Paused() revert"
        );

        // --- fund the payer, so the fee collection cannot be what fails. ---
        h.send_from_deployer(&d.fee_token, &encode_mint(c.root, WAVE_D2_FEE_MINT));
        assert_eq!(
            h.call_u128(&d.fee_token, &encode_balance_of(c.root), "balanceOf(root)"),
            WAVE_D2_FEE_MINT,
            "the mint did not land; the enrollment would revert on the fee transfer"
        );
        let fee_safe_before = h.call_u128(
            &d.fee_token,
            &encode_balance_of(c.manifest.fee_safe),
            "balanceOf(feeSafe) before",
        );

        let chain_now = h.latest_block_timestamp();
        let intent_id = keccak256(b"wave-d2 reconcile lifecycle intent");
        let mut lc = build_live_call(&c, chain_now, 0, 0, 0, 0, intent_id);
        // Swap the sentinel permit for one the token will accept. The four
        // preflight-checked fields are carried over unchanged, so nothing this
        // wave signs differs from what the earlier waves preflighted.
        lc.eip2612 = wave_d2_real_permit(
            &h,
            &d.fee_token,
            WAVE_D_ROOT_KEY,
            lc.eip2612.spender,
            lc.eip2612.value,
            lc.eip2612.deadline,
        );
        assert_eq!(
            lc.eip2612.owner, c.root,
            "the permit owner must be the payer the quote names"
        );
        assert_eq!(
            lc.eip2612.spender, c.manifest.goat_relay_gateway,
            "collectEip2612 requires spender == address(this)"
        );

        let intent_row = submit::intent_row_id(WAVE_D_PROFILE, intent_id);
        let rt = wave_d_runtime();
        rt.block_on(async {
            let (_dir, store) = wave_d_open_store().await;
            wave_d_seed_quote(&store, &lc, 9_999_999_999).await;
            let leases = SigningLeaseRegistry::new();
            let signer = RpcChainEnrollmentSigner::new(&chain, wave_d2_gas_policy())
                .expect("the harness RpcChain carries STREAM_G_BROADCASTER_PRIVATE_KEY");
            assert_eq!(
                signer.broadcaster_address(),
                addr20(WAVE_D2_BROADCASTER_ADDRESS),
                "the production signer resolved a different account than the key names"
            );
            let profile = AuthenticatedProfileId::for_test(WAVE_D_PROFILE);
            let ctx = SubmitContext {
                store: &store,
                chain: TrustedChain::live(&chain),
                signer: &signer,
                leases: &leases,
                data_key_hex: &wave_d_data_key(),
                manifest: &c.manifest,
                claim_owner: WAVE_D_CLAIM_OWNER,
                max_native_exposure_wei: WeiCeiling::new(WAVE_D_MAX_NATIVE_EXPOSURE_WEI),
            };

            // --- 1. QUOTE -> SUBMIT -> BROADCAST. -------------------------
            let receipt = submit::submit_sponsored_enrollment(&ctx, &profile, &lc.parts())
                .await
                .expect(
                    "the honest arm MUST broadcast; if the submit fails here every reconciliation \
                     assertion below is vacuous",
                );
            println!(
                "step 1: broadcast {} (revalidated at block {})",
                receipt.tx_hash_hex, receipt.revalidated_at_block
            );

            // The CHAIN's own verdict, by raw JSON-RPC.
            //
            // POLLED, not read once. `submit_sponsored_enrollment` returns on
            // ACCEPTANCE (`eth_sendRawTransaction` answered with a hash), which
            // is not the same event as anvil putting the transaction in a
            // block. A single read here was green 8/8 in isolation and red in
            // 2 of 5 full-gate runs under concurrent machine load; see
            // `AnvilHarness::receipt_when_mined`, which owns the bounded
            // deadline the two sibling senders already used.
            let onchain = h.receipt_when_mined(
                &receipt.tx_hash_hex,
                "the sponsored enrollment broadcast by the honest arm",
            );
            if onchain.get("status").and_then(|s| s.as_str()) != Some("0x1") {
                // Replay the identical call through `eth_call` so the panic
                // names the four-byte revert selector instead of leaving a
                // reader to guess which of `StreamGEnroll`'s twenty-odd
                // preconditions failed. The transaction reverted, so no state
                // changed and the replay reproduces it.
                let replay = h.raw_rpc(
                    "eth_call",
                    serde_json::json!([{
                        "from": hex20(signer.broadcaster_address()),
                        "to": d.goat_relay_gateway,
                        "input": format!(
                            "0x{}",
                            hex::encode(
                                crate::stream_g::direct_eth::sponsored_enrollment_calldata(
                                    &lc.call(),
                                )
                                    .expect("the call re-encodes"),
                            )
                        ),
                    }]),
                );
                panic!(
                    "the enrollment mined as a REVERT, so no SponsoredEnrollmentExecuted was \
                     emitted.\nreceipt: {onchain}\nreplay:  {replay:?}"
                );
            }
            let block_hex = onchain
                .get("blockNumber")
                .and_then(|b| b.as_str())
                .expect("a mined receipt has a block number");
            let log_block = u64::from_str_radix(block_hex.strip_prefix("0x").unwrap_or(block_hex), 16)
                .expect("receipt block number is hex");

            // The three on-chain effects, each read by raw `eth_call`.
            assert_eq!(
                h.call_u128(
                    &d.goat_relay_gateway,
                    &encode_intent_used(intent_id),
                    "intentUsed(intentId)",
                ),
                1,
                "the gateway does not report this intent as used — it did not execute"
            );
            assert_eq!(
                h.call_address(
                    &d.wallet_sponsorship_registry,
                    &encode_primary_of(c.secondary),
                    "primaryOf(secondary)",
                ),
                c.root,
                "the secondary was never linked — the enrollment's effects did not run"
            );
            assert_eq!(
                h.call_u128(
                    &d.fee_token,
                    &encode_balance_of(c.manifest.fee_safe),
                    "balanceOf(feeSafe) after",
                ),
                fee_safe_before + WAVE_D_FEE_AMOUNT,
                "the fee safe's balance did not move by the quoted fee — collectEip2612 did not \
                 run, so the permit was not really honoured"
            );

            // The store, after the broadcast and before any reconciliation.
            let attempt_id = wave_d_text(
                &store,
                "SELECT id FROM tx_attempts WHERE intent_id = ?",
                intent_row.clone(),
            )
            .await
            .expect("the reservation must have written a tx_attempts row");
            let allocation_id = wave_d_text(
                &store,
                "SELECT nonce_allocation_id FROM tx_attempts WHERE id = ?",
                attempt_id.clone(),
            )
            .await
            .expect("the attempt must name its action-nonce allocation");
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT status FROM tx_attempts WHERE id = ?",
                    attempt_id.clone(),
                )
                .await
                .as_deref(),
                Some(TX_ATTEMPT_STATUS_SUBMITTED),
                "an accepted broadcast must leave the attempt 'submitted'"
            );
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT status FROM intents WHERE id = ?",
                    intent_row.clone(),
                )
                .await
                .as_deref(),
                Some(INTENT_STATUS_SUBMITTED),
                "the intent is already 'executed' before anything reconciled it"
            );
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT status FROM nonce_allocations WHERE id = ?",
                    allocation_id.clone(),
                )
                .await
                .as_deref(),
                Some(NONCE_STATUS_ALLOCATED),
                "the action nonce is not 'allocated' after a broadcast"
            );
            assert_eq!(
                wave_d_count(
                    &store,
                    "SELECT COUNT(*) FROM reconciliation_events WHERE tx_attempt_id = ?",
                    attempt_id.clone(),
                )
                .await,
                0,
                "a reconciliation event exists before reconciliation ran"
            );

            // --- 2. NEGATIVE ARM: not buried deep enough yet. -------------
            let policy = MaintenancePolicy {
                interval: Duration::from_secs(900),
                lease_ttl_seconds: 60,
                max_rows: 16,
                claim_owner: SWEEPER_CLAIM_OWNER.to_string(),
                gateway: c.manifest.goat_relay_gateway,
                confirmations: WAVE_D2_CONFIRMATIONS,
                // 0 is the shipped default and is accepted on 31337 only; the
                // G-B1 refusal in `RpcChain::sponsored_enrollment_logs` applies
                // to every other chain.
                gateway_deploy_block: 0,
                max_scan_span: DEFAULT_MAX_SCAN_SPAN_BLOCKS,
            };
            let metrics = StreamGMetrics::new();

            let head_before = h.latest_block_number();
            assert_eq!(
                head_before, log_block,
                "precondition: the enrollment must be in the head block, so the log has depth 1 \
                 and {WAVE_D2_CONFIRMATIONS} confirmations are genuinely not yet reached"
            );

            let shallow = run_reconcile(
                &store,
                &wave_d_data_key(),
                TrustedChain::live(&chain),
                &metrics,
                &policy,
                WAVE_D2_WALL_NOW,
            )
            .await;
            match shallow {
                ReconcileStepOutcome::Scanned { from, to, logs, .. } => {
                    assert!(
                        to < log_block,
                        "the scan window reached the log's own block ({from}..={to} covers \
                         {log_block}) — the confirmation depth is not holding it back"
                    );
                    assert_eq!(
                        logs, 0,
                        "a SponsoredEnrollmentExecuted was returned from a window that stops \
                         before the block it was emitted in"
                    );
                }
                ReconcileStepOutcome::NothingToScan { .. } => {}
                other => panic!(
                    "the shallow pass neither scanned nor found an empty window: {other:?}"
                ),
            }
            println!("step 2: shallow pass at head {head_before} -> {shallow:?}");

            // NOTHING moved.
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT status FROM intents WHERE id = ?",
                    intent_row.clone(),
                )
                .await
                .as_deref(),
                Some(INTENT_STATUS_SUBMITTED),
                "THE HAZARD: the intent reached 'executed' before the confirmation depth did"
            );
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT status FROM tx_attempts WHERE id = ?",
                    attempt_id.clone(),
                )
                .await
                .as_deref(),
                Some(TX_ATTEMPT_STATUS_SUBMITTED),
                "the attempt was confirmed below the configured depth"
            );
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT status FROM nonce_allocations WHERE id = ?",
                    allocation_id.clone(),
                )
                .await
                .as_deref(),
                Some(NONCE_STATUS_ALLOCATED),
                "the action nonce was consumed below the configured depth"
            );
            assert_eq!(
                wave_d_count(
                    &store,
                    "SELECT COUNT(*) FROM reconciliation_events WHERE tx_attempt_id = ?",
                    attempt_id.clone(),
                )
                .await,
                0,
                "a durable reconciliation event was written below the configured depth"
            );
            assert_eq!(
                metrics.snapshot().reconcile_confirmed,
                0,
                "the shallow pass counted a confirmation"
            );

            // --- 3. POSITIVE ARM: bury it, change nothing else. -----------
            for _ in 0..(WAVE_D2_CONFIRMATIONS - 1) {
                h.mine();
            }
            let head_after = h.latest_block_number();
            assert_eq!(
                head_after,
                log_block + (WAVE_D2_CONFIRMATIONS - 1),
                "evm_mine did not advance the head by exactly the shortfall"
            );

            let deep = run_reconcile(
                &store,
                &wave_d_data_key(),
                TrustedChain::live(&chain),
                &metrics,
                &policy,
                WAVE_D2_WALL_NOW,
            )
            .await;
            match deep {
                ReconcileStepOutcome::Scanned {
                    from,
                    to,
                    logs,
                    quarantined,
                    stalled,
                    cursor_advanced,
                } => {
                    assert!(
                        from <= log_block && log_block <= to,
                        "the deep window {from}..={to} does not contain the log's block \
                         {log_block}"
                    );
                    assert_eq!(logs, 1, "expected exactly one SponsoredEnrollmentExecuted");
                    assert_eq!(
                        quarantined, 0,
                        "a real anvil log must fold, not land in quarantine"
                    );
                    assert_eq!(
                        stalled, 0,
                        "a real anvil log's receipt is on the node that served the log; a stall \
                         here means the corroboration read is looking at the wrong block"
                    );
                    assert!(
                        cursor_advanced,
                        "the cursor did not advance over a fully folded window"
                    );
                    assert_eq!(
                        reconcile::load_scan_cursor(&store, SCAN_CURSOR_ENROLLMENT_EXECUTED)
                            .await
                            .expect("cursor read"),
                        Some(to),
                        "the durable cursor disagrees with the window that was folded"
                    );
                }
                other => panic!("the deep pass did not scan: {other:?}"),
            }
            println!("step 3: deep pass at head {head_after} -> {deep:?}");

            // --- 4. THE TERMINAL STATE. -----------------------------------
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT status FROM tx_attempts WHERE id = ?",
                    attempt_id.clone(),
                )
                .await
                .as_deref(),
                Some(TX_ATTEMPT_STATUS_CONFIRMED),
                "the attempt did not reach 'confirmed'"
            );
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT tx_hash FROM tx_attempts WHERE id = ?",
                    attempt_id.clone(),
                )
                .await
                .as_deref(),
                Some(receipt.tx_hash_hex.as_str()),
                "the confirmed row names a different transaction than the one that executed"
            );
            assert_eq!(
                wave_d_count(
                    &store,
                    "SELECT COUNT(*) FROM tx_attempts WHERE id = ? AND confirmed_at IS NOT NULL",
                    attempt_id.clone(),
                )
                .await,
                1,
                "a confirmed attempt has no confirmed_at"
            );
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT status FROM intents WHERE id = ?",
                    intent_row.clone(),
                )
                .await
                .as_deref(),
                Some(INTENT_STATUS_EXECUTED),
                "the intent did not reach 'executed' — the lifecycle's last leg did not close"
            );
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT status FROM nonce_allocations WHERE id = ?",
                    allocation_id.clone(),
                )
                .await
                .as_deref(),
                Some(NONCE_STATUS_CONSUMED),
                "THE HAZARD, inverted: _markIntentAndNonce really did advance the action nonce \
                 on chain, so the reservation must be CONSUMED and never released"
            );
            assert_eq!(
                wave_d_count(
                    &store,
                    "SELECT COUNT(*) FROM reconciliation_events WHERE tx_attempt_id = ?",
                    attempt_id.clone(),
                )
                .await,
                1,
                "expected exactly one durable reconciliation event"
            );
            assert_eq!(
                wave_d_text(
                    &store,
                    "SELECT status FROM reconciliation_events WHERE tx_attempt_id = ?",
                    attempt_id.clone(),
                )
                .await
                .as_deref(),
                Some(TX_ATTEMPT_STATUS_CONFIRMED),
                "the reconciliation event does not record a confirmation"
            );

            // What the owner's status route would now report.
            let view = submit::get_enrollment_intent(&store, &profile, intent_id)
                .await
                .expect("status read")
                .expect("the intent must be visible to its owner");
            assert_eq!(view.status, INTENT_STATUS_EXECUTED);
            assert_eq!(
                view.latest_disposition.as_deref(),
                Some(TX_ATTEMPT_STATUS_CONFIRMED),
                "GET /v1/stream-g/status/:intentId would not report the confirmation"
            );

            let snap = metrics.snapshot();
            assert_eq!(snap.reconcile_confirmed, 1, "reconcile_confirmed");
            assert_eq!(snap.reconcile_logs_observed, 1, "reconcile_logs_observed");
            assert_eq!(snap.reconcile_errors, 0, "reconcile_errors");
            assert_eq!(snap.reconcile_passes, 2, "both passes must be counted");
            println!(
                "step 4: attempt {} confirmed, intent executed, nonce {} consumed; metrics {:?}",
                &attempt_id[..12],
                &allocation_id[..12],
                snap
            );
        });
    }
}
