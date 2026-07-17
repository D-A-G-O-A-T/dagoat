//! Live `ChainClient` over alloy HTTP JSON-RPC (anvil / any EVM RPC).

use std::str::FromStr;
use std::sync::Mutex;

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, B256, U256, keccak256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{Filter, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use url::Url;

use crate::chain::{
    BatchView, BoundWorker, ChainClient, ChainError, TxHash, decode_batch_return, encode_batches,
    encode_bind_with_signature, encode_challenge_batch, encode_claim_payout, encode_confirm_epoch,
    encode_enroll_self_with_signature, encode_finalize_batch, encode_has_baseline,
    encode_last_claimed_cumulative, encode_propose_batch, parse_address20, u128_from_word,
};
use crate::config::Config;

/// Role used when selecting which private key signs a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Proposer,
    Watcher,
    Challenger,
    Relayer,
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
    proposer_bond_wei: u128,
    challenger_bond_wei: u128,
    proposer: Option<PrivateKeySigner>,
    watcher: Option<PrivateKeySigner>,
    challenger: Option<PrivateKeySigner>,
    relayer: Option<PrivateKeySigner>,
    /// Serialize sends so nonce fillers do not race across roles on shared accounts.
    send_lock: Mutex<()>,
}

impl RpcChain {
    pub fn from_config(cfg: &Config) -> Result<Self, ChainError> {
        let rpc_url = Url::parse(&cfg.rpc_url)
            .map_err(|e| ChainError::Msg(format!("RPC_URL parse: {e}")))?;
        let epoch_settlement = parse_alloy_address(&cfg.epoch_settlement_address)?;
        let worker_binding = parse_alloy_address(&cfg.worker_binding_address)?;
        let enrollment_registry = parse_alloy_address(&cfg.enrollment_registry_address)?;

        Ok(Self {
            rpc_url,
            epoch_settlement,
            worker_binding,
            enrollment_registry,
            chain_id: cfg.chain_id,
            proposer_bond_wei: cfg.proposer_bond_wei,
            challenger_bond_wei: cfg.challenger_bond_wei,
            proposer: parse_key_opt(cfg.proposer_private_key.as_deref())?,
            watcher: parse_key_opt(cfg.watcher_private_key.as_deref())?,
            challenger: parse_key_opt(cfg.challenger_private_key.as_deref())?,
            relayer: parse_key_opt(cfg.relayer_private_key.as_deref())?,
            send_lock: Mutex::new(()),
        })
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
        };
        slot.as_ref()
            .ok_or_else(|| ChainError::Msg(format!("missing {name} for live RPC")))
    }

    fn send_tx(
        &self,
        role: Role,
        to: Address,
        value: U256,
        calldata: Vec<u8>,
    ) -> Result<TxHash, ChainError> {
        let signer = self.signer(role)?.clone();
        let url = self.rpc_url.clone();
        let chain_id = self.chain_id;
        let _guard = self
            .send_lock
            .lock()
            .map_err(|_| ChainError::Msg("send lock poisoned".into()))?;

        self.block_on(async move {
            let provider = ProviderBuilder::new()
                .wallet(signer)
                .connect_http(url);

            let mut tx = TransactionRequest::default()
                .with_to(to)
                .with_value(value)
                .with_input(Bytes::from(calldata));
            if chain_id != 0 {
                tx = tx.with_chain_id(chain_id);
            }

            let pending = provider
                .send_transaction(tx)
                .await
                .map_err(|e| ChainError::Msg(format!("send_transaction: {e}")))?;
            let receipt = pending
                .get_receipt()
                .await
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

    fn eth_call(&self, to: Address, calldata: Vec<u8>) -> Result<Bytes, ChainError> {
        let url = self.rpc_url.clone();
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            let tx = TransactionRequest::default()
                .with_to(to)
                .with_input(Bytes::from(calldata));
            provider
                .call(tx)
                .await
                .map_err(|e| ChainError::Msg(format!("eth_call: {e}")))
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
        )
    }

    fn confirm_epoch(&self, epoch: u64) -> Result<TxHash, ChainError> {
        let data = encode_confirm_epoch(epoch);
        self.send_tx(
            Role::Watcher,
            self.epoch_settlement,
            U256::ZERO,
            data,
        )
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
        self.send_tx(Role::Relayer, self.worker_binding, U256::ZERO, data)
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
        )
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
        match self.send_tx(Role::Watcher, self.epoch_settlement, U256::ZERO, data.clone()) {
            Ok(h) => Ok(h),
            Err(_) => self.send_tx(Role::Proposer, self.epoch_settlement, U256::ZERO, data),
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
        match self.send_tx(Role::Relayer, self.epoch_settlement, U256::ZERO, data.clone()) {
            Ok(h) => Ok(h),
            Err(_) => self.send_tx(Role::Proposer, self.epoch_settlement, U256::ZERO, data),
        }
    }

    fn increase_time(&self, seconds: u64) -> Result<(), ChainError> {
        if seconds == 0 {
            return Ok(());
        }
        let url = self.rpc_url.clone();
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            // anvil_increaseTime
            let _: serde_json::Value = provider
                .raw_request(
                    "anvil_increaseTime".into(),
                    [serde_json::json!(seconds)],
                )
                .await
                .map_err(|e| ChainError::Msg(format!("anvil_increaseTime: {e}")))?;
            let _: serde_json::Value = provider
                .raw_request("anvil_mine".into(), [serde_json::json!(1)])
                .await
                .map_err(|e| ChainError::Msg(format!("anvil_mine: {e}")))?;
            Ok(())
        })
    }

    fn block_timestamp(&self) -> Result<u64, ChainError> {
        let url = self.rpc_url.clone();
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            let block = provider
                .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
                .await
                .map_err(|e| ChainError::Msg(format!("eth_getBlock: {e}")))?
                .ok_or_else(|| ChainError::Msg("latest block missing".into()))?;
            Ok(block.header.timestamp)
        })
    }

    fn list_bound_workers(&self) -> Result<Vec<BoundWorker>, ChainError> {
        let url = self.rpc_url.clone();
        let binding = self.worker_binding;
        // WorkerBinding.Bound(address indexed wallet, string username)
        let topic0: B256 = keccak256(b"Bound(address,string)");
        self.block_on(async move {
            let provider = ProviderBuilder::new().connect_http(url);
            let filter = Filter::new()
                .address(binding)
                .event_signature(topic0)
                .from_block(0u64);
            let logs = provider
                .get_logs(&filter)
                .await
                .map_err(|e| ChainError::Msg(format!("eth_getLogs Bound: {e}")))?;
            let mut out = Vec::with_capacity(logs.len());
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
                out.push(BoundWorker { wallet, username });
            }
            // Last Bound wins if a wallet re-appeared (should not under set-once).
            out.sort_by(|a, b| a.wallet.cmp(&b.wallet));
            out.dedup_by(|a, b| a.wallet.eq_ignore_ascii_case(&b.wallet));
            Ok(out)
        })
    }
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
        assert!(
            err.to_string().contains("PROPOSER_PRIVATE_KEY"),
            "{err}"
        );
    }

    #[test]
    fn parse_alloy_address_accepts_plain_hex() {
        let a = parse_alloy_address("0x00000000000000000000000000000000000000Ab").unwrap();
        assert!(format!("{a:?}").to_lowercase().contains("ab"));
    }

    /// Optional smoke against local anvil — skipped in default CI.
    #[test]
    #[ignore = "requires local anvil at RPC_URL"]
    fn rpc_chain_anvil_smoke() {
        let rpc = std::env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".into());
        let mut m = HashMap::new();
        m.insert("RPC_URL".into(), rpc);
        m.insert("CHAIN_ID".into(), "31337".into());
        m.insert(
            "EPOCH_SETTLEMENT_ADDRESS".into(),
            std::env::var("EPOCH_SETTLEMENT_ADDRESS")
                .unwrap_or_else(|_| "0x0000000000000000000000000000000000000001".into()),
        );
        m.insert(
            "WORKER_BINDING_ADDRESS".into(),
            std::env::var("WORKER_BINDING_ADDRESS")
                .unwrap_or_else(|_| "0x0000000000000000000000000000000000000002".into()),
        );
        m.insert(
            "ENROLLMENT_REGISTRY_ADDRESS".into(),
            std::env::var("ENROLLMENT_REGISTRY_ADDRESS")
                .unwrap_or_else(|_| "0x0000000000000000000000000000000000000003".into()),
        );
        m.insert("REGISTRY_JSON".into(), "./registry.json".into());
        m.insert(
            "PROPOSER_PRIVATE_KEY".into(),
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        );
        let cfg = crate::config::load_from_map(&m).unwrap();
        let chain = RpcChain::from_config(&cfg).unwrap();
        // eth_call to empty contract address may fail; get_batch should at least attempt RPC.
        let _ = chain.get_batch(0);
    }
}
