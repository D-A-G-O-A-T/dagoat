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
}

/// One on-chain binding from `WorkerBinding.Bound`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundWorker {
    /// 0x-prefixed lowercase address.
    pub wallet: String,
    pub username: String,
}

/// First 4 bytes of keccak256(signature).
pub fn selector(sig: &str) -> [u8; 4] {
    let h = keccak256(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

pub fn encode_propose_batch(
    epoch: u64,
    merkle_root: [u8; 32],
    evidence_ref: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 3);
    out.extend_from_slice(&selector(
        "proposeBatch(uint256,bytes32,bytes32)",
    ));
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
    out.extend_from_slice(&selector(
        "bindWithSignature(address,string,uint256,bytes)",
    ));
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
    out.extend_from_slice(&selector(
        "enrollSelfWithSignature(address,uint256,bytes)",
    ));
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
    out.extend_from_slice(&selector(
        "claimPayout(uint256,address,uint256,bytes32[])",
    ));
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
            return Err(ChainError::Msg(format!("unknown batch status byte {other}")));
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
}

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
}

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
            if !(b.status == BatchStatus::None || b.status == BatchStatus::ChallengerWon) {
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
        g.bounds.insert(key, username.to_string());
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
        g.ops.push(MockOp::Enroll { wallet, deadline });
        Ok(Self::next_tx(&mut g))
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
        let batch = g
            .batches
            .get(&epoch)
            .ok_or(ChainError::NotFound(epoch))?;
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
        assert!(matches!(ops[0], MockOp::Propose { epoch: 20260714, .. }));
        assert!(matches!(ops[1], MockOp::Confirm { epoch: 20260714 }));
    }

    #[test]
    fn encode_propose_starts_with_selector() {
        let data = encode_propose_batch(1, [0u8; 32], [0u8; 32]);
        assert_eq!(&data[..4], &selector("proposeBatch(uint256,bytes32,bytes32)"));
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
        assert_eq!(
            &data[..4],
            &selector("lastClaimedCumulative(address)")
        );
        assert_eq!(data.len(), 4 + 32);
    }
}
