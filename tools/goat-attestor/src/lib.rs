//! GOAT FAH attribution attestor library.
//!
//! Untrusted off-chain daemon roles:
//! - **FAH stats reader** (cached, rate-limited)
//! - **Epoch batch proposer** (Merkle root + `proposeBatch`)
//! - **Enrollment snapshot** for newly-bound workers
//! - **Challenger** (inflate-only post-baseline; **strict equality** for enrollment /
//!   pre-baseline — under-report is protocol theft, not worker loss)
//! - **Relayer** HTTP API (gas-sponsored bind/enroll)
//!
//! Chain: `MockChain` when `GOAT_ATTESTOR_MOCK=1`; otherwise `RpcChain` (alloy HTTP).

pub mod chain;
pub mod challenger;
pub mod config;
pub mod evidence;
pub mod fah;
pub mod http_live;
pub mod merkle;
pub mod proposer;
pub mod registry;
pub mod relayer;
pub mod rpc_chain;
pub mod settlement;

pub use chain::{
    BatchStatus, BatchView, BoundWorker, ChainClient, ChainError, MockChain, TxHash,
    decode_batch_return, encode_batches, encode_bind_with_signature, encode_challenge_batch,
    encode_claim_payout, encode_confirm_epoch, encode_enroll_self_with_signature,
    encode_finalize_batch, encode_has_baseline, encode_last_claimed_cumulative,
    encode_propose_batch, parse_address20,
};
pub use settlement::{SettleClaimReport, settle_and_claim_batch};
pub use challenger::{
    ChallengeDecision, ChallengePolicy, Challenger, evaluate_batch, evaluate_batch_with_policy,
    policy_for_worker,
};
pub use config::Config;
pub use evidence::{evidence_ref_keccak, write_evidence_json};
pub use fah::{FahClient, FahError, FahUserStats, FixtureHttp, HttpGet};
pub use http_live::{AnyHttp, LiveHttp};
pub use merkle::{Leaf, MerkleTree, hash_pair, keccak256, leaf_hash};
pub use proposer::{
    ENROLLMENT_EPOCH_BASE, EpochBatch, Proposer, build_epoch_batch, daily_epoch_id,
    enrollment_epoch_id, is_enrollment_epoch,
};
pub use registry::{WorkerEntry, WorkerRegistry};
pub use relayer::{
    BindRelayRequest, EnrollRelayRequest, validate_bind_request, validate_enroll_request,
};
pub use rpc_chain::RpcChain;
