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

pub mod canonical_json;
pub mod chain;
pub mod challenger;
/// Doc-citation range audit — see the module doc for what it cannot prove.
///
/// `#[cfg(test)]`: it ships no runtime behaviour, only the sweep and its
/// helpers, so compiling it into the binary would be six dead symbols.
#[cfg(test)]
mod citation_audit;
pub mod config;
pub mod evidence;
pub mod fah;
pub mod gas_drips;
pub mod http_live;
/// Published-licence consistency audit — manifests, the two licence files, and
/// the README. See the module doc for what a green run does NOT prove (chiefly:
/// agreement between them is not entitlement to license the code at all).
///
/// `#[cfg(test)]` and private, like [`citation_audit`]: it ships no runtime
/// behaviour, only the audit and its manifest parser, so compiling it into the
/// binary would be dead symbols.
#[cfg(test)]
mod license_audit;
pub mod merkle;
pub mod proposer;
pub mod rate_limit;
pub mod registry;
pub mod relayer;
pub mod rpc_chain;
pub mod settlement;
pub mod sig_verify;
pub mod spend_ledger;
pub mod stream_g;

pub use canonical_json::{canonical_bytes, canonical_hash, CanonicalJsonError};
pub use chain::{
    decode_batch_return, encode_batches, encode_bind_with_signature, encode_challenge_batch,
    encode_claim_payout, encode_confirm_epoch, encode_enroll_self_with_signature,
    encode_finalize_batch, encode_has_baseline, encode_last_claimed_cumulative,
    encode_propose_batch, epoch_open_for_propose, parse_address20, BatchStatus, BatchView,
    BoundWorker, ChainClient, ChainError, MockChain, TxHash,
};
pub use challenger::{
    evaluate_batch, evaluate_batch_with_policy, policy_for_worker, ChallengeDecision,
    ChallengePolicy, Challenger,
};
pub use config::Config;
pub use evidence::{evidence_ref_keccak, write_evidence_json};
pub use fah::{FahClient, FahError, FahUserStats, FixtureHttp, HttpGet};
pub use gas_drips::{is_over_cap, utc_today, DripLedger, DEFAULT_DAILY_CAP};
pub use http_live::{AnyHttp, LiveHttp};
pub use merkle::{hash_pair, keccak256, leaf_hash, Leaf, MerkleTree};
pub use proposer::{
    build_epoch_batch, chain_or_wall_now, current_daily_epoch_id, daily_epoch_id,
    enrollment_epoch_id, is_enrollment_epoch, seconds_past_next_midnight, EpochBatch, Proposer,
    ENROLLMENT_EPOCH_BASE,
};
pub use registry::{WorkerEntry, WorkerRegistry};
pub use relayer::{
    validate_bind_request, validate_enroll_request, BindRelayRequest, EnrollRelayRequest,
};
pub use rpc_chain::RpcChain;
pub use settlement::{settle_and_claim_batch, SettleClaimReport};
