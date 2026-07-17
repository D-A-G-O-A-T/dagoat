//! Integration tests spanning FAH fixtures, merkle, proposer, challenger, mock chain, relayer.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use goat_attestor::chain::{BatchStatus, ChainClient, MockChain, MockOp};
use goat_attestor::challenger::{
    ChallengeDecision, ChallengePolicy, Challenger, evaluate_batch,
};
use goat_attestor::proposer::{enrollment_epoch_id, is_enrollment_epoch};
use goat_attestor::fah::{
    FahClient, FixtureHttp, HttpGet, default_fixtures_dir, parse_user_stats,
};
use goat_attestor::merkle::{Leaf, MerkleTree, hash_pair, leaf_hash, verify};
use goat_attestor::proposer::{build_epoch_batch, daily_epoch_id};
use goat_attestor::registry::{WorkerEntry, WorkerRegistry};
use goat_attestor::relayer::{
    BindRelayRequest, router_for, validate_bind_request,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn fixtures() -> FixtureHttp {
    FixtureHttp::new(default_fixtures_dir())
}

#[test]
fn t1_parse_alice_score() {
    let (status, body) = fixtures()
        .get("https://api.foldingathome.org/user/GOAT-alice")
        .unwrap();
    assert_eq!(status, 200);
    let s = parse_user_stats(&body).unwrap();
    assert_eq!(s.score, 51_022_340);
    assert_eq!(s.name, "GOAT-alice");
}

#[test]
fn t2_missing_score_errors() {
    let err = parse_user_stats(r#"{"name":"x","id":1,"wus":1}"#).unwrap_err();
    assert!(err.to_string().contains("score"));
}

#[test]
fn t3_cache_hit() {
    let client = FahClient::new(
        fixtures(),
        "https://api.foldingathome.org",
        Duration::from_secs(30),
    );
    let a = client.fetch_user("GOAT-alice").unwrap();
    let b = client.fetch_user("GOAT-alice").unwrap();
    assert_eq!(a.score, b.score);
    assert_eq!(client.live_count(), 1);
    assert_eq!(client.cache_count(), 1);
}

struct CountingHttp {
    n: std::sync::atomic::AtomicUsize,
    body: &'static str,
}

impl HttpGet for CountingHttp {
    fn get(&self, _url: &str) -> Result<(u16, String), goat_attestor::FahError> {
        self.n
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok((200, self.body.to_string()))
    }
}

#[test]
fn t4_rate_limit_min_interval() {
    let http = CountingHttp {
        n: std::sync::atomic::AtomicUsize::new(0),
        body: r#"{"name":"GOAT-alice","id":1,"score":1,"wus":1,"rank":1,"team":1}"#,
    };
    let client = FahClient::new(http, "https://example.test", Duration::from_secs(60));
    client.fetch_user("GOAT-alice").unwrap();
    let err = client.fetch_user("GOAT-bob").unwrap_err();
    assert!(
        matches!(err, goat_attestor::FahError::RateLimited(_)),
        "got {err:?}"
    );
}

#[test]
fn t5_leaf_hash_two_leaf_root_proof_roundtrip() {
    let a = Leaf {
        wallet: {
            let mut w = [0u8; 20];
            w[19] = 0xA1;
            w
        },
        cumulative_score: 51_022_340,
    };
    let b = Leaf {
        wallet: {
            let mut w = [0u8; 20];
            w[19] = 0xB2;
            w
        },
        cumulative_score: 600_000,
    };
    let la = leaf_hash(&a);
    let lb = leaf_hash(&b);
    let tree = MerkleTree::build(vec![a.clone(), b.clone()]);
    assert_eq!(tree.root(), hash_pair(&la, &lb));
    let proof = tree.proof(0).unwrap();
    assert!(verify(la, &proof, tree.root()));
    assert!(verify(lb, &tree.proof(1).unwrap(), tree.root()));
}

#[test]
fn t6_build_epoch_batch_alice_bob() {
    let workers = vec![
        (
            WorkerEntry {
                wallet: "0x00000000000000000000000000000000000000A1".into(),
                username: "GOAT-alice".into(),
                baseline_batched: true,
                fah_id: None,
                enrollment_epoch: None,
            },
            51_022_340u128,
        ),
        (
            WorkerEntry {
                wallet: "0x00000000000000000000000000000000000000B2".into(),
                username: "GOAT-bob".into(),
                baseline_batched: true,
                fah_id: None,
                enrollment_epoch: None,
            },
            600_000u128,
        ),
    ];
    let batch = build_epoch_batch(20260714, &workers, None).unwrap();
    assert_eq!(batch.leaves.len(), 2);
    assert_eq!(batch.leaves[0].cumulative_score, 51_022_340);
    assert_eq!(batch.leaves[1].cumulative_score, 600_000);
    assert_ne!(batch.merkle_root, [0u8; 32]);
}

#[test]
fn t7_evaluate_batch_ok_when_le() {
    let proposed = vec![("0xA1".into(), 100u128)];
    let public = vec![("0xA1".into(), 100u128)];
    assert_eq!(
        evaluate_batch(&proposed, &public, ChallengePolicy::InflateOnly),
        ChallengeDecision::Ok
    );
}

#[test]
fn t8_evaluate_batch_challenge_when_gt() {
    let proposed = vec![("0xA1".into(), 101u128)];
    let public = vec![("0xA1".into(), 100u128)];
    assert!(matches!(
        evaluate_batch(&proposed, &public, ChallengePolicy::InflateOnly),
        ChallengeDecision::Challenge { .. }
    ));
}

#[test]
fn t8b_enrollment_under_report_must_challenge() {
    // Consultant fatal hazard: baseline proposed 0 vs public 1e8 must slash.
    let proposed = vec![("0xA1".into(), 0u128)];
    let public = vec![("0xA1".into(), 100_000_000u128)];
    assert!(matches!(
        evaluate_batch(&proposed, &public, ChallengePolicy::StrictEquality),
        ChallengeDecision::Challenge {
            policy: ChallengePolicy::StrictEquality,
            ..
        }
    ));
    // Same under-report is OK under inflate-only (post-baseline daily).
    assert_eq!(
        evaluate_batch(&proposed, &public, ChallengePolicy::InflateOnly),
        ChallengeDecision::Ok
    );
    assert!(is_enrollment_epoch(enrollment_epoch_id(1)));
}

#[test]
fn t9_mock_chain_propose_confirm_records() {
    let chain = MockChain::new();
    let bond = 1_000_000_000_000_000_000u128;
    chain
        .propose_batch(20260714, [3u8; 32], [4u8; 32], bond)
        .unwrap();
    chain.confirm_epoch(20260714).unwrap();
    let b = chain.get_batch(20260714).unwrap();
    assert_eq!(b.status, BatchStatus::Proposed);
    assert!(b.watcher_confirmed_at > 0);
    let ops = chain.ops();
    assert!(matches!(ops[0], MockOp::Propose { .. }));
    assert!(matches!(ops[1], MockOp::Confirm { epoch: 20260714 }));
}

#[test]
fn t10_validate_bind_rejects_bad_username_and_empty_sig() {
    let bad_user = BindRelayRequest {
        wallet: "0x00000000000000000000000000000000000000A1".into(),
        username: "alice".into(),
        deadline: 1,
        signature: "0xab".into(),
    };
    assert!(validate_bind_request(&bad_user).is_err());

    let empty_sig = BindRelayRequest {
        wallet: "0x00000000000000000000000000000000000000A1".into(),
        username: "GOAT-alice".into(),
        deadline: 1,
        signature: "".into(),
    };
    assert!(validate_bind_request(&empty_sig).is_err());
}

#[tokio::test]
async fn t11_health_endpoint() {
    let app = router_for(MockChain::new());
    let res = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["ok"], true);
}

#[test]
fn challenger_integration_inflated_score() {
    let dir = tempfile::tempdir().unwrap();
    let chain = MockChain::new();
    let bond = 1_000_000_000_000_000_000u128;
    chain
        .propose_batch(20260714, [1u8; 32], [2u8; 32], bond)
        .unwrap();
    let fah = FahClient::new(
        fixtures(),
        "https://api.foldingathome.org",
        Duration::from_millis(0),
    );
    let mut reg = WorkerRegistry::new();
    reg.upsert(WorkerEntry {
        wallet: "0x00000000000000000000000000000000000000A1".into(),
        username: "GOAT-alice".into(),
        baseline_batched: true,
        fah_id: None,
        enrollment_epoch: None,
    });
    let c = Challenger {
        chain: &chain,
        fah: &fah,
        bond_wei: bond,
        evidence_dir: dir.path().to_path_buf(),
    };
    chain.set_has_baseline("0x00000000000000000000000000000000000000A1", true);
    let proposed = vec![(
        "0x00000000000000000000000000000000000000A1".into(),
        99_999_999u128,
    )];
    let d = c.review_epoch(20260714, &reg, &proposed).unwrap();
    assert!(matches!(d, ChallengeDecision::Challenge { .. }));
}

#[test]
fn challenger_integration_enrollment_under_report() {
    let dir = tempfile::tempdir().unwrap();
    let chain = MockChain::new();
    let bond = 1_000_000_000_000_000_000u128;
    let epoch = enrollment_epoch_id(1_720_000_000);
    chain
        .propose_batch(epoch, [1u8; 32], [2u8; 32], bond)
        .unwrap();
    let fah = FahClient::new(
        fixtures(),
        "https://api.foldingathome.org",
        Duration::from_millis(0),
    );
    let mut reg = WorkerRegistry::new();
    reg.upsert(WorkerEntry {
        wallet: "0x00000000000000000000000000000000000000A1".into(),
        username: "GOAT-alice".into(),
        baseline_batched: false,
        fah_id: None,
        enrollment_epoch: None,
    });
    let c = Challenger {
        chain: &chain,
        fah: &fah,
        bond_wei: bond,
        evidence_dir: dir.path().to_path_buf(),
    };
    let proposed = vec![(
        "0x00000000000000000000000000000000000000A1".into(),
        0u128, // theft: true public is 51022340
    )];
    let d = c.review_epoch(epoch, &reg, &proposed).unwrap();
    assert!(matches!(
        d,
        ChallengeDecision::Challenge {
            policy: ChallengePolicy::StrictEquality,
            ..
        }
    ));
}

#[test]
fn daily_epoch_smoke() {
    assert_eq!(daily_epoch_id(1_704_067_200), 20240101);
}
