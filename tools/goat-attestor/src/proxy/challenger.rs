//! Proxy epoch challenger — **strict equality, both directions, no tolerance**.
//!
//! Not `crate::challenger::ChallengePolicy::InflateOnly`, and not a variant of
//! it. The compute lane tolerates under-reports because its scores are
//! cumulative and a later honest batch makes the worker whole. Proxy epochs are
//! not cumulative: each allocates a bounded amount from a finite pre-funded pool
//! and closes, so an under-report is never recovered and an over-report is taken
//! from the other operators in the same pool. Both directions must be
//! challengeable.
//!
//! There is no `tolerance` field, constant or env key anywhere in this lane, and
//! `the_proxy_config_exposes_no_tolerance_and_no_chunk_size_knob` asserts its
//! absence by reflection. The two counters being compared observe one byte
//! stream at one seam — `body_bytes_to_consumer`, response body octets after
//! HTTP framing is stripped and chunked transfer-encoding is decoded, as they
//! cross into the tunnel — so there is no measurement error a tolerance could
//! absorb, only an inflation budget it would publish. At ε basis points every
//! colluding operator takes ε forever, free, and rationally.
//!
//! # What is compared
//!
//! Per `(session_id, operator)`: the proposer's folded byte total against the
//! gateway's `total_bytes` for that session; the chunk counts; the attributed
//! operator; and **set membership in both directions** — a session present in
//! one document and absent from the other is a Challenge, not a zero.
//!
//! # Where a forfeited bond goes
//!
//! To the reserve. Never to the challenger, never destroyed — the rule
//! `contracts/src/HoldbackEscrow.sol:9` already states for the compute lane,
//! applied here unchanged. A bounty to challengers would price the act of
//! challenging, turning dispute into a market and inviting frivolous challenges
//! against honest proposers whose only defence is gas. A successful challenger
//! recovers its own bond and nothing else. This module therefore computes a
//! decision and no amount: there is no share of anything for it to compute.
//!
//! # The honest residual, recorded and not hidden
//!
//! With no bounty there is no economic incentive to challenge, so in practice
//! the challenger is the protocol's own second daemon — first-party and
//! altruistic, exactly as the compute lane's challenger is today. This lane
//! therefore inherits that lane's known weakness: **if the only challenger stops
//! running, nothing detects a bad batch until finalization.** The dispute path
//! is not decentralised and no copy may describe it as such.

use std::collections::{BTreeMap, BTreeSet};

use super::meter::VerifiedMeterCommitment;

/// The proposer's per-session view, folded from stored receipts.
///
/// Byte counts and opaque identifiers only. Nothing here can carry a hostname,
/// path, query string, header or body byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTotal {
    pub session_id: [u8; 32],
    pub operator: [u8; 20],
    pub total_bytes: u128,
    pub chunk_count: u64,
}

/// The outcome of comparing one proposed epoch against one witnessed one.
///
/// `Challenge` carries the numbers that disagree, so an operator reading a
/// dispute sees the two counts rather than a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyChallengeDecision {
    Ok,
    Challenge {
        reason: String,
        session_id_hex: String,
        operator_hex: String,
        proposed_bytes: u128,
        witnessed_bytes: u128,
    },
}

/// Compare a proposed epoch against the gateway's own signed meter.
///
/// Takes a [`VerifiedMeterCommitment`], not a bare one: the ordering "signature
/// first, comparison second" is enforced by the type, because a test name
/// cannot enforce it. Epoch binding, session uniqueness and internal
/// consistency are likewise already established — a document failing any of them
/// cannot be wrapped — so there is no branch here to forget.
///
/// Deterministic in the face of input ordering: both sides are keyed into
/// `BTreeMap`s and walked in session-id order, so two challengers handed the
/// same two documents in different orders report the *same* first disagreement.
pub fn evaluate_proxy_epoch(
    proposed: &[SessionTotal],
    witnessed: &VerifiedMeterCommitment,
) -> ProxyChallengeDecision {
    let witnessed = witnessed.as_ref();

    // Direction 0: the proposer may not list one session twice. Keying by
    // session id below would silently keep one of the two rows while the
    // aggregation lane's fold counted both, which is an over-report that no
    // per-session comparison can see.
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    if let Some(dup) = proposed.iter().find(|s| !seen.insert(s.session_id)) {
        return ProxyChallengeDecision::Challenge {
            reason: "the proposed batch lists the same session more than once".into(),
            session_id_hex: hex::encode(dup.session_id),
            operator_hex: hex::encode(dup.operator),
            proposed_bytes: dup.total_bytes,
            witnessed_bytes: witnessed
                .sessions
                .iter()
                .find(|w| w.session_id == dup.session_id)
                .map_or(0, |w| w.total_bytes),
        };
    }

    let wit: BTreeMap<[u8; 32], &_> = witnessed
        .sessions
        .iter()
        .map(|s| (s.session_id, s))
        .collect();
    let prop: BTreeMap<[u8; 32], &SessionTotal> =
        proposed.iter().map(|s| (s.session_id, s)).collect();

    // Direction 1: everything the proposer claims must be witnessed, identically.
    for (id, p) in &prop {
        match wit.get(id) {
            None => {
                return ProxyChallengeDecision::Challenge {
                    reason: "session claimed by the proposer is absent from the gateway meter"
                        .into(),
                    session_id_hex: hex::encode(id),
                    operator_hex: hex::encode(p.operator),
                    proposed_bytes: p.total_bytes,
                    witnessed_bytes: 0,
                }
            }
            Some(w) => {
                if w.operator != p.operator {
                    return ProxyChallengeDecision::Challenge {
                        reason: format!(
                            "session attributed to 0x{} by the proposer and 0x{} by the gateway",
                            hex::encode(p.operator),
                            hex::encode(w.operator)
                        ),
                        session_id_hex: hex::encode(id),
                        operator_hex: hex::encode(p.operator),
                        proposed_bytes: p.total_bytes,
                        witnessed_bytes: w.total_bytes,
                    };
                }
                if w.total_bytes != p.total_bytes || w.chunk_count != p.chunk_count {
                    return ProxyChallengeDecision::Challenge {
                        reason:
                            "byte or chunk count differs from the gateway meter (exact equality)"
                                .into(),
                        session_id_hex: hex::encode(id),
                        operator_hex: hex::encode(p.operator),
                        proposed_bytes: p.total_bytes,
                        witnessed_bytes: w.total_bytes,
                    };
                }
            }
        }
    }

    // Direction 2: everything the gateway witnessed must be claimed. Omission is
    // not a saving — it is an uncompensated operator, and it is unrecoverable.
    for (id, w) in &wit {
        if !prop.contains_key(id) {
            return ProxyChallengeDecision::Challenge {
                reason: "session witnessed by the gateway is absent from the proposed batch".into(),
                session_id_hex: hex::encode(id),
                operator_hex: hex::encode(w.operator),
                proposed_bytes: 0,
                witnessed_bytes: w.total_bytes,
            };
        }
    }

    ProxyChallengeDecision::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::meter::{
        meter_digest, verify_meter_commitment, GatewayMeterCommitment, GatewayMeterSession,
        MeterError,
    };
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;

    /// The epoch every fixture in this module is about. Named rather than read
    /// back out of the commitment, so `verified()` performs a real epoch
    /// binding instead of comparing a field with itself.
    const FIXTURE_EPOCH: u64 = 8_000_000_020_664;
    const CHAIN_ID: u64 = 84_532;
    const VERIFYING: [u8; 20] = [0x99; 20];

    fn test_signer(seed: u8) -> PrivateKeySigner {
        let mut key = [0u8; 32];
        key[31] = seed;
        PrivateKeySigner::from_slice(&key).expect("a non-zero scalar is a valid key")
    }

    fn gateway_address(s: &PrivateKeySigner) -> [u8; 20] {
        s.address().into_array()
    }

    fn sign(s: &PrivateKeySigner, digest: [u8; 32]) -> String {
        let sig = s
            .sign_hash_sync(&alloy::primitives::B256::from_slice(&digest))
            .expect("sign");
        format!("0x{}", hex::encode(sig.as_bytes()))
    }

    /// Every negative test below compares against a commitment that was
    /// VERIFIED first, because `evaluate_proxy_epoch` only accepts a
    /// `VerifiedMeterCommitment`.
    fn verified(w: GatewayMeterCommitment) -> VerifiedMeterCommitment {
        let gw = test_signer(3);
        let digest = meter_digest(&w, CHAIN_ID, VERIFYING).expect("digest");
        verify_meter_commitment(
            w,
            &sign(&gw, digest),
            gateway_address(&gw),
            FIXTURE_EPOCH,
            CHAIN_ID,
            VERIFYING,
        )
        .expect("the fixture gateway signature must verify")
    }

    fn sess(id: u8, operator: u8, bytes: u128, chunks: u64) -> GatewayMeterSession {
        let mut s = [0u8; 32];
        s[0] = id;
        let mut o = [0u8; 20];
        o[19] = operator;
        GatewayMeterSession {
            session_id: s,
            operator: o,
            total_bytes: bytes,
            chunk_count: chunks,
        }
    }

    fn proposed(id: u8, operator: u8, bytes: u128, chunks: u64) -> SessionTotal {
        let m = sess(id, operator, bytes, chunks);
        SessionTotal {
            session_id: m.session_id,
            operator: m.operator,
            total_bytes: m.total_bytes,
            chunk_count: m.chunk_count,
        }
    }

    fn raw_commitment(sessions: Vec<GatewayMeterSession>) -> GatewayMeterCommitment {
        let total_bytes = sessions.iter().map(|s| s.total_bytes).sum();
        GatewayMeterCommitment {
            epoch_id: FIXTURE_EPOCH,
            gateway_id: [0x66; 32],
            sessions,
            total_bytes,
        }
    }

    /// Every comparison test below goes through verification, because
    /// `evaluate_proxy_epoch` cannot be called with anything else.
    fn commitment(sessions: Vec<GatewayMeterSession>) -> VerifiedMeterCommitment {
        verified(raw_commitment(sessions))
    }

    /// POSITIVE CONTROL. Without it, a mutation that made `evaluate_proxy_epoch`
    /// always challenge would leave every negative test below green.
    ///
    /// Mutations this detects: any spurious challenge on an exactly-agreeing
    /// epoch.
    #[test]
    fn an_epoch_where_the_proposer_and_the_gateway_agree_exactly_is_accepted() {
        let w = commitment(vec![
            sess(1, 0xA1, 104_857_600, 10),
            sess(2, 0xB2, 10_485_760, 1),
        ]);
        let p = vec![
            proposed(1, 0xA1, 104_857_600, 10),
            proposed(2, 0xB2, 10_485_760, 1),
        ];
        assert_eq!(evaluate_proxy_epoch(&p, &w), ProxyChallengeDecision::Ok);

        // …and the proposer's own ordering is not part of the answer.
        let reversed = vec![
            proposed(2, 0xB2, 10_485_760, 1),
            proposed(1, 0xA1, 104_857_600, 10),
        ];
        assert_eq!(
            evaluate_proxy_epoch(&reversed, &w),
            ProxyChallengeDecision::Ok
        );
    }

    /// Mutations this detects: reintroducing ANY tolerance, in either
    /// direction. One byte is the smallest possible discrepancy, so a test that
    /// passes here pins the tolerance at exactly zero — no epsilon can hide
    /// under it.
    #[test]
    fn a_one_byte_meter_discrepancy_is_challenged_in_both_directions() {
        let w = commitment(vec![sess(1, 0xA1, 104_857_600, 10)]);

        // Over-report by one byte.
        let over = vec![proposed(1, 0xA1, 104_857_601, 10)];
        match evaluate_proxy_epoch(&over, &w) {
            ProxyChallengeDecision::Challenge {
                proposed_bytes,
                witnessed_bytes,
                ..
            } => {
                assert_eq!(proposed_bytes, 104_857_601);
                assert_eq!(witnessed_bytes, 104_857_600);
            }
            other => panic!("a one-byte over-report must be challenged, got {other:?}"),
        }

        // Under-report by one byte — challenged too, because proxy epochs are
        // not cumulative and an under-report is never recovered by a later
        // batch.
        let under = vec![proposed(1, 0xA1, 104_857_599, 10)];
        assert!(matches!(
            evaluate_proxy_epoch(&under, &w),
            ProxyChallengeDecision::Challenge { .. }
        ));

        // A one-CHUNK discrepancy at an identical byte total is challenged on
        // the same terms: chunk count is an anti-fraud surface, not a comment.
        let chunky = vec![proposed(1, 0xA1, 104_857_600, 11)];
        assert!(matches!(
            evaluate_proxy_epoch(&chunky, &w),
            ProxyChallengeDecision::Challenge { .. }
        ));
    }

    /// Mutations this detects: comparing only sessions the proposer listed (so
    /// a proposer could omit a session the gateway saw), or only sessions the
    /// gateway listed (so a proposer could invent a session outright).
    #[test]
    fn a_session_present_in_only_one_document_is_challenged() {
        let w = commitment(vec![sess(1, 0xA1, 104_857_600, 10)]);

        let invented = vec![
            proposed(1, 0xA1, 104_857_600, 10),
            proposed(9, 0xC3, 10_485_760, 1),
        ];
        assert!(matches!(
            evaluate_proxy_epoch(&invented, &w),
            ProxyChallengeDecision::Challenge { .. }
        ));

        let w2 = commitment(vec![
            sess(1, 0xA1, 104_857_600, 10),
            sess(2, 0xB2, 10_485_760, 1),
        ]);
        let dropped = vec![proposed(1, 0xA1, 104_857_600, 10)];
        assert!(matches!(
            evaluate_proxy_epoch(&dropped, &w2),
            ProxyChallengeDecision::Challenge { .. }
        ));
    }

    /// Mutations this detects: reattributing a session to a different operator
    /// while keeping the byte count intact — the one forgery that leaves every
    /// total correct and compensates the wrong household.
    #[test]
    fn a_session_reattributed_to_a_different_operator_is_challenged() {
        let w = commitment(vec![sess(1, 0xA1, 104_857_600, 10)]);
        let swapped = vec![proposed(1, 0xB2, 104_857_600, 10)];
        assert!(matches!(
            evaluate_proxy_epoch(&swapped, &w),
            ProxyChallengeDecision::Challenge { .. }
        ));
    }

    /// A session listed twice by the proposer is a Challenge, not a silent
    /// collapse.
    ///
    /// Keying by session id makes the LAST row win, so a proposer that lists
    /// session 1 as 100 MiB and again as 10 MiB would present a map the gateway
    /// agrees with, while the aggregation lane's fold over the same rows counts
    /// 110 MiB. That is an over-report no per-session comparison can see.
    ///
    /// Mutations this detects: deleting the duplicate scan, or moving it after
    /// the `BTreeMap` collect (by which point the evidence is gone).
    #[test]
    fn a_session_the_proposer_lists_twice_is_challenged_and_not_collapsed() {
        let w = commitment(vec![sess(1, 0xA1, 104_857_600, 10)]);

        // POSITIVE CONTROL: the single-row form of the same claim is accepted,
        // so the challenge below is caused by the repeat and nothing else.
        assert_eq!(
            evaluate_proxy_epoch(&[proposed(1, 0xA1, 104_857_600, 10)], &w),
            ProxyChallengeDecision::Ok
        );

        let doubled = vec![
            proposed(1, 0xA1, 104_857_600, 10),
            proposed(1, 0xA1, 10_485_760, 1),
        ];
        match evaluate_proxy_epoch(&doubled, &w) {
            ProxyChallengeDecision::Challenge { reason, .. } => {
                assert!(
                    reason.contains("more than once"),
                    "the duplicate must be named as such, got {reason:?}"
                );
            }
            other => panic!("a repeated session must be challenged, got {other:?}"),
        }
    }

    /// The gateway's two artifacts must agree with each other, or a compromised
    /// gateway key could counter-sign receipts it never metered and still
    /// publish an honest-looking commitment.
    ///
    /// Mutations this detects: comparing the header total against itself;
    /// wrapping an inconsistent document anyway and leaving the check to the
    /// comparison.
    #[test]
    fn gateway_meter_total_must_equal_the_sum_of_its_countersigned_receipts_exactly() {
        let mut w = raw_commitment(vec![
            sess(1, 0xA1, 104_857_600, 10),
            sess(2, 0xB2, 10_485_760, 1),
        ]);
        assert!(w.is_internally_consistent(), "positive control");
        w.total_bytes += 1;
        assert!(
            !w.is_internally_consistent(),
            "an inflated header total must be detectable"
        );

        // Stronger than "it would be challenged": an inconsistent commitment
        // cannot become a VerifiedMeterCommitment at all, so it can never reach
        // the comparison in the first place. The signature below is over the
        // INFLATED document and is perfectly valid, which is the point.
        let gw = test_signer(3);
        let digest = meter_digest(&w, CHAIN_ID, VERIFYING).expect("digest");
        assert!(matches!(
            verify_meter_commitment(
                w,
                &sign(&gw, digest),
                gateway_address(&gw),
                FIXTURE_EPOCH,
                CHAIN_ID,
                VERIFYING
            ),
            Err(MeterError::InternallyInconsistent { .. })
        ));
    }

    /// Mutations this detects: trusting a meter document without checking the
    /// gateway signature, which would let anyone who can answer the meter
    /// endpoint dictate the challenge outcome.
    ///
    /// The ORDERING this test's name claims is enforced by the TYPE, not by
    /// this test: `evaluate_proxy_epoch` takes a `VerifiedMeterCommitment`,
    /// whose field is private and whose only constructor is
    /// `verify_meter_commitment`. Give `evaluate_proxy_epoch` a bare
    /// `&GatewayMeterCommitment` and this module stops compiling, which is the
    /// assertion.
    #[test]
    fn a_meter_commitment_signed_by_the_wrong_key_is_refused_before_it_is_compared() {
        let w = raw_commitment(vec![sess(1, 0xA1, 104_857_600, 10)]);
        let gateway = test_signer(3);
        let impostor = test_signer(9);
        assert_ne!(
            gateway_address(&gateway),
            gateway_address(&impostor),
            "positive control: the two fixtures are different keys"
        );
        let digest = meter_digest(&w, CHAIN_ID, VERIFYING).unwrap();

        verify_meter_commitment(
            w.clone(),
            &sign(&gateway, digest),
            gateway_address(&gateway),
            FIXTURE_EPOCH,
            CHAIN_ID,
            VERIFYING,
        )
        .expect("positive control: the real gateway's signature verifies");

        assert!(matches!(
            verify_meter_commitment(
                w.clone(),
                &sign(&impostor, digest),
                gateway_address(&gateway),
                FIXTURE_EPOCH,
                CHAIN_ID,
                VERIFYING,
            ),
            Err(MeterError::SignerMismatch { .. })
        ));

        // Garbage in the signature slot is refused too, and as a DIFFERENT
        // refusal — so "malformed" can never be mistaken for "wrong signer".
        assert!(matches!(
            verify_meter_commitment(
                w,
                "0xdeadbeef",
                gateway_address(&gateway),
                FIXTURE_EPOCH,
                CHAIN_ID,
                VERIFYING,
            ),
            Err(MeterError::MalformedSignature(_))
        ));
    }

    /// A genuinely gateway-signed commitment cannot be replayed into another
    /// epoch, another deployment, or another session set.
    ///
    /// All four arms below carry a real gateway signature. The refusal is not
    /// "this is forged" but "this is not the document this evaluation is
    /// about", and without it a replayed commitment from a previous epoch
    /// verifies perfectly and then challenges every honest session in the
    /// current one — forfeiting the proposer's bond on a document the gateway
    /// really did sign.
    ///
    /// Mutations this detects: dropping the `expected_epoch` check (arm 1);
    /// dropping `epochId` from the signed struct (arm 1 would then fail as a
    /// SignerMismatch rather than an EpochMismatch, which the arm asserts
    /// against); dropping chain id or the verifying contract from the domain
    /// (arms 2 and 3); hashing anything less than the whole session array into
    /// `sessionsHash` (arm 4).
    #[test]
    fn a_commitment_replayed_across_epochs_or_sessions_is_refused() {
        let gw = test_signer(3);
        let sign_for = |c: &GatewayMeterCommitment, chain: u64, verifying: [u8; 20]| {
            sign(&gw, meter_digest(c, chain, verifying).expect("digest"))
        };

        // POSITIVE CONTROL: the untouched document verifies.
        let now = raw_commitment(vec![sess(1, 0xA1, 104_857_600, 10)]);
        verify_meter_commitment(
            now.clone(),
            &sign_for(&now, CHAIN_ID, VERIFYING),
            gateway_address(&gw),
            FIXTURE_EPOCH,
            CHAIN_ID,
            VERIFYING,
        )
        .expect("positive control");

        // Arm 1 — last epoch's document, correctly signed for last epoch,
        // offered to an evaluation of this one.
        let mut last = now.clone();
        last.epoch_id = FIXTURE_EPOCH - 1;
        assert_eq!(
            verify_meter_commitment(
                last.clone(),
                &sign_for(&last, CHAIN_ID, VERIFYING),
                gateway_address(&gw),
                FIXTURE_EPOCH,
                CHAIN_ID,
                VERIFYING,
            ),
            Err(MeterError::EpochMismatch {
                expected: FIXTURE_EPOCH,
                found: FIXTURE_EPOCH - 1,
            })
        );

        // Arm 2 — signed for Anvil, offered to a Base Sepolia evaluation.
        assert!(matches!(
            verify_meter_commitment(
                now.clone(),
                &sign_for(&now, 31_337, VERIFYING),
                gateway_address(&gw),
                FIXTURE_EPOCH,
                CHAIN_ID,
                VERIFYING,
            ),
            Err(MeterError::SignerMismatch { .. })
        ));

        // Arm 3 — signed against another verifying contract on the same chain.
        assert!(matches!(
            verify_meter_commitment(
                now.clone(),
                &sign_for(&now, CHAIN_ID, [0x11; 20]),
                gateway_address(&gw),
                FIXTURE_EPOCH,
                CHAIN_ID,
                VERIFYING,
            ),
            Err(MeterError::SignerMismatch { .. })
        ));

        // Arm 4 — a session lifted out of one commitment and spliced into
        // another. `sessionsHash` covers the whole array, so the digest moves
        // and the signature no longer recovers to the gateway.
        let mut spliced = now.clone();
        spliced.sessions.push(sess(2, 0xB2, 10_485_760, 1));
        spliced.total_bytes += 10_485_760;
        assert!(matches!(
            verify_meter_commitment(
                spliced,
                &sign_for(&now, CHAIN_ID, VERIFYING),
                gateway_address(&gw),
                FIXTURE_EPOCH,
                CHAIN_ID,
                VERIFYING,
            ),
            Err(MeterError::SignerMismatch { .. })
        ));

        // Arm 5 — one session id listed twice. Refused before the signature is
        // looked at, and the signature here is VALID for the duplicated
        // document, so the refusal cannot be a signature failure wearing
        // another name.
        let mut doubled = now.clone();
        doubled.sessions.push(sess(1, 0xA1, 10_485_760, 1));
        doubled.total_bytes += 10_485_760;
        assert!(matches!(
            verify_meter_commitment(
                doubled.clone(),
                &sign_for(&doubled, CHAIN_ID, VERIFYING),
                gateway_address(&gw),
                FIXTURE_EPOCH,
                CHAIN_ID,
                VERIFYING,
            ),
            Err(MeterError::DuplicateSession { .. })
        ));

        // Arm 6 — a chain this lane may not settle on, refused before anything
        // else is read.
        assert_eq!(
            verify_meter_commitment(
                now.clone(),
                &sign_for(&now, 1, VERIFYING),
                gateway_address(&gw),
                FIXTURE_EPOCH,
                1,
                VERIFYING,
            ),
            Err(MeterError::ChainNotAllowed { chain_id: 1 })
        );
    }

    /// The seam, pinned across processes.
    ///
    /// The fixture is the contract between two programs: the node's meter and
    /// the gateway's meter both read it and must produce the number in
    /// `body_bytes_to_consumer`. It is not asserted against itself — the pinned
    /// total is re-derived here from the per-chunk payload sizes, and the
    /// wrong-seam total is pinned beside it as a negative control.
    ///
    /// Mutations this detects: the node metering socket bytes (TLS records,
    /// handshake, request line) instead of decoded body bytes — under which
    /// strict equality challenges every honest epoch; counting chunked framing
    /// octets as payload; editing one of the two pinned totals without the
    /// other.
    #[test]
    fn node_and_gateway_count_the_same_quantity_for_a_pinned_fixture_payload() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../goat-proxy-worker/fixtures/metered-quantity.json"
        ))
        .expect("fixture is malformed");
        let n = |key: &str| -> u128 {
            fixture[key]
                .as_str()
                .expect("integers are decimal strings")
                .parse()
                .expect("parse")
        };

        let expected = n("body_bytes_to_consumer");
        assert_eq!(
            expected,
            n("gateway_to_consumer"),
            "the two processes must pin the SAME number, or strict equality is unshippable"
        );
        assert!(expected > 0, "vacuity guard: the fixture payload is empty");
        assert_eq!(
            fixture["metered_quantity"], "body_bytes_to_consumer",
            "the fixture must name the quantity it pins"
        );

        // The pin is DERIVED, not trusted: the decoded body is exactly the sum
        // of the chunk payloads, and nothing else.
        let chunks: Vec<u128> = fixture["chunk_sizes"]
            .as_array()
            .expect("chunk_sizes is an array")
            .iter()
            .map(|v| v.as_str().expect("decimal string").parse().expect("parse"))
            .collect();
        assert!(
            chunks.len() > 1,
            "one chunk cannot demonstrate that framing is excluded"
        );
        assert_eq!(
            chunks.iter().sum::<u128>(),
            expected,
            "the metered total is not the sum of the chunk payloads"
        );

        // NEGATIVE CONTROL: the wrong seam, pinned so a meter that drifts back
        // onto the socket is caught here rather than by a forfeited bond.
        let socket = n("origin_socket_bytes");
        assert_eq!(
            socket,
            expected + n("chunk_framing_bytes") + n("response_head_bytes"),
            "the socket total must be the body plus exactly the bytes the meter excludes"
        );
        assert_ne!(
            socket, expected,
            "if the two seams agreed, this fixture could not detect a meter on the wrong one"
        );
    }
}
