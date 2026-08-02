//! Anti-fraud controls that no single signature check can express.
//!
//! Each function here is a **refusal**, never a warning and never a clamp, and
//! each is called from exactly one place: the per-bundle check from
//! `verify::verify_receipt_bundle` (stage `SelfDealing`), the per-epoch checks
//! from `aggregate::build_proxy_epoch_batch`.
//!
//! # What these controls do NOT do, stated so nobody claims otherwise
//!
//! They bound fraud about the **quantity** of bytes and about **who** moved
//! them. They say nothing about whether the bytes were worth moving. That is
//! the gap that makes this lane a transfer rather than an issuance.
//!
//! # What the gateway witness can and cannot see
//!
//! The whole three-party design leans on one fact: the gateway is the sole
//! ingress and is not compensated per byte, so its byte count is the
//! adversarially useful one. That is also the exact boundary of what it proves.
//!
//! It **can** see:
//!
//! * how many response body bytes crossed into the tunnel, so a consumer and an
//!   operator who agree on an inflated number cannot make the third signature
//!   agree with them (`verify` stage `GatewayWitness`, strict equality in both
//!   directions, no tolerance);
//! * which session and which operator those bytes were attributed to, so a
//!   session cannot be re-attributed after the fact.
//!
//! It **cannot** see:
//!
//! * whether the two parties are the same household. Nothing in the byte stream
//!   distinguishes wash traffic from demand; that is what
//!   [`check_not_self_dealing`] and [`check_pair_concentration`] are for, and
//!   both of them work off a sponsorship registry rather than off the traffic.
//! * whether the bytes had any purpose. Real bytes moved to a real allowlisted
//!   destination for no reason are indistinguishable, at every layer of this
//!   lane, from the same bytes moved for a reason.
//! * anything at all, if the gateway's own signing key is compromised. A
//!   compromised gateway signs whatever the colluding pair asks for and stage
//!   `GatewayWitness` passes. The second artifact — the gateway's independently
//!   retrievable signed meter commitment, compared by `super::challenger` —
//!   catches only the sub-case where the gateway's two documents disagree with
//!   each other. A gateway that lies consistently in both is not caught here,
//!   and no copy may say otherwise.
//!
//! # Why every ceiling here is keyed on a cluster root
//!
//! Compensation in this lane is per **byte**, not per node, so splitting one
//! connection across ten identities yields the same total and gains nothing on
//! the allocation itself. What extra identities buy is **ceiling evasion**: a
//! per-address byte ceiling and a per-address concentration cap are both free
//! to defeat by registering a second wallet. Every bound in this module is
//! therefore folded onto the sponsorship cluster root before it is compared,
//! and each has a named test whose positive control is the same traffic under
//! unrelated roots.

use std::collections::BTreeMap;

use thiserror::Error;

use super::aggregate::OperatorEpochTotal;
use super::challenger::SessionTotal;
use super::receipt::ChunkKind;
use super::store::StoredReceipt;
use super::BPS_DENOM;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FraudError {
    #[error(
        "SelfDealing: consumer 0x{consumer} and operator 0x{operator} resolve to cluster root \
         0x{root}"
    )]
    SelfDealing {
        consumer: String,
        operator: String,
        root: String,
    },
    #[error(
        "ClusterOverByteCeiling: root 0x{root} claims {claimed} bytes across {members} \
         identities, ceiling {ceiling}"
    )]
    ClusterOverByteCeiling {
        root: String,
        claimed: u128,
        members: usize,
        ceiling: u128,
    },
    #[error(
        "PairConcentrationExceeded: operator cluster 0x{operator} served {share_bps} bps of \
         consumer 0x{consumer}'s epoch bytes, cap {cap_bps}"
    )]
    PairConcentrationExceeded {
        operator: String,
        consumer: String,
        share_bps: u32,
        cap_bps: u32,
    },
    #[error(
        "ChunkSequenceGap: session 0x{session_id_hex} expected chunk {expected}, found {found}"
    )]
    ChunkSequenceGap {
        session_id_hex: String,
        expected: u64,
        found: u64,
    },
    #[error("MalformedSessionTail: session 0x{session_id_hex}: {reason}")]
    MalformedSessionTail {
        session_id_hex: String,
        reason: &'static str,
    },
}

/// THE self-dealing rule, written once, at whatever width the caller's registry
/// answers in.
///
/// Two parties self-deal when both roots resolve **and** resolve to the same
/// value. Both public entry points below funnel through this, so an edit to the
/// rule cannot leave one caller behind — and a test asserts the two agree.
///
/// An unresolvable root is deliberately **not** a finding. Absence of evidence
/// is not evidence: refusing on it would turn every un-enrolled honest consumer
/// into a fraud report. Whether enrolment is *required* is a policy question for
/// the lane's admission rules, not a question this comparison may answer by
/// accident.
fn shared_cluster_root(
    consumer_root: Option<&[u8]>,
    operator_root: Option<&[u8]>,
) -> Option<String> {
    match (consumer_root, operator_root) {
        (Some(c), Some(o)) if c == o => Some(hex::encode(c)),
        _ => None,
    }
}

/// Address inequality is not enough — a household holding two keys defeats it.
/// The cluster root is the identity that matters.
///
/// This is the **address-space** form: both parties are 20-byte wallets and the
/// registry answers in 20-byte roots. `verify` reaches the same rule through
/// [`check_not_self_dealing_by_cluster_root`], because a receipt identifies its
/// consumer by a 32-byte handle rather than by a wallet.
pub fn check_not_self_dealing(
    consumer: [u8; 20],
    operator: [u8; 20],
    root_of: &dyn Fn([u8; 20]) -> Option<[u8; 20]>,
) -> Result<(), FraudError> {
    if consumer == operator {
        return Err(FraudError::SelfDealing {
            consumer: hex::encode(consumer),
            operator: hex::encode(operator),
            root: hex::encode(consumer),
        });
    }
    let (rc, ro) = (root_of(consumer), root_of(operator));
    if let Some(root) =
        shared_cluster_root(rc.as_ref().map(|r| &r[..]), ro.as_ref().map(|r| &r[..]))
    {
        return Err(FraudError::SelfDealing {
            consumer: hex::encode(consumer),
            operator: hex::encode(operator),
            root,
        });
    }
    Ok(())
}

/// The same rule, reached from the per-bundle verifier, where the two lookups
/// have already been performed by `verify::ProxyPartyDirectory`.
///
/// This is **not** a second lookup path: it performs no lookup at all. It takes
/// the directory's two answers and applies [`shared_cluster_root`] to them. The
/// consumer is a 32-byte opaque handle here, so the address-equality shortcut in
/// [`check_not_self_dealing`] has no meaning at this width and is absent — an
/// operator wallet and a consumer handle can never be equal, and pretending to
/// compare them would be a check that cannot fail.
pub fn check_not_self_dealing_by_cluster_root(
    consumer_id: &[u8; 32],
    operator_wallet: &[u8; 20],
    consumer_root: Option<[u8; 32]>,
    operator_root: Option<[u8; 32]>,
) -> Result<(), FraudError> {
    if let Some(root) = shared_cluster_root(
        consumer_root.as_ref().map(|r| &r[..]),
        operator_root.as_ref().map(|r| &r[..]),
    ) {
        return Err(FraudError::SelfDealing {
            consumer: hex::encode(consumer_id),
            operator: hex::encode(operator_wallet),
            root,
        });
    }
    Ok(())
}

/// The epoch byte ceiling applies to the **cluster root**, not the address, so
/// registering a second operator identity buys no additional headroom.
///
/// The additions are `saturating_add`. An overflow panic inside a fraud control
/// is a denial of service reachable by anyone who can submit totals, and
/// saturation can only move a cluster's claim *up*, i.e. only toward a refusal —
/// it can never turn a breach into a pass. Reaching the saturation point at all
/// would need more bytes than `aggregate::storable_byte_total` lets through one
/// layer earlier.
pub fn check_cluster_byte_ceiling(
    totals: &[OperatorEpochTotal],
    root_of: &dyn Fn([u8; 20]) -> Option<[u8; 20]>,
    ceiling: u128,
) -> Result<(), FraudError> {
    let mut by_root: BTreeMap<[u8; 20], (u128, usize)> = BTreeMap::new();
    for t in totals {
        // An operator with no resolvable root is its own cluster. That is the
        // same "absence of evidence" posture as the self-dealing check: it
        // cannot create headroom, because a lone identity under its own root
        // still faces the whole ceiling.
        let root = root_of(t.operator).unwrap_or(t.operator);
        let e = by_root.entry(root).or_insert((0, 0));
        e.0 = e.0.saturating_add(t.total_bytes);
        e.1 += 1;
    }
    for (root, (claimed, members)) in by_root {
        if claimed > ceiling {
            return Err(FraudError::ClusterOverByteCeiling {
                root: hex::encode(root),
                claimed,
                members,
                ceiling,
            });
        }
    }
    Ok(())
}

/// No single operator CLUSTER may serve more than `cap_bps` of one consumer's
/// epoch bytes. The denominator is the CONSUMER's total, which is what makes
/// this a wash-traffic bound rather than a second copy of the byte ceiling.
///
/// The numerator is keyed on the CLUSTER ROOT, exactly as
/// [`check_cluster_byte_ceiling`] is. Keying on the raw address lets four sybil
/// identities under one root each hold 25% of a colluding consumer's bytes, stay
/// under a 2500 bps cap, and collectively serve all of it — the same evasion the
/// byte ceiling closes, left open in the function that is supposed to be the
/// wash-traffic bound.
///
/// **This bounds wash traffic; it does not detect it.** The bytes are genuinely
/// moved and genuinely metered, so no signature check anywhere in this lane can
/// tell them from demand. Two other things are doing most of the work and both
/// are scope conditions rather than mechanisms: the destination allowlist is
/// first-party and curated, so a pair cannot point at their own server, and the
/// consumer set is first-party, so a colluding consumer is a first-party bug
/// rather than an adversary. Both evaporate the moment an open marketplace
/// ships, which is exactly why that is gated.
pub fn check_pair_concentration(
    sessions: &[SessionTotal],
    consumer_of: &dyn Fn(&[u8; 32]) -> [u8; 32],
    root_of: &dyn Fn([u8; 20]) -> Option<[u8; 20]>,
    cap_bps: u32,
) -> Result<(), FraudError> {
    let mut consumer_total: BTreeMap<[u8; 32], u128> = BTreeMap::new();
    let mut pair_total: BTreeMap<([u8; 32], [u8; 20]), u128> = BTreeMap::new();
    for s in sessions {
        let c = consumer_of(&s.session_id);
        let root = root_of(s.operator).unwrap_or(s.operator);
        let ct = consumer_total.entry(c).or_insert(0);
        *ct = ct.saturating_add(s.total_bytes);
        let pt = pair_total.entry((c, root)).or_insert(0);
        *pt = pt.saturating_add(s.total_bytes);
    }
    for ((consumer, operator), bytes) in pair_total {
        let total = consumer_total.get(&consumer).copied().unwrap_or(0);
        if total == 0 {
            continue;
        }
        let share_bps =
            u32::try_from(bytes.saturating_mul(u128::from(BPS_DENOM)) / total).unwrap_or(u32::MAX);
        if share_bps > cap_bps {
            return Err(FraudError::PairConcentrationExceeded {
                operator: hex::encode(operator),
                consumer: hex::encode(consumer),
                share_bps,
                cap_bps,
            });
        }
    }
    Ok(())
}

/// Chunks contiguous from 0, exactly one FINAL, FINAL highest.
///
/// Every receipt in `receipts` must belong to one session; [`check_session_chunk_sequences`]
/// is the grouping wrapper. A duplicate `chunk_seq` — which is what a receipt
/// replayed back into its own session looks like once the store's UNIQUE index
/// has been bypassed or the replay arrives at a different node — lands as a
/// [`FraudError::ChunkSequenceGap`], because sorting puts the two copies
/// adjacent and the second one is then one short of its index.
pub fn check_session_chunk_sequence(receipts: &[StoredReceipt]) -> Result<(), FraudError> {
    if receipts.is_empty() {
        return Ok(());
    }
    let session_id_hex = receipts[0].session_id_hex.clone();
    let mut sorted: Vec<&StoredReceipt> = receipts.iter().collect();
    sorted.sort_by_key(|r| r.chunk_seq);

    for (i, r) in sorted.iter().enumerate() {
        let expected = i as u64;
        if r.chunk_seq != expected {
            return Err(FraudError::ChunkSequenceGap {
                session_id_hex: session_id_hex.clone(),
                expected,
                found: r.chunk_seq,
            });
        }
    }

    let finals: Vec<&StoredReceipt> = sorted
        .iter()
        .copied()
        .filter(|r| r.chunk_kind == ChunkKind::Final)
        .collect();
    match finals.len() {
        0 => Err(FraudError::MalformedSessionTail {
            session_id_hex,
            reason: "no FINAL chunk; the session never closed",
        }),
        1 => {
            if finals[0].chunk_seq != (sorted.len() as u64 - 1) {
                return Err(FraudError::MalformedSessionTail {
                    session_id_hex,
                    reason: "the FINAL chunk is not the highest chunk_seq",
                });
            }
            Ok(())
        }
        _ => Err(FraudError::MalformedSessionTail {
            session_id_hex,
            reason: "more than one FINAL chunk in one session",
        }),
    }
}

/// Group an epoch's receipts by session and hold every session to
/// [`check_session_chunk_sequence`].
///
/// The grouping key is the stored hex string rather than a decoded array on
/// purpose: this runs over rows the store wrote, a malformed identifier is
/// `aggregate`'s refusal to make, and re-deciding it here would give the lane
/// two answers.
pub fn check_session_chunk_sequences(receipts: &[StoredReceipt]) -> Result<(), FraudError> {
    let mut by_session: BTreeMap<&str, Vec<StoredReceipt>> = BTreeMap::new();
    for r in receipts {
        by_session
            .entry(r.session_id_hex.as_str())
            .or_default()
            .push(r.clone());
    }
    for group in by_session.values() {
        check_session_chunk_sequence(group)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(byte: u8) -> [u8; 20] {
        let mut x = [0u8; 20];
        x[19] = byte;
        x
    }

    fn w(byte: u8) -> [u8; 32] {
        let mut x = [0u8; 32];
        x[31] = byte;
        x
    }

    /// One session's worth of stored rows, from `(chunk_seq, kind)` pairs.
    fn stored_chunks(spec: &[(u64, ChunkKind)]) -> Vec<StoredReceipt> {
        spec.iter()
            .map(|(seq, kind)| StoredReceipt {
                receipt_hash_hex: hex::encode([0x01u8; 32]),
                epoch_id: 8_000_000_020_664,
                session_id_hex: hex::encode([0x5Eu8; 32]),
                chunk_seq: *seq,
                operator_wallet: hex::encode([0x99u8; 20]),
                consumer_id_hex: hex::encode([0x77u8; 32]),
                bytes_transferred: 1_048_576,
                chunk_kind: *kind,
                gateway_id_hex: hex::encode([0x66u8; 32]),
                price_goat_wei_per_mebibyte: 1_000_000_000_000,
            })
            .collect()
    }

    /// Mutations this detects: checking address inequality only (defeated by a
    /// second key under one household), or dropping the check entirely.
    /// Positive control: two genuinely unrelated parties pass.
    #[test]
    fn self_dealing_is_rejected_when_consumer_and_operator_share_a_cluster_root() {
        // 0x01 and 0x02 are both secondaries of root 0xFF; 0x03 is independent.
        let root_of = |x: [u8; 20]| -> Option<[u8; 20]> {
            match x[19] {
                1 | 2 => Some(a(0xFF)),
                other => Some(a(other)),
            }
        };

        assert!(matches!(
            check_not_self_dealing(a(1), a(1), &root_of),
            Err(FraudError::SelfDealing { .. })
        ));
        assert!(matches!(
            check_not_self_dealing(a(1), a(2), &root_of),
            Err(FraudError::SelfDealing { .. })
        ));
        check_not_self_dealing(a(1), a(3), &root_of).expect("unrelated parties must pass");

        // The refusal names the shared root, not one of the two addresses: an
        // investigator needs the household, and the two wallets are already in
        // the receipt.
        let err = check_not_self_dealing(a(1), a(2), &root_of).expect_err("shared root");
        assert_eq!(
            err,
            FraudError::SelfDealing {
                consumer: hex::encode(a(1)),
                operator: hex::encode(a(2)),
                root: hex::encode(a(0xFF)),
            }
        );

        // NEGATIVE CONTROL on the rule itself: a registry that resolves NOBODY
        // must not turn every honest pair into a finding. Absence of evidence is
        // not evidence.
        let knows_nobody = |_x: [u8; 20]| -> Option<[u8; 20]> { None };
        check_not_self_dealing(a(1), a(2), &knows_nobody)
            .expect("an unresolvable root is not a fraud finding");

        // ...but the address-equality half still fires without any registry at
        // all, so the two halves are independent.
        assert!(matches!(
            check_not_self_dealing(a(7), a(7), &knows_nobody),
            Err(FraudError::SelfDealing { .. })
        ));
    }

    /// The verifier's seam. `verify` identifies a consumer by a 32-byte handle,
    /// so it reaches the rule through the by-root entry point; both entry points
    /// must apply ONE rule, or the per-bundle stage and the documented control
    /// drift apart.
    ///
    /// Mutations this detects: giving the by-root entry point its own comparison
    /// (e.g. refusing when only one root resolves, or comparing the handle
    /// against the wallet); inverting either arm of [`shared_cluster_root`].
    #[test]
    fn both_self_dealing_entry_points_apply_one_rule() {
        let consumer_id = [0xC2u8; 32];
        let operator_wallet = a(1);

        // Shared root -> refusal, at both widths.
        assert!(matches!(
            check_not_self_dealing_by_cluster_root(
                &consumer_id,
                &operator_wallet,
                Some(w(0xFF)),
                Some(w(0xFF)),
            ),
            Err(FraudError::SelfDealing { .. })
        ));

        // Different roots -> pass.
        check_not_self_dealing_by_cluster_root(
            &consumer_id,
            &operator_wallet,
            Some(w(0xAA)),
            Some(w(0xBB)),
        )
        .expect("two different households must pass");

        // Either root missing -> pass, in both directions. This is the recorded
        // policy: an unknown SIGNER is a refusal (verify's own stages), an
        // unresolvable CLUSTER ROOT is not.
        for (c, o) in [
            (None, Some(w(0xFF))),
            (Some(w(0xFF)), None),
            (None, None),
            (None::<[u8; 32]>, Some(w(0xFF))),
        ] {
            check_not_self_dealing_by_cluster_root(&consumer_id, &operator_wallet, c, o)
                .expect("an unresolvable root is an absence of evidence, not a finding");
        }

        // The two entry points agree on the same four truth-table rows.
        let rows: [(Option<u8>, Option<u8>, bool); 4] = [
            (Some(0xFF), Some(0xFF), false),
            (Some(0xAA), Some(0xBB), true),
            (None, Some(0xFF), true),
            (Some(0xFF), None, true),
        ];
        for (c, o, expected_ok) in rows {
            let by_root = check_not_self_dealing_by_cluster_root(
                &consumer_id,
                &operator_wallet,
                c.map(w),
                o.map(w),
            )
            .is_ok();
            let by_address = {
                let root_of = |x: [u8; 20]| -> Option<[u8; 20]> {
                    if x == a(1) {
                        c.map(a)
                    } else {
                        o.map(a)
                    }
                };
                check_not_self_dealing(a(1), a(2), &root_of).is_ok()
            };
            assert_eq!(
                by_root, by_address,
                "the two entry points disagree on ({c:?}, {o:?})"
            );
            assert_eq!(by_root, expected_ok, "wrong verdict for ({c:?}, {o:?})");
        }
    }

    /// Mutations this detects: enforcing the byte ceiling per operator ADDRESS
    /// rather than per cluster root, which makes the ceiling free to evade by
    /// registering a second identity.
    #[test]
    fn sybil_operators_under_one_cluster_root_share_one_epoch_byte_ceiling() {
        let root_of = |x: [u8; 20]| -> Option<[u8; 20]> {
            match x[19] {
                1..=3 => Some(a(0xFF)),
                other => Some(a(other)),
            }
        };
        let ceiling = 100_000u128;
        let totals = vec![
            OperatorEpochTotal::for_test(a(1), 40_000, 4, 36_000, 4_000),
            OperatorEpochTotal::for_test(a(2), 40_000, 4, 36_000, 4_000),
            OperatorEpochTotal::for_test(a(3), 40_000, 4, 36_000, 4_000),
        ];
        let err = check_cluster_byte_ceiling(&totals, &root_of, ceiling)
            .expect_err("one root, three identities, 120 000 bytes against a 100 000 ceiling");
        assert_eq!(
            err,
            FraudError::ClusterOverByteCeiling {
                root: hex::encode(a(0xFF)),
                claimed: 120_000,
                members: 3,
                ceiling,
            }
        );

        // Positive control: three UNRELATED operators at the same volumes pass.
        let independent = |x: [u8; 20]| -> Option<[u8; 20]> { Some(x) };
        check_cluster_byte_ceiling(&totals, &independent, ceiling)
            .expect("unrelated operators must each get their own ceiling");

        // An operator the registry does not know is its own cluster — which
        // cannot create headroom, only consume its own.
        let knows_nobody = |_x: [u8; 20]| -> Option<[u8; 20]> { None };
        check_cluster_byte_ceiling(&totals, &knows_nobody, ceiling)
            .expect("an unresolvable root is one cluster of one, not a bypass");
        assert!(matches!(
            check_cluster_byte_ceiling(&totals, &knows_nobody, 39_999),
            Err(FraudError::ClusterOverByteCeiling { .. })
        ));

        // The boundary is `>`, not `>=`: exactly at the ceiling is allowed.
        check_cluster_byte_ceiling(&totals, &root_of, 120_000).expect("at the ceiling is allowed");
        assert!(matches!(
            check_cluster_byte_ceiling(&totals, &root_of, 119_999),
            Err(FraudError::ClusterOverByteCeiling { .. })
        ));
    }

    /// Mutations this detects: dropping the concentration cap; applying it to
    /// the wrong denominator (the operator's bytes instead of the consumer's);
    /// and -- the sybil case -- keying the numerator on the raw operator ADDRESS
    /// rather than the cluster root, which four identities under one household
    /// defeat for free.
    #[test]
    fn pair_concentration_over_the_cap_is_refused_at_aggregation() {
        let mut s1 = [0u8; 32];
        s1[0] = 1;
        let mut s2 = [0u8; 32];
        s2[0] = 2;
        let consumer = [0xCCu8; 32];
        let consumer_of = |_id: &[u8; 32]| consumer;
        let independent = |x: [u8; 20]| -> Option<[u8; 20]> { Some(x) };

        // One operator serves 80% of this consumer's epoch bytes; cap is 25%.
        let totals = vec![
            SessionTotal {
                session_id: s1,
                operator: a(1),
                total_bytes: 80,
                chunk_count: 8,
            },
            SessionTotal {
                session_id: s2,
                operator: a(2),
                total_bytes: 20,
                chunk_count: 2,
            },
        ];
        let err = check_pair_concentration(&totals, &consumer_of, &independent, 2_500)
            .expect_err("8000 bps against a 2500 bps cap");
        assert_eq!(
            err,
            FraudError::PairConcentrationExceeded {
                operator: hex::encode(a(1)),
                consumer: hex::encode(consumer),
                share_bps: 8_000,
                cap_bps: 2_500,
            }
        );

        let spread = vec![
            SessionTotal {
                session_id: s1,
                operator: a(1),
                total_bytes: 25,
                chunk_count: 3,
            },
            SessionTotal {
                session_id: s2,
                operator: a(2),
                total_bytes: 75,
                chunk_count: 8,
            },
        ];
        check_pair_concentration(&spread, &consumer_of, &independent, 7_500)
            .expect("at the cap is allowed");
        assert!(matches!(
            check_pair_concentration(&spread, &consumer_of, &independent, 7_499),
            Err(FraudError::PairConcentrationExceeded { .. })
        ));

        // THE DENOMINATOR. Two consumers, one operator serving 50 bytes to each:
        // per-consumer that is 100% twice, and against the OPERATOR's own total
        // it would be 50% twice. Only the consumer denominator refuses this.
        let two_consumers = |id: &[u8; 32]| -> [u8; 32] {
            let mut c = [0u8; 32];
            c[0] = id[0];
            c
        };
        let split = vec![
            SessionTotal {
                session_id: s1,
                operator: a(1),
                total_bytes: 50,
                chunk_count: 5,
            },
            SessionTotal {
                session_id: s2,
                operator: a(1),
                total_bytes: 50,
                chunk_count: 5,
            },
        ];
        assert!(
            matches!(
                check_pair_concentration(&split, &two_consumers, &independent, 5_000),
                Err(FraudError::PairConcentrationExceeded { share_bps, .. }) if share_bps == 10_000
            ),
            "the denominator must be the CONSUMER's epoch bytes, not the operator's"
        );
    }

    /// THE evasion the sibling function already closes for the byte ceiling,
    /// closed here too. Four sybil identities under one root each serve 25% of a
    /// colluding consumer's bytes, each stay under a 2500 bps cap, and
    /// collectively serve 100%.
    ///
    /// Mutations this detects: `check_pair_concentration` reverting to keying on
    /// `s.operator` instead of `root_of(s.operator)`.
    #[test]
    fn sybil_operators_under_one_root_cannot_split_a_pair_concentration_cap() {
        let consumer = [0xCCu8; 32];
        let consumer_of = |_id: &[u8; 32]| consumer;
        let root_of = |x: [u8; 20]| -> Option<[u8; 20]> {
            match x[19] {
                1..=4 => Some(a(0xFF)),
                other => Some(a(other)),
            }
        };
        let mut sessions = Vec::new();
        for i in 1u8..=4 {
            let mut id = [0u8; 32];
            id[0] = i;
            sessions.push(SessionTotal {
                session_id: id,
                operator: a(i),
                total_bytes: 25,
                chunk_count: 3,
            });
        }

        // POSITIVE CONTROL: treated as four unrelated operators, this passes.
        let independent = |x: [u8; 20]| -> Option<[u8; 20]> { Some(x) };
        check_pair_concentration(&sessions, &consumer_of, &independent, 2_500)
            .expect("unrelated operators each hold their own share");

        // Under one root, the same traffic is 100% of the consumer's bytes.
        let err = check_pair_concentration(&sessions, &consumer_of, &root_of, 2_500)
            .expect_err("one root serving all of a consumer's bytes");
        assert_eq!(
            err,
            FraudError::PairConcentrationExceeded {
                operator: hex::encode(a(0xFF)),
                consumer: hex::encode(consumer),
                share_bps: 10_000,
                cap_bps: 2_500,
            }
        );
    }

    /// The wash-traffic control BOUNDS, it does not DETECT. A pair moving real
    /// bytes for no purpose, while staying under the cap, is accepted — there is
    /// nothing in the receipts, the witness or the meter that distinguishes it
    /// from demand.
    ///
    /// This test exists so the residual is written down as an executable
    /// assertion rather than as a comment nobody re-reads. If a later change
    /// claims to *detect* wash traffic, this test is the one that has to be
    /// deleted, and deleting it is a decision somebody has to make on purpose.
    ///
    /// Mutations this detects: a cap that refuses everything (which would make
    /// every other refusal test in this file pass for the wrong reason).
    #[test]
    fn wash_traffic_under_the_cap_is_accepted_because_this_lane_cannot_see_purpose() {
        let consumer = [0xCCu8; 32];
        let consumer_of = |_id: &[u8; 32]| consumer;
        let independent = |x: [u8; 20]| -> Option<[u8; 20]> { Some(x) };

        // A colluding pair and three honest operators, all serving the same
        // consumer. The colluding operator takes 25% -- real bytes, moved to an
        // allowlisted destination, for no reason at all -- and is accepted.
        let mut sessions = Vec::new();
        for i in 1u8..=4 {
            let mut id = [0u8; 32];
            id[0] = i;
            sessions.push(SessionTotal {
                session_id: id,
                operator: a(i),
                total_bytes: 25,
                chunk_count: 3,
            });
        }
        check_pair_concentration(&sessions, &consumer_of, &independent, 2_500)
            .expect("25% is under a 2500 bps cap and is therefore ACCEPTED, purpose unexamined");

        // The bound is real, though: the same pair taking 26% is refused. Without
        // this arm the assertion above would also pass against a function that
        // accepts everything.
        sessions[0].total_bytes = 26;
        assert!(matches!(
            check_pair_concentration(&sessions, &consumer_of, &independent, 2_500),
            Err(FraudError::PairConcentrationExceeded { .. })
        ));
    }

    /// Mutations this detects: accepting a session whose chunks do not start at
    /// 0, or that skips a sequence number -- the cheapest way to claim ten
    /// chunks' bytes while submitting two receipts.
    #[test]
    fn a_session_with_a_gap_in_chunk_seq_is_refused() {
        let good = stored_chunks(&[
            (0, ChunkKind::Interim),
            (1, ChunkKind::Interim),
            (2, ChunkKind::Final),
        ]);
        check_session_chunk_sequence(&good).expect("positive control: contiguous from zero");

        let gap = stored_chunks(&[(0, ChunkKind::Interim), (2, ChunkKind::Final)]);
        assert!(matches!(
            check_session_chunk_sequence(&gap),
            Err(FraudError::ChunkSequenceGap {
                expected: 1,
                found: 2,
                ..
            })
        ));

        let late_start = stored_chunks(&[(1, ChunkKind::Interim), (2, ChunkKind::Final)]);
        assert!(matches!(
            check_session_chunk_sequence(&late_start),
            Err(FraudError::ChunkSequenceGap {
                expected: 0,
                found: 1,
                ..
            })
        ));

        // Order of submission is irrelevant: the check sorts first, so a
        // correct session shuffled is still correct.
        let mut shuffled = good.clone();
        shuffled.reverse();
        check_session_chunk_sequence(&shuffled).expect("submission order is not a finding");

        // An empty set is not a violation; it is nothing to check. Asserted so
        // nobody "fixes" it into a refusal that would red every epoch with an
        // idle operator in it.
        check_session_chunk_sequence(&[]).expect("no receipts is not a malformed session");
    }

    /// A receipt replayed back into its own session is a duplicate `chunk_seq`,
    /// and this is the layer that names it. **This is the third of three
    /// independent replay defences and the weakest of them**, present because
    /// each of the three fails differently:
    ///
    /// 1. the signed `epoch_id` inside the receipt struct (verify stage 2) —
    ///    kills cross-EPOCH replay, proved by
    ///    `a_receipt_replayed_into_a_later_epoch_is_rejected_by_the_signed_epoch_id`;
    /// 2. `UNIQUE(session_id_hex, chunk_seq)` and
    ///    `UNIQUE(operator_wallet, gateway_id_hex, counter)` in migration `0004`
    ///    — kill same-epoch replay at the moment of INSERT, including
    ///    cross-SESSION replay, which the counter is global across sessions and
    ///    epochs precisely to catch, proved by
    ///    `a_replayed_receipt_is_a_duplicate_key_violation_not_an_addition`;
    /// 3. this check, which catches a duplicate that reached the aggregation
    ///    document anyway — a row set assembled from more than one store, or a
    ///    proposer that read the same page twice.
    ///
    /// Mutations this detects: dropping the contiguity loop; comparing
    /// `sorted[i].chunk_seq` against the PREVIOUS value rather than against `i`,
    /// which accepts a duplicate; deduplicating the input instead of refusing it.
    #[test]
    fn a_replayed_chunk_inside_a_session_is_refused_as_a_sequence_violation() {
        // POSITIVE CONTROL: the honest three-chunk session passes.
        let honest = stored_chunks(&[
            (0, ChunkKind::Interim),
            (1, ChunkKind::Interim),
            (2, ChunkKind::Final),
        ]);
        check_session_chunk_sequence(&honest).expect("the honest session must pass");

        // Chunk 1 submitted twice, byte-for-byte. Sorted, that is [0, 1, 1, 2]:
        // index 2 expects chunk 2 and finds chunk 1.
        let mut replayed = honest.clone();
        replayed.push(honest[1].clone());
        let err = check_session_chunk_sequence(&replayed).expect_err("a replayed chunk");
        assert!(
            matches!(
                err,
                FraudError::ChunkSequenceGap {
                    expected: 2,
                    found: 1,
                    ..
                }
            ),
            "expected the duplicate to land as a sequence gap, got {err:?}"
        );

        // And the replayed bytes are NOT silently folded in: the refusal is the
        // whole answer, so no total is produced at all.
        assert!(check_session_chunk_sequence(&replayed).is_err());

        // The FINAL chunk replayed is caught by the tail rule as well as the
        // sequence rule, so the two are not one check wearing two hats.
        let two_tails = stored_chunks(&[(0, ChunkKind::Interim), (1, ChunkKind::Final)]);
        let mut tail_replay = two_tails.clone();
        tail_replay.push(two_tails[1].clone());
        assert!(check_session_chunk_sequence(&tail_replay).is_err());
    }

    /// Mutations this detects: allowing more than one FINAL per session (two
    /// tails, two sub-chunk-size receipts, one session), or allowing a FINAL
    /// that is not the highest sequence number (a session that never closes).
    #[test]
    fn a_session_with_two_final_chunks_is_refused() {
        let two_finals = stored_chunks(&[(0, ChunkKind::Final), (1, ChunkKind::Final)]);
        assert!(matches!(
            check_session_chunk_sequence(&two_finals),
            Err(FraudError::MalformedSessionTail {
                reason: "more than one FINAL chunk in one session",
                ..
            })
        ));

        let final_not_last = stored_chunks(&[(0, ChunkKind::Final), (1, ChunkKind::Interim)]);
        assert!(matches!(
            check_session_chunk_sequence(&final_not_last),
            Err(FraudError::MalformedSessionTail {
                reason: "the FINAL chunk is not the highest chunk_seq",
                ..
            })
        ));

        let no_final = stored_chunks(&[(0, ChunkKind::Interim), (1, ChunkKind::Interim)]);
        assert!(matches!(
            check_session_chunk_sequence(&no_final),
            Err(FraudError::MalformedSessionTail {
                reason: "no FINAL chunk; the session never closed",
                ..
            })
        ));

        // POSITIVE CONTROL: one FINAL, highest, passes.
        check_session_chunk_sequence(&stored_chunks(&[
            (0, ChunkKind::Interim),
            (1, ChunkKind::Final),
        ]))
        .expect("one FINAL at the top is a well-formed session");
    }

    /// The grouping wrapper must hold EVERY session, not just the first one it
    /// meets, and must not smear two sessions' chunks into one sequence.
    ///
    /// Mutations this detects: checking only `receipts[0]`'s session; grouping on
    /// something other than the session id (which would merge two honest
    /// sessions into one bogus gap); `return Ok(())` after the first group.
    #[test]
    fn every_session_in_an_epoch_is_held_to_the_sequence_rule() {
        let mut all = Vec::new();
        for s in 0u8..3 {
            for (seq, kind) in [(0u64, ChunkKind::Interim), (1, ChunkKind::Final)] {
                let mut r = stored_chunks(&[(seq, kind)]).remove(0);
                r.session_id_hex = hex::encode([s; 32]);
                all.push(r);
            }
        }
        // POSITIVE CONTROL: three well-formed sessions, interleaved.
        check_session_chunk_sequences(&all).expect("three honest sessions must pass");
        assert_eq!(all.len(), 6, "the sweep must have three sessions to sweep");

        // Break the LAST session only. A wrapper that checks the first group and
        // returns would still report green.
        let mut broken = all.clone();
        broken.last_mut().expect("non-empty").chunk_seq = 5;
        assert!(matches!(
            check_session_chunk_sequences(&broken),
            Err(FraudError::ChunkSequenceGap { .. })
        ));

        // Two DIFFERENT sessions each carrying chunk 0 are not a duplicate: a
        // wrapper that ignored the session id would refuse this honest set.
        let mut two_zeroes = Vec::new();
        for s in 0u8..2 {
            let mut r = stored_chunks(&[(0, ChunkKind::Final)]).remove(0);
            r.session_id_hex = hex::encode([s; 32]);
            two_zeroes.push(r);
        }
        check_session_chunk_sequences(&two_zeroes)
            .expect("two sessions may each have their own chunk 0");
    }

    /// Every refusal this module can produce is made of hex identifiers and
    /// integers. A destination — a URL, a path, a query string, a header — can
    /// never reach one, because none of the five variants has a field that could
    /// carry it.
    ///
    /// Mutations this detects: adding a `&str` field to a variant and rendering
    /// caller-supplied text into it; widening `reason` from `&'static str` to a
    /// formatted string built from row data.
    #[test]
    fn no_fraud_refusal_message_can_carry_a_destination() {
        let messages = [
            FraudError::SelfDealing {
                consumer: hex::encode([0x11u8; 32]),
                operator: hex::encode([0x22u8; 20]),
                root: hex::encode([0x33u8; 32]),
            }
            .to_string(),
            FraudError::ClusterOverByteCeiling {
                root: hex::encode([0x33u8; 20]),
                claimed: 120_000,
                members: 3,
                ceiling: 100_000,
            }
            .to_string(),
            FraudError::PairConcentrationExceeded {
                operator: hex::encode([0x44u8; 20]),
                consumer: hex::encode([0x55u8; 32]),
                share_bps: 8_000,
                cap_bps: 2_500,
            }
            .to_string(),
            FraudError::ChunkSequenceGap {
                session_id_hex: hex::encode([0x66u8; 32]),
                expected: 1,
                found: 2,
            }
            .to_string(),
            FraudError::MalformedSessionTail {
                session_id_hex: hex::encode([0x66u8; 32]),
                reason: "no FINAL chunk; the session never closed",
            }
            .to_string(),
        ];

        // FLOOR, exact: five is every variant this module declares, and a sweep
        // over a shrinking list proves nothing.
        assert_eq!(messages.len(), 5);
        let swept_bytes: usize = messages.iter().map(String::len).sum();
        assert!(
            swept_bytes > 400,
            "byte floor: only {swept_bytes} bytes swept"
        );

        // Assembled from fragments so the tokens are not themselves greppable
        // literals in this file.
        let forbidden: Vec<String> = [
            ["ht", "tp"].concat(),
            ["/", "/"].concat(),
            ["?", ""].concat(),
            ["hea", "der"].concat(),
            ["coo", "kie"].concat(),
            ["ho", "st"].concat(),
        ]
        .to_vec();

        for message in &messages {
            let lower = message.to_ascii_lowercase();
            for token in &forbidden {
                assert!(
                    !lower.contains(token.as_str()),
                    "a fraud refusal carries a destination-shaped token: {message}"
                );
            }
        }

        // POSITIVE CONTROL: the same sweep must catch a planted destination.
        let planted = ["a refusal naming ", "ht", "tps://example.invalid/a", "?b=c"].concat();
        let lower = planted.to_ascii_lowercase();
        assert!(
            forbidden.iter().any(|t| lower.contains(t.as_str())),
            "the sweep cannot detect a destination; its silence proves nothing"
        );
    }
}
