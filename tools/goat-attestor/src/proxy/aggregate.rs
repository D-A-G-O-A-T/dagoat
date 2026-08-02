//! Folding verified receipts into one leaf per operator per epoch, and the split.
//!
//! # Supply is constant here
//!
//! Every wei allocated in this module comes out of a **pre-funded pool of
//! already-existing GOAT**, bounded on chain against realized consumer
//! settlement. Nothing here increases supply and nothing here decreases it.
//! There is no supply-destroying split, no such parameter and no such event —
//! not deferred and not set to zero, but absent, so that no later governance
//! call can enable one.
//!
//! # Rounding, in one place
//!
//! [`gross_for_session`] floors once per **session**, because the price is a
//! field of the consumer-signed intent and is constant only within a session.
//! The 90/10 split floors the operator share and computes the protocol share by
//! **subtraction**, so `operator + protocol == gross` is an identity rather than
//! a coincidence. The remainder therefore lands on the protocol, which is the
//! direction that points toward solvency: an extra wei to an operator is an
//! extra wei the pool must cover, and across thousands of operators that is a
//! systematic overdraft; an extra wei to the protocol is a systematic
//! underspend, which is safe.
//!
//! The dust the `gross` floor discards is credited to nobody and stays in the
//! pool as unallocated balance. `Σ gross_i ≤ funded − reserve` therefore holds
//! *a fortiori*, and the conservation claim this module tests is exact: nothing
//! is created, and the only thing "lost" is never allocated in the first place.
//!
//! # Two unit systems, reconciled once
//!
//! A receipt prices bytes in **wei per mebibyte**
//! (`price_goat_wei_per_mebibyte`), because the chunk rule is a mebibyte rule.
//! [`super::proxy_merkle::gross_for_bytes`] prices them in **wei per gibibyte**,
//! because the operator-facing daily ceiling is a gibibyte band. The two are not
//! interchangeable and swapping them silently divides every operator's share by
//! 1024 — a loss no strict-equality challenger can see, because it compares
//! bytes and chunk counts and never value.
//!
//! So the conversion is a named function, [`price_goat_wei_per_gibibyte`], and
//! the identity it makes exact is
//! `gross_for_session(b, p) == gross_for_bytes(b, p * 1024)` for every `b` and
//! every `p` — exact because [`MEBIBYTES_PER_GIBIBYTE`] is 1024 and both
//! denominators are powers of two, so the multiplication moves no bit into the
//! floor. `a_mebibyte_price_and_a_gibibyte_rate_value_the_same_bytes_identically`
//! asserts both the identity and the 1024× shape of the confusion.
//!
//! # Two widths, reconciled once
//!
//! A stored receipt's `bytes_transferred` is a `u64` read back from a **signed**
//! 64-bit SQLite column; a [`SessionTotal`]'s `total_bytes` and a gateway meter
//! session's are `u128`. Folding receipts into sessions therefore crosses a
//! width in the widening direction, which is done with `u128::from` and never
//! with `as` — an `as` cast here is silent on the day it is wrong.
//!
//! The narrowing direction is the one that loses value, and it is not performed
//! at all: [`storable_byte_total`] *refuses* a total above [`MAX_STORABLE_BYTES`]
//! with a named error instead of truncating it into the column. That mirrors the
//! store's own `ValueOutOfRange` refusal one layer earlier, where the number is
//! still attributable to an operator.

use std::collections::BTreeMap;

use thiserror::Error;

use super::challenger::SessionTotal;
use super::fraud::{
    check_cluster_byte_ceiling, check_pair_concentration, check_session_chunk_sequences, FraudError,
};
use super::proxy_merkle::{is_proxy_epoch, ProxyLeaf, ProxyMerkleTree, GIB_BYTES};
use super::store::StoredReceipt;

/// Re-exported, never re-declared. Two declarations of one policy number in one
/// crate is exactly the drift that moves value with every test still green; the
/// declarations live beside the other lane bands in [`super`].
pub use super::{BPS_DENOM, MAX_TAKE_BPS, MIN_TAKE_BPS};

/// One mebibyte, in the width the settlement arithmetic runs in.
///
/// Derived from [`super::MIB_BYTES`] rather than written again: `as` here is a
/// widening `u64 -> u128` in a `const`, which cannot lose a bit, and `u128::from`
/// is not available in const context.
pub const MEBIBYTE: u128 = super::MIB_BYTES as u128;

/// The whole of the difference between the receipt's unit and the metering
/// unit — one thousand and twenty-four — computed from the two denominators so
/// it cannot drift from either.
pub const MEBIBYTES_PER_GIBIBYTE: u128 = GIB_BYTES / MEBIBYTE;

/// The widest byte total that can be written back into the receipt store.
///
/// SQLite's INTEGER is signed 64-bit, so `proxy_epoch_totals.total_bytes` and
/// `proxy_receipts.bytes_transferred` stop here. A total above it is refused by
/// [`storable_byte_total`] rather than truncated.
pub const MAX_STORABLE_BYTES: u128 = i64::MAX as u128;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AggregateError {
    #[error("Overflow: {what}")]
    Overflow { what: &'static str },
    #[error("TakeOutOfBand: {bps} bps is outside {MIN_TAKE_BPS}..={MAX_TAKE_BPS}")]
    TakeOutOfBand { bps: u32 },
    #[error("MalformedSessionId: {hex} is not 32 bytes of hex")]
    MalformedSessionId { hex: String },
    #[error("MalformedOperatorWallet: {hex} is not 20 bytes of hex")]
    MalformedOperatorWallet { hex: String },
    #[error(
        "SessionOperatorMismatch: session 0x{session_id_hex} is attributed to two different \
         operators by its own receipts"
    )]
    SessionOperatorMismatch { session_id_hex: String },
    #[error("MissingSessionPrice: session 0x{session_id_hex} has no priced receipt; refused, never zero")]
    MissingSessionPrice { session_id_hex: String },
    #[error("EpochNotInProxySpace: {epoch_id}")]
    EpochNotInProxySpace { epoch_id: u64 },
    #[error(
        "PoolWouldBeOverdrawn: gross {gross} exceeds allocatable {allocatable} \
         (funded {funded} - reserve {reserve}); refused, never clamped"
    )]
    PoolWouldBeOverdrawn {
        gross: u128,
        allocatable: u128,
        funded: u128,
        reserve: u128,
    },
    #[error("OperatorOverByteCeiling: 0x{operator} claims {claimed} bytes, ceiling {ceiling}")]
    OperatorOverByteCeiling {
        operator: String,
        claimed: u128,
        ceiling: u128,
    },
    #[error(
        "ByteTotalNotStorable: 0x{operator} totals {total_bytes} bytes, above the store's \
         {MAX_STORABLE_BYTES}; refused, never truncated"
    )]
    ByteTotalNotStorable { operator: String, total_bytes: u128 },
    #[error(
        "InconsistentSplit: 0x{operator} carries gross {gross}, operator share {payout} and \
         protocol share {protocol}, which is not the {take_bps} bps split of that gross"
    )]
    InconsistentSplit {
        operator: String,
        gross: u128,
        payout: u128,
        protocol: u128,
        take_bps: u32,
    },
    #[error(
        "DuplicateOperator: 0x{operator} appears in two totals; the settlement records one claim \
         per operator per epoch, so the second leaf could never be claimed"
    )]
    DuplicateOperator { operator: String },
    #[error("EvidenceNotCanonical: {detail}")]
    EvidenceNotCanonical { detail: String },
    #[error("EmptyBatch")]
    EmptyBatch,
    /// The anti-fraud lane's refusal, surfaced verbatim.
    ///
    /// Task 15 could not declare this variant — `super::fraud` did not exist
    /// yet and a `#[from]` on a missing type does not compile — so the module
    /// shipped with the per-epoch controls unwired. It is declared here, and
    /// [`build_proxy_epoch_batch`] runs those controls **before** the pool
    /// inequality, so a fraudulent batch is refused as fraud rather than as an
    /// overdraft. The two refusals point at different people: an overdraft is
    /// the funder's problem, a concentration breach is the pair's, and
    /// reporting the wrong one sends the investigation to the wrong place.
    #[error("fraud: {0}")]
    Fraud(#[from] FraudError),
}

/// Everything the per-epoch fraud controls need that [`OperatorEpochTotal`]
/// does not carry: the rows the sequence rule reads, the session-level view the
/// concentration cap is computed over, the two registry lookups, and the two
/// policy bounds.
///
/// It is a **required** parameter of [`build_proxy_epoch_batch`] and there is
/// deliberately no second entry point that skips it. A control the caller can
/// decline by calling a different function is not a control; that is the same
/// reasoning that keeps `super::store` accepting only a `VerifiedReceipt`.
///
/// `root_of` answers `None` for an identity the sponsorship registry does not
/// know, and every control here treats that as "its own cluster of one" rather
/// than as a finding — the same absence-of-evidence posture the per-bundle
/// self-dealing stage takes.
pub struct EpochFraudControls<'a> {
    /// The epoch's stored receipts, one group per session. Held to
    /// `super::fraud::check_session_chunk_sequences`.
    pub receipts: &'a [StoredReceipt],
    /// The challenger-agreed per-session view, which the concentration cap is
    /// computed over.
    pub sessions: &'a [SessionTotal],
    /// Session id -> the consumer that session belongs to. The concentration
    /// cap's **denominator** is the consumer's epoch bytes.
    pub consumer_of: &'a dyn Fn(&[u8; 32]) -> [u8; 32],
    /// Operator wallet -> its `WalletSponsorshipRegistry` cluster root. Every
    /// bound here is folded onto the root before it is compared, because a
    /// per-address bound is free to defeat with a second wallet.
    pub root_of: &'a dyn Fn([u8; 20]) -> Option<[u8; 20]>,
    /// Per-epoch byte ceiling, applied to the **cluster**, not the address.
    pub cluster_byte_ceiling: u128,
    /// Per-`(consumer, operator cluster)` concentration cap, in basis points.
    ///
    /// The configured default behind this is a **starting value pending founder
    /// review**, not a ratified policy number; the band it must fall inside is
    /// [`super::MIN_PAIR_CONCENTRATION_BPS`] ..=
    /// [`super::MAX_PAIR_CONCENTRATION_BPS`].
    pub pair_concentration_cap_bps: u32,
}

/// One operator's whole epoch, which becomes exactly one Merkle leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorEpochTotal {
    pub operator: [u8; 20],
    pub total_bytes: u128,
    pub receipt_count: u64,
    pub gross_goat_wei: u128,
    pub payout_goat_wei: u128,
    pub protocol_goat_wei: u128,
}

impl OperatorEpochTotal {
    /// `#[doc(hidden)] pub`, not `#[cfg(test)]`: the lane's integration tests
    /// build these, and an integration test compiles against the library
    /// without `cfg(test)`.
    #[doc(hidden)]
    pub fn for_test(
        operator: [u8; 20],
        total_bytes: u128,
        receipt_count: u64,
        payout: u128,
        protocol: u128,
    ) -> Self {
        Self {
            operator,
            total_bytes,
            receipt_count,
            gross_goat_wei: payout + protocol,
            payout_goat_wei: payout,
            protocol_goat_wei: protocol,
        }
    }

    /// The byte total narrowed to the store's column width, or a refusal.
    pub fn storable_total_bytes(&self) -> Result<u64, AggregateError> {
        storable_byte_total(self.operator, self.total_bytes)
    }
}

#[derive(Debug, Clone)]
pub struct ProxyEpochBatch {
    pub epoch_id: u64,
    pub leaves: Vec<ProxyLeaf>,
    pub merkle_root: [u8; 32],
    pub merkle_root_hex: String,
    pub evidence_ref: [u8; 32],
    pub total_gross_goat_wei: u128,
    pub total_payout_goat_wei: u128,
    pub total_protocol_goat_wei: u128,
    pub funded_goat_wei: u128,
    pub reserve_goat_wei: u128,
}

/// `floor(total_bytes * price / MEBIBYTE)`. Floored once, per session.
///
/// Multiplies before dividing. The other order truncates every sub-mebibyte
/// session to zero, and a settlement that values real bytes moved at nothing is
/// a defect no test of the Merkle tree would ever catch.
pub fn gross_for_session(
    total_bytes: u128,
    price_goat_wei_per_mebibyte: u128,
) -> Result<u128, AggregateError> {
    total_bytes
        .checked_mul(price_goat_wei_per_mebibyte)
        .map(|p| p / MEBIBYTE)
        .ok_or(AggregateError::Overflow {
            what: "bytes * price",
        })
}

/// The receipt's per-mebibyte price expressed in the metering lane's
/// per-gibibyte unit.
///
/// The bridge between the two unit systems, written once so that no caller
/// spells `* 1024` by hand and no caller forgets it. See the module docs.
pub fn price_goat_wei_per_gibibyte(
    price_goat_wei_per_mebibyte: u128,
) -> Result<u128, AggregateError> {
    price_goat_wei_per_mebibyte
        .checked_mul(MEBIBYTES_PER_GIBIBYTE)
        .ok_or(AggregateError::Overflow {
            what: "price per mebibyte -> price per gibibyte",
        })
}

/// `(operator, protocol)`. Protocol is a subtraction, so no wei is created or
/// destroyed and the remainder always lands on the protocol.
///
/// The operator expression is the settlement contract's own
/// `(grossGoatWei * OPERATOR_BPS) / BPS_DENOM`, wei for wei — which is what
/// `ProxyRevenueSettlement.claim` bounds the sum of leaf payouts by, so a
/// disagreement here is a batch every operator's proof is refused against.
pub fn split_gross(
    gross_goat_wei: u128,
    protocol_take_bps: u32,
) -> Result<(u128, u128), AggregateError> {
    if !(MIN_TAKE_BPS..=MAX_TAKE_BPS).contains(&protocol_take_bps) {
        return Err(AggregateError::TakeOutOfBand {
            bps: protocol_take_bps,
        });
    }
    let operator_bps = u128::from(BPS_DENOM - protocol_take_bps);
    let operator = gross_goat_wei
        .checked_mul(operator_bps)
        .ok_or(AggregateError::Overflow {
            what: "gross * operator_bps",
        })?
        / u128::from(BPS_DENOM);
    let protocol = gross_goat_wei - operator;
    Ok((operator, protocol))
}

pub fn check_operator_byte_ceiling(
    operator: [u8; 20],
    claimed: u128,
    ceiling: u128,
) -> Result<(), AggregateError> {
    if claimed > ceiling {
        return Err(AggregateError::OperatorOverByteCeiling {
            operator: hex::encode(operator),
            claimed,
            ceiling,
        });
    }
    Ok(())
}

/// Narrow a byte total into the store's signed 64-bit column, or refuse.
///
/// Never `as`. The store's own `ValueOutOfRange` catches this one layer later,
/// by which point the number is a bind parameter and no longer attributable to
/// an operator; this refusal names the operator.
pub fn storable_byte_total(operator: [u8; 20], total_bytes: u128) -> Result<u64, AggregateError> {
    if total_bytes > MAX_STORABLE_BYTES {
        return Err(AggregateError::ByteTotalNotStorable {
            operator: hex::encode(operator),
            total_bytes,
        });
    }
    u64::try_from(total_bytes).map_err(|_| AggregateError::ByteTotalNotStorable {
        operator: hex::encode(operator),
        total_bytes,
    })
}

/// `hex` -> a fixed-width array, accepting the bare and the `0x`-prefixed form.
///
/// The store writes `hex::encode(..)` bare and the receipt module writes the
/// prefixed form, so both reach this lane.
fn decode_fixed<const N: usize>(raw: &str) -> Option<[u8; N]> {
    hex::decode(raw.trim_start_matches("0x"))
        .ok()
        .and_then(|v| <[u8; N]>::try_from(v.as_slice()).ok())
}

/// A TYPED REFUSAL, not a panic. `session_id_hex` is a `String` read back from
/// SQLite; `copy_from_slice(&decode(..).unwrap_or_default())` panics on every
/// malformed value, because the fallback is an EMPTY `Vec` whose length can
/// never be 32 — so the "safe" unwrap guaranteed the crash it looked like it was
/// preventing. This is the path that produces the on-chain root.
fn decode_session_id(raw: &str) -> Result<[u8; 32], AggregateError> {
    decode_fixed::<32>(raw).ok_or_else(|| AggregateError::MalformedSessionId {
        hex: raw.to_string(),
    })
}

fn decode_operator(raw: &str) -> Result<[u8; 20], AggregateError> {
    decode_fixed::<20>(raw).ok_or_else(|| AggregateError::MalformedOperatorWallet {
        hex: raw.to_string(),
    })
}

/// Fold stored receipts into the proposer's per-session view.
///
/// This is the function [`SessionTotal`]'s own doc comment names ("folded from
/// stored receipts") and the one that crosses the `u64 -> u128` width. The
/// widening is `u128::from`; the total is then held to the store's own ceiling
/// so a value that could not be written back is refused here, named, rather than
/// truncated later.
///
/// Ordering is by session id, so two proposers handed the same receipts in
/// different orders produce the same document.
pub fn fold_session_totals(
    receipts: &[StoredReceipt],
) -> Result<Vec<SessionTotal>, AggregateError> {
    let mut by_session: BTreeMap<[u8; 32], SessionTotal> = BTreeMap::new();

    for r in receipts {
        let session_id = decode_session_id(&r.session_id_hex)?;
        let operator = decode_operator(&r.operator_wallet)?;
        let entry = by_session.entry(session_id).or_insert(SessionTotal {
            session_id,
            operator,
            total_bytes: 0,
            chunk_count: 0,
        });
        // Last-write-wins on the operator would let one forged chunk
        // re-attribute a whole session, and the strict-equality challenger
        // would then challenge the honest proposer.
        if entry.operator != operator {
            return Err(AggregateError::SessionOperatorMismatch {
                session_id_hex: hex::encode(session_id),
            });
        }
        // THE WIDENING, and the only one: `u128::from`, never `as`.
        entry.total_bytes = entry
            .total_bytes
            .checked_add(u128::from(r.bytes_transferred))
            .ok_or(AggregateError::Overflow {
                what: "session total_bytes",
            })?;
        entry.chunk_count = entry
            .chunk_count
            .checked_add(1)
            .ok_or(AggregateError::Overflow {
                what: "session chunk_count",
            })?;
    }

    for s in by_session.values() {
        storable_byte_total(s.operator, s.total_bytes)?;
    }
    Ok(by_session.into_values().collect())
}

/// Fold stored receipts into one total per operator. `session_totals` is the
/// challenger-agreed per-session view; receipts supply the per-session price.
pub fn fold_operator_totals(
    receipts: &[StoredReceipt],
    session_totals: &[SessionTotal],
    protocol_take_bps: u32,
    byte_ceiling: u128,
) -> Result<Vec<OperatorEpochTotal>, AggregateError> {
    // Price per session, taken from the receipts (all receipts of a session
    // carry the same intent, hence the same price — enforced by verify stage 5).
    let mut price: BTreeMap<[u8; 32], u128> = BTreeMap::new();
    let mut counts: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for r in receipts {
        let id = decode_session_id(&r.session_id_hex)?;
        price.insert(id, r.price_goat_wei_per_mebibyte);
        let c = counts.entry(id).or_insert(0);
        *c = c.checked_add(1).ok_or(AggregateError::Overflow {
            what: "receipts per session",
        })?;
    }

    let mut per_operator: BTreeMap<[u8; 20], OperatorEpochTotal> = BTreeMap::new();
    for s in session_totals {
        // A session with no priced receipt is an inconsistency, not a free
        // session. `unwrap_or(0)` prices it at zero and silently under-values
        // the operator — which the strict-equality challenger cannot detect,
        // because it compares bytes and chunk counts and never value.
        let p = *price
            .get(&s.session_id)
            .ok_or_else(|| AggregateError::MissingSessionPrice {
                session_id_hex: hex::encode(s.session_id),
            })?;
        let gross = gross_for_session(s.total_bytes, p)?;
        let entry = per_operator
            .entry(s.operator)
            .or_insert(OperatorEpochTotal {
                operator: s.operator,
                total_bytes: 0,
                receipt_count: 0,
                gross_goat_wei: 0,
                payout_goat_wei: 0,
                protocol_goat_wei: 0,
            });
        entry.total_bytes =
            entry
                .total_bytes
                .checked_add(s.total_bytes)
                .ok_or(AggregateError::Overflow {
                    what: "operator total_bytes",
                })?;
        entry.receipt_count = entry
            .receipt_count
            .checked_add(counts.get(&s.session_id).copied().unwrap_or(0))
            .ok_or(AggregateError::Overflow {
                what: "operator receipt_count",
            })?;
        entry.gross_goat_wei =
            entry
                .gross_goat_wei
                .checked_add(gross)
                .ok_or(AggregateError::Overflow {
                    what: "operator gross",
                })?;
    }

    let mut out = Vec::with_capacity(per_operator.len());
    for mut t in per_operator.into_values() {
        check_operator_byte_ceiling(t.operator, t.total_bytes, byte_ceiling)?;
        storable_byte_total(t.operator, t.total_bytes)?;
        let (payout, protocol) = split_gross(t.gross_goat_wei, protocol_take_bps)?;
        t.payout_goat_wei = payout;
        t.protocol_goat_wei = protocol;
        out.push(t);
    }
    Ok(out)
}

pub fn build_proxy_epoch_batch(
    epoch_id: u64,
    totals: Vec<OperatorEpochTotal>,
    controls: &EpochFraudControls<'_>,
    funded_goat_wei: u128,
    reserve_goat_wei: u128,
    protocol_take_bps: u32,
) -> Result<ProxyEpochBatch, AggregateError> {
    if !is_proxy_epoch(epoch_id) {
        return Err(AggregateError::EpochNotInProxySpace { epoch_id });
    }
    if totals.is_empty() {
        return Err(AggregateError::EmptyBatch);
    }
    if !(MIN_TAKE_BPS..=MAX_TAKE_BPS).contains(&protocol_take_bps) {
        return Err(AggregateError::TakeOutOfBand {
            bps: protocol_take_bps,
        });
    }

    // Every total is re-derived from its own gross at the declared take before
    // it is allowed to become a leaf. Without this the three money fields are
    // whatever the caller wrote, and a leaf carrying the GROSS — the one edit
    // that hands the operator the protocol's share as well — is indistinguishable
    // from a correct one at this layer.
    let mut seen: BTreeMap<[u8; 20], ()> = BTreeMap::new();
    for t in &totals {
        if seen.insert(t.operator, ()).is_some() {
            return Err(AggregateError::DuplicateOperator {
                operator: hex::encode(t.operator),
            });
        }
        let (payout, protocol) = split_gross(t.gross_goat_wei, protocol_take_bps)?;
        if t.payout_goat_wei != payout
            || t.protocol_goat_wei != protocol
            || payout
                .checked_add(protocol)
                .ok_or(AggregateError::Overflow { what: "split sum" })?
                != t.gross_goat_wei
        {
            return Err(AggregateError::InconsistentSplit {
                operator: hex::encode(t.operator),
                gross: t.gross_goat_wei,
                payout: t.payout_goat_wei,
                protocol: t.protocol_goat_wei,
                take_bps: protocol_take_bps,
            });
        }
    }

    // FRAUD BEFORE SOLVENCY. Ordered deliberately, and
    // `a_fraudulent_batch_is_refused_as_fraud_before_it_is_refused_as_an_overdraft`
    // proves the order observably rather than asserting about it. A batch built
    // out of self-dealt or wash traffic that also happens to exceed the pool
    // must report the fraud: an overdraft reads as "the funder deposited too
    // little", which is the wrong instruction to hand an investigator.
    //
    // All three bounds fold onto the sponsorship cluster root, so N identities
    // under one household share one ceiling and one concentration cap.
    check_session_chunk_sequences(controls.receipts)?;
    check_cluster_byte_ceiling(&totals, controls.root_of, controls.cluster_byte_ceiling)?;
    check_pair_concentration(
        controls.sessions,
        controls.consumer_of,
        controls.root_of,
        controls.pair_concentration_cap_bps,
    )?;

    let mut total_gross: u128 = 0;
    let mut total_payout: u128 = 0;
    let mut total_protocol: u128 = 0;
    for t in &totals {
        total_gross =
            total_gross
                .checked_add(t.gross_goat_wei)
                .ok_or(AggregateError::Overflow {
                    what: "epoch gross",
                })?;
        total_payout =
            total_payout
                .checked_add(t.payout_goat_wei)
                .ok_or(AggregateError::Overflow {
                    what: "epoch operator share",
                })?;
        total_protocol =
            total_protocol
                .checked_add(t.protocol_goat_wei)
                .ok_or(AggregateError::Overflow {
                    what: "epoch protocol share",
                })?;
    }

    let allocatable = funded_goat_wei.saturating_sub(reserve_goat_wei);
    if total_gross > allocatable {
        return Err(AggregateError::PoolWouldBeOverdrawn {
            gross: total_gross,
            allocatable,
            funded: funded_goat_wei,
            reserve: reserve_goat_wei,
        });
    }

    let leaves: Vec<ProxyLeaf> = totals
        .iter()
        .map(|t| ProxyLeaf {
            operator: t.operator,
            epoch_id,
            total_bytes: t.total_bytes,
            payout_goat_wei: t.payout_goat_wei,
        })
        .collect();
    let tree = ProxyMerkleTree::build(leaves.clone());

    // The evidence ref is the keccak of the CANONICAL bytes, not of a
    // pretty-printed serde rendering. The compute lane hashes `to_vec_pretty`
    // output, which makes its on-chain evidence ref depend on a pretty-printer;
    // this lane does not repeat that.
    let evidence = serde_json::json!({
        "schemaId": "GOAT_PROXY_EPOCH_EVIDENCE_V1",
        "epochId": epoch_id.to_string(),
        "merkleRoot": tree.root_hex(),
        "totalGrossGoatWei": total_gross.to_string(),
        "totalPayoutGoatWei": total_payout.to_string(),
        "totalProtocolGoatWei": total_protocol.to_string(),
        "fundedGoatWei": funded_goat_wei.to_string(),
        "reserveGoatWei": reserve_goat_wei.to_string(),
    });
    let evidence_ref = crate::canonical_json::canonical_hash(&evidence).map_err(|e| {
        AggregateError::EvidenceNotCanonical {
            detail: e.to_string(),
        }
    })?;

    Ok(ProxyEpochBatch {
        epoch_id,
        leaves,
        merkle_root: tree.root(),
        merkle_root_hex: tree.root_hex(),
        evidence_ref,
        total_gross_goat_wei: total_gross,
        total_payout_goat_wei: total_payout,
        total_protocol_goat_wei: total_protocol,
        funded_goat_wei,
        reserve_goat_wei,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::proxy_merkle::{gross_for_bytes, proxy_leaf_hash};
    use crate::proxy::receipt::ChunkKind;
    use std::path::{Path, PathBuf};

    /// The sample epoch every pinned vector in this lane is about, and the one
    /// `ProxyRevenueMerkleParity.t.sol` pins on the Solidity side.
    const SAMPLE_EPOCH: u64 = 8_000_000_020_664;

    /// Fraud controls that bind on nothing, for the arithmetic tests.
    ///
    /// Every field is deliberately wide open rather than absent: there is no
    /// `Option` and no "skip the checks" flag in [`EpochFraudControls`], so a
    /// test that is about the split has to say, in the call itself, that it is
    /// not exercising the fraud lane. The fraud lane's own behaviour is proved
    /// by `super::super::fraud`'s unit tests and by
    /// `a_fraudulent_batch_is_refused_as_fraud_before_it_is_refused_as_an_overdraft`
    /// below, which builds real controls.
    ///
    /// No receipts and no sessions means the sequence rule and the concentration
    /// cap have nothing to look at; `u128::MAX` bytes and a `BPS_DENOM` cap are
    /// bounds no total in this file can reach. None of it touches a wei.
    fn open_controls() -> EpochFraudControls<'static> {
        static IDENTITY_ROOT: fn([u8; 20]) -> Option<[u8; 20]> = |w| Some(w);
        static ONE_CONSUMER: fn(&[u8; 32]) -> [u8; 32] = |_| [0u8; 32];
        EpochFraudControls {
            receipts: &[],
            sessions: &[],
            consumer_of: &ONE_CONSUMER,
            root_of: &IDENTITY_ROOT,
            cluster_byte_ceiling: u128::MAX,
            pair_concentration_cap_bps: BPS_DENOM,
        }
    }

    fn stored_receipt(session_id: [u8; 32], price: u128) -> StoredReceipt {
        StoredReceipt {
            receipt_hash_hex: hex::encode([0x01; 32]),
            epoch_id: SAMPLE_EPOCH,
            session_id_hex: hex::encode(session_id),
            chunk_seq: 0,
            operator_wallet: hex::encode([0x99; 20]),
            consumer_id_hex: hex::encode([0x77; 32]),
            bytes_transferred: 1_048_576,
            chunk_kind: ChunkKind::Final,
            gateway_id_hex: hex::encode([0x66; 32]),
            price_goat_wei_per_mebibyte: price,
        }
    }

    fn repo_root() -> PathBuf {
        let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        crate_dir
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or(crate_dir)
    }

    /// The Solidity side of a cross-language pin, read at RUN time.
    ///
    /// `include_str!` is not used: this package is its own workspace and the
    /// sibling `contracts/` tree is outside the Docker build context, so every
    /// other `include_str!` in this crate stays inside the package. A missing
    /// file is a hard failure rather than a skip — a skipped parity check and a
    /// passing one are indistinguishable in a log.
    fn read_contract_source(rel: &str) -> String {
        let path = repo_root().join(rel);
        std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "the cross-language pin must read the real Solidity source at {}: {e}",
                path.display()
            )
        })
    }

    /// The declaration line's tail, for `<...> constant <NAME> = <value>;`.
    fn sol_constant_value<'a>(src: &'a str, name: &str) -> Option<&'a str> {
        for raw in src.lines() {
            let line = raw.trim();
            let Some(pos) = line.find("constant ") else {
                continue;
            };
            let Some(after) = line[pos + "constant ".len()..].strip_prefix(name) else {
                continue;
            };
            // Guard against a longer name that merely starts with this one:
            // `TAKE_BPS` must not match a `TAKE_BPS_X` declaration.
            let Some(value) = after.trim_start().strip_prefix('=') else {
                continue;
            };
            return Some(value.trim().trim_end_matches(';').trim());
        }
        None
    }

    /// `uint16 public constant OPERATOR_BPS = 9_000;` -> `9000`.
    fn sol_uint_constant(src: &str, name: &str) -> Option<u128> {
        let value = sol_constant_value(src, name)?;
        if value.starts_with("0x") || !value.starts_with(|c: char| c.is_ascii_digit()) {
            return None;
        }
        value
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '_')
            .filter(|c| *c != '_')
            .collect::<String>()
            .parse()
            .ok()
    }

    /// `bytes32 constant LEAF_A = 0x231e...;` -> the 32 bytes.
    fn sol_bytes32_constant(src: &str, name: &str) -> Option<[u8; 32]> {
        let value = sol_constant_value(src, name)?.strip_prefix("0x")?;
        <[u8; 32]>::try_from(hex::decode(value).ok()?.as_slice()).ok()
    }

    /// `address constant OP_A = address(uint160(0xA1));` -> the 20 bytes.
    fn sol_address_constant(src: &str, name: &str) -> Option<[u8; 20]> {
        let value = sol_constant_value(src, name)?;
        let start = value.find("0x")? + 2;
        let digits: String = value[start..]
            .chars()
            .take_while(|c| c.is_ascii_hexdigit() || *c == '_')
            .filter(|c| *c != '_')
            .collect();
        let n = u128::from_str_radix(&digits, 16).ok()?;
        let mut out = [0u8; 20];
        out[4..].copy_from_slice(&n.to_be_bytes());
        Some(out)
    }

    /// The conservation identity, proved exhaustively over the residue class
    /// that can produce a remainder rather than over three lucky samples, and
    /// over the whole configured take band rather than one point in it.
    ///
    /// Mutations this detects:
    /// - computing `protocol` as a second `floor(gross * take / DENOM)`, which
    ///   destroys a wei on every non-divisible gross
    /// - giving the remainder to the operator, which creates a wei the pool may
    ///   not hold (caught by the `gross * 9 / 10` equality, which conservation
    ///   alone would not see)
    /// - swapping the two shares
    /// - rounding the operator share up
    #[test]
    fn the_ninety_ten_split_creates_and_destroys_no_wei() {
        for gross in 0u128..=20_000 {
            let (operator, protocol) = split_gross(gross, 1_000).expect("no overflow");
            assert_eq!(
                operator + protocol,
                gross,
                "conservation failed at gross={gross}: {operator} + {protocol}"
            );
            assert_eq!(
                operator,
                gross * 9 / 10,
                "operator share must be floor(90%)"
            );
            assert!(
                protocol >= gross / 10,
                "the protocol absorbs the remainder, never the operator"
            );
        }

        // Every take the band admits, not only its top. A remainder exists for
        // some gross at every one of them.
        for bps in MIN_TAKE_BPS..=MAX_TAKE_BPS {
            for gross in 0u128..=2_000 {
                let (operator, protocol) = split_gross(gross, bps).expect("no overflow");
                assert_eq!(
                    operator + protocol,
                    gross,
                    "conservation failed at gross={gross}, take={bps}"
                );
                assert_eq!(
                    operator,
                    gross * u128::from(BPS_DENOM - bps) / u128::from(BPS_DENOM),
                    "the operator share is a floor of the configured complement"
                );
                assert!(
                    protocol >= gross * u128::from(bps) / u128::from(BPS_DENOM),
                    "the protocol must never receive less than its floored share"
                );
            }
        }

        // ONE WEI, called out: the smallest amount that can carry a remainder.
        // The operator's floored 90% of 1 wei is 0, so the protocol takes the
        // whole wei. Rounding the other way would hand the operator 111% of the
        // configured share.
        assert_eq!(split_gross(1, 1_000).expect("ok"), (0, 1));
        assert_eq!(split_gross(9, 1_000).expect("ok"), (8, 1));
        // …and a gross that divides EXACTLY leaves no remainder to place.
        assert_eq!(split_gross(10, 1_000).expect("ok"), (9, 1));
        assert_eq!(split_gross(10_000, 1_000).expect("ok"), (9_000, 1_000));
        assert_eq!(split_gross(0, 1_000).expect("ok"), (0, 0));

        // A large, deliberately non-divisible value, to prove it is not a
        // small-number artefact.
        let gross = 1_000_000_000_000_000_007u128;
        let (o, p) = split_gross(gross, 1_000).expect("no overflow");
        assert_eq!(o + p, gross);
        assert_eq!(p, gross - (gross * 9_000 / 10_000));

        // The widest gross the arithmetic admits still conserves: `gross *
        // 9_000` must not wrap. `u128::MAX` does overflow, and that is a typed
        // refusal rather than a wrapped share.
        let widest = u128::MAX / 9_000;
        let (o, p) = split_gross(widest, 1_000).expect("must not overflow");
        assert_eq!(o + p, widest);
        assert!(matches!(
            split_gross(u128::MAX, 1_000),
            Err(AggregateError::Overflow { .. })
        ));
    }

    /// Mutations this detects: applying the take twice; reading the take from a
    /// hard-coded constant instead of the configured value; accepting a take
    /// outside the band at the arithmetic layer.
    ///
    /// The band is the "The No-Ponzi Invariant — GoatCoin's load-bearing
    /// economic rule" spec, §8's LAUNCH band (800..=1000), not its ~15% hard
    /// ceiling. An earlier draft set `MAX_TAKE_BPS = 1_500`, which made 15% a
    /// routine config value: with the on-chain take immutable at 1000 and
    /// nothing comparing the two, a config edit would silently move 5% of gross
    /// from operators to the treasury with every test green.
    #[test]
    fn the_split_honours_the_configured_take_and_refuses_an_out_of_band_take() {
        let gross = 1_000_000u128;
        assert_eq!(split_gross(gross, 1_000).expect("ok"), (900_000, 100_000));
        assert_eq!(split_gross(gross, 800).expect("ok"), (920_000, 80_000));
        assert_eq!(split_gross(gross, 900).expect("ok"), (910_000, 90_000));
        assert!(matches!(
            split_gross(gross, 0),
            Err(AggregateError::TakeOutOfBand { .. })
        ));
        assert!(matches!(
            split_gross(gross, 799),
            Err(AggregateError::TakeOutOfBand { .. })
        ));
        assert!(matches!(
            split_gross(gross, 1_001),
            Err(AggregateError::TakeOutOfBand { .. })
        ));
        assert!(matches!(
            split_gross(gross, 1_500),
            Err(AggregateError::TakeOutOfBand { .. })
        ));
        assert_eq!(MIN_TAKE_BPS, 800);
        assert_eq!(MAX_TAKE_BPS, 1_000);
        assert_eq!(BPS_DENOM, 10_000);
    }

    /// Mutations this detects: `copy_from_slice` on an attacker-influenced hex
    /// string (a panic on the aggregation path that produces the on-chain root),
    /// and a session with no priced receipt being valued at zero — an
    /// under-payment the strict-equality challenger cannot see, because it
    /// compares bytes and chunk counts, never value.
    #[test]
    fn a_malformed_session_id_is_an_error_and_a_missing_price_is_not_zero() {
        let mut bad = stored_receipt([0x11; 32], 1_000);
        bad.session_id_hex = "not-hex".into();
        assert!(matches!(
            fold_operator_totals(&[bad], &[], 1_000, u128::MAX),
            Err(AggregateError::MalformedSessionId { .. })
        ));

        let mut short = stored_receipt([0x11; 32], 1_000);
        short.session_id_hex = "aabb".into(); // 2 bytes, not 32
        assert!(matches!(
            fold_operator_totals(&[short], &[], 1_000, u128::MAX),
            Err(AggregateError::MalformedSessionId { .. })
        ));

        // A session the receipts never priced must be refused, never valued at
        // zero.
        let orphan = SessionTotal {
            session_id: [0x99; 32],
            operator: [0xA1; 20],
            total_bytes: 1_048_576,
            chunk_count: 1,
        };
        assert!(matches!(
            fold_operator_totals(&[], std::slice::from_ref(&orphan), 1_000, u128::MAX),
            Err(AggregateError::MissingSessionPrice { .. })
        ));

        // POSITIVE CONTROL: a well-formed pair folds.
        let good = stored_receipt([0x99; 32], 1_000_000_000_000_000);
        let folded = fold_operator_totals(&[good], &[orphan], 1_000, u128::MAX).expect("folds");
        assert_eq!(folded.len(), 1);
        assert!(folded[0].gross_goat_wei > 0);
        // …and the fold applies the split, rather than leaving the two shares at
        // their zero initialisers.
        assert_eq!(folded[0].gross_goat_wei, 1_000_000_000_000_000);
        assert_eq!(folded[0].payout_goat_wei, 900_000_000_000_000);
        assert_eq!(folded[0].protocol_goat_wei, 100_000_000_000_000);
        assert_eq!(
            folded[0].payout_goat_wei + folded[0].protocol_goat_wei,
            folded[0].gross_goat_wei
        );
    }

    /// Mutations this detects: rounding the byte-to-wei conversion up, or
    /// applying the floor once per operator instead of once per session (which
    /// changes the result whenever an operator serves sessions at two different
    /// prices).
    #[test]
    fn the_floor_is_applied_per_session_and_the_dust_stays_in_the_pool() {
        // One MiB minus one byte at 1e15 wei/MiB: the exact conversion is
        // 999999046325683.59375 wei, so the floor must drop the fraction.
        let g = gross_for_session(1_048_575, 1_000_000_000_000_000).expect("ok");
        assert_eq!(g, 999_999_046_325_683);
        assert!(
            (1_048_575u128 * 1_000_000_000_000_000) / 1_048_576 == g,
            "must be a floor, not a round"
        );

        let per_session = gross_for_session(1_048_575, 1_000_000_000_000_000).unwrap()
            + gross_for_session(1_048_575, 3_000_000_000_000_000).unwrap();
        let naive_combined = (2 * 1_048_575u128 * 2_000_000_000_000_000) / 1_048_576;
        assert_ne!(
            per_session, naive_combined,
            "per-session flooring must not be silently replaced by an averaged single floor"
        );

        // The dust is never allocated: two sessions' floored grosses can only be
        // less than or equal to the unfloored sum, never more.
        assert!(per_session < naive_combined + 1);
        assert!(gross_for_session(0, u128::MAX >> 1).unwrap() == 0);
        assert!(matches!(
            gross_for_session(u128::MAX, 2),
            Err(AggregateError::Overflow { .. })
        ));
    }

    /// The No-Ponzi inequality as a refusal.
    ///
    /// Mutations this detects: clamping the batch to the pool instead of
    /// refusing; forgetting to subtract the reserve; comparing against `funded`
    /// alone; letting an equal-to-the-limit batch through as if it were over.
    #[test]
    fn a_batch_that_would_overdraw_the_pool_is_refused_not_clamped() {
        let totals = vec![
            OperatorEpochTotal::for_test([0xA1; 20], 104_857_600, 10, 900_000, 100_000),
            OperatorEpochTotal::for_test([0xB2; 20], 10_485_760, 1, 90_000, 10_000),
        ];
        // gross = 1_100_000; funded 1_200_000 with a 150_000 reserve leaves
        // 1_050_000.
        let err = build_proxy_epoch_batch(
            SAMPLE_EPOCH,
            totals.clone(),
            &open_controls(),
            1_200_000,
            150_000,
            1_000,
        )
        .expect_err("must refuse");
        assert!(matches!(err, AggregateError::PoolWouldBeOverdrawn { .. }));

        // Positive control at the exact boundary: allocatable == gross is
        // allowed.
        let batch = build_proxy_epoch_batch(
            SAMPLE_EPOCH,
            totals.clone(),
            &open_controls(),
            1_250_000,
            150_000,
            1_000,
        )
        .expect("exactly-funded batch must build");
        assert_eq!(batch.total_gross_goat_wei, 1_100_000);
        assert_eq!(
            batch.total_payout_goat_wei + batch.total_protocol_goat_wei,
            batch.total_gross_goat_wei,
            "epoch-level conservation"
        );

        // One wei less funding flips it back to a refusal — proving the
        // comparison is not off by one in the permissive direction.
        assert!(matches!(
            build_proxy_epoch_batch(
                SAMPLE_EPOCH,
                totals.clone(),
                &open_controls(),
                1_249_999,
                150_000,
                1_000
            ),
            Err(AggregateError::PoolWouldBeOverdrawn { .. })
        ));

        // Ignoring the reserve is the same defect wearing another name: with the
        // reserve subtracted this is a refusal, and `funded` alone would admit
        // it.
        assert!(matches!(
            build_proxy_epoch_batch(
                SAMPLE_EPOCH,
                totals.clone(),
                &open_controls(),
                1_100_000,
                1,
                1_000
            ),
            Err(AggregateError::PoolWouldBeOverdrawn { .. })
        ));
        assert!(
            build_proxy_epoch_batch(
                SAMPLE_EPOCH,
                totals.clone(),
                &open_controls(),
                1_100_000,
                0,
                1_000
            )
            .is_ok(),
            "positive control: a zero reserve at exactly the gross is fundable"
        );

        // Structural refusals that must not be reachable as a partial batch.
        assert!(matches!(
            build_proxy_epoch_batch(
                20_260_731,
                totals.clone(),
                &open_controls(),
                u128::MAX,
                0,
                1_000
            ),
            Err(AggregateError::EpochNotInProxySpace { .. })
        ));
        assert!(matches!(
            build_proxy_epoch_batch(SAMPLE_EPOCH, vec![], &open_controls(), u128::MAX, 0, 1_000),
            Err(AggregateError::EmptyBatch)
        ));
        assert!(matches!(
            build_proxy_epoch_batch(SAMPLE_EPOCH, totals, &open_controls(), u128::MAX, 0, 1_500),
            Err(AggregateError::TakeOutOfBand { .. })
        ));
    }

    /// Mutations this detects: putting the GROSS (not the operator share) into
    /// the leaf, which would hand the operator the protocol's take as well; or
    /// putting the protocol share into a leaf, which would make the take
    /// claimable by an address.
    #[test]
    fn the_leaf_carries_the_operator_share_only_and_the_take_is_never_a_leaf() {
        let totals = vec![OperatorEpochTotal::for_test(
            [0xA1; 20],
            104_857_600,
            10,
            900_000,
            100_000,
        )];
        let batch =
            build_proxy_epoch_batch(SAMPLE_EPOCH, totals, &open_controls(), 10_000_000, 0, 1_000)
                .expect("build");
        assert_eq!(
            batch.leaves.len(),
            1,
            "one leaf per operator, none for the protocol"
        );
        assert_eq!(batch.leaves[0].payout_goat_wei, 900_000);
        assert_eq!(batch.total_protocol_goat_wei, 100_000);
        let protocol_leaf = proxy_leaf_hash(&ProxyLeaf {
            operator: [0u8; 20],
            epoch_id: SAMPLE_EPOCH,
            total_bytes: 0,
            payout_goat_wei: 100_000,
        });
        assert!(
            !batch
                .leaves
                .iter()
                .any(|l| proxy_leaf_hash(l) == protocol_leaf),
            "the protocol take must not be a claimable leaf"
        );

        // The evidence ref covers the epoch totals, so a batch that moved a wei
        // from one side of the split to the other is a different document.
        assert_ne!(batch.evidence_ref, [0u8; 32]);
        let other = build_proxy_epoch_batch(
            SAMPLE_EPOCH,
            vec![OperatorEpochTotal::for_test(
                [0xA1; 20],
                104_857_600,
                10,
                900_001,
                99_999,
            )],
            &open_controls(),
            10_000_000,
            0,
            1_000,
        );
        assert!(
            matches!(other, Err(AggregateError::InconsistentSplit { .. })),
            "a wei moved from the protocol to the operator is not a buildable batch"
        );
    }

    /// Mutations this detects: an operator epoch total over the byte ceiling
    /// being silently truncated rather than refused.
    #[test]
    fn an_operator_over_the_epoch_byte_ceiling_is_refused_not_truncated() {
        let over = 214_748_364_801u128;
        assert!(matches!(
            check_operator_byte_ceiling([0xA1; 20], over, 214_748_364_800),
            Err(AggregateError::OperatorOverByteCeiling { .. })
        ));
        assert!(check_operator_byte_ceiling([0xA1; 20], 214_748_364_800, 214_748_364_800).is_ok());

        // The ceiling reaches the fold, not only the free function.
        let priced = stored_receipt([0x11; 32], 1);
        let session = SessionTotal {
            session_id: [0x11; 32],
            operator: [0xA1; 20],
            total_bytes: over,
            chunk_count: 1,
        };
        assert!(matches!(
            fold_operator_totals(
                std::slice::from_ref(&priced),
                std::slice::from_ref(&session),
                1_000,
                214_748_364_800
            ),
            Err(AggregateError::OperatorOverByteCeiling { .. })
        ));
        // POSITIVE CONTROL: the same fold at a ceiling that admits it.
        assert!(fold_operator_totals(&[priced], &[session], 1_000, over).is_ok());
    }

    /// **The cross-language pin for the arithmetic.** The five basis-point
    /// constants are read out of `ProxyRevenueSettlement.sol` at run time — not
    /// copied into this file — and the Rust split is then asserted, wei for wei,
    /// against the contract's own expressions.
    ///
    /// What the contract enforces and this must never violate:
    /// `claim` reverts `OperatorShareExceeded` unless
    /// `Σ payouts <= (grossGoatWei * OPERATOR_BPS) / BPS_DENOM`, and
    /// `finalizeBatch` routes `(gross * TAKE_BPS) / BPS_DENOM` with the take's
    /// own remainder landing on the reserve by subtraction.
    ///
    /// Mutations this detects: any change to `OPERATOR_BPS`, `TAKE_BPS`,
    /// `TREASURY_BPS`, `ATTESTOR_BPS`, `RESERVE_BPS` or `BPS_DENOM` on EITHER
    /// side of the language boundary; [`MAX_TAKE_BPS`] drifting off the
    /// immutable on-chain take; a Rust operator share computed as
    /// `gross - floor(gross * take / DENOM)` (which exceeds the contract's bound
    /// on every non-divisible gross and would revert every claim in the batch).
    #[test]
    fn the_split_agrees_wei_for_wei_with_the_settlement_contracts_own_arithmetic() {
        // The parser first, with its own controls: a parser that returns `None`
        // for everything would make every assertion below unreachable.
        assert_eq!(
            sol_uint_constant("    uint16 public constant FOO_BPS = 1_234;", "FOO_BPS"),
            Some(1_234)
        );
        assert_eq!(
            sol_uint_constant("    uint16 public constant FOO_BPS_X = 7;", "FOO_BPS"),
            None,
            "a longer name that starts with the same token must not match"
        );
        assert_eq!(
            sol_uint_constant("    uint16 public immutable FOO_BPS = 5;", "FOO_BPS"),
            None,
            "only a `constant` declaration is a pin"
        );
        assert_eq!(
            sol_uint_constant("    bytes32 constant FOO_BPS = 0x0102;", "FOO_BPS"),
            None,
            "a hex literal is not an integer pin"
        );

        let src = read_contract_source("contracts/src/proxy/ProxyRevenueSettlement.sol");
        let get = |n: &str| {
            sol_uint_constant(&src, n)
                .unwrap_or_else(|| panic!("{n} is not declared in the settlement source"))
        };
        let operator_bps = get("OPERATOR_BPS");
        let take_bps = get("TAKE_BPS");
        let treasury_bps = get("TREASURY_BPS");
        let attestor_bps = get("ATTESTOR_BPS");
        let reserve_bps = get("RESERVE_BPS");
        let denom = get("BPS_DENOM");

        assert_eq!(
            (operator_bps, take_bps, denom),
            (9_000, 1_000, 10_000),
            "the deployed settlement's split constants have moved"
        );
        assert_eq!(
            (treasury_bps, attestor_bps, reserve_bps),
            (600, 200, 200),
            "the take's three on-chain destinations have moved"
        );
        assert_eq!(
            operator_bps + take_bps,
            denom,
            "the two shares must be the whole of the gross"
        );
        assert_eq!(
            treasury_bps + attestor_bps + reserve_bps,
            take_bps,
            "the take's sub-lines must be the whole of the take"
        );
        assert_eq!(
            u128::from(BPS_DENOM),
            denom,
            "the off-chain denominator has drifted from the contract's"
        );
        assert_eq!(
            u128::from(MAX_TAKE_BPS),
            take_bps,
            "the launch band's top must equal the IMMUTABLE on-chain take, or a config edit \
             moves value with every test green"
        );
        assert!(
            u128::from(MIN_TAKE_BPS) < take_bps,
            "the band must admit more than the single on-chain value"
        );

        // The contract's own expressions, transcribed. Nothing below reads a
        // Rust constant for these.
        let claim_bound = |gross: u128| gross * operator_bps / denom;
        let on_chain_take = |gross: u128| gross * take_bps / denom;
        let route = |gross: u128| {
            let take = gross * take_bps / denom;
            let treasury = gross * treasury_bps / denom;
            let attestor = gross * attestor_bps / denom;
            (take, treasury, attestor, take - treasury - attestor)
        };

        let mut vectors: Vec<u128> = (0u128..=4_096).collect();
        vectors.extend([
            9_999,
            10_000,
            10_001,
            1_048_575,
            1_048_576,
            232_830_643,
            258_700_715,
            250_000_000_000_000_000,
            277_777_777_777_777_778,
            1_000_000_000_000_000_007,
            u128::from(u64::MAX),
            u128::MAX / 10_000,
        ]);
        for gross in vectors {
            let (operator, protocol) = split_gross(gross, MAX_TAKE_BPS).expect("no overflow");
            assert_eq!(
                operator,
                claim_bound(gross),
                "the Rust operator share is not the contract's own expression at gross={gross}"
            );
            assert_eq!(operator + protocol, gross, "conservation at gross={gross}");
            assert!(
                protocol >= on_chain_take(gross),
                "the off-chain protocol share must cover the take the contract routes, at \
                 gross={gross}"
            );
            let (take, treasury, attestor, reserve) = route(gross);
            assert_eq!(
                treasury + attestor + reserve,
                take,
                "the take's own remainder must land on the reserve at gross={gross}"
            );
            assert!(
                take + claim_bound(gross) <= gross,
                "the contract would overdraw its own gross at gross={gross}"
            );
        }

        // MANY OPERATORS. The contract bounds the sum of leaf payouts by a
        // single floor taken on the epoch TOTAL, while this lane takes one floor
        // per operator. Per-operator flooring must never sum above the
        // epoch-level bound, or `claim` reverts `OperatorShareExceeded` for
        // whichever operator happens to be last.
        for seed in 0u128..64 {
            let parts: Vec<u128> = (0u128..7)
                .map(|i| 1 + (seed * 4_099 + i * 7_919) % 99_991)
                .collect();
            let total: u128 = parts.iter().sum();
            let payouts: u128 = parts
                .iter()
                .map(|g| split_gross(*g, MAX_TAKE_BPS).expect("ok").0)
                .sum();
            let protocol: u128 = parts
                .iter()
                .map(|g| split_gross(*g, MAX_TAKE_BPS).expect("ok").1)
                .sum();
            assert_eq!(
                payouts + protocol,
                total,
                "epoch conservation at seed={seed}"
            );
            assert!(
                payouts <= claim_bound(total),
                "per-operator flooring summed above the contract's epoch bound at seed={seed}"
            );
            assert!(
                payouts + on_chain_take(total) <= total,
                "operators plus the routed take exceed the epoch's gross at seed={seed}"
            );
        }

        // NEGATIVE CONTROL: the bound is not vacuous. A leaf carrying the GROSS
        // would exceed it, which is what makes the assertions above meaningful.
        let g = 1_000_001u128;
        assert!(
            g > claim_bound(g),
            "the contract's bound admits the gross, so it bounds nothing"
        );
    }

    /// **The cross-language pin for the leaf.** The pinned vectors are read out
    /// of `ProxyRevenueMerkleParity.t.sol` at run time — the same literals the
    /// Solidity suite asserts against `keccak256(bytes.concat(keccak256(
    /// abi.encode(PROXY_LEAF_DOMAIN, operator, epochId, totalBytes,
    /// payoutGoatWei))))` — and the payouts are produced by [`split_gross`]
    /// rather than written down, so the split and the leaf are pinned together.
    ///
    /// Mutations this detects: the GROSS placed in the leaf instead of the
    /// operator share; the split's remainder moved to the operator (either
    /// changes the payout, hence the leaf, hence the root); leaves emitted in a
    /// different shape; the epoch id dropped from the leaf.
    #[test]
    fn the_epoch_batch_reproduces_the_pinned_solidity_parity_root() {
        // Parser controls first.
        assert_eq!(
            sol_bytes32_constant(
                "    bytes32 constant X = 0x0000000000000000000000000000000000000000000000000000000000000001;",
                "X"
            ),
            Some({
                let mut b = [0u8; 32];
                b[31] = 1;
                b
            })
        );
        assert_eq!(
            sol_bytes32_constant("bytes32 constant X = 0x01;", "X"),
            None
        );
        assert_eq!(
            sol_address_constant("    address constant OP = address(uint160(0xA1));", "OP"),
            Some({
                let mut a = [0u8; 20];
                a[19] = 0xA1;
                a
            })
        );

        let sol = read_contract_source("contracts/test/ProxyRevenueMerkleParity.t.sol");
        let uint = |n: &str| {
            sol_uint_constant(&sol, n).unwrap_or_else(|| panic!("{n} is not pinned in Solidity"))
        };
        let word = |n: &str| {
            sol_bytes32_constant(&sol, n).unwrap_or_else(|| panic!("{n} is not pinned in Solidity"))
        };
        let addr = |n: &str| {
            sol_address_constant(&sol, n).unwrap_or_else(|| panic!("{n} is not pinned in Solidity"))
        };

        let epoch_id = u64::try_from(uint("EPOCH")).expect("the pinned epoch fits a u64");
        assert_eq!(epoch_id, SAMPLE_EPOCH, "the two lanes pin different epochs");
        let (bytes_a, amt_a) = (uint("BYTES_A"), uint("AMT_A"));
        let (bytes_b, amt_b) = (uint("BYTES_B"), uint("AMT_B"));
        let (leaf_a, leaf_b, two_leaf_root) =
            (word("LEAF_A"), word("LEAF_B"), word("TWO_LEAF_ROOT"));
        let (op_a, op_b) = (addr("OP_A"), addr("OP_B"));
        assert_ne!(leaf_a, leaf_b, "the Solidity pins are not distinct");
        assert_ne!(op_a, op_b);

        // The grosses whose 90/10 split IS the pinned payout. Chosen so the
        // amounts below come out of the split rather than being written down.
        let gross_a = 277_777_777_777_777_778u128;
        let gross_b = 258_700_715u128;
        let (payout_a, protocol_a) = split_gross(gross_a, MAX_TAKE_BPS).expect("ok");
        let (payout_b, protocol_b) = split_gross(gross_b, MAX_TAKE_BPS).expect("ok");
        assert_eq!(
            payout_a, amt_a,
            "the split must reproduce the pinned Solidity payout exactly"
        );
        assert_eq!(payout_b, amt_b);

        let totals = vec![
            OperatorEpochTotal::for_test(op_a, bytes_a, 1, payout_a, protocol_a),
            OperatorEpochTotal::for_test(op_b, bytes_b, 1, payout_b, protocol_b),
        ];
        let gross_total = gross_a + gross_b;
        let batch = build_proxy_epoch_batch(
            epoch_id,
            totals,
            &open_controls(),
            gross_total,
            0,
            MAX_TAKE_BPS,
        )
        .expect("the pinned batch must build");

        assert_eq!(
            hex::encode(proxy_leaf_hash(&batch.leaves[0])),
            hex::encode(leaf_a),
            "leaf A"
        );
        assert_eq!(
            hex::encode(proxy_leaf_hash(&batch.leaves[1])),
            hex::encode(leaf_b),
            "leaf B"
        );
        assert_eq!(
            batch.merkle_root_hex,
            format!("0x{}", hex::encode(two_leaf_root)),
            "the aggregation's root is not the root Solidity pins"
        );
        assert_eq!(batch.total_gross_goat_wei, gross_total);
        assert_eq!(
            batch.total_payout_goat_wei + batch.total_protocol_goat_wei,
            batch.total_gross_goat_wei
        );

        // The contract's claim bound, on these very numbers.
        assert!(
            batch.total_payout_goat_wei <= gross_total * 9_000 / 10_000,
            "this batch would revert OperatorShareExceeded on chain"
        );

        // NEGATIVE CONTROL: the gross in the leaf is a DIFFERENT leaf, so the
        // pin above is not satisfied by any payout at all…
        assert_ne!(
            hex::encode(proxy_leaf_hash(&ProxyLeaf {
                operator: op_a,
                epoch_id,
                total_bytes: bytes_a,
                payout_goat_wei: gross_a,
            })),
            hex::encode(leaf_a),
            "a gross-valued leaf must not hash to the pinned operator-share leaf"
        );
        // …and the builder refuses to emit it in the first place.
        assert!(matches!(
            build_proxy_epoch_batch(
                epoch_id,
                vec![OperatorEpochTotal::for_test(op_a, bytes_a, 1, gross_a, 0)],
                &open_controls(),
                u128::MAX,
                0,
                MAX_TAKE_BPS,
            ),
            Err(AggregateError::InconsistentSplit { .. })
        ));
    }

    /// The two unit systems, reconciled and their confusion pinned.
    ///
    /// Mutations this detects: [`gross_for_session`] dividing by
    /// [`super::proxy_merkle::GIB_BYTES`] instead of [`MEBIBYTE`]; a caller
    /// handing a per-mebibyte price to [`super::proxy_merkle::gross_for_bytes`]
    /// without [`price_goat_wei_per_gibibyte`]; [`MEBIBYTES_PER_GIBIBYTE`]
    /// written as a literal that drifts from either denominator.
    #[test]
    fn a_mebibyte_price_and_a_gibibyte_rate_value_the_same_bytes_identically() {
        assert_eq!(MEBIBYTE, 1 << 20);
        assert_eq!(GIB_BYTES, 1 << 30);
        assert_eq!(MEBIBYTES_PER_GIBIBYTE, 1_024);
        assert_eq!(MEBIBYTE * MEBIBYTES_PER_GIBIBYTE, GIB_BYTES);
        assert_eq!(MEBIBYTE, u128::from(crate::proxy::MIB_BYTES));

        for bytes in [
            0u128,
            1,
            1_048_575,
            1_048_576,
            1_073_741_823,
            1_073_741_824,
            999_999_999,
            214_748_364_800,
        ] {
            for price_per_mebibyte in [
                1u128,
                7,
                232_830_643,
                1_000_000_000_000_000,
                crate::proxy::MAX_PRICE_GOAT_WEI_PER_MEBIBYTE,
            ] {
                let per_gibibyte =
                    price_goat_wei_per_gibibyte(price_per_mebibyte).expect("no overflow");
                assert_eq!(per_gibibyte, price_per_mebibyte * 1_024);
                assert_eq!(
                    gross_for_session(bytes, price_per_mebibyte).expect("ok"),
                    gross_for_bytes(bytes, per_gibibyte),
                    "the two unit systems disagree at {bytes} bytes, \
                     {price_per_mebibyte} wei/MiB"
                );
            }
        }

        // THE CONFUSION, pinned. Feeding a per-MEBIBYTE price to the
        // per-GIBIBYTE denominator under-values every session by exactly 1024x,
        // which is a loss no strict-equality challenger can observe.
        let bytes = 1_073_741_824u128;
        let price_per_mebibyte = 1_000_000_000_000_000u128;
        let correct = gross_for_session(bytes, price_per_mebibyte).expect("ok");
        let confused = gross_for_bytes(bytes, price_per_mebibyte);
        assert_eq!(correct, 1_024 * price_per_mebibyte);
        assert_ne!(correct, confused);
        assert_eq!(
            confused * MEBIBYTES_PER_GIBIBYTE,
            correct,
            "the mebibyte/gibibyte confusion is exactly a factor of 1024"
        );

        // And in the other direction: a per-GIBIBYTE rate handed to the
        // per-mebibyte denominator over-values by the same 1024.
        assert_eq!(
            gross_for_session(
                bytes,
                price_goat_wei_per_gibibyte(price_per_mebibyte).unwrap()
            )
            .expect("ok"),
            correct * MEBIBYTES_PER_GIBIBYTE
        );

        // The conversion refuses rather than wrapping.
        assert!(matches!(
            price_goat_wei_per_gibibyte(u128::MAX),
            Err(AggregateError::Overflow { .. })
        ));
    }

    /// The `u64 -> u128` fold, and the store's ceiling preserved one layer up.
    ///
    /// Mutations this detects: `r.bytes_transferred as u128` (silent on the day
    /// the width changes); last-write-wins on a session's operator; a byte total
    /// above the store's signed 64-bit column truncated instead of refused; the
    /// `0x` prefix rejected on one of the two forms the lane produces.
    #[test]
    fn folding_receipts_into_sessions_widens_without_a_cast_and_keeps_the_stores_ceiling() {
        // POSITIVE CONTROL: three chunks of one session fold to one row.
        let mut r0 = stored_receipt([0x11; 32], 1_000);
        r0.bytes_transferred = 10_485_760;
        let mut r1 = r0.clone();
        r1.chunk_seq = 1;
        let mut r2 = r0.clone();
        r2.chunk_seq = 2;
        r2.bytes_transferred = 7;
        let folded = fold_session_totals(&[r0.clone(), r1, r2]).expect("folds");
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].session_id, [0x11; 32]);
        assert_eq!(folded[0].operator, [0x99; 20]);
        assert_eq!(folded[0].total_bytes, 10_485_760u128 * 2 + 7);
        assert_eq!(folded[0].chunk_count, 3);

        // Exactly at the store's ceiling: accepted, and the widened value is the
        // ceiling itself rather than a truncation of it.
        let mut at_max = stored_receipt([0x22; 32], 1_000);
        at_max.bytes_transferred = u64::try_from(MAX_STORABLE_BYTES).expect("i64::MAX fits u64");
        let ok = fold_session_totals(&[at_max.clone()]).expect("i64::MAX is storable");
        assert_eq!(ok[0].total_bytes, MAX_STORABLE_BYTES);
        assert_eq!(
            storable_byte_total([0x99; 20], MAX_STORABLE_BYTES).expect("ok"),
            u64::try_from(MAX_STORABLE_BYTES).unwrap()
        );

        // One byte more is a TYPED refusal, not a truncation — the same
        // boundary the store's own `ValueOutOfRange` holds, asserted one layer
        // earlier where the operator is still named.
        let mut one_more = at_max.clone();
        one_more.chunk_seq = 1;
        one_more.bytes_transferred = 1;
        assert!(matches!(
            fold_session_totals(&[at_max, one_more]),
            Err(AggregateError::ByteTotalNotStorable { .. })
        ));
        assert!(matches!(
            storable_byte_total([0x99; 20], MAX_STORABLE_BYTES + 1),
            Err(AggregateError::ByteTotalNotStorable { .. })
        ));
        // A single receipt already above the ceiling — the widening is lossless
        // enough to SEE it, which an `as u64` narrowing later would not be.
        let mut huge = stored_receipt([0x22; 32], 1_000);
        huge.bytes_transferred = u64::MAX;
        assert!(matches!(
            fold_session_totals(&[huge]),
            Err(AggregateError::ByteTotalNotStorable { .. })
        ));

        // Malformed identifiers are typed refusals, never panics.
        let mut bad_wallet = stored_receipt([0x33; 32], 1_000);
        bad_wallet.operator_wallet = "not-hex".into();
        assert!(matches!(
            fold_session_totals(&[bad_wallet]),
            Err(AggregateError::MalformedOperatorWallet { .. })
        ));
        let mut short_wallet = stored_receipt([0x33; 32], 1_000);
        short_wallet.operator_wallet = "aabb".into();
        assert!(matches!(
            fold_session_totals(&[short_wallet]),
            Err(AggregateError::MalformedOperatorWallet { .. })
        ));
        let mut bad_session = stored_receipt([0x33; 32], 1_000);
        bad_session.session_id_hex = "zz".into();
        assert!(matches!(
            fold_session_totals(&[bad_session]),
            Err(AggregateError::MalformedSessionId { .. })
        ));

        // Two operators claiming one session is a refusal, not last-write-wins.
        let a = stored_receipt([0x44; 32], 1_000);
        let mut b = a.clone();
        b.chunk_seq = 1;
        b.operator_wallet = hex::encode([0x88; 20]);
        assert!(matches!(
            fold_session_totals(&[a, b]),
            Err(AggregateError::SessionOperatorMismatch { .. })
        ));

        // Both spellings the lane produces decode: the store writes the bare
        // form, the receipt module writes the `0x`-prefixed one.
        let mut prefixed = stored_receipt([0x55; 32], 1_000);
        prefixed.operator_wallet = format!("0x{}", hex::encode([0x99; 20]));
        prefixed.session_id_hex = format!("0x{}", hex::encode([0x55; 32]));
        let one = fold_session_totals(&[prefixed]).expect("folds");
        assert_eq!(one[0].operator, [0x99; 20]);
        assert_eq!(one[0].session_id, [0x55; 32]);

        // The folded document is ordered by session id regardless of input
        // order, so two proposers produce the same bytes.
        let s1 = stored_receipt([0xF1; 32], 1_000);
        let s2 = stored_receipt([0x02; 32], 1_000);
        let forward = fold_session_totals(&[s1.clone(), s2.clone()]).expect("folds");
        let backward = fold_session_totals(&[s2, s1]).expect("folds");
        assert_eq!(forward, backward);
        assert_eq!(forward[0].session_id, [0x02; 32]);
    }

    /// One operator, one leaf. The settlement records `claimed[epochId][operator]`,
    /// so a second leaf for the same operator can never be claimed and is a
    /// silent under-allocation rather than a duplicate payment.
    ///
    /// Mutations this detects: dropping the duplicate scan from
    /// [`build_proxy_epoch_batch`]; a fold that keys on something other than the
    /// operator address.
    #[test]
    fn two_leaves_for_one_operator_are_refused_because_only_one_can_ever_be_claimed() {
        let a = OperatorEpochTotal::for_test([0xA1; 20], 104_857_600, 10, 900_000, 100_000);
        let b = OperatorEpochTotal::for_test([0xB2; 20], 10_485_760, 1, 90_000, 10_000);

        // POSITIVE CONTROL: two DIFFERENT operators build, so the refusal below
        // is about the repeat and nothing else.
        let two = build_proxy_epoch_batch(
            SAMPLE_EPOCH,
            vec![a.clone(), b],
            &open_controls(),
            10_000_000,
            0,
            1_000,
        )
        .expect("two distinct operators must build");
        assert_eq!(two.leaves.len(), 2);

        assert!(matches!(
            build_proxy_epoch_batch(
                SAMPLE_EPOCH,
                vec![a.clone(), a],
                &open_controls(),
                10_000_000,
                0,
                1_000
            ),
            Err(AggregateError::DuplicateOperator { .. })
        ));
    }

    /// A total whose three money fields are not the declared take's split of its
    /// own gross never becomes a leaf.
    ///
    /// [`OperatorEpochTotal`] has public fields and
    /// [`OperatorEpochTotal::for_test`] accepts any pair, so without this check
    /// the leaf carries whatever the caller wrote and the `debug_assert` that
    /// would have caught it is compiled out of every release build.
    ///
    /// Mutations this detects: the re-derivation dropped from
    /// [`build_proxy_epoch_batch`]; a batch built at one take from totals split
    /// at another (which moves 2% of gross with every test otherwise green).
    #[test]
    fn an_operator_total_whose_split_does_not_match_the_configured_take_is_refused() {
        // POSITIVE CONTROL.
        let good = OperatorEpochTotal::for_test([0xA1; 20], 1, 1, 900_000, 100_000);
        assert!(build_proxy_epoch_batch(
            SAMPLE_EPOCH,
            vec![good],
            &open_controls(),
            10_000_000,
            0,
            1_000
        )
        .is_ok());

        // The GROSS in the leaf: the edit that hands the operator the take too.
        assert!(matches!(
            build_proxy_epoch_batch(
                SAMPLE_EPOCH,
                vec![OperatorEpochTotal::for_test([0xA1; 20], 1, 1, 1_000_000, 0)],
                &open_controls(),
                10_000_000,
                0,
                1_000,
            ),
            Err(AggregateError::InconsistentSplit { .. })
        ));

        // A total split at 800 bps offered to a batch declared at 1000 bps.
        let (payout, protocol) = split_gross(1_000_000, 800).expect("ok");
        let other_band = OperatorEpochTotal::for_test([0xA1; 20], 1, 1, payout, protocol);
        assert!(matches!(
            build_proxy_epoch_batch(
                SAMPLE_EPOCH,
                vec![other_band.clone()],
                &open_controls(),
                10_000_000,
                0,
                1_000
            ),
            Err(AggregateError::InconsistentSplit { .. })
        ));
        // …and the same total at its OWN take builds, so the refusal is about
        // the disagreement and not about the numbers.
        assert!(build_proxy_epoch_batch(
            SAMPLE_EPOCH,
            vec![other_band],
            &open_controls(),
            10_000_000,
            0,
            800
        )
        .is_ok());

        // A hand-built total whose fields simply do not add up.
        let inconsistent = OperatorEpochTotal {
            operator: [0xA1; 20],
            total_bytes: 1,
            receipt_count: 1,
            gross_goat_wei: 1_000_001,
            payout_goat_wei: 900_000,
            protocol_goat_wei: 100_000,
        };
        assert!(matches!(
            build_proxy_epoch_batch(
                SAMPLE_EPOCH,
                vec![inconsistent],
                &open_controls(),
                10_000_000,
                0,
                1_000
            ),
            Err(AggregateError::InconsistentSplit { .. })
        ));

        // The narrowing helper is reachable from the total itself, and refuses
        // rather than truncating.
        let storable = OperatorEpochTotal::for_test([0xA1; 20], 1_048_576, 1, 900_000, 100_000);
        assert_eq!(storable.storable_total_bytes().expect("ok"), 1_048_576);
        let unstorable =
            OperatorEpochTotal::for_test([0xA1; 20], MAX_STORABLE_BYTES + 1, 1, 900_000, 100_000);
        assert!(matches!(
            unstorable.storable_total_bytes(),
            Err(AggregateError::ByteTotalNotStorable { .. })
        ));
    }

    /// THE ORDER, proved observably. A batch that is BOTH fraudulent AND an
    /// overdraft must report the fraud.
    ///
    /// The two refusals are handed to different people. "The pool would be
    /// overdrawn" reads as "the funder deposited too little" and points the next
    /// action at the treasury; "this cluster is over its byte ceiling" points it
    /// at three wallets and one household. Reporting the wrong one does not just
    /// mislabel a failure, it sends the investigation somewhere else.
    ///
    /// Mutations this detects: deleting either fraud call from
    /// [`build_proxy_epoch_batch`]; moving them below the pool inequality;
    /// keying the byte ceiling on the operator address rather than the cluster
    /// root (the three sybils then each pass their own ceiling and only the
    /// overdraft fires).
    #[test]
    fn a_fraudulent_batch_is_refused_as_fraud_before_it_is_refused_as_an_overdraft() {
        // Three identities, one household. Each is individually modest; together
        // they are over the cluster ceiling.
        let sybil = |n: u8| {
            let mut w = [0u8; 20];
            w[19] = n;
            w
        };
        let household = sybil(0xFF);
        static ROOT_OF: fn([u8; 20]) -> Option<[u8; 20]> = |w| {
            let mut root = [0u8; 20];
            root[19] = if (1..=3).contains(&w[19]) {
                0xFF
            } else {
                w[19]
            };
            Some(root)
        };
        static ONE_CONSUMER: fn(&[u8; 32]) -> [u8; 32] = |_| [0xCCu8; 32];

        let totals: Vec<OperatorEpochTotal> = (1u8..=3)
            .map(|n| {
                let (payout, protocol) = split_gross(1_000_000, 1_000).expect("in band");
                OperatorEpochTotal::for_test(sybil(n), 40_000, 4, payout, protocol)
            })
            .collect();

        let controls = EpochFraudControls {
            receipts: &[],
            sessions: &[],
            consumer_of: &ONE_CONSUMER,
            root_of: &ROOT_OF,
            cluster_byte_ceiling: 100_000,
            pair_concentration_cap_bps: BPS_DENOM,
        };

        // Funded at 1 wei: this batch overdraws the pool by three whole grosses
        // AND breaches the cluster ceiling. It must report the fraud.
        let err = build_proxy_epoch_batch(SAMPLE_EPOCH, totals.clone(), &controls, 1, 0, 1_000)
            .expect_err("fraudulent and overdrawn at once");
        assert_eq!(
            err,
            AggregateError::Fraud(crate::proxy::fraud::FraudError::ClusterOverByteCeiling {
                root: hex::encode(household),
                claimed: 120_000,
                members: 3,
                ceiling: 100_000,
            })
        );

        // POSITIVE CONTROL #1 — the overdraft is real. Treated as three
        // unrelated operators, the same batch at the same funding reports the
        // pool, so the assertion above is the ORDER firing and not the only
        // refusal available.
        assert!(matches!(
            build_proxy_epoch_batch(SAMPLE_EPOCH, totals.clone(), &open_controls(), 1, 0, 1_000),
            Err(AggregateError::PoolWouldBeOverdrawn { .. })
        ));

        // POSITIVE CONTROL #2 — the fraud is real, independent of funding.
        // Funded to the brim, the cluster ceiling still refuses.
        assert!(matches!(
            build_proxy_epoch_batch(SAMPLE_EPOCH, totals.clone(), &controls, u128::MAX, 0, 1_000),
            Err(AggregateError::Fraud(
                crate::proxy::fraud::FraudError::ClusterOverByteCeiling { .. }
            ))
        ));

        // NEGATIVE CONTROL — raise the ceiling above the household's claim and
        // the same batch, same controls, same funding, builds. So the refusals
        // above are the ceiling comparison and not a builder that refuses
        // everything once a `root_of` is supplied.
        let roomy = EpochFraudControls {
            cluster_byte_ceiling: 120_000,
            ..controls
        };
        let batch = build_proxy_epoch_batch(SAMPLE_EPOCH, totals, &roomy, u128::MAX, 0, 1_000)
            .expect("an honest cluster under its ceiling must build");
        assert_eq!(batch.leaves.len(), 3);
    }

    /// The concentration cap and the session-sequence rule reach the batch
    /// builder too — the byte ceiling is not the only control wired in.
    ///
    /// Mutations this detects: wiring only `check_cluster_byte_ceiling` and
    /// leaving the other two calls out; passing the operator's own bytes as the
    /// concentration denominator; checking only the first session's sequence.
    #[test]
    fn the_concentration_cap_and_the_session_sequence_rule_both_reach_the_batch_builder() {
        let operator = [0xA1u8; 20];
        let (payout, protocol) = split_gross(1_000_000, 1_000).expect("in band");
        let totals = vec![OperatorEpochTotal::for_test(
            operator, 100, 2, payout, protocol,
        )];

        static IDENTITY_ROOT: fn([u8; 20]) -> Option<[u8; 20]> = |w| Some(w);
        static ONE_CONSUMER: fn(&[u8; 32]) -> [u8; 32] = |_| [0xCCu8; 32];

        // One operator serving 100% of one consumer's epoch bytes, against a
        // 50% cap.
        let sessions = vec![SessionTotal {
            session_id: [0x11; 32],
            operator,
            total_bytes: 100,
            chunk_count: 2,
        }];
        let concentrated = EpochFraudControls {
            receipts: &[],
            sessions: &sessions,
            consumer_of: &ONE_CONSUMER,
            root_of: &IDENTITY_ROOT,
            cluster_byte_ceiling: u128::MAX,
            pair_concentration_cap_bps: 5_000,
        };
        assert!(matches!(
            build_proxy_epoch_batch(
                SAMPLE_EPOCH,
                totals.clone(),
                &concentrated,
                u128::MAX,
                0,
                1_000
            ),
            Err(AggregateError::Fraud(
                crate::proxy::fraud::FraudError::PairConcentrationExceeded { .. }
            ))
        ));
        // POSITIVE CONTROL: the same traffic under a cap that permits it builds.
        let permitted = EpochFraudControls {
            pair_concentration_cap_bps: BPS_DENOM,
            ..concentrated
        };
        assert!(build_proxy_epoch_batch(
            SAMPLE_EPOCH,
            totals.clone(),
            &permitted,
            u128::MAX,
            0,
            1_000
        )
        .is_ok());

        // A session whose chunks skip a sequence number is refused at the batch,
        // not folded in.
        let mut r0 = stored_receipt([0x11; 32], 1_000);
        r0.chunk_kind = ChunkKind::Interim;
        let mut r2 = stored_receipt([0x11; 32], 1_000);
        r2.chunk_seq = 2;
        let gapped = vec![r0.clone(), r2];
        let with_gap = EpochFraudControls {
            receipts: &gapped,
            ..permitted
        };
        assert!(matches!(
            build_proxy_epoch_batch(SAMPLE_EPOCH, totals.clone(), &with_gap, u128::MAX, 0, 1_000),
            Err(AggregateError::Fraud(
                crate::proxy::fraud::FraudError::ChunkSequenceGap { .. }
            ))
        ));

        // POSITIVE CONTROL: the contiguous version of the same session builds.
        let mut r1 = stored_receipt([0x11; 32], 1_000);
        r1.chunk_seq = 1;
        let contiguous = vec![r0, r1];
        let sound = EpochFraudControls {
            receipts: &contiguous,
            ..permitted
        };
        assert!(
            build_proxy_epoch_batch(SAMPLE_EPOCH, totals, &sound, u128::MAX, 0, 1_000).is_ok(),
            "a contiguous session with one FINAL at the top must build"
        );
    }
}
