//! The gateway's metering witness.
//!
//! # Counter-semantics, stated so nobody over-reads it
//!
//! A [`TunnelMeterRecord`] is a **single witness to a byte count**. It is not a
//! proof of valued work, it settles nothing on its own, it moves no supply in
//! either direction, and its only job is to give the attestor's challenger a
//! second counter held by a party that is not compensated per byte.
//!
//! # Two fields, two epistemic statuses, and the names say which
//!
//! * [`TunnelMeterRecord::to_consumer`] is `body_bytes_to_consumer` — response
//!   body octets, after HTTP framing is stripped and chunked transfer-encoding
//!   is decoded, **as the gateway itself observed them crossing its own
//!   tunnel**. This is the witnessed quantity and the only payout basis.
//! * [`TunnelMeterRecord::node_reported_from_origin`] is a number the node
//!   asserted and the gateway merely re-signed. The gateway never touches the
//!   origin connection, so signing it attests to *receipt of a claim*, not to
//!   observation of the thing claimed. It is retained for diagnostics and for
//!   the [`GatewaySessionMeter::seal`] sanity bound, and it is named
//!   `node_reported_*` so that no future reader mistakes a countersignature for
//!   a witness.
//!
//! An earlier draft called the second field `from_origin` and let the hazard
//! map claim colluding parties "cannot produce the gateway signature" over it —
//! which is circular, because the gateway would sign whatever the node said.
//!
//! # One seam, pinned across two processes
//!
//! The node counts the same octets at `SessionMeter::observe`; the gateway
//! counts them here. The epoch challenger compares the two at **exact equality
//! with no tolerance in either direction**, so a meter that drifts onto the
//! socket seam — head bytes, chunk framing, TLS records — is a forfeited bond,
//! not a rounding difference. `fixtures/metered-quantity.json` beside the
//! worker crate pins the one number both processes must produce, and a test in
//! this module reads it rather than restating it.
//!
//! # Design authority
//!
//! The "Residential Proxy Network (P3) Implementation Plan", §4.1 ("Metered
//! quantity") and §2 (INV-11, INV-17); the "Residential Proxy Network — Worker
//! & Tunnel Spec (Tasks 18-36, 44, 45, 47)", Task 25.
//!
//! Honesty tagging: **[TARGET]**. No gateway is deployed, no record has ever
//! been signed outside a test, and nothing downstream of this file is reachable
//! from a running system.

use ml_dsa::signature::{Signer as _, Verifier as _};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair as _, MlDsa65, Signature, SigningKey,
    VerifyingKey, B32,
};
use sha3::{Digest, Sha3_256};

use goat_core::types::{ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN};

use crate::error::TunnelError;
use crate::frame::MAX_FRAME_PAYLOAD;

/// Domain separation for everything this module hashes and signs.
///
/// A signature made over a handshake transcript must not verify over a meter
/// record and vice versa, so the two contexts are disjoint byte strings.
pub const METER_RECORD_CONTEXT: &[u8] = b"GOAT-PROXY-TUNNEL-METER-v1";

/// The name of the one quantity this witness counts.
///
/// Held as a constant rather than as prose so the cross-process fixture can be
/// compared against it by a test instead of by a reader.
pub const METERED_QUANTITY: &str = "body_bytes_to_consumer";

/// How far the witnessed count may exceed the node's declared body length
/// before [`GatewaySessionMeter::seal`] refuses.
///
/// One frame, and the width is the reason: the gateway observes at frame
/// granularity, so it cannot notice an overrun until the frame that crosses the
/// declared length has already been counted. A tighter bound would refuse
/// honest sessions; a looser one would be slack nobody can justify. This is a
/// **sanity bound on a witness**, not a tolerance on a comparison — the epoch
/// comparison in the attestor is exact and there is no tolerance parameter
/// anywhere in this lane.
pub const BODY_OVERRUN_ALLOWANCE_BYTES: u64 = MAX_FRAME_PAYLOAD as u64;

/// Every field of [`TunnelMeterRecord`], in serialisation order.
///
/// This is the record's whole field set. Nothing here can carry a hostname, a
/// path, a query string, a header, a cookie or a body byte: every entry is a
/// byte count, a counter, or an opaque identifier the operator already agreed
/// to on screen.
pub const METER_RECORD_FIELDS: [&str; 7] = [
    "session_id",
    "allowlist_entry_id",
    "chunk_index",
    "node_reported_from_origin",
    "to_consumer",
    "declared_body_len",
    "sealed_at_unix",
];

/// What the gateway witnessed for one receipt chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TunnelMeterRecord {
    /// Opaque session identifier. Not derived from any destination.
    pub session_id: [u8; 32],
    /// Which entry of the published allowlist this session was serving — an
    /// **id**, never the name behind it.
    pub allowlist_entry_id: u32,
    /// Which receipt chunk of the session this record covers.
    pub chunk_index: u32,
    /// Re-signed, never witnessed, never a payout basis.
    pub node_reported_from_origin: u64,
    /// Witnessed. `body_bytes_to_consumer`, and the only payout basis.
    pub to_consumer: u64,
    /// The body length the node declared for this chunk before bytes moved.
    pub declared_body_len: u64,
    /// When the gateway sealed this record.
    pub sealed_at_unix: u64,
}

impl TunnelMeterRecord {
    /// Every field as `(name, decimal-or-hex string)`, in
    /// [`METER_RECORD_FIELDS`] order.
    ///
    /// The destructuring below is **exhaustive and carries no `..`**, which is
    /// the mechanism behind
    /// `meter_record_contains_no_url_path_or_host_field`: adding a
    /// `pub host: String` to the struct either fails to compile here, or — if
    /// the author also wires it through — produces an eighth entry that the
    /// field-set assertion refuses. There is no third outcome in which the new
    /// field ships unnoticed.
    pub fn canonical_fields(&self) -> Vec<(&'static str, String)> {
        let TunnelMeterRecord {
            session_id,
            allowlist_entry_id,
            chunk_index,
            node_reported_from_origin,
            to_consumer,
            declared_body_len,
            sealed_at_unix,
        } = self;
        vec![
            ("session_id", hex_lower(session_id)),
            ("allowlist_entry_id", allowlist_entry_id.to_string()),
            ("chunk_index", chunk_index.to_string()),
            (
                "node_reported_from_origin",
                node_reported_from_origin.to_string(),
            ),
            ("to_consumer", to_consumer.to_string()),
            ("declared_body_len", declared_body_len.to_string()),
            ("sealed_at_unix", sealed_at_unix.to_string()),
        ]
    }

    /// SHA3-256 over the context and every field, big-endian.
    ///
    /// Built from [`Self::canonical_fields`]' own field list rather than from a
    /// second hand-written sequence, so a field that reaches the record but not
    /// the hash is not expressible.
    pub fn record_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(METER_RECORD_CONTEXT);
        for (name, value) in self.canonical_fields() {
            h.update((name.len() as u32).to_be_bytes());
            h.update(name.as_bytes());
            h.update((value.len() as u32).to_be_bytes());
            h.update(value.as_bytes());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }
}

/// A gateway signature over one [`TunnelMeterRecord`].
#[derive(Clone, Copy)]
pub struct SignedTunnelMeterRecord {
    /// The hash that was signed. Never trusted on its own — see
    /// [`verify_meter_record`].
    pub record_hash: [u8; 32],
    /// The gateway's ML-DSA-65 identity public key.
    pub gateway_identity_pk: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
    /// The ML-DSA-65 signature over [`meter_preimage`].
    pub signature: [u8; ML_DSA_65_SIGNATURE_LEN],
}

impl core::fmt::Debug for SignedTunnelMeterRecord {
    /// Hand-written because 3 309 + 1 952 bytes of derived `Debug` in a test
    /// failure message is not a diagnostic, it is a denial of service against
    /// whoever is reading the output.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedTunnelMeterRecord")
            .field("record_hash", &hex_lower(&self.record_hash))
            .field("gateway_identity_pk_len", &self.gateway_identity_pk.len())
            .field("signature_len", &self.signature.len())
            .finish()
    }
}

impl PartialEq for SignedTunnelMeterRecord {
    fn eq(&self, other: &Self) -> bool {
        self.record_hash == other.record_hash
            && self.gateway_identity_pk == other.gateway_identity_pk
            && self.signature.as_slice() == other.signature.as_slice()
    }
}

impl Eq for SignedTunnelMeterRecord {}

/// The bytes an ML-DSA-65 signature is made over: context ‖ record hash.
pub fn meter_preimage(record_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(METER_RECORD_CONTEXT.len() + 32);
    out.extend_from_slice(METER_RECORD_CONTEXT);
    out.extend_from_slice(record_hash);
    out
}

/// A deterministic ML-DSA-65 signing key from a 32-byte seed.
///
/// Exposed so the gateway's key handling and this crate's integration tests use
/// one construction rather than two.
pub fn gateway_signing_key_from_seed(seed: [u8; 32]) -> SigningKey<MlDsa65> {
    let b = B32::try_from(&seed[..]).expect("a 32-byte seed is a B32");
    SigningKey::<MlDsa65>::from_seed(&b)
}

/// Sign a record with the gateway's identity key.
pub fn sign_meter_record(
    gateway_signer: &SigningKey<MlDsa65>,
    record: &TunnelMeterRecord,
) -> SignedTunnelMeterRecord {
    let record_hash = record.record_hash();
    let sig: Signature<MlDsa65> = gateway_signer.sign(&meter_preimage(&record_hash));
    let enc = sig.encode();
    let mut signature = [0u8; ML_DSA_65_SIGNATURE_LEN];
    signature.copy_from_slice(enc.as_slice());

    let vk: VerifyingKey<MlDsa65> = gateway_signer.verifying_key();
    let enc_vk = vk.encode();
    let mut gateway_identity_pk = [0u8; ML_DSA_65_PUBLIC_KEY_LEN];
    gateway_identity_pk.copy_from_slice(enc_vk.as_slice());

    SignedTunnelMeterRecord {
        record_hash,
        gateway_identity_pk,
        signature,
    }
}

/// Verify a record against a gateway signature.
///
/// Recomputes the hash from `record` rather than trusting `signed.record_hash`,
/// so a tampered record cannot ride a valid signature over the original hash.
pub fn verify_meter_record(record: &TunnelMeterRecord, signed: &SignedTunnelMeterRecord) -> bool {
    let recomputed = record.record_hash();
    if recomputed != signed.record_hash {
        return false;
    }
    let Ok(enc_vk) =
        EncodedVerifyingKey::<MlDsa65>::try_from(signed.gateway_identity_pk.as_slice())
    else {
        return false;
    };
    let vk = VerifyingKey::<MlDsa65>::decode(&enc_vk);
    let Ok(enc_sig) = EncodedSignature::<MlDsa65>::try_from(signed.signature.as_slice()) else {
        return false;
    };
    let Some(sig) = Signature::<MlDsa65>::decode(&enc_sig) else {
        return false;
    };
    vk.verify(&meter_preimage(&recomputed), &sig).is_ok()
}

/// The gateway's accumulator for one receipt chunk.
///
/// `observe` takes the **body slice handed into the tunnel** and counts its
/// length. That is the seam, and taking the slice rather than a number is what
/// makes it hard to count the wrong thing: a caller that wanted wire bytes
/// would have to construct the wire form and pass it here, which does not read
/// like an accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewaySessionMeter {
    session_id: [u8; 32],
    allowlist_entry_id: u32,
    chunk_index: u32,
    declared_body_len: u64,
    observed_to_consumer: u64,
    node_reported_from_origin: u64,
}

impl GatewaySessionMeter {
    /// A meter for one chunk, before any byte has crossed.
    pub fn new(
        session_id: [u8; 32],
        allowlist_entry_id: u32,
        chunk_index: u32,
        declared_body_len: u64,
    ) -> Self {
        Self {
            session_id,
            allowlist_entry_id,
            chunk_index,
            declared_body_len,
            observed_to_consumer: 0,
            node_reported_from_origin: 0,
        }
    }

    /// Count one body slice as it crosses into the tunnel.
    ///
    /// Overflow is a refusal, not a wrap and not a saturation: a counter that
    /// silently stops counting is a counter that under-reports for the rest of
    /// the session.
    pub fn observe(&mut self, body: &[u8]) -> Result<(), TunnelError> {
        self.observed_to_consumer = self
            .observed_to_consumer
            .checked_add(body.len() as u64)
            .ok_or(TunnelError::MeterCounterOverflow)?;
        Ok(())
    }

    /// Record the node's claim about the origin leg.
    ///
    /// Deliberately a separate call with a name that says whose number it is.
    /// Nothing checks it and nothing settles on it.
    pub fn accept_node_report(&mut self, node_reported_from_origin: u64) {
        self.node_reported_from_origin = node_reported_from_origin;
    }

    /// The witnessed count so far.
    pub fn observed_to_consumer(&self) -> u64 {
        self.observed_to_consumer
    }

    /// The node's claim so far. Never a payout basis.
    pub fn node_reported_from_origin(&self) -> u64 {
        self.node_reported_from_origin
    }

    /// Seal the witnessed count into a record.
    ///
    /// The witnessed count is bounded by the node's declaration plus
    /// [`BODY_OVERRUN_ALLOWANCE_BYTES`], and exceeding it is a **refusal**:
    /// never a clamp, never a truncation to the declared length. A clamp would
    /// turn a node that over-sent into a node that settled at exactly its
    /// declaration, which is indistinguishable from an honest session.
    ///
    /// The bound is on the witnessed count only. The node's origin-leg claim is
    /// carried through untouched however large it is, because bounding it would
    /// imply the gateway had grounds to judge it, and it has none.
    pub fn seal(&self, sealed_at_unix: u64) -> Result<TunnelMeterRecord, TunnelError> {
        let ceiling = self
            .declared_body_len
            .checked_add(BODY_OVERRUN_ALLOWANCE_BYTES)
            .ok_or(TunnelError::MeterCounterOverflow)?;
        if self.observed_to_consumer > ceiling {
            return Err(TunnelError::MeteredBytesExceedDeclared {
                observed: self.observed_to_consumer,
                declared: self.declared_body_len,
                allowance: BODY_OVERRUN_ALLOWANCE_BYTES,
            });
        }
        Ok(TunnelMeterRecord {
            session_id: self.session_id,
            allowlist_entry_id: self.allowlist_entry_id,
            chunk_index: self.chunk_index,
            node_reported_from_origin: self.node_reported_from_origin,
            to_consumer: self.observed_to_consumer,
            declared_body_len: self.declared_body_len,
            sealed_at_unix,
        })
    }
}

/// Lower-case hex, so the crate does not take a dependency to print 32 bytes.
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("nibble"));
        s.push(char::from_digit((b & 0x0F) as u32, 16).expect("nibble"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    // ------------------------------------------------------------------
    // The cross-process fixture
    // ------------------------------------------------------------------

    /// The fixture that pins the one quantity both counters observe.
    ///
    /// Read rather than restated. A constant copied into this file would be a
    /// second declaration of the number the fixture exists to make single.
    fn fixture_text() -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("goat-proxy-worker")
            .join("fixtures")
            .join("metered-quantity.json");
        fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "the cross-process metered-quantity fixture must be readable at {}: {e}",
                path.display()
            )
        })
    }

    /// The string value of one top-level key, without taking a JSON dependency
    /// on a crate that ships no JSON.
    ///
    /// The needle carries the colon deliberately. `body_bytes_to_consumer` is
    /// also a *value* in this fixture — it is what `metered_quantity` names —
    /// so a needle of just the quoted token finds the wrong occurrence and
    /// walks off into the fixture's prose note.
    fn fixture_str(text: &str, key: &str) -> Option<String> {
        let needle = format!("\"{key}\":");
        let at = text.find(&needle)? + needle.len();
        let rest = &text[at..];
        let open = rest.find('"')?;
        let rest = &rest[open + 1..];
        let close = rest.find('"')?;
        Some(rest[..close].to_string())
    }

    fn fixture_u64(text: &str, key: &str) -> u64 {
        fixture_str(text, key)
            .unwrap_or_else(|| panic!("fixture key {key} is absent"))
            .parse()
            .unwrap_or_else(|e| panic!("fixture key {key} is not an integer: {e}"))
    }

    /// The `chunk_sizes` array, as numbers.
    fn fixture_chunk_sizes(text: &str) -> Vec<u64> {
        let at = text.find("\"chunk_sizes\"").expect("chunk_sizes key");
        let open = text[at..].find('[').expect("chunk_sizes array") + at;
        let close = text[open..].find(']').expect("chunk_sizes array end") + open;
        text[open..close]
            .split('"')
            .filter_map(|s| s.trim().parse::<u64>().ok())
            .collect()
    }

    fn meter_at(declared: u64) -> GatewaySessionMeter {
        GatewaySessionMeter::new([0x5Au8; 32], 7, 3, declared)
    }

    // ------------------------------------------------------------------
    // The metered quantity
    // ------------------------------------------------------------------

    /// The one number the attestor's stage 10 compares at strict equality
    /// against the operator's claim, produced here from the gateway's own
    /// counting.
    ///
    /// **Mutations this detects:** counting wire bytes, socket bytes, response
    /// head bytes or chunk framing bytes in `observe`; settling on the node's
    /// origin-leg claim; and any drift of the metered seam away from the decoded
    /// body.
    #[test]
    fn the_payout_basis_is_the_gateway_observed_to_consumer_count() {
        let text = fixture_text();

        // Positive control on the reader itself: it can find a key whose value
        // this test knows independently, and it answers `None` for a key that
        // is not there. Without both, "the numbers agree" could be two
        // `unwrap_or(0)`s agreeing.
        assert_eq!(
            fixture_str(&text, "metered_quantity").as_deref(),
            Some(METERED_QUANTITY),
            "the fixture names a different metered quantity than this module does"
        );
        assert_eq!(fixture_str(&text, "no_such_key_in_the_fixture"), None);

        let body_bytes = fixture_u64(&text, "body_bytes_to_consumer");
        let gateway_side = fixture_u64(&text, "gateway_to_consumer");
        let socket_bytes = fixture_u64(&text, "origin_socket_bytes");
        let head = fixture_u64(&text, "response_head_bytes");
        let framing = fixture_u64(&text, "chunk_framing_bytes");
        let chunks = fixture_chunk_sizes(&text);
        assert_eq!(chunks.len(), 3, "the fixture's chunk list did not parse");
        assert_eq!(
            chunks.iter().sum::<u64>(),
            body_bytes,
            "the fixture's own chunk sizes do not sum to its body count"
        );
        assert_ne!(
            socket_bytes, body_bytes,
            "the fixture's negative control is not distinguishable from its positive one"
        );

        // The gateway counts the decoded body slices as they cross.
        let mut meter = meter_at(body_bytes);
        for size in &chunks {
            meter.observe(&vec![0xABu8; *size as usize]).unwrap();
        }
        // The node's claim about a leg nobody witnesses: the socket count.
        meter.accept_node_report(socket_bytes);
        let record = meter.seal(1_800_000_000).unwrap();

        assert_eq!(
            record.to_consumer, body_bytes,
            "the witness counted something other than {METERED_QUANTITY}"
        );
        assert_eq!(
            record.to_consumer, gateway_side,
            "the gateway's count and the fixture's gateway column disagree, so the attestor's \
             strict-equality stage would refuse an honest session"
        );
        assert_ne!(
            record.to_consumer, socket_bytes,
            "the witness counted socket bytes: head and chunk framing leaked into the payout basis"
        );
        assert_ne!(record.to_consumer, body_bytes + framing);
        assert_ne!(record.to_consumer, body_bytes + framing + head);
        assert_eq!(
            record.node_reported_from_origin, socket_bytes,
            "the node's claim must be carried through unchanged"
        );
        assert_ne!(
            record.to_consumer, record.node_reported_from_origin,
            "the two counts collapsed onto one number, so the asymmetry this record exists to \
             record is gone"
        );
    }

    /// The seam is the body slice, not the frame that carries it.
    ///
    /// **Mutations this detects:** adding the frame header or the AEAD tag to
    /// the observed count — the exact drift that turns a strict-equality
    /// comparison into a permanent mismatch of 26 bytes per frame.
    #[test]
    fn the_meter_counts_body_bytes_not_wire_bytes() {
        use crate::frame::{MAX_FRAME_WIRE, TUNNEL_FRAME_HEADER_LEN};

        let body = vec![0x11u8; 1_000];
        let mut meter = meter_at(1_000);
        meter.observe(&body).unwrap();
        assert_eq!(meter.observed_to_consumer(), 1_000);

        // Positive control: the wire form of that body is demonstrably longer,
        // so "1000, not the wire length" is a statement about two different
        // numbers.
        let wire_len = TUNNEL_FRAME_HEADER_LEN + body.len() + 16;
        assert!(wire_len > body.len());
        assert!(wire_len <= MAX_FRAME_WIRE);
        assert_ne!(meter.observed_to_consumer(), wire_len as u64);

        // And an empty observation moves nothing.
        meter.observe(&[]).unwrap();
        assert_eq!(meter.observed_to_consumer(), 1_000);
    }

    /// **Mutations this detects:** renaming the metered quantity on one side of
    /// the process boundary only.
    #[test]
    fn the_metered_quantity_name_matches_the_cross_process_fixture() {
        let text = fixture_text();
        assert_eq!(METERED_QUANTITY, "body_bytes_to_consumer");
        assert_eq!(
            fixture_str(&text, "metered_quantity").as_deref(),
            Some(METERED_QUANTITY)
        );
        // The fixture also names the wrong seam, on purpose. If that negative
        // control ever disappears, this crate's tests lose the only thing that
        // distinguishes "counted the body" from "counted whatever was there".
        assert!(
            text.contains("origin_socket_bytes"),
            "the fixture's negative control is gone"
        );
    }

    // ------------------------------------------------------------------
    // The sanity bound
    // ------------------------------------------------------------------

    /// **Mutations this detects:** dropping the ceiling check; clamping the
    /// witnessed count to the declared length instead of refusing; sealing the
    /// node's origin-leg claim as `to_consumer`; and widening the allowance
    /// past one frame.
    #[test]
    fn metered_bytes_never_exceed_declared_plus_allowance() {
        assert_eq!(BODY_OVERRUN_ALLOWANCE_BYTES, MAX_FRAME_PAYLOAD as u64);
        let declared = 10_000u64;

        // Positive control 1: an exact session seals, and seals the number that
        // was observed.
        let mut exact = meter_at(declared);
        exact.observe(&vec![0u8; declared as usize]).unwrap();
        exact.accept_node_report(declared * 10);
        let sealed = exact.seal(1_700_000_000).unwrap();
        assert_eq!(
            sealed.to_consumer, declared,
            "the sealed count is not the witnessed count"
        );
        assert_eq!(sealed.declared_body_len, declared);
        assert_eq!(
            sealed.node_reported_from_origin,
            declared * 10,
            "a node claim far above the ceiling must be carried, not bounded"
        );

        // Positive control 2: exactly at the bound still seals.
        let mut at_bound = meter_at(declared);
        at_bound
            .observe(&vec![
                0u8;
                (declared + BODY_OVERRUN_ALLOWANCE_BYTES) as usize
            ])
            .unwrap();
        assert_eq!(
            at_bound.seal(1).unwrap().to_consumer,
            declared + BODY_OVERRUN_ALLOWANCE_BYTES
        );

        // One byte past it is a refusal, not a clamp.
        let mut over = meter_at(declared);
        over.observe(&vec![
            0u8;
            (declared + BODY_OVERRUN_ALLOWANCE_BYTES + 1) as usize
        ])
        .unwrap();
        assert_eq!(
            over.seal(1),
            Err(TunnelError::MeteredBytesExceedDeclared {
                observed: declared + BODY_OVERRUN_ALLOWANCE_BYTES + 1,
                declared,
                allowance: BODY_OVERRUN_ALLOWANCE_BYTES,
            }),
            "an over-sending session was accepted, or was clamped to the declared length"
        );
    }

    /// **Mutations this detects:** replacing `checked_add` with a wrapping or
    /// saturating add in either the counter or the ceiling, so a counter that
    /// cannot count any further reports a small number instead of refusing.
    #[test]
    fn the_meter_refuses_a_counter_overflow_rather_than_wrapping() {
        // The ceiling arithmetic: a declaration near `u64::MAX` cannot have the
        // allowance added to it.
        let huge = meter_at(u64::MAX - 1);
        assert_eq!(huge.seal(1), Err(TunnelError::MeterCounterOverflow));

        // Positive control: the same declaration one allowance lower is fine.
        let ok = meter_at(u64::MAX - BODY_OVERRUN_ALLOWANCE_BYTES);
        assert!(ok.seal(1).is_ok());
    }

    // ------------------------------------------------------------------
    // Privacy of the record's field set
    // ------------------------------------------------------------------

    /// A **field-set** assertion, not a value assertion.
    ///
    /// **Mutations this detects:** adding a `pub host: String`, a `url`, a
    /// `path`, a `query` or a header field to [`TunnelMeterRecord`] — either as
    /// a compile error in `canonical_fields`, whose destructuring is exhaustive
    /// and carries no `..`, or as an eighth entry here; and reordering the
    /// serialised field list out of step with [`METER_RECORD_FIELDS`].
    #[test]
    fn meter_record_contains_no_url_path_or_host_field() {
        let record = meter_at(64).seal(1_700_000_000).unwrap();
        let fields = record.canonical_fields();
        let names: Vec<&str> = fields.iter().map(|(n, _)| *n).collect();

        assert_eq!(
            names,
            METER_RECORD_FIELDS.to_vec(),
            "the serialised field set is not the declared field set"
        );
        assert_eq!(fields.len(), 7);

        // Assembled at runtime so this file does not itself contain the tokens
        // it forbids as field names.
        let forbidden: Vec<String> = ["ho", "ur", "pa", "que", "hea", "coo", "ip"]
            .iter()
            .zip(["st", "l", "th", "ry", "der", "kie", "_address"].iter())
            .map(|(a, b)| format!("{a}{b}"))
            .collect();

        // Positive control: the matcher fires on a field set that DOES carry a
        // destination, so the clean result below is not a broken scanner.
        let control = ["session_id", "host", "url"];
        assert!(
            control
                .iter()
                .any(|n| forbidden.iter().any(|t| n.contains(t.as_str()))),
            "the scanner cannot see a destination field in its own control set"
        );

        for name in &names {
            for token in &forbidden {
                assert!(
                    !name.contains(token.as_str()),
                    "{name} can carry a destination; a meter record is byte counts and opaque \
                     identifiers only"
                );
            }
        }

        // And every value is an integer or a fixed-width hex identifier —
        // nothing that could hold a name.
        for (name, value) in &fields {
            if *name == "session_id" {
                assert_eq!(value.len(), 64, "session_id is not 32 hex-encoded bytes");
                assert!(value.chars().all(|c| c.is_ascii_hexdigit()));
            } else {
                assert!(
                    value.parse::<u64>().is_ok(),
                    "{name} carries {value}, which is not an integer"
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // Signature
    // ------------------------------------------------------------------

    /// **Mutations this detects:** verifying against `signed.record_hash`
    /// instead of recomputing from the record, which accepts any tampered
    /// record that ships its original hash; and dropping the hash comparison
    /// altogether.
    #[test]
    fn a_tampered_record_cannot_ride_a_valid_signature_over_the_original_hash() {
        let key = gateway_signing_key_from_seed([0x0Cu8; 32]);
        let record = meter_at(4_096).seal(1_700_000_000).unwrap();
        let signed = sign_meter_record(&key, &record);

        // Positive control: untouched, it verifies.
        assert!(
            verify_meter_record(&record, &signed),
            "an honest record did not verify, so the refusals below prove nothing"
        );

        // Every field, one at a time. A record whose payout basis has been
        // raised is the case that matters, and it is not special-cased.
        let mut mutants = Vec::new();
        for i in 0..7 {
            let mut m = record;
            match i {
                0 => m.session_id[0] ^= 0x01,
                1 => m.allowlist_entry_id += 1,
                2 => m.chunk_index += 1,
                3 => m.node_reported_from_origin += 1,
                4 => m.to_consumer += 1,
                5 => m.declared_body_len += 1,
                _ => m.sealed_at_unix += 1,
            }
            mutants.push(m);
        }
        for (i, m) in mutants.iter().enumerate() {
            assert_ne!(*m, record, "mutant {i} is not a mutation");
            assert!(
                !verify_meter_record(m, &signed),
                "field {} was changed and the original signature still verified",
                METER_RECORD_FIELDS[i]
            );
        }
    }

    /// **Mutations this detects:** ignoring the public key carried in the
    /// signed object, accepting a malformed key or signature encoding as valid,
    /// or verifying over a preimage that omits the domain context.
    #[test]
    fn a_foreign_gateway_key_does_not_verify_a_record() {
        let real = gateway_signing_key_from_seed([1u8; 32]);
        let foreign = gateway_signing_key_from_seed([2u8; 32]);
        let record = meter_at(1_024).seal(42).unwrap();

        let signed = sign_meter_record(&real, &record);
        assert!(verify_meter_record(&record, &signed));

        // Same record, different signer: the signature is over the same
        // preimage but by the wrong key.
        let mut swapped = signed;
        let other = sign_meter_record(&foreign, &record);
        swapped.gateway_identity_pk = other.gateway_identity_pk;
        assert!(
            !verify_meter_record(&record, &swapped),
            "a signature verified under a key that did not make it"
        );

        // And the foreign signature under the real key is equally refused.
        let mut crossed = other;
        crossed.gateway_identity_pk = signed.gateway_identity_pk;
        assert!(!verify_meter_record(&record, &crossed));
    }

    /// **Mutations this detects:** panicking on a malformed encoding instead of
    /// refusing (a remote input reaching an `expect`), and treating a truncated
    /// or zeroed signature as absent-but-fine.
    #[test]
    fn a_signed_record_verifies_and_a_malformed_signature_is_refused() {
        let key = gateway_signing_key_from_seed([9u8; 32]);
        let record = meter_at(512).seal(7).unwrap();
        let signed = sign_meter_record(&key, &record);
        assert!(verify_meter_record(&record, &signed));
        assert_eq!(signed.record_hash, record.record_hash());
        assert_eq!(signed.signature.len(), ML_DSA_65_SIGNATURE_LEN);
        assert_eq!(signed.gateway_identity_pk.len(), ML_DSA_65_PUBLIC_KEY_LEN);

        let mut zeroed = signed;
        zeroed.signature = [0u8; ML_DSA_65_SIGNATURE_LEN];
        assert!(!verify_meter_record(&record, &zeroed));

        let mut zero_key = signed;
        zero_key.gateway_identity_pk = [0u8; ML_DSA_65_PUBLIC_KEY_LEN];
        assert!(!verify_meter_record(&record, &zero_key));

        let mut wrong_hash = signed;
        wrong_hash.record_hash[31] ^= 0xFF;
        assert!(!verify_meter_record(&record, &wrong_hash));
    }

    /// **Mutations this detects:** leaving a field out of the hash preimage, so
    /// two records that differ in it share a signature; and hashing the field
    /// values without their names or lengths, which makes
    /// `("ab", "c")` and `("a", "bc")` collide.
    #[test]
    fn the_record_hash_covers_every_field() {
        let base = meter_at(4_096).seal(1_700_000_000).unwrap();
        let mut hashes = vec![base.record_hash()];
        for (i, field) in METER_RECORD_FIELDS.iter().enumerate() {
            let mut m = base;
            match i {
                0 => m.session_id[31] ^= 0x80,
                1 => m.allowlist_entry_id += 1,
                2 => m.chunk_index += 1,
                3 => m.node_reported_from_origin += 1,
                4 => m.to_consumer += 1,
                5 => m.declared_body_len += 1,
                _ => m.sealed_at_unix += 1,
            }
            let h = m.record_hash();
            assert!(
                !hashes.contains(&h),
                "changing {field} did not change the record hash, so it is outside the preimage"
            );
            hashes.push(h);
        }

        // Positive control on the comparison: the same record hashes the same
        // way twice, so "all different" above is not an artefact of a
        // non-deterministic hash.
        assert_eq!(base.record_hash(), base.record_hash());
        assert_eq!(hashes.len(), 8);

        // Length-prefixing, asserted on the value: two records whose field
        // strings concatenate identically must still differ.
        let mut a = base;
        let mut b = base;
        a.allowlist_entry_id = 1;
        a.chunk_index = 23;
        b.allowlist_entry_id = 12;
        b.chunk_index = 3;
        assert_ne!(
            a.record_hash(),
            b.record_hash(),
            "the preimage is not length-prefixed: two field splits collided"
        );
    }

    // ------------------------------------------------------------------
    // Source sweeps
    // ------------------------------------------------------------------

    /// Every `.rs` file this crate ships, minus its trailing test module. Same
    /// construction as `channel.rs`'s, and deliberately not shared: a sweep
    /// helper imported from another module's `#[cfg(test)]` tree is a helper
    /// that can be narrowed once and weaken three tests.
    fn production_sources() -> Vec<(String, String)> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut paths = Vec::new();
        collect_rs(&dir, &mut paths);
        paths.sort();
        paths
            .into_iter()
            .map(|p| {
                let text = fs::read_to_string(&p).expect("read source");
                let name = p
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("?")
                    .to_string();
                let marker = "\n#[cfg(test)]\nmod tests {";
                let prod = match text.rfind(marker) {
                    Some(i) => text[..i].to_string(),
                    None => text,
                };
                (name, prod)
            })
            .collect()
    }

    fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                collect_rs(&path, out);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    /// Raised in the same commit as the task that adds the next source file.
    const TUNNEL_SRC_FILES_AT_THIS_TASK: usize = 14;
    /// See the same constant in `channel.rs` for why the floor sits where it
    /// does.
    const MIN_SWEPT_PRODUCTION_BYTES: usize = 120_000;

    /// The design term is **allowlist**; the refusal set is the **deny-net**.
    ///
    /// **Mutations this detects:** introducing any of the three tokens a
    /// permit/refuse list is normally called into an identifier, a string
    /// literal, a comment or a doc comment anywhere in this crate's production
    /// source; and narrowing the sweep, since both floors are asserted before
    /// the absence is.
    #[test]
    fn the_tunnel_crate_uses_allowlist_and_deny_net_vocabulary_only() {
        // Assembled at runtime so this file does not itself contain the
        // literals it forbids.
        let forbidden: Vec<String> = vec![
            format!("{}{}", "block", "list"),
            format!("{}{}", "black", "list"),
            format!("{}{}", "white", "list"),
        ];
        // The approved half of the vocabulary, used as a second positive
        // control below. Only `allowlist` is checked: the **deny-net** is the
        // worker's refusal set and has no referent in this crate — the tunnel
        // carries an entry id and never sees a destination — so requiring the
        // word here would be requiring a file to say something untrue.
        let approved = ["allowlist"];

        let sources = production_sources();
        assert_eq!(
            sources.len(),
            TUNNEL_SRC_FILES_AT_THIS_TASK,
            "the sweep saw {} source file(s), not {}. If a file was added, raise the constant in \
             the same commit; do not lower it to meet a red floor",
            sources.len(),
            TUNNEL_SRC_FILES_AT_THIS_TASK
        );
        let total: usize = sources.iter().map(|(_, t)| t.len()).sum();
        assert!(
            total >= MIN_SWEPT_PRODUCTION_BYTES,
            "the sweep read only {total} byte(s) of production text, below the \
             {MIN_SWEPT_PRODUCTION_BYTES} floor"
        );

        // Positive control: the same matcher over text that does carry the
        // tokens must fire.
        let control = forbidden.join(" and ");
        for token in &forbidden {
            assert!(
                control.to_ascii_lowercase().contains(token.as_str()),
                "the scanner cannot see its own control string"
            );
        }
        // Second positive control: the approved vocabulary IS present in the
        // swept text, so a sweep reading nothing at all cannot pass.
        let joined: String = sources
            .iter()
            .map(|(_, t)| t.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join("\n");
        for word in approved {
            assert!(
                joined.contains(word),
                "the swept text does not contain {word}, so the sweep is reading the wrong thing"
            );
        }

        for (name, text) in &sources {
            let lower = text.to_ascii_lowercase();
            for token in &forbidden {
                assert!(
                    !lower.contains(token.as_str()),
                    "{name} uses retired list vocabulary; the design term is allowlist and the \
                     refusal set is the deny-net"
                );
            }
        }
    }

    /// The attestor's payout arithmetic never reads the node's origin-leg
    /// claim.
    ///
    /// A **source** assertion over the two attestor files that decide what an
    /// operator is owed. Neither may name `node_reported_from_origin`: the
    /// moment either does, the origin leg has become a settlement input and
    /// nothing witnesses it.
    ///
    /// # Why the positive control is a real file
    ///
    /// A synthetic control string proves the substring search works. It does
    /// not prove the reader is reading the attestor. `verify.rs` — which
    /// carries the field for diagnostics and is checked here to still do so —
    /// is the control that proves both at once: same reader, same needle, a
    /// file that must match. If a future edit moved the payout basis onto the
    /// origin claim, that edit would land in one of the two swept files and
    /// this test would red.
    ///
    /// **Mutations this detects:** switching the attestor's payout basis to
    /// `node_reported_from_origin` in `aggregate.rs` or `challenger.rs`;
    /// narrowing this sweep to nothing (the file count and byte floor are
    /// asserted first).
    #[test]
    fn node_reported_from_origin_is_never_read_by_any_payout_path() {
        let proxy = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("goat-attestor")
            .join("src")
            .join("proxy");

        let needle = format!("{}{}", "node_reported", "_from_origin");

        // The payout paths: aggregation decides the split, the challenger
        // decides whether to dispute it.
        let payout_paths = ["aggregate.rs", "challenger.rs"];
        let mut swept: Vec<(String, String)> = Vec::new();
        for name in payout_paths {
            let path = proxy.join(name);
            let text = fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!(
                    "the attestor's payout path {} must be readable at {}: {e}",
                    name,
                    path.display()
                )
            });
            swept.push((name.to_string(), text));
        }

        // Floors first: a sweep that read nothing would report a clean result.
        assert_eq!(swept.len(), payout_paths.len());
        let total: usize = swept.iter().map(|(_, t)| t.len()).sum();
        assert!(
            total >= 90_000,
            "the sweep read only {total} byte(s) of the attestor's payout paths; measured 112 018 \
             at this task, so a number this low means it is reading stubs"
        );

        // Positive control, on a real file with the same reader and the same
        // needle: `verify.rs` carries the field and must be seen to carry it.
        let control = fs::read_to_string(proxy.join("verify.rs")).expect("read verify.rs");
        assert!(
            control.contains(&needle),
            "the reader cannot find {needle} in a file that demonstrably contains it, so its \
             absence elsewhere means nothing"
        );

        for (name, text) in &swept {
            assert!(
                !text.contains(&needle),
                "{name} reads {needle}. That number is re-signed by the gateway, not witnessed by \
                 it, and no payout path may depend on it"
            );
        }
    }
}
