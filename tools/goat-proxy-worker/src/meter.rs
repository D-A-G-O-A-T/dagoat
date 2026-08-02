//! Byte metering. **Drafts only.**
//!
//! # The boundary, stated so the two lanes do not both implement it
//!
//! This module produces [`ChunkReceiptDraft`]s and stops. It does not
//! canonicalise, it does not hash, it does not sign, it does not counter-sign,
//! it does not aggregate, it does not decide a payout and it never touches a
//! chain. Canonicalisation — `bytes_transferred` rendered as a decimal
//! **string**, under the restricted RFC 8785 subset that refuses JSON numbers —
//! and signing belong to the attestor's proxy receipt module, which owns the
//! typehashes and the Merkle tree. A test sweeps this file's own source and
//! fails if a signing or settlement API appears in it.
//!
//! # ONE quantity, at ONE seam
//!
//! [`SessionMeter::observe`] receives **`body_bytes_to_consumer`** and nothing
//! else: response body octets, after HTTP framing is stripped and chunked
//! transfer-encoding is decoded, as they are handed into the tunnel. It is
//! **not** the socket counter, which includes TLS records, MACs, the handshake
//! and the outbound request, and which the gateway's counter cannot possibly
//! match.
//!
//! That distinction is what makes the epoch challenge defensible at **strict
//! equality with no tolerance parameter**. Strict equality over two *different*
//! seams — TLS record bytes on the origin socket versus AEAD-framed tunnel
//! bytes — would challenge every honest epoch and forfeit the proposer's bond
//! every time; that is a bug in the comparison, not a reason for a tolerance.
//! A tolerance is an inflation budget with a published size; the correct value
//! is zero and the correct implementation of zero is no parameter at all.
//!
//! `fixtures/metered-quantity.json` pins the number for a known payload and
//! records the socket total beside it as a **negative control**, so a meter
//! that drifts back onto the socket is caught by a red test instead of by a
//! forfeited bond.
//!
//! # What the origin leg is, and is not
//!
//! [`SessionMeter::node_reported_from_origin`] is carried because it is a
//! useful operational figure. It is **never a payout basis**: nothing witnesses
//! the origin leg, so it is a node assertion and no draft field derives from
//! it. A test asserts the drafts are identical whether or not it was recorded.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Task 35 and its Security invariants section (INV-11, INV-17); and the
//! "Residential Proxy Network (P3) Implementation Plan", §4.1 (the
//! metered-quantity row).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// The receipt chunk size, mirrored from the attestor and pinned against its
/// fixture by a test in this module. Defined once there, mirrored once here.
pub const CHUNK_BYTES: u64 = 10_485_760;

/// Which kind of chunk a draft describes.
///
/// An [`ChunkKind::Interim`] chunk is **exactly** [`CHUNK_BYTES`]; a
/// [`ChunkKind::Final`] chunk is `1..=CHUNK_BYTES`. Zero is refused in both
/// arms: a zero-byte receipt is a signature over nothing that still occupies a
/// row and a sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkKind {
    Interim,
    Final,
}

impl ChunkKind {
    /// The canonical spelling the attestor's receipt carries.
    pub fn as_str(self) -> &'static str {
        match self {
            ChunkKind::Interim => "INTERIM",
            ChunkKind::Final => "FINAL",
        }
    }
}

/// A monotonic counter shared across every session in this process.
///
/// The counter is an anti-replay ordinal, not a byte count. It is shared
/// because a per-session counter that restarts at zero lets two sessions
/// produce two drafts with the same ordinal.
#[derive(Debug, Clone, Default)]
pub struct MeterCounter(Arc<AtomicU64>);

impl MeterCounter {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU64::new(0)))
    }

    /// The next ordinal. Starts at 1; `0` names no draft.
    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// The highest ordinal handed out so far.
    pub fn issued(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// One chunk, ready for the attestor to canonicalise and the operator to sign.
///
/// **Every field is a byte count, an integer identifier or a closed enum.**
/// There is no host, no address, no port, no path, no query string, no header
/// and no body byte, and there is no field that could hold one (INV-11,
/// receipt half). The destination is the allowlist **entry id** and nothing
/// else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkReceiptDraft {
    pub session_id: [u8; 32],
    pub chunk_seq: u64,
    pub chunk_kind: ChunkKind,
    pub allowlist_entry_id: u32,
    pub bytes_transferred: u64,
    pub counter: u64,
    pub sealed_at_unix: u64,
}

/// Counts one session's `body_bytes_to_consumer` and seals it into drafts.
#[derive(Debug)]
pub struct SessionMeter {
    session_id: [u8; 32],
    allowlist_entry_id: u32,
    counter: MeterCounter,
    /// Every byte observed at the one seam, for the life of the session.
    observed_total: u64,
    /// Observed but not yet sealed into a draft.
    pending: u64,
    /// Carried, never a payout basis. See the module header.
    node_reported_from_origin: u64,
    drafts: Vec<ChunkReceiptDraft>,
    sealed: bool,
}

impl SessionMeter {
    pub fn new(session_id: [u8; 32], allowlist_entry_id: u32, counter: MeterCounter) -> Self {
        Self {
            session_id,
            allowlist_entry_id,
            counter,
            observed_total: 0,
            pending: 0,
            node_reported_from_origin: 0,
            drafts: Vec::new(),
            sealed: false,
        }
    }

    /// Observe `body_bytes_to_consumer`, sealing an interim draft each time a
    /// whole chunk has accumulated.
    ///
    /// `now_unix` is a parameter rather than a call into the clock so the seam
    /// a test replaces is explicit; nothing else about this function is
    /// replaceable.
    pub fn observe(&mut self, bytes: u64, now_unix: u64) {
        if self.sealed || bytes == 0 {
            return;
        }
        self.observed_total = self.observed_total.saturating_add(bytes);
        self.pending = self.pending.saturating_add(bytes);
        while self.pending >= CHUNK_BYTES {
            self.pending -= CHUNK_BYTES;
            self.push_draft(CHUNK_BYTES, ChunkKind::Interim, now_unix);
        }
    }

    /// Record what the node believes came off the origin leg. Operational only.
    pub fn note_origin_bytes(&mut self, bytes: u64) {
        self.node_reported_from_origin = self.node_reported_from_origin.saturating_add(bytes);
    }

    /// Close the session.
    ///
    /// A session that moved zero bytes emits **no** drafts at all rather than
    /// one empty one. At an exact multiple of [`CHUNK_BYTES`] the last interim
    /// chunk becomes the session's single `Final` — never a trailing zero-byte
    /// chunk appended after it.
    pub fn seal_final(&mut self, now_unix: u64) -> &[ChunkReceiptDraft] {
        if self.sealed {
            return &self.drafts;
        }
        self.sealed = true;
        if self.observed_total == 0 {
            return &self.drafts;
        }
        if self.pending > 0 {
            let remainder = self.pending;
            self.pending = 0;
            self.push_draft(remainder, ChunkKind::Final, now_unix);
        } else if let Some(last) = self.drafts.last_mut() {
            last.chunk_kind = ChunkKind::Final;
        }
        &self.drafts
    }

    fn push_draft(&mut self, bytes: u64, kind: ChunkKind, now_unix: u64) {
        let chunk_seq = self.drafts.len() as u64;
        self.drafts.push(ChunkReceiptDraft {
            session_id: self.session_id,
            chunk_seq,
            chunk_kind: kind,
            allowlist_entry_id: self.allowlist_entry_id,
            bytes_transferred: bytes,
            counter: self.counter.next(),
            sealed_at_unix: now_unix,
        });
    }

    /// The drafts sealed so far, dense and ordered.
    pub fn drafts(&self) -> &[ChunkReceiptDraft] {
        &self.drafts
    }

    /// Every `body_bytes_to_consumer` byte this session observed.
    pub fn observed_total(&self) -> u64 {
        self.observed_total
    }

    /// Carried, never a payout basis.
    pub fn node_reported_from_origin(&self) -> u64 {
        self.node_reported_from_origin
    }

    pub fn is_sealed(&self) -> bool {
        self.sealed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The attestor's pinned receipt fixture, compiled in so a deleted or moved
    /// file is a build failure rather than a skipped test.
    const ATTESTOR_FIXTURE: &str =
        include_str!("../../goat-attestor/fixtures/proxy_receipt_v1.json");
    /// The cross-process metered-quantity pin.
    const QUANTITY_FIXTURE: &str = include_str!("../fixtures/metered-quantity.json");

    fn fixture(text: &str) -> serde_json::Value {
        serde_json::from_str(text).expect("the pinned fixture must be JSON")
    }

    fn fixture_u64(text: &str, key: &str) -> u64 {
        fixture(text)
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("fixture must carry {key:?} as a decimal string"))
            .parse()
            .expect("a decimal integer")
    }

    fn meter() -> SessionMeter {
        SessionMeter::new([0x5E; 32], 7, MeterCounter::new())
    }

    /// One definition, two crates, one pinned fixture.
    ///
    /// Mutations this detects: `CHUNK_BYTES` edited here to 10_000_000 or to
    /// 1 MiB, which would make every draft this crate produces fail the
    /// attestor's chunk-size rule at verification time — after signing, and
    /// after the operator's bond is posted.
    #[test]
    fn chunk_bytes_matches_the_attestor_fixture() {
        assert_eq!(CHUNK_BYTES, 10_485_760);
        assert_eq!(
            CHUNK_BYTES,
            fixture_u64(ATTESTOR_FIXTURE, "chunkBytes"),
            "the worker's mirrored chunk size disagrees with the attestor's pin"
        );
        // POSITIVE CONTROL: the fixture reader can see a value that differs, so
        // the equality above is a comparison and not a tautology.
        assert_ne!(
            CHUNK_BYTES,
            fixture(ATTESTOR_FIXTURE)
                .get("sample")
                .and_then(|s| s.get("bytes_transferred"))
                .and_then(serde_json::Value::as_str)
                .expect("the sample carries a byte count")
                .parse::<u64>()
                .expect("decimal"),
            "the fixture reader is returning the same value for two different keys"
        );
        // The canonical chunk-kind spellings are the attestor's.
        assert_eq!(ChunkKind::Final.as_str(), "FINAL");
        assert_eq!(ChunkKind::Interim.as_str(), "INTERIM");
        assert_eq!(
            ChunkKind::Final.as_str(),
            fixture(ATTESTOR_FIXTURE)
                .get("sample")
                .and_then(|s| s.get("chunk_kind"))
                .and_then(serde_json::Value::as_str)
                .expect("the sample names a chunk kind")
        );
    }

    /// The seven boundary cases, exactly as the attestor states them.
    ///
    /// Mutations this detects: emitting a trailing zero-byte `Final` at an
    /// exact multiple; leaving the LAST chunk `Interim`; emitting more than one
    /// `Final`; an off-by-one in the interim count; a non-dense `chunk_seq`.
    #[test]
    fn sealing_is_exact_at_the_boundary() {
        let cases: [(u64, &[u64]); 7] = [
            (0, &[]),
            (1, &[1]),
            (10_485_759, &[10_485_759]),
            (10_485_760, &[10_485_760]),
            (10_485_761, &[10_485_760, 1]),
            (20_971_520, &[10_485_760, 10_485_760]),
            (20_971_521, &[10_485_760, 10_485_760, 1]),
        ];

        for (total, expected) in cases {
            let mut m = meter();
            m.observe(total, 1_800_000_000);
            let drafts = m.seal_final(1_800_000_100).to_vec();
            let sizes: Vec<u64> = drafts.iter().map(|d| d.bytes_transferred).collect();
            assert_eq!(sizes, expected, "sealing of {total}");

            // The sum is the total, always: a silent byte loss is impossible
            // rather than unlikely.
            assert_eq!(
                sizes.iter().sum::<u64>(),
                total,
                "sealing of {total} lost or invented bytes"
            );

            if total == 0 {
                assert!(drafts.is_empty(), "zero bytes emits no drafts at all");
                continue;
            }

            // Exactly one Final, and it is last.
            let finals = drafts
                .iter()
                .filter(|d| d.chunk_kind == ChunkKind::Final)
                .count();
            assert_eq!(finals, 1, "exactly one FINAL per session, for {total}");
            assert_eq!(
                drafts.last().expect("non-empty").chunk_kind,
                ChunkKind::Final
            );

            // Every non-final chunk is an exact interim chunk, and `chunk_seq`
            // is dense from zero.
            for (i, d) in drafts.iter().enumerate() {
                assert_eq!(d.chunk_seq, i as u64, "chunk_seq is not dense for {total}");
                if i + 1 < drafts.len() {
                    assert_eq!(d.chunk_kind, ChunkKind::Interim);
                    assert_eq!(d.bytes_transferred, CHUNK_BYTES);
                }
            }
        }

        // A one-byte increase past an exact multiple adds exactly one draft,
        // and it is the FINAL one carrying that single byte.
        let mut a = meter();
        a.observe(CHUNK_BYTES, 1);
        assert_eq!(a.seal_final(2).len(), 1);
        let mut b = meter();
        b.observe(CHUNK_BYTES + 1, 1);
        let d = b.seal_final(2);
        assert_eq!(d.len(), 2);
        assert_eq!(d[1].bytes_transferred, 1);
        assert_eq!(d[1].chunk_kind, ChunkKind::Final);

        // Sealing twice is idempotent: a double close does not append.
        let mut c = meter();
        c.observe(10, 1);
        let n = c.seal_final(2).len();
        assert_eq!(c.seal_final(3).len(), n, "a second seal appended a draft");
    }

    /// Mutations this detects: an interim draft sealed on a zero-byte
    /// observation; a `Final` emitted for a session that moved nothing, which
    /// is a signature over nothing occupying a row and a sequence number.
    #[test]
    fn no_zero_byte_draft_is_ever_emitted() {
        // A session that observed nothing at all.
        let mut m = meter();
        assert!(m.seal_final(1).is_empty());

        // A session fed nothing but zeroes.
        let mut m = meter();
        for _ in 0..100 {
            m.observe(0, 1);
        }
        assert!(m.seal_final(2).is_empty());
        assert_eq!(m.observed_total(), 0);

        // POSITIVE CONTROL: one real byte among them does produce a draft, so
        // the emptiness above is a decision and not a meter that never emits.
        let mut m = meter();
        m.observe(0, 1);
        m.observe(1, 1);
        m.observe(0, 1);
        let drafts = m.seal_final(2);
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].bytes_transferred, 1);

        // A long run of chunk-sized observations never produces an empty one.
        let mut m = meter();
        for _ in 0..3 {
            m.observe(CHUNK_BYTES, 1);
        }
        for d in m.seal_final(2) {
            assert!(d.bytes_transferred > 0, "a zero-byte draft was emitted");
        }
    }

    /// Mutations this detects: the counter made per-session, so two sessions
    /// hand out the same ordinal and one draft can replay another; the counter
    /// starting at 0, the value that names no draft.
    #[test]
    fn counter_is_monotonic_across_sessions() {
        let shared = MeterCounter::new();
        let mut seen: Vec<u64> = Vec::new();

        for session in 0..3u8 {
            let mut m = SessionMeter::new([session; 32], 7, shared.clone());
            m.observe(CHUNK_BYTES + 5, 1);
            for d in m.seal_final(2) {
                seen.push(d.counter);
            }
        }

        assert_eq!(seen.len(), 6, "three sessions of two chunks each");
        assert_eq!(seen[0], 1, "the ordinal must start at 1, not 0");
        for w in seen.windows(2) {
            assert!(
                w[1] > w[0],
                "the ordinal went backwards or repeated: {:?}",
                seen
            );
        }
        assert_eq!(shared.issued(), 6);

        // NEGATIVE CONTROL: two INDEPENDENT counters do collide, which is the
        // failure the shared one exists to prevent — so the monotonicity above
        // is a property of sharing and not an accident of ordering.
        let a = MeterCounter::new();
        let b = MeterCounter::new();
        assert_eq!(a.next(), b.next());
    }

    /// INV-11, receipt half, on the type.
    ///
    /// Mutations this detects: a host, an address, a port, a path or a header
    /// added to the draft "for debugging"; the entry id replaced by a name.
    #[test]
    fn a_draft_carries_no_host_path_or_header_field() {
        let mut m = meter();
        m.observe(1_234, 1_800_000_000);
        let drafts = m.seal_final(1_800_000_001).to_vec();
        assert_eq!(drafts.len(), 1, "vacuity guard: nothing to inspect");

        let rendered = format!("{:?}", drafts[0]);
        for poison in [
            "http",
            "://",
            "?",
            "host",
            "path",
            "query",
            "header",
            "cookie",
            "Authorization",
        ] {
            assert!(
                !rendered.to_ascii_lowercase().contains(poison),
                "the draft leaked {poison:?}: {rendered}"
            );
        }

        // The structural half: the struct's own declaration names no free-text
        // or destination-shaped field.
        let src = include_str!("meter.rs");
        let decl = src
            .split("pub struct ChunkReceiptDraft")
            .nth(1)
            .expect("the struct must be findable")
            .split("\n}")
            .next()
            .expect("the struct body must terminate");
        assert!(
            decl.len() > 150,
            "vacuity guard: the struct body did not parse"
        );
        for banned in [
            ": String",
            ": &str",
            ": Vec<u8>",
            ": IpAddr",
            ": SocketAddr",
            ": PathBuf",
            "host",
            "path",
            "header",
        ] {
            assert!(
                !decl.contains(banned),
                "ChunkReceiptDraft carries a {banned} field"
            );
        }
        // POSITIVE CONTROL: the structural scanner fires on a declaration that
        // does carry one.
        assert!("    pub host: String,".contains(": String"));

        // The destination is an entry id, and it is present.
        assert_eq!(drafts[0].allowlist_entry_id, 7);
    }

    /// INV-17. The meter counts the DECODED BODY, not the socket.
    ///
    /// Mutations this detects: `observe` wired to the socket counter, which
    /// would include TLS records, the handshake, the response head and the
    /// chunked framing — a total the gateway cannot match, challenged at strict
    /// equality, and the operator's bond forfeited on an honest epoch.
    #[test]
    fn the_meter_observes_decoded_body_bytes_not_socket_bytes() {
        let q = fixture(QUANTITY_FIXTURE);
        assert_eq!(
            q.get("metered_quantity")
                .and_then(serde_json::Value::as_str),
            Some("body_bytes_to_consumer"),
            "the fixture no longer names the quantity this meter counts"
        );

        let decoded: Vec<u64> = q
            .get("chunk_sizes")
            .and_then(serde_json::Value::as_array)
            .expect("the fixture pins the decoded chunk sizes")
            .iter()
            .map(|v| {
                v.as_str()
                    .expect("decimal string")
                    .parse()
                    .expect("decimal")
            })
            .collect();
        assert!(!decoded.is_empty(), "vacuity guard: no payload to feed");

        let body = fixture_u64(QUANTITY_FIXTURE, "body_bytes_to_consumer");
        let socket = fixture_u64(QUANTITY_FIXTURE, "origin_socket_bytes");
        let framing = fixture_u64(QUANTITY_FIXTURE, "chunk_framing_bytes");
        let head = fixture_u64(QUANTITY_FIXTURE, "response_head_bytes");

        // POSITIVE CONTROL, on the fixture itself: the socket seam really is a
        // DIFFERENT and LARGER number, so the assertion below can fail.
        assert!(
            socket > body,
            "the fixture's socket total is not larger than its body total; this test proves \
             nothing"
        );
        assert_eq!(
            socket,
            body + framing + head,
            "the fixture's own arithmetic does not hold"
        );

        // Feed the meter the DECODED chunks, one observation each.
        let mut m = meter();
        for n in &decoded {
            m.observe(*n, 1_800_000_000);
        }
        let drafts = m.seal_final(1_800_000_001).to_vec();
        let total: u64 = drafts.iter().map(|d| d.bytes_transferred).sum();

        assert_eq!(
            total, body,
            "the meter's draft total is not body_bytes_to_consumer"
        );
        assert_eq!(m.observed_total(), body);
        assert!(
            total < socket,
            "the meter counted the socket seam ({total} >= {socket}); the gateway cannot match \
             that number and every honest epoch would be challenged"
        );

        // The node and the gateway pin the SAME number.
        assert_eq!(
            body,
            fixture_u64(QUANTITY_FIXTURE, "gateway_to_consumer"),
            "the two counters no longer agree on the pinned payload"
        );
    }

    /// The origin leg is carried and is never a payout basis.
    ///
    /// Mutations this detects: `bytes_transferred` computed from
    /// `node_reported_from_origin`; the origin figure folded into
    /// `observed_total`.
    #[test]
    fn node_reported_from_origin_is_carried_but_is_never_a_payout_basis() {
        let mut with = meter();
        with.observe(4_096, 10);
        with.note_origin_bytes(9_999_999);
        let a = with.seal_final(11).to_vec();

        let mut without = meter();
        without.observe(4_096, 10);
        let b = without.seal_final(11).to_vec();

        // Same drafts, byte for byte and field for field.
        assert_eq!(a, b, "the origin figure changed what is payable");
        assert_eq!(with.observed_total(), 4_096);
        // POSITIVE CONTROL: the figure really was recorded, so the equality
        // above is not "we never set it".
        assert_eq!(with.node_reported_from_origin(), 9_999_999);
        assert_eq!(without.node_reported_from_origin(), 0);
    }

    /// The boundary, enforced on this file's own source.
    ///
    /// Mutations this detects: a `sign`, a `recover`, a typehash, a domain
    /// separator, a settlement call or a Merkle root added here — every one of
    /// which is the attestor's job, and duplicating any of them is how two
    /// implementations of one preimage start to disagree.
    #[test]
    fn the_meter_signs_nothing_and_settles_nothing() {
        let src = include_str!("meter.rs");
        let prod = match src.rfind("\n#[cfg(test)]\nmod tests {") {
            Some(i) => &src[..i],
            None => src,
        };
        assert!(
            prod.len() > 3_000,
            "vacuity guard: the production part did not parse"
        );

        let banned = [
            format!("{}{}", "sign_", "prehash"),
            format!("{}{}", "Signing", "Key"),
            format!("{}{}", "recover_", "from"),
            format!("{}{}", "keccak", "256"),
            format!("{}{}", "Keccak", "256"),
            format!("{}{}", "TYPE", "HASH"),
            format!("{}{}", "domain_", "separator"),
            format!("{}{}", "merkle_", "root"),
            format!("{}{}", "settle", "("),
        ];
        // POSITIVE CONTROL: the scanner sees every token in a string that has
        // them.
        let control = banned.join(" ");
        for b in &banned {
            assert!(control.contains(b.as_str()), "the scanner cannot see {b}");
        }
        for b in &banned {
            assert!(
                !prod.contains(b.as_str()),
                "the meter names {b}; canonicalisation and signing belong to the attestor"
            );
        }

        // And the crate carries no signing dependency at all: the operator's
        // key is not reachable from this process (INV-19).
        let manifest = include_str!("../Cargo.toml");
        let deps = manifest
            .split("[dev-dependencies]")
            .next()
            .expect("the manifest must have a dependency section");
        assert!(
            deps.len() > 500,
            "vacuity guard: the manifest did not split"
        );
        for signing_crate in ["k256 =", "ed25519", "secp256k1 ="] {
            assert!(
                !deps.contains(signing_crate),
                "{signing_crate} is a runtime dependency of the sidecar"
            );
        }
        // POSITIVE CONTROL: the dev section DOES carry the signing crate, so
        // the assertion above is about the split and not about a token nothing
        // ever contains.
        assert!(
            manifest.contains("k256 ="),
            "the test-only signing crate is gone; the split proves nothing"
        );
    }
}
