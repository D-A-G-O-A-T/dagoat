//! `BytesTransferredReceipt` — the three-party unit of settled work for the
//! allowlisted fetch network: its schema, its canonical bytes, its EIP-712
//! typehashes and the chunk rule that bounds how many of them a session emits.
//!
//! # A receipt says how much moved, never what moved
//!
//! Zero content logging is an invariant of this lane, not a preference, and it
//! is enforced here by construction rather than by review: there is no field on
//! this struct that can hold a hostname, an address, a URL, a path, a query
//! string, a header name, a header value or a body byte, because every field is
//! a byte count, a fixed-width identifier or a timestamp. The destination is an
//! **allowlist entry id** — an integer index into a curated manifest, itself
//! pinned by `allowlist_manifest_digest` — and nothing else. A receipt that can
//! identify what was fetched puts this lane inside data-controller territory and
//! defeats the whole design, so [`RECEIPT_FIELDS`] is the complete list and a
//! standalone privacy test sweeps the canonical bytes for the forbidden shapes.
//!
//! # Every integer is a decimal STRING
//!
//! [`crate::canonical_json`] is a deliberately restricted RFC 8785 subset that
//! **refuses** every JSON number and every JSON bool, and refuses any object key
//! outside `[A-Za-z0-9_]`. That is not a limitation to work around — it is what
//! makes the bytes reproducible in a second language. So `bytes_transferred` is
//! `"10485760"`, not `10485760`; `chunk_kind` is `"INTERIM"` or `"FINAL"`, not
//! `true`/`false`; and a receipt that serialised one integer as a JSON number
//! would not canonicalise at all, it would error.
//! `every_receipt_integer_is_a_decimal_string` asserts that over **all** values
//! with a floor on field count, so a field added tomorrow is covered by a test
//! written today.
//!
//! # One field table, two encodings
//!
//! The canonical-JSON key set and the EIP-712 field set are **derived from
//! [`RECEIPT_FIELDS`]**, so a field added to one and not the other is a test
//! failure rather than a silent divergence between what gets signed and what
//! gets hashed. [`RECEIPT_TYPEHASH_STR`] is a pinned constant — the type string
//! is immutable once anything has signed under it — and
//! `the_receipt_typehash_string_is_the_field_table_rendered` proves the pin and
//! the table still agree.
//!
//! # What is NOT here
//!
//! Nothing in this module issues supply, and nothing in it destroys supply. It
//! builds bytes and hashes. Signature *recovery* is Task 12's; the gateway meter
//! commitment is Task 14's; [`WITNESS_TYPEHASH_STR`] is declared here only so
//! all of this lane's type strings live in one file and can be checked for
//! collisions against the rest of the crate in one test.

use std::fmt;

use serde_json::{Map, Value};

use crate::canonical_json::{canonical_bytes, canonical_hash, CanonicalJsonError};
use crate::merkle::keccak256;
use crate::sig_verify::{address_word, domain_separator, eip712_digest, u256_be};

/// Start of the fetch-network epoch id space.
///
/// A **re-export**, never a second declaration: `proxy_merkle.rs` owns this
/// number, and two declarations of one constant in one crate is exactly the
/// drift that silently splits an id space in half.
pub use super::proxy_merkle::PROXY_EPOCH_BASE;

/// EIP-712 domain name for every signature in this lane.
///
/// Distinct from all four domains this crate already signs under
/// (`"GoatWorkerBinding"` at `sig_verify.rs:81`, `"GoatEnrollmentRegistry"` at
/// `sig_verify.rs:100`, and the two Stream G domains in
/// `stream_g/models.rs`), which is what stops a signature made for one lane
/// from being replayed into another.
///
/// ⚠️ The deployed settlement contract declares **no** EIP-712 domain of its
/// own — it verifies Merkle proofs, not signatures — so this name and version
/// are immutable by convention and by test, not by bytecode. Changing either
/// orphans every receipt anyone has already signed.
pub const PROXY_DOMAIN_NAME: &str = "GoatProxyRevenue";

/// EIP-712 domain version. See [`PROXY_DOMAIN_NAME`].
pub const PROXY_DOMAIN_VERSION: &str = "1";

/// Schema identifier for version 1 of the receipt.
///
/// This is metadata *about* a receipt — it labels the pinned fixture and the
/// stored rows — and is deliberately **not** one of [`RECEIPT_FIELDS`]: adding
/// it to the canonical object without adding it to the signed struct would break
/// the one-table-two-encodings property this module is built on.
pub const RECEIPT_SCHEMA_V1: &str = "GOAT_PROXY_BYTES_TRANSFERRED_RECEIPT_V1";

/// Bytes in one interim chunk: 10 MiB, exactly.
///
/// **There is no chunk-size configuration knob anywhere in this lane**, and
/// `the_proxy_config_exposes_no_tolerance_and_no_chunk_size_knob` asserts its
/// absence. A configurable chunk size is a configurable receipt count, and
/// receipt count is an anti-fraud surface: halving this would double every
/// operator's receipt count with no change in bytes moved.
pub const RECEIPT_CHUNK_BYTES: u64 = 10_485_760;

/// The receipt's EIP-712 type string.
///
/// Pinned rather than built at runtime because a type string is immutable the
/// moment anything signs under it. `the_receipt_typehash_string_is_the_field_table_rendered`
/// proves this pin still equals [`RECEIPT_FIELDS`] rendered, so the pin cannot
/// drift away from the struct it names.
pub const RECEIPT_TYPEHASH_STR: &str = "BytesTransferredReceipt(uint256 epochId,bytes32 sessionId,uint256 chunkSeq,string chunkKind,address operatorWallet,bytes32 consumerId,bytes32 gatewayId,uint256 allowlistEntryId,bytes32 allowlistManifestDigest,uint256 bytesTransferred,uint256 counter,bytes32 intentHash,bytes32 consentRecordHash,uint256 validFromUnix,uint256 validToUnix,uint256 priceGoatWeiPerMebibyte)";

/// The session intent's EIP-712 type string. See [`ProxySessionIntent`].
pub const INTENT_TYPEHASH_STR: &str = "ProxySessionIntent(uint256 epochId,bytes32 sessionId,address operatorWallet,bytes32 consumerId,bytes32 gatewayId,uint256 allowlistEntryId,bytes32 allowlistManifestDigest,uint256 maxBytes,uint256 validFromUnix,uint256 validToUnix,uint256 priceGoatWeiPerMebibyte)";

/// The gateway witness's EIP-712 type string.
///
/// Two counts, and the asymmetry between them is the load-bearing part. The
/// gateway **witnesses** `bodyBytesToConsumer` — bytes it observed crossing the
/// tunnel it is the sole ingress for — and merely **re-signs**
/// `nodeReportedFromOrigin`, which nothing in this system observes. Payout is on
/// the witnessed count for exactly that reason, and no copy anywhere may claim
/// the origin leg is attested.
///
/// The struct that carries these fields lands with the meter commitment; only
/// the type string lives here, so the whole lane's type strings can be checked
/// for collisions in one place.
pub const WITNESS_TYPEHASH_STR: &str = "GatewayWitness(bytes32 receiptStructHash,bytes32 gatewayId,uint256 bodyBytesToConsumer,uint256 nodeReportedFromOrigin,uint256 witnessedAtUnix)";

/// Every type string this lane declares, in one list.
///
/// Named as a function rather than spelled out at each call site so the task
/// that adds the fourth (the gateway meter commitment) extends the collision
/// check by editing one line.
pub fn proxy_type_strings() -> Vec<&'static str> {
    vec![
        RECEIPT_TYPEHASH_STR,
        INTENT_TYPEHASH_STR,
        WITNESS_TYPEHASH_STR,
        super::meter::METER_TYPEHASH_STR,
    ]
}

/// A chunk's kind is part of the signed struct, so it cannot be re-labelled
/// after the fact.
///
/// Encoded as a **string** in both encodings (`"INTERIM"` / `"FINAL"`), never as
/// a bool: [`crate::canonical_json`] refuses bools outright, and an `is_final`
/// flag would have had to be smuggled through as `"1"`/`"0"` — an integer
/// pretending to be an enum, which is how a third kind gets added later without
/// anybody noticing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkKind {
    /// Exactly [`RECEIPT_CHUNK_BYTES`]. Any other size is a refusal.
    Interim,
    /// `1..=RECEIPT_CHUNK_BYTES`, exactly one per session, highest `chunk_seq`.
    Final,
}

impl ChunkKind {
    /// The token that appears in the canonical JSON and is keccak-hashed into
    /// the EIP-712 word.
    pub fn as_token(self) -> &'static str {
        match self {
            ChunkKind::Interim => "INTERIM",
            ChunkKind::Final => "FINAL",
        }
    }
}

impl fmt::Display for ChunkKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_token())
    }
}

/// Why a receipt was refused before any signature was looked at.
///
/// Not `Clone`: [`CanonicalJsonError`] is not, and widening it to satisfy this
/// enum would be a change to the shared canonical encoder for the convenience of
/// one caller.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptError {
    #[error(
        "interim chunk carries {bytes} bytes; an interim chunk is EXACTLY {RECEIPT_CHUNK_BYTES}"
    )]
    InterimChunkNotExact { bytes: u64 },
    #[error("final chunk carries {bytes} bytes; a final chunk is 1..={RECEIPT_CHUNK_BYTES}")]
    FinalChunkOutOfRange { bytes: u64 },
    #[error("receipt does not canonicalise: {0}")]
    Canonical(#[from] CanonicalJsonError),
}

/// The receipt's field table: the **one** source both encodings are derived
/// from.
///
/// `(canonical JSON key, EIP-712 type, EIP-712 field name)`. The JSON keys are
/// snake_case and stay inside `[A-Za-z0-9_]`, which is the portable key alphabet
/// [`crate::canonical_json`] enforces; the EIP-712 names are camelCase because
/// that is what a Solidity struct declaration looks like, and the day one is
/// written the two must already agree.
pub const RECEIPT_FIELDS: [(&str, &str, &str); 16] = [
    ("epoch_id", "uint256", "epochId"),
    ("session_id", "bytes32", "sessionId"),
    ("chunk_seq", "uint256", "chunkSeq"),
    ("chunk_kind", "string", "chunkKind"),
    ("operator_wallet", "address", "operatorWallet"),
    ("consumer_id", "bytes32", "consumerId"),
    ("gateway_id", "bytes32", "gatewayId"),
    ("allowlist_entry_id", "uint256", "allowlistEntryId"),
    (
        "allowlist_manifest_digest",
        "bytes32",
        "allowlistManifestDigest",
    ),
    ("bytes_transferred", "uint256", "bytesTransferred"),
    ("counter", "uint256", "counter"),
    ("intent_hash", "bytes32", "intentHash"),
    ("consent_record_hash", "bytes32", "consentRecordHash"),
    ("valid_from_unix", "uint256", "validFromUnix"),
    ("valid_to_unix", "uint256", "validToUnix"),
    (
        "price_goat_wei_per_mebibyte",
        "uint256",
        "priceGoatWeiPerMebibyte",
    ),
];

/// [`RECEIPT_FIELDS`] rendered as an EIP-712 type string.
///
/// Exists so [`RECEIPT_TYPEHASH_STR`] can be *checked* rather than trusted. The
/// pinned constant is what code uses; this is what proves the pin still
/// describes the struct.
pub fn receipt_type_string_from_fields() -> String {
    let body = RECEIPT_FIELDS
        .iter()
        .map(|(_, ty, name)| format!("{ty} {name}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("BytesTransferredReceipt({body})")
}

/// One 10-MiB-or-smaller slice of one session's response body bytes, signed by
/// the operator, the consumer and the gateway.
///
/// Field-by-field, and what each one is NOT:
///
/// | field | what it is | what it is not |
/// |---|---|---|
/// | `epoch_id` | the settlement window, inside the fetch-network id space | not a date |
/// | `session_id` | an opaque 32-byte session handle | not derived from a destination |
/// | `chunk_seq` | dense from 0 within the session | — |
/// | `chunk_kind` | [`ChunkKind`] | — |
/// | `operator_wallet` | who is paid | — |
/// | `consumer_id` | an opaque 32-byte consumer handle | not an account name |
/// | `gateway_id` | which gateway witnessed | not a hostname |
/// | `allowlist_entry_id` | index into the curated manifest | **not** a URL, host or path |
/// | `allowlist_manifest_digest` | which manifest that index is into | — |
/// | `bytes_transferred` | `body_bytes_to_consumer` for this chunk | not socket bytes, not framing |
/// | `counter` | per-`(operator, gateway)` monotonic counter | — |
/// | `intent_hash` | binds the chunk to a signed [`ProxySessionIntent`] | — |
/// | `consent_record_hash` | binds it to the operator's consent record | — |
/// | `valid_from_unix` / `valid_to_unix` | the intent's validity window | — |
/// | `price_goat_wei_per_mebibyte` | the price at signing time | — |
///
/// `epoch_id` is inside the signed struct on purpose: it is one of three
/// independent replay defences, alongside the two UNIQUE indexes the store
/// carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytesTransferredReceipt {
    pub epoch_id: u64,
    pub session_id: [u8; 32],
    pub chunk_seq: u64,
    pub chunk_kind: ChunkKind,
    pub operator_wallet: [u8; 20],
    pub consumer_id: [u8; 32],
    pub gateway_id: [u8; 32],
    pub allowlist_entry_id: u64,
    pub allowlist_manifest_digest: [u8; 32],
    pub bytes_transferred: u64,
    pub counter: u64,
    pub intent_hash: [u8; 32],
    pub consent_record_hash: [u8; 32],
    pub valid_from_unix: u64,
    pub valid_to_unix: u64,
    pub price_goat_wei_per_mebibyte: u128,
}

/// What the operator and consumer agreed to before any byte moved.
///
/// The receipt binds to it by hash, so a chunk cannot be re-attributed to a
/// different destination, operator or price after the fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySessionIntent {
    pub epoch_id: u64,
    pub session_id: [u8; 32],
    pub operator_wallet: [u8; 20],
    pub consumer_id: [u8; 32],
    pub gateway_id: [u8; 32],
    pub allowlist_entry_id: u64,
    pub allowlist_manifest_digest: [u8; 32],
    /// Ceiling the session may not exceed, agreed in advance.
    pub max_bytes: u64,
    pub valid_from_unix: u64,
    pub valid_to_unix: u64,
    pub price_goat_wei_per_mebibyte: u128,
}

/// `0x`-prefixed lowercase hex of a 32-byte word.
fn hex32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// `0x`-prefixed lowercase hex of an address.
fn hex20(bytes: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(bytes))
}

impl ProxySessionIntent {
    /// Canonical JSON object. Same rules as the receipt's: decimal strings,
    /// lowercase `0x` hex, no numbers and no bools.
    pub fn canonical_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("epoch_id".into(), Value::String(self.epoch_id.to_string()));
        map.insert("session_id".into(), Value::String(hex32(&self.session_id)));
        map.insert(
            "operator_wallet".into(),
            Value::String(hex20(&self.operator_wallet)),
        );
        map.insert(
            "consumer_id".into(),
            Value::String(hex32(&self.consumer_id)),
        );
        map.insert("gateway_id".into(), Value::String(hex32(&self.gateway_id)));
        map.insert(
            "allowlist_entry_id".into(),
            Value::String(self.allowlist_entry_id.to_string()),
        );
        map.insert(
            "allowlist_manifest_digest".into(),
            Value::String(hex32(&self.allowlist_manifest_digest)),
        );
        map.insert(
            "max_bytes".into(),
            Value::String(self.max_bytes.to_string()),
        );
        map.insert(
            "valid_from_unix".into(),
            Value::String(self.valid_from_unix.to_string()),
        );
        map.insert(
            "valid_to_unix".into(),
            Value::String(self.valid_to_unix.to_string()),
        );
        map.insert(
            "price_goat_wei_per_mebibyte".into(),
            Value::String(self.price_goat_wei_per_mebibyte.to_string()),
        );
        Value::Object(map)
    }

    /// `keccak256(abi.encode(INTENT_TYPEHASH, …))`, one 32-byte word per field.
    pub fn intent_struct_hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(32 * 12);
        buf.extend_from_slice(&keccak256(INTENT_TYPEHASH_STR.as_bytes()));
        buf.extend_from_slice(&u256_be(u128::from(self.epoch_id)));
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&address_word(&self.operator_wallet));
        buf.extend_from_slice(&self.consumer_id);
        buf.extend_from_slice(&self.gateway_id);
        buf.extend_from_slice(&u256_be(u128::from(self.allowlist_entry_id)));
        buf.extend_from_slice(&self.allowlist_manifest_digest);
        buf.extend_from_slice(&u256_be(u128::from(self.max_bytes)));
        buf.extend_from_slice(&u256_be(u128::from(self.valid_from_unix)));
        buf.extend_from_slice(&u256_be(u128::from(self.valid_to_unix)));
        buf.extend_from_slice(&u256_be(self.price_goat_wei_per_mebibyte));
        keccak256(&buf)
    }

    /// The digest a consumer or operator actually signs.
    pub fn intent_digest(&self, chain_id: u64, verifying_contract: [u8; 20]) -> [u8; 32] {
        let domain = domain_separator(
            PROXY_DOMAIN_NAME,
            PROXY_DOMAIN_VERSION,
            chain_id,
            verifying_contract,
        );
        eip712_digest(&domain, &self.intent_struct_hash())
    }
}

impl BytesTransferredReceipt {
    /// The canonical JSON object, keyed by [`RECEIPT_FIELDS`]'s first column.
    ///
    /// Every value is a **string**. Integers are decimal strings, byte arrays
    /// are `0x`-prefixed lowercase hex, and [`ChunkKind`] is its token. Nothing
    /// here is a JSON number or a bool, because the canonical encoder refuses
    /// both.
    pub fn canonical_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("epoch_id".into(), Value::String(self.epoch_id.to_string()));
        map.insert("session_id".into(), Value::String(hex32(&self.session_id)));
        map.insert(
            "chunk_seq".into(),
            Value::String(self.chunk_seq.to_string()),
        );
        map.insert(
            "chunk_kind".into(),
            Value::String(self.chunk_kind.as_token().to_string()),
        );
        map.insert(
            "operator_wallet".into(),
            Value::String(hex20(&self.operator_wallet)),
        );
        map.insert(
            "consumer_id".into(),
            Value::String(hex32(&self.consumer_id)),
        );
        map.insert("gateway_id".into(), Value::String(hex32(&self.gateway_id)));
        map.insert(
            "allowlist_entry_id".into(),
            Value::String(self.allowlist_entry_id.to_string()),
        );
        map.insert(
            "allowlist_manifest_digest".into(),
            Value::String(hex32(&self.allowlist_manifest_digest)),
        );
        map.insert(
            "bytes_transferred".into(),
            Value::String(self.bytes_transferred.to_string()),
        );
        map.insert("counter".into(), Value::String(self.counter.to_string()));
        map.insert(
            "intent_hash".into(),
            Value::String(hex32(&self.intent_hash)),
        );
        map.insert(
            "consent_record_hash".into(),
            Value::String(hex32(&self.consent_record_hash)),
        );
        map.insert(
            "valid_from_unix".into(),
            Value::String(self.valid_from_unix.to_string()),
        );
        map.insert(
            "valid_to_unix".into(),
            Value::String(self.valid_to_unix.to_string()),
        );
        map.insert(
            "price_goat_wei_per_mebibyte".into(),
            Value::String(self.price_goat_wei_per_mebibyte.to_string()),
        );
        Value::Object(map)
    }

    /// RFC 8785 canonical bytes of [`Self::canonical_value`].
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReceiptError> {
        Ok(canonical_bytes(&self.canonical_value())?)
    }

    /// `keccak256(UTF8(canonical bytes))`. This is the content hash the store
    /// and the evidence bundle key on; it is **not** the EIP-712 digest.
    pub fn canonical_hash(&self) -> Result<[u8; 32], ReceiptError> {
        Ok(canonical_hash(&self.canonical_value())?)
    }

    /// `keccak256(abi.encode(RECEIPT_TYPEHASH, …))`.
    ///
    /// One 32-byte word per field, in [`RECEIPT_FIELDS`] order, with the one
    /// variable-length part (`chunk_kind`, an EIP-712 `string`) replaced by
    /// `keccak256(UTF8(token))` exactly as EIP-712 requires.
    pub fn receipt_struct_hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(32 * (RECEIPT_FIELDS.len() + 1));
        buf.extend_from_slice(&keccak256(RECEIPT_TYPEHASH_STR.as_bytes()));
        buf.extend_from_slice(&u256_be(u128::from(self.epoch_id)));
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&u256_be(u128::from(self.chunk_seq)));
        buf.extend_from_slice(&keccak256(self.chunk_kind.as_token().as_bytes()));
        buf.extend_from_slice(&address_word(&self.operator_wallet));
        buf.extend_from_slice(&self.consumer_id);
        buf.extend_from_slice(&self.gateway_id);
        buf.extend_from_slice(&u256_be(u128::from(self.allowlist_entry_id)));
        buf.extend_from_slice(&self.allowlist_manifest_digest);
        buf.extend_from_slice(&u256_be(u128::from(self.bytes_transferred)));
        buf.extend_from_slice(&u256_be(u128::from(self.counter)));
        buf.extend_from_slice(&self.intent_hash);
        buf.extend_from_slice(&self.consent_record_hash);
        buf.extend_from_slice(&u256_be(u128::from(self.valid_from_unix)));
        buf.extend_from_slice(&u256_be(u128::from(self.valid_to_unix)));
        buf.extend_from_slice(&u256_be(self.price_goat_wei_per_mebibyte));
        debug_assert_eq!(buf.len(), 32 * (RECEIPT_FIELDS.len() + 1));
        keccak256(&buf)
    }

    /// The digest all three parties sign, binding `chainId` and the verifying
    /// contract so a signature made for another deployment is refused.
    pub fn receipt_digest(&self, chain_id: u64, verifying_contract: [u8; 20]) -> [u8; 32] {
        let domain = domain_separator(
            PROXY_DOMAIN_NAME,
            PROXY_DOMAIN_VERSION,
            chain_id,
            verifying_contract,
        );
        eip712_digest(&domain, &self.receipt_struct_hash())
    }

    /// The chunk-size rule, applied to this receipt.
    pub fn check_chunk_size(&self) -> Result<(), ReceiptError> {
        check_chunk_size(self.chunk_kind, self.bytes_transferred)
    }

    /// Deterministic receipt for tests and fixtures.
    ///
    /// **`pub`, not `#[cfg(test)]`.** The lane's standalone privacy test is an
    /// *integration* test, so it compiles against this library without
    /// `cfg(test)` and a `#[cfg(test)]` constructor would be invisible to it.
    /// `#[doc(hidden)]` keeps it out of the published docs without making it
    /// unreachable.
    ///
    /// Every field the caller does not choose is a fixed, obviously-synthetic
    /// value, so two callers building "the same" receipt cannot disagree.
    #[doc(hidden)]
    pub fn for_test(
        epoch_id: u64,
        session_id: [u8; 32],
        chunk_seq: u64,
        chunk_kind: ChunkKind,
        bytes_transferred: u64,
    ) -> Self {
        Self {
            epoch_id,
            session_id,
            chunk_seq,
            chunk_kind,
            operator_wallet: [0xA1; 20],
            consumer_id: [0xC2; 32],
            gateway_id: [0x67; 32],
            allowlist_entry_id: 7,
            allowlist_manifest_digest: [0xD3; 32],
            bytes_transferred,
            counter: 42,
            intent_hash: [0x1E; 32],
            consent_record_hash: [0x2C; 32],
            valid_from_unix: 1_800_000_000,
            valid_to_unix: 1_800_003_600,
            price_goat_wei_per_mebibyte: 1_000_000_000_000,
        }
    }
}

/// The chunk rule, stated once and applied everywhere.
///
/// An [`ChunkKind::Interim`] chunk is **exactly** [`RECEIPT_CHUNK_BYTES`]; a
/// [`ChunkKind::Final`] chunk is `1..=RECEIPT_CHUNK_BYTES`. Zero is refused in
/// both arms: a zero-byte receipt is a signature over nothing that still
/// occupies a row and a sequence number.
pub fn check_chunk_size(kind: ChunkKind, bytes_transferred: u64) -> Result<(), ReceiptError> {
    match kind {
        ChunkKind::Interim if bytes_transferred == RECEIPT_CHUNK_BYTES => Ok(()),
        ChunkKind::Interim => Err(ReceiptError::InterimChunkNotExact {
            bytes: bytes_transferred,
        }),
        ChunkKind::Final if (1..=RECEIPT_CHUNK_BYTES).contains(&bytes_transferred) => Ok(()),
        ChunkKind::Final => Err(ReceiptError::FinalChunkOutOfRange {
            bytes: bytes_transferred,
        }),
    }
}

/// Split a session total into the chunks that will be receipted.
///
/// The returned vector is dense and ordered: element `i` carries `chunk_seq`
/// `i`, every element but the last is [`ChunkKind::Interim`] of exactly
/// [`RECEIPT_CHUNK_BYTES`], and the last is the session's single
/// [`ChunkKind::Final`]. A session that moved zero bytes emits **no** receipts
/// at all rather than one empty one.
///
/// The exact multiple is the case worth reading twice: `20_971_520` bytes is two
/// full chunks, and the second of them is the `Final`, not a third zero-byte
/// chunk appended after it.
pub fn split_into_chunks(total_bytes: u64) -> Vec<(u64, ChunkKind)> {
    if total_bytes == 0 {
        return Vec::new();
    }
    let remainder = total_bytes % RECEIPT_CHUNK_BYTES;
    let full = total_bytes / RECEIPT_CHUNK_BYTES;
    let interim = if remainder == 0 { full - 1 } else { full };

    let mut out = Vec::with_capacity(usize::try_from(interim + 1).unwrap_or(usize::MAX));
    for _ in 0..interim {
        out.push((RECEIPT_CHUNK_BYTES, ChunkKind::Interim));
    }
    out.push((
        if remainder == 0 {
            RECEIPT_CHUNK_BYTES
        } else {
            remainder
        },
        ChunkKind::Final,
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proposer::ENROLLMENT_EPOCH_BASE;

    /// The pinned fixture, compiled in so a deleted file is a build failure
    /// rather than a skipped test.
    const FIXTURE_JSON: &str = include_str!("../../fixtures/proxy_receipt_v1.json");

    /// The sample receipt the fixture pins. Every field is fixed, including the
    /// ones `for_test` chooses, so the bytes below are reproducible by anyone.
    fn pinned_receipt() -> BytesTransferredReceipt {
        BytesTransferredReceipt::for_test(
            PROXY_EPOCH_BASE + 20_664,
            [0x5E; 32],
            0,
            ChunkKind::Final,
            10_485_759,
        )
    }

    fn fixture() -> Value {
        serde_json::from_str(FIXTURE_JSON).expect("the pinned fixture must be JSON")
    }

    fn fixture_str(key: &str) -> String {
        fixture()
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("fixture must carry {key:?}"))
            .to_string()
    }

    /// The two field lists come from one table, so a field added to one and not
    /// the other cannot pass silently.
    ///
    /// Mutations this detects: adding a key to `canonical_value` without a
    /// [`RECEIPT_FIELDS`] row; renaming a JSON key; reordering
    /// [`RECEIPT_FIELDS`] against the struct-hash encoder (the order assertion
    /// catches it); dropping a field from [`RECEIPT_TYPEHASH_STR`].
    #[test]
    fn canonical_json_field_set_equals_the_eip712_field_set() {
        let receipt = pinned_receipt();
        let value = receipt.canonical_value();
        let object = value.as_object().expect("a receipt is a JSON object");

        // The JSON side, in the encoder's own output order (BTreeMap: sorted).
        let json_keys: Vec<&str> = object.keys().map(String::as_str).collect();

        // The table side.
        let mut table_keys: Vec<&str> = RECEIPT_FIELDS.iter().map(|(k, _, _)| *k).collect();
        assert_eq!(
            table_keys.len(),
            16,
            "the receipt has sixteen fields; a change here is a schema change"
        );
        table_keys.sort_unstable();
        assert_eq!(
            json_keys, table_keys,
            "the canonical object and the field table disagree"
        );

        // The EIP-712 side, parsed back out of the pinned type string rather
        // than re-rendered, so this compares the SIGNED text to the table.
        let inner = RECEIPT_TYPEHASH_STR
            .strip_prefix("BytesTransferredReceipt(")
            .and_then(|s| s.strip_suffix(')'))
            .expect("the type string is `Name(field,field,...)`");
        let signed: Vec<(&str, &str)> = inner
            .split(',')
            .map(|part| {
                let (ty, name) = part.split_once(' ').expect("`<type> <name>`");
                (ty, name)
            })
            .collect();
        let table: Vec<(&str, &str)> = RECEIPT_FIELDS.iter().map(|(_, t, n)| (*t, *n)).collect();
        assert_eq!(
            signed, table,
            "the signed type string and the field table disagree, in type or in ORDER — and \
             order is load-bearing: EIP-712 packs words positionally"
        );

        // Negative control: the comparison can fail. A table with one field
        // renamed must NOT equal the signed list.
        let mut mutated = table.clone();
        mutated[0] = ("uint256", "epochIdentifier");
        assert_ne!(
            signed, mutated,
            "the comparison above cannot distinguish anything; it proves nothing"
        );
    }

    /// The pinned constant still describes the struct it names.
    ///
    /// Mutations this detects: editing [`RECEIPT_TYPEHASH_STR`] without editing
    /// [`RECEIPT_FIELDS`], or the reverse. Either way the signed bytes move and
    /// every receipt already signed becomes unverifiable, so this must fail
    /// loudly rather than at the first rejected signature.
    #[test]
    fn the_receipt_typehash_string_is_the_field_table_rendered() {
        assert_eq!(receipt_type_string_from_fields(), RECEIPT_TYPEHASH_STR);
        // Independent length pin: a whitespace or separator change that
        // happened to round-trip through the renderer would still move this.
        assert_eq!(RECEIPT_TYPEHASH_STR.len(), 369);
    }

    /// Every value in the canonical object is a **string**, because the
    /// canonical encoder refuses JSON numbers and bools outright.
    ///
    /// Asserted over ALL values with a floor on field count, so a field added
    /// tomorrow is covered by this test written today.
    ///
    /// Mutations this detects: emitting any integer as a JSON number; modelling
    /// `chunk_kind` as a bool; emitting `null` for an unset field.
    #[test]
    fn every_receipt_integer_is_a_decimal_string() {
        let receipt = pinned_receipt();
        let value = receipt.canonical_value();
        let object = value.as_object().expect("object");

        assert!(
            object.len() >= 16,
            "field-count floor: {} fields swept, and a shrinking object would make the sweep \
             below pass by covering nothing",
            object.len()
        );

        for (key, v) in object {
            assert!(
                v.is_string(),
                "{key} is {v:?}, not a string — the canonical encoder refuses numbers and bools"
            );
        }

        // The integer-shaped fields are DECIMAL strings specifically: no `0x`,
        // no leading `+`, no underscores, no exponent.
        for key in [
            "epoch_id",
            "chunk_seq",
            "allowlist_entry_id",
            "bytes_transferred",
            "counter",
            "valid_from_unix",
            "valid_to_unix",
            "price_goat_wei_per_mebibyte",
        ] {
            let s = object[key].as_str().expect("string");
            assert!(
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
                "{key} = {s:?} is not a decimal string"
            );
        }

        // POSITIVE CONTROL: the canonical encoder really does refuse a number
        // and a bool, so the whole discipline above is load-bearing rather than
        // a style rule nobody enforces.
        let mut with_number = object.clone();
        with_number.insert("bytes_transferred".into(), Value::from(10_485_759u64));
        assert!(
            matches!(
                canonical_bytes(&Value::Object(with_number)),
                Err(CanonicalJsonError::NumberNotAllowed { .. })
            ),
            "a JSON number must be unhashable, or the decimal-string rule is decorative"
        );
        let mut with_bool = object.clone();
        with_bool.insert("chunk_kind".into(), Value::Bool(true));
        assert!(matches!(
            canonical_bytes(&Value::Object(with_bool)),
            Err(CanonicalJsonError::BoolNotAllowed { .. })
        ));

        // And the real object DOES canonicalise, so the two refusals above are
        // the encoder discriminating rather than refusing everything.
        assert!(receipt.canonical_bytes().is_ok());
    }

    /// KNOWN-ANSWER TEST — byte-for-byte against `fixtures/proxy_receipt_v1.json`.
    ///
    /// Two independent pins, both compared to the computed value: the fixture
    /// file (which a second implementation reads) and the source constants
    /// below (which a fixture regenerated from this very code cannot move).
    /// Never edit a pin to make this green — a drift here means every receipt
    /// this daemon signs disagrees with every receipt anything else verifies.
    ///
    /// Mutations this detects: any change to a field's encoding (hex case, `0x`
    /// prefix, decimal vs hex); any change to a field name; any change to a
    /// field's VALUE in `for_test`; reordering the EIP-712 words; changing the
    /// domain name or version.
    #[test]
    fn pinned_canonical_receipt_bytes_and_hash() {
        let receipt = pinned_receipt();
        let bytes = receipt.canonical_bytes().expect("must canonicalise");
        let text = String::from_utf8(bytes.clone()).expect("canonical bytes are UTF-8");
        let hash = hex32(&receipt.canonical_hash().expect("must hash"));
        let struct_hash = hex32(&receipt.receipt_struct_hash());
        let digest = hex32(&receipt.receipt_digest(31_337, [0x11; 20]));

        // Printed so `-- --nocapture` regenerates the fixture without anybody
        // hand-transcribing 500 characters.
        println!("canonicalBytes = {text}");
        println!("canonicalByteLength = {}", bytes.len());
        println!("canonicalHash = {hash}");
        println!("receiptStructHash = {struct_hash}");
        println!("receiptDigestAnvil = {digest}");

        const EXPECTED_BYTES: &str = concat!(
            r#"{"allowlist_entry_id":"7","#,
            r#""allowlist_manifest_digest":"0xd3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3","#,
            r#""bytes_transferred":"10485759","#,
            r#""chunk_kind":"FINAL","#,
            r#""chunk_seq":"0","#,
            r#""consent_record_hash":"0x2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c","#,
            r#""consumer_id":"0xc2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2","#,
            r#""counter":"42","#,
            r#""epoch_id":"8000000020664","#,
            r#""gateway_id":"0x6767676767676767676767676767676767676767676767676767676767676767","#,
            r#""intent_hash":"0x1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e","#,
            r#""operator_wallet":"0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","#,
            r#""price_goat_wei_per_mebibyte":"1000000000000","#,
            r#""session_id":"0x5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e","#,
            r#""valid_from_unix":"1800000000","#,
            r#""valid_to_unix":"1800003600"}"#,
        );
        assert_eq!(text, EXPECTED_BYTES, "canonical bytes drifted");
        assert_eq!(
            bytes.len(),
            823,
            "canonical byte length is part of the fixture"
        );

        // Cross-checked against an INDEPENDENT keccak implementation (foundry
        // `cast keccak`) over these exact 823 UTF-8 bytes, and over the 544-byte
        // EIP-712 preimage, so these constants are not merely self-consistent
        // with this crate's own tiny-keccak call.
        const EXPECTED_HASH: &str =
            "0x86e03786eba3440c3dc0c490013f7f2e324a5531e17212e30af4e96de76ad4d1";
        const EXPECTED_STRUCT_HASH: &str =
            "0xfc37274003050047b3afa3fcdcc11c7604e910425d92deebd0f4b9107839add6";
        const EXPECTED_DIGEST_ANVIL: &str =
            "0x373b1cee4e635e4b0e83f67aa47a2a2c076e95ec2e95008ca6346c0acb796d38";
        assert_eq!(hash, EXPECTED_HASH);
        assert_eq!(struct_hash, EXPECTED_STRUCT_HASH);
        assert_eq!(digest, EXPECTED_DIGEST_ANVIL);

        // The fixture is the SECOND pin, read from disk. It and the constants
        // above must agree with the computed value AND with each other — a
        // fixture regenerated from this very code cannot move the constants,
        // and a hand-edited constant cannot move the fixture.
        assert_eq!(fixture_str("schema"), RECEIPT_SCHEMA_V1);
        assert_eq!(fixture_str("canonicalBytes"), text);
        assert_eq!(fixture_str("canonicalHash"), hash);
        assert_eq!(fixture_str("receiptStructHash"), struct_hash);
        assert_eq!(fixture_str("receiptDigestAnvil"), digest);
        assert_eq!(fixture_str("receiptTypeString"), RECEIPT_TYPEHASH_STR);
        assert_eq!(fixture_str("intentTypeString"), INTENT_TYPEHASH_STR);
        assert_eq!(fixture_str("witnessTypeString"), WITNESS_TYPEHASH_STR);
        assert_eq!(fixture_str("domainName"), PROXY_DOMAIN_NAME);
        assert_eq!(fixture_str("domainVersion"), PROXY_DOMAIN_VERSION);
        assert_eq!(fixture_str("chunkBytes"), RECEIPT_CHUNK_BYTES.to_string());
        assert_eq!(fixture_str("digestChainId"), "31337");
        assert_eq!(
            fixture_str("canonicalByteLength"),
            bytes.len().to_string(),
            "the fixture's own length field must match the bytes beside it"
        );

        // The three type strings' hashes are pinned in the fixture too, so a
        // second implementation can check its typehash without re-deriving the
        // string. Each is `keccak256(UTF8(type string))` and nothing else.
        for (key, type_string) in [
            ("receiptTypehash", RECEIPT_TYPEHASH_STR),
            ("intentTypehash", INTENT_TYPEHASH_STR),
            ("witnessTypehash", WITNESS_TYPEHASH_STR),
        ] {
            assert_eq!(
                fixture_str(key),
                hex32(&keccak256(type_string.as_bytes())),
                "{key} in the fixture is not keccak256 of the type string beside it"
            );
        }

        // The sample block is the same receipt spelled out field by field, so a
        // reader can rebuild it without parsing the canonical bytes. It must be
        // exactly the canonical object.
        assert_eq!(
            fixture().get("sample"),
            Some(&receipt.canonical_value()),
            "the fixture's readable sample and its canonical bytes describe different receipts"
        );

        // Sorted-key order is a property of the encoder, not of the writer:
        // `allowlist_entry_id` leads and `valid_to_unix` trails regardless of
        // the order `canonical_value` inserts them in.
        assert!(text.starts_with(r#"{"allowlist_entry_id":"#));
        assert!(text.ends_with(r#""valid_to_unix":"1800003600"}"#));
    }

    /// None of this lane's type strings, nor its domain, collides with anything
    /// the crate already signs.
    ///
    /// A collision would mean a signature gathered for one purpose verifies for
    /// another — the exact hazard EIP-712 domains and typehashes exist to close.
    ///
    /// Mutations this detects: reusing an existing domain name for this lane;
    /// copying an existing type string; declaring two of this lane's type
    /// strings identically.
    #[test]
    fn proxy_domain_and_typehashes_do_not_collide_with_any_existing_domain() {
        use crate::stream_g::models::{
            FEE_QUOTE_TYPEHASH_STR, GOAT_TRANSFER_CORE_TYPEHASH_STR, LINK_SECONDARY_TYPEHASH_STR,
            SELL_CORE_TYPEHASH_STR, SPONSOR_ENROLLMENT_CORE_TYPEHASH_STR,
            USDT_TRANSFER_CORE_TYPEHASH_STR,
        };
        use crate::stream_g::preflight::SPONSOR_ENROLLMENT_TYPEHASH_STR;
        use crate::stream_g::root_authorization::ROOT_AUTHORIZATION_TYPEHASH_STR;
        use crate::stream_g::token_manifest::FEE_TOKEN_CONFIG_TYPEHASH_STR;

        // Every type string this crate already hashes, plus the two private
        // ones in `sig_verify.rs` (`sig_verify.rs:17` and `:21`) reproduced as
        // literals because they are declared inline there.
        let existing: Vec<&str> = vec![
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
            "Bind(address wallet,string username,uint256 nonce,uint256 deadline)",
            "Enroll(address wallet,uint256 nonce,uint256 deadline)",
            FEE_QUOTE_TYPEHASH_STR,
            SPONSOR_ENROLLMENT_CORE_TYPEHASH_STR,
            SELL_CORE_TYPEHASH_STR,
            GOAT_TRANSFER_CORE_TYPEHASH_STR,
            USDT_TRANSFER_CORE_TYPEHASH_STR,
            LINK_SECONDARY_TYPEHASH_STR,
            SPONSOR_ENROLLMENT_TYPEHASH_STR,
            ROOT_AUTHORIZATION_TYPEHASH_STR,
            FEE_TOKEN_CONFIG_TYPEHASH_STR,
            super::super::proxy_merkle::PROXY_LEAF_DOMAIN_STR,
        ];
        assert_eq!(
            existing.len(),
            13,
            "the comparison set is a floor: an empty or shrunken set would make every assertion \
             below pass vacuously"
        );

        let mine = proxy_type_strings();
        assert_eq!(
            mine.len(),
            4,
            "the lane declares four type strings: three here and the gateway meter commitment's"
        );
        assert!(
            mine.contains(&super::super::meter::METER_TYPEHASH_STR),
            "the meter commitment's type string must be inside the collision check, not beside it"
        );

        // POSITIVE CONTROL: the comparison can actually find a collision.
        let mut planted = mine.clone();
        planted.push(FEE_QUOTE_TYPEHASH_STR);
        assert!(
            planted.iter().any(|m| existing.contains(m)),
            "the collision check cannot detect a collision; its silence proves nothing"
        );

        for m in &mine {
            assert!(
                !existing.contains(m),
                "type string collides with an existing one: {m}"
            );
            assert!(
                !existing
                    .iter()
                    .any(|e| keccak256(e.as_bytes()) == keccak256(m.as_bytes())),
                "typehash collides with an existing one: {m}"
            );
        }
        // The three are distinct from EACH OTHER too.
        for (i, a) in mine.iter().enumerate() {
            for b in mine.iter().skip(i + 1) {
                assert_ne!(keccak256(a.as_bytes()), keccak256(b.as_bytes()));
            }
        }

        // The DOMAIN is the other half. Same chain id and verifying contract,
        // four existing names, four different separators.
        for existing_name in [
            "GoatWorkerBinding",      // sig_verify.rs:81
            "GoatEnrollmentRegistry", // sig_verify.rs:100
            "GoatRelayGateway",       // stream_g/models.rs
            "GoatWalletSponsorship",  // stream_g/models.rs
        ] {
            assert_ne!(PROXY_DOMAIN_NAME, existing_name);
            assert_ne!(
                domain_separator(PROXY_DOMAIN_NAME, PROXY_DOMAIN_VERSION, 31_337, [0x11; 20]),
                domain_separator(existing_name, "1", 31_337, [0x11; 20]),
                "domain separator collides with {existing_name}"
            );
        }

        // And the domain binds chain id and verifying contract, so the same
        // receipt signed for Anvil is not signed for Base Sepolia.
        let r = pinned_receipt();
        assert_ne!(
            r.receipt_digest(31_337, [0x11; 20]),
            r.receipt_digest(84_532, [0x11; 20])
        );
        assert_ne!(
            r.receipt_digest(31_337, [0x11; 20]),
            r.receipt_digest(31_337, [0x22; 20])
        );
    }

    /// Interim chunks are EXACT; final chunks are bounded; zero is neither.
    ///
    /// Mutations this detects: turning the interim equality into a `<=`;
    /// admitting a zero-byte final chunk; letting a final chunk exceed
    /// [`RECEIPT_CHUNK_BYTES`].
    #[test]
    fn chunk_size_rule_accepts_only_exact_interim_chunks_and_bounded_final_chunks() {
        // Accepted.
        assert!(check_chunk_size(ChunkKind::Interim, RECEIPT_CHUNK_BYTES).is_ok());
        for ok in [1, 2, RECEIPT_CHUNK_BYTES - 1, RECEIPT_CHUNK_BYTES] {
            assert!(
                check_chunk_size(ChunkKind::Final, ok).is_ok(),
                "a final chunk of {ok} bytes is inside 1..={RECEIPT_CHUNK_BYTES}"
            );
        }

        // Refused, with the specific variant.
        assert_eq!(
            check_chunk_size(ChunkKind::Final, 0),
            Err(ReceiptError::FinalChunkOutOfRange { bytes: 0 }),
            "a zero-byte receipt is a signature over nothing"
        );
        assert_eq!(
            check_chunk_size(ChunkKind::Final, RECEIPT_CHUNK_BYTES + 1),
            Err(ReceiptError::FinalChunkOutOfRange {
                bytes: RECEIPT_CHUNK_BYTES + 1
            })
        );
        assert_eq!(
            check_chunk_size(ChunkKind::Interim, 0),
            Err(ReceiptError::InterimChunkNotExact { bytes: 0 })
        );

        // The receipt-level wrapper reads the receipt's own two fields, not
        // some other pair.
        let mut r = pinned_receipt();
        r.chunk_kind = ChunkKind::Interim;
        r.bytes_transferred = RECEIPT_CHUNK_BYTES;
        assert!(r.check_chunk_size().is_ok());
        r.bytes_transferred = RECEIPT_CHUNK_BYTES - 1;
        assert!(r.check_chunk_size().is_err());
    }

    /// Ten mebibytes means 10 485 760 bytes and nothing near it.
    ///
    /// Mutations this detects: defining [`RECEIPT_CHUNK_BYTES`] as 10 000 000
    /// (the decimal megabyte), as 10 * 1024 * 1000, or off by one; relaxing the
    /// interim check to a range.
    #[test]
    fn an_interim_chunk_that_is_not_exactly_ten_mebibytes_is_refused() {
        assert_eq!(RECEIPT_CHUNK_BYTES, 10_485_760);
        assert_eq!(RECEIPT_CHUNK_BYTES, 10 * (1 << 20));
        assert_ne!(
            RECEIPT_CHUNK_BYTES, 10_000_000,
            "10 MiB is not 10 MB; the decimal megabyte would change every receipt count"
        );

        for off_by in [
            RECEIPT_CHUNK_BYTES - 1,
            RECEIPT_CHUNK_BYTES + 1,
            10_000_000,
            0,
            u64::MAX,
        ] {
            assert_eq!(
                check_chunk_size(ChunkKind::Interim, off_by),
                Err(ReceiptError::InterimChunkNotExact { bytes: off_by }),
                "{off_by} is not exactly one interim chunk"
            );
        }

        // Negative control: the exact value is accepted, so the five refusals
        // above are the equality firing and not a function that refuses all.
        assert!(check_chunk_size(ChunkKind::Interim, RECEIPT_CHUNK_BYTES).is_ok());
    }

    /// The boundary cases, spelled out, with the sum re-derived every time.
    ///
    /// Mutations this detects: emitting a trailing zero-byte `Final` at an exact
    /// multiple; making the LAST chunk `Interim`; emitting more than one
    /// `Final`; an off-by-one in the interim count; a non-dense `chunk_seq`.
    #[test]
    fn chunking_is_exact_at_the_ten_mebibyte_boundary() {
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
            let chunks = split_into_chunks(total);
            let sizes: Vec<u64> = chunks.iter().map(|(n, _)| *n).collect();
            assert_eq!(sizes, expected, "split of {total}");

            // Sum is the total, always. This is the assertion that makes a
            // silent byte loss impossible rather than unlikely.
            assert_eq!(
                sizes.iter().sum::<u64>(),
                total,
                "chunking of {total} lost or invented bytes"
            );

            // No zero-byte receipt is ever emitted.
            assert!(
                sizes.iter().all(|n| *n > 0),
                "a zero-byte chunk was emitted for {total}"
            );

            if total == 0 {
                assert!(chunks.is_empty(), "zero bytes emits no receipts at all");
                continue;
            }

            // Exactly one Final, and it is last.
            let finals = chunks
                .iter()
                .filter(|(_, k)| *k == ChunkKind::Final)
                .count();
            assert_eq!(finals, 1, "exactly one FINAL per session, for {total}");
            assert_eq!(chunks.last().expect("non-empty").1, ChunkKind::Final);

            // Every non-final chunk is an exact interim chunk, and every chunk
            // passes the rule it claims.
            for (seq, (bytes, kind)) in chunks.iter().enumerate() {
                assert!(
                    check_chunk_size(*kind, *bytes).is_ok(),
                    "chunk {seq} of {total} violates its own kind's rule"
                );
                if seq + 1 < chunks.len() {
                    assert_eq!(*kind, ChunkKind::Interim);
                    assert_eq!(*bytes, RECEIPT_CHUNK_BYTES);
                }
            }

            // chunk_seq is dense from 0 and ordered: the index IS the sequence
            // number, and a receipt built from element `i` carries `i`.
            for (seq, (bytes, kind)) in chunks.iter().enumerate() {
                let seq = u64::try_from(seq).expect("chunk counts are small");
                let receipt = BytesTransferredReceipt::for_test(
                    PROXY_EPOCH_BASE + 1,
                    [0x5E; 32],
                    seq,
                    *kind,
                    *bytes,
                );
                assert_eq!(receipt.chunk_seq, seq);
                assert!(receipt.check_chunk_size().is_ok());
            }
        }

        // A one-byte increase past an exact multiple adds exactly one chunk,
        // and it is the FINAL one carrying that single byte.
        assert_eq!(split_into_chunks(RECEIPT_CHUNK_BYTES).len(), 1);
        assert_eq!(split_into_chunks(RECEIPT_CHUNK_BYTES + 1).len(), 2);
        assert_eq!(
            split_into_chunks(RECEIPT_CHUNK_BYTES + 1).last().unwrap(),
            &(1, ChunkKind::Final)
        );
    }

    /// The fetch-network epoch id space cannot overlap the daily compute space
    /// below it or the enrolment space above it.
    ///
    /// Mutations this detects: moving [`PROXY_EPOCH_BASE`]; re-declaring it here
    /// instead of re-exporting `proxy_merkle`'s (the identity assertion catches
    /// a second declaration that drifts).
    #[test]
    fn proxy_epoch_id_space_is_disjoint() {
        // Bound through locals, the same way `proxy_merkle.rs`'s sibling test
        // does, so these are real comparisons rather than something the
        // compiler folds to `assert!(true)`.
        let proxy_base: u64 = PROXY_EPOCH_BASE;
        let enrollment_base: u64 = ENROLLMENT_EPOCH_BASE;

        // Below: the daily space is a `YYYYMMDD`-shaped integer, so its largest
        // conceivable member is the last day of the year 9999.
        let largest_daily_epoch_id: u64 = 99_991_231;
        assert!(
            proxy_base > largest_daily_epoch_id,
            "the fetch-network space must start above every daily epoch id"
        );

        // Above: a century of hourly epochs still lands below the enrolment
        // base, so the space cannot grow into its neighbour.
        let a_century_of_hours: u64 = 100 * 365 * 24;
        assert!(
            proxy_base + a_century_of_hours < enrollment_base,
            "a century of hourly fetch-network epochs must not reach the enrolment space"
        );

        // This module RE-EXPORTS the constant; it does not declare a second
        // one. If someone adds a local `pub const PROXY_EPOCH_BASE`, the
        // re-export above stops compiling — and if they shadow it, this fails.
        assert_eq!(
            PROXY_EPOCH_BASE,
            super::super::proxy_merkle::PROXY_EPOCH_BASE
        );
        assert_eq!(PROXY_EPOCH_BASE, 8_000_000_000_000);
        assert!(super::super::proxy_merkle::is_proxy_epoch(
            pinned_receipt().epoch_id
        ));
    }

    /// The intent is a distinct signed object, not a projection of the receipt.
    ///
    /// Mutations this detects: signing the intent under the receipt typehash;
    /// dropping the domain binding from `intent_digest`.
    #[test]
    fn the_session_intent_hashes_under_its_own_typehash() {
        let intent = ProxySessionIntent {
            epoch_id: PROXY_EPOCH_BASE + 20_664,
            session_id: [0x5E; 32],
            operator_wallet: [0xA1; 20],
            consumer_id: [0xC2; 32],
            gateway_id: [0x67; 32],
            allowlist_entry_id: 7,
            allowlist_manifest_digest: [0xD3; 32],
            max_bytes: 104_857_600,
            valid_from_unix: 1_800_000_000,
            valid_to_unix: 1_800_003_600,
            price_goat_wei_per_mebibyte: 1_000_000_000_000,
        };
        let receipt = pinned_receipt();
        assert_ne!(intent.intent_struct_hash(), receipt.receipt_struct_hash());
        assert_ne!(
            intent.intent_digest(31_337, [0x11; 20]),
            receipt.receipt_digest(31_337, [0x11; 20])
        );
        assert_ne!(
            intent.intent_digest(31_337, [0x11; 20]),
            intent.intent_digest(84_532, [0x11; 20]),
            "the intent digest binds the chain id too"
        );
        // The intent canonicalises under the same restricted subset.
        let value = intent.canonical_value();
        assert!(canonical_bytes(&value).is_ok());
        for (key, v) in value.as_object().expect("object") {
            assert!(v.is_string(), "{key} is not a string");
        }
    }
}
