//! RFC 8785 (JCS) canonical JSON over a **deliberately restricted subset**, plus
//! the keccak256 of those bytes.
//!
//! This is the byte-producing floor for `feeScheduleHash` as published in
//! the "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring" spec,
//! §8.1 "Quote construction":
//!
//! > "feeScheduleHash = keccak256(UTF8(RFC8785(schedulePayload))). Rust/JavaScript/ops
//! > fixtures pin the canonical bytes and hash before Policy Safe approval."
//!
//! # Why a restricted subset rather than a full JCS implementation
//!
//! Three-way agreement (Rust, JavaScript, ops) is the whole point, and we do not get
//! it for free. Two concrete gaps exist between "what `serde_json` emits" and "what
//! RFC 8785 mandates":
//!
//! 1. **Key ordering.** RFC 8785 §3.2.3 orders object members by UTF-16 code unit.
//!    `serde_json` (built here with `preserve_order` **off** — see the "why we may
//!    rely on this" note below) backs [`serde_json::Map`] with a [`BTreeMap`], whose
//!    key order is Rust `String` `Ord`, i.e. **UTF-8 byte order**. The two orders
//!    agree for all of ASCII and diverge only across the U+E000..=U+FFFF versus
//!    astral-plane boundary: UTF-8 sorts by scalar value throughout, whereas UTF-16
//!    sorts astral characters (encoded as surrogates 0xD800..=0xDBFF) *before*
//!    U+E000..=U+FFFF. A payload containing both kinds of key would hash differently
//!    in Rust and in JavaScript.
//!
//! 2. **Number encoding.** RFC 8785 §3.2.2.3 mandates the ECMAScript
//!    `Number::toString` algorithm (shortest round-tripping decimal, with its own
//!    exponent thresholds). `serde_json` does **not** implement that algorithm, so a
//!    JSON number is not reliably reproducible across the two runtimes.
//!
//! Rather than paper over either gap, this module **refuses to hash** any payload
//! that could exercise them. A payload that would make Rust and JavaScript disagree
//! must not be hashable at all — a hard [`CanonicalJsonError`] is strictly safer than
//! a digest only one side of the fixture pair can reproduce. Each of the three
//! constraints below is a distinct error variant rather than a prose caveat, so a
//! caller cannot ignore one by accident:
//!
//! * [`CanonicalJsonError::NonPortableKey`] — any object key outside `[A-Za-z0-9_]`.
//!   Restricting keys to ASCII makes gap (1) unreachable by construction: within
//!   ASCII, UTF-8 byte order and UTF-16 code-unit order are the same order.
//!   Pinned by [`tests::rejects_non_ascii_key`].
//! * [`CanonicalJsonError::NumberNotAllowed`] — any JSON number, anywhere. This costs
//!   us nothing, because the spec has already foreclosed numbers: "All
//!   integers/timestamps are decimal strings" (same spec, `:808`). Gap (2) is
//!   therefore unreachable too. Pinned by [`tests::rejects_number`].
//! * [`CanonicalJsonError::BoolNotAllowed`] — any JSON bool, anywhere. Bools are not
//!   in the 11-field schedule schema, and admitting a type the spec never blessed
//!   invites a future field whose JS-side encoding nobody checked.
//!   Pinned by [`tests::rejects_bool`].
//!
//! Validation is recursive, so a violation nested inside an object or array is caught
//! with the same force as one at the root — pinned by [`tests::rejects_nested_violations`].
//!
//! # Why we may rely on `serde_json` for ordering at all
//!
//! [`serde_json::Map`] is a [`BTreeMap`] **only while the `preserve_order` feature is
//! off**; with it on, `Map` becomes an `IndexMap` and preserves *insertion* order,
//! which would silently destroy reproducibility. This is load-bearing and verified,
//! not assumed: `Cargo.lock:4126-4136` pins `serde_json` 1.0.150 with dependencies
//! `itoa, memchr, serde, serde_core, zmij` — no `indexmap`, so the feature is off.
//! [`tests::key_order_is_byte_order_and_input_order_independent`] pins the resulting
//! behaviour directly, so if a future dependency ever unifies `preserve_order` on,
//! that test fails rather than the hash silently drifting.
//!
//! # What `serde_json` already gets right
//!
//! String **values** need no restriction. RFC 8785 §3.2.2.2 requires the same escape
//! set as ECMAScript `JSON.stringify`: escape `"` and `\`, use the short forms
//! `\b \f \n \r \t`, use `\u00xx` for the remaining C0 controls, and emit everything
//! else literally as UTF-8. `serde_json` does exactly this, and a Rust `String`
//! cannot hold a lone surrogate, so the well-formed-stringify divergence that bites
//! JavaScript cannot arise here. Pinned by [`tests::string_escaping_matches_jcs`].
//! Ordering is the only place the UTF-8/UTF-16 distinction is observable, which is why
//! the ASCII restriction applies to keys and not to values.
//!
//! [`BTreeMap`]: std::collections::BTreeMap

use serde_json::Value;
use thiserror::Error;

use crate::merkle::keccak256;

/// Refusal reasons. Every variant means "these bytes would not be reproducible
/// across Rust and JavaScript", never "this JSON is malformed".
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CanonicalJsonError {
    /// An object key outside `[A-Za-z0-9_]`. See module docs, gap (1).
    #[error(
        "non-portable object key at {path}: {key:?} has characters outside [A-Za-z0-9_]; \
         RFC 8785 orders keys by UTF-16 code unit but serde_json orders by UTF-8 byte, \
         and the two agree only within ASCII"
    )]
    NonPortableKey { path: String, key: String },

    /// A JSON number. See module docs, gap (2).
    #[error(
        "JSON number at {path}: RFC 8785 mandates ECMAScript Number::toString, which \
         serde_json does not implement; the fee-schedule schema requires all integers \
         and timestamps to be decimal strings"
    )]
    NumberNotAllowed { path: String },

    /// A JSON bool. Not part of the published 11-field schedule schema.
    #[error(
        "JSON bool at {path}: the canonical schedule schema admits only strings, \
         objects, arrays and null"
    )]
    BoolNotAllowed { path: String },

    /// `serde_json` failed to serialise an already-validated value. Not expected to
    /// be reachable; surfaced rather than unwrapped so a hash is never invented.
    #[error("canonical serialisation failed: {0}")]
    Serialize(String),
}

/// True for the portable key alphabet `[A-Za-z0-9_]`.
fn is_portable_key(key: &str) -> bool {
    !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Recursively reject anything that would make Rust and JavaScript disagree.
///
/// `path` is a JSONPath-ish breadcrumb (`$`, `$.feeToken`, `$.list[0]`) carried purely
/// so an operator reading a refusal knows which field to fix.
fn validate(value: &Value, path: &str) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Number(_) => Err(CanonicalJsonError::NumberNotAllowed {
            path: path.to_string(),
        }),
        Value::Bool(_) => Err(CanonicalJsonError::BoolNotAllowed {
            path: path.to_string(),
        }),
        Value::Null | Value::String(_) => Ok(()),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                validate(item, &format!("{path}[{i}]"))?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (key, child) in map {
                if !is_portable_key(key) {
                    return Err(CanonicalJsonError::NonPortableKey {
                        path: path.to_string(),
                        key: key.clone(),
                    });
                }
                validate(child, &format!("{path}.{key}"))?;
            }
            Ok(())
        }
    }
}

/// Canonical UTF-8 bytes for `value`, or a typed refusal.
///
/// The output is `RFC8785(value)` restricted to the subset described in the module
/// docs: no whitespace, object members sorted, strings escaped per JCS.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, CanonicalJsonError> {
    validate(value, "$")?;
    serde_json::to_vec(value).map_err(|e| CanonicalJsonError::Serialize(e.to_string()))
}

/// `keccak256(UTF8(RFC8785(value)))` — the hash construction named at
/// the "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring" spec, §8.1.
///
/// Note that per the same spec (§5.1 "FeeTokenRegistry") "Approval metadata is
/// outside the payload":
/// `feeScheduleHash` and any operator note live **outside** the object handed to this
/// function, which is what keeps the hash from having to reference itself.
pub fn canonical_hash(value: &Value) -> Result<[u8; 32], CanonicalJsonError> {
    Ok(keccak256(&canonical_bytes(value)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canonical_str(value: &Value) -> String {
        String::from_utf8(canonical_bytes(value).expect("must canonicalise")).unwrap()
    }

    /// The load-bearing claim from the module docs: `serde_json::Map` is a `BTreeMap`
    /// (`preserve_order` off, per `Cargo.lock:4126-4136`), so members come out in
    /// UTF-8 byte order no matter what order they went in. If a future dependency
    /// unifies `preserve_order` on, this fails instead of the hash drifting silently.
    #[test]
    fn key_order_is_byte_order_and_input_order_independent() {
        // Deliberately scrambled, and chosen so ASCII byte order is observable:
        // uppercase 'B' (0x42) sorts before lowercase 'a' (0x61), and '_' (0x5F)
        // sorts between them.
        let scrambled = json!({ "a": "1", "_z": "2", "B": "3", "aa": "4", "A0": "5" });
        assert_eq!(
            canonical_str(&scrambled),
            r#"{"A0":"5","B":"3","_z":"2","a":"1","aa":"4"}"#
        );

        // Same members, different insertion order => identical bytes.
        let other_order = json!({ "aa": "4", "A0": "5", "a": "1", "B": "3", "_z": "2" });
        assert_eq!(
            canonical_bytes(&scrambled).unwrap(),
            canonical_bytes(&other_order).unwrap()
        );
        assert_eq!(
            canonical_hash(&scrambled).unwrap(),
            canonical_hash(&other_order).unwrap()
        );
    }

    /// Gap (1): a key outside `[A-Za-z0-9_]` is where UTF-8 and UTF-16 ordering can
    /// diverge, so it must be unhashable rather than hashable-and-ambiguous.
    #[test]
    fn rejects_non_ascii_key() {
        let err = canonical_bytes(&json!({ "feeTokén": "x" })).unwrap_err();
        assert!(
            matches!(&err, CanonicalJsonError::NonPortableKey { key, .. } if key == "feeTokén"),
            "unexpected: {err:?}"
        );

        // Astral-plane key: the exact case where UTF-16 surrogate ordering sorts
        // *before* U+E000..=U+FFFF while UTF-8 sorts after.
        assert!(matches!(
            canonical_bytes(&json!({ "\u{1F410}": "goat" })).unwrap_err(),
            CanonicalJsonError::NonPortableKey { .. }
        ));

        // ASCII punctuation is also outside the alphabet: no partial credit.
        assert!(matches!(
            canonical_bytes(&json!({ "fee-token": "x" })).unwrap_err(),
            CanonicalJsonError::NonPortableKey { .. }
        ));
        assert!(matches!(
            canonical_bytes(&json!({ "": "x" })).unwrap_err(),
            CanonicalJsonError::NonPortableKey { .. }
        ));

        // The whole portable alphabet is accepted, so the rule is a real filter and
        // not an accidental blanket refusal.
        assert!(canonical_bytes(&json!({ "aZ0_": "x" })).is_ok());
    }

    /// Gap (2): serde_json does not implement ECMAScript `Number::toString`, and the
    /// spec requires decimal strings anyway.
    #[test]
    fn rejects_number() {
        let err = canonical_bytes(&json!({ "decimals": 6 })).unwrap_err();
        assert!(
            matches!(&err, CanonicalJsonError::NumberNotAllowed { path } if path == "$.decimals"),
            "unexpected: {err:?}"
        );
        // Floats and exponents are the worst case for round-tripping; same refusal.
        assert!(matches!(
            canonical_bytes(&json!({ "x": 1.0e21 })).unwrap_err(),
            CanonicalJsonError::NumberNotAllowed { .. }
        ));
        // The string form the spec actually mandates is accepted.
        assert_eq!(
            canonical_str(&json!({ "decimals": "6" })),
            r#"{"decimals":"6"}"#
        );
    }

    /// Bools are not in the published 11-field schema.
    #[test]
    fn rejects_bool() {
        let err = canonical_bytes(&json!({ "active": true })).unwrap_err();
        assert!(
            matches!(&err, CanonicalJsonError::BoolNotAllowed { path } if path == "$.active"),
            "unexpected: {err:?}"
        );
        assert!(matches!(
            canonical_bytes(&json!({ "active": false })).unwrap_err(),
            CanonicalJsonError::BoolNotAllowed { .. }
        ));
    }

    /// Constraint (c): nesting must not launder a violation. The error path names the
    /// offending field so an operator can fix it without guessing.
    #[test]
    fn rejects_nested_violations() {
        let err = canonical_bytes(&json!({ "gasUnitCeilings": { "bind": 120000 } })).unwrap_err();
        assert!(
            matches!(&err, CanonicalJsonError::NumberNotAllowed { path }
                if path == "$.gasUnitCeilings.bind"),
            "unexpected: {err:?}"
        );

        let err = canonical_bytes(&json!({ "list": ["ok", { "bad": true }] })).unwrap_err();
        assert!(
            matches!(&err, CanonicalJsonError::BoolNotAllowed { path }
                if path == "$.list[1].bad"),
            "unexpected: {err:?}"
        );

        let err =
            canonical_bytes(&json!({ "outer": { "inner": { "n\u{00e9}": "x" } } })).unwrap_err();
        assert!(
            matches!(&err, CanonicalJsonError::NonPortableKey { path, .. }
                if path == "$.outer.inner"),
            "unexpected: {err:?}"
        );
    }

    /// Nested objects/arrays canonicalise, sorting at every level, with no whitespace.
    #[test]
    fn nested_objects_and_arrays_canonicalise() {
        let value = json!({
            "gasUnitCeilings": { "enroll": "90000", "bind": "120000" },
            "actionFeesRaw": { "bind": "500000", "enroll": "400000" },
            "list": ["b", "a", { "z": "1", "y": "2" }, []],
            "nothing": null,
        });
        assert_eq!(
            canonical_str(&value),
            concat!(
                r#"{"actionFeesRaw":{"bind":"500000","enroll":"400000"},"#,
                r#""gasUnitCeilings":{"bind":"120000","enroll":"90000"},"#,
                r#""list":["b","a",{"y":"2","z":"1"},[]],"#,
                r#""nothing":null}"#
            )
        );
        // Array order is data, not a set: it must survive verbatim.
        assert!(canonical_str(&value).contains(r#"["b","a","#));
    }

    /// The degenerate payload still has a definite encoding.
    #[test]
    fn empty_object_canonicalises() {
        assert_eq!(canonical_str(&json!({})), "{}");
        assert_eq!(canonical_bytes(&json!({})).unwrap(), b"{}".to_vec());
        assert_eq!(canonical_str(&json!([])), "[]");
    }

    /// Pins the claim in the module docs that `serde_json`'s string-value escaping is
    /// already RFC 8785 §3.2.2.2 / `JSON.stringify` compatible, so values need no
    /// ASCII restriction. If serde_json ever changes its escape table, this fails.
    #[test]
    fn string_escaping_matches_jcs() {
        // Short forms for \b \f \n \r \t, `\u00xx` for other C0 controls, `"` and `\`
        // escaped, `/` NOT escaped, DEL and non-ASCII emitted literally as UTF-8.
        let value = json!({ "s": "\u{8}\u{c}\n\r\t\u{1}\"\\/\u{7f}é\u{1F410}" });
        assert_eq!(
            canonical_str(&value),
            "{\"s\":\"\\b\\f\\n\\r\\t\\u0001\\\"\\\\/\u{7f}é\u{1F410}\"}"
        );
    }

    /// KNOWN-ANSWER TEST — the fixture the JavaScript and ops implementations must
    /// reproduce byte-for-byte. Any refactor that changes the canonical bytes fails
    /// here loudly instead of drifting into a hash only Rust can compute.
    ///
    /// The payload is a five-field subset of the schedule schema at
    /// the "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring" spec, §8.1,
    /// with lowercase-hex address and decimal-string integers per §5.1, and is
    /// supplied in non-sorted order so the fixture also exercises the ordering rule.
    #[test]
    fn known_answer_hash() {
        let payload = json!({
            "scheduleVersion": "1",
            "feeToken": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "chainId": "8453",
            "schemaVersion": "1",
            "decimals": "6",
        });

        // Note the member order: "scheduleVersion" precedes "schemaVersion" because at
        // index 4 'd' (0x64) < 'm' (0x6D). That is *not* the order a human sorts these
        // two by eye, which is precisely why the fixture pins bytes and not intuition.
        const EXPECTED_BYTES: &str = concat!(
            r#"{"chainId":"8453","decimals":"6","#,
            r#""feeToken":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","#,
            r#""scheduleVersion":"1","schemaVersion":"1"}"#
        );
        assert_eq!(canonical_str(&payload), EXPECTED_BYTES);
        assert_eq!(
            EXPECTED_BYTES.len(),
            131,
            "canonical byte length is part of the fixture"
        );

        // Cross-checked against an independent keccak implementation (foundry
        // `cast keccak`) over these exact 131 UTF-8 bytes supplied as hex, so this
        // constant is not merely self-consistent with our own tiny-keccak call.
        const EXPECTED_HASH: &str =
            "21695bf5b63f320da2e6907150f510b2782fb70b89a17b2949786707b18cc3b8";
        assert_eq!(
            hex::encode(canonical_hash(&payload).unwrap()),
            EXPECTED_HASH
        );
    }
}
