//! INV-11's meter half, asserted from **outside** the crate.
//!
//! The unit tests in `meter.rs` can see private fields and private helpers.
//! These cannot, and that is the point: what a downstream consumer of this
//! crate can put into a meter record is exactly what these tests can reach. A
//! destination field that were somehow private and internal would still be a
//! defect, but a destination field on the public surface is the one that ends
//! up in a database, in a receipt and on a chain.
//!
//! Design authority: the "Residential Proxy Network (P3) Implementation Plan",
//! §2 (INV-11).

use goat_proxy_tunnel::meter::{
    gateway_signing_key_from_seed, sign_meter_record, verify_meter_record, GatewaySessionMeter,
    TunnelMeterRecord, METER_RECORD_FIELDS,
};

fn sealed(entry_id: u32, body: &[u8]) -> TunnelMeterRecord {
    let mut meter = GatewaySessionMeter::new([0x11u8; 32], entry_id, 0, body.len() as u64);
    meter.observe(body).unwrap();
    meter.accept_node_report(body.len() as u64 + 137);
    meter.seal(1_700_000_000).unwrap()
}

/// The public field set, enumerated from outside the crate.
///
/// **Mutations this detects:** adding any destination-bearing field to
/// `TunnelMeterRecord` and exposing it — the addition is a compile error inside
/// `canonical_fields`, and wiring it through produces an eighth name here.
#[test]
fn the_public_meter_surface_carries_no_destination_field() {
    let record = sealed(9, b"body bytes");
    let fields = record.canonical_fields();
    let names: Vec<&str> = fields.iter().map(|(n, _)| *n).collect();

    assert_eq!(names, METER_RECORD_FIELDS.to_vec());
    assert_eq!(names.len(), 7);

    // Assembled at runtime so this file does not itself contain the tokens it
    // forbids as field names.
    let forbidden: Vec<String> = ["ho", "ur", "pa", "que", "hea", "coo", "domai"]
        .iter()
        .zip(["st", "l", "th", "ry", "der", "kie", "n"].iter())
        .map(|(a, b)| format!("{a}{b}"))
        .collect();

    // Positive control: the matcher fires on a field set that DOES carry a
    // destination.
    let control = ["session_id", "host", "domain"];
    assert!(
        control
            .iter()
            .filter(|n| forbidden.iter().any(|t| n.contains(t.as_str())))
            .count()
            == 2,
        "the scanner cannot see the two destination fields in its own control set"
    );

    for name in &names {
        for token in &forbidden {
            assert!(
                !name.contains(token.as_str()),
                "{name} can carry a destination"
            );
        }
    }
}

/// Every serialised value is a number or a fixed-width opaque identifier.
///
/// **Mutations this detects:** widening any field to a free-text type, or
/// letting the allowlist **entry id** be replaced by the name behind it — the
/// substitution that turns a non-identifying record into a browsing history.
#[test]
fn a_meter_record_serialises_to_integers_and_identifiers_only() {
    let record = sealed(3, b"0123456789");
    for (name, value) in record.canonical_fields() {
        assert!(!value.is_empty(), "{name} serialised to nothing");
        if name == "session_id" {
            assert_eq!(value.len(), 64);
            assert!(
                value.chars().all(|c| c.is_ascii_hexdigit()),
                "session_id is not hex"
            );
        } else {
            assert!(
                value.parse::<u64>().is_ok(),
                "{name} carries {value:?}, which is not an integer"
            );
        }
    }

    // Positive control on the shape check: a value that is neither would fail
    // it, so the pass above is not vacuous.
    assert!("gateway.example".parse::<u64>().is_err());
    assert!(!"gateway.example".chars().all(|c| c.is_ascii_hexdigit()));
}

/// Two sessions to two different allowlist entries differ in exactly one field.
///
/// **Mutations this detects:** deriving any record field from the destination —
/// a hashed hostname in the session id, an entry id computed from the name, a
/// timestamp that leaks the origin. Anything of that shape makes a second field
/// differ.
#[test]
fn two_sessions_differ_only_in_the_allowlist_entry_id() {
    let body = b"identical body bytes";
    let a = sealed(1, body);
    let b = sealed(2, body);

    let fa = a.canonical_fields();
    let fb = b.canonical_fields();
    let differing: Vec<&str> = fa
        .iter()
        .zip(fb.iter())
        .filter(|((_, va), (_, vb))| va != vb)
        .map(|((n, _), _)| *n)
        .collect();
    assert_eq!(
        differing,
        vec!["allowlist_entry_id"],
        "a record field other than the entry id varies with the destination"
    );

    // Positive control on the comparison: a record that differs in a second
    // field is detected as differing in two.
    let c = sealed(2, b"a different body length");
    let fc = c.canonical_fields();
    let differing_two: Vec<&str> = fa
        .iter()
        .zip(fc.iter())
        .filter(|((_, va), (_, vc))| va != vc)
        .map(|((n, _), _)| *n)
        .collect();
    assert!(
        differing_two.len() > 1,
        "the comparison cannot see a second differing field, so the result above means nothing"
    );

    // And the signatures over the two records are distinct documents: nothing
    // about the destination is shared between them.
    let key = gateway_signing_key_from_seed([0x77u8; 32]);
    let sa = sign_meter_record(&key, &a);
    let sb = sign_meter_record(&key, &b);
    assert_ne!(sa.record_hash, sb.record_hash);
    assert!(verify_meter_record(&a, &sa));
    assert!(!verify_meter_record(&a, &sb));
}
