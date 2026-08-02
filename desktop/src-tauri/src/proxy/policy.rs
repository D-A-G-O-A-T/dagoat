//! The disclosure policy the consent record commits to.
//!
//! `POLICY_JSON` is the SAME FILE the React surface imports -- one artifact, two
//! readers, so the text the operator reads and the text the daemon hashed cannot
//! drift. The digest is over a separator-joined derivation of the parsed fields,
//! never over file bytes, so a CRLF checkout cannot move it.
//!
//! Design authority: the "The No-Ponzi Invariant — GoatCoin's load-bearing economic
//! rule" spec, §1 and §8.

use goat_proxy_worker::destinations::{self, RegistryError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const POLICY_DOMAIN: &str = "GOAT-PROXY-POLICY-v1";
/// Imported, not redeclared.
///
/// The canonical slug <-> id table and the serialisation taken over it live in
/// exactly one place -- `goat_proxy_worker::destinations` -- and this crate
/// already depends on that one by path (it drives the sidecar's own spawn rather
/// than reimplementing it). A second declaration of either the domain or the
/// table here is the drift the founder ruling exists to end.
pub const ALLOWLIST_DOMAIN: &str = destinations::CANONICAL_DIGEST_DOMAIN;
const UNIT: char = '\u{001f}';
const RECORD: char = '\u{001e}';

pub const POLICY_JSON: &str = include_str!("../../../src/proxy/policy.v1.json");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Paragraph {
    #[serde(default)]
    pub heading: String,
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowlistEntry {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDoc {
    #[serde(default)]
    pub policy_version: u32,
    #[serde(default)]
    pub paragraphs: Vec<Paragraph>,
    #[serde(default)]
    pub accept_label: String,
    #[serde(default)]
    pub decline_label: String,
    #[serde(default)]
    pub allowlist: Vec<AllowlistEntry>,
}

/// The compiled-in policy. Panics at first use only if the shared JSON is malformed,
/// which is a build-breaking authoring error, not a runtime condition.
pub fn policy_doc() -> PolicyDoc {
    serde_json::from_str(POLICY_JSON).expect("policy.v1.json is malformed")
}

/// The allowlist the sidecar reads, written out beside the other daemon-owned files.
///
/// The sidecar takes a PATH, not the parsed list, so the desktop materialises the
/// hosts from the one hashed artifact rather than shipping a second list that could
/// disagree with the text the operator signed.
pub fn allowlist_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("proxy-allowlist.json")
}

fn hex_digest(preimage: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(preimage.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn policy_preimage(doc: &PolicyDoc) -> String {
    let mut out = format!("{POLICY_DOMAIN}\n{}\n", doc.policy_version);
    for p in &doc.paragraphs {
        out.push_str(&p.heading);
        out.push(UNIT);
        out.push_str(&p.body);
        out.push(RECORD);
    }
    out
}

/// The canonical allowlist preimage, built by the ONE implementation.
///
/// This document names each destination by its **slug**; the sidecar names the
/// same destination by a `u32`. Both resolve through
/// `goat_proxy_worker::destinations`, which is why the two agree byte for byte.
///
/// Fallible on purpose: a slug the canonical registry does not carry produces no
/// preimage at all, so no operator is ever shown a digest over a destination the
/// daemon could not load.
pub fn allowlist_preimage(doc: &PolicyDoc) -> Result<String, RegistryError> {
    let pairs: Vec<(&str, &str)> = doc
        .allowlist
        .iter()
        .map(|e| (e.id.as_str(), e.host.as_str()))
        .collect();
    destinations::canonical_preimage_by_slug(&pairs)
}

pub fn policy_digest(doc: &PolicyDoc) -> String {
    hex_digest(&policy_preimage(doc))
}

pub fn allowlist_digest(doc: &PolicyDoc) -> Result<String, RegistryError> {
    Ok(hex_digest(&allowlist_preimage(doc)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_policy_json_parses_and_is_version_one() {
        let doc = policy_doc();
        assert_eq!(doc.policy_version, 1);
        assert_eq!(doc.paragraphs.len(), 12);
        assert_eq!(doc.allowlist.len(), 5);
        assert!(!doc.accept_label.is_empty());
    }

    /// Mutations this detects: any edit to the Rust preimage the JavaScript side did
    /// not make too. The fixture is the third party both readers assert against; a
    /// test comparing the two implementations to each other would drift together.
    #[test]
    fn rust_digests_match_the_cross_language_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../src/proxy/fixtures/policy-digest.json"
        ))
        .expect("fixture is malformed");
        let doc = policy_doc();
        assert_eq!(
            policy_digest(&doc),
            fixture["policy_digest"].as_str().unwrap()
        );
        assert_eq!(
            allowlist_digest(&doc).expect("every shipped slug is in the canonical registry"),
            fixture["allowlist_digest"].as_str().unwrap()
        );
        assert_eq!(
            doc.policy_version,
            fixture["policy_version"].as_u64().unwrap() as u32
        );
    }

    /// Mutations this detects: removing the sort, which would make the digest depend
    /// on file order -- a no-op reordering would then invalidate every signed record.
    #[test]
    fn allowlist_digest_is_order_independent() {
        let doc = policy_doc();
        let mut reversed = doc.clone();
        reversed.allowlist.reverse();
        assert_eq!(
            allowlist_digest(&doc).expect("resolves"),
            allowlist_digest(&reversed).expect("resolves")
        );
        // POSITIVE CONTROL: the preimage really carries the entries.
        let pre = allowlist_preimage(&doc).expect("resolves");
        for e in &doc.allowlist {
            assert!(pre.contains(&e.host));
        }
    }

    /// This half of the desktop names destinations by SLUG and the daemon names
    /// them by `u32`; the canonical registry is what makes the two one list.
    ///
    /// Mutations this detects: this crate declaring its own copy of the table
    /// instead of importing the sidecar's, which is exactly the divergence the
    /// founder ruling ends; the registry lookup dropped so the slug is written
    /// where the id belongs; a slug the registry does not carry hashed as a zero
    /// instead of refused.
    #[test]
    fn the_allowlist_preimage_is_serialised_through_the_canonical_registry() {
        let doc = policy_doc();
        let pre = allowlist_preimage(&doc).expect("resolves");
        assert!(pre.starts_with("GOAT-PROXY-ALLOWLIST-v2\n"));
        assert_eq!(pre.matches(RECORD).count(), doc.allowlist.len());
        // THREE fields per record, so TWO unit separators each.
        assert_eq!(pre.matches(UNIT).count(), 2 * doc.allowlist.len());
        for e in &doc.allowlist {
            let id = destinations::id_for_slug(&e.id).expect("a shipped slug is registered");
            assert!(
                pre.contains(&format!("{id}{UNIT}{}{UNIT}{}{RECORD}", e.id, e.host)),
                "the preimage does not carry {} as an id/slug/host record",
                e.id
            );
        }

        // AN UNREGISTERED SLUG IS A REFUSAL, not a zero and not a hash of
        // nothing.
        let mut stranger = doc.clone();
        stranger.allowlist.push(AllowlistEntry {
            id: "not-registered".into(),
            host: "elsewhere.example".into(),
            note: String::new(),
        });
        assert!(matches!(
            allowlist_digest(&stranger),
            Err(RegistryError::UnknownSlug(_))
        ));
        // POSITIVE CONTROL: the same push with a REGISTERED slug does hash, so
        // the refusal is about the registry and not about the extra row.
        let mut known = doc.clone();
        known.allowlist.push(AllowlistEntry {
            id: "documentation-example-com".into(),
            host: "example.com".into(),
            note: String::new(),
        });
        let widened = allowlist_digest(&known).expect("a registered slug resolves");
        assert_ne!(widened, allowlist_digest(&doc).expect("resolves"));
    }

    /// Mutations this detects: hashing only headings, only bodies, or a truncated
    /// paragraph list -- any of which lets the operator sign one text while the
    /// daemon hashes another.
    #[test]
    fn one_edited_character_moves_the_policy_digest() {
        let doc = policy_doc();
        let mut mutated = doc.clone();
        mutated.paragraphs[0].body.push(' ');
        assert_ne!(policy_digest(&doc), policy_digest(&mutated));
    }

    #[test]
    fn digests_are_sixty_four_lowercase_hex_characters() {
        let doc = policy_doc();
        for d in [policy_digest(&doc), allowlist_digest(&doc).expect("resolves")] {
            assert_eq!(d.len(), 64);
            assert!(d
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        }
    }
}
