//! The canonical destination registry, and the canonical serialisation the
//! operator-facing allowlist digest is taken over.
//!
//! # Founder ruling: one static slug <-> id mapping, shared by both components
//!
//! The two sides of this feature agreed on the DIGEST and still disagreed about
//! the DATA. The desktop names a destination by a **slug** in its disclosure
//! document -- the string an operator could read out loud -- while
//! [`crate::policy::AllowlistEntry::id`] is a **`u32`**, carried in receipts, in
//! [`crate::resolve::PinnedTarget`], in the `robots.txt` cache key and in every
//! operator log line. Neither identifier can simply become the other: a receipt
//! cannot carry a string it was never sized for, and a disclosure cannot show an
//! integer nobody can check.
//!
//! The ruling is that a canonical, static, one-to-one mapping between the two
//! exists **exactly once**, and that both sides serialise the destination list
//! through it before hashing. This module is that one place.
//!
//! # Where the mapping lives, and why here
//!
//! The table itself is `destinations.v1.json`, at the root of THIS crate, and
//! this module embeds it with `include_str!`. Three consumers read one
//! definition:
//!
//! 1. **The sidecar** -- this crate, the file's owner.
//! 2. **The desktop's Rust half** -- it already depends on this crate by path
//!    (it drives [`crate::supervisor::ProxySupervisor::spawn_pinned`] rather
//!    than reimplementing the spawn), so it IMPORTS these functions. There is no
//!    second copy of the table on that side, and the dependency runs
//!    desktop -> sidecar, which is the direction the manifest already fixes.
//! 3. **The desktop's JavaScript** -- it cannot link a Rust crate, so it carries
//!    a mirror. That mirror is compared against THESE EXACT BYTES by a test
//!    which reads this file off disk, so a drift between the two is a red test
//!    and never a silent divergence.
//!
//! The table did not go in the desktop tree, which would have let the JavaScript
//! import it directly, because the sidecar's production code would then have to
//! reach up into `desktop/` to build -- inverting the one dependency direction
//! this crate's manifest is explicit about, and making a standalone sidecar
//! build depend on a tree it is not allowed to know exists.
//!
//! # Ids are permanent
//!
//! A slug's id is its identity. The registry grows only by appending the next
//! integer, ids are never reused, and the numbering is contiguous from one --
//! [`registry`] refuses to build otherwise, so a gap left by a deleted row is a
//! refusal rather than a hole somebody later fills with a different destination.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Task 29 and its Security invariants section; and the founder ruling
//! recorded on [`crate::policy::operator_allowlist_preimage`].

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The one table. Embedded rather than read at run time so a missing or moved
/// registry is a compile error in this crate, not a daemon that starts and then
/// cannot name its own destinations.
pub const REGISTRY_JSON: &str = include_str!("../destinations.v1.json");

/// The schema tag the registry file must carry.
pub const REGISTRY_SCHEMA_ID: &str = "GOAT_PROXY_DESTINATION_REGISTRY_V1";

/// Domain separation for the canonical allowlist digest.
///
/// **v2, and the bump is the point.** A v1 preimage named a destination by ONE
/// identifier -- the slug on the desktop, the integer here -- so the two sides
/// produced different bytes from the same list. A v2 record names both, resolved
/// through this registry, which is what makes them agree. Any consent record
/// whose `allowlist_digest` was computed the v1 way therefore fails the gate,
/// which is the wanted behaviour: it was computed over a preimage that did not
/// bind what the operator's daemon would actually load.
pub const CANONICAL_DIGEST_DOMAIN: &str = "GOAT-PROXY-ALLOWLIST-v2";

/// Between the fields of one record.
pub const UNIT_SEPARATOR: char = '\u{1f}';

/// After each record.
pub const RECORD_SEPARATOR: char = '\u{1e}';

/// The longest slug the registry will accept. A bound, not a guess: it exists so
/// that "the table is small and readable" is enforced rather than hoped for.
const MAX_SLUG_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Why a destination could not be named canonically.
///
/// Every variant is a REFUSAL. There is deliberately no variant meaning "carry
/// on with a default", and no function in this module has a success path that
/// yields a digest over an identifier it could not resolve: an unknown slug and
/// an unknown id both stop here, rather than hashing a zero or hashing nothing.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RegistryError {
    /// The embedded table is itself unusable. Every lookup fails while this
    /// holds, so a corrupt registry closes the feature instead of opening it.
    #[error("the destination registry is unusable: {0}")]
    RegistryInvalid(String),
    /// A slug that is not in the table. **Not** a zero id.
    #[error("destination slug {0:?} is not in the canonical registry")]
    UnknownSlug(String),
    /// An id that is not in the table. **Not** an empty slug.
    #[error("destination id {0} is not in the canonical registry")]
    UnknownId(u32),
    /// Two entries of one list resolved to the same destination, so the list is
    /// not a set and its preimage would depend on which copy was rendered.
    #[error("destination id {0} appears twice in one list")]
    DuplicateDestination(u32),
    /// A host that could not be rendered unambiguously into the preimage.
    ///
    /// The preimage has no length prefixes -- the separators carry that weight
    /// -- so a host containing either separator could spell two different lists
    /// the same way. It is refused here as well as at load time, because this
    /// function is also reached from the desktop, whose document is not read by
    /// [`crate::policy::EgressPolicy::load_entries`].
    #[error("host {0:?} cannot be rendered into the canonical preimage")]
    MalformedHost(String),
}

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRegistry {
    schema_id: String,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
    destinations: Vec<WireDestination>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDestination {
    id: u32,
    slug: String,
}

/// One row: a slug and the integer that is its permanent identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub id: u32,
    pub slug: String,
}

/// The validated table, plus the reverse index.
pub struct Registry {
    rows: Vec<Destination>,
    id_of: HashMap<String, u32>,
}

impl Registry {
    /// Every row, in id order.
    pub fn rows(&self) -> &[Destination] {
        &self.rows
    }
}

fn invalid(msg: String) -> RegistryError {
    RegistryError::RegistryInvalid(msg)
}

/// A slug is lower-case ASCII letters, digits and inner hyphens.
///
/// The charset is not decoration. It is what makes the unprefixed preimage safe
/// from this side: a string drawn from `[a-z0-9-]` can contain neither
/// separator, so the slug field can never spell a record boundary.
fn check_slug(slug: &str) -> Result<(), RegistryError> {
    if slug.is_empty() || slug.len() > MAX_SLUG_LEN {
        return Err(invalid(format!(
            "slug {slug:?} must be between 1 and {MAX_SLUG_LEN} bytes"
        )));
    }
    if slug.starts_with('-') || slug.ends_with('-') {
        return Err(invalid(format!(
            "slug {slug:?} may not start or end with a hyphen"
        )));
    }
    if !slug
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(invalid(format!(
            "slug {slug:?} is outside the permitted set of lower-case ASCII letters, digits and \
             hyphens; that set is what keeps a slug from spelling a preimage separator"
        )));
    }
    Ok(())
}

fn build() -> Result<Registry, RegistryError> {
    let wire: WireRegistry = serde_json::from_str(REGISTRY_JSON)
        .map_err(|e| invalid(format!("the registry file does not match its schema: {e}")))?;

    if wire.schema_id != REGISTRY_SCHEMA_ID {
        return Err(invalid(format!(
            "schema_id is {:?}, expected {REGISTRY_SCHEMA_ID:?}",
            wire.schema_id
        )));
    }
    if wire.destinations.is_empty() {
        return Err(invalid(
            "the registry is empty; an empty table is a refusal, never a permissive one".into(),
        ));
    }

    // CONTIGUOUS FROM ONE, IN ORDER. This single check carries three properties
    // at once: no gaps, no duplicate ids, and no id zero -- zero being reserved
    // so that an uninitialised integer names no destination, exactly as
    // `validate_entry` requires of an allowlist entry.
    let mut rows = Vec::with_capacity(wire.destinations.len());
    for (i, d) in wire.destinations.iter().enumerate() {
        let expected = i as u32 + 1;
        if d.id != expected {
            return Err(invalid(format!(
                "row {i} carries id {} where contiguous numbering requires {expected}; the table \
                 is written in ascending order with no gaps, so that a deleted row is a refusal \
                 rather than a hole a different destination is later dropped into",
                d.id
            )));
        }
        check_slug(&d.slug)?;
        rows.push(Destination {
            id: d.id,
            slug: d.slug.clone(),
        });
    }

    // ONE-TO-ONE, the other direction. Contiguity already made the ids unique;
    // this makes the slugs unique, so no id has two names either.
    let mut id_of: HashMap<String, u32> = HashMap::with_capacity(rows.len());
    for row in &rows {
        if let Some(first) = id_of.insert(row.slug.clone(), row.id) {
            return Err(invalid(format!(
                "slug {:?} is mapped to ids {} and {}; the mapping is one-to-one",
                row.slug, first, row.id
            )));
        }
    }

    Ok(Registry { rows, id_of })
}

/// The validated table, built once.
///
/// Returns a REFUSAL rather than panicking when the embedded table is unusable.
/// A panic here would take the process down inside whatever call happened to
/// touch a destination first; an error makes every digest unobtainable, which
/// closes the feature by the same route every other refusal in this crate uses.
pub fn registry() -> Result<&'static Registry, RegistryError> {
    static REGISTRY: OnceLock<Result<Registry, RegistryError>> = OnceLock::new();
    REGISTRY.get_or_init(build).as_ref().map_err(Clone::clone)
}

/// The slug this id names. An id outside the table is [`RegistryError::UnknownId`].
pub fn slug_for_id(id: u32) -> Result<&'static str, RegistryError> {
    let reg = registry()?;
    reg.rows
        .iter()
        .find(|d| d.id == id)
        .map(|d| d.slug.as_str())
        .ok_or(RegistryError::UnknownId(id))
}

/// The id this slug names. A slug outside the table is
/// [`RegistryError::UnknownSlug`].
pub fn id_for_slug(slug: &str) -> Result<u32, RegistryError> {
    let reg = registry()?;
    reg.id_of
        .get(slug)
        .copied()
        .ok_or_else(|| RegistryError::UnknownSlug(slug.to_string()))
}

// ---------------------------------------------------------------------------
// The canonical serialisation
// ---------------------------------------------------------------------------

/// A host may carry neither separator, no control byte, no space, and must be
/// non-empty ASCII.
fn check_host(host: &str) -> Result<(), RegistryError> {
    let bad = host.is_empty()
        || !host.is_ascii()
        || host.bytes().any(|b| b.is_ascii_control() || b == b' ')
        || host.contains(UNIT_SEPARATOR)
        || host.contains(RECORD_SEPARATOR);
    if bad {
        return Err(RegistryError::MalformedHost(host.to_string()));
    }
    Ok(())
}

/// Render resolved triples. Private, so there is exactly one place that decides
/// what the canonical bytes are.
fn render(mut rows: Vec<(u32, &'static str, &str)>) -> Result<String, RegistryError> {
    // SORTED BY THE NUMERIC ID, ASCENDING -- not by the id's text, which orders
    // "10" before "2" and would make the digest depend on how many destinations
    // happen to be registered.
    rows.sort_by_key(|(id, _, _)| *id);
    for pair in rows.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(RegistryError::DuplicateDestination(pair[0].0));
        }
    }

    let mut out = format!("{CANONICAL_DIGEST_DOMAIN}\n");
    for (id, slug, host) in &rows {
        check_host(host)?;
        // Base ten, no padding and no separators -- the one spelling a `u32`
        // has here, and the reason the id field cannot spell a record boundary.
        out.push_str(&id.to_string());
        out.push(UNIT_SEPARATOR);
        out.push_str(slug);
        out.push(UNIT_SEPARATOR);
        out.push_str(host);
        out.push(RECORD_SEPARATOR);
    }
    Ok(out)
}

/// The canonical preimage for destinations named by their **numeric id**.
///
/// This is the sidecar's own entry point: it holds `u32` ids and must resolve
/// each one to its registered slug to produce the bytes. A mutation that skipped
/// the lookup could not produce the same string, which is what makes the
/// registry load-bearing on this side rather than decorative.
///
/// The exact construction, so a reader can see it without running a hash:
/// [`CANONICAL_DIGEST_DOMAIN`], a newline, then per destination sorted by id
/// ascending -- the id in base ten, [`UNIT_SEPARATOR`], the registered slug,
/// [`UNIT_SEPARATOR`], the host, [`RECORD_SEPARATOR`]. No trailing newline and
/// no length prefixes.
pub fn canonical_preimage_by_id(entries: &[(u32, &str)]) -> Result<String, RegistryError> {
    let mut rows: Vec<(u32, &'static str, &str)> = Vec::with_capacity(entries.len());
    for (id, host) in entries {
        rows.push((*id, slug_for_id(*id)?, host));
    }
    render(rows)
}

/// The canonical preimage for destinations named by their **slug**.
///
/// This is the desktop's entry point: its disclosure document names slugs, and
/// each one must resolve to its registered id to produce the bytes. The two
/// entry points converge on [`render`], so the two sides cannot disagree about
/// the serialisation without disagreeing about this crate.
pub fn canonical_preimage_by_slug(entries: &[(&str, &str)]) -> Result<String, RegistryError> {
    let mut rows: Vec<(u32, &'static str, &str)> = Vec::with_capacity(entries.len());
    for (slug, host) in entries {
        let id = id_for_slug(slug)?;
        rows.push((id, slug_for_id(id)?, host));
    }
    render(rows)
}

fn sha256(preimage: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(preimage.as_bytes());
    hasher.finalize().into()
}

/// SHA-256 of [`canonical_preimage_by_id`].
pub fn canonical_digest_by_id(entries: &[(u32, &str)]) -> Result<[u8; 32], RegistryError> {
    Ok(sha256(&canonical_preimage_by_id(entries)?))
}

/// SHA-256 of [`canonical_preimage_by_slug`]. **This is what consent binds.**
pub fn canonical_digest_by_slug(entries: &[(&str, &str)]) -> Result<[u8; 32], RegistryError> {
    Ok(sha256(&canonical_preimage_by_slug(entries)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped table is well formed, and every property the ruling requires
    /// of it is asserted here rather than assumed.
    ///
    /// Mutations this detects: a duplicate id or a duplicate slug added to
    /// `destinations.v1.json`; a gap left by a deleted row; an id zero; the
    /// contiguity check written as a `>=` so that ascending-with-holes passes.
    #[test]
    fn the_shipped_registry_is_contiguous_and_one_to_one() {
        let reg = registry().expect("the shipped registry must build");
        let rows = reg.rows();
        assert!(!rows.is_empty());

        // NO GAPS, NO DUPLICATE IDS, NO ZERO.
        for (i, d) in rows.iter().enumerate() {
            assert_eq!(d.id, i as u32 + 1, "row {i} breaks contiguous numbering");
        }
        assert!(rows.iter().all(|d| d.id != 0));

        // NO DUPLICATE SLUGS.
        for (i, a) in rows.iter().enumerate() {
            for b in &rows[i + 1..] {
                assert_ne!(a.slug, b.slug, "slug {:?} appears twice", a.slug);
            }
        }

        // ONE-TO-ONE, ASSERTED IN BOTH DIRECTIONS: every row round-trips through
        // both lookups and lands back on itself.
        for d in rows {
            assert_eq!(id_for_slug(&d.slug).expect("slug resolves"), d.id);
            assert_eq!(slug_for_id(d.id).expect("id resolves"), d.slug.as_str());
        }
    }

    /// Mutations this detects: an `unwrap_or(0)` on the slug lookup, which would
    /// name destination zero; an `unwrap_or_default()` on the id lookup, which
    /// would hash an empty slug; either lookup relaxed to a prefix or
    /// case-insensitive match.
    #[test]
    fn an_unregistered_slug_or_id_is_refused_and_never_defaulted() {
        assert_eq!(
            id_for_slug("no-such-destination"),
            Err(RegistryError::UnknownSlug("no-such-destination".into()))
        );
        // Case and whitespace are not near-misses to be forgiven.
        let known = registry().expect("registry").rows()[0].slug.clone();
        assert!(id_for_slug(&known.to_ascii_uppercase()).is_err());
        assert!(id_for_slug(&format!(" {known}")).is_err());

        let past_the_end = registry().expect("registry").rows().len() as u32 + 1;
        assert_eq!(slug_for_id(0), Err(RegistryError::UnknownId(0)));
        assert_eq!(
            slug_for_id(past_the_end),
            Err(RegistryError::UnknownId(past_the_end))
        );

        // ...and the refusal reaches the DIGEST, which is the property that
        // matters: no preimage is produced at all.
        assert!(canonical_digest_by_slug(&[("no-such-destination", "a.example")]).is_err());
        assert!(canonical_digest_by_id(&[(past_the_end, "a.example")]).is_err());

        // POSITIVE CONTROL: the same calls with a registered destination do
        // produce a digest, so the refusals above are about the identifier and
        // not about the shape of the call.
        assert!(canonical_digest_by_slug(&[(known.as_str(), "a.example")]).is_ok());
        assert!(canonical_digest_by_id(&[(1, "a.example")]).is_ok());
    }

    /// The two entry points are one serialisation.
    ///
    /// Mutations this detects: the slug-keyed path rendering the slug where the
    /// id-keyed path renders the id, or either path sorting differently -- which
    /// is exactly the disagreement between the two sides that this ruling
    /// exists to end.
    #[test]
    fn naming_a_destination_by_slug_or_by_id_produces_the_same_bytes() {
        let by_id = canonical_preimage_by_id(&[(4, "api.crossref.org"), (5, "api.openalex.org")])
            .expect("id path");
        let by_slug = canonical_preimage_by_slug(&[
            ("crossref-api", "api.crossref.org"),
            ("openalex-api", "api.openalex.org"),
        ])
        .expect("slug path");
        assert_eq!(by_id, by_slug);

        // The shape, spelled out.
        assert!(by_id.starts_with("GOAT-PROXY-ALLOWLIST-v2\n"));
        assert_eq!(by_id.matches(RECORD_SEPARATOR).count(), 2);
        assert_eq!(by_id.matches(UNIT_SEPARATOR).count(), 4);
        assert!(by_id.ends_with(RECORD_SEPARATOR));
        assert!(!by_id.ends_with('\n'));
        assert!(by_id.contains("4\u{1f}crossref-api\u{1f}api.crossref.org\u{1e}"));

        // NEGATIVE CONTROL: a different host really does move the bytes, so the
        // equality above is not two constants agreeing.
        let moved = canonical_preimage_by_id(&[(4, "elsewhere.example"), (5, "api.openalex.org")])
            .expect("id path");
        assert_ne!(by_id, moved);
    }

    /// Mutations this detects: the sort removed, so a no-op reordering of the
    /// list invalidates every signed record; the sort written on the id's TEXT,
    /// which orders 10 before 2 the moment the registry passes nine rows.
    #[test]
    fn the_preimage_is_ordered_by_the_numeric_id_and_not_by_its_text() {
        let forwards =
            canonical_preimage_by_id(&[(2, "b.example"), (9, "i.example"), (1, "a.example")])
                .expect("preimage");
        let backwards =
            canonical_preimage_by_id(&[(9, "i.example"), (1, "a.example"), (2, "b.example")])
                .expect("preimage");
        assert_eq!(forwards, backwards, "the digest must not depend on order");

        let one = forwards.find("1\u{1f}").expect("id 1 is rendered");
        let two = forwards.find("2\u{1f}").expect("id 2 is rendered");
        let nine = forwards.find("9\u{1f}").expect("id 9 is rendered");
        assert!(
            one < two && two < nine,
            "records are not in ascending id order"
        );

        // A TEXT SORT WOULD DISAGREE, and this is the assertion that says so out
        // loud. The registry has only nine rows, so the case cannot be made
        // through the public entry points; `render` is driven directly because
        // the subject here is the ORDERING and not the table.
        let wide = render(vec![(10, "ten", "j.example"), (2, "two", "b.example")]).expect("render");
        let two_at = wide.find("2\u{1f}two").expect("id 2 is rendered");
        let ten_at = wide.find("10\u{1f}ten").expect("id 10 is rendered");
        assert!(
            two_at < ten_at,
            "a text sort leaked into the render: 10 was placed before 2"
        );
    }

    /// Mutations this detects: two entries of one list silently collapsing to a
    /// single record, so a list with a repeated destination digests as a
    /// shorter, different list.
    #[test]
    fn one_destination_named_twice_in_a_list_is_refused() {
        assert_eq!(
            canonical_digest_by_id(&[(1, "a.example"), (1, "b.example")]),
            Err(RegistryError::DuplicateDestination(1))
        );
        assert_eq!(
            canonical_digest_by_slug(&[
                ("documentation-example-com", "a.example"),
                ("documentation-example-com", "b.example")
            ]),
            Err(RegistryError::DuplicateDestination(1))
        );
        // POSITIVE CONTROL: two DIFFERENT destinations are fine.
        assert!(canonical_digest_by_id(&[(1, "a.example"), (2, "b.example")]).is_ok());
    }

    /// Why the unprefixed preimage is safe: no field can spell a separator.
    ///
    /// The construction has no length prefixes -- the separators carry that
    /// weight -- so this has to be an assertion rather than a hope.
    ///
    /// Mutations this detects: the slug charset relaxed to arbitrary text; the
    /// host check dropped from the render path, which is the only guard the
    /// DESKTOP's document passes through.
    #[test]
    fn no_canonical_field_can_spell_a_preimage_separator() {
        // Every registered slug is drawn from a charset that excludes both.
        for d in registry().expect("registry").rows() {
            assert!(check_slug(&d.slug).is_ok());
            assert!(!d.slug.contains(UNIT_SEPARATOR));
            assert!(!d.slug.contains(RECORD_SEPARATOR));
        }
        // A slug carrying one is refused by the validator outright.
        assert!(check_slug("a\u{1f}b").is_err());
        assert!(check_slug("a\u{1e}b").is_err());
        // POSITIVE CONTROL: an ordinary slug passes, so the refusals above are
        // about the separator and not about the shape of the check.
        assert!(check_slug("crossref-api").is_ok());

        // A HOST carrying one is refused at render time, which is the guard the
        // desktop's document meets.
        for bad in ["a\u{1f}b.example", "a\u{1e}b.example", "", "a b.example"] {
            assert!(
                canonical_digest_by_id(&[(1, bad)]).is_err(),
                "a host that can spell a record boundary was rendered: {bad:?}"
            );
        }
        assert!(canonical_digest_by_id(&[(1, "ab.example")]).is_ok());

        // THE COLLISION IS REAL, stated out loud rather than assumed away: with
        // no length prefixes, a TWO-record list and a ONE-record list whose host
        // carries the separators are the same bytes. What makes it unreachable
        // is the two checks above, not the hash. Stated as an equality on
        // purpose -- an `assert_ne!` here would be a claim the construction
        // cannot support, and it would pass only until somebody wrote the
        // colliding pair correctly.
        let two = render(vec![(1, "one", "a.example"), (2, "two", "b.example")]).expect("render");
        let colliding_host = "a.example\u{1e}2\u{1f}two\u{1f}b.example";
        let one = format!(
            "{CANONICAL_DIGEST_DOMAIN}\n1{UNIT_SEPARATOR}one{UNIT_SEPARATOR}{colliding_host}{RECORD_SEPARATOR}"
        );
        assert_eq!(
            two, one,
            "the preimage boundary moved; re-derive this argument"
        );
        // ...and that host is exactly what the render path refuses, which is
        // what keeps the collision out of reach.
        assert!(canonical_digest_by_id(&[(1, colliding_host)]).is_err());
    }

    /// Mutations this detects: the domain string edited on one side only, or
    /// dropped entirely, which would let this digest collide with the digest of
    /// anything else the project hashes.
    #[test]
    fn the_digest_is_domain_separated_and_thirty_two_bytes() {
        let d = canonical_digest_by_id(&[(1, "a.example")]).expect("digest");
        assert_eq!(d.len(), 32);
        assert_ne!(d, [0u8; 32]);
        assert_eq!(CANONICAL_DIGEST_DOMAIN, "GOAT-PROXY-ALLOWLIST-v2");

        // The domain is really in the bytes: hashing the same records under a
        // different domain gives a different digest.
        let undomained = {
            let full = canonical_preimage_by_id(&[(1, "a.example")]).expect("preimage");
            let stripped = full
                .strip_prefix(&format!("{CANONICAL_DIGEST_DOMAIN}\n"))
                .expect("the domain prefix is present");
            sha256(stripped)
        };
        assert_ne!(d, undomained);
    }
}
