// The canonical destination registry, MIRRORED.
//
// The one definition lives in the sidecar crate, as `destinations.v1.json`. The
// sidecar embeds it; the desktop's Rust half IMPORTS the parsed table from that
// crate rather than declaring a copy. JavaScript cannot link a Rust crate, so
// this file is the one mirror in the system -- and `destinations.test.js` reads
// the canonical JSON off disk and refuses to pass unless these rows are exactly
// those rows, in that order. A drift here is a red test, never a silent
// divergence.
//
// The table did not go in this tree, which would have let this file import it
// directly, because the sidecar's production code would then have to reach up
// into `desktop/` to build -- inverting the one dependency direction its
// manifest is explicit about.
//
// Design authority: the "The No-Ponzi Invariant — GoatCoin's load-bearing economic
// rule" spec, §1 and §8; and the founder ruling that a canonical, static,
// one-to-one slug <-> id mapping is shared by both components.

export const REGISTRY_SCHEMA_ID = "GOAT_PROXY_DESTINATION_REGISTRY_V1";

/**
 * Ids are PERMANENT and are never reused. The table grows only by appending the
 * next integer, and the numbering is contiguous from one -- a gap left by a
 * deleted row is a refusal here as it is in Rust, so no future destination is
 * dropped into a hole a previous one left.
 *
 * Rows whose slug begins `documentation-` name IANA-reserved documentation
 * domains (RFC 2606 / RFC 6761). They exist so the loader, the digest and the
 * test fixtures have registered ids to use; they are not a statement that any
 * destination has been cleared for traffic.
 */
export const DESTINATIONS = [
  { id: 1, slug: "documentation-example-com" },
  { id: 2, slug: "documentation-example-org" },
  { id: 3, slug: "documentation-research-example-net" },
  { id: 4, slug: "crossref-api" },
  { id: 5, slug: "openalex-api" },
  { id: 6, slug: "datacite-api" },
  { id: 7, slug: "europepmc-api" },
  { id: 8, slug: "rcsb-files" },
  { id: 9, slug: "documentation-other-example" },
];

// Built at module load, and a table that is not one-to-one throws here rather
// than at the first lookup that happens to notice. A broken mirror stops the
// screen that would have asked somebody to sign against it.
const ID_OF = new Map();
const SLUG_OF = new Map();
for (const [i, d] of DESTINATIONS.entries()) {
  if (d.id !== i + 1) {
    throw new Error(`destination registry row ${i} carries id ${d.id} where contiguous numbering requires ${i + 1}`);
  }
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(d.slug) || d.slug.length > 64) {
    throw new Error(`destination slug ${JSON.stringify(d.slug)} is outside the permitted charset`);
  }
  if (ID_OF.has(d.slug)) throw new Error(`destination slug ${JSON.stringify(d.slug)} is mapped to two ids`);
  ID_OF.set(d.slug, d.id);
  SLUG_OF.set(d.id, d.slug);
}

/** The id this slug names. An unregistered slug is a REFUSAL, never a zero. */
export function idForSlug(slug) {
  const id = ID_OF.get(slug);
  if (id === undefined) {
    throw new Error(`destination slug ${JSON.stringify(slug)} is not in the canonical registry`);
  }
  return id;
}

/** The slug this id names. An unregistered id is a REFUSAL, never an empty string. */
export function slugForId(id) {
  const slug = SLUG_OF.get(id);
  if (slug === undefined) {
    throw new Error(`destination id ${id} is not in the canonical registry`);
  }
  return slug;
}
