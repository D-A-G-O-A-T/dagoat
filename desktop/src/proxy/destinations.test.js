import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { DESTINATIONS, REGISTRY_SCHEMA_ID, idForSlug, slugForId } from "./destinations.js";

// THE ONE DEFINITION, read as bytes off disk.
//
// `destinations.js` is the only mirror of the canonical slug <-> id table in the
// system: the sidecar embeds this file, and the desktop's Rust half imports the
// parsed table from that crate rather than declaring a copy. This test is what makes
// the mirror safe -- it compares the JavaScript rows against these exact bytes, so a
// drift is a red test and never a silent divergence.
//
// A runtime read rather than an `import` of the JSON, deliberately: the file lives
// outside this Vite root, and bundling it into the shipped app would make the sidecar
// tree a build input for the frontend. The test runs in Node and can simply read it.
const CANONICAL = JSON.parse(
  readFileSync(new URL("../../../tools/goat-proxy-worker/destinations.v1.json", import.meta.url), "utf8"),
);

describe("canonical destination registry", () => {
  /// Mutations this detects: ANY edit to the canonical table that this mirror did not
  /// make too -- a renumbered slug, a renamed slug, an appended row, a deleted row, or
  /// two rows swapped. This is the drift guard the whole mirror arrangement rests on.
  it("the javascript mirror is the canonical table, row for row", () => {
    expect(CANONICAL.schema_id).toBe(REGISTRY_SCHEMA_ID);
    const canonicalRows = CANONICAL.destinations.map((d) => ({ id: d.id, slug: d.slug }));
    expect(DESTINATIONS).toEqual(canonicalRows);
    // POSITIVE CONTROL: the comparison is not two empty arrays agreeing.
    expect(canonicalRows.length).toBeGreaterThan(0);
    expect(canonicalRows.some((d) => d.slug === "crossref-api")).toBe(true);
  });

  /// Mutations this detects: a duplicate id or slug added to either side; a gap left by
  /// a deleted row; an id zero, which would let an uninitialised integer name a
  /// destination; the contiguity check written as a `>=` so ascending-with-holes passes.
  it("the table is contiguous from one, with no gaps and no duplicates", () => {
    const ids = CANONICAL.destinations.map((d) => d.id);
    const slugs = CANONICAL.destinations.map((d) => d.slug);
    expect(ids).toEqual(ids.map((_, i) => i + 1));
    expect(new Set(ids).size).toBe(ids.length);
    expect(new Set(slugs).size).toBe(slugs.length);
    expect(ids).not.toContain(0);
    // The charset is what keeps a slug from spelling a preimage separator.
    for (const slug of slugs) expect(slug).toMatch(/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/);
  });

  /// Mutations this detects: either lookup built from the other's map, so the pair
  /// agrees with itself and not with the table; a lookup that falls back to the row's
  /// index instead of its declared id.
  it("every row round-trips through both lookups in both directions", () => {
    for (const d of CANONICAL.destinations) {
      expect(idForSlug(d.slug)).toBe(d.id);
      expect(slugForId(d.id)).toBe(d.slug);
    }
    // ...and the composition is the identity, which is what one-to-one means.
    for (const d of CANONICAL.destinations) {
      expect(slugForId(idForSlug(d.slug))).toBe(d.slug);
      expect(idForSlug(slugForId(d.id))).toBe(d.id);
    }
  });

  /// Mutations this detects: `?? 0` or `?? ""` on either lookup, which would name
  /// destination zero or hash an empty slug rather than refusing; either lookup relaxed
  /// to a case-insensitive or trimmed match.
  it("an unregistered slug or id is refused, never defaulted", () => {
    expect(() => idForSlug("no-such-destination")).toThrow(/not in the canonical registry/);
    expect(() => idForSlug("CROSSREF-API")).toThrow();
    expect(() => idForSlug(" crossref-api")).toThrow();
    expect(() => idForSlug(undefined)).toThrow();
    expect(() => slugForId(0)).toThrow(/not in the canonical registry/);
    expect(() => slugForId(DESTINATIONS.length + 1)).toThrow();
    // A string that looks like a registered id is not one: the table is keyed on the
    // number, and a loose `==` lookup would let "4" name destination four.
    expect(() => slugForId("4")).toThrow();
    // POSITIVE CONTROL: the registered spellings do resolve, so the refusals above are
    // about the identifier and not about the call.
    expect(idForSlug("crossref-api")).toBe(4);
    expect(slugForId(4)).toBe("crossref-api");
  });
});
