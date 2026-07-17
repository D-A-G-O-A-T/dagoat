import { describe, expect, it } from "vitest";
import { canonicalManifestJson, computeManifestRoot } from "./manifest.js";

const UNIT_A = { unit_id: "fah-wu-1", weight: 1, evidence: "ev-1" };
const UNIT_B = { unit_id: "fah-wu-2", weight: 1, evidence: "ev-2" };
const UNIT_C = { unit_id: "fah-wu-3", weight: 2, evidence: "ev-3" };

describe("canonicalManifestJson", () => {
  it("produces a fixed-key-order, no-whitespace JSON string sorted by unit_id", () => {
    expect(canonicalManifestJson("season0-fah", [UNIT_B, UNIT_A])).toBe(
      '{"jobId":"season0-fah","units":[{"unit_id":"fah-wu-1","weight":1,"evidence":"ev-1"},' +
        '{"unit_id":"fah-wu-2","weight":1,"evidence":"ev-2"}]}'
    );
  });

  it("ignores journal bookkeeping fields not part of the manifest", () => {
    const withExtra = {
      ...UNIT_A,
      backend_ref: "alice",
      at: 1_700_000_000,
      backendId: "folding_at_home",
      mintedInBatch: null,
    };
    expect(canonicalManifestJson("season0-fah", [withExtra])).toBe(canonicalManifestJson("season0-fah", [UNIT_A]));
  });

  it("serializes an empty unit list", () => {
    expect(canonicalManifestJson("season0-fah", [])).toBe('{"jobId":"season0-fah","units":[]}');
  });

  it("rejects a non-finite weight rather than silently poisoning the manifest", () => {
    expect(() => canonicalManifestJson("season0-fah", [{ unit_id: "x", weight: NaN, evidence: "e" }])).toThrow();
  });
});

describe("computeManifestRoot", () => {
  it("returns a bytes32-shaped hex hash", () => {
    expect(computeManifestRoot("season0-fah", [UNIT_A])).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("is order-insensitive: any permutation of the same unit set hashes identically", () => {
    const rootAB = computeManifestRoot("season0-fah", [UNIT_A, UNIT_B, UNIT_C]);
    const rootBA = computeManifestRoot("season0-fah", [UNIT_C, UNIT_A, UNIT_B]);
    const rootCBA = computeManifestRoot("season0-fah", [UNIT_C, UNIT_B, UNIT_A]);
    expect(rootAB).toBe(rootBA);
    expect(rootAB).toBe(rootCBA);
  });

  it("hashes identically regardless of extra journal fields on the unit objects", () => {
    const bare = computeManifestRoot("season0-fah", [UNIT_A, UNIT_B]);
    const withExtras = computeManifestRoot("season0-fah", [
      { ...UNIT_B, backendId: "folding_at_home", mintedInBatch: null },
      { ...UNIT_A, backend_ref: "alice", at: 1 },
    ]);
    expect(bare).toBe(withExtras);
  });

  it("a different unit set (added, removed, or changed unit) hashes differently", () => {
    const rootAB = computeManifestRoot("season0-fah", [UNIT_A, UNIT_B]);
    const rootA = computeManifestRoot("season0-fah", [UNIT_A]);
    const rootABC = computeManifestRoot("season0-fah", [UNIT_A, UNIT_B, UNIT_C]);
    const rootAB2 = computeManifestRoot("season0-fah", [UNIT_A, { ...UNIT_B, weight: 2 }]);
    expect(rootAB).not.toBe(rootA);
    expect(rootAB).not.toBe(rootABC);
    expect(rootAB).not.toBe(rootAB2);
  });

  it("a different jobId changes the root for the same units", () => {
    const root1 = computeManifestRoot("season0-fah", [UNIT_A]);
    const root2 = computeManifestRoot("some-other-job", [UNIT_A]);
    expect(root1).not.toBe(root2);
  });
});
