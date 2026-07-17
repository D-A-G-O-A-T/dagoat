import { beforeEach, describe, expect, it, vi } from "vitest";

// Store mock whose save() fails on exactly its 2nd call (the markMinted call right after a
// successful appendPending) then succeeds — models a transient disk error on the post-mint
// journal stamp, the scenario S9 fix b's markMinted rollback must survive without ever
// leaving units looking "minted" in this session. set() never throws, mirroring
// @tauri-apps/plugin-store's real behavior where set() updates the in-memory store
// immediately and only save() can fail (a durability write).
vi.mock("@tauri-apps/plugin-store", () => ({
  load: vi.fn(async () => {
    const data = new Map();
    let saveCallCount = 0;
    return {
      get: async (key) => data.get(key),
      set: async (key, value) => {
        data.set(key, value);
      },
      delete: async (key) => {
        data.delete(key);
      },
      save: vi.fn(async () => {
        saveCallCount += 1;
        if (saveCallCount === 2) {
          throw new Error("simulated disk write failure");
        }
      }),
    };
  }),
}));

const UNIT = {
  unit_id: "fah-wu-1",
  weight: 1,
  backend_ref: "alice",
  at: 1_700_000_000,
  evidence: "ev-1",
};

beforeEach(() => {
  vi.resetModules();
});

describe("journal markMinted — rollback on failed durable save (S9 fix b)", () => {
  it("a failed save leaves the unit pending, and a retry stamps it correctly", async () => {
    const { appendPending, markMinted, loadPending } = await import("./journal.js");

    await appendPending([UNIT], "folding_at_home"); // save call #1: succeeds

    // The on-chain mint already landed by the time markMinted runs (S9 fix b ordering) —
    // only the local journal write fails here.
    await expect(markMinted(["fah-wu-1"], "batch-1")).rejects.toThrow("simulated disk write failure");

    // Rolled back: still reads as pending, so the accept handler can safely retry — the
    // retry will land on WorkMinter.usedManifest -> stamp-only, never a second mint.
    const afterFailure = await loadPending();
    expect(afterFailure).toHaveLength(1);
    expect(afterFailure[0].mintedInBatch).toBeNull();

    // Retry: save call #3 succeeds.
    const stamped = await markMinted(["fah-wu-1"], "batch-1");
    expect(stamped.find((e) => e.unit_id === "fah-wu-1").mintedInBatch).toBe("batch-1");
    expect(await loadPending()).toEqual(stamped);
  });
});
