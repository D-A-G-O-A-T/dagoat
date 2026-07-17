import { beforeEach, describe, expect, it, vi } from "vitest";

// Store mock whose save() throws on its first two calls then succeeds — models a transient
// disk error that resolves itself, the scenario Fix 1(b)/(c) must survive without losing
// units. set() never throws, mirroring @tauri-apps/plugin-store's real behavior where set()
// updates the in-memory store immediately and only save() can fail (a durability write).
vi.mock("@tauri-apps/plugin-store", () => ({
  load: vi.fn(async () => {
    const data = new Map();
    let failuresRemaining = 2;
    return {
      get: async (key) => data.get(key),
      set: async (key, value) => {
        data.set(key, value);
      },
      delete: async (key) => {
        data.delete(key);
      },
      save: vi.fn(async () => {
        if (failuresRemaining > 0) {
          failuresRemaining -= 1;
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

describe("pendingRetry — never-drop retry on journal save failure", () => {
  it("attemptSavePending never throws: reports failure instead", async () => {
    const { attemptSavePending } = await import("./pendingRetry.js");
    const result = await attemptSavePending([UNIT], "folding_at_home");
    expect(result.saved).toBe(false);
    expect(result.error).toBeInstanceOf(Error);
  });

  it("retrying the same units across a save() that fails twice then succeeds lands in the journal exactly once, no loss, no duplicates", async () => {
    const { attemptSavePending } = await import("./pendingRetry.js");
    const { loadPending } = await import("./journal.js");

    // Attempt 1: fails (1st simulated failure). Units must be held, not dropped.
    let result = await attemptSavePending([UNIT], "folding_at_home");
    expect(result.saved).toBe(false);

    // Simulated 10s auto-retry #1: fails again (2nd simulated failure).
    result = await attemptSavePending([UNIT], "folding_at_home");
    expect(result.saved).toBe(false);

    // Simulated 10s auto-retry #2: succeeds.
    result = await attemptSavePending([UNIT], "folding_at_home");
    expect(result.saved).toBe(true);
    expect(result.journal).toHaveLength(1);
    expect(result.journal[0].unit_id).toBe("fah-wu-1");

    // Durable journal has the unit exactly once — dedup by unit_id held through every retry.
    const final = await loadPending();
    expect(final).toHaveLength(1);
    expect(final[0].unit_id).toBe("fah-wu-1");
  });

  it("retryUnsaved replays a buffered failure and clears it from the buffer on success", async () => {
    const { attemptSavePending, mergeUnsaved, retryUnsaved } = await import(
      "./pendingRetry.js"
    );
    const { loadPending } = await import("./journal.js");

    // First check-for-work call fails to save (1st simulated failure) -> buffered.
    const first = await attemptSavePending([UNIT], "folding_at_home");
    expect(first.saved).toBe(false);
    let buffer = mergeUnsaved([], [UNIT], "folding_at_home");
    expect(buffer).toHaveLength(1);

    // Auto-retry tick #1: still fails (2nd simulated failure) -> units remain in the buffer.
    let outcome = await retryUnsaved(buffer);
    expect(outcome.stillUnsaved).toHaveLength(1);
    expect(outcome.latestJournal).toBeNull();
    buffer = outcome.stillUnsaved;

    // Auto-retry tick #2: succeeds -> buffer drains, journal has the unit exactly once.
    outcome = await retryUnsaved(buffer);
    expect(outcome.stillUnsaved).toHaveLength(0);
    expect(outcome.latestJournal).toHaveLength(1);

    const final = await loadPending();
    expect(final).toHaveLength(1);
    expect(final[0].unit_id).toBe("fah-wu-1");
  });
});

// mergeUnsaved is a pure function; test it directly without the store mock plumbing above.
describe("mergeUnsaved (pure)", () => {
  it("dedupes by unit_id and preserves earlier buffered entries", async () => {
    const { mergeUnsaved } = await import("./pendingRetry.js");
    const unitA = { ...UNIT };
    const unitB = { ...UNIT, unit_id: "fah-wu-2" };

    let buffer = mergeUnsaved([], [unitA], "folding_at_home");
    expect(buffer).toHaveLength(1);
    expect(buffer[0].backendId).toBe("folding_at_home");

    // Re-merging the same unit_id must not duplicate it.
    buffer = mergeUnsaved(buffer, [unitA, unitB], "folding_at_home");
    expect(buffer.map((u) => u.unit_id)).toEqual(["fah-wu-1", "fah-wu-2"]);
  });
});
