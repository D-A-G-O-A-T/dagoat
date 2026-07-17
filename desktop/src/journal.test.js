import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/plugin-store", () => ({
  load: vi.fn(async () => {
    const data = new Map();
    return {
      get: async (key) => data.get(key),
      set: async (key, value) => {
        data.set(key, value);
      },
      delete: async (key) => {
        data.delete(key);
      },
      save: vi.fn(async () => {}),
    };
  }),
}));

const SAMPLE_UNITS = [
  {
    unit_id: "fah-wu-1",
    weight: 1,
    backend_ref: "alice",
    at: 1_700_000_000,
    evidence: "ev-1",
  },
  {
    unit_id: "fah-wu-2",
    weight: 1,
    backend_ref: "alice",
    at: 1_700_000_100,
    evidence: "ev-2",
  },
];

beforeEach(() => {
  vi.resetModules();
});

describe("journal pending units", () => {
  it("loadPending returns [] on a fresh store", async () => {
    const { loadPending } = await import("./journal.js");
    expect(await loadPending()).toEqual([]);
  });

  it("appendPending persists new units and loadPending reflects them", async () => {
    const { appendPending, loadPending } = await import("./journal.js");
    const next = await appendPending([SAMPLE_UNITS[0]], "folding_at_home");
    expect(next).toHaveLength(1);
    expect(next[0]).toMatchObject({
      unit_id: "fah-wu-1",
      weight: 1,
      backend_ref: "alice",
      at: 1_700_000_000,
      evidence: "ev-1",
      backendId: "folding_at_home",
      mintedInBatch: null,
    });
    expect(await loadPending()).toEqual(next);
  });

  it("appendPending does not duplicate an overlapping unit_id", async () => {
    const { appendPending, loadPending } = await import("./journal.js");
    await appendPending([SAMPLE_UNITS[0]], "folding_at_home");
    const next = await appendPending(
      [SAMPLE_UNITS[0], SAMPLE_UNITS[1]],
      "folding_at_home"
    );
    expect(next).toHaveLength(2);
    expect(next.map((e) => e.unit_id)).toEqual(["fah-wu-1", "fah-wu-2"]);
    expect(await loadPending()).toHaveLength(2);
  });

  it("markMinted stamps only matching unit_ids", async () => {
    const { appendPending, markMinted, loadPending } = await import("./journal.js");
    await appendPending(SAMPLE_UNITS, "folding_at_home");
    const stamped = await markMinted(["fah-wu-1"], "batch-7");
    expect(stamped.find((e) => e.unit_id === "fah-wu-1").mintedInBatch).toBe("batch-7");
    expect(stamped.find((e) => e.unit_id === "fah-wu-2").mintedInBatch).toBeNull();
    expect(await loadPending()).toEqual(stamped);
  });

  it("full round trip: appendPending → markMinted → loadPending", async () => {
    const { appendPending, markMinted, loadPending } = await import("./journal.js");
    await appendPending(SAMPLE_UNITS, "folding_at_home");
    await markMinted(["fah-wu-1", "fah-wu-2"], "batch-99");
    const final = await loadPending();
    expect(final).toHaveLength(2);
    expect(final.every((e) => e.mintedInBatch === "batch-99")).toBe(true);
    expect(final.every((e) => e.backendId === "folding_at_home")).toBe(true);
  });

  // Durability regression guard: a change that deletes `await store.save()` from either
  // function must fail these tests. loadPending() alone can't catch that regression — the
  // mock store's set() already updates its in-memory Map, so an in-memory read looks fine
  // even when the durable disk write (save()) was silently dropped.
  it("appendPending durably persists via store.save()", async () => {
    const { load } = await import("@tauri-apps/plugin-store");
    const { appendPending } = await import("./journal.js");
    await appendPending([SAMPLE_UNITS[0]], "folding_at_home");
    // vi.resetModules() (beforeEach) re-evaluates journal.js each test, so its memoized
    // storePromise is fresh, but the mocked `load` fn itself is not reset — use the most
    // recent call's store, not the first ever recorded across the whole file.
    const store = await load.mock.results.at(-1).value;
    expect(store.save).toHaveBeenCalled();
  });

  it("markMinted durably persists via store.save()", async () => {
    const { load } = await import("@tauri-apps/plugin-store");
    const { appendPending, markMinted } = await import("./journal.js");
    await appendPending(SAMPLE_UNITS, "folding_at_home");
    const store = await load.mock.results.at(-1).value;
    store.save.mockClear();
    await markMinted(["fah-wu-1"], "batch-1");
    expect(store.save).toHaveBeenCalled();
  });
});
