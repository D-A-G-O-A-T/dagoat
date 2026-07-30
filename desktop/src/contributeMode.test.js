import { beforeEach, describe, expect, it, vi } from "vitest";

// Vitest here runs in the DEFAULT NODE environment (no test.environment in
// vite.config.js, no jsdom dep) — `localStorage` is undefined. The current
// contributeMode.test.js already carries this polyfill; keep it (plus clear()).
function installMemoryStorage() {
  const mem = new Map();
  globalThis.localStorage = {
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => mem.set(k, String(v)),
    removeItem: (k) => mem.delete(k),
    clear: () => mem.clear(),
  };
}
installMemoryStorage();

vi.mock("./onboarding/appState.js", () => {
  const mem = new Map();
  return {
    readAppState: vi.fn(async (k, fb = null) => (mem.has(k) ? mem.get(k) : fb)),
    writeAppState: vi.fn(async (k, v) => (mem.set(k, v), true)),
    __mem: mem,
  };
});

import {
  MODE_PUBLIC_GOOD, MODE_WITH_GOAT, resolveEffectiveMode,
  loadContributeModeV2, saveContributeModeV2, CONTRIBUTE_MODE_KEY,
} from "./contributeMode.js";
import { __mem, writeAppState } from "./onboarding/appState.js";

beforeEach(() => { __mem.clear(); localStorage.clear(); });

describe("resolveEffectiveMode (tri-state, spec §10)", () => {
  it("explicit value always wins", () => {
    expect(resolveEffectiveMode(MODE_PUBLIC_GOOD, "wallet")).toBe(MODE_PUBLIC_GOOD);
    expect(resolveEffectiveMode(MODE_WITH_GOAT, "public_good_only")).toBe(MODE_WITH_GOAT);
  });
  it("never-set: wallet onboarding → with_goat, otherwise public_good", () => {
    expect(resolveEffectiveMode(null, "wallet")).toBe(MODE_WITH_GOAT);
    expect(resolveEffectiveMode(null, "public_good_only")).toBe(MODE_PUBLIC_GOOD);
    expect(resolveEffectiveMode(null, null)).toBe(MODE_PUBLIC_GOOD);
  });
  it("garbage explicit values are treated as never-set", () => {
    expect(resolveEffectiveMode("banana", "wallet")).toBe(MODE_WITH_GOAT);
  });
});

describe("loadContributeModeV2 migration", () => {
  it("migrates old localStorage value to an explicit store choice and removes it", async () => {
    localStorage.setItem("goat_contribute_mode", MODE_WITH_GOAT);
    const { explicit, effective } = await loadContributeModeV2("public_good_only");
    expect(explicit).toBe(MODE_WITH_GOAT);
    expect(effective).toBe(MODE_WITH_GOAT);
    expect(localStorage.getItem("goat_contribute_mode")).toBeNull();
    expect(__mem.get(CONTRIBUTE_MODE_KEY)).toBe(MODE_WITH_GOAT);
  });
  it("persists and reloads an explicit save", async () => {
    await saveContributeModeV2(MODE_PUBLIC_GOOD);
    const { explicit } = await loadContributeModeV2("wallet");
    expect(explicit).toBe(MODE_PUBLIC_GOOD);
  });
  it("keeps the legacy localStorage key when the store write fails (no data loss)", async () => {
    localStorage.setItem("goat_contribute_mode", MODE_WITH_GOAT);
    writeAppState.mockResolvedValueOnce(false);
    const { explicit, effective } = await loadContributeModeV2("public_good_only");
    expect(explicit).toBe(MODE_WITH_GOAT);
    expect(effective).toBe(MODE_WITH_GOAT);
    expect(localStorage.getItem("goat_contribute_mode")).not.toBeNull();
  });
});
