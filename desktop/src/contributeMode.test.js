import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  isGoatPilotMode,
  loadContributeMode,
  MODE_PUBLIC_GOOD,
  MODE_WITH_GOAT,
  saveContributeMode,
} from "./contributeMode.js";

const KEY = "goat_contribute_mode";

/** Minimal localStorage polyfill for node vitest (no jsdom). */
function installMemoryStorage() {
  const map = new Map();
  globalThis.localStorage = {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => {
      map.set(k, String(v));
    },
    removeItem: (k) => {
      map.delete(k);
    },
  };
}

beforeEach(() => {
  installMemoryStorage();
});

afterEach(() => {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
});

describe("contributeMode", () => {
  it("defaults to public_good", () => {
    expect(loadContributeMode()).toBe(MODE_PUBLIC_GOOD);
    expect(isGoatPilotMode(MODE_PUBLIC_GOOD)).toBe(false);
  });

  it("persists with_goat opt-in", () => {
    saveContributeMode(MODE_WITH_GOAT);
    expect(loadContributeMode()).toBe(MODE_WITH_GOAT);
    expect(isGoatPilotMode(MODE_WITH_GOAT)).toBe(true);
  });

  it("rejects unknown values as public_good", () => {
    try {
      localStorage.setItem(KEY, "nonsense");
    } catch {
      /* ignore */
    }
    expect(loadContributeMode()).toBe(MODE_PUBLIC_GOOD);
  });
});
