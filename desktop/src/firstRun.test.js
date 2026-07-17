import { describe, expect, it, vi } from "vitest";
import {
  canSubmit,
  cleanCustomName,
  fullUsername,
  needsFirstRun,
  saveUsername,
  shouldShowFirstRun,
} from "./components/FirstRunUsername.jsx";

describe("GOAT- username composition", () => {
  it("cleans the custom part to an FAH-safe token (letters/digits/underscore)", () => {
    expect(cleanCustomName("  Alice ")).toBe("Alice");
    expect(cleanCustomName("a l i c e!")).toBe("alice");
    expect(cleanCustomName("bob_2")).toBe("bob_2");
    expect(cleanCustomName("")).toBe("");
  });
  it("prefixes GOAT- for the full FAH username, or empty when the custom part is blank", () => {
    expect(fullUsername("Alice")).toBe("GOAT-Alice");
    expect(fullUsername("  bob_2 ")).toBe("GOAT-bob_2");
    expect(fullUsername("   ")).toBe("");
    expect(fullUsername("!!!")).toBe("");
  });
});

describe("needsFirstRun", () => {
  it("asks when no username is configured", () => {
    expect(needsFirstRun({ username: null, team: "1068318", passkey_is_default: true })).toBe(
      true,
    );
  });
  it("asks when the username is blank", () => {
    expect(needsFirstRun({ username: "   " })).toBe(true);
  });
  it("does not ask once a username exists", () => {
    expect(needsFirstRun({ username: "alice" })).toBe(false);
  });
  it("does not ask before identity has loaded (no flash)", () => {
    expect(needsFirstRun(null)).toBe(false);
  });
});

// Save is disabled while the input is empty (per binding semantics) and while a save is
// already in flight.
describe("canSubmit (Save button enablement)", () => {
  it("disables on an empty or whitespace-only name", () => {
    expect(canSubmit("")).toBe(false);
    expect(canSubmit("   ")).toBe(false);
    expect(canSubmit(null)).toBe(false);
    expect(canSubmit(undefined)).toBe(false);
  });
  it("enables once a non-blank name is entered", () => {
    expect(canSubmit("alice")).toBe(true);
    expect(canSubmit("  bob  ")).toBe(true);
  });
  it("disables while a save is already in flight", () => {
    expect(canSubmit("alice", true)).toBe(false);
  });
});

// Save must invoke backend_configure with the FAH registry id ("folding_at_home" — verified
// against build_registry(), not the "fah" guess), key "username", and the trimmed value.
describe("saveUsername (Save -> backend_configure)", () => {
  it("invokes backend_configure with the full GOAT- prefixed username", async () => {
    const invokeFn = vi.fn().mockResolvedValue(undefined);
    const result = await saveUsername("  alice  ", invokeFn);
    expect(invokeFn).toHaveBeenCalledWith("backend_configure", {
      id: "folding_at_home",
      key: "username",
      value: "GOAT-alice",
    });
    expect(result).toBe("GOAT-alice");
  });

  it("does nothing (no invoke call) on a blank value", async () => {
    const invokeFn = vi.fn();
    const result = await saveUsername("   ", invokeFn);
    expect(invokeFn).not.toHaveBeenCalled();
    expect(result).toBeNull();
  });
});

// "Later" dismisses until next launch: session-only, never persisted. shouldShowFirstRun takes
// the dismissed flag as a plain argument (App.jsx's React state) — nothing here reads storage,
// so a fresh session (dismissedThisSession = false) always re-derives from identity alone.
describe("shouldShowFirstRun (App.jsx gate: identity + session-only Later dismissal)", () => {
  it("shows when needed and not dismissed", () => {
    expect(shouldShowFirstRun({ username: "" }, false)).toBe(true);
  });

  it("Later hides it for the rest of the session without changing the underlying need", () => {
    expect(shouldShowFirstRun({ username: "" }, true)).toBe(false);
    // The fact itself (identity still has no username) is untouched by dismissal.
    expect(needsFirstRun({ username: "" })).toBe(true);
  });

  it("hides once a username is set, regardless of dismissal", () => {
    expect(shouldShowFirstRun({ username: "alice" }, false)).toBe(false);
    expect(shouldShowFirstRun({ username: "alice" }, true)).toBe(false);
  });
});
