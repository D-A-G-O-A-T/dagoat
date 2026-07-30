import { describe, expect, it, vi } from "vitest";
import {
  canSubmit, cleanCustomName, fullUsername, generatePasskey, isValidPasskeyInput,
  saveIdentity, GOAT_FAH_TEAM_ID, GOAT_USERNAME_PREFIX,
} from "./identity.js";

describe("username helpers (moved from FirstRunUsername)", () => {
  it("cleans to FAH-safe token and prefixes", () => {
    expect(cleanCustomName("  ch@rlie! ")).toBe("chrlie");
    expect(fullUsername("charlie")).toBe("GOAT-charlie");
    expect(fullUsername("   ")).toBe(""); // never a bare "GOAT-"
    expect(GOAT_USERNAME_PREFIX).toBe("GOAT-");
  });
});

describe("generatePasskey", () => {
  it("returns 32 lowercase hex chars that validate", () => {
    const pk = generatePasskey();
    expect(pk).toMatch(/^[0-9a-f]{32}$/);
    expect(isValidPasskeyInput(pk)).toBe(true);
  });
  it("is random (two calls differ)", () => {
    expect(generatePasskey()).not.toBe(generatePasskey());
  });
});

describe("isValidPasskeyInput", () => {
  it("accepts empty and 32-hex, rejects everything else", () => {
    expect(isValidPasskeyInput("")).toBe(true);
    expect(isValidPasskeyInput("a".repeat(32))).toBe(true);
    expect(isValidPasskeyInput("a".repeat(31))).toBe(false);
    expect(isValidPasskeyInput("z".repeat(32))).toBe(false);
  });
});

describe("canSubmit (moved from FirstRunUsername)", () => {
  it("requires a non-blank cleaned name", () => {
    expect(canSubmit("charlie")).toBe(true);
    expect(canSubmit("   ")).toBe(false);
    expect(canSubmit("!!!")).toBe(false); // cleans to empty
  });
  it("is blocked while saving", () => {
    expect(canSubmit("charlie", true)).toBe(false);
  });
});

describe("saveIdentity", () => {
  it("configures username, passkey, and always the GOAT team", async () => {
    const calls = [];
    const invokeFn = vi.fn(async (cmd, args) => calls.push([cmd, args]));
    await saveIdentity({ username: "GOAT-charlie", passkey: "ab".repeat(16) }, invokeFn);
    expect(calls).toEqual([
      ["backend_configure", { id: "folding_at_home", key: "username", value: "GOAT-charlie" }],
      ["backend_configure", { id: "folding_at_home", key: "passkey", value: "ab".repeat(16) }],
      ["backend_configure", { id: "folding_at_home", key: "team", value: GOAT_FAH_TEAM_ID }],
    ]);
  });
});
