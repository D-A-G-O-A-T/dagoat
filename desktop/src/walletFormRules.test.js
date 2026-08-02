import { describe, expect, it } from "vitest";
import { canSubmitImport, showPasswordMismatch, MIN_PW } from "./walletFormRules.js";

// A complete, valid import form. Each test perturbs exactly ONE field, so a green
// assertion can only come from the rule under test (not from some other field
// happening to be invalid).
const ok = {
  name: "Alice",
  pw: "correct-horse",
  pw2: "correct-horse",
  key: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  passkey: "",
  busy: false,
};

describe("canSubmitImport", () => {
  it("accepts a complete form", () => {
    expect(canSubmitImport(ok)).toBe(true);
  });

  // The point of the whole change: a mistyped confirm must block the import,
  // because the password is never echoed back and seals the key irreversibly.
  it("rejects a mistyped confirmation", () => {
    expect(canSubmitImport({ ...ok, pw2: "correct-hoarse" })).toBe(false);
    expect(canSubmitImport({ ...ok, pw2: "correct-horse " })).toBe(false); // trailing space
    expect(canSubmitImport({ ...ok, pw2: "Correct-horse" })).toBe(false); // case
  });

  it("rejects an empty confirmation even when the password is valid", () => {
    expect(canSubmitImport({ ...ok, pw2: "" })).toBe(false);
    expect(canSubmitImport({ ...ok, pw2: undefined })).toBe(false);
  });

  it("does not treat two matching-but-too-short passwords as valid", () => {
    const short = "a".repeat(MIN_PW - 1);
    expect(canSubmitImport({ ...ok, pw: short, pw2: short })).toBe(false);
  });

  it("accepts a password exactly at the minimum length", () => {
    const exact = "a".repeat(MIN_PW);
    expect(canSubmitImport({ ...ok, pw: exact, pw2: exact })).toBe(true);
  });

  it("still enforces the pre-existing fields", () => {
    expect(canSubmitImport({ ...ok, name: "   " })).toBe(false);
    expect(canSubmitImport({ ...ok, key: "   " })).toBe(false);
    expect(canSubmitImport({ ...ok, passkey: "not-hex" })).toBe(false);
    expect(canSubmitImport({ ...ok, busy: true })).toBe(false);
  });

  it("accepts a valid 32-hex passkey", () => {
    expect(canSubmitImport({ ...ok, passkey: "0123456789abcdef0123456789ABCDEF" })).toBe(true);
  });

  it("returns false (never throws) on an empty or missing form", () => {
    expect(canSubmitImport()).toBe(false);
    expect(canSubmitImport({})).toBe(false);
  });
});

describe("showPasswordMismatch", () => {
  it("stays silent until the user has typed into the confirm box", () => {
    expect(showPasswordMismatch("secret123", "")).toBe(false);
    expect(showPasswordMismatch("", "")).toBe(false);
    expect(showPasswordMismatch("secret123", undefined)).toBe(false);
  });

  it("warns as soon as the confirm box disagrees", () => {
    expect(showPasswordMismatch("secret123", "s")).toBe(true);
    expect(showPasswordMismatch("secret123", "secret124")).toBe(true);
  });

  it("clears once the two agree", () => {
    expect(showPasswordMismatch("secret123", "secret123")).toBe(false);
  });
});
