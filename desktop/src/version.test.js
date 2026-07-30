import { describe, expect, it } from "vitest";
import pkg from "../package.json";
import { APP_VERSION, APP_VERSION_LABEL } from "./version.js";

describe("version.js (single-source drift guard)", () => {
  it("app version matches package.json (no drift)", () => {
    expect(APP_VERSION).toBe(pkg.version);
  });

  it("label is testnet-tagged and clean", () => {
    expect(APP_VERSION_LABEL).toMatch(/testnet/);
    for (const re of [/\bwage\b/i, /\bincome\b/i, /\bprofit\b/i, /\bsalary\b/i, /\bearning\b/i]) {
      expect(APP_VERSION_LABEL).not.toMatch(re);
    }
  });
});
