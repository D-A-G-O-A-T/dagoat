import { describe, expect, it } from "vitest";
import { planAcceptAction } from "./opsAccept.js";

describe("planAcceptAction", () => {
  it("returns 'mint' when the manifestRoot has not been used on-chain", () => {
    expect(planAcceptAction({ alreadyUsed: false })).toBe("mint");
  });

  it("returns 'stamp-only' when the manifestRoot was already minted (usedManifest true / caught ManifestReplayed)", () => {
    expect(planAcceptAction({ alreadyUsed: true })).toBe("stamp-only");
  });
});
