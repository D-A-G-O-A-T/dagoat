import { describe, expect, it } from "vitest";
import { DEFAULT_FLAGS, routeBoot } from "./onboardingState.js";

describe("routeBoot (spec §5 boot routing + §11 store-failure rule)", () => {
  it("fresh install → disclaimer", () => {
    expect(routeBoot({ flags: DEFAULT_FLAGS, walletCount: 0 }).screen).toBe("disclaimer");
  });
  it("accepted but not completed, no wallet → wallet gate", () => {
    const flags = { disclaimerAccepted: true, completed: false, choice: null };
    expect(routeBoot({ flags, walletCount: 0 }).screen).toBe("wallet_gate");
  });
  it("completed → shell (both choices)", () => {
    for (const choice of ["wallet", "public_good_only"]) {
      const flags = { disclaimerAccepted: true, completed: true, choice };
      const r = routeBoot({ flags, walletCount: choice === "wallet" ? 1 : 0 });
      expect(r.screen).toBe("shell");
      expect(r.selfHeal).toBeNull();
    }
  });
  it("wallet exists but flags incomplete (crash mid-wizard) → shell + self-heal", () => {
    const r = routeBoot({ flags: { disclaimerAccepted: true, completed: false, choice: null }, walletCount: 1 });
    expect(r.screen).toBe("shell");
    expect(r.selfHeal).toEqual({ disclaimerAccepted: true, completed: true, choice: "wallet" });
  });
  it("store failure (flags null) + wallet exists → shell, disclaimer NOT re-shown", () => {
    const r = routeBoot({ flags: null, walletCount: 2 });
    expect(r.screen).toBe("shell");
    expect(r.selfHeal).toEqual({ disclaimerAccepted: true, completed: true, choice: "wallet" });
  });
  it("store failure + no wallet → disclaimer (true first run)", () => {
    expect(routeBoot({ flags: null, walletCount: 0 }).screen).toBe("disclaimer");
  });
});
