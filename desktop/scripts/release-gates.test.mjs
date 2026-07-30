import { describe, expect, it } from "vitest";
import {
  check84532Core,
  checkProductionEnv,
  checkVersionParity,
  isDeployedAddress,
  parseAppVersionJs,
  parseCargoPackageVersion,
  resolveEffectiveBundleTargets,
} from "./release-gates.mjs";

describe("release-gates (Stream D0)", () => {
  it("isDeployedAddress rejects null/zero", () => {
    expect(isDeployedAddress(null)).toBe(false);
    expect(isDeployedAddress("0x0000000000000000000000000000000000000000")).toBe(false);
    expect(isDeployedAddress("0x8f86403A4DE0BB5791fa46B8e795C547942fE4Cf")).toBe(true);
  });

  it("check84532Core fails closed on placeholder 84532.json shape", () => {
    const r = check84532Core({
      chainId: 84532,
      goatCoin: null,
      enrollmentRegistry: null,
      holdbackEscrow: null,
      workMinter: null,
      buyDesk: null,
      mockUSDT: null,
    });
    expect(r.ok).toBe(false);
    expect(r.missing).toEqual(
      expect.arrayContaining([
        "goatCoin",
        "enrollmentRegistry",
        "holdbackEscrow",
        "workMinter",
        "buyDesk",
        "mockUSDT",
      ]),
    );
  });

  it("check84532Core passes when all core keys are addresses", () => {
    const a = "0x1111111111111111111111111111111111111111";
    const r = check84532Core({
      goatCoin: a,
      enrollmentRegistry: a,
      holdbackEscrow: a,
      workMinter: a,
      buyDesk: a,
      mockUSDT: a,
    });
    expect(r.ok).toBe(true);
    expect(r.missing).toEqual([]);
  });

  it("checkVersionParity detects drift", () => {
    const ok = checkVersionParity({
      packageVersion: "0.1.0",
      tauriVersion: "0.1.0",
      cargoVersion: "0.1.0",
      appVersionJs: "0.1.0",
    });
    expect(ok.ok).toBe(true);
    const bad = checkVersionParity({
      packageVersion: "0.1.0",
      tauriVersion: "0.2.0",
      cargoVersion: "0.1.0",
      appVersionJs: "0.1.0",
    });
    expect(bad.ok).toBe(false);
    expect(bad.mismatches.join(" ")).toMatch(/tauri/);
  });

  it("parses Cargo.toml and version.js", () => {
    expect(parseCargoPackageVersion('[package]\nname = "x"\nversion = "1.2.3"\n')).toBe("1.2.3");
    expect(parseAppVersionJs('export const APP_VERSION = "9.9.9";\n')).toBe("9.9.9");
  });

  it("checkProductionEnv flags loopback relayer in strict mode", () => {
    const soft = checkProductionEnv({ VITE_ATTESTOR_RELAYER_URL: "http://127.0.0.1:8787" });
    expect(soft.warnings.length).toBeGreaterThan(0);
    const hard = checkProductionEnv(
      { VITE_ATTESTOR_RELAYER_URL: "http://127.0.0.1:8787" },
      { strict: true },
    );
    expect(hard.errors.length).toBeGreaterThan(0);
  });

  it("resolveEffectiveBundleTargets falls back to nsis-only without WiX", () => {
    const noWix = resolveEffectiveBundleTargets(["nsis", "msi"], { wixAvailable: false });
    expect(noWix.ok).toBe(true);
    expect(noWix.effective).toEqual(["nsis"]);
    expect(noWix.warnings.join(" ")).toMatch(/WiX/i);

    const withWix = resolveEffectiveBundleTargets(["nsis", "msi"], { wixAvailable: true });
    expect(withWix.effective).toEqual(["nsis", "msi"]);
    expect(withWix.warnings).toEqual([]);
  });

  it("resolveEffectiveBundleTargets fails if nsis missing", () => {
    const r = resolveEffectiveBundleTargets(["msi"], { wixAvailable: true });
    expect(r.ok).toBe(false);
  });
});
