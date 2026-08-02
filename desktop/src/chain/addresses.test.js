import { describe, expect, it } from "vitest";
import {
  CORE_DEPLOYMENT_KEYS,
  DEFAULT_NETWORK_ID,
  getDeployment,
  hasCoreAddresses,
  isDeployed,
  resolveDefaultNetworkId,
  resolveHideAnvil,
  visibleNetworks,
} from "./addresses.js";

describe("addresses (Stream B merge)", () => {
  it("lab default is anvil when VITE_DEFAULT_NETWORK_ID unset (module load)", () => {
    // Vitest runs without pilot env → 31337.
    expect(DEFAULT_NETWORK_ID).toBe(31337);
  });

  it("merges anvil factory + epoch into getDeployment(31337)", () => {
    const d = getDeployment(31337);
    expect(d).toBeTruthy();
    expect(d.buyDeskFactory).toMatch(/^0x/i);
    expect(d.workerBinding || d.epochSettlement).toBeTruthy();
    expect(isDeployed(31337)).toBe(true);
  });

  it("84532 carries the pilot deployment and reads as deployed", () => {
    const d = getDeployment(84532);
    expect(d).toBeTruthy();
    expect(d.chainId).toBe(84532);
    // This asserted `false` while the file held null placeholders. The pilot
    // deployment filled them in and the assertion was not updated with it, so
    // the `desktop` job was red for two pushes. The DATA is authoritative here:
    // the addresses are real, so the chain is deployed.
    expect(isDeployed(84532)).toBe(true);
    for (const k of CORE_DEPLOYMENT_KEYS) {
      expect(d[k]).toMatch(/^0x[0-9a-f]{40}$/i);
    }
  });

  it("isDeployed requires all core keys", () => {
    expect(CORE_DEPLOYMENT_KEYS).toEqual(
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

  it("isDeployed rejects an unknown chain", () => {
    expect(isDeployed(99999)).toBe(false);
  });

  // Every chain in the module-level map is really deployed now, so `isDeployed`
  // can no longer reach its own rejection branch and these four conditions
  // would sit uncovered behind a green suite. `hasCoreAddresses` takes the
  // deployment directly so each one is exercised against a real shape.
  it("hasCoreAddresses rejects null, empty, bare 0x and the zero address", () => {
    const good = getDeployment(84532);
    // CONTROL: the unmutated fixture must pass, or every case below passes for
    // the wrong reason.
    expect(hasCoreAddresses(good)).toBe(true);

    for (const bad of [null, undefined, "", "0x", "0x" + "0".repeat(40), 12345]) {
      for (const k of CORE_DEPLOYMENT_KEYS) {
        expect(hasCoreAddresses({ ...good, [k]: bad })).toBe(false);
      }
    }
    expect(hasCoreAddresses(null)).toBe(false);
    // A missing key, as distinct from a null one.
    for (const k of CORE_DEPLOYMENT_KEYS) {
      const missing = { ...good };
      delete missing[k];
      expect(hasCoreAddresses(missing)).toBe(false);
    }
  });
});

describe("Stream C T2 default network + hide anvil", () => {
  it("resolveDefaultNetworkId: unset → 31337, pilot → 84532", () => {
    expect(resolveDefaultNetworkId({})).toBe(31337);
    expect(resolveDefaultNetworkId({ VITE_DEFAULT_NETWORK_ID: "84532" })).toBe(84532);
    expect(resolveDefaultNetworkId({ VITE_DEFAULT_NETWORK_ID: "31337" })).toBe(31337);
    expect(resolveDefaultNetworkId({ VITE_DEFAULT_NETWORK_ID: "999" })).toBe(31337);
  });

  it("resolveHideAnvil: VITE_PILOT or VITE_HIDE_ANVIL", () => {
    expect(resolveHideAnvil({})).toBe(false);
    expect(resolveHideAnvil({ VITE_PILOT: "1" })).toBe(true);
    expect(resolveHideAnvil({ VITE_PILOT: "true" })).toBe(true);
    expect(resolveHideAnvil({ VITE_HIDE_ANVIL: "1" })).toBe(true);
  });

  it("visibleNetworks drops anvil in pilot env", () => {
    const lab = visibleNetworks({});
    expect(lab.map((n) => n.id)).toEqual([31337, 84532]);
    const pilot = visibleNetworks({ VITE_PILOT: "1" });
    expect(pilot.map((n) => n.id)).toEqual([84532]);
    expect(pilot.every((n) => n.id !== 31337)).toBe(true);
  });
});
