import { describe, expect, it } from "vitest";
import {
  CORE_DEPLOYMENT_KEYS,
  DEFAULT_NETWORK_ID,
  getDeployment,
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

  it("84532 is not deployed while placeholders are null", () => {
    const d = getDeployment(84532);
    expect(d).toBeTruthy();
    expect(d.chainId).toBe(84532);
    expect(isDeployed(84532)).toBe(false);
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

  it("isDeployed rejects zero address / unknown chain", () => {
    expect(isDeployed(84532)).toBe(false);
    expect(isDeployed(99999)).toBe(false);
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
