// Pure-helper tests for the keeper-fee disclosure (no jsdom / no component
// mount — same convention as tabs/Miner.test.js and firstRun.test.js).
import { describe, expect, it, vi } from "vitest";
import { formatGoat } from "../chain/format.js";
import {
  formatKeeperFeeDisclosure,
  keeperFeeDisclosureLine,
  readKeeperFeeSafe,
} from "./EarningStatus.jsx";

const FEE = 50_000_000_000_000_000n; // 0.05 GOAT
const EXPECTED = `Auto-claim keeper fee: ${formatGoat(FEE)} GOAT per payout — deducted from your minted GOAT to reimburse the keeper's claim gas. Your first (baseline) claim is never charged.`;
const ADDR = "0x00000000000000000000000000000000000000e5";

describe("formatKeeperFeeDisclosure", () => {
  it("returns the exact pinned copy for a nonzero fee", () => {
    expect(formatKeeperFeeDisclosure(FEE)).toBe(EXPECTED);
  });

  it("returns empty string for zero/falsy fees", () => {
    expect(formatKeeperFeeDisclosure(0n)).toBe("");
    expect(formatKeeperFeeDisclosure(null)).toBe("");
    expect(formatKeeperFeeDisclosure(undefined)).toBe("");
  });
});

describe("keeperFeeDisclosureLine", () => {
  it("returns the disclosure when bound and enrolled with a nonzero fee", () => {
    expect(keeperFeeDisclosureLine({ bound: true, enrolled: true }, FEE)).toBe(EXPECTED);
  });

  it("returns empty string unless both bound and enrolled", () => {
    expect(keeperFeeDisclosureLine({ bound: true, enrolled: false }, FEE)).toBe("");
    expect(keeperFeeDisclosureLine({ bound: false, enrolled: true }, FEE)).toBe("");
    expect(keeperFeeDisclosureLine({}, FEE)).toBe("");
    expect(keeperFeeDisclosureLine(null, FEE)).toBe("");
    expect(keeperFeeDisclosureLine(undefined, FEE)).toBe("");
  });

  it("returns empty string when bound+enrolled but fee is zero/falsy", () => {
    expect(keeperFeeDisclosureLine({ bound: true, enrolled: true }, 0n)).toBe("");
    expect(keeperFeeDisclosureLine({ bound: true, enrolled: true }, null)).toBe("");
    expect(keeperFeeDisclosureLine({ bound: true, enrolled: true }, undefined)).toBe("");
  });
});

describe("readKeeperFeeSafe", () => {
  it("resolves to 0n on RPC rejection without throwing", async () => {
    const publicClient = { readContract: vi.fn().mockRejectedValue(new Error("RPC down")) };
    const fee = await readKeeperFeeSafe(publicClient, ADDR);
    expect(fee).toBe(0n);
    expect(publicClient.readContract).toHaveBeenCalledTimes(1);
  });

  it("resolves to 0n without calling the client when client is falsy", async () => {
    expect(await readKeeperFeeSafe(null, ADDR)).toBe(0n);
    expect(await readKeeperFeeSafe(undefined, ADDR)).toBe(0n);
  });

  it("resolves to 0n without calling readContract when address is falsy", async () => {
    const publicClient = { readContract: vi.fn().mockResolvedValue(FEE) };
    expect(await readKeeperFeeSafe(publicClient, null)).toBe(0n);
    expect(await readKeeperFeeSafe(publicClient, "")).toBe(0n);
    expect(publicClient.readContract).not.toHaveBeenCalled();
  });

  it("resolves the on-chain fee on success", async () => {
    const publicClient = { readContract: vi.fn().mockResolvedValue(FEE) };
    expect(await readKeeperFeeSafe(publicClient, ADDR)).toBe(FEE);
    expect(publicClient.readContract).toHaveBeenCalledWith(
      expect.objectContaining({ address: ADDR, functionName: "keeperFee", args: [] }),
    );
  });

  it("coerces non-bigint resolved values (number, numeric string) to bigint", async () => {
    const asNumber = { readContract: vi.fn().mockResolvedValue(1234) };
    expect(await readKeeperFeeSafe(asNumber, ADDR)).toBe(1234n);
    const asString = { readContract: vi.fn().mockResolvedValue("50000000000000000") };
    expect(await readKeeperFeeSafe(asString, ADDR)).toBe(FEE);
  });
});
