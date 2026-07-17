import { describe, expect, it } from "vitest";
import {
  canSeeOpsTab,
  isFounderWallet,
  isTestnetWithMockUsdt,
  reduceEnrolledLogs,
} from "./opsAccess.js";

const ADDR_A = "0x1111111111111111111111111111111111111111";
const ADDR_B = "0x2222222222222222222222222222222222222222";
const ADDR_A_UPPER = "0x1111111111111111111111111111111111111111".toUpperCase();

describe("isTestnetWithMockUsdt", () => {
  it("returns true for local anvil (31337)", () => {
    expect(isTestnetWithMockUsdt(31337)).toBe(true);
    expect(isTestnetWithMockUsdt("31337")).toBe(true);
  });

  it("returns true for Base Sepolia (84532)", () => {
    expect(isTestnetWithMockUsdt(84532)).toBe(true);
    expect(isTestnetWithMockUsdt("84532")).toBe(true);
  });

  it("returns false for mainnet and unknown ids", () => {
    expect(isTestnetWithMockUsdt(1)).toBe(false);
    expect(isTestnetWithMockUsdt(8453)).toBe(false);
    expect(isTestnetWithMockUsdt(0)).toBe(false);
    expect(isTestnetWithMockUsdt(null)).toBe(false);
    expect(isTestnetWithMockUsdt(undefined)).toBe(false);
  });
});

describe("isFounderWallet", () => {
  it("matches addresses case-insensitively", () => {
    expect(isFounderWallet(ADDR_A, ADDR_A)).toBe(true);
    expect(isFounderWallet(ADDR_A, ADDR_A_UPPER)).toBe(true);
    expect(isFounderWallet(ADDR_A_UPPER, ADDR_A)).toBe(true);
  });

  it("returns false when addresses differ or either is missing", () => {
    expect(isFounderWallet(ADDR_A, ADDR_B)).toBe(false);
    expect(isFounderWallet(null, ADDR_A)).toBe(false);
    expect(isFounderWallet(ADDR_A, null)).toBe(false);
    expect(isFounderWallet("", ADDR_A)).toBe(false);
    expect(isFounderWallet(ADDR_A, "")).toBe(false);
    expect(isFounderWallet(undefined, undefined)).toBe(false);
  });
});

describe("canSeeOpsTab", () => {
  it("is founder-only — enrolled workers do not see Ops", () => {
    expect(canSeeOpsTab({ enrolled: true, isFounder: false })).toBe(false);
    expect(canSeeOpsTab({ enrolled: false, isFounder: false })).toBe(false);
    expect(canSeeOpsTab({ enrolled: null, isFounder: false })).toBe(false);
    expect(canSeeOpsTab({ enrolled: undefined, isFounder: undefined })).toBe(false);
  });

  it("is visible only for the registry safe (founder)", () => {
    expect(canSeeOpsTab({ enrolled: false, isFounder: true })).toBe(true);
    expect(canSeeOpsTab({ enrolled: true, isFounder: true })).toBe(true);
  });
});

describe("reduceEnrolledLogs", () => {
  it("returns currently enrolled addresses after last-write-wins on chronological logs", () => {
    const logs = [
      { who: ADDR_A, status: true },
      { who: ADDR_B, status: true },
      { who: ADDR_A, status: false },
      { who: ADDR_A, status: true },
    ];
    expect(reduceEnrolledLogs(logs)).toEqual([ADDR_A.toLowerCase(), ADDR_B.toLowerCase()]);
  });

  it("drops addresses whose final status is false", () => {
    const logs = [
      { who: ADDR_A, status: true },
      { who: ADDR_A, status: false },
      { who: ADDR_B, status: true },
    ];
    expect(reduceEnrolledLogs(logs)).toEqual([ADDR_B.toLowerCase()]);
  });

  it("normalizes addresses to lowercase and skips empty who", () => {
    const logs = [
      { who: ADDR_A_UPPER, status: true },
      { who: "", status: true },
      { who: null, status: true },
      { status: true },
    ];
    expect(reduceEnrolledLogs(logs)).toEqual([ADDR_A.toLowerCase()]);
  });

  it("returns empty for empty or non-array-like input", () => {
    expect(reduceEnrolledLogs([])).toEqual([]);
  });
});
