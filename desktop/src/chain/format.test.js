import { describe, expect, it } from "vitest";
import {
  decodeJob,
  decodeSession,
  formatBid,
  formatCap,
  formatGoat,
  formatUsdt,
  jobExists,
  NO_CAP,
  parseGoat,
  parseUsdt,
  quoteUsdtOut,
  shortAddress,
} from "./format.js";

describe("formatGoat / parseGoat (18dp)", () => {
  it("formats whole GOAT", () => {
    expect(formatGoat(1_000000000000000000n)).toBe("1");
  });

  it("formats fractional GOAT", () => {
    expect(formatGoat(1_500000000000000000n)).toBe("1.5");
  });

  it("formats zero and undefined as 0", () => {
    expect(formatGoat(0n)).toBe("0");
    expect(formatGoat(undefined)).toBe("0");
  });

  it("parses whole and fractional amounts back to wei", () => {
    expect(parseGoat("1")).toBe(1_000000000000000000n);
    expect(parseGoat("0.000000000000000001")).toBe(1n);
  });

  it("parses empty/blank input as 0n instead of throwing", () => {
    expect(parseGoat("")).toBe(0n);
    expect(parseGoat("   ")).toBe(0n);
    expect(parseGoat(undefined)).toBe(0n);
  });

  it("parses unparseable input (mid-typing amounts) as 0n instead of throwing", () => {
    // Wallet.jsx calls parseGoat directly in its render body for the live
    // "amount you'd receive" preview — a throw here would crash the tab.
    expect(parseGoat("abc")).toBe(0n);
    expect(parseGoat("1.2.3")).toBe(0n);
    expect(parseGoat("1,000")).toBe(0n);
  });

  it("clamps negative input to 0n", () => {
    expect(parseGoat("-1")).toBe(0n);
  });

  it("round-trips an arbitrary amount", () => {
    const wei = 123_456789012345678n;
    expect(parseGoat(formatGoat(wei))).toBe(wei);
  });
});

describe("formatUsdt / parseUsdt (6dp)", () => {
  it("formats MockUSDT amounts", () => {
    expect(formatUsdt(1_000000n)).toBe("1");
    expect(formatUsdt(10000n)).toBe("0.01");
  });

  it("parses MockUSDT amounts", () => {
    expect(parseUsdt("1")).toBe(1_000000n);
    expect(parseUsdt("0.01")).toBe(10000n);
  });

  it("parses unparseable/negative input as 0n instead of throwing", () => {
    expect(parseUsdt("abc")).toBe(0n);
    expect(parseUsdt("-1")).toBe(0n);
  });
});

describe("formatBid + quoteUsdtOut", () => {
  it("formats the default bid (10_000) as 0.01 USDT per GOAT", () => {
    expect(formatBid(10_000n)).toBe("0.01");
  });

  it("formats a zero bid (desk closed for value) as 0", () => {
    expect(formatBid(0n)).toBe("0");
  });

  it("quotes usdtOut identically to BuyDesk.sol's sell() math", () => {
    // 1 GOAT (1e18 wei) at the default bid of 10_000 -> 10_000 (0.01 USDT).
    expect(quoteUsdtOut(1_000000000000000000n, 10_000n)).toBe(10_000n);
    // 2.5 GOAT at bid 10_000 -> 25_000 (0.025 USDT).
    expect(quoteUsdtOut(2_500000000000000000n, 10_000n)).toBe(25_000n);
  });

  it("quotes 0 for a zero amount or zero bid", () => {
    expect(quoteUsdtOut(0n, 10_000n)).toBe(0n);
    expect(quoteUsdtOut(1_000000000000000000n, 0n)).toBe(0n);
  });
});

describe("formatCap", () => {
  it("renders the max-uint sentinel as 'no cap'", () => {
    expect(formatCap(NO_CAP)).toBe("no cap");
  });

  it("renders a real per-account cap in whole GOAT", () => {
    // 5000 GOAT — the value the founder's own 'Rocket' desk had set on-chain
    // but which the Market tab was never displaying.
    expect(formatCap(5_000n * 1_000000000000000000n)).toBe("5000 GOAT");
    expect(formatCap(1_500000000000000000n)).toBe("1.5 GOAT");
  });

  it("renders a zero cap as '0 GOAT', NOT 'no cap' (zero cap blocks all sells)", () => {
    // BuyDesk.sell() reverts CapExceeded on `already + amount > cap`, so a
    // zero cap is the opposite of unlimited — it must not read as "no cap".
    expect(formatCap(0n)).toBe("0 GOAT");
  });

  it("renders null/undefined as 'no cap'", () => {
    expect(formatCap(null)).toBe("no cap");
    expect(formatCap(undefined)).toBe("no cap");
  });
});

describe("decodeSession", () => {
  // Pins the bug a smoke test caught: viem decodes BuyDesk.currentSession()
  // as a positional array tuple [id, start, end, cap] (4 named outputs, not
  // a single keyed struct) — a destructure-as-object bug silently produced
  // undefined fields instead of throwing or erroring visibly.
  it("decodes a raw 4-element viem array tuple into a keyed session object", () => {
    const raw = [7n, 1_000n, 2_000n, 500_000n];
    expect(decodeSession(raw)).toEqual({ id: 7n, start: 1_000n, end: 2_000n, cap: 500_000n });
  });

  it("returns null (no session open) when id is 0n", () => {
    const raw = [0n, 0n, 0n, 0n];
    expect(decodeSession(raw)).toBeNull();
  });
});

describe("decodeJob / jobExists", () => {
  // Pins the same viem positional-tuple gotcha as decodeSession: jobs()
  // has 8 separate named outputs, so viem decodes a plain array, not a
  // keyed struct.
  const CATALOG_HASH = "0x1111111111111111111111111111111111111111111111111111111111111111";
  const ACCEPTOR = "0x0000000000000000000000000000000000000000";

  it("decodes a raw 8-element viem array tuple into a keyed job object", () => {
    const raw = [CATALOG_HASH, 1_000000000000000000n, 5_000000000000000000n, 500, ACCEPTOR, true, false, 12_345n];
    expect(decodeJob(raw)).toEqual({
      catalogHash: CATALOG_HASH,
      unitReward: 1_000000000000000000n,
      minted: 5_000000000000000000n,
      holdbackBps: 500,
      externalAcceptor: ACCEPTOR,
      founderAcceptOnly: true,
      closed: false,
      lastMint: 12_345n,
    });
  });

  it("jobExists is false for the zero-unitReward 'no job created yet' sentinel", () => {
    const raw = ["0x" + "0".repeat(64), 0n, 0n, 0, ACCEPTOR, false, false, 0n];
    expect(jobExists(decodeJob(raw))).toBe(false);
    expect(jobExists(null)).toBe(false);
  });

  it("jobExists is true once unitReward is nonzero", () => {
    const raw = [CATALOG_HASH, 1_000000000000000000n, 0n, 500, ACCEPTOR, true, false, 0n];
    expect(jobExists(decodeJob(raw))).toBe(true);
  });
});

describe("shortAddress", () => {
  it("truncates a 20-byte address to head…tail", () => {
    expect(shortAddress("0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0")).toBe("0x9fE4…a6e0");
  });

  it("returns empty string for falsy input", () => {
    expect(shortAddress("")).toBe("");
    expect(shortAddress(undefined)).toBe("");
  });
});
