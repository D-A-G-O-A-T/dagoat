import { describe, expect, it } from "vitest";
import { quoteUsdtOut } from "./chain/format.js";
import {
  buildDeskRow,
  ENROLLMENT_WARNING_COPY,
  HOLD_NOTICE_COPY,
  isOwnDesk,
  maxSellableGoatWei,
  NOT_EXCHANGE_COPY,
  pickDefaultDesk,
  POSTED_BID_COPY,
  SELL_INSUFFICIENT_GOAT_COPY,
  SELL_INSUFFICIENT_OWNER_USDT_COPY,
  sortDesksByBestBid,
} from "./market.js";

const OWNER_A = "0x1111111111111111111111111111111111111111";
const OWNER_B = "0x2222222222222222222222222222222222222222";
const OWNER_C = "0x3333333333333333333333333333333333333333";
const DESK_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DESK_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DESK_C = "0xcccccccccccccccccccccccccccccccccccccccc";

const OPEN_SESSION = [1n, 1_000n, 2_000n, 500_000n];
const NO_SESSION = [0n, 0n, 0n, 0n];

describe("buildDeskRow (desk-row aggregation)", () => {
  it("aggregates raw per-desk reads into a keyed row, decoding the session tuple", () => {
    const row = buildDeskRow({
      address: DESK_A,
      owner: OWNER_A,
      name: "Founder Desk",
      bid: 10_000n,
      depth: 500_000000n,
      sessionRaw: OPEN_SESSION,
    });
    expect(row).toEqual({
      address: DESK_A,
      owner: OWNER_A,
      name: "Founder Desk",
      displayName: "Founder Desk",
      bid: 10_000n,
      depth: 500_000000n,
      session: { id: 1n, start: 1_000n, end: 2_000n, cap: 500_000n },
      isOpen: true,
    });
  });

  it("falls back the display name to a shortened address when unnamed", () => {
    const row = buildDeskRow({ address: DESK_B, owner: OWNER_B, name: "", bid: 5_000n, depth: 0n, sessionRaw: NO_SESSION });
    expect(row.displayName).toBe("0x2222…2222");
    expect(row.name).toBe("");
  });

  it("treats a whitespace-only name the same as unnamed", () => {
    const row = buildDeskRow({ address: DESK_B, owner: OWNER_B, name: "   ", bid: 0n, depth: 0n, sessionRaw: NO_SESSION });
    expect(row.displayName).toBe("0x2222…2222");
  });

  it("marks isOpen false and session null when currentSession id is 0", () => {
    const row = buildDeskRow({ address: DESK_C, owner: OWNER_C, name: "Alice's Desk", bid: 15_000n, depth: 0n, sessionRaw: NO_SESSION });
    expect(row.session).toBeNull();
    expect(row.isOpen).toBe(false);
  });

  it("defaults missing bid/depth to 0n instead of undefined", () => {
    const row = buildDeskRow({ address: DESK_A, owner: OWNER_A, name: "", bid: undefined, depth: undefined, sessionRaw: NO_SESSION });
    expect(row.bid).toBe(0n);
    expect(row.depth).toBe(0n);
  });
});

describe("sortDesksByBestBid", () => {
  it("sorts by highest bid first — the founder's 0.01 vs Alice's better 0.015 bid", () => {
    const founder = buildDeskRow({ address: DESK_A, owner: OWNER_A, name: "Founder Desk", bid: 10_000n, depth: 500_000000n, sessionRaw: OPEN_SESSION });
    const alice = buildDeskRow({ address: DESK_B, owner: OWNER_B, name: "Alice's Desk", bid: 15_000n, depth: 500_000000n, sessionRaw: OPEN_SESSION });
    const sorted = sortDesksByBestBid([founder, alice]);
    expect(sorted.map((r) => r.displayName)).toEqual(["Alice's Desk", "Founder Desk"]);
  });

  it("does not mutate the input array", () => {
    const rows = [
      buildDeskRow({ address: DESK_A, owner: OWNER_A, name: "A", bid: 1n, depth: 0n, sessionRaw: NO_SESSION }),
      buildDeskRow({ address: DESK_B, owner: OWNER_B, name: "B", bid: 2n, depth: 0n, sessionRaw: NO_SESSION }),
    ];
    const original = [...rows];
    sortDesksByBestBid(rows);
    expect(rows).toEqual(original);
  });

  it("breaks ties on equal bids by desk address, deterministically", () => {
    const one = buildDeskRow({ address: DESK_B, owner: OWNER_A, name: "One", bid: 10_000n, depth: 0n, sessionRaw: NO_SESSION });
    const two = buildDeskRow({ address: DESK_A, owner: OWNER_B, name: "Two", bid: 10_000n, depth: 0n, sessionRaw: NO_SESSION });
    const sorted = sortDesksByBestBid([one, two]);
    expect(sorted.map((r) => r.address)).toEqual([DESK_A, DESK_B]);
  });

  it("handles zero desks and a single desk", () => {
    expect(sortDesksByBestBid([])).toEqual([]);
    const only = buildDeskRow({ address: DESK_A, owner: OWNER_A, name: "Solo", bid: 1n, depth: 0n, sessionRaw: NO_SESSION });
    expect(sortDesksByBestBid([only])).toEqual([only]);
  });
});

describe("isOwnDesk", () => {
  it("matches case-insensitively", () => {
    const row = buildDeskRow({ address: DESK_A, owner: OWNER_A.toUpperCase().replace("0X", "0x"), name: "", bid: 0n, depth: 0n, sessionRaw: NO_SESSION });
    expect(isOwnDesk(row, OWNER_A)).toBe(true);
  });

  it("is false for another owner's desk, or missing inputs", () => {
    const row = buildDeskRow({ address: DESK_A, owner: OWNER_A, name: "", bid: 0n, depth: 0n, sessionRaw: NO_SESSION });
    expect(isOwnDesk(row, OWNER_B)).toBe(false);
    expect(isOwnDesk(row, null)).toBe(false);
    expect(isOwnDesk(null, OWNER_A)).toBe(false);
  });
});

describe("pickDefaultDesk (best-bid seller routing, design §2.3)", () => {
  const founder = buildDeskRow({ address: DESK_A, owner: OWNER_A, name: "Founder Desk", bid: 10_000n, depth: 500_000000n, sessionRaw: OPEN_SESSION });
  const alice = buildDeskRow({ address: DESK_B, owner: OWNER_B, name: "Alice's Desk", bid: 15_000n, depth: 500_000000n, sessionRaw: OPEN_SESSION });
  const sorted = sortDesksByBestBid([founder, alice]);

  it("defaults to the best active bid — Alice's 0.015 over the founder's 0.01", () => {
    expect(pickDefaultDesk(sorted, OWNER_C)?.displayName).toBe("Alice's Desk");
  });

  it("skips the caller's own desk even if it has the best bid (OwnerCannotSell)", () => {
    expect(pickDefaultDesk(sorted, OWNER_B)?.displayName).toBe("Founder Desk");
  });

  it("skips a closed desk even if its bid is best", () => {
    const closedBest = buildDeskRow({ address: DESK_C, owner: OWNER_C, name: "Closed", bid: 99_000n, depth: 0n, sessionRaw: NO_SESSION });
    const withClosed = sortDesksByBestBid([founder, alice, closedBest]);
    expect(pickDefaultDesk(withClosed, "0x9999999999999999999999999999999999999999")?.displayName).toBe("Alice's Desk");
  });

  it("returns null when every open desk is the caller's own, or none are open", () => {
    expect(pickDefaultDesk(sorted, OWNER_A)?.displayName).toBe("Alice's Desk");
    expect(pickDefaultDesk([founder], OWNER_A)).toBeNull();
    const closedOnly = buildDeskRow({ address: DESK_C, owner: OWNER_C, name: "Closed", bid: 5n, depth: 0n, sessionRaw: NO_SESSION });
    expect(pickDefaultDesk([closedOnly], OWNER_A)).toBeNull();
  });
});

describe("estimated USDT calc (reused from chain/format.js — no duplicate math)", () => {
  it("matches BuyDesk.sol's sell() math for a sell at the best bid", () => {
    // 100 GOAT at Alice's 0.015 bid -> 1.5 USDT.
    expect(quoteUsdtOut(100_000000000000000000n, 15_000n)).toBe(1_500000n);
  });
});

describe("maxSellableGoatWei", () => {
  const oneGoat = 1_000000000000000000n;
  const bid = 10_000n; // 0.01 USDT per GOAT

  it("is capped by wallet GOAT balance", () => {
    expect(
      maxSellableGoatWei({
        goatBalance: 2n * oneGoat,
        bid,
        depth: 1_000000n, // plenty USDT
        sessionCap: null,
      }),
    ).toBe(2n * oneGoat);
  });

  it("is capped by desk depth at bid", () => {
    // 0.01 USDT depth => at most 1 GOAT
    expect(
      maxSellableGoatWei({
        goatBalance: 100n * oneGoat,
        bid,
        depth: 10_000n,
        sessionCap: null,
      }),
    ).toBe(oneGoat);
  });

  it("is capped by finite session cap", () => {
    expect(
      maxSellableGoatWei({
        goatBalance: 100n * oneGoat,
        bid,
        depth: 1_000000n,
        sessionCap: 5n * oneGoat,
      }),
    ).toBe(5n * oneGoat);
  });
});

describe("sell insufficient balance copy", () => {
  it("names the seller wallet GOAT shortfall, not the desk owner", () => {
    expect(SELL_INSUFFICIENT_GOAT_COPY).toMatch(/your wallet/i);
    expect(SELL_INSUFFICIENT_GOAT_COPY).toMatch(/GOAT/i);
    expect(SELL_INSUFFICIENT_GOAT_COPY).not.toMatch(/desk owner/i);
    expect(SELL_INSUFFICIENT_GOAT_COPY).not.toMatch(/USDT/i);
  });

  it("keeps owner-USDT copy only for residual owner-side failures", () => {
    expect(SELL_INSUFFICIENT_OWNER_USDT_COPY).toMatch(/desk owner/i);
    expect(SELL_INSUFFICIENT_OWNER_USDT_COPY).toMatch(/USDT/i);
  });
});

describe("honesty copy (Q7 house style + design §2.3)", () => {
  const ALL_COPY = [POSTED_BID_COPY, ENROLLMENT_WARNING_COPY, HOLD_NOTICE_COPY, NOT_EXCHANGE_COPY];
  const FORBIDDEN_WORDS = ["invest", "returns", "guaranteed", "profit", "yield", "market price"];

  it("labels every bid a posted buy order that may be zero, not a market price", () => {
    expect(POSTED_BID_COPY).toMatch(/posted buy order/i);
    expect(POSTED_BID_COPY).toMatch(/not a market price/i);
    expect(POSTED_BID_COPY).toMatch(/may be zero/i);
  });

  it("never uses forbidden investment vocabulary anywhere in the Market copy", () => {
    for (const copy of ALL_COPY) {
      for (const word of FORBIDDEN_WORDS) {
        // NOT_EXCHANGE_COPY legitimately says "not a market price" (negated),
        // so match the bare phrase only outside that one sanctioned negation.
        if (word === "market price" && copy === NOT_EXCHANGE_COPY) continue;
        if (word === "market price" && copy === POSTED_BID_COPY) continue;
        expect(copy.toLowerCase()).not.toContain(word);
      }
    }
  });

  it("states the not-an-exchange framing (design §2.3 / §5, no matching venue)", () => {
    expect(NOT_EXCHANGE_COPY).toMatch(/independent, voluntary/i);
    expect(NOT_EXCHANGE_COPY).toMatch(/not a matching exchange/i);
  });
});
