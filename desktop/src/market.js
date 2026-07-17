// Pure desk-list aggregation + sell-routing logic for the Market tab
// (multi-desk donor BuyDesk factory — docs/superpowers/specs/2026-07-13-
// donor-buydesk-factory-multidesk-design.md §2.3). Kept dependency-free of
// React/viem client calls so it's unit-testable without a chain connection
// — see market.test.js. Amount math (estimated USDT payout) is NOT
// duplicated here: Market.jsx reuses chain/format.js's quoteUsdtOut
// directly so the two never drift.
import { decodeSession, NO_CAP, shortAddress } from "./chain/format.js";

// Honesty copy (design §2.3 "Honesty" bullet + Q7 house style, HonestyBanner.jsx)
// — exported so every panel that shows a bid uses the exact same wording,
// and so market.test.js can pin the forbidden-vocabulary rule.
export const POSTED_BID_COPY = "a posted buy order, not a market price — may be zero";
export const ENROLLMENT_WARNING_COPY =
  "Your wallet is not enrolled yet — use Enroll myself above (pays ETH gas), or ask the founder to enroll this wallet address.";
export const HOLD_NOTICE_COPY =
  "You never have to sell. Workers earn and hold GOAT; selling GOAT for USDT on a desk is optional.";
export const NOT_EXCHANGE_COPY =
  "Each desk below is one donor's own independent, voluntary buy order — not a matching exchange or a market price.";

/// Builds one desk-list row from raw on-chain reads. `sessionRaw` is
/// BuyDesk.currentSession()'s positional tuple (see decodeSession's doc
/// comment for the viem multi-output gotcha it pins). `name` is the
/// factory's nameOf(owner) — an empty/blank name falls back to a
/// shortened address, per design §2.3 ("desk name (fallback to shortened
/// address if unnamed)").
export function buildDeskRow({ address, owner, name, bid, depth, sessionRaw }) {
  const trimmedName = (name ?? "").trim();
  const session = decodeSession(sessionRaw);
  return {
    address,
    owner,
    name: trimmedName,
    displayName: trimmedName || shortAddress(owner),
    bid: bid ?? 0n,
    depth: depth ?? 0n,
    session,
    isOpen: session != null,
  };
}

/**
 * Max GOAT wei a seller can realistically sell in one shot:
 * min(wallet GOAT balance, desk depth converted at bid, session cap if finite).
 * (Session "already sold" is not tracked here — cap is an upper bound.)
 */
export function maxSellableGoatWei({ goatBalance = 0n, bid = 0n, depth = 0n, sessionCap = null } = {}) {
  let max = goatBalance < 0n ? 0n : goatBalance;
  if (bid > 0n) {
    const byDepth = (depth * 1_000_000_000_000_000_000n) / bid;
    if (byDepth < max) max = byDepth;
  } else if (depth === 0n) {
    max = 0n;
  }
  if (sessionCap != null && sessionCap < NO_CAP && sessionCap < max) {
    max = sessionCap < 0n ? 0n : sessionCap;
  }
  return max < 0n ? 0n : max;
}

/** User-facing sell errors when the ERC20 revert is ambiguous (GOAT vs owner USDT). */
export const SELL_INSUFFICIENT_GOAT_COPY =
  "Your wallet does not have enough GOAT for that amount — lower the amount or use the slider (0 to your balance).";
export const SELL_INSUFFICIENT_OWNER_USDT_COPY =
  "The desk owner's wallet doesn't hold enough USDT to cover that sale right now — try a smaller amount, or the owner needs to top up their wallet.";

/// Sorts desk rows by best (highest) bid, descending — design §2.3 ("show
/// a table by best bid"). Ties break by desk address so ordering is
/// deterministic across renders instead of flickering when two desks post
/// the same bid.
export function sortDesksByBestBid(rows) {
  return [...rows].sort((a, b) => {
    if (a.bid !== b.bid) return a.bid > b.bid ? -1 : 1;
    return a.address.localeCompare(b.address);
  });
}

/// True when `row` is the given wallet's own desk (case-insensitive address
/// compare — viem addresses are checksummed but not guaranteed to match
/// case across independent reads).
export function isOwnDesk(row, myAddress) {
  if (!row || !myAddress) return false;
  return row.owner.toLowerCase() === myAddress.toLowerCase();
}

/// Default sell target: the best-bid desk (rows must already be sorted by
/// sortDesksByBestBid) that is (a) currently open and (b) not the seller's
/// own desk — BuyDesk.sol reverts OwnerCannotSell on a self-sell. Returns
/// null when no eligible desk exists (e.g. only your own desk, or every
/// desk is closed).
export function pickDefaultDesk(sortedRows, myAddress) {
  return sortedRows.find((row) => row.isOpen && !isOwnDesk(row, myAddress)) ?? null;
}
