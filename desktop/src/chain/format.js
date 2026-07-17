// Amount formatting/parsing shared by the Wallet (and later Ops/Miner)
// tabs. GOAT is 18dp, MockUSDT is 6dp (Global Constraints,
// docs/superpowers/plans/2026-07-11-season0-fullsystem.md). Kept dependency-
// free of any component so it's unit-testable on its own.
import { formatUnits, parseUnits } from "viem";

export const GOAT_DECIMALS = 18;
export const USDT_DECIMALS = 6;

/// bigint (wei) -> display string, e.g. 1_500000000000000000n -> "1.5"
export function formatGoat(wei) {
  return formatUnits(wei ?? 0n, GOAT_DECIMALS);
}

/// display string -> bigint (wei). Empty/unparseable/negative input parses
/// to 0n rather than throwing — this is called directly from render bodies
/// (live "amount you'd receive" previews) as the user types, so a stray
/// non-numeric character (e.g. "1.2.3") must never crash the tab.
export function parseGoat(amountStr) {
  return safeParseUnits(amountStr, GOAT_DECIMALS);
}

export function formatUsdt(wei) {
  return formatUnits(wei ?? 0n, USDT_DECIMALS);
}

export function parseUsdt(amountStr) {
  return safeParseUnits(amountStr, USDT_DECIMALS);
}

function safeParseUnits(amountStr, decimals) {
  const trimmed = (amountStr ?? "").trim();
  if (!trimmed) return 0n;
  try {
    const value = parseUnits(trimmed, decimals);
    return value < 0n ? 0n : value;
  } catch {
    return 0n;
  }
}

/// BuyDesk.bid is USDT (6dp) payable per 1e18 GOAT wei (i.e. per 1 whole
/// GOAT) — see BuyDesk.sol `sell()`: usdtOut = goatAmount * bid / 1e18.
/// Default bid 10_000 -> "0.01" (0.01 USDT per GOAT).
export function formatBid(bid) {
  return formatUnits(bid ?? 0n, USDT_DECIMALS);
}

/// usdtOut a caller would receive for `goatWei` GOAT at the given `bid`,
/// mirroring BuyDesk.sol's own math so the UI can preview before sending.
export function quoteUsdtOut(goatWei, bid) {
  if (!goatWei || !bid) return 0n;
  return (goatWei * bid) / 1_000_000_000_000_000_000n;
}

/// The "no per-account cap" sentinel: BuyDesk has no unlimited flag, so the
/// Market tab encodes "blank cap" as uint256 max when opening a session
/// (Market.jsx handleOpenSession). NOTE cap == 0 is NOT unlimited — sell()
/// reverts CapExceeded on `already + amount > cap`, so a zero cap blocks
/// every sell; only the max-uint sentinel means "no limit".
export const NO_CAP = 2n ** 256n - 1n;

/// BuyDesk session per-account cap (GOAT, 18dp) -> display string. The
/// max-uint sentinel renders as "no cap"; any real value shows in whole
/// GOAT, e.g. 5000000000000000000000n -> "5000 GOAT".
export function formatCap(cap) {
  if (cap == null || cap >= NO_CAP) return "no cap";
  return `${formatGoat(cap)} GOAT`;
}

export function shortAddress(addr) {
  if (!addr) return "";
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

export function shortHash(hash) {
  if (!hash) return "";
  return `${hash.slice(0, 10)}…`;
}

/// Vocabulary law: amounts always suffixed "(testnet)".
export function testnetAmount(displayValue, symbol) {
  return `${displayValue} ${symbol} (testnet)`;
}

/// Decodes BuyDesk.currentSession()'s return value into a session object,
/// or null when no session is open.
///
/// currentSession() has 4 separate named outputs, so viem's readContract
/// decodes it as a plain positional array tuple [id, start, end, cap] — NOT
/// a keyed object (that shorthand only applies to a single struct/tuple-
/// typed output). A prior bug here destructured it as if it were keyed,
/// which a smoke test caught; this helper pins the correct positional
/// decode with regression coverage.
export function decodeSession(raw) {
  const [id, start, end, cap] = raw;
  if (id === 0n) return null;
  return { id, start, end, cap };
}

/// Decodes WorkMinter.jobs(bytes32)'s return value into a keyed job object.
/// jobs() has 8 separate named outputs, so viem's readContract decodes it
/// as a plain positional array tuple — the same gotcha as currentSession()
/// above (see decodeSession's doc comment); a keyed-destructure here would
/// silently read undefined fields instead of throwing. unitReward === 0n is
/// WorkMinter.sol's own "job does not exist" sentinel (createJob requires
/// unitReward > 0), see jobExists().
export function decodeJob(raw) {
  const [catalogHash, unitReward, minted, holdbackBps, externalAcceptor, founderAcceptOnly, closed, lastMint] = raw;
  return { catalogHash, unitReward, minted, holdbackBps, externalAcceptor, founderAcceptOnly, closed, lastMint };
}

/// True only when jobs(jobId) decoded a real, created job.
export function jobExists(job) {
  return Boolean(job) && job.unitReward !== 0n;
}
