// Observed-shortfall gas floor (P5).
//
// THE BUG THIS CLOSES. The sell preflight compared a live ETH balance against a
// hardcoded gas estimate. A rejected transaction consumes no gas, so after a
// failed sell the balance is byte-identical on the retry and the gate returns
// {ok:true} again — forever, including after 00:00 UTC. Worse, in the common
// stuck band the gate short-circuited BEFORE reaching requestDrip, so the
// relayer was never contacted and the wallet's untouched daily drip was never
// even asked for.
//
// THE FIX. No choice of constant can fix that, because the defect is the SHAPE
// of the gate (a pure function of balance, which a rejected tx does not change)
// rather than the value of one number. So the gate learns from reality: when a
// transaction fails for insufficient funds at balance B, we record B, and every
// later gate for that (chain, wallet, step) requires strictly MORE than B. At
// the balance that just failed the requirement exceeds it BY CONSTRUCTION —
// `requiredWei` is the whole guarantee, and it holds regardless of fee
// movement, estimate error, or a fee-estimate collapse to 0n.
//
// WHY MODULE SCOPE, NOT COMPONENT STATE. App.jsx renders only the active panel
// (`const ActivePanel = PANELS[active] ?? Miner`), so switching tabs unmounts
// Market and destroys every piece of component state. Going to the Wallet tab
// to find your address — the exact thing a stuck user does next — would wipe a
// component-held floor and hand back a fresh silent pass. The store lives here,
// one scope up, so it survives unmount/remount.
//
// NOT PERSISTED. A full app restart clears it, costing one more loud (and
// self-relatching) failure. Serialising bigints to disk with an invalidation
// policy is more machinery than a testnet pilot justifies; the guarantee is
// stated honestly as "cannot keep passing within a session" rather than
// "never".

import { extractErrorName } from "./client.js";

export const FLOOR_STEP_APPROVE_SELL = "approveSell";
export const FLOOR_STEP_SELL = "sell";

/** Fresh, isolated store. Tests use this; the app uses the module default. */
export function newFloorStore() {
  return new Map();
}

const defaultStore = newFloorStore();

/** Stable key. Lowercased address so checksum casing can't bypass the floor. */
export function floorKey({ chainId, address, step }) {
  return `${chainId}:${String(address ?? "").toLowerCase()}:${step}`;
}

/**
 * THE GUARANTEE. At the balance that already failed, `floorWei === balance`, so
 * this returns `balance + 1n` and `needsGasDrip(balance, balance + 1n)` is true.
 * The gate cannot report "you can pay for this" at a balance already proven
 * insufficient. With no floor recorded (`0n`) this is exactly the old
 * behaviour, so nothing changes for a wallet that has never failed.
 */
export function requiredWei(estCostWei, floorWei) {
  const est = estCostWei ?? 0n;
  const floor = floorWei ?? 0n;
  // 0n means "nothing has failed here yet" — pass the estimate through
  // untouched so a wallet with no failure history sees the exact pre-fix
  // behaviour, including the deliberate fail-open when the fee estimate
  // collapses to 0n and makes estCostWei 0n.
  if (floor <= 0n) return est;
  return est > floor ? est : floor + 1n;
}

export function readFloorWei(key, store = defaultStore) {
  return store.get(key) ?? 0n;
}

/**
 * Record an observed shortfall. Monotonic (keeps the maximum) so a later,
 * lower reading can never lower the bar. A `sell` shortfall also raises the
 * `approveSell` floor: a sell that failed at B proves approve+sell needs more
 * than B. The reverse does not hold and is not applied.
 */
export function recordShortfallWei(key, balanceWei, store = defaultStore) {
  if (typeof balanceWei !== "bigint" || balanceWei < 0n) return;
  const prior = store.get(key) ?? 0n;
  if (balanceWei > prior) store.set(key, balanceWei);

  if (key.endsWith(`:${FLOOR_STEP_SELL}`)) {
    const combined = `${key.slice(0, -FLOOR_STEP_SELL.length)}${FLOOR_STEP_APPROVE_SELL}`;
    const priorCombined = store.get(combined) ?? 0n;
    if (balanceWei > priorCombined) store.set(combined, balanceWei);
  }
}

/** Clear every step's floor for one wallet on one chain (on a successful tx). */
export function clearFloorsForAddress({ chainId, address }, store = defaultStore) {
  const prefix = `${chainId}:${String(address ?? "").toLowerCase()}:`;
  for (const key of [...store.keys()]) {
    if (key.startsWith(prefix)) store.delete(key);
  }
}

/**
 * Clear ONE step's floor (review round 1, "also"). A successful approve only
 * proves the approve step's own gas was affordable — it says nothing about
 * whether a sell will be, so it must not silently discard a sell floor a
 * prior failed sell already earned. Use this at a single step's own success;
 * use `clearFloorsForAddress` only where a whole trade cycle has completed.
 */
export function clearFloorForStep({ chainId, address, step }, store = defaultStore) {
  store.delete(floorKey({ chainId, address, step }));
}

// viem's node-level funds errors (errors/node.js). Names, not just text, so a
// message rewording in a viem upgrade degrades to the regex rather than
// silently disabling the floor.
//
// FIX-1 (review round 1). geth's MOST COMMON way to say "this wallet can't
// afford the gas" is NOT "insufficient funds" — for a zero-value contract
// call, when balance/maxFeePerGas < gasNeeded, geth caps the eth_estimateGas
// search ceiling at that quotient and returns "gas required exceeds
// allowance (N)". viem's getNodeError (utils/errors/getNodeError.js) checks
// ExecutionRevertedError.nodeMessage — literally
// `/execution reverted|gas required exceeds allowance/` — BEFORE
// InsufficientFundsError.nodeMessage, so that message classifies as
// ExecutionRevertedError (name: "ExecutionRevertedError"), which used to
// return false here: onShortfall never fired, no floor was ever recorded,
// and the gate passed forever — the original P5 bug, verbatim, for what is
// actually the common path (only an OP-Stack L1 data-fee overshoot on an
// estimate that DID fit produces "insufficient funds" instead). Verified
// against viem's real error shape: `getEstimateGasError({ details: "gas
// required exceeds allowance (21000)" }, {})` yields
// `{ name: "EstimateGasExecutionError", shortMessage: "Execution reverted
// with reason: gas required exceeds allowance (21000).", cause: { name:
// "ExecutionRevertedError" } }` — see gasFloor.test.js.
//
// We match the TEXT, not the ExecutionRevertedError CLASS: the class also
// covers real decoded-by-string contract reverts, and INSUFFICIENT_GAS_COPY's
// claim that "no transaction was sent and nothing was spent" must stay true,
// which only holds if a genuine Solidity revert keeps classifying as false.
//
// IntrinsicGasTooLowError (nodeMessage `/intrinsic gas too low/`) is the
// same underlying failure one step further down: if the balance-based cap
// falls below the network's 21,000 intrinsic floor, geth can't even offer a
// gas value to try and returns this instead of "gas required exceeds
// allowance". It is a distinct, unambiguous node error class (never emitted
// for a contract revert), so it is matched by NAME like
// InsufficientFundsError, not by text.
const FUNDS_ERROR_NAMES = new Set(["InsufficientFundsError", "IntrinsicGasTooLowError"]);
const FUNDS_TEXT =
  /exceeds the balance|insufficient funds|exceeds transaction sender account balance|gas required exceeds allowance|intrinsic gas too low/i;

/**
 * Is this a node-level "can't afford the gas" failure (as opposed to a decoded
 * Solidity revert)? Getting this wrong in the false-positive direction poisons
 * the floor — blocking an affordable sell and spending the wallet's single
 * daily drip — so a decoded contract error always wins. Regex precedent:
 * chain/enroll.js:69.
 */
export function isInsufficientFundsError(err) {
  if (!err) return false;
  // A decoded custom Solidity error is never a funds problem, whatever the
  // wrapper's prose says.
  if (extractErrorName(err)) return false;

  let cursor = err;
  while (cursor) {
    if (cursor?.name && FUNDS_ERROR_NAMES.has(cursor.name)) return true;
    cursor = cursor.cause;
  }
  const text = `${err?.shortMessage ?? ""} ${err?.details ?? ""} ${err?.message ?? ""}`;
  return FUNDS_TEXT.test(text);
}

/**
 * Gate -> send -> learn. Exported (rather than inline in the React handlers)
 * because it is the ONLY seam this repo can test: a mutation run proved that
 * with the sequence inline, deleting both gate call sites left the suite at
 * its exact 266/1 baseline.
 *
 * `readBalance` is re-read AT FAILURE, not taken from the gate: if the gate
 * requested a drip that landed, the pre-gate reading is stale and recording it
 * would set a floor BELOW the current balance — which the very next gate would
 * clear, silently.
 */
export async function runGatedTx({ preflight, send, readBalance, onShortfall, onSuccess }) {
  const gate = await preflight();
  if (!gate?.ok) return { ok: false, gate };

  try {
    const result = await send();
    onSuccess?.();
    return { ok: true, result, gate };
  } catch (err) {
    if (isInsufficientFundsError(err)) {
      let observed;
      try {
        observed = await readBalance?.();
      } catch {
        observed = undefined;
      }
      if (typeof observed !== "bigint") observed = gate?.haveWei;
      if (typeof observed === "bigint") onShortfall?.(observed);
    }
    throw err;
  }
}

/** Exact 18-decimal wei -> string. No Number(): wei exceeds MAX_SAFE_INTEGER. */
function weiToTestEth(wei) {
  const neg = wei < 0n;
  const abs = neg ? -wei : wei;
  const whole = abs / 10n ** 18n;
  const frac = (abs % 10n ** 18n).toString().padStart(18, "0").replace(/0+$/, "");
  return `${neg ? "-" : ""}${whole}${frac ? `.${frac}` : ""}`;
}

// FIX-3 round 3 (review round 3): the underlying comparison arithmetic
// throughout this file stays at full wei precision — this constant and the
// function below affect DISPLAY only. Long wei-tail decimals (e.g.
// "0.003000000000000002") are an artefact of the `floor + 1n`/`+ 1n` terms
// propagating through to the rendered string, not information a stuck user
// can act on; "about" paired with 18 decimal places reads as a bug.
const DISPLAY_SIGNIFICANT_DIGITS = 4n;

/**
 * Round `wei` to `DISPLAY_SIGNIFICANT_DIGITS` significant digits for
 * rendering only. `direction` decides which way, and getting it backwards
 * for either caller is unsafe in a different way:
 *  - "up": for anything the user is being told to fund TO (a requirement or
 *    a suggestion). The displayed value must never be BELOW the real
 *    computed one — rounding down here would hand a stuck user a number
 *    that is provably still insufficient, the exact non-convergence this
 *    whole fix chain exists to close.
 *  - "down": for a balance actually held. The displayed value must never be
 *    ABOVE the real one — rounding up here would overstate what the wallet
 *    holds.
 * `wei <= 0n` (including the ordinary "nothing held yet" balance) passes
 * through unrounded — there is nothing to simplify.
 */
function roundWeiForDisplay(wei, direction) {
  if (wei <= 0n) return wei;
  const digits = BigInt(wei.toString().length);
  const drop = digits > DISPLAY_SIGNIFICANT_DIGITS ? digits - DISPLAY_SIGNIFICANT_DIGITS : 0n;
  const divisor = 10n ** drop;
  const truncated = wei / divisor; // bigint division always truncates toward zero
  const remainder = wei % divisor;
  const kept = direction === "up" && remainder > 0n ? truncated + 1n : truncated;
  return kept * divisor;
}

// FIX-3 (review round 1, corrected review round 2) headroom for the
// floor-dominant funding suggestion below. The suggestion must never be
// `floor + 1n` — that is the exact balance a real transaction already
// failed at, so a user who tops up to it fails again by construction and
// the guidance never converges (executed proof: floor 270000000000000 ->
// "needs about 0.000270000000000001 testnet ETH", one wei above what the
// user already held).
//
// ROUND-2 CORRECTION. Round 1 used a flat `estCostWei * 2` and stopped
// there. That still never converges: it compares only against the live
// ESTIMATE, never against the FLOOR itself, so when fees drop between the
// recorded failure and the retry, the estimate can collapse well below what
// the floor already proved is required. Executed proof: floor 0.002 ETH
// fails, fees then drop 10x so the live estimate is 0.0002 ETH -> round 1
// suggested "about 0.0004 testnet ETH" — comfortably UNDER the ~0.002 ETH
// the floor proves is needed. The user funds to 0.0004, retries, the gate
// blocks immediately: the same non-convergence bug, just relocated from
// "one wei above the balance" to "a static 2x estimate decoupled from the
// floor". The round-1 test fixture happened to sit at only a 1.35x
// floor/estimate ratio, where `est*2` still cleared the floor by luck,
// which is why it didn't catch this.
//
// The fix: the suggestion must dominate BOTH inputs, so it is the larger of
// two independent terms — `estCostWei * 2` (unchanged) and
// `requiredAmountWei * 3/2 + 1n` (1.5x headroom over the floor, matching
// the relayer's own 1.5x drip-sizing buffer, this file's
// `APPROVE_SELL_GATE_GAS` derivation comment in Market.jsx; the `+1n`
// survives integer-division truncation at tiny magnitudes). The second term
// ALONE always exceeds `requiredAmountWei` for any positive value, so the
// max is unconditionally a genuine improvement over the disproven floor+1n
// regardless of which term wins.
const FLOOR_DOMINANT_ESTIMATE_MULTIPLIER = 2n;
const FLOOR_HEADROOM_NUMERATOR = 3n;
const FLOOR_HEADROOM_DENOMINATOR = 2n;

function maxBigint(a, b) {
  return a > b ? a : b;
}

/**
 * The have/need line. The app renders the wallet's native ETH balance nowhere
 * else (zero formatEther calls across desktop/src), so two shipped strings
 * already tell users to "add testnet ETH" with no way to see how short they
 * are. Empty string when nothing is short, so the caller can render
 * unconditionally.
 *
 * FLOOR-DOMINANT CASE (FIX-3, review round 1). Once a floor is recorded,
 * `requiredWei` returns `floor + 1n` — one wei above a balance a real
 * transaction already PROVED insufficient, not an estimate of what is
 * actually needed. `requiredAmountWei > estCostWei` is exactly that
 * condition (see `requiredWei`): est-dominant returns `est` itself, so
 * `requiredAmountWei` can only exceed `estCostWei` when the floor branch
 * fired. Printing "needs about {floor+1n}" there stated a disproven number
 * as the target: the user tops up to it, retries, fails identically, the
 * floor re-latches one wei higher, and the guidance never converges — a real
 * failed transaction every cycle. This branch instead says plainly that the
 * true requirement is MORE than the failed balance and not knowable from a
 * rejected transaction, and — only when a live estimate is actually usable
 * (`estCostWei > 0n`) — suggests a genuinely actionable funding target that
 * is the larger of an estimate-based term and a floor-based term (see
 * `FLOOR_HEADROOM_NUMERATOR`/`DENOMINATOR` above), never from `floor + 1n`
 * and never from the estimate alone (round 2: a live estimate can drop well
 * below the floor between the recorded failure and the retry).
 *
 * `estCostWei` defaults to `requiredAmountWei` (so it's never less than it),
 * which keeps existing 2-argument callers on exactly the pre-FIX-3,
 * non-floor-dominant rendering.
 *
 * DISPLAY ROUNDING (review round 3). The have-line (a real balance) is
 * rounded DOWN to `DISPLAY_SIGNIFICANT_DIGITS` — never overstate what the
 * wallet holds. The floor-dominant suggestion is rounded UP — never
 * understate a funding target (see `roundWeiForDisplay`). The plain
 * "needs about {requiredAmountWei}" line (this function's ORIGINAL,
 * non-floor-dominant branch) is left at full precision: `requiredWei`
 * returns the raw `est` unmodified there (no `floor + 1n` propagation), so
 * there is no addition artefact to round away, and an existing test
 * (`gasFloor.test.js`, "does not lose precision on values past
 * Number.MAX_SAFE_INTEGER") deliberately locks in exact rendering for it.
 */
export function formatTestEthShortfall(balanceWei, requiredAmountWei, estCostWei = requiredAmountWei) {
  if (balanceWei >= requiredAmountWei) return "";
  const have = `This wallet holds ${weiToTestEth(roundWeiForDisplay(balanceWei, "down"))} testnet ETH.`;
  if (requiredAmountWei <= estCostWei) {
    return `${have} This step needs about ${weiToTestEth(requiredAmountWei)} testnet ETH.`;
  }
  const honest = `${have} A previous attempt at this step already failed at that balance, so it needs more than that — the exact amount can't be measured from a rejected transaction.`;
  if (estCostWei <= 0n) return honest;
  const suggestionWei = maxBigint(
    estCostWei * FLOOR_DOMINANT_ESTIMATE_MULTIPLIER,
    (requiredAmountWei * FLOOR_HEADROOM_NUMERATOR) / FLOOR_HEADROOM_DENOMINATOR + 1n,
  );
  return `${honest} Funding to about ${weiToTestEth(roundWeiForDisplay(suggestionWei, "up"))} testnet ETH gives real headroom for this step.`;
}
