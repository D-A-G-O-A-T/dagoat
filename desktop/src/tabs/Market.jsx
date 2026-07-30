import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { zeroAddress } from "viem";
import { useNetwork } from "../components/NetworkSwitch.jsx";
import DeskTable from "../components/DeskTable.jsx";
import { getDeployment, isDeployed } from "../chain/addresses.js";
import { extractErrorName, getPublicClient, getWalletClient } from "../chain/client.js";
import { useActiveAccount } from "../chain/wallet.js";
import { runTx } from "../chain/tx.js";
import { rpcUnreachableHint } from "../chain/errors.js";
import { settledValues } from "../chain/safeAll.js";
import { useMountedRef } from "../lib/useMountedRef.js";
import { ensureEnrolled } from "../chain/enroll.js";
import {
  gasDripMessage,
  GAS_DRIP_SPENT_STILL_SHORT_COPY,
  requestGasDrip,
} from "../chain/gasDrip.js";
import {
  clearFloorForStep,
  clearFloorsForAddress,
  FLOOR_STEP_APPROVE_SELL,
  FLOOR_STEP_SELL,
  floorKey,
  formatTestEthShortfall,
  isInsufficientFundsError,
  readFloorWei,
  recordShortfallWei,
  requiredWei,
  runGatedTx,
} from "../chain/gasFloor.js";
import {
  BUY_DESK_ABI,
  BUY_DESK_FACTORY_ABI,
  ENROLLMENT_REGISTRY_ABI,
  GOAT_COIN_ABI,
  MOCK_USDT_ABI,
} from "../chain/abis.js";
import { WORK_UNIT_FORMULA } from "../chain/constants.js";
import {
  formatBid,
  formatCap,
  formatGoat,
  formatUsdt,
  parseGoat,
  parseUsdt,
  quoteUsdtOut,
  shortHash,
  testnetAmount,
} from "../chain/format.js";
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
} from "../market.js";
import { isTestnetWithMockUsdt } from "../opsAccess.js";

// Stream C T5: slower poll on public RPC (was 10s → ~6 desks * 5 reads ≈ heavy).
// ~3–4 refreshes/min/client instead of 6. In-flight guard skips overlapping ticks.
export const POLL_MS = 18_000;
const MAX_UINT256 = 2n ** 256n - 1n;
const IDLE = { status: "idle", message: "" };
/** Slider resolution: 0..SLIDER_STEPS maps to 0..maxSellable. */
const SLIDER_STEPS = 1000;

// --- Gas-drip preflight (Task 7, corrected P5) -------------------------------
// Per-step gas-unit thresholds. Split (not combined) because handleSellApprove
// and handleSell are reached at different points of the journey: the approve
// step still has both steps ahead of it, but by the time handleSell runs the
// approval is already on-chain, so only the sell's own gas is still owed.
//
// DERIVATION (corrected, review round 1 / FIX-4). Measured with
// `forge test --match-path test/BuyDeskFactory.t.sol --gas-report` in
// ../contracts: GoatCoin.approve 46,319 (unchanged) and BuyDesk.sell max
// 147,870 (3 calls).
//
// test/BuyDeskFactory.t.sol, NOT test/BuyDesk.t.sol, is the right file to
// measure sell from: BuyDesk.t.sol deploys a BuyDesk directly, but the app
// only ever sells to a desk chosen from the FACTORY's desk list
// (Market.jsx: `tx({ address: selectedDesk, ... functionName: "sell" })`,
// `selectedDesk` populated from `desks` via the factory read in `refresh`).
// The factory-created desk's sell max (147,870) is higher than a directly
// deployed one's (145,524, BuyDesk.t.sol) — confirmed the real user path, not
// a measurement artifact: the full suite total across every desk-creation
// path agrees exactly (`forge test --gas-report`, whole suite: BuyDesk.sell
// max 147,870 across 213 calls; InvariantsV2.t.sol alone: 145,536).
//
// Foundry's gas report is CALL-FRAME gas and EXCLUDES the 21,000 intrinsic
// transaction cost, so it must be added here. Proof from the same table: the
// view function `bid` reports 2,291 and `sell`'s minimum is 21,788 — neither is
// arithmetically possible if 21,000 intrinsic were already included, since a
// transaction cannot cost less than 21,000 and 21,788 leaves 788 gas, not even
// enough for one cold SLOAD. These are internal CALLs from the test contract,
// which never incur intrinsic gas.
//
//   approve = 46,319 + 21,000 + ~900 calldata  ~= 68,000
//   sell    = 147,870 + 21,000 + ~300 calldata ~= 169,200 -> rounded to 170,000
export const APPROVE_GAS = 68_000n;
export const SELL_GAS = 170_000n;

// Combined threshold for the approve entry point. NOT simply APPROVE_GAS +
// SELL_GAS (238,000, after FIX-4's SELL_GAS correction) — deliberately capped
// at what a single relayer drip can satisfy in the CLIENT's fee units. The
// relayer sizes its drip as (60k + 120k) * 3/2 = 270,000 gas-equivalents
// priced at legacy eth_gasPrice, while this gate prices at
// estimateFeesPerGas().maxFeePerGas, which viem derives as baseFee * 1.2 +
// tip — up to 1.2x higher. One drip is therefore worth at least
// 270,000 / 1.2 = 225,000 units here — unchanged by FIX-4, since it depends
// only on the untouched relayer DripConfig and the 1.2x viem/legacy-pricing
// ratio, neither of which moved. A gate above that could land a drip, still
// refuse, and leave the day's quota burned for nothing — manufacturing a dead
// end the current code does not have.
//
// Being 13,000 units under the honest combined need (238,000 - 225,000, was
// 10,000 before FIX-4) is safe because the sell gate is a SECOND, independent
// checkpoint: a wallet that clears this one, does the approve, and is then
// short for the sell simply gets its (still unused) drip at the sell gate.
// The residual is covered by the floor either way. Raising the relayer's
// DripConfig to 68k/170k would let this be a plain sum; that change was
// explicitly out of scope for this fix.
export const APPROVE_SELL_GATE_GAS = 225_000n;
const GAS_DRIP_POLL_INTERVAL_MS = 500;
const GAS_DRIP_POLL_TIMEOUT_MS = 15_000;

/**
 * Replaces viem's raw InsufficientFundsError sentence ("The total cost
 * (gas * gas fee + value) of executing this transaction exceeds the balance of
 * the account."), which today reaches the user with no explanation anywhere on
 * the pilot configuration — the one banner that explains it (EarningStatus.jsx)
 * only renders when the relayer URL is localhost. States plainly that nothing
 * was sent and nothing was spent, because the first fear on seeing a failed
 * sell is that something was lost.
 */
export const INSUFFICIENT_GAS_COPY =
  "This wallet doesn't hold enough testnet ETH for gas on this step, so no transaction was sent and nothing was spent. Testnet ETH only pays network fees.";

/** Balance unreadable AND this wallet has already failed here for gas. */
export const GAS_BALANCE_UNREADABLE_COPY =
  "Can't read this wallet's testnet ETH balance right now, and a previous attempt here ran short of gas — not sending a transaction that would fail the same way.";

/** Pure: does this wallet's ETH fall short of the estimated gas cost? Both in wei. */
export function needsGasDrip(ethBalanceWei, estCostWei) {
  return ethBalanceWei < estCostWei;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Preflight before an approve or sell tx: read ETH balance + a gas-price
 * estimate (both injected so this is unit-testable without viem/Tauri),
 * decide via `needsGasDrip`, and if short, request a gas-drip and poll
 * balance until it covers the estimated cost (bounded).
 *
 * Dependency-injected by design (see Miner.jsx's gating helpers for the
 * pattern this codebase already uses) — the real callers below wire in
 * publicClient/account/requestGasDrip; tests wire in fakes and assert the
 * branches directly.
 *
 * @param {{
 *   getBalance: () => Promise<bigint>,
 *   estimateFeePerGas: () => Promise<bigint>,
 *   requestDrip: (address: string) => Promise<object>,
 *   address: string,
 *   gasUnits: bigint,
 *   sleep?: (ms: number) => Promise<void>,
 *   pollIntervalMs?: number,
 *   pollTimeoutMs?: number,
 * }} deps
 * @returns {Promise<{ ok: boolean, message?: string }>}
 */
export async function ensureGasForSell({
  getBalance,
  estimateFeePerGas,
  requestDrip,
  address,
  gasUnits,
  floorWei = 0n,
  sleep: sleepFn = sleep,
  pollIntervalMs = GAS_DRIP_POLL_INTERVAL_MS,
  pollTimeoutMs = GAS_DRIP_POLL_TIMEOUT_MS,
}) {
  let ethBalance;
  try {
    ethBalance = await getBalance();
  } catch {
    // Can't read balance. With no floor recorded, don't block: the tx itself
    // will surface any real gas problem through the error mapping. With a
    // floor, an unreadable balance is NOT evidence of solvency — the last
    // observed state was insufficient and we cannot prove it changed, so
    // leaving this fail-open would reopen the exact silent loop being closed.
    if ((floorWei ?? 0n) > 0n) return { ok: false, message: GAS_BALANCE_UNREADABLE_COPY };
    return { ok: true };
  }

  let feePerGas = 0n;
  try {
    feePerGas = await estimateFeePerGas();
  } catch {
    // Caller's estimateFeePerGas already tries a getGasPrice fallback
    // (FIX-4) before this throws — both paths failed, so fall back to
    // self-pay (no gate) rather than blocking the sell on an estimate we
    // can't make; the tx itself will surface a real gas problem.
    feePerGas = 0n;
  }
  const estCostWei = (feePerGas ?? 0n) * gasUnits;
  // THE P5 FIX. `requiredWei` folds in the highest balance this (chain, wallet,
  // step) has been OBSERVED to fail at. At that balance the requirement is
  // strictly greater by construction, so the gate cannot report "you can pay
  // for this" at a balance already proven insufficient — no matter what the
  // constants say, whether the fee estimate collapsed to 0n, or how many times
  // the user clicks. With no floor recorded this is exactly the old value.
  const needWei = requiredWei(estCostWei, floorWei ?? 0n);

  // estCostWei rides along on every returned shape from here down (FIX-3,
  // review round 1): it is the one piece of information that lets a caller
  // tell a floor-dominant `needWei` (== floor+1n, a disproven balance) apart
  // from an estimate-dominant one, which formatTestEthShortfall needs to
  // avoid suggesting a funding target that is proven insufficient by
  // construction. See gasFloor.js formatTestEthShortfall.
  if (!needsGasDrip(ethBalance, needWei)) return { ok: true, haveWei: ethBalance, needWei, estCostWei };

  const res = await requestDrip(address);
  if (!(res.ok && res.status === 200)) {
    return { ok: false, message: gasDripMessage(res), haveWei: ethBalance, needWei, estCostWei };
  }

  // A 200 means the relayer already committed this wallet's daily quota
  // (reserve-before-send) and told us exactly what it sent. `amount_wei` is a
  // decimal STRING — values exceed Number.MAX_SAFE_INTEGER, so BigInt, never
  // Number. If the promised amount cannot cover the requirement, say so NOW
  // rather than polling for 15 seconds to reach the same conclusion and then
  // inviting a retry that will 429.
  let promised = null;
  try {
    if (res.amount_wei != null) promised = BigInt(res.amount_wei);
  } catch {
    promised = null; // unparseable — degrade to polling, not to a wrong answer
  }
  if (promised != null && ethBalance + promised < needWei) {
    return { ok: false, message: GAS_DRIP_SPENT_STILL_SHORT_COPY, haveWei: ethBalance, needWei, estCostWei };
  }

  const deadline = Date.now() + pollTimeoutMs;
  let lastSeen = ethBalance;
  while (Date.now() < deadline) {
    await sleepFn(pollIntervalMs);
    let balance;
    try {
      balance = await getBalance();
    } catch {
      balance = 0n;
    }
    if (balance > lastSeen) lastSeen = balance;
    // Compare against the actual requirement, not just "did it rise" — an
    // unrelated incoming transfer must not falsely count as the drip (FIX-3).
    if (balance >= needWei) return { ok: true, haveWei: balance, needWei, estCostWei };
  }
  // Timed out. We are only here after a 200, which means the relayer already
  // committed this wallet's daily allowance — so the old behaviour of reusing
  // the network-error copy ("couldn't reach the service") was simply false, and
  // the copy it used before that invited a retry that would 429. Whether or not
  // `amount_wei` parsed, the allowance is gone and the balance is still short.
  return { ok: false, message: GAS_DRIP_SPENT_STILL_SHORT_COPY, haveWei: lastSeen, needWei, estCostWei };
}

/**
 * Real fee-per-gas estimate for the gate above: prefer estimateFeesPerGas's
 * maxFeePerGas; if that throws, fall back to getGasPrice (legacy/simple
 * chains, or a transient EIP-1559 estimation hiccup); only if BOTH fail do
 * we return 0n, which makes `needsGasDrip` always false — i.e. the feature
 * silently disables into the pre-Task-7 self-pay behavior rather than
 * blocking a sell on an estimate we have no way to make (FIX-4).
 */
async function realEstimateFeePerGas(publicClient) {
  try {
    const fees = await publicClient.estimateFeesPerGas();
    if (fees?.maxFeePerGas != null) return fees.maxFeePerGas;
  } catch {
    // fall through to getGasPrice
  }
  try {
    const price = await publicClient.getGasPrice();
    if (price != null) return price;
  } catch {
    // both estimate paths failed — see function-level comment above.
  }
  return 0n;
}

// --- Floor-gated approve/sell wiring (FIX-2, review round 1) ----------------
// A 31-mutation run found the gate's PURE LOGIC well covered but its WIRING
// invisible: with the read-store -> gate -> write-on-shortfall ->
// clear-on-success sequence inline in handleSellApprove/handleSell, six
// one-line changes survived a fully green suite, and two (M31: drop the
// floor read; M30: drop the floor write) individually reopened the exact bug
// this file exists to fix. `desktop/` has no jsdom/@testing-library/react
// (only @vitejs/plugin-react + vitest) and none is added here, so no React
// handler can be rendered in a test. The fix is the same DI pattern that
// already makes `ensureGasForSell` testable without a DOM: pull the sequence
// out as a plain, injectable function and call it directly from a test.
//
// `step`/`gasUnits`/`clearOnSuccess` are deliberately NOT passed in from the
// two JSX call sites below — they are baked into the two exported wrappers.
// Passing them in from the handler is exactly the shape that let M33 (the
// approve call site using SELL_GAS) and M34 (the sell call site recording
// under the approve key) hide inside untestable handler code; baking the
// constant into a testable function turns "the call site passed the wrong
// constant" into "the function has the wrong constant", which a test can
// pin directly.
async function runFloorGatedStep({
  step,
  gasUnits,
  clearOnSuccess,
  networkId,
  address,
  publicClient,
  send,
  onShortfallMessage,
  readFloor = readFloorWei,
  recordShortfall = recordShortfallWei,
  requestDrip: requestDripFn = requestGasDrip,
  preflight = ensureGasForSell,
}) {
  const key = floorKey({ chainId: networkId, address: address ?? "", step });
  let need = 0n;
  let est = 0n;
  const outcome = await runGatedTx({
    preflight: async () => {
      if (!publicClient || !address) return { ok: true };
      const gate = await preflight({
        getBalance: () => publicClient.getBalance({ address }),
        estimateFeePerGas: () => realEstimateFeePerGas(publicClient),
        requestDrip: requestDripFn,
        address,
        gasUnits,
        // The floor is READ here, from the injected store lookup, not
        // hardcoded — this is the exact line M31 deleted (replaced with
        // `0n`, `ensureGasForSell`'s default), which turns the gate back
        // into a pure function of balance and reopens P5 verbatim.
        floorWei: readFloor(key),
      });
      need = gate.needWei ?? 0n;
      est = gate.estCostWei ?? 0n;
      return gate;
    },
    send,
    readBalance: () => publicClient.getBalance({ address }),
    onShortfall: (observed) => {
      // The exact line M30 deleted: with no write, the floor never latches
      // and the gate can pass at the same balance forever.
      recordShortfall(key, observed);
      onShortfallMessage?.(formatTestEthShortfall(observed, need, est));
    },
    onSuccess: () => clearOnSuccess({ chainId: networkId, address }),
  });
  if (!outcome.ok && outcome.gate) {
    // Reached only when the GATE itself blocked before any send was
    // attempted (daily limit, drip-spent-still-short, unreadable balance) —
    // mutually exclusive with the onShortfall branch above, which fires from
    // inside runGatedTx's catch when `send` itself throws.
    onShortfallMessage?.(formatTestEthShortfall(outcome.gate.haveWei ?? 0n, need, est));
  }
  return outcome;
}

/**
 * Approve entry point: both approve AND sell gas are still ahead, so the
 * gate uses the combined threshold (M33 pins `gasUnits` here). Success only
 * proves the approve step's OWN gas was affordable — it says nothing about
 * whether a later sell will be — so success clears only the approve floor,
 * never the sell floor. (Review round 1, "also": clearing both here silently
 * discarded proof that sell had already failed at the wallet's current
 * balance, reopening the bug for the very next sell click.)
 *
 * `clearFloorForStep` is injectable (defaults to the real gasFloor.js
 * function, module-scope store) — same reason `readFloor`/`recordShortfall`
 * are: a test can point the REAL clearing logic at a local, isolated store
 * instead of either duplicating it or touching the shared default store.
 */
export function runApproveGasGate({ clearFloorForStep: clearStep = clearFloorForStep, ...deps }) {
  return runFloorGatedStep({
    ...deps,
    step: FLOOR_STEP_APPROVE_SELL,
    gasUnits: APPROVE_SELL_GATE_GAS,
    clearOnSuccess: ({ chainId, address }) => clearStep({ chainId, address, step: FLOOR_STEP_APPROVE_SELL }),
  });
}

/**
 * Sell entry point: only the sell's own gas is still owed (M34 pins `step`
 * here — recording under the wrong key would silently protect the wrong
 * step). A successful sell ends one full trade cycle, so clearing every
 * step's floor for this wallet on success is unchanged from the original
 * design. `clearFloorsForAddress` is injectable for the same reason as above.
 */
export function runSellGasGate({ clearFloorsForAddress: clearAll = clearFloorsForAddress, ...deps }) {
  return runFloorGatedStep({
    ...deps,
    step: FLOOR_STEP_SELL,
    gasUnits: SELL_GAS,
    clearOnSuccess: ({ chainId, address }) => clearAll({ chainId, address }),
  });
}

const ERROR_COPY = {
  TransferRestricted:
    "Transfer blocked: both addresses must be enrolled (use the Enroll myself button on this page, or founder enroll) — GoatCoin reverted with TransferRestricted.",
  NotEnrolled: "That desk owner is not enrolled — they must enroll (or the founder must enroll them) before selling.",
  NoActiveSession: "No trade session open on that desk.",
  CapExceeded: "That amount would exceed the per-account cap for this trade session.",
  ZeroPayout: "That amount is too small — it would pay out 0 USDT at the current bid.",
  OwnerCannotSell: "You can't sell to your own desk — pick another donor's desk.",
  // Ambiguous without context: sell() can revert InsufficientBalance on GOAT (seller)
  // or USDT (desk owner). Prefer client pre-checks; this is the owner-USDT residual.
  ERC20InsufficientBalance: SELL_INSUFFICIENT_OWNER_USDT_COPY,
  ERC20InsufficientAllowance:
    "This desk's cap is used up (or not set) — its owner needs to raise the cap before it can buy more GOAT.",
  NotOwner: "This key is not that desk's owner.",
  AlreadyHasDesk: "This wallet already has a desk — see My desk on this page.",
  NoDesk: "This wallet doesn't have a desk yet — open one first.",
  ZeroAddress: "Zero address is not a valid desk owner.",
};

export function friendlyError(err, networkId, sellCtx = null) {
  const hint = rpcUnreachableHint(err, networkId);
  if (hint) return hint;
  // Node-level "can't afford the gas" — checked before the raw-string
  // fallthrough. Precedent: chain/enroll.js:69 already maps this exact
  // viem string one directory over.
  if (isInsufficientFundsError(err)) return INSUFFICIENT_GAS_COPY;
  const name = extractErrorName(err);
  // Disambiguate ERC20InsufficientBalance: sell() does GOAT transferFrom first.
  if (name === "ERC20InsufficientBalance" && sellCtx) {
    const { sellWei, myGoatBalance } = sellCtx;
    if (sellWei != null && myGoatBalance != null && sellWei > myGoatBalance) {
      return SELL_INSUFFICIENT_GOAT_COPY;
    }
  }
  if (name && ERROR_COPY[name]) return ERROR_COPY[name];
  return err?.shortMessage || err?.message || String(err);
}

export default function Market() {
  const { networkId, network } = useNetwork();
  const deployment = getDeployment(networkId);
  const deployed = isDeployed(networkId) && Boolean(deployment?.buyDeskFactory);

  // The active Rust-backed account (or null) — re-renders on unlock/lock/switch
  // in the Wallet tab. Signing happens in Rust; the key is never in JS.
  const account = useActiveAccount();

  const address = account?.address ?? null;

  const publicClient = useMemo(() => {
    try {
      return getPublicClient(networkId);
    } catch {
      return null;
    }
  }, [networkId]);

  const walletClient = useMemo(() => {
    try {
      return getWalletClient(networkId, account);
    } catch {
      return null;
    }
  }, [networkId, account]);

  async function tx({ address: contractAddress, abi, functionName, args }) {
    return runTx({ publicClient, walletClient, account, address: contractAddress, abi, functionName, args });
  }

  const [desks, setDesks] = useState([]);
  const [myDeskAddress, setMyDeskAddress] = useState(null);
  const [enrolled, setEnrolled] = useState(null);
  // True only when the connected wallet is the registry's founder/safe address.
  // Desk depth is shown only to a desk's own owner (My desk panel) and to the
  // founder (debug) — never on the public list (founder direction 2026-07-13).
  const [isFounder, setIsFounder] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [lastRefreshed, setLastRefreshed] = useState(null);
  /** Stream C T5: skip overlapping poll ticks (slow public RPC). */
  const refreshInflight = useRef(false);
  /** Consultant hazard: do not setState after tab unmount. */
  const mounted = useMountedRef();

  const refresh = useCallback(async () => {
    if (!publicClient || !deployed) return;
    if (refreshInflight.current) return;
    refreshInflight.current = true;
    if (mounted.current) {
      setLoading(true);
      setLoadError("");
    }
    try {
      const length = await publicClient.readContract({
        address: deployment.buyDeskFactory,
        abi: BUY_DESK_FACTORY_ABI,
        functionName: "desksLength",
      });
      const indices = Array.from({ length: Number(length) }, (_, i) => BigInt(i));
      // Partial failure OK: one desks(i) 429 must not blank the whole list.
      const deskAddresses = await settledValues(
        indices.map((i) =>
          publicClient.readContract({
            address: deployment.buyDeskFactory,
            abi: BUY_DESK_FACTORY_ABI,
            functionName: "desks",
            args: [i],
          }),
        ),
      );
      const rows = await settledValues(
        deskAddresses.map(async (deskAddress) => {
          const fields = await settledValues([
            publicClient.readContract({ address: deskAddress, abi: BUY_DESK_ABI, functionName: "owner" }),
            publicClient.readContract({ address: deskAddress, abi: BUY_DESK_ABI, functionName: "bid" }),
            publicClient.readContract({ address: deskAddress, abi: BUY_DESK_ABI, functionName: "depth" }),
            publicClient.readContract({
              address: deskAddress,
              abi: BUY_DESK_ABI,
              functionName: "currentSession",
            }),
          ]);
          if (fields.length < 4) return undefined;
          const [owner, bid, depth, sessionRaw] = fields;
          let name = "";
          try {
            name = await publicClient.readContract({
              address: deployment.buyDeskFactory,
              abi: BUY_DESK_FACTORY_ABI,
              functionName: "nameOf",
              args: [owner],
            });
          } catch {
            name = "";
          }
          return buildDeskRow({ address: deskAddress, owner, name, bid, depth, sessionRaw });
        }),
      );
      if (!mounted.current) return;
      setDesks(sortDesksByBestBid(rows.filter(Boolean)));

      if (address) {
        const walletReads = await settledValues([
          publicClient.readContract({
            address: deployment.buyDeskFactory,
            abi: BUY_DESK_FACTORY_ABI,
            functionName: "deskOf",
            args: [address],
          }),
          publicClient.readContract({
            address: deployment.enrollmentRegistry,
            abi: ENROLLMENT_REGISTRY_ABI,
            functionName: "enrolled",
            args: [address],
          }),
          publicClient.readContract({
            address: deployment.enrollmentRegistry,
            abi: ENROLLMENT_REGISTRY_ABI,
            functionName: "safe",
          }),
        ]);
        if (!mounted.current) return;
        const myDesk = walletReads[0];
        const isEnrolled = walletReads[1];
        const safeAddress = walletReads[2];
        setMyDeskAddress(myDesk && myDesk.toLowerCase() !== zeroAddress ? myDesk : null);
        if (typeof isEnrolled === "boolean") setEnrolled(isEnrolled);
        if (safeAddress) setIsFounder(safeAddress?.toLowerCase() === address.toLowerCase());
      } else if (mounted.current) {
        setMyDeskAddress(null);
        setEnrolled(null);
        setIsFounder(false);
      }
      if (mounted.current) setLastRefreshed(new Date());
    } catch (err) {
      if (mounted.current) setLoadError(friendlyError(err, networkId));
    } finally {
      refreshInflight.current = false;
      if (mounted.current) setLoading(false);
    }
  }, [publicClient, deployed, deployment, address, networkId, mounted]);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, POLL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  const myDeskRow = useMemo(
    () => desks.find((d) => myDeskAddress && d.address.toLowerCase() === myDeskAddress.toLowerCase()) ?? null,
    [desks, myDeskAddress]
  );
  const bestOpenAddress = useMemo(() => pickDefaultDesk(desks, null)?.address ?? null, [desks]);

  // --- Sell panel -----------------------------------------------------------
  const [selectedDesk, setSelectedDesk] = useState("");
  useEffect(() => {
    const stillValid = desks.some((d) => d.address === selectedDesk && !isOwnDesk(d, address));
    if (stillValid) return;
    const def = pickDefaultDesk(desks, address);
    setSelectedDesk(def ? def.address : "");
  }, [desks, address, selectedDesk]);

  const [sellAmount, setSellAmount] = useState("");
  const [sellAllowance, setSellAllowance] = useState(0n);
  const [myGoatBalance, setMyGoatBalance] = useState(0n);
  const [sellState, setSellState] = useState(IDLE);
  // Have/need line in testnet ETH, shown only while a gas shortfall is live.
  // The app renders the wallet's native ETH balance nowhere else, so the two
  // shipped strings that say "send testnet ETH" were previously impossible to
  // act on from inside the product.
  const [sellGasNote, setSellGasNote] = useState("");
  const sellWei = parseGoat(sellAmount);
  const sellRow = desks.find((d) => d.address === selectedDesk) ?? null;
  const maxSellable = useMemo(
    () =>
      maxSellableGoatWei({
        goatBalance: myGoatBalance,
        bid: sellRow?.bid ?? 0n,
        depth: sellRow?.depth ?? 0n,
        sessionCap: sellRow?.session?.cap ?? null,
      }),
    [myGoatBalance, sellRow],
  );
  const sellNeedsApproval = Boolean(account) && sellWei > 0n && sellAllowance < sellWei;
  const sellExceedsGoat = sellWei > myGoatBalance;
  const sellExceedsMax = maxSellable > 0n && sellWei > maxSellable;
  // Slider position 0..SLIDER_STEPS for current sell amount vs max.
  let sellSlider = 0;
  if (maxSellable > 0n) {
    const raw = (sellWei * BigInt(SLIDER_STEPS)) / maxSellable;
    sellSlider = Number(raw > BigInt(SLIDER_STEPS) ? BigInt(SLIDER_STEPS) : raw);
  }

  function setSellFromWei(wei) {
    const clamped = wei < 0n ? 0n : maxSellable > 0n && wei > maxSellable ? maxSellable : wei;
    // Avoid scientific notation; formatGoat is fine for display.
    setSellAmount(clamped === 0n ? "" : formatGoat(clamped));
  }

  useEffect(() => {
    let cancelled = false;
    if (!publicClient || !deployed || !account?.address || !selectedDesk) {
      setSellAllowance(0n);
      return;
    }
    publicClient
      .readContract({
        address: deployment.goatCoin,
        abi: GOAT_COIN_ABI,
        functionName: "allowance",
        args: [account.address, selectedDesk],
      })
      .then((value) => {
        if (!cancelled) setSellAllowance(value);
      })
      .catch(() => {
        if (!cancelled) setSellAllowance(0n);
      });
    return () => {
      cancelled = true;
    };
  }, [publicClient, deployed, deployment, account, selectedDesk, lastRefreshed]);

  useEffect(() => {
    let cancelled = false;
    if (!publicClient || !deployed || !account?.address) {
      setMyGoatBalance(0n);
      return;
    }
    publicClient
      .readContract({
        address: deployment.goatCoin,
        abi: GOAT_COIN_ABI,
        functionName: "balanceOf",
        args: [account.address],
      })
      .then((value) => {
        if (!cancelled) setMyGoatBalance(value);
      })
      .catch(() => {
        if (!cancelled) setMyGoatBalance(0n);
      });
    return () => {
      cancelled = true;
    };
  }, [publicClient, deployed, deployment, account, lastRefreshed]);

  async function handleSellApprove(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment || !selectedDesk) return;
    setSellState({ status: "pending", message: "" });
    setSellGasNote("");
    try {
      if (sellWei === 0n) throw new Error("Enter an amount greater than 0.");
      if (sellExceedsGoat) throw new Error(SELL_INSUFFICIENT_GOAT_COPY);
      // Approve is reached first: both the approve AND the sell gas are
      // still ahead of this wallet.
      //
      // KNOWN OPEN GAP (review round 2): this call site itself — which of
      // `runApproveGasGate`/`runSellGasGate` gets invoked here — is
      // untested. A verifier swapped this for `runSellGasGate` and the
      // suite stayed fully green (it under-gates approve to SELL_GAS
      // instead of APPROVE_SELL_GATE_GAS, mis-keys the shortfall under the
      // sell step, and clears the sell floor on a mere approve success).
      // `desktop/` has no jsdom/@testing-library/react, so no test can
      // render this component and assert what a click handler calls; that
      // is a real limit of the current toolchain, not something another
      // layer of indirection can fix (routing through a shared
      // `runGasGate(step, ...)` would only relocate the same untestable
      // swap to the `step` argument). Closing this needs `jsdom` +
      // `@testing-library/react` as devDependencies — a `package.json`
      // change, and therefore the founder's decision under the commit
      // freeze, not made here. Everything BELOW this call site (the gate's
      // pure logic and its read-store/write/clear wiring) IS covered — see
      // `runApproveGasGate`'s own tests in Market.test.js.
      const outcome = await runApproveGasGate({
        networkId,
        address: account.address,
        publicClient,
        send: () =>
          tx({ address: deployment.goatCoin, abi: GOAT_COIN_ABI, functionName: "approve", args: [selectedDesk, sellWei] }),
        onShortfallMessage: setSellGasNote,
      });
      if (!outcome.ok) {
        setSellState({ status: "error", message: outcome.gate.message });
        return;
      }
      setSellState({ status: "idle", message: "Approved (testnet). You can sell now." });
      refresh();
    } catch (err) {
      setSellState({
        status: "error",
        message: err?.message === SELL_INSUFFICIENT_GOAT_COPY ? err.message : friendlyError(err, networkId, { sellWei, myGoatBalance }),
      });
    }
  }

  async function handleSell(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment || !selectedDesk) return;
    setSellState({ status: "pending", message: "" });
    setSellGasNote("");
    try {
      if (sellWei === 0n) throw new Error("Enter an amount greater than 0.");
      if (sellExceedsGoat) throw new Error(SELL_INSUFFICIENT_GOAT_COPY);
      if (sellExceedsMax) {
        throw new Error(
          "That amount is above what this desk can pay (depth / session limit) — use the slider or Max.",
        );
      }
      // handleSell is only ever reached once the allowance is already in
      // place (either it always was, or handleSellApprove already landed) —
      // only the sell's own gas is still owed (FIX-1, Task 7 numbering).
      //
      // KNOWN OPEN GAP (review round 2): same untested dispatch point as
      // handleSellApprove above — see that call site's comment for the full
      // explanation. Swapping this for `runApproveGasGate` is equally
      // undetectable by the current suite. Closing it needs `jsdom` +
      // `@testing-library/react` as devDependencies (a founder decision
      // under the commit freeze), not attempted here.
      const outcome = await runSellGasGate({
        networkId,
        address: account.address,
        publicClient,
        send: () => tx({ address: selectedDesk, abi: BUY_DESK_ABI, functionName: "sell", args: [sellWei] }),
        onShortfallMessage: setSellGasNote,
      });
      if (!outcome.ok) {
        setSellState({ status: "error", message: outcome.gate.message });
        return;
      }
      setSellState({ status: "success", message: `Sold (testnet). Tx ${shortHash(outcome.result)}` });
      setSellAmount("");
      refresh();
    } catch (err) {
      const msg =
        typeof err?.message === "string" &&
        (err.message === SELL_INSUFFICIENT_GOAT_COPY || err.message.includes("slider"))
          ? err.message
          : friendlyError(err, networkId, { sellWei, myGoatBalance });
      setSellState({ status: "error", message: msg });
    }
  }

  // --- Open my buy desk -------------------------------------------------------
  const [deskNameInput, setDeskNameInput] = useState("");
  const [createState, setCreateState] = useState(IDLE);
  async function handleCreateDesk(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment || enrolled !== true) return;
    setCreateState({ status: "pending", message: "" });
    try {
      const hash = await tx({
        address: deployment.buyDeskFactory,
        abi: BUY_DESK_FACTORY_ABI,
        functionName: "createDesk",
        args: [deskNameInput.trim()],
      });
      setCreateState({ status: "success", message: `Desk opened (testnet). Tx ${shortHash(hash)}` });
      setDeskNameInput("");
      refresh();
    } catch (err) {
      setCreateState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  // --- My desk: cap (allowance-based buying power) ------------------------------
  // Depth = the desk's USDT allowance FROM the owner (see BuyDesk.depth()), so
  // the desk's current cap is just myDeskRow.depth — no separate read. We only
  // read the owner's own wallet USDT so the panel can warn when the wallet
  // can't actually cover the committed cap (spec §3, honest residue).
  // USDT tools (faucet) live here for donors only — worker Wallet tab is GOAT-only.
  const [capAmount, setCapAmount] = useState("");
  const [myUsdtBalance, setMyUsdtBalance] = useState(0n);
  const [capState, setCapState] = useState(IDLE);
  const [faucetAmount, setFaucetAmount] = useState("1000");
  const [faucetState, setFaucetState] = useState(IDLE);
  const currentCap = myDeskRow?.depth ?? 0n;
  const showDonorUsdtFaucet =
    isTestnetWithMockUsdt(networkId) && Boolean(deployment?.mockUSDT) && Boolean(myDeskAddress);

  async function handleDonorFaucet(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment?.mockUSDT) return;
    setFaucetState({ status: "pending", message: "" });
    try {
      const amount = parseUsdt(faucetAmount);
      if (amount === 0n) throw new Error("Enter an amount greater than 0.");
      const hash = await tx({
        address: deployment.mockUSDT,
        abi: MOCK_USDT_ABI,
        functionName: "mint",
        args: [account.address, amount],
      });
      setFaucetState({ status: "success", message: `Minted (testnet). Tx ${shortHash(hash)}` });
      refresh();
    } catch (err) {
      setFaucetState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  useEffect(() => {
    let cancelled = false;
    if (!publicClient || !deployed || !account?.address || !myDeskAddress) {
      setMyUsdtBalance(0n);
      return;
    }
    publicClient
      .readContract({
        address: deployment.mockUSDT,
        abi: MOCK_USDT_ABI,
        functionName: "balanceOf",
        args: [account.address],
      })
      .then((balance) => {
        if (!cancelled) setMyUsdtBalance(balance);
      })
      .catch(() => {
        if (!cancelled) setMyUsdtBalance(0n);
      });
    return () => {
      cancelled = true;
    };
  }, [publicClient, deployed, deployment, account, myDeskAddress, lastRefreshed]);

  // Set the desk's cap = approve this much of your wallet USDT to the desk.
  // ONE transaction; the desk never custodies funds. Raising or lowering the
  // cap is the same call with a new amount.
  async function handleSetCap(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment || !myDeskAddress) return;
    setCapState({ status: "pending", message: "" });
    try {
      const amount = parseUsdt(capAmount);
      if (amount === 0n) throw new Error("Enter a cap greater than 0 — use Close desk to set it to 0.");
      const hash = await tx({ address: deployment.mockUSDT, abi: MOCK_USDT_ABI, functionName: "approve", args: [myDeskAddress, amount] });
      setCapState({ status: "success", message: `Cap set (testnet). Tx ${shortHash(hash)}` });
      setCapAmount("");
      refresh();
    } catch (err) {
      setCapState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  // Close the desk = approve(desk, 0): buying power drops to 0 immediately.
  // Your USDT never left your wallet, so there is nothing to withdraw.
  async function handleCloseDesk() {
    if (!walletClient || !account || !deployment || !myDeskAddress) return;
    setCapState({ status: "pending", message: "" });
    try {
      const hash = await tx({ address: deployment.mockUSDT, abi: MOCK_USDT_ABI, functionName: "approve", args: [myDeskAddress, 0n] });
      setCapState({ status: "success", message: `Desk closed — cap set to 0 (testnet). Tx ${shortHash(hash)}` });
      refresh();
    } catch (err) {
      setCapState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  // --- My desk: bid --------------------------------------------------------------
  const [bidAmount, setBidAmount] = useState("");
  const [bidState, setBidState] = useState(IDLE);
  async function handleSetBid(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment || !myDeskAddress) return;
    setBidState({ status: "pending", message: "" });
    try {
      const hash = await tx({ address: myDeskAddress, abi: BUY_DESK_ABI, functionName: "setBid", args: [parseUsdt(bidAmount)] });
      setBidState({ status: "success", message: `Bid updated (testnet). Tx ${shortHash(hash)}` });
      setBidAmount("");
      refresh();
    } catch (err) {
      setBidState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  // --- My desk: session -----------------------------------------------------------
  const [sessionMinutes, setSessionMinutes] = useState("60");
  const [sessionCap, setSessionCap] = useState("");
  const [sessionState, setSessionState] = useState(IDLE);
  async function handleOpenSession(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment || !myDeskAddress) return;
    setSessionState({ status: "pending", message: "" });
    try {
      const minutes = Number(sessionMinutes);
      if (!Number.isFinite(minutes) || minutes <= 0) throw new Error("Enter a duration greater than 0 minutes.");
      if (currentCap === 0n) throw new Error("Set a desk cap first — a session with no buying power can't pay any seller.");
      const start = BigInt(Math.floor(Date.now() / 1000));
      const end = start + BigInt(Math.round(minutes * 60));
      const cap = sessionCap.trim() === "" ? MAX_UINT256 : parseGoat(sessionCap);
      const hash = await tx({ address: myDeskAddress, abi: BUY_DESK_ABI, functionName: "openSession", args: [start, end, cap] });
      setSessionState({ status: "success", message: `Session opened (testnet). Tx ${shortHash(hash)}` });
      refresh();
    } catch (err) {
      setSessionState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  async function handleCloseSession() {
    if (!walletClient || !account || !deployment || !myDeskAddress) return;
    setSessionState({ status: "pending", message: "" });
    try {
      const hash = await tx({ address: myDeskAddress, abi: BUY_DESK_ABI, functionName: "closeSession", args: [] });
      setSessionState({ status: "success", message: `Session closed (testnet). Tx ${shortHash(hash)}` });
      refresh();
    } catch (err) {
      setSessionState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  // --- My desk: rename -----------------------------------------------------------
  const [renameInput, setRenameInput] = useState("");
  const [renameState, setRenameState] = useState(IDLE);
  async function handleRename(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment) return;
    setRenameState({ status: "pending", message: "" });
    try {
      const hash = await tx({
        address: deployment.buyDeskFactory,
        abi: BUY_DESK_FACTORY_ABI,
        functionName: "setDeskName",
        args: [renameInput.trim()],
      });
      setRenameState({ status: "success", message: `Renamed (testnet). Tx ${shortHash(hash)}` });
      setRenameInput("");
      refresh();
    } catch (err) {
      setRenameState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  if (!deployed) {
    return (
      <section className="tab-panel">
        <h2 className="page-title">Market</h2>
        <p className="placeholder-note">
          {network?.name ?? `Chain ${networkId}`} has no BuyDesk factory deployed yet.
          {deployment?.note ? ` ${deployment.note}` : ""}
        </p>
      </section>
    );
  }

  return (
    <section className="tab-panel wallet-tab market-tab">
      <h2 className="page-title">Market</h2>
      <p className="required-copy">{NOT_EXCHANGE_COPY}</p>

      <div className="wallet-section">
        <div className="wallet-section-header">
          <h3>Buy desks</h3>
          <div className="wallet-actions-row">
            <button type="button" onClick={refresh} disabled={loading}>
              {loading ? "Refreshing…" : "Refresh"}
            </button>
            {lastRefreshed && <span className="muted">Updated {lastRefreshed.toLocaleTimeString()}</span>}
          </div>
        </div>
        {loadError && <p className="error-text">{loadError}</p>}
        <DeskTable rows={desks} myAddress={address} bestOpenAddress={bestOpenAddress} showDepth={isFounder} />
      </div>

      <div className="market-two-col">
        <div className="wallet-section market-col">
        <h3>Sell GOAT</h3>
        <p className="required-copy">{HOLD_NOTICE_COPY}</p>
        {!account ? (
          <p className="placeholder-note">Import a key in the Wallet tab to sell.</p>
        ) : desks.length === 0 ? (
          <p className="placeholder-note">No buy desks yet — nothing to sell to.</p>
        ) : (
          <>
            <div className="wallet-form">
              <select value={selectedDesk} onChange={(e) => setSelectedDesk(e.target.value)}>
                <option value="" disabled>
                  Choose a desk…
                </option>
                {desks.map((row) => {
                  const mine = isOwnDesk(row, address);
                  return (
                    <option key={row.address} value={row.address} disabled={mine}>
                      {row.displayName} — 1 GOAT = {formatBid(row.bid)} USDT
                      {row.isOpen ? "" : " (closed)"}
                      {mine ? " (your desk)" : ""}
                    </option>
                  );
                })}
              </select>
            </div>
            {sellRow && (
              <dl className="balance-grid">
                <dt>Your GOAT (wallet)</dt>
                <dd>{testnetAmount(formatGoat(myGoatBalance), "GOAT")}</dd>
                <dt>Max sellable here</dt>
                <dd>
                  {testnetAmount(formatGoat(maxSellable), "GOAT")} — limited by your balance, desk
                  USDT depth, and session cap
                </dd>
                <dt>Posted bid</dt>
                <dd>
                  1 GOAT = {testnetAmount(formatBid(sellRow.bid), "USDT")} — {POSTED_BID_COPY}
                </dd>
                {isFounder && (
                  <>
                    <dt>Desk depth</dt>
                    <dd>{testnetAmount(formatUsdt(sellRow.depth), "USDT")} (founder debug)</dd>
                  </>
                )}
                <dt>Session</dt>
                <dd>{sellRow.isOpen ? `Open (#${sellRow.session.id.toString()})` : "No trade session open."}</dd>
                {sellRow.isOpen && (
                  <>
                    <dt>Session per-seller cap</dt>
                    <dd>{formatCap(sellRow.session.cap)}</dd>
                  </>
                )}
              </dl>
            )}
            {sellRow && sellRow.depth === 0n && (
              <p className="placeholder-note">
                Desk is empty — public good already delivered; new buyers add liquidity.
              </p>
            )}
            {sellExceedsGoat && sellWei > 0n && (
              <p className="error-text" role="alert">
                {SELL_INSUFFICIENT_GOAT_COPY}
              </p>
            )}
            <form className="wallet-form sell-form" onSubmit={sellNeedsApproval ? handleSellApprove : handleSell}>
              <label className="muted" htmlFor="sell-slider">
                Amount (0 → max sellable)
              </label>
              <input
                id="sell-slider"
                type="range"
                className="sell-slider"
                min={0}
                max={SLIDER_STEPS}
                step={1}
                value={Number.isFinite(sellSlider) ? sellSlider : 0}
                disabled={!account || !selectedDesk || maxSellable <= 0n}
                onChange={(e) => {
                  const step = BigInt(e.target.value);
                  if (maxSellable <= 0n || step <= 0n) {
                    setSellAmount("");
                    return;
                  }
                  setSellFromWei((maxSellable * step) / BigInt(SLIDER_STEPS));
                }}
              />
              <div className="wallet-actions-row">
                <input
                  type="text"
                  placeholder="Amount (GOAT)"
                  value={sellAmount}
                  onChange={(e) => setSellAmount(e.target.value)}
                  disabled={!account || !selectedDesk}
                  aria-invalid={sellExceedsGoat || sellExceedsMax}
                />
                <button
                  type="button"
                  disabled={!account || !selectedDesk || maxSellable <= 0n}
                  onClick={() => setSellFromWei(maxSellable)}
                >
                  Max
                </button>
              </div>
              <button
                type="submit"
                disabled={
                  !account ||
                  !selectedDesk ||
                  sellWei === 0n ||
                  !sellRow?.isOpen ||
                  sellRow?.depth === 0n ||
                  sellExceedsGoat ||
                  sellExceedsMax ||
                  sellState.status === "pending"
                }
              >
                {sellState.status === "pending"
                  ? sellNeedsApproval
                    ? "Approving…"
                    : "Selling…"
                  : sellNeedsApproval
                    ? "Approve GOAT"
                    : "Sell"}
              </button>
            </form>
            {sellWei > 0n && sellRow && (
              <p className="muted">
                You would receive ~{testnetAmount(formatUsdt(quoteUsdtOut(sellWei, sellRow.bid)), "USDT")}{" "}
                (sell proceeds — GOAT is minted for verified public-good work; USDT only arrives when
                you sell it here).
              </p>
            )}
            {sellState.message && (
              <p className={sellState.status === "error" ? "error-text" : "status-ok"}>{sellState.message}</p>
            )}
            {sellGasNote && (
              <p className="muted">
                {sellGasNote} Wallet: <code>{account?.address}</code>
              </p>
            )}
          </>
        )}
        </div>

        <div className="wallet-section market-col">
        <h3>{myDeskAddress ? "My desk" : "Be a donor"}</h3>
        {!account ? (
          <p className="placeholder-note">Import a key in the Wallet tab to become a donor.</p>
        ) : myDeskAddress ? (
          <>
            <p className="muted">
              Desk: <code>{myDeskAddress}</code>
            </p>
            {enrolled === false && <p className="status-warn">{ENROLLMENT_WARNING_COPY}</p>}
            <dl className="balance-grid">
              <dt>Desk cap (buying power)</dt>
              <dd>
                {testnetAmount(formatUsdt(currentCap), "USDT")} — USDT you’ve committed to this desk.
                Shrinks as GOAT is bought.
              </dd>
              <dt>Your wallet USDT</dt>
              <dd>
                {testnetAmount(formatUsdt(myUsdtBalance), "USDT")} — stays in your wallet; keep it ≥ your
                cap so sells clear
              </dd>
              <dt>Posted bid</dt>
              <dd>
                1 GOAT = {testnetAmount(formatBid(myDeskRow?.bid ?? 0n), "USDT")} — {POSTED_BID_COPY}
              </dd>
              <dt>Session</dt>
              <dd>
                {myDeskRow?.isOpen
                  ? `Open (#${myDeskRow.session.id.toString()}) until ${new Date(Number(myDeskRow.session.end) * 1000).toLocaleString()}`
                  : "No trade session open."}
              </dd>
              {myDeskRow?.isOpen && (
                <>
                  <dt>Per-seller sell limit</dt>
                  <dd>
                    {formatCap(myDeskRow.session.cap)} — the most GOAT any one seller can sell you this
                    session. A GOAT limit, separate from your desk cap. Blank when opening = no limit.
                  </dd>
                </>
              )}
            </dl>
            {currentCap === 0n && (
              <p className="status-warn">
                Your desk cap is 0, so it has no buying power and sellers can’t sell to it yet. Set a cap
                below — that approves some of your wallet USDT (you hold{" "}
                {testnetAmount(formatUsdt(myUsdtBalance), "USDT")}) for the desk to spend. Your USDT stays
                in your wallet until someone actually sells to you.
              </p>
            )}

            {showDonorUsdtFaucet && (
              <div className="wallet-form-block">
                <p className="muted">
                  <strong>Donor only</strong> — MockUSDT faucet (testnet). Workers never need USDT in
                  Wallet; GOAT is minted to them for verified public-good work, then sold on this
                  Market. Mint test USDT here to fund your desk cap.
                </p>
                <form className="wallet-form" onSubmit={handleDonorFaucet}>
                  <input
                    type="text"
                    placeholder="Amount (USDT)"
                    value={faucetAmount}
                    onChange={(e) => setFaucetAmount(e.target.value)}
                    disabled={!account}
                  />
                  <button type="submit" disabled={!account || faucetState.status === "pending"}>
                    {faucetState.status === "pending" ? "Minting…" : "MockUSDT faucet (testnet)"}
                  </button>
                </form>
                {faucetState.message && (
                  <p className={faucetState.status === "error" ? "error-text" : "status-ok"}>
                    {faucetState.message}
                  </p>
                )}
              </div>
            )}

            <div className="wallet-form-block">
              <p className="muted">
                Set your desk cap — commit up to this much of your <strong>wallet</strong> USDT as buying
                power. One step, no funding: your USDT stays in your wallet until someone sells to you.
                Enter a new amount anytime to raise or lower it.
              </p>
              <form className="wallet-form" onSubmit={handleSetCap}>
                <input
                  type="text"
                  placeholder="Cap (USDT)"
                  value={capAmount}
                  onChange={(e) => setCapAmount(e.target.value)}
                  disabled={!account}
                />
                <button type="submit" disabled={!account || capState.status === "pending"}>
                  {capState.status === "pending" ? "Setting…" : "Set cap"}
                </button>
              </form>
              <div className="wallet-actions-row">
                <button
                  type="button"
                  onClick={handleCloseDesk}
                  disabled={!account || currentCap === 0n || capState.status === "pending"}
                >
                  Close desk (cap → 0)
                </button>
              </div>
              {capState.message && (
                <p className={capState.status === "error" ? "error-text" : "status-ok"}>{capState.message}</p>
              )}
            </div>

            <div className="wallet-form-block">
              <p className="muted">
                Set your bid — {POSTED_BID_COPY}; never retroactive. USDT (6dp) per 1 GOAT, e.g. 0.01 = 10000 raw
                units.
              </p>
              <form className="wallet-form" onSubmit={handleSetBid}>
                <input
                  type="text"
                  placeholder="Bid (USDT per GOAT)"
                  value={bidAmount}
                  onChange={(e) => setBidAmount(e.target.value)}
                  disabled={!account}
                />
                <button type="submit" disabled={!account || bidAmount.trim() === "" || bidState.status === "pending"}>
                  {bidState.status === "pending" ? "Setting…" : "Set bid"}
                </button>
              </form>
              {bidState.message && (
                <p className={bidState.status === "error" ? "error-text" : "status-ok"}>{bidState.message}</p>
              )}
            </div>

            <div className="wallet-form-block">
              <p className="muted">
                Open a trade session so sellers can sell to you. Blank per-seller limit = no limit.
              </p>
              {currentCap === 0n && (
                <p className="status-warn">Set a desk cap first — a session with no buying power can’t pay any seller.</p>
              )}
              <form className="wallet-form" onSubmit={handleOpenSession}>
                <input
                  type="text"
                  placeholder="Duration (minutes)"
                  value={sessionMinutes}
                  onChange={(e) => setSessionMinutes(e.target.value)}
                  disabled={!account}
                />
                <input
                  type="text"
                  placeholder="Per-seller limit (GOAT, blank = none)"
                  value={sessionCap}
                  onChange={(e) => setSessionCap(e.target.value)}
                  disabled={!account}
                />
                <button
                  type="submit"
                  disabled={!account || currentCap === 0n || sessionState.status === "pending"}
                >
                  {sessionState.status === "pending" ? "Opening…" : "Open session"}
                </button>
              </form>
              <div className="wallet-actions-row">
                <button
                  type="button"
                  onClick={handleCloseSession}
                  disabled={!account || !myDeskRow?.isOpen || sessionState.status === "pending"}
                >
                  Close session
                </button>
              </div>
              {sessionState.message && (
                <p className={sessionState.status === "error" ? "error-text" : "status-ok"}>{sessionState.message}</p>
              )}
            </div>

            <div className="wallet-form-block">
              <p className="muted">Rename your desk — shown to sellers instead of your address.</p>
              <form className="wallet-form" onSubmit={handleRename}>
                <input
                  type="text"
                  placeholder={myDeskRow?.name || "Unnamed desk"}
                  value={renameInput}
                  onChange={(e) => setRenameInput(e.target.value)}
                  disabled={!account}
                />
                <button type="submit" disabled={!account || renameState.status === "pending"}>
                  {renameState.status === "pending" ? "Renaming…" : "Rename"}
                </button>
              </form>
              {renameState.message && (
                <p className={renameState.status === "error" ? "error-text" : "status-ok"}>{renameState.message}</p>
              )}
            </div>
          </>
        ) : (
          <>
            <p className="placeholder-note">
              Become a donor from this wallet — no second wallet needed. Opening a desk deploys your own BuyDesk;
              GOAT sold to it goes straight to this address.
            </p>
            {enrolled !== true && <p className="status-warn">{ENROLLMENT_WARNING_COPY}</p>}
            <form className="wallet-form" onSubmit={handleCreateDesk}>
              <input
                type="text"
                placeholder="Desk name (e.g. Alice's Desk)"
                value={deskNameInput}
                onChange={(e) => setDeskNameInput(e.target.value)}
                disabled={!account || enrolled !== true}
              />
              <button
                type="submit"
                disabled={!account || enrolled !== true || createState.status === "pending"}
              >
                {createState.status === "pending" ? "Opening…" : "Open my buy desk"}
              </button>
            </form>
            {createState.message && (
              <p className={createState.status === "error" ? "error-text" : "status-ok"}>{createState.message}</p>
            )}
          </>
        )}
        </div>
      </div>

      <div className="wallet-section">
        <h3>Enrollment</h3>
        {!account ? (
          <p className="placeholder-note">Unlock a wallet to check enrollment.</p>
        ) : enrolled === null ? (
          <p className="muted">Checking…</p>
        ) : enrolled ? (
          <p className="status-ok">Enrolled — can transfer GOAT, sell on desks, and open a buy desk.</p>
        ) : (
          <>
            <p className="status-warn">
              Not enrolled. Create/import auto-enrolls when the wallet has ETH for gas (anvil does).
              Or enroll yourself:
            </p>
            <button
              type="button"
              className="primary-cta"
              disabled={!walletClient || !deployment?.enrollmentRegistry}
              onClick={async () => {
                try {
                  await ensureEnrolled({
                    publicClient,
                    walletClient,
                    account,
                    enrollmentRegistry: deployment.enrollmentRegistry,
                  });
                  refresh();
                } catch (err) {
                  setLoadError(friendlyError(err, networkId));
                }
              }}
            >
              Enroll myself (pays ETH gas)
            </button>
          </>
        )}
        <p className="muted" style={{ marginTop: "0.5rem" }}>
          Gas is always native ETH (not GOAT). Anvil accounts ship with free ETH. Donors only need ETH for
          createDesk/approve — they do not need GOAT. Workers need ETH + GOAT to sell.
        </p>
      </div>

      <footer className="wallet-footer">
        <p>{WORK_UNIT_FORMULA}</p>
      </footer>
    </section>
  );
}
