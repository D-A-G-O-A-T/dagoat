import { beforeEach, describe, expect, it, vi } from "vitest";
import { getEstimateGasError } from "viem/utils";
import {
  clearFloorForStep,
  clearFloorsForAddress,
  floorKey,
  formatTestEthShortfall,
  FLOOR_STEP_APPROVE_SELL,
  FLOOR_STEP_SELL,
  isInsufficientFundsError,
  newFloorStore,
  readFloorWei,
  recordShortfallWei,
  requiredWei,
  runGatedTx,
} from "./gasFloor.js";

// ---------------------------------------------------------------------------
// requiredWei — the four-token expression that makes the reported bug
// impossible. At the exact balance that already failed, the requirement is
// strictly greater than that balance BY CONSTRUCTION, so no fee movement, no
// estimate error and no zero-fee collapse can undo the block.
// ---------------------------------------------------------------------------
describe("requiredWei", () => {
  it("uses the estimate when it already exceeds the floor", () => {
    expect(requiredWei(500n, 100n)).toBe(500n);
  });

  it("uses floor+1 when the floor dominates", () => {
    expect(requiredWei(100n, 500n)).toBe(501n);
  });

  it("uses floor+1 at the equality boundary (est === floor)", () => {
    // Without the +1 this returns `floor`, and `needsGasDrip(floor, floor)`
    // is false — the exact silent re-pass this whole change exists to close.
    expect(requiredWei(500n, 500n)).toBe(501n);
  });

  it("with no floor recorded, behaves exactly as the pre-fix gate did", () => {
    expect(requiredWei(500n, 0n)).toBe(500n);
    // Critically 0n, NOT 1n: a zero estimate with no floor is the deliberate
    // fail-open for a wallet that has never failed (both fee-estimate paths
    // down). Returning 1n here would make every such gate request a drip and
    // burn the wallet's single daily allowance on an RPC hiccup.
    expect(requiredWei(0n, 0n)).toBe(0n);
  });

  it("survives a zero-fee estimate collapse: the floor still governs", () => {
    // estimateFeePerGas throwing makes estCostWei 0n. Pre-fix that opened the
    // gate unconditionally; the floor is a separate absolute term.
    expect(requiredWei(0n, 12_345n)).toBe(12_346n);
  });

  it("handles values past Number.MAX_SAFE_INTEGER", () => {
    const big = 12_345_678_901_234_567_890n;
    expect(requiredWei(0n, big)).toBe(big + 1n);
  });
});

// ---------------------------------------------------------------------------
// The floor store. Module-scope by construction: App.jsx renders only the
// ACTIVE panel (`const ActivePanel = PANELS[active] ?? Miner`), so a tab
// switch unmounts Market and destroys any component state. A stuck user
// clicking to the Wallet tab and back must NOT get a fresh silent pass.
// ---------------------------------------------------------------------------
describe("floor store", () => {
  let store;
  beforeEach(() => {
    store = newFloorStore();
  });

  it("round-trips a recorded shortfall", () => {
    const key = floorKey({ chainId: 84532, address: "0xAbC", step: FLOOR_STEP_SELL });
    expect(readFloorWei(key, store)).toBe(0n);
    recordShortfallWei(key, 900n, store);
    expect(readFloorWei(key, store)).toBe(900n);
  });

  it("keeps the maximum, never the latest (a lower later reading cannot lower the bar)", () => {
    const key = floorKey({ chainId: 84532, address: "0xAbC", step: FLOOR_STEP_SELL });
    recordShortfallWei(key, 900n, store);
    recordShortfallWei(key, 100n, store);
    expect(readFloorWei(key, store)).toBe(900n);
  });

  it("is address-case-insensitive", () => {
    const upper = floorKey({ chainId: 84532, address: "0xABCDEF", step: FLOOR_STEP_SELL });
    const lower = floorKey({ chainId: 84532, address: "0xabcdef", step: FLOOR_STEP_SELL });
    recordShortfallWei(upper, 900n, store);
    expect(readFloorWei(lower, store)).toBe(900n);
  });

  it("isolates by chainId — a floor learned on one network must not block another", () => {
    const a = floorKey({ chainId: 84532, address: "0xAbC", step: FLOOR_STEP_SELL });
    const b = floorKey({ chainId: 31337, address: "0xAbC", step: FLOOR_STEP_SELL });
    recordShortfallWei(a, 900n, store);
    expect(readFloorWei(b, store)).toBe(0n);
  });

  it("isolates by step", () => {
    const sell = floorKey({ chainId: 84532, address: "0xAbC", step: FLOOR_STEP_SELL });
    const appr = floorKey({ chainId: 84532, address: "0xAbC", step: FLOOR_STEP_APPROVE_SELL });
    recordShortfallWei(sell, 900n, store);
    expect(readFloorWei(appr, store)).toBe(900n);
  });

  it("a sell shortfall raises the approve+sell floor too (approve+sell needs strictly more than sell)", () => {
    const sell = floorKey({ chainId: 84532, address: "0xAbC", step: FLOOR_STEP_SELL });
    const appr = floorKey({ chainId: 84532, address: "0xAbC", step: FLOOR_STEP_APPROVE_SELL });
    recordShortfallWei(sell, 900n, store);
    expect(readFloorWei(appr, store)).toBe(900n);
    // ...but not the other way round: clearing sell must not be implied by approve.
    recordShortfallWei(appr, 5_000n, store);
    expect(readFloorWei(sell, store)).toBe(900n);
  });

  it("clears every step for an address on success", () => {
    const sell = floorKey({ chainId: 84532, address: "0xAbC", step: FLOOR_STEP_SELL });
    const appr = floorKey({ chainId: 84532, address: "0xAbC", step: FLOOR_STEP_APPROVE_SELL });
    recordShortfallWei(sell, 900n, store);
    recordShortfallWei(appr, 5_000n, store);
    clearFloorsForAddress({ chainId: 84532, address: "0xabc" }, store);
    expect(readFloorWei(sell, store)).toBe(0n);
    expect(readFloorWei(appr, store)).toBe(0n);
  });

  it("clearing one address leaves another address's floor intact", () => {
    const mine = floorKey({ chainId: 84532, address: "0xAAA", step: FLOOR_STEP_SELL });
    const other = floorKey({ chainId: 84532, address: "0xBBB", step: FLOOR_STEP_SELL });
    recordShortfallWei(mine, 900n, store);
    recordShortfallWei(other, 700n, store);
    clearFloorsForAddress({ chainId: 84532, address: "0xAAA" }, store);
    expect(readFloorWei(mine, store)).toBe(0n);
    expect(readFloorWei(other, store)).toBe(700n);
  });

  it("ignores a non-bigint or negative reading rather than corrupting the floor", () => {
    const key = floorKey({ chainId: 84532, address: "0xAbC", step: FLOOR_STEP_SELL });
    recordShortfallWei(key, 900n, store);
    recordShortfallWei(key, undefined, store);
    recordShortfallWei(key, -5n, store);
    expect(readFloorWei(key, store)).toBe(900n);
  });

  // Review round 1, "also": handleSellApprove's success was clearing the
  // SELL floor as well as the approve floor, silently discarding proof that
  // a prior sell had already failed at the wallet's current balance.
  // clearFloorForStep is the narrower primitive that fixes it — it must
  // touch only its own step's key, leaving every other step's floor intact.
  it("clearFloorForStep clears only the named step, not the whole address (unlike clearFloorsForAddress)", () => {
    const sell = floorKey({ chainId: 84532, address: "0xAbC", step: FLOOR_STEP_SELL });
    const appr = floorKey({ chainId: 84532, address: "0xAbC", step: FLOOR_STEP_APPROVE_SELL });
    recordShortfallWei(sell, 900n, store);
    recordShortfallWei(appr, 5_000n, store);
    clearFloorForStep({ chainId: 84532, address: "0xAbC", step: FLOOR_STEP_APPROVE_SELL }, store);
    expect(readFloorWei(appr, store)).toBe(0n);
    expect(readFloorWei(sell, store)).toBe(900n); // untouched
  });
});

// ---------------------------------------------------------------------------
// isInsufficientFundsError — must fire on viem's node-level funds errors and
// must NOT fire on a decoded Solidity revert. A misclassified revert would
// poison the floor (blocking an affordable sell) and burn the wallet's single
// daily drip. The precedent for the regex is chain/enroll.js:69.
// ---------------------------------------------------------------------------
describe("isInsufficientFundsError", () => {
  it("matches viem's InsufficientFundsError by name through the cause chain", () => {
    const err = { name: "EstimateGasExecutionError", cause: { name: "InsufficientFundsError" } };
    expect(isInsufficientFundsError(err)).toBe(true);
  });

  it("matches viem's literal shortMessage", () => {
    const err = {
      shortMessage:
        "The total cost (gas * gas fee + value) of executing this transaction exceeds the balance of the account.",
    };
    expect(isInsufficientFundsError(err)).toBe(true);
  });

  it("matches the node phrasings enroll.js already handles", () => {
    expect(isInsufficientFundsError({ message: "insufficient funds for gas * price + value" })).toBe(true);
    expect(
      isInsufficientFundsError({ details: "exceeds transaction sender account balance" }),
    ).toBe(true);
  });

  it("does NOT match decoded Solidity reverts, even ones whose text mentions balance", () => {
    for (const name of [
      "TransferRestricted",
      "CapExceeded",
      "ERC20InsufficientBalance",
      "ERC20InsufficientAllowance",
      "NotEnrolled",
      "ZeroPayout",
    ]) {
      const err = { name: "ContractFunctionExecutionError", cause: { name } };
      expect(isInsufficientFundsError(err), `${name} must not read as a funds error`).toBe(false);
    }
  });

  it("does NOT match an unrelated error", () => {
    expect(isInsufficientFundsError(new Error("user rejected the request"))).toBe(false);
    expect(isInsufficientFundsError(null)).toBe(false);
  });

  it("a decoded contract error wins even if the wrapper text mentions funds", () => {
    const err = {
      name: "ContractFunctionExecutionError",
      shortMessage: "insufficient funds",
      cause: { name: "CapExceeded" },
    };
    expect(isInsufficientFundsError(err)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// FIX-1 (review round 1). geth's MOST COMMON way to say "this wallet can't
// afford the gas" is "gas required exceeds allowance (N)", not "insufficient
// funds" — and viem's own getNodeError classifies that text as
// ExecutionRevertedError (checked BEFORE InsufficientFundsError), which used
// to return false here, so no floor was ever recorded and the gate passed
// forever. These fixtures are built with viem's REAL error constructor
// (`getEstimateGasError`, the same one `walletClient.writeContract` uses
// internally when `eth_estimateGas` fails), not hand-typed approximations —
// see the shapes printed and verified in the FIX-1 code comment in
// gasFloor.js.
// ---------------------------------------------------------------------------
describe("isInsufficientFundsError — FIX-1 (review round 1): geth's real node messages", () => {
  it('classifies "gas required exceeds allowance" as a funds error, not a contract revert', () => {
    // The common path: balance/maxFeePerGas < gasNeeded for a zero-value
    // call, so geth's eth_estimateGas search ceiling is capped by the
    // balance and it can't find a working gas value.
    const err = getEstimateGasError({ details: "gas required exceeds allowance (21000)" }, {});
    // Sanity-check the fixture is faithful to what viem actually produces,
    // so this test fails loudly (not silently) if a viem upgrade changes it.
    expect(err.name).toBe("EstimateGasExecutionError");
    expect(err.cause.name).toBe("ExecutionRevertedError");
    expect(isInsufficientFundsError(err)).toBe(true);
  });

  it('classifies "intrinsic gas too low" (the balance cap falling below 21,000) as a funds error', () => {
    const err = getEstimateGasError({ details: "intrinsic gas too low" }, {});
    expect(err.cause.name).toBe("IntrinsicGasTooLowError");
    expect(isInsufficientFundsError(err)).toBe(true);
  });

  it("does NOT classify a genuine revert-for-an-unknown-reason (bare 'execution reverted') as a funds error", () => {
    // Same ExecutionRevertedError CLASS as the allowance case above, but
    // without the funds-specific text — this is what an ordinary contract
    // revert with no decoded reason looks like. Matching on the class
    // instead of the text (which FIX-1 explicitly avoids) would misclassify
    // this and poison the floor on every plain revert.
    const err = getEstimateGasError({ details: "execution reverted" }, {});
    expect(err.cause.name).toBe("ExecutionRevertedError");
    expect(isInsufficientFundsError(err)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// runGatedTx — the gate -> send -> record-floor -> clear-on-success ordering.
// This is the seam the mutation run proved was invisible: with the sequence
// inline in a React handler, deleting it left the suite at baseline.
// ---------------------------------------------------------------------------
describe("runGatedTx", () => {
  const FUNDS_ERR = { name: "InsufficientFundsError" };

  function harness(overrides = {}) {
    return {
      preflight: vi.fn(async () => ({ ok: true, haveWei: 100n })),
      send: vi.fn(async () => "0xhash"),
      readBalance: vi.fn(async () => 100n),
      onShortfall: vi.fn(),
      onSuccess: vi.fn(),
      ...overrides,
    };
  }

  it("does not send when the gate blocks", async () => {
    const h = harness({ preflight: vi.fn(async () => ({ ok: false, message: "nope" })) });
    const out = await runGatedTx(h);
    expect(out.ok).toBe(false);
    expect(out.gate.message).toBe("nope");
    expect(h.send).not.toHaveBeenCalled();
    expect(h.onShortfall).not.toHaveBeenCalled();
  });

  it("clears the floor on success", async () => {
    const h = harness();
    const out = await runGatedTx(h);
    expect(out.ok).toBe(true);
    expect(out.result).toBe("0xhash");
    expect(h.onSuccess).toHaveBeenCalledTimes(1);
    expect(h.onShortfall).not.toHaveBeenCalled();
  });

  it("records the floor from the balance observed AT FAILURE, not the pre-gate reading", async () => {
    // The gate saw 100n, then requested a drip that landed, so the balance at
    // the moment the tx failed is 900n. Recording the stale 100n would leave
    // required = 101n <= 900n and the very next gate would pass silently.
    const h = harness({
      preflight: vi.fn(async () => ({ ok: true, haveWei: 100n })),
      readBalance: vi.fn(async () => 900n),
      send: vi.fn(async () => {
        throw FUNDS_ERR;
      }),
    });
    await expect(runGatedTx(h)).rejects.toBe(FUNDS_ERR);
    expect(h.onShortfall).toHaveBeenCalledWith(900n);
  });

  it("falls back to the gate's reading when the post-failure balance read fails", async () => {
    const h = harness({
      readBalance: vi.fn(async () => {
        throw new Error("rpc down");
      }),
      send: vi.fn(async () => {
        throw FUNDS_ERR;
      }),
    });
    await expect(runGatedTx(h)).rejects.toBe(FUNDS_ERR);
    expect(h.onShortfall).toHaveBeenCalledWith(100n);
  });

  it("does NOT record a floor for a Solidity revert, and still rethrows it", async () => {
    const revert = { name: "ContractFunctionExecutionError", cause: { name: "CapExceeded" } };
    const h = harness({
      send: vi.fn(async () => {
        throw revert;
      }),
    });
    await expect(runGatedTx(h)).rejects.toBe(revert);
    expect(h.onShortfall).not.toHaveBeenCalled();
    expect(h.onSuccess).not.toHaveBeenCalled();
  });
});

describe("formatTestEthShortfall", () => {
  it("reports how much is held and how much this step needs", () => {
    const line = formatTestEthShortfall(1_000_000_000_000_000n, 2_500_000_000_000_000n);
    expect(line).toContain("0.001");
    expect(line).toContain("0.0025");
    expect(line).toMatch(/testnet ETH/);
  });

  it("returns an empty string when nothing is short", () => {
    expect(formatTestEthShortfall(5n, 5n)).toBe("");
    expect(formatTestEthShortfall(9n, 5n)).toBe("");
  });

  it("does not lose precision on values past Number.MAX_SAFE_INTEGER", () => {
    const line = formatTestEthShortfall(0n, 12_345_678_901_234_567_890n);
    expect(line).toContain("12.34567890123456789");
  });

  // -------------------------------------------------------------------------
  // FIX-3 (review round 1). Once a floor is recorded, requiredWei returns
  // floor+1n — a strict lower bound one wei above a balance a REAL
  // transaction already failed at, not an estimate. The old two-argument
  // form of this function printed that number as "needs about {floor+1n}":
  // executed proof from the review was floor 270000000000000n -> "This
  // wallet holds 0.00027 testnet ETH. This step needs about
  // 0.000270000000000001 testnet ETH." — a funding target the user cannot
  // ever satisfy without failing again by construction, so the guidance
  // never converges. Before this fix, the previous test block (now above)
  // only ever exercised the WIDE-GAP (non-floor-dominant) case, which is
  // exactly why this slipped through.
  // -------------------------------------------------------------------------
  describe("floor-dominant case (requiredAmountWei is floor+1n, not an estimate)", () => {
    const BALANCE = 270_000_000_000_000n; // the review's executed-proof number
    const FLOOR_PLUS_ONE = BALANCE + 1n; // what requiredWei returns once this balance has failed

    it("never repeats floor+1n as the funding target — the exact regression from the review", () => {
      const est = 200_000_000_000_000n; // a live estimate, LOWER than the floor (est <= floor => floor-dominant)
      const line = formatTestEthShortfall(BALANCE, FLOOR_PLUS_ONE, est);
      expect(line).not.toMatch(/0\.000270000000000001/);
      expect(line).not.toContain(FLOOR_PLUS_ONE.toString());
    });

    it("states the requirement as MORE than the failed balance and unknown, not a false precise number", () => {
      const est = 200_000_000_000_000n;
      const line = formatTestEthShortfall(BALANCE, FLOOR_PLUS_ONE, est);
      expect(line).toContain("0.00027 testnet ETH"); // honest have-line, unchanged
      expect(line).toMatch(/more than that/i);
      expect(line).toMatch(/exact amount can't be measured/i);
      expect(line).not.toMatch(/needs about/i); // that phrasing is reserved for a real estimate
    });

    it("suggests a genuinely actionable funding target that EXCEEDS the floor, not just double the estimate", () => {
      // Review round 2, FIX-3-critical: at this exact BALANCE/est pair the
      // floor/estimate ratio is only 1.35x, so a plain `estCostWei * 2`
      // (0.0004 ETH) happens to still clear the floor (0.00027 ETH) by
      // luck — which is exactly why this fixture didn't catch the round-2
      // regression. The correct FULL-PRECISION suggestion dominates the
      // floor too: max(estCostWei*2, requiredAmountWei*3/2+1) =
      // 405000000000002n wei here (the floor-based term edges out the
      // estimate-based one). Review round 3 then rounds that UP to 4
      // significant digits for display -> 0.0004051 testnet ETH (never
      // below the full-precision value: 405,100,000,000,000 >
      // 405,000,000,000,002).
      const est = 200_000_000_000_000n; // 0.0002 ETH
      const line = formatTestEthShortfall(BALANCE, FLOOR_PLUS_ONE, est);
      expect(line).toContain("0.0004051 testnet ETH");
    });

    it("omits a numeric suggestion (rather than a bogus 0) when the estimate itself is unusable", () => {
      // A fee-estimate collapse (both estimateFeesPerGas and getGasPrice
      // failed) makes estCostWei 0n. Suggesting "0 testnet ETH" would be
      // actively misleading, so the honest sentence stands alone.
      const line = formatTestEthShortfall(BALANCE, FLOOR_PLUS_ONE, 0n);
      expect(line).toMatch(/more than that/i);
      expect(line).not.toMatch(/funding to about/i);
    });

    it("is NOT floor-dominant (uses the plain needs-about line) when the estimate itself exceeds the floor", () => {
      // est > floor means requiredWei returned est itself (not floor+1n) —
      // an honest estimate, not a disproven number — so the original
      // two-part rendering is correct here.
      const est = FLOOR_PLUS_ONE; // requiredAmountWei === estCostWei: not floor-dominant
      const line = formatTestEthShortfall(BALANCE, FLOOR_PLUS_ONE, est);
      expect(line).toMatch(/needs about/i);
      expect(line).not.toMatch(/more than that/i);
    });

    it("stays within copy law: no wage/income/profit/salary/earning vocabulary, no positional above/below, no false retry promise", () => {
      const cases = [
        formatTestEthShortfall(BALANCE, FLOOR_PLUS_ONE, 200_000_000_000_000n),
        formatTestEthShortfall(BALANCE, FLOOR_PLUS_ONE, 0n),
      ];
      for (const line of cases) {
        for (const re of [/\bwage\b/i, /\bincome\b/i, /\bprofit\b/i, /\bsalary\b/i, /\bearn(ing)?s?\b/i, /\b(above|below)\b/i, /try again shortly/i]) {
          expect(line, `"${line}" matches forbidden ${re}`).not.toMatch(re);
        }
      }
    });

    it("2-argument calls (est defaults to requiredAmountWei) are never floor-dominant — pre-FIX-3 callers are unaffected", () => {
      // requiredAmountWei <= estCostWei is always true when estCostWei
      // defaults to requiredAmountWei itself, so every existing 2-arg call
      // site keeps rendering the plain needs-about line.
      const line = formatTestEthShortfall(BALANCE, FLOOR_PLUS_ONE);
      expect(line).toMatch(/needs about/i);
    });

    // -----------------------------------------------------------------------
    // Review round 2, FIX-3-critical: `estCostWei * 2` alone never compares
    // against the floor. Executed proof from the review: balance/floor
    // 0.002 ETH fails; fees then drop so the LIVE estimate at render time is
    // only 0.0002 ETH -> the round-1 code suggested "about 0.0004 testnet
    // ETH", which is comfortably UNDER the ~0.002 ETH the floor actually
    // proves is required. The user funds to 0.0004, retries, the gate
    // blocks immediately — non-convergence, just relocated from "one wei
    // above the balance" to "a static 2x estimate decoupled from the floor".
    // The round-1 fixture above sat at only a 1.35x floor/estimate ratio,
    // where `est*2` happened to still clear the floor by luck, which is
    // exactly why it didn't catch this.
    // -----------------------------------------------------------------------
    describe("round 2 regression: the suggestion must dominate the floor, not just the estimate", () => {
      it("floor 10x the live estimate — reproduces the review's exact numbers (fees dropped sharply after the failure)", () => {
        const failedBalance = 2_000_000_000_000_000n; // 0.002 ETH — the review's exact executed-proof number
        const requiredAmountWei = failedBalance + 1n; // what requiredWei returns once this balance has failed
        const liveEstimateAfterFeeDrop = 200_000_000_000_000n; // 0.0002 ETH — fees dropped 10x since the failure
        const line = formatTestEthShortfall(failedBalance, requiredAmountWei, liveEstimateAfterFeeDrop);

        // The round-1 bug's answer. If this ever appears again the fix has regressed.
        expect(line).not.toContain("0.0004 testnet ETH");
        // Full-precision: max(estCostWei*2, requiredAmountWei*3/2+1) =
        // 3,000,000,000,000,002n wei. Review round 3 rounds that UP to 4
        // significant digits for display: 0.003001 (never below the
        // full-precision value).
        expect(line).toContain("0.003001 testnet ETH");

        // The property that actually matters, checked directly against the
        // real balance a transaction failed at, past any string-formatting
        // detail: whatever number is suggested must exceed what the floor
        // proves is required, with real headroom, not just clear it by luck.
        const [, whole, frac] = line.match(/about (\d+)\.(\d+) testnet ETH/);
        const suggestedWei = BigInt(whole) * 10n ** 18n + BigInt(frac.padEnd(18, "0"));
        expect(suggestedWei).toBeGreaterThan(requiredAmountWei);
        expect(suggestedWei > (requiredAmountWei * 11n) / 10n).toBe(true); // at least 10% real headroom
      });

      it("floor well above the estimate (10x, round numbers) — the floor-based term wins the max", () => {
        const failedBalance = 1_000_000_000_000_000n; // 0.001 ETH
        const requiredAmountWei = failedBalance + 1n;
        const est = 100_000_000_000_000n; // 0.0001 ETH — 10x below the floor
        const line = formatTestEthShortfall(failedBalance, requiredAmountWei, est);

        expect(line).not.toContain("0.0002 testnet ETH"); // the old, floor-blind est*2 answer
        // Full-precision 1,500,000,000,000,002n wei, rounded UP for display.
        expect(line).toContain("0.001501 testnet ETH");

        const [, whole, frac] = line.match(/about (\d+)\.(\d+) testnet ETH/);
        const suggestedWei = BigInt(whole) * 10n ** 18n + BigInt(frac.padEnd(18, "0"));
        expect(suggestedWei).toBeGreaterThan(requiredAmountWei);
      });

      it("estimate close to the floor — the estimate-based term (2x) wins the max, and still exceeds the floor", () => {
        const failedBalance = 1_000_000_000_000_000n; // 0.001 ETH
        const requiredAmountWei = failedBalance + 1n;
        const est = 900_000_000_000_000n; // 0.0009 ETH — only slightly below the floor
        const line = formatTestEthShortfall(failedBalance, requiredAmountWei, est);

        // 0.0018 ETH (est*2) beats 0.001500000000000002 ETH (the floor term) here.
        expect(line).toContain("0.0018 testnet ETH");

        const [, whole, frac] = line.match(/about (\d+)\.(\d+) testnet ETH/);
        const suggestedWei = BigInt(whole) * 10n ** 18n + BigInt(frac.padEnd(18, "0"));
        expect(suggestedWei).toBeGreaterThan(requiredAmountWei);
      });
    });

    // -------------------------------------------------------------------------
    // Review round 3. The corrected round-2 arithmetic converges (the
    // suggestion always exceeds the floor), but rendering the full-precision
    // wei value produced strings like "Funding to about 0.003000000000000002
    // testnet ETH gives real headroom" — "about" paired with 18 decimal
    // places reads as a bug, and this string exists specifically to give a
    // stuck volunteer a number they can act on. The comparison arithmetic
    // stays at full wei precision throughout (`suggestionWei` above is never
    // rounded before the dominance check); only the RENDERED string changes.
    // -------------------------------------------------------------------------
    describe("round 3: displayed amounts are rounded, never below what they represent", () => {
      // Parse a "0.00xyz" testnet-ETH string back to exact wei, mirroring
      // weiToTestEth's own padding/stripping so the round trip is exact.
      function parseTestEth(str) {
        const m = str.match(/(\d+)\.(\d+)/);
        if (!m) return BigInt(str) * 10n ** 18n;
        return BigInt(m[1]) * 10n ** 18n + BigInt(m[2].padEnd(18, "0"));
      }

      // Digit count ignoring insignificant leading zeros in the fraction —
      // "0004051" (from "0.0004051") has 4, not 7; the OLD buggy
      // "003000000000000002" (from "0.003000000000000002") has 16.
      function significantFractionDigits(str) {
        const m = str.match(/\.(\d+)/);
        return m ? m[1].replace(/^0+/, "").length : 0;
      }

      // Independent re-derivation of the source's dominance formula, so
      // these tests assert against a computed expectation rather than a
      // string transcribed by hand.
      function expectedFullPrecisionSuggestion(requiredAmountWei, estCostWei) {
        const estTerm = estCostWei * 2n;
        const floorTerm = (requiredAmountWei * 3n) / 2n + 1n;
        return estTerm > floorTerm ? estTerm : floorTerm;
      }

      it("the funding suggestion has no long decimal tail (at most 4 significant digits)", () => {
        const failedBalance = 2_000_000_000_000_000n;
        const requiredAmountWei = failedBalance + 1n;
        const est = 200_000_000_000_000n;
        const line = formatTestEthShortfall(failedBalance, requiredAmountWei, est);
        const [, suggestedText] = line.match(/about ([\d.]+) testnet ETH/);
        // Significant digits, not raw fraction length: "0.0004051" has 7
        // fraction digits but only 4 SIGNIFICANT ones (leading zeros are
        // normal decimal placement, not tail noise). The exact regression
        // this closes is the old 16+ significant-digit tail
        // ("0.003000000000000002").
        expect(significantFractionDigits(suggestedText)).toBeLessThanOrEqual(4);
      });

      it("the funding suggestion, parsed back to wei, is never below the full-precision computed value (rounds UP)", () => {
        // A deliberately messy, non-round floor/estimate pair so the
        // full-precision suggestion itself has a long tail, not just the
        // floor+1n term.
        const failedBalance = 123_456_789_012_345n;
        const requiredAmountWei = failedBalance + 1n;
        const est = 7_777_777_777_777n; // well under the floor -> floor term wins
        const fullPrecisionSuggestion = expectedFullPrecisionSuggestion(requiredAmountWei, est);

        const line = formatTestEthShortfall(failedBalance, requiredAmountWei, est);
        const [, suggestedText] = line.match(/about ([\d.]+) testnet ETH/);
        const displayedWei = parseTestEth(suggestedText);
        expect(displayedWei).toBeGreaterThanOrEqual(fullPrecisionSuggestion);
        expect(displayedWei).toBeGreaterThanOrEqual(requiredAmountWei);
      });

      it("the have-line (balance) is rounded DOWN — never overstates what the wallet actually holds", () => {
        // A deliberately non-round balance (dust-level remainder from a
        // prior partial spend), well past 4 significant digits.
        const balance = 1_234_567_890_123_456n; // 0.001234567890123456 ETH
        const est = 1_000_000_000_000n;
        const requiredAmountWei = balance + est + 1n; // force floor-dominant so the have-line's context matches the reported bug
        const line = formatTestEthShortfall(balance, requiredAmountWei, est);
        const [, haveText] = line.match(/holds ([\d.]+) testnet ETH/);
        const displayedWei = parseTestEth(haveText);
        expect(displayedWei).toBeLessThanOrEqual(balance); // never claims more than actually held
        expect(significantFractionDigits(haveText)).toBeLessThanOrEqual(4);
      });

      it("small balances/suggestions below 4 significant digits are unaffected (rounding is a no-op)", () => {
        const line = formatTestEthShortfall(1_000_000_000_000_000n, 2_500_000_000_000_000n);
        expect(line).toContain("0.001 testnet ETH");
        expect(line).toContain("0.0025 testnet ETH");
      });
    });
  });
});
