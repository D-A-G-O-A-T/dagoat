import { describe, expect, it, vi } from "vitest";
import * as marketModule from "./Market.jsx";
import * as gasDripModule from "../chain/gasDrip.js";
import {
  APPROVE_GAS,
  APPROVE_SELL_GATE_GAS,
  ensureGasForSell,
  friendlyError,
  GAS_BALANCE_UNREADABLE_COPY,
  INSUFFICIENT_GAS_COPY,
  needsGasDrip,
  runApproveGasGate,
  runSellGasGate,
  SELL_GAS,
} from "./Market.jsx";
import {
  GAS_DRIP_LIMIT_COPY,
  GAS_DRIP_NO_GOAT_COPY,
  GAS_DRIP_SEND_FAILED_COPY,
  GAS_DRIP_IN_PROGRESS_COPY,
  GAS_DRIP_SPENT_STILL_SHORT_COPY,
  GAS_DRIP_UNAVAILABLE_COPY,
} from "../chain/gasDrip.js";
import {
  clearFloorForStep,
  clearFloorsForAddress,
  FLOOR_STEP_APPROVE_SELL,
  FLOOR_STEP_SELL,
  floorKey,
  newFloorStore,
  readFloorWei,
  recordShortfallWei,
} from "../chain/gasFloor.js";

describe("needsGasDrip", () => {
  it("needs a drip only when ETH < estimated cost", () => {
    expect(needsGasDrip(0n, 5n)).toBe(true);
    expect(needsGasDrip(10n, 5n)).toBe(false);
  });

  it("is a strict less-than: exactly enough ETH does not need a drip", () => {
    expect(needsGasDrip(5n, 5n)).toBe(false);
  });

  it("handles zero cost (no drip ever needed)", () => {
    expect(needsGasDrip(0n, 0n)).toBe(false);
  });
});

// FIX-2 (review round 1): the preflight itself was untested — every one of the
// tests above still passes with the `ensureGasForSell` call sites deleted from
// handleSellApprove/handleSell. `ensureGasForSell` is dependency-injected (same
// pattern as Miner.jsx's gating helpers) precisely so it can be driven directly
// here, independent of publicClient/viem/React.
describe("ensureGasForSell", () => {
  const FAST = { sleep: async () => {} }; // no real waiting in tests

  function deps(overrides = {}) {
    return {
      getBalance: async () => 0n,
      estimateFeePerGas: async () => 0n,
      requestDrip: vi.fn(async () => ({ ok: true, status: 200 })),
      address: "0xWORKER",
      gasUnits: SELL_GAS,
      ...FAST,
      ...overrides,
    };
  }

  it("affordable balance: requestDrip is NOT called, self-pay proceeds (ok)", async () => {
    const requestDrip = vi.fn();
    const result = await ensureGasForSell(
      deps({
        getBalance: async () => 1_000_000_000_000_000n, // 0.001 ETH
        estimateFeePerGas: async () => 1_000_000_000n, // 1 gwei
        gasUnits: SELL_GAS,
        requestDrip,
      }),
    );
    expect(result).toMatchObject({ ok: true });
    expect(requestDrip).not.toHaveBeenCalled();
  });

  it("unaffordable balance: requestDrip is called once; 200 + balance rising to cover cost -> ok", async () => {
    // Derived from SELL_GAS, never hardcoded: a stale literal here silently
    // becomes a balance that can never satisfy the gate, and the poll spins.
    const estCost = 1_000_000_000n * SELL_GAS; // 1 gwei * SELL_GAS
    let call = 0;
    const getBalance = vi.fn(async () => (call++ === 0 ? 0n : estCost)); // rises to exactly cover cost after the drip
    const requestDrip = vi.fn(async () => ({ ok: true, status: 200 }));
    const result = await ensureGasForSell(
      deps({
        getBalance,
        estimateFeePerGas: async () => 1_000_000_000n,
        gasUnits: SELL_GAS,
        requestDrip,
        address: "0xWORKER",
      }),
    );
    expect(requestDrip).toHaveBeenCalledTimes(1);
    expect(requestDrip).toHaveBeenCalledWith("0xWORKER");
    expect(result).toMatchObject({ ok: true });
  });

  it("drip returns 429 (daily limit): stops with the limit copy, caller must not proceed", async () => {
    const requestDrip = vi.fn(async () => ({ ok: false, status: 429, error: "DailyLimitReached" }));
    const result = await ensureGasForSell(
      deps({
        getBalance: async () => 0n,
        estimateFeePerGas: async () => 1_000_000_000n,
        requestDrip,
      }),
    );
    expect(requestDrip).toHaveBeenCalledTimes(1);
    expect(result).toMatchObject({ ok: false, message: GAS_DRIP_LIMIT_COPY });
  });

  it("poll times out after a 200: the allowance is spent, caller must not proceed", async () => {
    const requestDrip = vi.fn(async () => ({ ok: true, status: 200 }));
    const result = await ensureGasForSell(
      deps({
        getBalance: async () => 0n, // never rises
        estimateFeePerGas: async () => 1_000_000_000n,
        requestDrip,
        pollIntervalMs: 1,
        pollTimeoutMs: 5,
      }),
    );
    // A 200 committed this wallet's daily allowance before the send. Reporting
    // a network problem here (the old behaviour) was false, and the copy it
    // used before that invited a retry that would 429.
    expect(result).toMatchObject({ ok: false, message: GAS_DRIP_SPENT_STILL_SHORT_COPY });
  });

  it("FIX-3: an unrelated incoming transfer (balance rises but stays below cost) does not falsely succeed", async () => {
    const requestDrip = vi.fn(async () => ({ ok: true, status: 200 }));
    let call = 0;
    // Balance rises from 0 -> 1 wei (a real "did it rise" check would pass);
    // 1 wei is nowhere near the 1 gwei * SELL_GAS actually needed.
    const getBalance = vi.fn(async () => (call++ === 0 ? 0n : 1n));
    const result = await ensureGasForSell(
      deps({
        getBalance,
        estimateFeePerGas: async () => 1_000_000_000n,
        requestDrip,
        pollIntervalMs: 1,
        pollTimeoutMs: 5,
      }),
    );
    expect(result).toMatchObject({ ok: false, message: GAS_DRIP_SPENT_STILL_SHORT_COPY });
  });

  it("FIX-4: fee-estimate rejection surfaces as a thrown estimateFeePerGas -> falls back to self-pay (ok, no drip)", async () => {
    // ensureGasForSell itself doesn't retry estimateFeePerGas (that's the real
    // realEstimateFeePerGas's job, FIX-4) — it just must not block the sell
    // when the injected estimator throws.
    const requestDrip = vi.fn();
    const result = await ensureGasForSell(
      deps({
        getBalance: async () => 0n,
        estimateFeePerGas: async () => {
          throw new Error("rpc down");
        },
        requestDrip,
      }),
    );
    expect(result).toMatchObject({ ok: true });
    expect(requestDrip).not.toHaveBeenCalled();
  });

  it("FIX-1: the estimate passed differs between the two entry points (approve+sell vs sell-only)", async () => {
    // A balance that covers sell-only gas but NOT the combined approve+sell
    // gas — this is exactly the post-approve regression FIX-1 closes: using
    // the combined threshold on the second click would wrongly re-trigger
    // a drip (and burn the day's quota) even though the sell alone is affordable.
    const feePerGas = 1_000_000_000n; // 1 gwei
    const balance = feePerGas * SELL_GAS + 1n; // just over sell-only cost, under combined cost

    const sellOnlyDrip = vi.fn();
    const sellOnlyResult = await ensureGasForSell(
      deps({ getBalance: async () => balance, estimateFeePerGas: async () => feePerGas, gasUnits: SELL_GAS, requestDrip: sellOnlyDrip }),
    );
    expect(sellOnlyResult).toMatchObject({ ok: true });
    expect(sellOnlyDrip).not.toHaveBeenCalled();

    let call = 0;
    const combinedDrip = vi.fn(async () => ({ ok: true, status: 200 }));
    const combinedResult = await ensureGasForSell(
      deps({
        getBalance: vi.fn(async () => (call++ === 0 ? balance : feePerGas * APPROVE_SELL_GATE_GAS)),
        estimateFeePerGas: async () => feePerGas,
        gasUnits: APPROVE_SELL_GATE_GAS,
        requestDrip: combinedDrip,
      }),
    );
    expect(combinedDrip).toHaveBeenCalledTimes(1); // same balance now IS short of the combined threshold
    expect(combinedResult).toMatchObject({ ok: true });
  });
});

// ---------------------------------------------------------------------------
// P5. The reported defect: a rejected transaction consumes no gas, so after a
// failed sell the balance is unchanged, the gate's inputs are byte-identical,
// and it returns {ok:true} again — forever, including after 00:00 UTC. In the
// common stuck band it short-circuits BEFORE requestDrip, so the wallet's
// untouched daily drip is never even asked for.
//
// The fix is the observed-shortfall floor in ../chain/gasFloor.js. These tests
// drive `ensureGasForSell` across the SAME balance with and without a floor:
// same input, opposite outcome. Deleting the floor term from the gate makes
// the second half of each pair fail.
// ---------------------------------------------------------------------------
describe("P5 gas floor: the gate cannot keep passing after a failure", () => {
  const FAST = { sleep: async () => {} };
  const FEE = 1_000_000_000n; // 1 gwei

  function deps(overrides = {}) {
    return {
      getBalance: async () => 0n,
      estimateFeePerGas: async () => FEE,
      requestDrip: vi.fn(async () => ({ ok: true, status: 200 })),
      address: "0xWORKER",
      gasUnits: SELL_GAS,
      floorWei: 0n,
      ...FAST,
      ...overrides,
    };
  }

  // The load-bearing test. This is the bug, expressed as a pair.
  it("THE BUG: the same balance that passed the gate before a failure is refused after it", async () => {
    // A balance inside the old stuck band: comfortably over the pre-fix
    // 120_000-unit threshold, genuinely short of what the sell really costs.
    const balance = FEE * 130_000n;

    const beforeDrip = vi.fn(async () => ({ ok: true, status: 200 }));
    const before = await ensureGasForSell(
      deps({ getBalance: async () => balance, gasUnits: 120_000n, requestDrip: beforeDrip }),
    );
    expect(before).toMatchObject({ ok: true });
    expect(beforeDrip).not.toHaveBeenCalled(); // pre-fix behaviour: silent pass, no drip asked for

    // Now that exact balance has been observed to fail. Same balance, same fee.
    const afterDrip = vi.fn(async () => ({ ok: false, status: 429, error: "DailyLimitReached" }));
    const after = await ensureGasForSell(
      deps({
        getBalance: async () => balance,
        gasUnits: 120_000n,
        floorWei: balance,
        requestDrip: afterDrip,
      }),
    );
    expect(afterDrip).toHaveBeenCalledTimes(1); // it now ASKS instead of silently passing
    expect(after.ok).toBe(false);
  });

  it("a floor at the failing balance blocks even when the estimate says it is affordable", async () => {
    const balance = FEE * 500_000n; // hugely over any plausible estimate
    const requestDrip = vi.fn(async () => ({ ok: false, status: 429 }));
    const result = await ensureGasForSell(
      deps({ getBalance: async () => balance, floorWei: balance, requestDrip }),
    );
    expect(requestDrip).toHaveBeenCalledTimes(1);
    expect(result.ok).toBe(false);
  });

  it("recovery: once the balance rises past the floor, the gate passes again with no drip", async () => {
    const failed = FEE * 130_000n;
    const requestDrip = vi.fn();
    const result = await ensureGasForSell(
      deps({ getBalance: async () => failed + 1n, gasUnits: 120_000n, floorWei: failed, requestDrip }),
    );
    expect(result).toMatchObject({ ok: true });
    expect(requestDrip).not.toHaveBeenCalled();
  });

  it("fail-open on a fee-estimate collapse is closed ONLY when a floor exists", async () => {
    const throwing = async () => {
      throw new Error("rpc down");
    };
    // No floor: unchanged pre-fix tolerance of an estimator hiccup.
    const openDrip = vi.fn();
    expect(
      await ensureGasForSell(deps({ estimateFeePerGas: throwing, requestDrip: openDrip })),
    ).toMatchObject({ ok: true });
    expect(openDrip).not.toHaveBeenCalled();

    // With a floor, estCostWei collapsing to 0n must NOT reopen the gate.
    const closedDrip = vi.fn(async () => ({ ok: false, status: 429 }));
    const closed = await ensureGasForSell(
      deps({
        getBalance: async () => 5_000n,
        estimateFeePerGas: throwing,
        floorWei: 5_000n,
        requestDrip: closedDrip,
      }),
    );
    expect(closedDrip).toHaveBeenCalledTimes(1);
    expect(closed.ok).toBe(false);
  });

  it("fail-open on an unreadable balance is closed ONLY when a floor exists", async () => {
    const throwing = async () => {
      throw new Error("rpc down");
    };
    expect(await ensureGasForSell(deps({ getBalance: throwing }))).toMatchObject({ ok: true });

    const closed = await ensureGasForSell(deps({ getBalance: throwing, floorWei: 5_000n }));
    expect(closed.ok).toBe(false);
    expect(closed.message).toBe(GAS_BALANCE_UNREADABLE_COPY);
  });

  it("reports the balance it observed so the caller can record the right floor", async () => {
    const result = await ensureGasForSell(deps({ getBalance: async () => 7n, gasUnits: 0n }));
    expect(result).toMatchObject({ ok: true, haveWei: 7n });
  });
});

// ---------------------------------------------------------------------------
// The relayer discloses the drip size on the wire (`amount_wei`, a decimal
// STRING) and the client threw it away. A 200 has already committed the day's
// quota (reserve-before-send), so if the promised amount cannot cover the
// requirement, polling for 15 seconds to reach that conclusion — and then
// saying "try again shortly" — is both slow and false.
// ---------------------------------------------------------------------------
describe("P5: spend the relayer's amount_wei instead of discarding it", () => {
  const FEE = 1_000_000_000n;

  function deps(overrides = {}) {
    return {
      getBalance: async () => 0n,
      estimateFeePerGas: async () => FEE,
      address: "0xWORKER",
      gasUnits: SELL_GAS,
      floorWei: 0n,
      pollIntervalMs: 1,
      pollTimeoutMs: 5,
      ...overrides,
    };
  }

  it("a promised amount that cannot cover the requirement fails immediately, without polling", async () => {
    const sleepFn = vi.fn(async () => {});
    const result = await ensureGasForSell(
      deps({
        requestDrip: async () => ({ ok: true, status: 200, amount_wei: "1000" }), // nowhere near enough
        sleep: sleepFn,
      }),
    );
    expect(result.ok).toBe(false);
    expect(result.message).toBe(GAS_DRIP_SPENT_STILL_SHORT_COPY);
    // The assertion that makes this mutation-resistant: deleting the
    // pre-check reverts to polling, and sleep gets called.
    expect(sleepFn).not.toHaveBeenCalled();
  });

  it("parses amount_wei as a decimal string, exactly, past Number.MAX_SAFE_INTEGER", async () => {
    // A realistic drip at a busy-chain fee. Number() would round this; the
    // sufficiency pre-check must be exact, so the promised amount is one wei
    // SHORT of the requirement and must therefore be rejected. Rounding up
    // through Number() would wrongly let it proceed to a doomed poll.
    const bigFee = 100_000_000_000n; // 100 gwei
    const need = bigFee * SELL_GAS; // 1.67e16 wei
    expect(Number(need.toString())).toBeGreaterThan(Number.MAX_SAFE_INTEGER);

    const sleepFn = vi.fn(async () => {});
    const result = await ensureGasForSell(
      deps({
        estimateFeePerGas: async () => bigFee,
        getBalance: async () => 0n,
        requestDrip: async () => ({ ok: true, status: 200, amount_wei: (need - 1n).toString() }),
        sleep: sleepFn,
      }),
    );
    expect(result.message).toBe(GAS_DRIP_SPENT_STILL_SHORT_COPY);
    expect(sleepFn).not.toHaveBeenCalled();

    // ...and exactly the requirement is accepted.
    let call = 0;
    const okResult = await ensureGasForSell(
      deps({
        estimateFeePerGas: async () => bigFee,
        getBalance: async () => (call++ === 0 ? 0n : need),
        requestDrip: async () => ({ ok: true, status: 200, amount_wei: need.toString() }),
        sleep: async () => {},
      }),
    );
    expect(okResult).toMatchObject({ ok: true });
  });

  it("a poll timeout AFTER a 200 says the allowance is spent, not 'try again shortly'", async () => {
    const result = await ensureGasForSell(
      deps({
        getBalance: async () => 0n, // never rises
        requestDrip: async () => ({ ok: true, status: 200, amount_wei: (FEE * SELL_GAS).toString() }),
        sleep: async () => {},
      }),
    );
    expect(result.message).toBe(GAS_DRIP_SPENT_STILL_SHORT_COPY);
    expect(result.message).not.toBe(GAS_DRIP_UNAVAILABLE_COPY);
  });
});

describe("P5: friendlyError maps the node's insufficient-funds failure", () => {
  it("replaces viem's raw sentence with testnet-honest copy", () => {
    const err = {
      shortMessage:
        "The total cost (gas * gas fee + value) of executing this transaction exceeds the balance of the account.",
    };
    const msg = friendlyError(err, 84532);
    expect(msg).toBe(INSUFFICIENT_GAS_COPY);
    expect(msg).not.toMatch(/total cost/i);
  });

  it("leaves decoded Solidity reverts to their existing copy", () => {
    const err = { name: "ContractFunctionExecutionError", cause: { name: "CapExceeded" } };
    expect(friendlyError(err, 84532)).not.toBe(INSUFFICIENT_GAS_COPY);
  });

  // FIX-1 (review round 1): geth's actual "can't afford the gas" message for
  // a zero-value call is "gas required exceeds allowance", not "insufficient
  // funds" — see gasFloor.test.js for the full viem-fixture verification.
  // This end-to-end test confirms the fix reaches friendlyError, the
  // function the sell handler actually calls.
  it("maps geth's 'gas required exceeds allowance' the same way as 'insufficient funds' (FIX-1)", async () => {
    const { getEstimateGasError } = await import("viem/utils");
    const err = getEstimateGasError({ details: "gas required exceeds allowance (21000)" }, {});
    expect(friendlyError(err, 84532)).toBe(INSUFFICIENT_GAS_COPY);
  });
});

// ---------------------------------------------------------------------------
// FIX-2 (review round 1). A 31-mutation run found the gate's pure logic well
// covered but its WIRING — the read-store -> gate -> write-on-shortfall ->
// clear-on-success sequence — invisible: it lived inline in
// handleSellApprove/handleSell, and six one-line changes there survived a
// fully green suite (two, M30 and M31, individually reopened the reported
// bug). `desktop/` has no jsdom/@testing-library/react and none was added to
// close this — instead the sequence was pulled out as `runApproveGasGate`/
// `runSellGasGate`, exported and dependency-injected exactly like
// `ensureGasForSell` above, so it can be driven directly here.
//
// Each test below applies the SAME mutation the original review found (or,
// where the refactor moved the vulnerable line, the equivalent mutation at
// its new location — noted per test) directly to Market.jsx, re-runs this
// file, confirms the specific assertion fails, then restores the source.
// That manual mutation pass was recorded in the P5 fix-round-1 review;
// these tests are what makes each mutation fail.
// ---------------------------------------------------------------------------
describe("P5 fix round 1 (FIX-2): the floor wiring is now a pure, injectable seam", () => {
  const CHAIN = 84532;
  const ADDRESS = "0xWORKER";

  // A local, isolated floor store (never the module-scope default) so these
  // tests can't leak state into each other or into gasFloor.test.js.
  function harness(overrides = {}) {
    const floors = new Map();
    return {
      floors,
      readFloor: vi.fn((key) => floors.get(key) ?? 0n),
      recordShortfall: vi.fn((key, wei) => floors.set(key, wei)),
      networkId: CHAIN,
      address: ADDRESS,
      publicClient: { getBalance: vi.fn(async () => 999n) },
      send: vi.fn(async () => "0xhash"),
      onShortfallMessage: vi.fn(),
      preflight: vi.fn(async () => ({ ok: true, needWei: 0n, estCostWei: 0n })),
      ...overrides,
    };
  }

  describe("runApproveGasGate", () => {
    it("M31: reads the floor from the injected store and threads it into the gate (deleting the read reopens the bug)", async () => {
      const h = harness();
      h.floors.set(floorKey({ chainId: CHAIN, address: ADDRESS, step: FLOOR_STEP_APPROVE_SELL }), 12_345n);
      await runApproveGasGate(h);
      expect(h.readFloor).toHaveBeenCalled();
      expect(h.preflight).toHaveBeenCalledWith(expect.objectContaining({ floorWei: 12_345n }));
    });

    it("M33: gates the approve step with APPROVE_SELL_GATE_GAS, never SELL_GAS", async () => {
      const h = harness();
      await runApproveGasGate(h);
      expect(h.preflight).toHaveBeenCalledWith(expect.objectContaining({ gasUnits: APPROVE_SELL_GATE_GAS }));
      expect(h.preflight).not.toHaveBeenCalledWith(expect.objectContaining({ gasUnits: SELL_GAS }));
    });

    it("M30: records the observed shortfall on failure (deleting the write leaves the floor at 0 forever)", async () => {
      const FUNDS_ERR = { name: "InsufficientFundsError" };
      const h = harness({
        send: vi.fn(async () => {
          throw FUNDS_ERR;
        }),
        publicClient: { getBalance: vi.fn(async () => 777n) },
      });
      await expect(runApproveGasGate(h)).rejects.toBe(FUNDS_ERR);
      const key = floorKey({ chainId: CHAIN, address: ADDRESS, step: FLOOR_STEP_APPROVE_SELL });
      expect(h.recordShortfall).toHaveBeenCalledWith(key, 777n);
      expect(h.floors.get(key)).toBe(777n);
    });

    it('"also": clears ONLY the approve floor on success, never the sell floor', async () => {
      const clearStep = vi.fn();
      const h = harness({ clearFloorForStep: clearStep });
      const outcome = await runApproveGasGate(h);
      expect(outcome.ok).toBe(true);
      expect(clearStep).toHaveBeenCalledWith({ chainId: CHAIN, address: ADDRESS, step: FLOOR_STEP_APPROVE_SELL });
    });

    it('"also": the DEFAULT clearing (no override) really deletes only the approve key, proved against the real store', async () => {
      // Point the REAL clearFloorForStep at a local, isolated store (never
      // the module-scope default) instead of duplicating its logic in a spy.
      const store = newFloorStore();
      const apprKey = floorKey({ chainId: CHAIN, address: ADDRESS, step: FLOOR_STEP_APPROVE_SELL });
      const sellKey = floorKey({ chainId: CHAIN, address: ADDRESS, step: FLOOR_STEP_SELL });
      recordShortfallWei(apprKey, 900n, store);
      recordShortfallWei(sellKey, 900n, store);
      await runApproveGasGate({
        ...harness(),
        readFloor: (key) => readFloorWei(key, store),
        recordShortfall: (key, wei) => recordShortfallWei(key, wei, store),
        clearFloorForStep: (args) => clearFloorForStep(args, store),
      });
      expect(readFloorWei(apprKey, store)).toBe(0n); // cleared
      expect(readFloorWei(sellKey, store)).toBe(900n); // NOT touched by an approve success
    });
  });

  describe("runSellGasGate", () => {
    it("M34: records a shortfall under the SELL key, never the approve key", async () => {
      const FUNDS_ERR = { name: "InsufficientFundsError" };
      const h = harness({
        send: vi.fn(async () => {
          throw FUNDS_ERR;
        }),
        publicClient: { getBalance: vi.fn(async () => 555n) },
      });
      await expect(runSellGasGate(h)).rejects.toBe(FUNDS_ERR);
      const sellKey = floorKey({ chainId: CHAIN, address: ADDRESS, step: FLOOR_STEP_SELL });
      const apprKey = floorKey({ chainId: CHAIN, address: ADDRESS, step: FLOOR_STEP_APPROVE_SELL });
      expect(h.recordShortfall).toHaveBeenCalledWith(sellKey, 555n);
      expect(h.recordShortfall).not.toHaveBeenCalledWith(apprKey, 555n);
    });

    it("gates the sell step with SELL_GAS, never APPROVE_SELL_GATE_GAS", async () => {
      const h = harness();
      await runSellGasGate(h);
      expect(h.preflight).toHaveBeenCalledWith(expect.objectContaining({ gasUnits: SELL_GAS }));
      expect(h.preflight).not.toHaveBeenCalledWith(expect.objectContaining({ gasUnits: APPROVE_SELL_GATE_GAS }));
    });

    it("M32: clears every step's floor on a successful sell (unchanged blanket clear)", async () => {
      const clearAll = vi.fn();
      const h = harness({ clearFloorsForAddress: clearAll });
      const outcome = await runSellGasGate(h);
      expect(outcome.ok).toBe(true);
      expect(clearAll).toHaveBeenCalledWith({ chainId: CHAIN, address: ADDRESS });
    });

    it("M32: the DEFAULT clearing (no override) really clears BOTH steps, proved against the real store", async () => {
      const store = newFloorStore();
      const apprKey = floorKey({ chainId: CHAIN, address: ADDRESS, step: FLOOR_STEP_APPROVE_SELL });
      const sellKey = floorKey({ chainId: CHAIN, address: ADDRESS, step: FLOOR_STEP_SELL });
      recordShortfallWei(apprKey, 900n, store);
      recordShortfallWei(sellKey, 900n, store);
      await runSellGasGate({
        ...harness(),
        readFloor: (key) => readFloorWei(key, store),
        recordShortfall: (key, wei) => recordShortfallWei(key, wei, store),
        clearFloorsForAddress: (args) => clearFloorsForAddress(args, store),
      });
      expect(readFloorWei(apprKey, store)).toBe(0n);
      expect(readFloorWei(sellKey, store)).toBe(0n);
    });

    it("M31 (sell side): reads the floor from the injected store and threads it into the gate", async () => {
      const h = harness();
      h.floors.set(floorKey({ chainId: CHAIN, address: ADDRESS, step: FLOOR_STEP_SELL }), 42n);
      await runSellGasGate(h);
      expect(h.preflight).toHaveBeenCalledWith(expect.objectContaining({ floorWei: 42n }));
    });
  });

  it("does not send when the gate blocks (preflight ok:false short-circuits send)", async () => {
    const h = harness({ preflight: vi.fn(async () => ({ ok: false, message: "nope" })) });
    const outcome = await runSellGasGate(h);
    expect(outcome.ok).toBe(false);
    expect(outcome.gate.message).toBe("nope");
    expect(h.send).not.toHaveBeenCalled();
  });
});

// Task 7 wires the Market sell preflight to GD6's gas-drip client (../chain/gasDrip.js).
// GD6 already owns and copy-law-tests its failure strings (gasDrip.test.js) — this
// extends the copy-law corpus to the Market integration point, confirming Market
// never introduces new failure copy and the consumed strings stay testnet-honest.
describe("copy laws (gas-drip copy consumed by Market's sell preflight)", () => {
  // Discovered by reflection, not hand-maintained. A hardcoded array is how a
  // new string ships unregulated: the reviewer adds the constant and forgets
  // the list, and the suite stays green. Anything named *_COPY in either
  // module is now covered automatically.
  const ALL_GAS_DRIP_COPY = Object.entries({ ...gasDripModule, ...marketModule })
    .filter(([name, value]) => name.endsWith("_COPY") && typeof value === "string")
    .map(([, value]) => value);

  it("limit copy is testnet-honest, no forbidden vocab", () => {
    expect(GAS_DRIP_LIMIT_COPY).toMatch(/00:00 UTC/);
    for (const re of [/\bwage\b/i, /\bincome\b/i, /\bprofit\b/i]) {
      expect(GAS_DRIP_LIMIT_COPY).not.toMatch(re);
    }
  });

  it("no forbidden wage/income/profit/salary/earning vocabulary in any gas-drip copy Market can show", () => {
    const FORBIDDEN = [/\bwage\b/i, /\bincome\b/i, /\bprofit\b/i, /\bsalary\b/i, /\bearn(ing)?s?\b/i];
    for (const s of ALL_GAS_DRIP_COPY) {
      for (const re of FORBIDDEN) {
        expect(s, `"${s}" matches forbidden ${re}`).not.toMatch(re);
      }
    }
  });

  // Guards the reflection itself. If the filter ever stops matching (a rename,
  // a refactor to non-string exports), the two tests above would pass over an
  // empty corpus and assert nothing — the exact theatre this replaces.
  it("the reflected corpus actually contains the strings it claims to cover", () => {
    expect(ALL_GAS_DRIP_COPY.length).toBeGreaterThanOrEqual(8);
    for (const s of [
      GAS_DRIP_LIMIT_COPY,
      GAS_DRIP_SPENT_STILL_SHORT_COPY,
      INSUFFICIENT_GAS_COPY,
      GAS_BALANCE_UNREADABLE_COPY,
    ]) {
      expect(ALL_GAS_DRIP_COPY).toContain(s);
    }
  });

  it("no positional claims — the layout is not described in prose", () => {
    for (const s of ALL_GAS_DRIP_COPY) {
      expect(s, `"${s}" makes a positional claim`).not.toMatch(/\b(above|below)\b/i);
    }
  });

  it("nothing promises that a retry will succeed", () => {
    for (const s of ALL_GAS_DRIP_COPY) {
      expect(s, `"${s}" promises a retry will work`).not.toMatch(/try again shortly/i);
    }
  });

  it("the quota-exhausted strings say plainly that retrying today is refused", () => {
    for (const s of [GAS_DRIP_LIMIT_COPY, GAS_DRIP_SPENT_STILL_SHORT_COPY]) {
      expect(s).toMatch(/00:00 UTC/);
      expect(s).toMatch(/testnet ETH/);
    }
    expect(GAS_DRIP_LIMIT_COPY).toMatch(/will be refused/);
  });
});
