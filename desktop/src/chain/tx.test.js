import { describe, expect, it, vi } from "vitest";
import { runTx } from "./tx.js";

const ABI = [{ type: "function", name: "doThing", stateMutability: "nonpayable", inputs: [], outputs: [] }];

function makeClients() {
  const calls = [];
  const publicClient = {
    simulateContract: vi.fn(async (params) => {
      calls.push(["simulateContract", params]);
    }),
    waitForTransactionReceipt: vi.fn(async (params) => {
      calls.push(["waitForTransactionReceipt", params]);
      return { status: "success" };
    }),
  };
  const walletClient = {
    writeContract: vi.fn(async (params) => {
      calls.push(["writeContract", params]);
      return "0xhash";
    }),
  };
  return { publicClient, walletClient, calls };
}

describe("runTx", () => {
  it("simulates, then writes, then waits for the receipt, in that order", async () => {
    const { publicClient, walletClient, calls } = makeClients();
    const account = { address: "0xaccount" };

    const hash = await runTx({
      publicClient,
      walletClient,
      account,
      address: "0xcontract",
      abi: ABI,
      functionName: "doThing",
      args: [1, 2],
    });

    expect(hash).toBe("0xhash");
    expect(calls.map(([name]) => name)).toEqual([
      "simulateContract",
      "writeContract",
      "waitForTransactionReceipt",
    ]);
    expect(publicClient.simulateContract).toHaveBeenCalledWith({
      address: "0xcontract",
      abi: ABI,
      functionName: "doThing",
      args: [1, 2],
      account,
    });
    expect(walletClient.writeContract).toHaveBeenCalledWith({
      address: "0xcontract",
      abi: ABI,
      functionName: "doThing",
      args: [1, 2],
    });
    expect(publicClient.waitForTransactionReceipt).toHaveBeenCalledWith({
      hash: "0xhash",
      timeout: 60_000,
    });
  });

  it("propagates a simulateContract revert without calling writeContract", async () => {
    const { publicClient, walletClient } = makeClients();
    publicClient.simulateContract = vi.fn(async () => {
      throw new Error("NotSafe");
    });

    await expect(
      runTx({
        publicClient,
        walletClient,
        account: { address: "0xaccount" },
        address: "0xcontract",
        abi: ABI,
        functionName: "doThing",
        args: [],
      })
    ).rejects.toThrow("NotSafe");
    expect(walletClient.writeContract).not.toHaveBeenCalled();
  });

  // Review round 1, "also": simulateContract runs against state at call time;
  // the real mined tx can still revert on a state change between simulate and
  // inclusion (TOCTOU) even though it consumed real gas. Before this fix,
  // runTx resolved on ANY receipt, so a reverted-but-mined tx looked
  // identical to a success to every caller (Market.jsx would report "Sold
  // (testnet)", fire onSuccess, and clear the gas floor for a tx that never
  // actually landed).
  it("throws when the receipt status is reverted, so a mined-but-reverted tx is not treated as success", async () => {
    const { publicClient, walletClient } = makeClients();
    publicClient.waitForTransactionReceipt = vi.fn(async () => ({ status: "reverted" }));

    await expect(
      runTx({
        publicClient,
        walletClient,
        account: { address: "0xaccount" },
        address: "0xcontract",
        abi: ABI,
        functionName: "doThing",
        args: [],
      })
    ).rejects.toThrow(/reverted/i);
  });
});
