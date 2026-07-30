import { describe, expect, it, vi } from "vitest";
import { DEFAULT_RECEIPT_TIMEOUT_MS, waitForReceipt } from "./receipt.js";

describe("waitForReceipt", () => {
  it("defaults timeout to 60s", () => {
    expect(DEFAULT_RECEIPT_TIMEOUT_MS).toBe(60_000);
  });

  it("calls waitForTransactionReceipt with hash and default timeout", async () => {
    const publicClient = {
      waitForTransactionReceipt: vi.fn(async () => ({ status: "success" })),
    };
    const receipt = await waitForReceipt(publicClient, { hash: "0xabc" });
    expect(receipt).toEqual({ status: "success" });
    expect(publicClient.waitForTransactionReceipt).toHaveBeenCalledWith({
      hash: "0xabc",
      timeout: 60_000,
    });
  });

  it("honors timeoutMs override", async () => {
    const publicClient = {
      waitForTransactionReceipt: vi.fn(async () => ({ status: "success" })),
    };
    await waitForReceipt(publicClient, { hash: "0xdef", timeoutMs: 12_000 });
    expect(publicClient.waitForTransactionReceipt).toHaveBeenCalledWith({
      hash: "0xdef",
      timeout: 12_000,
    });
  });

  it("throws when receipt status is reverted", async () => {
    const publicClient = {
      waitForTransactionReceipt: vi.fn(async () => ({ status: "reverted" })),
    };
    await expect(waitForReceipt(publicClient, { hash: "0xdead" })).rejects.toThrow(
      /reverted/i,
    );
  });

  it("rejects missing hash / client", async () => {
    await expect(waitForReceipt({}, { hash: "0x1" })).rejects.toThrow(/publicClient/i);
    await expect(
      waitForReceipt(
        { waitForTransactionReceipt: vi.fn() },
        { hash: "" },
      ),
    ).rejects.toThrow(/hash/i);
  });
});
