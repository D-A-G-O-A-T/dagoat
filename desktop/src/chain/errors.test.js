import { describe, expect, it } from "vitest";
import { rpcUnreachableHint, ANVIL_DOWN_HINT } from "./errors.js";

function viemishError(name) {
  // Mimics viem's error shape: walk() visits the cause chain.
  const inner = { name };
  return {
    name: "ContractFunctionExecutionError",
    shortMessage: "HTTP request failed.",
    walk(predicate) {
      return predicate(inner) ? inner : null;
    },
  };
}

describe("rpcUnreachableHint", () => {
  it("maps HttpRequestError on local anvil to the dev-up hint", () => {
    expect(rpcUnreachableHint(viemishError("HttpRequestError"), 31337)).toBe(ANVIL_DOWN_HINT);
  });
  it("maps TimeoutError on local anvil to the dev-up hint", () => {
    expect(rpcUnreachableHint(viemishError("TimeoutError"), 31337)).toBe(ANVIL_DOWN_HINT);
  });
  it("does not fire on Base Sepolia", () => {
    expect(rpcUnreachableHint(viemishError("HttpRequestError"), 84532)).toBe(null);
  });
  it("does not fire for contract reverts", () => {
    const revert = { name: "ContractFunctionExecutionError", shortMessage: "reverted", walk: () => null };
    expect(rpcUnreachableHint(revert, 31337)).toBe(null);
  });
  it("falls back to message sniffing when walk is unavailable", () => {
    expect(rpcUnreachableHint({ message: "The request took too long to respond." }, 31337)).toBe(ANVIL_DOWN_HINT);
  });
});
