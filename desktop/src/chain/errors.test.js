import { describe, expect, it } from "vitest";
import {
  ACCESS_GATE_HINT,
  ANVIL_DOWN_HINT,
  REMOTE_RPC_HINT,
  bindTimeoutHint,
  formatHttpGateError,
  looksLikeAccessOrHtmlGate,
  rpcUnreachableHint,
} from "./errors.js";

function viemishError(name) {
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
  it("maps transport errors on Base Sepolia to volunteer remote hint", () => {
    expect(rpcUnreachableHint(viemishError("HttpRequestError"), 84532)).toBe(REMOTE_RPC_HINT);
    expect(REMOTE_RPC_HINT).not.toMatch(/anvil|8545|8787/i);
  });
  it("does not fire for contract reverts", () => {
    const revert = { name: "ContractFunctionExecutionError", shortMessage: "reverted", walk: () => null };
    expect(rpcUnreachableHint(revert, 31337)).toBe(null);
  });
  it("falls back to message sniffing when walk is unavailable", () => {
    expect(rpcUnreachableHint({ message: "The request took too long to respond." }, 31337)).toBe(
      ANVIL_DOWN_HINT,
    );
  });
});

describe("Access / HTML gate detection (consultant hazard #2)", () => {
  it("flags 302/401/403 and HTML bodies", () => {
    expect(looksLikeAccessOrHtmlGate(403, "")).toBe(true);
    expect(looksLikeAccessOrHtmlGate(200, "<!DOCTYPE html><html>cloudflare access")).toBe(true);
    expect(looksLikeAccessOrHtmlGate(200, '{"ok":true}')).toBe(false);
  });

  it("formatHttpGateError prefers structured JSON error", () => {
    expect(formatHttpGateError(400, "x", { error: "BadSignature" })).toBe(null);
  });

  it("formatHttpGateError maps HTML gate to ACCESS_GATE_HINT", () => {
    const msg = formatHttpGateError(403, "<html>cf-access login</html>", null);
    expect(msg).toContain("access gate");
    expect(msg).toMatch(/HTTP 403/);
    expect(ACCESS_GATE_HINT).not.toMatch(/anvil|8545/i);
  });
});

describe("bindTimeoutHint", () => {
  it("lab copy names ports; remote does not", () => {
    expect(bindTimeoutHint(45_000, 31337, true)).toMatch(/8545|8787/);
    expect(bindTimeoutHint(45_000, 84532, false)).not.toMatch(/8545|8787|anvil/i);
  });
});
