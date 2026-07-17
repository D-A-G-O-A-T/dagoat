// rustAccount builds a viem account whose signing delegates to the Rust
// wallet_* commands. These tests pin the command names + the load-bearing
// encoding (the JS↔Rust contract) and that results are returned verbatim.
import { beforeEach, describe, expect, it, vi } from "vitest";
import { toHex } from "viem";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args) => invoke(...args) }));

const { createRustAccount, __test } = await import("./rustAccount.js");

const ADDRESS = "0x1111111111111111111111111111111111111111";

beforeEach(() => {
  invoke.mockReset();
});

describe("createRustAccount", () => {
  it("exposes the address and viem account shape", () => {
    const account = createRustAccount(ADDRESS);
    expect(account.address).toBe(ADDRESS);
    expect(typeof account.signMessage).toBe("function");
    expect(typeof account.signTransaction).toBe("function");
    expect(typeof account.signTypedData).toBe("function");
  });

  it("signMessage invokes wallet_sign_message with hex of a string and returns verbatim", async () => {
    invoke.mockResolvedValue("0xdeadbeef");
    const account = createRustAccount(ADDRESS);
    const sig = await account.signMessage({ message: "hello" });
    expect(invoke).toHaveBeenCalledWith("wallet_sign_message", {
      expectedAddress: ADDRESS,
      messageHex: toHex("hello"),
    });
    expect(sig).toBe("0xdeadbeef");
  });

  it("signMessage passes raw hex through unchanged", async () => {
    invoke.mockResolvedValue("0xsig");
    const account = createRustAccount(ADDRESS);
    await account.signMessage({ message: { raw: "0xabcd" } });
    expect(invoke).toHaveBeenCalledWith("wallet_sign_message", {
      expectedAddress: ADDRESS,
      messageHex: "0xabcd",
    });
  });

  it("signTransaction serializes the EIP-1559 fields and returns the raw tx verbatim", async () => {
    invoke.mockResolvedValue("0x02signedraw");
    const account = createRustAccount(ADDRESS);
    const raw = await account.signTransaction({
      chainId: 31337,
      nonce: 7,
      to: "0x2222222222222222222222222222222222222222",
      value: 1000000000000000000n,
      gas: 21000n,
      maxFeePerGas: 2000000000n,
      maxPriorityFeePerGas: 1000000000n,
      data: "0x",
      type: "eip1559",
    });
    expect(raw).toBe("0x02signedraw");
    expect(invoke).toHaveBeenCalledTimes(1);
    const [command, payload] = invoke.mock.calls[0];
    expect(command).toBe("wallet_sign_transaction");
    expect(payload.expectedAddress).toBe(ADDRESS);
    const tx = JSON.parse(payload.txJson);
    expect(tx).toMatchObject({
      type: "eip1559",
      chainId: 31337,
      nonce: 7,
      to: "0x2222222222222222222222222222222222222222",
      value: "1000000000000000000", // bigint → decimal string
      gas: "21000",
      maxFeePerGas: "2000000000",
      maxPriorityFeePerGas: "1000000000",
      data: "0x",
    });
  });

  it("signTypedData stringifies with bigint→decimal and returns verbatim", async () => {
    invoke.mockResolvedValue("0x712sig");
    const account = createRustAccount(ADDRESS);
    const typed = {
      domain: { name: "GOAT", chainId: 31337n },
      types: { Foo: [{ name: "amount", type: "uint256" }] },
      primaryType: "Foo",
      message: { amount: 42n },
    };
    const sig = await account.signTypedData(typed);
    expect(sig).toBe("0x712sig");
    const [command, payload] = invoke.mock.calls[0];
    expect(command).toBe("wallet_sign_typed_data");
    expect(payload.expectedAddress).toBe(ADDRESS);
    const parsed = JSON.parse(payload.typedJson);
    expect(parsed.domain.chainId).toBe("31337");
    expect(parsed.message.amount).toBe("42");
    expect(parsed.primaryType).toBe("Foo");
  });
});

describe("encoding helpers", () => {
  it("bigintReplacer stringifies bigints only", () => {
    expect(__test.bigintReplacer("k", 5n)).toBe("5");
    expect(__test.bigintReplacer("k", "x")).toBe("x");
    expect(__test.bigintReplacer("k", 3)).toBe(3);
  });

  it("transactionToJson omits absent fields", () => {
    const json = JSON.parse(__test.transactionToJson({ to: ADDRESS }));
    expect(json).toEqual({ type: "eip1559", to: ADDRESS });
  });
});
