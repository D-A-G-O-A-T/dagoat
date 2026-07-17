import { describe, expect, it, vi } from "vitest";
import { hashTypedData, recoverTypedDataAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  BIND_TYPES,
  DEV_RELAYER_URL,
  ENROLL_TYPES,
  RELAYER_URL,
  bindDomain,
  buildBindTypedData,
  buildEnrollTypedData,
  deadlineFromNow,
  enrollDomain,
  isLocalRelayerUrl,
  postBindRelay,
  postEnrollRelay,
  relayerMode,
  resolveRelayerUrl,
  usernameMismatch,
} from "./attribution.js";

// Pinned cross-stack vectors (must match contracts/test/Eip712DesktopParity.t.sol).
const ANVIL0_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PINNED = {
  chainId: 31337,
  verifyingBind: "0x1111111111111111111111111111111111111111",
  verifyingEnroll: "0x2222222222222222222222222222222222222222",
  username: "GOAT-alice",
  nonce: 0n,
  deadline: 2_000_000_000n,
  bindDigest: "0x6760436048cb4918b0cd773e2c2db5f6bb28c3b8fb7cf34f215da680806cdfa2",
  enrollDigest: "0xc815623fc9a5e16ee135627955085cd554d7a678a970dd8e97297b17f629c1e7",
  bindSig:
    "0x5519983078728025bbcbdd0a213cf4a1545bfa71a48e86552a9c2be2802927f343e7b82e6a3a974e6dff2139e28e6d9eb270c59cd3dbf45c7ff2a72cb16dd7a61c",
  enrollSig:
    "0x1310f358af0800ba1551d77e5b962a95b1cb1460b49075632ae201fc5f8108a8513d78e9c625cd0cfc02b70b8b0c4e37fec3f20f5e017ef72bd2913779dac9f91c",
};

describe("relayer URL policy", () => {
  it("defaults to localhost dev URL when env unset", () => {
    expect(resolveRelayerUrl("")).toBe(DEV_RELAYER_URL);
    expect(isLocalRelayerUrl(DEV_RELAYER_URL)).toBe(true);
    expect(relayerMode(DEV_RELAYER_URL)).toBe("local-dev");
  });

  it("treats production HTTPS API as remote", () => {
    const prod = "https://api.goatcoin.example";
    expect(resolveRelayerUrl(prod)).toBe(prod);
    expect(isLocalRelayerUrl(prod)).toBe(false);
    expect(relayerMode(prod)).toBe("remote");
  });

  it("RELAYER_URL is defined (build may inject VITE_ override)", () => {
    expect(typeof RELAYER_URL).toBe("string");
    expect(RELAYER_URL.length).toBeGreaterThan(0);
  });
});

describe("EIP-712 domains", () => {
  it("bind domain matches WorkerBinding constructor name/version", () => {
    expect(bindDomain({ chainId: 31337, verifyingContract: "0xabc" })).toEqual({
      name: "GoatWorkerBinding",
      version: "1",
      chainId: 31337,
      verifyingContract: "0xabc",
    });
  });

  it("enroll domain matches EnrollmentRegistry constructor name/version", () => {
    expect(enrollDomain({ chainId: 31337, verifyingContract: "0xdef" })).toEqual({
      name: "GoatEnrollmentRegistry",
      version: "1",
      chainId: 31337,
      verifyingContract: "0xdef",
    });
  });
});

describe("EIP-712 cross-stack parity (viem ↔ Solidity pins)", () => {
  const account = privateKeyToAccount(ANVIL0_PK);

  it("hashTypedData Bind matches forge-pinned digest", () => {
    const td = buildBindTypedData({
      chainId: PINNED.chainId,
      workerBinding: PINNED.verifyingBind,
      wallet: account.address,
      username: PINNED.username,
      nonce: PINNED.nonce,
      deadline: PINNED.deadline,
    });
    expect(hashTypedData(td)).toBe(PINNED.bindDigest);
  });

  it("hashTypedData Enroll matches forge-pinned digest", () => {
    const td = buildEnrollTypedData({
      chainId: PINNED.chainId,
      enrollmentRegistry: PINNED.verifyingEnroll,
      wallet: account.address,
      nonce: PINNED.nonce,
      deadline: PINNED.deadline,
    });
    expect(hashTypedData(td)).toBe(PINNED.enrollDigest);
  });

  it("signTypedData Bind recovers worker and matches pinned sig", async () => {
    const td = buildBindTypedData({
      chainId: PINNED.chainId,
      workerBinding: PINNED.verifyingBind,
      wallet: account.address,
      username: PINNED.username,
      nonce: PINNED.nonce,
      deadline: PINNED.deadline,
    });
    const sig = await account.signTypedData(td);
    expect(sig.toLowerCase()).toBe(PINNED.bindSig.toLowerCase());
    const recovered = await recoverTypedDataAddress({ ...td, signature: sig });
    expect(recovered.toLowerCase()).toBe(account.address.toLowerCase());
  });

  it("signTypedData Enroll recovers worker and matches pinned sig", async () => {
    const td = buildEnrollTypedData({
      chainId: PINNED.chainId,
      enrollmentRegistry: PINNED.verifyingEnroll,
      wallet: account.address,
      nonce: PINNED.nonce,
      deadline: PINNED.deadline,
    });
    const sig = await account.signTypedData(td);
    expect(sig.toLowerCase()).toBe(PINNED.enrollSig.toLowerCase());
    const recovered = await recoverTypedDataAddress({ ...td, signature: sig });
    expect(recovered.toLowerCase()).toBe(account.address.toLowerCase());
  });

  it("wrong chainId produces a different Bind digest (fragility guard)", () => {
    const wrong = buildBindTypedData({
      chainId: 1,
      workerBinding: PINNED.verifyingBind,
      wallet: account.address,
      username: PINNED.username,
      nonce: PINNED.nonce,
      deadline: PINNED.deadline,
    });
    expect(hashTypedData(wrong)).not.toBe(PINNED.bindDigest);
  });
});

describe("primary types", () => {
  it("Bind matches contract BIND_TYPEHASH fields", () => {
    expect(BIND_TYPES.Bind.map((f) => `${f.type} ${f.name}`)).toEqual([
      "address wallet",
      "string username",
      "uint256 nonce",
      "uint256 deadline",
    ]);
  });

  it("Enroll matches contract ENROLL_TYPEHASH fields", () => {
    expect(ENROLL_TYPES.Enroll.map((f) => `${f.type} ${f.name}`)).toEqual([
      "address wallet",
      "uint256 nonce",
      "uint256 deadline",
    ]);
  });
});

describe("buildBindTypedData / buildEnrollTypedData", () => {
  it("builds Bind message with bigint nonce/deadline", () => {
    const td = buildBindTypedData({
      chainId: 31337,
      workerBinding: "0xCF75462c9e7fFf4eEB0c50185087a0fb9A056d2b",
      wallet: "0x1111111111111111111111111111111111111111",
      username: "GOAT-alice",
      nonce: 0n,
      deadline: 1_700_000_000n,
    });
    expect(td.primaryType).toBe("Bind");
    expect(td.message.username).toBe("GOAT-alice");
    expect(td.message.nonce).toBe(0n);
    expect(td.domain.name).toBe("GoatWorkerBinding");
  });

  it("builds Enroll message", () => {
    const td = buildEnrollTypedData({
      chainId: 31337,
      enrollmentRegistry: "0x2222222222222222222222222222222222222222",
      wallet: "0x1111111111111111111111111111111111111111",
      nonce: 2,
      deadline: 99,
    });
    expect(td.primaryType).toBe("Enroll");
    expect(td.message.nonce).toBe(2n);
    expect(td.message.deadline).toBe(99n);
  });
});

describe("deadlineFromNow", () => {
  it("adds default TTL", () => {
    expect(deadlineFromNow(1_000_000, 3600)).toBe(1_003_600n);
  });
});

describe("postRelay wrappers", () => {
  it("POSTs bind body to /v1/relay/bind", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ ok: true, tx_hash: "0xabc" }),
    });
    const out = await postBindRelay(
      {
        wallet: "0x1111111111111111111111111111111111111111",
        username: "GOAT-alice",
        deadline: 99,
        signature: "0xsig",
      },
      { fetchImpl },
    );
    expect(out).toEqual({ ok: true, tx_hash: "0xabc", error: null });
    expect(fetchImpl).toHaveBeenCalledWith(
      `${RELAYER_URL}/v1/relay/bind`,
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("POSTs enroll body to /v1/relay/enroll", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ ok: true, tx_hash: "0xdef" }),
    });
    const out = await postEnrollRelay(
      {
        wallet: "0x1111111111111111111111111111111111111111",
        deadline: 99,
        signature: "0xsig",
      },
      { fetchImpl },
    );
    expect(out.tx_hash).toBe("0xdef");
    expect(fetchImpl.mock.calls[0][0]).toContain("/v1/relay/enroll");
  });

  it("surfaces HTTP errors from relayer", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      json: async () => ({ ok: false, error: "username must start with \"GOAT-\"" }),
    });
    const out = await postBindRelay(
      { wallet: "0x1", username: "bad", deadline: 1, signature: "0x" },
      { fetchImpl },
    );
    expect(out.ok).toBe(false);
    expect(out.error).toContain("GOAT-");
  });

  it("surfaces network failures", async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
    const out = await postEnrollRelay(
      { wallet: "0x1", deadline: 1, signature: "0xab" },
      { fetchImpl },
    );
    expect(out.ok).toBe(false);
    expect(out.error).toContain("ECONNREFUSED");
  });

  it("maps Failed to fetch to relayer-unreachable guidance", async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error("Failed to fetch"));
    const out = await postBindRelay(
      { wallet: "0x1", username: "GOAT-a", deadline: 1, signature: "0x" },
      { fetchImpl },
    );
    expect(out.ok).toBe(false);
    expect(out.relayerDown).toBe(true);
    expect(out.error).toMatch(/Relayer unreachable/i);
    expect(out.error).toMatch(/serve-relayer|8787|wallet-gas/i);
  });
});

describe("usernameMismatch", () => {
  it("false when either side empty or equal", () => {
    expect(usernameMismatch("", "GOAT-a")).toBe(false);
    expect(usernameMismatch("GOAT-a", "")).toBe(false);
    expect(usernameMismatch("GOAT-a", "GOAT-a")).toBe(false);
  });
  it("true when both set and differ", () => {
    expect(usernameMismatch("GOAT-a", "GOAT-b")).toBe(true);
  });
});
