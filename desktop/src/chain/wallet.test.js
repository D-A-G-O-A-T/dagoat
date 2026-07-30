// wallet.js wraps the Rust wallet_* commands and refreshes the active-wallet
// store on state transitions. These tests pin the command names + args and the
// unlock/lock refresh behavior (invoke mocked — no Tauri runtime).
import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args) => invoke(...args) }));

const {
  listWallets,
  createWallet,
  importWallet,
  unlock,
  lock,
  activeWallet,
  removeWallet,
  getUnlockProgress,
} = await import("./wallet.js");
const { shouldRemask, sortWalletsActiveFirst } = await import("../tabs/Wallet.jsx");

beforeEach(() => {
  invoke.mockReset();
  invoke.mockResolvedValue(undefined);
});

describe("command wrappers", () => {
  it("listWallets → wallet_list", async () => {
    invoke.mockResolvedValue([{ name: "a", address: "0xabc" }]);
    await expect(listWallets()).resolves.toEqual([{ name: "a", address: "0xabc" }]);
    expect(invoke).toHaveBeenCalledWith("wallet_list");
  });

  it("createWallet → wallet_create with name+password", async () => {
    invoke.mockResolvedValue({ name: "a", address: "0xabc" });
    await createWallet("a", "pw12345678");
    expect(invoke).toHaveBeenCalledWith("wallet_create", { name: "a", password: "pw12345678" });
  });

  it("importWallet → wallet_import with camelCase privateKeyHex", async () => {
    invoke.mockResolvedValue({ name: "a", address: "0xabc" });
    await importWallet("a", "pw12345678", "0xkey");
    expect(invoke).toHaveBeenCalledWith("wallet_import", {
      name: "a",
      password: "pw12345678",
      privateKeyHex: "0xkey",
    });
  });

  it("activeWallet → wallet_active", async () => {
    invoke.mockResolvedValue(null);
    await expect(activeWallet()).resolves.toBeNull();
    expect(invoke).toHaveBeenCalledWith("wallet_active");
  });

  it("unlock invokes wallet_unlock then refreshes via wallet_active", async () => {
    invoke.mockImplementation((cmd) =>
      cmd === "wallet_unlock" ? Promise.resolve({ name: "a", address: "0xabc" }) : Promise.resolve(null)
    );
    const meta = await unlock("a", "pw12345678");
    expect(meta).toEqual({ name: "a", address: "0xabc" });
    expect(invoke).toHaveBeenCalledWith("wallet_unlock", { name: "a", password: "pw12345678" });
    expect(invoke).toHaveBeenCalledWith("wallet_active");
  });

  it("unlock progress stays pending mid-flight (survives Wallet tab remount)", async () => {
    let resolveUnlock;
    invoke.mockImplementation((cmd) => {
      if (cmd === "wallet_unlock") {
        return new Promise((resolve) => {
          resolveUnlock = resolve;
        });
      }
      return Promise.resolve({ name: "a", address: "0xabcdef0123456789" });
    });
    const pending = unlock("a", "pw12345678");
    expect(getUnlockProgress().status).toBe("pending");
    resolveUnlock({ name: "a", address: "0xabcdef0123456789" });
    await pending;
    expect(getUnlockProgress().status).toBe("success");
    expect(getUnlockProgress().message).toMatch(/Unlocked 0xabcd/i);
  });

  it("unlock progress records error without dropping pending mid-flight", async () => {
    invoke.mockImplementation((cmd) => {
      if (cmd === "wallet_unlock") return Promise.reject("wrong password");
      return Promise.resolve(null);
    });
    await expect(unlock("a", "bad")).rejects.toBe("wrong password");
    expect(getUnlockProgress()).toEqual({
      status: "error",
      message: "wrong password",
      name: "a",
    });
  });

  it("lock invokes wallet_lock then refreshes", async () => {
    await lock();
    expect(invoke).toHaveBeenCalledWith("wallet_lock");
    expect(invoke).toHaveBeenCalledWith("wallet_active");
  });

  it("removeWallet invokes wallet_remove then refreshes", async () => {
    await removeWallet("a", "pw12345678");
    expect(invoke).toHaveBeenCalledWith("wallet_remove", { name: "a", password: "pw12345678" });
    expect(invoke).toHaveBeenCalledWith("wallet_active");
  });
});

describe("sortWalletsActiveFirst (T27 P8: active wallet lists first)", () => {
  const list = [
    { name: "a", address: "0xA" },
    { name: "b", address: "0xB" },
    { name: "c", address: "0xC" },
  ];
  it("moves the active wallet to the front and keeps the rest in stored order", () => {
    expect(sortWalletsActiveFirst(list, "b").map((w) => w.name)).toEqual(["b", "a", "c"]);
    expect(list.map((w) => w.name)).toEqual(["a", "b", "c"]); // pure — input untouched
  });
  it("leaves the order unchanged when the active name is unknown or absent", () => {
    expect(sortWalletsActiveFirst(list, "nope").map((w) => w.name)).toEqual(["a", "b", "c"]);
    expect(sortWalletsActiveFirst(list, undefined).map((w) => w.name)).toEqual(["a", "b", "c"]);
  });
});

describe("shouldRemask (D1: auto re-mask on lock/switch)", () => {
  it("remasks when the wallet locks or switches", () => {
    expect(shouldRemask("0xA", null)).toBe(true); // locked
    expect(shouldRemask("0xA", "0xB")).toBe(true); // switched
  });
  it("stays as-is while the same wallet stays unlocked", () => {
    expect(shouldRemask("0xA", "0xA")).toBe(false);
    expect(shouldRemask(null, "0xA")).toBe(false); // fresh unlock: still masked by default
  });
});
