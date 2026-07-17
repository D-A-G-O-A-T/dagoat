// wallet.js wraps the Rust wallet_* commands and refreshes the active-wallet
// store on state transitions. These tests pin the command names + args and the
// unlock/lock refresh behavior (invoke mocked — no Tauri runtime).
import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args) => invoke(...args) }));

const { listWallets, createWallet, importWallet, unlock, lock, activeWallet, removeWallet } = await import(
  "./wallet.js"
);

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
