import { beforeEach, describe, expect, it, vi } from "vitest";

const store = new Map();
vi.mock("./onboarding/appState.js", () => ({
  readAppState: async (key, fallback) => (store.has(key) ? store.get(key) : fallback),
  writeAppState: async (key, value) => {
    store.set(key, value);
    return true;
  },
}));

const {
  normalizeWalletAddress,
  getWalletFahProfile,
  saveWalletFahProfile,
  bindWalletFahProfile,
  syncFahProfileForWallet,
  WALLET_FAH_PROFILES_KEY,
} = await import("./walletProfiles.js");

beforeEach(() => {
  store.clear();
});

describe("normalizeWalletAddress", () => {
  it("lowercases and trims", () => {
    expect(normalizeWalletAddress(" 0xAbC ")).toBe("0xabc");
  });
});

describe("save/get profile", () => {
  it("round-trips by address (case-insensitive)", async () => {
    await saveWalletFahProfile("0xAA", { username: "GOAT-Rookie", passkey: "ab".repeat(16) });
    expect(await getWalletFahProfile("0xaa")).toEqual({
      username: "GOAT-Rookie",
      passkey: "ab".repeat(16),
    });
    expect(store.get(WALLET_FAH_PROFILES_KEY)["0xaa"].username).toBe("GOAT-Rookie");
  });
});

describe("bindWalletFahProfile", () => {
  it("configures FAH then stores the profile", async () => {
    const calls = [];
    const invokeFn = vi.fn(async (cmd, args) => calls.push([cmd, args]));
    await bindWalletFahProfile(
      "0xbb",
      { username: "GOAT-Bob", passkey: "cd".repeat(16) },
      invokeFn,
    );
    expect(calls.some((c) => c[0] === "backend_configure" && c[1].key === "username")).toBe(true);
    expect(await getWalletFahProfile("0xBB")).toEqual({
      username: "GOAT-Bob",
      passkey: "cd".repeat(16),
    });
  });
});

describe("syncFahProfileForWallet", () => {
  it("applies the stored profile for the unlocked wallet", async () => {
    await saveWalletFahProfile("0xalice", { username: "GOAT-Rookie", passkey: "11".repeat(16) });
    await saveWalletFahProfile("0xbob", { username: "GOAT-Bob", passkey: "22".repeat(16) });
    const calls = [];
    const invokeFn = vi.fn(async (cmd, args) => {
      calls.push([cmd, args]);
      if (cmd === "backend_fah_identity") return { username: "GOAT-Rookie", passkey: "11".repeat(16) };
    });

    await syncFahProfileForWallet("0xbob", invokeFn);
    const userCalls = calls.filter((c) => c[0] === "backend_configure" && c[1].key === "username");
    expect(userCalls.at(-1)[1].value).toBe("GOAT-Bob");

    await syncFahProfileForWallet("0xalice", invokeFn);
    const afterAlice = calls.filter((c) => c[0] === "backend_configure" && c[1].key === "username");
    expect(afterAlice.at(-1)[1].value).toBe("GOAT-Rookie");
  });

  it("does NOT seed Bob from live Rookie when Alice already has a profile (stuck-Bob bug)", async () => {
    await saveWalletFahProfile("0xalice", { username: "GOAT-Rookie", passkey: "aa".repeat(16) });
    const invokeFn = vi.fn(async (cmd) => {
      if (cmd === "backend_fah_identity") {
        return { username: "GOAT-Rookie", passkey: "aa".repeat(16) };
      }
    });
    const out = await syncFahProfileForWallet("0xbob", invokeFn);
    expect(out).toBeNull();
    expect(await getWalletFahProfile("0xbob")).toBeNull();
  });

  it("does NOT seed when multiple wallets exist even if the map is empty", async () => {
    const invokeFn = vi.fn(async (cmd) => {
      if (cmd === "backend_fah_identity") {
        return { username: "GOAT-Rookie", passkey: "aa".repeat(16) };
      }
    });
    const out = await syncFahProfileForWallet("0xbob", invokeFn, { walletCount: 2 });
    expect(out).toBeNull();
    expect(await getWalletFahProfile("0xbob")).toBeNull();
  });

  it("legacy seed: empty map + sole wallet + live FAH username", async () => {
    const invokeFn = vi.fn(async (cmd) => {
      if (cmd === "backend_fah_identity") {
        return { username: "GOAT-Rookie", passkey: "ff".repeat(16) };
      }
      return undefined;
    });
    // Chain checked, no bind found — proves chain-precedence doesn't interfere with legacy
    // seeding when chain has nothing to say.
    const readBoundUsername = vi.fn(async () => null);
    const out = await syncFahProfileForWallet("0xalice", invokeFn, {
      walletCount: 1,
      networkId: 31337,
      readBoundUsername,
    });
    expect(out).toEqual({ username: "GOAT-Rookie", passkey: "ff".repeat(16) });
    expect(await getWalletFahProfile("0xalice")).toEqual({
      username: "GOAT-Rookie",
      passkey: "ff".repeat(16),
    });
  });
});

describe("chain-wins resolution", () => {
  it("adopts and persists the chain username when it differs from the stored local profile", async () => {
    await saveWalletFahProfile("0xalice", { username: "GOAT-Rookie", passkey: "11".repeat(16) });
    const readBoundUsername = vi.fn(async () => "GOAT-ChainName");
    const out = await syncFahProfileForWallet("0xalice", vi.fn(), {
      networkId: 31337,
      readBoundUsername,
    });
    expect(out).toEqual({ username: "GOAT-ChainName", passkey: "11".repeat(16) });
    expect(await getWalletFahProfile("0xalice")).toEqual({
      username: "GOAT-ChainName",
      passkey: "11".repeat(16),
    });
  });

  it("falls through to local/seed resolution unaffected when the chain read throws", async () => {
    await saveWalletFahProfile("0xalice", { username: "GOAT-Rookie", passkey: "11".repeat(16) });
    const readBoundUsername = vi.fn(async () => {
      throw new Error("RPC down");
    });
    const out = await syncFahProfileForWallet("0xalice", vi.fn(), {
      networkId: 31337,
      readBoundUsername,
    });
    expect(out).toEqual({ username: "GOAT-Rookie", passkey: "11".repeat(16) });
  });

  it("leaves the local profile unchanged when chain returns null (no bind)", async () => {
    await saveWalletFahProfile("0xalice", { username: "GOAT-Rookie", passkey: "11".repeat(16) });
    const readBoundUsername = vi.fn(async () => null);
    const out = await syncFahProfileForWallet("0xalice", vi.fn(), {
      networkId: 31337,
      readBoundUsername,
    });
    expect(out).toEqual({ username: "GOAT-Rookie", passkey: "11".repeat(16) });
    expect(await getWalletFahProfile("0xalice")).toEqual({
      username: "GOAT-Rookie",
      passkey: "11".repeat(16),
    });
  });

  it("adopts the chain username as a brand-new profile when no local profile exists", async () => {
    const readBoundUsername = vi.fn(async () => "GOAT-ChainOnly");
    const out = await syncFahProfileForWallet("0xnewwallet", vi.fn(), {
      networkId: 31337,
      readBoundUsername,
    });
    expect(out).toEqual({ username: "GOAT-ChainOnly", passkey: "" });
    expect(await getWalletFahProfile("0xnewwallet")).toEqual({
      username: "GOAT-ChainOnly",
      passkey: "",
    });
  });
});
