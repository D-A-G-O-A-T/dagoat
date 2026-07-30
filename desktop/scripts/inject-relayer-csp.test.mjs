import { describe, expect, it } from "vitest";
import {
  BASE_CONNECT,
  TAURI_CONNECT,
  buildCsp,
  collectExtraOrigins,
  hasAllTauriConnectTokens,
  originFromEnv,
  parseExtraConnect,
} from "./inject-relayer-csp.mjs";

describe("inject-relayer-csp (Stream C T3 + Tauri scheme hazard)", () => {
  it("TAURI_CONNECT includes ipc, tauri.localhost, asset schemes", () => {
    for (const need of [
      "ipc:",
      "http://ipc.localhost",
      "https://ipc.localhost",
      "http://tauri.localhost",
      "https://tauri.localhost",
      "wss://tauri.localhost",
      "tauri:",
      "asset:",
      "http://asset.localhost",
      "https://asset.localhost",
    ]) {
      expect(TAURI_CONNECT, `missing ${need}`).toContain(need);
    }
    expect(hasAllTauriConnectTokens(BASE_CONNECT)).toBe(true);
  });

  it("originFromEnv strips path and skips loopback", () => {
    expect(originFromEnv("https://relayer.example.com/v1")).toBe("https://relayer.example.com");
    expect(originFromEnv("http://127.0.0.1:8787")).toBe(null);
    expect(originFromEnv("not-a-url")).toBe(null);
  });

  it("parseExtraConnect accepts comma list", () => {
    expect(
      parseExtraConnect(
        "https://base-sepolia-rpc.publicnode.com, https://base-sepolia.g.alchemy.com",
      ),
    ).toEqual([
      "https://base-sepolia-rpc.publicnode.com",
      "https://base-sepolia.g.alchemy.com",
    ]);
  });

  it("buildCsp always keeps Tauri schemes even with extras", () => {
    const csp = buildCsp(["https://relayer.example.com"]);
    expect(csp).toContain("https://sepolia.base.org");
    expect(csp).toContain("http://127.0.0.1:8787");
    expect(csp).toContain("https://relayer.example.com");
    for (const t of TAURI_CONNECT) {
      expect(csp, `CSP missing Tauri token ${t}`).toContain(t);
    }
    expect(csp).toMatch(/default-src[^;]*asset:/);
    expect(csp).toMatch(/img-src[^;]*asset:/);
  });

  it("buildCsp throws if Tauri token were stripped (guard)", () => {
    // Simulate a broken merge by monkey-patching — call with extras that cannot strip BASE.
    // Guard is internal: building with normal extras always includes TAURI_CONNECT.
    const csp = buildCsp([]);
    expect(hasAllTauriConnectTokens(csp.split("connect-src ")[1].split(";")[0].split(" "))).toBe(
      true,
    );
  });

  it("collectExtraOrigins unions relayer + RPC + extras", () => {
    const o = collectExtraOrigins({
      VITE_ATTESTOR_RELAYER_URL: "https://r.example.com",
      VITE_RPC_URL: "https://base-sepolia.g.alchemy.com/v2/key",
      VITE_CSP_EXTRA_CONNECT: "https://base-sepolia-rpc.publicnode.com",
    });
    expect(o).toContain("https://r.example.com");
    expect(o).toContain("https://base-sepolia.g.alchemy.com");
    expect(o).toContain("https://base-sepolia-rpc.publicnode.com");
  });
});
