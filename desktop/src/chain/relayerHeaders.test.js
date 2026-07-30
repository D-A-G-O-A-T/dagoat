import { describe, expect, it } from "vitest";
import { hasCloudflareAccessEnv, relayerAuthHeaders } from "./relayerHeaders.js";

describe("relayerAuthHeaders", () => {
  it("always sends Content-Type", () => {
    expect(relayerAuthHeaders({})).toEqual({ "Content-Type": "application/json" });
  });

  it("omits CF headers when either Access env is missing", () => {
    expect(relayerAuthHeaders({ VITE_CF_ACCESS_CLIENT_ID: "id-only" })).toEqual({
      "Content-Type": "application/json",
    });
    expect(relayerAuthHeaders({ VITE_CF_ACCESS_CLIENT_SECRET: "secret-only" })).toEqual({
      "Content-Type": "application/json",
    });
  });

  it("attaches both CF-Access headers when both envs are set (speed-bump only)", () => {
    const h = relayerAuthHeaders({
      VITE_CF_ACCESS_CLIENT_ID: " client-id ",
      VITE_CF_ACCESS_CLIENT_SECRET: " client-secret ",
    });
    expect(h["Content-Type"]).toBe("application/json");
    expect(h["CF-Access-Client-Id"]).toBe("client-id");
    expect(h["CF-Access-Client-Secret"]).toBe("client-secret");
  });

  it("hasCloudflareAccessEnv requires both", () => {
    expect(hasCloudflareAccessEnv({})).toBe(false);
    expect(hasCloudflareAccessEnv({ VITE_CF_ACCESS_CLIENT_ID: "x" })).toBe(false);
    expect(
      hasCloudflareAccessEnv({
        VITE_CF_ACCESS_CLIENT_ID: "x",
        VITE_CF_ACCESS_CLIENT_SECRET: "y",
      }),
    ).toBe(true);
  });
});
