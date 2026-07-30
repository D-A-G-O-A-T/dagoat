import { describe, expect, it } from "vitest";
import { pickWalletForUnlock } from "./UnlockWalletOverlay.jsx";

describe("pickWalletForUnlock", () => {
  const list = [
    { name: "Alice", address: "0xA" },
    { name: "Bob", address: "0xB" },
  ];

  it("prefers the last-used wallet when still present", () => {
    expect(pickWalletForUnlock(list, "Bob")?.name).toBe("Bob");
  });

  it("falls back to the first wallet when last-used is unknown", () => {
    expect(pickWalletForUnlock(list, "Missing")?.name).toBe("Alice");
    expect(pickWalletForUnlock(list, null)?.name).toBe("Alice");
  });

  it("returns null for an empty list", () => {
    expect(pickWalletForUnlock([], "Bob")).toBeNull();
    expect(pickWalletForUnlock(null, "Bob")).toBeNull();
  });
});
