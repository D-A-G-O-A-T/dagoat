import { describe, expect, it } from "vitest";
import { settledPartition, settledValues } from "./safeAll.js";

describe("settledValues", () => {
  it("returns only fulfilled values in order", async () => {
    const out = await settledValues([
      Promise.resolve("a"),
      Promise.reject(new Error("nope")),
      Promise.resolve("c"),
    ]);
    expect(out).toEqual(["a", "c"]);
  });

  it("can map rejections via onRejected", async () => {
    const out = await settledValues([Promise.reject(new Error("x")), Promise.resolve(2)], {
      onRejected: () => -1,
    });
    expect(out).toEqual([-1, 2]);
  });
});

describe("settledPartition", () => {
  it("keeps slots aligned with nulls on failure", async () => {
    const { values, errors, okCount, failCount } = await settledPartition([
      Promise.resolve(10),
      Promise.reject(new Error("boom")),
      Promise.resolve(30),
    ]);
    expect(values).toEqual([10, null, 30]);
    expect(errors[0]).toBe(null);
    expect(String(errors[1])).toMatch(/boom/);
    expect(okCount).toBe(2);
    expect(failCount).toBe(1);
  });
});
