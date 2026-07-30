import { describe, expect, it } from "vitest";
import {
  AUTO_DUMP_COOLDOWN_MS,
  createStuckTracker,
  selectAutoDumpUnitIds,
  STUCK_THRESHOLD_MS,
} from "./stuckUnits.js";

const u = (row_key, progress) => ({ row_key, progress });

describe("createStuckTracker (founder rule: stuck = ≥30 s continuous at 0%)", () => {
  it("not stuck before 30 s at 0%, stuck after", () => {
    const t = createStuckTracker();
    expect(t.observe([u("a", 0)], 0).get("a")).toBe(false);
    expect(t.observe([u("a", 0)], 29_999).get("a")).toBe(false);
    expect(t.observe([u("a", 0)], STUCK_THRESHOLD_MS).get("a")).toBe(true);
  });
  it("any progress resets the clock", () => {
    const t = createStuckTracker();
    t.observe([u("a", 0)], 0);
    t.observe([u("a", 0.01)], 10_000); // moved — reset
    expect(t.observe([u("a", 0)], 15_000).get("a")).toBe(false);
    expect(t.observe([u("a", 0)], 45_000).get("a")).toBe(true); // 30 s after 15 s re-zero
  });
  it("tracks rows independently and forgets vanished rows", () => {
    const t = createStuckTracker();
    t.observe([u("a", 0), u("b", 0.5)], 0);
    const m = t.observe([u("a", 0), u("b", 0.5)], 31_000);
    expect(m.get("a")).toBe(true);
    expect(m.get("b")).toBe(false);
    t.observe([u("b", 0.5)], 32_000);          // "a" vanished
    expect(t.observe([u("a", 0)], 33_000).get("a")).toBe(false); // fresh clock
  });
});

describe("selectAutoDumpUnitIds", () => {
  const units = [
    { id: "u1", row_key: "a", progress: 0 },
    { id: "u2", row_key: "b", progress: 0 },
  ];
  it("selects stuck units past cooldown", () => {
    const stuck = new Map([
      ["a", true],
      ["b", false],
    ]);
    expect(selectAutoDumpUnitIds(units, stuck, new Map(), 100_000)).toEqual(["u1"]);
  });
  it("respects per-unit cooldown", () => {
    const stuck = new Map([
      ["a", true],
      ["b", true],
    ]);
    const last = new Map([["u1", 100_000]]);
    expect(
      selectAutoDumpUnitIds(units, stuck, last, 100_000 + AUTO_DUMP_COOLDOWN_MS - 1),
    ).toEqual(["u2"]);
    expect(
      selectAutoDumpUnitIds(units, stuck, last, 100_000 + AUTO_DUMP_COOLDOWN_MS),
    ).toEqual(["u1", "u2"]);
  });
});
