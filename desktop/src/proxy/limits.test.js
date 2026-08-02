import { describe, expect, it } from "vitest";
import {
  BYTES_PER_GB,
  BYTES_PER_KBPS,
  DEFAULT_DAILY_CAP_GB,
  DEFAULT_THROTTLE_KBPS,
  MAX_DAILY_CAP_GB,
  MAX_THROTTLE_KBPS,
  MAX_WINDOWS,
  MIN_DAILY_CAP_GB,
  MIN_THROTTLE_KBPS,
  ceilingBytes,
  clampLimits,
  effectiveCeilingBytes,
  minuteOfWeek,
  scheduleAdmits,
  throttleBytesPerSec,
} from "./limits.js";

describe("proxy limits (UI bounds only -- the daemon is the enforcement)", () => {
  /// Mutations this detects: dropping either bound, or swapping the lo/hi arguments,
  /// which would render a range the daemon will silently overrule.
  it("clamps a hostile cap into range", () => {
    expect(clampLimits({ daily_cap_gb: 99_999 }).daily_cap_gb).toBe(MAX_DAILY_CAP_GB);
    expect(clampLimits({ daily_cap_gb: 0 }).daily_cap_gb).toBe(MIN_DAILY_CAP_GB);
    expect(clampLimits({ daily_cap_gb: -1 }).daily_cap_gb).toBe(MIN_DAILY_CAP_GB);
    // POSITIVE CONTROL: an in-range value passes through untouched.
    expect(clampLimits({ daily_cap_gb: 12 }).daily_cap_gb).toBe(12);
  });

  it("clamps throttle into range", () => {
    expect(clampLimits({ throttle_kbps: 1 }).throttle_kbps).toBe(MIN_THROTTLE_KBPS);
    expect(clampLimits({ throttle_kbps: 10_000_000 }).throttle_kbps).toBe(MAX_THROTTLE_KBPS);
    expect(clampLimits({ throttle_kbps: 4_096 }).throttle_kbps).toBe(4_096);
  });

  /// Mutations this detects: `>=` instead of `>` on the window bound (a zero-length
  /// window that renders as "active"), or dropping the truncate (an unbounded list
  /// the daemon will cut anyway, so the screen and the daemon disagree).
  it("drops inverted windows and truncates beyond the maximum", () => {
    const many = Array.from({ length: 12 }, (_, i) => ({
      start_min_local: i * 60,
      end_min_local: i * 60 + 30,
      days_mask: 0x7f,
    }));
    many.push({ start_min_local: 600, end_min_local: 600, days_mask: 0x7f });
    const c = clampLimits({ windows: many });
    expect(c.windows).toHaveLength(MAX_WINDOWS);
    expect(c.windows.every((w) => w.end_min_local > w.start_min_local)).toBe(true);
    expect(clampLimits({ windows: [{ start_min_local: 120, end_min_local: 60, days_mask: 0x7f }] }).windows).toHaveLength(
      0,
    );
    expect(clampLimits({ windows: [{ start_min_local: 0, end_min_local: 60, days_mask: 0 }] }).windows).toHaveLength(0);
  });

  /// Mutations this detects: `Boolean(src.enabled)` instead of `=== true`. The switch
  /// state arrives from IPC as JSON; a truthy string would turn egress on.
  it("enabled is never truthy-coerced from a non-boolean", () => {
    for (const v of ["yes", 1, "true", {}, []]) expect(clampLimits({ enabled: v }).enabled).toBe(false);
    // POSITIVE CONTROL: a real boolean still works.
    expect(clampLimits({ enabled: true }).enabled).toBe(true);
  });

  it("an empty schedule admits every minute", () => {
    const l = clampLimits({});
    expect(scheduleAdmits(l, 0)).toBe(true);
    expect(scheduleAdmits(l, 10_079)).toBe(true);
  });

  /// Mutations this detects: `<=` on the end bound (egress one minute past the window),
  /// or dropping the day-mask test (the same clock hour on every day of the week).
  it("a window admits only inside its own minutes and days", () => {
    const l = clampLimits({ windows: [{ start_min_local: 60, end_min_local: 120, days_mask: 0x01 }] });
    expect(scheduleAdmits(l, 59)).toBe(false);
    expect(scheduleAdmits(l, 60)).toBe(true);
    expect(scheduleAdmits(l, 119)).toBe(true);
    expect(scheduleAdmits(l, 120)).toBe(false);
    expect(scheduleAdmits(l, 1_500)).toBe(false); // same clock time, different day bit
  });

  it("minuteOfWeek treats Monday as day zero", () => {
    expect(minuteOfWeek(new Date(2026, 6, 27, 0, 0))).toBe(0); // Monday
    expect(minuteOfWeek(new Date(2026, 6, 26, 23, 59))).toBe(6 * 1_440 + 1_439); // Sunday
  });

  it("byte conversions are declared once and are the ones the record carries", () => {
    expect(ceilingBytes({ daily_cap_gb: 5 })).toBe(5 * BYTES_PER_GB);
    expect(throttleBytesPerSec({ throttle_kbps: 2_048 })).toBe(2_048 * BYTES_PER_KBPS);
    expect(clampLimits({}).daily_cap_gb).toBe(DEFAULT_DAILY_CAP_GB);
    expect(clampLimits({}).throttle_kbps).toBe(DEFAULT_THROTTLE_KBPS);
  });

  /// Mutations this detects: rendering the configured ceiling instead of
  /// min(consented, configured). Raising the control above the signed ceiling must
  /// change the number on screen by nothing at all, because it changes the daemon's
  /// answer by nothing at all.
  it("the rendered ceiling is min(consented, configured), never the control alone", () => {
    const consented = 5 * BYTES_PER_GB;
    expect(effectiveCeilingBytes(consented, { daily_cap_gb: 200 })).toBe(consented);
    expect(effectiveCeilingBytes(consented, { daily_cap_gb: 2 })).toBe(2 * BYTES_PER_GB);
    // Nothing signed means nothing runs, so there is no ceiling in force to show.
    expect(effectiveCeilingBytes(0, { daily_cap_gb: 200 })).toBe(0);
    expect(effectiveCeilingBytes(undefined, { daily_cap_gb: 200 })).toBe(0);
  });
});
