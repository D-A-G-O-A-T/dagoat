// UI-side bounds. These exist so the controls render honest ranges -- they are NOT the
// enforcement. The daemon re-clamps on every write and re-reads the file on every
// request, and it additionally takes min(consented, configured), so nothing typed into
// this window can raise a ceiling the operator signed.
export const MIN_DAILY_CAP_GB = 1;
export const MAX_DAILY_CAP_GB = 200;
export const DEFAULT_DAILY_CAP_GB = 5;
export const MIN_THROTTLE_KBPS = 64;
export const MAX_THROTTLE_KBPS = 100_000;
export const DEFAULT_THROTTLE_KBPS = 2_048;
export const MAX_WINDOWS = 7;
export const LIMITS_SCHEMA = 1;

/** GB on the control, bytes in the record. One conversion, declared once. */
export const BYTES_PER_GB = 1_000_000_000;
/** kbps on the control, bytes per second in the record: 1000 bits / 8 = 125 bytes. */
export const BYTES_PER_KBPS = 125;

function clampNumber(v, lo, hi, fallback) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(hi, Math.max(lo, Math.round(n)));
}

export function clampLimits(input) {
  const src = input && typeof input === "object" ? input : {};
  const windows = Array.isArray(src.windows) ? src.windows : [];
  return {
    enabled: src.enabled === true,
    daily_cap_gb: clampNumber(src.daily_cap_gb, MIN_DAILY_CAP_GB, MAX_DAILY_CAP_GB, DEFAULT_DAILY_CAP_GB),
    throttle_kbps: clampNumber(src.throttle_kbps, MIN_THROTTLE_KBPS, MAX_THROTTLE_KBPS, DEFAULT_THROTTLE_KBPS),
    windows: windows
      .map((w) => ({
        start_min_local: clampNumber(w?.start_min_local, 0, 1_439, 0),
        end_min_local: clampNumber(w?.end_min_local, 1, 1_440, 1_440),
        days_mask: clampNumber(w?.days_mask, 0, 0x7f, 0x7f),
      }))
      .filter((w) => w.end_min_local > w.start_min_local && (w.days_mask & 0x7f) !== 0)
      .slice(0, MAX_WINDOWS),
    schema: LIMITS_SCHEMA,
  };
}

export function scheduleAdmits(limits, minuteOfWeek) {
  if (!limits.windows.length) return true;
  const day = Math.floor(minuteOfWeek / 1_440);
  const minute = minuteOfWeek % 1_440;
  return limits.windows.some(
    (w) => ((w.days_mask >> day) & 1) === 1 && minute >= w.start_min_local && minute < w.end_min_local,
  );
}

/** Minute-of-week for a Date, Monday = 0. Local clock, matching the operator's own hours. */
export function minuteOfWeek(date) {
  const day = (date.getDay() + 6) % 7;
  return day * 1_440 + date.getHours() * 60 + date.getMinutes();
}

export function ceilingBytes(limits) {
  return clampLimits(limits).daily_cap_gb * BYTES_PER_GB;
}

export function throttleBytesPerSec(limits) {
  return clampLimits(limits).throttle_kbps * BYTES_PER_KBPS;
}

/**
 * What the daemon will actually enforce: `min(consented, configured)`.
 *
 * Rendering the configured number alone would be a lie whenever the operator raised
 * the control above what they signed -- the control moves, the ceiling does not.
 * A zero or absent consented value means nothing has been signed, and nothing signed
 * means no ceiling at all is in force because nothing runs.
 */
export function effectiveCeilingBytes(consentedBytes, limits) {
  const consented = Number(consentedBytes ?? 0);
  if (!Number.isFinite(consented) || consented <= 0) return 0;
  return Math.min(consented, ceilingBytes(limits));
}
