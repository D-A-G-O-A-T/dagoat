// Founder rule (spec §7): a unit is "stuck" only after ≥30 continuous seconds at
// 0% progress. Per-row dump buttons key off this — the global dump is retired.
// After the threshold, Contribute auto-dumps (with cooldown) so the user need not click.
export const STUCK_THRESHOLD_MS = 30_000;
/** Min gap between auto-dump attempts for the same unit id (avoids dump loops). */
export const AUTO_DUMP_COOLDOWN_MS = 60_000;

export function createStuckTracker(thresholdMs = STUCK_THRESHOLD_MS) {
  const zeroSince = new Map(); // row_key → first-seen-at-zero ms
  return {
    observe(units, nowMs) {
      const stuck = new Map();
      const seen = new Set();
      for (const unit of units) {
        const key = unit.row_key ?? unit.id;
        seen.add(key);
        if (Number(unit.progress) > 0) {
          zeroSince.delete(key);
          stuck.set(key, false);
          continue;
        }
        if (!zeroSince.has(key)) zeroSince.set(key, nowMs);
        stuck.set(key, nowMs - zeroSince.get(key) >= thresholdMs);
      }
      for (const key of [...zeroSince.keys()]) if (!seen.has(key)) zeroSince.delete(key);
      return stuck;
    },
  };
}

/**
 * Pure: unit ids that should auto-dump now (stuck + past cooldown).
 * @param {Array<{ id?: string, row_key?: string }>} units
 * @param {Map<string, boolean>} stuckMap
 * @param {Map<string, number>} lastAttemptById unitId → last auto-dump attempt ms
 * @param {number} nowMs
 * @param {number} [cooldownMs]
 * @returns {string[]}
 */
export function selectAutoDumpUnitIds(
  units,
  stuckMap,
  lastAttemptById,
  nowMs,
  cooldownMs = AUTO_DUMP_COOLDOWN_MS,
) {
  const out = [];
  for (const unit of units ?? []) {
    const id = unit?.id;
    if (!id) continue;
    const key = unit.row_key ?? id;
    if (stuckMap?.get(key) !== true) continue;
    const last = lastAttemptById?.get(id) ?? 0;
    if (nowMs - last < cooldownMs) continue;
    out.push(id);
  }
  return out;
}
