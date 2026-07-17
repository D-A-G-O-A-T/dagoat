// Never-drop retry logic for the Miner's completions journal write.
//
// backend_completions (the FAH adapter's list_completions) durably advances the adapter's
// baseline the moment it returns units — those units can never be re-derived from the
// backend again. If the UI's journal store.save() then throws (e.g. a transient disk error),
// the units must NOT be discarded: they stay in a React "unsaved" buffer, re-attempted every
// 10s and on a manual retry, until appendPending durably persists them. Extracted from
// Miner.jsx so this contract is testable without a DOM/React renderer.
import { appendPending } from "./journal.js";

export const RETRY_INTERVAL_MS = 10_000;

/// One save attempt. Never throws: on failure the caller must hold `units` in an
/// unsaved-units buffer and retry — the units must never be dropped from state.
export async function attemptSavePending(units, backendId) {
  try {
    const journal = await appendPending(units, backendId);
    return { saved: true, journal };
  } catch (error) {
    return { saved: false, error };
  }
}

/// Merge newly-unsaved units into an existing buffer, deduped by unit_id (mirrors the
/// journal's own dedup so a stuck unit is never queued twice across retries). Each buffered
/// unit remembers which backend it came from so a later retry can be grouped and replayed
/// through the correct `appendPending(units, backendId)` call even if the buffer ends up
/// holding units from more than one backend at once.
export function mergeUnsaved(buffer, units, backendId) {
  const seen = new Set(buffer.map((u) => u.unit_id));
  const merged = [...buffer];
  for (const unit of units ?? []) {
    if (!unit || seen.has(unit.unit_id)) continue;
    seen.add(unit.unit_id);
    merged.push({ ...unit, backendId });
  }
  return merged;
}

/// Groups a flat unsaved buffer back into per-backend batches, preserving first-seen order.
export function groupByBackend(buffer) {
  const order = [];
  const groups = new Map();
  for (const unit of buffer) {
    if (!groups.has(unit.backendId)) {
      groups.set(unit.backendId, []);
      order.push(unit.backendId);
    }
    groups.get(unit.backendId).push(unit);
  }
  return order.map((backendId) => ({ backendId, units: groups.get(backendId) }));
}

/// Retries every backend-group in the buffer once. Returns the units that are STILL unsaved
/// (never drops a unit that didn't durably save this attempt) plus the latest successful
/// journal snapshot, if any group saved. Used by both the 10s auto-retry interval and the
/// manual "Retry save" button, so both paths exercise identical logic.
export async function retryUnsaved(buffer) {
  let stillUnsaved = [];
  let latestJournal = null;
  for (const { backendId, units } of groupByBackend(buffer)) {
    const result = await attemptSavePending(units, backendId);
    if (result.saved) {
      latestJournal = result.journal;
    } else {
      stillUnsaved = stillUnsaved.concat(units);
    }
  }
  return { stillUnsaved, latestJournal };
}
