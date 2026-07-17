// Durable pending-units journal — at-most-once contract for WorkBackend completions.
//
// backend_completions advances the adapter baseline and never redelivers units, so the
// caller MUST persist returned units before using them for anything else (render, mint, …).
// Pattern mirrors chain/client.js: Tauri plugin-store, lazy memoized handle, explicit save.
import { load } from "@tauri-apps/plugin-store";

const STORE_FILE = "pending-units.dat";
const PENDING_KEY = "pending";

// Lazily-created, memoized so repeated load/append/markMinted share one open handle.
let storePromise = null;
function getStore() {
  if (!storePromise) {
    storePromise = load(STORE_FILE, { autoSave: false });
  }
  return storePromise;
}

/// Returns the persisted pending-units array, or [] if nothing stored yet.
export async function loadPending() {
  const store = await getStore();
  const pending = await store.get(PENDING_KEY);
  return Array.isArray(pending) ? pending : [];
}

/// Appends newly completed WorkUnits, deduped by unit_id. Persists before returning.
/// Callers must update React state only from this return value — never from the raw
/// backend_completions result.
export async function appendPending(units, backendId) {
  const store = await getStore();
  const existing = await loadPending();
  const seen = new Set(existing.map((e) => e.unit_id));
  const next = [...existing];
  for (const unit of units ?? []) {
    if (!unit || seen.has(unit.unit_id)) continue;
    seen.add(unit.unit_id);
    next.push({
      unit_id: unit.unit_id,
      weight: unit.weight,
      backend_ref: unit.backend_ref,
      at: unit.at,
      evidence: unit.evidence,
      backendId,
      mintedInBatch: null,
    });
  }
  await store.set(PENDING_KEY, next);
  await store.save();
  return next;
}

/// Stamps matching unit_ids with mintedInBatch = batchId. Persists and returns the full list.
///
/// On a failed durable save (e.g. a transient disk error — S9 fix b), rolls the in-memory
/// store back to its pre-stamp state and re-throws: the units must read back as still
/// pending, not silently "minted" in this session, so a retry is safe (it lands on
/// WorkMinter.usedManifest -> stamp-only, never a second on-chain mint attempt).
export async function markMinted(unitIds, batchId) {
  const store = await getStore();
  const existing = await loadPending();
  const idSet = new Set(unitIds ?? []);
  const next = existing.map((entry) =>
    idSet.has(entry.unit_id) ? { ...entry, mintedInBatch: batchId } : entry
  );
  try {
    await store.set(PENDING_KEY, next);
    await store.save();
  } catch (error) {
    await store.set(PENDING_KEY, existing);
    throw error;
  }
  return next;
}
