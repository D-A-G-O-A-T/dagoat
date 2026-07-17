// Deterministic manifest canonicalization for WorkMinter.mintBatch's
// `manifestRoot` argument (Ops tab, task S9).
//
// The founder reviews a batch of pending units pulled from journal.js
// (order = whatever the store happened to persist them in) and the UI must
// hash EXACTLY the same bytes every time the same unit set is accepted —
// regardless of array order — so two runs (or two founders comparing notes)
// never disagree on what was minted. That rules out JSON.stringify on the
// raw array: it is order-preserving, not order-canonical. This module is a
// small hand-rolled canonical-JSON serializer instead: sort by unit_id, fix
// the key order per unit, no whitespace.
import { keccak256, stringToBytes } from "viem";

function jsonString(value) {
  return JSON.stringify(String(value ?? ""));
}

// weight is a small integer work-unit count in Season-0 (never fractional);
// reject non-finite input so a corrupted journal entry can't silently
// poison a manifest that's about to authorize a mint.
function jsonNumber(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) throw new Error(`Invalid unit weight: ${value}`);
  return String(n);
}

// Fixed key order (unit_id, weight, evidence) — only these three fields are
// part of the manifest. journal.js's bookkeeping fields (backend_ref, at,
// backendId, mintedInBatch) are deliberately excluded: they're local
// provenance, not part of what was accepted for mint.
function canonicalUnitJson(unit) {
  return `{"unit_id":${jsonString(unit.unit_id)},"weight":${jsonNumber(unit.weight)},"evidence":${jsonString(unit.evidence)}}`;
}

/// Canonical JSON string for a manifest: `{"jobId":"...","units":[...]}`,
/// units sorted by unit_id ascending, no whitespace anywhere. Any
/// permutation of the same unit set (and any extra fields on each unit
/// object) always produces the identical string.
export function canonicalManifestJson(jobIdStr, units) {
  const sorted = [...(units ?? [])].sort((a, b) => {
    if (a.unit_id < b.unit_id) return -1;
    if (a.unit_id > b.unit_id) return 1;
    return 0;
  });
  const unitsJson = sorted.map(canonicalUnitJson).join(",");
  return `{"jobId":${jsonString(jobIdStr)},"units":[${unitsJson}]}`;
}

/// keccak256 of the canonical manifest JSON — this is the `manifestRoot`
/// argument to WorkMinter.mintBatch. Order-insensitive: any permutation of
/// the same unit set hashes identically; a different unit set (different
/// ids, weights, or evidence) hashes differently.
export function computeManifestRoot(jobIdStr, units) {
  return keccak256(stringToBytes(canonicalManifestJson(jobIdStr, units)));
}
