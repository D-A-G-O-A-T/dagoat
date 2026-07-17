// Pure decision helper for the Ops tab's "Accept batch & mint" flow (S9 fix
// b: stamp-after-confirm hardening).
//
// WorkMinter now rejects a replayed manifestRoot on-chain (S9 fix a). That
// makes recovery safe: if a prior attempt's mintBatch landed on-chain but
// the local journal stamp (journal.markMinted) then failed, the units were
// mint on-chain and are stuck as "pending" locally. A retry must detect
// that (via WorkMinter.usedManifest(manifestRoot)) and skip straight to
// re-stamping the journal instead of re-sending a doomed-to-revert mint.
// Extracted from Ops.jsx so this decision is testable without a DOM/React
// renderer.

/// alreadyUsed: the on-chain WorkMinter.usedManifest(manifestRoot) read (or
/// a caught ManifestReplayed revert from simulate — belt-and-braces).
/// Returns "stamp-only" when the manifest was already minted (skip
/// sending a tx, go straight to the journal stamp), else "mint".
export function planAcceptAction({ alreadyUsed }) {
  return alreadyUsed ? "stamp-only" : "mint";
}
