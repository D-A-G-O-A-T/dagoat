import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

// Verified against build_registry() in desktop/src-tauri/src/workbackend/mod.rs — the FAH
// adapter is registered under this key (not "fah").
const FAH_BACKEND_ID = "folding_at_home";

// Every Goat worker folds under a GOAT-namespaced FAH username (founder direction 2026-07-14):
// the prefix keeps Goat names in their own space (away from the general FAH population) and the
// full string is the on-chain binding to the worker's wallet — the basis for attributing their
// public FAH score to the right wallet. The user only picks the part AFTER the prefix.
export const GOAT_USERNAME_PREFIX = "GOAT-";

/** The user-typed part, cleaned to an FAH-safe token: letters, digits, underscore only; trimmed.
 *  Everything else is dropped so the resulting FAH username is always well-formed and matches what
 *  a challenger will read back from the public stats API. */
export function cleanCustomName(raw) {
  return (raw ?? "").trim().replace(/[^A-Za-z0-9_]/g, "");
}

/** The full FAH username Goat folds under = GOAT- prefix + the cleaned custom name. Empty custom
 *  yields "" (never a bare "GOAT-"). */
export function fullUsername(raw) {
  const custom = cleanCustomName(raw);
  return custom ? `${GOAT_USERNAME_PREFIX}${custom}` : "";
}

/** Ask only when identity has loaded AND no username is set. Null identity = still loading
 *  (or backend unavailable) — never flash the modal on a guess. */
export function needsFirstRun(identity) {
  if (!identity) return false;
  return !(identity.username ?? "").trim();
}

/** App.jsx-level gate: needsFirstRun() plus the "Later" dismissal. `dismissedThisSession` is
 *  plain React state the caller owns — nothing here reads from or writes to storage, so a fresh
 *  launch (fresh state, dismissedThisSession = false) always re-evaluates from identity alone. */
export function shouldShowFirstRun(identity, dismissedThisSession) {
  return !dismissedThisSession && needsFirstRun(identity);
}

/** Save-button enablement: a non-blank custom name (after cleaning), and not already mid-save. */
export function canSubmit(name, saving = false) {
  return Boolean(cleanCustomName(name)) && !saving;
}

/** Persists the chosen username via the real backend_configure Tauri command. The stored value is
 *  the FULL `GOAT-<custom>` string (team defaults to GOAT 1068318; passkey is optional later).
 *  Extracted from the component so the invoke call + payload shape are unit-testable without rendering. */
export async function saveUsername(value, invokeFn = invoke) {
  const full = fullUsername(value);
  if (!full) return null;
  await invokeFn("backend_configure", { id: FAH_BACKEND_ID, key: "username", value: full });
  return full;
}

/** One-time first-run prompt: the only thing Goat needs from the user is the custom part of their
 *  GOAT-namespaced Folding@home username (team defaults to GOAT 1068318). Optional passkey and
 *  gasless wallet bind/enroll complete in the Contribute tab. "Later" defers to the next launch:
 *  session-only, nothing persisted, so it reappears. */
export default function FirstRunUsername({ onDone }) {
  const [name, setName] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const preview = fullUsername(name);

  function handleLater() {
    onDone(null);
  }

  async function handleSave(e) {
    e.preventDefault();
    if (!canSubmit(name, saving)) return;
    setSaving(true);
    setError("");
    try {
      const saved = await saveUsername(name);
      onDone(saved);
    } catch (err) {
      setError(err?.message ?? String(err));
      setSaving(false);
    }
  }

  return (
    <div
      className="firstrun-overlay"
      onKeyDown={(e) => {
        if (e.key === "Escape") handleLater();
      }}
    >
      <form className="firstrun-card" onSubmit={handleSave}>
        <h2>What&apos;s your username?</h2>
        <p className="muted">
          This is how Folding@home credits your science — and it&apos;s what binds your folding to{" "}
          <strong>your wallet</strong> for the pilot attribution path. Everyone folds under a{" "}
          <code>GOAT-</code> name, and it must be unique to you. Choose it carefully: change it later
          and pilot attribution pauses until it matches again.
        </p>
        <div className="firstrun-input-row">
          <span className="firstrun-prefix">{GOAT_USERNAME_PREFIX}</span>
          <input
            autoFocus
            type="text"
            placeholder="your name (letters, digits, _)"
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoComplete="off"
          />
        </div>
        <p className="firstrun-preview">
          You&apos;ll fold as <strong>{preview || "GOAT-…"}</strong>
        </p>
        <p className="muted firstrun-next-hint">
          After Save: open Contribute → optional passkey, then <strong>Bind &amp; enroll (gasless)</strong>{" "}
          with an unlocked wallet (testnet pilot).
        </p>
        {error && <p className="error-text">{error}</p>}
        <div className="firstrun-actions">
          <button type="submit" disabled={!canSubmit(name, saving)}>
            {saving ? "Saving…" : "Save"}
          </button>
          <button type="button" className="link-button" onClick={handleLater}>
            Later
          </button>
        </div>
      </form>
    </div>
  );
}
