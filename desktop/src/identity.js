import { invoke } from "@tauri-apps/api/core";

// Verified against build_registry() in desktop/src-tauri/src/workbackend/mod.rs — the FAH
// adapter is registered under this key (not "fah").
export const FAH_BACKEND_ID = "folding_at_home";

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

export const TEAM_STATS_URL = "https://stats.foldingathome.org/team/1068318";
/** GOAT Folding@home team id — must match fah.rs DEFAULT_TEAM. */
export const GOAT_FAH_TEAM_ID = "1068318";

/** Optional FAH passkey: empty (base score works) OR exactly 32 hex chars (QRB bonus). */
export const PASSKEY_HEX_RE = /^[0-9a-fA-F]{32}$/;

export function isValidPasskeyInput(raw) {
  const v = (raw ?? "").trim();
  return v === "" || PASSKEY_HEX_RE.test(v);
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

/** 32-hex FAH identity token (16 random bytes). Honest copy rule (D2): this is
 *  an identity token we generate — never call it a "bonus" passkey. */
export function generatePasskey() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** One-shot identity write used by the wizard: username + passkey + locked team. */
export async function saveIdentity({ username, passkey }, invokeFn = invoke) {
  await invokeFn("backend_configure", { id: FAH_BACKEND_ID, key: "username", value: username });
  if (passkey) {
    await invokeFn("backend_configure", { id: FAH_BACKEND_ID, key: "passkey", value: passkey });
  }
  await invokeFn("backend_configure", { id: FAH_BACKEND_ID, key: "team", value: GOAT_FAH_TEAM_ID });
}
