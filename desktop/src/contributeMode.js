/** Contribute dual-mode (P3-direct). Default follows onboarding: wallet-onboarded
 *  users are with_goat until they explicitly opt out (D4). */

import { createContext, useContext } from "react";
import { readAppState, writeAppState } from "./onboarding/appState.js";

export const MODE_PUBLIC_GOOD = "public_good";
export const MODE_WITH_GOAT = "with_goat";

export const CONTRIBUTE_MODE_KEY = "contribute_mode_v2";
const LEGACY_LS_KEY = "goat_contribute_mode";

/** Tri-state resolution (spec §10): explicit user choice wins; otherwise the
 *  onboarding choice decides (wallet → with_goat, anything else → public_good). */
export function resolveEffectiveMode(explicit, choice) {
  if (explicit === MODE_WITH_GOAT || explicit === MODE_PUBLIC_GOOD) return explicit;
  return choice === "wallet" ? MODE_WITH_GOAT : MODE_PUBLIC_GOOD;
}

/** Load { explicit, effective }. Runs the one-time localStorage → store migration. */
export async function loadContributeModeV2(onboardingChoice) {
  let explicit = await readAppState(CONTRIBUTE_MODE_KEY, null);
  if (explicit !== MODE_WITH_GOAT && explicit !== MODE_PUBLIC_GOOD) explicit = null;
  if (explicit === null) {
    try {
      const legacy = localStorage.getItem(LEGACY_LS_KEY);
      if (legacy === MODE_WITH_GOAT || legacy === MODE_PUBLIC_GOOD) {
        explicit = legacy;
        const ok = await writeAppState(CONTRIBUTE_MODE_KEY, legacy);
        if (ok) localStorage.removeItem(LEGACY_LS_KEY);
      }
    } catch { /* storage unavailable — stay tri-state null */ }
  }
  return { explicit, effective: resolveEffectiveMode(explicit, onboardingChoice) };
}

export function saveContributeModeV2(mode) {
  return writeAppState(CONTRIBUTE_MODE_KEY, mode);
}

export function isGoatPilotMode(mode) {
  return mode === MODE_WITH_GOAT;
}

export const ContributeModeContext = createContext({
  mode: MODE_PUBLIC_GOOD,
  setMode: () => {},
  goatPilot: false,
});

export function useContributeMode() {
  return useContext(ContributeModeContext);
}
