// Pure boot-routing state machine (spec §5) + its persistence wrappers.
import { readAppState, writeAppState } from "./appState.js";

export const ONBOARDING_KEY = "onboarding";
export const DEFAULT_FLAGS = { disclaimerAccepted: false, completed: false, choice: null };

/** Boot decision. `flags` may be null (store failure). Rules (spec §5, §11):
 *  - a wallet on disk implies prior acceptance → shell, self-heal the flags;
 *  - otherwise: no acceptance → disclaimer; accepted but unfinished → wallet gate. */
export function routeBoot({ flags, walletCount }) {
  const f = flags ?? DEFAULT_FLAGS;
  if (walletCount > 0 && !f.completed) {
    return { screen: "shell", selfHeal: { disclaimerAccepted: true, completed: true, choice: "wallet" } };
  }
  if (!f.disclaimerAccepted) return { screen: "disclaimer", selfHeal: null };
  if (!f.completed) return { screen: "wallet_gate", selfHeal: null };
  return { screen: "shell", selfHeal: null };
}

export async function loadOnboardingFlags() {
  const v = await readAppState(ONBOARDING_KEY, null);
  return v && typeof v === "object" ? { ...DEFAULT_FLAGS, ...v } : null;
}

export function saveOnboardingFlags(flags) {
  return writeAppState(ONBOARDING_KEY, flags);
}
