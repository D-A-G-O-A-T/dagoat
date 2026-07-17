/** Contribute dual-mode (P3-direct). Default = public good only; GOAT pilot is opt-in. */

import { createContext, useContext } from "react";

export const MODE_PUBLIC_GOOD = "public_good";
export const MODE_WITH_GOAT = "with_goat";

const KEY = "goat_contribute_mode";

export function loadContributeMode() {
  try {
    return localStorage.getItem(KEY) === MODE_WITH_GOAT ? MODE_WITH_GOAT : MODE_PUBLIC_GOOD;
  } catch {
    return MODE_PUBLIC_GOOD;
  }
}

export function saveContributeMode(mode) {
  try {
    localStorage.setItem(KEY, mode);
  } catch {
    /* private mode / unavailable storage — mode still works in-session via React state */
  }
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
