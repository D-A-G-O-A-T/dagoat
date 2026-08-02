// Submit-enablement rule shared by the TWO import-wallet surfaces: the onboarding
// wizard step (onboarding/steps/ImportWallet.jsx) and the Wallet tab's
// "Add a wallet → Import wallet" overlay (components/AddWalletOverlay.jsx).
//
// It lives here because the two forms must agree. An import encrypts the pasted key
// under a password that is never echoed back and never recoverable — a typo is only
// discovered at the next unlock, when the key is already sealed behind the wrong
// password. So the password is entered twice and both must match, exactly as the two
// create-wallet forms already do.
//
// Pure + exported so it is unit-testable without rendering (the desktop suite has no
// jsdom; cf. pickWalletForUnlock in components/UnlockWalletOverlay.jsx).
import { isValidPasskeyInput } from "./identity.js";

/** Minimum wallet password length — shared by the create and import forms so the
 *  "min N chars" placeholder can never drift from the length actually enforced. */
export const MIN_PW = 8;

/** True when the import form is complete and safe to submit.
 *  @param {{name?: string, pw?: string, pw2?: string, key?: string, passkey?: string, busy?: boolean}} f */
export function canSubmitImport({ name, pw, pw2, key, passkey, busy } = {}) {
  return Boolean(
    (name ?? "").trim() &&
    (pw ?? "").length >= MIN_PW &&
    (pw ?? "") === (pw2 ?? "") &&
    (key ?? "").trim() &&
    isValidPasskeyInput(passkey) &&
    !busy,
  );
}

/** True when the confirm field has been typed into and disagrees with the password —
 *  i.e. when the "Passwords do not match." hint should be visible. Silent while the
 *  confirm box is still empty, so the message appears on typo, not on every keystroke. */
export function showPasswordMismatch(pw, pw2) {
  return (pw2 ?? "").length > 0 && (pw ?? "") !== (pw2 ?? "");
}
