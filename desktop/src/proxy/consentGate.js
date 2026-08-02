import { invoke } from "@tauri-apps/api/core";
import { allowlistDigest, policyDigest } from "./policyDigest.js";
import { buildConsentRecord, consentFields, consentMessageHex, normalizeHex } from "./consentRecord.js";
import { ceilingBytes, throttleBytesPerSec } from "./limits.js";
import {
  PROXY_CONSENT_ABSENT_NOTE,
  PROXY_CONSENT_BAD_SIGNATURE_NOTE,
  PROXY_CONSENT_EXPIRED_NOTE,
  PROXY_CONSENT_MALFORMED_NOTE,
  PROXY_CONSENT_NOT_YET_VALID_NOTE,
  PROXY_CONSENT_STALE_NOTE,
  PROXY_CONSENT_WALLET_MISMATCH_NOTE,
  PROXY_CONSENT_WALLET_UNKNOWN_NOTE,
  PROXY_POLICY_MISMATCH_NOTE,
} from "./copy.js";

// One entry per non-valid `ConsentState` the Rust gate can report. A state with no
// note renders as an off switch with no explanation, which reads as a bug in the app
// rather than as a refusal the operator can act on.
const NOTES = {
  absent: PROXY_CONSENT_ABSENT_NOTE,
  expired: PROXY_CONSENT_EXPIRED_NOTE,
  not_yet_valid: PROXY_CONSENT_NOT_YET_VALID_NOTE,
  stale_policy: PROXY_CONSENT_STALE_NOTE,
  wallet_mismatch: PROXY_CONSENT_WALLET_MISMATCH_NOTE,
  wallet_unknown: PROXY_CONSENT_WALLET_UNKNOWN_NOTE,
  bad_signature: PROXY_CONSENT_BAD_SIGNATURE_NOTE,
  malformed: PROXY_CONSENT_MALFORMED_NOTE,
};

/** Every state the daemon can report except `valid` has an operator-facing sentence. */
export const BLOCKING_CONSENT_STATES = Object.keys(NOTES);

export function consentNoteFor(state) {
  return NOTES[state] ?? "";
}

/**
 * Pure: what a switch flip means. No side effect, so the routing is testable alone.
 *
 * Turning it OFF is unconditional and never consults consent -- an operator who wants
 * traffic stopped gets traffic stopped whatever the record says.
 */
export function nextSwitchIntent(consentState, desiredOn) {
  if (!desiredOn) return { action: "disable", reason: "operator switched it off" };
  if (consentState === "valid") return { action: "enable", reason: "consent verifies" };
  if (consentState === "wallet_mismatch") return { action: "show_wallet_mismatch", reason: consentState };
  if (consentState === "wallet_unknown") return { action: "require_wallet", reason: consentState };
  return { action: "open_disclosure", reason: consentState ?? "absent" };
}

/** The switch position is the daemon's answer, never React intent. */
export function switchIsOn(status) {
  return Boolean(status?.running) && status?.consent?.state === "valid" && Boolean(status?.limits?.enabled);
}

/**
 * Assemble, sign and submit the record.
 *
 * The ceiling and the throttle go INSIDE the signed bytes, so the operator signs the
 * caps as well as the text. The daemon then enforces min(consented, configured), which
 * is why a later change in this window can lower a cap and can never raise one.
 */
export async function grantConsent({
  policy,
  daemonPolicyDigest,
  daemonAllowlistDigest,
  wallet,
  deviceId,
  nowUnix,
  limits,
  signMessage = (args) => invoke("wallet_sign_message", args),
  submit = (args) => invoke("backend_proxy_consent_grant", args),
}) {
  // Anti-drift: refuse to sign text this screen did not verify against the daemon's hash.
  if (
    normalizeHex(policyDigest(policy)) !== normalizeHex(daemonPolicyDigest) ||
    normalizeHex(allowlistDigest(policy)) !== normalizeHex(daemonAllowlistDigest)
  ) {
    throw new Error(PROXY_POLICY_MISMATCH_NOTE);
  }
  const fields = consentFields({
    policy,
    wallet,
    deviceId,
    nowUnix,
    dailyCeilingBytes: ceilingBytes(limits),
    throttleBytesPerSec: throttleBytesPerSec(limits),
  });
  const signature = await signMessage({
    expectedAddress: wallet,
    messageHex: consentMessageHex(fields),
  });
  const record = buildConsentRecord({ fields, signature });
  return submit({ recordJson: JSON.stringify(record) });
}

/**
 * No wallet argument, deliberately.
 *
 * The expected operator address is resolved Rust-side from the wallet this process
 * holds unlocked. A check whose expected value the webview supplies is
 * self-referential: the caller would name the same address the record names, and every
 * self-signed blob would verify.
 */
export function readProxyStatus() {
  return invoke("backend_proxy_status");
}

export function readEgressSince(sinceSeq) {
  return invoke("backend_proxy_egress_log", { sinceSeq });
}

export function writeProxyLimits(limits) {
  return invoke("backend_proxy_set_limits", { limitsJson: JSON.stringify(limits) });
}

export function killProxy() {
  return invoke("backend_proxy_kill");
}

export function revokeProxyConsent() {
  return invoke("backend_proxy_consent_revoke");
}
