// The signed consent record. The UI assembles it and asks the Rust wallet to sign it;
// the Rust command verifies it before writing; the sidecar verifies it AGAIN from the
// file before opening a socket. Three checks, one of which does not trust this process.
//
// THE PREIMAGE IS PINNED, NOT INVENTED HERE. It is written by hand in three places --
// this file, `desktop/src-tauri/src/proxy/consent.rs`, and the sidecar's own consent
// module -- so all three assert against `tools/goat-proxy-worker/fixtures/
// consent-preimage.json` rather than against each other's memory of it. A test that
// compares this implementation to itself proves nothing.
//
// THE CEILING AND THE THROTTLE ARE INSIDE THE PREIMAGE ON PURPOSE. A ceiling that
// lived outside the signature could be raised by editing a file while the signature
// still verified. The daemon takes min(consented, configured), so the controls may
// only lower what the operator signed; raising past it needs a new signature.
import { allowlistDigest, policyDigest } from "./policyDigest.js";

/// The first line of the preimage. Domain separation, so the digest of a consent
/// record cannot collide with the digest of anything else this project hashes.
export const CONSENT_HEADER = "GOAT Residential Proxy Consent Record v1";
export const CONSENT_SCHEMA = 1;
export const CONSENT_TTL_SECS = 90 * 24 * 60 * 60; // 7_776_000

/**
 * Lower-case `0x`-hex, the one spelling the preimage uses.
 *
 * The sidecar holds the wallet as twenty BYTES and hex-encodes them on the way into
 * its preimage, which is always lower case. A checksummed spelling signed here would
 * produce a preimage the sidecar never reconstructs, and every signature would fail
 * verification on the daemon side while passing on this one.
 */
export function normalizeHex(value) {
  const raw = String(value ?? "").trim();
  const body = raw.startsWith("0x") || raw.startsWith("0X") ? raw.slice(2) : raw;
  return `0x${body.toLowerCase()}`;
}

export function consentFields({
  policy,
  wallet,
  deviceId,
  nowUnix,
  dailyCeilingBytes,
  throttleBytesPerSec,
}) {
  return {
    schema: CONSENT_SCHEMA,
    policy_version: policy.policy_version,
    policy_digest: normalizeHex(policyDigest(policy)),
    allowlist_digest: normalizeHex(allowlistDigest(policy)),
    wallet: normalizeHex(wallet),
    device_id: String(deviceId ?? ""),
    daily_ceiling_bytes: Number(dailyCeilingBytes),
    throttle_bytes_per_sec: Number(throttleBytesPerSec),
    granted_at_unix: Number(nowUnix),
    expires_at_unix: Number(nowUnix) + CONSENT_TTL_SECS,
  };
}

/**
 * The exact bytes the operator's signature is over: a `\n`-joined line block with NO
 * trailing newline. Pinned by `fixtures/consent-preimage.json`.
 */
export function consentPreimage(f) {
  return [
    CONSENT_HEADER,
    `schema: ${f.schema}`,
    `policy_version: ${f.policy_version}`,
    `policy_digest: ${normalizeHex(f.policy_digest)}`,
    `allowlist_digest: ${normalizeHex(f.allowlist_digest)}`,
    `wallet: ${normalizeHex(f.wallet)}`,
    `device_id: ${f.device_id}`,
    `daily_ceiling_bytes: ${f.daily_ceiling_bytes}`,
    `throttle_bytes_per_sec: ${f.throttle_bytes_per_sec}`,
    `granted_at_unix: ${f.granted_at_unix}`,
    `expires_at_unix: ${f.expires_at_unix}`,
  ].join("\n");
}

/**
 * UTF-8 bytes of the preimage as `0x`-hex, the shape `wallet_sign_message` expects.
 * The EIP-191 prefix is applied by the signer over the DECODED bytes, never over this
 * hex string.
 */
export function consentMessageHex(f) {
  const bytes = new TextEncoder().encode(consentPreimage(f));
  let out = "0x";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function buildConsentRecord({ fields, signature }) {
  return { ...fields, signature: normalizeHex(signature) };
}

export function isBlockingConsentState(state) {
  return state !== "valid";
}
