// Shared HTTP headers for attestor relayer calls (bind / enroll / gas-drip).
//
// Cloudflare Access (optional): when VITE_CF_ACCESS_CLIENT_ID and
// VITE_CF_ACCESS_CLIENT_SECRET are set at **build time**, attach the service-token
// headers so the packaged app can pass a CF Access gate in front of the tunnel.
//
// HONESTY (consultant / hardening design): Access tokens ship inside the installer
// and are extractable. They are a **speed-bump only**. Load-bearing gates are H1
// (off-chain EIP-712 verify) + spend_ledger (H2/H2b) on the relayer.

/**
 * @param {Record<string, string | undefined>} [env] — injectable for tests;
 *   defaults to `import.meta.env` fields when present.
 * @returns {Record<string, string>}
 */
export function relayerAuthHeaders(env) {
  const e =
    env ??
    (typeof import.meta !== "undefined" && import.meta.env ? import.meta.env : {});
  const headers = { "Content-Type": "application/json" };
  const id = String(e.VITE_CF_ACCESS_CLIENT_ID ?? "").trim();
  const secret = String(e.VITE_CF_ACCESS_CLIENT_SECRET ?? "").trim();
  // Both required — a half-configured token confuses CF and looks like a working auth path.
  if (id && secret) {
    headers["CF-Access-Client-Id"] = id;
    headers["CF-Access-Client-Secret"] = secret;
  }
  return headers;
}

/**
 * True when both CF Access env vars are present (build-time pilot remote posture).
 * Does **not** prove the token is valid or secret.
 */
export function hasCloudflareAccessEnv(env) {
  const e =
    env ??
    (typeof import.meta !== "undefined" && import.meta.env ? import.meta.env : {});
  return Boolean(
    String(e.VITE_CF_ACCESS_CLIENT_ID ?? "").trim() &&
      String(e.VITE_CF_ACCESS_CLIENT_SECRET ?? "").trim(),
  );
}
