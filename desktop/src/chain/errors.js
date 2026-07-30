// Transport-level failure → actionable hint.
// Lab (31337): anvil/dev-up guidance.
// Pilot remote (84532+): volunteer-facing copy — never name anvil ports.

export const ANVIL_DOWN_HINT =
  "Local anvil isn't running or isn't reachable at 127.0.0.1:8545 — run contracts\\dev-up.ps1, then Refresh.";

/** Volunteer-facing RPC failure on a public testnet (Base Sepolia pilot). */
export const REMOTE_RPC_HINT =
  "Network unavailable — check your connection and try again. If this continues, contact the pilot operator.";

/**
 * Cloudflare Access / reverse-proxy returned HTML instead of JSON.
 * Speed-bump only — not a wallet or signature failure.
 */
export const ACCESS_GATE_HINT =
  "Relayer access gate blocked this request. This build may be missing Cloudflare Access credentials, or the pilot Access policy rejected the service token. Contact the pilot operator — this is not a wallet error.";

const TRANSPORT_ERRORS = new Set(["HttpRequestError", "TimeoutError"]);

function isTransportish(err) {
  if (!err) return false;
  const viaWalk =
    typeof err.walk === "function" && err.walk((e) => TRANSPORT_ERRORS.has(e?.name));
  if (viaWalk) return true;
  if (TRANSPORT_ERRORS.has(err.name)) return true;
  const msg = `${err.shortMessage ?? ""} ${err.message ?? ""}`;
  return /HTTP request failed|took too long to respond|failed to fetch|networkerror/i.test(msg);
}

/**
 * @param {unknown} err
 * @param {number|string} networkId
 * @returns {string|null}
 */
export function rpcUnreachableHint(err, networkId) {
  if (!err || !isTransportish(err)) return null;
  const id = Number(networkId);
  if (id === 31337) return ANVIL_DOWN_HINT;
  if (id === 84532) return REMOTE_RPC_HINT;
  // Unknown public-ish networks: still avoid anvil instructions.
  if (id && id !== 31337) return REMOTE_RPC_HINT;
  return null;
}

/**
 * Detect CF Access / HTML auth pages in an HTTP response body.
 * @param {number} status
 * @param {string} [bodyText]
 * @returns {boolean}
 */
export function looksLikeAccessOrHtmlGate(status, bodyText = "") {
  if (status === 302 || status === 401 || status === 403) return true;
  const sample = String(bodyText || "").slice(0, 400).toLowerCase();
  if (!sample) return false;
  return (
    sample.includes("<!doctype") ||
    sample.includes("<html") ||
    sample.includes("cloudflare") ||
    sample.includes("cf-access") ||
    sample.includes("login.cloudflareaccess.com") ||
    sample.includes("access denied")
  );
}

/**
 * Prefer structured JSON error; otherwise map gate/HTML bodies for volunteers.
 * @returns {string|null} null → caller may use data.error or generic HTTP status
 */
export function formatHttpGateError(status, bodyText, data) {
  if (data && typeof data.error === "string" && data.error.trim()) {
    return null; // structured error wins
  }
  if (looksLikeAccessOrHtmlGate(status, bodyText)) {
    return `${ACCESS_GATE_HINT} (HTTP ${status})`;
  }
  const trimmed = String(bodyText || "").trim();
  if (trimmed && !trimmed.startsWith("{") && !trimmed.startsWith("[")) {
    return `Relayer returned a non-JSON response (HTTP ${status}). If Access is enabled, this app may be missing CF Access headers — contact the pilot operator.`;
  }
  return null;
}

/**
 * Bind/enroll timeout copy — lab vs remote.
 * @param {number} ms
 * @param {number|string} [networkId]
 * @param {boolean} [localRelayer]
 */
export function bindTimeoutHint(ms, networkId = 31337, localRelayer = true) {
  const secs = Math.round(Number(ms) / 1000) || 0;
  if (Number(networkId) === 31337 && localRelayer) {
    return (
      `Bind timed out after ${secs}s. ` +
      `Check anvil (:8545) and relayer (:8787), then click Bind again.`
    );
  }
  return (
    `Bind timed out after ${secs}s. ` +
    `Check your connection and try again. If this continues, contact the pilot operator.`
  );
}

// Tauri command rejections arrive as plain strings (Result<_, String>); normal
// JS errors arrive as Error. Surface either without leaking anything else.
export function commandError(err) {
  if (typeof err === "string") return err;
  return err?.message || String(err);
}
