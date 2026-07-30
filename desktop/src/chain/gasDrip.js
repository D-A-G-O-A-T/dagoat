// Gasless-sell gas-drip client wrapper (Task 6).
// Pure, injectable POST wrapper around the attestor relayer's gas-drip endpoint.
// Mirrors the postRelay style in ./attribution.js — never throws, fetchImpl injectable,
// unit-testable without Tauri or a real network.
//
// SERVER CONTRACT (verified): POST {base}/v1/relay/gas-drip body {"wallet":"0x…"}.
// `amount_wei` in a 200 response is a DECIMAL STRING, not a number — values exceed
// Number.MAX_SAFE_INTEGER. Parse with BigInt(...) if a numeric value is ever needed;
// never Number() it. `remaining_today` / `limit` are plain small-count numbers.

import { RELAYER_URL } from "./attribution.js";
import { relayerAuthHeaders } from "./relayerHeaders.js";

/**
 * 429 DailyLimitReached — cap-agnostic, no hardcoded number.
 *
 * Says outright that retrying will be REFUSED rather than merely unhelpful.
 * The relayer's ledger has no release, decrement or refund operation
 * (`DripLedger` exposes only load_count and commit, and commit only
 * increments), and quota is reserved before the send, so there is no
 * user-reachable second top-up on the same UTC day. The copy must not imply
 * otherwise.
 */
export const GAS_DRIP_LIMIT_COPY =
  "This wallet has already used today's testnet ETH top-up, and a second one today will be refused. Send testnet ETH to this wallet to sell now, or try again after 00:00 UTC.";

/**
 * A drip was sent (200 — so the day's allowance is definitively spent) and the
 * wallet still holds less than this step needs for gas. Distinct from
 * GAS_DRIP_UNAVAILABLE_COPY, which invites a retry: here a retry cannot help
 * today, and saying "try again shortly" would be false.
 */
export const GAS_DRIP_SPENT_STILL_SHORT_COPY =
  "The testnet ETH top-up used this wallet's allowance for today and is still less than this step needs for gas. Send testnet ETH to this wallet to sell now, or try again after 00:00 UTC.";

/** 502 DripSendFailed — the send failed AND the reservation still consumed today's drip. */
export const GAS_DRIP_SEND_FAILED_COPY =
  "The gas top-up didn't go through, and it used today's gasless sell. Add testnet ETH to sell now, or try again after 00:00 UTC.";

/** 400 NoGoatToSell — wallet holds 0 GOAT. */
export const GAS_DRIP_NO_GOAT_COPY = "You have no GOAT to sell yet.";

/** 409 DripInProgress — a drip for this wallet is already in flight. */
export const GAS_DRIP_IN_PROGRESS_COPY =
  "A gas top-up for this wallet is already in progress — give it a moment.";

/**
 * 503 (disabled/underfunded/ledger unavailable) and other 502s: the relayer
 * ANSWERED and refused, so no quota was reserved (the cap check runs before any
 * chain spend) and retrying is reasonable. No promise about when.
 */
export const GAS_DRIP_UNAVAILABLE_COPY =
  "The gas top-up service is not handing out testnet ETH right now. You can try the sell again, or send testnet ETH to this wallet.";

/**
 * status 0 — the request never got an answer. This is the genuinely ambiguous
 * case and the copy must not resolve it: a POST that timed out may or may not
 * have reserved this wallet's daily allowance before the connection died. On
 * the pilot the relayer is reached over a tunnel, so this is a likely failure
 * mode, not an exotic one. Claiming either way would be wrong about half the
 * time.
 */
export const GAS_DRIP_UNREACHABLE_COPY =
  "Couldn't reach the gas top-up service, so there's no way to tell whether today's testnet ETH top-up for this wallet was used. You can try the sell again, or send testnet ETH to this wallet.";

/** CF Access / HTML gate instead of JSON (Stream C T4). */
export const GAS_DRIP_ACCESS_GATE_COPY =
  "The gas top-up service is behind an access gate this build cannot pass. Contact the pilot operator — this is not a wallet error. You can still sell if this wallet already has testnet ETH.";

/**
 * POST /v1/relay/gas-drip for `wallet`. Returns the parsed response body merged
 * with the HTTP status. Never throws: a thrown fetch/network error maps to
 * `{ ok:false, error:"network", status:0 }`.
 *
 * @param {string} wallet
 * @param {{ fetchImpl?: typeof fetch, base?: string, timeoutMs?: number }} [opts]
 */
export async function requestGasDrip(
  wallet,
  { fetchImpl = fetch, base = RELAYER_URL, timeoutMs = 20_000 } = {},
) {
  const url = `${String(base).replace(/\/$/, "")}/v1/relay/gas-drip`;
  let res;
  try {
    const ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = ctrl && timeoutMs > 0 ? setTimeout(() => ctrl.abort(), timeoutMs) : null;
    try {
      res = await fetchImpl(url, {
        method: "POST",
        headers: relayerAuthHeaders(),
        body: JSON.stringify({ wallet }),
        ...(ctrl ? { signal: ctrl.signal } : {}),
      });
    } finally {
      if (timer) clearTimeout(timer);
    }
  } catch {
    return { ok: false, error: "network", status: 0 };
  }

  // text → JSON so Access HTML gates are visible (Stream C T4 / consultant hazard #2).
  let bodyText = "";
  try {
    bodyText = typeof res.text === "function" ? await res.text() : "";
  } catch {
    bodyText = "";
  }
  let data = null;
  if (bodyText) {
    try {
      data = JSON.parse(bodyText);
    } catch {
      data = null;
    }
  }

  const status = res.status;
  // Non-JSON / CF Access HTML → surface as typed soft error for gasDripMessage.
  if (data == null && bodyText && !String(bodyText).trim().startsWith("{")) {
    return {
      ok: false,
      error: "AccessGateOrNonJson",
      status,
      bodyPreview: String(bodyText).slice(0, 120),
    };
  }
  if ((status === 302 || status === 401 || status === 403) && !data?.ok) {
    return {
      ok: false,
      error: data?.error || "AccessGateOrNonJson",
      status,
      ...(data ?? {}),
    };
  }

  return {
    ok: Boolean(data?.ok),
    ...(data ?? {}),
    status,
  };
}

/**
 * Map a `requestGasDrip()` result to user-facing copy.
 * @param {{ status?: number, error?: string }} res
 * @returns {string}
 */
export function gasDripMessage(res) {
  const status = res?.status;
  const error = res?.error;

  // The 429 body carries `resets_at` (real wall-clock UTC midnight, computed
  // server-side). Render it rather than the hardcoded fallback, so the one
  // genuinely actionable field the endpoint returns stops being discarded.
  if (status === 429) {
    const resetsAt = typeof res?.resets_at === "string" ? res.resets_at.trim() : "";
    return resetsAt ? GAS_DRIP_LIMIT_COPY.replace("00:00 UTC", resetsAt) : GAS_DRIP_LIMIT_COPY;
  }
  if (status === 400 && error === "NoGoatToSell") return GAS_DRIP_NO_GOAT_COPY;
  if (status === 409) return GAS_DRIP_IN_PROGRESS_COPY;
  if (status === 502 && error === "DripSendFailed") return GAS_DRIP_SEND_FAILED_COPY;
  if (
    error === "AccessGateOrNonJson" ||
    status === 401 ||
    status === 403 ||
    status === 302
  ) {
    return GAS_DRIP_ACCESS_GATE_COPY;
  }
  // status 0 means no answer came back at all — quota state unknowable, so it
  // gets copy that says so rather than being folded in with a clean refusal.
  if (status === 0) return GAS_DRIP_UNREACHABLE_COPY;
  // 503 (GasDripDisabled / RelayerUnderfunded / GasDripLedgerUnavailable), any
  // other 502 and a non-NoGoatToSell 400 are all answered refusals.
  return GAS_DRIP_UNAVAILABLE_COPY;
}
