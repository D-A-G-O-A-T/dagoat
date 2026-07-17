// Transport-level failure → actionable hint. Only for Local anvil (31337): on a public
// network an unreachable RPC is not something dev-up.ps1 fixes.
export const ANVIL_DOWN_HINT =
  "Local anvil isn't running or isn't reachable at 127.0.0.1:8545 — run contracts\\dev-up.ps1, then Refresh.";

const TRANSPORT_ERRORS = new Set(["HttpRequestError", "TimeoutError"]);

export function rpcUnreachableHint(err, networkId) {
  if (networkId !== 31337 || !err) return null;
  const viaWalk =
    typeof err.walk === "function" && err.walk((e) => TRANSPORT_ERRORS.has(e?.name));
  if (viaWalk) return ANVIL_DOWN_HINT;
  if (TRANSPORT_ERRORS.has(err.name)) return ANVIL_DOWN_HINT;
  const msg = `${err.shortMessage ?? ""} ${err.message ?? ""}`;
  if (/HTTP request failed|took too long to respond/i.test(msg)) return ANVIL_DOWN_HINT;
  return null;
}
