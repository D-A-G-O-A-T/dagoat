// Pilot attribution status (Phase 4 T12): on-chain bind/enroll + baseline watermark.
// Honesty: no present-tense "you are earning GOAT" — TARGET/pilot/testnet language only.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { animate } from "motion";
import { useReducedMotion } from "motion/react";
import { getDeployment } from "../chain/addresses.js";
import { getPublicClient, getWalletClient } from "../chain/client.js";
import { EPOCH_SETTLEMENT_ABI } from "../chain/abis.js";
import { formatGoat, shortAddress } from "../chain/format.js";
import {
  RELAYER_URL,
  bindAndEnrollAuto,
  isLocalRelayerUrl,
  readEarningStatus,
  relayerMode,
  usernameMismatch,
} from "../chain/attribution.js";
import { PASSKEY_ATTRIBUTION_NOTE } from "../onboarding/copy.js";
import { bindTimeoutHint, rpcUnreachableHint } from "../chain/errors.js";
import { useMountedRef } from "../lib/useMountedRef.js";

// Stream C T5: slower poll on public RPC (was 15s). In-flight guard skips overlap.
export const POLL_MS = 25_000;
const PENDING_KEY = "goat-desktop:bind-enroll-pending";
/** In-flight bind must finish or fail within this window (relayer/RPC hang). */
const BIND_TIMEOUT_MS = 45_000;
/** localStorage "pending" older than this is treated as abandoned. */
const STALE_PENDING_MS = 20_000;

function loadPendingLocal(wallet) {
  if (!wallet || typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(PENDING_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed?.wallet?.toLowerCase() !== wallet.toLowerCase()) return null;
    // Never restore "pending" as a live spinner — that left users stuck after
    // crash/reload while nothing was in flight. Keep errors / done for UX.
    if (parsed.phase === "pending") {
      const age = Date.now() - Number(parsed.at || 0);
      if (!parsed.at || age > STALE_PENDING_MS) {
        window.localStorage.removeItem(PENDING_KEY);
        return null;
      }
      // Recent pending from another tab — still clear for this session; in-flight
      // is tracked by React `acting`, not localStorage.
      window.localStorage.removeItem(PENDING_KEY);
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function savePendingLocal(record) {
  if (typeof window === "undefined") return;
  try {
    if (!record) {
      window.localStorage.removeItem(PENDING_KEY);
      return;
    }
    // Do not persist mid-flight pending — only terminal outcomes (error/done).
    if (record.phase === "pending") return;
    window.localStorage.setItem(PENDING_KEY, JSON.stringify(record));
  } catch {
    /* ignore quota */
  }
}

function errMessage(err) {
  if (err == null) return "Unknown error";
  if (typeof err === "string") return err;
  return err.message || String(err);
}

function withTimeout(promise, ms, { networkId = 31337, localRelayer = true } = {}) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(bindTimeoutHint(ms, networkId, localRelayer))), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/// Honesty-reviewed keeper-fee disclosure (2026-07-16 consultant review §6.3).
/// Empty string when the fee is zero/unset — render nothing rather than a "0" line.
export function formatKeeperFeeDisclosure(keeperFeeWei) {
  if (!keeperFeeWei || keeperFeeWei <= 0n) return "";
  return `Auto-claim keeper fee: ${formatGoat(keeperFeeWei)} GOAT per payout — deducted from your minted GOAT to reimburse the keeper's claim gas. Your first (baseline) claim is never charged.`;
}

/// Disclosure only applies to a wallet that is bound + enrolled (claim path exists).
export function keeperFeeDisclosureLine(status, keeperFeeWei) {
  if (!status || !status.bound || !status.enrolled) return "";
  return formatKeeperFeeDisclosure(keeperFeeWei);
}

/// Fail-quiet keeperFee() reader — resolves to 0n on any RPC/decode error or
/// missing client/address; never rejects, so it can be fire-and-forget.
export async function readKeeperFeeSafe(publicClient, epochSettlementAddress) {
  if (!publicClient || !epochSettlementAddress) return 0n;
  try {
    const v = await publicClient.readContract({
      address: epochSettlementAddress,
      abi: EPOCH_SETTLEMENT_ABI,
      functionName: "keeperFee",
      args: [],
    });
    return typeof v === "bigint" ? v : BigInt(v ?? 0);
  } catch {
    return 0n;
  }
}

/** Bind/enroll UI appears ONLY when action is needed (spec §7). */
export function attributionViewModel({ bound, enrolled, usernameMismatch }) {
  return { needsAction: !bound || !enrolled || Boolean(usernameMismatch) };
}

/** T27 P4: masked-by-default passkey readout. Purely local toggle state — no invoke,
 *  no password gate (founder: "no need to encrypt this key"). Reuses the RevealKeyRow
 *  interaction pattern (button-styled value, click to reveal/hide). */
function MaskedPasskey({ value }) {
  const [revealed, setRevealed] = useState(false);
  if (!value) return "Not set";
  return (
    <button
      type="button"
      className="reveal-key-row__value"
      onClick={() => setRevealed((v) => !v)}
      title={revealed ? "Click to hide" : "Click to reveal"}
    >
      {revealed ? <code>{value}</code> : <span aria-label="hidden">••••••••</span>}
    </button>
  );
}

// Same honest credit-lag copy as tabs/Miner.jsx's CREDIT_LAG_NOTE (kept as a local literal here —
// not imported — so this component never depends on tabs/, which would create components/ ↔
// tabs/ circular imports since Miner.jsx renders EarningStatus).
const PENDING_CREDIT_LAG_NOTE =
  "Credited work units come from Folding@home's public stats and can lag hours behind a unit " +
  "finishing on your machine. GOAT is not automatic — pilot mint is a testnet TARGET after bind, " +
  "enroll, and a finalized epoch (not live mainnet earnings).";

/** Animates a numeric readout between chain-state snapshots; honest values only — no invented
 *  numbers are ever passed in. Skips the tween under reduced motion (renders the target value). */
function CountUp({ value, decimals = 0 }) {
  const reduced = useReducedMotion();
  const [shown, setShown] = useState(value);
  useEffect(() => {
    if (reduced) {
      setShown(value);
      return;
    }
    const controls = animate(shown, value, {
      duration: 0.6,
      ease: "easeInOut",
      onUpdate: (v) => setShown(v),
    });
    return () => controls.stop();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value, reduced]);
  return <>{shown.toFixed(decimals)}</>;
}

/**
 * @param {object} props
 * @param {number} props.networkId
 * @param {import('viem').Account | null} props.account — Rust-backed viem account
 * @param {string | null} props.walletAddress
 * @param {string | null} props.fahUsername — local FAH identity username
 * @param {string | null} [props.fahPasskey] — local FAH identity passkey value (A2, read-only display)
 * @param {boolean} [props.connected] — Miner's live backend-connected flag (gates Check for accepted work)
 * @param {Array} [props.pendingUnits] — journal units not yet minted (Task 17)
 * @param {() => Promise<void>} [props.onCheckWork] — poll for newly accepted work (Task 17)
 * @param {boolean} [props.checking] — Miner's in-flight flag for onCheckWork (busy label/disable)
 * @param {string} [props.checkError] — Miner's check-completions error (surfaced verbatim)
 */
export default function EarningStatus({
  networkId,
  account,
  walletAddress,
  fahUsername,
  fahPasskey = null,
  connected = false,
  pendingUnits = [],
  onCheckWork,
  checking = false,
  checkError = "",
}) {
  const deployment = getDeployment(networkId);
  const hasContracts = Boolean(
    deployment?.workerBinding && deployment?.epochSettlement && deployment?.enrollmentRegistry,
  );

  const publicClient = useMemo(() => {
    if (!hasContracts) return null;
    try {
      return getPublicClient(networkId);
    } catch {
      return null;
    }
  }, [networkId, hasContracts]);

  const walletClient = useMemo(() => {
    try {
      return getWalletClient(networkId, account);
    } catch {
      return null;
    }
  }, [networkId, account]);

  const [status, setStatus] = useState(null);
  const [loadError, setLoadError] = useState("");
  const [loading, setLoading] = useState(false);
  const [keeperFee, setKeeperFee] = useState(0n);

  const [actionState, setActionState] = useState(
    () =>
      loadPendingLocal(walletAddress) || {
        phase: "idle", // idle | pending | done | error
        bindTx: null,
        enrollTx: null,
        error: "",
        mode: "",
      },
  );
  const [acting, setActing] = useState(false);
  // Auto-bind once per wallet+username until success or explicit error handled.
  const autoKeyRef = useRef("");
  /** Stream C T5: skip overlapping status polls. */
  const refreshInflight = useRef(false);
  /** Consultant hazard: do not setState after unmount. */
  const mounted = useMountedRef();

  // Zone 1 wallet-address copy affordance — copies the FULL address even though the grid shows
  // a truncated one.
  const [addressCopied, setAddressCopied] = useState(false);
  const handleCopyAddress = useCallback(() => {
    if (!walletAddress || typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
      return;
    }
    navigator.clipboard.writeText(walletAddress).then(
      () => {
        setAddressCopied(true);
        setTimeout(() => setAddressCopied(false), 1500);
      },
      () => {
        /* clipboard denied — non-fatal, address is still shown truncated */
      },
    );
  }, [walletAddress]);

  const refresh = useCallback(async () => {
    if (!publicClient || !walletAddress || !hasContracts) {
      if (mounted.current) {
        setStatus(null);
        setKeeperFee(0n);
      }
      return;
    }
    if (refreshInflight.current) return;
    refreshInflight.current = true;
    // Fire-and-forget fee read — only apply if still mounted.
    readKeeperFeeSafe(publicClient, deployment?.epochSettlement).then((fee) => {
      if (mounted.current) setKeeperFee(fee);
    });
    if (mounted.current) {
      setLoading(true);
      setLoadError("");
    }
    try {
      const snap = await readEarningStatus(publicClient, {
        workerBinding: deployment.workerBinding,
        epochSettlement: deployment.epochSettlement,
        enrollmentRegistry: deployment.enrollmentRegistry,
        wallet: walletAddress,
      });
      if (!mounted.current) return;
      setStatus(snap);
      if (snap.bound && snap.enrolled) {
        savePendingLocal(null);
        setActionState((prev) =>
          prev.phase === "pending" || prev.phase === "idle"
            ? { phase: "done", bindTx: prev.bindTx, enrollTx: prev.enrollTx, error: "", mode: prev.mode }
            : prev,
        );
      }
    } catch (err) {
      if (mounted.current) setLoadError(errMessage(err));
    } finally {
      refreshInflight.current = false;
      if (mounted.current) setLoading(false);
    }
  }, [publicClient, walletAddress, hasContracts, deployment, mounted]);

  useEffect(() => {
    refresh();
    if (!publicClient || !walletAddress) return undefined;
    const t = setInterval(refresh, POLL_MS);
    return () => clearInterval(t);
  }, [refresh, publicClient, walletAddress]);

  useEffect(() => {
    setActionState(
      loadPendingLocal(walletAddress) || {
        phase: "idle",
        bindTx: null,
        enrollTx: null,
        error: "",
        mode: "",
      },
    );
    autoKeyRef.current = "";
  }, [walletAddress]);

  const handleBindAndEnroll = useCallback(async () => {
    if (!publicClient || !account || !walletAddress) {
      setActionState({
        phase: "error",
        bindTx: null,
        enrollTx: null,
        error: "Unlock a wallet in Wallet first, then Bind & enroll again.",
        mode: "",
      });
      return;
    }
    if (!walletClient) {
      setActionState({
        phase: "error",
        bindTx: null,
        enrollTx: null,
        error:
          Number(networkId) === 31337
            ? "No wallet client — unlock this wallet and confirm network is Local anvil (31337)."
            : "No wallet client — unlock this wallet and confirm the pilot network is selected.",
        mode: "",
      });
      return;
    }
    const username = (fahUsername ?? "").trim();
    if (!username.startsWith("GOAT-")) {
      setActionState({
        phase: "error",
        bindTx: null,
        enrollTx: null,
        error: "Set a GOAT- username first (Contribute → FAH username).",
        mode: "",
      });
      return;
    }
    setActing(true);
    // Clear sticky prior error so retry is not blocked by localStorage state.
    autoKeyRef.current = "";
    setActionState({
      phase: "pending",
      wallet: walletAddress,
      bindTx: null,
      enrollTx: null,
      error: "",
      mode: "",
      at: Date.now(),
    });
    try {
      const { bind, enroll, mode } = await withTimeout(
        bindAndEnrollAuto({
          publicClient,
          walletClient,
          account,
          chainId: networkId,
          username,
          wallet: walletAddress,
        }),
        BIND_TIMEOUT_MS,
        { networkId, localRelayer: isLocalRelayerUrl(RELAYER_URL) },
      );
      if (!bind.ok) {
        const next = {
          phase: "error",
          wallet: walletAddress,
          bindTx: bind.tx_hash ?? null,
          enrollTx: null,
          error: bind.error || "Bind failed",
          mode: mode || "",
          at: Date.now(),
        };
        setActionState(next);
        savePendingLocal(next);
        return;
      }
      if (!enroll?.ok) {
        const next = {
          phase: "error",
          wallet: walletAddress,
          bindTx: bind.tx_hash ?? null,
          enrollTx: enroll?.tx_hash ?? null,
          error: enroll?.error || "Enroll failed (bind may have succeeded — refresh status)",
          mode: mode || "",
          at: Date.now(),
        };
        setActionState(next);
        savePendingLocal(next);
        return;
      }
      const next = {
        phase: "done",
        wallet: walletAddress,
        bindTx: bind.tx_hash ?? null,
        enrollTx: enroll.tx_hash ?? null,
        error: "",
        mode: mode || "relayer",
        at: Date.now(),
      };
      setActionState(next);
      savePendingLocal(null);
      await refresh();
    } catch (err) {
      const raw = errMessage(err);
      const rpcHint = rpcUnreachableHint(
        { message: raw, name: /timeout|failed to fetch|http request failed/i.test(raw) ? "TimeoutError" : "Error" },
        networkId,
      );
      const friendly = rpcHint
        ? `${rpcHint} Raw: ${raw.slice(0, 180)}`
        : raw;
      const next = {
        phase: "error",
        wallet: walletAddress,
        bindTx: null,
        enrollTx: null,
        error: friendly,
        mode: "",
        at: Date.now(),
      };
      setActionState(next);
      savePendingLocal(next);
    } finally {
      setActing(false);
    }
  }, [
    publicClient,
    walletClient,
    account,
    walletAddress,
    fahUsername,
    networkId,
    refresh,
  ]);

  // After username is set + wallet unlocked: auto bind & enroll once (relayer, else wallet gas).
  // Skip only while a live attempt is running or a real error is shown (user can Retry).
  useEffect(() => {
    if (!hasContracts || !publicClient || !account || !walletAddress) return;
    if (acting || loading) return;
    const username = (fahUsername ?? "").trim();
    if (!username.startsWith("GOAT-")) return;
    if (!status) return;
    if (status.bound && status.enrolled) return;
    // Do not block on sticky "pending" — that was a localStorage ghost.
    if (actionState.phase === "error") return;
    if (actionState.phase === "pending" && acting) return;
    const key = `${walletAddress.toLowerCase()}|${username}|${networkId}`;
    if (autoKeyRef.current === key) return;
    autoKeyRef.current = key;
    handleBindAndEnroll();
  }, [
    hasContracts,
    publicClient,
    account,
    walletAddress,
    fahUsername,
    status,
    acting,
    loading,
    actionState.phase,
    networkId,
    handleBindAndEnroll,
  ]);

  function clearStuckPending() {
    savePendingLocal(null);
    autoKeyRef.current = "";
    setActing(false);
    setActionState({
      phase: "idle",
      bindTx: null,
      enrollTx: null,
      error: "",
      mode: "",
    });
  }

  if (!hasContracts) {
    return (
      <div className="wallet-section earning-status">
        <h3>Attribution (pilot)</h3>
        <p className="placeholder-note">
          WorkerBinding / EpochSettlement not on this network deployment yet — bind &amp; enroll
          unavailable here.
        </p>
      </div>
    );
  }

  const mismatch = status && usernameMismatch(fahUsername, status.username);
  const feeDisclosure = keeperFeeDisclosureLine(status, keeperFee);
  const canBind =
    Boolean(account && walletAddress && fahUsername?.startsWith("GOAT-")) &&
    !(status?.bound && status?.enrolled);
  const viewModel = attributionViewModel({
    bound: Boolean(status?.bound),
    enrolled: Boolean(status?.enrolled),
    usernameMismatch: mismatch,
  });
  // Honest numeric readouts (spec §7 amendment) — GOAT-decimal-converted lastClaimedCumulative
  // and the local pending-journal count. Never a live "claimable" figure; 0 until a baseline
  // actually exists on chain.
  const claimedGoat = status?.hasBaseline ? Number(formatGoat(status.lastClaimedCumulative)) : 0;

  return (
    <>
      {walletAddress && (
        <div className="glass stat-box">
          <div className="stat-box__grid">
            {/* T27 P5+P6 row layout: row 1 = username + team; row 2 = passkey (full);
                row 3 = bound wallet (full); row 4 = claimed + pending. */}
            <div>
              <p className="stat-box__label">FAH username</p>
              <p className="stat-box__value">{fahUsername?.trim() || "— not set —"}</p>
            </div>
            <div>
              <p className="stat-box__label">Team · locked</p>
              <p className="stat-box__value">Goat Project - id: 1068318</p>
            </div>
            <div className="stat-box__item--full">
              <p className="stat-box__label">FAH passkey</p>
              <p className="stat-box__value">
                <MaskedPasskey value={fahPasskey} />
              </p>
            </div>
            <div className="stat-box__item--full">
              <p className="stat-box__label">Bound wallet</p>
              <p className="stat-box__value">
                <button
                  type="button"
                  className="attr-copy-addr"
                  title="Click to copy"
                  onClick={handleCopyAddress}
                >
                  {shortAddress(walletAddress)}
                </button>
                {addressCopied && <span className="muted"> copied</span>}
              </p>
            </div>
            <div>
              <p className="stat-box__label">Claimed so far · testnet</p>
              <p className="stat-box__value">
                <CountUp value={claimedGoat} decimals={2} /> GOAT
              </p>
            </div>
            <div>
              <p className="stat-box__label">Pending · awaiting settlement</p>
              <p className="stat-box__value">
                <CountUp value={pendingUnits.length} /> units
              </p>
            </div>
          </div>
          <p className="muted">{PASSKEY_ATTRIBUTION_NOTE}</p>
          <p className="muted">
            Claim when an epoch is finalized by the attestor — no live public FAH score in this UI;
            never invents a claimable amount.
          </p>
        </div>
      )}
      <div className="wallet-section earning-status">
      <div className="wallet-section-header">
        <h3>Attribution (pilot / testnet)</h3>
        <button type="button" className="btn-outline" onClick={refresh} disabled={loading || !walletAddress}>
          {loading ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      <p className="muted">
        TARGET model: after a finalized epoch and baseline, verified public-good work may mint pilot
        GOAT on-chain. This panel shows binding status only — it does not claim you are earning now.
      </p>

      {!walletAddress ? (
        <p className="status-warn">Unlock a wallet in Wallet to bind &amp; enroll.</p>
      ) : (
        <>
          {loadError && <p className="error-text">{loadError}</p>}

          {actionState.phase === "done" && status?.bound && status?.enrolled && (
            <p className="status-ok">
              Bound &amp; enrolled on testnet
              {actionState.mode ? ` (${actionState.mode})` : ""} — claim path opens after finalized
              epochs (TARGET).
            </p>
          )}

          {/* Zone 2: action zone — renders ONLY when attributionViewModel says something needs
              attention (spec §7). */}
          {viewModel.needsAction && (
            <>
              {mismatch && (
                <p className="error-text" role="alert">
                  Local FAH username does not match the on-chain binding — pilot attribution is
                  paused until they match.
                </p>
              )}

              {canBind && (
                <div className="wallet-actions-row">
                  <button
                    type="button"
                    className="btn-outline"
                    disabled={acting || !account}
                    onClick={handleBindAndEnroll}
                  >
                    {acting ? "Binding…" : "Bind & enroll (gasless, or ETH if relayer down)"}
                  </button>
                  {(acting || actionState.phase === "pending" || actionState.phase === "error") && (
                    <button type="button" className="btn-outline" onClick={clearStuckPending} disabled={false}>
                      {acting ? "Cancel wait" : "Clear & retry"}
                    </button>
                  )}
                </div>
              )}

              {acting && (
                <p className="status-warn">
                  Pending bind/enroll submission… (times out at {BIND_TIMEOUT_MS / 1000}s if stuck)
                </p>
              )}
              {!acting && actionState.phase === "pending" && (
                <p className="status-warn">
                  Previous attempt was interrupted. Click <strong>Clear &amp; retry</strong>, then
                  Bind again.
                </p>
              )}
              {actionState.phase === "error" && actionState.error && (
                <p className="error-text" role="alert">
                  {actionState.error}
                </p>
              )}
              {!fahUsername?.startsWith("GOAT-") && (
                <p className="muted">
                  Set FAH username under Contribute (GOAT-…) — bind &amp; enroll runs automatically
                  once a wallet is unlocked.
                </p>
              )}
            </>
          )}

          {/* Zone 3: everything developer-ish, closed by default (spec §7). */}
          <details className="tech-details">
            <summary>Technical details</summary>

            <dl className="balance-grid">
              <dt>FAH username (local)</dt>
              <dd>{fahUsername?.trim() || "— not set —"}</dd>
              <dt>Bound username (chain)</dt>
              <dd>
                {status?.bound
                  ? status.username || "—"
                  : status
                    ? "not bound"
                    : loadError
                      ? "—"
                      : "…"}
              </dd>
              <dt>Enrolled</dt>
              <dd>{status ? (status.enrolled ? "yes" : "no") : "…"}</dd>
              <dt>Baseline (hasBaseline)</dt>
              <dd>{status ? (status.hasBaseline ? "yes" : "not yet") : "…"}</dd>
              <dt>lastClaimedCumulative</dt>
              <dd>
                {status
                  ? status.hasBaseline
                    ? String(status.lastClaimedCumulative)
                    : "— (set on first claim / enrollment epoch)"
                  : "…"}
              </dd>
            </dl>

            <p className="muted">
              Relayer: <code>{RELAYER_URL}</code>{" "}
              <span className="muted">({relayerMode(RELAYER_URL)})</span>
              {deployment?.workerBinding && (
                <>
                  {" "}
                  · WorkerBinding <code>{String(deployment.workerBinding).slice(0, 10)}…</code>
                </>
              )}
            </p>
            {isLocalRelayerUrl(RELAYER_URL) && (
              <p className="status-warn" role="status">
                Local-dev relayer (127.0.0.1 / localhost). Gasless bind needs{" "}
                <code>goat-attestor serve-relayer</code> on :8787 (leave it running). New wallets
                start with <strong>0 ETH</strong> — MockUSDT faucet is not gas. If you see
                &quot;exceeds the balance&quot;, either start the relayer or fund a little anvil ETH
                to this wallet. Do not import the RELAYER key as Rookie.
              </p>
            )}
            {feeDisclosure && <p className="muted">{feeDisclosure}</p>}

            <div className="wallet-section-header">
              <h4>Pending work units</h4>
              <div className="wallet-actions-row">
                <button type="button" className="btn-outline" onClick={onCheckWork} disabled={!connected || checking}>
                  {checking ? "Checking…" : "Check for accepted work"}
                </button>
              </div>
            </div>
            {checkError && <p className="error-text">{checkError}</p>}
            <p className="muted credit-lag-note">{PENDING_CREDIT_LAG_NOTE}</p>
            {pendingUnits.length === 0 ? (
              <p className="placeholder-note">
                No pending units yet — credited work units come from Folding@home&apos;s public
                stats and can lag hours after a unit finishes locally. Click Check for accepted
                work to poll.
              </p>
            ) : (
              <table className="pending-table">
                <thead>
                  <tr>
                    <th>id</th>
                    <th>when</th>
                    <th>weight</th>
                    <th>status</th>
                  </tr>
                </thead>
                <tbody>
                  {pendingUnits.map((unit) => (
                    <tr key={unit.unit_id}>
                      <td>
                        <code>{unit.unit_id}</code>
                      </td>
                      <td>{new Date(unit.at * 1000).toLocaleString()}</td>
                      <td>{unit.weight}</td>
                      <td>
                        {unit.mintedInBatch == null ? (
                          <span className="status-warn">Pending</span>
                        ) : (
                          <span className="status-ok">{`Minted (batch ${unit.mintedInBatch})`}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </details>
        </>
      )}
      </div>
    </>
  );
}
