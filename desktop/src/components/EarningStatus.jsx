// Pilot attribution status (Phase 4 T12): on-chain bind/enroll + baseline watermark.
// Honesty: no present-tense "you are earning GOAT" — TARGET/pilot/testnet language only.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getDeployment } from "../chain/addresses.js";
import { getPublicClient, getWalletClient } from "../chain/client.js";
import { EPOCH_SETTLEMENT_ABI } from "../chain/abis.js";
import { formatGoat } from "../chain/format.js";
import {
  RELAYER_URL,
  bindAndEnrollAuto,
  isLocalRelayerUrl,
  readEarningStatus,
  relayerMode,
  usernameMismatch,
} from "../chain/attribution.js";

const POLL_MS = 15_000;
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

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(
      () =>
        reject(
          new Error(
            `${label} timed out after ${Math.round(ms / 1000)}s. ` +
              `Check anvil (:8545) and relayer (:8787), then click Bind again.`,
          ),
        ),
      ms,
    );
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

/**
 * @param {object} props
 * @param {number} props.networkId
 * @param {import('viem').Account | null} props.account — Rust-backed viem account
 * @param {string | null} props.walletAddress
 * @param {string | null} props.fahUsername — local FAH identity username
 */
export default function EarningStatus({ networkId, account, walletAddress, fahUsername }) {
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

  const refresh = useCallback(async () => {
    if (!publicClient || !walletAddress || !hasContracts) {
      setStatus(null);
      setKeeperFee(0n);
      return;
    }
    // Fire-and-forget: never awaited, never touches loadError/loading — the
    // bind/enroll status path below must not be blocked by the fee read.
    readKeeperFeeSafe(publicClient, deployment?.epochSettlement).then(setKeeperFee);
    setLoading(true);
    setLoadError("");
    try {
      const snap = await readEarningStatus(publicClient, {
        workerBinding: deployment.workerBinding,
        epochSettlement: deployment.epochSettlement,
        enrollmentRegistry: deployment.enrollmentRegistry,
        wallet: walletAddress,
      });
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
      setLoadError(errMessage(err));
    } finally {
      setLoading(false);
    }
  }, [publicClient, walletAddress, hasContracts, deployment]);

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
        error: "Unlock Rookie in Wallet first, then Bind & enroll again.",
        mode: "",
      });
      return;
    }
    if (!walletClient) {
      setActionState({
        phase: "error",
        bindTx: null,
        enrollTx: null,
        error: "No wallet client — unlock Rookie and confirm network is Local anvil (31337).",
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
        "Bind & enroll",
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
      const friendly = /failed to fetch|http request failed/i.test(raw)
        ? `Anvil RPC unreachable (http://127.0.0.1:8545). Start anvil, then re-run contracts/dev-up.ps1 if needed, restart the desktop app, unlock Rookie, Bind again. Raw: ${raw.slice(0, 180)}`
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

  return (
    <div className="wallet-section earning-status">
      <div className="wallet-section-header">
        <h3>Attribution (pilot / testnet)</h3>
        <button type="button" onClick={refresh} disabled={loading || !walletAddress}>
          {loading ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      <p className="muted">
        TARGET model: after a finalized epoch and baseline, verified public-good work may mint pilot
        GOAT on-chain. This panel shows binding status only — it does not claim you are earning now.
      </p>

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
          <code>goat-attestor serve-relayer</code> on :8787 (leave it running). New wallets start with{" "}
          <strong>0 ETH</strong> — MockUSDT faucet is not gas. If you see &quot;exceeds the balance&quot;,
          either start the relayer or fund a little anvil ETH to this wallet. Do not import the
          RELAYER key as Rookie.
        </p>
      )}

      {!walletAddress ? (
        <p className="status-warn">Unlock a wallet in Wallet to bind &amp; enroll.</p>
      ) : (
        <>
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
            <dt>Claimable</dt>
            <dd className="muted">
              Claim when an epoch is finalized by the attestor — no live public FAH score in this UI;
              never invents a claimable amount.
            </dd>
          </dl>

          {feeDisclosure && <p className="muted">{feeDisclosure}</p>}

          {mismatch && (
            <p className="error-text" role="alert">
              Local FAH username does not match the on-chain binding — pilot attribution is paused
              until they match.
            </p>
          )}

          {loadError && <p className="error-text">{loadError}</p>}

          {canBind && (
            <div className="wallet-actions-row">
              <button
                type="button"
                className="primary-cta"
                disabled={acting || !account}
                onClick={handleBindAndEnroll}
              >
                {acting ? "Binding…" : "Bind & enroll (gasless, or ETH if relayer down)"}
              </button>
              {(acting || actionState.phase === "pending" || actionState.phase === "error") && (
                <button type="button" onClick={clearStuckPending} disabled={false}>
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
              Previous attempt was interrupted. Click <strong>Clear &amp; retry</strong>, then Bind
              again.
            </p>
          )}
          {actionState.phase === "error" && actionState.error && (
            <p className="error-text" role="alert">
              {actionState.error}
            </p>
          )}
          {actionState.phase === "done" && status?.bound && status?.enrolled && (
            <p className="status-ok">
              Bound &amp; enrolled on testnet
              {actionState.mode ? ` (${actionState.mode})` : ""} — claim path opens after finalized
              epochs (TARGET).
            </p>
          )}
          {!fahUsername?.startsWith("GOAT-") && (
            <p className="muted">
              Set FAH username under Contribute (GOAT-…) — bind &amp; enroll runs automatically once
              a wallet is unlocked.
            </p>
          )}
        </>
      )}
    </div>
  );
}
