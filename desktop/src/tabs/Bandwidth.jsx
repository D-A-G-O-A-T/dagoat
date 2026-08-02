import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import BandwidthSwitch from "../components/BandwidthSwitch.jsx";
import UnlockWalletOverlay from "../components/UnlockWalletOverlay.jsx";
import ProxyDisclosure from "../proxy/steps/ProxyDisclosure.jsx";
import { useActiveAccount, useActiveWallet } from "../chain/wallet.js";
import { clampLimits, effectiveCeilingBytes } from "../proxy/limits.js";
import { egressReducer, initialEgressState, needsReconcile } from "../proxy/egressFeed.js";
import {
  consentNoteFor,
  grantConsent,
  killProxy,
  nextSwitchIntent,
  readEgressSince,
  readProxyStatus,
  revokeProxyConsent,
  switchIsOn,
  writeProxyLimits,
} from "../proxy/consentGate.js";
import {
  PROXY_ALLOWLIST_NOTE,
  PROXY_ALLOWLIST_TITLE,
  PROXY_BYTES_SESSION_LABEL,
  PROXY_BYTES_TODAY_LABEL,
  PROXY_CAPS_CONSENTED_NOTE,
  PROXY_CAPS_ENFORCEMENT_NOTE,
  PROXY_CAP_LABEL,
  PROXY_COUNTER_SOURCE_NOTE,
  PROXY_COUNTER_UNOBSERVED,
  PROXY_EGRESS_EMPTY,
  PROXY_EGRESS_GAP_NOTE,
  PROXY_EGRESS_LOG_TITLE,
  PROXY_EGRESS_PRIVACY_NOTE,
  PROXY_EGRESS_UNOBSERVED,
  PROXY_HALT_RECEIPT_LABEL,
  PROXY_HALT_UNVERIFIED_NOTE,
  PROXY_KILL_LABEL,
  PROXY_KILL_SUBTEXT,
  PROXY_MARKETPLACE_GATE_NOTE,
  PROXY_PAYOUT_NOTE,
  PROXY_REFUSAL_NOW_NOTE,
  PROXY_REVOKE_LABEL,
  PROXY_REVOKE_SUBTEXT,
  PROXY_SCHEDULE_EMPTY_NOTE,
  PROXY_SCHEDULE_LABEL,
  PROXY_SEQUENCE_BROKEN_NOTE,
  PROXY_SIGN_REFUSED_NOTE,
  PROXY_SOCKETS_LABEL,
  PROXY_SPLIT_PROVENANCE_NOTE,
  PROXY_STATUS_TITLE,
  PROXY_TARGET_POSTURE,
  PROXY_THROTTLE_LABEL,
  PROXY_UNAVAILABLE_NOTE,
} from "../proxy/copy.js";

// POLL, NOT PUSH. The shell has zero Tauri events and this lane adds none: the
// sidecar's event stream is its stdout, and the one spawn path owns the child. The
// polled status is therefore the only authority, and it runs at the shell's own 3 s
// cadence -- the shipped latency claim is 3 s.
export const PROXY_STATUS_POLL_MS = 3_000;

function gb(bytes) {
  return `${(Number(bytes || 0) / 1_000_000_000).toFixed(3)} GB`;
}

/**
 * A number nobody read is not zero.
 *
 * `bytes_today` arrives as `null` and `sockets_open` as `{ kind: "unverified" }` when
 * the background process's own figure was not observed. Printing 0 there would report
 * a clean machine that was never checked.
 */
function observed(value, render) {
  if (value === null || value === undefined) return PROXY_COUNTER_UNOBSERVED;
  return render(value);
}

function socketCount(sockets) {
  if (sockets?.kind === "census") return String(sockets.value);
  return PROXY_COUNTER_UNOBSERVED;
}

export default function Bandwidth() {
  const account = useActiveAccount();
  const wallet = useActiveWallet();
  const [available, setAvailable] = useState(false);
  const [policyDoc, setPolicyDoc] = useState(null);
  const [status, setStatus] = useState(null);
  const [limits, setLimits] = useState(clampLimits({}));
  const [showDisclosure, setShowDisclosure] = useState(false);
  const [showUnlock, setShowUnlock] = useState(false);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const [haltReceipt, setHaltReceipt] = useState(null);
  const [feed, dispatchFeed] = useReducer(egressReducer, undefined, initialEgressState);
  const feedRef = useRef(feed);
  feedRef.current = feed;

  useEffect(() => {
    invoke("backend_proxy_available").then(setAvailable).catch(() => setAvailable(false));
    invoke("backend_proxy_policy").then(setPolicyDoc).catch(() => setPolicyDoc(null));
    invoke("backend_proxy_limits").then((l) => setLimits(clampLimits(l))).catch(() => {});
  }, []);

  // The polled authority: counters, consent state, and the proof that no entry the
  // background process holds is missing from this list.
  useEffect(() => {
    let cancelled = false;
    let timer = null;
    async function tick() {
      try {
        const s = await readProxyStatus();
        if (cancelled) return;
        setStatus(s);
        if (needsReconcile(feedRef.current, s.last_seq)) {
          const events = await readEgressSince(feedRef.current.highestSeq);
          if (!cancelled) dispatchFeed({ type: "reconcile", events });
        }
      } catch {
        if (!cancelled) setStatus(null);
      }
      if (!cancelled) timer = setTimeout(tick, PROXY_STATUS_POLL_MS);
    }
    tick();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [account?.address]);

  const consentState = status?.consent?.state ?? "absent";

  const handleSwitch = useCallback(
    async (desiredOn) => {
      setNote("");
      const intent = nextSwitchIntent(consentState, desiredOn);
      if (intent.action === "open_disclosure") {
        setShowDisclosure(true);
        return;
      }
      if (intent.action === "require_wallet") {
        setShowUnlock(true);
        return;
      }
      if (intent.action === "show_wallet_mismatch") {
        setNote(consentNoteFor("wallet_mismatch"));
        return;
      }
      setBusy(true);
      try {
        const next = clampLimits({ ...limits, enabled: intent.action === "enable" });
        setLimits(clampLimits(await writeProxyLimits(next)));
      } catch (err) {
        setNote(String(err));
      } finally {
        setBusy(false);
      }
    },
    [consentState, limits],
  );

  const handleSign = useCallback(async () => {
    // `useActiveWallet()` returns `{ name, address }` or null -- there is NO `unlocked`
    // field. The real unlock gate is `wallet_sign_message`'s own signer check, which
    // errors when the wallet is locked; that error lands in the catch below.
    if (!wallet?.address) {
      setShowUnlock(true);
      return;
    }
    setBusy(true);
    try {
      await grantConsent({
        policy: policyDoc.policy,
        daemonPolicyDigest: policyDoc.policy_digest,
        daemonAllowlistDigest: policyDoc.allowlist_digest,
        wallet: account.address,
        deviceId: policyDoc.device_id,
        nowUnix: Math.floor(Date.now() / 1000),
        limits,
      });
      setShowDisclosure(false);
    } catch (err) {
      setNote(`${PROXY_SIGN_REFUSED_NOTE} ${String(err)}`);
    } finally {
      setBusy(false);
    }
  }, [account?.address, policyDoc, wallet?.address, limits]);

  async function applyLimits(patch) {
    const next = clampLimits({ ...limits, ...patch });
    setLimits(next);
    try {
      setLimits(clampLimits(await writeProxyLimits(next)));
    } catch (err) {
      setNote(String(err));
    }
  }

  if (!available) {
    return (
      <section className="panel glass">
        <p role="note">{PROXY_UNAVAILABLE_NOTE}</p>
      </section>
    );
  }
  if (!policyDoc) return null;

  const streamAttached = Boolean(status?.egress_stream_attached);
  const ceiling = effectiveCeilingBytes(status?.consent?.daily_ceiling_bytes, limits);

  return (
    <section className="panel glass proxy-panel">
      <p className="proxy-posture" role="note">{PROXY_TARGET_POSTURE}</p>
      <p className="proxy-posture" role="note">{PROXY_REFUSAL_NOW_NOTE}</p>
      <p className="proxy-posture" role="note">{PROXY_PAYOUT_NOTE}</p>
      <p className="proxy-posture" role="note">{PROXY_SPLIT_PROVENANCE_NOTE}</p>
      <p className="proxy-posture" role="note">{PROXY_MARKETPLACE_GATE_NOTE}</p>

      <BandwidthSwitch on={switchIsOn(status)} disabled={busy} onChange={handleSwitch} />
      {consentNoteFor(consentState) ? (
        <p className="proxy-warn" role="alert">{consentNoteFor(consentState)}</p>
      ) : null}
      {note ? <p className="proxy-warn" role="alert">{note}</p> : null}

      <h3>{PROXY_STATUS_TITLE}</h3>
      <dl className="proxy-counters">
        <dt>{PROXY_BYTES_TODAY_LABEL}</dt><dd>{observed(status?.bytes_today, gb)}</dd>
        <dt>{PROXY_BYTES_SESSION_LABEL}</dt><dd>{observed(status?.bytes_session, gb)}</dd>
        <dt>{PROXY_SOCKETS_LABEL}</dt><dd>{socketCount(status?.sockets_open)}</dd>
      </dl>
      <p className="proxy-hint">{PROXY_COUNTER_SOURCE_NOTE}</p>

      <label className="proxy-control">
        {PROXY_CAP_LABEL}
        <input
          type="number"
          min={1}
          max={200}
          value={limits.daily_cap_gb}
          onChange={(e) => applyLimits({ daily_cap_gb: e.target.value })}
        />
      </label>
      <label className="proxy-control">
        {PROXY_THROTTLE_LABEL}
        <input
          type="number"
          min={64}
          max={100000}
          value={limits.throttle_kbps}
          onChange={(e) => applyLimits({ throttle_kbps: e.target.value })}
        />
      </label>
      <div className="proxy-control">
        <span>{PROXY_SCHEDULE_LABEL}</span>
        {limits.windows.length === 0 ? <p className="proxy-hint">{PROXY_SCHEDULE_EMPTY_NOTE}</p> : null}
        <input
          type="number"
          min={0}
          max={1439}
          value={limits.windows[0]?.start_min_local ?? 0}
          onChange={(e) =>
            applyLimits({
              windows: [
                {
                  start_min_local: e.target.value,
                  end_min_local: limits.windows[0]?.end_min_local ?? 1440,
                  days_mask: 0x7f,
                },
              ],
            })
          }
        />
        <input
          type="number"
          min={1}
          max={1440}
          value={limits.windows[0]?.end_min_local ?? 1440}
          onChange={(e) =>
            applyLimits({
              windows: [
                {
                  start_min_local: limits.windows[0]?.start_min_local ?? 0,
                  end_min_local: e.target.value,
                  days_mask: 0x7f,
                },
              ],
            })
          }
        />
      </div>
      <p className="proxy-hint">{PROXY_CAPS_ENFORCEMENT_NOTE}</p>
      <p className="proxy-hint">{PROXY_CAPS_CONSENTED_NOTE}</p>
      <p className="proxy-hint">{ceiling > 0 ? gb(ceiling) : PROXY_COUNTER_UNOBSERVED}</p>

      <h3>{PROXY_ALLOWLIST_TITLE}</h3>
      <p className="proxy-hint">{PROXY_ALLOWLIST_NOTE}</p>
      <ul className="proxy-allowlist">
        {policyDoc.policy.allowlist.map((e) => (
          <li key={e.id}>
            <code>{e.host}</code> {e.note}
          </li>
        ))}
      </ul>

      <button
        type="button"
        className="btn btn--danger"
        onClick={async () => {
          setHaltReceipt(await killProxy().catch(() => null));
        }}
      >
        {PROXY_KILL_LABEL}
      </button>
      <p className="proxy-hint">{PROXY_KILL_SUBTEXT}</p>
      <button
        type="button"
        className="btn"
        onClick={async () => {
          setHaltReceipt(await revokeProxyConsent().catch(() => null));
        }}
      >
        {PROXY_REVOKE_LABEL}
      </button>
      <p className="proxy-hint">{PROXY_REVOKE_SUBTEXT}</p>
      {haltReceipt ? (
        <p role="status">
          {PROXY_HALT_RECEIPT_LABEL}{" "}
          {haltReceipt.sockets_open_after?.kind === "census"
            ? haltReceipt.sockets_open_after.value
            : PROXY_HALT_UNVERIFIED_NOTE}
        </p>
      ) : null}

      <h3>{PROXY_EGRESS_LOG_TITLE}</h3>
      <p className="proxy-hint">{PROXY_EGRESS_PRIVACY_NOTE}</p>
      {status?.sequence_broken ? <p className="proxy-warn" role="alert">{PROXY_SEQUENCE_BROKEN_NOTE}</p> : null}
      {feed.gapDetected ? <p className="proxy-hint">{PROXY_EGRESS_GAP_NOTE}</p> : null}
      {!streamAttached ? (
        <p className="proxy-warn" role="alert">{PROXY_EGRESS_UNOBSERVED}</p>
      ) : feed.rows.length === 0 ? (
        <p>{PROXY_EGRESS_EMPTY}</p>
      ) : (
        <ul className="proxy-egress">
          {feed.rows.map((r) => (
            <li key={r.seq}>
              <code>{r.host}</code> <code>{r.resolved_ip}</code> {r.outcome} {r.bytes_in + r.bytes_out} B
            </li>
          ))}
        </ul>
      )}

      {showDisclosure ? (
        <ProxyDisclosure
          policyDoc={policyDoc}
          walletPresent={Boolean(wallet?.address)}
          busy={busy}
          onSign={handleSign}
          onDecline={() => setShowDisclosure(false)}
        />
      ) : null}
      {showUnlock ? <UnlockWalletOverlay onClose={() => setShowUnlock(false)} /> : null}
    </section>
  );
}
