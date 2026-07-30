import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useContributeMode } from "../contributeMode.js";
import BackendCard from "../components/BackendCard.jsx";
import FahPreview from "../components/FahPreview.jsx";
import EarningStatus from "../components/EarningStatus.jsx";
import { useActiveWallet, useActiveAccount, listWallets } from "../chain/wallet.js";
import { useNetwork } from "../components/NetworkSwitch.jsx";
import { loadPending } from "../journal.js";
import { attemptSavePending, mergeUnsaved, retryUnsaved, RETRY_INTERVAL_MS } from "../pendingRetry.js";
import { createStuckTracker, selectAutoDumpUnitIds } from "../stuckUnits.js";
import { resolveCause, fetchProjectCause } from "../causes.js";
import { EARNING_OFF_CARD } from "../onboarding/copy.js";
import { syncFahProfileForWallet } from "../walletProfiles.js";
import { readBoundUsername } from "../chain/attribution.js";
import UnlockWalletOverlay from "../components/UnlockWalletOverlay.jsx";

const STATUS_POLL_MS = 3_000;
const ENGINE_POLL_MS = 2_000;
const COMPLETIONS_POLL_MS = 300_000;

// Exact user-facing copy for the managed controls (P3.1). Exported so tests pin the wording.
// Stop now kills the FAH client process (A-D T5, design §C3) — it no longer finishes the unit
// first, so this copy must never claim it "protects the science".
export const STOP_SUBTEXT =
  "Kills the FAH client process. Folding resumes from the work unit's last checkpoint when you start again.";
// A Folding@home client that is linked to an FAH account ignores local resource-config commands,
// so Goat must NOT claim it set CPU/GPU. Honest note shown instead (driven by status.linked).
export const ACCOUNT_MANAGED_NOTE =
  "This machine is linked to a Folding@home account — CPU and GPU settings follow your account, not Goat.";
// Honest credit-lag copy: credited work units come from Folding@home's public stats (which can
// lag hours behind a unit finishing locally), and GOAT is never automatic. Season-0 Ops mintBatch
// accept was retired; pilot settlement is TARGET (bind/enroll + epoch/attestor on testnet).
// Vocabulary law: no mine/mining/wage/paycheck/salary/guaranteed.
export const CREDIT_LAG_NOTE =
  "Credited work units come from Folding@home's public stats and can lag hours behind a unit " +
  "finishing on your machine. GOAT is not automatic — pilot mint is a testnet TARGET after bind, " +
  "enroll, and a finalized epoch (not live mainnet earnings).";
// B6: shown (and Start blocked) when the wallet has neither a local FAH profile nor an on-chain
// bind — folding anonymously would credit nobody, so Start routes the user to bind first.
export const NO_FAH_IDENTITY_BLOCKED =
  "This wallet has no GOAT-username yet. Go to the Wallet tab to bind one before contributing so your work is credited.";
// B8: standing warning (not transient like engineDetail) — an FAH-account-linked machine can
// silently override the GOAT username Goat just configured. B7b (RESOLVED 2026-07-19,
// founder-directed option 3): the local fah-client's control socket still exposes no unlink
// command (verified against fah-client-bastet source, v8.5.5/v8.5.6) — but the MANAGED portable
// client's account link lives in GoatApp's own client.db (SQLite, under the managed engine dir),
// which GoatApp owns outright. So GoatApp automatically clears that link (stop client → schema-
// verified delete of exactly the account-token rows → restart → re-verify) when the account
// overrides the wallet's GOAT username, rather than only ever telling the user to do it by hand.
// This warning discloses that behavior IN ADVANCE (so the app never silently rewrites the
// account relationship without prior on-screen notice) and is honest that re-linking afterward
// still requires the user's own Folding@home web client — see AUTO_UNLINKED_NOTE for the note
// shown after an unlink has actually happened.
export const LINKED_ACCOUNT_WARNING =
  "This machine is linked to a Folding@home account, which can override your GOAT username at " +
  "any time. If that happens, GoatApp automatically unlinks this machine from that account to " +
  "keep your contributions credited to you. Re-linking afterward requires signing in to " +
  "Folding@home's web client.";
// B7b (RESOLVED, option 3): honest note for after GoatApp has actually performed the automatic
// unlink (severed the managed client's account-token in its own client.db) because the linked
// account was overriding the wallet's GOAT username. Rendered through the same generic
// `status.detail` panel that already surfaces backend-driven copy (Rust sets `live.detail` to
// this same honest wording — see fah.rs `post_unlink_recovered_detail`). Kept here as an exported
// constant purely so copy-law tests pin the canonical wording. Never implies re-linking is
// automatic — that still requires the user's own Folding@home web client.
export const AUTO_UNLINKED_NOTE =
  "GoatApp automatically unlinked this machine from your Folding@home account because it was " +
  "overriding your GOAT username. Folding continues under your GOAT identity. To re-link this " +
  "machine, sign in to Folding@home's web client.";
/** B4a: the honest note shown while the OLD wallet's in-flight work unit finishes after a
 *  wallet switch, before the NEW wallet's Start is allowed. */
export function finishingNote(oldName, newName) {
  return `Finishing ${oldName || "the previous wallet"}'s work unit — ${newName || "the new wallet"} starts next.`;
}

/** True when the folding run is currently paused (drives the Pause↔Resume toggle). */
export function isPausedState(state) {
  return String(state ?? "").toLowerCase() === "paused";
}

/** FAH assign/download loop — not computing yet (progress often 0%). */
export function isWaitingState(state) {
  return String(state ?? "").toLowerCase() === "waiting";
}

/** Unit-level: stuck assign/download at ~0% (matches Rust unit_looks_stuck heuristic). */
export function unitLooksStuck(unit) {
  if (!unit) return false;
  const st = String(unit.state ?? "").toUpperCase();
  const waiting =
    st.includes("WAIT") ||
    ["DOWNLOAD", "ASSIGN", "GET_WAIT", "CORE", "SEND", "UPLOAD", "UPLOADING", "FETCH", "COPY"].includes(
      st,
    );
  const pct =
    unit.progress_pct != null && unit.progress_pct !== ""
      ? Number(unit.progress_pct)
      : Number(unit.progress) <= 1
        ? Number(unit.progress) * 100
        : Number(unit.progress);
  return waiting && (!Number.isFinite(pct) || pct < 0.1);
}

/** Pure per-row view model: unique key (row_key fix for same-project parallel
 *  units), friendly science label, and per-row dump gating (30 s stuck rule). */
export function unitRowModel(unit, stuckMap, configCause = null, projectCause = null) {
  const key = unit.row_key ?? unit.id;
  return {
    key,
    causeLabel: resolveCause({ unitCause: unit.cause, projectCause, configCause }),
    showDump: stuckMap.get(key) === true,
  };
}

/** Single toggle label: "Resume" when paused, otherwise "Pause". */
export function pauseResumeLabel(state) {
  return isPausedState(state) ? "Resume" : "Pause";
}

/** Engine states where the UI keeps polling engine_report to auto-advance (replaces Re-check). */
export function enginePolling(engineState) {
  const s = String(engineState ?? "").toLowerCase();
  return s === "missing" || s === "provisioning" || s === "error";
}

/// Normalize backend progress for the bar: FAH reports 0..1 fractions; REHEARSAL
/// reports 0..100. Null/undefined/NaN/negative → 0; clamp to [0, 100].
export function normalizeProgress(progress) {
  const n = Number(progress);
  if (!Number.isFinite(n) || n < 0) return 0;
  const pct = n <= 1 ? n * 100 : n;
  if (pct > 100) return 100;
  return pct;
}

function errMessage(err) {
  if (err == null) return "Unknown error";
  if (typeof err === "string") return err;
  return err.message || String(err);
}

// Survives tab navigation: module scope outlives the component's mount/unmount, and the Rust
// backend (plus the FAH client) keeps folding across tab switches. This remembers whether *Goat*
// started the run (managed lifecycle) per backend id, so returning to Contribute restores the
// Pause/Stop controls instead of collapsing to just "Start contributing". Cleared on Stop.
const contributeSession = {};

// States that mean "no live folding run" — the FAH client is not attached (installed/reachable
// but not connected), never installed, idle, stopped, disconnected, or errored. Mirrors the Rust
// FahLive::from_install states (fah.rs). "paused" is deliberately NOT here — a paused run is still
// a live run. Anything not in this set counts as active (folding or paused).
const INACTIVE_STATES = new Set([
  "",
  "not_installed",
  "installed_not_connected",
  "reachable_not_connected",
  "disconnected",
  "idle",
  "stopped",
  "error",
]);

/** A backend status counts as an active run (folding or paused) — used to reflect the live
 *  worker status after a remount, to grey out Start while a run is in progress, and to detect a
 *  dead backend (e.g. the user killed FAHClient) so the UI can recover instead of sticking. */
export function isActiveStatus(status) {
  if (!status) return false;
  return !INACTIVE_STATES.has(String(status.state ?? "").toLowerCase());
}

/** B6: Start is blocked when the resolver found neither a local profile nor a chain bind. */
export function shouldBlockStartForIdentity(resolvedProfile) {
  return !resolvedProfile?.username;
}

// B4a: wallet switch sets a module-level "finishing" note (App.jsx's switch effect writes it;
// this component may be unmounted when the switch happens since only the active tab renders —
// mirrors wallet.js's unlockProgress external-store pattern for the same reason).
let foldGateNote = null;
const foldGateListeners = new Set();
function emitFoldGate() {
  for (const listener of foldGateListeners) listener();
}
export function setFoldGateNote(note) {
  foldGateNote = note;
  emitFoldGate();
}
export function clearFoldGateNote() {
  foldGateNote = null;
  emitFoldGate();
}
function subscribeFoldGate(cb) {
  foldGateListeners.add(cb);
  return () => foldGateListeners.delete(cb);
}
function getFoldGateSnapshot() {
  return foldGateNote;
}
export function useFoldGateNote() {
  return useSyncExternalStore(subscribeFoldGate, getFoldGateSnapshot, () => null);
}

/** Current fold-gate note — for tests and non-React callers (mirrors getUnlockProgress). */
export function getFoldGateNote() {
  return foldGateNote;
}

/** FIX-A: pure gate-lift decision — whichever (possibly cancelled) switch-effect instance set
 *  the note, an observed non-active FAH status means folding is done and the gate must lift. */
export function foldGateAfterStatus(note, statusActive) {
  return statusActive ? note : null;
}

/** FIX-A: apply foldGateAfterStatus to the live store from any status observation point. This
 *  is the authoritative clearer — Miner's status observation calls it on every snapshot, so a
 *  stranded note (switch effect cancelled mid-poll, early-returned, or finish-rejected) can
 *  never keep Start bricked once the client is actually idle. */
export function applyFoldGateStatus(statusActive) {
  const next = foldGateAfterStatus(foldGateNote, statusActive);
  if (next !== foldGateNote) {
    foldGateNote = next;
    emitFoldGate();
  }
}

/** B4/B4a wiring lives in App.jsx (only the active tab is mounted); Miner exposes this so
 *  App.jsx can clear a stale managed-run record without reaching into Miner's own React state,
 *  which doesn't exist while Miner is unmounted. */
export function clearContributeSession(backendId) {
  delete contributeSession[backendId];
}

/** Pure predicate for the App-level wallet-switch effect: only act on a real switch between two
 *  different, non-null addresses (never on first-unlock or a lock-out). Exported so the switch
 *  trigger gets pure-logic Vitest coverage without rendering App.jsx. */
export function shouldGateOnWalletSwitch(prevAddress, nextAddress) {
  return Boolean(prevAddress && nextAddress && prevAddress !== nextAddress);
}

export default function Miner() {
  const { goatPilot } = useContributeMode();
  const [catalog, setCatalog] = useState([]);
  const [catalogError, setCatalogError] = useState("");
  const [selectedId, setSelectedId] = useState(null);

  const [installState, setInstallState] = useState(null);
  const [installError, setInstallError] = useState("");
  const [connected, setConnected] = useState(false);
  const [actionError, setActionError] = useState("");
  const [status, setStatus] = useState(null);
  const [engineDetail, setEngineDetail] = useState("");
  // Live managed-engine snapshot polled from backend_engine_report while not connected — carries
  // real installer download/EULA progress so the UI never shows a fabricated percentage.
  const [engineReport, setEngineReport] = useState(null);
  const [contributing, setContributing] = useState(false);
  // True only when this session was started via Start contributing (the managed lifecycle). A bare
  // external attach leaves it false so we never expose auto-config controls over the user's own
  // FAH settings (spec §11 — attach must not override the user's client).
  const [managedRun, setManagedRun] = useState(false);

  // FAH identity snapshot (username) — feeds EarningStatus's fahUsername prop. The username/team/
  // passkey editors moved into the onboarding wizard (BindUsername); Contribute only reads it.
  const [identity, setIdentity] = useState(null);
  const [dumpBusyId, setDumpBusyId] = useState(null);
  const [dumpNote, setDumpNote] = useState("");
  // unitId → last auto-dump attempt (ms); prevents dump loops while still stuck.
  const autoDumpAttemptRef = useRef(new Map());

  // Unique-key stuck tracker (spec §7): a row is "stuck" only after >=30s continuously at 0%
  // progress, keyed by row_key so parallel units on the same project never collide.
  // Lazy init so createStuckTracker() runs once, not on every render.
  const stuckTrackerRef = useRef(null);
  if (stuckTrackerRef.current === null) stuckTrackerRef.current = createStuckTracker();
  const stuckTracker = stuckTrackerRef.current;
  // Project-level science-cause cache (tier 2 of resolveCause) — keyed by project id, fetched
  // once per distinct project seen in status.units.
  const [projectCauses, setProjectCauses] = useState({});
  const requestedCausesRef = useRef(new Set());
  // Component-level mounted guard for late-resolving cause fetches: the cause effect re-runs on
  // every 3s status poll, so a per-invocation `cancelled` flag would discard in-flight results
  // (and requestedCausesRef would then permanently block a retry). Only a real unmount cancels.
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // Active wallet (Rust-backed) — for bound wallet note + gasless bind/enroll.
  // Re-renders on unlock/lock/switch in the Wallet tab.
  const activeWallet = useActiveWallet();
  const walletAddress = activeWallet?.address ?? null;
  const account = useActiveAccount();
  const { networkId } = useNetwork();
  // B4a: set by App.jsx's wallet-switch effect while the OLD wallet's in-flight unit finishes;
  // module-scope store since this component unmounts on tab switch (see useFoldGateNote above).
  const foldGateNote = useFoldGateNote();
  // Earn-on + Start without unlock → password popup (defaults to last-used wallet).
  const [unlockOpen, setUnlockOpen] = useState(false);
  const [startAfterUnlock, setStartAfterUnlock] = useState(false);
  const [pending, setPending] = useState([]);
  const [checkError, setCheckError] = useState("");
  const [checking, setChecking] = useState(false);

  // Never-drop buffer: units the backend already durably credited but that failed to save to
  // the local journal (e.g. a transient disk error). Held in state — never discarded — and
  // retried every RETRY_INTERVAL_MS and on demand until appendPending durably persists them.
  const [unsavedUnits, setUnsavedUnits] = useState([]);
  const [retrying, setRetrying] = useState(false);

  const selectedEntry = catalog.find((e) => e.id === selectedId) ?? null;

  // Load catalog + pending journal on mount.
  useEffect(() => {
    let cancelled = false;
    invoke("catalog_list")
      .then((entries) => {
        if (cancelled) return;
        setCatalog(Array.isArray(entries) ? entries : []);
        setCatalogError("");
      })
      .catch((err) => {
        if (!cancelled) setCatalogError(errMessage(err));
      });
    loadPending()
      .then((list) => {
        if (!cancelled) setPending(list);
      })
      .catch(() => {
        /* store unavailable outside Tauri — leave [] */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // FAH identity follows the active wallet (per-wallet GOAT-username profile). Re-read after
  // unlock/switch so Attribution never shows Alice's Rookie while Bob is unlocked.
  useEffect(() => {
    let cancelled = false;
    invoke("backend_fah_identity")
      .then((snap) => {
        if (!cancelled) setIdentity(snap);
      })
      .catch(() => {
        if (!cancelled) setIdentity(null);
      });
    return () => {
      cancelled = true;
    };
  }, [walletAddress]);

  // Auto-select the first enabled catalog entry once loaded.
  useEffect(() => {
    if (selectedId != null) return;
    const first = catalog.find((e) => e.enabled);
    if (first) setSelectedId(first.id);
  }, [catalog, selectedId]);

  // Detect install state when selection changes; reset local connect/status.
  useEffect(() => {
    if (!selectedId) {
      setInstallState(null);
      setConnected(false);
      setStatus(null);
      setActionError("");
      setInstallError("");
      setEngineReport(null);
      setEngineDetail("");
      setManagedRun(false);
      return;
    }
    let cancelled = false;
    setActionError("");
    setInstallError("");
    setInstallState(null);
    setEngineReport(null);
    setEngineDetail("");
    // Restore whether *Goat* started this backend's run (survives tab navigation via module
    // scope) — a bare external attach stays false so we never expose managed controls over it.
    setManagedRun(contributeSession[selectedId]?.managedRun ?? false);
    invoke("backend_detect", { id: selectedId })
      .then((state) => {
        if (!cancelled) setInstallState(state);
      })
      .catch((err) => {
        if (!cancelled) setInstallError(errMessage(err));
      });
    // Probe the REAL folding status. The Rust backend and FAH client keep folding across tab
    // navigation, so returning to Contribute must reflect the live status rather than reset to
    // "not folding". If a run is active, restore connected + status so the status panel and the
    // Pause/Stop controls (when managed) reappear and Start stays greyed.
    invoke("backend_status", { id: selectedId })
      .then((snap) => {
        if (cancelled) return;
        // Surface the real state either way; the recover effect below tears down a stale managed
        // run when the backend is not actually attached (e.g. FAHClient was killed).
        setStatus(snap ?? null);
        setConnected(isActiveStatus(snap));
      })
      .catch(() => {
        if (!cancelled) {
          setConnected(false);
          setStatus(null);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [selectedId]);

  // Auto-recover from a dead/disconnected backend: if status reports a non-active state (e.g. the
  // user killed FAHClient -> "installed_not_connected"), tear down the managed-run UI so
  // "Start contributing" re-enables and Pause/Stop hide, instead of sticking on "Contributing".
  useEffect(() => {
    if (!status) return;
    const active = isActiveStatus(status);
    // FIX-A: authoritative gate-lift — folding done / client gone means the wallet-switch fold
    // gate lifts here, no matter which (possibly cancelled) App switch-effect set the note.
    applyFoldGateStatus(active);
    if (!active) {
      setConnected(false);
      setManagedRun(false);
      if (selectedId) delete contributeSession[selectedId];
      setEngineDetail("FAHClient is no longer attached — Start contributing to relaunch it.");
    }
  }, [status, selectedId]);

  // Auto-refresh the managed-engine snapshot while not connected — this replaces the manual
  // Re-check button and surfaces live provisioning (installer download / EULA) progress during
  // a long-running Start contributing.
  useEffect(() => {
    if (!selectedId || connected) return;
    let cancelled = false;
    async function pollEngine() {
      try {
        const rep = await invoke("backend_engine_report", { id: selectedId });
        if (!cancelled) setEngineReport(rep);
      } catch {
        /* engine_report unavailable outside Tauri — leave last snapshot */
      }
    }
    pollEngine();
    const timer = setInterval(pollEngine, ENGINE_POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [selectedId, connected]);

  // After unlock popup succeeds, auto-continue Start contributing once the wallet is active.
  useEffect(() => {
    if (!startAfterUnlock || !walletAddress || unlockOpen) return;
    setStartAfterUnlock(false);
    handleStartContributing();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only fire on unlock→active transition
  }, [startAfterUnlock, walletAddress, unlockOpen]);

  /**
   * Primary one-click lifecycle (P3.1): ensure the engine (auto-download + launch the official
   * installer when missing — its EULA window opens once) → connect → auto-configure (CPU cores
   * minus 2 + all GPUs) and fold. Live provisioning progress is shown by the engine_report poll.
   */
  async function handleStartContributing() {
    if (!selectedId) return;

    // Earn GOAT on + no unlocked wallet → unlock popup (last used wallet pre-selected).
    if (goatPilot && !walletAddress) {
      setActionError("");
      const wallets = await listWallets().catch(() => []);
      if (!Array.isArray(wallets) || wallets.length === 0) {
        setActionError(
          "Earn GOAT is on but no wallet is stored. Create or import a wallet in the Wallet tab first.",
        );
        return;
      }
      setStartAfterUnlock(true);
      setUnlockOpen(true);
      return;
    }

    setContributing(true);
    setActionError("");
    setEngineDetail("");
    try {
      // Bind live FAH user to this wallet's GOAT-username BEFORE fold (e.g. GOAT-Bob ↔ Bob).
      // Without this, a prior wallet's FAH user can keep folding and steal attribution.
      if (walletAddress) {
        setEngineDetail("Applying wallet FAH identity…");
        const wallets = await listWallets().catch(() => []);
        const resolved = await syncFahProfileForWallet(walletAddress, invoke, {
          walletCount: Array.isArray(wallets) ? wallets.length : 0,
          networkId,
          readBoundUsername,
        }).catch(() => null);
        if (shouldBlockStartForIdentity(resolved)) {
          // B6: no local profile and no chain bind — block Start rather than fold anonymously.
          setActionError(NO_FAH_IDENTITY_BLOCKED);
          return;
        }
        try {
          const snap = await invoke("backend_fah_identity");
          setIdentity(snap);
        } catch {
          /* identity readout is best-effort */
        }
      }
      // One-click: ensure engine (download latest if missing) → wait until API is up →
      // connect WS → start (identity/team + fold). Do not require a second click.
      let report = await invoke("backend_ensure_engine", { id: selectedId });
      setEngineReport(report);
      let state = String(report?.state ?? "").toLowerCase();

      // Ready = process up but port not yet listening — poll instead of asking the user to click again.
      if (state === "ready" || state === "provisioning") {
        setEngineDetail(report?.detail || "Waiting for Folding@home local API…");
        for (let i = 0; i < 60 && state !== "running" && state !== "error"; i++) {
          await new Promise((r) => setTimeout(r, 500));
          try {
            report = await invoke("backend_engine_report", { id: selectedId });
            setEngineReport(report);
            state = String(report?.state ?? "").toLowerCase();
            if (state === "ready" || state === "missing") {
              // Re-ensure: spawn/wait if still not listening.
              report = await invoke("backend_ensure_engine", { id: selectedId });
              setEngineReport(report);
              state = String(report?.state ?? "").toLowerCase();
            }
          } catch {
            /* keep waiting */
          }
        }
      }

      if (state === "running" || state === "ready") {
        setEngineDetail("Connecting to FAH client…");
        let connectErr = null;
        for (let attempt = 0; attempt < 5; attempt++) {
          try {
            await invoke("backend_connect", { id: selectedId });
            connectErr = null;
            break;
          } catch (err) {
            connectErr = err;
            await new Promise((r) => setTimeout(r, 600));
          }
        }
        if (connectErr) {
          setActionError(errMessage(connectErr));
          return;
        }
        setConnected(true);
        setManagedRun(true);
        contributeSession[selectedId] = { managedRun: true };

        setEngineDetail("Applying GOAT team / fold…");
        let startErr = null;
        for (let attempt = 0; attempt < 5; attempt++) {
          try {
            await invoke("backend_start", { id: selectedId });
            startErr = null;
            break;
          } catch (err) {
            startErr = err;
            await new Promise((r) => setTimeout(r, 600));
          }
        }
        if (startErr) {
          setActionError(errMessage(startErr));
        } else {
          let linked = false;
          let ver = null;
          try {
            const snap = await invoke("backend_status", { id: selectedId });
            setStatus(snap);
            linked = !!snap?.linked;
            ver = snap?.client_version ?? null;
          } catch {
            /* status unavailable */
          }
          const verNote = ver ? ` FAH client v${ver}.` : "";
          setEngineDetail(
            linked
              ? ACCOUNT_MANAGED_NOTE + verNote
              : `Contributing — all CPU cores minus 2 and available GPUs are folding.${verNote}`,
          );
        }
      } else if (state === "error") {
        setActionError(report?.detail ?? "Could not provision the engine.");
      } else {
        setActionError(
          report?.detail ||
            "Folding@home did not become ready in time. Finish any installer window, then try Start contributing once more.",
        );
      }
    } catch (err) {
      setActionError(errMessage(err));
    } finally {
      setContributing(false);
    }
  }

  /** One toggle: pause the run, or resume it (v8 "fold"/unpause). Part of the managed lifecycle. */
  async function handlePauseResume() {
    if (!selectedId) return;
    setActionError("");
    const paused = isPausedState(status?.state);
    try {
      if (paused) {
        await invoke("backend_start", { id: selectedId });
        setEngineDetail("Resumed folding.");
      } else {
        await invoke("backend_pause", { id: selectedId });
        setEngineDetail("Folding paused — Resume to continue.");
      }
    } catch (err) {
      setActionError(errMessage(err));
    }
  }

  /** Stop = kill the FAH client process (A-D T5). The run is over — reset the managed-run UI. */
  async function handleStop() {
    if (!selectedId) return;
    setActionError("");
    try {
      await invoke("backend_stop", { id: selectedId });
      setManagedRun(false);
      contributeSession[selectedId] = { managedRun: false };
      setConnected(false);
      setStatus(null);
      setEngineDetail("FAH client stopped. Start contributing will relaunch it.");
    } catch (err) {
      setActionError(errMessage(err));
    }
  }

  // Poll backend_status every 3s while connected.
  useEffect(() => {
    if (!connected || !selectedId) {
      setStatus(null);
      return;
    }
    let cancelled = false;
    async function poll() {
      try {
        const snap = await invoke("backend_status", { id: selectedId });
        if (!cancelled) setStatus(snap);
      } catch (err) {
        if (!cancelled) setActionError(errMessage(err));
      }
    }
    poll();
    const timer = setInterval(poll, STATUS_POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [connected, selectedId]);

  // Tier-2 science cause (spec §7 causes.js): fetch project metadata cause once per distinct
  // project id seen in the live unit list, so causeLabel can fall back to it when the FAH
  // assignment itself omits `cause`. Late results are kept, not discarded: this effect re-runs
  // on every 3s status poll, so gating on a per-invocation cleanup flag would throw away every
  // in-flight resolution while requestedCausesRef blocked the retry. The functional
  // setProjectCauses update is safe after later status changes; only unmount cancels.
  useEffect(() => {
    const ids = [...new Set((status?.units ?? []).map((u) => String(u.project ?? "")).filter(Boolean))];
    const toFetch = ids.filter((id) => !requestedCausesRef.current.has(id));
    if (toFetch.length === 0) return;
    for (const id of toFetch) requestedCausesRef.current.add(id);
    toFetch.forEach((id) => {
      fetchProjectCause(id).then((cause) => {
        if (!mountedRef.current || cause == null) return;
        setProjectCauses((prev) => ({ ...prev, [id]: cause }));
      });
    });
  }, [status]);

  const checkCompletions = useCallback(async () => {
    if (!selectedId) return;
    setChecking(true);
    setCheckError("");
    try {
      const units = await invoke("backend_completions", { id: selectedId });
      // The backend (backend_completions) already durably advanced past these units the
      // moment it returned them — they can never be re-fetched. If the journal save fails,
      // the units must NOT be discarded: hold them in the never-drop buffer instead.
      const result = await attemptSavePending(units, selectedId);
      if (result.saved) {
        setPending(result.journal);
      } else {
        setUnsavedUnits((prev) => mergeUnsaved(prev, units, selectedId));
        setCheckError(errMessage(result.error));
      }
    } catch (err) {
      setCheckError(errMessage(err));
    } finally {
      setChecking(false);
    }
  }, [selectedId]);

  // Auto-check completions every 5 minutes while connected.
  useEffect(() => {
    if (!connected || !selectedId) return;
    const timer = setInterval(checkCompletions, COMPLETIONS_POLL_MS);
    return () => clearInterval(timer);
  }, [connected, selectedId, checkCompletions]);

  const retryUnsavedNow = useCallback(async () => {
    if (unsavedUnits.length === 0) return;
    setRetrying(true);
    try {
      const { stillUnsaved, latestJournal } = await retryUnsaved(unsavedUnits);
      setUnsavedUnits(stillUnsaved);
      if (latestJournal) setPending(latestJournal);
    } finally {
      setRetrying(false);
    }
  }, [unsavedUnits]);

  // Never give up: keep retrying every RETRY_INTERVAL_MS while anything is unsaved. Units
  // stay in `unsavedUnits` (never dropped from state) until a retry durably persists them.
  useEffect(() => {
    if (unsavedUnits.length === 0) return;
    const timer = setInterval(retryUnsavedNow, RETRY_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [unsavedUnits, retryUnsavedNow]);

  /** Dump one stuck FAH unit (official WS cmd:dump) so the client can re-assign.
   *  @param {string} unitId
   *  @param {{ auto?: boolean }} [opts] auto=true when fired by the 30s stuck rule
   */
  async function handleDumpUnit(unitId, opts = {}) {
    if (!selectedId || !unitId) return;
    const auto = Boolean(opts.auto);
    setDumpBusyId(unitId);
    setDumpNote("");
    setActionError("");
    try {
      await invoke("backend_dump_unit", { id: selectedId, unitId });
      setDumpNote(
        auto
          ? `Auto-dumped unit ${unitId.slice(0, 12)}… (0% for ≥30s) — FAH should re-assign.`
          : `Dumped unit ${unitId.slice(0, 12)}… — FAH should re-assign. If still stuck, Pause then Dump again.`,
      );
      // Refresh status quickly after dump.
      try {
        const s = await invoke("backend_status", { id: selectedId });
        setStatus(s);
      } catch {
        /* ignore */
      }
    } catch (err) {
      setActionError(errMessage(err));
    } finally {
      setDumpBusyId(null);
    }
  }

  // Auto-dump units stuck at 0% for ≥30s (same rule as the Dump WU button). One at a time;
  // per-unit cooldown avoids dump loops if FAH re-queues the same id still at 0%.
  useEffect(() => {
    if (!connected || !selectedId || dumpBusyId) return;
    const units = status?.units ?? [];
    if (units.length === 0) return;
    const now = Date.now();
    const stuck = stuckTracker.observe(units, now);
    // Clear cooldown marks for units that recovered (progress or gone from stuck).
    for (const unit of units) {
      const id = unit?.id;
      if (!id) continue;
      const key = unit.row_key ?? id;
      if (stuck.get(key) !== true) autoDumpAttemptRef.current.delete(id);
    }
    const toDump = selectAutoDumpUnitIds(units, stuck, autoDumpAttemptRef.current, now);
    if (toDump.length === 0) return;
    const unitId = toDump[0];
    autoDumpAttemptRef.current.set(unitId, now);
    handleDumpUnit(unitId, { auto: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- dump when status/stuck clock advances
  }, [status, connected, selectedId, dumpBusyId]);

  const pendingForSelected = pending.filter((u) => u.backendId === selectedId);
  const engineState = String(engineReport?.state ?? installState ?? "").toLowerCase();
  const isPaused = isPausedState(status?.state);
  const ready =
    installState === "installed" ||
    installState === "running" ||
    ["ready", "running", "external"].includes(engineState);
  // Actively computing right now: attached, an active (non-dead) state, and not paused.
  const foldingActive = connected && isActiveStatus(status) && !isPaused;
  // Per-row dump gating (spec §7): row_key-keyed 30s-at-0% rule, computed fresh on every render
  // from the live unit list.
  const stuckMap = stuckTracker.observe(status?.units ?? [], Date.now());

  return (
    <section className="tab-panel miner-tab">
      {unlockOpen && (
        <UnlockWalletOverlay
          onClose={() => {
            setUnlockOpen(false);
            setStartAfterUnlock(false);
          }}
          onUnlocked={() => {
            setUnlockOpen(false);
            // startAfterUnlock stays true until walletAddress updates, then the effect starts fold.
          }}
        />
      )}
      <h2 className="page-title contribute-title">Contribute</h2>

      {goatPilot && unsavedUnits.length > 0 && (
        <div className="wallet-section unsaved-units-alert glass" role="alert">
          <p className="error-text">
            {unsavedUnits.length} accepted work unit{unsavedUnits.length === 1 ? "" : "s"} are
            NOT yet saved — retrying…
          </p>
          <div className="wallet-actions-row">
            <button type="button" onClick={retryUnsavedNow} disabled={retrying}>
              {retrying ? "Retrying…" : "Retry save"}
            </button>
          </div>
        </div>
      )}

      {/* Two columns start here: left content top = Work backends, right = 3D preview (not sticky). */}
      <div className="contribute-layout">
        <div className="contribute-main">

      {/* Zero-catalog fallback: catalog still loading or catalog_list failed — the page must
          never render blank (honesty: failure states stay visible). Same pre-task strings. */}
      {catalog.length === 0 && (
        <div className="wallet-section glass">
          <h3>Work backends</h3>
          {catalogError ? (
            <p className="error-text">{catalogError}</p>
          ) : (
            <p className="muted">Loading catalog…</p>
          )}
        </div>
      )}

      {catalog.length > 1 && (
        <div className="wallet-section glass">
          <h3>Work backends</h3>
          {catalogError && <p className="error-text">{catalogError}</p>}
          <div className="backend-grid">
            {catalog.map((entry) => (
              <BackendCard
                key={entry.id}
                entry={entry}
                selected={entry.id === selectedId}
                onSelect={setSelectedId}
              />
            ))}
          </div>
        </div>
      )}

      {selectedEntry && (
        <>
          <div className="wallet-section glass">
            <div className="hero-head">
              <h2>Contribute</h2>
              <span className="hero-head__chip">{selectedEntry.display_name}</span>
            </div>
            <p className="muted contribute-lede">
              One app. <strong>Start contributing</strong> downloads the official portable Folding@home
              client when needed (no EULA installer window) then enables supported GPUs and starts
              folding. Pause or Stop anytime. Powered by Folding@home open source. Goat does not claim a
              GPU sandbox. GOAT pilot is optional (Mode B).
            </p>
            {installError && <p className="error-text">{installError}</p>}
            {installState === null && !installError && <p className="muted">Detecting install…</p>}

            <div className="contribute-primary">
              <button
                type="button"
                className="primary-cta"
                onClick={handleStartContributing}
                disabled={!selectedId || contributing || managedRun || foldingActive || !!foldGateNote}
              >
                {contributing
                  ? "Starting (portable FAH · GPU · fold)…"
                  : foldingActive
                    ? "Contributing"
                    : isPaused
                      ? "Paused"
                      : "Start contributing"}
              </button>
              {managedRun && (
                <>
                  <button
                    type="button"
                    className="btn-pause"
                    onClick={handlePauseResume}
                    disabled={!selectedId}
                    title={isPaused ? "Resume folding" : "Pause folding (keeps the engine running)"}
                  >
                    {pauseResumeLabel(status?.state)}
                  </button>
                  <button
                    type="button"
                    className="btn-finish"
                    onClick={handleStop}
                    disabled={!selectedId}
                    title={STOP_SUBTEXT}
                  >
                    Stop
                  </button>
                </>
              )}
            </div>
            {managedRun && <p className="muted control-subtext">{STOP_SUBTEXT}</p>}

            {/* Live provisioning detail (installer download %, then EULA wait) — never fabricated. */}
            {engineReport?.detail && (enginePolling(engineState) || contributing) && (
              <p className={engineState === "error" ? "error-text" : "install-hint"}>
                {engineReport.detail}
              </p>
            )}
            {engineDetail && <p className="install-hint">{engineDetail}</p>}
            {foldGateNote && <p className="install-hint">{foldGateNote}</p>}
            {actionError && <p className="error-text">{actionError}</p>}

            {engineState === "missing" && !contributing && !engineDetail && (
              <div className="miner-install">
                <p className="install-hint">{selectedEntry.install_hint}</p>
              </div>
            )}

            {connected && status?.linked && (
              <p className="warning-text">{LINKED_ACCOUNT_WARNING}</p>
            )}

            {(ready || connected) && connected && status && (
              <div className="miner-status">
                    <p
                      className={
                        status.state === "error"
                          ? "error-text"
                          : isWaitingState(status.state)
                            ? "status-warn"
                            : "status-ok"
                      }
                    >
                      State: {status.state}
                      {isWaitingState(status.state)
                        ? " (assign/download — not computing yet)"
                        : ""}
                    </p>
                    {dumpNote && <p className="status-ok">{dumpNote}</p>}
                    {(status.units ?? []).map((unit) => {
                      const model = unitRowModel(
                        unit,
                        stuckMap,
                        null,
                        projectCauses[String(unit.project ?? "")] ?? null,
                      );
                      // Align with FAH Web Control Progress column (wu_progress → "25.5").
                      const pctStr =
                        unit.progress_pct != null && unit.progress_pct !== ""
                          ? String(unit.progress_pct)
                          : normalizeProgress(unit.progress).toFixed(1);
                      const pctNum = Number(pctStr);
                      const res = unit.resource || "GPU";
                      const wuNum =
                        unit.number != null && unit.number !== ""
                          ? `#${unit.number}`
                          : null;
                      const stateTok = unit.state || status.state || "";
                      const stuck = unitLooksStuck(unit);
                      return (
                        <div key={model.key} className="progress-row">
                          <div className="progress-row__label">
                            <span title={unit.id}>
                              {res} · Project {unit.project || "?"}
                              <span className="unit-row__cause">{model.causeLabel}</span>
                              {wuNum ? ` · WU ${wuNum}` : ""}
                              {stateTok ? ` · ${stateTok}` : ""}
                              {stuck ? " · stuck?" : ""}
                            </span>
                            <span className={stuck ? "status-warn" : "status-ok"}>
                              {res} Progress {pctStr}%
                            </span>
                          </div>
                          <div
                            className="progress-bar"
                            role="progressbar"
                            aria-valuenow={pctNum}
                            aria-valuemin={0}
                            aria-valuemax={100}
                          >
                            <div
                              className="progress-bar__fill"
                              style={{ transform: `scaleX(${Math.min(100, Math.max(0, pctNum)) / 100})` }}
                            />
                          </div>
                          <div className="wallet-actions-row">
                            <p className="fah-unit-id muted" title={unit.id}>
                              {unit.id}
                            </p>
                            {model.showDump && (
                              <button
                                type="button"
                                className="unit-row__dump"
                                disabled={dumpBusyId === unit.id}
                                onClick={() => handleDumpUnit(unit.id)}
                              >
                                {dumpBusyId === unit.id ? "Dumping…" : "Dump WU"}
                              </button>
                            )}
                          </div>
                        </div>
                      );
                    })}
                    {status.detail ? (
                      <p
                        className={
                          status.state === "error" || /stuck/i.test(status.detail)
                            ? "error-text"
                            : "muted"
                        }
                      >
                        {status.detail}
                      </p>
                    ) : null}
                  </div>
                )}
          </div>

          {goatPilot ? (
            <EarningStatus
              networkId={networkId}
              account={account}
              walletAddress={walletAddress}
              connected={connected}
              fahUsername={identity?.username ?? null}
              fahPasskey={identity?.passkey ?? null}
              pendingUnits={pendingForSelected}
              onCheckWork={checkCompletions}
              checking={checking}
              checkError={checkError}
            />
          ) : (
            <div className="glass earning-off">
              <p>{EARNING_OFF_CARD}</p>
            </div>
          )}
        </>
      )}
        </div>

        <div className="contribute-side">
          <FahPreview status={status} folding={foldingActive || contributing} />
        </div>
      </div>
    </section>
  );
}
