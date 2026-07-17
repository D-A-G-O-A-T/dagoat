import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useContributeMode } from "../contributeMode.js";
import BackendCard from "../components/BackendCard.jsx";
import FahPreview from "../components/FahPreview.jsx";
import EarningStatus from "../components/EarningStatus.jsx";
import {
  canSubmit as canSubmitUsername,
  fullUsername,
  GOAT_USERNAME_PREFIX,
  saveUsername,
} from "../components/FirstRunUsername.jsx";
import { useActiveWallet, useActiveAccount } from "../chain/wallet.js";
import { useNetwork } from "../components/NetworkSwitch.jsx";
import { loadPending } from "../journal.js";
import { attemptSavePending, mergeUnsaved, retryUnsaved, RETRY_INTERVAL_MS } from "../pendingRetry.js";
import brandLockup from "../assets/brand/goat-lockup-horizontal-dark.png";

const STATUS_POLL_MS = 3_000;
const ENGINE_POLL_MS = 2_000;
const COMPLETIONS_POLL_MS = 300_000;
const POWER_LEVELS = [
  { id: "low", label: "Low" },
  { id: "medium", label: "Medium" },
  { id: "full", label: "Full" },
];

// Exact user-facing copy for the managed controls (P3.1). Exported so tests pin the wording.
// Stop now kills the FAH client process (A-D T5, design §C3) — it no longer finishes the unit
// first, so this copy must never claim it "protects the science".
export const STOP_SUBTEXT =
  "Kills the FAH client process. Folding resumes from the work unit's last checkpoint when you start again.";
export const AUTOCONFIG_NOTE =
  "Uses all CPU cores minus 2 and available GPUs — adjust with the power control.";
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

export const TEAM_STATS_URL = "https://stats.foldingathome.org/team/1068318";
/** GOAT Folding@home team id — must match fah.rs DEFAULT_TEAM. */
export const GOAT_FAH_TEAM_ID = "1068318";

/** Team brand block renders when the install folds for the GOAT team (1068318). Passkey is no
 *  longer required — team brand is honest without the retired shared secret. */
export function showTeamBrand(identity) {
  return identity?.team === "1068318";
}

/** Optional FAH passkey: empty (base score works) OR exactly 32 hex chars (QRB bonus). */
export const PASSKEY_HEX_RE = /^[0-9a-fA-F]{32}$/;

export function isValidPasskeyInput(raw) {
  const v = (raw ?? "").trim();
  return v === "" || PASSKEY_HEX_RE.test(v);
}

const FAH_BACKEND_ID = "folding_at_home";

/** Job-card auto-config note: the account-managed note when the client is FAH-account-linked (it
 *  ignores local config), else the honest CPU-minus-2 + GPU note. Driven by backend status.linked. */
export function autoConfigNote(linked) {
  return linked ? ACCOUNT_MANAGED_NOTE : AUTOCONFIG_NOTE;
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

  const [powerLevel, setPowerLevel] = useState("medium");
  const [powerError, setPowerError] = useState("");

  // FAH identity snapshot (username/team/passkey flags) — drives brand + username/passkey UI.
  const [identity, setIdentity] = useState(null);
  const [usernameDraft, setUsernameDraft] = useState("");
  const [usernameError, setUsernameError] = useState("");
  const [usernameSaving, setUsernameSaving] = useState(false);
  const [usernameSavedNote, setUsernameSavedNote] = useState("");
  const [passkeyDraft, setPasskeyDraft] = useState("");
  const [passkeyError, setPasskeyError] = useState("");
  const [passkeySaving, setPasskeySaving] = useState(false);
  const [passkeySavedNote, setPasskeySavedNote] = useState("");
  const [dumpBusyId, setDumpBusyId] = useState(null);
  const [dumpNote, setDumpNote] = useState("");
  const [teamBusy, setTeamBusy] = useState(false);
  const [teamNote, setTeamNote] = useState("");

  // Active wallet (Rust-backed) — for bound wallet note + gasless bind/enroll.
  // Re-renders on unlock/lock/switch in the Wallet tab.
  const activeWallet = useActiveWallet();
  const walletAddress = activeWallet?.address ?? null;
  const account = useActiveAccount();
  const { networkId } = useNetwork();
  const [pending, setPending] = useState([]);
  const [checkError, setCheckError] = useState("");
  const [checking, setChecking] = useState(false);

  // Never-drop buffer: units the backend already durably credited but that failed to save to
  // the local journal (e.g. a transient disk error). Held in state — never discarded — and
  // retried every RETRY_INTERVAL_MS and on demand until appendPending durably persists them.
  const [unsavedUnits, setUnsavedUnits] = useState([]);
  const [retrying, setRetrying] = useState(false);

  const selectedEntry = catalog.find((e) => e.id === selectedId) ?? null;

  // Load catalog + pending journal + wallet key on mount.
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
  }, []);

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
    if (status && !isActiveStatus(status)) {
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

  /**
   * Advanced external-attach: connect to a Folding@home client the user already runs, for
   * read-only progress only. Deliberately never calls backend_start — it must not override the
   * user's own settings (spec §11: only Start contributing applies auto-config).
   */
  async function handleAttachConnect() {
    if (!selectedId) return;
    setActionError("");
    try {
      await invoke("backend_connect", { id: selectedId });
      setConnected(true);
      setManagedRun(false);
      contributeSession[selectedId] = { managedRun: false };
      setEngineDetail(
        "Attached to your Folding@home client (read-only progress; resource settings untouched — " +
          "your saved FAH username/passkey may be applied)."
      );
    } catch (err) {
      setConnected(false);
      setActionError(errMessage(err));
    }
  }

  /**
   * Primary one-click lifecycle (P3.1): ensure the engine (auto-download + launch the official
   * installer when missing — its EULA window opens once) → connect → auto-configure (CPU cores
   * minus 2 + all GPUs) and fold. Live provisioning progress is shown by the engine_report poll.
   */
  async function handleStartContributing() {
    if (!selectedId) return;
    setContributing(true);
    setActionError("");
    setEngineDetail("");
    try {
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
          try {
            await invoke("backend_set_power", { id: selectedId, level: "full" });
            setPowerLevel("full");
          } catch {
            /* non-fatal */
          }
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

  async function handlePower(level) {
    if (!selectedId) return;
    setPowerError("");
    try {
      await invoke("backend_set_power", { id: selectedId, level });
      setPowerLevel(level);
    } catch (err) {
      setPowerError(errMessage(err));
    }
  }

  /** Dump one stuck FAH unit (official WS cmd:dump) so the client can re-assign. */
  async function handleDumpUnit(unitId) {
    if (!selectedId || !unitId) return;
    setDumpBusyId(unitId);
    setDumpNote("");
    setActionError("");
    try {
      await invoke("backend_dump_unit", { id: selectedId, unitId });
      setDumpNote(`Dumped unit ${unitId.slice(0, 12)}… — FAH should re-assign. If still stuck, Pause then Dump again.`);
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

  async function handleDumpAllStuck() {
    const stuck = (status?.units ?? []).filter(unitLooksStuck);
    if (!selectedId || stuck.length === 0) return;
    setDumpNote("");
    setActionError("");
    for (const u of stuck) {
      // Sequential dumps — FAH client is single-threaded on config/unit ops.
      // eslint-disable-next-line no-await-in-loop
      await handleDumpUnit(u.id);
    }
    try {
      // After dumping stuck WUs, request fold again so slots refill.
      await invoke("backend_start", { id: selectedId });
      setDumpNote(
        `Dumped ${stuck.length} stuck unit(s) and re-sent fold. Watch unit states leave DOWNLOAD/ASSIGN.`,
      );
    } catch (err) {
      setActionError(errMessage(err));
    }
  }

  /** Push GOAT team 1068318 to FAH (hot-apply when connected). Account-linked clients may still
   *  re-sync account team — change team on foldingathome.org or unlink if this doesn't stick. */
  async function handleSetGoatTeam() {
    if (!selectedId) return;
    setTeamBusy(true);
    setTeamNote("");
    setActionError("");
    try {
      await invoke("backend_configure", {
        id: selectedId,
        key: "team",
        value: GOAT_FAH_TEAM_ID,
      });
      // Re-send identity + fold so team applies without full restart.
      if (connected) {
        try {
          await invoke("backend_start", { id: selectedId });
        } catch {
          /* configure already hot-applied identity patch */
        }
        const snap = await invoke("backend_status", { id: selectedId });
        setStatus(snap);
        const liveTeam = snap?.team != null ? String(snap.team) : "?";
        if (liveTeam === GOAT_FAH_TEAM_ID) {
          setTeamNote(`FAH team is now ${GOAT_FAH_TEAM_ID} (GOAT).`);
        } else {
          setTeamNote(
            `Pushed GOAT team ${GOAT_FAH_TEAM_ID}; live client still reports team ${liveTeam}. ` +
              "Account-linked machines often keep the account team — set team " +
              `${GOAT_FAH_TEAM_ID} at foldingathome.org or unlink this machine, then Start again.`,
          );
        }
      } else {
        setTeamNote(
          `Saved GOAT team ${GOAT_FAH_TEAM_ID}. Start contributing so the FAH client receives it.`,
        );
      }
    } catch (err) {
      setActionError(errMessage(err));
    } finally {
      setTeamBusy(false);
    }
  }

  async function handleSaveUsername(e) {
    e?.preventDefault?.();
    // Allow typing with or without the GOAT- prefix.
    let raw = usernameDraft.trim();
    if (raw.toUpperCase().startsWith(GOAT_USERNAME_PREFIX.toUpperCase())) {
      raw = raw.slice(GOAT_USERNAME_PREFIX.length);
    }
    if (!canSubmitUsername(raw, usernameSaving)) {
      setUsernameError("Enter a name (letters, digits, underscore).");
      setUsernameSavedNote("");
      return;
    }
    setUsernameSaving(true);
    setUsernameError("");
    setUsernameSavedNote("");
    try {
      const saved = await saveUsername(raw);
      const snap = await invoke("backend_fah_identity");
      setIdentity(snap);
      setUsernameDraft("");
      setUsernameSavedNote(
        `Saved FAH username ${saved}. Stop and Start contributing so ClientWeb picks it up (if a run is already live).`,
      );
    } catch (err) {
      setUsernameError(errMessage(err));
    } finally {
      setUsernameSaving(false);
    }
  }

  async function handleSavePasskey(e) {
    e?.preventDefault?.();
    const raw = passkeyDraft.trim();
    if (!isValidPasskeyInput(raw)) {
      setPasskeyError("Passkey must be empty or exactly 32 hex characters.");
      setPasskeySavedNote("");
      return;
    }
    setPasskeySaving(true);
    setPasskeyError("");
    setPasskeySavedNote("");
    try {
      await invoke("backend_configure", {
        id: FAH_BACKEND_ID,
        key: "passkey",
        value: raw,
      });
      const snap = await invoke("backend_fah_identity");
      setIdentity(snap);
      setPasskeyDraft("");
      setPasskeySavedNote(
        raw
          ? "Passkey saved for local FAH client (QRB bonus when FAH accepts it)."
          : "Passkey cleared — base FAH score works without one.",
      );
    } catch (err) {
      setPasskeyError(errMessage(err));
    } finally {
      setPasskeySaving(false);
    }
  }

  const pendingForSelected = pending.filter((u) => u.backendId === selectedId);
  const engineState = String(engineReport?.state ?? installState ?? "").toLowerCase();
  const isPaused = isPausedState(status?.state);
  const ready =
    installState === "installed" ||
    installState === "running" ||
    ["ready", "running", "external"].includes(engineState);
  // Actively computing right now: attached, an active (non-dead) state, and not paused.
  const foldingActive = connected && isActiveStatus(status) && !isPaused;

  return (
    <section className="tab-panel miner-tab">
      <h2>Contribute</h2>
      <p className="muted contribute-lede">
        One app. <strong>Start contributing</strong> downloads the official portable Folding@home
        client when needed (no EULA installer window) then enables supported GPUs and starts
        folding. Pause or Stop anytime. Powered by Folding@home open source. Goat does not claim a
        GPU sandbox. GOAT pilot is optional (Mode B).
      </p>

      <div className="contribute-layout">
        <div className="contribute-main">

      {goatPilot && unsavedUnits.length > 0 && (
        <div className="wallet-section unsaved-units-alert" role="alert">
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

      <div className="wallet-section">
        <h3>Work backends</h3>
        {catalogError && <p className="error-text">{catalogError}</p>}
        {catalog.length === 0 && !catalogError ? (
          <p className="muted">Loading catalog…</p>
        ) : (
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
        )}
      </div>

      {selectedEntry && (
        <>
          <div className="wallet-section">
            <h3>{selectedEntry.display_name}</h3>
            {installError && <p className="error-text">{installError}</p>}
            {installState === null && !installError && <p className="muted">Detecting install…</p>}

            <div className="contribute-primary">
              <button
                type="button"
                className="primary-cta"
                onClick={handleStartContributing}
                disabled={!selectedId || contributing || managedRun || foldingActive}
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
            {actionError && <p className="error-text">{actionError}</p>}

            {engineState === "missing" && !contributing && !engineDetail && (
              <div className="miner-install">
                <p className="install-hint">{selectedEntry.install_hint}</p>
              </div>
            )}

            {(ready || connected) && (
              <>
                {!managedRun && (
                  <details className="advanced-attach">
                    <summary>Already run Folding@home yourself?</summary>
                    <p className="muted">
                      Attach Goat to your existing Folding@home client for read-only progress. This
                      does not change your client&apos;s settings — only Start contributing
                      configures CPU and GPU.
                    </p>
                    {!connected ? (
                      <button type="button" onClick={handleAttachConnect}>
                        Connect
                      </button>
                    ) : (
                      <p className="status-ok">Attached.</p>
                    )}
                  </details>
                )}

                {connected && status && (
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
                    {(status.units ?? []).some(unitLooksStuck) && (
                      <div className="wallet-actions-row" style={{ marginBottom: 8 }}>
                        <button
                          type="button"
                          onClick={handleDumpAllStuck}
                          disabled={Boolean(dumpBusyId)}
                        >
                          {dumpBusyId ? "Dumping…" : "Dump stuck units (0% assign/download)"}
                        </button>
                      </div>
                    )}
                    {dumpNote && <p className="status-ok">{dumpNote}</p>}
                    {(status.units ?? []).map((unit) => {
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
                        <div key={unit.id} className="progress-row">
                          <div className="progress-row__label">
                            <span title={unit.id}>
                              {res} · Project {unit.project || "?"}
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
                              style={{ width: `${Math.min(100, Math.max(0, pctNum))}%` }}
                            />
                          </div>
                          <div className="wallet-actions-row">
                            <p className="fah-unit-id muted" title={unit.id}>
                              {unit.id}
                            </p>
                            {(stuck ||
                              String(stateTok).toUpperCase() === "PAUSE" ||
                              String(stateTok).toUpperCase() === "PAUSED") && (
                              <button
                                type="button"
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

                <div className="miner-power">
                  <p className="muted">FAH resource control — never affects mint</p>
                  <div className="network-switch" role="group" aria-label="Power level">
                    {POWER_LEVELS.map((level) => (
                      <button
                        key={level.id}
                        type="button"
                        className={`network-switch__btn ${powerLevel === level.id ? "active" : ""}`}
                        aria-pressed={powerLevel === level.id}
                        onClick={() => handlePower(level.id)}
                      >
                        {level.label}
                      </button>
                    ))}
                  </div>
                  {powerError && <p className="error-text">{powerError}</p>}
                </div>

                {showTeamBrand(identity) && (
                  <a
                    className="team-brand"
                    href={TEAM_STATS_URL}
                    target="_blank"
                    rel="noreferrer"
                    title="GOAT — Folding@home team 1068318 (live public stats)"
                  >
                    <img src={brandLockup} alt="GOAT — view Folding@home team 1068318 live stats" />
                  </a>
                )}
              </>
            )}
          </div>

          <div className="wallet-section passkey-section">
            <h3>FAH team</h3>
            <p className="muted">
              Science credits go to Folding@home <strong>team {GOAT_FAH_TEAM_ID}</strong> (GOAT). If
              this machine was linked with an account token, the account may force another team
              (e.g. 11) — that overrides username-only config until you fix the account team or
              unlink.
            </p>
            {status?.team != null && String(status.team) !== "" ? (
              <p
                className={
                  String(status.team) === GOAT_FAH_TEAM_ID ? "status-ok" : "status-warn"
                }
                role={String(status.team) === GOAT_FAH_TEAM_ID ? undefined : "alert"}
              >
                Live FAH team: <strong>{String(status.team)}</strong>
                {String(status.team) === GOAT_FAH_TEAM_ID
                  ? " (GOAT)"
                  : ` — wrong team (want ${GOAT_FAH_TEAM_ID})`}
              </p>
            ) : (
              <p className="muted">Live team unknown until connected / Start contributing.</p>
            )}
            <div className="wallet-actions-row">
              <button type="button" disabled={teamBusy} onClick={handleSetGoatTeam}>
                {teamBusy ? "Setting…" : `Set GOAT team (${GOAT_FAH_TEAM_ID})`}
              </button>
              <a className="muted" href={TEAM_STATS_URL} target="_blank" rel="noreferrer">
                Team stats
              </a>
            </div>
            {teamNote && (
              <p className={/wrong|still reports|unlink/i.test(teamNote) ? "status-warn" : "status-ok"}>
                {teamNote}
              </p>
            )}
          </div>

          <div className="wallet-section passkey-section">
            <h3>FAH username</h3>
            <p className="muted">
              Folding@home credits science under this name (not your wallet name). Everyone folds as{" "}
              <code>GOAT-…</code>. This is also what bind &amp; enroll uses for pilot attribution —
              separate from wallet address / wallet vault name.
            </p>
            {identity?.username?.trim() ? (
              <p className="status-ok">
                Current FAH username: <strong>{identity.username}</strong>
              </p>
            ) : (
              <p className="status-warn" role="alert">
                No FAH username set in Goat. ClientWeb may still show an old FAH default (e.g.
                GoatLeader) until you save one here and restart contributing.
              </p>
            )}
            <form className="username-form" onSubmit={handleSaveUsername}>
              <div className="firstrun-input-row">
                <span className="firstrun-prefix">{GOAT_USERNAME_PREFIX}</span>
                <input
                  type="text"
                  name="fah-username"
                  autoComplete="off"
                  placeholder="your name (letters, digits, _)"
                  value={usernameDraft}
                  onChange={(ev) => {
                    setUsernameDraft(ev.target.value);
                    setUsernameError("");
                    setUsernameSavedNote("");
                  }}
                  spellCheck={false}
                />
              </div>
              <p className="firstrun-preview muted">
                Will save as{" "}
                <strong>
                  {fullUsername(
                    usernameDraft.trim().toUpperCase().startsWith(GOAT_USERNAME_PREFIX.toUpperCase())
                      ? usernameDraft.trim().slice(GOAT_USERNAME_PREFIX.length)
                      : usernameDraft,
                  ) || "GOAT-…"}
                </strong>
              </p>
              <button
                type="submit"
                disabled={
                  usernameSaving ||
                  !canSubmitUsername(
                    usernameDraft.trim().toUpperCase().startsWith(GOAT_USERNAME_PREFIX.toUpperCase())
                      ? usernameDraft.trim().slice(GOAT_USERNAME_PREFIX.length)
                      : usernameDraft,
                  )
                }
              >
                {usernameSaving
                  ? "Saving…"
                  : identity?.username?.trim()
                    ? "Update FAH username"
                    : "Save FAH username"}
              </button>
            </form>
            {usernameError && <p className="error-text">{usernameError}</p>}
            {usernameSavedNote && <p className="status-ok">{usernameSavedNote}</p>}
            {identity?.username?.trim() && (
              <p className="muted">
                Changing the name later pauses pilot attribution until bind matches again. Stop +
                Start contributing after a change so the FAH client applies it.
              </p>
            )}
          </div>

          <div className="wallet-section passkey-section">
            <h3>Optional FAH passkey</h3>
            <p className="muted">
              Optional 32-hex Folding@home passkey for QRB bonus. Not required for base score or
              wallet attribution. Sent only to your local FAH client — not your wallet password.
            </p>
            {identity?.passkey_set ? (
              <p className="status-ok">
                Passkey on file
                {identity?.passkey_is_default
                  ? " (legacy shared key — replace with your own when you can)."
                  : "."}
              </p>
            ) : (
              <p className="muted">No passkey set — base folding still attributes via username.</p>
            )}
            <form className="passkey-form" onSubmit={handleSavePasskey}>
              <input
                type="password"
                name="fah-passkey"
                autoComplete="off"
                placeholder="32 hex chars (optional)"
                value={passkeyDraft}
                onChange={(ev) => {
                  setPasskeyDraft(ev.target.value);
                  setPasskeyError("");
                  setPasskeySavedNote("");
                }}
                spellCheck={false}
              />
              <button type="submit" disabled={passkeySaving || !isValidPasskeyInput(passkeyDraft)}>
                {passkeySaving ? "Saving…" : "Save passkey"}
              </button>
            </form>
            {passkeyError && <p className="error-text">{passkeyError}</p>}
            {passkeySavedNote && <p className="status-ok">{passkeySavedNote}</p>}
          </div>

          {goatPilot ? (
            <>
              <div className="wallet-section">
                <h3>Bound wallet</h3>
                {walletAddress ? (
                  <p className="status-ok">
                    Pilot attribution targets {walletAddress} after bind &amp; enroll (testnet).
                  </p>
                ) : (
                  <p className="status-warn">No wallet unlocked — set one in Wallet to bind &amp; enroll</p>
                )}
              </div>

              <EarningStatus
                networkId={networkId}
                account={account}
                walletAddress={walletAddress}
                fahUsername={identity?.username ?? null}
              />

              <div className="wallet-section">
                <div className="wallet-section-header">
                  <h3>Pending work units</h3>
                  <div className="wallet-actions-row">
                    <button
                      type="button"
                      onClick={checkCompletions}
                      disabled={!connected || checking}
                    >
                      {checking ? "Checking…" : "Check for accepted work"}
                    </button>
                  </div>
                </div>
                {checkError && <p className="error-text">{checkError}</p>}
                <p className="muted credit-lag-note">{CREDIT_LAG_NOTE}</p>
                {pendingForSelected.length === 0 ? (
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
                      {pendingForSelected.map((unit) => (
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
              </div>
            </>
          ) : (
            <div className="wallet-section">
              <h3>GOAT pilot</h3>
              <p className="mode-gate-note" role="status">
                Public good only — GOAT pilot is off. Switch mode to join testnet GOAT.
              </p>
            </div>
          )}

          <div className="wallet-section">
            <h3>Job</h3>
            <dl className="balance-grid">
              <dt>Backend</dt>
              <dd>{selectedEntry.display_name}</dd>
              <dt>Beneficiary</dt>
              <dd>{selectedEntry.beneficiary}</dd>
              <dt>Isolation</dt>
              <dd>{selectedEntry.isolation_class}</dd>
              <dt>Honesty</dt>
              <dd>
                {(selectedEntry.honesty_tags ?? []).length === 0
                  ? "—"
                  : selectedEntry.honesty_tags.join(" · ")}
              </dd>
              <dt>Formula</dt>
              <dd>{selectedEntry.formula}</dd>
            </dl>
            <p className="muted autoconfig-note">{autoConfigNote(status?.linked)}</p>
            <p className="required-copy">
              {goatPilot
                ? "The backend does the science; Goat settles pilot GOAT after founder accept — testnet."
                : "The backend does the science. Public-good mode does not mint GOAT — switch mode for the testnet pilot."}
            </p>
          </div>
        </>
      )}
        </div>

        <FahPreview status={status} folding={foldingActive || contributing} />
      </div>
    </section>
  );
}
