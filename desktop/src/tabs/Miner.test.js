import { beforeEach, describe, expect, it } from "vitest";
import {
  ACCOUNT_MANAGED_NOTE,
  applyFoldGateStatus,
  AUTO_UNLINKED_NOTE,
  clearFoldGateNote,
  CREDIT_LAG_NOTE,
  enginePolling,
  finishingNote,
  foldGateAfterStatus,
  getFoldGateNote,
  isPausedState,
  isWaitingState,
  LINKED_ACCOUNT_WARNING,
  NO_FAH_IDENTITY_BLOCKED,
  normalizeProgress,
  pauseResumeLabel,
  setFoldGateNote,
  shouldBlockStartForIdentity,
  shouldGateOnWalletSwitch,
  STOP_SUBTEXT,
  unitLooksStuck,
  unitRowModel,
} from "./Miner.jsx";

describe("normalizeProgress", () => {
  it("treats values in 0..1 as fractions", () => {
    expect(normalizeProgress(0.42)).toBe(42);
    expect(normalizeProgress(1)).toBe(100);
  });

  it("treats values already as percentages as-is", () => {
    expect(normalizeProgress(20)).toBe(20);
    expect(normalizeProgress(100)).toBe(100);
  });

  it("maps zero to 0", () => {
    expect(normalizeProgress(0)).toBe(0);
  });

  it("defensive: undefined, null, NaN, negative → 0", () => {
    expect(normalizeProgress(undefined)).toBe(0);
    expect(normalizeProgress(null)).toBe(0);
    expect(normalizeProgress(NaN)).toBe(0);
    expect(normalizeProgress(-1)).toBe(0);
    expect(normalizeProgress(-0.5)).toBe(0);
  });

  it("clamps values greater than 100", () => {
    expect(normalizeProgress(150)).toBe(100);
    expect(normalizeProgress(101)).toBe(100);
  });
});

// P3.1 auto-pilot Start — the managed control set is a single Pause↔Resume toggle plus Stop.
describe("Pause↔Resume toggle", () => {
  it("shows Resume only when the run is paused", () => {
    expect(pauseResumeLabel("paused")).toBe("Resume");
    expect(pauseResumeLabel("PAUSED")).toBe("Resume");
    expect(isPausedState("paused")).toBe(true);
  });

  it("shows Pause while running/idle/unknown", () => {
    expect(pauseResumeLabel("running")).toBe("Pause");
    expect(pauseResumeLabel("idle")).toBe("Pause");
    expect(pauseResumeLabel(undefined)).toBe("Pause");
    expect(pauseResumeLabel(null)).toBe("Pause");
    expect(isPausedState("running")).toBe(false);
  });

  it("is one toggle, never the removed separate controls", () => {
    // The old UI had "Pause folding", "Resume fold", "Finish unit", "Re-check" and "Disconnect".
    // The toggle only ever renders one of exactly these two labels.
    const labels = new Set([pauseResumeLabel("running"), pauseResumeLabel("paused")]);
    expect([...labels].sort()).toEqual(["Pause", "Resume"]);
    for (const removed of ["Re-check", "Disconnect", "Resume fold", "Finish unit", "Pause folding"]) {
      expect(labels.has(removed)).toBe(false);
    }
  });
});

describe("Stop control", () => {
  it("uses the exact kill-process checkpoint subtext", () => {
    expect(STOP_SUBTEXT).toBe(
      "Kills the FAH client process. Folding resumes from the work unit's last checkpoint when you start again."
    );
  });

  it("never claims Stop protects the science (Stop now kills the process, not finishes the unit)", () => {
    expect(STOP_SUBTEXT.toLowerCase()).not.toContain("protects the science");
    expect(STOP_SUBTEXT.toLowerCase()).not.toContain("finishes the current work unit");
  });
});

describe("engine auto-polling (replaces Re-check)", () => {
  it("keeps polling while missing/provisioning/error to auto-advance", () => {
    expect(enginePolling("missing")).toBe(true);
    expect(enginePolling("provisioning")).toBe(true);
    expect(enginePolling("error")).toBe(true);
  });

  it("stops polling once ready/running/external", () => {
    expect(enginePolling("ready")).toBe(false);
    expect(enginePolling("running")).toBe(false);
    expect(enginePolling("external")).toBe(false);
    expect(enginePolling(undefined)).toBe(false);
  });
});

// FIX C/D — account-linked honesty: the engine hint must NOT claim Goat set CPU/GPU when the
// client is bound to a Folding@home account (it ignores local config).
describe("account-managed engine hint", () => {
  it("never repeats the CPU/GPU claim Goat cannot honor when linked", () => {
    expect(ACCOUNT_MANAGED_NOTE.toLowerCase()).not.toContain("minus 2");
    expect(ACCOUNT_MANAGED_NOTE.toLowerCase()).toContain("account");
  });
});

describe("waiting / stuck unit helpers (Assign Wait Loop honesty)", () => {
  it("treats overall waiting as not paused", () => {
    expect(isWaitingState("waiting")).toBe(true);
    expect(isWaitingState("running")).toBe(false);
    expect(isPausedState("waiting")).toBe(false);
  });

  it("flags DOWNLOAD/ASSIGN at 0% as stuck", () => {
    expect(unitLooksStuck({ state: "DOWNLOAD", progress: 0, progress_pct: "0.0" })).toBe(true);
    expect(unitLooksStuck({ state: "ASSIGN", progress: 0 })).toBe(true);
    expect(unitLooksStuck({ state: "RUN", progress: 0.1, progress_pct: "10.0" })).toBe(false);
    expect(unitLooksStuck({ state: "PAUSE", progress: 0 })).toBe(false);
  });
});

// FIX D — credit-lag honesty: credited WUs come from FAH public stats (can lag hours), and GOAT
// is not automatic (pilot/TARGET epoch path — Ops mintBatch accept retired).
describe("credit-lag copy", () => {
  it("names the public-stats lag and that GOAT is not automatic", () => {
    const note = CREDIT_LAG_NOTE.toLowerCase();
    expect(note).toContain("stats");
    expect(note).toContain("lag");
    expect(note).toContain("not automatic");
    expect(note).toContain("target");
    // Retired path must not reappear.
    expect(note).not.toContain("ops");
  });
});

// Copy law: no mine/mining/wage/paycheck/salary/guaranteed in the managed control strings.
describe("copy law", () => {
  it("avoids earning/wage vocabulary in control copy", () => {
    const corpus = [
      STOP_SUBTEXT,
      ACCOUNT_MANAGED_NOTE,
      CREDIT_LAG_NOTE,
      NO_FAH_IDENTITY_BLOCKED,
      LINKED_ACCOUNT_WARNING,
      AUTO_UNLINKED_NOTE,
      finishingNote("GOAT-Old", "GOAT-New"),
    ]
      .join(" ")
      .toLowerCase();
    for (const banned of ["mine", "mining", "wage", "paycheck", "salary", "guaranteed"]) {
      expect(corpus.includes(banned)).toBe(false);
    }
  });

  it("B6 blocked-Start copy points the user at the Wallet tab bind path", () => {
    expect(NO_FAH_IDENTITY_BLOCKED).toContain("Wallet tab");
  });

  it("B8 linked-account warning tells the user to unlink", () => {
    expect(LINKED_ACCOUNT_WARNING.toLowerCase()).toContain("unlink");
  });

  it("B7b RESOLVED (option 3): the standing warning discloses the automatic unlink IN ADVANCE", () => {
    const lower = LINKED_ACCOUNT_WARNING.toLowerCase();
    expect(lower).toContain("automatically unlinks this machine");
    expect(lower).toContain("web client");
    // Superseded claim (GoatApp said it was unable to unlink) must not reappear.
    expect(lower).not.toContain("cannot unlink");
  });

  it("B7b RESOLVED: the post-unlink note is honest about what happened and what re-linking needs", () => {
    const lower = AUTO_UNLINKED_NOTE.toLowerCase();
    expect(lower).toContain("automatically unlinked");
    expect(lower).toContain("overriding your goat username");
    expect(lower).toContain("web client");
  });

  it("B4a finishingNote names both the old and new wallet", () => {
    const note = finishingNote("GOAT-Old", "GOAT-New");
    expect(note).toContain("GOAT-Old");
    expect(note).toContain("GOAT-New");
  });
});

describe("shouldBlockStartForIdentity", () => {
  it("blocks when the resolver found no username", () => {
    expect(shouldBlockStartForIdentity(null)).toBe(true);
    expect(shouldBlockStartForIdentity({ username: "" })).toBe(true);
  });
  it("allows when a username resolved", () => {
    expect(shouldBlockStartForIdentity({ username: "GOAT-Bob" })).toBe(false);
  });
});

describe("shouldGateOnWalletSwitch", () => {
  it("only gates on a real switch between two different non-null addresses", () => {
    expect(shouldGateOnWalletSwitch(null, "0xa")).toBe(false); // first unlock
    expect(shouldGateOnWalletSwitch("0xa", null)).toBe(false); // lock
    expect(shouldGateOnWalletSwitch("0xa", "0xa")).toBe(false); // no-op re-render
    expect(shouldGateOnWalletSwitch("0xa", "0xb")).toBe(true); // real switch
  });
});

// FIX-A: gate clearing is decoupled from the switch-effect instance that set the note, so a
// cancelled/early-returned/finish-rejected effect can never leave Start bricked.
describe("fold gate lifecycle (FIX-A)", () => {
  beforeEach(() => {
    clearFoldGateNote();
  });

  it("foldGateAfterStatus keeps the note only while the run is active", () => {
    expect(foldGateAfterStatus("note", true)).toBe("note");
    expect(foldGateAfterStatus("note", false)).toBeNull();
    expect(foldGateAfterStatus(null, true)).toBeNull();
    expect(foldGateAfterStatus(null, false)).toBeNull();
  });

  it("note set → idle observed → cleared (authoritative clearer)", () => {
    setFoldGateNote(finishingNote("GOAT-Old", "GOAT-New"));
    applyFoldGateStatus(true); // still folding — gate holds
    expect(getFoldGateNote()).toContain("GOAT-Old");
    applyFoldGateStatus(false); // idle observed — gate lifts
    expect(getFoldGateNote()).toBeNull();
    applyFoldGateStatus(false); // idempotent once lifted
    expect(getFoldGateNote()).toBeNull();
  });

  it("a re-switch replaces a stranded note instead of leaving it to a cancelled run", () => {
    // First switch set a note, then was cancelled mid-poll (never cleared).
    setFoldGateNote(finishingNote("GOAT-A", "GOAT-B"));
    // Second switch run owns the gate: clears up front (App does this at the top of every run)…
    clearFoldGateNote();
    // …so an early-return on idle leaves Start unbricked…
    expect(getFoldGateNote()).toBeNull();
    // …and an active run gets a fresh, correctly-named note.
    setFoldGateNote(finishingNote("GOAT-B", "GOAT-A"));
    expect(getFoldGateNote()).toContain("GOAT-B");
    expect(getFoldGateNote()).not.toContain("GOAT-A's"); // old pair's possessive gone
  });

  it("a rejected backend_finish fail-opens the gate (App's reject path clears)", () => {
    setFoldGateNote(finishingNote("GOAT-Old", "GOAT-New"));
    clearFoldGateNote(); // App's catch on backend_finish reject
    expect(getFoldGateNote()).toBeNull();
  });
});

describe("unitRowModel (dup-project fix + science tag + per-row dump)", () => {
  const unit = { id: "u1", row_key: "u1", project: "18201", progress: 0, progress_pct: "0.0", state: "RUN", cause: "cancer", resource: "GPU" };
  it("keys rows by row_key, never project", () => {
    const rows = [unit, { ...unit, row_key: "u1#1", progress: 0.4 }].map((u) => unitRowModel(u, new Map()));
    expect(rows[0].key).toBe("u1");
    expect(rows[1].key).toBe("u1#1");
  });
  it("labels science from per-unit cause", () => {
    expect(unitRowModel(unit, new Map()).causeLabel).toBe("Cancer research");
  });
  it("shows Dump only when the stuck tracker says stuck", () => {
    expect(unitRowModel(unit, new Map([["u1", false]])).showDump).toBe(false);
    expect(unitRowModel(unit, new Map([["u1", true]])).showDump).toBe(true);
  });
});
