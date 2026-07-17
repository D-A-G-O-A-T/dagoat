import { describe, expect, it } from "vitest";
import {
  ACCOUNT_MANAGED_NOTE,
  AUTOCONFIG_NOTE,
  autoConfigNote,
  CREDIT_LAG_NOTE,
  enginePolling,
  isPausedState,
  isValidPasskeyInput,
  isWaitingState,
  normalizeProgress,
  pauseResumeLabel,
  showTeamBrand,
  STOP_SUBTEXT,
  TEAM_STATS_URL,
  unitLooksStuck,
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

describe("auto-config job-card note", () => {
  it("states the CPU-minus-2 + GPU auto-config and points at the power control", () => {
    expect(AUTOCONFIG_NOTE).toBe(
      "Uses all CPU cores minus 2 and available GPUs — adjust with the power control."
    );
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

// FIX C/D — account-linked honesty: the job-card auto-config note must NOT claim Goat set
// CPU/GPU when the client is bound to a Folding@home account (it ignores local config).
describe("account-linked auto-config note", () => {
  it("shows the CPU-minus-2 + GPU note only for an unlinked client", () => {
    expect(autoConfigNote(false)).toBe(AUTOCONFIG_NOTE);
    expect(autoConfigNote(undefined)).toBe(AUTOCONFIG_NOTE);
    expect(autoConfigNote(null)).toBe(AUTOCONFIG_NOTE);
  });

  it("shows the account-managed note when linked, never the CPU/GPU claim", () => {
    expect(autoConfigNote(true)).toBe(ACCOUNT_MANAGED_NOTE);
    // The linked note must not repeat the "cores minus 2" claim Goat cannot honor.
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
    const corpus = [STOP_SUBTEXT, AUTOCONFIG_NOTE, ACCOUNT_MANAGED_NOTE, CREDIT_LAG_NOTE]
      .join(" ")
      .toLowerCase();
    for (const banned of ["mine", "mining", "wage", "paycheck", "salary", "guaranteed"]) {
      expect(corpus.includes(banned)).toBe(false);
    }
  });
});

// Team brand: GOAT team 1068318 only (passkey no longer required — retired shared secret).
describe("showTeamBrand", () => {
  it("shows for the GOAT team regardless of passkey flags", () => {
    expect(showTeamBrand({ team: "1068318", passkey_is_default: true })).toBe(true);
    expect(showTeamBrand({ team: "1068318", passkey_is_default: false, passkey_set: false })).toBe(
      true,
    );
    expect(showTeamBrand({ team: "1068318", passkey_set: true })).toBe(true);
  });
  it("hides for a custom team", () => {
    expect(showTeamBrand({ team: "42", passkey_is_default: true })).toBe(false);
  });
  it("hides while identity is not loaded", () => {
    expect(showTeamBrand(null)).toBe(false);
  });
});

describe("isValidPasskeyInput", () => {
  it("accepts empty (base score works without a passkey)", () => {
    expect(isValidPasskeyInput("")).toBe(true);
    expect(isValidPasskeyInput("   ")).toBe(true);
  });
  it("accepts exactly 32 hex chars", () => {
    expect(isValidPasskeyInput("31415926535897932384626433832795")).toBe(true);
    expect(isValidPasskeyInput("abcdef0123456789ABCDEF0123456789")).toBe(true);
  });
  it("rejects wrong length or non-hex", () => {
    expect(isValidPasskeyInput("deadbeef")).toBe(false);
    expect(isValidPasskeyInput("g".repeat(32))).toBe(false);
    expect(isValidPasskeyInput("0".repeat(31))).toBe(false);
    expect(isValidPasskeyInput("0".repeat(33))).toBe(false);
  });
});

describe("TEAM_STATS_URL", () => {
  it("points at the public Folding@home team stats page", () => {
    expect(TEAM_STATS_URL).toBe("https://stats.foldingathome.org/team/1068318");
  });
});
