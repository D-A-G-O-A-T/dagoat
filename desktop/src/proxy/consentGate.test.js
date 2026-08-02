import { beforeEach, describe, expect, it, vi } from "vitest";
import policy from "./policy.v1.json";
import { allowlistDigest, policyDigest } from "./policyDigest.js";
import { consentMessageHex, consentPreimage, normalizeHex } from "./consentRecord.js";
import { clampLimits } from "./limits.js";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args) => invoke(...args) }));

const {
  BLOCKING_CONSENT_STATES,
  consentNoteFor,
  grantConsent,
  killProxy,
  nextSwitchIntent,
  readEgressSince,
  readProxyStatus,
  revokeProxyConsent,
  switchIsOn,
  writeProxyLimits,
} = await import("./consentGate.js");

const WALLET = "0x00112233445566778899AaBbCcDdEeFf00112233";
const LIMITS = clampLimits({ daily_cap_gb: 5, throttle_kbps: 2_048 });

beforeEach(() => {
  invoke.mockReset();
  invoke.mockResolvedValue(null);
});

describe("consent gate routing", () => {
  /// Mutations this detects: routing an absent record to `enable`, which would ask the
  /// daemon to start with nothing signed.
  it("turning the switch on with no record routes to the disclosure and writes nothing", () => {
    expect(nextSwitchIntent("absent", true)).toEqual({ action: "open_disclosure", reason: "absent" });
    expect(nextSwitchIntent(undefined, true).action).toBe("open_disclosure");
    expect(invoke).not.toHaveBeenCalled();
  });

  for (const state of ["expired", "stale_policy", "bad_signature", "malformed"]) {
    it(`turning the switch on with a ${state} record re-opens the disclosure`, () => {
      expect(nextSwitchIntent(state, true)).toEqual({ action: "open_disclosure", reason: state });
    });
  }

  /// Mutations this detects: folding `wallet_mismatch` into the disclosure route, which
  /// asks the operator to sign a second record instead of telling them the first one
  /// belongs to another key -- two records, two keys, and no way to tell which is live.
  it("a wallet mismatch does not re-prompt for signing -- it asks for the right wallet", () => {
    expect(nextSwitchIntent("wallet_mismatch", true).action).toBe("show_wallet_mismatch");
    expect(nextSwitchIntent("wallet_unknown", true).action).toBe("require_wallet");
  });

  it("turning the switch on with a valid record enables limits daemon-side", () => {
    expect(nextSwitchIntent("valid", true).action).toBe("enable");
  });

  /// Mutations this detects: gating the off-path on consent. An operator who wants
  /// traffic stopped must get it stopped whatever the record says.
  it("turning the switch off always halts, whatever the consent state", () => {
    for (const state of [...BLOCKING_CONSENT_STATES, "valid", undefined]) {
      expect(nextSwitchIntent(state, false).action).toBe("disable");
    }
  });

  /// Mutations this detects: deriving the switch from React intent, or from any one of
  /// the three daemon facts alone -- each of which is on while traffic is off.
  it("the switch reflects daemon status, never local intent", () => {
    expect(switchIsOn({ running: true, consent: { state: "valid" }, limits: { enabled: true } })).toBe(true);
    expect(switchIsOn({ running: false, consent: { state: "valid" }, limits: { enabled: true } })).toBe(false);
    expect(switchIsOn({ running: true, consent: { state: "expired" }, limits: { enabled: true } })).toBe(false);
    expect(switchIsOn({ running: true, consent: { state: "valid" }, limits: { enabled: false } })).toBe(false);
    expect(switchIsOn(null)).toBe(false);
    expect(switchIsOn(undefined)).toBe(false);
  });

  it("every non-valid state has an explicit operator-facing note", () => {
    for (const state of BLOCKING_CONSENT_STATES) {
      expect(consentNoteFor(state), `${state} has no note`).not.toBe("");
    }
    expect(BLOCKING_CONSENT_STATES).toEqual(
      expect.arrayContaining([
        "absent",
        "expired",
        "not_yet_valid",
        "stale_policy",
        "wallet_mismatch",
        "wallet_unknown",
        "bad_signature",
        "malformed",
      ]),
    );
    // POSITIVE CONTROL: the valid state deliberately has no warning to show.
    expect(consentNoteFor("valid")).toBe("");
  });
});

describe("granting consent", () => {
  /// Mutations this detects: signing anything other than the pinned preimage -- a JSON
  /// blob, the hex string itself, or a record assembled after signing.
  it("grantConsent signs the exact preimage and submits the assembled record", async () => {
    const signMessage = vi.fn(async () => `0x${"22".repeat(65)}`);
    const submit = vi.fn(async () => ({ state: "valid" }));
    await grantConsent({
      policy,
      daemonPolicyDigest: policyDigest(policy),
      daemonAllowlistDigest: allowlistDigest(policy),
      wallet: WALLET,
      deviceId: "00112233445566778899aabbccddeeff",
      nowUnix: 1_800_000_000,
      limits: LIMITS,
      signMessage,
      submit,
    });

    const record = JSON.parse(submit.mock.calls[0][0].recordJson);
    expect(signMessage).toHaveBeenCalledWith({
      expectedAddress: WALLET,
      messageHex: consentMessageHex(record),
    });
    expect(record.signature).toBe(`0x${"22".repeat(65)}`);
    expect(record.wallet).toBe(normalizeHex(WALLET));
    expect(record.daily_ceiling_bytes).toBe(5_000_000_000);
    expect(record.throttle_bytes_per_sec).toBe(2_048 * 125);
    expect(consentPreimage(record)).toContain("daily_ceiling_bytes: 5000000000");
  });

  /// Mutations this detects: dropping the digest comparison, which lets this screen
  /// sign one text while the daemon holds the hash of another.
  it("signing is blocked when the local disclosure digest disagrees with the daemon", async () => {
    const signMessage = vi.fn();
    const submit = vi.fn();
    await expect(
      grantConsent({
        policy,
        daemonPolicyDigest: "0".repeat(64),
        daemonAllowlistDigest: allowlistDigest(policy),
        wallet: WALLET,
        deviceId: "d",
        nowUnix: 1_800_000_000,
        limits: LIMITS,
        signMessage,
        submit,
      }),
    ).rejects.toThrow(/disagree about the disclosure text/);
    expect(signMessage).not.toHaveBeenCalled();
    expect(submit).not.toHaveBeenCalled();
  });

  /// Mutations this detects: submitting a record before the signature resolves, which
  /// would store an unsigned record the daemon then refuses -- leaving a trace of a
  /// grant that never happened.
  it("a refused signature leaves the switch off and stores nothing", async () => {
    const signMessage = vi.fn(async () => {
      throw new Error("wallet is locked");
    });
    const submit = vi.fn();
    await expect(
      grantConsent({
        policy,
        daemonPolicyDigest: policyDigest(policy),
        daemonAllowlistDigest: allowlistDigest(policy),
        wallet: WALLET,
        deviceId: "d",
        nowUnix: 1_800_000_000,
        limits: LIMITS,
        signMessage,
        submit,
      }),
    ).rejects.toThrow(/wallet is locked/);
    expect(submit).not.toHaveBeenCalled();
  });
});

describe("IPC wrappers name the commands the backend registers", () => {
  it("each wrapper calls its own snake_case command", async () => {
    await readProxyStatus();
    await readEgressSince(7);
    await writeProxyLimits(LIMITS);
    await killProxy();
    await revokeProxyConsent();
    expect(invoke.mock.calls.map((c) => c[0])).toEqual([
      "backend_proxy_status",
      "backend_proxy_egress_log",
      "backend_proxy_set_limits",
      "backend_proxy_kill",
      "backend_proxy_consent_revoke",
    ]);
    expect(invoke.mock.calls[1][1]).toEqual({ sinceSeq: 7 });
    expect(JSON.parse(invoke.mock.calls[2][1].limitsJson).daily_cap_gb).toBe(5);
  });

  /// Mutations this detects: re-adding a `wallet` argument to the status read. The
  /// expected operator address must be the one the Rust process holds unlocked, never
  /// one the webview names -- otherwise the caller picks its own expected value and
  /// the consent check is self-referential.
  it("the status read names no wallet -- the backend resolves the active one", async () => {
    await readProxyStatus();
    expect(invoke.mock.calls[0]).toEqual(["backend_proxy_status"]);
  });
});
