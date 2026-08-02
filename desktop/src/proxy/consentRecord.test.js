import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import policy from "./policy.v1.json";
import { allowlistDigest, policyDigest } from "./policyDigest.js";
import {
  CONSENT_HEADER,
  CONSENT_SCHEMA,
  CONSENT_TTL_SECS,
  buildConsentRecord,
  consentFields,
  consentMessageHex,
  consentPreimage,
  isBlockingConsentState,
  normalizeHex,
} from "./consentRecord.js";

// THE CROSS-LANGUAGE PIN. Written by the sidecar lane, read here without being
// touched: `tools/goat-proxy-worker/**` is zero-edit for this lane, which is exactly
// what makes it a third party. A test comparing this implementation to itself would
// prove nothing.
const FIXTURE = JSON.parse(
  readFileSync(new URL("../../../tools/goat-proxy-worker/fixtures/consent-preimage.json", import.meta.url), "utf8"),
);

/** The fixture writes the integer fields as JSON strings; the record on disk is numbers. */
const num = (v) => Number(v);

function fixtureFields() {
  const r = FIXTURE.record;
  return {
    schema: num(r.schema),
    policy_version: num(r.policy_version),
    policy_digest: r.policy_digest,
    allowlist_digest: r.allowlist_digest,
    wallet: r.wallet,
    device_id: r.device_id,
    daily_ceiling_bytes: num(r.daily_ceiling_bytes),
    throttle_bytes_per_sec: num(r.throttle_bytes_per_sec),
    granted_at_unix: num(r.granted_at_unix),
    expires_at_unix: num(r.expires_at_unix),
  };
}

const FIELDS = () =>
  consentFields({
    policy,
    wallet: "0x00112233445566778899AaBbCcDdEeFf00112233",
    deviceId: "00112233445566778899aabbccddeeff",
    nowUnix: 1_800_000_000,
    dailyCeilingBytes: 5_000_000_000,
    throttleBytesPerSec: 262_144,
  });

describe("consent record", () => {
  /// Mutations this detects: a separator changed here and not in the two Rust
  /// implementations; the field order changed; a trailing newline added or removed;
  /// the header line reworded. Any of those makes the desktop sign one string and
  /// the daemon recover an address from another, so every signature fails.
  it("preimage matches the cross-language fixture", () => {
    const hex = consentMessageHex(fixtureFields());
    expect(hex).toBe(FIXTURE.preimage_hex);
  });

  /// Mutations this detects: dropping any field from the preimage. The daemon checks
  /// all ten, and a field outside the signature is a field a file edit can change.
  it("preimage is domain-separated and pins every field the daemon checks", () => {
    const pre = consentPreimage(FIELDS());
    expect(pre.startsWith(`${CONSENT_HEADER}\n`)).toBe(true);
    expect(pre.endsWith("\n")).toBe(false);
    for (const key of [
      "schema",
      "policy_version",
      "policy_digest",
      "allowlist_digest",
      "wallet",
      "device_id",
      "daily_ceiling_bytes",
      "throttle_bytes_per_sec",
      "granted_at_unix",
      "expires_at_unix",
    ]) {
      expect(pre, `preimage omits ${key}`).toContain(`\n${key}: `);
    }
    expect(pre.split("\n")).toHaveLength(11);
  });

  /// Mutations this detects: a ceiling or throttle moved OUT of the preimage, which
  /// would let a file edit raise a cap while the signature still verified.
  it("the ceiling and the throttle are inside the signed bytes", () => {
    const a = consentPreimage(FIELDS());
    const b = consentPreimage({ ...FIELDS(), daily_ceiling_bytes: 200_000_000_000 });
    const c = consentPreimage({ ...FIELDS(), throttle_bytes_per_sec: 12_800_000 });
    expect(b).not.toBe(a);
    expect(c).not.toBe(a);
  });

  it("re-affirmation window is exactly 90 days", () => {
    expect(CONSENT_TTL_SECS).toBe(90 * 24 * 60 * 60);
    const f = FIELDS();
    expect(f.expires_at_unix - f.granted_at_unix).toBe(CONSENT_TTL_SECS);
  });

  it("preimage is deterministic across calls", () => {
    expect(consentPreimage(FIELDS())).toBe(consentPreimage(FIELDS()));
  });

  /// Mutations this detects: signing a checksummed address spelling. The sidecar
  /// holds twenty bytes and hex-encodes them lower case, so a mixed-case preimage is
  /// one the daemon never reconstructs.
  it("the wallet and the digests are lower-cased before signing", () => {
    const f = FIELDS();
    expect(f.wallet).toBe("0x00112233445566778899aabbccddeeff00112233");
    expect(consentPreimage(f)).toContain("wallet: 0x00112233445566778899aabbccddeeff00112233");
    expect(normalizeHex("0xABCD")).toBe("0xabcd");
    expect(normalizeHex("ABCD")).toBe("0xabcd");
  });

  it("changing one allowlist entry changes the preimage", () => {
    // A REGISTERED slug, because the canonical registry is what the allowlist digest
    // is serialised through: an unregistered one is refused outright rather than
    // producing a different preimage, and this test's subject is the difference.
    const mutated = {
      ...policy,
      allowlist: [...policy.allowlist, { id: "documentation-example-com", host: "example.com", note: "n" }],
    };
    const a = consentPreimage(FIELDS());
    const b = consentPreimage(
      consentFields({
        policy: mutated,
        wallet: "0x00112233445566778899AaBbCcDdEeFf00112233",
        deviceId: "00112233445566778899aabbccddeeff",
        nowUnix: 1_800_000_000,
        dailyCeilingBytes: 5_000_000_000,
        throttleBytesPerSec: 262_144,
      }),
    );
    expect(b).not.toBe(a);
    // POSITIVE CONTROL: the same policy really does reproduce the same preimage,
    // so the inequality above is not two random strings.
    expect(consentPreimage(FIELDS())).toBe(a);
  });

  it("fields carry the current policy and allowlist digests", () => {
    const f = FIELDS();
    expect(f.policy_digest).toBe(normalizeHex(policyDigest(policy)));
    expect(f.allowlist_digest).toBe(normalizeHex(allowlistDigest(policy)));
    expect(f.schema).toBe(CONSENT_SCHEMA);
  });

  /// Mutations this detects: a record built with extra or renamed keys. The sidecar
  /// parses with `deny_unknown_fields`, so one stray key is a refusal to start.
  it("built record carries the schema and the signature verbatim, and no extra keys", () => {
    const record = buildConsentRecord({ fields: FIELDS(), signature: `0x${"11".repeat(65)}` });
    expect(record.schema).toBe(CONSENT_SCHEMA);
    expect(record.signature).toBe(`0x${"11".repeat(65)}`);
    expect(Object.keys(record).sort()).toEqual(
      [
        "allowlist_digest",
        "daily_ceiling_bytes",
        "device_id",
        "expires_at_unix",
        "granted_at_unix",
        "policy_digest",
        "policy_version",
        "schema",
        "signature",
        "throttle_bytes_per_sec",
        "wallet",
      ].sort(),
    );
  });

  /// Mutations this detects: `state !== "valid"` relaxed to a truthiness check, which
  /// would let `undefined` (no status yet) read as permission.
  it("every non-valid consent state blocks traffic", () => {
    for (const s of [
      undefined,
      null,
      "",
      "absent",
      "malformed",
      "stale_policy",
      "expired",
      "bad_signature",
      "wallet_mismatch",
      "wallet_unknown",
    ]) {
      expect(isBlockingConsentState(s), `${s} did not block`).toBe(true);
    }
    // POSITIVE CONTROL: the one state that does not block.
    expect(isBlockingConsentState("valid")).toBe(false);
  });
});
