import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as proxyCopy from "./copy.js";
import policy from "./policy.v1.json";

// Forbidden tokens are ASSEMBLED, never written -- the same technique the attestor's
// citation audit uses -- so this file does not itself contain the vocabulary it
// forbids. `w()` returns the token; `re()` returns a whole-word case-insensitive
// regex whose source is exactly what the upstream suites declare, so the drift test
// at the bottom can still find it in their source.
const w = (...parts) => parts.join("");
const re = (token) => new RegExp(`\\b${token}\\b`, "i");

const MONEY = [
  w("wa", "ge"),
  w("pay", "check"),
  w("inc", "ome"),
  w("sal", "ary"),
  w("pro", "fit"),
  w("get pa", "id"),
  w("ea", "rn money"),
  w("passive inc", "ome"),
];
// Named for the SHAPE, not for the token, so this identifier is not itself a hit.
const PRESENT_TENSE_TOKENS = [w("ea", "rn"), w("ea", "rning"), w("ea", "rnings"), w("ea", "rns")];
const MINER_SUBSTRINGS = [
  w("mi", "ne"),
  w("mi", "ning"),
  w("wa", "ge"),
  w("pay", "check"),
  w("sal", "ary"),
  "guaranteed",
];
const POLICY_WORDS = [w("block", "list"), w("black", "list"), w("white", "list"), w("lic", "ense")];
// The public-export curator's own rule, reassembled.
const CURATOR = new RegExp(
  `\\b(you\\s+(will\\s+)?${w("ea", "rn")}|start\\s+${w("ea", "rning")}|${w("get\\s+pa", "id")}|${w("pay", "check")}|${w("wa", "ge")}|${w("sal", "ary")})\\b`,
  "i",
);

function hasForbiddenInvestment(s) {
  return /\binvestment\b/i.test(s.replace(/not an investment/gi, ""));
}

// Reflected sweep: anything string-valued exported from copy.js is covered
// automatically, so a new constant cannot be added outside the net.
const REFLECTED = Object.values(proxyCopy).filter((v) => typeof v === "string");
const DISCLOSURE = policy.paragraphs
  .flatMap((p) => [p.heading, p.body])
  .concat([policy.accept_label, policy.decline_label])
  .concat(policy.allowlist.map((e) => e.note));
const CORPUS = [...REFLECTED, ...DISCLOSURE];

describe("bandwidth copy law", () => {
  /// Mutations this detects: any retired money word planted in copy.js or in the
  /// disclosure artifact, in any of the four inherited spellings plus the curator's.
  it("no forbidden vocabulary in any bandwidth copy, against all four existing lists", () => {
    for (const s of CORPUS) {
      for (const token of [...MONEY, ...PRESENT_TENSE_TOKENS]) {
        expect(s, `"${s}" matches ${token}`).not.toMatch(re(token));
      }
      for (const banned of MINER_SUBSTRINGS) {
        expect(s.toLowerCase().includes(banned), `"${s}" contains "${banned}"`).toBe(false);
      }
      expect(s, `"${s}" matches the curator rule`).not.toMatch(CURATOR);
      expect(hasForbiddenInvestment(s), `"${s}" uses "investment" outside "not an investment"`).toBe(false);
    }
    // POSITIVE CONTROL: the regexes really do fire. A sweep whose matcher is broken
    // passes against any corpus at all.
    for (const token of [...MONEY, ...PRESENT_TENSE_TOKENS]) {
      expect(`a sentence containing ${token} in it`).toMatch(re(token));
    }
    expect(`you will ${w("ea", "rn")} something`).toMatch(CURATOR);
    expect(hasForbiddenInvestment("this is an investment")).toBe(true);
  });

  it("the reflected corpus actually contains the strings it claims to cover", () => {
    expect(proxyCopy.PROXY_ALL_COPY.length).toBeGreaterThanOrEqual(40);
    for (const s of proxyCopy.PROXY_ALL_COPY) expect(CORPUS).toContain(s);
    expect(CORPUS.length).toBeGreaterThanOrEqual(70);
    // Floor on the reflected half alone, so a shrunken copy.js cannot be masked by
    // the disclosure half of the corpus.
    expect(REFLECTED.length).toBeGreaterThanOrEqual(45);
  });

  it("vocabulary rulings hold: allowlist and deny-net, never the retired words", () => {
    for (const s of CORPUS) {
      for (const token of POLICY_WORDS) {
        expect(s.toLowerCase(), `"${s}" contains "${token}"`).not.toContain(token);
      }
    }
    expect(CORPUS.join(" ").toLowerCase()).toContain("allowlist");
  });

  /// Mutations this detects: softening or deleting any of the nine consequences the
  /// threat model requires the operator to have read before signing.
  it("the disclosure names every consequence the threat model requires", () => {
    const all = DISCLOSURE.join(" ").toLowerCase();
    expect(all).toContain("ip address"); // the operator's IP is the source
    expect(all).toContain("internet provider"); // provider termination
    expect(all).toContain("cancellation");
    expect(all).toContain("captcha"); // household lockouts
    expect(all).toContain("police"); // law-enforcement contact
    expect(all).toContain("allowlist"); // inspectable list
    expect(all).toContain("90 days"); // re-affirmation
    expect(all).toContain("five seconds"); // revocation latency
    expect(all).toContain("no goat is created");
  });

  it("the disclosure never claims a payout, a price, or a live market", () => {
    const all = DISCLOSURE.join(" ").toLowerCase();
    for (const claim of ["you will receive", "you get", "rewards", "payout", "per gb", "revenue"]) {
      expect(all, `disclosure claims "${claim}"`).not.toContain(claim);
    }
  });

  it("no supply-destroying mechanism is described anywhere on this surface", () => {
    const marker = w("bu", "rn");
    for (const s of CORPUS) expect(s.toLowerCase()).not.toContain(marker);
    // POSITIVE CONTROL: the marker is a real substring test, not a no-op.
    expect(`we ${marker} tokens`).toContain(marker);
  });

  it("every capability claim carries a NOW, TARGET or RESEARCH tag", () => {
    const tagged = [
      proxyCopy.PROXY_TARGET_POSTURE,
      proxyCopy.PROXY_REFUSAL_NOW_NOTE,
      proxyCopy.PROXY_PAYOUT_NOTE,
      proxyCopy.PROXY_SPLIT_PROVENANCE_NOTE,
      proxyCopy.PROXY_MARKETPLACE_GATE_NOTE,
    ];
    for (const s of tagged) expect(s).toMatch(/^\[(NOW|TARGET|RESEARCH)\]/);
    expect(proxyCopy.PROXY_MARKETPLACE_GATE_NOTE).toMatch(/^\[RESEARCH\]/);
    expect(proxyCopy.PROXY_TARGET_POSTURE).toMatch(/^\[TARGET\]/);
    // Exactly one [NOW] claim, and it is about refusing.
    const now = REFLECTED.filter((s) => s.startsWith("[NOW]"));
    expect(now).toHaveLength(1);
    expect(now[0].toLowerCase()).toContain("refus");
  });

  /// Mutations this detects: a bandwidth component reusing the existing switch's
  /// stylesheet classes, which imports that stylesheet's retired vocabulary into a
  /// file this lane creates, in a tree the curator sweeps.
  it("no bandwidth component inherits a retired token through a CSS class name", () => {
    const files = [
      "../components/BandwidthSwitch.jsx",
      "../tabs/Bandwidth.jsx",
      "./steps/ProxyDisclosure.jsx",
    ];
    let scanned = 0;
    let scannedBytes = 0;
    for (const rel of files) {
      const raw = readFileSync(new URL(rel, import.meta.url), "utf8");
      const src = raw.toLowerCase();
      scanned += 1;
      scannedBytes += raw.length;
      for (const token of [...MONEY, ...PRESENT_TENSE_TOKENS]) {
        expect(src, `${rel} contains "${token}" (check className= as well as copy)`).not.toContain(token);
      }
      for (const token of MINER_SUBSTRINGS) {
        expect(src, `${rel} contains "${token}"`).not.toContain(token);
      }
    }
    expect(scanned).toBe(files.length);
    // Floor on BYTES as well as files: a read that silently returned "" would keep
    // the file count and sweep nothing.
    expect(scannedBytes).toBeGreaterThan(8_000);
    // POSITIVE CONTROL: the switch really does use the replacement class names.
    const sw = readFileSync(new URL("../components/BandwidthSwitch.jsx", import.meta.url), "utf8");
    expect(sw).toContain("bandwidth-switch__track");
  });

  it("the disclosure text is not duplicated in any component (one artifact, one hash)", () => {
    const sentinel = policy.paragraphs[2].body.slice(0, 40);
    expect(sentinel.length).toBe(40); // the sentinel is real, not an empty slice
    for (const rel of [
      "../tabs/Bandwidth.jsx",
      "./steps/ProxyDisclosure.jsx",
      "../components/BandwidthSwitch.jsx",
      "./copy.js",
    ]) {
      const src = readFileSync(new URL(rel, import.meta.url), "utf8");
      expect(src, `${rel} inlines disclosure text`).not.toContain(sentinel);
    }
    // POSITIVE CONTROL: the sentinel IS in the artifact it came from.
    expect(readFileSync(new URL("./policy.v1.json", import.meta.url), "utf8")).toContain(sentinel);
  });

  /// Mutations this detects: a future edit to any of the four inherited suites that
  /// drops a token, silently narrowing this sweep to whatever is left.
  it("the four inherited vocabulary lists still declare the tokens this sweep assumes", () => {
    const files = {
      "../onboarding/copy.test.js": [...MONEY],
      "../tabs/Market.test.js": [w("wa", "ge"), w("inc", "ome"), w("pro", "fit"), w("sal", "ary")],
      "../version.test.js": [w("wa", "ge"), w("inc", "ome"), w("pro", "fit"), w("sal", "ary")],
      "../tabs/Miner.test.js": MINER_SUBSTRINGS,
    };
    for (const [rel, tokens] of Object.entries(files)) {
      const src = readFileSync(new URL(rel, import.meta.url), "utf8").toLowerCase();
      expect(src.length, `${rel} read as empty`).toBeGreaterThan(200);
      for (const token of tokens) {
        expect(src, `${rel} no longer bans "${token}"`).toContain(token);
      }
    }
  });
});
