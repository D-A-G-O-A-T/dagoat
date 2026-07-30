import { describe, expect, it } from "vitest";
import {
  ALL_COPY, DISCLAIMER_PARAGRAPHS, PASSKEY_HELP, USERNAME_CAUTION, KEY_REVEAL_WARNING,
  PASSKEY_ATTRIBUTION_NOTE,
} from "./copy.js";

// Forbidden vocabulary (07_Tokenomics_Framework honesty rules + locked decisions):
const FORBIDDEN = [
  /\bwage\b/i, /\bpaycheck\b/i, /\bincome\b/i, /\bsalary\b/i, /\bprofit\b/i,
  /\bget paid\b/i, /\bearn money\b/i, /\bpassive income\b/i,
  /protects science/i,
];

/** "investment" is allowed ONLY inside the exact disclaimer phrase
 *  "not an investment" — strip the allowed phrase, then any remaining
 *  occurrence is a violation. (A lookahead can't express this: the negation
 *  precedes the word.) */
function hasForbiddenInvestment(s) {
  return /\binvestment\b/i.test(s.replace(/not an investment/gi, ""));
}

describe("copy laws (spec §13)", () => {
  it("no forbidden vocabulary anywhere in wizard/shell copy", () => {
    for (const s of ALL_COPY) {
      for (const re of FORBIDDEN) {
        expect(s, `"${s}" matches forbidden ${re}`).not.toMatch(re);
      }
      expect(hasForbiddenInvestment(s), `"${s}" uses "investment" outside "not an investment"`).toBe(false);
    }
  });
  it("disclaimer states testnet + no monetary value + self-custody", () => {
    const all = DISCLAIMER_PARAGRAPHS.map((p) => `${p.heading} ${p.body}`).join(" ");
    expect(all).toMatch(/test network/i);
    expect(all).toMatch(/no monetary value/i);
    expect(all).toMatch(/cannot be recovered/i);
    expect(all).toMatch(/Folding@home/);
  });
  it("generated passkey is never called a bonus passkey (D2)", () => {
    expect(PASSKEY_HELP).not.toMatch(/bonus token|bonus passkey/i);
    expect(PASSKEY_HELP).toMatch(/identity token/i);
    expect(PASSKEY_HELP).toMatch(/keep your bonus/i); // pasting an FAH-issued one IS allowed this claim
  });
  it("username caution says permanent (D11)", () => {
    expect(USERNAME_CAUTION).toMatch(/permanent/i);
    expect(USERNAME_CAUTION).toMatch(/cannot be changed/i);
  });
  it("key reveal warning is explicit (D1)", () => {
    expect(KEY_REVEAL_WARNING).toMatch(/only time it is shown automatically/i);
    expect(KEY_REVEAL_WARNING).toMatch(/controls your GOAT/);
  });
  it("passkey attribution note is bound into ALL_COPY (A2)", () => {
    expect(ALL_COPY).toContain(PASSKEY_ATTRIBUTION_NOTE);
  });
});
