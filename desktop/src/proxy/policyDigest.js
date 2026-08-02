// Digest of the disclosure policy. Deliberately NOT a hash of the file bytes: a CRLF
// checkout on Windows would change those. The preimage is a separator-joined
// derivation of the parsed fields, so JS and Rust agree byte-for-byte from the same
// policy.v1.json.
//
// Design authority: the "The No-Ponzi Invariant — GoatCoin's load-bearing economic
// rule" spec, §1 and §8.
import { sha256, stringToHex } from "viem";
import { idForSlug, slugForId } from "./destinations.js";

export const POLICY_DOMAIN = "GOAT-PROXY-POLICY-v1";
// v2, and the bump is the point. A v1 allowlist preimage named a destination by ONE
// identifier -- the slug here, the u32 in the daemon -- so the two sides produced
// different bytes from one list. A v2 record names both, resolved through the
// canonical registry, which is what makes them agree. Any consent record whose
// allowlist digest was computed the v1 way therefore fails the gate, which is wanted:
// it was computed over a preimage that did not bind what the daemon would load.
export const ALLOWLIST_DOMAIN = "GOAT-PROXY-ALLOWLIST-v2";

export const UNIT = String.fromCharCode(0x1f); // between fields of one record
export const RECORD = String.fromCharCode(0x1e); // after each record

// Printable ASCII with no space -- byte for byte what the Rust render path permits.
// A host outside that set could spell a record boundary, and the preimage has no
// length prefixes to fall back on.
const RENDERABLE_HOST = /^[\x21-\x7e]+$/;

function hexDigest(preimage) {
  return sha256(stringToHex(preimage)).slice(2).toLowerCase();
}

export function policyPreimage(policy) {
  let out = `${POLICY_DOMAIN}\n${policy.policy_version}\n`;
  for (const p of policy.paragraphs) out += `${p.heading}${UNIT}${p.body}${RECORD}`;
  return out;
}

/**
 * The canonical allowlist preimage.
 *
 * Every entry is serialised THROUGH the canonical slug <-> id registry: the document
 * names a slug, `idForSlug` turns it into the u32 the daemon carries, and `slugForId`
 * reads the registry's own spelling back out, so the bytes are the registry's and not
 * the document's. A slug the registry does not carry THROWS -- it is never a zero id,
 * and the digest of a list containing it is never computed at all.
 *
 * The construction, exactly: the domain, a newline, then per destination sorted by the
 * NUMERIC id ascending -- the id in base ten, UNIT, the registered slug, UNIT, the
 * host, RECORD. No trailing newline and no length prefixes; the separators carry that
 * weight, which is safe only because the id renders as digits, the slug charset is
 * lower-case letters, digits and hyphens, and a host that could spell a separator is
 * refused here.
 */
export function allowlistPreimage(policy) {
  const rows = policy.allowlist.map((e) => {
    const id = idForSlug(e.id);
    const host = String(e.host ?? "");
    if (!RENDERABLE_HOST.test(host)) {
      throw new Error(`host ${JSON.stringify(host)} cannot be rendered into the canonical preimage`);
    }
    return { id, slug: slugForId(id), host };
  });
  // Sorted on the NUMBER, not on its text: a text sort orders "10" before "2" the
  // moment the registry passes nine rows.
  rows.sort((a, b) => a.id - b.id);
  for (let i = 1; i < rows.length; i += 1) {
    if (rows[i].id === rows[i - 1].id) {
      throw new Error(`destination id ${rows[i].id} appears twice in one list`);
    }
  }
  let out = `${ALLOWLIST_DOMAIN}\n`;
  for (const r of rows) out += `${r.id}${UNIT}${r.slug}${UNIT}${r.host}${RECORD}`;
  return out;
}

export function policyDigest(policy) {
  return hexDigest(policyPreimage(policy));
}

export function allowlistDigest(policy) {
  return hexDigest(allowlistPreimage(policy));
}
