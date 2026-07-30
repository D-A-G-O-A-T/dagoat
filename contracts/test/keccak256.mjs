// keccak256 (original Keccak padding, NOT NIST SHA3) in dependency-free JavaScript.
//
// WHY THIS FILE EXISTS AT ALL
// ---------------------------
// The "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring" spec, §8.1,
// requires "Rust/JavaScript/ops fixtures pin the canonical bytes and hash before
// Policy Safe approval" for
//     feeScheduleHash = keccak256(UTF8(RFC8785(schedulePayload))).
// A JavaScript fixture that cannot compute keccak256 cannot pin that hash.
//
// Node cannot supply it. `crypto.getHashes()` on Node v24.18.0 offers `sha3-256`
// but no `keccak*`: SHA3-256 and keccak256 differ in the domain-separation byte
// appended before the multi-rate padding (0x06 for SHA3 per FIPS 202 §B.2,
// 0x01 for the original Keccak submission that Ethereum froze on). They are
// different functions over the same permutation, so `sha3-256` is not a
// substitute — using it would produce a digest no Solidity `keccak256` and no
// Rust `tiny-keccak` could ever match.
//
// Adding an npm dependency was rejected: `contracts/` has no package.json and
// no node_modules, `node --test test/StreamGManifest.test.mjs` is the whole
// runner, and pulling a package in to check a hash would make the parity
// fixture depend on a supply chain the Rust side does not share.
//
// WHY IT IS TRUSTWORTHY
// ---------------------
// It is not trusted on the strength of this comment. `keccak256.test.mjs` runs
// it against fixed vectors before `StreamGManifest.test.mjs` uses it for
// anything: the two classic published Keccak-256 answers ("" and "abc") plus
// three inputs of 135/136/137 bytes that straddle the 136-byte rate boundary,
// so a padding or block-loop error cannot hide. Every one of the five was also
// reproduced with foundry `cast keccak`, an implementation from outside this
// repository, so agreement with the Rust digest downstream is agreement
// between independent implementations rather than a shared mistake.
//
// BigInt lanes are used deliberately: the 32-bit-halves formulation is roughly
// an order of magnitude faster and considerably easier to get subtly wrong.
// This module hashes two short payloads per test run; clarity wins.

const MASK64 = (1n << 64n) - 1n;

/** Keccak-f[1600] round constants, FIPS 202 §3.2.5 (24 rounds). */
const ROUND_CONSTANTS = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

/** Rho rotation offsets, FIPS 202 §3.2.2, laid out flat as [x + 5*y]. */
const ROTATION_OFFSETS = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
].map(BigInt);

/** Rate in bytes for a 256-bit capacity: (1600 - 2*256) / 8 = 136. */
const RATE_BYTES = 136;

function rotl64(lane, bits) {
  if (bits === 0n) return lane;
  return ((lane << bits) | (lane >> (64n - bits))) & MASK64;
}

/** Keccak-f[1600] permutation, in place, over 25 BigInt lanes indexed [x + 5*y]. */
function keccakF1600(state) {
  for (let round = 0; round < 24; round += 1) {
    // theta
    const c = new Array(5);
    for (let x = 0; x < 5; x += 1) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; x += 1) {
      const d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1n);
      for (let y = 0; y < 5; y += 1) state[x + 5 * y] ^= d;
    }

    // rho + pi: B[y][(2x + 3y) mod 5] = rot(A[x][y], r[x][y])
    const b = new Array(25).fill(0n);
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(state[x + 5 * y], ROTATION_OFFSETS[x + 5 * y]);
      }
    }

    // chi
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        state[x + 5 * y] =
          b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y] & MASK64) & b[((x + 2) % 5) + 5 * y]);
      }
    }

    // iota
    state[0] ^= ROUND_CONSTANTS[round];
  }
}

/**
 * keccak256 over a byte sequence.
 *
 * @param {Uint8Array} message
 * @returns {Uint8Array} 32 bytes
 */
export function keccak256(message) {
  // Multi-rate padding with the ORIGINAL Keccak domain byte 0x01. Changing this
  // to 0x06 turns the function into SHA3-256; the vectors in
  // keccak256.test.mjs are what stops that edit from passing silently.
  const padded = new Uint8Array(Math.ceil((message.length + 1) / RATE_BYTES) * RATE_BYTES);
  padded.set(message);
  padded[message.length] = 0x01;
  padded[padded.length - 1] |= 0x80;

  const state = new Array(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += RATE_BYTES) {
    for (let lane = 0; lane < RATE_BYTES / 8; lane += 1) {
      let value = 0n;
      for (let byte = 7; byte >= 0; byte -= 1) {
        value = (value << 8n) | BigInt(padded[offset + lane * 8 + byte]); // little-endian lane
      }
      state[lane] ^= value;
    }
    keccakF1600(state);
  }

  const out = new Uint8Array(32);
  for (let lane = 0; lane < 4; lane += 1) {
    let value = state[lane];
    for (let byte = 0; byte < 8; byte += 1) {
      out[lane * 8 + byte] = Number(value & 0xffn);
      value >>= 8n;
    }
  }
  return out;
}

/** keccak256 of a string's UTF-8 encoding, as lowercase hex without an 0x prefix. */
export function keccak256Utf8Hex(text) {
  const digest = keccak256(new TextEncoder().encode(text));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}
