import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { keccak256Utf8Hex } from './keccak256.mjs';

// This file exists so that `StreamGManifest.test.mjs` never has to argue that
// its keccak is a real keccak. If the hand-written permutation in
// `keccak256.mjs` is wrong, it is wrong HERE — against fixed answers this
// repository did not produce — rather than in a cross-language parity
// assertion, where a broken hasher would look like a Rust/JS disagreement.

/**
 * Vectors 1-2 are the published Keccak-256 answers for the empty string and
 * "abc". Vectors 3-5 straddle the 136-byte rate: 135 bytes is the largest
 * input that still pads into a single block, 136 forces a second (all-padding)
 * block, and 137 exercises a partial second block. A wrong pad byte, a
 * misplaced 0x80, or an off-by-one in the absorb loop fails at least one of
 * these even when short inputs pass.
 *
 * All five were independently reproduced with foundry `cast keccak` (see the
 * commands in each comment); the point of pinning them is that a future edit
 * to the permutation has to disagree with a third party, not with itself.
 */
const VECTORS = [
  // cast keccak ""
  ['', 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'],
  // cast keccak "abc"
  ['abc', '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'],
  // cast keccak "aaa...a" (135 bytes)
  ['a'.repeat(135), '34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446'],
  // cast keccak "aaa...a" (136 bytes)
  ['a'.repeat(136), 'a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e'],
  // cast keccak "aaa...a" (137 bytes)
  ['a'.repeat(137), 'd869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39'],
];

test('keccak256 matches published vectors across the rate boundary', () => {
  for (const [input, expected] of VECTORS) {
    assert.equal(
      keccak256Utf8Hex(input),
      expected,
      `keccak256 of a ${input.length}-byte input`,
    );
  }
});

test('keccak256 is not SHA3-256 (the 0x01 vs 0x06 domain byte)', () => {
  // Node ships `sha3-256` and no keccak, so the tempting "fix" for a missing
  // keccak is to reach for SHA3-256. It is a different function over the same
  // permutation: FIPS 202 §B.2 appends the domain bits 01 before the multi-rate
  // pad, the original Keccak submission Ethereum froze on appends nothing.
  // Solidity's keccak256 and Rust's tiny-keccak both implement the latter, so
  // this inequality is the property that makes the parity fixture meaningful.
  const sha3 = createHash('sha3-256').update('abc', 'utf8').digest('hex');
  assert.equal(sha3, '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532');
  assert.notEqual(keccak256Utf8Hex('abc'), sha3);
});
