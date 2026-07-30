import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { keccak256Utf8Hex } from './keccak256.mjs';

// Minimal RFC 8785-ish JCS: object keys sorted lexicographically, no whitespace.
// `Array.prototype.sort` with no comparator orders by UTF-16 code unit, which is
// exactly what RFC 8785 §3.2.3 mandates.
//
// This function produces bytes for anything; it does not police its input. The
// Rust side (`tools/goat-attestor/src/canonical_json.rs`) deliberately REFUSES
// inputs whose bytes the two runtimes could disagree on, so anything hashed for
// cross-language parity must go through `canonicalizeSchedulePayload` or
// `canonicalizeDeploymentPayload` below, both of which apply the same refusals.
//
// (Until 2026-07-28 raw `canonicalize` was also used by a "Stream G manifest
// JCS is stable and key-order independent" test. That test canonicalised a
// manifest-shaped fixture INCLUDING its own `deploymentManifestHash` field,
// hashed it with SHA-256 — not keccak — and compared the result to itself. It
// proved key-order stability and nothing else; it was not, and could not be, a
// content binding, because a payload containing its own digest can never be
// made to match. It has been replaced by the deploymentManifestHash tests at
// the bottom of this file, which hash a payload the digest is NOT a member of.
// Its fixture also carried JSON numbers, which `canonical_json.rs` refuses
// outright, so the repository had been pinning two mutually exclusive
// definitions of "the manifest's canonical bytes".)
function canonicalize(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalize(v)).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  const body = keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',');
  return `{${body}}`;
}

// (A `sha256Hex` helper lived here, used only by the retired legacy manifest
// test described above. It was originally named `keccak256Hex` while computing
// SHA-256 — a name that was not harmless, because a reader checking "does the JS
// fixture pin the same digest as Rust?" would see `keccak256Hex(...)` and
// conclude yes. Nothing in this file computes SHA-256 any more; every digest
// here is real keccak256 from ./keccak256.mjs.)

// Mirror of `canonical_json::validate` (tools/goat-attestor/src/canonical_json.rs:125-153,
// with the key alphabet from `is_portable_key` at :117-119).
// The three refusals are not stylistic. Rust's serde_json orders object members
// by UTF-8 byte while RFC 8785 orders by UTF-16 code unit (they agree only
// within ASCII), and RFC 8785 §3.2.2.3 mandates the ECMAScript
// `Number::toString` algorithm, which serde_json does not implement. Rather than
// let one runtime silently win those cases, BOTH sides refuse to hash them —
// so this JS validator has to reject exactly what Rust rejects, or the two
// implementations would disagree about which payloads are hashable at all.
function assertPortable(value, path) {
  if (typeof value === 'number') {
    throw new Error(
      `JSON number at ${path}: RFC 8785 mandates ECMAScript Number::toString, which ` +
        'serde_json does not implement; the fee-schedule schema requires all integers ' +
        'and timestamps to be decimal strings',
    );
  }
  if (typeof value === 'boolean') {
    throw new Error(
      `JSON bool at ${path}: the canonical schedule schema admits only strings, ` +
        'objects, arrays and null',
    );
  }
  if (value === null || typeof value === 'string') return;
  if (Array.isArray(value)) {
    value.forEach((item, i) => assertPortable(item, `${path}[${i}]`));
    return;
  }
  if (typeof value === 'object') {
    for (const key of Object.keys(value)) {
      if (!/^[A-Za-z0-9_]+$/.test(key)) {
        throw new Error(
          `non-portable object key at ${path}: ${JSON.stringify(key)} has characters ` +
            'outside [A-Za-z0-9_]',
        );
      }
      assertPortable(value[key], `${path}.${key}`);
    }
    return;
  }
  throw new Error(`unsupported JSON type at ${path}`);
}

/** JS counterpart of `canonical_json::canonical_bytes`: validate, then serialise. */
function canonicalizeSchedulePayload(payload) {
  assertPortable(payload, '$');
  return canonicalize(payload);
}

/** JS counterpart of `canonical_json::canonical_hash`. */
function feeScheduleHashOf(payload) {
  return `0x${keccak256Utf8Hex(canonicalizeSchedulePayload(payload))}`;
}

// Resolved from this file, not from cwd: the other tests here use cwd-relative
// paths because they read artifacts that only exist when run from `contracts/`,
// but the attestor fixture is a fixed sibling of this repository tree and the
// parity claim should not depend on where node was launched.
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

test('31337.stream-g.json if present is G1-only and has required keys', () => {
  const path = resolve('deployments/31337.stream-g.json');
  if (!existsSync(path)) {
    // Deploy test creates it; this remains a soft check when artifact absent.
    return;
  }
  const raw = readFileSync(path, 'utf8');
  const json = JSON.parse(raw);
  assert.equal(json.chainId, 31337);
  assert.equal(json.schemaVersion, 1);
  assert.equal(json.phase, 'G1');
  for (const key of [
    'enrollmentRegistry',
    'goatCoin',
    'feeToken',
    'feeTokenRegistry',
    'walletSponsorshipRegistry',
    'sponsoredBuyDesk',
    'goatRelayGateway',
    'policySafe',
    'feeSafe',
    'recoverySafe',
    'deskOwner',
    'quoteSigner',
    'deploymentManifestHash',
    'feeScheduleHash',
  ]) {
    assert.ok(json[key], `missing ${key}`);
  }
  assert.equal(existsSync(resolve('deployments/84532.stream-g.json')), false);
});

// ---------------------------------------------------------------------------
// feeScheduleHash cross-language parity
//
// The "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring" spec,
// §8.1 "Quote construction":
//   "feeScheduleHash = keccak256(UTF8(RFC8785(schedulePayload))). Rust/JavaScript/ops
//    fixtures pin the canonical bytes and hash before Policy Safe approval."
// and §5.1: "Desktop, relayer, deployment tooling, and Foundry fixtures must
// produce the same bytes/hash".
//
// These tests are the JavaScript half of that pair. They pin the same two
// fixtures the Rust half pins, by value, so the two are compared rather than
// merely both existing:
//   * the five-field known-answer payload in
//     `tools/goat-attestor/src/canonical_json.rs` (`tests::known_answer_hash`)
//   * the shipped schedule in
//     `tools/goat-attestor/fixtures/stream_g_fee_schedule.json`, pinned Rust-side
//     by `stream_g::quotes` (`shipped_placeholder_fee_schedule_is_published_and_serves_no_price`)
// ---------------------------------------------------------------------------

test('feeScheduleHash: JS reproduces the Rust known-answer bytes and hash', () => {
  // Byte-identical to the payload in canonical_json.rs `tests::known_answer_hash`,
  // supplied in the same non-sorted order so this fixture exercises the ordering
  // rule and not just the hash.
  const payload = {
    scheduleVersion: '1',
    feeToken: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
    chainId: '8453',
    schemaVersion: '1',
    decimals: '6',
  };

  // "scheduleVersion" precedes "schemaVersion": at index 4, 'd' (0x64) < 'm'
  // (0x6D). Not the order a human sorts those two by eye, which is why the
  // fixture pins bytes rather than intuition.
  const EXPECTED_BYTES =
    '{"chainId":"8453","decimals":"6",' +
    '"feeToken":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",' +
    '"scheduleVersion":"1","schemaVersion":"1"}';

  assert.equal(canonicalizeSchedulePayload(payload), EXPECTED_BYTES);
  assert.equal(EXPECTED_BYTES.length, 131, 'canonical byte length is part of the fixture');
  assert.equal(
    keccak256Utf8Hex(EXPECTED_BYTES),
    '21695bf5b63f320da2e6907150f510b2782fb70b89a17b2949786707b18cc3b8',
  );
});

test('feeScheduleHash: JS reproduces the SHIPPED schedule bytes and hash', () => {
  const path = resolve(REPO_ROOT, 'tools/goat-attestor/fixtures/stream_g_fee_schedule.json');
  const file = JSON.parse(readFileSync(path, 'utf8'));

  // Approval metadata is outside the payload (spec :808): the schedule payload
  // is exactly eleven named fields, and neither `feeScheduleHash` nor `note` is
  // among them, so both are siblings of `payload` rather than members of it.
  // That is what keeps the digest from having to reference itself, and it is
  // why editing the operator note does not move the hash.
  //
  // Corrected 2026-07-27: this cited `:244-246`, which is the *deployment
  // manifest* section — that is where the sentence "Approval metadata is
  // outside the payload" is literally written (`:244`). The schedule inherits
  // the rule, but via `:808` ("the same RFC 8785/UTF-8 rules as the deployment
  // manifest"), so `:808` is the citation that governs a schedule-payload
  // claim.
  assert.ok(file.payload, 'the shipped schedule must carry a payload object');
  assert.equal(file.payload.feeScheduleHash, undefined);
  assert.equal(file.payload.note, undefined);

  const bytes = canonicalizeSchedulePayload(file.payload);

  // Pinned verbatim from `quotes.rs` SHIPPED_CANONICAL_BYTES. Written here as a
  // literal, not derived, so this is a comparison against the Rust fixture and
  // not a restatement of whatever the file happens to contain today.
  const EXPECTED_BYTES =
    '{"actionFeesRaw":{"GOAT_STREAM_G_GOAT_TRANSFER_V1":null,' +
    '"GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1":null,' +
    '"GOAT_STREAM_G_SPONSORED_SELL_V1":null,' +
    '"GOAT_STREAM_G_USDT_TRANSFER_V1":null},' +
    '"calldataByteCeilings":{"GOAT_STREAM_G_GOAT_TRANSFER_V1":"0",' +
    '"GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1":"0",' +
    '"GOAT_STREAM_G_SPONSORED_SELL_V1":"0",' +
    '"GOAT_STREAM_G_USDT_TRANSFER_V1":"0"},' +
    '"chainId":"31337","decimals":"6",' +
    '"feeToken":"0xddc10602782af652bb913f7bde1fd82981db7dd9",' +
    '"gasUnitCeilings":{"GOAT_STREAM_G_GOAT_TRANSFER_V1":"0",' +
    '"GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1":"0",' +
    '"GOAT_STREAM_G_SPONSORED_SELL_V1":"0",' +
    '"GOAT_STREAM_G_USDT_TRANSFER_V1":"0"},' +
    '"maxNativeExposureWei":"0","scheduleVersion":"1","schemaVersion":"1",' +
    '"validAfter":"0","validUntil":"0"}';

  assert.equal(bytes, EXPECTED_BYTES, 'JS canonical bytes differ from the Rust fixture');
  assert.equal(bytes.length, 728, 'canonical byte length is part of the fixture');

  // The digest the Rust side computes, pinned as a literal for the same reason.
  const EXPECTED_HASH = '0x1c663d43fccc550dd95ef9dcd469eb12ac98006d355fea4ce9fcdc002ff8d952';
  assert.equal(feeScheduleHashOf(file.payload), EXPECTED_HASH);

  // The file must declare the digest of its own payload, or `goat-attestor`
  // refuses to start (StreamGStartupError::FeeScheduleHashSelfMismatch).
  assert.equal(file.feeScheduleHash, EXPECTED_HASH);

  // ...and the deployment artifact must publish the same value, or every quote
  // reverts ConfigHashMismatch() at contracts/src/libraries/StreamGCommon.sol:122-124.
  const artifactPath = resolve('deployments/31337.stream-g.json');
  if (existsSync(artifactPath)) {
    const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
    assert.equal(artifact.feeScheduleHash, EXPECTED_HASH);
  }

  // The canonical byte length is 728 ASCII characters, so `.length` (UTF-16 code
  // units) and the UTF-8 byte count coincide. Asserted rather than assumed,
  // because the Rust fixture pins 728 BYTES.
  assert.equal(new TextEncoder().encode(bytes).length, 728);
});

test('feeScheduleHash: JS refuses exactly what the Rust canonicaliser refuses', () => {
  // A payload one runtime hashes and the other rejects is worse than a
  // mismatch: it would ship as "parity verified" on whichever side ran.
  assert.throws(
    () => canonicalizeSchedulePayload({ chainId: 31337 }),
    /JSON number at \$\.chainId/,
  );
  assert.throws(
    () => canonicalizeSchedulePayload({ enabled: true }),
    /JSON bool at \$\.enabled/,
  );
  assert.throws(
    () => canonicalizeSchedulePayload({ 'fee-token': '0x00' }),
    /non-portable object key at \$/,
  );
  // Recursive, matching `canonical_json::tests::rejects_nested_violations`.
  assert.throws(
    () => canonicalizeSchedulePayload({ a: { b: [{ c: 1 }] } }),
    /JSON number at \$\.a\.b\[0\]\.c/,
  );
});

// ---------------------------------------------------------------------------
// deploymentManifestHash cross-language parity
//
// The "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring" spec,
// §5.1 "FeeTokenRegistry":
//   manifestHash = keccak256(UTF8(RFC8785(payload)))
// and §5.1: "Desktop, relayer, deployment tooling, and Foundry fixtures must
// produce the same bytes/hash and require equality with the on-chain approved
// hash."
//
// This is the ORIGINAL of the rule feeScheduleHash inherits (§8.1 says the
// schedule "uses the same RFC 8785/UTF-8 rules as the deployment manifest").
// Until 2026-07-28 `deploymentManifestHash` was the literal
// keccak256("stream-g-manifest-g1"), a tag that hashed nothing: every address
// and every runtime code hash could change and it would not move.
//
// The Rust half is `tools/goat-attestor/src/stream_g/deployment_payload.rs`
// (`tests::known_answer_hash` and
// `tests::shipped_deployment_payload_is_published_and_binds_the_manifest`);
// the ops half is `goat-attestor deployment-manifest-hash --payload-json`.
// ---------------------------------------------------------------------------

// Mirror of `deployment_payload::require_lowercase_hex`.
//
// Every hex-valued field in the payload must be spelled LOWERCASE, per spec
// `:244` ("addresses are lowercase 0x plus 40 hex digits"), and is REFUSED
// otherwise. The paths are `releaseCommit`, each `contracts[*].address` and
// `contracts[*].runtimeCodeHash`, and each `accounts[*]`.
//
// This used to lowercase instead of refusing, on the stated grounds that the
// document's only producer was `vm.serializeAddress` (EIP-55 mixed case) and a
// refusal would leave a document no tool in this repository could hash. That
// was false — `lib/forge-std/src/Vm.sol:1351` declares `toLowercase` — and
// `DeployStreamG.writeDeploymentPayload` now emits
// `vm.toLowercase(vm.toString(addr))`. The cost of the old accommodation was
// that the canonical bytes were a PROJECTION of the file rather than its own
// values reordered, so an operator diffing the document against the hashed
// bytes saw different text.
//
// Deliberately schema-directed rather than "police anything that looks like
// hex": a pattern rule would silently start policing a future field nobody
// checked, in one runtime before the other.
function assertLowercaseHex(payload) {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('payload is not a JSON object');
  }
  const check = (field, value) => {
    if (typeof value !== 'string') return;
    if (/[A-Z]/.test(value)) throw new Error(`${field} is not lowercase: ${value}`);
  };
  check('payload.releaseCommit', payload.releaseCommit);
  if (payload.contracts !== undefined) {
    if (
      payload.contracts === null ||
      typeof payload.contracts !== 'object' ||
      Array.isArray(payload.contracts)
    ) {
      throw new Error('payload.contracts is not a JSON object');
    }
    for (const [role, entry] of Object.entries(payload.contracts)) {
      if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
        throw new Error(`payload.contracts.${role} is not a JSON object`);
      }
      for (const field of ['address', 'runtimeCodeHash']) {
        check(`payload.contracts.${role}.${field}`, entry[field]);
      }
    }
  }
  if (payload.accounts !== undefined) {
    if (
      payload.accounts === null ||
      typeof payload.accounts !== 'object' ||
      Array.isArray(payload.accounts)
    ) {
      throw new Error('payload.accounts is not a JSON object');
    }
    for (const [role, entry] of Object.entries(payload.accounts)) {
      check(`payload.accounts.${role}`, entry);
    }
  }
}

/** JS counterpart of `deployment_payload::canonical_deployment_payload_bytes`. */
function canonicalizeDeploymentPayload(payload) {
  assertLowercaseHex(payload);
  assertPortable(payload, '$');
  return canonicalize(payload);
}

/** JS counterpart of `DeploymentPayload::computed_deployment_manifest_hash`. */
function deploymentManifestHashOf(payload) {
  return `0x${keccak256Utf8Hex(canonicalizeDeploymentPayload(payload))}`;
}

test('deploymentManifestHash: JS reproduces the Rust known-answer bytes and hash', () => {
  // Byte-identical to the payload in `deployment_payload.rs`'s `tests::doc_with`
  // default, supplied here in a scrambled member order so this fixture also
  // exercises the ordering rule. Every hex value carries LETTERS on purpose: an
  // all-digit fixture would make the casing rule unobservable.
  const payload = {
    releaseCommit: 'abcdef0123456789abcdef0123456789abcdef01',
    schemaVersion: '2',
    accounts: {
      RECOVERY_SAFE: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee08',
      DESK_OWNER: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee01',
      QUOTE_SIGNER: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee07',
      FEE_TOKEN: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee04',
      ENROLLMENT_REGISTRY: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee02',
      POLICY_SAFE: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee06',
      FEE_SAFE: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee03',
      GOAT_COIN: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee05',
    },
    contracts: {
      WALLET_SPONSORSHIP_REGISTRY: {
        runtimeCodeHash: '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        address: '0xdddddddddddddddddddddddddddddddddddddddd',
      },
      GATEWAY: {
        runtimeCodeHash: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        address: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      },
      SPONSORED_BUY_DESK: {
        address: '0xcccccccccccccccccccccccccccccccccccccccc',
        runtimeCodeHash: '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      },
      FEE_TOKEN_REGISTRY: {
        address: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        runtimeCodeHash: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
    },
    chainId: '31337',
    deploymentVersion: '1',
  };

  const EXPECTED_BYTES =
    '{"accounts":{"DESK_OWNER":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee01",' +
    '"ENROLLMENT_REGISTRY":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee02",' +
    '"FEE_SAFE":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee03",' +
    '"FEE_TOKEN":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee04",' +
    '"GOAT_COIN":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee05",' +
    '"POLICY_SAFE":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee06",' +
    '"QUOTE_SIGNER":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee07",' +
    '"RECOVERY_SAFE":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee08"},' +
    '"chainId":"31337","contracts":{' +
    '"FEE_TOKEN_REGISTRY":{"address":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",' +
    '"runtimeCodeHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},' +
    '"GATEWAY":{"address":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",' +
    '"runtimeCodeHash":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},' +
    '"SPONSORED_BUY_DESK":{"address":"0xcccccccccccccccccccccccccccccccccccccccc",' +
    '"runtimeCodeHash":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},' +
    '"WALLET_SPONSORSHIP_REGISTRY":{"address":"0xdddddddddddddddddddddddddddddddddddddddd",' +
    '"runtimeCodeHash":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}},' +
    '"deploymentVersion":"1","releaseCommit":"abcdef0123456789abcdef0123456789abcdef01",' +
    '"schemaVersion":"2"}';

  assert.equal(canonicalizeDeploymentPayload(payload), EXPECTED_BYTES);
  assert.equal(EXPECTED_BYTES.length, 1282, 'canonical byte length is part of the fixture');
  assert.equal(new TextEncoder().encode(EXPECTED_BYTES).length, 1282);
  assert.equal(
    keccak256Utf8Hex(EXPECTED_BYTES),
    'a12e1fdc329e77af55c7161c244246f954ce485ecf1487c5f5a5fa66a79d0abb',
  );
});

test('deploymentManifestHash: JS reproduces the SHIPPED payload bytes and hash', () => {
  const path = resolve(REPO_ROOT, 'tools/goat-attestor/fixtures/stream_g_deployment_payload.json');
  const file = JSON.parse(readFileSync(path, 'utf8'));

  // Approval metadata is outside the payload (spec :244): the payload is
  // exactly five named fields, and neither `deploymentManifestHash` nor `note`
  // is among them. That is what keeps the digest from having to reference
  // itself — and it is precisely what the retired legacy test got wrong.
  assert.ok(file.payload, 'the shipped document must carry a payload object');
  assert.equal(file.payload.deploymentManifestHash, undefined);
  assert.equal(file.payload.note, undefined);
  assert.deepEqual(
    Object.keys(file.payload).sort(),
    ['accounts', 'chainId', 'contracts', 'deploymentVersion', 'releaseCommit', 'schemaVersion'],
  );
  assert.equal(file.payload.schemaVersion, '2');
  assert.deepEqual(
    Object.keys(file.payload.contracts).sort(),
    ['FEE_TOKEN_REGISTRY', 'GATEWAY', 'SPONSORED_BUY_DESK', 'WALLET_SPONSORSHIP_REGISTRY'],
  );
  assert.deepEqual(Object.keys(file.payload.accounts).sort(), [
    'DESK_OWNER',
    'ENROLLMENT_REGISTRY',
    'FEE_SAFE',
    'FEE_TOKEN',
    'GOAT_COIN',
    'POLICY_SAFE',
    'QUOTE_SIGNER',
    'RECOVERY_SAFE',
  ]);
  // Four + eight = every address the flat artifact carries.
  assert.equal(
    Object.keys(file.payload.contracts).length + Object.keys(file.payload.accounts).length,
    12,
  );

  // Spec `:244` — the file itself is lowercase, so the canonical bytes are its
  // own values reordered rather than a projection of them. Asserted on the raw
  // TEXT, because every comparison downstream is case-insensitive and would
  // pass either way.
  const rawText = readFileSync(path, 'utf8');
  assert.equal(
    /"0x[0-9a-fA-F]*[A-F][0-9a-fA-F]*"/.test(rawText),
    false,
    'precondition: every hex value in the shipped payload is lowercase (spec :244)',
  );

  const bytes = canonicalizeDeploymentPayload(file.payload);

  // Pinned verbatim from `deployment_payload.rs`. Written as a literal, not
  // derived, so this compares against the Rust fixture rather than restating
  // whatever the file happens to contain today.
  const EXPECTED_BYTES =
    '{"accounts":{"DESK_OWNER":"0x7fa9385be102ac3eac297483dd6233d62b3e1496",' +
    '"ENROLLMENT_REGISTRY":"0x104fbc016f4bb334d775a19e8a6510109ac63e00",' +
    '"FEE_SAFE":"0xd1ccc21678e1b7015a472216b2f501f421645b43",' +
    '"FEE_TOKEN":"0xddc10602782af652bb913f7bde1fd82981db7dd9",' +
    '"GOAT_COIN":"0x037eda3adb1198021a9b2e88c22b464fd38db3f3",' +
    '"POLICY_SAFE":"0x7fa9385be102ac3eac297483dd6233d62b3e1496",' +
    '"QUOTE_SIGNER":"0xebd5a85005dcc98dabb7a2888de82d43c5a6957e",' +
    '"RECOVERY_SAFE":"0xb8705214e170151048eff0a1ede1824fff19cb9c"},' +
    '"chainId":"31337","contracts":{' +
    '"FEE_TOKEN_REGISTRY":{"address":"0x7fdb3132ff7d02d8b9e221c61cc895ce9a4bb773",' +
    '"runtimeCodeHash":"0xfba313e548e577b7511cbde7326a5afb713940d7c9d9de7f46e28df26ebf3b75"},' +
    '"GATEWAY":{"address":"0x4ff05a443250a64a18c68cedd2122cfdf3872140",' +
    '"runtimeCodeHash":"0x474ebb2bf11d1462c26e0d5dab9cd8d326b81094d44041f43e31c143976531db"},' +
    '"SPONSORED_BUY_DESK":{"address":"0xd76ffbd1eff76c510c3a509fe22864688ac3a588",' +
    '"runtimeCodeHash":"0xb31c7ccddd6577c6d2ac9ebdd3f3cd9f95d320198eade02a9e387277c6d36dae"},' +
    '"WALLET_SPONSORSHIP_REGISTRY":{"address":"0xfd07c974e33dd1626640ba3a5acf0418faacca7a",' +
    '"runtimeCodeHash":"0xdd985541ff21871feeeabdcc70ae3ce65a1f7f5b1bbf8249e1aa8ec170b735d4"}},' +
    '"deploymentVersion":"1","releaseCommit":"0000000000000000000000000000000000000000",' +
    '"schemaVersion":"2"}';

  assert.equal(bytes, EXPECTED_BYTES, 'JS canonical bytes differ from the Rust fixture');
  assert.equal(bytes.length, 1282, 'canonical byte length is part of the fixture');
  assert.equal(new TextEncoder().encode(bytes).length, 1282);

  const EXPECTED_HASH = '0x05f8b33ddff7855f64c5f38553cadea8648f5d1889ca17624a59f9f507d26491';
  assert.equal(deploymentManifestHashOf(file.payload), EXPECTED_HASH);

  // The file must declare the digest of its own payload, or `goat-attestor`
  // refuses to start (StreamGStartupError::DeploymentManifestHashSelfMismatch).
  assert.equal(file.deploymentManifestHash, EXPECTED_HASH);

  // ...and the deployment artifact must publish the same value, or `start`
  // refuses with DeploymentManifestHashMismatch and every signed intent names a
  // deployment the manifest never approved.
  const artifactPath = resolve('deployments/31337.stream-g.json');
  if (existsSync(artifactPath)) {
    const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
    assert.equal(artifact.deploymentManifestHash, EXPECTED_HASH);

    // All TWELVE addresses must name the artifact's. This is the JavaScript
    // half of `start`'s per-role bind: the digest cannot notice an address
    // edited in the FLAT artifact, because nothing the payload hashes moved.
    // Before schema 2 only the four `contracts` roles were here, and the other
    // eight were bound by nothing in any language.
    for (const [role, key] of [
      ['FEE_TOKEN_REGISTRY', 'feeTokenRegistry'],
      ['GATEWAY', 'goatRelayGateway'],
      ['SPONSORED_BUY_DESK', 'sponsoredBuyDesk'],
      ['WALLET_SPONSORSHIP_REGISTRY', 'walletSponsorshipRegistry'],
    ]) {
      assert.equal(
        file.payload.contracts[role].address.toLowerCase(),
        artifact[key].toLowerCase(),
        `${role} disagrees with the artifact's ${key}`,
      );
    }
    for (const [role, key] of [
      ['DESK_OWNER', 'deskOwner'],
      ['ENROLLMENT_REGISTRY', 'enrollmentRegistry'],
      ['FEE_SAFE', 'feeSafe'],
      ['FEE_TOKEN', 'feeToken'],
      ['GOAT_COIN', 'goatCoin'],
      ['POLICY_SAFE', 'policySafe'],
      ['QUOTE_SIGNER', 'quoteSigner'],
      ['RECOVERY_SAFE', 'recoverySafe'],
    ]) {
      assert.equal(
        file.payload.accounts[role].toLowerCase(),
        artifact[key].toLowerCase(),
        `${role} disagrees with the artifact's ${key}`,
      );
    }
  }
});

// This test runs AFTER `forge test` in run-full-gate.ps1, and that ordering is
// the whole point of it.
//
// `contracts/deployments/31337.stream-g.payload.json` is a COMMITTED file that
// `DeployStreamG.writeDeploymentPayload` rewrites unconditionally on every
// `forge test` run. If a contract edit moves a runtime code hash, or a deploy
// parameter moves an address, that rewrite leaves the committed document
// declaring a `deploymentManifestHash` its own content no longer produces — and
// `goat-attestor` then refuses to start against the repository's own artifacts
// with `DeploymentManifestHashSelfMismatch`.
//
// Nothing used to notice at gate time. Step 1 (`cargo test --lib`, which owns
// the byte-identity guards) runs BEFORE step 4 (`forge test`), so the gate
// checked the artifacts the PREVIOUS run left behind, passed, and then left the
// tree red. This is the check that runs on the far side of step 4.
test('deploymentManifestHash: forge test left the committed payload self-consistent', () => {
  const artifactPath = resolve('deployments/31337.stream-g.payload.json');
  if (!existsSync(artifactPath)) return; // deploy test creates it

  const rawArtifact = readFileSync(artifactPath, 'utf8');
  const doc = JSON.parse(rawArtifact);
  assert.equal(
    deploymentManifestHashOf(doc.payload),
    doc.deploymentManifestHash,
    'the committed deployment payload does not hash to the digest it declares. `forge test` ' +
      'rewrote it from DeployStreamG.t.sol::SHIPPED_DEPLOYMENT_MANIFEST_HASH; recompute with ' +
      '`goat-attestor deployment-manifest-hash --payload-json contracts/deployments/' +
      '31337.stream-g.payload.json`, put the value in that constant, re-run `forge test`, and ' +
      're-copy both artifacts into tools/goat-attestor/fixtures/',
  );

  // ...and it must be byte-identical to the fixture compiled into the binary,
  // or the daemon's built-in fall-through describes a deployment the lab no
  // longer has.
  const fixture = readFileSync(
    resolve(REPO_ROOT, 'tools/goat-attestor/fixtures/stream_g_deployment_payload.json'),
    'utf8',
  );
  assert.equal(
    rawArtifact,
    fixture,
    'contracts/deployments/31337.stream-g.payload.json and ' +
      'tools/goat-attestor/fixtures/stream_g_deployment_payload.json have diverged; re-copy ' +
      'the artifact over the fixture',
  );
});

test('deploymentManifestHash: key-order independent, hex-case REFUSED, one nibble moves it', () => {
  const base = {
    schemaVersion: '2',
    deploymentVersion: '1',
    chainId: '31337',
    releaseCommit: 'abcdef0123456789abcdef0123456789abcdef01',
    accounts: {
      DESK_OWNER: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee01',
      ENROLLMENT_REGISTRY: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee02',
      FEE_SAFE: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee03',
      FEE_TOKEN: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee04',
      GOAT_COIN: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee05',
      POLICY_SAFE: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee06',
      QUOTE_SIGNER: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee07',
      RECOVERY_SAFE: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee08',
    },
    contracts: {
      FEE_TOKEN_REGISTRY: {
        address: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        runtimeCodeHash: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      GATEWAY: {
        address: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        runtimeCodeHash: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      },
      SPONSORED_BUY_DESK: {
        address: '0xcccccccccccccccccccccccccccccccccccccccc',
        runtimeCodeHash: '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      },
      WALLET_SPONSORSHIP_REGISTRY: {
        address: '0xdddddddddddddddddddddddddddddddddddddddd',
        runtimeCodeHash: '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
      },
    },
  };

  // Member order does not move the digest — JCS sorts.
  const scrambled = {
    contracts: base.contracts,
    schemaVersion: base.schemaVersion,
    accounts: base.accounts,
    releaseCommit: base.releaseCommit,
    deploymentVersion: base.deploymentVersion,
    chainId: base.chainId,
  };
  assert.notEqual(
    JSON.stringify(base),
    JSON.stringify(scrambled),
    'the two must differ as TEXT',
  );
  assert.equal(deploymentManifestHashOf(base), deploymentManifestHashOf(scrambled));

  // Uppercase hex is REFUSED, in each of the four hashed paths individually —
  // one loop over "the payload" would leave three of them unchecked. Rust does
  // the same in `deployment_payload::tests::refuses_uppercase_hex_in_every_hashed_field`;
  // a payload one runtime hashes and the other rejects would ship as "parity
  // verified" on whichever side ran.
  const withUpper = (mutate) => {
    const p = JSON.parse(JSON.stringify(base));
    mutate(p);
    return p;
  };
  for (const [label, mutate] of [
    ['releaseCommit', (p) => (p.releaseCommit = p.releaseCommit.toUpperCase())],
    [
      'contracts[*].address',
      (p) => (p.contracts.GATEWAY.address = `0x${p.contracts.GATEWAY.address.slice(2).toUpperCase()}`),
    ],
    [
      'contracts[*].runtimeCodeHash',
      (p) =>
        (p.contracts.GATEWAY.runtimeCodeHash = `0x${p.contracts.GATEWAY.runtimeCodeHash
          .slice(2)
          .toUpperCase()}`),
    ],
    [
      'accounts[*]',
      (p) => (p.accounts.QUOTE_SIGNER = `0x${p.accounts.QUOTE_SIGNER.slice(2).toUpperCase()}`),
    ],
  ]) {
    assert.throws(
      () => canonicalizeDeploymentPayload(withUpper(mutate)),
      /is not lowercase/,
      `${label} must be refused, not normalised`,
    );
  }

  // One NIBBLE must move the digest. Without this arm every assertion above
  // would also hold for a canonicaliser that discarded the addresses.
  const nudged = JSON.parse(JSON.stringify(base));
  nudged.contracts.GATEWAY.address = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc';
  assert.notEqual(deploymentManifestHashOf(base), deploymentManifestHashOf(nudged));

  // ...and a runtime code hash edit must move it too.
  const recoded = JSON.parse(JSON.stringify(base));
  recoded.contracts.GATEWAY.runtimeCodeHash =
    '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc';
  assert.notEqual(deploymentManifestHashOf(base), deploymentManifestHashOf(recoded));

  // ...and so must each of the eight account addresses, individually.
  for (const role of Object.keys(base.accounts)) {
    const moved = JSON.parse(JSON.stringify(base));
    moved.accounts[role] = '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeff';
    assert.notEqual(
      deploymentManifestHashOf(base),
      deploymentManifestHashOf(moved),
      `${role} is not bound by the digest`,
    );
  }

  // The same refusals the Rust canonicaliser applies, over the deployment
  // payload shape: a payload one runtime hashes and the other rejects would
  // ship as "parity verified" on whichever side ran.
  assert.throws(() => canonicalizeDeploymentPayload({ chainId: 31337 }), /JSON number at \$\.chainId/);
  assert.throws(
    () => canonicalizeDeploymentPayload({ contracts: { 'bad-role': { address: '0x00' } } }),
    /non-portable object key at \$\.contracts/,
  );
});
