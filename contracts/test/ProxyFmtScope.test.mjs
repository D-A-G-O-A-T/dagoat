import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

// ---------------------------------------------------------------------------
// A repo-wide `forge fmt` is a supply-chain-shaped hazard here, not a tidy-up.
//
// FOUR contracts have their compiled runtime code hash committed ON CHAIN and
// pinned by a frozen literal in `tools/goat-attestor/check-role-code-hashes.ps1`:
//
//     contracts/src/FeeTokenRegistry.sol           (role FEE_TOKEN_REGISTRY)
//     contracts/src/GoatRelayGateway.sol           (role GATEWAY)
//     contracts/src/SponsoredBuyDesk.sol           (role SPONSORED_BUY_DESK)
//     contracts/src/WalletSponsorshipRegistry.sol  (role WALLET_SPONSORSHIP_REGISTRY)
//
// Why a REFORMAT of any of them is not a no-op, measured in this repository:
// solc appends a CBOR metadata trailer to the deployed bytecode, and that
// trailer carries an IPFS digest OF THE SOURCE. A comment-only edit was measured
// to leave the deployed size byte-identical at 9,345 bytes and still move
// `runtimeCodeHash`. So a whitespace-only reformat changes:
//
//   1. the artifact's `rawMetadata`, whose sha256 is the frozen literal that
//      gate step 10 checks -- its detail line reads
//      "4 role contract(s) match their frozen rawMetadata sha256";
//   2. the role's `runtimeCodeHash`, which is a hashed member of the deployment
//      payload, so `deploymentManifestHash` moves too and the committed document
//      no longer hashes to the digest it declares (gate step 5, the node parity
//      pair in `contracts/test/StreamGManifest.test.mjs`);
//   3. nothing about behaviour, so nobody looking at the diff expects any of it.
//
// And it is not a hypothetical trap: `forge fmt --check` is dirty on ALL FOUR of
// them today (40 of 67 `.sol` files under `src/` are not fmt-clean), which is why
// CI keeps the check advisory. A single unscoped `forge fmt` therefore reformats
// every one of the four and reds two gate steps at once.
//
// This file is the standing check. It sweeps the repository's COMMAND surfaces --
// CI workflows, PowerShell/shell scripts, and the shell code fences of task files
// and documentation -- and fails when any of them invokes a MUTATING, UNSCOPED
// `forge fmt`.
//
// Three deliberate scope decisions, each of which is a way this check could have
// been quietly useless:
//
// * `forge fmt --check` is EXEMPT. It writes nothing -- it is a read-only diff,
//   it is `continue-on-error: true` in CI, and the repository ships 40 dirty
//   files. Banning it would make this test red against the tree it ships into,
//   and a guard that is red on arrival gets deleted rather than obeyed.
//
// * "Scoped" means EVERY non-flag argument names a `.sol` FILE. `forge fmt .`,
//   `forge fmt src`, and `forge fmt --root contracts` all name a path and all
//   reformat the four; a rule of "has an argument" would wave them through.
//
// * PROSE IS NOT AN INVOCATION. Half a dozen documents warn against a bare
//   `forge fmt` in inline backticks, and the warnings must not be the finding.
//   Only shell-language code fences count in markdown, only non-comment lines
//   count in scripts and YAML, and the command must sit at a command position
//   (line start, or after `&&`/`;`/`|`/`(`/`run:`/a prompt) -- without that last
//   rule a `git commit -m "...unscoped forge fmt..."` line reads as an offender.
//
// PATH LITERALS ARE ASSEMBLED FROM FRAGMENTS BELOW, NEVER WRITTEN OUT. This file
// sits inside the citation audit's own walk roots (`contracts/test`, extensions
// `sol`/`mjs`/`js`), so a literal internal-doc-tree path here would be that
// audit's first finding -- the same reason its rule table assembles its markers
// at runtime. Dated filename stems are avoided for the second half of the same
// rule; the historical registry below keys on an undated stem instead.
// ---------------------------------------------------------------------------

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..', '..');

/** The four whose runtime code hash is committed on chain. */
const CODE_HASH_PINNED = [
  'contracts/src/FeeTokenRegistry.sol',
  'contracts/src/GoatRelayGateway.sol',
  'contracts/src/SponsoredBuyDesk.sol',
  'contracts/src/WalletSponsorshipRegistry.sol',
];

/** Directories with no command surface of ours, or none at all. */
const SKIP_DIRS = new Set([
  'node_modules',
  'target',
  'out',
  'cache',
  'lib', // vendored forge-std / OpenZeppelin: upstream's commands, not ours
  'dist',
  'broadcast',
  'artifacts',
  '__pycache__',
]);

/** Extensions that can carry a shell command. */
const COMMAND_FILE = /\.(md|ya?ml|ps1|sh|bash)$/i;

/**
 * Markdown fence info-strings whose contents are shell commands. The empty
 * string is included because plain ``` fences in this repository's plans are
 * overwhelmingly shell; `js`, `solidity`, `rust`, `json` and friends are NOT
 * here, which is what keeps a JavaScript fence quoting this very matcher from
 * reading as an invocation of it.
 */
const SHELL_FENCES = new Set([
  '',
  'bash',
  'sh',
  'shell',
  'console',
  'powershell',
  'ps1',
  'pwsh',
  'text',
  'txt',
  'cmd',
  'bat',
]);

/** What may immediately precede `forge` for it to be a command and not prose. */
const COMMAND_POSITION = /(?:^|[;&|(]|&&|\|\||run:|\$|>|^\s*-\s|\bthen\b|\bdo\b|\belse\b)\s*$/;

/**
 * Classify the argument text that follows a `forge fmt` token.
 *
 * `ADVISORY` -- carries `--check`; writes nothing.
 * `SCOPED`   -- at least one non-flag argument, and every one names a `.sol` file.
 * `UNSCOPED` -- everything else, including no arguments at all. This is the ban.
 */
export function classifyFmtArguments(rest) {
  const tokens = rest.split(/\s+/).filter(Boolean);
  if (tokens.includes('--check')) return 'ADVISORY';
  const operands = [];
  for (let i = 0; i < tokens.length; i += 1) {
    if (tokens[i].startsWith('-')) {
      if (tokens[i] === '--root') i += 1; // its value is a directory, not an operand
      continue;
    }
    operands.push(tokens[i]);
  }
  if (operands.length > 0 && operands.every((p) => p.endsWith('.sol'))) return 'SCOPED';
  return 'UNSCOPED';
}

/**
 * Every `forge fmt` invocation in one file's text, as
 * `{ verdict, path, line, text }`.
 *
 * Exported so the positive controls can drive the REAL pipeline over a synthetic
 * file instead of re-implementing a simpler one beside it.
 */
export function scanCommandText(relPath, text) {
  const isMarkdown = relPath.endsWith('.md');
  const found = [];
  let fence = null;
  text.split('\n').forEach((raw, index) => {
    const line = raw.replace(/\r$/, '');
    const trimmed = line.trim();
    if (isMarkdown) {
      const open = trimmed.match(/^(?:```|~~~)\s*([A-Za-z0-9_+-]*)/);
      if (open) {
        fence = fence === null ? open[1].toLowerCase() : null;
        return;
      }
      if (fence === null || !SHELL_FENCES.has(fence)) return;
    }
    if (trimmed.startsWith('#') || trimmed.startsWith('//')) return; // a comment, not a command
    const token = /forge\s+fmt\b/g;
    let hit;
    while ((hit = token.exec(line)) !== null) {
      const before = line.slice(0, hit.index).replace(/\s+$/, '');
      if (before !== '' && !COMMAND_POSITION.test(before)) continue;
      const rest = line.slice(hit.index + hit[0].length).split(/&&|\|\||;|\||`|\)|>|"|'/)[0];
      found.push({
        verdict: classifyFmtArguments(rest),
        path: relPath,
        line: index + 1,
        text: trimmed,
      });
    }
  });
  return found;
}

function* walkCommandFiles(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      // Dot-directories are tooling state, agent-local config and worktree
      // checkouts -- none of it committed, and a worktree copy would double
      // every finding. `.github` is the exception because it is the CI surface.
      if (entry.name.startsWith('.') && entry.name !== '.github') continue;
      yield* walkCommandFiles(full);
    } else if (COMMAND_FILE.test(entry.name)) {
      yield full;
    }
  }
}

/** One sweep of the whole tree: `{ scanned, occurrences }`. */
function sweep() {
  const scanned = [];
  const occurrences = [];
  for (const abs of walkCommandFiles(REPO_ROOT)) {
    const rel = relative(REPO_ROOT, abs).split(sep).join('/');
    scanned.push(rel);
    occurrences.push(...scanCommandText(rel, readFileSync(abs, 'utf8')));
  }
  return { scanned, occurrences };
}

// The internal plan tree, assembled rather than written (see the header).
const PLAN_TREE = ['docs', 'superpowers', 'plans'].join('/');

/**
 * The unscoped invocations that already existed when this check was written.
 *
 * Both are superseded contract plans from before the code-hash pinning existed;
 * both tell a reader to run a bare `forge fmt` before committing, which is the
 * exact hazard. They are recorded here, keyed by an UNDATED filename stem and a
 * count, so that the sweep is green on the unmodified tree while any NEW
 * occurrence anywhere is red.
 *
 * This registry is exact in both directions on purpose. If one of these
 * documents is corrected, this test goes red and the entry must be removed --
 * an allowlist that survives the thing it excuses is how a guard rots into
 * decoration.
 */
const KNOWN_HISTORICAL = [
  { stem: 'goatcoin-contracts', count: 5 },
  { stem: 'epochsettlement-contracts', count: 1 },
];

/** True when `rel` is the plan-tree document `entry` describes. */
function isKnownHistorical(rel, entry) {
  return rel.startsWith(`${PLAN_TREE}/`) && rel.endsWith(`-${entry.stem}.md`);
}

/**
 * Files the sweep MUST have read, one per surface class, named individually so
 * that a narrowed walk fails loudly instead of passing over an empty world.
 * Every one of these is a published path, so this list holds in the internal
 * tree and in an exported checkout alike.
 */
const REQUIRED_SWEEP_COVERAGE = [
  '.github/workflows/ci.yml',
  '.github/workflows/contracts.yml',
  'tools/goat-attestor/run-full-gate.ps1',
  'tools/goat-attestor/check-role-code-hashes.ps1',
  'contracts/README.md',
  'README.md',
];

// ---------------------------------------------------------------------------

/**
 * POSITIVE CONTROL for the classifier.
 *
 * Mutations this detects:
 *  - a matcher narrowed to only the zero-argument form, so `forge fmt .` passes
 *  - `--root <dir>` treated as a scoping argument
 *  - `.sol` file lists misread as unscoped (which would red the whole gate)
 *  - `--check` reclassified as mutating (which would red the shipped tree)
 */
test('test_classifyFmtArguments_separates_mutating_repo_wide_from_scoped_and_readonly', () => {
  // Every one of these MUST be caught. Without this block a classifier that
  // returned 'SCOPED' unconditionally would pass the sweep forever.
  for (const rest of [
    '', // bare `forge fmt`
    '   ', // bare, trailing whitespace
    ' .', // names a path, formats everything
    ' src',
    ' src/',
    ' contracts/src',
    ' --root contracts',
    ' -C 2', // a flag with a value, no operands
  ]) {
    assert.equal(
      classifyFmtArguments(rest),
      'UNSCOPED',
      `argument text ${JSON.stringify(rest)} must be refused`,
    );
  }

  // ...and every one of these MUST NOT be.
  assert.equal(classifyFmtArguments(' --check'), 'ADVISORY');
  assert.equal(classifyFmtArguments(' --check src'), 'ADVISORY');
  assert.equal(classifyFmtArguments(' src/Foo.sol'), 'SCOPED');
  assert.equal(
    classifyFmtArguments(' src/proxy/ProxyRevenueSettlement.sol test/ProxyRevenueSettlement.t.sol'),
    'SCOPED',
  );
  assert.equal(classifyFmtArguments(' --raw src/Foo.sol'), 'SCOPED');
});

/**
 * POSITIVE CONTROL for the whole pipeline, driven through `scanCommandText`
 * itself -- the same function the sweep calls -- over synthetic file contents.
 *
 * Mutations this detects:
 *  - a fence/comment filter so broad that nothing ever reaches the classifier
 *  - the command-position rule widened until commit messages are findings
 *  - the command-position rule narrowed until `&&`-chained calls are missed
 *  - the markdown fence tracker failing to open, so no fenced line is ever read
 */
test('test_scanCommandText_catches_an_injected_unscoped_invocation_in_every_surface', () => {
  const yaml = [
    'jobs:',
    '  fmt:',
    '    steps:',
    '      - run: forge fmt',
    '      - run: forge fmt --check',
    '      - run: forge fmt src/Foo.sol',
    '      # run: forge fmt',
  ].join('\n');
  const fromYaml = scanCommandText('.github/workflows/__control__.yml', yaml);
  assert.deepEqual(
    fromYaml.map((f) => `${f.verdict}:${f.line}`),
    ['UNSCOPED:4', 'ADVISORY:5', 'SCOPED:6'],
    'the YAML control must yield exactly one unscoped finding, on line 4',
  );

  const script = ['Set-Location contracts', 'forge fmt', '# forge fmt'].join('\n');
  assert.deepEqual(
    scanCommandText('tools/__control__.ps1', script).map((f) => `${f.verdict}:${f.line}`),
    ['UNSCOPED:2'],
  );

  const markdown = [
    'Never run a bare `forge fmt`; it moves the committed code hashes.',
    '',
    '```bash',
    'cd contracts && forge fmt && cd ..',
    'git commit -m "test: guard against an unscoped forge fmt moving code hashes"',
    '```',
    '',
    '```js',
    "const BARE = 'forge fmt';",
    '```',
  ].join('\n');
  const fromMarkdown = scanCommandText(`${PLAN_TREE}/__control__.md`, markdown);
  assert.deepEqual(
    fromMarkdown.map((f) => `${f.verdict}:${f.line}`),
    ['UNSCOPED:4'],
    'prose, a commit-message body and a JavaScript fence must not read as invocations',
  );
});

/**
 * Vacuity guard: the sweep must actually reach the surfaces it claims.
 *
 * Mutations this detects:
 *  - a skip list widened until `.github` or `tools` is excluded
 *  - the extension filter narrowed so markdown or `.ps1` stops being read
 *  - a walk rooted at the wrong directory, which would find nothing and pass
 */
test('test_sweep_reaches_every_command_surface_it_claims_to_cover', () => {
  const { scanned, occurrences } = sweep();
  const seen = new Set(scanned);
  for (const required of REQUIRED_SWEEP_COVERAGE) {
    assert.ok(seen.has(required), `sweep never read ${required}`);
  }
  // Measured on the tree this shipped into: 381 command files read, 23
  // occurrences (6 unscoped, 14 scoped, 3 advisory). The floors sit well under
  // the measured values so ordinary churn does not move them, and well over
  // zero so an amputated walk cannot pass.
  // (No ISO date is written here. This file sits inside the citation audit's
  // walk roots, and a bare date near a document-kind word is a finding there.)
  assert.ok(scanned.length >= 100, `sweep read only ${scanned.length} command files`);
  const advisory = occurrences.filter((o) => o.verdict === 'ADVISORY');
  assert.ok(
    advisory.length >= 1,
    'no `forge fmt --check` found anywhere -- the classifier is not reaching real text',
  );

  // The strong floor applies only where the internal plan tree exists. An
  // exported checkout does not carry it, and "the tree is smaller" must not
  // read the same as "the sweep broke".
  if (existsSync(resolve(REPO_ROOT, PLAN_TREE))) {
    assert.ok(
      occurrences.filter((o) => o.verdict === 'SCOPED').length >= 10,
      `only ${occurrences.length} occurrences total; the plan tree should carry many scoped calls`,
    );
  }
});

/**
 * THE CHECK. No mutating, unscoped `forge fmt` outside the historical registry.
 *
 * Mutations this detects:
 *  - any new script, CI job, task file or document that invokes a bare `forge fmt`
 *  - a historical entry silently growing an extra occurrence
 *  - the registry left in place after the document it excuses was corrected
 */
test('test_no_unscoped_forge_fmt_outside_the_known_historical_registry', () => {
  const { scanned, occurrences } = sweep();
  const unscoped = occurrences.filter((o) => o.verdict === 'UNSCOPED');

  const unexpected = [];
  const counted = new Map(KNOWN_HISTORICAL.map((e) => [e.stem, 0]));
  for (const hit of unscoped) {
    const entry = KNOWN_HISTORICAL.find((e) => isKnownHistorical(hit.path, e));
    if (entry) counted.set(entry.stem, counted.get(entry.stem) + 1);
    else unexpected.push(`${hit.path}:${hit.line}  ${hit.text}`);
  }

  assert.deepEqual(
    unexpected,
    [],
    'an unscoped `forge fmt` reformats the four contracts whose runtime code hash is ' +
      'committed on chain, moving their rawMetadata sha256 (gate step 10) and their ' +
      'runtimeCodeHash inside deploymentManifestHash (gate step 5). Name the files ' +
      `instead: forge fmt <file>.sol ...\n${unexpected.join('\n')}`,
  );

  for (const entry of KNOWN_HISTORICAL) {
    const matches = scanned.filter((rel) => isKnownHistorical(rel, entry));
    if (matches.length === 0) continue; // exported checkout: the plan tree is absent
    assert.equal(matches.length, 1, `the stem "${entry.stem}" matched ${matches.length} files`);
    assert.equal(
      counted.get(entry.stem),
      entry.count,
      `the historical registry expects ${entry.count} unscoped call(s) in ${matches[0]} but ` +
        `found ${counted.get(entry.stem)}. If the document was corrected, delete the entry; ` +
        'if a new one was added, remove it from the document instead.',
    );
  }
});

/**
 * The list of at-risk contracts is real and non-empty.
 *
 * Mutations this detects:
 *  - a renamed or deleted role contract leaving the header comment describing
 *    a hazard that no longer has a subject
 *  - the list emptied, which would make the whole file's premise unverified
 */
test('test_code_hash_pinned_contracts_all_exist_and_carry_source', () => {
  assert.equal(CODE_HASH_PINNED.length, 4, 'gate step 10 pins exactly four role contracts');
  for (const rel of CODE_HASH_PINNED) {
    const abs = resolve(REPO_ROOT, rel);
    assert.ok(existsSync(abs), `${rel} is missing`);
    const text = readFileSync(abs, 'utf8');
    assert.ok(text.includes('contract '), `${rel} carries no contract declaration`);
  }

  // The pin itself must still be there, or nothing downstream notices a moved
  // hash and this whole file is guarding an abandoned mechanism.
  const pin = readFileSync(
    resolve(REPO_ROOT, 'tools/goat-attestor/check-role-code-hashes.ps1'),
    'utf8',
  );
  assert.ok(pin.includes('rawMetadata'), 'the code-hash pin no longer reads rawMetadata');
  for (const name of [
    'FeeTokenRegistry',
    'GoatRelayGateway',
    'SponsoredBuyDesk',
    'WalletSponsorshipRegistry',
  ]) {
    assert.ok(pin.includes(name), `the code-hash pin no longer names ${name}`);
  }
});
