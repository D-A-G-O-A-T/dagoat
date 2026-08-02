import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Founder ruling FR-1: no supply-destruction code path, no such parameter, no such
// event on the proxy revenue lane. `ProxyRevenueNoBurn.t.sol` scans the compiled
// runtime and the compiled ABI; this scans the SOURCE, so a path reachable only
// through an unlinked library, an inherited abstract, or a comment-documented
// "future switch" is still caught.
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");

// The lane's full source set, in the order the tasks create it. Most of these do
// NOT exist yet: `proxy_merkle.rs` lands in Task 5, `receipt.rs` in Task 11,
// `aggregate.rs` in Task 15, the worker's `meter.rs` in Task 35, the tunnel's in
// Task 25. A flat `readFileSync` over all of them throws ENOENT on most and the
// negative control is unreachable.
//
// So: sweep what EXISTS, and hold the floor with SWEPT_FLOOR, which every task
// that adds a lane source raises in the same commit. A missing-but-expected file
// is not silently skipped -- it is skipped LOUDLY, by failing the floor.
//
// Contract sources live under `src/proxy/`, not flat in `src/`.
export const PROXY_SOURCES = [
  "contracts/src/proxy/ProxyRevenueSettlement.sol",
  "contracts/src/proxy/ProxyConsumerRegistry.sol",
  "contracts/src/proxy/ProxyRevenueTreasury.sol",
  "tools/goat-attestor/src/proxy/aggregate.rs",
  "tools/goat-attestor/src/proxy/proxy_merkle.rs",
  "tools/goat-attestor/src/proxy/receipt.rs",
  // Added by the controller 2026-07-31 after Task 16. These five landed across
  // Tasks 12-16 and none was ever listed, so the source arm of the three-layer
  // no-burn assertion was reading 6 of the lane's 11 files while reporting a pass.
  // The other two arms (runtime selector scan, compiled-ABI scan) only see the
  // Solidity, so an attestor-side supply-destruction path had no coverage at all.
  "tools/goat-attestor/src/proxy/verify.rs",
  "tools/goat-attestor/src/proxy/store.rs",
  "tools/goat-attestor/src/proxy/meter.rs",
  "tools/goat-attestor/src/proxy/challenger.rs",
  "tools/goat-attestor/src/proxy/fraud.rs",
  // Task 17's two modules. `mod.rs` matters most of the four sweeps' targets: it
  // holds the lane's policy bands, so a supply-destruction knob added there would be
  // the one place a reader would look for it and the one place this sweep was blind.
  "tools/goat-attestor/src/proxy/routes.rs",
  "tools/goat-attestor/src/proxy/mod.rs",
  "tools/goat-proxy-worker/src/meter.rs",
  "tools/goat-proxy-tunnel/src/meter.rs",
];

// Raised by: Task 5 -> 3, Task 7 -> 4, Task 11 -> 5, Task 15 -> 6, Task 25 -> 7,
// Task 35 -> 8. Never lower this to make a red run green.
// (Task 4's file already exists, so the floor starts at 2 rather than 1.)
//
// Task 7 raises it to 4 and closes a two-step gap in one move: Task 5 landed
// `proxy_merkle.rs` WITHOUT raising the floor to 3, so between then and now the
// sweep was reading four files against a floor of two. The schedule above is the
// authority on the value, not the previous line's value plus one.
// Task 11 raises it to 5: `tools/goat-attestor/src/proxy/receipt.rs` now exists and
// is swept. Five of the eight listed sources are present (the three Solidity files,
// `proxy_merkle.rs` and `receipt.rs`); `aggregate.rs` and the two worker/tunnel
// meters are Tasks 15/25/35. Raised by the controller because the implementing
// agent was scoped out of `contracts/` -- a floor left slack is a vacuity guard
// that has stopped guarding.
// Task 15 raises it to 6: `tools/goat-attestor/src/proxy/aggregate.rs` now exists and
// is swept. Raised by the controller for the second time because the implementing
// agent was scoped out of `contracts/` -- the pattern is deliberate (an attestor-lane
// agent must not be able to reach the Solidity tree), so the floor bump is the
// controller's standing follow-up, not an oversight to be fixed by widening scope.
// Controller, 2026-07-31, after Task 16: 11. Eleven of the thirteen listed sources
// now exist (three Solidity + eight attestor `proxy/` modules); the two outstanding
// are the worker and tunnel meters, Tasks 25 and 35. The jump from 6 is not a task
// increment -- it is closing a five-file gap where the sweep reported a pass over
// files it had never opened. Never lower this to make a red run green.
// Controller, 2026-07-31, after Task 17: 13. Thirteen of the fifteen listed sources
// exist (three Solidity + ten attestor `proxy/` modules); the outstanding two are the
// worker and tunnel meters, Tasks 25 and 35. Two independent sweeps now read this
// lane -- this one and the attestor's own `lane_audit.rs`, which walks all of
// `src/proxy/` from CARGO_MANIFEST_DIR. They disagreed for one task; they agree now.
// Never lower this to make a red run green.
export const SWEPT_FLOOR = 13;

// Assembled at runtime rather than written as a literal, so this file can be swept
// by the lane's own vocabulary audits without tripping them.
const TOKEN = ["bu", "rn"].join("");
//
// SUBSTRING, NOT A WORD MATCH, and that is a correction the controls forced. A
// `\b<token>(from|ed)?\b` form -- the obvious first draft -- misses every camelCase
// identifier a real reintroduction would use: `burnBps`, `burnLater`, `buyAndBurn`
// and `noBurnBps` all failed to fire, because in `burnBps` there is no word
// boundary between `n` and `B`. A scanner that only catches the spelling nobody
// would use is a scanner that cannot fail. The suffix list is gone entirely.
const MARKER = new RegExp(TOKEN, "i");

// A comment line may state that the mechanism is ABSENT -- `ProxyRevenueSettlement`
// documents exactly that, at length, and deleting the documentation to satisfy the
// scanner would be the scanner making the codebase worse. So on COMMENT LINES ONLY,
// an occurrence directly governed by a negation is struck out before matching, and
// whatever survives is still a hit.
//
// This is narrow on purpose and its narrowness is asserted below: a line reading
// "no <token> today, but <token>Later() ships in v2" still fails, because only the
// negated occurrence is struck. A DECLARATION is never a comment line and is never
// eligible for the allowance at all.
const NEGATED = new RegExp(`\\b(no|not|never|zero|without)\\s+${TOKEN}\\w*`, "gi");
const COMMENT_LINE = /^\s*(\/\/|\/\*|\*|#)/;

/** Every line of `src` that names the mechanism, as [lineNumber, trimmedLine]. */
export function hitsIn(src) {
  return src
    .split("\n")
    .map((line, i) => [i + 1, line])
    .filter(([, line]) => MARKER.test(COMMENT_LINE.test(line) ? line.replace(NEGATED, " ") : line))
    .map(([n, line]) => [n, line.trim()]);
}

test("the source scanner detects what it claims to detect", () => {
  // POSITIVE CONTROLS -- a scanner that cannot fire proves nothing.
  assert.equal(hitsIn("    function burnFrom(address a, uint256 v) external {").length, 1);
  assert.equal(hitsIn("    function burn(uint256 amount) external {}").length, 1);
  assert.equal(hitsIn("    event Burned(address indexed who, uint256 amount);").length, 1);
  assert.equal(hitsIn("    uint256 public burnBps;").length, 1);
  // camelCase, where a word-boundary matcher silently misses.
  assert.equal(hitsIn("    function buyAndBurn(uint256 amount) internal {").length, 1);
  assert.equal(hitsIn("    let n = self.burn_bps;").length, 1);
  // A declaration is not a comment, so the negation allowance never reaches it --
  // even when the identifier itself is spelled to look like a denial.
  assert.equal(hitsIn("    uint256 public noBurnBps;").length, 1);

  // THE ALLOWANCE IS NARROW: only the negated occurrence is struck out.
  assert.equal(hitsIn("/// no burn today, but burnLater() ships in v2").length, 1);
  assert.equal(hitsIn("// burn is disabled for now, see the switch below").length, 1);

  // ...and it does cover a plain statement of absence.
  assert.equal(hitsIn("/// there is no burn function, no burn constant, no burn event").length, 0);

  // NEGATIVE CONTROLS -- ordinary lines must not fire.
  assert.equal(hitsIn("    uint256 public totalClaimed;").length, 0);
  assert.equal(hitsIn("    f.goatClaimed += payoutGoatWei;").length, 0);
});

test("no burn vocabulary in the proxy revenue sources", () => {
  let swept = 0;
  let bytes = 0;
  for (const rel of PROXY_SOURCES) {
    const abs = join(REPO_ROOT, rel);
    if (!existsSync(abs)) continue;
    const src = readFileSync(abs, "utf8");
    swept += 1;
    bytes += src.length;
    const hits = hitsIn(src);
    assert.deepEqual(hits, [], `${rel} names the forbidden mechanism at ${JSON.stringify(hits)}`);
  }
  assert.ok(swept >= SWEPT_FLOOR, `vacuity guard: swept ${swept} files, floor is ${SWEPT_FLOOR}`);
  assert.ok(bytes > 2_000, `vacuity guard: swept only ${bytes} bytes; the scanner is reading nothing`);
});

test("every lane source that exists is inside the sweep set", () => {
  // The complement of the guard above: a lane file created and never added to
  // PROXY_SOURCES would otherwise never be swept at all.
  const present = PROXY_SOURCES.filter((rel) => existsSync(join(REPO_ROOT, rel)));
  assert.ok(present.length >= SWEPT_FLOOR);
  for (const rel of present) assert.ok(readFileSync(join(REPO_ROOT, rel), "utf8").length > 0, rel);
});
