#Requires -Version 5.1
<#
.SYNOPSIS
    The full local gate for goat-attestor + contracts. THIS IS THE GATE THAT
    ACTUALLY RUNS TODAY.

.DESCRIPTION
    Runs, in order, stopping at the first failure:

      1. cargo test --lib                      (unit suite)
      2. cargo clippy --all-targets -D warnings
      3. the #[ignore]d live-Anvil hazard suite, against a node this script
         starts and reaps
      4. forge test                            (contracts/)
      5. node --test on the contracts/ parity fixtures -- the JavaScript half
         of the cross-language feeScheduleHash pair the spec makes a
         PRECONDITION of Policy Safe approval
      6. EIP-170 size assertion on GoatRelayGateway, computed from the build
         artifact rather than trusted to `forge build --sizes`' exit status
      7. sha256 freeze check on EVERY file in migrations/
      8. auxiliary script integrity -- every .ps1 in the tree PARSES, and means
         the same thing under the encoding the host actually reads
      9. script call-site ABI consistency -- every `cast send`/`cast call`
         signature in those scripts still names a function the compiled
         contracts have, and no `forge script` invocation of an overloaded
         entry point is missing its --sig or names an entry point the target
         does not declare. Both checks are pinned PER FILE as well as
         tree-wide, because both defects that motivated this step were
         per-file.

    A final PASS/FAIL table is printed and the exit code is 0 only if every
    step passed.

    Every step's stdout is also written to `gate-logs\<timestamp>\NN-<step>.log`
    (UTF-8, no BOM, last 20 runs kept), and a FAIL prints the failing step's log
    path plus an excerpt naming the tests that went red. Use those files rather
    than re-running with a redirection: the table alone never named a test, and
    two intermittent failures were lost that way.

.NOTES
    WHY THIS FILE EXISTS AND NOT CI
    -------------------------------
    `.github/workflows/ci.yml` has NEVER RUN, and cannot run as things stand:
      * in the development tree the git toplevel sits well above this project,
        so the workflow files land several levels below the repository root
        where GitHub Actions cannot discover them;
      * `ci.yml` is untracked, as is the crate's own source, so a runner would
        check out a tree with no `stream_g` module at all;
      * `git remote -v` is empty -- there is nowhere to push to.
    Do NOT describe the ignored tests as "covered by CI". They are
    covered by THIS SCRIPT, run by a human, and by nothing else.

    Step 3 is the reason this file is a priority: the hazard tests are
    invisible to `cargo test --lib`, so a change that breaks them ships green.
    Their exact count is pinned by `$ExpectedLibIgnored`/`$ExpectedIgnoredPassed`
    below (17 as of Task 11 Wave D2, which added the reconciliation lifecycle
    proof).

    Step 5 exists for the same reason in a different language.
    `contracts/test/StreamGManifest.test.mjs` is the ONLY artifact that ties the
    fee-schedule digest to `contracts/deployments/31337.stream-g.json` in one
    place, and until it was wired here NOTHING ran it: this script's steps were
    all cargo/clippy/anvil/forge, and `.github/workflows/ci.yml` runs node only
    in the `desktop` job. The failure that permitted: someone edits the shipped
    payload and regenerates the Rust constants, the JS canonicaliser or its
    pinned bytes drift, every gate stays green, and the cross-language parity
    that the "Stream G -- USDT Gas Abstraction and Multi-Wallet Sponsoring"
    spec, section 8.1, makes a
    precondition of Policy Safe approval is silently unverified at the moment of
    approval.

.EXAMPLE
    pwsh -File .\run-full-gate.ps1
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # native exit codes are checked by hand

# ---------------------------------------------------------------------------
# TOOLCHAIN BOOTSTRAP
#
# This is load-bearing, not convenience. Under a POSIX shell on this platform
# MSYS ships its own `link.exe` (coreutils) which SHADOWS the MSVC linker on
# PATH, and `cargo` then fails to link with a `missing operand` error that
# looks nothing like a linker-selection problem. Prepending the MSVC toolchain
# directory puts the real linker first.
#
# Everything here is DISCOVERED, never hardcoded: this file is committed and is
# destined for a public repository, so it must not name a user account, a
# machine layout, or a specific toolchain version. Discovery scans the fixed
# drives for the standard install roots and takes the highest version found.
# ---------------------------------------------------------------------------

function Get-FixedDriveRoots {
    Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
        Where-Object { $_.Root -match '^[A-Za-z]:\\$' } |
        ForEach-Object { $_.Root.TrimEnd('\') }
}

function Get-HighestChild {
    param([string[]]$Globs)
    $hits = @()
    foreach ($g in $Globs) {
        $hits += Get-ChildItem -Path $g -Directory -ErrorAction SilentlyContinue
    }
    if ($hits.Count -eq 0) { return $null }
    ($hits | Sort-Object Name -Descending | Select-Object -First 1).FullName
}

$drives = Get-FixedDriveRoots

# MSVC build tools -- bin (linker), lib, include.
$msvcGlobs = $drives | ForEach-Object {
    "$_\Program Files (x86)\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*"
    "$_\Program Files\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*"
}
$msvcRoot = Get-HighestChild -Globs $msvcGlobs

# Windows SDK -- ucrt/um headers and libraries.
$sdkGlobs = $drives | ForEach-Object {
    "$_\Program Files (x86)\Windows Kits\10\Lib\*"
    "$_\Program Files\Windows Kits\10\Lib\*"
}
$sdkLibRoot = Get-HighestChild -Globs $sdkGlobs
if ($sdkLibRoot) { $sdkIncRoot = $sdkLibRoot -replace '\\Lib\\', '\Include\' }

$pathAdds = @()
if ($msvcRoot) { $pathAdds += (Join-Path $msvcRoot 'bin\Hostx64\x64') }
# Per-user toolchains, via the environment rather than a literal account name.
foreach ($toolHome in @($env:CARGO_HOME, $env:FOUNDRY_HOME)) {
    if ($toolHome) { $pathAdds += (Join-Path $toolHome 'bin') }
}
if ($env:USERPROFILE) {
    $pathAdds += (Join-Path $env:USERPROFILE '.cargo\bin')
    $pathAdds += (Join-Path $env:USERPROFILE '.foundry\bin')
}
foreach ($p in $pathAdds) {
    if ((Test-Path $p) -and (($env:PATH -split ';') -notcontains $p)) {
        $env:PATH = "$p;$env:PATH"
    }
}

$libAdds = @()
$incAdds = @()
if ($msvcRoot) {
    $libAdds += (Join-Path $msvcRoot 'lib\x64')
    $incAdds += (Join-Path $msvcRoot 'include')
}
if ($sdkLibRoot) {
    $libAdds += (Join-Path $sdkLibRoot 'um\x64'), (Join-Path $sdkLibRoot 'ucrt\x64')
    $incAdds += (Join-Path $sdkIncRoot 'ucrt'), (Join-Path $sdkIncRoot 'um'), (Join-Path $sdkIncRoot 'shared')
}
$libAdds = @($libAdds | Where-Object { Test-Path $_ })
$incAdds = @($incAdds | Where-Object { Test-Path $_ })
if ($libAdds.Count -gt 0) { $env:LIB     = ($libAdds -join ';') + ';' + $env:LIB }
if ($incAdds.Count -gt 0) { $env:INCLUDE = ($incAdds -join ';') + ';' + $env:INCLUDE }

# Fail early and legibly rather than mid-gate with a confusing native error.
$missing = @()
# `node` is in this list on purpose. Step 5 runs the JavaScript half of the
# cross-language feeScheduleHash fixture, and a step that SKIPS when its runtime
# is absent is exactly the zero-enforcement-signal problem step 5 was added to
# remove: the summary would print PASS-by-omission for a check that never ran.
# A missing node is a broken machine, reported here as loudly as a missing forge.
foreach ($tool in @('cargo', 'forge', 'cast', 'anvil', 'node')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { $missing += $tool }
}
if ($missing.Count -gt 0) {
    Write-Host "FATAL: required tool(s) not on PATH: $($missing -join ', ')" -ForegroundColor Red
    exit 1
}


# ---------------------------------------------------------------------------
# PINNED EXPECTATIONS
#
# These are asserted exactly (or as a floor, where noted). When a wave ADDS
# tests, BUMP THE NUMBER DELIBERATELY in the same commit that adds them, and
# say so in the commit message. NEVER delete an assertion, and never loosen one
# to `-ge` that is written `-eq`, to make a red gate go green: a count that can
# only ever drift upward stops detecting a suite that has silently shrunk (a
# deleted test, an `#[ignore]` added, a `--skip` that grew a typo).
#
# Provenance of the current values: architect's verified baseline at HEAD
# e0b0e65, re-confirmed by Task 10 Wave 1 after the rpc_chain_anvil_smoke repair
# and the removal of --disable-code-size-limit from the harness, then re-pinned
# after the 5-Critical remediation:
#   cargo --lib  573 -> 574  (+1: the Critical-5 post-send nonce test)
#   forge test   242 -> 246  (+3 Critical 4 EpochSettlement resolver tests,
#                             +1 Critical 3b snapshot subject-binding test)
# Re-pinned again after Task 11 Wave A, measured by the architect personally
# and corroborated by the wave's independent verifier:
#   cargo --lib  574 -> 601  (+27: SecretHex + state/config plumbing + the
#                             fee-schedule governance-tag binding (Wave 0),
#                             and the error envelope, extractor-rejection
#                             mapping, CORS preflight, body limit and Stream G
#                             rate limiter (Wave 1))
#   forge test   246 -> 247  (+1: the HoldbackEscrow co-claimant lockout test
#                             added with the per-(epoch,worker) jobId fix for
#                             consultant Critical Concern 3)
# The forge number is EXACT on purpose. `fail_on_revert = true` (foundry.toml)
# means a handler revert now FAILS the suite instead of being discarded, so this
# pin is the thing that notices if someone turns that back off and the count
# quietly changes.
#
# `$ExpectedNodeParityTests` is new with step 5, measured on this machine
# (node v24.18.0): 5 tests in contracts/test/StreamGManifest.test.mjs plus 2 in
# contracts/test/keccak256.test.mjs. It is EXACT for the same reason as the
# forge pin. Measured, not assumed, on 2026-07-26: `node --test` on a path that
# does not exist DOES exit 1 ("Could not find ..."), so a typo in the file list
# below is caught by the exit code alone; what it does NOT catch is a fixture
# that still exists with a test DELETED out of it, which reports "pass 6 fail 0"
# and exits 0. That is the case this pin detects.
#
# Re-pinned 2026-07-28 by the deploymentManifestHash content binding
# (`deploymentManifestHash` was `keccak256("stream-g-manifest-g1")`, a tag that
# hashed nothing; it is now `keccak256(UTF8(RFC8785(payload)))` over the new
# deployment-payload document):
#   forge test   247 -> 248  (+1: DeployStreamG.t.sol's
#                             `test_writes_deployment_payload_document`, which
#                             pins the four committed roles' addresses AND
#                             their live EXTCODEHASH values -- the inputs the
#                             Rust and JavaScript legs hash)
#   node --test  7 -> 9      (5 + 2 became 6 + 2 + 1: the legacy
#                             "Stream G manifest JCS is stable" test was
#                             RETIRED -- it canonicalised a manifest INCLUDING
#                             its own deploymentManifestHash and hashed it with
#                             SHA-256, so it could never be a content binding --
#                             and three deploymentManifestHash tests were added
#                             in its place)
#
# Re-pinned again 2026-07-28 by the deploymentManifestHash repair wave:
#   node --test  9 -> 10     (+1: "forge test left the committed payload
#                             self-consistent". Step 1 owns the byte-identity
#                             guards and runs BEFORE step 4, so the gate used to
#                             check the artifacts the PREVIOUS run left behind,
#                             pass, and then leave the tree red -- the committed
#                             payload declaring a digest its own content no
#                             longer produces, which goat-attestor refuses to
#                             start against. This is the check on the far side
#                             of step 4.)
# The forge count is UNCHANGED at 248: the deployments-directory override is
# deliberately NOT tested from `forge test` -- see the note at the bottom of
# contracts/test/DeployStreamG.t.sol. It is proved by the 17 deploying tests of
# step 3, every one of which goes through it. (Step 3 runs 19 as of the
# 2026-07-28 node-forensics re-pin below; the 18th spawns a child on purpose and
# the 19th fails a node on purpose -- neither deploys.)
# ---------------------------------------------------------------------------
# Re-pinned 2026-07-28 by the RPC-read-deadline fix (see STEP 3's hang note):
#   cargo --lib  776 -> 778  (+2, both non-ignored and node-free:
#                             rpc_chain's `a_node_that_accepts_and_never_answers_
#                             fails_with_a_named_deadline_not_a_hang` and its
#                             refused-port control arm)
#   ignored      17  -> 18   (+1: anvil_harness's
#                             `output_within_kills_a_child_that_never_finishes_
#                             and_names_the_budget`, which spawns a real anvil as
#                             a deliberately never-exiting child and so belongs in
#                             the step that already requires Foundry)
# ---------------------------------------------------------------------------
# Re-pinned 2026-07-28 (later, same day) by the NODE-FORENSICS instrumentation.
# That round did NOT fix the stall and does not claim to -- see STEP 3's note.
# It makes the next occurrence record what nobody has yet recorded: whether the
# node still answered a brand-new socket at the moment the harness gave up.
#   cargo --lib  778 -> 782  (+4, all non-ignored and node-free, in
#                             anvil_harness: a serving endpoint reads ANSWERED
#                             and carries both environmental counts; a socket
#                             that ACCEPTS AND NEVER REPLIES reads NO ANSWER
#                             (the wedged-node shape); a closed port reads NO
#                             ANSWER on the refusal, not on the budget; and the
#                             report is emitted on an unwinding drop but NOT on
#                             an ordinary one)
#   ignored      18  -> 19   (+1: `forensics_from_a_panicking_harness_scope_
#                             find_the_live_node_still_answering` -- the
#                             calibration arm. It needs a real anvil because it
#                             is the only thing that proves the probe runs
#                             BEFORE the harness reaps its own node; with
#                             `_forensics` moved below `_node` in AnvilHarness
#                             the verdict flips to NO ANSWER and this is the
#                             only test that notices.)
$ExpectedLibTestsMin     = 601      # floor: `cargo test --lib` passed count
$ExpectedLibIgnored      = 19       # exact: #[ignore]d tests skipped by --lib
$ExpectedIgnoredPassed   = 19       # exact: the live-Anvil hazard suite
$ExpectedForgeTests      = 248      # exact: `forge test` passed count
$ExpectedNodeParityTests = 10       # exact: node --test passed count (step 5)
$Eip170Limit             = 24576    # bytes; EIP-170 deployed-code cap
# STEPS 8 AND 9 HAVE NO PINS HERE, ON PURPOSE. Every floor and every required-set
# literal those two checks use lives in the param() block of
# tools\goat-attestor\check-aux-scripts.ps1 -- the ONE implementation of both
# checks, and the file GitHub Actions calls as well. A pin left in this gate would
# be a pin CI does not honour: the same two-implementations defect that already
# cost this repository a migration-freeze table in two places plus a test
# asserting the two agree. Read that file for each number's provenance and the
# measurement behind it.

# Step 7's freeze table: EVERY migration, not just 0001. An applied migration is
# frozen because a database that already recorded `schema_migrations.version = N`
# will never re-run N -- so an edit to 000N gives two deployments the same
# recorded schema version and different schemas. That hazard applies to 0002 and
# 0003 exactly as it applies to 0001.
#
# This is an ORDERED, EXPLICIT list, and step 7 also asserts that the migrations/
# directory contains nothing outside it. A glob-and-hash would let a new
# migration file arrive unfrozen, which is the state the freeze exists to
# prevent. Adding a migration means adding its row here, in the same commit.
$MigrationFreeze = [ordered]@{
    '0001_stream_g.sql'            = 'b4cc6a3dd60de02bf75d57f1528d13cf61b489f182b4b8dab788f8d82edf607b'
    '0002_stream_g_outbox.sql'     = 'd4f3ef94cb3c60f8972717c73cfa24aabea18fcffe6c2f87947083c9797a2bac'
    '0003_stream_g_scan_cursor.sql' = 'c9797c54380685434fe649bf083552ae49a9ff17dc6a51169f64b8420cc4668e'
}

# STEP 10 HAS NO PINS HERE EITHER, for the same reason steps 8 and 9 do not. The
# freeze table of four SHA-256(rawMetadata) values, the role->artifact map, the
# payload path, all five vacuity guards and the whole argument for each of them
# now live in the param() block and header of
# tools\goat-attestor\check-role-code-hashes.ps1 -- the ONE implementation, and
# the file GitHub Actions calls as well. Extracted 2026-07-29, third after checks
# 8 and 9; before that this step was gate-enforced and not CI-enforced, and the
# reason recorded was a design decision rather than effort.
#
# Read that file for what the canary protects, why it pins the compiler's
# rawMetadata rather than keccak(deployedBytecode) (immutables are substituted at
# construction and the gateway artifact is unlinked -- both measured), and why it
# is the SECOND line of defence: a source edit reds STEP 5 first, and what step
# 10 catches is the FIX for that.

# Anvil the harness's documented behaviour was verified against. Advisory: the
# gate warns on a mismatch, it does not fail, because the pinned version is a
# statement about what was tested, not a hard requirement.
$ExpectedAnvilVersion    = '1.7.1'

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
$AttestorDir  = $PSScriptRoot
$ContractsDir = (Resolve-Path (Join-Path $PSScriptRoot '..\..\contracts')).Path
$MigrationDir = Join-Path $AttestorDir 'migrations'
$GatewayJson  = Join-Path $ContractsDir 'out\GoatRelayGateway.sol\GoatRelayGateway.json'

# STEPS 8 AND 9's SUBJECT AND IMPLEMENTATION. The tree they sweep, and the ONE
# file that implements both checks -- also called by GitHub Actions, so neither
# the logic nor its pins may be duplicated here.
$RepoRoot       = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$AuxCheckScript = Join-Path $AttestorDir 'check-aux-scripts.ps1'

# STEP 10's IMPLEMENTATION, extracted 2026-07-29 for the same reason and called
# the same way. It carries its own freeze table and its own vacuity guards;
# nothing about it is restated here.
$RoleCheckScript = Join-Path $AttestorDir 'check-role-code-hashes.ps1'

# WHICH POWERSHELL RUNS THAT CHILD, discovered rather than hardcoded to
# powershell.exe. Step 8 part (b) asks whether a file means the same thing "as
# the host reads it", and the host is whichever PowerShell is running THIS script.
# Launching the child under a different one would answer that question about a
# host nobody here uses -- and under a UTF-8-default host the comparison cannot
# fail at all, which is a vacuous green. So the child runs under this process's
# own executable.
$PsHostExe = $null
try { $PsHostExe = [string](Get-Process -Id $PID).Path } catch { $PsHostExe = $null }
if ((-not $PsHostExe) -or (-not (Test-Path -LiteralPath $PsHostExe))) {
    foreach ($psCand in @((Join-Path $PSHOME 'pwsh.exe'), (Join-Path $PSHOME 'powershell.exe'))) {
        if (Test-Path -LiteralPath $psCand) { $PsHostExe = $psCand; break }
    }
}
if ((-not $PsHostExe) -or (-not (Test-Path -LiteralPath $PsHostExe))) {
    Write-Host 'FATAL: could not locate this host PowerShell executable; steps 8 and 9 cannot be launched' -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# PER-STEP LOGS -- the thing that makes a red gate DIAGNOSABLE
#
# This exists because a failing gate used to name no test. `Invoke-Tool` ended
# in `| Out-Host`, and `Out-Host` writes straight to the host: unlike
# `Write-Host` (which since PowerShell 5.0 goes through the Information stream,
# stream 6) it is NOT intercepted by `.\run-full-gate.ps1 *> log.txt`. The
# observed consequence, twice, on consecutive runs: a 46 KB redirected log whose
# entire failure content was
#   `cargo test --lib   FAIL   cargo exited 101 (773 passed, 1 failed)`
# -- the verdict table (Write-Host, captured) with none of the tool output
# (Out-Host, dropped). The failing test could not be named, so the flake could
# not be fixed, only re-observed.
#
# Two independent repairs, because the capture path must not be the single
# point of failure again:
#   1. every tool's stdout is written to its own file under gate-logs/<run>/,
#      UTF-8 with no BOM. Not `Out-File`/`Set-Content`: under Windows
#      PowerShell those emit UTF-16 or a BOM depending on the verb, and `grep`
#      finds NOTHING in a UTF-16 file -- which reads as "no failures" and is
#      how a red run gets reported as green.
#   2. `Out-Host` is replaced by `Write-Host`, so a `*>` redirection now
#      captures the live output too.
#
# Runs are kept in timestamped directories (the last $GateLogKeep) rather than
# overwritten, because the failures worth chasing are the intermittent ones and
# the previous run is exactly the evidence you want when this one goes red.
# ---------------------------------------------------------------------------
$GateLogRoot = Join-Path $AttestorDir 'gate-logs'
$GateLogDir  = Join-Path $GateLogRoot (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
$GateLogKeep = 20
[void](New-Item -ItemType Directory -Force -Path $GateLogDir)
$script:LogSeq = 0

# Prune old run directories, oldest first, keeping the most recent $GateLogKeep
# INCLUDING the one just created.
$oldRuns = @(Get-ChildItem -LiteralPath $GateLogRoot -Directory -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending | Select-Object -Skip $GateLogKeep)
foreach ($old in $oldRuns) {
    Remove-Item -LiteralPath $old.FullName -Recurse -Force -ErrorAction SilentlyContinue
}

function Write-Utf8NoBom {
    param([string]$Path, [string]$Text)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

# Step 5's fixtures, listed EXPLICITLY rather than as a directory or a glob.
#
# Two reasons, one measured and one structural. Measured (node v24.18.0 on this
# machine): `node --test test/` fails outright with
# `Error: Cannot find module ...\contracts\test` -- node 24 treats a positional
# argument as a file to run, not a directory to walk. Structural: a glob would
# make the pinned count above drift silently every time someone adds an
# unrelated .mjs, which is precisely the drift the pin exists to catch.
#
# keccak256.test.mjs is in the list, not just the manifest fixture. It pins
# ./keccak256.mjs against published Keccak vectors and against the SHA3-256
# domain byte; StreamGManifest.test.mjs's whole parity claim is computed with
# that implementation, so a broken keccak256.mjs would make the parity fixture
# agree with Rust about the BYTES and disagree about the HASH -- or worse, be
# wrong on both sides in the same way.
#
# Paths are relative because node is run with $ContractsDir as its working
# directory: StreamGManifest.test.mjs resolves `deployments/31337.stream-g.json`
# from cwd (its own comment says so), so running it from anywhere else would
# quietly skip the artifact half of the check via its `existsSync` guard.
$NodeParityTests = @(
    'test/StreamGManifest.test.mjs',
    'test/keccak256.test.mjs'
)

# ---------------------------------------------------------------------------
# Plumbing
# ---------------------------------------------------------------------------
$script:Steps      = New-Object System.Collections.ArrayList
$script:Failure    = $null
$script:FailedStep = $null
$script:LastTool   = $null

function Write-Banner {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Add-StepResult {
    param([string]$Name, [string]$Status, [string]$Detail)
    [void]$script:Steps.Add([pscustomobject]@{
        Step   = $Name
        Status = $Status
        Detail = $Detail
    })
}

function Fail-Step {
    param([string]$Name, [string]$Reason)
    Add-StepResult -Name $Name -Status 'FAIL' -Detail $Reason
    $script:Failure = "$Name : $Reason"
    $script:FailedStep = $Name
    throw $script:Failure
}

# The lines a human actually needs out of a failed tool run, pulled from the
# captured stdout and re-emitted at the bottom of the gate.
#
# A verdict line ("1 failed") tells you the gate is red; it does not tell you
# WHICH test, and a reader who has to go looking usually does not. Both harnesses
# print the name in a recognisable place -- cargo lists it under `failures:` and
# repeats the panic above it, forge prefixes it with `[FAIL` -- so the excerpt is
# matched on those rather than on a fixed tail, which would just show a summary
# block that is already in the table.
function Get-FailureExcerpt {
    param([string]$Text, [int]$Max = 60)
    if ([string]::IsNullOrEmpty($Text)) { return @() }
    $hits = @()
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*\[FAIL' -or
            $line -match '^\s*failures:' -or
            $line -match '^\s{4}\S+::\S+' -or
            $line -match "^\s*---- .* stdout ----" -or
            $line -match '^\s*(thread .* panicked|assertion .* failed|Error:|error(\[E\d+\])?:)') {
            $hits += $line
        }
    }
    if ($hits.Count -gt $Max) { $hits = $hits[0..($Max - 1)] + "  ... excerpt truncated at $Max lines; the full log is above" }
    return $hits
}

# The ONE thing this gate reads out of check-aux-scripts.ps1's stdout: the
# human-readable detail string for a step's SUMMARY row, so that extracting steps
# 8 and 9 did not cost the table the counts it used to print.
#
# THE EXIT CODE REMAINS THE VERDICT. This reader is cosmetic. A renamed or lost
# marker line yields $null, the step still fails on a non-zero exit, and a zero
# exit with no PASS line is failed EXPLICITLY at the call site rather than
# reported green -- so the one thing a broken parse cannot do is manufacture a
# pass.
function Get-AuxCheckDetail {
    param([string]$Text, [string]$Check)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $m = [regex]::Match(
        $Text,
        ('(?m)^GATE-DETAIL\s+{0}\s+(?<status>\S+)\s+(?<detail>.*)$' -f [regex]::Escape($Check)))
    if (-not $m.Success) { return $null }
    return [pscustomobject]@{
        Status = $m.Groups['status'].Value
        Detail = $m.Groups['detail'].Value.Trim()
    }
}

# Exit 1 and exit 2 are DIFFERENT REPORTS, and this is where they are kept
# different. A child that could not run has produced no verdict over the surface;
# calling that "findings" would be a claim the child never made, and calling it a
# pass is the failure the whole exit contract exists to prevent.
function Get-AuxCheckFailReason {
    # $ScriptName is a parameter rather than the literal it used to be, because
    # THREE checks are now children (8, 9 and 10) and a message naming the wrong
    # file sends a reader to the wrong place to triage. Defaulted, so the two
    # original call sites read exactly as before.
    param([int]$ExitCode, $Detail, [string]$LogPath, [string]$ScriptName = 'check-aux-scripts.ps1')
    $what = 'reported findings'
    if ($ExitCode -eq 2) {
        $what = 'COULD NOT RUN -- that is neither a finding nor a pass; a prerequisite is missing'
    }
    $tail = ''
    if ($null -ne $Detail) { $tail = ' -- ' + $Detail.Detail }
    return ("${ScriptName} exited ${ExitCode}; the check ${what}${tail}. Every finding is " +
            "quoted in the excerpt below and in full in $LogPath")
}

# Runs a native tool in $WorkDir, echoes its stdout, and returns both the text
# and the real exit code.
#
# Two deliberate choices, both learned the hard way:
#
#  * NOT `Start-Process -NoNewWindow -Wait -RedirectStandardOutput ...`. That
#    form HANGS FOREVER when this script is launched from a host with no
#    console attached (a background/detached shell, a CI-style runner): the
#    child never starts and -Wait never returns. Observed on this machine.
#  * NOT `& tool 2>&1`. In Windows PowerShell 5.1 that wraps every stderr line
#    in a NativeCommandError ErrorRecord and sets `$?` to $false even when the
#    tool exited 0. Here stderr is left alone: it flows straight to the console
#    (so compiler diagnostics stay visible) and every assertion below keys off
#    stdout, which is where both `cargo test`'s `test result:` line and
#    `forge test`'s summary line are written.
#  * NOT `| Out-Host`, which is what this function used to end with. `Out-Host`
#    writes directly to the host and is therefore invisible to
#    `.\run-full-gate.ps1 *> log.txt`; a redirected FAIL log contained the
#    verdict table and none of the tool output, so the failing test could not be
#    named. `Write-Host` goes through the Information stream, which `*>` does
#    capture. See the PER-STEP LOGS block above; every run is also written to
#    disk regardless of how the caller redirects.
# ---------------------------------------------------------------------------
# PER-STEP DEADLINE -- what turns a HANG into a named red
#
# Measured, 2026-07-28: during one gate run `forge script
# script/DeployStreamG.s.sol --broadcast` (spawned by the step-3 hazard suite)
# finished its simulation and then sat. Twenty seconds of sampling showed 0.172s
# of CPU across 86 threads -- 0.86%, i.e. wedged, not working. The harness anvil
# it was talking to answered `eth_blockNumber` normally the whole time.
#
# `Invoke-Tool` had no deadline of any kind, so the gate waited. It would have
# waited forever: no PASS, no FAIL, no verdict table, no exit code. That is
# strictly WORSE than a red gate -- a red gate names a test, and this names
# nothing and never returns -- and it happened in the one script that is this
# repository's only enforcement. The run only ended because a human found the
# pid and killed it 15 minutes in.
#
# Why a JOB and not `Start-Process -Wait` or a .NET timer:
#
#  * The pipeline form `& $Exe @ToolArgs | ...` is kept EXACTLY as it was.
#    Every note in `Invoke-Tool` below was learned the hard way and none of it
#    is worth re-learning to gain a timeout; the watchdog is bolted alongside,
#    not through, that pipeline.
#  * A `System.Timers.Timer` callback cannot run script safely while the main
#    thread is blocked inside a native pipeline. A background JOB is a separate
#    process and cannot be starved by the very hang it exists to break.
#
# Two safety rules on WHAT it may kill, because this machine also runs a
# long-lived relayer that must survive:
#
#  1. Only processes DESCENDED from this script's own pid. The relayer was not
#     started by the gate, so it is not in the tree.
#  2. Only processes CREATED AFTER the step started. Windows recycles pids, and
#     without this an unlucky recycle could point the parent chain at something
#     that predates the run. A process older than the step cannot be its child.
#
# The watchdog writes its verdict flag BEFORE it kills anything, so the reason
# survives even though killing the child is what unblocks the pipeline.
#
# WHERE THE FLAGS LIVE, and why not next to the per-step logs: OUTSIDE THE
# REPOSITORY. The obvious home is `gate-logs/<run>/`, and that was the first
# implementation. It was wrong. `gate-logs/` sits under `tools/`, which is an
# allowlisted export tree, and `*.log` is deny-globbed there but a dotfile is
# not -- so within three gate runs the public-export curator was reporting five
# `.cargo-test-lib.done` / `.timeout` files as paths "permitted by the allowlist
# but NOT in the baseline", i.e. this script's own IPC scratch had become
# candidate export material (the review bucket went 4 -> 10). Ephemeral
# coordination files do not belong inside the surface another tool audits.
# Nothing is lost: the timeout's reason is copied into the step log header and
# into the Fail-Step message before the flag is deleted.
# ---------------------------------------------------------------------------

# Per-run scratch for the watchdog flags, under the OS temp dir, removed at the
# end of the run. A fresh GUID per run, so two concurrent gates cannot read each
# other's flags -- which would make one report the other's timeout.
$GateFlagDir = Join-Path ([System.IO.Path]::GetTempPath()) ('goat-gate-flags-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Force -Path $GateFlagDir)

# Default ceiling for one step, and the per-step overrides. These are ceilings
# on a BUG, not expected durations: warm, the whole gate finishes in about 40
# seconds and its longest step (the live-anvil hazard suite) in about 27. The
# numbers are large enough that a cold `cargo` rebuild of the whole dependency
# graph cannot trip them, and small enough that a wedged child is reported the
# same day.
$DefaultStepTimeoutSec = 1800
$StepTimeoutSec = @{
    'cargo-test-lib'     = 2400   # can include a full cold build
    'cargo-clippy'       = 2400   # ditto, and clippy is slower than check
    'anvil-version'      = 60     # prints a version string; anything else is wrong
    'anvil-hazard-suite' = 1200   # WHERE THE OBSERVED HANG WAS. ~27s warm.
                                  # NOT fixed -- bounded and instrumented. Read
                                  # STEP 3's header (through "ROUND 3") before
                                  # spending a minute on a recurrence. The
                                  # harness now records whether the node was
                                  # still answering; read
                                  # gate-logs\node-forensics.log, NOT this step
                                  # log -- only the failure arm reaches the step
                                  # log, and the arm that fires on a passing
                                  # stall does not. ROUND 3 says which is which.
    'forge-test'         = 1200
    'node-parity'        = 300
    'forge-build-sizes'  = 900
    'aux-script-integrity'   = 300   # a tree walk plus 14 parses; ~1s warm
    'script-abi-consistency' = 300   # + 142 artifact reads; ~2s warm
}

$WatchdogScript = {
    param([int]$RootPid, [int]$TimeoutSec, [string]$DoneFlag, [string]$TimeoutFlag, [datetime]$StepStart)

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $DoneFlag) { return }
        Start-Sleep -Milliseconds 500
    }
    # Last look before doing anything destructive: the step may have finished in
    # the half-second since the loop's final check.
    if (Test-Path -LiteralPath $DoneFlag) { return }

    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                    Select-Object ProcessId, ParentProcessId, Name, CreationDate)
    $byParent = @{}
    foreach ($p in $procs) {
        $k = [int]$p.ParentProcessId
        if (-not $byParent.ContainsKey($k)) { $byParent[$k] = New-Object System.Collections.ArrayList }
        [void]$byParent[$k].Add($p)
    }

    # Never a victim, for two different reasons:
    #  * $PID here is the WATCHDOG'S OWN host process, a direct child of the
    #    gate. Measured on the first run of this code: it put itself on the kill
    #    list and shot itself partway through the loop, so the remaining victims
    #    were never killed and the hang would have continued. The flag file was
    #    already written, so the gate reported a timeout it had not actually
    #    broken -- a report without the action it claims.
    #  * conhost.exe is the console host, not a tool. Killing it takes the
    #    gate's own console with it and unblocks nothing.
    $protectedNames = @('conhost.exe', 'WerFault.exe')

    $victims = New-Object System.Collections.ArrayList
    $seen    = @{}
    $queue   = New-Object System.Collections.Queue
    $queue.Enqueue($RootPid)
    $seen[$RootPid] = $true
    $seen[$PID]     = $true
    while ($queue.Count -gt 0) {
        $cur = [int]$queue.Dequeue()
        if (-not $byParent.ContainsKey($cur)) { continue }
        foreach ($child in $byParent[$cur]) {
            $cid = [int]$child.ProcessId
            if ($seen.ContainsKey($cid)) { continue }
            $seen[$cid] = $true
            # Rule 2: a process that existed before this step began cannot be
            # this step's child; the parent link is a recycled pid.
            if ($null -ne $child.CreationDate -and $child.CreationDate -lt $StepStart) { continue }
            if ($protectedNames -contains $child.Name) { continue }
            [void]$victims.Add(('{0}:{1}' -f $cid, $child.Name))
            $queue.Enqueue($cid)
        }
    }

    # Flag first, kill second. Killing the child is what unblocks the parent's
    # pipeline, so anything written after the kill races the parent's read.
    [System.IO.File]::WriteAllText(
        $TimeoutFlag,
        ("timeout after {0}s`r`nkilled: {1}`r`n" -f $TimeoutSec, ($victims -join ' ')),
        (New-Object System.Text.UTF8Encoding($false)))

    foreach ($v in $victims) {
        $vid = [int]($v -split ':')[0]
        try { Stop-Process -Id $vid -Force -ErrorAction Stop } catch { }
    }
}

function Invoke-Tool {
    param(
        [Parameter(Mandatory)][string]  $Exe,
        [Parameter(Mandatory)][string[]]$ToolArgs,
        [Parameter(Mandatory)][string]  $WorkDir,
        [string] $LogName,
        [string] $StepName,
        [int]    $TimeoutSec = 0
    )
    if (-not $LogName)  { $LogName  = [System.IO.Path]::GetFileNameWithoutExtension($Exe) }
    if (-not $StepName) { $StepName = $LogName }
    if ($TimeoutSec -le 0) {
        $TimeoutSec = if ($StepTimeoutSec.ContainsKey($LogName)) { $StepTimeoutSec[$LogName] }
                      else { $DefaultStepTimeoutSec }
    }

    $safeName    = ($LogName -replace '[^A-Za-z0-9._-]', '-')
    $doneFlag    = Join-Path $GateFlagDir ('{0}.done' -f $safeName)
    $timeoutFlag = Join-Path $GateFlagDir ('{0}.timeout' -f $safeName)
    # DELETE BEFORE WRITING. A stale flag from an earlier run of the same step
    # would be read as this run's verdict -- the exact way a previous run's
    # plausible-looking output has already been reported as a current one here.
    Remove-Item -LiteralPath $doneFlag    -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $timeoutFlag -Force -ErrorAction SilentlyContinue

    $stepStart = Get-Date
    $watchdog = $null
    try {
        $watchdog = Start-Job -ScriptBlock $WatchdogScript `
            -ArgumentList $PID, $TimeoutSec, $doneFlag, $timeoutFlag, $stepStart
    } catch {
        # A gate that cannot arm its watchdog still has to run; it just runs
        # without the deadline, and says so rather than pretending.
        Write-Host "WARNING: step deadline NOT armed for ${StepName}: $_" -ForegroundColor Yellow
    }

    $lines = @()
    Push-Location -LiteralPath $WorkDir
    try {
        & $Exe @ToolArgs | Tee-Object -Variable lines | ForEach-Object { Write-Host $_ }
        $code = $LASTEXITCODE
    }
    finally {
        Pop-Location
        # Disarm FIRST, in a finally, so a throw or a Ctrl-C between here and
        # the job cleanup cannot leave a watchdog that later kills an unrelated
        # descendant of this script.
        try { [System.IO.File]::WriteAllText($doneFlag, 'done', (New-Object System.Text.UTF8Encoding($false))) } catch { }
        if ($watchdog) {
            try { Stop-Job   -Job $watchdog -ErrorAction SilentlyContinue } catch { }
            try { Remove-Job -Job $watchdog -Force -ErrorAction SilentlyContinue } catch { }
        }
    }
    if ($null -eq $lines) { $lines = @() }
    if ($null -eq $code)  { $code = 0 }
    $text = ($lines | Out-String)

    # The watchdog fired: the child was killed, so the non-zero exit code below
    # is a CONSEQUENCE of the timeout and not a diagnosis of one. Say which.
    $timedOut = Test-Path -LiteralPath $timeoutFlag
    $killDetail = ''
    if ($timedOut) {
        try { $killDetail = ((Get-Content -LiteralPath $timeoutFlag -Raw) -replace '\r?\n', ' ').Trim() } catch { }
    }
    # Read, THEN delete. Both flags are pure coordination state; the reason has
    # already been copied into $killDetail and goes into the step log header and
    # the Fail-Step message below.
    Remove-Item -LiteralPath $doneFlag    -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $timeoutFlag -Force -ErrorAction SilentlyContinue

    $script:LogSeq++
    $safe = $safeName
    $logPath = Join-Path $GateLogDir ('{0:d2}-{1}.log' -f $script:LogSeq, $safe)
    $header = @(
        "# $Exe $($ToolArgs -join ' ')",
        "# cwd      : $WorkDir",
        "# started  : $($stepStart.ToString('o'))",
        "# finished : $(Get-Date -Format o)",
        "# deadline : ${TimeoutSec}s  (timed out: $timedOut)",
        "# exit code: $code",
        "# NOTE: this file is the tool's STDOUT. stderr was left unredirected on",
        "#       purpose (see Invoke-Tool) and went to the console.",
        ''
    ) -join "`r`n"
    try {
        Write-Utf8NoBom -Path $logPath -Text ($header + $text)
    } catch {
        Write-Host "WARNING: could not write step log ${logPath}: $_" -ForegroundColor Yellow
    }

    $result = [pscustomobject]@{
        ExitCode = $code
        StdOut   = $text
        All      = $text
        LogPath  = $logPath
        TimedOut = $timedOut
    }
    # Remembered so the FAIL block at the bottom can quote the tool that
    # actually went red without every Fail-Step call site having to pass it.
    $script:LastTool = $result

    # A deadline breach is reported HERE, not left to each call site's
    # exit-code check. Every one of those checks would report the kill's
    # side-effect ("cargo exited 1", "could not parse a test result: line")
    # and none would say the step was killed for hanging -- which is the whole
    # finding. Fail-Step throws, so this returns nothing and the gate stops
    # with a named red instead of running on.
    if ($timedOut) {
        Fail-Step -Name $StepName -Reason (
            "step exceeded ${TimeoutSec}s and was killed -- the child process stopped making " +
            "progress. This is a HANG, not a test failure; the tool's own exit code ($code) is " +
            "a consequence of the kill. [$killDetail] Partial stdout: $logPath")
    }
    return $result
}

# `test result: ok. 562 passed; 0 failed; 16 ignored; 0 measured; 0 filtered out`
function Get-CargoTestCounts {
    param([string]$Text)
    $m = [regex]::Match(
        $Text,
        'test result:\s+(?<verdict>\w+)\.\s+(?<passed>\d+)\s+passed;\s+(?<failed>\d+)\s+failed;\s+(?<ignored>\d+)\s+ignored')
    if (-not $m.Success) { return $null }
    return [pscustomobject]@{
        Verdict = $m.Groups['verdict'].Value
        Passed  = [int]$m.Groups['passed'].Value
        Failed  = [int]$m.Groups['failed'].Value
        Ignored = [int]$m.Groups['ignored'].Value
    }
}

# `Ran 29 test suites in 7.89s (...): 242 tests passed, 0 failed, 0 skipped (242 total tests)`
function Get-ForgeTestCounts {
    param([string]$Text)
    $m = [regex]::Match(
        $Text,
        '(?<passed>\d+)\s+tests?\s+passed,\s+(?<failed>\d+)\s+failed,\s+(?<skipped>\d+)\s+skipped\s+\((?<total>\d+)\s+total\s+tests?\)')
    if (-not $m.Success) { return $null }
    return [pscustomobject]@{
        Passed  = [int]$m.Groups['passed'].Value
        Failed  = [int]$m.Groups['failed'].Value
        Skipped = [int]$m.Groups['skipped'].Value
        Total   = [int]$m.Groups['total'].Value
    }
}

# node --test's summary block:
#   ℹ tests 7
#   ℹ suites 0
#   ℹ pass 7
#   ℹ fail 0
#
# Each key is matched on its OWN anchored line rather than with one span-the-
# block regex. `fail` in particular also appears later in `✖ failing tests:`,
# and a lazy `.*?` across the block would be one output-format change away from
# reading the count out of that heading instead of out of the summary.
# The leading glyph is matched as `\S+` because it is a non-ASCII information
# mark whose literal in this file would depend on the file's own encoding.
function Get-NodeTestCounts {
    param([string]$Text)
    $total  = [regex]::Match($Text, '(?m)^\s*\S+\s+tests\s+(?<n>\d+)\s*$')
    $passed = [regex]::Match($Text, '(?m)^\s*\S+\s+pass\s+(?<n>\d+)\s*$')
    $failed = [regex]::Match($Text, '(?m)^\s*\S+\s+fail\s+(?<n>\d+)\s*$')
    if (-not ($total.Success -and $passed.Success -and $failed.Success)) { return $null }
    return [pscustomobject]@{
        Total  = [int]$total.Groups['n'].Value
        Passed = [int]$passed.Groups['n'].Value
        Failed = [int]$failed.Groups['n'].Value
    }
}

function Get-FreeTcpPort {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    if ($port -eq 8545) {
        # 8545 may belong to a pilot/dev node; the Rust harness refuses it too.
        return Get-FreeTcpPort
    }
    return $port
}

# JSON-RPC eth_chainId, used both to wait for readiness and to prove the node
# we started is the one the tests will talk to.
function Get-NodeChainId {
    param([string]$Url)
    $body = '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
    try {
        $resp = Invoke-RestMethod -Uri $Url -Method Post -Body $body `
            -ContentType 'application/json' -TimeoutSec 3 -ErrorAction Stop
    } catch {
        return $null
    }
    if ($null -eq $resp.result) { return $null }
    return [Convert]::ToInt64([string]$resp.result, 16)
}

# STEP 9's READERS, STEP 8's WALK, AND BOTH STEPS' PINS ARE NOT IN THIS FILE.
# They live in tools\goat-attestor\check-aux-scripts.ps1, which this gate calls
# twice (see STEP 8 and STEP 9 below) and which GitHub Actions calls too. They
# were moved out WHOLE rather than copied: the quote/comment scanner, the
# logical-line folder and the Solidity signature canonicaliser each exist exactly
# once, so there is no second copy for CI to drift from.

$overallStart = Get-Date

try {
    Write-Banner 'goat-attestor full gate'
    Write-Host "attestor : $AttestorDir"
    Write-Host "contracts: $ContractsDir"

    # -----------------------------------------------------------------------
    # STEP 1 -- cargo test --lib
    #
    # IF THIS EVER REPORTS `773 passed, 1 failed` AGAIN, START HERE.
    #
    # It did, twice, on consecutive runs, and the failing test could not be
    # named because this script's output escaped the caller's redirection --
    # fixed above, so a recurrence now prints the test name and leaves
    # 01-cargo-test-lib.log on disk. Read that file FIRST; everything below is
    # only what was already ruled out, so that the next investigation starts
    # where this one stopped rather than where it started.
    #
    # Ruled out by measurement here, after the fix:
    #  * not reproducible: 14 consecutive full gate runs green at
    #    774 / 0 / 17, plus 8 standalone `forge test` runs at 248.
    #  * not artifact drift: contracts/deployments/31337.stream-g{,.payload}.json
    #    sha256-match tools/goat-attestor/fixtures/ before and after.
    #  * the ONLY cross-process shared mutable state `cargo test --lib` has is
    #    those two files -- read by exactly three tests
    #    (token_manifest::tests::loads_real_committed_stream_g_manifest_if_present,
    #    token_manifest::tests::builtin_manifest_is_byte_identical_to_the_committed_deployment_artifact,
    #    deployment_payload::tests::builtin_payload_is_byte_identical_to_the_committed_deployment_artifact)
    #    and rewritten in place by step 4 / any concurrent `forge test`.
    #    Emptying either file makes exactly those tests fail, one of them with
    #    `EOF while parsing a value at line 1 column 0` -- so the shape matches.
    #    But the window is a few microseconds of a `fs::write` truncate, and
    #    150 runs of those three tests under a continuous concurrent
    #    `forge test` loop produced 0 failures and 0 skips. It is not
    #    sufficient to explain 2 failures in 8 runs, and was NOT fixed
    #    speculatively on the strength of a shape match.
    # -----------------------------------------------------------------------
    Write-Banner '1/10  cargo test --lib'
    $r = Invoke-Tool -Exe 'cargo' -ToolArgs @('test', '--lib') -WorkDir $AttestorDir `
        -LogName 'cargo-test-lib' -StepName 'cargo test --lib'
    $c = Get-CargoTestCounts -Text $r.All
    if ($null -eq $c) {
        Fail-Step -Name 'cargo test --lib' -Reason 'could not parse a `test result:` line from cargo output'
    }
    if ($r.ExitCode -ne 0) {
        Fail-Step -Name 'cargo test --lib' -Reason "cargo exited $($r.ExitCode) ($($c.Passed) passed, $($c.Failed) failed)"
    }
    if ($c.Failed -ne 0) {
        Fail-Step -Name 'cargo test --lib' -Reason "$($c.Failed) test(s) failed"
    }
    if ($c.Passed -lt $ExpectedLibTestsMin) {
        Fail-Step -Name 'cargo test --lib' -Reason "only $($c.Passed) passed, expected at least $ExpectedLibTestsMin -- the suite has SHRUNK"
    }
    if ($c.Ignored -ne $ExpectedLibIgnored) {
        Fail-Step -Name 'cargo test --lib' -Reason "$($c.Ignored) ignored, expected exactly $ExpectedLibIgnored -- an #[ignore] was added or removed; bump `$ExpectedLibIgnored/`$ExpectedIgnoredPassed deliberately"
    }
    Add-StepResult -Name 'cargo test --lib' -Status 'PASS' `
        -Detail "$($c.Passed) passed / $($c.Failed) failed / $($c.Ignored) ignored"

    # -----------------------------------------------------------------------
    # STEP 2 -- clippy
    # -----------------------------------------------------------------------
    Write-Banner '2/10  cargo clippy --all-targets -- -D warnings'
    $r = Invoke-Tool -Exe 'cargo' `
        -ToolArgs @('clippy', '--all-targets', '--', '-D', 'warnings') -WorkDir $AttestorDir `
        -LogName 'cargo-clippy' -StepName 'cargo clippy'
    if ($r.ExitCode -ne 0) {
        Fail-Step -Name 'cargo clippy' -Reason "clippy exited $($r.ExitCode)"
    }
    Add-StepResult -Name 'cargo clippy' -Status 'PASS' -Detail 'no warnings'

    # -----------------------------------------------------------------------
    # STEP 3 -- the live-Anvil hazard suite
    #
    # The node is started HERE and reaped in the `finally` below, so a failing
    # assertion (or Ctrl-C) cannot leak an anvil onto the machine.
    #
    # NOTE the anvil flags: --chain-id 31337 --silent, and deliberately NOT
    # --disable-code-size-limit. Wave 1 dropped that flag from the Rust harness
    # so the suite doubles as an EIP-170 regression guard; a node started here
    # with the limit lifted would put the hole straight back.
    #
    # =======================================================================
    # THE 1200s HANG -- STILL NOT ROOT-CAUSED. Bounded (round 2) and now
    # self-diagnosing (round 3); not cured.
    # IF THIS STEP EVER HANGS OR FAILS ON A TIMEOUT AGAIN, START HERE, AND
    # READ "ROUND 3" AT THE BOTTOM FIRST -- it corrects two claims made above
    # and names the one measurement that splits what is left. Everything here
    # is what has already been ruled out, so the next investigation resumes
    # rather than restarts.
    #
    # WHAT WAS SEEN. One run in five: no failure, a HANG. 10 of 17 tests
    # printed `ok`, then nothing -- no `... ok` for
    # `stream_g_anvil_nonce_drift_after_reservation_leaves_a_row_the_sweeper_
    # resolves`, no `test result:` line. The watchdog killed it at 1200s and
    # listed rustup / cargo / goat_attestor / anvil / FORGE. The step is ~27s
    # warm, so this was a stall of at least 40x, not slowness.
    #
    # THE MECHANISM (proved, not inferred). `RpcChain` built every provider
    # with `ProviderBuilder::new().connect_http(url)`, whose reqwest client
    # has NO connect/read/request timeout, and only 3 of its 17 call sites
    # wrapped the future in a timeout. So a node that accepted the connection
    # and then stopped answering parked the caller on `.await` forever. The
    # harness's OWN reads set a 15s reqwest timeout -- which is exactly why a
    # stall surfaced inside a submit/sweep and never inside `h.call_u128`.
    # Reproduced on demand by suspending the harness's own anvil
    # (NtSuspendProcess) mid-suite: the run stopped inside THE SAME TEST at
    # THE SAME POSITION as the gate log, still running at 134s, with dCPU
    # 0.000s over 5s for every process in the tree and an ESTABLISHED socket
    # to the node -- blocked, not spinning -- and completed with exit 0 when
    # the node was resumed. Freezing during `deploy_stream_g` instead
    # reproduced the reported forge.exe: forge alive at 200.9s, zero CPU, no
    # output (`Command::output()` has no timeout either).
    #
    # THE FIX. Every read now runs under a bounded deadline whose error names
    # the operation and the budget (`rpc_chain.rs`: RPC_READ_TIMEOUT = 30s,
    # `with_deadline`), and every external tool this harness shells out to
    # runs under `anvil_harness::output_within` (FORGE_TIMEOUT = 300s,
    # CAST_TIMEOUT = 60s). A stalled peer is now a named failure inside one
    # step budget instead of a watchdog kill 40x later. Both are covered by
    # tests that HANG, not fail, when reverted -- verified.
    #
    # RULED OUT BY EXPERIMENT, so do not re-run these:
    #  * a deadlock. No Mutex/RwLock on this path outside test modules; the
    #    only reachable lock (`submit::SigningLeaseRegistry`) is non-blocking
    #    `try_acquire` and holds no guard across an await; the store uses
    #    `try_lock_exclusive`; every chain read is deliberately taken OUTSIDE
    #    `write_tx`. And the induced hang was idle with a live socket, which
    #    is not what a lock deadlock looks like.
    #  * anvil wedged by a full pipe. The gate drains both pipes (below), and
    #    `spawn_anvil` gives the harness's node `Stdio::null()` on both --
    #    there is no pipe to fill. Both are --silent.
    #  * the malformed WAVE_D_RAW_TX payload wedging the node: 400 sends,
    #    probing eth_blockNumber after each -- the node answered every time.
    #  * `forge script` wedging on its own: 150 runs against fresh anvils,
    #    mean 1.00s, max 2.45s, 0 hangs.
    #  * port/state collision: `free_port()` binds :0 and asserts != 8545;
    #    observed ports climb and wrap cleanly, TIME_WAIT peaked at ~4,800 of
    #    16,384.
    #  * HARNESS_LOCK starvation: a hang there would have NO anvil child, and
    #    the observed kill list had one.
    #
    # STILL OPEN, stated plainly: ~61 faithful step-3 executions (20 bare, 15
    # after steps 1-2, 26 full-gate) produced 0 natural hangs, so WHY a local
    # anvil stops answering is NOT known -- an anvil-side stall and a lost
    # loopback response on one connection were not separated. The 1200s
    # ceiling below stays for that reason: it is the backstop for a stall the
    # deadlines above do not cover, not the diagnosis.
    #
    # ===================== ROUND 3, 2026-07-28 (later) =====================
    # READ THIS BEFORE THE PARAGRAPH ABOVE. "Diagnosed and fixed" overstates
    # what the deadlines did, and the record is corrected here rather than
    # rewritten above so the sequence stays legible.
    #
    # THE STALL SURVIVED THE DEADLINES. It now fails BOUNDED at ~332s instead
    # of being killed at 1200s -- which is the whole benefit, and it is a
    # reporting benefit, not a cure:
    #     forge script DeployStreamG --broadcast --rpc-url http://127.0.0.1:50312
    #     made no progress within 300s and was killed.
    # The deadlines made the condition VISIBLE and NAMED. They did not remove
    # it. Nothing below is a fix and nothing below claims to be.
    #
    # ONE CORRECTION OF FACT, because it moves where to look. That failure log
    # ends with `Script ran successfully / == Return == / == Logs ==`, which
    # reads as "forge finished the work and then would not exit". It is not:
    # Foundry 1.7.1 prints that block from the SIMULATION, before a single
    # transaction is broadcast, and prints nothing at all between the
    # gas-estimate block and ONCHAIN EXECUTION COMPLETE. Verified by running a
    # --broadcast deploy against a NON-silent anvil and aligning forge's stdout
    # with the node's RPC log: 21 eth_sendRawTransaction + 42
    # eth_getTransactionReceipt, all silent, 0.91s end to end. So the stall is
    # not downstream of the work -- it is inside the node conversation, at or
    # just after the first send.
    #
    # RULED OUT BY EXPERIMENT IN THIS ROUND -- do not re-run these either:
    #  * WINDOWS EPHEMERAL-PORT / TIME_WAIT EXHAUSTION. Killed three ways.
    #    (a) Positive control, the decisive one: the pool was driven to 16,114
    #    of 16,384. At 14,609 held, a fresh connect still completed in 0 ms;
    #    at the wall, failure is AddressAlreadyInUse (WSAEADDRINUSE 10048) in
    #    1-4 ms EVERY time. Exhaustion produces an immediate ERROR, never a
    #    silent stall, so it cannot be this shape even if it occurred.
    #    (b) Peak during the suite is 4,921 of 16,384 (30%) -- nowhere near.
    #    (c) Windows logs events 4227/4231/4266 on exactly this condition and
    #    has NEVER logged one on this machine; the excluded-port range is
    #    empty, so all 16,384 are usable.
    #  * NODE REAPING / OVERLAP. ~900 samples across 84 runs: the anvil count
    #    was never above 2 (this gate's node + exactly one harness node), and 1
    #    between tests. No harness node outlived its successor's start.
    #  * RESOURCE EXHAUSTION (handles/memory). Through a captured freeze,
    #    anvil's working set was FLAT at 42.3 MB and its cumulative CPU did not
    #    move (0.08 -> 0.08); no handle growth.
    #  * WINDOWS LOOPBACK VIA A HYPER-V VIRTUAL SWITCH (a documented hazard of
    #    this exact shape). Hyper-V, WSL and VirtualMachinePlatform are all
    #    InstallState 2 (disabled); no vEthernet adapter. Not applicable here.
    #  * INCONCLUSIVE, stated as such: TCP retransmissions run at a constant
    #    ~1/sec machine-wide background (174 over 181s). One connection's
    #    retransmit ladder is ~5 events and is indistinguishable from that
    #    noise, so this counter cannot decide the retransmit hypothesis either
    #    way. Do not read it as evidence in either direction.
    #
    # WHAT A FREEZE ACTUALLY LOOKS LIKE (captured once under instrumentation,
    # 84 faithful bare step-3 runs: 83 at 25-28s, one at 44s). forge appeared
    # at t=23s and lived to t~41s -- ~19s against a ~1.5s norm -- and across
    # that entire window anvil burned NO CPU and its memory did not move. Then
    # the whole 21-transaction broadcast completed in under 2s. So the two
    # sides exchanged essentially nothing for 19s and then did all the work at
    # once. That rules out "anvil is slow executing the deploy". syn_sent was
    # 0 throughout, so nothing was failing to connect.
    #
    # RATES, honestly: 1 freeze in 84 bare runs (~1.2%) at >=19s; 0 at >=30s;
    # 0 at >=300s. The gate's own retained logs show 1 stall in 20 runs that
    # reached step 3 -- NOT the ~1-in-6 that was believed. The 300s variant is
    # too rare to put a rate on from what has been run.
    #
    # THE REMAINING FORK IS BINARY, AND ONE MEASUREMENT SPLITS IT:
    #     at the moment of the stall, was the NODE still serving?
    #   * yes -> the node was healthy; the stall is connection-level or
    #     client-side. Look at the ~1,100 short-lived TCP connections a suite
    #     run makes (every RpcChain call site builds a fresh reqwest client,
    #     and anvil_harness::json_rpc builds one PER CALL), and at free_port()'s
    #     TOCTOU window.
    #   * no  -> anvil itself stopped serving. Look at the node.
    # Five investigations have ended at this fork because nobody recorded the
    # answer while the stall was happening.
    #
    # SO THE HARNESS NOW RECORDS IT ITSELF, on TWO arms. Both emit the same
    # block:
    #     - a fresh-socket eth_blockNumber verdict (hand-rolled on std::net, so
    #       it shares nothing with alloy or reqwest and cannot be served by a
    #       pooled connection): ANSWERED <body> or NO ANSWER <reason>
    #     - the live anvil process count and pids
    #     - the host TIME_WAIT / ESTABLISHED census
    #
    # WHERE TO LOOK -- the two arms do NOT land in the same place, and an
    # earlier version of this note said they did. Read this before grepping.
    #
    #  1. AT-GIVE-UP (`anvil_harness::PanicForensics`), fires only on a
    #     FAILING test. It is AnvilHarness's FIRST field, so on any unwinding
    #     failure -- a FORGE_TIMEOUT kill, an RPC_READ_TIMEOUT surfacing as a
    #     failed assertion, or a plain assertion failure -- it reads the node
    #     BEFORE the harness reaps it. Lands in BOTH places: this step's log
    #     (libtest prints a failing test's captured stderr) and the file below.
    #
    #  2. MID-FLIGHT (`anvil_harness::output_within_probed`), fires at 15s
    #     while `forge script --broadcast` is STILL RUNNING -- the stall caught
    #     in progress rather than after it resolved. This one fires on runs
    #     that PASS, which is the entire reason it exists: the 46.4s step-3 run
    #     that motivated it exited 0 with every test green, so arm 1 recorded
    #     nothing. On a PASSING test it does NOT appear in this step's log --
    #     libtest captures stderr per test, that capture is inherited by the
    #     threads a test spawns (an earlier revision assumed the opposite and
    #     reported through `eprintln!` on that assumption -- it was discarded on
    #     every green run), and this step deliberately does not pass
    #     --nocapture.
    #     Precisely: `record_forensics` still ALSO writes stderr, so if a test
    #     that took a mid-flight reading later FAILS, libtest releases that
    #     test's captured output and the reading does reach this log too. So
    #     "never in the step log" is wrong; "not there when the test passes" is
    #     right, and the passing case is the one that motivated the file.
    #
    # SO: the file is the sink that works on both arms.
    #     tools\goat-attestor\gate-logs\node-forensics.log
    # Appended, never rotated, gitignored, one `===== <UTC> <ARM> [<test>] =====`
    # header per reading. It is NOT per-run -- check the timestamp against this
    # step's own start before attributing a reading to the run you are looking
    # at. `GOAT_FORENSICS_LOG` overrides the path.
    #
    # `--- node forensics` still greps for the block itself in either sink.
    # That one line converts "it stalled" into "it stalled AND the node was /
    # was not reachable".
    #
    # THE INSTRUMENT IS CALIBRATED, not merely written -- seven mutations, each
    # killed by a named test: a probe hard-wired to succeed; a failed probe
    # rendered as ANSWERED; the anvil count replaced by prose; the
    # `std::thread::panicking()` guard removed; `_forensics` moved below
    # `_node` (verdict flips to NO ANSWER -- caught only by the ignored
    # calibration test); reachability inferred from the connect alone; and the
    # probe's own read timeout removed (that one HANGS at 150s+ rather than
    # failing, which is why it is bounded). One assertion in the first draft
    # could not fail -- the report's own explanatory prose contains both
    # "ANSWERED" and "NO ANSWER", so a whole-report contains() was vacuous.
    # Mutation caught it; review had not. Assert on the verdict LINE.
    #
    # TWO TRAPS FOR WHOEVER MUTATION-TESTS THIS CRATE NEXT, both hit here:
    #  * `Copy-Item` PRESERVES LastWriteTime. Restoring a pristine backup over
    #    a mutated source therefore leaves the source OLDER than the binary
    #    cargo just built from the MUTANT, cargo skips the rebuild, and every
    #    subsequent run silently exercises the mutant while reporting green.
    #    That invalidated a full 12-run pass here. Touch the file after any
    #    restore, and prove it: the built test binary is greppable, so search
    #    it for the mutant's own string before trusting a run.
    #  * A mutation that leaves the mutated code still reachable is not a
    #    mutation. Detaching the watchdog's JoinHandle did not stop the thread,
    #    and renaming a label the forensics block prints twice changed nothing
    #    observable. Both "survived" and both were the harness's fault, not the
    #    test's.
    #
    # WHERE TO RESUME. Nothing here is a root cause and no fix was invented on
    # a shape match. Take the next `--- node forensics` block the gate prints
    # and follow whichever branch of the fork above it names.
    # =======================================================================
    # -----------------------------------------------------------------------
    Write-Banner '3/10  live-Anvil hazard suite (#[ignore]d)'

    $anvilVer = Invoke-Tool -Exe 'anvil' -ToolArgs @('--version') -WorkDir $AttestorDir `
        -LogName 'anvil-version' -StepName 'anvil hazard suite'
    if ($anvilVer.All -notmatch [regex]::Escape($ExpectedAnvilVersion)) {
        Write-Host "WARNING: anvil is not $ExpectedAnvilVersion -- the harness's documented behaviour was verified against that build." -ForegroundColor Yellow
    }

    $anvilPort = Get-FreeTcpPort
    $anvilUrl  = "http://127.0.0.1:$anvilPort"
    $anvilProc = $null
    $savedRpcUrl = $env:RPC_URL

    try {
        Write-Host "starting anvil on $anvilUrl ..."
        # .NET Process rather than Start-Process, for the same console-less-host
        # reason given on Invoke-Tool. Both pipes are drained by
        # Begin*ReadLine (which discards, having no subscriber) so a chatty
        # build of anvil cannot fill a pipe buffer and wedge the node.
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = 'anvil'
        $psi.Arguments              = "--port $anvilPort --chain-id 31337 --silent"
        $psi.WorkingDirectory       = $AttestorDir
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $anvilProc = [System.Diagnostics.Process]::Start($psi)
        $anvilProc.BeginOutputReadLine()
        $anvilProc.BeginErrorReadLine()

        $chainId = $null
        $deadline = (Get-Date).AddSeconds(45)
        while ((Get-Date) -lt $deadline) {
            $chainId = Get-NodeChainId -Url $anvilUrl
            if ($null -ne $chainId) { break }
            Start-Sleep -Milliseconds 250
        }
        if ($null -eq $chainId) {
            Fail-Step -Name 'anvil hazard suite' -Reason "no anvil answered eth_chainId on $anvilUrl within 45s"
        }
        if ($chainId -ne 31337) {
            Fail-Step -Name 'anvil hazard suite' -Reason "node on $anvilUrl reports chain id $chainId, expected 31337"
        }
        Write-Host "anvil up, eth_chainId = $chainId"

        $env:RPC_URL = $anvilUrl

        # `--package goat-attestor` DOES NOT WORK: this crate declares its own
        # [workspace], and the repository root is package `goat-core`, so cargo
        # answers `package ID specification 'goat-attestor' did not match any
        # packages`. Run from the crate directory with --lib.
        #
        # `--test-threads=1` is REQUIRED, not a nicety: the three legacy
        # rpc_chain.rs tests share the one node at RPC_URL and a per-instance
        # send_lock, and the harness reap test polls its old ephemeral port
        # after releasing HARNESS_LOCK.
        $r = Invoke-Tool -Exe 'cargo' `
            -ToolArgs @('test', '--lib', '--', '--ignored', '--test-threads=1') `
            -WorkDir $AttestorDir -LogName 'anvil-hazard-suite' -StepName 'anvil hazard suite'

        $c = Get-CargoTestCounts -Text $r.All
        if ($null -eq $c) {
            Fail-Step -Name 'anvil hazard suite' -Reason 'could not parse a `test result:` line from cargo output'
        }
        if ($r.ExitCode -ne 0) {
            Fail-Step -Name 'anvil hazard suite' -Reason "cargo exited $($r.ExitCode) ($($c.Passed) passed, $($c.Failed) failed)"
        }
        if ($c.Failed -ne 0) {
            Fail-Step -Name 'anvil hazard suite' -Reason "$($c.Failed) hazard test(s) failed"
        }
        if ($c.Passed -ne $ExpectedIgnoredPassed) {
            Fail-Step -Name 'anvil hazard suite' -Reason "$($c.Passed) passed, expected exactly $ExpectedIgnoredPassed -- bump `$ExpectedIgnoredPassed deliberately if a wave added one"
        }
        Add-StepResult -Name 'anvil hazard suite' -Status 'PASS' `
            -Detail "$($c.Passed) passed / $($c.Failed) failed on $anvilUrl"
    }
    finally {
        $env:RPC_URL = $savedRpcUrl
        if ($null -ne $anvilProc) {
            try {
                if (-not $anvilProc.HasExited) {
                    Write-Host "reaping anvil (pid $($anvilProc.Id)) ..."
                    Stop-Process -Id $anvilProc.Id -Force -ErrorAction Stop
                    [void]$anvilProc.WaitForExit(10000)
                }
            } catch {
                Write-Host "WARNING: could not reap anvil pid $($anvilProc.Id): $_" -ForegroundColor Yellow
            }
        }
        # Belt and braces: anything still holding the port we handed out.
        $stragglers = Get-Process -Name 'anvil' -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -eq $(if ($null -ne $anvilProc) { $anvilProc.Id } else { -1 }) }
        foreach ($s in $stragglers) {
            Stop-Process -Id $s.Id -Force -ErrorAction SilentlyContinue
        }
    }

    # -----------------------------------------------------------------------
    # STEP 4 -- forge test
    # -----------------------------------------------------------------------
    Write-Banner '4/10  forge test (contracts/)'
    $r = Invoke-Tool -Exe 'forge' -ToolArgs @('test') -WorkDir $ContractsDir `
        -LogName 'forge-test' -StepName 'forge test'
    $f = Get-ForgeTestCounts -Text $r.All
    if ($null -eq $f) {
        Fail-Step -Name 'forge test' -Reason 'could not parse the `N tests passed, M failed` summary line'
    }
    if ($r.ExitCode -ne 0) {
        Fail-Step -Name 'forge test' -Reason "forge exited $($r.ExitCode) ($($f.Passed) passed, $($f.Failed) failed)"
    }
    if ($f.Failed -ne 0) {
        Fail-Step -Name 'forge test' -Reason "$($f.Failed) contract test(s) failed"
    }
    if ($f.Passed -ne $ExpectedForgeTests) {
        Fail-Step -Name 'forge test' -Reason "$($f.Passed) passed, expected exactly $ExpectedForgeTests -- bump `$ExpectedForgeTests deliberately"
    }
    Add-StepResult -Name 'forge test' -Status 'PASS' `
        -Detail "$($f.Passed) passed / $($f.Failed) failed / $($f.Skipped) skipped"

    # -----------------------------------------------------------------------
    # STEP 5 -- node parity fixtures (contracts/test/*.mjs)
    #
    # The JavaScript half of the cross-language feeScheduleHash pair required by
    # The "Stream G -- USDT Gas Abstraction and Multi-Wallet Sponsoring" spec, section 8.1 "Quote construction":
    #   "feeScheduleHash = keccak256(UTF8(RFC8785(schedulePayload))).
    #    Rust/JavaScript/ops fixtures pin the canonical bytes and hash before
    #    Policy Safe approval."
    # The Rust leg runs in step 1, the ops leg is `goat-attestor
    # fee-schedule-hash`, and this is the leg nothing ran until now.
    #
    # Since 2026-07-28 this step also carries the SAME three-way pair for
    # `deploymentManifestHash` -- the ORIGINAL of that rule, published in section 5.1
    # ("manifestHash = keccak256(UTF8(RFC8785(payload)))"), which section 8.1 says the
    # schedule merely inherits. Its Rust leg is
    # `stream_g::deployment_payload`, its ops leg is `goat-attestor
    # deployment-manifest-hash --payload-json`.
    #
    # WHY IT SITS HERE AND NOT LATER, which is load-bearing rather than tidy:
    # StreamGManifest.test.mjs asserts that `deployments/31337.stream-g.json`
    # publishes the same digests the shipped schedule and the shipped deployment
    # payload declare, AND that its four role addresses are the ones the payload
    # committed. That artifact is REWRITTEN by `forge test`
    # (contracts/test/DeployStreamG.t.sol's SHIPPED_FEE_SCHEDULE_HASH and
    # SHIPPED_DEPLOYMENT_MANIFEST_HASH are the deploy parameters, and
    # `writeDeploymentPayload` rewrites the payload document beside it). Running
    # node before step 4 would check the artifact a previous run left behind;
    # running it here checks the one this gate just produced.
    #
    # THIS STEP MUST NEVER SKIP. A skip is indistinguishable in the summary from
    # a pass, which is the zero-enforcement-signal failure the whole step exists
    # to remove -- so a missing node is a hard failure, twice over: the
    # toolchain preflight at the top of this file lists 'node' among the
    # required tools and exits 1 before any step runs, and the guard below is
    # the backstop that keeps that true if someone edits it out of that list.
    # -----------------------------------------------------------------------
    Write-Banner '5/10  node parity fixtures (contracts/test/*.mjs)'

    if (-not (Get-Command 'node' -ErrorAction SilentlyContinue)) {
        Fail-Step -Name 'node parity fixtures' `
            -Reason 'node is not on PATH -- the JavaScript half of the feeScheduleHash parity fixture CANNOT BE SKIPPED; install node 24+ and re-run'
    }
    foreach ($fixture in $NodeParityTests) {
        $full = Join-Path $ContractsDir $fixture
        if (-not (Test-Path -LiteralPath $full)) {
            Fail-Step -Name 'node parity fixtures' -Reason "fixture not found: $full"
        }
    }

    $r = Invoke-Tool -Exe 'node' -ToolArgs (@('--test') + $NodeParityTests) -WorkDir $ContractsDir `
        -LogName 'node-parity' -StepName 'node parity fixtures'
    $n = Get-NodeTestCounts -Text $r.All
    if ($null -eq $n) {
        Fail-Step -Name 'node parity fixtures' -Reason 'could not parse node --test''s `tests/pass/fail` summary block'
    }
    if ($r.ExitCode -ne 0) {
        Fail-Step -Name 'node parity fixtures' -Reason "node exited $($r.ExitCode) ($($n.Passed) passed, $($n.Failed) failed)"
    }
    if ($n.Failed -ne 0) {
        Fail-Step -Name 'node parity fixtures' -Reason "$($n.Failed) parity fixture(s) failed -- the JS canonicaliser, its pinned bytes, or the deployment artifact has drifted from Rust"
    }
    if ($n.Passed -ne $ExpectedNodeParityTests) {
        Fail-Step -Name 'node parity fixtures' -Reason "$($n.Passed) passed, expected exactly $ExpectedNodeParityTests -- a fixture was deleted; bump `$ExpectedNodeParityTests deliberately if one was added"
    }
    Add-StepResult -Name 'node parity fixtures' -Status 'PASS' `
        -Detail "$($n.Passed) passed / $($n.Failed) failed across $($NodeParityTests.Count) file(s)"

    # -----------------------------------------------------------------------
    # STEP 6 -- EIP-170 size assertion
    #
    # `forge build --sizes` is run for its table and to refresh out/, but its
    # EXIT CODE IS NOT TRUSTED as the assertion.
    #
    # Measured during Wave 1 rather than assumed: with GoatRelayGateway
    # deliberately bloated to 43,019 bytes, forge 1.7.1 printed
    #   Error: some contracts exceed the runtime size limit (EIP-170: 24576 bytes)
    # and exited 1. So today it does the right thing. The independent check
    # below is kept anyway, for two reasons that outlive that measurement:
    # `forge build --help` documents only that --sizes prints a table, so the
    # exit status is undocumented behaviour that can change under us; and the
    # artifact read pins the ACTUAL BYTE COUNT, which is what makes a slow
    # creep toward the cap visible in the log long before it trips.
    # -----------------------------------------------------------------------
    Write-Banner '6/10  EIP-170 size guard (GoatRelayGateway)'
    $r = Invoke-Tool -Exe 'forge' -ToolArgs @('build', '--sizes') -WorkDir $ContractsDir `
        -LogName 'forge-build-sizes' -StepName 'EIP-170 size guard'
    Write-Host "(forge build --sizes exited $($r.ExitCode) -- recorded, NOT trusted as the assertion)"

    if (-not (Test-Path -LiteralPath $GatewayJson)) {
        Fail-Step -Name 'EIP-170 size guard' -Reason "artifact not found: $GatewayJson"
    }
    $artifact = Get-Content -LiteralPath $GatewayJson -Raw | ConvertFrom-Json
    $obj = [string]$artifact.deployedBytecode.object
    if (-not $obj.StartsWith('0x')) {
        Fail-Step -Name 'EIP-170 size guard' -Reason "deployedBytecode.object does not start with 0x -- cannot size it safely"
    }
    # len/2 - 1 : two hex chars per byte, minus the leading "0x" (one byte's worth of chars).
    $gatewayBytes = [int](($obj.Length / 2) - 1)
    Write-Host "GoatRelayGateway deployed runtime = $gatewayBytes bytes (EIP-170 cap $Eip170Limit, margin $($Eip170Limit - $gatewayBytes))"
    if ($gatewayBytes -gt $Eip170Limit) {
        Fail-Step -Name 'EIP-170 size guard' -Reason "GoatRelayGateway is $gatewayBytes bytes, over the $Eip170Limit cap by $($gatewayBytes - $Eip170Limit)"
    }
    Add-StepResult -Name 'EIP-170 size guard' -Status 'PASS' `
        -Detail "GoatRelayGateway $gatewayBytes B (cap $Eip170Limit)"

    # -----------------------------------------------------------------------
    # STEP 7 -- migration freeze
    #
    # WHAT GIT DOES AND DOES NOT PROTECT HERE (corrected 2026-07-27; the previous
    # comment claimed 0001 was untracked, which is false):
    #   * 0001_stream_g.sql and 0002_stream_g_outbox.sql ARE tracked at HEAD, so
    #     an edit to either shows up in `git diff` -- but only if someone looks.
    #     Nothing FAILS on it.
    #   * 0003_stream_g_scan_cursor.sql is UNTRACKED as of this writing, so an
    #     edit to it does not even show up as a diff. It must be `git add`ed in
    #     the commit that lands migration 3.
    # Either way git enforces nothing at gate time. These hashes are the only
    # thing in the repository that FAILS on an edit to an applied migration.
    #
    # Every migration is frozen, not just 0001: a database that already recorded
    # `schema_migrations.version = N` never re-runs N, so editing 0002 or 0003
    # forks the schema of every deployment sitting at that version exactly the
    # way editing 0001 would. New work is a new numbered file.
    # -----------------------------------------------------------------------
    Write-Banner '7/10  migrations/ freeze'
    if (-not (Test-Path -LiteralPath $MigrationDir)) {
        Fail-Step -Name 'migration freeze' -Reason "missing: $MigrationDir"
    }

    # Direction 1: nothing in the freeze table may be missing or modified.
    foreach ($name in $MigrationFreeze.Keys) {
        $path = Join-Path $MigrationDir $name
        if (-not (Test-Path -LiteralPath $path)) {
            Fail-Step -Name 'migration freeze' -Reason "missing: $path"
        }
        $expected = $MigrationFreeze[$name]
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
        Write-Host "sha256 $name = $actual"
        if ($actual -ne $expected) {
            Fail-Step -Name 'migration freeze' `
                -Reason "$name HAS BEEN MODIFIED`n  expected $expected`n  actual   $actual"
        }
    }

    # Direction 2 (the paired arm): no .sql file in migrations/ may be absent
    # from the freeze table. Without this, adding 0004 and forgetting to pin it
    # leaves the gate green over an unfrozen migration -- the exact gap that let
    # 0003 ship unpinned.
    $onDisk = @(Get-ChildItem -LiteralPath $MigrationDir -Filter '*.sql' -File |
                    Select-Object -ExpandProperty Name)
    $unfrozen = @($onDisk | Where-Object { -not $MigrationFreeze.Contains($_) })
    if ($unfrozen.Count -gt 0) {
        Fail-Step -Name 'migration freeze' `
            -Reason "migration file(s) NOT in the freeze table: $($unfrozen -join ', ')`n  add the sha256 to `$MigrationFreeze in this script and to MIGRATION_SHA256 in src/stream_g/store.rs"
    }

    Add-StepResult -Name 'migration freeze' -Status 'PASS' `
        -Detail "$($MigrationFreeze.Count) migration(s) match their frozen sha256"

    # -----------------------------------------------------------------------
    # STEP 8 -- AUXILIARY SCRIPT INTEGRITY
    #
    # THE GATE COVERS WHAT IT RUNS, and it runs none of the standup, release or
    # publish scripts. That gap shipped three separate defects, none of which
    # turned this gate a single shade of red: contracts/dev-up.ps1 could not
    # deploy EpochSettlement (fixed in 737cfa4), contracts/testnet-up.ps1 carried
    # the IDENTICAL break for a further session because 737cfa4 fixed one caller
    # and not the other, and desktop/scripts/release-build.ps1 could not be PARSED
    # at all while release-hash.ps1 parsed fine and silently lost the command
    # warning an operator that their release was going out UNSIGNED.
    #
    # WHAT IT ASSERTS -- that the file the host executes is the file the author
    # wrote, in two parts (it parses; and its command graph is the same under
    # UTF-8 as under the encoding the host actually uses) -- and the whole argument
    # for each part now lives in check-aux-scripts.ps1. ONE implementation,
    # because this check also has to run in GitHub Actions and a second copy in
    # YAML would be a second thing to keep exact. Its param() block holds the pins.
    #
    # IT IS LAUNCHED WITH THIS HOST'S OWN EXECUTABLE, which is load-bearing
    # rather than tidy: part (b) compares the file as Parser::ParseFile decodes it
    # against the file as UTF-8, and "as the host decodes it" is only the same
    # question on both sides of the call if it is the same host. Under a host whose
    # default encoding is already UTF-8 that comparison cannot fail, and the child
    # prints its host and encoding and says so rather than reporting a vacuous
    # green.
    #
    # STEPS 8 AND 9 STAY TWO SEPARATE ROWS. The child is called twice -- once with
    # -Skip9, once with -Skip8 -- so each keeps its own SUMMARY line, its own log
    # and its own deadline, and neither can hide inside the other's verdict. The
    # walk runs twice as a result; it costs a fraction of a second, and it is the
    # SAME code both times, so the two steps still cannot disagree about scope.
    #
    # EXIT CODES: 0 pass, 1 a real finding, 2 the check COULD NOT RUN. 2 is
    # reported as FAIL here with DIFFERENT WORDING, because "could not check" must
    # never render as the green of a check that ran -- and must not be triaged as
    # a finding either.
    # -----------------------------------------------------------------------
    Write-Banner '8/10  auxiliary script integrity (*.ps1)'
    if (-not (Test-Path -LiteralPath $AuxCheckScript)) {
        Fail-Step -Name 'aux script integrity' `
            -Reason "missing: $AuxCheckScript -- steps 8 and 9 are implemented in that file"
    }
    $r = Invoke-Tool -Exe $PsHostExe -WorkDir $AttestorDir `
        -ToolArgs @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $AuxCheckScript,
                    '-RepoRoot', $RepoRoot, '-ContractsDir', $ContractsDir, '-Skip9') `
        -LogName 'aux-script-integrity' -StepName 'aux script integrity'
    $auxDetail = Get-AuxCheckDetail -Text $r.All -Check 'check8'
    if ($r.ExitCode -ne 0) {
        Fail-Step -Name 'aux script integrity' -Reason (
            Get-AuxCheckFailReason -ExitCode $r.ExitCode -Detail $auxDetail -LogPath $r.LogPath)
    }
    # A ZERO EXIT IS NOT ENOUGH. The child reports SKIPPED for a check it did not
    # run, and exits 0 when everything it DID run passed -- so without this arm a
    # future edit that passes the wrong switch would record a check that never
    # happened as a PASS. That is the precise failure mode step 5's header calls
    # PASS-by-omission.
    if (($null -eq $auxDetail) -or ($auxDetail.Status -ne 'PASS')) {
        $auxSaid = 'no GATE-DETAIL check8 line at all'
        if ($null -ne $auxDetail) { $auxSaid = $auxDetail.Status }
        Fail-Step -Name 'aux script integrity' -Reason (
            "check-aux-scripts.ps1 exited 0 but did not report check8 as PASS -- it said: " +
            "${auxSaid}. A SKIPPED or unreported check must never be recorded as a passed one. " +
            "Full output: $($r.LogPath)")
    }
    Add-StepResult -Name 'aux script integrity' -Status 'PASS' -Detail $auxDetail.Detail

    # -----------------------------------------------------------------------
    # STEP 9 -- SCRIPT CALL-SITE ABI CONSISTENCY
    #
    # STEP 8 proves each .ps1 PARSES and means one thing. It does NOT prove the
    # script would still WORK: a syntax-valid script fails at runtime when the
    # contract parameter ABIs move underneath it, and step 8 reads such a file as
    # healthy because nothing about it is malformed -- it is merely calling
    # something that no longer exists. Both 737cfa4 defects are exactly that
    # shape and neither is visible to step 8.
    #
    # WHAT IT ASSERTS: every `cast send`/`cast call` signature in those scripts
    # still names a function some compiled artifact declares, and every
    # `forge script` invocation of an overloaded entry point carries a --sig whose
    # VALUE names one of the target's declared entry points. Both are pinned PER
    # FILE as well as tree-wide, because both defects that motivated the step were
    # per-file. Ten vacuity guards stand behind those two loops, since a loop over
    # an empty set is green. All of it, and the measurement behind every pin, is
    # in check-aux-scripts.ps1.
    #
    # SCOPE IS SHARED WITH STEP 8 BY CONSTRUCTION, still: the child builds the
    # swept set once per invocation from the same walk with the same prune list,
    # so a prune-list edit that hides a script from one check hides it from both,
    # and the walk's own count floor and required-set guard fail first.
    #
    # THE ABI UNIVERSE IS FRESH BECAUSE OF WHERE THIS STEP SITS. It is built from
    # contracts/out/**/*.json, which STEP 4 (`forge test`) and STEP 6
    # (`forge build --sizes`) have already regenerated by now -- the same ordering
    # argument that puts step 5 after step 4. A CI job calling the child directly
    # must build first, or it reads whatever the checkout contained; an ABSENT
    # out/ is exit 2 from the child, never a green.
    # -----------------------------------------------------------------------
    Write-Banner '9/10  script call-site ABI consistency'
    if (-not (Test-Path -LiteralPath $AuxCheckScript)) {
        Fail-Step -Name 'script ABI consistency' `
            -Reason "missing: $AuxCheckScript -- steps 8 and 9 are implemented in that file"
    }
    $r = Invoke-Tool -Exe $PsHostExe -WorkDir $AttestorDir `
        -ToolArgs @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $AuxCheckScript,
                    '-RepoRoot', $RepoRoot, '-ContractsDir', $ContractsDir, '-Skip8') `
        -LogName 'script-abi-consistency' -StepName 'script ABI consistency'
    $abiDetail = Get-AuxCheckDetail -Text $r.All -Check 'check9'
    if ($r.ExitCode -ne 0) {
        Fail-Step -Name 'script ABI consistency' -Reason (
            Get-AuxCheckFailReason -ExitCode $r.ExitCode -Detail $abiDetail -LogPath $r.LogPath)
    }
    if (($null -eq $abiDetail) -or ($abiDetail.Status -ne 'PASS')) {
        $abiSaid = 'no GATE-DETAIL check9 line at all'
        if ($null -ne $abiDetail) { $abiSaid = $abiDetail.Status }
        Fail-Step -Name 'script ABI consistency' -Reason (
            "check-aux-scripts.ps1 exited 0 but did not report check9 as PASS -- it said: " +
            "${abiSaid}. A SKIPPED or unreported check must never be recorded as a passed one. " +
            "Full output: $($r.LogPath)")
    }
    Add-StepResult -Name 'script ABI consistency' -Status 'PASS' -Detail $abiDetail.Detail

    # -----------------------------------------------------------------------
    # STEP 10 -- ROLE CODE-HASH CANARY
    #
    # WHAT IT ASSERTS -- that the four contracts whose code hash FeeTokenRegistry
    # commits ON CHAIN, and which `deploymentManifestHash` folds in, still compile
    # from the source a human last blessed -- and the whole argument, the freeze
    # table of four SHA-256(rawMetadata) literals, and five vacuity guards now live
    # in check-role-code-hashes.ps1. ONE implementation, because this check also
    # has to run in GitHub Actions and a second copy of a freeze table in YAML
    # would be a second thing to keep exact -- the scar this repository already
    # carries once, in the migration freeze.
    #
    # IT IS THE SECOND LINE OF DEFENCE, not the first. A source edit reds STEP 5
    # first, on the node-parity fixture, because `forge test` regenerates the
    # payload while the declared digest stays pinned, and this step never runs.
    # What it catches is the FIX for that: re-pinning the declared hash greens
    # step 5 while the commitment already on chain stays stale. Step 5 then
    # compares the new document against itself; this compares against a literal a
    # human had to type. Two different oracles.
    #
    # LAUNCHED WITH THIS HOST'S OWN EXECUTABLE, like the other two children, so
    # "the host" means the same thing on both sides of every call this gate makes.
    #
    # EXIT CODES: 0 pass, 1 a real finding, 2 the check COULD NOT RUN. 2 is
    # reported as FAIL here with DIFFERENT WORDING, because "could not check" must
    # never render as the green of a check that ran.
    # -----------------------------------------------------------------------
    Write-Banner '10/10  role code-hash canary'
    if (-not (Test-Path -LiteralPath $RoleCheckScript)) {
        Fail-Step -Name 'role code-hash canary' `
            -Reason "missing: $RoleCheckScript -- step 10 is implemented in that file"
    }
    $r = Invoke-Tool -Exe $PsHostExe -WorkDir $AttestorDir `
        -ToolArgs @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $RoleCheckScript,
                    '-ContractsDir', $ContractsDir) `
        -LogName 'role-code-hash-canary' -StepName 'role code-hash canary'
    $roleDetail = Get-AuxCheckDetail -Text $r.All -Check 'check10'
    if ($r.ExitCode -ne 0) {
        Fail-Step -Name 'role code-hash canary' -Reason (
            Get-AuxCheckFailReason -ExitCode $r.ExitCode -Detail $roleDetail -LogPath $r.LogPath `
                -ScriptName 'check-role-code-hashes.ps1')
    }
    # A ZERO EXIT IS NOT ENOUGH -- the same PASS-by-omission guard steps 8 and 9
    # carry. The child exits 0 when what it ran passed; this arm is what stops a
    # future edit recording a check that never happened as a passed one.
    if (($null -eq $roleDetail) -or ($roleDetail.Status -ne 'PASS')) {
        $roleSaid = 'no GATE-DETAIL check10 line at all'
        if ($null -ne $roleDetail) { $roleSaid = $roleDetail.Status }
        Fail-Step -Name 'role code-hash canary' -Reason (
            "check-role-code-hashes.ps1 exited 0 but did not report check10 as PASS -- it said: " +
            "${roleSaid}. An unreported check must never be recorded as a passed one. " +
            "Full output: $($r.LogPath)")
    }
    Add-StepResult -Name 'role code-hash canary' -Status 'PASS' -Detail $roleDetail.Detail
}
catch {
    if ($null -eq $script:Failure) {
        $script:Failure = "unexpected error: $_"
        Add-StepResult -Name 'gate' -Status 'FAIL' -Detail "$_"
    }
}
finally {
    # The watchdog scratch, gone on every path: pass, fail, an unhandled throw,
    # and Ctrl-C. Individual flags are already removed by `Invoke-Tool`; this is
    # the directory itself, plus anything a step that died mid-flight left in
    # it. Nothing in here is evidence -- the reasons are in the step logs.
    if ($GateFlagDir -and (Test-Path -LiteralPath $GateFlagDir)) {
        Remove-Item -LiteralPath $GateFlagDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
# EVERY step belongs in this list. A step that is missing from it is not omitted
# from the summary -- it falls through to the "unexpected step" loop below, which
# prints in RED unconditionally, so its PASS is rendered as though it had failed;
# and if an earlier step stops the gate before it runs, it is never printed as
# SKIPPED either, because nothing here knows it was supposed to happen. That was
# the state of 'aux script integrity' before step 9 was added, and step 9 would
# have inherited it.
$allSteps = @(
    'cargo test --lib',
    'cargo clippy',
    'anvil hazard suite',
    'forge test',
    'node parity fixtures',
    'EIP-170 size guard',
    'migration freeze',
    'aux script integrity',
    'script ABI consistency',
    'role code-hash canary'
)
$seen = @{}
foreach ($s in $script:Steps) { $seen[$s.Step] = $s }

Write-Banner 'SUMMARY'
foreach ($name in $allSteps) {
    if ($seen.ContainsKey($name)) {
        $s = $seen[$name]
        $colour = 'Green'
        if ($s.Status -ne 'PASS') { $colour = 'Red' }
        Write-Host ("  {0,-24} {1,-7} {2}" -f $s.Step, $s.Status, $s.Detail) -ForegroundColor $colour
    } else {
        Write-Host ("  {0,-24} {1,-7} {2}" -f $name, 'SKIPPED', 'not reached -- an earlier step failed') -ForegroundColor DarkYellow
    }
}
foreach ($s in $script:Steps) {
    if (-not ($allSteps -contains $s.Step)) {
        Write-Host ("  {0,-24} {1,-7} {2}" -f $s.Step, $s.Status, $s.Detail) -ForegroundColor Red
    }
}

$elapsed = (Get-Date) - $overallStart
Write-Host ''
Write-Host ("elapsed: {0:n1}s" -f $elapsed.TotalSeconds)
Write-Host "per-step logs: $GateLogDir"

if ($null -ne $script:Failure) {
    Write-Host ''
    Write-Host 'GATE: FAIL' -ForegroundColor Red
    Write-Host "  $($script:Failure)" -ForegroundColor Red

    # NAME THE TEST. A verdict line without one is what made the last two
    # intermittent failures unfixable: they were observed, reported as
    # "773 passed, 1 failed", and the 1 could never be identified.
    if ($null -ne $script:LastTool) {
        # Path on its own line: Write-Host output is wrapped at the host width
        # when redirected, and a wrapped path is a path nobody can copy.
        Write-Host '  full stdout of the failing step:' -ForegroundColor Red
        Write-Host "    $($script:LastTool.LogPath)" -ForegroundColor Red
        # @(...) is NOT decoration. `Get-FailureExcerpt` ends in `return $hits`,
        # and PowerShell unrolls a one-element array into a scalar on the way
        # out; `Set-StrictMode -Version Latest` then throws
        # PropertyNotFoundStrict on `.Count`. Observed live: a step that failed
        # with exactly ONE matching excerpt line printed the verdict and then
        # died with "The property 'Count' cannot be found on this object" --
        # i.e. the excerpt this block exists to print was lost, in the one code
        # path whose entire job is naming the failing test.
        $excerpt = @(Get-FailureExcerpt -Text $script:LastTool.All)
        if ($excerpt.Count -gt 0) {
            Write-Host '  --- failure excerpt ---' -ForegroundColor Red
            foreach ($line in $excerpt) { Write-Host "  $line" -ForegroundColor Red }
        } else {
            Write-Host '  (no [FAIL]/failures:/panic line in the captured stdout -- see the log above;' -ForegroundColor Yellow
            Write-Host '   stderr is deliberately not captured, so a build/link error will be on the console only)' -ForegroundColor Yellow
        }
    }
    exit 1
}

Write-Host ''
Write-Host 'GATE: PASS' -ForegroundColor Green
# This used to read "ci.yml is NOT live". Measured 2026-07-29 against the
# published repository's Actions history: SIX runs of it exist and the last five
# are green -- but all six ran a 70-line, 3-job revision of that file. Everything
# added since, including the two jobs that mirror steps 8 and 9, is unproven. The
# reminder now says the true thing, because the false version invited a reader to
# dismiss a badge that does exist, and its replacement must not invite the
# opposite error of reading that badge as covering this gate.
Write-Host '(reminder: the CURRENT ci.yml revision has never run -- a green badge covers 3 of its jobs)' -ForegroundColor DarkGray
exit 0
