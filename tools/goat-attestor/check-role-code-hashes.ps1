#Requires -Version 5.1
# .SYNOPSIS
#     The gate's step 10 (role code-hash canary), as ONE implementation that both
#     run-full-gate.ps1 and GitHub Actions call.
#
# .DESCRIPTION
#     WHY THIS IS A SEPARATE FILE.
#
#     This check was inline in run-full-gate.ps1, which made it gate-enforced and
#     not CI-enforced, and the reason recorded there was a design decision rather
#     than effort: mirroring it by pasting the freeze table into a workflow YAML
#     would create a SECOND copy of the one thing whose entire value is being
#     exact. This repository already carries that scar -- the migration freeze
#     table lives in two places and needed a test asserting the two agree. So the
#     logic and the table live here, once, and both callers shell out to it. Steps
#     8 and 9 were extracted first, for the same reason, into
#     check-aux-scripts.ps1; this is the third.
#
#     THE PINS LIVE HERE, in the param() block, not in the caller. A row left
#     behind in run-full-gate.ps1 would be a row CI does not honour, which is the
#     two-implementations defect one level down.
#
#     WHAT THIS CHECK ASSERTS.
#
#     Four contracts have their code hash committed ON CHAIN by FeeTokenRegistry,
#     and those four hashes are folded into deploymentManifestHash. This step pins
#     SHA-256(artifact.rawMetadata) for each of them against a human-bumped
#     literal, so a source or compiler-settings change that moves an on-chain
#     commitment cannot pass unnoticed.
#
#     IT IS THE SECOND LINE OF DEFENCE, NOT THE FIRST, and the distinction is
#     load-bearing. A source edit trips STEP 5 (the node parity fixture) first,
#     because forge test regenerates the payload with the new code hash while the
#     DECLARED digest still comes from the pinned deployment-manifest hash, so
#     declared and computed diverge and this step never runs. The first draft of
#     that comment claimed the gate was blind to a moved hash; its own mutation
#     test disproved it.
#
#     SO WHAT THIS ADDS IS A DEFENCE AGAINST THE FIX. Step 5's failure reads
#     "declared != computed", and the obvious way to green it is to update the
#     declared hash to the new computed value and regenerate the payload -- which
#     restores a green gate while the manifest ALREADY COMMITTED ON CHAIN stays
#     stale. Step 5 structurally cannot see that, because after the regeneration
#     it compares the new document against itself. This step compares against a
#     literal a human had to type, so the same fix has to touch a row here and
#     acknowledge the republish. Two different oracles: step 5 asks whether the
#     document is self-consistent, step 10 asks whether the code is the code a
#     human last blessed. It also names WHICH of the four moved, which a digest
#     mismatch does not.
#
#     WHY A FORMATTING PASS IS NOT COSMETIC HERE, measured 2026-07-29 rather than
#     argued. A COMMENT-ONLY edit to src/WalletSponsorshipRegistry.sol left the
#     deployed size byte-for-byte identical at 9,345 bytes and still moved the
#     code hash from 0xdc6369ea... to 0x3c5745d5... Only the trailing solc CBOR
#     metadata differed -- the bytecode ends a264697066735822...64736f6c6343000818,
#     an IPFS digest OF THE SOURCE. And 'forge fmt --check' is dirty on ALL FOUR of
#     these contracts. So "reformat later, it is only whitespace" is false here: it
#     invalidates the on-chain capability commitment and needs a Policy Safe
#     FeeTokenRegistry.setActiveManifestHash transaction to repair.
#
#     WHAT IS PINNED, and why it is NOT the on-chain hash. These are
#     SHA-256(artifact.rawMetadata) -- the compiler's own record of the source and
#     the settings that produced the contract. It moves if and only if the source
#     or the compiler settings move, which is exactly the canary wanted.
#
#     It deliberately is NOT keccak(deployedBytecode), because that CANNOT equal
#     the on-chain code, and both reasons were measured:
#
#       * IMMUTABLES are substituted at construction. WalletSponsorshipRegistry
#         has 12 immutable reference slots, so the artifact carries zeros where the
#         chain carries constructor values. Its artifact keccak is 0xdc6369ea...
#         while the payload records 0xdd985541... -- and that difference is
#         CORRECT, not a defect. It was chased down before being reported as one.
#       * GoatRelayGateway's artifact bytecode is UNLINKED: 3 linkReferences and a
#         placeholder at hex offset 2298. 'cast keccak' refuses it outright.
#
#     So this is a canary on the INPUTS, not a re-derivation of the on-chain value.
#     Verifying the committed hash against a live chain still needs a chain and is
#     still open work.
#
#     BUMP A ROW ONLY IN THE SAME COMMIT that regenerates the deployment payload
#     and re-publishes the manifest. A row bumped on its own silently re-blesses a
#     stale on-chain commitment, which is the whole thing this exists to prevent.
#
#     THIS FILE IS IN CHECK 8's SWEPT SET. It is a .ps1 under the repository root
#     that no prune-list entry hides, so check 8 parses it and compares its command
#     graph under both decodings. That is why it is BOM-LESS and PURE ASCII (write
#     "--" for an em-dash, never the character) and why every 'forge'/'cast'
#     example above sits in a comment. It is also why check-aux-scripts.ps1's
#     -ExpectedAuxScriptsMin went 14 -> 15 when this file landed, and why the CI
#     job's exact scope count went 12 -> 13.
#
#     A NOTE ON BACKTICKS, learned the hard way in this directory. Inside a
#     "..." string, backtick-f is a FORM FEED (0x0C) and backtick-n is a newline.
#     check-aux-scripts.ps1 shipped a blocker message reading backtick-f-o-r-g-e
#     and rendered it as 0x0C followed by "orge build". Quote command names with
#     single quotes inside double-quoted strings.
#
# .PARAMETER ContractsDir
#     Foundry project. Empty means <this script's grandparent>\contracts, resolved
#     in the body -- NOT as a param default, because $PSScriptRoot is EMPTY inside
#     the param() block when the file is launched with `powershell -File <path>`,
#     and a script that dies in its own signature reports nothing at all, which is
#     the one outcome the exit contract exists to prevent.
#
# .PARAMETER PayloadRelPath
#     The deployment payload, relative to ContractsDir. Read only to confirm that
#     the roles pinned here are the roles the manifest actually commits.
#
# .NOTES
#     EXIT CONTRACT (machine-readable; this is what a caller keys off):
#
#       0  the check RAN and PASSED.
#       1  the check RAN and FAILED -- a pinned hash moved, or a pin describes
#          something the manifest does not.
#       2  the check COULD NOT RUN (contracts/out absent, an artifact missing or
#          unparseable, the payload missing or unparseable). DISTINCT FROM 1 ON
#          PURPOSE: "could not check" must never be reportable as "checked and
#          fine", and must not be triaged as a finding either. NEVER 0.
#
#     2 OUTRANKS 1 when both occur: a run that could not hash one of the four has
#     not produced a verdict over the whole surface. Every finding is still
#     printed in full.
#
#     STDOUT CONTRACT. Findings and blockers print one per line, prefixed
#     `[FAIL] ` so that run-full-gate's Get-FailureExcerpt (which matches
#     ^\s*\[FAIL) quotes them without parsing anything. Immediately before the
#     summary:
#
#         GATE-DETAIL check10 <PASS|FAIL|COULD-NOT-RUN> <detail text>
#
#     run-full-gate reads ONLY the <detail text> off that line, to reproduce the
#     SUMMARY row it printed before this file existed. THE EXIT CODE REMAINS THE
#     SOLE AUTHORITY: if the line is absent the gate falls back to a generic
#     detail and still reports the exit code's verdict, so a lost marker cannot
#     turn a red into a green.
#
# .EXAMPLE
#     powershell -NoProfile -File .\check-role-code-hashes.ps1
#
# .EXAMPLE
#     powershell -NoProfile -File .\check-role-code-hashes.ps1 -ContractsDir C:\r\contracts

[CmdletBinding()]
param(
    [string] $ContractsDir = '',

    [string] $PayloadRelPath = 'deployments\31337.stream-g.payload.json',

    # FeeTokenRegistry commits an address AND a runtimeCodeHash for four roles. A
    # table of a different size means a role stopped being covered, or one was
    # invented here. Asserted, not assumed.
    [int] $ExpectedRoleCount = 4,

    # SHA-256(artifact.rawMetadata), lowercase hex. THE LITERAL IS THE TEST: do
    # not replace a row with an expression derived from the artifact, which is the
    # assertion-that-cannot-fail shape this repository has recorded nine times.
    [System.Collections.Specialized.OrderedDictionary] $RoleMetadataFreeze = ([ordered]@{
        'FEE_TOKEN_REGISTRY'          = 'f9ddeded5cdcff6eca8957a000d37b2106c8f58d7d7716166d2108ca384c3a16'
        'GATEWAY'                     = '1e483725795f6ddaee7012b6fb50ca5faec95e037638f65032d7abf5bb657be8'
        'SPONSORED_BUY_DESK'          = '8be0e57d28f6adb7ecc4c2880376caa23d4972571ad7e9ef7aead8694d341ef4'
        'WALLET_SPONSORSHIP_REGISTRY' = '4bf6d9b4625b3396d49ffe845e35db05e8758cf9bc0567ac2f2c3c66daf1e73a'
    }),

    # Role -> the artifact that implements it. SEPARATE from the freeze table on
    # purpose, so a renamed contract is a lookup failure rather than a silently
    # unchecked row. The artifact filename is what Foundry writes as
    # out/<Source.sol>/<ContractName>.json.
    [System.Collections.Specialized.OrderedDictionary] $RoleArtifactName = ([ordered]@{
        'FEE_TOKEN_REGISTRY'          = 'FeeTokenRegistry'
        'GATEWAY'                     = 'GoatRelayGateway'
        'SPONSORED_BUY_DESK'          = 'SponsoredBuyDesk'
        'WALLET_SPONSORSHIP_REGISTRY' = 'WalletSponsorshipRegistry'
    })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ContractsDir)) {
    $ContractsDir = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path 'contracts'
}

$script:Findings = New-Object System.Collections.ArrayList
$script:Blockers = New-Object System.Collections.ArrayList

function Add-Finding { param([string]$Text) [void]$script:Findings.Add($Text) }
function Add-Blocker { param([string]$Text) [void]$script:Blockers.Add($Text) }

Write-Output '=============================================================================='
Write-Output '  ROLE CODE-HASH CANARY (gate step 10)'
Write-Output '=============================================================================='
Write-Output ("  host        : {0} {1}" -f $PSVersionTable.PSEdition, $PSVersionTable.PSVersion)
Write-Output ("  contracts   : {0}" -f $ContractsDir)

$freezeKeys   = @($RoleMetadataFreeze.Keys)
$artifactKeys = @($RoleArtifactName.Keys)

# ---------------------------------------------------------------------------
# GUARD 1 -- the freeze table and the role map must describe the same roles. A
# row present in one and absent from the other is either a role that looks pinned
# and is not checked, or a check with nothing to compare against.
# MUTATION that turns it red: delete any single row from either table.
# ---------------------------------------------------------------------------
$onlyInFreeze = @($freezeKeys | Where-Object { $artifactKeys -notcontains $_ })
$onlyInMap    = @($artifactKeys | Where-Object { $freezeKeys -notcontains $_ })
if (($onlyInFreeze.Count -gt 0) -or ($onlyInMap.Count -gt 0)) {
    Add-Finding (
        "the freeze table and the role->artifact map disagree. Only in freeze: " +
        "$($onlyInFreeze -join ', '). Only in map: $($onlyInMap -join ', '). A role in one " +
        "table and not the other is either pinned-but-unchecked or checked-against-nothing.")
}

# ---------------------------------------------------------------------------
# GUARD 2 -- the size of the covered set. A loop over three roles is green while
# the fourth goes unwatched.
# ---------------------------------------------------------------------------
if ($freezeKeys.Count -ne $ExpectedRoleCount) {
    Add-Finding (
        "the freeze table holds $($freezeKeys.Count) role(s), expected exactly $ExpectedRoleCount. " +
        "FeeTokenRegistry commits an address AND a runtimeCodeHash for $ExpectedRoleCount roles; a " +
        "table of a different size means a role stopped being covered or one was invented here.")
}

# ---------------------------------------------------------------------------
# GUARD 3 -- the roles pinned here must be the roles the PAYLOAD actually
# commits. Pinning a role the manifest does not carry protects nothing, and a role
# the manifest carries that is absent here is unprotected -- and that direction is
# the dangerous one.
# MUTATION that turns it red: rename a role key in the payload, or here.
# ---------------------------------------------------------------------------
$payloadPath = Join-Path $ContractsDir $PayloadRelPath
if (-not (Test-Path -LiteralPath $payloadPath)) {
    Add-Blocker (
        "the deployment payload is missing: $payloadPath. This check CANNOT RUN, which is not the " +
        "same as passing -- with no payload there is nothing to confirm the pinned roles are the " +
        "roles actually committed on chain. STEP 4 ('forge test') writes it.")
}
else {
    $payloadRoles = @()
    $payloadOk = $true
    try {
        $payloadJson = Get-Content -LiteralPath $payloadPath -Raw | ConvertFrom-Json
        $payloadRoles = @($payloadJson.payload.contracts.PSObject.Properties.Name)
    }
    catch {
        $payloadOk = $false
        Add-Blocker "could not parse the deployment payload ${payloadPath}: $_"
    }
    if ($payloadOk) {
        $notInPayload  = @($freezeKeys | Where-Object { $payloadRoles -notcontains $_ })
        $notPinnedHere = @($payloadRoles | Where-Object { $freezeKeys -notcontains $_ })
        if (($notInPayload.Count -gt 0) -or ($notPinnedHere.Count -gt 0)) {
            Add-Finding (
                "the pinned roles are not the roles the manifest commits. Pinned but absent from " +
                "the payload: $($notInPayload -join ', '). Committed on chain but NOT pinned " +
                "here: $($notPinnedHere -join ', '). The second list is the dangerous one.")
        }
    }
}

# ---------------------------------------------------------------------------
# GUARD 4 -- the artifact directory. An absent out/ is the CI shape: the job
# downloads it as an artifact, and "the artifact never arrived" must read as
# COULD NOT RUN rather than as four roles that happened to match.
# ---------------------------------------------------------------------------
$outDir = Join-Path $ContractsDir 'out'
$canHash = $true
if (-not (Test-Path -LiteralPath $outDir)) {
    $canHash = $false
    Add-Blocker (
        "the compiled-artifact directory does not exist: $outDir. This check CANNOT RUN, which is " +
        "not the same as passing. 'forge build' (or the gate's forge test step) populates out/; in " +
        "CI it arrives as a downloaded artifact.")
}

# ---------------------------------------------------------------------------
# THE CANARY ITSELF
# ---------------------------------------------------------------------------
$hashed = 0
if ($canHash) {
    foreach ($roleName in $freezeKeys) {
        if (-not $RoleArtifactName.Contains($roleName)) { continue }   # guard 1 already reported it
        $artName = [string]$RoleArtifactName[$roleName]
        $artPath = Join-Path $outDir ("{0}.sol\{1}.json" -f $artName, $artName)
        if (-not (Test-Path -LiteralPath $artPath)) {
            Add-Blocker "$roleName -- artifact not found, so its hash could not be computed: $artPath"
            continue
        }
        $rawMeta = $null
        try {
            $artJson = Get-Content -LiteralPath $artPath -Raw | ConvertFrom-Json
            if ($artJson.PSObject.Properties.Name -contains 'rawMetadata') {
                $rawMeta = [string]$artJson.rawMetadata
            }
        }
        catch {
            Add-Blocker "$roleName -- artifact did not parse, so its hash could not be computed: $artPath"
            continue
        }
        # An EMPTY rawMetadata hashes to a constant and would compare equal for
        # every role, so absence is a FINDING rather than a skip: the artifact is
        # there and readable, and it carries nothing to pin.
        if ([string]::IsNullOrEmpty($rawMeta)) {
            Add-Finding "$roleName -- $artName.json carries no rawMetadata, so there is nothing to pin"
            continue
        }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($rawMeta)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $actual = ([System.BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
        }
        finally {
            $sha256.Dispose()
        }
        $hashed++
        $expected = [string]$RoleMetadataFreeze[$roleName]
        Write-Output ("  rawMetadata sha256 {0,-28} = {1}" -f $artName, $actual)
        # Case-SENSITIVE. A pin that differs only in case is a pin that was
        # retyped, and this file's sibling shipped a case-insensitive lookup that
        # merged two genuinely different selectors.
        if ($actual -cne $expected) {
            Add-Finding (
                "$roleName ($artName) HAS MOVED" + [System.Environment]::NewLine +
                "         expected $expected" + [System.Environment]::NewLine +
                "         actual   $actual" + [System.Environment]::NewLine +
                "         Its compiled source or compiler settings changed, so its ON-CHAIN " +
                "runtimeCodeHash has moved too and the manifest FeeTokenRegistry committed is now " +
                "stale. If the change was intended, regenerate the deployment payload, re-publish " +
                "the manifest, and bump this row IN THE SAME COMMIT.")
        }
    }
}

# ---------------------------------------------------------------------------
# GUARD 5 -- the loop above is the check, and a loop that hashed nothing is
# green. This is the floor on the WORK, not on the table: guard 2 counts rows,
# this counts hashes actually computed.
# ---------------------------------------------------------------------------
if ($canHash -and ($hashed -ne $ExpectedRoleCount)) {
    Add-Blocker (
        "hashed $hashed of $ExpectedRoleCount role contract(s). Guard 2 counts table rows; this " +
        "counts hashes actually computed, and the two are different measurements -- a table of " +
        "four whose artifacts all failed to load would satisfy guard 2 and check nothing.")
}

Write-Output ''
foreach ($b in $script:Blockers) { Write-Output ("[FAIL] check 10 COULD NOT RUN -- {0}" -f $b) }
foreach ($f in $script:Findings) { Write-Output ("[FAIL] check 10 -- {0}" -f $f) }

$status = 'PASS'
$detail = "$hashed role contract(s) match their frozen rawMetadata sha256"
$exitCode = 0
if ($script:Findings.Count -gt 0) {
    $exitCode = 1
    $status = 'FAIL'
    $detail = "$($script:Findings.Count) finding(s) -- see the [FAIL] line(s) above"
}
# 2 OUTRANKS 1: a blocked run produced no verdict over the whole surface, which is
# a different report from "checked, and here is what is wrong".
if ($script:Blockers.Count -gt 0) {
    $exitCode = 2
    $status = 'COULD-NOT-RUN'
    $detail = "$($script:Blockers.Count) blocker(s) -- see the [FAIL] line(s) above"
}

Write-Output ''
Write-Output ("GATE-DETAIL check10 {0} {1}" -f $status, $detail)
Write-Output ("ROLE-CANARY SUMMARY: role code-hash canary = {0}; hashed = {1}; findings = {2}; blockers = {3}; exit {4}" -f `
    $status, $hashed, $script:Findings.Count, $script:Blockers.Count, $exitCode)

exit $exitCode
