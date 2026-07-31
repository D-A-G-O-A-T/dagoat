# contracts/launch-base-sepolia.ps1 - one-command launcher for the Stream B
# Base Sepolia (84532) pilot.
#
# WHY THIS EXISTS. `testnet-up.ps1` is env-driven and reads five values plus a
# funded DEPLOYER_PRIVATE_KEY out of the process environment. Setting those by
# hand means the operator pastes a live private key into a shell, where it lands
# in history, in the scrollback, and in any transcript of the session. This
# reads them straight out of `contracts/.env` -- the file that already holds
# them, is git-ignored, and is on the curator's TREE_EXCLUDE list -- so the key
# is never displayed, never typed, and never leaves the machine.
#
# It also bridges the one name mismatch: `.env` calls it BASE_SEPOLIA_RPC_URL,
# `testnet-up.ps1` reads RPC_URL.
#
# USAGE
#   powershell -ExecutionPolicy Bypass -File contracts\launch-base-sepolia.ps1 -DryRun
#   powershell -ExecutionPolicy Bypass -File contracts\launch-base-sepolia.ps1 -Confirm
#
# -DryRun prints the plan and broadcasts nothing. The real run REQUIRES -Confirm:
# this deploys to a public chain and cannot be undone, so an accidental
# invocation with no arguments must do nothing. That is the whole reason the
# flag is mandatory rather than a convenience.

[CmdletBinding()]
param(
    [switch] $DryRun,
    [switch] $Confirm,
    [switch] $SkipSeed,
    [switch] $SkipEpoch
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$envPath = Join-Path $here ".env"

if (-not (Test-Path $envPath)) {
    throw "contracts/.env not found at $envPath -- it holds the deploy key and addresses."
}

# --- load .env into the process environment ----------------------------------
# Values are assigned, never written to the host. `-split '=', 2` so a value
# containing '=' (an RPC URL with a query string) survives intact.
$loaded = @{}
foreach ($line in (Get-Content -LiteralPath $envPath)) {
    $t = $line.Trim()
    if ($t -eq "" -or $t.StartsWith("#")) { continue }
    $parts = $t -split '=', 2
    if ($parts.Count -ne 2) { continue }
    $name = $parts[0].Trim()
    $value = $parts[1].Trim()
    if ($name -eq "") { continue }
    [Environment]::SetEnvironmentVariable($name, $value)
    $loaded[$name] = $value.Length
}

# --- bridge the name mismatch ------------------------------------------------
if (-not $env:RPC_URL -and $env:BASE_SEPOLIA_RPC_URL) {
    $env:RPC_URL = $env:BASE_SEPOLIA_RPC_URL
}
if (-not $env:CHAIN_ID) { $env:CHAIN_ID = "84532" }

# --- assert every required value arrived, WITHOUT printing any of them -------
# Length only. A missing key and a truncated one are different failures and the
# operator needs to be able to tell them apart before a broadcast, not after.
$required = @(
    "RPC_URL",
    "CHAIN_ID",
    "SAFE_ADDRESS",
    "FOUNDER_ADDRESS",
    "RESERVE_ADDRESS",
    "WATCHER_ADDRESS",
    "DEPLOYER_PRIVATE_KEY"
)
$missing = @()
Write-Host "=== config loaded from contracts/.env (lengths only) ==="
foreach ($name in $required) {
    $v = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($v)) {
        $missing += $name
        Write-Host ("  {0,-22} MISSING" -f $name)
        continue
    }
    if ($name -like "*PRIVATE_KEY*") {
        # Never echo key material, not even a prefix. 66 = "0x" + 64 hex.
        $shape = if ($v.Length -eq 66 -and $v.StartsWith("0x")) { "well-formed" } else { "UNEXPECTED SHAPE" }
        Write-Host ("  {0,-22} {1} chars, {2}" -f $name, $v.Length, $shape)
    } else {
        Write-Host ("  {0,-22} {1}" -f $name, $v)
    }
}
if ($missing.Count -gt 0) {
    throw "missing required value(s): $($missing -join ', ')"
}

if ($env:CHAIN_ID -ne "84532") {
    throw "this launcher is for Base Sepolia only; CHAIN_ID is $($env:CHAIN_ID)"
}

# --- refuse to run against a stack that is already deployed ------------------
# testnet-up.ps1 is a FRESH-STACK script (B2): re-running it deploys a second,
# parallel set of contracts and overwrites the manifests that name the first.
# The desktop app and the attestor then point at the new stack while any funds,
# enrolments and sessions stay on the old one -- silently.
$manifest = Join-Path $here "deployments\84532.json"
if (Test-Path $manifest) {
    throw @"
deployments/84532.json already exists -- a Stream B stack is already deployed on
Base Sepolia. This script deploys a FRESH stack and would overwrite the manifest
that points at the existing one, orphaning anything already on it.

Move or delete the 84532*.json manifests deliberately if you really intend a
second deployment.
"@
}

# --- confirm ------------------------------------------------------------------
if (-not $DryRun -and -not $Confirm) {
    throw @"
refusing to broadcast without -Confirm.

This deploys three contract sets to Base Sepolia (chain 84532), a PUBLIC chain,
and cannot be undone. Run with -DryRun first to see the plan, then re-run with
-Confirm to broadcast.
"@
}

# 🔴 HASHTABLE SPLAT, NOT AN ARRAY, AND THIS COST A REAL DEPLOYMENT.
#
# The first revision built `$args = @("-DryRun")` and called `& $child @args`.
# ARRAY splatting binds POSITIONALLY, and a [switch] cannot be set positionally,
# so the string "-DryRun" was silently discarded: the parent reported
# `count=1 [-DryRun]` while the child saw `DryRun=False`. testnet-up.ps1 ran in
# REAL mode and broadcast DeployFreeMarket to Base Sepolia -- 7 transactions,
# nonce 22 -> 29 -- during what was supposed to be a dry run. Reproduced in
# isolation before being fixed here.
#
# HASHTABLE splatting binds by NAME, which is what a switch needs. The failure
# was silent in the direction that broadcasts, which is why this is a comment
# and not just a diff.
#
# Also note the variable is no longer called `$args`: that is an automatic
# variable, and shadowing it is what made the array form look plausible.
$forward = @{}
if ($DryRun)    { $forward['DryRun']    = $true }
if ($SkipSeed)  { $forward['SkipSeed']  = $true }
if ($SkipEpoch) { $forward['SkipEpoch'] = $true }

Write-Host ""
Write-Host "=== handing off to testnet-up.ps1 ($($forward.Keys -join ', ')) ==="
Write-Host ""

# 🔴 DO NOT `exit $LASTEXITCODE` HERE. $LASTEXITCODE reports the last NATIVE
# command, not the child SCRIPT, so it is stale whenever the child ran no
# external process -- a clean dry run exited 1 on that alone. On a deploy this
# is dangerous in BOTH directions: a stale 1 cries failure on a good run, and a
# stale 0 reports success on a failed one, which is the worse half.
#
# testnet-up.ps1 sets $ErrorActionPreference = "Stop" and `throw`s on any failed
# step, and `&` runs it in this runspace, so a real failure arrives here as a
# terminating error. Catch that and let it decide the exit code.
try {
    & (Join-Path $here "testnet-up.ps1") @forward
} catch {
    Write-Host ""
    Write-Host "=== testnet-up.ps1 FAILED ==="
    Write-Host $_.Exception.Message
    Write-Host ""
    Write-Host "If this was a real run, the chain may hold a PARTIAL stack. Check"
    Write-Host "contracts/deployments/84532.json and the deployer nonce before re-running:"
    Write-Host "re-running deploys a SECOND stack, it does not resume the first."
    exit 1
}
exit 0
