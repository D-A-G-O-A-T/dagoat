# contracts/set-watcher.ps1 - rotate EpochSettlement's watcher on Base Sepolia (84532).
#
# WHY THIS EXISTS RATHER THAN A BARE `cast send`.
#
# The obvious command is:
#   cast send <epoch> "setWatcher(address)" <NEW> --private-key <SAFE KEY> --rpc-url ...
# and it has three problems. It puts a live protocol-ADMIN key in shell history
# and scrollback. It accepts, without complaint, several addresses that are
# catastrophic here. And it reports success by exit code, which for a chain write
# against a load-balanced RPC is not evidence.
#
# This reads the key from contracts/.env the way launch-base-sepolia.ps1 does --
# never displayed, never typed -- refuses the known-bad targets, rehearses with
# eth_call, and verifies by reading the value back off chain twice.
#
# USAGE
#   powershell -File contracts\set-watcher.ps1 -NewWatcher 0x... -DryRun
#   powershell -File contracts\set-watcher.ps1 -NewWatcher 0x... -Confirm

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $NewWatcher,
    [switch] $DryRun,
    [switch] $Confirm
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$envPath = Join-Path $here ".env"
if (-not (Test-Path $envPath)) { throw "contracts/.env not found at $envPath" }

foreach ($line in (Get-Content -LiteralPath $envPath)) {
    $t = $line.Trim()
    if ($t -eq "" -or $t.StartsWith("#")) { continue }
    $parts = $t -split '=', 2
    if ($parts.Count -ne 2) { continue }
    [Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim())
}
if (-not $env:RPC_URL -and $env:BASE_SEPOLIA_RPC_URL) { $env:RPC_URL = $env:BASE_SEPOLIA_RPC_URL }

$RPC   = $env:RPC_URL
$SAFE  = $env:SAFE_ADDRESS
$KEY   = $env:DEPLOYER_PRIVATE_KEY
if ([string]::IsNullOrWhiteSpace($RPC))  { throw "RPC_URL / BASE_SEPOLIA_RPC_URL missing" }
if ([string]::IsNullOrWhiteSpace($SAFE)) { throw "SAFE_ADDRESS missing" }
if ([string]::IsNullOrWhiteSpace($KEY))  { throw "DEPLOYER_PRIVATE_KEY missing" }

$epochPath = Join-Path $here "deployments\84532.epoch.json"
if (-not (Test-Path $epochPath)) { throw "no deployments/84532.epoch.json -- nothing deployed to rotate" }
$EPOCH = (Get-Content $epochPath -Raw | ConvertFrom-Json).epochSettlement

function Norm([string] $a) { return $a.Trim().ToLowerInvariant() }

# --- REFUSALS. Each one is a specific, measured hazard, not defensive padding.
$new = $NewWatcher.Trim()
if ($new -notmatch '^0x[0-9a-fA-F]{40}$') {
    throw "not a 20-byte hex address: '$new'"
}
if ((Norm $new) -eq (Norm '0x0000000000000000000000000000000000000000')) {
    # The contract rejects this too (BadArg), but failing here costs no gas.
    throw "address(0) -- the contract rejects it; nothing to send"
}
if ((Norm $new) -eq (Norm $SAFE)) {
    throw @"
the new watcher equals SAFE_ADDRESS ($SAFE).

That is the state this rotation exists to leave. The SAFE key can mint GOAT
without limit, pause transfers, slash escrow and set every parameter, and
`safe` is IMMUTABLE on the token, the escrow and this contract -- there is no
rotation for it, only a redeploy. The watcher, by contrast, can set exactly one
field on an already-proposed batch. Do not alias them.
"@
}
# The four published Anvil dev keys. Measured on Base Sepolia 2026-07-30:
# nonces 23,642 / 2,246 / 1,153 / 427 -- strangers transact from all four on
# THIS chain. Pointing the watcher at one hands the role to the public.
$anvilPublic = @{
    '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266' = 'anvil #0 (attestor PROPOSER)'
    '0x70997970c51812dc3a010c7d01b50e0d17dc79c8' = 'anvil #1 (attestor CHALLENGER)'
    '0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc' = 'anvil #2 (attestor RELAYER)'
    '0x15d34aaf54267db7d7c367839aaf71a00a2c6a65' = 'anvil #4 (attestor WATCHER)'
}
if ($anvilPublic.Contains((Norm $new))) {
    throw @"
$new is $($anvilPublic[(Norm $new)]) -- a PUBLISHED Anvil development key.

Its private key ships in public documentation. Measured on Base Sepolia on
2026-07-30, all four of these addresses carry hundreds to tens of thousands of
transactions from strangers. Setting the watcher to one hands the role to
anybody on earth. Reconcile the OTHER direction: put a private key you control
into the daemon.
"@
}

Write-Host "=== setWatcher on Base Sepolia (84532) ==="
Write-Host "  epochSettlement : $EPOCH"
Write-Host "  safe (sender)   : $SAFE"
Write-Host "  new watcher     : $new"
Write-Host "  rpc             : $RPC"

# --- read the CURRENT value, twice. One reading proves nothing against a
#     load-balanced endpoint.
function Read-Watcher {
    $a = (cast call $EPOCH "watcher()(address)" --rpc-url $RPC | Out-String).Trim()
    Start-Sleep -Seconds 2
    $b = (cast call $EPOCH "watcher()(address)" --rpc-url $RPC | Out-String).Trim()
    if ((Norm $a) -ne (Norm $b)) { throw "watcher() disagreed across two reads ($a vs $b) -- retry" }
    return $a
}
$before = Read-Watcher
Write-Host "  current watcher : $before"
if ((Norm $before) -eq (Norm $new)) {
    Write-Host "  already set to that address; nothing to do."
    exit 0
}

# --- rehearse. `cast call` is eth_call: nothing is broadcast.
#     NOTE what this does and does not prove: it proves the onlySafe gate and
#     that the value is not address(0). A typo'd but well-formed address also
#     returns 0x, so this says NOTHING about the address being the right one.
$sim = (cast call $EPOCH "setWatcher(address)" $new --from $SAFE --rpc-url $RPC 2>&1 | Out-String).Trim()
if ($sim -ne "" -and $sim -ne "0x") { throw "rehearsal reverted: $sim" }
Write-Host "  rehearsal       : passes the onlySafe gate (says nothing about the address itself)"

if ($DryRun) { Write-Host "`nDRY RUN -- nothing broadcast."; exit 0 }
if (-not $Confirm) { throw "refusing to broadcast without -Confirm. Run with -DryRun first." }

Write-Host "`n>>> sending setWatcher"
cast send $EPOCH "setWatcher(address)" $new --private-key $KEY --rpc-url $RPC | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "cast send exited $LASTEXITCODE -- do NOT blind-retry. Read watcher() back first: the send may have landed."
}

# --- verify by READING THE CHAIN, not by the exit code above.
$after = Read-Watcher
Write-Host "  watcher now     : $after"
if ((Norm $after) -ne (Norm $new)) {
    throw "VERIFICATION FAILED: watcher() reads $after, expected $new"
}

# --- two-sided identity probe: the new address must NOT get NotWatcher, and the
#     old one MUST. A one-sided check passes when nothing changed.
$notWatcher = '0x8d23bcde'
$asNew = (cast call $EPOCH "confirmEpoch(uint256)" 1 --from $new --rpc-url $RPC 2>&1 | Out-String).Trim()
$asOld = (cast call $EPOCH "confirmEpoch(uint256)" 1 --from $before --rpc-url $RPC 2>&1 | Out-String).Trim()
if ($asNew -match $notWatcher) { throw "VERIFICATION FAILED: the new watcher still gets NotWatcher()" }
if ($asOld -notmatch $notWatcher) { throw "VERIFICATION FAILED: the OLD watcher does not get NotWatcher() -- the role did not move" }
Write-Host "  identity probe  : new address accepted, old address now rejected"

Write-Host @"

DONE -- but the rotation is NOT finished. Still required, or it silently reverts:
  1. contracts/.env       WATCHER_ADDRESS=$new   (feeds the CONSTRUCTOR; stale
                          value reinstates the old watcher on the next deploy)
  2. tools/goat-attestor/.env  WATCHER_PRIVATE_KEY for this address
  3. restart the daemon (config is read once at startup; no hot reload)
"@
exit 0
