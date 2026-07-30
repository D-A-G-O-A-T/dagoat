# Prints "yes" when the recorded EpochSettlement address has code on the local chain
# (i.e. the persisted anvil state already carries a deployment; GOAT-START.bat then
# skips dev-up so redeployment doesn't orphan persisted balances). Prints "no" otherwise.
$ErrorActionPreference = "SilentlyContinue"
$root = Split-Path -Parent $PSScriptRoot
$epochJson = Join-Path $PSScriptRoot "src\chain\deployments\31337.epoch.json"
$cast = Join-Path $env:USERPROFILE ".foundry\bin\cast.exe"
try {
    $addr = (Get-Content $epochJson -Raw | ConvertFrom-Json).epochSettlement
    if (-not $addr) { Write-Output "no"; exit 0 }
    $code = & $cast code $addr --rpc-url "http://127.0.0.1:8545" 2>$null
    if ($code -and $code -ne "0x") { Write-Output "yes" } else { Write-Output "no" }
} catch {
    Write-Output "no"
}
