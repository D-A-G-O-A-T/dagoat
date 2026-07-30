# Sync goat-attestor .env contract addresses from desktop deployment JSONs.
#
# Usage:
#   .\sync-env-from-desktop.ps1                  # default: 31337 (local lab)
#   .\sync-env-from-desktop.ps1 -ChainId 84532   # Base Sepolia pilot
#
# After contracts/dev-up.ps1 (31337) or contracts/testnet-up.ps1 (84532).
# Never silently mix 31337 addresses into a 84532 CHAIN_ID (branch-review footgun).

param(
    [ValidateSet("31337", "84532")]
    [string]$ChainId = "31337",
    [string]$RpcUrl = ""
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$depDir = Join-Path $PSScriptRoot "..\..\desktop\src\chain\deployments"
$epochPath = Join-Path $depDir "$ChainId.epoch.json"
$basePath = Join-Path $depDir "$ChainId.json"
if (-not (Test-Path $epochPath)) { Write-Error "Missing $epochPath - deploy epoch lane or run testnet-up.ps1" }
if (-not (Test-Path $basePath)) { Write-Error "Missing $basePath" }

$epoch = Get-Content $epochPath -Raw | ConvertFrom-Json
$base = Get-Content $basePath -Raw | ConvertFrom-Json

function Assert-Addr([string]$Label, $Value) {
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        Write-Error "$Label is null/empty in desktop deployments for chain $ChainId - not syncing partial addresses"
    }
    $s = [string]$Value
    if ($s -eq "0x" -or $s -match '^0x0{40}$') {
        Write-Error "$Label is zero/placeholder for chain $ChainId"
    }
    return $s
}

$workerBinding = Assert-Addr "workerBinding" $epoch.workerBinding
$epochSettlement = Assert-Addr "epochSettlement" $epoch.epochSettlement
$enrollmentRegistry = Assert-Addr "enrollmentRegistry" $base.enrollmentRegistry
$goatCoin = Assert-Addr "goatCoin" $base.goatCoin

$deployBlock = $null
if ($null -ne $epoch.workerBindingDeployBlock -and "$($epoch.workerBindingDeployBlock)" -ne "") {
    $deployBlock = [string]$epoch.workerBindingDeployBlock
}

# Default RPCs when -RpcUrl not passed.
if ([string]::IsNullOrWhiteSpace($RpcUrl)) {
    if ($ChainId -eq "84532") {
        $RpcUrl = "https://sepolia.base.org"
    } else {
        $RpcUrl = "http://127.0.0.1:8545"
    }
}

$envFile = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path $envFile)) {
    Copy-Item (Join-Path $PSScriptRoot ".env.example") $envFile
}

$keysWritten = @{
    "EPOCH_SETTLEMENT_ADDRESS" = $false
    "WORKER_BINDING_ADDRESS" = $false
    "ENROLLMENT_REGISTRY_ADDRESS" = $false
    "GOAT_COIN_ADDRESS" = $false
    "CHAIN_ID" = $false
    "RPC_URL" = $false
    "WORKER_BINDING_DEPLOY_BLOCK" = $false
}

$lines = Get-Content $envFile
$out = foreach ($line in $lines) {
    if ($line -match '^\s*EPOCH_SETTLEMENT_ADDRESS=') {
        $keysWritten["EPOCH_SETTLEMENT_ADDRESS"] = $true
        "EPOCH_SETTLEMENT_ADDRESS=$epochSettlement"
    } elseif ($line -match '^\s*WORKER_BINDING_ADDRESS=') {
        $keysWritten["WORKER_BINDING_ADDRESS"] = $true
        "WORKER_BINDING_ADDRESS=$workerBinding"
    } elseif ($line -match '^\s*ENROLLMENT_REGISTRY_ADDRESS=') {
        $keysWritten["ENROLLMENT_REGISTRY_ADDRESS"] = $true
        "ENROLLMENT_REGISTRY_ADDRESS=$enrollmentRegistry"
    } elseif ($line -match '^\s*GOAT_COIN_ADDRESS=') {
        $keysWritten["GOAT_COIN_ADDRESS"] = $true
        "GOAT_COIN_ADDRESS=$goatCoin"
    } elseif ($line -match '^\s*CHAIN_ID=') {
        $keysWritten["CHAIN_ID"] = $true
        "CHAIN_ID=$ChainId"
    } elseif ($line -match '^\s*RPC_URL=') {
        $keysWritten["RPC_URL"] = $true
        "RPC_URL=$RpcUrl"
    } elseif ($line -match '^\s*WORKER_BINDING_DEPLOY_BLOCK=') {
        $keysWritten["WORKER_BINDING_DEPLOY_BLOCK"] = $true
        if ($null -ne $deployBlock) {
            "WORKER_BINDING_DEPLOY_BLOCK=$deployBlock"
        } else {
            $line
        }
    } else {
        $line
    }
}

# Append any keys that never appeared (older .env templates).
if (-not $keysWritten["EPOCH_SETTLEMENT_ADDRESS"]) { $out += "EPOCH_SETTLEMENT_ADDRESS=$epochSettlement" }
if (-not $keysWritten["WORKER_BINDING_ADDRESS"]) { $out += "WORKER_BINDING_ADDRESS=$workerBinding" }
if (-not $keysWritten["ENROLLMENT_REGISTRY_ADDRESS"]) { $out += "ENROLLMENT_REGISTRY_ADDRESS=$enrollmentRegistry" }
if (-not $keysWritten["GOAT_COIN_ADDRESS"]) { $out += "GOAT_COIN_ADDRESS=$goatCoin" }
if (-not $keysWritten["CHAIN_ID"]) { $out += "CHAIN_ID=$ChainId" }
if (-not $keysWritten["RPC_URL"]) { $out += "RPC_URL=$RpcUrl" }
if (-not $keysWritten["WORKER_BINDING_DEPLOY_BLOCK"]) {
    if ($null -ne $deployBlock) {
        $out += "WORKER_BINDING_DEPLOY_BLOCK=$deployBlock"
    } elseif ($ChainId -eq "84532") {
        Write-Warning "workerBindingDeployBlock missing on 84532 epoch JSON - G-B1 pin not written. Re-run testnet-up.ps1 or set WORKER_BINDING_DEPLOY_BLOCK manually."
    }
}

$out | Set-Content -Encoding ascii $envFile

Write-Host "Updated .env from desktop chain $ChainId :"
Write-Host "  CHAIN_ID=$ChainId"
Write-Host "  RPC_URL=$RpcUrl"
Write-Host "  WORKER_BINDING_ADDRESS=$workerBinding"
Write-Host "  ENROLLMENT_REGISTRY_ADDRESS=$enrollmentRegistry"
Write-Host "  EPOCH_SETTLEMENT_ADDRESS=$epochSettlement"
Write-Host "  GOAT_COIN_ADDRESS=$goatCoin"
if ($null -ne $deployBlock) {
    Write-Host "  WORKER_BINDING_DEPLOY_BLOCK=$deployBlock"
} else {
    Write-Host "  WORKER_BINDING_DEPLOY_BLOCK=(not set)"
}
if ($ChainId -eq "84532") {
    Write-Host "  AUTO_WARP must stay off; AUTO_SETTLE opt-in only (Stream B B7/B8)."
}
Write-Host 'Restart the relayer: .\start-relayer.ps1'
