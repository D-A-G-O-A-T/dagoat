# Sync goat-attestor .env contract addresses from desktop deployment JSONs.
# Run after contracts/dev-up.ps1 so gasless bind hits the same contracts as the app.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$epochPath = Join-Path $PSScriptRoot "..\..\desktop\src\chain\deployments\31337.epoch.json"
$basePath = Join-Path $PSScriptRoot "..\..\desktop\src\chain\deployments\31337.json"
if (-not (Test-Path $epochPath)) { Write-Error "Missing $epochPath" }
if (-not (Test-Path $basePath)) { Write-Error "Missing $basePath" }

$epoch = Get-Content $epochPath -Raw | ConvertFrom-Json
$base = Get-Content $basePath -Raw | ConvertFrom-Json

$envFile = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path $envFile)) {
    Copy-Item (Join-Path $PSScriptRoot ".env.example") $envFile
}

$lines = Get-Content $envFile
$out = foreach ($line in $lines) {
    if ($line -match '^\s*EPOCH_SETTLEMENT_ADDRESS=') {
        "EPOCH_SETTLEMENT_ADDRESS=$($epoch.epochSettlement)"
    } elseif ($line -match '^\s*WORKER_BINDING_ADDRESS=') {
        "WORKER_BINDING_ADDRESS=$($epoch.workerBinding)"
    } elseif ($line -match '^\s*ENROLLMENT_REGISTRY_ADDRESS=') {
        "ENROLLMENT_REGISTRY_ADDRESS=$($base.enrollmentRegistry)"
    } else {
        $line
    }
}
$out | Set-Content -Encoding ascii $envFile

Write-Host "Updated .env:"
Write-Host "  WORKER_BINDING_ADDRESS=$($epoch.workerBinding)"
Write-Host "  ENROLLMENT_REGISTRY_ADDRESS=$($base.enrollmentRegistry)"
Write-Host "  EPOCH_SETTLEMENT_ADDRESS=$($epoch.epochSettlement)"
Write-Host "Restart the relayer: .\\start-relayer.ps1"
