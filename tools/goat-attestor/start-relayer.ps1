# Start goat-attestor gasless bind/enroll relayer for local pilot.
# Requires: anvil on :8545 with Season-0 contracts matching tools/goat-attestor/.env
# Desktop defaults to http://127.0.0.1:8787 - leave this process running while testing Bind & enroll.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".\.env")) {
    Write-Error "Missing .env - copy .env.example and set addresses + RELAYER_PRIVATE_KEY"
}

# Load .env into process env (simple KEY=VALUE lines)
Get-Content ".\.env" | ForEach-Object {
    $line = $_.Trim()
    if ($line -eq "" -or $line.StartsWith("#")) { return }
    $i = $line.IndexOf("=")
    if ($i -lt 1) { return }
    $k = $line.Substring(0, $i).Trim()
    $v = $line.Substring($i + 1).Trim()
    [Environment]::SetEnvironmentVariable($k, $v, "Process")
}

$bind = $env:RELAYER_BIND
if (-not $bind) { $bind = "127.0.0.1:8787" }

Write-Host "Starting relayer on $bind (RPC=$($env:RPC_URL) chain=$($env:CHAIN_ID))"
Write-Host "WorkerBinding=$($env:WORKER_BINDING_ADDRESS)"
Write-Host "EnrollmentRegistry=$($env:ENROLLMENT_REGISTRY_ADDRESS)"
Write-Host "Press Ctrl+C to stop."

cargo run -- serve-relayer --bind $bind
