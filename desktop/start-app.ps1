# Launch D.A. G.O.A.T. desktop for local pilot.
#
# The app UI is served by Vite on http://localhost:5173 (dev).
# Do NOT open Chrome yourself - use the "D.A. G.O.A.T." desktop window only.
# If you open a browser to localhost and see "refused to connect", Vite is not running.
#
# Prerequisites: anvil on :8545; after each anvil restart:
#   cd <repo root>; .\contracts\dev-up.ps1

$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot

$logDir = Join-Path $PSScriptRoot '.run-logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$exe = Join-Path $PSScriptRoot 'src-tauri\target\debug\dagoat.exe'

function Write-Status([string]$msg) {
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    Write-Host $line
    Add-Content -Path (Join-Path $logDir 'launcher.log') -Value $line -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host '=== D.A. G.O.A.T. local launcher ===' -ForegroundColor Green
Write-Host 'Uses Vite :5173 + debug dagoat.exe'
Write-Host 'Use the desktop window titled D.A. G.O.A.T. - not Chrome.'
Write-Host ''

if (-not (Get-NetTCPConnection -LocalPort 8545 -State Listen -ErrorAction SilentlyContinue)) {
    Write-Status 'WARNING: anvil not on :8545'
} else {
    Write-Status 'anvil OK'
}

# Stop previous dagoat only
Get-Process -Name dagoat -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Start vite if not already listening
$viteListen = Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue
if (-not $viteListen) {
    Write-Status 'Starting Vite on :5173 ...'
    $viteLog = Join-Path $logDir 'vite.log'
    $viteCmd = "Set-Location '$PSScriptRoot'; npm run dev 2>&1 | Tee-Object -FilePath '$viteLog'"
    Start-Process powershell -ArgumentList '-NoExit','-Command',$viteCmd -WorkingDirectory $PSScriptRoot | Out-Null
    for ($i = 0; $i -lt 45; $i++) {
        Start-Sleep -Seconds 1
        if (Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue) { break }
    }
    if (-not (Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue)) {
        Write-Status 'FATAL: Vite failed to start - see .run-logs\vite.log'
        pause
        exit 1
    }
    Write-Status 'Vite OK'
} else {
    Write-Status 'Vite already on :5173'
}

# Ensure debug binary
if (-not (Test-Path $exe)) {
    Write-Status 'Building debug dagoat.exe ...'
    Push-Location (Join-Path $PSScriptRoot 'src-tauri')
    cargo build
    Pop-Location
    if (-not (Test-Path $exe)) {
        Write-Status 'FATAL: cargo build failed'
        pause
        exit 1
    }
}

Write-Status ("Starting {0}" -f $exe)
$p = Start-Process -FilePath $exe -WorkingDirectory $PSScriptRoot -PassThru
Write-Status ("dagoat pid={0}" -f $p.Id)

Start-Sleep -Seconds 3
if (-not (Get-Process -Id $p.Id -ErrorAction SilentlyContinue)) {
    Write-Status 'FATAL: dagoat exited immediately'
    $el = Join-Path $env:LOCALAPPDATA 'com.goatcoin.dagoat\exit.log'
    if (Test-Path $el) { Get-Content $el -Tail 20 }
    pause
    exit 1
}

# Probe that UI origin is up
try {
    $r = Invoke-WebRequest -Uri 'http://localhost:5173/' -UseBasicParsing -TimeoutSec 3
    Write-Status ("Vite HTTP {0}" -f $r.StatusCode)
} catch {
    Write-Status ('WARNING: cannot fetch http://localhost:5173/ - UI will show connection refused: ' + $_.Exception.Message)
}

Write-Host ''
Write-Host 'Look for the desktop window: D.A. G.O.A.T.' -ForegroundColor Green
Write-Host 'Do NOT open Chrome to localhost - that is not the app.'
Write-Host 'Leave the Vite PowerShell window open too.'
Write-Host ''
Write-Host 'Press Enter to close this status window (app keeps running)...'
pause
