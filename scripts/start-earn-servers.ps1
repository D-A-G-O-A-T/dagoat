# START EARN SERVERS - local testnet dependencies for GOAT pilot earnings.
#
# Brings up (or verifies) everything the desktop needs before Bind/enroll and fold->mint:
#   1) anvil (chain 31337) on :8545
#   2) Season-0 contracts (dev-up) if chain has no deployment code
#   3) goat-attestor .env synced from desktop deployment JSONs
#   4) gasless bind/enroll relayer on :8787
#   5) attestor daemon (auto-earn: propose -> warp -> settle -> claim)
#
# Leaves long-running processes in separate titled console windows.
# Double-click: START-EARN-SERVERS.bat  (repo root)

$ErrorActionPreference = "Stop"
$env:PATH = "$env:USERPROFILE\.foundry\bin;$env:PATH"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Contracts = Join-Path $Root "contracts"
$Attestor = Join-Path $Root "tools\goat-attestor"
$DesktopDeploy = Join-Path $Root "desktop\src\chain\deployments\31337.json"
$EpochDeploy = Join-Path $Root "desktop\src\chain\deployments\31337.epoch.json"
$LogDir = Join-Path $Root "desktop\.run-logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogFile = Join-Path $LogDir "earn-servers.log"

function Write-Log {
    param([string]$msg, [string]$color = "White")
    $line = "[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $msg
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Test-PortListen {
    param([int]$port)
    return [bool](Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
}

function Test-AnvilRpc {
    try {
        $body = '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:8545" -Method Post -Body $body `
            -ContentType "application/json" -TimeoutSec 3
        if (-not $r.result) { return $false }
        # Prefer chain 31337 (0x7a69); still report up if any anvil answers so we do not double-start.
        return $true
    } catch {
        return $false
    }
}

function Test-AnvilChainIdOk {
    try {
        $body = '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:8545" -Method Post -Body $body `
            -ContentType "application/json" -TimeoutSec 3
        return ($r.result -eq "0x7a69" -or $r.result -eq "0x7A69")
    } catch {
        return $false
    }
}

function Test-ContractsLive {
    if (-not (Test-Path $DesktopDeploy)) { return $false }
    try {
        $d = Get-Content $DesktopDeploy -Raw | ConvertFrom-Json
        $addr = $d.enrollmentRegistry
        if (-not $addr) { return $false }
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $code = & cast code $addr --rpc-url "http://127.0.0.1:8545" 2>$null
        } finally {
            $ErrorActionPreference = $prev
        }
        if ($LASTEXITCODE -ne 0) { return $false }
        $code = ("$code").Trim()
        return ($code -and $code -ne "0x" -and $code.Length -gt 4)
    } catch {
        return $false
    }
}

function Test-RelayerUp {
    if (-not (Test-PortListen 8787)) { return $false }
    try {
        $null = Invoke-WebRequest -Uri "http://127.0.0.1:8787/" -UseBasicParsing -TimeoutSec 2
        return $true
    } catch {
        if ($_.Exception.Response) { return $true }
        return $true
    }
}

function Test-DaemonRunning {
    $procs = Get-CimInstance Win32_Process -Filter "Name = 'goat-attestor.exe'" -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        if ($p.CommandLine -match "daemon") { return $true }
    }
    $w = Get-Process | Where-Object { $_.MainWindowTitle -match "GOAT-AUTO-EARN" } -ErrorAction SilentlyContinue
    return [bool]$w
}

function Start-TitledCmd {
    param([string]$title, [string]$workDir, [string]$command)
    $cmd = "title $title & cd /d `"$workDir`" & $command"
    Start-Process -FilePath "cmd.exe" -ArgumentList "/k", $cmd -WorkingDirectory $workDir | Out-Null
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  GOAT earn servers (local testnet)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Repo: $Root"
Write-Host " Log:  $LogFile"
Write-Host ""

$needDeploy = $false

# ---- 1) anvil ---------------------------------------------------------------
if (Test-AnvilRpc) {
    if (Test-AnvilChainIdOk) {
        Write-Log "anvil OK (:8545, chain 31337)" "Green"
    } else {
        Write-Log "anvil OK on :8545 but chainId is not 31337 - desktop expects Local anvil (31337)" "Yellow"
    }
} else {
    # --state makes the chain SURVIVE restarts (balances, epochs, binds persist;
    # dumped every 60s). To RESET deliberately: close GOAT-ANVIL, delete
    # desktop\.anvil-state.json, re-run this script.
    $stateFile = Join-Path $Root "desktop\.anvil-state.json"
    Write-Log "Starting anvil (chain-id 31337, persistent state)..." "Yellow"
    Start-TitledCmd "GOAT-ANVIL" $Root "anvil --chain-id 31337 --port 8545 --state `"$stateFile`" --state-interval 60"
    $up = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 500
        if (Test-AnvilRpc) { $up = $true; break }
    }
    if (-not $up) {
        Write-Log "FATAL: anvil did not answer on http://127.0.0.1:8545" "Red"
        pause
        exit 1
    }
    Write-Log "anvil started" "Green"
    $needDeploy = $true
}

# ---- 2) contracts -----------------------------------------------------------
if (-not $needDeploy) {
    $needDeploy = -not (Test-ContractsLive)
}

if ($needDeploy) {
    Write-Log "Deploying Season-0 contracts (dev-up.ps1)..." "Yellow"
    Push-Location $Contracts
    try {
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Contracts "dev-up.ps1")
        if ($LASTEXITCODE -ne 0) { throw "dev-up.ps1 exit $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
    if (-not (Test-ContractsLive)) {
        Write-Log "FATAL: contracts still not live after dev-up" "Red"
        pause
        exit 1
    }
    Write-Log "contracts deployed + desktop JSONs refreshed" "Green"
} else {
    Write-Log "contracts already live on anvil (skip redeploy; keeps binds)" "Green"
}

# ---- 3) sync attestor env ---------------------------------------------------
Write-Log "Syncing goat-attestor .env from desktop deployments..." "Yellow"
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Attestor "sync-env-from-desktop.ps1")
if ($LASTEXITCODE -ne 0) {
    Write-Log "FATAL: sync-env-from-desktop.ps1 failed" "Red"
    pause
    exit 1
}
Write-Log "attestor .env synced" "Green"

# ---- 4) relayer -------------------------------------------------------------
if (Test-RelayerUp) {
    Write-Log "relayer already OK (:8787)" "Green"
} else {
    Write-Log "Starting gasless relayer on :8787..." "Yellow"
    $relayerCmd = "powershell -NoProfile -ExecutionPolicy Bypass -File `".\start-relayer.ps1`""
    Start-TitledCmd "GOAT-RELAYER" $Attestor $relayerCmd
    $ok = $false
    for ($i = 0; $i -lt 90; $i++) {
        Start-Sleep -Seconds 1
        if (Test-RelayerUp) { $ok = $true; break }
        if (($i % 10) -eq 9) {
            $sec = $i + 1
            Write-Log "  waiting for relayer compile/start... (${sec}s)" "DarkGray"
        }
    }
    if (-not $ok) {
        Write-Log "FATAL: relayer not healthy on :8787 - check GOAT-RELAYER window" "Red"
        pause
        exit 1
    }
    Write-Log "relayer healthy (:8787)" "Green"
}

# ---- 5) auto-earn daemon ----------------------------------------------------
if (Test-DaemonRunning) {
    Write-Log "auto-earn daemon already running" "Green"
} else {
    Write-Log "Starting auto-earn daemon (propose/settle/claim loop)..." "Yellow"
    $daemonPs1 = Join-Path $LogDir "run-auto-earn-daemon.ps1"
    $daemonBody = @"
`$ErrorActionPreference = 'Stop'
Set-Location '$Attestor'
Get-Content '.\.env' | ForEach-Object {
  `$line = `$_.Trim()
  if (`$line -eq '' -or `$line.StartsWith('#')) { return }
  `$i = `$line.IndexOf('=')
  if (`$i -lt 1) { return }
  [Environment]::SetEnvironmentVariable(`$line.Substring(0, `$i).Trim(), `$line.Substring(`$i + 1).Trim(), 'Process')
}
Write-Host 'auto-earn daemon - leave this window open'
Write-Host ('RPC=' + `$env:RPC_URL + ' EPOCH=' + `$env:EPOCH_SETTLEMENT_ADDRESS)
cargo run -- daemon --interval 120
"@
    Set-Content -Path $daemonPs1 -Value $daemonBody -Encoding UTF8
    Start-TitledCmd "GOAT-AUTO-EARN" $Attestor "powershell -NoProfile -ExecutionPolicy Bypass -File `"$daemonPs1`""
    Start-Sleep -Seconds 3
    Write-Log "auto-earn daemon window launched (first cargo build may take a minute)" "Green"
}

# ---- health report ----------------------------------------------------------
Write-Host ""
Write-Host "-------- HEALTH CHECK --------" -ForegroundColor Cyan
$checks = @(
    @{ Name = "anvil RPC :8545 (31337)"; Ok = (Test-AnvilRpc) }
    @{ Name = "contracts (EnrollmentRegistry code)"; Ok = (Test-ContractsLive) }
    @{ Name = "relayer :8787 (gasless bind/enroll)"; Ok = (Test-RelayerUp) }
    @{ Name = "attestor .env present"; Ok = (Test-Path (Join-Path $Attestor ".env")) }
    @{ Name = "desktop 31337.json"; Ok = (Test-Path $DesktopDeploy) }
    @{ Name = "desktop 31337.epoch.json"; Ok = (Test-Path $EpochDeploy) }
)

$failed = 0
foreach ($c in $checks) {
    if ($c.Ok) {
        Write-Host ("  [OK]   {0}" -f $c.Name) -ForegroundColor Green
        Write-Log ("OK  " + $c.Name)
    } else {
        Write-Host ("  [FAIL] {0}" -f $c.Name) -ForegroundColor Red
        Write-Log ("FAIL " + $c.Name)
        $failed++
    }
}

if (Test-Path $DesktopDeploy) {
    $d = Get-Content $DesktopDeploy -Raw | ConvertFrom-Json
    Write-Host ""
    Write-Host "  EnrollmentRegistry: $($d.enrollmentRegistry)"
    Write-Host "  GoatCoin:           $($d.goatCoin)"
}
if (Test-Path $EpochDeploy) {
    $e = Get-Content $EpochDeploy -Raw | ConvertFrom-Json
    Write-Host "  WorkerBinding:      $($e.workerBinding)"
    Write-Host "  EpochSettlement:    $($e.epochSettlement)"
}

Write-Host ""
if ($failed -gt 0) {
    Write-Host "RESULT: $failed check(s) failed - fix the red lines above." -ForegroundColor Red
    Write-Host "Log: $LogFile"
    pause
    exit 1
}

Write-Host "RESULT: all earn-server dependencies healthy." -ForegroundColor Green
Write-Host ""
Write-Host "Leave open:" -ForegroundColor Yellow
Write-Host "  GOAT-ANVIL       local chain"
Write-Host "  GOAT-RELAYER     gasless Bind and enroll"
Write-Host "  GOAT-AUTO-EARN   propose / settle / claim loop"
Write-Host ""
Write-Host "Next: double-click START-GOATAPP.bat" -ForegroundColor Cyan
Write-Host "In app: unlock wallet -> Contribute -> Start contributing -> Bind and enroll if needed."
Write-Host "Note: first successful claim is baseline (0 GOAT mint); later score deltas mint GOAT."
Write-Host ""
Write-Host "Press Enter to close this status window (servers keep running)..."
pause
exit 0
