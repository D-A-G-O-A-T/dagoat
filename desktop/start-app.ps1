# Launch D.A. G.O.A.T. desktop for local pilot.
#
# Starts Vite (hidden — no extra terminal) + debug dagoat.exe, then waits until
# the app closes and tears down everything this launcher started.
# Do NOT open Chrome yourself - use the "D.A. G.O.A.T." desktop window only.
#
# Prerequisites: run START-EARN-SERVERS.bat first (persistent anvil + contracts +
# relayer + auto-earn daemon). Earn-server windows are intentionally left running
# (shared infra); only GoatAPP-related processes are closed here.

$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot

$logDir = Join-Path $PSScriptRoot '.run-logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$exe = Join-Path $PSScriptRoot 'src-tauri\target\debug\dagoat.exe'
$pidFile = Join-Path $logDir 'goatapp-session.pids'

function Write-Status([string]$msg) {
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    Write-Host $line
    Add-Content -Path (Join-Path $logDir 'launcher.log') -Value $line -ErrorAction SilentlyContinue
}

function Stop-ProcessTree([int]$ProcessId) {
    if ($ProcessId -le 0) { return }
    try {
        Get-CimInstance Win32_Process -Filter "ParentProcessId = $ProcessId" -ErrorAction SilentlyContinue |
            ForEach-Object { Stop-ProcessTree ([int]$_.ProcessId) }
    } catch { }
    Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
}

function Stop-ListenersOnPort([int]$Port) {
    $conns = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
        if ($c.OwningProcess) {
            Write-Status ("Stopping process on :{0} (pid {1})" -f $Port, $c.OwningProcess)
            Stop-ProcessTree ([int]$c.OwningProcess)
        }
    }
}

Write-Host ''
Write-Host '=== D.A. G.O.A.T. local launcher ===' -ForegroundColor Green
Write-Host 'Vite :5173 (hidden) + debug dagoat.exe'
Write-Host 'This window closes when GoatAPP exits.'
Write-Host ''

if (-not (Get-NetTCPConnection -LocalPort 8545 -State Listen -ErrorAction SilentlyContinue)) {
    Write-Status 'WARNING: anvil not on :8545 — run START-EARN-SERVERS.bat for earn path'
} else {
    Write-Status 'anvil OK'
}

# Stop previous dagoat only
Get-Process -Name dagoat -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$viteStartedByUs = $false
$viteProc = $null

# Start vite if not already listening — HIDDEN (no extra terminal window)
$viteListen = Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue
if (-not $viteListen) {
    Write-Status 'Starting Vite on :5173 (hidden window)...'
    $viteLog = Join-Path $logDir 'vite.log'
    # cmd /c so we get a single process tree we can kill; no -NoExit console left behind
    $viteArgs = "/c `"cd /d `"$PSScriptRoot`" && npm run dev > `"$viteLog`" 2>&1`""
    $viteProc = Start-Process -FilePath "cmd.exe" -ArgumentList $viteArgs `
        -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru
    $viteStartedByUs = $true
    for ($i = 0; $i -lt 45; $i++) {
        Start-Sleep -Seconds 1
        if (Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue) { break }
    }
    if (-not (Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue)) {
        Write-Status 'FATAL: Vite failed to start - see .run-logs\vite.log'
        if ($viteProc) { Stop-ProcessTree $viteProc.Id }
        pause
        exit 1
    }
    Write-Status ("Vite OK (launcher pid {0})" -f $viteProc.Id)
} else {
    Write-Status 'Vite already on :5173 (will not stop it on app close)'
}

# RC.EXE, before cargo runs, because tauri-winres needs the Windows Resource
# Compiler and CANNOT FIND IT ON THIS MACHINE without help. Its lookup order is
# the $RC / $RC_<target> env vars, then PATH, then the Windows SDK registry key
# (HKLM ...\Windows Kits\Installed Roots). Measured 2026-07-30: that registry key
# is ABSENT here (the SDK lives under a non-standard root on D:), rc.exe is not
# on PATH, and the build dies with "Are you sure you have RC.EXE in your $PATH".
# It is a BUILD-SCRIPT dependency, so a cached build can hide it for weeks --
# dagoat.exe built fine on 7/21 and failed on 7/29 after a dependency bump forced
# the build script to re-run. Locate rc.exe and prepend it for THIS process only;
# nothing global is touched.
if (-not (Get-Command rc.exe -ErrorAction SilentlyContinue)) {
    $rcDirs = @()
    foreach ($kitRoot in @("D:\Program Files (x86)\Windows Kits\10\bin",
                           "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
                           "${env:ProgramFiles}\Windows Kits\10\bin")) {
        if (Test-Path $kitRoot) {
            # Highest SDK version first, x64 only (the build host is x64).
            Get-ChildItem $kitRoot -Directory -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending | ForEach-Object {
                    $cand = Join-Path $_.FullName 'x64'
                    if (Test-Path (Join-Path $cand 'rc.exe')) { $rcDirs += $cand }
                }
        }
    }
    if ($rcDirs.Count -gt 0) {
        $env:PATH = "$($rcDirs[0]);$env:PATH"
        Write-Status ("rc.exe not on PATH; using {0}" -f (Join-Path $rcDirs[0] 'rc.exe'))
    } else {
        Write-Status 'FATAL: rc.exe not found on PATH or under any Windows Kits root.'
        Write-Status 'Install the Windows 10/11 SDK (any recent version), or set $env:RC to the full path of rc.exe.'
        if ($viteStartedByUs -and $viteProc) { Stop-ProcessTree $viteProc.Id }
        pause
        exit 1
    }
}

# ALWAYS rebuild (incremental - fast when nothing changed). Running a stale exe is
# worse than a short wait: the JS frontend calls Tauri commands that only exist in
# the current Rust (e.g. backend_finish, wallet_reveal_key) and breaks against old builds.
Write-Status 'Building debug dagoat.exe (incremental)...'
Push-Location (Join-Path $PSScriptRoot 'src-tauri')
cargo build
$buildExit = $LASTEXITCODE
Pop-Location
if ($buildExit -ne 0 -or -not (Test-Path $exe)) {
    Write-Status 'FATAL: cargo build failed'
    if ($viteStartedByUs -and $viteProc) { Stop-ProcessTree $viteProc.Id }
    pause
    exit 1
}

Write-Status ("Starting {0}" -f $exe)
$p = Start-Process -FilePath $exe -WorkingDirectory $PSScriptRoot -PassThru
Write-Status ("dagoat pid={0}" -f $p.Id)

Start-Sleep -Seconds 3
if (-not (Get-Process -Id $p.Id -ErrorAction SilentlyContinue)) {
    Write-Status 'FATAL: dagoat exited immediately'
    $el = Join-Path $env:LOCALAPPDATA 'com.goatcoin.dagoat\exit.log'
    if (Test-Path $el) { Get-Content $el -Tail 20 }
    if ($viteStartedByUs -and $viteProc) { Stop-ProcessTree $viteProc.Id }
    pause
    exit 1
}

# Probe that UI origin is up
try {
    $r = Invoke-WebRequest -Uri 'http://localhost:5173/' -UseBasicParsing -TimeoutSec 3
    Write-Status ("Vite HTTP {0}" -f $r.StatusCode)
} catch {
    Write-Status ('WARNING: cannot fetch http://localhost:5173/ - UI may show connection refused: ' + $_.Exception.Message)
}

# Record session pids for debugging / emergency cleanup
@(
    "dagoat=$($p.Id)"
    "viteStartedByUs=$viteStartedByUs"
    if ($viteProc) { "viteCmd=$($viteProc.Id)" }
) | Set-Content -Path $pidFile -Encoding ascii

Write-Host ''
Write-Host 'Look for the desktop window: D.A. G.O.A.T.' -ForegroundColor Green
Write-Host 'Do NOT open Chrome to localhost - that is not the app.'
Write-Host 'Waiting for GoatAPP to close (this terminal auto-closes after)...' -ForegroundColor Yellow
Write-Host ''

# Block until the app exits (user closes the D.A. G.O.A.T. window).
try {
    Wait-Process -Id $p.Id -ErrorAction SilentlyContinue
} catch { }

Write-Status 'GoatAPP closed — cleaning up launcher processes...'

# Only stop Vite if this launcher started it (don't kill a shared/dev Vite).
if ($viteStartedByUs) {
    if ($viteProc -and -not $viteProc.HasExited) {
        Stop-ProcessTree $viteProc.Id
    }
    # Ensure :5173 is free (npm/node child may outlive the cmd wrapper)
    Stop-ListenersOnPort 5173
    Write-Status 'Vite stopped'
}

# Extra safety: no stray dagoat left
Get-Process -Name dagoat -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Remove-Item -Path $pidFile -Force -ErrorAction SilentlyContinue
Write-Status 'Cleanup done — exiting launcher'
Start-Sleep -Milliseconds 400
exit 0
