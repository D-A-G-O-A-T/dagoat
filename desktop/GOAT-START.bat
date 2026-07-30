@echo off
REM NOTE: superseded by the split launchers at the repo root (preferred):
REM   START-EARN-SERVERS.bat  - chain + contracts + relayer + auto-earn daemon
REM   START-GOATAPP.bat       - the desktop app only
REM This all-in-one remains usable but does NOT start the relayer/auto-earn daemon.
REM Double-click this file to start GOAT the durable way (outside any agent shell).
REM Leaves two consoles open: ANVIL (if needed) and cargo tauri dev.

REM Self-locating: this file lives in <repo>\desktop, so ROOT is its parent.
REM pushd/popd normalises the trailing "\.." away, so %ROOT% stays a clean
REM absolute path and every %ROOT%\... expansion below is unchanged in shape.
pushd "%~dp0.."
set ROOT=%CD%
popd
set LOGS=%ROOT%\desktop\.run-logs

echo.
echo === GOAT local stack ===
echo.

REM Anvil if not listening. --state makes the chain SURVIVE restarts (balances, epochs,
REM binds persist in .anvil-state.json; dumped every 60s so a closed window loses <=60s).
REM To RESET the dev chain deliberately: close ANVIL, delete desktop\.anvil-state.json.
netstat -an | findstr ":8545" | findstr "LISTENING" >nul
if errorlevel 1 (
  echo Starting anvil in a new window (persistent state)...
  start "ANVIL" /D "%ROOT%" cmd /k "title ANVIL - leave open & cd /d %ROOT% & anvil --state desktop\.anvil-state.json --state-interval 60"
  echo Waiting 4s for anvil...
  timeout /t 4 /nobreak >nul
) else (
  echo anvil already listening on 8545
)

REM Deploy ONLY when the persisted chain has no contracts yet (dev-up redeploys at new
REM addresses every run, which would orphan persisted balances). Probe the recorded
REM EpochSettlement address for code; skip dev-up when it responds.
set DEPLOYED=
for /f "usebackq delims=" %%A in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\desktop\check-deployed.ps1"`) do set DEPLOYED=%%A
if "%DEPLOYED%"=="yes" (
  echo Contracts already deployed on persisted chain - skipping dev-up.
) else (
  echo Deploying contracts (dev-up)...
  cd /d %ROOT%
  powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\contracts\dev-up.ps1"
  if errorlevel 1 (
    echo dev-up FAILED
    pause
    exit /b 1
  )
)

echo Starting cargo tauri dev in a new window...
start "GOAT tauri dev" /D "%ROOT%\desktop" cmd /k "title GOAT cargo tauri dev - leave open & cd /d %ROOT%\desktop & set RUST_BACKTRACE=1 & cargo tauri dev"

echo.
echo Started. Look for window: D.A. G.O.A.T.
echo Leave open: ANVIL window + GOAT cargo tauri dev window.
echo Do NOT open Chrome to localhost.
echo.
pause
