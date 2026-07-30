@echo off
REM ============================================================================
REM  START-GOATAPP.bat
REM  Launch only the D.A. G.O.A.T. desktop app (Vite + dagoat.exe).
REM  This console waits for GoatAPP to close, then exits (Vite killed if we started it).
REM  Prerequisites: run START-EARN-SERVERS.bat first (anvil + relayer for earn path).
REM  Earn-server terminals (ANVIL/RELAYER/AUTO-EARN) stay up until you close them.
REM ============================================================================
setlocal
cd /d "%~dp0desktop"

echo.
echo  Starting D.A. G.O.A.T. desktop...
echo  Use the app window — do NOT open Chrome to localhost.
echo  This window closes automatically when GoatAPP exits.
echo.

REM Quick health hints (non-fatal)
netstat -an | findstr ":8545" | findstr "LISTENING" >nul
if errorlevel 1 (
  echo  [WARN] anvil not on :8545 — Bind/balances need START-EARN-SERVERS.bat
) else (
  echo  [OK]   anvil :8545
)

netstat -an | findstr ":8787" | findstr "LISTENING" >nul
if errorlevel 1 (
  echo  [WARN] relayer not on :8787 — gasless Bind ^& enroll needs START-EARN-SERVERS.bat
) else (
  echo  [OK]   relayer :8787
)

echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0desktop\start-app.ps1"
exit /b %ERRORLEVEL%
