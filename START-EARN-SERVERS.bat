@echo off
REM ============================================================================
REM  START-EARN-SERVERS.bat
REM  Local testnet stack for earning GOAT (anvil + contracts + relayer + auto-earn).
REM  Double-click this first. Leave the opened console windows running.
REM ============================================================================
setlocal
cd /d "%~dp0"

echo.
echo  GOAT earn servers — starting...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start-earn-servers.ps1"
set ERR=%ERRORLEVEL%

if not %ERR%==0 (
  echo.
  echo  FAILED with exit code %ERR%
  pause
  exit /b %ERR%
)

exit /b 0
