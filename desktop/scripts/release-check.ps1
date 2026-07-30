# Stream D0 — release-check wrapper (Windows).
# Fail-closed: exit 1 if version drift, null 84532 addresses, or bad bundle targets.
param(
    [switch]$StrictEnv,
    [switch]$Json,
    [switch]$RequireWix
)

$ErrorActionPreference = "Stop"
$desktop = Split-Path -Parent $PSScriptRoot
Set-Location $desktop

$nodeArgs = @("scripts/release-check.mjs")
if ($StrictEnv) { $nodeArgs += "--strict-env" }
if ($Json) { $nodeArgs += "--json" }
if ($RequireWix) { $nodeArgs += "--require-wix" }

& node @nodeArgs
exit $LASTEXITCODE
