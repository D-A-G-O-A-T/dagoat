# Stream D0 -- orchestrate pilot release build (NSIS + MSI).
# Does NOT code-sign (D1 skipped). Does NOT enable updater (D2 deferred).
#
# Usage (from anywhere):
#   powershell -ExecutionPolicy Bypass -File desktop\scripts\release-build.ps1
#   powershell -ExecutionPolicy Bypass -File desktop\scripts\release-build.ps1 -SkipCheck
#   powershell -ExecutionPolicy Bypass -File desktop\scripts\release-build.ps1 -StrictEnv
#
# Prereq: B-live frozen 84532 addresses, .env.production.local filled, Stream E hostname final.

param(
    [switch]$SkipCheck,
    [switch]$StrictEnv,
    [switch]$SkipBuild,
    [switch]$SkipMinisign
)

$ErrorActionPreference = "Stop"
$desktop = Split-Path -Parent $PSScriptRoot
Set-Location $desktop

function Import-DotEnvFile([string]$Path) {
    if (-not (Test-Path $Path)) { return $false }
    Get-Content $Path | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#")) { return }
        $i = $line.IndexOf("=")
        if ($i -lt 1) { return }
        $k = $line.Substring(0, $i).Trim()
        $v = $line.Substring($i + 1).Trim()
        if (
            ($v.StartsWith('"') -and $v.EndsWith('"')) -or
            ($v.StartsWith("'") -and $v.EndsWith("'"))
        ) {
            $v = $v.Substring(1, $v.Length - 2)
        }
        # Do not print values
        Set-Item -Path "Env:$k" -Value $v
    }
    return $true
}

# WiX v3 (candle/light) required for MSI -- fall back to NSIS-only if absent.
$wixOut = (& node (Join-Path $PSScriptRoot "detect-wix.mjs") 2>$null | Out-String).Trim()
$wixAvailable = ($wixOut -eq "true")
$bundleArgs = if ($wixAvailable) { @("--bundles", "nsis,msi") } else { @("--bundles", "nsis") }

Write-Host "=== Stream D release-build ==="
Write-Host " desktop: $desktop"
Write-Host " Authenticode: no | updater: deferred | minisign: yes if available"
Write-Host " WiX: $(if ($wixAvailable) { 'found -- NSIS+MSI' } else { 'MISSING -- NSIS only (install WiX v3 for MSI)' })"
Write-Host " tauri bundles: $($bundleArgs -join ' ')"
Write-Host " NOTE: installMode=currentUser (AppData\Local). Uninstall any old Program Files build first."

if (-not $SkipCheck) {
    $checkArgs = @()
    if ($StrictEnv) { $checkArgs += "-StrictEnv" }
    & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "release-check.ps1") @checkArgs
    if ($LASTEXITCODE -ne 0) {
        throw "release-check FAILED (fail-closed). Fix 84532 freeze / versions / bundle targets before building."
    }
} else {
    Write-Warning "SkipCheck set -- not recommended for volunteer builds"
}

$envLocal = Join-Path $desktop ".env.production.local"
if (Import-DotEnvFile $envLocal) {
    Write-Host "Loaded .env.production.local into process env (values not printed)"
} else {
    Write-Warning "No .env.production.local -- lab/default VITE_* will bake into the binary"
}

$pkg = Get-Content (Join-Path $desktop "package.json") -Raw | ConvertFrom-Json
$version = $pkg.version
$stage = Join-Path $desktop "dist-release\$version"
New-Item -ItemType Directory -Force -Path $stage | Out-Null

if (-not $SkipBuild) {
    Write-Host ">>> npm install (if needed) + cargo tauri build (long)"
    if (-not (Test-Path (Join-Path $desktop "node_modules"))) {
        npm install
        if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
    }
    # Prefer npx tauri so CLI version matches package.json.
    # --bundles limits targets when WiX is absent (consultant WiX hazard).
    & npx tauri build @bundleArgs
    if ($LASTEXITCODE -ne 0) { throw "tauri build failed" }
} else {
    Write-Warning "SkipBuild -- staging whatever already exists under src-tauri/target/release/bundle"
}

$bundleRoot = Join-Path $desktop "src-tauri\target\release\bundle"
if (-not (Test-Path $bundleRoot)) {
    throw "Bundle output missing: $bundleRoot (build did not produce installers)"
}

# Copy NSIS + MSI artifacts
$copied = 0
Get-ChildItem -Path $bundleRoot -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
    $_.Extension -in @(".exe", ".msi")
} | ForEach-Object {
    $dest = Join-Path $stage $_.Name
    Copy-Item $_.FullName $dest -Force
    Write-Host "staged $($_.Name)"
    $copied++
}
if ($copied -eq 0) {
    throw "No .exe/.msi found under $bundleRoot"
}
if (-not $wixAvailable) {
    $msiCount = @(Get-ChildItem -Path $stage -Filter *.msi -ErrorAction SilentlyContinue).Count
    if ($msiCount -eq 0) {
        Write-Warning "No MSI staged (expected without WiX). Pilot can ship NSIS-only; install WiX for dual targets."
    }
}

# Docs into stage
$volDoc = Join-Path $desktop "docs\VOLUNTEER_INSTALL.md"
if (Test-Path $volDoc) {
    Copy-Item $volDoc (Join-Path $stage "VOLUNTEER_INSTALL.md") -Force
}

$hashArgs = @{ StageDir = $stage }
if ($SkipMinisign) { $hashArgs.SkipMinisign = $true }
& powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "release-hash.ps1") @hashArgs
if ($LASTEXITCODE -ne 0) { throw "release-hash failed" }

Write-Host ""
Write-Host "=== release-build complete ==="
Write-Host " version : $version"
Write-Host " stage   : $stage"
Write-Host " next    : upload to GitHub Releases (private) + paste SHA256SUMS lines in the invite"
Write-Host "           see docs/RELEASE_OPERATOR.md"
Write-Host "=============================="
