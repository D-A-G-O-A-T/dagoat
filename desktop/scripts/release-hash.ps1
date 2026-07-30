# Stream D0 -- SHA-256 manifest (+ optional minisign) for staged installers.
param(
    [Parameter(Mandatory = $true)]
    [string]$StageDir,
    [switch]$SkipMinisign
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $StageDir)) {
    throw "StageDir not found: $StageDir"
}

$files = @(Get-ChildItem -Path $StageDir -File | Where-Object {
    $_.Extension -match '\.(exe|msi)$' -or $_.Name -match '\.(exe|msi)$'
})
if ($files.Count -eq 0) {
    # Also accept any non-sum files for hashing if installers used different names
    $files = @(Get-ChildItem -Path $StageDir -File | Where-Object {
        $_.Name -notmatch 'SHA256SUMS|INSTALL|RELEASE|\.minisig$'
    })
}
if ($files.Count -eq 0) {
    throw "No artifacts to hash in $StageDir"
}

$sumsPath = Join-Path $StageDir "SHA256SUMS.txt"
$lines = New-Object System.Collections.Generic.List[string]
foreach ($f in ($files | Sort-Object Name)) {
    $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    # GNU coreutils style: "<hash>  <filename>"
    $lines.Add("$hash  $($f.Name)")
    Write-Host "SHA256 $($f.Name) = $hash"
}
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllLines($sumsPath, $lines, $utf8NoBom)
Write-Host "Wrote $sumsPath"

if ($SkipMinisign) {
    Write-Host "minisign skipped (-SkipMinisign)"
    exit 0
}

$minisign = Get-Command minisign -ErrorAction SilentlyContinue
if (-not $minisign) {
    Write-Warning "minisign not on PATH -- SHA256SUMS.txt written without .minisig. Install minisign and re-run, or set MINISIGN_SECRET_KEY path later."
    exit 0
}

$secret = $env:MINISIGN_SECRET_KEY
if ([string]::IsNullOrWhiteSpace($secret)) {
    Write-Warning "MINISIGN_SECRET_KEY not set -- skipping signature. Generate OUTSIDE the repo: minisign -G -p `$env:USERPROFILE\.secrets\minisign.pub -s `$env:USERPROFILE\.secrets\minisign.key"
    exit 0
}
if (-not (Test-Path $secret)) {
    throw "MINISIGN_SECRET_KEY path not found: $secret"
}
# Refuse signing if the secret key lives under the desktop/ project tree (leak risk).
$desktopRoot = Split-Path -Parent $PSScriptRoot
$resolvedSecret = [System.IO.Path]::GetFullPath($secret)
$resolvedDesktop = [System.IO.Path]::GetFullPath($desktopRoot)
if ($resolvedSecret.StartsWith($resolvedDesktop, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "MINISIGN_SECRET_KEY must not live under desktop/ (got $resolvedSecret). Move it outside the repo (e.g. %USERPROFILE%\.secrets\minisign.key)."
}

$sigPath = "$sumsPath.minisig"
& minisign -S -s $secret -m $sumsPath -x $sigPath
if ($LASTEXITCODE -ne 0) { throw "minisign sign failed" }
Write-Host "Wrote $sigPath"
Write-Host "Publish minisign.pub with the release; never publish the secret key."
