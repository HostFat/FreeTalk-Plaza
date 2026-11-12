#!/usr/bin/env pwsh
# Publish the already-signed web container without rebuilding the UI.
#
# `deploy-tool deploy` runs `dx build --release` (Rust -> WASM, wasm-bindgen),
# signs the bundle, then calls `fdev publish`. When the build is already done,
# this script skips the first two steps and only sends the state.
#
# It refuses to guess: if the signed artifacts are missing, run deploy-tool.

[CmdletBinding()]
param(
    # Directory with web.contract.wasm, webapp.parameters, webapp.state.
    [string]$StateDir = (Join-Path $env:APPDATA 'freetalk'),
    # Optional explicit path to fdev(.exe).
    [string]$Fdev
)

$ErrorActionPreference = 'Stop'
$repoRoot = $PSScriptRoot

function Find-Fdev {
    param([string]$Explicit)

    if ($Explicit) {
        if (-not (Test-Path $Explicit)) {
            throw "fdev not found at $Explicit"
        }
        return $Explicit
    }

    $candidates = @(
        (Get-Command fdev -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        (Join-Path $env:LOCALAPPDATA 'freenet\bin\fdev.exe'),
        (Join-Path $env:USERPROFILE '.cargo\bin\fdev.exe'),
        (Join-Path $env:USERPROFILE '.cargo\bin\fdev')
    ) | Where-Object { $_ -and (Test-Path $_) }

    if (-not $candidates) {
        throw "fdev not found. Install it or pass -Fdev <path>."
    }

    $path = $candidates | Select-Object -First 1

    # PowerShell can treat an extensionless binary as a document. Copy it to a
    # .exe so Start-Process sees a native executable.
    if ($path -notmatch '\.exe$') {
        $copy = Join-Path $env:TEMP 'fdev-publish-only.exe'
        Copy-Item $path $copy -Force
        return $copy
    }
    return $path
}

$code = Join-Path $StateDir 'web.contract.wasm'
$parameters = Join-Path $StateDir 'webapp.parameters'
$state = Join-Path $StateDir 'webapp.state'
$metadata = Join-Path $StateDir 'webapp.metadata'

foreach ($file in @($code, $parameters, $state)) {
    if (-not (Test-Path $file)) {
        throw "Missing $file. Run ``deploy-tool deploy`` first."
    }
}

$fdevPath = Find-Fdev -Explicit $Fdev

Write-Host "Publishing signed bundle from $StateDir"
if (Test-Path $metadata) {
    $meta = Get-Item $metadata
    Write-Host ("  build signed: {0}" -f $meta.LastWriteTime)
}

# Warn when sources changed after the last build: publish-only would send the
# previous UI. This is a warning, not a failure, because CSS-only rebuilds and
# deliberate re-publishes are valid.
$sourceRoots = @('ui', 'common', 'plaza-contract', 'plaza-delegate') |
    ForEach-Object { Join-Path $repoRoot $_ } |
    Where-Object { Test-Path $_ }

$newestSource = $sourceRoots |
    ForEach-Object {
        Get-ChildItem $_ -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.FullName -notmatch '[\\/](node_modules|target|dist|\.git)[\\/]'
            }
    } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($newestSource -and (Test-Path $metadata)) {
    $meta = Get-Item $metadata
    if ($newestSource.LastWriteTime -gt $meta.LastWriteTime.AddSeconds(2)) {
        Write-Warning (("Sources changed after the last build ({0}: {1}). " +
            "Run ``deploy-tool deploy`` instead.") -f `
            $newestSource.FullName, $newestSource.LastWriteTime)
    }
}

$arguments = @(
    'publish',
    '--code', $code,
    '--parameters', $parameters,
    'contract',
    '--state', $state
)

Write-Host "Running: $fdevPath $($arguments -join ' ')"
& $fdevPath @arguments
if ($LASTEXITCODE -ne 0) {
    throw "fdev publish failed with exit code $LASTEXITCODE"
}
