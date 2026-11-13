#!/usr/bin/env pwsh
# Fast deploy: build the UI once with a persistent Cargo target directory,
# sign the web container, merge the state and publish it.
#
# The slow part of `deploy-tool deploy` is `dx build --release` compiling into
# a temporary target dir on every run. This script keeps the target dir inside
# the repo so Cargo reuses compiled dependencies on the next deploy.
#
# First run is still a full build; later runs are incremental.
#
# Usage:
#   pwsh ./deploy-fast.ps1
#   pwsh ./deploy-fast.ps1 -Version 52
#   pwsh ./deploy-fast.ps1 -SkipCss

[CmdletBinding()]
param(
    # Version to sign. Defaults to the next version in the state dir.
    [int]$Version = 0,
    # Skip `npm run build:css` (only if the CSS is already up to date).
    [switch]$SkipCss,
    # Use the size-optimized release profile (slower) instead of release-fast.
    [switch]$Production,
    [string]$StateDir = (Join-Path $env:APPDATA 'freetalk'),
    [string]$TargetDir = (Join-Path $PSScriptRoot 'target\dx-fast')
)

$ErrorActionPreference = 'Stop'
$repoRoot = $PSScriptRoot

function Find-Tool {
    param(
        [string]$Name,
        [string[]]$Candidates
    )
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return (Resolve-Path $candidate).Path
        }
    }
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    return $null
}

# PowerShell can treat an extensionless binary as a document. Copy it to a
# .exe so the call is a native executable.
function Ensure-Exe {
    param([string]$Path, [string]$Name)
    if (-not $Path) { return $Path }
    if ($Path -match '\.exe$') { return $Path }
    $copy = Join-Path $env:TEMP "$Name-fast-deploy.exe"
    Copy-Item $Path $copy -Force
    return $copy
}

# dx and fdev live outside PATH on this machine.
$dx = Find-Tool -Name 'dx' -Candidates @(
    (Join-Path $env:USERPROFILE 'code\freenet\bin\dx'),
    (Join-Path $env:USERPROFILE '.cargo\bin\dx.exe')
)
$fdev = Find-Tool -Name 'fdev' -Candidates @(
    (Join-Path $env:LOCALAPPDATA 'freenet\bin\fdev.exe'),
    (Join-Path $env:USERPROFILE '.cargo\bin\fdev.exe'),
    (Join-Path $env:USERPROFILE 'code\freenet\bin\fdev')
)
$webContainerTool = Find-Tool -Name 'web-container-tool' -Candidates @(
    (Join-Path $env:TEMP 'web-container-tool.exe'),
    (Join-Path $repoRoot '..\freenet-shared\web-container-tool\target\release\web-container-tool.exe'),
    (Join-Path $repoRoot '..\freenet-shared\web-container-tool\target\debug\web-container-tool.exe')
)
$npm = Find-Tool -Name 'npm' -Candidates @(
    (Join-Path $env:ProgramFiles 'nodejs\npm.cmd'),
    (Join-Path $env:USERPROFILE 'AppData\Roaming\npm\npm.cmd')
)

if (-not $dx) { throw "dx not found. Install dioxus-cli." }
if (-not $fdev) { throw "fdev not found. Install it or run deploy-tool deploy once." }
if (-not $webContainerTool) {
    throw "web-container-tool not found. Run deploy-tool deploy once (it extracts the tool to %TEMP%), or build it from freenet-shared."
}
$dx = Ensure-Exe -Path $dx -Name 'dx'
$fdev = Ensure-Exe -Path $fdev -Name 'fdev'
$webContainerTool = Ensure-Exe -Path $webContainerTool -Name 'web-container-tool'

# The signed bundle is published at a path derived from the live contract id.
$contractWasm = Join-Path $StateDir 'web.contract.wasm'
$parameters = Join-Path $StateDir 'webapp.parameters'
$metadata = Join-Path $StateDir 'webapp.metadata'
$archive = Join-Path $StateDir 'webapp.bootstrap.tar.xz'
$state = Join-Path $StateDir 'webapp.state'
$versionFile = Join-Path $StateDir 'version'

foreach ($file in @($contractWasm, $parameters)) {
    if (-not (Test-Path $file)) {
        throw "Missing $file. Run deploy-tool initial-web-deploy first."
    }
}

$projectId = 'freetalk'
$deployToml = Join-Path $repoRoot 'deploy.toml'
if (Test-Path $deployToml) {
    $match = Select-String -Path $deployToml -Pattern '^\s*id\s*=\s*"([^"]+)"' |
        Select-Object -First 1
    if ($match) { $projectId = $match.Matches[0].Groups[1].Value }
}

$savedVersion = 0
if (Test-Path $versionFile) {
    $savedVersion = [int]((Get-Content $versionFile -Raw).Trim())
}
$chosenVersion = [Math]::Max($savedVersion, $Version)
if ($chosenVersion -le 0) {
    throw "Version file is missing or invalid. Pass -Version."
}

$contractId = (& $fdev get-contract-id --code $contractWasm --parameters $parameters).Trim()
if (-not $contractId) {
    throw "fdev get-contract-id returned an empty contract id."
}

Write-Host "Deploying version $chosenVersion to $contractId"
Write-Host "  target dir: $TargetDir"

# Fast CSS rebuild. It is cheap and keeps styles.css in sync with the source.
if (-not $SkipCss) {
    if (-not $npm) { throw "npm not found. Pass -SkipCss if the CSS is already built." }
    Write-Host "Building CSS..."
    & $npm --prefix (Join-Path $repoRoot 'ui') run build:css
    if ($LASTEXITCODE -ne 0) { throw "npm run build:css failed." }
}

New-Item -ItemType Directory -Force $TargetDir | Out-Null
$env:CARGO_TARGET_DIR = $TargetDir

$buildProfile = if ($Production) { "release" } else { "release-fast" }
Write-Host "Building UI with profile $buildProfile (first run is a full build, later runs are incremental)..."
$buildTimer = [System.Diagnostics.Stopwatch]::StartNew()
# DWARF debug info is on by default in dx and roughly doubles the wasm. The
# published bundle does not need it.
if ($Production) {
    & $dx build --package plaza-ui --base-path "/v1/contract/web/$contractId/" --release --debug-symbols false
} else {
    & $dx build --package plaza-ui --base-path "/v1/contract/web/$contractId/" --profile release-fast --debug-symbols false
}
if ($LASTEXITCODE -ne 0) { throw "dx build failed." }
$buildTimer.Stop()
Write-Host ("Build finished in {0:n1}s" -f $buildTimer.Elapsed.TotalSeconds)

# dx writes <target>/dx/plaza-ui/release/web/public.
$publicDir = Get-ChildItem $TargetDir -Recurse -Directory -Filter 'public' -ErrorAction SilentlyContinue |
    Where-Object { Test-Path (Join-Path $_.FullName 'index.html') } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if (-not $publicDir) {
    throw "Could not find the built public directory under $TargetDir."
}
Write-Host "Bundle: $($publicDir.FullName)"

# dx leaves the hashed JS/wasm of every earlier build in assets/. Remove the
# ones index.html does not load: the archive would otherwise carry dozens of
# multi-megabyte wasm files.
$assetsDir = Join-Path $publicDir.FullName 'assets'
$indexHtml = Get-Content (Join-Path $publicDir.FullName 'index.html') -Raw
$currentJs = [regex]::Match($indexHtml, 'assets/(plaza-ui-[A-Za-z0-9]+\.js)').Groups[1].Value
if ($currentJs) {
    $currentJsPath = Join-Path $assetsDir $currentJs
    $jsText = Get-Content $currentJsPath -Raw
    $currentWasm = [regex]::Match($jsText, 'plaza-ui_bg-[A-Za-z0-9]+\.wasm').Value
    $stale = Get-ChildItem $assetsDir -File | Where-Object {
        ($_.Name -like 'plaza-ui-*.js' -and $_.Name -ne $currentJs) -or
        ($_.Name -like 'plaza-ui_bg-*.wasm' -and $_.Name -ne $currentWasm)
    }
    if ($stale) {
        $freed = ($stale | Measure-Object Length -Sum).Sum
        $stale | Remove-Item -Force
        Write-Host ("Removed {0} stale bundle files ({1:n0} MB)." -f $stale.Count, ($freed / 1MB))
    }
}

# Build the tar.xz exactly like deploy-tool: entries relative to public, no ./.
$items = Get-ChildItem $publicDir.FullName -Force | Select-Object -ExpandProperty Name
if (-not $items) { throw "The public directory is empty." }
if (Test-Path $archive) { Remove-Item $archive -Force }
& tar -cJf $archive -C $publicDir.FullName @items
if ($LASTEXITCODE -ne 0) { throw "tar failed to create $archive." }

Write-Host "Signing web container..."
$env:PROJECT_ID = $projectId
& $webContainerTool sign --input $archive --output $metadata --parameters $parameters --version $chosenVersion
if ($LASTEXITCODE -ne 0) { throw "web-container-tool sign failed." }

# webapp.state = u64be(metadata len) + metadata + u64be(archive len) + archive.
$metadataBytes = [IO.File]::ReadAllBytes($metadata)
$archiveBytes = [IO.File]::ReadAllBytes($archive)
$stream = New-Object System.IO.MemoryStream
$writer = New-Object System.IO.BinaryWriter($stream)
$writer.Write([uint64]$metadataBytes.Length) # BinaryWriter is little-endian
$writer.Flush()
$buffer = $stream.ToArray()
[Array]::Reverse($buffer) # only the 8-byte length so far
$stream.SetLength(0)
$stream.Position = 0
$stream.Write($buffer, 0, $buffer.Length)
$stream.Write($metadataBytes, 0, $metadataBytes.Length)

$archiveLength = New-Object System.IO.MemoryStream
$lengthWriter = New-Object System.IO.BinaryWriter($archiveLength)
$lengthWriter.Write([uint64]$archiveBytes.Length)
$lengthWriter.Flush()
$lengthBytes = $archiveLength.ToArray()
[Array]::Reverse($lengthBytes)
$stream.Write($lengthBytes, 0, $lengthBytes.Length)
$stream.Write($archiveBytes, 0, $archiveBytes.Length)
[IO.File]::WriteAllBytes($state, $stream.ToArray())
$writer.Dispose()
$stream.Dispose()

# Match deploy-tool: reserve the version even if the publish below fails.
Set-Content -Path $versionFile -Value ($chosenVersion + 1)

Write-Host "Publishing..."
& (Join-Path $repoRoot 'publish-only.ps1') -StateDir $StateDir -Fdev $fdev
if ($LASTEXITCODE -ne 0) { throw "publish-only failed." }

Write-Host "Deployed version $chosenVersion."
