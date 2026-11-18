# Two-node smoke test for a Freenet web app.
#
# Starts two isolated nodes with fresh data directories, publishes the signed
# bundle to both and checks that each serves the app. It does not drive a
# browser: after it passes, open the app on both ports and exercise the UI.
#
# Usage:
#   pwsh ./tests/two-node-e2e.ps1
#   pwsh ./tests/two-node-e2e.ps1 -Cleanup
#   pwsh ./tests/two-node-e2e.ps1 -SkipStart   # reuse running nodes

param(
    [int]$NodeA = 7510,
    [int]$NodeB = 7512,
    [int]$NetworkA = 31338,
    [int]$NetworkB = 31339,
    [string]$SiteId = 'BvbQPohf6micoP1CBneuhNoZUBMToy6UqW4AzodyaLMW',
    [string]$StateDir = (Join-Path $env:APPDATA 'freetalk'),
    [switch]$SkipStart,
    [switch]$Cleanup
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$freenet = Join-Path $env:LOCALAPPDATA 'freenet\bin\freenet.exe'
$started = @()

function Test-Http([string]$Url) {
    try {
        return (Invoke-WebRequest -Uri $Url -TimeoutSec 5 -UseBasicParsing).StatusCode -eq 200
    } catch {
        return $false
    }
}

function Wait-Node([int]$Port) {
    for ($i = 0; $i -lt 30; $i++) {
        if (Test-Http "http://127.0.0.1:$Port/") { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Test-App([int]$Port) {
    return Test-Http "http://127.0.0.1:$Port/v1/contract/web/$SiteId/index.html"
}

if ($Cleanup) {
    Get-CimInstance Win32_Process |
        Where-Object { $_.Name -eq 'freenet.exe' -and $_.CommandLine -like '*freenet-two-node-*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Get-ChildItem $env:LOCALAPPDATA -Directory -Filter 'freenet-two-node-*' -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output 'Cleaned the two test nodes.'
    return
}

if (-not $SkipStart) {
    if (-not (Test-Path $freenet)) { throw "freenet not found at $freenet" }
    foreach ($spec in @(@{ Port = $NodeA; Network = $NetworkA; Name = 'A' }, @{ Port = $NodeB; Network = $NetworkB; Name = 'B' })) {
        $dir = Join-Path $env:LOCALAPPDATA "freenet-two-node-$($spec.Name)"
        Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path (Join-Path $dir 'config'), (Join-Path $dir 'data'), (Join-Path $dir 'logs') | Out-Null
        $args = @(
            'network', '--is-gateway', '--skip-load-from-network',
            '--network-port', "$($spec.Network)",
            '--public-network-address', '127.0.0.1',
            '--public-network-port', "$($spec.Network)",
            '--ws-api-port', "$($spec.Port)",
            '--config-dir', (Join-Path $dir 'config'),
            '--data-dir', (Join-Path $dir 'data'),
            '--log-dir', (Join-Path $dir 'logs')
        )
        $started += Start-Process -FilePath $freenet -ArgumentList $args -PassThru
    }
}

$ok = $true
foreach ($port in @($NodeA, $NodeB)) {
    if (-not (Wait-Node $port)) {
        Write-Error "Node on $port did not answer."
        $ok = $false
        continue
    }
    & (Join-Path $repo 'publish-only.ps1') -StateDir $StateDir -ApiPort $port
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Publish to $port failed."
        $ok = $false
        continue
    }
    if (-not (Test-App $port)) {
        Write-Error "App is not served on $port."
        $ok = $false
        continue
    }
    Write-Output "Node $port serves the app."
}

if ($ok) {
    Write-Output ''
    Write-Output "Both nodes are up. Manual UI steps:"
    Write-Output "  1. Open http://127.0.0.1:$NodeA/v1/contract/web/$SiteId/index.html"
    Write-Output "  2. Create a board and a topic with an image."
    Write-Output "  3. Open the same board on http://127.0.0.1:$NodeB/ and wait for the state."
    Write-Output "  4. Check the image, then run this script with -Cleanup when done."
} else {
    Write-Error 'Two-node smoke test failed.'
    exit 1
}
