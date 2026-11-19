#!/usr/bin/env pwsh
# Run the Playwright UI tests against the Dioxus example-data build.
#
#   pwsh ./test-e2e.ps1
#   pwsh ./test-e2e.ps1 -Project chromium
#   pwsh ./test-e2e.ps1 -Headed
#
# The script starts `dx serve` on port 8082 with example-data,no-sync, waits
# for the app, runs `npm test`, and stops the server it started. If a server is
# already listening on 8082 it is reused and left running.
param(
    [string]$Project = "",
    [switch]$Headed,
    [int]$Port = 8082
)

$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot
$ui = Join-Path $repo "ui"
$tests = Join-Path $ui "tests"

function Find-Tool {
    param([string]$Name, [string[]]$Candidates)
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return (Resolve-Path $candidate).Path
        }
    }
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    return $null
}

function Ensure-Exe {
    param([string]$Path)
    if (-not $Path) { return $Path }
    if ($Path -match '\.exe$') { return $Path }
    $copy = Join-Path $env:TEMP "dx-e2e.exe"
    Copy-Item $Path $copy -Force
    return $copy
}

$dx = Find-Tool -Name 'dx' -Candidates @(
    (Join-Path $env:USERPROFILE 'code\freenet\bin\dx'),
    (Join-Path $env:USERPROFILE '.cargo\bin\dx.exe')
)
if (-not $dx) { throw "dx not found. Install dioxus-cli." }
$dx = Ensure-Exe -Path $dx

if (-not (Test-Path (Join-Path $tests 'node_modules'))) {
    Write-Host "Installing Playwright test dependencies..." -ForegroundColor Cyan
    Push-Location $tests
    try { & npm install --no-audit --no-fund } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw "npm install failed." }
}

$listening = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
$server = $null
if (-not $listening) {
    Write-Host "Starting dx serve on port $Port..." -ForegroundColor Cyan
    $serverLog = Join-Path $env:TEMP "plaza-e2e-server.log"
    $serverErr = Join-Path $env:TEMP "plaza-e2e-server.err.log"
    $server = Start-Process -FilePath $dx -ArgumentList @(
        'serve',
        '--port', "$Port",
        '--open', 'false',
        '--hot-reload', 'false',
        '--watch', 'false',
        '--features', 'example-data,no-sync'
    ) -WorkingDirectory $ui -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $serverLog -RedirectStandardError $serverErr

    $deadline = (Get-Date).AddMinutes(4)
    $ready = $false
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
            $ready = $true
            break
        }
        if ($server.HasExited) {
            Write-Host "dx serve exited before the port opened. Log: $serverLog" -ForegroundColor Red
            Get-Content $serverLog -Tail 20 -ErrorAction SilentlyContinue
            Get-Content $serverErr -Tail 20 -ErrorAction SilentlyContinue
            break
        }
    }
    if (-not $ready) {
        if ($server -and -not $server.HasExited) {
            taskkill /T /F /PID $server.Id 2>$null | Out-Null
        }
        throw "The dev server did not become ready on port $Port."
    }
    # The HTTP listener opens before the wasm bundle is ready; give the app a
    # moment, then let Playwright's own selectors wait for the UI.
    Start-Sleep -Seconds 2
    Write-Host "Dev server is listening on port $Port." -ForegroundColor Green
} else {
    Write-Host "Using the server already listening on port $Port." -ForegroundColor Yellow
}

$code = 1
try {
    Push-Location $tests
    try {
        Write-Host "Running Playwright..." -ForegroundColor Cyan
        $arguments = @('playwright', 'test')
        if ($Project) { $arguments += "--project=$Project" }
        if ($Headed) { $arguments += '--headed' }
        & npx @arguments
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
    }
} finally {
    if ($server) {
        Write-Host "Stopping dx serve..." -ForegroundColor Cyan
        taskkill /T /F /PID $server.Id 2>$null | Out-Null
    }
}

exit $code
