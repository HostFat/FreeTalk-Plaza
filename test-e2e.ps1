#!/usr/bin/env pwsh
# Run the Playwright UI tests against the Dioxus example-data build.
#
#   pwsh ./test-e2e.ps1
#   pwsh ./test-e2e.ps1 -Project chromium
#   pwsh ./test-e2e.ps1 -Headed
#
# Playwright runs tests/serve-example.mjs: it builds the UI with
# example-data,no-sync, serves the static bundle on port 8082, runs the tests
# and stops the server. If a server is already listening on the port,
# Playwright reuses it.
param(
    [string]$Project = "",
    [switch]$Headed,
    [int]$Port = 8082
)

$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot
$tests = Join-Path $repo "ui\tests"

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

# Playwright's webServer runs tests/serve-example.mjs, which builds with this
# dx and then serves the static bundle. Building before serving removes the
# dev server's "app is being rebuilt" race.
$env:DX_BIN = $dx
$env:PORT = "$Port"
$env:PLAYWRIGHT_BASE_URL = "http://localhost:$Port"

Push-Location $tests
try {
    Write-Host "Running Playwright (server managed by Playwright)..." -ForegroundColor Cyan
    $arguments = @('playwright', 'test')
    if ($Project) { $arguments += "--project=$Project" }
    if ($Headed) { $arguments += '--headed' }
    & npx @arguments
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}

exit $code
