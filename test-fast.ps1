# Inner-loop tests for the forum crates.
#
# `cargo test` at the workspace root also builds `plazactl`, which embeds the
# contract wasm: after every deploy that re-links the CLI and costs up to a
# minute and a half, with no benefit while iterating on core or UI code.
#
#   pwsh ./test-fast.ps1          core + UI (the default loop)
#   pwsh ./test-fast.ps1 -Core    only plaza-core's unit tests
#   pwsh ./test-fast.ps1 -Ui      only plaza-ui
#   pwsh ./test-fast.ps1 -All     the whole workspace, for before a commit
param(
    [switch]$Core,
    [switch]$Ui,
    [switch]$All
)

$ErrorActionPreference = "Stop"

function Invoke-TestStep {
    param([string]$Name, [string[]]$Arguments)

    Write-Host "-> $Name" -ForegroundColor Cyan
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    & cargo @Arguments
    $code = $LASTEXITCODE
    $watch.Stop()
    Write-Host ("   {0}: {1:N1}s" -f $Name, $watch.Elapsed.TotalSeconds) -ForegroundColor DarkGray
    if ($code -ne 0) {
        Write-Host "$Name failed (exit $code)" -ForegroundColor Red
        exit $code
    }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

if ($All) {
    Invoke-TestStep "workspace" @("test")
} elseif ($Ui -and -not $Core) {
    Invoke-TestStep "plaza-ui" @("test", "-p", "plaza-ui")
} elseif ($Core -and -not $Ui) {
    Invoke-TestStep "plaza-core --lib" @("test", "-p", "plaza-core", "--lib")
} else {
    Invoke-TestStep "plaza-core --lib" @("test", "-p", "plaza-core", "--lib")
    Invoke-TestStep "plaza-ui" @("test", "-p", "plaza-ui")
}

$total.Stop()
Write-Host ("total: {0:N1}s" -f $total.Elapsed.TotalSeconds) -ForegroundColor Green
