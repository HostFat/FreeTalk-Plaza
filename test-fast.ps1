# Inner-loop tests for the forum crates.
#
# `cargo test` at the workspace root also builds `plazactl`, which embeds the
# contract wasm: after every deploy that re-links the CLI and costs up to a
# minute and a half, with no benefit while iterating on core or UI code.
#
#   pwsh ./test-fast.ps1                    core + topic + UI (default loop)
#   pwsh ./test-fast.ps1 -Core              only plaza-core's unit tests
#   pwsh ./test-fast.ps1 -Topic             only plaza-topic-core's unit tests
#   pwsh ./test-fast.ps1 -Ui                only plaza-ui
#   pwsh ./test-fast.ps1 -Contracts         contract interface tests (6 crates)
#   pwsh ./test-fast.ps1 -Core -Filter foo  filtered unit tests
#   pwsh ./test-fast.ps1 -All               the whole workspace, for before a commit
param(
    [switch]$Core,
    [switch]$Topic,
    [switch]$Ui,
    [switch]$Contracts,
    [switch]$All,
    [string]$Filter = ""
)

$ErrorActionPreference = "Stop"

if (-not $env:RUSTC_WRAPPER -and (Get-Command 'sccache' -ErrorAction SilentlyContinue)) {
    $env:RUSTC_WRAPPER = 'sccache'
}
$useNextest = [bool](Get-Command 'cargo-nextest' -ErrorAction SilentlyContinue)

function Invoke-TestStep {
    param([string]$Name, [string[]]$TargetArgs)

    $runner = if ($useNextest) { "cargo nextest" } else { "cargo test" }
    Write-Host "-> $Name ($runner)" -ForegroundColor Cyan
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $argsList = if ($useNextest) {
        @("nextest", "run", "--no-fail-fast") + $TargetArgs
    } else {
        @("test") + $TargetArgs
    }
    if ($Filter) {
        $argsList += $Filter
    }
    & cargo @argsList
    $code = $LASTEXITCODE
    $watch.Stop()
    Write-Host ("   {0}: {1:N1}s" -f $Name, $watch.Elapsed.TotalSeconds) -ForegroundColor DarkGray
    if ($code -ne 0) {
        Write-Host "$Name failed (exit $code)" -ForegroundColor Red
        exit $code
    }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()
$selected = $Core -or $Topic -or $Ui -or $Contracts

if ($All) {
    Invoke-TestStep "workspace" @("--workspace")
} elseif ($selected) {
    if ($Core) { Invoke-TestStep "plaza-core --lib" @("-p", "plaza-core", "--lib") }
    if ($Topic) { Invoke-TestStep "plaza-topic-core --lib" @("-p", "plaza-topic-core", "--lib") }
    if ($Contracts) {
        Invoke-TestStep "contracts" @(
            "-p", "plaza-member-contract",
            "-p", "plaza-profile-contract",
            "-p", "plaza-activity-contract",
            "-p", "plaza-moderation-contract",
            "-p", "plaza-section-contract",
            "-p", "plaza-topic-contract"
        )
    }
    if ($Ui) { Invoke-TestStep "plaza-ui" @("-p", "plaza-ui", "--bin", "plaza-ui") }
} else {
    Invoke-TestStep "plaza-core --lib" @("-p", "plaza-core", "--lib")
    Invoke-TestStep "plaza-topic-core --lib" @("-p", "plaza-topic-core", "--lib")
    Invoke-TestStep "plaza-ui" @("-p", "plaza-ui", "--bin", "plaza-ui")
}

$total.Stop()
Write-Host ("total: {0:N1}s" -f $total.Elapsed.TotalSeconds) -ForegroundColor Green
