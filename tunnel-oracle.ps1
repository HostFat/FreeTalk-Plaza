#!/usr/bin/env pwsh
# Keep the Oracle API tunnel alive. The VM closes long SSH sessions after a
# few hours; this supervisor restarts ssh whenever it exits.
#
# Usage:
#   pwsh ./tunnel-oracle.ps1
#   pwsh ./tunnel-oracle.ps1 -LocalPort 7511
#
# To survive closing this terminal, register it as a logon task once:
#   $action = New-ScheduledTaskAction -Execute 'pwsh.exe' `
#       -Argument '-NoProfile -File "<repo>\tunnel-oracle.ps1"'
#   $trigger = New-ScheduledTaskTrigger -AtLogOn
#   Register-ScheduledTask -TaskName 'FreeTalk Oracle tunnel' `
#       -Action $action -Trigger $trigger -Description 'Keeps the FreeTalk Oracle API tunnel alive'
#
# Environment overrides are the same as deploy-oracle.ps1.

[CmdletBinding()]
param(
    [int]$LocalPort = 7511,
    [int]$RemotePort = 7509,
    [string]$OracleHost = $env:PLAZA_ORACLE_HOST,
    [string]$OracleUser = $(if ($env:PLAZA_ORACLE_USER) { $env:PLAZA_ORACLE_USER } else { 'ubuntu' }),
    [string]$KeyPath = $(if ($env:PLAZA_ORACLE_KEY) { $env:PLAZA_ORACLE_KEY } else { Join-Path $env:USERPROFILE '.oci\freenet-node' })
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($OracleHost)) {
    throw "Oracle host is required. Pass -OracleHost or set PLAZA_ORACLE_HOST."
}
$logPath = Join-Path $env:LOCALAPPDATA 'freetalk-oracle-tunnel.log'

function Test-LocalPort([int]$Port) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $task = $client.ConnectAsync('127.0.0.1', $Port)
        if ($task.Wait(500) -and $client.Connected) { return $true }
    } catch {
        # Not listening.
    } finally {
        $client.Dispose()
    }
    return $false
}

function Write-Log([string]$Message) {
    $line = "{0:u} {1}" -f (Get-Date), $Message
    Write-Host $line
    Add-Content -LiteralPath $logPath -Value $line -Encoding utf8
}

if (-not (Test-Path -LiteralPath $KeyPath)) {
    throw "SSH key not found: $KeyPath (set PLAZA_ORACLE_KEY)"
}
if (Test-LocalPort $LocalPort) {
    Write-Log "Port $LocalPort is already served by another tunnel; leaving it alone."
    exit 0
}

while ($true) {
    Write-Log "Starting tunnel $LocalPort -> ${OracleHost}:${RemotePort}"
    & ssh -N `
        -o BatchMode=yes `
        -o ExitOnForwardFailure=yes `
        -o ServerAliveInterval=20 `
        -o ServerAliveCountMax=3 `
        -i $KeyPath `
        -L "${LocalPort}:127.0.0.1:${RemotePort}" `
        "$OracleUser@$OracleHost"
    Write-Log "Tunnel exited with code $LASTEXITCODE; retrying in 5 seconds."
    Start-Sleep -Seconds 5
    while (Test-LocalPort $LocalPort) {
        # A stale process still owns the port; wait for it to go away.
        Start-Sleep -Seconds 5
    }
}
