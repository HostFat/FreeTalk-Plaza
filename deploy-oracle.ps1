#!/usr/bin/env pwsh
# Deploy to the Oracle node without depending on a long-lived tunnel.
#
# The node's API is bound to 127.0.0.1:7509 on the VM. This script starts the
# tunnel supervisor on 7511 when nothing is listening, publishes, and leaves
# the supervisor running so the tunnel survives the VM's SSH session limit.
# An existing tunnel (for example tunnel-oracle.ps1) is reused.
#
# Usage:
#   pwsh ./deploy-oracle.ps1
#   pwsh ./deploy-oracle.ps1 -Version 402
#
# Environment overrides:
#   PLAZA_ORACLE_HOST  required (or pass -OracleHost)
#   PLAZA_ORACLE_USER  default ubuntu
#   PLAZA_ORACLE_KEY   default %USERPROFILE%\.oci\freenet-node

[CmdletBinding()]
param(
    [int]$Version = 0,
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

if (-not (Test-Path -LiteralPath $KeyPath)) {
    throw "SSH key not found: $KeyPath (set PLAZA_ORACLE_KEY)"
}

if (-not (Test-LocalPort $LocalPort)) {
    Write-Host "Starting the tunnel from the Startup folder..."
    $supervisor = Join-Path $PSScriptRoot 'tunnel-oracle.ps1'
    $logPath = Join-Path $env:LOCALAPPDATA 'freetalk-oracle-tunnel.log'
    $startup = [Environment]::GetFolderPath('Startup')
    $launcher = Join-Path $startup 'FreeTalk-Oracle-Tunnel.cmd'
    $content = "@echo off`r`npwsh -NoProfile -WindowStyle Hidden -File `"$supervisor`" -LocalPort $LocalPort -RemotePort $RemotePort -OracleHost `"$OracleHost`" -OracleUser `"$OracleUser`" -KeyPath `"$KeyPath`"`r`n"
    if (-not (Test-Path -LiteralPath $launcher) -or
        (Get-Content -Raw -LiteralPath $launcher) -ne $content) {
        Set-Content -LiteralPath $launcher -Value $content -Encoding ascii
    }
    # Explorer starts it outside this process tree, so the tunnel survives the
    # deploy and the terminal. The same file runs at every logon.
    Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f $launcher)
    $deadline = (Get-Date).AddSeconds(25)
    while ((Get-Date) -lt $deadline -and -not (Test-LocalPort $LocalPort)) {
        Start-Sleep -Milliseconds 300
    }
    if (-not (Test-LocalPort $LocalPort)) {
        throw "The tunnel did not open port $LocalPort within 25 seconds. See $logPath."
    }
    Write-Host "Tunnel open; the Startup entry keeps it alive at every logon."
} else {
    Write-Host "Reusing the tunnel already listening on 127.0.0.1:$LocalPort."
}

$deploy = Join-Path $PSScriptRoot 'deploy-fast.ps1'
& $deploy -Version $Version -ExtraApiPorts $LocalPort
if ($LASTEXITCODE -ne 0) {
    throw "deploy-fast.ps1 failed with exit code $LASTEXITCODE"
}
