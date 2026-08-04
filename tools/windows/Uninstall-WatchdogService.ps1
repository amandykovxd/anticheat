[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PythonExecutable,
    [Parameter(Mandatory = $true)]
    [string]$WatchdogScript,
    [Parameter(Mandatory = $true)]
    [string]$Config,
    [switch]$SkipTerminalNotification
)

$ErrorActionPreference = 'Stop'
$serviceName = 'AcTelemetryWatchdog'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -eq $service) {
    Write-Output "$serviceName is not installed."
    exit 0
}
if (-not $SkipTerminalNotification) {
    & $PythonExecutable $WatchdogScript --config $Config --terminal-only clean_shutdown
    if ($LASTEXITCODE -ne 0) {
        throw 'The receiver did not accept the clean-shutdown transition.'
    }
}
if ($service.Status -ne 'Stopped') {
    & sc.exe stop $serviceName | Write-Verbose
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
& sc.exe delete $serviceName | Write-Verbose
if ($LASTEXITCODE -ne 0) {
    throw "Failed to delete $serviceName."
}

Write-Output 'Service removed. Event logs, spool, watchdog state, and telemetry were preserved.'
