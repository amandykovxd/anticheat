[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServiceBinary,
    [Parameter(Mandatory = $true)]
    [string]$PythonExecutable,
    [Parameter(Mandatory = $true)]
    [string]$WatchdogScript,
    [Parameter(Mandatory = $true)]
    [string]$Config,
    [Parameter(Mandatory = $true)]
    [string]$WorkingDirectory,
    [switch]$SkipTerminalNotification
)

$ErrorActionPreference = 'Stop'
$serviceName = 'AcTelemetryWatchdog'

function Resolve-ExistingFile([string]$Path) {
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer -or $item.FullName.Contains('"')) {
        throw "Invalid service path: $Path"
    }
    return $item.FullName
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}
if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
    throw "$serviceName is not installed."
}

$serviceExe = Resolve-ExistingFile $ServiceBinary
$pythonExe = Resolve-ExistingFile $PythonExecutable
$watchdog = Resolve-ExistingFile $WatchdogScript
$configFile = Resolve-ExistingFile $Config
$working = (Get-Item -LiteralPath $WorkingDirectory -ErrorAction Stop).FullName

if (-not $SkipTerminalNotification) {
    & $pythonExe $watchdog --config $configFile --terminal-only clean_shutdown
    if ($LASTEXITCODE -ne 0) {
        throw 'The receiver did not accept the clean-shutdown transition.'
    }
}

& sc.exe stop $serviceName | Write-Verbose
$service = Get-Service -Name $serviceName
$service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))

$imagePath = ('"{0}" --service --python "{1}" --watchdog "{2}" ' +
    '--config "{3}" --working-directory "{4}"') -f `
    $serviceExe, $pythonExe, $watchdog, $configFile, $working
& sc.exe config $serviceName 'binPath=' $imagePath | Write-Verbose
if ($LASTEXITCODE -ne 0) {
    throw "Failed to update $serviceName."
}
& sc.exe start $serviceName | Write-Verbose
if ($LASTEXITCODE -ne 0) {
    throw "Failed to start $serviceName."
}

Write-Output "$serviceName configuration updated and service restarted."
