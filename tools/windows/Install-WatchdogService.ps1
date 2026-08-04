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
    [Parameter(Mandatory = $true)]
    [string]$StateDirectory
)

$ErrorActionPreference = 'Stop'
$serviceName = 'AcTelemetryWatchdog'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell session.'
    }
}

function Resolve-ExistingFile([string]$Path, [string]$Label) {
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer) {
        throw "$Label must be a file: $Path"
    }
    if ($item.FullName.Contains('"')) {
        throw "$Label contains an unsupported quote character."
    }
    return $item.FullName
}

function Invoke-Sc([string[]]$Arguments) {
    & sc.exe @Arguments | Write-Verbose
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe failed with exit code $LASTEXITCODE: $($Arguments -join ' ')"
    }
}

function Assert-NotBroadlyWritable([string]$Path) {
    $broadSids = @(
        'S-1-1-0',
        'S-1-5-11',
        'S-1-5-32-545'
    )
    $writeMask = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::CreateFiles -bor
        [Security.AccessControl.FileSystemRights]::Modify -bor
        [Security.AccessControl.FileSystemRights]::FullControl
    foreach ($rule in (Get-Acl -LiteralPath $Path).Access) {
        $sid = $rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
        if ($rule.AccessControlType -eq 'Allow' -and
            $sid -in $broadSids -and
            (($rule.FileSystemRights -band $writeMask) -ne 0)) {
            throw "$Path grants write access to a broad principal ($sid)."
        }
    }
}

Assert-Administrator
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw "$serviceName already exists. Use Update-WatchdogService.ps1."
}

$serviceExe = Resolve-ExistingFile $ServiceBinary 'ServiceBinary'
$pythonExe = Resolve-ExistingFile $PythonExecutable 'PythonExecutable'
$watchdog = Resolve-ExistingFile $WatchdogScript 'WatchdogScript'
$configFile = Resolve-ExistingFile $Config 'Config'
$working = (Get-Item -LiteralPath $WorkingDirectory -ErrorAction Stop).FullName
$stateWasPresent = Test-Path -LiteralPath $StateDirectory
$state = New-Item -ItemType Directory -Path $StateDirectory -Force

foreach ($path in @($serviceExe, $pythonExe, $watchdog, $configFile)) {
    Assert-NotBroadlyWritable $path
}
if ($stateWasPresent) {
    Assert-NotBroadlyWritable $state.FullName
    & icacls.exe $state.FullName '/grant:r' 'SYSTEM:(OI)(CI)(M)' |
        Write-Verbose
} else {
    & icacls.exe $state.FullName '/inheritance:r' '/grant:r' `
        'SYSTEM:(OI)(CI)(F)' 'BUILTIN\Administrators:(OI)(CI)(F)' | Write-Verbose
}
if ($LASTEXITCODE -ne 0) {
    throw "Failed to restrict ACLs on $($state.FullName)"
}

$imagePath = ('"{0}" --service --python "{1}" --watchdog "{2}" ' +
    '--config "{3}" --working-directory "{4}"') -f `
    $serviceExe, $pythonExe, $watchdog, $configFile, $working

Invoke-Sc @(
    'create', $serviceName,
    'binPath=', $imagePath,
    'start=', 'delayed-auto',
    'obj=', 'LocalSystem',
    'DisplayName=', 'Anticheat Telemetry Watchdog'
)
Invoke-Sc @('description', $serviceName,
    'Supervises the anticheat collector and telemetry shipper; does not enforce on the target.')
Invoke-Sc @('sidtype', $serviceName, 'restricted')
Invoke-Sc @('failure', $serviceName, 'reset=', '86400',
    'actions=', 'restart/5000/restart/15000/none/0')
Invoke-Sc @('failureflag', $serviceName, '1')
Invoke-Sc @('start', $serviceName)

Write-Output "$serviceName installed and started with a restricted LocalSystem child token."
