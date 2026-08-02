[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Enable', 'Query', 'Reset')]
    [string]$Action,

    [string]$DriverName = 'AcTelemetry.sys',

    [string]$EvidenceDirectory = 'out\driver-verifier'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Driver Verifier requires an elevated test machine.'
}

New-Item -ItemType Directory -Force $EvidenceDirectory | Out-Null
$settingsPath = Join-Path $EvidenceDirectory 'querysettings.txt'
$queryPath = Join-Path $EvidenceDirectory 'query.txt'

switch ($Action) {
    'Enable' {
        & verifier.exe /standard /driver $DriverName
        if ($LASTEXITCODE -ne 0) {
            throw "verifier enable failed with $LASTEXITCODE"
        }
        & verifier.exe /bootmode oneboot
        if ($LASTEXITCODE -ne 0) {
            throw "verifier bootmode failed with $LASTEXITCODE"
        }
        & verifier.exe /querysettings 2>&1 | Set-Content $settingsPath
        Write-Host 'Driver Verifier is configured for one boot. Reboot the disposable test VM.'
    }
    'Query' {
        & verifier.exe /querysettings 2>&1 | Set-Content $settingsPath
        if ($LASTEXITCODE -ne 0) {
            throw "verifier querysettings failed with $LASTEXITCODE"
        }
        & verifier.exe /query 2>&1 | Set-Content $queryPath
        if ($LASTEXITCODE -ne 0) {
            throw "verifier query failed with $LASTEXITCODE"
        }
        $settings = Get-Content $settingsPath -Raw
        if ($settings -notmatch [regex]::Escape($DriverName)) {
            throw "$DriverName is not active in Driver Verifier settings"
        }
        Get-CimInstance Win32_OperatingSystem |
            Select-Object Caption, Version, BuildNumber, LastBootUpTime |
            ConvertTo-Json |
            Set-Content (Join-Path $EvidenceDirectory 'operating-system.json')
    }
    'Reset' {
        & verifier.exe /reset
        if ($LASTEXITCODE -ne 0) {
            throw "verifier reset failed with $LASTEXITCODE"
        }
        Write-Host 'Driver Verifier settings were reset. Reboot the test VM.'
    }
}
