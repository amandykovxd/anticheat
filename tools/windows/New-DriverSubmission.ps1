[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DriverBuildDirectory,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^https://')]
    [string]$TimestampUrl,

    [switch]$MachineCertificateStore
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Find-WindowsKitTool {
    param([Parameter(Mandatory = $true)][string]$Name)

    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $candidate = Get-ChildItem -Path $kitsRoot -Filter $Name -Recurse -File |
        Where-Object { $_.DirectoryName -match '\\x64$' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if (-not $candidate) {
        throw "$Name was not found under $kitsRoot"
    }
    return $candidate.FullName
}

$source = (Resolve-Path $DriverBuildDirectory).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
$stage = Join-Path $output 'package'
New-Item -ItemType Directory -Force $stage | Out-Null

foreach ($name in @('AcTelemetry.sys', 'AcTelemetry.inf')) {
    $path = Join-Path $source $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "$name is missing from $source"
    }
    Copy-Item -LiteralPath $path -Destination $stage -Force
}

$inf2cat = Find-WindowsKitTool 'Inf2Cat.exe'
$signTool = Find-WindowsKitTool 'SignTool.exe'
& $inf2cat "/driver:$stage" '/os:10_X64' '/verbose'
if ($LASTEXITCODE -ne 0) {
    throw "Inf2Cat exited with $LASTEXITCODE"
}

$storeArguments = @()
if ($MachineCertificateStore) {
    $storeArguments += '/sm'
}
foreach ($file in @('AcTelemetry.sys', 'AcTelemetry.cat')) {
    $path = Join-Path $stage $file
    & $signTool sign @storeArguments /s My /sha1 $CertificateThumbprint `
        /fd sha256 /tr $TimestampUrl /td sha256 /v $path
    if ($LASTEXITCODE -ne 0) {
        throw "SignTool failed for $file with $LASTEXITCODE"
    }
}

$ddf = Join-Path $output 'AcTelemetry.ddf'
$cab = Join-Path $output 'AcTelemetry-submission.cab'
$ddfLines = @(
    '.OPTION EXPLICIT',
    ".Set CabinetNameTemplate=$([IO.Path]::GetFileName($cab))",
    ".Set DiskDirectoryTemplate=$output",
    '.Set CompressionType=MSZIP',
    '.Set Cabinet=on',
    '.Set Compress=on',
    "`"$(Join-Path $stage 'AcTelemetry.inf')`" AcTelemetry.inf",
    "`"$(Join-Path $stage 'AcTelemetry.sys')`" AcTelemetry.sys",
    "`"$(Join-Path $stage 'AcTelemetry.cat')`" AcTelemetry.cat"
)
$ddfLines | Set-Content -LiteralPath $ddf -Encoding ascii
& makecab.exe /F $ddf
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $cab)) {
    throw "MakeCab failed with $LASTEXITCODE"
}

& $signTool sign @storeArguments /s My /sha1 $CertificateThumbprint `
    /fd sha256 /tr $TimestampUrl /td sha256 /v $cab
if ($LASTEXITCODE -ne 0) {
    throw "SignTool failed for the submission CAB with $LASTEXITCODE"
}
& $signTool verify /pa /v $cab
if ($LASTEXITCODE -ne 0) {
    throw "submission CAB signature verification failed with $LASTEXITCODE"
}

$evidence = [ordered]@{
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    package_type = 'partner_center_submission'
    production_deployable = $false
    cab_sha256 = (Get-FileHash -Algorithm SHA256 $cab).Hash.ToLowerInvariant()
    sys_sha256 = (Get-FileHash -Algorithm SHA256 (
        Join-Path $stage 'AcTelemetry.sys')).Hash.ToLowerInvariant()
    cat_sha256 = (Get-FileHash -Algorithm SHA256 (
        Join-Path $stage 'AcTelemetry.cat')).Hash.ToLowerInvariant()
    required_next_step = 'Submit CAB to Partner Center and verify the Microsoft-signed return package.'
}
$evidence | ConvertTo-Json | Set-Content `
    -LiteralPath (Join-Path $output 'submission-evidence.json') `
    -Encoding utf8

Write-Host "Created Partner Center submission: $cab"
