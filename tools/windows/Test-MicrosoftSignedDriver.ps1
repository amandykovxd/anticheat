[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageDirectory,

    [Parameter(Mandatory = $true)]
    [string]$EvidencePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path $PackageDirectory).Path
$systemFile = Get-ChildItem $root -Filter AcTelemetry.sys -Recurse -File |
    Select-Object -First 1
$catalogFile = Get-ChildItem $root -Filter AcTelemetry.cat -Recurse -File |
    Select-Object -First 1
$infFile = Get-ChildItem $root -Filter AcTelemetry.inf -Recurse -File |
    Select-Object -First 1
if (-not $systemFile -or -not $catalogFile -or -not $infFile) {
    throw 'returned package must contain AcTelemetry.sys, AcTelemetry.cat, and AcTelemetry.inf'
}

$kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$signTool = Get-ChildItem $kitsRoot -Filter SignTool.exe -Recurse -File |
    Where-Object { $_.DirectoryName -match '\\x64$' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if (-not $signTool) {
    throw 'SignTool.exe was not found'
}

& $signTool.FullName verify /kp /all /v $systemFile.FullName
if ($LASTEXITCODE -ne 0) {
    throw 'AcTelemetry.sys does not have a valid kernel-policy signature'
}
& $signTool.FullName verify /pa /all /v $catalogFile.FullName
if ($LASTEXITCODE -ne 0) {
    throw 'AcTelemetry.cat does not have a valid catalog signature'
}

$evidence = [ordered]@{
    verified_at_utc = [DateTime]::UtcNow.ToString('o')
    microsoft_return_package_verified = $true
    sys_sha256 = (Get-FileHash -Algorithm SHA256 $systemFile.FullName).Hash.ToLowerInvariant()
    cat_sha256 = (Get-FileHash -Algorithm SHA256 $catalogFile.FullName).Hash.ToLowerInvariant()
    inf_sha256 = (Get-FileHash -Algorithm SHA256 $infFile.FullName).Hash.ToLowerInvariant()
}
$evidence | ConvertTo-Json | Set-Content -LiteralPath $EvidencePath -Encoding utf8
Write-Host "Verified Microsoft-returned driver package under $root"
