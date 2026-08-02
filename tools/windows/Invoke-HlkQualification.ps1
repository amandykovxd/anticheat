[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ProjectDefinition,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedPackage,

    [string]$EvidenceDirectory = 'out\hlk'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$project = (Resolve-Path $ProjectDefinition).Path
if (-not $env:WTTSTDIO) {
    throw 'WTTSTDIO is not set; run this script on an HLK Controller.'
}
$engine = Join-Path $env:WTTSTDIO 'HlkExecutionEngine.exe'
if (-not (Test-Path -LiteralPath $engine -PathType Leaf)) {
    throw "HLK execution engine was not found at $engine"
}

New-Item -ItemType Directory -Force $EvidenceDirectory | Out-Null
$transcript = Join-Path $EvidenceDirectory 'hlk-execution.log'
& $engine /Project $project /RunCollection 2>&1 |
    Tee-Object -FilePath $transcript
if ($LASTEXITCODE -ne 0) {
    throw "HLK execution engine exited with $LASTEXITCODE"
}
if (-not (Test-Path -LiteralPath $ExpectedPackage -PathType Leaf)) {
    throw "HLK result package was not created at $ExpectedPackage"
}
if ([IO.Path]::GetExtension($ExpectedPackage) -ne '.hlkx') {
    throw 'ExpectedPackage must be an .hlkx result package'
}

$evidence = [ordered]@{
    completed_at_utc = [DateTime]::UtcNow.ToString('o')
    project_definition_sha256 = (Get-FileHash -Algorithm SHA256 $project).Hash.ToLowerInvariant()
    package_sha256 = (Get-FileHash -Algorithm SHA256 $ExpectedPackage).Hash.ToLowerInvariant()
    package_path = [IO.Path]::GetFullPath($ExpectedPackage)
}
$evidence | ConvertTo-Json | Set-Content `
    (Join-Path $EvidenceDirectory 'hlk-evidence.json') -Encoding utf8
