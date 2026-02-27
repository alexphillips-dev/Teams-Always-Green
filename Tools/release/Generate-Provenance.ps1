param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string[]]$SubjectFiles = @(),
    [string]$OutputPath = "",
    [string]$Tag = "",
    [string]$Version = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-PathUnderRepo([string]$repoRootPath, [string]$candidate) {
    if ([string]::IsNullOrWhiteSpace($candidate)) { return "" }
    if ([System.IO.Path]::IsPathRooted($candidate)) { return $candidate }
    return (Join-Path $repoRootPath $candidate)
}

function Get-DisplayPath([string]$repoRootPath, [string]$absolutePath) {
    $repoFull = [System.IO.Path]::GetFullPath($repoRootPath).TrimEnd('\') + '\'
    $fileFull = [System.IO.Path]::GetFullPath($absolutePath)
    if ($fileFull.StartsWith($repoFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return ($fileFull.Substring($repoFull.Length)).Replace('\', '/')
    }
    return [System.IO.Path]::GetFileName($fileFull)
}

$repoRootAbs = (Resolve-Path -Path $RepoRoot).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $repoRootAbs "release-provenance.json"
}
$outputAbs = Resolve-PathUnderRepo -repoRootPath $repoRootAbs -candidate $OutputPath

$subjects = New-Object System.Collections.Generic.List[object]
foreach ($file in @($SubjectFiles)) {
    if ([string]::IsNullOrWhiteSpace([string]$file)) { continue }
    $abs = Resolve-PathUnderRepo -repoRootPath $repoRootAbs -candidate ([string]$file)
    if (-not (Test-Path -LiteralPath $abs -PathType Leaf)) { continue }
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $abs).Hash.ToUpperInvariant()
    $subjects.Add([ordered]@{
        name = (Get-DisplayPath -repoRootPath $repoRootAbs -absolutePath $abs)
        sha256 = $hash
    }) | Out-Null
}

$provenance = [ordered]@{
    schemaVersion = "1.0"
    generatedAtUtc = [DateTime]::UtcNow.ToString("o")
    repository = [string]$env:GITHUB_REPOSITORY
    ref = [string]$env:GITHUB_REF
    refName = [string]$env:GITHUB_REF_NAME
    commit = [string]$env:GITHUB_SHA
    workflow = [string]$env:GITHUB_WORKFLOW
    runId = [string]$env:GITHUB_RUN_ID
    runAttempt = [string]$env:GITHUB_RUN_ATTEMPT
    actor = [string]$env:GITHUB_ACTOR
    tag = [string]$Tag
    version = [string]$Version
    subjects = $subjects
}

$json = $provenance | ConvertTo-Json -Depth 8
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($outputAbs, ($json + [Environment]::NewLine), $utf8NoBom)
Write-Host ("Generated provenance: {0}" -f $outputAbs)
