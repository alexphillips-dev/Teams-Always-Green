param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [Parameter(Mandatory = $true)][string[]]$InputFiles,
    [string]$OutputPath = ""
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
    $OutputPath = Join-Path $repoRootAbs "release-checksums.sha256"
}
$outputAbs = Resolve-PathUnderRepo -repoRootPath $repoRootAbs -candidate $OutputPath

$rows = New-Object System.Collections.Generic.List[string]
foreach ($candidate in @($InputFiles)) {
    $resolved = Resolve-PathUnderRepo -repoRootPath $repoRootAbs -candidate ([string]$candidate)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw ("Checksum input file not found: {0}" -f $candidate)
    }
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolved).Hash.ToUpperInvariant()
    $displayPath = Get-DisplayPath -repoRootPath $repoRootAbs -absolutePath $resolved
    $rows.Add(("{0} *{1}" -f $hash, $displayPath)) | Out-Null
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines($outputAbs, $rows, $utf8NoBom)
Write-Host ("Generated checksums: {0}" -f $outputAbs)
