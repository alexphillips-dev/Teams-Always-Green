param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$ManifestPath = "app/setup/QuickSetup.manifest.json",
    [string]$OutputPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Convert-ManifestPathToLocal([string]$manifestPath) {
    return ($manifestPath -replace "/", "\")
}

$repoRootAbs = (Resolve-Path -Path $RepoRoot).Path
$manifestAbsPath = if ([System.IO.Path]::IsPathRooted($ManifestPath)) { $ManifestPath } else { Join-Path $repoRootAbs $ManifestPath }
if (-not (Test-Path -LiteralPath $manifestAbsPath -PathType Leaf)) {
    throw "Manifest file not found: $manifestAbsPath"
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $repoRootAbs "release-sbom.cdx.json"
}
$outputAbs = if ([System.IO.Path]::IsPathRooted($OutputPath)) { $OutputPath } else { Join-Path $repoRootAbs $OutputPath }

$manifest = Get-Content -Raw -Path $manifestAbsPath | ConvertFrom-Json
if (-not $manifest -or -not $manifest.files) {
    throw "Manifest is invalid or missing files table."
}

$versionPath = Join-Path $repoRootAbs "VERSION"
$appVersion = if (Test-Path -LiteralPath $versionPath -PathType Leaf) {
    (Get-Content -Path $versionPath -Raw).Trim()
} else {
    "0.0.0"
}

$components = New-Object System.Collections.Generic.List[object]
foreach ($entry in $manifest.files.PSObject.Properties) {
    $relativePath = [string]$entry.Name
    $expectedHash = ([string]$entry.Value).ToUpperInvariant()
    $absolutePath = Join-Path $repoRootAbs (Convert-ManifestPathToLocal $relativePath)
    if (-not (Test-Path -LiteralPath $absolutePath -PathType Leaf)) { continue }
    $fileInfo = Get-Item -LiteralPath $absolutePath
    $components.Add([ordered]@{
        type = "file"
        name = $relativePath
        version = $appVersion
        hashes = @(
            @{
                alg = "SHA-256"
                content = $expectedHash
            }
        )
        properties = @(
            @{
                name = "tag.file.size"
                value = [string]$fileInfo.Length
            }
        )
    }) | Out-Null
}

$sbom = [ordered]@{
    bomFormat = "CycloneDX"
    specVersion = "1.5"
    serialNumber = ("urn:uuid:{0}" -f [Guid]::NewGuid().ToString())
    version = 1
    metadata = [ordered]@{
        timestamp = [DateTime]::UtcNow.ToString("o")
        component = [ordered]@{
            type = "application"
            name = "Teams Always Green"
            version = $appVersion
        }
        tools = @(
            [ordered]@{
                vendor = "Teams Always Green"
                name = "Generate-Sbom.ps1"
                version = "1"
            }
        )
    }
    components = $components
}

$json = $sbom | ConvertTo-Json -Depth 12
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($outputAbs, ($json + [Environment]::NewLine), $utf8NoBom)
Write-Host ("Generated SBOM: {0}" -f $outputAbs)
