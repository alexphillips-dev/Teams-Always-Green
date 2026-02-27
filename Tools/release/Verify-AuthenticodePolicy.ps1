param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$ManifestPath = "app/setup/QuickSetup.manifest.json",
    [string[]]$InputFiles = @(),
    [string]$ExpectedThumbprint = "",
    [switch]$RequireTrustedStatus
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Convert-ManifestPathToLocal([string]$manifestPath) {
    return ($manifestPath -replace "/", "\")
}

function Get-SignableManifestFiles([string]$manifestAbsPath, [string]$repoRootPath) {
    $manifest = Get-Content -Raw -Path $manifestAbsPath | ConvertFrom-Json
    if (-not $manifest -or -not $manifest.files) {
        throw "Manifest is invalid or missing files table."
    }
    $signable = New-Object System.Collections.Generic.List[string]
    foreach ($name in $manifest.files.PSObject.Properties.Name) {
        $ext = [System.IO.Path]::GetExtension($name).ToLowerInvariant()
        if ($ext -notin @(".ps1", ".psm1", ".psd1", ".vbs", ".cmd")) { continue }
        $fullPath = Join-Path $repoRootPath (Convert-ManifestPathToLocal $name)
        if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
            [void]$signable.Add($fullPath)
        }
    }
    return $signable
}

$repoRootAbs = (Resolve-Path -Path $RepoRoot).Path
$manifestAbsPath = if ([System.IO.Path]::IsPathRooted($ManifestPath)) { $ManifestPath } else { Join-Path $repoRootAbs $ManifestPath }
if (-not (Test-Path -LiteralPath $manifestAbsPath -PathType Leaf)) {
    throw "Manifest file not found: $manifestAbsPath"
}

$expectedNormalized = ([string]$ExpectedThumbprint).Trim().ToUpperInvariant()
$files = New-Object System.Collections.Generic.List[string]
if (@($InputFiles).Count -gt 0) {
    foreach ($candidate in @($InputFiles)) {
        if ([string]::IsNullOrWhiteSpace([string]$candidate)) { continue }
        $resolved = if ([System.IO.Path]::IsPathRooted([string]$candidate)) { [string]$candidate } else { Join-Path $repoRootAbs ([string]$candidate) }
        if (Test-Path -LiteralPath $resolved -PathType Leaf) {
            [void]$files.Add($resolved)
        }
    }
} else {
    $files = Get-SignableManifestFiles -manifestAbsPath $manifestAbsPath -repoRootPath $repoRootAbs
}
if ($files.Count -eq 0) {
    throw "No signable files found from manifest."
}

$allowedStatuses = @(
    [System.Management.Automation.SignatureStatus]::Valid,
    [System.Management.Automation.SignatureStatus]::NotTrusted
)

$failures = New-Object System.Collections.Generic.List[string]
foreach ($file in $files) {
    $sig = Get-AuthenticodeSignature -FilePath $file
    if (-not $sig) {
        [void]$failures.Add(("{0}: signature metadata missing." -f $file))
        continue
    }
    if ($sig.Status -eq [System.Management.Automation.SignatureStatus]::NotSigned) {
        [void]$failures.Add(("{0}: not signed." -f $file))
        continue
    }
    if ($RequireTrustedStatus -and $sig.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        [void]$failures.Add(("{0}: status '{1}' (trusted signature required)." -f $file, [string]$sig.Status))
        continue
    }
    if (-not $RequireTrustedStatus -and $sig.Status -notin $allowedStatuses) {
        [void]$failures.Add(("{0}: status '{1}'." -f $file, [string]$sig.Status))
        continue
    }

    if (-not $sig.SignerCertificate) {
        [void]$failures.Add(("{0}: signer certificate missing." -f $file))
        continue
    }

    if (-not [string]::IsNullOrWhiteSpace($expectedNormalized)) {
        $actualThumbprint = ([string]$sig.SignerCertificate.Thumbprint).Trim().ToUpperInvariant()
        if ($actualThumbprint -ne $expectedNormalized) {
            [void]$failures.Add(("{0}: signer thumbprint mismatch. expected={1} actual={2}" -f $file, $expectedNormalized, $actualThumbprint))
            continue
        }
    }
}

if ($failures.Count -gt 0) {
    throw ("Authenticode policy check failed:`n- " + ($failures -join "`n- "))
}

Write-Host ("Authenticode policy check passed for {0} files." -f $files.Count)
