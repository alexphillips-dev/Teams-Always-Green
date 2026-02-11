param(
    [Parameter(Mandatory = $true)][string]$CertificateThumbprint,
    [ValidateSet("CurrentUser", "LocalMachine")][string]$StoreLocation = "CurrentUser",
    [string]$StoreName = "My",
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$ManifestPath = "QuickSetup.manifest.json",
    [string]$TimestampServer = "http://timestamp.digicert.com"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Convert-ManifestPathToLocal([string]$manifestPath) {
    return ($manifestPath -replace "/", "\")
}

function Get-SignableManifestFiles([string]$manifestAbsPath, [string]$repoRootPath) {
    $manifest = Get-Content -Raw -Path $manifestAbsPath | ConvertFrom-Json
    $signable = New-Object System.Collections.Generic.List[string]
    foreach ($name in $manifest.files.PSObject.Properties.Name) {
        $ext = [System.IO.Path]::GetExtension($name).ToLowerInvariant()
        if ($ext -notin @(".ps1", ".psm1", ".psd1", ".vbs", ".cmd")) { continue }
        $fullPath = Join-Path $repoRootPath (Convert-ManifestPathToLocal $name)
        if (Test-Path $fullPath) {
            [void]$signable.Add($fullPath)
        }
    }
    return $signable
}

$repoRoot = (Resolve-Path $RepoRoot).Path
$manifestAbsPath = if ([System.IO.Path]::IsPathRooted($ManifestPath)) { $ManifestPath } else { Join-Path $repoRoot $ManifestPath }
if (-not (Test-Path $manifestAbsPath)) {
    throw "Manifest file not found: $manifestAbsPath"
}

$certPath = "Cert:\$StoreLocation\$StoreName\$CertificateThumbprint"
$certificate = Get-Item -Path $certPath -ErrorAction SilentlyContinue
if (-not $certificate) {
    throw "Certificate not found at $certPath"
}
if (-not $certificate.HasPrivateKey) {
    throw "Certificate at $certPath does not have a private key."
}

$filesToSign = Get-SignableManifestFiles -manifestAbsPath $manifestAbsPath -repoRootPath $repoRoot
if ($filesToSign.Count -eq 0) {
    throw "No signable files were found from manifest entries."
}

Write-Host ("Signing {0} file(s) with cert {1}" -f $filesToSign.Count, $CertificateThumbprint)
$failed = New-Object System.Collections.Generic.List[string]

foreach ($file in $filesToSign) {
    $result = Set-AuthenticodeSignature -FilePath $file -Certificate $certificate -TimestampServer $TimestampServer
    if ($result.Status -ne "Valid") {
        [void]$failed.Add(("{0} => {1}" -f $file, $result.Status))
    } else {
        Write-Host ("Signed: {0}" -f $file)
    }
}

if ($failed.Count -gt 0) {
    throw ("Signing failed for:`n- " + ($failed -join "`n- "))
}

Write-Host "Release signing complete."
