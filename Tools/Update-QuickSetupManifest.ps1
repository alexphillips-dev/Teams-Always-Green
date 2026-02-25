Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Is-TextFile([string]$relativePath) {
    $ext = [System.IO.Path]::GetExtension($relativePath)
    if ([string]::IsNullOrWhiteSpace($ext)) { return $true }
    $ext = $ext.ToLowerInvariant()
    return @(".ps1", ".cmd", ".vbs", ".json", ".xml", ".md", ".txt", ".log", ".csv", ".ini") -contains $ext
}

function Get-NormalizedBytesHash([string]$path, [string]$lineEnding) {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    if (-not $bytes) { return $null }

    $normalized = New-Object System.Collections.Generic.List[byte]
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $b = $bytes[$i]
        if ($b -eq 0x0D) {
            if (($i + 1) -lt $bytes.Length -and $bytes[$i + 1] -eq 0x0A) { $i++ }
            $normalized.Add(0x0A)
            continue
        }
        $normalized.Add($b)
    }

    if ($lineEnding -eq "CRLF") {
        $withCrLf = New-Object System.Collections.Generic.List[byte]
        foreach ($b in $normalized) {
            if ($b -eq 0x0A) {
                $withCrLf.Add(0x0D)
                $withCrLf.Add(0x0A)
            } else {
                $withCrLf.Add($b)
            }
        }
        $normalized = $withCrLf
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($normalized.ToArray())
        return ([BitConverter]::ToString($hash)).Replace("-", "")
    } finally {
        $sha.Dispose()
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $repoRoot "Script\\QuickSetup\\QuickSetup.manifest.json"
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Manifest not found: $manifestPath"
}

$manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
$lineEnding = [string]$manifest.normalizedLineEndings
if ([string]::IsNullOrWhiteSpace($lineEnding)) { $lineEnding = "LF" }

# Ensure new core module is present in manifest.
$required = @(
    "Script/Core/AppInfo.ps1"
)
foreach ($rel in $required) {
    if (-not ($manifest.files.PSObject.Properties.Name -contains $rel)) {
        $manifest.files | Add-Member -MemberType NoteProperty -Name $rel -Value "" -Force
    }
}

$updates = 0
foreach ($prop in @($manifest.files.PSObject.Properties)) {
    $rel = [string]$prop.Name
    $full = Join-Path $repoRoot ($rel -replace "/", "\\")
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        Write-Warning ("Skipping missing file: {0}" -f $rel)
        continue
    }
    $hash = $null
    if (Is-TextFile $rel) {
        $hash = Get-NormalizedBytesHash $full $lineEnding
    } else {
        $hash = (Get-FileHash -Algorithm SHA256 -Path $full).Hash
    }
    if ([string]$prop.Value -ne [string]$hash) {
        $manifest.files.$rel = [string]$hash
        $updates++
    }
}

$manifest.generatedAt = (Get-Date).ToString("o")
$json = $manifest | ConvertTo-Json -Depth 6
Set-Content -Path $manifestPath -Value $json -Encoding UTF8
Write-Host ("Updated QuickSetup manifest. Files changed={0}" -f $updates)
