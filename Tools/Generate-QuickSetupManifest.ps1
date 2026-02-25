param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$ManifestPath = "Script/QuickSetup/QuickSetup.manifest.json",
    [string]$SignaturePath = "Script/QuickSetup/QuickSetup.manifest.sig",
    [string]$ManifestPrivateKeyPath = "",
    [string]$ManifestPublicKeyPath = "",
    [ValidateSet("LF", "CRLF")][string]$NormalizedLineEndings = "LF",
    [switch]$Check,
    [switch]$Sign,
    [switch]$RequireSignature
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Convert-ToManifestPath([string]$path) {
    return ($path -replace "\\", "/")
}

function Get-IsTextFile([string]$manifestPath) {
    $ext = [System.IO.Path]::GetExtension($manifestPath)
    if ([string]::IsNullOrWhiteSpace($ext)) { return $true }
    $ext = $ext.ToLowerInvariant()
    return @(".ps1", ".cmd", ".vbs", ".json", ".xml", ".md", ".txt", ".log", ".csv", ".ini") -contains $ext
}

function Get-NormalizedBytesHash([string]$path, [string]$lineEnding) {
    $bytes = [System.IO.File]::ReadAllBytes($path)
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

function Get-QuickSetupManifestFiles([string]$quickSetupPath) {
    $raw = Get-Content -Path $quickSetupPath -Raw
    $blockMatch = [regex]::Match(
        $raw,
        '(?ms)^\$script:QuickSetupFiles\s*=\s*@\((?<body>.*?)^\)\s*$'
    )
    if (-not $blockMatch.Success) {
        throw "Could not find `$script:QuickSetupFiles block in QuickSetup.ps1."
    }

    $body = $blockMatch.Groups["body"].Value
    $pathMatches = [regex]::Matches($body, 'Path\s*=\s*"(?<path>[^"]+)"')
    if ($pathMatches.Count -eq 0) {
        throw "No Path entries found in `$script:QuickSetupFiles block."
    }

    $seen = @{}
    $ordered = New-Object System.Collections.Generic.List[string]
    foreach ($match in $pathMatches) {
        $path = [string]$match.Groups["path"].Value
        if (-not $seen.ContainsKey($path)) {
            $seen[$path] = $true
            [void]$ordered.Add($path)
        }
    }
    return $ordered
}

function Get-ManifestCanonicalJson([hashtable]$files, [string]$normalizedLineEndings) {
    $canonical = [ordered]@{
        hashAlgorithm = "SHA256"
        normalizedLineEndings = $normalizedLineEndings
        generatedAt = ""
        files = [ordered]@{}
    }
    foreach ($key in @($files.Keys | Sort-Object)) {
        $canonical.files[$key] = [string]$files[$key]
    }
    return ($canonical | ConvertTo-Json -Depth 8 -Compress)
}

function Convert-SignatureTextToBytes([string]$signatureText) {
    if ([string]::IsNullOrWhiteSpace($signatureText)) { return $null }
    $trimmed = $signatureText.Trim()
    if ($trimmed -match '^[A-Fa-f0-9]+$') {
        if (($trimmed.Length % 2) -ne 0) { return $null }
        $bytes = New-Object byte[] ($trimmed.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $bytes[$i] = [Convert]::ToByte($trimmed.Substring($i * 2, 2), 16)
        }
        return $bytes
    }
    try {
        return [Convert]::FromBase64String($trimmed)
    } catch {
        return $null
    }
}

function New-ManifestSignatureHex([string]$canonicalJson, [string]$privateKeyXml) {
    $data = [System.Text.Encoding]::UTF8.GetBytes($canonicalJson)
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.FromXmlString($privateKeyXml)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $signature = $rsa.SignData($data, $sha)
        return ([BitConverter]::ToString($signature)).Replace("-", "")
    } finally {
        $sha.Dispose()
        $rsa.Dispose()
    }
}

function Test-ManifestSignature([string]$canonicalJson, [string]$signatureText, [string]$publicKeyXml) {
    if ([string]::IsNullOrWhiteSpace($canonicalJson) -or [string]::IsNullOrWhiteSpace($signatureText) -or [string]::IsNullOrWhiteSpace($publicKeyXml)) {
        return $false
    }
    $signatureBytes = Convert-SignatureTextToBytes $signatureText
    if (-not $signatureBytes -or $signatureBytes.Length -eq 0) { return $false }
    try {
        $data = [System.Text.Encoding]::UTF8.GetBytes($canonicalJson)
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.FromXmlString($publicKeyXml)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            return $rsa.VerifyData($data, $sha, $signatureBytes)
        } finally {
            $sha.Dispose()
            $rsa.Dispose()
        }
    } catch {
        return $false
    }
}

$repoRoot = (Resolve-Path $RepoRoot).Path
$manifestAbsPath = if ([System.IO.Path]::IsPathRooted($ManifestPath)) { $ManifestPath } else { Join-Path $repoRoot $ManifestPath }
$signatureAbsPath = if ([System.IO.Path]::IsPathRooted($SignaturePath)) { $SignaturePath } else { Join-Path $repoRoot $SignaturePath }
$quickSetupPath = Join-Path $repoRoot "Script/QuickSetup/QuickSetup.ps1"
if (-not (Test-Path $quickSetupPath)) {
    throw "QuickSetup.ps1 was not found at: $quickSetupPath"
}

$manifestPaths = Get-QuickSetupManifestFiles -quickSetupPath $quickSetupPath
$files = [ordered]@{}
foreach ($relativePath in $manifestPaths) {
    $absolutePath = Join-Path $repoRoot $relativePath
    if (-not (Test-Path $absolutePath)) {
        throw "Manifest entry points to missing file: $relativePath"
    }

    $manifestKey = Convert-ToManifestPath $relativePath
    if (Get-IsTextFile $manifestKey) {
        $hash = Get-NormalizedBytesHash -path $absolutePath -lineEnding $NormalizedLineEndings
    } else {
        $hash = (Get-FileHash -Algorithm SHA256 -Path $absolutePath).Hash
    }
    $files[$manifestKey] = $hash
}

$generatedManifest = [ordered]@{
    hashAlgorithm = "SHA256"
    normalizedLineEndings = $NormalizedLineEndings
    generatedAt = (Get-Date).ToString("o")
    files = $files
}
$canonicalJson = Get-ManifestCanonicalJson -files $files -normalizedLineEndings $NormalizedLineEndings

if ($Check) {
    if (-not (Test-Path $manifestAbsPath)) {
        throw "Manifest file not found: $manifestAbsPath"
    }

    $existing = Get-Content -Path $manifestAbsPath -Raw | ConvertFrom-Json
    $differences = New-Object System.Collections.Generic.List[string]

    if ([string]$existing.hashAlgorithm -ne "SHA256") {
        [void]$differences.Add("hashAlgorithm expected SHA256 but found '$($existing.hashAlgorithm)'")
    }
    if ([string]$existing.normalizedLineEndings -ne $NormalizedLineEndings) {
        [void]$differences.Add("normalizedLineEndings expected '$NormalizedLineEndings' but found '$($existing.normalizedLineEndings)'")
    }

    $existingKeys = @()
    if ($existing.files) { $existingKeys = @($existing.files.PSObject.Properties.Name) }
    $generatedKeys = @($files.Keys)
    $missingKeys = @($generatedKeys | Where-Object { $_ -notin $existingKeys })
    $extraKeys = @($existingKeys | Where-Object { $_ -notin $generatedKeys })
    if ($missingKeys.Count -gt 0) { [void]$differences.Add("missing keys: $($missingKeys -join ', ')") }
    if ($extraKeys.Count -gt 0) { [void]$differences.Add("extra keys: $($extraKeys -join ', ')") }

    foreach ($key in $generatedKeys) {
        $expected = [string]$files[$key]
        $actual = if ($existing.files.PSObject.Properties.Name -contains $key) { [string]$existing.files.$key } else { "" }
        if ($actual -ne $expected) {
            [void]$differences.Add("hash mismatch for '$key'")
        }
    }

    $signatureExists = (Test-Path -LiteralPath $signatureAbsPath -PathType Leaf)
    if ($RequireSignature -and -not $signatureExists) {
        [void]$differences.Add(("signature file missing: '{0}'" -f $signatureAbsPath))
    }
    if ($signatureExists) {
        $existingSignature = (Get-Content -Path $signatureAbsPath -Raw).Trim()
        if ([string]::IsNullOrWhiteSpace($existingSignature)) {
            [void]$differences.Add("signature file is empty")
        } elseif (-not (Convert-SignatureTextToBytes $existingSignature)) {
            [void]$differences.Add("signature format invalid")
        } elseif (-not [string]::IsNullOrWhiteSpace($ManifestPublicKeyPath)) {
            $publicKeyPath = if ([System.IO.Path]::IsPathRooted($ManifestPublicKeyPath)) { $ManifestPublicKeyPath } else { Join-Path $repoRoot $ManifestPublicKeyPath }
            if (-not (Test-Path -LiteralPath $publicKeyPath -PathType Leaf)) {
                [void]$differences.Add(("public key file missing: '{0}'" -f $publicKeyPath))
            } else {
                $publicKeyXml = (Get-Content -Path $publicKeyPath -Raw).Trim()
                if (-not (Test-ManifestSignature -canonicalJson $canonicalJson -signatureText $existingSignature -publicKeyXml $publicKeyXml)) {
                    [void]$differences.Add("signature verification failed")
                }
            }
        }
    }

    if ($differences.Count -gt 0) {
        Write-Error ("QuickSetup.manifest.json is out of date:`n- " + ($differences -join "`n- "))
        exit 1
    }

    Write-Host "QuickSetup.manifest.json is up to date."
    exit 0
}

$json = $generatedManifest | ConvertTo-Json -Depth 6
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($manifestAbsPath, ($json + "`r`n"), $utf8NoBom)
Write-Host "Updated manifest: $manifestAbsPath"
if ($Sign) {
    if ([string]::IsNullOrWhiteSpace($ManifestPrivateKeyPath)) {
        throw "ManifestPrivateKeyPath is required when -Sign is used."
    }
    $privateKeyPath = if ([System.IO.Path]::IsPathRooted($ManifestPrivateKeyPath)) { $ManifestPrivateKeyPath } else { Join-Path $repoRoot $ManifestPrivateKeyPath }
    if (-not (Test-Path -LiteralPath $privateKeyPath -PathType Leaf)) {
        throw "Manifest private key file not found: $privateKeyPath"
    }
    $privateKeyXml = (Get-Content -Path $privateKeyPath -Raw).Trim()
    if ([string]::IsNullOrWhiteSpace($privateKeyXml)) {
        throw "Manifest private key file is empty: $privateKeyPath"
    }
    $signatureHex = New-ManifestSignatureHex -canonicalJson $canonicalJson -privateKeyXml $privateKeyXml
    [System.IO.File]::WriteAllText($signatureAbsPath, ($signatureHex + "`r`n"), $utf8NoBom)
    Write-Host "Updated signature: $signatureAbsPath"
}
