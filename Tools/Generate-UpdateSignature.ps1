param(
    [string]$RepoRoot = "",
    [string]$InputFile = "Script/Teams Always Green.ps1",
    [Parameter(Mandatory = $true)][string]$PrivateKeyPath,
    [string]$SignaturePath = "",
    [ValidateSet("Hex", "Base64")][string]$OutputEncoding = "Hex",
    [string]$PublicKeyPath = "",
    [switch]$Verify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-PathUnderRepo([string]$repoRootPath, [string]$candidate) {
    if ([string]::IsNullOrWhiteSpace($candidate)) { return "" }
    if ([System.IO.Path]::IsPathRooted($candidate)) { return $candidate }
    return (Join-Path $repoRootPath $candidate)
}

function Convert-SignatureBytesToText([byte[]]$bytes, [string]$encoding) {
    if (-not $bytes) { return "" }
    if ($encoding -eq "Base64") { return [Convert]::ToBase64String($bytes) }
    return ([BitConverter]::ToString($bytes)).Replace("-", "")
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

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $scriptDir = [string]$PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($scriptDir) -and $PSCommandPath) {
        $scriptDir = Split-Path -Parent $PSCommandPath
    }
    if ([string]::IsNullOrWhiteSpace($scriptDir)) {
        $scriptDir = (Get-Location).Path
    }
    $RepoRoot = Join-Path $scriptDir ".."
}
$repoRootAbs = (Resolve-Path $RepoRoot).Path
$inputAbs = Resolve-PathUnderRepo -repoRootPath $repoRootAbs -candidate $InputFile
$privateKeyAbs = Resolve-PathUnderRepo -repoRootPath $repoRootAbs -candidate $PrivateKeyPath

if (-not (Test-Path -LiteralPath $inputAbs -PathType Leaf)) {
    throw "Input file not found: $inputAbs"
}
if (-not (Test-Path -LiteralPath $privateKeyAbs -PathType Leaf)) {
    throw "Private key file not found: $privateKeyAbs"
}

if ([string]::IsNullOrWhiteSpace($SignaturePath)) {
    $SignaturePath = ($inputAbs + ".sig")
}
$signatureAbs = Resolve-PathUnderRepo -repoRootPath $repoRootAbs -candidate $SignaturePath
$signatureDir = Split-Path -Parent $signatureAbs
if (-not [string]::IsNullOrWhiteSpace($signatureDir) -and -not (Test-Path -LiteralPath $signatureDir -PathType Container)) {
    New-Item -ItemType Directory -Path $signatureDir -Force | Out-Null
}

$privateKeyXml = (Get-Content -Path $privateKeyAbs -Raw -ErrorAction Stop).Trim()
if ([string]::IsNullOrWhiteSpace($privateKeyXml)) {
    throw "Private key file is empty: $privateKeyAbs"
}

$data = [System.IO.File]::ReadAllBytes($inputAbs)
$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
$rsa.FromXmlString($privateKeyXml)
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $signatureBytes = $rsa.SignData($data, $sha)
} finally {
    $sha.Dispose()
    $rsa.Dispose()
}

$signatureText = Convert-SignatureBytesToText -bytes $signatureBytes -encoding $OutputEncoding
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($signatureAbs, ($signatureText + "`r`n"), $utf8NoBom)
Write-Host ("Generated update signature: {0}" -f $signatureAbs)

$verifyRequested = $Verify -or -not [string]::IsNullOrWhiteSpace($PublicKeyPath)
if ($verifyRequested) {
    if ([string]::IsNullOrWhiteSpace($PublicKeyPath)) {
        throw "PublicKeyPath is required when -Verify is used."
    }
    $publicKeyAbs = Resolve-PathUnderRepo -repoRootPath $repoRootAbs -candidate $PublicKeyPath
    if (-not (Test-Path -LiteralPath $publicKeyAbs -PathType Leaf)) {
        throw "Public key file not found: $publicKeyAbs"
    }
    $publicKeyXml = (Get-Content -Path $publicKeyAbs -Raw -ErrorAction Stop).Trim()
    if ([string]::IsNullOrWhiteSpace($publicKeyXml)) {
        throw "Public key file is empty: $publicKeyAbs"
    }
    $writtenSignatureBytes = Convert-SignatureTextToBytes (Get-Content -Path $signatureAbs -Raw)
    if (-not $writtenSignatureBytes -or $writtenSignatureBytes.Length -eq 0) {
        throw "Generated signature could not be parsed for verification."
    }
    $verifier = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $verifier.FromXmlString($publicKeyXml)
    $verifySha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $ok = $verifier.VerifyData($data, $verifySha, $writtenSignatureBytes)
    } finally {
        $verifySha.Dispose()
        $verifier.Dispose()
    }
    if (-not $ok) {
        throw "Generated signature verification failed."
    }
    Write-Host "Signature verification succeeded."
}
