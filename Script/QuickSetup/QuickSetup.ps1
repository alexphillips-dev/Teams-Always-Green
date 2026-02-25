# QuickSetup.ps1 - Download and install Teams Always Green into a chosen folder
# Creates Desktop, Start Menu, and Startup shortcuts (no VBS needed).

Add-Type -AssemblyName System.Windows.Forms
$ErrorActionPreference = 'Stop'
trap {
    Write-Error ("QuickSetup error at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
    throw
}

$script:QuickSetupStateDir = Join-Path $env:LOCALAPPDATA "TeamsAlwaysGreen"
$script:QuickSetupLastPathFile = Join-Path $script:QuickSetupStateDir "QuickSetup.lastpath.txt"
$script:QuickSetupManifestRelativePath = "Script\QuickSetup\QuickSetup.manifest.json"
$script:QuickSetupManifestSignatureRelativePath = "Script\QuickSetup\QuickSetup.manifest.sig"
$script:QuickSetupManifestSignaturePublicKeyXml = @'
<RSAKeyValue><Modulus>x5tns2fd2g/AZEs6ciZ+nWS2RfG5UN5mq+T2QGBS+UfX5uoTlffG123lTwRvMIZY+iecs20UtpR5gYx/ZYjtZuGqHyuBfsTd2dYWzyPonAYqlksAM9sADNMrSFjxeoXeOl+i/sZeprZl/Vahk1Z8G+sgxxMaiVYjGBAmfSZ9yKfI+M3r4cJQzwvpo+nlMHRZN8T0R7FWRJdrG+dNPgR/BefkXUiO+xmQBW0ej4PPMmuN5jPcUiS0c194CrTHuL8hn+lHA3PyGuUeFPurthv256HZ8H6+KIEQhULQMcSEgQGEKwSIwIYPFY9DuzHU6j6FphZR/DobJIEItQT2NVFM1oaFm7W0ImWhxJ5q80UL7D5Nb83KFXQ/P2hPTDRrm7XbYUR+diUfa/8yRxW2SLzvn8kzPmobMXLy0IN9X9SV0zXOpW/ChcbppcMAO9iQ6ogPmLYpERtBwjIGi2oLSKNSdJ69n4GAmwmMJD+UHWlbbmvH59L3bi82cn3tCHCyqkSZhCWi2uZj6AYfdtq0D8i9wqFWYE8IYsXhQnlpLzhqeDHoQ3ZWZ/heGG9aLdIT3IkHIiTpIfUCbYgqPikMKYbNjAaNDAlhvkruchMVIFo0qnYx7879eKlKpsH2IAUBtadLL96WcmocP5z+qpo4bw9knoqiRcz7icMUsIJxl/9kY4E=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>
'@
$script:QuickSetupRequireManifestSignature = $true
$script:QuickSetupTrustedOwner = "alexphillips-dev"
$script:QuickSetupTrustedRepo = "Teams-Always-Green"

function Test-QuickSetupTrustedUrl([string]$url) {
    if ([string]::IsNullOrWhiteSpace($url)) { return $false }
    try {
        $uri = [System.Uri]$url
        if ($uri.Scheme -ne "https") { return $false }
        if ([string]::IsNullOrWhiteSpace($uri.Host)) { return $false }
        $urlHost = $uri.Host.ToLowerInvariant()
        if ($urlHost -ne "raw.githubusercontent.com") { return $false }
        $path = [string]$uri.AbsolutePath
        if ([string]::IsNullOrWhiteSpace($path)) { return $false }
        $expectedPrefix = ("/{0}/{1}/" -f $script:QuickSetupTrustedOwner, $script:QuickSetupTrustedRepo).ToLowerInvariant()
        return $path.ToLowerInvariant().StartsWith($expectedPrefix)
    } catch {
        return $false
    }
}

function Test-QuickSetupManifest([object]$manifest, [object[]]$files) {
    if (-not $manifest) {
        return [pscustomobject]@{ IsValid = $false; Reason = "Manifest is missing." }
    }
    if (-not $manifest.files) {
        return [pscustomobject]@{ IsValid = $false; Reason = "Manifest file hash table is missing." }
    }

    $algorithm = if ($manifest.PSObject.Properties.Name -contains "hashAlgorithm") { [string]$manifest.hashAlgorithm } else { "" }
    if ($algorithm.ToUpperInvariant() -ne "SHA256") {
        return [pscustomobject]@{ IsValid = $false; Reason = "Manifest hash algorithm must be SHA256." }
    }

    $lineEnding = if ($manifest.PSObject.Properties.Name -contains "normalizedLineEndings") { [string]$manifest.normalizedLineEndings } else { "" }
    if ($lineEnding -notin @("LF", "CRLF")) {
        return [pscustomobject]@{ IsValid = $false; Reason = "Manifest normalizedLineEndings must be LF or CRLF." }
    }

    foreach ($file in @($files)) {
        if (-not $file -or [string]::IsNullOrWhiteSpace([string]$file.Path)) { continue }
        $key = [string]$file.Path
        $manifestKey = $key.Replace("\", "/")
        if (-not ($manifest.files.PSObject.Properties.Name -contains $manifestKey)) {
            return [pscustomobject]@{ IsValid = $false; Reason = ("Manifest missing hash for {0}." -f $key) }
        }
        $expected = [string]$manifest.files.$manifestKey
        if ([string]::IsNullOrWhiteSpace($expected) -or ($expected -notmatch '^[A-Fa-f0-9]{64}$')) {
            return [pscustomobject]@{ IsValid = $false; Reason = ("Manifest hash format invalid for {0}." -f $key) }
        }
    }

    return [pscustomobject]@{ IsValid = $true; Reason = "" }
}

function Get-LastInstallBase {
    try {
        if (Test-Path $script:QuickSetupLastPathFile) {
            $text = Get-Content -Path $script:QuickSetupLastPathFile -ErrorAction Stop | Select-Object -First 1
            if (-not [string]::IsNullOrWhiteSpace($text)) { return $text.Trim() }
        }
    } catch { $null = $_ }
    return [Environment]::GetFolderPath("MyDocuments")
}

function Set-LastInstallBase([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return }
    try {
        if (-not (Test-Path $script:QuickSetupStateDir)) {
            New-Item -ItemType Directory -Path $script:QuickSetupStateDir -Force | Out-Null
        }
        Set-Content -Path $script:QuickSetupLastPathFile -Value $path -Encoding ASCII
    } catch { $null = $_ }
}

function Get-QuickSetupSourceRoot {
    $seedDirs = @()
    if ($PSScriptRoot) { $seedDirs += $PSScriptRoot }
    if ($PSCommandPath) { $seedDirs += (Split-Path -Parent $PSCommandPath) }
    if ($MyInvocation.MyCommand.Path) { $seedDirs += (Split-Path -Parent $MyInvocation.MyCommand.Path) }

    $seen = @{}
    foreach ($seed in $seedDirs) {
        if ([string]::IsNullOrWhiteSpace($seed)) { continue }
        $probe0 = $seed
        $probe1 = $null
        $probe2 = $null
        try { $probe1 = Split-Path -Path $probe0 -Parent } catch { $null = $_ }
        if (-not [string]::IsNullOrWhiteSpace($probe1)) {
            try { $probe2 = Split-Path -Path $probe1 -Parent } catch { $null = $_ }
        }

        foreach ($probe in @($probe0, $probe1, $probe2)) {
            if ([string]::IsNullOrWhiteSpace($probe)) { continue }
            $probeFull = $probe
            try { $probeFull = [System.IO.Path]::GetFullPath($probe) } catch { $null = $_ }
            if ($seen.ContainsKey($probeFull)) { continue }
            $seen[$probeFull] = $true
            if (Test-Path (Join-Path $probeFull "Script\Teams Always Green.ps1")) {
                return $probeFull
            }
        }
    }
    return $null
}

function Get-QuickSetupLocalIconPath {
    $sourceRoot = Get-QuickSetupSourceRoot
    if (-not $sourceRoot) { return $null }
    $iconPath = Join-Path $sourceRoot "Meta\Icons\Tray_Icon.ico"
    if (Test-Path $iconPath) { return $iconPath }
    return $null
}

function Get-RecommendedInstallPath {
    $base = Join-Path $env:LOCALAPPDATA "Programs"
    return (Join-Path $base "Teams Always Green")
}

function Get-OneDrivePathDiagnostics([string]$path) {
    $resolved = ""
    if (-not [string]::IsNullOrWhiteSpace($path)) {
        try {
            $resolved = [System.IO.Path]::GetFullPath($path)
        } catch {
            $resolved = [string]$path
        }
    }

    $signals = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($resolved)) {
        foreach ($candidate in @([string]$env:OneDriveCommercial, [string]$env:OneDriveConsumer, [string]$env:OneDrive)) {
            if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
            $root = ""
            try { $root = [System.IO.Path]::GetFullPath($candidate).TrimEnd('\') } catch { $root = [string]$candidate.TrimEnd('\') }
            if ([string]::IsNullOrWhiteSpace($root)) { continue }
            if ($resolved.Equals($root, [System.StringComparison]::OrdinalIgnoreCase) -or
                $resolved.StartsWith(($root + "\"), [System.StringComparison]::OrdinalIgnoreCase)) {
                $signals.Add(("UnderOneDriveRoot={0}" -f $root))
            }
        }

        if ($resolved -match '(?i)[\\/](OneDrive)(\s-\s[^\\/]+)?([\\/]|$)') {
            $signals.Add("OneDrivePathLike=True")
        }

        try {
            $current = $resolved
            while (-not [string]::IsNullOrWhiteSpace($current) -and (Test-Path -LiteralPath $current)) {
                $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
                if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                    $signals.Add(("ReparsePointAt={0}" -f $current))
                    break
                }
                $parent = Split-Path -Path $current -Parent
                if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) { break }
                $current = $parent
            }
        } catch { $null = $_ }
    }

    $uniqueSignals = @($signals | Select-Object -Unique)
    return [pscustomobject]@{
        Path = $resolved
        IsOneDriveManaged = ($uniqueSignals.Count -gt 0)
        Signals = $uniqueSignals
        Summary = if ($uniqueSignals.Count -gt 0) { $uniqueSignals -join "; " } else { "none" }
        RecommendedInstallPath = (Get-RecommendedInstallPath)
    }
}

$tempRoot = $env:TEMP
if ([string]::IsNullOrWhiteSpace($tempRoot)) { $tempRoot = $env:TMP }
if ([string]::IsNullOrWhiteSpace($tempRoot)) { $tempRoot = [System.IO.Path]::GetTempPath() }
if ([string]::IsNullOrWhiteSpace($tempRoot)) { $tempRoot = (Get-Location).Path }
$logPath = Join-Path $tempRoot "TeamsAlwaysGreen-QuickSetup.log"
$script:DisableSetupLog = $false
function Write-SetupLog([string]$message) {
    if ($script:DisableSetupLog) { return }
    try {
        $line = "[{0}] {1}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $message
        Add-Content -Path $logPath -Value $line
    } catch {
                $null = $_
            }
}

function Cleanup-SetupTempFiles {
    param([bool]$success)
    if (-not $success) { return }
    $script:DisableSetupLog = $true
    $paths = @()
    if ($script:WelcomeTempIconPath) { $paths += $script:WelcomeTempIconPath }
    $paths += (Join-Path $tempRoot "TeamsAlwaysGreen-Welcome.ico")
    $paths += (Join-Path $tempRoot "TeamsAlwaysGreen-QuickSetup.log")
    foreach ($path in ($paths | Select-Object -Unique)) {
        if ($path -and (Test-Path $path)) {
            try { Remove-Item -Path $path -Force -ErrorAction Stop } catch { $null = $_ }
        }
    }
    try {
        Get-ChildItem -Path $tempRoot -Filter "TeamsAlwaysGreen-QuickSetup*.ps1" -ErrorAction SilentlyContinue | ForEach-Object {
            try { Remove-Item -Path $_.FullName -Force -ErrorAction Stop } catch { $null = $_ }
        }
    } catch {
                $null = $_
            }
    try {
        Get-ChildItem -Path $tempRoot -Filter "teams-always-green-run.*" -ErrorAction SilentlyContinue | ForEach-Object {
            try { Remove-Item -Path $_.FullName -Force -ErrorAction Stop } catch { $null = $_ }
        }
    } catch {
                $null = $_
            }

    # Schedule a delayed cleanup to handle files still locked by the shell/editor.
    try {
        $cleanupScript = Join-Path $tempRoot ("TeamsAlwaysGreen-Cleanup-" + [Guid]::NewGuid().ToString("N") + ".ps1")
        $targetsLine = ('$targets = @("{0}\TeamsAlwaysGreen-QuickSetup.log","{0}\TeamsAlwaysGreen-Welcome.ico","{0}\teams-always-green-run.err","{0}\teams-always-green-run.out")' -f $tempRoot)
        $lines = @(
            '$ErrorActionPreference = "SilentlyContinue"'
            'Start-Sleep -Seconds 2'
            $targetsLine
            'foreach ($t in $targets) { if ([string]::IsNullOrWhiteSpace($t)) { continue }; for ($i=0; $i -lt 5; $i++) { Remove-Item -Force -ErrorAction SilentlyContinue $t; if (-not (Test-Path $t)) { break }; Start-Sleep -Milliseconds 400 } }'
            ('Get-ChildItem -Path "{0}" -Filter "TeamsAlwaysGreen-QuickSetup*.ps1" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue' -f $tempRoot)
            ('Remove-Item -Force -ErrorAction SilentlyContinue "{0}"' -f $cleanupScript)
        )
        Set-Content -Path $cleanupScript -Value ($lines -join "`r`n") -Encoding ASCII
        Start-Process "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -WindowStyle Hidden -File `"$cleanupScript`"" -WindowStyle Hidden
    } catch {
                $null = $_
            }
}

function Show-SetupError([string]$message) {
    Write-SetupLog "ERROR: $message"
    Show-SetupPrompt -message ($message + "`n`nLog: $logPath") -title "Quick Setup" -buttons ([System.Windows.Forms.MessageBoxButtons]::OK) -icon ([System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
}

function Show-SetupInfo {
    param(
        [string]$message,
        [System.Windows.Forms.Form]$owner
    )
    if ([string]::IsNullOrWhiteSpace($message)) { return }
    Write-SetupLog ("INFO: {0}" -f $message)
    Show-SetupPrompt -message $message -title "Quick Setup" -buttons ([System.Windows.Forms.MessageBoxButtons]::OK) -icon ([System.Windows.Forms.MessageBoxIcon]::Information) -owner $owner | Out-Null
}

function Show-SetupPrompt {
    param(
        [string]$message,
        [string]$title,
        [System.Windows.Forms.MessageBoxButtons]$buttons,
        [System.Windows.Forms.MessageBoxIcon]$icon,
        [System.Windows.Forms.Form]$owner
    )
    $localOwner = $owner
    if (-not $localOwner) {
        $localOwner = New-Object System.Windows.Forms.Form
        $localOwner.Width = 1
        $localOwner.Height = 1
        $localOwner.StartPosition = "CenterScreen"
        $localOwner.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
        $localOwner.ShowInTaskbar = $false
        $localOwner.TopMost = $true
        $localOwner.Opacity = 0
        $localOwner.Show()
        [System.Windows.Forms.Application]::DoEvents()
    }
    $result = [System.Windows.Forms.MessageBox]::Show($localOwner, $message, $title, $buttons, $icon)
    if (-not $owner -and $localOwner) { $localOwner.Close() }
    return $result
}

function New-SetupOwner {
    $owner = New-Object System.Windows.Forms.Form
    $owner.Width = 1
    $owner.Height = 1
    $owner.StartPosition = "CenterScreen"
    $owner.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
    $owner.ShowInTaskbar = $false
    $owner.TopMost = $true
    $owner.Opacity = 0
    $owner.Show()
    [System.Windows.Forms.Application]::DoEvents()
    return $owner
}

function Get-FileHashHex([string]$path) {
    try {
        return (Get-FileHash -Algorithm SHA256 -Path $path -ErrorAction Stop).Hash
    } catch {
        return $null
    }
}

function Is-TextFile([string]$relativePath) {
    $ext = [System.IO.Path]::GetExtension($relativePath)
    if ([string]::IsNullOrWhiteSpace($ext)) { return $true }
    $ext = $ext.ToLowerInvariant()
    return @(".ps1", ".cmd", ".vbs", ".json", ".xml", ".md", ".txt", ".log", ".csv", ".ini") -contains $ext
}

function Get-NormalizedBytesHash([string]$path, [string]$lineEnding) {
    try {
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
        $hash = $sha.ComputeHash($normalized.ToArray())
        return ([BitConverter]::ToString($hash)).Replace("-", "")
    } catch {
        return $null
    }
}

function Load-Manifest([string]$path) {
    if (-not (Test-Path $path)) { return $null }
    try {
        $raw = Get-Content -Path $path -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return $raw | ConvertFrom-Json
    } catch {
        return $null
    }
}

function Load-ManifestSignature([string]$path) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $raw = (Get-Content -Path $path -Raw -ErrorAction Stop).Trim()
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return $raw
    } catch {
        return $null
    }
}

function Get-ManifestCanonicalJson([object]$manifest) {
    if (-not $manifest -or -not $manifest.files) { return $null }
    $files = [ordered]@{}
    foreach ($key in @($manifest.files.PSObject.Properties.Name | Sort-Object)) {
        $files[[string]$key] = [string]$manifest.files.$key
    }
    $canonical = [ordered]@{
        hashAlgorithm = [string]$manifest.hashAlgorithm
        normalizedLineEndings = [string]$manifest.normalizedLineEndings
        generatedAt = ""
        files = $files
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

function Test-QuickSetupManifestSignature {
    param(
        [object]$manifest,
        [string]$signatureText,
        [string]$publicKeyXml,
        [switch]$RequireSignature
    )

    if ([string]::IsNullOrWhiteSpace($signatureText)) {
        if ($RequireSignature) {
            return [pscustomobject]@{ IsValid = $false; Status = "Missing"; Reason = "Manifest signature is required but missing." }
        }
        return [pscustomobject]@{ IsValid = $true; Status = "Missing"; Reason = "" }
    }
    if ([string]::IsNullOrWhiteSpace($publicKeyXml)) {
        if ($RequireSignature) {
            return [pscustomobject]@{ IsValid = $false; Status = "NoPublicKey"; Reason = "Manifest signature is present but no trusted public key is configured." }
        }
        return [pscustomobject]@{ IsValid = $true; Status = "NoPublicKey"; Reason = "" }
    }

    $signatureBytes = Convert-SignatureTextToBytes $signatureText
    if (-not $signatureBytes -or $signatureBytes.Length -eq 0) {
        return [pscustomobject]@{ IsValid = $false; Status = "InvalidSignatureFormat"; Reason = "Manifest signature format is invalid." }
    }

    $canonical = Get-ManifestCanonicalJson $manifest
    if ([string]::IsNullOrWhiteSpace($canonical)) {
        return [pscustomobject]@{ IsValid = $false; Status = "InvalidManifest"; Reason = "Manifest canonical payload is unavailable." }
    }

    try {
        $data = [System.Text.Encoding]::UTF8.GetBytes($canonical)
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.FromXmlString($publicKeyXml)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $ok = $rsa.VerifyData($data, $sha, $signatureBytes)
        } finally {
            $sha.Dispose()
            $rsa.Dispose()
        }
        if ($ok) {
            return [pscustomobject]@{ IsValid = $true; Status = "Verified"; Reason = "" }
        }
        return [pscustomobject]@{ IsValid = $false; Status = "InvalidSignature"; Reason = "Manifest signature verification failed." }
    } catch {
        return [pscustomobject]@{ IsValid = $false; Status = "VerificationError"; Reason = $_.Exception.Message }
    }
}

function Get-ManifestExpectedHash([object]$manifest, [string]$relativePath) {
    if (-not $manifest -or -not $manifest.files -or [string]::IsNullOrWhiteSpace($relativePath)) { return $null }
    $manifestKey = $relativePath.Replace("\", "/")
    if ($manifest.files.PSObject.Properties.Name -contains $manifestKey) {
        return [string]$manifest.files.$manifestKey
    }
    return $null
}

function Test-AssetHashMatchesManifest([object]$manifest, [string]$relativePath, [string]$path) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return [pscustomobject]@{ IsValid = $false; Reason = "Asset file is missing."; Actual = ""; Expected = "" }
    }

    $expected = Get-ManifestExpectedHash -manifest $manifest -relativePath $relativePath
    if ([string]::IsNullOrWhiteSpace($expected)) {
        return [pscustomobject]@{ IsValid = $false; Reason = "Manifest expected hash is missing."; Actual = ""; Expected = "" }
    }

    $actual = Get-FileHashHex $path
    if (-not $actual -or ($actual.ToLowerInvariant() -ne [string]$expected.ToLowerInvariant())) {
        $matched = $false
        if (Is-TextFile $relativePath) {
            $lineEnding = if ($manifest -and $manifest.normalizedLineEndings) { [string]$manifest.normalizedLineEndings } else { "LF" }
            $normalizedHash = Get-NormalizedBytesHash $path $lineEnding
            if ($normalizedHash -and ($normalizedHash.ToLowerInvariant() -eq [string]$expected.ToLowerInvariant())) {
                $actual = $normalizedHash
                $matched = $true
            }
        }
        if (-not $matched) {
            return [pscustomobject]@{
                IsValid = $false
                Reason = "Asset hash mismatch."
                Actual = [string]$actual
                Expected = [string]$expected
            }
        }
    }

    return [pscustomobject]@{
        IsValid = $true
        Reason = ""
        Actual = [string]$actual
        Expected = [string]$expected
    }
}

function Test-UninstallAssetTrust([object]$manifest, [string]$relativePath, [string]$path) {
    $hashCheck = Test-AssetHashMatchesManifest -manifest $manifest -relativePath $relativePath -path $path
    if (-not $hashCheck.IsValid) {
        return [pscustomobject]@{
            IsValid = $false
            TrustMode = "None"
            Reason = ("{0} Expected={1} Actual={2}" -f $hashCheck.Reason, $hashCheck.Expected, $hashCheck.Actual)
        }
    }

    try {
        $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
        if ($sig -and $sig.SignerCertificate) {
            if ([string]$sig.Status -ne "Valid") {
                return [pscustomobject]@{
                    IsValid = $false
                    TrustMode = "Authenticode"
                    Reason = ("Authenticode signature is present but invalid: {0}" -f [string]$sig.Status)
                }
            }
            return [pscustomobject]@{
                IsValid = $true
                TrustMode = "Manifest+Authenticode"
                Reason = ""
            }
        }
    } catch {
        Write-SetupLog ("Authenticode check skipped for {0}: {1}" -f $relativePath, $_.Exception.Message)
    }

    return [pscustomobject]@{
        IsValid = $true
        TrustMode = "ManifestSignature"
        Reason = ""
    }
}

function New-ProgressForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Teams Always Green - Setup"
    $form.Width = 520
    $form.Height = 200
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

    $label = New-Object System.Windows.Forms.Label
    $label.AutoSize = $true
    $label.Text = "Preparing..."
    $label.Location = New-Object System.Drawing.Point(16, 12)

    $progress = New-Object System.Windows.Forms.ProgressBar
    $progress.Width = 470
    $progress.Height = 20
    $progress.Location = New-Object System.Drawing.Point(16, 42)
    $progress.Minimum = 0
    $progress.Maximum = 100

    $meta = New-Object System.Windows.Forms.Label
    $meta.AutoSize = $true
    $meta.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Regular)
    $meta.Text = "Files: 0/0"
    $meta.Location = New-Object System.Drawing.Point(16, 70)

    $detailsLink = New-Object System.Windows.Forms.LinkLabel
    $detailsLink.Text = "Show details"
    $detailsLink.AutoSize = $true
    $detailsLink.Location = New-Object System.Drawing.Point(400, 70)

    $detailsList = New-Object System.Windows.Forms.ListBox
    $detailsList.Width = 470
    $detailsList.Height = 70
    $detailsList.Location = New-Object System.Drawing.Point(16, 92)
    $detailsList.Visible = $false

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Width = 90
    $cancelButton.Location = New-Object System.Drawing.Point(300, 128)

    $nextButton = New-Object System.Windows.Forms.Button
    $nextButton.Text = "Next"
    $nextButton.Width = 90
    $nextButton.Enabled = $false
    $nextButton.Location = New-Object System.Drawing.Point(396, 128)

    $form.Controls.Add($label)
    $form.Controls.Add($progress)
    $form.Controls.Add($meta)
    $form.Controls.Add($detailsLink)
    $form.Controls.Add($detailsList)
    $form.Controls.Add($cancelButton)
    $form.Controls.Add($nextButton)
    $form.TopMost = $true
    $form.Show()
    [System.Windows.Forms.Application]::DoEvents()
    $ui = @{
        Form = $form
        Label = $label
        Progress = $progress
        Meta = $meta
        DetailsLink = $detailsLink
        DetailsList = $detailsList
        CancelButton = $cancelButton
        NextButton = $nextButton
        NextClicked = $false
        Cancelled = $false
        DetailsVisible = $false
        BaseHeight = $form.Height
        ExpandedHeight = $form.Height + 90
        ButtonsYBase = 128
        ButtonsYExpanded = 218
        StartTime = (Get-Date)
        BytesDownloaded = 0
    }
    $detailsLink.Add_LinkClicked({
        if ($ui.DetailsVisible) {
            $ui.DetailsVisible = $false
            $ui.DetailsList.Visible = $false
            $ui.Form.Height = $ui.BaseHeight
            $ui.CancelButton.Location = New-Object System.Drawing.Point(300, $ui.ButtonsYBase)
            $ui.NextButton.Location = New-Object System.Drawing.Point(396, $ui.ButtonsYBase)
            $ui.DetailsLink.Text = "Show details"
        } else {
            $ui.DetailsVisible = $true
            $ui.DetailsList.Visible = $true
            $ui.Form.Height = $ui.ExpandedHeight
            $ui.CancelButton.Location = New-Object System.Drawing.Point(300, $ui.ButtonsYExpanded)
            $ui.NextButton.Location = New-Object System.Drawing.Point(396, $ui.ButtonsYExpanded)
            $ui.DetailsLink.Text = "Hide details"
        }
    })
    $cancelButton.Add_Click({
        $ui.Cancelled = $true
        $ui.CancelButton.Enabled = $false
        $ui.Label.Text = "Canceling after current file..."
    })
    return $ui
}

function New-ProgressDialog {
    param(
        [string]$title = "Preparing...",
        [bool]$showDetails = $false
    )
    $ui = New-ProgressForm
    if ($ui -and $ui.Label -and -not [string]::IsNullOrWhiteSpace($title)) {
        $ui.Label.Text = $title
    }
    if ($ui -and $ui.DetailsList) {
        $ui.DetailsList.Visible = [bool]$showDetails
        if ($ui.DetailsLink) {
            $ui.DetailsLink.Text = if ($ui.DetailsList.Visible) { "Hide details" } else { "Show details" }
        }
    }
    return $ui
}

function Update-Progress($ui, $current, $total, [string]$message) {
    if (-not $ui) { return }
    $current = Get-ScalarInt $current
    $total = Get-ScalarInt $total
    $pct = 0
    if ($total -gt 0) { $pct = [Math]::Min(100, [Math]::Round(($current / $total) * 100)) }
    $ui.Label.Text = $message
    $ui.Progress.Value = $pct
    if ($ui.Meta) {
        try {
            $startTime = $ui.StartTime
            if ($startTime -is [System.Array] -and $startTime.Count -gt 0) { $startTime = $startTime[0] }
            if (-not ($startTime -is [DateTime])) { $startTime = Get-Date; $ui.StartTime = $startTime }
            $elapsed = (Get-Date) - $startTime
            $rate = if ($elapsed.TotalMinutes -gt 0 -and $current -gt 0) { "{0:N1} files/min" -f ($current / $elapsed.TotalMinutes) } else { "-" }
            $remaining = [Math]::Max(0, $total - $current)
            $etaSeconds = if ($current -gt 0) { ($elapsed.TotalSeconds / $current) * $remaining } else { 0 }
            if ($etaSeconds -gt 0) {
                $etaMinutes = [int][Math]::Floor($etaSeconds / 60)
                $etaRemainSeconds = [int]($etaSeconds % 60)
                $etaText = "{0:00}:{1:00}" -f $etaMinutes, $etaRemainSeconds
            } else {
                $etaText = '--:--'
            }
            $ui.Meta.Text = ("Files: {0}/{1} | Rate: {2} | ETA: {3}" -f $current, $total, $rate, $etaText)
        } catch {
            try { $ui.Meta.Text = ("Files: {0}/{1}" -f $current, $total) } catch { $null = $_ }
        }
    }
    [System.Windows.Forms.Application]::DoEvents()
}

function Get-ScalarInt($value) {
    if ($value -is [System.Array]) {
        if ($value.Count -gt 0) { return [int]$value[0] }
        return 0
    }
    try { return [int]$value } catch { return 0 }
}

function Wait-For-ProgressNext($ui) {
    if (-not $ui -or -not $ui.Form -or $ui.Form.IsDisposed) { return }
    $ui.NextClicked = $false
    $ui.NextButton.Enabled = $true
    $ui.NextButton.Add_Click({ $ui.NextClicked = $true })
    while (-not $ui.NextClicked -and -not $ui.Cancelled -and $ui.Form.Visible) {
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 50
    }
    try { $ui.Form.Close() } catch { $null = $_ }
}

function Show-Welcome {
    param([System.Windows.Forms.Form]$owner)
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Teams Always Green - Welcome"
    $form.ClientSize = New-Object System.Drawing.Size(580, 380)
    $form.Width = 600
    $form.Height = 400
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true

    $headerPanel = New-Object System.Windows.Forms.Panel
    $headerPanel.Width = 560
    $headerPanel.Height = 58
    $headerPanel.Location = New-Object System.Drawing.Point(16, 12)
    $headerPanel.BackColor = $form.BackColor

    $iconBox = New-Object System.Windows.Forms.PictureBox
    $iconBox.Size = New-Object System.Drawing.Size(32, 32)
    $iconBox.Location = New-Object System.Drawing.Point(0, 6)
    $iconBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage
    $iconPath = $null
    $localRoot = Get-QuickSetupSourceRoot
    if ($localRoot) {
        $iconPath = Join-Path $localRoot "Meta\Icons\Tray_Icon.ico"
    }
    $welcomeIcon = $null
    if ($iconPath -and (Test-Path $iconPath)) {
        try { $welcomeIcon = New-Object System.Drawing.Icon($iconPath) } catch { $null = $_ }
    }
    if (-not $welcomeIcon) {
        try {
            try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { $null = $_ }
            $remoteIconUrl = "https://raw.githubusercontent.com/alexphillips-dev/Teams-Always-Green/main/Meta/Icons/Tray_Icon.ico"
            $remoteIconPath = Join-Path $env:TEMP "TeamsAlwaysGreen-Welcome.ico"
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($remoteIconUrl, $remoteIconPath)
            if (Test-Path $remoteIconPath) { $welcomeIcon = New-Object System.Drawing.Icon($remoteIconPath) }
            $script:WelcomeTempIconPath = $remoteIconPath
        } catch {
                    $null = $_
                }
    }
    if ($welcomeIcon) {
        $iconBox.Image = $welcomeIcon.ToBitmap()
        try { $form.Icon = $welcomeIcon } catch { $null = $_ }
    } else {
        $iconBox.Image = [System.Drawing.SystemIcons]::Information.ToBitmap()
        try { $form.Icon = [System.Drawing.SystemIcons]::Information } catch { $null = $_ }
    }

    $title = New-Object System.Windows.Forms.Label
    $title.AutoSize = $true
    $title.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $title.Text = "Welcome to Teams Always Green"
    $title.Location = New-Object System.Drawing.Point(44, 6)

    $tagline = New-Object System.Windows.Forms.Label
    $tagline.AutoSize = $false
    $tagline.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
    $tagline.Text = "Stay available without micromanaging your status."
    $tagline.Location = New-Object System.Drawing.Point(44, 34)
    $tagline.Width = 500
    $tagline.Height = 18
    $tagline.Padding = New-Object System.Windows.Forms.Padding(0, 1, 0, 0)

    $headerPanel.Controls.Add($iconBox)
    $headerPanel.Controls.Add($title)
    $headerPanel.Controls.Add($tagline)

    $card = New-Object System.Windows.Forms.Panel
    $card.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $card.Width = 552
    $card.Height = 210
    $card.Location = New-Object System.Drawing.Point(16, 72)

    $body = New-Object System.Windows.Forms.Label
    $body.AutoSize = $false
    $body.Width = 520
    $body.Height = 190
    $body.Location = New-Object System.Drawing.Point(12, 10)
                $body.Text = @(
        "Quick setup will install the app and walk you through the choices below.",
        "",
        "Steps:",
        "  1) Choose an install folder (default is Documents\\Teams Always Green)",
        "  2) Choose whether to create shortcuts",
        "  3) Download and verify app files",
        "  4) Review the summary and launch",
        "",
        "This setup will:",
        "  - Install the app files into a single folder",
        "  - Optionally create Start Menu/Desktop/Startup shortcuts",
        "",
        "This setup does not:",
        "  - Change your Teams settings",
        "  - Run anything in the background without your permission"
    ) -join [Environment]::NewLine

    $card.Controls.Add($body)

    $shortcutsBox = New-Object System.Windows.Forms.CheckBox
    $shortcutsBox.Text = "Create Start Menu/Desktop shortcuts (Recommended)"
    $shortcutsBox.Checked = $true
    $shortcutsBox.AutoSize = $true
    $shortcutsBox.Location = New-Object System.Drawing.Point(24, 296)

    $continue = New-Object System.Windows.Forms.Button
    $continue.Text = "Continue"
    $continue.Width = 100
    $continue.Location = New-Object System.Drawing.Point(320, 320)

    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = "Cancel"
    $cancel.Width = 100
    $cancel.Location = New-Object System.Drawing.Point(430, 320)

    $continue.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.AcceptButton = $continue
    $form.CancelButton = $cancel

    $form.Controls.Add($headerPanel)
    $form.Controls.Add($card)
    $form.Controls.Add($shortcutsBox)
    $form.Controls.Add($continue)
    $form.Controls.Add($cancel)
    if ($owner) {
        $result = $form.ShowDialog($owner)
    } else {
        $result = $form.ShowDialog()
    }
    return @{
        Proceed = ($result -eq [System.Windows.Forms.DialogResult]::OK)
        CreateShortcuts = [bool]$shortcutsBox.Checked
    }
}

function Show-SetupSummary {
    param(
        [string]$installPath,
        [string]$integrityStatus,
        [bool]$portableMode,
        [string[]]$shortcutsCreated,
        [string]$logPath
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Teams Always Green - Setup Complete"
    $form.Width = 680
    $form.Height = 410
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.BackColor = [System.Drawing.Color]::White
    $form.ShowIcon = $true
    $windowIconPath = Join-Path $installPath "Meta\Icons\Tray_Icon.ico"
    try {
        if (Test-Path $windowIconPath) {
            $form.Icon = New-Object System.Drawing.Icon($windowIconPath, 32, 32)
        } else {
            $form.Icon = [System.Drawing.SystemIcons]::Application
        }
    } catch {
        try { $form.Icon = [System.Drawing.SystemIcons]::Application } catch { $null = $_ }
    }

    $header = New-Object System.Windows.Forms.Panel
    $header.Width = 640
    $header.Height = 66
    $header.Location = New-Object System.Drawing.Point(16, 12)
    $header.BackColor = [System.Drawing.Color]::FromArgb(245, 248, 252)

    $iconBox = New-Object System.Windows.Forms.PictureBox
    $iconBox.Size = New-Object System.Drawing.Size(36, 36)
    $iconBox.Location = New-Object System.Drawing.Point(12, 14)
    $iconBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage
    try {
        if (Test-Path $windowIconPath) {
            $iconBox.Image = (New-Object System.Drawing.Icon($windowIconPath, 32, 32)).ToBitmap()
        } else {
            $iconBox.Image = [System.Drawing.SystemIcons]::Information.ToBitmap()
        }
    } catch {
        try { $iconBox.Image = [System.Drawing.SystemIcons]::Information.ToBitmap() } catch { $null = $_ }
    }

    $headerTitle = New-Object System.Windows.Forms.Label
    $headerTitle.AutoSize = $true
    $headerTitle.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $headerTitle.Text = "Install completed successfully."
    $headerTitle.Location = New-Object System.Drawing.Point(60, 10)

    $headerSubtitle = New-Object System.Windows.Forms.Label
    $headerSubtitle.AutoSize = $true
    $headerSubtitle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
    $headerSubtitle.Text = "You're ready to launch Teams Always Green."
    $headerSubtitle.Location = New-Object System.Drawing.Point(60, 36)

    $header.Controls.Add($iconBox)
    $header.Controls.Add($headerTitle)
    $header.Controls.Add($headerSubtitle)

    $separator = New-Object System.Windows.Forms.Panel
    $separator.Width = 640
    $separator.Height = 1
    $separator.Location = New-Object System.Drawing.Point(16, 84)
    $separator.BackColor = [System.Drawing.Color]::FromArgb(220, 220, 220)

    $summaryGroup = New-Object System.Windows.Forms.GroupBox
    $summaryGroup.Text = "Install summary"
    $summaryGroup.Width = 640
    $summaryGroup.Height = 200
    $summaryGroup.Location = New-Object System.Drawing.Point(16, 92)

    $shortcutsText = if ($shortcutsCreated -and $shortcutsCreated.Count -gt 0) { $shortcutsCreated -join "; " } else { "None (portable mode)" }
    $modeText = if ($portableMode) { "Portable (no shortcuts)" } else { "Standard" }

    $summaryTable = New-Object System.Windows.Forms.TableLayoutPanel
    $summaryTable.ColumnCount = 2
    $summaryTable.RowCount = 0
    $summaryTable.Dock = [System.Windows.Forms.DockStyle]::Fill
    $summaryTable.Padding = New-Object System.Windows.Forms.Padding(12, 18, 12, 10)
    $summaryTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $summaryTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $addSummaryRow = {
        param([string]$labelText, $valueControl)
        $rowIndex = $summaryTable.RowCount
        $summaryTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
        $label = New-Object System.Windows.Forms.Label
        $label.AutoSize = $true
        $label.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $label.Text = $labelText
        $label.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 6)
        $valueControl.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)
        $summaryTable.Controls.Add($label, 0, $rowIndex)
        $summaryTable.Controls.Add($valueControl, 1, $rowIndex)
        $summaryTable.RowCount++
    }

    $valueStyle = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
    $maxValueWidth = 500
    $toolTip = New-Object System.Windows.Forms.ToolTip

    $valueInstall = New-Object System.Windows.Forms.Label
    $valueInstall.Font = $valueStyle
    $valueInstall.AutoSize = $true
    $valueInstall.MaximumSize = New-Object System.Drawing.Size($maxValueWidth, 0)
    $valueInstall.Text = $installPath
    $toolTip.SetToolTip($valueInstall, $installPath)

    $valueMode = New-Object System.Windows.Forms.Label
    $valueMode.Font = $valueStyle
    $valueMode.AutoSize = $true
    $valueMode.MaximumSize = New-Object System.Drawing.Size($maxValueWidth, 0)
    $valueMode.Text = $modeText

    $valueIntegrity = New-Object System.Windows.Forms.Label
    $valueIntegrity.Font = $valueStyle
    $valueIntegrity.AutoSize = $true
    $valueIntegrity.MaximumSize = New-Object System.Drawing.Size($maxValueWidth, 0)
    $valueIntegrity.Text = $integrityStatus

    $valueShortcuts = New-Object System.Windows.Forms.Label
    $valueShortcuts.Font = $valueStyle
    $valueShortcuts.AutoSize = $true
    $valueShortcuts.MaximumSize = New-Object System.Drawing.Size($maxValueWidth, 0)
    $valueShortcuts.Text = $shortcutsText

    $valueLog = New-Object System.Windows.Forms.LinkLabel
    $valueLog.Font = $valueStyle
    $valueLog.AutoSize = $true
    $valueLog.MaximumSize = New-Object System.Drawing.Size($maxValueWidth, 0)
    $valueLog.Text = $logPath
    $valueLog.LinkBehavior = [System.Windows.Forms.LinkBehavior]::HoverUnderline
    $toolTip.SetToolTip($valueLog, $logPath)
    $valueLog.Add_LinkClicked({
        try { Start-Process "notepad.exe" $logPath } catch { $null = $_ }
    })

    & $addSummaryRow "Install Path:" $valueInstall
    & $addSummaryRow "Mode:" $valueMode
    & $addSummaryRow "Integrity:" $valueIntegrity
    & $addSummaryRow "Shortcuts:" $valueShortcuts
    & $addSummaryRow "Setup Log:" $valueLog

    $summaryGroup.Controls.Add($summaryTable)

    $note = New-Object System.Windows.Forms.Label
    $note.AutoSize = $true
    $note.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Regular)
    $note.ForeColor = [System.Drawing.Color]::FromArgb(90, 90, 90)
    $note.Text = "Tip: You can open Settings any time from the tray icon."
    $note.Location = New-Object System.Drawing.Point(18, 290)

    $buttonLaunch = New-Object System.Windows.Forms.Button
    $buttonLaunch.Text = "Launch"
    $buttonLaunch.Width = 90
    $buttonLaunch.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $buttonLaunch.Location = New-Object System.Drawing.Point(16, 320)

    $buttonSettings = New-Object System.Windows.Forms.Button
    $buttonSettings.Text = "Settings"
    $buttonSettings.Width = 90
    $buttonSettings.Location = New-Object System.Drawing.Point(116, 320)

    $buttonFolder = New-Object System.Windows.Forms.Button
    $buttonFolder.Text = "Open Folder"
    $buttonFolder.Width = 110
    $buttonFolder.Location = New-Object System.Drawing.Point(216, 320)

    $buttonClose = New-Object System.Windows.Forms.Button
    $buttonClose.Text = "Close"
    $buttonClose.Width = 90
    $buttonClose.Location = New-Object System.Drawing.Point(546, 320)

    $buttonLaunch.DialogResult = [System.Windows.Forms.DialogResult]::Yes
    $buttonSettings.DialogResult = [System.Windows.Forms.DialogResult]::Retry
    $buttonFolder.DialogResult = [System.Windows.Forms.DialogResult]::Ignore
    $buttonClose.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.AcceptButton = $buttonLaunch
    $form.CancelButton = $buttonClose

    $form.Controls.Add($header)
    $form.Controls.Add($separator)
    $form.Controls.Add($summaryGroup)
    $form.Controls.Add($note)
    $form.Controls.Add($buttonLaunch)
    $form.Controls.Add($buttonSettings)
    $form.Controls.Add($buttonFolder)
    $form.Controls.Add($buttonClose)
    $form.TopMost = $true
    $result = $form.ShowDialog()
    switch ($result) {
        ([System.Windows.Forms.DialogResult]::Yes) { return "Launch" }
        ([System.Windows.Forms.DialogResult]::Retry) { return "Settings" }
        ([System.Windows.Forms.DialogResult]::Ignore) { return "Folder" }
        default { return "Close" }
    }
}

if ($false) {
Write-SetupLog "Quick setup started."

$setupOwner = New-SetupOwner
$welcome = Show-Welcome -owner $setupOwner
if (-not $welcome.Proceed) {
    Write-SetupLog "Install canceled at welcome screen."
    Write-Output "Install canceled."
    if ($setupOwner -and -not $setupOwner.IsDisposed) { $setupOwner.Close() }
    Cleanup-SetupTempFiles -success $true
    exit 1
}
if (-not $welcome.CreateShortcuts) {
    Write-SetupLog "Welcome: shortcuts disabled (portable mode selected)."
} else {
    Write-SetupLog "Welcome: shortcuts enabled."
}

$step1 = Show-SetupPrompt -message "Step 1 of 4: Choose the install folder location." -title "Install Location" -buttons ([System.Windows.Forms.MessageBoxButtons]::OKCancel) -icon ([System.Windows.Forms.MessageBoxIcon]::Information) -owner $setupOwner
if ($step1 -ne [System.Windows.Forms.DialogResult]::OK) {
    Write-SetupLog "Install canceled at install location step."
    Write-Output "Install canceled."
    if ($setupOwner -and -not $setupOwner.IsDisposed) { $setupOwner.Close() }
    exit 1
}

$defaultBase = [Environment]::GetFolderPath("MyDocuments")
$defaultPath = Join-Path $defaultBase "Teams Always Green"

$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = "Select the parent folder (we will create a Teams Always Green folder inside)"
$dialog.SelectedPath = $defaultPath

if ($dialog.ShowDialog($setupOwner) -ne [System.Windows.Forms.DialogResult]::OK) {
    Write-Output "Install canceled."
    if ($setupOwner -and -not $setupOwner.IsDisposed) { $setupOwner.Close() }
    exit 1
}

$selectedBase = $dialog.SelectedPath
$appFolderName = "Teams Always Green"
if ([string]::Equals([System.IO.Path]::GetFileName($selectedBase), $appFolderName, [System.StringComparison]::OrdinalIgnoreCase)) {
    $installPath = $selectedBase
} else {
    $installPath = Join-Path $selectedBase $appFolderName
}
if (-not (Test-Path $installPath)) {
    New-Item -ItemType Directory -Path $installPath -Force | Out-Null
}
$detectedScript = Join-Path $installPath "Script\Teams Always Green.ps1"
if (Test-Path $detectedScript) {
    $choice = Show-SetupPrompt -message "An existing install was detected at:`n$installPath`n`nUpgrade/repair this install?" -title "Existing Install" -buttons ([System.Windows.Forms.MessageBoxButtons]::YesNoCancel) -icon ([System.Windows.Forms.MessageBoxIcon]::Question) -owner $setupOwner
    if ($choice -eq [System.Windows.Forms.DialogResult]::Cancel) {
        Write-Output "Install canceled."
        if ($setupOwner -and -not $setupOwner.IsDisposed) { $setupOwner.Close() }
        exit 1
    }
    if ($choice -eq [System.Windows.Forms.DialogResult]::No) {
        if ($dialog.ShowDialog($setupOwner) -ne [System.Windows.Forms.DialogResult]::OK) {
            Write-Output "Install canceled."
            if ($setupOwner -and -not $setupOwner.IsDisposed) { $setupOwner.Close() }
            exit 1
        }
        $selectedBase = $dialog.SelectedPath
        if ([string]::Equals([System.IO.Path]::GetFileName($selectedBase), $appFolderName, [System.StringComparison]::OrdinalIgnoreCase)) {
            $installPath = $selectedBase
        } else {
            $installPath = Join-Path $selectedBase $appFolderName
        }
        if (-not (Test-Path $installPath)) {
            New-Item -ItemType Directory -Path $installPath -Force | Out-Null
        }
    }
}
$portableMode = $false
$portableMarker = Join-Path $installPath "Meta\PortableMode.txt"
if (Test-Path $portableMarker) {
    $portableMode = $true
} else {
    $portableMode = (-not [bool]$welcome.CreateShortcuts)
}
$folders = @(
    "Debug",
    "Meta",
    "Meta\Icons",
    "Meta\Keys",
    "Script",
    "Script\Core",
    "Script\Features",
    "Script\I18n",
    "Script\Tray",
    "Script\UI",
    "Script\Uninstall"
)
if ($portableMode) {
    $folders += @("Logs", "Settings")
}
foreach ($name in $folders) {
    $path = Join-Path $installPath $name
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}
if ($portableMode) {
    try {
        Set-Content -Path $portableMarker -Value ("PortableMode=1`nSetOn={0}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")) -Encoding ASCII
        Write-SetupLog "Portable mode enabled."
    } catch {
                $null = $_
            }
} else {
    try { if (Test-Path $portableMarker) { Remove-Item -Path $portableMarker -Force -ErrorAction SilentlyContinue } } catch { $null = $_ }
}

$metaDir = Join-Path $installPath "Meta"
foreach ($legacyLocator in @(
    (Join-Path $metaDir "Teams-Always-Green.settings.path.txt"),
    (Join-Path $metaDir "Teams-Always-Green.log.path.txt"),
    (Join-Path $installPath "Teams-Always-Green.settings.path.txt"),
    (Join-Path $installPath "Teams-Always-Green.log.path.txt")
)) {
    try { if (Test-Path $legacyLocator) { Remove-Item -Path $legacyLocator -Force -ErrorAction SilentlyContinue } } catch { $null = $_ }
}

$rawBase = "https://raw.githubusercontent.com/alexphillips-dev/Teams-Always-Green/main"
$cacheBuster = [Guid]::NewGuid().ToString("N")
$filesToDownload = @(
    @{ Url = "$rawBase/Script/Teams%20Always%20Green.ps1"; Path = "Script\Teams Always Green.ps1" },
    @{ Url = "$rawBase/Script/Core/Logging.ps1"; Path = "Script\Core\Logging.ps1" },
    @{ Url = "$rawBase/Script/Core/Paths.ps1"; Path = "Script\Core\Paths.ps1" },
    @{ Url = "$rawBase/Script/Core/Runtime.ps1"; Path = "Script\Core\Runtime.ps1" },
    @{ Url = "$rawBase/Script/Core/DateTime.ps1"; Path = "Script\Core\DateTime.ps1" },
    @{ Url = "$rawBase/Script/Core/Settings.ps1"; Path = "Script\Core\Settings.ps1" },
    @{ Url = "$rawBase/Script/Features/Hotkeys.ps1"; Path = "Script\Features\Hotkeys.ps1" },
    @{ Url = "$rawBase/Script/Features/Profiles.ps1"; Path = "Script\Features\Profiles.ps1" },
    @{ Url = "$rawBase/Script/Features/Scheduling.ps1"; Path = "Script\Features\Scheduling.ps1" },
    @{ Url = "$rawBase/Script/Features/UpdateEngine.ps1"; Path = "Script\Features\UpdateEngine.ps1" },
    @{ Url = "$rawBase/Script/I18n/UiStrings.ps1"; Path = "Script\I18n\UiStrings.ps1" },
    @{ Url = "$rawBase/Script/Tray/Menu.ps1"; Path = "Script\Tray\Menu.ps1" },
    @{ Url = "$rawBase/Script/UI/SettingsDialog.ps1"; Path = "Script\UI\SettingsDialog.ps1" },
    @{ Url = "$rawBase/Script/UI/HistoryDialog.ps1"; Path = "Script\UI\HistoryDialog.ps1" },
    @{ Url = "$rawBase/Script/Uninstall/Uninstall-Teams-Always-Green.ps1"; Path = "Script\Uninstall\Uninstall-Teams-Always-Green.ps1" },
    @{ Url = "$rawBase/Script/Uninstall/Uninstall-Teams-Always-Green.vbs"; Path = "Script\Uninstall\Uninstall-Teams-Always-Green.vbs" },
    @{ Url = "$rawBase/VERSION"; Path = "VERSION" },
    @{ Url = "$rawBase/Teams%20Always%20Green.VBS"; Path = "Teams Always Green.VBS" },
    @{ Url = "$rawBase/Debug/Teams%20Always%20Green%20-%20Debug.VBS"; Path = "Debug\Teams Always Green - Debug.VBS" },
    @{ Url = "$rawBase/Meta/Keys/quicksetup-manifest-public.xml"; Path = "Meta\Keys\quicksetup-manifest-public.xml" },
    @{ Url = "$rawBase/Meta/Teams-Always-Green.updatekey.xml"; Path = "Meta\Teams-Always-Green.updatekey.xml" },
    @{ Url = "$rawBase/Meta/Icons/Tray_Icon.ico"; Path = "Meta\Icons\Tray_Icon.ico" },
    @{ Url = "$rawBase/Meta/Icons/Settings_Icon.ico"; Path = "Meta\Icons\Settings_Icon.ico" }
)
$targetScript = Join-Path $installPath "Script\Teams Always Green.ps1"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {
            $null = $_
        }

$ui = New-ProgressForm
Update-Progress $ui 0 1 "Step 2 of 4: Preparing download..."

$localRoot = $null
$localRoot = Get-QuickSetupSourceRoot

$localManifestPath = $null
$useLocal = $false
if ($localRoot) {
    $localManifestPath = Join-Path $localRoot $script:QuickSetupManifestRelativePath
    if (Test-Path (Join-Path $localRoot "Script\Teams Always Green.ps1")) {
        $useLocal = (Show-SetupPrompt -message (
            "Local app files were found in this local repository checkout.`nUse local files instead of downloading?",
            "Use Local Files"
        ) -title "Use Local Files" -buttons ([System.Windows.Forms.MessageBoxButtons]::YesNo) -icon ([System.Windows.Forms.MessageBoxIcon]::Question)) -eq [System.Windows.Forms.DialogResult]::Yes
    }
}

$manifest = $null
$manifestSignature = $null
if ($useLocal) {
    $manifest = Load-Manifest $localManifestPath
    $manifestSignature = Load-ManifestSignature (Join-Path $localRoot $script:QuickSetupManifestSignatureRelativePath)
} else {
    $manifestUrl = "$rawBase/Script/QuickSetup/QuickSetup.manifest.json?v=$cacheBuster"
    if (-not (Test-QuickSetupTrustedUrl $manifestUrl)) {
        Show-SetupError ("Blocked untrusted manifest URL: {0}" -f $manifestUrl)
        exit 1
    }
    $manifestTarget = Join-Path $installPath "Meta\QuickSetup.manifest.json"
    try {
        Invoke-WebRequest -Uri $manifestUrl -OutFile $manifestTarget -UseBasicParsing
        $manifest = Load-Manifest $manifestTarget
    } catch {
        Show-SetupError "Manifest download failed. Setup cannot continue without integrity validation."
        exit 1
    }
    $manifestSignatureUrl = "$rawBase/Script/QuickSetup/QuickSetup.manifest.sig?v=$cacheBuster"
    if (-not (Test-QuickSetupTrustedUrl $manifestSignatureUrl)) {
        Show-SetupError ("Blocked untrusted manifest signature URL: {0}" -f $manifestSignatureUrl)
        exit 1
    }
    $manifestSignatureTarget = Join-Path $installPath "Meta\QuickSetup.manifest.sig"
    try {
        Invoke-WebRequest -Uri $manifestSignatureUrl -OutFile $manifestSignatureTarget -UseBasicParsing -ErrorAction Stop
        $manifestSignature = Load-ManifestSignature $manifestSignatureTarget
    } catch {
        Write-SetupLog "Manifest signature was not downloaded; proceeding with hash-manifest validation."
    }
}
$manifestCheck = Test-QuickSetupManifest -manifest $manifest -files $filesToDownload
if (-not $manifestCheck.IsValid) {
    Show-SetupError ("Manifest validation failed: {0}" -f $manifestCheck.Reason)
    exit 1
}
$manifestSignatureCheck = Test-QuickSetupManifestSignature -manifest $manifest -signatureText $manifestSignature -publicKeyXml $script:QuickSetupManifestSignaturePublicKeyXml -RequireSignature:$script:QuickSetupRequireManifestSignature
if (-not $manifestSignatureCheck.IsValid) {
    Show-SetupError ("Manifest signature validation failed: {0}" -f $manifestSignatureCheck.Reason)
    exit 1
}
$integrityStatus = "Verified"
if ($manifestSignatureCheck.Status -eq "Verified") {
    $integrityStatus = "Verified (manifest signature)"
} elseif ($manifestSignatureCheck.Status -eq "NoPublicKey") {
    $integrityStatus = "Verified (signature present, key not configured)"
}

$total = $filesToDownload.Count
$index = 0
$downloadedFiles = New-Object System.Collections.ArrayList
foreach ($file in $filesToDownload) {
    if ($ui.Cancelled) { break }
    $index++
    $targetPath = Join-Path $installPath $file.Path
    $status = "Step 2 of 4: Downloading {0} ({1}/{2})" -f $file.Path, $index, $total
    if ($ui.DetailsList) {
        [void]$ui.DetailsList.Items.Insert(0, $file.Path)
        while ($ui.DetailsList.Items.Count -gt 3) { $ui.DetailsList.Items.RemoveAt($ui.DetailsList.Items.Count - 1) }
    }
    Update-Progress $ui $index $total $status
    Write-SetupLog $status

    if ($useLocal) {
        $sourcePath = Join-Path $localRoot $file.Path
        if (-not (Test-Path $sourcePath)) {
            Show-SetupError "Missing local file: $sourcePath"
            exit 1
        }
        Copy-Item -Path $sourcePath -Destination $targetPath -Force
    } else {
        try {
            if (-not (Test-QuickSetupTrustedUrl $file.Url)) {
                Show-SetupError ("Blocked untrusted download URL: {0}" -f [string]$file.Url)
                exit 1
            }
            $downloadUrl = if ($file.Url -match "\?") { "$($file.Url)&v=$cacheBuster" } else { "$($file.Url)?v=$cacheBuster" }
            Invoke-WebRequest -Uri $downloadUrl -OutFile $targetPath -UseBasicParsing
        } catch {
            Show-SetupError ("Download failed: {0}" -f $file.Url)
            exit 1
        }
    }
    if (Test-Path $targetPath) {
        try {
            $ui.BytesDownloaded += (Get-Item $targetPath).Length
            Update-Progress $ui $index $total $status
        } catch {
                    $null = $_
                }
        [void]$downloadedFiles.Add($targetPath)
    }

    if ($manifest -and $manifest.files) {
        $manifestKey = $file.Path.Replace("\", "/")
        $expected = [string]$manifest.files.$manifestKey
        if ([string]::IsNullOrWhiteSpace($expected)) {
            Show-SetupError ("Manifest expected hash is missing for {0}." -f $file.Path)
            exit 1
        }
        Update-Progress $ui $index $total ("Step 2 of 4: Verifying {0} ({1}/{2})" -f $file.Path, $index, $total)
        $actual = Get-FileHashHex $targetPath
        if (-not $actual -or ($actual.ToLowerInvariant() -ne [string]$expected.ToLowerInvariant())) {
            Write-SetupLog ("Integrity expected: {0}" -f $expected)
            Write-SetupLog ("Integrity actual:   {0}" -f $actual)
            $matched = $false
            if (Is-TextFile $file.Path) {
                Write-SetupLog ("Integrity text file: {0}" -f $file.Path)
                $altLf = Get-NormalizedBytesHash $targetPath "LF"
                if ($altLf -and ($altLf.ToLowerInvariant() -eq [string]$expected.ToLowerInvariant())) {
                    $matched = $true
                } else {
                    $altCrLf = Get-NormalizedBytesHash $targetPath "CRLF"
                    if ($altCrLf -and ($altCrLf.ToLowerInvariant() -eq [string]$expected.ToLowerInvariant())) {
                        $matched = $true
                    }
                }
                Write-SetupLog ("Integrity alt LF:   {0}" -f $altLf)
                Write-SetupLog ("Integrity alt CRLF: {0}" -f $altCrLf)
            } else {
                Write-SetupLog ("Integrity binary file: {0}" -f $file.Path)
            }
            if (-not $matched) {
                Show-SetupError ("Integrity check failed for {0}. See log for hash details." -f $file.Path)
                exit 1
            }
            Write-SetupLog ("Integrity check matched after line-ending normalization: {0}" -f $file.Path)
        }
    }
}

if ($ui -and $ui.Form) {
    if ($ui.Cancelled) {
        try { $ui.Form.Close() } catch { $null = $_ }
    } else {
        Write-SetupLog "Download completed."
        Update-Progress $ui $total $total "Step 2 of 4: Download complete. Click Next to continue."
        Wait-For-ProgressNext $ui
    }
}

if ($ui.Cancelled) {
    foreach ($path in $downloadedFiles) {
        try { Remove-Item -Path $path -Force -ErrorAction Stop } catch { $null = $_ }
    }
    Show-SetupError "Install canceled during download. Partial files were removed."
    exit 1
}
}

function New-Shortcut([string]$shortcutPath, [string]$targetScriptPath, [string]$workingDir) {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $shortcut.Arguments = "-NoProfile -ExecutionPolicy RemoteSigned -WindowStyle Hidden -File `"$targetScriptPath`""
    $shortcut.WorkingDirectory = $workingDir
    $shortcut.WindowStyle = 7
    $iconPath = Join-Path $workingDir "Meta\Icons\Tray_Icon.ico"
    if (Test-Path $iconPath) {
        $shortcut.IconLocation = "$iconPath,0"
        Write-SetupLog "Shortcut icon set: $iconPath"
    } else {
        $shortcut.IconLocation = "$env:WINDIR\System32\shell32.dll,1"
        Write-SetupLog "Shortcut icon missing, using shell32 fallback."
    }
    $shortcut.Save()
}

function New-VbsShortcut([string]$shortcutPath, [string]$vbsPath, [string]$workingDir) {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = "$env:WINDIR\System32\wscript.exe"
    $shortcut.Arguments = "`"$vbsPath`""
    $shortcut.WorkingDirectory = $workingDir
    $shortcut.WindowStyle = 1
    $iconPath = Join-Path $workingDir "Meta\Icons\Tray_Icon.ico"
    if (Test-Path $iconPath) {
        $shortcut.IconLocation = "$iconPath,0"
        Write-SetupLog "Shortcut icon set: $iconPath"
    } else {
        $shortcut.IconLocation = "$env:WINDIR\System32\shell32.dll,1"
        Write-SetupLog "Shortcut icon missing, using shell32 fallback."
    }
    $shortcut.Save()
}

function Install-UninstallAssets {
    param(
        [string]$installPath,
        [object]$manifest
    )

    $uninstallDir = Join-Path $installPath "Script\Uninstall"
    $uninstallScriptPath = Join-Path $uninstallDir "Uninstall-Teams-Always-Green.ps1"
    $uninstallVbsPath = Join-Path $uninstallDir "Uninstall-Teams-Always-Green.vbs"
    if (-not (Test-Path -LiteralPath $uninstallDir -PathType Container)) {
        New-Item -ItemType Directory -Path $uninstallDir -Force | Out-Null
    }

    $assets = @(
        @{
            RelativePath = "Script\Uninstall\Uninstall-Teams-Always-Green.ps1"
            Url = "$script:QuickSetupRawBase/Script/Uninstall/Uninstall-Teams-Always-Green.ps1"
            Path = $uninstallScriptPath
        },
        @{
            RelativePath = "Script\Uninstall\Uninstall-Teams-Always-Green.vbs"
            Url = "$script:QuickSetupRawBase/Script/Uninstall/Uninstall-Teams-Always-Green.vbs"
            Path = $uninstallVbsPath
        }
    )

    $stagedFromFallback = $false
    $stagedFromLocal = $false
    $stagedFromRemote = $false
    $sourceRoot = Get-QuickSetupSourceRoot
    foreach ($asset in $assets) {
        $targetPath = [string]$asset.Path
        $localStaged = $false
        if ($sourceRoot) {
            $localPath = Join-Path $sourceRoot ([string]$asset.RelativePath)
            if (Test-Path -LiteralPath $localPath -PathType Leaf) {
                Copy-Item -Path $localPath -Destination $targetPath -Force
                $localStaged = $true
                $stagedFromFallback = $true
                $stagedFromLocal = $true
            }
        }

        if (-not $localStaged) {
            if (-not (Test-QuickSetupTrustedUrl $asset.Url)) {
                throw ("Blocked untrusted uninstall asset URL: {0}" -f [string]$asset.Url)
            }
            $downloadUrl = if ([string]$asset.Url -match "\?") { "$($asset.Url)&v=$script:QuickSetupCacheBuster" } else { "$($asset.Url)?v=$script:QuickSetupCacheBuster" }
            Invoke-WebRequest -Uri $downloadUrl -OutFile $targetPath -UseBasicParsing
            $stagedFromFallback = $true
            $stagedFromRemote = $true
        }
        if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
            throw ("Failed to stage uninstall asset: {0}" -f $targetPath)
        }

        $trust = Test-UninstallAssetTrust -manifest $manifest -relativePath ([string]$asset.RelativePath) -path $targetPath
        if (-not $trust.IsValid) {
            throw ("Uninstall asset trust check failed for {0}: {1}" -f [string]$asset.RelativePath, [string]$trust.Reason)
        }
        Write-SetupLog ("Uninstall asset trusted: {0} ({1})" -f [string]$asset.RelativePath, [string]$trust.TrustMode)
    }

    if ($stagedFromRemote) {
        Write-SetupLog "Uninstall assets downloaded from trusted source and verified."
    } elseif ($stagedFromLocal) {
        Write-SetupLog "Uninstall assets copied from local repository and verified."
    } elseif ($stagedFromFallback) {
        Write-SetupLog "Uninstall assets staged from fallback source and verified."
    } else {
        Write-SetupLog "Uninstall assets were pre-staged and verified."
    }

    return @{
        ScriptPath = $uninstallScriptPath
        VbsPath = $uninstallVbsPath
    }
}

function Finalize-Install {
    param(
        [string]$installPath,
        [string]$targetScript,
        [bool]$portableMode,
        [bool]$enableStartup,
        [object]$manifest
    )

    $programsDir = [Environment]::GetFolderPath("Programs")
    $menuFolder = Join-Path $programsDir "Teams Always Green"
    if (-not (Test-Path $menuFolder)) {
        New-Item -ItemType Directory -Path $menuFolder -Force | Out-Null
    }
    $menuShortcut = Join-Path $menuFolder "Teams Always Green.lnk"
    $uninstallShortcut = Join-Path $menuFolder "Uninstall Teams Always Green.lnk"
    $desktopDir = [Environment]::GetFolderPath("Desktop")
    $desktopShortcut = Join-Path $desktopDir "Teams Always Green.lnk"

    if ($enableStartup) {
        $startupDir = [Environment]::GetFolderPath("Startup")
        $startupShortcut = Join-Path $startupDir "Teams Always Green.lnk"
    }

    $uninstallVbsPath = $null
    try {
        $uninstallAssets = Install-UninstallAssets -installPath $installPath -manifest $manifest
        $uninstallVbsPath = [string]$uninstallAssets.VbsPath
    } catch {
        Write-SetupLog ("Failed to stage uninstall assets: {0}" -f $_.Exception.Message)
    }

    $shortcutsCreated = @()
    if (-not $portableMode) {
        try {
            New-Shortcut -shortcutPath $menuShortcut -targetScriptPath $targetScript -workingDir $installPath
            $shortcutsCreated += "Start Menu"
            if ($enableStartup) {
                New-Shortcut -shortcutPath $startupShortcut -targetScriptPath $targetScript -workingDir $installPath
                $shortcutsCreated += "Startup"
            }
            New-Shortcut -shortcutPath $desktopShortcut -targetScriptPath $targetScript -workingDir $installPath
            $shortcutsCreated += "Desktop"
            if (Test-Path $uninstallVbsPath) {
                New-VbsShortcut -shortcutPath $uninstallShortcut -vbsPath $uninstallVbsPath -workingDir $installPath
                $shortcutsCreated += "Uninstall"
            }
        } catch {
            Write-SetupLog "Failed to create shortcuts: $($_.Exception.Message)"
        }
    } else {
        Write-SetupLog "Portable mode: shortcuts not created."
    }
    return $shortcutsCreated
}

function Show-SetupWizard {
    param([System.Windows.Forms.Form]$owner)

    $state = [ordered]@{
        Cancelled = $false
        Action = "Close"
        InstallPath = $null
        CreateShortcuts = $true
        EnableStartup = $false
        IntegrityStatus = "Not verified"
        InstallSource = "Remote (GitHub)"
        ShortcutsCreated = @()
        PortableMode = $false
        FinalizeCompleted = $false
        AllowSummary = $false
        Manifest = $null
        OneDriveRiskDetected = $false
        OneDriveRiskSummary = ""
        OneDriveRecommendedPath = (Get-RecommendedInstallPath)
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Teams Always Green - Setup"
    $form.Width = 640
    $form.Height = 470
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

    $title = New-Object System.Windows.Forms.Label
    $title.AutoSize = $true
    $title.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $title.Location = New-Object System.Drawing.Point(16, 12)
    $title.Text = "Setup"

    $stepper = New-Object System.Windows.Forms.Label
    $stepper.AutoSize = $true
    $stepper.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Regular)
    $stepper.ForeColor = [System.Drawing.Color]::FromArgb(90, 90, 90)
    $stepper.Location = New-Object System.Drawing.Point(120, 14)
    $stepper.Text = "Step 1 of 4 - Welcome"

    $panelWelcome = New-Object System.Windows.Forms.Panel
    $panelWelcome.Location = New-Object System.Drawing.Point(16, 44)
    $panelWelcome.Size = New-Object System.Drawing.Size(600, 340)

    $headerPanel = New-Object System.Windows.Forms.Panel
    $headerPanel.Width = 580
    $headerPanel.Height = 56
    $headerPanel.Location = New-Object System.Drawing.Point(0, 0)
    $headerPanel.BackColor = $form.BackColor

    $welcomeIconBox = New-Object System.Windows.Forms.PictureBox
    $welcomeIconBox.Size = New-Object System.Drawing.Size(32, 32)
    $welcomeIconBox.Location = New-Object System.Drawing.Point(0, 6)
    $welcomeIconBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage

    $welcomeIcon = $null
    $iconPath = $null
    $localRoot = Get-QuickSetupSourceRoot
    if ($localRoot) { $iconPath = Join-Path $localRoot "Meta\Icons\Tray_Icon.ico" }
    if ($iconPath -and (Test-Path $iconPath)) {
        try { $welcomeIcon = New-Object System.Drawing.Icon($iconPath) } catch { $null = $_ }
    }
    if (-not $welcomeIcon) {
        try {
            try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { $null = $_ }
            $remoteIconUrl = "https://raw.githubusercontent.com/alexphillips-dev/Teams-Always-Green/main/Meta/Icons/Tray_Icon.ico"
            $remoteIconPath = Join-Path $env:TEMP "TeamsAlwaysGreen-Welcome.ico"
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($remoteIconUrl, $remoteIconPath)
            if (Test-Path $remoteIconPath) { $welcomeIcon = New-Object System.Drawing.Icon($remoteIconPath) }
            $script:WelcomeTempIconPath = $remoteIconPath
        } catch {
                    $null = $_
                }
    }
    if ($welcomeIcon) {
        $welcomeIconBox.Image = $welcomeIcon.ToBitmap()
        try { $form.Icon = $welcomeIcon } catch { $null = $_ }
    } else {
        $welcomeIconBox.Image = [System.Drawing.SystemIcons]::Information.ToBitmap()
    }

    $welcomeTitle = New-Object System.Windows.Forms.Label
    $welcomeTitle.AutoSize = $true
    $welcomeTitle.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $welcomeTitle.Text = "Welcome to Teams Always Green"
    $welcomeTitle.Location = New-Object System.Drawing.Point(44, 4)

    $welcomeTagline = New-Object System.Windows.Forms.Label
    $welcomeTagline.AutoSize = $false
    $welcomeTagline.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
    $welcomeTagline.Text = "Stay available without micromanaging your status."
    $welcomeTagline.Location = New-Object System.Drawing.Point(44, 30)
    $welcomeTagline.Width = 520
    $welcomeTagline.Height = 18
    $welcomeTagline.Padding = New-Object System.Windows.Forms.Padding(0, 1, 0, 0)

    $headerPanel.Controls.Add($welcomeIconBox)
    $headerPanel.Controls.Add($welcomeTitle)
    $headerPanel.Controls.Add($welcomeTagline)

    $card = New-Object System.Windows.Forms.Panel
    $card.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $card.Width = 580
    $card.Height = 210
    $card.Location = New-Object System.Drawing.Point(0, 60)

    $welcomeBody = New-Object System.Windows.Forms.Label
    $welcomeBody.AutoSize = $false
    $welcomeBody.Width = 550
    $welcomeBody.Height = 190
    $welcomeBody.Location = New-Object System.Drawing.Point(12, 10)
                $welcomeBody.Text = @(
        "Quick setup will install the app and walk you through the choices below.",
        "",
        "Steps:",
        "  1) Choose an install folder (default is Documents\\Teams Always Green)",
        "  2) Choose whether to create shortcuts",
        "  3) Download and verify app files",
        "  4) Review the summary and launch",
        "",
        "This setup will:",
        "  - Install the app files into a single folder",
        "  - Optionally create Start Menu/Desktop/Startup shortcuts",
        "",
        "This setup does not:",
        "  - Change your Teams settings",
        "  - Run anything in the background without your permission"
    ) -join [Environment]::NewLine

    $card.Controls.Add($welcomeBody)

    $chkShortcuts = New-Object System.Windows.Forms.CheckBox
    $chkShortcuts.Text = "Create Start Menu/Desktop shortcuts (Recommended)"
    $chkShortcuts.Checked = $true
    $chkShortcuts.AutoSize = $true
    $chkShortcuts.Location = New-Object System.Drawing.Point(8, 280)

    $chkStartup = New-Object System.Windows.Forms.CheckBox
    $chkStartup.Text = "Start with Windows"
    $chkStartup.Checked = $false
    $chkStartup.AutoSize = $true
    $chkStartup.Location = New-Object System.Drawing.Point(8, 304)

    $chkShortcuts.Add_CheckedChanged({
        $chkStartup.Enabled = [bool]$chkShortcuts.Checked
        if (-not $chkStartup.Enabled) { $chkStartup.Checked = $false }
    })

    $panelWelcome.Controls.Add($headerPanel)
    $panelWelcome.Controls.Add($card)
    $panelWelcome.Controls.Add($chkShortcuts)
    $panelWelcome.Controls.Add($chkStartup)

    $panelLocation = New-Object System.Windows.Forms.Panel
    $panelLocation.Location = New-Object System.Drawing.Point(16, 44)
    $panelLocation.Size = New-Object System.Drawing.Size(600, 320)
    $panelLocation.Visible = $false

    $locLabel = New-Object System.Windows.Forms.Label
    $locLabel.AutoSize = $true
    $locLabel.Text = "Step 1 of 4: Choose the install folder location."
    $locLabel.Location = New-Object System.Drawing.Point(0, 0)

    $locText = New-Object System.Windows.Forms.TextBox
    $locText.Width = 420
    $locText.Location = New-Object System.Drawing.Point(0, 28)

    $locBrowse = New-Object System.Windows.Forms.Button
    $locBrowse.Text = "Browse..."
    $locBrowse.Width = 90
    $locBrowse.Location = New-Object System.Drawing.Point(430, 26)

    $locDefault = New-Object System.Windows.Forms.CheckBox
    $locDefault.Text = "Use default install location"
    $locDefault.AutoSize = $true
    $locDefault.Checked = $true
    $locDefault.Location = New-Object System.Drawing.Point(0, 56)

    $locHint = New-Object System.Windows.Forms.Label
    $locHint.AutoSize = $true
    $locHint.Text = "A 'Teams Always Green' folder will be created inside the selected path."
    $locHint.Location = New-Object System.Drawing.Point(0, 82)

    $applyDefaultLocation = {
        $defaultBase = Get-LastInstallBase
        $locText.Text = $defaultBase
        $locText.ReadOnly = $true
        $locBrowse.Enabled = $false
    }

    $locDefault.Add_CheckedChanged({
        if ($locDefault.Checked) {
            & $applyDefaultLocation
        } else {
            $locText.ReadOnly = $false
            $locBrowse.Enabled = $true
        }
    })

    $locStatus = New-Object System.Windows.Forms.Label
    $locStatus.AutoSize = $true
    $locStatus.Location = New-Object System.Drawing.Point(0, 104)

    $updateLocationStatus = {
        $base = $locText.Text
        if ([string]::IsNullOrWhiteSpace($base)) {
            $locStatus.Text = "Choose a folder to continue."
            $locStatus.ForeColor = [System.Drawing.Color]::FromArgb(140, 80, 0)
            return
        }
        if (-not (Test-Path $base)) {
            $locStatus.Text = "Folder does not exist. You can create it on the next step."
            $locStatus.ForeColor = [System.Drawing.Color]::FromArgb(140, 80, 0)
            return
        }
        try {
            $probePath = Join-Path $base ("write-test-{0}.tmp" -f [Guid]::NewGuid().ToString("N"))
            Set-Content -Path $probePath -Value "ok" -Encoding ASCII -ErrorAction Stop
            Remove-Item -Path $probePath -Force -ErrorAction SilentlyContinue
            $locStatus.Text = "Writable folder detected."
            $locStatus.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 60)
        } catch {
            $locStatus.Text = "Folder is not writable. Choose a different location."
            $locStatus.ForeColor = [System.Drawing.Color]::FromArgb(170, 40, 40)
        }
    }

    $locText.Add_TextChanged({ & $updateLocationStatus })
    $locDefault.Add_CheckedChanged({ & $updateLocationStatus })
    & $applyDefaultLocation
    & $updateLocationStatus

    $locBrowse.Add_Click({
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = "Select the parent folder (we will create a Teams Always Green folder inside)"
        $dialog.SelectedPath = $locText.Text
        if ($dialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
            $locText.Text = $dialog.SelectedPath
        }
    })

    $panelLocation.Controls.Add($locLabel)
    $panelLocation.Controls.Add($locText)
    $panelLocation.Controls.Add($locBrowse)
    $panelLocation.Controls.Add($locDefault)
    $panelLocation.Controls.Add($locHint)
    $panelLocation.Controls.Add($locStatus)

    $panelDownload = New-Object System.Windows.Forms.Panel
    $panelDownload.Location = New-Object System.Drawing.Point(16, 44)
    $panelDownload.Size = New-Object System.Drawing.Size(600, 320)
    $panelDownload.Visible = $false

    $dlLabel = New-Object System.Windows.Forms.Label
    $dlLabel.AutoSize = $true
    $dlLabel.Text = "Step 2 of 4: Preparing download..."
    $dlLabel.Location = New-Object System.Drawing.Point(0, 0)

    $dlProgress = New-Object System.Windows.Forms.ProgressBar
    $dlProgress.Width = 560
    $dlProgress.Height = 20
    $dlProgress.Location = New-Object System.Drawing.Point(0, 28)
    $dlProgress.Minimum = 0
    $dlProgress.Maximum = 100

    $dlMeta = New-Object System.Windows.Forms.Label
    $dlMeta.AutoSize = $true
    $dlMeta.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
    $dlMeta.Text = "Files: 0/0"
    $dlMeta.Location = New-Object System.Drawing.Point(0, 54)

    $dlSummary = New-Object System.Windows.Forms.Label
    $dlSummary.AutoSize = $true
    $dlSummary.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
    $dlSummary.Text = ""
    $dlSummary.Location = New-Object System.Drawing.Point(0, 72)

    $dlDetailsLink = New-Object System.Windows.Forms.LinkLabel
    $dlDetailsLink.Text = "Show details"
    $dlDetailsLink.AutoSize = $true
    $dlDetailsLink.Location = New-Object System.Drawing.Point(460, 54)

    $dlDetailsList = New-Object System.Windows.Forms.ListBox
    $dlDetailsList.Width = 560
    $dlDetailsList.Height = 160
    $dlDetailsList.Location = New-Object System.Drawing.Point(0, 96)
    $dlDetailsList.HorizontalScrollbar = $true
    $dlDetailsList.IntegralHeight = $false
    $dlDetailsList.Visible = $false

    $dlCancel = New-Object System.Windows.Forms.Button
    $dlCancel.Text = "Cancel Download"
    $dlCancel.Width = 130
    $dlCancel.Location = New-Object System.Drawing.Point(0, 248)

    $panelDownload.Controls.Add($dlLabel)
    $panelDownload.Controls.Add($dlProgress)
    $panelDownload.Controls.Add($dlMeta)
    $panelDownload.Controls.Add($dlDetailsLink)
    $panelDownload.Controls.Add($dlDetailsList)
    $panelDownload.Controls.Add($dlCancel)
    $panelDownload.Controls.Add($dlSummary)

    $panelSummary = New-Object System.Windows.Forms.Panel
    $panelSummary.Location = New-Object System.Drawing.Point(16, 44)
    $panelSummary.Size = New-Object System.Drawing.Size(600, 320)
    $panelSummary.Visible = $false

    $summaryTitle = New-Object System.Windows.Forms.Label
    $summaryTitle.AutoSize = $true
    $summaryTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $summaryTitle.Text = "Install completed successfully."
    $summaryTitle.Location = New-Object System.Drawing.Point(0, 0)

    $summaryGroup = New-Object System.Windows.Forms.GroupBox
    $summaryGroup.Text = "Install summary"
    $summaryGroup.Width = 580
    $summaryGroup.Height = 180
    $summaryGroup.Location = New-Object System.Drawing.Point(0, 30)

    $summaryTable = New-Object System.Windows.Forms.TableLayoutPanel
    $summaryTable.Dock = [System.Windows.Forms.DockStyle]::Fill
    $summaryTable.Padding = New-Object System.Windows.Forms.Padding(10, 18, 10, 10)
    $summaryTable.ColumnCount = 2
    $summaryTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $summaryTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $sumInstall = New-Object System.Windows.Forms.Label
    $sumMode = New-Object System.Windows.Forms.Label
    $sumSource = New-Object System.Windows.Forms.Label
    $sumIntegrity = New-Object System.Windows.Forms.Label
    $sumShortcuts = New-Object System.Windows.Forms.Label
    $sumLog = New-Object System.Windows.Forms.LinkLabel

    foreach ($lbl in @($sumInstall,$sumMode,$sumSource,$sumIntegrity,$sumShortcuts,$sumLog)) {
        $lbl.AutoSize = $true
        $lbl.MaximumSize = New-Object System.Drawing.Size(420, 0)
    }
    $sumLog.LinkBehavior = [System.Windows.Forms.LinkBehavior]::HoverUnderline
    $sumLog.Add_LinkClicked({ if (Test-Path $logPath) { Start-Process $logPath } })

    $addRow = {
        param([string]$labelText, $valueLabel)
        $row = $summaryTable.RowCount
        $summaryTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
        $label = New-Object System.Windows.Forms.Label
        $label.AutoSize = $true
        $label.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $label.Text = $labelText
        $label.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 6)
        $valueLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)
        $summaryTable.Controls.Add($label, 0, $row)
        $summaryTable.Controls.Add($valueLabel, 1, $row)
        $summaryTable.RowCount++
    }

    & $addRow "Install Path:" $sumInstall
    & $addRow "Mode:" $sumMode
    & $addRow "Source:" $sumSource
    & $addRow "Integrity:" $sumIntegrity
    & $addRow "Shortcuts:" $sumShortcuts
    & $addRow "Setup Log:" $sumLog

    $summaryGroup.Controls.Add($summaryTable)

    $pinTip = New-Object System.Windows.Forms.Label
    $pinTip.AutoSize = $true
    $pinTip.ForeColor = [System.Drawing.Color]::FromArgb(90,90,90)
    $pinTip.Text = "Tip: Pin the tray icon via the ^ menu so it's always visible."
    $pinTip.Location = New-Object System.Drawing.Point(0, 220)

    $sumLaunch = New-Object System.Windows.Forms.Button
    $sumLaunch.Text = "Launch"
    $sumLaunch.Width = 90
    $sumLaunch.Location = New-Object System.Drawing.Point(0, 250)

    $sumSettings = New-Object System.Windows.Forms.Button
    $sumSettings.Text = "Settings"
    $sumSettings.Width = 90
    $sumSettings.Location = New-Object System.Drawing.Point(100, 250)

    $sumFolder = New-Object System.Windows.Forms.Button
    $sumFolder.Text = "Open Folder"
    $sumFolder.Width = 110
    $sumFolder.Location = New-Object System.Drawing.Point(200, 250)

    $sumClose = New-Object System.Windows.Forms.Button
    $sumClose.Text = "Close"
    $sumClose.Width = 90
    $sumClose.Location = New-Object System.Drawing.Point(490, 250)

    $copyLog = New-Object System.Windows.Forms.Button
    $copyLog.Text = "Copy log path"
    $copyLog.Width = 110
    $copyLog.Location = New-Object System.Drawing.Point(0, 280)
    $copyLog.Add_Click({ try { [System.Windows.Forms.Clipboard]::SetText($logPath) } catch { $null = $_ } })

    $openAfter = New-Object System.Windows.Forms.CheckBox
    $openAfter.Text = "Open install folder after finish"
    $openAfter.AutoSize = $true
    $openAfter.Location = New-Object System.Drawing.Point(130, 282)

    $panelSummary.Controls.Add($summaryTitle)
    $panelSummary.Controls.Add($summaryGroup)
    $panelSummary.Controls.Add($pinTip)
    $panelSummary.Controls.Add($sumLaunch)
    $panelSummary.Controls.Add($sumSettings)
    $panelSummary.Controls.Add($sumFolder)
    $panelSummary.Controls.Add($sumClose)
    $panelSummary.Controls.Add($copyLog)
    $panelSummary.Controls.Add($openAfter)

    $btnBack = New-Object System.Windows.Forms.Button
    $btnBack.Text = "Back"
    $btnBack.Width = 90
    $btnBack.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right

    $btnNext = New-Object System.Windows.Forms.Button
    $btnNext.Text = "Next"
    $btnNext.Width = 90
    $btnNext.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Width = 90
    $btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right

    $form.Controls.Add($title)
    $form.Controls.Add($stepper)
    $form.Controls.Add($panelWelcome)
    $form.Controls.Add($panelLocation)
    $form.Controls.Add($panelDownload)
    $form.Controls.Add($panelSummary)
    $baseFormHeight = $form.Height
    $summaryFormHeight = [Math]::Max(420, $baseFormHeight - 50)
    $positionNavButtons = {
        if (-not $form -or $form.IsDisposed) { return }
        $clientWidth = Get-ScalarInt @($form.ClientSize.Width)
        $clientHeight = Get-ScalarInt @($form.ClientSize.Height)
        $cancelWidth = Get-ScalarInt @($btnCancel.Width)
        $cancelHeight = Get-ScalarInt @($btnCancel.Height)
        $nextWidth = Get-ScalarInt @($btnNext.Width)
        $backWidth = Get-ScalarInt @($btnBack.Width)
        $buttonsY = $clientHeight - $cancelHeight - 14
        if ($buttonsY -lt 0) { $buttonsY = 0 }
        $btnCancel.Location = New-Object System.Drawing.Point(($clientWidth - $cancelWidth - 16), $buttonsY)
        $btnNext.Location = New-Object System.Drawing.Point(($btnCancel.Left - $nextWidth - 10), $buttonsY)
        $btnBack.Location = New-Object System.Drawing.Point(($btnNext.Left - $backWidth - 10), $buttonsY)
    }
    & $positionNavButtons
    $form.add_Shown({ & $positionNavButtons })
    $form.add_ClientSizeChanged({ & $positionNavButtons })

    $form.Controls.Add($btnBack)
    $form.Controls.Add($btnNext)
    $form.Controls.Add($btnCancel)

    $stepRef = [ref]0
    $state.DownloadComplete = $false
    $state.OpenAfterFinish = $false

    $showStep = {
        param([int]$index)
        if ($index -eq 3 -and -not $state.AllowSummary) { return }
        $stepRef.Value = $index
        $panelWelcome.Visible = ($index -eq 0)
        $panelLocation.Visible = ($index -eq 1)
        $panelDownload.Visible = ($index -eq 2)
        $panelSummary.Visible = ($index -eq 3)
        switch ($index) {
            0 { $stepper.Text = "Step 1 of 4 - Welcome" }
            1 { $stepper.Text = "Step 1 of 4 - Location" }
            2 { $stepper.Text = "Step 2 of 4 - Download" }
            3 { $stepper.Text = "Step 4 of 4 - Summary" }
        }
        if ($index -eq 3) {
            $form.Height = $summaryFormHeight
        } else {
            $form.Height = $baseFormHeight
        }
        & $positionNavButtons
        $btnBack.Enabled = ($index -gt 0 -and $index -lt 3)
        $btnBack.Visible = ($index -lt 3)
        $btnNext.Visible = ($index -lt 3)
        $btnCancel.Visible = ($index -lt 3)
        if ($index -eq 2) {
            $btnNext.Enabled = $state.DownloadComplete
        } elseif ($index -eq 3) {
            $btnBack.Enabled = $false
            $btnNext.Enabled = $false
            $btnBack.Visible = $false
            $btnNext.Visible = $false
            $btnCancel.Visible = $false
        } else {
            $btnNext.Enabled = $true
        }
    }

    $btnCancel.Add_Click({ $state.Cancelled = $true; $form.Close() })
    $btnBack.Add_Click({
        if ($stepRef.Value -eq 1) { & $showStep 0 }
        elseif ($stepRef.Value -eq 2 -and -not $state.DownloadComplete) { & $showStep 1 }
    })

    $btnNext.Add_Click({
        Write-SetupLog ("Next clicked. Step={0} DownloadComplete={1}" -f $stepRef.Value, $state.DownloadComplete)
        if ($stepRef.Value -eq 2) {
            if (-not $state.DownloadComplete) {
                Show-SetupInfo "Download is still running. Please wait until it finishes."
                return
            }
            if (-not $state.FinalizeCompleted) {
                $btnNext.Enabled = $false
                $btnBack.Enabled = $false
                $btnCancel.Enabled = $false
                if ($dlLabel) { $dlLabel.Text = "Finalizing install..." }
                [System.Windows.Forms.Application]::DoEvents()
                try {
                    $state.ShortcutsCreated = Finalize-Install -installPath $state.InstallPath -targetScript $targetScript -portableMode $state.PortableMode -enableStartup $state.EnableStartup -manifest $state.Manifest
                    $state.FinalizeCompleted = $true
                } catch {
                    Write-SetupLog ("Finalize-Install failed: {0}" -f $_.Exception.Message)
                    $state.ShortcutsCreated = @("Install finalized with warnings")
                    $state.FinalizeCompleted = $true
                }
            }
            $sumInstall.Text = $state.InstallPath
            $sumMode.Text = if ($state.PortableMode) { "Portable (no shortcuts)" } else { "Standard" }
            $sumSource.Text = if ($state.OneDriveRiskDetected) { "{0} | OneDrive path advisory" -f $state.InstallSource } else { $state.InstallSource }
            $sumIntegrity.Text = $state.IntegrityStatus
            $sumShortcuts.Text = if ($state.ShortcutsCreated.Count -gt 0) { $state.ShortcutsCreated -join "; " } else { "None" }
            $sumLog.Text = $logPath
            $pinTip.Visible = (-not $state.PortableMode)
            $state.AllowSummary = $true
            & $showStep 3
            return
        }
        if ($stepRef.Value -eq 0) {
            $state.CreateShortcuts = [bool]$chkShortcuts.Checked
            $state.EnableStartup = [bool]$chkStartup.Checked
            & $applyDefaultLocation
            & $showStep 1
            return
        }
        if ($stepRef.Value -eq 1) {
            if ($locDefault.Checked) { & $applyDefaultLocation }
            if ([string]::IsNullOrWhiteSpace($locText.Text)) {
                & $applyDefaultLocation
            }
            $selectedBase = $locText.Text
            Set-LastInstallBase $selectedBase
            try {
                $root = [System.IO.Path]::GetPathRoot($selectedBase)
                $drive = Get-PSDrive -Name $root.TrimEnd('\') -ErrorAction SilentlyContinue
                if ($drive -and $drive.Free -lt 200MB) {
                    Show-SetupInfo "Not enough free space in the selected drive (need at least 200 MB)."
                    return
                }
            } catch { $null = $_ }
            try {
                $probePath = Join-Path $selectedBase ("write-test-{0}.tmp" -f [Guid]::NewGuid().ToString("N"))
                Set-Content -Path $probePath -Value "ok" -Encoding ASCII
                Remove-Item -Path $probePath -Force -ErrorAction SilentlyContinue
            } catch {
                Show-SetupInfo "Cannot write to the selected folder. Choose a different location."
                return
            }
            $appFolderName = "Teams Always Green"
            if ([string]::Equals([System.IO.Path]::GetFileName($selectedBase), $appFolderName, [System.StringComparison]::OrdinalIgnoreCase)) {
                $state.InstallPath = $selectedBase
            } else {
                $state.InstallPath = Join-Path $selectedBase $appFolderName
            }

            $oneDriveRisk = Get-OneDrivePathDiagnostics -path $state.InstallPath
            $state.OneDriveRiskDetected = [bool]$oneDriveRisk.IsOneDriveManaged
            $state.OneDriveRiskSummary = [string]$oneDriveRisk.Summary
            $state.OneDriveRecommendedPath = [string]$oneDriveRisk.RecommendedInstallPath
            if ($state.OneDriveRiskDetected) {
                Write-SetupLog ("OneDrive install-path advisory: Path={0}; Signals={1}; Recommended={2}" -f $state.InstallPath, $state.OneDriveRiskSummary, $state.OneDriveRecommendedPath)
                $warningMessage = @(
                    "The selected install location appears to be OneDrive-managed."
                    ""
                    "Selected: $($state.InstallPath)"
                    "Recommended: $($state.OneDriveRecommendedPath)"
                    ""
                    "Sync/file-provider locking can interrupt install, update, or uninstall for business users."
                    "Continue anyway?"
                ) -join [Environment]::NewLine
                $warningResult = Show-SetupPrompt -message $warningMessage -title "OneDrive path warning" -buttons ([System.Windows.Forms.MessageBoxButtons]::YesNo) -icon ([System.Windows.Forms.MessageBoxIcon]::Warning) -owner $form
                if ($warningResult -ne [System.Windows.Forms.DialogResult]::Yes) {
                    Show-SetupInfo -message ("Choose a local non-synced folder. Recommended:`n{0}" -f $state.OneDriveRecommendedPath) -owner $form
                    return
                }
            }

            if (-not (Test-Path $state.InstallPath)) {
                New-Item -ItemType Directory -Path $state.InstallPath -Force | Out-Null
            }
            $state.PortableMode = (-not $state.CreateShortcuts)
            $shortcutsSummary = if ($state.CreateShortcuts) { "Shortcuts: Yes" } else { "Shortcuts: No" }
            $startupSummary = if ($state.EnableStartup) { "Startup: Yes" } else { "Startup: No" }
            $modeSummary = if ($state.PortableMode) { "Mode: Portable" } else { "Mode: Standard" }
            if ($dlSummary) {
                $dlSummary.Text = ("Install to: {0} | {1} | {2} | {3}" -f $state.InstallPath, $modeSummary, $shortcutsSummary, $startupSummary)
                if ($state.OneDriveRiskDetected) {
                    $dlSummary.Text = ("{0} | OneDrive: Warning" -f $dlSummary.Text)
                }
            }
            & $showStep 2
            $targetScript = Join-Path $state.InstallPath "Script\Teams Always Green.ps1"

            $folders = @(
                "Debug","Meta","Meta\Icons","Meta\Keys","Script","Script\Core","Script\Features","Script\I18n","Script\Tray","Script\UI","Script\Uninstall"
            )
            if ($state.PortableMode) {
                $folders += @("Logs", "Settings")
            }
            foreach ($name in $folders) {
                $path = Join-Path $state.InstallPath $name
                if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
            }

            $metaDir = Join-Path $state.InstallPath "Meta"
            $portableMarker = Join-Path $metaDir "PortableMode.txt"
            if ($state.PortableMode) {
                try {
                    Set-Content -Path $portableMarker -Value ("PortableMode=1`nSetOn={0}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")) -Encoding ASCII
                    Write-SetupLog "Portable mode enabled."
                } catch {
                            $null = $_
                        }
            } else {
                try { if (Test-Path $portableMarker) { Remove-Item -Path $portableMarker -Force -ErrorAction SilentlyContinue } } catch { $null = $_ }
            }
            foreach ($legacyLocator in @(
                (Join-Path $metaDir "Teams-Always-Green.settings.path.txt"),
                (Join-Path $metaDir "Teams-Always-Green.log.path.txt"),
                (Join-Path $state.InstallPath "Teams-Always-Green.settings.path.txt"),
                (Join-Path $state.InstallPath "Teams-Always-Green.log.path.txt")
            )) {
                try { if (Test-Path $legacyLocator) { Remove-Item -Path $legacyLocator -Force -ErrorAction SilentlyContinue } } catch { $null = $_ }
            }

            $localRoot = Get-QuickSetupSourceRoot
            $useLocal = $false
            if ($localRoot -and (Test-Path (Join-Path $localRoot "Script\Teams Always Green.ps1"))) {
                $useLocal = $true
                Write-SetupLog "Using local app files for install."
            }
            $state.InstallSource = if ($useLocal) { "Local repository" } else { "Remote (GitHub)" }
            if ($dlSummary) {
                $dlSummary.Text = ("{0} | Source: {1}" -f $dlSummary.Text, $state.InstallSource)
            }

            $manifest = $null
            $manifestSignature = $null
            if ($useLocal) {
                $manifest = Load-Manifest (Join-Path $localRoot $script:QuickSetupManifestRelativePath)
                $manifestSignature = Load-ManifestSignature (Join-Path $localRoot $script:QuickSetupManifestSignatureRelativePath)
            } else {
                $manifestUrl = "$script:QuickSetupRawBase/Script/QuickSetup/QuickSetup.manifest.json?v=$script:QuickSetupCacheBuster"
                if (-not (Test-QuickSetupTrustedUrl $manifestUrl)) {
                    Show-SetupError ("Blocked untrusted manifest URL: {0}" -f $manifestUrl)
                    $state.Cancelled = $true
                    $form.Close()
                    return
                }
                $manifestTarget = Join-Path $state.InstallPath "Meta\QuickSetup.manifest.json"
                try {
                    Invoke-WebRequest -Uri $manifestUrl -OutFile $manifestTarget -UseBasicParsing
                    $manifest = Load-Manifest $manifestTarget
                } catch {
                    Show-SetupError "Manifest download failed. Setup cannot continue without integrity validation."
                    $state.Cancelled = $true
                    $form.Close()
                    return
                }
                $manifestSignatureUrl = "$script:QuickSetupRawBase/Script/QuickSetup/QuickSetup.manifest.sig?v=$script:QuickSetupCacheBuster"
                if (-not (Test-QuickSetupTrustedUrl $manifestSignatureUrl)) {
                    Show-SetupError ("Blocked untrusted manifest signature URL: {0}" -f $manifestSignatureUrl)
                    $state.Cancelled = $true
                    $form.Close()
                    return
                }
                $manifestSignatureTarget = Join-Path $state.InstallPath "Meta\QuickSetup.manifest.sig"
                try {
                    Invoke-WebRequest -Uri $manifestSignatureUrl -OutFile $manifestSignatureTarget -UseBasicParsing -ErrorAction Stop
                    $manifestSignature = Load-ManifestSignature $manifestSignatureTarget
                } catch {
                    Write-SetupLog "Manifest signature was not downloaded; proceeding with hash-manifest validation."
                }
            }
            $manifestCheck = Test-QuickSetupManifest -manifest $manifest -files $script:QuickSetupFiles
            if (-not $manifestCheck.IsValid) {
                Show-SetupError ("Manifest validation failed: {0}" -f $manifestCheck.Reason)
                $state.Cancelled = $true
                $form.Close()
                return
            }
            $manifestSignatureCheck = Test-QuickSetupManifestSignature -manifest $manifest -signatureText $manifestSignature -publicKeyXml $script:QuickSetupManifestSignaturePublicKeyXml -RequireSignature:$script:QuickSetupRequireManifestSignature
            if (-not $manifestSignatureCheck.IsValid) {
                Show-SetupError ("Manifest signature validation failed: {0}" -f $manifestSignatureCheck.Reason)
                $state.Cancelled = $true
                $form.Close()
                return
            }
            $state.IntegrityStatus = "Verified"
            if ($manifestSignatureCheck.Status -eq "Verified") {
                $state.IntegrityStatus = "Verified (manifest signature)"
            } elseif ($manifestSignatureCheck.Status -eq "NoPublicKey") {
                $state.IntegrityStatus = "Verified (signature present, key not configured)"
            }
            $state.Manifest = $manifest

    $downloadUi = @{
        Form = $form
        Label = $dlLabel
        Progress = $dlProgress
        Meta = $dlMeta
        DetailsLink = $dlDetailsLink
        DetailsList = $dlDetailsList
        CancelButton = $dlCancel
        NextButton = $null
        NextClicked = $false
        Cancelled = $false
        StartTime = (Get-Date)
        BytesDownloaded = 0
    }
    $dlDetailsLink.Add_LinkClicked({
        $dlDetailsList.Visible = -not $dlDetailsList.Visible
        $dlDetailsLink.Text = if ($dlDetailsList.Visible) { "Hide details" } else { "Show details" }
    })
    $dlCancel.Add_Click({
        $downloadUi.Cancelled = $true
        $dlCancel.Enabled = $false
        $dlLabel.Text = "Canceling after current file..."
    })

            $total = $script:QuickSetupFiles.Count
            $index = 0
            $downloaded = New-Object System.Collections.ArrayList
            foreach ($file in $script:QuickSetupFiles) {
                if ($downloadUi.Cancelled) { break }
                $index++
                $targetPath = Join-Path $state.InstallPath $file.Path
                $status = "Step 2 of 4: Downloading {0} ({1}/{2})" -f $file.Path, $index, $total
                if ($downloadUi.DetailsList) {
                    [void]$downloadUi.DetailsList.Items.Insert(0, $file.Path)
                }
                Update-Progress $downloadUi $index $total $status
                Write-SetupLog $status

                if ($useLocal) {
                    $sourcePath = Join-Path $localRoot $file.Path
                    if (-not (Test-Path $sourcePath)) {
                        Show-SetupError "Missing local file: $sourcePath"
                        $state.Cancelled = $true
                        break
                    }
                    Copy-Item -Path $sourcePath -Destination $targetPath -Force
                } else {
                    try {
                        if (-not (Test-QuickSetupTrustedUrl $file.Url)) {
                            Show-SetupError ("Blocked untrusted download URL: {0}" -f [string]$file.Url)
                            $state.Cancelled = $true
                            break
                        }
                        $downloadUrl = if ($file.Url -match "\?") { "$($file.Url)&v=$script:QuickSetupCacheBuster" } else { "$($file.Url)?v=$script:QuickSetupCacheBuster" }
                        Invoke-WebRequest -Uri $downloadUrl -OutFile $targetPath -UseBasicParsing
                    } catch {
                        $choice = Show-SetupPrompt -message ("Download failed for:`n{0}`n`nRetry = try this file again`nIgnore = go back to location step`nAbort = cancel setup" -f $file.Url) -title "Download Failed" -buttons ([System.Windows.Forms.MessageBoxButtons]::AbortRetryIgnore) -icon ([System.Windows.Forms.MessageBoxIcon]::Warning) -owner $form
                        if ($choice -eq [System.Windows.Forms.DialogResult]::Retry) {
                            $index--
                            continue
                        }
                        if ($choice -eq [System.Windows.Forms.DialogResult]::Ignore) {
                            $state.Cancelled = $true
                            & $showStep 1
                            break
                        }
                        $state.Cancelled = $true
                        break
                    }
                }

                if (Test-Path $targetPath) { [void]$downloaded.Add($targetPath) }

                if ($manifest -and $manifest.files) {
                    $manifestKey = $file.Path.Replace("\", "/")
                    $expected = [string]$manifest.files.$manifestKey
                    if ([string]::IsNullOrWhiteSpace($expected)) {
                        Show-SetupError ("Manifest expected hash is missing for {0}." -f $file.Path)
                        $state.Cancelled = $true
                        break
                    }
                    Update-Progress $downloadUi $index $total ("Step 2 of 4: Verifying {0} ({1}/{2})" -f $file.Path, $index, $total)
                    $actual = Get-FileHashHex $targetPath
                    if (-not $actual -or ($actual.ToLowerInvariant() -ne [string]$expected.ToLowerInvariant())) {
                        $matched = $false
                        if (Is-TextFile $file.Path) {
                            $altLf = Get-NormalizedBytesHash $targetPath "LF"
                            if ($altLf -and ($altLf.ToLowerInvariant() -eq [string]$expected.ToLowerInvariant())) {
                                $matched = $true
                            } else {
                                $altCrLf = Get-NormalizedBytesHash $targetPath "CRLF"
                                if ($altCrLf -and ($altCrLf.ToLowerInvariant() -eq [string]$expected.ToLowerInvariant())) {
                                    $matched = $true
                                }
                            }
                        }
                        if (-not $matched) {
                            Show-SetupError ("Integrity check failed for {0}. See log for hash details." -f $file.Path)
                            $state.Cancelled = $true
                            break
                        }
                    }
                }
            }

            if ($downloadUi.Cancelled -or $state.Cancelled) {
                foreach ($path in $downloaded) {
                    try { Remove-Item -Path $path -Force -ErrorAction Stop } catch { $null = $_ }
                }
                $state.Cancelled = $true
                $form.Close()
                return
            }

            Update-Progress $downloadUi $total $total "Step 2 of 4: Download complete. Click Next to continue."
            if ($dlSummary) {
                $dlSummary.Text = "Download + integrity verification complete. Click Next to finalize install."
            }
            $state.DownloadComplete = $true
            $btnNext.Enabled = $true
            [System.Windows.Forms.Application]::DoEvents()
            return
        }
    })

    $sumLaunch.Add_Click({ $state.OpenAfterFinish = [bool]$openAfter.Checked; $state.Action = "Launch"; $form.Close() })
    $sumSettings.Add_Click({ $state.OpenAfterFinish = [bool]$openAfter.Checked; $state.Action = "Settings"; $form.Close() })
    $sumFolder.Add_Click({ $state.OpenAfterFinish = [bool]$openAfter.Checked; $state.Action = "Folder"; $form.Close() })
    $sumClose.Add_Click({ $state.OpenAfterFinish = [bool]$openAfter.Checked; $state.Action = "Close"; $form.Close() })

    & $showStep 0
    if ($owner) { $form.ShowDialog($owner) | Out-Null } else { $form.ShowDialog() | Out-Null }
    return $state
}

$script:QuickSetupRawBase = "https://raw.githubusercontent.com/alexphillips-dev/Teams-Always-Green/main"
$script:QuickSetupCacheBuster = [Guid]::NewGuid().ToString("N")
$script:QuickSetupFiles = @(
    @{ Url = "$script:QuickSetupRawBase/Script/Teams%20Always%20Green.ps1"; Path = "Script\Teams Always Green.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Core/Logging.ps1"; Path = "Script\Core\Logging.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Core/Paths.ps1"; Path = "Script\Core\Paths.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Core/Runtime.ps1"; Path = "Script\Core\Runtime.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Core/DateTime.ps1"; Path = "Script\Core\DateTime.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Core/Settings.ps1"; Path = "Script\Core\Settings.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Features/Hotkeys.ps1"; Path = "Script\Features\Hotkeys.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Features/Profiles.ps1"; Path = "Script\Features\Profiles.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Features/Scheduling.ps1"; Path = "Script\Features\Scheduling.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Features/UpdateEngine.ps1"; Path = "Script\Features\UpdateEngine.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/I18n/UiStrings.ps1"; Path = "Script\I18n\UiStrings.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Tray/Menu.ps1"; Path = "Script\Tray\Menu.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/UI/SettingsDialog.ps1"; Path = "Script\UI\SettingsDialog.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/UI/HistoryDialog.ps1"; Path = "Script\UI\HistoryDialog.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Uninstall/Uninstall-Teams-Always-Green.ps1"; Path = "Script\Uninstall\Uninstall-Teams-Always-Green.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Uninstall/Uninstall-Teams-Always-Green.vbs"; Path = "Script\Uninstall\Uninstall-Teams-Always-Green.vbs" },
    @{ Url = "$script:QuickSetupRawBase/VERSION"; Path = "VERSION" },
    @{ Url = "$script:QuickSetupRawBase/Teams%20Always%20Green.VBS"; Path = "Teams Always Green.VBS" },
    @{ Url = "$script:QuickSetupRawBase/Debug/Teams%20Always%20Green%20-%20Debug.VBS"; Path = "Debug\Teams Always Green - Debug.VBS" },
    @{ Url = "$script:QuickSetupRawBase/Meta/Keys/quicksetup-manifest-public.xml"; Path = "Meta\Keys\quicksetup-manifest-public.xml" },
    @{ Url = "$script:QuickSetupRawBase/Meta/Teams-Always-Green.updatekey.xml"; Path = "Meta\Teams-Always-Green.updatekey.xml" },
    @{ Url = "$script:QuickSetupRawBase/Meta/Icons/Tray_Icon.ico"; Path = "Meta\Icons\Tray_Icon.ico" },
    @{ Url = "$script:QuickSetupRawBase/Meta/Icons/Settings_Icon.ico"; Path = "Meta\Icons\Settings_Icon.ico" }
)

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {
            $null = $_
        }

Write-SetupLog "Quick setup started."
$setupOwner = New-SetupOwner
$wizard = Show-SetupWizard -owner $setupOwner
if ($setupOwner -and -not $setupOwner.IsDisposed) { $setupOwner.Close() }

if (-not $wizard -or $wizard.Cancelled) {
    Write-SetupLog "Install canceled in setup wizard."
    Cleanup-SetupTempFiles -success $true
    exit 1
}

$installPath = $wizard.InstallPath
if ([string]::IsNullOrWhiteSpace($installPath)) {
    Write-SetupLog "Install canceled: missing install path."
    Cleanup-SetupTempFiles -success $true
    exit 1
}

$targetScript = Join-Path $installPath "Script\Teams Always Green.ps1"
Write-SetupLog ("Summary action selected: {0}" -f $wizard.Action)

if ($wizard.Action -eq "Launch") {
    Write-SetupLog "Launch requested."
    $launchVbs = Join-Path $installPath "Teams Always Green.VBS"
    if (Test-Path $launchVbs) {
        try {
            $proc = Start-Process "$env:WINDIR\System32\wscript.exe" -ArgumentList "`"$launchVbs`"" -WorkingDirectory $installPath -PassThru -ErrorAction Stop
            Write-SetupLog ("Launch started (wscript). PID={0}" -f $proc.Id)
        } catch {
            Write-SetupLog ("Launch failed (wscript): {0}" -f $_.Exception.Message)
        }
    }
    if (-not (Test-Path $targetScript)) {
        Show-SetupError "Launch failed: app script not found at $targetScript"
    } elseif (-not (Test-Path $launchVbs)) {
        $launchArgs = "-NoProfile -ExecutionPolicy RemoteSigned -WindowStyle Hidden -File `"$targetScript`""
        try {
            $proc = Start-Process "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $launchArgs -WorkingDirectory $installPath -PassThru -ErrorAction Stop
            Write-SetupLog ("Launch started (hidden). PID={0}" -f $proc.Id)
        } catch {
            Write-SetupLog ("Launch failed (hidden): {0}" -f $_.Exception.Message)
            try {
                $proc = Start-Process "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList ("-NoProfile -ExecutionPolicy RemoteSigned -File `"$targetScript`"") -WorkingDirectory $installPath -PassThru -ErrorAction Stop
                Write-SetupLog ("Launch started (visible). PID={0}" -f $proc.Id)
            } catch {
                Show-SetupError ("Launch failed: {0}" -f $_.Exception.Message)
            }
        }
    }
} elseif ($wizard.Action -eq "Settings") {
    Start-Process "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy RemoteSigned -WindowStyle Hidden -File `"$targetScript`" -SettingsOnly" -WorkingDirectory $installPath
} elseif ($wizard.Action -eq "Folder") {
    Start-Process "explorer.exe" $installPath
}

if ($wizard.OpenAfterFinish -and $wizard.Action -ne "Folder") {
    try {
        Start-Process "explorer.exe" $installPath
    } catch {
                $null = $_
            }
}

Cleanup-SetupTempFiles -success $true
exit 0
