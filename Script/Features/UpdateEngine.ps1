# --- Update engine (release lookup, validation, apply) ---
# Extracted from main script for maintainability.

function Get-LatestReleaseInfo([string]$owner, [string]$repo) {
    if ([string]::IsNullOrWhiteSpace($owner) -or [string]::IsNullOrWhiteSpace($repo)) { return $null }
    if ($owner -notmatch '^[A-Za-z0-9._-]+$' -or $repo -notmatch '^[A-Za-z0-9._-]+$') {
        Write-Log "Update check blocked: invalid owner/repo setting." "WARN" $null "Update"
        return $null
    }
    $uri = "https://api.github.com/repos/$owner/$repo/releases/latest"
    $headers = @{ "User-Agent" = "TeamsAlwaysGreen" }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    } catch {
    }
    try {
        return Invoke-RestMethod -Uri $uri -Headers $headers -ErrorAction Stop
    } catch {
        Write-Log "Update check failed: $($_.Exception.Message)" "WARN" $_.Exception "Update"
        return $null
    }
}

function Test-TrustedGithubUrl([string]$url, [string]$owner, [string]$repo) {
    if ([string]::IsNullOrWhiteSpace($url)) { return $false }
    try {
        $uri = [System.Uri]$url
        if ($uri.Scheme -ne "https") { return $false }
        $uriHost = $uri.Host.ToLowerInvariant()
        if ($uriHost -notin @("github.com", "api.github.com", "objects.githubusercontent.com")) { return $false }
        $expected = "/$owner/$repo/"
        if ($uriHost -eq "github.com" -or $uriHost -eq "api.github.com") {
            return $uri.AbsolutePath.ToLowerInvariant().Contains($expected.ToLowerInvariant())
        }
        return $true
    } catch {
        return $false
    }
}

function Test-ReleaseTrust([object]$release, [string]$owner, [string]$repo, [bool]$strictPolicy, [bool]$allowPrerelease) {
    if (-not $release) { return [pscustomobject]@{ IsTrusted = $false; Reason = "Release payload missing." } }
    if ($strictPolicy) {
        if ($release.PSObject.Properties.Name -contains "draft" -and [bool]$release.draft) {
            return [pscustomobject]@{ IsTrusted = $false; Reason = "Draft releases are blocked by policy." }
        }
        if (-not $allowPrerelease -and ($release.PSObject.Properties.Name -contains "prerelease") -and [bool]$release.prerelease) {
            return [pscustomobject]@{ IsTrusted = $false; Reason = "Pre-release updates are blocked by policy." }
        }
    }
    if ($release.PSObject.Properties.Name -contains "html_url") {
        if (-not (Test-TrustedGithubUrl ([string]$release.html_url) $owner $repo)) {
            return [pscustomobject]@{ IsTrusted = $false; Reason = "Release html_url does not match trusted repository." }
        }
    }
    if ($release.PSObject.Properties.Name -contains "assets" -and $release.assets) {
        foreach ($asset in $release.assets) {
            if ($asset -and ($asset.PSObject.Properties.Name -contains "browser_download_url")) {
                if (-not (Test-TrustedGithubUrl ([string]$asset.browser_download_url) $owner $repo)) {
                    return [pscustomobject]@{ IsTrusted = $false; Reason = "Asset URL does not match trusted repository." }
                }
            }
        }
    }
    return [pscustomobject]@{ IsTrusted = $true; Reason = "" }
}

function Get-LatestReleaseCached([string]$owner, [string]$repo, [switch]$Force) {
    if (-not $Force) {
        if ($script:UpdateCache.CheckedAt -and $script:UpdateCache.Release) {
            $ageMinutes = ([DateTime]::UtcNow - $script:UpdateCache.CheckedAt).TotalMinutes
            if ($ageMinutes -lt $script:UpdateCacheTtlMinutes) {
                return $script:UpdateCache.Release
            }
        }
    }
    $release = Get-LatestReleaseInfo $owner $repo
    if ($release) {
        $script:UpdateCache.Release = $release
        $script:UpdateCache.CheckedAt = [DateTime]::UtcNow
        $script:UpdateCache.LatestVersion = Get-ReleaseVersionString $release
    }
    return $release
}

function Get-ReleaseVersionString($release) {
    if (-not $release) { return $null }
    $tag = $null
    if ($release.PSObject.Properties.Name -contains "tag_name") { $tag = [string]$release.tag_name }
    if ([string]::IsNullOrWhiteSpace($tag) -and ($release.PSObject.Properties.Name -contains "name")) {
        $tag = [string]$release.name
    }
    if ([string]::IsNullOrWhiteSpace($tag)) { return $null }
    $tag = $tag.Trim()
    if ($tag.StartsWith("v")) { $tag = $tag.Substring(1) }
    return $tag
}

function Compare-VersionString([string]$left, [string]$right) {
    $leftVersion = $null
    $rightVersion = $null
    if (-not [version]::TryParse($left, [ref]$leftVersion)) { return 0 }
    if (-not [version]::TryParse($right, [ref]$rightVersion)) { return 0 }
    return $leftVersion.CompareTo($rightVersion)
}

function Get-ReleaseAsset($release, [string]$assetName) {
    if (-not $release -or -not $release.assets) { return $null }
    foreach ($asset in $release.assets) {
        if ([string]$asset.name -eq $assetName) { return $asset }
    }
    return $null
}

function Get-ReleaseAssetHash([object]$release, [string]$assetName) {
    if (-not $release) { return $null }
    $hashAsset = Get-ReleaseAsset $release ($assetName + ".sha256")
    if (-not $hashAsset) { $hashAsset = Get-ReleaseAsset $release ($assetName + ".sha256.txt") }
    if (-not $hashAsset -or -not $hashAsset.browser_download_url) { return $null }
    $tempHash = Join-Path $env:TEMP ("TeamsAlwaysGreen.hash." + [Guid]::NewGuid().ToString("N") + ".tmp")
    try {
        Invoke-WebRequest -Uri $hashAsset.browser_download_url -OutFile $tempHash -UseBasicParsing -ErrorAction Stop
        $raw = (Get-Content -Path $tempHash -Raw).Trim()
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        $parts = $raw -split "\s+"
        $hash = $parts[0]
        if ($hash -match "^[A-Fa-f0-9]{64}$") {
            return $hash.ToUpperInvariant()
        }
    } catch {
    } finally {
        try { if (Test-Path $tempHash) { Remove-Item -Path $tempHash -Force } } catch { }
    }
    return $null
}

function Get-UpdatePublicKeyXml {
    if ($script:UpdatePublicKeyPath -and (Test-Path $script:UpdatePublicKeyPath)) {
        try { return (Get-Content -Path $script:UpdatePublicKeyPath -Raw).Trim() } catch { }
    }
    return $null
}

function Get-ReleaseAssetSignatureBytes([object]$release, [string]$assetName) {
    if (-not $release) { return $null }
    $sigAsset = Get-ReleaseAsset $release ($assetName + ".sig")
    if (-not $sigAsset -or -not $sigAsset.browser_download_url) { return $null }
    $tempSig = Join-Path $env:TEMP ("TeamsAlwaysGreen.sig." + [Guid]::NewGuid().ToString("N") + ".tmp")
    try {
        Invoke-WebRequest -Uri $sigAsset.browser_download_url -OutFile $tempSig -UseBasicParsing -ErrorAction Stop
        $raw = (Get-Content -Path $tempSig -Raw).Trim()
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        if ($raw -match "^[A-Fa-f0-9]+$") {
            $bytes = New-Object byte[] ($raw.Length / 2)
            for ($i = 0; $i -lt $bytes.Length; $i++) {
                $bytes[$i] = [Convert]::ToByte($raw.Substring($i * 2, 2), 16)
            }
            return $bytes
        }
        return [Convert]::FromBase64String($raw)
    } catch {
        return $null
    } finally {
        try { if (Test-Path $tempSig) { Remove-Item -Path $tempSig -Force } } catch { }
    }
}

function Verify-UpdateSignature([string]$filePath, [byte[]]$signatureBytes, [string]$publicKeyXml) {
    if (-not $filePath -or -not $signatureBytes -or -not $publicKeyXml) { return $false }
    try {
        $data = [System.IO.File]::ReadAllBytes($filePath)
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

function Invoke-UpdateCheck {
    param(
        [switch]$Force,
        [object]$Release,
        [switch]$SilentNoUpdate
    )
    if (-not (Test-RateLimit "UpdateCheck")) {
        Write-Log "Update check blocked by rate limit." "WARN" $null "Update"
        if ($Force) {
            [System.Windows.Forms.MessageBox]::Show(
                "Update checks are temporarily rate-limited. Please wait and try again.",
                "Update check",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
        }
        return
    }
    if (-not $Force) {
        if (-not ($settings.PSObject.Properties.Name -contains "AutoUpdateEnabled") -or -not [bool]$settings.AutoUpdateEnabled) { return }
    }
    $owner = if ($settings.PSObject.Properties.Name -contains "UpdateOwner" -and -not [string]::IsNullOrWhiteSpace([string]$settings.UpdateOwner)) { [string]$settings.UpdateOwner } else { "alexphillips-dev" }
    $repo = if ($settings.PSObject.Properties.Name -contains "UpdateRepo" -and -not [string]::IsNullOrWhiteSpace([string]$settings.UpdateRepo)) { [string]$settings.UpdateRepo } else { "Teams-Always-Green" }
    if ($owner -notmatch '^[A-Za-z0-9._-]+$' -or $repo -notmatch '^[A-Za-z0-9._-]+$') {
        Write-Log "Update check blocked: owner/repo settings are invalid." "ERROR" $null "Update"
        if ($Force) {
            [System.Windows.Forms.MessageBox]::Show(
                "Update owner/repo settings are invalid.",
                "Update check",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
        return
    }
    $assetName = "Teams Always Green.ps1"
    $strictUpdate = ([bool]$settings.StrictUpdatePolicy -or [bool]$settings.SecurityModeEnabled)
    $allowPrerelease = [bool]$settings.UpdateAllowPrerelease
    $release = $Release
    if (-not $release) {
        $release = Get-LatestReleaseCached $owner $repo -Force:$Force
    } else {
        $script:UpdateCache.Release = $release
        $script:UpdateCache.CheckedAt = [DateTime]::UtcNow
    }
    if (-not $release) {
        if ($Force) {
            [System.Windows.Forms.MessageBox]::Show(
                "Unable to check for updates right now.",
                "Update check",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
        }
        return
    }
    $trust = Test-ReleaseTrust $release $owner $repo $strictUpdate $allowPrerelease
    if (-not $trust.IsTrusted) {
        Write-Log ("Update blocked by trust policy: {0}" -f $trust.Reason) "ERROR" $null "Update"
        if ($Force) {
            [System.Windows.Forms.MessageBox]::Show(
                ("Update check failed trust policy.`n`n{0}" -f $trust.Reason),
                "Update blocked",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
        return
    }
    $latestVersion = Get-ReleaseVersionString $release
    if ([string]::IsNullOrWhiteSpace($latestVersion)) {
        if ($Force) {
            [System.Windows.Forms.MessageBox]::Show(
                "Unable to determine the latest version.",
                "Update check",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
        }
        return
    }
    $script:UpdateCache.LatestVersion = $latestVersion
    $compare = (Compare-VersionString $latestVersion $appVersion)
    if ($compare -lt 0 -and -not [bool]$settings.UpdateAllowDowngrade) {
        Write-Log ("Update blocked: downgrade from {0} to {1} is not allowed." -f $appVersion, $latestVersion) "WARN" $null "Update"
        return
    }
    if ($compare -eq 0) {
        Write-Log ("No updates available. Current version={0}" -f $appVersion) "INFO" $null "Update"
        if ($Force -and -not $SilentNoUpdate) {
            [System.Windows.Forms.MessageBox]::Show(
                ("No updates are available.`n`nCurrent version: {0}" -f $appVersion),
                "No updates available",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
        }
        return
    }
    $prompt = "A new version is available.`n`nCurrent: $appVersion`nLatest: $latestVersion`n`nDownload and install now?"
    $result = [System.Windows.Forms.MessageBox]::Show(
        $prompt,
        "Update available",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
    if ($result -ne [System.Windows.Forms.DialogResult]::Yes) {
        Write-Log "Update available; user chose not to update." "INFO" $null "Update"
        return
    }

    $asset = Get-ReleaseAsset $release $assetName
    if (-not $asset -or -not $asset.browser_download_url) {
        Write-Log "Update asset not found in latest release." "WARN" $null "Update"
        [System.Windows.Forms.MessageBox]::Show(
            "Update asset '$assetName' was not found in the latest release.",
            "Update failed",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return
    }
    if (-not (Test-TrustedGithubUrl ([string]$asset.browser_download_url) $owner $repo)) {
        Write-Log "Update blocked: asset download URL is untrusted." "ERROR" $null "Update"
        [System.Windows.Forms.MessageBox]::Show(
            "Update asset URL failed trust validation.",
            "Update blocked",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        return
    }

    $tempPath = Join-Path $env:TEMP ("Teams Always Green.ps1." + [Guid]::NewGuid().ToString("N") + ".tmp")
    $backupPath = $null
    try {
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $tempPath -UseBasicParsing -ErrorAction Stop
        $downloadInfo = Get-Item -Path $tempPath -ErrorAction Stop
        if ($downloadInfo.Length -lt 2048) {
            throw "Downloaded file looks too small."
        }
        $requireHash = ([bool]$settings.UpdateRequireHash -or $strictUpdate)
        $expectedHash = Get-ReleaseAssetHash $release $assetName
        if ($requireHash -and -not $expectedHash) {
            throw "Update hash asset is required but missing."
        }
        if ($expectedHash) {
            $actualHash = (Get-FileHash -Algorithm SHA256 -Path $tempPath -ErrorAction Stop).Hash
            if ($expectedHash -ne $actualHash) {
                throw "Downloaded file hash mismatch."
            }
        }
        if ($settings.PSObject.Properties.Name -contains "UpdateRequireSignature" -and [bool]$settings.UpdateRequireSignature) {
            $publicKey = Get-UpdatePublicKeyXml
            if (-not $publicKey) {
                throw "Update signature public key missing."
            }
            $sigBytes = Get-ReleaseAssetSignatureBytes $release $assetName
            if (-not $sigBytes) {
                throw "Update signature missing."
            }
            if (-not (Verify-UpdateSignature $tempPath $sigBytes $publicKey)) {
                throw "Update signature verification failed."
            }
        }

        $backupPath = Join-Path $script:MetaDir ("Teams Always Green.ps1.bak." + (Get-Date -Format "yyyyMMddHHmmss"))
        Copy-Item -Path $scriptPath -Destination $backupPath -Force
        Move-Item -Path $tempPath -Destination $scriptPath -Force
        $versionPathLocal = Join-Path $script:AppRoot "VERSION"
        try {
            Set-Content -Path $versionPathLocal -Value $latestVersion -Encoding ASCII
            if ($release.PSObject.Properties.Name -contains "published_at" -and $release.published_at) {
                try {
                    $published = [DateTime]::Parse($release.published_at)
                    (Get-Item -Path $versionPathLocal).LastWriteTime = $published
                } catch {
                }
            }
        } catch {
        }
        Write-Log "Update applied; restarting." "INFO" $null "Update"
        Set-ShutdownMarker "clean"
        if (Get-Command -Name Flush-LogBuffer -ErrorAction SilentlyContinue) { Flush-LogBuffer }
        Release-MutexOnce
        $script:CleanupDone = $true
        Start-Process -FilePath "powershell.exe" -WindowStyle Hidden -WorkingDirectory $script:AppRoot -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
        [System.Windows.Forms.Application]::Exit()
    } catch {
        try { if (Test-Path $tempPath) { Remove-Item -Path $tempPath -Force } } catch { }
        try {
            if ($backupPath -and (Test-Path $backupPath)) {
                Copy-Item -Path $backupPath -Destination $scriptPath -Force
            }
        } catch {
        }
        Write-Log "Update failed: $($_.Exception.Message)" "ERROR" $_.Exception "Update"
        [System.Windows.Forms.MessageBox]::Show(
            "Update failed.`n$($_.Exception.Message)",
            "Update failed",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }
}
