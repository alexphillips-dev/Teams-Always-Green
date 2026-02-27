param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-LatestFile([string]$Path, [string]$Filter) {
    return Get-ChildItem -Path $Path -Filter $Filter -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

function Wait-UntilPathRemoved([string]$Path, [int]$TimeoutSeconds = 20) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-Path -LiteralPath $Path)) { return $true }
        Start-Sleep -Milliseconds 250
    }
    return (-not (Test-Path -LiteralPath $Path))
}

function Convert-ToWindowsPath([string]$RelativePath) {
    return ($RelativePath -replace "/", "\")
}

$repoRootAbs = (Resolve-Path $RepoRoot).Path
$manifestPath = Join-Path $repoRootAbs "app/setup/QuickSetup.manifest.json"
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Smoke install/uninstall: manifest not found: $manifestPath"
}

$manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
if (-not $manifest -or -not $manifest.files) {
    throw "Smoke install/uninstall: manifest format is invalid."
}

$sandboxRoot = Join-Path $env:TEMP ("TAG-InstallUninstall-Smoke-" + [Guid]::NewGuid().ToString("N"))
$installRoot = Join-Path $sandboxRoot "Install"
$localAppDataBase = Join-Path $sandboxRoot "LocalAppData"
$runtimeTempRoot = Join-Path $sandboxRoot "Temp"
New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
New-Item -ItemType Directory -Path $localAppDataBase -Force | Out-Null
New-Item -ItemType Directory -Path $runtimeTempRoot -Force | Out-Null

try {
    Write-Host ("[smoke] staging install layout at {0}" -f $installRoot)
    foreach ($entry in $manifest.files.PSObject.Properties) {
        $relativePath = [string]$entry.Name
        if ([string]::IsNullOrWhiteSpace($relativePath)) { continue }

        $sourcePath = Join-Path $repoRootAbs (Convert-ToWindowsPath $relativePath)
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            throw ("Manifest entry not found in repo: {0}" -f $relativePath)
        }

        $destPath = Join-Path $installRoot (Convert-ToWindowsPath $relativePath)
        $destDir = Split-Path -Path $destPath -Parent
        if (-not (Test-Path -LiteralPath $destDir -PathType Container)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }
        Copy-Item -LiteralPath $sourcePath -Destination $destPath -Force
    }

    $uninstallScript = Join-Path $installRoot "app/uninstall/Uninstall-Teams-Always-Green.ps1"
    if (-not (Test-Path -LiteralPath $uninstallScript -PathType Leaf)) {
        throw "Smoke install/uninstall: uninstall script missing from staged install."
    }

    $powershellPath = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
    if (-not (Test-Path -LiteralPath $powershellPath -PathType Leaf)) {
        $powershellPath = "powershell.exe"
    }

    $escapedScript = $uninstallScript.Replace("'", "''")
    $escapedInstallRoot = $installRoot.Replace("'", "''")
    $escapedLocal = $localAppDataBase.Replace("'", "''")
    $escapedTemp = $runtimeTempRoot.Replace("'", "''")
    $command = @"
`$env:LOCALAPPDATA='$escapedLocal'
`$env:TEMP='$escapedTemp'
`$env:TMP='$escapedTemp'
& '$escapedScript' -InstallRoot '$escapedInstallRoot' -Silent -Relaunched -HideConsole -AppDataPolicy Remove -Confirm:`$false
exit `$LASTEXITCODE
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))

    Write-Host "[smoke] running silent uninstall..."
    $proc = Start-Process -FilePath $powershellPath -ArgumentList "-NoProfile -ExecutionPolicy RemoteSigned -EncodedCommand $encoded" -PassThru -Wait -WindowStyle Hidden
    if ([int]$proc.ExitCode -ne 0) {
        throw ("Smoke install/uninstall: uninstall exit code was {0}" -f [int]$proc.ExitCode)
    }

    $reportFile = Get-LatestFile -Path $runtimeTempRoot -Filter "TeamsAlwaysGreen-Uninstall-*.json"
    if (-not $reportFile) {
        throw "Smoke install/uninstall: uninstall report file was not created."
    }
    $report = Get-Content -Path $reportFile.FullName -Raw | ConvertFrom-Json
    if (-not $report) {
        throw "Smoke install/uninstall: uninstall report could not be parsed."
    }
    if ([string]$report.Result -ne "Completed") {
        throw ("Smoke install/uninstall: expected Result='Completed', got '{0}'" -f [string]$report.Result)
    }

    if (-not (Wait-UntilPathRemoved -Path $installRoot -TimeoutSeconds 20)) {
        throw "Smoke install/uninstall: install root still exists after uninstall."
    }

    $appDataRoot = Join-Path $localAppDataBase "TeamsAlwaysGreen"
    if (-not (Wait-UntilPathRemoved -Path $appDataRoot -TimeoutSeconds 20)) {
        throw "Smoke install/uninstall: app data root still exists after uninstall."
    }

    Write-Host "[smoke] install/uninstall smoke passed."
} finally {
    Remove-Item -LiteralPath $sandboxRoot -Recurse -Force -ErrorAction SilentlyContinue
}
