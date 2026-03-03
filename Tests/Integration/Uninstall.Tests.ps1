Set-StrictMode -Version Latest

Describe "Uninstall integration" {
    BeforeAll {
        $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
        $script:uninstallSource = Join-Path $script:repoRoot "app/uninstall/Uninstall-Teams-Always-Green.ps1"
        $script:pwshPath = Join-Path $env:WINDIR "System32/WindowsPowerShell/v1.0/powershell.exe"

        function New-UninstallSandbox {
            param(
                [bool]$WithMarkers,
                [string]$RootPath = ""
            )

            $root = if ([string]::IsNullOrWhiteSpace($RootPath)) {
                Join-Path $env:TEMP ("TAG-Uninstall-IT-" + [Guid]::NewGuid().ToString("N"))
            } else {
                [string]$RootPath
            }
            $uninstallDir = Join-Path $root "app/uninstall"
            New-Item -ItemType Directory -Path $uninstallDir -Force | Out-Null
            Copy-Item -Path $script:uninstallSource -Destination (Join-Path $uninstallDir "Uninstall-Teams-Always-Green.ps1") -Force

            if ($WithMarkers) {
                New-Item -ItemType Directory -Path (Join-Path $root "app/runtime") -Force | Out-Null
                New-Item -ItemType Directory -Path (Join-Path $root "Meta") -Force | Out-Null
                Set-Content -Path (Join-Path $root "app/runtime/Teams Always Green.ps1") -Value "# marker" -Encoding UTF8
                Set-Content -Path (Join-Path $root "Teams Always Green.VBS") -Value "' marker" -Encoding ASCII
                Set-Content -Path (Join-Path $uninstallDir "Uninstall-Teams-Always-Green.vbs") -Value "' marker" -Encoding ASCII
            }

            return $root
        }

        function Invoke-UninstallChild {
            param(
                [string]$ScriptPath,
                [string]$InstallRoot,
                [string]$Arguments,
                [string]$LocalAppDataPath,
                [string]$RuntimeTempRoot,
                [string]$OneDrivePath = "",
                [string]$WorkingDirectory = "",
                [bool]$Relaunched = $true
            )

            $escapedScript = $ScriptPath.Replace("'", "''")
            $escapedRoot = $InstallRoot.Replace("'", "''")
            $escapedLocal = $LocalAppDataPath.Replace("'", "''")
            $escapedTemp = $RuntimeTempRoot.Replace("'", "''")
            $escapedOneDrive = $OneDrivePath.Replace("'", "''")
            $relaunchArg = if ($Relaunched) { "-Relaunched " } else { "" }
            $command = "`$env:LOCALAPPDATA='{0}'; `$env:TEMP='{1}'; `$env:TMP='{1}'; `$env:OneDrive='{4}'; & '{2}' {6}-InstallRoot '{3}' -Confirm:`$false {5}; exit `$LASTEXITCODE" -f $escapedLocal, $escapedTemp, $escapedScript, $escapedRoot, $escapedOneDrive, $Arguments, $relaunchArg
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
            $startParams = @{
                FilePath = $script:pwshPath
                ArgumentList = "-NoProfile -ExecutionPolicy RemoteSigned -EncodedCommand $encoded"
                PassThru = $true
                Wait = $true
                WindowStyle = "Hidden"
            }
            if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
                $startParams["WorkingDirectory"] = $WorkingDirectory
            }
            $proc = Start-Process @startParams
            return [int]$proc.ExitCode
        }

        function Get-UninstallArtifacts {
            param([string]$RuntimeTempRoot)

            $latestLog = Get-ChildItem -Path $RuntimeTempRoot -Filter "TeamsAlwaysGreen-Uninstall-*.log" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1
            $latestReport = Get-ChildItem -Path $RuntimeTempRoot -Filter "TeamsAlwaysGreen-Uninstall-*.json" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1

            $logText = if ($latestLog) { Get-Content -Path $latestLog.FullName -Raw } else { "" }
            $reportObj = $null
            if ($latestReport) {
                try { $reportObj = Get-Content -Path $latestReport.FullName -Raw | ConvertFrom-Json } catch { $null = $_ }
            }

            return [pscustomobject]@{
                LogText = $logText
                Report = $reportObj
                LogPath = if ($latestLog) { $latestLog.FullName } else { "" }
                ReportPath = if ($latestReport) { $latestReport.FullName } else { "" }
            }
        }

        function Wait-UntilRemoved {
            param([string]$Path, [int]$TimeoutSeconds = 15)

            $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
            while ((Get-Date) -lt $deadline) {
                if (-not (Test-Path -LiteralPath $Path)) { return $true }
                Start-Sleep -Milliseconds 300
            }
            return (-not (Test-Path -LiteralPath $Path))
        }

        function Start-LockFileHolder {
            param(
                [string]$FilePath,
                [int]$HoldSeconds = 20
            )

            $escapedPath = $FilePath.Replace("'", "''")
            $command = "`$path='{0}'; `$stream=[System.IO.File]::Open(`$path,[System.IO.FileMode]::OpenOrCreate,[System.IO.FileAccess]::ReadWrite,[System.IO.FileShare]::None); try {{ Start-Sleep -Seconds {1} }} finally {{ `$stream.Dispose() }}" -f $escapedPath, $HoldSeconds
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
            return Start-Process -FilePath $script:pwshPath -ArgumentList "-NoProfile -ExecutionPolicy RemoteSigned -EncodedCommand $encoded" -PassThru -WindowStyle Hidden
        }
    }

    It "supports dry-run mode without deleting files" {
        $root = New-UninstallSandbox -WithMarkers $true
        $scriptPath = Join-Path $root "app/uninstall/Uninstall-Teams-Always-Green.ps1"
        $localAppData = Join-Path $env:TEMP ("TAG-Uninstall-IT-Local-" + [Guid]::NewGuid().ToString("N"))
        $runTemp = Join-Path $env:TEMP ("TAG-Uninstall-IT-Run-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $localAppData -Force | Out-Null
        New-Item -ItemType Directory -Path $runTemp -Force | Out-Null

        $exitCode = Invoke-UninstallChild -ScriptPath $scriptPath -InstallRoot $root -Arguments "-Silent -WhatIf -AppDataPolicy Remove" -LocalAppDataPath $localAppData -RuntimeTempRoot $runTemp
        $artifacts = Get-UninstallArtifacts -RuntimeTempRoot $runTemp

        $exitCode | Should -Be 0
        (Test-Path -LiteralPath $root) | Should -BeTrue
        $artifacts.Report | Should -Not -BeNullOrEmpty
        [string]$artifacts.Report.Result | Should -Be "DryRun"
        [string]$artifacts.Report.ResultNormalized | Should -Be "DryRun-Validated"
        $artifacts.LogText | Should -Match "Dry run complete"

        Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $localAppData -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $runTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "removes install root and app data when policy is Remove" {
        $root = New-UninstallSandbox -WithMarkers $true
        $scriptPath = Join-Path $root "app/uninstall/Uninstall-Teams-Always-Green.ps1"

        $localBase = Join-Path $env:TEMP ("TAG-Uninstall-IT-Local-" + [Guid]::NewGuid().ToString("N"))
        $appDataRoot = Join-Path $localBase "TeamsAlwaysGreen"
        $runTemp = Join-Path $env:TEMP ("TAG-Uninstall-IT-Run-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $appDataRoot -Force | Out-Null
        New-Item -ItemType Directory -Path $runTemp -Force | Out-Null
        Set-Content -Path (Join-Path $appDataRoot "settings.json") -Value "{}" -Encoding UTF8

        $exitCode = Invoke-UninstallChild -ScriptPath $scriptPath -InstallRoot $root -Arguments "-Silent -AppDataPolicy Remove" -LocalAppDataPath $localBase -RuntimeTempRoot $runTemp
        $artifacts = Get-UninstallArtifacts -RuntimeTempRoot $runTemp

        $exitCode | Should -Be 0
        $artifacts.Report | Should -Not -BeNullOrEmpty
        [string]$artifacts.Report.Result | Should -Be "Completed"
        [string]$artifacts.Report.ResultNormalized | Should -Be "Completed-Clean"
        [bool]$artifacts.Report.EntryPointPhaseComplete | Should -BeTrue
        [string]$artifacts.Report.PhaseMarkerPath | Should -Not -BeNullOrEmpty
        $artifacts.Report.HealthCheck | Should -Not -BeNullOrEmpty
        (Wait-UntilRemoved -Path $root -TimeoutSeconds 15) | Should -BeTrue
        (Wait-UntilRemoved -Path $appDataRoot -TimeoutSeconds 15) | Should -BeTrue

        Remove-Item -Path $localBase -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $runTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "blocks uninstall when install signature markers are missing" {
        $root = New-UninstallSandbox -WithMarkers $false
        $scriptPath = Join-Path $root "app/uninstall/Uninstall-Teams-Always-Green.ps1"
        $localAppData = Join-Path $env:TEMP ("TAG-Uninstall-IT-Local-" + [Guid]::NewGuid().ToString("N"))
        $runTemp = Join-Path $env:TEMP ("TAG-Uninstall-IT-Run-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $localAppData -Force | Out-Null
        New-Item -ItemType Directory -Path $runTemp -Force | Out-Null

        $exitCode = Invoke-UninstallChild -ScriptPath $scriptPath -InstallRoot $root -Arguments "-Silent" -LocalAppDataPath $localAppData -RuntimeTempRoot $runTemp
        $artifacts = Get-UninstallArtifacts -RuntimeTempRoot $runTemp

        $exitCode | Should -Be 10
        (Test-Path -LiteralPath $root) | Should -BeTrue
        $artifacts.Report | Should -Not -BeNullOrEmpty
        [string]$artifacts.Report.Result | Should -Be "SafetyBlocked"
        $artifacts.LogText | Should -Match "Install signature files were not found"

        Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $localAppData -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $runTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "logs OneDrive-like path indicators for diagnostics" {
        $oneDriveBase = Join-Path $env:TEMP (("One" + "Drive - TAG-Uninstall-IT-") + [Guid]::NewGuid().ToString("N"))
        $root = Join-Path $oneDriveBase "Teams Always Green"
        $root = New-UninstallSandbox -WithMarkers $false -RootPath $root
        $scriptPath = Join-Path $root "app/uninstall/Uninstall-Teams-Always-Green.ps1"
        $localAppData = Join-Path $env:TEMP ("TAG-Uninstall-IT-Local-" + [Guid]::NewGuid().ToString("N"))
        $runTemp = Join-Path $env:TEMP ("TAG-Uninstall-IT-Run-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $localAppData -Force | Out-Null
        New-Item -ItemType Directory -Path $runTemp -Force | Out-Null

        $exitCode = Invoke-UninstallChild -ScriptPath $scriptPath -InstallRoot $root -Arguments "-Silent" -LocalAppDataPath $localAppData -RuntimeTempRoot $runTemp -OneDrivePath $oneDriveBase
        $artifacts = Get-UninstallArtifacts -RuntimeTempRoot $runTemp

        $exitCode | Should -Be 10
        $artifacts.Report | Should -Not -BeNullOrEmpty
        [bool]$artifacts.Report.OneDrivePathLike | Should -BeTrue
        @($artifacts.Report.OneDriveSignals).Count | Should -BeGreaterThan 0
        $artifacts.LogText | Should -Match "InstallRoot OneDrive indicators"
        $artifacts.LogText | Should -Match "OneDrivePathLike=True"

        Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $oneDriveBase -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $localAppData -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $runTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "removes install root even when launched with install-root working directory" {
        $root = New-UninstallSandbox -WithMarkers $true
        $scriptPath = Join-Path $root "app/uninstall/Uninstall-Teams-Always-Green.ps1"
        $localAppData = Join-Path $env:TEMP ("TAG-Uninstall-IT-Local-" + [Guid]::NewGuid().ToString("N"))
        $runTemp = Join-Path $env:TEMP ("TAG-Uninstall-IT-Run-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $localAppData -Force | Out-Null
        New-Item -ItemType Directory -Path $runTemp -Force | Out-Null

        $exitCode = Invoke-UninstallChild -ScriptPath $scriptPath -InstallRoot $root -Arguments "-Silent -AppDataPolicy Keep" -LocalAppDataPath $localAppData -RuntimeTempRoot $runTemp -WorkingDirectory $root -Relaunched $false
        $artifacts = Get-UninstallArtifacts -RuntimeTempRoot $runTemp

        $exitCode | Should -Be 0
        $artifacts.Report | Should -Not -BeNullOrEmpty
        [string]$artifacts.Report.Result | Should -Be "Completed"
        $artifacts.LogText | Should -Match "Current working directory:"
        $artifacts.LogText | Should -Not -Match ([Regex]::Escape("Current working directory: " + $root))
        (Wait-UntilRemoved -Path $root -TimeoutSeconds 15) | Should -BeTrue

        Remove-Item -Path $localAppData -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $runTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "captures residual lock diagnostics on OneDrive-like locked uninstall path" {
        $oneDriveBase = Join-Path $env:TEMP (("One" + "Drive - TAG-Uninstall-Lock-") + [Guid]::NewGuid().ToString("N"))
        $root = Join-Path $oneDriveBase "Teams Always Green"
        $root = New-UninstallSandbox -WithMarkers $true -RootPath $root
        $scriptPath = Join-Path $root "app/uninstall/Uninstall-Teams-Always-Green.ps1"
        $localAppData = Join-Path $env:TEMP ("TAG-Uninstall-IT-Local-" + [Guid]::NewGuid().ToString("N"))
        $runTemp = Join-Path $env:TEMP ("TAG-Uninstall-IT-Run-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $localAppData -Force | Out-Null
        New-Item -ItemType Directory -Path $runTemp -Force | Out-Null

        $lockFile = Join-Path $root "app/uninstall/lock.tmp"
        Set-Content -Path $lockFile -Value "lock" -Encoding ASCII
        $holder = Start-LockFileHolder -FilePath $lockFile -HoldSeconds 25
        try {
            $exitCode = Invoke-UninstallChild -ScriptPath $scriptPath -InstallRoot $root -Arguments "-Silent -AppDataPolicy Keep" -LocalAppDataPath $localAppData -RuntimeTempRoot $runTemp -OneDrivePath $oneDriveBase
            $artifacts = Get-UninstallArtifacts -RuntimeTempRoot $runTemp

            $exitCode | Should -Be 30
            $artifacts.Report | Should -Not -BeNullOrEmpty
            [string]$artifacts.Report.Result | Should -Be "PartialCleanup"
            @("PartialCleanup-RebootPending", "PartialCleanup-OneDriveLock", "PartialCleanup-Locked") | Should -Contain ([string]$artifacts.Report.ResultNormalized)
            [bool]$artifacts.Report.OneDrivePathLike | Should -BeTrue
            [string]$artifacts.Report.ResidualReason | Should -Be "lock"
            @($artifacts.Report.ResidualPaths).Count | Should -BeGreaterThan 0
            $artifacts.LogText | Should -Match "Residual reason classification: lock"
        } finally {
            if ($holder -and -not $holder.HasExited) {
                Stop-Process -Id $holder.Id -Force -ErrorAction SilentlyContinue
            }
        }

        Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $oneDriveBase -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $localAppData -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $runTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "removes legacy startup shortcut naming variant during uninstall" {
        $root = New-UninstallSandbox -WithMarkers $true
        $scriptPath = Join-Path $root "app/uninstall/Uninstall-Teams-Always-Green.ps1"
        $localAppData = Join-Path $env:TEMP ("TAG-Uninstall-IT-Local-" + [Guid]::NewGuid().ToString("N"))
        $runTemp = Join-Path $env:TEMP ("TAG-Uninstall-IT-Run-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $localAppData -Force | Out-Null
        New-Item -ItemType Directory -Path $runTemp -Force | Out-Null

        $startupDir = [Environment]::GetFolderPath("Startup")
        $legacyStartupPath = Join-Path $startupDir "Teams-Always-Green.lnk"
        $backupPath = ""
        $hadExisting = Test-Path -LiteralPath $legacyStartupPath -PathType Leaf
        if ($hadExisting) {
            $backupPath = Join-Path $startupDir ("Teams-Always-Green.bak." + [Guid]::NewGuid().ToString("N") + ".lnk")
            Move-Item -LiteralPath $legacyStartupPath -Destination $backupPath -Force
        }

        try {
            Set-Content -Path $legacyStartupPath -Value "legacy-shortcut-marker" -Encoding ASCII
            $exitCode = Invoke-UninstallChild -ScriptPath $scriptPath -InstallRoot $root -Arguments "-Silent -AppDataPolicy Keep" -LocalAppDataPath $localAppData -RuntimeTempRoot $runTemp
            $artifacts = Get-UninstallArtifacts -RuntimeTempRoot $runTemp

            $exitCode | Should -Be 0
            $artifacts.Report | Should -Not -BeNullOrEmpty
            [string]$artifacts.Report.Result | Should -Be "Completed"
            (Test-Path -LiteralPath $legacyStartupPath -PathType Leaf) | Should -BeFalse
        } finally {
            if (-not [string]::IsNullOrWhiteSpace($backupPath) -and (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
                Move-Item -LiteralPath $backupPath -Destination $legacyStartupPath -Force
            } elseif (Test-Path -LiteralPath $legacyStartupPath -PathType Leaf) {
                Remove-Item -LiteralPath $legacyStartupPath -Force -ErrorAction SilentlyContinue
            }
        }

        Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $localAppData -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $runTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "removes desktop shortcut variants during uninstall" {
        $root = New-UninstallSandbox -WithMarkers $true
        $scriptPath = Join-Path $root "app/uninstall/Uninstall-Teams-Always-Green.ps1"
        $localAppData = Join-Path $env:TEMP ("TAG-Uninstall-IT-Local-" + [Guid]::NewGuid().ToString("N"))
        $runTemp = Join-Path $env:TEMP ("TAG-Uninstall-IT-Run-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $localAppData -Force | Out-Null
        New-Item -ItemType Directory -Path $runTemp -Force | Out-Null

        $desktopDir = [Environment]::GetFolderPath("Desktop")
        $desktopCurrent = Join-Path $desktopDir "Teams Always Green.lnk"
        $desktopLegacy = Join-Path $desktopDir "Teams-Always-Green.lnk"
        $backupCurrent = ""
        $backupLegacy = ""
        if (Test-Path -LiteralPath $desktopCurrent -PathType Leaf) {
            $backupCurrent = Join-Path $desktopDir ("Teams Always Green.bak." + [Guid]::NewGuid().ToString("N") + ".lnk")
            Move-Item -LiteralPath $desktopCurrent -Destination $backupCurrent -Force
        }
        if (Test-Path -LiteralPath $desktopLegacy -PathType Leaf) {
            $backupLegacy = Join-Path $desktopDir ("Teams-Always-Green.bak." + [Guid]::NewGuid().ToString("N") + ".lnk")
            Move-Item -LiteralPath $desktopLegacy -Destination $backupLegacy -Force
        }

        try {
            Set-Content -Path $desktopCurrent -Value "desktop-shortcut-current" -Encoding ASCII
            Set-Content -Path $desktopLegacy -Value "desktop-shortcut-legacy" -Encoding ASCII

            $exitCode = Invoke-UninstallChild -ScriptPath $scriptPath -InstallRoot $root -Arguments "-Silent -AppDataPolicy Keep" -LocalAppDataPath $localAppData -RuntimeTempRoot $runTemp
            $artifacts = Get-UninstallArtifacts -RuntimeTempRoot $runTemp

            $exitCode | Should -Be 0
            $artifacts.Report | Should -Not -BeNullOrEmpty
            [string]$artifacts.Report.Result | Should -Be "Completed"
            (Test-Path -LiteralPath $desktopCurrent -PathType Leaf) | Should -BeFalse
            (Test-Path -LiteralPath $desktopLegacy -PathType Leaf) | Should -BeFalse
        } finally {
            foreach ($path in @($desktopCurrent, $desktopLegacy)) {
                if (Test-Path -LiteralPath $path -PathType Leaf) {
                    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($backupCurrent) -and (Test-Path -LiteralPath $backupCurrent -PathType Leaf)) {
                Move-Item -LiteralPath $backupCurrent -Destination $desktopCurrent -Force
            }
            if (-not [string]::IsNullOrWhiteSpace($backupLegacy) -and (Test-Path -LiteralPath $backupLegacy -PathType Leaf)) {
                Move-Item -LiteralPath $backupLegacy -Destination $desktopLegacy -Force
            }
        }

        Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $localAppData -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $runTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

