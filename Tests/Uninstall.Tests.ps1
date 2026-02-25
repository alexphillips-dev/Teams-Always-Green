Set-StrictMode -Version Latest

Describe "Uninstall integration" {
    BeforeAll {
        $script:repoRoot = Split-Path -Parent $PSScriptRoot
        $script:uninstallSource = Join-Path $script:repoRoot "Script/Uninstall/Uninstall-Teams-Always-Green.ps1"
        $script:pwshPath = Join-Path $env:WINDIR "System32/WindowsPowerShell/v1.0/powershell.exe"

        function New-UninstallSandbox {
            param([bool]$WithMarkers)

            $root = Join-Path $env:TEMP ("TAG-Uninstall-IT-" + [Guid]::NewGuid().ToString("N"))
            $uninstallDir = Join-Path $root "Script/Uninstall"
            New-Item -ItemType Directory -Path $uninstallDir -Force | Out-Null
            Copy-Item -Path $script:uninstallSource -Destination (Join-Path $uninstallDir "Uninstall-Teams-Always-Green.ps1") -Force

            if ($WithMarkers) {
                New-Item -ItemType Directory -Path (Join-Path $root "Script") -Force | Out-Null
                New-Item -ItemType Directory -Path (Join-Path $root "Meta") -Force | Out-Null
                Set-Content -Path (Join-Path $root "Script/Teams Always Green.ps1") -Value "# marker" -Encoding UTF8
                Set-Content -Path (Join-Path $root "Teams Always Green.VBS") -Value "' marker" -Encoding ASCII
                Set-Content -Path (Join-Path $uninstallDir "Uninstall-Teams-Always-Green.vbs") -Value "' marker" -Encoding ASCII
            }

            return $root
        }

        function Invoke-UninstallChild {
            param(
                [string]$ScriptPath,
                [string]$Arguments,
                [string]$LocalAppDataPath,
                [string]$RuntimeTempRoot
            )

            $escapedScript = $ScriptPath.Replace("'", "''")
            $escapedLocal = $LocalAppDataPath.Replace("'", "''")
            $escapedTemp = $RuntimeTempRoot.Replace("'", "''")
            $command = "`$env:LOCALAPPDATA='{0}'; `$env:TEMP='{1}'; `$env:TMP='{1}'; & '{2}' -Confirm:`$false {3}; exit `$LASTEXITCODE" -f $escapedLocal, $escapedTemp, $escapedScript, $Arguments
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
            $proc = Start-Process -FilePath $script:pwshPath -ArgumentList "-NoProfile -ExecutionPolicy RemoteSigned -EncodedCommand $encoded" -PassThru -Wait -WindowStyle Hidden
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
    }

    It "supports dry-run mode without deleting files" {
        $root = New-UninstallSandbox -WithMarkers $true
        $scriptPath = Join-Path $root "Script/Uninstall/Uninstall-Teams-Always-Green.ps1"
        $localAppData = Join-Path $env:TEMP ("TAG-Uninstall-IT-Local-" + [Guid]::NewGuid().ToString("N"))
        $runTemp = Join-Path $env:TEMP ("TAG-Uninstall-IT-Run-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $localAppData -Force | Out-Null
        New-Item -ItemType Directory -Path $runTemp -Force | Out-Null

        $exitCode = Invoke-UninstallChild -ScriptPath $scriptPath -Arguments "-Silent -WhatIf -AppDataPolicy Remove" -LocalAppDataPath $localAppData -RuntimeTempRoot $runTemp
        $artifacts = Get-UninstallArtifacts -RuntimeTempRoot $runTemp

        $exitCode | Should -Be 0
        (Test-Path -LiteralPath $root) | Should -BeTrue
        $artifacts.Report | Should -Not -BeNullOrEmpty
        [string]$artifacts.Report.Result | Should -Be "DryRun"
        $artifacts.LogText | Should -Match "Dry run complete"

        Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $localAppData -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $runTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "removes install root and app data when policy is Remove" {
        $root = New-UninstallSandbox -WithMarkers $true
        $scriptPath = Join-Path $root "Script/Uninstall/Uninstall-Teams-Always-Green.ps1"

        $localBase = Join-Path $env:TEMP ("TAG-Uninstall-IT-Local-" + [Guid]::NewGuid().ToString("N"))
        $appDataRoot = Join-Path $localBase "TeamsAlwaysGreen"
        $runTemp = Join-Path $env:TEMP ("TAG-Uninstall-IT-Run-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $appDataRoot -Force | Out-Null
        New-Item -ItemType Directory -Path $runTemp -Force | Out-Null
        Set-Content -Path (Join-Path $appDataRoot "settings.json") -Value "{}" -Encoding UTF8

        $exitCode = Invoke-UninstallChild -ScriptPath $scriptPath -Arguments "-Silent -AppDataPolicy Remove" -LocalAppDataPath $localBase -RuntimeTempRoot $runTemp
        $artifacts = Get-UninstallArtifacts -RuntimeTempRoot $runTemp

        $exitCode | Should -Be 0
        $artifacts.Report | Should -Not -BeNullOrEmpty
        [string]$artifacts.Report.Result | Should -Be "CleanupStarted"
        (Wait-UntilRemoved -Path $root -TimeoutSeconds 15) | Should -BeTrue
        (Wait-UntilRemoved -Path $appDataRoot -TimeoutSeconds 15) | Should -BeTrue

        Remove-Item -Path $localBase -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $runTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "blocks uninstall when install signature markers are missing" {
        $root = New-UninstallSandbox -WithMarkers $false
        $scriptPath = Join-Path $root "Script/Uninstall/Uninstall-Teams-Always-Green.ps1"
        $localAppData = Join-Path $env:TEMP ("TAG-Uninstall-IT-Local-" + [Guid]::NewGuid().ToString("N"))
        $runTemp = Join-Path $env:TEMP ("TAG-Uninstall-IT-Run-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $localAppData -Force | Out-Null
        New-Item -ItemType Directory -Path $runTemp -Force | Out-Null

        $exitCode = Invoke-UninstallChild -ScriptPath $scriptPath -Arguments "-Silent" -LocalAppDataPath $localAppData -RuntimeTempRoot $runTemp
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
}
