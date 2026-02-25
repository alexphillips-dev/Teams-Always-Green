[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "", Scope = "Function", Target = "Ensure-TempExecution")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Scope = "Function", Target = "Remove-AppShortcuts")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Scope = "Function", Target = "Get-TrackedProcessCandidates")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Scope = "Function", Target = "Stop-AppProcesses")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "", Scope = "Function", Target = "Remove-AppShortcuts")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "", Scope = "Function", Target = "Stop-AppProcesses")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "", Scope = "Function", Target = "Remove-PathWithRetry")]
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param(
    [switch]$Silent,
    [switch]$RemoveAppData,
    [ValidateSet("Keep", "Remove", "Prompt")]
    [string]$AppDataPolicy = "Prompt",
    [string]$InstallRoot = "",
    [switch]$Relaunched
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$script:ScriptFilePath = if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
    [string]$PSCommandPath
} else {
    [string]$MyInvocation.MyCommand.Path
}

$script:ExitCodes = @{
    Success        = 0
    UserCancelled  = 2
    SafetyBlocked  = 10
    PartialCleanup = 30
    RelaunchFailed = 40
    UnhandledError = 99
}

$script:AppName = "Teams Always Green"
$script:AppDataRoot = Join-Path $env:LOCALAPPDATA "TeamsAlwaysGreen"
$script:IsDryRun = [bool]$WhatIfPreference

$tempRoot = if (-not [string]::IsNullOrWhiteSpace($env:TEMP)) {
    $env:TEMP
} elseif (-not [string]::IsNullOrWhiteSpace($env:TMP)) {
    $env:TMP
} else {
    [System.IO.Path]::GetTempPath()
}

$runId = (Get-Date).ToString("yyyyMMdd-HHmmss")
$script:UninstallLogPath = Join-Path $tempRoot ("TeamsAlwaysGreen-Uninstall-{0}.log" -f $runId)
$script:UninstallReportPath = Join-Path $tempRoot ("TeamsAlwaysGreen-Uninstall-{0}.json" -f $runId)

$script:UninstallReport = [ordered]@{
    StartedAtUtc             = [DateTime]::UtcNow.ToString("o")
    ScriptPath               = [string]$script:ScriptFilePath
    InstallRoot              = [string]$InstallRoot
    Relaunched               = [bool]$Relaunched
    Silent                   = [bool]$Silent
    DryRun                   = [bool]$script:IsDryRun
    AppDataPolicyRequested   = [string]$AppDataPolicy
    AppDataPolicyEffective   = ""
    RemoveAppDataSwitch      = [bool]$RemoveAppData
    RemoveAppDataResolved    = $false
    ProcessCandidates        = @()
    ProcessesStopped         = @()
    ProcessStopFailures      = @()
    ShortcutsRemoved         = @()
    ShortcutRemoveFailures   = @()
    RemovedInstallRoot       = $false
    RemovedAppDataRoot       = $false
    OneDrivePathLike         = $false
    OneDriveSignals          = @()
    LockDiagnostics          = ""
    Result                   = "Pending"
    ExitCode                 = -1
    Summary                  = ""
    CompletedAtUtc           = ""
}

function Write-UninstallLog([string]$message) {
    if ([string]::IsNullOrWhiteSpace($message)) { return }
    try {
        $line = "[{0}] {1}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $message
        Add-Content -Path $script:UninstallLogPath -Value $line -Encoding UTF8 -WhatIf:$false -Confirm:$false
    } catch {
        $null = $_
    }
}

function Save-UninstallReport {
    try {
        $script:UninstallReport.CompletedAtUtc = [DateTime]::UtcNow.ToString("o")
        $json = $script:UninstallReport | ConvertTo-Json -Depth 8
        Set-Content -Path $script:UninstallReportPath -Value $json -Encoding UTF8 -WhatIf:$false -Confirm:$false
    } catch {
        Write-UninstallLog ("Failed to write uninstall report: {0}" -f $_.Exception.Message)
    }
}

function Show-UninstallMessage {
    param(
        [string]$Summary,
        [string]$Title,
        [System.Windows.Forms.MessageBoxIcon]$Icon,
        [string]$LogPath,
        [string]$ReportPath
    )

    if ($Silent) { return }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Width = 760
    $form.Height = 350
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.BackColor = [System.Drawing.Color]::White
    $form.TopMost = $true

    $header = New-Object System.Windows.Forms.Panel
    $header.Width = 720
    $header.Height = 72
    $header.Location = New-Object System.Drawing.Point(16, 12)
    switch ($Icon) {
        ([System.Windows.Forms.MessageBoxIcon]::Warning) { $header.BackColor = [System.Drawing.Color]::FromArgb(255, 244, 214) }
        ([System.Windows.Forms.MessageBoxIcon]::Error) { $header.BackColor = [System.Drawing.Color]::FromArgb(255, 228, 228) }
        default { $header.BackColor = [System.Drawing.Color]::FromArgb(227, 243, 255) }
    }

    $iconBox = New-Object System.Windows.Forms.PictureBox
    $iconBox.Size = New-Object System.Drawing.Size(28, 28)
    $iconBox.Location = New-Object System.Drawing.Point(14, 22)
    $iconBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage
    switch ($Icon) {
        ([System.Windows.Forms.MessageBoxIcon]::Warning) { $iconBox.Image = [System.Drawing.SystemIcons]::Warning.ToBitmap() }
        ([System.Windows.Forms.MessageBoxIcon]::Error) { $iconBox.Image = [System.Drawing.SystemIcons]::Error.ToBitmap() }
        default { $iconBox.Image = [System.Drawing.SystemIcons]::Information.ToBitmap() }
    }

    $summaryTitle = New-Object System.Windows.Forms.Label
    $summaryTitle.AutoSize = $true
    $summaryTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $summaryTitle.Location = New-Object System.Drawing.Point(52, 10)
    $summaryTitle.Text = $Title

    $summaryLabel = New-Object System.Windows.Forms.Label
    $summaryLabel.AutoSize = $false
    $summaryLabel.Width = 650
    $summaryLabel.Height = 36
    $summaryLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Regular)
    $summaryLabel.Location = New-Object System.Drawing.Point(52, 32)
    $summaryLabel.Text = [string]$Summary

    $header.Controls.Add($iconBox)
    $header.Controls.Add($summaryTitle)
    $header.Controls.Add($summaryLabel)

    $logLabel = New-Object System.Windows.Forms.Label
    $logLabel.AutoSize = $true
    $logLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
    $logLabel.Location = New-Object System.Drawing.Point(18, 100)
    $logLabel.Text = "Log file"

    $logText = New-Object System.Windows.Forms.TextBox
    $logText.Location = New-Object System.Drawing.Point(20, 122)
    $logText.Width = 614
    $logText.Height = 50
    $logText.Multiline = $true
    $logText.ReadOnly = $true
    $logText.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
    $logText.Text = [string]$LogPath

    $openLogBtn = New-Object System.Windows.Forms.Button
    $openLogBtn.Text = "Open Log"
    $openLogBtn.Width = 94
    $openLogBtn.Height = 28
    $openLogBtn.Location = New-Object System.Drawing.Point(642, 133)
    $openLogBtn.Add_Click({
        try {
            if (-not [string]::IsNullOrWhiteSpace($logText.Text) -and (Test-Path -LiteralPath $logText.Text -PathType Leaf)) {
                Start-Process -FilePath "notepad.exe" -ArgumentList @($logText.Text) | Out-Null
            }
        } catch {
            $null = $_
        }
    })

    $reportLabel = New-Object System.Windows.Forms.Label
    $reportLabel.AutoSize = $true
    $reportLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
    $reportLabel.Location = New-Object System.Drawing.Point(18, 183)
    $reportLabel.Text = "Report file"

    $reportText = New-Object System.Windows.Forms.TextBox
    $reportText.Location = New-Object System.Drawing.Point(20, 205)
    $reportText.Width = 614
    $reportText.Height = 50
    $reportText.Multiline = $true
    $reportText.ReadOnly = $true
    $reportText.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
    $reportText.Text = [string]$ReportPath

    $openReportBtn = New-Object System.Windows.Forms.Button
    $openReportBtn.Text = "Open Report"
    $openReportBtn.Width = 94
    $openReportBtn.Height = 28
    $openReportBtn.Location = New-Object System.Drawing.Point(642, 216)
    $openReportBtn.Add_Click({
        try {
            if (-not [string]::IsNullOrWhiteSpace($reportText.Text) -and (Test-Path -LiteralPath $reportText.Text -PathType Leaf)) {
                Start-Process -FilePath "notepad.exe" -ArgumentList @($reportText.Text) | Out-Null
            }
        } catch {
            $null = $_
        }
    })

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Width = 96
    $okButton.Height = 30
    $okButton.Location = New-Object System.Drawing.Point(640, 270)
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $form.AcceptButton = $okButton
    $form.CancelButton = $okButton
    $form.Controls.Add($header)
    $form.Controls.Add($logLabel)
    $form.Controls.Add($logText)
    $form.Controls.Add($openLogBtn)
    $form.Controls.Add($reportLabel)
    $form.Controls.Add($reportText)
    $form.Controls.Add($openReportBtn)
    $form.Controls.Add($okButton)
    [void]$form.ShowDialog()
}

function Complete-Uninstall {
    param(
        [int]$ExitCode,
        [string]$Result,
        [string]$Summary,
        [switch]$NotifyUser,
        [System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::Information,
        [string]$Title = "Uninstall Teams Always Green"
    )

    if (-not [string]::IsNullOrWhiteSpace($Summary)) {
        Write-UninstallLog $Summary
    }
    $script:UninstallReport.Result = [string]$Result
    $script:UninstallReport.ExitCode = [int]$ExitCode
    $script:UninstallReport.Summary = [string]$Summary
    Save-UninstallReport

    if ($NotifyUser) {
        Show-UninstallMessage -Summary $Summary -Title $Title -Icon $Icon -LogPath $script:UninstallLogPath -ReportPath $script:UninstallReportPath
    }

    exit $ExitCode
}

function Get-PowerShellPath {
    $candidate = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    return "powershell.exe"
}

function Get-InstallRootFromScriptPath([string]$scriptPath) {
    if ([string]::IsNullOrWhiteSpace($scriptPath)) { return "" }
    return (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $scriptPath)))
}

function Test-IsProtectedPath([string]$fullPath) {
    if ([string]::IsNullOrWhiteSpace($fullPath)) { return $true }
    $trimmed = $fullPath.TrimEnd("\")
    if ([string]::IsNullOrWhiteSpace($trimmed)) { return $true }

    $roots = @()
    try { $roots += [System.IO.Path]::GetPathRoot($trimmed).TrimEnd("\") } catch { $null = $_ }
    $roots += @(
        ($env:SystemDrive + "\").TrimEnd("\"),
        [string]$env:USERPROFILE,
        [string]$env:ProgramFiles,
        [string]${env:ProgramFiles(x86)},
        [string]$env:LOCALAPPDATA,
        [string]$env:APPDATA,
        [Environment]::GetFolderPath("Desktop"),
        [Environment]::GetFolderPath("MyDocuments")
    )
    foreach ($candidate in @($roots | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        if ($trimmed.Equals([string]$candidate.TrimEnd("\"), [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Test-UninstallTargetPath([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) {
        return [pscustomobject]@{ IsSafe = $false; Reason = "Install path is empty."; Path = "" }
    }

    try {
        $resolved = [System.IO.Path]::GetFullPath($path)
    } catch {
        return [pscustomobject]@{ IsSafe = $false; Reason = "Install path could not be resolved."; Path = "" }
    }

    if (Test-IsProtectedPath $resolved) {
        return [pscustomobject]@{ IsSafe = $false; Reason = "Install path resolves to a protected system/user location."; Path = $resolved }
    }

    $markers = @(
        (Join-Path $resolved "Script\Teams Always Green.ps1"),
        (Join-Path $resolved "Teams Always Green.VBS"),
        (Join-Path $resolved "Meta")
    )
    $hasMarker = $false
    foreach ($marker in $markers) {
        if (Test-Path -LiteralPath $marker) {
            $hasMarker = $true
            break
        }
    }
    if (-not $hasMarker) {
        return [pscustomobject]@{ IsSafe = $false; Reason = "Install signature files were not found under the target path."; Path = $resolved }
    }

    return [pscustomobject]@{ IsSafe = $true; Reason = ""; Path = $resolved }
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
        } catch {
            $null = $_
        }
    }

    $uniqueSignals = @($signals | Select-Object -Unique)
    return [pscustomobject]@{
        Path = $resolved
        IsOneDriveLike = ($uniqueSignals.Count -gt 0)
        Signals = $uniqueSignals
        Summary = if ($uniqueSignals.Count -gt 0) { $uniqueSignals -join "; " } else { "none" }
    }
}

function Get-EffectiveAppDataPolicy {
    param(
        [switch]$SilentMode,
        [switch]$RemoveAppDataSwitch,
        [string]$RequestedPolicy
    )

    if ($RemoveAppDataSwitch) { return "Remove" }
    switch ($RequestedPolicy) {
        "Keep" { return "Keep" }
        "Remove" { return "Remove" }
        default {
            if ($SilentMode) { return "Keep" }
            return "Prompt"
        }
    }
}

function New-UninstallProgressUi {
    if ($Silent -or $script:IsDryRun) { return $null }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Teams Always Green - Uninstall"
    $form.Width = 640
    $form.Height = 240
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true

    $title = New-Object System.Windows.Forms.Label
    $title.AutoSize = $true
    $title.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $title.Location = New-Object System.Drawing.Point(16, 12)
    $title.Text = "Uninstall"

    $stepper = New-Object System.Windows.Forms.Label
    $stepper.AutoSize = $true
    $stepper.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Regular)
    $stepper.ForeColor = [System.Drawing.Color]::FromArgb(90, 90, 90)
    $stepper.Location = New-Object System.Drawing.Point(120, 15)
    $stepper.Text = "Step 1 of 4 - Preparing"

    $label = New-Object System.Windows.Forms.Label
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point(16, 52)
    $label.Text = "Preparing uninstall..."

    $progress = New-Object System.Windows.Forms.ProgressBar
    $progress.Width = 590
    $progress.Height = 20
    $progress.Location = New-Object System.Drawing.Point(16, 76)
    $progress.Minimum = 0
    $progress.Maximum = 100
    $progress.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous

    $meta = New-Object System.Windows.Forms.Label
    $meta.AutoSize = $true
    $meta.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Regular)
    $meta.Location = New-Object System.Drawing.Point(16, 104)
    $meta.Text = ""

    $detailsLink = New-Object System.Windows.Forms.LinkLabel
    $detailsLink.Text = "Show details"
    $detailsLink.AutoSize = $true
    $detailsLink.Location = New-Object System.Drawing.Point(525, 104)

    $detailsList = New-Object System.Windows.Forms.ListBox
    $detailsList.Width = 590
    $detailsList.Height = 70
    $detailsList.Location = New-Object System.Drawing.Point(16, 126)
    $detailsList.Visible = $false

    $baseHeight = 240
    $expandedHeight = 320
    $detailsLink.Add_LinkClicked({
        $detailsList.Visible = -not $detailsList.Visible
        if ($detailsList.Visible) {
            $detailsLink.Text = "Hide details"
            $form.Height = $expandedHeight
        } else {
            $detailsLink.Text = "Show details"
            $form.Height = $baseHeight
        }
    })

    $form.Controls.Add($title)
    $form.Controls.Add($stepper)
    $form.Controls.Add($label)
    $form.Controls.Add($progress)
    $form.Controls.Add($meta)
    $form.Controls.Add($detailsLink)
    $form.Controls.Add($detailsList)
    $form.Show()
    [System.Windows.Forms.Application]::DoEvents()

    return @{
        Form = $form
        Stepper = $stepper
        Label = $label
        Progress = $progress
        Meta = $meta
        DetailsList = $detailsList
    }
}

function Set-UninstallProgress($ui, [int]$percent, [string]$stepText, [string]$message, [string]$metaText) {
    if (-not $ui) { return }
    if ($ui.Form.IsDisposed) { return }
    $pct = [Math]::Max(0, [Math]::Min(100, $percent))
    $ui.Progress.Value = $pct
    $ui.Stepper.Text = $stepText
    $ui.Label.Text = $message
    $ui.Meta.Text = $metaText
    [System.Windows.Forms.Application]::DoEvents()
}

function Add-UninstallDetail($ui, [string]$message) {
    if ([string]::IsNullOrWhiteSpace($message)) { return }
    Write-UninstallLog $message
    if (-not $ui -or $ui.Form.IsDisposed) { return }
    [void]$ui.DetailsList.Items.Insert(0, $message)
    while ($ui.DetailsList.Items.Count -gt 40) {
        $ui.DetailsList.Items.RemoveAt($ui.DetailsList.Items.Count - 1)
    }
    [System.Windows.Forms.Application]::DoEvents()
}

function Close-UninstallProgress($ui) {
    if (-not $ui) { return }
    try {
        if ($ui.Form -and -not $ui.Form.IsDisposed) {
            $ui.Form.Close()
            $ui.Form.Dispose()
        }
    } catch {
        $null = $_
    }
}

function Ensure-TempExecution([string]$resolvedInstallRoot) {
    if ($Relaunched) { return }

    $scriptPath = [string]$script:ScriptFilePath
    if ([string]::IsNullOrWhiteSpace($scriptPath) -or -not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        Complete-Uninstall -ExitCode $script:ExitCodes.RelaunchFailed -Result "RelaunchFailed" -Summary "Unable to resolve uninstall script path for temp execution." -NotifyUser -Icon ([System.Windows.Forms.MessageBoxIcon]::Error) -Title "Uninstall failed"
    }

    $runnerPath = Join-Path $tempRoot ("TAG-UninstallRunner-{0}.ps1" -f [Guid]::NewGuid().ToString("N"))
    try {
        Copy-Item -Path $scriptPath -Destination $runnerPath -Force
    } catch {
        Complete-Uninstall -ExitCode $script:ExitCodes.RelaunchFailed -Result "RelaunchFailed" -Summary ("Unable to stage uninstall runner: {0}" -f $_.Exception.Message) -NotifyUser -Icon ([System.Windows.Forms.MessageBoxIcon]::Error) -Title "Uninstall failed"
    }

    $argLine = "-NoProfile -ExecutionPolicy RemoteSigned -File `"{0}`" -Relaunched -InstallRoot `"{1}`" -AppDataPolicy {2}" -f $runnerPath, $resolvedInstallRoot, $AppDataPolicy
    if ($Silent) { $argLine += " -Silent" }
    if ($RemoveAppData) { $argLine += " -RemoveAppData" }
    if ($script:IsDryRun) { $argLine += " -WhatIf" }

    $windowStyle = if ($Silent) { "Hidden" } else { "Normal" }
    try {
        Write-UninstallLog ("Relaunching uninstall from temp runner: {0}" -f $runnerPath)
        Start-Process -FilePath (Get-PowerShellPath) -ArgumentList $argLine -WindowStyle $windowStyle -WorkingDirectory $tempRoot -ErrorAction Stop | Out-Null
        exit 0
    } catch {
        Complete-Uninstall -ExitCode $script:ExitCodes.RelaunchFailed -Result "RelaunchFailed" -Summary ("Unable to launch temp uninstall runner: {0}" -f $_.Exception.Message) -NotifyUser -Icon ([System.Windows.Forms.MessageBoxIcon]::Error) -Title "Uninstall failed"
    }
}

function Ensure-SafeWorkingDirectory([string]$installRoot) {
    try {
        $currentPath = [string](Get-Location).Path
    } catch {
        $currentPath = ""
    }
    if ([string]::IsNullOrWhiteSpace($currentPath) -or [string]::IsNullOrWhiteSpace($installRoot)) { return }

    $installFull = ""
    $currentFull = ""
    try { $installFull = [System.IO.Path]::GetFullPath($installRoot).TrimEnd("\") } catch { $installFull = [string]$installRoot.TrimEnd("\") }
    try { $currentFull = [System.IO.Path]::GetFullPath($currentPath).TrimEnd("\") } catch { $currentFull = [string]$currentPath.TrimEnd("\") }
    if ([string]::IsNullOrWhiteSpace($installFull) -or [string]::IsNullOrWhiteSpace($currentFull)) { return }

    $insideInstallRoot = $currentFull.Equals($installFull, [System.StringComparison]::OrdinalIgnoreCase) -or
        $currentFull.StartsWith(($installFull + "\"), [System.StringComparison]::OrdinalIgnoreCase)
    if (-not $insideInstallRoot) { return }

    try {
        Set-Location -LiteralPath $tempRoot -ErrorAction Stop
        Write-UninstallLog ("Working directory moved from install root to temp: {0}" -f $tempRoot)
    } catch {
        Write-UninstallLog ("Failed to move working directory off install root: {0}" -f $_.Exception.Message)
    }
}

function Get-ShortcutMap {
    $programsDir = [Environment]::GetFolderPath("Programs")
    $menuFolder = Join-Path $programsDir $script:AppName
    return @{
        MenuFolder        = $menuFolder
        MainShortcut      = (Join-Path $menuFolder "Teams Always Green.lnk")
        UninstallShortcut = (Join-Path $menuFolder "Uninstall Teams Always Green.lnk")
        DesktopShortcut   = (Join-Path ([Environment]::GetFolderPath("Desktop")) "Teams Always Green.lnk")
        StartupShortcut   = (Join-Path ([Environment]::GetFolderPath("Startup")) "Teams Always Green.lnk")
    }
}

function Remove-AppShortcuts([hashtable]$shortcutMap, $ui) {
    $result = [ordered]@{
        Removed = @()
        Failed  = @()
    }

    foreach ($shortcut in @(
        [string]$shortcutMap.MainShortcut,
        [string]$shortcutMap.UninstallShortcut,
        [string]$shortcutMap.DesktopShortcut,
        [string]$shortcutMap.StartupShortcut
    )) {
        if ([string]::IsNullOrWhiteSpace($shortcut)) { continue }
        try {
            if (-not (Test-Path -LiteralPath $shortcut)) { continue }
            if ($script:IsDryRun) {
                Add-UninstallDetail $ui ("WhatIf: would remove shortcut: {0}" -f $shortcut)
                continue
            }
            Remove-Item -LiteralPath $shortcut -Force -ErrorAction Stop
            $result.Removed += $shortcut
            Add-UninstallDetail $ui ("Removed shortcut: {0}" -f $shortcut)
        } catch {
            $failure = ("{0} | {1}" -f $shortcut, $_.Exception.Message)
            $result.Failed += $failure
            Add-UninstallDetail $ui ("Failed to remove shortcut: {0}" -f $failure)
        }
    }

    try {
        $menuFolder = [string]$shortcutMap.MenuFolder
        if (-not [string]::IsNullOrWhiteSpace($menuFolder) -and (Test-Path -LiteralPath $menuFolder -PathType Container)) {
            $childCount = (Get-ChildItem -Path $menuFolder -Force | Measure-Object).Count
            if ($childCount -eq 0) {
                if ($script:IsDryRun) {
                    Add-UninstallDetail $ui ("WhatIf: would remove empty Start Menu folder: {0}" -f $menuFolder)
                } else {
                    Remove-Item -LiteralPath $menuFolder -Force -ErrorAction Stop
                    Add-UninstallDetail $ui ("Removed empty Start Menu folder: {0}" -f $menuFolder)
                }
            }
        }
    } catch {
        Add-UninstallDetail $ui ("Failed to remove Start Menu folder: {0}" -f $_.Exception.Message)
    }

    return [pscustomobject]$result
}

function Get-TrackedProcessCandidates([string]$installRoot) {
    $filter = "Name='wscript.exe' OR Name='cscript.exe' OR Name='powershell.exe' OR Name='pwsh.exe'"
    try {
        $all = @(Get-CimInstance Win32_Process -Filter $filter -ErrorAction Stop)
    } catch {
        Write-UninstallLog ("Process discovery failed: {0}" -f $_.Exception.Message)
        return @()
    }

    $tokens = @(
        $installRoot,
        (Join-Path $installRoot "Script\Teams Always Green.ps1"),
        (Join-Path $installRoot "Teams Always Green.VBS"),
        (Join-Path $installRoot "Script\Uninstall")
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.ToLowerInvariant() }

    $selected = New-Object System.Collections.Generic.List[object]
    foreach ($proc in $all) {
        $procId = [int]$proc.ProcessId
        if ($procId -eq $PID) { continue }
        $cmd = [string]$proc.CommandLine
        if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
        $cmdLower = $cmd.ToLowerInvariant()
        foreach ($token in $tokens) {
            if ($cmdLower.Contains($token)) {
                $selected.Add([pscustomobject]@{
                    ProcessId = $procId
                    Name = [string]$proc.Name
                    CommandLine = [string]$proc.CommandLine
                })
                break
            }
        }
    }
    return @($selected | Sort-Object ProcessId -Unique)
}

function Stop-AppProcesses([string]$installRoot, $ui) {
    $result = [ordered]@{
        Candidates = @()
        Stopped    = @()
        Failed     = @()
    }

    $candidates = @(Get-TrackedProcessCandidates -installRoot $installRoot)
    foreach ($candidate in $candidates) {
        $result.Candidates += ("PID={0}|Name={1}" -f $candidate.ProcessId, $candidate.Name)
        if ($script:IsDryRun) {
            Add-UninstallDetail $ui ("WhatIf: would stop PID={0} Name={1}" -f $candidate.ProcessId, $candidate.Name)
            continue
        }

        $stopped = $false
        foreach ($delay in @(200, 500, 900)) {
            try {
                Stop-Process -Id ([int]$candidate.ProcessId) -Force -ErrorAction Stop
                $stopped = $true
                break
            } catch {
                Start-Sleep -Milliseconds $delay
            }
        }

        if ($stopped) {
            $result.Stopped += [int]$candidate.ProcessId
            Add-UninstallDetail $ui ("Stopped process PID={0} Name={1}" -f $candidate.ProcessId, $candidate.Name)
        } else {
            $result.Failed += [int]$candidate.ProcessId
            Add-UninstallDetail $ui ("Failed to stop PID={0}" -f $candidate.ProcessId)
        }
    }

    return [pscustomobject]$result
}

function Get-PathLockDiagnostics([string]$installRoot) {
    $details = New-Object System.Collections.Generic.List[string]
    $oneDrive = Get-OneDrivePathDiagnostics -path $installRoot
    $details.Add(("OneDrivePathLike={0}" -f [bool]$oneDrive.IsOneDriveLike))
    if ($oneDrive.Signals.Count -gt 0) {
        foreach ($signal in @($oneDrive.Signals)) {
            $details.Add(("OneDriveSignal={0}" -f [string]$signal))
        }
    }

    $candidates = @(Get-TrackedProcessCandidates -installRoot $installRoot)
    if ($candidates.Count -eq 0) {
        $details.Add("ProcessLocks=none")
        return ($details -join " || ")
    }

    $items = New-Object System.Collections.Generic.List[string]
    foreach ($candidate in $candidates) {
        $cmd = [string]$candidate.CommandLine
        if ($cmd.Length -gt 160) { $cmd = $cmd.Substring(0, 160) + "..." }
        $items.Add(("PID={0};Name={1};Cmd={2}" -f $candidate.ProcessId, $candidate.Name, $cmd))
    }
    $details.Add(("ProcessLocks={0}" -f ($items -join " || ")))
    return ($details -join " || ")
}

function Remove-PathWithRetry([string]$path, [string]$label, [int]$maxAttempts, $ui, [int]$basePercent) {
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    if ($script:IsDryRun) {
        Add-UninstallDetail $ui ("WhatIf: would remove {0}: {1}" -f $label, $path)
        return $true
    }

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        if (-not (Test-Path -LiteralPath $path)) {
            Add-UninstallDetail $ui ("Removed {0}: {1}" -f $label, $path)
            return $true
        }

        try {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
        } catch {
            $null = $_
        }

        if (-not (Test-Path -LiteralPath $path)) {
            Add-UninstallDetail $ui ("Removed {0}: {1}" -f $label, $path)
            return $true
        }

        $progressSpan = 12
        $pct = $basePercent + [int][Math]::Min($progressSpan, [Math]::Floor(($attempt / [double]$maxAttempts) * $progressSpan))
        Set-UninstallProgress $ui $pct "Step 3 of 4 - Removing files" ("Retrying {0} remove..." -f $label) ("Attempt {0}/{1}" -f $attempt, $maxAttempts)
        Add-UninstallDetail $ui ("Attempt {0}/{1} failed for {2}" -f $attempt, $maxAttempts, $label)
        $delay = [Math]::Min(2000, [int](150 * [Math]::Pow(2, [Math]::Min(4, $attempt))))
        Start-Sleep -Milliseconds $delay
    }

    if (Test-Path -LiteralPath $path) {
        Add-UninstallDetail $ui ("Failed to remove {0}: {1}" -f $label, $path)
        return $false
    }

    return $true
}

try {
    $scriptPath = [string]$script:ScriptFilePath
    $resolvedInstallRoot = if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
        Get-InstallRootFromScriptPath $scriptPath
    } else {
        [string]$InstallRoot
    }

    Write-UninstallLog ("Uninstall started. Script={0}" -f $scriptPath)
    Write-UninstallLog ("InstallRoot parameter={0}" -f $resolvedInstallRoot)
    Write-UninstallLog ("Relaunched={0} Silent={1} DryRun={2}" -f $Relaunched, $Silent, $script:IsDryRun)
    $oneDrivePathInfo = Get-OneDrivePathDiagnostics -path $resolvedInstallRoot
    $script:UninstallReport.OneDrivePathLike = [bool]$oneDrivePathInfo.IsOneDriveLike
    $script:UninstallReport.OneDriveSignals = @($oneDrivePathInfo.Signals)
    Write-UninstallLog ("InstallRoot OneDrive indicators: {0}" -f $oneDrivePathInfo.Summary)

    $validation = Test-UninstallTargetPath $resolvedInstallRoot
    if (-not $validation.IsSafe) {
        Complete-Uninstall -ExitCode $script:ExitCodes.SafetyBlocked -Result "SafetyBlocked" -Summary ("Uninstall blocked for safety: {0}" -f $validation.Reason) -NotifyUser -Icon ([System.Windows.Forms.MessageBoxIcon]::Error) -Title "Uninstall blocked"
    }
    $resolvedInstallRoot = [string]$validation.Path
    $script:UninstallReport.InstallRoot = $resolvedInstallRoot
    $oneDrivePathInfo = Get-OneDrivePathDiagnostics -path $resolvedInstallRoot
    $script:UninstallReport.OneDrivePathLike = [bool]$oneDrivePathInfo.IsOneDriveLike
    $script:UninstallReport.OneDriveSignals = @($oneDrivePathInfo.Signals)
    Write-UninstallLog ("Current working directory: {0}" -f [string](Get-Location).Path)
    Ensure-SafeWorkingDirectory -installRoot $resolvedInstallRoot

    Ensure-TempExecution -resolvedInstallRoot $resolvedInstallRoot

    $ui = New-UninstallProgressUi
    Set-UninstallProgress $ui 5 "Step 1 of 4 - Verify" "Verifying install path and options..." ("Install path: {0}" -f $resolvedInstallRoot)
    if ($oneDrivePathInfo.IsOneDriveLike) {
        Add-UninstallDetail $ui ("OneDrive advisory: sync/file-provider locks can delay cleanup. Signals={0}" -f $oneDrivePathInfo.Summary)
    }

    $operation = "Remove app files, shortcuts, and selected local data"
    if (-not $PSCmdlet.ShouldProcess($resolvedInstallRoot, $operation)) {
        if ($script:IsDryRun) {
            $previewPolicy = Get-EffectiveAppDataPolicy -SilentMode:$Silent -RemoveAppDataSwitch:$RemoveAppData -RequestedPolicy $AppDataPolicy
            Complete-Uninstall -ExitCode $script:ExitCodes.Success -Result "DryRun" -Summary ("Dry run complete. Planned uninstall root: {0}. AppData policy: {1}." -f $resolvedInstallRoot, $previewPolicy)
        }
        Complete-Uninstall -ExitCode $script:ExitCodes.UserCancelled -Result "Cancelled" -Summary "Uninstall cancelled by confirmation prompt."
    }

    $effectivePolicy = Get-EffectiveAppDataPolicy -SilentMode:$Silent -RemoveAppDataSwitch:$RemoveAppData -RequestedPolicy $AppDataPolicy
    if ($effectivePolicy -eq "Prompt" -and -not $Silent) {
        $dataResp = [System.Windows.Forms.MessageBox]::Show(
            "Also remove local settings and logs?`n`nDefault is to keep local data.`nPath: $script:AppDataRoot",
            "Uninstall Teams Always Green",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($dataResp -eq [System.Windows.Forms.DialogResult]::Yes) {
            $effectivePolicy = "Remove"
        } else {
            $effectivePolicy = "Keep"
        }
    } elseif ($effectivePolicy -eq "Prompt") {
        $effectivePolicy = "Keep"
    }

    $removeAppDataRequested = ($effectivePolicy -eq "Remove")
    $script:UninstallReport.AppDataPolicyEffective = $effectivePolicy
    $script:UninstallReport.RemoveAppDataResolved = [bool]$removeAppDataRequested
    Add-UninstallDetail $ui ("AppData policy: {0}" -f $effectivePolicy)

    if (-not $Silent -and -not $script:IsDryRun) {
        $resp = [System.Windows.Forms.MessageBox]::Show(
            "Remove app files from:`n$resolvedInstallRoot`n`nRunning app processes will be stopped.",
            "Uninstall Teams Always Green",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($resp -ne [System.Windows.Forms.DialogResult]::Yes) {
            Complete-Uninstall -ExitCode $script:ExitCodes.UserCancelled -Result "Cancelled" -Summary "Uninstall cancelled by user."
        }
    }

    Set-UninstallProgress $ui 18 "Step 2 of 4 - Cleanup" "Removing shortcuts..." ""
    $shortcutMap = Get-ShortcutMap
    $shortcutResult = Remove-AppShortcuts -shortcutMap $shortcutMap -ui $ui
    $script:UninstallReport.ShortcutsRemoved = @($shortcutResult.Removed)
    $script:UninstallReport.ShortcutRemoveFailures = @($shortcutResult.Failed)

    Set-UninstallProgress $ui 32 "Step 2 of 4 - Cleanup" "Stopping running processes..." ""
    $processResult = Stop-AppProcesses -installRoot $resolvedInstallRoot -ui $ui
    $script:UninstallReport.ProcessCandidates = @($processResult.Candidates)
    $script:UninstallReport.ProcessesStopped = @($processResult.Stopped)
    $script:UninstallReport.ProcessStopFailures = @($processResult.Failed)

    Set-UninstallProgress $ui 48 "Step 3 of 4 - Removing files" "Removing app files..." ""
    $removedInstallRoot = Remove-PathWithRetry -path $resolvedInstallRoot -label "install root" -maxAttempts 18 -ui $ui -basePercent 48
    $script:UninstallReport.RemovedInstallRoot = [bool]$removedInstallRoot

    if ($removeAppDataRequested) {
        Set-UninstallProgress $ui 78 "Step 3 of 4 - Removing files" "Removing local settings and logs..." ""
        $removedAppDataRoot = Remove-PathWithRetry -path $script:AppDataRoot -label "app data" -maxAttempts 12 -ui $ui -basePercent 78
        $script:UninstallReport.RemovedAppDataRoot = [bool]$removedAppDataRoot
    } else {
        $script:UninstallReport.RemovedAppDataRoot = $false
        Add-UninstallDetail $ui "Local settings/logs retained."
    }

    $allGood = $removedInstallRoot -and (-not $removeAppDataRequested -or $script:UninstallReport.RemovedAppDataRoot)
    if (-not $allGood) {
        $script:UninstallReport.LockDiagnostics = Get-PathLockDiagnostics -installRoot $resolvedInstallRoot
        Add-UninstallDetail $ui ("Lock diagnostics: {0}" -f $script:UninstallReport.LockDiagnostics)
    }

    Set-UninstallProgress $ui 100 "Step 4 of 4 - Complete" "Finalizing uninstall..." ""
    Start-Sleep -Milliseconds 300
    Close-UninstallProgress $ui

    if ($allGood) {
        Complete-Uninstall -ExitCode $script:ExitCodes.Success -Result "Completed" -Summary "Uninstall completed successfully." -NotifyUser:(-not $Silent) -Icon ([System.Windows.Forms.MessageBoxIcon]::Information) -Title "Uninstall complete"
    }

    $partialSummary = "Uninstall completed with warnings. Some files could not be removed."
    if ([bool]$script:UninstallReport.OneDrivePathLike -or ([string]$script:UninstallReport.LockDiagnostics -match 'OneDrivePathLike=True')) {
        $partialSummary += " OneDrive sync or file-provider locks may be preventing removal."
    }
    Complete-Uninstall -ExitCode $script:ExitCodes.PartialCleanup -Result "PartialCleanup" -Summary $partialSummary -NotifyUser -Icon ([System.Windows.Forms.MessageBoxIcon]::Warning) -Title "Uninstall completed with warnings"
} catch {
    $message = "Unhandled uninstall error: {0}" -f $_.Exception.Message
    Write-UninstallLog $message
    $script:UninstallReport.Result = "UnhandledError"
    $script:UninstallReport.ExitCode = $script:ExitCodes.UnhandledError
    $script:UninstallReport.Summary = $message
    Save-UninstallReport
    Show-UninstallMessage -Summary $message -Title "Uninstall failed" -Icon ([System.Windows.Forms.MessageBoxIcon]::Error) -LogPath $script:UninstallLogPath -ReportPath $script:UninstallReportPath
    exit $script:ExitCodes.UnhandledError
}
