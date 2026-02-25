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
    [switch]$Relaunched,
    [switch]$HideConsole
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class TAGNativeConsole {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
"@
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
        [string]$Title = "Uninstall Teams Always Green",
        $Ui = $null
    )

    if (-not [string]::IsNullOrWhiteSpace($Summary)) {
        Write-UninstallLog $Summary
    }
    $script:UninstallReport.Result = [string]$Result
    $script:UninstallReport.ExitCode = [int]$ExitCode
    $script:UninstallReport.Summary = [string]$Summary
    Save-UninstallReport

    if ($NotifyUser) {
        if ($Ui -and $Ui.Form -and -not $Ui.Form.IsDisposed) {
            Show-UninstallCompletionInUi -ui $Ui -Summary $Summary -Title $Title -Icon $Icon -LogPath $script:UninstallLogPath -ReportPath $script:UninstallReportPath
        } else {
            Show-UninstallMessage -Summary $Summary -Title $Title -Icon $Icon -LogPath $script:UninstallLogPath -ReportPath $script:UninstallReportPath
        }
    } else {
        Close-UninstallProgress $Ui
    }

    exit $ExitCode
}

function Show-UninstallCompletionInUi {
    param(
        $ui,
        [string]$Summary,
        [string]$Title,
        [System.Windows.Forms.MessageBoxIcon]$Icon,
        [string]$LogPath,
        [string]$ReportPath
    )

    if (-not $ui -or -not $ui.Form -or $ui.Form.IsDisposed) { return }

    $ui.State.NextClicked = $false
    $ui.State.BackClicked = $false
    $ui.State.Cancelled = $false
    $ui.Stepper.Text = "Step 4 of 4 - Complete"
    $ui.Label.Text = [string]$Title
    $ui.Meta.Text = [string]$Summary
    $ui.Progress.Value = 100
    $ui.OptionsPanel.Visible = $false
    $ui.BackButton.Visible = $false
    $ui.CancelButton.Visible = $false
    $ui.NextButton.Visible = $true
    $ui.NextButton.Enabled = $true
    $ui.NextButton.Text = "Finish"
    $ui.Form.AcceptButton = $ui.NextButton
    $ui.Form.CancelButton = $ui.NextButton

    Add-UninstallDetail $ui ("Log: {0}" -f [string]$LogPath)
    Add-UninstallDetail $ui ("Report: {0}" -f [string]$ReportPath)
    [System.Windows.Forms.Application]::DoEvents()

    while (-not $ui.State.NextClicked -and -not $ui.State.Cancelled -and -not $ui.Form.IsDisposed) {
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 60
    }

    Close-UninstallProgress $ui
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
    $form.Width = 760
    $form.Height = 390
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    $contentLeft = 16
    $contentWidth = 710

    $title = New-Object System.Windows.Forms.Label
    $title.AutoSize = $true
    $title.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $title.Location = New-Object System.Drawing.Point($contentLeft, 12)
    $title.Text = "Uninstall"

    $stepper = New-Object System.Windows.Forms.Label
    $stepper.AutoSize = $true
    $stepper.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Regular)
    $stepper.ForeColor = [System.Drawing.Color]::FromArgb(90, 90, 90)
    $stepper.Location = New-Object System.Drawing.Point(120, 15)
    $stepper.Text = "Step 1 of 4 - Preparing"

    $label = New-Object System.Windows.Forms.Label
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point($contentLeft, 52)
    $label.Text = "Preparing uninstall..."

    $progress = New-Object System.Windows.Forms.ProgressBar
    $progress.Width = $contentWidth
    $progress.Height = 20
    $progress.Location = New-Object System.Drawing.Point($contentLeft, 76)
    $progress.Minimum = 0
    $progress.Maximum = 100
    $progress.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
    $progress.Visible = $false

    $meta = New-Object System.Windows.Forms.Label
    $meta.AutoSize = $true
    $meta.MaximumSize = New-Object System.Drawing.Size($contentWidth, 0)
    $meta.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Regular)
    $meta.Location = New-Object System.Drawing.Point($contentLeft, 78)
    $meta.Text = ""

    $optionsPanel = New-Object System.Windows.Forms.Panel
    $optionsPanel.Width = $contentWidth
    $optionsPanel.Height = 148
    $optionsPanel.Location = New-Object System.Drawing.Point($contentLeft, 126)
    $optionsPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

    $optionsPrompt = New-Object System.Windows.Forms.Label
    $optionsPrompt.AutoSize = $true
    $optionsPrompt.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Bold)
    $optionsPrompt.Location = New-Object System.Drawing.Point(10, 8)
    $optionsPrompt.Text = "Review uninstall options, then click Next to continue."

    $installPathLabel = New-Object System.Windows.Forms.Label
    $installPathLabel.AutoSize = $true
    $installPathLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8.25, [System.Drawing.FontStyle]::Regular)
    $installPathLabel.ForeColor = [System.Drawing.Color]::FromArgb(85, 85, 85)
    $installPathLabel.Location = New-Object System.Drawing.Point(10, 30)
    $installPathLabel.Text = "Install location"

    $installPathBox = New-Object System.Windows.Forms.TextBox
    $installPathBox.Location = New-Object System.Drawing.Point(10, 46)
    $installPathBox.Width = ($contentWidth - 22)
    $installPathBox.Height = 20
    $installPathBox.ReadOnly = $true
    $installPathBox.BackColor = [System.Drawing.Color]::FromArgb(249, 249, 249)
    $installPathBox.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $installPathBox.TabStop = $false
    $installPathBox.Text = ""

    $removeDataCheck = New-Object System.Windows.Forms.CheckBox
    $removeDataCheck.AutoSize = $true
    $removeDataCheck.Location = New-Object System.Drawing.Point(10, 72)
    $removeDataCheck.Text = "Also remove local settings and logs"

    $dryRunCheck = New-Object System.Windows.Forms.CheckBox
    $dryRunCheck.AutoSize = $true
    $dryRunCheck.Location = New-Object System.Drawing.Point(10, 92)
    $dryRunCheck.Text = "Dry run (preview only, no files are deleted)"

    $appDataPathLabel = New-Object System.Windows.Forms.Label
    $appDataPathLabel.AutoSize = $false
    $appDataPathLabel.Width = ($contentWidth - 22)
    $appDataPathLabel.Height = 30
    $appDataPathLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8.25, [System.Drawing.FontStyle]::Regular)
    $appDataPathLabel.ForeColor = [System.Drawing.Color]::FromArgb(85, 85, 85)
    $appDataPathLabel.Location = New-Object System.Drawing.Point(10, 112)
    $appDataPathLabel.Text = ""

    $optionsPanel.Controls.Add($optionsPrompt)
    $optionsPanel.Controls.Add($installPathLabel)
    $optionsPanel.Controls.Add($installPathBox)
    $optionsPanel.Controls.Add($removeDataCheck)
    $optionsPanel.Controls.Add($dryRunCheck)
    $optionsPanel.Controls.Add($appDataPathLabel)

    $detailsLink = New-Object System.Windows.Forms.LinkLabel
    $detailsLink.Text = "Show details"
    $detailsLink.AutoSize = $true
    $detailsLink.Location = New-Object System.Drawing.Point(630, 256)

    $detailsList = New-Object System.Windows.Forms.ListBox
    $detailsList.Width = $contentWidth
    $detailsList.Height = 84
    $detailsList.Location = New-Object System.Drawing.Point($contentLeft, 278)
    $detailsList.Visible = $false

    $cancelButtonX = $contentLeft + $contentWidth - 90
    $nextButtonX = $cancelButtonX - 98
    $backButtonX = $nextButtonX - 98
    $backButton = New-Object System.Windows.Forms.Button
    $backButton.Text = "Back"
    $backButton.Width = 90
    $backButton.Height = 30
    $backButton.Location = New-Object System.Drawing.Point($backButtonX, 320)
    $backButton.Enabled = $false

    $nextButton = New-Object System.Windows.Forms.Button
    $nextButton.Text = "Next"
    $nextButton.Width = 90
    $nextButton.Height = 30
    $nextButton.Location = New-Object System.Drawing.Point($nextButtonX, 320)
    $nextButton.Enabled = $true

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Width = 90
    $cancelButton.Height = 30
    $cancelButton.Location = New-Object System.Drawing.Point($cancelButtonX, 320)
    $cancelButton.Enabled = $true

    $state = @{
        NextClicked = $false
        BackClicked = $false
        Cancelled = $false
        AllowClose = $false
    }

    $form.Tag = $state
    $nextButton.Add_Click({
        param($sender, $args)
        $uiState = $sender.FindForm().Tag
        if ($uiState) { $uiState.NextClicked = $true }
    })
    $backButton.Add_Click({
        param($sender, $args)
        $uiState = $sender.FindForm().Tag
        if ($uiState) { $uiState.BackClicked = $true }
    })
    $cancelButton.Add_Click({
        param($sender, $args)
        $uiState = $sender.FindForm().Tag
        if ($uiState) { $uiState.Cancelled = $true }
    })

    $form.Add_FormClosing({
        param($sender, $eventArgs)
        $uiState = $sender.Tag
        if ($null -eq $uiState) { return }
        if (-not [bool]$uiState.AllowClose) {
            $uiState.Cancelled = $true
            if ($eventArgs -is [System.Windows.Forms.FormClosingEventArgs]) {
                $eventArgs.Cancel = $true
            }
        }
    })

    $baseHeight = 390
    $expandedHeight = 480
    $detailsLink.Add_LinkClicked({
        $detailsList.Visible = -not $detailsList.Visible
        if ($detailsList.Visible) {
            $detailsLink.Text = "Hide details"
            $form.Height = $expandedHeight
            $backButton.Location = New-Object System.Drawing.Point($backButtonX, 390)
            $nextButton.Location = New-Object System.Drawing.Point($nextButtonX, 390)
            $cancelButton.Location = New-Object System.Drawing.Point($cancelButtonX, 390)
        } else {
            $detailsLink.Text = "Show details"
            $form.Height = $baseHeight
            $backButton.Location = New-Object System.Drawing.Point($backButtonX, 320)
            $nextButton.Location = New-Object System.Drawing.Point($nextButtonX, 320)
            $cancelButton.Location = New-Object System.Drawing.Point($cancelButtonX, 320)
        }
    }.GetNewClosure())

    $form.AcceptButton = $nextButton
    $form.CancelButton = $cancelButton
    $form.Controls.Add($title)
    $form.Controls.Add($stepper)
    $form.Controls.Add($label)
    $form.Controls.Add($progress)
    $form.Controls.Add($meta)
    $form.Controls.Add($optionsPanel)
    $form.Controls.Add($detailsLink)
    $form.Controls.Add($detailsList)
    $form.Controls.Add($backButton)
    $form.Controls.Add($nextButton)
    $form.Controls.Add($cancelButton)
    $form.Show()
    [System.Windows.Forms.Application]::DoEvents()

    return @{
        Form = $form
        Stepper = $stepper
        Label = $label
        Progress = $progress
        Meta = $meta
        OptionsPanel = $optionsPanel
        OptionsPrompt = $optionsPrompt
        InstallPathBox = $installPathBox
        RemoveDataCheck = $removeDataCheck
        DryRunCheck = $dryRunCheck
        AppDataPathLabel = $appDataPathLabel
        DetailsList = $detailsList
        DetailsLink = $detailsLink
        BackButton = $backButton
        NextButton = $nextButton
        CancelButton = $cancelButton
        State = $state
    }
}

function Wait-UninstallWizardAction($ui) {
    if (-not $ui -or -not $ui.Form -or $ui.Form.IsDisposed) { return "Next" }

    $ui.State.NextClicked = $false
    $ui.State.BackClicked = $false
    $ui.State.Cancelled = $false
    while (-not $ui.Form.IsDisposed) {
        if ($ui.State.Cancelled) { return "Cancel" }
        if ($ui.State.BackClicked) { return "Back" }
        if ($ui.State.NextClicked) { return "Next" }
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 60
    }
    return "Cancel"
}

function Hide-ConsoleWindow {
    try {
        $hwnd = [TAGNativeConsole]::GetConsoleWindow()
        if ($hwnd -ne [IntPtr]::Zero) {
            [TAGNativeConsole]::ShowWindow($hwnd, 0) | Out-Null
        }
    } catch {
        $null = $_
    }
}

function Set-UninstallUiLayout($ui, [bool]$showProgress) {
    if (-not $ui -or -not $ui.Form -or $ui.Form.IsDisposed) { return }
    $metaTop = if ($showProgress) { 104 } else { 78 }
    $ui.Meta.Location = New-Object System.Drawing.Point(16, $metaTop)
    $metaHeight = [Math]::Max(20, [int]$ui.Meta.PreferredHeight)
    $optionsTop = $metaTop + $metaHeight + 8
    $detailsTop = $optionsTop + $ui.OptionsPanel.Height + 8

    $detailsX = [Math]::Max(16, $ui.Progress.Right - [int]$ui.DetailsLink.PreferredWidth)
    if ($showProgress) {
        $ui.Progress.Visible = $true
        $ui.OptionsPanel.Location = New-Object System.Drawing.Point(16, $optionsTop)
        $ui.DetailsLink.Location = New-Object System.Drawing.Point($detailsX, $detailsTop)
        $ui.DetailsList.Location = New-Object System.Drawing.Point(16, ($detailsTop + 22))
        return
    }

    $ui.Progress.Visible = $false
    $ui.OptionsPanel.Location = New-Object System.Drawing.Point(16, $optionsTop)
    $ui.DetailsLink.Location = New-Object System.Drawing.Point($detailsX, $detailsTop)
    $ui.DetailsList.Location = New-Object System.Drawing.Point(16, ($detailsTop + 22))
}

function Set-UninstallProgress($ui, [int]$percent, [string]$stepText, [string]$message, [string]$metaText) {
    if (-not $ui) { return }
    if ($ui.Form.IsDisposed) { return }
    $showProgress = -not ([string]$stepText -like "Step 1*")
    $pct = [Math]::Max(0, [Math]::Min(100, $percent))
    $ui.Progress.Value = $pct
    $ui.Stepper.Text = $stepText
    $ui.Label.Text = $message
    $ui.Meta.Text = $metaText
    Set-UninstallUiLayout -ui $ui -showProgress:$showProgress
    [System.Windows.Forms.Application]::DoEvents()
}

function Prepare-UninstallWizardStep1 {
    param(
        $ui,
        [string]$resolvedInstallRoot,
        [string]$effectivePolicy,
        [bool]$dryRunChecked
    )

    if (-not $ui -or -not $ui.Form -or $ui.Form.IsDisposed) { return }

    $ui.State.NextClicked = $false
    $ui.State.BackClicked = $false
    $ui.State.Cancelled = $false
    $ui.OptionsPanel.Visible = $true
    $ui.BackButton.Visible = $true
    $ui.BackButton.Enabled = $false
    $ui.NextButton.Visible = $true
    $ui.NextButton.Enabled = $true
    $ui.NextButton.Text = "Next"
    $ui.CancelButton.Visible = $true
    $ui.CancelButton.Enabled = $true
    $ui.Form.AcceptButton = $ui.NextButton
    $ui.Form.CancelButton = $ui.CancelButton

    $ui.OptionsPrompt.Text = "Review uninstall options, then click Next to continue."
    $ui.InstallPathBox.Text = [string]$resolvedInstallRoot
    $ui.AppDataPathLabel.Text = ("Local data path: {0}" -f $script:AppDataRoot)
    $ui.RemoveDataCheck.Checked = ($effectivePolicy -eq "Remove")
    $ui.RemoveDataCheck.Enabled = ($effectivePolicy -eq "Prompt")
    $ui.DryRunCheck.Checked = [bool]$dryRunChecked
    $ui.DryRunCheck.Enabled = $true
    if ($effectivePolicy -eq "Keep") {
        $ui.OptionsPrompt.Text = "Local settings and logs will be kept by policy."
    } elseif ($effectivePolicy -eq "Remove") {
        $ui.OptionsPrompt.Text = "Local settings and logs will be removed by policy."
    }
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
            if ($ui.State) { $ui.State.AllowClose = $true }
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

    $argLine = "-NoProfile -ExecutionPolicy Bypass -File `"{0}`" -Relaunched -InstallRoot `"{1}`" -AppDataPolicy {2}" -f $runnerPath, $resolvedInstallRoot, $AppDataPolicy
    if ($Silent) { $argLine += " -Silent" }
    if ($RemoveAppData) { $argLine += " -RemoveAppData" }
    if ($HideConsole) { $argLine += " -HideConsole" }
    if ($script:IsDryRun) { $argLine += " -WhatIf" }

    $windowStyle = if ($Silent -or $HideConsole) { "Hidden" } else { "Normal" }
    try {
        Write-UninstallLog ("Relaunching uninstall from temp runner: {0}" -f $runnerPath)
        Write-UninstallLog ("Relaunch window style: {0}" -f $windowStyle)
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

    $isInstallRoot = ($label -eq "install root")
    $pathIsOneDriveLike = $false
    if ($isInstallRoot) {
        try {
            $pathIsOneDriveLike = [bool](Get-OneDrivePathDiagnostics -path $path).IsOneDriveLike
        } catch {
            $pathIsOneDriveLike = $false
        }
    }
    $attemptLimit = if ($pathIsOneDriveLike) { [Math]::Min($maxAttempts, 6) } else { $maxAttempts }
    $lastErrorMessage = ""
    $earlyExitReason = ""

    for ($attempt = 1; $attempt -le $attemptLimit; $attempt++) {
        if (-not (Test-Path -LiteralPath $path)) {
            Add-UninstallDetail $ui ("Removed {0}: {1}" -f $label, $path)
            return $true
        }

        try {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
        } catch {
            $lastErrorMessage = [string]$_.Exception.Message
            try {
                & cmd.exe /c "rmdir /s /q `"$path`"" | Out-Null
            } catch {
                $null = $_
            }
        }

        if (-not (Test-Path -LiteralPath $path)) {
            Add-UninstallDetail $ui ("Removed {0}: {1}" -f $label, $path)
            return $true
        }

        if ($isInstallRoot -and $pathIsOneDriveLike -and $attempt -ge 3) {
            $remainingLocks = @(Get-TrackedProcessCandidates -installRoot $path)
            if ($remainingLocks.Count -eq 0) {
                $earlyExitReason = "No process locks detected; OneDrive/file-provider lock likely."
                Add-UninstallDetail $ui "No app process locks detected; OneDrive/file-provider lock likely. Stopping retries early."
                break
            }
        }

        $progressSpan = 12
        $pct = $basePercent + [int][Math]::Min($progressSpan, [Math]::Floor(($attempt / [double]$attemptLimit) * $progressSpan))
        Set-UninstallProgress $ui $pct "Step 3 of 4 - Removing files" ("Retrying {0} remove..." -f $label) ("Attempt {0}/{1}" -f $attempt, $attemptLimit)
        Add-UninstallDetail $ui ("Attempt {0}/{1} failed for {2}" -f $attempt, $attemptLimit, $label)
        if (-not [string]::IsNullOrWhiteSpace($lastErrorMessage)) {
            Add-UninstallDetail $ui ("Delete error: {0}" -f $lastErrorMessage)
        }
        if ($pathIsOneDriveLike) {
            $delay = [Math]::Min(900, [int](120 * [Math]::Pow(2, [Math]::Min(3, $attempt))))
        } else {
            $delay = [Math]::Min(2000, [int](150 * [Math]::Pow(2, [Math]::Min(4, $attempt))))
        }
        Start-Sleep -Milliseconds $delay
    }

    if (Test-Path -LiteralPath $path) {
        if (-not [string]::IsNullOrWhiteSpace($earlyExitReason)) {
            Add-UninstallDetail $ui ("Stopped retry loop for {0}: {1}" -f $label, $earlyExitReason)
        }
        Add-UninstallDetail $ui ("Failed to remove {0}: {1}" -f $label, $path)
        return $false
    }

    return $true
}

$ui = $null
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
    Write-UninstallLog ("HideConsole={0}" -f [bool]$HideConsole)
    try {
        $policyMachine = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue
        $policyUser = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction SilentlyContinue
        $policyProcess = Get-ExecutionPolicy -Scope Process -ErrorAction SilentlyContinue
        Write-UninstallLog ("ExecutionPolicy LocalMachine={0} CurrentUser={1} Process={2}" -f $policyMachine, $policyUser, $policyProcess)
    } catch {
        $null = $_
    }
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

    if ($HideConsole -and -not $Silent) {
        Hide-ConsoleWindow
        Write-UninstallLog "Console window hidden for interactive uninstall."
    }

    $dryRunFromParameter = [bool]$script:IsDryRun
    $ui = New-UninstallProgressUi
    while ($true) {
        $effectivePolicy = Get-EffectiveAppDataPolicy -SilentMode:$Silent -RemoveAppDataSwitch:$RemoveAppData -RequestedPolicy $AppDataPolicy
        if ($effectivePolicy -eq "Prompt" -and $Silent) {
            $effectivePolicy = "Keep"
        }
        $cycleDryRunFromWizard = $false

        Set-UninstallProgress $ui 5 "Step 1 of 4 - Verify" "Verify uninstall target and options." "Confirm the target path and local data preference."
        if ($oneDrivePathInfo.IsOneDriveLike) {
            Add-UninstallDetail $ui ("OneDrive advisory: sync/file-provider locks can delay cleanup. Signals={0}" -f $oneDrivePathInfo.Summary)
        }

        if ($ui -and $ui.Form -and -not $ui.Form.IsDisposed) {
            Prepare-UninstallWizardStep1 -ui $ui -resolvedInstallRoot $resolvedInstallRoot -effectivePolicy $effectivePolicy -dryRunChecked ([bool]$script:IsDryRun)
            Add-UninstallDetail $ui ("Ready to remove app files from: {0}" -f $resolvedInstallRoot)
            Add-UninstallDetail $ui "Next step will stop running app processes and begin file cleanup."

            $choice = Wait-UninstallWizardAction $ui
            if ($choice -eq "Cancel") {
                Complete-Uninstall -ExitCode $script:ExitCodes.UserCancelled -Result "Cancelled" -Summary "Uninstall cancelled by user." -Ui $ui
            }
            if ($effectivePolicy -eq "Prompt") {
                if ($ui.RemoveDataCheck.Checked) {
                    $effectivePolicy = "Remove"
                } else {
                    $effectivePolicy = "Keep"
                }
            }
            if ($ui.DryRunCheck.Checked -and -not $dryRunFromParameter) {
                $script:IsDryRun = $true
                $script:UninstallReport.DryRun = $true
                $cycleDryRunFromWizard = $true
                Add-UninstallDetail $ui "Dry run enabled from uninstall wizard. No files will be deleted."
            } elseif (-not $dryRunFromParameter) {
                $script:IsDryRun = $false
                $script:UninstallReport.DryRun = $false
            }

            $ui.OptionsPanel.Visible = $false
            $ui.BackButton.Visible = $false
            $ui.NextButton.Enabled = $false
            $ui.CancelButton.Enabled = $false
            $ui.CancelButton.Visible = $false
            $ui.Form.AcceptButton = $null
            $ui.Form.CancelButton = $null
        }

        $operation = "Remove app files, shortcuts, and selected local data"
        if (-not $PSCmdlet.ShouldProcess($resolvedInstallRoot, $operation)) {
            if ($script:IsDryRun) {
                if ($cycleDryRunFromWizard -and $ui -and $ui.Form -and -not $ui.Form.IsDisposed) {
                    Add-UninstallDetail $ui ("Dry run complete. Planned uninstall root: {0}. AppData policy: {1}." -f $resolvedInstallRoot, $effectivePolicy)
                    Add-UninstallDetail $ui "Returned to Step 1. Uncheck dry run to perform actual uninstall."
                    $script:IsDryRun = $false
                    $script:UninstallReport.DryRun = $false
                    continue
                }
                Complete-Uninstall -ExitCode $script:ExitCodes.Success -Result "DryRun" -Summary ("Dry run complete. Planned uninstall root: {0}. AppData policy: {1}." -f $resolvedInstallRoot, $effectivePolicy) -Ui $ui
            }
            Complete-Uninstall -ExitCode $script:ExitCodes.UserCancelled -Result "Cancelled" -Summary "Uninstall cancelled by confirmation prompt." -Ui $ui
        }

        $removeAppDataRequested = ($effectivePolicy -eq "Remove")
        $script:UninstallReport.AppDataPolicyEffective = $effectivePolicy
        $script:UninstallReport.RemoveAppDataResolved = [bool]$removeAppDataRequested
        Add-UninstallDetail $ui ("AppData policy: {0}" -f $effectivePolicy)

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

        if ($script:IsDryRun) {
            if ($cycleDryRunFromWizard -and $ui -and $ui.Form -and -not $ui.Form.IsDisposed) {
                Add-UninstallDetail $ui ("Dry run complete. Planned uninstall root: {0}. AppData policy: {1}." -f $resolvedInstallRoot, $effectivePolicy)
                Add-UninstallDetail $ui "Returned to Step 1. Uncheck dry run to perform actual uninstall."
                $script:IsDryRun = $false
                $script:UninstallReport.DryRun = $false
                continue
            }
            Complete-Uninstall -ExitCode $script:ExitCodes.Success -Result "DryRun" -Summary ("Dry run complete. Planned uninstall root: {0}. AppData policy: {1}." -f $resolvedInstallRoot, $effectivePolicy) -NotifyUser:(-not $Silent) -Icon ([System.Windows.Forms.MessageBoxIcon]::Information) -Title "Uninstall dry run complete" -Ui $ui
        }

        if ($allGood) {
            Complete-Uninstall -ExitCode $script:ExitCodes.Success -Result "Completed" -Summary "Uninstall completed successfully." -NotifyUser:(-not $Silent) -Icon ([System.Windows.Forms.MessageBoxIcon]::Information) -Title "Uninstall complete" -Ui $ui
        }

        $partialSummary = "Uninstall completed with warnings. Some files could not be removed."
        if ([bool]$script:UninstallReport.OneDrivePathLike -or ([string]$script:UninstallReport.LockDiagnostics -match 'OneDrivePathLike=True')) {
            $partialSummary += " OneDrive sync or file-provider locks may be preventing removal."
        }
        Complete-Uninstall -ExitCode $script:ExitCodes.PartialCleanup -Result "PartialCleanup" -Summary $partialSummary -NotifyUser -Icon ([System.Windows.Forms.MessageBoxIcon]::Warning) -Title "Uninstall completed with warnings" -Ui $ui
    }
} catch {
    $message = "Unhandled uninstall error: {0}" -f $_.Exception.Message
    if ($ui -and $ui.Form -and -not $ui.Form.IsDisposed) {
        Complete-Uninstall -ExitCode $script:ExitCodes.UnhandledError -Result "UnhandledError" -Summary $message -NotifyUser:(-not $Silent) -Icon ([System.Windows.Forms.MessageBoxIcon]::Error) -Title "Uninstall failed" -Ui $ui
    }
    Write-UninstallLog $message
    $script:UninstallReport.Result = "UnhandledError"
    $script:UninstallReport.ExitCode = $script:ExitCodes.UnhandledError
    $script:UninstallReport.Summary = $message
    Save-UninstallReport
    Show-UninstallMessage -Summary $message -Title "Uninstall failed" -Icon ([System.Windows.Forms.MessageBoxIcon]::Error) -LogPath $script:UninstallLogPath -ReportPath $script:UninstallReportPath
    exit $script:ExitCodes.UnhandledError
}
