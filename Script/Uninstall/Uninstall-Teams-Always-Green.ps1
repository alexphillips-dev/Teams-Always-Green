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
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class TAGNativeFileOps {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool MoveFileEx(string existingFileName, string newFileName, int flags);
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
$script:MoveFileDelayUntilReboot = 0x4
$script:DeleteFailureHints = @{}

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
    KnownLockerCandidates    = @()
    KnownLockersStopped      = @()
    KnownLockerStopFailures  = @()
    ForceCloseKnownLockers   = $false
    ShortcutsRemoved         = @()
    ShortcutRemoveFailures   = @()
    EntryPointPhaseComplete  = $false
    PhaseMarkerPath          = ""
    RemovedInstallRoot       = $false
    RemovedAppDataRoot       = $false
    RenameFallbackUsed       = $false
    RenameFallbackPath       = ""
    DeferredCleanupScheduled = $false
    DeferredCleanupPath      = ""
    OneDrivePathLike         = $false
    OneDriveSignals          = @()
    LockDiagnostics          = ""
    ResidualPaths            = @()
    ResidualReason           = ""
    HealthCheck              = @{}
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
    $ui.BackButton.Visible = $true
    $ui.BackButton.Enabled = $true
    $ui.BackButton.Text = "Copy diagnostics"
    $ui.CancelButton.Visible = $false
    $ui.NextButton.Visible = $true
    $ui.NextButton.Enabled = $true
    $ui.NextButton.Text = "Finish"
    $ui.Form.AcceptButton = $ui.NextButton
    $ui.Form.CancelButton = $null

    Add-UninstallDetail $ui ("Log: {0}" -f [string]$LogPath)
    Add-UninstallDetail $ui ("Report: {0}" -f [string]$ReportPath)
    [System.Windows.Forms.Application]::DoEvents()

    while (-not $ui.State.NextClicked -and -not $ui.State.Cancelled -and -not $ui.Form.IsDisposed) {
        if ($ui.State.BackClicked) {
            $ui.State.BackClicked = $false
            try {
                $diagText = New-UninstallDiagnosticsText -Title $Title -Summary $Summary -LogPath $LogPath -ReportPath $ReportPath
                [System.Windows.Forms.Clipboard]::SetText($diagText)
                Add-UninstallDetail $ui "Diagnostics copied to clipboard."
            } catch {
                Add-UninstallDetail $ui ("Failed to copy diagnostics: {0}" -f $_.Exception.Message)
            }
        }
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 60
    }

    Close-UninstallProgress $ui
}

function New-UninstallDiagnosticsText {
    param(
        [string]$Title,
        [string]$Summary,
        [string]$LogPath,
        [string]$ReportPath
    )

    $lines = @(
        ("Title: {0}" -f [string]$Title),
        ("Summary: {0}" -f [string]$Summary),
        ("Result: {0}" -f [string]$script:UninstallReport.Result),
        ("ExitCode: {0}" -f [string]$script:UninstallReport.ExitCode),
        ("InstallRoot: {0}" -f [string]$script:UninstallReport.InstallRoot),
        ("Log: {0}" -f [string]$LogPath),
        ("Report: {0}" -f [string]$ReportPath),
        ("StartedAtUtc: {0}" -f [string]$script:UninstallReport.StartedAtUtc),
        ("CompletedAtUtc: {0}" -f [string]$script:UninstallReport.CompletedAtUtc)
    )
    return ($lines -join [Environment]::NewLine)
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
    $optionsPanel.Height = 172
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

    $forceCloseLockersCheck = New-Object System.Windows.Forms.CheckBox
    $forceCloseLockersCheck.AutoSize = $true
    $forceCloseLockersCheck.Location = New-Object System.Drawing.Point(10, 112)
    $forceCloseLockersCheck.Text = "Force close likely locking apps before cleanup (advanced)"

    $appDataPathLabel = New-Object System.Windows.Forms.Label
    $appDataPathLabel.AutoSize = $false
    $appDataPathLabel.Width = ($contentWidth - 22)
    $appDataPathLabel.Height = 30
    $appDataPathLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8.25, [System.Drawing.FontStyle]::Regular)
    $appDataPathLabel.ForeColor = [System.Drawing.Color]::FromArgb(85, 85, 85)
    $appDataPathLabel.Location = New-Object System.Drawing.Point(10, 136)
    $appDataPathLabel.Text = ""

    $optionsPanel.Controls.Add($optionsPrompt)
    $optionsPanel.Controls.Add($installPathLabel)
    $optionsPanel.Controls.Add($installPathBox)
    $optionsPanel.Controls.Add($removeDataCheck)
    $optionsPanel.Controls.Add($dryRunCheck)
    $optionsPanel.Controls.Add($forceCloseLockersCheck)
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

    $baseHeight = 410
    $expandedHeight = 560
    $detailsLink.Add_LinkClicked({
        $detailsList.Visible = -not $detailsList.Visible
        if ($detailsList.Visible) {
            $detailsLink.Text = "Hide details"
            $form.Height = $expandedHeight
        } else {
            $detailsLink.Text = "Show details"
            $form.Height = $baseHeight
        }
        $buttonY = [Math]::Max(0, $form.ClientSize.Height - $nextButton.Height - 12)
        $backButton.Location = New-Object System.Drawing.Point($backButtonX, $buttonY)
        $nextButton.Location = New-Object System.Drawing.Point($nextButtonX, $buttonY)
        $cancelButton.Location = New-Object System.Drawing.Point($cancelButtonX, $buttonY)
        if ($detailsList.Visible) {
            $detailsTop = $detailsList.Location.Y
            $maxDetailsHeight = [Math]::Max(60, $buttonY - $detailsTop - 8)
            $detailsList.Height = $maxDetailsHeight
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
        ForceCloseLockersCheck = $forceCloseLockersCheck
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
    } else {
        $ui.Progress.Visible = $false
        $ui.OptionsPanel.Location = New-Object System.Drawing.Point(16, $optionsTop)
        $ui.DetailsLink.Location = New-Object System.Drawing.Point($detailsX, $detailsTop)
        $ui.DetailsList.Location = New-Object System.Drawing.Point(16, ($detailsTop + 22))
    }

    $buttonBottomMargin = 12
    $buttonY = [Math]::Max(0, $ui.Form.ClientSize.Height - $ui.NextButton.Height - $buttonBottomMargin)
    $ui.BackButton.Location = New-Object System.Drawing.Point($ui.BackButton.Location.X, $buttonY)
    $ui.NextButton.Location = New-Object System.Drawing.Point($ui.NextButton.Location.X, $buttonY)
    $ui.CancelButton.Location = New-Object System.Drawing.Point($ui.CancelButton.Location.X, $buttonY)

    if ($ui.DetailsList.Visible) {
        $detailsTopDynamic = $ui.DetailsList.Location.Y
        $availableHeight = [Math]::Max(60, $buttonY - $detailsTopDynamic - 8)
        $ui.DetailsList.Height = $availableHeight
    }
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
        $dryRunChecked,
        [bool]$forceCloseKnownLockersChecked
    )

    if (-not $ui -or -not $ui.Form -or $ui.Form.IsDisposed) { return }

    $ui.State.NextClicked = $false
    $ui.State.BackClicked = $false
    $ui.State.Cancelled = $false
    $ui.OptionsPanel.Visible = $true
    $ui.BackButton.Visible = $true
    $ui.BackButton.Enabled = $false
    $ui.BackButton.Text = "Back"
    $ui.NextButton.Visible = $true
    $ui.NextButton.Enabled = $true
    $ui.NextButton.Text = "Next"
    $ui.CancelButton.Visible = $true
    $ui.CancelButton.Enabled = $true
    $ui.CancelButton.Text = "Cancel"
    $ui.Form.AcceptButton = $ui.NextButton
    $ui.Form.CancelButton = $ui.CancelButton

    $ui.OptionsPrompt.Text = "Review uninstall options, then click Next to continue."
    $ui.InstallPathBox.Text = [string]$resolvedInstallRoot
    $ui.AppDataPathLabel.Text = ("Local data path: {0}" -f $script:AppDataRoot)
    $ui.RemoveDataCheck.Checked = ($effectivePolicy -eq "Remove")
    $ui.RemoveDataCheck.Enabled = ($effectivePolicy -eq "Prompt")
    $dryRunEnabled = $false
    try {
        if ($dryRunChecked -is [bool]) {
            $dryRunEnabled = [bool]$dryRunChecked
        } elseif ($null -ne $dryRunChecked) {
            $raw = [string]$dryRunChecked
            switch -Regex ($raw.Trim()) {
                '^(?i:true|1|yes|y)$' { $dryRunEnabled = $true; break }
                '^(?i:false|0|no|n|)$' { $dryRunEnabled = $false; break }
                default { $dryRunEnabled = [bool]$dryRunChecked }
            }
        }
    } catch {
        $dryRunEnabled = $false
    }
    $ui.DryRunCheck.Checked = $dryRunEnabled
    $ui.DryRunCheck.Enabled = $true
    if ($ui.ForceCloseLockersCheck) {
        $ui.ForceCloseLockersCheck.Checked = [bool]$forceCloseKnownLockersChecked
        $ui.ForceCloseLockersCheck.Enabled = $true
    }
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

function Get-LockReasonCategory([string]$hint) {
    if ([string]::IsNullOrWhiteSpace($hint)) { return "unknown" }
    $text = [string]$hint
    if ($text -match '(?i)being used by another process|cannot access the file') { return "lock" }
    if ($text -match '(?i)access is denied|unauthorized') { return "acl" }
    if ($text -match '(?i)path too long|filename or extension is too long') { return "path" }
    return "unknown"
}

function Get-ResidualPathSnapshot([string]$path, [int]$maxItems = 40) {
    $items = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) { return @() }

    try {
        $items.Add([string]$path)
        $children = @(Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction Stop | Select-Object -ExpandProperty FullName)
        foreach ($child in @($children | Select-Object -First ([Math]::Max(0, $maxItems - 1)))) {
            $items.Add([string]$child)
        }
    } catch {
        $items.Add(("snapshot-error: {0}" -f $_.Exception.Message))
    }
    return @($items)
}

function Write-UninstallPhaseMarker([string]$installRoot, [string]$policy, [bool]$removeAppData, $ui) {
    $markerPath = Join-Path $tempRoot ("TeamsAlwaysGreen-Uninstall-Phase1-{0}.json" -f $runId)
    try {
        $payload = [ordered]@{
            Phase                    = "EntryPointsRemoved"
            TimestampUtc             = [DateTime]::UtcNow.ToString("o")
            InstallRoot              = [string]$installRoot
            AppDataPolicyEffective   = [string]$policy
            RemoveAppDataResolved    = [bool]$removeAppData
        } | ConvertTo-Json -Depth 4
        Set-Content -Path $markerPath -Value $payload -Encoding UTF8 -WhatIf:$false -Confirm:$false
        $script:UninstallReport.EntryPointPhaseComplete = $true
        $script:UninstallReport.PhaseMarkerPath = $markerPath
        Add-UninstallDetail $ui ("Phase 1 complete marker written: {0}" -f $markerPath)
    } catch {
        Add-UninstallDetail $ui ("Failed to write phase marker: {0}" -f $_.Exception.Message)
    }
}

function Get-KnownLockerProcesses([string]$installRoot, [bool]$oneDriveLike) {
    $names = @("onedrive.exe", "explorer.exe", "code.exe", "devenv.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "windowsterminal.exe")
    $parentPid = 0
    try {
        $selfProc = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $PID) -ErrorAction Stop
        $parentPid = [int]$selfProc.ParentProcessId
    } catch {
        $parentPid = 0
    }

    $candidates = New-Object System.Collections.Generic.List[object]
    $installRootLower = [string]$installRoot.ToLowerInvariant()
    $procFilter = @($names | ForEach-Object { "Name='{0}'" -f $_ }) -join " OR "
    try {
        $all = @(Get-CimInstance Win32_Process -Filter $procFilter -ErrorAction Stop)
    } catch {
        return @()
    }

    foreach ($proc in $all) {
        $procId = [int]$proc.ProcessId
        if ($procId -eq $PID -or ($parentPid -gt 0 -and $procId -eq $parentPid)) { continue }
        $name = [string]$proc.Name
        $cmd = [string]$proc.CommandLine
        $isMatch = $false
        $reason = ""
        if (-not [string]::IsNullOrWhiteSpace($cmd) -and $cmd.ToLowerInvariant().Contains($installRootLower)) {
            $isMatch = $true
            $reason = "CommandLineContainsInstallRoot"
        } elseif ($oneDriveLike -and ($name -ieq "OneDrive.exe" -or $name -ieq "explorer.exe")) {
            $isMatch = $true
            $reason = "OneDriveLikePathLocker"
        }
        if ($isMatch) {
            $candidates.Add([pscustomobject]@{
                ProcessId = $procId
                Name = $name
                CommandLine = $cmd
                Reason = $reason
            })
        }
    }
    return @($candidates | Sort-Object ProcessId -Unique)
}

function Stop-KnownLockerProcesses([object[]]$candidates, $ui) {
    $result = [ordered]@{
        Stopped = @()
        Failed  = @()
    }
    foreach ($proc in @($candidates)) {
        if (-not $proc) { continue }
        $pid = [int]$proc.ProcessId
        $name = [string]$proc.Name
        if ($script:IsDryRun) {
            Add-UninstallDetail $ui ("WhatIf: would stop locker PID={0} Name={1}" -f $pid, $name)
            continue
        }
        $stopped = $false
        foreach ($delay in @(120, 300, 600)) {
            try {
                Stop-Process -Id $pid -Force -ErrorAction Stop
                $stopped = $true
                break
            } catch {
                Start-Sleep -Milliseconds $delay
            }
        }
        if ($stopped) {
            $result.Stopped += ("PID={0}|Name={1}" -f $pid, $name)
            Add-UninstallDetail $ui ("Stopped likely locker PID={0} Name={1}" -f $pid, $name)
        } else {
            $result.Failed += ("PID={0}|Name={1}" -f $pid, $name)
            Add-UninstallDetail $ui ("Failed to stop likely locker PID={0} Name={1}" -f $pid, $name)
        }
    }
    return [pscustomobject]$result
}

function Try-RenamePathForCleanup([string]$path, $ui) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) { return "" }
    try {
        $parent = Split-Path -Path $path -Parent
        $leaf = Split-Path -Path $path -Leaf
        $renamedLeaf = "{0}._removing_{1}" -f $leaf, (Get-Date -Format "yyyyMMddHHmmss")
        $renamedPath = Join-Path $parent $renamedLeaf
        Rename-Item -LiteralPath $path -NewName $renamedLeaf -ErrorAction Stop
        Add-UninstallDetail $ui ("Rename fallback succeeded: {0} -> {1}" -f $path, $renamedPath)
        $script:UninstallReport.RenameFallbackUsed = $true
        $script:UninstallReport.RenameFallbackPath = $renamedPath
        return $renamedPath
    } catch {
        Add-UninstallDetail $ui ("Rename fallback failed for {0}: {1}" -f $path, $_.Exception.Message)
        return ""
    }
}

function Schedule-PathRemovalAtReboot([string]$path, $ui) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) { return $false }
    try {
        $ok = [TAGNativeFileOps]::MoveFileEx([string]$path, $null, [int]$script:MoveFileDelayUntilReboot)
        if ($ok) {
            Add-UninstallDetail $ui ("Deferred cleanup scheduled for reboot: {0}" -f $path)
            $script:UninstallReport.DeferredCleanupScheduled = $true
            $script:UninstallReport.DeferredCleanupPath = [string]$path
            return $true
        }
        $winErr = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Add-UninstallDetail $ui ("Deferred cleanup scheduling failed for {0} (Win32={1})" -f $path, $winErr)
    } catch {
        Add-UninstallDetail $ui ("Deferred cleanup scheduling failed for {0}: {1}" -f $path, $_.Exception.Message)
    }
    return $false
}

function Invoke-UninstallRetryGuidance($ui, [string]$installRoot, [string]$lockDiagnostics) {
    if (-not $ui -or -not $ui.Form -or $ui.Form.IsDisposed) { return $false }
    $ui.State.NextClicked = $false
    $ui.State.Cancelled = $false
    $ui.Stepper.Text = "Step 3 of 4 - Removal blocked"
    $ui.Label.Text = "Cleanup is blocked by file locks."
    $ui.Meta.Text = "Pause OneDrive sync and close File Explorer/editor terminals that reference this folder, then click Retry."
    Set-UninstallUiLayout -ui $ui -showProgress:$true
    Add-UninstallDetail $ui ("Retry guidance lock diagnostics: {0}" -f [string]$lockDiagnostics)
    $ui.NextButton.Visible = $true
    $ui.NextButton.Enabled = $true
    $ui.NextButton.Text = "Retry"
    $ui.CancelButton.Visible = $true
    $ui.CancelButton.Enabled = $true
    $ui.CancelButton.Text = "Skip"
    $ui.BackButton.Visible = $false
    $ui.Form.AcceptButton = $ui.NextButton
    $ui.Form.CancelButton = $ui.CancelButton

    while (-not $ui.Form.IsDisposed) {
        if ($ui.State.Cancelled) { return $false }
        if ($ui.State.NextClicked) { return $true }
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 60
    }
    return $false
}

function Invoke-UninstallHealthCheck([string]$installRoot, [hashtable]$shortcutMap) {
    $status = [ordered]@{
        InstallRootExists = [bool](Test-Path -LiteralPath $installRoot)
        MainShortcutExists = [bool](Test-Path -LiteralPath ([string]$shortcutMap.MainShortcut))
        UninstallShortcutExists = [bool](Test-Path -LiteralPath ([string]$shortcutMap.UninstallShortcut))
        DesktopShortcutExists = [bool](Test-Path -LiteralPath ([string]$shortcutMap.DesktopShortcut))
        StartupShortcutExists = [bool](Test-Path -LiteralPath ([string]$shortcutMap.StartupShortcut))
        ProcessLockCount = 0
        Healthy = $true
    }
    try {
        $lockers = @(Get-TrackedProcessCandidates -installRoot $installRoot)
        $status.ProcessLockCount = $lockers.Count
    } catch {
        $status.ProcessLockCount = 0
    }
    $status.Healthy = (-not $status.MainShortcutExists) -and
        (-not $status.UninstallShortcutExists) -and
        (-not $status.DesktopShortcutExists) -and
        (-not $status.StartupShortcutExists) -and
        ($status.ProcessLockCount -eq 0)
    return [pscustomobject]$status
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

        if ($isInstallRoot) {
            $renamedPath = Try-RenamePathForCleanup -path $path -ui $ui
            if (-not [string]::IsNullOrWhiteSpace($renamedPath)) {
                try {
                    Remove-Item -LiteralPath $renamedPath -Recurse -Force -ErrorAction Stop
                } catch {
                    $lastErrorMessage = [string]$_.Exception.Message
                    try {
                        & cmd.exe /c "rmdir /s /q `"$renamedPath`"" | Out-Null
                    } catch {
                        $null = $_
                    }
                }
                if (-not (Test-Path -LiteralPath $renamedPath)) {
                    Add-UninstallDetail $ui ("Removed {0} after rename fallback: {1}" -f $label, $renamedPath)
                    return $true
                }
                $path = $renamedPath
            }
            $null = Schedule-PathRemovalAtReboot -path $path -ui $ui
        }

        $script:DeleteFailureHints[$label] = [string]$lastErrorMessage
        $script:UninstallReport.ResidualPaths = @(Get-ResidualPathSnapshot -path $path -maxItems 40)
        $script:UninstallReport.ResidualReason = Get-LockReasonCategory -hint $lastErrorMessage
        Add-UninstallDetail $ui ("Residual reason classification: {0}" -f [string]$script:UninstallReport.ResidualReason)
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
    $wizardDryRunSummary = ""
    $forceCloseKnownLockers = $false
    while ($true) {
        $effectivePolicy = Get-EffectiveAppDataPolicy -SilentMode:$Silent -RemoveAppDataSwitch:$RemoveAppData -RequestedPolicy $AppDataPolicy
        if ($effectivePolicy -eq "Prompt" -and $Silent) {
            $effectivePolicy = "Keep"
        }
        $cycleDryRunFromWizard = $false

        $stepOneMessage = "Verify uninstall target and options."
        $stepOneMeta = "Confirm the target path and local data preference."
        if (-not [string]::IsNullOrWhiteSpace($wizardDryRunSummary)) {
            $stepOneMessage = "Dry run completed successfully."
            $stepOneMeta = $wizardDryRunSummary
        }
        Set-UninstallProgress $ui 5 "Step 1 of 4 - Verify" $stepOneMessage $stepOneMeta
        if ($oneDrivePathInfo.IsOneDriveLike) {
            Add-UninstallDetail $ui ("OneDrive advisory: sync/file-provider locks can delay cleanup. Signals={0}" -f $oneDrivePathInfo.Summary)
        }

        if ($ui -and $ui.Form -and -not $ui.Form.IsDisposed) {
            Prepare-UninstallWizardStep1 -ui $ui -resolvedInstallRoot $resolvedInstallRoot -effectivePolicy $effectivePolicy -dryRunChecked ([bool]$script:IsDryRun) -forceCloseKnownLockersChecked:$forceCloseKnownLockers
            if (-not [string]::IsNullOrWhiteSpace($wizardDryRunSummary)) {
                $ui.OptionsPrompt.Text = "Dry run completed successfully. Review options and click Next to continue."
            }
            Add-UninstallDetail $ui ("Ready to remove app files from: {0}" -f $resolvedInstallRoot)
            Add-UninstallDetail $ui "Next step will stop running app processes and begin file cleanup."

            $choice = Wait-UninstallWizardAction $ui
            if ($choice -eq "Cancel") {
                Complete-Uninstall -ExitCode $script:ExitCodes.UserCancelled -Result "Cancelled" -Summary "Uninstall cancelled by user." -Ui $ui
            }
            $wizardDryRunSummary = ""
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
            if ($ui.ForceCloseLockersCheck) {
                $forceCloseKnownLockers = [bool]$ui.ForceCloseLockersCheck.Checked
                $script:UninstallReport.ForceCloseKnownLockers = $forceCloseKnownLockers
                if ($forceCloseKnownLockers) {
                    Add-UninstallDetail $ui "Force-close likely lockers is enabled."
                }
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
                    $wizardDryRunSummary = ("Dry run complete. Planned uninstall root: {0}. AppData policy: {1}." -f $resolvedInstallRoot, $effectivePolicy)
                    Add-UninstallDetail $ui $wizardDryRunSummary
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

        $knownLockers = @(Get-KnownLockerProcesses -installRoot $resolvedInstallRoot -oneDriveLike ([bool]$oneDrivePathInfo.IsOneDriveLike))
        $script:UninstallReport.KnownLockerCandidates = @($knownLockers | ForEach-Object { "PID={0}|Name={1}|Reason={2}" -f $_.ProcessId, $_.Name, $_.Reason })
        if ($knownLockers.Count -gt 0) {
            Add-UninstallDetail $ui ("Known locker candidates: {0}" -f ($script:UninstallReport.KnownLockerCandidates -join " || "))
        }
        if ($forceCloseKnownLockers -and $knownLockers.Count -gt 0) {
            $lockerStopResult = Stop-KnownLockerProcesses -candidates $knownLockers -ui $ui
            $script:UninstallReport.KnownLockersStopped = @($lockerStopResult.Stopped)
            $script:UninstallReport.KnownLockerStopFailures = @($lockerStopResult.Failed)
        }

        Write-UninstallPhaseMarker -installRoot $resolvedInstallRoot -policy $effectivePolicy -removeAppData:$removeAppDataRequested -ui $ui

        Set-UninstallProgress $ui 48 "Step 3 of 4 - Removing files" "Removing app files..." ""
        $removedInstallRoot = Remove-PathWithRetry -path $resolvedInstallRoot -label "install root" -maxAttempts 18 -ui $ui -basePercent 48
        if (-not $removedInstallRoot -and -not $Silent -and -not $script:IsDryRun) {
            $lockDiagBeforeRetry = Get-PathLockDiagnostics -installRoot $resolvedInstallRoot
            $doRetry = Invoke-UninstallRetryGuidance -ui $ui -installRoot $resolvedInstallRoot -lockDiagnostics $lockDiagBeforeRetry
            if ($doRetry) {
                if ($forceCloseKnownLockers) {
                    $retryLockers = @(Get-KnownLockerProcesses -installRoot $resolvedInstallRoot -oneDriveLike ([bool]$oneDrivePathInfo.IsOneDriveLike))
                    if ($retryLockers.Count -gt 0) {
                        $retryStopResult = Stop-KnownLockerProcesses -candidates $retryLockers -ui $ui
                        $script:UninstallReport.KnownLockersStopped += @($retryStopResult.Stopped)
                        $script:UninstallReport.KnownLockerStopFailures += @($retryStopResult.Failed)
                    }
                }
                $removedInstallRoot = Remove-PathWithRetry -path $resolvedInstallRoot -label "install root" -maxAttempts 6 -ui $ui -basePercent 58
            } else {
                Add-UninstallDetail $ui "User skipped retry guidance step."
            }
        }
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
            if ($script:UninstallReport.ResidualPaths.Count -gt 0) {
                Add-UninstallDetail $ui ("Residual paths detected: {0}" -f [int]$script:UninstallReport.ResidualPaths.Count)
            }
        }

        Set-UninstallProgress $ui 96 "Step 4 of 4 - Verify" "Running uninstall health checks..." ""
        $finalShortcutMap = Get-ShortcutMap
        $health = Invoke-UninstallHealthCheck -installRoot $resolvedInstallRoot -shortcutMap $finalShortcutMap
        $script:UninstallReport.HealthCheck = $health
        Add-UninstallDetail $ui ("Health check: InstallRootExists={0}; StartupShortcutExists={1}; ProcessLockCount={2}" -f $health.InstallRootExists, $health.StartupShortcutExists, $health.ProcessLockCount)

        Set-UninstallProgress $ui 100 "Step 4 of 4 - Complete" "Finalizing uninstall..." ""
        Start-Sleep -Milliseconds 300

        if ($script:IsDryRun) {
            if ($cycleDryRunFromWizard -and $ui -and $ui.Form -and -not $ui.Form.IsDisposed) {
                $wizardDryRunSummary = ("Dry run complete. Planned uninstall root: {0}. AppData policy: {1}." -f $resolvedInstallRoot, $effectivePolicy)
                Add-UninstallDetail $ui $wizardDryRunSummary
                Add-UninstallDetail $ui "Returned to Step 1. Uncheck dry run to perform actual uninstall."
                $script:IsDryRun = $false
                $script:UninstallReport.DryRun = $false
                continue
            }
            Complete-Uninstall -ExitCode $script:ExitCodes.Success -Result "DryRun" -Summary ("Dry run complete. Planned uninstall root: {0}. AppData policy: {1}." -f $resolvedInstallRoot, $effectivePolicy) -NotifyUser:(-not $Silent) -Icon ([System.Windows.Forms.MessageBoxIcon]::Information) -Title "Uninstall dry run complete" -Ui $ui
        }

        if ($allGood -and [bool]$health.Healthy -and -not [bool]$script:UninstallReport.DeferredCleanupScheduled) {
            Complete-Uninstall -ExitCode $script:ExitCodes.Success -Result "Completed" -Summary "Uninstall completed successfully." -NotifyUser:(-not $Silent) -Icon ([System.Windows.Forms.MessageBoxIcon]::Information) -Title "Uninstall complete" -Ui $ui
        }

        $partialSummary = "Uninstall completed with warnings. Some files could not be removed."
        if ([bool]$script:UninstallReport.OneDrivePathLike -or ([string]$script:UninstallReport.LockDiagnostics -match 'OneDrivePathLike=True')) {
            $partialSummary += " OneDrive sync or file-provider locks may be preventing removal."
        }
        if ([bool]$script:UninstallReport.DeferredCleanupScheduled -and -not [string]::IsNullOrWhiteSpace([string]$script:UninstallReport.DeferredCleanupPath)) {
            $partialSummary += (" Deferred cleanup is scheduled at next reboot for: {0}." -f [string]$script:UninstallReport.DeferredCleanupPath)
        }
        if (-not [bool]$health.Healthy) {
            $partialSummary += " Final health checks found remaining entry points or process locks."
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
