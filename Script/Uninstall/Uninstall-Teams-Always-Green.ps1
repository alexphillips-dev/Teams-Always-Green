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
    ScriptPath               = [string]$MyInvocation.MyCommand.Path
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

function Show-UninstallMessage([string]$message, [string]$title, [System.Windows.Forms.MessageBoxIcon]$icon) {
    if ($Silent) { return }
    [void][System.Windows.Forms.MessageBox]::Show(
        $message,
        $title,
        [System.Windows.Forms.MessageBoxButtons]::OK,
        $icon
    )
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
        $message = "{0}`n`nLog: {1}`nReport: {2}" -f $Summary, $script:UninstallLogPath, $script:UninstallReportPath
        Show-UninstallMessage -message $message -title $Title -icon $Icon
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

    $scriptPath = [string]$MyInvocation.MyCommand.Path
    if ([string]::IsNullOrWhiteSpace($scriptPath) -or -not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        Complete-Uninstall -ExitCode $script:ExitCodes.RelaunchFailed -Result "RelaunchFailed" -Summary "Unable to resolve uninstall script path for temp execution." -NotifyUser -Icon ([System.Windows.Forms.MessageBoxIcon]::Error) -Title "Uninstall failed"
    }

    $runnerPath = Join-Path $tempRoot ("TAG-UninstallRunner-{0}.ps1" -f [Guid]::NewGuid().ToString("N"))
    try {
        Copy-Item -Path $scriptPath -Destination $runnerPath -Force
    } catch {
        Complete-Uninstall -ExitCode $script:ExitCodes.RelaunchFailed -Result "RelaunchFailed" -Summary ("Unable to stage uninstall runner: {0}" -f $_.Exception.Message) -NotifyUser -Icon ([System.Windows.Forms.MessageBoxIcon]::Error) -Title "Uninstall failed"
    }

    $args = New-Object System.Collections.Generic.List[string]
    $args.Add("-NoProfile")
    $args.Add("-ExecutionPolicy")
    $args.Add("RemoteSigned")
    $args.Add("-File")
    $args.Add($runnerPath)
    $args.Add("-Relaunched")
    $args.Add("-InstallRoot")
    $args.Add($resolvedInstallRoot)
    $args.Add("-AppDataPolicy")
    $args.Add($AppDataPolicy)
    $args.Add("-Confirm:`$false")
    if ($Silent) { $args.Add("-Silent") }
    if ($RemoveAppData) { $args.Add("-RemoveAppData") }
    if ($script:IsDryRun) { $args.Add("-WhatIf") }

    $windowStyle = if ($Silent) { "Hidden" } else { "Normal" }
    try {
        Start-Process -FilePath (Get-PowerShellPath) -ArgumentList @($args.ToArray()) -WindowStyle $windowStyle -ErrorAction Stop | Out-Null
        exit 0
    } catch {
        Complete-Uninstall -ExitCode $script:ExitCodes.RelaunchFailed -Result "RelaunchFailed" -Summary ("Unable to launch temp uninstall runner: {0}" -f $_.Exception.Message) -NotifyUser -Icon ([System.Windows.Forms.MessageBoxIcon]::Error) -Title "Uninstall failed"
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
    $candidates = @(Get-TrackedProcessCandidates -installRoot $installRoot)
    if ($candidates.Count -eq 0) { return "none" }

    $items = New-Object System.Collections.Generic.List[string]
    foreach ($candidate in $candidates) {
        $cmd = [string]$candidate.CommandLine
        if ($cmd.Length -gt 160) { $cmd = $cmd.Substring(0, 160) + "..." }
        $items.Add(("PID={0};Name={1};Cmd={2}" -f $candidate.ProcessId, $candidate.Name, $cmd))
    }
    return ($items -join " || ")
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
    $scriptPath = [string]$MyInvocation.MyCommand.Path
    $resolvedInstallRoot = if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
        Get-InstallRootFromScriptPath $scriptPath
    } else {
        [string]$InstallRoot
    }

    Write-UninstallLog ("Uninstall started. Script={0}" -f $scriptPath)
    Write-UninstallLog ("InstallRoot parameter={0}" -f $resolvedInstallRoot)
    Write-UninstallLog ("Relaunched={0} Silent={1} DryRun={2}" -f $Relaunched, $Silent, $script:IsDryRun)

    $validation = Test-UninstallTargetPath $resolvedInstallRoot
    if (-not $validation.IsSafe) {
        Complete-Uninstall -ExitCode $script:ExitCodes.SafetyBlocked -Result "SafetyBlocked" -Summary ("Uninstall blocked for safety: {0}" -f $validation.Reason) -NotifyUser -Icon ([System.Windows.Forms.MessageBoxIcon]::Error) -Title "Uninstall blocked"
    }
    $resolvedInstallRoot = [string]$validation.Path
    $script:UninstallReport.InstallRoot = $resolvedInstallRoot

    Ensure-TempExecution -resolvedInstallRoot $resolvedInstallRoot

    $ui = New-UninstallProgressUi
    Set-UninstallProgress $ui 5 "Step 1 of 4 - Verify" "Verifying install path and options..." ("Install path: {0}" -f $resolvedInstallRoot)

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

    Complete-Uninstall -ExitCode $script:ExitCodes.PartialCleanup -Result "PartialCleanup" -Summary "Uninstall completed with warnings. Some files could not be removed." -NotifyUser -Icon ([System.Windows.Forms.MessageBoxIcon]::Warning) -Title "Uninstall completed with warnings"
} catch {
    $message = "Unhandled uninstall error: {0}" -f $_.Exception.Message
    Write-UninstallLog $message
    $script:UninstallReport.Result = "UnhandledError"
    $script:UninstallReport.ExitCode = $script:ExitCodes.UnhandledError
    $script:UninstallReport.Summary = $message
    Save-UninstallReport
    Show-UninstallMessage -message ("{0}`n`nLog: {1}`nReport: {2}" -f $message, $script:UninstallLogPath, $script:UninstallReportPath) -title "Uninstall failed" -icon ([System.Windows.Forms.MessageBoxIcon]::Error)
    exit $script:ExitCodes.UnhandledError
}
