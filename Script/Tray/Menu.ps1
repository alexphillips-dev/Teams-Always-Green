# --- Tray icon + context menu (build + handlers) ---
$contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
$script:TrayMenu = $contextMenu
$contextMenu.ShowItemToolTips = $false
$script:TrayMenuOpening = $false
$script:TrayTooltipDelayMs = 900
$script:TrayMenuToolTip = New-Object System.Windows.Forms.ToolTip
$script:TrayMenuToolTip.InitialDelay = $script:TrayTooltipDelayMs
$script:TrayMenuToolTip.ReshowDelay = 400
$script:TrayMenuToolTip.AutoPopDelay = 8000
$script:TrayMenuToolTip.ShowAlways = $true
$script:TrayTooltipPendingText = $null
$script:TrayTooltipTimer = New-Object System.Windows.Forms.Timer
$script:TrayTooltipTimer.Interval = $script:TrayTooltipDelayMs
$script:TrayTooltipTimer.Add_Tick({
    $script:TrayTooltipTimer.Stop()
    if ([string]::IsNullOrWhiteSpace($script:TrayTooltipPendingText)) { return }
    try {
        $pos = [System.Windows.Forms.Cursor]::Position
        $pt = $contextMenu.PointToClient($pos)
        $script:TrayMenuToolTip.Show($script:TrayTooltipPendingText, $contextMenu, $pt)
    } catch { }
})

if (Get-Command Sync-SettingsReference -ErrorAction SilentlyContinue) {
    Sync-SettingsReference $script:Settings
}
if (-not $script:Settings) {
    $settingsVar = Get-Variable -Name settings -Scope Script -ErrorAction SilentlyContinue
    if ($settingsVar -and $settingsVar.Value) { $script:Settings = $settingsVar.Value }
}
if (-not $script:Settings) {
    $defaultVar = Get-Variable -Name defaultSettings -Scope Script -ErrorAction SilentlyContinue
    if ($defaultVar -and $defaultVar.Value) { $script:Settings = $defaultVar.Value }
}
if (-not $script:Settings) {
    $script:Settings = [pscustomobject]@{ IntervalSeconds = 60; LogLevel = "INFO"; ActiveProfile = "Default" }
}
try {
    Set-Variable -Name settings -Scope Script -Value $script:Settings -Force
} catch { }

function Set-MenuTooltip([System.Windows.Forms.ToolStripItem]$item, [string]$text) {
    if (-not $item) { return }
    $item.ToolTipText = $text
    $item.Add_MouseEnter({
        param($sender, $e)
        if ([string]::IsNullOrWhiteSpace($sender.ToolTipText)) { return }
        $script:TrayTooltipPendingText = $sender.ToolTipText
        $script:TrayTooltipTimer.Stop()
        $script:TrayTooltipTimer.Start()
    })
    $item.Add_MouseLeave({
        $script:TrayTooltipTimer.Stop()
        $script:TrayTooltipPendingText = $null
        try { $script:TrayMenuToolTip.Hide($contextMenu) } catch { }
    })
}

function Update-TrayLabels {
    $startLabel = if ($script:isRunning -or $script:isPaused) { (L "Stop") } else { (L "Start") }
    if ($startStopItem) { $startStopItem.Text = $startLabel }

    if ($toggleNowItem) { $toggleNowItem.Text = (L "Toggle Once") }

    $pauseLabel = if ($script:isPaused) { (L "Resume") } else { (L "Pause") }
    if ($pauseMenu) {
        $pauseMenu.Text = $pauseLabel
        $pauseMenu.ToolTipText = if ($script:isPaused) { (L "Resume toggling.") } else { (L "Pause toggling for a duration or until a time.") }
    }
    if ($script:pauseResumeItem) { $script:pauseResumeItem.Text = (L "Resume") }

    if ($runOnceNowItem) {
        if ($script:isRunning -or $script:isPaused) {
            $runOnceNowItem.Text = (L "Run Once (Next Cycle)")
            $runOnceNowItem.ToolTipText = (L "Queue one toggle on the next cycle.")
        } else {
            $runOnceNowItem.Text = (L "Run Once Now")
            $runOnceNowItem.ToolTipText = (L "Trigger one toggle immediately.")
        }
    }

    if ($script:safeModeActive) {
        if ($startStopItem) { $startStopItem.ToolTipText = (L "Safe Mode active. Reset Safe Mode to resume.") }
        if ($toggleNowItem) { $toggleNowItem.ToolTipText = (L "Safe Mode active. Reset Safe Mode to toggle.") }
    } else {
        if ($startStopItem) { $startStopItem.ToolTipText = (L "Start or stop automatic toggling.") }
        if ($toggleNowItem) { $toggleNowItem.ToolTipText = (L "Trigger a single toggle immediately.") }
    }
}

function Invoke-TrayAction([string]$name, [ScriptBlock]$action) {
    try {
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            Set-LastUserAction $name "Tray"
        }
        & $action
    } catch {
        $key = if ([string]::IsNullOrWhiteSpace($name)) { "TrayAction" } else { "TrayAction-$name" }
        Write-LogThrottled $key ("Tray action failed: {0}" -f $_.Exception.Message) "ERROR" 10
    }
}

$startStopItem = New-Object System.Windows.Forms.ToolStripMenuItem("Start")
Set-MenuTooltip $startStopItem (L "Start or stop automatic toggling.")
$startStopItem.Add_Click({
    Invoke-TrayAction "StartStop" {
        if ($script:isRunning -or $script:isPaused) {
            Stop-Toggling
        } else {
            Start-Toggling
        }
    }
})

$toggleNowItem = New-Object System.Windows.Forms.ToolStripMenuItem("Toggle Once")
Set-MenuTooltip $toggleNowItem (L "Trigger a single toggle immediately.")
$toggleNowItem.Add_Click({ Invoke-TrayAction "ToggleOnce" { Do-Toggle "manual" } })

$statusItem = New-Object System.Windows.Forms.ToolStripMenuItem("Status")
Set-MenuTooltip $statusItem (L "View current status details.")
$statusLineState = New-Object System.Windows.Forms.ToolStripMenuItem("Status: Stopped")
$statusLineState.Name = "StatusStateItem"
$statusLineInterval = New-Object System.Windows.Forms.ToolStripMenuItem("Interval: 60s")
$statusLineToggles = New-Object System.Windows.Forms.ToolStripMenuItem("Toggles: 0")
$statusLineLast = New-Object System.Windows.Forms.ToolStripMenuItem("Last: Never")
$statusLineNext = New-Object System.Windows.Forms.ToolStripMenuItem("Next: N/A")
$statusLinePauseUntil = New-Object System.Windows.Forms.ToolStripMenuItem("Paused Until: N/A")
$statusLineSchedule = New-Object System.Windows.Forms.ToolStripMenuItem("Schedule: Off")
$statusLineSafeMode = New-Object System.Windows.Forms.ToolStripMenuItem("Safe Mode: Off")

    $statusLineState.Enabled = $true
$statusLineInterval.Enabled = $true
$statusLineToggles.Enabled = $true
$statusLineLast.Enabled = $true
$statusLineNext.Enabled = $true
$statusLinePauseUntil.Enabled = $true
$statusLineSchedule.Enabled = $true
$statusLineSafeMode.Enabled = $true

    $statusItem.DropDownItems.AddRange(@(
        $statusLineState,
        $statusLineInterval,
        $statusLineToggles,
        $statusLineLast,
        $statusLineNext,
        $statusLinePauseUntil,
        $statusLineSchedule,
        $statusLineSafeMode
    ))

$statusUpdateTimer = New-Object System.Windows.Forms.Timer
$statusUpdateTimer.Interval = 1000
$statusUpdateTimer.Add_Tick({
    Invoke-SafeTimerAction "StatusUpdateTimer" {
        if ($script:isShuttingDown -or $script:CleanupDone) { return }
        Request-StatusUpdate
    }
})

function Set-StatusUpdateTimerEnabled([bool]$enabled) {
    if ($enabled) {
        if (-not $statusUpdateTimer.Enabled) { $statusUpdateTimer.Start() }
    } elseif ($statusUpdateTimer.Enabled) {
        $statusUpdateTimer.Stop()
    }
}

$intervalMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Interval")
Set-MenuTooltip $intervalMenu (L "Change the toggle interval.")

function Set-Interval([int]$seconds) {
    $oldInterval = [int]$script:Settings.IntervalSeconds
    $script:Settings.IntervalSeconds = Normalize-IntervalSeconds $seconds
    Save-Settings $script:Settings
    $timer.Interval = $script:Settings.IntervalSeconds * 1000
    if ($script:isRunning) { Update-NextToggleTime }
    Request-StatusUpdate
    Write-Log "Interval changed from $oldInterval to $($script:Settings.IntervalSeconds) seconds (running=$script:isRunning)." "INFO" $null "Set-Interval"
}

function Prompt-CustomIntervalSeconds {
    $current = [string]$script:Settings.IntervalSeconds
$inputText = [Microsoft.VisualBasic.Interaction]::InputBox(
        "Enter custom interval in seconds (5-86400).",
        "Custom Interval",
        $current
    )
if ([string]::IsNullOrWhiteSpace($inputText)) { return $null }
    $value = 0
if (-not [int]::TryParse($inputText, [ref]$value)) { return $null }
    if ($value -le 0) { return $null }
    return (Normalize-IntervalSeconds $value)
}

function New-IntervalItem([string]$label, [int]$seconds) {
    $item = New-Object System.Windows.Forms.ToolStripMenuItem($label)
    $item.Tag = $seconds
    $item.CheckOnClick = $true
    $item.Add_Click({
        param($sender, $e)
        foreach ($i in $intervalMenu.DropDownItems | Where-Object { $_ -is [System.Windows.Forms.ToolStripMenuItem] }) { $i.Checked = $false }
        $sender.Checked = $true
        Invoke-TrayAction "Interval" { Set-Interval ([int]$sender.Tag) }
    })
    if ($script:Settings.IntervalSeconds -eq $seconds) { $item.Checked = $true }
    return $item
}

$intervalMenu.DropDownItems.AddRange(@(
    (New-IntervalItem "15 seconds" 15),
    (New-IntervalItem "30 seconds" 30),
    (New-IntervalItem "60 seconds" 60),
    (New-IntervalItem "2 minutes" 120),
    (New-IntervalItem "5 minutes" 300)
))

$customIntervalItem = New-Object System.Windows.Forms.ToolStripMenuItem("Custom...")
$customIntervalItem.Add_Click({
    Invoke-TrayAction "IntervalCustom" {
        $value = Prompt-CustomIntervalSeconds
        if ($null -eq $value) {
            [System.Windows.Forms.MessageBox]::Show(
                "Please enter a valid number of seconds (5-86400).",
                "Invalid interval",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            return
        }
        foreach ($i in $intervalMenu.DropDownItems | Where-Object { $_ -is [System.Windows.Forms.ToolStripMenuItem] }) { $i.Checked = $false }
        Set-Interval $value
    }
})

$intervalMenu.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
$intervalMenu.DropDownItems.Add($customIntervalItem) | Out-Null

$pauseMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Pause")
Set-MenuTooltip $pauseMenu "Pause toggling for a duration or until a time."
$script:pauseResumeItem = $null

function Show-PauseUntilDialog {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Pause Until"
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.ClientSize = New-Object System.Drawing.Size(320, 140)

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Pause until:"
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point(12, 20)

    $picker = New-Object System.Windows.Forms.DateTimePicker
    $picker.Format = [System.Windows.Forms.DateTimePickerFormat]::Custom
    $picker.CustomFormat = "yyyy-MM-dd h:mm tt"
    $picker.ShowUpDown = $true
    $picker.Width = 200
    $picker.Location = New-Object System.Drawing.Point(100, 16)
    $picker.Value = (Get-Date).AddMinutes(15)

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Width = 80
    $okButton.Location = New-Object System.Drawing.Point(140, 80)
    $okButton.Add_Click({
        Pause-UntilDate $picker.Value
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })

 $contextMenu.Add_Opening({
     if ($script:TrayMenuOpening) { return }
     $script:TrayMenuOpening = $true
     try {
         if (Get-Command Update-TrayLabels -ErrorAction SilentlyContinue) { Update-TrayLabels }
         if (Get-Command Localize-MenuItems -ErrorAction SilentlyContinue) { Localize-MenuItems $contextMenu.Items }
         if ($updateProfilesMenu) { & $updateProfilesMenu }
     } finally {
         $script:TrayMenuOpening = $false
     }
 })

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Width = 80
    $cancelButton.Location = New-Object System.Drawing.Point(230, 80)
    $cancelButton.Add_Click({
        $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Close()
    })

    $form.Controls.Add($label)
    $form.Controls.Add($picker)
    $form.Controls.Add($okButton)
    $form.Controls.Add($cancelButton)
    Update-ThemePreference
    Apply-ThemeToControl $form $script:ThemePalette $script:UseDarkTheme
    $form.ShowDialog() | Out-Null
}

function Rebuild-PauseMenu {
    $pauseMenu.DropDownItems.Clear()
    foreach ($mins in Get-PauseDurations) {
        $item = New-Object System.Windows.Forms.ToolStripMenuItem("$mins minutes")
        $item.Tag = $mins
        $item.Add_Click({
            param($sender, $e)
            Invoke-TrayAction "Pause" { Pause-Toggling ([int]$sender.Tag) }
        })
        $pauseMenu.DropDownItems.Add($item) | Out-Null
    }
    $script:pauseUntilItem = New-Object System.Windows.Forms.ToolStripMenuItem((L "Pause until..."))
    $script:pauseUntilItem.Add_Click({
        Invoke-TrayAction "PauseUntil" { Show-PauseUntilDialog }
    })
    $pauseMenu.DropDownItems.Add($script:pauseUntilItem) | Out-Null
    $pauseMenu.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
    $script:pauseResumeItem = New-Object System.Windows.Forms.ToolStripMenuItem((L "Resume"))
    $script:pauseResumeItem.Enabled = $false
    $script:pauseResumeItem.Add_Click({
        Invoke-TrayAction "Resume" {
            if ($script:isPaused) {
                Start-Toggling
            }
        }
    })
    $pauseMenu.DropDownItems.Add($script:pauseResumeItem) | Out-Null
}

Rebuild-PauseMenu

$resetCountersItem = New-Object System.Windows.Forms.ToolStripMenuItem("Reset Counters")
$resetCountersItem.Add_Click({
    $script:tickCount = 0
    $script:lastToggleTime = $null
    Save-Stats
    Request-StatusUpdate
    Write-Log "Counters reset." "INFO" $null "Reset-Counters"
})

$resetSafeModeItem = New-Object System.Windows.Forms.ToolStripMenuItem("Reset Safe Mode")
$resetSafeModeItem.Visible = $false
$resetSafeModeItem.Add_Click({ Reset-SafeMode })

$recoverNowItem = New-Object System.Windows.Forms.ToolStripMenuItem("Recover Now")
$recoverNowItem.Visible = $false
$recoverNowItem.Add_Click({ Recover-Now })

$logLevelMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Log Level")
$logLevelItems = @("DEBUG", "INFO", "WARN", "ERROR", "FATAL")
foreach ($level in $logLevelItems) {
    $levelItem = New-Object System.Windows.Forms.ToolStripMenuItem($level)
    $levelItem.CheckOnClick = $true
    $levelItem.Add_Click({
        param($sender, $e)
        Set-LogLevel $sender.Text "tray"
    })
    $logLevelMenu.DropDownItems.Add($levelItem) | Out-Null
}

$script:openSettingsItem = $script:openSettingsItem
if (-not $script:openSettingsItem) {
    $script:openSettingsItem = New-Object System.Windows.Forms.ToolStripMenuItem("Settings...")
    Set-MenuTooltip $script:openSettingsItem (L "Open the settings window.")
    $script:openSettingsItem.Add_Click({
        Invoke-TrayAction "Settings" {
            Write-Log "Tray action: Open Settings" "DEBUG" $null "Tray-Action"
            Show-SettingsDialog
        }
    })
}
$openSettingsItem = $script:openSettingsItem

$script:openLogsFolderItem = $script:openLogsFolderItem
if (-not $script:openLogsFolderItem) {
    $script:openLogsFolderItem = New-Object System.Windows.Forms.ToolStripMenuItem("Open Logs Folder")
    Set-MenuTooltip $script:openLogsFolderItem (L "Open the Logs folder.")
    $script:openLogsFolderItem.Add_Click({
        Invoke-TrayAction "OpenLogsFolder" {
            try {
                if (-not (Test-Path $script:LogDirectory)) {
                    Ensure-Directory $script:LogDirectory "Logs" | Out-Null
                }
                Start-Process -FilePath explorer.exe -ArgumentList ("`"{0}`"" -f $script:LogDirectory)
                Write-Log "Tray action: Open Logs Folder" "DEBUG" $null "Tray-Action"
            } catch {
                Write-Log "Failed to open Logs folder." "ERROR" $_.Exception "Tray-Action"
            }
        }
    })
}
$openLogsFolderItem = $script:openLogsFolderItem

$script:openSettingsFolderItem = $script:openSettingsFolderItem
if (-not $script:openSettingsFolderItem) {
    $script:openSettingsFolderItem = New-Object System.Windows.Forms.ToolStripMenuItem("Open Settings Folder")
    $script:openSettingsFolderItem.Add_Click({
        try {
            if (-not (Test-Path $script:SettingsDirectory)) {
                Ensure-Directory $script:SettingsDirectory "Settings" | Out-Null
            }
            Start-Process -FilePath explorer.exe -ArgumentList ("`"{0}`"" -f $script:SettingsDirectory)
            Write-Log "Tray action: Open Settings Folder" "DEBUG" $null "Tray-Action"
        } catch {
            Write-Log "Failed to open Settings folder." "ERROR" $_.Exception "Tray-Action"
        }
    })
}
$openSettingsFolderItem = $script:openSettingsFolderItem

$script:logsMenu = $script:logsMenu
if (-not $script:logsMenu) {
    $script:logsMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Logs")
    Set-MenuTooltip $script:logsMenu (L "Log tools and log level.")
}
$logsMenu = $script:logsMenu

$script:clearLogItem = $script:clearLogItem
if (-not $script:clearLogItem) {
    $script:clearLogItem = New-Object System.Windows.Forms.ToolStripMenuItem("Clear Log")
    $script:clearLogItem.Add_Click({
        Invoke-TrayAction "ClearLog" {
            $result = [System.Windows.Forms.MessageBox]::Show(
                "Clear the log file now?",
                "Clear Log",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($result -ne [System.Windows.Forms.DialogResult]::Yes) {
                Write-Log "Clear log canceled." "INFO" $null "Clear-Log"
                return
            }
            try {
                Clear-LogFile
            } catch {
                Write-Log "Failed to clear log file." "ERROR" $_.Exception "Clear-Log"
            }
        }
    })
}
$clearLogItem = $script:clearLogItem

$viewLogItem = New-Object System.Windows.Forms.ToolStripMenuItem("View Log")
$viewLogItem.Add_Click({
    try {
        if (-not (Test-Path $logPath)) {
            "" | Set-Content -Path $logPath -Encoding UTF8
        }
        Start-Process notepad.exe $logPath
    } catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to open log file.`n$($_.Exception.Message)",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        Write-Log "Failed to open log file." "ERROR" $_.Exception "View-Log"
    }
})

$viewLogTailItem = New-Object System.Windows.Forms.ToolStripMenuItem("View Log (Tail)")
$viewLogTailItem.Add_Click({
    Show-LogTailDialog
})

if ($logsMenu.DropDownItems) { $logsMenu.DropDownItems.Clear() }
$logsMenu.DropDownItems.Add($viewLogItem) | Out-Null
$logsMenu.DropDownItems.Add($viewLogTailItem) | Out-Null
$logsMenu.DropDownItems.Add($logLevelMenu) | Out-Null
$logsMenu.DropDownItems.Add($clearLogItem) | Out-Null
$logsMenu.DropDownItems.Add($openLogsFolderItem) | Out-Null

$quickSettingsMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Quick Options")
Set-MenuTooltip $quickSettingsMenu (L "Quick toggles for common settings.")
$quickStartOnLaunchItem = New-Object System.Windows.Forms.ToolStripMenuItem("Start on Launch")
$quickStartOnLaunchItem.CheckOnClick = $true
$quickStartOnLaunchItem.Checked = [bool]$script:Settings.StartOnLaunch
$quickStartOnLaunchItem.Add_Click({
    if ($null -ne $applyStartOnLaunch) {
        & $applyStartOnLaunch $quickStartOnLaunchItem.Checked
    }
})

$quickRunOnceOnLaunchItem = New-Object System.Windows.Forms.ToolStripMenuItem("Run Once on Launch")
$quickRunOnceOnLaunchItem.CheckOnClick = $true
$quickRunOnceOnLaunchItem.Checked = [bool]$script:Settings.RunOnceOnLaunch
$quickRunOnceOnLaunchItem.Add_Click({
    if ($null -ne $applyRunOnceOnLaunch) {
        & $applyRunOnceOnLaunch $quickRunOnceOnLaunchItem.Checked
    }
})

$quickQuietModeItem = New-Object System.Windows.Forms.ToolStripMenuItem("Quiet Mode")
$quickQuietModeItem.CheckOnClick = $true
$quickQuietModeItem.Checked = [bool]$script:Settings.QuietMode
$quickQuietModeItem.Add_Click({
    if ($null -ne $applyQuietMode) {
        & $applyQuietMode $quickQuietModeItem.Checked
    }
})
$script:QuickQuietModeItem = $quickQuietModeItem

$quickSettingsMenu.DropDownItems.Add($quickStartOnLaunchItem) | Out-Null
$quickSettingsMenu.DropDownItems.Add($quickRunOnceOnLaunchItem) | Out-Null
$quickSettingsMenu.DropDownItems.Add($quickQuietModeItem) | Out-Null

$updateQuickSettingsChecks = {
    $quickStartOnLaunchItem.Checked = [bool]$script:Settings.StartOnLaunch
    $quickRunOnceOnLaunchItem.Checked = [bool]$script:Settings.RunOnceOnLaunch
    $quickQuietModeItem.Checked = [bool]$script:Settings.QuietMode
}

$applyQuietMode = {
    param([bool]$value)
    $script:Settings.QuietMode = $value
    Save-Settings $script:Settings
    & $updateQuickSettingsChecks
}

$applyStartOnLaunch = {
    param([bool]$value)
    $script:Settings.StartOnLaunch = $value
    Save-Settings $script:Settings
    & $updateQuickSettingsChecks
}

$applyRunOnceOnLaunch = {
    param([bool]$value)
    $script:Settings.RunOnceOnLaunch = $value
    Save-Settings $script:Settings
    & $updateQuickSettingsChecks
}

$profilesMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Profiles")
Set-MenuTooltip $profilesMenu (L "Switch between profiles.")

function Switch-ToProfile([string]$name) {
    if (-not ((Get-ObjectKeys $script:Settings.Profiles) -contains $name)) { return }
    if (-not (Confirm-ProfileSwitch $name $script:Settings.Profiles[$name])) { return }
    $profile = Migrate-ProfileSnapshot $script:Settings.Profiles[$name]
    $validation = Test-ProfileSnapshot $profile
    if (-not $validation.Ok) {
        $lastGood = Get-ProfileLastGood $name
        if ($null -ne $lastGood) {
            Write-Log "Profile '$name' invalid; using last known good snapshot." "WARN" $null "Profiles"
            $profile = Migrate-ProfileSnapshot $lastGood
        } else {
            Write-Log ("Profile switch aborted: {0}" -f $validation.Message) "WARN" $null "Profiles"
            return
        }
    }
    $script:Settings.ActiveProfile = $name
    $script:Settings = Apply-ProfileSnapshot $script:Settings $profile
    Update-ProfileLastGood $name $profile
    Save-Settings $script:Settings
    Apply-SettingsRuntime
    if ($updateProfilesMenu) { & $updateProfilesMenu }
    Write-Log "Profile switched: $name" "INFO" $null "Profiles"
}

$updateProfilesMenu = {
    if (-not $profilesMenu) { return }
    $profilesMenu.DropDownItems.Clear()
    $names = @(Get-ObjectKeys $script:Settings.Profiles | Sort-Object)
    foreach ($name in $names) {
        $item = New-Object System.Windows.Forms.ToolStripMenuItem($name)
        $item.CheckOnClick = $true
        $item.Checked = ($script:Settings.ActiveProfile -eq $name)
        $item.Add_Click({
            param($sender, $e)
            Switch-ToProfile $sender.Text
        })
        $profilesMenu.DropDownItems.Add($item) | Out-Null
    }
    $profilesMenu.Enabled = ((@($names)).Count -gt 0)
}

& $updateProfilesMenu

$runOnceNowItem = New-Object System.Windows.Forms.ToolStripMenuItem("Run Once (Next Cycle)")
Set-MenuTooltip $runOnceNowItem (L "Queue one toggle on the next cycle (when stopped).")
$runOnceNowItem.Add_Click({
    Invoke-TrayAction "RunOnce" { Do-Toggle "manual" }
})
Update-TrayLabels
Localize-MenuItems $contextMenu.Items


