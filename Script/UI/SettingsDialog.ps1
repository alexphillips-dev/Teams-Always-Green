# --- Settings dialog creation and event wiring (build/bind) ---
function Show-SettingsDialog {
    Write-Log "UI: Settings open requested." "DEBUG" $null "Settings-Dialog"
    try {
        $script:SettingsDialogStart = Get-Date
        $script:settings = Ensure-SettingsCollections $script:settings
        $script:settings = Normalize-Settings (Migrate-Settings $script:settings)
        $settings = $script:settings
        if ($script:SettingsForm -and -not $script:SettingsForm.IsDisposed) {
            $reuseOk = $true
            try {
                $settingsIconPath = Join-Path (Split-Path -Path $scriptPath -Parent) "Meta\\Icons\\Settings_Icon.ico"
                if (Test-Path $settingsIconPath) {
                    try { $script:SettingsForm.Icon = New-Object System.Drawing.Icon($settingsIconPath) } catch { }
                }
                Set-FormTaskbarIcon $script:SettingsForm $settingsIconPath
                if (-not $script:SettingsForm.Visible) {
                    $script:SettingsForm.Show()
                }
                $script:SettingsForm.WindowState = [System.Windows.Forms.FormWindowState]::Normal
                $script:SettingsForm.BringToFront()
                $script:SettingsForm.Activate()
                Set-SettingsDirty $false
                if ($script:ClearProfileDirtyIndicator) { & $script:ClearProfileDirtyIndicator }
                if ($script:UpdateSettingsBanner) { & $script:UpdateSettingsBanner }
            } catch {
                Write-Log "UI: Settings open failed while reusing existing form." "ERROR" $_.Exception "Settings-Dialog"
                try {
                    $script:SettingsForm.Dispose()
                } catch { }
                $script:SettingsForm = $null
                $reuseOk = $false
            }
            if ($reuseOk) { return }
        }
        $form = New-Object System.Windows.Forms.Form
        $script:SettingsForm = $form
        $form.SuspendLayout()
    $form.Text = "Settings"
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "Sizable"
    $form.MaximizeBox = $true
    $form.MinimizeBox = $true
    $form.ShowInTaskbar = $true
    $form.ShowIcon = $true
    $form.ClientSize = New-Object System.Drawing.Size(620, 540)
    $form.MinimumSize = New-Object System.Drawing.Size(520, 480)
    $settingsIconPath = Join-Path (Split-Path -Path $scriptPath -Parent) "Meta\\Icons\\Settings_Icon.ico"
    if (Test-Path $settingsIconPath) {
        $form.Icon = New-Object System.Drawing.Icon($settingsIconPath)
    } elseif ($notifyIcon -and $notifyIcon.Icon) {
        $form.Icon = $notifyIcon.Icon
    } elseif (Test-Path $iconPath) {
        $form.Icon = New-Object System.Drawing.Icon($iconPath)
    } else {
        $form.Icon = [System.Drawing.SystemIcons]::Application
    }
    Set-FormTaskbarIcon $form $settingsIconPath
    $form.Add_Shown({
        param($sender, $e)
        $shownIconPath = Join-Path (Split-Path -Path $scriptPath -Parent) "Meta\\Icons\\Settings_Icon.ico"
        Set-FormTaskbarIcon $sender $shownIconPath
    })

    $mainPanel = New-Object System.Windows.Forms.Panel
    $mainPanel.Dock = "Fill"
    $mainPanel.AutoScroll = $false
    $mainPanel.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)
    $script:MainPanel = $mainPanel
    $mainPanel.SuspendLayout()

    $tabControl = New-Object System.Windows.Forms.TabControl
    $tabControl.Dock = "Fill"
    $script:SettingsTabControl = $tabControl
    $script:ProfilesTabLoaded = $false
    $script:DiagnosticsTabLoaded = $false
    $script:LoggingTabLoaded = $false
    $script:AboutTabLoaded = $false
    $script:SettingsLayoutDirty = $true
    $tabControl.SuspendLayout()

    $script:GetSettingsTabKey = {
        param($tab)
        if (-not $tab) { return "" }
        if ($tab.Tag -is [string] -and -not [string]::IsNullOrWhiteSpace($tab.Tag)) { return [string]$tab.Tag }
        if (-not [string]::IsNullOrWhiteSpace($tab.Name)) { return [string]$tab.Name }
        return [string]$tab.Text
    }
    $script:GetSettingsTabPage = {
        param([string]$key)
        if (-not $script:SettingsTabControl -or [string]::IsNullOrWhiteSpace($key)) { return $null }
        return $script:SettingsTabControl.TabPages |
            Where-Object {
                (($_.Tag -is [string]) -and $_.Tag -eq $key) -or
                ($_.Name -eq $key) -or
                ($_.Text -eq $key)
            } |
            Select-Object -First 1
    }

    $toolTip = New-Object System.Windows.Forms.ToolTip
    $script:SettingsToolTip = $toolTip

    $statusBadgePanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $statusBadgePanel.FlowDirection = "LeftToRight"
    $statusBadgePanel.AutoSize = $true
    $statusBadgePanel.WrapContents = $false
    $statusBadgePanel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)
    $statusBadgePanel.Tag = "Status Badges"

    $newBadge = {
        param([string]$text)
        $badge = New-Object System.Windows.Forms.Label
        $badge.Text = $text
        $badge.AutoSize = $true
        $badge.Padding = New-Object System.Windows.Forms.Padding(6, 2, 6, 2)
        $badge.Margin = New-Object System.Windows.Forms.Padding(0, 0, 6, 0)
        $badge.BackColor = [System.Drawing.Color]::DimGray
        $badge.ForeColor = [System.Drawing.Color]::White
        $badge.Visible = $false
        return $badge
    }

    $badgeRunning = & $newBadge "Running"
    $badgePaused = & $newBadge "Paused"
    $badgeStopped = & $newBadge "Stopped"
    $badgeSchedule = & $newBadge "Schedule"
    $badgeDebug = & $newBadge "Debug"
    $badgeSafeMode = & $newBadge "Safe Mode"

    $statusBadgePanel.Controls.Add($badgeRunning) | Out-Null
    $statusBadgePanel.Controls.Add($badgePaused) | Out-Null
    $statusBadgePanel.Controls.Add($badgeStopped) | Out-Null
    $statusBadgePanel.Controls.Add($badgeSchedule) | Out-Null
    $statusBadgePanel.Controls.Add($badgeDebug) | Out-Null
    $statusBadgePanel.Controls.Add($badgeSafeMode) | Out-Null

    $script:SettingsStatusBadges = @{
        Running = $badgeRunning
        Paused = $badgePaused
        Stopped = $badgeStopped
        Schedule = $badgeSchedule
        Debug = $badgeDebug
        SafeMode = $badgeSafeMode
    }

    $statusGroup = New-Object System.Windows.Forms.GroupBox
    $statusGroup.Text = "Current Status"
    $statusGroup.Dock = "Top"
    $statusGroup.AutoSize = $true
    $statusGroup.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $statusGroup.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)
    $statusGroup.Tag = "Current Status"

    $statusLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $statusLayout.ColumnCount = 2
    $statusLayout.RowCount = 15
    $statusLayout.AutoSize = $true
    $statusLayout.Dock = "Top"
    $statusLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $statusLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Text = "Status"
    $statusLabel.AutoSize = $true
    $statusLabel.Anchor = "Left"

    $statusValue = New-Object System.Windows.Forms.Label
    $statusValue.Text = "N/A"
    $statusValue.AutoSize = $true
    $statusValue.Anchor = "Left"

    $nextLabel = New-Object System.Windows.Forms.Label
    $nextLabel.Text = "Next Toggle"
    $nextLabel.AutoSize = $true
    $nextLabel.Anchor = "Left"

    $nextValue = New-Object System.Windows.Forms.Label
    $nextValue.Text = "N/A"
    $nextValue.AutoSize = $true
    $nextValue.Anchor = "Left"

    $keyboardLabel = New-Object System.Windows.Forms.Label
    $keyboardLabel.Text = "Keyboard"
    $keyboardLabel.AutoSize = $true
    $keyboardLabel.Anchor = "Left"

    $keyboardValue = New-Object System.Windows.Forms.Label
    $keyboardValue.Text = "Caps:Off Num:Off Scroll:Off"
    $keyboardValue.AutoSize = $true
    $keyboardValue.Anchor = "Left"

    $uptimeLabel = New-Object System.Windows.Forms.Label
    $uptimeLabel.Text = "Uptime"
    $uptimeLabel.AutoSize = $true
    $uptimeLabel.Anchor = "Left"

    $uptimeValue = New-Object System.Windows.Forms.Label
    $uptimeValue.Text = "0m"
    $uptimeValue.AutoSize = $true
    $uptimeValue.Anchor = "Left"

    $lastToggleLabel = New-Object System.Windows.Forms.Label
    $lastToggleLabel.Text = "Last Toggle"
    $lastToggleLabel.AutoSize = $true
    $lastToggleLabel.Anchor = "Left"

    $lastToggleValue = New-Object System.Windows.Forms.Label
    $lastToggleValue.Text = "None"
    $lastToggleValue.AutoSize = $true
    $lastToggleValue.Anchor = "Left"

    $nextCountdownLabel = New-Object System.Windows.Forms.Label
    $nextCountdownLabel.Text = "Next Toggle In"
    $nextCountdownLabel.AutoSize = $true
    $nextCountdownLabel.Anchor = "Left"

    $nextCountdownValue = New-Object System.Windows.Forms.Label
    $nextCountdownValue.Text = "N/A"
    $nextCountdownValue.AutoSize = $true
    $nextCountdownValue.Anchor = "Left"

    $profileStatusLabel = New-Object System.Windows.Forms.Label
    $profileStatusLabel.Text = "Active Profile"
    $profileStatusLabel.AutoSize = $true
    $profileStatusLabel.Anchor = "Left"

    $profileStatusValue = New-Object System.Windows.Forms.Label
    $profileStatusValue.Text = "N/A"
    $profileStatusValue.AutoSize = $true
    $profileStatusValue.Anchor = "Left"

    $scheduleStatusLabel = New-Object System.Windows.Forms.Label
    $scheduleStatusLabel.Text = "Schedule Status"
    $scheduleStatusLabel.AutoSize = $true
    $scheduleStatusLabel.Anchor = "Left"

    $scheduleStatusValue = New-Object System.Windows.Forms.Label
    $scheduleStatusValue.Text = "Off"
    $scheduleStatusValue.AutoSize = $true
    $scheduleStatusValue.Anchor = "Left"

    $safeModeStatusLabel = New-Object System.Windows.Forms.Label
    $safeModeStatusLabel.Text = "Safe Mode"
    $safeModeStatusLabel.AutoSize = $true
    $safeModeStatusLabel.Anchor = "Left"

    $safeModeStatusValue = New-Object System.Windows.Forms.Label
    $safeModeStatusValue.Text = "Off"
    $safeModeStatusValue.AutoSize = $true
    $safeModeStatusValue.Anchor = "Left"

    $statusSpacer1 = New-Object System.Windows.Forms.Label
    $statusSpacer1.Text = ""
    $statusSpacer1.AutoSize = $false
    $statusSpacer1.Height = 8

    $statusSpacer2 = New-Object System.Windows.Forms.Label
    $statusSpacer2.Text = ""
    $statusSpacer2.AutoSize = $false
    $statusSpacer2.Height = 8

    $statusSpacer3 = New-Object System.Windows.Forms.Label
    $statusSpacer3.Text = ""
    $statusSpacer3.AutoSize = $false
    $statusSpacer3.Height = 8

    $statusSpacer4 = New-Object System.Windows.Forms.Label
    $statusSpacer4.Text = ""
    $statusSpacer4.AutoSize = $false
    $statusSpacer4.Height = 8

    $statusSpacer5 = New-Object System.Windows.Forms.Label
    $statusSpacer5.Text = ""
    $statusSpacer5.AutoSize = $false
    $statusSpacer5.Height = 8

    $statusSpacer6 = New-Object System.Windows.Forms.Label
    $statusSpacer6.Text = ""
    $statusSpacer6.AutoSize = $false
    $statusSpacer6.Height = 8

    $statusSpacer7 = New-Object System.Windows.Forms.Label
    $statusSpacer7.Text = ""
    $statusSpacer7.AutoSize = $false
    $statusSpacer7.Height = 8

    $statusLayout.Controls.Add($statusLabel, 0, 0)
    $statusLayout.Controls.Add($statusValue, 1, 0)
    $statusLayout.Controls.Add($statusSpacer1, 0, 1)
    $statusLayout.SetColumnSpan($statusSpacer1, 2)
    $statusLayout.Controls.Add($nextLabel, 0, 2)
    $statusLayout.Controls.Add($nextValue, 1, 2)
    $statusLayout.Controls.Add($statusSpacer2, 0, 3)
    $statusLayout.SetColumnSpan($statusSpacer2, 2)
    $statusLayout.Controls.Add($nextCountdownLabel, 0, 4)
    $statusLayout.Controls.Add($nextCountdownValue, 1, 4)
    $statusLayout.Controls.Add($statusSpacer3, 0, 5)
    $statusLayout.SetColumnSpan($statusSpacer3, 2)
    $statusLayout.Controls.Add($lastToggleLabel, 0, 6)
    $statusLayout.Controls.Add($lastToggleValue, 1, 6)
    $statusLayout.Controls.Add($statusSpacer4, 0, 7)
    $statusLayout.SetColumnSpan($statusSpacer4, 2)
    $statusLayout.Controls.Add($profileStatusLabel, 0, 8)
    $statusLayout.Controls.Add($profileStatusValue, 1, 8)
    $statusLayout.Controls.Add($statusSpacer5, 0, 9)
    $statusLayout.SetColumnSpan($statusSpacer5, 2)
    $statusLayout.Controls.Add($scheduleStatusLabel, 0, 10)
    $statusLayout.Controls.Add($scheduleStatusValue, 1, 10)
    $statusLayout.Controls.Add($statusSpacer6, 0, 11)
    $statusLayout.SetColumnSpan($statusSpacer6, 2)
    $statusLayout.Controls.Add($safeModeStatusLabel, 0, 12)
    $statusLayout.Controls.Add($safeModeStatusValue, 1, 12)
    $statusLayout.Controls.Add($statusSpacer7, 0, 13)
    $statusLayout.SetColumnSpan($statusSpacer7, 2)
    $statusLayout.Controls.Add($keyboardLabel, 0, 14)
    $statusLayout.Controls.Add($keyboardValue, 1, 14)
    $statusGroup.Controls.Add($statusLayout)

    $toggleGroup = New-Object System.Windows.Forms.GroupBox
    $toggleGroup.Text = "Toggle Counters"
    $toggleGroup.Dock = "Top"
    $toggleGroup.AutoSize = $true
    $toggleGroup.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $toggleGroup.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)
    $toggleGroup.Tag = "Toggle Counters"

    $toggleLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $toggleLayout.ColumnCount = 2
    $toggleLayout.RowCount = 2
    $toggleLayout.AutoSize = $true
    $toggleLayout.Dock = "Top"
    $toggleLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $toggleLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $toggleCurrentLabel = New-Object System.Windows.Forms.Label
    $toggleCurrentLabel.Text = "Current Toggles"
    $toggleCurrentLabel.AutoSize = $true
    $toggleCurrentLabel.Anchor = "Left"

    $toggleCurrentValue = New-Object System.Windows.Forms.Label
    $toggleCurrentValue.Text = "0"
    $toggleCurrentValue.AutoSize = $true
    $toggleCurrentValue.Anchor = "Left"

    $toggleLifetimeLabel = New-Object System.Windows.Forms.Label
    $toggleLifetimeLabel.Text = "Lifetime Toggles"
    $toggleLifetimeLabel.AutoSize = $true
    $toggleLifetimeLabel.Anchor = "Left"

    $toggleLifetimeValue = New-Object System.Windows.Forms.Label
    $toggleLifetimeValue.Text = "0"
    $toggleLifetimeValue.AutoSize = $true
    $toggleLifetimeValue.Anchor = "Left"

    $toggleLayout.Controls.Add($toggleCurrentLabel, 0, 0)
    $toggleLayout.Controls.Add($toggleCurrentValue, 1, 0)
    $toggleLayout.Controls.Add($toggleLifetimeLabel, 0, 1)
    $toggleLayout.Controls.Add($toggleLifetimeValue, 1, 1)
    $toggleGroup.Controls.Add($toggleLayout)

    $funStatsGroup = New-Object System.Windows.Forms.GroupBox
    $funStatsGroup.Text = "Fun Stats"
    $funStatsGroup.Dock = "Top"
    $funStatsGroup.AutoSize = $true
    $funStatsGroup.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $funStatsGroup.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)
    $funStatsGroup.Tag = "Fun Stats"

    $funStatsLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $funStatsLayout.ColumnCount = 2
    $funStatsLayout.RowCount = 6
    $funStatsLayout.AutoSize = $true
    $funStatsLayout.Dock = "Top"
    $funStatsLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $funStatsLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $funDailyLabel = New-Object System.Windows.Forms.Label
    $funDailyLabel.Text = "Today's Toggles"
    $funDailyLabel.AutoSize = $true
    $funDailyLabel.Anchor = "Left"

    $funDailyValue = New-Object System.Windows.Forms.Label
    $funDailyValue.Text = "0"
    $funDailyValue.AutoSize = $true
    $funDailyValue.Anchor = "Left"
    $script:SettingsFunDailyValue = $funDailyValue

    $funStreakCurrentLabel = New-Object System.Windows.Forms.Label
    $funStreakCurrentLabel.Text = "Current Streak"
    $funStreakCurrentLabel.AutoSize = $true
    $funStreakCurrentLabel.Anchor = "Left"

    $funStreakCurrentValue = New-Object System.Windows.Forms.Label
    $funStreakCurrentValue.Text = "0 days"
    $funStreakCurrentValue.AutoSize = $true
    $funStreakCurrentValue.Anchor = "Left"
    $script:SettingsFunStreakCurrentValue = $funStreakCurrentValue

    $funStreakBestLabel = New-Object System.Windows.Forms.Label
    $funStreakBestLabel.Text = "Best Streak"
    $funStreakBestLabel.AutoSize = $true
    $funStreakBestLabel.Anchor = "Left"

    $funStreakBestValue = New-Object System.Windows.Forms.Label
    $funStreakBestValue.Text = "0 days"
    $funStreakBestValue.AutoSize = $true
    $funStreakBestValue.Anchor = "Left"
    $script:SettingsFunStreakBestValue = $funStreakBestValue

    $funMostActiveLabel = New-Object System.Windows.Forms.Label
    $funMostActiveLabel.Text = "Most Active Hour"
    $funMostActiveLabel.AutoSize = $true
    $funMostActiveLabel.Anchor = "Left"

    $funMostActiveValue = New-Object System.Windows.Forms.Label
    $funMostActiveValue.Text = "N/A"
    $funMostActiveValue.AutoSize = $true
    $funMostActiveValue.Anchor = "Left"
    $script:SettingsFunMostActiveHourValue = $funMostActiveValue

    $funLongestPauseLabel = New-Object System.Windows.Forms.Label
    $funLongestPauseLabel.Text = "Longest Pause"
    $funLongestPauseLabel.AutoSize = $true
    $funLongestPauseLabel.Anchor = "Left"

    $funLongestPauseValue = New-Object System.Windows.Forms.Label
    $funLongestPauseValue.Text = "N/A"
    $funLongestPauseValue.AutoSize = $true
    $funLongestPauseValue.Anchor = "Left"
    $script:SettingsFunLongestPauseValue = $funLongestPauseValue

    $funTotalRunLabel = New-Object System.Windows.Forms.Label
    $funTotalRunLabel.Text = "Total Run Time"
    $funTotalRunLabel.AutoSize = $true
    $funTotalRunLabel.Anchor = "Left"

    $funTotalRunValue = New-Object System.Windows.Forms.Label
    $funTotalRunValue.Text = "0m"
    $funTotalRunValue.AutoSize = $true
    $funTotalRunValue.Anchor = "Left"
    $script:SettingsFunTotalRunValue = $funTotalRunValue

    $funStatsLayout.Controls.Add($funDailyLabel, 0, 0)
    $funStatsLayout.Controls.Add($funDailyValue, 1, 0)
    $funStatsLayout.Controls.Add($funStreakCurrentLabel, 0, 1)
    $funStatsLayout.Controls.Add($funStreakCurrentValue, 1, 1)
    $funStatsLayout.Controls.Add($funStreakBestLabel, 0, 2)
    $funStatsLayout.Controls.Add($funStreakBestValue, 1, 2)
    $funStatsLayout.Controls.Add($funMostActiveLabel, 0, 3)
    $funStatsLayout.Controls.Add($funMostActiveValue, 1, 3)
    $funStatsLayout.Controls.Add($funLongestPauseLabel, 0, 4)
    $funStatsLayout.Controls.Add($funLongestPauseValue, 1, 4)
    $funStatsLayout.Controls.Add($funTotalRunLabel, 0, 5)
    $funStatsLayout.Controls.Add($funTotalRunValue, 1, 5)
    $funStatsGroup.Controls.Add($funStatsLayout)

    $copyStatusButton = New-Object System.Windows.Forms.Button
    $copyStatusButton.Text = "Copy Status"
    $copyStatusButton.Width = 120
    $copyStatusButton.Tag = "Copy Status"
    $script:CopyStatusButton = $copyStatusButton
    $copyStatusButton.Add_Click({
        $ownerForm = $null
        if ($script:SettingsForm -and -not $script:SettingsForm.IsDisposed) {
            $ownerForm = $script:SettingsForm
        }
        $lines = @()
        $lines += "Teams Always Green - Status"
        $lines += "Status: $($script:SettingsStatusValue.Text)"
        $lines += "Next Toggle: $($script:SettingsNextValue.Text)"
        $lines += "Last Toggle: $($script:SettingsLastToggleValue.Text)"
        $lines += "Active Profile: $($script:SettingsProfileStatusValue.Text)"
        $lines += "Schedule: $($script:SettingsScheduleStatusValue.Text)"
        $lines += "Safe Mode: $($script:SettingsSafeModeStatusValue.Text)"
        $lines += "Keyboard: $($script:SettingsKeyboardValue.Text)"
        $lines += "Current Toggles: $($script:SettingsToggleCurrentValue.Text)"
        $lines += "Lifetime Toggles: $($script:SettingsToggleLifetimeValue.Text)"
        $lines += "Today's Toggles: $($script:SettingsFunDailyValue.Text)"
        $lines += "Current Streak: $($script:SettingsFunStreakCurrentValue.Text)"
        $lines += "Best Streak: $($script:SettingsFunStreakBestValue.Text)"
        $lines += "Most Active Hour: $($script:SettingsFunMostActiveHourValue.Text)"
        $lines += "Longest Pause: $($script:SettingsFunLongestPauseValue.Text)"
        $lines += "Total Run Time: $($script:SettingsFunTotalRunValue.Text)"
        $text = ($lines -join "`r`n")
        [System.Windows.Forms.Clipboard]::SetText($text)
        [System.Windows.Forms.MessageBox]::Show(
            $ownerForm,
            "Status copied to clipboard.",
            "Status",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        Write-Log "Status copied to clipboard." "INFO" $null "Status"
    })

    $copyStatusPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $copyStatusPanel.FlowDirection = "LeftToRight"
    $copyStatusPanel.AutoSize = $true
    $copyStatusPanel.WrapContents = $false
    $copyStatusPanel.Controls.Add($copyStatusButton) | Out-Null
    $copyStatusPanel.Tag = "Copy Status"

    $topPanel = New-Object System.Windows.Forms.Panel
    $topPanel.Dock = "Top"
    $topPanel.AutoSize = $true
    $topPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink

    $script:SettingsBannerPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $script:SettingsBannerPanel.FlowDirection = "LeftToRight"
    $script:SettingsBannerPanel.AutoSize = $true
    $script:SettingsBannerPanel.WrapContents = $false
    $script:SettingsBannerPanel.Dock = "Top"
    $script:SettingsBannerPanel.Padding = New-Object System.Windows.Forms.Padding(10, 6, 10, 6)
    $script:SettingsBannerPanel.Margin = New-Object System.Windows.Forms.Padding(8, 6, 8, 6)
    $script:SettingsBannerPanel.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $script:SettingsBannerPanel.Visible = $false

    $script:SettingsBannerLabel = New-Object System.Windows.Forms.Label
    $script:SettingsBannerLabel.AutoSize = $true
    $script:SettingsBannerLabel.ForeColor = [System.Drawing.Color]::Gold
    $script:SettingsBannerLabel.Margin = New-Object System.Windows.Forms.Padding(0, 2, 12, 0)

    $script:SettingsBannerRestoreButton = New-Object System.Windows.Forms.Button
    $script:SettingsBannerRestoreButton.Text = "Restore Defaults"
    $script:SettingsBannerRestoreButton.AutoSize = $true
    $script:SettingsBannerRestoreButton.Visible = $false
    $script:SettingsBannerRestoreButton.Add_Click({
        $choice = [System.Windows.Forms.MessageBox]::Show(
            "Restore defaults and exit minimal mode? This will overwrite current settings.",
            "Restore Defaults",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($choice -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        $restored = Copy-SettingsValue $defaultSettings
        $restored = Normalize-Settings (Migrate-Settings $restored)
        & $applySettingsToControls $restored
        $script:settings = $restored
        Save-SettingsImmediate $restored
        try {
            $state = Get-CrashState
            $state.Count = 0
            $state.LastCrash = $null
            $state.OverrideMinimalMode = $true
            Save-CrashState $state
        } catch { }
        $script:MinimalModeActive = $false
        $script:MinimalModeReason = $null
        $script:SettingsAutoCorrected = $false
        $script:SettingsAutoCorrectedMessage = $null
        if ($script:UpdateSettingsBanner) { & $script:UpdateSettingsBanner }
        Write-Log "Settings restored from banner (defaults applied)." "WARN" $null "Settings"
    })

    $script:SettingsBannerExitMinimalButton = New-Object System.Windows.Forms.Button
    $script:SettingsBannerExitMinimalButton.Text = "Exit Minimal Mode"
    $script:SettingsBannerExitMinimalButton.AutoSize = $true
    $script:SettingsBannerExitMinimalButton.Visible = $false
    $script:SettingsBannerExitMinimalButton.Add_Click({
        $choice = [System.Windows.Forms.MessageBox]::Show(
            "Exit minimal mode and resume normal startup? This does not reset settings.",
            "Exit Minimal Mode",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($choice -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        try {
            $state = Get-CrashState
            $state.Count = 0
            $state.LastCrash = $null
            $state.OverrideMinimalMode = $true
            Save-CrashState $state
        } catch { }
        $script:OverrideMinimalMode = $true
        $script:MinimalModeActive = $false
        $script:MinimalModeReason = $null
        if ($script:UpdateSettingsBanner) { & $script:UpdateSettingsBanner }
        Write-Log "Minimal mode cleared by user." "WARN" $null "Settings"
    })

    $script:SettingsBannerPanel.Controls.Add($script:SettingsBannerLabel) | Out-Null
    $script:SettingsBannerPanel.Controls.Add($script:SettingsBannerExitMinimalButton) | Out-Null
    $script:SettingsBannerPanel.Controls.Add($script:SettingsBannerRestoreButton) | Out-Null

    $script:UpdateSettingsBanner = {
        $lines = @()
        $autoCorrectVisible = $false
        $tamperVisible = $false
        if ($script:SettingsAutoCorrected) {
            $seen = $false
            if ($settings -and ($settings.PSObject.Properties.Name -contains "AutoCorrectedNoticeSeen")) {
                $seen = [bool]$settings.AutoCorrectedNoticeSeen
            }
            if (-not $seen) {
                if ([string]::IsNullOrWhiteSpace($script:SettingsAutoCorrectedMessage)) {
                    $lines += "Settings were auto-corrected for stability."
                } else {
                    $lines += $script:SettingsAutoCorrectedMessage
                }
                $autoCorrectVisible = $true
            }
        }
        if ($script:SettingsTampered) {
            $tamperSeen = $false
            if ($settings -and ($settings.PSObject.Properties.Name -contains "SettingsTamperNoticeSeen")) {
                $tamperSeen = [bool]$settings.SettingsTamperNoticeSeen
            }
            if (-not $tamperSeen) {
                if ([string]::IsNullOrWhiteSpace($script:SettingsTamperMessage)) {
                    $lines += "Settings file changed outside the app. Please review your settings."
                } else {
                    $lines += $script:SettingsTamperMessage
                }
                $tamperVisible = $true
            }
        }
        if ($script:MinimalModeActive) {
            $lines += "Minimal mode is active after repeated crashes."
        }
        if ($lines.Count -eq 0) {
            $script:SettingsBannerPanel.Visible = $false
            return
        }
        $script:SettingsBannerLabel.Text = ($lines -join " ")
        $script:SettingsBannerExitMinimalButton.Visible = [bool]$script:MinimalModeActive
        $script:SettingsBannerRestoreButton.Visible = [bool]$script:MinimalModeActive
        $script:SettingsBannerPanel.Visible = $true
        if ($autoCorrectVisible -and $settings -and ($settings.PSObject.Properties.Name -contains "AutoCorrectedNoticeSeen")) {
            try {
                $settings.AutoCorrectedNoticeSeen = $true
                $script:settings = $settings
                Save-SettingsImmediate $settings
                $script:SettingsAutoCorrected = $false
                $script:SettingsAutoCorrectedMessage = $null
            } catch { }
        }
        if ($tamperVisible -and $settings -and ($settings.PSObject.Properties.Name -contains "SettingsTamperNoticeSeen")) {
            try {
                $settings.SettingsTamperNoticeSeen = $true
                $script:settings = $settings
                Save-SettingsImmediate $settings
                $script:SettingsTampered = $false
                $script:SettingsTamperMessage = $null
            } catch { }
        }
    }

    $script:SettingsDirtyLabel = New-Object System.Windows.Forms.Label
    $script:SettingsDirtyLabel.Text = "Unsaved changes"
    $script:SettingsDirtyLabel.ForeColor = [System.Drawing.Color]::DarkOrange
    $script:SettingsDirtyLabel.AutoSize = $true
    $script:SettingsDirtyLabel.Margin = New-Object System.Windows.Forms.Padding(12, 6, 0, 0)
    $script:SettingsDirtyLabel.Visible = $false
    $script:SettingsDirtyLabel.Dock = "Top"

    $script:SettingsRecoveredLabel = New-Object System.Windows.Forms.Label
    $script:SettingsRecoveredLabel.Text = "Recovered settings from last known good snapshot. Please review."
    $script:SettingsRecoveredLabel.ForeColor = [System.Drawing.Color]::Gold
    $script:SettingsRecoveredLabel.AutoSize = $true
    $script:SettingsRecoveredLabel.Margin = New-Object System.Windows.Forms.Padding(12, 0, 0, 6)
    $script:SettingsRecoveredLabel.Visible = $script:SettingsRecovered
    $script:SettingsRecoveredLabel.Dock = "Top"

    $script:SettingsSaveLabel = New-Object System.Windows.Forms.Label
    $script:SettingsSaveLabel.Text = "Settings saved"
    $script:SettingsSaveLabel.ForeColor = [System.Drawing.Color]::LightGreen
    $script:SettingsSaveLabel.AutoSize = $true
    $script:SettingsSaveLabel.Margin = New-Object System.Windows.Forms.Padding(12, 0, 0, 6)
    $script:SettingsSaveLabel.Visible = $false
    $script:SettingsSaveLabel.Dock = "Top"

    $searchPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $searchPanel.FlowDirection = "LeftToRight"
    $searchPanel.AutoSize = $true
    $searchPanel.WrapContents = $false
    $searchPanel.Dock = "Top"
    $searchPanel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)

    $searchLabel = New-Object System.Windows.Forms.Label
    $searchLabel.Text = "Search settings:"
    $searchLabel.AutoSize = $true
    $searchLabel.Margin = New-Object System.Windows.Forms.Padding(12, 4, 0, 0)

    $script:SettingsSearchBox = New-Object System.Windows.Forms.TextBox
    $script:SettingsSearchBox.Width = 220
    $script:SettingsSearchBox.Margin = New-Object System.Windows.Forms.Padding(6, 0, 0, 0)

    $searchClearButton = New-Object System.Windows.Forms.Button
    $searchClearButton.Text = (L "Clear")
    $searchClearButton.AutoSize = $true
    $searchClearButton.Margin = New-Object System.Windows.Forms.Padding(6, 0, 0, 0)
    $searchClearButton.Add_Click({
        if ($script:SettingsSearchBox) { $script:SettingsSearchBox.Text = "" }
    })

    $script:SettingsSearchTimer = New-Object System.Windows.Forms.Timer
    $script:SettingsSearchTimer.Interval = 250
    $script:SettingsSearchTimer.Add_Tick({
        $script:SettingsSearchTimer.Stop()
        if ($script:ApplySettingsSearchFilter) {
            & $script:ApplySettingsSearchFilter $script:SettingsSearchBox.Text
        }
    })

    $script:SettingsSearchBox.Add_TextChanged({
        if ($script:SettingsSearchTimer) {
            $script:SettingsSearchTimer.Stop()
            $script:SettingsSearchTimer.Start()
            return
        }
        if ($script:ApplySettingsSearchFilter) { & $script:ApplySettingsSearchFilter $script:SettingsSearchBox.Text }
    })

    $searchPanel.Controls.Add($searchLabel) | Out-Null
    $searchPanel.Controls.Add($script:SettingsSearchBox) | Out-Null
    $searchPanel.Controls.Add($searchClearButton) | Out-Null
    $script:SettingsSearchPanel = $searchPanel

    $topPanel.Controls.Add($script:SettingsBannerPanel)
    if ($script:UpdateSettingsBanner) { & $script:UpdateSettingsBanner }
    $topPanel.Controls.Add($script:SettingsDirtyLabel)
    $topPanel.Controls.Add($script:SettingsRecoveredLabel)
    $topPanel.Controls.Add($script:SettingsSaveLabel)
    $topPanel.Controls.Add($searchPanel)
    $mainPanel.Controls.Add($tabControl)
    $mainPanel.Controls.Add($topPanel)

    $addSettingRow = {
        param($panel, $labelText, $control)
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $labelText
        $label.Tag = $labelText
        $label.AutoSize = $true
        $label.Anchor = "Left"
        $label.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $control.Anchor = "Left"
        $control.Tag = $labelText
        if ($panel -is [System.Windows.Forms.TableLayoutPanel]) {
            $panel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
            $panel.Controls.Add($label, 0, $panel.RowCount)
            $panel.Controls.Add($control, 1, $panel.RowCount)
            $panel.RowCount++
        }
        return $label
    }
    $script:AddSettingRow = $addSettingRow

    $addErrorRow = {
        param($panel)
        $errorLabel = New-Object System.Windows.Forms.Label
        $errorLabel.ForeColor = [System.Drawing.Color]::IndianRed
        $errorLabel.AutoSize = $true
        $errorLabel.Visible = $false
        if ($panel -is [System.Windows.Forms.TableLayoutPanel]) {
            [void]$panel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
            $spacer = New-Object System.Windows.Forms.Label
            $spacer.Text = ""
            $spacer.AutoSize = $true
            [void]$panel.Controls.Add($spacer, 0, $panel.RowCount)
            [void]$panel.Controls.Add($errorLabel, 1, $panel.RowCount)
            $panel.RowCount++
        }
        return $errorLabel
    }
    $script:AddErrorRow = $addErrorRow

    $addFullRow = {
        param($panel, $control)
        if ($panel -is [System.Windows.Forms.TableLayoutPanel]) {
            [void]$panel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
            [void]$panel.Controls.Add($control, 0, $panel.RowCount)
            $panel.SetColumnSpan($control, 2)
            $panel.RowCount++
        }
    }
    $script:AddFullRow = $addFullRow

    $resetTabDefaults = {
        param([string]$tabName)
        if (-not $script:TabDefaultsMap -or -not $script:TabDefaultsMap.ContainsKey($tabName)) { return }
        if ($tabName -eq "Profiles") {
            $confirm = [System.Windows.Forms.MessageBox]::Show(
                (L "Reset all profiles to defaults?`n`nThis will remove all custom profiles."),
                (L "Reset Profiles"),
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        }
        $props = $script:TabDefaultsMap[$tabName]
        foreach ($prop in $props) {
            if ($defaultSettings.PSObject.Properties.Name -contains $prop) {
                Set-SettingsPropertyValue $settings $prop (Copy-SettingsValue $defaultSettings.$prop)
            }
        }
        if ($tabName -eq "Profiles") {
            if (-not ($settings.Profiles -is [hashtable])) { $settings.Profiles = @{} }
            if ([string]::IsNullOrWhiteSpace([string]$settings.ActiveProfile)) { $settings.ActiveProfile = "Default" }
        }
        if ($script:ApplySettingsToControls) { & $script:ApplySettingsToControls $settings }
        Set-SettingsDirty $true
        Write-Log "UI: Reset defaults for $tabName tab." "DEBUG" $null "Settings-ResetTab"
    }
    $script:ResetTabDefaults = $resetTabDefaults

    $addSpacerRow = {
        param($panel, [int]$height = 10)
        if ($panel -is [System.Windows.Forms.TableLayoutPanel]) {
            $spacer = New-Object System.Windows.Forms.Label
            $spacer.Text = ""
            $spacer.AutoSize = $false
            $spacer.Height = $height
            $spacer.Width = 1
            $spacer.Tag = "Spacer"
            [void]$panel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, $height)))
            [void]$panel.Controls.Add($spacer, 0, $panel.RowCount)
            $panel.SetColumnSpan($spacer, 2)
            $panel.RowCount++
        }
    }
    $script:AddSettingRow = $addSettingRow
    $script:AddSpacerRow = $addSpacerRow
    $script:AddFullRow = $addFullRow

    $addSectionHeader = {
        param($panel, [string]$title)
        if (-not ($panel -is [System.Windows.Forms.TableLayoutPanel])) { return }
        $headerPanel = New-Object System.Windows.Forms.TableLayoutPanel
        $headerPanel.ColumnCount = 3
        $headerPanel.RowCount = 1
        $headerPanel.AutoSize = $true
        $headerPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $headerPanel.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::AddColumns
        $headerPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
        $headerPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
        $headerPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
        $headerPanel.Tag = "Header:$title"

        $columnIndex = 0
        $iconPath = Join-Path $script:DataRoot ("Meta\\Icons\\{0}_icon.ico" -f $title)
        if (Test-Path $iconPath) {
            try {
                $icon = New-Object System.Drawing.Icon($iconPath)
                $iconBox = New-Object System.Windows.Forms.PictureBox
                $iconBox.Size = New-Object System.Drawing.Size(18, 18)
                $iconBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage
                $iconBox.Image = $icon.ToBitmap()
                $headerPanel.Controls.Add($iconBox, $columnIndex, 0)
                $columnIndex++
            } catch {
            }
        }

        $headerLabel = New-Object System.Windows.Forms.Label
        $headerLabel.Text = $title
        $headerLabel.AutoSize = $true
        $headerLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $headerLabel.Font = New-Object System.Drawing.Font($panel.Font.FontFamily, 13, ([System.Drawing.FontStyle]::Bold -bor [System.Drawing.FontStyle]::Underline))
        $headerPanel.Controls.Add($headerLabel, $columnIndex, 0)

        if ($script:TabDefaultsMap -and $script:TabDefaultsMap.ContainsKey($title)) {
            $resetButton = New-Object System.Windows.Forms.Button
            $resetButton.Text = "Reset"
            $resetButton.AutoSize = $true
            $resetButton.Margin = New-Object System.Windows.Forms.Padding(12, 0, 0, 0)
            $resetButton.Tag = "Reset $title"
            $resetButton.Add_Click({
                if ($script:ResetTabDefaults) { & $script:ResetTabDefaults $title }
            })
            $headerPanel.Controls.Add($resetButton, 2, 0)
        }

        if ($script:AddFullRow) { & $script:AddFullRow $panel $headerPanel }
        if ($script:AddSpacerRow) { & $script:AddSpacerRow $panel 6 }
    }

    $createTabPanel = {
        param([string]$title)
        $page = New-Object System.Windows.Forms.TabPage
        $page.Text = $title
        $page.Name = $title
        $page.Tag = $title
        $page.AutoScroll = $true
        $page.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)
        $panel = New-Object System.Windows.Forms.TableLayoutPanel
        $panel.ColumnCount = 2
        $panel.RowCount = 0
        $panel.AutoSize = $true
        $panel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $panel.Dock = "Top"
        $panel.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::AddRows
        $panel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
        $panel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
        $page.Controls.Add($panel)
        $tabControl.TabPages.Add($page) | Out-Null
        return $panel
    }

    $statusPanel = & $createTabPanel "Status"
    $generalPanel = & $createTabPanel "General"
    $schedulePanel = & $createTabPanel "Scheduling"
    $hotkeyPanel = & $createTabPanel "Hotkeys"
    $loggingPanel = & $createTabPanel "Logging"
    $profilesPanel = & $createTabPanel "Profiles"
    $appearancePanel = & $createTabPanel "Appearance"
    $diagnosticsPanel = & $createTabPanel "Diagnostics"
    $advancedPanel = & $createTabPanel "Advanced"
    $aboutPanel = & $createTabPanel "About"

    $ensureTabPanel = {
        param($panel, $pageTitle)
        if ($panel -is [System.Windows.Forms.TableLayoutPanel]) { return $panel }
        $page = if ($script:GetSettingsTabPage) { & $script:GetSettingsTabPage $pageTitle } else { $null }
        if (-not $page) { return $panel }
        if ([string]::IsNullOrWhiteSpace([string]$page.Tag)) { $page.Tag = $pageTitle }
        if ([string]::IsNullOrWhiteSpace([string]$page.Name)) { $page.Name = $pageTitle }
        $page.Controls.Clear()
        $newPanel = New-Object System.Windows.Forms.TableLayoutPanel
        $newPanel.ColumnCount = 2
        $newPanel.RowCount = 0
        $newPanel.AutoSize = $true
        $newPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $newPanel.Dock = "Top"
        $newPanel.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::AddRows
        $newPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
        $newPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
        $page.Controls.Add($newPanel)
        return $newPanel
    }

    $statusPanel = & $ensureTabPanel $statusPanel "Status"
    $generalPanel = & $ensureTabPanel $generalPanel "General"
    $schedulePanel = & $ensureTabPanel $schedulePanel "Scheduling"
    $hotkeyPanel = & $ensureTabPanel $hotkeyPanel "Hotkeys"
    $loggingPanel = & $ensureTabPanel $loggingPanel "Logging"
    $profilesPanel = & $ensureTabPanel $profilesPanel "Profiles"
    $appearancePanel = & $ensureTabPanel $appearancePanel "Appearance"
    $diagnosticsPanel = & $ensureTabPanel $diagnosticsPanel "Diagnostics"
    $advancedPanel = & $ensureTabPanel $advancedPanel "Advanced"
    $aboutPanel = & $ensureTabPanel $aboutPanel "About"


    & $addSectionHeader $generalPanel "General"
    & $addSectionHeader $schedulePanel "Scheduling"
    & $addSectionHeader $loggingPanel "Logging"
    & $addSectionHeader $statusPanel "Status"
    & $addSectionHeader $hotkeyPanel "Hotkeys"
    & $addSectionHeader $profilesPanel "Profiles"
    & $addSectionHeader $appearancePanel "Appearance"
    & $addSectionHeader $diagnosticsPanel "Diagnostics"
    & $addSectionHeader $advancedPanel "Advanced"
    & $addSectionHeader $aboutPanel "About"

    $script:intervalBox = New-Object System.Windows.Forms.NumericUpDown
    $script:intervalBox.Minimum = 5
    $script:intervalBox.Maximum = 86400
    $script:intervalBox.Value = [int]$settings.IntervalSeconds
    $script:intervalBox.Width = 120

    $script:startWithWindowsBox = New-Object System.Windows.Forms.CheckBox
    $script:startWithWindowsBox.Checked = [bool]$settings.StartWithWindows
    $script:startWithWindowsBox.AutoSize = $true

    $script:openSettingsLastTabBox = New-Object System.Windows.Forms.CheckBox
    $script:openSettingsLastTabBox.Checked = [bool]$settings.OpenSettingsAtLastTab
    $script:openSettingsLastTabBox.AutoSize = $true

    $script:languageBox = New-Object System.Windows.Forms.ComboBox
    $script:languageBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $script:languageBox.Width = 180
    $script:UpdateLanguageItems = {
        param([string]$selectedCode)
        $items = @(
            [pscustomobject]@{ Code = "auto"; Label = (L "Auto (System)") }
            [pscustomobject]@{ Code = "en"; Label = (L "English") }
            [pscustomobject]@{ Code = "es"; Label = (L "Español") }
            [pscustomobject]@{ Code = "fr"; Label = (L "Français") }
            [pscustomobject]@{ Code = "de"; Label = (L "Deutsch") }
        )
        $script:languageBox.DisplayMember = "Label"
        $script:languageBox.ValueMember = "Code"
        $script:languageBox.Items.Clear()
        foreach ($item in $items) { [void]$script:languageBox.Items.Add($item) }
        if ([string]::IsNullOrWhiteSpace($selectedCode)) {
            $selectedCode = [string]$settings.UiLanguage
        }
        if ([string]::IsNullOrWhiteSpace($selectedCode)) { $selectedCode = "auto" }
        $selectedItem = $items | Where-Object { $_.Code -eq $selectedCode } | Select-Object -First 1
        if ($selectedItem) {
            $script:languageBox.SelectedItem = $selectedItem
        } elseif ($script:languageBox.Items.Count -gt 0) {
            $script:languageBox.SelectedIndex = 0
        }
    }
    if ($script:UpdateLanguageItems) { & $script:UpdateLanguageItems ([string]$settings.UiLanguage) }
    $script:languageBox.Add_SelectedIndexChanged({
        if ($script:SettingsIsApplying) { return }
        $selected = $script:languageBox.SelectedItem
        if ($selected -and $selected.PSObject.Properties.Name -contains "Code") {
            $code = [string]$selected.Code
            $script:UiLanguage = Resolve-UiLanguage $code
            if ($script:UpdateLanguageItems) {
                $script:SettingsIsApplying = $true
                & $script:UpdateLanguageItems $code
                $script:SettingsIsApplying = $false
            }
            if ($script:UpdateTooltipStyleItems) {
                $currentStyle = [string]$settings.TooltipStyle
                if ([string]::IsNullOrWhiteSpace($currentStyle)) {
                    $currentStyle = if ([bool]$settings.MinimalTrayTooltip) { "Minimal" } else { "Standard" }
                }
                $script:SettingsIsApplying = $true
                & $script:UpdateTooltipStyleItems $currentStyle
                $script:SettingsIsApplying = $false
            }
            if ($script:UpdateThemeModeItems) {
                $themeModeValue = [string]$settings.ThemeMode
                if ([string]::IsNullOrWhiteSpace($themeModeValue)) { $themeModeValue = "Auto" }
                $themeModeLabel = switch ($themeModeValue.ToUpperInvariant()) {
                    "LIGHT" { "Light" }
                    "DARK" { "Dark" }
                    "HIGH CONTRAST" { "High Contrast" }
                    default { "Auto Detect" }
                }
                $script:SettingsIsApplying = $true
                & $script:UpdateThemeModeItems $themeModeLabel
                $script:SettingsIsApplying = $false
            }
            if ($script:SettingsForm -and -not $script:SettingsForm.IsDisposed) {
                Localize-ControlTree $script:SettingsForm
                if ($script:ApplySettingsLocalizationOverrides) { & $script:ApplySettingsLocalizationOverrides }
            }
            if ($script:TrayMenu) { Localize-MenuItems $script:TrayMenu.Items }
            if (Get-Command Update-TrayLabels -ErrorAction SilentlyContinue) { Update-TrayLabels }
        }
        Set-SettingsDirty $true
    })

    $script:rememberChoiceBox = New-Object System.Windows.Forms.CheckBox
    $script:rememberChoiceBox.Checked = [bool]$settings.RememberChoice
    $script:rememberChoiceBox.AutoSize = $true

    $script:showFirstRunToastBox = New-Object System.Windows.Forms.CheckBox
    $script:showFirstRunToastBox.Checked = [bool]$settings.ShowFirstRunToast
    $script:showFirstRunToastBox.AutoSize = $true

    $script:startOnLaunchBox = New-Object System.Windows.Forms.CheckBox
    $script:startOnLaunchBox.Checked = [bool]$settings.StartOnLaunch
    $script:startOnLaunchBox.AutoSize = $true

    $script:quietModeBox = New-Object System.Windows.Forms.CheckBox
    $script:quietModeBox.Checked = [bool]$settings.QuietMode
    $script:quietModeBox.AutoSize = $true

    $script:tooltipStyleBox = New-Object System.Windows.Forms.ComboBox
    $script:tooltipStyleBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $script:tooltipStyleBox.Width = 140
    $script:UpdateTooltipStyleItems = {
        param([string]$selectedCode)
        $items = @(
            [pscustomobject]@{ Code = "Minimal"; Label = (L "Minimal") }
            [pscustomobject]@{ Code = "Standard"; Label = (L "Standard") }
            [pscustomobject]@{ Code = "Verbose"; Label = (L "Verbose") }
        )
        $script:tooltipStyleBox.DisplayMember = "Label"
        $script:tooltipStyleBox.ValueMember = "Code"
        $script:tooltipStyleBox.Items.Clear()
        foreach ($item in $items) { [void]$script:tooltipStyleBox.Items.Add($item) }
        if ([string]::IsNullOrWhiteSpace($selectedCode)) { $selectedCode = "Standard" }
        $selectedItem = $items | Where-Object { $_.Code -eq $selectedCode } | Select-Object -First 1
        if ($selectedItem) {
            $script:tooltipStyleBox.SelectedItem = $selectedItem
        } elseif ($script:tooltipStyleBox.Items.Count -gt 0) {
            $script:tooltipStyleBox.SelectedIndex = 0
        }
    }
    if ($script:UpdateTooltipStyleItems) {
        $tooltipStyleValue = [string]$settings.TooltipStyle
        if ([string]::IsNullOrWhiteSpace($tooltipStyleValue)) {
            $tooltipStyleValue = if ([bool]$settings.MinimalTrayTooltip) { "Minimal" } else { "Standard" }
        }
        & $script:UpdateTooltipStyleItems $tooltipStyleValue
    }

    $script:disableBalloonBox = New-Object System.Windows.Forms.CheckBox
    $script:disableBalloonBox.Checked = [bool]$settings.DisableBalloonTips
    $script:disableBalloonBox.AutoSize = $true

    $script:themeModeBox = New-Object System.Windows.Forms.ComboBox
    $script:themeModeBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $script:themeModeBox.Width = 140
    $script:UpdateThemeModeItems = {
        param([string]$selectedCode)
        $items = @(
            [pscustomobject]@{ Code = "Auto Detect"; Label = (L "Auto Detect") }
            [pscustomobject]@{ Code = "Light"; Label = (L "Light") }
            [pscustomobject]@{ Code = "Dark"; Label = (L "Dark") }
            [pscustomobject]@{ Code = "High Contrast"; Label = (L "High Contrast") }
        )
        $script:themeModeBox.DisplayMember = "Label"
        $script:themeModeBox.ValueMember = "Code"
        $script:themeModeBox.Items.Clear()
        foreach ($item in $items) { [void]$script:themeModeBox.Items.Add($item) }
        if ([string]::IsNullOrWhiteSpace($selectedCode)) { $selectedCode = "Auto Detect" }
        $selectedItem = $items | Where-Object { $_.Code -eq $selectedCode } | Select-Object -First 1
        if ($selectedItem) {
            $script:themeModeBox.SelectedItem = $selectedItem
        } elseif ($script:themeModeBox.Items.Count -gt 0) {
            $script:themeModeBox.SelectedIndex = 0
        }
    }
    if ($script:UpdateThemeModeItems) {
        $themeModeValue = [string]$settings.ThemeMode
        if ([string]::IsNullOrWhiteSpace($themeModeValue)) { $themeModeValue = "Auto" }
        $themeModeLabel = switch ($themeModeValue.ToUpperInvariant()) {
            "LIGHT" { "Light" }
            "DARK" { "Dark" }
            "HIGH CONTRAST" { "High Contrast" }
            default { "Auto Detect" }
        }
        & $script:UpdateThemeModeItems $themeModeLabel
    }

    $script:fontSizeBox = New-Object System.Windows.Forms.NumericUpDown
    $script:fontSizeBox.Minimum = 8
    $script:fontSizeBox.Maximum = 24
    $script:fontSizeBox.Value = 12
    $script:fontSizeBox.Width = 80

    $fontSizeUnit = New-Object System.Windows.Forms.Label
    $fontSizeUnit.Text = "pt"
    $fontSizeUnit.AutoSize = $true

    $fontSizePanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $fontSizePanel.FlowDirection = "LeftToRight"
    $fontSizePanel.AutoSize = $true
    $fontSizePanel.WrapContents = $false
    $fontSizePanel.Controls.Add($script:fontSizeBox) | Out-Null
    $fontSizePanel.Controls.Add($fontSizeUnit) | Out-Null
    $fontSizePanel.Tag = "Font Size (Tray)"
    $script:fontSizeBox.Tag = "Font Size (Tray)"
    $fontSizeUnit.Tag = "Font Size (Tray)"

    $script:settingsFontSizeBox = New-Object System.Windows.Forms.NumericUpDown
    $script:settingsFontSizeBox.Minimum = 8
    $script:settingsFontSizeBox.Maximum = 24
    $script:settingsFontSizeBox.Value = 12
    $script:settingsFontSizeBox.Width = 80

    $settingsFontSizeUnit = New-Object System.Windows.Forms.Label
    $settingsFontSizeUnit.Text = "pt"
    $settingsFontSizeUnit.AutoSize = $true

    $settingsFontSizePanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $settingsFontSizePanel.FlowDirection = "LeftToRight"
    $settingsFontSizePanel.AutoSize = $true
    $settingsFontSizePanel.WrapContents = $false
    $settingsFontSizePanel.Controls.Add($script:settingsFontSizeBox) | Out-Null
    $settingsFontSizePanel.Controls.Add($settingsFontSizeUnit) | Out-Null
    $settingsFontSizePanel.Tag = "Settings Font Size"
    $script:settingsFontSizeBox.Tag = "Settings Font Size"
    $settingsFontSizeUnit.Tag = "Settings Font Size"

    $script:statusRunningColorPanel = New-Object System.Windows.Forms.Panel
    $script:statusRunningColorPanel.Size = New-Object System.Drawing.Size(28, 16)

    $script:StatusRunningColorButton = New-Object System.Windows.Forms.Button
    $script:StatusRunningColorButton.Text = "Change..."
    $script:StatusRunningColorButton.Width = 80

    $statusRunningColorRow = New-Object System.Windows.Forms.FlowLayoutPanel
    $statusRunningColorRow.FlowDirection = "LeftToRight"
    $statusRunningColorRow.AutoSize = $true
    $statusRunningColorRow.WrapContents = $false
    $statusRunningColorRow.Controls.Add($script:statusRunningColorPanel) | Out-Null
    $statusRunningColorRow.Controls.Add($script:StatusRunningColorButton) | Out-Null
    $statusRunningColorRow.Tag = "Status Color (Running)"
    $script:statusRunningColorPanel.Tag = "Status Color (Running)"
    $script:StatusRunningColorButton.Tag = "Status Color (Running)"

    $script:statusPausedColorPanel = New-Object System.Windows.Forms.Panel
    $script:statusPausedColorPanel.Size = New-Object System.Drawing.Size(28, 16)

    $script:StatusPausedColorButton = New-Object System.Windows.Forms.Button
    $script:StatusPausedColorButton.Text = "Change..."
    $script:StatusPausedColorButton.Width = 80

    $statusPausedColorRow = New-Object System.Windows.Forms.FlowLayoutPanel
    $statusPausedColorRow.FlowDirection = "LeftToRight"
    $statusPausedColorRow.AutoSize = $true
    $statusPausedColorRow.WrapContents = $false
    $statusPausedColorRow.Controls.Add($script:statusPausedColorPanel) | Out-Null
    $statusPausedColorRow.Controls.Add($script:StatusPausedColorButton) | Out-Null
    $statusPausedColorRow.Tag = "Status Color (Paused)"
    $script:statusPausedColorPanel.Tag = "Status Color (Paused)"
    $script:StatusPausedColorButton.Tag = "Status Color (Paused)"

    $script:statusStoppedColorPanel = New-Object System.Windows.Forms.Panel
    $script:statusStoppedColorPanel.Size = New-Object System.Drawing.Size(28, 16)

    $script:StatusStoppedColorButton = New-Object System.Windows.Forms.Button
    $script:StatusStoppedColorButton.Text = "Change..."
    $script:StatusStoppedColorButton.Width = 80

    $statusStoppedColorRow = New-Object System.Windows.Forms.FlowLayoutPanel
    $statusStoppedColorRow.FlowDirection = "LeftToRight"
    $statusStoppedColorRow.AutoSize = $true
    $statusStoppedColorRow.WrapContents = $false
    $statusStoppedColorRow.Controls.Add($script:statusStoppedColorPanel) | Out-Null
    $statusStoppedColorRow.Controls.Add($script:StatusStoppedColorButton) | Out-Null
    $statusStoppedColorRow.Tag = "Status Color (Stopped)"
    $script:statusStoppedColorPanel.Tag = "Status Color (Stopped)"
    $script:StatusStoppedColorButton.Tag = "Status Color (Stopped)"

    $statusColorsGrid = New-Object System.Windows.Forms.TableLayoutPanel
    $statusColorsGrid.ColumnCount = 2
    $statusColorsGrid.RowCount = 3
    $statusColorsGrid.AutoSize = $true
    $statusColorsGrid.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $statusColorsGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $statusColorsGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))

    $statusRunningLabelInline = New-Object System.Windows.Forms.Label
    $statusRunningLabelInline.Text = "Running"
    $statusRunningLabelInline.AutoSize = $true
    $statusRunningLabelInline.Margin = New-Object System.Windows.Forms.Padding(0, 6, 8, 0)

    $statusPausedLabelInline = New-Object System.Windows.Forms.Label
    $statusPausedLabelInline.Text = "Paused"
    $statusPausedLabelInline.AutoSize = $true
    $statusPausedLabelInline.Margin = New-Object System.Windows.Forms.Padding(0, 6, 8, 0)

    $statusStoppedLabelInline = New-Object System.Windows.Forms.Label
    $statusStoppedLabelInline.Text = "Stopped"
    $statusStoppedLabelInline.AutoSize = $true
    $statusStoppedLabelInline.Margin = New-Object System.Windows.Forms.Padding(0, 6, 8, 0)

    $statusColorsGrid.Controls.Add($statusRunningLabelInline, 0, 0)
    $statusColorsGrid.Controls.Add($statusRunningColorRow, 1, 0)
    $statusColorsGrid.Controls.Add($statusPausedLabelInline, 0, 1)
    $statusColorsGrid.Controls.Add($statusPausedColorRow, 1, 1)
    $statusColorsGrid.Controls.Add($statusStoppedLabelInline, 0, 2)
    $statusColorsGrid.Controls.Add($statusStoppedColorRow, 1, 2)

    $script:compactModeBox = New-Object System.Windows.Forms.CheckBox
    $script:compactModeBox.Checked = [bool]$settings.CompactMode
    $script:compactModeBox.AutoSize = $true

    $appearancePreviewGroup = New-Object System.Windows.Forms.GroupBox
    $appearancePreviewGroup.Text = "Preview"
    $appearancePreviewGroup.AutoSize = $true
    $appearancePreviewGroup.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $appearancePreviewGroup.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)

    $appearancePreviewLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $appearancePreviewLayout.ColumnCount = 2
    $appearancePreviewLayout.RowCount = 5
    $appearancePreviewLayout.AutoSize = $true
    $appearancePreviewLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $appearancePreviewLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $previewTooltipLabel = New-Object System.Windows.Forms.Label
    $previewTooltipLabel.Text = "Tray Tooltip"
    $previewTooltipLabel.AutoSize = $true

    $previewTooltipValue = New-Object System.Windows.Forms.Label
    $previewTooltipValue.Text = "Standard"
    $previewTooltipValue.AutoSize = $true

    $previewFontLabel = New-Object System.Windows.Forms.Label
    $previewFontLabel.Text = "Font Size"
    $previewFontLabel.AutoSize = $true

    $previewFontValue = New-Object System.Windows.Forms.Label
    $previewFontValue.Text = "Normal"
    $previewFontValue.AutoSize = $true

    $previewRunningLabel = New-Object System.Windows.Forms.Label
    $previewRunningLabel.Text = "Status (Running)"
    $previewRunningLabel.AutoSize = $true

    $previewRunningPanel = New-Object System.Windows.Forms.Panel
    $previewRunningPanel.Size = New-Object System.Drawing.Size(28, 16)
    $previewRunningPanel.Tag = "Preview Status (Running)"

    $previewPausedLabel = New-Object System.Windows.Forms.Label
    $previewPausedLabel.Text = "Status (Paused)"
    $previewPausedLabel.AutoSize = $true

    $previewPausedPanel = New-Object System.Windows.Forms.Panel
    $previewPausedPanel.Size = New-Object System.Drawing.Size(28, 16)
    $previewPausedPanel.Tag = "Preview Status (Paused)"

    $previewStoppedLabel = New-Object System.Windows.Forms.Label
    $previewStoppedLabel.Text = "Status (Stopped)"
    $previewStoppedLabel.AutoSize = $true

    $previewStoppedPanel = New-Object System.Windows.Forms.Panel
    $previewStoppedPanel.Size = New-Object System.Drawing.Size(28, 16)
    $previewStoppedPanel.Tag = "Preview Status (Stopped)"

    $appearancePreviewLayout.Controls.Add($previewTooltipLabel, 0, 0)
    $appearancePreviewLayout.Controls.Add($previewTooltipValue, 1, 0)
    $appearancePreviewLayout.Controls.Add($previewFontLabel, 0, 1)
    $appearancePreviewLayout.Controls.Add($previewFontValue, 1, 1)
    $appearancePreviewLayout.Controls.Add($previewRunningLabel, 0, 2)
    $appearancePreviewLayout.Controls.Add($previewRunningPanel, 1, 2)
    $appearancePreviewLayout.Controls.Add($previewPausedLabel, 0, 3)
    $appearancePreviewLayout.Controls.Add($previewPausedPanel, 1, 3)
    $appearancePreviewLayout.Controls.Add($previewStoppedLabel, 0, 4)
    $appearancePreviewLayout.Controls.Add($previewStoppedPanel, 1, 4)

    $appearancePreviewContainer = New-Object System.Windows.Forms.TableLayoutPanel
    $appearancePreviewContainer.ColumnCount = 1
    $appearancePreviewContainer.RowCount = 1
    $appearancePreviewContainer.AutoSize = $true
    $appearancePreviewContainer.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $appearancePreviewContainer.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))

    $sampleTitle = New-Object System.Windows.Forms.Label
    $sampleTitle.Text = "Sample Tooltip"
    $sampleTitle.AutoSize = $true
    $sampleTitle.Margin = New-Object System.Windows.Forms.Padding(0, 10, 0, 2)

    $sampleStack = New-Object System.Windows.Forms.FlowLayoutPanel
    $sampleStack.FlowDirection = "TopDown"
    $sampleStack.AutoSize = $true
    $sampleStack.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $sampleStack.WrapContents = $false
    $sampleStack.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)
    $sampleStack.Anchor = "Left"

    $makeSampleRow = {
        $row = New-Object System.Windows.Forms.FlowLayoutPanel
        $row.FlowDirection = "LeftToRight"
        $row.AutoSize = $true
        $row.WrapContents = $false
        $row.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)

        $panel = New-Object System.Windows.Forms.Panel
        $panel.Size = New-Object System.Drawing.Size(12, 12)
        $panel.Margin = New-Object System.Windows.Forms.Padding(0, 2, 6, 0)

        $text = New-Object System.Windows.Forms.Label
        $text.AutoSize = $true

        $row.Controls.Add($panel) | Out-Null
        $row.Controls.Add($text) | Out-Null
        return [pscustomobject]@{ Row = $row; Panel = $panel; Text = $text }
    }

    $sampleRunning = & $makeSampleRow
    $samplePaused = & $makeSampleRow
    $sampleStopped = & $makeSampleRow

    $sampleStack.Controls.Add($sampleRunning.Row) | Out-Null
    $sampleStack.Controls.Add($samplePaused.Row) | Out-Null
    $sampleStack.Controls.Add($sampleStopped.Row) | Out-Null

    $samplePanel = New-Object System.Windows.Forms.TableLayoutPanel
    $samplePanel.ColumnCount = 1
    $samplePanel.RowCount = 2
    $samplePanel.AutoSize = $true
    $samplePanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $samplePanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $samplePanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $samplePanel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)
    $samplePanel.Controls.Add($sampleTitle, 0, 0)
    $samplePanel.Controls.Add($sampleStack, 0, 1)

    $appearancePreviewContainer.Controls.Add($samplePanel, 0, 0)
    $appearancePreviewGroup.Controls.Add($appearancePreviewContainer)
    $script:AppearancePreviewGroup = $appearancePreviewGroup

    $script:PreviewTooltipValue = $previewTooltipValue
    $script:PreviewFontValue = $previewFontValue
    $script:PreviewRunningPanel = $previewRunningPanel
    $script:PreviewPausedPanel = $previewPausedPanel
    $script:PreviewStoppedPanel = $previewStoppedPanel
    $script:TooltipStyleBox = $script:tooltipStyleBox
    $script:FontSizeBox = $script:fontSizeBox
    $script:SettingsFontSizeBox = $script:settingsFontSizeBox
    $script:StatusRunningColorPanel = $script:statusRunningColorPanel
    $script:StatusPausedColorPanel = $script:statusPausedColorPanel
    $script:StatusStoppedColorPanel = $script:statusStoppedColorPanel
    $script:PreviewSampleTitle = $sampleTitle
    $script:PreviewSampleRunningPanel = $sampleRunning.Panel
    $script:PreviewSampleRunningText = $sampleRunning.Text
    $script:PreviewSamplePausedPanel = $samplePaused.Panel
    $script:PreviewSamplePausedText = $samplePaused.Text
    $script:PreviewSampleStoppedPanel = $sampleStopped.Panel
    $script:PreviewSampleStoppedText = $sampleStopped.Text

    $updateAppearancePreview = {
        if ($script:PreviewTooltipValue) {
            $tooltipItem = $script:TooltipStyleBox.SelectedItem
            if ($tooltipItem -and $tooltipItem.PSObject.Properties.Name -contains "Label") {
                $script:PreviewTooltipValue.Text = [string]$tooltipItem.Label
            } else {
                $script:PreviewTooltipValue.Text = [string]$tooltipItem
            }
        }
        if ($script:PreviewFontValue) { $script:PreviewFontValue.Text = "$($script:FontSizeBox.Value) pt / $($script:SettingsFontSizeBox.Value) pt" }
        if ($script:PreviewRunningPanel) { $script:PreviewRunningPanel.BackColor = $script:StatusRunningColorPanel.BackColor }
        if ($script:PreviewPausedPanel) { $script:PreviewPausedPanel.BackColor = $script:StatusPausedColorPanel.BackColor }
        if ($script:PreviewStoppedPanel) { $script:PreviewStoppedPanel.BackColor = $script:StatusStoppedColorPanel.BackColor }
        if ($script:PreviewSampleTitle) { $script:PreviewSampleTitle.Text = (L "Sample Tooltip") }
        if ($script:PreviewSampleRunningPanel) { $script:PreviewSampleRunningPanel.BackColor = $script:StatusRunningColorPanel.BackColor }
        if ($script:PreviewSamplePausedPanel) { $script:PreviewSamplePausedPanel.BackColor = $script:StatusPausedColorPanel.BackColor }
        if ($script:PreviewSampleStoppedPanel) { $script:PreviewSampleStoppedPanel.BackColor = $script:StatusStoppedColorPanel.BackColor }
        if ($script:PreviewSampleRunningText) { $script:PreviewSampleRunningText.Text = ("{0}: {1}" -f (L "Status"), (L "Running")) }
        if ($script:PreviewSamplePausedText) { $script:PreviewSamplePausedText.Text = ("{0}: {1}" -f (L "Status"), (L "Paused")) }
        if ($script:PreviewSampleStoppedText) { $script:PreviewSampleStoppedText.Text = ("{0}: {1}" -f (L "Status"), (L "Stopped")) }
    }
    $script:UpdateAppearancePreview = $updateAppearancePreview

    $script:ColorDialog = New-Object System.Windows.Forms.ColorDialog
    $script:ColorDialog.FullOpen = $true

    $script:PickStatusColor = {
        param($panel)
        if (-not $panel) { return }
        $script:ColorDialog.Color = $panel.BackColor
        if ($script:ColorDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $panel.BackColor = $script:ColorDialog.Color
            & $updateAppearancePreview
            if (-not $script:SettingsIsApplying) { Set-SettingsDirty $true }
        }
    }

    $script:StatusRunningColorButton.Add_Click({ & $script:PickStatusColor $script:statusRunningColorPanel })
    $script:StatusPausedColorButton.Add_Click({ & $script:PickStatusColor $script:statusPausedColorPanel })
    $script:StatusStoppedColorButton.Add_Click({ & $script:PickStatusColor $script:statusStoppedColorPanel })

    $script:tooltipStyleBox.Add_SelectedIndexChanged({ if (-not $script:SettingsIsApplying) { & $updateAppearancePreview } })

    $script:fontSizeBox.Add_ValueChanged({
        if (-not $script:SettingsIsApplying) {
            Apply-MenuFontSize ([int]$script:fontSizeBox.Value)
            & $updateAppearancePreview
            Set-SettingsDirty $true
        }
    })

    $script:settingsFontSizeBox.Add_ValueChanged({
        if (-not $script:SettingsIsApplying) {
            Apply-SettingsFontSize ([int]$script:settingsFontSizeBox.Value)
            & $updateAppearancePreview
            Set-SettingsDirty $true
        }
    })

    $applyCompactMode = {
        param([bool]$enabled)
        $pad = if ($enabled) { 6 } else { 10 }
        if ($script:MainPanel) {
            $script:MainPanel.Padding = New-Object System.Windows.Forms.Padding($pad, $pad, $pad, $pad)
        }
        foreach ($page in $script:SettingsTabControl.TabPages) {
            $page.Padding = New-Object System.Windows.Forms.Padding($pad, $pad, $pad, $pad)
        }
    }
    $script:ApplyCompactMode = $applyCompactMode

    $script:compactModeBox.Add_CheckedChanged({
        if (-not $script:SettingsIsApplying) {
            & $applyCompactMode $script:compactModeBox.Checked
            Set-SettingsDirty $true
        }
    })

    $script:toggleCountBox = New-Object System.Windows.Forms.NumericUpDown
    $script:toggleCountBox.Minimum = 0
    $script:toggleCountBox.Maximum = 1000000
    $script:toggleCountBox.Value = [int]$settings.ToggleCount
    $script:toggleCountBox.Width = 120

    $resetStatsButton = New-Object System.Windows.Forms.Button
    $resetStatsButton.Text = "Reset Toggle Count"
    $resetStatsButton.Width = 100

    $script:LastTogglePicker = New-Object System.Windows.Forms.DateTimePicker
    $script:LastTogglePicker.Format = [System.Windows.Forms.DateTimePickerFormat]::Custom
    $script:LastTogglePicker.CustomFormat = Normalize-DateTimeFormat ([string]$settings.DateTimeFormat)
    $script:LastTogglePicker.ShowCheckBox = $true
    $script:LastTogglePicker.Width = 200

    $lastToggleNowButton = New-Object System.Windows.Forms.Button
    $lastToggleNowButton.Text = "Now"
    $lastToggleNowButton.Width = 60

    $lastToggleClearButton = New-Object System.Windows.Forms.Button
    $lastToggleClearButton.Text = "Clear"
    $lastToggleClearButton.Width = 60

    $lastTogglePanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $lastTogglePanel.FlowDirection = "LeftToRight"
    $lastTogglePanel.AutoSize = $true
    $lastTogglePanel.WrapContents = $false
    $lastTogglePanel.Controls.Add($script:LastTogglePicker) | Out-Null
    $lastTogglePanel.Controls.Add($lastToggleNowButton) | Out-Null
    $lastTogglePanel.Controls.Add($lastToggleClearButton) | Out-Null
    $lastTogglePanel.Tag = "Last Toggle Time"
    $script:LastTogglePicker.Tag = "Last Toggle Time"
    $lastToggleNowButton.Tag = "Last Toggle Time"
    $lastToggleClearButton.Tag = "Last Toggle Time"

    $lastToggleNowButton.Add_Click({
        $script:LastTogglePicker.Value = Get-Date
        $script:LastTogglePicker.Checked = $true
        if (-not $script:SettingsIsApplying) { Set-SettingsDirty $true }
    })

    $lastToggleClearButton.Add_Click({
        $script:LastTogglePicker.Checked = $false
        if (-not $script:SettingsIsApplying) { Set-SettingsDirty $true }
    })

    $script:runOnceOnLaunchBox = New-Object System.Windows.Forms.CheckBox
    $script:runOnceOnLaunchBox.Checked = [bool]$settings.RunOnceOnLaunch
    $script:runOnceOnLaunchBox.AutoSize = $true

    $script:dateTimeFormatBox = New-Object System.Windows.Forms.TextBox
    $script:dateTimeFormatBox.Width = 240
    $script:dateTimeFormatBox.Text = Normalize-DateTimeFormat ([string]$settings.DateTimeFormat)
    $script:dateTimeFormatBox.Tag = "Date/Time Format"

    $script:dateTimeFormatPresetBox = New-Object System.Windows.Forms.ComboBox
    $script:dateTimeFormatPresetBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $script:dateTimeFormatPresetBox.Width = 200
    $script:dateTimeFormatPresetBox.Items.Add("Custom") | Out-Null
    $script:dateTimeFormatPresetBox.Items.Add("yyyy-MM-dd HH:mm:ss") | Out-Null
    $script:dateTimeFormatPresetBox.Items.Add("MM/dd/yyyy h:mm tt") | Out-Null
    $script:dateTimeFormatPresetBox.Items.Add("dd/MM/yyyy HH:mm") | Out-Null
    $script:dateTimeFormatPresetBox.Items.Add("yyyy-MM-ddTHH:mm:ss") | Out-Null
    $script:dateTimeFormatPresetBox.SelectedIndex = 0
    $script:dateTimeFormatPresetBox.Tag = "Date/Time Format Preset"

    $script:useSystemDateTimeFormatBox = New-Object System.Windows.Forms.CheckBox
    $script:useSystemDateTimeFormatBox.Checked = [bool]$settings.UseSystemDateTimeFormat
    $script:useSystemDateTimeFormatBox.AutoSize = $true
    $script:useSystemDateTimeFormatBox.Tag = "Use System Date/Time Format"

    $script:systemDateTimeFormatModeBox = New-Object System.Windows.Forms.ComboBox
    $script:systemDateTimeFormatModeBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $script:systemDateTimeFormatModeBox.Width = 120
    $script:systemDateTimeFormatModeBox.Items.Add("Short") | Out-Null
    $script:systemDateTimeFormatModeBox.Items.Add("Long") | Out-Null
    $script:systemDateTimeFormatModeBox.SelectedItem = if ([string]$settings.SystemDateTimeFormatMode -eq "Long") { "Long" } else { "Short" }
    $script:systemDateTimeFormatModeBox.Tag = "System Date/Time Style"

    $script:dateTimeFormatPreviewLabel = New-Object System.Windows.Forms.Label
    $script:dateTimeFormatPreviewLabel.AutoSize = $true
    $script:dateTimeFormatPreviewLabel.Text = ""
    $script:dateTimeFormatPreviewLabel.Tag = "Date/Time Preview"

    $script:dateTimeFormatWarningLabel = New-Object System.Windows.Forms.Label
    $script:dateTimeFormatWarningLabel.AutoSize = $true
    $script:dateTimeFormatWarningLabel.ForeColor = [System.Drawing.Color]::FromArgb(220, 80, 80)
    $script:dateTimeFormatWarningLabel.Text = ""
    $script:dateTimeFormatWarningLabel.Visible = $false
    $script:dateTimeFormatWarningLabel.Tag = "Date/Time Format Warning"

    $script:updateDateTimePreview = {
        $useSystem = [bool]$script:useSystemDateTimeFormatBox.Checked
        $mode = [string]$script:systemDateTimeFormatModeBox.SelectedItem
        if ([string]::IsNullOrWhiteSpace($mode)) { $mode = "Short" }
        $previewText = ""
        if ($useSystem) {
            $script:dateTimeFormatWarningLabel.Visible = $false
            $script:dateTimeFormatWarningLabel.Text = ""
            $formatToken = if ($mode -eq "Long") { "F" } else { "g" }
            try {
                $previewText = (Get-Date).ToString($formatToken)
            } catch {
                $previewText = (Get-Date).ToString("g")
            }
        } else {
            $raw = [string]$script:dateTimeFormatBox.Text
            $raw = if ($null -eq $raw) { "" } else { $raw.Trim() }
            if ([string]::IsNullOrWhiteSpace($raw)) { $raw = $script:DateTimeFormatDefault }
            try {
                $previewText = (Get-Date).ToString($raw)
                $script:dateTimeFormatWarningLabel.Visible = $false
                $script:dateTimeFormatWarningLabel.Text = ""
            } catch {
                $previewText = (Get-Date).ToString($script:DateTimeFormatDefault)
                $script:dateTimeFormatWarningLabel.Text = "Invalid format. Reset to default on save."
                $script:dateTimeFormatWarningLabel.Visible = $true
            }
        }
        $script:dateTimeFormatPreviewLabel.Text = "Preview: $previewText"
    }

    $script:dateTimeFormatPresetBox.Add_SelectedIndexChanged({
        if ($script:SettingsIsApplying) { return }
        $selected = [string]$script:dateTimeFormatPresetBox.SelectedItem
        if ($selected -and $selected -ne "Custom") {
            $script:dateTimeFormatBox.Text = $selected
            $script:useSystemDateTimeFormatBox.Checked = $false
        }
        if ($script:updateDateTimePreview) { & $script:updateDateTimePreview }
    })

    $script:useSystemDateTimeFormatBox.Add_CheckedChanged({
        if ($script:SettingsIsApplying) { return }
        $enabled = -not $script:useSystemDateTimeFormatBox.Checked
        $script:dateTimeFormatBox.Enabled = $enabled
        $script:dateTimeFormatPresetBox.Enabled = $enabled
        $script:systemDateTimeFormatModeBox.Enabled = $script:useSystemDateTimeFormatBox.Checked
        if ($script:updateDateTimePreview) { & $script:updateDateTimePreview }
    })

    $script:systemDateTimeFormatModeBox.Add_SelectedIndexChanged({
        if ($script:SettingsIsApplying) { return }
        if ($script:updateDateTimePreview) { & $script:updateDateTimePreview }
    })

    $script:dateTimeFormatBox.Add_TextChanged({
        if ($script:SettingsIsApplying) { return }
        if ($script:updateDateTimePreview) { & $script:updateDateTimePreview }
    })

    $script:dateTimeFormatBox.Add_Leave({
        if ($script:SettingsIsApplying) { return }
        $raw = [string]$script:dateTimeFormatBox.Text
        $raw = if ($null -eq $raw) { "" } else { $raw.Trim() }
        if ([string]::IsNullOrWhiteSpace($raw)) { $raw = $script:DateTimeFormatDefault }
        try {
            [DateTime]::Now.ToString($raw) | Out-Null
            $script:dateTimeFormatBox.Text = $raw
            $script:dateTimeFormatWarningLabel.Visible = $false
            $script:dateTimeFormatWarningLabel.Text = ""
        } catch {
            $script:dateTimeFormatBox.Text = $script:DateTimeFormatDefault
            $script:dateTimeFormatWarningLabel.Text = "Invalid format. Reset to default."
            $script:dateTimeFormatWarningLabel.Visible = $true
        }
        if ($script:updateDateTimePreview) { & $script:updateDateTimePreview }
    })

    $script:pauseUntilBox = New-Object System.Windows.Forms.DateTimePicker
    $script:pauseUntilBox.Format = [System.Windows.Forms.DateTimePickerFormat]::Custom
    $script:pauseUntilBox.CustomFormat = Normalize-DateTimeFormat ([string]$settings.DateTimeFormat)
    $script:pauseUntilBox.ShowUpDown = $true
    $script:pauseUntilBox.ShowCheckBox = $true
    $script:pauseUntilBox.Width = 200
    if ($settings.PauseUntil) {
        try {
            $script:pauseUntilBox.Value = [DateTime]::Parse([string]$settings.PauseUntil)
            $script:pauseUntilBox.Checked = $true
        } catch {
            $script:pauseUntilBox.Checked = $false
        }
    } else {
        $script:pauseUntilBox.Checked = $false
    }

    $script:pauseDurationsBox = New-Object System.Windows.Forms.TextBox
    $script:pauseDurationsBox.Text = [string]$settings.PauseDurationsMinutes
    $script:pauseDurationsBox.Width = 240

    $script:scheduleOverrideBox = New-Object System.Windows.Forms.CheckBox
    $script:scheduleOverrideBox.Text = "Override global schedule"
    $script:scheduleOverrideBox.Checked = [bool]$settings.ScheduleOverrideEnabled
    $script:scheduleOverrideBox.AutoSize = $true
    $script:scheduleOverrideBox.Tag = "Schedule Override"

    $script:scheduleEnabledBox = New-Object System.Windows.Forms.CheckBox
    $script:scheduleEnabledBox.Checked = [bool]$settings.ScheduleEnabled
    $script:scheduleEnabledBox.AutoSize = $true

    $script:scheduleStartBox = New-Object System.Windows.Forms.DateTimePicker
    $script:scheduleStartBox.Format = [System.Windows.Forms.DateTimePickerFormat]::Time
    $script:scheduleStartBox.ShowUpDown = $true
    $script:scheduleStartBox.Width = 120

    $script:scheduleEndBox = New-Object System.Windows.Forms.DateTimePicker
    $script:scheduleEndBox.Format = [System.Windows.Forms.DateTimePickerFormat]::Time
    $script:scheduleEndBox.ShowUpDown = $true
    $script:scheduleEndBox.Width = 120

    $script:scheduleWeekdaysBox = New-Object System.Windows.Forms.TextBox
    $script:scheduleWeekdaysBox.Text = [string]$settings.ScheduleWeekdays
    $script:scheduleWeekdaysBox.Width = 240

    $script:scheduleSuspendUntilBox = New-Object System.Windows.Forms.DateTimePicker
    $script:scheduleSuspendUntilBox.Format = [System.Windows.Forms.DateTimePickerFormat]::Custom
    $script:scheduleSuspendUntilBox.CustomFormat = Normalize-DateTimeFormat ([string]$settings.DateTimeFormat)
    $script:scheduleSuspendUntilBox.ShowUpDown = $true
    $script:scheduleSuspendUntilBox.ShowCheckBox = $true
    $script:scheduleSuspendUntilBox.Width = 200
    if ($settings.ScheduleSuspendUntil) {
        try {
            $script:scheduleSuspendUntilBox.Value = [DateTime]::Parse([string]$settings.ScheduleSuspendUntil)
            $script:scheduleSuspendUntilBox.Checked = $true
        } catch {
            $script:scheduleSuspendUntilBox.Checked = $false
        }
    } else {
        $script:scheduleSuspendUntilBox.Checked = $false
    }

    $script:scheduleSuspendQuickBox = New-Object System.Windows.Forms.ComboBox
    $script:scheduleSuspendQuickBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $script:scheduleSuspendQuickBox.Width = 160
    $script:scheduleSuspendQuickBox.Items.Add("Select...") | Out-Null
    foreach ($hours in @(1, 2, 4, 8)) {
        $script:scheduleSuspendQuickBox.Items.Add("$hours hour") | Out-Null
    }
    $script:scheduleSuspendQuickBox.Items.Add("Clear suspension") | Out-Null
    $script:scheduleSuspendQuickBox.SelectedIndex = 0
    $script:scheduleSuspendQuickBox.Add_SelectedIndexChanged({
        if ($script:SettingsIsApplying) { return }
        $text = [string]$script:scheduleSuspendQuickBox.SelectedItem
        if ($text -eq "Select...") { return }
        if ($text -eq "Clear suspension") {
            $script:scheduleSuspendUntilBox.Checked = $false
        } else {
            $hoursValue = 0
            if ([int]::TryParse(($text -replace "\\D", ""), [ref]$hoursValue) -and $hoursValue -gt 0) {
                $script:scheduleSuspendUntilBox.Checked = $true
                $script:scheduleSuspendUntilBox.Value = (Get-Date).AddHours($hoursValue)
            }
        }
        Set-SettingsDirty $true
        $script:scheduleSuspendQuickBox.SelectedIndex = 0
    })

    $script:updateScheduleOverrideUI = {
        $enabled = [bool]$script:scheduleOverrideBox.Checked
        foreach ($ctrl in @(
            $script:scheduleEnabledBox,
            $script:scheduleStartBox,
            $script:scheduleEndBox,
            $script:scheduleWeekdaysBox,
            $script:scheduleSuspendUntilBox,
            $script:scheduleSuspendQuickBox
        )) {
            if ($ctrl) { $ctrl.Enabled = $enabled }
        }
    }

    $script:scheduleOverrideBox.Add_CheckedChanged({
        if ($script:SettingsIsApplying) { return }
        if ($script:updateScheduleOverrideUI) { & $script:updateScheduleOverrideUI }
        Set-SettingsDirty $true
    })
    if ($script:updateScheduleOverrideUI) { & $script:updateScheduleOverrideUI }

    $script:SafeModeEnabledBox = New-Object System.Windows.Forms.CheckBox
    $script:SafeModeEnabledBox.Checked = [bool]$settings.SafeModeEnabled
    $script:SafeModeEnabledBox.AutoSize = $true

    $script:safeModeThresholdBox = New-Object System.Windows.Forms.NumericUpDown
    $script:safeModeThresholdBox.Minimum = 1
    $script:safeModeThresholdBox.Maximum = 100
    $script:safeModeThresholdBox.Value = [int]$settings.SafeModeFailureThreshold
    $script:safeModeThresholdBox.Width = 120

    $script:hotkeyToggleBox = New-Object System.Windows.Forms.TextBox
    $script:hotkeyToggleBox.Text = [string]$settings.HotkeyToggle
    $script:hotkeyToggleBox.Width = 240

    $script:hotkeyStartStopBox = New-Object System.Windows.Forms.TextBox
    $script:hotkeyStartStopBox.Text = [string]$settings.HotkeyStartStop
    $script:hotkeyStartStopBox.Width = 240

    $script:hotkeyPauseResumeBox = New-Object System.Windows.Forms.TextBox
    $script:hotkeyPauseResumeBox.Text = [string]$settings.HotkeyPauseResume
    $script:hotkeyPauseResumeBox.Width = 240

    $hotkeyStatusLabel = New-Object System.Windows.Forms.Label
    $hotkeyStatusLabel.Text = "Hotkey Status"
    $hotkeyStatusLabel.AutoSize = $true

    $hotkeyStatusValue = New-Object System.Windows.Forms.Label
    $hotkeyStatusValue.Text = $script:HotkeyStatusText
    $hotkeyStatusValue.AutoSize = $true

    $script:logLevelBox = New-Object System.Windows.Forms.ComboBox
    $script:logLevelBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $script:logLevelBox.Items.AddRange(@("DEBUG", "INFO", "WARN", "ERROR", "FATAL"))
    $selectedLogLevel = [string]$settings.LogLevel
    if ([string]::IsNullOrWhiteSpace($selectedLogLevel)) { $selectedLogLevel = "INFO" }
    if ($script:logLevelBox.Items.Contains($selectedLogLevel.ToUpperInvariant())) {
        $script:logLevelBox.SelectedItem = $selectedLogLevel.ToUpperInvariant()
    } else {
        $script:logLevelBox.SelectedItem = "INFO"
    }
    $script:logLevelBox.Width = 240

    $script:logIncludeStackTraceBox = New-Object System.Windows.Forms.CheckBox
    $script:logIncludeStackTraceBox.Checked = [bool]$settings.LogIncludeStackTrace
    $script:logIncludeStackTraceBox.AutoSize = $true

    $script:logToEventLogBox = New-Object System.Windows.Forms.CheckBox
    $script:logToEventLogBox.Checked = [bool]$settings.LogToEventLog
    $script:logToEventLogBox.AutoSize = $true
    $script:logToEventLogBox.Tag = "Enable Event Log"

    $eventLogLevelPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $eventLogLevelPanel.FlowDirection = "LeftToRight"
    $eventLogLevelPanel.AutoSize = $true
    $eventLogLevelPanel.WrapContents = $false
    $eventLogLevelPanel.Tag = "Event Log Levels"
    $script:LogEventLevelBoxes = @{}
    $script:LogEventLevelLabelKeys = @{
        "ERROR" = "Error"
        "FATAL" = "Fatal"
        "WARN"  = "Warning"
        "INFO"  = "Info"
    }
    foreach ($levelName in @("ERROR", "FATAL", "WARN", "INFO")) {
        $box = New-Object System.Windows.Forms.CheckBox
        $labelKey = if ($script:LogEventLevelLabelKeys.ContainsKey($levelName)) { $script:LogEventLevelLabelKeys[$levelName] } else { $levelName }
        $box.Text = (L $labelKey $labelKey)
        $box.AutoSize = $true
        $box.Margin = New-Object System.Windows.Forms.Padding(0, 0, 12, 0)
        $enabled = $false
        if ($settings.LogEventLevels -is [hashtable] -and $settings.LogEventLevels.ContainsKey($levelName)) {
            $enabled = [bool]$settings.LogEventLevels[$levelName]
        } elseif ($settings.LogEventLevels -is [pscustomobject] -and ($settings.LogEventLevels.PSObject.Properties.Name -contains $levelName)) {
            $enabled = [bool]$settings.LogEventLevels.$levelName
        }
        $box.Checked = $enabled
        $eventLogLevelPanel.Controls.Add($box) | Out-Null
        $script:LogEventLevelBoxes[$levelName] = $box
    }
    $eventLogLevelPanel.Tag = "Event Log Levels"

    $script:verboseUiLogBox = New-Object System.Windows.Forms.CheckBox
    $script:verboseUiLogBox.Checked = [bool]$settings.VerboseUiLogging
    $script:verboseUiLogBox.AutoSize = $true

    $debugModeButton = New-Object System.Windows.Forms.Button
    $debugModeButton.Text = "Enable Debug (10 min)"
    $debugModeButton.Width = 150
    $script:DebugModeButton = $debugModeButton

    $debugModeStatus = New-Object System.Windows.Forms.Label
    $debugModeStatus.Text = "Off"
    $debugModeStatus.AutoSize = $true
    $script:DebugModeStatus = $debugModeStatus

    $script:logMaxBox = New-Object System.Windows.Forms.NumericUpDown
    $script:logMaxBox.Minimum = 64
    $script:logMaxBox.Maximum = 102400
    $script:logMaxBox.Value = [int]([Math]::Max(64, [int]($settings.LogMaxBytes / 1024)))
    $script:logMaxBox.Width = 120

    $script:logRetentionBox = New-Object System.Windows.Forms.NumericUpDown
    $script:logRetentionBox.Minimum = 0
    $script:logRetentionBox.Maximum = 365
    $script:logRetentionBox.Value = [int]([Math]::Max(0, [int]$settings.LogRetentionDays))
    $script:logRetentionBox.Width = 120
    $script:logRetentionBox.Tag = "Log Retention (days)"

    $script:logDirectoryBox = New-Object System.Windows.Forms.TextBox
    $script:logDirectoryBox.Width = 320
    $logDirValue = [string]$settings.LogDirectory
    $script:logDirectoryBox.Text = if ([string]::IsNullOrWhiteSpace($logDirValue)) { $script:LogDirectory } else { Convert-FromRelativePath $logDirValue }

    $logDirectoryBrowseButton = New-Object System.Windows.Forms.Button
    $logDirectoryBrowseButton.Text = "Browse..."
    $logDirectoryBrowseButton.Width = 80
    $logDirectoryBrowseButton.Add_Click({
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = "Choose a folder for Teams-Always-Green logs and settings backups."
        if (-not [string]::IsNullOrWhiteSpace($script:logDirectoryBox.Text) -and (Test-Path $script:logDirectoryBox.Text)) {
            $dialog.SelectedPath = $script:logDirectoryBox.Text
        } else {
            $dialog.SelectedPath = $script:LogDirectory
        }
        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $script:logDirectoryBox.Text = $dialog.SelectedPath
        }
    })

    $logDirectoryPanel = New-Object System.Windows.Forms.TableLayoutPanel
    $logDirectoryPanel.ColumnCount = 2
    $logDirectoryPanel.RowCount = 1
    $logDirectoryPanel.AutoSize = $true
    $logDirectoryPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $logDirectoryPanel.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::AddColumns
    $logDirectoryPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $logDirectoryPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $script:logDirectoryBox.Dock = "Fill"
    $script:logDirectoryBox.Margin = New-Object System.Windows.Forms.Padding(0, 0, 6, 0)
    $logDirectoryBrowseButton.Margin = New-Object System.Windows.Forms.Padding(0)
    $logDirectoryPanel.Controls.Add($script:logDirectoryBox, 0, 0) | Out-Null
    $logDirectoryPanel.Controls.Add($logDirectoryBrowseButton, 1, 0) | Out-Null
    $logDirectoryPanel.Tag = "Log Folder"
    $script:logDirectoryBox.Tag = "Log Folder"
    $logDirectoryBrowseButton.Tag = "Log Folder"
    $script:logDirectoryPanel = $logDirectoryPanel
    $script:logDirectoryBrowseButton = $logDirectoryBrowseButton

    $logFilesLabel = New-Object System.Windows.Forms.Label
    $logFilesLabel.AutoSize = $true
    $script:LogFilesListText = "Teams-Always-Green.log, Teams-Always-Green.log.#, Teams-Always-Green.fallback.log, Teams-Always-Green.bootstrap.log"
    $logFilesLabel.Text = $script:LogFilesListText
    $logFilesLabel.Tag = "Log Files List"
    $script:logFilesLabel = $logFilesLabel

    $viewLogButton = New-Object System.Windows.Forms.Button
    $viewLogButton.Text = "View Log"
    $viewLogButton.Width = 120
    $script:ViewLogButton = $viewLogButton
    $viewLogButton.Add_Click({
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

    $viewLogTailButton = New-Object System.Windows.Forms.Button
    $viewLogTailButton.Text = "View Log (Tail)"
    $viewLogTailButton.Width = 120
    $script:ViewLogTailButton = $viewLogTailButton
    $viewLogTailButton.Add_Click({
        Show-LogTailDialog
    })

    $exportLogTailButton = New-Object System.Windows.Forms.Button
    $exportLogTailButton.Text = "Export Log Tail..."
    $exportLogTailButton.Width = 120
    $script:ExportLogTailButton = $exportLogTailButton
    $exportLogTailButton.Add_Click({
        & $script:RunSettingsAction "Export Log Tail" {
            $dialog = New-Object System.Windows.Forms.SaveFileDialog
            $dialog.Title = "Export Log Tail"
            $dialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
            $dialog.FileName = "Teams-Always-Green.log.tail.txt"
            if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
            $lines = @()
            if (Test-Path $logPath) {
                $lines = Get-Content -Path $logPath -Tail 200
            }
            $lines | Set-Content -Path $dialog.FileName -Encoding UTF8
            Write-Log "Exported log tail to $($dialog.FileName)." "INFO" $null "Export-LogTail"
        }
    })

$clearLogButton = New-Object System.Windows.Forms.Button
    $clearLogButton.Text = "Clear Log..."
    $clearLogButton.Width = 120
    $script:ClearLogButton = $clearLogButton
    $clearLogButton.Add_Click({
        & $script:RunSettingsAction "Clear Log" {
            $result = [System.Windows.Forms.MessageBox]::Show(
                "Are you sure you want to clear the log file?",
                "Clear Log",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($result -ne [System.Windows.Forms.DialogResult]::Yes) {
                Write-Log "Clear log canceled." "INFO" $null "Clear-Log"
                return
            }
            "" | Set-Content -Path $logPath -Encoding UTF8
            Write-Log "Log file cleared." "INFO" $null "Clear-Log"
            if ($script:UpdateSettingsStatus) { & $script:UpdateSettingsStatus }
        }
    })

    $logSnapshotButton = New-Object System.Windows.Forms.Button
    $logSnapshotButton.Text = "Log Snapshot"
    $logSnapshotButton.Width = 120
    $script:LogSnapshotButton = $logSnapshotButton
    $logSnapshotButton.Add_Click({
        & $script:RunSettingsAction "Log Snapshot" {
            $summary = "[STATE] Running=$script:isRunning Paused=$script:isPaused Schedule=$((Format-ScheduleStatus)) Interval=$($settings.IntervalSeconds)s Profile=$($settings.ActiveProfile)"
            Write-Log $summary "INFO" $null "Log-Snapshot"
        }
    })

    $openLogFolderButton = New-Object System.Windows.Forms.Button
    $openLogFolderButton.Text = "Open Log Folder"
    $openLogFolderButton.Width = 120
    $script:OpenLogFolderButton = $openLogFolderButton
    $openLogFolderButton.Add_Click({
        try {
            $logFolder = Split-Path -Path $logPath -Parent
            if (-not [string]::IsNullOrWhiteSpace($logFolder)) {
                Start-Process explorer.exe $logFolder
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to open log folder.`n$($_.Exception.Message)",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
            Write-Log "Failed to open log folder." "ERROR" $_.Exception "Open-LogFolder"
        }
    })

    $validateFoldersButton = New-Object System.Windows.Forms.Button
    $validateFoldersButton.Text = "Validate Folders"
    $validateFoldersButton.Width = 120
    $validateFoldersButton.Tag = "Validate Folders"
    $script:ValidateFoldersButton = $validateFoldersButton

    $script:ApplySettingsLocalizationOverrides = {
        if ($script:SettingsStatusLabel) { $script:SettingsStatusLabel.Text = (L "Status") }
        if ($script:SettingsNextLabel) { $script:SettingsNextLabel.Text = (L "Next Toggle") }
        if ($script:SettingsNextCountdownLabel) { $script:SettingsNextCountdownLabel.Text = (L "Next Toggle In") }
        if ($script:SettingsLastToggleLabel) { $script:SettingsLastToggleLabel.Text = (L "Last Toggle") }
        if ($script:SettingsProfileStatusLabel) { $script:SettingsProfileStatusLabel.Text = (L "Active Profile") }
        if ($script:SettingsScheduleStatusLabel) { $script:SettingsScheduleStatusLabel.Text = (L "Schedule Status") }
        if ($script:SettingsSafeModeStatusLabel) { $script:SettingsSafeModeStatusLabel.Text = (L "Safe Mode") }
        if ($script:SettingsKeyboardLabel) { $script:SettingsKeyboardLabel.Text = (L "Keyboard") }
        if ($script:SettingsUptimeLabel) { $script:SettingsUptimeLabel.Text = (L "Uptime") }
        if ($script:SettingsFunDailyLabel) { $script:SettingsFunDailyLabel.Text = (L "Today's Toggles") }
        if ($script:SettingsFunStreakCurrentLabel) { $script:SettingsFunStreakCurrentLabel.Text = (L "Current Streak") }
        if ($script:SettingsFunStreakBestLabel) { $script:SettingsFunStreakBestLabel.Text = (L "Best Streak") }
        if ($script:SettingsFunMostActiveLabel) { $script:SettingsFunMostActiveLabel.Text = (L "Most Active Hour") }
        if ($script:SettingsFunLongestPauseLabel) { $script:SettingsFunLongestPauseLabel.Text = (L "Longest Pause") }
        if ($script:SettingsFunTotalRunLabel) { $script:SettingsFunTotalRunLabel.Text = (L "Total Run Time") }
        if ($script:SettingsFilesLabel -and $script:SettingsFilesListText) { $script:SettingsFilesLabel.Text = $script:SettingsFilesListText }
        if ($script:DebugModeButton) { $script:DebugModeButton.Text = (L "Enable Debug (10 min)" "Enable Debug (10 min)") }
        if ($script:LogEventLevelBoxes -and $script:LogEventLevelLabelKeys) {
            foreach ($levelName in $script:LogEventLevelBoxes.Keys) {
                $labelKey = if ($script:LogEventLevelLabelKeys.ContainsKey($levelName)) { $script:LogEventLevelLabelKeys[$levelName] } else { $levelName }
                $script:LogEventLevelBoxes[$levelName].Text = (L $labelKey $labelKey)
            }
        }
        if ($script:AboutSupportLink) {
            $script:AboutSupportLink.Text = (L "Report Issue" "Report Issue")
            $script:AboutSupportLinkText = $script:AboutSupportLink.Text
        }
        if ($script:CopyStatusButton) { $script:CopyStatusButton.Text = (L "Copy Status") }
        if ($script:SimulateToggleButton) { $script:SimulateToggleButton.Text = (L "Toggle Now") }
        if ($script:SimulateStartStopButton) { $script:SimulateStartStopButton.Text = (L "Start/Stop") }
        if ($script:SimulatePauseResumeButton) { $script:SimulatePauseResumeButton.Text = (L "Pause/Resume") }
        if ($script:ViewLogButton) { $script:ViewLogButton.Text = (L "View Log") }
        if ($script:ViewLogTailButton) { $script:ViewLogTailButton.Text = (L "View Log (Tail)") }
        if ($script:ExportLogTailButton) { $script:ExportLogTailButton.Text = (L "Export Log Tail...") }
        if ($script:ClearLogButton) { $script:ClearLogButton.Text = (L "Clear Log...") }
        if ($script:LogSnapshotButton) { $script:LogSnapshotButton.Text = (L "Log Snapshot") }
        if ($script:OpenLogFolderButton) { $script:OpenLogFolderButton.Text = (L "Open Log Folder") }
        if ($script:logDirectoryBrowseButton) { $script:logDirectoryBrowseButton.Text = (L "Browse...") }
        if ($script:StatusRunningColorButton) { $script:StatusRunningColorButton.Text = (L "Change...") }
        if ($script:StatusPausedColorButton) { $script:StatusPausedColorButton.Text = (L "Change...") }
        if ($script:StatusStoppedColorButton) { $script:StatusStoppedColorButton.Text = (L "Change...") }
        if ($script:UpdateAppearancePreview) { & $script:UpdateAppearancePreview }
        if ($script:logFilesLabel -and $script:LogFilesListText) { $script:logFilesLabel.Text = $script:LogFilesListText }
    }
    $validateFoldersButton.Add_Click({
        $results = Validate-FolderPaths
        $lines = @()
        $lines += "Folder status:"
        $lines += ""
        foreach ($item in $results) {
            $status = if (-not $item.Exists) { "Missing" } elseif ($item.Writable) { "OK" } else { "Read-only" }
            $lines += ("{0}: {1}" -f $item.Name, $status)
        }
        $lines += ""
        $lines += "If a folder is missing or read-only, the app will try to recreate it or fall back to a safe default."
        $message = ($lines -join "`r`n")
        [System.Windows.Forms.MessageBox]::Show(
            $message,
            "Folder Validation",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        $issues = @($results | Where-Object { -not $_.Exists -or -not $_.Writable })
        if ($issues.Count -eq 0) {
            Write-Log "Folder validation: OK." "INFO" $null "Settings-Validation"
        } else {
            $issueText = ($issues | ForEach-Object {
                $status = if (-not $_.Exists) { "Missing" } elseif (-not $_.Writable) { "Read-only" } else { "OK" }
                "{0}={1}" -f $_.Name, $status
            }) -join ", "
            Write-Log ("Folder validation issues: " + $issueText) "WARN" $null "Settings-Validation"
        }
        Write-Log "Folder validation run from settings dialog." "INFO" $null "Settings-Validation"
    })

    $runHealthCheckButton = New-Object System.Windows.Forms.Button
    $runHealthCheckButton.Text = "Run Health Check"
    $runHealthCheckButton.Width = 140
    $runHealthCheckButton.Tag = "Run Health Check"
    $runHealthCheckButton.Add_Click({
        Invoke-HealthCheckDialog
    })
    $script:RunHealthCheckButton = $runHealthCheckButton

    $exportDiagnosticsButton = New-Object System.Windows.Forms.Button
    $exportDiagnosticsButton.Text = "Export Diagnostics..."
    $exportDiagnosticsButton.Width = 140
    $exportDiagnosticsButton.Add_Click({
        & $script:RunSettingsAction "Export Diagnostics" {
            $dialog = New-Object System.Windows.Forms.SaveFileDialog
            $dialog.Title = "Export Diagnostics"
            $dialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
            $dialog.FileName = "Teams-Always-Green.diagnostics.txt"
            if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
            $lines = @()
            $lines += "Teams-Always-Green Diagnostics"
            $lines += "Generated: $(Format-DateTime (Get-Date))"
            $lines += ""
            $lines += "Version: $appVersion"
            $lines += "Last Updated: $appLastUpdated"
            $lines += "Script Path: $scriptPath"
            $lines += ""
            $lines += "Session: $script:SessionId"
            $lines += "Uptime: $([int]((Get-Date) - $script:AppStartTime).TotalMinutes) min"
            $lines += "State: $($script:StatusStateText)"
            $lines += "Running: $script:isRunning"
            $lines += "Paused: $script:isPaused"
            $lines += "Paused Until: $($settings.PauseUntil)"
            $lines += "Schedule: $(Format-ScheduleStatus)"
            $lines += "Schedule Suspended: $script:isScheduleSuspended"
            $lines += "Next Toggle: $(Format-NextInfo)"
            $lines += "Toggle Count: $($script:tickCount)"
            $lines += "Last Toggle: $($script:lastToggleTime)"
            $lines += "Last Toggle Result: $($script:LastToggleResult)"
            $lines += "Last Toggle Result Time: $($script:LastToggleResultTime)"
            $lines += "Last Toggle Error: $($script:LastToggleError)"
            $lines += "Last Restart: $($script:LastRestartTime)"
            $logSizeBytes = 0
            if (Test-Path $logPath) {
                try { $logSizeBytes = (Get-Item -Path $logPath).Length } catch { $logSizeBytes = 0 }
            }
            $lines += "Log Path: $logPath"
            $lines += "Log Size: $logSizeBytes bytes"
            $lines += "Log Rotations: $($script:LogRotationCount)"
            $lines += "Last Log Write: $($script:LastLogWriteTime)"
            $lines += "Safe Mode: $script:safeModeActive"
            $lines += "Consecutive Failures: $($script:toggleFailCount)"
            $lines += ""
            $lines += "Settings Snapshot:"
            $snapshot = Get-SettingsSnapshot $settings
            foreach ($key in ($snapshot.Keys | Sort-Object)) {
                $lines += "  $key = $($snapshot[$key])"
            }
            $lines += ""
            $lines += "Last Errors:"
            if ($script:LastErrorMessage) {
                $lines += ("  {0} - {1}" -f (Format-DateTime $script:LastErrorTime), $script:LastErrorMessage)
            } else {
                $lines += "  None"
            }
            $lines += ""
            $lines += "Recent Errors:"
            if ($script:RecentErrors.Count -gt 0) {
                foreach ($entry in $script:RecentErrors) {
                    $lines += ("  {0} [{1}] {2}" -f (Format-DateTime $entry.Time), $entry.Context, $entry.Message)
                }
            } else {
                $lines += "  None"
            }
            $lines += ""
            $lines += "Recent Actions:"
            $lines += (Get-RecentActionsLines)
            $lines += ""
            $lines += "Date/Time Format: " + (if ($settings.UseSystemDateTimeFormat) { "System ($($settings.SystemDateTimeFormatMode))" } else { [string]$settings.DateTimeFormat })
            $lines += ""
            if ($settings.ScrubDiagnostics) {
                $lines = Scrub-LogLines $lines
            }
            $lines | Set-Content -Path $dialog.FileName -Encoding UTF8
            $exportSize = 0
            try { $exportSize = (Get-Item -Path $dialog.FileName).Length } catch { }
            Write-Log "Exported diagnostics to $($dialog.FileName) ($exportSize bytes)." "INFO" $null "Export-Diagnostics"
        }
    })
    $script:ExportDiagnosticsButton = $exportDiagnosticsButton

    $copyDiagnosticsButton = New-Object System.Windows.Forms.Button
    $copyDiagnosticsButton.Text = "Copy Diagnostics"
    $copyDiagnosticsButton.Width = 140
    $copyDiagnosticsButton.Add_Click({
        & $script:RunSettingsAction "Copy Diagnostics" {
            $lines = @()
            $lines += "Teams-Always-Green Diagnostics"
            $lines += "Generated: $(Format-DateTime (Get-Date))"
            $lines += ""
            $lines += "Version: $appVersion"
            $lines += "Last Updated: $appLastUpdated"
            $lines += "Script Path: $scriptPath"
            $lines += ""
            $lines += "Session: $script:SessionId"
            $lines += "Uptime: $([int]((Get-Date) - $script:AppStartTime).TotalMinutes) min"
            $lines += "State: $($script:StatusStateText)"
            $lines += "Running: $script:isRunning"
            $lines += "Paused: $script:isPaused"
            $lines += "Paused Until: $($settings.PauseUntil)"
            $lines += "Schedule: $(Format-ScheduleStatus)"
            $lines += "Schedule Suspended: $script:isScheduleSuspended"
            $lines += "Next Toggle: $(Format-NextInfo)"
            $lines += "Toggle Count: $($script:tickCount)"
            $lines += "Last Toggle: $($script:lastToggleTime)"
            $lines += "Last Toggle Result: $($script:LastToggleResult)"
            $lines += "Last Toggle Result Time: $($script:LastToggleResultTime)"
            $lines += "Last Toggle Error: $($script:LastToggleError)"
            $lines += "Last Restart: $($script:LastRestartTime)"
            $logSizeBytes = 0
            if (Test-Path $logPath) {
                try { $logSizeBytes = (Get-Item -Path $logPath).Length } catch { $logSizeBytes = 0 }
            }
            $lines += "Log Path: $logPath"
            $lines += "Log Size: $logSizeBytes bytes"
            $lines += "Log Rotations: $($script:LogRotationCount)"
            $lines += "Last Log Write: $($script:LastLogWriteTime)"
            $lines += "Safe Mode: $script:safeModeActive"
            $lines += "Consecutive Failures: $($script:toggleFailCount)"
            $lines += ""
            $lines += "Settings Snapshot:"
            $snapshot = Get-SettingsSnapshot $settings
            foreach ($key in ($snapshot.Keys | Sort-Object)) {
                $lines += "  $key = $($snapshot[$key])"
            }
            $lines += ""
            $lines += "Recent Actions:"
            $lines += (Get-RecentActionsLines)
            if ($settings.ScrubDiagnostics) {
                $lines = Scrub-LogLines $lines
            }
            $text = $lines -join "`r`n"
            [System.Windows.Forms.Clipboard]::SetText($text)
            Write-Log "Diagnostics copied to clipboard (lines=$($lines.Count))." "INFO" $null "Diagnostics"
        }
    })
    $script:CopyDiagnosticsButton = $copyDiagnosticsButton

    $scrubDiagnosticsBox = New-Object System.Windows.Forms.CheckBox
    $scrubDiagnosticsBox.Text = "Scrub diagnostics (redact user paths)"
    $scrubDiagnosticsBox.AutoSize = $true
    $scrubDiagnosticsBox.Tag = "Scrub Diagnostics"
    $script:ScrubDiagnosticsBox = $scrubDiagnosticsBox

    $debugModeButton.Add_Click({
        Enable-DebugMode
    })

    $reportIssueButton = New-Object System.Windows.Forms.Button
    $reportIssueButton.Text = "Report Issue..."
    $reportIssueButton.Width = 140

    $reportIssueButton.Add_Click({
        & $script:RunSettingsAction "Report Issue" {
            $dialog = New-Object System.Windows.Forms.SaveFileDialog
            $dialog.Title = "Report Issue"
            $dialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
            $dialog.FileName = "Teams-Always-Green.issue.txt"
            if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
            $lines = @()
            $lines += "Teams-Always-Green Issue Report"
            $lines += "Generated: $(Format-DateTime (Get-Date))"
            $lines += ""
            $lines += "Diagnostics:"
            $lines += "Version: $appVersion"
            $lines += "Last Updated: $appLastUpdated"
            $lines += "Script Path: $scriptPath"
            $lines += "Session: $script:SessionId"
            $lines += "Uptime: $([int]((Get-Date) - $script:AppStartTime).TotalMinutes) min"
            $lines += "State: $($script:StatusStateText)"
            $lines += "Schedule: $(Format-ScheduleStatus)"
            $lines += "Safe Mode: $script:safeModeActive"
            $logSizeBytes = 0
            if (Test-Path $logPath) {
                try { $logSizeBytes = (Get-Item -Path $logPath).Length } catch { $logSizeBytes = 0 }
            }
            $lines += "Log Path: $logPath"
            $lines += "Log Size: $logSizeBytes bytes"
            $lines += "Log Rotations: $($script:LogRotationCount)"
            $lines += "Last Log Write: $($script:LastLogWriteTime)"
            $lines += ""
            $lines += "Recent Actions:"
            $lines += (Get-RecentActionsLines)
            $lines += ""
            $lines += "Last 200 Log Lines:"
            if (Test-Path $logPath) {
                $lines += Get-Content -Path $logPath -Tail 200
            } else {
                $lines += "Log file not found."
            }
            if ($settings.ScrubDiagnostics) {
                $lines = Scrub-LogLines $lines
            }
            $lines | Set-Content -Path $dialog.FileName -Encoding UTF8
            $reportSize = 0
            try { $reportSize = (Get-Item -Path $dialog.FileName).Length } catch { }
            Write-Log "Exported issue report to $($dialog.FileName) ($reportSize bytes)." "INFO" $null "Diagnostics"
        }
    })
    $script:ReportIssueButton = $reportIssueButton

    $logSizeValue = New-Object System.Windows.Forms.Label
    $logSizeValue.Text = "N/A"
    $logSizeValue.AutoSize = $true
    $logSizeValue.Tag = "Log Size"
    $logSizeValue.Margin = New-Object System.Windows.Forms.Padding(8, 4, 0, 0)

    $diagnosticsGroup = New-Object System.Windows.Forms.GroupBox
    $diagnosticsGroup.Text = "Diagnostics"
    $diagnosticsGroup.AutoSize = $true
    $diagnosticsGroup.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $diagnosticsGroup.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)
    $script:DiagnosticsGroup = $diagnosticsGroup

    $diagnosticsLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $diagnosticsLayout.ColumnCount = 2
    $diagnosticsLayout.RowCount = 8
    $diagnosticsLayout.AutoSize = $true
    $diagnosticsLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $diagnosticsLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $diagErrorLabel = New-Object System.Windows.Forms.Label
    $diagErrorLabel.Text = "Last Error"
    $diagErrorLabel.AutoSize = $true

    $diagErrorValue = New-Object System.Windows.Forms.Label
    $diagErrorValue.Text = "None"
    $diagErrorValue.AutoSize = $true

    $diagRestartLabel = New-Object System.Windows.Forms.Label
    $diagRestartLabel.Text = "Last Restart"
    $diagRestartLabel.AutoSize = $true

    $diagRestartValue = New-Object System.Windows.Forms.Label
    $diagRestartValue.Text = "N/A"
    $diagRestartValue.AutoSize = $true

    $diagSafeModeLabel = New-Object System.Windows.Forms.Label
    $diagSafeModeLabel.Text = "Safe Mode"
    $diagSafeModeLabel.AutoSize = $true

    $diagSafeModeValue = New-Object System.Windows.Forms.Label
    $diagSafeModeValue.Text = "Off"
    $diagSafeModeValue.AutoSize = $true

    $diagLastToggleLabel = New-Object System.Windows.Forms.Label
    $diagLastToggleLabel.Text = "Last Toggle"
    $diagLastToggleLabel.AutoSize = $true

    $diagLastToggleValue = New-Object System.Windows.Forms.Label
    $diagLastToggleValue.Text = "None"
    $diagLastToggleValue.AutoSize = $true

    $diagFailLabel = New-Object System.Windows.Forms.Label
    $diagFailLabel.Text = "Consecutive Fails"
    $diagFailLabel.AutoSize = $true

    $diagFailValue = New-Object System.Windows.Forms.Label
    $diagFailValue.Text = "0"
    $diagFailValue.AutoSize = $true

    $diagLogSizeLabel = New-Object System.Windows.Forms.Label
    $diagLogSizeLabel.Text = "Log Size"
    $diagLogSizeLabel.AutoSize = $true

    $diagLogSizeValue = New-Object System.Windows.Forms.Label
    $diagLogSizeValue.Text = "N/A"
    $diagLogSizeValue.AutoSize = $true

    $diagLogRotateLabel = New-Object System.Windows.Forms.Label
    $diagLogRotateLabel.Text = "Log Rotations"
    $diagLogRotateLabel.AutoSize = $true

    $diagLogRotateValue = New-Object System.Windows.Forms.Label
    $diagLogRotateValue.Text = "0"
    $diagLogRotateValue.AutoSize = $true

    $diagLogWriteLabel = New-Object System.Windows.Forms.Label
    $diagLogWriteLabel.Text = "Last Log Write"
    $diagLogWriteLabel.AutoSize = $true

    $diagLogWriteValue = New-Object System.Windows.Forms.Label
    $diagLogWriteValue.Text = "N/A"
    $diagLogWriteValue.AutoSize = $true

    $diagnosticsLayout.Controls.Add($diagErrorLabel, 0, 0)
    $diagnosticsLayout.Controls.Add($diagErrorValue, 1, 0)
    $diagnosticsLayout.Controls.Add($diagRestartLabel, 0, 1)
    $diagnosticsLayout.Controls.Add($diagRestartValue, 1, 1)
    $diagnosticsLayout.Controls.Add($diagSafeModeLabel, 0, 2)
    $diagnosticsLayout.Controls.Add($diagSafeModeValue, 1, 2)
    $diagnosticsLayout.Controls.Add($diagLastToggleLabel, 0, 3)
    $diagnosticsLayout.Controls.Add($diagLastToggleValue, 1, 3)
    $diagnosticsLayout.Controls.Add($diagFailLabel, 0, 4)
    $diagnosticsLayout.Controls.Add($diagFailValue, 1, 4)
    $diagnosticsLayout.Controls.Add($diagLogSizeLabel, 0, 5)
    $diagnosticsLayout.Controls.Add($diagLogSizeValue, 1, 5)
    $diagnosticsLayout.Controls.Add($diagLogRotateLabel, 0, 6)
    $diagnosticsLayout.Controls.Add($diagLogRotateValue, 1, 6)
    $diagnosticsLayout.Controls.Add($diagLogWriteLabel, 0, 7)
    $diagnosticsLayout.Controls.Add($diagLogWriteValue, 1, 7)
    $diagnosticsGroup.Controls.Add($diagnosticsLayout)

    $logCategoryGroup = New-Object System.Windows.Forms.GroupBox
    $logCategoryGroup.Text = "Log Categories"
    $logCategoryGroup.AutoSize = $true
    $logCategoryGroup.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $logCategoryGroup.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)
    $script:LogCategoryGroup = $logCategoryGroup

    $logCategoryPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $logCategoryPanel.FlowDirection = "LeftToRight"
    $logCategoryPanel.WrapContents = $true
    $logCategoryPanel.AutoSize = $true
    $logCategoryPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink

    $script:logCategoryBoxes = @{}
    foreach ($name in $script:LogCategoryNames) {
        $box = New-Object System.Windows.Forms.CheckBox
        $box.Text = $name
        $box.AutoSize = $true
        $box.Checked = [bool]$script:LogCategories[$name]
        $script:logCategoryBoxes[$name] = $box
        $logCategoryPanel.Controls.Add($box) | Out-Null
    }
    $logCategoryGroup.Controls.Add($logCategoryPanel)

    $validateHotkeysButton = New-Object System.Windows.Forms.Button
    $validateHotkeysButton.Text = "Validate Hotkeys"
    $validateHotkeysButton.Width = 140
    $validateHotkeysButton.Add_Click({
        $results = @()
        $entries = @(
            @{ Name = "Toggle Now"; Value = [string]$script:hotkeyToggleBox.Text },
            @{ Name = "Start/Stop"; Value = [string]$script:hotkeyStartStopBox.Text },
            @{ Name = "Pause/Resume"; Value = [string]$script:hotkeyPauseResumeBox.Text }
        )
        foreach ($entry in $entries) {
            $value = [string]$entry.Value
            if ([string]::IsNullOrWhiteSpace($value)) {
                $results += "{0}: Disabled" -f $entry.Name
                continue
            }
            $isValid = Validate-HotkeyString $value
            $results += "{0}: {1} ({2})" -f $entry.Name, ($(if ($isValid) { "OK" } else { "Invalid" })), $value
        }
        [System.Windows.Forms.MessageBox]::Show(
            ($results -join "`n"),
            "Hotkey Validation",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    })

    $simulateHotkeysPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $simulateHotkeysPanel.FlowDirection = "LeftToRight"
    $simulateHotkeysPanel.AutoSize = $true
    $simulateHotkeysPanel.WrapContents = $true

    $simulateToggleButton = New-Object System.Windows.Forms.Button
    $simulateToggleButton.Text = "Toggle Now"
    $simulateToggleButton.Width = 110
    $script:SimulateToggleButton = $simulateToggleButton
    $simulateToggleButton.Add_Click({
        Set-LastUserAction "Test Hotkey: Toggle Now" "Settings"
        Write-Log "UI: Simulated hotkey: Toggle Now" "DEBUG" $null "Hotkey-Test"
        Do-Toggle "hotkey-test"
    })

    $simulateStartStopButton = New-Object System.Windows.Forms.Button
    $simulateStartStopButton.Text = "Start/Stop"
    $simulateStartStopButton.Width = 110
    $script:SimulateStartStopButton = $simulateStartStopButton
    $simulateStartStopButton.Add_Click({
        Set-LastUserAction "Test Hotkey: Start/Stop" "Settings"
        Write-Log "UI: Simulated hotkey: Start/Stop" "DEBUG" $null "Hotkey-Test"
        if ($script:isRunning) { Stop-Toggling } else { Start-Toggling }
    })

    $simulatePauseResumeButton = New-Object System.Windows.Forms.Button
    $simulatePauseResumeButton.Text = "Pause/Resume"
    $simulatePauseResumeButton.Width = 120
    $script:SimulatePauseResumeButton = $simulatePauseResumeButton
    $simulatePauseResumeButton.Add_Click({
        Set-LastUserAction "Test Hotkey: Pause/Resume" "Settings"
        Write-Log "UI: Simulated hotkey: Pause/Resume" "DEBUG" $null "Hotkey-Test"
        if ($script:isPaused) {
            Start-Toggling
        } else {
            $durations = Get-PauseDurations
            if ($durations.Count -gt 0) { Pause-Toggling ([int]$durations[0]) }
        }
    })

    $simulateHotkeysPanel.Controls.Add($simulateToggleButton) | Out-Null
    $simulateHotkeysPanel.Controls.Add($simulateStartStopButton) | Out-Null
    $simulateHotkeysPanel.Controls.Add($simulatePauseResumeButton) | Out-Null

    $getTabPanel = {
        param([string]$title)
        $page = if ($script:GetSettingsTabPage) { & $script:GetSettingsTabPage $title } else { $null }
        if (-not $page) { return $null }
        if ([string]::IsNullOrWhiteSpace([string]$page.Tag)) { $page.Tag = $title }
        if ([string]::IsNullOrWhiteSpace([string]$page.Name)) { $page.Name = $title }
        $panel = $page.Controls | Where-Object { $_ -is [System.Windows.Forms.TableLayoutPanel] } | Select-Object -First 1
        if ($panel) { return $panel }
        $panel = New-Object System.Windows.Forms.TableLayoutPanel
        $panel.ColumnCount = 2
        $panel.RowCount = 0
        $panel.AutoSize = $true
        $panel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $panel.Dock = "Top"
        $panel.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::AddRows
        $panel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
        $panel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
        $page.Controls.Add($panel)
        return $panel
    }

    $statusPanel = & $getTabPanel "Status"
    $generalPanel = & $getTabPanel "General"
    $schedulePanel = & $getTabPanel "Scheduling"
    $hotkeyPanel = & $getTabPanel "Hotkeys"
    $loggingPanel = & $getTabPanel "Logging"
    $profilesPanel = & $getTabPanel "Profiles"
    $diagnosticsPanel = & $getTabPanel "Diagnostics"
    $advancedPanel = & $getTabPanel "Advanced"
    $appearancePanel = & $getTabPanel "Appearance"
    $aboutPanel = & $getTabPanel "About"

    $script:SettingsTabPanels = @{
        Status = $statusPanel
        General = $generalPanel
        Scheduling = $schedulePanel
        Hotkeys = $hotkeyPanel
        Logging = $loggingPanel
        Profiles = $profilesPanel
        Appearance = $appearancePanel
        Diagnostics = $diagnosticsPanel
        Advanced = $advancedPanel
        About = $aboutPanel
    }

    $script:ApplySettingsSearchFilter = {
        param([string]$text)
        $needle = if ($text) { $text.Trim().ToLowerInvariant() } else { "" }
        if ($script:SettingsSearchLast -eq $needle) { return }
        $script:SettingsSearchLast = $needle
        foreach ($panel in $script:SettingsTabPanels.Values) {
            if (-not $panel) { continue }
            $hasMatch = $false
            $headerControls = @()
            foreach ($control in $panel.Controls) {
                $tagText = [string]$control.Tag
                if ($tagText -like "Header:*") {
                    $headerControls += $control
                    continue
                }
                if ([string]::IsNullOrWhiteSpace($needle)) {
                    $control.Visible = $true
                    continue
                }
                if ($tagText -eq "Spacer") {
                    $control.Visible = $false
                    continue
                }
                if ([string]::IsNullOrWhiteSpace($tagText)) {
                    $control.Visible = $true
                    $hasMatch = $true
                    continue
                }
                if ($tagText.ToLowerInvariant().Contains($needle)) {
                    $control.Visible = $true
                    $hasMatch = $true
                } else {
                    $control.Visible = $false
                }
            }
            foreach ($header in $headerControls) {
                $header.Visible = ([string]::IsNullOrWhiteSpace($needle) -or $hasMatch)
            }
        }
        if ($script:UpdateTabLayouts) { & $script:UpdateTabLayouts }
    }

    & $addSectionHeader $generalPanel "General"
    & $addSectionHeader $schedulePanel "Scheduling"
    & $addSectionHeader $loggingPanel "Logging"
    & $addSectionHeader $statusPanel "Status"
    & $addSectionHeader $hotkeyPanel "Hotkeys"
    & $addSectionHeader $profilesPanel "Profiles"
    & $addSectionHeader $appearancePanel "Appearance"
    & $addSectionHeader $diagnosticsPanel "Diagnostics"
    & $addSectionHeader $advancedPanel "Advanced"
    & $addSectionHeader $aboutPanel "About"

    $updateTabLayouts = {
        $updatePanelWidth = $null
        $updatePanelWidth = {
            param($control, [int]$maxWidth)
            if (-not $control) { return }
            if ($control -is [System.Windows.Forms.FlowLayoutPanel]) {
                $control.MaximumSize = New-Object System.Drawing.Size($maxWidth, 0)
                $control.Width = $maxWidth
            }
            foreach ($child in $control.Controls) {
                & $updatePanelWidth $child $maxWidth
            }
        }
        $targetTabControl = $script:SettingsTabControl
        if (-not $targetTabControl) { return }
        $sizeKey = "{0}x{1}" -f $targetTabControl.Width, $targetTabControl.Height
        if (-not $script:SettingsLayoutDirty -and $script:SettingsLayoutLast -eq $sizeKey) { return }
        $script:SettingsLayoutLast = $sizeKey
        $script:SettingsLayoutDirty = $false
        foreach ($page in $targetTabControl.TabPages) {
            $targetWidth = [Math]::Max(200, $page.ClientSize.Width - 30)
            & $updatePanelWidth $page $targetWidth
        }

        if ($script:AboutPanel -and $script:AboutPanel.Parent) {
            $panelWidth = [Math]::Max(320, $script:AboutPanel.Parent.ClientSize.Width - 30)
            if ($script:AboutGroup) {
                $script:AboutGroup.MinimumSize = New-Object System.Drawing.Size($panelWidth, 0)
                $script:AboutGroup.Width = $panelWidth
            }
            if ($script:AboutLayout) {
                $layoutWidth = [Math]::Max(320, $panelWidth - 20)
                $script:AboutLayout.AutoSize = $true
                $script:AboutLayout.Width = $layoutWidth
                $script:AboutLayout.MinimumSize = New-Object System.Drawing.Size($layoutWidth, 0)
                $script:AboutLayout.MaximumSize = New-Object System.Drawing.Size($layoutWidth, 0)
            }
            $valueWidth = [Math]::Max(260, $panelWidth - 120)
            if ($script:AboutTitleLabel) {
                $script:AboutTitleLabel.MaximumSize = New-Object System.Drawing.Size($valueWidth, 0)
            }
            if ($script:AboutDescValue -and $script:AboutPathValue) {
                $script:AboutDescValue.MaximumSize = New-Object System.Drawing.Size($valueWidth, 0)
                $script:AboutPathValue.MaximumSize = New-Object System.Drawing.Size($valueWidth, 0)
            }
        }
        if ($script:logDirectoryPanel -and $script:logDirectoryBox -and $script:logDirectoryBrowseButton) {
            $available = [Math]::Max(140, $script:logDirectoryPanel.Width - $script:logDirectoryBrowseButton.Width - 12)
            if ($script:logDirectoryBox.Width -ne $available) {
                $script:logDirectoryBox.Width = $available
            }
        }
        if ($script:logFilesLabel -and $script:SettingsLoggingPanel -and $script:SettingsLoggingPanel.Parent) {
            $labelWidth = [Math]::Max(200, $script:SettingsLoggingPanel.Parent.ClientSize.Width - 180)
            $script:logFilesLabel.MaximumSize = New-Object System.Drawing.Size($labelWidth, 0)
        }
    }
    $script:UpdateTabLayouts = $updateTabLayouts

    $script:SettingsTabBuildPending = $false
    $tabControl.Add_SelectedIndexChanged({
        if (-not $script:SettingsTabControl.SelectedTab) { return }
        if ($script:SettingsTabBuildPending) { return }
        $script:SettingsTabBuildPending = $true
        $script:SettingsForm.BeginInvoke([Action]{
            try {
                if (-not $script:SettingsTabControl.SelectedTab) { return }
                $title = if ($script:GetSettingsTabKey) { & $script:GetSettingsTabKey $script:SettingsTabControl.SelectedTab } else { [string]$script:SettingsTabControl.SelectedTab.Text }
                if ($title -eq "Profiles") {
                    if ($script:BuildProfilesTab) { & $script:BuildProfilesTab }
                } elseif ($title -eq "Diagnostics") {
                    if ($script:BuildDiagnosticsTab) { & $script:BuildDiagnosticsTab }
                } elseif ($title -eq "Logging") {
                    if ($script:BuildLoggingTab) { & $script:BuildLoggingTab }
                } elseif ($title -eq "About") {
                    if ($script:BuildAboutTab) { & $script:BuildAboutTab }
                }
            } finally {
                $script:SettingsTabBuildPending = $false
            }
        }) | Out-Null
    })

    $profileGroup = New-Object System.Windows.Forms.GroupBox
    $profileGroup.Text = "Profiles"
    $profileGroup.AutoSize = $true
    $profileGroup.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $profileGroup.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)
    $profileGroup.Tag = "Profiles"
    $script:ProfileGroup = $profileGroup

    $aboutGroup = New-Object System.Windows.Forms.GroupBox
    $aboutGroup.Text = "About"
    $aboutGroup.AutoSize = $true
    $aboutGroup.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $aboutGroup.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)
    $aboutGroup.Tag = "About"
    $aboutGroup.Dock = "Top"
    $aboutGroup.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)

    $aboutLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $aboutLayout.ColumnCount = 2
    $aboutLayout.RowCount = 20
    $aboutLayout.AutoSize = $true
    $aboutLayout.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $aboutLayout.Dock = "Top"
    $aboutLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $aboutLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $script:AboutGroup = $aboutGroup
    $script:AboutLayout = $aboutLayout

    $aboutTitlePanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $aboutTitlePanel.AutoSize = $true
    $aboutTitlePanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $aboutTitlePanel.WrapContents = $false
    $aboutTitlePanel.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
    $aboutTitlePanel.Dock = "Top"

    $aboutTitleIconPath = Join-Path $script:DataRoot "Meta\\Icons\\Tray_Icon.ico"
    if (Test-Path $aboutTitleIconPath) {
        try {
            $aboutTitleIcon = New-Object System.Drawing.Icon($aboutTitleIconPath)
            $aboutTitleIconBox = New-Object System.Windows.Forms.PictureBox
            $aboutTitleIconBox.Size = New-Object System.Drawing.Size(20, 20)
            $aboutTitleIconBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage
            $aboutTitleIconBox.Image = $aboutTitleIcon.ToBitmap()
            $aboutTitlePanel.Controls.Add($aboutTitleIconBox) | Out-Null
        } catch {
        }
    }

    $aboutTitleLabel = New-Object System.Windows.Forms.Label
    $aboutTitleLabel.Text = "Teams-Always-Green"
    $aboutTitleLabel.AutoSize = $true
    $aboutTitleLabel.Font = New-Object System.Drawing.Font($aboutTitleLabel.Font.FontFamily, 14, [System.Drawing.FontStyle]::Bold)
    $aboutTitleLabel.Margin = New-Object System.Windows.Forms.Padding(6, 0, 0, 0)
    $aboutTitlePanel.Controls.Add($aboutTitleLabel) | Out-Null
    $script:AboutTitleLabel = $aboutTitleLabel
    $script:AboutTitleText = $aboutTitleLabel.Text

    $aboutDescLabel = New-Object System.Windows.Forms.Label
    $aboutDescLabel.Text = "Overview"
    $aboutDescLabel.AutoSize = $true

    $aboutDescValue = New-Object System.Windows.Forms.Label
    $aboutDescValue.Text = "Keeps Microsoft Teams active by periodically toggling Scroll Lock. Runs quietly in the tray with simple controls, scheduling, and profiles so you stay available without micromanaging your status."
    $aboutDescValue.Tag = "About Overview"
    $aboutDescValue.AutoSize = $true
    $aboutDescValue.MaximumSize = New-Object System.Drawing.Size(460, 0)
    $script:AboutDescValue = $aboutDescValue
    $script:AboutOverviewText = $aboutDescValue.Tag

    $aboutVersionLabel = New-Object System.Windows.Forms.Label
    $aboutVersionLabel.Text = "Version"
    $aboutVersionLabel.AutoSize = $true

    $aboutVersionValue = New-Object System.Windows.Forms.Label
    $aboutVersionValue.Text = $appVersion
    $aboutVersionValue.AutoSize = $true
    $script:AboutVersionValue = $aboutVersionValue

    $aboutBuildLabel = New-Object System.Windows.Forms.Label
    $aboutBuildLabel.Text = "Build"
    $aboutBuildLabel.AutoSize = $true

    $buildTimestampValue = "Unknown"
    if ($appBuildTimestamp) {
        $buildTimestampValue = $appBuildTimestamp.ToString("yyyy-MM-dd HH:mm")
    }
    $aboutBuildValue = New-Object System.Windows.Forms.Label
    $aboutBuildValue.Text = "{0} ({1})" -f $appBuildId, $buildTimestampValue
    $aboutBuildValue.AutoSize = $true
    $script:AboutBuildValue = $aboutBuildValue

    $aboutUpdatedLabel = New-Object System.Windows.Forms.Label
    $aboutUpdatedLabel.Text = "Last Updated"
    $aboutUpdatedLabel.AutoSize = $true

    $aboutUpdatedValue = New-Object System.Windows.Forms.Label
    $aboutUpdatedValue.Text = $appLastUpdated
    $aboutUpdatedValue.AutoSize = $true
    $script:AboutUpdatedValue = $aboutUpdatedValue

    $aboutPathLabel = New-Object System.Windows.Forms.Label
    $aboutPathLabel.Text = "Script Path"
    $aboutPathLabel.AutoSize = $true

    $aboutPathValue = New-Object System.Windows.Forms.Label
    $aboutPathValue.Text = $scriptPath
    $aboutPathValue.AutoSize = $true
    $script:AboutPathValue = $aboutPathValue

    $aboutLatestLabel = New-Object System.Windows.Forms.Label
    $aboutLatestLabel.Text = "Latest Release"
    $aboutLatestLabel.AutoSize = $true

    $aboutLatestValue = New-Object System.Windows.Forms.Label
    $aboutLatestValue.Text = "Unknown (check)"
    $aboutLatestValue.AutoSize = $true
    $script:AboutLatestReleaseValue = $aboutLatestValue

    $aboutCheckedLabel = New-Object System.Windows.Forms.Label
    $aboutCheckedLabel.Text = "Last Checked"
    $aboutCheckedLabel.AutoSize = $true

    $aboutCheckedValue = New-Object System.Windows.Forms.Label
    $aboutCheckedValue.Text = "Never"
    $aboutCheckedValue.AutoSize = $true
    $script:AboutCheckedValue = $aboutCheckedValue

    $updateAboutChecked = {
        param([datetime]$checkedUtc)
        if (-not $script:AboutCheckedValue) { return }
        if (-not $checkedUtc) {
            $script:AboutCheckedValue.Text = "Never"
            return
        }
        $local = [DateTime]::SpecifyKind($checkedUtc, [DateTimeKind]::Utc).ToLocalTime()
        $ageSeconds = ([DateTime]::UtcNow - $checkedUtc).TotalSeconds
        if ($ageSeconds -lt 60) {
            $script:AboutCheckedValue.Text = "Checked just now (" + $local.ToString("t") + ")"
        } else {
            $script:AboutCheckedValue.Text = "Checked " + $local.ToString("g")
        }
    }

    if ($script:UpdateCache.LatestVersion -and $script:AboutLatestReleaseValue) {
        $script:AboutLatestReleaseValue.Text = $script:UpdateCache.LatestVersion
    }
    if ($script:UpdateCache.CheckedAt) { & $updateAboutChecked $script:UpdateCache.CheckedAt }

    $aboutCheckPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $aboutCheckLabel = New-Object System.Windows.Forms.Label
    $aboutCheckLabel.Text = "Check Updates"
    $aboutCheckLabel.AutoSize = $true
    $aboutCheckLabel.Margin = New-Object System.Windows.Forms.Padding(0, 6, 0, 0)

    $aboutCheckPanel.AutoSize = $true
    $aboutCheckPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $aboutCheckPanel.WrapContents = $false
    $aboutCheckPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
    $aboutCheckPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Left

    $aboutCheckButton = New-Object System.Windows.Forms.Button
    $aboutCheckButton.Text = "Check Now"
    $aboutCheckButton.AutoSize = $true
    $aboutCheckButton.Margin = New-Object System.Windows.Forms.Padding(0, 0, 6, 0)
    $aboutCheckButton.Add_Click({
        $release = Get-LatestReleaseCached "alexphillips-dev" "Teams-Always-Green" -Force
        if ($release) {
            $latestVersion = Get-ReleaseVersionString $release
            if (-not [string]::IsNullOrWhiteSpace($latestVersion) -and $script:AboutLatestReleaseValue) {
                $script:AboutLatestReleaseValue.Text = $latestVersion
            }
        }
        if ($script:UpdateCache.CheckedAt) { & $updateAboutChecked $script:UpdateCache.CheckedAt }
        Invoke-UpdateCheck -Force
    })

    $aboutReleaseLink = New-Object System.Windows.Forms.LinkLabel
    $aboutReleaseLink.Text = "GitHub Releases"
    $aboutReleaseLink.AutoSize = $true
    $aboutReleaseLink.LinkBehavior = [System.Windows.Forms.LinkBehavior]::HoverUnderline
    $aboutReleaseLink.Margin = New-Object System.Windows.Forms.Padding(6, 6, 0, 0)
    $aboutReleaseLink.Add_LinkClicked({
        Start-Process "https://github.com/alexphillips-dev/Teams-Always-Green/releases"
    })

    $aboutCheckPanel.Controls.Add($aboutCheckButton)
    $aboutCheckPanel.Controls.Add($aboutReleaseLink)

    $aboutSpacer1 = New-Object System.Windows.Forms.Label
    $aboutSpacer1.Text = ""
    $aboutSpacer1.AutoSize = $false
    $aboutSpacer1.Height = 8

    $aboutSpacer2 = New-Object System.Windows.Forms.Label
    $aboutSpacer2.Text = ""
    $aboutSpacer2.AutoSize = $false
    $aboutSpacer2.Height = 8

    $aboutSpacer3 = New-Object System.Windows.Forms.Label
    $aboutSpacer3.Text = ""
    $aboutSpacer3.AutoSize = $false
    $aboutSpacer3.Height = 8

    $aboutSpacer4 = New-Object System.Windows.Forms.Label
    $aboutSpacer4.Text = ""
    $aboutSpacer4.AutoSize = $false
    $aboutSpacer4.Height = 8

    $aboutSpacer5 = New-Object System.Windows.Forms.Label
    $aboutSpacer5.Text = ""
    $aboutSpacer5.AutoSize = $false
    $aboutSpacer5.Height = 8

    $aboutSpacer6 = New-Object System.Windows.Forms.Label
    $aboutSpacer6.Text = ""
    $aboutSpacer6.AutoSize = $false
    $aboutSpacer6.Height = 8

    $aboutSupportLabel = New-Object System.Windows.Forms.Label
    $aboutSupportLabel.Text = "Support"
    $aboutSupportLabel.AutoSize = $true

    $aboutSupportLink = New-Object System.Windows.Forms.LinkLabel
    $aboutSupportLink.Text = "Report Issue"
    $aboutSupportLink.AutoSize = $true
    $aboutSupportLink.LinkBehavior = [System.Windows.Forms.LinkBehavior]::HoverUnderline
    $aboutSupportLink.Add_LinkClicked({
        Start-Process "https://github.com/alexphillips-dev/Teams-Always-Green/issues"
    })
    $script:AboutSupportLink = $aboutSupportLink
    $script:AboutSupportLinkText = $aboutSupportLink.Text


    $aboutDevLabel = New-Object System.Windows.Forms.Label
    $aboutDevLabel.Text = "Developed by"
    $aboutDevLabel.AutoSize = $true

    $aboutDevValue = New-Object System.Windows.Forms.Label
    $aboutDevValue.Text = "Alex Phillips"
    $aboutDevValue.AutoSize = $true
    $script:AboutDevValue = $aboutDevValue
    $script:AboutDeveloperText = $aboutDevValue.Text

    $aboutPartLabel = New-Object System.Windows.Forms.Label
    $aboutPartLabel.Text = "In Part By"
    $aboutPartLabel.AutoSize = $true

    $aboutPartValue = New-Object System.Windows.Forms.Label
    $aboutPartValue.Text = "GPT-5.2-Codex"
    $aboutPartValue.AutoSize = $true
    $script:AboutPartValue = $aboutPartValue
    $script:AboutPartText = $aboutPartValue.Text

    $aboutLayout.Controls.Add($aboutTitlePanel, 0, 0)
    $aboutLayout.SetColumnSpan($aboutTitlePanel, 2)
    $aboutLayout.Controls.Add($aboutSpacer1, 0, 1)
    $aboutLayout.SetColumnSpan($aboutSpacer1, 2)
    $aboutLayout.Controls.Add($aboutDescLabel, 0, 2)
    $aboutLayout.Controls.Add($aboutDescValue, 1, 2)
    $aboutLayout.Controls.Add($aboutSpacer2, 0, 3)
    $aboutLayout.SetColumnSpan($aboutSpacer2, 2)
    $aboutLayout.Controls.Add($aboutVersionLabel, 0, 4)
    $aboutLayout.Controls.Add($aboutVersionValue, 1, 4)
    $aboutLayout.Controls.Add($aboutBuildLabel, 0, 5)
    $aboutLayout.Controls.Add($aboutBuildValue, 1, 5)
    $aboutLayout.Controls.Add($aboutSpacer3, 0, 6)
    $aboutLayout.SetColumnSpan($aboutSpacer3, 2)
    $aboutLayout.Controls.Add($aboutUpdatedLabel, 0, 7)
    $aboutLayout.Controls.Add($aboutUpdatedValue, 1, 7)
    $aboutLayout.Controls.Add($aboutSpacer4, 0, 8)
    $aboutLayout.SetColumnSpan($aboutSpacer4, 2)
    $aboutLayout.Controls.Add($aboutPathLabel, 0, 9)
    $aboutLayout.Controls.Add($aboutPathValue, 1, 9)
    $aboutLayout.Controls.Add($aboutSpacer4, 0, 10)
    $aboutLayout.SetColumnSpan($aboutSpacer4, 2)
    $aboutLayout.Controls.Add($aboutLatestLabel, 0, 11)
    $aboutLayout.Controls.Add($aboutLatestValue, 1, 11)
    $aboutLayout.Controls.Add($aboutCheckLabel, 0, 12)
    $aboutLayout.Controls.Add($aboutCheckPanel, 1, 12)
    $aboutLayout.Controls.Add($aboutCheckedLabel, 0, 13)
    $aboutLayout.Controls.Add($aboutCheckedValue, 1, 13)
    $aboutLayout.Controls.Add($aboutSpacer5, 0, 14)
    $aboutLayout.SetColumnSpan($aboutSpacer5, 2)
    $aboutLayout.Controls.Add($aboutSupportLabel, 0, 15)
    $aboutLayout.Controls.Add($aboutSupportLink, 1, 15)
    $aboutLayout.Controls.Add($aboutSpacer6, 0, 16)
    $aboutLayout.SetColumnSpan($aboutSpacer6, 2)
    $aboutLayout.Controls.Add($aboutDevLabel, 0, 17)
    $aboutLayout.Controls.Add($aboutDevValue, 1, 17)
    $aboutLayout.Controls.Add($aboutPartLabel, 0, 18)
    $aboutLayout.Controls.Add($aboutPartValue, 1, 18)
    $aboutGroup.Controls.Add($aboutLayout)
    $script:AboutPanel = $aboutPanel
    $script:UpdateAboutValues = {
        $buildStamp = "Unknown"
        if ($appBuildTimestamp) { $buildStamp = $appBuildTimestamp.ToString("yyyy-MM-dd HH:mm") }
        if ($script:AboutTitleLabel -and $script:AboutTitleText) { $script:AboutTitleLabel.Text = $script:AboutTitleText }
        if ($script:AboutDescValue -and $script:AboutOverviewText) { $script:AboutDescValue.Text = (L $script:AboutOverviewText) }
        if ($script:AboutVersionValue) { $script:AboutVersionValue.Text = $appVersion }
        if ($script:AboutBuildValue) { $script:AboutBuildValue.Text = "{0} ({1})" -f $appBuildId, $buildStamp }
        if ($script:AboutUpdatedValue) { $script:AboutUpdatedValue.Text = $appLastUpdated }
        if ($script:AboutPathValue) { $script:AboutPathValue.Text = $scriptPath }
        if ($script:AboutSupportLink -and $script:AboutSupportLinkText) { $script:AboutSupportLink.Text = $script:AboutSupportLinkText }
        if ($script:AboutDevValue -and $script:AboutDeveloperText) { $script:AboutDevValue.Text = $script:AboutDeveloperText }
        if ($script:AboutPartValue -and $script:AboutPartText) { $script:AboutPartValue.Text = $script:AboutPartText }
    }

    $profileLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $profileLayout.ColumnCount = 2
    $profileLayout.RowCount = 5
    $profileLayout.AutoSize = $true
    $profileLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $profileLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $profileLabel = New-Object System.Windows.Forms.Label
    $profileLabel.Text = "Active Profile"
    $profileLabel.AutoSize = $true
    $profileLabel.Anchor = "Left"

    $script:profileBox = New-Object System.Windows.Forms.ComboBox
    $script:profileBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $script:profileBox.Width = 160

    $profileHintLabel = New-Object System.Windows.Forms.Label
    $profileHintLabel.Text = "Changes apply to the selected profile."
    $profileHintLabel.AutoSize = $true
    $profileHintLabel.ForeColor = [System.Drawing.Color]::Gray

    $script:profileReadOnlyBox = New-Object System.Windows.Forms.CheckBox
    $script:profileReadOnlyBox.Text = "Read-only"
    $script:profileReadOnlyBox.AutoSize = $true
    $script:profileReadOnlyBox.Tag = "Profile Read-only"

    $script:profileDirtyLabel = New-Object System.Windows.Forms.Label
    $script:profileDirtyLabel.Text = "Unsaved profile changes"
    $script:profileDirtyLabel.AutoSize = $true
    $script:profileDirtyLabel.ForeColor = [System.Drawing.Color]::DarkOrange
    $script:profileDirtyLabel.Visible = $false
    $script:profileDirtyLabel.Tag = "Profile Dirty"

    $profileActionsLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $profileActionsLayout.ColumnCount = 1
    $profileActionsLayout.RowCount = 2
    $profileActionsLayout.AutoSize = $true
    $profileActionsLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $manageGroup = New-Object System.Windows.Forms.GroupBox
    $manageGroup.Text = "Manage"
    $manageGroup.AutoSize = $true
    $manageGroup.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $manageGroup.Padding = New-Object System.Windows.Forms.Padding(8, 10, 8, 8)

    $transferGroup = New-Object System.Windows.Forms.GroupBox
    $transferGroup.Text = "Transfer"
    $transferGroup.AutoSize = $true
    $transferGroup.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $transferGroup.Padding = New-Object System.Windows.Forms.Padding(8, 10, 8, 8)

    $manageButtons = New-Object System.Windows.Forms.FlowLayoutPanel
    $manageButtons.FlowDirection = "LeftToRight"
    $manageButtons.WrapContents = $true
    $manageButtons.AutoSize = $true
    $manageButtons.Dock = "Fill"

    $transferButtons = New-Object System.Windows.Forms.FlowLayoutPanel
    $transferButtons.FlowDirection = "LeftToRight"
    $transferButtons.WrapContents = $true
    $transferButtons.AutoSize = $true
    $transferButtons.Dock = "Fill"

    $newProfileButton = New-Object System.Windows.Forms.Button
    $newProfileButton.Text = "New..."
    $newProfileButton.Width = 80

    $renameProfileButton = New-Object System.Windows.Forms.Button
    $renameProfileButton.Text = "Rename..."
    $renameProfileButton.Width = 85

    $deleteProfileButton = New-Object System.Windows.Forms.Button
    $deleteProfileButton.Text = "Delete"
    $deleteProfileButton.Width = 80
    $deleteProfileButton.ForeColor = [System.Drawing.Color]::Tomato

    $exportProfileButton = New-Object System.Windows.Forms.Button
    $exportProfileButton.Text = "Export..."
    $exportProfileButton.Width = 80

    $importProfileButton = New-Object System.Windows.Forms.Button
    $importProfileButton.Text = "Import..."
    $importProfileButton.Width = 80

    $saveProfileButton = New-Object System.Windows.Forms.Button
    $saveProfileButton.Text = "Save"
    $saveProfileButton.Width = 80

    $saveAsProfileButton = New-Object System.Windows.Forms.Button
    $saveAsProfileButton.Text = "Save As..."
    $saveAsProfileButton.Width = 90

    $duplicateProfileButton = New-Object System.Windows.Forms.Button
    $duplicateProfileButton.Text = "Copy As..."
    $duplicateProfileButton.Width = 90

    $loadProfileButton = New-Object System.Windows.Forms.Button
    $loadProfileButton.Text = "Load"
    $loadProfileButton.Width = 80

    $manageButtons.Controls.Add($newProfileButton) | Out-Null
    $manageButtons.Controls.Add($renameProfileButton) | Out-Null
    $manageButtons.Controls.Add($duplicateProfileButton) | Out-Null
    $manageButtons.Controls.Add($deleteProfileButton) | Out-Null

    $transferButtons.Controls.Add($saveProfileButton) | Out-Null
    $transferButtons.Controls.Add($saveAsProfileButton) | Out-Null
    $transferButtons.Controls.Add($loadProfileButton) | Out-Null
    $transferButtons.Controls.Add($exportProfileButton) | Out-Null
    $transferButtons.Controls.Add($importProfileButton) | Out-Null

    $manageGroup.Controls.Add($manageButtons)
    $transferGroup.Controls.Add($transferButtons)

    $profileActionsLayout.Controls.Add($manageGroup, 0, 0)
    $profileActionsLayout.Controls.Add($transferGroup, 0, 1)

    $profileLayout.Controls.Add($profileLabel, 0, 0)
    $profileLayout.Controls.Add($script:profileBox, 1, 0)
    $profileLayout.Controls.Add($profileHintLabel, 1, 1)
    $profileLayout.Controls.Add($script:profileReadOnlyBox, 1, 2)
    $profileLayout.Controls.Add($script:profileDirtyLabel, 1, 3)
    $profileLayout.Controls.Add($profileActionsLayout, 1, 4)
    $profileGroup.Controls.Add($profileLayout)

    $script:refreshProfileList = {
        $script:SettingsIsApplying = $true
        $script:profileBox.Items.Clear()
        $names = @(Get-ObjectKeys $settings.Profiles) | Sort-Object
        foreach ($name in $names) { [void]$script:profileBox.Items.Add($name) }
        $selected = $settings.ActiveProfile
        if (-not [string]::IsNullOrWhiteSpace($selected) -and $script:profileBox.Items.Contains($selected)) {
            $script:profileBox.SelectedItem = $selected
        } elseif ($script:profileBox.Items.Count -gt 0) {
            $script:profileBox.SelectedIndex = 0
        }
        if ($script:profileReadOnlyBox) {
            $profile = $null
            if (-not [string]::IsNullOrWhiteSpace($selected) -and (Get-ObjectKeys $settings.Profiles) -contains $selected) {
                $profile = $settings.Profiles[$selected]
            }
            $script:profileReadOnlyBox.Checked = (Get-ProfileReadOnly $profile)
        }
        $script:SettingsIsApplying = $false
        if ($script:UpdateProfileDirtyIndicator) { & $script:UpdateProfileDirtyIndicator }
    }

    if ($script:SettingsTabControl -and $script:SettingsTabControl.SelectedTab -and ((& $script:GetSettingsTabKey $script:SettingsTabControl.SelectedTab) -eq "Profiles")) {
        & $script:refreshProfileList
        $script:ProfilesTabLoaded = $true
    } else {
        $script:ProfilesTabLoaded = $false
    }

    $script:profileBox.Add_SelectedIndexChanged({
        if ($script:SettingsIsApplying) { return }
        if ($script:profileBox.SelectedItem -eq $null) { return }
        $newName = [string]$script:profileBox.SelectedItem
        if (-not ((Get-ObjectKeys $settings.Profiles) -contains $newName)) { return }
        if ($settings.ActiveProfile -eq $newName) { return }
        $previousName = [string]$settings.ActiveProfile
        if (-not (Confirm-ProfileSwitch $newName $settings.Profiles[$newName])) {
            $script:SettingsIsApplying = $true
            if (-not [string]::IsNullOrWhiteSpace($previousName) -and $script:profileBox.Items.Contains($previousName)) {
                $script:profileBox.SelectedItem = $previousName
            }
            $script:SettingsIsApplying = $false
            return
        }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        if (-not ($settings.Profiles -is [hashtable])) {
            $table = @{}
            foreach ($key in Get-ObjectKeys $settings.Profiles) { $table[$key] = $settings.Profiles.$key }
            $settings.Profiles = $table
        }
        Sync-ActiveProfileSnapshot $settings
        $settings.ActiveProfile = $newName
        $settings = Apply-ProfileSnapshot $settings $settings.Profiles[$newName]
        if ($script:ApplySettingsToControls) { & $script:ApplySettingsToControls $settings }
        if ($script:profileReadOnlyBox) { $script:profileReadOnlyBox.Checked = (Get-ProfileReadOnly $settings.Profiles[$newName]) }
        Set-SettingsDirty $false
        Save-Settings $settings
        if ($updateProfilesMenu) { & $updateProfilesMenu }
        $sw.Stop()
        Write-Log "UI: Profile switched: $newName (ms=$($sw.ElapsedMilliseconds))" "DEBUG" $null "Profiles"
    })

    $script:getProfileFromControls = {
        $profile = [ordered]@{}
        $profile["IntervalSeconds"] = [int]$script:intervalBox.Value
        $profile["RememberChoice"] = [bool]$script:rememberChoiceBox.Checked
        $profile["StartOnLaunch"] = [bool]$script:startOnLaunchBox.Checked
        $profile["RunOnceOnLaunch"] = [bool]$script:runOnceOnLaunchBox.Checked
        $profile["QuietMode"] = [bool]$script:quietModeBox.Checked
        $selectedTooltip = $script:tooltipStyleBox.SelectedItem
        if ($selectedTooltip -and $selectedTooltip.PSObject.Properties.Name -contains "Code") {
            $profile["TooltipStyle"] = [string]$selectedTooltip.Code
        } else {
            $profile["TooltipStyle"] = [string]$selectedTooltip
        }
        $profile["MinimalTrayTooltip"] = ([string]$profile["TooltipStyle"] -eq "Minimal")
        $profile["FontSize"] = [int]$script:fontSizeBox.Value
        $profile["SettingsFontSize"] = [int]$script:settingsFontSizeBox.Value
        $profile["StatusColorRunning"] = Convert-ColorToString $script:statusRunningColorPanel.BackColor
        $profile["StatusColorPaused"] = Convert-ColorToString $script:statusPausedColorPanel.BackColor
        $profile["StatusColorStopped"] = Convert-ColorToString $script:statusStoppedColorPanel.BackColor
        $profile["CompactMode"] = [bool]$script:compactModeBox.Checked
        $profile["DisableBalloonTips"] = [bool]$script:disableBalloonBox.Checked
        $profile["PauseDurationsMinutes"] = [string]$script:pauseDurationsBox.Text
        $profile["ScheduleOverrideEnabled"] = [bool]$script:scheduleOverrideBox.Checked
        $profile["ScheduleEnabled"] = [bool]$script:scheduleEnabledBox.Checked
        $profile["ScheduleStart"] = $script:scheduleStartBox.Value.ToString("HH:mm")
        $profile["ScheduleEnd"] = $script:scheduleEndBox.Value.ToString("HH:mm")
        $profile["ScheduleWeekdays"] = [string]$script:scheduleWeekdaysBox.Text
        $profile["ScheduleSuspendUntil"] = if ($script:scheduleSuspendUntilBox.Checked) { $script:scheduleSuspendUntilBox.Value.ToString("o") } else { $null }
        $profile["SafeModeEnabled"] = [bool]$script:SafeModeEnabledBox.Checked
        $profile["SafeModeFailureThreshold"] = [int]$script:safeModeThresholdBox.Value
        $profile["HotkeyToggle"] = [string]$script:hotkeyToggleBox.Text
        $profile["HotkeyStartStop"] = [string]$script:hotkeyStartStopBox.Text
        $profile["HotkeyPauseResume"] = [string]$script:hotkeyPauseResumeBox.Text
        $profile["LogMaxBytes"] = [int]($script:logMaxBox.Value * 1024)
        $profile["ProfileSchemaVersion"] = $script:ProfileSchemaVersion
        $profile["ReadOnly"] = if ($script:profileReadOnlyBox) { [bool]$script:profileReadOnlyBox.Checked } else { $false }
        return $profile
    }

    $script:EnsureProfilesHashtable = {
        if ($null -eq $settings) { return }
        $profiles = $settings.Profiles
        if ($profiles -is [hashtable]) { return }
        if ($profiles -is [System.Collections.IDictionary]) {
            $table = @{}
            foreach ($key in $profiles.Keys) { $table[$key] = $profiles[$key] }
            $settings.Profiles = $table
            return
        }
        if ($profiles -is [pscustomobject]) {
            $table = @{}
            foreach ($key in $profiles.PSObject.Properties.Name) { $table[$key] = $profiles.$key }
            $settings.Profiles = $table
            return
        }
        if ($profiles -is [System.Array]) {
            Write-Log "Profiles structure invalid (array). Resetting to defaults." "WARN" $null "Profiles"
            $settings.Profiles = @{}
            return
        }
        if ($null -eq $profiles) { $settings.Profiles = @{}; return }
        try {
            $table = @{}
            foreach ($key in Get-ObjectKeys $profiles) { $table[$key] = $profiles.$key }
            $settings.Profiles = $table
        } catch {
            Write-Log "Profiles structure invalid. Resetting to defaults." "WARN" $_.Exception "Profiles"
            $settings.Profiles = @{}
        }
    }

    $script:EnsureLogCategoriesHashtable = {
        if ($null -eq $settings) { return }
        $cats = $settings.LogCategories
        if ($cats -is [hashtable]) { return }
        if ($cats -is [System.Collections.IDictionary]) {
            $table = @{}
            foreach ($key in $cats.Keys) { $table[$key] = $cats[$key] }
            $settings.LogCategories = $table
            return
        }
        if ($cats -is [pscustomobject]) {
            $table = @{}
            foreach ($key in $cats.PSObject.Properties.Name) { $table[$key] = $cats.$key }
            $settings.LogCategories = $table
            return
        }
        if ($null -eq $cats) { $settings.LogCategories = @{}; return }
        try {
            $table = @{}
            foreach ($key in Get-ObjectKeys $cats) { $table[$key] = $cats.$key }
            $settings.LogCategories = $table
        } catch {
            $settings.LogCategories = @{}
        }
    }

    $confirmProfileWritable = {
        param([string]$name, [string]$action)
        if ($script:EnsureProfilesHashtable) { & $script:EnsureProfilesHashtable }
        if ([string]::IsNullOrWhiteSpace($name)) { return $false }
        if (-not ((Get-ObjectKeys $settings.Profiles) -contains $name)) { return $true }
        $isReadOnly = Get-ProfileReadOnly $settings.Profiles[$name]
        if ($isReadOnly -and ($action -eq "Save" -or $action -eq "Overwrite")) {
            if ($script:profileReadOnlyBox -and -not $script:profileReadOnlyBox.Checked) { return $true }
        }
        if ($isReadOnly) {
            [System.Windows.Forms.MessageBox]::Show(
                "Profile '$name' is read-only and cannot be modified ($action).",
                "Read-only Profile",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            return $false
        }
        return $true
    }

    $saveProfileButton.Add_Click({
        try {
            if ($script:EnsureProfilesHashtable) { & $script:EnsureProfilesHashtable }
            if ($script:profileBox.SelectedItem -eq $null) { return }
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $name = [string]$script:profileBox.SelectedItem
            if (-not (& $confirmProfileWritable $name "Save")) { return }
            $settings.Profiles[$name] = & $script:getProfileFromControls
            $settings.ActiveProfile = $name
            $settings = Apply-ProfileSnapshot $settings $settings.Profiles[$name]
            if ($script:profileReadOnlyBox) { $script:profileReadOnlyBox.Checked = (Get-ProfileReadOnly $settings.Profiles[$name]) }
            Update-ProfileLastGood $name (Migrate-ProfileSnapshot $settings.Profiles[$name])
            Save-Settings $settings
            if ($updateProfilesMenu) { & $updateProfilesMenu }
            if ($script:UpdateProfileDirtyIndicator) { & $script:UpdateProfileDirtyIndicator }
            if ($script:ClearProfileDirtyIndicator) { & $script:ClearProfileDirtyIndicator }
            $sw.Stop()
            Write-Log "UI: Profile saved: $name (ms=$($sw.ElapsedMilliseconds))" "DEBUG" $null "Profiles"
        } catch {
            Write-Log "UI: Profile save failed." "ERROR" $_.Exception "Profiles"
            if ($_.InvocationInfo) {
                Write-Log ("UI: Profile save failed at {0}:{1} char {2}" -f $_.InvocationInfo.ScriptName, $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine) "ERROR" $null "Profiles"
                Write-Log ("UI: Profile save failed line: {0}" -f ($_.InvocationInfo.Line.Trim())) "ERROR" $null "Profiles"
            }
            [System.Windows.Forms.MessageBox]::Show(
                "Save failed. Please check the log for details.",
                "Profile Save Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
    })

    $saveAsProfileButton.Add_Click({
        try {
            if ($script:EnsureProfilesHashtable) { & $script:EnsureProfilesHashtable }
            $defaultName = if ($script:profileBox.SelectedItem) { [string]$script:profileBox.SelectedItem } else { "New Profile" }
            $name = [Microsoft.VisualBasic.Interaction]::InputBox("Profile name:", "Save As Profile", $defaultName)
            if ([string]::IsNullOrWhiteSpace($name)) { return }
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $name = $name.Trim()
            if ((Get-ObjectKeys $settings.Profiles) -contains $name) {
                if (-not (& $confirmProfileWritable $name "Overwrite")) { return }
                $result = [System.Windows.Forms.MessageBox]::Show(
                    "Profile '$name' exists. Overwrite?",
                    "Overwrite Profile",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )
                if ($result -ne [System.Windows.Forms.DialogResult]::Yes) { return }
            }
            $settings.Profiles[$name] = & $script:getProfileFromControls
            $settings.ActiveProfile = $name
            $settings = Apply-ProfileSnapshot $settings $settings.Profiles[$name]
            if ($script:profileReadOnlyBox) { $script:profileReadOnlyBox.Checked = (Get-ProfileReadOnly $settings.Profiles[$name]) }
            Update-ProfileLastGood $name (Migrate-ProfileSnapshot $settings.Profiles[$name])
            Save-Settings $settings
            if ($updateProfilesMenu) { & $updateProfilesMenu }
            if ($script:UpdateProfileDirtyIndicator) { & $script:UpdateProfileDirtyIndicator }
            if ($script:ClearProfileDirtyIndicator) { & $script:ClearProfileDirtyIndicator }
            $sw.Stop()
            Write-Log "UI: Profile saved as: $name (ms=$($sw.ElapsedMilliseconds))" "DEBUG" $null "Profiles"
        } catch {
            Write-Log "UI: Profile save-as failed." "ERROR" $_.Exception "Profiles"
            if ($_.InvocationInfo) {
                Write-Log ("UI: Profile save-as failed at {0}:{1} char {2}" -f $_.InvocationInfo.ScriptName, $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine) "ERROR" $null "Profiles"
                Write-Log ("UI: Profile save-as failed line: {0}" -f ($_.InvocationInfo.Line.Trim())) "ERROR" $null "Profiles"
            }
            [System.Windows.Forms.MessageBox]::Show(
                "Save As failed. Please check the log for details.",
                "Profile Save Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
    })

    $duplicateProfileButton.Add_Click({
        if ($script:EnsureProfilesHashtable) { & $script:EnsureProfilesHashtable }
        if ($script:profileBox.SelectedItem -eq $null) { return }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $sourceName = [string]$script:profileBox.SelectedItem
        $defaultName = "$sourceName Copy"
        $name = [Microsoft.VisualBasic.Interaction]::InputBox("Copy profile name:", "Copy Profile", $defaultName)
        if ([string]::IsNullOrWhiteSpace($name)) { return }
        $name = $name.Trim()
        if ((Get-ObjectKeys $settings.Profiles) -contains $name) {
            [System.Windows.Forms.MessageBox]::Show(
                "A profile named '$name' already exists.",
                "Profile Exists",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            return
        }
        $sourceProfile = $settings.Profiles[$sourceName]
        $profileCopy = $sourceProfile | ConvertTo-Json -Depth 6 | ConvertFrom-Json
        $settings.Profiles[$name] = $profileCopy
        $settings.ActiveProfile = $name
        Update-ProfileLastGood $name (Migrate-ProfileSnapshot $settings.Profiles[$name])
        Save-Settings $settings
        & $script:refreshProfileList
        if ($updateProfilesMenu) { & $updateProfilesMenu }
        $sw.Stop()
        Write-Log "UI: Profile copied: $sourceName -> $name (ms=$($sw.ElapsedMilliseconds))" "DEBUG" $null "Profiles"
    })

    $loadProfileButton.Add_Click({
        if ($script:EnsureProfilesHashtable) { & $script:EnsureProfilesHashtable }
        if ($script:profileBox.SelectedItem -eq $null) { return }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $name = [string]$script:profileBox.SelectedItem
        if (-not ((Get-ObjectKeys $settings.Profiles) -contains $name)) { return }
        if (-not (Confirm-ProfileSwitch $name $settings.Profiles[$name])) { return }
        Write-Log "UI: ---------- Profile Load ----------" "DEBUG" $null "Profiles"
        $merged = [pscustomobject]@{}
        foreach ($prop in $settings.PSObject.Properties.Name) {
            $merged | Add-Member -MemberType NoteProperty -Name $prop -Value $settings.$prop
        }
        $merged = Apply-ProfileSnapshot $merged $settings.Profiles[$name]
        & $applySettingsToControls $merged
        $settings.ActiveProfile = $name
        if ($script:profileReadOnlyBox) { $script:profileReadOnlyBox.Checked = (Get-ProfileReadOnly $settings.Profiles[$name]) }
        Set-SettingsDirty $true
        if ($updateProfilesMenu) { & $updateProfilesMenu }
        $sw.Stop()
        Write-Log "UI: Profile loaded: $name (ms=$($sw.ElapsedMilliseconds))" "DEBUG" $null "Profiles"
    })

    $newProfileButton.Add_Click({
        if ($script:EnsureProfilesHashtable) { & $script:EnsureProfilesHashtable }
        $name = [Microsoft.VisualBasic.Interaction]::InputBox("Enter a new profile name:", "New Profile", "Custom")
        if ([string]::IsNullOrWhiteSpace($name)) { return }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $name = $name.Trim()
        if ((Get-ObjectKeys $settings.Profiles) -contains $name) {
            [System.Windows.Forms.MessageBox]::Show(
                "A profile named '$name' already exists.",
                "Profile Exists",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            return
        }
        $settings.Profiles[$name] = & $script:getProfileFromControls
        $settings.ActiveProfile = $name
        Update-ProfileLastGood $name (Migrate-ProfileSnapshot $settings.Profiles[$name])
        Save-Settings $settings
        & $script:refreshProfileList
        if ($updateProfilesMenu) { & $updateProfilesMenu }
        $sw.Stop()
        Write-Log "UI: Profile created: $name (ms=$($sw.ElapsedMilliseconds))" "DEBUG" $null "Profiles"
    })

    $renameProfileButton.Add_Click({
        if ($script:EnsureProfilesHashtable) { & $script:EnsureProfilesHashtable }
        if ($script:profileBox.SelectedItem -eq $null) { return }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $oldName = [string]$script:profileBox.SelectedItem
        if (-not (& $confirmProfileWritable $oldName "Rename")) { return }
        $name = [Microsoft.VisualBasic.Interaction]::InputBox("Enter a new name for '$oldName':", "Rename Profile", $oldName)
        if ([string]::IsNullOrWhiteSpace($name)) { return }
        $name = $name.Trim()
        if ($name -eq $oldName) { return }
        if ((Get-ObjectKeys $settings.Profiles) -contains $name) {
            [System.Windows.Forms.MessageBox]::Show(
                "A profile named '$name' already exists.",
                "Profile Exists",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            return
        }
        $settings.Profiles[$name] = $settings.Profiles[$oldName]
        $settings.Profiles.Remove($oldName)
        $lastGood = Get-ProfileLastGood $oldName
        if ($null -ne $lastGood) {
            Update-ProfileLastGood $name $lastGood
            Remove-ProfileLastGood $oldName
        }
        if ($settings.ActiveProfile -eq $oldName) { $settings.ActiveProfile = $name }
        Save-Settings $settings
        & $script:refreshProfileList
        if ($updateProfilesMenu) { & $updateProfilesMenu }
        $sw.Stop()
        Write-Log "UI: Profile renamed: $oldName -> $name (ms=$($sw.ElapsedMilliseconds))" "DEBUG" $null "Profiles"
    })

    $deleteProfileButton.Add_Click({
        if ($script:EnsureProfilesHashtable) { & $script:EnsureProfilesHashtable }
        if ($script:profileBox.SelectedItem -eq $null) { return }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $name = [string]$script:profileBox.SelectedItem
        if (-not (& $confirmProfileWritable $name "Delete")) { return }
        if ((Get-ObjectKeys $settings.Profiles).Count -le 1) {
            [System.Windows.Forms.MessageBox]::Show(
                "At least one profile must remain.",
                "Cannot Delete",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            return
        }
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Delete profile '$name'?",
            "Delete Profile",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($result -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        $settings.Profiles.Remove($name)
        Remove-ProfileLastGood $name
        if ($settings.ActiveProfile -eq $name) {
            $profileKeys = @(Get-ObjectKeys $settings.Profiles)
            if ($profileKeys.Count -gt 0) { $settings.ActiveProfile = $profileKeys[0] }
        }
        Save-Settings $settings
        & $script:refreshProfileList
        if ($updateProfilesMenu) { & $updateProfilesMenu }
        $sw.Stop()
        Write-Log "UI: Profile deleted: $name (ms=$($sw.ElapsedMilliseconds))" "DEBUG" $null "Profiles"
    })

    $exportProfileButton.Add_Click({
        if ($script:EnsureProfilesHashtable) { & $script:EnsureProfilesHashtable }
        if ($script:profileBox.SelectedItem -eq $null) { return }
        $name = [string]$script:profileBox.SelectedItem
        if (-not ((Get-ObjectKeys $settings.Profiles) -contains $name)) { return }
        $dialog = New-Object System.Windows.Forms.SaveFileDialog
        $dialog.Title = "Export Profile"
        $dialog.Filter = "Profile Files (*.json)|*.json|All Files (*.*)|*.*"
        $dialog.FileName = "Teams-Always-Green.profile.$name.json"
        if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        try {
            $payload = [pscustomobject]@{
                Name = $name
                Profile = $settings.Profiles[$name]
            }
            $payload | ConvertTo-Json -Depth 6 | Set-Content -Path $dialog.FileName -Encoding UTF8
            Write-Log "Profile exported: $name -> $($dialog.FileName)" "INFO" $null "Profiles"
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to export profile.`n$($_.Exception.Message)",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
            Write-Log "Failed to export profile." "ERROR" $_.Exception "Profiles"
        }
    })

    $importProfileButton.Add_Click({
        if ($script:EnsureProfilesHashtable) { & $script:EnsureProfilesHashtable }
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title = "Import Profile"
        $dialog.Filter = "Profile Files (*.json)|*.json|All Files (*.*)|*.*"
        if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        try {
            $raw = Get-Content -Path $dialog.FileName -Raw | ConvertFrom-Json
            $importProfile = $null
            $defaultName = "Imported"
            if ($raw.PSObject.Properties.Name -contains "Profile") {
                $importProfile = $raw.Profile
                if ($raw.PSObject.Properties.Name -contains "Name") { $defaultName = [string]$raw.Name }
            } else {
                $importProfile = $raw
            }
            if ($null -eq $importProfile) { throw "Invalid profile file." }
            $importProfile = Migrate-ProfileSnapshot $importProfile
            $validation = Test-ProfileSnapshot $importProfile
            if (-not $validation.Ok) { throw ("Profile validation failed: {0}" -f $validation.Message) }
            $name = [Microsoft.VisualBasic.Interaction]::InputBox("Profile name:", "Import Profile", $defaultName)
            if ([string]::IsNullOrWhiteSpace($name)) { return }
            $name = $name.Trim()
            if ((Get-ObjectKeys $settings.Profiles) -contains $name) {
                if (-not (& $confirmProfileWritable $name "Overwrite")) { return }
                $result = [System.Windows.Forms.MessageBox]::Show(
                    "Profile '$name' exists. Overwrite?",
                    "Overwrite Profile",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )
                if ($result -ne [System.Windows.Forms.DialogResult]::Yes) { return }
            }
            $settings.Profiles[$name] = $importProfile
            $settings.ActiveProfile = $name
            Update-ProfileLastGood $name (Migrate-ProfileSnapshot $settings.Profiles[$name])
            Save-Settings $settings
            & $script:refreshProfileList
            if ($updateProfilesMenu) { & $updateProfilesMenu }
            Write-Log "Profile imported: $name" "INFO" $null "Profiles"
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to import profile.`n$($_.Exception.Message)",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
            Write-Log "Failed to import profile." "ERROR" $_.Exception "Profiles"
        }
    })

    $exportButton = New-Object System.Windows.Forms.Button
    $exportButton.Text = "Export..."
    $exportButton.Width = 90

    $importButton = New-Object System.Windows.Forms.Button
    $importButton.Text = "Import..."
    $importButton.Width = 90

    $settingsTransferPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $settingsTransferPanel.FlowDirection = "LeftToRight"
    $settingsTransferPanel.AutoSize = $true
    $settingsTransferPanel.WrapContents = $true
    $settingsTransferPanel.Controls.Add($exportButton) | Out-Null
    $settingsTransferPanel.Controls.Add($importButton) | Out-Null

    $script:settingsDirectoryBox = New-Object System.Windows.Forms.TextBox
    $script:settingsDirectoryBox.Width = 320
    $settingsDirValue = [string]$settings.SettingsDirectory
    $script:settingsDirectoryBox.Text = if ([string]::IsNullOrWhiteSpace($settingsDirValue)) { $script:SettingsDirectory } else { Convert-FromRelativePath $settingsDirValue }

    $settingsDirectoryBrowseButton = New-Object System.Windows.Forms.Button
    $settingsDirectoryBrowseButton.Text = "Browse..."
    $settingsDirectoryBrowseButton.Width = 80
    $settingsDirectoryBrowseButton.Add_Click({
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = "Choose a folder for Teams-Always-Green settings files."
        if (-not [string]::IsNullOrWhiteSpace($script:settingsDirectoryBox.Text) -and (Test-Path $script:settingsDirectoryBox.Text)) {
            $dialog.SelectedPath = $script:settingsDirectoryBox.Text
        } else {
            $dialog.SelectedPath = $script:SettingsDirectory
        }
        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $script:settingsDirectoryBox.Text = $dialog.SelectedPath
        }
    })

    $settingsDirectoryPanel = New-Object System.Windows.Forms.TableLayoutPanel
    $settingsDirectoryPanel.ColumnCount = 2
    $settingsDirectoryPanel.RowCount = 1
    $settingsDirectoryPanel.AutoSize = $true
    $settingsDirectoryPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $settingsDirectoryPanel.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::AddColumns
    $settingsDirectoryPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $settingsDirectoryPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $script:settingsDirectoryBox.Dock = "Fill"
    $script:settingsDirectoryBox.Margin = New-Object System.Windows.Forms.Padding(0, 0, 6, 0)
    $settingsDirectoryBrowseButton.Margin = New-Object System.Windows.Forms.Padding(0)
    $settingsDirectoryPanel.Controls.Add($script:settingsDirectoryBox, 0, 0) | Out-Null
    $settingsDirectoryPanel.Controls.Add($settingsDirectoryBrowseButton, 1, 0) | Out-Null
    $settingsDirectoryPanel.Tag = "Settings Folder"
    $script:settingsDirectoryBox.Tag = "Settings Folder"
    $settingsDirectoryBrowseButton.Tag = "Settings Folder"

    $settingsFilesLabel = New-Object System.Windows.Forms.Label
    $settingsFilesLabel.AutoSize = $true
    $settingsFilesLabel.Dock = "Fill"
    $settingsFilesLabel.AutoEllipsis = $false
    $settingsFilesLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $settingsFilesLabel.MaximumSize = New-Object System.Drawing.Size(360, 0)
    $script:SettingsFilesListText = "Teams-Always-Green.settings.json`r`nTeams-Always-Green.settings.json.bak#"
    $settingsFilesLabel.Text = $script:SettingsFilesListText
    $script:SettingsFilesLabel = $settingsFilesLabel

    $script:BuildProfilesTab = {
        if ($script:ProfilesTabLoaded) { return }
        $panel = $script:SettingsTabPanels["Profiles"]
        if (-not $panel) { return }
        $panel.SuspendLayout()
        try {
            if ($script:AddFullRow -and $script:ProfileGroup) { & $script:AddFullRow $panel $script:ProfileGroup }
        } finally {
            $panel.ResumeLayout()
        }
        if ($script:refreshProfileList) { & $script:refreshProfileList }
        $script:ProfilesTabLoaded = $true
    }

    $script:BuildDiagnosticsTab = {
        if ($script:DiagnosticsTabLoaded) { return }
        $panel = $script:SettingsTabPanels["Diagnostics"]
        if (-not $panel) { return }
        $panel.SuspendLayout()
        try {
            if ($script:AddSettingRow) {
                if ($script:RunHealthCheckButton) { & $script:AddSettingRow $panel "Run Health Check" $script:RunHealthCheckButton | Out-Null }
                if ($script:ExportDiagnosticsButton) { & $script:AddSettingRow $panel "Export Diagnostics" $script:ExportDiagnosticsButton | Out-Null }
                if ($script:CopyDiagnosticsButton) { & $script:AddSettingRow $panel "Copy Diagnostics" $script:CopyDiagnosticsButton | Out-Null }
                if ($script:ScrubDiagnosticsBox) { & $script:AddSettingRow $panel "Scrub Diagnostics" $script:ScrubDiagnosticsBox | Out-Null }
                if ($script:ReportIssueButton) { & $script:AddSettingRow $panel "Report Issue" $script:ReportIssueButton | Out-Null }
            }
            if ($script:AddSpacerRow) { & $script:AddSpacerRow $panel }
            if ($script:AddFullRow -and $script:LogCategoryGroup) { & $script:AddFullRow $panel $script:LogCategoryGroup }
            if ($script:AddSpacerRow) { & $script:AddSpacerRow $panel }
            if ($script:AddFullRow -and $script:DiagnosticsGroup) { & $script:AddFullRow $panel $script:DiagnosticsGroup }
        } finally {
            $panel.ResumeLayout()
        }
        $script:DiagnosticsTabLoaded = $true
    }

    $script:BuildLoggingTab = {
        if ($script:LoggingTabLoaded) { return }
        $panel = $script:SettingsTabPanels["Logging"]
        if (-not $panel) { return }
        $panel.SuspendLayout()
        try {
            if ($script:AddSettingRow) {
                if ($script:logDirectoryPanel) { & $script:AddSettingRow $panel "Log Folder" $script:logDirectoryPanel | Out-Null }
                if ($script:logFilesLabel) { & $script:AddSettingRow $panel "Log Files" $script:logFilesLabel | Out-Null }
                if ($script:ValidateFoldersButton) { & $script:AddSettingRow $panel "Validate Folders" $script:ValidateFoldersButton | Out-Null }
                if ($script:AddSpacerRow) { & $script:AddSpacerRow $panel }
                if ($script:LogMaxSizePanel) { & $script:AddSettingRow $panel "Log Max Size (KB)" $script:LogMaxSizePanel | Out-Null }
                if ($script:AddErrorRow) { $script:ErrorLabels["Log Max Size (KB)"] = & $script:AddErrorRow $panel }
                & $script:AddSettingRow $panel "Log Retention (days)" $script:logRetentionBox | Out-Null
                if ($script:ViewLogButton) { & $script:AddSettingRow $panel "Open Log File" $script:ViewLogButton | Out-Null }
                if ($script:ViewLogTailButton) { & $script:AddSettingRow $panel "Open Log Tail" $script:ViewLogTailButton | Out-Null }
                if ($script:ExportLogTailButton) { & $script:AddSettingRow $panel "Export Log Tail" $script:ExportLogTailButton | Out-Null }
                if ($script:LogSnapshotButton) { & $script:AddSettingRow $panel "Log Snapshot" $script:LogSnapshotButton | Out-Null }
                if ($script:ClearLogButton) { & $script:AddSettingRow $panel "Clear Log" $script:ClearLogButton | Out-Null }
                if ($script:OpenLogFolderButton) { & $script:AddSettingRow $panel "Open Log Folder" $script:OpenLogFolderButton | Out-Null }
            }
        } finally {
            $panel.ResumeLayout()
        }
        if ($script:ApplySettingsTooltips) { & $script:ApplySettingsTooltips $panel }
        Localize-ControlTree $panel
        if ($script:ApplySettingsLocalizationOverrides) { & $script:ApplySettingsLocalizationOverrides }
        $script:SettingsLayoutDirty = $true
        if ($script:UpdateTabLayouts) { & $script:UpdateTabLayouts }
        $script:LoggingTabLoaded = $true
    }

    $script:BuildAboutTab = {
        if ($script:AboutTabLoaded) { return }
        $panel = $script:SettingsTabPanels["About"]
        if (-not $panel) { return }
        $panel.SuspendLayout()
        try {
            if ($script:AddFullRow -and $script:AboutGroup) { & $script:AddFullRow $panel $script:AboutGroup }
        } finally {
            $panel.ResumeLayout()
        }
        if ($script:UpdateAboutValues) { & $script:UpdateAboutValues }
        if ($script:ApplySettingsTooltips) { & $script:ApplySettingsTooltips $panel }
        Localize-ControlTree $panel
        if ($script:ApplySettingsLocalizationOverrides) { & $script:ApplySettingsLocalizationOverrides }
        $script:SettingsLayoutDirty = $true
        if ($script:UpdateTabLayouts) { & $script:UpdateTabLayouts }
        $script:AboutTabLoaded = $true
    }

    & $addFullRow $statusPanel $statusBadgePanel
    & $addFullRow $statusPanel $statusGroup
    & $addFullRow $statusPanel $toggleGroup
    & $addFullRow $statusPanel $funStatsGroup
    & $addFullRow $statusPanel $copyStatusPanel

    & $addSettingRow $generalPanel "Interval Seconds" $script:intervalBox | Out-Null
    $script:ErrorLabels = @{}
    $script:ErrorLabels["Interval Seconds"] = & $addErrorRow $generalPanel
    & $addSettingRow $generalPanel "Start with Windows" $script:startWithWindowsBox | Out-Null
    & $addSettingRow $generalPanel "Open Settings at Last Tab" $script:openSettingsLastTabBox | Out-Null
    & $addSettingRow $generalPanel "Language" $script:languageBox | Out-Null
    & $addSettingRow $generalPanel "Remember Choice" $script:rememberChoiceBox | Out-Null
    & $addSettingRow $generalPanel "Show First-Run Tips" $script:showFirstRunToastBox | Out-Null
    & $addSettingRow $generalPanel "Start on Launch" $script:startOnLaunchBox | Out-Null
    & $addSettingRow $generalPanel "Run Once on Launch" $script:runOnceOnLaunchBox | Out-Null
    & $addSettingRow $generalPanel "Date/Time Format" $script:dateTimeFormatBox | Out-Null
    $script:ErrorLabels["Date/Time Format"] = & $addErrorRow $generalPanel
    & $addSettingRow $generalPanel "Date/Time Format Preset" $script:dateTimeFormatPresetBox | Out-Null
    & $addSettingRow $generalPanel "Use System Date/Time Format" $script:useSystemDateTimeFormatBox | Out-Null
    & $addSettingRow $generalPanel "System Date/Time Style" $script:systemDateTimeFormatModeBox | Out-Null
    & $addSettingRow $generalPanel "Date/Time Preview" $script:dateTimeFormatPreviewLabel | Out-Null
    & $addFullRow $generalPanel $script:dateTimeFormatWarningLabel
    & $addSettingRow $generalPanel "Reset Toggle Count" $resetStatsButton | Out-Null
    & $addSettingRow $generalPanel "Last Toggle Time" $lastTogglePanel | Out-Null
    $script:ErrorLabels["Last Toggle Time"] = & $addErrorRow $generalPanel
    if ($script:AddSpacerRow) { & $script:AddSpacerRow $generalPanel }
    & $addSettingRow $generalPanel "Settings Folder" $settingsDirectoryPanel | Out-Null
    & $addSettingRow $generalPanel "Settings Files" $settingsFilesLabel | Out-Null
    if ($script:AddSpacerRow) { & $script:AddSpacerRow $generalPanel }
    & $addSettingRow $generalPanel "Export/Import Settings" $settingsTransferPanel | Out-Null

    & $addSettingRow $appearancePanel "Quiet Mode" $script:quietModeBox | Out-Null
    & $addSettingRow $appearancePanel "Tray Tooltip Style" $script:tooltipStyleBox | Out-Null
    & $addSettingRow $appearancePanel "Disable Tray Balloon Tips" $script:disableBalloonBox | Out-Null
    & $addSettingRow $appearancePanel "Theme Mode" $script:themeModeBox | Out-Null
    & $addSettingRow $appearancePanel "Font Size (Tray)" $fontSizePanel | Out-Null
    & $addSettingRow $appearancePanel "Settings Font Size" $settingsFontSizePanel | Out-Null
    $statusColorsContainer = New-Object System.Windows.Forms.TableLayoutPanel
    $statusColorsContainer.ColumnCount = 2
    $statusColorsContainer.RowCount = 1
    $statusColorsContainer.AutoSize = $true
    $statusColorsContainer.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $statusColorsContainer.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $statusColorsContainer.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $script:AppearancePreviewGroup.Margin = New-Object System.Windows.Forms.Padding(16, 0, 0, 0)
    $script:AppearancePreviewGroup.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left)
    $statusColorsContainer.Controls.Add($statusColorsGrid, 0, 0)
    $statusColorsContainer.Controls.Add($script:AppearancePreviewGroup, 1, 0)
    & $addSettingRow $appearancePanel "Status Colors" $statusColorsContainer | Out-Null
    & $addSettingRow $appearancePanel "Compact Mode" $script:compactModeBox | Out-Null
    if ($script:AddSpacerRow) { & $script:AddSpacerRow $appearancePanel }

    & $addSettingRow $schedulePanel "Schedule Override" $script:scheduleOverrideBox | Out-Null
    & $addSettingRow $schedulePanel "Schedule Enabled" $script:scheduleEnabledBox | Out-Null
    & $addSettingRow $schedulePanel "Schedule Start" $script:scheduleStartBox | Out-Null
    $script:ErrorLabels["Schedule Start"] = & $addErrorRow $schedulePanel
    & $addSettingRow $schedulePanel "Schedule End" $script:scheduleEndBox | Out-Null
    $script:ErrorLabels["Schedule End"] = & $addErrorRow $schedulePanel
    & $addSettingRow $schedulePanel "Schedule Weekdays (e.g., Mon,Tue,Wed)" $script:scheduleWeekdaysBox | Out-Null
    & $addSettingRow $schedulePanel "Schedule Suspend Until" $script:scheduleSuspendUntilBox | Out-Null
    & $addSettingRow $schedulePanel "Suspend schedule for..." $script:scheduleSuspendQuickBox | Out-Null
    & $addSettingRow $schedulePanel "Pause Until" $script:pauseUntilBox | Out-Null
    & $addSettingRow $schedulePanel "Pause Durations (minutes, comma-separated)" $script:pauseDurationsBox | Out-Null
    $script:ErrorLabels["Pause Durations (minutes, comma-separated)"] = & $addErrorRow $schedulePanel

    $pauseQuickBox = New-Object System.Windows.Forms.ComboBox
    $pauseQuickBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $pauseQuickBox.Width = 120
    $pauseQuickBox.Items.Add("Select...") | Out-Null
    foreach ($minutes in @(15, 30, 60, 120)) {
        $pauseQuickBox.Items.Add("$minutes min") | Out-Null
    }
    $pauseQuickBox.SelectedIndex = 0
    $pauseQuickBox.Add_SelectedIndexChanged({
        if ($script:SettingsIsApplying) { return }
        $text = [string]$pauseQuickBox.SelectedItem
        if ($text -eq "Select...") { return }
        $minutesValue = 0
        if ([int]::TryParse(($text -replace "\\D", ""), [ref]$minutesValue) -and $minutesValue -gt 0) {
            $target = (Get-Date).AddMinutes($minutesValue)
            $script:pauseUntilBox.Checked = $true
            $script:pauseUntilBox.Value = $target
            Set-SettingsDirty $true
        }
        $pauseQuickBox.SelectedIndex = 0
    })
    & $addSettingRow $schedulePanel "Pause for..." $pauseQuickBox | Out-Null

    & $addSettingRow $hotkeyPanel "Hotkey: Toggle Now" $script:hotkeyToggleBox | Out-Null
    $script:ErrorLabels["Hotkey: Toggle Now"] = & $addErrorRow $hotkeyPanel
    & $addSettingRow $hotkeyPanel "Hotkey: Start/Stop" $script:hotkeyStartStopBox | Out-Null
    $script:ErrorLabels["Hotkey: Start/Stop"] = & $addErrorRow $hotkeyPanel
    & $addSettingRow $hotkeyPanel "Hotkey: Pause/Resume" $script:hotkeyPauseResumeBox | Out-Null
    $script:ErrorLabels["Hotkey: Pause/Resume"] = & $addErrorRow $hotkeyPanel
    & $addSettingRow $hotkeyPanel "Hotkey Status" $hotkeyStatusValue | Out-Null
    $script:SettingsHotkeyWarningLabel = New-Object System.Windows.Forms.Label
    $script:SettingsHotkeyWarningLabel.Text = ""
    $script:SettingsHotkeyWarningLabel.AutoSize = $true
    $script:SettingsHotkeyWarningLabel.ForeColor = [System.Drawing.Color]::OrangeRed
    $script:SettingsHotkeyWarningLabel.Visible = $false
    & $addSettingRow $hotkeyPanel "Hotkey Warning" $script:SettingsHotkeyWarningLabel | Out-Null
    if ($script:AddSpacerRow) { & $script:AddSpacerRow $hotkeyPanel }
    & $addSettingRow $hotkeyPanel "Validate Hotkeys" $validateHotkeysButton | Out-Null
    & $addSettingRow $hotkeyPanel "Test Hotkeys" $simulateHotkeysPanel | Out-Null

    & $addSettingRow $advancedPanel "Safe Mode Enabled" $script:SafeModeEnabledBox | Out-Null
    & $addSettingRow $advancedPanel "Safe Mode Failure Threshold" $script:safeModeThresholdBox | Out-Null
    $script:ErrorLabels["Safe Mode Failure Threshold"] = & $addErrorRow $advancedPanel
    if ($script:AddSpacerRow) { & $script:AddSpacerRow $advancedPanel }
    & $addSettingRow $advancedPanel "Log Level" $script:logLevelBox | Out-Null
    & $addSettingRow $advancedPanel "Include Stack Trace" $script:logIncludeStackTraceBox | Out-Null
    & $addSettingRow $advancedPanel "Verbose UI Logging" $script:verboseUiLogBox | Out-Null
    & $addSettingRow $advancedPanel "Enable Event Log" $script:logToEventLogBox | Out-Null
    & $addSettingRow $advancedPanel "Event Log Levels" $eventLogLevelPanel | Out-Null
    & $addSettingRow $advancedPanel "Debug Mode" $debugModeButton | Out-Null
    & $addSettingRow $advancedPanel "Debug Status" $debugModeStatus | Out-Null
    if ($script:AddSpacerRow) { & $script:AddSpacerRow $advancedPanel }
    $logMaxSizePanel = New-Object System.Windows.Forms.TableLayoutPanel
    $logMaxSizePanel.ColumnCount = 2
    $logMaxSizePanel.RowCount = 1
    $logMaxSizePanel.AutoSize = $true
    $logMaxSizePanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $logMaxSizePanel.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::AddColumns
    $logMaxSizePanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $logMaxSizePanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $script:logMaxBox.Margin = New-Object System.Windows.Forms.Padding(0, 0, 6, 0)
    $logSizeValue.Margin = New-Object System.Windows.Forms.Padding(0, 4, 0, 0)
    $logMaxSizePanel.Controls.Add($script:logMaxBox, 0, 0) | Out-Null
    $logMaxSizePanel.Controls.Add($logSizeValue, 1, 0) | Out-Null
    $script:LogMaxSizePanel = $logMaxSizePanel

    if ($tabControl.SelectedTab -and ((& $script:GetSettingsTabKey $tabControl.SelectedTab) -eq "Profiles")) {
        if ($script:BuildProfilesTab) { & $script:BuildProfilesTab }
    }
    if ($tabControl.SelectedTab -and ((& $script:GetSettingsTabKey $tabControl.SelectedTab) -eq "Diagnostics")) {
        if ($script:BuildDiagnosticsTab) { & $script:BuildDiagnosticsTab }
    }
    if ($tabControl.SelectedTab -and ((& $script:GetSettingsTabKey $tabControl.SelectedTab) -eq "Logging")) {
        if ($script:BuildLoggingTab) { & $script:BuildLoggingTab }
    }
    if ($tabControl.SelectedTab -and ((& $script:GetSettingsTabKey $tabControl.SelectedTab) -eq "About")) {
        if ($script:BuildAboutTab) { & $script:BuildAboutTab }
    }

    foreach ($panel in @($statusPanel, $generalPanel, $schedulePanel, $hotkeyPanel, $loggingPanel, $profilesPanel, $diagnosticsPanel, $advancedPanel, $appearancePanel, $aboutPanel)) {
        if ($panel -is [System.Windows.Forms.TableLayoutPanel]) {
            $panel.AutoSize = $true
            $panel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
            $panel.PerformLayout()
            if ($panel.Parent -is [System.Windows.Forms.Control]) {
                $panel.Parent.PerformLayout()
            }
        }
    }


    $buttonsPanel = New-Object System.Windows.Forms.TableLayoutPanel
    $buttonsPanel.ColumnCount = 2
    $buttonsPanel.RowCount = 1
    $buttonsPanel.Dock = "Bottom"
    $buttonsPanel.Padding = New-Object System.Windows.Forms.Padding(10, 5, 10, 10)
    $buttonsPanel.AutoSize = $true
    $buttonsPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 60)))
    $buttonsPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 40)))

    $leftButtons = New-Object System.Windows.Forms.FlowLayoutPanel
    $leftButtons.FlowDirection = "LeftToRight"
    $leftButtons.Dock = "Fill"
    $leftButtons.AutoSize = $true

    $rightButtons = New-Object System.Windows.Forms.FlowLayoutPanel
    $rightButtons.FlowDirection = "RightToLeft"
    $rightButtons.Dock = "Fill"
    $rightButtons.AutoSize = $true

    $script:SettingsOkButton = New-Object System.Windows.Forms.Button
    $script:SettingsOkButton.Text = "Save"
    $script:SettingsOkButton.Width = 90
    $script:SettingsOkButton.Enabled = $false

    $doneButton = New-Object System.Windows.Forms.Button
    $doneButton.Text = "Done"
    $doneButton.Width = 90

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Width = 90
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $cancelButton.Add_Click({
        Write-Log "UI: Settings closed via Cancel." "DEBUG" $null "Settings-Dialog"
        if ($script:settingsDialogLastSaved) {
            & $applySettingsToControls $script:settingsDialogLastSaved
            Set-SettingsDirty $false
            $savedLang = [string]$script:settingsDialogLastSaved.UiLanguage
            if ([string]::IsNullOrWhiteSpace($savedLang)) { $savedLang = "auto" }
            $script:UiLanguage = Resolve-UiLanguage $savedLang
            if ($script:SettingsForm -and -not $script:SettingsForm.IsDisposed) {
                Localize-ControlTree $script:SettingsForm
                if ($script:ApplySettingsLocalizationOverrides) { & $script:ApplySettingsLocalizationOverrides }
            }
            if ($script:TrayMenu) { Localize-MenuItems $script:TrayMenu.Items }
            if (Get-Command Update-TrayLabels -ErrorAction SilentlyContinue) { Update-TrayLabels }
        }
        if ($script:SettingsForm -and -not $script:SettingsForm.IsDisposed) {
            $script:SettingsForm.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
            $script:SettingsForm.Close()
        }
    })

    $resetButton = New-Object System.Windows.Forms.Button
    $resetButton.Text = "Restore Defaults"
    $resetButton.Width = 130
    $resetConfirmSeconds = 5
    $resetConfirmState = [pscustomobject]@{
        Pending = $false
        Remaining = 0
        Deadline = $null
    }

    $testButton = New-Object System.Windows.Forms.Button
    $testButton.Text = "Test Toggle"
    $testButton.Width = 110

    $previewChangesButton = New-Object System.Windows.Forms.Button
    $previewChangesButton.Text = "Preview Changes"
    $previewChangesButton.Width = 130

    $undoChangesButton = New-Object System.Windows.Forms.Button
    $undoChangesButton.Text = "Undo Changes"
    $undoChangesButton.Width = 120

    $script:LastSavedLabel = New-Object System.Windows.Forms.Label
    $script:LastSavedLabel.AutoSize = $true
    $script:LastSavedLabel.Text = "Last saved: Never"

    $settingsDirty = $false
    $script:SettingsDirty = $false
    $script:SettingsIsApplying = $false
    $settingsUiRefreshInProgress = $false
    $script:SettingsUiRefreshInProgress = $false
    $script:settingsDialogLastSaved = $null

    $script:CopySettingsObject = {
        param($src)
        if ($null -eq $src) { return $null }
        return ($src | ConvertTo-Json -Depth 6 | ConvertFrom-Json)
    }

    $script:UpdateLastSavedLabel = {
        param($time)
        $suffix = ""
        if ($script:LastSettingsSaveOk -eq $false -and -not [string]::IsNullOrWhiteSpace($script:LastSettingsSaveMessage)) {
            $suffix = " (last save failed: $script:LastSettingsSaveMessage)"
        }
        if ($time -is [DateTime]) {
            $script:LastSavedLabel.Text = "Last saved: $(Format-DateTime $time)$suffix"
            return
        }
        if (Test-Path $settingsPath) {
            try {
                $script:LastSavedLabel.Text = "Last saved: $(Format-DateTime (Get-Item -Path $settingsPath).LastWriteTime)$suffix"
                return
            } catch { }
        }
        $script:LastSavedLabel.Text = "Last saved: Never$suffix"
    }
    $script:SetDirty = {
        param([bool]$value)
        if ($settingsDirty -eq $value) { return }
        $settingsDirty = $value
        $script:SettingsDirty = $value
        if ($script:SettingsOkButton) { $script:SettingsOkButton.Enabled = $value }
        if ($script:SettingsDirtyLabel) { $script:SettingsDirtyLabel.Visible = $value }
        if ($value -and $script:SettingsSaveLabel) { $script:SettingsSaveLabel.Visible = $false }
        $dirtyVar = Get-Variable -Name UpdateProfileDirtyIndicator -Scope Script -ErrorAction SilentlyContinue
        if ($dirtyVar -and $dirtyVar.Value -is [scriptblock]) { & $dirtyVar.Value }
    }

    $script:UpdateProfileDirtyIndicator = {
        if (-not $script:profileDirtyLabel) { return }
        if (-not $settings) { $script:profileDirtyLabel.Visible = $false; return }
        if (-not $script:SettingsDirty) { $script:profileDirtyLabel.Visible = $false; return }
        $name = [string]$settings.ActiveProfile
        if ([string]::IsNullOrWhiteSpace($name)) { $script:profileDirtyLabel.Visible = $false; return }
        if (-not ((Get-ObjectKeys $settings.Profiles) -contains $name)) { $script:profileDirtyLabel.Visible = $false; return }
        $current = $null
        if ($script:getProfileFromControls) {
            $current = & $script:getProfileFromControls
        } else {
            $current = Get-ProfileSnapshot $settings
        }
        $stored = Migrate-ProfileSnapshot $settings.Profiles[$name]
        $diff = Get-ProfileDiffSummary $current $stored
        $script:profileDirtyLabel.Visible = (-not [string]::IsNullOrWhiteSpace($diff))
    }

    $script:ClearProfileDirtyIndicator = {
        if (-not $script:profileDirtyLabel) { return }
        $script:profileDirtyLabel.Visible = $false
    }

    $runSettingsAction = {
        param([string]$name, [scriptblock]$action)
        Set-LastUserAction $name "Settings"
        try {
            $actionStart = Get-Date
            if ($settings.VerboseUiLogging) {
                Write-Log "UI: Settings action started: $name" "DEBUG" $null "Settings-UI"
            }
            & $action
            $elapsedMs = [int]((Get-Date) - $actionStart).TotalMilliseconds
            if ($settings.VerboseUiLogging) {
                $script:LogResultOverride = "OK"
                Write-Log "UI: Settings action completed: $name (ms=$elapsedMs)" "DEBUG" $null "Settings-UI"
            } else {
                $script:LogResultOverride = "OK"
                Write-Log "UI: Settings action: $name (ms=$elapsedMs)" "DEBUG" $null "Settings-UI"
            }
        } catch {
            $script:LogResultOverride = "Failed"
            Write-Log "Settings action failed: $name" "ERROR" $_.Exception "Settings-UI"
            [System.Windows.Forms.MessageBox]::Show(
                "Settings action failed ($name).`n$($_.Exception.Message)",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
    }
    $script:RunSettingsAction = $runSettingsAction

    $script:ClearFieldErrors = {
        foreach ($label in $script:ErrorLabels.Values) {
            $label.Text = ""
            $label.Visible = $false
        }
    }

    $script:SetFieldError = {
        param([string]$key, [string]$message)
        if ($script:ErrorLabels.ContainsKey($key)) {
            $script:ErrorLabels[$key].Text = $message
            $script:ErrorLabels[$key].Visible = $true
        }
        return $message
    }

    $script:normalizeInputs = {
        if ($script:SettingsIsApplying) { return }
        $script:SettingsIsApplying = $true
        try {
            $script:intervalBox.Value = Normalize-IntervalSeconds ([int]$script:intervalBox.Value)
            $script:toggleCountBox.Value = [int][Math]::Max(0, [int]$script:toggleCountBox.Value)
            $script:logMaxBox.Value = [int][Math]::Min(102400, [Math]::Max(64, [int]$script:logMaxBox.Value))
            $script:safeModeThresholdBox.Value = [int][Math]::Max(1, [int]$script:safeModeThresholdBox.Value)
            $script:fontSizeBox.Value = [int][Math]::Min(24, [Math]::Max(8, [int]$script:fontSizeBox.Value))
            $script:settingsFontSizeBox.Value = [int][Math]::Min(24, [Math]::Max(8, [int]$script:settingsFontSizeBox.Value))

            $rawDurations = [string]$script:pauseDurationsBox.Text
            if (-not [string]::IsNullOrWhiteSpace($rawDurations)) {
                $trimmed = $rawDurations.Trim()
                $endsWithSeparator = $trimmed -match "[,;\\s]$"
                $parts = New-Object System.Collections.Generic.List[int]
                $seen = @{}
                foreach ($part in ($trimmed -split "[,; ]+" | Where-Object { $_ -ne "" })) {
                    $num = 0
                    if ([int]::TryParse($part, [ref]$num) -and $num -gt 0 -and -not $seen.ContainsKey($num)) {
                        $seen[$num] = $true
                        $parts.Add($num)
                    }
                }
                if (-not $endsWithSeparator -and $parts.Count -gt 0) {
                    $normalized = ($parts | ForEach-Object { $_ }) -join ","
                    if ($normalized -ne $rawDurations) {
                        $script:pauseDurationsBox.Text = $normalized
                    }
                }
            }
        } finally {
            $script:SettingsIsApplying = $false
        }
    }

    $script:normalizeInputsTimer = New-Object System.Windows.Forms.Timer
    $script:normalizeInputsTimer.Interval = 250
    $script:normalizeInputsTimer.Add_Tick({
        Invoke-SafeTimerAction "NormalizeInputsTimer" {
            $script:normalizeInputsTimer.Stop()
            if ($script:normalizeInputs) { & $script:normalizeInputs }
        }
    })

    $script:scheduleNormalizeInputs = {
        $timerVar = Get-Variable -Name normalizeInputsTimer -Scope Script -ErrorAction SilentlyContinue
        if (-not $timerVar -or -not $timerVar.Value) {
            $script:normalizeInputsTimer = New-Object System.Windows.Forms.Timer
            $script:normalizeInputsTimer.Interval = 250
            $script:normalizeInputsTimer.Add_Tick({
                Invoke-SafeTimerAction "NormalizeInputsTimer" {
                    $script:normalizeInputsTimer.Stop()
                    if ($script:normalizeInputs) { & $script:normalizeInputs }
                }
            })
        }
        if ($script:normalizeInputsTimer.Enabled) { $script:normalizeInputsTimer.Stop() }
        $script:normalizeInputsTimer.Start()
    }

    $bindDirty = {
        param($control)
        if ($control -is [System.Windows.Forms.TextBox]) {
            $control.Add_TextChanged({
                if (-not $script:SettingsIsApplying) {
                    Set-SettingsDirty $true
                    if ($script:scheduleNormalizeInputs -is [scriptblock] -and $this -ne $script:logDirectoryBox -and $this -ne $script:settingsDirectoryBox -and $this -ne $script:dateTimeFormatBox) {
                        & $script:scheduleNormalizeInputs
                    }
                }
            })
        } elseif ($control -is [System.Windows.Forms.CheckBox]) {
            $control.Add_CheckedChanged({ if (-not $script:SettingsIsApplying) { Set-SettingsDirty $true } })
        } elseif ($control -is [System.Windows.Forms.NumericUpDown]) {
            $control.Add_ValueChanged({
                if (-not $script:SettingsIsApplying) {
                    Set-SettingsDirty $true
                    if ($script:scheduleNormalizeInputs -is [scriptblock]) { & $script:scheduleNormalizeInputs }
                }
            })
        } elseif ($control -is [System.Windows.Forms.ComboBox]) {
            $control.Add_SelectedIndexChanged({ if (-not $script:SettingsIsApplying) { Set-SettingsDirty $true } })
        } elseif ($control -is [System.Windows.Forms.DateTimePicker]) {
            $control.Add_ValueChanged({ if (-not $script:SettingsIsApplying) { Set-SettingsDirty $true } })
        } elseif ($control -is [System.Windows.Forms.TrackBar]) {
            $control.Add_ValueChanged({ if (-not $script:SettingsIsApplying) { Set-SettingsDirty $true } })
        }
    }

    foreach ($ctrl in @(
        $script:profileReadOnlyBox,
        $script:intervalBox, $script:startWithWindowsBox, $script:openSettingsLastTabBox, $script:languageBox, $script:rememberChoiceBox, $script:showFirstRunToastBox, $script:startOnLaunchBox, $script:quietModeBox, $script:dateTimeFormatBox, $script:dateTimeFormatPresetBox, $script:useSystemDateTimeFormatBox, $script:systemDateTimeFormatModeBox,
        $script:tooltipStyleBox, $script:disableBalloonBox, $script:themeModeBox, $script:fontSizeBox, $script:settingsFontSizeBox, $script:compactModeBox, $script:toggleCountBox, $script:LastTogglePicker, $script:runOnceOnLaunchBox, $script:pauseUntilBox,
        $script:pauseDurationsBox, $script:scheduleOverrideBox, $script:scheduleEnabledBox, $script:scheduleStartBox, $script:scheduleEndBox, $script:scheduleWeekdaysBox,
        $script:scheduleSuspendUntilBox, $script:scheduleSuspendQuickBox, $script:SafeModeEnabledBox, $script:safeModeThresholdBox,
        $script:hotkeyToggleBox, $script:hotkeyStartStopBox, $script:hotkeyPauseResumeBox, $script:logLevelBox, $script:logMaxBox, $script:logRetentionBox, $script:logDirectoryBox,
        $script:settingsDirectoryBox,
        $script:logIncludeStackTraceBox, $script:logToEventLogBox, $script:verboseUiLogBox, $script:ScrubDiagnosticsBox
    )) { & $bindDirty $ctrl }

    if ($script:logCategoryBoxes) {
        foreach ($box in $script:logCategoryBoxes.Values) { & $bindDirty $box }
    }
    if ($script:LogEventLevelBoxes) {
        foreach ($box in $script:LogEventLevelBoxes.Values) { & $bindDirty $box }
    }


    $setToolTip = {
        param($control, [string]$text)
        if ($control -and -not [string]::IsNullOrWhiteSpace($text)) {
            if ($script:SettingsToolTip) {
                $script:SettingsToolTip.SetToolTip($control, $text)
            } elseif ($toolTip) {
                $toolTip.SetToolTip($control, $text)
            }
        }
    }
    $script:SetSettingsToolTip = $setToolTip

    $settingTooltips = @{
        "Interval Seconds" = "How often Scroll Lock toggles while running. Minimum 5 seconds, maximum 24 hours."
        "Start with Windows" = "Create or remove a Startup shortcut so the tray app launches on sign-in."
        "Open Settings at Last Tab" = "Reopen Settings on the last tab you used."
        "Remember Choice" = "Remember the answer to the start prompt shown on launch."
        "Show First-Run Tips" = "Show a short help tip after the first launch."
        "Start on Launch" = "Automatically start toggling when the app launches."
        "Run Once on Launch" = "Toggle Scroll Lock once at startup without staying in a running loop."
        "Date/Time Format" = "Format used for all displayed timestamps. Example: yyyy-MM-dd HH:mm:ss."
        "Date/Time Format Preset" = "Pick a common format and apply it to the format box."
        "Use System Date/Time Format" = "Use Windows regional short/long date and time formats."
        "System Date/Time Style" = "Choose Short or Long system date/time style."
        "Date/Time Preview" = "Live preview of how timestamps will appear."
        "Toggle Count" = "Stored count of successful toggles. Saved with settings."
        "Reset Toggle Count" = "Reset toggle count and last toggle time to defaults."
        "Last Toggle Time" = "Manually set the last toggle time. Uncheck to clear it. Use the Now or Clear buttons for quick updates."
        "Pause Until" = "Temporarily pause toggling until a specific time."
        "Pause Durations (minutes, comma-separated)" = "Quick-pause options used by the pause menu and controls. Example: 5,15,30."
        "Pause for..." = "Quickly pause for a selected duration and auto-resume."
        "Quiet Mode" = "Suppress tray balloon notifications."
        "Tray Tooltip Style" = "Choose how much detail appears in the tray tooltip: Minimal, Standard, or Verbose."
        "Disable Tray Balloon Tips" = "Disable all balloon tips from the tray icon."
        "Theme Mode" = "Choose Light, Dark, Auto Detect, or High Contrast for the app and menus."
        "Font Size (Tray)" = "Adjust tray menu font size."
        "Settings Font Size" = "Adjust font size in the settings window only."
        "Status Color (Running)" = "Pick the color used for the Running status indicator."
        "Status Color (Paused)" = "Pick the color used for the Paused status indicator."
        "Status Color (Stopped)" = "Pick the color used for the Stopped status indicator."
        "Compact Mode" = "Reduce padding to fit more settings on screen."
        "Schedule Override" = "When enabled, this profile's schedule replaces the global schedule."
        "Schedule Enabled" = "Only run within the schedule window when enabled."
        "Schedule Start" = "Daily start time for the schedule."
        "Schedule End" = "Daily end time for the schedule."
        "Schedule Weekdays (e.g., Mon,Tue,Wed)" = "Days the schedule applies. Use short names like Mon,Tue,Wed."
        "Schedule Suspend Until" = "Temporarily ignore the schedule until this time."
        "Suspend schedule for..." = "Quickly suspend scheduling for a set duration."
        "Hotkey: Toggle Now" = "Global hotkey to toggle Scroll Lock once. Leave blank to disable."
        "Hotkey: Start/Stop" = "Global hotkey to start or stop toggling. Leave blank to disable."
        "Hotkey: Pause/Resume" = "Global hotkey to pause or resume toggling. Leave blank to disable."
        "Hotkey Status" = "Shows whether the hotkeys registered successfully."
        "Validate Hotkeys" = "Validate hotkey strings without registering them."
        "Test Hotkeys" = "Simulate hotkey actions using the buttons below."
        "Safe Mode Enabled" = "Disable toggling after repeated failures to prevent constant errors."
        "Safe Mode Failure Threshold" = "Number of consecutive failures before Safe Mode activates."
        "Log Level" = "Minimum severity written to the log."
        "Include Stack Trace" = "Include exception stack traces for ERROR and FATAL entries."
        "Verbose UI Logging" = "Log UI actions at INFO instead of DEBUG."
        "Enable Event Log" = "Write selected log levels to the Windows Application log."
        "Event Log Levels" = "Choose which severities are written to the Windows Event Log."
        "Debug Mode" = "Temporarily set log level to DEBUG for troubleshooting."
        "Debug Status" = "Shows whether temporary debug mode is active."
        "Log Folder" = "Folder where logs and settings backups are written. Leave blank to use the script folder."
        "Log Files" = "Files written in the log folder, including rotations and settings backup copies."
        "Validate Folders" = "Check that app folders exist and are writable."
        "Run Health Check" = "Run a quick health check for folders and settings."
        "Copy Status" = "Copy current status details to the clipboard."
        "Log Max Size (KB)" = "Rotate the log when it exceeds this size."
        "Log Retention (days)" = "Delete old log files after this many days. Set to 0 to keep indefinitely."
        "Log Size" = "Current log size compared to the max size threshold."
        "Open Log File" = "Open the full log in the default editor."
        "Open Log Tail" = "Open a live tail view of the log."
        "Export Log Tail" = "Save the last 200 log lines to a file."
        "Log Snapshot" = "Write a one-line state snapshot into the log."
        "Clear Log" = "Clear the log file after confirmation."
        "Open Log Folder" = "Open the folder containing the log file."
        "Settings Folder" = "Folder where the settings file and its backups are written. Leave blank to use the script folder."
        "Settings Files" = "Settings files stored in the selected folder."
        "Export Diagnostics" = "Write a diagnostics summary to a text file."
        "Copy Diagnostics" = "Copy a diagnostics summary to the clipboard."
        "Scrub Diagnostics" = "Redact usernames and local paths in diagnostics outputs."
        "Report Issue" = "Export diagnostics plus the last 200 log lines."
        "Export/Import Settings" = "Save settings to a file or load settings from a file."
        "Profile Read-only" = "Lock a profile to prevent edits. Turn off to allow changes."
    }
    $script:SettingTooltips = $settingTooltips

    $applyTooltips = {
        param($control)
        if (-not $control) { return }
        $tag = [string]$control.Tag
        if ($script:SettingTooltips -and $script:SettingTooltips.ContainsKey($tag)) {
            if ($script:SetSettingsToolTip) {
                & $script:SetSettingsToolTip $control $script:SettingTooltips[$tag]
            } elseif ($setToolTip) {
                & $setToolTip $control $script:SettingTooltips[$tag]
            }
        }
        foreach ($child in $control.Controls) {
            if ($script:ApplySettingsTooltips) {
                & $script:ApplySettingsTooltips $child
            }
        }
    }
    $script:ApplySettingsTooltips = $applyTooltips

    foreach ($page in $script:SettingsTabControl.TabPages) {
        & $applyTooltips $page
    }

    & $setToolTip $profileLabel "Select the active profile that the app should use."
    & $setToolTip $script:profileBox "Choose which saved profile is active."
    & $setToolTip $newProfileButton "Create a new profile from the current settings."
    & $setToolTip $renameProfileButton "Rename the selected profile."
    & $setToolTip $deleteProfileButton "Delete the selected profile."
    & $setToolTip $exportProfileButton "Export the selected profile to a file."
    & $setToolTip $importProfileButton "Import a profile from a file."
    & $setToolTip $saveProfileButton "Save current settings into the selected profile."
    & $setToolTip $saveAsProfileButton "Save current settings as a new profile."
    & $setToolTip $duplicateProfileButton "Copy the selected profile to a new profile."
    & $setToolTip $loadProfileButton "Load settings from the selected profile."
    & $setToolTip $previewChangesButton "Preview changes without saving."
    & $setToolTip $undoChangesButton "Revert changes back to the last saved settings."
    & $setToolTip $copyDiagnosticsButton "Copy diagnostics to the clipboard."

    $script:SettingsStatusPanel = $statusPanel
    $script:SettingsHotkeyPanel = $hotkeyPanel
    $script:SettingsLoggingPanel = $loggingPanel
    $script:SettingsDiagnosticsPanel = $diagnosticsPanel
    $script:SettingsStatusLabel = $statusLabel
    $script:SettingsNextLabel = $nextLabel
    $script:SettingsNextCountdownLabel = $nextCountdownLabel
    $script:SettingsLastToggleLabel = $lastToggleLabel
    $script:SettingsProfileStatusLabel = $profileStatusLabel
    $script:SettingsScheduleStatusLabel = $scheduleStatusLabel
    $script:SettingsSafeModeStatusLabel = $safeModeStatusLabel
    $script:SettingsKeyboardLabel = $keyboardLabel
    $script:SettingsUptimeLabel = $uptimeLabel
    $script:SettingsFunDailyLabel = $funDailyLabel
    $script:SettingsFunStreakCurrentLabel = $funStreakCurrentLabel
    $script:SettingsFunStreakBestLabel = $funStreakBestLabel
    $script:SettingsFunMostActiveLabel = $funMostActiveLabel
    $script:SettingsFunLongestPauseLabel = $funLongestPauseLabel
    $script:SettingsFunTotalRunLabel = $funTotalRunLabel
    $script:SettingsStatusValue = $statusValue
    $script:SettingsNextValue = $nextValue
    $script:SettingsUptimeValue = $uptimeValue
    $script:SettingsLastToggleValue = $lastToggleValue
    $script:SettingsNextCountdownValue = $nextCountdownValue
    $script:SettingsToggleCurrentValue = $toggleCurrentValue
    $script:SettingsToggleLifetimeValue = $toggleLifetimeValue
    $script:SettingsProfileStatusValue = $profileStatusValue
    $script:SettingsScheduleStatusValue = $scheduleStatusValue
    $script:SettingsSafeModeStatusValue = $safeModeStatusValue
    $script:SettingsKeyboardValue = $keyboardValue
    $script:SettingsHotkeyStatusValue = $hotkeyStatusValue
    $script:SettingsLogMaxBox = $script:logMaxBox
    $script:SettingsLogSizeValue = $logSizeValue
    $script:SettingsDiagErrorValue = $diagErrorValue
    $script:SettingsDiagRestartValue = $diagRestartValue
    $script:SettingsDiagSafeModeValue = $diagSafeModeValue
    $script:SettingsDebugModeStatus = $debugModeStatus
    $script:SettingsDiagLastToggleValue = $diagLastToggleValue
    $script:SettingsDiagFailValue = $diagFailValue
    $script:SettingsDiagLogSizeValue = $diagLogSizeValue
    $script:SettingsDiagLogRotateValue = $diagLogRotateValue
    $script:SettingsDiagLogWriteValue = $diagLogWriteValue
    $script:SettingsResetConfirmState = $resetConfirmState
    $script:SettingsResetButton = $resetButton

    if ($script:logCategoryBoxes) {
        foreach ($name in $script:LogCategoryNames) {
            if ($script:logCategoryBoxes.ContainsKey($name)) {
                & $setToolTip $script:logCategoryBoxes[$name] "Include $name category entries when the log level allows."
            }
        }
    }

    $applySettingsToControls = {
        param($src)
        $script:SettingsIsApplying = $true
        $script:intervalBox.Value = [int]$src.IntervalSeconds
        $script:startWithWindowsBox.Checked = [bool]$src.StartWithWindows
        $script:openSettingsLastTabBox.Checked = [bool]$src.OpenSettingsAtLastTab
        if ($script:UpdateLanguageItems) {
            $script:SettingsIsApplying = $true
            & $script:UpdateLanguageItems ([string]$src.UiLanguage)
            $script:SettingsIsApplying = $false
        }
        $script:rememberChoiceBox.Checked = [bool]$src.RememberChoice
        $script:showFirstRunToastBox.Checked = [bool]$src.ShowFirstRunToast
        $script:startOnLaunchBox.Checked = [bool]$src.StartOnLaunch
        $script:quietModeBox.Checked = [bool]$src.QuietMode
        $tooltipStyleValue = [string]$src.TooltipStyle
        if ([string]::IsNullOrWhiteSpace($tooltipStyleValue)) {
            $tooltipStyleValue = if ([bool]$src.MinimalTrayTooltip) { "Minimal" } else { "Standard" }
        }
        if ($script:UpdateTooltipStyleItems) {
            $script:SettingsIsApplying = $true
            & $script:UpdateTooltipStyleItems $tooltipStyleValue
            $script:SettingsIsApplying = $false
        } elseif ($script:tooltipStyleBox.Items.Contains($tooltipStyleValue)) {
            $script:tooltipStyleBox.SelectedItem = $tooltipStyleValue
        } else {
            $script:tooltipStyleBox.SelectedItem = "Standard"
        }
        $script:disableBalloonBox.Checked = [bool]$src.DisableBalloonTips
        $themeModeValue = [string]$src.ThemeMode
        if ([string]::IsNullOrWhiteSpace($themeModeValue)) { $themeModeValue = "Auto" }
        $themeModeLabel = switch ($themeModeValue.ToUpperInvariant()) {
            "LIGHT" { "Light" }
            "DARK" { "Dark" }
            "HIGH CONTRAST" { "High Contrast" }
            default { "Auto Detect" }
        }
        if ($script:UpdateThemeModeItems) {
            $script:SettingsIsApplying = $true
            & $script:UpdateThemeModeItems $themeModeLabel
            $script:SettingsIsApplying = $false
        } else {
            $script:themeModeBox.SelectedItem = $themeModeLabel
        }
        $fontSizeValue = 12
        if ($src.PSObject.Properties.Name -contains "FontSize") {
            $fontSizeValue = [int]$src.FontSize
        }
        if ($fontSizeValue -lt $script:fontSizeBox.Minimum) { $fontSizeValue = [int]$script:fontSizeBox.Minimum }
        if ($fontSizeValue -gt $script:fontSizeBox.Maximum) { $fontSizeValue = [int]$script:fontSizeBox.Maximum }
        $script:fontSizeBox.Value = $fontSizeValue

        $settingsFontSizeValue = 12
        if ($src.PSObject.Properties.Name -contains "SettingsFontSize") {
            $settingsFontSizeValue = [int]$src.SettingsFontSize
        }
        if ($settingsFontSizeValue -lt $script:settingsFontSizeBox.Minimum) { $settingsFontSizeValue = [int]$script:settingsFontSizeBox.Minimum }
        if ($settingsFontSizeValue -gt $script:settingsFontSizeBox.Maximum) { $settingsFontSizeValue = [int]$script:settingsFontSizeBox.Maximum }
        $script:settingsFontSizeBox.Value = $settingsFontSizeValue
        $script:statusRunningColorPanel.BackColor = Convert-ColorString ([string]$src.StatusColorRunning) ([System.Drawing.Color]::Green)
        $script:statusPausedColorPanel.BackColor = Convert-ColorString ([string]$src.StatusColorPaused) ([System.Drawing.Color]::DarkGoldenrod)
        $script:statusStoppedColorPanel.BackColor = Convert-ColorString ([string]$src.StatusColorStopped) ([System.Drawing.Color]::Red)
        $script:compactModeBox.Checked = [bool]$src.CompactMode
        if ($script:ApplyCompactMode) { & $script:ApplyCompactMode $script:compactModeBox.Checked }
        & $updateAppearancePreview
        Apply-MenuFontSize ([int]$script:fontSizeBox.Value)
        Apply-SettingsFontSize ([int]$script:settingsFontSizeBox.Value)
        $script:toggleCountBox.Value = [int]$src.ToggleCount
        if ($src.LastToggleTime) {
            try {
                $script:LastTogglePicker.Value = [DateTime]::Parse([string]$src.LastToggleTime)
                $script:LastTogglePicker.Checked = $true
            } catch {
                $script:LastTogglePicker.Checked = $false
            }
        } else {
            $script:LastTogglePicker.Checked = $false
        }
        $script:runOnceOnLaunchBox.Checked = [bool]$src.RunOnceOnLaunch
        $formatValue = Normalize-DateTimeFormat ([string]$src.DateTimeFormat)
        $script:dateTimeFormatBox.Text = $formatValue
        $useSystemValue = [bool]$src.UseSystemDateTimeFormat
        $script:useSystemDateTimeFormatBox.Checked = $useSystemValue
        $modeValue = [string]$src.SystemDateTimeFormatMode
        if ([string]::IsNullOrWhiteSpace($modeValue)) { $modeValue = "Short" }
        if ($script:systemDateTimeFormatModeBox.Items.Contains($modeValue)) {
            $script:systemDateTimeFormatModeBox.SelectedItem = $modeValue
        } else {
            $script:systemDateTimeFormatModeBox.SelectedItem = "Short"
        }
        $script:dateTimeFormatBox.Enabled = -not $useSystemValue
        $script:dateTimeFormatPresetBox.Enabled = -not $useSystemValue
        $script:systemDateTimeFormatModeBox.Enabled = $useSystemValue
        $pickerFormat = if ($useSystemValue) { if ($modeValue -eq "Long") { "F" } else { "g" } } else { $formatValue }
        $script:LastTogglePicker.CustomFormat = $pickerFormat
        $script:pauseUntilBox.CustomFormat = $pickerFormat
        $script:scheduleSuspendUntilBox.CustomFormat = $pickerFormat
        if ($script:updateDateTimePreview) { & $script:updateDateTimePreview }
        if ($src.PauseUntil) {
            try {
                $script:pauseUntilBox.Value = [DateTime]::Parse([string]$src.PauseUntil)
                $script:pauseUntilBox.Checked = $true
            } catch {
                $script:pauseUntilBox.Checked = $false
            }
        } else {
            $script:pauseUntilBox.Checked = $false
        }
        $script:pauseDurationsBox.Text = [string]$src.PauseDurationsMinutes
        $script:scheduleEnabledBox.Checked = [bool]$src.ScheduleEnabled
        $tmpTime = [TimeSpan]::Zero
        if (Try-ParseTime ([string]$src.ScheduleStart) ([ref]$tmpTime)) {
            $script:scheduleStartBox.Value = (Get-Date).Date.Add($tmpTime)
        }
        if (Try-ParseTime ([string]$src.ScheduleEnd) ([ref]$tmpTime)) {
            $script:scheduleEndBox.Value = (Get-Date).Date.Add($tmpTime)
        }
        $script:scheduleWeekdaysBox.Text = [string]$src.ScheduleWeekdays
        if ($src.ScheduleSuspendUntil) {
            try {
                $script:scheduleSuspendUntilBox.Value = [DateTime]::Parse([string]$src.ScheduleSuspendUntil)
                $script:scheduleSuspendUntilBox.Checked = $true
            } catch {
                $script:scheduleSuspendUntilBox.Checked = $false
            }
        } else {
            $script:scheduleSuspendUntilBox.Checked = $false
        }
        if ($script:scheduleSuspendQuickBox.Items.Count -gt 0) { $script:scheduleSuspendQuickBox.SelectedIndex = 0 }
        if ($script:scheduleOverrideBox) {
            $script:scheduleOverrideBox.Checked = [bool]$src.ScheduleOverrideEnabled
        }
        if ($script:updateScheduleOverrideUI) { & $script:updateScheduleOverrideUI }
        $script:SafeModeEnabledBox.Checked = [bool]$src.SafeModeEnabled
        $script:safeModeThresholdBox.Value = [int]$src.SafeModeFailureThreshold
        $script:hotkeyToggleBox.Text = [string]$src.HotkeyToggle
        $script:hotkeyStartStopBox.Text = [string]$src.HotkeyStartStop
        $script:hotkeyPauseResumeBox.Text = [string]$src.HotkeyPauseResume
        $script:logIncludeStackTraceBox.Checked = [bool]$src.LogIncludeStackTrace
        $script:logToEventLogBox.Checked = [bool]$src.LogToEventLog
        $script:verboseUiLogBox.Checked = [bool]$src.VerboseUiLogging
        if ($script:LogEventLevelBoxes) {
            foreach ($levelName in $script:LogEventLevelBoxes.Keys) {
                $enabled = $false
                if ($src.LogEventLevels -is [hashtable] -and $src.LogEventLevels.ContainsKey($levelName)) {
                    $enabled = [bool]$src.LogEventLevels[$levelName]
                } elseif ($src.LogEventLevels -is [pscustomobject] -and ($src.LogEventLevels.PSObject.Properties.Name -contains $levelName)) {
                    $enabled = [bool]$src.LogEventLevels.$levelName
                }
                $script:LogEventLevelBoxes[$levelName].Checked = $enabled
            }
        }
        if ($script:ScrubDiagnosticsBox) {
            $script:ScrubDiagnosticsBox.Checked = [bool]$src.ScrubDiagnostics
        }
        if ($script:DebugModeStatus) {
            $script:DebugModeStatus.Text = if ($script:DebugModeUntil) { "On (10 min)" } else { "Off" }
        }
        $levelText = [string]$src.LogLevel
        if ([string]::IsNullOrWhiteSpace($levelText)) { $levelText = "INFO" }
        $levelText = $levelText.ToUpperInvariant()
        if ($script:logLevelBox.Items.Contains($levelText)) {
            $script:logLevelBox.SelectedItem = $levelText
        } else {
            $script:logLevelBox.SelectedItem = "INFO"
        }
        $logMaxKbValue = [int]([Math]::Max(64, [int]($src.LogMaxBytes / 1024)))
        $script:logMaxBox.Value = $logMaxKbValue
        $logRetentionValue = 0
        if ($src.PSObject.Properties.Name -contains "LogRetentionDays") {
            $logRetentionValue = [int]$src.LogRetentionDays
        }
        if ($logRetentionValue -lt $script:logRetentionBox.Minimum) { $logRetentionValue = [int]$script:logRetentionBox.Minimum }
        if ($logRetentionValue -gt $script:logRetentionBox.Maximum) { $logRetentionValue = [int]$script:logRetentionBox.Maximum }
        $script:logRetentionBox.Value = $logRetentionValue
        $logDirValue = if ($src.PSObject.Properties.Name -contains "LogDirectory") { [string]$src.LogDirectory } else { "" }
        if ([string]::IsNullOrWhiteSpace($logDirValue)) { $logDirValue = $script:LogDirectory }
        $script:logDirectoryBox.Text = $logDirValue
        $settingsDirValue = if ($src.PSObject.Properties.Name -contains "SettingsDirectory") { [string]$src.SettingsDirectory } else { "" }
        if ([string]::IsNullOrWhiteSpace($settingsDirValue)) { $settingsDirValue = $script:SettingsDirectory }
        $script:settingsDirectoryBox.Text = $settingsDirValue
        if ($script:logCategoryBoxes) {
            foreach ($name in $script:LogCategoryNames) {
                if ($script:logCategoryBoxes.ContainsKey($name)) {
                    $value = $true
                    if ($src.PSObject.Properties.Name -contains "LogCategories") {
                        if ($src.LogCategories -is [hashtable] -and $src.LogCategories.ContainsKey($name)) {
                            $value = [bool]$src.LogCategories[$name]
                        } elseif ($src.LogCategories -is [pscustomobject] -and $src.LogCategories.PSObject.Properties.Name -contains $name) {
                            $value = [bool]$src.LogCategories.$name
                        }
                    }
                    $script:logCategoryBoxes[$name].Checked = $value
                }
            }
        }
        $script:SettingsIsApplying = $false
        Set-SettingsDirty $false
        Clear-SettingsFieldErrors
    }
    $script:ApplySettingsToControls = $applySettingsToControls

    $settings = Ensure-SettingsCollections $settings
    $settings = Normalize-Settings (Migrate-Settings $settings)
    $script:settings = $settings
    & $applySettingsToControls $settings
    $script:settingsDialogLastSaved = & $script:CopySettingsObject $settings
    & $script:UpdateLastSavedLabel $null
    $script:SettingsIsApplying = $true
    if ($settings.OpenSettingsAtLastTab -and $settings.LastSettingsTab) {
        $targetTab = if ($script:GetSettingsTabPage) { & $script:GetSettingsTabPage $settings.LastSettingsTab } else { $null }
        if ($targetTab) { $script:SettingsTabControl.SelectedTab = $targetTab }
    } else {
        $defaultTab = if ($script:GetSettingsTabPage) { & $script:GetSettingsTabPage "Status" } else { $null }
        if ($defaultTab) { $script:SettingsTabControl.SelectedTab = $defaultTab }
    }
    if ($script:SettingsTabControl -and $script:SettingsTabControl.SelectedTab) {
        $selectedTabKey = if ($script:GetSettingsTabKey) { & $script:GetSettingsTabKey $script:SettingsTabControl.SelectedTab } else { [string]$script:SettingsTabControl.SelectedTab.Text }
        if ($selectedTabKey -eq "Profiles") {
            if ($script:BuildProfilesTab) { & $script:BuildProfilesTab }
        } elseif ($selectedTabKey -eq "Diagnostics") {
            if ($script:BuildDiagnosticsTab) { & $script:BuildDiagnosticsTab }
        }
    }
    $script:SettingsIsApplying = $false
    Set-SettingsDirty $false
    if ($script:ClearProfileDirtyIndicator) { & $script:ClearProfileDirtyIndicator }
    if ($form) {
        $form.Add_Shown({
            try {
                Set-SettingsDirty $false
                if ($script:ClearProfileDirtyIndicator) { & $script:ClearProfileDirtyIndicator }
            } catch { }
        })
    }

    $normalizeSettings = {
        param($src)
        if (-not $src) { return $defaultSettings }
        $null = Extract-RuntimeFromSettings $src
        $extras = Get-SettingsExtraFields $src
        $merged = [pscustomobject]@{}
        foreach ($prop in $defaultSettings.PSObject.Properties.Name) {
            if ($src.PSObject.Properties.Name -contains $prop) {
                $merged | Add-Member -MemberType NoteProperty -Name $prop -Value $src.$prop
            } else {
                $merged | Add-Member -MemberType NoteProperty -Name $prop -Value $defaultSettings.$prop
            }
        }
        foreach ($key in $extras.Keys) {
            if (-not ($merged.PSObject.Properties.Name -contains $key)) {
                $merged | Add-Member -MemberType NoteProperty -Name $key -Value $extras[$key]
            }
        }
        return (Normalize-Settings (Migrate-Settings $merged))
    }

    $exportButton.Add_Click({
        & $script:RunSettingsAction "Export Settings" {
            $dialog = New-Object System.Windows.Forms.SaveFileDialog
            $dialog.Filter = "JSON Files (*.json)|*.json|All Files (*.*)|*.*"
            $dialog.FileName = "Teams-Always-Green.settings.json"
            if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                try {
                    $exportSettings = Get-SettingsForSave $settings
                    $exportSettings | Add-Member -MemberType NoteProperty -Name "ExportedAt" -Value (Get-Date).ToString("o") -Force
                    $exportSettings | Add-Member -MemberType NoteProperty -Name "ExportedBy" -Value $env:USERNAME -Force
                    $exportSettings | Add-Member -MemberType NoteProperty -Name "ExportedFromVersion" -Value $appVersion -Force
                    $exportSettings | Add-Member -MemberType NoteProperty -Name "ExportedSchemaVersion" -Value $script:SettingsSchemaVersion -Force
                    $exportSettings | ConvertTo-Json -Depth 6 | Set-Content -Path $dialog.FileName -Encoding UTF8
                    Write-Log "Settings exported to $($dialog.FileName)." "INFO" $null "Settings-Export"
                } catch {
                    Write-Log "Failed to export settings." "ERROR" $_.Exception "Settings-Export"
                    [System.Windows.Forms.MessageBox]::Show(
                        "Failed to export settings.`n$($_.Exception.Message)",
                        "Error",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    ) | Out-Null
                }
            } else {
                Write-Log "Settings export canceled." "INFO" $null "Settings-Export"
            }
        }
    })

    $importButton.Add_Click({
        & $script:RunSettingsAction "Import Settings" {
            $dialog = New-Object System.Windows.Forms.OpenFileDialog
            $dialog.Filter = "JSON Files (*.json)|*.json|All Files (*.*)|*.*"
            if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                try {
                    $loaded = Get-Content -Path $dialog.FileName -Raw | ConvertFrom-Json
                    $validation = Test-SettingsSchema $loaded
                    $script:SettingsFutureVersion = $validation.FutureVersion
                    if ($validation.IsCritical) {
                        throw "Settings file is invalid or incomplete."
                    }
                    if ($validation.FutureVersion -or $validation.Issues.Count -gt 0) {
                        $warnLines = @()
                        if ($validation.FutureVersion) { $warnLines += "Settings file is from a newer version." }
                        if ($validation.Issues.Count -gt 0) { $warnLines += ($validation.Issues | Select-Object -First 6) }
                        $warnText = "Import warnings:`n" + ($warnLines -join "`n") + "`n`nContinue?"
                        $choice = [System.Windows.Forms.MessageBox]::Show(
                            $warnText,
                            "Import Warnings",
                            [System.Windows.Forms.MessageBoxButtons]::YesNo,
                            [System.Windows.Forms.MessageBoxIcon]::Warning
                        )
                        if ($choice -ne [System.Windows.Forms.DialogResult]::Yes) {
                            Write-Log "Settings import canceled after warnings." "INFO" $null "Settings-Import"
                            return
                        }
                    }
                    $merged = & $normalizeSettings $loaded
                    $script:SettingsExtraFields = Get-SettingsExtraFields $merged
                    $diff = Get-SettingsDiffSummary $settings $merged
                    if ($diff.Count -gt 0) {
                        $confirmText = "Import will apply the following changes:`n$($diff.Summary)`n`nContinue?"
                        $confirm = [System.Windows.Forms.MessageBox]::Show(
                            $confirmText,
                            "Confirm Import",
                            [System.Windows.Forms.MessageBoxButtons]::YesNo,
                            [System.Windows.Forms.MessageBoxIcon]::Question
                        )
                        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
                            Write-Log "Settings import canceled by user." "INFO" $null "Settings-Import"
                            return
                        }
                    }
                    & $applySettingsToControls $merged
                    Write-Log "Settings imported from $($dialog.FileName)." "INFO" $null "Settings-Import"
                    Set-SettingsDirty $true
                } catch {
                    Write-Log "Failed to import settings." "ERROR" $_.Exception "Settings-Import"
                    [System.Windows.Forms.MessageBox]::Show(
                        "Failed to import settings.`n$($_.Exception.Message)",
                        "Error",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    ) | Out-Null
                }
            } else {
                Write-Log "Settings import canceled." "INFO" $null "Settings-Import"
            }
        }
    })

    $resetButton.Add_Click({
        & $script:RunSettingsAction "Restore Defaults" {
            if (-not $resetConfirmState.Pending) {
                $resetConfirmState.Pending = $true
                $resetConfirmState.Remaining = $resetConfirmSeconds
                $resetConfirmState.Deadline = (Get-Date).AddSeconds($resetConfirmSeconds)
                $resetButton.Text = "Confirm Reset ($($resetConfirmState.Remaining))"
                return
            }
            $resetConfirmState.Pending = $false
            $resetConfirmState.Deadline = $null
            $resetButton.Text = "Restore Defaults"
            & $applySettingsToControls $defaultSettings
            Write-Log "Settings restored to defaults (dialog only)." "INFO" $null "Settings-Reset"
            Set-SettingsDirty $true
        }
    })

    $testButton.Add_Click({
        & $script:RunSettingsAction "Test Toggle" {
            Do-Toggle "settings-test"
        }
    })

    $resetStatsButton.Add_Click({
        & $script:RunSettingsAction "Reset Stats" {
            $result = [System.Windows.Forms.MessageBox]::Show(
                "Reset toggle count and last toggle time?",
                "Reset Stats",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($result -ne [System.Windows.Forms.DialogResult]::Yes) {
                Write-Log "Stats reset canceled." "INFO" $null "Settings-ResetStats"
                return
            }
            $script:tickCount = 0
            $script:lastToggleTime = $null
            Set-SettingsPropertyValue $settings "ToggleCount" 0
            Set-SettingsPropertyValue $settings "LastToggleTime" $null
            Save-Stats
            $script:toggleCountBox.Value = 0
            $script:LastTogglePicker.Checked = $false
            Request-StatusUpdate
            Set-SettingsDirty $false
            Write-Log "Stats reset from settings dialog." "INFO" $null "Settings-ResetStats"
        }
    })

    $script:CollectSettingsFromControls = {
        param([switch]$ShowErrors)
        Clear-SettingsFieldErrors
        $errors = @()
        $intervalSeconds = $null
        $toggleCount = $null
        $lastToggleTime = $null
        $pauseUntil = $null
        $pauseDurations = $null
        $scheduleStart = $null
        $scheduleEnd = $null
        $scheduleWeekdays = $null
        $scheduleSuspendUntil = $null
        $safeModeThreshold = $null
        $hotkeyToggle = $null
        $hotkeyStartStop = $null
        $hotkeyPauseResume = $null
        $logMaxKb = $null

        try {
            $intervalSeconds = [int]$script:intervalBox.Value
            if ($intervalSeconds -le 0) { throw "IntervalSeconds <= 0" }
            $intervalSeconds = Normalize-IntervalSeconds $intervalSeconds
        } catch {
            $errors += (Set-SettingsFieldError "Interval Seconds" "Interval Seconds must be a number > 0.")
        }

        try {
            $toggleCount = [int]$script:toggleCountBox.Value
            if ($toggleCount -lt 0) { throw "ToggleCount < 0" }
        } catch {
            $errors += (Set-SettingsFieldError "Toggle Count" "Toggle Count must be a number >= 0.")
        }

        if ($script:LastTogglePicker.Checked) {
            $lastToggleTime = $script:LastTogglePicker.Value
        }

        if ($script:pauseUntilBox.Checked) {
            $pauseUntil = $script:pauseUntilBox.Value
        }

        $pauseDurations = [string]$script:pauseDurationsBox.Text
        if ([string]::IsNullOrWhiteSpace($pauseDurations)) {
            $errors += (Set-SettingsFieldError "Pause Durations (minutes, comma-separated)" "Pause Durations must contain at least one number.")
        } else {
            $parts = @()
            foreach ($part in ($pauseDurations -split "[,; ]+" | Where-Object { $_ -ne "" })) {
                $num = 0
                if ([int]::TryParse($part, [ref]$num) -and $num -gt 0) { $parts += $num }
            }
            if ($parts.Count -eq 0) {
                $errors += (Set-SettingsFieldError "Pause Durations (minutes, comma-separated)" "Pause Durations must contain at least one number.")
            }
        }

        if ($script:scheduleEnabledBox.Checked) {
            $scheduleStart = [TimeSpan]::Zero
            $scheduleEnd = [TimeSpan]::Zero
            if (-not (Try-ParseTime $script:scheduleStartBox.Text ([ref]$scheduleStart))) {
                $errors += (Set-SettingsFieldError "Schedule Start" "Schedule Start must be a valid time (HH:mm).")
            }
            if (-not (Try-ParseTime $script:scheduleEndBox.Text ([ref]$scheduleEnd))) {
                $errors += (Set-SettingsFieldError "Schedule End" "Schedule End must be a valid time (HH:mm).")
            }
            $scheduleWeekdays = [string]$script:scheduleWeekdaysBox.Text
        }
        if ($script:scheduleSuspendUntilBox.Checked) {
            $scheduleSuspendUntil = $script:scheduleSuspendUntilBox.Value
        }

        try {
            $safeModeThreshold = [int]$script:safeModeThresholdBox.Value
            if ($safeModeThreshold -lt 1) { throw "SafeModeThreshold < 1" }
        } catch {
            $errors += (Set-SettingsFieldError "Safe Mode Failure Threshold" "Safe Mode Failure Threshold must be a number >= 1.")
        }

        $hotkeyToggle = [string]$script:hotkeyToggleBox.Text
        $hotkeyStartStop = [string]$script:hotkeyStartStopBox.Text
        $hotkeyPauseResume = [string]$script:hotkeyPauseResumeBox.Text
        if (-not (Validate-HotkeyString $hotkeyToggle)) { $errors += (Set-SettingsFieldError "Hotkey: Toggle Now" "Hotkey: Toggle Now is invalid.") }
        if (-not (Validate-HotkeyString $hotkeyStartStop)) { $errors += (Set-SettingsFieldError "Hotkey: Start/Stop" "Hotkey: Start/Stop is invalid.") }
        if (-not (Validate-HotkeyString $hotkeyPauseResume)) { $errors += (Set-SettingsFieldError "Hotkey: Pause/Resume" "Hotkey: Pause/Resume is invalid.") }

        try {
            $logMaxKb = [int]$script:logMaxBox.Value
            if ($logMaxKb -lt 64 -or $logMaxKb -gt 102400) { throw "LogMaxKb out of range" }
        } catch {
            $errors += (Set-SettingsFieldError "Log Max Size (KB)" "Log Max Size must be a number between 64 and 102400 (KB).")
        }

        $formatText = [string]$script:dateTimeFormatBox.Text
        $formatText = if ($null -eq $formatText) { "" } else { $formatText.Trim() }
        if (-not [string]::IsNullOrWhiteSpace($formatText) -and -not $script:useSystemDateTimeFormatBox.Checked) {
            try {
                [DateTime]::Now.ToString($formatText) | Out-Null
            } catch {
                $errors += (Set-SettingsFieldError "Date/Time Format" "Date/Time Format is invalid.")
            }
        } else {
            $formatText = $script:DateTimeFormatDefault
        }

        if ($errors.Count -gt 0) {
            if ($ShowErrors) {
                Write-Log ("Settings validation failed: " + ($errors -join "; ")) "WARN" $null "Settings-Validation"
                [System.Windows.Forms.MessageBox]::Show(
                    ($errors -join "`n"),
                    "Invalid settings",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
            }
            return [pscustomobject]@{ Errors = $errors }
        }

        $pending = & $script:CopySettingsObject $settings
        if ($script:profileBox.SelectedItem) {
            $pending.ActiveProfile = [string]$script:profileBox.SelectedItem
        }

        $pending.IntervalSeconds = $intervalSeconds
        $pending.StartWithWindows = $script:startWithWindowsBox.Checked
        $pending.OpenSettingsAtLastTab = $script:openSettingsLastTabBox.Checked
        $selectedLang = $null
        if ($script:languageBox) { $selectedLang = $script:languageBox.SelectedItem }
        if ($selectedLang -and $selectedLang.PSObject.Properties.Name -contains "Code") {
            $pending.UiLanguage = [string]$selectedLang.Code
        } else {
            $pending.UiLanguage = "auto"
        }
        $pending.RememberChoice = $script:rememberChoiceBox.Checked
        $pending.ShowFirstRunToast = [bool]$script:showFirstRunToastBox.Checked
        $pending.StartOnLaunch = $script:startOnLaunchBox.Checked
        $pending.QuietMode = $script:quietModeBox.Checked
        $pending.DisableBalloonTips = $script:disableBalloonBox.Checked
        $pending.DateTimeFormat = Normalize-DateTimeFormat $formatText
        $pending.UseSystemDateTimeFormat = [bool]$script:useSystemDateTimeFormatBox.Checked
        $pending.SystemDateTimeFormatMode = [string]$script:systemDateTimeFormatModeBox.SelectedItem
        if ([string]::IsNullOrWhiteSpace($pending.SystemDateTimeFormatMode)) { $pending.SystemDateTimeFormatMode = "Short" }
        $themeModeSelected = $null
        if ($script:themeModeBox.SelectedItem -and $script:themeModeBox.SelectedItem.PSObject.Properties.Name -contains "Code") {
            $themeModeSelected = [string]$script:themeModeBox.SelectedItem.Code
        } else {
            $themeModeSelected = [string]$script:themeModeBox.SelectedItem
        }
        $pending.ThemeMode = switch ($themeModeSelected) {
            "Light" { "Light" }
            "Dark" { "Dark" }
            "High Contrast" { "High Contrast" }
            default { "Auto" }
        }
        if ($script:tooltipStyleBox.SelectedItem -and $script:tooltipStyleBox.SelectedItem.PSObject.Properties.Name -contains "Code") {
            $pending.TooltipStyle = [string]$script:tooltipStyleBox.SelectedItem.Code
        } else {
            $pending.TooltipStyle = [string]$script:tooltipStyleBox.SelectedItem
        }
        if ([string]::IsNullOrWhiteSpace($pending.TooltipStyle)) { $pending.TooltipStyle = "Standard" }
        $pending.MinimalTrayTooltip = ($pending.TooltipStyle -eq "Minimal")
        $pending.FontSize = [int]$script:fontSizeBox.Value
        $pending.SettingsFontSize = [int]$script:settingsFontSizeBox.Value
        $pending.StatusColorRunning = Convert-ColorToString $script:statusRunningColorPanel.BackColor
        $pending.StatusColorPaused = Convert-ColorToString $script:statusPausedColorPanel.BackColor
        $pending.StatusColorStopped = Convert-ColorToString $script:statusStoppedColorPanel.BackColor
        $pending.CompactMode = $script:compactModeBox.Checked
        $pending.ToggleCount = $toggleCount
        $pending.LastToggleTime = if ($lastToggleTime) { $lastToggleTime.ToString("o") } else { $null }
        $pending.RunOnceOnLaunch = $script:runOnceOnLaunchBox.Checked
        $pending.PauseUntil = if ($pauseUntil) { $pauseUntil.ToString("o") } else { $null }
        $pending.PauseDurationsMinutes = [string]$script:pauseDurationsBox.Text
        $pending.ScheduleOverrideEnabled = $script:scheduleOverrideBox.Checked
        $pending.ScheduleEnabled = $script:scheduleEnabledBox.Checked
        $pending.ScheduleStart = $script:scheduleStartBox.Value.ToString("HH:mm")
        $pending.ScheduleEnd = $script:scheduleEndBox.Value.ToString("HH:mm")
        $pending.ScheduleWeekdays = [string]$script:scheduleWeekdaysBox.Text
        $pending.ScheduleSuspendUntil = if ($scheduleSuspendUntil) { $scheduleSuspendUntil.ToString("o") } else { $null }
        $pending.SafeModeEnabled = $script:SafeModeEnabledBox.Checked
        $pending.SafeModeFailureThreshold = $safeModeThreshold
        $pending.HotkeyToggle = $hotkeyToggle
        $pending.HotkeyStartStop = $hotkeyStartStop
        $pending.HotkeyPauseResume = $hotkeyPauseResume
        $pending.LogLevel = [string]$script:logLevelBox.SelectedItem
        if ([string]::IsNullOrWhiteSpace($pending.LogLevel)) {
            $pending.LogLevel = [string]$settings.LogLevel
        }
        if ([string]::IsNullOrWhiteSpace($pending.LogLevel)) {
            $pending.LogLevel = "INFO"
        }
        $pending.LogLevel = $pending.LogLevel.ToUpperInvariant()
        if (-not $script:LogLevels.ContainsKey($pending.LogLevel)) {
            $pending.LogLevel = [string]$settings.LogLevel
            if ([string]::IsNullOrWhiteSpace($pending.LogLevel)) { $pending.LogLevel = "INFO" }
            $pending.LogLevel = $pending.LogLevel.ToUpperInvariant()
        }
        $pending.LogMaxBytes = $logMaxKb * 1024
        $pending.LogRetentionDays = [int]$script:logRetentionBox.Value
        $pending.DataRoot = $script:DataRoot
        $logDirText = Normalize-PathText ([string]$script:logDirectoryBox.Text)
        if ([string]::IsNullOrWhiteSpace($logDirText)) {
            $pending.LogDirectory = $script:FolderNames.Logs
        } else {
            $resolvedLogDir = Convert-FromRelativePath $logDirText
            if ([string]::IsNullOrWhiteSpace($resolvedLogDir)) { $resolvedLogDir = $defaultLogDir }
            $pending.LogDirectory = Convert-ToRelativePathIfUnderRoot $resolvedLogDir
        }
        $settingsDirText = Normalize-PathText ([string]$script:settingsDirectoryBox.Text)
        if ([string]::IsNullOrWhiteSpace($settingsDirText)) {
            $pending.SettingsDirectory = $script:FolderNames.Settings
        } else {
            $resolvedSettingsDir = Convert-FromRelativePath $settingsDirText
            if ([string]::IsNullOrWhiteSpace($resolvedSettingsDir)) { $resolvedSettingsDir = $defaultSettingsDir }
            $pending.SettingsDirectory = Convert-ToRelativePathIfUnderRoot $resolvedSettingsDir
        }
        $pending.LogIncludeStackTrace = $script:logIncludeStackTraceBox.Checked
        $pending.LogToEventLog = $script:logToEventLogBox.Checked
        $pending.VerboseUiLogging = $script:verboseUiLogBox.Checked
        $pending.LogEventLevels = @{}
        if ($script:LogEventLevelBoxes) {
            foreach ($levelName in $script:LogEventLevelBoxes.Keys) {
                $pending.LogEventLevels[$levelName] = [bool]$script:LogEventLevelBoxes[$levelName].Checked
            }
        }
        if ($script:ScrubDiagnosticsBox) {
            $pending.ScrubDiagnostics = $script:ScrubDiagnosticsBox.Checked
        }
        $pending.LogCategories = @{}
        if ($script:logCategoryBoxes) {
            foreach ($name in $script:LogCategoryNames) {
                if ($script:logCategoryBoxes.ContainsKey($name)) {
                    $pending.LogCategories[$name] = [bool]$script:logCategoryBoxes[$name].Checked
                }
            }
        }
        if ($script:SettingsTabControl -and $script:SettingsTabControl.SelectedTab) {
            $pending.LastSettingsTab = if ($script:GetSettingsTabKey) { & $script:GetSettingsTabKey $script:SettingsTabControl.SelectedTab } else { [string]$script:SettingsTabControl.SelectedTab.Text }
        }
        Sync-ActiveProfileSnapshot $pending

        $pending = Normalize-Settings (Migrate-Settings $pending)
        return [pscustomobject]@{
            Settings = $pending
            Errors = $errors
            LastToggleTime = $lastToggleTime
            PauseUntil = $pauseUntil
            ScheduleSuspendUntil = $scheduleSuspendUntil
        }
    }

    $script:ShowPendingSettingsDiff = {
        param($pendingSettings)
        $baseSnapshot = if ($script:LastSettingsSnapshot) { $script:LastSettingsSnapshot } else { Get-SettingsSnapshot $settings }
        $pendingSnapshot = Get-SettingsSnapshot $pendingSettings
        $pendingHash = Get-SettingsSnapshotHash $pendingSnapshot
        $baseHash = if ($script:LastSettingsSnapshotHash) { $script:LastSettingsSnapshotHash } else { Get-SettingsSnapshotHash $baseSnapshot }
        if ($pendingHash -eq $baseHash) {
            [System.Windows.Forms.MessageBox]::Show(
                "No changes detected.",
                "Preview Changes",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            return $false
        }
        $pendingDiffs = @(Get-SettingsDiff $baseSnapshot $pendingSnapshot)
        if ($pendingDiffs.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "No changes detected.",
                "Preview Changes",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            return $false
        }
        $maxLines = 20
        $shown = $pendingDiffs | Select-Object -First $maxLines
        $message = "Changes preview:`n`n" + ($shown -join "`n")
        if ($pendingDiffs.Count -gt $maxLines) {
            $message += "`n`n...and $($pendingDiffs.Count - $maxLines) more."
        }
        [System.Windows.Forms.MessageBox]::Show(
            $message,
            "Preview Changes",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        return $true
    }

    $previewChangesButton.Add_Click({
        & $script:RunSettingsAction "Preview Changes" {
            $collectResult = & $script:CollectSettingsFromControls -ShowErrors
            if (-not $collectResult -or $collectResult.Errors.Count -gt 0) { return }
            if (& $script:ShowPendingSettingsDiff $collectResult.Settings) {
                Write-Log "UI: Settings preview displayed." "DEBUG" $null "Settings-Dialog"
            }
        }
    })

    $undoChangesButton.Add_Click({
        & $script:RunSettingsAction "Undo Changes" {
            if (-not $script:settingsDialogLastSaved) { return }
            & $applySettingsToControls $script:settingsDialogLastSaved
            Set-SettingsDirty $false
            Write-Log "UI: Settings reverted to last saved." "DEBUG" $null "Settings-Dialog"
        }
    })

    $script:SettingsOkButton.Add_Click({
        try {
        Set-LastUserAction "Save Settings" "Settings"
        $collectResult = & $script:CollectSettingsFromControls -ShowErrors
        if (-not $collectResult -or $collectResult.Errors.Count -gt 0) { return }

        $pendingSettings = $collectResult.Settings
        $lastToggleTime = $collectResult.LastToggleTime
        $pauseUntil = $collectResult.PauseUntil
        $scheduleSuspendUntil = $collectResult.ScheduleSuspendUntil

        $settings = $pendingSettings
        if ($script:EnsureProfilesHashtable) { & $script:EnsureProfilesHashtable }
        if ($script:EnsureLogCategoriesHashtable) { & $script:EnsureLogCategoriesHashtable }

        if ($settings.StartWithWindows -ne $pendingSettings.StartWithWindows) {
            try {
                Set-StartupShortcut $pendingSettings.StartWithWindows
            } catch {
                Write-Log "Failed to update startup shortcut." "ERROR" $_.Exception "Settings-Dialog"
                [System.Windows.Forms.MessageBox]::Show(
                    "Failed to update Startup setting.`n$($_.Exception.Message)",
                    "Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                ) | Out-Null
                return
            }
        }

        $logLevelChanged = ($settings.LogLevel -ne $pendingSettings.LogLevel)
        $script:settings = $pendingSettings
        $settings = $script:settings
        if ($script:EnsureProfilesHashtable) { & $script:EnsureProfilesHashtable }
        if ($script:EnsureLogCategoriesHashtable) { & $script:EnsureLogCategoriesHashtable }
        $desiredSettingsDir = Resolve-DirectoryOrDefault ([string]$settings.SettingsDirectory) $defaultSettingsDir "Settings"
        if ($desiredSettingsDir -ne $script:SettingsDirectory) {
            Set-SettingsDirectory $desiredSettingsDir
        }
        $desiredLogDir = Resolve-DirectoryOrDefault ([string]$settings.LogDirectory) $defaultLogDir "Logs"
        if ($desiredLogDir -ne $script:LogDirectory) {
            Set-LogDirectory $desiredLogDir
        }
        if ($script:LastSettingsSnapshot) {
            $pendingSnapshot = Get-SettingsSnapshot $pendingSettings
            $pendingHash = Get-SettingsSnapshotHash $pendingSnapshot
            if ($script:LastSettingsSnapshotHash -and $pendingHash -eq $script:LastSettingsSnapshotHash) {
                $pendingDiffs = @()
            } else {
                $pendingDiffs = @(Get-SettingsDiff $script:LastSettingsSnapshot $pendingSnapshot)
            }
            # Confirm Save prompt removed per request.
        }

        Write-Log "UI: ---------- Settings Save ----------" "DEBUG" $null "Settings-Dialog"
        Save-Settings $settings
        if ($updateProfilesMenu) { & $updateProfilesMenu }

        if ($script:QuickQuietModeItem) { $script:QuickQuietModeItem.Checked = [bool]$settings.QuietMode }
        if ($updateQuickSettingsChecks) { & $updateQuickSettingsChecks }
        $script:LogLevel = [string]$settings.LogLevel
        if ([string]::IsNullOrWhiteSpace($script:LogLevel)) { $script:LogLevel = "INFO" }
        $script:LogLevel = $script:LogLevel.ToUpperInvariant()
        if (-not $script:LogLevels.ContainsKey($script:LogLevel)) { $script:LogLevel = "INFO" }
        $settings.DateTimeFormat = Normalize-DateTimeFormat ([string]$settings.DateTimeFormat)
        $script:DateTimeFormat = $settings.DateTimeFormat
        $script:UseSystemDateTimeFormat = [bool]$settings.UseSystemDateTimeFormat
        $script:SystemDateTimeFormatMode = if ([string]::IsNullOrWhiteSpace([string]$settings.SystemDateTimeFormatMode)) { "Short" } else { [string]$settings.SystemDateTimeFormatMode }
        $pickerFormat = if ($script:UseSystemDateTimeFormat) { if ($script:SystemDateTimeFormatMode -eq "Long") { "F" } else { "g" } } else { $script:DateTimeFormat }
        if ($script:LastTogglePicker) { $script:LastTogglePicker.CustomFormat = $pickerFormat }
        if ($script:pauseUntilBox) { $script:pauseUntilBox.CustomFormat = $pickerFormat }
        if ($script:scheduleSuspendUntilBox) { $script:scheduleSuspendUntilBox.CustomFormat = $pickerFormat }
        if ($script:dateTimeFormatBox) { $script:dateTimeFormatBox.Text = $script:DateTimeFormat }
        if ($script:useSystemDateTimeFormatBox) {
            $script:useSystemDateTimeFormatBox.Checked = $script:UseSystemDateTimeFormat
        }
        if ($script:systemDateTimeFormatModeBox) {
            $script:systemDateTimeFormatModeBox.SelectedItem = if ($script:SystemDateTimeFormatMode -eq "Long") { "Long" } else { "Short" }
        }
        if ($script:dateTimeFormatPresetBox) { $script:dateTimeFormatPresetBox.SelectedIndex = 0 }
        if ($script:dateTimeFormatBox) { $script:dateTimeFormatBox.Enabled = -not $script:UseSystemDateTimeFormat }
        if ($script:dateTimeFormatPresetBox) { $script:dateTimeFormatPresetBox.Enabled = -not $script:UseSystemDateTimeFormat }
        if ($script:systemDateTimeFormatModeBox) { $script:systemDateTimeFormatModeBox.Enabled = $script:UseSystemDateTimeFormat }
        if ($script:updateDateTimePreview) { & $script:updateDateTimePreview }
        Update-LogLevelMenuChecks
        if ($logLevelChanged -and $script:DebugModeUntil) {
            Disable-DebugMode
        }
        $script:LogMaxBytes = [int]$settings.LogMaxBytes
        $script:LogMaxTotalBytes = [long]$settings.LogMaxTotalBytes
        if ($script:LogMaxTotalBytes -le 0) { $script:LogMaxTotalBytes = 20971520 }
        $script:EventLogReady = $false
        Update-LogCategorySettings
        Update-ThemePreference
        Apply-MenuFontSize ([int]$settings.FontSize)
        Apply-SettingsFontSize ([int]$settings.SettingsFontSize)
        if (-not $settings.SafeModeEnabled) {
            $script:safeModeActive = $false
            $script:toggleFailCount = 0
        }

        $script:lastToggleTime = $lastToggleTime

        if ($pauseUntil -and $pauseUntil -gt (Get-Date)) {
            $script:isPaused = $true
            $script:isRunning = $true
            $script:pauseUntil = $pauseUntil
            $timer.Stop()
            Update-NotifyIconText "Paused"
        } else {
            if ($script:isPaused) {
                $script:isPaused = $false
                $script:pauseUntil = $null
                Start-Toggling
            }
        }

        $timer.Interval = [int]$settings.IntervalSeconds * 1000
        if ($script:isRunning -and -not $script:isPaused) { $timer.Start() }
        Rebuild-PauseMenu
        Register-Hotkeys
        Update-NextToggleTime
        Request-StatusUpdate
        Write-Log "UI: Settings updated via dialog. LogLevel=$($settings.LogLevel) LogMaxBytes=$($settings.LogMaxBytes) LogMaxTotalBytes=$($settings.LogMaxTotalBytes)" "DEBUG" $null "Settings-Dialog"
        $script:settingsDialogLastSaved = & $script:CopySettingsObject $settings
        & $script:UpdateLastSavedLabel (Get-Date)
        Set-SettingsDirty $false
        if ($script:UpdateProfileDirtyIndicator) { & $script:UpdateProfileDirtyIndicator }

        if ($script:SettingsForm -and -not $script:SettingsForm.IsDisposed) {
            $script:SettingsForm.DialogResult = [System.Windows.Forms.DialogResult]::None
        }
        } catch {
            Write-Log "UI: Settings save failed." "ERROR" $_.Exception "Settings-Dialog"
            if ($_.InvocationInfo) {
                Write-Log ("UI: Settings save failed at {0}:{1} char {2}" -f $_.InvocationInfo.ScriptName, $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine) "ERROR" $null "Settings-Dialog"
                Write-Log ("UI: Settings save failed line: {0}" -f ($_.InvocationInfo.Line.Trim())) "ERROR" $null "Settings-Dialog"
            }
            [System.Windows.Forms.MessageBox]::Show(
                "Save failed. Please check the log for details.",
                "Settings Save Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
    })

    $doneButton.Add_Click({
        Write-Log "UI: Settings closed via Done." "DEBUG" $null "Settings-Dialog"
        if ($script:SettingsForm -and -not $script:SettingsForm.IsDisposed) {
            $script:SettingsForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $script:SettingsForm.Close()
        }
    })

    $leftButtons.Controls.Add($resetButton)
    $leftButtons.Controls.Add($testButton)
    $leftButtons.Controls.Add($previewChangesButton)
    $leftButtons.Controls.Add($undoChangesButton)
    $leftButtons.Controls.Add($script:LastSavedLabel)

    $rightButtons.Controls.Add($cancelButton)
    $rightButtons.Controls.Add($doneButton)
    $rightButtons.Controls.Add($script:SettingsOkButton)

    $buttonsPanel.Controls.Add($leftButtons, 0, 0)
    $buttonsPanel.Controls.Add($rightButtons, 1, 0)

    $form.AcceptButton = $script:SettingsOkButton
    $form.CancelButton = $cancelButton

    $form.Controls.Add($mainPanel)
    $form.Controls.Add($buttonsPanel)

    Update-ThemePreference

    $formatSize = {
        param([long]$bytes)
        if ($bytes -ge 1MB) { return ("{0:N1} MB" -f ($bytes / 1MB)) }
        if ($bytes -ge 1KB) { return ("{0:N0} KB" -f ($bytes / 1KB)) }
        return ("{0} B" -f $bytes)
    }
    $script:FormatSize = $formatSize
    $setTextIfChanged = {
        param($control, $text)
        if ($null -eq $control) { return }
        if (-not $control.PSObject.Properties.Match('Text')) { return }
        $newText = [string]$text
        try {
            if ($control.Text -ne $newText) { $control.Text = $newText }
        } catch {
            return
        }
    }
    $setVisibleIfChanged = {
        param($control, $visible)
        if ($null -eq $control) { return }
        if (-not $control.PSObject.Properties.Match('Visible')) { return }
        $newVisible = [bool]$visible
        try {
            if ($control.Visible -ne $newVisible) { $control.Visible = $newVisible }
        } catch {
            return
        }
    }
    $setForeColorIfChanged = {
        param($control, $color)
        if ($null -eq $control) { return }
        if (-not $control.PSObject.Properties.Match('ForeColor')) { return }
        try {
            if ($control.ForeColor -ne $color) { $control.ForeColor = $color }
        } catch {
            return
        }
    }
    $script:SettingsSetText = $setTextIfChanged
    $script:SettingsSetVisible = $setVisibleIfChanged
    $script:SettingsSetForeColor = $setForeColorIfChanged

    $updateSettingsStatus = {
        if ($script:isShuttingDown -or $script:SettingsUiRefreshInProgress) { return }
        $script:SettingsUiRefreshInProgress = $true
        $script:Now = Get-Date
        $step = "init"
        $statusCacheVar = Get-Variable -Name SettingsStatusCache -Scope Script -ErrorAction SilentlyContinue
        if (-not $statusCacheVar -or -not $statusCacheVar.Value) { $script:SettingsStatusCache = @{} }
        $getCachedValue = {
            param([string]$key, $value, [ScriptBlock]$compute)
            if ($script:SettingsStatusCache.ContainsKey($key)) {
                $entry = $script:SettingsStatusCache[$key]
                if ($entry -and $entry.Value -eq $value) { return $entry.Result }
            }
            $result = & $compute
            $script:SettingsStatusCache[$key] = @{ Value = $value; Result = $result }
            return $result
        }
        if (-not ($script:SettingsSetText -is [scriptblock])) {
            $script:SettingsSetText = {
                param($control, $text)
                if ($null -eq $control) { return }
                if (-not $control.PSObject.Properties.Match('Text')) { return }
                $newText = [string]$text
                try {
                    if ($control.Text -ne $newText) { $control.Text = $newText }
                } catch {
                    return
                }
            }
        }
        if (-not ($script:SettingsSetVisible -is [scriptblock])) {
            $script:SettingsSetVisible = {
                param($control, $visible)
                if ($null -eq $control) { return }
                if (-not $control.PSObject.Properties.Match('Visible')) { return }
                $newVisible = [bool]$visible
                try {
                    if ($control.Visible -ne $newVisible) { $control.Visible = $newVisible }
                } catch {
                    return
                }
            }
        }
        if (-not ($script:SettingsSetForeColor -is [scriptblock])) {
            $script:SettingsSetForeColor = {
                param($control, $color)
                if ($null -eq $control) { return }
                if (-not $control.PSObject.Properties.Match('ForeColor')) { return }
                try {
                    if ($control.ForeColor -ne $color) { $control.ForeColor = $color }
                } catch {
                    return
                }
            }
        }
        $getSettingsControl = {
            param([string]$name)
            $var = Get-Variable -Name $name -Scope Script -ErrorAction SilentlyContinue
            if ($var) { return $var.Value }
            return $null
        }
        try {
        $targetForm = $script:SettingsForm
        if (-not $targetForm -or $targetForm.IsDisposed) { return }
        $shouldUpdate = ($targetForm.Visible -and $targetForm.WindowState -ne [System.Windows.Forms.FormWindowState]::Minimized)
        $selectedTab = $script:SettingsTabControl.SelectedTab
        $statusPage = $script:SettingsStatusPanel.Parent
        $hotkeysPage = $script:SettingsHotkeyPanel.Parent
        $loggingPage = $script:SettingsLoggingPanel.Parent
        $diagnosticsPage = $script:SettingsDiagnosticsPanel.Parent

            $step = "StatusTab"
            if ($shouldUpdate -and $statusPage -and $selectedTab -eq $statusPage) {
                $step = "StatusTab-Base"
                Request-StatusUpdate
                $pauseUntilText = Format-PauseUntilText
                $statusText = $script:StatusStateText
                if ($script:isPaused) {
                    if ($pauseUntilText -and $pauseUntilText -ne "N/A") {
                        $statusText = "Paused (Until $pauseUntilText)"
                    } else {
                        $statusText = "Paused"
                    }
                }
                if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $script:SettingsStatusValue $statusText }
                if ($script:SettingsSetForeColor -is [scriptblock]) { & $script:SettingsSetForeColor $script:SettingsStatusValue $script:StatusStateColor }
                $nextText = Format-NextInfo
                if ($script:isPaused) {
                    if ($pauseUntilText -and $pauseUntilText -ne "N/A") {
                        $nextText = "Paused (Until $pauseUntilText)"
                    } else {
                        $nextText = "Paused"
                    }
                }
                if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $script:SettingsNextValue $nextText }
                $uptimeSpan = (Get-Date) - $script:AppStartTime
                if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $script:SettingsUptimeValue ("{0}h {1}m" -f [int]$uptimeSpan.TotalHours, $uptimeSpan.Minutes) }
                if ($script:LastToggleResultTime) {
                    if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $script:SettingsLastToggleValue "$($script:LastToggleResult) - $(Format-LocalTime $script:LastToggleResultTime)" }
                } else {
                    if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $script:SettingsLastToggleValue $script:LastToggleResult }
                }
                if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $script:SettingsNextCountdownValue "N/A" }
                if ($script:isRunning -and -not $script:isPaused -and -not $script:isScheduleBlocked -and $script:nextToggleTime) {
                    $remaining = [int][Math]::Max(0, ($script:nextToggleTime - (Get-Date)).TotalSeconds)
                    if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $script:SettingsNextCountdownValue "$remaining s ($($script:nextToggleTime.ToString("T")))" }
                }
                if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $script:SettingsProfileStatusValue ([string]$settings.ActiveProfile) }
                if ($script:SettingsToggleCurrentValue) {
                    if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $script:SettingsToggleCurrentValue ([string]$script:tickCount) }
                }
                if ($script:SettingsToggleLifetimeValue) {
                    if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $script:SettingsToggleLifetimeValue ([string]$settings.ToggleCount) }
                }
                $step = "StatusTab-FunStats"
                try {
                    $cacheFresh = $false
                    if ($script:FunStatsCache -and $script:FunStatsCache.Updated) {
                        $cacheFresh = ((Get-Date) - $script:FunStatsCache.Updated).TotalSeconds -lt 10
                    }
                    if (-not $cacheFresh) {
                        $funStats = Ensure-FunStats $settings
                        $dailyCount = [string](Get-DailyToggleCount $funStats (Get-Date))
                        $streaks = Get-ToggleStreaks $funStats
                        $mostActive = Get-MostActiveHourLabel $funStats
                        $longestPause = 0
                        try {
                            if ($funStats -is [System.Collections.IDictionary] -and $funStats.ContainsKey("LongestPauseMinutes")) {
                                $longestPause = [int]$funStats["LongestPauseMinutes"]
                            } elseif ($funStats -and $funStats.PSObject.Properties.Match("LongestPauseMinutes").Count -gt 0) {
                                $longestPause = [int]$funStats.LongestPauseMinutes
                            }
                        } catch {
                            $longestPause = 0
                        }
                        $totalRun = 0.0
                        try {
                            if ($funStats -is [System.Collections.IDictionary] -and $funStats.ContainsKey("TotalRunMinutes")) {
                                $totalRun = [double]$funStats["TotalRunMinutes"]
                            } elseif ($funStats -and $funStats.PSObject.Properties.Match("TotalRunMinutes").Count -gt 0) {
                                $totalRun = [double]$funStats.TotalRunMinutes
                            }
                        } catch {
                            $totalRun = 0.0
                        }
                        $script:FunStatsCache = @{
                            Updated = Get-Date
                            Daily = $dailyCount
                            Streaks = $streaks
                            MostActive = $mostActive
                            LongestPause = $longestPause
                            TotalRun = $totalRun
                        }
                    } else {
                        $dailyCount = [string]$script:FunStatsCache.Daily
                        $streaks = $script:FunStatsCache.Streaks
                        $mostActive = $script:FunStatsCache.MostActive
                        $longestPause = [int]$script:FunStatsCache.LongestPause
                        $totalRun = [double]$script:FunStatsCache.TotalRun
                    }
                    $funDailyControl = & $getSettingsControl 'SettingsFunDailyValue'
                    if ($funDailyControl) {
                        if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $funDailyControl $dailyCount }
                    }
                    $funStreakCurrentControl = & $getSettingsControl 'SettingsFunStreakCurrentValue'
                    if ($funStreakCurrentControl -and $streaks) {
                        if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $funStreakCurrentControl "$($streaks.Current) days" }
                    }
                    $funStreakBestControl = & $getSettingsControl 'SettingsFunStreakBestValue'
                    if ($funStreakBestControl -and $streaks) {
                        if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $funStreakBestControl "$($streaks.Best) days" }
                    }
                    $funMostActiveControl = & $getSettingsControl 'SettingsFunMostActiveHourValue'
                    if ($funMostActiveControl) {
                        if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $funMostActiveControl $mostActive }
                    }
                    $funLongestPauseControl = & $getSettingsControl 'SettingsFunLongestPauseValue'
                    if ($funLongestPauseControl) {
                        if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $funLongestPauseControl (if ($longestPause -gt 0) { "$longestPause min" } else { "N/A" }) }
                    }
                    $funTotalRunControl = & $getSettingsControl 'SettingsFunTotalRunValue'
                    if ($funTotalRunControl) {
                        if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $funTotalRunControl (Format-TotalRunTime $totalRun) }
                    }
                } catch {
                    # swallow to avoid UI spam; outer logger will still catch severe issues elsewhere
                }
                $step = "StatusTab-Schedule"
                $scheduleText = Format-ScheduleStatus
                $scheduleStatusControl = & $getSettingsControl 'SettingsScheduleStatusValue'
                try {
                    if ($scheduleStatusControl -and ($script:SettingsSetText -is [scriptblock])) {
                        & $script:SettingsSetText $scheduleStatusControl $scheduleText
                    }
                } catch {
                    # ignore transient UI updates
                }
                $safeModeStatusControl = & $getSettingsControl 'SettingsSafeModeStatusValue'
                try {
                    if ($safeModeStatusControl -and ($script:SettingsSetText -is [scriptblock])) {
                        & $script:SettingsSetText $safeModeStatusControl (if ($script:safeModeActive) { "On (Fails=$($script:toggleFailCount))" } else { "Off" })
                    }
                } catch {
                    # ignore transient UI updates
                }
                $step = "StatusTab-Keyboard"
                $caps = [System.Windows.Forms.Control]::IsKeyLocked([System.Windows.Forms.Keys]::CapsLock)
                $num = [System.Windows.Forms.Control]::IsKeyLocked([System.Windows.Forms.Keys]::NumLock)
                $scroll = [System.Windows.Forms.Control]::IsKeyLocked([System.Windows.Forms.Keys]::Scroll)
                $keyboardStatusControl = & $getSettingsControl 'SettingsKeyboardValue'
                if ($keyboardStatusControl -and ($script:SettingsSetText -is [scriptblock])) {
                    & $script:SettingsSetText $keyboardStatusControl ("Caps:{0} Num:{1} Scroll:{2}" -f ($(if ($caps) { "On" } else { "Off" })), ($(if ($num) { "On" } else { "Off" })), ($(if ($scroll) { "On" } else { "Off" })))
                }
            }

            $step = "HotkeysTab"
            if ($shouldUpdate -and $hotkeysPage -and $selectedTab -eq $hotkeysPage) {
                if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $script:SettingsHotkeyStatusValue $script:HotkeyStatusText }
                if ($script:SettingsHotkeyWarningLabel) {
                    $hasIssues = ($script:HotkeyStatusText -match "Failed|Issues")
                    if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $script:SettingsHotkeyWarningLabel "One or more hotkeys failed to register. Update them and click Validate." }
                    if ($script:SettingsSetVisible -is [scriptblock]) { & $script:SettingsSetVisible $script:SettingsHotkeyWarningLabel $hasIssues }
                }
            }

            $step = "LoggingTab"
            if ($shouldUpdate -and $loggingPage -and $selectedTab -eq $loggingPage) {
                $logBytes = 0
                if (Test-Path $logPath) {
                    try { $logBytes = (Get-Item -Path $logPath).Length } catch { $logBytes = 0 }
                }
                $now = Get-Date
                $shouldRefresh = $true
                $lastUpdateVar = Get-Variable -Name SettingsLoggingStatusLastUpdate -Scope Script -ErrorAction SilentlyContinue
                $lastBytesVar = Get-Variable -Name SettingsLoggingStatusLastBytes -Scope Script -ErrorAction SilentlyContinue
                if ($lastUpdateVar -and $lastUpdateVar.Value -and $lastBytesVar -and $lastBytesVar.Value -eq $logBytes) {
                    if (($now - $lastUpdateVar.Value).TotalSeconds -lt 2) { $shouldRefresh = $false }
                }
                if ($shouldRefresh) {
                    $maxBytes = [long]($script:SettingsLogMaxBox.Value * 1024)
                    $logSizeText = & $getCachedValue ("LogSizeText:{0}:{1}" -f $logBytes, $maxBytes) "$logBytes|$maxBytes" {
                        "$(& $script:FormatSize $logBytes) / $(& $script:FormatSize $maxBytes)"
                    }
                    if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $script:SettingsLogSizeValue $logSizeText }
                    $script:SettingsLoggingStatusLastUpdate = $now
                    $script:SettingsLoggingStatusLastBytes = $logBytes
                }
            }

            $step = "DiagnosticsTab"
            if ($shouldUpdate -and $diagnosticsPage -and $selectedTab -eq $diagnosticsPage) {
                try {
                    $diagErrorControl = & $getSettingsControl 'SettingsDiagErrorValue'
                    $diagRestartControl = & $getSettingsControl 'SettingsDiagRestartValue'
                    $diagSafeModeControl = & $getSettingsControl 'SettingsDiagSafeModeValue'
                    $debugModeStatusControl = & $getSettingsControl 'SettingsDebugModeStatus'
                    $diagLastToggleControl = & $getSettingsControl 'SettingsDiagLastToggleValue'
                    $diagFailControl = & $getSettingsControl 'SettingsDiagFailValue'
                    $diagLogSizeControl = & $getSettingsControl 'SettingsDiagLogSizeValue'
                    $diagLogRotateControl = & $getSettingsControl 'SettingsDiagLogRotateValue'
                    $diagLogWriteControl = & $getSettingsControl 'SettingsDiagLogWriteValue'
                    if ($script:LastErrorMessage) {
                        $errorTime = if ($script:LastErrorTime) { Format-LocalTime $script:LastErrorTime } else { "Unknown" }
                        if ($diagErrorControl -and ($script:SettingsSetText -is [scriptblock])) { & $script:SettingsSetText $diagErrorControl "$errorTime - $($script:LastErrorMessage)" }
                    } else {
                        if ($diagErrorControl -and ($script:SettingsSetText -is [scriptblock])) { & $script:SettingsSetText $diagErrorControl "None" }
                    }
                    if ($diagRestartControl -and ($script:SettingsSetText -is [scriptblock])) { & $script:SettingsSetText $diagRestartControl (Format-LocalTime $script:AppStartTime) }
                    if ($diagSafeModeControl -and ($script:SettingsSetText -is [scriptblock])) { & $script:SettingsSetText $diagSafeModeControl ($(if ($script:safeModeActive) { "On" } else { "Off" })) }
                    if ($debugModeStatusControl -and ($script:SettingsSetText -is [scriptblock])) { & $script:SettingsSetText $debugModeStatusControl (if ($script:DebugModeUntil) { "On (10 min)" } else { "Off" }) }
                    if ($script:LastToggleResultTime) {
                        if ($diagLastToggleControl -and ($script:SettingsSetText -is [scriptblock])) { & $script:SettingsSetText $diagLastToggleControl "$($script:LastToggleResult) - $(Format-LocalTime $script:LastToggleResultTime)" }
                    } else {
                        if ($diagLastToggleControl -and ($script:SettingsSetText -is [scriptblock])) { & $script:SettingsSetText $diagLastToggleControl $script:LastToggleResult }
                    }
                    if ($diagFailControl -and ($script:SettingsSetText -is [scriptblock])) { & $script:SettingsSetText $diagFailControl ([string]$script:toggleFailCount) }
                    $diagBytes = 0
                    if (Test-Path $logPath) {
                        try { $diagBytes = (Get-Item -Path $logPath).Length } catch { $diagBytes = 0 }
                    }
                    $diagSizeText = & $getCachedValue ("DiagLogSize:{0}" -f $diagBytes) $diagBytes { & $script:FormatSize $diagBytes }
                    if ($diagLogSizeControl -and ($script:SettingsSetText -is [scriptblock])) { & $script:SettingsSetText $diagLogSizeControl $diagSizeText }
                    if ($diagLogRotateControl -and ($script:SettingsSetText -is [scriptblock])) { & $script:SettingsSetText $diagLogRotateControl ([string]$script:LogRotationCount) }
                    if ($script:LastLogWriteTime) {
                        if ($diagLogWriteControl -and ($script:SettingsSetText -is [scriptblock])) { & $script:SettingsSetText $diagLogWriteControl (Format-LocalTime $script:LastLogWriteTime) }
                    } else {
                        if ($diagLogWriteControl -and ($script:SettingsSetText -is [scriptblock])) { & $script:SettingsSetText $diagLogWriteControl "N/A" }
                    }
                } catch {
                    # swallow to avoid UI spam on diagnostics refresh
                }
            }

            $step = "ResetConfirm"
            if ($script:SettingsResetConfirmState.Pending) {
                $remainingSeconds = [int][Math]::Ceiling(($script:SettingsResetConfirmState.Deadline - (Get-Date)).TotalSeconds)
                if ($remainingSeconds -le 0) {
                    $script:SettingsResetConfirmState.Pending = $false
                    $script:SettingsResetConfirmState.Deadline = $null
                    if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $script:SettingsResetButton "Restore Defaults" }
                } else {
                    $script:SettingsResetConfirmState.Remaining = $remainingSeconds
                    if ($script:SettingsSetText -is [scriptblock]) { & $script:SettingsSetText $script:SettingsResetButton "Confirm Reset ($($script:SettingsResetConfirmState.Remaining))" }
                }
            }
        } catch {
            $lineInfo = $null
            if ($_.InvocationInfo) {
                $lineNo = $_.InvocationInfo.ScriptLineNumber
                $lineText = $_.InvocationInfo.Line
                if ($lineNo) { $lineInfo = "Line ${lineNo}: $lineText" }
            }
            $detail = if ($lineInfo) { "Settings status update failed at $step. $lineInfo" } else { "Settings status update failed at $step." }
            Write-LogThrottled "SettingsStatus-$step" $detail "WARN" 10
        } finally {
            $script:Now = $null
            $script:SettingsUiRefreshInProgress = $false
        }
    }
    $script:UpdateSettingsStatus = $updateSettingsStatus

    $script:SettingsFirstPaintDone = $false
    $script:SettingsStatusTimer = New-Object System.Windows.Forms.Timer
    $script:SettingsStatusTimer.Interval = 2000
    $script:SettingsStatusTimer.Add_Tick({
        Invoke-SafeTimerAction "SettingsStatusTimer" {
            if ($script:isShuttingDown -or $script:CleanupDone) { return }
            if ($script:UpdateSettingsStatus) { & $script:UpdateSettingsStatus }
        }
    })

    $updateStatusTimerState = {
        if ($script:isShuttingDown -or $script:CleanupDone) { return }
        if (-not $script:SettingsFirstPaintDone) { return }
        $targetForm = $script:SettingsForm
        if (-not $targetForm -or $targetForm.IsDisposed) { return }
        $shouldRun = ($targetForm.Visible -and $targetForm.WindowState -ne [System.Windows.Forms.FormWindowState]::Minimized)
        if ($shouldRun) {
            if (-not $script:SettingsStatusTimer.Enabled) { $script:SettingsStatusTimer.Start() }
        } else {
            if ($script:SettingsStatusTimer.Enabled) { $script:SettingsStatusTimer.Stop() }
        }
    }
    $script:UpdateStatusTimerState = $updateStatusTimerState

    $form.Add_Shown({
        if (-not $script:SettingsForm -or $script:SettingsForm.IsDisposed) { return }
        Invoke-SettingsShownStep "Apply-Theme" { Apply-ThemeToControl $script:SettingsForm $script:ThemePalette $script:UseDarkTheme }
        Invoke-SettingsShownStep "Apply-MenuFontSize" { Apply-MenuFontSize ([int]$settings.FontSize) }
        Invoke-SettingsShownStep "Apply-SettingsFontSize" { Apply-SettingsFontSize ([int]$settings.SettingsFontSize) }
        if ($script:UpdateAppearancePreview) { Invoke-SettingsShownStep "UpdateAppearancePreview" { & $script:UpdateAppearancePreview } }
        if ($script:UpdateTabLayouts) { Invoke-SettingsShownStep "UpdateTabLayouts" { & $script:UpdateTabLayouts } }
        if ($script:UpdateSettingsStatus) {
            Invoke-SettingsShownStep "UpdateSettingsStatus" {
                $script:SettingsForm.BeginInvoke([Action]{
                    if ($script:UpdateSettingsStatus) { & $script:UpdateSettingsStatus }
                    $script:SettingsFirstPaintDone = $true
                    if ($script:UpdateStatusTimerState) { & $script:UpdateStatusTimerState }
                }) | Out-Null
            }
        } else {
            $script:SettingsFirstPaintDone = $true
            if ($script:UpdateStatusTimerState) { Invoke-SettingsShownStep "UpdateStatusTimerState" { & $script:UpdateStatusTimerState } }
        }
    })

    $form.Add_SizeChanged({
        if ($script:UpdateTabLayouts) { & $script:UpdateTabLayouts }
        if ($script:UpdateStatusTimerState) { & $script:UpdateStatusTimerState }
    })

    $form.Add_VisibleChanged({
        if ($script:UpdateStatusTimerState) { & $script:UpdateStatusTimerState }
    })

    $form.Add_FormClosing({
        if ($script:openSettingsLastTabBox) {
            $settings.OpenSettingsAtLastTab = [bool]$script:openSettingsLastTabBox.Checked
        }
        if ($settings.OpenSettingsAtLastTab -and $script:SettingsTabControl -and $script:SettingsTabControl.SelectedTab) {
            $settings.LastSettingsTab = if ($script:GetSettingsTabKey) { & $script:GetSettingsTabKey $script:SettingsTabControl.SelectedTab } else { [string]$script:SettingsTabControl.SelectedTab.Text }
            Save-Settings $settings -Immediate
        }
        if ($script:SettingsStatusTimer) {
            $script:SettingsStatusTimer.Stop()
            $script:SettingsStatusTimer.Dispose()
            $script:SettingsStatusTimer = $null
        }
        if ($script:SettingsSearchTimer) {
            $script:SettingsSearchTimer.Stop()
            $script:SettingsSearchTimer.Dispose()
            $script:SettingsSearchTimer = $null
        }
        $script:SettingsForm = $null
    })

    $form.Add_FormClosed({
        param($sender, $e)
        $durationSeconds = [Math]::Round(((Get-Date) - $script:SettingsDialogStart).TotalSeconds, 2)
        $result = $null
        if ($sender -is [System.Windows.Forms.Form]) { $result = $sender.DialogResult }
        Write-Log "UI: Settings dialog closed. Result=$result Dirty=$script:SettingsDirty DurationSeconds=$durationSeconds" "DEBUG" $null "Settings-Dialog"
    })
        if ($tabControl) { $tabControl.ResumeLayout($false) }
        if ($mainPanel) { $mainPanel.ResumeLayout($false) }
        if ($form) { $form.ResumeLayout($false); $form.PerformLayout() }
        Localize-ControlTree $form
        if ($script:ApplySettingsLocalizationOverrides) { & $script:ApplySettingsLocalizationOverrides }
        if ($script:UpdateAboutValues) { & $script:UpdateAboutValues }
        Write-Log "UI: Settings dialog opened." "DEBUG" $null "Settings-Dialog"
        $form.Show()
        $form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
        $form.StartPosition = "CenterScreen"
        $form.TopMost = $true
        $form.BringToFront()
        $form.Activate()
        $form.Focus()
        $form.TopMost = $false
    } catch {
        Write-Log "UI: Settings open failed." "ERROR" $_.Exception "Settings-Dialog"
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to open Settings.`n$($_.Exception.Message)",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        if ($script:SettingsForm -and $script:SettingsForm.IsDisposed) { $script:SettingsForm = $null }
    }
}

function Ensure-SettingsDialogVisible {
    Write-Log "UI: Ensure settings visible called." "DEBUG" $null "Settings-Dialog"
    if ($script:SettingsForm -and -not $script:SettingsForm.IsDisposed -and $script:SettingsForm.Visible) {
        Write-Log ("UI: Settings already visible. Visible={0} WindowState={1}" -f $script:SettingsForm.Visible, $script:SettingsForm.WindowState) "DEBUG" $null "Settings-Dialog"
        return
    }
    Write-Log "UI: Settings not visible; opening now." "DEBUG" $null "Settings-Dialog"
    Show-SettingsDialog
    if ($script:SettingsForm) {
        Write-Log ("UI: Settings open attempt complete. Visible={0} Disposed={1} WindowState={2}" -f $script:SettingsForm.Visible, $script:SettingsForm.IsDisposed, $script:SettingsForm.WindowState) "DEBUG" $null "Settings-Dialog"
    } else {
        Write-Log "UI: Settings open attempt complete. SettingsForm is null." "DEBUG" $null "Settings-Dialog"
    }
    if ($script:DeferredSettingsTimer) {
        $script:DeferredSettingsTimer.Stop()
        $script:DeferredSettingsTimer.Dispose()
        $script:DeferredSettingsTimer = $null
    }
    $script:DeferredSettingsTimer = New-Object System.Windows.Forms.Timer
    $script:DeferredSettingsTimer.Interval = 150
    $script:DeferredSettingsTimer.Add_Tick({
        Invoke-SafeTimerAction "DeferredSettingsTimer" {
            if ($script:DeferredSettingsTimer) {
                $script:DeferredSettingsTimer.Stop()
                $script:DeferredSettingsTimer.Dispose()
                $script:DeferredSettingsTimer = $null
            }
            if (-not ($script:SettingsForm -and -not $script:SettingsForm.IsDisposed -and $script:SettingsForm.Visible)) {
                Write-Log "UI: Settings still not visible; retry open." "DEBUG" $null "Settings-Dialog"
                Show-SettingsDialog
            } else {
                Write-Log "UI: Settings now visible." "DEBUG" $null "Settings-Dialog"
            }
        }
    })
    $script:DeferredSettingsTimer.Start()
}

function Show-SettingsAlreadyOpenNotice {
    $topForm = New-Object System.Windows.Forms.Form
    $topForm.StartPosition = "Manual"
    $topForm.Size = New-Object System.Drawing.Size(1, 1)
    $topForm.Location = New-Object System.Drawing.Point(-2000, -2000)
    $topForm.ShowInTaskbar = $false
    $topForm.TopMost = $true
    $topForm.Opacity = 0
    $topForm.Show()
    $topForm.Activate()
    [System.Windows.Forms.MessageBox]::Show(
        $topForm,
        "Settings is already open.",
        "Settings",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
    $topForm.Close()
    $topForm.Dispose()
}

$script:openSettingsItem = $script:openSettingsItem
if (-not $script:openSettingsItem) {
    $script:openSettingsItem = New-Object System.Windows.Forms.ToolStripMenuItem("Settings...")
    Set-MenuTooltip $script:openSettingsItem "Open the settings window."
    $script:openSettingsItem.Add_Click({
        Invoke-TrayAction "Settings" {
            Write-Log "Tray action: Open Settings" "DEBUG" $null "Tray-Action"
            Write-Log "UI: Settings open requested from tray." "DEBUG" $null "Settings-Dialog"
            if ($script:SettingsForm -and -not $script:SettingsForm.IsDisposed -and $script:SettingsForm.Visible) {
                Show-SettingsAlreadyOpenNotice
                $script:SettingsForm.WindowState = [System.Windows.Forms.FormWindowState]::Normal
                $script:SettingsForm.BringToFront()
                $script:SettingsForm.Activate()
                return
            }
            Ensure-SettingsDialogVisible
        }
    })
}
$openSettingsItem = $script:openSettingsItem

$script:openLogsFolderItem = $script:openLogsFolderItem
if (-not $script:openLogsFolderItem) {
    $script:openLogsFolderItem = New-Object System.Windows.Forms.ToolStripMenuItem("Open Logs Folder")
    Set-MenuTooltip $script:openLogsFolderItem "Open the Logs folder."
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
    Set-MenuTooltip $script:logsMenu "Log tools and log level."
    $clearLogItem = New-Object System.Windows.Forms.ToolStripMenuItem("Clear Log")
    $clearLogItem.Add_Click({
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
    $script:logsMenu.DropDownItems.Add($logLevelMenu) | Out-Null
    $script:logsMenu.DropDownItems.Add($clearLogItem) | Out-Null
    if ($script:openLogsFolderItem) { $script:logsMenu.DropDownItems.Add($script:openLogsFolderItem) | Out-Null }
}
$logsMenu = $script:logsMenu
function Show-LogTailDialog {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Log (Tail)"
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "Sizable"
    $form.ClientSize = New-Object System.Drawing.Size(720, 480)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Multiline = $true
    $textBox.ReadOnly = $true
    $textBox.ScrollBars = "Vertical"
    $textBox.Dock = "Fill"
    $textBox.Font = New-Object System.Drawing.Font("Consolas", 9)

    $buttonsPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttonsPanel.FlowDirection = "RightToLeft"
    $buttonsPanel.Dock = "Bottom"
    $buttonsPanel.Padding = New-Object System.Windows.Forms.Padding(10, 5, 10, 10)
    $buttonsPanel.AutoSize = $true

    $refreshButton = New-Object System.Windows.Forms.Button
    $refreshButton.Text = "Refresh"
    $refreshButton.Width = 90

    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = "Close"
    $closeButton.Width = 90
    $closeButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $loadTail = {
        try {
            if (-not (Test-Path $logPath)) {
                "" | Set-Content -Path $logPath -Encoding UTF8
            }
            $lines = Get-Content -Path $logPath -Tail 200
            $textBox.Text = $lines -join "`r`n"
            $textBox.SelectionStart = $textBox.Text.Length
            $textBox.ScrollToCaret()
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to load log file.`n$($_.Exception.Message)",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
            Write-Log "Failed to load log tail." "ERROR" $_.Exception "Log-Tail"
        }
    }

    $refreshButton.Add_Click({ & $loadTail })

    $buttonsPanel.Controls.Add($closeButton)
    $buttonsPanel.Controls.Add($refreshButton)

    $form.Controls.Add($textBox)
    $form.Controls.Add($buttonsPanel)
    $form.CancelButton = $closeButton

    & $loadTail
    [void]$form.ShowDialog()
}

