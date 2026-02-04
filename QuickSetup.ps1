# QuickSetup.ps1 - Download and install Teams Always Green into a chosen folder
# Creates Desktop, Start Menu, and Startup shortcuts (no VBS needed).

Add-Type -AssemblyName System.Windows.Forms
$ErrorActionPreference = 'Stop'

$tempRoot = $env:TEMP
if ([string]::IsNullOrWhiteSpace($tempRoot)) { $tempRoot = $env:TMP }
if ([string]::IsNullOrWhiteSpace($tempRoot)) { $tempRoot = [System.IO.Path]::GetTempPath() }
if ([string]::IsNullOrWhiteSpace($tempRoot)) { $tempRoot = (Get-Location).Path }
$logPath = Join-Path $tempRoot "TeamsAlwaysGreen-QuickSetup.log"
function Write-SetupLog([string]$message) {
    try {
        $line = "[{0}] {1}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $message
        Add-Content -Path $logPath -Value $line
    } catch {
    }
}

function Cleanup-SetupTempFiles {
    param([bool]$success)
    if (-not $success) { return }
    Write-SetupLog "Cleaning up QuickSetup temp files."
    $paths = @()
    if ($script:WelcomeTempIconPath) { $paths += $script:WelcomeTempIconPath }
    $paths += (Join-Path $tempRoot "TeamsAlwaysGreen-Welcome.ico")
    $paths += (Join-Path $tempRoot "TeamsAlwaysGreen-QuickSetup.log")
    foreach ($path in ($paths | Select-Object -Unique)) {
        if ($path -and (Test-Path $path)) {
            try { Remove-Item -Path $path -Force -ErrorAction Stop } catch { }
        }
    }
    try {
        Get-ChildItem -Path $tempRoot -Filter "TeamsAlwaysGreen-QuickSetup*.ps1" -ErrorAction SilentlyContinue | ForEach-Object {
            try { Remove-Item -Path $_.FullName -Force -ErrorAction Stop } catch { }
        }
    } catch {
    }
    try {
        Get-ChildItem -Path $tempRoot -Filter "teams-always-green-run.*" -ErrorAction SilentlyContinue | ForEach-Object {
            try { Remove-Item -Path $_.FullName -Force -ErrorAction Stop } catch { }
        }
    } catch {
    }

    # Schedule a delayed cleanup to handle files still locked by the shell/editor.
    try {
        $cleanupCmd = Join-Path $tempRoot ("TeamsAlwaysGreen-Cleanup-" + [Guid]::NewGuid().ToString("N") + ".cmd")
        $pattern = Join-Path $tempRoot "TeamsAlwaysGreen-QuickSetup*.ps1"
        $lines = @(
            "@echo off",
            "timeout /t 2 >nul",
            "del /f /q `"$($tempRoot)\TeamsAlwaysGreen-QuickSetup.log`"",
            "del /f /q `"$($tempRoot)\TeamsAlwaysGreen-Welcome.ico`"",
            "del /f /q `"$($tempRoot)\teams-always-green-run.err`"",
            "del /f /q `"$($tempRoot)\teams-always-green-run.out`"",
            ('for %%F in ("{0}") do del /f /q "%%~fF"' -f $pattern),
            "del /f /q `"$cleanupCmd`""
        )
        Set-Content -Path $cleanupCmd -Value ($lines -join "`r`n") -Encoding ASCII
        Start-Process "$env:WINDIR\System32\cmd.exe" -ArgumentList "/c `"$cleanupCmd`"" -WindowStyle Hidden
        Write-SetupLog "Scheduled delayed temp cleanup."
    } catch {
    }
}

function Show-SetupError([string]$message) {
    Write-SetupLog "ERROR: $message"
    Show-SetupPrompt -message ($message + "`n`nLog: $logPath") -title "Quick Setup" -buttons ([System.Windows.Forms.MessageBoxButtons]::OK) -icon ([System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
}

function Show-SetupPrompt {
    param(
        [string]$message,
        [string]$title,
        [System.Windows.Forms.MessageBoxButtons]$buttons,
        [System.Windows.Forms.MessageBoxIcon]$icon,
        [System.Windows.Forms.Form]$owner
    )
    $localOwner = $owner
    if (-not $localOwner) {
        $localOwner = New-Object System.Windows.Forms.Form
        $localOwner.Width = 1
        $localOwner.Height = 1
        $localOwner.StartPosition = "CenterScreen"
        $localOwner.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
        $localOwner.ShowInTaskbar = $false
        $localOwner.TopMost = $true
        $localOwner.Opacity = 0
        $localOwner.Show()
        [System.Windows.Forms.Application]::DoEvents()
    }
    $result = [System.Windows.Forms.MessageBox]::Show($localOwner, $message, $title, $buttons, $icon)
    if (-not $owner -and $localOwner) { $localOwner.Close() }
    return $result
}

function New-SetupOwner {
    $owner = New-Object System.Windows.Forms.Form
    $owner.Width = 1
    $owner.Height = 1
    $owner.StartPosition = "CenterScreen"
    $owner.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
    $owner.ShowInTaskbar = $false
    $owner.TopMost = $true
    $owner.Opacity = 0
    $owner.Show()
    [System.Windows.Forms.Application]::DoEvents()
    return $owner
}

function Get-FileHashHex([string]$path) {
    try {
        return (Get-FileHash -Algorithm SHA256 -Path $path -ErrorAction Stop).Hash
    } catch {
        return $null
    }
}

function Is-TextFile([string]$relativePath) {
    $ext = [System.IO.Path]::GetExtension($relativePath)
    if ([string]::IsNullOrWhiteSpace($ext)) { return $true }
    $ext = $ext.ToLowerInvariant()
    return @(".ps1", ".cmd", ".vbs", ".json", ".md", ".txt", ".log", ".csv", ".ini") -contains $ext
}

function Get-NormalizedBytesHash([string]$path, [string]$lineEnding) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        if (-not $bytes) { return $null }
        $normalized = New-Object System.Collections.Generic.List[byte]
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $b = $bytes[$i]
            if ($b -eq 0x0D) {
                if (($i + 1) -lt $bytes.Length -and $bytes[$i + 1] -eq 0x0A) { $i++ }
                $normalized.Add(0x0A)
                continue
            }
            $normalized.Add($b)
        }

        if ($lineEnding -eq "CRLF") {
            $withCrLf = New-Object System.Collections.Generic.List[byte]
            foreach ($b in $normalized) {
                if ($b -eq 0x0A) {
                    $withCrLf.Add(0x0D)
                    $withCrLf.Add(0x0A)
                } else {
                    $withCrLf.Add($b)
                }
            }
            $normalized = $withCrLf
        }

        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hash = $sha.ComputeHash($normalized.ToArray())
        return ([BitConverter]::ToString($hash)).Replace("-", "")
    } catch {
        return $null
    }
}

function Load-Manifest([string]$path) {
    if (-not (Test-Path $path)) { return $null }
    try {
        $raw = Get-Content -Path $path -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return $raw | ConvertFrom-Json
    } catch {
        return $null
    }
}

function New-ProgressForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Teams Always Green - Setup"
    $form.Width = 520
    $form.Height = 140
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

    $label = New-Object System.Windows.Forms.Label
    $label.AutoSize = $true
    $label.Text = "Preparing..."
    $label.Location = New-Object System.Drawing.Point(16, 12)

    $progress = New-Object System.Windows.Forms.ProgressBar
    $progress.Width = 470
    $progress.Height = 20
    $progress.Location = New-Object System.Drawing.Point(16, 42)
    $progress.Minimum = 0
    $progress.Maximum = 100

    $form.Controls.Add($label)
    $form.Controls.Add($progress)
    $form.TopMost = $true
    $form.Show()
    [System.Windows.Forms.Application]::DoEvents()
    return @{ Form = $form; Label = $label; Progress = $progress }
}

function Update-Progress($ui, [int]$current, [int]$total, [string]$message) {
    if (-not $ui) { return }
    $pct = 0
    if ($total -gt 0) { $pct = [Math]::Min(100, [Math]::Round(($current / $total) * 100)) }
    $ui.Label.Text = $message
    $ui.Progress.Value = $pct
    [System.Windows.Forms.Application]::DoEvents()
}

function Show-Welcome {
    param([System.Windows.Forms.Form]$owner)
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Teams Always Green - Welcome"
    $form.ClientSize = New-Object System.Drawing.Size(580, 380)
    $form.Width = 600
    $form.Height = 400
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true

    $headerPanel = New-Object System.Windows.Forms.Panel
    $headerPanel.Width = 560
    $headerPanel.Height = 58
    $headerPanel.Location = New-Object System.Drawing.Point(16, 12)
    $headerPanel.BackColor = $form.BackColor

    $iconBox = New-Object System.Windows.Forms.PictureBox
    $iconBox.Size = New-Object System.Drawing.Size(32, 32)
    $iconBox.Location = New-Object System.Drawing.Point(0, 6)
    $iconBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage
    $iconPath = $null
    $localRoot = $PSScriptRoot
    if (-not $localRoot -and $PSCommandPath) {
        $localRoot = Split-Path -Parent $PSCommandPath
    }
    if ($localRoot) {
        $iconPath = Join-Path $localRoot "Meta\Icons\Tray_Icon.ico"
    }
    $welcomeIcon = $null
    if ($iconPath -and (Test-Path $iconPath)) {
        try { $welcomeIcon = New-Object System.Drawing.Icon($iconPath) } catch { }
    }
    if (-not $welcomeIcon) {
        try {
            try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
            $remoteIconUrl = "https://raw.githubusercontent.com/alexphillips-dev/Teams-Always-Green/main/Meta/Icons/Tray_Icon.ico"
            $remoteIconPath = Join-Path $env:TEMP "TeamsAlwaysGreen-Welcome.ico"
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($remoteIconUrl, $remoteIconPath)
            if (Test-Path $remoteIconPath) { $welcomeIcon = New-Object System.Drawing.Icon($remoteIconPath) }
            $script:WelcomeTempIconPath = $remoteIconPath
        } catch {
        }
    }
    if ($welcomeIcon) {
        $iconBox.Image = $welcomeIcon.ToBitmap()
        try { $form.Icon = $welcomeIcon } catch { }
    } else {
        $iconBox.Image = [System.Drawing.SystemIcons]::Information.ToBitmap()
        try { $form.Icon = [System.Drawing.SystemIcons]::Information } catch { }
    }

    $title = New-Object System.Windows.Forms.Label
    $title.AutoSize = $true
    $title.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $title.Text = "Welcome to Teams Always Green"
    $title.Location = New-Object System.Drawing.Point(44, 6)

    $tagline = New-Object System.Windows.Forms.Label
    $tagline.AutoSize = $false
    $tagline.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
    $tagline.Text = "Stay available without micromanaging your status."
    $tagline.Location = New-Object System.Drawing.Point(44, 34)
    $tagline.Width = 500
    $tagline.Height = 18
    $tagline.Padding = New-Object System.Windows.Forms.Padding(0, 1, 0, 0)

    $headerPanel.Controls.Add($iconBox)
    $headerPanel.Controls.Add($title)
    $headerPanel.Controls.Add($tagline)

    $card = New-Object System.Windows.Forms.Panel
    $card.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $card.Width = 552
    $card.Height = 210
    $card.Location = New-Object System.Drawing.Point(16, 72)

    $body = New-Object System.Windows.Forms.Label
    $body.AutoSize = $false
    $body.Width = 520
    $body.Height = 190
    $body.Location = New-Object System.Drawing.Point(12, 10)
    $body.Text = @"
Quick setup will install the app and walk you through the choices below.

Steps:
  1) Choose an install folder (default is Documents\Teams Always Green)
  2) Choose whether to create shortcuts
  3) Download and verify app files
  4) Review the summary and launch

This setup will:
  • Install the app files into a single folder
  • Optionally create Start Menu/Desktop/Startup shortcuts

This setup does not:
  • Change your Teams settings
  • Run anything in the background without your permission
"@

    $card.Controls.Add($body)

    $shortcutsBox = New-Object System.Windows.Forms.CheckBox
    $shortcutsBox.Text = "Create Start Menu/Desktop shortcuts (Recommended)"
    $shortcutsBox.Checked = $true
    $shortcutsBox.AutoSize = $true
    $shortcutsBox.Location = New-Object System.Drawing.Point(24, 296)

    $continue = New-Object System.Windows.Forms.Button
    $continue.Text = "Continue"
    $continue.Width = 100
    $continue.Location = New-Object System.Drawing.Point(320, 320)

    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = "Cancel"
    $cancel.Width = 100
    $cancel.Location = New-Object System.Drawing.Point(430, 320)

    $continue.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.AcceptButton = $continue
    $form.CancelButton = $cancel

    $form.Controls.Add($headerPanel)
    $form.Controls.Add($card)
    $form.Controls.Add($shortcutsBox)
    $form.Controls.Add($continue)
    $form.Controls.Add($cancel)
    if ($owner) {
        $result = $form.ShowDialog($owner)
    } else {
        $result = $form.ShowDialog()
    }
    return @{
        Proceed = ($result -eq [System.Windows.Forms.DialogResult]::OK)
        CreateShortcuts = [bool]$shortcutsBox.Checked
    }
}

function Show-SetupSummary {
    param(
        [string]$installPath,
        [string]$integrityStatus,
        [bool]$portableMode,
        [string[]]$shortcutsCreated,
        [string]$logPath
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Teams Always Green - Setup Complete"
    $form.Width = 680
    $form.Height = 410
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.BackColor = [System.Drawing.Color]::White
    $form.ShowIcon = $true
    $windowIconPath = Join-Path $installPath "Meta\Icons\Tray_Icon.ico"
    try {
        if (Test-Path $windowIconPath) {
            $form.Icon = New-Object System.Drawing.Icon($windowIconPath, 32, 32)
        } else {
            $form.Icon = [System.Drawing.SystemIcons]::Application
        }
    } catch {
        try { $form.Icon = [System.Drawing.SystemIcons]::Application } catch { }
    }

    $header = New-Object System.Windows.Forms.Panel
    $header.Width = 640
    $header.Height = 66
    $header.Location = New-Object System.Drawing.Point(16, 12)
    $header.BackColor = [System.Drawing.Color]::FromArgb(245, 248, 252)

    $iconBox = New-Object System.Windows.Forms.PictureBox
    $iconBox.Size = New-Object System.Drawing.Size(36, 36)
    $iconBox.Location = New-Object System.Drawing.Point(12, 14)
    $iconBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage
    try {
        if (Test-Path $windowIconPath) {
            $iconBox.Image = (New-Object System.Drawing.Icon($windowIconPath, 32, 32)).ToBitmap()
        } else {
            $iconBox.Image = [System.Drawing.SystemIcons]::Information.ToBitmap()
        }
    } catch {
        try { $iconBox.Image = [System.Drawing.SystemIcons]::Information.ToBitmap() } catch { }
    }

    $headerTitle = New-Object System.Windows.Forms.Label
    $headerTitle.AutoSize = $true
    $headerTitle.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $headerTitle.Text = "Install completed successfully."
    $headerTitle.Location = New-Object System.Drawing.Point(60, 10)

    $headerSubtitle = New-Object System.Windows.Forms.Label
    $headerSubtitle.AutoSize = $true
    $headerSubtitle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
    $headerSubtitle.Text = "You're ready to launch Teams Always Green."
    $headerSubtitle.Location = New-Object System.Drawing.Point(60, 36)

    $header.Controls.Add($iconBox)
    $header.Controls.Add($headerTitle)
    $header.Controls.Add($headerSubtitle)

    $separator = New-Object System.Windows.Forms.Panel
    $separator.Width = 640
    $separator.Height = 1
    $separator.Location = New-Object System.Drawing.Point(16, 84)
    $separator.BackColor = [System.Drawing.Color]::FromArgb(220, 220, 220)

    $summaryGroup = New-Object System.Windows.Forms.GroupBox
    $summaryGroup.Text = "Install summary"
    $summaryGroup.Width = 640
    $summaryGroup.Height = 200
    $summaryGroup.Location = New-Object System.Drawing.Point(16, 92)

    $shortcutsText = if ($shortcutsCreated -and $shortcutsCreated.Count -gt 0) { $shortcutsCreated -join "; " } else { "None (portable mode)" }
    $modeText = if ($portableMode) { "Portable (no shortcuts)" } else { "Standard" }

    $summaryTable = New-Object System.Windows.Forms.TableLayoutPanel
    $summaryTable.ColumnCount = 2
    $summaryTable.RowCount = 0
    $summaryTable.Dock = [System.Windows.Forms.DockStyle]::Fill
    $summaryTable.Padding = New-Object System.Windows.Forms.Padding(12, 18, 12, 10)
    $summaryTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $summaryTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $addSummaryRow = {
        param([string]$labelText, $valueControl)
        $rowIndex = $summaryTable.RowCount
        $summaryTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
        $label = New-Object System.Windows.Forms.Label
        $label.AutoSize = $true
        $label.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $label.Text = $labelText
        $label.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 6)
        $valueControl.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)
        $summaryTable.Controls.Add($label, 0, $rowIndex)
        $summaryTable.Controls.Add($valueControl, 1, $rowIndex)
        $summaryTable.RowCount++
    }

    $valueStyle = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
    $maxValueWidth = 500
    $toolTip = New-Object System.Windows.Forms.ToolTip

    $valueInstall = New-Object System.Windows.Forms.Label
    $valueInstall.Font = $valueStyle
    $valueInstall.AutoSize = $true
    $valueInstall.MaximumSize = New-Object System.Drawing.Size($maxValueWidth, 0)
    $valueInstall.Text = $installPath
    $toolTip.SetToolTip($valueInstall, $installPath)

    $valueMode = New-Object System.Windows.Forms.Label
    $valueMode.Font = $valueStyle
    $valueMode.AutoSize = $true
    $valueMode.MaximumSize = New-Object System.Drawing.Size($maxValueWidth, 0)
    $valueMode.Text = $modeText

    $valueIntegrity = New-Object System.Windows.Forms.Label
    $valueIntegrity.Font = $valueStyle
    $valueIntegrity.AutoSize = $true
    $valueIntegrity.MaximumSize = New-Object System.Drawing.Size($maxValueWidth, 0)
    $valueIntegrity.Text = $integrityStatus

    $valueShortcuts = New-Object System.Windows.Forms.Label
    $valueShortcuts.Font = $valueStyle
    $valueShortcuts.AutoSize = $true
    $valueShortcuts.MaximumSize = New-Object System.Drawing.Size($maxValueWidth, 0)
    $valueShortcuts.Text = $shortcutsText

    $valueLog = New-Object System.Windows.Forms.LinkLabel
    $valueLog.Font = $valueStyle
    $valueLog.AutoSize = $true
    $valueLog.MaximumSize = New-Object System.Drawing.Size($maxValueWidth, 0)
    $valueLog.Text = $logPath
    $valueLog.LinkBehavior = [System.Windows.Forms.LinkBehavior]::HoverUnderline
    $toolTip.SetToolTip($valueLog, $logPath)
    $valueLog.Add_LinkClicked({
        try { Start-Process "notepad.exe" $logPath } catch { }
    })

    & $addSummaryRow "Install Path:" $valueInstall
    & $addSummaryRow "Mode:" $valueMode
    & $addSummaryRow "Integrity:" $valueIntegrity
    & $addSummaryRow "Shortcuts:" $valueShortcuts
    & $addSummaryRow "Setup Log:" $valueLog

    $summaryGroup.Controls.Add($summaryTable)

    $note = New-Object System.Windows.Forms.Label
    $note.AutoSize = $true
    $note.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Regular)
    $note.ForeColor = [System.Drawing.Color]::FromArgb(90, 90, 90)
    $note.Text = "Tip: You can open Settings any time from the tray icon."
    $note.Location = New-Object System.Drawing.Point(18, 290)

    $buttonLaunch = New-Object System.Windows.Forms.Button
    $buttonLaunch.Text = "Launch"
    $buttonLaunch.Width = 90
    $buttonLaunch.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $buttonLaunch.Location = New-Object System.Drawing.Point(16, 320)

    $buttonSettings = New-Object System.Windows.Forms.Button
    $buttonSettings.Text = "Settings"
    $buttonSettings.Width = 90
    $buttonSettings.Location = New-Object System.Drawing.Point(116, 320)

    $buttonFolder = New-Object System.Windows.Forms.Button
    $buttonFolder.Text = "Open Folder"
    $buttonFolder.Width = 110
    $buttonFolder.Location = New-Object System.Drawing.Point(216, 320)

    $buttonClose = New-Object System.Windows.Forms.Button
    $buttonClose.Text = "Close"
    $buttonClose.Width = 90
    $buttonClose.Location = New-Object System.Drawing.Point(546, 320)

    $buttonLaunch.DialogResult = [System.Windows.Forms.DialogResult]::Yes
    $buttonSettings.DialogResult = [System.Windows.Forms.DialogResult]::Retry
    $buttonFolder.DialogResult = [System.Windows.Forms.DialogResult]::Ignore
    $buttonClose.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.AcceptButton = $buttonLaunch
    $form.CancelButton = $buttonClose

    $form.Controls.Add($header)
    $form.Controls.Add($separator)
    $form.Controls.Add($summaryGroup)
    $form.Controls.Add($note)
    $form.Controls.Add($buttonLaunch)
    $form.Controls.Add($buttonSettings)
    $form.Controls.Add($buttonFolder)
    $form.Controls.Add($buttonClose)
    $form.TopMost = $true
    $result = $form.ShowDialog()
    switch ($result) {
        ([System.Windows.Forms.DialogResult]::Yes) { return "Launch" }
        ([System.Windows.Forms.DialogResult]::Retry) { return "Settings" }
        ([System.Windows.Forms.DialogResult]::Ignore) { return "Folder" }
        default { return "Close" }
    }
}

Write-SetupLog "Quick setup started."

$setupOwner = New-SetupOwner
$welcome = Show-Welcome -owner $setupOwner
if (-not $welcome.Proceed) {
    Write-SetupLog "Install canceled at welcome screen."
    Write-Host "Install canceled."
    if ($setupOwner -and -not $setupOwner.IsDisposed) { $setupOwner.Close() }
    Cleanup-SetupTempFiles -success $true
    exit 1
}
if (-not $welcome.CreateShortcuts) {
    Write-SetupLog "Welcome: shortcuts disabled (portable mode selected)."
} else {
    Write-SetupLog "Welcome: shortcuts enabled."
}

$step1 = Show-SetupPrompt -message "Step 1 of 4: Choose the install folder location." -title "Install Location" -buttons ([System.Windows.Forms.MessageBoxButtons]::OKCancel) -icon ([System.Windows.Forms.MessageBoxIcon]::Information) -owner $setupOwner
if ($step1 -ne [System.Windows.Forms.DialogResult]::OK) {
    Write-SetupLog "Install canceled at install location step."
    Write-Host "Install canceled."
    if ($setupOwner -and -not $setupOwner.IsDisposed) { $setupOwner.Close() }
    exit 1
}

$defaultBase = [Environment]::GetFolderPath("MyDocuments")
$defaultPath = Join-Path $defaultBase "Teams Always Green"

$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = "Select the parent folder (we will create a Teams Always Green folder inside)"
$dialog.SelectedPath = $defaultPath

if ($dialog.ShowDialog($setupOwner) -ne [System.Windows.Forms.DialogResult]::OK) {
    Write-Host "Install canceled."
    if ($setupOwner -and -not $setupOwner.IsDisposed) { $setupOwner.Close() }
    exit 1
}

$selectedBase = $dialog.SelectedPath
$appFolderName = "Teams Always Green"
if ([string]::Equals([System.IO.Path]::GetFileName($selectedBase), $appFolderName, [System.StringComparison]::OrdinalIgnoreCase)) {
    $installPath = $selectedBase
} else {
    $installPath = Join-Path $selectedBase $appFolderName
}
if (-not (Test-Path $installPath)) {
    New-Item -ItemType Directory -Path $installPath -Force | Out-Null
}
$detectedScript = Join-Path $installPath "Script\Teams Always Green.ps1"
if (Test-Path $detectedScript) {
    $choice = Show-SetupPrompt -message "An existing install was detected at:`n$installPath`n`nUpgrade/repair this install?" -title "Existing Install" -buttons ([System.Windows.Forms.MessageBoxButtons]::YesNoCancel) -icon ([System.Windows.Forms.MessageBoxIcon]::Question) -owner $setupOwner
    if ($choice -eq [System.Windows.Forms.DialogResult]::Cancel) {
        Write-Host "Install canceled."
        if ($setupOwner -and -not $setupOwner.IsDisposed) { $setupOwner.Close() }
        exit 1
    }
    if ($choice -eq [System.Windows.Forms.DialogResult]::No) {
        if ($dialog.ShowDialog($setupOwner) -ne [System.Windows.Forms.DialogResult]::OK) {
            Write-Host "Install canceled."
            if ($setupOwner -and -not $setupOwner.IsDisposed) { $setupOwner.Close() }
            exit 1
        }
        $selectedBase = $dialog.SelectedPath
        if ([string]::Equals([System.IO.Path]::GetFileName($selectedBase), $appFolderName, [System.StringComparison]::OrdinalIgnoreCase)) {
            $installPath = $selectedBase
        } else {
            $installPath = Join-Path $selectedBase $appFolderName
        }
        if (-not (Test-Path $installPath)) {
            New-Item -ItemType Directory -Path $installPath -Force | Out-Null
        }
    }
}
$portableMode = $false
$portableMarker = Join-Path $installPath "Meta\PortableMode.txt"
if (Test-Path $portableMarker) {
    $portableMode = $true
} else {
    $portableMode = (-not [bool]$welcome.CreateShortcuts)
}
$folders = @(
    "Debug",
    "Logs",
    "Meta",
    "Settings",
    "Meta\Icons",
    "Script",
    "Script\Core",
    "Script\Features",
    "Script\I18n",
    "Script\Tray",
    "Script\UI"
)
foreach ($name in $folders) {
    $path = Join-Path $installPath $name
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}
if ($portableMode) {
    try {
        Set-Content -Path $portableMarker -Value ("PortableMode=1`nSetOn={0}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")) -Encoding ASCII
        Write-SetupLog "Portable mode enabled."
    } catch {
    }
}

$metaDir = Join-Path $installPath "Meta"
$settingsDir = Join-Path $installPath "Settings"
$logsDir = Join-Path $installPath "Logs"
$settingsLocator = Join-Path $metaDir "Teams-Always-Green.settings.path.txt"
$logLocator = Join-Path $metaDir "Teams-Always-Green.log.path.txt"
try {
    Set-Content -Path $settingsLocator -Value $settingsDir -Encoding ASCII
    Set-Content -Path $logLocator -Value $logsDir -Encoding ASCII
} catch {
    Write-Host "Failed to write locator files: $($_.Exception.Message)"
}

$rawBase = "https://raw.githubusercontent.com/alexphillips-dev/Teams-Always-Green/main"
$cacheBuster = [Guid]::NewGuid().ToString("N")
$filesToDownload = @(
    @{ Url = "$rawBase/Script/Teams%20Always%20Green.ps1"; Path = "Script\Teams Always Green.ps1" },
    @{ Url = "$rawBase/Script/Core/Logging.ps1"; Path = "Script\Core\Logging.ps1" },
    @{ Url = "$rawBase/Script/Core/Paths.ps1"; Path = "Script\Core\Paths.ps1" },
    @{ Url = "$rawBase/Script/Core/Runtime.ps1"; Path = "Script\Core\Runtime.ps1" },
    @{ Url = "$rawBase/Script/Core/Settings.ps1"; Path = "Script\Core\Settings.ps1" },
    @{ Url = "$rawBase/Script/Features/Hotkeys.ps1"; Path = "Script\Features\Hotkeys.ps1" },
    @{ Url = "$rawBase/Script/Features/Profiles.ps1"; Path = "Script\Features\Profiles.ps1" },
    @{ Url = "$rawBase/Script/Features/Scheduling.ps1"; Path = "Script\Features\Scheduling.ps1" },
    @{ Url = "$rawBase/Script/I18n/UiStrings.ps1"; Path = "Script\I18n\UiStrings.ps1" },
    @{ Url = "$rawBase/Script/Tray/Menu.ps1"; Path = "Script\Tray\Menu.ps1" },
    @{ Url = "$rawBase/Script/UI/SettingsDialog.ps1"; Path = "Script\UI\SettingsDialog.ps1" },
    @{ Url = "$rawBase/Script/UI/HistoryDialog.ps1"; Path = "Script\UI\HistoryDialog.ps1" },
    @{ Url = "$rawBase/VERSION"; Path = "VERSION" },
    @{ Url = "$rawBase/Teams%20Always%20Green.VBS"; Path = "Teams Always Green.VBS" },
    @{ Url = "$rawBase/Debug/Teams%20Always%20Green%20-%20Debug.VBS"; Path = "Debug\Teams Always Green - Debug.VBS" },
    @{ Url = "$rawBase/Meta/Icons/Tray_Icon.ico"; Path = "Meta\Icons\Tray_Icon.ico" },
    @{ Url = "$rawBase/Meta/Icons/Settings_Icon.ico"; Path = "Meta\Icons\Settings_Icon.ico" }
)
$targetScript = Join-Path $installPath "Script\Teams Always Green.ps1"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {
}

$ui = New-ProgressForm
Update-Progress $ui 0 1 "Preparing installer..."

$localRoot = $null
if ($PSScriptRoot) { $localRoot = $PSScriptRoot }
elseif ($PSCommandPath) { $localRoot = Split-Path -Parent $PSCommandPath }
elseif ($MyInvocation.MyCommand.Path) { $localRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }

$localManifestPath = $null
$useLocal = $false
if ($localRoot) {
    $localManifestPath = Join-Path $localRoot "QuickSetup.manifest.json"
    if (Test-Path (Join-Path $localRoot "Script\Teams Always Green.ps1")) {
        $useLocal = (Show-SetupPrompt -message (
            "Local app files were found next to QuickSetup.ps1.`nUse local files instead of downloading?",
            "Use Local Files"
        ) -title "Use Local Files" -buttons ([System.Windows.Forms.MessageBoxButtons]::YesNo) -icon ([System.Windows.Forms.MessageBoxIcon]::Question)) -eq [System.Windows.Forms.DialogResult]::Yes
    }
}

$manifest = $null
if ($useLocal) {
    $manifest = Load-Manifest $localManifestPath
} else {
    $manifestUrl = "$rawBase/QuickSetup.manifest.json?v=$cacheBuster"
    $manifestTarget = Join-Path $installPath "Meta\QuickSetup.manifest.json"
    try {
        Invoke-WebRequest -Uri $manifestUrl -OutFile $manifestTarget -UseBasicParsing
        $manifest = Load-Manifest $manifestTarget
    } catch {
        Write-SetupLog "Manifest download failed; continuing without integrity validation."
        $manifest = $null
    }
}
$integrityStatus = if ($manifest) { "Verified" } else { "Not verified (manifest unavailable)" }

$total = $filesToDownload.Count
$index = 0
foreach ($file in $filesToDownload) {
    $index++
    $targetPath = Join-Path $installPath $file.Path
    $status = "Installing {0} ({1}/{2})" -f $file.Path, $index, $total
    Update-Progress $ui $index $total $status
    Write-SetupLog $status

    if ($useLocal) {
        $sourcePath = Join-Path $localRoot $file.Path
        if (-not (Test-Path $sourcePath)) {
            Show-SetupError "Missing local file: $sourcePath"
            exit 1
        }
        Copy-Item -Path $sourcePath -Destination $targetPath -Force
    } else {
        try {
            $downloadUrl = if ($file.Url -match "\?") { "$($file.Url)&v=$cacheBuster" } else { "$($file.Url)?v=$cacheBuster" }
            Invoke-WebRequest -Uri $downloadUrl -OutFile $targetPath -UseBasicParsing
        } catch {
            Show-SetupError ("Download failed: {0}" -f $file.Url)
            exit 1
        }
    }

    if ($manifest -and $manifest.files) {
        $manifestKey = $file.Path.Replace("\", "/")
        $expected = $manifest.files.$manifestKey
        if ($expected) {
            $actual = Get-FileHashHex $targetPath
            if (-not $actual -or ($actual.ToLowerInvariant() -ne [string]$expected.ToLowerInvariant())) {
                Write-SetupLog ("Integrity expected: {0}" -f $expected)
                Write-SetupLog ("Integrity actual:   {0}" -f $actual)
                $matched = $false
                if (Is-TextFile $file.Path) {
                    Write-SetupLog ("Integrity text file: {0}" -f $file.Path)
                    $altLf = Get-NormalizedBytesHash $targetPath "LF"
                    if ($altLf -and ($altLf.ToLowerInvariant() -eq [string]$expected.ToLowerInvariant())) {
                        $matched = $true
                    } else {
                        $altCrLf = Get-NormalizedBytesHash $targetPath "CRLF"
                        if ($altCrLf -and ($altCrLf.ToLowerInvariant() -eq [string]$expected.ToLowerInvariant())) {
                            $matched = $true
                        }
                    }
                    Write-SetupLog ("Integrity alt LF:   {0}" -f $altLf)
                    Write-SetupLog ("Integrity alt CRLF: {0}" -f $altCrLf)
                } else {
                    Write-SetupLog ("Integrity binary file: {0}" -f $file.Path)
                }
                if (-not $matched) {
                    Show-SetupError ("Integrity check failed for {0}. See log for hash details." -f $file.Path)
                    exit 1
                }
                Write-SetupLog ("Integrity check matched after line-ending normalization: {0}" -f $file.Path)
            }
        }
    }
}

if ($ui -and $ui.Form) { $ui.Form.Close() }
function New-Shortcut([string]$shortcutPath, [string]$targetScriptPath, [string]$workingDir) {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetScriptPath`""
    $shortcut.WorkingDirectory = $workingDir
    $shortcut.WindowStyle = 7
    $iconPath = Join-Path $workingDir "Meta\Icons\Tray_Icon.ico"
    if (Test-Path $iconPath) {
        $shortcut.IconLocation = "$iconPath,0"
        Write-SetupLog "Shortcut icon set: $iconPath"
    } else {
        $shortcut.IconLocation = "$env:WINDIR\System32\shell32.dll,1"
        Write-SetupLog "Shortcut icon missing, using shell32 fallback."
    }
    $shortcut.Save()
}

$programsDir = [Environment]::GetFolderPath("Programs")
$menuFolder = Join-Path $programsDir "Teams Always Green"
if (-not (Test-Path $menuFolder)) {
    New-Item -ItemType Directory -Path $menuFolder -Force | Out-Null
}
$menuShortcut = Join-Path $menuFolder "Teams Always Green.lnk"
$uninstallShortcut = Join-Path $menuFolder "Uninstall Teams Always Green.lnk"
$desktopDir = [Environment]::GetFolderPath("Desktop")
$desktopShortcut = Join-Path $desktopDir "Teams Always Green.lnk"

$enableStartup = $false
if (-not $portableMode) {
    $enableStartup = (Show-SetupPrompt -message (
        "Step 3 of 4: Start Teams Always Green when Windows starts?",
        "Startup Shortcut"
    ) -title "Startup Shortcut" -buttons ([System.Windows.Forms.MessageBoxButtons]::YesNo) -icon ([System.Windows.Forms.MessageBoxIcon]::Question) -owner $setupOwner) -eq [System.Windows.Forms.DialogResult]::Yes

    if ($enableStartup) {
        $startupDir = [Environment]::GetFolderPath("Startup")
        $startupShortcut = Join-Path $startupDir "Teams Always Green.lnk"
    }
}

$uninstallScriptPath = Join-Path $installPath "Uninstall-Teams-Always-Green.ps1"
$uninstallScript = @'
param([switch]$Silent)
Add-Type -AssemblyName System.Windows.Forms

$scriptPath = $MyInvocation.MyCommand.Path
$installRoot = Split-Path -Parent $scriptPath
$programsDir = [Environment]::GetFolderPath("Programs")
$menuFolder = Join-Path $programsDir "Teams Always Green"
$shortcuts = @(
    Join-Path $menuFolder "Teams Always Green.lnk",
    Join-Path $menuFolder "Uninstall Teams Always Green.lnk",
    Join-Path ([Environment]::GetFolderPath("Desktop")) "Teams Always Green.lnk",
    Join-Path ([Environment]::GetFolderPath("Startup")) "Teams Always Green.lnk"
)

foreach ($shortcut in $shortcuts) {
    try { if (Test-Path $shortcut) { Remove-Item -Path $shortcut -Force -ErrorAction SilentlyContinue } } catch { }
}
try {
    if (Test-Path $menuFolder -and -not (Get-ChildItem -Path $menuFolder -Force | Measure-Object).Count) {
        Remove-Item -Path $menuFolder -Force -ErrorAction SilentlyContinue
    }
} catch { }

$deleteFiles = $true
if (-not $Silent) {
        $resp = Show-SetupPrompt -message (
            "Remove the app files from:`n$installRoot`n`nThis will close the app if it is running.",
            "Uninstall Teams Always Green"
        ) -title "Uninstall Teams Always Green" -buttons ([System.Windows.Forms.MessageBoxButtons]::YesNo) -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($resp -ne [System.Windows.Forms.DialogResult]::Yes) { $deleteFiles = $false }
}

if (-not $deleteFiles) { return }
$cmdPath = Join-Path $env:TEMP ("TAG-Uninstall-" + [Guid]::NewGuid().ToString("N") + ".cmd")
$cmd = "@echo off`r`n" + "timeout /t 2 >nul`r`n" + "rmdir /s /q `"$installRoot`"`r`n" + "del /f /q `"$cmdPath`"`r`n"
Set-Content -Path $cmdPath -Value $cmd -Encoding ASCII
Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$cmdPath`"" -WindowStyle Hidden
'@
try {
    Set-Content -Path $uninstallScriptPath -Value $uninstallScript -Encoding UTF8
} catch {
    Write-SetupLog "Failed to write uninstall script."
}

$shortcutsCreated = @()
if (-not $portableMode) {
    try {
        New-Shortcut -shortcutPath $menuShortcut -targetScriptPath $targetScript -workingDir $installPath
        $shortcutsCreated += "Start Menu"
        if ($enableStartup) {
            New-Shortcut -shortcutPath $startupShortcut -targetScriptPath $targetScript -workingDir $installPath
            $shortcutsCreated += "Startup"
        }
        New-Shortcut -shortcutPath $desktopShortcut -targetScriptPath $targetScript -workingDir $installPath
        $shortcutsCreated += "Desktop"
        if (Test-Path $uninstallScriptPath) {
            New-Shortcut -shortcutPath $uninstallShortcut -targetScriptPath $uninstallScriptPath -workingDir $installPath
            $shortcutsCreated += "Uninstall"
        }
    } catch {
        Write-Host "Failed to create shortcuts: $($_.Exception.Message)"
    }
} else {
    Write-SetupLog "Portable mode: shortcuts not created."
}

Write-Host "Installed Teams Always Green to: $installPath"
Write-Host "Setup log: $logPath"
if (-not $portableMode) {
    $pinMessage = @"
Teams Always Green runs in the system tray.

To keep it visible:
1) Click the ^ arrow in the taskbar.
2) Drag the Teams Always Green icon onto the taskbar tray.
   - Or open Settings > Personalization > Taskbar > Other system tray icons.
"@
    [void](Show-SetupPrompt -message $pinMessage -title "Pin to Tray" -buttons ([System.Windows.Forms.MessageBoxButtons]::OK) -icon ([System.Windows.Forms.MessageBoxIcon]::Information) -owner $setupOwner)
    Write-SetupLog "Pin-to-tray tip shown."
}
Write-SetupLog "Install completed. Showing summary."

$action = Show-SetupSummary -installPath $installPath -integrityStatus $integrityStatus -portableMode $portableMode -shortcutsCreated $shortcutsCreated -logPath $logPath
Write-SetupLog ("Summary action selected: {0}" -f $action)
if ($action -eq "Launch") {
    Write-SetupLog "Launch requested."
    $launchVbs = Join-Path $installPath "Teams Always Green.VBS"
    if (Test-Path $launchVbs) {
        try {
            $proc = Start-Process "$env:WINDIR\System32\wscript.exe" -ArgumentList "`"$launchVbs`"" -WorkingDirectory $installPath -PassThru -ErrorAction Stop
            Write-SetupLog ("Launch started (wscript). PID={0}" -f $proc.Id)
        } catch {
            Write-SetupLog ("Launch failed (wscript): {0}" -f $_.Exception.Message)
        }
    }
    if (-not (Test-Path $targetScript)) {
        Show-SetupError "Launch failed: app script not found at $targetScript"
    } elseif (-not (Test-Path $launchVbs)) {
        $launchArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetScript`""
        try {
            $proc = Start-Process "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $launchArgs -WorkingDirectory $installPath -PassThru -ErrorAction Stop
            Write-SetupLog ("Launch started (hidden). PID={0}" -f $proc.Id)
        } catch {
            Write-SetupLog ("Launch failed (hidden): {0}" -f $_.Exception.Message)
            try {
                $proc = Start-Process "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"$targetScript`"") -WorkingDirectory $installPath -PassThru -ErrorAction Stop
                Write-SetupLog ("Launch started (visible). PID={0}" -f $proc.Id)
            } catch {
                Show-SetupError ("Launch failed: {0}" -f $_.Exception.Message)
            }
        }
    }
} elseif ($action -eq "Settings") {
        Start-Process "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetScript`" -SettingsOnly" -WorkingDirectory $installPath
    } elseif ($action -eq "Folder") {
        Start-Process "explorer.exe" $installPath
    }
    if ($setupOwner -and -not $setupOwner.IsDisposed) { $setupOwner.Close() }

