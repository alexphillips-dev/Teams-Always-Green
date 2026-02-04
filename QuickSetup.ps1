# QuickSetup.ps1 - Download and install Teams Always Green into a chosen folder
# Creates Desktop, Start Menu, and Startup shortcuts (no VBS needed).

Add-Type -AssemblyName System.Windows.Forms
$ErrorActionPreference = 'Stop'

$tempRoot = $env:TEMP
if ([string]::IsNullOrWhiteSpace($tempRoot)) { $tempRoot = $env:TMP }
if ([string]::IsNullOrWhiteSpace($tempRoot)) { $tempRoot = [System.IO.Path]::GetTempPath() }
if ([string]::IsNullOrWhiteSpace($tempRoot)) { $tempRoot = (Get-Location).Path }
$logPath = Join-Path $tempRoot "TeamsAlwaysGreen-QuickSetup.log"
$script:DisableSetupLog = $false
function Write-SetupLog([string]$message) {
    if ($script:DisableSetupLog) { return }
    try {
        $line = "[{0}] {1}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $message
        Add-Content -Path $logPath -Value $line
    } catch {
    }
}

function Cleanup-SetupTempFiles {
    param([bool]$success)
    if (-not $success) { return }
    $script:DisableSetupLog = $true
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
        $cleanupScript = Join-Path $tempRoot ("TeamsAlwaysGreen-Cleanup-" + [Guid]::NewGuid().ToString("N") + ".ps1")
        $targetsLine = ('$targets = @("{0}\TeamsAlwaysGreen-QuickSetup.log","{0}\TeamsAlwaysGreen-Welcome.ico","{0}\teams-always-green-run.err","{0}\teams-always-green-run.out")' -f $tempRoot)
        $lines = @(
            '$ErrorActionPreference = "SilentlyContinue"'
            'Start-Sleep -Seconds 2'
            $targetsLine
            'foreach ($t in $targets) { if ([string]::IsNullOrWhiteSpace($t)) { continue }; for ($i=0; $i -lt 5; $i++) { Remove-Item -Force -ErrorAction SilentlyContinue $t; if (-not (Test-Path $t)) { break }; Start-Sleep -Milliseconds 400 } }'
            ('Get-ChildItem -Path "{0}" -Filter "TeamsAlwaysGreen-QuickSetup*.ps1" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue' -f $tempRoot)
            ('Remove-Item -Force -ErrorAction SilentlyContinue "{0}"' -f $cleanupScript)
        )
        Set-Content -Path $cleanupScript -Value ($lines -join "`r`n") -Encoding ASCII
        Start-Process "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$cleanupScript`"" -WindowStyle Hidden
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
    $form.Height = 200
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

    $meta = New-Object System.Windows.Forms.Label
    $meta.AutoSize = $true
    $meta.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Regular)
    $meta.Text = "Files: 0/0"
    $meta.Location = New-Object System.Drawing.Point(16, 70)

    $detailsLink = New-Object System.Windows.Forms.LinkLabel
    $detailsLink.Text = "Show details"
    $detailsLink.AutoSize = $true
    $detailsLink.Location = New-Object System.Drawing.Point(400, 70)

    $detailsList = New-Object System.Windows.Forms.ListBox
    $detailsList.Width = 470
    $detailsList.Height = 70
    $detailsList.Location = New-Object System.Drawing.Point(16, 92)
    $detailsList.Visible = $false

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Width = 90
    $cancelButton.Location = New-Object System.Drawing.Point(300, 128)

    $nextButton = New-Object System.Windows.Forms.Button
    $nextButton.Text = "Next"
    $nextButton.Width = 90
    $nextButton.Enabled = $false
    $nextButton.Location = New-Object System.Drawing.Point(396, 128)

    $form.Controls.Add($label)
    $form.Controls.Add($progress)
    $form.Controls.Add($meta)
    $form.Controls.Add($detailsLink)
    $form.Controls.Add($detailsList)
    $form.Controls.Add($cancelButton)
    $form.Controls.Add($nextButton)
    $form.TopMost = $true
    $form.Show()
    [System.Windows.Forms.Application]::DoEvents()
    $ui = @{
        Form = $form
        Label = $label
        Progress = $progress
        Meta = $meta
        DetailsLink = $detailsLink
        DetailsList = $detailsList
        CancelButton = $cancelButton
        NextButton = $nextButton
        NextClicked = $false
        Cancelled = $false
        DetailsVisible = $false
        BaseHeight = $form.Height
        ExpandedHeight = $form.Height + 90
        ButtonsYBase = 128
        ButtonsYExpanded = 218
        StartTime = (Get-Date)
        BytesDownloaded = 0
    }
    $detailsLink.Add_LinkClicked({
        if ($ui.DetailsVisible) {
            $ui.DetailsVisible = $false
            $ui.DetailsList.Visible = $false
            $ui.Form.Height = $ui.BaseHeight
            $ui.CancelButton.Location = New-Object System.Drawing.Point(300, $ui.ButtonsYBase)
            $ui.NextButton.Location = New-Object System.Drawing.Point(396, $ui.ButtonsYBase)
            $ui.DetailsLink.Text = "Show details"
        } else {
            $ui.DetailsVisible = $true
            $ui.DetailsList.Visible = $true
            $ui.Form.Height = $ui.ExpandedHeight
            $ui.CancelButton.Location = New-Object System.Drawing.Point(300, $ui.ButtonsYExpanded)
            $ui.NextButton.Location = New-Object System.Drawing.Point(396, $ui.ButtonsYExpanded)
            $ui.DetailsLink.Text = "Hide details"
        }
    })
    $cancelButton.Add_Click({
        $ui.Cancelled = $true
        $ui.CancelButton.Enabled = $false
        $ui.Label.Text = "Canceling after current file..."
    })
    return $ui
}

function Update-Progress($ui, [int]$current, [int]$total, [string]$message) {
    if (-not $ui) { return }
    $pct = 0
    if ($total -gt 0) { $pct = [Math]::Min(100, [Math]::Round(($current / $total) * 100)) }
    $ui.Label.Text = $message
    $ui.Progress.Value = $pct
    if ($ui.Meta) {
        $elapsed = (Get-Date) - $ui.StartTime
        $rate = if ($elapsed.TotalMinutes -gt 0 -and $current -gt 0) { "{0:N1} files/min" -f ($current / $elapsed.TotalMinutes) } else { "-" }
        $remaining = [Math]::Max(0, $total - $current)
        $etaSeconds = if ($current -gt 0) { ($elapsed.TotalSeconds / $current) * $remaining } else { 0 }
        $etaText = if ($etaSeconds -gt 0) { ([TimeSpan]::FromSeconds($etaSeconds)).ToString('mm\:ss') } else { '--:--' }
        $ui.Meta.Text = ("Files: {0}/{1} | Rate: {2} | ETA: {3}" -f $current, $total, $rate, $etaText)
    }
    [System.Windows.Forms.Application]::DoEvents()
}

function Wait-For-ProgressNext($ui) {
    if (-not $ui -or -not $ui.Form -or $ui.Form.IsDisposed) { return }
    $ui.NextClicked = $false
    $ui.NextButton.Enabled = $true
    $ui.NextButton.Add_Click({ $ui.NextClicked = $true })
    while (-not $ui.NextClicked -and -not $ui.Cancelled -and $ui.Form.Visible) {
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 50
    }
    try { $ui.Form.Close() } catch { }
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
                $body.Text = @(
        "Quick setup will install the app and walk you through the choices below.",
        "",
        "Steps:",
        "  1) Choose an install folder (default is Documents\\Teams Always Green)",
        "  2) Choose whether to create shortcuts",
        "  3) Download and verify app files",
        "  4) Review the summary and launch",
        "",
        "This setup will:",
        "  - Install the app files into a single folder",
        "  - Optionally create Start Menu/Desktop/Startup shortcuts",
        "",
        "This setup does not:",
        "  - Change your Teams settings",
        "  - Run anything in the background without your permission"
    ) -join [Environment]::NewLine

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

if ($false) {
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
Update-Progress $ui 0 1 "Step 2 of 4: Preparing download..."

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
$downloadedFiles = New-Object System.Collections.ArrayList
foreach ($file in $filesToDownload) {
    if ($ui.Cancelled) { break }
    $index++
    $targetPath = Join-Path $installPath $file.Path
    $status = "Step 2 of 4: Downloading {0} ({1}/{2})" -f $file.Path, $index, $total
    if ($ui.DetailsList) {
        [void]$ui.DetailsList.Items.Insert(0, $file.Path)
        while ($ui.DetailsList.Items.Count -gt 3) { $ui.DetailsList.Items.RemoveAt($ui.DetailsList.Items.Count - 1) }
    }
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
    if (Test-Path $targetPath) {
        try {
            $ui.BytesDownloaded += (Get-Item $targetPath).Length
            Update-Progress $ui $index $total $status
        } catch {
        }
        [void]$downloadedFiles.Add($targetPath)
    }

    if ($manifest -and $manifest.files) {
        $manifestKey = $file.Path.Replace("\", "/")
        $expected = $manifest.files.$manifestKey
        if ($expected) {
            Update-Progress $ui $index $total ("Step 2 of 4: Verifying {0} ({1}/{2})" -f $file.Path, $index, $total)
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

if ($ui -and $ui.Form) {
    if ($ui.Cancelled) {
        try { $ui.Form.Close() } catch { }
    } else {
        Write-SetupLog "Download completed."
        Update-Progress $ui $total $total "Step 2 of 4: Download complete. Click Next to continue."
        Wait-For-ProgressNext $ui
    }
}

if ($ui.Cancelled) {
    foreach ($path in $downloadedFiles) {
        try { Remove-Item -Path $path -Force -ErrorAction Stop } catch { }
    }
    Show-SetupError "Install canceled during download. Partial files were removed."
    exit 1
}
}

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

function Finalize-Install {
    param(
        [string]$installPath,
        [string]$targetScript,
        [bool]$portableMode,
        [bool]$enableStartup
    )

    $programsDir = [Environment]::GetFolderPath("Programs")
    $menuFolder = Join-Path $programsDir "Teams Always Green"
    if (-not (Test-Path $menuFolder)) {
        New-Item -ItemType Directory -Path $menuFolder -Force | Out-Null
    }
    $menuShortcut = Join-Path $menuFolder "Teams Always Green.lnk"
    $uninstallShortcut = Join-Path $menuFolder "Uninstall Teams Always Green.lnk"
    $desktopDir = [Environment]::GetFolderPath("Desktop")
    $desktopShortcut = Join-Path $desktopDir "Teams Always Green.lnk"

    if ($enableStartup) {
        $startupDir = [Environment]::GetFolderPath("Startup")
        $startupShortcut = Join-Path $startupDir "Teams Always Green.lnk"
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
            Write-SetupLog "Failed to create shortcuts: $($_.Exception.Message)"
        }
    } else {
        Write-SetupLog "Portable mode: shortcuts not created."
    }
    return $shortcutsCreated
}

function Show-SetupWizard {
    param([System.Windows.Forms.Form]$owner)

    $state = [ordered]@{
        Cancelled = $false
        Action = "Close"
        InstallPath = $null
        CreateShortcuts = $true
        EnableStartup = $false
        IntegrityStatus = "Not verified"
        ShortcutsCreated = @()
        PortableMode = $false
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Teams Always Green - Setup"
    $form.Width = 640
    $form.Height = 460
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

    $title = New-Object System.Windows.Forms.Label
    $title.AutoSize = $true
    $title.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $title.Location = New-Object System.Drawing.Point(16, 12)
    $title.Text = "Setup"

    $panelWelcome = New-Object System.Windows.Forms.Panel
    $panelWelcome.Location = New-Object System.Drawing.Point(16, 44)
    $panelWelcome.Size = New-Object System.Drawing.Size(600, 320)

    $headerPanel = New-Object System.Windows.Forms.Panel
    $headerPanel.Width = 580
    $headerPanel.Height = 56
    $headerPanel.Location = New-Object System.Drawing.Point(0, 0)
    $headerPanel.BackColor = $form.BackColor

    $welcomeIconBox = New-Object System.Windows.Forms.PictureBox
    $welcomeIconBox.Size = New-Object System.Drawing.Size(32, 32)
    $welcomeIconBox.Location = New-Object System.Drawing.Point(0, 6)
    $welcomeIconBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage

    $welcomeIcon = $null
    $iconPath = $null
    $localRoot = $PSScriptRoot
    if (-not $localRoot -and $PSCommandPath) { $localRoot = Split-Path -Parent $PSCommandPath }
    if ($localRoot) { $iconPath = Join-Path $localRoot "Meta\Icons\Tray_Icon.ico" }
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
        $welcomeIconBox.Image = $welcomeIcon.ToBitmap()
        try { $form.Icon = $welcomeIcon } catch { }
    } else {
        $welcomeIconBox.Image = [System.Drawing.SystemIcons]::Information.ToBitmap()
    }

    $welcomeTitle = New-Object System.Windows.Forms.Label
    $welcomeTitle.AutoSize = $true
    $welcomeTitle.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $welcomeTitle.Text = "Welcome to Teams Always Green"
    $welcomeTitle.Location = New-Object System.Drawing.Point(44, 4)

    $welcomeTagline = New-Object System.Windows.Forms.Label
    $welcomeTagline.AutoSize = $false
    $welcomeTagline.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
    $welcomeTagline.Text = "Stay available without micromanaging your status."
    $welcomeTagline.Location = New-Object System.Drawing.Point(44, 30)
    $welcomeTagline.Width = 520
    $welcomeTagline.Height = 18
    $welcomeTagline.Padding = New-Object System.Windows.Forms.Padding(0, 1, 0, 0)

    $headerPanel.Controls.Add($welcomeIconBox)
    $headerPanel.Controls.Add($welcomeTitle)
    $headerPanel.Controls.Add($welcomeTagline)

    $card = New-Object System.Windows.Forms.Panel
    $card.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $card.Width = 580
    $card.Height = 190
    $card.Location = New-Object System.Drawing.Point(0, 60)

    $welcomeBody = New-Object System.Windows.Forms.Label
    $welcomeBody.AutoSize = $false
    $welcomeBody.Width = 550
    $welcomeBody.Height = 170
    $welcomeBody.Location = New-Object System.Drawing.Point(12, 10)
                $welcomeBody.Text = @(
        "Quick setup will install the app and walk you through the choices below.",
        "",
        "Steps:",
        "  1) Choose an install folder (default is Documents\\Teams Always Green)",
        "  2) Choose whether to create shortcuts",
        "  3) Download and verify app files",
        "  4) Review the summary and launch",
        "",
        "This setup will:",
        "  - Install the app files into a single folder",
        "  - Optionally create Start Menu/Desktop/Startup shortcuts",
        "",
        "This setup does not:",
        "  - Change your Teams settings",
        "  - Run anything in the background without your permission"
    ) -join [Environment]::NewLine

    $card.Controls.Add($welcomeBody)

    $chkShortcuts = New-Object System.Windows.Forms.CheckBox
    $chkShortcuts.Text = "Create Start Menu/Desktop shortcuts (Recommended)"
    $chkShortcuts.Checked = $true
    $chkShortcuts.AutoSize = $true
    $chkShortcuts.Location = New-Object System.Drawing.Point(8, 260)

    $chkStartup = New-Object System.Windows.Forms.CheckBox
    $chkStartup.Text = "Start with Windows"
    $chkStartup.Checked = $false
    $chkStartup.AutoSize = $true
    $chkStartup.Location = New-Object System.Drawing.Point(8, 284)

    $chkShortcuts.Add_CheckedChanged({
        $chkStartup.Enabled = [bool]$chkShortcuts.Checked
        if (-not $chkStartup.Enabled) { $chkStartup.Checked = $false }
    })

    $panelWelcome.Controls.Add($headerPanel)
    $panelWelcome.Controls.Add($card)
    $panelWelcome.Controls.Add($chkShortcuts)
    $panelWelcome.Controls.Add($chkStartup)

    $panelLocation = New-Object System.Windows.Forms.Panel
    $panelLocation.Location = New-Object System.Drawing.Point(16, 44)
    $panelLocation.Size = New-Object System.Drawing.Size(600, 320)
    $panelLocation.Visible = $false

    $locLabel = New-Object System.Windows.Forms.Label
    $locLabel.AutoSize = $true
    $locLabel.Text = "Step 1 of 4: Choose the install folder location."
    $locLabel.Location = New-Object System.Drawing.Point(0, 0)

    $locText = New-Object System.Windows.Forms.TextBox
    $locText.Width = 420
    $locText.Location = New-Object System.Drawing.Point(0, 28)

    $locBrowse = New-Object System.Windows.Forms.Button
    $locBrowse.Text = "Browse..."
    $locBrowse.Width = 90
    $locBrowse.Location = New-Object System.Drawing.Point(430, 26)

    $locHint = New-Object System.Windows.Forms.Label
    $locHint.AutoSize = $true
    $locHint.Text = "A 'Teams Always Green' folder will be created inside the selected path."
    $locHint.Location = New-Object System.Drawing.Point(0, 60)

    $locBrowse.Add_Click({
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = "Select the parent folder (we will create a Teams Always Green folder inside)"
        $dialog.SelectedPath = $locText.Text
        if ($dialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
            $locText.Text = $dialog.SelectedPath
        }
    })

    $panelLocation.Controls.Add($locLabel)
    $panelLocation.Controls.Add($locText)
    $panelLocation.Controls.Add($locBrowse)
    $panelLocation.Controls.Add($locHint)

    $panelDownload = New-Object System.Windows.Forms.Panel
    $panelDownload.Location = New-Object System.Drawing.Point(16, 44)
    $panelDownload.Size = New-Object System.Drawing.Size(600, 320)
    $panelDownload.Visible = $false

    $dlLabel = New-Object System.Windows.Forms.Label
    $dlLabel.AutoSize = $true
    $dlLabel.Text = "Step 2 of 4: Preparing download..."
    $dlLabel.Location = New-Object System.Drawing.Point(0, 0)

    $dlProgress = New-Object System.Windows.Forms.ProgressBar
    $dlProgress.Width = 560
    $dlProgress.Height = 20
    $dlProgress.Location = New-Object System.Drawing.Point(0, 28)
    $dlProgress.Minimum = 0
    $dlProgress.Maximum = 100

    $dlMeta = New-Object System.Windows.Forms.Label
    $dlMeta.AutoSize = $true
    $dlMeta.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
    $dlMeta.Text = "Files: 0/0"
    $dlMeta.Location = New-Object System.Drawing.Point(0, 54)

    $dlDetailsLink = New-Object System.Windows.Forms.LinkLabel
    $dlDetailsLink.Text = "Show details"
    $dlDetailsLink.AutoSize = $true
    $dlDetailsLink.Location = New-Object System.Drawing.Point(460, 54)

    $dlDetailsList = New-Object System.Windows.Forms.ListBox
    $dlDetailsList.Width = 560
    $dlDetailsList.Height = 80
    $dlDetailsList.Location = New-Object System.Drawing.Point(0, 78)
    $dlDetailsList.Visible = $false

    $dlCancel = New-Object System.Windows.Forms.Button
    $dlCancel.Text = "Cancel Download"
    $dlCancel.Width = 130
    $dlCancel.Location = New-Object System.Drawing.Point(0, 168)

    $panelDownload.Controls.Add($dlLabel)
    $panelDownload.Controls.Add($dlProgress)
    $panelDownload.Controls.Add($dlMeta)
    $panelDownload.Controls.Add($dlDetailsLink)
    $panelDownload.Controls.Add($dlDetailsList)
    $panelDownload.Controls.Add($dlCancel)

    $panelSummary = New-Object System.Windows.Forms.Panel
    $panelSummary.Location = New-Object System.Drawing.Point(16, 44)
    $panelSummary.Size = New-Object System.Drawing.Size(600, 320)
    $panelSummary.Visible = $false

    $summaryTitle = New-Object System.Windows.Forms.Label
    $summaryTitle.AutoSize = $true
    $summaryTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $summaryTitle.Text = "Install completed successfully."
    $summaryTitle.Location = New-Object System.Drawing.Point(0, 0)

    $summaryGroup = New-Object System.Windows.Forms.GroupBox
    $summaryGroup.Text = "Install summary"
    $summaryGroup.Width = 580
    $summaryGroup.Height = 180
    $summaryGroup.Location = New-Object System.Drawing.Point(0, 30)

    $summaryTable = New-Object System.Windows.Forms.TableLayoutPanel
    $summaryTable.Dock = [System.Windows.Forms.DockStyle]::Fill
    $summaryTable.Padding = New-Object System.Windows.Forms.Padding(10, 18, 10, 10)
    $summaryTable.ColumnCount = 2
    $summaryTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $summaryTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $sumInstall = New-Object System.Windows.Forms.Label
    $sumMode = New-Object System.Windows.Forms.Label
    $sumIntegrity = New-Object System.Windows.Forms.Label
    $sumShortcuts = New-Object System.Windows.Forms.Label
    $sumLog = New-Object System.Windows.Forms.Label

    foreach ($lbl in @($sumInstall,$sumMode,$sumIntegrity,$sumShortcuts,$sumLog)) {
        $lbl.AutoSize = $true
        $lbl.MaximumSize = New-Object System.Drawing.Size(420, 0)
    }

    $addRow = {
        param([string]$labelText, $valueLabel)
        $row = $summaryTable.RowCount
        $summaryTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
        $label = New-Object System.Windows.Forms.Label
        $label.AutoSize = $true
        $label.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $label.Text = $labelText
        $label.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 6)
        $valueLabel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)
        $summaryTable.Controls.Add($label, 0, $row)
        $summaryTable.Controls.Add($valueLabel, 1, $row)
        $summaryTable.RowCount++
    }

    & $addRow "Install Path:" $sumInstall
    & $addRow "Mode:" $sumMode
    & $addRow "Integrity:" $sumIntegrity
    & $addRow "Shortcuts:" $sumShortcuts
    & $addRow "Setup Log:" $sumLog

    $summaryGroup.Controls.Add($summaryTable)

    $pinTip = New-Object System.Windows.Forms.Label
    $pinTip.AutoSize = $true
    $pinTip.ForeColor = [System.Drawing.Color]::FromArgb(90,90,90)
    $pinTip.Text = "Tip: Pin the tray icon via the ^ menu so it's always visible."
    $pinTip.Location = New-Object System.Drawing.Point(0, 220)

    $sumLaunch = New-Object System.Windows.Forms.Button
    $sumLaunch.Text = "Launch"
    $sumLaunch.Width = 90
    $sumLaunch.Location = New-Object System.Drawing.Point(0, 250)

    $sumSettings = New-Object System.Windows.Forms.Button
    $sumSettings.Text = "Settings"
    $sumSettings.Width = 90
    $sumSettings.Location = New-Object System.Drawing.Point(100, 250)

    $sumFolder = New-Object System.Windows.Forms.Button
    $sumFolder.Text = "Open Folder"
    $sumFolder.Width = 110
    $sumFolder.Location = New-Object System.Drawing.Point(200, 250)

    $sumClose = New-Object System.Windows.Forms.Button
    $sumClose.Text = "Close"
    $sumClose.Width = 90
    $sumClose.Location = New-Object System.Drawing.Point(490, 250)

    $panelSummary.Controls.Add($summaryTitle)
    $panelSummary.Controls.Add($summaryGroup)
    $panelSummary.Controls.Add($pinTip)
    $panelSummary.Controls.Add($sumLaunch)
    $panelSummary.Controls.Add($sumSettings)
    $panelSummary.Controls.Add($sumFolder)
    $panelSummary.Controls.Add($sumClose)

    $btnBack = New-Object System.Windows.Forms.Button
    $btnBack.Text = "Back"
    $btnBack.Width = 90
    $btnBack.Location = New-Object System.Drawing.Point(340, 380)

    $btnNext = New-Object System.Windows.Forms.Button
    $btnNext.Text = "Next"
    $btnNext.Width = 90
    $btnNext.Location = New-Object System.Drawing.Point(440, 380)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Width = 90
    $btnCancel.Location = New-Object System.Drawing.Point(540, 380)

    $form.Controls.Add($title)
    $form.Controls.Add($panelWelcome)
    $form.Controls.Add($panelLocation)
    $form.Controls.Add($panelDownload)
    $form.Controls.Add($panelSummary)
    $form.Controls.Add($btnBack)
    $form.Controls.Add($btnNext)
    $form.Controls.Add($btnCancel)

    $stepRef = [ref]0
    $downloadComplete = $false

    $showStep = {
        param([int]$index)
        $stepRef.Value = $index
        $panelWelcome.Visible = ($index -eq 0)
        $panelLocation.Visible = ($index -eq 1)
        $panelDownload.Visible = ($index -eq 2)
        $panelSummary.Visible = ($index -eq 3)
        $btnBack.Enabled = ($index -gt 0 -and $index -lt 3)
        if ($index -eq 2) {
            $btnNext.Enabled = $downloadComplete
        } elseif ($index -eq 3) {
            $btnBack.Enabled = $false
            $btnNext.Enabled = $false
        } else {
            $btnNext.Enabled = $true
        }
    }

    $btnCancel.Add_Click({ $state.Cancelled = $true; $form.Close() })
    $btnBack.Add_Click({
        if ($stepRef.Value -eq 1) { & $showStep 0 }
        elseif ($stepRef.Value -eq 2 -and -not $downloadComplete) { & $showStep 1 }
    })

    $btnNext.Add_Click({
        if ($stepRef.Value -eq 0) {
            $state.CreateShortcuts = [bool]$chkShortcuts.Checked
            $state.EnableStartup = [bool]$chkStartup.Checked
            $defaultBase = [Environment]::GetFolderPath("MyDocuments")
            $locText.Text = (Join-Path $defaultBase "Teams Always Green")
            & $showStep 1
            return
        }
        if ($stepRef.Value -eq 1) {
            if ([string]::IsNullOrWhiteSpace($locText.Text)) {
                $defaultBase = [Environment]::GetFolderPath("MyDocuments")
                $locText.Text = (Join-Path $defaultBase "Teams Always Green")
            }
            $selectedBase = $locText.Text
            $appFolderName = "Teams Always Green"
            if ([string]::Equals([System.IO.Path]::GetFileName($selectedBase), $appFolderName, [System.StringComparison]::OrdinalIgnoreCase)) {
                $state.InstallPath = $selectedBase
            } else {
                $state.InstallPath = Join-Path $selectedBase $appFolderName
            }
            if (-not (Test-Path $state.InstallPath)) {
                New-Item -ItemType Directory -Path $state.InstallPath -Force | Out-Null
            }
            & $showStep 2

            $state.PortableMode = (-not $state.CreateShortcuts)
            $targetScript = Join-Path $state.InstallPath "Script\Teams Always Green.ps1"

            $folders = @(
                "Debug","Logs","Meta","Settings","Meta\Icons","Script","Script\Core","Script\Features","Script\I18n","Script\Tray","Script\UI"
            )
            foreach ($name in $folders) {
                $path = Join-Path $state.InstallPath $name
                if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
            }

            $metaDir = Join-Path $state.InstallPath "Meta"
            $settingsDir = Join-Path $state.InstallPath "Settings"
            $logsDir = Join-Path $state.InstallPath "Logs"
            $portableMarker = Join-Path $metaDir "PortableMode.txt"
            if ($state.PortableMode) {
                try {
                    Set-Content -Path $portableMarker -Value ("PortableMode=1`nSetOn={0}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")) -Encoding ASCII
                    Write-SetupLog "Portable mode enabled."
                } catch {
                }
            } else {
                try { if (Test-Path $portableMarker) { Remove-Item -Path $portableMarker -Force -ErrorAction SilentlyContinue } } catch { }
            }
            try {
                Set-Content -Path (Join-Path $metaDir "Teams-Always-Green.settings.path.txt") -Value $settingsDir -Encoding ASCII
                Set-Content -Path (Join-Path $metaDir "Teams-Always-Green.log.path.txt") -Value $logsDir -Encoding ASCII
            } catch { }

            $localRoot = $null
            if ($PSScriptRoot) { $localRoot = $PSScriptRoot }
            elseif ($PSCommandPath) { $localRoot = Split-Path -Parent $PSCommandPath }
            elseif ($MyInvocation.MyCommand.Path) { $localRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
            $useLocal = $false
            if ($localRoot -and (Test-Path (Join-Path $localRoot "Script\Teams Always Green.ps1"))) {
                $useLocal = $true
                Write-SetupLog "Using local app files for install."
            }

            $manifest = $null
            if ($useLocal) {
                $manifest = Load-Manifest (Join-Path $localRoot "QuickSetup.manifest.json")
            } else {
                $manifestUrl = "$script:QuickSetupRawBase/QuickSetup.manifest.json?v=$script:QuickSetupCacheBuster"
                $manifestTarget = Join-Path $state.InstallPath "Meta\QuickSetup.manifest.json"
                try {
                    Invoke-WebRequest -Uri $manifestUrl -OutFile $manifestTarget -UseBasicParsing
                    $manifest = Load-Manifest $manifestTarget
                } catch {
                    Write-SetupLog "Manifest download failed; continuing without integrity validation."
                }
            }
            $state.IntegrityStatus = if ($manifest) { "Verified" } else { "Not verified (manifest unavailable)" }

            $downloadUi = @{
                Form = $form
                Label = $dlLabel
                Progress = $dlProgress
                Meta = $dlMeta
                DetailsLink = $dlDetailsLink
                DetailsList = $dlDetailsList
                CancelButton = $dlCancel
                NextButton = $null
                NextClicked = $false
                Cancelled = $false
                DetailsVisible = $false
                StartTime = (Get-Date)
                BytesDownloaded = 0
            }

            $dlDetailsLink.Add_LinkClicked({
                $downloadUi.DetailsVisible = -not $downloadUi.DetailsVisible
                $downloadUi.DetailsList.Visible = $downloadUi.DetailsVisible
                $dlDetailsLink.Text = if ($downloadUi.DetailsVisible) { "Hide details" } else { "Show details" }
            })
            $dlCancel.Add_Click({
                $downloadUi.Cancelled = $true
                $dlCancel.Enabled = $false
                $dlLabel.Text = "Canceling after current file..."
            })

            $total = $script:QuickSetupFiles.Count
            $index = 0
            $downloaded = New-Object System.Collections.ArrayList
            foreach ($file in $script:QuickSetupFiles) {
                if ($downloadUi.Cancelled) { break }
                $index++
                $targetPath = Join-Path $state.InstallPath $file.Path
                $status = "Step 2 of 4: Downloading {0} ({1}/{2})" -f $file.Path, $index, $total
                if ($downloadUi.DetailsList) {
                    [void]$downloadUi.DetailsList.Items.Insert(0, $file.Path)
                    while ($downloadUi.DetailsList.Items.Count -gt 3) { $downloadUi.DetailsList.Items.RemoveAt($downloadUi.DetailsList.Items.Count - 1) }
                }
                Update-Progress $downloadUi $index $total $status
                Write-SetupLog $status

                if ($useLocal) {
                    $sourcePath = Join-Path $localRoot $file.Path
                    if (-not (Test-Path $sourcePath)) {
                        Show-SetupError "Missing local file: $sourcePath"
                        $state.Cancelled = $true
                        break
                    }
                    Copy-Item -Path $sourcePath -Destination $targetPath -Force
                } else {
                    try {
                        $downloadUrl = if ($file.Url -match "\?") { "$($file.Url)&v=$script:QuickSetupCacheBuster" } else { "$($file.Url)?v=$script:QuickSetupCacheBuster" }
                        Invoke-WebRequest -Uri $downloadUrl -OutFile $targetPath -UseBasicParsing
                    } catch {
                        Show-SetupError ("Download failed: {0}" -f $file.Url)
                        $state.Cancelled = $true
                        break
                    }
                }

                if (Test-Path $targetPath) { [void]$downloaded.Add($targetPath) }

                if ($manifest -and $manifest.files) {
                    $manifestKey = $file.Path.Replace("\", "/")
                    $expected = $manifest.files.$manifestKey
                    if ($expected) {
                        Update-Progress $downloadUi $index $total ("Step 2 of 4: Verifying {0} ({1}/{2})" -f $file.Path, $index, $total)
                        $actual = Get-FileHashHex $targetPath
                        if (-not $actual -or ($actual.ToLowerInvariant() -ne [string]$expected.ToLowerInvariant())) {
                            $matched = $false
                            if (Is-TextFile $file.Path) {
                                $altLf = Get-NormalizedBytesHash $targetPath "LF"
                                if ($altLf -and ($altLf.ToLowerInvariant() -eq [string]$expected.ToLowerInvariant())) {
                                    $matched = $true
                                } else {
                                    $altCrLf = Get-NormalizedBytesHash $targetPath "CRLF"
                                    if ($altCrLf -and ($altCrLf.ToLowerInvariant() -eq [string]$expected.ToLowerInvariant())) {
                                        $matched = $true
                                    }
                                }
                            }
                            if (-not $matched) {
                                Show-SetupError ("Integrity check failed for {0}. See log for hash details." -f $file.Path)
                                $state.Cancelled = $true
                                break
                            }
                        }
                    }
                }
            }

            if ($downloadUi.Cancelled -or $state.Cancelled) {
                foreach ($path in $downloaded) {
                    try { Remove-Item -Path $path -Force -ErrorAction Stop } catch { }
                }
                $state.Cancelled = $true
                $form.Close()
                return
            }

            Update-Progress $downloadUi $total $total "Step 2 of 4: Download complete. Click Next to continue."
            $downloadComplete = $true
            $btnNext.Enabled = $true

            $state.ShortcutsCreated = Finalize-Install -installPath $state.InstallPath -targetScript $targetScript -portableMode $state.PortableMode -enableStartup $state.EnableStartup

            $sumInstall.Text = $state.InstallPath
            $sumMode.Text = if ($state.PortableMode) { "Portable (no shortcuts)" } else { "Standard" }
            $sumIntegrity.Text = $state.IntegrityStatus
            $sumShortcuts.Text = if ($state.ShortcutsCreated.Count -gt 0) { $state.ShortcutsCreated -join "; " } else { "None" }
            $sumLog.Text = $logPath
            $pinTip.Visible = (-not $state.PortableMode)
            & $showStep 3
        }
    })

    $sumLaunch.Add_Click({ $state.Action = "Launch"; $form.Close() })
    $sumSettings.Add_Click({ $state.Action = "Settings"; $form.Close() })
    $sumFolder.Add_Click({ $state.Action = "Folder"; $form.Close() })
    $sumClose.Add_Click({ $state.Action = "Close"; $form.Close() })

    & $showStep 0
    if ($owner) { $form.ShowDialog($owner) | Out-Null } else { $form.ShowDialog() | Out-Null }
    return $state
}

$script:QuickSetupRawBase = "https://raw.githubusercontent.com/alexphillips-dev/Teams-Always-Green/main"
$script:QuickSetupCacheBuster = [Guid]::NewGuid().ToString("N")
$script:QuickSetupFiles = @(
    @{ Url = "$script:QuickSetupRawBase/Script/Teams%20Always%20Green.ps1"; Path = "Script\Teams Always Green.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Core/Logging.ps1"; Path = "Script\Core\Logging.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Core/Paths.ps1"; Path = "Script\Core\Paths.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Core/Runtime.ps1"; Path = "Script\Core\Runtime.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Core/Settings.ps1"; Path = "Script\Core\Settings.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Features/Hotkeys.ps1"; Path = "Script\Features\Hotkeys.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Features/Profiles.ps1"; Path = "Script\Features\Profiles.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Features/Scheduling.ps1"; Path = "Script\Features\Scheduling.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/I18n/UiStrings.ps1"; Path = "Script\I18n\UiStrings.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/Tray/Menu.ps1"; Path = "Script\Tray\Menu.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/UI/SettingsDialog.ps1"; Path = "Script\UI\SettingsDialog.ps1" },
    @{ Url = "$script:QuickSetupRawBase/Script/UI/HistoryDialog.ps1"; Path = "Script\UI\HistoryDialog.ps1" },
    @{ Url = "$script:QuickSetupRawBase/VERSION"; Path = "VERSION" },
    @{ Url = "$script:QuickSetupRawBase/Teams%20Always%20Green.VBS"; Path = "Teams Always Green.VBS" },
    @{ Url = "$script:QuickSetupRawBase/Debug/Teams%20Always%20Green%20-%20Debug.VBS"; Path = "Debug\Teams Always Green - Debug.VBS" },
    @{ Url = "$script:QuickSetupRawBase/Meta/Icons/Tray_Icon.ico"; Path = "Meta\Icons\Tray_Icon.ico" },
    @{ Url = "$script:QuickSetupRawBase/Meta/Icons/Settings_Icon.ico"; Path = "Meta\Icons\Settings_Icon.ico" }
)

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {
}

Write-SetupLog "Quick setup started."
$setupOwner = New-SetupOwner
$wizard = Show-SetupWizard -owner $setupOwner
if ($setupOwner -and -not $setupOwner.IsDisposed) { $setupOwner.Close() }

if (-not $wizard -or $wizard.Cancelled) {
    Write-SetupLog "Install canceled in setup wizard."
    Cleanup-SetupTempFiles -success $true
    exit 1
}

$installPath = $wizard.InstallPath
if ([string]::IsNullOrWhiteSpace($installPath)) {
    Write-SetupLog "Install canceled: missing install path."
    Cleanup-SetupTempFiles -success $true
    exit 1
}

$targetScript = Join-Path $installPath "Script\Teams Always Green.ps1"
Write-SetupLog ("Summary action selected: {0}" -f $wizard.Action)

if ($wizard.Action -eq "Launch") {
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
} elseif ($wizard.Action -eq "Settings") {
    Start-Process "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetScript`" -SettingsOnly" -WorkingDirectory $installPath
} elseif ($wizard.Action -eq "Folder") {
    Start-Process "explorer.exe" $installPath
}

Cleanup-SetupTempFiles -success $true
exit 0

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





