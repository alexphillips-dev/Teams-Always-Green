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
    $form.Width = 520
    $form.Height = 300
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true

    $title = New-Object System.Windows.Forms.Label
    $title.AutoSize = $true
    $title.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $title.Text = "Welcome to Teams Always Green"
    $title.Location = New-Object System.Drawing.Point(16, 12)

    $body = New-Object System.Windows.Forms.Label
    $body.AutoSize = $false
    $body.Width = 470
    $body.Height = 160
    $body.Location = New-Object System.Drawing.Point(16, 44)
    $body.Text = @"
This quick setup will install the app and create any shortcuts you choose.

What happens next:
 - Choose an install folder (default is Documents\Teams Always Green)
 - Optional: enable portable mode (no shortcuts)
 - Download and verify app files
 - Summary with Launch / Settings / Open Folder
"@

    $continue = New-Object System.Windows.Forms.Button
    $continue.Text = "Continue"
    $continue.Width = 100
    $continue.Location = New-Object System.Drawing.Point(300, 220)

    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = "Cancel"
    $cancel.Width = 100
    $cancel.Location = New-Object System.Drawing.Point(410, 220)

    $continue.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.AcceptButton = $continue
    $form.CancelButton = $cancel

    $form.Controls.Add($title)
    $form.Controls.Add($body)
    $form.Controls.Add($continue)
    $form.Controls.Add($cancel)
    if ($owner) {
        $result = $form.ShowDialog($owner)
    } else {
        $result = $form.ShowDialog()
    }
    return ($result -eq [System.Windows.Forms.DialogResult]::OK)
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
    $form.Width = 560
    $form.Height = 290
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

    $title = New-Object System.Windows.Forms.Label
    $title.AutoSize = $true
    $title.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $title.Text = "Install completed successfully."
    $title.Location = New-Object System.Drawing.Point(16, 12)

    $summary = New-Object System.Windows.Forms.TextBox
    $summary.Multiline = $true
    $summary.ReadOnly = $true
    $summary.BorderStyle = [System.Windows.Forms.BorderStyle]::None
    $summary.BackColor = $form.BackColor
    $summary.Width = 520
    $summary.Height = 120
    $summary.Location = New-Object System.Drawing.Point(16, 44)

    $shortcutsText = if ($shortcutsCreated -and $shortcutsCreated.Count -gt 0) { $shortcutsCreated -join "; " } else { "None (portable mode)" }
    $modeText = if ($portableMode) { "Portable (no shortcuts)" } else { "Standard" }
    $summary.Text = @"
Install Path: $installPath
Mode: $modeText
Integrity: $integrityStatus
Shortcuts: $shortcutsText
Setup Log: $logPath
"@

    $buttonLaunch = New-Object System.Windows.Forms.Button
    $buttonLaunch.Text = "Launch"
    $buttonLaunch.Width = 90
    $buttonLaunch.Location = New-Object System.Drawing.Point(16, 175)

    $buttonSettings = New-Object System.Windows.Forms.Button
    $buttonSettings.Text = "Settings"
    $buttonSettings.Width = 90
    $buttonSettings.Location = New-Object System.Drawing.Point(116, 175)

    $buttonFolder = New-Object System.Windows.Forms.Button
    $buttonFolder.Text = "Open Folder"
    $buttonFolder.Width = 110
    $buttonFolder.Location = New-Object System.Drawing.Point(216, 175)

    $buttonClose = New-Object System.Windows.Forms.Button
    $buttonClose.Text = "Close"
    $buttonClose.Width = 90
    $buttonClose.Location = New-Object System.Drawing.Point(446, 175)

    $action = "Close"
    $buttonLaunch.Add_Click({ $action = "Launch"; $form.Close() })
    $buttonSettings.Add_Click({ $action = "Settings"; $form.Close() })
    $buttonFolder.Add_Click({ $action = "Folder"; $form.Close() })
    $buttonClose.Add_Click({ $action = "Close"; $form.Close() })

    $form.Controls.Add($title)
    $form.Controls.Add($summary)
    $form.Controls.Add($buttonLaunch)
    $form.Controls.Add($buttonSettings)
    $form.Controls.Add($buttonFolder)
    $form.Controls.Add($buttonClose)
    $form.TopMost = $true
    $form.ShowDialog() | Out-Null
    return $action
}

Write-SetupLog "Quick setup started."

$setupOwner = New-SetupOwner
$continue = Show-Welcome -owner $setupOwner
if (-not $continue) {
    Write-SetupLog "Install canceled at welcome screen."
    Write-Host "Install canceled."
    if ($setupOwner -and -not $setupOwner.IsDisposed) { $setupOwner.Close() }
    exit 1
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
    $portableMode = (Show-SetupPrompt -message (
        "Step 2 of 4: Use portable mode?`n`nPortable mode skips Start Menu/Desktop/Startup shortcuts.",
        "Portable Mode"
    ) -title "Portable Mode" -buttons ([System.Windows.Forms.MessageBoxButtons]::YesNo) -icon ([System.Windows.Forms.MessageBoxIcon]::Question) -owner $setupOwner) -eq [System.Windows.Forms.DialogResult]::Yes
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
        $shortcut.IconLocation = $iconPath
    } else {
        $shortcut.IconLocation = "$env:WINDIR\System32\shell32.dll,1"
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

    $action = Show-SetupSummary -installPath $installPath -integrityStatus $integrityStatus -portableMode $portableMode -shortcutsCreated $shortcutsCreated -logPath $logPath
    if ($action -eq "Launch") {
        Start-Process "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetScript`"" -WorkingDirectory $installPath
    } elseif ($action -eq "Settings") {
        Start-Process "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetScript`" -SettingsOnly" -WorkingDirectory $installPath
    } elseif ($action -eq "Folder") {
        Start-Process "explorer.exe" $installPath
    }
    if ($setupOwner -and -not $setupOwner.IsDisposed) { $setupOwner.Close() }

