# QuickSetup.ps1 - Download and install Teams Always Green into a chosen folder
# Creates Desktop, Start Menu, and Startup shortcuts (no VBS needed).

Add-Type -AssemblyName System.Windows.Forms
$ErrorActionPreference = 'Stop'

$logPath = Join-Path $env:TEMP "TeamsAlwaysGreen-QuickSetup.log"
function Write-SetupLog([string]$message) {
    try {
        $line = "[{0}] {1}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $message
        Add-Content -Path $logPath -Value $line
    } catch {
    }
}

function Show-SetupError([string]$message) {
    Write-SetupLog "ERROR: $message"
    [System.Windows.Forms.MessageBox]::Show(
        $message + "`n`nLog: $logPath",
        "Quick Setup",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
}

function Get-FileHashHex([string]$path) {
    try {
        return (Get-FileHash -Algorithm SHA256 -Path $path -ErrorAction Stop).Hash
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

Write-SetupLog "Quick setup started."

$defaultBase = [Environment]::GetFolderPath("MyDocuments")
$defaultPath = Join-Path $defaultBase "Teams Always Green"

$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = "Select install folder for Teams Always Green"
$dialog.SelectedPath = $defaultPath

if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
    Write-Host "Install canceled."
    exit 1
}

$installPath = $dialog.SelectedPath
$detectedScript = Join-Path $installPath "Script\Teams Always Green.ps1"
if (Test-Path $detectedScript) {
    $choice = [System.Windows.Forms.MessageBox]::Show(
        "An existing install was detected at:`n$installPath`n`nUpgrade/repair this install?",
        "Existing Install",
        [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )
    if ($choice -eq [System.Windows.Forms.DialogResult]::Cancel) {
        Write-Host "Install canceled."
        exit 1
    }
    if ($choice -eq [System.Windows.Forms.DialogResult]::No) {
        if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
            Write-Host "Install canceled."
            exit 1
        }
        $installPath = $dialog.SelectedPath
    }
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

$localRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$localManifestPath = Join-Path $localRoot "QuickSetup.manifest.json"
$useLocal = $false
if (Test-Path (Join-Path $localRoot "Script\Teams Always Green.ps1")) {
    $useLocal = [System.Windows.Forms.MessageBox]::Show(
        "Local app files were found next to QuickSetup.ps1.`nUse local files instead of downloading?",
        "Use Local Files",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    ) -eq [System.Windows.Forms.DialogResult]::Yes
}

$manifest = $null
if ($useLocal) {
    $manifest = Load-Manifest $localManifestPath
} else {
    $manifestUrl = "$rawBase/QuickSetup.manifest.json"
    $manifestTarget = Join-Path $installPath "Meta\QuickSetup.manifest.json"
    try {
        Invoke-WebRequest -Uri $manifestUrl -OutFile $manifestTarget -UseBasicParsing
        $manifest = Load-Manifest $manifestTarget
    } catch {
        Write-SetupLog "Manifest download failed; continuing without integrity validation."
        $manifest = $null
    }
}

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
            Invoke-WebRequest -Uri $file.Url -OutFile $targetPath -UseBasicParsing
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
                Show-SetupError ("Integrity check failed for {0}." -f $file.Path)
                exit 1
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
$desktopDir = [Environment]::GetFolderPath("Desktop")
$desktopShortcut = Join-Path $desktopDir "Teams Always Green.lnk"

$enableStartup = [System.Windows.Forms.MessageBox]::Show(
    "Start Teams Always Green when Windows starts?",
    "Startup Shortcut",
    [System.Windows.Forms.MessageBoxButtons]::YesNo,
    [System.Windows.Forms.MessageBoxIcon]::Question
) -eq [System.Windows.Forms.DialogResult]::Yes

if ($enableStartup) {
    $startupDir = [Environment]::GetFolderPath("Startup")
    $startupShortcut = Join-Path $startupDir "Teams Always Green.lnk"
}

try {
    New-Shortcut -shortcutPath $menuShortcut -targetScriptPath $targetScript -workingDir $installPath
    if ($enableStartup) {
        New-Shortcut -shortcutPath $startupShortcut -targetScriptPath $targetScript -workingDir $installPath
    }
    New-Shortcut -shortcutPath $desktopShortcut -targetScriptPath $targetScript -workingDir $installPath
} catch {
    Write-Host "Failed to create shortcuts: $($_.Exception.Message)"
}

Write-Host "Installed Teams Always Green to: $installPath"
Write-Host "Start Menu shortcut: $menuShortcut"
if ($enableStartup) {
    Write-Host "Startup shortcut: $startupShortcut"
} else {
    Write-Host "Startup shortcut: (skipped)"
}
Write-Host "Desktop shortcut: $desktopShortcut"
Write-Host "Setup log: $logPath"

$postAction = [System.Windows.Forms.MessageBox]::Show(
    "Install complete.`n`nYes = Launch now`nNo = Open Settings`nCancel = Close",
    "Quick Setup",
    [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
    [System.Windows.Forms.MessageBoxIcon]::Information
)
if ($postAction -eq [System.Windows.Forms.DialogResult]::Yes) {
    Start-Process "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetScript`"" -WorkingDirectory $installPath
} elseif ($postAction -eq [System.Windows.Forms.DialogResult]::No) {
    Start-Process "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetScript`" -SettingsOnly" -WorkingDirectory $installPath
}

