# QuickSetup.ps1 - Download and install Teams Always Green into a chosen folder
# Creates Desktop, Start Menu, and Startup shortcuts (no VBS needed).

Add-Type -AssemblyName System.Windows.Forms

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

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {
}

foreach ($file in $filesToDownload) {
    $targetPath = Join-Path $installPath $file.Path
    try {
        Invoke-WebRequest -Uri $file.Url -OutFile $targetPath -UseBasicParsing
    } catch {
        Write-Host ("Download failed: {0} -> {1}" -f $file.Url, $file.Path)
        throw
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

