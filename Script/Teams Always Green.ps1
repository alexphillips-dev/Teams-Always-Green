
# Teams Always Green
# Main entry script for the app. This file owns startup, tray menu, timers,
# settings UI, profiles, logging, scheduling, and shutdown/cleanup.
#
# Files and folders (relative to app root):
# - Script\Teams Always Green.ps1      Main script (this file)
# - Teams Always Green.VBS             Launches the script hidden (no console)
# - QuickSetup.cmd / QuickSetup.ps1    Installer/bootstrapper
# - Logs\                              Runtime logs (main + bootstrap)
# - Settings\                          Settings JSON and backups
# - Meta\                              App metadata and icons
# - Meta\Icons\                        App/UI icon assets (.ico)
# - Debug\                             Debug launcher logs
# - VERSION                            Current app version (used by updates)
#
# Settings and state:
# - Settings JSON is validated and migrated on load.
# - Profile snapshots are cached as â€œlast known goodâ€ for safe rollback.
# - Runtime counters and status are persisted separately from user settings.
#
# Logging:
# - Log level/category filtering is respected everywhere.
# - Debug mode can temporarily override verbosity.
# - Log rotation and retention are enforced by size and age.
#
# Tray menu (high level):
# - Start/Stop/Toggle/Pause and interval control
# - Quick Options, Profiles, Status, Logs, History
# - Settings, Restart, Exit
#
# Troubleshooting:
# - If the app does not appear, check Debug\*.vbs.log and Logs\*.log
# - If settings fail to load, the script will preserve the last good copy
# - If UI feels stale, use Restart to rebuild the tray/menu state
#
# Run modes:
# - -SettingsOnly opens the settings window without starting the tray loop
#
# Folder integrity:
# - Keep the folder structure intact (Script/Logs/Settings/Meta/Debug)

# --- Runtime setup and WinForms initialization (load assemblies, set UI defaults) ---
param(
    [switch]$SettingsOnly
)

$script:SettingsOnly = $SettingsOnly

Set-StrictMode -Version Latest
$proc = $null
$script:TimerGuards = @{}
$script:TrayMenu = $null
$script:TrayMenuToolTip = $null
$script:TrayMenuOpening = $false
$script:UpdateCache = @{
    CheckedAt     = $null
    Release       = $null
    LatestVersion = $null
}
$script:UpdateCacheTtlMinutes = 15
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)


# --- Localization (dot-sourced) ---
. "$PSScriptRoot\I18n\UiStrings.ps1"

# --- Single-instance protection (per-script mutex, abandon-safe) ---
function Get-PathHash([string]$text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($text.ToLowerInvariant())
        ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
    } finally {
        $sha.Dispose()
    }
}

# --- Paths, Meta folder, and locator files (resolve root, ensure dirs) ---
$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path -Parent $scriptPath
$appRoot = if ((Split-Path -Leaf $scriptDir) -ieq "Script") { Split-Path -Parent $scriptDir } else { $scriptDir }
$script:FolderNames = @{
    Logs = "Logs"
    Settings = "Settings"
    Meta = "Meta"
    Debug = "Debug"
    Script = "Script"
}
$script:DataRoot = $appRoot
$script:PathWarnings = @()

function Add-PathWarning([string]$message) {
    if (-not [string]::IsNullOrWhiteSpace($message)) {
        $script:PathWarnings += $message
    }
}

function Write-PathWarningNow([string]$message) {
    if ([string]::IsNullOrWhiteSpace($message)) { return }
    if (Get-Command -Name Write-Log -ErrorAction SilentlyContinue) {
        Write-Log $message "WARN" $null "Paths"
    } else {
        Add-PathWarning $message
    }
}

function Normalize-PathText([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return "" }
    $trimmed = $path.Trim()
    if ($trimmed.StartsWith('"') -and $trimmed.EndsWith('"')) {
        $trimmed = $trimmed.Trim('"')
    }
    $expanded = [Environment]::ExpandEnvironmentVariables($trimmed)
    try {
        return [System.IO.Path]::GetFullPath($expanded)
    } catch {
        return $expanded
    }
}

function Convert-FromRelativePath([string]$value) {
    $normalized = Normalize-PathText $value
    if ([string]::IsNullOrWhiteSpace($normalized)) { return "" }
    if (-not [System.IO.Path]::IsPathRooted($normalized)) {
        return (Join-Path $script:DataRoot $normalized)
    }
    return $normalized
}

function Convert-ToRelativePathIfUnderRoot([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return "" }
    try {
        $full = [System.IO.Path]::GetFullPath($path)
        $root = [System.IO.Path]::GetFullPath($script:DataRoot)
        if ($full.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $full.Substring($root.Length).TrimStart('\')
        }
    } catch {
    }
    return $path
}

function Is-PathUnderRoot([string]$path, [string]$root) {
    if ([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($root)) { return $false }
    try {
        $full = [System.IO.Path]::GetFullPath($path)
        $rootFull = [System.IO.Path]::GetFullPath($root)
        if (-not $rootFull.EndsWith('\')) { $rootFull += '\' }
        return $full.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)
    } catch {
        return $false
    }
}

function Sanitize-DirectorySetting([string]$value, [string]$defaultName, [string]$label, [bool]$allowExternal) {
    if ([string]::IsNullOrWhiteSpace($value)) { return "" }
    $resolved = Convert-FromRelativePath $value
    if (-not $allowExternal) {
        if (-not (Is-PathUnderRoot $resolved $script:DataRoot)) {
            Write-PathWarningNow "$label path outside app folder blocked; using default."
            return ""
        }
    }
    return Convert-ToRelativePathIfUnderRoot $resolved
}

function Test-DirectoryWritable([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    try {
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
        $testFile = Join-Path $path ("~write_test_{0}.tmp" -f ([Guid]::NewGuid().ToString("N")))
        Set-Content -Path $testFile -Value "test" -Encoding ASCII
        Remove-Item -Path $testFile -Force
        return $true
    } catch {
        return $false
    }
}

function Ensure-Directory([string]$path, [string]$label = "Directory") {
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    try {
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
        return $true
    } catch {
        Write-PathWarningNow "$label missing and could not be created: $path"
        return $false
    }
}

function Resolve-DirectoryOrDefault([string]$inputPath, [string]$defaultPath, [string]$label) {
    $resolved = Convert-FromRelativePath $inputPath
    if ([string]::IsNullOrWhiteSpace($resolved)) { $resolved = $defaultPath }
    $resolved = Normalize-PathText $resolved
    Ensure-Directory $resolved $label | Out-Null
    if (-not (Test-DirectoryWritable $resolved)) {
        Write-PathWarningNow "$label directory not writable: $resolved. Falling back to $defaultPath."
        $resolved = $defaultPath
        Ensure-Directory $resolved $label | Out-Null
    }
    return $resolved
}

function Ensure-AppFolders {
    $folders = @($script:FolderNames.Logs, $script:FolderNames.Settings, $script:FolderNames.Meta, $script:FolderNames.Debug, $script:FolderNames.Script)
    foreach ($folder in $folders) {
        $path = Join-Path $script:DataRoot $folder
        Ensure-Directory $path $folder | Out-Null
    }
}

function Harden-AppPermissions {
    $paths = @(
        $script:DataRoot,
        $script:SettingsDirectory,
        $script:LogDirectory,
        $script:MetaDir
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path $_) }
    foreach ($path in $paths) {
        try {
            $acl = Get-Acl -Path $path
            $rules = @($acl.Access) | Where-Object {
                $_.AccessControlType -eq "Allow" -and
                ($_.IdentityReference -match "Everyone|Users") -and
                ($_.FileSystemRights -match "Write|Modify|FullControl")
            }
            foreach ($rule in $rules) {
                $acl.RemoveAccessRule($rule) | Out-Null
            }
            Set-Acl -Path $path -AclObject $acl
        } catch {
            Write-Log ("Permission hardening skipped for {0}: {1}" -f $path, $_.Exception.Message) "WARN" $_.Exception "Security"
        }
    }
}

function Get-SettingsFileHash {
    if (-not $script:settingsPath -or -not (Test-Path $script:settingsPath)) { return $null }
    try {
        return (Get-FileHash -Algorithm $script:SettingsHashAlgorithm -Path $script:settingsPath -ErrorAction Stop).Hash
    } catch {
        return $null
    }
}

function Redact-Paths([string]$message) {
    if ([string]::IsNullOrWhiteSpace($message)) { return $message }
    $result = $message
    try {
        if ($script:DataRoot) {
            $result = $result -replace [regex]::Escape($script:DataRoot), "%APPROOT%"
        }
        $userProfile = $env:USERPROFILE
        if (-not [string]::IsNullOrWhiteSpace($userProfile)) {
            $result = $result -replace [regex]::Escape($userProfile), "%USERPROFILE%"
        }
    } catch {
    }
    return $result
}

function Get-IntegrityTargets {
    $scriptDir = Join-Path $script:DataRoot $script:FolderNames.Script
    if (Test-Path $scriptDir) {
        return (Get-ChildItem -Path $scriptDir -Recurse -File -Filter *.ps1 | Select-Object -ExpandProperty FullName)
    }
    return @($scriptPath)
}

function Write-IntegrityManifest([string[]]$files) {
    if (-not $files -or $files.Count -eq 0) { $files = Get-IntegrityTargets }
    $entries = @()
    foreach ($file in $files) {
        try {
            $hash = (Get-FileHash -Algorithm SHA256 -Path $file -ErrorAction Stop).Hash
            $relative = Convert-ToRelativePathIfUnderRoot $file
            $entries += [pscustomobject]@{ Path = $relative; Sha256 = $hash }
        } catch {
            Write-Log ("Integrity: failed to hash {0}" -f $file) "WARN" $_.Exception "Integrity"
        }
    }
    $payload = [pscustomobject]@{
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString("o")
        Version      = $appVersion
        Files        = $entries
    }
    Ensure-Directory $script:MetaDir "Meta" | Out-Null
    $payload | ConvertTo-Json -Depth 4 | Set-Content -Path $script:IntegrityManifestPath -Encoding UTF8
}

function Verify-IntegrityManifest {
    if (-not (Test-Path $script:IntegrityManifestPath)) {
        return [pscustomobject]@{ Ok = $false; Missing = $true; Issues = @("Manifest missing") }
    }
    try {
        $raw = Get-Content -Path $script:IntegrityManifestPath -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return [pscustomobject]@{ Ok = $false; Missing = $false; Issues = @("Manifest empty") }
        }
        $manifest = $raw | ConvertFrom-Json
    } catch {
        return [pscustomobject]@{ Ok = $false; Missing = $false; Issues = @("Manifest unreadable") }
    }
    if (-not $manifest -or -not $manifest.Files) {
        return [pscustomobject]@{ Ok = $false; Missing = $false; Issues = @("Manifest invalid") }
    }
    $issues = @()
    foreach ($entry in $manifest.Files) {
        if (-not $entry -or -not $entry.Path) { continue }
        $relative = [string]$entry.Path
        $target = Convert-FromRelativePath $relative
        if (-not (Test-Path $target)) {
            $issues += ("Missing {0}" -f $relative)
            continue
        }
        try {
            $hash = (Get-FileHash -Algorithm SHA256 -Path $target -ErrorAction Stop).Hash
            if ([string]$entry.Sha256 -and $hash -ne [string]$entry.Sha256) {
                $issues += ("Modified {0}" -f $relative)
            }
        } catch {
            $issues += ("Unreadable {0}" -f $relative)
        }
    }
    return [pscustomobject]@{ Ok = ($issues.Count -eq 0); Missing = $false; Issues = $issues }
}

$script:MetaDir = Join-Path $script:DataRoot $script:FolderNames.Meta
try { Ensure-Directory $script:MetaDir "Meta" | Out-Null } catch { }
$script:SettingsLocatorPath = Join-Path $script:MetaDir "Teams-Always-Green.settings.path.txt"
$script:LogLocatorPath = Join-Path $script:MetaDir "Teams-Always-Green.log.path.txt"
$script:CommandFilePath = Join-Path $script:MetaDir "Teams-Always-Green.commands.txt"
$script:CommandFileMaxBytes = 4096
$script:CommandFileMaxLines = 20
$script:CommandFileAllowList = @(
    "TEST_TOGGLE",
    "HOTKEY_TOGGLE",
    "HOTKEY_STARTSTOP",
    "HOTKEY_PAUSERESUME",
    "DEBUG_MODE",
    "LOG_SNAPSHOT",
    "CLEAR_LOG"
)
$script:SettingsHashAlgorithm = "SHA256"
$script:StatusFilePath = Join-Path $script:MetaDir "Teams-Always-Green.status.json"
$script:SettingsLastGoodPath = Join-Path $script:MetaDir "Teams-Always-Green.settings.lastgood.json"
$script:SettingsCorruptDir = Join-Path $script:MetaDir "Corrupt"
$script:StateLastGoodPath = Join-Path $script:MetaDir "Teams-Always-Green.state.lastgood.json"
$script:StateCorruptDir = Join-Path $script:MetaDir "Corrupt"
$script:StartupSnapshotPath = Join-Path $script:MetaDir "Teams-Always-Green.startup.json"
$script:CrashStatePath = Join-Path $script:MetaDir "Teams-Always-Green.crash.json"
$script:IntegrityManifestPath = Join-Path $script:MetaDir "Teams-Always-Green.integrity.json"
$script:IntegrityStatus = "Unknown"
$script:IntegrityIssues = @()
$script:IntegrityFailed = $false
$script:UpdatePublicKeyPath = Join-Path $script:MetaDir "Teams-Always-Green.updatekey.xml"
$oldSettingsLocator = Join-Path $script:DataRoot "Teams-Always-Green.settings.path.txt"
$oldLogLocator = Join-Path $script:DataRoot "Teams-Always-Green.log.path.txt"
if ((Test-Path $oldSettingsLocator) -and -not (Test-Path $script:SettingsLocatorPath)) {
    try { Move-Item -Path $oldSettingsLocator -Destination $script:SettingsLocatorPath -Force } catch { }
}
if ((Test-Path $oldLogLocator) -and -not (Test-Path $script:LogLocatorPath)) {
    try { Move-Item -Path $oldLogLocator -Destination $script:LogLocatorPath -Force } catch { }
}
$defaultSettingsDir = Join-Path $script:DataRoot $script:FolderNames.Settings
$defaultLogDir = Join-Path $script:DataRoot $script:FolderNames.Logs
$script:SettingsDirectory = Resolve-DirectoryOrDefault "" $defaultSettingsDir "Settings"
$script:LogDirectory = Resolve-DirectoryOrDefault "" $defaultLogDir "Logs"
$script:StatePath = Join-Path $script:SettingsDirectory "Teams-Always-Green.state.json"
if (Test-Path $script:SettingsLocatorPath) {
    try {
        $locatorValue = (Get-Content -Path $script:SettingsLocatorPath -Raw).Trim()
        $script:SettingsDirectory = Resolve-DirectoryOrDefault $locatorValue $defaultSettingsDir "Settings"
    } catch {
    }
}
if (Test-Path $script:LogLocatorPath) {
    try {
        $logLocatorValue = (Get-Content -Path $script:LogLocatorPath -Raw).Trim()
        $script:LogDirectory = Resolve-DirectoryOrDefault $logLocatorValue $defaultLogDir "Logs"
    } catch {
    }
}
if (-not [string]::IsNullOrWhiteSpace($script:SettingsDirectory)) {
    $script:StatePath = Join-Path $script:SettingsDirectory "Teams-Always-Green.state.json"
}
Ensure-AppFolders | Out-Null
$bootstrapLogFile = "Teams-Always-Green.bootstrap.log"
$bootstrapLogRoot = Join-Path $script:DataRoot $bootstrapLogFile
$bootstrapLogTarget = Join-Path $script:LogDirectory $bootstrapLogFile
if ((Test-Path $bootstrapLogRoot) -and ($bootstrapLogRoot -ne $bootstrapLogTarget)) {
    try {
        if (-not (Test-Path $script:LogDirectory)) {
            New-Item -ItemType Directory -Path $script:LogDirectory -Force | Out-Null
        }
        Move-Item -Path $bootstrapLogRoot -Destination $bootstrapLogTarget -Force
    } catch {
    }
}
$script:BootstrapLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.bootstrap.log"
$script:ShutdownMarkerPath = Join-Path $script:MetaDir "Teams-Always-Green.shutdown.state.txt"

function Get-CrashState {
    $state = @{ Count = 0; LastCrash = $null; OverrideMinimalMode = $false; OverrideMinimalModeLogged = $false }
    if (-not (Test-Path $script:CrashStatePath)) { return $state }
    try {
        $raw = Get-Content -Path $script:CrashStatePath -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) { return $state }
        $loaded = $raw | ConvertFrom-Json
        if ($loaded -and ($loaded.PSObject.Properties.Name -contains "Count")) {
            $state.Count = [int]$loaded.Count
        }
        if ($loaded -and ($loaded.PSObject.Properties.Name -contains "LastCrash")) {
            $state.LastCrash = [string]$loaded.LastCrash
        }
        if ($loaded -and ($loaded.PSObject.Properties.Name -contains "OverrideMinimalMode")) {
            $state.OverrideMinimalMode = [bool]$loaded.OverrideMinimalMode
        }
        if ($loaded -and ($loaded.PSObject.Properties.Name -contains "OverrideMinimalModeLogged")) {
            $state.OverrideMinimalModeLogged = [bool]$loaded.OverrideMinimalModeLogged
        }
    } catch {
    }
    return $state
}

function Save-CrashState($state) {
    if (-not $state) { return }
    try {
        $payload = [pscustomobject]@{
            Count = [int]$state.Count
            LastCrash = [string]$state.LastCrash
            OverrideMinimalMode = [bool]$state.OverrideMinimalMode
            OverrideMinimalModeLogged = [bool]$state.OverrideMinimalModeLogged
        }
        $payload | ConvertTo-Json -Depth 3 | Set-Content -Path $script:CrashStatePath -Encoding UTF8
    } catch {
    }
}

function Save-StartupSnapshot {
    try {
        $payload = [pscustomobject]@{
            Timestamp = (Get-Date).ToString("o")
            DataRoot = $script:DataRoot
            LogDirectory = $script:LogDirectory
            SettingsDirectory = $script:SettingsDirectory
            LogPath = $logPath
            SettingsPath = $settingsPath
            StatePath = $script:StatePath
            ScriptPath = $scriptPath
            Version = $appVersion
        }
        $payload | ConvertTo-Json -Depth 4 | Set-Content -Path $script:StartupSnapshotPath -Encoding UTF8
    } catch {
    }
}

function Repair-FromStartupSnapshot($defaultSettings) {
    $snapshot = $null
    if (Test-Path $script:StartupSnapshotPath) {
        try {
            $raw = Get-Content -Path $script:StartupSnapshotPath -Raw
            if (-not [string]::IsNullOrWhiteSpace($raw)) { $snapshot = $raw | ConvertFrom-Json }
        } catch {
        }
    }

    $targetSettingsDir = if ($snapshot -and $snapshot.PSObject.Properties.Name -contains "SettingsDirectory") { Convert-FromRelativePath $snapshot.SettingsDirectory } else { $script:SettingsDirectory }
    $targetLogDir = if ($snapshot -and $snapshot.PSObject.Properties.Name -contains "LogDirectory") { Convert-FromRelativePath $snapshot.LogDirectory } else { $script:LogDirectory }
    $targetStatePath = if ($snapshot -and $snapshot.PSObject.Properties.Name -contains "StatePath") { Convert-FromRelativePath $snapshot.StatePath } else { $script:StatePath }
    $targetSettingsPath = if ($snapshot -and $snapshot.PSObject.Properties.Name -contains "SettingsPath") { Convert-FromRelativePath $snapshot.SettingsPath } else { $settingsPath }

    try { Ensure-Directory $targetSettingsDir "Settings" | Out-Null } catch { }
    try { Ensure-Directory $targetLogDir "Logs" | Out-Null } catch { }
    try { Ensure-Directory (Split-Path -Path $targetStatePath -Parent) "Settings" | Out-Null } catch { }

    $settingsOk = $false
    if (Test-Path $targetSettingsPath) {
        try {
            $raw = Get-Content -Path $targetSettingsPath -Raw
            if (-not [string]::IsNullOrWhiteSpace($raw)) { $null = $raw | ConvertFrom-Json; $settingsOk = $true }
        } catch {
            $settingsOk = $false
        }
    }

    if (-not $settingsOk -and $defaultSettings) {
        try {
            $recovered = Load-LastGoodSettings
            if ($recovered) {
                $recovered = Normalize-Settings (Migrate-Settings $recovered)
                Save-SettingsImmediate $recovered
                Write-Log "Startup repair: restored settings from last known good snapshot." "WARN" $null "Startup-Repair"
            } else {
                Save-SettingsImmediate $defaultSettings
                Write-Log "Startup repair: settings file missing or invalid; defaults restored." "WARN" $null "Startup-Repair"
            }
        } catch {
        }
    }
}
# --- Date/time formatting helpers (presets + locale) ---
$script:DateTimeFormatDefault = "yyyy-MM-dd HH:mm:ss"
$script:DateTimeFormat = $script:DateTimeFormatDefault
$script:UseSystemDateTimeFormat = $true
$script:SystemDateTimeFormatMode = "Short"
$script:SettingsLoadFailed = $false
$script:SettingsRecovered = $false
$script:SettingsSaveInProgress = $false
$script:SettingsAutoCorrected = $false
$script:SettingsAutoCorrectedMessage = $null
$script:SettingsTampered = $false
$script:SettingsTamperMessage = $null
$script:MinimalModeActive = $false
$script:MinimalModeReason = $null

function Normalize-DateTimeFormat([string]$format) {
    if ([string]::IsNullOrWhiteSpace($format)) { return $script:DateTimeFormatDefault }
    try {
        [DateTime]::Now.ToString($format) | Out-Null
        return $format
    } catch {
        return $script:DateTimeFormatDefault
    }
}

function Format-DateTime($value) {
    if ($null -eq $value) { return "N/A" }
    if ($script:UseSystemDateTimeFormat) {
        $systemFormat = if ($script:SystemDateTimeFormatMode -eq "Long") { "F" } else { "g" }
        try {
            return ([DateTime]$value).ToString($systemFormat)
        } catch {
            return [string]$value
        }
    }
    $format = Normalize-DateTimeFormat $script:DateTimeFormat
    try {
        return ([DateTime]$value).ToString($format)
    } catch {
        return [string]$value
    }
}

function Normalize-IntervalSeconds([int]$seconds) {
    if ($seconds -lt 5) { return 5 }
    if ($seconds -gt 86400) { return 86400 }
    return $seconds
}

function Get-EnvironmentSummary {
    try {
        $culture = [System.Globalization.CultureInfo]::CurrentCulture.Name
        $uiCulture = [System.Globalization.CultureInfo]::CurrentUICulture.Name
        $is64 = [Environment]::Is64BitProcess
        $dpi = $null
        try {
            $dpi = [System.Windows.Forms.Screen]::PrimaryScreen.DeviceDpi
        } catch { }
        $dpiText = if ($dpi) { $dpi } else { "Unknown" }
        return ("Environment summary: Culture={0} UICulture={1} DPI={2} 64Bit={3}" -f $culture, $uiCulture, $dpiText, $is64)
    } catch {
        return "Environment summary: Unavailable"
    }
}

# --- Bootstrap logging before full logger is initialized (early file log) ---
function Write-BootstrapLog([string]$message, [string]$level = "INFO") {
    try {
        $timestamp = (Get-Date).ToString($script:DateTimeFormatDefault)
        $line = "[${timestamp}] [$level] [Bootstrap] $message"
        Add-Content -Path $script:BootstrapLogPath -Value $line
    } catch { }
}

Write-BootstrapLog ("Paths resolved: DataRoot={0} Logs={1} Settings={2}" -f $script:DataRoot, $script:LogDirectory, $script:SettingsDirectory) "INFO"

function Save-LastGoodSettingsRaw([string]$rawJson) {
    if ([string]::IsNullOrWhiteSpace($rawJson)) { return }
    try {
        Ensure-Directory $script:MetaDir "Meta" | Out-Null
        Set-Content -Path $script:SettingsLastGoodPath -Value $rawJson -Encoding UTF8
    } catch {
    }
}

function Save-CorruptSettingsCopy([string]$rawJson) {
    try {
        Ensure-Directory $script:SettingsCorruptDir "Corrupt" | Out-Null
        $stamp = (Get-Date).ToString("yyyyMMddHHmmss")
        $target = Join-Path $script:SettingsCorruptDir ("Teams-Always-Green.settings.corrupt.{0}.json" -f $stamp)
        if (-not [string]::IsNullOrWhiteSpace($rawJson)) {
            Set-Content -Path $target -Value $rawJson -Encoding UTF8
        } elseif (Test-Path $script:settingsPath) {
            Copy-Item -Path $script:settingsPath -Destination $target -Force
        }
        Write-BootstrapLog "Corrupt settings saved to $target" "WARN"
    } catch {
    }
}

function Load-LastGoodSettings {
    try {
        if (Test-Path $script:SettingsLastGoodPath) {
            $raw = Get-Content -Path $script:SettingsLastGoodPath -Raw
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $loaded = $raw | ConvertFrom-Json
                $validation = Test-SettingsSchema $loaded
                if ($validation.IsCritical) { return $null }
                return $loaded
            }
        }
    } catch {
    }
    return $null
}

if ($script:PathWarnings -and $script:PathWarnings.Count -gt 0) {
    foreach ($msg in $script:PathWarnings) {
        Write-BootstrapLog $msg "WARN"
    }
    $script:PathWarnings = @()
}

Write-BootstrapLog "Startup: ScriptPath=$scriptPath LogDir=$script:LogDirectory SettingsDir=$script:SettingsDirectory" "INFO"

# --- Shutdown marker for crash detection (clean-exit flag) ---
function Set-ShutdownMarker([string]$state) {
    try {
        Set-Content -Path $script:ShutdownMarkerPath -Value $state -Encoding ASCII
    } catch {
        Write-BootstrapLog "Failed to write shutdown marker: $($_.Exception.Message)" "WARN"
    }
}

function Get-ShutdownMarker {
    try {
        if (Test-Path $script:ShutdownMarkerPath) {
            return (Get-Content -Path $script:ShutdownMarkerPath -Raw).Trim()
        }
    } catch { }
    return $null
}

# --- Logging stubs for early startup (safe logging pre-settings) ---
if (-not (Get-Command -Name Write-Log -ErrorAction SilentlyContinue)) {
    function Write-Log([string]$message, [string]$level = "INFO", [Exception]$exception = $null, [string]$context = $null, [switch]$Force) {
        Write-BootstrapLog $message $level
    }
}

if (-not (Get-Command -Name Write-LogEx -ErrorAction SilentlyContinue)) {
    function Write-LogEx([string]$message, [string]$level = "ERROR", [Exception]$exception = $null, [string]$context = $null, [switch]$Force) {
        Write-Log $message $level $exception $context -Force:$Force
    }
}

$script:LogThrottle = @{}

function Write-LogThrottled([string]$key, [string]$message, [string]$level = "INFO", [int]$minSeconds = 10) {
    if ([string]::IsNullOrWhiteSpace($key)) { return }
    $now = Get-Date
    $last = $null
    if ($script:LogThrottle.ContainsKey($key)) {
        $last = $script:LogThrottle[$key]
    }
    if ($last -and (($now - $last).TotalSeconds -lt $minSeconds)) {
        return
    }
    $script:LogThrottle[$key] = $now
    Write-Log $message $level $null $key
}

function Invoke-SafeTimerAction([string]$name, [ScriptBlock]$action) {
    $guardsVar = Get-Variable -Name TimerGuards -Scope Script -ErrorAction SilentlyContinue
    if (-not $guardsVar -or -not $guardsVar.Value) { $script:TimerGuards = @{} }
    if ($script:TimerGuards.ContainsKey($name) -and $script:TimerGuards[$name]) { return }
    $script:TimerGuards[$name] = $true
    try {
        & $action
    } catch {
        $safeName = if ([string]::IsNullOrWhiteSpace($name)) { "Timer" } else { "Timer-$name" }
        Write-LogThrottled $safeName ("Timer handler failed: {0}" -f $_.Exception.Message) "WARN" 15
    } finally {
        $script:TimerGuards[$name] = $false
    }
}

function Clear-StaleRuntimeState([string]$reason) {
    try {
        $targets = @(
            $script:CommandFilePath,
            $script:StatusFilePath,
            $script:ShutdownMarkerPath
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        foreach ($path in $targets) {
            try {
                if (Test-Path $path) {
                    Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
                }
            } catch {
            }
        }
        $script:SettingsForm = $null
        $script:SettingsFormIcon = $null
        $note = if ([string]::IsNullOrWhiteSpace($reason)) { "Cleared stale runtime state." } else { "Cleared stale runtime state ($reason)." }
        Write-BootstrapLog $note "WARN"
    } catch {
    }
}

function Get-PathHealthSummary {
    $logWritable = Test-DirectoryWritable $script:LogDirectory
    $settingsWritable = Test-DirectoryWritable $script:SettingsDirectory
    return ("Paths: DataRoot={0} LogDir={1} (Writable={2}) SettingsDir={3} (Writable={4})" -f `
        $script:DataRoot, $script:LogDirectory, $logWritable, $script:SettingsDirectory, $settingsWritable)
}

function Validate-RequiredFiles {
    if (-not (Test-Path $versionPath)) {
        Write-LogThrottled "Missing-Version" "VERSION file missing; version display may be inaccurate." "WARN" 300
    }
    $iconFiles = @(
        (Join-Path $script:DataRoot "Meta\\Icons\\Tray_Icon.ico"),
        (Join-Path $script:DataRoot "Meta\\Icons\\Settings_Icon.ico")
    )
    foreach ($icon in $iconFiles) {
        if (-not (Test-Path $icon)) {
            Write-LogThrottled ("MissingIcon-" + (Split-Path -Leaf $icon)) ("Icon missing: {0}. Using fallback icon." -f $icon) "WARN" 300
        }
    }
}

function Log-FolderHealthOnce {
    $results = Validate-FolderPaths
    $bad = @($results | Where-Object { -not $_.Exists -or -not $_.Writable })
    if ($bad.Count -gt 0) {
        $summary = $bad | ForEach-Object {
            $state = if (-not $_.Exists) { "Missing" } elseif (-not $_.Writable) { "ReadOnly" } else { "OK" }
            "{0}={1}" -f $_.Name, $state
        }
        Write-Log ("Folder check: " + ($summary -join ", ")) "WARN" $null "Folders"
    } else {
        Write-LogThrottled "FolderHealth" "Folder check: OK" "INFO" 600
    }
}

function Validate-FolderPaths {
    $results = @()
    $paths = @(
        @{ Name = "DataRoot"; Path = $script:DataRoot },
        @{ Name = "Logs"; Path = $script:LogDirectory },
        @{ Name = "Settings"; Path = $script:SettingsDirectory },
        @{ Name = "Meta"; Path = $script:MetaDir },
        @{ Name = "Debug"; Path = (Join-Path $script:DataRoot $script:FolderNames.Debug) }
    )
    foreach ($item in $paths) {
        $exists = Test-Path $item.Path
        $writable = if ($exists) { Test-DirectoryWritable $item.Path } else { $false }
        $results += [pscustomobject]@{
            Name     = $item.Name
            Path     = $item.Path
            Exists   = $exists
            Writable = $writable
        }
    }
    return $results
}

function Invoke-HealthCheckDialog {
    $lines = @()
    $issues = @()
    $folderResults = Validate-FolderPaths
    foreach ($item in $folderResults) {
        $state = if (-not $item.Exists) { "Missing" } elseif (-not $item.Writable) { "Read-only" } else { "OK" }
        $lines += ("{0}: {1}" -f $item.Name, $state)
        if ($state -ne "OK") { $issues += ("{0}={1}" -f $item.Name, $state) }
    }
    $settingsFile = $script:settingsPath
    if (-not [string]::IsNullOrWhiteSpace($settingsFile) -and (Test-Path $settingsFile)) {
        try {
            $null = Get-Content -Path $settingsFile -Raw | ConvertFrom-Json -ErrorAction Stop
            $lines += "Settings file: OK"
        } catch {
            $lines += "Settings file: Invalid"
            $issues += "Settings file invalid"
        }
    } else {
        $lines += "Settings file: Missing"
        $issues += "Settings file missing"
    }

    $summary = if ($issues.Count -gt 0) { "Issues found" } else { "All checks passed" }
    $message = "Health check`n`n" + ($lines -join "`n") + "`n`n" + $summary
    if ($issues.Count -gt 0) {
        Write-Log ("Health check issues: " + ($issues -join ", ")) "WARN" $null "Diagnostics"
    } else {
        Write-Log "Health check: OK" "INFO" $null "Diagnostics"
    }
    [System.Windows.Forms.MessageBox]::Show(
        $message,
        "Health Check",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
}

function Test-SettingsSchema($settings) {
    $issues = @()
    $isCritical = $false
    $futureVersion = $false
    $schemaVersion = 1

    if (-not $settings) {
        $issues += "Settings object is null."
        $isCritical = $true
    } elseif (-not ($settings -is [pscustomobject] -or $settings -is [hashtable])) {
        $issues += "Settings root is not an object."
        $isCritical = $true
    }

    $schemaValue = Get-SettingsPropertyValue $settings "SchemaVersion"
    if ($null -ne $schemaValue) {
        try {
            $schemaVersion = [int]$schemaValue
        } catch {
            $issues += "SchemaVersion is not numeric."
            $isCritical = $true
            $schemaVersion = -1
        }
    } else {
        $issues += "SchemaVersion missing."
    }

    if ($schemaVersion -gt $script:SettingsSchemaVersion) {
        $futureVersion = $true
        $issues += ("Settings schema version {0} is newer than supported {1}." -f $schemaVersion, $script:SettingsSchemaVersion)
    }

    $propertyNames = @()
    if ($settings) {
        $propertyNames = if ($settings -is [hashtable]) { $settings.Keys } else { $settings.PSObject.Properties.Name }
    }
    if ($script:DefaultSettingsKeys -and $script:DefaultSettingsKeys.Count -gt 0) {
        $missing = @()
        foreach ($key in $script:DefaultSettingsKeys) {
            if ($script:SettingsRuntimeKeys -contains $key) { continue }
            if (-not ($propertyNames -contains $key)) {
                $missing += $key
            }
        }
        if ($missing.Count -gt 0) {
            $issues += ("Missing keys: {0}" -f ((@($missing | Select-Object -First 8)) -join ","))
        }
    }

    if ($settings -and ($settings.PSObject.Properties.Name -contains "Profiles")) {
        if ($null -ne $settings.Profiles -and -not ($settings.Profiles -is [hashtable] -or $settings.Profiles -is [pscustomobject])) {
            $issues += "Profiles must be an object."
            $isCritical = $true
        }
    }
    if ($settings -and ($settings.PSObject.Properties.Name -contains "LogCategories")) {
        if ($null -ne $settings.LogCategories -and -not ($settings.LogCategories -is [hashtable] -or $settings.LogCategories -is [pscustomobject])) {
            $issues += "LogCategories must be an object."
        }
    }
    if ($settings -and ($settings.PSObject.Properties.Name -contains "LogEventLevels")) {
        if ($null -ne $settings.LogEventLevels -and -not ($settings.LogEventLevels -is [hashtable] -or $settings.LogEventLevels -is [pscustomobject])) {
            $issues += "LogEventLevels must be an object."
        }
    }
    if ($settings -and ($settings.PSObject.Properties.Name -contains "IntervalSeconds")) {
        if ($settings.IntervalSeconds -isnot [int] -and $settings.IntervalSeconds -isnot [long] -and $settings.IntervalSeconds -isnot [double]) {
            $issues += "IntervalSeconds is not numeric."
        }
    }
    if ($settings -and ($settings.PSObject.Properties.Name -contains "LogMaxBytes")) {
        if ($settings.LogMaxBytes -isnot [int] -and $settings.LogMaxBytes -isnot [long] -and $settings.LogMaxBytes -isnot [double]) {
            $issues += "LogMaxBytes is not numeric."
        }
    }
    if ($settings -and ($settings.PSObject.Properties.Name -contains "LogMaxTotalBytes")) {
        if ($settings.LogMaxTotalBytes -isnot [int] -and $settings.LogMaxTotalBytes -isnot [long] -and $settings.LogMaxTotalBytes -isnot [double]) {
            $issues += "LogMaxTotalBytes is not numeric."
        }
    }
    if ($settings -and ($settings.PSObject.Properties.Name -contains "LogRetentionDays")) {
        if ($settings.LogRetentionDays -isnot [int] -and $settings.LogRetentionDays -isnot [long] -and $settings.LogRetentionDays -isnot [double]) {
            $issues += "LogRetentionDays is not numeric."
        }
    }

    return [pscustomobject]@{
        IsValid       = (-not $isCritical)
        IsCritical    = $isCritical
        Issues        = $issues
        SchemaVersion = $schemaVersion
        FutureVersion = $futureVersion
    }
}

function Get-SettingsExtraFields($settings) {
    $extras = @{}
    if (-not $settings) { return $extras }
    if (-not $script:DefaultSettingsKeys -or $script:DefaultSettingsKeys.Count -eq 0) { return $extras }
    if ($settings -is [hashtable]) {
        foreach ($key in $settings.Keys) {
            if ($script:DefaultSettingsKeys -contains $key) { continue }
            if ($script:SettingsRuntimeKeys -contains $key) { continue }
            if ($key -like "Exported*") { continue }
            $extras[$key] = $settings[$key]
        }
        return $extras
    }
    foreach ($prop in $settings.PSObject.Properties) {
        if ($script:DefaultSettingsKeys -contains $prop.Name) { continue }
        if ($script:SettingsRuntimeKeys -contains $prop.Name) { continue }
        if ($prop.Name -like "Exported*") { continue }
        $extras[$prop.Name] = $prop.Value
    }
    return $extras
}

function Extract-RuntimeFromSettings($settings) {
    $runtime = @{}
    if (-not $settings) { return $runtime }
    foreach ($key in $script:SettingsRuntimeKeys) {
        if ($settings -is [hashtable]) {
            if ($settings.ContainsKey($key)) {
                $runtime[$key] = $settings[$key]
                $settings.Remove($key) | Out-Null
            }
        } elseif ($settings.PSObject.Properties.Name -contains $key) {
            $runtime[$key] = $settings.$key
            $settings.PSObject.Properties.Remove($key)
        }
    }
    return $runtime
}

function Apply-RuntimeOverridesToState($state, $runtime) {
    if (-not $state -or -not $runtime -or $runtime.Count -eq 0) { return $false }
    $changed = $false
    if ($runtime.ContainsKey("ToggleCount")) {
        $incoming = [int]$runtime["ToggleCount"]
        if ([int]$state.ToggleCount -eq 0 -and $incoming -gt 0) {
            $state.ToggleCount = $incoming
            $changed = $true
        }
    }
    if ($runtime.ContainsKey("LastToggleTime")) {
        if ($null -eq $state.LastToggleTime -and $null -ne $runtime["LastToggleTime"]) {
            $state.LastToggleTime = $runtime["LastToggleTime"]
            $changed = $true
        }
    }
    if ($runtime.ContainsKey("Stats")) {
        $incomingStats = Convert-ToHashtable $runtime["Stats"]
        $currentStats = Convert-ToHashtable $state.Stats
        if ($currentStats.Count -eq 0 -and $incomingStats.Count -gt 0) {
            $state.Stats = $incomingStats
            $changed = $true
        }
    }
    return $changed
}

function Get-SettingsDiffSummary($before, $after, [int]$maxKeys = 12) {
    if (-not $before) { $before = $defaultSettings }
    if (-not $after) { $after = $defaultSettings }
    $beforeSnap = Get-SettingsSnapshot $before
    $afterSnap = Get-SettingsSnapshot $after
    $allKeys = @($beforeSnap.Keys + $afterSnap.Keys) | Sort-Object -Unique
    $changed = @()
    foreach ($key in $allKeys) {
        if ($script:SettingsNonDiffKeys -and ($script:SettingsNonDiffKeys -contains $key)) { continue }
        $oldVal = if ($beforeSnap.ContainsKey($key)) { $beforeSnap[$key] } else { "<missing>" }
        $newVal = if ($afterSnap.ContainsKey($key)) { $afterSnap[$key] } else { "<missing>" }
        if ($oldVal -ne $newVal) { $changed += $key }
    }
    $summaryKeys = if ($changed.Count -gt 0) { ($changed | Select-Object -First $maxKeys) -join ", " } else { "" }
    $summary = if ($changed.Count -eq 0) {
        "No changes detected."
    } else {
        $tail = if ($changed.Count -gt $maxKeys) { " (and $($changed.Count - $maxKeys) more)" } else { "" }
        ("Changes ({0}): {1}{2}" -f $changed.Count, $summaryKeys, $tail)
    }
    return [pscustomobject]@{
        Count   = $changed.Count
        Keys    = $changed
        Summary = $summary
    }
}
# --- Global state, caches, and UI references (script-wide) ---
$notifyIcon = $null
$hash = Get-PathHash $scriptPath
$mutexName = "Local\TeamsAlwaysGreenPS_$($hash.Substring(0,16))"
$script:SessionId = [Guid]::NewGuid().ToString("N").Substring(0, 8)
$script:AppStartTime = Get-Date
$script:LastErrorMessage = $null
$script:LastErrorTime = $null
$script:isScheduleSuspended = $false
$script:LastScheduleBlocked = $false
$script:LastToggleResult = "None"
$script:LastToggleResultTime = $null
$script:LastToggleError = $null
$script:LastSettingsSnapshot = $null
$script:LastSettingsSnapshotHash = $null
$script:isShuttingDown = $false
$script:CleanupDone = $false
$script:SettingsForm = $null
$script:SettingsFormIcon = $null
$script:SettingsSchemaVersion = 8
$script:StateSchemaVersion = 1
$script:SettingsRuntimeKeys = @("ToggleCount", "LastToggleTime", "Stats")
$script:SettingsNonDiffKeys = @("LastSaved", "LastSavedBy", "SettingsOrigin", "AppVersion") + $script:SettingsRuntimeKeys
$script:SettingsFutureVersion = $false
$script:SettingsExtraFields = @{}
$script:SettingsLoadIssues = @()
$script:DefaultSettingsKeys = @()
$script:PendingRuntimeFromSettings = @{}
$script:ProfileSchemaVersion = 1
$script:ProfileMetadataKeys = @("ProfileSchemaVersion", "ReadOnly")
$script:ProfilesLastGoodPath = $null
$script:ProfilesLastGood = @{}
$script:ProfileSnapshotCacheKey = $null
$script:ProfileSnapshotCache = $null
$script:UpdateProfileDirtyIndicator = $null
$script:LastSettingsSaveOk = $true
$script:LastSettingsSaveMessage = ""
$script:AppState = $null
$script:LastStateSnapshot = $null
$script:LastStateSnapshotHash = $null
$script:SettingsToggleCurrentValue = $null
$script:SettingsToggleLifetimeValue = $null
$script:ScheduleWeekdayCacheText = $null
$script:ScheduleWeekdayCacheSet = @()
$script:ScheduleTimeCacheKey = $null
$script:ScheduleStartCache = [TimeSpan]::Zero
$script:ScheduleEndCache = [TimeSpan]::Zero
$script:ScheduleStatusCacheKey = $null
$script:ScheduleStatusCacheValue = $null
$script:NextInfoCacheKey = $null
$script:NextInfoCacheValue = $null
$script:HotkeyStatusText = "Unknown"
# --- Debounced timers and periodic tasks (reduce churn) ---
$script:SaveSettingsPending = $null
$script:SaveSettingsDebounceMs = 400
$script:SaveSettingsTimer = New-Object System.Windows.Forms.Timer
$script:SaveSettingsTimer.Interval = $script:SaveSettingsDebounceMs
$script:SaveSettingsTimer.Add_Tick({
    Invoke-SafeTimerAction "SaveSettingsTimer" {
        if ($script:isShuttingDown -or $script:CleanupDone) {
            $script:SaveSettingsTimer.Stop()
            return
        }
        $script:SaveSettingsTimer.Stop()
        if ($script:SaveSettingsPending) {
            Save-SettingsImmediate $script:SaveSettingsPending
            $script:SaveSettingsPending = $null
        }
    }
})
$script:StatusUpdatePending = $false
$script:StatusUpdateInProgress = $false
$script:StatusUpdateDebounceTimer = New-Object System.Windows.Forms.Timer
$script:StatusUpdateDebounceTimer.Interval = 120
$script:StatusUpdateDebounceTimer.Add_Tick({
    Invoke-SafeTimerAction "StatusUpdateDebounceTimer" {
        if ($script:isShuttingDown -or $script:CleanupDone) {
            $script:StatusUpdateDebounceTimer.Stop()
            return
        }
        $script:StatusUpdateDebounceTimer.Stop()
        $script:StatusUpdatePending = $false
        Update-StatusText
    }
})
$script:LogFlushTimer = New-Object System.Windows.Forms.Timer
$script:LogFlushTimer.Interval = 1000
$script:LogFlushTimer.Add_Tick({
    Invoke-SafeTimerAction "LogFlushTimer" {
        if ($script:isShuttingDown -or $script:CleanupDone) {
            $script:LogFlushTimer.Stop()
            return
        }
        Flush-LogBuffer
    }
})
$script:LastScheduleSuspended = $false
$script:DebugModeUntil = $null
$script:PreviousLogLevel = $null
$script:LastRestartTime = Get-Date
$script:LastUserAction = $null
$script:LastUserActionTime = $null
$script:LastUserActionContext = $null
$script:LastUserActionId = $null
$script:LastActionLogged = $null
$script:RecentActions = New-Object System.Collections.ArrayList
$script:RecentActionsMax = 50
$script:DeferredSettingsTimer = $null
$script:SettingsIsApplying = $false
$script:SetDirty = $null
$script:SettingsOkButton = $null
$script:SettingsDirtyLabel = $null
$script:SettingsSaveLabel = $null
$script:SettingsSaveTimer = $null
$script:CollectSettingsFromControls = $null
$script:ClearFieldErrors = $null
$script:ErrorLabels = $null
$script:SetFieldError = $null
$script:LastTogglePicker = $null
$script:LastSavedLabel = $null
$script:CopySettingsObject = $null
$script:UpdateLastSavedLabel = $null
$script:ShowPendingSettingsDiff = $null
$script:IntervalBox = $null
$script:ToggleCountBox = $null
$script:PauseUntilBox = $null
$script:PauseDurationsBox = $null
$script:ScheduleOverrideBox = $null
$script:ScheduleEnabledBox = $null
$script:ScheduleStartBox = $null
$script:ScheduleEndBox = $null
$script:ScheduleWeekdaysBox = $null
$script:ScheduleSuspendUntilBox = $null
$script:SafeModeEnabledBox = $null
$script:SafeModeThresholdBox = $null
$script:HotkeyToggleBox = $null
$script:HotkeyStartStopBox = $null
$script:HotkeyPauseResumeBox = $null
$script:LogMaxBox = $null
$script:LogRetentionBox = $null
$script:ProfileBox = $null
$script:StartWithWindowsBox = $null
$script:OpenSettingsLastTabBox = $null
$script:RememberChoiceBox = $null
$script:StartOnLaunchBox = $null
$script:QuietModeBox = $null
$script:DisableBalloonBox = $null
$script:ThemeModeBox = $null
$script:TooltipStyleBox = $null
$script:FontSizeBox = $null
$script:SettingsFontSizeBox = $null
$script:StatusRunningColorPanel = $null
$script:StatusPausedColorPanel = $null
$script:StatusStoppedColorPanel = $null
$script:PickStatusColor = $null
$script:ColorDialog = $null
$script:ApplyCompactMode = $null
$script:MainPanel = $null
$script:DebugModeStatus = $null
$script:SettingsDebugModeStatus = $null
$script:CompactModeBox = $null
$script:RunOnceOnLaunchBox = $null
$script:ScheduleSuspendQuickBox = $null
$script:LogLevelBox = $null
$script:LogIncludeStackTraceBox = $null
$script:LogToEventLogBox = $null
$script:LogEventLevelBoxes = $null
$script:VerboseUiLogBox = $null
$script:ScrubDiagnosticsBox = $null
$script:LogCategoryBoxes = $null
$script:LastHoverUpdateTime = $null
$script:HoverUpdateMinMs = 1000
$script:WarningCount = 0
$script:ErrorCount = 0
$script:LogWriteCount = 0
$script:LogRotationCount = 0
$script:LastLogRotationTime = $null
$script:LastLogWriteTime = $null
$script:RecentLogLines = New-Object System.Collections.ArrayList
$script:RecentLogLinesMax = 200
$script:LogResultOverride = $null
$script:LogSummaryTimer = $null
$script:LogSummaryIntervalMinutes = 5
$script:LastLogSizeCheckTime = $null
$script:LogBuffer = New-Object System.Collections.Generic.List[string]
$script:LogBufferMax = 20
$script:IsFlushingLog = $false
$script:DebugForceAllCategories = $false
$script:PreviousLogCategories = $null
$script:MinLogFreeMB = 50
$script:LastLowDiskWarnTime = $null
$script:RunId = ([Guid]::NewGuid().ToString("N")).Substring(0, 8)
$script:LastErrorId = $null
$script:LastSettingsChangeSummary = $null
$script:LastSettingsChangeDetail = $null
$script:FallbackLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.fallback.log"
$script:FallbackLogWarned = $false
$script:LogDirFallbackWarned = $false
$script:DebugModeTimer = New-Object System.Windows.Forms.Timer
$script:DebugModeTimer.Interval = 1000
$script:DebugModeTimer.Add_Tick({
    Invoke-SafeTimerAction "DebugModeTimer" {
        if ($script:isShuttingDown -or $script:CleanupDone) {
            $script:DebugModeTimer.Stop()
            return
        }
        $debugStatus = Get-DebugModeStatusText
        if ($script:DebugModeStatus) { $script:DebugModeStatus.Text = $debugStatus }
        if ($script:SettingsDebugModeStatus) { $script:SettingsDebugModeStatus.Text = $debugStatus }
        try { Request-StatusUpdate } catch { }
        if ($script:DebugModeUntil -and (Get-Date) -ge $script:DebugModeUntil) {
            $script:DebugModeTimer.Stop()
            Disable-DebugMode
            Update-LogLevelMenuChecks
            if (Get-Command -Name Start-LogSummaryTimer -ErrorAction SilentlyContinue) { Start-LogSummaryTimer }
            Write-Log "Debug mode expired; log level restored." "INFO" $null "Logging"
        }
    }
})
# --- App metadata (version/build/release) ---
$versionPath = Join-Path $script:DataRoot "VERSION"
$appVersion = "1.0.0"
$appLastUpdated = "Unknown"
if (Test-Path $versionPath) {
    try {
        $rawVersion = (Get-Content -Path $versionPath -Raw).Trim()
        if (-not [string]::IsNullOrWhiteSpace($rawVersion)) {
            $appVersion = $rawVersion
        }
        $versionInfo = Get-Item -Path $versionPath
        if ($versionInfo -and $versionInfo.LastWriteTime) {
            $appLastUpdated = $versionInfo.LastWriteTime.ToString("yyyy-MM-dd")
        }
    } catch {
    }
}
$integrityResult = Verify-IntegrityManifest
if ($integrityResult.Missing) {
    Write-Log "Integrity manifest missing; generating baseline." "WARN" $null "Integrity"
    Write-IntegrityManifest
    $script:IntegrityStatus = "Generated"
    $script:IntegrityFailed = $false
} elseif (-not $integrityResult.Ok) {
    $script:IntegrityStatus = "Mismatch"
    $script:IntegrityIssues = $integrityResult.Issues
    $script:IntegrityFailed = $true
    Write-Log ("Integrity check failed: " + ($integrityResult.Issues -join "; ")) "WARN" $null "Integrity"
} else {
    $script:IntegrityStatus = "OK"
    $script:IntegrityIssues = @()
    $script:IntegrityFailed = $false
}
$appBuildTimestamp = $null
$appBuildId = ([Guid]::NewGuid().ToString("N")).Substring(0, 8)
$appScriptHash = $null
try {
    $appBuildTimestamp = (Get-Item -Path $scriptPath -ErrorAction Stop).LastWriteTime
    $appScriptHash = (Get-FileHash -Algorithm SHA256 -Path $scriptPath -ErrorAction Stop).Hash
} catch {
    $appBuildTimestamp = $null
    $appScriptHash = $null
}

function Get-StartupSource {
    try {
        $proc = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $PID) -ErrorAction Stop
        if ($proc.ParentProcessId) {
            $parent = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $proc.ParentProcessId) -ErrorAction SilentlyContinue
            if ($parent -and $parent.Name) {
                $parentName = $parent.Name.ToLowerInvariant()
                if ($parentName -eq "wscript.exe" -or $parentName -eq "cscript.exe") { return "VBS" }
                if ($parentName -eq "explorer.exe") { return "Explorer" }
                if ($parentName -eq "powershell.exe") { return "PowerShell" }
                return $parent.Name
            }
        }
    } catch {
    }
    return "Unknown"
}

function Get-LatestReleaseInfo([string]$owner, [string]$repo) {
    $uri = "https://api.github.com/repos/$owner/$repo/releases/latest"
    $headers = @{ "User-Agent" = "TeamsAlwaysGreen" }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    } catch {
    }
    try {
        return Invoke-RestMethod -Uri $uri -Headers $headers -ErrorAction Stop
    } catch {
        Write-Log "Update check failed: $($_.Exception.Message)" "WARN" $_.Exception "Update"
        return $null
    }
}

function Get-LatestReleaseCached([string]$owner, [string]$repo, [switch]$Force) {
    if (-not $Force) {
        if ($script:UpdateCache.CheckedAt -and $script:UpdateCache.Release) {
            $ageMinutes = ([DateTime]::UtcNow - $script:UpdateCache.CheckedAt).TotalMinutes
            if ($ageMinutes -lt $script:UpdateCacheTtlMinutes) {
                return $script:UpdateCache.Release
            }
        }
    }
    $release = Get-LatestReleaseCached $owner $repo -Force:$Force
    if ($release) {
        $script:UpdateCache.Release = $release
        $script:UpdateCache.CheckedAt = [DateTime]::UtcNow
        $script:UpdateCache.LatestVersion = Get-ReleaseVersionString $release
    }
    return $release
}

function Get-ReleaseVersionString($release) {
    if (-not $release) { return $null }
    $tag = $null
    if ($release.PSObject.Properties.Name -contains "tag_name") { $tag = [string]$release.tag_name }
    if ([string]::IsNullOrWhiteSpace($tag) -and ($release.PSObject.Properties.Name -contains "name")) {
        $tag = [string]$release.name
    }
    if ([string]::IsNullOrWhiteSpace($tag)) { return $null }
    $tag = $tag.Trim()
    if ($tag.StartsWith("v")) { $tag = $tag.Substring(1) }
    return $tag
}

function Compare-VersionString([string]$left, [string]$right) {
    $leftVersion = $null
    $rightVersion = $null
    if (-not [version]::TryParse($left, [ref]$leftVersion)) { return 0 }
    if (-not [version]::TryParse($right, [ref]$rightVersion)) { return 0 }
    return $leftVersion.CompareTo($rightVersion)
}

function Get-ReleaseAsset($release, [string]$assetName) {
    if (-not $release -or -not $release.assets) { return $null }
    foreach ($asset in $release.assets) {
        if ([string]$asset.name -eq $assetName) { return $asset }
    }
    return $null
}

function Get-ReleaseAssetHash([object]$release, [string]$assetName) {
    if (-not $release) { return $null }
    $hashAsset = Get-ReleaseAsset $release ($assetName + ".sha256")
    if (-not $hashAsset) { $hashAsset = Get-ReleaseAsset $release ($assetName + ".sha256.txt") }
    if (-not $hashAsset -or -not $hashAsset.browser_download_url) { return $null }
    $tempHash = Join-Path $env:TEMP ("TeamsAlwaysGreen.hash." + [Guid]::NewGuid().ToString("N") + ".tmp")
    try {
        Invoke-WebRequest -Uri $hashAsset.browser_download_url -OutFile $tempHash -UseBasicParsing -ErrorAction Stop
        $raw = (Get-Content -Path $tempHash -Raw).Trim()
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        $parts = $raw -split "\s+"
        $hash = $parts[0]
        if ($hash -match "^[A-Fa-f0-9]{64}$") {
            return $hash.ToUpperInvariant()
        }
    } catch {
    } finally {
        try { if (Test-Path $tempHash) { Remove-Item -Path $tempHash -Force } } catch { }
    }
    return $null
}

function Get-UpdatePublicKeyXml {
    if ($script:UpdatePublicKeyPath -and (Test-Path $script:UpdatePublicKeyPath)) {
        try { return (Get-Content -Path $script:UpdatePublicKeyPath -Raw).Trim() } catch { }
    }
    return $null
}

function Get-ReleaseAssetSignatureBytes([object]$release, [string]$assetName) {
    if (-not $release) { return $null }
    $sigAsset = Get-ReleaseAsset $release ($assetName + ".sig")
    if (-not $sigAsset -or -not $sigAsset.browser_download_url) { return $null }
    $tempSig = Join-Path $env:TEMP ("TeamsAlwaysGreen.sig." + [Guid]::NewGuid().ToString("N") + ".tmp")
    try {
        Invoke-WebRequest -Uri $sigAsset.browser_download_url -OutFile $tempSig -UseBasicParsing -ErrorAction Stop
        $raw = (Get-Content -Path $tempSig -Raw).Trim()
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        if ($raw -match "^[A-Fa-f0-9]+$") {
            $bytes = New-Object byte[] ($raw.Length / 2)
            for ($i = 0; $i -lt $bytes.Length; $i++) {
                $bytes[$i] = [Convert]::ToByte($raw.Substring($i * 2, 2), 16)
            }
            return $bytes
        }
        return [Convert]::FromBase64String($raw)
    } catch {
        return $null
    } finally {
        try { if (Test-Path $tempSig) { Remove-Item -Path $tempSig -Force } } catch { }
    }
}

function Verify-UpdateSignature([string]$filePath, [byte[]]$signatureBytes, [string]$publicKeyXml) {
    if (-not $filePath -or -not $signatureBytes -or -not $publicKeyXml) { return $false }
    try {
        $data = [System.IO.File]::ReadAllBytes($filePath)
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.FromXmlString($publicKeyXml)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            return $rsa.VerifyData($data, $sha, $signatureBytes)
        } finally {
            $sha.Dispose()
            $rsa.Dispose()
        }
    } catch {
        return $false
    }
}

function Invoke-UpdateCheck {
    param(
        [switch]$Force
    )
    if (-not $Force) {
        if (-not ($settings.PSObject.Properties.Name -contains "AutoUpdateEnabled") -or -not [bool]$settings.AutoUpdateEnabled) { return }
    }
    $owner = "alexphillips-dev"
    $repo = "Teams-Always-Green"
    $assetName = "Teams Always Green.ps1"
    $release = Get-LatestReleaseInfo $owner $repo
    if (-not $release) { return }
    $latestVersion = Get-ReleaseVersionString $release
    if ([string]::IsNullOrWhiteSpace($latestVersion)) { return }
    if ((Compare-VersionString $latestVersion $appVersion) -le 0) { return }

    $prompt = "A new version is available.`n`nCurrent: $appVersion`nLatest: $latestVersion`n`nDownload and install now?"
    $result = [System.Windows.Forms.MessageBox]::Show(
        $prompt,
        "Update available",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
    if ($result -ne [System.Windows.Forms.DialogResult]::Yes) {
        Write-Log "Update available; user chose not to update." "INFO" $null "Update"
        return
    }

    $asset = Get-ReleaseAsset $release $assetName
    if (-not $asset -or -not $asset.browser_download_url) {
        Write-Log "Update asset not found in latest release." "WARN" $null "Update"
        [System.Windows.Forms.MessageBox]::Show(
            "Update asset '$assetName' was not found in the latest release.",
            "Update failed",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return
    }

    $tempPath = Join-Path $env:TEMP ("Teams Always Green.ps1." + [Guid]::NewGuid().ToString("N") + ".tmp")
    $backupPath = $null
    try {
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $tempPath -UseBasicParsing -ErrorAction Stop
        $downloadInfo = Get-Item -Path $tempPath -ErrorAction Stop
        if ($downloadInfo.Length -lt 2048) {
            throw "Downloaded file looks too small."
        }
        $expectedHash = Get-ReleaseAssetHash $release $assetName
        if ($expectedHash) {
            $actualHash = (Get-FileHash -Algorithm SHA256 -Path $tempPath -ErrorAction Stop).Hash
            if ($expectedHash -ne $actualHash) {
                throw "Downloaded file hash mismatch."
            }
        }
        if ($settings.PSObject.Properties.Name -contains "UpdateRequireSignature" -and [bool]$settings.UpdateRequireSignature) {
            $publicKey = Get-UpdatePublicKeyXml
            if (-not $publicKey) {
                throw "Update signature public key missing."
            }
            $sigBytes = Get-ReleaseAssetSignatureBytes $release $assetName
            if (-not $sigBytes) {
                throw "Update signature missing."
            }
            if (-not (Verify-UpdateSignature $tempPath $sigBytes $publicKey)) {
                throw "Update signature verification failed."
            }
        }

        $backupPath = Join-Path $script:MetaDir ("Teams Always Green.ps1.bak." + (Get-Date -Format "yyyyMMddHHmmss"))
        Copy-Item -Path $scriptPath -Destination $backupPath -Force
        Move-Item -Path $tempPath -Destination $scriptPath -Force
        $versionPathLocal = Join-Path $script:DataRoot "VERSION"
        try {
            Set-Content -Path $versionPathLocal -Value $latestVersion -Encoding ASCII
            if ($release.PSObject.Properties.Name -contains "published_at" -and $release.published_at) {
                try {
                    $published = [DateTime]::Parse($release.published_at)
                    (Get-Item -Path $versionPathLocal).LastWriteTime = $published
                } catch {
                }
            }
        } catch {
        }
        Write-Log "Update applied; restarting." "INFO" $null "Update"
        Set-ShutdownMarker "clean"
        if (Get-Command -Name Flush-LogBuffer -ErrorAction SilentlyContinue) { Flush-LogBuffer }
        Release-MutexOnce
        $script:CleanupDone = $true
        Start-Process -FilePath "powershell.exe" -WindowStyle Hidden -WorkingDirectory $script:DataRoot -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
        [System.Windows.Forms.Application]::Exit()
    } catch {
        try { if (Test-Path $tempPath) { Remove-Item -Path $tempPath -Force } } catch { }
        try {
            if ($backupPath -and (Test-Path $backupPath)) {
                Copy-Item -Path $backupPath -Destination $scriptPath -Force
            }
        } catch {
        }
        Write-Log "Update failed: $($_.Exception.Message)" "ERROR" $_.Exception "Update"
        [System.Windows.Forms.MessageBox]::Show(
            "Update failed.`n$($_.Exception.Message)",
            "Update failed",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }
}

# --- Single-instance mutex acquisition (acquire/retry) ---
$createdNew = $false
$mutex = New-Object System.Threading.Mutex($false, $mutexName, [ref]$createdNew)
$script:SingleInstanceMutex = $mutex

$script:HasMutex = $false
try {
    # Try to acquire immediately. If another instance is running, this will be false.
    $script:HasMutex = $mutex.WaitOne(0, $false)
} catch [System.Threading.AbandonedMutexException] {
    # Previous instance died without releasing; treat as not-running and continue.
    $script:HasMutex = $true
    Clear-StaleRuntimeState "abandoned mutex"
}

if (-not $script:HasMutex) {
    [System.Windows.Forms.MessageBox]::Show(
        "Teams-Always-Green is already running for this script path (check the system tray).",
        "Already running",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
    exit
}

# --- Log/settings paths and logging defaults (resolve + create) ---
# Resolve paths (same folder as script)
$iconPath  = Join-Path $script:DataRoot "Meta\\Icons\\Tray_Icon.ico"
$script:logPath   = Join-Path $script:LogDirectory "Teams-Always-Green.log"
$script:AuditLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.audit.log"
$script:settingsPath = Join-Path $script:SettingsDirectory "Teams-Always-Green.settings.json"
# Ensure default folders exist
try {
    if (-not (Test-Path $script:LogDirectory)) {
        New-Item -ItemType Directory -Path $script:LogDirectory -Force | Out-Null
    }
    if (-not (Test-Path $script:SettingsDirectory)) {
        New-Item -ItemType Directory -Path $script:SettingsDirectory -Force | Out-Null
    }
} catch {
}
# Move root log/settings files into their folders if they were created in the script directory
$rootLogPath = Join-Path $script:DataRoot "Teams-Always-Green.log"
if ((Test-Path $rootLogPath) -and ($script:LogDirectory -ne $script:DataRoot)) {
    try { Move-Item -Path $rootLogPath -Destination $script:logPath -Force } catch { }
}
$rootSettingsPath = Join-Path $script:DataRoot "Teams-Always-Green.settings.json"
if ((Test-Path $rootSettingsPath) -and ($script:SettingsDirectory -ne $script:DataRoot)) {
    try { Move-Item -Path $rootSettingsPath -Destination $script:settingsPath -Force } catch { }
}
foreach ($i in 1..3) {
    $rootBak = Join-Path $script:DataRoot ("Teams-Always-Green.settings.json.bak{0}" -f $i)
    $destBak = Join-Path $script:SettingsDirectory ("Teams-Always-Green.settings.json.bak{0}" -f $i)
    if ((Test-Path $rootBak) -and ($script:SettingsDirectory -ne $script:DataRoot)) {
        try { Move-Item -Path $rootBak -Destination $destBak -Force } catch { }
    }
}
# --- Logging configuration defaults (levels/limits) ---
$script:LogLevel = "INFO"
$script:LogMaxBytes = 1048576
$script:LogMaxTotalBytes = 20971520
$script:PeakWorkingSetMB = 0
$script:FirstErrorSnapshotWritten = $false
$script:AuditLogEnabled = $true
$script:AuditLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.audit.log"
$script:LogLevels = @{
    "DEBUG" = 1
    "INFO"  = 2
    "WARN"  = 3
    "ERROR" = 4
    "FATAL" = 5
}
$script:RecentErrors = New-Object System.Collections.ArrayList
$script:LogCategoryNames = @("General", "Startup", "Settings", "Schedule", "Hotkeys", "Tray", "Profiles", "Diagnostics", "Logging")
$script:LogCategories = @{}
$script:EventLogSource = "TeamsAlwaysGreen"
$script:EventLogReady = $false

# --- Logging categorization and filtering (categories) ---
function Get-LogCategory([string]$context) {
    if ([string]::IsNullOrWhiteSpace($context)) { return "General" }
    if ($context -match "Startup") { return "Startup" }
    if ($context -match "Settings") { return "Settings" }
    if ($context -match "Schedule") { return "Schedule" }
    if ($context -match "Hotkey") { return "Hotkeys" }
    if ($context -match "Tray") { return "Tray" }
    if ($context -match "Profile") { return "Profiles" }
    if ($context -match "Diagnostics|SelfTest|Export") { return "Diagnostics" }
    if ($context -match "Log") { return "Logging" }
    return "General"
}

function Get-RecommendedLogLevel([string]$context, [string]$message) {
    if ($context -match "Settings-UI") { return "DEBUG" }
    if ($context -match "Timer|Watchdog") { return "DEBUG" }
    if ($message -match "^UI: Settings action (started|completed)") { return "DEBUG" }
    if ($context -match "Settings-Dialog" -and $message -match "^UI: Settings dialog") { return "DEBUG" }
    if ($message -match "^UI:" -and -not [bool]$settings.VerboseUiLogging) { return "DEBUG" }
    return $null
}

function Should-IncludeInfoTags([string]$context, [string]$message, [string]$category) {
    if ([string]::IsNullOrWhiteSpace($context)) { return $false }
    if ($context -match "Tray|Settings|Profiles|Hotkey|Schedule|Update|Logging|Diagnostics|Startup|Shutdown|Restart|Exit|State|Status") { return $true }
    if ($message -match "Tray action|Settings|Profile|Schedule|Update|Log level|Restart|Exit") { return $true }
    return $false
}

function Update-LogCategorySettings {
    $script:LogCategories = @{}
    foreach ($name in $script:LogCategoryNames) {
        $enabled = $true
        if ($settings.PSObject.Properties.Name -contains "LogCategories") {
            if ($settings.LogCategories -is [hashtable] -and $settings.LogCategories.ContainsKey($name)) {
                $enabled = [bool]$settings.LogCategories[$name]
            } elseif ($settings.LogCategories -is [pscustomobject] -and $settings.LogCategories.PSObject.Properties.Name -contains $name) {
                $enabled = [bool]$settings.LogCategories.$name
            }
        }
        $script:LogCategories[$name] = $enabled
    }
}

function Update-PeakWorkingSet {
    try {
        $proc = Get-Process -Id $PID -ErrorAction Stop
        $mb = [Math]::Round(($proc.WorkingSet64 / 1MB), 1)
        if ($mb -gt $script:PeakWorkingSetMB) {
            $script:PeakWorkingSetMB = $mb
        }
    } catch {
    }
}

function Get-ToggleRatePerMinute([double]$uptimeMinutes) {
    if ($uptimeMinutes -le 0) { return 0 }
    return [Math]::Round(($script:tickCount / $uptimeMinutes), 2)
}

function Log-StateSummary([string]$reason) {
    $scheduleStatus = Format-ScheduleStatus
    Write-Log ("State: Running={0} Paused={1} ScheduleEnabled={2} ScheduleBlocked={3} ScheduleStatus={4} Interval={5}s Profile={6}" -f `
        $script:isRunning, $script:isPaused, [bool]$settings.ScheduleEnabled, $script:isScheduleBlocked, $scheduleStatus, $settings.IntervalSeconds, $settings.ActiveProfile) `
        "INFO" $null ($reason)
}

function Log-StartupSummary {
    Write-Log ("Startup summary: Profile={0} Interval={1}s LogLevel={2} QuietMode={3} StartOnLaunch={4} RunOnceOnLaunch={5} ScheduleEnabled={6} Paused={7}" -f `
        $settings.ActiveProfile, $settings.IntervalSeconds, $settings.LogLevel, $settings.QuietMode, $settings.StartOnLaunch, $settings.RunOnceOnLaunch, $settings.ScheduleEnabled, $script:isPaused) `
        "DEBUG" $null "Startup"
}

function Log-ShutdownSummary([string]$reason) {
    $uptimeMinutes = [Math]::Round(((Get-Date) - $script:AppStartTime).TotalMinutes, 1)
    Update-PeakWorkingSet
    $toggleRate = Get-ToggleRatePerMinute $uptimeMinutes
    $peakMb = if ($script:PeakWorkingSetMB -gt 0) { $script:PeakWorkingSetMB } else { 0 }
    Write-Log ("Shutdown summary: Reason={0} Profile={1} Interval={2}s LogLevel={3} Running={4} Paused={5} ScheduleEnabled={6} Warns={7} Errors={8}" -f `
        $reason, $settings.ActiveProfile, $settings.IntervalSeconds, $settings.LogLevel, $script:isRunning, $script:isPaused, $settings.ScheduleEnabled, $script:WarningCount, $script:ErrorCount) `
        "INFO" $null "Shutdown"
    Write-Log ("Session end: SessionID={0} LogWrites={1} Rotations={2} LastLogWrite={3} UptimeMinutes={4} PeakMB={5} TogglesPerMin={6}" -f `
        $script:RunId, $script:LogWriteCount, $script:LogRotationCount, (Format-DateTime $script:LastLogWriteTime), $uptimeMinutes, $peakMb, $toggleRate) "INFO" $null "Shutdown"
    Update-FunStatsOnShutdown $uptimeMinutes
}

function Write-AuditLog([string]$action, [string]$context = $null, [string]$actionId = $null, [string]$detail = $null) {
    if (-not $script:AuditLogEnabled) { return }
    if ([string]::IsNullOrWhiteSpace($action)) { return }
    try {
        Ensure-LogDirectoryWritable
        if (-not $script:AuditLogPath) {
            $script:AuditLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.audit.log"
        }
        $timestamp = Format-DateTime (Get-Date)
        $parts = @("[${timestamp}]", "[AUDIT]", "Action=$action")
        if ($context) { $parts += "Context=$context" }
        if ($actionId) { $parts += "Id=$actionId" }
        if ($detail) { $parts += "Detail=$detail" }
        Add-Content -Path $script:AuditLogPath -Value ($parts -join " ")
    } catch {
    }
}

function Set-LastUserAction([string]$name, [string]$context = $null) {
    if ([string]::IsNullOrWhiteSpace($name)) { return }
    $script:LastUserAction = $name
    $script:LastUserActionContext = $context
    $script:LastUserActionTime = Get-Date
    $script:LastUserActionId = [Guid]::NewGuid().ToString("N").Substring(0, 6)
    Add-RecentAction $name $context $script:LastUserActionId
    Write-AuditLog $name $context $script:LastUserActionId
}

function Get-LastUserActionLabel([int]$maxMinutes = 10) {
    if (-not $script:LastUserActionTime -or -not $script:LastUserAction) { return $null }
    $age = (Get-Date) - $script:LastUserActionTime
    if ($age.TotalMinutes -gt $maxMinutes) { return $null }
    if ($script:LastUserActionContext) {
        return "$($script:LastUserActionContext): $($script:LastUserAction)"
    }
    return $script:LastUserAction
}

function Add-RecentAction([string]$name, [string]$context, [string]$actionId) {
    if ([string]::IsNullOrWhiteSpace($name)) { return }
    $entry = [pscustomobject]@{
        Time    = Get-Date
        Context = $context
        Action  = $name
        Id      = $actionId
    }
    [void]$script:RecentActions.Add($entry)
    while ($script:RecentActions.Count -gt $script:RecentActionsMax) {
        $script:RecentActions.RemoveAt(0) | Out-Null
    }
}

function Get-RecentActionsLines {
    $lines = New-Object System.Collections.Generic.List[string]
    if (-not $script:RecentActions -or $script:RecentActions.Count -eq 0) {
        $lines.Add("  None")
        return $lines
    }
    foreach ($entry in $script:RecentActions) {
        $time = Format-DateTime $entry.Time
        $label = if ([string]::IsNullOrWhiteSpace($entry.Context)) { $entry.Action } else { "$($entry.Context): $($entry.Action)" }
        if ($entry.Id) {
            $lines.Add(("  {0} [{1}] {2}" -f $time, $entry.Id, $label))
        } else {
            $lines.Add(("  {0} {1}" -f $time, $label))
        }
    }
    return $lines
}

function Add-RecentError([string]$message, [string]$context, [Exception]$exception) {
    $entry = [pscustomobject]@{
        Time = Get-Date
        Context = $context
        Message = $message
        ExceptionType = if ($exception) { $exception.GetType().FullName } else { $null }
    }
    [void]$script:RecentErrors.Add($entry)
    while ($script:RecentErrors.Count -gt 20) {
        $script:RecentErrors.RemoveAt(0) | Out-Null
    }
}

# --- Logging formatting and error helpers (tags/stack) ---
function Format-Exception([Exception]$ex) {
    if ($null -eq $ex) { return "" }
    $lines = @(
        "ExceptionType=$($ex.GetType().FullName)"
        "Message=$($ex.Message)"
    )
    if ($ex.InnerException) {
        $lines += "InnerExceptionType=$($ex.InnerException.GetType().FullName)"
        $lines += "InnerMessage=$($ex.InnerException.Message)"
    }
    $includeStack = $false
    if (Get-Variable -Name settings -Scope Script -ErrorAction SilentlyContinue) {
        if ($settings -and ($settings.PSObject.Properties.Name -contains "LogIncludeStackTrace")) {
            $includeStack = [bool]$settings.LogIncludeStackTrace
        }
    }
    if ($ex.StackTrace -and $includeStack) {
        $lines += "StackTrace=$($ex.StackTrace)"
    }
    return ($lines -join " | ")
}

function Release-MutexOnce {
    if ($script:HasMutex -and $script:SingleInstanceMutex) {
        try {
            $script:SingleInstanceMutex.ReleaseMutex() | Out-Null
        } finally {
            $script:HasMutex = $false
        }
    }
}

function New-ErrorId {
    return ([Guid]::NewGuid().ToString("N")).Substring(0, 6)
}

function Write-LogEx([string]$message, [string]$level = "ERROR", [Exception]$exception = $null, [string]$context = $null, [switch]$Force) {
    $errorId = New-ErrorId
    $script:LastErrorId = $errorId
    $hresult = $null
    $win32 = $null
    if ($exception) {
        try { $hresult = $exception.HResult } catch { }
        try { $win32 = [Runtime.InteropServices.Marshal]::GetLastWin32Error() } catch { }
    }
    $parts = @()
    if ($null -ne $hresult) { $parts += ("HResult=0x{0:X8}" -f $hresult) }
    if ($null -ne $win32 -and $win32 -ne 0) { $parts += ("Win32Error={0}" -f $win32) }
    if ($script:LastUserActionId) { $parts += ("ActionId={0}" -f $script:LastUserActionId) }
    if ($script:LastUserAction) { $parts += ("LastAction={0}" -f $script:LastUserAction) }
    if ($script:LastSettingsChangeSummary) { $parts += ("LastSettings={0}" -f $script:LastSettingsChangeSummary) }
    if ($parts.Count -gt 0) {
        $message = "$message | " + ($parts -join " ")
    }
    Write-Log $message $level $exception $context -Force:$Force
}

function Rotate-LogIfNeeded([int]$maxBytes = 1048576) {
    try {
        if (Should-SkipLogWrite) { return }
        if (-not (Test-Path $logPath)) { return }
        $now = Get-Date
        if ($script:LastLogSizeCheckTime -and (($now - $script:LastLogSizeCheckTime).TotalSeconds -lt 1)) {
            return
        }
        $script:LastLogSizeCheckTime = $now
        if ($script:LogMaxBytes -is [int] -and $script:LogMaxBytes -gt 0) {
            $maxBytes = $script:LogMaxBytes
        }
        $size = (Get-Item -Path $logPath).Length
        if ($size -lt $maxBytes) { return }
        $oldSize = $size
        $rotated = $false
        for ($i = 5; $i -ge 1; $i--) {
            $src = if ($i -eq 1) { $logPath } else { "$logPath.$($i - 1)" }
            $dst = "$logPath.$i"
            if (Test-Path $src) {
                if (Test-Path $dst) {
                    Remove-Item -Path $dst -Force
                }
                Rename-Item -Path $src -NewName $dst
                $rotated = $true
            }
        }
        if ($rotated) {
            $script:LogRotationCount++
            $script:LastLogRotationTime = Get-Date
            $timestamp = Format-DateTime (Get-Date)
            $parts = @("[${timestamp}]", "[INFO]", "[Log-Rotation]", "[Category=Logging]")
            $line = ($parts -join " ") + " Log rotated. PreviousSize=$oldSize NewSize=0"
            Add-Content -Path $logPath -Value $line
        }
        Purge-OldLogs
    } catch {
        # Swallow log rotation errors to avoid breaking startup.
    }
}

function Purge-OldLogs {
    $days = 0
    try { $days = [int]$settings.LogRetentionDays } catch { $days = 0 }
    $logDir = Split-Path -Path $script:logPath -Parent
    if (-not (Test-Path $logDir)) { return }
    $removed = 0
    if ($days -gt 0) {
        $cutoff = (Get-Date).AddDays(-$days)
        Get-ChildItem -Path $logDir -File -Filter "Teams-Always-Green*.log*" | ForEach-Object {
            if ($_.FullName -ne $script:logPath -and $_.LastWriteTime -lt $cutoff) {
                try {
                    Remove-Item -Path $_.FullName -Force
                    $removed++
                } catch { }
            }
        }
        if ($removed -gt 0 -and $script:LogLevel -eq "DEBUG") {
            Write-Log ("Log retention purge removed {0} file(s) older than {1} days." -f $removed, $days) "DEBUG" $null "Logging"
        }
    }
    $maxTotal = $script:LogMaxTotalBytes
    try {
        if ($settings -and ($settings.PSObject.Properties.Name -contains "LogMaxTotalBytes")) {
            $maxTotal = [long]$settings.LogMaxTotalBytes
        }
    } catch {
        $maxTotal = $script:LogMaxTotalBytes
    }
    if ($maxTotal -gt 0) {
        $files = Get-ChildItem -Path $logDir -File -Filter "Teams-Always-Green*.log*" | Sort-Object LastWriteTime
        $total = 0
        foreach ($file in $files) { $total += $file.Length }
        $removedTotal = 0
        foreach ($file in $files) {
            if ($total -le $maxTotal) { break }
            if ($file.FullName -eq $script:logPath) { continue }
            try {
                $total -= $file.Length
                Remove-Item -Path $file.FullName -Force
                $removedTotal++
            } catch { }
        }
        if ($removedTotal -gt 0 -and $script:LogLevel -eq "DEBUG") {
            Write-Log ("Log size purge removed {0} file(s) to stay under {1} bytes." -f $removedTotal, $maxTotal) "DEBUG" $null "Logging"
        }
    }
}

function Flush-LogBuffer {
    if ($script:IsFlushingLog) { return }
    if ($script:LogBuffer.Count -eq 0) { return }
    $script:IsFlushingLog = $true
    try {
        $lines = $script:LogBuffer.ToArray()
        $script:LogBuffer.Clear()
        $written = $false
        for ($i = 0; $i -lt 3; $i++) {
            try {
                Add-Content -Path $logPath -Value $lines
                $written = $true
                break
            } catch {
                Start-Sleep -Milliseconds (60 * ($i + 1))
            }
        }
        if (-not $written) {
            try { Add-Content -Path $script:FallbackLogPath -Value $lines } catch { }
        }
    } catch {
        # Ignore flush errors.
    } finally {
        $script:IsFlushingLog = $false
    }
}
$script:LogFlushTimer.Start()

function Is-EventLogLevelEnabled([string]$level) {
    $settingsVar = Get-Variable -Name settings -Scope Script -ErrorAction SilentlyContinue
    if (-not $settingsVar -or -not $settingsVar.Value) { return $false }
    if (-not [bool]$settingsVar.Value.LogToEventLog) { return $false }
    $upper = [string]$level
    if ([string]::IsNullOrWhiteSpace($upper)) { return $false }
    $upper = $upper.Trim().ToUpperInvariant()
    $levels = $settingsVar.Value.LogEventLevels
    if ($levels -is [hashtable]) {
        if ($levels.ContainsKey($upper)) { return [bool]$levels[$upper] }
        return $false
    }
    if ($levels -is [pscustomobject] -and ($levels.PSObject.Properties.Name -contains $upper)) {
        return [bool]$levels.$upper
    }
    return ($upper -eq "ERROR" -or $upper -eq "FATAL")
}

function Write-EventLogSafe([string]$message, [string]$level) {
    if (-not (Is-EventLogLevelEnabled $level)) { return }
    try {
        if (-not $script:EventLogReady) {
            if (-not [System.Diagnostics.EventLog]::SourceExists($script:EventLogSource)) {
                New-EventLog -LogName "Application" -Source $script:EventLogSource | Out-Null
            }
            $script:EventLogReady = $true
        }
        $entryType = [System.Diagnostics.EventLogEntryType]::Error
        if ($level -eq "WARN") { $entryType = [System.Diagnostics.EventLogEntryType]::Warning }
        if ($level -eq "INFO") { $entryType = [System.Diagnostics.EventLogEntryType]::Information }
        Write-EventLog -LogName "Application" -Source $script:EventLogSource -EventId 1000 -EntryType $entryType -Message $message
    } catch {
        $script:EventLogReady = $false
    }
}

function Add-RecentLogLine([string]$line) {
    if ([string]::IsNullOrWhiteSpace($line)) { return }
    [void]$script:RecentLogLines.Add($line)
    while ($script:RecentLogLines.Count -gt $script:RecentLogLinesMax) {
        $script:RecentLogLines.RemoveAt(0) | Out-Null
    }
}

function Dump-RecentLogs([string]$reason) {
    if (-not $script:RecentLogLines -or $script:RecentLogLines.Count -eq 0) { return }
    $timestamp = Format-DateTime (Get-Date)
    $header = "[${timestamp}] [FATAL] [Recent-Logs] Dumping recent log buffer. Reason=$reason"
    $footer = "[${timestamp}] [FATAL] [Recent-Logs] End of recent log buffer."
    try {
        Add-Content -Path $script:logPath -Value $header
        foreach ($line in $script:RecentLogLines) {
            Add-Content -Path $script:logPath -Value $line
        }
        Add-Content -Path $script:logPath -Value $footer
    } catch {
        try {
            Add-Content -Path $script:FallbackLogPath -Value $header
            foreach ($line in $script:RecentLogLines) {
                Add-Content -Path $script:FallbackLogPath -Value $line
            }
            Add-Content -Path $script:FallbackLogPath -Value $footer
        } catch { }
    }
}

function Write-FirstErrorSnapshot([string]$reason) {
    if ($script:FirstErrorSnapshotWritten) { return }
    if (-not $script:RecentLogLines -or $script:RecentLogLines.Count -eq 0) { return }
    $script:FirstErrorSnapshotWritten = $true
    $timestamp = Format-DateTime (Get-Date)
    $header = "[${timestamp}] [ERROR] [Recent-Logs] First error snapshot. Reason=$reason"
    $footer = "[${timestamp}] [ERROR] [Recent-Logs] End of first error snapshot."
    $tail = @($script:RecentLogLines | Select-Object -Last 5)
    try {
        Add-Content -Path $script:logPath -Value $header
        foreach ($line in $tail) {
            Add-Content -Path $script:logPath -Value $line
        }
        Add-Content -Path $script:logPath -Value $footer
    } catch {
        try {
            Add-Content -Path $script:FallbackLogPath -Value $header
            foreach ($line in $tail) {
                Add-Content -Path $script:FallbackLogPath -Value $line
            }
            Add-Content -Path $script:FallbackLogPath -Value $footer
        } catch { }
    }
}

function Scrub-LogText([string]$text) {
    if ([string]::IsNullOrEmpty($text)) { return $text }
    $scrubbed = $text
    if ($env:USERPROFILE) {
        $scrubbed = $scrubbed -replace [regex]::Escape($env:USERPROFILE), "%USERPROFILE%"
    }
    if ($env:USERNAME) {
        $scrubbed = $scrubbed -replace [regex]::Escape($env:USERNAME), "%USERNAME%"
    }
    return $scrubbed
}

function Scrub-LogLines([string[]]$lines) {
    if (-not $lines) { return $lines }
    return $lines | ForEach-Object { Scrub-LogText $_ }
}

function Write-DiagnosticsReport([string]$targetPath) {
    if ([string]::IsNullOrWhiteSpace($targetPath)) { return $null }
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
    if ($settings.ScrubDiagnostics) {
        $lines = Scrub-LogLines $lines
    }
    $lines | Set-Content -Path $targetPath -Encoding UTF8
    return $targetPath
}

function Get-DriveFreeMB([string]$path) {
    try {
        $normalized = Normalize-PathText $path
        if ([string]::IsNullOrWhiteSpace($normalized)) { return -1 }
        $root = [System.IO.Path]::GetPathRoot($normalized)
        if ([string]::IsNullOrWhiteSpace($root)) { return -1 }
        $drive = New-Object System.IO.DriveInfo($root)
        return [math]::Floor($drive.AvailableFreeSpace / 1MB)
    } catch {
        return -1
    }
}

function Should-SkipLogWrite {
    $freeMb = Get-DriveFreeMB $script:LogDirectory
    if ($freeMb -ge 0 -and $freeMb -lt $script:MinLogFreeMB) {
        $now = Get-Date
        if (-not $script:LastLowDiskWarnTime -or (($now - $script:LastLowDiskWarnTime).TotalSeconds -gt 60)) {
            $script:LastLowDiskWarnTime = $now
            Write-BootstrapLog "Low disk space (${freeMb} MB free). Skipping log writes." "WARN"
        }
        return $true
    }
    return $false
}

function Ensure-LogDirectoryWritable {
    if (Test-DirectoryWritable $script:LogDirectory) { return }
    $fallback = Join-Path $script:DataRoot $script:FolderNames.Logs
    if (-not $script:LogDirFallbackWarned) {
        $script:LogDirFallbackWarned = $true
        Write-BootstrapLog "Log directory not writable; falling back to $fallback." "WARN"
    }
    $script:LogDirectory = Resolve-DirectoryOrDefault $fallback $fallback "Logs"
    $script:logPath = Join-Path $script:LogDirectory "Teams-Always-Green.log"
    $script:FallbackLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.fallback.log"
    $script:BootstrapLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.bootstrap.log"
    $script:AuditLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.audit.log"
    try {
        $locatorValue = Convert-ToRelativePathIfUnderRoot $script:LogDirectory
        Set-Content -Path $script:LogLocatorPath -Value $locatorValue -Encoding ASCII
    } catch {
    }
}

function Write-Log([string]$message, [string]$level = "INFO", [Exception]$exception = $null, [string]$context = $null, [switch]$Force) {
    $settingsVar = Get-Variable -Name settings -Scope Script -ErrorAction SilentlyContinue
    if ($settingsVar -and $settingsVar.Value -and ($settingsVar.Value.PSObject.Properties.Name -contains "LogLevel")) {
        $desiredLevel = [string]$settingsVar.Value.LogLevel
        if (-not [string]::IsNullOrWhiteSpace($desiredLevel)) {
            $desiredLevel = $desiredLevel.Trim().ToUpperInvariant()
            if (-not $script:LogLevels.ContainsKey($desiredLevel)) {
                $desiredLevel = "INFO"
            }
            if ($script:DebugModeUntil) {
                $desiredLevel = "DEBUG"
            }
            if ($script:LogLevel -ne $desiredLevel) {
                $script:LogLevel = $desiredLevel
            }
        }
    }
    $levelKey = $level.ToUpperInvariant()
    $suppressTags = $false
    $tagKeyLine = $false
    if (-not [string]::IsNullOrWhiteSpace($message)) {
        $trimmedMessage = $message.Trim()
        if ($trimmedMessage -match "^Tag Key:") {
            $suppressTags = $true
            $tagKeyLine = $true
        } elseif ($trimmedMessage -match "^=+$" -or $trimmedMessage -match "APP (START|RESTART|EXIT)") {
            $suppressTags = $true
        }
    } elseif ($message -eq "") {
        $suppressTags = $true
    }
    if (-not $script:LogLevels.ContainsKey($levelKey)) {
        $levelKey = "INFO"
    }
    if (($levelKey -eq "INFO" -or $levelKey -eq "WARN") -and $script:LogLevel -ne "DEBUG") {
        $message = Redact-Paths $message
    }
    if (-not $script:LogLevels.ContainsKey($script:LogLevel)) {
        $script:LogLevel = "INFO"
    }
    $category = Get-LogCategory $context
    $recommended = Get-RecommendedLogLevel $context $message
    if ($recommended -eq "DEBUG" -and $levelKey -eq "INFO") {
        if ($script:LogLevel -ne "DEBUG") {
            return
        }
        $levelKey = "DEBUG"
    }
    $forceLine = $Force -or $suppressTags
    if (-not $forceLine) {
        if ($script:LogLevels.ContainsKey($levelKey) -and $script:LogLevels.ContainsKey($script:LogLevel)) {
            if ($script:LogLevels[$levelKey] -lt $script:LogLevels[$script:LogLevel]) {
                return
            }
        }
    }
    if (-not $forceLine -and -not $script:DebugForceAllCategories) {
        if ($levelKey -ne "FATAL") {
            if ($script:LogCategories.ContainsKey($category) -and -not $script:LogCategories[$category]) {
                return
            }
        }
    }
    if ($levelKey -eq "ERROR" -or $levelKey -eq "FATAL") {
        $script:LastErrorMessage = $message
        $script:LastErrorTime = Get-Date
        Add-RecentError $message $context $exception
        $script:ErrorCount++
    } elseif ($levelKey -eq "WARN") {
        $script:WarningCount++
    }
    $script:LogWriteCount++
    if (-not $forceLine -and $levelKey -ne "FATAL") {
        if (Should-SkipLogWrite) {
            return
        }
    }
    Ensure-LogDirectoryWritable
    if (-not (Test-Path $script:LogDirectory)) {
        if (-not (Ensure-Directory $script:LogDirectory "Logs")) {
            Write-BootstrapLog "Log directory missing and could not be created: $script:LogDirectory" "WARN"
            return
        }
    }
    if ($script:logPath -and ((Split-Path -Parent $script:logPath) -ne $script:LogDirectory)) {
        $script:logPath = Join-Path $script:LogDirectory "Teams-Always-Green.log"
    }
    Rotate-LogIfNeeded
    $timestamp = Format-DateTime (Get-Date)
    $displayLevel = $levelKey
    if ($script:LogLevel -eq "DEBUG" -and $levelKey -eq "INFO") {
        $displayLevel = "DEBUG"
    }
    $includeInfoTags = $false
    if ($suppressTags) {
        if ($tagKeyLine) {
            $line = "[${timestamp}] [$displayLevel] [Tag Key] " + ($message.Substring(8).Trim())
        } else {
            $line = "[${timestamp}] [$displayLevel] $message"
        }
    } else {
        $parts = @("[${timestamp}]", "[$displayLevel]")
        if ($script:LogLevel -eq "DEBUG") {
            $parts += "[S=$($script:RunId)]"
            $logType = if ($message -like "UI:*" -or $context -match "Settings|Tray|Profiles|Hotkey-Test") { "UI" } else { "SYS" }
            $parts += "[T=$logType]"
            if ($settingsVar -and $settingsVar.Value -and ($settingsVar.Value.PSObject.Properties.Name -contains "ActiveProfile")) {
                $profileName = [string]$settingsVar.Value.ActiveProfile
                if (-not [string]::IsNullOrWhiteSpace($profileName)) {
                    $parts += "[P=$profileName]"
                }
            }
            if ($context -match "Settings") {
                $tabControlVar = Get-Variable -Name SettingsTabControl -Scope Script -ErrorAction SilentlyContinue
                if ($tabControlVar -and $tabControlVar.Value -and $tabControlVar.Value.SelectedTab) {
                    $parts += "[Tab=$($tabControlVar.Value.SelectedTab.Text)]"
                }
            }
            if ($script:LastUserActionId) {
                $parts += "[E=$($script:LastUserActionId)]"
            }
            if ($script:LogResultOverride) {
                $parts += "[R=$($script:LogResultOverride)]"
                $script:LogResultOverride = $null
            }
        } else {
            if ($includeInfoTags) {
                if ($category -and $category -ne "General") {
                    $parts += "[C=$category]"
                } elseif ($context) {
                    $parts += "[C=$context]"
                }
            }
            if ($script:LogResultOverride) {
                $script:LogResultOverride = $null
            }
        }
        $actionLabel = Get-LastUserActionLabel
        if ($script:LogLevel -eq "DEBUG") {
            if ($actionLabel) {
                if ([bool]$settings.VerboseUiLogging) {
                    $parts += "[Action=$actionLabel]"
                }
                if ($script:LastUserActionId) { $message = "$message (ActionId=$($script:LastUserActionId))" }
            } elseif ($context) {
                $parts += "[C=$context]"
            } elseif ($category) {
                $parts += "[Category=$category]"
            }
        }
        $line = ($parts -join " ") + " " + $message
    }
    $exText = Format-Exception $exception
    if ($exText) { $line += " | $exText" }
    Add-RecentLogLine $line
    if ($levelKey -eq "ERROR") {
        Write-FirstErrorSnapshot $message
    }
    $script:LastLogWriteTime = Get-Date
    [void]$script:LogBuffer.Add($line)
    if ($script:LogBuffer.Count -ge $script:LogBufferMax -or $Force -or $levelKey -eq "ERROR" -or $levelKey -eq "FATAL") {
        try {
            Flush-LogBuffer
        } catch {
            if (-not $script:FallbackLogWarned) {
                $script:FallbackLogWarned = $true
                $fallbackLine = if ($script:LogLevel -eq "DEBUG") {
                    "[${timestamp}] [WARN] [SessionID=$($script:RunId)] [Log-Fallback] Failed to flush log buffer. Writing to fallback log."
                } else {
                    "[${timestamp}] [WARN] [Log-Fallback] Failed to flush log buffer. Writing to fallback log."
                }
                Add-Content -Path $script:FallbackLogPath -Value $fallbackLine
            }
            Add-Content -Path $script:FallbackLogPath -Value $line
        }
    }
    if ($levelKey -eq "FATAL") {
        Dump-RecentLogs $message
    }
    Write-EventLogSafe $line $levelKey
}

# --- Log/settings directory management (validate/repair) ---
function Set-LogDirectory([string]$directory, [switch]$SkipLog) {
    $desired = Convert-FromRelativePath $directory
    $resolved = Resolve-DirectoryOrDefault $directory $defaultLogDir "Logs"
    if (-not $SkipLog -and -not [string]::IsNullOrWhiteSpace($desired)) {
        $desiredNormalized = Normalize-PathText $desired
        if ($resolved -ne $desiredNormalized) {
            Write-Log "Log directory not usable; using $resolved" "WARN" $null "Logging"
        }
    }

    $oldLogPath = $script:logPath
    $oldDir = $script:LogDirectory
    $script:LogDirectory = $resolved
    $script:logPath = Join-Path $script:LogDirectory "Teams-Always-Green.log"
    $script:FallbackLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.fallback.log"
    $script:BootstrapLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.bootstrap.log"
    $script:AuditLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.audit.log"

    if ($oldDir -ne $script:LogDirectory) {
        try {
            $locatorValue = Convert-ToRelativePathIfUnderRoot $script:LogDirectory
            Set-Content -Path $script:LogLocatorPath -Value $locatorValue -Encoding ASCII
        } catch {
            if (-not $SkipLog) {
                Write-Log "Failed to write log locator file." "WARN" $_.Exception "Logging"
            }
        }
    }

    if ($oldLogPath -and $oldLogPath -ne $script:logPath -and (Test-Path $oldLogPath) -and -not (Test-Path $script:logPath)) {
        try {
            Move-Item -Path $oldLogPath -Destination $script:logPath -Force
        } catch {
            if (-not $SkipLog) {
                Write-Log "Failed to move log file to new directory." "WARN" $_.Exception "Logging"
            }
        }
    }

    if (-not $SkipLog -and $oldDir -ne $script:LogDirectory) {
        Write-Log "Log directory set to $($script:LogDirectory)" "INFO" $null "Logging"
    }
}

function Set-SettingsDirectory([string]$directory, [switch]$SkipLog) {
    $desired = Convert-FromRelativePath $directory
    $resolved = Resolve-DirectoryOrDefault $directory $defaultSettingsDir "Settings"
    if (-not $SkipLog -and -not [string]::IsNullOrWhiteSpace($desired)) {
        $desiredNormalized = Normalize-PathText $desired
        if ($resolved -ne $desiredNormalized) {
            Write-Log "Settings directory not usable; using $resolved" "WARN" $null "Settings"
        }
    }

    $oldSettingsPath = $script:settingsPath
    $oldStatePath = $script:StatePath
    $oldProfilesLastGoodPath = $script:ProfilesLastGoodPath
    $oldDir = $script:SettingsDirectory
    $script:SettingsDirectory = $resolved
    $script:settingsPath = Join-Path $script:SettingsDirectory "Teams-Always-Green.settings.json"
    $script:StatePath = Join-Path $script:SettingsDirectory "Teams-Always-Green.state.json"
    $script:ProfilesLastGoodPath = Join-Path $script:SettingsDirectory "Teams-Always-Green.profiles.lastgood.json"

    if ($oldDir -ne $script:SettingsDirectory) {
        try {
            $locatorValue = Convert-ToRelativePathIfUnderRoot $script:SettingsDirectory
            Set-Content -Path $script:SettingsLocatorPath -Value $locatorValue -Encoding ASCII
        } catch {
            if (-not $SkipLog) {
                Write-Log "Failed to write settings locator file." "WARN" $_.Exception "Settings"
            }
        }
    }

    if ($oldSettingsPath -and $oldSettingsPath -ne $script:settingsPath -and (Test-Path $oldSettingsPath) -and -not (Test-Path $script:settingsPath)) {
        try {
            Move-Item -Path $oldSettingsPath -Destination $script:settingsPath -Force
        } catch {
            if (-not $SkipLog) {
                Write-Log "Failed to move settings file to new directory." "WARN" $_.Exception "Settings"
            }
        }
    }
    if ($oldStatePath -and $oldStatePath -ne $script:StatePath -and (Test-Path $oldStatePath) -and -not (Test-Path $script:StatePath)) {
        try {
            Move-Item -Path $oldStatePath -Destination $script:StatePath -Force
        } catch {
            if (-not $SkipLog) {
                Write-Log "Failed to move state file to new directory." "WARN" $_.Exception "Settings"
            }
        }
    }
    if ($oldProfilesLastGoodPath -and $oldProfilesLastGoodPath -ne $script:ProfilesLastGoodPath -and (Test-Path $oldProfilesLastGoodPath) -and -not (Test-Path $script:ProfilesLastGoodPath)) {
        try {
            Move-Item -Path $oldProfilesLastGoodPath -Destination $script:ProfilesLastGoodPath -Force
        } catch {
            if (-not $SkipLog) {
                Write-Log "Failed to move profile last-good file to new directory." "WARN" $_.Exception "Settings"
            }
        }
    }

    if ($oldDir -and $oldDir -ne $script:SettingsDirectory) {
        foreach ($i in 1..3) {
            $oldBak = Join-Path $oldDir ("Teams-Always-Green.settings.json.bak{0}" -f $i)
            $newBak = Join-Path $script:SettingsDirectory ("Teams-Always-Green.settings.json.bak{0}" -f $i)
            if ((Test-Path $oldBak) -and -not (Test-Path $newBak)) {
                try {
                    Move-Item -Path $oldBak -Destination $newBak -Force
                } catch {
                    if (-not $SkipLog) {
                        Write-Log "Failed to move settings backup to new directory." "WARN" $_.Exception "Settings"
                    }
                }
            }
        }
        foreach ($i in 1..3) {
            $oldBak = Join-Path $oldDir ("Teams-Always-Green.state.json.bak{0}" -f $i)
            $newBak = Join-Path $script:SettingsDirectory ("Teams-Always-Green.state.json.bak{0}" -f $i)
            if ((Test-Path $oldBak) -and -not (Test-Path $newBak)) {
                try {
                    Move-Item -Path $oldBak -Destination $newBak -Force
                } catch {
                    if (-not $SkipLog) {
                        Write-Log "Failed to move state backup to new directory." "WARN" $_.Exception "Settings"
                    }
                }
            }
        }
    }

    if (-not $SkipLog -and $oldDir -ne $script:SettingsDirectory) {
        Write-Log "Settings directory set to $($script:SettingsDirectory)" "INFO" $null "Settings"
    }
}


# --- Tray menu + UI dialogs (dot-sourced) ---

# --- Settings load/save and schema migration (read/validate/migrate) ---
function Load-Settings {
    if (-not (Test-Path $settingsPath)) {
        return $null
    }
    try {
        $raw = Get-Content -Path $settingsPath -Raw
        $loaded = $raw | ConvertFrom-Json
        $validation = Test-SettingsSchema $loaded
        $script:SettingsLoadIssues = $validation.Issues
        $script:SettingsFutureVersion = $validation.FutureVersion
        if ($validation.IsCritical) {
            throw ("Settings validation failed: {0}" -f (($validation.Issues | Select-Object -First 6) -join "; "))
        }
        if ($validation.FutureVersion) {
            Write-Log ("Settings schema version {0} is newer than supported {1}. Some fields may be preserved but not editable." -f $validation.SchemaVersion, $script:SettingsSchemaVersion) "WARN" $null "Load-Settings"
        }
        if ($validation.Issues.Count -gt 0) {
            Write-Log ("Settings validation warnings: {0}" -f (($validation.Issues | Select-Object -First 6) -join "; ")) "WARN" $null "Load-Settings"
        }
        $script:SettingsExtraFields = Get-SettingsExtraFields $loaded
        Save-LastGoodSettingsRaw $raw
        $script:SettingsLoadFailed = $false
        $script:SettingsRecovered = $false
        $info = Get-Item -Path $settingsPath -ErrorAction SilentlyContinue
        if ($info) {
            Write-LogThrottled "Settings-Load" ("Settings loaded from {0} (bytes={1} modified={2})" -f $settingsPath, $info.Length, (Format-DateTime $info.LastWriteTime)) "INFO" 60
        } else {
            Write-Log "Settings loaded." "INFO" $null "Settings-Load"
        }
        return $loaded
    } catch {
        $script:SettingsLoadFailed = $true
        Write-Log "Failed to load settings." "ERROR" $_.Exception "Load-Settings"
        try {
            $rawFallback = if (Test-Path $settingsPath) { Get-Content -Path $settingsPath -Raw } else { "" }
            Save-CorruptSettingsCopy $rawFallback
        } catch {
        }
        $lastGood = Load-LastGoodSettings
        if ($lastGood) {
            $validation = Test-SettingsSchema $lastGood
            $script:SettingsLoadIssues = $validation.Issues
            $script:SettingsFutureVersion = $validation.FutureVersion
            $script:SettingsExtraFields = Get-SettingsExtraFields $lastGood
            Write-Log "Recovered settings from last known good snapshot." "WARN" $null "Load-Settings"
            $script:SettingsRecovered = $true
            return $lastGood
        }
        return $null
    }
}

function Rotate-SettingsBackups {
    if (-not (Test-Path $settingsPath)) { return }
    $backupDir = Split-Path -Path $settingsPath -Parent
    for ($i = 3; $i -ge 1; $i--) {
        $src = if ($i -eq 1) { $settingsPath } else { Join-Path $backupDir ("Teams-Always-Green.settings.json.bak{0}" -f ($i - 1)) }
        $dst = Join-Path $backupDir ("Teams-Always-Green.settings.json.bak{0}" -f $i)
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination $dst -Force
        }
    }
    try {
        Get-ChildItem -Path $backupDir -Filter "Teams-Always-Green.settings.json.bak*" -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Name -match "bak(\\d+)$") {
                $num = [int]$Matches[1]
                if ($num -gt 3) {
                    Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                }
            } elseif ($_.Name -match "bak\\.") {
                Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {
    }
}

function Purge-SettingsBackups {
    param([string]$targetDir)
    $backupDir = if (-not [string]::IsNullOrWhiteSpace($targetDir)) { $targetDir } elseif ($settingsPath) { Split-Path -Path $settingsPath -Parent } else { return }
    $deleted = 0
    try {
        Get-ChildItem -Path $backupDir -Filter "Teams-Always-Green.settings.json.bak*" -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Name -match "bak([1-3])$") { return }
            Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
            $deleted++
        }
    } catch {
    }
    if ($deleted -gt 0) {
        Write-Log ("Purged {0} old settings backups." -f $deleted) "DEBUG" $null "Settings"
    }
}

function Save-LastGoodStateRaw([string]$rawJson) {
    if ([string]::IsNullOrWhiteSpace($rawJson)) { return }
    try {
        Set-Content -Path $script:StateLastGoodPath -Value $rawJson -Encoding UTF8
    } catch {
    }
}

function Save-CorruptStateCopy([string]$rawJson) {
    if ([string]::IsNullOrWhiteSpace($rawJson)) { return }
    try {
        Ensure-Directory $script:StateCorruptDir "Corrupt" | Out-Null
        $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
        $target = Join-Path $script:StateCorruptDir ("Teams-Always-Green.state.corrupt.{0}.json" -f $stamp)
        Set-Content -Path $target -Value $rawJson -Encoding UTF8
    } catch {
    }
}

function Load-LastGoodState {
    try {
        if (Test-Path $script:StateLastGoodPath) {
            $raw = Get-Content -Path $script:StateLastGoodPath -Raw
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                return ($raw | ConvertFrom-Json)
            }
        }
    } catch {
    }
    return $null
}

function Normalize-State($state) {
    if (-not $state) { return $state }
    if ($null -eq (Get-SettingsPropertyValue $state "SchemaVersion")) {
        Set-SettingsPropertyValue $state "SchemaVersion" $script:StateSchemaVersion
    }
    if ($null -eq (Get-SettingsPropertyValue $state "SettingsHash")) {
        Set-SettingsPropertyValue $state "SettingsHash" $null
    }
    if ($null -eq (Get-SettingsPropertyValue $state "ToggleCount")) {
        Set-SettingsPropertyValue $state "ToggleCount" 0
    }
    if (-not ($state.PSObject.Properties.Name -contains "LastToggleTime")) {
        Set-SettingsPropertyValue $state "LastToggleTime" $null
    }
    if (-not ($state.PSObject.Properties.Name -contains "Stats")) {
        Set-SettingsPropertyValue $state "Stats" @{}
    }
    $stats = Convert-ToHashtable (Get-SettingsPropertyValue $state "Stats")
    if (-not $stats.ContainsKey("InstallDate")) { $stats["InstallDate"] = (Get-Date).ToString("o") }
    if (-not $stats.ContainsKey("TotalRunMinutes")) { $stats["TotalRunMinutes"] = 0 }
    if (-not $stats.ContainsKey("DailyToggles")) { $stats["DailyToggles"] = @{} }
    if (-not $stats.ContainsKey("HourlyToggles")) { $stats["HourlyToggles"] = @{} }
    if (-not $stats.ContainsKey("LongestPauseMinutes")) { $stats["LongestPauseMinutes"] = 0 }
    if (-not $stats.ContainsKey("LongestPauseAt")) { $stats["LongestPauseAt"] = $null }
    Set-SettingsPropertyValue $state "Stats" $stats
    return $state
}

function Convert-ToHashtable($obj) {
    if ($obj -is [hashtable]) { return $obj }
    if ($obj -is [pscustomobject]) {
        $table = @{}
        foreach ($prop in $obj.PSObject.Properties) {
            $table[$prop.Name] = $prop.Value
        }
        return $table
    }
    return @{}
}

function Load-State {
    if (-not (Test-Path $script:StatePath)) {
        return $null
    }
    try {
        $raw = Get-Content -Path $script:StatePath -Raw
        $loaded = $raw | ConvertFrom-Json
        Save-LastGoodStateRaw $raw
        return (Normalize-State $loaded)
    } catch {
        Write-Log "Failed to load state." "WARN" $_.Exception "Load-State"
        try {
            $rawFallback = if (Test-Path $script:StatePath) { Get-Content -Path $script:StatePath -Raw } else { "" }
            Save-CorruptStateCopy $rawFallback
        } catch {
        }
        $lastGood = Load-LastGoodState
        if ($lastGood) {
            Write-Log "Recovered state from last known good snapshot." "WARN" $null "Load-State"
            return (Normalize-State $lastGood)
        }
        return $null
    }
}

function Rotate-StateBackups {
    if (-not (Test-Path $script:StatePath)) { return }
    $backupDir = Split-Path -Path $script:StatePath -Parent
    for ($i = 3; $i -ge 1; $i--) {
        $src = if ($i -eq 1) { $script:StatePath } else { Join-Path $backupDir ("Teams-Always-Green.state.json.bak{0}" -f ($i - 1)) }
        $dst = Join-Path $backupDir ("Teams-Always-Green.state.json.bak{0}" -f $i)
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination $dst -Force
        }
    }
    try {
        Get-ChildItem -Path $backupDir -Filter "Teams-Always-Green.state.json.bak*" -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Name -match "bak(\\d+)$") {
                $num = [int]$Matches[1]
                if ($num -gt 3) {
                    Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                }
            }
        }
    } catch {
        Write-Log "Ignored error in catch block." "DEBUG" $_.Exception "Catch"
    }
}

function Get-StateSnapshot($state) {
    $snapshot = @{}
    foreach ($prop in $state.PSObject.Properties) {
        $value = $prop.Value
        $snapshot[$prop.Name] = if ($null -eq $value) { "<null>" } else { [string]$value }
    }
    return $snapshot
}

function Get-StateSnapshotHash($snapshot) {
    $pairs = $snapshot.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }
    return ($pairs -join "|")
}

function Apply-StateToSettings($settings, $state) {
    if (-not $settings -or -not $state) { return }
    if ($state.PSObject.Properties.Name -contains "ToggleCount") {
        Set-SettingsPropertyValue $settings "ToggleCount" ([int]$state.ToggleCount)
    }
    if ($state.PSObject.Properties.Name -contains "LastToggleTime") {
        Set-SettingsPropertyValue $settings "LastToggleTime" $state.LastToggleTime
    }
    if ($state.PSObject.Properties.Name -contains "Stats") {
        Set-SettingsPropertyValue $settings "Stats" $state.Stats
    }
}

function Sync-StateFromSettings($settings) {
    if (-not $settings) { return }
    if (-not $script:AppState) { $script:AppState = [pscustomobject]@{} }
    if ($settings.PSObject.Properties.Name -contains "ToggleCount") {
        $script:AppState.ToggleCount = [int]$settings.ToggleCount
    }
    if ($settings.PSObject.Properties.Name -contains "LastToggleTime") {
        $script:AppState.LastToggleTime = $settings.LastToggleTime
    }
    if ($settings.PSObject.Properties.Name -contains "Stats") {
        $script:AppState.Stats = Convert-ToHashtable $settings.Stats
    }
    $script:AppState = Normalize-State $script:AppState
}

function Save-StateImmediate($state) {
    if (-not $state) { return }
    try {
        if (-not (Test-Path $script:SettingsDirectory)) {
            Ensure-Directory $script:SettingsDirectory "Settings" | Out-Null
        }
        if (-not (Test-DirectoryWritable $script:SettingsDirectory)) {
            return
        }
        if (-not $script:StatePath) {
            $script:StatePath = Join-Path $script:SettingsDirectory "Teams-Always-Green.state.json"
        }
        Rotate-StateBackups
        $normalized = Normalize-State $state
        $snapshot = Get-StateSnapshot $normalized
        $hash = Get-StateSnapshotHash $snapshot
        if ($script:LastStateSnapshotHash -and $script:LastStateSnapshotHash -eq $hash) {
            return
        }
        $stateJson = $normalized | ConvertTo-Json -Depth 6
        $tempStatePath = Join-Path $script:SettingsDirectory ("Teams-Always-Green.state.json.tmp.{0}" -f ([Guid]::NewGuid().ToString("N")))
        $stateJson | Set-Content -Path $tempStatePath -Encoding UTF8
        try {
            Move-Item -Path $tempStatePath -Destination $script:StatePath -Force
        } catch {
            Copy-Item -Path $tempStatePath -Destination $script:StatePath -Force
            try { Remove-Item -Path $tempStatePath -Force -ErrorAction SilentlyContinue } catch { }
        }
        Save-LastGoodStateRaw $stateJson
        $script:LastStateSnapshot = $snapshot
        $script:LastStateSnapshotHash = $hash
    } catch {
        Write-Log "Failed to save state." "WARN" $_.Exception "Save-State"
    }
}

function Save-State($state) {
    Save-StateImmediate $state
}

function Get-SettingsForSave($settings) {
    if (-not $settings) { return $null }
    $copy = Copy-SettingsValue $settings
    foreach ($key in $script:SettingsRuntimeKeys) {
        if ($copy.PSObject.Properties.Name -contains $key) {
            $copy.PSObject.Properties.Remove($key)
        }
    }
    if ($script:SettingsExtraFields -and $script:SettingsExtraFields.Count -gt 0) {
        foreach ($key in $script:SettingsExtraFields.Keys) {
            if (-not ($copy.PSObject.Properties.Name -contains $key)) {
                $copy | Add-Member -MemberType NoteProperty -Name $key -Value $script:SettingsExtraFields[$key] -Force
            }
        }
    }
    $copy | Add-Member -MemberType NoteProperty -Name "AppVersion" -Value $appVersion -Force
    $copy | Add-Member -MemberType NoteProperty -Name "LastSaved" -Value (Get-Date).ToString("o") -Force
    $copy | Add-Member -MemberType NoteProperty -Name "LastSavedBy" -Value $env:USERNAME -Force
    $copy | Add-Member -MemberType NoteProperty -Name "SettingsOrigin" -Value "Teams-Always-Green" -Force
    $ordered = [ordered]@{}
    foreach ($name in ($copy.PSObject.Properties.Name | Sort-Object)) {
        $ordered[$name] = $copy.$name
    }
    return [pscustomobject]$ordered
}

function Get-SettingsPropertyValue($settings, [string]$name) {
    if (-not $settings) { return $null }
    if ($settings -is [hashtable]) {
        if ($settings.ContainsKey($name)) { return $settings[$name] }
        return $null
    }
    if ($settings.PSObject.Properties.Name -contains $name) { return $settings.$name }
    return $null
}

function Set-SettingsPropertyValue($settings, [string]$name, $value) {
    if (-not $settings) { return }
    if ($settings -is [hashtable]) {
        $settings[$name] = $value
        return
    }
    if ($settings.PSObject.Properties.Name -contains $name) {
        $settings.$name = $value
        return
    }
    $settings | Add-Member -MemberType NoteProperty -Name $name -Value $value -Force
}

function Sync-SettingsReference($settings) {
    if (-not $settings) { return }
    $script:settings = $settings
    $script:Settings = $settings
    try {
        Set-Variable -Name settings -Scope Script -Value $settings -Force
    } catch {
    }
}

function Copy-SettingsValue($value) {
    if ($null -eq $value) { return $null }
    if ($value -is [hashtable]) {
        $copy = @{}
        foreach ($key in $value.Keys) {
            $copy[$key] = Copy-SettingsValue $value[$key]
        }
        return $copy
    }
    if ($value -is [System.Collections.IDictionary]) {
        $copy = @{}
        foreach ($key in $value.Keys) {
            $copy[$key] = Copy-SettingsValue $value[$key]
        }
        return $copy
    }
    if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
        $items = @()
        foreach ($item in $value) {
            $items += (Copy-SettingsValue $item)
        }
        return $items
    }
    if ($value -is [pscustomobject]) {
        try {
            return ($value | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
        } catch {
            return $value
        }
    }
    return $value
}

function Get-ObjectKeys($obj) {
    if ($obj -is [hashtable]) { return @($obj.Keys) }
    if ($obj -is [pscustomobject]) { return @($obj.PSObject.Properties.Name) }
    return @()
}

function Get-ObjectValue($obj, [string]$name) {
    if (-not $obj) { return $null }
    if ($obj -is [hashtable]) { return $obj[$name] }
    if ($obj -is [pscustomobject]) {
        if ($obj.PSObject.Properties.Name -contains $name) { return $obj.$name }
        return $null
    }
    return $null
}

function Ensure-SettingsCollections($settings) {
    if (-not $settings) { return $settings }
    if ($settings.PSObject.Properties.Name -contains "Profiles") {
        if ($settings.Profiles -isnot [hashtable]) { $settings.Profiles = Convert-ToHashtable $settings.Profiles }
    }
    if (-not ($settings.Profiles -is [hashtable])) { $settings.Profiles = @{} }

    if ($settings.PSObject.Properties.Name -contains "LogCategories") {
        if ($settings.LogCategories -isnot [hashtable]) { $settings.LogCategories = Convert-ToHashtable $settings.LogCategories }
    }
    if (-not ($settings.LogCategories -is [hashtable])) { $settings.LogCategories = @{} }

    if ($settings.PSObject.Properties.Name -contains "LogEventLevels") {
        if ($settings.LogEventLevels -isnot [hashtable]) { $settings.LogEventLevels = Convert-ToHashtable $settings.LogEventLevels }
    }
    if (-not ($settings.LogEventLevels -is [hashtable])) { $settings.LogEventLevels = @{} }
    return $settings
}

# --- Settings UI state helpers (dirty tracking) ---
function Set-SettingsDirty([bool]$value) {
    if ($script:SetDirty -is [scriptblock]) {
        & $script:SetDirty $value
    }
}

function Show-SettingsSaveToast([string]$message = "Settings saved") {
    if (-not $script:SettingsSaveLabel) { return }
    if (-not $script:SettingsForm -or $script:SettingsForm.IsDisposed) { return }
    if (-not $script:SettingsForm.Visible) { return }
    $script:SettingsSaveLabel.Text = $message
    $script:SettingsSaveLabel.Visible = $true
    if (-not $script:SettingsSaveTimer) {
        $script:SettingsSaveTimer = New-Object System.Windows.Forms.Timer
        $script:SettingsSaveTimer.Interval = 2000
        $script:SettingsSaveTimer.Add_Tick({
            Invoke-SafeTimerAction "SettingsSaveTimer" {
                if ($script:SettingsSaveLabel) { $script:SettingsSaveLabel.Visible = $false }
                if ($script:SettingsSaveTimer) { $script:SettingsSaveTimer.Stop() }
            }
        })
    }
    $script:SettingsSaveTimer.Stop()
    $script:SettingsSaveTimer.Start()
}

function Clear-SettingsFieldErrors {
    if ($script:ClearFieldErrors -is [scriptblock]) {
        & $script:ClearFieldErrors
    }
}

function Set-SettingsFieldError([string]$key, [string]$message) {
    if ($script:SetFieldError -is [scriptblock]) {
        return (& $script:SetFieldError $key $message)
    }
    return $message
}

# --- Settings normalization and migration (sanitize defaults) ---
function Normalize-Settings($settings) {
    if (-not $settings) { return $settings }
    $settings.IntervalSeconds = Normalize-IntervalSeconds ([int]$settings.IntervalSeconds)
    if ([string]::IsNullOrWhiteSpace([string]$settings.ThemeMode)) { Set-SettingsPropertyValue $settings "ThemeMode" "Auto" }
    if ([string]::IsNullOrWhiteSpace([string]$settings.TooltipStyle)) { Set-SettingsPropertyValue $settings "TooltipStyle" "Standard" }
    if (-not ($settings.PSObject.Properties.Name -contains "FontSize")) { Set-SettingsPropertyValue $settings "FontSize" 12 }
    if (-not ($settings.PSObject.Properties.Name -contains "SettingsFontSize")) { Set-SettingsPropertyValue $settings "SettingsFontSize" 12 }
    if (-not ($settings.PSObject.Properties.Name -contains "LogDirectory")) { Set-SettingsPropertyValue $settings "LogDirectory" "" }
    if (-not ($settings.PSObject.Properties.Name -contains "SettingsDirectory")) { Set-SettingsPropertyValue $settings "SettingsDirectory" "" }
    if (-not ($settings.PSObject.Properties.Name -contains "DataRoot")) { Set-SettingsPropertyValue $settings "DataRoot" $script:DataRoot }
    if ([string]::IsNullOrWhiteSpace([string]$settings.DataRoot)) { $settings.DataRoot = $script:DataRoot }
    if (-not ($settings.PSObject.Properties.Name -contains "AllowExternalPaths")) { Set-SettingsPropertyValue $settings "AllowExternalPaths" $false }
    $allowExternal = [bool]$settings.AllowExternalPaths
    $settings.SettingsDirectory = Sanitize-DirectorySetting ([string]$settings.SettingsDirectory) $script:FolderNames.Settings "Settings" $allowExternal
    $settings.LogDirectory = Sanitize-DirectorySetting ([string]$settings.LogDirectory) $script:FolderNames.Logs "Logs" $allowExternal
    if (-not ($settings.PSObject.Properties.Name -contains "DateTimeFormat")) { Set-SettingsPropertyValue $settings "DateTimeFormat" $script:DateTimeFormatDefault }
    if (-not ($settings.PSObject.Properties.Name -contains "UseSystemDateTimeFormat")) { Set-SettingsPropertyValue $settings "UseSystemDateTimeFormat" $true }
    if (-not ($settings.PSObject.Properties.Name -contains "SystemDateTimeFormatMode")) { Set-SettingsPropertyValue $settings "SystemDateTimeFormatMode" "Short" }
    $settings.DateTimeFormat = Normalize-DateTimeFormat ([string]$settings.DateTimeFormat)
    if ([string]::IsNullOrWhiteSpace([string]$settings.SystemDateTimeFormatMode)) { $settings.SystemDateTimeFormatMode = "Short" }
    if (-not ($settings.PSObject.Properties.Name -contains "ToggleCount")) { Set-SettingsPropertyValue $settings "ToggleCount" 0 }
    if (-not ($settings.PSObject.Properties.Name -contains "LastToggleTime")) { Set-SettingsPropertyValue $settings "LastToggleTime" $null }
    if (-not ($settings.PSObject.Properties.Name -contains "Stats")) { Set-SettingsPropertyValue $settings "Stats" @{} }
    if (-not ($settings.PSObject.Properties.Name -contains "OpenSettingsAtLastTab")) { Set-SettingsPropertyValue $settings "OpenSettingsAtLastTab" $false }
    if (-not ($settings.PSObject.Properties.Name -contains "LastSettingsTab")) { Set-SettingsPropertyValue $settings "LastSettingsTab" "General" }
    if ([string]::IsNullOrWhiteSpace([string]$settings.LogLevel)) { Set-SettingsPropertyValue $settings "LogLevel" "INFO" }
    $upperLogLevel = ([string]$settings.LogLevel).ToUpperInvariant()
    if (-not $script:LogLevels.ContainsKey($upperLogLevel)) { Set-SettingsPropertyValue $settings "LogLevel" "INFO" }
    if (-not ($settings.PSObject.Properties.Name -contains "LogRetentionDays")) { Set-SettingsPropertyValue $settings "LogRetentionDays" 14 }
    try {
        $settings.LogRetentionDays = [int]$settings.LogRetentionDays
    } catch {
        $settings.LogRetentionDays = 14
    }
    if ($settings.LogRetentionDays -lt 0) { $settings.LogRetentionDays = 0 }
    if ($settings.LogRetentionDays -gt 365) { $settings.LogRetentionDays = 365 }
    try {
        $settings.LogMaxBytes = [int]$settings.LogMaxBytes
    } catch {
        $settings.LogMaxBytes = 1048576
    }
    if ($settings.LogMaxBytes -lt 65536) { $settings.LogMaxBytes = 65536 }
    if (-not ($settings.PSObject.Properties.Name -contains "LogMaxTotalBytes")) { Set-SettingsPropertyValue $settings "LogMaxTotalBytes" 20971520 }
    try {
        $settings.LogMaxTotalBytes = [long]$settings.LogMaxTotalBytes
    } catch {
        $settings.LogMaxTotalBytes = 20971520
    }
    $minTotal = [Math]::Max([long]$settings.LogMaxBytes, 1048576)
    if ($settings.LogMaxTotalBytes -lt $minTotal) { $settings.LogMaxTotalBytes = $minTotal }
    if ($settings.LogMaxTotalBytes -gt 1073741824) { $settings.LogMaxTotalBytes = 1073741824 }
    if ([string]::IsNullOrWhiteSpace([string]$settings.LogDirectory)) { $settings.LogDirectory = "" }
    if ([string]::IsNullOrWhiteSpace([string]$settings.SettingsDirectory)) { $settings.SettingsDirectory = "" }
    if ($settings.FontSize -lt 8) { $settings.FontSize = 8 }
    if ($settings.FontSize -gt 24) { $settings.FontSize = 24 }
    if ($settings.SettingsFontSize -lt 8) { $settings.SettingsFontSize = 8 }
    if ($settings.SettingsFontSize -gt 24) { $settings.SettingsFontSize = 24 }
    if (-not ($settings.PSObject.Properties.Name -contains "HistoryView")) {
        Set-SettingsPropertyValue $settings "HistoryView" @{
            Filter = "All"
            Search = ""
            AutoRefresh = $true
            SortColumn = 0
            SortAsc = $true
            Columns = @("Time", "Result", "Source", "Message")
            MaxRows = 200
        }
    } else {
        $historyView = $settings.HistoryView
        if ($historyView -isnot [hashtable]) { $historyView = Convert-ToHashtable $historyView }
        if (-not $historyView.ContainsKey("Filter")) { $historyView["Filter"] = "All" }
        if (-not $historyView.ContainsKey("Search")) { $historyView["Search"] = "" }
        if (-not $historyView.ContainsKey("AutoRefresh")) { $historyView["AutoRefresh"] = $true }
        if (-not $historyView.ContainsKey("SortColumn")) { $historyView["SortColumn"] = 0 }
        if (-not $historyView.ContainsKey("SortAsc")) { $historyView["SortAsc"] = $true }
        if (-not $historyView.ContainsKey("Columns")) { $historyView["Columns"] = @("Time", "Result", "Source", "Message") }
        if (-not $historyView.ContainsKey("MaxRows")) { $historyView["MaxRows"] = 200 }
        if (-not $historyView.ContainsKey("RelativeTime")) { $historyView["RelativeTime"] = $false }
        if (-not $historyView.ContainsKey("PinFilters")) { $historyView["PinFilters"] = $false }
        if (-not $historyView.ContainsKey("WrapMessages")) { $historyView["WrapMessages"] = $true }
        if (-not $historyView.ContainsKey("SourceFilter")) { $historyView["SourceFilter"] = "All" }
        if (-not $historyView.ContainsKey("WindowState")) { $historyView["WindowState"] = "" }
        if (-not $historyView.ContainsKey("WindowBounds")) { $historyView["WindowBounds"] = $null }
        Set-SettingsPropertyValue $settings "HistoryView" $historyView
    }
    if ($null -eq (Get-SettingsPropertyValue $settings "SchemaVersion")) {
        Set-SettingsPropertyValue $settings "SchemaVersion" $script:SettingsSchemaVersion
    }
    return $settings
}

function Validate-SettingsForSave($settings) {
    $issues = @()
    if (-not $settings) { return @{ Settings = $settings; Issues = $issues } }
    if (-not ($settings.PSObject.Properties.Name -contains "AllowExternalPaths")) { $settings.AllowExternalPaths = $false }
    $allowExternal = [bool]$settings.AllowExternalPaths
    if ($settings.PSObject.Properties.Name -contains "DataRoot") {
        if ([string]::IsNullOrWhiteSpace([string]$settings.DataRoot) -or ([string]$settings.DataRoot -ne $script:DataRoot)) {
            $issues += "DataRoot invalid; reset to app folder"
            $settings.DataRoot = $script:DataRoot
        }
    } else {
        $settings | Add-Member -MemberType NoteProperty -Name "DataRoot" -Value $script:DataRoot -Force
    }
    if (-not $allowExternal) {
        if (-not [string]::IsNullOrWhiteSpace([string]$settings.LogDirectory)) {
            $resolvedLog = Convert-FromRelativePath ([string]$settings.LogDirectory)
            if (-not (Is-PathUnderRoot $resolvedLog $script:DataRoot)) {
                $issues += "LogDirectory outside app folder; reset to default"
                $settings.LogDirectory = ""
            }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$settings.SettingsDirectory)) {
            $resolvedSettings = Convert-FromRelativePath ([string]$settings.SettingsDirectory)
            if (-not (Is-PathUnderRoot $resolvedSettings $script:DataRoot)) {
                $issues += "SettingsDirectory outside app folder; reset to default"
                $settings.SettingsDirectory = ""
            }
        }
    }
    if ($settings.PSObject.Properties.Name -contains "UiLanguage") {
        $allowedLangs = @("auto") + @($script:UiStrings.Keys)
        $requested = ([string]$settings.UiLanguage).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($requested) -or -not ($allowedLangs -contains $requested)) {
            $issues += "UiLanguage invalid; reset to auto"
            $settings.UiLanguage = "auto"
        }
    }
    if ($settings.PSObject.Properties.Name -contains "ThemeMode") {
        $allowedThemes = @("Auto", "Light", "Dark", "HighContrast")
        if (-not ($allowedThemes -contains [string]$settings.ThemeMode)) {
            $issues += "ThemeMode invalid; reset to Auto"
            $settings.ThemeMode = "Auto"
        }
    }
    if ($settings.PSObject.Properties.Name -contains "TooltipStyle") {
        $allowedStyles = @("Standard", "Minimal", "Verbose")
        if (-not ($allowedStyles -contains [string]$settings.TooltipStyle)) {
            $issues += "TooltipStyle invalid; reset to Standard"
            $settings.TooltipStyle = "Standard"
        }
    }
    if ($settings.PSObject.Properties.Name -contains "SystemDateTimeFormatMode") {
        $allowedDateModes = @("Short", "Long")
        if (-not ($allowedDateModes -contains [string]$settings.SystemDateTimeFormatMode)) {
            $issues += "SystemDateTimeFormatMode invalid; reset to Short"
            $settings.SystemDateTimeFormatMode = "Short"
        }
    }
    if ($settings.PSObject.Properties.Name -contains "LogLevel") {
        $upper = ([string]$settings.LogLevel).ToUpperInvariant()
        if (-not $script:LogLevels.ContainsKey($upper)) {
            $issues += "LogLevel invalid; reset to INFO"
            $settings.LogLevel = "INFO"
        } else {
            $settings.LogLevel = $upper
        }
    }
    if ($settings.PSObject.Properties.Name -contains "PauseDurationsMinutes") {
        $durations = @()
        foreach ($part in ([string]$settings.PauseDurationsMinutes -split ",")) {
            $value = 0
            if ([int]::TryParse($part.Trim(), [ref]$value)) {
                if ($value -gt 0 -and $value -le 1440) { $durations += $value }
            }
        }
        if ($durations.Count -eq 0) {
            $issues += "PauseDurationsMinutes invalid; reset to defaults"
            $durations = @(5, 15, 30)
        }
        $settings.PauseDurationsMinutes = ($durations | Sort-Object -Unique) -join ","
    }
    if ($settings.PSObject.Properties.Name -contains "ScheduleWeekdays") {
        $validDays = @("Mon","Tue","Wed","Thu","Fri","Sat","Sun")
        $days = @()
        foreach ($part in ([string]$settings.ScheduleWeekdays -split ",")) {
            $day = $part.Trim()
            if ($validDays -contains $day) { $days += $day }
        }
        if ($days.Count -eq 0) {
            $issues += "ScheduleWeekdays invalid; reset to defaults"
            $days = @("Mon","Tue","Wed","Thu","Fri")
        }
        $settings.ScheduleWeekdays = ($days | Select-Object -Unique) -join ","
    }
    if ($settings.IntervalSeconds -lt 5) {
        $issues += "IntervalSeconds too low; clamped to 5"
        $settings.IntervalSeconds = 5
    }
    if ($settings.IntervalSeconds -gt 3600) {
        $issues += "IntervalSeconds too high; clamped to 3600"
        $settings.IntervalSeconds = 3600
    }
    if ($settings.LogRetentionDays -lt 1) {
        $issues += "LogRetentionDays too low; clamped to 1"
        $settings.LogRetentionDays = 1
    }
    if ($settings.LogMaxBytes -lt 65536) {
        $issues += "LogMaxBytes too low; clamped to 65536"
        $settings.LogMaxBytes = 65536
    }
    if ($settings.PSObject.Properties.Name -contains "LogMaxTotalBytes") {
        $minTotal = [Math]::Max([long]$settings.LogMaxBytes, 1048576)
        if ($settings.LogMaxTotalBytes -lt $minTotal) {
            $issues += "LogMaxTotalBytes too low; clamped to $minTotal"
            $settings.LogMaxTotalBytes = $minTotal
        }
    }
    if ([bool]$settings.ScheduleEnabled) {
        $tmp = [TimeSpan]::Zero
        if (-not (Try-ParseTime $settings.ScheduleStart ([ref]$tmp))) {
            $issues += "ScheduleStart invalid; schedule disabled"
            $settings.ScheduleEnabled = $false
        }
        if (-not (Try-ParseTime $settings.ScheduleEnd ([ref]$tmp))) {
            $issues += "ScheduleEnd invalid; schedule disabled"
            $settings.ScheduleEnabled = $false
        }
    }
    return @{ Settings = $settings; Issues = $issues }
}

function Migrate-Settings($settings) {
    if (-not $settings) { return $settings }
    $current = 1
    $schemaValue = Get-SettingsPropertyValue $settings "SchemaVersion"
    if ($null -ne $schemaValue) { $current = [int]$schemaValue }
    if ($current -lt 2) {
        if (-not ($settings.PSObject.Properties.Name -contains "TooltipStyle")) {
            Set-SettingsPropertyValue $settings "TooltipStyle" (if ([bool]$settings.MinimalTrayTooltip) { "Minimal" } else { "Standard" })
        }
        if (-not ($settings.PSObject.Properties.Name -contains "FontSize")) { Set-SettingsPropertyValue $settings "FontSize" 12 }
        if (-not ($settings.PSObject.Properties.Name -contains "SettingsFontSize")) { Set-SettingsPropertyValue $settings "SettingsFontSize" 12 }
        if (-not ($settings.PSObject.Properties.Name -contains "LogDirectory")) { Set-SettingsPropertyValue $settings "LogDirectory" "" }
        if (-not ($settings.PSObject.Properties.Name -contains "SettingsDirectory")) { Set-SettingsPropertyValue $settings "SettingsDirectory" "" }
        $current = 2
    }
    if ($current -lt 3) {
        if (-not ($settings.PSObject.Properties.Name -contains "OpenSettingsAtLastTab")) { Set-SettingsPropertyValue $settings "OpenSettingsAtLastTab" $false }
        if (-not ($settings.PSObject.Properties.Name -contains "LastSettingsTab")) { Set-SettingsPropertyValue $settings "LastSettingsTab" "General" }
        $current = 3
    }
    if ($current -lt 4) {
        if (-not ($settings.PSObject.Properties.Name -contains "DateTimeFormat")) { Set-SettingsPropertyValue $settings "DateTimeFormat" $script:DateTimeFormatDefault }
        $current = 4
    }
    if ($current -lt 5) {
        if (-not ($settings.PSObject.Properties.Name -contains "UseSystemDateTimeFormat")) { Set-SettingsPropertyValue $settings "UseSystemDateTimeFormat" $true }
        if (-not ($settings.PSObject.Properties.Name -contains "SystemDateTimeFormatMode")) { Set-SettingsPropertyValue $settings "SystemDateTimeFormatMode" "Short" }
        $current = 5
    }
    if ($current -lt 6) {
        if (-not ($settings.PSObject.Properties.Name -contains "DataRoot")) { Set-SettingsPropertyValue $settings "DataRoot" $script:DataRoot }
        $current = 6
    }
    if ($current -lt 7) {
        $current = 7
    }
    if ($current -lt 8) {
        if (-not ($settings.PSObject.Properties.Name -contains "AllowExternalPaths")) {
            Set-SettingsPropertyValue $settings "AllowExternalPaths" $false
        }
        $current = 8
    }
    Set-SettingsPropertyValue $settings "SchemaVersion" $current
    return $settings
}

function Save-SettingsImmediate($settings) {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    if ($script:SettingsSaveInProgress) {
        Write-LogThrottled "Settings-SaveInProgress" "Settings save already in progress; skipping." "WARN" 5
        return
    }
    $script:SettingsSaveInProgress = $true
    try {
        Sync-ActiveProfileSnapshot $settings
        $settings = Migrate-Settings $settings
        $validation = Validate-SettingsForSave $settings
        $settings = $validation.Settings
        if ($validation.Issues.Count -gt 0) {
            Write-Log ("Settings validation: " + ($validation.Issues -join "; ")) "WARN" $null "Settings-Validate"
        }
        $settings = Normalize-Settings $settings
        Sync-StateFromSettings $settings
        if ($script:SettingsFutureVersion) {
            Write-LogThrottled "Settings-FutureVersion" ("Settings schema is newer than supported; preserving unknown fields where possible.") "WARN" 600
        }
        $newSnapshot = Get-SettingsSnapshot $settings
        $newHash = Get-SettingsSnapshotHash $newSnapshot
        if ($script:LastSettingsSnapshotHash -and $script:LastSettingsSnapshotHash -eq $newHash) {
            $stopwatch.Stop()
            Save-StateImmediate $script:AppState
            Write-Log "UI: Settings unchanged; skip save." "DEBUG" $null "Settings-Save"
            $script:LastSettingsSaveOk = $true
            $script:LastSettingsSaveMessage = ""
            return
        }
        $changedKeys = @()
        if ($script:LastSettingsSnapshot) {
            $allKeys = @($script:LastSettingsSnapshot.Keys + $newSnapshot.Keys) | Sort-Object -Unique
            foreach ($key in $allKeys) {
                $oldVal = if ($script:LastSettingsSnapshot.ContainsKey($key)) { $script:LastSettingsSnapshot[$key] } else { "<missing>" }
                $newVal = if ($newSnapshot.ContainsKey($key)) { $newSnapshot[$key] } else { "<missing>" }
                if ($oldVal -ne $newVal) { $changedKeys += $key }
            }
        }
        if (-not (Test-Path $script:SettingsDirectory)) {
            Ensure-Directory $script:SettingsDirectory "Settings" | Out-Null
        }
        if (-not (Test-DirectoryWritable $script:SettingsDirectory)) {
            Write-Log "Settings directory not writable; falling back to default Settings folder." "WARN" $null "Settings-Save"
            $fallbackSettingsDir = Join-Path $script:DataRoot $script:FolderNames.Settings
            $script:SettingsDirectory = Resolve-DirectoryOrDefault $fallbackSettingsDir $fallbackSettingsDir "Settings"
        }
        $script:settingsPath = Join-Path $script:SettingsDirectory "Teams-Always-Green.settings.json"
        $script:StatePath = Join-Path $script:SettingsDirectory "Teams-Always-Green.state.json"
        Rotate-SettingsBackups
        $settingsToSave = Get-SettingsForSave $settings
        $settingsJson = $settingsToSave | ConvertTo-Json -Depth 6
        $tempSettingsPath = Join-Path $script:SettingsDirectory ("Teams-Always-Green.settings.json.tmp.{0}" -f ([Guid]::NewGuid().ToString("N")))
        try {
            $settingsJson | Set-Content -Path $tempSettingsPath -Encoding UTF8
            try {
                $null = Get-Content -Path $tempSettingsPath -Raw | ConvertFrom-Json -ErrorAction Stop
            } catch {
                throw "Saved settings JSON is not valid."
            }
            try {
                Move-Item -Path $tempSettingsPath -Destination $settingsPath -Force
            } catch {
                Copy-Item -Path $tempSettingsPath -Destination $settingsPath -Force
                try { Remove-Item -Path $tempSettingsPath -Force -ErrorAction SilentlyContinue } catch { }
            }
            Save-LastGoodSettingsRaw $settingsJson
        } catch {
            $fallbackBackup = Join-Path $script:SettingsDirectory "Teams-Always-Green.settings.json.bak1"
            if (Test-Path $fallbackBackup) {
                try { Copy-Item -Path $fallbackBackup -Destination $settingsPath -Force } catch { }
            }
            throw
        }
        if (@($changedKeys).Count -gt 0) {
            $categoryMap = @{
                General     = @("IntervalSeconds", "StartWithWindows", "RememberChoice", "StartOnLaunch", "RunOnceOnLaunch", "QuietMode", "DisableBalloonTips", "OpenSettingsAtLastTab", "LastSettingsTab", "DateTimeFormat", "UseSystemDateTimeFormat", "SystemDateTimeFormatMode", "PauseUntil", "PauseDurationsMinutes", "SettingsDirectory", "DataRoot")
                Appearance  = @("TooltipStyle", "ThemeMode", "FontSize", "SettingsFontSize", "StatusColorRunning", "StatusColorPaused", "StatusColorStopped", "CompactMode", "MinimalTrayTooltip")
                Schedule    = @("ScheduleOverrideEnabled", "ScheduleEnabled", "ScheduleStart", "ScheduleEnd", "ScheduleWeekdays", "ScheduleSuspendUntil")
                Hotkeys     = @("HotkeyToggle", "HotkeyStartStop", "HotkeyPauseResume")
                Logging     = @("LogLevel", "LogMaxBytes", "LogMaxTotalBytes", "LogRetentionDays", "LogIncludeStackTrace", "LogToEventLog", "LogEventLevels", "LogCategories", "LogDirectory")
                Diagnostics = @("ScrubDiagnostics")
                Profiles    = @("ActiveProfile", "Profiles")
            }
            $grouped = @()
            foreach ($category in $categoryMap.Keys) {
                $keys = $changedKeys | Where-Object { $categoryMap[$category] -contains $_ }
                if (@($keys).Count -gt 0) {
                    $grouped += ("{0}[{1}]" -f $category, ($keys | Sort-Object | Select-Object -Unique) -join ",")
                }
            }
            $categorizedKeys = @()
            foreach ($values in $categoryMap.Values) { $categorizedKeys += $values }
            $otherKeys = $changedKeys | Where-Object { $categorizedKeys -notcontains $_ }
            if (@($otherKeys).Count -gt 0) {
                $grouped += ("Other[{0}]" -f (($otherKeys | Sort-Object | Select-Object -Unique) -join ","))
            }
            $script:LastSettingsChangeSummary = ($grouped -join "; ")
            Write-Log ("UI: Settings changed: " + $script:LastSettingsChangeSummary) "DEBUG" $null "Settings-Change"
            $detailParts = @()
            foreach ($key in ($changedKeys | Sort-Object)) {
                $oldVal = if ($script:LastSettingsSnapshot.ContainsKey($key)) { $script:LastSettingsSnapshot[$key] } else { "<missing>" }
                $newVal = if ($newSnapshot.ContainsKey($key)) { $newSnapshot[$key] } else { "<missing>" }
                $detailParts += ("{0}={1} -> {2}" -f $key, $oldVal, $newVal)
            }
            if ($detailParts.Count -gt 0) {
                $script:LastSettingsChangeDetail = ($detailParts -join "; ")
                Write-Log ("UI: Settings changed detail: " + $script:LastSettingsChangeDetail) "DEBUG" $null "Settings-Change"
            }
        }
        $stopwatch.Stop()
        Write-Log ("UI: Settings saved to {0} (ms={1})" -f $settingsPath, $stopwatch.ElapsedMilliseconds) "DEBUG" $null "Settings-Save"
        Show-SettingsSaveToast
        $script:LastSettingsSnapshot = $newSnapshot
        $script:LastSettingsSnapshotHash = $newHash
        $script:LastSettingsSaveOk = $true
        $script:LastSettingsSaveMessage = ""
        try { Purge-SettingsBackups } catch { }
        try {
            $savedHash = Get-SettingsFileHash
            if ($savedHash) {
                if (-not $script:AppState) { $script:AppState = [pscustomobject]@{} }
                $script:AppState.SettingsHash = $savedHash
            }
        } catch { }
        Sync-SettingsReference $settings
        Save-StateImmediate $script:AppState
    } catch {
        $stopwatch.Stop()
        $script:LastSettingsSaveOk = $false
        $script:LastSettingsSaveMessage = [string]$_.Exception.Message
        Write-Log "Failed to save settings." "ERROR" $_.Exception "Save-Settings"
        if ($script:UpdateLastSavedLabel) { & $script:UpdateLastSavedLabel $null }
    }
    finally {
        $script:SettingsSaveInProgress = $false
    }
}

function Save-Settings($settings, [switch]$Immediate) {
    if ($Immediate) {
        Save-SettingsImmediate $settings
        return
    }
    $script:SaveSettingsPending = $settings
    if ($script:SaveSettingsTimer.Enabled) {
        $script:SaveSettingsTimer.Stop()
    }
    $script:SaveSettingsTimer.Start()
}

function Flush-SettingsSave {
    if ($script:SaveSettingsPending) {
        Save-SettingsImmediate $script:SaveSettingsPending
        $script:SaveSettingsPending = $null
    }
}

function Get-SettingsSnapshot($settings) {
    $snapshot = @{}
    foreach ($prop in $settings.PSObject.Properties) {
        if ($script:SettingsNonDiffKeys -and ($script:SettingsNonDiffKeys -contains $prop.Name)) { continue }
        $value = $prop.Value
        $snapshot[$prop.Name] = if ($null -eq $value) { "<null>" } else { [string]$value }
    }
    return $snapshot
}

function Get-SettingsSnapshotHash($snapshot) {
    $pairs = $snapshot.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }
    return ($pairs -join "|")
}

function Get-SettingsDiff($oldSnapshot, $newSnapshot) {
    $changes = @()
    $allKeys = @($oldSnapshot.Keys + $newSnapshot.Keys) | Sort-Object -Unique
    foreach ($key in $allKeys) {
        $oldVal = if ($oldSnapshot.ContainsKey($key)) { $oldSnapshot[$key] } else { "<missing>" }
        $newVal = if ($newSnapshot.ContainsKey($key)) { $newSnapshot[$key] } else { "<missing>" }
        if ($oldVal -ne $newVal) {
            $changes += "${key}: $oldVal -> $newVal"
        }
    }
    return $changes
}

# --- Profile snapshots and sync (last-good/diff) ---
$script:ProfilePropertyNames = @(
    "IntervalSeconds",
    "RememberChoice",
    "StartOnLaunch",
    "RunOnceOnLaunch",
    "QuietMode",
    "MinimalTrayTooltip",
    "TooltipStyle",
    "DisableBalloonTips",
    "PauseDurationsMinutes",
    "ScheduleOverrideEnabled",
    "ScheduleEnabled",
    "ScheduleStart",
    "ScheduleEnd",
    "ScheduleWeekdays",
    "ScheduleSuspendUntil",
    "SafeModeEnabled",
    "SafeModeFailureThreshold",
    "HotkeyToggle",
    "HotkeyStartStop",
    "HotkeyPauseResume",
    "LogMaxBytes",
    "LogMaxTotalBytes",
    "ThemeMode",
    "FontSize",
    "SettingsFontSize",
    "StatusColorRunning",
    "StatusColorPaused",
    "StatusColorStopped",
    "CompactMode"
)

function Load-ProfilesLastGood {
    $script:ProfilesLastGood = @{}
    if (-not $script:ProfilesLastGoodPath) { return }
    if (-not (Test-Path $script:ProfilesLastGoodPath)) { return }
    try {
        $raw = Get-Content -Path $script:ProfilesLastGoodPath -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) { return }
        $loaded = $raw | ConvertFrom-Json
        if ($loaded -is [pscustomobject]) {
            $table = @{}
            foreach ($prop in $loaded.PSObject.Properties) {
                $table[$prop.Name] = $prop.Value
            }
            $script:ProfilesLastGood = $table
        } elseif ($loaded -is [hashtable]) {
            $script:ProfilesLastGood = $loaded
        }
    } catch {
        Write-Log "Failed to load profile last-good file." "WARN" $_.Exception "Profiles"
    }
}

function Save-ProfilesLastGood {
    if (-not $script:ProfilesLastGoodPath) { return }
    try {
        $json = ($script:ProfilesLastGood | ConvertTo-Json -Depth 6)
        $tmp = Join-Path $script:SettingsDirectory ("Teams-Always-Green.profiles.lastgood.json.tmp.{0}" -f ([Guid]::NewGuid().ToString("N")))
        $json | Set-Content -Path $tmp -Encoding UTF8
        try {
            Move-Item -Path $tmp -Destination $script:ProfilesLastGoodPath -Force
        } catch {
            Copy-Item -Path $tmp -Destination $script:ProfilesLastGoodPath -Force
            try { Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue } catch { }
        }
    } catch {
        Write-Log "Failed to save profile last-good file." "WARN" $_.Exception "Profiles"
    }
}

function Update-ProfileLastGood([string]$name, $snapshot) {
    if ([string]::IsNullOrWhiteSpace($name) -or -not $snapshot) { return }
    if (-not $script:ProfilesLastGood) { $script:ProfilesLastGood = @{} }
    $script:ProfilesLastGood[$name] = $snapshot
    Save-ProfilesLastGood
}

function Remove-ProfileLastGood([string]$name) {
    if (-not $script:ProfilesLastGood) { return }
    if ($script:ProfilesLastGood.ContainsKey($name)) {
        $script:ProfilesLastGood.Remove($name) | Out-Null
        Save-ProfilesLastGood
    }
}

function Get-ProfileLastGood([string]$name) {
    if (-not $script:ProfilesLastGood) { return $null }
    if ($script:ProfilesLastGood.ContainsKey($name)) { return $script:ProfilesLastGood[$name] }
    return $null
}

function Migrate-ProfileSnapshot($profile) {
    if (-not $profile) { return $profile }
    if ($profile -is [hashtable]) {
        if (-not $profile.ContainsKey("ProfileSchemaVersion")) { $profile["ProfileSchemaVersion"] = $script:ProfileSchemaVersion }
        if (-not $profile.ContainsKey("ReadOnly")) { $profile["ReadOnly"] = $false }
        return $profile
    }
    if (-not ($profile.PSObject.Properties.Name -contains "ProfileSchemaVersion")) {
        $profile | Add-Member -MemberType NoteProperty -Name "ProfileSchemaVersion" -Value $script:ProfileSchemaVersion -Force
    }
    if (-not ($profile.PSObject.Properties.Name -contains "ReadOnly")) {
        $profile | Add-Member -MemberType NoteProperty -Name "ReadOnly" -Value $false -Force
    }
    return $profile
}

function Test-ProfileSnapshot($profile) {
    $issues = @()
    if (-not $profile) {
        $issues += "Profile is null."
        return [pscustomobject]@{ IsValid = $false; Issues = $issues }
    }
    if (-not ($profile -is [hashtable] -or $profile -is [pscustomobject])) {
        $issues += "Profile is not an object."
        return [pscustomobject]@{ IsValid = $false; Issues = $issues }
    }
    $required = @("IntervalSeconds", "HotkeyToggle", "HotkeyStartStop", "HotkeyPauseResume")
    foreach ($key in $required) {
        $hasKey = if ($profile -is [hashtable]) { $profile.ContainsKey($key) } else { $profile.PSObject.Properties.Name -contains $key }
        if (-not $hasKey) { $issues += "Missing $key" }
    }
    return [pscustomobject]@{ IsValid = ($issues.Count -eq 0); Issues = $issues }
}

function Get-ProfileReadOnly($profile) {
    if (-not $profile) { return $false }
    if ($profile -is [hashtable]) {
        if ($profile.ContainsKey("ReadOnly")) { return [bool]$profile["ReadOnly"] }
        return $false
    }
    if ($profile.PSObject.Properties.Name -contains "ReadOnly") { return [bool]$profile.ReadOnly }
    return $false
}

function Get-ProfileSnapshotHashFromSettings($source) {
    $pairs = @()
    foreach ($name in $script:ProfilePropertyNames) {
        if ($source.PSObject.Properties.Name -contains $name) {
            $pairs += ("{0}={1}" -f $name, $source.$name)
        }
    }
    try {
        if ($source -and $source.Profiles -and $source.ActiveProfile) {
            $activeName = [string]$source.ActiveProfile
            if (-not [string]::IsNullOrWhiteSpace($activeName) -and (Get-ObjectKeys $source.Profiles) -contains $activeName) {
                $pairs += ("ReadOnly={0}" -f (Get-ProfileReadOnly $source.Profiles[$activeName]))
            }
        }
    } catch { }
    return ($pairs -join "|")
}

function Get-ProfileDiffSummary($currentSettings, $profile, [int]$maxKeys = 10) {
    $current = Get-ProfileSnapshot $currentSettings
    $target = Migrate-ProfileSnapshot $profile
    $changed = @()
    foreach ($name in $script:ProfilePropertyNames) {
        if ($script:ProfileMetadataKeys -contains $name) { continue }
        $oldVal = if ($current.PSObject.Properties.Name -contains $name) { $current.$name } else { "<missing>" }
        $newVal = if ($target -is [hashtable]) { if ($target.ContainsKey($name)) { $target[$name] } else { "<missing>" } } else { if ($target.PSObject.Properties.Name -contains $name) { $target.$name } else { "<missing>" } }
        if ($oldVal -ne $newVal) { $changed += $name }
    }
    $summaryKeys = if ($changed.Count -gt 0) { ($changed | Select-Object -First $maxKeys) -join ", " } else { "" }
    $tail = if ($changed.Count -gt $maxKeys) { " (and $($changed.Count - $maxKeys) more)" } else { "" }
    $summary = if ($changed.Count -eq 0) { "No changes." } else { "Changes ($($changed.Count)): $summaryKeys$tail" }
    return [pscustomobject]@{
        Count = $changed.Count
        Keys = $changed
        Summary = $summary
    }
}

function Confirm-ProfileSwitch([string]$name, $profile) {
    $diff = Get-ProfileDiffSummary $settings $profile
    if ($diff.Count -le 0) { return $true }
    $message = "Switch to profile '$name'?`n$($diff.Summary)"
    $result = [System.Windows.Forms.MessageBox]::Show(
        $message,
        "Confirm Profile Switch",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )
    return ($result -eq [System.Windows.Forms.DialogResult]::Yes)
}

function Get-ProfileSnapshot($source) {
    $cacheKey = Get-ProfileSnapshotHashFromSettings $source
    if ($script:ProfileSnapshotCacheKey -and $script:ProfileSnapshotCacheKey -eq $cacheKey -and $script:ProfileSnapshotCache) {
        return $script:ProfileSnapshotCache
    }
    $readOnly = $false
    try {
        if ($source -and $source.Profiles -and $source.ActiveProfile) {
            $activeName = [string]$source.ActiveProfile
            if (-not [string]::IsNullOrWhiteSpace($activeName) -and (Get-ObjectKeys $source.Profiles) -contains $activeName) {
                $readOnly = Get-ProfileReadOnly $source.Profiles[$activeName]
            }
        }
    } catch { }
    $snapshot = [pscustomobject]@{
        ProfileSchemaVersion = $script:ProfileSchemaVersion
        ReadOnly = $readOnly
    }
    foreach ($name in $script:ProfilePropertyNames) {
        if ($source.PSObject.Properties.Name -contains $name) {
            $snapshot | Add-Member -MemberType NoteProperty -Name $name -Value $source.$name
        }
    }
    $script:ProfileSnapshotCacheKey = $cacheKey
    $script:ProfileSnapshotCache = $snapshot
    return $snapshot
}

function Apply-ProfileSnapshot($target, $profile) {
    $profile = Migrate-ProfileSnapshot $profile
    $validation = Test-ProfileSnapshot $profile
    if (-not $validation.IsValid) {
        $msg = "Profile is invalid: " + (($validation.Issues | Select-Object -First 4) -join ", ")
        Write-Log $msg "WARN" $null "Profiles"
        return $target
    }
    $overrideSchedule = $true
    $hasOverrideFlag = $false
    if ($profile -is [hashtable]) {
        if ($profile.ContainsKey("ScheduleOverrideEnabled")) {
            $overrideSchedule = [bool]$profile["ScheduleOverrideEnabled"]
            $hasOverrideFlag = $true
        }
    } elseif ($profile -and ($profile.PSObject.Properties.Name -contains "ScheduleOverrideEnabled")) {
        $overrideSchedule = [bool]$profile.ScheduleOverrideEnabled
        $hasOverrideFlag = $true
    }
    if (-not $hasOverrideFlag) {
        Set-SettingsPropertyValue $target "ScheduleOverrideEnabled" $overrideSchedule
    }
    foreach ($name in $script:ProfilePropertyNames) {
        if (-not $overrideSchedule -and $name -in @("ScheduleEnabled", "ScheduleStart", "ScheduleEnd", "ScheduleWeekdays", "ScheduleSuspendUntil")) {
            continue
        }
        if ($profile -is [hashtable]) {
            if ($profile.ContainsKey($name)) {
                Set-SettingsPropertyValue $target $name $profile[$name]
            }
        } elseif ($profile.PSObject.Properties.Name -contains $name) {
            Set-SettingsPropertyValue $target $name $profile.$name
        }
    }
    return $target
}

function Sync-ActiveProfileSnapshot($settings) {
    if (-not $settings) { return }
    if (-not ($settings.PSObject.Properties.Name -contains "Profiles")) { return }
    if (-not ($settings.PSObject.Properties.Name -contains "ActiveProfile")) { return }
    if (-not ($settings.Profiles -is [hashtable])) { return }
    $name = [string]$settings.ActiveProfile
    if ([string]::IsNullOrWhiteSpace($name)) { return }
    $settings.Profiles[$name] = Get-ProfileSnapshot $settings
}

# --- Default settings and initial load (first-run) ---
$defaultSettings = [pscustomobject]@{
    SchemaVersion = $script:SettingsSchemaVersion
    IntervalSeconds = 60
    StartWithWindows = $false
    RememberChoice = $true
    StartOnLaunch = $false
    QuietMode = $true
    DisableBalloonTips = $false
    OpenSettingsAtLastTab = $true
    LastSettingsTab = "General"
    DateTimeFormat = $script:DateTimeFormatDefault
    UseSystemDateTimeFormat = $true
    SystemDateTimeFormatMode = "Short"
    ShowFirstRunToast = $true
    FirstRunToastShown = $false
    AutoCorrectedNoticeSeen = $false
    UiLanguage = "auto"
    ToggleCount = 0
    LastToggleTime = $null
    Stats = @{
        InstallDate = (Get-Date).ToString("o")
        TotalRunMinutes = 0
        DailyToggles = @{}
        HourlyToggles = @{}
        LongestPauseMinutes = 0
        LongestPauseAt = $null
    }
    RunOnceOnLaunch = $false
    PauseUntil = $null
    PauseDurationsMinutes = "5,15,30"
    ScheduleOverrideEnabled = $true
    ScheduleEnabled = $false
    ScheduleStart = "08:00"
    ScheduleEnd = "17:00"
    ScheduleWeekdays = "Mon,Tue,Wed,Thu,Fri"
    ScheduleSuspendUntil = $null
    SafeModeEnabled = $true
    SafeModeFailureThreshold = 3
    HotkeyToggle = "Ctrl+Alt+T"
    HotkeyStartStop = "Ctrl+Alt+S"
    HotkeyPauseResume = "Ctrl+Alt+P"
    LogLevel = "INFO"
    LogMaxBytes = 1048576
    LogMaxTotalBytes = 20971520
    LogRetentionDays = 14
    DataRoot = $script:DataRoot
    LogDirectory = $script:FolderNames.Logs
    SettingsDirectory = $script:FolderNames.Settings
    AllowExternalPaths = $false
    AutoUpdateEnabled = $true
    UpdateRequireSignature = $true
    HardenPermissions = $true
    SettingsTamperNoticeSeen = $false
    ActiveProfile = "Default"
    Profiles = @{}
    MinimalTrayTooltip = $false
    TooltipStyle = "Standard"
    FontSize = 8
    SettingsFontSize = 8
    StatusColorRunning = "#00AA00"
    StatusColorPaused = "#B8860B"
    StatusColorStopped = "#CC0000"
    CompactMode = $false
    LogIncludeStackTrace = $false
    LogToEventLog = $false
    LogEventLevels = @{
        ERROR = $true
        FATAL = $true
        WARN  = $false
        INFO  = $false
    }
    VerboseUiLogging = $false
    ScrubDiagnostics = $false
    ThemeMode = "Auto"
    LogCategories = @{
        General = $true
        Startup = $true
        Settings = $true
        Schedule = $true
        Hotkeys = $true
        Tray = $true
        Profiles = $true
        Diagnostics = $true
        Logging = $true
    }
}

$script:DefaultSettingsKeys = @($defaultSettings.PSObject.Properties.Name)

Repair-FromStartupSnapshot $defaultSettings

$script:TabDefaultsMap = @{
    General = @(
        "IntervalSeconds",
        "StartWithWindows",
        "OpenSettingsAtLastTab",
        "RememberChoice",
        "StartOnLaunch",
        "RunOnceOnLaunch",
        "DateTimeFormat",
        "UseSystemDateTimeFormat",
        "SystemDateTimeFormatMode",
        "ShowFirstRunToast"
    )
    Scheduling = @(
        "ScheduleOverrideEnabled",
        "ScheduleEnabled",
        "ScheduleStart",
        "ScheduleEnd",
        "ScheduleWeekdays",
        "ScheduleSuspendUntil",
        "PauseUntil",
        "PauseDurationsMinutes"
    )
    Hotkeys = @(
        "HotkeyToggle",
        "HotkeyStartStop",
        "HotkeyPauseResume"
    )
    Logging = @(
        "LogDirectory",
        "LogMaxBytes",
        "LogMaxTotalBytes",
        "LogRetentionDays"
    )
    Appearance = @(
        "QuietMode",
        "TooltipStyle",
        "DisableBalloonTips",
        "ThemeMode",
        "FontSize",
        "SettingsFontSize",
        "StatusColorRunning",
        "StatusColorPaused",
        "StatusColorStopped",
        "CompactMode"
    )
    Advanced = @(
        "SafeModeEnabled",
        "SafeModeFailureThreshold",
        "LogLevel",
        "LogIncludeStackTrace",
        "LogToEventLog",
        "LogEventLevels",
        "VerboseUiLogging",
        "ScrubDiagnostics",
        "AutoUpdateEnabled"
    )
    Profiles = @(
        "ActiveProfile",
        "Profiles"
    )
}

$settingsLoadedFromFile = $true
$settingsPreJson = $null
$convertToStableObject = {
    param($value)
    if ($null -eq $value) { return $null }
    if ($value -is [hashtable]) {
        $ordered = [ordered]@{}
        foreach ($k in ($value.Keys | Sort-Object)) {
            $ordered[$k] = & $convertToStableObject $value[$k]
        }
        return $ordered
    }
    if ($value -is [pscustomobject]) {
        $ordered = [ordered]@{}
        foreach ($name in ($value.PSObject.Properties.Name | Sort-Object)) {
            $ordered[$name] = & $convertToStableObject $value.$name
        }
        return $ordered
    }
    if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
        $list = @()
        foreach ($item in $value) { $list += & $convertToStableObject $item }
        return $list
    }
    return $value
}
$settings = Load-Settings
if (-not $settings) {
    $settings = $defaultSettings
    $settingsLoadedFromFile = $false
    $script:SettingsExtraFields = @{}
    $script:SettingsFutureVersion = $false
    $script:SettingsLoadIssues = @()
    if ($script:SettingsLoadFailed -and -not $script:SettingsRecovered) {
        Write-Log "Settings corrupted; defaults loaded." "WARN" $null "Load-Settings"
        $settings.SafeModeEnabled = $true
        $script:safeModeActive = $true
        $script:toggleFailCount = [int]$settings.SafeModeFailureThreshold
        Write-Log "Safe Mode forced due to settings recovery failure." "WARN" $null "Load-Settings"
    }
} else {
    try {
        $settingsPreJson = (& $convertToStableObject $settings) | ConvertTo-Json -Depth 8
    } catch {
        $settingsPreJson = $null
    }
    try { Purge-SettingsBackups } catch { }
    $settings = Migrate-Settings $settings
    foreach ($prop in $defaultSettings.PSObject.Properties.Name) {
        if (-not ($settings.PSObject.Properties.Name -contains $prop)) {
            $settings | Add-Member -MemberType NoteProperty -Name $prop -Value $defaultSettings.$prop
        }
    }
    if (-not ($settings.PSObject.Properties.Name -contains "TooltipStyle") -or [string]::IsNullOrWhiteSpace([string]$settings.TooltipStyle)) {
        $settings.TooltipStyle = if ([bool]$settings.MinimalTrayTooltip) { "Minimal" } else { "Standard" }
    }
    if (-not ($settings.PSObject.Properties.Name -contains "FontSize")) {
        $settings.FontSize = $defaultSettings.FontSize
    }
    if (-not ($settings.PSObject.Properties.Name -contains "SettingsFontSize")) {
        $settings.SettingsFontSize = $defaultSettings.SettingsFontSize
    }
    if (-not ($settings.PSObject.Properties.Name -contains "ScheduleOverrideEnabled")) { $settings.ScheduleOverrideEnabled = $defaultSettings.ScheduleOverrideEnabled }
    if (-not ($settings.PSObject.Properties.Name -contains "StatusColorRunning")) { $settings.StatusColorRunning = $defaultSettings.StatusColorRunning }
    if (-not ($settings.PSObject.Properties.Name -contains "StatusColorPaused")) { $settings.StatusColorPaused = $defaultSettings.StatusColorPaused }
    if (-not ($settings.PSObject.Properties.Name -contains "StatusColorStopped")) { $settings.StatusColorStopped = $defaultSettings.StatusColorStopped }
    if ([string]$settings.StatusColorRunning -eq "#000000") { $settings.StatusColorRunning = $defaultSettings.StatusColorRunning }
    if ([string]$settings.StatusColorPaused -eq "#000000") { $settings.StatusColorPaused = $defaultSettings.StatusColorPaused }
    if ([string]$settings.StatusColorStopped -eq "#000000") { $settings.StatusColorStopped = $defaultSettings.StatusColorStopped }
    if (-not ($settings.PSObject.Properties.Name -contains "CompactMode")) { $settings.CompactMode = $defaultSettings.CompactMode }
}

$script:UiLanguage = Resolve-UiLanguage ([string]$settings.UiLanguage)

if ($settingsLoadedFromFile) {
    $script:PendingRuntimeFromSettings = Extract-RuntimeFromSettings $settings
    if ($script:PendingRuntimeFromSettings.Count -gt 0) {
        Write-Log "Runtime stats found in settings file; migrating to state file." "INFO" $null "Settings"
    }
} else {
    $script:PendingRuntimeFromSettings = @{}
}

$profilesChanged = $false
$settingsAutoSaved = $false
$settingsRepairPerformed = $false
if (-not ($settings.PSObject.Properties.Name -contains "Profiles") -or $null -eq $settings.Profiles) {
    $settings.Profiles = @{}
    $profilesChanged = $true
    $settingsRepairPerformed = $true
}
if ($settings.Profiles -is [pscustomobject]) {
    $table = @{}
    foreach ($prop in $settings.Profiles.PSObject.Properties) {
        $table[$prop.Name] = $prop.Value
    }
    $settings.Profiles = $table
    $profilesChanged = $true
}
if (-not ($settings.Profiles -is [hashtable])) {
    $settings.Profiles = @{}
    $profilesChanged = $true
    $settingsRepairPerformed = $true
}
    if (-not ($settings.PSObject.Properties.Name -contains "LogCategories") -or $null -eq $settings.LogCategories) {
        $settings.LogCategories = $defaultSettings.LogCategories
        $profilesChanged = $true
        $settingsRepairPerformed = $true
    } elseif ($settings.LogCategories -is [pscustomobject]) {
        $table = @{}
        foreach ($prop in $settings.LogCategories.PSObject.Properties) {
            $table[$prop.Name] = [bool]$prop.Value
        }
        $settings.LogCategories = $table
        $profilesChanged = $true
    } elseif (-not ($settings.LogCategories -is [hashtable])) {
        $settings.LogCategories = $defaultSettings.LogCategories
        $profilesChanged = $true
        $settingsRepairPerformed = $true
    }
    if (-not ($settings.PSObject.Properties.Name -contains "LogRetentionDays")) {
        $settings.LogRetentionDays = $defaultSettings.LogRetentionDays
        $profilesChanged = $true
        $settingsRepairPerformed = $true
    }
    if (-not ($settings.PSObject.Properties.Name -contains "LogEventLevels") -or $null -eq $settings.LogEventLevels) {
        $settings.LogEventLevels = $defaultSettings.LogEventLevels
        $profilesChanged = $true
        $settingsRepairPerformed = $true
    } elseif ($settings.LogEventLevels -is [pscustomobject]) {
        $table = @{}
        foreach ($prop in $settings.LogEventLevels.PSObject.Properties) {
            $table[$prop.Name] = [bool]$prop.Value
        }
        $settings.LogEventLevels = $table
        $profilesChanged = $true
    } elseif (-not ($settings.LogEventLevels -is [hashtable])) {
        $settings.LogEventLevels = $defaultSettings.LogEventLevels
        $profilesChanged = $true
        $settingsRepairPerformed = $true
    }
    if ($settings.LogEventLevels -is [hashtable]) {
        foreach ($name in $defaultSettings.LogEventLevels.Keys) {
            if (-not $settings.LogEventLevels.ContainsKey($name)) {
                $settings.LogEventLevels[$name] = [bool]$defaultSettings.LogEventLevels[$name]
                $profilesChanged = $true
                $settingsRepairPerformed = $true
            }
        }
    }
    foreach ($name in $script:LogCategoryNames) {
        if (-not $settings.LogCategories.ContainsKey($name)) {
            $settings.LogCategories[$name] = $true
            $profilesChanged = $true
            $settingsRepairPerformed = $true
        }
    }
    if (-not ($settings.PSObject.Properties.Name -contains "VerboseUiLogging")) {
        $settings.VerboseUiLogging = $defaultSettings.VerboseUiLogging
        $profilesChanged = $true
        $settingsRepairPerformed = $true
    }
    if (-not ($settings.PSObject.Properties.Name -contains "ThemeMode")) {
        $settings.ThemeMode = $defaultSettings.ThemeMode
        $profilesChanged = $true
        $settingsRepairPerformed = $true
    }
if (-not ($settings.PSObject.Properties.Name -contains "ActiveProfile") -or [string]::IsNullOrWhiteSpace($settings.ActiveProfile)) {
    $settings.ActiveProfile = "Default"
    $profilesChanged = $true
    $settingsRepairPerformed = $true
}
if (@(Get-ObjectKeys $settings.Profiles).Count -eq 0) {
    $settings.Profiles["Default"] = Get-ProfileSnapshot $settings
    $settings.Profiles["Work"] = Get-ProfileSnapshot $settings
    $settings.Profiles["Home"] = Get-ProfileSnapshot $settings
    $profilesChanged = $true
    $settingsRepairPerformed = $true
}

foreach ($name in @(Get-ObjectKeys $settings.Profiles)) {
    $profile = $settings.Profiles[$name]
    $profile = Migrate-ProfileSnapshot $profile
    $validation = Test-ProfileSnapshot $profile
    if (-not $validation.IsValid) {
        $lastGood = Get-ProfileLastGood $name
        if ($lastGood) {
            $settings.Profiles[$name] = Migrate-ProfileSnapshot $lastGood
            $profilesChanged = $true
            $settingsRepairPerformed = $true
            Write-Log "Profile '$name' recovered from last known good snapshot." "WARN" $null "Profiles"
        } else {
            Write-Log ("Profile '$name' failed validation: {0}" -f (($validation.Issues | Select-Object -First 4) -join ", ")) "WARN" $null "Profiles"
        }
    } else {
        $settings.Profiles[$name] = $profile
        Update-ProfileLastGood $name $profile
    }
}
if ($profilesChanged) {
    Save-Settings $settings
    $settingsAutoSaved = $true
}

if (-not ($settings.PSObject.Properties.Name -contains "DataRoot") -or [string]::IsNullOrWhiteSpace([string]$settings.DataRoot)) {
    $settings.DataRoot = $script:DataRoot
} elseif ($settings.DataRoot -ne $script:DataRoot) {
    Write-Log "Settings DataRoot differs; using $script:DataRoot." "WARN" $null "Settings"
}

$desiredSettingsDir = Resolve-DirectoryOrDefault ([string]$settings.SettingsDirectory) $defaultSettingsDir "Settings"
Set-SettingsDirectory $desiredSettingsDir -SkipLog
Load-ProfilesLastGood

$desiredLogDir = Resolve-DirectoryOrDefault ([string]$settings.LogDirectory) $defaultLogDir "Logs"
Set-LogDirectory $desiredLogDir -SkipLog

if ($settings.PSObject.Properties.Name -contains "HardenPermissions") {
    if ([bool]$settings.HardenPermissions) {
        try { Harden-AppPermissions } catch { }
    }
}

$settings.DateTimeFormat = Normalize-DateTimeFormat ([string]$settings.DateTimeFormat)
$script:DateTimeFormat = $settings.DateTimeFormat
$script:UseSystemDateTimeFormat = [bool]$settings.UseSystemDateTimeFormat
$script:SystemDateTimeFormatMode = if ([string]::IsNullOrWhiteSpace([string]$settings.SystemDateTimeFormatMode)) { "Short" } else { [string]$settings.SystemDateTimeFormatMode }

$autoCorrectReasons = @()
if ($settingsLoadedFromFile) {
    if ($script:SettingsLoadIssues -and $script:SettingsLoadIssues.Count -gt 0) {
        $autoCorrectReasons += "Load issues detected."
    }
    if ($settingsRepairPerformed) {
        $autoCorrectReasons += "Profiles or logging defaults restored."
    }
}
if ($autoCorrectReasons.Count -gt 0) {
    $script:SettingsAutoCorrected = $true
    $script:SettingsAutoCorrectedMessage = L "We auto-corrected some settings to keep the app stable. Review them in Settings."
    if ($settings.PSObject.Properties.Name -contains "AutoCorrectedNoticeSeen") {
        $settings.AutoCorrectedNoticeSeen = $false
    }
    if (-not $settingsAutoSaved) {
        Save-SettingsImmediate $settings
    }
    Write-Log ("Settings auto-corrected: " + ($autoCorrectReasons -join " ")) "WARN" $null "Settings"
}

if ((Get-ObjectKeys $settings.Profiles) -contains $settings.ActiveProfile) {
    $settings = Apply-ProfileSnapshot $settings $settings.Profiles[$settings.ActiveProfile]
    Write-Log "Applied active profile '$($settings.ActiveProfile)' at startup." "INFO" $null "Profiles"
}

Sync-SettingsReference $settings

Update-LogCategorySettings

$state = Load-State
if (-not $state) {
    $state = [pscustomobject]@{
        SchemaVersion = $script:StateSchemaVersion
        ToggleCount = 0
        LastToggleTime = $null
        Stats = @{
            InstallDate = (Get-Date).ToString("o")
            TotalRunMinutes = 0
            DailyToggles = @{}
            HourlyToggles = @{}
            LongestPauseMinutes = 0
            LongestPauseAt = $null
        }
    }
    if ($settings -and ($settings.PSObject.Properties.Name -contains "ToggleCount")) {
        $state.ToggleCount = [int]$settings.ToggleCount
    }
    if ($settings -and ($settings.PSObject.Properties.Name -contains "LastToggleTime")) {
        $state.LastToggleTime = $settings.LastToggleTime
    }
    if ($settings -and ($settings.PSObject.Properties.Name -contains "Stats")) {
        $state.Stats = Convert-ToHashtable $settings.Stats
    }
}
$runtimeMigrated = $false
if ($script:PendingRuntimeFromSettings -and $script:PendingRuntimeFromSettings.Count -gt 0) {
    $runtimeMigrated = Apply-RuntimeOverridesToState $state $script:PendingRuntimeFromSettings
}
$currentSettingsHash = Get-SettingsFileHash
if ($currentSettingsHash) {
    if ($state.PSObject.Properties.Name -contains "SettingsHash") {
        $previousHash = [string]$state.SettingsHash
        if (-not [string]::IsNullOrWhiteSpace($previousHash) -and $previousHash -ne $currentSettingsHash) {
            $script:SettingsTampered = $true
            $script:SettingsTamperMessage = "Settings file changed outside the app. Please review your settings."
        }
    }
    $state.SettingsHash = $currentSettingsHash
}
$script:AppState = Normalize-State $state
Apply-StateToSettings $settings $script:AppState
$script:LastStateSnapshot = Get-StateSnapshot $script:AppState
$script:LastStateSnapshotHash = Get-StateSnapshotHash $script:LastStateSnapshot

$script:LastSettingsSnapshot = Get-SettingsSnapshot $settings
$script:LastSettingsSnapshotHash = Get-SettingsSnapshotHash $script:LastSettingsSnapshot

if ($script:PendingRuntimeFromSettings -and $script:PendingRuntimeFromSettings.Count -gt 0) {
    Save-StateImmediate $script:AppState
    Save-SettingsImmediate $settings
    $script:PendingRuntimeFromSettings = @{}
}

$script:LogLevel = [string]$settings.LogLevel
if ([string]::IsNullOrWhiteSpace($script:LogLevel)) { $script:LogLevel = "INFO" }
$script:LogLevel = $script:LogLevel.ToUpperInvariant()
if (-not $script:LogLevels.ContainsKey($script:LogLevel)) { $script:LogLevel = "INFO" }
$script:LogMaxBytes = [int]$settings.LogMaxBytes
if ($script:LogMaxBytes -le 0) { $script:LogMaxBytes = 1048576 }
$script:LogMaxTotalBytes = [long]$settings.LogMaxTotalBytes
if ($script:LogMaxTotalBytes -le 0) { $script:LogMaxTotalBytes = 20971520 }

Invoke-UpdateCheck

# --- Global error trap and shutdown handling (cleanup) ---
trap {
    try {
        if (Get-Command -Name Write-BootstrapLog -ErrorAction SilentlyContinue) {
            Write-BootstrapLog "Unhandled exception trapped." "ERROR"
        }
        if (Get-Command -Name Write-LogEx -ErrorAction SilentlyContinue) {
            Write-LogEx "Unhandled exception." "FATAL" $_.Exception "Trap" -Force
        } elseif (Get-Command -Name Write-Log -ErrorAction SilentlyContinue) {
            Write-Log "Unhandled exception." "FATAL" $_.Exception "Trap" -Force
        } else {
            try {
                $fallback = Join-Path $script:LogDirectory "Teams-Always-Green.fallback.log"
                $msg = "[{0}] [FATAL] [Trap] Unhandled exception: {1}" -f (Format-DateTime (Get-Date)), $_.Exception.Message
                Add-Content -Path $fallback -Value $msg
            } catch { }
        }
        if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
            $positionLine = "Position: " + $_.InvocationInfo.PositionMessage.Trim()
            if (Get-Command -Name Write-Log -ErrorAction SilentlyContinue) {
                Write-Log $positionLine "FATAL" $_.Exception "Trap"
            } elseif (Get-Command -Name Write-BootstrapLog -ErrorAction SilentlyContinue) {
                Write-BootstrapLog $positionLine "ERROR"
            }
        }
        try { Flush-LogBuffer } catch { }
        $errorIdValue = "N/A"
        $lastErrorVar = Get-Variable -Name LastErrorId -Scope Script -ErrorAction SilentlyContinue
        if ($lastErrorVar -and $lastErrorVar.Value) { $errorIdValue = $lastErrorVar.Value }
        [System.Windows.Forms.MessageBox]::Show(
            "A fatal error occurred and the app will close.`n$($_.Exception.Message)`n`nErrorId: $errorIdValue",
            "Fatal Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    } finally {
        if (Get-Command -Name Release-MutexOnce -ErrorAction SilentlyContinue) {
            Release-MutexOnce
        }
    }
    break
}

$previousShutdown = Get-ShutdownMarker
$crashState = Get-CrashState
$overrideMinimal = $false
if ($crashState -and ($crashState.PSObject.Properties.Name -contains "OverrideMinimalMode")) {
    $overrideMinimal = [bool]$crashState.OverrideMinimalMode
}
$script:OverrideMinimalMode = $overrideMinimal
if ($previousShutdown -and $previousShutdown -ne "clean") {
    Write-Log "Crash detected: previous session did not exit cleanly." "WARN" $null "Startup"
    try {
        $crashState.Count = [int]$crashState.Count + 1
        $crashState.LastCrash = (Get-Date).ToString("o")
        Save-CrashState $crashState
        if (-not $script:OverrideMinimalMode -and $crashState.Count -ge 2) {
            $script:MinimalModeActive = $true
            $script:MinimalModeReason = "Detected $($crashState.Count) crashes in a row."
            Write-Log ("Minimal mode enabled: {0}" -f $script:MinimalModeReason) "WARN" $null "Startup"
        }
    } catch {
    }
    Clear-StaleRuntimeState "unclean shutdown"
    try {
        $lastGood = Load-LastGoodSettings
        if ($lastGood) {
            $choice = [System.Windows.Forms.MessageBox]::Show(
                "The previous session did not exit cleanly.`n`nRestore the last known good settings snapshot?",
                "Crash Detected",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($choice -eq [System.Windows.Forms.DialogResult]::Yes) {
                $settings = Migrate-Settings $lastGood
                $settings = Normalize-Settings $settings
                Save-SettingsImmediate $settings
                Write-Log "Restored settings from last known good snapshot." "WARN" $null "Startup"
            }
        }
    } catch {
    }
} else {
    if ($crashState.Count -ne 0) {
        $crashState.Count = 0
        $crashState.LastCrash = $null
        Save-CrashState $crashState
    }
}
if ($script:IntegrityFailed -and -not $script:OverrideMinimalMode -and -not $script:MinimalModeActive) {
    $script:MinimalModeActive = $true
    $script:MinimalModeReason = "Integrity check failed."
    Write-Log ("Minimal mode enabled: {0}" -f $script:MinimalModeReason) "WARN" $null "Integrity"
}
if ($script:OverrideMinimalMode) {
    $script:MinimalModeActive = $false
    $script:MinimalModeReason = $null
}
Set-ShutdownMarker "started"
Write-Log "" "INFO" $null "Init"
Write-Log "=======================================================================" "INFO" $null "Init"
Write-Log "=                              APP START                              =" "INFO" $null "Init"
Write-Log "=======================================================================" "INFO" $null "Init"
if ($script:LogLevel -eq "DEBUG") {
    Write-Log "Tag Key: S=SessionID T=Type P=Profile C=Context Tab=Tab E=EventId R=Result" "INFO" $null "Logging"
    Write-Log "=======================================================================" "INFO" $null "Init"
}
Write-Log (Get-PathHealthSummary) "DEBUG" $null "Init"
Validate-RequiredFiles
Log-FolderHealthOnce
if (Get-Command -Name Start-LogSummaryTimer -ErrorAction SilentlyContinue) { Start-LogSummaryTimer }
Purge-OldLogs
$buildStamp = if ($appBuildTimestamp) { Format-DateTime $appBuildTimestamp } else { "Unknown" }
$scriptHashValue = if ($appScriptHash) { $appScriptHash } else { "Unknown" }
$configHashValue = "Unknown"
try {
    if (Test-Path $settingsPath) {
        $configHashValue = (Get-FileHash -Algorithm SHA256 -Path $settingsPath -ErrorAction Stop).Hash
    }
} catch {
    $configHashValue = "Unknown"
}
if ($configHashValue -and $configHashValue.Length -gt 12) { $configHashValue = $configHashValue.Substring(0, 12) }
$profileHashValue = "Unknown"
try {
    $profileSnapshot = Get-ProfileSnapshot $settings
    $profileHashValue = Get-SettingsSnapshotHash (Get-SettingsSnapshot $profileSnapshot)
} catch {
    $profileHashValue = "Unknown"
}
if ($profileHashValue -and $profileHashValue.Length -gt 12) { $profileHashValue = $profileHashValue.Substring(0, 12) }
$startupSource = Get-StartupSource
$settingsAgeMinutes = "Unknown"
try {
    if (Test-Path $settingsPath) {
        $age = (Get-Date) - (Get-Item -Path $settingsPath).LastWriteTime
        $settingsAgeMinutes = [Math]::Round($age.TotalMinutes, 1)
    }
} catch {
    $settingsAgeMinutes = "Unknown"
}
$themeModeValue = if ($settings.PSObject.Properties.Name -contains "ThemeMode") { [string]$settings.ThemeMode } else { "Unknown" }
$themeResolved = $themeModeValue
if ($themeModeValue -eq "Auto") {
    if (Get-Command -Name Get-SystemThemeIsDark -ErrorAction SilentlyContinue) {
        $themeResolved = if (Get-SystemThemeIsDark) { "Dark" } else { "Light" }
    } else {
        $themeResolved = "Unknown"
    }
}
$hotkeyStatusValue = if ($script:HotkeyStatusText) { $script:HotkeyStatusText } else { "Unknown" }
Write-Log ("Session start: SessionID={0} Profile={1} LogLevel={2} Version={3} SchemaVersion={4} Build={5}" -f `
    $script:RunId, $settings.ActiveProfile, $settings.LogLevel, $appVersion, $script:SettingsSchemaVersion, $buildStamp) "INFO" $null "Init"
Write-Log ("Session path: LogPath={0}" -f $logPath) "INFO" $null "Init"
Write-Log ("Session path: SettingsPath={0}" -f $settingsPath) "INFO" $null "Init"
Write-Log ("Session path: StatePath={0}" -f $script:StatePath) "INFO" $null "Init"
Save-StartupSnapshot
Write-Log ("Metadata: BuildId={0} ScriptHash={1} SchemaVersion={2} ConfigHash={3} ProfileHash={4} StartupSource={5} SettingsAgeMin={6} ThemeMode={7} ThemeResolved={8} Hotkeys={9}" -f `
    $appBuildId, $scriptHashValue, $script:SettingsSchemaVersion, $configHashValue, $profileHashValue, $startupSource, $settingsAgeMinutes, $themeModeValue, $themeResolved, $hotkeyStatusValue) "DEBUG" $null "Init"
Write-Log "Startup. ScriptPath=$scriptPath" "DEBUG" $null "Init"
Write-Log "Startup. SettingsPath=$settingsPath" "DEBUG" $null "Init"
Write-Log "Startup. LogPath=$logPath" "DEBUG" $null "Init"
$psVersion = $PSVersionTable.PSVersion
$osVersion = [Environment]::OSVersion.VersionString
$pidValue = $PID
Write-Log "Environment. PID=$pidValue PSVersion=$psVersion OS=$osVersion" "DEBUG" $null "Init"
Write-Log (Get-EnvironmentSummary) "DEBUG" $null "Init"
Write-Log ("Settings snapshot. IntervalSeconds={0} QuietMode={1} MinimalTooltip={2} DisableBalloonTips={3} StartWithWindows={4} RememberChoice={5} StartOnLaunch={6} RunOnceOnLaunch={7} PauseUntil={8} PauseDurations={9} ScheduleEnabled={10} ScheduleStart={11} ScheduleEnd={12} ScheduleWeekdays={13} ScheduleSuspendUntil={14} SafeModeEnabled={15} SafeModeFailureThreshold={16} HotkeyToggle={17} HotkeyStartStop={18} HotkeyPauseResume={19} ToggleCount={20} LogLevel={21} LogMaxBytes={22} LogMaxTotalBytes={23} LogIncludeStackTrace={24} LogToEventLog={25} LogCategories={26}" -f `
    $settings.IntervalSeconds, $settings.QuietMode, $settings.MinimalTrayTooltip, $settings.DisableBalloonTips, $settings.StartWithWindows, $settings.RememberChoice, $settings.StartOnLaunch, $settings.RunOnceOnLaunch, $settings.PauseUntil, $settings.PauseDurationsMinutes, $settings.ScheduleEnabled, $settings.ScheduleStart, $settings.ScheduleEnd, $settings.ScheduleWeekdays, $settings.ScheduleSuspendUntil, $settings.SafeModeEnabled, $settings.SafeModeFailureThreshold, $settings.HotkeyToggle, $settings.HotkeyStartStop, $settings.HotkeyPauseResume, $settings.ToggleCount, $settings.LogLevel, $settings.LogMaxBytes, $settings.LogMaxTotalBytes, $settings.LogIncludeStackTrace, $settings.LogToEventLog, ((Get-ObjectKeys $settings.LogCategories | Sort-Object | ForEach-Object { "$_=$(Get-ObjectValue $settings.LogCategories $_)" }) -join ",")) "DEBUG" $null "Init"

# --- Startup shortcut management (create/remove) ---
function Get-StartupShortcutPath {
    $startupDir = [Environment]::GetFolderPath("Startup")
    return Join-Path $startupDir "Teams-Always-Green.lnk"
}

function Set-StartupShortcut([bool]$enabled) {
    $shortcutPath = Get-StartupShortcutPath
    if ($enabled) {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
        $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
    $shortcut.WorkingDirectory = $script:DataRoot
        $shortcut.WindowStyle = 7
        $shortcut.IconLocation = if (Test-Path $iconPath) { $iconPath } else { "$env:WINDIR\System32\shell32.dll,1" }
        $shortcut.Save()
    } else {
        if (Test-Path $shortcutPath) {
            Remove-Item -Path $shortcutPath -Force
        }
    }
}

try {
    $startupPath = Get-StartupShortcutPath
    $startupEnabled = Test-Path $startupPath
    if ($settings.StartWithWindows -ne $startupEnabled) {
        $settings.StartWithWindows = $startupEnabled
        Save-Settings $settings
    }
} catch {
    Write-Log "Failed to read startup shortcut." "ERROR" $_.Exception "Startup"
}

# --- Key simulation (SendInput) for toggling ---
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class KeyboardSimulator {
    [StructLayout(LayoutKind.Sequential)]
    public struct INPUT {
        public uint type;
        public InputUnion U;
    }
    [StructLayout(LayoutKind.Explicit)]
    public struct InputUnion {
        [FieldOffset(0)]
        public KEYBDINPUT ki;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct KEYBDINPUT {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }
    public const int INPUT_KEYBOARD = 1;
    public const int KEYEVENTF_KEYUP = 0x0002;
    [DllImport("user32.dll", SetLastError = true)]
    public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
    [DllImport("user32.dll")]
    public static extern void keybd_event(byte bVk, byte bScan, int dwFlags, int dwExtraInfo);
}
"@

Add-Type -ReferencedAssemblies System.Windows.Forms,System.Drawing @"
using System;
using System.Drawing;
using System.Windows.Forms;

public static class ThemeColors {
    public static Color MenuText = SystemColors.MenuText;
}

public class ThemeColorTable : ProfessionalColorTable {
    public Color MenuBackColor = SystemColors.Menu;
    public Color MenuBorderColor = SystemColors.ActiveBorder;
    public Color MenuItemSelectedColor = SystemColors.Highlight;
    public Color MenuItemSelectedTextColor = SystemColors.HighlightText;
    public Color MenuItemPressedColor = SystemColors.Menu;
    public Color SeparatorColor = SystemColors.ControlDark;

    public override Color ToolStripDropDownBackground { get { return MenuBackColor; } }
    public override Color MenuBorder { get { return MenuBorderColor; } }
    public override Color MenuItemSelected { get { return MenuItemSelectedColor; } }
    public override Color MenuItemSelectedGradientBegin { get { return MenuItemSelectedColor; } }
    public override Color MenuItemSelectedGradientEnd { get { return MenuItemSelectedColor; } }
    public override Color MenuItemPressedGradientBegin { get { return MenuItemPressedColor; } }
    public override Color MenuItemPressedGradientEnd { get { return MenuItemPressedColor; } }
    public override Color ImageMarginGradientBegin { get { return MenuBackColor; } }
    public override Color ImageMarginGradientMiddle { get { return MenuBackColor; } }
    public override Color ImageMarginGradientEnd { get { return MenuBackColor; } }
    public override Color SeparatorDark { get { return SeparatorColor; } }
    public override Color SeparatorLight { get { return SeparatorColor; } }
}

public class StatusMenuRenderer : ToolStripProfessionalRenderer {
    public StatusMenuRenderer(ProfessionalColorTable table) : base(table) {
    }

    protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e) {
        var item = e.Item as ToolStripMenuItem;
        if (item != null && item.Name == "StatusStateItem") {
            string prefix = "Status: ";
            string state = item.Tag as string;
            if (state == null) { state = string.Empty; }
            Color stateColor = item.ForeColor.IsEmpty ? Color.Red : item.ForeColor;
            Rectangle rect = e.TextRectangle;
            TextRenderer.DrawText(e.Graphics, prefix, e.TextFont, rect, ThemeColors.MenuText, TextFormatFlags.Left);
            Size prefixSize = TextRenderer.MeasureText(e.Graphics, prefix, e.TextFont, rect.Size, TextFormatFlags.Left);
            Rectangle stateRect = new Rectangle(rect.X + prefixSize.Width, rect.Y, rect.Width - prefixSize.Width, rect.Height);
            TextRenderer.DrawText(e.Graphics, state, e.TextFont, stateRect, stateColor, TextFormatFlags.Left);
            return;
        }
        base.OnRenderItemText(e);
    }
}
"@

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class IconHelpers {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public extern static bool DestroyIcon(IntPtr handle);
}
"@

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class FormIconNative {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr SendMessage(IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);
}
"@

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class WindowNative {
    public const int SW_RESTORE = 9;
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")]
    public static extern bool IsIconic(IntPtr hWnd);
}
"@

Add-Type -ReferencedAssemblies System.Windows.Forms @"
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
public static class HotKeyNative {
    public const int WM_HOTKEY = 0x0312;
    public const int MOD_ALT = 0x0001;
    public const int MOD_CONTROL = 0x0002;
    public const int MOD_SHIFT = 0x0004;
    public const int MOD_WIN = 0x0008;
    [DllImport("user32.dll")]
    public static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);
    [DllImport("user32.dll")]
    public static extern bool UnregisterHotKey(IntPtr hWnd, int id);
}
public class HotKeyMessageFilter : IMessageFilter {
    public static Action<int> HotKeyPressed;
    public bool PreFilterMessage(ref Message m) {
        if (m.Msg == HotKeyNative.WM_HOTKEY && HotKeyPressed != null) {
            HotKeyPressed(m.WParam.ToInt32());
        }
        return false;
    }
}
"@

function Invoke-ScrollLockToggleInternal {
    [KeyboardSimulator]::keybd_event(0x91, 0, 0, 0)
    Start-Sleep -Milliseconds 50
    [KeyboardSimulator]::keybd_event(0x91, 0, 2, 0)
}

function Set-FormTaskbarIcon($form, [string]$iconPath) {
    if (-not $form -or $form.IsDisposed) { return }
    if ([string]::IsNullOrWhiteSpace($iconPath) -or -not (Test-Path $iconPath)) { return }
    try {
        $icon = New-Object System.Drawing.Icon($iconPath)
        $script:SettingsFormIcon = $icon
        $form.Icon = $icon
        if ($form.Handle -ne [IntPtr]::Zero) {
            [FormIconNative]::SendMessage($form.Handle, 0x80, [IntPtr]1, $icon.Handle) | Out-Null
            [FormIconNative]::SendMessage($form.Handle, 0x80, [IntPtr]0, $icon.Handle) | Out-Null
        }
    } catch {
    }
}

# --- App state (running/paused flags) ---
# --- Runtime state and scheduling helpers (next toggle) ---
$script:isRunning = $false
$script:isToggling = $false
$script:isTicking = $false
$script:isPaused = $false
$script:pauseUntil = $null
$script:lastState = $null
$script:isScheduleBlocked = $false
$script:safeModeActive = $false
$script:toggleFailCount = 0
$script:OverlayIcon = $null
$script:isShuttingDown = $false
$script:CleanupDone = $false
$script:LastThemeIsDark = $null
$script:LastThemeCheckTime = $null
$script:ForceThemeApply = $false
$script:LastStatusSnapshot = $null
$script:LastStatusUpdateTime = Get-Date
$script:Now = $null
$script:LastNotifyText = $null
$script:LogThrottle = @{}
$script:HotKeyFilterAdded = $false
$script:tickCount = 0
$script:lastToggleTime = $null
$script:nextToggleTime = $null
$script:StatsShutdownUpdated = $false

$toggleTimeValue = $null
if ($script:AppState -and ($script:AppState.PSObject.Properties.Name -contains "LastToggleTime")) {
    $toggleTimeValue = $script:AppState.LastToggleTime
} elseif ($settings -and ($settings.PSObject.Properties.Name -contains "LastToggleTime")) {
    $toggleTimeValue = $settings.LastToggleTime
}
if ($toggleTimeValue) {
    $parsed = $null
    try {
        $parsed = [DateTime]::Parse($toggleTimeValue)
        $script:lastToggleTime = $parsed
    } catch {
        Write-Log "Failed to parse LastToggleTime." "ERROR" $_.Exception "Parse-Settings"
    }
}

if ($settings.PauseUntil) {
    $pauseParsed = $null
    try {
        $pauseParsed = [DateTime]::Parse($settings.PauseUntil)
        if ($pauseParsed -gt (Get-Date)) {
            $script:isPaused = $true
            $script:isRunning = $true
            $script:pauseUntil = $pauseParsed
        } else {
            $settings.PauseUntil = $null
            Save-Settings $settings
        }
    } catch {
        Write-Log "Failed to parse PauseUntil." "ERROR" $_.Exception "Parse-Settings"
    }
}
# --- Fun stats tracking (streaks/counters) ---
function Convert-ToHashtable($obj) {
    if ($obj -is [hashtable]) { return $obj }
    if ($obj -is [pscustomobject]) {
        $table = @{}
        foreach ($prop in $obj.PSObject.Properties) {
            $table[$prop.Name] = $prop.Value
        }
        return $table
    }
    return @{}
}

function Ensure-FunStats($settings) {
    if (-not $settings) { return @{} }
    $stats = Convert-ToHashtable (Get-SettingsPropertyValue $settings "Stats")
    if (-not $stats) { $stats = @{} }
    if (-not $stats.ContainsKey("InstallDate")) { $stats["InstallDate"] = (Get-Date).ToString("o") }
    if (-not $stats.ContainsKey("TotalRunMinutes")) { $stats["TotalRunMinutes"] = 0 }
    if (-not $stats.ContainsKey("LongestPauseMinutes")) { $stats["LongestPauseMinutes"] = 0 }
    if (-not $stats.ContainsKey("LongestPauseAt")) { $stats["LongestPauseAt"] = $null }

    $daily = Convert-ToHashtable $stats["DailyToggles"]
    if (-not $daily) { $daily = @{} }
    $stats["DailyToggles"] = $daily

    $hourly = Convert-ToHashtable $stats["HourlyToggles"]
    if (-not $hourly) { $hourly = @{} }
    $stats["HourlyToggles"] = $hourly

    Set-SettingsPropertyValue $settings "Stats" $stats
    return $stats
}

function Update-FunStatsOnToggle([DateTime]$when) {
    if (-not $when) { return }
    $stats = Ensure-FunStats $settings
    $daily = Convert-ToHashtable $stats["DailyToggles"]
    $dateKey = $when.ToString("yyyy-MM-dd")
    $currentDaily = 0
    if ($daily.ContainsKey($dateKey)) { $currentDaily = [int]$daily[$dateKey] }
    $daily[$dateKey] = $currentDaily + 1
    $stats["DailyToggles"] = $daily

    $hourly = Convert-ToHashtable $stats["HourlyToggles"]
    $hourKey = [string]$when.Hour
    $currentHour = 0
    if ($hourly.ContainsKey($hourKey)) { $currentHour = [int]$hourly[$hourKey] }
    $hourly[$hourKey] = $currentHour + 1
    $stats["HourlyToggles"] = $hourly

    Set-SettingsPropertyValue $settings "Stats" $stats
}

function Update-FunStatsOnPause([int]$minutes) {
    if ($minutes -le 0) { return }
    $stats = Ensure-FunStats $settings
    $currentLongest = 0
    if ($stats.ContainsKey("LongestPauseMinutes")) { $currentLongest = [int]$stats["LongestPauseMinutes"] }
    if ($minutes -gt $currentLongest) {
        $stats["LongestPauseMinutes"] = $minutes
        $stats["LongestPauseAt"] = (Get-Date).ToString("o")
        Set-SettingsPropertyValue $settings "Stats" $stats
    }
}

function Update-FunStatsOnShutdown([double]$uptimeMinutes) {
    if ($script:StatsShutdownUpdated) { return }
    if ($uptimeMinutes -le 0) { return }
    $stats = Ensure-FunStats $settings
    $total = 0.0
    if ($stats.ContainsKey("TotalRunMinutes")) { $total = [double]$stats["TotalRunMinutes"] }
    $stats["TotalRunMinutes"] = [Math]::Round(($total + $uptimeMinutes), 1)
    Set-SettingsPropertyValue $settings "Stats" $stats
    Sync-StateFromSettings $settings
    Apply-StateToSettings $settings $script:AppState
    Save-StateImmediate $script:AppState
    $script:StatsShutdownUpdated = $true
}

function Get-DailyToggleCount($stats, [DateTime]$when) {
    if (-not $stats) { return 0 }
    $daily = Convert-ToHashtable $stats["DailyToggles"]
    $key = $when.ToString("yyyy-MM-dd")
    if ($daily.ContainsKey($key)) { return [int]$daily[$key] }
    return 0
}

function Get-MostActiveHourLabel($stats) {
    if (-not $stats) { return "N/A" }
    $hourly = Convert-ToHashtable $stats["HourlyToggles"]
    if (@(Get-ObjectKeys $hourly).Count -eq 0) { return "N/A" }
    $topHour = $null
    $topCount = -1
    foreach ($key in $hourly.Keys) {
        $count = [int]$hourly[$key]
        if ($count -gt $topCount) {
            $topCount = $count
            $topHour = [int]$key
        }
    }
    if ($null -eq $topHour) { return "N/A" }
    return ("{0:00}:00" -f $topHour)
}

function Get-ToggleStreaks($stats) {
    $result = @{ Current = 0; Best = 0 }
    if (-not $stats) { return $result }
    $daily = Convert-ToHashtable $stats["DailyToggles"]
    if (@(Get-ObjectKeys $daily).Count -eq 0) { return $result }

    $dates = @()
    foreach ($key in $daily.Keys) {
        $count = [int]$daily[$key]
        if ($count -gt 0) {
            try { $dates += [DateTime]::ParseExact($key, "yyyy-MM-dd", $null) } catch { }
        }
    }
    if (@($dates).Count -eq 0) { return $result }
    $dates = @($dates | Sort-Object)

    $best = 1
    $current = 1
    for ($i = 1; $i -lt @($dates).Count; $i++) {
        if (($dates[$i] - $dates[$i - 1]).Days -eq 1) {
            $current++
            if ($current -gt $best) { $best = $current }
        } else {
            $current = 1
        }
    }

    $today = (Get-Date).Date
    $todayKey = $today.ToString("yyyy-MM-dd")
    if (-not $daily.ContainsKey($todayKey) -or [int]$daily[$todayKey] -le 0) {
        $result.Current = 0
    } else {
        $streak = 1
        $check = $today.AddDays(-1)
        while ($daily.ContainsKey($check.ToString("yyyy-MM-dd")) -and [int]$daily[$check.ToString("yyyy-MM-dd")] -gt 0) {
            $streak++
            $check = $check.AddDays(-1)
        }
        $result.Current = $streak
    }
    $result.Best = $best
    return $result
}

function Format-TotalRunTime([double]$minutes) {
    if ($minutes -le 0) { return "0m" }
    $span = [TimeSpan]::FromMinutes($minutes)
    if ($span.TotalDays -ge 1) {
        return ("{0}d {1}h {2}m" -f [int]$span.TotalDays, $span.Hours, $span.Minutes)
    }
    if ($span.TotalHours -ge 1) {
        return ("{0}h {1}m" -f [int]$span.TotalHours, $span.Minutes)
    }
    return ("{0}m" -f [int]$span.TotalMinutes)
}

Ensure-FunStats $settings | Out-Null
Sync-StateFromSettings $settings
Apply-StateToSettings $settings $script:AppState
Save-StateImmediate $script:AppState
# --- Stats persistence and next-toggle calculations ---
function Save-Stats {
    if ($null -eq (Get-SettingsPropertyValue $settings "ToggleCount")) {
        Set-SettingsPropertyValue $settings "ToggleCount" 0
    }
    Set-SettingsPropertyValue $settings "LastToggleTime" (if ($script:lastToggleTime) { $script:lastToggleTime.ToString("o") } else { $null })
    Ensure-FunStats $settings | Out-Null
    Sync-StateFromSettings $settings
    Apply-StateToSettings $settings $script:AppState
    Save-State $script:AppState
}

function Update-NextToggleTime {
    if ($script:isRunning -and -not $script:isScheduleBlocked) {
        $script:nextToggleTime = (Get-Date).AddSeconds([int]$settings.IntervalSeconds)
    } else {
        $script:nextToggleTime = $null
    }
}

function Get-Now {
    if ($script:Now) { return $script:Now }
    return Get-Date
}

function Format-LocalTime($value, [string]$format = $null) {
    if ($null -eq $value) { return "N/A" }
    if ($script:UseSystemDateTimeFormat -and [string]::IsNullOrWhiteSpace($format)) {
        return Format-DateTime $value
    }
    $effectiveFormat = if ([string]::IsNullOrWhiteSpace($format)) { $script:DateTimeFormat } else { $format }
    $effectiveFormat = Normalize-DateTimeFormat $effectiveFormat
    try {
        return ([DateTime]$value).ToString($effectiveFormat)
    } catch {
        return [string]$value
    }
}

function Get-DebugModeStatusText {
    if (-not $script:DebugModeUntil) { return "Off" }
    $remaining = [int][Math]::Ceiling(($script:DebugModeUntil - (Get-Date)).TotalSeconds)
    if ($remaining -lt 0) { $remaining = 0 }
    $mins = [int]($remaining / 60)
    $secs = $remaining % 60
    return ("On ({0}m {1}s)" -f $mins, $secs)
}
function Convert-ColorString([string]$value, [System.Drawing.Color]$fallback) {
    if ([string]::IsNullOrWhiteSpace($value)) { return $fallback }
    try {
        if ($value -match "Color \\[(.+)\\]") {
            $inner = $Matches[1]
            if ($inner -match "A=(\\d+), R=(\\d+), G=(\\d+), B=(\\d+)") {
                return [System.Drawing.Color]::FromArgb([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4])
            }
            $value = $inner
        }
        return [System.Drawing.ColorTranslator]::FromHtml($value)
    } catch {
        return $fallback
    }
}

function Convert-ColorToString([System.Drawing.Color]$color) {
    return "#$($color.R.ToString("X2"))$($color.G.ToString("X2"))$($color.B.ToString("X2"))"
}

function Apply-MenuFontSize([int]$size) {
    if ($size -le 0) { $size = 12 }
    $baseFont = [System.Windows.Forms.SystemInformation]::MenuFont
    $newFont = New-Object System.Drawing.Font($baseFont.FontFamily, $size, $baseFont.Style)
    if (Get-Variable -Name contextMenu -Scope Script -ErrorAction SilentlyContinue) {
        if ($script:contextMenu) { $script:contextMenu.Font = $newFont }
    }
}

function Apply-SettingsFontSize([int]$size) {
    if ($size -le 0) { $size = 12 }
    $baseFont = [System.Windows.Forms.SystemInformation]::MenuFont
    $newFont = New-Object System.Drawing.Font($baseFont.FontFamily, $size, $baseFont.Style)
    if ($script:SettingsForm -and -not $script:SettingsForm.IsDisposed) { $script:SettingsForm.Font = $newFont }
}

Apply-MenuFontSize ([int]$settings.FontSize)
Apply-SettingsFontSize ([int]$settings.SettingsFontSize)

function Format-TimeOrNever($time, [bool]$showSeconds) {
    if ($null -eq $time) { return "Never" }
    return Format-DateTime $time
}

function Format-PauseRemaining {
    if (-not $script:isPaused -or $null -eq $script:pauseUntil) { return $null }
    $remaining = [int][Math]::Max(0, ($script:pauseUntil - (Get-Now)).TotalSeconds)
    $mins = [int]($remaining / 60)
    $secs = $remaining % 60
    return "{0}m {1}s" -f $mins, $secs
}

function Format-NextInfo {
    $now = Get-Now
    $nowKey = $now.ToString("yyyyMMddHHmmss")
    $key = "$nowKey|$script:isRunning|$script:isPaused|$script:isScheduleBlocked|$script:isScheduleSuspended|$($script:nextToggleTime)|$($script:pauseUntil)|$($settings.IntervalSeconds)"
    if ($script:NextInfoCacheKey -eq $key) { return $script:NextInfoCacheValue }
    $result = "N/A"
    if ($script:isRunning -and $script:isScheduleSuspended) {
        $result = "Suspended"
    } elseif ($script:isRunning -and $script:isScheduleBlocked) {
        $result = "Scheduled"
    } elseif ($script:isPaused) {
        $pauseText = Format-PauseRemaining
        $result = if ($pauseText) { "Paused ($pauseText)" } else { "Paused" }
    } elseif (-not $script:isRunning -or $null -eq $script:nextToggleTime) {
        $result = "N/A"
    } else {
        $remaining = [int][Math]::Max(0, ($script:nextToggleTime - $now).TotalSeconds)
        $showSeconds = ([int]$settings.IntervalSeconds -lt 60)
        $nextTime = Format-TimeOrNever $script:nextToggleTime $showSeconds
        $result = "$remaining s ($nextTime)"
    }
    $script:NextInfoCacheKey = $key
    $script:NextInfoCacheValue = $result
    return $result
}

function Format-PauseUntilText {
    if (-not $script:isPaused -or $null -eq $script:pauseUntil) { return "N/A" }
    return Format-TimeOrNever $script:pauseUntil $false
}

# --- Interval and schedule parsing helpers ---
function Get-PauseDurations {
    $raw = [string]$settings.PauseDurationsMinutes
    if ([string]::IsNullOrWhiteSpace($raw)) { return @(5, 15, 30) }
    $values = @()
    foreach ($part in ($raw -split "[,; ]+" | Where-Object { $_ -ne "" })) {
        $num = 0
        if ([int]::TryParse($part, [ref]$num) -and $num -gt 0) {
            $values += $num
        }
    }
    if ($values.Count -eq 0) { return @(5, 15, 30) }
    return $values | Sort-Object -Unique
}

function Get-ScheduleWeekdaySet([string]$text) {
    if ($script:ScheduleWeekdayCacheText -eq $text -and $script:ScheduleWeekdayCacheSet) {
        return $script:ScheduleWeekdayCacheSet
    }
    if ([string]::IsNullOrWhiteSpace($text)) { return @() }
    $map = @{
        "MON" = [DayOfWeek]::Monday
        "TUE" = [DayOfWeek]::Tuesday
        "WED" = [DayOfWeek]::Wednesday
        "THU" = [DayOfWeek]::Thursday
        "FRI" = [DayOfWeek]::Friday
        "SAT" = [DayOfWeek]::Saturday
        "SUN" = [DayOfWeek]::Sunday
    }
    $set = @()
    foreach ($part in ($text -split "[,; ]+" | Where-Object { $_ -ne "" })) {
        $key = $part.ToUpperInvariant().Substring(0, [Math]::Min(3, $part.Length))
        if ($map.ContainsKey($key)) { $set += $map[$key] }
    }
    $set = $set | Sort-Object -Unique
    $script:ScheduleWeekdayCacheText = $text
    $script:ScheduleWeekdayCacheSet = $set
    return $set
}

function Try-ParseTime([string]$text, [ref]$result) {
    $result.Value = [TimeSpan]::Zero
    if ([string]::IsNullOrWhiteSpace($text)) { return $false }
    $parsed = [TimeSpan]::Zero
    $ok = [TimeSpan]::TryParse($text, [ref]$parsed)
    if ($ok) { $result.Value = $parsed }
    return $ok
}

function Get-ScheduleSuspendUntil {
    $raw = [string]$settings.ScheduleSuspendUntil
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    try {
        return [DateTime]::Parse($raw)
    } catch {
        return $null
    }
}

function Is-WithinSchedule {
    if (-not [bool]$settings.ScheduleEnabled) { return $true }
    $days = Get-ScheduleWeekdaySet $settings.ScheduleWeekdays
    if ($days.Count -gt 0 -and -not ($days -contains (Get-Date).DayOfWeek)) { return $false }
    $cacheKey = "{0}|{1}" -f $settings.ScheduleStart, $settings.ScheduleEnd
    if ($script:ScheduleTimeCacheKey -ne $cacheKey) {
        $start = [TimeSpan]::Zero
        $end = [TimeSpan]::Zero
        if (-not (Try-ParseTime $settings.ScheduleStart ([ref]$start))) { return $true }
        if (-not (Try-ParseTime $settings.ScheduleEnd ([ref]$end))) { return $true }
        $script:ScheduleStartCache = $start
        $script:ScheduleEndCache = $end
        $script:ScheduleTimeCacheKey = $cacheKey
    }
    $start = $script:ScheduleStartCache
    $end = $script:ScheduleEndCache
    $now = (Get-Date).TimeOfDay
    if ($start -le $end) {
        return ($now -ge $start -and $now -le $end)
    }
    return ($now -ge $start -or $now -le $end)
}

function Update-ScheduleBlock {
    $script:isScheduleSuspended = $false
    if ([bool]$settings.ScheduleEnabled) {
        $suspendUntil = Get-ScheduleSuspendUntil
        if ($suspendUntil -and $suspendUntil -gt (Get-Date)) {
            $script:isScheduleBlocked = $true
            $script:isScheduleSuspended = $true
            if (-not $script:LastScheduleSuspended) {
                Write-Log "SCHED: Schedule suspended until $(Format-DateTime $suspendUntil)." "INFO" $null "Schedule"
                Log-StateSummary "Schedule"
            }
            $script:LastScheduleSuspended = $true
            $script:LastScheduleBlocked = $true
            return $true
        }
    }
    if ($script:LastScheduleSuspended) {
        Write-Log "SCHED: Schedule suspension ended." "INFO" $null "Schedule"
        $script:LastScheduleSuspended = $false
        Log-StateSummary "Schedule"
    }
    $script:isScheduleBlocked = [bool]$settings.ScheduleEnabled -and -not (Is-WithinSchedule)
    if ($script:LastScheduleBlocked -ne $script:isScheduleBlocked) {
        $blockedText = if ($script:isScheduleBlocked) { "blocked (outside schedule)." } else { "unblocked (inside schedule)." }
        Write-Log "SCHED: Schedule $blockedText" "INFO" $null "Schedule"
        Log-StateSummary "Schedule"
    }
    $script:LastScheduleBlocked = $script:isScheduleBlocked
    return $script:isScheduleBlocked
}

$null = Update-ScheduleBlock
Log-StartupSummary

function Format-ScheduleStatus {
    $key = "{0}|{1}|{2}|{3}|{4}|{5}" -f $settings.ScheduleEnabled, $settings.ScheduleStart, $settings.ScheduleEnd, $settings.ScheduleWeekdays, $settings.ScheduleSuspendUntil, $script:isScheduleSuspended
    if ($script:ScheduleStatusCacheKey -eq $key -and $script:ScheduleStatusCacheValue) {
        return $script:ScheduleStatusCacheValue
    }
    $value = "Off"
    if ([bool]$settings.ScheduleEnabled) {
        if ($script:isScheduleSuspended) {
            $suspendUntil = Get-ScheduleSuspendUntil
            $suspendText = Format-TimeOrNever $suspendUntil $false
            $value = "Suspended until $suspendText"
        } else {
            $value = "On ($($settings.ScheduleStart)-$($settings.ScheduleEnd) $($settings.ScheduleWeekdays))"
        }
    }
    $script:ScheduleStatusCacheKey = $key
    $script:ScheduleStatusCacheValue = $value
    return $value
}

function Update-NotifyIconText([string]$state) {
    if ($script:isShuttingDown -or -not $notifyIcon) { return }
    $tooltipStyle = "Standard"
    if ($settings -and ($settings.PSObject.Properties.Name -contains "TooltipStyle")) {
        $tooltipStyle = [string]$settings.TooltipStyle
    } elseif ($settings.MinimalTrayTooltip) {
        $tooltipStyle = "Minimal"
    }
    if ($tooltipStyle -eq "Minimal") {
        $short = "Teams-Always-Green ($state)"
        if ($short.Length -gt 63) { $short = $short.Substring(0, 63) }
        if ($script:LastNotifyText -eq $short) { return }
        $script:LastNotifyText = $short
        $notifyIcon.Text = $short
        return
    }
    $startupEnabled = [bool]$settings.StartWithWindows
    $nextShort = "N/A"
    if ($script:isRunning -and -not $script:isPaused -and -not $script:isScheduleBlocked -and $script:nextToggleTime) {
        $remaining = [int][Math]::Max(0, ($script:nextToggleTime - (Get-Date)).TotalSeconds)
        $nextShort = "$remaining s"
    } elseif ($script:isPaused) {
        $nextShort = "Paused"
    } elseif ($script:isScheduleSuspended) {
        $nextShort = "Susp"
    } elseif ($script:isScheduleBlocked) {
        $nextShort = "Hold"
    }
    $pauseShort = $null
    if ($script:isPaused) {
        $pauseRemaining = Format-PauseRemaining
        $pauseShort = if ($pauseRemaining) { $pauseRemaining } else { "On" }
    }
    $scheduleEnabled = [bool]$settings.ScheduleEnabled
    $scheduleShort = if (-not $scheduleEnabled) { "Off" } elseif ($script:isScheduleSuspended) { "Susp" } elseif ($script:isScheduleBlocked) { "Hold" } else { "On" }
    $parts = @("Teams-Always-Green ($state)")
    if ($nextShort -and $nextShort -ne "N/A") { $parts += "N:$nextShort" }
    if ($scheduleEnabled -or $script:isScheduleSuspended -or $script:isScheduleBlocked) { $parts += "S:$scheduleShort" }
    if ($startupEnabled) { $parts += "SU:On" }
    if ($pauseShort) { $parts += "P:$pauseShort" }
    if ($tooltipStyle -eq "Verbose") {
        $parts += "I:$($settings.IntervalSeconds)s"
        $parts += "P:$($settings.ActiveProfile)"
    }
    $short = $parts -join " "
    while ($short.Length -gt 63 -and $parts.Count -gt 2) {
        $parts = $parts[0..($parts.Count - 2)]
        $short = $parts -join " "
    }
    if ($short.Length -gt 63) { $short = $short.Substring(0, 63) }
    if ($script:LastNotifyText -eq $short) { return }
    $script:LastNotifyText = $short
    $notifyIcon.Text = $short
}

function Parse-Hotkey([string]$text) {
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $mods = 0
    $keyName = $null
    foreach ($part in ($text -split "\+" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })) {
        switch ($part.ToUpperInvariant()) {
            "CTRL" { $mods = $mods -bor [HotKeyNative]::MOD_CONTROL }
            "CONTROL" { $mods = $mods -bor [HotKeyNative]::MOD_CONTROL }
            "ALT" { $mods = $mods -bor [HotKeyNative]::MOD_ALT }
            "SHIFT" { $mods = $mods -bor [HotKeyNative]::MOD_SHIFT }
            "WIN" { $mods = $mods -bor [HotKeyNative]::MOD_WIN }
            default { $keyName = $part }
        }
    }
    if ([string]::IsNullOrWhiteSpace($keyName)) { return $null }
    try {
        $key = [System.Windows.Forms.Keys]::$keyName
    } catch {
        return $null
    }
    return @{ Modifiers = $mods; Vk = [int]$key }
}

function Validate-HotkeyString([string]$text) {
    if ([string]::IsNullOrWhiteSpace($text)) { return $true }
    return ($null -ne (Parse-Hotkey $text))
}

function Run-SelfTest {
    $issues = @()
    if (-not (Validate-HotkeyString $settings.HotkeyToggle)) { $issues += "HotkeyToggle invalid" }
    if (-not (Validate-HotkeyString $settings.HotkeyStartStop)) { $issues += "HotkeyStartStop invalid" }
    if (-not (Validate-HotkeyString $settings.HotkeyPauseResume)) { $issues += "HotkeyPauseResume invalid" }
    if ([bool]$settings.ScheduleEnabled) {
        $tmp = [TimeSpan]::Zero
        if (-not (Try-ParseTime $settings.ScheduleStart ([ref]$tmp))) { $issues += "ScheduleStart invalid" }
        if (-not (Try-ParseTime $settings.ScheduleEnd ([ref]$tmp))) { $issues += "ScheduleEnd invalid" }
        $null = Get-ScheduleWeekdaySet $settings.ScheduleWeekdays
    }
    if ($issues.Count -eq 0) {
        Write-Log "SelfTest: OK" "INFO" $null "SelfTest"
    } else {
        Write-Log ("SelfTest issues: " + ($issues -join "; ")) "WARN" $null "SelfTest"
    }
    return $issues
}

$selfTestIssues = Run-SelfTest
$hotkeyStatus = if (@($selfTestIssues | Where-Object { $_ -like "Hotkey*" }).Count -gt 0) { "Issues" } else { "OK" }
$scheduleStatus = if (@($selfTestIssues | Where-Object { $_ -like "Schedule*" }).Count -gt 0) { "Issues" } else { "OK" }
$profileCount = if ($settings.Profiles -is [hashtable]) { $settings.Profiles.Keys.Count } else { 0 }
Write-Log ("Health Summary: Hotkeys={0} Schedule={1} Profiles={2} EventLog={3} StackTrace={4}" -f `
    $hotkeyStatus, $scheduleStatus, $profileCount, $settings.LogToEventLog, $settings.LogIncludeStackTrace) "INFO" $null "SelfTest"

$script:HotkeyStatusText = "Unknown"
$script:HotkeyWarned = $false

function Register-Hotkeys {
    if ($script:isShuttingDown) { return }
    Unregister-Hotkeys
    if (-not $script:HotKeyFilterAdded) {
        [System.Windows.Forms.Application]::AddMessageFilter((New-Object HotKeyMessageFilter))
        $script:HotKeyFilterAdded = $true
    }
    [HotKeyMessageFilter]::HotKeyPressed = [System.Action[int]]{
        param($id)
        switch ($id) {
            1001 { Do-Toggle "hotkey" }
            1002 { if ($script:isRunning) { Stop-Toggling } else { Start-Toggling } }
            1003 {
                if ($script:isPaused) {
                    Start-Toggling
                } else {
                    $durations = Get-PauseDurations
                    if ($durations.Count -gt 0) { Pause-Toggling ([int]$durations[0]) }
                }
            }
        }
    }
    $map = @{
        1001 = $settings.HotkeyToggle
        1002 = $settings.HotkeyStartStop
        1003 = $settings.HotkeyPauseResume
    }
    $registered = 0
    $failed = 0
    foreach ($id in $map.Keys) {
        $parsed = Parse-Hotkey $map[$id]
        if ($parsed) {
            $ok = [HotKeyNative]::RegisterHotKey([IntPtr]::Zero, $id, [uint32]$parsed.Modifiers, [uint32]$parsed.Vk)
            if (-not $ok) {
                Write-Log "HOTKEY: Failed to register id=$id value=$($map[$id])." "WARN" $null "Hotkey"
                $failed++
            } else {
                $registered++
            }
        }
    }
    Write-Log "HOTKEY: Registration complete. Registered=$registered Failed=$failed." "INFO" $null "Hotkey"
    if ($failed -gt 0) {
        $script:HotkeyStatusText = "Failed ($failed)"
        if (-not $script:HotkeyWarned -and $notifyIcon) {
            Show-Balloon "Teams-Always-Green" "Some hotkeys failed to register. Open Settings > Hotkeys to adjust." ([System.Windows.Forms.ToolTipIcon]::Warning)
            $script:HotkeyWarned = $true
        }
    } elseif ($registered -gt 0) {
        $script:HotkeyStatusText = "Registered ($registered)"
    } else {
        $script:HotkeyStatusText = "Disabled"
    }
    Write-Log ("Metadata: Hotkeys={0}" -f $script:HotkeyStatusText) "DEBUG" $null "Hotkey"
}

function Unregister-Hotkeys {
    foreach ($id in 1001, 1002, 1003) {
        [HotKeyNative]::UnregisterHotKey([IntPtr]::Zero, $id) | Out-Null
    }
    Write-Log "HOTKEY: Unregistered." "INFO" $null "Hotkey"
    $script:HotkeyStatusText = "Unregistered"
}

function Get-SystemThemeIsDark {
    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    try {
        $props = Get-ItemProperty -Path $path -ErrorAction Stop
    } catch {
        return $false
    }
    if ($null -ne $props.SystemUsesLightTheme) {
        return ([int]$props.SystemUsesLightTheme -eq 0)
    }
    if ($null -ne $props.AppsUseLightTheme) {
        return ([int]$props.AppsUseLightTheme -eq 0)
    }
    return $false
}

function Get-ThemePalette([bool]$useDark) {
    if ($useDark) {
        return @{
            MenuBack = [System.Drawing.Color]::FromArgb(32, 32, 32)
            MenuFore = [System.Drawing.Color]::Gainsboro
            MenuHighlight = [System.Drawing.Color]::FromArgb(62, 62, 62)
            MenuHighlightText = [System.Drawing.Color]::Gainsboro
            MenuBorder = [System.Drawing.Color]::FromArgb(70, 70, 70)
            MenuSeparator = [System.Drawing.Color]::FromArgb(80, 80, 80)
            FormBack = [System.Drawing.Color]::FromArgb(30, 30, 30)
            ControlFore = [System.Drawing.Color]::Gainsboro
            InputBack = [System.Drawing.Color]::FromArgb(45, 45, 45)
            InputFore = [System.Drawing.Color]::Gainsboro
            ButtonBack = [System.Drawing.Color]::FromArgb(55, 55, 55)
            ButtonFore = [System.Drawing.Color]::Gainsboro
        }
    }
    return @{
        MenuBack = [System.Drawing.SystemColors]::Menu
        MenuFore = [System.Drawing.SystemColors]::MenuText
        MenuHighlight = [System.Drawing.SystemColors]::Highlight
        MenuHighlightText = [System.Drawing.SystemColors]::HighlightText
        MenuBorder = [System.Drawing.SystemColors]::ActiveBorder
        MenuSeparator = [System.Drawing.SystemColors]::ControlDark
        FormBack = [System.Drawing.SystemColors]::Control
        ControlFore = [System.Drawing.SystemColors]::ControlText
        InputBack = [System.Drawing.SystemColors]::Window
        InputFore = [System.Drawing.SystemColors]::WindowText
        ButtonBack = [System.Drawing.SystemColors]::Control
        ButtonFore = [System.Drawing.SystemColors]::ControlText
    }
}

function Apply-ThemeToMenuItem($item, $palette) {
    if ($null -eq $item) { return }
    $item.BackColor = $palette.MenuBack
    if ($item -is [System.Windows.Forms.ToolStripSeparator]) {
        $item.ForeColor = $palette.MenuSeparator
        return
    }
    if ($item -is [System.Windows.Forms.ToolStripMenuItem]) {
        if ($item.Name -ne "StatusStateItem") {
            $item.ForeColor = $palette.MenuFore
        }
        if ($item.DropDownItems.Count -gt 0) {
            $item.DropDown.BackColor = $palette.MenuBack
            $item.DropDown.ForeColor = $palette.MenuFore
            foreach ($child in $item.DropDownItems) {
                Apply-ThemeToMenuItem $child $palette
            }
        }
    }
}

function Apply-ThemeToMenu($menu, $palette) {
    if ($null -eq $menu) { return }
    $table = New-Object ThemeColorTable
    $table.MenuBackColor = $palette.MenuBack
    $table.MenuBorderColor = $palette.MenuBorder
    $table.MenuItemSelectedColor = $palette.MenuHighlight
    $table.MenuItemSelectedTextColor = $palette.MenuHighlightText
    $table.MenuItemPressedColor = $palette.MenuBack
    $table.SeparatorColor = $palette.MenuSeparator
    [ThemeColors]::MenuText = $palette.MenuFore
    $menu.Renderer = New-Object StatusMenuRenderer($table)
    $menu.BackColor = $palette.MenuBack
    $menu.ForeColor = $palette.MenuFore
    foreach ($item in $menu.Items) {
        Apply-ThemeToMenuItem $item $palette
    }
}

function Start-LogSummaryTimer {
    if ($script:LogLevel -ne "DEBUG") {
        Stop-LogSummaryTimer
        return
    }
    if (-not $script:LogSummaryTimer) {
        $script:LogSummaryTimer = New-Object System.Windows.Forms.Timer
        $script:LogSummaryTimer.Interval = [int]($script:LogSummaryIntervalMinutes * 60000)
        $script:LogSummaryTimer.Add_Tick({
            Invoke-SafeTimerAction "LogSummaryTimer" {
                if ($script:isShuttingDown -or $script:CleanupDone) {
                    Stop-LogSummaryTimer
                    return
                }
                if ($script:LogLevel -ne "DEBUG") {
                    Stop-LogSummaryTimer
                    return
                }
                $logSizeBytes = 0
                if (Test-Path $script:logPath) {
                    try { $logSizeBytes = (Get-Item -Path $script:logPath).Length } catch { $logSizeBytes = 0 }
                }
                Write-Log ("Log summary: Level={0} Writes={1} Rotations={2} LogSize={3} bytes Warns={4} Errors={5}" -f `
                    $script:LogLevel, $script:LogWriteCount, $script:LogRotationCount, $logSizeBytes, $script:WarningCount, $script:ErrorCount) "DEBUG" $null "Logging"
            }
        })
    }
    if (-not $script:LogSummaryTimer.Enabled) {
        $script:LogSummaryTimer.Start()
    }
}

function Stop-LogSummaryTimer {
    if ($script:LogSummaryTimer -and $script:LogSummaryTimer.Enabled) {
        $script:LogSummaryTimer.Stop()
    }
}

function Apply-ThemeToControl($control, $palette, [bool]$useDark) {
    if ($null -eq $control) { return }
    if (-not $useDark -and -not $script:ForceThemeApply) { return }
    $tagText = [string]$control.Tag
    if ($tagText -like "Status Color*" -or $tagText -like "Preview Status*") {
        foreach ($child in $control.Controls) {
            Apply-ThemeToControl $child $palette $useDark
        }
        return
    }
    if ($control -is [System.Windows.Forms.TextBox] -or
        $control -is [System.Windows.Forms.MaskedTextBox] -or
        $control -is [System.Windows.Forms.ComboBox] -or
        $control -is [System.Windows.Forms.ListBox] -or
        $control -is [System.Windows.Forms.NumericUpDown] -or
        $control -is [System.Windows.Forms.DateTimePicker]) {
        $control.BackColor = $palette.InputBack
        $control.ForeColor = $palette.InputFore
    } elseif ($control -is [System.Windows.Forms.Button]) {
        $control.BackColor = $palette.ButtonBack
        $control.ForeColor = $palette.ButtonFore
        $control.UseVisualStyleBackColor = $false
    } else {
        $control.BackColor = $palette.FormBack
        $control.ForeColor = $palette.ControlFore
    }
    foreach ($child in $control.Controls) {
        Apply-ThemeToControl $child $palette $useDark
    }
}

function Update-ThemePreference {
    $mode = "Auto"
    if (Get-Variable -Name settings -Scope Script -ErrorAction SilentlyContinue) {
        if ($settings -and ($settings.PSObject.Properties.Name -contains "ThemeMode")) {
            $mode = [string]$settings.ThemeMode
        }
    }
    $mode = $mode.Trim()
    if ([string]::IsNullOrWhiteSpace($mode)) { $mode = "Auto" }
    if ($mode -eq "Auto") {
        $now = Get-Date
        if ($script:LastThemeCheckTime -and (($now - $script:LastThemeCheckTime).TotalSeconds -lt 1)) { return }
        $script:LastThemeCheckTime = $now
    }
    $isDark = $false
    $forceApply = $false
    $palette = $null
    switch ($mode.ToUpperInvariant()) {
        "DARK" { $isDark = $true }
        "LIGHT" { $isDark = $false }
        "HIGH CONTRAST" {
            $isDark = $false
            $forceApply = $true
            $palette = @{
                MenuBack = [System.Drawing.SystemColors]::Window
                MenuFore = [System.Drawing.SystemColors]::WindowText
                MenuHighlight = [System.Drawing.SystemColors]::Highlight
                MenuHighlightText = [System.Drawing.SystemColors]::HighlightText
                MenuBorder = [System.Drawing.SystemColors]::ActiveBorder
                MenuSeparator = [System.Drawing.SystemColors]::ControlDark
                FormBack = [System.Drawing.SystemColors]::Window
                ControlFore = [System.Drawing.SystemColors]::WindowText
                InputBack = [System.Drawing.SystemColors]::Window
                InputFore = [System.Drawing.SystemColors]::WindowText
                ButtonBack = [System.Drawing.SystemColors]::Control
                ButtonFore = [System.Drawing.SystemColors]::ControlText
            }
        }
        default { $isDark = Get-SystemThemeIsDark }
    }
    if ($script:LastThemeIsDark -ne $isDark -or $null -eq $script:ThemePalette -or $script:ForceThemeApply -ne $forceApply) {
        $script:UseDarkTheme = $isDark
        $script:ForceThemeApply = $forceApply
        $script:ThemePalette = if ($palette) { $palette } else { Get-ThemePalette $script:UseDarkTheme }
        Apply-ThemeToMenu $contextMenu $script:ThemePalette
        $script:LastThemeIsDark = $isDark
    }
}

function New-StateIcon([System.Drawing.Icon]$baseIcon, [System.Drawing.Color]$stateColor) {
    if ($null -eq $baseIcon) { return $null }
    $bitmap = $baseIcon.ToBitmap()
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $brush = New-Object System.Drawing.SolidBrush($stateColor)
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::Black, 1)
    try {
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $size = [int][Math]::Max(4, [Math]::Floor($bitmap.Width * 0.35))
        $x = [int]($bitmap.Width - $size - 1)
        $y = [int]($bitmap.Height - $size - 1)
        $graphics.FillEllipse($brush, $x, $y, $size, $size)
        $graphics.DrawEllipse($pen, $x, $y, $size, $size)
        $iconHandle = $bitmap.GetHicon()
        $icon = [System.Drawing.Icon]::FromHandle($iconHandle)
        $cloned = $icon.Clone()
        [IconHelpers]::DestroyIcon($iconHandle) | Out-Null
        $icon.Dispose()
        return $cloned
    } finally {
        $pen.Dispose()
        $brush.Dispose()
        $graphics.Dispose()
        $bitmap.Dispose()
    }
}

function Update-NotifyIconState {
    if ($script:isShuttingDown) { return }
    if ($null -eq $notifyIcon) { return }
    if (-not $script:BaseNotifyIcon) { $script:BaseNotifyIcon = $notifyIcon.Icon }
    if (-not $script:StatusStateColor) {
        $script:StatusStateColor = Get-StatusStateColor $script:StatusStateText
    }
    $newIcon = New-StateIcon $script:BaseNotifyIcon $script:StatusStateColor
    if ($newIcon) {
        if ($script:OverlayIcon) { $script:OverlayIcon.Dispose() }
        $script:OverlayIcon = $newIcon
        $notifyIcon.Icon = $script:OverlayIcon
    }
}

function Process-CommandFile {
    if (-not (Test-Path $script:CommandFilePath)) { return }
    $commands = @()
    try {
        $info = Get-Item -Path $script:CommandFilePath -ErrorAction SilentlyContinue
        if ($info -and $info.Length -gt $script:CommandFileMaxBytes) {
            Write-Log ("Command file too large ({0} bytes). Ignoring." -f $info.Length) "WARN" $null "CommandFile"
            Remove-Item -Path $script:CommandFilePath -Force -ErrorAction SilentlyContinue
            return
        }
        $commands = Get-Content -Path $script:CommandFilePath -ErrorAction SilentlyContinue
        Remove-Item -Path $script:CommandFilePath -Force -ErrorAction SilentlyContinue
    } catch {
        return
    }
    if ($commands.Count -gt $script:CommandFileMaxLines) {
        $commands = $commands | Select-Object -First $script:CommandFileMaxLines
        Write-Log "Command file truncated to max line count." "WARN" $null "CommandFile"
    }
    foreach ($command in $commands) {
        if ([string]::IsNullOrWhiteSpace($command)) { continue }
        $normalized = $command.Trim().ToUpperInvariant()
        if (-not ($script:CommandFileAllowList -contains $normalized)) {
            Write-Log ("Ignoring unknown command: {0}" -f $normalized) "WARN" $null "CommandFile"
            continue
        }
        switch ($normalized) {
            "TEST_TOGGLE" {
                try {
                    Do-Toggle "settings-test"
                    Write-Log "Test toggle requested from settings." "INFO" $null "Settings-Dialog"
                } catch {
                    Write-Log "Test toggle failed." "ERROR" $_.Exception "Settings-Dialog"
                }
            }
            "HOTKEY_TOGGLE" {
                try {
                    Set-LastUserAction "Test Hotkey: Toggle Now" "Settings"
                    Write-Log "UI: Simulated hotkey: Toggle Now" "DEBUG" $null "Hotkey-Test"
                    Do-Toggle "hotkey-test"
                } catch {
                    Write-Log "Hotkey test (Toggle Now) failed." "ERROR" $_.Exception "Hotkey-Test"
                }
            }
            "HOTKEY_STARTSTOP" {
                try {
                    Set-LastUserAction "Test Hotkey: Start/Stop" "Settings"
                    Write-Log "UI: Simulated hotkey: Start/Stop" "DEBUG" $null "Hotkey-Test"
                    if ($script:isRunning) { Stop-Toggling } else { Start-Toggling }
                } catch {
                    Write-Log "Hotkey test (Start/Stop) failed." "ERROR" $_.Exception "Hotkey-Test"
                }
            }
            "HOTKEY_PAUSERESUME" {
                try {
                    Set-LastUserAction "Test Hotkey: Pause/Resume" "Settings"
                    Write-Log "UI: Simulated hotkey: Pause/Resume" "DEBUG" $null "Hotkey-Test"
                    if ($script:isPaused) {
                        Start-Toggling
                    } else {
                        $durations = Get-PauseDurations
                        if ($durations.Count -gt 0) { Pause-Toggling ([int]$durations[0]) }
                    }
                } catch {
                    Write-Log "Hotkey test (Pause/Resume) failed." "ERROR" $_.Exception "Hotkey-Test"
                }
            }
            "DEBUG_MODE" {
                try {
                    Enable-DebugMode
                } catch {
                    Write-Log "Failed to enable debug mode." "ERROR" $_.Exception "Logging"
                }
            }
            "LOG_SNAPSHOT" {
                try {
                    Write-LogSnapshot
                } catch {
                    Write-Log "Failed to write log snapshot." "ERROR" $_.Exception "Log-Snapshot"
                }
            }
            "CLEAR_LOG" {
                try {
                    Clear-LogFile
                } catch {
                    Write-Log "Failed to clear log file." "ERROR" $_.Exception "Clear-Log"
                }
            }
        }
    }
}

function Enable-DebugMode {
    $script:PreviousLogLevel = $script:LogLevel
    $script:LogLevel = "DEBUG"
    if (-not $script:PreviousLogCategories) {
        $script:PreviousLogCategories = @{}
        foreach ($key in $script:LogCategories.Keys) {
            $script:PreviousLogCategories[$key] = $script:LogCategories[$key]
        }
    }
    $script:DebugForceAllCategories = $true
    $script:DebugModeUntil = (Get-Date).AddMinutes(10)
    $script:DebugModeTimer.Start()
    $debugStatus = Get-DebugModeStatusText
    if ($script:DebugModeStatus) { $script:DebugModeStatus.Text = $debugStatus }
    if ($script:SettingsDebugModeStatus) { $script:SettingsDebugModeStatus.Text = $debugStatus }
    Update-LogLevelMenuChecks
    if (Get-Command -Name Start-LogSummaryTimer -ErrorAction SilentlyContinue) { Start-LogSummaryTimer }
    try { Request-StatusUpdate } catch { }
    Write-Log "Debug mode enabled for 10 minutes (all categories forced on)." "INFO" $null "Logging"
}

function Disable-DebugMode {
    $script:DebugModeUntil = $null
    if ($script:PreviousLogLevel) {
        $script:LogLevel = $script:PreviousLogLevel
        $script:PreviousLogLevel = $null
    }
    if ($script:PreviousLogCategories) {
        foreach ($key in $script:PreviousLogCategories.Keys) {
            if ($script:LogCategories.ContainsKey($key)) {
                $script:LogCategories[$key] = $script:PreviousLogCategories[$key]
            }
        }
        $script:PreviousLogCategories = $null
    }
    $script:DebugForceAllCategories = $false
    if ($script:DebugModeTimer) { $script:DebugModeTimer.Stop() }
    if ($script:DebugModeStatus) { $script:DebugModeStatus.Text = "Off" }
    if ($script:SettingsDebugModeStatus) { $script:SettingsDebugModeStatus.Text = "Off" }
    try { Request-StatusUpdate } catch { }
}

function Write-LogSnapshot {
    $summary = "[STATE] Running=$script:isRunning Paused=$script:isPaused Schedule=$(Format-ScheduleStatus) Interval=$($settings.IntervalSeconds)s Profile=$($settings.ActiveProfile)"
    Write-Log $summary "INFO" $null "Log-Snapshot"
}

function Clear-LogFile {
    if (-not $script:LogPath) { return }
    "" | Set-Content -Path $script:LogPath -Encoding UTF8
    Write-Log "Log file cleared." "INFO" $null "Clear-Log"
}

function Reset-SafeMode {
    $script:safeModeActive = $false
    $script:toggleFailCount = 0
    Request-StatusUpdate
    Write-Log "Safe Mode reset." "INFO" $null "SafeMode"
}

function Invoke-SettingsShownStep([string]$name, [ScriptBlock]$action) {
    try {
        & $action
    } catch {
        Write-Log ("Settings shown step failed: {0}" -f $name) "WARN" $_.Exception "Settings-Dialog"
    }
}

function Recover-Now {
    $script:safeModeActive = $false
    $script:toggleFailCount = 0
    try { Register-Hotkeys } catch { }
    try { Update-NextToggleTime } catch { }
    Request-StatusUpdate
    Write-Log "Recovery requested: Safe Mode cleared and hotkeys re-registered." "INFO" $null "SafeMode"
    try {
        Show-Balloon "Teams Always Green" "Recovery complete. Safe Mode cleared and hotkeys re-registered." ([System.Windows.Forms.ToolTipIcon]::Info)
    } catch {
    }
}

function Update-LogLevelMenuChecks {
    if ($null -eq $logLevelMenu) { return }
    foreach ($item in $logLevelMenu.DropDownItems) {
        if ($item -is [System.Windows.Forms.ToolStripMenuItem]) {
            $item.Checked = ($item.Text -eq $script:LogLevel)
        }
    }
}

function Set-LogLevel([string]$level, [string]$source = "tray") {
    if ([string]::IsNullOrWhiteSpace($level)) { return }
    $upper = $level.ToUpperInvariant()
    if (-not $script:LogLevels.ContainsKey($upper)) { return }
    $previous = $script:LogLevel
    Set-LastUserAction "Log Level -> $upper" "Tray"
    $settings.LogLevel = $upper
    $script:LogLevel = $upper
    if ($script:DebugModeUntil) {
        Disable-DebugMode
    }
    Write-Log ("UI: Log level change requested: {0} -> {1} (source={2})" -f $previous, $upper, $source) "DEBUG" $null "LogLevel" -Force
    Save-Settings $settings
    Update-LogLevelMenuChecks
    Write-Log "UI: Log level set to $upper (source=$source)." "DEBUG" $null "LogLevel" -Force
    Write-Log "=======================================================================" "INFO" $null "LogLevel"
    Write-Log ("LOG LEVEL CHANGED: {0} -> {1} (source={2})" -f $previous, $upper, $source) "INFO" $null "LogLevel" -Force
    Write-Log "=======================================================================" "INFO" $null "LogLevel"
    if (Get-Command -Name Start-LogSummaryTimer -ErrorAction SilentlyContinue) { Start-LogSummaryTimer }
}

function Get-StatusStateColor([string]$state) {
    $runningColor = Convert-ColorString ([string]$settings.StatusColorRunning) ([System.Drawing.Color]::Green)
    $pausedColor = Convert-ColorString ([string]$settings.StatusColorPaused) ([System.Drawing.Color]::DarkGoldenrod)
    $stoppedColor = Convert-ColorString ([string]$settings.StatusColorStopped) ([System.Drawing.Color]::Red)
    if ($state -like "Paused*") { return $pausedColor }
    if ($state -eq "Running") { return $runningColor }
    return $stoppedColor
}

function Update-StatusText {
    if ($script:isShuttingDown -or $script:StatusUpdateInProgress) { return }
    $script:StatusUpdateInProgress = $true
    $script:Now = Get-Date
    try {
        Update-ScheduleBlock | Out-Null
        if ($script:isPaused) {
            $state = "Paused"
        } elseif ($script:isRunning -and $script:isScheduleSuspended) {
            $state = "Paused (Schedule Suspend)"
        } elseif ($script:isRunning -and $script:isScheduleBlocked) {
            $state = "Paused (Schedule)"
        } else {
            $state = if ($script:isRunning) { "Running" } else { "Stopped" }
        }
        $actionLabel = Get-LastUserActionLabel
        if ($actionLabel -and $actionLabel -ne $script:LastActionLogged) {
            Write-Log ("UI: Last action: {0}" -f $actionLabel) "DEBUG" $null "Action"
            $script:LastActionLogged = $actionLabel
        }
        $script:StatusStateColor = Get-StatusStateColor $state
        $showSeconds = ([int]$settings.IntervalSeconds -lt 60)
        $lastText = Format-TimeOrNever $script:lastToggleTime $showSeconds
        $nextText = Format-NextInfo
        $pauseUntilText = Format-PauseUntilText
        if ($script:isPaused) { $nextText = "Paused" }
        $snapshot = "$state|$($settings.IntervalSeconds)|$($script:tickCount)|$lastText|$nextText|$pauseUntilText"
        $now = $script:Now
        if ($script:LastStatusSnapshot -eq $snapshot -and (($now - $script:LastStatusUpdateTime).TotalMilliseconds -lt 500)) {
            return
        }
        $script:LastStatusSnapshot = $snapshot
        $script:LastStatusUpdateTime = $now
    if ($script:lastState -ne $state) {
        if (-not [string]::IsNullOrWhiteSpace($script:lastState)) {
            Write-Log "State changed from $($script:lastState) to $state. Next=$nextText" "INFO" $null "State"
        }
        $script:lastState = $state
    }
        $script:StatusStateText = $state
        $stateText = Localize-StatusValue $state
        $displayLast = Localize-StatusValue $lastText
        $displayNext = Localize-StatusValue $nextText
        $displayPause = Localize-StatusValue $pauseUntilText
        $statusLineState.Text = ((L "Status: {0}") -f $stateText)
        $statusLineState.Tag = $state
        $statusLineState.ForeColor = $script:StatusStateColor
        $statusLineInterval.Text = ((L "Interval: {0}s") -f $settings.IntervalSeconds)
        $statusLineToggles.Text = ((L "Toggles: {0}") -f $script:tickCount)
        $statusLineLast.Text = ((L "Last: {0}") -f $displayLast)
        $statusLineNext.Text = ((L "Next: {0}") -f $displayNext)
        $statusLinePauseUntil.Text = ((L "Paused Until: {0}") -f $displayPause)
        $scheduleText = Format-ScheduleStatus
        $displaySchedule = Localize-StatusValue $scheduleText
        if ($statusLineSchedule) { $statusLineSchedule.Text = ((L "Schedule: {0}") -f $displaySchedule) }
        if ($statusLineSafeMode) { $statusLineSafeMode.Text = ((L "Safe Mode: {0}") -f (Localize-StatusValue ($(if ($script:safeModeActive) { "On" } else { "Off" })))) }
        $statusLineLast.Visible = -not ([string]::IsNullOrWhiteSpace($lastText) -or $lastText -eq "Never")
        $statusLineNext.Visible = -not ([string]::IsNullOrWhiteSpace($nextText) -or $nextText -eq "N/A")
        $statusLinePauseUntil.Visible = -not ([string]::IsNullOrWhiteSpace($pauseUntilText) -or $pauseUntilText -eq "N/A" -or $pauseUntilText -eq "Not Paused")
        if ($statusLineSchedule) { $statusLineSchedule.Visible = -not ([string]::IsNullOrWhiteSpace($scheduleText) -or $scheduleText -eq "Off") }
        if ($statusLineSafeMode) { $statusLineSafeMode.Visible = $script:safeModeActive }
        Update-TrayLabels
        if ($startStopItem) { $startStopItem.Enabled = -not $script:safeModeActive }
        if ($toggleNowItem) { $toggleNowItem.Enabled = -not $script:safeModeActive }
        if ($pauseMenu) { $pauseMenu.Enabled = $script:isRunning }
        if ($runOnceNowItem) { $runOnceNowItem.Enabled = -not $script:isRunning }
        if ($script:pauseResumeItem) { $script:pauseResumeItem.Enabled = $script:isPaused }
        if ($script:pauseUntilItem) { $script:pauseUntilItem.Enabled = -not $script:isPaused }
        if ($resetSafeModeItem) { $resetSafeModeItem.Visible = $script:safeModeActive }
        if ($recoverNowItem) { $recoverNowItem.Visible = $script:safeModeActive }
        if (Get-Command -Name Update-StatusBadges -ErrorAction SilentlyContinue) { Update-StatusBadges }
        Update-NotifyIconState
        Update-NotifyIconText $state
        Write-StatusSnapshot $state $lastText $nextText $pauseUntilText $scheduleText
    } finally {
        $script:Now = $null
        $script:StatusUpdateInProgress = $false
    }
}

function Update-StatusBadges {
    $badgesVar = Get-Variable -Name SettingsStatusBadges -Scope Script -ErrorAction SilentlyContinue
    if (-not $badgesVar -or -not $badgesVar.Value) { return }
    $badges = $badgesVar.Value
    $isPaused = $script:isPaused -or $script:isScheduleBlocked -or $script:isScheduleSuspended
    $isRunning = $script:isRunning -and -not $isPaused
    $isStopped = -not $script:isRunning -and -not $script:isPaused
    $showSchedule = [bool]$settings.ScheduleEnabled -or $script:isScheduleBlocked -or $script:isScheduleSuspended
    $showDebug = ($script:LogLevel -eq "DEBUG") -or [bool]$script:DebugModeUntil
    $showSafeMode = $script:safeModeActive
    $runningColor = Convert-ColorString ([string]$settings.StatusColorRunning) ([System.Drawing.Color]::Green)
    $pausedColor = Convert-ColorString ([string]$settings.StatusColorPaused) ([System.Drawing.Color]::DarkGoldenrod)
    $stoppedColor = Convert-ColorString ([string]$settings.StatusColorStopped) ([System.Drawing.Color]::Red)
    $scheduleColor = [System.Drawing.Color]::SteelBlue
    $debugColor = [System.Drawing.Color]::MediumPurple
    $safeModeColor = [System.Drawing.Color]::DarkOrange

    $applyBadge = {
        param($badge, [bool]$visible, [System.Drawing.Color]$color)
        if (-not $badge) { return }
        $badge.Visible = $visible
        if ($visible) {
            $badge.BackColor = $color
            $badge.ForeColor = [System.Drawing.Color]::White
        }
    }

    & $applyBadge $badges.Running $isRunning $runningColor
    & $applyBadge $badges.Paused $isPaused $pausedColor
    & $applyBadge $badges.Stopped $isStopped $stoppedColor
    & $applyBadge $badges.Schedule $showSchedule $scheduleColor
    & $applyBadge $badges.Debug $showDebug $debugColor
    & $applyBadge $badges.SafeMode $showSafeMode $safeModeColor
}

function Get-StatusBalloonText {
    $state = if ([string]::IsNullOrWhiteSpace($script:StatusStateText)) { "Unknown" } else { $script:StatusStateText }
    $showSeconds = ([int]$settings.IntervalSeconds -lt 60)
    $lastText = Format-TimeOrNever $script:lastToggleTime $showSeconds
    $nextText = Format-NextInfo
    $pauseUntilText = Format-PauseUntilText
    $scheduleText = Format-ScheduleStatus
    $safeModeText = $(if ($script:safeModeActive) { "On" } else { "Off" })
    return "Status: $state`nInterval: $($settings.IntervalSeconds)s`nToggles: $($script:tickCount)`nLast: $lastText`nNext: $nextText`nPaused Until: $pauseUntilText`nSchedule: $scheduleText`nSafe Mode: $safeModeText"
}

function Get-KeyboardStatus {
    try {
        $caps = [System.Windows.Forms.Control]::IsKeyLocked([System.Windows.Forms.Keys]::CapsLock)
        $num = [System.Windows.Forms.Control]::IsKeyLocked([System.Windows.Forms.Keys]::NumLock)
        $scroll = [System.Windows.Forms.Control]::IsKeyLocked([System.Windows.Forms.Keys]::Scroll)
        return ("Caps:{0} Num:{1} Scroll:{2}" -f ($(if ($caps) { "On" } else { "Off" })), ($(if ($num) { "On" } else { "Off" })), ($(if ($scroll) { "On" } else { "Off" })))
    } catch {
        return "N/A"
    }
}

function Write-StatusSnapshot([string]$state, [string]$lastText, [string]$nextText, [string]$pauseUntilText, [string]$scheduleText) {
    try {
        if (-not (Test-Path $script:MetaDir)) {
            New-Item -ItemType Directory -Path $script:MetaDir -Force | Out-Null
        }
        $nextCountdown = "N/A"
        if ($script:nextToggleTime) {
            $remaining = [int][Math]::Ceiling(($script:nextToggleTime - (Get-Date)).TotalSeconds)
            if ($remaining -lt 0) { $remaining = 0 }
            $nextCountdown = "$remaining s ($($script:nextToggleTime.ToString("T")))"
        }
        $payload = [ordered]@{
            UpdatedUtc   = (Get-Date).ToUniversalTime().ToString("o")
            Status       = $state
            Interval     = [int]$settings.IntervalSeconds
            Toggles      = [int]$script:tickCount
            LastToggle   = $lastText
            NextToggle   = $nextText
            NextToggleIn = $nextCountdown
            PauseUntil   = $pauseUntilText
            Schedule     = $scheduleText
            SafeMode     = $(if ($script:safeModeActive) { "On" } else { "Off" })
            Keyboard     = Get-KeyboardStatus
            ActiveProfile = $settings.ActiveProfile
            HotkeyStatus = $(if ($script:HotkeyStatusText) { $script:HotkeyStatusText } else { "Unknown" })
            DebugMode    = Get-DebugModeStatusText
        }
        $json = $payload | ConvertTo-Json -Depth 3
        Set-Content -Path $script:StatusFilePath -Value $json -Encoding UTF8
    } catch {
        Write-Log "Failed to write status snapshot." "WARN" $_.Exception "Status"
    }
}

function Request-StatusUpdate {
    if ($script:StatusUpdatePending) { return }
    $script:StatusUpdatePending = $true
    $script:StatusUpdateDebounceTimer.Start()
}

function Apply-SettingsRuntime {
    $settings.IntervalSeconds = Normalize-IntervalSeconds ([int]$settings.IntervalSeconds)
    $timer.Interval = [int]$settings.IntervalSeconds * 1000
    if (-not $script:DebugModeUntil) {
        $script:LogLevel = [string]$settings.LogLevel
        if ([string]::IsNullOrWhiteSpace($script:LogLevel)) { $script:LogLevel = "INFO" }
        $script:LogLevel = $script:LogLevel.ToUpperInvariant()
        if (-not $script:LogLevels.ContainsKey($script:LogLevel)) { $script:LogLevel = "INFO" }
    }
    $settings.DateTimeFormat = Normalize-DateTimeFormat ([string]$settings.DateTimeFormat)
    $script:DateTimeFormat = $settings.DateTimeFormat
    $script:UseSystemDateTimeFormat = [bool]$settings.UseSystemDateTimeFormat
    $script:SystemDateTimeFormatMode = if ([string]::IsNullOrWhiteSpace([string]$settings.SystemDateTimeFormatMode)) { "Short" } else { [string]$settings.SystemDateTimeFormatMode }
    Update-LogLevelMenuChecks
    if (Get-Command -Name Start-LogSummaryTimer -ErrorAction SilentlyContinue) { Start-LogSummaryTimer }
    $script:LogMaxBytes = [int]$settings.LogMaxBytes
    $script:LogMaxTotalBytes = [long]$settings.LogMaxTotalBytes
    if ($script:LogMaxTotalBytes -le 0) { $script:LogMaxTotalBytes = 20971520 }
    if (-not $settings.SafeModeEnabled) {
        $script:safeModeActive = $false
        $script:toggleFailCount = 0
    }
    Update-LogCategorySettings
    Register-Hotkeys
    Rebuild-PauseMenu
    Update-TrayLabels
    Update-NextToggleTime
    Request-StatusUpdate
    if ($updateQuickSettingsChecks) { & $updateQuickSettingsChecks }
    if ($updateProfilesMenu) { & $updateProfilesMenu }
}

function Show-Balloon([string]$title, [string]$text, [System.Windows.Forms.ToolTipIcon]$icon) {
    if ($script:isShuttingDown) { return }
    if (-not $settings.QuietMode -and -not $settings.DisableBalloonTips) {
        $notifyIcon.ShowBalloonTip(1200, $title, $text, $icon)
    }
}

function Show-FirstRunToast {
    if (-not $settings.ShowFirstRunToast) { return }
    if ($settings.FirstRunToastShown) { return }
    $settings.FirstRunToastShown = $true
    Save-Settings $settings
    Write-Log "First-run tips shown." "INFO" $null "Startup"
    Show-Balloon "Teams-Always-Green" "Tip: Right-click the tray icon to start, pause, or open Settings." ([System.Windows.Forms.ToolTipIcon]::Info)
}

function Do-Toggle([string]$source) {
    if ($script:isToggling) { return }
    $script:isToggling = $true
    try {
        Invoke-ScrollLockToggleInternal
        $script:toggleFailCount = 0
        if ($null -eq $settings.ToggleCount) { $settings.ToggleCount = 0 }
        $settings.ToggleCount++
        $script:tickCount++
        $script:lastToggleTime = Get-Date
        $script:LastToggleResult = "Success"
        $script:LastToggleResultTime = $script:lastToggleTime
        $script:LastToggleError = $null
        Update-FunStatsOnToggle $script:lastToggleTime
        if ($script:isRunning) { Update-NextToggleTime }
        Request-StatusUpdate
        Save-Stats
        Write-Log "Toggle succeeded (source=$source). ToggleCount=$($script:tickCount)" "INFO" $null "Do-Toggle"
    } catch {
        Write-Log "Toggle failed (source=$source)." "ERROR" $_.Exception "Do-Toggle"
        $script:toggleFailCount++
        $script:LastToggleResult = "Failed"
        $script:LastToggleResultTime = Get-Date
        $script:LastToggleError = $_.Exception.Message
        if ($settings.SafeModeEnabled -and $script:toggleFailCount -ge [int]$settings.SafeModeFailureThreshold) {
            $script:safeModeActive = $true
            Stop-Toggling
            Request-StatusUpdate
            Show-Balloon "Teams-Always-Green" "Safe Mode enabled after repeated failures." ([System.Windows.Forms.ToolTipIcon]::Warning)
        }
        if ($source -ne "timer") {
            [System.Windows.Forms.MessageBox]::Show(
                "Error toggling Scroll Lock:`n$($_.Exception.Message)",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
    } finally {
        $script:isToggling = $false
    }
}

# --- Timer (interval set by settings) ---
$timer = New-Object System.Windows.Forms.Timer
$settings.IntervalSeconds = Normalize-IntervalSeconds ([int]$settings.IntervalSeconds)
$timer.Interval = [int]$settings.IntervalSeconds * 1000
$timer.Add_Tick({
    Invoke-SafeTimerAction "MainToggleTimer" {
        if ($script:isShuttingDown -or $script:CleanupDone) { return }
        if ($script:isTicking) {
            Write-LogThrottled "Timer" "Timer tick skipped (re-entrancy guard)." "WARN" 5
            return
        }
        $script:isTicking = $true
        try {
            Update-PeakWorkingSet
            if (Update-ScheduleBlock) {
                Request-StatusUpdate
                return
            }
            Do-Toggle "timer"
        } finally {
            $script:isTicking = $false
        }
    }
})

function Start-Toggling {
    if ($script:isRunning -and -not $script:isPaused) { return }
    if ($script:safeModeActive) {
        [System.Windows.Forms.MessageBox]::Show(
            "Safe Mode is active due to repeated failures. Use 'Reset Safe Mode' from the tray menu to resume.",
            "Safe Mode",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return
    }
    $wasPaused = $script:isPaused
    $timer.Interval = [int]$settings.IntervalSeconds * 1000
    $timer.Start()
    $script:isRunning = $true
    $script:isPaused = $false
    $script:pauseUntil = $null
    $settings.PauseUntil = $null
    Save-Settings $settings
    Update-NextToggleTime
    if (Update-ScheduleBlock) {
        $timer.Stop()
    }
    Request-StatusUpdate
    if ($startStopItem) { $startStopItem.Enabled = $true }
    if (-not $script:isShuttingDown -and $notifyIcon) { $notifyIcon.Text = "Teams-Always-Green (Running)" }
    Write-Log "[STATE] Toggling started. IntervalSeconds=$($settings.IntervalSeconds)" "INFO" $null "Start-Toggling"
    if ($wasPaused) {
        Write-Log "[STATE] Resumed from pause." "INFO" $null "Start-Toggling"
    }
    Log-StateSummary "Start-Toggling"
    Show-Balloon "Teams-Always-Green" "Started." ([System.Windows.Forms.ToolTipIcon]::Info)
    Update-TrayLabels
}

function Stop-Toggling {
    if (-not $script:isRunning -and -not $script:isPaused) { return }
    $timer.Stop()
    $script:isRunning = $false
    $script:isPaused = $false
    $script:pauseUntil = $null
    $settings.PauseUntil = $null
    Save-Settings $settings
    Update-NextToggleTime
    Request-StatusUpdate
    if ($startStopItem) { $startStopItem.Enabled = $true }
    if (-not $script:isShuttingDown -and $notifyIcon) { $notifyIcon.Text = "Teams-Always-Green (Stopped)" }
    Write-Log "[STATE] Toggling stopped." "INFO" $null "Stop-Toggling"
    Log-StateSummary "Stop-Toggling"
    Show-Balloon "Teams-Always-Green" "Stopped." ([System.Windows.Forms.ToolTipIcon]::Info)
    Update-TrayLabels
}

function Pause-Toggling([int]$minutes) {
    if (-not $script:isRunning) {
        [System.Windows.Forms.MessageBox]::Show(
            "Start the toggler before pausing.",
            "Not running",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        return
    }
    $timer.Stop()
    $script:isPaused = $true
    $script:pauseUntil = (Get-Date).AddMinutes($minutes)
    $settings.PauseUntil = $script:pauseUntil.ToString("o")
    Save-Settings $settings
    Update-FunStatsOnPause $minutes
    Request-StatusUpdate
    if (-not $script:isShuttingDown -and $notifyIcon) { $notifyIcon.Text = "Teams-Always-Green (Paused)" }
    Write-Log "[STATE] Paused for $minutes minutes." "INFO" $null "Pause-Toggling"
    Log-StateSummary "Pause-Toggling"
    Show-Balloon "Teams-Always-Green" "Paused for $minutes minutes." ([System.Windows.Forms.ToolTipIcon]::Info)
}

function Pause-UntilDate([DateTime]$until) {
    if (-not $script:isRunning) {
        [System.Windows.Forms.MessageBox]::Show(
            "Start the toggler before pausing.",
            "Not running",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        return
    }
    if ($until -le (Get-Date)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Pause time must be in the future.",
            "Invalid time",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        return
    }
    $timer.Stop()
    $script:isPaused = $true
    $script:pauseUntil = $until
    $settings.PauseUntil = $script:pauseUntil.ToString("o")
    Save-Settings $settings
    $pauseMinutes = [int][Math]::Round(($script:pauseUntil - (Get-Date)).TotalMinutes, 0)
    if ($pauseMinutes -gt 0) { Update-FunStatsOnPause $pauseMinutes }
    Request-StatusUpdate
    if (-not $script:isShuttingDown -and $notifyIcon) { $notifyIcon.Text = "Teams-Always-Green (Paused)" }
    Write-Log ("[STATE] Paused until {0}." -f (Format-DateTime $script:pauseUntil)) "INFO" $null "Pause-Until"
    Log-StateSummary "Pause-Until"
    Show-Balloon "Teams-Always-Green" ("Paused until {0}." -f (Format-DateTime $script:pauseUntil)) ([System.Windows.Forms.ToolTipIcon]::Info)
}

# --- Tray menu + UI dialogs (dot-sourced) ---

function Soft-Restart {
    if ($script:CleanupDone -or $script:isShuttingDown) { return }
    Write-Log "Tray action: Soft Restart" "DEBUG" $null "Tray-Action"
    Write-Log "" "INFO" $null "Restart"
    Write-Log "=======================================================================" "INFO" $null "Restart"
    Write-Log "=                           APP SOFT RESTART                           =" "INFO" $null "Restart"
    Write-Log "=======================================================================" "INFO" $null "Restart"

    $wasRunning = $script:isRunning
    $wasPaused = $script:isPaused

    try { Flush-SettingsSave } catch { }
    try { Flush-LogBuffer } catch { }

    try { $timer.Stop() } catch { }
    try { $pauseTimer.Stop() } catch { }
    try { $watchdogTimer.Stop() } catch { }
    try { $statusUpdateTimer.Stop() } catch { }

    Unregister-Hotkeys
    Apply-SettingsRuntime
    Refresh-TrayMenu

    try { $pauseTimer.Start() } catch { }
    try { $watchdogTimer.Start() } catch { }
    try { $statusUpdateTimer.Start() } catch { }

    if ($wasRunning -and -not $wasPaused) {
        Start-Toggling
    } elseif ($timer.Enabled) {
        $timer.Stop()
    }

    Request-StatusUpdate
    Write-Log "Soft restart completed." "INFO" $null "Restart"
}

Sync-SettingsReference $settings

# Load tray menu + settings/history dialogs after core functions are defined
. "$PSScriptRoot\Tray\Menu.ps1"
. "$PSScriptRoot\UI\SettingsDialog.ps1"
. "$PSScriptRoot\UI\HistoryDialog.ps1"

if (-not (Get-Command Set-MenuTooltip -ErrorAction SilentlyContinue)) {
    function Set-MenuTooltip([System.Windows.Forms.ToolStripItem]$item, [string]$text) {
        if (-not $item) { return }
        $item.ToolTipText = $text
    }
}

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

$historyItem = New-Object System.Windows.Forms.ToolStripMenuItem("History")
Set-MenuTooltip $historyItem "View recent toggle history."
$historyItem.Add_Click({
    Invoke-TrayAction "History" { Show-HistoryDialog }
})

$restartItem = New-Object System.Windows.Forms.ToolStripMenuItem("Restart")
Set-MenuTooltip $restartItem "Restart the app."
$restartItem.Add_Click({
    if ($script:CleanupDone) { return }
    Write-Log "Tray action: Restart" "DEBUG" $null "Tray-Action"
    Write-Log "" "INFO" $null "Restart"
    Write-Log "=======================================================================" "INFO" $null "Restart"
    Write-Log "=                             APP RESTART                             =" "INFO" $null "Restart"
    Write-Log "=======================================================================" "INFO" $null "Restart"
    Log-ShutdownSummary "Restart"
    Set-ShutdownMarker "clean"
    try { Flush-LogBuffer } catch { }
    $script:isShuttingDown = $true
    Flush-SettingsSave
    Flush-LogBuffer
    $statusUpdateTimer.Stop()
    $pauseTimer.Stop()
    $watchdogTimer.Stop()
    if ($script:LogSummaryTimer) {
        $script:LogSummaryTimer.Stop()
        $script:LogSummaryTimer.Dispose()
        $script:LogSummaryTimer = $null
    }
    Unregister-Hotkeys
    Stop-Toggling
    if ($script:OverlayIcon) { $script:OverlayIcon.Dispose() }
    if ($notifyIcon) {
        try { $notifyIcon.Visible = $false } catch { }
        try { $notifyIcon.Dispose() } catch { }
        $notifyIcon = $null
    }
    Write-Log "Tray icon disposed." "INFO" $null "Tray"
    $timer.Dispose()
    $statusUpdateTimer.Dispose()
    $pauseTimer.Dispose()
    $watchdogTimer.Dispose()
    Release-MutexOnce
    try {
        Write-Log "Restart spawn: launching new instance." "INFO" $null "Restart"
        $proc = Start-Process -FilePath "powershell.exe" -WindowStyle Hidden -WorkingDirectory $script:DataRoot -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -PassThru
        if ($proc -and $proc.Id) { Write-Log ("Restart new PID={0}" -f $proc.Id) "INFO" $null "Restart" }
    } catch {
        Write-LogEx "Failed to restart app." "ERROR" $_.Exception "Restart" -Force
    }
    Write-Log "Restart requested via tray menu." "INFO" $null "Restart"
    $script:CleanupDone = $true
    [System.Windows.Forms.Application]::Exit()
})

$exitItem = New-Object System.Windows.Forms.ToolStripMenuItem("Exit")
Set-MenuTooltip $exitItem "Exit the app."
$exitItem.Add_Click({
    if ($script:CleanupDone) { return }
    Write-Log "Tray action: Exit" "DEBUG" $null "Tray-Action"
    Write-Log "" "INFO" $null "Exit"
    Write-Log "=======================================================================" "INFO" $null "Exit"
    Write-Log "=                               APP EXIT                              =" "INFO" $null "Exit"
    Write-Log "=======================================================================" "INFO" $null "Exit"
    Log-ShutdownSummary "Exit"
    Set-ShutdownMarker "clean"
    try { Flush-LogBuffer } catch { }
    $script:isShuttingDown = $true
    Flush-SettingsSave
    Flush-LogBuffer
    $statusUpdateTimer.Stop()
    $pauseTimer.Stop()
    $watchdogTimer.Stop()
    Unregister-Hotkeys
    Stop-Toggling
    if ($script:OverlayIcon) { $script:OverlayIcon.Dispose() }
    if ($notifyIcon) {
        try { $notifyIcon.Visible = $false } catch { }
        try { $notifyIcon.Dispose() } catch { }
        $notifyIcon = $null
    }
    Write-Log "Tray icon disposed." "INFO" $null "Tray"
    $timer.Dispose()
    $statusUpdateTimer.Dispose()
    $pauseTimer.Dispose()
    $watchdogTimer.Dispose()
    Release-MutexOnce
    Write-Log "Exit requested via tray menu." "INFO" $null "Exit"
    $script:CleanupDone = $true
    [System.Windows.Forms.Application]::Exit()
})

$contextMenu.Items.AddRange(@(
    $startStopItem,
    $toggleNowItem,
    $pauseMenu,
    $intervalMenu,
    $runOnceNowItem,
    (New-Object System.Windows.Forms.ToolStripSeparator),
    $statusItem,
    $profilesMenu,
    $quickSettingsMenu,
    $openSettingsItem,
    (New-Object System.Windows.Forms.ToolStripSeparator),
    $logsMenu,
    $historyItem,
    $resetSafeModeItem,
    $recoverNowItem,
    (New-Object System.Windows.Forms.ToolStripSeparator),
    $restartItem,
    $exitItem
))

if ($script:SettingsOnly) {
    Show-SettingsDialog
    [System.Windows.Forms.Application]::Run()
    return
}

# Use a built-in icon (no external .ico needed)
$notifyIcon = New-Object System.Windows.Forms.NotifyIcon
if (Test-Path $iconPath) {
    $notifyIcon.Icon = New-Object System.Drawing.Icon($iconPath)
} else {
    $notifyIcon.Icon = [System.Drawing.SystemIcons]::Application
}
$script:BaseNotifyIcon = $notifyIcon.Icon
$notifyIcon.Text = "Teams-Always-Green (Stopped)"
$notifyIcon.Text = if ($script:isPaused) { "Teams-Always-Green (Paused)" } else { $notifyIcon.Text }
$notifyIcon.Visible = $false
$notifyIcon.ContextMenuStrip = $contextMenu
Write-Log "Tray icon created." "INFO" $null "Tray"
Apply-MenuFontSize ([int]$settings.FontSize)
Update-ThemePreference
Request-StatusUpdate
Update-StatusText
Update-LogLevelMenuChecks
Register-Hotkeys

# Left-click shows status balloon; double-click toggles start/stop
$notifyIcon.Add_Click({
    if ($_.Button -eq [System.Windows.Forms.MouseButtons]::Left) {
        Request-StatusUpdate
        $statusText = Get-StatusBalloonText
        Show-Balloon "Teams-Always-Green" $statusText ([System.Windows.Forms.ToolTipIcon]::Info)
    }
})
$notifyIcon.Add_MouseMove({
    $now = Get-Date
    if ($script:LastHoverUpdateTime -and (($now - $script:LastHoverUpdateTime).TotalMilliseconds -lt $script:HoverUpdateMinMs)) {
        return
    }
    $script:LastHoverUpdateTime = $now
    Update-StatusText
})
$notifyIcon.Add_DoubleClick({
    if ($script:isRunning) { Stop-Toggling } else { Start-Toggling }
})

# Update the Status line when the context menu opens
$contextMenu.Add_Opening({
    if ($script:TrayMenuOpening) { return }
    $script:TrayMenuOpening = $true
    try {
        Update-ThemePreference
        Apply-MenuFontSize ([int]$settings.FontSize)
        Update-StatusText
        Set-StatusUpdateTimerEnabled $true
    } finally {
        $script:TrayMenuOpening = $false
    }
})

$contextMenu.Add_Closed({
    Set-StatusUpdateTimerEnabled $false
    try { $script:TrayTooltipTimer.Stop() } catch { }
    $script:TrayTooltipPendingText = $null
    try { $script:TrayMenuToolTip.Hide($contextMenu) } catch { }
})

function Refresh-TrayMenu {
    try { Rebuild-PauseMenu } catch { }
    try { if ($updateQuickSettingsChecks) { & $updateQuickSettingsChecks } } catch { }
    try { if ($updateProfilesMenu) { & $updateProfilesMenu } } catch { }
    try { Update-LogLevelMenuChecks } catch { }
    try { Apply-MenuFontSize ([int]$settings.FontSize) } catch { }
    try { Update-ThemePreference } catch { }
    try { Update-StatusText } catch { }
}


$pauseTimer = New-Object System.Windows.Forms.Timer
$pauseTimer.Interval = 1000
$pauseTimer.Add_Tick({
    Invoke-SafeTimerAction "PauseTimer" {
        if ($script:isShuttingDown -or $script:CleanupDone) { return }
        if ($script:isPaused -and $script:pauseUntil -ne $null -and (Get-Date) -ge $script:pauseUntil) {
            Start-Toggling
        }
    }
})
$pauseTimer.Start()

$watchdogTimer = New-Object System.Windows.Forms.Timer
$watchdogTimer.Interval = 2000
$watchdogTimer.Add_Tick({
    Invoke-SafeTimerAction "WatchdogTimer" {
        if ($script:isShuttingDown -or $script:CleanupDone) { return }
        Process-CommandFile
        Request-StatusUpdate
        Update-ScheduleBlock | Out-Null
        if ($script:isRunning -and -not $script:isPaused) {
            if ($script:isScheduleBlocked) {
                if ($timer.Enabled) { $timer.Stop() }
                return
            }
            if (-not $timer.Enabled) {
                $timer.Start()
                Write-LogThrottled "Watchdog" "Watchdog restarted timer." "WARN" 30
            }
        } elseif ($timer.Enabled) {
            $timer.Stop()
        }
    }
})
$watchdogTimer.Start()

$statusHeartbeatTimer = New-Object System.Windows.Forms.Timer
$statusHeartbeatTimer.Interval = 1000
$statusHeartbeatTimer.Add_Tick({
    Invoke-SafeTimerAction "StatusHeartbeatTimer" {
        if ($script:isShuttingDown -or $script:CleanupDone) { return }
        Update-PeakWorkingSet
        Request-StatusUpdate
    }
})
$statusHeartbeatTimer.Start()

$notifyIcon.Visible = $true
Write-Log "Tray icon visible (startup complete)." "INFO" $null "Tray"
try { Show-FirstRunToast } catch { }

function Show-StartPrompt {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Teams-Always-Green"
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.ClientSize = New-Object System.Drawing.Size(380, 150)

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Start Scroll Lock toggling now?`n`nYou can control it later from the tray icon (right-click)."
    $label.Location = New-Object System.Drawing.Point(12, 10)
    $label.Size = New-Object System.Drawing.Size(355, 60)

    $checkbox = New-Object System.Windows.Forms.CheckBox
    $checkbox.Text = "Remember my choice"
    $checkbox.Location = New-Object System.Drawing.Point(12, 75)
    $checkbox.AutoSize = $true

    $yesButton = New-Object System.Windows.Forms.Button
    $yesButton.Text = "Yes"
    $yesButton.Location = New-Object System.Drawing.Point(200, 105)
    $yesButton.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $noButton = New-Object System.Windows.Forms.Button
    $noButton.Text = "No"
    $noButton.Location = New-Object System.Drawing.Point(285, 105)
    $noButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $form.Controls.AddRange(@($label, $checkbox, $yesButton, $noButton))
    $form.AcceptButton = $yesButton
    $form.CancelButton = $noButton

    $result = $form.ShowDialog()
    return @{
        StartNow = ($result -eq [System.Windows.Forms.DialogResult]::OK)
        Remember = $checkbox.Checked
    }
}

# --- Optional: confirmation prompt on launch ---
$overrideAtStartup = $script:OverrideMinimalMode
$overrideLogOnce = $false
$overrideState = $null
if (-not $overrideAtStartup -and (Test-Path $script:CrashStatePath)) {
    try {
        $rawOverride = Get-Content -Path $script:CrashStatePath -Raw
        if (-not [string]::IsNullOrWhiteSpace($rawOverride)) {
            $loadedOverride = $rawOverride | ConvertFrom-Json
            if ($loadedOverride -and ($loadedOverride.PSObject.Properties.Name -contains "OverrideMinimalMode") -and [bool]$loadedOverride.OverrideMinimalMode) {
                $overrideAtStartup = $true
                $script:OverrideMinimalMode = $true
                $overrideState = $loadedOverride
                if (-not ($loadedOverride.PSObject.Properties.Name -contains "OverrideMinimalModeLogged") -or -not [bool]$loadedOverride.OverrideMinimalModeLogged) {
                    $overrideLogOnce = $true
                }
            }
        }
    } catch {
    }
}

if ($script:MinimalModeActive -and -not $overrideAtStartup) {
    Request-StatusUpdate
    Show-Balloon "Teams-Always-Green" "Minimal mode enabled after repeated crashes. Open Settings to review." ([System.Windows.Forms.ToolTipIcon]::Warning)
    Write-Log "Startup: minimal mode active (auto-start suppressed)." "WARN" $null "Startup"
} elseif ($script:MinimalModeActive -and $overrideAtStartup) {
    $script:MinimalModeActive = $false
    $script:MinimalModeReason = $null
    if ($overrideLogOnce) {
        Write-Log "Startup: minimal mode override applied." "INFO" $null "Startup"
        try {
            $state = Get-CrashState
            $state.OverrideMinimalModeLogged = $true
            Save-CrashState $state
        } catch {
        }
    }
} elseif ($script:isPaused) {
    Request-StatusUpdate
    Show-Balloon "Teams-Always-Green" "Paused; will auto-resume when the timer expires." ([System.Windows.Forms.ToolTipIcon]::Info)
} elseif ($settings.RememberChoice) {
    if ($settings.RunOnceOnLaunch) {
        Do-Toggle "startup"
        Show-Balloon "Teams-Always-Green" "Ran once on launch." ([System.Windows.Forms.ToolTipIcon]::Info)
    } elseif ($settings.StartOnLaunch) {
        Start-Toggling
    } else {
        Show-Balloon "Teams-Always-Green" "Loaded in tray (Stopped). Right-click for options." ([System.Windows.Forms.ToolTipIcon]::Info)
    }
} else {
    $prompt = Show-StartPrompt
    if ($prompt.Remember) {
        $settings.RememberChoice = $true
        $settings.StartOnLaunch = [bool]$prompt.StartNow
        Save-Settings $settings
    }
    if ($settings.RunOnceOnLaunch) {
        Do-Toggle "startup"
        Show-Balloon "Teams-Always-Green" "Ran once on launch." ([System.Windows.Forms.ToolTipIcon]::Info)
    } elseif ($prompt.StartNow) {
        Start-Toggling
    } else {
        Show-Balloon "Teams-Always-Green" "Loaded in tray (Stopped). Right-click for options." ([System.Windows.Forms.ToolTipIcon]::Info)
    }
}

# --- Run message loop (keeps tray app alive) ---
[System.Windows.Forms.Application]::Run()

# Cleanup if Application.Run exits unexpectedly
try {
    if ($script:CleanupDone) { return }
    $script:isShuttingDown = $true
    $statusUpdateTimer.Stop()
    $pauseTimer.Stop()
    $watchdogTimer.Stop()
    Unregister-Hotkeys
    Stop-Toggling
    if ($script:OverlayIcon) { $script:OverlayIcon.Dispose() }
    if ($notifyIcon) {
        try { $notifyIcon.Visible = $false } catch { }
        try { $notifyIcon.Dispose() } catch { }
        $notifyIcon = $null
    }
    $timer.Dispose()
    $statusUpdateTimer.Dispose()
    $pauseTimer.Dispose()
    $watchdogTimer.Dispose()
    Release-MutexOnce
    $script:CleanupDone = $true
} catch {
    Write-Log "Cleanup failed." "ERROR" $_.Exception "Cleanup"
}

function Test-DirectoryWritable([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    try {
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
        $testFile = Join-Path $path ("~write_test_{0}.tmp" -f ([Guid]::NewGuid().ToString("N")))
        Set-Content -Path $testFile -Value "test" -Encoding ASCII
        Remove-Item -Path $testFile -Force
        return $true
    } catch {
        return $false
    }
}

function Ensure-Directory([string]$path, [string]$label = "Directory") {
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    try {
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
        return $true
    } catch {
        Write-PathWarningNow "$label missing and could not be created: $path"
        return $false
    }
}

function Resolve-DirectoryOrDefault([string]$inputPath, [string]$defaultPath, [string]$label) {
    $resolved = Convert-FromRelativePath $inputPath
    if ([string]::IsNullOrWhiteSpace($resolved)) { $resolved = $defaultPath }
    $resolved = Normalize-PathText $resolved
    Ensure-Directory $resolved $label | Out-Null
    if (-not (Test-DirectoryWritable $resolved)) {
        Write-PathWarningNow "$label directory not writable: $resolved. Falling back to $defaultPath."
        $resolved = $defaultPath
        Ensure-Directory $resolved $label | Out-Null
    }
    return $resolved
}

function Ensure-AppFolders {
    $folders = @($script:FolderNames.Logs, $script:FolderNames.Settings, $script:FolderNames.Meta, $script:FolderNames.Debug, $script:FolderNames.Script)
    foreach ($folder in $folders) {
        $path = Join-Path $script:DataRoot $folder
        Ensure-Directory $path $folder | Out-Null
    }
}

$script:MetaDir = Join-Path $script:DataRoot $script:FolderNames.Meta

