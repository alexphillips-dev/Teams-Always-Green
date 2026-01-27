# Teams-Always-Green.ps1
# Teams Always Green - tray-based status helper with settings, profiles, scheduling, hotkeys, and logging.

# --- Runtime setup and WinForms initialization ---
param(
    [switch]$SettingsOnly
)

$script:SettingsOnly = $SettingsOnly

Set-StrictMode -Version Latest
$proc = $null
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

# --- Single-instance protection (unique per script path + abandoned mutex safe) ---
function Get-PathHash([string]$text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($text.ToLowerInvariant())
        ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
    } finally {
        $sha.Dispose()
    }
}

# --- Paths, Meta folder, and locator files ---
$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path -Parent $scriptPath
$script:MetaDir = Join-Path $scriptDir "Meta"
try {
    if (-not (Test-Path $script:MetaDir)) {
        New-Item -ItemType Directory -Path $script:MetaDir -Force | Out-Null
    }
} catch {
}
$script:SettingsLocatorPath = Join-Path $script:MetaDir "Teams-Always-Green.settings.path.txt"
$script:LogLocatorPath = Join-Path $script:MetaDir "Teams-Always-Green.log.path.txt"
$script:CommandFilePath = Join-Path $script:MetaDir "Teams-Always-Green.commands.txt"
$script:StatusFilePath = Join-Path $script:MetaDir "Teams-Always-Green.status.json"
$oldSettingsLocator = Join-Path $scriptDir "Teams-Always-Green.settings.path.txt"
$oldLogLocator = Join-Path $scriptDir "Teams-Always-Green.log.path.txt"
if ((Test-Path $oldSettingsLocator) -and -not (Test-Path $script:SettingsLocatorPath)) {
    try { Move-Item -Path $oldSettingsLocator -Destination $script:SettingsLocatorPath -Force } catch { }
}
if ((Test-Path $oldLogLocator) -and -not (Test-Path $script:LogLocatorPath)) {
    try { Move-Item -Path $oldLogLocator -Destination $script:LogLocatorPath -Force } catch { }
}
$defaultSettingsDir = Join-Path $scriptDir "Settings"
$defaultLogDir = Join-Path $scriptDir "Logs"
$script:SettingsDirectory = if (Test-Path $defaultSettingsDir) { $defaultSettingsDir } else { $scriptDir }
$script:LogDirectory = if (Test-Path $defaultLogDir) { $defaultLogDir } else { $scriptDir }
if (Test-Path $script:SettingsLocatorPath) {
    try {
        $locatorValue = (Get-Content -Path $script:SettingsLocatorPath -Raw).Trim()
        if (-not [string]::IsNullOrWhiteSpace($locatorValue) -and (Test-Path $locatorValue)) {
            $script:SettingsDirectory = $locatorValue
        }
    } catch {
    }
}
if (Test-Path $script:LogLocatorPath) {
    try {
        $logLocatorValue = (Get-Content -Path $script:LogLocatorPath -Raw).Trim()
        if (-not [string]::IsNullOrWhiteSpace($logLocatorValue) -and (Test-Path $logLocatorValue)) {
            $script:LogDirectory = $logLocatorValue
        }
    } catch {
    }
}
$bootstrapLogFile = "Teams-Always-Green.bootstrap.log"
$bootstrapLogRoot = Join-Path $scriptDir $bootstrapLogFile
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
# --- Date/time formatting helpers ---
$script:DateTimeFormatDefault = "yyyy-MM-dd HH:mm:ss"
$script:DateTimeFormat = $script:DateTimeFormatDefault
$script:UseSystemDateTimeFormat = $true
$script:SystemDateTimeFormatMode = "Short"

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

# --- Bootstrap logging before full logger is initialized ---
function Write-BootstrapLog([string]$message, [string]$level = "INFO") {
    try {
        $timestamp = (Get-Date).ToString($script:DateTimeFormatDefault)
        $line = "[${timestamp}] [$level] [Bootstrap] $message"
        Add-Content -Path $script:BootstrapLogPath -Value $line
    } catch { }
}

Write-BootstrapLog "Startup: ScriptPath=$scriptPath LogDir=$script:LogDirectory SettingsDir=$script:SettingsDirectory" "INFO"

# --- Shutdown marker for crash detection ---
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

# --- Logging stubs for early startup ---
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
# --- Global state, caches, and UI references ---
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
$script:SettingsSchemaVersion = 5
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
# --- Debounced timers and periodic tasks ---
$script:SaveSettingsPending = $null
$script:SaveSettingsDebounceMs = 400
$script:SaveSettingsTimer = New-Object System.Windows.Forms.Timer
$script:SaveSettingsTimer.Interval = $script:SaveSettingsDebounceMs
$script:SaveSettingsTimer.Add_Tick({
    if ($script:isShuttingDown -or $script:CleanupDone) {
        $script:SaveSettingsTimer.Stop()
        return
    }
    $script:SaveSettingsTimer.Stop()
    if ($script:SaveSettingsPending) {
        Save-SettingsImmediate $script:SaveSettingsPending
        $script:SaveSettingsPending = $null
    }
})
$script:StatusUpdatePending = $false
$script:StatusUpdateInProgress = $false
$script:StatusUpdateDebounceTimer = New-Object System.Windows.Forms.Timer
$script:StatusUpdateDebounceTimer.Interval = 120
$script:StatusUpdateDebounceTimer.Add_Tick({
    if ($script:isShuttingDown -or $script:CleanupDone) {
        $script:StatusUpdateDebounceTimer.Stop()
        return
    }
    $script:StatusUpdateDebounceTimer.Stop()
    $script:StatusUpdatePending = $false
    Update-StatusText
})
$script:LogFlushTimer = New-Object System.Windows.Forms.Timer
$script:LogFlushTimer.Interval = 1000
$script:LogFlushTimer.Add_Tick({
    if ($script:isShuttingDown -or $script:CleanupDone) {
        $script:LogFlushTimer.Stop()
        return
    }
    Flush-LogBuffer
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
$script:RunId = ([Guid]::NewGuid().ToString("N")).Substring(0, 8)
$script:LastErrorId = $null
$script:LastSettingsChangeSummary = $null
$script:LastSettingsChangeDetail = $null
$script:FallbackLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.fallback.log"
$script:FallbackLogWarned = $false
$script:DebugModeTimer = New-Object System.Windows.Forms.Timer
$script:DebugModeTimer.Interval = 1000
$script:DebugModeTimer.Add_Tick({
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
})
# --- App metadata ---
$versionPath = Join-Path $scriptDir "VERSION"
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

function Invoke-UpdateCheck {
    param(
        [switch]$Force
    )
    if (-not $Force) {
        if (-not ($settings.PSObject.Properties.Name -contains "AutoUpdateEnabled") -or -not [bool]$settings.AutoUpdateEnabled) { return }
    }
    $owner = "alexphillips-dev"
    $repo = "Teams-Always-Green"
    $assetName = "Teams-Always-Green.ps1"
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

    $tempPath = Join-Path $env:TEMP ("Teams-Always-Green.ps1." + [Guid]::NewGuid().ToString("N") + ".tmp")
    try {
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $tempPath -UseBasicParsing -ErrorAction Stop
        $downloadInfo = Get-Item -Path $tempPath -ErrorAction Stop
        if ($downloadInfo.Length -lt 2048) {
            throw "Downloaded file looks too small."
        }

        $backupPath = Join-Path $script:MetaDir ("Teams-Always-Green.ps1.bak." + (Get-Date -Format "yyyyMMddHHmmss"))
        Copy-Item -Path $scriptPath -Destination $backupPath -Force
        Move-Item -Path $tempPath -Destination $scriptPath -Force
        $versionPathLocal = Join-Path $scriptDir "VERSION"
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
        Start-Process -FilePath "powershell.exe" -WindowStyle Hidden -WorkingDirectory $scriptDir -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
        [System.Windows.Forms.Application]::Exit()
    } catch {
        try { if (Test-Path $tempPath) { Remove-Item -Path $tempPath -Force } } catch { }
        Write-Log "Update failed: $($_.Exception.Message)" "ERROR" $_.Exception "Update"
        [System.Windows.Forms.MessageBox]::Show(
            "Update failed.`n$($_.Exception.Message)",
            "Update failed",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }
}

# --- Single-instance mutex acquisition ---
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

# --- Log/settings paths and logging defaults ---
# Resolve paths (same folder as script)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$iconPath  = Join-Path $scriptDir "Meta\\Icons\\Tray_Icon.ico"
$script:logPath   = Join-Path $script:LogDirectory "Teams-Always-Green.log"
$script:settingsPath = Join-Path $script:SettingsDirectory "Teams-Always-Green.settings.json"
# --- Logging configuration defaults ---
$script:LogLevel = "INFO"
$script:LogMaxBytes = 1048576
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

# --- Logging categorization and filtering ---
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

function Log-StateSummary([string]$reason) {
    $scheduleStatus = Format-ScheduleStatus
    Write-Log ("State: Running={0} Paused={1} ScheduleEnabled={2} ScheduleBlocked={3} ScheduleStatus={4} Interval={5}s Profile={6}" -f `
        $script:isRunning, $script:isPaused, [bool]$settings.ScheduleEnabled, $script:isScheduleBlocked, $scheduleStatus, $settings.IntervalSeconds, $settings.ActiveProfile) `
        "INFO" $null ($reason)
}

function Log-StartupSummary {
    Write-Log ("Startup summary: Profile={0} Interval={1}s LogLevel={2} QuietMode={3} StartOnLaunch={4} RunOnceOnLaunch={5} ScheduleEnabled={6} Paused={7}" -f `
        $settings.ActiveProfile, $settings.IntervalSeconds, $settings.LogLevel, $settings.QuietMode, $settings.StartOnLaunch, $settings.RunOnceOnLaunch, $settings.ScheduleEnabled, $script:isPaused) `
        "INFO" $null "Startup"
}

function Log-ShutdownSummary([string]$reason) {
    $uptimeMinutes = [Math]::Round(((Get-Date) - $script:AppStartTime).TotalMinutes, 1)
    Write-Log ("Shutdown summary: Reason={0} Profile={1} Interval={2}s LogLevel={3} Running={4} Paused={5} ScheduleEnabled={6} Warns={7} Errors={8}" -f `
        $reason, $settings.ActiveProfile, $settings.IntervalSeconds, $settings.LogLevel, $script:isRunning, $script:isPaused, $settings.ScheduleEnabled, $script:WarningCount, $script:ErrorCount) `
        "INFO" $null "Shutdown"
    Write-Log ("Session end: SessionID={0} LogWrites={1} Rotations={2} LastLogWrite={3} UptimeMinutes={4}" -f `
        $script:RunId, $script:LogWriteCount, $script:LogRotationCount, (Format-DateTime $script:LastLogWriteTime), $uptimeMinutes) "INFO" $null "Shutdown"
    Update-FunStatsOnShutdown $uptimeMinutes
}

function Set-LastUserAction([string]$name, [string]$context = $null) {
    if ([string]::IsNullOrWhiteSpace($name)) { return }
    $script:LastUserAction = $name
    $script:LastUserActionContext = $context
    $script:LastUserActionTime = Get-Date
    $script:LastUserActionId = [Guid]::NewGuid().ToString("N").Substring(0, 6)
    Add-RecentAction $name $context $script:LastUserActionId
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

# --- Logging formatting and error helpers ---
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
    if ($hresult -ne $null) { $parts += ("HResult=0x{0:X8}" -f $hresult) }
    if ($win32 -ne $null -and $win32 -ne 0) { $parts += ("Win32Error={0}" -f $win32) }
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
    if ($days -le 0) { return }
    $logDir = Split-Path -Path $script:logPath -Parent
    if (-not (Test-Path $logDir)) { return }
    $cutoff = (Get-Date).AddDays(-$days)
    $removed = 0
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

function Flush-LogBuffer {
    if ($script:IsFlushingLog) { return }
    if ($script:LogBuffer.Count -eq 0) { return }
    $script:IsFlushingLog = $true
    try {
        $lines = $script:LogBuffer.ToArray()
        $script:LogBuffer.Clear()
        Add-Content -Path $logPath -Value $lines
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
    Rotate-LogIfNeeded
    $timestamp = Format-DateTime (Get-Date)
    $displayLevel = $levelKey
    if ($script:LogLevel -eq "DEBUG" -and $levelKey -eq "INFO") {
        $displayLevel = "DEBUG"
    }
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
        } elseif ($script:LogResultOverride) {
            $script:LogResultOverride = $null
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

# --- Log/settings directory management ---
function Set-LogDirectory([string]$directory, [switch]$SkipLog) {
    $resolved = if ([string]::IsNullOrWhiteSpace($directory)) { $scriptDir } else { $directory }
    try {
        if (-not (Test-Path $resolved)) {
            New-Item -ItemType Directory -Path $resolved -Force | Out-Null
        }
    } catch {
        if (-not $SkipLog) {
            Write-Log "Failed to create log directory: $resolved" "ERROR" $_.Exception "Logging"
        }
        return
    }

    $oldLogPath = $script:logPath
    $oldDir = $script:LogDirectory
    $script:LogDirectory = $resolved
    $script:logPath = Join-Path $script:LogDirectory "Teams-Always-Green.log"
    $script:FallbackLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.fallback.log"
    $script:BootstrapLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.bootstrap.log"

    if ($oldDir -ne $script:LogDirectory) {
        try {
            Set-Content -Path $script:LogLocatorPath -Value $script:LogDirectory -Encoding ASCII
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
    $resolved = if ([string]::IsNullOrWhiteSpace($directory)) { $scriptDir } else { $directory }
    try {
        if (-not (Test-Path $resolved)) {
            New-Item -ItemType Directory -Path $resolved -Force | Out-Null
        }
    } catch {
        if (-not $SkipLog) {
            Write-Log "Failed to create settings directory: $resolved" "ERROR" $_.Exception "Settings"
        }
        return
    }

    $oldSettingsPath = $script:settingsPath
    $oldDir = $script:SettingsDirectory
    $script:SettingsDirectory = $resolved
    $script:settingsPath = Join-Path $script:SettingsDirectory "Teams-Always-Green.settings.json"

    if ($oldDir -ne $script:SettingsDirectory) {
        try {
            Set-Content -Path $script:SettingsLocatorPath -Value $script:SettingsDirectory -Encoding ASCII
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
    }

    if (-not $SkipLog -and $oldDir -ne $script:SettingsDirectory) {
        Write-Log "Settings directory set to $($script:SettingsDirectory)" "INFO" $null "Settings"
    }
}

# --- Settings load/save and schema migration ---
function Load-Settings {
    if (-not (Test-Path $settingsPath)) {
        return $null
    }
    try {
        $raw = Get-Content -Path $settingsPath -Raw
        $loaded = $raw | ConvertFrom-Json
        $info = Get-Item -Path $settingsPath -ErrorAction SilentlyContinue
        if ($info) {
            Write-Log ("Settings loaded from {0} (bytes={1} modified={2})" -f $settingsPath, $info.Length, (Format-DateTime $info.LastWriteTime)) "INFO" $null "Settings-Load"
        } else {
            Write-Log "Settings loaded." "INFO" $null "Settings-Load"
        }
        return $loaded
    } catch {
        Write-Log "Failed to load settings." "ERROR" $_.Exception "Load-Settings"
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

function Get-ObjectKeys($obj) {
    if ($obj -is [hashtable]) { return @($obj.Keys) }
    if ($obj -is [pscustomobject]) { return @($obj.PSObject.Properties.Name) }
    return @()
}

# --- Settings UI state helpers ---
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
            if ($script:SettingsSaveLabel) { $script:SettingsSaveLabel.Visible = $false }
            if ($script:SettingsSaveTimer) { $script:SettingsSaveTimer.Stop() }
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

# --- Settings normalization and migration ---
function Normalize-Settings($settings) {
    if (-not $settings) { return $settings }
    $settings.IntervalSeconds = Normalize-IntervalSeconds ([int]$settings.IntervalSeconds)
    if ([string]::IsNullOrWhiteSpace([string]$settings.ThemeMode)) { Set-SettingsPropertyValue $settings "ThemeMode" "Auto" }
    if ([string]::IsNullOrWhiteSpace([string]$settings.TooltipStyle)) { Set-SettingsPropertyValue $settings "TooltipStyle" "Standard" }
    if (-not ($settings.PSObject.Properties.Name -contains "FontSize")) { Set-SettingsPropertyValue $settings "FontSize" 12 }
    if (-not ($settings.PSObject.Properties.Name -contains "SettingsFontSize")) { Set-SettingsPropertyValue $settings "SettingsFontSize" 12 }
    if (-not ($settings.PSObject.Properties.Name -contains "LogDirectory")) { Set-SettingsPropertyValue $settings "LogDirectory" "" }
    if (-not ($settings.PSObject.Properties.Name -contains "SettingsDirectory")) { Set-SettingsPropertyValue $settings "SettingsDirectory" "" }
    if (-not ($settings.PSObject.Properties.Name -contains "DateTimeFormat")) { Set-SettingsPropertyValue $settings "DateTimeFormat" $script:DateTimeFormatDefault }
    if (-not ($settings.PSObject.Properties.Name -contains "UseSystemDateTimeFormat")) { Set-SettingsPropertyValue $settings "UseSystemDateTimeFormat" $true }
    if (-not ($settings.PSObject.Properties.Name -contains "SystemDateTimeFormatMode")) { Set-SettingsPropertyValue $settings "SystemDateTimeFormatMode" "Short" }
    $settings.DateTimeFormat = Normalize-DateTimeFormat ([string]$settings.DateTimeFormat)
    if ([string]::IsNullOrWhiteSpace([string]$settings.SystemDateTimeFormatMode)) { $settings.SystemDateTimeFormatMode = "Short" }
    if (-not ($settings.PSObject.Properties.Name -contains "OpenSettingsAtLastTab")) { Set-SettingsPropertyValue $settings "OpenSettingsAtLastTab" $false }
    if (-not ($settings.PSObject.Properties.Name -contains "LastSettingsTab")) { Set-SettingsPropertyValue $settings "LastSettingsTab" "General" }
    if ([string]::IsNullOrWhiteSpace([string]$settings.LogLevel)) { Set-SettingsPropertyValue $settings "LogLevel" "INFO" }
    $upperLogLevel = ([string]$settings.LogLevel).ToUpperInvariant()
    if (-not $script:LogLevels.ContainsKey($upperLogLevel)) { Set-SettingsPropertyValue $settings "LogLevel" "INFO" }
    if ($settings.FontSize -lt 8) { $settings.FontSize = 8 }
    if ($settings.FontSize -gt 24) { $settings.FontSize = 24 }
    if ($settings.SettingsFontSize -lt 8) { $settings.SettingsFontSize = 8 }
    if ($settings.SettingsFontSize -gt 24) { $settings.SettingsFontSize = 24 }
    if ($null -eq (Get-SettingsPropertyValue $settings "SchemaVersion")) {
        Set-SettingsPropertyValue $settings "SchemaVersion" $script:SettingsSchemaVersion
    }
    return $settings
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
    Set-SettingsPropertyValue $settings "SchemaVersion" $current
    return $settings
}

function Save-SettingsImmediate($settings) {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        Sync-ActiveProfileSnapshot $settings
        $settings = Normalize-Settings (Migrate-Settings $settings)
        $newSnapshot = Get-SettingsSnapshot $settings
        $newHash = Get-SettingsSnapshotHash $newSnapshot
        if ($script:LastSettingsSnapshotHash -and $script:LastSettingsSnapshotHash -eq $newHash) {
            $stopwatch.Stop()
            Write-Log "UI: Settings unchanged; skip save." "DEBUG" $null "Settings-Save"
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
        Rotate-SettingsBackups
        $settings | ConvertTo-Json -Depth 4 | Set-Content -Path $settingsPath -Encoding UTF8
        if (@($changedKeys).Count -gt 0) {
            $categoryMap = @{
                General     = @("IntervalSeconds", "StartWithWindows", "RememberChoice", "StartOnLaunch", "RunOnceOnLaunch", "QuietMode", "DisableBalloonTips", "OpenSettingsAtLastTab", "LastSettingsTab", "DateTimeFormat", "UseSystemDateTimeFormat", "SystemDateTimeFormatMode", "ToggleCount", "LastToggleTime", "PauseUntil", "PauseDurationsMinutes", "SettingsDirectory")
                Appearance  = @("TooltipStyle", "ThemeMode", "FontSize", "SettingsFontSize", "StatusColorRunning", "StatusColorPaused", "StatusColorStopped", "CompactMode", "MinimalTrayTooltip")
                Schedule    = @("ScheduleEnabled", "ScheduleStart", "ScheduleEnd", "ScheduleWeekdays", "ScheduleSuspendUntil")
                Hotkeys     = @("HotkeyToggle", "HotkeyStartStop", "HotkeyPauseResume")
                Logging     = @("LogLevel", "LogMaxBytes", "LogRetentionDays", "LogIncludeStackTrace", "LogToEventLog", "LogEventLevels", "LogCategories", "LogDirectory")
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
            Write-Log ("UI: Settings changed: " + $script:LastSettingsChangeSummary) "INFO" $null "Settings-Change"
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
        Write-Log ("UI: Settings saved to {0} (ms={1})" -f $settingsPath, $stopwatch.ElapsedMilliseconds) "INFO" $null "Settings-Save"
        Show-SettingsSaveToast
        $script:LastSettingsSnapshot = $newSnapshot
        $script:LastSettingsSnapshotHash = $newHash
    } catch {
        $stopwatch.Stop()
        Write-Log "Failed to save settings." "ERROR" $_.Exception "Save-Settings"
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

# --- Profile snapshots and sync ---
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
    "ThemeMode",
    "FontSize",
    "SettingsFontSize",
    "StatusColorRunning",
    "StatusColorPaused",
    "StatusColorStopped",
    "CompactMode"
)

function Get-ProfileSnapshot($source) {
    $snapshot = [pscustomobject]@{}
    foreach ($name in $script:ProfilePropertyNames) {
        if ($source.PSObject.Properties.Name -contains $name) {
            $snapshot | Add-Member -MemberType NoteProperty -Name $name -Value $source.$name
        }
    }
    return $snapshot
}

function Apply-ProfileSnapshot($target, $profile) {
    foreach ($name in $script:ProfilePropertyNames) {
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

# --- Default settings and initial load ---
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
    LogRetentionDays = 14
    LogDirectory = ""
    SettingsDirectory = ""
    AutoUpdateEnabled = $true
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

$settings = Load-Settings
if (-not $settings) {
    $settings = $defaultSettings
} else {
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
    if (-not ($settings.PSObject.Properties.Name -contains "StatusColorRunning")) { $settings.StatusColorRunning = $defaultSettings.StatusColorRunning }
    if (-not ($settings.PSObject.Properties.Name -contains "StatusColorPaused")) { $settings.StatusColorPaused = $defaultSettings.StatusColorPaused }
    if (-not ($settings.PSObject.Properties.Name -contains "StatusColorStopped")) { $settings.StatusColorStopped = $defaultSettings.StatusColorStopped }
    if ([string]$settings.StatusColorRunning -eq "#000000") { $settings.StatusColorRunning = $defaultSettings.StatusColorRunning }
    if ([string]$settings.StatusColorPaused -eq "#000000") { $settings.StatusColorPaused = $defaultSettings.StatusColorPaused }
    if ([string]$settings.StatusColorStopped -eq "#000000") { $settings.StatusColorStopped = $defaultSettings.StatusColorStopped }
    if (-not ($settings.PSObject.Properties.Name -contains "CompactMode")) { $settings.CompactMode = $defaultSettings.CompactMode }
}

$profilesChanged = $false
if (-not ($settings.PSObject.Properties.Name -contains "Profiles") -or $null -eq $settings.Profiles) {
    $settings.Profiles = @{}
    $profilesChanged = $true
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
}
    if (-not ($settings.PSObject.Properties.Name -contains "LogCategories") -or $null -eq $settings.LogCategories) {
        $settings.LogCategories = $defaultSettings.LogCategories
        $profilesChanged = $true
    } elseif ($settings.LogCategories -is [pscustomobject]) {
    $table = @{}
    foreach ($prop in $settings.LogCategories.PSObject.Properties) {
        $table[$prop.Name] = [bool]$prop.Value
    }
    $settings.LogCategories = $table
    $profilesChanged = $true
}
    if (-not ($settings.PSObject.Properties.Name -contains "LogRetentionDays")) {
        $settings.LogRetentionDays = $defaultSettings.LogRetentionDays
        $profilesChanged = $true
    }
    if (-not ($settings.PSObject.Properties.Name -contains "LogEventLevels") -or $null -eq $settings.LogEventLevels) {
        $settings.LogEventLevels = $defaultSettings.LogEventLevels
        $profilesChanged = $true
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
    }
    if ($settings.LogEventLevels -is [hashtable]) {
        foreach ($name in $defaultSettings.LogEventLevels.Keys) {
            if (-not $settings.LogEventLevels.ContainsKey($name)) {
                $settings.LogEventLevels[$name] = [bool]$defaultSettings.LogEventLevels[$name]
                $profilesChanged = $true
            }
        }
    }
    foreach ($name in $script:LogCategoryNames) {
        if (-not $settings.LogCategories.ContainsKey($name)) {
            $settings.LogCategories[$name] = $true
            $profilesChanged = $true
        }
    }
    if (-not ($settings.PSObject.Properties.Name -contains "VerboseUiLogging")) {
        $settings.VerboseUiLogging = $defaultSettings.VerboseUiLogging
        $profilesChanged = $true
    }
    if (-not ($settings.PSObject.Properties.Name -contains "ThemeMode")) {
        $settings.ThemeMode = $defaultSettings.ThemeMode
        $profilesChanged = $true
    }
if (-not ($settings.PSObject.Properties.Name -contains "ActiveProfile") -or [string]::IsNullOrWhiteSpace($settings.ActiveProfile)) {
    $settings.ActiveProfile = "Default"
    $profilesChanged = $true
}
if (@(Get-ObjectKeys $settings.Profiles).Count -eq 0) {
    $settings.Profiles["Default"] = Get-ProfileSnapshot $settings
    $settings.Profiles["Work"] = Get-ProfileSnapshot $settings
    $settings.Profiles["Home"] = Get-ProfileSnapshot $settings
    $profilesChanged = $true
}
if ($profilesChanged) {
    Save-Settings $settings
}

if ($settings.PSObject.Properties.Name -contains "SettingsDirectory") {
    Set-SettingsDirectory ([string]$settings.SettingsDirectory) -SkipLog
}

if ($settings.PSObject.Properties.Name -contains "LogDirectory") {
    Set-LogDirectory ([string]$settings.LogDirectory) -SkipLog
}

$settings.DateTimeFormat = Normalize-DateTimeFormat ([string]$settings.DateTimeFormat)
$script:DateTimeFormat = $settings.DateTimeFormat
$script:UseSystemDateTimeFormat = [bool]$settings.UseSystemDateTimeFormat
$script:SystemDateTimeFormatMode = if ([string]::IsNullOrWhiteSpace([string]$settings.SystemDateTimeFormatMode)) { "Short" } else { [string]$settings.SystemDateTimeFormatMode }

if ((Get-ObjectKeys $settings.Profiles) -contains $settings.ActiveProfile) {
    $settings = Apply-ProfileSnapshot $settings $settings.Profiles[$settings.ActiveProfile]
    Write-Log "Applied active profile '$($settings.ActiveProfile)' at startup." "INFO" $null "Profiles"
}

Update-LogCategorySettings


$script:LastSettingsSnapshot = Get-SettingsSnapshot $settings
$script:LastSettingsSnapshotHash = Get-SettingsSnapshotHash $script:LastSettingsSnapshot

$script:LogLevel = [string]$settings.LogLevel
if ([string]::IsNullOrWhiteSpace($script:LogLevel)) { $script:LogLevel = "INFO" }
$script:LogLevel = $script:LogLevel.ToUpperInvariant()
if (-not $script:LogLevels.ContainsKey($script:LogLevel)) { $script:LogLevel = "INFO" }
$script:LogMaxBytes = [int]$settings.LogMaxBytes
if ($script:LogMaxBytes -le 0) { $script:LogMaxBytes = 1048576 }

Invoke-UpdateCheck

# --- Global error trap and shutdown handling ---
trap {
    try {
        Write-BootstrapLog "Unhandled exception trapped." "ERROR"
        if (Get-Command -Name Write-LogEx -ErrorAction SilentlyContinue) {
            Write-LogEx "Unhandled exception." "FATAL" $_.Exception "Trap" -Force
        } elseif (Get-Command -Name Write-Log -ErrorAction SilentlyContinue) {
            Write-Log "Unhandled exception." "FATAL" $_.Exception "Trap" -Force
        } else {
            try {
                $fallback = Join-Path $scriptDir "Teams-Always-Green.fallback.log"
                $msg = "[{0}] [FATAL] [Trap] Unhandled exception: {1}" -f (Format-DateTime (Get-Date)), $_.Exception.Message
                Add-Content -Path $fallback -Value $msg
            } catch { }
        }
        if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
            Write-Log ("Position: " + $_.InvocationInfo.PositionMessage.Trim()) "FATAL" $_.Exception "Trap"
        }
        try { Flush-LogBuffer } catch { }
        [System.Windows.Forms.MessageBox]::Show(
            "A fatal error occurred and the app will close.`n$($_.Exception.Message)`n`nErrorId: $($script:LastErrorId)",
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
if ($previousShutdown -and $previousShutdown -ne "clean") {
    Write-Log "Crash detected: previous session did not exit cleanly." "WARN" $null "Startup"
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
Write-Log "Boot: Init" "INFO" $null "Init"
Write-Log "Boot: Paths" "INFO" $null "Init"
Write-Log "Boot: Settings" "INFO" $null "Init"
Write-Log "Boot: UI" "INFO" $null "Init"
Write-Log "Boot: Tray" "INFO" $null "Init"
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
Write-Log ("Session start: SessionID={0} Profile={1} LogLevel={2} LogPath={3} SettingsPath={4} Version={5} SchemaVersion={6} Build={7}" -f `
    $script:RunId, $settings.ActiveProfile, $settings.LogLevel, $logPath, $settingsPath, $appVersion, $script:SettingsSchemaVersion, $buildStamp) "INFO" $null "Init"
Write-Log ("Metadata: BuildId={0} ScriptHash={1} SchemaVersion={2} ConfigHash={3} ProfileHash={4} StartupSource={5} SettingsAgeMin={6} ThemeMode={7} ThemeResolved={8} Hotkeys={9}" -f `
    $appBuildId, $scriptHashValue, $script:SettingsSchemaVersion, $configHashValue, $profileHashValue, $startupSource, $settingsAgeMinutes, $themeModeValue, $themeResolved, $hotkeyStatusValue) "INFO" $null "Init"
Write-Log "Startup. ScriptPath=$scriptPath SettingsPath=$settingsPath LogPath=$logPath" "INFO" $null "Init"
$psVersion = $PSVersionTable.PSVersion
$osVersion = [Environment]::OSVersion.VersionString
$pidValue = $PID
Write-Log "Environment. PID=$pidValue PSVersion=$psVersion OS=$osVersion" "INFO" $null "Init"
Write-Log ("Settings snapshot. IntervalSeconds={0} QuietMode={1} MinimalTooltip={2} DisableBalloonTips={3} StartWithWindows={4} RememberChoice={5} StartOnLaunch={6} RunOnceOnLaunch={7} PauseUntil={8} PauseDurations={9} ScheduleEnabled={10} ScheduleStart={11} ScheduleEnd={12} ScheduleWeekdays={13} ScheduleSuspendUntil={14} SafeModeEnabled={15} SafeModeFailureThreshold={16} HotkeyToggle={17} HotkeyStartStop={18} HotkeyPauseResume={19} ToggleCount={20} LogLevel={21} LogMaxBytes={22} LogIncludeStackTrace={23} LogToEventLog={24} LogCategories={25}" -f `
    $settings.IntervalSeconds, $settings.QuietMode, $settings.MinimalTrayTooltip, $settings.DisableBalloonTips, $settings.StartWithWindows, $settings.RememberChoice, $settings.StartOnLaunch, $settings.RunOnceOnLaunch, $settings.PauseUntil, $settings.PauseDurationsMinutes, $settings.ScheduleEnabled, $settings.ScheduleStart, $settings.ScheduleEnd, $settings.ScheduleWeekdays, $settings.ScheduleSuspendUntil, $settings.SafeModeEnabled, $settings.SafeModeFailureThreshold, $settings.HotkeyToggle, $settings.HotkeyStartStop, $settings.HotkeyPauseResume, $settings.ToggleCount, $settings.LogLevel, $settings.LogMaxBytes, $settings.LogIncludeStackTrace, $settings.LogToEventLog, ((Get-ObjectKeys $settings.LogCategories | Sort-Object | ForEach-Object { "$_=$($settings.LogCategories[$_])" }) -join ",")) "INFO" $null "Init"

# --- Startup shortcut management ---
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
        $shortcut.WorkingDirectory = $scriptDir
        $shortcut.WindowStyle = 7
        $shortcut.IconLocation = if (Test-Path $iconPath) { $iconPath } else { "$env:WINDIR\System32\shell32.dll,1" }
        $shortcut.Save()
    } else {
        if (Test-Path $shortcutPath) {
            Remove-Item -Path $shortcutPath -Force
        }
    }
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

# --- Key simulation (SendInput) ---
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

# --- App state ---
# --- Runtime state and scheduling helpers ---
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

if ($settings.LastToggleTime) {
    $parsed = $null
    try {
        $parsed = [DateTime]::Parse($settings.LastToggleTime)
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
# --- Fun stats tracking ---
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
    $script:Stats = $stats
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
    Save-SettingsImmediate $settings
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
    if ($hourly.Count -eq 0) { return "N/A" }
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
    if ($daily.Count -eq 0) { return $result }

    $dates = @()
    foreach ($key in $daily.Keys) {
        $count = [int]$daily[$key]
        if ($count -gt 0) {
            try { $dates += [DateTime]::ParseExact($key, "yyyy-MM-dd", $null) } catch { }
        }
    }
    if ($dates.Count -eq 0) { return $result }
    $dates = $dates | Sort-Object

    $best = 1
    $current = 1
    for ($i = 1; $i -lt $dates.Count; $i++) {
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
# --- Stats persistence and next-toggle calculations ---
function Save-Stats {
    if ($null -eq $settings.ToggleCount) { $settings.ToggleCount = 0 }
    $settings.LastToggleTime = if ($script:lastToggleTime) { $script:lastToggleTime.ToString("o") } else { $null }
    Ensure-FunStats $settings | Out-Null
    Save-Settings $settings
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
function Normalize-IntervalSeconds([int]$seconds) {
    if ($seconds -lt 5) { return 5 }
    if ($seconds -gt 86400) { return 86400 }
    return $seconds
}

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
    $startupText = if ($settings.StartWithWindows) { "On" } else { "Off" }
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
    $scheduleShort = if (-not [bool]$settings.ScheduleEnabled) { "Off" } elseif ($script:isScheduleSuspended) { "Susp" } elseif ($script:isScheduleBlocked) { "Hold" } else { "On" }
    $parts = @("Teams-Always-Green ($state)", "N:$nextShort", "S:$scheduleShort", "SU:$startupText")
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
    } elseif ($registered -gt 0) {
        $script:HotkeyStatusText = "Registered ($registered)"
    } else {
        $script:HotkeyStatusText = "Disabled"
    }
    Write-Log ("Metadata: Hotkeys={0}" -f $script:HotkeyStatusText) "INFO" $null "Hotkey"
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

function Start-LogSummaryTimer {
    if ($script:LogLevel -ne "DEBUG") {
        Stop-LogSummaryTimer
        return
    }
    if (-not $script:LogSummaryTimer) {
        $script:LogSummaryTimer = New-Object System.Windows.Forms.Timer
        $script:LogSummaryTimer.Interval = [int]($script:LogSummaryIntervalMinutes * 60000)
        $script:LogSummaryTimer.Add_Tick({
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
        $commands = Get-Content -Path $script:CommandFilePath -ErrorAction SilentlyContinue
        Remove-Item -Path $script:CommandFilePath -Force -ErrorAction SilentlyContinue
    } catch {
        return
    }
    foreach ($command in $commands) {
        if ([string]::IsNullOrWhiteSpace($command)) { continue }
        switch ($command.Trim().ToUpperInvariant()) {
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
                    Write-Log "UI: Simulated hotkey: Toggle Now" "INFO" $null "Hotkey-Test"
                    Do-Toggle "hotkey-test"
                } catch {
                    Write-Log "Hotkey test (Toggle Now) failed." "ERROR" $_.Exception "Hotkey-Test"
                }
            }
            "HOTKEY_STARTSTOP" {
                try {
                    Set-LastUserAction "Test Hotkey: Start/Stop" "Settings"
                    Write-Log "UI: Simulated hotkey: Start/Stop" "INFO" $null "Hotkey-Test"
                    if ($script:isRunning) { Stop-Toggling } else { Start-Toggling }
                } catch {
                    Write-Log "Hotkey test (Start/Stop) failed." "ERROR" $_.Exception "Hotkey-Test"
                }
            }
            "HOTKEY_PAUSERESUME" {
                try {
                    Set-LastUserAction "Test Hotkey: Pause/Resume" "Settings"
                    Write-Log "UI: Simulated hotkey: Pause/Resume" "INFO" $null "Hotkey-Test"
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
    Write-Log ("UI: Log level change requested: {0} -> {1} (source={2})" -f $previous, $upper, $source) "INFO" $null "LogLevel" -Force
    Save-Settings $settings
    Update-LogLevelMenuChecks
    Write-Log "UI: Log level set to $upper (source=$source)." "INFO" $null "LogLevel" -Force
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
            Write-Log ("UI: Last action: {0}" -f $actionLabel) "INFO" $null "Action"
            $script:LastActionLogged = $actionLabel
        }
        $script:StatusStateColor = Get-StatusStateColor $state
        $showSeconds = ([int]$settings.IntervalSeconds -lt 60)
        $lastText = Format-TimeOrNever $script:lastToggleTime $showSeconds
        $nextText = Format-NextInfo
        $pauseUntilText = Format-PauseUntilText
        $snapshot = "$state|$($settings.IntervalSeconds)|$($script:tickCount)|$lastText|$nextText|$pauseUntilText"
        $now = $script:Now
        if ($script:LastStatusSnapshot -eq $snapshot -and (($now - $script:LastStatusUpdateTime).TotalMilliseconds -lt 500)) {
            return
        }
        $script:LastStatusSnapshot = $snapshot
        $script:LastStatusUpdateTime = $now
        if ($script:lastState -ne $state) {
            Write-Log "State changed from $($script:lastState) to $state. Next=$nextText" "INFO" $null "State"
            $script:lastState = $state
        }
        $script:StatusStateText = $state
        $statusLineState.Text = "Status: $state"
        $statusLineState.Tag = $state
        $statusLineState.ForeColor = $script:StatusStateColor
        $statusLineInterval.Text = "Interval: $($settings.IntervalSeconds)s"
        $statusLineToggles.Text = "Toggles: $($script:tickCount)"
        $statusLineLast.Text = "Last: $lastText"
        $statusLineNext.Text = "Next: $nextText"
        $statusLinePauseUntil.Text = "Paused Until: $pauseUntilText"
        $scheduleText = Format-ScheduleStatus
        if ($statusLineSchedule) { $statusLineSchedule.Text = "Schedule: $scheduleText" }
        if ($statusLineSafeMode) { $statusLineSafeMode.Text = "Safe Mode: " + ($(if ($script:safeModeActive) { "On" } else { "Off" })) }
        if ($script:pauseResumeItem) { $script:pauseResumeItem.Enabled = $script:isPaused }
        if ($resetSafeModeItem) { $resetSafeModeItem.Enabled = $script:safeModeActive }
        Update-NotifyIconState
        Update-NotifyIconText $state
        Write-StatusSnapshot $state $lastText $nextText $pauseUntilText $scheduleText
    } finally {
        $script:Now = $null
        $script:StatusUpdateInProgress = $false
    }
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
    if (-not $settings.SafeModeEnabled) {
        $script:safeModeActive = $false
        $script:toggleFailCount = 0
    }
    Update-LogCategorySettings
    Register-Hotkeys
    Rebuild-PauseMenu
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
    if ($script:isShuttingDown -or $script:CleanupDone) { return }
    if ($script:isTicking) {
        Write-LogThrottled "Timer" "Timer tick skipped (re-entrancy guard)." "WARN" 5
        return
    }
    $script:isTicking = $true
    try {
        if (Update-ScheduleBlock) {
            Request-StatusUpdate
            return
        }
        Do-Toggle "timer"
    } finally {
        $script:isTicking = $false
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
    $startItem.Enabled = $false
    $stopItem.Enabled  = $true
    if (-not $script:isShuttingDown -and $notifyIcon) { $notifyIcon.Text = "Teams-Always-Green (Running)" }
    Write-Log "[STATE] Toggling started. IntervalSeconds=$($settings.IntervalSeconds)" "INFO" $null "Start-Toggling"
    if ($wasPaused) {
        Write-Log "[STATE] Resumed from pause." "INFO" $null "Start-Toggling"
    }
    Log-StateSummary "Start-Toggling"
    Show-Balloon "Teams-Always-Green" "Started." ([System.Windows.Forms.ToolTipIcon]::Info)
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
    $startItem.Enabled = $true
    $stopItem.Enabled  = $false
    if (-not $script:isShuttingDown -and $notifyIcon) { $notifyIcon.Text = "Teams-Always-Green (Stopped)" }
    Write-Log "[STATE] Toggling stopped." "INFO" $null "Stop-Toggling"
    Log-StateSummary "Stop-Toggling"
    Show-Balloon "Teams-Always-Green" "Stopped." ([System.Windows.Forms.ToolTipIcon]::Info)
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

# --- Tray icon + context menu ---
$contextMenu = New-Object System.Windows.Forms.ContextMenuStrip

$startItem = New-Object System.Windows.Forms.ToolStripMenuItem("Start")
$startItem.Add_Click({ Start-Toggling })

$stopItem = New-Object System.Windows.Forms.ToolStripMenuItem("Stop")
$stopItem.Enabled = $false
$stopItem.Add_Click({ Stop-Toggling })

$toggleNowItem = New-Object System.Windows.Forms.ToolStripMenuItem("Toggle Now")
$toggleNowItem.Add_Click({ Do-Toggle "manual" })

$statusItem = New-Object System.Windows.Forms.ToolStripMenuItem("Status")
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
    if ($script:isShuttingDown -or $script:CleanupDone) { return }
    Request-StatusUpdate
})

function Set-StatusUpdateTimerEnabled([bool]$enabled) {
    if ($enabled) {
        if (-not $statusUpdateTimer.Enabled) { $statusUpdateTimer.Start() }
    } elseif ($statusUpdateTimer.Enabled) {
        $statusUpdateTimer.Stop()
    }
}

$intervalMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Interval")

function Set-Interval([int]$seconds) {
    $oldInterval = [int]$settings.IntervalSeconds
    $settings.IntervalSeconds = Normalize-IntervalSeconds $seconds
    Save-Settings $settings
    $timer.Interval = $settings.IntervalSeconds * 1000
    if ($script:isRunning) { Update-NextToggleTime }
    Request-StatusUpdate
    Write-Log "Interval changed from $oldInterval to $($settings.IntervalSeconds) seconds (running=$script:isRunning)." "INFO" $null "Set-Interval"
}

function Prompt-CustomIntervalSeconds {
    $current = [string]$settings.IntervalSeconds
    $input = [Microsoft.VisualBasic.Interaction]::InputBox(
        "Enter custom interval in seconds (5-86400).",
        "Custom Interval",
        $current
    )
    if ([string]::IsNullOrWhiteSpace($input)) { return $null }
    $value = 0
    if (-not [int]::TryParse($input, [ref]$value)) { return $null }
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
        Set-Interval ([int]$sender.Tag)
    })
    if ($settings.IntervalSeconds -eq $seconds) { $item.Checked = $true }
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
})

$intervalMenu.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
$intervalMenu.DropDownItems.Add($customIntervalItem) | Out-Null

$pauseMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Pause")
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
            Pause-Toggling ([int]$sender.Tag)
        })
        $pauseMenu.DropDownItems.Add($item) | Out-Null
    }
    $pauseUntilItem = New-Object System.Windows.Forms.ToolStripMenuItem("Pause until...")
    $pauseUntilItem.Add_Click({
        Show-PauseUntilDialog
    })
    $pauseMenu.DropDownItems.Add($pauseUntilItem) | Out-Null
    $pauseMenu.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
    $script:pauseResumeItem = New-Object System.Windows.Forms.ToolStripMenuItem("Resume")
    $script:pauseResumeItem.Enabled = $false
    $script:pauseResumeItem.Add_Click({
        if ($script:isPaused) {
            Start-Toggling
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
$resetSafeModeItem.Add_Click({ Reset-SafeMode })

$quietModeItem = New-Object System.Windows.Forms.ToolStripMenuItem("Quiet Mode")
$quietModeItem.CheckOnClick = $true
$quietModeItem.Checked = [bool]$settings.QuietMode
$quietModeItem.Add_Click({
    if ($null -ne $applyQuietMode) {
        & $applyQuietMode $quietModeItem.Checked
    } else {
        $settings.QuietMode = $quietModeItem.Checked
        Save-Settings $settings
    }
})

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

$quickSettingsMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Quick Settings")
$quickStartOnLaunchItem = New-Object System.Windows.Forms.ToolStripMenuItem("Start on Launch")
$quickStartOnLaunchItem.CheckOnClick = $true
$quickStartOnLaunchItem.Checked = [bool]$settings.StartOnLaunch
$quickStartOnLaunchItem.Add_Click({
    if ($null -ne $applyStartOnLaunch) {
        & $applyStartOnLaunch $quickStartOnLaunchItem.Checked
    }
})

$quickRunOnceOnLaunchItem = New-Object System.Windows.Forms.ToolStripMenuItem("Run Once on Launch")
$quickRunOnceOnLaunchItem.CheckOnClick = $true
$quickRunOnceOnLaunchItem.Checked = [bool]$settings.RunOnceOnLaunch
$quickRunOnceOnLaunchItem.Add_Click({
    if ($null -ne $applyRunOnceOnLaunch) {
        & $applyRunOnceOnLaunch $quickRunOnceOnLaunchItem.Checked
    }
})

$quickQuietModeItem = New-Object System.Windows.Forms.ToolStripMenuItem("Quiet Mode")
$quickQuietModeItem.CheckOnClick = $true
$quickQuietModeItem.Checked = [bool]$settings.QuietMode
$quickQuietModeItem.Add_Click({
    if ($null -ne $applyQuietMode) {
        & $applyQuietMode $quickQuietModeItem.Checked
    }
})

$quickSettingsMenu.DropDownItems.Add($quickStartOnLaunchItem) | Out-Null
$quickSettingsMenu.DropDownItems.Add($quickRunOnceOnLaunchItem) | Out-Null
$quickSettingsMenu.DropDownItems.Add($quickQuietModeItem) | Out-Null

$updateQuickSettingsChecks = {
    $quickStartOnLaunchItem.Checked = [bool]$settings.StartOnLaunch
    $quickRunOnceOnLaunchItem.Checked = [bool]$settings.RunOnceOnLaunch
    $quickQuietModeItem.Checked = [bool]$settings.QuietMode
    $quietModeItem.Checked = [bool]$settings.QuietMode
}

$applyQuietMode = {
    param([bool]$value)
    $settings.QuietMode = $value
    Save-Settings $settings
    & $updateQuickSettingsChecks
}

$applyStartOnLaunch = {
    param([bool]$value)
    $settings.StartOnLaunch = $value
    Save-Settings $settings
    & $updateQuickSettingsChecks
}

$applyRunOnceOnLaunch = {
    param([bool]$value)
    $settings.RunOnceOnLaunch = $value
    Save-Settings $settings
    & $updateQuickSettingsChecks
}

$profilesMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Profiles")

function Switch-ToProfile([string]$name) {
    if (-not ((Get-ObjectKeys $settings.Profiles) -contains $name)) { return }
    $settings.ActiveProfile = $name
    $settings = Apply-ProfileSnapshot $settings $settings.Profiles[$name]
    Save-Settings $settings
    Apply-SettingsRuntime
    if ($updateProfilesMenu) { & $updateProfilesMenu }
    Write-Log "Profile switched: $name" "INFO" $null "Profiles"
}

$updateProfilesMenu = {
    if (-not $profilesMenu) { return }
    $profilesMenu.DropDownItems.Clear()
    $names = @(Get-ObjectKeys $settings.Profiles) | Sort-Object
    foreach ($name in $names) {
        $item = New-Object System.Windows.Forms.ToolStripMenuItem($name)
        $item.CheckOnClick = $true
        $item.Checked = ($settings.ActiveProfile -eq $name)
        $item.Add_Click({
            param($sender, $e)
            Switch-ToProfile $sender.Text
        })
        $profilesMenu.DropDownItems.Add($item) | Out-Null
    }
    $profilesMenu.Enabled = ($names.Count -gt 0)
}

& $updateProfilesMenu

$runOnceNowItem = New-Object System.Windows.Forms.ToolStripMenuItem("Run Once Now")
$runOnceNowItem.Add_Click({
    Do-Toggle "manual"
})

# --- Settings dialog creation and event wiring ---
function Show-SettingsDialog {
    Write-Log "UI: Settings open requested." "INFO" $null "Settings-Dialog" -Force
    try {
        $script:SettingsDialogStart = Get-Date
        if ($script:SettingsForm -and -not $script:SettingsForm.IsDisposed) {
            try {
                if (-not $script:SettingsForm.Visible) {
                    $script:SettingsForm.Show()
                }
                $script:SettingsForm.WindowState = [System.Windows.Forms.FormWindowState]::Normal
                $script:SettingsForm.BringToFront()
                $script:SettingsForm.Activate()
                $settingsIconPath = Join-Path (Split-Path -Path $scriptPath -Parent) "Meta\\Icons\\Settings_Icon.ico"
                Set-FormTaskbarIcon $script:SettingsForm $settingsIconPath
            } catch {
                Write-Log "UI: Settings open failed while reusing existing form." "ERROR" $_.Exception "Settings-Dialog"
            }
            return
        }
        $form = New-Object System.Windows.Forms.Form
        $script:SettingsForm = $form
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

    $tabControl = New-Object System.Windows.Forms.TabControl
    $tabControl.Dock = "Fill"
    $script:SettingsTabControl = $tabControl

    $toolTip = New-Object System.Windows.Forms.ToolTip

    $statusGroup = New-Object System.Windows.Forms.GroupBox
    $statusGroup.Text = "Current Status"
    $statusGroup.Dock = "Top"
    $statusGroup.AutoSize = $true
    $statusGroup.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $statusGroup.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)

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
    $funLongestPauseLabel.Text = "Longest Pause Used"
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

    $topPanel = New-Object System.Windows.Forms.Panel
    $topPanel.Dock = "Top"
    $topPanel.AutoSize = $true
    $topPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink

    $script:SettingsDirtyLabel = New-Object System.Windows.Forms.Label
    $script:SettingsDirtyLabel.Text = "Unsaved changes"
    $script:SettingsDirtyLabel.ForeColor = [System.Drawing.Color]::DarkOrange
    $script:SettingsDirtyLabel.AutoSize = $true
    $script:SettingsDirtyLabel.Margin = New-Object System.Windows.Forms.Padding(12, 6, 0, 0)
    $script:SettingsDirtyLabel.Visible = $false
    $script:SettingsDirtyLabel.Dock = "Top"

    $script:SettingsSaveLabel = New-Object System.Windows.Forms.Label
    $script:SettingsSaveLabel.Text = "Settings saved"
    $script:SettingsSaveLabel.ForeColor = [System.Drawing.Color]::LightGreen
    $script:SettingsSaveLabel.AutoSize = $true
    $script:SettingsSaveLabel.Margin = New-Object System.Windows.Forms.Padding(12, 0, 0, 6)
    $script:SettingsSaveLabel.Visible = $false
    $script:SettingsSaveLabel.Dock = "Top"

    $topPanel.Controls.Add($script:SettingsDirtyLabel)
    $topPanel.Controls.Add($script:SettingsSaveLabel)
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

    $addFullRow = {
        param($panel, $control)
        if ($panel -is [System.Windows.Forms.TableLayoutPanel]) {
            [void]$panel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
            [void]$panel.Controls.Add($control, 0, $panel.RowCount)
            $panel.SetColumnSpan($control, 2)
            $panel.RowCount++
        }
    }

    $addSpacerRow = {
        param($panel, [int]$height = 10)
        if ($panel -is [System.Windows.Forms.TableLayoutPanel]) {
            $spacer = New-Object System.Windows.Forms.Label
            $spacer.Text = ""
            $spacer.AutoSize = $false
            $spacer.Height = $height
            $spacer.Width = 1
            [void]$panel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, $height)))
            [void]$panel.Controls.Add($spacer, 0, $panel.RowCount)
            $panel.SetColumnSpan($spacer, 2)
            $panel.RowCount++
        }
    }

    $addSectionHeader = {
        param($panel, [string]$title)
        if (-not ($panel -is [System.Windows.Forms.TableLayoutPanel])) { return }
        $headerPanel = New-Object System.Windows.Forms.TableLayoutPanel
        $headerPanel.ColumnCount = 2
        $headerPanel.RowCount = 1
        $headerPanel.AutoSize = $true
        $headerPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $headerPanel.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::AddColumns
        $headerPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
        $headerPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))

        $columnIndex = 0
        $iconPath = Join-Path $scriptDir ("Meta\\Icons\\{0}_icon.ico" -f $title)
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

        & $addFullRow $panel $headerPanel
        & $addSpacerRow $panel 6
    }

    $createTabPanel = {
        param([string]$title)
        $page = New-Object System.Windows.Forms.TabPage
        $page.Text = $title
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
        $page = $script:SettingsTabControl.TabPages | Where-Object { $_.Text -eq $pageTitle } | Select-Object -First 1
        if (-not $page) { return $panel }
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

    $script:rememberChoiceBox = New-Object System.Windows.Forms.CheckBox
    $script:rememberChoiceBox.Checked = [bool]$settings.RememberChoice
    $script:rememberChoiceBox.AutoSize = $true

    $script:startOnLaunchBox = New-Object System.Windows.Forms.CheckBox
    $script:startOnLaunchBox.Checked = [bool]$settings.StartOnLaunch
    $script:startOnLaunchBox.AutoSize = $true

    $script:quietModeBox = New-Object System.Windows.Forms.CheckBox
    $script:quietModeBox.Checked = [bool]$settings.QuietMode
    $script:quietModeBox.AutoSize = $true

    $script:tooltipStyleBox = New-Object System.Windows.Forms.ComboBox
    $script:tooltipStyleBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $script:tooltipStyleBox.Items.AddRange(@("Minimal", "Standard", "Verbose"))
    $script:tooltipStyleBox.Width = 140

    $script:disableBalloonBox = New-Object System.Windows.Forms.CheckBox
    $script:disableBalloonBox.Checked = [bool]$settings.DisableBalloonTips
    $script:disableBalloonBox.AutoSize = $true

    $script:themeModeBox = New-Object System.Windows.Forms.ComboBox
    $script:themeModeBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $script:themeModeBox.Items.AddRange(@("Auto Detect", "Light", "Dark", "High Contrast"))
    $script:themeModeBox.Width = 140

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

    $statusRunningColorButton = New-Object System.Windows.Forms.Button
    $statusRunningColorButton.Text = "Change..."
    $statusRunningColorButton.Width = 80

    $statusRunningColorRow = New-Object System.Windows.Forms.FlowLayoutPanel
    $statusRunningColorRow.FlowDirection = "LeftToRight"
    $statusRunningColorRow.AutoSize = $true
    $statusRunningColorRow.WrapContents = $false
    $statusRunningColorRow.Controls.Add($script:statusRunningColorPanel) | Out-Null
    $statusRunningColorRow.Controls.Add($statusRunningColorButton) | Out-Null
    $statusRunningColorRow.Tag = "Status Color (Running)"
    $script:statusRunningColorPanel.Tag = "Status Color (Running)"
    $statusRunningColorButton.Tag = "Status Color (Running)"

    $script:statusPausedColorPanel = New-Object System.Windows.Forms.Panel
    $script:statusPausedColorPanel.Size = New-Object System.Drawing.Size(28, 16)

    $statusPausedColorButton = New-Object System.Windows.Forms.Button
    $statusPausedColorButton.Text = "Change..."
    $statusPausedColorButton.Width = 80

    $statusPausedColorRow = New-Object System.Windows.Forms.FlowLayoutPanel
    $statusPausedColorRow.FlowDirection = "LeftToRight"
    $statusPausedColorRow.AutoSize = $true
    $statusPausedColorRow.WrapContents = $false
    $statusPausedColorRow.Controls.Add($script:statusPausedColorPanel) | Out-Null
    $statusPausedColorRow.Controls.Add($statusPausedColorButton) | Out-Null
    $statusPausedColorRow.Tag = "Status Color (Paused)"
    $script:statusPausedColorPanel.Tag = "Status Color (Paused)"
    $statusPausedColorButton.Tag = "Status Color (Paused)"

    $script:statusStoppedColorPanel = New-Object System.Windows.Forms.Panel
    $script:statusStoppedColorPanel.Size = New-Object System.Drawing.Size(28, 16)

    $statusStoppedColorButton = New-Object System.Windows.Forms.Button
    $statusStoppedColorButton.Text = "Change..."
    $statusStoppedColorButton.Width = 80

    $statusStoppedColorRow = New-Object System.Windows.Forms.FlowLayoutPanel
    $statusStoppedColorRow.FlowDirection = "LeftToRight"
    $statusStoppedColorRow.AutoSize = $true
    $statusStoppedColorRow.WrapContents = $false
    $statusStoppedColorRow.Controls.Add($script:statusStoppedColorPanel) | Out-Null
    $statusStoppedColorRow.Controls.Add($statusStoppedColorButton) | Out-Null
    $statusStoppedColorRow.Tag = "Status Color (Stopped)"
    $script:statusStoppedColorPanel.Tag = "Status Color (Stopped)"
    $statusStoppedColorButton.Tag = "Status Color (Stopped)"

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

    $appearancePreviewGroup.Controls.Add($appearancePreviewLayout)

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

    $updateAppearancePreview = {
        if ($script:PreviewTooltipValue) { $script:PreviewTooltipValue.Text = [string]$script:TooltipStyleBox.SelectedItem }
        if ($script:PreviewFontValue) { $script:PreviewFontValue.Text = "$($script:FontSizeBox.Value) pt / $($script:SettingsFontSizeBox.Value) pt" }
        if ($script:PreviewRunningPanel) { $script:PreviewRunningPanel.BackColor = $script:StatusRunningColorPanel.BackColor }
        if ($script:PreviewPausedPanel) { $script:PreviewPausedPanel.BackColor = $script:StatusPausedColorPanel.BackColor }
        if ($script:PreviewStoppedPanel) { $script:PreviewStoppedPanel.BackColor = $script:StatusStoppedColorPanel.BackColor }
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

    $statusRunningColorButton.Add_Click({ & $script:PickStatusColor $script:statusRunningColorPanel })
    $statusPausedColorButton.Add_Click({ & $script:PickStatusColor $script:statusPausedColorPanel })
    $statusStoppedColorButton.Add_Click({ & $script:PickStatusColor $script:statusStoppedColorPanel })

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
    foreach ($levelName in @("ERROR", "FATAL", "WARN", "INFO")) {
        $box = New-Object System.Windows.Forms.CheckBox
        $box.Text = $levelName
        $box.AutoSize = $true
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
    $script:logDirectoryBox.Text = if ([string]::IsNullOrWhiteSpace([string]$settings.LogDirectory)) { $script:LogDirectory } else { [string]$settings.LogDirectory }

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

    $logDirectoryPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $logDirectoryPanel.FlowDirection = "LeftToRight"
    $logDirectoryPanel.AutoSize = $true
    $logDirectoryPanel.WrapContents = $false
    $logDirectoryPanel.Controls.Add($script:logDirectoryBox) | Out-Null
    $logDirectoryPanel.Controls.Add($logDirectoryBrowseButton) | Out-Null
    $logDirectoryPanel.Tag = "Log Folder"
    $script:logDirectoryBox.Tag = "Log Folder"
    $logDirectoryBrowseButton.Tag = "Log Folder"

    $logFilesLabel = New-Object System.Windows.Forms.Label
    $logFilesLabel.AutoSize = $true
    $logFilesLabel.Text = "Teams-Always-Green.log, Teams-Always-Green.log.#, Teams-Always-Green.fallback.log, Teams-Always-Green.bootstrap.log"

    $viewLogButton = New-Object System.Windows.Forms.Button
    $viewLogButton.Text = "View Log"
    $viewLogButton.Width = 120
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
    $viewLogTailButton.Add_Click({
        Show-LogTailDialog
    })

    $exportLogTailButton = New-Object System.Windows.Forms.Button
    $exportLogTailButton.Text = "Export Log Tail..."
    $exportLogTailButton.Width = 120
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
    $logSnapshotButton.Add_Click({
        & $script:RunSettingsAction "Log Snapshot" {
            $summary = "[STATE] Running=$script:isRunning Paused=$script:isPaused Schedule=$((Format-ScheduleStatus)) Interval=$($settings.IntervalSeconds)s Profile=$($settings.ActiveProfile)"
            Write-Log $summary "INFO" $null "Log-Snapshot"
        }
    })

    $openLogFolderButton = New-Object System.Windows.Forms.Button
    $openLogFolderButton.Text = "Open Log Folder"
    $openLogFolderButton.Width = 120
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
    $simulateToggleButton.Add_Click({
        Set-LastUserAction "Test Hotkey: Toggle Now" "Settings"
        Write-Log "UI: Simulated hotkey: Toggle Now" "INFO" $null "Hotkey-Test"
        Do-Toggle "hotkey-test"
    })

    $simulateStartStopButton = New-Object System.Windows.Forms.Button
    $simulateStartStopButton.Text = "Start/Stop"
    $simulateStartStopButton.Width = 110
    $simulateStartStopButton.Add_Click({
        Set-LastUserAction "Test Hotkey: Start/Stop" "Settings"
        Write-Log "UI: Simulated hotkey: Start/Stop" "INFO" $null "Hotkey-Test"
        if ($script:isRunning) { Stop-Toggling } else { Start-Toggling }
    })

    $simulatePauseResumeButton = New-Object System.Windows.Forms.Button
    $simulatePauseResumeButton.Text = "Pause/Resume"
    $simulatePauseResumeButton.Width = 120
    $simulatePauseResumeButton.Add_Click({
        Set-LastUserAction "Test Hotkey: Pause/Resume" "Settings"
        Write-Log "UI: Simulated hotkey: Pause/Resume" "INFO" $null "Hotkey-Test"
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
        $page = $script:SettingsTabControl.TabPages | Where-Object { $_.Text -eq $title } | Select-Object -First 1
        if (-not $page) { return $null }
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
        foreach ($page in $targetTabControl.TabPages) {
            $targetWidth = [Math]::Max(200, $page.ClientSize.Width - 30)
            & $updatePanelWidth $page $targetWidth
        }

        if ($script:AboutDescValue -and $script:AboutPathValue -and $script:AboutPanel) {
            $valueWidth = [Math]::Max(200, $script:AboutPanel.Parent.ClientSize.Width - 180)
            $script:AboutDescValue.MaximumSize = New-Object System.Drawing.Size($valueWidth, 0)
            $script:AboutPathValue.MaximumSize = New-Object System.Drawing.Size($valueWidth, 0)
        }
    }
    $script:UpdateTabLayouts = $updateTabLayouts

    $profileGroup = New-Object System.Windows.Forms.GroupBox
    $profileGroup.Text = "Profiles"
    $profileGroup.AutoSize = $true
    $profileGroup.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $profileGroup.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)

    $aboutGroup = New-Object System.Windows.Forms.GroupBox
    $aboutGroup.Text = "About"
    $aboutGroup.AutoSize = $true
    $aboutGroup.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $aboutGroup.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)

    $aboutLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $aboutLayout.ColumnCount = 2
    $aboutLayout.RowCount = 20
    $aboutLayout.AutoSize = $true
    $aboutLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $aboutLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $aboutTitlePanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $aboutTitlePanel.AutoSize = $true
    $aboutTitlePanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $aboutTitlePanel.WrapContents = $false
    $aboutTitlePanel.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight

    $aboutTitleIconPath = Join-Path $scriptDir "Meta\\Icons\\Tray_Icon.ico"
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

    $aboutDescLabel = New-Object System.Windows.Forms.Label
    $aboutDescLabel.Text = "Overview"
    $aboutDescLabel.AutoSize = $true

    $aboutDescValue = New-Object System.Windows.Forms.Label
    $aboutDescValue.Text = "Keeps Microsoft Teams active by periodically toggling Scroll Lock. Runs quietly in the tray with simple controls, scheduling, and profiles so you stay available without micromanaging your status."
    $aboutDescValue.AutoSize = $true
    $aboutDescValue.MaximumSize = New-Object System.Drawing.Size(460, 0)
    $script:AboutDescValue = $aboutDescValue

    $aboutVersionLabel = New-Object System.Windows.Forms.Label
    $aboutVersionLabel.Text = "Version"
    $aboutVersionLabel.AutoSize = $true

    $aboutVersionValue = New-Object System.Windows.Forms.Label
    $aboutVersionValue.Text = $appVersion
    $aboutVersionValue.AutoSize = $true

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

    $aboutUpdatedLabel = New-Object System.Windows.Forms.Label
    $aboutUpdatedLabel.Text = "Last Updated"
    $aboutUpdatedLabel.AutoSize = $true

    $aboutUpdatedValue = New-Object System.Windows.Forms.Label
    $aboutUpdatedValue.Text = $appLastUpdated
    $aboutUpdatedValue.AutoSize = $true

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
        $release = Get-LatestReleaseInfo "alexphillips-dev" "Teams-Always-Green"
        if ($release) {
            $latestVersion = Get-ReleaseVersionString $release
            if (-not [string]::IsNullOrWhiteSpace($latestVersion) -and $script:AboutLatestReleaseValue) {
                $script:AboutLatestReleaseValue.Text = $latestVersion
            }
        }
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
    $aboutSupportLink.Text = "Report an Issue"
    $aboutSupportLink.AutoSize = $true
    $aboutSupportLink.LinkBehavior = [System.Windows.Forms.LinkBehavior]::HoverUnderline
    $aboutSupportLink.Add_LinkClicked({
        Start-Process "https://github.com/alexphillips-dev/Teams-Always-Green/issues"
    })

    $aboutSupportEmailLabel = New-Object System.Windows.Forms.Label
    $aboutSupportEmailLabel.Text = "Support Email"
    $aboutSupportEmailLabel.AutoSize = $true

    $aboutSupportEmailValue = New-Object System.Windows.Forms.Label
    $aboutSupportEmailValue.Text = "N/A (use Issues link)"
    $aboutSupportEmailValue.AutoSize = $true

    $aboutDevLabel = New-Object System.Windows.Forms.Label
    $aboutDevLabel.Text = "Developed by"
    $aboutDevLabel.AutoSize = $true

    $aboutDevValue = New-Object System.Windows.Forms.Label
    $aboutDevValue.Text = "Alex Phillips"
    $aboutDevValue.AutoSize = $true

    $aboutPartLabel = New-Object System.Windows.Forms.Label
    $aboutPartLabel.Text = "In Part By"
    $aboutPartLabel.AutoSize = $true

    $aboutPartValue = New-Object System.Windows.Forms.Label
    $aboutPartValue.Text = "GPT-5.2-Codex"
    $aboutPartValue.AutoSize = $true

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
    $aboutLayout.Controls.Add($aboutSpacer5, 0, 13)
    $aboutLayout.SetColumnSpan($aboutSpacer5, 2)
    $aboutLayout.Controls.Add($aboutSupportLabel, 0, 14)
    $aboutLayout.Controls.Add($aboutSupportLink, 1, 14)
    $aboutLayout.Controls.Add($aboutSupportEmailLabel, 0, 15)
    $aboutLayout.Controls.Add($aboutSupportEmailValue, 1, 15)
    $aboutLayout.Controls.Add($aboutSpacer6, 0, 16)
    $aboutLayout.SetColumnSpan($aboutSpacer6, 2)
    $aboutLayout.Controls.Add($aboutDevLabel, 0, 17)
    $aboutLayout.Controls.Add($aboutDevValue, 1, 17)
    $aboutLayout.Controls.Add($aboutPartLabel, 0, 18)
    $aboutLayout.Controls.Add($aboutPartValue, 1, 18)
    $aboutGroup.Controls.Add($aboutLayout)
    $script:AboutPanel = $aboutPanel

    $profileLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $profileLayout.ColumnCount = 2
    $profileLayout.RowCount = 3
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
    $duplicateProfileButton.Text = "Duplicate"
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
    $profileLayout.Controls.Add($profileActionsLayout, 1, 2)
    $profileGroup.Controls.Add($profileLayout)

    $script:refreshProfileList = {
        $script:profileBox.Items.Clear()
        $names = @(Get-ObjectKeys $settings.Profiles) | Sort-Object
        foreach ($name in $names) { [void]$script:profileBox.Items.Add($name) }
        $selected = $settings.ActiveProfile
        if (-not [string]::IsNullOrWhiteSpace($selected) -and $script:profileBox.Items.Contains($selected)) {
            $script:profileBox.SelectedItem = $selected
        } elseif ($script:profileBox.Items.Count -gt 0) {
            $script:profileBox.SelectedIndex = 0
        }
    }

    & $script:refreshProfileList

    $script:profileBox.Add_SelectedIndexChanged({
        if ($script:SettingsIsApplying) { return }
        if ($script:profileBox.SelectedItem -eq $null) { return }
        $newName = [string]$script:profileBox.SelectedItem
        if (-not ((Get-ObjectKeys $settings.Profiles) -contains $newName)) { return }
        if ($settings.ActiveProfile -eq $newName) { return }
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
        Set-SettingsDirty $false
        Save-Settings $settings
        if ($updateProfilesMenu) { & $updateProfilesMenu }
        $sw.Stop()
        Write-Log "UI: Profile switched: $newName (ms=$($sw.ElapsedMilliseconds))" "INFO" $null "Profiles"
    })

    $script:getProfileFromControls = {
        $profile = [ordered]@{}
        $profile["IntervalSeconds"] = [int]$script:intervalBox.Value
        $profile["RememberChoice"] = [bool]$script:rememberChoiceBox.Checked
        $profile["StartOnLaunch"] = [bool]$script:startOnLaunchBox.Checked
        $profile["RunOnceOnLaunch"] = [bool]$script:runOnceOnLaunchBox.Checked
        $profile["QuietMode"] = [bool]$script:quietModeBox.Checked
        $profile["TooltipStyle"] = [string]$script:tooltipStyleBox.SelectedItem
        $profile["MinimalTrayTooltip"] = ([string]$script:tooltipStyleBox.SelectedItem -eq "Minimal")
        $profile["FontSize"] = [int]$script:fontSizeBox.Value
        $profile["SettingsFontSize"] = [int]$script:settingsFontSizeBox.Value
        $profile["StatusColorRunning"] = Convert-ColorToString $script:statusRunningColorPanel.BackColor
        $profile["StatusColorPaused"] = Convert-ColorToString $script:statusPausedColorPanel.BackColor
        $profile["StatusColorStopped"] = Convert-ColorToString $script:statusStoppedColorPanel.BackColor
        $profile["CompactMode"] = [bool]$script:compactModeBox.Checked
        $profile["DisableBalloonTips"] = [bool]$script:disableBalloonBox.Checked
        $profile["PauseDurationsMinutes"] = [string]$script:pauseDurationsBox.Text
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
        return $profile
    }

    $saveProfileButton.Add_Click({
        if ($script:profileBox.SelectedItem -eq $null) { return }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $name = [string]$script:profileBox.SelectedItem
        $settings.Profiles[$name] = & $script:getProfileFromControls
        $settings.ActiveProfile = $name
        Save-Settings $settings
        if ($updateProfilesMenu) { & $updateProfilesMenu }
        $sw.Stop()
        Write-Log "UI: Profile saved: $name (ms=$($sw.ElapsedMilliseconds))" "INFO" $null "Profiles"
    })

    $saveAsProfileButton.Add_Click({
        $defaultName = if ($script:profileBox.SelectedItem) { [string]$script:profileBox.SelectedItem } else { "New Profile" }
        $name = [Microsoft.VisualBasic.Interaction]::InputBox("Profile name:", "Save As Profile", $defaultName)
        if ([string]::IsNullOrWhiteSpace($name)) { return }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $name = $name.Trim()
        if ((Get-ObjectKeys $settings.Profiles) -contains $name) {
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
        Save-Settings $settings
        if ($updateProfilesMenu) { & $updateProfilesMenu }
        $sw.Stop()
        Write-Log "UI: Profile saved as: $name (ms=$($sw.ElapsedMilliseconds))" "INFO" $null "Profiles"
    })

    $duplicateProfileButton.Add_Click({
        if ($script:profileBox.SelectedItem -eq $null) { return }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $sourceName = [string]$script:profileBox.SelectedItem
        $defaultName = "$sourceName Copy"
        $name = [Microsoft.VisualBasic.Interaction]::InputBox("Duplicate profile name:", "Duplicate Profile", $defaultName)
        if ([string]::IsNullOrWhiteSpace($name)) { return }
        $name = $name.Trim()
        if (-not ($settings.Profiles -is [hashtable])) {
            $table = @{}
            foreach ($key in Get-ObjectKeys $settings.Profiles) { $table[$key] = $settings.Profiles.$key }
            $settings.Profiles = $table
        }
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
        Save-Settings $settings
        & $script:refreshProfileList
        if ($updateProfilesMenu) { & $updateProfilesMenu }
        $sw.Stop()
        Write-Log "UI: Profile duplicated: $sourceName -> $name (ms=$($sw.ElapsedMilliseconds))" "INFO" $null "Profiles"
    })

    $loadProfileButton.Add_Click({
        if ($script:profileBox.SelectedItem -eq $null) { return }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $name = [string]$script:profileBox.SelectedItem
        if (-not ((Get-ObjectKeys $settings.Profiles) -contains $name)) { return }
        Write-Log "UI: ---------- Profile Load ----------" "INFO" $null "Profiles"
        $merged = [pscustomobject]@{}
        foreach ($prop in $settings.PSObject.Properties.Name) {
            $merged | Add-Member -MemberType NoteProperty -Name $prop -Value $settings.$prop
        }
        $merged = Apply-ProfileSnapshot $merged $settings.Profiles[$name]
        & $applySettingsToControls $merged
        $settings.ActiveProfile = $name
        Set-SettingsDirty $true
        if ($updateProfilesMenu) { & $updateProfilesMenu }
        $sw.Stop()
        Write-Log "UI: Profile loaded: $name (ms=$($sw.ElapsedMilliseconds))" "INFO" $null "Profiles"
    })

    $newProfileButton.Add_Click({
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
        Save-Settings $settings
        & $script:refreshProfileList
        if ($updateProfilesMenu) { & $updateProfilesMenu }
        $sw.Stop()
        Write-Log "UI: Profile created: $name (ms=$($sw.ElapsedMilliseconds))" "INFO" $null "Profiles"
    })

    $renameProfileButton.Add_Click({
        if ($script:profileBox.SelectedItem -eq $null) { return }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $oldName = [string]$script:profileBox.SelectedItem
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
        if (-not ($settings.Profiles -is [hashtable])) {
            $table = @{}
            foreach ($key in Get-ObjectKeys $settings.Profiles) { $table[$key] = $settings.Profiles.$key }
            $settings.Profiles = $table
        }
        $settings.Profiles[$name] = $settings.Profiles[$oldName]
        $settings.Profiles.Remove($oldName)
        if ($settings.ActiveProfile -eq $oldName) { $settings.ActiveProfile = $name }
        Save-Settings $settings
        & $script:refreshProfileList
        if ($updateProfilesMenu) { & $updateProfilesMenu }
        $sw.Stop()
        Write-Log "UI: Profile renamed: $oldName -> $name (ms=$($sw.ElapsedMilliseconds))" "INFO" $null "Profiles"
    })

    $deleteProfileButton.Add_Click({
        if ($script:profileBox.SelectedItem -eq $null) { return }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $name = [string]$script:profileBox.SelectedItem
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
        if (-not ($settings.Profiles -is [hashtable])) {
            $table = @{}
            foreach ($key in Get-ObjectKeys $settings.Profiles) { $table[$key] = $settings.Profiles.$key }
            $settings.Profiles = $table
        }
        $settings.Profiles.Remove($name)
        if ($settings.ActiveProfile -eq $name) {
            $profileKeys = @(Get-ObjectKeys $settings.Profiles)
            if ($profileKeys.Count -gt 0) { $settings.ActiveProfile = $profileKeys[0] }
        }
        Save-Settings $settings
        & $script:refreshProfileList
        if ($updateProfilesMenu) { & $updateProfilesMenu }
        $sw.Stop()
        Write-Log "UI: Profile deleted: $name (ms=$($sw.ElapsedMilliseconds))" "INFO" $null "Profiles"
    })

    $exportProfileButton.Add_Click({
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
            $name = [Microsoft.VisualBasic.Interaction]::InputBox("Profile name:", "Import Profile", $defaultName)
            if ([string]::IsNullOrWhiteSpace($name)) { return }
            $name = $name.Trim()
            if ((Get-ObjectKeys $settings.Profiles) -contains $name) {
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
    $script:settingsDirectoryBox.Text = if ([string]::IsNullOrWhiteSpace([string]$settings.SettingsDirectory)) { $script:SettingsDirectory } else { [string]$settings.SettingsDirectory }

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

    $settingsDirectoryPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $settingsDirectoryPanel.FlowDirection = "LeftToRight"
    $settingsDirectoryPanel.AutoSize = $true
    $settingsDirectoryPanel.WrapContents = $false
    $settingsDirectoryPanel.Controls.Add($script:settingsDirectoryBox) | Out-Null
    $settingsDirectoryPanel.Controls.Add($settingsDirectoryBrowseButton) | Out-Null
    $settingsDirectoryPanel.Tag = "Settings Folder"
    $script:settingsDirectoryBox.Tag = "Settings Folder"
    $settingsDirectoryBrowseButton.Tag = "Settings Folder"

    $settingsFilesLabel = New-Object System.Windows.Forms.Label
    $settingsFilesLabel.AutoSize = $true
    $settingsFilesLabel.Text = "Teams-Always-Green.settings.json, Teams-Always-Green.settings.json.bak#"

    & $addFullRow $statusPanel $statusGroup
    & $addFullRow $statusPanel $toggleGroup
    & $addFullRow $statusPanel $funStatsGroup

    & $addFullRow $profilesPanel $profileGroup

    & $addSettingRow $generalPanel "Interval Seconds" $script:intervalBox | Out-Null
    $script:ErrorLabels = @{}
    $script:ErrorLabels["Interval Seconds"] = & $addErrorRow $generalPanel
    & $addSettingRow $generalPanel "Start with Windows" $script:startWithWindowsBox | Out-Null
    & $addSettingRow $generalPanel "Open Settings at Last Tab" $script:openSettingsLastTabBox | Out-Null
    & $addSettingRow $generalPanel "Remember Choice" $script:rememberChoiceBox | Out-Null
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
    & $addSpacerRow $generalPanel
    & $addSettingRow $generalPanel "Settings Folder" $settingsDirectoryPanel | Out-Null
    & $addSettingRow $generalPanel "Settings Files" $settingsFilesLabel | Out-Null
    & $addSpacerRow $generalPanel
    & $addSettingRow $generalPanel "Export/Import Settings" $settingsTransferPanel | Out-Null

    & $addSettingRow $appearancePanel "Quiet Mode" $script:quietModeBox | Out-Null
    & $addSettingRow $appearancePanel "Tray Tooltip Style" $script:tooltipStyleBox | Out-Null
    & $addSettingRow $appearancePanel "Disable Tray Balloon Tips" $script:disableBalloonBox | Out-Null
    & $addSettingRow $appearancePanel "Theme Mode" $script:themeModeBox | Out-Null
    & $addSettingRow $appearancePanel "Font Size (Tray)" $fontSizePanel | Out-Null
    & $addSettingRow $appearancePanel "Settings Font Size" $settingsFontSizePanel | Out-Null
    & $addSettingRow $appearancePanel "Status Color (Running)" $statusRunningColorRow | Out-Null
    & $addSettingRow $appearancePanel "Status Color (Paused)" $statusPausedColorRow | Out-Null
    & $addSettingRow $appearancePanel "Status Color (Stopped)" $statusStoppedColorRow | Out-Null
    & $addSettingRow $appearancePanel "Compact Mode" $script:compactModeBox | Out-Null
    & $addSpacerRow $appearancePanel
    & $addFullRow $appearancePanel $appearancePreviewGroup

    & $addFullRow $aboutPanel $aboutGroup

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
    & $addSpacerRow $hotkeyPanel
    & $addSettingRow $hotkeyPanel "Validate Hotkeys" $validateHotkeysButton | Out-Null
    & $addSettingRow $hotkeyPanel "Test Hotkeys" $simulateHotkeysPanel | Out-Null

    & $addSettingRow $advancedPanel "Safe Mode Enabled" $script:SafeModeEnabledBox | Out-Null
    & $addSettingRow $advancedPanel "Safe Mode Failure Threshold" $script:safeModeThresholdBox | Out-Null
    $script:ErrorLabels["Safe Mode Failure Threshold"] = & $addErrorRow $advancedPanel
    & $addSpacerRow $advancedPanel
    & $addSettingRow $advancedPanel "Log Level" $script:logLevelBox | Out-Null
    & $addSettingRow $advancedPanel "Include Stack Trace" $script:logIncludeStackTraceBox | Out-Null
    & $addSettingRow $advancedPanel "Verbose UI Logging" $script:verboseUiLogBox | Out-Null
    & $addSettingRow $advancedPanel "Enable Event Log" $script:logToEventLogBox | Out-Null
    & $addSettingRow $advancedPanel "Event Log Levels" $eventLogLevelPanel | Out-Null
    & $addSettingRow $advancedPanel "Debug Mode" $debugModeButton | Out-Null
    & $addSettingRow $advancedPanel "Debug Status" $debugModeStatus | Out-Null
    & $addSpacerRow $advancedPanel
    & $addSettingRow $loggingPanel "Log Folder" $logDirectoryPanel | Out-Null
    & $addSettingRow $loggingPanel "Log Files" $logFilesLabel | Out-Null
    & $addSpacerRow $loggingPanel

    $logMaxSizePanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $logMaxSizePanel.FlowDirection = "LeftToRight"
    $logMaxSizePanel.AutoSize = $true
    $logMaxSizePanel.WrapContents = $false
    $logMaxSizePanel.Controls.Add($script:logMaxBox) | Out-Null
    $logMaxSizePanel.Controls.Add($logSizeValue) | Out-Null

    & $addSettingRow $loggingPanel "Log Max Size (KB)" $logMaxSizePanel | Out-Null
    $script:ErrorLabels["Log Max Size (KB)"] = & $addErrorRow $loggingPanel
    & $addSettingRow $loggingPanel "Log Retention (days)" $script:logRetentionBox | Out-Null
    & $addSettingRow $loggingPanel "Open Log File" $viewLogButton | Out-Null
    & $addSettingRow $loggingPanel "Open Log Tail" $viewLogTailButton | Out-Null
    & $addSettingRow $loggingPanel "Export Log Tail" $exportLogTailButton | Out-Null
    & $addSettingRow $loggingPanel "Log Snapshot" $logSnapshotButton | Out-Null
    & $addSettingRow $loggingPanel "Clear Log" $clearLogButton | Out-Null
    & $addSettingRow $loggingPanel "Open Log Folder" $openLogFolderButton | Out-Null

    & $addSettingRow $diagnosticsPanel "Export Diagnostics" $exportDiagnosticsButton | Out-Null
    & $addSettingRow $diagnosticsPanel "Copy Diagnostics" $copyDiagnosticsButton | Out-Null
    & $addSettingRow $diagnosticsPanel "Scrub Diagnostics" $scrubDiagnosticsBox | Out-Null
    & $addSettingRow $diagnosticsPanel "Report Issue" $reportIssueButton | Out-Null
    & $addSpacerRow $diagnosticsPanel
    & $addFullRow $diagnosticsPanel $logCategoryGroup
    & $addSpacerRow $diagnosticsPanel
    & $addFullRow $diagnosticsPanel $diagnosticsGroup

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
        Write-Log "UI: Settings closed via Cancel." "INFO" $null "Settings-Dialog" -Force
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
    $settingsDialogLastSaved = $null

    $script:CopySettingsObject = {
        param($src)
        if ($null -eq $src) { return $null }
        return ($src | ConvertTo-Json -Depth 6 | ConvertFrom-Json)
    }

    $script:UpdateLastSavedLabel = {
        param($time)
        if ($time -is [DateTime]) {
            $script:LastSavedLabel.Text = "Last saved: $(Format-DateTime $time)"
            return
        }
        if (Test-Path $settingsPath) {
            try {
                $script:LastSavedLabel.Text = "Last saved: $(Format-DateTime (Get-Item -Path $settingsPath).LastWriteTime)"
                return
            } catch { }
        }
        $script:LastSavedLabel.Text = "Last saved: Never"
    }
    $script:SetDirty = {
        param([bool]$value)
        if ($settingsDirty -eq $value) { return }
        $settingsDirty = $value
        $script:SettingsDirty = $value
        if ($script:SettingsOkButton) { $script:SettingsOkButton.Enabled = $value }
        if ($script:SettingsDirtyLabel) { $script:SettingsDirtyLabel.Visible = $value }
        if ($value -and $script:SettingsSaveLabel) { $script:SettingsSaveLabel.Visible = $false }
    }

    $runSettingsAction = {
        param([string]$name, [scriptblock]$action)
        Set-LastUserAction $name "Settings"
        try {
            $actionStart = Get-Date
            if ($settings.VerboseUiLogging) {
                Write-Log "UI: Settings action started: $name" "INFO" $null "Settings-UI"
            }
            & $action
            $elapsedMs = [int]((Get-Date) - $actionStart).TotalMilliseconds
            if ($settings.VerboseUiLogging) {
                $script:LogResultOverride = "OK"
                Write-Log "UI: Settings action completed: $name (ms=$elapsedMs)" "INFO" $null "Settings-UI"
            } else {
                $script:LogResultOverride = "OK"
                Write-Log "UI: Settings action: $name (ms=$elapsedMs)" "INFO" $null "Settings-UI"
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
        $script:normalizeInputsTimer.Stop()
        if ($script:normalizeInputs) { & $script:normalizeInputs }
    })

    $script:scheduleNormalizeInputs = {
        $timerVar = Get-Variable -Name normalizeInputsTimer -Scope Script -ErrorAction SilentlyContinue
        if (-not $timerVar -or -not $timerVar.Value) {
            $script:normalizeInputsTimer = New-Object System.Windows.Forms.Timer
            $script:normalizeInputsTimer.Interval = 250
                $script:normalizeInputsTimer.Add_Tick({
                $script:normalizeInputsTimer.Stop()
                if ($script:normalizeInputs) { & $script:normalizeInputs }
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
        $script:profileBox,
        $script:intervalBox, $script:startWithWindowsBox, $script:openSettingsLastTabBox, $script:rememberChoiceBox, $script:startOnLaunchBox, $script:quietModeBox, $script:dateTimeFormatBox, $script:dateTimeFormatPresetBox, $script:useSystemDateTimeFormatBox, $script:systemDateTimeFormatModeBox,
        $script:tooltipStyleBox, $script:disableBalloonBox, $script:themeModeBox, $script:fontSizeBox, $script:settingsFontSizeBox, $script:compactModeBox, $script:toggleCountBox, $script:LastTogglePicker, $script:runOnceOnLaunchBox, $script:pauseUntilBox,
        $script:pauseDurationsBox, $script:scheduleEnabledBox, $script:scheduleStartBox, $script:scheduleEndBox, $script:scheduleWeekdaysBox,
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
            $toolTip.SetToolTip($control, $text)
        }
    }

    $settingTooltips = @{
        "Interval Seconds" = "How often Scroll Lock toggles while running. Minimum 5 seconds, maximum 24 hours."
        "Start with Windows" = "Create or remove a Startup shortcut so the tray app launches on sign-in."
        "Open Settings at Last Tab" = "Reopen Settings on the last tab you used."
        "Remember Choice" = "Remember the answer to the start prompt shown on launch."
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
    }

    $applyTooltips = {
        param($control)
        if (-not $control) { return }
        $tag = [string]$control.Tag
        if ($settingTooltips.ContainsKey($tag)) {
            & $setToolTip $control $settingTooltips[$tag]
        }
        foreach ($child in $control.Controls) {
            & $applyTooltips $child
        }
    }

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
    & $setToolTip $duplicateProfileButton "Duplicate the selected profile."
    & $setToolTip $loadProfileButton "Load settings from the selected profile."
    & $setToolTip $previewChangesButton "Preview changes without saving."
    & $setToolTip $undoChangesButton "Revert changes back to the last saved settings."
    & $setToolTip $copyDiagnosticsButton "Copy diagnostics to the clipboard."

    $script:SettingsStatusPanel = $statusPanel
    $script:SettingsHotkeyPanel = $hotkeyPanel
    $script:SettingsLoggingPanel = $loggingPanel
    $script:SettingsDiagnosticsPanel = $diagnosticsPanel
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
        $script:rememberChoiceBox.Checked = [bool]$src.RememberChoice
        $script:startOnLaunchBox.Checked = [bool]$src.StartOnLaunch
        $script:quietModeBox.Checked = [bool]$src.QuietMode
        $tooltipStyleValue = [string]$src.TooltipStyle
        if ([string]::IsNullOrWhiteSpace($tooltipStyleValue)) {
            $tooltipStyleValue = if ([bool]$src.MinimalTrayTooltip) { "Minimal" } else { "Standard" }
        }
        if ($script:tooltipStyleBox.Items.Contains($tooltipStyleValue)) {
            $script:tooltipStyleBox.SelectedItem = $tooltipStyleValue
        } else {
            $script:tooltipStyleBox.SelectedItem = "Standard"
        }
        $script:disableBalloonBox.Checked = [bool]$src.DisableBalloonTips
        $themeModeValue = [string]$src.ThemeMode
        if ([string]::IsNullOrWhiteSpace($themeModeValue)) { $themeModeValue = "Auto" }
        switch ($themeModeValue.ToUpperInvariant()) {
            "LIGHT" { $script:themeModeBox.SelectedItem = "Light" }
            "DARK" { $script:themeModeBox.SelectedItem = "Dark" }
            "HIGH CONTRAST" { $script:themeModeBox.SelectedItem = "High Contrast" }
            default { $script:themeModeBox.SelectedItem = "Auto Detect" }
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

    & $applySettingsToControls $settings
    $settingsDialogLastSaved = & $script:CopySettingsObject $settings
    & $script:UpdateLastSavedLabel $null
    if ($settings.OpenSettingsAtLastTab -and $settings.LastSettingsTab) {
        $targetTab = $script:SettingsTabControl.TabPages | Where-Object { $_.Text -eq $settings.LastSettingsTab } | Select-Object -First 1
        if ($targetTab) { $script:SettingsTabControl.SelectedTab = $targetTab }
    } else {
        $defaultTab = $script:SettingsTabControl.TabPages | Where-Object { $_.Text -eq "Status" } | Select-Object -First 1
        if ($defaultTab) { $script:SettingsTabControl.SelectedTab = $defaultTab }
    }

    $normalizeSettings = {
        param($src)
        $merged = [pscustomobject]@{}
        foreach ($prop in $defaultSettings.PSObject.Properties.Name) {
            if ($src.PSObject.Properties.Name -contains $prop) {
                $merged | Add-Member -MemberType NoteProperty -Name $prop -Value $src.$prop
            } else {
                $merged | Add-Member -MemberType NoteProperty -Name $prop -Value $defaultSettings.$prop
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
                    $settings | ConvertTo-Json -Depth 4 | Set-Content -Path $dialog.FileName -Encoding UTF8
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
                    $merged = & $normalizeSettings $loaded
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
            $settings.ToggleCount = 0
            $settings.LastToggleTime = $null
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
        $pending.RememberChoice = $script:rememberChoiceBox.Checked
        $pending.StartOnLaunch = $script:startOnLaunchBox.Checked
        $pending.QuietMode = $script:quietModeBox.Checked
        $pending.DisableBalloonTips = $script:disableBalloonBox.Checked
        $pending.DateTimeFormat = Normalize-DateTimeFormat $formatText
        $pending.UseSystemDateTimeFormat = [bool]$script:useSystemDateTimeFormatBox.Checked
        $pending.SystemDateTimeFormatMode = [string]$script:systemDateTimeFormatModeBox.SelectedItem
        if ([string]::IsNullOrWhiteSpace($pending.SystemDateTimeFormatMode)) { $pending.SystemDateTimeFormatMode = "Short" }
        $themeModeSelected = [string]$script:themeModeBox.SelectedItem
        $pending.ThemeMode = switch ($themeModeSelected) {
            "Light" { "Light" }
            "Dark" { "Dark" }
            "High Contrast" { "High Contrast" }
            default { "Auto" }
        }
        $pending.TooltipStyle = [string]$script:tooltipStyleBox.SelectedItem
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
        $logDirText = [string]$script:logDirectoryBox.Text
        if ([string]::IsNullOrWhiteSpace($logDirText) -or $logDirText -eq $scriptDir) {
            $pending.LogDirectory = ""
        } else {
            $pending.LogDirectory = $logDirText.Trim()
        }
        $settingsDirText = [string]$script:settingsDirectoryBox.Text
        if ([string]::IsNullOrWhiteSpace($settingsDirText) -or $settingsDirText -eq $scriptDir) {
            $pending.SettingsDirectory = ""
        } else {
            $pending.SettingsDirectory = $settingsDirText.Trim()
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
            $pending.LastSettingsTab = [string]$script:SettingsTabControl.SelectedTab.Text
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
                Write-Log "UI: Settings preview displayed." "INFO" $null "Settings-Dialog"
            }
        }
    })

    $undoChangesButton.Add_Click({
        & $script:RunSettingsAction "Undo Changes" {
            if (-not $settingsDialogLastSaved) { return }
            & $applySettingsToControls $settingsDialogLastSaved
            Set-SettingsDirty $false
            Write-Log "UI: Settings reverted to last saved." "INFO" $null "Settings-Dialog"
        }
    })

    $script:SettingsOkButton.Add_Click({
        Set-LastUserAction "Save Settings" "Settings"
        $collectResult = & $script:CollectSettingsFromControls -ShowErrors
        if (-not $collectResult -or $collectResult.Errors.Count -gt 0) { return }

        $pendingSettings = $collectResult.Settings
        $lastToggleTime = $collectResult.LastToggleTime
        $pauseUntil = $collectResult.PauseUntil
        $scheduleSuspendUntil = $collectResult.ScheduleSuspendUntil

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
        if ($settings.PSObject.Properties.Name -contains "SettingsDirectory") {
            $desiredSettingsDir = [string]$settings.SettingsDirectory
            if ([string]::IsNullOrWhiteSpace($desiredSettingsDir) -or $desiredSettingsDir -eq $scriptDir) {
                $desiredSettingsDir = $scriptDir
            }
            if ($desiredSettingsDir -ne $script:SettingsDirectory) {
                Set-SettingsDirectory $desiredSettingsDir
            }
        }
        if ($settings.PSObject.Properties.Name -contains "LogDirectory") {
            $desiredLogDir = [string]$settings.LogDirectory
            if ([string]::IsNullOrWhiteSpace($desiredLogDir) -or $desiredLogDir -eq $scriptDir) {
                $desiredLogDir = $scriptDir
            }
            if ($desiredLogDir -ne $script:LogDirectory) {
                Set-LogDirectory $desiredLogDir
            }
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

    Write-Log "UI: ---------- Settings Save ----------" "INFO" $null "Settings-Dialog"
    Save-Settings $settings
        if ($updateProfilesMenu) { & $updateProfilesMenu }

        $quietModeItem.Checked = [bool]$settings.QuietMode
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
        Write-Log "UI: Settings updated via dialog. LogLevel=$($settings.LogLevel) LogMaxBytes=$($settings.LogMaxBytes)" "INFO" $null "Settings-Dialog"
        $settingsDialogLastSaved = & $script:CopySettingsObject $settings
        & $script:UpdateLastSavedLabel (Get-Date)
        Set-SettingsDirty $false

        if ($script:SettingsForm -and -not $script:SettingsForm.IsDisposed) {
            $script:SettingsForm.DialogResult = [System.Windows.Forms.DialogResult]::None
        }
    })

    $doneButton.Add_Click({
        Write-Log "UI: Settings closed via Done." "INFO" $null "Settings-Dialog" -Force
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

    $updateSettingsStatus = {
        if ($script:isShuttingDown -or $script:SettingsUiRefreshInProgress) { return }
        $script:SettingsUiRefreshInProgress = $true
        $script:Now = Get-Date
        try {
        $targetForm = $script:SettingsForm
        if (-not $targetForm -or $targetForm.IsDisposed) { return }
        $shouldUpdate = ($targetForm.Visible -and $targetForm.WindowState -ne [System.Windows.Forms.FormWindowState]::Minimized)
        $selectedTab = $script:SettingsTabControl.SelectedTab
        $statusPage = $script:SettingsStatusPanel.Parent
        $hotkeysPage = $script:SettingsHotkeyPanel.Parent
        $loggingPage = $script:SettingsLoggingPanel.Parent
        $diagnosticsPage = $script:SettingsDiagnosticsPanel.Parent

            if ($shouldUpdate -and $statusPage -and $selectedTab -eq $statusPage) {
                Request-StatusUpdate
                $script:SettingsStatusValue.Text = $script:StatusStateText
                $script:SettingsStatusValue.ForeColor = $script:StatusStateColor
                $nextText = Format-NextInfo
                $script:SettingsNextValue.Text = $nextText
                $uptimeSpan = (Get-Date) - $script:AppStartTime
                $script:SettingsUptimeValue.Text = ("{0}h {1}m" -f [int]$uptimeSpan.TotalHours, $uptimeSpan.Minutes)
                if ($script:LastToggleResultTime) {
                    $script:SettingsLastToggleValue.Text = "$($script:LastToggleResult) - $(Format-LocalTime $script:LastToggleResultTime)"
                } else {
                    $script:SettingsLastToggleValue.Text = $script:LastToggleResult
                }
                $script:SettingsNextCountdownValue.Text = "N/A"
                if ($script:isRunning -and -not $script:isPaused -and -not $script:isScheduleBlocked -and $script:nextToggleTime) {
                    $remaining = [int][Math]::Max(0, ($script:nextToggleTime - (Get-Date)).TotalSeconds)
                    $script:SettingsNextCountdownValue.Text = "$remaining s ($($script:nextToggleTime.ToString("T")))"
                }
                $script:SettingsProfileStatusValue.Text = [string]$settings.ActiveProfile
                if ($script:SettingsToggleCurrentValue) {
                    $script:SettingsToggleCurrentValue.Text = [string]$script:tickCount
                }
                if ($script:SettingsToggleLifetimeValue) {
                    $script:SettingsToggleLifetimeValue.Text = [string]$settings.ToggleCount
                }
                $funStats = Ensure-FunStats $settings
                if ($script:SettingsFunDailyValue) {
                    $script:SettingsFunDailyValue.Text = [string](Get-DailyToggleCount $funStats (Get-Date))
                }
                $streaks = Get-ToggleStreaks $funStats
                if ($script:SettingsFunStreakCurrentValue) {
                    $script:SettingsFunStreakCurrentValue.Text = "$($streaks.Current) days"
                }
                if ($script:SettingsFunStreakBestValue) {
                    $script:SettingsFunStreakBestValue.Text = "$($streaks.Best) days"
                }
                if ($script:SettingsFunMostActiveHourValue) {
                    $script:SettingsFunMostActiveHourValue.Text = Get-MostActiveHourLabel $funStats
                }
                if ($script:SettingsFunLongestPauseValue) {
                    $longestPause = 0
                    if ($funStats.ContainsKey("LongestPauseMinutes")) { $longestPause = [int]$funStats["LongestPauseMinutes"] }
                    $script:SettingsFunLongestPauseValue.Text = if ($longestPause -gt 0) { "$longestPause min" } else { "N/A" }
                }
                if ($script:SettingsFunTotalRunValue) {
                    $totalRun = 0.0
                    if ($funStats.ContainsKey("TotalRunMinutes")) { $totalRun = [double]$funStats["TotalRunMinutes"] }
                    $script:SettingsFunTotalRunValue.Text = Format-TotalRunTime $totalRun
                }
                $scheduleText = Format-ScheduleStatus
                $script:SettingsScheduleStatusValue.Text = $scheduleText
                $script:SettingsSafeModeStatusValue.Text = if ($script:safeModeActive) { "On (Fails=$($script:toggleFailCount))" } else { "Off" }
                $caps = [System.Windows.Forms.Control]::IsKeyLocked([System.Windows.Forms.Keys]::CapsLock)
                $num = [System.Windows.Forms.Control]::IsKeyLocked([System.Windows.Forms.Keys]::NumLock)
                $scroll = [System.Windows.Forms.Control]::IsKeyLocked([System.Windows.Forms.Keys]::Scroll)
                $script:SettingsKeyboardValue.Text = "Caps:{0} Num:{1} Scroll:{2}" -f ($(if ($caps) { "On" } else { "Off" })), ($(if ($num) { "On" } else { "Off" })), ($(if ($scroll) { "On" } else { "Off" }))
            }

            if ($shouldUpdate -and $hotkeysPage -and $selectedTab -eq $hotkeysPage) {
                $script:SettingsHotkeyStatusValue.Text = $script:HotkeyStatusText
            }

            if ($shouldUpdate -and $loggingPage -and $selectedTab -eq $loggingPage) {
                $logBytes = 0
                if (Test-Path $logPath) {
                    try { $logBytes = (Get-Item -Path $logPath).Length } catch { $logBytes = 0 }
                }
                $maxBytes = [long]($script:SettingsLogMaxBox.Value * 1024)
                $script:SettingsLogSizeValue.Text = "$(& $script:FormatSize $logBytes) / $(& $script:FormatSize $maxBytes)"
            }

            if ($shouldUpdate -and $diagnosticsPage -and $selectedTab -eq $diagnosticsPage) {
                if ($script:LastErrorMessage) {
                    $errorTime = if ($script:LastErrorTime) { Format-LocalTime $script:LastErrorTime } else { "Unknown" }
                    $script:SettingsDiagErrorValue.Text = "$errorTime - $($script:LastErrorMessage)"
                } else {
                    $script:SettingsDiagErrorValue.Text = "None"
                }
                $script:SettingsDiagRestartValue.Text = Format-LocalTime $script:AppStartTime
                $script:SettingsDiagSafeModeValue.Text = $(if ($script:safeModeActive) { "On" } else { "Off" })
                $script:SettingsDebugModeStatus.Text = if ($script:DebugModeUntil) { "On (10 min)" } else { "Off" }
                if ($script:LastToggleResultTime) {
                    $script:SettingsDiagLastToggleValue.Text = "$($script:LastToggleResult) - $(Format-LocalTime $script:LastToggleResultTime)"
                } else {
                    $script:SettingsDiagLastToggleValue.Text = $script:LastToggleResult
                }
                $script:SettingsDiagFailValue.Text = [string]$script:toggleFailCount
                $diagBytes = 0
                if (Test-Path $logPath) {
                    try { $diagBytes = (Get-Item -Path $logPath).Length } catch { $diagBytes = 0 }
                }
                $script:SettingsDiagLogSizeValue.Text = & $script:FormatSize $diagBytes
                $script:SettingsDiagLogRotateValue.Text = [string]$script:LogRotationCount
                if ($script:LastLogWriteTime) {
                    $script:SettingsDiagLogWriteValue.Text = Format-LocalTime $script:LastLogWriteTime
                } else {
                    $script:SettingsDiagLogWriteValue.Text = "N/A"
                }
            }

            if ($script:SettingsResetConfirmState.Pending) {
                $remainingSeconds = [int][Math]::Ceiling(($script:SettingsResetConfirmState.Deadline - (Get-Date)).TotalSeconds)
                if ($remainingSeconds -le 0) {
                    $script:SettingsResetConfirmState.Pending = $false
                    $script:SettingsResetConfirmState.Deadline = $null
                    $script:SettingsResetButton.Text = "Restore Defaults"
                } else {
                    $script:SettingsResetConfirmState.Remaining = $remainingSeconds
                    $script:SettingsResetButton.Text = "Confirm Reset ($($script:SettingsResetConfirmState.Remaining))"
                }
            }
        } finally {
            $script:Now = $null
            $script:SettingsUiRefreshInProgress = $false
        }
    }
    $script:UpdateSettingsStatus = $updateSettingsStatus

    $script:SettingsStatusTimer = New-Object System.Windows.Forms.Timer
    $script:SettingsStatusTimer.Interval = 1000
    $script:SettingsStatusTimer.Add_Tick({
        if ($script:isShuttingDown -or $script:CleanupDone) { return }
        if ($script:UpdateSettingsStatus) { & $script:UpdateSettingsStatus }
    })

    $updateStatusTimerState = {
        if ($script:isShuttingDown -or $script:CleanupDone) { return }
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
        Apply-ThemeToControl $script:SettingsForm $script:ThemePalette $script:UseDarkTheme
        Apply-MenuFontSize ([int]$settings.FontSize)
        Apply-SettingsFontSize ([int]$settings.SettingsFontSize)
        if ($script:UpdateAppearancePreview) { & $script:UpdateAppearancePreview }
        if ($script:UpdateTabLayouts) { & $script:UpdateTabLayouts }
        if ($script:UpdateSettingsStatus) { & $script:UpdateSettingsStatus }
        if ($script:UpdateStatusTimerState) { & $script:UpdateStatusTimerState }
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
            $settings.LastSettingsTab = [string]$script:SettingsTabControl.SelectedTab.Text
            Save-Settings $settings -Immediate
        }
        if ($script:SettingsStatusTimer) {
            $script:SettingsStatusTimer.Stop()
            $script:SettingsStatusTimer.Dispose()
            $script:SettingsStatusTimer = $null
        }
        $script:SettingsForm = $null
    })

    $form.Add_FormClosed({
        param($sender, $e)
        $durationSeconds = [Math]::Round(((Get-Date) - $script:SettingsDialogStart).TotalSeconds, 2)
        $result = $null
        if ($sender -is [System.Windows.Forms.Form]) { $result = $sender.DialogResult }
        Write-Log "UI: Settings dialog closed. Result=$result Dirty=$script:SettingsDirty DurationSeconds=$durationSeconds" "INFO" $null "Settings-Dialog"
    })
        Write-Log "UI: Settings dialog opened." "INFO" $null "Settings-Dialog"
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
    Write-Log "UI: Ensure settings visible called." "INFO" $null "Settings-Dialog" -Force
    if ($script:SettingsForm -and -not $script:SettingsForm.IsDisposed -and $script:SettingsForm.Visible) {
        Write-Log ("UI: Settings already visible. Visible={0} WindowState={1}" -f $script:SettingsForm.Visible, $script:SettingsForm.WindowState) "INFO" $null "Settings-Dialog" -Force
        return
    }
    Write-Log "UI: Settings not visible; opening now." "INFO" $null "Settings-Dialog" -Force
    Show-SettingsDialog
    if ($script:SettingsForm) {
        Write-Log ("UI: Settings open attempt complete. Visible={0} Disposed={1} WindowState={2}" -f $script:SettingsForm.Visible, $script:SettingsForm.IsDisposed, $script:SettingsForm.WindowState) "INFO" $null "Settings-Dialog" -Force
    } else {
        Write-Log "UI: Settings open attempt complete. SettingsForm is null." "INFO" $null "Settings-Dialog" -Force
    }
    if ($script:DeferredSettingsTimer) {
        $script:DeferredSettingsTimer.Stop()
        $script:DeferredSettingsTimer.Dispose()
        $script:DeferredSettingsTimer = $null
    }
    $script:DeferredSettingsTimer = New-Object System.Windows.Forms.Timer
    $script:DeferredSettingsTimer.Interval = 150
    $script:DeferredSettingsTimer.Add_Tick({
        if ($script:DeferredSettingsTimer) {
            $script:DeferredSettingsTimer.Stop()
            $script:DeferredSettingsTimer.Dispose()
            $script:DeferredSettingsTimer = $null
        }
        if (-not ($script:SettingsForm -and -not $script:SettingsForm.IsDisposed -and $script:SettingsForm.Visible)) {
            Write-Log "UI: Settings still not visible; retry open." "INFO" $null "Settings-Dialog" -Force
            Show-SettingsDialog
        } else {
            Write-Log "UI: Settings now visible." "INFO" $null "Settings-Dialog" -Force
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

$openSettingsItem = New-Object System.Windows.Forms.ToolStripMenuItem("Settings...")
$openSettingsItem.Add_Click({
    Write-Log "Tray action: Open Settings" "INFO" $null "Tray-Action"
    Write-Log "UI: Settings open requested from tray." "INFO" $null "Settings-Dialog" -Force
    if ($script:SettingsForm -and -not $script:SettingsForm.IsDisposed -and $script:SettingsForm.Visible) {
        Show-SettingsAlreadyOpenNotice
        $script:SettingsForm.WindowState = [System.Windows.Forms.FormWindowState]::Normal
        $script:SettingsForm.BringToFront()
        $script:SettingsForm.Activate()
        return
    }
    Ensure-SettingsDialogVisible
})
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

function Show-HistoryDialog {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "History"
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "Sizable"
    $form.ClientSize = New-Object System.Drawing.Size(760, 460)

    $topPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $topPanel.Dock = "Top"
    $topPanel.AutoSize = $true
    $topPanel.WrapContents = $false
    $topPanel.Padding = New-Object System.Windows.Forms.Padding(10, 8, 10, 0)

    $summaryLabel = New-Object System.Windows.Forms.Label
    $summaryLabel.AutoSize = $true
    $summaryLabel.Text = "Total: 0  Success: 0  Fail: 0"

    $filterLabel = New-Object System.Windows.Forms.Label
    $filterLabel.AutoSize = $true
    $filterLabel.Text = "Filter:"
    $filterLabel.Margin = New-Object System.Windows.Forms.Padding(18, 3, 4, 0)

    $filterCombo = New-Object System.Windows.Forms.ComboBox
    $filterCombo.DropDownStyle = "DropDownList"
    $filterCombo.Width = 110
    [void]$filterCombo.Items.AddRange(@("All", "Succeeded", "Failed"))
    $filterCombo.SelectedIndex = 0

    $searchLabel = New-Object System.Windows.Forms.Label
    $searchLabel.AutoSize = $true
    $searchLabel.Text = "Search:"
    $searchLabel.Margin = New-Object System.Windows.Forms.Padding(16, 3, 4, 0)

    $searchBox = New-Object System.Windows.Forms.TextBox
    $searchBox.Width = 180

    $autoRefresh = New-Object System.Windows.Forms.CheckBox
    $autoRefresh.Text = "Auto-refresh"
    $autoRefresh.AutoSize = $true
    $autoRefresh.Margin = New-Object System.Windows.Forms.Padding(16, 1, 0, 0)

    $topPanel.Controls.Add($summaryLabel)
    $topPanel.Controls.Add($filterLabel)
    $topPanel.Controls.Add($filterCombo)
    $topPanel.Controls.Add($searchLabel)
    $topPanel.Controls.Add($searchBox)
    $topPanel.Controls.Add($autoRefresh)

    $list = New-Object System.Windows.Forms.ListView
    $list.View = [System.Windows.Forms.View]::Details
    $list.FullRowSelect = $true
    $list.GridLines = $true
    $list.Dock = "Fill"
    $list.Font = New-Object System.Drawing.Font("Consolas", 9)
    [void]$list.Columns.Add("Time", 170)
    [void]$list.Columns.Add("Result", 80)
    [void]$list.Columns.Add("Source", 120)
    [void]$list.Columns.Add("Message", 340)

    $buttonsPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttonsPanel.FlowDirection = "RightToLeft"
    $buttonsPanel.Dock = "Bottom"
    $buttonsPanel.Padding = New-Object System.Windows.Forms.Padding(10, 5, 10, 10)
    $buttonsPanel.AutoSize = $true

    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = "Close"
    $closeButton.Width = 90
    $closeButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $copyButton = New-Object System.Windows.Forms.Button
    $copyButton.Text = "Copy"
    $copyButton.Width = 90

    $exportButton = New-Object System.Windows.Forms.Button
    $exportButton.Text = "Export"
    $exportButton.Width = 90

    $buttonsPanel.Controls.Add($closeButton)
    $buttonsPanel.Controls.Add($exportButton)
    $buttonsPanel.Controls.Add($copyButton)

    $form.Controls.Add($list)
    $form.Controls.Add($buttonsPanel)
    $form.Controls.Add($topPanel)
    $form.CancelButton = $closeButton

    $script:HistoryEvents = @()

    $parseEvents = {
        param([string[]]$lines)
        $result = @()
        foreach ($line in $lines) {
            if ($line -notmatch "Toggle (succeeded|failed)") { continue }
            $timestamp = ""
            if ($line -match "^\[(?<ts>[^\]]+)\]") { $timestamp = $matches["ts"] }
            $outcome = if ($line -match "Toggle succeeded") { "Succeeded" } elseif ($line -match "Toggle failed") { "Failed" } else { "Unknown" }
            $source = ""
            if ($line -match "source=([^\)\s]+)") { $source = $matches[1] }
            $message = $line -replace '^\[[^\]]+\]\s*\[[A-Z]+\]\s*', ''
            $message = $message -replace '\[[A-Z][^]]*\]\s*', ''
            $result += [pscustomobject]@{
                Timestamp = $timestamp
                Result = $outcome
                Source = $source
                Message = $message.Trim()
            }
        }
        return $result
    }

    $applyFilter = {
        $filtered = $script:HistoryEvents
        $filterValue = [string]$filterCombo.SelectedItem
        if ($filterValue -eq "Succeeded") {
            $filtered = $filtered | Where-Object { $_.Result -eq "Succeeded" }
        } elseif ($filterValue -eq "Failed") {
            $filtered = $filtered | Where-Object { $_.Result -eq "Failed" }
        }
        $query = $searchBox.Text
        if ($query) {
            $filtered = $filtered | Where-Object {
                $_.Timestamp -like "*$query*" -or
                $_.Result -like "*$query*" -or
                $_.Source -like "*$query*" -or
                $_.Message -like "*$query*"
            }
        }

        $list.BeginUpdate()
        $list.Items.Clear()
        if (@($script:HistoryEvents).Count -eq 0) {
            [void]$list.Items.Add((New-Object System.Windows.Forms.ListViewItem("No toggle history yet.")))
        } elseif (@($filtered).Count -eq 0) {
            [void]$list.Items.Add((New-Object System.Windows.Forms.ListViewItem("No results match the current filter.")))
        } else {
            foreach ($ev in $filtered) {
                $item = New-Object System.Windows.Forms.ListViewItem($ev.Timestamp)
                [void]$item.SubItems.Add($ev.Result)
                [void]$item.SubItems.Add($ev.Source)
                [void]$item.SubItems.Add($ev.Message)
                [void]$list.Items.Add($item)
            }
        }
        $list.EndUpdate()

        $total = @($filtered).Count
        $success = @($filtered | Where-Object { $_.Result -eq "Succeeded" }).Count
        $fail = @($filtered | Where-Object { $_.Result -eq "Failed" }).Count
        $summaryLabel.Text = "Total: $total  Success: $success  Fail: $fail"
    }

    $loadHistory = {
        try {
            if (-not (Test-Path $logPath)) {
                "" | Set-Content -Path $logPath -Encoding UTF8
            }
            $lines = Get-Content -Path $logPath -Tail 600
            $script:HistoryEvents = & $parseEvents $lines | Select-Object -Last 100
        } catch {
            $script:HistoryEvents = @()
            Write-Log "Failed to load history." "ERROR" $_.Exception "History"
        }
        & $applyFilter
    }

    $copyButton.Add_Click({
        $items = if ($list.SelectedItems.Count -gt 0) { $list.SelectedItems } else { $list.Items }
        if ($items.Count -eq 0) { return }
        $lines = @()
        foreach ($item in $items) {
            $cols = @($item.Text)
            for ($i = 1; $i -lt $item.SubItems.Count; $i++) {
                $cols += $item.SubItems[$i].Text
            }
            $lines += ($cols -join "`t")
        }
        try { Set-Clipboard -Value ($lines -join "`r`n") } catch { }
    })

    $exportButton.Add_Click({
        $dialog = New-Object System.Windows.Forms.SaveFileDialog
        $dialog.Filter = "Text Files (*.txt)|*.txt|CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
        $dialog.FileName = "Teams-Always-Green.history.txt"
        if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $items = $list.Items
        $lines = @()
        foreach ($item in $items) {
            $cols = @($item.Text)
            for ($i = 1; $i -lt $item.SubItems.Count; $i++) {
                $cols += $item.SubItems[$i].Text
            }
            $lines += ($cols -join ",")
        }
        try { Set-Content -Path $dialog.FileName -Value $lines -Encoding UTF8 } catch { }
    })

    $filterCombo.Add_SelectedIndexChanged({ & $applyFilter })
    $searchBox.Add_TextChanged({ & $applyFilter })

    $refreshTimer = New-Object System.Windows.Forms.Timer
    $refreshTimer.Interval = 2000
    $refreshTimer.Add_Tick({
        if ($autoRefresh.Checked) { & $loadHistory }
    })
    $form.Add_FormClosing({
        try { $refreshTimer.Stop() } catch { }
    })
    $refreshTimer.Start()

    & $loadHistory

    Update-ThemePreference
    Apply-ThemeToControl $form $script:ThemePalette $script:UseDarkTheme

    [void]$form.ShowDialog()
}

function Soft-Restart {
    if ($script:CleanupDone -or $script:isShuttingDown) { return }
    Write-Log "Tray action: Soft Restart" "INFO" $null "Tray-Action"
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
$historyItem.Add_Click({
    Show-HistoryDialog
})

$restartItem = New-Object System.Windows.Forms.ToolStripMenuItem("Restart")
$restartItem.Add_Click({
    if ($script:CleanupDone) { return }
    Write-Log "Tray action: Restart" "INFO" $null "Tray-Action"
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
        $proc = Start-Process -FilePath "powershell.exe" -WindowStyle Hidden -WorkingDirectory $scriptDir -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -PassThru
        if ($proc -and $proc.Id) { Write-Log ("Restart new PID={0}" -f $proc.Id) "INFO" $null "Restart" }
    } catch {
        Write-LogEx "Failed to restart app." "ERROR" $_.Exception "Restart" -Force
    }
    Write-Log "Restart requested via tray menu." "INFO" $null "Restart"
    $script:CleanupDone = $true
    [System.Windows.Forms.Application]::Exit()
})

$exitItem = New-Object System.Windows.Forms.ToolStripMenuItem("Exit")
$exitItem.Add_Click({
    if ($script:CleanupDone) { return }
    Write-Log "Tray action: Exit" "INFO" $null "Tray-Action"
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
    $startItem,
    $stopItem,
    $toggleNowItem,
    $pauseMenu,
    $resetCountersItem,
    $resetSafeModeItem,
    $runOnceNowItem,
    (New-Object System.Windows.Forms.ToolStripSeparator),
    $intervalMenu,
    $quietModeItem,
    $logLevelMenu,
    $quickSettingsMenu,
    $profilesMenu,
    (New-Object System.Windows.Forms.ToolStripSeparator),
    $statusItem,
    $openSettingsItem,
    $historyItem,
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
    Update-ThemePreference
    Apply-MenuFontSize ([int]$settings.FontSize)
    Update-StatusText
    Set-StatusUpdateTimerEnabled $true
})

$contextMenu.Add_Closed({
    Set-StatusUpdateTimerEnabled $false
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
    if ($script:isShuttingDown -or $script:CleanupDone) { return }
    if ($script:isPaused -and $script:pauseUntil -ne $null -and (Get-Date) -ge $script:pauseUntil) {
        Start-Toggling
    }
})
$pauseTimer.Start()

$watchdogTimer = New-Object System.Windows.Forms.Timer
$watchdogTimer.Interval = 2000
$watchdogTimer.Add_Tick({
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
})
$watchdogTimer.Start()

$statusHeartbeatTimer = New-Object System.Windows.Forms.Timer
$statusHeartbeatTimer.Interval = 1000
$statusHeartbeatTimer.Add_Tick({
    if ($script:isShuttingDown -or $script:CleanupDone) { return }
    Request-StatusUpdate
})
$statusHeartbeatTimer.Start()

$notifyIcon.Visible = $true
Write-Log "Tray icon visible (startup complete)." "INFO" $null "Tray"

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
if ($script:isPaused) {
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

