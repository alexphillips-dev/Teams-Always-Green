
# Teams Always Green
# PSScriptAnalyzerSettings -DisableRuleName PSUseApprovedVerbs
# Main tray app script. Keeps Teams presence active by toggling Scroll Lock.
# Includes profiles, schedule/pause controls, hotkeys, Settings/History UI,
# startup prompts, recovery/self-heal, logging, and restart/exit handling.
#
# Runtime data root (default): %LocalAppData%\TeamsAlwaysGreen
# - Logs\      App/bootstrap/audit logs
# - Settings\  Settings/state JSON + backups
# - Meta\      Crash/status markers, cache, and metadata
# - Meta\Icons\ Tray/UI icons
#
# Launcher/install helpers:
# - Teams Always Green.VBS
# - Script\QuickSetup\QuickSetup.cmd / Script\QuickSetup\QuickSetup.ps1
#
# Run mode:
# - -SettingsOnly opens Settings without starting the tray loop

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Scope='Function', Target='*', Justification='Legacy function names are intentionally retained for compatibility.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Scope='Function', Target='*', Justification='Legacy function names are intentionally retained for compatibility.')]
# --- Runtime setup and WinForms initialization (load assemblies, set UI defaults) ---
param(
    [switch]$SettingsOnly,
    [switch]$RelaunchedFromRestart
)

$script:SettingsOnly = $SettingsOnly
$script:RelaunchedFromRestart = [bool]$RelaunchedFromRestart

Set-StrictMode -Version Latest
$proc = $null
$script:TimerGuards = @{}
$script:TrayMenu = $null
$script:TrayMenuToolTip = $null
$script:TrayMenuOpening = $false
$script:TrayMenuHeavyInitialized = $false
$script:TrayMenuNeedsRefresh = $true
$script:TrayTooltipTimer = $null
$script:TrayTooltipPendingText = $null
$script:TrayTooltipDelayMs = 900
$script:TrayTooltipHookedItems = @{}
$script:TrayTooltipEventsHooked = $false
$script:TrayStatusStateItem = $null
$script:TrayStatusNextItem = $null
$script:TrayStatusProfileItem = $null
$script:TrayStatusSummaryItem = $null
$script:DeferredStartupTimer = $null
$script:DeferredStartupDone = $false
$script:DeferredMaintenanceTimer = $null
$script:DirectoryWritableCache = @{}
$script:DirectoryWritableCacheTtlSeconds = 300
$script:WatchdogTickCounter = 0
$script:PendingSignaturePolicyCheck = $false
$script:PermissionHardeningSkipLogged = $false
$script:IsElevatedSession = $false
$script:ScrollLockReleaseDelayDefaultMs = 50
$script:ScrollLockReleaseDelayMinMs = 20
$script:ScrollLockReleaseDelayMaxMs = 500
$script:IgnoredCatchCapabilityCache = @{
    CheckedAtUtc              = [DateTime]::MinValue
    HasWriteLogExceptionDeduped = $false
    HasWriteLog               = $false
    HasWriteBootstrapLog      = $false
}
$script:IgnoredCatchCapabilityCacheTtlSeconds = 30
function Write-IgnoredCatch(
    [Parameter(Mandatory = $true)]
    [System.Management.Automation.ErrorRecord]$ErrorRecord,
    [string]$Context = "Catch"
) {
    if (-not $ErrorRecord) { return }
    try {
        $logEnabled = $true
        $logLevelVar = Get-Variable -Name LogLevel -Scope Script -ErrorAction SilentlyContinue
        if ($logLevelVar -and -not [string]::IsNullOrWhiteSpace([string]$logLevelVar.Value)) {
            $isDebugLevel = ([string]$logLevelVar.Value).ToUpperInvariant() -eq "DEBUG"
            $debugOverride = $false
            $debugUntil = Get-Variable -Name DebugModeUntil -Scope Script -ErrorAction SilentlyContinue
            if ($debugUntil -and $debugUntil.Value -is [DateTime]) {
                $debugOverride = ((Get-Date) -lt [DateTime]$debugUntil.Value)
            }
            $logEnabled = ($isDebugLevel -or $debugOverride)
        }

        if ([string]::IsNullOrWhiteSpace($Context) -or $Context -eq "Catch") {
            $invocation = $ErrorRecord.InvocationInfo
            if ($invocation) {
                $name = ""
                if ($invocation.MyCommand -and -not [string]::IsNullOrWhiteSpace([string]$invocation.MyCommand.Name)) {
                    $name = [string]$invocation.MyCommand.Name
                } elseif (-not [string]::IsNullOrWhiteSpace([string]$invocation.InvocationName)) {
                    $name = [string]$invocation.InvocationName
                }
                $lineNo = if ($invocation.ScriptLineNumber -gt 0) { [int]$invocation.ScriptLineNumber } else { 0 }
                if (-not [string]::IsNullOrWhiteSpace($name)) {
                    $Context = if ($lineNo -gt 0) { "Catch/$name:L$lineNo" } else { "Catch/$name" }
                } elseif ($lineNo -gt 0) {
                    $Context = "Catch/L$lineNo"
                }
            }
        }

        $nowUtc = [DateTime]::UtcNow
        if (-not $script:IgnoredCatchCapabilityCache) {
            $script:IgnoredCatchCapabilityCache = @{
                CheckedAtUtc                = [DateTime]::MinValue
                HasWriteLogExceptionDeduped = $false
                HasWriteLog                 = $false
                HasWriteBootstrapLog        = $false
            }
        }
        $lastCheckedUtc = [DateTime]$script:IgnoredCatchCapabilityCache.CheckedAtUtc
        if (($nowUtc - $lastCheckedUtc).TotalSeconds -ge [double]$script:IgnoredCatchCapabilityCacheTtlSeconds) {
            $script:IgnoredCatchCapabilityCache.CheckedAtUtc = $nowUtc
            $script:IgnoredCatchCapabilityCache.HasWriteLogExceptionDeduped = [bool](Get-Command -Name Write-LogExceptionDeduped -ErrorAction SilentlyContinue)
            $script:IgnoredCatchCapabilityCache.HasWriteLog = [bool](Get-Command -Name Write-Log -ErrorAction SilentlyContinue)
            $script:IgnoredCatchCapabilityCache.HasWriteBootstrapLog = [bool](Get-Command -Name Write-BootstrapLog -ErrorAction SilentlyContinue)
        }

        if ($script:IgnoredCatchCapabilityCache.HasWriteLogExceptionDeduped) {
            if ($logEnabled) {
                Write-LogExceptionDeduped "Ignored error in catch block." "DEBUG" $ErrorRecord.Exception $Context 90
            }
            return
        }
        if ($script:IgnoredCatchCapabilityCache.HasWriteLog) {
            if ($logEnabled) {
                Write-Log "Ignored error in catch block." "DEBUG" $ErrorRecord.Exception $Context
            }
            return
        }
        if ($script:IgnoredCatchCapabilityCache.HasWriteBootstrapLog) {
            $detail = if ($ErrorRecord.Exception) { [string]$ErrorRecord.Exception.Message } else { [string]$ErrorRecord }
            Write-BootstrapLog ("Ignored catch: {0}" -f $detail) "DEBUG"
        }
    } catch {}
}
try {
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity)
    $script:IsElevatedSession = [bool]$currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $script:IsElevatedSession = $false
}
$script:UpdateCache = @{
    CheckedAt     = $null
    Release       = $null
    LatestVersion = $null
}
$script:UpdateCacheTtlMinutes = 15
$script:UpdateNetworkTimeoutSeconds = 8
$script:UpdateNetworkMaxAttempts = 3
$script:AboutUpdateJobTimeoutSeconds = 25
$script:AboutCheckButton = $null
$script:AboutCheckInProgress = $false
$script:AboutUpdateJob = $null
$script:AboutUpdateJobStartedUtc = $null
$script:AboutUpdatePollTimer = $null
$script:UpdateAboutChecked = $null
$script:ErrorFingerprintCache = @{}
$script:DeferredStartupSkipUpdate = $false
$script:CrashRecoveryTier = 0
$script:RepairModeActive = $false
$script:HealthMonitorTimer = $null
$script:SelfHealStats = @{
    SuppressedErrorCount = 0
    SettingsRepairCount  = 0
    CrashTierActions     = 0
    TrayFallbackCount    = 0
    TimerRecoveryQueued  = 0
    TimerRecoverySuccess = 0
    TimerRecoveryFailed  = 0
    QueueSuppressedCount = 0
    HeartbeatRecoveries  = 0
    RepairAllRuns        = 0
}
$script:SelfHealRecentActions = New-Object System.Collections.ArrayList
$script:SelfHealRecentActionsMax = 30
$script:SelfHealActionQueue = New-Object System.Collections.ArrayList
$script:SelfHealActionQueueMax = 64
$script:SelfHealActionTimer = $null
$script:SelfHealActionThrottle = @{}
$script:SelfHealBackoffBaseSeconds = 5
$script:SelfHealActionThrottleWindowSeconds = 300
$script:ComponentHeartbeat = @{}
$script:ComponentHeartbeatThresholdSeconds = @{
    WatchdogTimer      = 20
    PauseTimer         = 20
    LogFlushTimer      = 60
    HealthMonitorTimer = 420
}
$script:ProfileSwitchSelectedKeys = @()
$script:ProfileApplySelectionPending = $false
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)


# --- Localization (dot-sourced) ---
. "$PSScriptRoot\I18n\UiStrings.ps1"

# --- Core helpers (contracts, runtime budgets, atomic writes) ---
$script:CoreModuleLoadOrder = @(
    "Core\Paths.ps1",
    "Core\Runtime.ps1",
    "Core\DateTime.ps1",
    "Core\Settings.ps1",
    "Core\Logging.ps1"
)
foreach ($coreModuleRelativePath in $script:CoreModuleLoadOrder) {
    $coreModulePath = Join-Path $PSScriptRoot $coreModuleRelativePath
    if (-not (Test-Path -LiteralPath $coreModulePath -PathType Leaf)) {
        throw "Required core module is missing: $coreModulePath"
    }
    . $coreModulePath
}

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

function Get-StringSha256Hex([string]$text) {
    if ($null -eq $text) { $text = "" }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$text)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("X2") }) -join "")
    } finally {
        $sha.Dispose()
    }
}

function Get-ProfileExportSignature([string]$name, $profileSnapshot) {
    $normalizedProfile = Migrate-ProfileSnapshot $profileSnapshot
    $canonicalPayload = [ordered]@{
        FormatVersion = 1
        Name = [string]$name
        Profile = $normalizedProfile
    }
    $canonicalJson = $canonicalPayload | ConvertTo-Json -Depth 8 -Compress
    return (Get-StringSha256Hex $canonicalJson)
}

function Test-ProfileExportSignature($payload) {
    if (-not $payload) {
        return [pscustomobject]@{ IsValid = $false; Reason = "Profile payload is missing." }
    }
    $hasProfile = $payload.PSObject.Properties.Name -contains "Profile"
    if (-not $hasProfile) {
        return [pscustomobject]@{ IsValid = $false; Reason = "Profile payload is missing Profile data." }
    }
    $hasSignature = $payload.PSObject.Properties.Name -contains "Signature"
    if (-not $hasSignature -or [string]::IsNullOrWhiteSpace([string]$payload.Signature)) {
        return [pscustomobject]@{ IsValid = $false; Reason = "Profile payload signature is missing." }
    }
    $algorithm = "SHA256"
    if ($payload.PSObject.Properties.Name -contains "SignatureAlgorithm" -and -not [string]::IsNullOrWhiteSpace([string]$payload.SignatureAlgorithm)) {
        $algorithm = [string]$payload.SignatureAlgorithm
    }
    if ($algorithm.ToUpperInvariant() -ne "SHA256") {
        return [pscustomobject]@{ IsValid = $false; Reason = "Unsupported profile signature algorithm: $algorithm" }
    }

    $payloadName = if ($payload.PSObject.Properties.Name -contains "Name") { [string]$payload.Name } else { "Imported" }
    $expected = Get-ProfileExportSignature $payloadName $payload.Profile
    $actual = ([string]$payload.Signature).Trim().ToUpperInvariant()
    if ($expected -ne $actual) {
        return [pscustomobject]@{ IsValid = $false; Reason = "Profile signature mismatch." }
    }
    return [pscustomobject]@{ IsValid = $true; Reason = "" }
}

# --- Paths, Meta folder, and locator files (resolve root, ensure dirs) ---
$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path -Parent $scriptPath
$appRoot = if ((Split-Path -Leaf $scriptDir) -ieq "Script") { Split-Path -Parent $scriptDir } else { $scriptDir }
$script:AppRoot = $appRoot
$script:FolderNames = @{
    Logs = "Logs"
    Settings = "Settings"
    Meta = "Meta"
    Debug = "Debug"
    Script = "Script"
}
$script:RuntimeModuleAllowList = @(
    "Core\Logging.ps1",
    "Core\Paths.ps1",
    "Core\Runtime.ps1",
    "Core\DateTime.ps1",
    "Core\Settings.ps1",
    "Features\UpdateEngine.ps1",
    "I18n\UiStrings.ps1",
    "Tray\Menu.ps1",
    "UI\HistoryDialog.ps1",
    "UI\SettingsDialog.ps1"
)
$script:RuntimeModuleContractVersions = @{
    "Update-Module" = "1.0.0"
    "Tray-Module" = "1.0.0"
    "Settings-UI" = "1.0.0"
    "History-UI" = "1.0.0"
}
$script:ImportAllowedExtensions = @{
    Settings = @(".json")
    Profile  = @(".json")
}
$script:RuntimeModuleLastError = ""
$script:UpdateModuleAvailable = $true
$portableMarkerPath = Join-Path $script:AppRoot "Meta\PortableMode.txt"
$script:PortableMode = Test-Path $portableMarkerPath
$script:DevMode = Test-Path (Join-Path $script:AppRoot ".git")
$script:InstalledMode = (-not $script:PortableMode -and -not $script:DevMode)
$script:EnforceDataRootPaths = [bool]$script:InstalledMode
$defaultUserDataRoot = Join-Path ([Environment]::GetFolderPath("LocalApplicationData")) "TeamsAlwaysGreen"
$script:DataRoot = if ($script:PortableMode) { $script:AppRoot } else { $defaultUserDataRoot }
$script:PathWarnings = @()
$script:SuppressPathWarnings = $false

function Add-PathWarning([string]$message) {
    if (-not [string]::IsNullOrWhiteSpace($message)) {
        $script:PathWarnings += $message
    }
}

function Write-PathWarningNow([string]$message) {
    if ([string]::IsNullOrWhiteSpace($message)) { return }
    try {
        if ([bool]$script:SuppressPathWarnings) { return }
    } catch { Write-IgnoredCatch $_ }
    if (Get-Command -Name Write-Log -ErrorAction SilentlyContinue) {
        Write-Log $message "WARN" $null "Paths"
    } else {
        Add-PathWarning $message
    }
}

function Write-SecurityMessage([string]$message, [string]$level = "WARN", [string]$context = "Security") {
    if ([string]::IsNullOrWhiteSpace($message)) { return }
    if (Get-Command -Name Write-Log -ErrorAction SilentlyContinue) {
        Write-Log $message $level $null $context
        return
    }
    if (Get-Command -Name Write-BootstrapLog -ErrorAction SilentlyContinue) {
        Write-BootstrapLog ("[{0}] {1}" -f $context, $message) $level
        return
    }
    Add-PathWarning ("[{0}] {1}" -f $context, $message)
}

function Get-EffectiveAllowExternalPaths([bool]$requestedAllowExternal) {
    if ($script:EnforceDataRootPaths) { return $false }
    return $requestedAllowExternal
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

function Get-CanonicalPath([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return "" }
    $normalized = Normalize-PathText $path
    if ([string]::IsNullOrWhiteSpace($normalized)) { return "" }
    try {
        return [System.IO.Path]::GetFullPath($normalized)
    } catch {
        return $normalized
    }
}

function Test-UnsafeReparseItem($item) {
    if ($null -eq $item) { return $false }
    try {
        if (-not ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            return $false
        }
    } catch {
        return $false
    }

    $linkType = ""
    try {
        if ($item.PSObject.Properties.Name -contains "LinkType" -and $null -ne $item.LinkType) {
            $linkType = [string]$item.LinkType
        }
    } catch { Write-IgnoredCatch $_ }
    if (-not [string]::IsNullOrWhiteSpace($linkType)) {
        return $true
    }

    $targets = @()
    try {
        if ($item.PSObject.Properties.Name -contains "Target" -and $null -ne $item.Target) {
            $targets = @(
                $item.Target | ForEach-Object {
                    $targetText = [string]$_
                    if ([string]::IsNullOrWhiteSpace($targetText)) { return }
                    # Ignore provider placeholders (for example "{}") and only
                    # treat real filesystem-looking targets as unsafe redirects.
                    if ($targetText -match '^[A-Za-z]:\\' -or $targetText -match '^\\\\' -or $targetText -match '^[.]{1,2}[\\/]' -or $targetText -match '[\\/]') {
                        $targetText
                    }
                }
            )
        }
    } catch { Write-IgnoredCatch $_ }
    if ($targets.Count -gt 0) {
        return $true
    }

    # Cloud/file-provider placeholder reparse points (for example OneDrive) do not
    # indicate link redirection by themselves, so they are treated as trusted.
    return $false
}

function Test-PathHasReparsePoint([string]$path, [string]$StopAtPath = $null, [switch]$IncludeStopPath) {
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    $full = Get-CanonicalPath $path
    if ([string]::IsNullOrWhiteSpace($full)) { return $false }
    $stopFull = Get-CanonicalPath $StopAtPath
    try {
        $current = $full
        while (-not [string]::IsNullOrWhiteSpace($current) -and (Test-Path $current)) {
            $isStopPath = (-not [string]::IsNullOrWhiteSpace($stopFull)) -and
                          $current.Equals($stopFull, [System.StringComparison]::OrdinalIgnoreCase)
            if ($isStopPath -and -not $IncludeStopPath) { break }
            try {
                $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
                if (Test-UnsafeReparseItem $item) {
                    return $true
                }
            } catch { Write-IgnoredCatch $_ }
            if ($isStopPath) { break }
            $parent = Split-Path -Path $current -Parent
            if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) { break }
            $current = $parent
        }
    } catch { Write-IgnoredCatch $_ }
    return $false
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
    } catch { Write-IgnoredCatch $_ }
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

function Get-PathRelativeToRoot([string]$path, [string]$root) {
    if ([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($root)) { return "" }
    try {
        $full = [System.IO.Path]::GetFullPath($path)
        $rootFull = [System.IO.Path]::GetFullPath($root)
        if (-not $rootFull.EndsWith('\')) { $rootFull += '\' }
        if ($full.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $full.Substring($rootFull.Length).TrimStart('\')
        }
    } catch { Write-IgnoredCatch $_ }
    return ""
}

function Test-TrustedFilePath([string]$path, [string]$root, [string]$tag = "Security", [string]$label = "File", [switch]$RequireExists) {
    if ([string]::IsNullOrWhiteSpace($path)) {
        $script:RuntimeModuleLastError = "Path is empty."
        Write-SecurityMessage ("{0}: path is empty for {1}." -f $tag, $label) "ERROR" $tag
        if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) { Write-SecurityAuditEvent "PathPolicyEmpty" "$label" "ERROR" $tag }
        return $false
    }
    $resolved = Get-CanonicalPath $path
    if ([string]::IsNullOrWhiteSpace($resolved)) {
        $script:RuntimeModuleLastError = "Failed to resolve path."
        Write-SecurityMessage ("{0}: failed to resolve path for {1}: {2}" -f $tag, $label, $path) "ERROR" $tag
        if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) { Write-SecurityAuditEvent "PathPolicyResolveFailed" "$label|$path" "ERROR" $tag }
        return $false
    }
    if (-not (Is-PathUnderRoot $resolved $root)) {
        $script:RuntimeModuleLastError = "Path is outside app root."
        Write-SecurityMessage ("{0}: path outside app root blocked for {1}: {2}" -f $tag, $label, $resolved) "ERROR" $tag
        if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) { Write-SecurityAuditEvent "PathPolicyOutsideRoot" "$label|$resolved" "ERROR" $tag }
        return $false
    }
    if (Test-PathHasReparsePoint -Path $resolved -StopAtPath $root) {
        Write-SecurityMessage ("{0}: path contains reparse point for {1}: {2}. Allowed under trusted app root policy." -f $tag, $label, $resolved) "WARN" $tag
        if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) { Write-SecurityAuditEvent "PathPolicyReparseAllowed" "$label|$resolved" "WARN" $tag }
    }
    if ($RequireExists -and -not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        $script:RuntimeModuleLastError = "Required module file is missing."
        Write-SecurityMessage ("{0}: required file missing for {1}: {2}" -f $tag, $label, $resolved) "ERROR" $tag
        if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) { Write-SecurityAuditEvent "PathPolicyMissingFile" "$label|$resolved" "ERROR" $tag }
        return $false
    }
    return $true
}

function Test-RuntimeModulePathAllowed([string]$path, [string]$tag = "Runtime-Module") {
    $script:RuntimeModuleLastError = ""
    if (-not (Test-TrustedFilePath -path $path -root $script:AppRoot -tag $tag -label "Runtime module" -RequireExists)) {
        if ([string]::IsNullOrWhiteSpace($script:RuntimeModuleLastError)) {
            $script:RuntimeModuleLastError = "Path trust validation failed."
        }
        return $false
    }
    $relative = Get-PathRelativeToRoot $path $script:AppRoot
    if ([string]::IsNullOrWhiteSpace($relative)) {
        Write-SecurityMessage ("{0}: failed to resolve runtime module relative path: {1}" -f $tag, $path) "ERROR" $tag
        if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) { Write-SecurityAuditEvent "RuntimeModuleRelativePathMissing" "$path" "ERROR" $tag }
        $script:RuntimeModuleLastError = "Failed to resolve runtime module relative path."
        return $false
    }
    $normalized = $relative -replace '/', '\'
    $normalized = $normalized -replace '\\+', '\'
    if ($normalized.StartsWith("Script\", [System.StringComparison]::OrdinalIgnoreCase)) {
        $normalized = $normalized.Substring(7)
    }
    $allowed = $false
    foreach ($entry in $script:RuntimeModuleAllowList) {
        $allowEntry = ([string]$entry -replace '/', '\') -replace '\\+', '\'
        if ([string]::Equals($allowEntry, $normalized, [System.StringComparison]::OrdinalIgnoreCase)) {
            $allowed = $true
            break
        }
    }
    if (-not $allowed) {
        Write-SecurityMessage ("{0}: runtime module is not allowlisted and was blocked: {1}" -f $tag, $normalized) "ERROR" $tag
        if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) { Write-SecurityAuditEvent "RuntimeModuleBlocked" "$normalized" "ERROR" $tag }
        $script:RuntimeModuleLastError = ("Runtime module is not allowlisted: {0}" -f $normalized)
        return $false
    }
    return $true
}

function Import-RuntimeModule([string]$path, [string]$tag = "Runtime-Module") {
    if (-not (Test-RuntimeModulePathAllowed -path $path -tag $tag)) { return $false }
    try {
        $modulePathFull = Get-CanonicalPath $path
        $imported = & {
            param($modulePath)
            $before = @{}
            foreach ($fn in (Get-ChildItem Function:\)) {
                if (-not $before.ContainsKey($fn.Name)) {
                    $before[$fn.Name] = $true
                }
            }
            . $modulePath
            $selected = New-Object System.Collections.ArrayList
            foreach ($fn in (Get-ChildItem Function:\)) {
                $isNewName = -not $before.ContainsKey($fn.Name)
                $sameFile = $false
                try {
                    if ($fn.ScriptBlock -and $fn.ScriptBlock.File) {
                        $fnFile = [System.IO.Path]::GetFullPath([string]$fn.ScriptBlock.File)
                        $sameFile = $fnFile.Equals($modulePath, [System.StringComparison]::OrdinalIgnoreCase)
                    }
                } catch { Write-IgnoredCatch $_ }
                if ($isNewName -or $sameFile) {
                    [void]$selected.Add($fn)
                }
            }
            $selected
        } $modulePathFull
        $importedList = @($imported)
        if ($importedList.Count -eq 0) {
            $script:RuntimeModuleLastError = "Module loaded but exported no discoverable functions."
            Write-SecurityMessage ("{0}: runtime module loaded but exported no functions: {1}" -f $tag, $path) "ERROR" $tag
            return $false
        }
        foreach ($func in $importedList) {
            if (-not $func -or -not $func.Name -or -not $func.ScriptBlock) { continue }
            Set-Item -Path ("Function:\script:{0}" -f $func.Name) -Value $func.ScriptBlock -Force
        }
        $script:RuntimeModuleLastError = ""
        return $true
    } catch {
        $script:RuntimeModuleLastError = [string]$_.Exception.Message
        Write-SecurityMessage ("{0}: runtime module import failed: {1}" -f $tag, $path) "ERROR" $tag
        if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) { Write-SecurityAuditEvent "RuntimeModuleImportFailed" "$path|$($_.Exception.Message)" "ERROR" $tag }
        return $false
    }
}

function Test-ModuleVersionContract([string]$moduleTag, [string]$commandName) {
    if ([string]::IsNullOrWhiteSpace($moduleTag) -or [string]::IsNullOrWhiteSpace($commandName)) { return $true }
    if (-not $script:RuntimeModuleContractVersions.ContainsKey($moduleTag)) { return $true }
    $expected = [string]$script:RuntimeModuleContractVersions[$moduleTag]
    if ([string]::IsNullOrWhiteSpace($expected)) { return $true }

    $command = Get-Command -Name $commandName -CommandType Function -ErrorAction SilentlyContinue
    if (-not $command) {
        Write-Log ("{0}: module version command missing: {1}" -f $moduleTag, $commandName) "WARN" $null $moduleTag
        return $false
    }
    try {
        $actual = (& $commandName)
        $actualString = [string]$actual
        if ([string]::IsNullOrWhiteSpace($actualString)) {
            Write-Log ("{0}: module version command returned empty value." -f $moduleTag) "WARN" $null $moduleTag
            return $false
        }
        if (-not [string]::Equals($actualString.Trim(), $expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Log ("{0}: module version mismatch (expected={1}, actual={2})." -f $moduleTag, $expected, $actualString) "WARN" $null $moduleTag
            return $false
        }
        return $true
    } catch {
        Write-LogExceptionDeduped ("{0}: failed to evaluate module version contract." -f $moduleTag) "WARN" $_.Exception $moduleTag 60
        return $false
    }
}

function Test-ImportExportFilePath([string]$path, [string]$label, [string[]]$allowedExtensions, [switch]$RequireExists, [int64]$MaxBytes = 0, [string]$Context = "ImportExport") {
    if ([string]::IsNullOrWhiteSpace($path)) {
        Write-SecurityMessage ("{0}: blocked empty path for {1}." -f $Context, $label) "WARN" $Context
        if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) { Write-SecurityAuditEvent "ImportExportEmptyPath" "$label" "WARN" $Context }
        return $false
    }
    $resolved = Get-CanonicalPath $path
    if ([string]::IsNullOrWhiteSpace($resolved)) {
        Write-SecurityMessage ("{0}: blocked unresolved path for {1}: {2}" -f $Context, $label, $path) "WARN" $Context
        if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) { Write-SecurityAuditEvent "ImportExportResolveFailed" "$label|$path" "WARN" $Context }
        return $false
    }
    if ($allowedExtensions -and $allowedExtensions.Count -gt 0) {
        $ext = [System.IO.Path]::GetExtension($resolved)
        $okExt = $false
        foreach ($allowedExt in $allowedExtensions) {
            if ([string]::Equals($ext, $allowedExt, [System.StringComparison]::OrdinalIgnoreCase)) {
                $okExt = $true
                break
            }
        }
        if (-not $okExt) {
            Write-SecurityMessage ("{0}: blocked path with disallowed extension for {1}: {2}" -f $Context, $label, $resolved) "WARN" $Context
            if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) { Write-SecurityAuditEvent "ImportExportBadExtension" "$label|$resolved" "WARN" $Context }
            return $false
        }
    }
    if ($RequireExists -and -not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        Write-SecurityMessage ("{0}: required file missing for {1}: {2}" -f $Context, $label, $resolved) "WARN" $Context
        if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) { Write-SecurityAuditEvent "ImportExportMissingFile" "$label|$resolved" "WARN" $Context }
        return $false
    }
    $reparseScanPath = $resolved
    if (-not $RequireExists) {
        try {
            $parent = Split-Path -Path $resolved -Parent
            if (-not [string]::IsNullOrWhiteSpace($parent)) { $reparseScanPath = $parent }
        } catch { Write-IgnoredCatch $_ }
    }
    if (Test-PathHasReparsePoint -Path $reparseScanPath) {
        Write-SecurityMessage ("{0}: blocked reparse-linked path for {1}: {2}" -f $Context, $label, $resolved) "WARN" $Context
        if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) { Write-SecurityAuditEvent "ImportExportReparseBlocked" "$label|$resolved" "WARN" $Context }
        return $false
    }
    if ($RequireExists -and $MaxBytes -gt 0) {
        try {
            $info = Get-Item -LiteralPath $resolved -ErrorAction Stop
            if ([int64]$info.Length -gt $MaxBytes) {
                Write-SecurityMessage ("{0}: blocked oversized file for {1}: {2} bytes > {3} bytes." -f $Context, $label, [int64]$info.Length, $MaxBytes) "WARN" $Context
                if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) { Write-SecurityAuditEvent "ImportExportFileTooLarge" "$label|$resolved|$([int64]$info.Length)" "WARN" $Context }
                return $false
            }
        } catch {
            Write-SecurityMessage ("{0}: failed to inspect file for {1}: {2}" -f $Context, $resolved, $_.Exception.Message) "WARN" $Context
            if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) { Write-SecurityAuditEvent "ImportExportInspectFailed" "$label|$resolved|$($_.Exception.Message)" "WARN" $Context }
            return $false
        }
    }
    return $true
}

function Test-TrustedDirectoryPath([string]$path, [string]$root, [bool]$allowExternal) {
    $full = Get-CanonicalPath $path
    if ([string]::IsNullOrWhiteSpace($full)) { return $false }
    if (-not $allowExternal) {
        if (-not (Is-PathUnderRoot $full $root)) { return $false }
        if (Test-PathHasReparsePoint -Path $full -StopAtPath $root) { return $false }
        return $true
    }
    if (Test-PathHasReparsePoint $full) { return $false }
    return $true
}

function Sanitize-DirectorySetting([string]$value, [string]$defaultName, [string]$label, [bool]$allowExternal) {
    if ([string]::IsNullOrWhiteSpace($value)) { return "" }
    $allowExternal = Get-EffectiveAllowExternalPaths $allowExternal
    $resolved = Convert-FromRelativePath $value
    if (-not (Test-TrustedDirectoryPath $resolved $script:DataRoot $allowExternal)) {
        if (-not $allowExternal -and -not (Is-PathUnderRoot $resolved $script:DataRoot)) {
            Write-PathWarningNow "$label path outside app folder blocked; using default."
        } else {
            Write-PathWarningNow "$label path uses a reparse point (junction/symlink) and was blocked."
        }
        return ""
    }
    return Convert-ToRelativePathIfUnderRoot $resolved
}

function Test-DirectoryWritable([string]$path, [switch]$ForceRefresh) {
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    $cacheKey = $path
    try { $cacheKey = [System.IO.Path]::GetFullPath($path).ToLowerInvariant() } catch { Write-IgnoredCatch $_ }

    if (-not $ForceRefresh -and $script:DirectoryWritableCache -and $script:DirectoryWritableCache.ContainsKey($cacheKey)) {
        try {
            $entry = $script:DirectoryWritableCache[$cacheKey]
            if ($entry -and ($entry.PSObject.Properties.Name -contains "CheckedAtUtc")) {
                $ttl = 300
                try { $ttl = [Math]::Max(30, [int]$script:DirectoryWritableCacheTtlSeconds) } catch { $ttl = 300 }
                $ageSeconds = ([DateTime]::UtcNow - [DateTime]$entry.CheckedAtUtc).TotalSeconds
                if ($ageSeconds -ge 0 -and $ageSeconds -lt $ttl) {
                    return [bool]$entry.Writable
                }
            }
        } catch { Write-IgnoredCatch $_ }
    }

    $isWritable = $false
    try {
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
        $testFile = Join-Path $path ("~write_test_{0}.tmp" -f ([Guid]::NewGuid().ToString("N")))
        Set-Content -Path $testFile -Value "test" -Encoding ASCII
        Remove-Item -Path $testFile -Force
        $isWritable = $true
    } catch {
        $isWritable = $false
    }

    try {
        if (-not $script:DirectoryWritableCache) { $script:DirectoryWritableCache = @{} }
        $script:DirectoryWritableCache[$cacheKey] = [pscustomobject]@{
            Writable     = $isWritable
            CheckedAtUtc = [DateTime]::UtcNow
        }
    } catch { Write-IgnoredCatch $_ }

    return $isWritable
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

function Resolve-DirectoryOrDefault([string]$inputPath, [string]$defaultPath, [string]$label, [bool]$allowExternal = $true) {
    $allowExternal = Get-EffectiveAllowExternalPaths $allowExternal
    $resolved = Convert-FromRelativePath $inputPath
    if ([string]::IsNullOrWhiteSpace($resolved)) { $resolved = $defaultPath }
    $resolved = Get-CanonicalPath $resolved
    if (-not (Test-TrustedDirectoryPath $resolved $script:DataRoot $allowExternal)) {
        if (-not $allowExternal -and -not (Is-PathUnderRoot $resolved $script:DataRoot)) {
            Write-PathWarningNow "$label path outside app data root blocked; falling back to default path."
        } else {
            Write-PathWarningNow "$label path uses a junction/symlink; falling back to default path."
        }
        $resolved = Get-CanonicalPath $defaultPath
    }
    Ensure-Directory $resolved $label | Out-Null
    if (-not (Test-DirectoryWritable $resolved)) {
        Write-PathWarningNow "$label directory not writable: $resolved. Falling back to $defaultPath."
        $resolved = $defaultPath
        Ensure-Directory $resolved $label | Out-Null
    }
    return $resolved
}

function Ensure-AppFolders {
    $folders = @($script:FolderNames.Logs, $script:FolderNames.Settings, $script:FolderNames.Meta, $script:FolderNames.Debug)
    foreach ($folder in $folders) {
        $path = Join-Path $script:DataRoot $folder
        Ensure-Directory $path $folder | Out-Null
    }
}

function Harden-AppPermissions {
    if (-not $script:IsElevatedSession) {
        if (-not $script:PermissionHardeningSkipLogged) {
            Write-Log "Permission hardening skipped in standard user context (not elevated)." "INFO" $null "Security"
            $script:PermissionHardeningSkipLogged = $true
        }
        return
    }
    $paths = @(
        $script:DataRoot,
        $script:SettingsDirectory,
        $script:LogDirectory,
        $script:MetaDir
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path $_) }
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $loggedPrivilegeSkip = $false
    foreach ($path in $paths) {
        try {
            $acl = Get-Acl -Path $path
            try { $acl.SetAccessRuleProtection($true, $true) } catch { Write-IgnoredCatch $_ }
            $rules = @($acl.Access) | Where-Object {
                $_.AccessControlType -eq "Allow" -and
                ($_.IdentityReference -match "Everyone|Users|Authenticated Users") -and
                ($_.FileSystemRights -match "Write|Modify|FullControl")
            }
            foreach ($rule in $rules) {
                $acl.RemoveAccessRule($rule) | Out-Null
            }
            if (-not [string]::IsNullOrWhiteSpace($currentUser)) {
                $identity = New-Object System.Security.Principal.NTAccount($currentUser)
                $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $identity,
                    [System.Security.AccessControl.FileSystemRights]::Modify,
                    [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit",
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                $acl.SetAccessRule($userRule)
            }
            Set-Acl -Path $path -AclObject $acl
        } catch {
            $permissionException = $_.Exception
            if ($permissionException -is [System.Security.AccessControl.PrivilegeNotHeldException]) {
                if (-not $loggedPrivilegeSkip) {
                    Write-Log ("Permission hardening skipped in standard user context: {0}" -f $permissionException.Message) "INFO" $permissionException "Security"
                    $loggedPrivilegeSkip = $true
                }
            } else {
                Write-Log ("Permission hardening skipped for {0}: {1}" -f $path, $permissionException.Message) "WARN" $permissionException "Security"
            }
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
        if ($script:AppRoot) {
            $result = $result -replace [regex]::Escape($script:AppRoot), "%APPROOT%"
        }
        if ($script:DataRoot) {
            $result = $result -replace [regex]::Escape($script:DataRoot), "%DATAROOT%"
        }
        $userProfile = $env:USERPROFILE
        if (-not [string]::IsNullOrWhiteSpace($userProfile)) {
            $result = $result -replace [regex]::Escape($userProfile), "%USERPROFILE%"
        }
    } catch { Write-IgnoredCatch $_ }
    return $result
}

function Redact-SensitiveText([string]$message) {
    if ([string]::IsNullOrWhiteSpace($message)) { return $message }
    $result = Redact-Paths $message
    try {
        $result = [regex]::Replace(
            $result,
            '(?im)\b(api[_-]?key|access[_-]?token|token|secret|password|passwd|pwd)\b\s*[:=]\s*([^\s|;,]+)',
            { param($m) "{0}=[REDACTED]" -f $m.Groups[1].Value }
        )
        $result = [regex]::Replace(
            $result,
            '(?im)\b(authorization\s*:\s*bearer)\s+([A-Za-z0-9\-\._~\+\/]+=*)',
            { param($m) "{0} [REDACTED]" -f $m.Groups[1].Value }
        )
        $result = [regex]::Replace($result, '(?i)\bgh[pousr]_[A-Za-z0-9]{20,}\b', '[REDACTED_TOKEN]')
        $result = [regex]::Replace($result, '(?i)\bxox[baprs]-[A-Za-z0-9-]{10,}\b', '[REDACTED_TOKEN]')
    } catch { Write-IgnoredCatch $_ }
    return $result
}

function Get-IntegrityTargets {
    $scriptDir = Join-Path $script:AppRoot $script:FolderNames.Script
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
try { Ensure-Directory $script:MetaDir "Meta" | Out-Null } catch { Write-IgnoredCatch $_ }
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
$script:RollbackStatePath = Join-Path $script:MetaDir "Teams-Always-Green.rollback.state.json"
$script:SettingsVersionsDir = Join-Path $script:MetaDir "SettingsVersions"
$script:ProfileVersionsDir = Join-Path $script:MetaDir "ProfileVersions"
$script:FirstRunWizardMarkerPath = Join-Path $script:MetaDir "Teams-Always-Green.first-run.complete"
$script:IntegrityManifestPath = Join-Path $script:MetaDir "Teams-Always-Green.integrity.json"
$script:MinimalModeStatePath = Join-Path $script:MetaDir "Teams-Always-Green.minimalmode.state.json"
$script:RestartRequestMarkerPath = Join-Path $script:MetaDir "Teams-Always-Green.restart.request.txt"
$script:LifetimeStatsPath = Join-Path $script:MetaDir "Teams-Always-Green.lifetime.json"
$script:BadgeShareCardsDir = Join-Path $script:MetaDir "BadgeCards"
$script:LifetimeToggleHighWater = -1L
$script:LifetimeToggleHighWaterLoaded = $false
$script:IntegrityStatus = "Unknown"
$script:IntegrityIssues = @()
$script:IntegrityFailed = $false
$script:UpdatePublicKeyPath = Join-Path $script:MetaDir "Teams-Always-Green.updatekey.xml"
$script:SettingsVersionRetentionCount = 25
$script:ProfileVersionRetentionCount = 20
$script:StartupLoadingIndicator = $false
$script:ActionToastLastByMessage = @{}
$oldSettingsLocator = Join-Path $script:AppRoot "Teams-Always-Green.settings.path.txt"
$oldLogLocator = Join-Path $script:AppRoot "Teams-Always-Green.log.path.txt"
if ((Test-Path $oldSettingsLocator) -and -not (Test-Path $script:SettingsLocatorPath)) {
    try { Move-Item -Path $oldSettingsLocator -Destination $script:SettingsLocatorPath -Force } catch { Write-IgnoredCatch $_ }
}
if ((Test-Path $oldLogLocator) -and -not (Test-Path $script:LogLocatorPath)) {
    try { Move-Item -Path $oldLogLocator -Destination $script:LogLocatorPath -Force } catch { Write-IgnoredCatch $_ }
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
    } catch { Write-IgnoredCatch $_ }
}
if (Test-Path $script:LogLocatorPath) {
    try {
        $logLocatorValue = (Get-Content -Path $script:LogLocatorPath -Raw).Trim()
        $script:LogDirectory = Resolve-DirectoryOrDefault $logLocatorValue $defaultLogDir "Logs"
    } catch { Write-IgnoredCatch $_ }
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
    } catch { Write-IgnoredCatch $_ }
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
    } catch { Write-IgnoredCatch $_ }
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
    } catch { Write-IgnoredCatch $_ }
}

function Get-MinimalModeState {
    $result = [ordered]@{
        Active = $false
        Reason = $null
        CrashCount = 0
        RecoveryTier = 0
        Override = $false
        IntegrityFailed = $false
    }

    try { $result.Active = [bool]$script:MinimalModeActive } catch { Write-IgnoredCatch $_ }
    try { $result.Reason = [string]$script:MinimalModeReason } catch { Write-IgnoredCatch $_ }
    try { $result.Override = [bool]$script:OverrideMinimalMode } catch { Write-IgnoredCatch $_ }
    try { $result.IntegrityFailed = [bool]$script:IntegrityFailed } catch { Write-IgnoredCatch $_ }

    $crashState = $null
    try { $crashState = Get-CrashState } catch { Write-IgnoredCatch $_ }
    if ($crashState) {
        if ($crashState.PSObject.Properties.Name -contains "Count") {
            try { $result.CrashCount = [Math]::Max(0, [int]$crashState.Count) } catch { Write-IgnoredCatch $_ }
        }
        if ($crashState.PSObject.Properties.Name -contains "OverrideMinimalMode") {
            try { $result.Override = [bool]$crashState.OverrideMinimalMode } catch { Write-IgnoredCatch $_ }
        }
    }

    if ($result.CrashCount -gt 0) {
        try { $result.RecoveryTier = [int](Get-CrashRecoveryTier $result.CrashCount) } catch { Write-IgnoredCatch $_ }
    }

    if ($result.Override) {
        $result.Active = $false
        if ([string]::IsNullOrWhiteSpace($result.Reason)) {
            $result.Reason = "Minimal mode override is enabled."
        }
    } elseif (-not $result.Active) {
        if ($result.IntegrityFailed) {
            $result.Active = $true
            if ([string]::IsNullOrWhiteSpace($result.Reason)) {
                $result.Reason = "Integrity check failed."
            }
        } elseif ($result.RecoveryTier -ge 1) {
            $result.Active = $true
            if ([string]::IsNullOrWhiteSpace($result.Reason)) {
                $result.Reason = "Crash recovery tier $($result.RecoveryTier)."
            }
        }
    }

    return [pscustomobject]$result
}

function Save-MinimalModeState {
    param(
        [bool]$Active,
        [string]$Reason = $null,
        [bool]$Override = $false,
        [string]$Source = "Runtime"
    )
    try {
        Ensure-Directory $script:MetaDir "Meta" | Out-Null
    } catch { Write-IgnoredCatch $_ }
    try {
        $payload = [pscustomobject]@{
            Active = [bool]$Active
            Reason = if ([string]::IsNullOrWhiteSpace($Reason)) { $null } else { [string]$Reason }
            Override = [bool]$Override
            Source = [string]$Source
            UpdatedUtc = (Get-Date).ToUniversalTime().ToString("o")
        }
        $json = $payload | ConvertTo-Json -Depth 3
        Write-AtomicTextFile -Path $script:MinimalModeStatePath -Content $json -Encoding UTF8 -VerifyJson
    } catch { Write-IgnoredCatch $_ }
}

function Get-SavedMinimalModeState {
    if ([string]::IsNullOrWhiteSpace([string]$script:MinimalModeStatePath)) { return $null }
    if (-not (Test-Path -LiteralPath $script:MinimalModeStatePath)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $script:MinimalModeStatePath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        $loaded = $raw | ConvertFrom-Json -ErrorAction Stop
        if (-not $loaded) { return $null }
        return $loaded
    } catch {
        return $null
    }
}

function Sync-MinimalModeState {
    param([string]$Source = "Runtime")
    try {
        $state = Get-MinimalModeState
        if ($state) {
            $overrideValue = $false
            if ($state.PSObject.Properties.Name -contains "Override") {
                $overrideValue = [bool]$state.Override
            }
            Save-MinimalModeState -Active ([bool]$state.Active) -Reason ([string]$state.Reason) -Override $overrideValue -Source $Source
        }
    } catch { Write-IgnoredCatch $_ }
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
    } catch { Write-IgnoredCatch $_ }
}

function Repair-FromStartupSnapshot($defaultSettings) {
    $snapshot = $null
    if (Test-Path $script:StartupSnapshotPath) {
        try {
            $raw = Get-Content -Path $script:StartupSnapshotPath -Raw
            if (-not [string]::IsNullOrWhiteSpace($raw)) { $snapshot = $raw | ConvertFrom-Json }
        } catch { Write-IgnoredCatch $_ }
    }

    $targetSettingsDir = if ($snapshot -and $snapshot.PSObject.Properties.Name -contains "SettingsDirectory") { Convert-FromRelativePath $snapshot.SettingsDirectory } else { $script:SettingsDirectory }
    $targetLogDir = if ($snapshot -and $snapshot.PSObject.Properties.Name -contains "LogDirectory") { Convert-FromRelativePath $snapshot.LogDirectory } else { $script:LogDirectory }
    $targetStatePath = if ($snapshot -and $snapshot.PSObject.Properties.Name -contains "StatePath") { Convert-FromRelativePath $snapshot.StatePath } else { $script:StatePath }
    $targetSettingsPath = if ($snapshot -and $snapshot.PSObject.Properties.Name -contains "SettingsPath") { Convert-FromRelativePath $snapshot.SettingsPath } else { $settingsPath }

    try { Ensure-Directory $targetSettingsDir "Settings" | Out-Null } catch { Write-IgnoredCatch $_ }
    try { Ensure-Directory $targetLogDir "Logs" | Out-Null } catch { Write-IgnoredCatch $_ }
    try { Ensure-Directory (Split-Path -Path $targetStatePath -Parent) "Settings" | Out-Null } catch { Write-IgnoredCatch $_ }

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
        } catch { Write-IgnoredCatch $_ }
    }
}
# --- Date/time formatting helpers (Core\DateTime.ps1) ---
$script:SettingsLoadFailed = $false
$script:SettingsRecovered = $false
$script:SettingsSaveInProgress = $false
$script:SettingsAutoCorrected = $false
$script:SettingsAutoCorrectedMessage = $null
$script:SettingsTampered = $false
$script:SettingsTamperMessage = $null
$script:MinimalModeActive = $false
$script:MinimalModeReason = $null

function Normalize-IntervalSeconds([int]$seconds) {
    if ($seconds -lt 5) { return 5 }
    if ($seconds -gt 86400) { return 86400 }
    return $seconds
}

function Normalize-ScrollLockReleaseDelayMs([int]$delayMs) {
    $min = [int]$script:ScrollLockReleaseDelayMinMs
    $max = [int]$script:ScrollLockReleaseDelayMaxMs
    $fallback = [int]$script:ScrollLockReleaseDelayDefaultMs
    if ($min -lt 1) { $min = 1 }
    if ($max -lt $min) { $max = $min }
    if ($fallback -lt $min -or $fallback -gt $max) { $fallback = $min }

    if ($delayMs -lt 0) { $delayMs = $fallback }
    if ($delayMs -lt $min) { return $min }
    if ($delayMs -gt $max) { return $max }
    return $delayMs
}

function Get-EnvironmentSummary {
    try {
        $culture = [System.Globalization.CultureInfo]::CurrentCulture.Name
        $uiCulture = [System.Globalization.CultureInfo]::CurrentUICulture.Name
        $is64 = [Environment]::Is64BitProcess
        $dpi = $null
        try {
            $dpi = [System.Windows.Forms.Screen]::PrimaryScreen.DeviceDpi
        } catch { Write-IgnoredCatch $_ }
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
    } catch { Write-IgnoredCatch $_ }
}

Write-BootstrapLog ("Paths resolved: DataRoot={0} Logs={1} Settings={2}" -f $script:DataRoot, $script:LogDirectory, $script:SettingsDirectory) "INFO"

function Save-LastGoodSettingsRaw([string]$rawJson) {
    if ([string]::IsNullOrWhiteSpace($rawJson)) { return }
    try {
        Ensure-Directory $script:MetaDir "Meta" | Out-Null
        Write-AtomicTextFile -Path $script:SettingsLastGoodPath -Content $rawJson -Encoding UTF8
    } catch { Write-IgnoredCatch $_ }
}

function Save-CorruptSettingsCopy([string]$rawJson) {
    try {
        Ensure-Directory $script:SettingsCorruptDir "Corrupt" | Out-Null
        $stamp = (Get-Date).ToString("yyyyMMddHHmmss")
        $target = Join-Path $script:SettingsCorruptDir ("Teams-Always-Green.settings.corrupt.{0}.json" -f $stamp)
        if (-not [string]::IsNullOrWhiteSpace($rawJson)) {
            Write-AtomicTextFile -Path $target -Content $rawJson -Encoding UTF8
        } elseif (Test-Path $script:settingsPath) {
            Copy-Item -Path $script:settingsPath -Destination $target -Force
        }
        Write-BootstrapLog "Corrupt settings saved to $target" "WARN"
    } catch { Write-IgnoredCatch $_ }
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
    } catch { Write-IgnoredCatch $_ }
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
        Write-AtomicTextFile -Path $script:ShutdownMarkerPath -Content $state -Encoding ASCII
    } catch {
        Write-BootstrapLog "Failed to write shutdown marker: $($_.Exception.Message)" "WARN"
    }
}

function Get-ShutdownMarker {
    try {
        if (Test-Path $script:ShutdownMarkerPath) {
            return (Get-Content -Path $script:ShutdownMarkerPath -Raw).Trim()
        }
    } catch { Write-IgnoredCatch $_ }
    return $null
}

function Set-RestartRequestMarker {
    try {
        Ensure-Directory $script:MetaDir "Meta" | Out-Null
        $stamp = (Get-Date).ToUniversalTime().ToString("o")
        Write-AtomicTextFile -Path $script:RestartRequestMarkerPath -Content $stamp -Encoding ASCII
    } catch {
        Write-BootstrapLog "Failed to write restart request marker." "WARN"
    }
}

function Consume-RestartRequestMarker([int]$maxAgeSeconds = 180) {
    if ([string]::IsNullOrWhiteSpace([string]$script:RestartRequestMarkerPath)) { return $false }
    if (-not (Test-Path -LiteralPath $script:RestartRequestMarkerPath)) { return $false }
    $raw = ""
    try {
        $raw = (Get-Content -LiteralPath $script:RestartRequestMarkerPath -Raw -ErrorAction Stop).Trim()
    } catch {
        $raw = ""
    }
    try {
        Remove-Item -LiteralPath $script:RestartRequestMarkerPath -Force -ErrorAction SilentlyContinue
    } catch { Write-IgnoredCatch $_ }
    if ([string]::IsNullOrWhiteSpace($raw)) { return $true }
    try {
        $stampUtc = [DateTime]::Parse($raw).ToUniversalTime()
        $ageSeconds = ((Get-Date).ToUniversalTime() - $stampUtc).TotalSeconds
        if ($ageSeconds -lt -15) { return $false }
        return ($ageSeconds -le [Math]::Max(30, [int]$maxAgeSeconds))
    } catch {
        return $true
    }
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
$script:BootTimer = $null
$script:BootStageDurations = @{}
$script:BootBudgetWarned = @{}
$script:StartupBudgetsMs = if (Get-Command Get-DefaultStartupBudgetsMs -ErrorAction SilentlyContinue) {
    Get-DefaultStartupBudgetsMs
} else {
    @{}
}
$script:HotkeysReady = $false
$script:HotkeysPending = $false
$script:FolderCheckTimer = $null
$script:PostShowStatusTimer = $null

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

function Get-ErrorFingerprint([string]$context, [string]$message, [Exception]$exception = $null) {
    $parts = @()
    $parts += ([string]$context).Trim().ToLowerInvariant()
    $parts += ([string]$message).Trim().ToLowerInvariant()
    if ($exception) {
        try { $parts += [string]$exception.GetType().FullName } catch { Write-IgnoredCatch $_ }
        try { $parts += [string]$exception.Message } catch { Write-IgnoredCatch $_ }
        try {
            if ($exception.StackTrace) {
                $firstLine = ([string]$exception.StackTrace -split "`r?`n" | Select-Object -First 1)
                if (-not [string]::IsNullOrWhiteSpace($firstLine)) { $parts += $firstLine.Trim() }
            }
        } catch { Write-IgnoredCatch $_ }
    }
    $raw = ($parts -join "|")
    if ([string]::IsNullOrWhiteSpace($raw)) { return "" }
    return (Get-StringSha256Hex $raw)
}

function Write-LogExceptionDeduped(
    [string]$message,
    [string]$level = "ERROR",
    [Exception]$exception = $null,
    [string]$context = "General",
    [int]$minSeconds = 30
) {
    $fingerprint = Get-ErrorFingerprint $context $message $exception
    if ([string]::IsNullOrWhiteSpace($fingerprint)) {
        Write-Log $message $level $exception $context
        return
    }
    $now = Get-Date
    if ($script:ErrorFingerprintCache.ContainsKey($fingerprint)) {
        $lastSeen = $script:ErrorFingerprintCache[$fingerprint]
        if ($lastSeen -and (($now - $lastSeen).TotalSeconds -lt $minSeconds)) {
            $script:SelfHealStats.SuppressedErrorCount = [int]$script:SelfHealStats.SuppressedErrorCount + 1
            return
        }
    }
    $script:ErrorFingerprintCache[$fingerprint] = $now
    Write-Log $message $level $exception $context
}

function Invoke-ResilientAction {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$Action,
        [int]$MaxAttempts = 2,
        [int]$BaseDelayMs = 150,
        [string]$Context = "Resilience",
        [ScriptBlock]$OnFailure
    )
    $attempts = [Math]::Max(1, $MaxAttempts)
    for ($attempt = 1; $attempt -le $attempts; $attempt++) {
        try {
            & $Action
            return $true
        } catch {
            $isLast = ($attempt -ge $attempts)
            $msg = ("{0} failed on attempt {1}/{2}: {3}" -f $Name, $attempt, $attempts, $_.Exception.Message)
            $logLevel = if ($isLast) { "ERROR" } else { "WARN" }
            Write-LogExceptionDeduped $msg $logLevel $_.Exception $Context 30
            if ($isLast) {
                if ($OnFailure) {
                    try { & $OnFailure $_.Exception } catch { Write-IgnoredCatch $_ }
                }
                return $false
            }
            Start-Sleep -Milliseconds ([Math]::Max(50, ($BaseDelayMs * $attempt)))
        }
    }
    return $false
}

if (-not $script:BootTimer) {
    $script:BootTimer = [System.Diagnostics.Stopwatch]::StartNew()
}
function Write-BootStage([string]$label) {
    try {
        $timerVar = Get-Variable -Name BootTimer -Scope Script -ErrorAction SilentlyContinue
        if (-not $timerVar -or -not $timerVar.Value) {
            $script:BootTimer = [System.Diagnostics.Stopwatch]::StartNew()
        }
        $elapsed = $script:BootTimer.ElapsedMilliseconds
        Write-Log ("Boot: {0} +{1}ms" -f $label, $elapsed) "INFO" $null "Startup"
        if (-not [string]::IsNullOrWhiteSpace($label)) {
            $script:BootStageDurations[$label] = $elapsed
            if (Get-Command Test-StartupStageBudget -ErrorAction SilentlyContinue) {
                $budgetResult = Test-StartupStageBudget -Stage $label -ElapsedMs $elapsed -Budgets $script:StartupBudgetsMs
                if ($budgetResult.HasBudget -and -not $budgetResult.WithinBudget) {
                    $warnDeltaMs = [int64]([Math]::Max(500, [Math]::Ceiling([double]$budgetResult.BudgetMs * 0.15)))
                    if ($budgetResult.DeltaMs -ge $warnDeltaMs -and -not $script:BootBudgetWarned.ContainsKey($budgetResult.StageKey)) {
                        Write-Log ("Boot budget exceeded: {0} {1}ms > {2}ms (+{3}ms)." -f $label, $elapsed, $budgetResult.BudgetMs, $budgetResult.DeltaMs) "WARN" $null "Startup"
                        $script:BootBudgetWarned[$budgetResult.StageKey] = $true
                    }
                }
            }
            if (($label -eq "Startup complete" -or $label -eq "Deferred startup done") -and (Get-Command Get-StartupBudgetSummaryText -ErrorAction SilentlyContinue)) {
                $summary = Get-StartupBudgetSummaryText -Durations $script:BootStageDurations -Budgets $script:StartupBudgetsMs
                if (-not [string]::IsNullOrWhiteSpace($summary)) {
                    Write-Log ("Boot budget summary: {0}" -f $summary) "INFO" $null "Startup"
                }
            }
        }
    } catch { Write-IgnoredCatch $_ }
}

function Start-DeferredMaintenanceTasks {
    if ($script:DeferredMaintenanceTimer) { return }
    $script:DeferredMaintenanceTimer = New-Object System.Windows.Forms.Timer
    $script:DeferredMaintenanceTimer.Interval = 250
    $script:DeferredMaintenanceTimer.Add_Tick({
        Invoke-SafeTimerAction "DeferredMaintenanceTimer" {
            if ($script:DeferredMaintenanceTimer) {
                try { $script:DeferredMaintenanceTimer.Stop() } catch { Write-IgnoredCatch $_ }
                try { $script:DeferredMaintenanceTimer.Dispose() } catch { Write-IgnoredCatch $_ }
                $script:DeferredMaintenanceTimer = $null
            }
            if ($script:PendingSignaturePolicyCheck) {
                try {
                    Invoke-ScriptSignaturePolicyCheck
                } catch { Write-IgnoredCatch $_ } finally {
                    $script:PendingSignaturePolicyCheck = $false
                }
            }
            try {
                if (Get-Command -Name Ensure-SettingsUiLoaded -ErrorAction SilentlyContinue) {
                    [void](Ensure-SettingsUiLoaded)
                }
            } catch { Write-IgnoredCatch $_ }
            try { Purge-OldLogs } catch { Write-IgnoredCatch $_ }
            try { Save-StartupSnapshot } catch { Write-IgnoredCatch $_ }
            if ($script:DeferredStartupSkipUpdate) {
                Write-Log "Deferred startup update check skipped by crash-recovery policy." "WARN" $null "Startup"
            } else {
                try { Invoke-UpdateCheck } catch { Write-IgnoredCatch $_ }
            }
            try {
                if (Get-Command -Name Get-EnvironmentSummary -ErrorAction SilentlyContinue) {
                    $envSummary = Get-EnvironmentSummary
                    if (-not [string]::IsNullOrWhiteSpace($envSummary)) {
                        Write-Log $envSummary "DEBUG" $null "Init"
                    }
                }
            } catch { Write-IgnoredCatch $_ }
        }
    })
    $script:DeferredMaintenanceTimer.Start()
}

function Invoke-DeferredStartupTasks {
    if ($script:DeferredStartupDone) { return }
    if ($script:isShuttingDown -or $script:CleanupDone) { return }
    $script:DeferredStartupDone = $true
    Write-BootStage "Deferred startup begin"
    if (-not $script:FolderCheckTimer) {
        $script:FolderCheckTimer = New-Object System.Windows.Forms.Timer
        $script:FolderCheckTimer.Interval = 500
        $script:FolderCheckTimer.Add_Tick({
            Invoke-SafeTimerAction "FolderCheckTimer" {
                try { $script:FolderCheckTimer.Stop() } catch { Write-IgnoredCatch $_ }
                try { $script:FolderCheckTimer.Dispose() } catch { Write-IgnoredCatch $_ }
                $script:FolderCheckTimer = $null
                try { Validate-RequiredFiles } catch { Write-IgnoredCatch $_ }
                try { Log-FolderHealthOnce } catch { Write-IgnoredCatch $_ }
                Write-BootStage "Folder check done"
            }
        })
        $script:FolderCheckTimer.Start()
    }
    try { if (Get-Command -Name Start-LogSummaryTimer -ErrorAction SilentlyContinue) { Start-LogSummaryTimer } } catch { Write-IgnoredCatch $_ }
    try { Start-DeferredMaintenanceTasks } catch { Write-IgnoredCatch $_ }
    Set-StartupLoadingIndicator $false
    Write-BootStage "Deferred startup done"
}

function Invoke-SafeTimerAction([string]$name, [ScriptBlock]$action) {
    $guardsVar = Get-Variable -Name TimerGuards -Scope Script -ErrorAction SilentlyContinue
    if (-not $guardsVar -or -not $guardsVar.Value) { $script:TimerGuards = @{} }
    if ($script:TimerGuards.ContainsKey($name) -and $script:TimerGuards[$name]) { return }
    $script:TimerGuards[$name] = $true
    try {
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $script:ComponentHeartbeat[$name] = Get-Date
        }
        & $action
    } catch {
        $safeName = if ([string]::IsNullOrWhiteSpace($name)) { "Timer" } else { "Timer-$name" }
        Write-LogThrottled $safeName ("Timer handler failed: {0}" -f $_.Exception.Message) "WARN" 15
        if (-not [string]::IsNullOrWhiteSpace($name) -and (Get-Command Request-TimerSelfHeal -ErrorAction SilentlyContinue)) {
            try {
                Request-TimerSelfHeal -TimerName $name -Reason $_.Exception.Message | Out-Null
            } catch { Write-IgnoredCatch $_ }
        }
    } finally {
        $script:TimerGuards[$name] = $false
    }
}

function Invoke-UiSafeAction {
    param(
        [string]$Name,
        [ScriptBlock]$Action,
        [string]$Context = "UI",
        [switch]$ShowDialog,
        [string]$DialogTitle = "Error",
        [string]$DialogMessagePrefix = "Action failed"
    )
    if (-not $Action) { return $false }
    if ([string]::IsNullOrWhiteSpace($Name)) { $Name = "UI Action" }
    try { Set-LastUserAction $Name $Context } catch { Write-IgnoredCatch $_ }
    $actionStart = Get-Date
    try {
        $settingsVar = Get-Variable -Name settings -Scope Script -ErrorAction SilentlyContinue
        $verboseUi = $false
        if ($settingsVar -and $settingsVar.Value -and ($settingsVar.Value.PSObject.Properties.Name -contains "VerboseUiLogging")) {
            $verboseUi = [bool]$settingsVar.Value.VerboseUiLogging
        }
        if ($verboseUi) {
            Write-Log "UI: Action started: $Name" "DEBUG" $null $Context
        }
        & $Action
        $elapsedMs = [int]((Get-Date) - $actionStart).TotalMilliseconds
        $script:LogResultOverride = "OK"
        Write-Log "UI: Action completed: $Name (ms=$elapsedMs)" "DEBUG" $null $Context
        return $true
    } catch {
        $script:LogResultOverride = "Failed"
        Write-Log "UI: Action failed: $Name" "ERROR" $_.Exception $Context
        if ($ShowDialog) {
            [System.Windows.Forms.MessageBox]::Show(
                "$DialogMessagePrefix ($Name).`n$($_.Exception.Message)",
                $DialogTitle,
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
        return $false
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
            } catch { Write-IgnoredCatch $_ }
        }
        $script:SettingsForm = $null
        $script:SettingsFormIcon = $null
        $note = if ([string]::IsNullOrWhiteSpace($reason)) { "Cleared stale runtime state." } else { "Cleared stale runtime state ($reason)." }
        Write-BootstrapLog $note "WARN"
    } catch { Write-IgnoredCatch $_ }
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
        (Join-Path $script:AppRoot "Meta\\Icons\\Tray_Icon.ico"),
        (Join-Path $script:AppRoot "Meta\\Icons\\Settings_Icon.ico")
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
        @{ Name = "Debug"; Path = (Join-Path $script:AppRoot $script:FolderNames.Debug) }
    )
    foreach ($item in $paths) {
        $exists = Test-Path $item.Path
        $writable = if ($exists) { Test-DirectoryWritable $item.Path } else { $false }
        $trusted = if ($exists) { -not (Test-PathHasReparsePoint $item.Path) } else { $true }
        $results += [pscustomobject]@{
            Name     = $item.Name
            Path     = $item.Path
            Exists   = $exists
            Writable = $writable
            Trusted  = $trusted
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

function Test-SettingsSchema($settings, [switch]$Strict) {
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
    $unknown = @()
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
        foreach ($key in $propertyNames) {
            if ($script:DefaultSettingsKeys -contains $key) { continue }
            if ($script:SettingsRuntimeKeys -contains $key) { continue }
            if ($key -like "Exported*") { continue }
            $unknown += [string]$key
        }
        if ($Strict -and $unknown.Count -gt 0) {
            $issues += ("Unknown keys blocked by strict mode: {0}" -f ((@($unknown | Select-Object -First 8)) -join ","))
            $isCritical = $true
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
        UnknownKeys   = $unknown
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

function Read-JsonFileSecure([string]$path, [int]$maxBytes, [string]$label = "JSON file") {
    if ([string]::IsNullOrWhiteSpace($path)) { throw "$label path is empty." }
    if (-not (Test-Path $path)) { throw "$label not found." }
    $info = Get-Item -LiteralPath $path -ErrorAction Stop
    if ($maxBytes -gt 0 -and [int64]$info.Length -gt [int64]$maxBytes) {
        throw ("{0} exceeds max size ({1} bytes)." -f $label, $maxBytes)
    }
    $raw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { throw "$label is empty." }
    return ($raw | ConvertFrom-Json -ErrorAction Stop)
}

function Get-RateLimitRule([string]$name) {
    if ([string]::IsNullOrWhiteSpace($name)) { return $null }
    if (-not $script:SecurityRateLimitDefaults) { return $null }
    if (-not $script:SecurityRateLimitDefaults.ContainsKey($name)) { return $null }
    return $script:SecurityRateLimitDefaults[$name]
}

function Test-RateLimit([string]$name, [int]$windowSeconds = 60, [int]$maxAttempts = 5) {
    if ([string]::IsNullOrWhiteSpace($name)) { return $true }
    $rule = Get-RateLimitRule $name
    if ($rule) {
        if ($rule.ContainsKey("WindowSeconds")) { $windowSeconds = [int]$rule["WindowSeconds"] }
        if ($rule.ContainsKey("MaxAttempts")) { $maxAttempts = [int]$rule["MaxAttempts"] }
    }
    if ($windowSeconds -le 0 -or $maxAttempts -le 0) { return $true }
    if (-not $script:SecurityRateLimits) { $script:SecurityRateLimits = @{} }
    if (-not $script:SecurityRateLimits.ContainsKey($name)) {
        $script:SecurityRateLimits[$name] = New-Object System.Collections.ArrayList
    }
    $now = Get-Date
    $cutoff = $now.AddSeconds(-1 * $windowSeconds)
    $entries = [System.Collections.ArrayList]$script:SecurityRateLimits[$name]
    for ($i = $entries.Count - 1; $i -ge 0; $i--) {
        if ([datetime]$entries[$i] -lt $cutoff) {
            $entries.RemoveAt($i)
        }
    }
    if ($entries.Count -ge $maxAttempts) {
        return $false
    }
    [void]$entries.Add($now)
    return $true
}

function Get-AppScriptSignatureInfo([string]$path) {
    $result = [pscustomobject]@{
        Status = "Unknown"
        Thumbprint = ""
        Subject = ""
        Message = ""
    }
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path $path)) {
        $result.Status = "Missing"
        $result.Message = "Script file not found."
        return $result
    }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
        if ($sig) {
            $result.Status = [string]$sig.Status
            if ($sig.SignerCertificate) {
                $result.Thumbprint = [string]$sig.SignerCertificate.Thumbprint
                $result.Subject = [string]$sig.SignerCertificate.Subject
            }
            $result.Message = [string]$sig.StatusMessage
        }
    } catch {
        $result.Status = "Error"
        $result.Message = [string]$_.Exception.Message
    }
    return $result
}

function Test-ScriptSignaturePolicy([string]$path, [bool]$enforce) {
    $sig = Get-AppScriptSignatureInfo $path
    $status = [string]$sig.Status
    $thumbprint = if ([string]::IsNullOrWhiteSpace([string]$sig.Thumbprint)) { "" } else { ([string]$sig.Thumbprint).ToUpperInvariant() }
    $trustedThumbprints = @()
    if ($settings -and ($settings.PSObject.Properties.Name -contains "TrustedSignerThumbprints")) {
        foreach ($part in ([string]$settings.TrustedSignerThumbprints -split "[,; ]+")) {
            if (-not [string]::IsNullOrWhiteSpace($part)) { $trustedThumbprints += $part.ToUpperInvariant() }
        }
    }
    $trustedThumbprints = @($trustedThumbprints | Select-Object -Unique)
    $thumbprintAllowed = ($trustedThumbprints.Count -eq 0 -or ($thumbprint -and ($trustedThumbprints -contains $thumbprint)))
    $isValid = ($status -eq "Valid" -and $thumbprintAllowed)
    $reason = if ($isValid) { "" } elseif ($status -ne "Valid") { "Authenticode status: $status" } else { "Signer thumbprint is not trusted." }
    return [pscustomobject]@{
        IsValid = $isValid
        Enforced = $enforce
        Status = $status
        Thumbprint = $thumbprint
        Reason = $reason
    }
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
        } elseif ($incomingStats.Count -gt 0) {
            $incomingLifetime = 0
            $currentLifetime = 0
            try {
                if ($incomingStats.ContainsKey("LifetimeToggleCount")) { $incomingLifetime = [int64]$incomingStats["LifetimeToggleCount"] }
            } catch {
                $incomingLifetime = 0
            }
            try {
                if ($currentStats.ContainsKey("LifetimeToggleCount")) { $currentLifetime = [int64]$currentStats["LifetimeToggleCount"] }
            } catch {
                $currentLifetime = 0
            }
            if ($incomingLifetime -lt 0) { $incomingLifetime = 0 }
            if ($currentLifetime -lt 0) { $currentLifetime = 0 }
            if ($incomingLifetime -gt $currentLifetime) {
                $currentStats["LifetimeToggleCount"] = $incomingLifetime
                $changed = $true
            }
            try {
                $incomingPointsHighWater = 0
                $currentPointsHighWater = 0
                if ($incomingStats.ContainsKey("BadgePointsHighWater")) { $incomingPointsHighWater = [int][Math]::Max(0, [int]$incomingStats["BadgePointsHighWater"]) }
                if ($currentStats.ContainsKey("BadgePointsHighWater")) { $currentPointsHighWater = [int][Math]::Max(0, [int]$currentStats["BadgePointsHighWater"]) }
                if ($incomingPointsHighWater -gt $currentPointsHighWater) {
                    $currentStats["BadgePointsHighWater"] = $incomingPointsHighWater
                    $changed = $true
                }
            } catch { Write-IgnoredCatch $_ }
            try {
                $incomingUnlocked = Convert-ToHashtable $incomingStats["BadgeUnlocked"]
                $currentUnlocked = Convert-ToHashtable $currentStats["BadgeUnlocked"]
                $unlockMerged = $false
                foreach ($unlockKey in @($incomingUnlocked.Keys)) {
                    if (-not $currentUnlocked.ContainsKey($unlockKey)) {
                        $currentUnlocked[$unlockKey] = $incomingUnlocked[$unlockKey]
                        $unlockMerged = $true
                    }
                }
                if ($unlockMerged) {
                    $currentStats["BadgeUnlocked"] = $currentUnlocked
                    $changed = $true
                }
            } catch { Write-IgnoredCatch $_ }
            try {
                $incomingHistory = @($incomingStats["BadgeHistory"])
                $currentHistory = @($currentStats["BadgeHistory"])
                if ($incomingHistory.Count -gt 0) {
                    $historyById = @{}
                    foreach ($entry in $currentHistory) {
                        if (-not $entry) { continue }
                        $entryId = ""
                        try { $entryId = [string]$entry.Id } catch { $entryId = "" }
                        if ([string]::IsNullOrWhiteSpace($entryId)) { continue }
                        $historyById[$entryId] = $entry
                    }
                    $historyMerged = $false
                    foreach ($entry in $incomingHistory) {
                        if (-not $entry) { continue }
                        $entryId = ""
                        try { $entryId = [string]$entry.Id } catch { $entryId = "" }
                        if ([string]::IsNullOrWhiteSpace($entryId)) { continue }
                        if (-not $historyById.ContainsKey($entryId)) {
                            $historyById[$entryId] = $entry
                            $historyMerged = $true
                        }
                    }
                    if ($historyMerged) {
                        $mergedHistory = @($historyById.Values)
                        if ($mergedHistory.Count -gt 300) { $mergedHistory = @($mergedHistory | Select-Object -Last 300) }
                        $currentStats["BadgeHistory"] = $mergedHistory
                        $changed = $true
                    }
                }
            } catch { Write-IgnoredCatch $_ }
            try {
                $incomingProfileMap = Convert-ToHashtable $incomingStats["ProfileLifetimeToggles"]
                $currentProfileMap = Convert-ToHashtable $currentStats["ProfileLifetimeToggles"]
                $profileChanged = $false
                foreach ($profileKey in @($incomingProfileMap.Keys)) {
                    $incomingValue = 0L
                    $currentValue = 0L
                    try { $incomingValue = [int64][Math]::Max(0, [int64]$incomingProfileMap[$profileKey]) } catch { $incomingValue = 0L }
                    if ($currentProfileMap.ContainsKey($profileKey)) {
                        try { $currentValue = [int64][Math]::Max(0, [int64]$currentProfileMap[$profileKey]) } catch { $currentValue = 0L }
                    }
                    if ($incomingValue -gt $currentValue) {
                        $currentProfileMap[$profileKey] = $incomingValue
                        $profileChanged = $true
                    }
                }
                if ($profileChanged) {
                    $currentStats["ProfileLifetimeToggles"] = $currentProfileMap
                    $changed = $true
                }
            } catch { Write-IgnoredCatch $_ }
            try {
                $incomingProfileHigh = Convert-ToHashtable $incomingStats["ProfileLifetimeHighWater"]
                $currentProfileHigh = Convert-ToHashtable $currentStats["ProfileLifetimeHighWater"]
                $profileHighChanged = $false
                foreach ($profileKey in @($incomingProfileHigh.Keys)) {
                    $incomingValue = 0L
                    $currentValue = 0L
                    try { $incomingValue = [int64][Math]::Max(0, [int64]$incomingProfileHigh[$profileKey]) } catch { $incomingValue = 0L }
                    if ($currentProfileHigh.ContainsKey($profileKey)) {
                        try { $currentValue = [int64][Math]::Max(0, [int64]$currentProfileHigh[$profileKey]) } catch { $currentValue = 0L }
                    }
                    if ($incomingValue -gt $currentValue) {
                        $currentProfileHigh[$profileKey] = $incomingValue
                        $profileHighChanged = $true
                    }
                }
                if ($profileHighChanged) {
                    $currentStats["ProfileLifetimeHighWater"] = $currentProfileHigh
                    $changed = $true
                }
            } catch { Write-IgnoredCatch $_ }
            if ($changed) {
                $state.Stats = $currentStats
            }
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
$script:SessionEndingHandler = $null
$script:SessionEndingSubscribed = $false
$script:SettingsForm = $null
$script:SettingsFormIcon = $null
$script:SettingsSchemaVersion = 11
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
$script:SettingsMaxBytes = 1048576
$script:ProfileImportMaxBytes = 262144
$script:SecurityDefaultUpdateOwner = "alexphillips-dev"
$script:SecurityDefaultUpdateRepo = "Teams-Always-Green"
$script:SecurityRateLimitDefaults = @{
    UpdateCheck   = @{ WindowSeconds = 60; MaxAttempts = 5 }
    SettingsImport = @{ WindowSeconds = 60; MaxAttempts = 4 }
    ProfileImport = @{ WindowSeconds = 60; MaxAttempts = 6 }
}
$script:SecurityRateLimits = @{}
$script:AuditChainPath = $null
$script:AuditChainLastHash = "GENESIS"
$script:SecurityAuditChainPath = $null
$script:SecurityAuditChainLastHash = "GENESIS"
$script:SecurityAuditVerifyEveryN = 25
$script:SecurityAuditWriteCount = 0
$script:SecurityAuditVerifyInProgress = $false
$script:RollbackState = $null
$script:ScriptSignatureStatus = "Unknown"
$script:ScriptSignatureThumbprint = ""
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
        try { Request-StatusUpdate } catch { Write-IgnoredCatch $_ }
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
$versionPath = Join-Path $script:AppRoot "VERSION"
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
    } catch { Write-IgnoredCatch $_ }
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
    Write-Log ("Build metadata: Id={0} Hash={1}" -f $appBuildId, $appScriptHash) "DEBUG" $null "Build"
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
    } catch { Write-IgnoredCatch $_ }
    return "Unknown"
}

# --- Update engine (release lookup, validation, apply) ---
$updateModulePath = Join-Path $PSScriptRoot "Features\\UpdateEngine.ps1"
if (-not (Import-RuntimeModule $updateModulePath "Update-Module")) {
    $script:UpdateModuleAvailable = $false
    $reason = if ([string]::IsNullOrWhiteSpace($script:RuntimeModuleLastError)) { "Unknown reason." } else { $script:RuntimeModuleLastError }
    Write-SecurityMessage ("Update module unavailable; update checks disabled. Path={0} Reason={1}" -f $updateModulePath, $reason) "WARN" "Update-Module"
    if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) {
        Write-SecurityAuditEvent "UpdateModuleUnavailable" ("Path={0}|Reason={1}" -f $updateModulePath, $reason) "WARN" "Update-Module"
    }
    if (-not (Get-Command Invoke-UpdateCheck -ErrorAction SilentlyContinue)) {
        function Invoke-UpdateCheck {
            param(
                [switch]$Force,
                [object]$Release,
                [switch]$SilentNoUpdate
            )
            $null = $Release
            $null = $SilentNoUpdate
            Write-SecurityMessage "Update check requested, but update module is unavailable." "WARN" "Update-Module"
            if ($Force) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Update feature is temporarily unavailable in this install.`n`nPlease run QuickSetup or reinstall the app package.",
                    "Update unavailable",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
            }
        }
    }
} elseif (-not (Test-ModuleVersionContract "Update-Module" "Get-UpdateModuleVersion")) {
    $script:UpdateModuleAvailable = $false
    Write-SecurityMessage "Update module version contract failed; update checks disabled." "WARN" "Update-Module"
    if (-not (Get-Command Invoke-UpdateCheck -ErrorAction SilentlyContinue)) {
        function Invoke-UpdateCheck {
            param(
                [switch]$Force,
                [object]$Release,
                [switch]$SilentNoUpdate
            )
            $null = $Release
            $null = $SilentNoUpdate
            Write-SecurityMessage "Update check requested, but update module version contract failed." "WARN" "Update-Module"
            if ($Force) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Update feature is temporarily unavailable in this install.`n`nPlease run QuickSetup or reinstall the app package.",
                    "Update unavailable",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
            }
        }
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
$iconPath  = Join-Path $script:AppRoot "Meta\\Icons\\Tray_Icon.ico"
$script:logPath   = Join-Path $script:LogDirectory "Teams-Always-Green.log"
$script:AuditLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.audit.log"
$script:SecurityAuditLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.security.log"
$script:AuditChainPath = Join-Path $script:MetaDir "Teams-Always-Green.audit.chain.json"
$script:SecurityAuditChainPath = Join-Path $script:MetaDir "Teams-Always-Green.security.chain.json"
$script:SecurityAuditChainLastHash = "GENESIS"
$script:SecurityAuditWriteCount = 0
$script:settingsPath = Join-Path $script:SettingsDirectory "Teams-Always-Green.settings.json"
# Ensure default folders exist
try {
    if (-not (Test-Path $script:LogDirectory)) {
        New-Item -ItemType Directory -Path $script:LogDirectory -Force | Out-Null
    }
    if (-not (Test-Path $script:SettingsDirectory)) {
        New-Item -ItemType Directory -Path $script:SettingsDirectory -Force | Out-Null
    }
} catch { Write-IgnoredCatch $_ }
# Move root log/settings files into their folders if they were created in the script directory
$rootLogPath = Join-Path $script:AppRoot "Teams-Always-Green.log"
if ((Test-Path $rootLogPath) -and ($script:LogDirectory -ne $script:AppRoot)) {
    try { Move-Item -Path $rootLogPath -Destination $script:logPath -Force } catch { Write-IgnoredCatch $_ }
}
$rootSettingsPath = Join-Path $script:AppRoot "Teams-Always-Green.settings.json"
if ((Test-Path $rootSettingsPath) -and ($script:SettingsDirectory -ne $script:AppRoot)) {
    try { Move-Item -Path $rootSettingsPath -Destination $script:settingsPath -Force } catch { Write-IgnoredCatch $_ }
}
foreach ($i in 1..3) {
    $rootBak = Join-Path $script:AppRoot ("Teams-Always-Green.settings.json.bak{0}" -f $i)
    $destBak = Join-Path $script:SettingsDirectory ("Teams-Always-Green.settings.json.bak{0}" -f $i)
    if ((Test-Path $rootBak) -and ($script:SettingsDirectory -ne $script:AppRoot)) {
        try { Move-Item -Path $rootBak -Destination $destBak -Force } catch { Write-IgnoredCatch $_ }
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
$script:SecurityAuditEnabled = $true
$script:SecurityAuditLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.security.log"
$script:LogLevels = @{
    "DEBUG" = 1
    "INFO"  = 2
    "WARN"  = 3
    "ERROR" = 4
    "FATAL" = 5
}
$script:RecentErrors = New-Object System.Collections.ArrayList
$script:LogCategoryNames = @("General", "Startup", "Settings", "Schedule", "Hotkeys", "Tray", "Profiles", "Diagnostics", "Logging", "Security")
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

function Get-LogEventId([string]$context, [string]$level, [string]$message) {
    $ctx = if ([string]::IsNullOrWhiteSpace($context)) { "General" } else { $context }
    $prefix = switch -Regex ($ctx) {
        "Settings|UI" { "SET"; break }
        "Profile" { "PRF"; break }
        "Update" { "UPD"; break }
        "Hotkey" { "HKT"; break }
        "Tray" { "TRY"; break }
        "Schedule" { "SCH"; break }
        "Log|Logging" { "LOG"; break }
        "Diagnostics|SelfTest|Health|Export" { "DIA"; break }
        "Startup|Init" { "STR"; break }
        "Restart" { "RST"; break }
        "Exit|Shutdown|Cleanup" { "EXT"; break }
        "State|Status" { "STA"; break }
        "Security|Integrity" { "SEC"; break }
        "Command" { "CMD"; break }
        default { "GEN" }
    }
    $normalizedLevel = if ([string]::IsNullOrWhiteSpace($level)) { "INFO" } else { $level.ToUpperInvariant() }
    $levelBase = switch ($normalizedLevel) {
        "DEBUG" { 100 }
        "INFO"  { 200 }
        "WARN"  { 300 }
        "ERROR" { 400 }
        "FATAL" { 900 }
        default { 200 }
    }
    $bucket = 0
    if (-not [string]::IsNullOrWhiteSpace($message)) {
        $normalized = (($message.ToLowerInvariant() -replace "\d+", "0") -replace "\s+", " ").Trim()
        if ($normalized.Length -gt 0) {
            $sum = 0
            foreach ($ch in $normalized.ToCharArray()) { $sum += [int][char]$ch }
            $bucket = ($sum % 50)
        }
    }
    $number = $levelBase + $bucket
    return ("{0}-{1:000}" -f $prefix, $number)
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
    } catch { Write-IgnoredCatch $_ }
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
    Write-Log ("Startup summary: Profile={0} Interval={1}s LogLevel={2} QuietMode={3} StartOnLaunch={4} RunOnceOnLaunch={5} AutoStartOnRestart={6} RelaunchedFromRestart={7} ScheduleEnabled={8} Paused={9}" -f `
        $settings.ActiveProfile, $settings.IntervalSeconds, $settings.LogLevel, $settings.QuietMode, $settings.StartOnLaunch, $settings.RunOnceOnLaunch, (Get-SettingsPropertyValue $settings "AutoStartOnRestart" $false), $script:RelaunchedFromRestart, $settings.ScheduleEnabled, $script:isPaused) `
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

function Unregister-SystemSessionEndingHandler {
    if (-not $script:SessionEndingSubscribed -or -not $script:SessionEndingHandler) { return }
    try {
        [Microsoft.Win32.SystemEvents]::remove_SessionEnding($script:SessionEndingHandler)
    } catch { Write-IgnoredCatch $_ } finally {
        $script:SessionEndingSubscribed = $false
        $script:SessionEndingHandler = $null
    }
}

function Register-SystemSessionEndingHandler {
    if ($script:SessionEndingSubscribed) { return }
    try {
        $script:SessionEndingHandler = [Microsoft.Win32.SessionEndingEventHandler]{
            param($src, $e)
            $null = $src
            if ($script:CleanupDone -or $script:isShuttingDown) { return }
            $reason = "WindowsSessionEnding"
            try {
                if ($e -and $e.Reason -eq [Microsoft.Win32.SessionEndReasons]::Logoff) {
                    $reason = "WindowsLogoff"
                } elseif ($e -and $e.Reason -eq [Microsoft.Win32.SessionEndReasons]::SystemShutdown) {
                    $reason = "WindowsShutdown"
                }
            } catch { Write-IgnoredCatch $_ }
            Write-Log ("System session ending detected. Reason={0}" -f $reason) "INFO" $null "Shutdown"
            Invoke-AppShutdownCleanup -Reason $reason
        }
        [Microsoft.Win32.SystemEvents]::add_SessionEnding($script:SessionEndingHandler)
        $script:SessionEndingSubscribed = $true
        Write-Log "Registered Windows session-ending shutdown handler." "DEBUG" $null "Startup"
    } catch {
        Write-Log "Failed to register session-ending handler." "WARN" $_.Exception "Startup"
        $script:SessionEndingSubscribed = $false
        $script:SessionEndingHandler = $null
    }
}

function Invoke-AppShutdownCleanup {
    param(
        [string]$Reason = "Exit",
        [switch]$SkipAppExit
    )
    if ($script:CleanupDone) { return }
    if ($script:isShuttingDown -and -not $SkipAppExit) { return }

    $script:isShuttingDown = $true
    try {
        Log-ShutdownSummary $Reason
    } catch { Write-IgnoredCatch $_ }
    try { Set-ShutdownMarker "clean" } catch { Write-IgnoredCatch $_ }
    try { Flush-SettingsSave } catch { Write-IgnoredCatch $_ }
    try { Flush-LogBuffer } catch { Write-IgnoredCatch $_ }

    try {
        if (Get-Command -Name Set-StatusUpdateTimerEnabled -ErrorAction SilentlyContinue) {
            Set-StatusUpdateTimerEnabled $false
        }
    } catch { Write-IgnoredCatch $_ }

    $stopTimer = {
        param([string]$name)
        $var = Get-Variable -Name $name -Scope Script -ErrorAction SilentlyContinue
        if (-not $var -or -not $var.Value) { return }
        $obj = $var.Value
        try { if ($obj.PSObject.Methods.Name -contains "Stop") { $obj.Stop() } } catch { Write-IgnoredCatch $_ }
    }
    $disposeTimer = {
        param([string]$name, [switch]$clearValue)
        $var = Get-Variable -Name $name -Scope Script -ErrorAction SilentlyContinue
        if (-not $var -or -not $var.Value) { return }
        $obj = $var.Value
        try { if ($obj.PSObject.Methods.Name -contains "Dispose") { $obj.Dispose() } } catch { Write-IgnoredCatch $_ }
        if ($clearValue) { try { Set-Variable -Name $name -Scope Script -Value $null -Force } catch { Write-IgnoredCatch $_ } }
    }

    $timerNames = @(
        "timer",
        "statusUpdateTimer",
        "StatusUpdateDebounceTimer",
        "SaveSettingsTimer",
        "pauseTimer",
        "watchdogTimer",
        "DeferredMaintenanceTimer",
        "FolderCheckTimer",
        "DeferredStartupTimer",
        "HealthMonitorTimer",
        "LogSummaryTimer",
        "LogFlushTimer",
        "SelfHealActionTimer",
        "PostShowStatusTimer"
    )
    foreach ($timerName in $timerNames) {
        & $stopTimer $timerName
    }

    try { Unregister-Hotkeys } catch { Write-IgnoredCatch $_ }
    try { Stop-Toggling } catch { Write-IgnoredCatch $_ }
    foreach ($timerName in $timerNames) {
        & $disposeTimer $timerName -clearValue
    }
    try { Stop-SelfHealQueueTimer } catch { Write-IgnoredCatch $_ }
    try { if ($script:OverlayIcon) { $script:OverlayIcon.Dispose(); $script:OverlayIcon = $null } } catch { Write-IgnoredCatch $_ }
    try {
        if ($notifyIcon) {
            try { $notifyIcon.Visible = $false } catch { Write-IgnoredCatch $_ }
            try { $notifyIcon.Dispose() } catch { Write-IgnoredCatch $_ }
            $notifyIcon = $null
        }
    } catch { Write-IgnoredCatch $_ }

    try { Unregister-SystemSessionEndingHandler } catch { Write-IgnoredCatch $_ }
    try { Release-MutexOnce } catch { Write-IgnoredCatch $_ }
    try { Flush-LogBuffer } catch { Write-IgnoredCatch $_ }
    $script:CleanupDone = $true
    if (-not $SkipAppExit) {
        try { [System.Windows.Forms.Application]::Exit() } catch { Write-IgnoredCatch $_ }
    }
}

function Load-AuditChainState {
    if (-not $script:AuditChainPath -or -not (Test-Path $script:AuditChainPath)) { return }
    try {
        $loaded = Read-JsonFileSecure $script:AuditChainPath 32768 "Audit chain state"
        if ($loaded -and ($loaded.PSObject.Properties.Name -contains "LastHash")) {
            $last = [string]$loaded.LastHash
            if (-not [string]::IsNullOrWhiteSpace($last) -and $last -match "^[A-Fa-f0-9]{64}$") {
                $script:AuditChainLastHash = $last.ToUpperInvariant()
            }
        }
    } catch { Write-IgnoredCatch $_ }
}

function Save-AuditChainState {
    if (-not $script:AuditChainPath) { return }
    try {
        $payload = [pscustomobject]@{
            UpdatedUtc = (Get-Date).ToUniversalTime().ToString("o")
            LastHash   = [string]$script:AuditChainLastHash
            SessionId  = [string]$script:SessionId
        }
        $tmp = Join-Path $script:MetaDir ("Teams-Always-Green.audit.chain.json.tmp.{0}" -f ([Guid]::NewGuid().ToString("N")))
        $payload | ConvertTo-Json -Depth 4 | Set-Content -Path $tmp -Encoding UTF8
        try {
            Move-Item -Path $tmp -Destination $script:AuditChainPath -Force
        } catch {
            Copy-Item -Path $tmp -Destination $script:AuditChainPath -Force
            try { Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue } catch { Write-IgnoredCatch $_ }
        }
    } catch { Write-IgnoredCatch $_ }
}

function Load-SecurityAuditChainState {
    if (-not $script:SecurityAuditChainPath -or -not (Test-Path $script:SecurityAuditChainPath)) { return }
    try {
        $loaded = Read-JsonFileSecure $script:SecurityAuditChainPath 32768 "Security audit chain state"
        if ($loaded -and ($loaded.PSObject.Properties.Name -contains "LastHash")) {
            $last = [string]$loaded.LastHash
            if (-not [string]::IsNullOrWhiteSpace($last) -and $last -match "^[A-Fa-f0-9]{64}$") {
                $script:SecurityAuditChainLastHash = $last.ToUpperInvariant()
            }
        }
    } catch { Write-IgnoredCatch $_ }
}

function Save-SecurityAuditChainState {
    if (-not $script:SecurityAuditChainPath) { return }
    try {
        $payload = [pscustomobject]@{
            UpdatedUtc = (Get-Date).ToUniversalTime().ToString("o")
            LastHash   = [string]$script:SecurityAuditChainLastHash
            SessionId  = [string]$script:SessionId
        }
        $tmp = Join-Path $script:MetaDir ("Teams-Always-Green.security.chain.json.tmp.{0}" -f ([Guid]::NewGuid().ToString("N")))
        $payload | ConvertTo-Json -Depth 4 | Set-Content -Path $tmp -Encoding UTF8
        try {
            Move-Item -Path $tmp -Destination $script:SecurityAuditChainPath -Force
        } catch {
            Copy-Item -Path $tmp -Destination $script:SecurityAuditChainPath -Force
            try { Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue } catch { Write-IgnoredCatch $_ }
        }
    } catch { Write-IgnoredCatch $_ }
}

function Test-SecurityAuditLogChain([int]$tailLines = 300) {
    if (-not $script:SecurityAuditLogPath -or -not (Test-Path $script:SecurityAuditLogPath)) { return $true }
    try {
        $lines = @(Get-Content -Path $script:SecurityAuditLogPath -Tail ([Math]::Max(50, $tailLines)))
        if (@($lines).Count -eq 0) { return $true }
        $pattern = 'PrevHash=(?<prev>GENESIS|[A-Fa-f0-9]{64})\s+PayloadHash=(?<payload>[A-Fa-f0-9]{64})\s+Hash=(?<hash>[A-Fa-f0-9]{64})'
        $entries = @()
        foreach ($line in $lines) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $match = [regex]::Match([string]$line, $pattern)
            if (-not $match.Success) { continue }
            $entries += [pscustomobject]@{
                PrevHash    = ([string]$match.Groups["prev"].Value).ToUpperInvariant()
                PayloadHash = ([string]$match.Groups["payload"].Value).ToUpperInvariant()
                Hash        = ([string]$match.Groups["hash"].Value).ToUpperInvariant()
            }
        }
        if ($entries.Count -eq 0) { return $true }
        $prior = $null
        foreach ($entry in $entries) {
            if ($prior -and $entry.PrevHash -ne $prior) { return $false }
            $computed = (Get-StringSha256Hex ("{0}|{1}" -f $entry.PrevHash, $entry.PayloadHash)).ToUpperInvariant()
            if ($computed -ne $entry.Hash) { return $false }
            $prior = $entry.Hash
        }
        if ($script:SecurityAuditChainLastHash -and $script:SecurityAuditChainLastHash -ne "GENESIS" -and $prior -and $prior -ne $script:SecurityAuditChainLastHash) {
            return $false
        }
        return $true
    } catch {
        return $false
    }
}

function Compare-AppVersion([string]$left, [string]$right) {
    if ([string]::IsNullOrWhiteSpace($left) -or [string]::IsNullOrWhiteSpace($right)) { return 0 }
    $leftVersion = $null
    $rightVersion = $null
    if (-not [version]::TryParse($left, [ref]$leftVersion)) { return 0 }
    if (-not [version]::TryParse($right, [ref]$rightVersion)) { return 0 }
    return $leftVersion.CompareTo($rightVersion)
}

function New-RollbackStateDefault {
    return @{
        HighestVersion          = [string]$appVersion
        HighestSettingsSequence = 0
        LastSettingsHash        = ""
        UpdatedUtc              = $null
    }
}

function Load-RollbackState {
    $state = New-RollbackStateDefault
    if (-not $script:RollbackStatePath -or -not (Test-Path $script:RollbackStatePath)) { return $state }
    try {
        $loaded = Read-JsonFileSecure $script:RollbackStatePath 65536 "Rollback state"
        if ($loaded -and ($loaded.PSObject.Properties.Name -contains "HighestVersion")) {
            $state.HighestVersion = [string]$loaded.HighestVersion
        }
        if ($loaded -and ($loaded.PSObject.Properties.Name -contains "HighestSettingsSequence")) {
            $state.HighestSettingsSequence = [Math]::Max(0, [int]$loaded.HighestSettingsSequence)
        }
        if ($loaded -and ($loaded.PSObject.Properties.Name -contains "LastSettingsHash")) {
            $state.LastSettingsHash = [string]$loaded.LastSettingsHash
        }
        if ($loaded -and ($loaded.PSObject.Properties.Name -contains "UpdatedUtc")) {
            $state.UpdatedUtc = [string]$loaded.UpdatedUtc
        }
    } catch { Write-IgnoredCatch $_ }
    return $state
}

function Save-RollbackState($state) {
    if (-not $state) { return }
    try {
        Ensure-Directory $script:MetaDir "Meta" | Out-Null
        $payload = [pscustomobject]@{
            HighestVersion          = [string]$state.HighestVersion
            HighestSettingsSequence = [int]$state.HighestSettingsSequence
            LastSettingsHash        = [string]$state.LastSettingsHash
            UpdatedUtc              = (Get-Date).ToUniversalTime().ToString("o")
        }
        $json = $payload | ConvertTo-Json -Depth 4
        Write-AtomicTextFile -Path $script:RollbackStatePath -Content $json -Encoding UTF8 -VerifyJson
    } catch { Write-IgnoredCatch $_ }
}

function Get-SettingsSequenceValue($settings, [int]$default = 0) {
    if (-not $settings) { return $default }
    $raw = Get-SettingsPropertyValue $settings "SettingsSequence"
    if ($null -eq $raw) { return $default }
    $parsed = $default
    if ([int]::TryParse([string]$raw, [ref]$parsed)) {
        return [Math]::Max(0, $parsed)
    }
    return $default
}

function Test-RollbackProtectionState($settings) {
    if (-not $script:RollbackState) {
        $script:RollbackState = Load-RollbackState
    }
    $state = $script:RollbackState
    $highestVersion = if ($state -and $state.ContainsKey("HighestVersion")) { [string]$state.HighestVersion } else { "" }
    $highestSequence = if ($state -and $state.ContainsKey("HighestSettingsSequence")) { [int]$state.HighestSettingsSequence } else { 0 }
    $settingsSequence = Get-SettingsSequenceValue $settings 0
    $versionRollback = $false
    if (-not [string]::IsNullOrWhiteSpace($highestVersion)) {
        $versionRollback = ((Compare-AppVersion $appVersion $highestVersion) -lt 0)
    }
    $settingsRollback = ($highestSequence -gt 0 -and $settingsSequence -lt $highestSequence)
    return [pscustomobject]@{
        VersionRollbackDetected  = $versionRollback
        SettingsRollbackDetected = $settingsRollback
        HighestVersion           = $highestVersion
        HighestSettingsSequence  = $highestSequence
        SettingsSequence         = $settingsSequence
    }
}

function Update-RollbackStateFromSettings($settings) {
    if (-not $settings) { return }
    if (-not $script:RollbackState) {
        $script:RollbackState = Load-RollbackState
    }
    $state = $script:RollbackState
    $updated = $false
    $seq = Get-SettingsSequenceValue $settings 0
    if ($seq -gt [int]$state.HighestSettingsSequence) {
        $state.HighestSettingsSequence = $seq
        $updated = $true
    }
    $versionCmp = Compare-AppVersion $appVersion ([string]$state.HighestVersion)
    if ($versionCmp -gt 0 -or [string]::IsNullOrWhiteSpace([string]$state.HighestVersion)) {
        $state.HighestVersion = [string]$appVersion
        $updated = $true
    }
    try {
        $snapshot = Get-SettingsSnapshot $settings
        $state.LastSettingsHash = Get-SettingsSnapshotHash $snapshot
        $updated = $true
    } catch { Write-IgnoredCatch $_ }
    if ($updated) {
        Save-RollbackState $state
        $script:RollbackState = $state
    }
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
        $safeDetail = if ($detail) { Redact-SensitiveText $detail } else { $null }
        if ($safeDetail) { $parts += "Detail=$safeDetail" }
        if (-not $script:AuditChainLastHash) { $script:AuditChainLastHash = "GENESIS" }
        if ($script:AuditChainLastHash -eq "GENESIS") { Load-AuditChainState }
        $payloadText = ("{0}|{1}|{2}|{3}|{4}" -f $timestamp, $action, $context, $actionId, $safeDetail)
        $prevHash = if ($script:AuditChainLastHash) { [string]$script:AuditChainLastHash } else { "GENESIS" }
        $entryHash = Get-StringSha256Hex ("{0}|{1}" -f $prevHash, $payloadText)
        $parts += "PrevHash=$prevHash"
        $parts += "Hash=$entryHash"
        Add-Content -Path $script:AuditLogPath -Value ($parts -join " ")
        $script:AuditChainLastHash = $entryHash
        Save-AuditChainState
    } catch { Write-IgnoredCatch $_ }
}

function Write-SecurityAuditEvent([string]$eventName, [string]$detail = $null, [string]$level = "WARN", [string]$context = "Security") {
    if (-not $script:SecurityAuditEnabled) { return }
    if ([string]::IsNullOrWhiteSpace($eventName)) { return }
    $normalizedLevel = if ([string]::IsNullOrWhiteSpace($level)) { "WARN" } else { $level.ToUpperInvariant() }
    if (-not $script:LogLevels.ContainsKey($normalizedLevel)) { $normalizedLevel = "WARN" }
    $safeDetail = if ($detail) { Redact-SensitiveText $detail } else { $null }
    try {
        Ensure-LogDirectoryWritable
        if (-not $script:SecurityAuditLogPath) {
            $script:SecurityAuditLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.security.log"
        }
        if (-not $script:SecurityAuditChainLastHash) { $script:SecurityAuditChainLastHash = "GENESIS" }
        if ($script:SecurityAuditChainLastHash -eq "GENESIS") { Load-SecurityAuditChainState }
        $timestamp = Format-DateTime (Get-Date)
        $parts = @("[${timestamp}]", "[$normalizedLevel]", "[SECURITY]", "Event=$eventName")
        if ($context) { $parts += "Context=$context" }
        if ($safeDetail) { $parts += ("Detail={0}" -f $safeDetail) }
        $payloadText = ("{0}|{1}|{2}|{3}|{4}" -f $timestamp, $normalizedLevel, $eventName, $context, $safeDetail)
        $prevHash = if ($script:SecurityAuditChainLastHash) { [string]$script:SecurityAuditChainLastHash } else { "GENESIS" }
        $payloadHash = Get-StringSha256Hex $payloadText
        $entryHash = Get-StringSha256Hex ("{0}|{1}" -f $prevHash, $payloadHash)
        $parts += "PrevHash=$prevHash"
        $parts += "PayloadHash=$payloadHash"
        $parts += "Hash=$entryHash"
        Add-Content -Path $script:SecurityAuditLogPath -Value ($parts -join " ")
        $script:SecurityAuditChainLastHash = $entryHash
        Save-SecurityAuditChainState
        $script:SecurityAuditWriteCount = [int]$script:SecurityAuditWriteCount + 1
        if (-not $script:SecurityAuditVerifyInProgress -and $script:SecurityAuditWriteCount -ge ([Math]::Max(1, [int]$script:SecurityAuditVerifyEveryN))) {
            $script:SecurityAuditVerifyInProgress = $true
            try {
                if (-not (Test-SecurityAuditLogChain -tailLines 500)) {
                    Write-Log "Security audit log chain verification failed." "WARN" $null "Security"
                }
            } finally {
                $script:SecurityAuditWriteCount = 0
                $script:SecurityAuditVerifyInProgress = $false
            }
        }
    } catch { Write-IgnoredCatch $_ }
    try {
        Write-AuditLog ("Security:{0}" -f $eventName) $context $script:LastUserActionId $detail
    } catch { Write-IgnoredCatch $_ }
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

function Add-SelfHealRecentAction([string]$name, [string]$status, [string]$detail = "") {
    if ([string]::IsNullOrWhiteSpace($name)) { return }
    if ([string]::IsNullOrWhiteSpace($status)) { $status = "Info" }
    if (-not $script:SelfHealRecentActions) {
        $script:SelfHealRecentActions = New-Object System.Collections.ArrayList
    }
    $entry = [pscustomobject]@{
        Time   = Get-Date
        Name   = [string]$name
        Status = [string]$status
        Detail = [string]$detail
    }
    [void]$script:SelfHealRecentActions.Add($entry)
    $max = [Math]::Max(10, [int]$script:SelfHealRecentActionsMax)
    while ($script:SelfHealRecentActions.Count -gt $max) {
        $script:SelfHealRecentActions.RemoveAt(0) | Out-Null
    }
}

function Get-SelfHealRecentActionLines {
    $lines = New-Object System.Collections.Generic.List[string]
    if (-not $script:SelfHealRecentActions -or $script:SelfHealRecentActions.Count -eq 0) {
        $lines.Add("  None")
        return $lines
    }
    foreach ($entry in $script:SelfHealRecentActions) {
        $time = Format-DateTime $entry.Time
        $detail = if ([string]::IsNullOrWhiteSpace([string]$entry.Detail)) { "" } else { " - $([string]$entry.Detail)" }
        $lines.Add(("  {0} [{1}] {2}{3}" -f $time, [string]$entry.Status, [string]$entry.Name, $detail))
    }
    return $lines
}

function Test-SelfHealQueueThreshold([string]$key, [int]$windowSeconds = 300, [int]$maxEvents = 6) {
    if ([string]::IsNullOrWhiteSpace($key)) { return $true }
    $windowSeconds = [Math]::Max(30, $windowSeconds)
    $maxEvents = [Math]::Max(1, $maxEvents)
    if (-not $script:SelfHealActionThrottle) { $script:SelfHealActionThrottle = @{} }
    $now = Get-Date
    $entry = $null
    if ($script:SelfHealActionThrottle.ContainsKey($key)) {
        $entry = $script:SelfHealActionThrottle[$key]
    }
    if (-not $entry) {
        $entry = [pscustomobject]@{
            WindowStart = $now
            Count       = 0
        }
        $script:SelfHealActionThrottle[$key] = $entry
    }
    if (-not $entry.WindowStart -or (($now - $entry.WindowStart).TotalSeconds -ge $windowSeconds)) {
        $entry.WindowStart = $now
        $entry.Count = 0
    }
    if ([int]$entry.Count -ge $maxEvents) {
        $script:SelfHealStats.QueueSuppressedCount = [int]$script:SelfHealStats.QueueSuppressedCount + 1
        return $false
    }
    $entry.Count = [int]$entry.Count + 1
    return $true
}

function Start-SelfHealQueueTimer {
    if ($script:SelfHealActionTimer) { return }
    $script:SelfHealActionTimer = New-Object System.Windows.Forms.Timer
    $script:SelfHealActionTimer.Interval = 1000
    $script:SelfHealActionTimer.Add_Tick({
        Invoke-SafeTimerAction "SelfHealActionTimer" {
            if ($script:isShuttingDown -or $script:CleanupDone) {
                if ($script:SelfHealActionTimer) { $script:SelfHealActionTimer.Stop() }
                return
            }
            Invoke-SelfHealQueue
        }
    })
    $script:SelfHealActionTimer.Start()
}

function Stop-SelfHealQueueTimer {
    if (-not $script:SelfHealActionTimer) { return }
    try { $script:SelfHealActionTimer.Stop() } catch { Write-IgnoredCatch $_ }
    try { $script:SelfHealActionTimer.Dispose() } catch { Write-IgnoredCatch $_ }
    $script:SelfHealActionTimer = $null
}

function Enqueue-SelfHealAction {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$Action,
        [string]$Reason = "",
        [int]$InitialDelaySeconds = 1,
        [int]$MaxAttempts = 3,
        [int]$WindowSeconds = 300,
        [int]$MaxPerWindow = 6,
        [switch]$AllowDuplicate
    )
    if ($script:isShuttingDown -or $script:CleanupDone) { return $false }
    if (-not $script:SelfHealActionQueue) {
        $script:SelfHealActionQueue = New-Object System.Collections.ArrayList
    }
    if (-not $AllowDuplicate) {
        $existing = @($script:SelfHealActionQueue | Where-Object { $_.Name -eq $Name -and $_.Reason -eq $Reason })
        if ($existing.Count -gt 0) { return $false }
    }
    if (-not (Test-SelfHealQueueThreshold -key ("Queue:{0}" -f $Name) -windowSeconds $WindowSeconds -maxEvents $MaxPerWindow)) {
        Add-SelfHealRecentAction $Name "Suppressed" "Queue threshold reached"
        Write-LogThrottled ("SelfHeal-QueueSuppressed-{0}" -f $Name) ("Self-heal queue suppressed for {0} (threshold reached)." -f $Name) "WARN" 60
        return $false
    }
    while ($script:SelfHealActionQueue.Count -ge [Math]::Max(10, [int]$script:SelfHealActionQueueMax)) {
        $script:SelfHealActionQueue.RemoveAt(0) | Out-Null
    }
    $delay = [Math]::Max(0, $InitialDelaySeconds)
    $item = [pscustomobject]@{
        Id         = [Guid]::NewGuid().ToString("N")
        Name       = $Name
        Reason     = [string]$Reason
        Action     = $Action
        Attempts   = 0
        MaxAttempts = [Math]::Max(1, $MaxAttempts)
        CreatedUtc = [DateTime]::UtcNow
        NextRunUtc = [DateTime]::UtcNow.AddSeconds($delay)
    }
    [void]$script:SelfHealActionQueue.Add($item)
    Add-SelfHealRecentAction $Name "Queued" $Reason
    Start-SelfHealQueueTimer
    return $true
}

function Invoke-SelfHealQueue([switch]$Force) {
    if (-not $script:SelfHealActionQueue -or $script:SelfHealActionQueue.Count -eq 0) { return }
    if ($script:isShuttingDown -or $script:CleanupDone) { return }
    $nowUtc = [DateTime]::UtcNow
    $snapshot = @($script:SelfHealActionQueue)
    foreach ($item in $snapshot) {
        if (-not $item) { continue }
        if (-not $Force -and $item.NextRunUtc -gt $nowUtc) { continue }
        for ($idx = $script:SelfHealActionQueue.Count - 1; $idx -ge 0; $idx--) {
            if ($script:SelfHealActionQueue[$idx].Id -eq $item.Id) {
                $script:SelfHealActionQueue.RemoveAt($idx) | Out-Null
                break
            }
        }
        try {
            Add-SelfHealRecentAction $item.Name "Started" $item.Reason
            & $item.Action
            if ($item.Name -like "Timer:*") {
                $script:SelfHealStats.TimerRecoverySuccess = [int]$script:SelfHealStats.TimerRecoverySuccess + 1
            }
            Add-SelfHealRecentAction $item.Name "Succeeded" $item.Reason
            Write-LogThrottled ("SelfHeal-Succeeded-{0}" -f $item.Name) ("Self-heal succeeded: {0}" -f $item.Name) "INFO" 20
        } catch {
            $attempts = [int]$item.Attempts + 1
            $item.Attempts = $attempts
            $message = [string]$_.Exception.Message
            if ($attempts -lt [int]$item.MaxAttempts) {
                $delaySeconds = [Math]::Max(1, [int]($script:SelfHealBackoffBaseSeconds * [Math]::Pow(2, $attempts - 1)))
                $item.NextRunUtc = [DateTime]::UtcNow.AddSeconds($delaySeconds)
                [void]$script:SelfHealActionQueue.Add($item)
                Add-SelfHealRecentAction $item.Name "Retry" ("Attempt {0}/{1}: {2}" -f $attempts, $item.MaxAttempts, $message)
                Write-LogThrottled ("SelfHeal-Retry-{0}" -f $item.Name) ("Self-heal retry scheduled for {0} in {1}s (attempt {2}/{3})." -f $item.Name, $delaySeconds, $attempts, $item.MaxAttempts) "WARN" 20
            } else {
                if ($item.Name -like "Timer:*") {
                    $script:SelfHealStats.TimerRecoveryFailed = [int]$script:SelfHealStats.TimerRecoveryFailed + 1
                }
                Add-SelfHealRecentAction $item.Name "Failed" $message
                Write-LogExceptionDeduped ("Self-heal failed permanently: {0}" -f $item.Name) "ERROR" $_.Exception "SelfHeal" 20
            }
        }
    }
}

function Invoke-TimerSelfHeal([string]$TimerName) {
    if ([string]::IsNullOrWhiteSpace($TimerName)) { return $false }
    $timerMap = @{
        MainToggleTimer           = "timer"
        StatusUpdateTimer         = "statusUpdateTimer"
        PauseTimer                = "pauseTimer"
        WatchdogTimer             = "watchdogTimer"
        SaveSettingsTimer         = "SaveSettingsTimer"
        StatusUpdateDebounceTimer = "StatusUpdateDebounceTimer"
        LogFlushTimer             = "LogFlushTimer"
        DeferredMaintenanceTimer  = "DeferredMaintenanceTimer"
        SettingsStatusTimer       = "SettingsStatusTimer"
        HealthMonitorTimer        = "HealthMonitorTimer"
        DeferredStartupTimer      = "DeferredStartupTimer"
        FolderCheckTimer          = "FolderCheckTimer"
        PostShowStatusTimer       = "PostShowStatusTimer"
    }
    if ($TimerName -eq "HealthMonitorTimer" -and (-not (Get-Variable -Name HealthMonitorTimer -Scope Script -ErrorAction SilentlyContinue))) {
        try {
            Start-HealthMonitor
            $script:SelfHealStats.HeartbeatRecoveries = [int]$script:SelfHealStats.HeartbeatRecoveries + 1
            return $true
        } catch {
            Write-LogExceptionDeduped "Health monitor self-heal failed." "WARN" $_.Exception "SelfHeal" 30
            return $false
        }
    }
    $varName = if ($timerMap.ContainsKey($TimerName)) { [string]$timerMap[$TimerName] } else { [string]$TimerName }
    $timerVar = Get-Variable -Name $varName -Scope Script -ErrorAction SilentlyContinue
    if (-not $timerVar -or -not $timerVar.Value) {
        Write-LogThrottled ("SelfHeal-TimerMissing-{0}" -f $TimerName) ("Self-heal could not find timer variable for {0}." -f $TimerName) "WARN" 30
        return $false
    }
    $timer = $timerVar.Value
    if (-not ($timer -is [System.Windows.Forms.Timer])) { return $false }
    try {
        try { $timer.Stop() } catch { Write-IgnoredCatch $_ }
        $timer.Start()
        $script:ComponentHeartbeat[$TimerName] = Get-Date
        $script:SelfHealStats.HeartbeatRecoveries = [int]$script:SelfHealStats.HeartbeatRecoveries + 1
        return $true
    } catch {
        Write-LogExceptionDeduped ("Timer self-heal failed for {0}." -f $TimerName) "WARN" $_.Exception "SelfHeal" 30
        return $false
    }
}

function Request-TimerSelfHeal {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TimerName,
        [string]$Reason = "Timer handler failure"
    )
    if ([string]::IsNullOrWhiteSpace($TimerName)) { return $false }
    $timerNameCopy = [string]$TimerName
    $reasonCopy = [string]$Reason
    $queued = Enqueue-SelfHealAction -Name ("Timer:{0}" -f $timerNameCopy) -Reason $reasonCopy -InitialDelaySeconds 2 -MaxAttempts 4 -WindowSeconds 300 -MaxPerWindow 6 -Action {
        Invoke-TimerSelfHeal -TimerName $timerNameCopy | Out-Null
    }
    if ($queued) {
        $script:SelfHealStats.TimerRecoveryQueued = [int]$script:SelfHealStats.TimerRecoveryQueued + 1
    }
    return $queued
}

function Invoke-HeartbeatWatchdog([switch]$Force) {
    if (-not $script:ComponentHeartbeatThresholdSeconds) { return }
    $now = Get-Date
    foreach ($component in @($script:ComponentHeartbeatThresholdSeconds.Keys)) {
        $threshold = [Math]::Max(5, [int]$script:ComponentHeartbeatThresholdSeconds[$component])
        $heartbeat = $null
        if ($script:ComponentHeartbeat.ContainsKey($component)) {
            $heartbeat = $script:ComponentHeartbeat[$component]
        }
        if (-not $Force) {
            if (-not $heartbeat) {
                $uptimeSeconds = 0
                if ($script:AppStartTime) {
                    $uptimeSeconds = [int]((Get-Date) - $script:AppStartTime).TotalSeconds
                }
                if ($uptimeSeconds -lt ($threshold * 2)) { continue }
            } elseif (($now - $heartbeat).TotalSeconds -lt $threshold) {
                continue
            }
        }
        if (Request-TimerSelfHeal -TimerName $component -Reason "Heartbeat stale") {
            Write-LogThrottled ("SelfHeal-Heartbeat-{0}" -f $component) ("Heartbeat watchdog queued self-heal for {0}." -f $component) "WARN" 30
        }
        $script:ComponentHeartbeat[$component] = $now
    }
}

function Invoke-RepairAll([string]$Source = "manual") {
    if ($script:isShuttingDown -or $script:CleanupDone) { return $false }
    $script:SelfHealStats.RepairAllRuns = [int]$script:SelfHealStats.RepairAllRuns + 1
    Add-SelfHealRecentAction "RepairAll" "Started" ("Source={0}" -f $Source)
    $completed = @()
    try {
        try { Flush-SettingsSave; $completed += "Flushed pending settings save" } catch { Write-IgnoredCatch $_ }
        try { Validate-RequiredFiles; $completed += "Validated required files" } catch { Write-IgnoredCatch $_ }
        try { Start-RepairMode; $completed += "Applied repair mode snapshot recovery" } catch { Write-IgnoredCatch $_ }
        try { [void](Ensure-SettingsUiLoaded); $completed += "Validated Settings UI module" } catch { Write-IgnoredCatch $_ }
        try { [void](Ensure-HistoryUiLoaded); $completed += "Validated History UI module" } catch { Write-IgnoredCatch $_ }
        foreach ($component in @("WatchdogTimer", "PauseTimer", "HealthMonitorTimer", "LogFlushTimer", "StatusUpdateDebounceTimer")) {
            try {
                if (Invoke-TimerSelfHeal -TimerName $component) {
                    $completed += ("Restarted {0}" -f $component)
                }
            } catch { Write-IgnoredCatch $_ }
        }
        try { Invoke-HeartbeatWatchdog -Force } catch { Write-IgnoredCatch $_ }
        try { Invoke-SelfHealQueue -Force } catch { Write-IgnoredCatch $_ }
        try { Request-StatusUpdate } catch { Write-IgnoredCatch $_ }
        try { Update-StatusText } catch { Write-IgnoredCatch $_ }
        try { if (Get-Command Update-TrayLabels -ErrorAction SilentlyContinue) { Update-TrayLabels } } catch { Write-IgnoredCatch $_ }

        $summary = if ($completed.Count -gt 0) { ($completed -join "; ") } else { "No repair actions were required." }
        Add-SelfHealRecentAction "RepairAll" "Completed" $summary
        Write-Log ("Repair all completed (source={0}): {1}" -f $Source, $summary) "INFO" $null "Recovery"
        try {
            Show-Balloon "Teams-Always-Green" "Repair all completed." ([System.Windows.Forms.ToolTipIcon]::Info)
        } catch { Write-IgnoredCatch $_ }
        return $true
    } catch {
        Add-SelfHealRecentAction "RepairAll" "Failed" $_.Exception.Message
        Write-LogExceptionDeduped ("Repair all failed (source={0})." -f $Source) "ERROR" $_.Exception "Recovery" 20
        return $false
    }
}

function Test-SettingsStateIntegrity {
    try {
        if (-not $script:AppState) { return $true }
        $stateHash = $null
        if ($script:AppState.PSObject.Properties.Name -contains "SettingsHash") {
            $stateHash = [string]$script:AppState.SettingsHash
        }
        if ([string]::IsNullOrWhiteSpace($stateHash)) { return $true }
        $currentHash = Get-SettingsFileHash
        if ([string]::IsNullOrWhiteSpace($currentHash)) { return $true }
        return ($currentHash -eq $stateHash)
    } catch {
        return $true
    }
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
        ("Message={0}" -f (Redact-SensitiveText ([string]$ex.Message)))
    )
    if ($ex.InnerException) {
        $lines += "InnerExceptionType=$($ex.InnerException.GetType().FullName)"
        $lines += ("InnerMessage={0}" -f (Redact-SensitiveText ([string]$ex.InnerException.Message)))
    }
    $includeStack = $false
    if (Get-Variable -Name settings -Scope Script -ErrorAction SilentlyContinue) {
        if ($settings -and ($settings.PSObject.Properties.Name -contains "LogIncludeStackTrace")) {
            $includeStack = [bool]$settings.LogIncludeStackTrace
        }
    }
    if ($ex.StackTrace -and $includeStack) {
        $lines += ("StackTrace={0}" -f (Redact-SensitiveText ([string]$ex.StackTrace)))
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
        try { $hresult = $exception.HResult } catch { Write-IgnoredCatch $_ }
        try { $win32 = [Runtime.InteropServices.Marshal]::GetLastWin32Error() } catch { Write-IgnoredCatch $_ }
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
        Write-IgnoredCatch $_
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
                } catch { Write-IgnoredCatch $_ }
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
            } catch { Write-IgnoredCatch $_ }
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
            try { Add-Content -Path $script:FallbackLogPath -Value $lines } catch { Write-IgnoredCatch $_ }
        }
    } catch {
        # Ignore flush errors.
        Write-IgnoredCatch $_
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
        } catch { Write-IgnoredCatch $_ }
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
        } catch { Write-IgnoredCatch $_ }
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
    $lines += "Self-Healing:"
    $queueDepth = if ($script:SelfHealActionQueue) { @($script:SelfHealActionQueue).Count } else { 0 }
    $lines += "  Queue Depth: $queueDepth"
    $lines += "  Repair-All Runs: $([int]$script:SelfHealStats.RepairAllRuns)"
    $lines += "  Heartbeat Recoveries: $([int]$script:SelfHealStats.HeartbeatRecoveries)"
    $lines += "  Timer Recoveries: queued=$([int]$script:SelfHealStats.TimerRecoveryQueued) succeeded=$([int]$script:SelfHealStats.TimerRecoverySuccess) failed=$([int]$script:SelfHealStats.TimerRecoveryFailed)"
    $lines += "  Queue Suppressed: $([int]$script:SelfHealStats.QueueSuppressedCount)"
    $lines += "  Recent Auto-Repairs:"
    $lines += (Get-SelfHealRecentActionLines)
    $lines += ""
    $lines += "Date/Time Format: " + $(if ($settings.UseSystemDateTimeFormat) { "System ($($settings.SystemDateTimeFormatMode))" } else { [string]$settings.DateTimeFormat })
    if ($settings.ScrubDiagnostics) {
        $lines = Scrub-LogLines $lines
    }
    $lines | Set-Content -Path $targetPath -Encoding UTF8
    return $targetPath
}

function Export-SupportBundle([string]$outputPath) {
    if ([string]::IsNullOrWhiteSpace($outputPath)) { return $null }
    $tempRoot = Join-Path $env:TEMP ("TeamsAlwaysGreen.support." + [Guid]::NewGuid().ToString("N"))
    $bundleRoot = Join-Path $tempRoot "bundle"
    try {
        New-Item -ItemType Directory -Path $bundleRoot -Force | Out-Null
        $diagnosticsPath = Join-Path $bundleRoot "diagnostics.txt"
        Write-DiagnosticsReport $diagnosticsPath | Out-Null

        $recentLogPath = Join-Path $bundleRoot "recent-log.txt"
        $recentLines = @()
        if (Test-Path $logPath) {
            $recentLines = @(Get-Content -Path $logPath -Tail 500 -ErrorAction SilentlyContinue)
        } else {
            $recentLines = @("Log file not found.")
        }
        if ($settings.ScrubDiagnostics) { $recentLines = @(Scrub-LogLines $recentLines) }
        $recentLines | Set-Content -Path $recentLogPath -Encoding UTF8

        $filesToCopy = @(
            @{ Source = $logPath; Target = "Teams-Always-Green.log" },
            @{ Source = $script:AuditLogPath; Target = "Teams-Always-Green.audit.log" },
            @{ Source = $script:SecurityAuditLogPath; Target = "Teams-Always-Green.security.log" },
            @{ Source = $script:BootstrapLogPath; Target = "Teams-Always-Green.bootstrap.log" },
            @{ Source = $script:settingsPath; Target = "Teams-Always-Green.settings.json" },
            @{ Source = $script:StatePath; Target = "Teams-Always-Green.state.json" }
        )
        foreach ($entry in $filesToCopy) {
            $src = [string]$entry.Source
            if ([string]::IsNullOrWhiteSpace($src) -or -not (Test-Path $src)) { continue }
            $dst = Join-Path $bundleRoot ([string]$entry.Target)
            if ($settings.ScrubDiagnostics -and ($dst -like "*.log" -or $dst -like "*.json")) {
                try {
                    $raw = Get-Content -Path $src -Raw -ErrorAction Stop
                    $clean = Scrub-LogText $raw
                    Set-Content -Path $dst -Value $clean -Encoding UTF8
                } catch {
                    Copy-Item -Path $src -Destination $dst -Force
                }
            } else {
                Copy-Item -Path $src -Destination $dst -Force
            }
        }

        $metaPath = Join-Path $bundleRoot "bundle-info.txt"
        $metaLines = @(
            "Teams-Always-Green Support Bundle",
            ("Generated: {0}" -f (Format-DateTime (Get-Date))),
            ("Version: {0}" -f $appVersion),
            ("Build: {0}" -f $appBuildId),
            ("Last Updated: {0}" -f $appLastUpdated),
            ("Script Path: {0}" -f $scriptPath),
            ("Log Directory: {0}" -f $script:LogDirectory),
            ("Settings Directory: {0}" -f $script:SettingsDirectory),
            ("Scrub Diagnostics: {0}" -f [bool]$settings.ScrubDiagnostics)
        )
        $metaLines | Set-Content -Path $metaPath -Encoding UTF8

        $destDir = Split-Path -Parent $outputPath
        if (-not [string]::IsNullOrWhiteSpace($destDir) -and -not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }

        if (Test-Path $outputPath) { Remove-Item -Path $outputPath -Force -ErrorAction SilentlyContinue }
        Compress-Archive -Path (Join-Path $bundleRoot "*") -DestinationPath $outputPath -CompressionLevel Optimal -Force
        Write-Log ("Support bundle exported to {0}" -f $outputPath) "INFO" $null "Diagnostics"
        return $outputPath
    } catch {
        Write-Log ("Support bundle export failed: {0}" -f $_.Exception.Message) "ERROR" $_.Exception "Diagnostics"
        return $null
    } finally {
        try { if (Test-Path $tempRoot) { Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue } } catch { Write-IgnoredCatch $_ }
    }
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
    $script:SecurityAuditLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.security.log"
    try {
        $locatorValue = Convert-ToRelativePathIfUnderRoot $script:LogDirectory
        Set-Content -Path $script:LogLocatorPath -Value $locatorValue -Encoding ASCII
    } catch { Write-IgnoredCatch $_ }
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
    $message = Redact-SensitiveText $message
    if (-not $script:LogLevels.ContainsKey($script:LogLevel)) {
        $script:LogLevel = "INFO"
    }
    $category = Get-LogCategory $context
    $eventId = Get-LogEventId $context $levelKey $message
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
        if ($eventId) { $parts += "[E=$eventId]" }
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
                $parts += "[A=$($script:LastUserActionId)]"
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

Load-SecurityAuditChainState
if (-not (Test-SecurityAuditLogChain -tailLines 400)) {
    Write-Log "Security audit chain verification failed on startup." "WARN" $null "Security"
}

# --- Log/settings directory management (validate/repair) ---
function Set-LogDirectory([string]$directory, [switch]$SkipLog) {
    $desired = Convert-FromRelativePath $directory
    $allowExternal = $false
    try {
        if (Get-Variable -Name settings -Scope Script -ErrorAction SilentlyContinue) {
            $allowExternal = [bool]$script:settings.AllowExternalPaths
        }
    } catch { Write-IgnoredCatch $_ }
    $resolved = Resolve-DirectoryOrDefault $directory $defaultLogDir "Logs" $allowExternal
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
    $script:SecurityAuditLogPath = Join-Path $script:LogDirectory "Teams-Always-Green.security.log"

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
    $allowExternal = $false
    try {
        if (Get-Variable -Name settings -Scope Script -ErrorAction SilentlyContinue) {
            $allowExternal = [bool]$script:settings.AllowExternalPaths
        }
    } catch { Write-IgnoredCatch $_ }
    $resolved = Resolve-DirectoryOrDefault $directory $defaultSettingsDir "Settings" $allowExternal
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
    if (-not (Test-ImportExportFilePath -path $settingsPath -label "Settings load" -allowedExtensions @(".json") -RequireExists -MaxBytes ([int64]$script:SettingsMaxBytes) -Context "Settings-Load")) {
        Write-Log "Settings load blocked by security path policy." "ERROR" $null "Settings-Load"
        return $null
    }
    try {
        $info = Get-Item -LiteralPath $settingsPath -ErrorAction Stop
        if ([int64]$info.Length -gt [int64]$script:SettingsMaxBytes) {
            throw ("Settings file exceeds max size ({0} bytes)." -f $script:SettingsMaxBytes)
        }
        $raw = Get-Content -Path $settingsPath -Raw
        $loaded = $raw | ConvertFrom-Json
        $strictSchema = $false
        if ($loaded -and ($loaded.PSObject.Properties.Name -contains "SecurityModeEnabled") -and [bool]$loaded.SecurityModeEnabled) { $strictSchema = $true }
        if ($loaded -and ($loaded.PSObject.Properties.Name -contains "StrictSettingsImport") -and [bool]$loaded.StrictSettingsImport) { $strictSchema = $true }
        $validation = Test-SettingsSchema $loaded -Strict:$strictSchema
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
        $script:SettingsExtraFields = if ($strictSchema) { @{} } else { Get-SettingsExtraFields $loaded }
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
        Add-SelfHealRecentAction "LoadSettings" "Failed" $_.Exception.Message
        try {
            $rawFallback = if (Test-Path $settingsPath) { Get-Content -Path $settingsPath -Raw } else { "" }
            Save-CorruptSettingsCopy $rawFallback
        } catch { Write-IgnoredCatch $_ }
        $lastGood = Load-LastGoodSettings
        if ($lastGood) {
            $strictSchema = $false
            if ($lastGood -and ($lastGood.PSObject.Properties.Name -contains "SecurityModeEnabled") -and [bool]$lastGood.SecurityModeEnabled) { $strictSchema = $true }
            if ($lastGood -and ($lastGood.PSObject.Properties.Name -contains "StrictSettingsImport") -and [bool]$lastGood.StrictSettingsImport) { $strictSchema = $true }
            $validation = Test-SettingsSchema $lastGood -Strict:$strictSchema
            $script:SettingsLoadIssues = $validation.Issues
            $script:SettingsFutureVersion = $validation.FutureVersion
            $script:SettingsExtraFields = if ($strictSchema) { @{} } else { Get-SettingsExtraFields $lastGood }
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
    } catch { Write-IgnoredCatch $_ }
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
    } catch { Write-IgnoredCatch $_ }
    if ($deleted -gt 0) {
        Write-Log ("Purged {0} old settings backups." -f $deleted) "DEBUG" $null "Settings"
    }
}

function Save-SettingsVersionSnapshot([string]$settingsJson, [int]$sequence) {
    if ([string]::IsNullOrWhiteSpace($settingsJson)) { return }
    try {
        Ensure-Directory $script:SettingsVersionsDir "Meta" | Out-Null
        $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
        $safeSequence = [Math]::Max(0, [int]$sequence)
        $fileName = "Teams-Always-Green.settings.v{0}.{1}.json" -f $safeSequence, $stamp
        $target = Join-Path $script:SettingsVersionsDir $fileName
        Write-AtomicTextFile -Path $target -Content $settingsJson -Encoding UTF8 -VerifyJson
        $keep = [Math]::Max(5, [int]$script:SettingsVersionRetentionCount)
        $files = @(Get-ChildItem -Path $script:SettingsVersionsDir -Filter "Teams-Always-Green.settings.v*.json" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        if ($files.Count -gt $keep) {
            foreach ($old in @($files | Select-Object -Skip $keep)) {
                try { Remove-Item -Path $old.FullName -Force -ErrorAction SilentlyContinue } catch { Write-IgnoredCatch $_ }
            }
        }
    } catch {
        Write-Log "Failed to write versioned settings snapshot." "WARN" $_.Exception "Settings-Version"
    }
}

function Get-SettingsVersionSnapshotFiles {
    try {
        if (-not (Test-Path $script:SettingsVersionsDir)) { return @() }
        return @(Get-ChildItem -Path $script:SettingsVersionsDir -Filter "Teams-Always-Green.settings.v*.json" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    } catch {
        return @()
    }
}

function Load-SettingsFromVersionSnapshot([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return $null }
    if (-not (Test-Path $path)) { return $null }
    if (-not (Test-TrustedFilePath -path $path -root $script:SettingsVersionsDir -tag "Settings-Version" -label "Settings version snapshot" -RequireExists)) {
        Write-Log "Settings version snapshot load blocked by security path policy." "WARN" $null "Settings-Version"
        return $null
    }
    try {
        $raw = Get-Content -Path $path -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        $loaded = $raw | ConvertFrom-Json
        $loaded = Migrate-Settings $loaded
        $validated = Validate-SettingsForSave $loaded
        $normalized = Normalize-Settings $validated.Settings
        Ensure-StockProfiles $normalized | Out-Null
        return $normalized
    } catch {
        Write-Log "Failed to load settings version snapshot." "ERROR" $_.Exception "Settings-Version"
        return $null
    }
}

function Restore-SettingsFromVersionSnapshot([string]$path = $null) {
    try {
        $targetPath = $path
        if ([string]::IsNullOrWhiteSpace($targetPath)) {
            $snapshots = Get-SettingsVersionSnapshotFiles
            if ($snapshots.Count -eq 0) {
                return [pscustomobject]@{ Success = $false; Message = "No settings snapshots are available."; Path = $null }
            }
            if ($snapshots.Count -gt 1) {
                $targetPath = $snapshots[1].FullName
            } else {
                $targetPath = $snapshots[0].FullName
            }
        }
        $restored = Load-SettingsFromVersionSnapshot $targetPath
        if (-not $restored) {
            return [pscustomobject]@{ Success = $false; Message = "Failed to load selected settings snapshot."; Path = $targetPath }
        }

        $script:settings = $restored
        $settings = $script:settings
        Sync-SettingsReference $settings
        Apply-SettingsRuntime
        Save-SettingsImmediate $settings
        try { Refresh-TrayMenu } catch { Write-IgnoredCatch $_ }
        try { Request-StatusUpdate } catch { Write-IgnoredCatch $_ }

        Write-Log ("Restored settings from snapshot: {0}" -f $targetPath) "INFO" $null "Settings-Version"
        return [pscustomobject]@{ Success = $true; Message = "Settings restored from snapshot."; Path = $targetPath }
    } catch {
        Write-Log "Failed to restore settings from snapshot." "ERROR" $_.Exception "Settings-Version"
        return [pscustomobject]@{ Success = $false; Message = [string]$_.Exception.Message; Path = $path }
    }
}

function Save-LastGoodStateRaw([string]$rawJson) {
    if ([string]::IsNullOrWhiteSpace($rawJson)) { return }
    try {
        Write-AtomicTextFile -Path $script:StateLastGoodPath -Content $rawJson -Encoding UTF8
    } catch { Write-IgnoredCatch $_ }
}

function Save-CorruptStateCopy([string]$rawJson) {
    if ([string]::IsNullOrWhiteSpace($rawJson)) { return }
    try {
        Ensure-Directory $script:StateCorruptDir "Corrupt" | Out-Null
        $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
        $target = Join-Path $script:StateCorruptDir ("Teams-Always-Green.state.corrupt.{0}.json" -f $stamp)
        Write-AtomicTextFile -Path $target -Content $rawJson -Encoding UTF8
    } catch { Write-IgnoredCatch $_ }
}

function Load-LastGoodState {
    try {
        if (Test-Path $script:StateLastGoodPath) {
            $raw = Get-Content -Path $script:StateLastGoodPath -Raw
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                return ($raw | ConvertFrom-Json)
            }
        }
    } catch { Write-IgnoredCatch $_ }
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
    if (-not $stats.ContainsKey("CrashFreeSince")) { $stats["CrashFreeSince"] = [string]$stats["InstallDate"] }
    if (-not $stats.ContainsKey("ProfileUsageMinutes")) { $stats["ProfileUsageMinutes"] = @{} }
    if (-not $stats.ContainsKey("ReliableMinutes")) { $stats["ReliableMinutes"] = 0 }
    if (-not $stats.ContainsKey("DegradedMinutes")) { $stats["DegradedMinutes"] = 0 }
    if (-not $stats.ContainsKey("LifetimeToggleCount")) { $stats["LifetimeToggleCount"] = 0 }
    if (-not $stats.ContainsKey("ProfileLifetimeToggles")) { $stats["ProfileLifetimeToggles"] = @{} }
    if (-not $stats.ContainsKey("ProfileLifetimeHighWater")) { $stats["ProfileLifetimeHighWater"] = @{} }
    if (-not $stats.ContainsKey("BadgeUnlocked")) { $stats["BadgeUnlocked"] = @{} }
    if (-not $stats.ContainsKey("BadgeHistory")) { $stats["BadgeHistory"] = @() }
    if (-not $stats.ContainsKey("BadgePoints")) { $stats["BadgePoints"] = 0 }
    if (-not $stats.ContainsKey("BadgeLevel")) { $stats["BadgeLevel"] = 1 }
    if (-not $stats.ContainsKey("BadgeLevelProgressPct")) { $stats["BadgeLevelProgressPct"] = 0.0 }
    if (-not $stats.ContainsKey("BadgeLastUnlockId")) { $stats["BadgeLastUnlockId"] = "" }
    if (-not $stats.ContainsKey("BadgeLastUnlockAt")) { $stats["BadgeLastUnlockAt"] = $null }
    if (-not $stats.ContainsKey("BadgeCurrentSeason")) { $stats["BadgeCurrentSeason"] = "" }
    if (-not $stats.ContainsKey("BadgeCatalogVersion")) { $stats["BadgeCatalogVersion"] = 1 }
    if (-not $stats.ContainsKey("BadgePointsHighWater")) { $stats["BadgePointsHighWater"] = 0 }
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
    if (-not (Test-ImportExportFilePath -path $script:StatePath -label "State load" -allowedExtensions @(".json") -RequireExists -MaxBytes ([int64]$script:SettingsMaxBytes) -Context "State-Load")) {
        Write-Log "State load blocked by security path policy." "ERROR" $null "State-Load"
        return $null
    }
    try {
        $raw = Get-Content -Path $script:StatePath -Raw
        $loaded = $raw | ConvertFrom-Json
        Save-LastGoodStateRaw $raw
        return (Normalize-State $loaded)
    } catch {
        Write-Log "Failed to load state." "WARN" $_.Exception "Load-State"
        Add-SelfHealRecentAction "LoadState" "Failed" $_.Exception.Message
        try {
            $rawFallback = if (Test-Path $script:StatePath) { Get-Content -Path $script:StatePath -Raw } else { "" }
            Save-CorruptStateCopy $rawFallback
        } catch { Write-IgnoredCatch $_ }
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
        if (Get-Command -Name Convert-SettingsSnapshotValueToStableString -ErrorAction SilentlyContinue) {
            $snapshot[$prop.Name] = Convert-SettingsSnapshotValueToStableString $value
        } else {
            $snapshot[$prop.Name] = if ($null -eq $value) { "<null>" } else { [string]$value }
        }
    }
    return $snapshot
}

function Get-StateSnapshotHash($snapshot) {
    $pairs = $snapshot.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" }
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
        Set-SettingsPropertyValue $script:AppState "ToggleCount" ([int]$settings.ToggleCount)
    }
    if ($settings.PSObject.Properties.Name -contains "LastToggleTime") {
        Set-SettingsPropertyValue $script:AppState "LastToggleTime" $settings.LastToggleTime
    }
    if ($settings.PSObject.Properties.Name -contains "Stats") {
        $incomingStats = Convert-ToHashtable $settings.Stats
        $baseStats = Convert-ToHashtable (Get-SettingsPropertyValue $script:AppState "Stats" @{})

        if ($baseStats.Count -eq 0 -and $script:StatePath -and (Test-Path $script:StatePath)) {
            try {
                $stateFromDisk = Load-State
                if ($stateFromDisk -and ($stateFromDisk.PSObject.Properties.Name -contains "Stats")) {
                    $baseStats = Convert-ToHashtable $stateFromDisk.Stats
                }
            } catch { Write-IgnoredCatch $_ }
        }

        if ($baseStats.Count -gt 0) {
            $mergeState = [pscustomobject]@{
                ToggleCount = [int](Get-SettingsPropertyValue $script:AppState "ToggleCount" 0)
                LastToggleTime = (Get-SettingsPropertyValue $script:AppState "LastToggleTime" $null)
                Stats = $baseStats
            }
            $runtime = @{ Stats = $incomingStats }
            if ($settings.PSObject.Properties.Name -contains "ToggleCount") { $runtime["ToggleCount"] = [int]$settings.ToggleCount }
            if ($settings.PSObject.Properties.Name -contains "LastToggleTime") { $runtime["LastToggleTime"] = $settings.LastToggleTime }
            Apply-RuntimeOverridesToState $mergeState $runtime | Out-Null
            Set-SettingsPropertyValue $script:AppState "ToggleCount" ([int]$mergeState.ToggleCount)
            Set-SettingsPropertyValue $script:AppState "LastToggleTime" $mergeState.LastToggleTime
            Set-SettingsPropertyValue $script:AppState "Stats" (Convert-ToHashtable $mergeState.Stats)
        } else {
            Set-SettingsPropertyValue $script:AppState "Stats" $incomingStats
        }
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
        if (-not (Test-ImportExportFilePath -path $script:StatePath -label "State save" -allowedExtensions @(".json") -Context "State-Save")) {
            Write-Log "State save blocked by security path policy." "ERROR" $null "State-Save"
            return
        }
        Rotate-StateBackups
        $normalized = Normalize-State $state
        $snapshot = Get-StateSnapshot $normalized
        $hash = Get-StateSnapshotHash $snapshot
        if ($script:LastStateSnapshotHash -and $script:LastStateSnapshotHash -eq $hash) {
            return
        }
        $stateJson = $normalized | ConvertTo-Json -Depth 6
        Write-AtomicTextFile -Path $script:StatePath -Content $stateJson -Encoding UTF8 -VerifyJson
        Save-LastGoodStateRaw $stateJson
        $script:LastStateSnapshot = $snapshot
        $script:LastStateSnapshotHash = $hash
    } catch {
        Write-Log "Failed to save state." "WARN" $_.Exception "Save-State"
        Add-SelfHealRecentAction "SaveState" "Failed" $_.Exception.Message
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
    if ($settings -is [System.Collections.IDictionary]) {
        if ($settings.Contains($name)) { return $settings[$name] }
        return $null
    }
    $prop = $null
    try { $prop = $settings.PSObject.Properties[$name] } catch { $prop = $null }
    if ($prop) { return $prop.Value }
    return $null
}

function Set-SettingsPropertyValue($settings, [string]$name, $value) {
    if (-not $settings) { return }
    if ($settings -is [System.Collections.IDictionary]) {
        $settings[$name] = $value
        return
    }
    $prop = $null
    try { $prop = $settings.PSObject.Properties[$name] } catch { $prop = $null }
    if ($prop) {
        $prop.Value = $value
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
    } catch { Write-IgnoredCatch $_ }
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

function Show-ActionToast([string]$message, [string]$title = "Teams-Always-Green", [switch]$ForceBalloon) {
    if ([string]::IsNullOrWhiteSpace($message)) { return }
    if ($script:isShuttingDown -or $script:CleanupDone) { return }
    $now = Get-Date
    $key = [string]$message
    if (-not ($script:ActionToastLastByMessage -is [hashtable])) {
        $script:ActionToastLastByMessage = @{}
    }
    if ($script:ActionToastLastByMessage.ContainsKey($key)) {
        $last = $script:ActionToastLastByMessage[$key]
        if ($last -is [DateTime] -and (($now - $last).TotalSeconds -lt 2)) {
            return
        }
    }
    $script:ActionToastLastByMessage[$key] = $now

    $settingsFormVisible = $false
    try {
        $settingsFormVar = Get-Variable -Name SettingsForm -Scope Script -ErrorAction SilentlyContinue
        if ($settingsFormVar -and $settingsFormVar.Value -and -not $settingsFormVar.Value.IsDisposed) {
            $settingsFormVisible = [bool]$settingsFormVar.Value.Visible
        }
    } catch { Write-IgnoredCatch $_ }
    if (-not $ForceBalloon -and $settingsFormVisible -and $script:SettingsSaveLabel) {
        Show-SettingsSaveToast $message
        return
    }

    if (-not $notifyIcon) { return }
    if ($ForceBalloon) {
        try {
            $notifyIcon.ShowBalloonTip(1400, $title, $message, [System.Windows.Forms.ToolTipIcon]::Info)
        } catch { Write-IgnoredCatch $_ }
        return
    }
    if (Get-Command -Name Show-Balloon -ErrorAction SilentlyContinue) {
        try { Show-Balloon $title $message ([System.Windows.Forms.ToolTipIcon]::Info) } catch { Write-IgnoredCatch $_ }
        return
    }
    try {
        $notifyIcon.ShowBalloonTip(1400, $title, $message, [System.Windows.Forms.ToolTipIcon]::Info)
    } catch { Write-IgnoredCatch $_ }
}

function Set-StartupLoadingIndicator([bool]$enabled, [string]$stage = "Starting") {
    $script:StartupLoadingIndicator = $enabled
    if (-not $notifyIcon) { return }
    try {
        if ($enabled) {
            $suffix = if ([string]::IsNullOrWhiteSpace($stage)) { "Starting..." } else { "{0}..." -f $stage.Trim() }
            $text = "Teams-Always-Green ($suffix)"
            if ($text.Length -gt 63) { $text = $text.Substring(0, 63) }
            $notifyIcon.Text = $text
        } else {
            if (Get-Command -Name Update-NotifyIconText -ErrorAction SilentlyContinue) {
                Update-NotifyIconText $script:StatusStateText
            } else {
                $notifyIcon.Text = "Teams-Always-Green"
            }
        }
    } catch { Write-IgnoredCatch $_ }
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
    if (-not ($settings.PSObject.Properties.Name -contains "ScrollLockReleaseDelayMs")) {
        Set-SettingsPropertyValue $settings "ScrollLockReleaseDelayMs" $script:ScrollLockReleaseDelayDefaultMs
    }
    try {
        $settings.ScrollLockReleaseDelayMs = [int]$settings.ScrollLockReleaseDelayMs
    } catch {
        $settings.ScrollLockReleaseDelayMs = [int]$script:ScrollLockReleaseDelayDefaultMs
    }
    $settings.ScrollLockReleaseDelayMs = Normalize-ScrollLockReleaseDelayMs ([int]$settings.ScrollLockReleaseDelayMs)
    if ([string]::IsNullOrWhiteSpace([string]$settings.ThemeMode)) { Set-SettingsPropertyValue $settings "ThemeMode" "Auto" }
    if ([string]::IsNullOrWhiteSpace([string]$settings.TooltipStyle)) { Set-SettingsPropertyValue $settings "TooltipStyle" "Standard" }
    if (-not ($settings.PSObject.Properties.Name -contains "FontSize")) { Set-SettingsPropertyValue $settings "FontSize" 12 }
    if (-not ($settings.PSObject.Properties.Name -contains "SettingsFontSize")) { Set-SettingsPropertyValue $settings "SettingsFontSize" 12 }
    if (-not ($settings.PSObject.Properties.Name -contains "LogDirectory")) { Set-SettingsPropertyValue $settings "LogDirectory" "" }
    if (-not ($settings.PSObject.Properties.Name -contains "SettingsDirectory")) { Set-SettingsPropertyValue $settings "SettingsDirectory" "" }
    if (-not ($settings.PSObject.Properties.Name -contains "DataRoot")) { Set-SettingsPropertyValue $settings "DataRoot" $script:DataRoot }
    if ([string]::IsNullOrWhiteSpace([string]$settings.DataRoot)) { $settings.DataRoot = $script:DataRoot }
    if (-not ($settings.PSObject.Properties.Name -contains "AllowExternalPaths")) { Set-SettingsPropertyValue $settings "AllowExternalPaths" $false }
    if (-not ($settings.PSObject.Properties.Name -contains "SettingsSequence")) { Set-SettingsPropertyValue $settings "SettingsSequence" 0 }
    if (-not ($settings.PSObject.Properties.Name -contains "SecurityModeEnabled")) { Set-SettingsPropertyValue $settings "SecurityModeEnabled" $false }
    if (-not ($settings.PSObject.Properties.Name -contains "StrictSettingsImport")) { Set-SettingsPropertyValue $settings "StrictSettingsImport" $false }
    if (-not ($settings.PSObject.Properties.Name -contains "StrictProfileImport")) { Set-SettingsPropertyValue $settings "StrictProfileImport" $true }
    if (-not ($settings.PSObject.Properties.Name -contains "StrictUpdatePolicy")) { Set-SettingsPropertyValue $settings "StrictUpdatePolicy" $true }
    if (-not ($settings.PSObject.Properties.Name -contains "RequireScriptSignature")) { Set-SettingsPropertyValue $settings "RequireScriptSignature" $false }
    if (-not ($settings.PSObject.Properties.Name -contains "TrustedSignerThumbprints")) { Set-SettingsPropertyValue $settings "TrustedSignerThumbprints" "" }
    if (-not ($settings.PSObject.Properties.Name -contains "UpdateOwner")) { Set-SettingsPropertyValue $settings "UpdateOwner" $script:SecurityDefaultUpdateOwner }
    if (-not ($settings.PSObject.Properties.Name -contains "UpdateRepo")) { Set-SettingsPropertyValue $settings "UpdateRepo" $script:SecurityDefaultUpdateRepo }
    if (-not ($settings.PSObject.Properties.Name -contains "UpdateRequireHash")) { Set-SettingsPropertyValue $settings "UpdateRequireHash" $true }
    if (-not ($settings.PSObject.Properties.Name -contains "UpdateAllowDowngrade")) { Set-SettingsPropertyValue $settings "UpdateAllowDowngrade" $false }
    if (-not ($settings.PSObject.Properties.Name -contains "UpdateAllowPrerelease")) { Set-SettingsPropertyValue $settings "UpdateAllowPrerelease" $false }
    if (-not ($settings.PSObject.Properties.Name -contains "UpdateRequireSignature")) { Set-SettingsPropertyValue $settings "UpdateRequireSignature" $true }
    if (-not ($settings.PSObject.Properties.Name -contains "HardenPermissions")) { Set-SettingsPropertyValue $settings "HardenPermissions" $true }
    if (-not ($settings.PSObject.Properties.Name -contains "LogIncludeStackTrace")) { Set-SettingsPropertyValue $settings "LogIncludeStackTrace" $false }
    if (-not ($settings.PSObject.Properties.Name -contains "LogToEventLog")) { Set-SettingsPropertyValue $settings "LogToEventLog" $false }
    if (-not ($settings.PSObject.Properties.Name -contains "ScrubDiagnostics")) { Set-SettingsPropertyValue $settings "ScrubDiagnostics" $true }
    if (-not ($settings.PSObject.Properties.Name -contains "FirstRunWizardCompleted")) { Set-SettingsPropertyValue $settings "FirstRunWizardCompleted" $false }
    if (-not ($settings.PSObject.Properties.Name -contains "BadgeTrackingMode")) { Set-SettingsPropertyValue $settings "BadgeTrackingMode" "Global" }
    if (-not ($settings.PSObject.Properties.Name -contains "AutoStartOnRestart")) { Set-SettingsPropertyValue $settings "AutoStartOnRestart" $false }
    if ([bool]$settings.SecurityModeEnabled) {
        $settings.StrictSettingsImport = $true
        $settings.StrictProfileImport = $true
        $settings.StrictUpdatePolicy = $true
        $settings.UpdateRequireHash = $true
        $settings.UpdateRequireSignature = $true
        $settings.AllowExternalPaths = $false
        $settings.HardenPermissions = $true
        $settings.LogIncludeStackTrace = $false
        $settings.LogToEventLog = $false
        $settings.ScrubDiagnostics = $true
    }
    $requestedAllowExternal = [bool]$settings.AllowExternalPaths
    $allowExternal = Get-EffectiveAllowExternalPaths $requestedAllowExternal
    if ($allowExternal -ne $requestedAllowExternal) {
        $settings.AllowExternalPaths = $allowExternal
    }
    $settingsSequence = Get-SettingsSequenceValue $settings 0
    Set-SettingsPropertyValue $settings "SettingsSequence" $settingsSequence
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
    if (-not ($settings.PSObject.Properties.Name -contains "SecurityModeEnabled")) { $settings.SecurityModeEnabled = $false }
    if (-not ($settings.PSObject.Properties.Name -contains "StrictSettingsImport")) { $settings.StrictSettingsImport = $false }
    if (-not ($settings.PSObject.Properties.Name -contains "StrictProfileImport")) { $settings.StrictProfileImport = $true }
    if (-not ($settings.PSObject.Properties.Name -contains "StrictUpdatePolicy")) { $settings.StrictUpdatePolicy = $true }
    if (-not ($settings.PSObject.Properties.Name -contains "RequireScriptSignature")) { $settings.RequireScriptSignature = $false }
    if (-not ($settings.PSObject.Properties.Name -contains "TrustedSignerThumbprints")) { $settings.TrustedSignerThumbprints = "" }
    if (-not ($settings.PSObject.Properties.Name -contains "UpdateOwner")) { $settings.UpdateOwner = $script:SecurityDefaultUpdateOwner }
    if (-not ($settings.PSObject.Properties.Name -contains "UpdateRepo")) { $settings.UpdateRepo = $script:SecurityDefaultUpdateRepo }
    if (-not ($settings.PSObject.Properties.Name -contains "UpdateRequireHash")) { $settings.UpdateRequireHash = $true }
    if (-not ($settings.PSObject.Properties.Name -contains "UpdateAllowDowngrade")) { $settings.UpdateAllowDowngrade = $false }
    if (-not ($settings.PSObject.Properties.Name -contains "UpdateAllowPrerelease")) { $settings.UpdateAllowPrerelease = $false }
    if (-not ($settings.PSObject.Properties.Name -contains "UpdateRequireSignature")) { $settings.UpdateRequireSignature = $true }
    if (-not ($settings.PSObject.Properties.Name -contains "HardenPermissions")) { $settings.HardenPermissions = $true }
    if (-not ($settings.PSObject.Properties.Name -contains "LogIncludeStackTrace")) { $settings.LogIncludeStackTrace = $false }
    if (-not ($settings.PSObject.Properties.Name -contains "LogToEventLog")) { $settings.LogToEventLog = $false }
    if (-not ($settings.PSObject.Properties.Name -contains "ScrubDiagnostics")) { $settings.ScrubDiagnostics = $true }
    if (-not ($settings.PSObject.Properties.Name -contains "FirstRunWizardCompleted")) { $settings.FirstRunWizardCompleted = $false }
    if (-not ($settings.PSObject.Properties.Name -contains "BadgeTrackingMode")) { $settings.BadgeTrackingMode = "Global" }
    if (-not ($settings.PSObject.Properties.Name -contains "AutoStartOnRestart")) { $settings.AutoStartOnRestart = $false }
    if (-not ($settings.PSObject.Properties.Name -contains "ScrollLockReleaseDelayMs")) { $settings.ScrollLockReleaseDelayMs = $script:ScrollLockReleaseDelayDefaultMs }
    try {
        $settings.ScrollLockReleaseDelayMs = [int]$settings.ScrollLockReleaseDelayMs
    } catch {
        $issues += "ScrollLockReleaseDelayMs invalid; reset to default"
        $settings.ScrollLockReleaseDelayMs = [int]$script:ScrollLockReleaseDelayDefaultMs
    }
    $normalizedDelay = Normalize-ScrollLockReleaseDelayMs ([int]$settings.ScrollLockReleaseDelayMs)
    if ($normalizedDelay -ne [int]$settings.ScrollLockReleaseDelayMs) {
        $issues += ("ScrollLockReleaseDelayMs out of range; clamped to {0}" -f $normalizedDelay)
        $settings.ScrollLockReleaseDelayMs = $normalizedDelay
    }
    if ([bool]$settings.SecurityModeEnabled) {
        $settings.StrictSettingsImport = $true
        $settings.StrictProfileImport = $true
        $settings.StrictUpdatePolicy = $true
        $settings.UpdateRequireHash = $true
        $settings.UpdateRequireSignature = $true
        $settings.AllowExternalPaths = $false
        $settings.HardenPermissions = $true
        $settings.LogIncludeStackTrace = $false
        $settings.LogToEventLog = $false
        $settings.ScrubDiagnostics = $true
    }
    if (-not ($settings.PSObject.Properties.Name -contains "AllowExternalPaths")) { $settings.AllowExternalPaths = $false }
    if (-not ($settings.PSObject.Properties.Name -contains "SettingsSequence")) { $settings.SettingsSequence = 0 }
    $requestedAllowExternal = [bool]$settings.AllowExternalPaths
    $allowExternal = Get-EffectiveAllowExternalPaths $requestedAllowExternal
    if ($allowExternal -ne $requestedAllowExternal) {
        $issues += "AllowExternalPaths disabled by installed mode policy"
        $settings.AllowExternalPaths = $allowExternal
    }
    $settings.SettingsSequence = Get-SettingsSequenceValue $settings 0
    if ($settings.PSObject.Properties.Name -contains "DataRoot") {
        if ([string]::IsNullOrWhiteSpace([string]$settings.DataRoot) -or ([string]$settings.DataRoot -ne $script:DataRoot)) {
            $issues += "DataRoot invalid; reset to data root"
            $settings.DataRoot = $script:DataRoot
        }
    } else {
        $settings | Add-Member -MemberType NoteProperty -Name "DataRoot" -Value $script:DataRoot -Force
    }
    if (-not $allowExternal) {
        if (-not [string]::IsNullOrWhiteSpace([string]$settings.LogDirectory)) {
            $resolvedLog = Convert-FromRelativePath ([string]$settings.LogDirectory)
            if (-not (Test-TrustedDirectoryPath $resolvedLog $script:DataRoot $false)) {
                $issues += "LogDirectory outside data root; reset to default"
                $settings.LogDirectory = ""
            }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$settings.SettingsDirectory)) {
            $resolvedSettings = Convert-FromRelativePath ([string]$settings.SettingsDirectory)
            if (-not (Test-TrustedDirectoryPath $resolvedSettings $script:DataRoot $false)) {
                $issues += "SettingsDirectory outside data root; reset to default"
                $settings.SettingsDirectory = ""
            }
        }
    } else {
        if (-not [string]::IsNullOrWhiteSpace([string]$settings.LogDirectory)) {
            $resolvedLogExt = Convert-FromRelativePath ([string]$settings.LogDirectory)
            if (-not (Test-TrustedDirectoryPath $resolvedLogExt $script:DataRoot $true)) {
                $issues += "LogDirectory rejected due to reparse point; reset to default"
                $settings.LogDirectory = ""
            }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$settings.SettingsDirectory)) {
            $resolvedSettingsExt = Convert-FromRelativePath ([string]$settings.SettingsDirectory)
            if (-not (Test-TrustedDirectoryPath $resolvedSettingsExt $script:DataRoot $true)) {
                $issues += "SettingsDirectory rejected due to reparse point; reset to default"
                $settings.SettingsDirectory = ""
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace([string]$settings.UpdateOwner) -or [string]$settings.UpdateOwner -notmatch '^[A-Za-z0-9._-]+$') {
        $issues += "UpdateOwner invalid; reset to default"
        $settings.UpdateOwner = $script:SecurityDefaultUpdateOwner
    }
    if ([string]::IsNullOrWhiteSpace([string]$settings.UpdateRepo) -or [string]$settings.UpdateRepo -notmatch '^[A-Za-z0-9._-]+$') {
        $issues += "UpdateRepo invalid; reset to default"
        $settings.UpdateRepo = $script:SecurityDefaultUpdateRepo
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
    if ($settings.PSObject.Properties.Name -contains "BadgeTrackingMode") {
        $badgeMode = [string]$settings.BadgeTrackingMode
        if ([string]::IsNullOrWhiteSpace($badgeMode)) { $badgeMode = "Global" }
        switch ($badgeMode.ToLowerInvariant()) {
            "global" { $settings.BadgeTrackingMode = "Global" }
            "profile" { $settings.BadgeTrackingMode = "Profile" }
            default {
                $issues += "BadgeTrackingMode invalid; reset to Global"
                $settings.BadgeTrackingMode = "Global"
            }
        }
    } else {
        $settings.BadgeTrackingMode = "Global"
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
    $scrollLockDelayDefault = 50
    try {
        $delayDefaultVar = Get-Variable -Name ScrollLockReleaseDelayDefaultMs -Scope Script -ErrorAction SilentlyContinue
        if ($delayDefaultVar -and $null -ne $delayDefaultVar.Value) {
            $scrollLockDelayDefault = [int]$delayDefaultVar.Value
        }
    } catch {
        $scrollLockDelayDefault = 50
    }
    $schemaValue = Get-SettingsPropertyValue $settings "SchemaVersion"
    if ($null -ne $schemaValue) { $current = [int]$schemaValue }
    if ($current -lt 2) {
        if (-not ($settings.PSObject.Properties.Name -contains "TooltipStyle")) {
            Set-SettingsPropertyValue $settings "TooltipStyle" $(if ([bool]$settings.MinimalTrayTooltip) { "Minimal" } else { "Standard" })
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
    if ($current -lt 9) {
        if (-not ($settings.PSObject.Properties.Name -contains "SecurityModeEnabled")) { Set-SettingsPropertyValue $settings "SecurityModeEnabled" $false }
        if (-not ($settings.PSObject.Properties.Name -contains "StrictSettingsImport")) { Set-SettingsPropertyValue $settings "StrictSettingsImport" $false }
        if (-not ($settings.PSObject.Properties.Name -contains "StrictProfileImport")) { Set-SettingsPropertyValue $settings "StrictProfileImport" $true }
        if (-not ($settings.PSObject.Properties.Name -contains "StrictUpdatePolicy")) { Set-SettingsPropertyValue $settings "StrictUpdatePolicy" $true }
        if (-not ($settings.PSObject.Properties.Name -contains "RequireScriptSignature")) { Set-SettingsPropertyValue $settings "RequireScriptSignature" $false }
        if (-not ($settings.PSObject.Properties.Name -contains "TrustedSignerThumbprints")) { Set-SettingsPropertyValue $settings "TrustedSignerThumbprints" "" }
        if (-not ($settings.PSObject.Properties.Name -contains "UpdateOwner")) { Set-SettingsPropertyValue $settings "UpdateOwner" $script:SecurityDefaultUpdateOwner }
        if (-not ($settings.PSObject.Properties.Name -contains "UpdateRepo")) { Set-SettingsPropertyValue $settings "UpdateRepo" $script:SecurityDefaultUpdateRepo }
        if (-not ($settings.PSObject.Properties.Name -contains "UpdateRequireHash")) { Set-SettingsPropertyValue $settings "UpdateRequireHash" $true }
        if (-not ($settings.PSObject.Properties.Name -contains "UpdateAllowDowngrade")) { Set-SettingsPropertyValue $settings "UpdateAllowDowngrade" $false }
        if (-not ($settings.PSObject.Properties.Name -contains "UpdateAllowPrerelease")) { Set-SettingsPropertyValue $settings "UpdateAllowPrerelease" $false }
        if (-not ($settings.PSObject.Properties.Name -contains "UpdateRequireSignature")) { Set-SettingsPropertyValue $settings "UpdateRequireSignature" $true }
        if (-not ($settings.PSObject.Properties.Name -contains "HardenPermissions")) { Set-SettingsPropertyValue $settings "HardenPermissions" $true }
        $current = 9
    }
    if ($current -lt 10) {
        if (-not ($settings.PSObject.Properties.Name -contains "BadgeTrackingMode")) {
            Set-SettingsPropertyValue $settings "BadgeTrackingMode" "Global"
        }
        $current = 10
    }
    if ($current -lt 11) {
        if (-not ($settings.PSObject.Properties.Name -contains "ScrollLockReleaseDelayMs")) {
            Set-SettingsPropertyValue $settings "ScrollLockReleaseDelayMs" $scrollLockDelayDefault
        }
        $current = 11
    }
    if (-not ($settings.PSObject.Properties.Name -contains "FirstRunWizardCompleted")) {
        Set-SettingsPropertyValue $settings "FirstRunWizardCompleted" $false
    }
    if (-not ($settings.PSObject.Properties.Name -contains "SettingsSequence")) {
        Set-SettingsPropertyValue $settings "SettingsSequence" 0
    } else {
        Set-SettingsPropertyValue $settings "SettingsSequence" (Get-SettingsSequenceValue $settings 0)
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
        $previousBadgeMode = ""
        try {
            if ($script:settings -and -not [object]::ReferenceEquals($script:settings, $settings)) {
                $previousBadgeMode = [string](Get-SettingsPropertyValue $script:settings "BadgeTrackingMode" "")
            }
        } catch {
            $previousBadgeMode = ""
        }
        if ([string]::IsNullOrWhiteSpace($previousBadgeMode)) {
            try { $previousBadgeMode = [string]$script:BadgeTrackingModeLastApplied } catch { $previousBadgeMode = "" }
        }
        $newBadgeMode = [string](Get-SettingsPropertyValue $settings "BadgeTrackingMode" "Global")
        if ([string]::IsNullOrWhiteSpace($newBadgeMode)) { $newBadgeMode = "Global" }
        try {
            if (Get-Command -Name Invoke-BadgeTrackingModeMigration -ErrorAction SilentlyContinue) {
                Invoke-BadgeTrackingModeMigration $settings $previousBadgeMode $newBadgeMode | Out-Null
            }
        } catch {
            Write-Log "Badge scope migration failed during settings save; preserving existing stats." "WARN" $_.Exception "Badges"
        }
        Sync-StateFromSettings $settings
        Apply-StateToSettings $settings $script:AppState
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
        if (-not $script:RollbackState) {
            $script:RollbackState = Load-RollbackState
        }
        $sequenceFloor = 0
        try {
            if ($script:RollbackState -and $script:RollbackState.ContainsKey("HighestSettingsSequence")) {
                $sequenceFloor = [Math]::Max(0, [int]$script:RollbackState.HighestSettingsSequence)
            }
        } catch { Write-IgnoredCatch $_ }
        $currentSequence = Get-SettingsSequenceValue $settings 0
        $nextSequence = [Math]::Max($currentSequence + 1, $sequenceFloor + 1)
        Set-SettingsPropertyValue $settings "SettingsSequence" $nextSequence
        $newSnapshot = Get-SettingsSnapshot $settings
        $newHash = Get-SettingsSnapshotHash $newSnapshot
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
        if (-not (Test-ImportExportFilePath -path $script:settingsPath -label "Settings save" -allowedExtensions @(".json") -Context "Settings-Save")) {
            Write-Log "Settings save blocked by security path policy." "ERROR" $null "Settings-Save"
            return
        }
        if (-not (Test-ImportExportFilePath -path $script:StatePath -label "State save" -allowedExtensions @(".json") -Context "Settings-Save")) {
            Write-Log "State save blocked by security path policy." "ERROR" $null "Settings-Save"
            return
        }
        Rotate-SettingsBackups
        $settingsToSave = Get-SettingsForSave $settings
        $settingsJson = $settingsToSave | ConvertTo-Json -Depth 6
        try {
            Write-AtomicTextFile -Path $settingsPath -Content $settingsJson -Encoding UTF8 -VerifyJson
            Save-LastGoodSettingsRaw $settingsJson
            Save-SettingsVersionSnapshot $settingsJson $nextSequence
            $saveVerify = Test-SavedSettingsFile -path $settingsPath -expectedSequence $nextSequence
            if (-not $saveVerify.IsValid) {
                Write-Log ("Settings save verification failed: {0}" -f $saveVerify.Reason) "WARN" $null "Settings-Save"
                Add-SelfHealRecentAction "SettingsSaveVerify" "Retry" $saveVerify.Reason
                $script:SelfHealStats.SettingsRepairCount = [int]$script:SelfHealStats.SettingsRepairCount + 1
                $fallbackBackup = Join-Path $script:SettingsDirectory "Teams-Always-Green.settings.json.bak1"
                if (Test-Path $fallbackBackup) {
                    try { Copy-Item -Path $fallbackBackup -Destination $settingsPath -Force } catch { Write-IgnoredCatch $_ }
                }
                Write-AtomicTextFile -Path $settingsPath -Content $settingsJson -Encoding UTF8 -VerifyJson
                $saveVerifyRetry = Test-SavedSettingsFile -path $settingsPath -expectedSequence $nextSequence
                if (-not $saveVerifyRetry.IsValid) {
                    throw ("Settings save verification failed after repair attempt: {0}" -f $saveVerifyRetry.Reason)
                }
                Write-Log "Settings save self-heal succeeded after verification failure." "WARN" $null "Settings-Save"
                Add-SelfHealRecentAction "SettingsSaveVerify" "Succeeded" "Self-heal rewrite succeeded"
            }
        } catch {
            $fallbackBackup = Join-Path $script:SettingsDirectory "Teams-Always-Green.settings.json.bak1"
            if (Test-Path $fallbackBackup) {
                try { Copy-Item -Path $fallbackBackup -Destination $settingsPath -Force } catch { Write-IgnoredCatch $_ }
            }
            Add-SelfHealRecentAction "SettingsSaveVerify" "Failed" $_.Exception.Message
            throw
        }
        if (@($changedKeys).Count -gt 0) {
            $categoryMap = @{
                General     = @("IntervalSeconds", "StartWithWindows", "RememberChoice", "StartOnLaunch", "RunOnceOnLaunch", "AutoStartOnRestart", "QuietMode", "DisableBalloonTips", "OpenSettingsAtLastTab", "LastSettingsTab", "DateTimeFormat", "UseSystemDateTimeFormat", "SystemDateTimeFormatMode", "PauseUntil", "PauseDurationsMinutes", "SettingsDirectory", "DataRoot")
                Appearance  = @("TooltipStyle", "ThemeMode", "FontSize", "SettingsFontSize", "StatusColorRunning", "StatusColorPaused", "StatusColorStopped", "CompactMode", "MinimalTrayTooltip")
                Schedule    = @("ScheduleOverrideEnabled", "ScheduleEnabled", "ScheduleStart", "ScheduleEnd", "ScheduleWeekdays", "ScheduleSuspendUntil")
                Hotkeys     = @("HotkeyToggle", "HotkeyStartStop", "HotkeyPauseResume")
                Logging     = @("LogLevel", "LogMaxBytes", "LogMaxTotalBytes", "LogRetentionDays", "LogIncludeStackTrace", "LogToEventLog", "LogEventLevels", "LogCategories", "LogDirectory")
                Diagnostics = @("ScrubDiagnostics")
                Profiles    = @("ActiveProfile", "Profiles")
                Security    = @("SecurityModeEnabled", "StrictSettingsImport", "StrictProfileImport", "StrictUpdatePolicy", "RequireScriptSignature", "TrustedSignerThumbprints", "AllowExternalPaths", "AutoUpdateEnabled", "UpdateOwner", "UpdateRepo", "UpdateRequireHash", "UpdateRequireSignature", "UpdateAllowDowngrade", "UpdateAllowPrerelease", "HardenPermissions")
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
        Show-ActionToast "Settings saved"
        $script:LastSettingsSnapshot = $newSnapshot
        $script:LastSettingsSnapshotHash = $newHash
        $script:LastSettingsSaveOk = $true
        $script:LastSettingsSaveMessage = ""
        try { Purge-SettingsBackups } catch { Write-IgnoredCatch $_ }
        try {
            $savedHash = Get-SettingsFileHash
            if ($savedHash) {
                if (-not $script:AppState) { $script:AppState = [pscustomobject]@{} }
                $script:AppState.SettingsHash = $savedHash
            }
        } catch { Write-IgnoredCatch $_ }
        Sync-SettingsReference $settings
        $script:BadgeTrackingModeLastApplied = [string](Get-SettingsPropertyValue $settings "BadgeTrackingMode" "Global")
        Save-StateImmediate $script:AppState
        Update-RollbackStateFromSettings $settings
    } catch {
        $stopwatch.Stop()
        $script:LastSettingsSaveOk = $false
        $script:LastSettingsSaveMessage = [string]$_.Exception.Message
        Add-SelfHealRecentAction "SaveSettings" "Failed" $script:LastSettingsSaveMessage
        Write-LogExceptionDeduped "Failed to save settings." "ERROR" $_.Exception "Save-Settings" 20
        if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
            $savePos = ("Save settings failure location: " + $_.InvocationInfo.PositionMessage.Trim())
            Write-LogExceptionDeduped $savePos "ERROR" $_.Exception "Save-Settings" 20
        }
        if ($_.ScriptStackTrace) {
            Write-LogExceptionDeduped ("Save settings stack: " + [string]$_.ScriptStackTrace) "ERROR" $_.Exception "Save-Settings" 20
        } elseif ($_.Exception -and $_.Exception.ScriptStackTrace) {
            Write-LogExceptionDeduped ("Save settings stack: " + [string]$_.Exception.ScriptStackTrace) "ERROR" $_.Exception "Save-Settings" 20
        }
        if ($_.Exception -and $_.Exception.TargetSite) {
            Write-LogExceptionDeduped ("Save settings target site: " + [string]$_.Exception.TargetSite) "ERROR" $_.Exception "Save-Settings" 20
        }
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

function Convert-SettingsSnapshotValueToStableString($value, [int]$depth = 0) {
    if ($null -eq $value) { return "<null>" }
    if ($depth -ge 10) { return "<max-depth>" }
    if ($value -is [datetime]) {
        try { return ([datetime]$value).ToString("o") } catch { return [string]$value }
    }
    if ($value -is [bool]) { return $(if ($value) { "true" } else { "false" }) }
    if ($value -is [string]) { return [string]$value }
    if ($value -is [pscustomobject]) {
        try {
            $value = Convert-ToHashtable $value
        } catch { Write-IgnoredCatch $_ }
    }
    if ($value -is [System.Collections.IDictionary]) {
        $parts = @()
        foreach ($key in @($value.Keys | Sort-Object { [string]$_ })) {
            $child = Convert-SettingsSnapshotValueToStableString $value[$key] ($depth + 1)
            $parts += ("{0}:{1}" -f [string]$key, $child)
        }
        return "{" + ($parts -join ",") + "}"
    }
    if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
        $items = @()
        foreach ($item in @($value)) {
            $items += (Convert-SettingsSnapshotValueToStableString $item ($depth + 1))
        }
        return "[" + ($items -join ",") + "]"
    }
    try {
        return [string]$value
    } catch {
        return "<unprintable>"
    }
}

function Get-SettingsSnapshot($settings) {
    $snapshot = @{}
    foreach ($prop in $settings.PSObject.Properties) {
        if ($script:SettingsNonDiffKeys -and ($script:SettingsNonDiffKeys -contains $prop.Name)) { continue }
        $snapshot[$prop.Name] = Convert-SettingsSnapshotValueToStableString $prop.Value
    }
    return $snapshot
}

function Get-SettingsSnapshotHash($snapshot) {
    $pairs = $snapshot.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" }
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

function Test-SavedSettingsFile([string]$path, [int]$expectedSequence) {
    if ([string]::IsNullOrWhiteSpace($path)) {
        return [pscustomobject]@{ IsValid = $false; Reason = "Path is empty." }
    }
    if (-not (Test-Path $path)) {
        return [pscustomobject]@{ IsValid = $false; Reason = "Settings file missing after save." }
    }
    try {
        $raw = Get-Content -Path $path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return [pscustomobject]@{ IsValid = $false; Reason = "Settings file is empty." }
        }
        $loaded = $raw | ConvertFrom-Json -ErrorAction Stop
        $sequence = Get-SettingsSequenceValue $loaded -1
        if ($sequence -lt $expectedSequence) {
            return [pscustomobject]@{ IsValid = $false; Reason = ("Settings sequence mismatch (expected >= {0}, got {1})." -f $expectedSequence, $sequence) }
        }
        $schemaVersion = Get-SettingsPropertyValue $loaded "SchemaVersion" $null
        if ($null -eq $schemaVersion) {
            return [pscustomobject]@{ IsValid = $false; Reason = "SchemaVersion missing after save." }
        }
        return [pscustomobject]@{ IsValid = $true; Reason = "" }
    } catch {
        return [pscustomobject]@{ IsValid = $false; Reason = $_.Exception.Message }
    }
}

# --- Profile snapshots and sync (last-good/diff) ---
$script:ProfilePropertyNames = @(
    "IntervalSeconds",
    "ScrollLockReleaseDelayMs",
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
            try { Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue } catch { Write-IgnoredCatch $_ }
        }
    } catch {
        Write-Log "Failed to save profile last-good file." "WARN" $_.Exception "Profiles"
    }
}

function Copy-ObjectDeep($obj) {
    if ($null -eq $obj) { return $null }
    try {
        if ($obj -is [string] -or $obj.GetType().IsValueType) { return $obj }
    } catch { Write-IgnoredCatch $_ }
    try {
        $json = $obj | ConvertTo-Json -Depth 20 -Compress
        if ([string]::IsNullOrWhiteSpace($json)) { return $null }
        $copy = $json | ConvertFrom-Json
        if ($obj -is [hashtable]) { return (Convert-ToHashtable $copy) }
        return $copy
    } catch {
        return $obj
    }
}

function Get-ProfileVersionSnapshotDir([string]$name) {
    if ([string]::IsNullOrWhiteSpace($name)) { return $null }
    $safe = [regex]::Replace($name.Trim(), "[^A-Za-z0-9._-]", "_")
    if ([string]::IsNullOrWhiteSpace($safe)) { $safe = "Profile" }
    return (Join-Path $script:ProfileVersionsDir $safe)
}

function Save-ProfileVersionSnapshot([string]$name, $snapshot) {
    if ([string]::IsNullOrWhiteSpace($name) -or -not $snapshot) { return }
    try {
        Ensure-Directory $script:ProfileVersionsDir "Meta" | Out-Null
        $profileDir = Get-ProfileVersionSnapshotDir $name
        if ([string]::IsNullOrWhiteSpace($profileDir)) { return }
        Ensure-Directory $profileDir "Meta" | Out-Null
        $safeName = Split-Path -Leaf $profileDir
        $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
        $fileName = "{0}.v{1}.json" -f $safeName, $stamp
        $target = Join-Path $profileDir $fileName
        $payload = [ordered]@{
            Name = $name
            SavedAt = (Get-Date).ToString("o")
            Profile = (Migrate-ProfileSnapshot (Copy-ObjectDeep $snapshot))
        }
        $json = $payload | ConvertTo-Json -Depth 8
        Write-AtomicTextFile -Path $target -Content $json -Encoding UTF8 -VerifyJson

        $keep = [Math]::Max(10, [int]$script:ProfileVersionRetentionCount)
        $files = @(Get-ChildItem -Path $profileDir -Filter "$safeName.v*.json" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        if ($files.Count -gt $keep) {
            foreach ($old in @($files | Select-Object -Skip $keep)) {
                try { Remove-Item -Path $old.FullName -Force -ErrorAction SilentlyContinue } catch { Write-IgnoredCatch $_ }
            }
        }
    } catch {
        Write-Log ("Failed to save profile snapshot version for '{0}'." -f $name) "WARN" $_.Exception "Profiles"
    }
}

function Get-ProfileVersionSnapshotFiles([string]$name) {
    $profileDir = Get-ProfileVersionSnapshotDir $name
    if ([string]::IsNullOrWhiteSpace($profileDir)) { return @() }
    if (-not (Test-Path $profileDir)) { return @() }
    $safeName = Split-Path -Leaf $profileDir
    return @(Get-ChildItem -Path $profileDir -Filter "$safeName.v*.json" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
}

function Update-ProfileLastGood([string]$name, $snapshot) {
    if ([string]::IsNullOrWhiteSpace($name) -or -not $snapshot) { return }
    if (-not $script:ProfilesLastGood) { $script:ProfilesLastGood = @{} }
    $script:ProfilesLastGood[$name] = $snapshot
    Save-ProfilesLastGood
    Save-ProfileVersionSnapshot $name $snapshot
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

function Migrate-ProfileSnapshot($profileSnapshot) {
    if (-not $profileSnapshot) { return $profileSnapshot }
    if ($profileSnapshot -is [hashtable]) {
        if (-not $profileSnapshot.ContainsKey("ProfileSchemaVersion")) { $profileSnapshot["ProfileSchemaVersion"] = $script:ProfileSchemaVersion }
        if (-not $profileSnapshot.ContainsKey("ReadOnly")) { $profileSnapshot["ReadOnly"] = $false }
        return $profileSnapshot
    }
    if (-not ($profileSnapshot.PSObject.Properties.Name -contains "ProfileSchemaVersion")) {
        $profileSnapshot | Add-Member -MemberType NoteProperty -Name "ProfileSchemaVersion" -Value $script:ProfileSchemaVersion -Force
    }
    if (-not ($profileSnapshot.PSObject.Properties.Name -contains "ReadOnly")) {
        $profileSnapshot | Add-Member -MemberType NoteProperty -Name "ReadOnly" -Value $false -Force
    }
    return $profileSnapshot
}

function Test-ProfileSnapshot($profileSnapshot, [switch]$Strict) {
    $issues = @()
    if (-not $profileSnapshot) {
        $issues += "Profile is null."
        return [pscustomobject]@{ IsValid = $false; Issues = $issues }
    }
    if (-not ($profileSnapshot -is [hashtable] -or $profileSnapshot -is [pscustomobject])) {
        $issues += "Profile is not an object."
        return [pscustomobject]@{ IsValid = $false; Issues = $issues }
    }
    $required = @("IntervalSeconds", "HotkeyToggle", "HotkeyStartStop", "HotkeyPauseResume")
    foreach ($key in $required) {
        $hasKey = if ($profileSnapshot -is [hashtable]) { $profileSnapshot.ContainsKey($key) } else { $profileSnapshot.PSObject.Properties.Name -contains $key }
        if (-not $hasKey) { $issues += "Missing $key" }
    }
    $intervalValue = $null
    if ($profileSnapshot -is [hashtable]) {
        if ($profileSnapshot.ContainsKey("IntervalSeconds")) { $intervalValue = $profileSnapshot["IntervalSeconds"] }
    } elseif ($profileSnapshot.PSObject.Properties.Name -contains "IntervalSeconds") {
        $intervalValue = $profileSnapshot.IntervalSeconds
    }
    if ($null -ne $intervalValue) {
        $interval = 0
        if (-not [int]::TryParse([string]$intervalValue, [ref]$interval) -or $interval -lt 5 -or $interval -gt 3600) {
            $issues += "IntervalSeconds out of range (5-3600)."
        }
    }
    if ($Strict) {
        $allowed = @($script:ProfilePropertyNames + $script:ProfileMetadataKeys)
        $unknown = @()
        if ($profileSnapshot -is [hashtable]) {
            foreach ($key in $profileSnapshot.Keys) {
                if (-not ($allowed -contains [string]$key)) { $unknown += [string]$key }
            }
        } else {
            foreach ($prop in $profileSnapshot.PSObject.Properties.Name) {
                if (-not ($allowed -contains [string]$prop)) { $unknown += [string]$prop }
            }
        }
        if ($unknown.Count -gt 0) {
            $issues += ("Unknown profile keys blocked by strict mode: {0}" -f ((@($unknown | Select-Object -First 6)) -join ","))
        }
    }
    return [pscustomobject]@{ IsValid = ($issues.Count -eq 0); Issues = $issues }
}

function Get-ProfileReadOnly($profileSnapshot) {
    if (-not $profileSnapshot) { return $false }
    if ($profileSnapshot -is [hashtable]) {
        if ($profileSnapshot.ContainsKey("ReadOnly")) { return [bool]$profileSnapshot["ReadOnly"] }
        return $false
    }
    if ($profileSnapshot.PSObject.Properties.Name -contains "ReadOnly") { return [bool]$profileSnapshot.ReadOnly }
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
    } catch { Write-IgnoredCatch $_ }
    return ($pairs -join "|")
}

function Get-ProfileDiffSummary($currentSettings, $targetProfile, [int]$maxKeys = 10) {
    $current = Get-ProfileSnapshot $currentSettings
    $target = Migrate-ProfileSnapshot $targetProfile
    $changed = @()
    $changes = @()
    foreach ($name in $script:ProfilePropertyNames) {
        if ($script:ProfileMetadataKeys -contains $name) { continue }
        $oldVal = if ($current.PSObject.Properties.Name -contains $name) { $current.$name } else { "<missing>" }
        $newVal = if ($target -is [hashtable]) { if ($target.ContainsKey($name)) { $target[$name] } else { "<missing>" } } else { if ($target.PSObject.Properties.Name -contains $name) { $target.$name } else { "<missing>" } }
        if ($oldVal -ne $newVal) {
            $changed += $name
            $changes += [pscustomobject]@{
                Key = $name
                OldValue = $oldVal
                NewValue = $newVal
            }
        }
    }
    $summaryKeys = if ($changed.Count -gt 0) { ($changed | Select-Object -First $maxKeys) -join ", " } else { "" }
    $tail = if ($changed.Count -gt $maxKeys) { " (and $($changed.Count - $maxKeys) more)" } else { "" }
    $summary = if ($changed.Count -eq 0) { "No changes." } else { "Changes ($($changed.Count)): $summaryKeys$tail" }
    return [pscustomobject]@{
        Count = $changed.Count
        Keys = $changed
        Changes = $changes
        Summary = $summary
    }
}

function Get-ProfileDiffDisplayName([string]$key) {
    if ([string]::IsNullOrWhiteSpace($key)) { return "" }
    $map = @{
        "IntervalSeconds" = (L "Interval Seconds" "Interval Seconds")
        "RememberChoice" = (L "Remember Choice" "Remember Choice")
        "StartOnLaunch" = (L "Start on Launch" "Start on Launch")
        "RunOnceOnLaunch" = (L "Run Once on Launch" "Run Once on Launch")
        "AutoStartOnRestart" = (L "Auto Start on Restart" "Auto Start on Restart")
        "QuietMode" = (L "Quiet Mode" "Quiet Mode")
        "MinimalTrayTooltip" = (L "Tray Tooltip Style" "Tray Tooltip Style")
        "TooltipStyle" = (L "Tray Tooltip Style" "Tray Tooltip Style")
        "DisableBalloonTips" = (L "Disable Tray Balloon Tips" "Disable Tray Balloon Tips")
        "PauseDurationsMinutes" = (L "Pause Durations (minutes, comma-separated)" "Pause Durations (minutes, comma-separated)")
        "ScheduleOverrideEnabled" = (L "Schedule Override" "Schedule Override")
        "ScheduleEnabled" = (L "Schedule Enabled" "Schedule Enabled")
        "ScheduleStart" = (L "Schedule Start" "Schedule Start")
        "ScheduleEnd" = (L "Schedule End" "Schedule End")
        "ScheduleWeekdays" = (L "Schedule Weekdays (e.g., Mon,Tue,Wed)" "Schedule Weekdays (e.g., Mon,Tue,Wed)")
        "ScheduleSuspendUntil" = (L "Schedule Suspend Until" "Schedule Suspend Until")
        "SafeModeEnabled" = (L "Safe Mode Enabled" "Safe Mode Enabled")
        "SafeModeFailureThreshold" = (L "Safe Mode Failure Threshold" "Safe Mode Failure Threshold")
        "HotkeyToggle" = (L "Hotkey: Toggle Now" "Hotkey: Toggle Now")
        "HotkeyStartStop" = (L "Hotkey: Start/Stop" "Hotkey: Start/Stop")
        "HotkeyPauseResume" = (L "Hotkey: Pause/Resume" "Hotkey: Pause/Resume")
        "LogMaxBytes" = (L "Log Max Size (KB)" "Log Max Size (KB)")
        "LogMaxTotalBytes" = (L "Log Max Size (KB)" "Log Max Size (KB)")
        "ThemeMode" = (L "Theme Mode" "Theme Mode")
        "FontSize" = (L "Font Size (Tray)" "Font Size (Tray)")
        "SettingsFontSize" = (L "Settings Font Size" "Settings Font Size")
        "StatusColorRunning" = (L "Status Color (Running)" "Status Color (Running)")
        "StatusColorPaused" = (L "Status Color (Paused)" "Status Color (Paused)")
        "StatusColorStopped" = (L "Status Color (Stopped)" "Status Color (Stopped)")
        "CompactMode" = (L "Compact Mode" "Compact Mode")
    }
    if ($map.ContainsKey($key)) { return [string]$map[$key] }
    return ([regex]::Replace($key, "([a-z0-9])([A-Z])", '$1 $2'))
}

function Format-ProfileDiffValue($value, [string]$key = $null) {
    if ($null -eq $value) { return (L "N/A" "N/A") }
    $text = [string]$value
    if ([string]::IsNullOrWhiteSpace($text)) { return "(empty)" }
    if ($text -eq "<missing>") { return "(not set)" }
    if ($text -eq "<null>") { return (L "N/A" "N/A") }

    if ($value -is [bool]) {
        return (if ($value) { (L "On" "On") } else { (L "Off" "Off") })
    }
    if ($text -match '^(?i:true|false)$') {
        return (if ($text -match '^(?i:true)$') { (L "On" "On") } else { (L "Off" "Off") })
    }

    if ($key -in @("TooltipStyle", "ThemeMode")) {
        switch ($text.ToUpperInvariant()) {
            "MINIMAL" { return (L "Minimal" "Minimal") }
            "STANDARD" { return (L "Standard" "Standard") }
            "VERBOSE" { return (L "Verbose" "Verbose") }
            "AUTO" { return (L "Auto Detect" "Auto Detect") }
            "LIGHT" { return (L "Light" "Light") }
            "DARK" { return (L "Dark" "Dark") }
            "HIGH CONTRAST" { return (L "High Contrast" "High Contrast") }
        }
    }

    if ($key -in @("LogMaxBytes", "LogMaxTotalBytes")) {
        $bytes = 0
        if ([int64]::TryParse($text, [ref]$bytes)) {
            $kb = [math]::Round(($bytes / 1KB), 0)
            return ("{0} KB" -f $kb)
        }
    }

    if ($text.Length -gt 72) { return ($text.Substring(0, 69) + "...") }
    return $text
}

function Confirm-ProfileSwitch([string]$name, $targetProfile) {
    $script:ProfileApplySelectionPending = $false
    $script:ProfileSwitchSelectedKeys = @()
    $diff = Get-ProfileDiffSummary $settings $targetProfile
    if ($diff.Count -le 0) { return $true }
    $previewMax = 14
    $previewChanges = @($diff.Changes | Select-Object -First $previewMax)
    $remaining = [Math]::Max(0, $diff.Count - $previewChanges.Count)

    $form = New-Object System.Windows.Forms.Form
    $form.Text = (L "Confirm Profile Switch" "Confirm Profile Switch")
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MinimizeBox = $false
    $form.MaximizeBox = $false
    $form.ShowInTaskbar = $false
    $form.ClientSize = New-Object System.Drawing.Size(560, 390)
    $form.Icon = [System.Drawing.SystemIcons]::Question

    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = [System.Windows.Forms.DockStyle]::Fill
    $layout.ColumnCount = 1
    $layout.RowCount = 6
    $layout.Padding = New-Object System.Windows.Forms.Padding(12)
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))

    $header = New-Object System.Windows.Forms.Label
    $header.AutoSize = $true
    $header.Font = New-Object System.Drawing.Font($form.Font.FontFamily, 10, [System.Drawing.FontStyle]::Bold)
    $header.Text = [string]::Format((L "Switch to profile '{0}'?" "Switch to profile '{0}'?"), $name)

    $summary = New-Object System.Windows.Forms.Label
    $summary.AutoSize = $true
    $summary.Margin = New-Object System.Windows.Forms.Padding(0, 4, 0, 8)
    $summary.Text = [string]::Format((L "Select which changes to apply ({0}):" "Select which changes to apply ({0}):"), $diff.Count)

    $list = New-Object System.Windows.Forms.CheckedListBox
    $list.Dock = [System.Windows.Forms.DockStyle]::Fill
    $list.CheckOnClick = $true
    $list.HorizontalScrollbar = $true
    $list.IntegralHeight = $false
    $list.ScrollAlwaysVisible = $true
    $displayRows = @()
    foreach ($change in $previewChanges) {
        $field = Get-ProfileDiffDisplayName ([string]$change.Key)
        $oldText = Format-ProfileDiffValue $change.OldValue ([string]$change.Key)
        $newText = Format-ProfileDiffValue $change.NewValue ([string]$change.Key)
        $displayRows += [pscustomobject]@{
            Key = [string]$change.Key
            Text = "{0}: {1} -> {2}" -f $field, $oldText, $newText
        }
    }
    foreach ($row in $displayRows) {
        $idx = $list.Items.Add($row.Text)
        $list.SetItemChecked($idx, $true)
    }

    $quickButtons = New-Object System.Windows.Forms.FlowLayoutPanel
    $quickButtons.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
    $quickButtons.Dock = [System.Windows.Forms.DockStyle]::Fill
    $quickButtons.AutoSize = $true
    $quickButtons.WrapContents = $false

    $selectAllButton = New-Object System.Windows.Forms.Button
    $selectAllButton.Text = (L "Select All" "Select All")
    $selectAllButton.AutoSize = $true
    $selectAllButton.Add_Click({
        for ($i = 0; $i -lt $list.Items.Count; $i++) {
            $list.SetItemChecked($i, $true)
        }
    })

    $clearAllButton = New-Object System.Windows.Forms.Button
    $clearAllButton.Text = (L "Clear All" "Clear All")
    $clearAllButton.AutoSize = $true
    $clearAllButton.Margin = New-Object System.Windows.Forms.Padding(6, 0, 0, 0)
    $clearAllButton.Add_Click({
        for ($i = 0; $i -lt $list.Items.Count; $i++) {
            $list.SetItemChecked($i, $false)
        }
    })

    [void]$quickButtons.Controls.Add($selectAllButton)
    [void]$quickButtons.Controls.Add($clearAllButton)

    $tail = New-Object System.Windows.Forms.Label
    $tail.AutoSize = $true
    $tail.Margin = New-Object System.Windows.Forms.Padding(0, 8, 0, 0)
    $tail.Text = if ($remaining -gt 0) {
        [string]::Format((L "...and {0} more change(s). Save profile first if you need to compare all fields." "...and {0} more change(s). Save profile first if you need to compare all fields."), $remaining)
    } else {
        (L "Review and select the changes above before continuing." "Review and select the changes above before continuing.")
    }

    $buttons = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttons.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft
    $buttons.Dock = [System.Windows.Forms.DockStyle]::Fill
    $buttons.AutoSize = $true
    $buttons.WrapContents = $false
    $buttons.Margin = New-Object System.Windows.Forms.Padding(0, 12, 0, 0)

    $noButton = New-Object System.Windows.Forms.Button
    $noButton.Text = (L "No" "No")
    $noButton.Width = 100
    $noButton.DialogResult = [System.Windows.Forms.DialogResult]::No

    $yesButton = New-Object System.Windows.Forms.Button
    $yesButton.Text = (L "Yes" "Yes")
    $yesButton.Width = 100
    $yesButton.DialogResult = [System.Windows.Forms.DialogResult]::Yes

    [void]$buttons.Controls.Add($noButton)
    [void]$buttons.Controls.Add($yesButton)
    [void]$layout.Controls.Add($header, 0, 0)
    [void]$layout.Controls.Add($summary, 0, 1)
    [void]$layout.Controls.Add($list, 0, 2)
    [void]$layout.Controls.Add($quickButtons, 0, 3)
    [void]$layout.Controls.Add($tail, 0, 4)
    [void]$layout.Controls.Add($buttons, 0, 5)
    [void]$form.Controls.Add($layout)
    $form.AcceptButton = $yesButton
    $form.CancelButton = $noButton

    try {
        $result = $form.ShowDialog()
        if ($result -ne [System.Windows.Forms.DialogResult]::Yes) {
            $script:ProfileApplySelectionPending = $false
            $script:ProfileSwitchSelectedKeys = @()
            return $false
        }
        $selectedKeys = @()
        foreach ($checkedIndex in $list.CheckedIndices) {
            $idx = [int]$checkedIndex
            if ($idx -ge 0 -and $idx -lt $displayRows.Count) {
                $selectedKeys += [string]$displayRows[$idx].Key
            }
        }
        if ($selectedKeys.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                (L "Select at least one change to apply." "Select at least one change to apply."),
                (L "No Changes Selected" "No Changes Selected"),
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            $script:ProfileApplySelectionPending = $false
            $script:ProfileSwitchSelectedKeys = @()
            return $false
        }
        $script:ProfileSwitchSelectedKeys = @($selectedKeys | Select-Object -Unique)
        $script:ProfileApplySelectionPending = $true
        return $true
    } finally {
        $form.Dispose()
    }
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
    } catch { Write-IgnoredCatch $_ }
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

function Apply-ProfileSnapshot($target, $profileSnapshot) {
    $profileSnapshot = Migrate-ProfileSnapshot $profileSnapshot
    $applySelection = [bool]$script:ProfileApplySelectionPending
    $selectedKeys = @()
    if ($applySelection -and ($script:ProfileSwitchSelectedKeys -is [System.Collections.IEnumerable])) {
        $selectedKeys = @($script:ProfileSwitchSelectedKeys | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    $strictProfileValidation = $false
    try {
        if ($settings -and ($settings.PSObject.Properties.Name -contains "SecurityModeEnabled") -and [bool]$settings.SecurityModeEnabled) { $strictProfileValidation = $true }
        if ($settings -and ($settings.PSObject.Properties.Name -contains "StrictProfileImport") -and [bool]$settings.StrictProfileImport) { $strictProfileValidation = $true }
    } catch { Write-IgnoredCatch $_ }
    $validation = Test-ProfileSnapshot $profileSnapshot -Strict:$strictProfileValidation
    if (-not $validation.IsValid) {
        $msg = "Profile is invalid: " + (($validation.Issues | Select-Object -First 4) -join ", ")
        Write-Log $msg "WARN" $null "Profiles"
        $script:ProfileApplySelectionPending = $false
        $script:ProfileSwitchSelectedKeys = @()
        return $target
    }
    $overrideSchedule = $true
    $hasOverrideFlag = $false
    if ($profileSnapshot -is [hashtable]) {
        if ($profileSnapshot.ContainsKey("ScheduleOverrideEnabled")) {
            $overrideSchedule = [bool]$profileSnapshot["ScheduleOverrideEnabled"]
            $hasOverrideFlag = $true
        }
    } elseif ($profileSnapshot -and ($profileSnapshot.PSObject.Properties.Name -contains "ScheduleOverrideEnabled")) {
        $overrideSchedule = [bool]$profileSnapshot.ScheduleOverrideEnabled
        $hasOverrideFlag = $true
    }
    if (-not $hasOverrideFlag) {
        if ((-not $applySelection) -or ($selectedKeys -contains "ScheduleOverrideEnabled")) {
            Set-SettingsPropertyValue $target "ScheduleOverrideEnabled" $overrideSchedule
        }
    }
    foreach ($name in $script:ProfilePropertyNames) {
        if ($applySelection -and $selectedKeys.Count -gt 0 -and ($selectedKeys -notcontains $name)) {
            continue
        }
        if (-not $overrideSchedule -and $name -in @("ScheduleEnabled", "ScheduleStart", "ScheduleEnd", "ScheduleWeekdays", "ScheduleSuspendUntil")) {
            continue
        }
        if ($profileSnapshot -is [hashtable]) {
            if ($profileSnapshot.ContainsKey($name)) {
                Set-SettingsPropertyValue $target $name $profileSnapshot[$name]
            }
        } elseif ($profileSnapshot.PSObject.Properties.Name -contains $name) {
            Set-SettingsPropertyValue $target $name $profileSnapshot.$name
        }
    }
    $script:ProfileApplySelectionPending = $false
    $script:ProfileSwitchSelectedKeys = @()
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

function New-ProfileSnapshotClone($settings) {
    $snapshot = Get-ProfileSnapshot $settings
    if (-not $snapshot) { return $null }
    $json = $snapshot | ConvertTo-Json -Depth 6
    return (ConvertFrom-Json $json)
}

function Ensure-StockProfiles($settings) {
    if (-not $settings) { return $false }
    $changed = $false
    if (-not ($settings.PSObject.Properties.Name -contains "Profiles") -or -not ($settings.Profiles -is [hashtable])) {
        $settings.Profiles = @{}
        $changed = $true
    }
    $profileKeys = @(Get-ObjectKeys $settings.Profiles)
    if ($profileKeys.Count -eq 0) {
        foreach ($profileName in @("Default", "Home", "Work")) {
            $settings.Profiles[$profileName] = New-ProfileSnapshotClone $settings
            $changed = $true
        }
    } elseif (-not ($profileKeys -contains "Default")) {
        $settings.Profiles["Default"] = New-ProfileSnapshotClone $settings
        $changed = $true
    }
    $activeName = if ($settings.PSObject.Properties.Name -contains "ActiveProfile") { [string]$settings.ActiveProfile } else { "" }
    if ([string]::IsNullOrWhiteSpace($activeName) -or -not ((Get-ObjectKeys $settings.Profiles) -contains $activeName)) {
        $settings.ActiveProfile = "Default"
        $changed = $true
    }
    return $changed
}

# --- Default settings and initial load (first-run) ---
$defaultSettings = [pscustomobject]@{
    SchemaVersion = $script:SettingsSchemaVersion
    SettingsSequence = 0
    IntervalSeconds = 60
    ScrollLockReleaseDelayMs = $script:ScrollLockReleaseDelayDefaultMs
    StartWithWindows = $false
    RememberChoice = $true
    StartOnLaunch = $false
    AutoStartOnRestart = $false
    QuietMode = $true
    DisableBalloonTips = $false
    OpenSettingsAtLastTab = $true
    LastSettingsTab = "General"
    DateTimeFormat = $script:DateTimeFormatDefault
    UseSystemDateTimeFormat = $true
    SystemDateTimeFormatMode = "Short"
    ShowFirstRunToast = $true
    FirstRunToastShown = $false
    FirstRunWizardCompleted = $false
    AutoCorrectedNoticeSeen = $false
    UiLanguage = "auto"
    BadgeTrackingMode = "Global"
    ToggleCount = 0
    LastToggleTime = $null
    Stats = @{
        InstallDate = (Get-Date).ToString("o")
        TotalRunMinutes = 0
        DailyToggles = @{}
        HourlyToggles = @{}
        LongestPauseMinutes = 0
        LongestPauseAt = $null
        CrashFreeSince = (Get-Date).ToString("o")
        ProfileUsageMinutes = @{}
        ReliableMinutes = 0
        DegradedMinutes = 0
        LifetimeToggleCount = 0
        ProfileLifetimeToggles = @{}
        ProfileLifetimeHighWater = @{}
        BadgeUnlocked = @{}
        BadgeHistory = @()
        BadgePoints = 0
        BadgeLevel = 1
        BadgeLevelProgressPct = 0.0
        BadgeLastUnlockId = ""
        BadgeLastUnlockAt = $null
        BadgeCurrentSeason = ""
        BadgeCatalogVersion = 1
        BadgePointsHighWater = 0
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
    SecurityModeEnabled = $false
    StrictSettingsImport = $false
    StrictProfileImport = $true
    StrictUpdatePolicy = $true
    RequireScriptSignature = $false
    TrustedSignerThumbprints = ""
    AutoUpdateEnabled = $true
    UpdateOwner = $script:SecurityDefaultUpdateOwner
    UpdateRepo = $script:SecurityDefaultUpdateRepo
    UpdateRequireHash = $true
    UpdateAllowDowngrade = $false
    UpdateAllowPrerelease = $false
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
    ScrubDiagnostics = $true
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
        Security = $true
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
        "AutoStartOnRestart",
        "DateTimeFormat",
        "UseSystemDateTimeFormat",
        "SystemDateTimeFormatMode",
        "ShowFirstRunToast",
        "BadgeTrackingMode"
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
        "AutoUpdateEnabled",
        "SecurityModeEnabled",
        "StrictSettingsImport",
        "StrictProfileImport",
        "StrictUpdatePolicy",
        "RequireScriptSignature",
        "TrustedSignerThumbprints",
        "UpdateOwner",
        "UpdateRepo",
        "UpdateRequireHash",
        "UpdateRequireSignature",
        "UpdateAllowDowngrade",
        "UpdateAllowPrerelease",
        "AllowExternalPaths",
        "HardenPermissions"
    )
    Profiles = @(
        "ActiveProfile",
        "Profiles"
    )
}

$settingsLoadedFromFile = $true
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
    try { Purge-SettingsBackups } catch { Write-IgnoredCatch $_ }
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
if (Ensure-StockProfiles $settings) {
    $profilesChanged = $true
    $settingsRepairPerformed = $true
}

foreach ($name in @(Get-ObjectKeys $settings.Profiles)) {
    $currentProfile = $settings.Profiles[$name]
    $currentProfile = Migrate-ProfileSnapshot $currentProfile
    $strictProfileValidation = ([bool]$settings.SecurityModeEnabled -or [bool]$settings.StrictProfileImport)
    $validation = Test-ProfileSnapshot $currentProfile -Strict:$strictProfileValidation
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
        $settings.Profiles[$name] = $currentProfile
        Update-ProfileLastGood $name $currentProfile
    }
}
$rollbackCheck = Test-RollbackProtectionState $settings
if ($rollbackCheck.VersionRollbackDetected) {
    Write-Log ("Rollback protection: app version rollback detected (current={0}, highest={1})." -f $appVersion, $rollbackCheck.HighestVersion) "WARN" $null "Security"
    if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) {
        Write-SecurityAuditEvent "VersionRollbackDetected" ("Current={0}|Highest={1}" -f $appVersion, $rollbackCheck.HighestVersion) "WARN" "Settings-Rollback"
    }
}
if ($rollbackCheck.SettingsRollbackDetected) {
    $targetSequence = [Math]::Max(([int]$rollbackCheck.HighestSettingsSequence + 1), 1)
    Set-SettingsPropertyValue $settings "SettingsSequence" $targetSequence
    $profilesChanged = $true
    $settingsRepairPerformed = $true
    Write-Log ("Rollback protection: settings sequence rollback detected (current={0}, highest={1}); sequence advanced to {2}." -f $rollbackCheck.SettingsSequence, $rollbackCheck.HighestSettingsSequence, $targetSequence) "WARN" $null "Security"
    if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) {
        Write-SecurityAuditEvent "SettingsRollbackDetected" ("Current={0}|Highest={1}|Forced={2}" -f $rollbackCheck.SettingsSequence, $rollbackCheck.HighestSettingsSequence, $targetSequence) "WARN" "Settings-Rollback"
    }
}
$requestedAllowExternalPaths = [bool]$settings.AllowExternalPaths
$effectiveAllowExternalPaths = Get-EffectiveAllowExternalPaths $requestedAllowExternalPaths
if ($effectiveAllowExternalPaths -ne $requestedAllowExternalPaths) {
    $settings.AllowExternalPaths = $effectiveAllowExternalPaths
    $profilesChanged = $true
    $settingsRepairPerformed = $true
    Write-Log "AllowExternalPaths disabled by installed mode policy." "INFO" $null "Settings"
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

$desiredSettingsDir = Resolve-DirectoryOrDefault ([string]$settings.SettingsDirectory) $defaultSettingsDir "Settings" ([bool]$settings.AllowExternalPaths)
Set-SettingsDirectory $desiredSettingsDir -SkipLog
Load-ProfilesLastGood

$desiredLogDir = Resolve-DirectoryOrDefault ([string]$settings.LogDirectory) $defaultLogDir "Logs" ([bool]$settings.AllowExternalPaths)
Set-LogDirectory $desiredLogDir -SkipLog

$pathSettingsChanged = $false
$resolvedSettingsRel = Convert-ToRelativePathIfUnderRoot $script:SettingsDirectory
$resolvedLogRel = Convert-ToRelativePathIfUnderRoot $script:LogDirectory
$currentSettingsDirValue = [string](Get-SettingsPropertyValue $settings "SettingsDirectory" "")
$currentLogDirValue = [string](Get-SettingsPropertyValue $settings "LogDirectory" "")
if ($currentSettingsDirValue -ne $resolvedSettingsRel) {
    Set-SettingsPropertyValue $settings "SettingsDirectory" $resolvedSettingsRel
    $pathSettingsChanged = $true
}
if ($currentLogDirValue -ne $resolvedLogRel) {
    Set-SettingsPropertyValue $settings "LogDirectory" $resolvedLogRel
    $pathSettingsChanged = $true
}
if ($pathSettingsChanged) {
    try {
        Save-Settings $settings -Immediate
        $settingsAutoSaved = $true
        $settingsRepairPerformed = $true
        Write-Log "Settings paths were normalized to app-local directories." "INFO" $null "Settings"
    } catch {
        Write-Log "Failed to persist normalized settings/log paths." "WARN" $_.Exception "Settings"
    }
}

if ($settings.PSObject.Properties.Name -contains "HardenPermissions") {
    if ([bool]$settings.HardenPermissions) {
        try { Harden-AppPermissions } catch { Write-IgnoredCatch $_ }
    }
}

function Invoke-ScriptSignaturePolicyCheck([switch]$Enforce) {
    try {
        $signaturePolicy = Test-ScriptSignaturePolicy $scriptPath ([bool]$Enforce)
        $script:ScriptSignatureStatus = [string]$signaturePolicy.Status
        $script:ScriptSignatureThumbprint = [string]$signaturePolicy.Thumbprint
        if ($signaturePolicy.IsValid) {
            Write-Log ("Script signature verified. Status={0}" -f $signaturePolicy.Status) "INFO" $null "Security"
        } else {
            $reason = if ([string]::IsNullOrWhiteSpace([string]$signaturePolicy.Reason)) { "signature check failed" } else { [string]$signaturePolicy.Reason }
            $level = if ($signaturePolicy.Enforced) { "ERROR" } else { "INFO" }
            $signatureMessage = if ($signaturePolicy.Enforced) {
                "Script signature not trusted: {0}" -f $reason
            } else {
                "Script signature not trusted (enforcement disabled): {0}" -f $reason
            }
            Write-Log $signatureMessage $level $null "Security"
            if ($signaturePolicy.Enforced) {
                $script:IntegrityFailed = $true
                $script:IntegrityStatus = "SignatureFailed"
                $script:IntegrityIssues += "Authenticode verification failed"
            }
        }
    } catch {
        Write-Log "Script signature policy check failed unexpectedly." "WARN" $_.Exception "Security"
    }
}

$signatureEnforced = ($settings.PSObject.Properties.Name -contains "RequireScriptSignature" -and [bool]$settings.RequireScriptSignature)
if ($signatureEnforced) {
    Invoke-ScriptSignaturePolicyCheck -Enforce
} else {
    $script:PendingSignaturePolicyCheck = $true
    $script:ScriptSignatureStatus = "Deferred"
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
    if (-not ($settings.PSObject.Properties.Name -contains "AutoCorrectedNoticeSeen")) {
        Set-SettingsPropertyValue $settings "AutoCorrectedNoticeSeen" $false
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
$script:BadgeTrackingModeLastApplied = [string](Get-SettingsPropertyValue $settings "BadgeTrackingMode" "Global")
if (-not $script:SaveSettingsPending) {
    Update-RollbackStateFromSettings $settings
}
Write-BootStage "Settings ready"

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
            CrashFreeSince = (Get-Date).ToString("o")
            ProfileUsageMinutes = @{}
            ReliableMinutes = 0
            DegradedMinutes = 0
            LifetimeToggleCount = 0
            ProfileLifetimeToggles = @{}
            ProfileLifetimeHighWater = @{}
            BadgeUnlocked = @{}
            BadgeHistory = @()
            BadgePoints = 0
            BadgeLevel = 1
            BadgeLevelProgressPct = 0.0
            BadgeLastUnlockId = ""
            BadgeLastUnlockAt = $null
            BadgeCurrentSeason = ""
            BadgeCatalogVersion = 1
            BadgePointsHighWater = 0
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
if ($script:PendingRuntimeFromSettings -and $script:PendingRuntimeFromSettings.Count -gt 0) {
    Apply-RuntimeOverridesToState $state $script:PendingRuntimeFromSettings | Out-Null
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
            } catch { Write-IgnoredCatch $_ }
        }
        if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
            $positionLine = "Position: " + $_.InvocationInfo.PositionMessage.Trim()
            if (Get-Command -Name Write-Log -ErrorAction SilentlyContinue) {
                Write-Log $positionLine "FATAL" $_.Exception "Trap"
            } elseif (Get-Command -Name Write-BootstrapLog -ErrorAction SilentlyContinue) {
                Write-BootstrapLog $positionLine "ERROR"
            }
        }
        try { Flush-LogBuffer } catch { Write-IgnoredCatch $_ }
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

function Get-CrashRecoveryTier([int]$crashCount) {
    if ($crashCount -ge 6) { return 3 }
    if ($crashCount -ge 4) { return 2 }
    if ($crashCount -ge 2) { return 1 }
    return 0
}

function Invoke-CrashRecoveryTierActions($settingsRef, $crashState) {
    $crashCount = 0
    try { $crashCount = [int]$crashState.Count } catch { $crashCount = 0 }
    $tier = Get-CrashRecoveryTier $crashCount
    $script:CrashRecoveryTier = $tier
    if ($tier -lt 1) { return $tier }

    $script:SelfHealStats.CrashTierActions = [int]$script:SelfHealStats.CrashTierActions + 1
    if ($tier -ge 2) {
        $script:DeferredStartupSkipUpdate = $true
        Write-LogThrottled "CrashRecovery-SkipUpdate" "Crash recovery: deferred update checks are temporarily disabled for this session." "WARN" 60
    }
    if ($tier -ge 3 -and $settingsRef) {
        $changed = $false
        if ([bool](Get-SettingsPropertyValue $settingsRef "StartOnLaunch" $false)) {
            Set-SettingsPropertyValue $settingsRef "StartOnLaunch" $false
            $changed = $true
        }
        if ([bool](Get-SettingsPropertyValue $settingsRef "RunOnceOnLaunch" $false)) {
            Set-SettingsPropertyValue $settingsRef "RunOnceOnLaunch" $false
            $changed = $true
        }
        if ($changed) {
            try {
                Save-SettingsImmediate $settingsRef
                Write-Log "Crash recovery: startup auto-run settings were disabled after repeated crashes." "WARN" $null "Startup"
            } catch {
                Write-LogExceptionDeduped "Crash recovery failed while disabling startup auto-run settings." "WARN" $_.Exception "Startup" 60
            }
        }
    }
    return $tier
}

$previousShutdown = Get-ShutdownMarker
$restartMarkerTriggered = $false
try { $restartMarkerTriggered = Consume-RestartRequestMarker 300 } catch { $restartMarkerTriggered = $false }
if (-not $script:RelaunchedFromRestart -and $restartMarkerTriggered) {
    $script:RelaunchedFromRestart = $true
}
if ($script:RelaunchedFromRestart) {
    Write-Log "Startup relaunch context detected." "INFO" $null "Startup"
}
$crashState = Get-CrashState
$overrideMinimal = $false
if ($crashState -and ($crashState.PSObject.Properties.Name -contains "OverrideMinimalMode")) {
    $overrideMinimal = [bool]$crashState.OverrideMinimalMode
}
$savedMinimalState = Get-SavedMinimalModeState
if (-not $overrideMinimal -and $savedMinimalState -and ($savedMinimalState.PSObject.Properties.Name -contains "Override") -and [bool]$savedMinimalState.Override) {
    $overrideMinimal = $true
    try {
        if ($crashState -and ($crashState.PSObject.Properties.Name -contains "OverrideMinimalMode")) {
            $crashState.OverrideMinimalMode = $true
            Save-CrashState $crashState
        }
    } catch { Write-IgnoredCatch $_ }
    Write-Log "Startup: minimal mode override restored from persisted state." "INFO" $null "Startup"
}
$script:OverrideMinimalMode = $overrideMinimal
if ($previousShutdown -and $previousShutdown -ne "clean") {
    Write-Log "Crash detected: previous session did not exit cleanly." "WARN" $null "Startup"
    $recoveryTier = 0
    try {
        try { Mark-FunStatsCrashEvent } catch { Write-IgnoredCatch $_ }
        $crashState.Count = [int]$crashState.Count + 1
        $crashState.LastCrash = (Get-Date).ToString("o")
        Save-CrashState $crashState
        $recoveryTier = Invoke-CrashRecoveryTierActions $settings $crashState
        if (-not $script:OverrideMinimalMode -and $recoveryTier -ge 1) {
            $script:MinimalModeActive = $true
            $script:MinimalModeReason = "Detected $($crashState.Count) crashes in a row."
            Write-Log ("Minimal mode enabled: {0}" -f $script:MinimalModeReason) "WARN" $null "Startup"
        }
    } catch { Write-IgnoredCatch $_ }
    Clear-StaleRuntimeState "unclean shutdown"
    try {
        $lastGood = Load-LastGoodSettings
        if ($lastGood) {
            $autoRestore = ($recoveryTier -ge 2)
            $shouldRestore = $false
            if ($autoRestore) {
                $shouldRestore = $true
                Write-Log "Crash recovery: auto-restoring last known good settings due to repeated crashes." "WARN" $null "Startup"
            } else {
                $choice = [System.Windows.Forms.MessageBox]::Show(
                    "The previous session did not exit cleanly.`n`nRestore the last known good settings snapshot?",
                    "Crash Detected",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )
                $shouldRestore = ($choice -eq [System.Windows.Forms.DialogResult]::Yes)
            }
            if ($shouldRestore) {
                $settings = Migrate-Settings $lastGood
                $settings = Normalize-Settings $settings
                Save-SettingsImmediate $settings
                Write-Log "Restored settings from last known good snapshot." "WARN" $null "Startup"
            }
        }
    } catch { Write-IgnoredCatch $_ }
} else {
    $script:CrashRecoveryTier = 0
    $script:DeferredStartupSkipUpdate = $false
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
try { Sync-MinimalModeState "Startup" } catch { Write-IgnoredCatch $_ }
Write-BootStage "Crash state handled"
Set-ShutdownMarker "started"
Write-Log "" "INFO" $null "Init"
Write-Log "=======================================================================" "INFO" $null "Init"
Write-Log "=                              APP START                              =" "INFO" $null "Init"
Write-Log "=======================================================================" "INFO" $null "Init"
if ($script:LogLevel -eq "DEBUG") {
    Write-Log "Tag Key: E=EventId S=SessionID T=Type P=Profile C=Context Tab=Tab A=ActionId R=Result" "INFO" $null "Logging"
    Write-Log "=======================================================================" "INFO" $null "Init"
}
Write-Log (Get-PathHealthSummary) "DEBUG" $null "Init"
$buildStamp = if ($appBuildTimestamp) { Format-DateTime $appBuildTimestamp } else { "Unknown" }
Write-Log ("Session start: SessionID={0} Profile={1} LogLevel={2} Version={3} SchemaVersion={4} Build={5}" -f `
    $script:RunId, $settings.ActiveProfile, $settings.LogLevel, $appVersion, $script:SettingsSchemaVersion, $buildStamp) "INFO" $null "Init"
Write-Log ("Session path: LogPath={0}" -f $logPath) "INFO" $null "Init"
Write-Log ("Session path: SettingsPath={0}" -f $settingsPath) "INFO" $null "Init"
Write-Log ("Session path: StatePath={0}" -f $script:StatePath) "INFO" $null "Init"
Write-Log "Startup. ScriptPath=$scriptPath" "DEBUG" $null "Init"
Write-Log "Startup. SettingsPath=$settingsPath" "DEBUG" $null "Init"
Write-Log "Startup. LogPath=$logPath" "DEBUG" $null "Init"
$psVersion = $PSVersionTable.PSVersion
$osVersion = [Environment]::OSVersion.VersionString
$pidValue = $PID
Write-Log "Environment. PID=$pidValue PSVersion=$psVersion OS=$osVersion" "DEBUG" $null "Init"

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
        $shortcut.Arguments = "-NoProfile -ExecutionPolicy RemoteSigned -WindowStyle Hidden -File `"$scriptPath`""
    $shortcut.WorkingDirectory = $script:AppRoot
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
        if (item != null && item.Name == "TopStatusSummaryItem") {
            string text = item.Text ?? string.Empty;
            string statusPrefix = "Status: ";
            string statusValue = text;
            int idx = text.IndexOf(':');
            if (idx >= 0) {
                statusPrefix = text.Substring(0, idx + 1) + " ";
                statusValue = text.Substring(idx + 1).Trim();
            } else {
                statusValue = text.Trim();
            }
            if (statusValue == null) { statusValue = string.Empty; }
            Color stateColor = item.ForeColor.IsEmpty ? Color.Red : item.ForeColor;
            Rectangle rect = e.TextRectangle;
            TextRenderer.DrawText(e.Graphics, statusPrefix, e.TextFont, rect, ThemeColors.MenuText, TextFormatFlags.Left);
            Size prefixSize = TextRenderer.MeasureText(e.Graphics, statusPrefix, e.TextFont, rect.Size, TextFormatFlags.Left);
            Rectangle statusRect = new Rectangle(rect.X + prefixSize.Width, rect.Y, rect.Width - prefixSize.Width, rect.Height);
            TextRenderer.DrawText(e.Graphics, statusValue, e.TextFont, statusRect, stateColor, TextFormatFlags.Left);
            return;
        }
        if (item != null && (item.Name == "StatusStateItem" || item.Name == "TopStatusStateItem")) {
            string text = item.Text ?? string.Empty;
            string prefix = "Status: ";
            string state = string.Empty;
            int idx = text.IndexOf(':');
            if (idx >= 0) {
                prefix = text.Substring(0, idx + 1) + " ";
                state = text.Substring(idx + 1).Trim();
            } else if (!string.IsNullOrWhiteSpace(text)) {
                state = text.Trim();
            }
            if (string.IsNullOrWhiteSpace(state) && item.Tag != null) {
                state = item.Tag.ToString();
            }
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
    $releaseDelayMs = [int]$script:ScrollLockReleaseDelayDefaultMs
    try {
        if ($settings -and ($settings.PSObject.Properties.Name -contains "ScrollLockReleaseDelayMs")) {
            $releaseDelayMs = Normalize-ScrollLockReleaseDelayMs ([int]$settings.ScrollLockReleaseDelayMs)
        } else {
            $releaseDelayMs = Normalize-ScrollLockReleaseDelayMs $releaseDelayMs
        }
    } catch {
        $releaseDelayMs = [int]$script:ScrollLockReleaseDelayDefaultMs
    }
    [KeyboardSimulator]::keybd_event(0x91, 0, 0, 0)
    Start-Sleep -Milliseconds $releaseDelayMs
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
    } catch { Write-IgnoredCatch $_ }
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
$script:StatsLastSampleAt = $null
$script:StatsLastSampleProfile = $null

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

function Get-LifetimeCountFromStatsObject($stats, [int64]$fallback = 0) {
    $safeFallback = [int64][Math]::Max(0, [int64]$fallback)
    if (-not $stats) { return $safeFallback }
    try {
        if ($stats -is [System.Collections.IDictionary] -and $stats.ContainsKey("LifetimeToggleCount")) {
            return [int64][Math]::Max(0, [int64]$stats["LifetimeToggleCount"])
        }
        if ($stats.PSObject.Properties.Match("LifetimeToggleCount").Count -gt 0) {
            return [int64][Math]::Max(0, [int64]$stats.LifetimeToggleCount)
        }
    } catch { Write-IgnoredCatch $_ }
    return $safeFallback
}

function Get-PersistentLifetimeToggleCount {
    if ($script:LifetimeToggleHighWaterLoaded -and $script:LifetimeToggleHighWater -ge 0) {
        return [int64]$script:LifetimeToggleHighWater
    }
    $maxLifetime = 0L
    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($path in @($script:LifetimeStatsPath, $script:StatePath, $script:StateLastGoodPath)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$path)) { [void]$candidates.Add([string]$path) }
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$script:SettingsDirectory)) {
        foreach ($i in 1..3) {
            [void]$candidates.Add((Join-Path $script:SettingsDirectory ("Teams-Always-Green.state.json.bak{0}" -f $i)))
        }
    }
    foreach ($path in @($candidates | Select-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace([string]$path)) { continue }
        if (-not (Test-Path $path)) { continue }
        try {
            $raw = Get-Content -Path $path -Raw -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($raw)) { continue }
            $obj = $raw | ConvertFrom-Json -ErrorAction Stop
            $candidate = 0L
            if ($path -eq $script:LifetimeStatsPath) {
                if ($obj.PSObject.Properties.Match("LifetimeToggleCount").Count -gt 0) {
                    $candidate = [int64]$obj.LifetimeToggleCount
                }
            } elseif ($obj -and $obj.PSObject.Properties.Match("Stats").Count -gt 0) {
                $candidate = Get-LifetimeCountFromStatsObject $obj.Stats 0
            }
            if ($candidate -gt $maxLifetime) { $maxLifetime = $candidate }
        } catch { Write-IgnoredCatch $_ }
    }

    try {
        if ($script:PendingRuntimeFromSettings -and $script:PendingRuntimeFromSettings.ContainsKey("Stats")) {
            $pendingLifetime = Get-LifetimeCountFromStatsObject $script:PendingRuntimeFromSettings["Stats"] 0
            if ($pendingLifetime -gt $maxLifetime) { $maxLifetime = $pendingLifetime }
        }
    } catch { Write-IgnoredCatch $_ }

    if ($maxLifetime -lt 0) { $maxLifetime = 0L }
    $script:LifetimeToggleHighWater = [int64]$maxLifetime
    $script:LifetimeToggleHighWaterLoaded = $true
    return [int64]$script:LifetimeToggleHighWater
}

function Save-PersistentLifetimeToggleCount([int64]$count, [switch]$Force) {
    $safeCount = [int64][Math]::Max(0, [int64]$count)
    $currentHighWater = Get-PersistentLifetimeToggleCount
    if (-not $Force -and $safeCount -le $currentHighWater) { return }
    $script:LifetimeToggleHighWater = $safeCount
    $script:LifetimeToggleHighWaterLoaded = $true
    try {
        Ensure-Directory $script:MetaDir "Meta" | Out-Null
        $payload = [pscustomobject]@{
            LifetimeToggleCount = [int64]$safeCount
            UpdatedUtc = (Get-Date).ToUniversalTime().ToString("o")
        }
        $json = $payload | ConvertTo-Json -Depth 3
        Write-AtomicTextFile -Path $script:LifetimeStatsPath -Content $json -Encoding UTF8 -VerifyJson
    } catch {
        Write-LogThrottled "Lifetime-HighWater-Save" "Failed to persist lifetime high-water counter." "WARN" 120
    }
}

function Get-BadgeScopeKey([string]$trackingMode, [string]$profileName) {
    $mode = if ([string]::IsNullOrWhiteSpace($trackingMode)) { "Global" } else { $trackingMode }
    if ($mode -eq "Profile") {
        $safeProfile = if ([string]::IsNullOrWhiteSpace($profileName)) { "default" } else { $profileName.Trim().ToLowerInvariant() }
        return ("profile:{0}" -f $safeProfile)
    }
    return "global"
}

function Get-ScopedBadgeId([string]$baseId, [string]$trackingMode, [string]$profileName) {
    $safeBase = if ([string]::IsNullOrWhiteSpace($baseId)) { "badge-unknown" } else { $baseId }
    $scope = Get-BadgeScopeKey $trackingMode $profileName
    return ("{0}::{1}" -f $safeBase, $scope)
}

function Invoke-BadgeTrackingModeMigration($settingsRef, [string]$previousMode, [string]$newMode) {
    if (-not $settingsRef) { return $false }

    $normalizeMode = {
        param([string]$modeValue)
        $raw = if ([string]::IsNullOrWhiteSpace($modeValue)) { "Global" } else { $modeValue.Trim() }
        if ($raw.ToLowerInvariant() -eq "profile") { return "Profile" }
        return "Global"
    }
    $fromMode = & $normalizeMode $previousMode
    $toMode = & $normalizeMode $newMode
    if ($fromMode -eq $toMode) { return $false }

    $stats = Convert-ToHashtable (Get-SettingsPropertyValue $settingsRef "Stats" @{})
    if (-not $stats) { $stats = @{} }
    $stats = Ensure-BadgeStats $stats $settingsRef
    $activeProfile = [string](Get-SettingsPropertyValue $settingsRef "ActiveProfile" "Default")
    if ([string]::IsNullOrWhiteSpace($activeProfile)) { $activeProfile = "Default" }

    $globalScope = "global"
    $profileScope = Get-BadgeScopeKey "Profile" $activeProfile
    $unlockedMap = Convert-ToHashtable $stats["BadgeUnlocked"]
    $history = @($stats["BadgeHistory"])
    $historyIds = @{}
    foreach ($entry in @($history)) {
        if (-not $entry) { continue }
        $entryId = ""
        try { $entryId = [string]$entry.Id } catch { $entryId = "" }
        if (-not [string]::IsNullOrWhiteSpace($entryId)) { $historyIds[$entryId] = $true }
    }

    $newEntries = 0
    $changed = $false

    if ($fromMode -eq "Global" -and $toMode -eq "Profile") {
        $globalLifetime = Get-LifetimeCountFromStatsObject $stats 0
        $profileLifetime = Get-ProfileLifetimeToggleCount $stats $activeProfile $globalLifetime
        if ($globalLifetime -gt $profileLifetime) {
            Set-ProfileLifetimeToggleCount $stats $activeProfile ([int64]$globalLifetime)
            $changed = $true
        }

        foreach ($id in @($unlockedMap.Keys)) {
            $entry = Convert-ToHashtable $unlockedMap[$id]
            if ($entry.Count -eq 0) { continue }
            $entryScope = if ($entry.ContainsKey("Scope")) { [string]$entry["Scope"] } else { "" }
            if ([string]::IsNullOrWhiteSpace($entryScope)) {
                $entryScope = if ([string]$id -like "*::profile:*") { "profile:unknown" } else { "global" }
            }
            if ($entryScope -ne $globalScope) { continue }

            $baseId = if ($entry.ContainsKey("BaseId") -and -not [string]::IsNullOrWhiteSpace([string]$entry["BaseId"])) {
                [string]$entry["BaseId"]
            } elseif ([string]$id -match "^(.*)::") {
                [string]$Matches[1]
            } else {
                [string]$id
            }
            $profileId = Get-ScopedBadgeId $baseId "Profile" $activeProfile
            if ($unlockedMap.ContainsKey($profileId)) { continue }

            $newEntry = @{}
            foreach ($key in @($entry.Keys)) { $newEntry[$key] = $entry[$key] }
            $newEntry["Id"] = $profileId
            $newEntry["BaseId"] = $baseId
            $newEntry["Scope"] = $profileScope
            $newEntry["Profile"] = $activeProfile
            if (-not $newEntry.ContainsKey("UnlockedAt") -or [string]::IsNullOrWhiteSpace([string]$newEntry["UnlockedAt"])) {
                $newEntry["UnlockedAt"] = (Get-Date).ToString("o")
            }
            $unlockedMap[$profileId] = $newEntry
            if (-not $historyIds.ContainsKey($profileId)) {
                $history += [pscustomobject]@{
                    Id = $profileId
                    Name = if ($newEntry.ContainsKey("Name")) { [string]$newEntry["Name"] } else { $profileId }
                    Kind = if ($newEntry.ContainsKey("Kind")) { [string]$newEntry["Kind"] } else { "Milestone" }
                    Rarity = if ($newEntry.ContainsKey("Rarity")) { [string]$newEntry["Rarity"] } else { "Common" }
                    Tier = if ($newEntry.ContainsKey("Tier")) { [string]$newEntry["Tier"] } else { "Bronze" }
                    Scope = if ($newEntry.ContainsKey("Scope")) { [string]$newEntry["Scope"] } else { $profileScope }
                    Icon = if ($newEntry.ContainsKey("Icon")) { [string]$newEntry["Icon"] } else { (Get-BadgeRarityIcon "Common") }
                    Points = if ($newEntry.ContainsKey("Points")) { [int]$newEntry["Points"] } else { 0 }
                    UnlockedAt = if ($newEntry.ContainsKey("UnlockedAt")) { [string]$newEntry["UnlockedAt"] } else { (Get-Date).ToString("o") }
                    Profile = if ($newEntry.ContainsKey("Profile")) { [string]$newEntry["Profile"] } else { $activeProfile }
                }
                $historyIds[$profileId] = $true
            }
            $newEntries++
            $changed = $true
        }
    } elseif ($fromMode -eq "Profile" -and $toMode -eq "Global") {
        $profileMap = Convert-ToHashtable $stats["ProfileLifetimeToggles"]
        $maxProfileLifetime = 0L
        foreach ($profileKey in @($profileMap.Keys)) {
            $value = 0L
            try { $value = [int64][Math]::Max(0, [int64]$profileMap[$profileKey]) } catch { $value = 0L }
            if ($value -gt $maxProfileLifetime) { $maxProfileLifetime = $value }
        }
        $currentLifetime = Get-LifetimeCountFromStatsObject $stats 0
        if ($maxProfileLifetime -gt $currentLifetime) {
            $stats["LifetimeToggleCount"] = [int64]$maxProfileLifetime
            Save-PersistentLifetimeToggleCount ([int64]$maxProfileLifetime)
            $changed = $true
        }

        foreach ($id in @($unlockedMap.Keys)) {
            $entry = Convert-ToHashtable $unlockedMap[$id]
            if ($entry.Count -eq 0) { continue }
            $entryScope = if ($entry.ContainsKey("Scope")) { [string]$entry["Scope"] } else { "" }
            if ([string]::IsNullOrWhiteSpace($entryScope)) {
                $entryScope = if ([string]$id -like "*::profile:*") { "profile:unknown" } else { "global" }
            }
            if (-not $entryScope.StartsWith("profile:", [System.StringComparison]::OrdinalIgnoreCase)) { continue }

            $baseId = if ($entry.ContainsKey("BaseId") -and -not [string]::IsNullOrWhiteSpace([string]$entry["BaseId"])) {
                [string]$entry["BaseId"]
            } elseif ([string]$id -match "^(.*)::") {
                [string]$Matches[1]
            } else {
                [string]$id
            }
            $globalId = Get-ScopedBadgeId $baseId "Global" $activeProfile
            if ($unlockedMap.ContainsKey($globalId)) { continue }

            $newEntry = @{}
            foreach ($key in @($entry.Keys)) { $newEntry[$key] = $entry[$key] }
            $newEntry["Id"] = $globalId
            $newEntry["BaseId"] = $baseId
            $newEntry["Scope"] = $globalScope
            $newEntry["Profile"] = ""
            if (-not $newEntry.ContainsKey("UnlockedAt") -or [string]::IsNullOrWhiteSpace([string]$newEntry["UnlockedAt"])) {
                $newEntry["UnlockedAt"] = (Get-Date).ToString("o")
            }
            $unlockedMap[$globalId] = $newEntry
            if (-not $historyIds.ContainsKey($globalId)) {
                $history += [pscustomobject]@{
                    Id = $globalId
                    Name = if ($newEntry.ContainsKey("Name")) { [string]$newEntry["Name"] } else { $globalId }
                    Kind = if ($newEntry.ContainsKey("Kind")) { [string]$newEntry["Kind"] } else { "Milestone" }
                    Rarity = if ($newEntry.ContainsKey("Rarity")) { [string]$newEntry["Rarity"] } else { "Common" }
                    Tier = if ($newEntry.ContainsKey("Tier")) { [string]$newEntry["Tier"] } else { "Bronze" }
                    Scope = if ($newEntry.ContainsKey("Scope")) { [string]$newEntry["Scope"] } else { $globalScope }
                    Icon = if ($newEntry.ContainsKey("Icon")) { [string]$newEntry["Icon"] } else { (Get-BadgeRarityIcon "Common") }
                    Points = if ($newEntry.ContainsKey("Points")) { [int]$newEntry["Points"] } else { 0 }
                    UnlockedAt = if ($newEntry.ContainsKey("UnlockedAt")) { [string]$newEntry["UnlockedAt"] } else { (Get-Date).ToString("o") }
                    Profile = if ($newEntry.ContainsKey("Profile")) { [string]$newEntry["Profile"] } else { "" }
                }
                $historyIds[$globalId] = $true
            }
            $newEntries++
            $changed = $true
        }
    }

    if (-not $changed) { return $false }

    if ($history.Count -gt 300) { $history = @($history | Select-Object -Last 300) }
    $stats["BadgeUnlocked"] = $unlockedMap
    $stats["BadgeHistory"] = $history
    $stats = Ensure-BadgeStats $stats $settingsRef
    $badgeRecalc = Update-BadgeProgress $stats $settingsRef (Get-Date)
    if ($badgeRecalc -and $badgeRecalc.PSObject.Properties.Name -contains "Stats") {
        $stats = Convert-ToHashtable $badgeRecalc.Stats
    }
    Set-SettingsPropertyValue $settingsRef "Stats" $stats
    Write-Log ("Badge scope migration applied: {0} -> {1} (active={2}, cloned={3})" -f $fromMode, $toMode, $activeProfile, $newEntries) "INFO" $null "Badges"
    return $true
}

function Get-ProfileLifetimeToggleCount($stats, [string]$profileName, [int64]$fallback = 0) {
    if (-not $stats) { return [int64][Math]::Max(0, [int64]$fallback) }
    $safeProfile = if ([string]::IsNullOrWhiteSpace($profileName)) { "Default" } else { $profileName }
    $profileMap = Convert-ToHashtable $stats["ProfileLifetimeToggles"]
    if ($profileMap.ContainsKey($safeProfile)) {
        try { return [int64][Math]::Max(0, [int64]$profileMap[$safeProfile]) } catch { Write-IgnoredCatch $_ }
    }
    return [int64][Math]::Max(0, [int64]$fallback)
}

function Set-ProfileLifetimeToggleCount($stats, [string]$profileName, [int64]$count) {
    if (-not $stats) { return }
    $safeProfile = if ([string]::IsNullOrWhiteSpace($profileName)) { "Default" } else { $profileName }
    $safeCount = [int64][Math]::Max(0, [int64]$count)
    $profileMap = Convert-ToHashtable $stats["ProfileLifetimeToggles"]
    $highWaterMap = Convert-ToHashtable $stats["ProfileLifetimeHighWater"]
    $existingHigh = 0L
    if ($highWaterMap.ContainsKey($safeProfile)) {
        try { $existingHigh = [int64][Math]::Max(0, [int64]$highWaterMap[$safeProfile]) } catch { $existingHigh = 0L }
    }
    if ($safeCount -lt $existingHigh) { $safeCount = $existingHigh }
    $profileMap[$safeProfile] = $safeCount
    if ($safeCount -gt $existingHigh) { $highWaterMap[$safeProfile] = $safeCount }
    $stats["ProfileLifetimeToggles"] = $profileMap
    $stats["ProfileLifetimeHighWater"] = $highWaterMap
}

function Get-EffectiveBadgeToggleCount($stats, $settingsRef, [string]$profileName = "Default") {
    $trackingMode = Get-BadgeTrackingMode $settingsRef
    $globalCount = Get-LifetimeCountFromStatsObject $stats 0
    if ($trackingMode -eq "Profile") {
        return [int64][Math]::Max(0, (Get-ProfileLifetimeToggleCount $stats $profileName $globalCount))
    }
    return [int64][Math]::Max(0, $globalCount)
}

function Ensure-BadgeStats($stats, $settingsRef = $null) {
    if (-not $stats) { $stats = @{} }
    $trackingMode = Get-BadgeTrackingMode $settingsRef
    $activeProfile = "Default"
    try {
        $activeProfile = [string](Get-SettingsPropertyValue $settingsRef "ActiveProfile" "Default")
    } catch {
        $activeProfile = "Default"
    }
    if ([string]::IsNullOrWhiteSpace($activeProfile)) { $activeProfile = "Default" }

    $globalLifetime = Get-LifetimeCountFromStatsObject $stats 0
    if (-not $stats.ContainsKey("ProfileLifetimeToggles")) { $stats["ProfileLifetimeToggles"] = @{} }
    if (-not $stats.ContainsKey("ProfileLifetimeHighWater")) { $stats["ProfileLifetimeHighWater"] = @{} }
    if (-not $stats.ContainsKey("BadgeUnlocked")) { $stats["BadgeUnlocked"] = @{} }
    if (-not $stats.ContainsKey("BadgeHistory")) { $stats["BadgeHistory"] = @() }
    if (-not $stats.ContainsKey("BadgePoints")) { $stats["BadgePoints"] = 0 }
    if (-not $stats.ContainsKey("BadgeLevel")) { $stats["BadgeLevel"] = 1 }
    if (-not $stats.ContainsKey("BadgeLevelProgressPct")) { $stats["BadgeLevelProgressPct"] = 0.0 }
    if (-not $stats.ContainsKey("BadgeLastUnlockId")) { $stats["BadgeLastUnlockId"] = "" }
    if (-not $stats.ContainsKey("BadgeLastUnlockAt")) { $stats["BadgeLastUnlockAt"] = $null }
    if (-not $stats.ContainsKey("BadgeCurrentSeason")) { $stats["BadgeCurrentSeason"] = "" }
    if (-not $stats.ContainsKey("BadgeCatalogVersion")) { $stats["BadgeCatalogVersion"] = 1 }
    if (-not $stats.ContainsKey("BadgePointsHighWater")) { $stats["BadgePointsHighWater"] = 0 }

    $profileMap = Convert-ToHashtable $stats["ProfileLifetimeToggles"]
    $highWaterMap = Convert-ToHashtable $stats["ProfileLifetimeHighWater"]
    if (-not $profileMap.ContainsKey($activeProfile)) {
        $profileMap[$activeProfile] = $globalLifetime
    }
    foreach ($key in @($profileMap.Keys)) {
        $value = 0L
        try { $value = [int64][Math]::Max(0, [int64]$profileMap[$key]) } catch { $value = 0L }
        $high = 0L
        if ($highWaterMap.ContainsKey($key)) {
            try { $high = [int64][Math]::Max(0, [int64]$highWaterMap[$key]) } catch { $high = 0L }
        }
        if ($value -lt $high) { $value = $high }
        $profileMap[$key] = $value
        if ($value -gt $high) { $highWaterMap[$key] = $value }
    }
    $stats["ProfileLifetimeToggles"] = $profileMap
    $stats["ProfileLifetimeHighWater"] = $highWaterMap

    $unlockedMap = Convert-ToHashtable $stats["BadgeUnlocked"]
    $historyList = @()
    foreach ($entry in @($stats["BadgeHistory"])) {
        if (-not $entry) { continue }
        $id = ""
        $name = ""
        $kind = "Unknown"
        $rarity = "Common"
        $tier = "Bronze"
        $scope = "global"
        $icon = "[C]"
        $points = 0
        $unlockedAt = (Get-Date).ToString("o")
        $profileName = ""
        try {
            $id = [string]$entry.Id
            $name = [string]$entry.Name
            if ($entry.PSObject.Properties.Match("Kind").Count -gt 0) { $kind = [string]$entry.Kind }
            if ($entry.PSObject.Properties.Match("Rarity").Count -gt 0) { $rarity = [string]$entry.Rarity }
            if ($entry.PSObject.Properties.Match("Tier").Count -gt 0) { $tier = [string]$entry.Tier }
            if ($entry.PSObject.Properties.Match("Scope").Count -gt 0) { $scope = [string]$entry.Scope }
            if ($entry.PSObject.Properties.Match("Icon").Count -gt 0) { $icon = [string]$entry.Icon }
            if ($entry.PSObject.Properties.Match("Points").Count -gt 0) { $points = [int]$entry.Points }
            if ($entry.PSObject.Properties.Match("UnlockedAt").Count -gt 0) { $unlockedAt = [string]$entry.UnlockedAt }
            if ($entry.PSObject.Properties.Match("Profile").Count -gt 0) { $profileName = [string]$entry.Profile }
        } catch { Write-IgnoredCatch $_ }
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        if ([string]::IsNullOrWhiteSpace($name)) { $name = $id }
        if ([string]::IsNullOrWhiteSpace($scope)) { $scope = "global" }
        if ([string]::IsNullOrWhiteSpace($icon)) { $icon = Get-BadgeRarityIcon $rarity }
        if ($points -le 0) { $points = Get-BadgeRarityPoints $rarity $kind }
        $normalized = [pscustomobject]@{
            Id = $id
            Name = $name
            Kind = $kind
            Rarity = $rarity
            Tier = $tier
            Scope = $scope
            Icon = $icon
            Points = $points
            UnlockedAt = $unlockedAt
            Profile = $profileName
        }
        $historyList += $normalized
        if (-not $unlockedMap.ContainsKey($id)) {
            $unlockedMap[$id] = @{
                Id = $id
                Name = $name
                Kind = $kind
                Rarity = $rarity
                Tier = $tier
                Scope = $scope
                Icon = $icon
                Points = $points
                UnlockedAt = $unlockedAt
                Profile = $profileName
            }
        }
    }
    if ($historyList.Count -gt 250) { $historyList = @($historyList | Select-Object -Last 250) }
    $stats["BadgeHistory"] = $historyList
    $stats["BadgeUnlocked"] = $unlockedMap
    $stats["BadgeCurrentSeason"] = Get-BadgeSeasonName (Get-Date)

    if ($trackingMode -eq "Global" -and $globalLifetime -gt 0 -and -not $profileMap.ContainsKey($activeProfile)) {
        $profileMap[$activeProfile] = $globalLifetime
        $stats["ProfileLifetimeToggles"] = $profileMap
    }
    return $stats
}

function Get-BadgeUnlockCandidates($stats, $settingsRef, [DateTime]$now = (Get-Date)) {
    $activeProfile = [string](Get-SettingsPropertyValue $settingsRef "ActiveProfile" "Default")
    if ([string]::IsNullOrWhiteSpace($activeProfile)) { $activeProfile = "Default" }
    $trackingMode = Get-BadgeTrackingMode $settingsRef
    $scopeKey = Get-BadgeScopeKey $trackingMode $activeProfile
    $effectiveToggleCount = Get-EffectiveBadgeToggleCount $stats $settingsRef $activeProfile

    $candidates = New-Object System.Collections.Generic.List[object]
    foreach ($m in (Get-MilestoneDefinitions)) {
        if ($effectiveToggleCount -ge [int64]$m.Value) {
            [void]$candidates.Add([pscustomobject]@{
                Id = Get-ScopedBadgeId ([string]$m.Id) $trackingMode $activeProfile
                BaseId = [string]$m.Id
                Name = [string]$m.Name
                Kind = "Milestone"
                Rarity = [string]$m.Rarity
                Tier = [string]$m.Tier
                Icon = [string]$m.Icon
                Points = [int]$m.Points
                Scope = $scopeKey
                Profile = $activeProfile
            })
        }
    }

    $streaks = Get-ToggleStreaks $stats
    $currentStreak = [int]$streaks.Current
    $crashFreeDays = [int](Get-CrashFreeDays $stats $now)
    $reliability = [double](Get-UptimeReliabilityPercent $stats)
    $dailyCount = [int](Get-DailyToggleCount $stats $now)
    $totalRunMinutes = 0.0
    try { $totalRunMinutes = [double]$stats["TotalRunMinutes"] } catch { $totalRunMinutes = 0.0 }

    foreach ($def in (Get-BonusBadgeDefinitions)) {
        $unlock = $false
        switch ([string]$def.Id) {
            "bonus-streak-keeper" { $unlock = ($currentStreak -ge 7) }
            "bonus-streak-master" { $unlock = ($currentStreak -ge 30) }
            "bonus-crashfree-week" { $unlock = ($crashFreeDays -ge 7) }
            "bonus-crashfree-month" { $unlock = ($crashFreeDays -ge 30) }
            "bonus-reliable-ops" { $unlock = ($reliability -ge 98.0) }
            "bonus-rock-solid" { $unlock = ($reliability -ge 99.9) }
            "bonus-marathon" { $unlock = ($totalRunMinutes -ge 1440.0) }
            "bonus-nosleep" { $unlock = ($totalRunMinutes -ge 43200.0) }
            "bonus-million" { $unlock = ($effectiveToggleCount -ge 1000000) }
        }
        if ($unlock) {
            [void]$candidates.Add([pscustomobject]@{
                Id = Get-ScopedBadgeId ([string]$def.Id) $trackingMode $activeProfile
                BaseId = [string]$def.Id
                Name = [string]$def.Name
                Kind = "Bonus"
                Rarity = [string]$def.Rarity
                Tier = [string]$def.Tier
                Icon = [string]$def.Icon
                Points = [int]$def.Points
                Scope = $scopeKey
                Profile = $activeProfile
            })
        }
    }

    $seasonDef = Get-SeasonalBadgeDefinition $now
    if ($seasonDef -and $effectiveToggleCount -gt 0) {
        [void]$candidates.Add([pscustomobject]@{
            Id = Get-ScopedBadgeId ([string]$seasonDef.Id) $trackingMode $activeProfile
            BaseId = [string]$seasonDef.Id
            Name = [string]$seasonDef.Name
            Kind = "Seasonal"
            Rarity = [string]$seasonDef.Rarity
            Tier = [string]$seasonDef.Tier
            Icon = [string]$seasonDef.Icon
            Points = [int]$seasonDef.Points
            Scope = $scopeKey
            Profile = $activeProfile
        })
    }

    foreach ($def in (Get-ComboBadgeDefinitions)) {
        $unlock = $false
        switch ([string]$def.Id) {
            "combo-precision-triple" { $unlock = ($currentStreak -ge 7 -and $dailyCount -ge 25 -and $reliability -ge 99.0) }
            "combo-momentum-chain" { $unlock = ($currentStreak -ge 14 -and $dailyCount -ge 75) }
            "combo-iron-marathon" { $unlock = ($currentStreak -ge 30 -and $totalRunMinutes -ge 10080.0) }
        }
        if ($unlock) {
            [void]$candidates.Add([pscustomobject]@{
                Id = Get-ScopedBadgeId ([string]$def.Id) $trackingMode $activeProfile
                BaseId = [string]$def.Id
                Name = [string]$def.Name
                Kind = "Combo"
                Rarity = [string]$def.Rarity
                Tier = [string]$def.Tier
                Icon = [string]$def.Icon
                Points = [int]$def.Points
                Scope = $scopeKey
                Profile = $activeProfile
            })
        }
    }

    foreach ($def in (Get-ResilienceBadgeDefinitions)) {
        $unlock = $false
        switch ([string]$def.Id) {
            "resilience-bounceback" { $unlock = ($crashFreeDays -ge 3) }
            "resilience-hardened" { $unlock = ($crashFreeDays -ge 14 -and $reliability -ge 99.0) }
            "resilience-unkillable" { $unlock = ($crashFreeDays -ge 60 -and $reliability -ge 99.9) }
        }
        if ($unlock) {
            [void]$candidates.Add([pscustomobject]@{
                Id = Get-ScopedBadgeId ([string]$def.Id) $trackingMode $activeProfile
                BaseId = [string]$def.Id
                Name = [string]$def.Name
                Kind = "Resilience"
                Rarity = [string]$def.Rarity
                Tier = [string]$def.Tier
                Icon = [string]$def.Icon
                Points = [int]$def.Points
                Scope = $scopeKey
                Profile = $activeProfile
            })
        }
    }

    return @($candidates | Group-Object Id | ForEach-Object { $_.Group[0] })
}

function Update-BadgeProgress($stats, $settingsRef, [DateTime]$now = (Get-Date), [switch]$ShowToast) {
    if (-not $stats) { return [pscustomobject]@{ NewUnlocks = @(); Stats = @{} } }
    $stats = Ensure-BadgeStats $stats $settingsRef
    $unlockedMap = Convert-ToHashtable $stats["BadgeUnlocked"]
    $history = @($stats["BadgeHistory"])

    $newUnlocks = New-Object System.Collections.Generic.List[object]
    foreach ($candidate in @(Get-BadgeUnlockCandidates $stats $settingsRef $now)) {
        if (-not $candidate) { continue }
        $id = [string]$candidate.Id
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        if ($unlockedMap.ContainsKey($id)) { continue }
        $stamp = $now.ToString("o")
        $unlockedMap[$id] = @{
            Id = $id
            BaseId = [string]$candidate.BaseId
            Name = [string]$candidate.Name
            Kind = [string]$candidate.Kind
            Rarity = [string]$candidate.Rarity
            Tier = [string]$candidate.Tier
            Icon = [string]$candidate.Icon
            Points = [int]$candidate.Points
            Scope = [string]$candidate.Scope
            Profile = [string]$candidate.Profile
            UnlockedAt = $stamp
        }
        $history += [pscustomobject]@{
            Id = $id
            Name = [string]$candidate.Name
            Kind = [string]$candidate.Kind
            Rarity = [string]$candidate.Rarity
            Tier = [string]$candidate.Tier
            Scope = [string]$candidate.Scope
            Icon = [string]$candidate.Icon
            Points = [int]$candidate.Points
            UnlockedAt = $stamp
            Profile = [string]$candidate.Profile
        }
        try {
            Write-Log ("Badge unlocked: {0} [{1}] scope={2}" -f [string]$candidate.Name, [string]$candidate.Kind, [string]$candidate.Scope) "INFO" $null "Badges"
        } catch { Write-IgnoredCatch $_ }
        [void]$newUnlocks.Add($candidate)
    }

    if ($history.Count -gt 300) {
        $history = @($history | Select-Object -Last 300)
    }

    $totalPoints = 0
    foreach ($entryObj in @($unlockedMap.Values)) {
        $entry = Convert-ToHashtable $entryObj
        $points = 0
        if ($entry.ContainsKey("Points")) {
            try { $points = [int]$entry["Points"] } catch { $points = 0 }
        }
        if ($points -le 0) {
            $rarity = if ($entry.ContainsKey("Rarity")) { [string]$entry["Rarity"] } else { "Common" }
            $kind = if ($entry.ContainsKey("Kind")) { [string]$entry["Kind"] } else { "Milestone" }
            $points = Get-BadgeRarityPoints $rarity $kind
        }
        $totalPoints += [Math]::Max(0, $points)
    }

    $pointsHighWater = 0
    try { $pointsHighWater = [int]$stats["BadgePointsHighWater"] } catch { $pointsHighWater = 0 }
    if ($totalPoints -lt $pointsHighWater) {
        $totalPoints = $pointsHighWater
    } else {
        $pointsHighWater = $totalPoints
    }
    $levelInfo = Get-BadgeLevelInfo $totalPoints

    $stats["BadgeUnlocked"] = $unlockedMap
    $stats["BadgeHistory"] = $history
    $stats["BadgePoints"] = [int]$totalPoints
    $stats["BadgePointsHighWater"] = [int]$pointsHighWater
    $stats["BadgeLevel"] = [int]$levelInfo.Level
    $stats["BadgeLevelProgressPct"] = [double]$levelInfo.ProgressPct
    $stats["BadgeCurrentSeason"] = Get-BadgeSeasonName $now
    $stats["BadgeCatalogVersion"] = 1

    if ($newUnlocks.Count -gt 0) {
        $last = $newUnlocks[$newUnlocks.Count - 1]
        $stats["BadgeLastUnlockId"] = [string]$last.Id
        $stats["BadgeLastUnlockAt"] = $now.ToString("o")
    }

    if ($ShowToast -and $newUnlocks.Count -gt 0) {
        $showCount = [Math]::Min(2, $newUnlocks.Count)
        for ($i = 0; $i -lt $showCount; $i++) {
            $unlock = $newUnlocks[$i]
            $toast = ("Badge unlocked: {0} {1} ({2})" -f [string]$unlock.Icon, [string]$unlock.Name, [string]$unlock.Kind)
            try {
                Show-ActionToast $toast "Badge Unlocked" -ForceBalloon
            } catch { Write-IgnoredCatch $_ }
        }
        if ($newUnlocks.Count -gt $showCount) {
            $remaining = $newUnlocks.Count - $showCount
            try { Show-ActionToast ("Badge streak: +{0} more unlocks" -f $remaining) "Badge Unlocked" -ForceBalloon } catch { Write-IgnoredCatch $_ }
        }
    }

    $newUnlockArray = @()
    try {
        $newUnlockArray = @($newUnlocks.ToArray())
    } catch {
        $newUnlockArray = @($newUnlocks)
    }
    $resultObject = New-Object PSObject -Property ([ordered]@{
        NewUnlocks = $newUnlockArray
        Stats = $stats
    })
    return $resultObject
}

function Get-BadgeScopeUnlockedEntries($stats, $settingsRef, [string]$kindFilter = "") {
    if (-not $stats) { return @() }
    $activeProfile = [string](Get-SettingsPropertyValue $settingsRef "ActiveProfile" "Default")
    if ([string]::IsNullOrWhiteSpace($activeProfile)) { $activeProfile = "Default" }
    $trackingMode = Get-BadgeTrackingMode $settingsRef
    $scopeKey = Get-BadgeScopeKey $trackingMode $activeProfile
    $unlocked = @{}
    try {
        if ($stats -is [System.Collections.IDictionary] -and $stats.ContainsKey("BadgeUnlocked")) {
            $unlocked = Convert-ToHashtable $stats["BadgeUnlocked"]
        } elseif ($stats -and $stats.PSObject.Properties.Match("BadgeUnlocked").Count -gt 0) {
            $unlocked = Convert-ToHashtable $stats.BadgeUnlocked
        }
    } catch {
        $unlocked = @{}
    }
    $result = New-Object System.Collections.Generic.List[object]
    $seenIds = @{}
    foreach ($entryObj in @($unlocked.Values)) {
        $entry = Convert-ToHashtable $entryObj
        if (-not $entry -or @($entry.Keys).Count -eq 0) { continue }
        $id = if ($entry.ContainsKey("Id")) { [string]$entry["Id"] } else { "" }
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        if ($seenIds.ContainsKey($id)) { continue }
        $scope = if ($entry.ContainsKey("Scope")) { [string]$entry["Scope"] } else { "global" }
        if ($scope -ne $scopeKey) { continue }
        if (-not [string]::IsNullOrWhiteSpace($kindFilter)) {
            $kind = if ($entry.ContainsKey("Kind")) { [string]$entry["Kind"] } else { "" }
            if ($kind -ne $kindFilter) { continue }
        }
        $seenIds[$id] = $true
        [void]$result.Add([pscustomobject]$entry)
    }

    # Legacy fallback: synthesize unlock entries from history when map is missing/partial.
    if ($result.Count -eq 0) {
        $history = @()
        try {
            if ($stats -is [System.Collections.IDictionary] -and $stats.ContainsKey("BadgeHistory")) {
                $history = @($stats["BadgeHistory"])
            } elseif ($stats -and $stats.PSObject.Properties.Match("BadgeHistory").Count -gt 0) {
                $history = @($stats.BadgeHistory)
            }
        } catch {
            $history = @()
        }
        foreach ($entryObj in $history) {
            $entry = Convert-ToHashtable $entryObj
            if (-not $entry -or @($entry.Keys).Count -eq 0) { continue }
            $id = if ($entry.ContainsKey("Id")) { [string]$entry["Id"] } else { "" }
            if ([string]::IsNullOrWhiteSpace($id)) { continue }
            if ($seenIds.ContainsKey($id)) { continue }
            $scope = if ($entry.ContainsKey("Scope")) { [string]$entry["Scope"] } else { "global" }
            if ($scope -ne $scopeKey) { continue }
            if (-not [string]::IsNullOrWhiteSpace($kindFilter)) {
                $kind = if ($entry.ContainsKey("Kind")) { [string]$entry["Kind"] } else { "" }
                if ($kind -ne $kindFilter) { continue }
            }
            $seenIds[$id] = $true
            [void]$result.Add([pscustomobject]$entry)
        }
    }

    # If milestone entries are still missing, derive from effective lifetime toggles.
    if (($result.Count -eq 0) -and ([string]::IsNullOrWhiteSpace($kindFilter) -or $kindFilter -eq "Milestone")) {
        $effectiveToggles = 0L
        try { $effectiveToggles = [int64](Get-EffectiveBadgeToggleCount $stats $settingsRef $activeProfile) } catch { $effectiveToggles = 0L }
        if ($effectiveToggles -gt 0) {
            foreach ($def in @(Get-MilestoneDefinitions)) {
                $value = 0L
                try { $value = [int64]$def.Value } catch { $value = 0L }
                if ($value -le 0 -or $effectiveToggles -lt $value) { continue }
                $id = Get-ScopedBadgeId ([string]$def.Id) $trackingMode $activeProfile
                if ([string]::IsNullOrWhiteSpace($id) -or $seenIds.ContainsKey($id)) { continue }
                $seenIds[$id] = $true
                [void]$result.Add([pscustomobject]@{
                    Id = $id
                    BaseId = [string]$def.Id
                    Name = [string]$def.Name
                    Kind = "Milestone"
                    Rarity = [string]$def.Rarity
                    Tier = [string]$def.Tier
                    Icon = [string]$def.Icon
                    Points = [int]$def.Points
                    Scope = $scopeKey
                    Profile = $activeProfile
                })
            }
        }
    }

    try {
        return @($result.ToArray())
    } catch {
        $fallback = New-Object System.Collections.ArrayList
        foreach ($item in $result) { [void]$fallback.Add($item) }
        return @($fallback)
    }
}

function Get-BadgeSummary($stats, $settingsRef, [DateTime]$now = (Get-Date)) {
    try {
        $stats = Ensure-BadgeStats $stats $settingsRef
        try {
            $updateResult = Update-BadgeProgress $stats $settingsRef $now
            if ($updateResult -and $updateResult.PSObject.Properties.Match("Stats").Count -gt 0 -and $updateResult.Stats) {
                $stats = Convert-ToHashtable $updateResult.Stats
            }
        } catch { Write-IgnoredCatch $_ }
        $activeProfile = [string](Get-SettingsPropertyValue $settingsRef "ActiveProfile" "Default")
        if ([string]::IsNullOrWhiteSpace($activeProfile)) { $activeProfile = "Default" }
        $trackingMode = Get-BadgeTrackingMode $settingsRef
        $effectiveToggles = Get-EffectiveBadgeToggleCount $stats $settingsRef $activeProfile
        $milestoneInfo = Get-MilestoneInfo $effectiveToggles
        $scopeEntries = @(Get-BadgeScopeUnlockedEntries $stats $settingsRef "")
        $scopeEntries = @($scopeEntries | Group-Object Id | ForEach-Object { $_.Group[0] })
        $catalogTotal = @(Get-BadgeCatalogDefinitions).Count
        $catalogUnlocked = $scopeEntries.Count
        $milestoneUnlockedByProgress = 0
        foreach ($def in @(Get-MilestoneDefinitions)) {
            try {
                if ([int64]$effectiveToggles -ge [int64]$def.Value) { $milestoneUnlockedByProgress++ }
            } catch { Write-IgnoredCatch $_ }
        }
        if ($catalogUnlocked -lt $milestoneUnlockedByProgress) {
            $catalogUnlocked = $milestoneUnlockedByProgress
        }
        $catalogLocked = [Math]::Max(0, ($catalogTotal - $catalogUnlocked))

        $currentBadgeText = if ([int64]$milestoneInfo.CurrentValue -gt 0) {
            [string]$milestoneInfo.CurrentName
        } else {
            "None yet"
        }
        $nextBadgeText = if ($milestoneInfo.IsMax) {
            "MAX"
        } else {
            ("{0} ({1:N0}) [{2}] - {3:N0} left" -f [string]$milestoneInfo.NextName, [int64]$milestoneInfo.NextValue, [string]$milestoneInfo.NextTier, [int64]$milestoneInfo.LeftToNext)
        }
        $milestoneText = Get-MilestoneStatus ([int]$effectiveToggles)
        $milestonePctText = if ($milestoneInfo.IsMax) { "100.0%" } else { ("{0:N1}%" -f [double]$milestoneInfo.ProgressToNextPct) }

        $streaks = Get-ToggleStreaks $stats
        $currentStreak = [int]$streaks.Current
        $crashFreeDays = [int](Get-CrashFreeDays $stats $now)
        $reliabilityPct = [double](Get-UptimeReliabilityPercent $stats)
        $totalRunMinutes = 0.0
        try { $totalRunMinutes = [double]$stats["TotalRunMinutes"] } catch { $totalRunMinutes = 0.0 }
        $bonusBadgeText = Get-BonusBadgeLabel $stats $currentStreak $reliabilityPct $crashFreeDays $totalRunMinutes $effectiveToggles

        $seasonDef = Get-SeasonalBadgeDefinition $now
        $seasonalText = if ($seasonDef) { ("{0} {1}" -f [string]$seasonDef.Icon, [string]$seasonDef.Name) } else { "N/A" }
        $comboEntries = @(Get-BadgeScopeUnlockedEntries $stats $settingsRef "Combo")
        $resilienceEntries = @(Get-BadgeScopeUnlockedEntries $stats $settingsRef "Resilience")
        $comboText = if ($comboEntries.Count -gt 0) { [string]$comboEntries[-1].Name } else { "None yet" }
        $resilienceText = if ($resilienceEntries.Count -gt 0) { [string]$resilienceEntries[-1].Name } else { "None yet" }

        $history = @($stats["BadgeHistory"])
        $recent = if ($history.Count -gt 0) { $history[-1] } else { $null }
        $recentUnlockText = "None"
        if ($recent) {
            $recentTime = ""
            try { $recentTime = Format-LocalTime ([DateTime]::Parse([string]$recent.UnlockedAt)) } catch { $recentTime = [string]$recent.UnlockedAt }
            $recentUnlockText = ("{0} ({1}) at {2}" -f [string]$recent.Name, [string]$recent.Kind, $recentTime)
        }

        $points = 0
        $level = 1
        $levelPct = 0.0
        try { $points = [int]$stats["BadgePoints"] } catch { $points = 0 }
        try { $level = [int]$stats["BadgeLevel"] } catch { $level = 1 }
        try { $levelPct = [double]$stats["BadgeLevelProgressPct"] } catch { $levelPct = 0.0 }
        $levelInfo = Get-BadgeLevelInfo $points

        return [pscustomobject]@{
            TrackingMode = $trackingMode
            EffectiveToggleCount = [int64]$effectiveToggles
            CurrentBadgeText = $currentBadgeText
            CurrentBadgeRarity = [string]$milestoneInfo.CurrentRarity
            NextBadgeText = $nextBadgeText
            MilestoneText = $milestoneText
            MilestonePctText = $milestonePctText
            BonusBadgeText = $bonusBadgeText
            SeasonalBadgeText = $seasonalText
            ComboBadgeText = $comboText
            ResilienceBadgeText = $resilienceText
            CatalogText = ("{0}/{1} unlocked ({2} locked)" -f $catalogUnlocked, $catalogTotal, $catalogLocked)
            BadgePoints = $points
            BadgeLevel = $level
            BadgeLevelProgressPct = [double]$levelPct
            BadgeLevelText = ("Lvl {0} ({1:N0} pts, {2:N1}% to next)" -f $level, $points, $levelPct)
            NextLevelAt = [int]$levelInfo.NextLevelAt
            RecentUnlockText = $recentUnlockText
        }
    } catch {
        $summaryError = if ($_.Exception) { [string]$_.Exception.Message } else { "Unknown error" }
        $summaryErrorType = "System.Exception"
        try {
            if ($_.Exception -and $_.Exception.GetType()) { $summaryErrorType = [string]$_.Exception.GetType().FullName }
        } catch {
            $summaryErrorType = "System.Exception"
        }
        $summaryErrorPos = ""
        try {
            if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
                $summaryErrorPos = [string](($_.InvocationInfo.PositionMessage -split "`r?`n")[0])
            }
        } catch {
            $summaryErrorPos = ""
        }
        if (-not [string]::IsNullOrWhiteSpace($summaryErrorPos)) {
            $summaryError = ("{0}: {1} ({2})" -f $summaryErrorType, $summaryError, $summaryErrorPos)
        } else {
            $summaryError = ("{0}: {1}" -f $summaryErrorType, $summaryError)
        }
        try {
            Write-LogThrottled "BadgeSummary-SafeFallback" ("Badge summary generation failed; using safe summary fallback: {0}" -f $summaryError) "WARN" 60
        } catch { Write-IgnoredCatch $_ }

        $safeStats = Convert-ToHashtable $stats
        $trackingMode = "Global"
        try { $trackingMode = Get-BadgeTrackingMode $settingsRef } catch { $trackingMode = "Global" }
        $activeProfile = "Default"
        try { $activeProfile = [string](Get-SettingsPropertyValue $settingsRef "ActiveProfile" "Default") } catch { $activeProfile = "Default" }
        if ([string]::IsNullOrWhiteSpace($activeProfile)) { $activeProfile = "Default" }

        $effectiveToggles = 0L
        try {
            $effectiveToggles = [int64](Get-EffectiveBadgeToggleCount $safeStats $settingsRef $activeProfile)
        } catch {
            try { $effectiveToggles = [int64](Get-LifetimeCountFromStatsObject $safeStats 0) } catch { $effectiveToggles = 0L }
        }
        if ($effectiveToggles -lt 0) { $effectiveToggles = 0L }

        $currentBadgeText = "None yet"
        $nextBadgeText = ("Rookie (100) [Bronze] - {0:N0} left" -f [Math]::Max(0L, (100L - $effectiveToggles)))
        $milestonePctText = "0.0%"
        $currentRarity = "Common"
        $milestoneText = ("Next: Rookie (100) - {0:N0} left" -f [Math]::Max(0L, (100L - $effectiveToggles)))
        try {
            $milestoneInfo = Get-MilestoneInfo $effectiveToggles
            if ($milestoneInfo) {
                $currentRarity = [string]$milestoneInfo.CurrentRarity
                $currentBadgeText = if ([int64]$milestoneInfo.CurrentValue -gt 0) {
                    [string]$milestoneInfo.CurrentName
                } else {
                    "None yet"
                }
                $nextBadgeText = if ($milestoneInfo.IsMax) {
                    "MAX"
                } else {
                    ("{0} ({1:N0}) [{2}] - {3:N0} left" -f [string]$milestoneInfo.NextName, [int64]$milestoneInfo.NextValue, [string]$milestoneInfo.NextTier, [int64]$milestoneInfo.LeftToNext)
                }
                $milestonePctText = if ($milestoneInfo.IsMax) { "100.0%" } else { ("{0:N1}%" -f [double]$milestoneInfo.ProgressToNextPct) }
                $milestoneText = if ($milestoneInfo.IsMax) {
                    "Max milestone reached"
                } else {
                    ("Next: {0} ({1:N0}) - {2:N0} left" -f [string]$milestoneInfo.NextName, [int64]$milestoneInfo.NextValue, [int64]$milestoneInfo.LeftToNext)
                }
            }
        } catch { Write-IgnoredCatch $_ }

        $scopeEntries = @()
        try { $scopeEntries = @(Get-BadgeScopeUnlockedEntries $safeStats $settingsRef "") } catch { $scopeEntries = @() }
        $catalogUnlocked = @($scopeEntries).Count
        $catalogTotal = $catalogUnlocked
        try { $catalogTotal = @(Get-BadgeCatalogDefinitions).Count } catch { Write-IgnoredCatch $_ }
        if ($catalogTotal -lt $catalogUnlocked) { $catalogTotal = $catalogUnlocked }
        $catalogLocked = [Math]::Max(0, ($catalogTotal - $catalogUnlocked))

        $byKindNames = {
            param([object[]]$entries, [string]$kind, [string]$noneText = "None yet")
            $names = @()
            foreach ($entryObj in @($entries)) {
                $entry = Convert-ToHashtable $entryObj
                $entryKind = if ($entry.ContainsKey("Kind")) { [string]$entry["Kind"] } else { "" }
                if ($entryKind -ne $kind) { continue }
                $entryName = if ($entry.ContainsKey("Name")) { [string]$entry["Name"] } else { "" }
                if (-not [string]::IsNullOrWhiteSpace($entryName)) { $names += $entryName }
            }
            $names = @($names | Select-Object -Unique)
            if ($names.Count -eq 0) { return $noneText }
            return ($names -join ", ")
        }
        $bonusBadgeText = & $byKindNames @($scopeEntries) "Bonus" "None yet"
        $seasonalText = & $byKindNames @($scopeEntries) "Seasonal" "N/A"
        $comboText = & $byKindNames @($scopeEntries) "Combo" "None yet"
        $resilienceText = & $byKindNames @($scopeEntries) "Resilience" "None yet"

        $recentUnlockText = "None"
        try {
            $history = @($safeStats["BadgeHistory"])
            if ($history.Count -gt 0) {
                $recent = $history[-1]
                if ($recent) {
                    $recentName = [string]$recent.Name
                    $recentKind = [string]$recent.Kind
                    $recentAt = [string]$recent.UnlockedAt
                    $recentUnlockText = if ([string]::IsNullOrWhiteSpace($recentAt)) {
                        ("{0} ({1})" -f $recentName, $recentKind)
                    } else {
                        ("{0} ({1}) at {2}" -f $recentName, $recentKind, $recentAt)
                    }
                }
            }
        } catch { Write-IgnoredCatch $_ }

        $points = 0
        try { $points = [int]$safeStats["BadgePoints"] } catch { $points = 0 }
        if ($points -lt 0) { $points = 0 }
        $levelInfo = $null
        try { $levelInfo = Get-BadgeLevelInfo $points } catch { $levelInfo = $null }
        $level = 1
        $levelPct = 0.0
        $nextLevelAt = 100
        if ($levelInfo) {
            try { $level = [int]$levelInfo.Level } catch { $level = 1 }
            try { $levelPct = [double]$levelInfo.ProgressPct } catch { $levelPct = 0.0 }
            try { $nextLevelAt = [int]$levelInfo.NextLevelAt } catch { $nextLevelAt = 100 }
        }

        return [pscustomobject]@{
            TrackingMode = $trackingMode
            EffectiveToggleCount = [int64]$effectiveToggles
            CurrentBadgeText = $currentBadgeText
            CurrentBadgeRarity = $currentRarity
            NextBadgeText = $nextBadgeText
            MilestoneText = $milestoneText
            MilestonePctText = $milestonePctText
            BonusBadgeText = $bonusBadgeText
            SeasonalBadgeText = $seasonalText
            ComboBadgeText = $comboText
            ResilienceBadgeText = $resilienceText
            CatalogText = ("{0}/{1} unlocked ({2} locked)" -f $catalogUnlocked, $catalogTotal, $catalogLocked)
            BadgePoints = [int]$points
            BadgeLevel = [int]$level
            BadgeLevelProgressPct = [double]$levelPct
            BadgeLevelText = ("Lvl {0} ({1:N0} pts, {2:N1}% to next)" -f $level, $points, $levelPct)
            NextLevelAt = [int]$nextLevelAt
            RecentUnlockText = $recentUnlockText
        }
    }
}

function Export-BadgeShareCard($settingsRef = $null, [switch]$OpenFolder) {
    $targetSettings = if ($settingsRef) { $settingsRef } else { $settings }
    $stats = Ensure-FunStats $targetSettings
    $summary = Get-BadgeSummary $stats $targetSettings (Get-Date)
    Ensure-Directory $script:BadgeShareCardsDir "BadgeCards" | Out-Null
    $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $path = Join-Path $script:BadgeShareCardsDir ("BadgeCard-{0}.txt" -f $stamp)
    $lines = @()
    $lines += "Teams-Always-Green - Badge Card"
    $lines += ("Generated: {0}" -f (Format-LocalTime (Get-Date)))
    $lines += ("Mode: {0}" -f [string]$summary.TrackingMode)
    $lines += ("Effective Toggles: {0:N0}" -f [int64]$summary.EffectiveToggleCount)
    $lines += ("Current Badge: {0}" -f [string]$summary.CurrentBadgeText)
    $lines += ("Next Badge: {0}" -f [string]$summary.NextBadgeText)
    $lines += ("Points/Level: {0}" -f [string]$summary.BadgeLevelText)
    $lines += ("Catalog: {0}" -f [string]$summary.CatalogText)
    $lines += ("Seasonal: {0}" -f [string]$summary.SeasonalBadgeText)
    $lines += ("Combo: {0}" -f [string]$summary.ComboBadgeText)
    $lines += ("Resilience: {0}" -f [string]$summary.ResilienceBadgeText)
    $lines += ("Bonus: {0}" -f [string]$summary.BonusBadgeText)
    $lines += ("Recent Unlock: {0}" -f [string]$summary.RecentUnlockText)
    $content = ($lines -join "`r`n")
    Write-AtomicTextFile -Path $path -Content $content -Encoding UTF8
    if ($OpenFolder) {
        try { Start-Process -FilePath explorer.exe -ArgumentList ("`"{0}`"" -f $script:BadgeShareCardsDir) | Out-Null } catch { Write-IgnoredCatch $_ }
    }
    return $path
}

function Ensure-FunStats($settings) {
    if (-not $settings) { return @{} }
    $stats = Convert-ToHashtable (Get-SettingsPropertyValue $settings "Stats")
    if (-not $stats) { $stats = @{} }
    if (-not $stats.ContainsKey("InstallDate")) { $stats["InstallDate"] = (Get-Date).ToString("o") }
    if (-not $stats.ContainsKey("TotalRunMinutes")) { $stats["TotalRunMinutes"] = 0 }
    if (-not $stats.ContainsKey("LongestPauseMinutes")) { $stats["LongestPauseMinutes"] = 0 }
    if (-not $stats.ContainsKey("LongestPauseAt")) { $stats["LongestPauseAt"] = $null }
    if (-not $stats.ContainsKey("CrashFreeSince")) { $stats["CrashFreeSince"] = [string]$stats["InstallDate"] }
    if (-not $stats.ContainsKey("ReliableMinutes")) { $stats["ReliableMinutes"] = 0 }
    if (-not $stats.ContainsKey("DegradedMinutes")) { $stats["DegradedMinutes"] = 0 }
    if (-not $stats.ContainsKey("LifetimeToggleCount")) { $stats["LifetimeToggleCount"] = 0 }

    $daily = Convert-ToHashtable $stats["DailyToggles"]
    if (-not $daily) { $daily = @{} }
    $stats["DailyToggles"] = $daily

    $hourly = Convert-ToHashtable $stats["HourlyToggles"]
    if (-not $hourly) { $hourly = @{} }
    $stats["HourlyToggles"] = $hourly

    $profileUsage = Convert-ToHashtable $stats["ProfileUsageMinutes"]
    if (-not $profileUsage) { $profileUsage = @{} }
    $stats["ProfileUsageMinutes"] = $profileUsage

    # One-way migration: seed lifetime stat from ToggleCount for existing installs.
    $seedLifetime = 0
    try {
        $rawSeed = Get-SettingsPropertyValue $settings "ToggleCount" 0
        $parsedSeed = 0
        if ($rawSeed -is [int]) {
            $seedLifetime = [int]$rawSeed
        } elseif ([int]::TryParse([string]$rawSeed, [ref]$parsedSeed)) {
            $seedLifetime = [int]$parsedSeed
        }
    } catch {
        $seedLifetime = 0
    }
    if ($seedLifetime -lt 0) { $seedLifetime = 0 }
    $currentLifetime = 0
    try { $currentLifetime = [int]$stats["LifetimeToggleCount"] } catch { $currentLifetime = 0 }
    if ($currentLifetime -lt 0) { $currentLifetime = 0 }
    $stateLifetime = 0
    try {
        if ($script:AppState -and $script:AppState.PSObject.Properties.Name -contains "Stats") {
            $stateLifetime = [int](Get-LifetimeCountFromStatsObject $script:AppState.Stats 0)
        }
    } catch {
        $stateLifetime = 0
    }
    $persistentLifetime = 0
    try {
        $persistentLifetime = [int](Get-PersistentLifetimeToggleCount)
    } catch {
        $persistentLifetime = 0
    }
    $finalLifetime = [int][Math]::Max([Math]::Max($currentLifetime, $seedLifetime), [Math]::Max($stateLifetime, $persistentLifetime))
    if ($finalLifetime -lt 0) { $finalLifetime = 0 }
    if ($finalLifetime -gt $currentLifetime) {
        Write-LogThrottled "Lifetime-Recovered" ("Recovered lifetime toggles to {0:N0} (current={1:N0}, seed={2:N0}, state={3:N0}, persistent={4:N0})." -f $finalLifetime, $currentLifetime, $seedLifetime, $stateLifetime, $persistentLifetime) "INFO" 60
    }
    $stats["LifetimeToggleCount"] = $finalLifetime
    Save-PersistentLifetimeToggleCount ([int64]$finalLifetime)
    $activeProfile = [string](Get-SettingsPropertyValue $settings "ActiveProfile" "Default")
    if ([string]::IsNullOrWhiteSpace($activeProfile)) { $activeProfile = "Default" }
    Set-ProfileLifetimeToggleCount $stats $activeProfile ([int64]$finalLifetime)
    $stats = Ensure-BadgeStats $stats $settings
    $badgeInit = Update-BadgeProgress $stats $settings (Get-Date)
    if ($badgeInit -and $badgeInit.PSObject.Properties.Name -contains "Stats") {
        $stats = Convert-ToHashtable $badgeInit.Stats
    }

    Set-SettingsPropertyValue $settings "Stats" $stats
    return $stats
}

function Mark-FunStatsCrashEvent {
    if (-not $settings) { return }
    $stats = Ensure-FunStats $settings
    $stats["CrashFreeSince"] = (Get-Date).ToString("o")
    $badgeUpdate = Update-BadgeProgress $stats $settings (Get-Date)
    if ($badgeUpdate -and $badgeUpdate.PSObject.Properties.Name -contains "Stats") {
        $stats = Convert-ToHashtable $badgeUpdate.Stats
    }
    Set-SettingsPropertyValue $settings "Stats" $stats
    $script:FunStatsCache = $null
}

function Update-FunStatsRuntimeProgress([DateTime]$now = (Get-Date)) {
    if (-not $settings) { return }
    if (-not $script:StatsLastSampleAt) {
        $script:StatsLastSampleAt = $now
        $script:StatsLastSampleProfile = [string](Get-SettingsPropertyValue $settings "ActiveProfile" "Default")
        return
    }
    $elapsedMinutes = ($now - $script:StatsLastSampleAt).TotalMinutes
    if ($elapsedMinutes -le 0) {
        $script:StatsLastSampleAt = $now
        return
    }

    # Bound extreme samples (sleep/resume clock jumps) to avoid distorting long-term stats.
    if ($elapsedMinutes -gt 15) { $elapsedMinutes = 15 }

    $stats = Ensure-FunStats $settings
    $profileUsage = Convert-ToHashtable $stats["ProfileUsageMinutes"]
    $profileName = [string]$script:StatsLastSampleProfile
    if ([string]::IsNullOrWhiteSpace($profileName)) {
        $profileName = [string](Get-SettingsPropertyValue $settings "ActiveProfile" "Default")
    }
    if ([string]::IsNullOrWhiteSpace($profileName)) { $profileName = "Default" }
    $currentProfileMinutes = 0.0
    if ($profileUsage.ContainsKey($profileName)) {
        try { $currentProfileMinutes = [double]$profileUsage[$profileName] } catch { $currentProfileMinutes = 0.0 }
    }
    $profileUsage[$profileName] = [Math]::Round(($currentProfileMinutes + $elapsedMinutes), 3)
    $stats["ProfileUsageMinutes"] = $profileUsage

    $reliable = 0.0
    $degraded = 0.0
    try { if ($stats.ContainsKey("ReliableMinutes")) { $reliable = [double]$stats["ReliableMinutes"] } } catch { $reliable = 0.0 }
    try { if ($stats.ContainsKey("DegradedMinutes")) { $degraded = [double]$stats["DegradedMinutes"] } } catch { $degraded = 0.0 }
    $isReliableSlice = (-not $script:safeModeActive -and -not $script:isPaused)
    if ($isReliableSlice) {
        $reliable += $elapsedMinutes
    } else {
        $degraded += $elapsedMinutes
    }
    $stats["ReliableMinutes"] = [Math]::Round($reliable, 3)
    $stats["DegradedMinutes"] = [Math]::Round($degraded, 3)
    Set-SettingsPropertyValue $settings "Stats" $stats

    $script:StatsLastSampleAt = $now
    $script:StatsLastSampleProfile = [string](Get-SettingsPropertyValue $settings "ActiveProfile" "Default")
    $script:FunStatsCache = $null
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

    $lifetime = 0
    try { $lifetime = [int]$stats["LifetimeToggleCount"] } catch { $lifetime = 0 }
    if ($lifetime -lt 0) { $lifetime = 0 }
    $stats["LifetimeToggleCount"] = ($lifetime + 1)
    Save-PersistentLifetimeToggleCount ([int64]$stats["LifetimeToggleCount"])
    $activeProfile = [string](Get-SettingsPropertyValue $settings "ActiveProfile" "Default")
    if ([string]::IsNullOrWhiteSpace($activeProfile)) { $activeProfile = "Default" }
    $profileLifetime = Get-ProfileLifetimeToggleCount $stats $activeProfile ([int64]$stats["LifetimeToggleCount"])
    Set-ProfileLifetimeToggleCount $stats $activeProfile ([int64]$profileLifetime + 1)
    $badgeUpdate = Update-BadgeProgress $stats $settings $when -ShowToast
    if ($badgeUpdate -and $badgeUpdate.PSObject.Properties.Name -contains "Stats") {
        $stats = Convert-ToHashtable $badgeUpdate.Stats
    }

    Set-SettingsPropertyValue $settings "Stats" $stats
    $script:FunStatsCache = $null
}

function Get-LifetimeToggleCount($stats, [int]$fallback = 0) {
    $safeFallback = [Math]::Max(0, [int]$fallback)
    if (-not $stats) { return $safeFallback }
    try {
        if ($stats -is [System.Collections.IDictionary] -and $stats.ContainsKey("LifetimeToggleCount")) {
            $count = [int]$stats["LifetimeToggleCount"]
            return [Math]::Max(0, $count)
        }
        if ($stats.PSObject.Properties.Match("LifetimeToggleCount").Count -gt 0) {
            $count = [int]$stats.LifetimeToggleCount
            return [Math]::Max(0, $count)
        }
    } catch { Write-IgnoredCatch $_ }
    return $safeFallback
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
        $script:FunStatsCache = $null
    }
}

function Update-FunStatsOnShutdown([double]$uptimeMinutes) {
    if ($script:StatsShutdownUpdated) { return }
    if ($uptimeMinutes -le 0) { return }
    Update-FunStatsRuntimeProgress (Get-Date)
    $stats = Ensure-FunStats $settings
    $total = 0.0
    if ($stats.ContainsKey("TotalRunMinutes")) { $total = [double]$stats["TotalRunMinutes"] }
    $stats["TotalRunMinutes"] = [Math]::Round(($total + $uptimeMinutes), 1)
    $shutdownLifetime = Get-LifetimeCountFromStatsObject $stats 0
    Save-PersistentLifetimeToggleCount ([int64]$shutdownLifetime)
    $badgeUpdate = Update-BadgeProgress $stats $settings (Get-Date)
    if ($badgeUpdate -and $badgeUpdate.PSObject.Properties.Name -contains "Stats") {
        $stats = Convert-ToHashtable $badgeUpdate.Stats
    }
    Set-SettingsPropertyValue $settings "Stats" $stats
    $script:FunStatsCache = $null
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
            try { $dates += [DateTime]::ParseExact($key, "yyyy-MM-dd", $null) } catch { Write-IgnoredCatch $_ }
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

function Get-CrashFreeDays($stats, [DateTime]$now = (Get-Date)) {
    if (-not $stats) { return 0 }
    $sinceText = $null
    if ($stats -is [System.Collections.IDictionary] -and $stats.ContainsKey("CrashFreeSince")) {
        $sinceText = [string]$stats["CrashFreeSince"]
    } elseif ($stats -and $stats.PSObject.Properties.Match("CrashFreeSince").Count -gt 0) {
        $sinceText = [string]$stats.CrashFreeSince
    }
    if ([string]::IsNullOrWhiteSpace($sinceText)) { return 0 }
    try {
        $since = [DateTime]::Parse($sinceText)
        return [Math]::Max(0, [int][Math]::Floor(($now - $since).TotalDays))
    } catch {
        return 0
    }
}

function Get-ProfileUsageSplitLabel($stats, [string]$activeProfile = "Default") {
    if (-not $stats) { return "N/A" }
    $profileUsage = @{}
    if ($stats -is [System.Collections.IDictionary] -and $stats.ContainsKey("ProfileUsageMinutes")) {
        $profileUsage = Convert-ToHashtable $stats["ProfileUsageMinutes"]
    } elseif ($stats -and $stats.PSObject.Properties.Match("ProfileUsageMinutes").Count -gt 0) {
        $profileUsage = Convert-ToHashtable $stats.ProfileUsageMinutes
    }
    if (-not $profileUsage -or @($profileUsage.Keys).Count -eq 0) {
        if ([string]::IsNullOrWhiteSpace($activeProfile)) { $activeProfile = "Default" }
        return ("{0} 100%" -f $activeProfile)
    }
    $totals = New-Object System.Collections.Generic.List[object]
    $totalMinutes = 0.0
    foreach ($key in @($profileUsage.Keys)) {
        $minutes = 0.0
        try { $minutes = [double]$profileUsage[$key] } catch { $minutes = 0.0 }
        if ($minutes -lt 0) { $minutes = 0.0 }
        $totalMinutes += $minutes
        [void]$totals.Add([pscustomobject]@{ Name = [string]$key; Minutes = $minutes })
    }
    if ($totalMinutes -le 0) { return "N/A" }
    $top = @($totals | Sort-Object Minutes -Descending | Select-Object -First 3)
    $parts = @()
    foreach ($entry in $top) {
        $pct = [int][Math]::Round(($entry.Minutes / $totalMinutes) * 100.0)
        $parts += ("{0} {1}%" -f $entry.Name, $pct)
    }
    return ($parts -join " | ")
}

function Get-UptimeReliabilityPercent($stats) {
    if (-not $stats) { return 100.0 }
    $reliable = 0.0
    $degraded = 0.0
    try {
        if ($stats -is [System.Collections.IDictionary]) {
            if ($stats.ContainsKey("ReliableMinutes")) { $reliable = [double]$stats["ReliableMinutes"] }
            if ($stats.ContainsKey("DegradedMinutes")) { $degraded = [double]$stats["DegradedMinutes"] }
        } else {
            if ($stats.PSObject.Properties.Match("ReliableMinutes").Count -gt 0) { $reliable = [double]$stats.ReliableMinutes }
            if ($stats.PSObject.Properties.Match("DegradedMinutes").Count -gt 0) { $degraded = [double]$stats.DegradedMinutes }
        }
    } catch {
        $reliable = 0.0
        $degraded = 0.0
    }
    $total = $reliable + $degraded
    if ($total -le 0) { return 100.0 }
    return [Math]::Round((($reliable / $total) * 100.0), 1)
}

function Get-EstimatedTimeSavedMinutes([int]$toggleCount) {
    $safeToggles = [Math]::Max(0, [int]$toggleCount)
    $secondsPerToggleSaved = 2.0
    return [Math]::Round((($safeToggles * $secondsPerToggleSaved) / 60.0), 1)
}

function Get-BadgeTrackingMode($settingsRef = $null) {
    $target = if ($settingsRef) { $settingsRef } else { $settings }
    $mode = "Global"
    try {
        $raw = [string](Get-SettingsPropertyValue $target "BadgeTrackingMode" "Global")
        if (-not [string]::IsNullOrWhiteSpace($raw)) { $mode = $raw }
    } catch {
        $mode = "Global"
    }
    switch ($mode.ToLowerInvariant()) {
        "profile" { return "Profile" }
        default { return "Global" }
    }
}

function Get-BadgeRarityIcon([string]$rarity) {
    $key = if ([string]::IsNullOrWhiteSpace($rarity)) { "" } else { $rarity.ToLowerInvariant() }
    switch ($key) {
        "uncommon" { return "[U]" }
        "rare" { return "[R]" }
        "epic" { return "[E]" }
        "legendary" { return "[L]" }
        "mythic" { return "[M]" }
        "transcendent" { return "[T]" }
        "ascended" { return "[A]" }
        "celestial" { return "[C*]" }
        "cosmic" { return "[X]" }
        "beyond" { return "[B]" }
        default { return "[C]" }
    }
}

function Get-BadgeRarityPoints([string]$rarity, [string]$kind = "Milestone") {
    $key = if ([string]::IsNullOrWhiteSpace($rarity)) { "" } else { $rarity.ToLowerInvariant() }
    $base = switch ($key) {
        "uncommon" { 20 }
        "rare" { 35 }
        "epic" { 55 }
        "legendary" { 85 }
        "mythic" { 120 }
        "transcendent" { 170 }
        "ascended" { 240 }
        "celestial" { 330 }
        "cosmic" { 460 }
        "beyond" { 640 }
        default { 12 }
    }
    $multiplier = switch ([string]$kind) {
        "Seasonal" { 1.1 }
        "Combo" { 1.25 }
        "Resilience" { 1.2 }
        "Bonus" { 0.9 }
        default { 1.0 }
    }
    return [int][Math]::Round(($base * $multiplier), 0)
}

function Get-BadgeTierName([long]$value) {
    $safe = [int64][Math]::Max(0, [int64]$value)
    if ($safe -ge 100000000) { return "Omega" }
    if ($safe -ge 10000000) { return "Mythic" }
    if ($safe -ge 1000000) { return "Diamond" }
    if ($safe -ge 100000) { return "Platinum" }
    if ($safe -ge 10000) { return "Gold" }
    if ($safe -ge 1000) { return "Silver" }
    return "Bronze"
}

function Get-MilestoneDefinitions {
    $raw = @(
        @{ Value = 100; Name = "Rookie"; Rarity = "Common" },
        @{ Value = 250; Name = "Consistent"; Rarity = "Common" },
        @{ Value = 500; Name = "Grinder"; Rarity = "Uncommon" },
        @{ Value = 1000; Name = "Dedicated"; Rarity = "Uncommon" },
        @{ Value = 2500; Name = "Streaker"; Rarity = "Rare" },
        @{ Value = 5000; Name = "Engine"; Rarity = "Rare" },
        @{ Value = 10000; Name = "Iron Will"; Rarity = "Epic" },
        @{ Value = 25000; Name = "Relentless"; Rarity = "Epic" },
        @{ Value = 50000; Name = "Unstoppable"; Rarity = "Legendary" },
        @{ Value = 100000; Name = "Legend"; Rarity = "Legendary" },
        @{ Value = 250000; Name = "Mythic"; Rarity = "Mythic" },
        @{ Value = 500000; Name = "Titan"; Rarity = "Mythic" },
        @{ Value = 1000000; Name = "Godmode"; Rarity = "Transcendent" },
        @{ Value = 2500000; Name = "Warp Drive"; Rarity = "Transcendent" },
        @{ Value = 5000000; Name = "Reality Bender"; Rarity = "Transcendent" },
        @{ Value = 10000000; Name = "Time Lord"; Rarity = "Ascended" },
        @{ Value = 25000000; Name = "Planetary"; Rarity = "Ascended" },
        @{ Value = 50000000; Name = "Galactic"; Rarity = "Ascended" },
        @{ Value = 100000000; Name = "Universal"; Rarity = "Celestial" },
        @{ Value = 250000000; Name = "Multiversal"; Rarity = "Celestial" },
        @{ Value = 500000000; Name = "Infinity"; Rarity = "Cosmic" },
        @{ Value = 1000000000; Name = "Impossible"; Rarity = "Cosmic" },
        @{ Value = 2000000000; Name = "Absurdity Achieved"; Rarity = "Beyond" }
    )
    $defs = @()
    foreach ($entry in $raw) {
        $value = [int64]$entry.Value
        $rarity = [string]$entry.Rarity
        $defs += [pscustomobject]@{
            Id     = ("milestone-{0}" -f $value)
            Kind   = "Milestone"
            Value  = $value
            Name   = [string]$entry.Name
            Rarity = $rarity
            Tier   = Get-BadgeTierName $value
            Icon   = Get-BadgeRarityIcon $rarity
            Points = Get-BadgeRarityPoints $rarity "Milestone"
        }
    }
    return $defs
}

function Get-MilestoneInfo([long]$toggleCount) {
    $safeToggles = [int64][Math]::Max(0, [int64]$toggleCount)
    $milestones = Get-MilestoneDefinitions
    $lastReached = $null
    $next = $null
    $previousValue = 0L
    foreach ($m in $milestones) {
        $value = [int64]$m.Value
        if ($safeToggles -ge $value) {
            $lastReached = $m
            $previousValue = $value
        } else {
            $next = $m
            break
        }
    }
    if ($null -eq $next) {
        $lastValue = if ($lastReached) { [int64]$lastReached.Value } else { 0L }
        $lastName = if ($lastReached) { [string]$lastReached.Name } else { "None" }
        $lastRarity = if ($lastReached) { [string]$lastReached.Rarity } else { "Common" }
        return [pscustomobject]@{
            CurrentId         = if ($lastReached) { [string]$lastReached.Id } else { "" }
            CurrentValue      = $lastValue
            CurrentName       = $lastName
            CurrentRarity     = $lastRarity
            CurrentTier       = if ($lastReached) { [string]$lastReached.Tier } else { "Bronze" }
            CurrentIcon       = if ($lastReached) { [string]$lastReached.Icon } else { (Get-BadgeRarityIcon "Common") }
            NextId            = $null
            NextValue         = $null
            NextName          = "MAX"
            NextRarity        = $lastRarity
            NextTier          = if ($lastReached) { [string]$lastReached.Tier } else { "Bronze" }
            NextIcon          = if ($lastReached) { [string]$lastReached.Icon } else { (Get-BadgeRarityIcon "Common") }
            LeftToNext        = 0L
            ProgressToNextPct = 100.0
            IsMax             = $true
        }
    }

    $nextValue = [int64]$next.Value
    $leftToNext = [int64][Math]::Max(0, ($nextValue - $safeToggles))
    $range = [double]([Math]::Max(1L, ($nextValue - $previousValue)))
    $progressRaw = (($safeToggles - $previousValue) / $range) * 100.0
    $progress = [Math]::Round([Math]::Max(0.0, [Math]::Min(100.0, $progressRaw)), 1)

    return [pscustomobject]@{
        CurrentId         = if ($lastReached) { [string]$lastReached.Id } else { "" }
        CurrentValue      = if ($lastReached) { [int64]$lastReached.Value } else { 0L }
        CurrentName       = if ($lastReached) { [string]$lastReached.Name } else { "None yet" }
        CurrentRarity     = if ($lastReached) { [string]$lastReached.Rarity } else { "Common" }
        CurrentTier       = if ($lastReached) { [string]$lastReached.Tier } else { "Bronze" }
        CurrentIcon       = if ($lastReached) { [string]$lastReached.Icon } else { (Get-BadgeRarityIcon "Common") }
        NextId            = [string]$next.Id
        NextValue         = $nextValue
        NextName          = [string]$next.Name
        NextRarity        = [string]$next.Rarity
        NextTier          = [string]$next.Tier
        NextIcon          = [string]$next.Icon
        LeftToNext        = $leftToNext
        ProgressToNextPct = $progress
        IsMax             = $false
    }
}

function Get-BonusBadgeDefinitions {
    return @(
        [pscustomobject]@{ Id = "bonus-streak-keeper"; Name = "Streak Keeper"; Kind = "Bonus"; Rarity = "Uncommon"; Tier = "Bronze"; Icon = (Get-BadgeRarityIcon "Uncommon"); Points = (Get-BadgeRarityPoints "Uncommon" "Bonus") },
        [pscustomobject]@{ Id = "bonus-streak-master"; Name = "Streak Master"; Kind = "Bonus"; Rarity = "Rare"; Tier = "Silver"; Icon = (Get-BadgeRarityIcon "Rare"); Points = (Get-BadgeRarityPoints "Rare" "Bonus") },
        [pscustomobject]@{ Id = "bonus-crashfree-week"; Name = "Crash-Free Week"; Kind = "Bonus"; Rarity = "Uncommon"; Tier = "Bronze"; Icon = (Get-BadgeRarityIcon "Uncommon"); Points = (Get-BadgeRarityPoints "Uncommon" "Bonus") },
        [pscustomobject]@{ Id = "bonus-crashfree-month"; Name = "Crash-Free Month"; Kind = "Bonus"; Rarity = "Rare"; Tier = "Silver"; Icon = (Get-BadgeRarityIcon "Rare"); Points = (Get-BadgeRarityPoints "Rare" "Bonus") },
        [pscustomobject]@{ Id = "bonus-reliable-ops"; Name = "Reliable Ops"; Kind = "Bonus"; Rarity = "Uncommon"; Tier = "Bronze"; Icon = (Get-BadgeRarityIcon "Uncommon"); Points = (Get-BadgeRarityPoints "Uncommon" "Bonus") },
        [pscustomobject]@{ Id = "bonus-rock-solid"; Name = "Rock Solid"; Kind = "Bonus"; Rarity = "Epic"; Tier = "Gold"; Icon = (Get-BadgeRarityIcon "Epic"); Points = (Get-BadgeRarityPoints "Epic" "Bonus") },
        [pscustomobject]@{ Id = "bonus-marathon"; Name = "Marathon"; Kind = "Bonus"; Rarity = "Uncommon"; Tier = "Bronze"; Icon = (Get-BadgeRarityIcon "Uncommon"); Points = (Get-BadgeRarityPoints "Uncommon" "Bonus") },
        [pscustomobject]@{ Id = "bonus-nosleep"; Name = "No-Sleep Mode"; Kind = "Bonus"; Rarity = "Legendary"; Tier = "Platinum"; Icon = (Get-BadgeRarityIcon "Legendary"); Points = (Get-BadgeRarityPoints "Legendary" "Bonus") },
        [pscustomobject]@{ Id = "bonus-million"; Name = "One-in-a-Million"; Kind = "Bonus"; Rarity = "Mythic"; Tier = "Diamond"; Icon = (Get-BadgeRarityIcon "Mythic"); Points = (Get-BadgeRarityPoints "Mythic" "Bonus") }
    )
}

function Get-SeasonalBadgeDefinitions {
    return @(
        [pscustomobject]@{ Id = "season-winter"; Name = "Winter Operator"; Season = "Winter"; Kind = "Seasonal"; Rarity = "Rare"; Tier = "Silver"; Icon = (Get-BadgeRarityIcon "Rare"); Points = (Get-BadgeRarityPoints "Rare" "Seasonal") },
        [pscustomobject]@{ Id = "season-spring"; Name = "Spring Operator"; Season = "Spring"; Kind = "Seasonal"; Rarity = "Rare"; Tier = "Silver"; Icon = (Get-BadgeRarityIcon "Rare"); Points = (Get-BadgeRarityPoints "Rare" "Seasonal") },
        [pscustomobject]@{ Id = "season-summer"; Name = "Summer Operator"; Season = "Summer"; Kind = "Seasonal"; Rarity = "Epic"; Tier = "Gold"; Icon = (Get-BadgeRarityIcon "Epic"); Points = (Get-BadgeRarityPoints "Epic" "Seasonal") },
        [pscustomobject]@{ Id = "season-autumn"; Name = "Autumn Operator"; Season = "Autumn"; Kind = "Seasonal"; Rarity = "Rare"; Tier = "Silver"; Icon = (Get-BadgeRarityIcon "Rare"); Points = (Get-BadgeRarityPoints "Rare" "Seasonal") }
    )
}

function Get-ComboBadgeDefinitions {
    return @(
        [pscustomobject]@{ Id = "combo-precision-triple"; Name = "Precision Triple"; Kind = "Combo"; Rarity = "Epic"; Tier = "Gold"; Icon = (Get-BadgeRarityIcon "Epic"); Points = (Get-BadgeRarityPoints "Epic" "Combo") },
        [pscustomobject]@{ Id = "combo-momentum-chain"; Name = "Momentum Chain"; Kind = "Combo"; Rarity = "Legendary"; Tier = "Platinum"; Icon = (Get-BadgeRarityIcon "Legendary"); Points = (Get-BadgeRarityPoints "Legendary" "Combo") },
        [pscustomobject]@{ Id = "combo-iron-marathon"; Name = "Iron Marathon"; Kind = "Combo"; Rarity = "Mythic"; Tier = "Diamond"; Icon = (Get-BadgeRarityIcon "Mythic"); Points = (Get-BadgeRarityPoints "Mythic" "Combo") }
    )
}

function Get-ResilienceBadgeDefinitions {
    return @(
        [pscustomobject]@{ Id = "resilience-bounceback"; Name = "Bounceback"; Kind = "Resilience"; Rarity = "Uncommon"; Tier = "Bronze"; Icon = (Get-BadgeRarityIcon "Uncommon"); Points = (Get-BadgeRarityPoints "Uncommon" "Resilience") },
        [pscustomobject]@{ Id = "resilience-hardened"; Name = "Hardened"; Kind = "Resilience"; Rarity = "Epic"; Tier = "Gold"; Icon = (Get-BadgeRarityIcon "Epic"); Points = (Get-BadgeRarityPoints "Epic" "Resilience") },
        [pscustomobject]@{ Id = "resilience-unkillable"; Name = "Unkillable"; Kind = "Resilience"; Rarity = "Legendary"; Tier = "Platinum"; Icon = (Get-BadgeRarityIcon "Legendary"); Points = (Get-BadgeRarityPoints "Legendary" "Resilience") }
    )
}

function Get-BadgeCatalogDefinitions {
    return @(
        @(Get-MilestoneDefinitions) +
        @(Get-BonusBadgeDefinitions) +
        @(Get-SeasonalBadgeDefinitions) +
        @(Get-ComboBadgeDefinitions) +
        @(Get-ResilienceBadgeDefinitions)
    )
}

function Get-BadgeSeasonName([DateTime]$now = (Get-Date)) {
    switch ([int]$now.Month) {
        { $_ -in 12,1,2 } { return "Winter" }
        { $_ -in 3,4,5 } { return "Spring" }
        { $_ -in 6,7,8 } { return "Summer" }
        default { return "Autumn" }
    }
}

function Get-SeasonalBadgeDefinition([DateTime]$now = (Get-Date)) {
    $season = Get-BadgeSeasonName $now
    foreach ($def in (Get-SeasonalBadgeDefinitions)) {
        if ([string]$def.Season -eq $season) { return $def }
    }
    return $null
}

function Get-BadgeLevelInfo([int]$points) {
    $safePoints = [Math]::Max(0, [int]$points)
    $level = [Math]::Max(1, [int][Math]::Floor([Math]::Sqrt($safePoints / 25.0)) + 1)
    $currentFloor = [int](25 * [Math]::Pow(($level - 1), 2))
    $nextAt = [int](25 * [Math]::Pow($level, 2))
    $delta = [Math]::Max(1, ($nextAt - $currentFloor))
    $progress = [Math]::Round(([Math]::Max(0, ($safePoints - $currentFloor)) / [double]$delta) * 100.0, 1)
    return [pscustomobject]@{
        Level = $level
        NextLevelAt = $nextAt
        ProgressPct = [Math]::Max(0.0, [Math]::Min(100.0, $progress))
    }
}

function Get-BonusBadgeLabel($stats, [int]$currentStreak = 0, [double]$reliabilityPercent = 100.0, [int]$crashFreeDays = 0, [double]$totalRunMinutes = 0.0, [long]$lifetimeToggleCount = 0) {
    $badges = New-Object System.Collections.Generic.List[string]
    if ($currentStreak -ge 30) { [void]$badges.Add("Streak Master") }
    elseif ($currentStreak -ge 7) { [void]$badges.Add("Streak Keeper") }
    if ($crashFreeDays -ge 30) { [void]$badges.Add("Crash-Free Month") }
    elseif ($crashFreeDays -ge 7) { [void]$badges.Add("Crash-Free Week") }
    if ($reliabilityPercent -ge 99.9) { [void]$badges.Add("Rock Solid") }
    elseif ($reliabilityPercent -ge 98.0) { [void]$badges.Add("Reliable Ops") }
    if ($totalRunMinutes -ge 43200) { [void]$badges.Add("No-Sleep Mode") }
    elseif ($totalRunMinutes -ge 1440) { [void]$badges.Add("Marathon") }
    if ($lifetimeToggleCount -ge 1000000) { [void]$badges.Add("One-in-a-Million") }
    if ($badges.Count -eq 0) { return "None yet" }
    return (($badges | Select-Object -Unique) -join ", ")
}

function Get-MilestoneStatus([int]$toggleCount) {
    $info = Get-MilestoneInfo ([int64]$toggleCount)
    if ($info.IsMax) {
        return ("Max milestone reached: {0} {1:N0} ({2}) [{3}]" -f [string]$info.CurrentIcon, [int64]$info.CurrentValue, [string]$info.CurrentName, [string]$info.CurrentTier)
    }
    if ([int64]$info.CurrentValue -le 0) {
        return ("Next: {0} {1:N0} ({2}) [{3}] [{4:N0} left]" -f [string]$info.NextIcon, [int64]$info.NextValue, [string]$info.NextName, [string]$info.NextTier, [int64]$info.LeftToNext)
    }
    return ("Reached: {0} {1:N0} ({2}) [{3}] | Next: {4} {5:N0} ({6}) [{7}] [{8:N0} left]" -f [string]$info.CurrentIcon, [int64]$info.CurrentValue, [string]$info.CurrentName, [string]$info.CurrentTier, [string]$info.NextIcon, [int64]$info.NextValue, [string]$info.NextName, [string]$info.NextTier, [int64]$info.LeftToNext)
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
$script:StatsLastSampleAt = Get-Date
$script:StatsLastSampleProfile = [string](Get-SettingsPropertyValue $settings "ActiveProfile" "Default")
Sync-StateFromSettings $settings
Apply-StateToSettings $settings $script:AppState
Save-StateImmediate $script:AppState
# --- Stats persistence and next-toggle calculations ---
function Save-Stats {
    if ($null -eq (Get-SettingsPropertyValue $settings "ToggleCount")) {
        Set-SettingsPropertyValue $settings "ToggleCount" 0
    }
    Set-SettingsPropertyValue $settings "LastToggleTime" $(if ($script:lastToggleTime) { $script:lastToggleTime.ToString("o") } else { $null })
    Update-FunStatsRuntimeProgress (Get-Date)
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
    if ($item -is [System.Windows.Forms.ToolStripLabel]) {
        $item.ForeColor = $palette.MenuFore
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
    try { Request-StatusUpdate } catch { Write-IgnoredCatch $_ }
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
    try { Request-StatusUpdate } catch { Write-IgnoredCatch $_ }
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
    try { Sync-MinimalModeState "ResetSafeMode" } catch { Write-IgnoredCatch $_ }
    Request-StatusUpdate
    Write-Log "Safe Mode reset." "INFO" $null "SafeMode"
}

function Reset-CrashRecoveryState {
    try {
        $crashState = Get-CrashState
        if ($crashState) {
            $crashState.Count = 0
            $crashState.LastCrash = $null
            $crashState.OverrideMinimalMode = $false
            $crashState.OverrideMinimalModeLogged = $false
            Save-CrashState $crashState
        }
    } catch {
        Write-Log "Reset crash recovery state encountered an error while updating crash counters." "WARN" $_.Exception "SafeMode"
    }
    $script:OverrideMinimalMode = $false
    $script:MinimalModeActive = $false
    $script:MinimalModeReason = $null
    $script:safeModeActive = $false
    $script:toggleFailCount = 0
    try { Sync-MinimalModeState "ResetCrashRecoveryState" } catch { Write-IgnoredCatch $_ }
    Request-StatusUpdate
    Write-Log "Crash recovery state reset (crash counters and safe mode cleared)." "INFO" $null "SafeMode"
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
    try { Register-Hotkeys } catch { Write-IgnoredCatch $_ }
    try { Update-NextToggleTime } catch { Write-IgnoredCatch $_ }
    Request-StatusUpdate
    Write-Log "Recovery requested: Safe Mode cleared and hotkeys re-registered." "INFO" $null "SafeMode"
    try {
        Show-Balloon "Teams-Always-Green" "Recovery complete. Safe Mode cleared and hotkeys re-registered." ([System.Windows.Forms.ToolTipIcon]::Info)
    } catch { Write-IgnoredCatch $_ }
}

function Start-RepairMode {
    if ($script:RepairModeActive) { return }
    $script:RepairModeActive = $true
    Add-SelfHealRecentAction "RepairMode" "Started" ""
    try {
        Write-Log "Repair mode started." "WARN" $null "Recovery"
        try { Flush-SettingsSave } catch { Write-IgnoredCatch $_ }
        try { Reset-CrashRecoveryState } catch { Write-IgnoredCatch $_ }
        try {
            $lastGoodSettings = Load-LastGoodSettings
            if ($lastGoodSettings) {
                $settings = Normalize-Settings (Migrate-Settings $lastGoodSettings)
                Save-SettingsImmediate $settings
                Write-Log "Repair mode: restored settings from last known good snapshot." "WARN" $null "Recovery"
                Add-SelfHealRecentAction "RepairMode" "Succeeded" "Restored settings snapshot"
            }
        } catch {
            Write-LogExceptionDeduped "Repair mode failed while restoring settings snapshot." "WARN" $_.Exception "Recovery" 20
            Add-SelfHealRecentAction "RepairMode" "Retry" "Settings snapshot restore failed"
        }
        try {
            $lastGoodState = Load-LastGoodState
            if ($lastGoodState) {
                $script:AppState = Normalize-State $lastGoodState
                Save-StateImmediate $script:AppState
                Apply-StateToSettings $settings $script:AppState
                Write-Log "Repair mode: restored runtime state from last known good snapshot." "WARN" $null "Recovery"
                Add-SelfHealRecentAction "RepairMode" "Succeeded" "Restored runtime state snapshot"
            }
        } catch {
            Write-LogExceptionDeduped "Repair mode failed while restoring runtime state snapshot." "WARN" $_.Exception "Recovery" 20
            Add-SelfHealRecentAction "RepairMode" "Retry" "State snapshot restore failed"
        }
        try { Apply-SettingsRuntime } catch { Write-IgnoredCatch $_ }
        try { Request-StatusUpdate } catch { Write-IgnoredCatch $_ }
        try { Update-TrayLabels } catch { Write-IgnoredCatch $_ }
        try {
            Show-Balloon "Teams-Always-Green" "Repair mode completed. Recovery actions were applied." ([System.Windows.Forms.ToolTipIcon]::Info)
        } catch { Write-IgnoredCatch $_ }
        Write-Log "Repair mode completed." "INFO" $null "Recovery"
        Add-SelfHealRecentAction "RepairMode" "Completed" "Recovery actions applied"
    } finally {
        $script:RepairModeActive = $false
    }
}

function Start-HealthMonitor {
    if ($script:HealthMonitorTimer) { return }
    $script:HealthMonitorTimer = New-Object System.Windows.Forms.Timer
    $script:HealthMonitorTimer.Interval = 300000
    $script:HealthMonitorTimer.Add_Tick({
        Invoke-SafeTimerAction "HealthMonitorTimer" {
            if ($script:isShuttingDown -or $script:CleanupDone) { return }
            if (-not (Test-Path $script:settingsPath)) {
                Write-LogThrottled "HealthMonitor-SettingsMissing" "Health monitor: settings file missing; attempting self-heal." "WARN" 120
                Start-RepairMode
                return
            }
            if (-not (Test-Path $script:StatePath)) {
                Write-LogThrottled "HealthMonitor-StateMissing" "Health monitor: state file missing; recreating runtime state." "WARN" 120
                Save-StateImmediate $script:AppState
                return
            }
            if (-not (Test-SettingsStateIntegrity)) {
                Write-LogThrottled "HealthMonitor-SettingsStateMismatch" "Health monitor: settings/state integrity mismatch detected; queuing repair-all." "WARN" 120
                Enqueue-SelfHealAction -Name "SettingsStateIntegrity" -Reason "Settings hash mismatch" -InitialDelaySeconds 1 -MaxAttempts 2 -WindowSeconds 600 -MaxPerWindow 3 -Action {
                    Invoke-RepairAll -Source "integrity-watchdog" | Out-Null
                } | Out-Null
                return
            }
            if ($script:SelfHealStats.SuppressedErrorCount -gt 0) {
                Write-LogThrottled "HealthMonitor-SuppressedErrors" ("Health monitor: suppressed repeated errors={0}" -f [int]$script:SelfHealStats.SuppressedErrorCount) "INFO" 300
            }
            try { Invoke-HeartbeatWatchdog } catch { Write-IgnoredCatch $_ }
            try { Invoke-SelfHealQueue } catch { Write-IgnoredCatch $_ }
        }
    })
    $script:ComponentHeartbeat["HealthMonitorTimer"] = Get-Date
    $script:HealthMonitorTimer.Start()
    Start-SelfHealQueueTimer
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
        if ($script:isRunning -and -not $script:isPaused -and -not $script:isScheduleBlocked -and $null -eq $script:nextToggleTime) {
            Update-NextToggleTime
        }
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
        $pauseUntilText = Format-PauseUntilText
        $nextText = "N/A"
        $nextRemainingSeconds = $null
        if ($script:isPaused) {
            $nextText = "Paused"
        } elseif ($script:isRunning -and $script:isScheduleSuspended) {
            $nextText = "Suspended"
        } elseif ($script:isRunning -and $script:isScheduleBlocked) {
            $nextText = "Scheduled"
        } elseif ($script:isRunning) {
            $nowRuntime = Get-Now
            $intervalSeconds = [Math]::Max(1, [int]$settings.IntervalSeconds)
            if ($null -eq $script:nextToggleTime) {
                $script:nextToggleTime = $nowRuntime.AddSeconds($intervalSeconds)
            } elseif ($script:nextToggleTime -le $nowRuntime) {
                $script:nextToggleTime = $nowRuntime.AddSeconds($intervalSeconds)
            }
            $remaining = [int][Math]::Max(0, ($script:nextToggleTime - $nowRuntime).TotalSeconds)
            $nextRemainingSeconds = $remaining
            $nextTime = Format-TimeOrNever $script:nextToggleTime $showSeconds
            $nextText = "$remaining s ($nextTime)"
        }
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
        if ([string]::IsNullOrWhiteSpace($displayNext)) {
            $displayNext = [string]$nextText
        }
        $displayPause = Localize-StatusValue $pauseUntilText
        $activeProfileName = [string]$settings.ActiveProfile
        if ([string]::IsNullOrWhiteSpace($activeProfileName)) { $activeProfileName = "Default" }
        $scheduleText = Format-ScheduleStatus
        $displaySchedule = Localize-StatusValue $scheduleText

        $summaryState = if ($script:isRunning -and -not $script:isPaused -and -not $script:isScheduleBlocked -and -not $script:isScheduleSuspended) {
            "Running"
        } elseif ($script:isRunning -or $script:isPaused) {
            "Paused"
        } else {
            "Stopped"
        }
        $summaryStateText = Localize-StatusValue $summaryState
        $summaryStateValue = $summaryStateText
        $summaryNextCompact = if ($null -ne $nextRemainingSeconds) { "$nextRemainingSeconds s" } else { $nextText }
        $summaryNextDisplay = Localize-StatusValue $summaryNextCompact
        if ([string]::IsNullOrWhiteSpace($summaryNextDisplay)) {
            $summaryNextDisplay = [string]$summaryNextCompact
        }
        $summaryStatusLabel = [string](L "Status")
        if ([string]::IsNullOrWhiteSpace($summaryStatusLabel)) { $summaryStatusLabel = "Status" }
        # Keep top summary compact: status only. "Next" appears on its own line below.
        $summaryText = ("{0}: {1}" -f $summaryStatusLabel, $summaryStateValue)

        $nextExactDetail = if ($script:isRunning -and -not $script:isPaused -and -not $script:isScheduleBlocked -and -not $script:isScheduleSuspended -and $script:nextToggleTime) {
            Format-TimeOrNever $script:nextToggleTime $showSeconds
        } else {
            $nextText
        }
        $summaryTooltip = @(
            ((L "Status: {0}") -f $stateText),
            ((L "Next: {0}") -f $summaryNextDisplay),
            ((L "Next At: {0}") -f (Localize-StatusValue $nextExactDetail)),
            ((L "Interval: {0}s") -f $settings.IntervalSeconds),
            ("{0}: {1}" -f (L "Active Profile"), $activeProfileName),
            ((L "Schedule: {0}") -f $displaySchedule)
        ) -join [Environment]::NewLine

        if ($script:TrayStatusSummaryItem) {
            $script:TrayStatusSummaryItem.Text = $summaryText
            $script:TrayStatusSummaryItem.ForeColor = $script:StatusStateColor
            $script:TrayStatusSummaryItem.Tag = $null
            $script:TrayStatusSummaryItem.ToolTipText = $summaryTooltip
        }
        $topNextText = $summaryNextDisplay
        if ($script:TrayStatusStateItem) {
            $script:TrayStatusStateItem.Text = ((L "Status: {0}") -f $stateText)
            $script:TrayStatusStateItem.ForeColor = $script:StatusStateColor
            $script:TrayStatusStateItem.Tag = $null
        }
        if ($script:TrayStatusNextItem) {
            if ([string]::IsNullOrWhiteSpace($topNextText)) {
                $topNextText = (L "N/A")
            }
            $nextTemplate = [string](L "Next: {0}")
            if ($nextTemplate -notlike "*{0}*") {
                $nextTemplate = "Next: {0}"
            }
            $script:TrayStatusNextItem.Text = ($nextTemplate -f $topNextText)
            if ($contextMenu) {
                $script:TrayStatusNextItem.ForeColor = $contextMenu.ForeColor
            } else {
                $script:TrayStatusNextItem.ForeColor = [System.Drawing.Color]::Empty
            }
            $script:TrayStatusNextItem.Tag = $null
        }
        if ($script:TrayStatusProfileItem) {
            $script:TrayStatusProfileItem.Text = ("{0}: {1}" -f (L "Active Profile"), $activeProfileName)
            if ($contextMenu) {
                $script:TrayStatusProfileItem.ForeColor = $contextMenu.ForeColor
            } else {
                $script:TrayStatusProfileItem.ForeColor = [System.Drawing.Color]::Empty
            }
            $script:TrayStatusProfileItem.Tag = $null
        }
        $statusLineState.Text = ((L "Status: {0}") -f $stateText)
        $statusLineState.Tag = $state
        $statusLineState.ForeColor = $script:StatusStateColor
        $statusLineInterval.Text = ((L "Interval: {0}s") -f $settings.IntervalSeconds)
        $statusLineToggles.Text = ((L "Toggles: {0}") -f $script:tickCount)
        $statusLineLast.Text = ((L "Last: {0}") -f $displayLast)
        $statusLineNext.Text = ((L "Next: {0}") -f $displayNext)
        $statusLinePauseUntil.Text = ((L "Paused Until: {0}") -f $displayPause)
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
        if ($runOnceNowItem) {
            $runOnceNowItem.Enabled = -not $script:safeModeActive
            if ([string]::IsNullOrWhiteSpace([string]$runOnceNowItem.Text)) {
                $runOnceNowItem.Text = (L "Run Once (Next Cycle)" "Run Once Next Cycle")
            }
            if ($contextMenu) {
                $runOnceNowItem.ForeColor = $contextMenu.ForeColor
            } else {
                $runOnceNowItem.ForeColor = [System.Drawing.Color]::Empty
            }
        }
        if ($script:pauseResumeItem) { $script:pauseResumeItem.Enabled = $script:isPaused }
        if ($script:pauseUntilItem) { $script:pauseUntilItem.Enabled = -not $script:isPaused }
        if ($resetSafeModeItem) { $resetSafeModeItem.Visible = $script:safeModeActive }
        if ($recoverNowItem) { $recoverNowItem.Visible = $script:safeModeActive }
        if (Get-Command -Name Update-StatusBadges -ErrorAction SilentlyContinue) { Update-StatusBadges }
        Update-NotifyIconState
        Update-NotifyIconText $state
        $settingsFormVar = Get-Variable -Name SettingsForm -Scope Script -ErrorAction SilentlyContinue
        $settingsVisible = $false
        if ($settingsFormVar -and $settingsFormVar.Value -and -not $settingsFormVar.Value.IsDisposed) {
            $settingsVisible = [bool]$settingsFormVar.Value.Visible
        }
        if (-not $settingsVisible) {
            Write-StatusSnapshot $state $lastText $nextText $pauseUntilText $scheduleText
        }
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
        if ($script:StatusFilePath -is [System.IO.FileInfo]) {
            $script:StatusFilePath = $script:StatusFilePath.FullName
        } elseif ($script:StatusFilePath -isnot [string]) {
            $script:StatusFilePath = [string]$script:StatusFilePath
        }
        [System.IO.File]::WriteAllText($script:StatusFilePath, $json, (New-Object System.Text.UTF8Encoding($false)))
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
    if ($script:HotkeysReady) {
        Register-Hotkeys
    } else {
        $script:HotkeysPending = $true
    }
    Rebuild-PauseMenu
    Update-TrayLabels
    Update-NextToggleTime
    Request-StatusUpdate
    if ($script:TrayMenuHeavyInitialized) {
        if ($updateQuickSettingsChecks) { & $updateQuickSettingsChecks }
        if ($updateProfilesMenu) { & $updateProfilesMenu }
        $script:TrayMenuNeedsRefresh = $false
    } else {
        $script:TrayMenuNeedsRefresh = $true
    }
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
    Set-SettingsPropertyValue $settings "FirstRunToastShown" $true
    Save-Settings $settings
    Write-Log "First-run tips shown." "INFO" $null "Startup"
    Show-Balloon "Teams-Always-Green" "Tip: Right-click the tray icon to start, pause, or open Settings." ([System.Windows.Forms.ToolTipIcon]::Info)
}

function Do-Toggle([string]$source) {
    if ($script:isToggling) { return }
    $script:isToggling = $true
    $step = "toggle"
    try {
        Invoke-ScrollLockToggleInternal
        $step = "stats:ToggleCount"
        $script:toggleFailCount = 0
        $currentToggleCount = Get-SettingsPropertyValue $settings "ToggleCount"
        if ($null -eq $currentToggleCount) { $currentToggleCount = 0 }
        Set-SettingsPropertyValue $settings "ToggleCount" ([int]$currentToggleCount + 1)
        $step = "stats:LastToggleTime"
        $script:tickCount++
        $script:lastToggleTime = Get-Date
        $script:LastToggleResult = "Success"
        $script:LastToggleResultTime = $script:lastToggleTime
        $script:LastToggleError = $null
        $step = "stats:FunStats"
        Update-FunStatsOnToggle $script:lastToggleTime
        $step = "stats:NextToggle"
        if ($script:isRunning) { Update-NextToggleTime }
        $step = "ui:StatusUpdate"
        Request-StatusUpdate
        $step = "state:SaveStats"
        Save-Stats
        Write-Log "Toggle succeeded (source=$source). ToggleCount=$($script:tickCount)" "INFO" $null "Do-Toggle"
    } catch {
        Write-Log ("Toggle failed (source={0}) at step={1}." -f $source, $step) "ERROR" $_.Exception "Do-Toggle"
        try {
            if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
                Write-Log ("Toggle failure location: {0}" -f $_.InvocationInfo.PositionMessage.Trim()) "ERROR" $null "Do-Toggle"
            }
        } catch { Write-IgnoredCatch $_ }
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
    Update-ScheduleBlock | Out-Null
    if ($script:isScheduleBlocked) {
        $timer.Stop()
        $script:nextToggleTime = $null
    } else {
        Update-NextToggleTime
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
    try { Update-StatusText } catch { Write-IgnoredCatch $_ }
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
    try { Update-StatusText } catch { Write-IgnoredCatch $_ }
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

    try { Flush-SettingsSave } catch { Write-IgnoredCatch $_ }
    try { Flush-LogBuffer } catch { Write-IgnoredCatch $_ }

    try { $timer.Stop() } catch { Write-IgnoredCatch $_ }
    try { $pauseTimer.Stop() } catch { Write-IgnoredCatch $_ }
    try { $watchdogTimer.Stop() } catch { Write-IgnoredCatch $_ }
    try { $statusUpdateTimer.Stop() } catch { Write-IgnoredCatch $_ }
    try { if ($script:DeferredMaintenanceTimer) { $script:DeferredMaintenanceTimer.Stop() } } catch { Write-IgnoredCatch $_ }

    Unregister-Hotkeys
    Apply-SettingsRuntime
    Refresh-TrayMenu -SkipHeavyBuild

    try { $pauseTimer.Start() } catch { Write-IgnoredCatch $_ }
    try { $watchdogTimer.Start() } catch { Write-IgnoredCatch $_ }
    try { $statusUpdateTimer.Start() } catch { Write-IgnoredCatch $_ }

    if ($wasRunning -and -not $wasPaused) {
        Start-Toggling
    } elseif ($timer.Enabled) {
        $timer.Stop()
    }

    Request-StatusUpdate
    Write-Log "Soft restart completed." "INFO" $null "Restart"
}

Sync-SettingsReference $settings

# Load tray menu after core functions are defined
$trayModulePath = Join-Path $PSScriptRoot "Tray\\Menu.ps1"
$script:TrayModuleHealthy = $true
if (-not (Test-RuntimeModulePathAllowed -path $trayModulePath -tag "Tray-Module")) {
    $reason = if ([string]::IsNullOrWhiteSpace($script:RuntimeModuleLastError)) { "Unknown reason." } else { $script:RuntimeModuleLastError }
    Write-Log ("Tray-Module: runtime module path blocked. Reason={0}" -f $reason) "ERROR" $null "Tray-Module"
    $script:TrayModuleHealthy = $false
}
if ($script:TrayModuleHealthy) {
    try {
        # Tray module defines both functions and top-level runtime objects (for example
        # context menu instances), so it must load in script scope.
        . $trayModulePath
        $script:RuntimeModuleLastError = ""
    } catch {
        $script:RuntimeModuleLastError = [string]$_.Exception.Message
        Write-SecurityMessage ("Tray-Module: runtime module import failed: {0}" -f $trayModulePath) "ERROR" "Tray-Module"
        if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) {
            Write-SecurityAuditEvent "RuntimeModuleImportFailed" ("{0}|{1}" -f $trayModulePath, $script:RuntimeModuleLastError) "ERROR" "Tray-Module"
        }
        $script:TrayModuleHealthy = $false
    }
}
Write-BootStage "Tray menu loaded"
if ($script:TrayModuleHealthy -and (Get-Command Test-ModuleFunctionContract -ErrorAction SilentlyContinue)) {
    $trayRequiredFunctions = @("Update-TrayLabels", "Invoke-TrayAction", "Set-StatusUpdateTimerEnabled")
    $trayFunctionMap = @{}
    foreach ($trayFunctionName in $trayRequiredFunctions) {
        $trayCommand = Get-Command -Name $trayFunctionName -CommandType Function -ErrorAction SilentlyContinue
        if ($trayCommand -and $trayCommand.ScriptBlock) {
            $trayFunctionMap[$trayFunctionName] = $trayCommand.ScriptBlock
        }
    }
    $trayContractResult = Test-ModuleFunctionContract -ModuleTag "Tray-Module" -FunctionMap $trayFunctionMap -RequiredFunctions $trayRequiredFunctions
    if (-not $trayContractResult.IsValid) {
        $missing = $trayContractResult.MissingFunctions -join ", "
        Write-Log ("Tray-Module: Required functions missing: {0}" -f $missing) "ERROR" $null "Tray-Module"
        $script:TrayModuleHealthy = $false
    }
}
if ($script:TrayModuleHealthy -and -not (Test-ModuleVersionContract "Tray-Module" "Get-TrayModuleVersion")) {
    $script:TrayModuleHealthy = $false
}
if (-not $script:TrayModuleHealthy) {
    $script:SelfHealStats.TrayFallbackCount = [int]$script:SelfHealStats.TrayFallbackCount + 1
    Write-Log "Tray-Module: entering self-heal fallback mode (limited tray features)." "WARN" $null "Tray-Module"
    try { Ensure-TrayModuleFallback } catch { Write-IgnoredCatch $_ }
}

$script:SettingsUiLoaded = $false
$script:HistoryUiLoaded = $false
$script:ImportedUiFunctions = @{}
$script:UiModuleContracts = @{
    "Settings-UI" = @("Show-SettingsDialog", "Show-LogTailDialog", "Ensure-SettingsDialogVisible")
    "History-UI" = @("Show-HistoryDialog")
}

function Import-ScriptFunctionsToScriptScope([string]$path, [string]$tag) {
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    $resolved = $null
    try {
        $resolved = (Resolve-Path -Path $path -ErrorAction Stop).Path
    } catch {
        Write-Log ("{0}: UI path not found: {1}" -f $tag, $path) "ERROR" $_.Exception $tag
        return $false
    }
    if (Get-Command Test-RuntimeModulePathAllowed -ErrorAction SilentlyContinue) {
        if (-not (Test-RuntimeModulePathAllowed -path $resolved -tag $tag)) {
            Write-Log ("{0}: UI module path blocked by runtime policy: {1}" -f $tag, $resolved) "ERROR" $null $tag
            if (Get-Command Write-SecurityAuditEvent -ErrorAction SilentlyContinue) { Write-SecurityAuditEvent "UiModuleBlocked" "$tag|$resolved" "ERROR" $tag }
            return $false
        }
    } else {
        if (-not (Is-PathUnderRoot $resolved $script:AppRoot)) {
            Write-Log ("{0}: UI path outside app root blocked: {1}" -f $tag, $resolved) "ERROR" $null $tag
            return $false
        }
    }
    $funcs = @()
    try {
        $funcs = & {
            param($p)
            . $p
            Get-ChildItem Function:\ | Where-Object { $_.ScriptBlock -and $_.ScriptBlock.File -eq $p }
        } $resolved
    } catch {
        Write-Log ("{0}: UI module failed to load." -f $tag) "ERROR" $_.Exception $tag
        return $false
    }
    $funcList = @($funcs)
    if (-not $funcList -or $funcList.Count -eq 0) {
        Write-Log ("{0}: No functions imported from UI module." -f $tag) "ERROR" $null $tag
        return $false
    }
    foreach ($func in $funcList) {
        try {
            Set-Item -Path ("Function:\script:{0}" -f $func.Name) -Value $func.ScriptBlock -Force
        } catch {
            Write-Log ("{0}: Failed to register function {1} in script scope." -f $tag, $func.Name) "ERROR" $_.Exception $tag
            return $false
        }
        $script:ImportedUiFunctions[$func.Name] = $func.ScriptBlock
    }
    return $true
}

function Ensure-SettingsUiLoaded {
    if ($script:SettingsUiLoaded) { return $true }
    try {
        $ok = Import-ScriptFunctionsToScriptScope (Join-Path $PSScriptRoot "UI\SettingsDialog.ps1") "Settings-UI"
        if ($ok) {
            if (Get-Command Test-ModuleFunctionContract -ErrorAction SilentlyContinue) {
                $contract = Test-ModuleFunctionContract -ModuleTag "Settings-UI" -FunctionMap $script:ImportedUiFunctions -RequiredFunctions $script:UiModuleContracts["Settings-UI"]
                if (-not $contract.IsValid) {
                    Write-Log ("Settings-UI: Required functions missing: {0}" -f ($contract.MissingFunctions -join ", ")) "ERROR" $null "Settings-UI"
                    return $false
                }
            }
            if (-not (Test-ModuleVersionContract "Settings-UI" "Get-SettingsUiModuleVersion")) {
                Write-Log "Settings-UI: module version contract failed." "ERROR" $null "Settings-UI"
                return $false
            }
            $script:SettingsUiLoaded = $true
            return $true
        }
        return $false
    } catch {
        Write-Log "Failed to load Settings UI module." "ERROR" $_.Exception "Settings-UI"
        return $false
    }
}

function Ensure-HistoryUiLoaded {
    if ($script:HistoryUiLoaded) { return $true }
    try {
        $ok = Import-ScriptFunctionsToScriptScope (Join-Path $PSScriptRoot "UI\HistoryDialog.ps1") "History-UI"
        if ($ok) {
            if (Get-Command Test-ModuleFunctionContract -ErrorAction SilentlyContinue) {
                $contract = Test-ModuleFunctionContract -ModuleTag "History-UI" -FunctionMap $script:ImportedUiFunctions -RequiredFunctions $script:UiModuleContracts["History-UI"]
                if (-not $contract.IsValid) {
                    Write-Log ("History-UI: Required functions missing: {0}" -f ($contract.MissingFunctions -join ", ")) "ERROR" $null "History-UI"
                    return $false
                }
            }
            if (-not (Test-ModuleVersionContract "History-UI" "Get-HistoryUiModuleVersion")) {
                Write-Log "History-UI: module version contract failed." "ERROR" $null "History-UI"
                return $false
            }
            $script:HistoryUiLoaded = $true
            return $true
        }
        return $false
    } catch {
        Write-Log "Failed to load History UI module." "ERROR" $_.Exception "History-UI"
        return $false
    }
}

function Show-SettingsDialog {
    if (-not (Ensure-SettingsUiLoaded)) { return }
    if ($script:ImportedUiFunctions.ContainsKey("Show-SettingsDialog")) {
        & $script:ImportedUiFunctions["Show-SettingsDialog"]
        return
    }
    Write-Log "Show-SettingsDialog missing after load." "ERROR" $null "Settings-UI"
}

function Show-LogTailDialog {
    if (-not (Ensure-SettingsUiLoaded)) { return }
    if ($script:ImportedUiFunctions.ContainsKey("Show-LogTailDialog")) {
        & $script:ImportedUiFunctions["Show-LogTailDialog"]
        return
    }
    Write-Log "Show-LogTailDialog missing after load." "ERROR" $null "Settings-UI"
}

function Show-HistoryDialog {
    if (-not (Ensure-HistoryUiLoaded)) { return }
    if ($script:ImportedUiFunctions.ContainsKey("Show-HistoryDialog")) {
        & $script:ImportedUiFunctions["Show-HistoryDialog"]
        return
    }
    Write-Log "Show-HistoryDialog missing after load." "ERROR" $null "History-UI"
}

function Ensure-MenuItemVariable([string]$name, [string]$text, [bool]$enabled = $false, [ScriptBlock]$onClick = $null) {
    $existing = Get-Variable -Name $name -Scope Script -ErrorAction SilentlyContinue
    if ($existing -and $existing.Value) { return $existing.Value }
    $item = New-Object System.Windows.Forms.ToolStripMenuItem($text)
    $item.Enabled = $enabled
    if ($onClick) { $item.Add_Click($onClick) }
    Set-Variable -Name $name -Scope Script -Value $item -Force
    return $item
}

function Ensure-TrayModuleFallback {
    if (-not (Get-Variable -Name contextMenu -Scope Script -ErrorAction SilentlyContinue)) {
        $script:contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
        $script:TrayMenu = $script:contextMenu
    } elseif (-not $script:contextMenu) {
        $script:contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
        $script:TrayMenu = $script:contextMenu
    }

    if (-not (Get-Command Update-TrayLabels -ErrorAction SilentlyContinue)) {
        Set-Item -Path Function:\script:Update-TrayLabels -Value { } -Force
    }
    if (-not (Get-Command Invoke-TrayAction -ErrorAction SilentlyContinue)) {
        Set-Item -Path Function:\script:Invoke-TrayAction -Value {
            param([string]$name, [ScriptBlock]$action)
            $null = $name
            try { if ($action) { & $action } } catch { Write-LogThrottled "TrayFallback-Action" ("Tray fallback action failed: {0}" -f $_.Exception.Message) "ERROR" 10 }
        } -Force
    }
    if (-not (Get-Command Set-StatusUpdateTimerEnabled -ErrorAction SilentlyContinue)) {
        Set-Item -Path Function:\script:Set-StatusUpdateTimerEnabled -Value {
            param([bool]$enabled)
            $null = $enabled
        } -Force
    }

    Ensure-MenuItemVariable "startStopItem" "Start/Stop" $false | Out-Null
    Ensure-MenuItemVariable "toggleNowItem" "Toggle Once" $false | Out-Null
    Ensure-MenuItemVariable "pauseMenu" "Pause" $false | Out-Null
    Ensure-MenuItemVariable "intervalMenu" "Interval" $false | Out-Null
    Ensure-MenuItemVariable "runOnceNowItem" "Run Once" $false | Out-Null
    Ensure-MenuItemVariable "profilesMenu" "Profiles" $false | Out-Null
    Ensure-MenuItemVariable "quickSettingsMenu" "Quick Options" $false | Out-Null
    Ensure-MenuItemVariable "logsMenu" "Logs" $false | Out-Null
    Ensure-MenuItemVariable "openSettingsItem" "Settings" $true { Show-SettingsDialog } | Out-Null
    Ensure-MenuItemVariable "resetSafeModeItem" "Reset Safe Mode" $true { Reset-SafeMode } | Out-Null
    Ensure-MenuItemVariable "recoverNowItem" "Recover Now" $true { Recover-Now } | Out-Null
}

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

$viewLogTailItem = New-Object System.Windows.Forms.ToolStripMenuItem("View Log Tail")
$viewLogTailItem.Add_Click({
    Show-LogTailDialog
})

$historyItem = New-Object System.Windows.Forms.ToolStripMenuItem("History")
Set-MenuTooltip $historyItem "View recent toggle history."
$historyItem.Add_Click({
    Invoke-TrayAction "History" { Show-HistoryDialog }
})

$repairModeItem = New-Object System.Windows.Forms.ToolStripMenuItem("Repair Mode")
Set-MenuTooltip $repairModeItem "Run self-heal recovery actions (restore last-good state and reset crash counters)."
$repairModeItem.Add_Click({
    Invoke-TrayAction "RepairMode" { Start-RepairMode }
})

$repairAllItem = New-Object System.Windows.Forms.ToolStripMenuItem("Repair All")
Set-MenuTooltip $repairAllItem "Run full self-heal checks, module validation, timer recovery, and snapshot repair."
$repairAllItem.Add_Click({
    Invoke-TrayAction "RepairAll" { Invoke-RepairAll -Source "tray" | Out-Null }
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
    try { Set-RestartRequestMarker } catch { Write-IgnoredCatch $_ }
    Invoke-AppShutdownCleanup -Reason "Restart" -SkipAppExit
    try {
        Write-Log "Restart spawn: launching new instance." "INFO" $null "Restart"
        $proc = Start-Process -FilePath "powershell.exe" -WindowStyle Hidden -WorkingDirectory $script:AppRoot -ArgumentList "-NoProfile -ExecutionPolicy RemoteSigned -File `"$scriptPath`" -RelaunchedFromRestart" -PassThru
        if ($proc -and $proc.Id) { Write-Log ("Restart new PID={0}" -f $proc.Id) "INFO" $null "Restart" }
    } catch {
        Write-LogEx "Failed to restart app." "ERROR" $_.Exception "Restart" -Force
    }
    Write-Log "Restart requested via tray menu." "INFO" $null "Restart"
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
    Write-Log "Exit requested via tray menu." "INFO" $null "Exit"
    Invoke-AppShutdownCleanup -Reason "Exit"
})

if (-not (Get-Variable -Name contextMenu -Scope Script -ErrorAction SilentlyContinue) -or -not $script:contextMenu) {
    Ensure-TrayModuleFallback
}
Ensure-MenuItemVariable "startStopItem" "Start/Stop" $false | Out-Null
Ensure-MenuItemVariable "toggleNowItem" "Toggle Once" $false | Out-Null
Ensure-MenuItemVariable "pauseMenu" "Pause" $false | Out-Null
Ensure-MenuItemVariable "intervalMenu" "Interval" $false | Out-Null
Ensure-MenuItemVariable "runOnceNowItem" "Run Once" $false | Out-Null
Ensure-MenuItemVariable "profilesMenu" "Profiles" $false | Out-Null
Ensure-MenuItemVariable "quickSettingsMenu" "Quick Options" $false | Out-Null
Ensure-MenuItemVariable "openSettingsItem" "Settings" $true { Show-SettingsDialog } | Out-Null
Ensure-MenuItemVariable "logsMenu" "Logs" $false | Out-Null
Ensure-MenuItemVariable "resetSafeModeItem" "Reset Safe Mode" $true { Reset-SafeMode } | Out-Null
Ensure-MenuItemVariable "recoverNowItem" "Recover Now" $true { Recover-Now } | Out-Null

function New-TraySectionHeader([string]$text) {
    $item = New-Object System.Windows.Forms.ToolStripLabel($text)
    $item.AutoSize = $true
    $item.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $item.Padding = New-Object System.Windows.Forms.Padding(24, 0, 0, 0)
    $item.Margin = New-Object System.Windows.Forms.Padding(0, 4, 0, 2)
    try {
        $item.Font = New-Object System.Drawing.Font($contextMenu.Font, ([System.Drawing.FontStyle]::Bold -bor [System.Drawing.FontStyle]::Underline))
    } catch { Write-IgnoredCatch $_ }
    return $item
}

function Get-TrayMenuDefaultTooltip([System.Windows.Forms.ToolStripItem]$item) {
    if (-not $item) { return $null }
    if ($item -is [System.Windows.Forms.ToolStripSeparator]) { return $null }
    if ($item -is [System.Windows.Forms.ToolStripLabel]) { return $null }
    $name = [string]$item.Name
    $text = [string]$item.Text
    if ($name -eq "TopStatusSummaryItem") {
        return (L "Current app state. Hover for full details.")
    }
    if ($name -eq "TopStatusStateItem" -or $text -like "Status:*") {
        return (L "Current app state.")
    }
    if ($name -eq "TopStatusNextItem" -or $text -like "Next:*") {
        return (L "Time until the next automatic toggle.")
    }
    if ($name -eq "TopStatusProfileItem" -or $text -like "Active Profile:*") {
        return (L "Currently active profile.")
    }
    if ($text -eq (L "Run Once Now") -or $text -eq (L "Run Once Next Cycle") -or $text -eq (L "Run Once (Next Cycle)")) {
        return (L "Trigger one toggle now or queue it for the next cycle.")
    }
    if ($text -eq (L "History")) { return (L "View recent toggle history.") }
    if ($text -eq (L "Logs")) { return (L "Open log tools and files.") }
    if ($text -eq (L "Profiles")) { return (L "Switch between profiles.") }
    if ($text -eq (L "Quick Options")) { return (L "Quick toggles for common settings.") }
    if ($text -eq (L "Recovery")) { return (L "Safe-mode and self-healing actions.") }
    if ($text -eq (L "Settings")) { return (L "Open the settings window.") }
    if ($text -eq (L "Restart")) { return (L "Restart the app.") }
    if ($text -eq (L "Exit")) { return (L "Exit the app.") }
    if ($item -is [System.Windows.Forms.ToolStripMenuItem] -and $item.DropDownItems -and $item.DropDownItems.Count -gt 0) {
        return (L "Open submenu.")
    }
    if (-not [string]::IsNullOrWhiteSpace($text)) {
        return (L "Select this action.")
    }
    return $null
}

function Ensure-TrayTooltipHost {
    if (-not $contextMenu) { return }
    $contextMenu.ShowItemToolTips = $true
}

function Ensure-TrayMenuTooltips([System.Windows.Forms.ToolStripItemCollection]$items) {
    if (-not $items) { return }
    Ensure-TrayTooltipHost

    foreach ($item in $items) {
        if (-not ($item -is [System.Windows.Forms.ToolStripMenuItem])) { continue }

        if ([string]::IsNullOrWhiteSpace([string]$item.ToolTipText)) {
            $tip = Get-TrayMenuDefaultTooltip $item
            if (-not [string]::IsNullOrWhiteSpace($tip)) {
                $item.ToolTipText = $tip
            }
        }

        if ($item.DropDownItems -and $item.DropDownItems.Count -gt 0) {
            Ensure-TrayMenuTooltips $item.DropDownItems
        }
    }
}

if (-not $script:TrayStatusStateItem) {
    $script:TrayStatusStateItem = New-Object System.Windows.Forms.ToolStripMenuItem("Status: Stopped")
    $script:TrayStatusStateItem.Name = "TopStatusStateItem"
    $script:TrayStatusStateItem.Enabled = $true
}
if (-not $script:TrayStatusNextItem) {
    $script:TrayStatusNextItem = New-Object System.Windows.Forms.ToolStripMenuItem("Next: N/A")
    $script:TrayStatusNextItem.Name = "TopStatusNextItem"
    $script:TrayStatusNextItem.Enabled = $true
}
if (-not $script:TrayStatusProfileItem) {
    $script:TrayStatusProfileItem = New-Object System.Windows.Forms.ToolStripMenuItem("Active Profile: Default")
    $script:TrayStatusProfileItem.Name = "TopStatusProfileItem"
    $script:TrayStatusProfileItem.Enabled = $true
}
if (-not $script:TrayStatusSummaryItem) {
    $script:TrayStatusSummaryItem = New-Object System.Windows.Forms.ToolStripMenuItem("Status: Stopped")
    $script:TrayStatusSummaryItem.Name = "TopStatusSummaryItem"
    $script:TrayStatusSummaryItem.Enabled = $true
    try {
        $script:TrayStatusSummaryItem.Font = New-Object System.Drawing.Font("Consolas", $contextMenu.Font.Size, [System.Drawing.FontStyle]::Regular)
    } catch { Write-IgnoredCatch $_ }
}

$recoveryMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Recovery")
$recoveryMenu.DropDownItems.AddRange(@(
    $resetSafeModeItem,
    $recoverNowItem,
    $repairModeItem,
    $repairAllItem
))
Set-MenuTooltip $recoveryMenu "Safe-mode and self-healing recovery actions."

$toolsMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Actions")
$toolsMenu.DropDownItems.AddRange(@(
    $profilesMenu,
    $quickSettingsMenu,
    $historyItem,
    $logsMenu,
    $recoveryMenu
))
Set-MenuTooltip $toolsMenu "Profiles, quick options, logs, and recovery actions."

$controlMenu = New-Object System.Windows.Forms.ToolStripMenuItem("More")
$controlMenu.DropDownItems.AddRange(@(
    $toggleNowItem,
    $runOnceNowItem,
    $pauseMenu,
    $intervalMenu
))
Set-MenuTooltip $controlMenu "Toggle once, run once, pause, and interval controls."

$contextMenu.Items.AddRange(@(
    (New-TraySectionHeader "Status"),
    $script:TrayStatusSummaryItem,
    $script:TrayStatusNextItem,
    (New-Object System.Windows.Forms.ToolStripSeparator),
    (New-TraySectionHeader "Control"),
    $startStopItem,
    $controlMenu,
    (New-Object System.Windows.Forms.ToolStripSeparator),
    (New-TraySectionHeader "Tools"),
    $toolsMenu,
    $openSettingsItem,
    (New-Object System.Windows.Forms.ToolStripSeparator),
    (New-TraySectionHeader "System"),
    $restartItem,
    $exitItem
))
$contextMenu.ShowItemToolTips = $true
Ensure-TrayMenuTooltips $contextMenu.Items

Register-SystemSessionEndingHandler

if ($script:SettingsOnly) {
    Show-SettingsDialog
    [System.Windows.Forms.Application]::Run()
    Invoke-AppShutdownCleanup -Reason "SettingsOnlyExit" -SkipAppExit
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
Write-BootStage "Tray icon created"
Set-StartupLoadingIndicator $true "Starting"
try { Refresh-TrayMenu -SkipHeavyBuild } catch { Write-IgnoredCatch $_ }
Update-LogLevelMenuChecks

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
        if (-not $script:TrayMenuHeavyInitialized -or $script:TrayMenuNeedsRefresh) {
            Refresh-TrayMenu
        } else {
            if (Get-Command Update-TrayLabels -ErrorAction SilentlyContinue) { Update-TrayLabels }
            Update-StatusText
        }
        # Keep compact summary fresh and recover stale running "Next: N/A" visuals.
        if ($script:isRunning -and -not $script:isPaused -and -not $script:isScheduleBlocked -and -not $script:isScheduleSuspended) {
            $nowRuntime = Get-Now
            $intervalSeconds = [Math]::Max(1, [int]$settings.IntervalSeconds)
            if ($null -eq $script:nextToggleTime -or $script:nextToggleTime -le $nowRuntime) {
                $script:nextToggleTime = $nowRuntime.AddSeconds($intervalSeconds)
            }
            if ($script:TrayStatusNextItem -and ([string]$script:TrayStatusNextItem.Text -like "*N/A*")) {
                Update-StatusText
            }
        }
        Ensure-TrayMenuTooltips $contextMenu.Items
        Set-StatusUpdateTimerEnabled $true
    } finally {
        $script:TrayMenuOpening = $false
    }
})

$contextMenu.Add_Closed({
    Set-StatusUpdateTimerEnabled $false
    try { if ($contextMenu) { $contextMenu.ShowItemToolTips = $true } } catch { Write-IgnoredCatch $_ }
})

function Refresh-TrayMenu([switch]$SkipHeavyBuild) {
    try { Rebuild-PauseMenu } catch { Write-IgnoredCatch $_ }
    if (-not $SkipHeavyBuild) {
        try { if ($updateQuickSettingsChecks) { & $updateQuickSettingsChecks } } catch { Write-IgnoredCatch $_ }
        try { if ($updateProfilesMenu) { & $updateProfilesMenu } } catch { Write-IgnoredCatch $_ }
    } else {
        $script:TrayMenuNeedsRefresh = $true
    }
    try { Update-LogLevelMenuChecks } catch { Write-IgnoredCatch $_ }
    try { Apply-MenuFontSize ([int]$settings.FontSize) } catch { Write-IgnoredCatch $_ }
    try { Update-ThemePreference } catch { Write-IgnoredCatch $_ }
    try { Update-StatusText } catch { Write-IgnoredCatch $_ }
    try { Ensure-TrayMenuTooltips $contextMenu.Items } catch { Write-IgnoredCatch $_ }
    if (-not $SkipHeavyBuild) {
        $script:TrayMenuHeavyInitialized = $true
        $script:TrayMenuNeedsRefresh = $false
    }
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
$watchdogTimer.Interval = 1000
$watchdogTimer.Add_Tick({
    Invoke-SafeTimerAction "WatchdogTimer" {
        if ($script:isShuttingDown -or $script:CleanupDone) { return }
        $script:WatchdogTickCounter = [int]$script:WatchdogTickCounter + 1
        try { Update-FunStatsRuntimeProgress (Get-Date) } catch { Write-IgnoredCatch $_ }
        Update-PeakWorkingSet
        Request-StatusUpdate
        if (($script:WatchdogTickCounter % 2) -eq 0) {
            Process-CommandFile
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
    }
})
$watchdogTimer.Start()

$notifyIcon.Visible = $true
Write-Log "Tray icon visible (startup complete)." "INFO" $null "Tray"
Write-BootStage "Startup complete"
try { Start-HealthMonitor } catch { Write-IgnoredCatch $_ }
if (-not $script:PostShowStatusTimer) {
    $script:PostShowStatusTimer = New-Object System.Windows.Forms.Timer
    $script:PostShowStatusTimer.Interval = 250
    $script:PostShowStatusTimer.Add_Tick({
        Invoke-SafeTimerAction "PostShowStatusTimer" {
            if ($script:PostShowStatusTimer) {
                $script:PostShowStatusTimer.Stop()
                $script:PostShowStatusTimer.Dispose()
                $script:PostShowStatusTimer = $null
            }
            Request-StatusUpdate
            Update-StatusText
        }
    })
    $script:PostShowStatusTimer.Start()
}

$script:HotkeysReady = $true
$script:HotkeysPending = $false
Register-Hotkeys
Write-BootStage "Hotkeys registered"

if (-not $script:DeferredStartupTimer) {
    $script:DeferredStartupTimer = New-Object System.Windows.Forms.Timer
    $script:DeferredStartupTimer.Interval = 750
    $script:DeferredStartupTimer.Add_Tick({
        Invoke-SafeTimerAction "DeferredStartupTimer" {
            if ($script:DeferredStartupTimer) {
                $script:DeferredStartupTimer.Stop()
                $script:DeferredStartupTimer.Dispose()
                $script:DeferredStartupTimer = $null
            }
            Invoke-DeferredStartupTasks
        }
    })
    $script:DeferredStartupTimer.Start()
}

function Show-FirstRunWizard {
    if (-not $settings) { return }
    $completed = [bool](Get-SettingsPropertyValue $settings "FirstRunWizardCompleted" $false)
    $markerExists = Test-Path -LiteralPath $script:FirstRunWizardMarkerPath
    if ($completed -and $markerExists) { return }

    Ensure-StockProfiles $settings | Out-Null
    $wizard = New-Object System.Windows.Forms.Form
    $wizard.Text = (L "Welcome" "Welcome")
    $wizard.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $wizard.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $wizard.MinimizeBox = $false
    $wizard.MaximizeBox = $false
    $wizard.ShowInTaskbar = $false
    $wizard.ClientSize = New-Object System.Drawing.Size(520, 300)

    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = [System.Windows.Forms.DockStyle]::Fill
    $layout.Padding = New-Object System.Windows.Forms.Padding(12)
    $layout.ColumnCount = 2
    $layout.RowCount = 8
    $layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $title = New-Object System.Windows.Forms.Label
    $title.AutoSize = $true
    $title.Font = New-Object System.Drawing.Font($wizard.Font.FontFamily, 11, [System.Drawing.FontStyle]::Bold)
    $title.Text = (L "Welcome to Teams-Always-Green" "Welcome to Teams-Always-Green")
    $layout.Controls.Add($title, 0, 0)
    $layout.SetColumnSpan($title, 2)

    $desc = New-Object System.Windows.Forms.Label
    $desc.AutoSize = $true
    $desc.Margin = New-Object System.Windows.Forms.Padding(0, 6, 0, 8)
    $desc.MaximumSize = New-Object System.Drawing.Size(480, 0)
    $desc.Text = (L "Choose your defaults. You can change all of these later in Settings." "Choose your defaults. You can change all of these later in Settings.")
    $layout.Controls.Add($desc, 0, 1)
    $layout.SetColumnSpan($desc, 2)

    $languageLabel = New-Object System.Windows.Forms.Label
    $languageLabel.Text = (L "Language" "Language")
    $languageLabel.AutoSize = $true
    $languageLabel.Margin = New-Object System.Windows.Forms.Padding(0, 6, 10, 0)
    $languageBox = New-Object System.Windows.Forms.ComboBox
    $languageBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $languageBox.Width = 220
    $languageItems = @(
        [pscustomobject]@{ Code = "auto"; Label = (L "Auto (System)" "Auto (System)") },
        [pscustomobject]@{ Code = "en"; Label = (L "English" "English") },
        [pscustomobject]@{ Code = "es"; Label = "Español" },
        [pscustomobject]@{ Code = "fr"; Label = "Français" },
        [pscustomobject]@{ Code = "de"; Label = "Deutsch" },
        [pscustomobject]@{ Code = "it"; Label = "Italiano" },
        [pscustomobject]@{ Code = "pt"; Label = "Português" },
        [pscustomobject]@{ Code = "nl"; Label = "Nederlands" },
        [pscustomobject]@{ Code = "pl"; Label = "Polski" }
    )
    foreach ($item in $languageItems) { [void]$languageBox.Items.Add($item) }
    $languageBox.DisplayMember = "Label"
    $initialLang = [string](Get-SettingsPropertyValue $settings "UiLanguage" "auto")
    if ([string]::IsNullOrWhiteSpace($initialLang)) { $initialLang = "auto" }
    $selectedLang = $languageItems | Where-Object { $_.Code -eq $initialLang } | Select-Object -First 1
    if (-not $selectedLang) { $selectedLang = $languageItems[0] }
    $languageBox.SelectedItem = $selectedLang
    $layout.Controls.Add($languageLabel, 0, 2)
    $layout.Controls.Add($languageBox, 1, 2)

    $profileLabel = New-Object System.Windows.Forms.Label
    $profileLabel.Text = (L "Active Profile" "Active Profile")
    $profileLabel.AutoSize = $true
    $profileLabel.Margin = New-Object System.Windows.Forms.Padding(0, 6, 10, 0)
    $profileBox = New-Object System.Windows.Forms.ComboBox
    $profileBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $profileBox.Width = 220
    $profileNames = @(Get-ObjectKeys $settings.Profiles | Sort-Object)
    foreach ($profileName in $profileNames) { [void]$profileBox.Items.Add($profileName) }
    $activeName = [string](Get-SettingsPropertyValue $settings "ActiveProfile" "Default")
    if (-not [string]::IsNullOrWhiteSpace($activeName) -and $profileBox.Items.Contains($activeName)) {
        $profileBox.SelectedItem = $activeName
    } elseif ($profileBox.Items.Count -gt 0) {
        $profileBox.SelectedIndex = 0
    }
    $layout.Controls.Add($profileLabel, 0, 3)
    $layout.Controls.Add($profileBox, 1, 3)

    $startOnLaunchBox = New-Object System.Windows.Forms.CheckBox
    $startOnLaunchBox.Text = (L "Start on Launch" "Start on Launch")
    $startOnLaunchBox.AutoSize = $true
    $startOnLaunchBox.Checked = [bool](Get-SettingsPropertyValue $settings "StartOnLaunch" $false)
    $layout.Controls.Add($startOnLaunchBox, 1, 4)

    $runOnceOnLaunchBox = New-Object System.Windows.Forms.CheckBox
    $runOnceOnLaunchBox.Text = (L "Run Once on Launch" "Run Once on Launch")
    $runOnceOnLaunchBox.AutoSize = $true
    $runOnceOnLaunchBox.Checked = [bool](Get-SettingsPropertyValue $settings "RunOnceOnLaunch" $false)
    $layout.Controls.Add($runOnceOnLaunchBox, 1, 5)

    $firstRunTipsBox = New-Object System.Windows.Forms.CheckBox
    $firstRunTipsBox.Text = (L "Show First-Run Tips" "Show First-Run Tips")
    $firstRunTipsBox.AutoSize = $true
    $firstRunTipsBox.Checked = [bool](Get-SettingsPropertyValue $settings "ShowFirstRunToast" $true)
    $layout.Controls.Add($firstRunTipsBox, 1, 6)

    $buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttonPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft
    $buttonPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $buttonPanel.AutoSize = $true
    $buttonPanel.WrapContents = $false
    $buttonPanel.Margin = New-Object System.Windows.Forms.Padding(0, 12, 0, 0)

    $skipButton = New-Object System.Windows.Forms.Button
    $skipButton.Text = (L "Skip" "Skip")
    $skipButton.Width = 96
    $skipButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $finishButton = New-Object System.Windows.Forms.Button
    $finishButton.Text = (L "Finish" "Finish")
    $finishButton.Width = 96
    $finishButton.DialogResult = [System.Windows.Forms.DialogResult]::OK

    [void]$buttonPanel.Controls.Add($skipButton)
    [void]$buttonPanel.Controls.Add($finishButton)
    $layout.Controls.Add($buttonPanel, 0, 7)
    $layout.SetColumnSpan($buttonPanel, 2)
    [void]$wizard.Controls.Add($layout)
    $wizard.AcceptButton = $finishButton
    $wizard.CancelButton = $skipButton

    $result = $wizard.ShowDialog()
    try {
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            $chosenLanguage = if ($languageBox.SelectedItem -and $languageBox.SelectedItem.PSObject.Properties.Name -contains "Code") { [string]$languageBox.SelectedItem.Code } else { "auto" }
            if ([string]::IsNullOrWhiteSpace($chosenLanguage)) { $chosenLanguage = "auto" }
            Set-SettingsPropertyValue $settings "UiLanguage" $chosenLanguage
            $script:UiLanguage = Resolve-UiLanguage $chosenLanguage
            if ($profileBox.SelectedItem -and $settings.Profiles -and ((Get-ObjectKeys $settings.Profiles) -contains [string]$profileBox.SelectedItem)) {
                Set-SettingsPropertyValue $settings "ActiveProfile" ([string]$profileBox.SelectedItem)
            }
            Set-SettingsPropertyValue $settings "StartOnLaunch" ([bool]$startOnLaunchBox.Checked)
            Set-SettingsPropertyValue $settings "RunOnceOnLaunch" ([bool]$runOnceOnLaunchBox.Checked)
            Set-SettingsPropertyValue $settings "ShowFirstRunToast" ([bool]$firstRunTipsBox.Checked)
            Set-SettingsPropertyValue $settings "RememberChoice" $true
        }

        Set-SettingsPropertyValue $settings "FirstRunWizardCompleted" $true
        try {
            Ensure-Directory $script:MetaDir "Meta" | Out-Null
            Write-AtomicTextFile -Path $script:FirstRunWizardMarkerPath -Content ((Get-Date).ToString("o")) -Encoding ASCII
        } catch { Write-IgnoredCatch $_ }
        Save-SettingsImmediate $settings
        try { Apply-SettingsRuntime } catch { Write-IgnoredCatch $_ }
        try { if ($script:TrayMenu) { Localize-MenuItems $script:TrayMenu.Items } } catch { Write-IgnoredCatch $_ }
        try { Update-TrayLabels } catch { Write-IgnoredCatch $_ }
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            Show-ActionToast (L "First-run setup saved" "First-run setup saved")
        }
    } finally {
        $wizard.Dispose()
    }
}

try { Show-FirstRunWizard } catch { Write-Log "First-run wizard failed." "WARN" $_.Exception "Startup" }
try { Show-FirstRunToast } catch { Write-IgnoredCatch $_ }

function Show-StartPrompt {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = (L "Teams-Always-Green" "Teams-Always-Green")
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.ClientSize = New-Object System.Drawing.Size(380, 150)

    $label = New-Object System.Windows.Forms.Label
    $label.Text = (L "Start Scroll Lock toggling now?`n`nYou can control it later from the tray icon (right-click)." "Start Scroll Lock toggling now?`n`nYou can control it later from the tray icon (right-click).")
    $label.Location = New-Object System.Drawing.Point(12, 10)
    $label.Size = New-Object System.Drawing.Size(355, 60)

    $checkbox = New-Object System.Windows.Forms.CheckBox
    $checkbox.Text = (L "Remember my choice" "Remember my choice")
    $checkbox.Location = New-Object System.Drawing.Point(12, 75)
    $checkbox.AutoSize = $true

    $yesButton = New-Object System.Windows.Forms.Button
    $yesButton.Text = (L "Yes" "Yes")
    $yesButton.Location = New-Object System.Drawing.Point(200, 105)
    $yesButton.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $noButton = New-Object System.Windows.Forms.Button
    $noButton.Text = (L "No" "No")
    $noButton.Location = New-Object System.Drawing.Point(285, 105)
    $noButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $form.Controls.AddRange(@($label, $checkbox, $yesButton, $noButton))
    $form.AcceptButton = $yesButton
    $form.CancelButton = $noButton

    try {
        $result = $form.ShowDialog()
        return @{
            StartNow = ($result -eq [System.Windows.Forms.DialogResult]::OK)
            Remember = $checkbox.Checked
        }
    } finally {
        $form.Dispose()
    }
}

# --- Optional: confirmation prompt on launch ---
$overrideAtStartup = $script:OverrideMinimalMode
$overrideLogOnce = $false
if (-not $overrideAtStartup -and (Test-Path $script:CrashStatePath)) {
    try {
        $rawOverride = Get-Content -Path $script:CrashStatePath -Raw
        if (-not [string]::IsNullOrWhiteSpace($rawOverride)) {
            $loadedOverride = $rawOverride | ConvertFrom-Json
            if ($loadedOverride -and ($loadedOverride.PSObject.Properties.Name -contains "OverrideMinimalMode") -and [bool]$loadedOverride.OverrideMinimalMode) {
                $overrideAtStartup = $true
                $script:OverrideMinimalMode = $true
                if (-not ($loadedOverride.PSObject.Properties.Name -contains "OverrideMinimalModeLogged") -or -not [bool]$loadedOverride.OverrideMinimalModeLogged) {
                    $overrideLogOnce = $true
                }
            }
        }
    } catch { Write-IgnoredCatch $_ }
}

if ($script:MinimalModeActive -and -not $overrideAtStartup) {
    $allowAutoStartInMinimal = ($script:RelaunchedFromRestart -and [bool](Get-SettingsPropertyValue $settings "AutoStartOnRestart" $false))
    if ($allowAutoStartInMinimal) {
        Write-Log "Startup: minimal mode is active, but Auto Start on Restart was requested; starting toggle." "WARN" $null "Startup"
        Start-Toggling
    } else {
        Request-StatusUpdate
        Show-Balloon "Teams-Always-Green" "Minimal mode enabled after repeated crashes. Open Settings to review." ([System.Windows.Forms.ToolTipIcon]::Warning)
        Write-Log "Startup: minimal mode active (auto-start suppressed)." "WARN" $null "Startup"
    }
} elseif ($script:MinimalModeActive -and $overrideAtStartup) {
    $script:MinimalModeActive = $false
    $script:MinimalModeReason = $null
    if ($overrideLogOnce) {
        Write-Log "Startup: minimal mode override applied." "INFO" $null "Startup"
        try {
            $state = Get-CrashState
            $state.OverrideMinimalModeLogged = $true
            Save-CrashState $state
        } catch { Write-IgnoredCatch $_ }
    }
} elseif ($script:isPaused) {
    Request-StatusUpdate
    Show-Balloon "Teams-Always-Green" "Paused; will auto-resume when the timer expires." ([System.Windows.Forms.ToolTipIcon]::Info)
} elseif ($script:RelaunchedFromRestart -and [bool](Get-SettingsPropertyValue $settings "AutoStartOnRestart" $false)) {
    Write-Log "Startup: auto-starting toggle after app restart." "INFO" $null "Startup"
    Start-Toggling
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
    Invoke-AppShutdownCleanup -Reason "RunLoopExit" -SkipAppExit
} catch {
    Write-Log "Cleanup failed." "ERROR" $_.Exception "Cleanup"
}
