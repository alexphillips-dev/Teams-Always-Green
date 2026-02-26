Set-StrictMode -Version Latest

# App identity and app-scoped filenames live here so the rest of the codebase
# does not repeat hard-coded literals everywhere.

if (-not (Get-Variable -Name AppDisplayName -Scope Script -ErrorAction SilentlyContinue)) { $script:AppDisplayName = "Teams Always Green" }
if (-not (Get-Variable -Name AppSlug -Scope Script -ErrorAction SilentlyContinue)) { $script:AppSlug = "Teams-Always-Green" }
if (-not (Get-Variable -Name AppDataFolderName -Scope Script -ErrorAction SilentlyContinue)) { $script:AppDataFolderName = "TeamsAlwaysGreen" }
if (-not (Get-Variable -Name AppRepoOwnerDefault -Scope Script -ErrorAction SilentlyContinue)) { $script:AppRepoOwnerDefault = "alexphillips-dev" }
if (-not (Get-Variable -Name AppRepoNameDefault -Scope Script -ErrorAction SilentlyContinue)) { $script:AppRepoNameDefault = "Teams-Always-Green" }
if (-not (Get-Variable -Name AppMainScriptFileName -Scope Script -ErrorAction SilentlyContinue)) { $script:AppMainScriptFileName = "Teams Always Green.ps1" }

function Get-AppScopedFileName([string]$suffix) {
    if ([string]::IsNullOrWhiteSpace($suffix)) { return $script:AppSlug }
    return ("{0}.{1}" -f $script:AppSlug, $suffix)
}

$script:AppUserAgent = $script:AppDataFolderName
$script:AppTrayIconRelativePath = "assets\\icons\\Tray_Icon.ico"

$script:AppMainLogFileName = Get-AppScopedFileName "log"
$script:AppFallbackLogFileName = Get-AppScopedFileName "fallback.log"
$script:AppBootstrapLogFileName = Get-AppScopedFileName "bootstrap.log"
$script:AppAuditLogFileName = Get-AppScopedFileName "audit.log"
$script:AppSecurityLogFileName = Get-AppScopedFileName "security.log"
$script:AppAuditChainFileName = Get-AppScopedFileName "audit.chain.json"
$script:AppSecurityAuditChainFileName = Get-AppScopedFileName "security.chain.json"
$script:AppSettingsFileName = Get-AppScopedFileName "settings.json"
$script:AppStateFileName = Get-AppScopedFileName "state.json"
$script:AppProfilesLastGoodFileName = Get-AppScopedFileName "profiles.lastgood.json"
$script:AppSettingsBackupGlob = ("{0}.bak*" -f $script:AppSettingsFileName)
$script:AppStateBackupGlob = ("{0}.bak*" -f $script:AppStateFileName)
$script:AppSettingsLocatorFileName = Get-AppScopedFileName "settings.path.txt"
$script:AppLogLocatorFileName = Get-AppScopedFileName "log.path.txt"
$script:AppCommandQueueFileName = Get-AppScopedFileName "commands.txt"
$script:AppStatusFileName = Get-AppScopedFileName "status.json"
$script:AppSettingsLastGoodFileName = Get-AppScopedFileName "settings.lastgood.json"
$script:AppStateLastGoodFileName = Get-AppScopedFileName "state.lastgood.json"
$script:AppStartupSnapshotFileName = Get-AppScopedFileName "startup.json"
$script:AppCrashStateFileName = Get-AppScopedFileName "crash.json"
$script:AppRollbackStateFileName = Get-AppScopedFileName "rollback.state.json"
$script:AppFirstRunMarkerFileName = Get-AppScopedFileName "first-run.complete"
$script:AppIntegrityManifestFileName = Get-AppScopedFileName "integrity.json"
$script:AppMinimalModeStateFileName = Get-AppScopedFileName "minimalmode.state.json"
$script:AppRestartRequestFileName = Get-AppScopedFileName "restart.request.txt"
$script:AppLifetimeStatsFileName = Get-AppScopedFileName "lifetime.json"
$script:AppUpdatePublicKeyFileName = Get-AppScopedFileName "updatekey.xml"
$script:AppShutdownStateFileName = Get-AppScopedFileName "shutdown.state.txt"

function Get-AppBackupFileName([string]$baseFileName, [int]$index) {
    if ([string]::IsNullOrWhiteSpace($baseFileName)) { return "" }
    return ("{0}.bak{1}" -f $baseFileName, [Math]::Max(1, [int]$index))
}

function Initialize-LogPathVariables {
    if ([string]::IsNullOrWhiteSpace([string]$script:LogDirectory)) { return }
    $script:logPath = Join-Path $script:LogDirectory $script:AppMainLogFileName
    $script:FallbackLogPath = Join-Path $script:LogDirectory $script:AppFallbackLogFileName
    $script:BootstrapLogPath = Join-Path $script:LogDirectory $script:AppBootstrapLogFileName
    $script:AuditLogPath = Join-Path $script:LogDirectory $script:AppAuditLogFileName
    $script:SecurityAuditLogPath = Join-Path $script:LogDirectory $script:AppSecurityLogFileName
}

function Initialize-SettingsPathVariables {
    if ([string]::IsNullOrWhiteSpace([string]$script:SettingsDirectory)) { return }
    $script:settingsPath = Join-Path $script:SettingsDirectory $script:AppSettingsFileName
    $script:StatePath = Join-Path $script:SettingsDirectory $script:AppStateFileName
    $script:ProfilesLastGoodPath = Join-Path $script:SettingsDirectory $script:AppProfilesLastGoodFileName
}

function Get-AppRepoUrl([ValidateSet("repo","releases","issues","raw")][string]$kind) {
    $owner = if ($script:AppRepoOwnerDefault) { [string]$script:AppRepoOwnerDefault } else { "alexphillips-dev" }
    $repo = if ($script:AppRepoNameDefault) { [string]$script:AppRepoNameDefault } else { "Teams-Always-Green" }
    switch ($kind) {
        "repo" { return ("https://github.com/{0}/{1}" -f $owner, $repo) }
        "releases" { return ("https://github.com/{0}/{1}/releases" -f $owner, $repo) }
        "issues" { return ("https://github.com/{0}/{1}/issues" -f $owner, $repo) }
        "raw" { return ("https://raw.githubusercontent.com/{0}/{1}/main" -f $owner, $repo) }
    }
}
