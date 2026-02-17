Set-StrictMode -Version Latest

function Get-AppPaths {
    param(
        [string]$AppRoot = $script:AppRoot,
        [string]$DataRoot = $script:DataRoot,
        [string]$LogDirectory = $script:LogDirectory,
        [string]$SettingsDirectory = $script:SettingsDirectory,
        [string]$MetaDir = $script:MetaDir
    )

    $paths = [ordered]@{
        AppRoot  = $AppRoot
        DataRoot = $DataRoot
        Logs     = [ordered]@{
            Directory = $LogDirectory
            Main      = if ($LogDirectory) { Join-Path $LogDirectory $script:AppMainLogFileName } else { $null }
            Fallback  = if ($LogDirectory) { Join-Path $LogDirectory $script:AppFallbackLogFileName } else { $null }
            Bootstrap = if ($LogDirectory) { Join-Path $LogDirectory $script:AppBootstrapLogFileName } else { $null }
            Audit     = if ($LogDirectory) { Join-Path $LogDirectory $script:AppAuditLogFileName } else { $null }
            Security  = if ($LogDirectory) { Join-Path $LogDirectory $script:AppSecurityLogFileName } else { $null }
        }
        Settings = [ordered]@{
            Directory       = $SettingsDirectory
            SettingsJson    = if ($SettingsDirectory) { Join-Path $SettingsDirectory $script:AppSettingsFileName } else { $null }
            StateJson       = if ($SettingsDirectory) { Join-Path $SettingsDirectory $script:AppStateFileName } else { $null }
            ProfilesLastGood = if ($SettingsDirectory) { Join-Path $SettingsDirectory $script:AppProfilesLastGoodFileName } else { $null }
        }
        Meta     = [ordered]@{
            Directory            = $MetaDir
            SettingsLocator      = if ($MetaDir) { Join-Path $MetaDir $script:AppSettingsLocatorFileName } else { $null }
            LogLocator           = if ($MetaDir) { Join-Path $MetaDir $script:AppLogLocatorFileName } else { $null }
            Commands             = if ($MetaDir) { Join-Path $MetaDir $script:AppCommandQueueFileName } else { $null }
            Status               = if ($MetaDir) { Join-Path $MetaDir $script:AppStatusFileName } else { $null }
            SettingsLastGood     = if ($MetaDir) { Join-Path $MetaDir $script:AppSettingsLastGoodFileName } else { $null }
            StateLastGood        = if ($MetaDir) { Join-Path $MetaDir $script:AppStateLastGoodFileName } else { $null }
            StartupSnapshot      = if ($MetaDir) { Join-Path $MetaDir $script:AppStartupSnapshotFileName } else { $null }
            CrashState           = if ($MetaDir) { Join-Path $MetaDir $script:AppCrashStateFileName } else { $null }
            RollbackState        = if ($MetaDir) { Join-Path $MetaDir $script:AppRollbackStateFileName } else { $null }
            FirstRunMarker       = if ($MetaDir) { Join-Path $MetaDir $script:AppFirstRunMarkerFileName } else { $null }
            IntegrityManifest    = if ($MetaDir) { Join-Path $MetaDir $script:AppIntegrityManifestFileName } else { $null }
            MinimalModeState     = if ($MetaDir) { Join-Path $MetaDir $script:AppMinimalModeStateFileName } else { $null }
            RestartRequest       = if ($MetaDir) { Join-Path $MetaDir $script:AppRestartRequestFileName } else { $null }
            LifetimeStats        = if ($MetaDir) { Join-Path $MetaDir $script:AppLifetimeStatsFileName } else { $null }
            UpdatePublicKey      = if ($MetaDir) { Join-Path $MetaDir $script:AppUpdatePublicKeyFileName } else { $null }
            ShutdownState        = if ($MetaDir) { Join-Path $MetaDir $script:AppShutdownStateFileName } else { $null }
            AuditChain           = if ($MetaDir) { Join-Path $MetaDir $script:AppAuditChainFileName } else { $null }
            SecurityAuditChain   = if ($MetaDir) { Join-Path $MetaDir $script:AppSecurityAuditChainFileName } else { $null }
        }
    }

    return [pscustomobject]$paths
}

function Sync-AppPaths {
    # Snapshot-only helper: we still keep the original $script:* path vars as the
    # executable source of truth for now, but expose a structured view for new code.
    $script:Paths = Get-AppPaths
    return $script:Paths
}

