Set-StrictMode -Version Latest

BeforeAll {
    $script:repoRoot = Split-Path -Parent $PSScriptRoot
    $script:mainScript = Join-Path $script:repoRoot "Script/Teams Always Green.ps1"
    $script:settingsDialogScript = Join-Path $script:repoRoot "Script/UI/SettingsDialog.ps1"
    $script:historyDialogScript = Join-Path $script:repoRoot "Script/UI/HistoryDialog.ps1"
    $script:trayMenuScript = Join-Path $script:repoRoot "Script/Tray/Menu.ps1"
    $script:updateEngineScript = Join-Path $script:repoRoot "Script/Features/UpdateEngine.ps1"
    $script:coreRuntimeScript = Join-Path $script:repoRoot "Script/Core/Runtime.ps1"
    $script:uiStringsScript = Join-Path $script:repoRoot "Script/I18n/UiStrings.ps1"
    $script:versionPath = Join-Path $script:repoRoot "VERSION"
    $script:changelogPath = Join-Path $script:repoRoot "CHANGELOG.md"
    $script:mainText = Get-Content -Raw -Path $script:mainScript
    $script:settingsDialogText = Get-Content -Raw -Path $script:settingsDialogScript
    $script:historyDialogText = Get-Content -Raw -Path $script:historyDialogScript
    $script:trayMenuText = Get-Content -Raw -Path $script:trayMenuScript
    $script:updateEngineText = Get-Content -Raw -Path $script:updateEngineScript
    $script:coreRuntimeText = Get-Content -Raw -Path $script:coreRuntimeScript

    $tokens = $null
    $errors = $null
    $script:mainAst = [System.Management.Automation.Language.Parser]::ParseFile($script:mainScript, [ref]$tokens, [ref]$errors)
    $script:functionTextByName = @{}
    $script:mainAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object {
        $script:functionTextByName[$_.Name] = $_.Extent.Text
    }
}

Describe "Quality: Script Parse" {
    It "main script parses without syntax errors" {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script:mainScript, [ref]$tokens, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It "UI scripts parse without syntax errors" {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script:settingsDialogScript, [ref]$tokens, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty

        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script:historyDialogScript, [ref]$tokens, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty

        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script:updateEngineScript, [ref]$tokens, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }
}

Describe "Quality: Critical Features" {
    It "supports SettingsOnly startup mode" {
        $script:mainText | Should -Match '\[switch\]\$SettingsOnly'
    }

    It "contains critical tray actions" {
        $script:mainText | Should -Match 'ToolStripMenuItem\("History"\)'
        $script:mainText | Should -Match 'ToolStripMenuItem\("Restart"\)'
        $script:mainText | Should -Match 'ToolStripMenuItem\("Exit"\)'
    }

    It "contains core toggle lifecycle functions" {
        $script:mainText | Should -Match 'function\s+Do-Toggle'
        $script:mainText | Should -Match 'function\s+Start-Toggling'
        $script:mainText | Should -Match 'function\s+Stop-Toggling'
    }

    It "contains UI safety wrapper and event-id logging hooks" {
        $script:mainText | Should -Match 'function\s+Invoke-UiSafeAction'
        $script:mainText | Should -Match 'function\s+Write-LogExceptionDeduped'
        $script:mainText | Should -Match 'function\s+Get-LogEventId'
        $script:mainText | Should -Match '\[E=\$eventId\]'
    }

    It "contains self-heal and repair mode helpers" {
        $script:mainText | Should -Match 'function\s+Get-CrashRecoveryTier'
        $script:mainText | Should -Match 'function\s+Start-RepairMode'
        $script:mainText | Should -Match 'function\s+Start-HealthMonitor'
        $script:mainText | Should -Match 'function\s+Test-SavedSettingsFile'
        $script:mainText | Should -Match 'Ensure-TrayModuleFallback'
    }

    It "contains settings startup fallback UI" {
        $script:settingsDialogText | Should -Match 'function\s+Show-SettingsFallbackDialog'
        $script:settingsDialogText | Should -Match 'Show-SettingsFallbackDialog -ErrorMessage'
    }

    It "loads update module before tray module at startup" {
        $updateLoad = $script:mainText.IndexOf('$updateModulePath = Join-Path $PSScriptRoot "Features\\UpdateEngine.ps1"')
        $trayLoad = $script:mainText.IndexOf('$trayModulePath = Join-Path $PSScriptRoot "Tray\\Menu.ps1"')
        $updateLoad | Should -BeGreaterThan -1
        $trayLoad | Should -BeGreaterThan -1
        $updateLoad | Should -BeLessThan $trayLoad
    }
}

Describe "Quality: Profile and Update Coverage" {
    It "enforces stock profiles" {
        $script:mainText | Should -Match 'function\s+Ensure-StockProfiles'
        $script:mainText | Should -Match '"Default"'
        $script:mainText | Should -Match '"Home"'
        $script:mainText | Should -Match '"Work"'
    }

    It "supports manual update checks with release injection and no-update flow" {
        $script:updateEngineText | Should -Match 'function\s+Get-UpdateModuleVersion'
        $script:updateEngineText | Should -Match 'function\s+Invoke-UpdateCheck'
        $script:updateEngineText | Should -Match '\[object\]\$Release'
        $script:updateEngineText | Should -Match '\[switch\]\$SilentNoUpdate'
        $script:updateEngineText | Should -Match 'No updates are available'
        $script:updateEngineText | Should -Match 'function\s+Test-ReleaseTrust'
        $script:updateEngineText | Should -Match 'Test-TrustedGithubUrl'
        $script:updateEngineText | Should -Match 'Test-RateLimit "UpdateCheck"'
    }

    It "uses timeout and retry policy for update network calls" {
        $script:updateEngineText | Should -Match 'function\s+Get-UpdateNetworkPolicy'
        $script:updateEngineText | Should -Match 'function\s+Invoke-UpdateRestRequest'
        $script:updateEngineText | Should -Match 'function\s+Invoke-UpdateDownloadRequest'
        $script:settingsDialogText | Should -Match 'AboutUpdateJobTimeoutSeconds'
        $script:settingsDialogText | Should -Match 'Invoke-RestMethod\s+-Uri\s+\$uri\s+-Headers\s+\$headers\s+-TimeoutSec'
    }

    It "keeps profile hover handlers theme-safe" {
        $script:settingsDialogText | Should -Match 'SetDeleteProfileButtonHover'
        $script:settingsDialogText | Should -Match 'SetNewProfileButtonHover'
        $script:settingsDialogText | Should -Match 'DeleteProfileButtonThemeForeColor'
        $script:settingsDialogText | Should -Match 'NewProfileButtonThemeForeColor'
    }

    It "exposes crash recovery reset action in diagnostics" {
        $script:settingsDialogText | Should -Match 'Reset Crash State'
        $script:mainText | Should -Match 'function\s+Reset-CrashRecoveryState'
    }
}

Describe "Quality: UI Integration Contracts" {
    BeforeAll {
        Invoke-Expression $script:coreRuntimeText
        Invoke-Expression $script:functionTextByName["Import-ScriptFunctionsToScriptScope"]

        function Write-Log {
            param([string]$Message, [string]$Level, [object]$Exception, [string]$Context)
        }
        function Is-PathUnderRoot {
            param([string]$Path, [string]$Root)
            return $true
        }
        function Test-PathHasReparsePoint {
            param([string]$Path, [string]$StopAtPath, [switch]$IncludeStopPath)
            return $false
        }

        $script:AppRoot = $script:repoRoot
        $script:ImportedUiFunctions = @{}
    }

    It "validates settings UI exported-function contract" {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:settingsDialogScript, [ref]$tokens, [ref]$errors)
        $errors | Should -BeNullOrEmpty

        $functionMap = @{}
        $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object {
            $functionMap[$_.Name] = [scriptblock]::Create("param()")
        }

        $contract = Test-ModuleFunctionContract -ModuleTag "Settings-UI" -FunctionMap $functionMap -RequiredFunctions @("Show-SettingsDialog", "Show-LogTailDialog", "Ensure-SettingsDialogVisible")
        $contract.IsValid | Should -BeTrue
        $functionMap.ContainsKey("Get-SettingsUiModuleVersion") | Should -BeTrue
    }

    It "imports history UI functions and satisfies required contract" {
        $script:ImportedUiFunctions = @{}
        $ok = Import-ScriptFunctionsToScriptScope $script:historyDialogScript "History-UI"
        $ok | Should -BeTrue
        $contract = Test-ModuleFunctionContract -ModuleTag "History-UI" -FunctionMap $script:ImportedUiFunctions -RequiredFunctions @("Show-HistoryDialog")
        $contract.IsValid | Should -BeTrue
        $script:ImportedUiFunctions.ContainsKey("Get-HistoryUiModuleVersion") | Should -BeTrue
    }

    It "validates tray module exported-function contract" {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:trayMenuScript, [ref]$tokens, [ref]$errors)
        $errors | Should -BeNullOrEmpty

        $functionMap = @{}
        $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object {
            $functionMap[$_.Name] = [scriptblock]::Create("param()")
        }

        $contract = Test-ModuleFunctionContract -ModuleTag "Tray-Module" -FunctionMap $functionMap -RequiredFunctions @("Update-TrayLabels", "Invoke-TrayAction", "Set-StatusUpdateTimerEnabled")
        $contract.IsValid | Should -BeTrue
        $functionMap.ContainsKey("Get-TrayModuleVersion") | Should -BeTrue
    }
}

Describe "Quality: Startup Budgets" {
    BeforeAll {
        Invoke-Expression $script:coreRuntimeText
    }

    It "defines startup budgets for critical boot stages" {
        $budgets = Get-DefaultStartupBudgetsMs
        $budgets.Keys -contains "Startup complete" | Should -BeTrue
        [int64]$budgets["Startup complete"] | Should -BeGreaterThan 0
    }

    It "detects when startup stage exceeds budget" {
        $budgets = Get-DefaultStartupBudgetsMs
        $over = Test-StartupStageBudget -Stage "Startup complete" -ElapsedMs ([int64]$budgets["Startup complete"] + 1) -Budgets $budgets
        $over.HasBudget | Should -BeTrue
        $over.WithinBudget | Should -BeFalse
    }

    It "parses boot stage timings from log lines" {
        $parsed = Convert-BootLogLineToStageTiming "[2/11/2026 2:18 PM] [INFO] Boot: Startup complete +4050ms"
        $parsed.Stage | Should -Be "Startup complete"
        [int64]$parsed.ElapsedMs | Should -Be 4050
    }
}

Describe "Quality: Localization Coverage" {
    BeforeAll {
        . $script:uiStringsScript
        $script:uiLanguages = @($script:UiStrings.Keys | Sort-Object)
        $script:uiNonEnglishLanguages = @($script:uiLanguages | Where-Object { $_ -ne "en" })
        $script:requiredUiKeys = @(
            "Settings",
            "General",
            "Scheduling",
            "Hotkeys",
            "Logging",
            "Profiles",
            "Appearance",
            "Diagnostics",
            "Advanced",
            "About",
            "Language",
            "Save",
            "Cancel",
            "Done",
            "Start",
            "Stop",
            "Pause",
            "Resume"
        )
    }

    It "contains required UI keys for every language table" {
        foreach ($lang in $script:uiLanguages) {
            foreach ($key in $script:requiredUiKeys) {
                $script:UiStrings[$lang].ContainsKey($key) | Should -BeTrue
            }
        }
    }

    It "keeps broad translation coverage for required UI keys in non-English languages" {
        foreach ($lang in $script:uiNonEnglishLanguages) {
            $translatedCount = 0
            foreach ($key in $script:requiredUiKeys) {
                $value = [string]$script:UiStrings[$lang][$key]
                $english = [string]$script:UiStrings["en"][$key]
                [string]::IsNullOrWhiteSpace($value) | Should -BeFalse
                if ($value -ne $english) { $translatedCount++ }
            }
            $translatedCount | Should -BeGreaterOrEqual 12
        }
    }
}

Describe "Quality: Settings Migration Unit Tests" {
    BeforeAll {
        function Get-SettingsPropertyValue {
            param($settings, [string]$name, $default = $null)
            if (-not $settings) { return $default }
            if ($settings.PSObject.Properties.Name -contains $name) { return $settings.$name }
            return $default
        }
        function Set-SettingsPropertyValue {
            param($settings, [string]$name, $value)
            if (-not $settings) { return }
            if ($settings.PSObject.Properties.Name -contains $name) {
                $settings.$name = $value
            } else {
                $settings | Add-Member -MemberType NoteProperty -Name $name -Value $value -Force
            }
        }
        Invoke-Expression $script:functionTextByName["Migrate-Settings"]
    }

    It "migrates legacy settings to current schema and adds required keys" {
        $script:DateTimeFormatDefault = "yyyy-MM-dd HH:mm:ss"
        $script:DataRoot = "C:\\Temp\\TeamsAlwaysGreen"
        $script:SettingsSchemaVersion = 9
        $script:SecurityDefaultUpdateOwner = "alexphillips-dev"
        $script:SecurityDefaultUpdateRepo = "Teams-Always-Green"

        $legacy = [pscustomobject]@{
            SchemaVersion = 1
            IntervalSeconds = 60
            LogLevel = "INFO"
            MinimalTrayTooltip = $false
        }
        $migrated = Migrate-Settings $legacy

        [int]$migrated.SchemaVersion | Should -Be 9
        $migrated.PSObject.Properties.Name | Should -Contain "DateTimeFormat"
        $migrated.PSObject.Properties.Name | Should -Contain "UseSystemDateTimeFormat"
        $migrated.PSObject.Properties.Name | Should -Contain "DataRoot"
        $migrated.PSObject.Properties.Name | Should -Contain "AllowExternalPaths"
        $migrated.PSObject.Properties.Name | Should -Contain "SecurityModeEnabled"
        $migrated.PSObject.Properties.Name | Should -Contain "StrictProfileImport"
        $migrated.PSObject.Properties.Name | Should -Contain "UpdateOwner"
    }

    It "preserves future schema versions without downgrading" {
        $future = [pscustomobject]@{
            SchemaVersion = 99
            IntervalSeconds = 60
        }
        $migrated = Migrate-Settings $future
        [int]$migrated.SchemaVersion | Should -Be 99
    }

    It "adds update security keys when migrating from schema 8" {
        $script:DataRoot = "C:\\Temp\\TeamsAlwaysGreen"
        $script:SettingsSchemaVersion = 9
        $script:SecurityDefaultUpdateOwner = "alexphillips-dev"
        $script:SecurityDefaultUpdateRepo = "Teams-Always-Green"

        $legacy = [pscustomobject]@{
            SchemaVersion = 8
            IntervalSeconds = 60
            LogLevel = "INFO"
        }
        $migrated = Migrate-Settings $legacy

        [int]$migrated.SchemaVersion | Should -Be 9
        $migrated.PSObject.Properties.Name | Should -Contain "UpdateOwner"
        $migrated.PSObject.Properties.Name | Should -Contain "UpdateRepo"
        $migrated.PSObject.Properties.Name | Should -Contain "UpdateRequireHash"
        $migrated.PSObject.Properties.Name | Should -Contain "UpdateRequireSignature"
        $migrated.PSObject.Properties.Name | Should -Contain "HardenPermissions"
    }
}

Describe "Quality: Profile Signature Unit Tests" {
    BeforeAll {
        $script:ProfileSchemaVersion = 1
        function Migrate-ProfileSnapshot {
            param($profile)
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
        Invoke-Expression $script:functionTextByName["Get-StringSha256Hex"]
        Invoke-Expression $script:functionTextByName["Get-ProfileExportSignature"]
        Invoke-Expression $script:functionTextByName["Test-ProfileExportSignature"]
    }

    It "accepts a valid profile signature" {
        $profile = [pscustomobject]@{
            IntervalSeconds = 60
            HotkeyToggle = "Ctrl+Shift+F12"
            HotkeyStartStop = ""
            HotkeyPauseResume = ""
        }
        $payload = [pscustomobject]@{
            Name = "Default"
            Profile = $profile
            SignatureAlgorithm = "SHA256"
        }
        $payload | Add-Member -MemberType NoteProperty -Name "Signature" -Value (Get-ProfileExportSignature $payload.Name $payload.Profile) -Force
        $result = Test-ProfileExportSignature $payload
        $result.IsValid | Should -BeTrue
    }

    It "rejects a tampered profile signature" {
        $profile = [pscustomobject]@{
            IntervalSeconds = 60
            HotkeyToggle = "Ctrl+Shift+F12"
            HotkeyStartStop = ""
            HotkeyPauseResume = ""
        }
        $payload = [pscustomobject]@{
            Name = "Default"
            Profile = $profile
            SignatureAlgorithm = "SHA256"
            Signature = "00"
        }
        $result = Test-ProfileExportSignature $payload
        $result.IsValid | Should -BeFalse
    }
}

Describe "Quality: Security Unit Tests" {
    BeforeAll {
        function Get-SettingsPropertyValue {
            param($settings, [string]$name, $default = $null)
            if (-not $settings) { return $default }
            if ($settings.PSObject.Properties.Name -contains $name) { return $settings.$name }
            return $default
        }
        Invoke-Expression $script:functionTextByName["Get-RateLimitRule"]
        Invoke-Expression $script:functionTextByName["Test-RateLimit"]
        Invoke-Expression $script:functionTextByName["Test-SettingsSchema"]
        Invoke-Expression $script:functionTextByName["Test-ProfileSnapshot"]
    }

    It "enforces rate limiting after max attempts" {
        $script:SecurityRateLimitDefaults = @{ Probe = @{ WindowSeconds = 60; MaxAttempts = 2 } }
        $script:SecurityRateLimits = @{}
        (Test-RateLimit "Probe") | Should -BeTrue
        (Test-RateLimit "Probe") | Should -BeTrue
        (Test-RateLimit "Probe") | Should -BeFalse
    }

    It "blocks unknown settings keys when strict schema mode is enabled" {
        $script:SettingsSchemaVersion = 9
        $script:DefaultSettingsKeys = @("SchemaVersion", "IntervalSeconds", "LogLevel")
        $script:SettingsRuntimeKeys = @()
        $candidate = [pscustomobject]@{
            SchemaVersion = 9
            IntervalSeconds = 60
            LogLevel = "INFO"
            UnexpectedKey = "x"
        }
        $result = Test-SettingsSchema $candidate -Strict
        $result.IsCritical | Should -BeTrue
        $result.Issues -join ";" | Should -Match 'Unknown keys blocked by strict mode'
    }

    It "blocks unknown profile keys when strict profile mode is enabled" {
        $script:ProfilePropertyNames = @("IntervalSeconds", "HotkeyToggle", "HotkeyStartStop", "HotkeyPauseResume")
        $script:ProfileMetadataKeys = @("ProfileSchemaVersion", "ReadOnly")
        $candidate = [pscustomobject]@{
            IntervalSeconds = 60
            HotkeyToggle = "Ctrl+Alt+T"
            HotkeyStartStop = ""
            HotkeyPauseResume = ""
            EvilKey = "x"
        }
        $result = Test-ProfileSnapshot $candidate -Strict
        $result.IsValid | Should -BeFalse
        $result.Issues -join ";" | Should -Match 'Unknown profile keys blocked by strict mode'
    }
}

Describe "Quality: Version and Changelog" {
    It "uses semantic versioning in VERSION file" {
        Test-Path $script:versionPath | Should -BeTrue
        $version = (Get-Content -Path $script:versionPath -Raw).Trim()
        $version | Should -Match '^\d+\.\d+\.\d+$'
    }

    It "contains changelog entry for current version" {
        Test-Path $script:changelogPath | Should -BeTrue
        $version = (Get-Content -Path $script:versionPath -Raw).Trim()
        $changelog = Get-Content -Path $script:changelogPath -Raw
        $changelog | Should -Match '(?im)^##\s*\[Unreleased\]'
        $changelog | Should -Match ("(?im)^##\s*\[?{0}\]?" -f [regex]::Escape($version))
    }
}
