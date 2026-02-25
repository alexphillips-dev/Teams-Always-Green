[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "", Scope = "Function", Target = "Ensure-UninstallShortcut")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Scope = "Function", Target = "Remove-AppShortcuts")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Scope = "Function", Target = "Get-TrackedProcessCandidates")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Scope = "Function", Target = "Get-PathLockDiagnostics")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Scope = "Function", Target = "Stop-AppProcesses")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "", Scope = "Function", Target = "Remove-AppShortcuts")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "", Scope = "Function", Target = "Stop-TrackedProcess")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "", Scope = "Function", Target = "Stop-AppProcesses")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "", Scope = "Function", Target = "Start-RemovalWorker")]
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param(
    [switch]$Silent,
    [switch]$RemoveAppData,
    [ValidateSet("Keep", "Remove", "Prompt")]
    [string]$AppDataPolicy = "Prompt"
)

Add-Type -AssemblyName System.Windows.Forms
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:ExitCodes = @{
    Success           = 0
    UserCancelled     = 2
    SafetyBlocked     = 10
    WorkerStartFailed = 20
    PartialCleanup    = 30
    UnhandledError    = 99
}

$script:AppName = "Teams Always Green"
$script:AppDataRoot = Join-Path $env:LOCALAPPDATA "TeamsAlwaysGreen"
$script:IsDryRun = [bool]$WhatIfPreference

$tempRoot = if (-not [string]::IsNullOrWhiteSpace($env:TEMP)) {
    $env:TEMP
} elseif (-not [string]::IsNullOrWhiteSpace($env:TMP)) {
    $env:TMP
} else {
    [System.IO.Path]::GetTempPath()
}

$runId = (Get-Date).ToString("yyyyMMdd-HHmmss")
$script:UninstallLogPath = Join-Path $tempRoot ("TeamsAlwaysGreen-Uninstall-{0}.log" -f $runId)
$script:UninstallReportPath = Join-Path $tempRoot ("TeamsAlwaysGreen-Uninstall-{0}.json" -f $runId)

$script:UninstallReport = [ordered]@{
    StartedAtUtc             = [DateTime]::UtcNow.ToString("o")
    ScriptPath               = [string]$MyInvocation.MyCommand.Path
    InstallRoot              = ""
    Silent                   = [bool]$Silent
    DryRun                   = [bool]$script:IsDryRun
    AppDataPolicyRequested   = [string]$AppDataPolicy
    AppDataPolicyEffective   = ""
    RemoveAppDataSwitch      = [bool]$RemoveAppData
    RemoveAppDataResolved    = $false
    ShortcutsRemoved         = @()
    ShortcutRemoveFailures   = @()
    ProcessesStopped         = @()
    ProcessStopFailures      = @()
    ProcessCandidates        = @()
    CleanupWorkerStarted     = $false
    CleanupWorkerPath        = ""
    LockDiagnostics          = ""
    RollbackPerformed        = $false
    RollbackResult           = ""
    Result                   = "Pending"
    ExitCode                 = -1
    Summary                  = ""
    CompletedAtUtc           = ""
}

function Write-UninstallLog([string]$message) {
    if ([string]::IsNullOrWhiteSpace($message)) { return }
    try {
        $line = "[{0}] {1}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $message
        Add-Content -Path $script:UninstallLogPath -Value $line -Encoding UTF8 -WhatIf:$false -Confirm:$false
    } catch {
        $null = $_
    }
}

function Save-UninstallReport {
    try {
        $script:UninstallReport.CompletedAtUtc = [DateTime]::UtcNow.ToString("o")
        $json = $script:UninstallReport | ConvertTo-Json -Depth 8
        Set-Content -Path $script:UninstallReportPath -Value $json -Encoding UTF8 -WhatIf:$false -Confirm:$false
    } catch {
        Write-UninstallLog ("Failed to write uninstall report: {0}" -f $_.Exception.Message)
    }
}

function Show-UninstallMessage([string]$message, [string]$title, [System.Windows.Forms.MessageBoxIcon]$icon) {
    if ($Silent) { return }
    [void][System.Windows.Forms.MessageBox]::Show(
        $message,
        $title,
        [System.Windows.Forms.MessageBoxButtons]::OK,
        $icon
    )
}

function Complete-Uninstall {
    param(
        [int]$ExitCode,
        [string]$Result,
        [string]$Summary,
        [switch]$NotifyUser,
        [System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::Information,
        [string]$Title = "Uninstall Teams Always Green"
    )

    if (-not [string]::IsNullOrWhiteSpace($Summary)) {
        Write-UninstallLog $Summary
    }
    $script:UninstallReport.Result = [string]$Result
    $script:UninstallReport.ExitCode = [int]$ExitCode
    $script:UninstallReport.Summary = [string]$Summary
    Save-UninstallReport

    if ($NotifyUser) {
        $message = "{0}`n`nLog: {1}`nReport: {2}" -f $Summary, $script:UninstallLogPath, $script:UninstallReportPath
        Show-UninstallMessage $message $Title $Icon
    }

    exit $ExitCode
}

function Get-InstallRootFromScriptPath([string]$scriptPath) {
    if ([string]::IsNullOrWhiteSpace($scriptPath)) { return "" }
    return (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $scriptPath)))
}

function Test-IsProtectedPath([string]$fullPath) {
    if ([string]::IsNullOrWhiteSpace($fullPath)) { return $true }
    $trimmed = $fullPath.TrimEnd("\")
    if ([string]::IsNullOrWhiteSpace($trimmed)) { return $true }

    $roots = @()
    try { $roots += [System.IO.Path]::GetPathRoot($trimmed).TrimEnd("\") } catch { $null = $_ }
    $roots += @(
        ($env:SystemDrive + "\").TrimEnd("\"),
        [string]$env:USERPROFILE,
        [string]$env:ProgramFiles,
        [string]${env:ProgramFiles(x86)},
        [string]$env:LOCALAPPDATA,
        [string]$env:APPDATA,
        [Environment]::GetFolderPath("Desktop"),
        [Environment]::GetFolderPath("MyDocuments")
    )
    foreach ($candidate in @($roots | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        if ($trimmed.Equals([string]$candidate.TrimEnd("\"), [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Test-UninstallTargetPath([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) {
        return [pscustomobject]@{ IsSafe = $false; Reason = "Install path is empty."; Path = "" }
    }

    try {
        $resolved = [System.IO.Path]::GetFullPath($path)
    } catch {
        return [pscustomobject]@{ IsSafe = $false; Reason = "Install path could not be resolved."; Path = "" }
    }

    if (Test-IsProtectedPath $resolved) {
        return [pscustomobject]@{ IsSafe = $false; Reason = "Install path resolves to a protected system/user location."; Path = $resolved }
    }

    $markers = @(
        (Join-Path $resolved "Script\Teams Always Green.ps1"),
        (Join-Path $resolved "Teams Always Green.VBS"),
        (Join-Path $resolved "Meta")
    )
    $hasMarker = $false
    foreach ($marker in $markers) {
        if (Test-Path -LiteralPath $marker) {
            $hasMarker = $true
            break
        }
    }
    if (-not $hasMarker) {
        return [pscustomobject]@{ IsSafe = $false; Reason = "Install signature files were not found under the target path."; Path = $resolved }
    }

    return [pscustomobject]@{ IsSafe = $true; Reason = ""; Path = $resolved }
}

function Get-EffectiveAppDataPolicy {
    param(
        [switch]$SilentMode,
        [switch]$RemoveAppDataSwitch,
        [string]$RequestedPolicy
    )

    if ($RemoveAppDataSwitch) { return "Remove" }
    switch ($RequestedPolicy) {
        "Keep" { return "Keep" }
        "Remove" { return "Remove" }
        default {
            if ($SilentMode) { return "Keep" }
            return "Prompt"
        }
    }
}

function Get-ShortcutMap {
    $programsDir = [Environment]::GetFolderPath("Programs")
    $menuFolder = Join-Path $programsDir $script:AppName
    return @{
        MenuFolder         = $menuFolder
        MainShortcut       = (Join-Path $menuFolder "Teams Always Green.lnk")
        UninstallShortcut  = (Join-Path $menuFolder "Uninstall Teams Always Green.lnk")
        DesktopShortcut    = (Join-Path ([Environment]::GetFolderPath("Desktop")) "Teams Always Green.lnk")
        StartupShortcut    = (Join-Path ([Environment]::GetFolderPath("Startup")) "Teams Always Green.lnk")
    }
}

function Remove-AppShortcuts([hashtable]$shortcutMap) {
    $result = [ordered]@{
        Removed                  = @()
        Failed                   = @()
        RemovedUninstallShortcut = $false
    }

    foreach ($shortcut in @(
        [string]$shortcutMap.MainShortcut,
        [string]$shortcutMap.UninstallShortcut,
        [string]$shortcutMap.DesktopShortcut,
        [string]$shortcutMap.StartupShortcut
    )) {
        if ([string]::IsNullOrWhiteSpace($shortcut)) { continue }
        try {
            if (-not (Test-Path -LiteralPath $shortcut)) { continue }
            if ($script:IsDryRun) {
                Write-UninstallLog ("WhatIf: would remove shortcut: {0}" -f $shortcut)
                continue
            }
            Remove-Item -LiteralPath $shortcut -Force -ErrorAction Stop
            $result.Removed += $shortcut
            if ($shortcut.Equals([string]$shortcutMap.UninstallShortcut, [System.StringComparison]::OrdinalIgnoreCase)) {
                $result.RemovedUninstallShortcut = $true
            }
            Write-UninstallLog ("Removed shortcut: {0}" -f $shortcut)
        } catch {
            $failure = ("{0} | {1}" -f $shortcut, $_.Exception.Message)
            $result.Failed += $failure
            Write-UninstallLog ("Failed to remove shortcut: {0}" -f $failure)
        }
    }

    try {
        $menuFolder = [string]$shortcutMap.MenuFolder
        if (-not [string]::IsNullOrWhiteSpace($menuFolder) -and (Test-Path -LiteralPath $menuFolder -PathType Container)) {
            $childCount = (Get-ChildItem -Path $menuFolder -Force | Measure-Object).Count
            if ($childCount -eq 0) {
                if ($script:IsDryRun) {
                    Write-UninstallLog ("WhatIf: would remove empty Start Menu folder: {0}" -f $menuFolder)
                } else {
                    Remove-Item -LiteralPath $menuFolder -Force -ErrorAction Stop
                    Write-UninstallLog ("Removed empty Start Menu folder: {0}" -f $menuFolder)
                }
            }
        }
    } catch {
        Write-UninstallLog ("Failed to remove Start Menu folder: {0}" -f $_.Exception.Message)
    }

    return [pscustomobject]$result
}

function Ensure-UninstallShortcut([string]$installRoot, [hashtable]$shortcutMap) {
    if ($script:IsDryRun) {
        Write-UninstallLog ("WhatIf: would recreate uninstall shortcut at {0}" -f [string]$shortcutMap.UninstallShortcut)
        return $true
    }

    try {
        $menuFolder = [string]$shortcutMap.MenuFolder
        if (-not (Test-Path -LiteralPath $menuFolder -PathType Container)) {
            New-Item -ItemType Directory -Path $menuFolder -Force | Out-Null
        }

        $uninstallVbs = Join-Path $installRoot "Script\Uninstall\Uninstall-Teams-Always-Green.vbs"
        if (-not (Test-Path -LiteralPath $uninstallVbs -PathType Leaf)) {
            Write-UninstallLog ("Rollback failed: uninstall VBS is missing: {0}" -f $uninstallVbs)
            return $false
        }

        $shortcutPath = [string]$shortcutMap.UninstallShortcut
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = "$env:WINDIR\System32\wscript.exe"
        $shortcut.Arguments = "`"$uninstallVbs`""
        $shortcut.WorkingDirectory = $installRoot
        $iconPath = Join-Path $installRoot "Meta\Icons\Tray_Icon.ico"
        if (Test-Path -LiteralPath $iconPath -PathType Leaf) {
            $shortcut.IconLocation = "$iconPath,0"
        } else {
            $shortcut.IconLocation = "$env:WINDIR\System32\shell32.dll,1"
        }
        $shortcut.Save()
        Write-UninstallLog ("Rollback complete: recreated uninstall shortcut: {0}" -f $shortcutPath)
        return $true
    } catch {
        Write-UninstallLog ("Rollback failed: unable to recreate uninstall shortcut: {0}" -f $_.Exception.Message)
        return $false
    }
}

function Get-TrackedProcessCandidates([string]$installRoot) {
    $filter = "Name='wscript.exe' OR Name='cscript.exe' OR Name='powershell.exe' OR Name='pwsh.exe'"
    try {
        $all = @(Get-CimInstance Win32_Process -Filter $filter -ErrorAction Stop)
    } catch {
        Write-UninstallLog ("Process discovery failed: {0}" -f $_.Exception.Message)
        return @()
    }

    $tokens = @(
        $installRoot,
        (Join-Path $installRoot "Script\Teams Always Green.ps1"),
        (Join-Path $installRoot "Teams Always Green.VBS"),
        (Join-Path $installRoot "Script\Uninstall\Uninstall-Teams-Always-Green.ps1")
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.ToLowerInvariant() }

    $byId = @{}
    foreach ($proc in $all) {
        $byId[[int]$proc.ProcessId] = $proc
    }

    $direct = @{}
    foreach ($proc in $all) {
        $procId = [int]$proc.ProcessId
        if ($procId -eq $PID) { continue }
        $cmd = [string]$proc.CommandLine
        if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
        $cmdLower = $cmd.ToLowerInvariant()
        foreach ($token in $tokens) {
            if ($cmdLower.Contains($token)) {
                $direct[$procId] = $true
                break
            }
        }
    }

    $selected = New-Object System.Collections.Generic.List[object]
    foreach ($proc in $all) {
        $procId = [int]$proc.ProcessId
        if ($procId -eq $PID) { continue }
        $reason = $null

        if ($direct.ContainsKey($procId)) {
            $reason = "direct-commandline-match"
        } else {
            $cursor = [int]$proc.ParentProcessId
            for ($depth = 0; $depth -lt 12; $depth++) {
                if ($cursor -le 0) { break }
                if ($direct.ContainsKey($cursor)) {
                    $reason = ("descendant-of-{0}" -f $cursor)
                    break
                }
                if (-not $byId.ContainsKey($cursor)) { break }
                $cursor = [int]$byId[$cursor].ParentProcessId
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($reason)) {
            $selected.Add([pscustomobject]@{
                ProcessId     = $procId
                ParentProcess = [int]$proc.ParentProcessId
                Name          = [string]$proc.Name
                MatchReason   = $reason
                CommandLine   = [string]$proc.CommandLine
            })
        }
    }

    return @($selected | Sort-Object ProcessId -Unique)
}

function Get-PathLockDiagnostics([string]$installRoot) {
    $candidates = @(Get-TrackedProcessCandidates -installRoot $installRoot)
    if ($candidates.Count -eq 0) { return "none" }

    $items = New-Object System.Collections.Generic.List[string]
    foreach ($candidate in $candidates) {
        $cmd = [string]$candidate.CommandLine
        if ($cmd.Length -gt 180) { $cmd = $cmd.Substring(0, 180) + "..." }
        $items.Add(("PID={0};Name={1};Reason={2};Cmd={3}" -f $candidate.ProcessId, $candidate.Name, $candidate.MatchReason, $cmd))
    }
    return ($items -join " || ")
}

function Stop-TrackedProcess([pscustomobject]$candidate) {
    if ($script:IsDryRun) {
        Write-UninstallLog ("WhatIf: would stop PID={0} Name={1} Reason={2}" -f $candidate.ProcessId, $candidate.Name, $candidate.MatchReason)
        return $true
    }

    $delays = @(200, 500, 1000)
    foreach ($delay in $delays) {
        try {
            Stop-Process -Id ([int]$candidate.ProcessId) -Force -ErrorAction Stop
            Write-UninstallLog ("Stopped process PID={0} Name={1} Reason={2}" -f $candidate.ProcessId, $candidate.Name, $candidate.MatchReason)
            return $true
        } catch {
            Write-UninstallLog ("Stop attempt failed for PID={0}: {1}" -f $candidate.ProcessId, $_.Exception.Message)
            Start-Sleep -Milliseconds $delay
        }
    }

    try {
        $stillRunning = Get-Process -Id ([int]$candidate.ProcessId) -ErrorAction Stop
        if ($stillRunning) {
            Write-UninstallLog ("PID={0} is still running after retries." -f $candidate.ProcessId)
            return $false
        }
    } catch {
        return $true
    }
    return $false
}

function Stop-AppProcesses([string]$installRoot) {
    $result = [ordered]@{
        Candidates = @()
        Stopped    = @()
        Failed     = @()
    }

    $candidates = @(Get-TrackedProcessCandidates -installRoot $installRoot)
    foreach ($candidate in $candidates) {
        $result.Candidates += ("PID={0}|Name={1}|Reason={2}" -f $candidate.ProcessId, $candidate.Name, $candidate.MatchReason)
        if (Stop-TrackedProcess -candidate $candidate) {
            $result.Stopped += [int]$candidate.ProcessId
        } else {
            $result.Failed += [int]$candidate.ProcessId
        }
    }

    if ($candidates.Count -eq 0) {
        Write-UninstallLog "No candidate app processes found."
    } else {
        Write-UninstallLog ("Process stop summary: candidates={0} stopped={1} failed={2}" -f $candidates.Count, $result.Stopped.Count, $result.Failed.Count)
    }

    if (-not $script:IsDryRun) {
        Start-Sleep -Milliseconds 700
    }

    return [pscustomobject]$result
}

function Start-RemovalWorker([string]$installRoot, [bool]$removeAppData, [string]$appDataRoot, [string]$logPath) {
    if ($script:IsDryRun) {
        Write-UninstallLog ("WhatIf: would start cleanup worker for install path '{0}' (RemoveAppData={1})" -f $installRoot, $removeAppData)
        return [pscustomobject]@{ Started = $true; CleanupPath = ""; Error = "" }
    }

    $cleanupPath = Join-Path $tempRoot ("TAG-UninstallCleanup-{0}.ps1" -f [Guid]::NewGuid().ToString("N"))
    $escapedInstallRoot = $installRoot.Replace("'", "''")
    $escapedAppDataRoot = $appDataRoot.Replace("'", "''")
    $escapedLogPath = $logPath.Replace("'", "''")
    $escapedCleanupPath = $cleanupPath.Replace("'", "''")
    $removeAppDataLiteral = if ($removeAppData) { '$true' } else { '$false' }

    $cleanupScript = @"
`$ErrorActionPreference = 'SilentlyContinue'
function Write-CleanupLog([string]`$message) {
    if ([string]::IsNullOrWhiteSpace(`$message)) { return }
    try {
        Add-Content -Path '$escapedLogPath' -Value ('[{0}] [cleanup] {1}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), `$message) -Encoding UTF8
    } catch {
        `$null = `$_
    }
}
function Get-LockDiagnostics([string]`$rootPath) {
    try {
        `$filter = "Name='wscript.exe' OR Name='cscript.exe' OR Name='powershell.exe' OR Name='pwsh.exe'"
        `$list = @(Get-CimInstance Win32_Process -Filter `$filter -ErrorAction Stop)
        `$items = New-Object System.Collections.Generic.List[string]
        foreach (`$proc in `$list) {
            `$cmd = [string]`$proc.CommandLine
            if ([string]::IsNullOrWhiteSpace(`$cmd)) { continue }
            if (`$cmd.IndexOf(`$rootPath, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
            if (`$cmd.Length -gt 160) { `$cmd = `$cmd.Substring(0, 160) + '...' }
            `$items.Add(('PID={0};Name={1};Cmd={2}' -f `$proc.ProcessId, `$proc.Name, `$cmd))
        }
        if (`$items.Count -eq 0) { return 'none' }
        return (`$items -join ' || ')
    } catch {
        return ('diag-error: ' + `$_.Exception.Message)
    }
}
function Remove-WithRetry([string]`$targetPath, [string]`$label) {
    if ([string]::IsNullOrWhiteSpace(`$targetPath)) { return `$false }
    for (`$attempt = 1; `$attempt -le 12; `$attempt++) {
        if (-not (Test-Path -LiteralPath `$targetPath)) { return `$true }
        Remove-Item -LiteralPath `$targetPath -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath `$targetPath)) { return `$true }
        `$delay = [Math]::Min(3000, [int](200 * [Math]::Pow(2, [Math]::Min(4, `$attempt))))
        Write-CleanupLog ('Attempt {0} failed for {1}; backoff={2}ms' -f `$attempt, `$label, `$delay)
        Start-Sleep -Milliseconds `$delay
    }
    if (Test-Path -LiteralPath `$targetPath) {
        `$diag = Get-LockDiagnostics '$escapedInstallRoot'
        Write-CleanupLog ('Lock diagnostics for {0}: {1}' -f `$label, `$diag)
        return `$false
    }
    return `$true
}
Write-CleanupLog 'Cleanup worker started.'
`$removedInstall = Remove-WithRetry '$escapedInstallRoot' 'install-root'
if (`$removedInstall) {
    Write-CleanupLog ('Removed install path: {0}' -f '$escapedInstallRoot')
} else {
    Write-CleanupLog ('Failed to remove install path: {0}' -f '$escapedInstallRoot')
}
`$removeAppData = $removeAppDataLiteral
if (`$removeAppData) {
    `$removedData = Remove-WithRetry '$escapedAppDataRoot' 'app-data'
    if (`$removedData) {
        Write-CleanupLog ('Removed app data path: {0}' -f '$escapedAppDataRoot')
    } else {
        Write-CleanupLog ('Failed to remove app data path: {0}' -f '$escapedAppDataRoot')
    }
}
Remove-Item -LiteralPath '$escapedCleanupPath' -Force -ErrorAction SilentlyContinue
"@

    try {
        Set-Content -Path $cleanupPath -Value $cleanupScript -Encoding UTF8
        Start-Process "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy RemoteSigned -WindowStyle Hidden -File `"$cleanupPath`"" -WindowStyle Hidden -ErrorAction Stop | Out-Null
        Write-UninstallLog ("Started cleanup worker: {0}" -f $cleanupPath)
        return [pscustomobject]@{ Started = $true; CleanupPath = $cleanupPath; Error = "" }
    } catch {
        Write-UninstallLog ("Failed to start cleanup worker: {0}" -f $_.Exception.Message)
        return [pscustomobject]@{ Started = $false; CleanupPath = $cleanupPath; Error = [string]$_.Exception.Message }
    }
}

try {
    $scriptPath = $MyInvocation.MyCommand.Path
    $installRoot = Get-InstallRootFromScriptPath $scriptPath
    $script:UninstallReport.InstallRoot = [string]$installRoot

    Write-UninstallLog ("Uninstall started. Script={0}" -f $scriptPath)
    Write-UninstallLog ("Resolved install root={0}" -f $installRoot)
    Write-UninstallLog ("AppData root={0}" -f $script:AppDataRoot)
    Write-UninstallLog ("DryRun={0}" -f $script:IsDryRun)

    $validation = Test-UninstallTargetPath $installRoot
    if (-not $validation.IsSafe) {
        Complete-Uninstall -ExitCode $script:ExitCodes.SafetyBlocked -Result "SafetyBlocked" -Summary ("Uninstall blocked for safety: {0}" -f $validation.Reason) -NotifyUser -Icon ([System.Windows.Forms.MessageBoxIcon]::Error) -Title "Uninstall blocked"
    }
    $installRoot = [string]$validation.Path
    $script:UninstallReport.InstallRoot = $installRoot

    $operation = "Remove app files, shortcuts, and selected local data"
    if (-not $PSCmdlet.ShouldProcess($installRoot, $operation)) {
        if ($script:IsDryRun) {
            $previewPolicy = Get-EffectiveAppDataPolicy -SilentMode:$Silent -RemoveAppDataSwitch:$RemoveAppData -RequestedPolicy $AppDataPolicy
            $summary = "Dry run complete. Planned uninstall root: {0}. AppData policy: {1}." -f $installRoot, $previewPolicy
            Complete-Uninstall -ExitCode $script:ExitCodes.Success -Result "DryRun" -Summary $summary
        } else {
            Complete-Uninstall -ExitCode $script:ExitCodes.UserCancelled -Result "Cancelled" -Summary "Uninstall cancelled by confirmation prompt."
        }
    }

    $effectivePolicy = Get-EffectiveAppDataPolicy -SilentMode:$Silent -RemoveAppDataSwitch:$RemoveAppData -RequestedPolicy $AppDataPolicy
    if ($effectivePolicy -eq "Prompt" -and -not $Silent) {
        $dataResp = [System.Windows.Forms.MessageBox]::Show(
            "Also remove local settings and logs?`n`nDefault is to keep local data.`nPath: $script:AppDataRoot",
            "Uninstall Teams Always Green",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($dataResp -eq [System.Windows.Forms.DialogResult]::Yes) {
            $effectivePolicy = "Remove"
        } else {
            $effectivePolicy = "Keep"
        }
    } elseif ($effectivePolicy -eq "Prompt") {
        $effectivePolicy = "Keep"
    }
    $removeAppDataRequested = ($effectivePolicy -eq "Remove")
    $script:UninstallReport.AppDataPolicyEffective = $effectivePolicy
    $script:UninstallReport.RemoveAppDataResolved = [bool]$removeAppDataRequested
    Write-UninstallLog ("AppDataPolicy requested={0} effective={1} remove={2}" -f $AppDataPolicy, $effectivePolicy, $removeAppDataRequested)

    if (-not $Silent -and -not $script:IsDryRun) {
        $resp = [System.Windows.Forms.MessageBox]::Show(
            "Remove app files from:`n$installRoot`n`nRunning app processes will be stopped.",
            "Uninstall Teams Always Green",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($resp -ne [System.Windows.Forms.DialogResult]::Yes) {
            Complete-Uninstall -ExitCode $script:ExitCodes.UserCancelled -Result "Cancelled" -Summary "Uninstall cancelled by user."
        }
    }

    $shortcutMap = Get-ShortcutMap
    $shortcutResult = Remove-AppShortcuts -shortcutMap $shortcutMap
    $script:UninstallReport.ShortcutsRemoved = @($shortcutResult.Removed)
    $script:UninstallReport.ShortcutRemoveFailures = @($shortcutResult.Failed)

    $processResult = Stop-AppProcesses -installRoot $installRoot
    $script:UninstallReport.ProcessCandidates = @($processResult.Candidates)
    $script:UninstallReport.ProcessesStopped = @($processResult.Stopped)
    $script:UninstallReport.ProcessStopFailures = @($processResult.Failed)

    $workerResult = Start-RemovalWorker -installRoot $installRoot -removeAppData:$removeAppDataRequested -appDataRoot $script:AppDataRoot -logPath $script:UninstallLogPath
    $script:UninstallReport.CleanupWorkerStarted = [bool]$workerResult.Started
    $script:UninstallReport.CleanupWorkerPath = [string]$workerResult.CleanupPath

    if (-not $workerResult.Started) {
        $script:UninstallReport.LockDiagnostics = Get-PathLockDiagnostics -installRoot $installRoot
        Write-UninstallLog ("Lock diagnostics: {0}" -f $script:UninstallReport.LockDiagnostics)

        $rollbackPerformed = $false
        if ([bool]$shortcutResult.RemovedUninstallShortcut) {
            $rollbackPerformed = Ensure-UninstallShortcut -installRoot $installRoot -shortcutMap $shortcutMap
        }
        $script:UninstallReport.RollbackPerformed = [bool]$rollbackPerformed
        $script:UninstallReport.RollbackResult = if ($rollbackPerformed) { "Uninstall shortcut restored." } else { "Uninstall shortcut restore not required or failed." }

        $failureSummary = "Cleanup worker failed to start. No files were removed yet. {0}" -f $script:UninstallReport.RollbackResult
        if ($rollbackPerformed) {
            Complete-Uninstall -ExitCode $script:ExitCodes.WorkerStartFailed -Result "WorkerStartFailed" -Summary $failureSummary -NotifyUser -Icon ([System.Windows.Forms.MessageBoxIcon]::Error) -Title "Uninstall failed"
        } else {
            Complete-Uninstall -ExitCode $script:ExitCodes.PartialCleanup -Result "PartialCleanup" -Summary $failureSummary -NotifyUser -Icon ([System.Windows.Forms.MessageBoxIcon]::Error) -Title "Uninstall failed"
        }
    }

    $summary = if ($script:IsDryRun) {
        "Dry run complete. No files were removed."
    } else {
        "Uninstall started in the background."
    }
    Complete-Uninstall -ExitCode $script:ExitCodes.Success -Result "CleanupStarted" -Summary $summary -NotifyUser:(-not $Silent) -Icon ([System.Windows.Forms.MessageBoxIcon]::Information) -Title "Uninstall started"
} catch {
    $message = "Unhandled uninstall error: {0}" -f $_.Exception.Message
    Write-UninstallLog $message
    $script:UninstallReport.Result = "UnhandledError"
    $script:UninstallReport.ExitCode = $script:ExitCodes.UnhandledError
    $script:UninstallReport.Summary = $message
    Save-UninstallReport
    Show-UninstallMessage ("{0}`n`nLog: {1}`nReport: {2}" -f $message, $script:UninstallLogPath, $script:UninstallReportPath) "Uninstall failed" ([System.Windows.Forms.MessageBoxIcon]::Error)
    exit $script:ExitCodes.UnhandledError
}
