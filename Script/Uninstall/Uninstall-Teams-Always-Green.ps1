param(
    [switch]$Silent,
    [switch]$RemoveAppData
)

Add-Type -AssemblyName System.Windows.Forms
$ErrorActionPreference = "Stop"

$script:AppName = "Teams Always Green"
$script:AppDataRoot = Join-Path $env:LOCALAPPDATA "TeamsAlwaysGreen"
$tempRoot = if (-not [string]::IsNullOrWhiteSpace($env:TEMP)) { $env:TEMP } elseif (-not [string]::IsNullOrWhiteSpace($env:TMP)) { $env:TMP } else { [System.IO.Path]::GetTempPath() }
$script:UninstallLogPath = Join-Path $tempRoot ("TeamsAlwaysGreen-Uninstall-{0}.log" -f (Get-Date).ToString("yyyyMMdd-HHmmss"))

function Write-UninstallLog([string]$message) {
    if ([string]::IsNullOrWhiteSpace($message)) { return }
    try {
        $line = "[{0}] {1}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $message
        Add-Content -Path $script:UninstallLogPath -Value $line -Encoding UTF8
    } catch {
        $null = $_
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

function Remove-AppShortcuts {
    $programsDir = [Environment]::GetFolderPath("Programs")
    $menuFolder = Join-Path $programsDir $script:AppName
    $shortcuts = @(
        (Join-Path $menuFolder "Teams Always Green.lnk")
        (Join-Path $menuFolder "Uninstall Teams Always Green.lnk")
        (Join-Path ([Environment]::GetFolderPath("Desktop")) "Teams Always Green.lnk")
        (Join-Path ([Environment]::GetFolderPath("Startup")) "Teams Always Green.lnk")
    )
    foreach ($shortcut in $shortcuts) {
        try {
            if (Test-Path -LiteralPath $shortcut) {
                Remove-Item -LiteralPath $shortcut -Force -ErrorAction SilentlyContinue
                Write-UninstallLog ("Removed shortcut: {0}" -f $shortcut)
            }
        } catch {
            Write-UninstallLog ("Failed to remove shortcut: {0} | {1}" -f $shortcut, $_.Exception.Message)
        }
    }
    try {
        if (Test-Path -LiteralPath $menuFolder -and -not (Get-ChildItem -Path $menuFolder -Force | Measure-Object).Count) {
            Remove-Item -LiteralPath $menuFolder -Force -ErrorAction SilentlyContinue
            Write-UninstallLog ("Removed empty Start Menu folder: {0}" -f $menuFolder)
        }
    } catch {
        Write-UninstallLog ("Failed to remove Start Menu folder: {0}" -f $_.Exception.Message)
    }
}

function Stop-AppProcesses([string]$installRoot) {
    $filter = "Name='wscript.exe' OR Name='cscript.exe' OR Name='powershell.exe' OR Name='pwsh.exe'"
    try {
        $procs = @(Get-CimInstance Win32_Process -Filter $filter -ErrorAction Stop)
    } catch {
        Write-UninstallLog ("Process discovery failed: {0}" -f $_.Exception.Message)
        return
    }

    foreach ($proc in $procs) {
        $cmd = [string]$proc.CommandLine
        if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
        if ($cmd.IndexOf($installRoot, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        try {
            Stop-Process -Id ([int]$proc.ProcessId) -Force -ErrorAction Stop
            Write-UninstallLog ("Stopped process PID={0} Name={1}" -f $proc.ProcessId, $proc.Name)
        } catch {
            Write-UninstallLog ("Failed to stop PID={0}: {1}" -f $proc.ProcessId, $_.Exception.Message)
        }
    }

    Start-Sleep -Milliseconds 700
}

function Start-RemovalWorker([string]$installRoot, [bool]$removeAppData, [string]$appDataRoot, [string]$logPath) {
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
function Remove-WithRetry([string]`$targetPath) {
    if ([string]::IsNullOrWhiteSpace(`$targetPath)) { return `$false }
    for (`$attempt = 0; `$attempt -lt 12; `$attempt++) {
        if (-not (Test-Path -LiteralPath `$targetPath)) { return `$true }
        Remove-Item -LiteralPath `$targetPath -Recurse -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 400
    }
    return (-not (Test-Path -LiteralPath `$targetPath))
}
Write-CleanupLog 'Cleanup worker started.'
`$removedInstall = Remove-WithRetry '$escapedInstallRoot'
if (`$removedInstall) {
    Write-CleanupLog ('Removed install path: {0}' -f '$escapedInstallRoot')
} else {
    Write-CleanupLog ('Failed to remove install path: {0}' -f '$escapedInstallRoot')
}
`$removeAppData = $removeAppDataLiteral
if (`$removeAppData) {
    `$removedData = Remove-WithRetry '$escapedAppDataRoot'
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
        return $true
    } catch {
        Write-UninstallLog ("Failed to start cleanup worker: {0}" -f $_.Exception.Message)
        return $false
    }
}

$scriptPath = $MyInvocation.MyCommand.Path
$installRoot = Get-InstallRootFromScriptPath $scriptPath
Write-UninstallLog ("Uninstall started. Script={0}" -f $scriptPath)
Write-UninstallLog ("Resolved install root={0}" -f $installRoot)
Write-UninstallLog ("AppData root={0}" -f $script:AppDataRoot)

$validation = Test-UninstallTargetPath $installRoot
if (-not $validation.IsSafe) {
    Write-UninstallLog ("Safety check failed: {0}" -f $validation.Reason)
    Show-UninstallMessage ("Uninstall blocked for safety.`n`nReason: {0}`n`nLog: {1}" -f $validation.Reason, $script:UninstallLogPath) "Uninstall blocked" ([System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}
$installRoot = $validation.Path

Remove-AppShortcuts

$deleteFiles = $true
$removeAppDataRequested = [bool]$RemoveAppData
if (-not $Silent) {
    $resp = [System.Windows.Forms.MessageBox]::Show(
        "Remove the app files from:`n$installRoot`n`nThis will close running app processes.",
        "Uninstall Teams Always Green",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    if ($resp -ne [System.Windows.Forms.DialogResult]::Yes) { $deleteFiles = $false }
}

if (-not $deleteFiles) {
    Write-UninstallLog "User cancelled uninstall."
    exit 0
}

if (-not $Silent) {
    $dataResp = [System.Windows.Forms.MessageBox]::Show(
        "Also remove local settings and logs?`n$script:AppDataRoot",
        "Uninstall Teams Always Green",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )
    if ($dataResp -eq [System.Windows.Forms.DialogResult]::Yes) {
        $removeAppDataRequested = $true
    }
}
Write-UninstallLog ("RemoveAppData={0}" -f $removeAppDataRequested)

Stop-AppProcesses -installRoot $installRoot
$workerStarted = Start-RemovalWorker -installRoot $installRoot -removeAppData:$removeAppDataRequested -appDataRoot $script:AppDataRoot -logPath $script:UninstallLogPath

if (-not $workerStarted) {
    Show-UninstallMessage ("Uninstall could not start cleanup worker.`n`nLog: {0}" -f $script:UninstallLogPath) "Uninstall failed" ([System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}

if (-not $Silent) {
    Show-UninstallMessage ("Uninstall started in the background.`n`nLog: {0}" -f $script:UninstallLogPath) "Uninstall started" ([System.Windows.Forms.MessageBoxIcon]::Information)
}

exit 0
