param(
    [switch]$FailOnAnalyzer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step([string]$text) {
    Write-Host ("[{0}] {1}" -f (Get-Date).ToString("HH:mm:ss"), $text)
}

function Test-ParseFile([string]$path) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        $first = $errors | Select-Object -First 1
        throw ("Parse error in {0}: {1} (Line {2})" -f $path, $first.Message, $first.Extent.StartLineNumber)
    }
}

Write-Step "Parse check"
$repoRoot = Split-Path -Parent $PSScriptRoot
$targets = @(
    "Script\\Teams Always Green.ps1",
    "Script\\UI\\SettingsDialog.ps1",
    "Script\\Features\\UpdateEngine.ps1",
    "Script\\Tray\\Menu.ps1",
    "Script\\QuickSetup\\QuickSetup.ps1",
    "Script\\Core\\AppInfo.ps1",
    "Script\\Core\\Paths.ps1",
    "Script\\Core\\Runtime.ps1",
    "Script\\Core\\Settings.ps1",
    "Script\\Core\\Logging.ps1"
)
foreach ($rel in $targets) {
    $full = Join-Path $repoRoot $rel
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { continue }
    Test-ParseFile $full
    Write-Host ("  OK  {0}" -f $rel)
}
Write-Step "PSScriptAnalyzer (if available)"
try {
    if (Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue) {
        $settingsPath = Join-Path $repoRoot "PSScriptAnalyzerSettings.psd1"
        $result = Invoke-ScriptAnalyzer -Path (Join-Path $repoRoot "Script") -Recurse -Settings $settingsPath -Severity Warning,Error
        if ($result -and $result.Count -gt 0) {
            $top = $result | Select-Object -First 25 | ForEach-Object { "  {0}:{1} {2} ({3})" -f $_.ScriptName, $_.Line, $_.Message, $_.RuleName }
            Write-Host ("  WARN  {0} analyzer issue(s) found (showing first 25):" -f $result.Count)
            Write-Host ($top -join "`n")
            if ($FailOnAnalyzer) {
                throw ("PSScriptAnalyzer found {0} issue(s)." -f $result.Count)
            }
        } else {
            Write-Host "  OK  No analyzer warnings/errors."
        }
    } else {
        Write-Host "  SKIP  Invoke-ScriptAnalyzer not installed."
    }
} catch {
    throw
}

Write-Step "Done"
