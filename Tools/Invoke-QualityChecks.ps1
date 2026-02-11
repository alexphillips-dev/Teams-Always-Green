param(
    [switch]$Ci,
    [switch]$FailOnWarnings
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$analyzerSettings = Join-Path $repoRoot "PSScriptAnalyzerSettings.psd1"
$manifestScript = Join-Path $repoRoot "Tools/Generate-QuickSetupManifest.ps1"
$pesterTests = Join-Path $repoRoot "Tools/Quality.Tests.ps1"

Write-Host "== Quality checks starting =="
Write-Host "RepoRoot: $repoRoot"

if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    throw "PSScriptAnalyzer module is not installed."
}
if (-not (Get-Module -ListAvailable -Name Pester)) {
    throw "Pester module is not installed."
}

$analyzePaths = @(
    (Join-Path $repoRoot "QuickSetup.ps1"),
    (Join-Path $repoRoot "Script")
)

$analyzerParams = @{
    Recurse = $true
    Severity = @("Information", "Warning", "Error")
}
if (Test-Path $analyzerSettings) {
    $analyzerParams["Settings"] = $analyzerSettings
}

Write-Host "Running PSScriptAnalyzer..."
$issues = @()
foreach ($path in $analyzePaths) {
    $issues += @(Invoke-ScriptAnalyzer -Path $path @analyzerParams)
}
$warningIssues = @($issues | Where-Object { $_.Severity -eq "Warning" })
$errorIssues = @($issues | Where-Object { $_.Severity -eq "Error" })

if ($errorIssues.Count -gt 0) {
    $errorIssues | Select-Object RuleName, Severity, ScriptPath, Line, Message | Format-Table -AutoSize | Out-String | Write-Host
    throw "PSScriptAnalyzer reported $($errorIssues.Count) error(s)."
}

if ($warningIssues.Count -gt 0) {
    Write-Host ("PSScriptAnalyzer warnings: {0}" -f $warningIssues.Count)
    if ($FailOnWarnings) {
        $warningIssues | Select-Object RuleName, Severity, ScriptPath, Line, Message | Format-Table -AutoSize | Out-String | Write-Host
        throw "PSScriptAnalyzer warnings are configured to fail this run."
    }
}

Write-Host "Checking QuickSetup manifest freshness..."
& $manifestScript -RepoRoot $repoRoot -Check

Write-Host "Running Pester tests..."
$pesterResult = Invoke-Pester -Path $pesterTests -PassThru -Output Detailed
if ($pesterResult.FailedCount -gt 0) {
    throw "Pester reported $($pesterResult.FailedCount) failing test(s)."
}

Write-Host "== Quality checks passed =="
