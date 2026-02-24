param(
    [switch]$Ci,
    [switch]$FailOnWarnings,
    [string]$WarningBudgetFile = "",
    [int]$WarningBudget = -1,
    [string]$CoverageConfigFile = "",
    [double]$MinCoveragePercent = -1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$analyzerSettings = Join-Path $repoRoot "PSScriptAnalyzerSettings.psd1"
$manifestScript = Join-Path $repoRoot "Tools/Generate-QuickSetupManifest.ps1"
$privacyScanScript = Join-Path $repoRoot "Tools/Find-PrivacyLeaks.ps1"
$verifyScript = Join-Path $repoRoot "Tools/Verify.ps1"
$pesterToolsTests = Join-Path $repoRoot "Tools/Quality.Tests.ps1"
$pesterRepoTests = Join-Path $repoRoot "Tests"
$defaultWarningBudgetPath = Join-Path $repoRoot "Tools/PSScriptAnalyzer.warning-budget.json"
$defaultCoverageConfigPath = Join-Path $repoRoot "Tools/Pester.coverage.json"
$versionPath = Join-Path $repoRoot "VERSION"
$changelogPath = Join-Path $repoRoot "CHANGELOG.md"

Write-Host "== Quality checks starting =="
Write-Host "RepoRoot: $repoRoot"

if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    throw "PSScriptAnalyzer module is not installed."
}
if (-not (Get-Module -ListAvailable -Name Pester)) {
    throw "Pester module is not installed."
}

if (Test-Path -LiteralPath $verifyScript -PathType Leaf) {
    Write-Host "Running parse verification..."
    & $verifyScript -SkipAnalyzer
}

Write-Host "Checking VERSION and changelog..."
if (-not (Test-Path $versionPath)) {
    throw "VERSION file is missing."
}
$version = (Get-Content -Path $versionPath -Raw).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') {
    throw "VERSION is not semantic versioning (major.minor.patch): '$version'"
}
if (-not (Test-Path $changelogPath)) {
    throw "CHANGELOG.md is missing."
}
$changelog = Get-Content -Path $changelogPath -Raw
if ($changelog -notmatch '(?im)^##\s*\[Unreleased\]') {
    throw "CHANGELOG.md is missing an [Unreleased] section."
}
$versionPattern = ("(?im)^##\s*\[?{0}\]?" -f [regex]::Escape($version))
if ($changelog -notmatch $versionPattern) {
    throw "CHANGELOG.md is missing an entry for VERSION '$version'."
}

Write-Host "Running privacy/security leak scan..."
& $privacyScanScript -AllTracked

$analyzePaths = @(
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
    $effectiveWarningBudget = $WarningBudget
    $budgetSource = ""
    $resolvedWarningBudgetPath = ""
    if ([string]::IsNullOrWhiteSpace($WarningBudgetFile)) {
        if (Test-Path -LiteralPath $defaultWarningBudgetPath -PathType Leaf) {
            $resolvedWarningBudgetPath = $defaultWarningBudgetPath
        }
    } else {
        $resolvedWarningBudgetPath = if ([System.IO.Path]::IsPathRooted($WarningBudgetFile)) {
            $WarningBudgetFile
        } else {
            Join-Path $repoRoot $WarningBudgetFile
        }
    }
    if ($resolvedWarningBudgetPath -and (Test-Path -LiteralPath $resolvedWarningBudgetPath -PathType Leaf)) {
        try {
            $warningBudgetConfig = Get-Content -Path $resolvedWarningBudgetPath -Raw | ConvertFrom-Json
            if ($warningBudgetConfig -and $warningBudgetConfig.PSObject.Properties.Name -contains "maxWarnings") {
                $effectiveWarningBudget = [int]$warningBudgetConfig.maxWarnings
                $budgetSource = $resolvedWarningBudgetPath
            }
        } catch {
            throw ("Failed to load warning budget file '{0}': {1}" -f $resolvedWarningBudgetPath, $_.Exception.Message)
        }
    }
    if ($FailOnWarnings) {
        $warningIssues | Select-Object RuleName, Severity, ScriptPath, Line, Message | Format-Table -AutoSize | Out-String | Write-Host
        throw "PSScriptAnalyzer warnings are configured to fail this run."
    }
    if ($effectiveWarningBudget -ge 0) {
        $budgetLabel = if ([string]::IsNullOrWhiteSpace($budgetSource)) { "command-line budget" } else { "budget file" }
        Write-Host ("PSScriptAnalyzer warning budget ({0}): {1}" -f $budgetLabel, $effectiveWarningBudget)
        if ($warningIssues.Count -gt $effectiveWarningBudget) {
            $warningIssues | Select-Object RuleName, Severity, ScriptPath, Line, Message | Format-Table -AutoSize | Out-String | Write-Host
            throw ("PSScriptAnalyzer warning budget exceeded: {0} > {1}" -f $warningIssues.Count, $effectiveWarningBudget)
        }
    }
}

Write-Host "Checking QuickSetup manifest freshness..."
& $manifestScript -RepoRoot $repoRoot -Check -RequireSignature -ManifestPublicKeyPath "Meta/Keys/quicksetup-manifest-public.xml"

Write-Host "Running Pester tests..."
$pesterPaths = @()
if (Test-Path -LiteralPath $pesterToolsTests -PathType Leaf) { $pesterPaths += $pesterToolsTests }
if (Test-Path -LiteralPath $pesterRepoTests -PathType Container) { $pesterPaths += $pesterRepoTests }
if ($pesterPaths.Count -eq 0) { throw "No Pester test paths found." }
$effectiveMinCoveragePercent = $MinCoveragePercent
$coveragePaths = @()
$resolvedCoverageConfigPath = ""
if ([string]::IsNullOrWhiteSpace($CoverageConfigFile)) {
    if (Test-Path -LiteralPath $defaultCoverageConfigPath -PathType Leaf) {
        $resolvedCoverageConfigPath = $defaultCoverageConfigPath
    }
} else {
    $resolvedCoverageConfigPath = if ([System.IO.Path]::IsPathRooted($CoverageConfigFile)) {
        $CoverageConfigFile
    } else {
        Join-Path $repoRoot $CoverageConfigFile
    }
}
if ($resolvedCoverageConfigPath -and (Test-Path -LiteralPath $resolvedCoverageConfigPath -PathType Leaf)) {
    try {
        $coverageConfig = Get-Content -Path $resolvedCoverageConfigPath -Raw | ConvertFrom-Json
        if ($coverageConfig -and $coverageConfig.PSObject.Properties.Name -contains "minCoveragePercent" -and $MinCoveragePercent -lt 0) {
            $effectiveMinCoveragePercent = [double]$coverageConfig.minCoveragePercent
        }
        if ($coverageConfig -and $coverageConfig.PSObject.Properties.Name -contains "paths" -and $coverageConfig.paths) {
            foreach ($candidate in @($coverageConfig.paths)) {
                $pathText = [string]$candidate
                if ([string]::IsNullOrWhiteSpace($pathText)) { continue }
                if ([System.IO.Path]::IsPathRooted($pathText)) {
                    $coveragePaths += $pathText
                } else {
                    $coveragePaths += (Join-Path $repoRoot $pathText)
                }
            }
        }
    } catch {
        throw ("Failed to load coverage config file '{0}': {1}" -f $resolvedCoverageConfigPath, $_.Exception.Message)
    }
}

if ($coveragePaths.Count -gt 0 -or $effectiveMinCoveragePercent -ge 0) {
    if (-not (Get-Command -Name New-PesterConfiguration -ErrorAction SilentlyContinue)) {
        throw "New-PesterConfiguration is required for coverage gating but is not available."
    }
    $pesterConfig = New-PesterConfiguration
    $pesterConfig.Run.Path = $pesterPaths
    $pesterConfig.Run.PassThru = $true
    $pesterConfig.Output.Verbosity = "Detailed"
    if ($coveragePaths.Count -gt 0) {
        $pesterConfig.CodeCoverage.Enabled = $true
        $pesterConfig.CodeCoverage.Path = $coveragePaths
    }
    $pesterResult = Invoke-Pester -Configuration $pesterConfig
} else {
    $pesterResult = Invoke-Pester -Path $pesterPaths -PassThru -Output Detailed
}
if ($pesterResult.FailedCount -gt 0) {
    throw "Pester reported $($pesterResult.FailedCount) failing test(s)."
}
if ($effectiveMinCoveragePercent -ge 0) {
    if (-not $pesterResult.CodeCoverage -or $null -eq $pesterResult.CodeCoverage.CoveragePercent) {
        throw "Coverage gate requested but Pester did not return coverage metrics."
    }
    $coveragePercent = [double]$pesterResult.CodeCoverage.CoveragePercent
    Write-Host ("Pester code coverage: {0:N2}%" -f $coveragePercent)
    if ($coveragePercent -lt $effectiveMinCoveragePercent) {
        throw ("Pester coverage gate failed: {0:N2}% < {1:N2}%" -f $coveragePercent, $effectiveMinCoveragePercent)
    }
}

Write-Host "== Quality checks passed =="
