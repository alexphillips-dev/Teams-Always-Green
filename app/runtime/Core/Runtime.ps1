Set-StrictMode -Version Latest

function Convert-BootLogLineToStageTiming {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Line
    )

    if ($Line -match 'Boot:\s+(.+?)\s+\+(\d+)ms') {
        return [pscustomobject]@{
            Stage = $Matches[1]
            ElapsedMs = [int64]$Matches[2]
        }
    }
    return $null
}

function Get-DefaultStartupBudgetsMs {
    return [ordered]@{
        "Settings ready" = 2500
        "Crash state handled" = 3500
        "Tray menu loaded" = 4500
        "UI modules loaded" = 5000
        "Tray icon created" = 5500
        "Hotkeys registered" = 6000
        "Startup complete" = 6500
        "Deferred startup done" = 8500
        "Folder check done" = 10000
    }
}

function Test-StartupStageBudget {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Stage,
        [Parameter(Mandatory = $true)]
        [int64]$ElapsedMs,
        [hashtable]$Budgets
    )

    if (-not $Budgets) {
        $Budgets = Get-DefaultStartupBudgetsMs
    }

    $budgetMs = $null
    foreach ($key in $Budgets.Keys) {
        if ([string]::Equals([string]$key, [string]$Stage, [System.StringComparison]::OrdinalIgnoreCase)) {
            $budgetMs = [int64]$Budgets[$key]
            break
        }
    }

    $hasBudget = $null -ne $budgetMs
    $withinBudget = if ($hasBudget) { $ElapsedMs -le $budgetMs } else { $true }
    $delta = if ($hasBudget) { $ElapsedMs - $budgetMs } else { 0 }

    return [pscustomobject]@{
        Stage = $Stage
        StageKey = $Stage.ToLowerInvariant()
        ElapsedMs = $ElapsedMs
        HasBudget = $hasBudget
        BudgetMs = if ($hasBudget) { $budgetMs } else { $null }
        WithinBudget = $withinBudget
        DeltaMs = $delta
    }
}

function Get-StartupBudgetSummaryText {
    param(
        [hashtable]$Durations,
        [hashtable]$Budgets
    )

    if (-not $Durations -or $Durations.Count -eq 0) { return "" }
    if (-not $Budgets) { $Budgets = Get-DefaultStartupBudgetsMs }

    $parts = @()
    foreach ($key in $Budgets.Keys) {
        $hit = $null
        foreach ($stage in $Durations.Keys) {
            if ([string]::Equals([string]$stage, [string]$key, [System.StringComparison]::OrdinalIgnoreCase)) {
                $hit = [int64]$Durations[$stage]
                break
            }
        }
        if ($null -ne $hit) {
            $parts += ("{0}={1}/{2}ms" -f $key, $hit, [int64]$Budgets[$key])
        }
    }
    return ($parts -join "; ")
}

function Test-ModuleFunctionContract {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleTag,
        [hashtable]$FunctionMap,
        [string[]]$RequiredFunctions
    )

    if (-not $FunctionMap) { $FunctionMap = @{} }
    if (-not $RequiredFunctions) { $RequiredFunctions = @() }

    $missing = @()
    foreach ($name in $RequiredFunctions) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if (-not $FunctionMap.ContainsKey($name) -or -not $FunctionMap[$name]) {
            $missing += $name
        }
    }

    return [pscustomobject]@{
        ModuleTag = $ModuleTag
        IsValid = ($missing.Count -eq 0)
        MissingFunctions = $missing
    }
}
