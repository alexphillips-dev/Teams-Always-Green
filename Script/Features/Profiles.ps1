# --- Profiles module (profile runtime helpers) ---

function Get-ProfilesModuleVersion {
    return "1.0.0"
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
