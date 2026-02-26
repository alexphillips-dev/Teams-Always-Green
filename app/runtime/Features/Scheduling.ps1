# --- Scheduling module (weekday parsing + runtime schedule state) ---

function Get-SchedulingModuleVersion {
    return "1.0.0"
}

function Get-ScheduleWeekdaySet([string]$text) {
    if ($script:ScheduleWeekdayCacheText -eq $text -and $script:ScheduleWeekdayCacheSet) {
        return $script:ScheduleWeekdayCacheSet
    }
    if ([string]::IsNullOrWhiteSpace($text)) { return @() }
    $map = @{
        "MON" = [DayOfWeek]::Monday
        "TUE" = [DayOfWeek]::Tuesday
        "WED" = [DayOfWeek]::Wednesday
        "THU" = [DayOfWeek]::Thursday
        "FRI" = [DayOfWeek]::Friday
        "SAT" = [DayOfWeek]::Saturday
        "SUN" = [DayOfWeek]::Sunday
    }
    $set = @()
    foreach ($part in ($text -split "[,; ]+" | Where-Object { $_ -ne "" })) {
        $key = $part.ToUpperInvariant().Substring(0, [Math]::Min(3, $part.Length))
        if ($map.ContainsKey($key)) { $set += $map[$key] }
    }
    $set = $set | Sort-Object -Unique
    $script:ScheduleWeekdayCacheText = $text
    $script:ScheduleWeekdayCacheSet = $set
    return $set
}

function Get-ScheduleSuspendUntil {
    $raw = [string]$settings.ScheduleSuspendUntil
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    try {
        return [DateTime]::Parse($raw)
    } catch {
        return $null
    }
}

function Is-WithinSchedule {
    if (-not [bool]$settings.ScheduleEnabled) { return $true }
    $days = Get-ScheduleWeekdaySet $settings.ScheduleWeekdays
    if ($days.Count -gt 0 -and -not ($days -contains (Get-Date).DayOfWeek)) { return $false }
    $cacheKey = "{0}|{1}" -f $settings.ScheduleStart, $settings.ScheduleEnd
    if ($script:ScheduleTimeCacheKey -ne $cacheKey) {
        $start = [TimeSpan]::Zero
        $end = [TimeSpan]::Zero
        if (-not (Try-ParseTime $settings.ScheduleStart ([ref]$start))) { return $true }
        if (-not (Try-ParseTime $settings.ScheduleEnd ([ref]$end))) { return $true }
        $script:ScheduleStartCache = $start
        $script:ScheduleEndCache = $end
        $script:ScheduleTimeCacheKey = $cacheKey
    }
    $start = $script:ScheduleStartCache
    $end = $script:ScheduleEndCache
    $now = (Get-Date).TimeOfDay
    if ($start -le $end) {
        return ($now -ge $start -and $now -le $end)
    }
    return ($now -ge $start -or $now -le $end)
}

function Update-ScheduleBlock {
    $script:isScheduleSuspended = $false
    if ([bool]$settings.ScheduleEnabled) {
        $suspendUntil = Get-ScheduleSuspendUntil
        if ($suspendUntil -and $suspendUntil -gt (Get-Date)) {
            $script:isScheduleBlocked = $true
            $script:isScheduleSuspended = $true
            if (-not $script:LastScheduleSuspended) {
                Write-Log "SCHED: Schedule suspended until $(Format-DateTime $suspendUntil)." "INFO" $null "Schedule"
                Log-StateSummary "Schedule"
            }
            $script:LastScheduleSuspended = $true
            $script:LastScheduleBlocked = $true
            return $true
        }
    }
    if ($script:LastScheduleSuspended) {
        Write-Log "SCHED: Schedule suspension ended." "INFO" $null "Schedule"
        $script:LastScheduleSuspended = $false
        Log-StateSummary "Schedule"
    }
    $script:isScheduleBlocked = [bool]$settings.ScheduleEnabled -and -not (Is-WithinSchedule)
    if ($script:LastScheduleBlocked -ne $script:isScheduleBlocked) {
        $blockedText = if ($script:isScheduleBlocked) { "blocked (outside schedule)." } else { "unblocked (inside schedule)." }
        Write-Log "SCHED: Schedule $blockedText" "INFO" $null "Schedule"
        Log-StateSummary "Schedule"
    }
    $script:LastScheduleBlocked = $script:isScheduleBlocked
    return $script:isScheduleBlocked
}

function Format-ScheduleStatus {
    $key = "{0}|{1}|{2}|{3}|{4}|{5}" -f $settings.ScheduleEnabled, $settings.ScheduleStart, $settings.ScheduleEnd, $settings.ScheduleWeekdays, $settings.ScheduleSuspendUntil, $script:isScheduleSuspended
    if ($script:ScheduleStatusCacheKey -eq $key -and $script:ScheduleStatusCacheValue) {
        return $script:ScheduleStatusCacheValue
    }
    $value = "Off"
    if ([bool]$settings.ScheduleEnabled) {
        if ($script:isScheduleSuspended) {
            $suspendUntil = Get-ScheduleSuspendUntil
            $suspendText = Format-TimeOrNever $suspendUntil $false
            $value = "Suspended until $suspendText"
        } else {
            $value = "On ($($settings.ScheduleStart)-$($settings.ScheduleEnd) $($settings.ScheduleWeekdays))"
        }
    }
    $script:ScheduleStatusCacheKey = $key
    $script:ScheduleStatusCacheValue = $value
    return $value
}
