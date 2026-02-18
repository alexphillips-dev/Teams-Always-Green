Set-StrictMode -Version Latest

# Date/time formatting helpers shared across the app.
# This is dot-sourced from the main script so $script:* variables live in app script scope.

if (-not (Get-Variable -Name DateTimeFormatDefault -Scope Script -ErrorAction SilentlyContinue)) {
    $script:DateTimeFormatDefault = "yyyy-MM-dd HH:mm:ss"
}
if (-not (Get-Variable -Name DateTimeFormat -Scope Script -ErrorAction SilentlyContinue)) {
    $script:DateTimeFormat = $script:DateTimeFormatDefault
}
if (-not (Get-Variable -Name UseSystemDateTimeFormat -Scope Script -ErrorAction SilentlyContinue)) {
    $script:UseSystemDateTimeFormat = $true
}
if (-not (Get-Variable -Name SystemDateTimeFormatMode -Scope Script -ErrorAction SilentlyContinue)) {
    $script:SystemDateTimeFormatMode = "Short"
}

function Normalize-DateTimeFormat([string]$format) {
    if ([string]::IsNullOrWhiteSpace($format)) { return $script:DateTimeFormatDefault }
    try {
        [DateTime]::Now.ToString($format) | Out-Null
        return $format
    } catch {
        return $script:DateTimeFormatDefault
    }
}

function Format-DateTime($value) {
    if ($null -eq $value) { return "N/A" }
    if ($script:UseSystemDateTimeFormat) {
        $systemFormat = if ($script:SystemDateTimeFormatMode -eq "Long") { "F" } else { "g" }
        try {
            return ([DateTime]$value).ToString($systemFormat)
        } catch {
            return [string]$value
        }
    }
    $format = Normalize-DateTimeFormat $script:DateTimeFormat
    try {
        return ([DateTime]$value).ToString($format)
    } catch {
        return [string]$value
    }
}

