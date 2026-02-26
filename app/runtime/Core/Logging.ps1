Set-StrictMode -Version Latest

# Logging helpers that do not redefine the main app logger.

function Write-LogOnce {
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Level = "WARN",
        [string]$Context = "General"
    )
    if (-not (Get-Variable -Name LogOnceCache -Scope Script -ErrorAction SilentlyContinue)) {
        $script:LogOnceCache = @{}
    }
    if ($script:LogOnceCache.ContainsKey($Key)) { return }
    $script:LogOnceCache[$Key] = $true
    if (Get-Command -Name Write-Log -ErrorAction SilentlyContinue) {
        Write-Log $Message $Level $null $Context
    }
}

