Set-StrictMode -Version Latest

function Test-HasProperty {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $Object) { return $false }
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    try {
        return ($Object.PSObject.Properties.Name -contains $Name)
    } catch {
        return $false
    }
}

function Get-PropertyValue {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        $Default = $null
    )
    if (-not (Test-HasProperty $Object $Name)) { return $Default }
    try { return $Object.$Name } catch { return $Default }
}

function Set-PropertyValue {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        $Value
    )
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) { return }
    try {
        if (-not (Test-HasProperty $Object $Name)) {
            $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value -Force
        } else {
            $Object.$Name = $Value
        }
    } catch {
        try { $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value -Force } catch { $null = $_ }
    }
}

function Get-SettingBool {
    param($Settings, [string]$Name, [bool]$Default = $false)
    $value = Get-PropertyValue $Settings $Name $Default
    try { return [bool]$value } catch { return $Default }
}

function Get-SettingInt {
    param($Settings, [string]$Name, [int]$Default = 0, [int]$Min = [int]::MinValue, [int]$Max = [int]::MaxValue)
    $value = Get-PropertyValue $Settings $Name $Default
    try {
        $i = [int]$value
        if ($i -lt $Min) { return $Min }
        if ($i -gt $Max) { return $Max }
        return $i
    } catch {
        return $Default
    }
}

function Get-SettingString {
    param($Settings, [string]$Name, [string]$Default = "")
    $value = Get-PropertyValue $Settings $Name $Default
    if ($null -eq $value) { return $Default }
    return [string]$value
}

function Write-AtomicTextFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [AllowNull()]
        [string]$Content = "",
        [ValidateSet("UTF8", "ASCII")]
        [string]$Encoding = "UTF8",
        [switch]$VerifyJson
    )

    $targetPath = [System.IO.Path]::GetFullPath($Path)
    $targetDir = Split-Path -Path $targetPath -Parent
    if ([string]::IsNullOrWhiteSpace($targetDir)) {
        throw "Atomic write target directory could not be resolved for path: $Path"
    }
    if (-not (Test-Path -LiteralPath $targetDir -PathType Container)) {
        [System.IO.Directory]::CreateDirectory($targetDir) | Out-Null
    }

    $fileName = [System.IO.Path]::GetFileName($targetPath)
    $tempPath = Join-Path $targetDir ("{0}.tmp.{1}" -f $fileName, [guid]::NewGuid().ToString("N"))
    $textEncoding = if ($Encoding -eq "ASCII") {
        [System.Text.Encoding]::ASCII
    } else {
        New-Object System.Text.UTF8Encoding($false)
    }

    try {
        $stream = [System.IO.File]::Open($tempPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $writer = New-Object System.IO.StreamWriter($stream, $textEncoding)
            try {
                $writer.Write([string]$Content)
                $writer.Flush()
                $stream.Flush($true)
            } finally {
                $writer.Dispose()
            }
        } finally {
            $stream.Dispose()
        }

        if ($VerifyJson) {
            $jsonText = [System.IO.File]::ReadAllText($tempPath, $textEncoding)
            $null = $jsonText | ConvertFrom-Json -ErrorAction Stop
        }

        if (Test-Path -LiteralPath $targetPath -PathType Leaf) {
            try {
                [System.IO.File]::Replace($tempPath, $targetPath, $null, $true)
            } catch {
                Move-Item -LiteralPath $tempPath -Destination $targetPath -Force
            }
        } else {
            Move-Item -LiteralPath $tempPath -Destination $targetPath -Force
        }
    } finally {
        if (Test-Path -LiteralPath $tempPath -PathType Leaf) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}
