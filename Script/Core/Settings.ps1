Set-StrictMode -Version Latest

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
