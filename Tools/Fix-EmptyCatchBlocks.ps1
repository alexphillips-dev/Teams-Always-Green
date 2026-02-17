param(
    [Parameter(Mandatory = $false)]
    [string]$Path = "Script\\Teams Always Green.ps1",

    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

function Get-NewlineStyle {
    param([Parameter(Mandatory)] [string]$Text)
    if ($Text -match "`r`n") { return "`r`n" }
    return "`n"
}

$resolved = Resolve-Path -LiteralPath $Path
$raw = Get-Content -LiteralPath $resolved -Raw
$newline = Get-NewlineStyle -Text $raw

$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($raw, [ref]$tokens, [ref]$errors)
if ($errors -and $errors.Count -gt 0) {
    throw ("Parse errors found; refusing to modify file. FirstError={0}" -f $errors[0].Message)
}

$catchAsts = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CatchClauseAst] }, $true)
$targets = @($catchAsts | Where-Object { $_.Body -and $_.Body.Statements.Count -eq 0 })

if ($targets.Count -eq 0) {
    Write-Output "No empty catch blocks found."
    exit 0
}

# Build edits from end-to-start to keep offsets stable.
$edits = @()
foreach ($c in $targets) {
    $body = $c.Body.Extent
    $innerStart = $body.StartOffset + 1
    $innerLen = ($body.EndOffset - 1) - $innerStart
    if ($innerLen -lt 0) { continue }

    $inner = $raw.Substring($innerStart, $innerLen)

    $indent = " " * [Math]::Max(0, ($c.Body.Extent.StartColumnNumber - 1))
    $innerIndent = $indent + "    "

    $replacement = $null

    $hasNewline = ($inner -match "(\r\n|\n)")
    $trimmed = $inner.Trim()

    if (-not $hasNewline -and $trimmed.Length -eq 0) {
        # One-liner: catch { } -> catch { $null = $_ }
        $replacement = " `$null = `$_ "
    } else {
        # Multiline (or comment-only): insert a real statement on its own line so it can't be swallowed by '# ...'.
        $prefix = $inner.TrimEnd()
        if ($prefix.Length -gt 0) {
            $replacement = $prefix + $newline + $innerIndent + "`$null = `$_" + $newline + $indent
        } else {
            $replacement = $newline + $innerIndent + "`$null = `$_" + $newline + $indent
        }
    }

    $edits += [pscustomobject]@{
        Start = $innerStart
        Length = $innerLen
        Replacement = $replacement
    }
}

$edits = $edits | Sort-Object Start -Descending

$new = $raw
foreach ($e in $edits) {
    $new = $new.Remove($e.Start, $e.Length).Insert($e.Start, $e.Replacement)
}

Write-Output ("Empty catch blocks fixed: {0}" -f $edits.Count)

if ($WhatIf) {
    Write-Output "WhatIf set; not writing file."
    exit 0
}

[IO.File]::WriteAllText($resolved, $new, [Text.UTF8Encoding]::new($false))
