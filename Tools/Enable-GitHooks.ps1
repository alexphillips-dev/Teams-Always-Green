Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$hookPath = Join-Path $repoRoot ".githooks"

if (-not (Test-Path -LiteralPath $hookPath -PathType Container)) {
    throw "Hooks folder not found: $hookPath"
}

git -C $repoRoot config core.hooksPath .githooks
Write-Host "Configured git hooks path: .githooks"
