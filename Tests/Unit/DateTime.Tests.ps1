Set-StrictMode -Version Latest

Describe "Core: DateTime helpers" {
    BeforeAll {
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
        . (Join-Path $repoRoot "app/runtime/Core/DateTime.ps1")
    }

    It "Normalize-DateTimeFormat falls back to default on empty input" {
        Normalize-DateTimeFormat "" | Should -Be $script:DateTimeFormatDefault
        Normalize-DateTimeFormat $null | Should -Be $script:DateTimeFormatDefault
    }

    It "Normalize-DateTimeFormat falls back to default on invalid format" {
        Normalize-DateTimeFormat "%" | Should -Be $script:DateTimeFormatDefault
    }

    It "Format-DateTime returns N/A for null values" {
        Format-DateTime $null | Should -Be "N/A"
    }

    It "Format-DateTime uses custom format when system format is disabled" {
        $script:UseSystemDateTimeFormat = $false
        $script:DateTimeFormat = "yyyy"
        Format-DateTime ([datetime]"2026-02-17T12:00:00") | Should -Be "2026"
    }

    It "Format-DateTime uses system format without throwing" {
        $script:UseSystemDateTimeFormat = $true
        $script:SystemDateTimeFormatMode = "Short"
        $text = Format-DateTime ([datetime]"2026-02-17T12:00:00")
        [string]::IsNullOrWhiteSpace($text) | Should -BeFalse
    }
}

