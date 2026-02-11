Set-StrictMode -Version Latest

BeforeAll {
    $script:repoRoot = Split-Path -Parent $PSScriptRoot
    $script:mainScript = Join-Path $script:repoRoot "Script/Teams Always Green.ps1"
    $script:settingsDialogScript = Join-Path $script:repoRoot "Script/UI/SettingsDialog.ps1"
    $script:historyDialogScript = Join-Path $script:repoRoot "Script/UI/HistoryDialog.ps1"
    $script:mainText = Get-Content -Raw -Path $script:mainScript
}

Describe "Quality: Script Parse" {
    It "main script parses without syntax errors" {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script:mainScript, [ref]$tokens, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It "UI scripts parse without syntax errors" {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script:settingsDialogScript, [ref]$tokens, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty

        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script:historyDialogScript, [ref]$tokens, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }
}

Describe "Quality: Critical Features" {
    It "supports SettingsOnly startup mode" {
        $script:mainText | Should -Match '\[switch\]\$SettingsOnly'
    }

    It "contains critical tray actions" {
        $script:mainText | Should -Match 'ToolStripMenuItem\("History"\)'
        $script:mainText | Should -Match 'ToolStripMenuItem\("Restart"\)'
        $script:mainText | Should -Match 'ToolStripMenuItem\("Exit"\)'
    }

    It "contains core toggle lifecycle functions" {
        $script:mainText | Should -Match 'function\s+Do-Toggle'
        $script:mainText | Should -Match 'function\s+Start-Toggling'
        $script:mainText | Should -Match 'function\s+Stop-Toggling'
    }
}
