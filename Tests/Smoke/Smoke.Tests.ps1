Set-StrictMode -Version Latest

Describe 'Smoke' {
    BeforeAll {
        function Parse-ScriptFile {
            param([Parameter(Mandatory = $true)][string]$Path)

            $tokens = $null
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
            [pscustomobject]@{
                Ast = $ast
                Errors = $errors
            }
        }

        $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
        $script:mainScript = Join-Path $script:repoRoot 'Script/Teams Always Green.ps1'
        $script:settingsDialogScript = Join-Path $script:repoRoot 'Script/UI/SettingsDialog.ps1'
        $script:historyDialogScript = Join-Path $script:repoRoot 'Script/UI/HistoryDialog.ps1'
        $script:mainText = Get-Content -Raw -Path $script:mainScript
    }

    Context 'Startup' {
        It 'main script parses without syntax errors' {
            $parsed = Parse-ScriptFile -Path $script:mainScript
            $parsed.Errors | Should -BeNullOrEmpty
        }

        It 'UI dialog scripts parse without syntax errors' {
            (Parse-ScriptFile -Path $script:settingsDialogScript).Errors | Should -BeNullOrEmpty
            (Parse-ScriptFile -Path $script:historyDialogScript).Errors | Should -BeNullOrEmpty
        }

        It 'supports SettingsOnly startup mode' {
            $script:mainText | Should -Match '\[switch\]\$SettingsOnly'
        }
    }

    Context 'Tray actions' {
        It 'wires required tray actions' {
            $script:mainText | Should -Match 'ToolStripMenuItem\("History"\)'
            $script:mainText | Should -Match 'ToolStripMenuItem\("Restart"\)'
            $script:mainText | Should -Match 'ToolStripMenuItem\("Exit"\)'
        }

        It 'has wrappers for Settings and History UI' {
            $script:mainText | Should -Match 'function\s+Show-SettingsDialog'
            $script:mainText | Should -Match 'function\s+Show-HistoryDialog'
        }
    }

    Context 'Toggle cycle' {
        It 'defines toggle lifecycle functions' {
            $script:mainText | Should -Match 'function\s+Do-Toggle'
            $script:mainText | Should -Match 'function\s+Start-Toggling'
            $script:mainText | Should -Match 'function\s+Stop-Toggling'
        }

        It 'invokes Do-Toggle on timer tick' {
            $script:mainText | Should -Match 'Invoke-SafeTimerAction\s+\"MainToggleTimer\"'
            $script:mainText | Should -Match 'Do-Toggle\s+\"timer\"'
        }
    }

    Context 'Settings and History open path' {
        It 'uses imported UI function map before fallback' {
            $script:mainText | Should -Match 'ImportedUiFunctions\.ContainsKey\(\"Show-SettingsDialog\"\)'
            $script:mainText | Should -Match 'ImportedUiFunctions\.ContainsKey\(\"Show-HistoryDialog\"\)'
        }

        It 'logs missing UI functions after load when contracts are not satisfied' {
            $script:mainText | Should -Match 'Show-SettingsDialog missing after load'
            $script:mainText | Should -Match 'Show-HistoryDialog missing after load'
        }
    }
}
