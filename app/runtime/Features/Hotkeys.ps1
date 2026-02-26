# --- Hotkeys module (parsing + registration lifecycle) ---

function Get-HotkeysModuleVersion {
    return "1.0.0"
}

function Parse-Hotkey([string]$text) {
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $mods = 0
    $keyName = $null
    foreach ($part in ($text -split "\+" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })) {
        switch ($part.ToUpperInvariant()) {
            "CTRL" { $mods = $mods -bor [HotKeyNative]::MOD_CONTROL }
            "CONTROL" { $mods = $mods -bor [HotKeyNative]::MOD_CONTROL }
            "ALT" { $mods = $mods -bor [HotKeyNative]::MOD_ALT }
            "SHIFT" { $mods = $mods -bor [HotKeyNative]::MOD_SHIFT }
            "WIN" { $mods = $mods -bor [HotKeyNative]::MOD_WIN }
            default { $keyName = $part }
        }
    }
    if ([string]::IsNullOrWhiteSpace($keyName)) { return $null }
    try {
        $key = [System.Windows.Forms.Keys]::$keyName
    } catch {
        return $null
    }
    return @{ Modifiers = $mods; Vk = [int]$key }
}

function Validate-HotkeyString([string]$text) {
    if ([string]::IsNullOrWhiteSpace($text)) { return $true }
    return ($null -ne (Parse-Hotkey $text))
}

function Register-Hotkeys {
    if ($script:isShuttingDown) { return }
    Unregister-Hotkeys
    if (-not $script:HotKeyFilterAdded) {
        [System.Windows.Forms.Application]::AddMessageFilter((New-Object HotKeyMessageFilter))
        $script:HotKeyFilterAdded = $true
    }
    [HotKeyMessageFilter]::HotKeyPressed = [System.Action[int]]{
        param($id)
        switch ($id) {
            1001 { Do-Toggle "hotkey" }
            1002 { if ($script:isRunning) { Stop-Toggling } else { Start-Toggling } }
            1003 {
                if ($script:isPaused) {
                    Start-Toggling
                } else {
                    $durations = Get-PauseDurations
                    if ($durations.Count -gt 0) { Pause-Toggling ([int]$durations[0]) }
                }
            }
        }
    }
    $map = @{
        1001 = $settings.HotkeyToggle
        1002 = $settings.HotkeyStartStop
        1003 = $settings.HotkeyPauseResume
    }
    $registered = 0
    $failed = 0
    foreach ($id in $map.Keys) {
        $parsed = Parse-Hotkey $map[$id]
        if ($parsed) {
            $ok = [HotKeyNative]::RegisterHotKey([IntPtr]::Zero, $id, [uint32]$parsed.Modifiers, [uint32]$parsed.Vk)
            if (-not $ok) {
                Write-Log "HOTKEY: Failed to register id=$id value=$($map[$id])." "WARN" $null "Hotkey"
                $failed++
            } else {
                $registered++
            }
        }
    }
    Write-Log "HOTKEY: Registration complete. Registered=$registered Failed=$failed." "INFO" $null "Hotkey"
    if ($failed -gt 0) {
        $script:HotkeyStatusText = "Failed ($failed)"
        if (-not $script:HotkeyWarned -and $notifyIcon) {
            Show-Balloon "Teams-Always-Green" "Some hotkeys failed to register. Open Settings > Hotkeys to adjust." ([System.Windows.Forms.ToolTipIcon]::Warning)
            $script:HotkeyWarned = $true
        }
    } elseif ($registered -gt 0) {
        $script:HotkeyStatusText = "Registered ($registered)"
    } else {
        $script:HotkeyStatusText = "Disabled"
    }
    Write-Log ("Metadata: Hotkeys={0}" -f $script:HotkeyStatusText) "DEBUG" $null "Hotkey"
}

function Unregister-Hotkeys {
    foreach ($id in 1001, 1002, 1003) {
        [HotKeyNative]::UnregisterHotKey([IntPtr]::Zero, $id) | Out-Null
    }
    Write-Log "HOTKEY: Unregistered." "INFO" $null "Hotkey"
    $script:HotkeyStatusText = "Unregistered"
}
