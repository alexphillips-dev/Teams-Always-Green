' Teams Always Green.VBS
' Launches the main script hidden (no console window).

Option Explicit

Dim shell, scriptDir, scriptPath, cmd
Set shell = CreateObject("WScript.Shell")

scriptDir = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\") - 1)
scriptPath = scriptDir & "\Teams Always Green.ps1"

cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & scriptPath & """"
shell.Run cmd, 0, False
