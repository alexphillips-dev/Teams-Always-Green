' Teams Always Green - Debug.VBS
' Launches the main script hidden and captures output to a debug log file.

Option Explicit

Dim shell, scriptDir, scriptPath, logPath, cmd
Set shell = CreateObject("WScript.Shell")

scriptDir = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\") - 1)
' Script sits one level up from Debug\
scriptPath = Left(scriptDir, InStrRev(scriptDir, "\") - 1) & "\Teams Always Green.ps1"
logPath = scriptDir & "\Teams Always Green.debug.vbs.log"

cmd = "cmd /c ""powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & scriptPath & """ >> """ & logPath & """ 2>&1"""
shell.Run cmd, 0, False
