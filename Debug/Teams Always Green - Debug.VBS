' Teams Always Green - Debug.VBS
' Launches the main script hidden and captures output to a debug log file.

Option Explicit

Dim shell, scriptDir, scriptPath, logPath, cmd
Set shell = CreateObject("WScript.Shell")

scriptDir = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\") - 1)
' Runtime entry script sits under app\runtime
scriptPath = Left(scriptDir, InStrRev(scriptDir, "\") - 1) & "\app\runtime\Teams Always Green.ps1"
logPath = scriptDir & "\Teams Always Green.debug.vbs.log"

cmd = "cmd /c ""powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -WindowStyle Hidden -File """ & scriptPath & """ >> """ & logPath & """ 2>&1"""
shell.Run cmd, 0, False

