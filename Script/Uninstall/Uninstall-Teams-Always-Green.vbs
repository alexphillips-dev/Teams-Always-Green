Option Explicit

Dim shell, fso
Dim vbsPath, uninstallDir, scriptDir, installRoot, uninstallPs1
Dim tempDir, launcherLog, psPath, cmd, rc, runnerPs1
Dim ts

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

vbsPath = WScript.ScriptFullName
uninstallDir = fso.GetParentFolderName(vbsPath)
scriptDir = fso.GetParentFolderName(uninstallDir)
installRoot = fso.GetParentFolderName(scriptDir)
uninstallPs1 = fso.BuildPath(uninstallDir, "Uninstall-Teams-Always-Green.ps1")

tempDir = shell.ExpandEnvironmentStrings("%TEMP%")
launcherLog = fso.BuildPath(tempDir, "TeamsAlwaysGreen-UninstallLauncher.log")

Sub WriteLog(message)
    On Error Resume Next
    Set ts = fso.OpenTextFile(launcherLog, 8, True)
    ts.WriteLine "[" & Now & "] " & message
    ts.Close
    Set ts = Nothing
    On Error GoTo 0
End Sub

Function ResolvePowerShellPath()
    Dim sysRoot, candidate
    sysRoot = shell.ExpandEnvironmentStrings("%SystemRoot%")

    candidate = fso.BuildPath(sysRoot, "System32\WindowsPowerShell\v1.0\powershell.exe")
    If fso.FileExists(candidate) Then
        ResolvePowerShellPath = candidate
        Exit Function
    End If

    candidate = fso.BuildPath(sysRoot, "Sysnative\WindowsPowerShell\v1.0\powershell.exe")
    If fso.FileExists(candidate) Then
        ResolvePowerShellPath = candidate
        Exit Function
    End If

    ResolvePowerShellPath = "powershell.exe"
End Function

If Not fso.FileExists(uninstallPs1) Then
    MsgBox "Uninstall script not found:" & vbCrLf & uninstallPs1, vbCritical, "Uninstall launcher error"
    WScript.Quit 1
End If

psPath = ResolvePowerShellPath()
Randomize
runnerPs1 = fso.BuildPath(tempDir, "TAG-UninstallRunner-" & CStr(Int(Timer * 1000)) & "-" & CStr(Int((Rnd * 1000000) + 1)) & ".ps1")

On Error Resume Next
fso.CopyFile uninstallPs1, runnerPs1, True
If Err.Number <> 0 Then
    WriteLog "Launcher failed to stage runner: " & Err.Description
    MsgBox "Unable to stage uninstall runner." & vbCrLf & vbCrLf & "Log:" & vbCrLf & launcherLog, vbCritical, "Uninstall launcher error"
    WScript.Quit 1
End If
On Error GoTo 0

cmd = """" & psPath & """ -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & runnerPs1 & """ -Relaunched -InstallRoot """ & installRoot & """ -HideConsole"

WriteLog "Launcher started. Version=4"
WriteLog "PowerShell path: " & psPath
WriteLog "Install root: " & installRoot
WriteLog "Runner path: " & runnerPs1
WriteLog "Command: " & cmd

On Error Resume Next
rc = shell.Run(cmd, 0, True)
If Err.Number <> 0 Then
    WriteLog "Launcher failed: " & Err.Description
    MsgBox "Unable to start uninstall." & vbCrLf & vbCrLf & "Log:" & vbCrLf & launcherLog, vbCritical, "Uninstall launcher error"
    WScript.Quit 1
End If
WriteLog "Launcher exit code: " & rc
If rc <> 0 Then
    MsgBox "Uninstall failed to start (exit code " & rc & ")." & vbCrLf & vbCrLf & "Log:" & vbCrLf & launcherLog, vbCritical, "Uninstall launcher error"
    WScript.Quit rc
End If
On Error GoTo 0
