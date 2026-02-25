Option Explicit

Dim shell, fso
Dim vbsPath, uninstallDir, scriptDir, installRoot, uninstallPs1
Dim tempDir, launcherLog, psPath, cmd
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
cmd = """" & psPath & """ -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & uninstallPs1 & """ -InstallRoot """ & installRoot & """"

WriteLog "Launcher started."
WriteLog "PowerShell path: " & psPath
WriteLog "Install root: " & installRoot
WriteLog "Command: " & cmd

On Error Resume Next
shell.Run cmd, 0, False
If Err.Number <> 0 Then
    WriteLog "Launcher failed: " & Err.Description
    MsgBox "Unable to start uninstall." & vbCrLf & vbCrLf & "Log:" & vbCrLf & launcherLog, vbCritical, "Uninstall launcher error"
    WScript.Quit 1
End If
On Error GoTo 0
