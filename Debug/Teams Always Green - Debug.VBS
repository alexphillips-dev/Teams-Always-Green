' Teams Always Green - Debug.VBS
' Robust debug launcher with startup diagnostics and output capture.

Option Explicit

Const LOG_MAX_BYTES = 2097152 ' 2 MB

Dim shell, fso
Dim scriptFile, debugDir, appRoot, mainScriptPath, logPath, powershellPath
Dim cmd, argsText

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

scriptFile = WScript.ScriptFullName
debugDir = GetParentPath(scriptFile)
appRoot = GetParentPath(debugDir)
mainScriptPath = appRoot & "\app\runtime\Teams Always Green.ps1"
logPath = debugDir & "\Teams Always Green.debug.vbs.log"

RotateLogIfNeeded logPath, LOG_MAX_BYTES
WriteLogLine logPath, "=== Debug launcher started ==="
WriteLogLine logPath, "Launcher: " & scriptFile
WriteLogLine logPath, "App root: " & appRoot
WriteLogLine logPath, "Main script: " & mainScriptPath

If Not fso.FileExists(mainScriptPath) Then
    WriteLogLine logPath, "ERROR: Main script not found."
    MsgBox "Could not find app/runtime/Teams Always Green.ps1." & vbCrLf & vbCrLf & _
           "Expected path:" & vbCrLf & mainScriptPath & vbCrLf & vbCrLf & _
           "Log: " & logPath, vbCritical, "Teams Always Green - Debug"
    WScript.Quit 2
End If

powershellPath = ResolvePowerShellPath()
WriteLogLine logPath, "PowerShell: " & powershellPath

argsText = BuildArgumentString()
If Len(argsText) > 0 Then
    WriteLogLine logPath, "Args: " & argsText
End If

cmd = "cmd /d /c """ & Quote(powershellPath) & _
      " -NoProfile -ExecutionPolicy RemoteSigned -WindowStyle Hidden -File " & Quote(mainScriptPath) & _
      argsText & " 1>>" & Quote(logPath) & " 2>>&1"""

WriteLogLine logPath, "Launch command: " & cmd

On Error Resume Next
shell.Run cmd, 0, False
If Err.Number <> 0 Then
    WriteLogLine logPath, "ERROR: shell.Run failed (" & CStr(Err.Number) & "): " & Err.Description
    MsgBox "Failed to launch Teams Always Green." & vbCrLf & vbCrLf & _
           "Error: " & Err.Description & vbCrLf & vbCrLf & _
           "Log: " & logPath, vbCritical, "Teams Always Green - Debug"
    WScript.Quit 3
End If
On Error GoTo 0

WriteLogLine logPath, "Launcher invoked successfully."

Function GetParentPath(pathText)
    GetParentPath = Left(pathText, InStrRev(pathText, "\") - 1)
End Function

Function ResolvePowerShellPath()
    Dim winDir, sysnative, system32
    winDir = shell.ExpandEnvironmentStrings("%WINDIR%")
    system32 = winDir & "\System32\WindowsPowerShell\v1.0\powershell.exe"
    sysnative = winDir & "\Sysnative\WindowsPowerShell\v1.0\powershell.exe"

    If fso.FileExists(system32) Then
        ResolvePowerShellPath = system32
        Exit Function
    End If
    If fso.FileExists(sysnative) Then
        ResolvePowerShellPath = sysnative
        Exit Function
    End If

    ResolvePowerShellPath = "powershell.exe"
End Function

Function BuildArgumentString()
    Dim i, argText, combined
    combined = ""
    For i = 0 To WScript.Arguments.Count - 1
        argText = CStr(WScript.Arguments(i))
        combined = combined & " " & Quote(argText)
    Next
    BuildArgumentString = combined
End Function

Function Quote(textValue)
    Quote = """" & textValue & """"
End Function

Sub WriteLogLine(filePath, messageText)
    Dim stream, lineText
    lineText = "[" & NowIso() & "] " & messageText
    On Error Resume Next
    Set stream = fso.OpenTextFile(filePath, 8, True, 0)
    If Err.Number = 0 Then
        stream.WriteLine lineText
        stream.Close
    End If
    Set stream = Nothing
    On Error GoTo 0
End Sub

Sub RotateLogIfNeeded(filePath, maxBytes)
    Dim fileObj, archivePath
    On Error Resume Next
    If fso.FileExists(filePath) Then
        Set fileObj = fso.GetFile(filePath)
        If Err.Number = 0 Then
            If CLng(fileObj.Size) > CLng(maxBytes) Then
                archivePath = filePath & "." & Replace(Replace(Replace(NowIso(), ":", ""), "-", ""), "T", "-") & ".bak"
                fso.MoveFile filePath, archivePath
            End If
        End If
    End If
    Set fileObj = Nothing
    On Error GoTo 0
End Sub

Function NowIso()
    Dim d
    d = Now
    NowIso = Year(d) & "-" & Pad2(Month(d)) & "-" & Pad2(Day(d)) & "T" & _
             Pad2(Hour(d)) & ":" & Pad2(Minute(d)) & ":" & Pad2(Second(d))
End Function

Function Pad2(num)
    Pad2 = Right("0" & CStr(num), 2)
End Function

