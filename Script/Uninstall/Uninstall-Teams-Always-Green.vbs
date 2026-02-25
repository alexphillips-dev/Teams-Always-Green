Dim shell, fso, vbsPath, uninstallPs1, cmd
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
vbsPath = WScript.ScriptFullName
uninstallPs1 = fso.BuildPath(fso.GetParentFolderName(vbsPath), "Uninstall-Teams-Always-Green.ps1")
cmd = "powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File """ & uninstallPs1 & """"
shell.Run cmd, 1, False
