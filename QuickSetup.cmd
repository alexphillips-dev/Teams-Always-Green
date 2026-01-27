@echo off
setlocal
set "QS_URL=https://raw.githubusercontent.com/alexphillips-dev/Teams%%20Always%%20Green/main/QuickSetup.ps1"
set "QS_PATH=%TEMP%\TeamsAlwaysGreen-QuickSetup.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "try { [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12 } catch {} ; Invoke-WebRequest -UseBasicParsing -Uri '%QS_URL%' -OutFile '%QS_PATH%'"
if not exist "%QS_PATH%" (
  echo Failed to download QuickSetup.ps1
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%QS_PATH%"
endlocal

