@echo off
setlocal

set "QS_CHANNEL=%TAG_QUICKSETUP_CHANNEL%"
if not defined QS_CHANNEL set "QS_CHANNEL=main"
if /I "%QS_CHANNEL%" NEQ "main" if /I "%QS_CHANNEL%" NEQ "dev" set "QS_CHANNEL=main"

if /I "%QS_CHANNEL%"=="main" (
  for /f "delims=" %%B in ('git -C "%~dp0..\.." rev-parse --abbrev-ref HEAD 2^>nul') do (
    if /I "%%B"=="dev" set "QS_CHANNEL=dev"
  )
)

set "TAG_QUICKSETUP_CHANNEL=%QS_CHANNEL%"
set "QS_URL=https://raw.githubusercontent.com/alexphillips-dev/Teams-Always-Green/refs/heads/%QS_CHANNEL%/Script/QuickSetup/QuickSetup.ps1?ts=%RANDOM%%RANDOM%"
set "QS_PATH=%TEMP%\TeamsAlwaysGreen-QuickSetup.ps1"
powershell.exe -NoProfile -Command "try { [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12 } catch {} ; Invoke-WebRequest -UseBasicParsing -Uri '%QS_URL%' -OutFile '%QS_PATH%' ; try { Unblock-File -Path '%QS_PATH%' -ErrorAction SilentlyContinue } catch {}"
if not exist "%QS_PATH%" (
  echo Failed to download QuickSetup.ps1
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "%QS_PATH%"
endlocal
