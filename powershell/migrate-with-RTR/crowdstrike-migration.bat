@echo off
setlocal

REM ==========================================================
REM CrowdStrike Sensor Migration - Silent Launcher (v1.0)
REM This script automates the migration of a CrowdStrike sensor
REM to a new tenant using a PowerShell script. It handles
REM self-elevation, script download, and silent execution.
REM ==========================================================

:: -- 0) Self-elevate to Administrator (UAC) --
net session >NUL 2>&1
if %errorlevel% NEQ 0 (
  echo [INFO] Requesting administrator rights...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

:: -- 1) Setup working folder and parameters --
set "WORKDIR=%SystemDrive%\CSMigrate"
set "SCRIPT=%WORKDIR%\falcon_windows_migrate.ps1"
set "TRANSCRIPT=%WORKDIR%\cs_migrate_transcript.txt"

:: >>> EDIT THESE VALUES ONLY <<<
set "NEW_CLIENT_ID=xxxxxxxxxxxxxx"
set "NEW_CLIENT_SECRET=xxxxxxxxxxxxxx"
set "OLD_CLIENT_ID=xxxxxxxxxxxxxx"
set "OLD_CLIENT_SECRET=xxxxxxxxxxxxxx"
set "NEW_CLOUD=us-2"
set "OLD_CLOUD=us-2"
set "FALCON_TAGS=YOURTAG"
:: >>> STOP EDITING <<<

if not exist "%WORKDIR%" mkdir "%WORKDIR%" >NUL 2>&1

:: -- 2) Ensure the migration script exists (download if missing) --
if not exist "%SCRIPT%" (
  echo [INFO] Downloading the CrowdStrike migration script...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.8.0/powershell/migrate/falcon_windows_migrate.ps1' -OutFile '%SCRIPT%'"
  if %errorlevel% NEQ 0 (
    echo [ERROR] Failed to download the migrate script. Check internet/proxy and retry.
    endlocal
    exit /b 1
  )
)

:: -- 3) Unblock the script --
echo [INFO] Unblocking the script to allow execution...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Unblock-File -Path '%SCRIPT%'" >NUL 2>&1

:: -- 4) Run the migration silently in the background --
echo [INFO] Starting the migration process...
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Try { Start-Transcript -Path '%TRANSCRIPT%' -Append -ErrorAction SilentlyContinue } Catch {} ; & '%SCRIPT%' -NewFalconClientId '%NEW_CLIENT_ID%' -NewFalconClientSecret '%NEW_CLIENT_SECRET%' -OldFalconClientId '%OLD_CLIENT_ID%' -OldFalconClientSecret '%OLD_CLIENT_SECRET%' -NewFalconCloud '%NEW_CLOUD%' -OldFalconCloud '%OLD_CLOUD%' -ProvToken '%PROV_TOKEN%' -Tags '%FALCON_TAGS%' ; Try { Stop-Transcript } Catch {}"

echo [SUCCESS] The CrowdStrike migration script has been launched in the background. Check '%TRANSCRIPT%' for details.
endlocal
exit /b 0
