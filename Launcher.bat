@echo off
setlocal enabledelayedexpansion

:: ====================================================
:: Check for admin rights
:: ====================================================
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting elevation...
    goto UACPrompt
)
goto Admin

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:Admin
pushd "%CD%"
CD /D "%~dp0"

:: ====================================================
:: PowerShell Script Launcher for VS Telemetry Disable
:: ====================================================
title Visual Studio Telemetry Disable Launcher

:: Set script directory
set "SCRIPT_DIR=%~dp0"

:: Define PowerShell paths
set "PS7_PATH=C:\Program Files\PowerShell\7\pwsh.exe"
set "PS7_PREVIEW_PATH=C:\Program Files\PowerShell\7-preview\pwsh.exe"
set "PS5_PATH=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

:: Initialize variables
set "PS_EXE="
set "PS_SCRIPT="
set "PS_VERSION="

:: Check for PowerShell 7 first (preferred)
if exist "%PS7_PATH%" (
    set "PS_EXE=%PS7_PATH%"
    set "PS_SCRIPT=%SCRIPT_DIR%script\off_telemetry_ps7.ps1"
    set "PS_VERSION=PowerShell 7"
    goto :found_powershell
)

:: Check for PowerShell 7 Preview
if exist "%PS7_PREVIEW_PATH%" (
    set "PS_EXE=%PS7_PREVIEW_PATH%"
    set "PS_SCRIPT=%SCRIPT_DIR%script\off_telemetry_ps7.ps1"
    set "PS_VERSION=PowerShell 7 Preview"
    goto :found_powershell
)

:: Check for PowerShell 5
if exist "%PS5_PATH%" (
    set "PS_EXE=%PS5_PATH%"
    set "PS_SCRIPT=%SCRIPT_DIR%script\off_telemetry_ps5.ps1"
    set "PS_VERSION=PowerShell 5"
    goto :found_powershell
)

:: No PowerShell found
echo [ERROR] No compatible PowerShell version found!
echo.
echo Please install either:
echo  - PowerShell 7 (recommended)
echo  - PowerShell 5 (Windows PowerShell)
echo.
pause
exit /b 1

:found_powershell
:: Check if the corresponding PowerShell script exists
if not exist "%PS_SCRIPT%" (
    echo [ERROR] PowerShell script not found: %PS_SCRIPT%
    echo.
    if "%PS_VERSION%"=="PowerShell 7" (
        echo Make sure off_telemetry_ps7.ps1 is in the 'script' subdirectory.
    ) else if "%PS_VERSION%"=="PowerShell 7 Preview" (
        echo Make sure off_telemetry_ps7.ps1 is in the 'script' subdirectory.
    ) else (
        echo Make sure off_telemetry_ps5.ps1 is in the 'script' subdirectory.
    )
    echo.
    pause
    exit /b 1
)

echo.
echo ====================================================
echo  Visual Studio Telemetry Disable Script Launcher
echo.
echo                by EXLOUD aka BOBER
echo             https://github.com/EXLOUD
echo.
echo ====================================================
echo.
echo Using: %PS_VERSION%
echo Script location: %PS_SCRIPT%
echo.
echo This will disable telemetry for:
echo  - Visual Studio 2015-2022
echo  - Visual Studio Code  
echo  - .NET CLI
echo  - NuGet
echo.

:confirmation
set /p "CONFIRM=Do you want to continue? (Y/N): "
if /i "!CONFIRM!"=="y" goto :proceed
if /i "!CONFIRM!"=="yes" goto :proceed
if /i "!CONFIRM!"=="n" goto :cancel
if /i "!CONFIRM!"=="no" goto :cancel
echo Invalid input. Please enter Y or N.
goto :confirmation

:cancel
echo.
echo Operation cancelled by user.
pause
exit /b 0

:proceed
cls
echo.
echo [INFO] Launching script on %PS_VERSION% ...
echo.

:: Change directory to script location
cd /d "%SCRIPT_DIR%"

:: Launch PowerShell script with execution policy bypass
"%PS_EXE%" -ExecutionPolicy Bypass -NoProfile -File "%PS_SCRIPT%"

:: Check exit code
if %errorLevel% == 0 (
    echo.
    echo [SUCCESS] Script completed successfully!
) else (
    echo.
    echo [ERROR] Script encountered errors. Exit code: %errorLevel%
)

echo.
echo Press any key to exit...
pause >nul
exit /b 0
