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
:: Visual Studio Telemetry Disable Launcher
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
set "SCRIPT_TYPE="

:: ====================================================
:: Find PowerShell Executable
:: ====================================================

if exist "%PS7_PATH%" (
    set "PS_EXE=%PS7_PATH%"
    set "PS_VERSION=PowerShell 7"
    goto :found_powershell
)

if exist "%PS7_PREVIEW_PATH%" (
    set "PS_EXE=%PS7_PREVIEW_PATH%"
    set "PS_VERSION=PowerShell 7 Preview"
    goto :found_powershell
)

if exist "%PS5_PATH%" (
    set "PS_EXE=%PS5_PATH%"
    set "PS_VERSION=PowerShell 5"
    goto :found_powershell
)

echo [ERROR] No compatible PowerShell version found!
echo.
echo Please install either:
echo  - PowerShell 7 (recommended)
echo  - PowerShell 5 (Windows PowerShell)
echo.
pause
exit /b 1

:found_powershell

:: ====================================================
:: Detect Windows Version and PowerShell
:: ====================================================
for /f "tokens=4-5 delims=. " %%i in ('ver') do (
    set "WIN_MAJOR=%%i"
    set "WIN_MINOR=%%j"
)

:: Determine script based on Windows version and PowerShell version
if !WIN_MAJOR! GEQ 10 (
    if "%PS_VERSION%"=="PowerShell 5" (
        set "SCRIPT_BASENAME=off_telemetry_ps5.ps1"
        set "SCRIPT_TYPE=Windows 10/11 - PowerShell 5"
    ) else (
        set "SCRIPT_BASENAME=off_telemetry_ps7.ps1"
        set "SCRIPT_TYPE=Windows 10/11 - PowerShell 7"
    )
) else (
    if "%PS_VERSION%"=="PowerShell 5" (
        set "SCRIPT_BASENAME=off_telemetry_ps5_win7+.ps1"
        set "SCRIPT_TYPE=Windows 7/8/8.1 - PowerShell 5"
    ) else (
        set "SCRIPT_BASENAME=off_telemetry_ps7.ps1"
        set "SCRIPT_TYPE=Windows 7/8/8.1 - PowerShell 7"
    )
)

:: ====================================================
:: Locate Script
:: ====================================================
set "SCRIPT_FOUND="

set "TEST_SCRIPT=%SCRIPT_DIR%!SCRIPT_BASENAME!"
if exist "!TEST_SCRIPT!" (
    set "PS_SCRIPT=!TEST_SCRIPT!"
    set "SCRIPT_FOUND=YES"
    goto :script_found
)

set "TEST_SCRIPT=%SCRIPT_DIR%script\!SCRIPT_BASENAME!"
if exist "!TEST_SCRIPT!" (
    set "PS_SCRIPT=!TEST_SCRIPT!"
    set "SCRIPT_FOUND=YES"
    set "SCRIPT_TYPE=!SCRIPT_TYPE! (from script folder)"
    goto :script_found
)

echo [ERROR] Expected script !SCRIPT_BASENAME! not found!
echo.
echo Please make sure this script exists:
echo  - !SCRIPT_BASENAME!
echo Either in the same folder as this launcher or in the 'script' subfolder.
echo.
pause
exit /b 1

:script_found

:: ====================================================
:: Display Information
:: ====================================================

echo.
echo ====================================================
echo  Visual Studio Telemetry Disable Script Launcher
echo.
echo                     by EXLOUD
echo             https://github.com/EXLOUD
echo ====================================================
echo.
echo System Information:
echo  - PowerShell: %PS_VERSION%
echo  - Script: !SCRIPT_TYPE!
echo  - Location: !PS_SCRIPT!
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
echo [INFO] Launching Visual Studio Telemetry Disabler...
echo [INFO] PowerShell: %PS_VERSION%
echo [INFO] Script: !SCRIPT_TYPE!
echo.

cd /d "%SCRIPT_DIR%"

"%PS_EXE%" -ExecutionPolicy Bypass -NoProfile -File "!PS_SCRIPT!"

if %errorLevel% == 0 (
    echo.
    echo [SUCCESS] Script completed successfully!
    echo.
    echo Visual Studio telemetry settings have been disabled.
    echo Some changes may require restarting Visual Studio.
) else (
    echo.
    echo [ERROR] Script encountered errors. Exit code: %errorLevel%
    echo.
    echo This may happen if:
    echo  - Visual Studio is not installed
    echo  - Administrator rights are required
    echo  - Registry access is restricted
)

echo.
echo Press any key to exit...
pause >nul
exit /b 0
