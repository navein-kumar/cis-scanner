@echo off
:: CIS Benchmark Scanner - Launcher
:: CodeSecure Solutions - v2.1
:: Run as Administrator

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

:: Check if custom policy was passed as argument
if "%~1"=="" (
    echo [*] Auto-detecting OS and policy...
    powershell -ExecutionPolicy Bypass -File "cis_scan.ps1"
) else (
    echo [*] Using custom policy: %~1
    powershell -ExecutionPolicy Bypass -File "cis_scan.ps1" -Policy "%~1"
)

exit /b
