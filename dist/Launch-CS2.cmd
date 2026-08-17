@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Launch-CS2.ps1" %*
if errorlevel 1 (
    echo.
    pause
)
