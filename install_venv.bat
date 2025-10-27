@echo off
REM SANYA-VPN Environment Setup Script
REM This script creates a Python virtual environment.

ECHO =======================================
ECHO SANYA-VPN Environment Setup
ECHO =======================================

REM Check if Python is installed and available in PATH
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO ERROR: Python is not found in your PATH.
    ECHO Please install Python 3 from https://www.python.org/ and ensure it's added to your PATH.
    pause
    exit /b 1
)

ECHO Found Python:
python --version

REM Create the virtual environment in a folder named 'venv'
IF EXIST .\\venv (
    ECHO Virtual environment 'venv' already exists. Skipping creation.
) ELSE (
    ECHO Creating virtual environment in 'venv' folder...
    python -m venv venv
    IF %ERRORLEVEL% NEQ 0 (
        ECHO ERROR: Failed to create the virtual environment.
        pause
        exit /b 1
    )
    ECHO Virtual environment created successfully.
)

ECHO.
ECHO --- Tailscale Check ---
WHERE tailscale.exe >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO WARNING: tailscale.exe not found in your system's PATH.
    ECHO SANYA-VPN requires Tailscale to be installed.
    ECHO Please download and install it from https://tailscale.com/download/windows
) ELSE (
    ECHO Found tailscale.exe.
)

ECHO.
ECHO Setup complete.
ECHO You can now run the client using SANYA-VPN.bat
ECHO.
pause
