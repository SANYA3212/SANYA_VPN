@echo off
REM SANYA-VPN Client Launcher
REM This script activates the virtual environment (if it exists)
REM and launches the main Python client application.

ECHO Starting SANYA-VPN Client...

REM Check for a virtual environment in a 'venv' subdirectory
IF EXIST .\\venv\\Scripts\\activate.bat (
    ECHO Activating virtual environment...
    CALL .\\venv\\Scripts\\activate.bat
) ELSE (
    ECHO No virtual environment ('venv') found. Running with system Python.
    ECHO For best results, please run install_venv.bat first.
)

REM Launch the client application
ECHO Launching GUI...
python .\\client\\client_vpn_setup.py

ECHO SANYA-VPN client closed.
pause
