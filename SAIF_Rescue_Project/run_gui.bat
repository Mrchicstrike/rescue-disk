@echo off
title HIKMA Rescue Engine
cd /d "%~dp0"
echo Launching HIKMA Rescue GUI Desktop Window...
if exist ".venv\Scripts\python.exe" (
	start "" ".\.venv\Scripts\python.exe" "main.py"
	exit /b
)

where py >nul 2>&1
if errorlevel 1 (
	echo Python 3 was not found. Install Python 3, then run setup_windows.bat.
	pause
	exit /b 1
)

py -3 -c "import psutil, tkinter" >nul 2>&1
if errorlevel 1 (
	echo HIKMA dependencies are missing. Run setup_windows.bat first.
	pause
	exit /b 1
)

py -3 "main.py"



