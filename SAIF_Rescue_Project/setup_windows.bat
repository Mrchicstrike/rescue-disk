@echo off
title HIKMA Windows Setup
cd /d "%~dp0"

where py >nul 2>&1
if errorlevel 1 (
    echo Python 3 was not found. Install Python 3 for Windows, then run this setup again.
    pause
    exit /b 1
)

py -3 -c "import tkinter" >nul 2>&1
if errorlevel 1 (
    echo Python was installed without Tkinter. Reinstall Python 3 with Tcl/Tk support.
    pause
    exit /b 1
)

py -3 -c "import psutil" >nul 2>&1
if errorlevel 1 py -3 -m pip install --user psutil
if errorlevel 1 (
    echo Could not install psutil. Check your internet connection and try again.
    pause
    exit /b 1
)

echo HIKMA is ready. Start it with run_gui.bat.
pause