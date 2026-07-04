@echo off
cd /d "%~dp0"
py main.py
if %errorlevel% neq 0 (
    echo.
    echo Error: Make sure Python is installed and dependencies are set up.
    echo Run setup.bat first if you haven't already.
    pause
)
