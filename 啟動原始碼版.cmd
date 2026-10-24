@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 integrity_guard.py gui
) else (
    python integrity_guard.py gui
)
if errorlevel 1 pause
