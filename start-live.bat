@echo off
rem Starts the always-on screen redaction overlay in the background (no window).
rem Stop it with Ctrl+Alt+F12.
start "" "%~dp0.venv\Scripts\pythonw.exe" "%~dp0live.py"
echo Live redaction starting (takes ~10 seconds to load). Press Ctrl+Alt+F12 to stop it.
timeout /t 4 >nul
