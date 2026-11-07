@echo off
rem Drag and drop images or folders onto this file to redact them.
"%~dp0.venv\Scripts\python.exe" "%~dp0redact.py" --report %*
pause
