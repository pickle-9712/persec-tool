@echo off
rem Take a screenshot (Win+Shift+S), then double-click this. The clipboard image gets redacted in place.
"%~dp0.venv\Scripts\python.exe" "%~dp0redact.py" --clipboard --report
timeout /t 3 >nul
