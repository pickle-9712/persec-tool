@echo off
rem Stops the live overlay from starting automatically at login.
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\opsec-tool live redaction.lnk" 2>nul
echo Removed from startup.
pause
