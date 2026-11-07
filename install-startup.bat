@echo off
rem Makes the live overlay start automatically every time you log in to Windows.
powershell -NoProfile -Command "$s=(New-Object -ComObject WScript.Shell).CreateShortcut([Environment]::GetFolderPath('Startup')+'\opsec-tool live redaction.lnk'); $s.TargetPath='%~dp0.venv\Scripts\pythonw.exe'; $s.Arguments='\"%~dp0live.py\"'; $s.WorkingDirectory='%~dp0'; $s.Save()"
echo Installed: live redaction will start automatically when you log in.
pause
