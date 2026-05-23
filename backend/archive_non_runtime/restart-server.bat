@echo off
setlocal
cd /d "%~dp0"
call .\stop-server.bat
call .\start-server.bat
endlocal
