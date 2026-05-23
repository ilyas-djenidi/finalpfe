@echo off
setlocal
echo [CyBrain] Stopping server on port 5000...
for /f "tokens=5" %%P in ('netstat -ano ^| findstr :5000 ^| findstr LISTENING') do (
  echo [CyBrain] Killing PID %%P
  taskkill /PID %%P /F >nul 2>nul
)
echo [CyBrain] Done.
endlocal
