@echo off
setlocal
rem Zero-install wrapper: runs the class carver via the wmi.py launcher.
set "LAUNCHER=%~dp0..\wmi.py"

set "PY312=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if exist "%PY312%" (
  "%PY312%" "%LAUNCHER%" carve %*
  exit /b %ERRORLEVEL%
)

where py >nul 2>nul
if not errorlevel 1 (
  py -3 "%LAUNCHER%" carve %*
  exit /b %ERRORLEVEL%
)

echo Python 3 not found. Run: python "%LAUNCHER%" carve ...
exit /b 1
