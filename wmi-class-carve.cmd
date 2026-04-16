@echo off
setlocal

set "PY312=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if exist "%PY312%" (
  "%PY312%" -m wmi_forensics.class_carve_cli %*
  exit /b %ERRORLEVEL%
)

where py >nul 2>nul
if not errorlevel 1 (
  py -3 -m wmi_forensics.class_carve_cli %*
  exit /b %ERRORLEVEL%
)

echo Python 3 not found. Run: python -m wmi_forensics.class_carve_cli ...
exit /b 1
