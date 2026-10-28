@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher was not found. Install Python 3.11 or newer and enable PATH.
  pause
  exit /b 1
)
if not exist .venv\Scripts\python.exe (
  echo Creating isolated Python environment...
  py -3 -m venv .venv
  if errorlevel 1 goto fail
)
call .venv\Scripts\python.exe -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto fail
start "HuntWeave server" /D "%~dp0" "%~dp0.venv\Scripts\python.exe" "%~dp0app.py"
timeout /t 2 /nobreak >nul
start "" http://127.0.0.1:5055
exit /b 0
:fail
echo Startup failed. Review the message above and run CHECK_HUNTWEAVE.bat.
pause
exit /b 1
