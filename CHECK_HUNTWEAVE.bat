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
.venv\Scripts\python.exe -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto fail
.venv\Scripts\python.exe -m unittest discover -s tests -v
if errorlevel 1 goto fail
echo.
echo All HuntWeave tests passed.
pause
exit /b 0
:fail
echo Check failed. Review the first error above.
pause
exit /b 1
