@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul || (echo Python launcher not found.& pause & exit /b 1)
if not exist .venv\Scripts\python.exe (echo Virtual environment missing. Run START_HUNTWEAVE.bat first.& pause & exit /b 1)
.venv\Scripts\python.exe -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto fail
.venv\Scripts\python.exe -m unittest discover -s tests -v
if errorlevel 1 goto fail
echo.
echo Test run completed successfully.
pause
exit /b 0
:fail
echo Check failed. Review the first error above.
pause
exit /b 1
