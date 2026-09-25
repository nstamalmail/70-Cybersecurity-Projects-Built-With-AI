@echo off
echo Building Mobile Device Forensics Workflow...
echo.

REM Check PyInstaller
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo Building executable...
pyinstaller --onefile --windowed --name "MobileForensicsWorkflow" --icon=NONE app.py

echo.
if exist dist\MobileForensicsWorkflow.exe (
    echo Build successful!
    echo Output: dist\MobileForensicsWorkflow.exe
) else (
    echo Build failed. Check errors above.
)
pause
