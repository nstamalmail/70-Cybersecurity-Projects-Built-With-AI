@echo off
echo Building Ransomware Tabletop Simulator + IR Runbook Builder...
echo.

REM Check PyInstaller
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo Building executable...
pyinstaller --onefile --windowed --name "RansomwareSimulator" --icon=NONE app.py

echo.
if exist dist\RansomwareSimulator.exe (
    echo Build successful!
    echo Output: dist\RansomwareSimulator.exe
) else (
    echo Build failed. Check errors above.
)
pause
