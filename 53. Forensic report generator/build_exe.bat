@echo off
echo Building Forensic Report Generator...
echo.

REM Check PyInstaller
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo Building executable...
pyinstaller --onefile --windowed --name "ForensicReportGenerator" --icon=NONE app.py

echo.
if exist dist\ForensicReportGenerator.exe (
    echo Build successful!
    echo Output: dist\ForensicReportGenerator.exe
) else (
    echo Build failed. Check errors above.
)
pause
