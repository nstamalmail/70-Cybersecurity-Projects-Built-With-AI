@echo off
echo ========================================
echo Windows Event Log Correlator - Build Script
echo ========================================
echo.

where pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo Building Windows Event Log Correlator...
pyinstaller --onefile --windowed --name "EventLogCorrelator" ^
    --icon=NUL ^
    --clean ^
    app.py

echo.
if %errorlevel% equ 0 (
    echo Build successful!
    echo Executable: dist\EventLogCorrelator.exe
) else (
    echo Build failed. Check errors above.
)
echo.
pause
