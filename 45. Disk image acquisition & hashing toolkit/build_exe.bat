@echo off
REM FAHT-GUI Build Script
REM Builds portable executable using PyInstaller

echo ========================================
echo Building FAHT-GUI Portable Executable
echo ========================================

REM Check if PyInstaller is installed
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

REM Build executable
pyinstaller --onefile --windowed --name "FAHT-GUI" --clean app.py

echo.
echo Build complete! Check dist\FAHT-GUI.exe
pause
