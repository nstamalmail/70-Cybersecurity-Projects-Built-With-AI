@echo off
echo ==========================================
echo  SOC Alert Triage Dashboard - Build Script
echo ==========================================
echo.

REM Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH.
    pause
    exit /b 1
)

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies.
    pause
    exit /b 1
)

echo.
echo Building executable with PyInstaller...
pyinstaller --noconfirm ^
    --onefile ^
    --windowed ^
    --name "SOC_Triage_Dashboard" ^
    --add-data "sample_data;sample_data" ^
    --hidden-import PySide6.QtWidgets ^
    --hidden-import PySide6.QtCore ^
    --hidden-import PySide6.QtGui ^
    --hidden-import PySide6.QtPrintSupport ^
    main_app.py

if errorlevel 1 (
    echo ERROR: Build failed.
    pause
    exit /b 1
)

echo.
echo ==========================================
echo  Build complete!
echo  Output: dist\SOC_Triage_Dashboard.exe
echo ==========================================
echo.
pause
