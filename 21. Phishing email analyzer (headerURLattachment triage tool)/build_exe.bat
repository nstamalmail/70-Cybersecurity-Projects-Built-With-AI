@echo off
echo ============================================
echo   Phishing Email Analyzer - Build Script
echo ============================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.10+.
    pause
    exit /b 1
)

REM Install dependencies
echo [1/3] Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

REM Build with PyInstaller
echo [2/3] Building executable...
pyinstaller ^
    --onefile ^
    --windowed ^
    --name "PhishingEmailAnalyzer" ^
    --add-data "sample_data;sample_data" ^
    --clean ^
    main_app.py

if errorlevel 1 (
    echo [ERROR] Build failed.
    pause
    exit /b 1
)

echo [3/3] Build complete!
echo.
echo Executable: dist\PhishingEmailAnalyzer.exe
echo.
pause
