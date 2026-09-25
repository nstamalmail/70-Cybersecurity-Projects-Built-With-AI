@echo off
REM ============================================================
REM Firewall Rule Auditor - Build Script
REM Creates standalone executable using PyInstaller
REM ============================================================

echo.
echo ============================================================
echo  Firewall Rule Auditor - Build Executable
echo ============================================================
echo.

REM Check Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found in PATH
    echo Please install Python 3.10+ and add to PATH
    pause
    exit /b 1
)

REM Check PyInstaller is installed
python -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
    if errorlevel 1 (
        echo ERROR: Failed to install PyInstaller
        pause
        exit /b 1
    )
)

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo Building executable...
echo This may take 2-5 minutes...
echo.

pyinstaller ^
    --onefile ^
    --windowed ^
    --name "FirewallRuleAuditor" ^
    --add-data "sample_data;sample_data" ^
    --icon NONE ^
    --clean ^
    main_app.py

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  Build Complete!
echo ============================================================
echo.
echo  Executable: dist\FirewallRuleAuditor.exe
echo.
echo  To run: double-click the exe or run from command line
echo.
pause
