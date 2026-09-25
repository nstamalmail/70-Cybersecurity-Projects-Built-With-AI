@echo off
echo ============================================
echo  Honeypot Fingerprinting GUI - Build Script
echo ============================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.10+
    pause
    exit /b 1
)

REM Install dependencies
echo [1/3] Installing dependencies...
pip install -r requirements.txt pyinstaller --quiet
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

REM Build executable
echo [2/3] Building executable...
pyinstaller --onefile --windowed --name "HoneypotGUI" --clean --noconfirm main_app.py
if errorlevel 1 (
    echo ERROR: Build failed
    pause
    exit /b 1
)

REM Copy sample data
echo [3/3] Copying sample data...
mkdir dist\sample_data 2>nul
copy sample_data\*.json dist\sample_data\ >nul 2>&1

echo.
echo ============================================
echo  Build complete!
echo  Executable: dist\HoneypotGUI.exe
echo ============================================
pause
