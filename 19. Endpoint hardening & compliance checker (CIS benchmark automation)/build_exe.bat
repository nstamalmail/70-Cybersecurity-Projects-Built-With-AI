@echo off
echo ============================================
echo CIS Benchmark Compliance Checker - Build
echo ============================================
echo.

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Please install Python 3.10+
    pause
    exit /b 1
)

REM Install dependencies
echo [1/3] Installing dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

REM Build with PyInstaller
echo.
echo [2/3] Building executable...
pyinstaller ^
    --onefile ^
    --windowed ^
    --name "CIS_Compliance_Checker" ^
    --icon=NONE ^
    --add-data "sample_data;sample_data" ^
    --hidden-import=PySide6.QtWidgets ^
    --hidden-import=PySide6.QtCore ^
    --hidden-import=PySide6.QtGui ^
    main_app.py

if %errorlevel% neq 0 (
    echo ERROR: Build failed
    pause
    exit /b 1
)

echo.
echo [3/3] Build complete!
echo.
echo Output: dist\CIS_Compliance_Checker.exe
echo.
echo The executable is portable and includes sample data.
echo Run it on any Windows system without Python installed.
echo.
pause
