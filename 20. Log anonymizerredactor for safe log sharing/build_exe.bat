@echo off
echo ========================================
echo  Log Anonymizer/Redactor - Build Script
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Check if PyInstaller is installed
pyinstaller --version >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

REM Check if requirements are installed
echo Installing requirements...
pip install -r requirements.txt

echo.
echo Building executable...
echo.

pyinstaller ^
    --onefile ^
    --windowed ^
    --name "LogAnonymizer" ^
    --icon=NONE ^
    --add-data "sample_data;sample_data" ^
    --hidden-import PySide6 ^
    --hidden-import PySide6.QtWidgets ^
    --hidden-import PySide6.QtCore ^
    --hidden-import PySide6.QtGui ^
    main_app.py

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo ========================================
echo  Build successful!
echo  Output: dist\LogAnonymizer.exe
echo ========================================
echo.
pause
