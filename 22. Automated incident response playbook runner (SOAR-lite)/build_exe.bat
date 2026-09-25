@echo off
echo ========================================
echo Building SOAR-lite Executable
echo ========================================
echo.

echo Step 1: Installing dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Error installing dependencies!
    pause
    exit /b 1
)

echo Step 2: Building executable with PyInstaller...
pyinstaller --onefile --windowed --name "SOAR-Lite" ^
    --icon=NONE ^
    --add-data "sample_data;sample_data" ^
    --hidden-import=PySide6.QtWidgets ^
    --hidden-import=PySide6.QtCore ^
    --hidden-import=PySide6.QtGui ^
    --noconfirm ^
    main_app.py

if %errorlevel% neq 0 (
    echo Error building executable!
    pause
    exit /b 1
)

echo.
echo ========================================
echo Build complete! 
echo Executable located at: dist\SOAR-Lite.exe
echo ========================================
pause
