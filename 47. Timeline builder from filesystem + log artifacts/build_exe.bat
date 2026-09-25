@echo off
echo ========================================
echo Timeline Builder - Build Script
echo ========================================
echo.

where pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo Building Timeline Builder...
pyinstaller --onefile --windowed --name "TimelineBuilder" ^
    --icon=NUL ^
    --clean ^
    app.py

echo.
if %errorlevel% equ 0 (
    echo Build successful!
    echo Executable: dist\TimelineBuilder.exe
) else (
    echo Build failed. Check errors above.
)
echo.
pause
