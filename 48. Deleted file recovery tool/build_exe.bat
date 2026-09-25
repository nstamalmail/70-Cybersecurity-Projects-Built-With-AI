@echo off
echo ========================================
echo Deleted File Recovery Tool - Build Script
echo ========================================
echo.

where pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo Building Deleted File Recovery Tool...
pyinstaller --onefile --windowed --name "DeletedFileRecovery" ^
    --icon=NUL ^
    --clean ^
    app.py

echo.
if %errorlevel% equ 0 (
    echo Build successful!
    echo Executable: dist\DeletedFileRecovery.exe
) else (
    echo Build failed. Check errors above.
)
echo.
pause
