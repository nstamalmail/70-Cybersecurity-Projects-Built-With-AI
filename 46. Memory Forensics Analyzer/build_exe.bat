@echo off
echo ========================================
echo Memory Forensics Analyzer - Build Script
echo ========================================
echo.

where pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo Building Memory Forensics Analyzer...
pyinstaller --onefile --windowed --name "MemoryForensicsAnalyzer" ^
    --icon=NUL ^
    --add-data "*.md;." ^
    --clean ^
    app.py

echo.
if %errorlevel% equ 0 (
    echo Build successful!
    echo Executable: dist\MemoryForensicsAnalyzer.exe
) else (
    echo Build failed. Check errors above.
)
echo.
pause
