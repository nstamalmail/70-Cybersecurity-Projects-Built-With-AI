@echo off
echo ========================================
echo Browser Artifact Extractor - Build Script
echo ========================================
echo.

where pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo Building Browser Artifact Extractor...
pyinstaller --onefile --windowed --name "BrowserArtifactExtractor" ^
    --icon=NUL ^
    --clean ^
    app.py

echo.
if %errorlevel% equ 0 (
    echo Build successful!
    echo Executable: dist\BrowserArtifactExtractor.exe
) else (
    echo Build failed. Check errors above.
)
echo.
pause
