@echo off
REM Build the portable WazuhRulePackBuilder.exe
REM Requires: Python 3.10+ and PyInstaller (pip install pyinstaller)
setlocal
cd /d "%~dp0"

python -m PyInstaller --noconfirm --clean WazuhRulePackBuilder.spec
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

echo.
echo Built: dist\WazuhRulePackBuilder.exe
echo Copy that single file to any Windows 10/11 x64 machine - no Python needed.
endlocal