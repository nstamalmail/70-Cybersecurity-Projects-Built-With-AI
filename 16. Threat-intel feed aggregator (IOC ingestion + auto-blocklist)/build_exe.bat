@echo off
echo ========================================
echo  Threat-Intel Feed Aggregator Builder
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt
pip install pyinstaller
echo.

REM Build executable
echo Building executable...
pyinstaller --onefile --windowed --name "ThreatIntelAggregator" main_app.py
echo.

REM Check if build was successful
if exist "dist\ThreatIntelAggregator.exe" (
    echo ========================================
    echo  BUILD SUCCESSFUL!
    echo  Output: dist\ThreatIntelAggregator.exe
    echo ========================================
) else (
    echo ========================================
    echo  BUILD FAILED!
    echo  Check the output above for errors.
    echo ========================================
)

pause
