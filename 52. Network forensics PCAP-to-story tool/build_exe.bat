@echo off
echo Building Network Forensics PCAP-to-Story Tool...
echo.

REM Check PyInstaller
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo Building executable...
pyinstaller --onefile --windowed --name "NetworkForensicsPCAP" --icon=NONE app.py

echo.
if exist dist\NetworkForensicsPCAP.exe (
    echo Build successful!
    echo Output: dist\NetworkForensicsPCAP.exe
) else (
    echo Build failed. Check errors above.
)
pause
