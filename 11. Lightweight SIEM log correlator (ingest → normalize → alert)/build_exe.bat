@echo off
REM Build a portable single-file Windows executable with PyInstaller.
REM Result: dist\SIEMCorrelator.exe
cd /d "%~dp0"
python -m PyInstaller --noconfirm --clean --onefile --windowed --name SIEMCorrelator main.py
echo.
echo Build complete: dist\SIEMCorrelator.exe
pause