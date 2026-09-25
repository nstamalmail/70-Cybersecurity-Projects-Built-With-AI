@echo off
REM ============================================================
REM  PacketSniffer - portable EXE build script (Windows)
REM  Output: dist\PacketSniffer.exe  (single portable file)
REM ============================================================
setlocal
cd /d "%~dp0"

echo [1/4] Ensuring PyInstaller is available...
python -m pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo      Installing pyinstaller...
    python -m pip install --quiet pyinstaller || goto :fail
)

echo [2/4] Running unit tests first...
python -m unittest discover -s tests 2>&1 | findstr /C:"OK" /C:"FAILED"
echo      (build continues even if you skipped tests)

echo [3/4] Building PacketSniffer.exe with PyInstaller...
python -m PyInstaller sniffer.spec --noconfirm || goto :fail

echo [4/4] Computing SHA256...
set EXE=dist\PacketSniffer.exe
if not exist "%EXE%" goto :fail
powershell -NoProfile -Command "(Get-FileHash '%EXE%' -Algorithm SHA256).Hash" > sha256.txt 2>nul
if exist sha256.txt (
    set /p HASH=<sha256.txt
    echo      SHA256: %HASH%
    del sha256.txt
)

echo.
echo Build OK: %EXE%
echo Distribute the single .exe - no Python install required on the target.
exit /b 0

:fail
echo BUILD FAILED - see output above.
exit /b 1
