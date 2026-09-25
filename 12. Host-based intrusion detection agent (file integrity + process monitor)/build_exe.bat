@echo off
REM ============================================================
REM  SentinelHIDS portable build (PyInstaller one-file, windowed)
REM  Output: dist\SentinelHIDS.exe
REM ============================================================
setlocal
cd /d "%~dp0"

python -m pip install --quiet --upgrade pyinstaller psutil || goto :err

python -m PyInstaller --noconfirm --clean --onefile --windowed ^
  --name SentinelHIDS ^
  --hidden-import psutil ^
  --collect-submodules hids ^
  --collect-submodules watchdog ^
  run.py || goto :err

echo.
echo [OK] Portable agent built: dist\SentinelHIDS.exe
echo      Run it from any folder - it creates a sibling "data\" directory.
exit /b 0

:err
echo [ERROR] Build failed. See output above.
exit /b 1
