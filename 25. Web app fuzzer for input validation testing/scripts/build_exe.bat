@echo off
REM Build a portable single-file Windows exe with PyInstaller.
REM Run from the project root:  scripts\build_exe.bat
setlocal

set PY=python
if exist ".venv\Scripts\python.exe" set PY=.venv\Scripts\python.exe

echo ==^> Installing build deps (dev)
"%PY%" -m pip install -r requirements.txt -r requirements-dev.txt

echo ==^> Running engine self-test before packaging
"%PY%" scripts\selftest.py
if errorlevel 1 (
    echo Self-test FAILED - aborting build.
    exit /b 1
)

echo ==^> Building WebFuzzer.exe (onefile, windowed, samples bundled)
"%PY%" -m PyInstaller --noconfirm --clean ^
    --onefile --windowed --name WebFuzzer ^
    --add-data "%~dp0..\samples;samples" ^
    main.py

echo ==^> Verifying the portable exe headlessly
dist\WebFuzzer.exe --selftest
if errorlevel 1 (
    echo Exe self-test FAILED - see selftest_result.txt
    exit /b 1
)

echo ==^> Done. Portable exe: dist\WebFuzzer.exe
endlocal
