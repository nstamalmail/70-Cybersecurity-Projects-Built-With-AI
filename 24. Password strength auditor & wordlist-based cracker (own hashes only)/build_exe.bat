@echo off
REM Build the portable one-file HashArmor.exe (Windows).
cd /d "%~dp0"

python -m pip install --quiet "pyinstaller>=6.10,<7"

python -m PyInstaller --noconfirm --clean ^
  --onefile --windowed ^
  --name HashArmor ^
  --add-data "assets\wordlists;assets\wordlists" ^
  --hidden-import tkinter ^
  --hidden-import tkinter.filedialog ^
  --hidden-import tkinter.messagebox ^
  main.py

echo.
echo Build complete -^> dist\HashArmor.exe
