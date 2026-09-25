"""Shared dark theme constants for NTAM (topology mapper)."""
BACKGROUND = "#12151c"
PANEL = "#1a1f2b"
PANEL_ALT = "#202636"
BORDER = "#2c3446"
TEXT = "#e6e9f0"
TEXT_DIM = "#8b93a7"
ACCENT = "#4f8cff"
ACCENT_DIM = "#2a5db0"
GREEN = "#2ecc71"
RED = "#e74c3c"
ORANGE = "#f39c12"
YELLOW = "#f1c40f"
GRAY = "#5d6470"

STYLESHEET = """
QWidget { background-color: #12151c; color: #e6e9f0; font-size: 13px; }
QMainWindow, QDialog { background-color: #12151c; }
QGroupBox { border: 1px solid #2c3446; border-radius: 6px; margin-top: 12px; padding-top: 10px; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: #4f8cff; }
QPushButton { background-color: #202636; border: 1px solid #2c3446; border-radius: 4px;
              padding: 6px 14px; min-height: 22px; }
QPushButton:hover { border-color: #4f8cff; }
QPushButton:pressed { background-color: #2a5db0; }
QPushButton:disabled { color: #8b93a7; border-color: #2c3446; }
QPushButton#primary { background-color: #4f8cff; border: none; font-weight: bold; }
QPushButton#primary:hover { background-color: #6699ff; }
QLineEdit, QSpinBox, QComboBox, QCheckBox, QPlainTextEdit { background-color: #1a1f2b;
    border: 1px solid #2c3446; border-radius: 4px; padding: 4px 6px; }
QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border-color: #4f8cff; }
QTableWidget { background-color: #1a1f2b; alternate-background-color: #202636;
    gridline-color: #2c3446; border: 1px solid #2c3446; border-radius: 4px; }
QHeaderView::section { background-color: #202636; border: none;
    border-bottom: 2px solid #2c3446; padding: 6px; font-weight: bold; }
QTabWidget::pane { border: 1px solid #2c3446; border-radius: 4px; }
QTabBar::tab { background: #1a1f2b; border: 1px solid #2c3446; border-bottom: none;
    padding: 7px 18px; margin-right: 2px; border-top-left-radius: 4px; border-top-right-radius: 4px; }
QTabBar::tab:selected { background: #202636; color: #4f8cff; font-weight: bold; }
QTextBrowser, QListWidget { background-color: #1a1f2b; border: 1px solid #2c3446; border-radius: 4px; }
QLabel#dim { color: #8b93a7; }
QLabel#banner { font-size: 17px; font-weight: bold; color: #4f8cff; padding: 4px; }
QPlainTextEdit#console { font-family: 'Consolas', monospace; font-size: 12px; background-color: #0d1017; }
QStatusBar { background: #1a1f2b; border-top: 1px solid #2c3446; }
QScrollBar:vertical { background: #1a1f2b; width: 10px; border-radius: 5px; }
QScrollBar::handle:vertical { background: #5d6470; border-radius: 5px; min-height: 25px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
"""
