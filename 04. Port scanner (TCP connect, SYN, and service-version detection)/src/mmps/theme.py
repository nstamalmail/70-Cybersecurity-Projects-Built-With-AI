"""Shared dark theme constants for MMPS (Multi-Mode Port Scanner)."""

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

STYLESHEET = f"""
QWidget {{
    background-color: {BACKGROUND};
    color: {TEXT};
    font-size: 13px;
}}
QMainWindow, QDialog {{ background-color: {BACKGROUND}; }}
QGroupBox {{
    border: 1px solid {BORDER};
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 10px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: {ACCENT};
}}
QPushButton {{
    background-color: {PANEL_ALT};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 6px 14px;
    min-height: 22px;
}}
QPushButton:hover {{ border-color: {ACCENT}; }}
QPushButton:pressed {{ background-color: {ACCENT_DIM}; }}
QPushButton:disabled {{ color: {TEXT_DIM}; border-color: {BORDER}; }}
QPushButton#primary {{
    background-color: {ACCENT};
    border: none;
    font-weight: bold;
}}
QPushButton#primary:hover {{ background-color: #6699ff; }}
QPushButton#danger {{ background-color: {RED}; border: none; font-weight: bold; }}
QLineEdit, QSpinBox, QComboBox, QPlainTextEdit {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 4px 6px;
    selection-background-color: {ACCENT_DIM};
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{ border-color: {ACCENT}; }}
QTableWidget {{
    background-color: {PANEL};
    alternate-background-color: {PANEL_ALT};
    gridline-color: {BORDER};
    border: 1px solid {BORDER};
    border-radius: 4px;
}}
QHeaderView::section {{
    background-color: {PANEL_ALT};
    border: none;
    border-bottom: 2px solid {BORDER};
    padding: 6px;
    font-weight: bold;
}}
QProgressBar {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 4px;
    text-align: center;
    height: 18px;
}}
QProgressBar::chunk {{
    background-color: {ACCENT};
    border-radius: 3px;
}}
QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 4px; }}
QTabBar::tab {{
    background: {PANEL};
    border: 1px solid {BORDER};
    border-bottom: none;
    padding: 7px 18px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}}
QTabBar::tab:selected {{ background: {PANEL_ALT}; color: {ACCENT}; font-weight: bold; }}
QTextBrowser, QListWidget, QTreeWidget {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 4px;
}}
QLabel#dim {{ color: {TEXT_DIM}; }}
QLabel#banner {{
    font-size: 17px;
    font-weight: bold;
    color: {ACCENT};
    padding: 4px;
}}
QLabel#mono {{ font-family: 'Consolas', monospace; }}
QPlainTextEdit#console {{
    font-family: 'Consolas', monospace;
    font-size: 12px;
    background-color: #0d1017;
}}
QStatusBar {{ background: {PANEL}; border-top: 1px solid {BORDER}; }}
QCheckBox::indicator, QRadioButton::indicator {{ width: 15px; height: 15px; }}
QScrollBar:vertical {{
    background: {PANEL}; width: 10px; border-radius: 5px;
}}
QScrollBar::handle:vertical {{ background: {GRAY}; border-radius: 5px; min-height: 25px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
"""
