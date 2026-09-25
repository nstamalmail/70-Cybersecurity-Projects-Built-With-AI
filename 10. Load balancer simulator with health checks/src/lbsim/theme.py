"""Shared dark theme constants for LBSim (Load Balancer Simulator)."""

# Palette
BG        = "#1b1e27"
PANEL     = "#232838"
PANEL_ALT = "#2a3045"
ACCENT    = "#4f8cff"
ACCENT_DIM= "#6fa8ff"
TEXT      = "#e6eaf2"
MUTED     = "#9aa4bd"
GREEN     = "#39d98a"
RED       = "#ff5c5c"
ORANGE    = "#ffb648"

QSS = f"""
QWidget {{ background: {BG}; color: {TEXT}; font-family: 'Segoe UI'; font-size: 13px; }}
QGroupBox {{
    background: {PANEL}; border: 1px solid {PANEL_ALT}; border-radius: 8px;
    margin-top: 12px; padding-top: 8px; font-weight: bold;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; color: {ACCENT_DIM}; }}
QLabel {{ background: transparent; }}
QPushButton {{
    background: {ACCENT}; color: white; border: none; border-radius: 6px;
    padding: 7px 14px; font-weight: bold;
}}
QPushButton:hover {{ background: {ACCENT_DIM}; }}
QPushButton:disabled {{ background: {PANEL_ALT}; color: {MUTED}; }}
QPushButton#danger {{ background: {RED}; }}
QPushButton#ok {{ background: {GREEN}; color: #10241a; }}
QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {{
    background: {PANEL_ALT}; border: 1px solid {ACCENT_DIM}; border-radius: 5px; padding: 5px;
    selection-background-color: {ACCENT};
}}
QTableWidget {{
    background: {PANEL}; alternate-background-color: {PANEL_ALT};
    gridline-color: {PANEL_ALT}; border: 1px solid {PANEL_ALT}; border-radius: 6px;
}}
QHeaderView::section {{
    background: {PANEL_ALT}; color: {ACCENT_DIM}; border: none;
    padding: 6px; font-weight: bold;
}}
QTabWidget::pane {{ border: 1px solid {PANEL_ALT}; border-radius: 6px; background: {PANEL}; }}
QTabBar::tab {{
    background: {BG}; color: {MUTED}; padding: 8px 18px; margin-right: 2px;
    border-top-left-radius: 6px; border-top-right-radius: 6px;
}}
QTabBar::tab:selected {{ background: {PANEL}; color: {ACCENT_DIM}; font-weight: bold; }}
QTextEdit, QPlainTextEdit {{
    background: {PANEL}; border: 1px solid {PANEL_ALT}; border-radius: 6px;
    color: {TEXT}; font-family: Consolas, monospace;
}}
QProgressBar {{
    background: {PANEL_ALT}; border: none; border-radius: 4px; height: 14px;
    text-align: center; color: {TEXT};
}}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 4px; }}
QMenuBar {{ background: {PANEL}; color: {TEXT}; }}
QMenuBar::item:selected {{ background: {ACCENT}; }}
QMenu {{ background: {PANEL}; border: 1px solid {PANEL_ALT}; }}
QMenu::item:selected {{ background: {ACCENT}; }}
QStatusBar {{ background: {PANEL}; color: {MUTED}; }}
QCheckBox::indicator, QRadioButton::indicator {{ width: 15px; height: 15px; }}
QScrollBar:vertical {{ background: {BG}; width: 10px; }}
QScrollBar::handle:vertical {{ background: {PANEL_ALT}; border-radius: 5px; min-height: 24px; }}
"""
