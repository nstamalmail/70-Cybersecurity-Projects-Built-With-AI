"""Dark analyst theme shared by every workbench view."""
from __future__ import annotations

from app.config import APP

COLORS = {
    "bg": "#0e1116",
    "bg_alt": "#151a21",
    "panel": "#171d25",
    "panel_alt": "#1d242e",
    "border": "#262e3a",
    "border_strong": "#37414f",
    "text": "#e6e9ef",
    "text_dim": "#98a2b3",
    "text_faint": "#6b7687",
    "accent": APP.get("accent", "#4da3ff"),
    "ok": "#30a46c",
    "warn": "#f5a524",
    "bad": "#e5484d",
    "info": "#4da3ff",
    "crit": "#c4319a",
}

SEVERITY = {
    "critical": COLORS["bad"],
    "ransomware": COLORS["bad"],
    "malicious": COLORS["bad"],
    "high": COLORS["bad"],
    "medium": COLORS["warn"],
    "suspicious": COLORS["warn"],
    "beacon": COLORS["warn"],
    "low": COLORS["ok"],
    "clean": COLORS["ok"],
    "benign": COLORS["ok"],
    "info": COLORS["text_dim"],
    "unknown": COLORS["text_dim"],
}

CATEGORY_COLORS = {
    "process": "#e5484d",
    "memory": "#f5a524",
    "file": "#30a46c",
    "registry": "#a855f7",
    "network": "#4da3ff",
    "sync": "#8b8d98",
    "system": "#b08968",
    "ui": "#22d3ee",
    "crypto": "#c4319a",
    "persistence": "#f97316",
    "discovery": "#38bdf8",
    "access": "#a3e635",
    "modification": "#f5a524",
    "obfuscation": "#a855f7",
    "destruction": "#e5484d",
    "dns": "#22d3ee",
    "tls": "#818cf8",
}


def color_for(key: str, default: str | None = None) -> str:
    return (
        SEVERITY.get((key or "").lower())
        or CATEGORY_COLORS.get((key or "").lower())
        or default
        or COLORS["text_dim"]
    )


def stylesheet() -> str:
    c = COLORS
    return f"""
* {{ outline: 0; }}
QWidget {{ background: {c['bg']}; color: {c['text']};
           font-family: 'Segoe UI', 'Inter', 'Noto Sans', sans-serif; font-size: 10pt; }}
QMainWindow, QDialog {{ background: {c['bg']}; }}

QTabWidget::pane {{ border: 1px solid {c['border']}; border-radius: 8px; background: {c['panel']};
                    top: -1px; }}
QTabBar::tab {{ background: {c['bg_alt']}; color: {c['text_dim']}; padding: 7px 15px; margin-right: 2px;
                border: 1px solid {c['border']}; border-bottom: none;
                border-top-left-radius: 7px; border-top-right-radius: 7px; }}
QTabBar::tab:selected {{ background: {c['panel']}; color: {c['text']}; border-bottom: 2px solid {c['accent']}; }}
QTabBar::tab:hover:!selected {{ background: {c['panel_alt']}; color: {c['text']}; }}

QGroupBox {{ border: 1px solid {c['border']}; border-radius: 8px; margin-top: 14px; padding: 12px 10px 10px 10px;
             background: {c['panel']}; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 5px; color: {c['text_dim']};
                    font-weight: 600; letter-spacing: .3px; }}

QPushButton {{ background: {c['panel_alt']}; color: {c['text']}; border: 1px solid {c['border_strong']};
               border-radius: 7px; padding: 6px 13px; }}
QPushButton:hover {{ background: #24303d; border-color: {c['accent']}; }}
QPushButton:pressed {{ background: #1b232d; }}
QPushButton:disabled {{ color: {c['text_faint']}; border-color: {c['border']}; background: {c['bg_alt']}; }}
QPushButton[accent="true"] {{ background: {c['accent']}; color: #06121f; border-color: {c['accent']};
                              font-weight: 600; }}
QPushButton[accent="true"]:hover {{ background: #6fb6ff; }}
QPushButton[danger="true"] {{ background: #3a1c1f; border-color: #6b2b30; color: #ff9b9e; }}

QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QPlainTextEdit, QTextEdit {{
    background: {c['bg_alt']}; border: 1px solid {c['border']}; border-radius: 7px;
    padding: 5px 8px; selection-background-color: {c['accent']}; selection-color: #06121f; }}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus {{ border-color: {c['accent']}; }}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox QAbstractItemView {{ background: {c['panel_alt']}; border: 1px solid {c['border']};
                               selection-background-color: {c['accent']}; }}
QCheckBox {{ spacing: 7px; color: {c['text']}; }}
QCheckBox::indicator {{ width: 15px; height: 15px; border-radius: 4px; border: 1px solid {c['border_strong']};
                        background: {c['bg_alt']}; }}
QCheckBox::indicator:checked {{ background: {c['accent']}; border-color: {c['accent']}; }}

QTableWidget, QTableView {{ background: {c['panel']}; alternate-background-color: {c['bg_alt']};
                            gridline-color: {c['border']}; border: 1px solid {c['border']};
                            border-radius: 8px; }}
QTableWidget::item, QTableView::item {{ padding: 3px 5px; }}
QTableWidget::item:selected, QTableView::item:selected {{ background: #1e3a5f; color: {c['text']}; }}
QHeaderView::section {{ background: {c['bg_alt']}; color: {c['text_dim']}; padding: 6px 8px;
                        border: none; border-right: 1px solid {c['border']};
                        border-bottom: 1px solid {c['border']}; font-weight: 600; }}
QTableCornerButton::section {{ background: {c['bg_alt']}; border: none; }}

QTreeWidget, QTreeView, QListWidget, QListView {{ background: {c['panel']}; border: 1px solid {c['border']};
                        border-radius: 8px; alternate-background-color: {c['bg_alt']}; }}
QTreeWidget::item:selected, QListWidget::item:selected {{ background: #1e3a5f; }}

QScrollBar:vertical {{ background: transparent; width: 11px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {c['border_strong']}; border-radius: 5px; min-height: 26px; }}
QScrollBar::handle:vertical:hover {{ background: {c['accent']}; }}
QScrollBar:horizontal {{ background: transparent; height: 11px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {c['border_strong']}; border-radius: 5px; min-width: 26px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

QProgressBar {{ background: {c['bg_alt']}; border: 1px solid {c['border']}; border-radius: 7px;
                text-align: center; color: {c['text']}; height: 16px; }}
QProgressBar::chunk {{ background: {c['accent']}; border-radius: 6px; }}

QStatusBar {{ background: {c['bg_alt']}; color: {c['text_dim']}; border-top: 1px solid {c['border']}; }}
QMenuBar {{ background: {c['bg_alt']}; color: {c['text']}; }}
QMenuBar::item:selected {{ background: {c['panel_alt']}; border-radius: 5px; }}
QMenu {{ background: {c['panel_alt']}; border: 1px solid {c['border']}; padding: 5px; }}
QMenu::item {{ padding: 6px 22px 6px 14px; border-radius: 5px; }}
QMenu::item:selected {{ background: {c['accent']}; color: #06121f; }}
QMenu::separator {{ height: 1px; background: {c['border']}; margin: 4px 8px; }}

QDockWidget {{ titlebar-close-icon: none; }}
QDockWidget::title {{ background: {c['bg_alt']}; padding: 6px 10px; border: 1px solid {c['border']};
                      color: {c['text_dim']}; font-weight: 600; }}
QSplitter::handle {{ background: {c['border']}; }}
QSplitter::handle:horizontal {{ width: 3px; }}
QSplitter::handle:vertical {{ height: 3px; }}
QToolTip {{ background: {c['panel_alt']}; color: {c['text']}; border: 1px solid {c['border_strong']};
            padding: 4px 7px; }}
QLabel[role="title"] {{ font-size: 19pt; font-weight: 700; }}
QLabel[role="subtitle"] {{ color: {c['text_dim']}; font-size: 9.5pt; }}
QLabel[role="section"] {{ font-size: 11.5pt; font-weight: 600; color: {c['text']}; }}
QLabel[role="dim"] {{ color: {c['text_dim']}; }}
QLabel[role="mono"] {{ font-family: 'Cascadia Mono', Consolas, monospace; font-size: 9pt; }}
QLabel[role="chip"] {{ background: {c['panel_alt']}; border: 1px solid {c['border_strong']};
                       border-radius: 11px; padding: 3px 10px; color: {c['text_dim']}; }}
QFrame[role="card"] {{ background: {c['panel']}; border: 1px solid {c['border']}; border-radius: 10px; }}
QFrame[role="hline"] {{ background: {c['border']}; max-height: 1px; border: none; }}
"""


def apply_theme(app) -> None:
    app.setStyleSheet(stylesheet())
