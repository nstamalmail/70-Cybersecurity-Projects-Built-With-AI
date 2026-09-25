"""Shared application shell.

``AppShell`` provides the common chrome every workbench reuses - header, tab
host, console dock, status bar, menus and the Report & Export tab - while
subclasses only supply their own views (``build_tabs``) and the report they can
produce (``current_report``).
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QAction, QDesktopServices
from PySide6.QtWidgets import (
    QDockWidget,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.bus import LogBus
from app.config import APP, data_root, logs_dir, reports_dir, settings_path
from app.reporting import FORMATS, Report
from app.ui import theme
from app.ui.report_panel import ReportPanel, _open_path
from app.ui.widgets import LogConsole, badge, hsep, title_label


class AppShell(QMainWindow):
    """Base main window: header, tabs, console, status bar, report tab."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.bus = LogBus(APP["slug"])
        self.setWindowTitle(f"{APP['name']}  v{APP['version']}")
        self.resize(1360, 880)
        self.setMinimumSize(980, 640)
        theme.apply_theme(self._qapp())

        central = QWidget()
        outer = QVBoxLayout(central)
        outer.setContentsMargins(10, 8, 10, 6)
        outer.setSpacing(8)

        # ------------------------------------------------------------ header
        header = QFrame()
        header.setProperty("role", "card")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(14, 10, 14, 10)
        hl.setSpacing(12)

        text_col = QVBoxLayout()
        text_col.setSpacing(1)
        text_col.addWidget(title_label(f"{APP['name']}"))
        sub = QLabel(APP["subtitle"])
        sub.setProperty("role", "subtitle")
        text_col.addWidget(sub)
        hl.addLayout(text_col)
        hl.addStretch(1)

        self._chips_widget = QWidget()
        self._chips = QHBoxLayout(self._chips_widget)
        self._chips.setContentsMargins(0, 0, 0, 0)
        self._chips.setSpacing(6)
        hl.addWidget(self._chips_widget)
        self.set_header_chips([])
        outer.addWidget(header)

        # -------------------------------------------------------------- tabs
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        outer.addWidget(self.tabs, 1)
        self.setCentralWidget(central)

        # let the subclass build its own views first
        self.build_tabs()

        # report tab (always last, always present)
        self.report_panel = ReportPanel(self.current_report, self.bus, self)
        self.add_tab(self.report_panel, "Report & Export")
        self.tabs.currentChanged.connect(self._on_tab_changed)

        # ----------------------------------------------------------- console
        console_wrap = QWidget()
        cw = QVBoxLayout(console_wrap)
        cw.setContentsMargins(6, 6, 6, 6)
        cw.setSpacing(6)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Session log"))
        bar.addStretch(1)
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._console_clear)
        open_log = QPushButton("Open log file")
        open_log.clicked.connect(lambda: _open_path(logs_dir()))
        bar.addWidget(clear_btn)
        bar.addWidget(open_log)
        cw.addLayout(bar)
        self.console = LogConsole()
        cw.addWidget(self.console, 1)

        self.console_dock = QDockWidget("Console", self)
        self.console_dock.setWidget(console_wrap)
        self.console_dock.setMinimumHeight(170)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.console_dock)
        self.bus.record.connect(self.console.append_record)

        self._build_menus()
        self.statusBar().showMessage(f"{APP['name']} ready \u00b7 data: {data_root()}")
        self.log(f"{APP['name']} v{APP['version']} started")
        self.log(f"Data directory: {data_root()}")

    # ------------------------------------------------------------- overrides
    def build_tabs(self) -> None:  # pragma: no cover - overridden
        """Create the application specific tabs (call ``add_tab``)."""

    def current_report(self) -> Report | None:  # pragma: no cover - overridden
        """Return the report for the current analysis, or ``None``."""
        return None

    def open_artifact(self) -> None:  # pragma: no cover - overridden
        """Hook for File ▸ Open artefact."""

    def build_tools_menu(self, menu) -> None:  # pragma: no cover - overridden
        """Hook allowing subclasses to add Tools menu entries."""

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _qapp():
        from PySide6.QtWidgets import QApplication

        app = QApplication.instance()
        if app is None:
            app = QApplication([])
        return app

    def add_tab(self, widget: QWidget, title: str) -> int:
        return self.tabs.addTab(widget, title)

    def log(self, message: str, level: str = "info") -> None:
        self.bus.log(message, level)

    def set_header_chips(self, chips: list[tuple[str, str]]) -> None:
        while self._chips.count():
            item = self._chips.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        for text, color in chips:
            self._chips.addWidget(badge(text, color))
        self._chips_widget.setVisible(bool(chips))

    def set_status(self, message: str) -> None:
        self.statusBar().showMessage(message)

    def refresh_report(self) -> None:
        self.report_panel.refresh()

    def show_report_tab(self) -> None:
        self.tabs.setCurrentWidget(self.report_panel)

    def _on_tab_changed(self, index: int) -> None:
        if self.tabs.widget(index) is self.report_panel:
            self.report_panel.refresh()

    def _console_clear(self) -> None:
        self.console.clear()
        self.bus.clear()

    # ----------------------------------------------------------------- menus
    def _build_menus(self) -> None:
        menubar = self.menuBar()

        file_menu = menubar.addMenu("&File")
        act_open = QAction("Open artefact\u2026", self)
        act_open.setShortcut("Ctrl+O")
        act_open.triggered.connect(self.open_artifact)
        file_menu.addAction(act_open)
        file_menu.addSeparator()

        export_menu = file_menu.addMenu("Export report as")
        for label, fmt, _pattern in FORMATS:
            act = QAction(label, self)
            act.triggered.connect(lambda _c=False, f=fmt: self.report_panel.export_format(f))
            export_menu.addAction(act)
        act_all = QAction("Export all formats\u2026", self)
        act_all.triggered.connect(self.report_panel.export_all_formats)
        file_menu.addAction(act_all)
        act_folder = QAction("Open reports folder", self)
        act_folder.triggered.connect(lambda: _open_path(reports_dir()))
        file_menu.addAction(act_folder)
        file_menu.addSeparator()
        act_quit = QAction("Exit", self)
        act_quit.setShortcut("Ctrl+Q")
        act_quit.triggered.connect(self.close)
        file_menu.addAction(act_quit)

        view_menu = menubar.addMenu("&View")
        act_console = QAction("Show console", self, checkable=True)
        act_console.setChecked(True)
        act_console.toggled.connect(self.console_dock.setVisible)
        view_menu.addAction(act_console)
        act_clear = QAction("Clear console", self)
        act_clear.triggered.connect(self._console_clear)
        view_menu.addAction(act_clear)
        act_refresh = QAction("Refresh report", self)
        act_refresh.setShortcut("F5")
        act_refresh.triggered.connect(self.refresh_report)
        view_menu.addAction(act_refresh)

        tools_menu = menubar.addMenu("&Tools")
        self.build_tools_menu(tools_menu)

        help_menu = menubar.addMenu("&Help")
        act_data = QAction("Open data folder", self)
        act_data.triggered.connect(lambda: _open_path(data_root()))
        help_menu.addAction(act_data)
        act_about = QAction("About", self)
        act_about.triggered.connect(self._about)
        help_menu.addAction(act_about)

    def _about(self) -> None:
        QMessageBox.information(
            self,
            f"About {APP['name']}",
            f"<b>{APP['name']}</b> v{APP['version']}<br><br>{APP['description']}"
            f"<br><br><b>Data directory:</b><br>{data_root()}"
            f"<br><br><b>Reports:</b><br>{reports_dir()}"
            f"<br><br><b>Settings:</b><br>{settings_path()}",
        )
