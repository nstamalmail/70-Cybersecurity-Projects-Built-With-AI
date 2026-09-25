"""Report preview and export surface.

This is the "generate a report and export / download it" capability of the
workbench: it renders whatever :class:`~app.reporting.Report` the current
analysis produced and lets the analyst save it to any location on disk in
HTML, PDF, JSON, CSV or Markdown (or dump every format in one click).
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

from PySide6.QtCore import QUrl, Qt
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.config import APP, exports_dir, reports_dir
from app.reporting import (
    FORMATS,
    Report,
    export_all,
    export_report,
    suggested_path,
    to_markdown,
    to_json,
    verdict_color,
)
from app.ui.theme import COLORS
from app.ui.widgets import ClickableText, DataTable, KVGrid, dim_label, hsep

_FILTER_STRING = ";;".join(f"{label} ({pattern})" for label, _fmt, pattern in FORMATS)


class ReportPanel(QWidget):
    """Preview + export UI for the current report."""

    def __init__(self, provider, bus=None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._provider = provider
        self._bus = bus
        self._report: Report | None = None
        self._last_export: Path | None = None
        #: Set to ``False`` by automated tests so confirmation dialogs do not block.
        self.interactive = True

        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # ---------------------------------------------------------- toolbar
        bar = QHBoxLayout()
        bar.setSpacing(6)
        bar.addWidget(QLabel("Report & Export"))
        bar.addStretch(1)

        self._btn_refresh = QPushButton("Refresh")
        self._btn_refresh.setToolTip("Rebuild the report from the current analysis")
        self._btn_refresh.clicked.connect(self.refresh)

        self._btn_export = QPushButton("Export report\u2026")
        self._btn_export.setProperty("accent", "true")
        self._btn_export.setToolTip("Save the report to a file (HTML, PDF, JSON, CSV, Markdown)")
        self._btn_export.setMenu(self._build_export_menu())

        self._btn_all = QPushButton("Export all formats")
        self._btn_all.setToolTip("Write HTML + PDF + JSON + CSV + Markdown into the reports folder")
        self._btn_all.clicked.connect(self.export_all_formats)

        self._btn_folder = QPushButton("Open reports folder")
        self._btn_folder.clicked.connect(
            lambda: _open_path(reports_dir())
        )

        self._btn_open = QPushButton("Open last export")
        self._btn_open.setEnabled(False)
        self._btn_open.clicked.connect(self._open_last)

        for btn in (
            self._btn_refresh,
            self._btn_export,
            self._btn_all,
            self._btn_folder,
            self._btn_open,
        ):
            bar.addWidget(btn)
        root.addLayout(bar)

        # ----------------------------------------------------------- banner
        self._banner = QFrame()
        self._banner.setProperty("role", "card")
        bl = QHBoxLayout(self._banner)
        bl.setContentsMargins(12, 9, 12, 9)
        bl.setSpacing(12)
        self._verdict = QLabel("\u2014")
        self._verdict.setStyleSheet("font-size:15pt;font-weight:700;")
        self._score = QLabel("")
        self._score.setProperty("role", "dim")
        self._summary = dim_label("No analysis yet - load an artefact or click \u201cLoad demo data\u201d.")
        bl.addWidget(self._verdict)
        bl.addWidget(self._score)
        bl.addWidget(self._summary, 1)
        root.addWidget(self._banner)

        self._tabs = QTabWidget()
        root.addWidget(self._tabs, 1)

        self._status = QLabel("Ready. Reports are written under " + str(reports_dir()))
        self._status.setProperty("role", "dim")
        self._status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        root.addWidget(hsep())
        root.addWidget(self._status)

        self._show_placeholder()

    # --------------------------------------------------------------- export
    def _build_export_menu(self) -> QMenu:
        menu = QMenu(self)
        for label, fmt, _pattern in FORMATS:
            action = menu.addAction(label)
            action.triggered.connect(lambda _checked=False, f=fmt: self.export_format(f))
        menu.addSeparator()
        copy_action = menu.addAction("Copy report as Markdown")
        copy_action.triggered.connect(self.copy_markdown)
        copy_action = menu.addAction("Copy raw JSON")
        copy_action.triggered.connect(self.copy_json)
        return menu

    def export_format(self, fmt: str) -> None:
        report = self._provider()
        if report is None:
            self._warn("Nothing to export yet - run an analysis first.")
            return
        default = suggested_path(report, fmt)
        path, _ = QFileDialog.getSaveFileName(
            self, f"Export report as {fmt.upper()}", str(default), _FILTER_STRING
        )
        if not path:
            return
        target = Path(path)
        ext = "csv" if fmt in ("csv", "iocs.csv") else fmt
        if target.suffix.lower() != f".{ext}":
            target = target.with_suffix(f".{ext}")
        try:
            written = export_report(report, target, fmt)
        except Exception as exc:  # pragma: no cover - surfaced in the UI
            self._warn(f"Export failed: {exc}")
            return
        self._last_export = written
        self._btn_open.setEnabled(True)
        self._status.setText(f"Exported \u2192 {written}")
        if self._bus:
            self._bus.success(f"Report exported to {written}")
        if self.interactive:
            QMessageBox.information(
                self,
                "Export complete",
                f"Report written to:\n{written}\n\nUse \u201cOpen last export\u201d to view it.",
            )

    def export_all_formats(self) -> None:
        report = self._provider()
        if report is None:
            self._warn("Nothing to export yet - run an analysis first.")
            return
        written = export_all(report)
        if not written:
            self._warn("Export failed - see the console for details.")
            return
        self._last_export = written[0]
        self._btn_open.setEnabled(True)
        self._status.setText(
            f"Exported {len(written)} files to {written[0].parent}"
        )
        if self._bus:
            for path in written:
                self._bus.success(f"Report exported: {path}")
        if self.interactive:
            QMessageBox.information(
                self,
                "Export complete",
                f"{len(written)} files written to:\n{written[0].parent}",
            )

    def copy_markdown(self) -> None:
        report = self._provider()
        if report is None:
            return
        from PySide6.QtWidgets import QApplication

        QApplication.clipboard().setText(to_markdown(report))
        self._status.setText("Report copied to clipboard as Markdown.")

    def copy_json(self) -> None:
        report = self._provider()
        if report is None:
            return
        from PySide6.QtWidgets import QApplication

        QApplication.clipboard().setText(to_json(report))
        self._status.setText("Raw JSON copied to clipboard.")

    def _open_last(self) -> None:
        if self._last_export and self._last_export.exists():
            _open_path(self._last_export)
        else:
            self._warn("No exported file available yet.")

    # --------------------------------------------------------------- render
    def refresh(self) -> None:
        report = self._provider()
        if report is None:
            self._show_placeholder()
            return
        self._report = report
        self._render(report)

    def report(self) -> Report | None:
        return self._report

    def _show_placeholder(self) -> None:
        self._tabs.clear()
        placeholder = QWidget()
        lay = QVBoxLayout(placeholder)
        lay.addStretch(1)
        lbl = QLabel(
            "No report yet.\n\nLoad an artefact (or generate the built-in demo data), "
            "run the analysis, then press Refresh to build the report."
        )
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setProperty("role", "dim")
        lay.addWidget(lbl)
        lay.addStretch(1)
        self._tabs.addTab(placeholder, "Report")
        self._verdict.setText("\u2014")
        self._verdict.setStyleSheet(f"font-size:15pt;font-weight:700;color:{COLORS['text_dim']};")
        self._score.setText("")
        self._summary.setText("No analysis yet.")

    def _render(self, report: Report) -> None:
        self._tabs.clear()
        color = verdict_color(report.verdict)
        self._verdict.setText(report.verdict or "\u2014")
        self._verdict.setStyleSheet(f"font-size:15pt;font-weight:700;color:{color};")
        bits = []
        if report.risk_score is not None:
            bits.append(f"risk score {report.risk_score}")
        bits.append(f"{len(report.iocs)} IOCs")
        bits.append(f"generated {report.generated_at:%H:%M:%S}")
        self._score.setText(" \u00b7 ".join(bits))
        self._summary.setText(report.summary or "")

        if report.meta:
            self._tabs.addTab(KVGrid(report.meta), "Overview")

        if report.iocs:
            table = DataTable(
                ["Type", "Value", "Source", "Confidence", "Context"],
                export_name="iocs",
            )
            table.set_data(
                [
                    [
                        ioc.get("ioc_type", ""),
                        ioc.get("value", ""),
                        ioc.get("source", ""),
                        f"{float(ioc.get('confidence', 0.0)):.2f}",
                        ioc.get("context", ""),
                    ]
                    for ioc in report.iocs
                ]
            )
            self._tabs.addTab(table, f"IOCs ({len(report.iocs)})")

        for sec in report.sections:
            if sec.is_empty():
                continue
            widget: QWidget
            if sec.kind == "kv":
                widget = KVGrid(sec.data)
            elif sec.kind == "table":
                widget = DataTable(sec.columns, export_name="section")
                widget.set_data(sec.rows)
            elif sec.kind == "list":
                widget = ClickableText("\n".join(f"\u2022 {i}" for i in sec.items))
            else:
                widget = ClickableText(sec.text)
            label = sec.title if len(sec.title) <= 26 else sec.title[:24] + "\u2026"
            self._tabs.addTab(widget, label)

        raw = QWidget()
        raw_lay = QVBoxLayout(raw)
        raw_lay.setContentsMargins(0, 0, 0, 0)
        raw_lay.addWidget(ClickableText(to_json(report)))
        self._tabs.addTab(raw, "Raw JSON")

        if report.artifacts:
            self._tabs.addTab(
                ClickableText("\n".join(report.artifacts)), "Artefacts"
            )

        self._status.setText(
            f"Report ready \u00b7 {len(report.sections)} sections \u00b7 "
            f"export to HTML / PDF / JSON / CSV / Markdown"
        )

    # -------------------------------------------------------------- helpers
    def _warn(self, message: str) -> None:
        QMessageBox.warning(self, APP["name"], message)
        if self._bus:
            self._bus.warn(message)


def _open_path(path) -> None:
    path = Path(path)
    if path.is_dir():
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
    elif path.exists():
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
    else:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(exports_dir())))


__all__ = ["ReportPanel", "_open_path"]
