"""Workbench views for the Ransomware Behavior Analysis Report."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFrame, QHBoxLayout, QLabel, QPushButton,
    QSplitter, QVBoxLayout, QWidget,
)

from app.config import APP, demo_dir
from app.core import detection
from app.core.engine import AnalysisResult
from app.ui.theme import COLORS, color_for
from app.ui.widgets import (
    BarChart, ClickableText, DataTable, KVGrid, StatStrip, dim_label, section_label,
)


def _card() -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setProperty("role", "card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(12, 10, 12, 10)
    layout.setSpacing(8)
    return frame, layout


def _row() -> tuple[QWidget, QHBoxLayout]:
    widget = QWidget()
    layout = QHBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(8)
    return widget, layout


def _mono(text: str = "", height: int = 120) -> ClickableText:
    view = ClickableText(text)
    view.setMinimumHeight(height)
    return view


class IngestView(QWidget):
    analyseReport = Signal(str)
    analyseDemo = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        source, sl = _card()
        sl.addWidget(section_label("Report source"))
        sl.addWidget(dim_label("Drop a Cuckoo / CAPE report here. Parsing happens locally."))
        from app.ui.widgets import FilePicker
        self.picker = FilePicker("Sandbox report", "All files (*)")
        sl.addWidget(self.picker)
        buttons, bl = _row()
        self.btn_analyse = QPushButton("Analyse report")
        self.btn_analyse.setProperty("role", "primary")
        self.btn_analyse.clicked.connect(lambda: self._emit_path())
        bl.addWidget(self.btn_analyse)
        bl.addStretch(1)
        sl.addWidget(buttons)
        root.addWidget(source)

        demo, dl = _card()
        dl.addWidget(section_label("Offline demo fixtures"))
        dl.addWidget(dim_label("Synthetic ransomware reports: no live sample used."))
        self.demo_table = DataTable(["Fixture", "Behaviour", "File", "Format", "Bytes"], export_name="demo_fixtures")
        import app.demo as demo_mod
        self.demo_table.set_data(demo_mod.fixture_rows())
        dl.addWidget(self.demo_table, 1)
        demo_buttons, dbl = _row()
        self.btn_demo = QPushButton("Analyse selected fixture")
        self.btn_demo.setProperty("role", "primary")
        self.btn_demo.clicked.connect(self._emit_demo)
        self.demo_table.rowActivated.connect(lambda _: self._emit_demo())
        dbl.addWidget(self.btn_demo)
        dbl.addStretch(1)
        dl.addWidget(demo_buttons)
        root.addWidget(demo, 1)

    def bind_settings(self, settings) -> None:
        pass

    def set_recent(self, rows: list[list]) -> None:
        pass

    def _emit_path(self) -> None:
        path = self.picker.path()
        if path is not None:
            self.analyseReport.emit(str(path))

    def _emit_demo(self) -> None:
        row = self.demo_table.selected_row()
        if row:
            self.analyseDemo.emit(str(row[0]))


class EncryptionStagesView(QWidget):
    """Ransomware encryption stages and file operations."""
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._result: AnalysisResult | None = None
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        self.stats = StatStrip()
        root.addWidget(self.stats)

        splitter = QSplitter(Qt.Horizontal)
        table_card, tcl = _card()
        tcl.addWidget(section_label("Encryption patterns detected"))
        self.table = DataTable(
            ["Severity", "Pattern", "Process", "Evidence", "Confidence"],
            export_name="encryption_patterns",
        )
        self.table.rowSelected.connect(self._show_detail)
        tcl.addWidget(self.table)
        splitter.addWidget(table_card)

        detail_card, dl = _card()
        dl.addWidget(section_label("Pattern detail"))
        self.detail = _mono("Select a pattern to inspect.", 250)
        dl.addWidget(self.detail)
        splitter.addWidget(detail_card)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

    def set_analysis(self, result: AnalysisResult | None) -> None:
        self._result = result
        if result is None:
            return
        self.table.set_data([a.to_row() for a in result.artifacts])
        counts = {}
        for a in result.artifacts:
            counts[a.severity] = counts.get(a.severity, 0) + 1
        self.stats.set_stats([
            ("Patterns", len(result.artifacts), COLORS["warn"] if result.artifacts else COLORS["text_dim"]),
            ("Critical", counts.get("critical", 0), COLORS["bad"]),
            ("High", counts.get("high", 0), COLORS["bad"]),
            ("Files", result.stats.get("file_ops", 0), COLORS["info"]),
            ("Verdict", result.severity.upper(), color_for(result.severity)),
        ])

    def _show_detail(self, index: int) -> None:
        if index < 0 or index >= len(self._result.artifacts if self._result else []):
            return
        artifact = self._result.artifacts[index]
        lines = [
            f"Pattern   : {artifact.technique_id} - {artifact.technique_name}",
            f"Severity  : {artifact.severity}",
            f"Process   : {artifact.process_name} (pid {artifact.process_id})",
            f"Confidence: {artifact.confidence:.2f}",
            "",
            "Evidence",
        ]
        for ev in artifact.evidence:
            lines.append(f"  - {ev}")
        if artifact.references:
            lines.extend(["", "References"])
            for ref in artifact.references:
                lines.append(f"  {ref}")
        self.detail.set_text("\n".join(lines))


class FileOpsView(QWidget):
    """File operations timeline."""
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        chart_card, cl = _card()
        cl.addWidget(section_label("File operations by category"))
        self.chart = BarChart(height=200)
        cl.addWidget(self.chart)
        root.addWidget(chart_card)

        table_card, tcl = _card()
        tcl.addWidget(section_label("All file operations"))
        self.table = DataTable(["Time", "PID", "Process", "Category", "API", "Details"], export_name="file_ops")
        tcl.addWidget(self.table)
        root.addWidget(table_card, 1)

    def set_analysis(self, result: AnalysisResult | None) -> None:
        if result is None:
            return
        categories = result.categories()
        self.chart.set_data(list(categories.keys()), list(categories.values()), unit=" calls")
        file_ops = [call for call in result.calls if call.category in ("file", "crypto")]
        self.table.set_data([call.to_row()[:6] for call in file_ops])


class IOCView(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._iocs: list[dict] = []
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)
        self.stats = StatStrip()
        root.addWidget(self.stats)
        self.table = DataTable(["Type", "Value", "Source", "Confidence", "Context"], export_name="indicators")
        root.addWidget(self.table, 1)

    def set_analysis(self, result: AnalysisResult | None) -> None:
        self._iocs = list(result.iocs) if result else []
        self.stats.set_stats([("Indicators", len(self._iocs), COLORS["accent"])])
        self.table.set_data([
            [item.get("type", ""), item.get("value", ""), item.get("source", ""),
             f"{float(item.get('confidence', 0)):.2f}", item.get("context", "")]
            for item in self._iocs
        ])
