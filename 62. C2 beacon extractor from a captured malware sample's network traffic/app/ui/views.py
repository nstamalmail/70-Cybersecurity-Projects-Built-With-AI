"""Workbench views for the Malware Persistence Technique Cataloger."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDoubleSpinBox, QFrame, QGridLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QSpinBox, QSplitter, QTreeWidget,
    QTreeWidgetItem, QVBoxLayout, QWidget,
)

from app.config import APP, demo_dir
from app.core import detection
from app.core.engine import AnalysisResult
from app.ui.theme import COLORS, color_for
from app.ui.widgets import (
    AttackMatrix, BarChart, ClickableText, DataTable, KVGrid, StatStrip,
    badge, dim_label, section_label,
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
        self._settings = None
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
        dl.addWidget(dim_label("Synthetic reports: no live sample or network access used."))
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

        recent, rl = _card()
        rl.addWidget(section_label("Recently analysed reports"))
        self.recent_table = DataTable(["When", "Sample", "Format", "Persistence", "Score", "Source"], export_name="recent_reports")
        rl.addWidget(self.recent_table)
        root.addWidget(recent)

    def bind_settings(self, settings) -> None:
        self._settings = settings

    def set_recent(self, rows: list[list]) -> None:
        self.recent_table.set_data(rows)

    def _emit_path(self) -> None:
        path = self.picker.path()
        if path is not None:
            self.analyseReport.emit(str(path))

    def _emit_demo(self) -> None:
        row = self.demo_table.selected_row()
        if row:
            self.analyseDemo.emit(str(row[0]))


class CatalogView(QWidget):
    """Primary view: persistence techniques table + detail."""
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._result: AnalysisResult | None = None
        self._artifacts: list = []
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        self.stats = StatStrip()
        root.addWidget(self.stats)

        splitter = QSplitter(Qt.Horizontal)
        table_card, tcl = _card()
        tcl.addWidget(section_label("Detected persistence mechanisms"))
        self.table = DataTable(
            ["Severity", "Technique", "Name", "Source", "Evidence", "Confidence", "Details"],
            export_name="persistence",
        )
        self.table.rowSelected.connect(self._show_detail)
        tcl.addWidget(self.table)
        splitter.addWidget(table_card)

        detail_card, dl = _card()
        dl.addWidget(section_label("Evidence and remediation"))
        self.detail = _mono("Select a persistence mechanism to inspect.", 250)
        dl.addWidget(self.detail)
        splitter.addWidget(detail_card)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

        cat_card, ccl = _card()
        ccl.addWidget(section_label("Pattern catalogue"))
        self.catalogue = DataTable(
            ["ID", "Name", "Severity", "Steps", "Gap", "Tags"], export_name="pattern_catalogue",
        )
        self.catalogue.set_data([
            [item["pattern_id"], item["name"], item["severity"],
             " -> ".join(item["steps"].split(" -> ")), item["gap"], ", ".join(item["tags"])]
            for item in detection.pattern_catalogue()
        ])
        ccl.addWidget(self.catalogue)
        root.addWidget(cat_card)

    def set_analysis(self, result: AnalysisResult | None) -> None:
        self._result = result
        if result is None:
            return
        self._artifacts = list(result.artifacts)
        self.table.set_data([a.to_row() for a in self._artifacts])
        counts = {}
        for a in self._artifacts:
            counts[a.severity] = counts.get(a.severity, 0) + 1
        self.stats.set_stats([
            ("Persistence", len(self._artifacts), COLORS["warn"] if self._artifacts else COLORS["text_dim"]),
            ("Critical", counts.get("critical", 0), COLORS["bad"]),
            ("High", counts.get("high", 0), COLORS["bad"]),
            ("Medium", counts.get("medium", 0), COLORS["warn"]),
            ("Low", counts.get("low", 0), COLORS["ok"]),
            ("Verdict", result.severity.upper(), color_for(result.severity)),
        ])

    def _show_detail(self, index: int) -> None:
        if index < 0 or index >= len(self._artifacts):
            return
        artifact = self._artifacts[index]
        lines = [
            f"Technique  : {artifact.technique_id} - {artifact.technique_name}",
            f"Severity   : {artifact.severity}",
            f"Source     : {artifact.source}",
            f"Process    : {artifact.process_name} (pid {artifact.process_id})",
            f"Confidence : {artifact.confidence:.2f}",
        ]
        if artifact.key_path:
            lines.append(f"Registry   : {artifact.key_path}")
        if artifact.service_name:
            lines.append(f"Service    : {artifact.service_name}")
        if artifact.binary_path:
            lines.append(f"Binary     : {artifact.binary_path}")
        lines.append("")
        lines.append("Evidence")
        for ev in artifact.evidence:
            lines.append(f"  - {ev}")
        if artifact.references:
            lines.append("")
            lines.append("References")
            for ref in artifact.references:
                lines.append(f"  {ref}")
        self.detail.set_text("\n".join(lines))


class ProcessTreeView(QWidget):
    """Reconstructed process tree with detail."""
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._result: AnalysisResult | None = None
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        splitter = QSplitter(Qt.Horizontal)
        tree_card, tl = _card()
        tl.addWidget(section_label("Process tree"))
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Process", "PID", "Calls", "Categories"])
        self.tree.setAlternatingRowColors(True)
        self.tree.itemSelectionChanged.connect(self._show_detail)
        tl.addWidget(self.tree)
        splitter.addWidget(tree_card)

        detail_card, dl = _card()
        dl.addWidget(section_label("Process detail"))
        self.detail = _mono("Select a process.", 200)
        dl.addWidget(self.detail)
        self.chart = BarChart(height=170)
        dl.addWidget(self.chart)
        splitter.addWidget(detail_card)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

    def set_analysis(self, result: AnalysisResult | None) -> None:
        self._result = result
        if result is None:
            return
        self.tree.clear()
        nodes = {node.process_id: node for node in result.processes}
        children = {}
        for node in result.processes:
            parent = node.parent_pid if node.parent_pid in nodes else None
            children.setdefault(parent, []).append(node.process_id)

        def build(pid, parent_item=None):
            node = nodes[pid]
            item = QTreeWidgetItem([node.process_name, str(pid), str(node.call_count),
                                    ", ".join(f"{n}:{c}" for n, c in sorted(node.categories.items(), key=lambda kv: -kv[1])[:3])])
            item.setData(0, Qt.UserRole, pid)
            if parent_item is None:
                self.tree.addTopLevelItem(item)
            else:
                parent_item.addChild(item)
            for child in sorted(children.get(pid, [])):
                build(child, item)

        for pid in children.get(None, [node.process_id for node in result.processes]):
            build(pid)
        self.tree.expandAll()

    def _show_detail(self):
        items = self.tree.selectedItems()
        if not items or self._result is None:
            return
        pid = items[0].data(0, Qt.UserRole)
        node = next((n for n in self._result.processes if n.process_id == pid), None)
        if node:
            lines = [f"Process: {node.process_name}", f"PID: {node.process_id}",
                     f"Parent: {node.parent_pid or '-'}", f"Calls: {node.call_count}",
                     f"Path: {node.path or '-'}"]
            if node.categories:
                lines.append("")
                lines.append("Categories")
                for name, count in sorted(node.categories.items(), key=lambda kv: -kv[1]):
                    lines.append(f"  {count:6d}  {name}")
            self.detail.set_text("\n".join(lines))
            if node.categories:
                labels = list(node.categories.keys())
                self.chart.set_data(labels, [node.categories[n] for n in labels], unit=" calls")


class IOCView(QWidget):
    """Indicators of compromise."""
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
        counts = {}
        for item in self._iocs:
            counts[item.get("type", "")] = counts.get(item.get("type", ""), 0) + 1
        self.stats.set_stats([
            ("Indicators", len(self._iocs), COLORS["accent"]),
        ] + [(name, counts.get(name, 0), COLORS["info"]) for name in sorted(counts)])
        self.table.set_data([
            [item.get("type", ""), item.get("value", ""), item.get("source", ""),
             f"{float(item.get('confidence', 0)):.2f}", item.get("context", "")]
            for item in self._iocs
        ])


class ATTnCKView(QWidget):
    """ATT&CK heatmap of detected techniques."""
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        card, cl = _card()
        cl.addWidget(section_label("ATT&CK Persistence Technique Coverage"))
        cl.addWidget(dim_label("Detected techniques mapped to MITRE ATT&CK TA0003."))
        self.matrix = AttackMatrix()
        self.matrix.setMinimumHeight(300)
        cl.addWidget(self.matrix, 1)
        root.addWidget(card, 2)

    def set_analysis(self, result: AnalysisResult | None) -> None:
        if result is None:
            return
        columns = {}
        for artifact in result.artifacts:
            tag = artifact.source or "behavior"
            columns.setdefault(tag, []).append(artifact)
        matrix_columns = []
        for tag, artifacts in columns.items():
            cells = [{
                "id": a.technique_id, "name": a.technique_name, "value": 1, "max": 1,
                "level": a.severity,
                "note": f"{a.process_name} @ {a.timestamp:.2f}s\nconfidence: {a.confidence:.2f}",
            } for a in artifacts[:6]]
            matrix_columns.append((tag, cells))
        self.matrix.set_columns(matrix_columns)
