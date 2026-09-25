"""Workbench views (architecture §4).

Each view is a ``QWidget`` with a ``set_analysis(result)`` slot, so the main
window can hand the same :class:`~app.core.engine.AnalysisResult` to every tab
after an analysis run:

======================  =====================================================
``IngestView``          report/demo selection, run controls, recent reports
``OverviewView``        verdict, KPI strip, category chart, pattern matrix
``TimelineView``        call-rate chart, event strip, bursts, busiest windows
``SequenceView``        filterable API call table + evidence pane + motifs
``PatternView``         behavioural findings + the full pattern catalogue
``ProcessView``         reconstructed process tree with per-process detail
``GraphView``           Markov behaviour graph + transition table + paths
``HeatmapView``         process x category heatmap + API frequency table
``IOCView``             indicators of compromise with type filters
======================  =====================================================
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.config import APP, demo_dir
from app.core import detection
from app.core.categorize import is_suspicious
from app.core.engine import AnalysisResult
from app.ui.graphs import BehaviorGraph, HeatmapWidget
from app.ui.theme import COLORS, color_for
from app.ui.widgets import (
    AttackMatrix,
    BarChart,
    ClickableText,
    DataTable,
    KVGrid,
    StatStrip,
    TimelineStrip,
    badge,
    dim_label,
    mono_label,
    section_label,
)


# --------------------------------------------------------------------------- #
#  small helpers
# --------------------------------------------------------------------------- #
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


def qt_file_filter() -> str:
    """Turn the config's ``(label, pattern)`` pairs into a Qt filter string."""
    filters = APP.get("file_filters") or []
    if isinstance(filters, str):
        return filters
    parts = [f"{label} ({pattern})" for label, pattern in filters]
    return ";;".join(parts) or "All files (*)"


# --------------------------------------------------------------------------- #
#  Ingest / run
# --------------------------------------------------------------------------- #
class IngestView(QWidget):
    """Choose a sandbox report (or a demo fixture) and run the analysis."""

    analyseReport = Signal(str)     # filesystem path
    analyseDemo = Signal(str)       # fixture key

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._settings = None
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        source, sl = _card()
        sl.addWidget(section_label("Report source"))
        sl.addWidget(
            dim_label(
                "Drop a Cuckoo / CAPE report here — JSON, CAPE .bson behaviour logs or JSON Lines. "
                "Nothing is uploaded; parsing happens locally in this process."
            )
        )
        from app.ui.widgets import FilePicker

        self.picker = FilePicker("Sandbox report", qt_file_filter())
        sl.addWidget(self.picker)

        buttons, bl = _row()
        self.btn_analyse = QPushButton("Analyse report")
        self.btn_analyse.setProperty("role", "primary")
        self.btn_analyse.clicked.connect(lambda: self._emit_path())
        self.btn_open = QPushButton("Open path in explorer")
        self.btn_open.clicked.connect(self._reveal)
        bl.addWidget(self.btn_analyse)
        bl.addWidget(self.btn_open)
        bl.addStretch(1)
        sl.addWidget(buttons)

        options, ol = _row()
        self.chk_collapse = QCheckBox("Collapse repeated call loops")
        self.chk_collapse.setChecked(True)
        self.chk_ignore_sync = QCheckBox("Ignore system / sync noise")
        self.chk_high_only = QCheckBox("Only high-severity patterns")
        ol.addWidget(self.chk_collapse)
        ol.addWidget(self.chk_ignore_sync)
        ol.addWidget(self.chk_high_only)
        ol.addStretch(1)
        ol.addWidget(QLabel("Loop threshold"))
        self.spin_threshold = QSpinBox()
        self.spin_threshold.setRange(2, 500)
        self.spin_threshold.setValue(3)
        ol.addWidget(self.spin_threshold)
        sl.addWidget(options)
        root.addWidget(source)

        demo, dl = _card()
        dl.addWidget(section_label("Offline demo fixtures"))
        dl.addWidget(
            dim_label(
                "Synthetic reports generated in memory: no live sample, sandbox or network access is "
                "used. They exercise every parser and every view."
            )
        )
        self.demo_table = DataTable(
            ["Fixture", "Behaviour", "File", "Format", "Bytes"], export_name="demo_fixtures"
        )
        import app.demo as demo_mod

        self.demo_table.set_data(demo_mod.fixture_rows())
        dl.addWidget(self.demo_table, 1)
        demo_buttons, dbl = _row()
        self.btn_demo = QPushButton("Analyse selected fixture")
        self.btn_demo.setProperty("role", "primary")
        self.btn_demo.clicked.connect(self._emit_demo)
        self.demo_table.rowActivated.connect(lambda _index: self._emit_demo())
        dbl.addWidget(self.btn_demo)
        dbl.addWidget(dim_label(f"Fixture files are written on demand to {demo_dir()}"))
        dbl.addStretch(1)
        dl.addWidget(demo_buttons)
        root.addWidget(demo, 1)

        recent, rl = _card()
        rl.addWidget(section_label("Recently analysed reports"))
        self.recent_table = DataTable(
            ["When", "Sample", "Format", "Calls", "Processes", "Findings", "Verdict", "Score", "Source"],
            export_name="recent_reports",
        )
        rl.addWidget(self.recent_table)
        root.addWidget(recent)

    # ------------------------------------------------------------------ wiring
    def bind_settings(self, settings) -> None:
        self._settings = settings
        self.chk_collapse.setChecked(bool(settings.get("collapse_loops", True)))
        self.spin_threshold.setValue(int(settings.get("collapse_threshold", 3)))
        self.chk_high_only.setChecked(str(settings.get("pattern_min_severity", "low")) == "high")
        self.chk_ignore_sync.setChecked(bool(settings.get("ignore_categories", [])))

    def apply_to_settings(self, settings) -> None:
        settings.set("collapse_loops", self.chk_collapse.isChecked())
        settings.set("collapse_threshold", self.spin_threshold.value())
        settings.set("pattern_min_severity", "high" if self.chk_high_only.isChecked() else "low")
        settings.set(
            "ignore_categories",
            ["system", "sync"] if self.chk_ignore_sync.isChecked() else [],
        )

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

    def _reveal(self) -> None:
        path = self.picker.path()
        if path is not None:
            from app.ui.report_panel import _open_path

            _open_path(path.parent)


# --------------------------------------------------------------------------- #
#  Overview
# --------------------------------------------------------------------------- #
class OverviewView(QWidget):
    """Verdict, KPIs, category distribution and pattern coverage matrix."""

    patternSelected = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        self.stats = StatStrip()
        root.addWidget(self.stats)

        self.narrative = _mono("No analysis run yet — pick a report in the Ingest tab.", 84)
        root.addWidget(self.narrative)

        middle = QSplitter(Qt.Horizontal)
        chart_card, cl = _card()
        cl.addWidget(section_label("Calls per API category"))
        self.chart = BarChart(height=210)
        cl.addWidget(self.chart)
        middle.addWidget(chart_card)

        meta_card, ml = _card()
        ml.addWidget(section_label("Report metadata"))
        self.meta_grid = KVGrid()
        ml.addWidget(self.meta_grid)
        middle.addWidget(meta_card)
        middle.setStretchFactor(0, 3)
        middle.setStretchFactor(1, 2)
        root.addWidget(middle, 1)

        matrix_card, tcl = _card()
        tcl.addWidget(section_label("Behaviour pattern coverage (by tactic tag)"))
        tcl.addWidget(dim_label("Cell intensity follows severity; click a cell to inspect the finding."))
        self.matrix = AttackMatrix()
        self.matrix.setMinimumHeight(230)
        self.matrix.cellClicked.connect(lambda cell: self.patternSelected.emit(str(cell.get("id", ""))))
        tcl.addWidget(self.matrix, 1)
        root.addWidget(matrix_card, 2)

    def set_analysis(self, result: AnalysisResult | None) -> None:
        if result is None:
            return
        categories = result.categories()
        self.stats.set_stats(
            [
                ("API calls", f"{result.call_count:,}", COLORS["accent"]),
                ("Processes", len(result.processes), COLORS["info"]),
                ("Findings", len(result.matches), COLORS["warn"] if result.matches else COLORS["text_dim"]),
                ("Indicators", len(result.iocs), COLORS["info"]),
                ("Duration", f"{result.duration:.1f}s", COLORS["text_dim"]),
                ("Verdict", result.severity.upper(), color_for(result.severity)),
            ]
        )
        narrative = [f"Sample: {result.meta.sample_name or result.source_name or '-'}",
                     f"Format: {result.source_format} · score {result.score}/100 ({result.severity})"]
        if result.matches:
            narrative.append("")
            for match in result.matches[:8]:
                narrative.append(
                    f"[{match.severity.upper():8s}] {match.pattern_id} {match.name} "
                    f"(pid {match.process_id} @ {match.start_ts:.2f}s)"
                    + (f" → {match.target}" if match.target else "")
                )
        if result.meta.warnings:
            narrative.append("")
            narrative.extend(f"warning: {warning}" for warning in result.meta.warnings)
        self.narrative.set_text("\n".join(narrative))

        labels = list(categories.keys())
        values = [categories[name] for name in labels]
        self.chart.set_data(
            labels,
            values,
            unit=" calls",
            bands=[(1e12, COLORS["accent"])],
        )
        self.meta_grid.set_data(
            {
                "Report": result.meta.report_id or "-",
                "Source": result.source_name or "-",
                "Format": result.source_format,
                "Sample": result.meta.sample_name or "-",
                "SHA-256": result.meta.sample_sha256 or "-",
                "Machine": result.meta.machine or "-",
                "Analysis started": result.meta.analysis_started or "-",
                "Unique APIs": result.stats.get("unique_apis", "-"),
                "Transitions": len(result.transitions),
                "Clusters": len(result.clusters),
                "Calls / second": result.stats.get("calls_per_second", "-"),
                "Failure ratio": f"{float(result.stats.get('failure_ratio', 0.0)) * 100:.1f}%",
            }
        )

        # pattern coverage grouped by tactic tag
        columns: dict[str, list[dict]] = {}
        for match in result.matches:
            pattern = detection.PATTERN_INDEX.get(match.pattern_id)
            tags = list(pattern.tags) if pattern else ["untagged"]
            for tag in tags or ["untagged"]:
                columns.setdefault(tag, []).append(match)
        matrix_columns: list[tuple[str, list[dict]]] = []
        for tag, matches in columns.items():
            cells = [
                {
                    "id": match.pattern_id,
                    "name": match.name,
                    "value": 1,
                    "max": 1,
                    "level": match.severity,
                    "note": f"{match.process_name or match.process_id} @ {match.start_ts:.2f}s"
                    + (f"\ntarget: {match.target}" if match.target else ""),
                }
                for match in matches[:6]
            ]
            matrix_columns.append((tag, cells))
        self.matrix.set_columns(matrix_columns)


# --------------------------------------------------------------------------- #
#  Timeline
# --------------------------------------------------------------------------- #
class TimelineView(QWidget):
    """Call-rate chart, event strip and burst analysis."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        rate_card, rl = _card()
        rl.addWidget(section_label("Call rate over the analysis"))
        rl.addWidget(dim_label("Per-bucket call counts for the dominant categories."))
        self.rate = BarChart(height=200)
        rl.addWidget(self.rate)
        root.addWidget(rate_card)

        strip_card, sl = _card()
        sl.addWidget(section_label("Event strip"))
        sl.addWidget(dim_label("Pattern findings and burst windows on a shared time axis."))
        self.strip = TimelineStrip(height=170)
        sl.addWidget(self.strip)
        root.addWidget(strip_card)

        tables = QSplitter(Qt.Horizontal)
        burst_card, bl = _card()
        bl.addWidget(section_label("Activity bursts"))
        self.bursts = DataTable(["Start (s)", "End (s)", "Calls", "Rate (calls/s)"], export_name="bursts")
        bl.addWidget(self.bursts)
        tables.addWidget(burst_card)

        window_card, wl = _card()
        wl.addWidget(section_label("Busiest windows by category"))
        self.windows = DataTable(["Window (s)", "Calls", "Top category", "Share"], export_name="windows")
        wl.addWidget(self.windows)
        tables.addWidget(window_card)
        root.addWidget(tables, 1)

    def set_analysis(self, result: AnalysisResult | None) -> None:
        if result is None:
            return
        buckets = int(APP["settings"].get("timeline_buckets", 120))
        buckets = min(buckets, max(8, len(result.calls)))
        times, matrix = result.timeline_buckets(buckets)
        categories = list(result.categories())
        totals = [sum(row) for row in matrix]
        self.rate.set_data(
            [f"{value:.1f}" for value in times],
            totals,
            unit=" calls",
            bands=[(1e12, COLORS["accent"])],
        )

        events = [
            {
                "ts": match.start_ts,
                "label": match.name,
                "category": "process" if match.severity == "critical" else "system",
                "detail": f"{match.pattern_id} · {match.severity} · pid {match.process_id}"
                + (f" → {match.target}" if match.target else ""),
            }
            for match in result.matches
        ]
        events.extend(
            {
                "ts": burst["start"],
                "label": f"burst x{burst['calls']}",
                "category": "network",
                "detail": f"{burst['rate']} calls/s between {burst['start']}s and {burst['end']}s",
            }
            for burst in result.bursts
        )
        self.strip.set_events(events, lanes=["process", "system", "network"])

        self.bursts.set_data(
            [[burst["start"], burst["end"], burst["calls"], burst["rate"]] for burst in result.bursts]
        )

        rows: list[list] = []
        for index, timestamp in enumerate(times):
            row = matrix[index] if index < len(matrix) else []
            total = sum(row)
            if not total:
                continue
            top = max(range(len(row)), key=lambda position: row[position]) if row else 0
            share = (row[top] / total * 100) if total else 0.0
            rows.append(
                [
                    f"{timestamp:.1f}",
                    total,
                    categories[top] if categories and top < len(categories) else "-",
                    f"{share:.0f}%",
                ]
            )
        rows.sort(key=lambda item: -item[1])
        self.windows.set_data(rows[:60])


# --------------------------------------------------------------------------- #
#  Sequence viewer
# --------------------------------------------------------------------------- #
class SequenceView(QWidget):
    """The core view: filterable call table, evidence pane and mined motifs."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._result: AnalysisResult | None = None
        self._calls: list = []
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(8)

        filters_card, fl = _card()
        fl.addWidget(section_label("Filters"))
        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(6)

        self.combo_process = QComboBox()
        self.combo_category = QComboBox()
        self.combo_api = QComboBox()
        self.combo_api.setEditable(True)
        self.edit_search = QLineEdit()
        self.edit_search.setPlaceholderText("Argument text contains…")
        self.chk_failed = QCheckBox("Failed calls only")
        self.chk_repeats = QCheckBox("Repeated runs only")
        self.spin_repeat = QSpinBox()
        self.spin_repeat.setRange(2, 5000)
        self.spin_repeat.setValue(3)
        self.spin_from = QDoubleSpinBox()
        self.spin_from.setRange(0.0, 1e9)
        self.spin_from.setDecimals(2)
        self.spin_to = QDoubleSpinBox()
        self.spin_to.setRange(0.0, 1e9)
        self.spin_to.setDecimals(2)
        self.spin_to.setValue(1e9)
        self.chk_suspicious = QCheckBox("Suspicious APIs only")

        for row, (label, widget) in enumerate(
            [
                ("Process", self.combo_process),
                ("Category", self.combo_category),
                ("API", self.combo_api),
            ]
        ):
            grid.addWidget(QLabel(label), row, 0)
            grid.addWidget(widget, row, 1)

        grid.addWidget(QLabel("From (s)"), 0, 2)
        grid.addWidget(self.spin_from, 0, 3)
        grid.addWidget(QLabel("To (s)"), 1, 2)
        grid.addWidget(self.spin_to, 1, 3)
        grid.addWidget(self.edit_search, 2, 2, 1, 2)

        flags, flagl = _row()
        flagl.addWidget(self.chk_failed)
        flagl.addWidget(self.chk_repeats)
        flagl.addWidget(self.spin_repeat)
        flagl.addWidget(self.chk_suspicious)
        flagl.addStretch(1)
        self.lbl_count = dim_label("")
        flagl.addWidget(self.lbl_count)
        grid.addWidget(flags, 3, 0, 1, 4)
        fl.addLayout(grid)

        for widget in (
            self.combo_process,
            self.combo_category,
            self.combo_api,
        ):
            widget.currentIndexChanged.connect(self._refresh)
        self.combo_api.editTextChanged.connect(self._refresh)
        self.edit_search.textChanged.connect(self._refresh)
        self.chk_failed.toggled.connect(self._refresh)
        self.chk_repeats.toggled.connect(self._refresh)
        self.chk_suspicious.toggled.connect(self._refresh)
        self.spin_repeat.valueChanged.connect(self._refresh)
        self.spin_from.valueChanged.connect(self._refresh)
        self.spin_to.valueChanged.connect(self._refresh)
        root.addWidget(filters_card)

        splitter = QSplitter(Qt.Vertical)
        self.table = DataTable(
            ["Time (s)", "PID", "Process", "Category", "API", "Status", "x", "Arguments", "Return"],
            export_name="api_calls",
        )
        self.table.setMinimumHeight(240)
        self.table.table.itemSelectionChanged.connect(self._show_detail)
        splitter.addWidget(self.table)

        bottom = QSplitter(Qt.Horizontal)
        motifs_card, mcl = _card()
        mcl.addWidget(section_label("Mined motifs (click to filter the table)"))
        self.motifs = DataTable(["Steps", "Support", "Process", "Start (s)", "Span (s)", "Chain"], export_name="motifs")
        self.motifs.table.doubleClicked.connect(lambda *_: self._focus_motif())
        motifs_card_layout = mcl
        motifs_card_layout.addWidget(self.motifs)
        bottom.addWidget(motifs_card)

        detail_card, dl = _card()
        dl.addWidget(section_label("Call evidence"))
        self.detail = _mono("Select a call to inspect its arguments.", 150)
        dl.addWidget(self.detail)
        bottom.addWidget(detail_card)
        bottom.setStretchFactor(0, 3)
        bottom.setStretchFactor(1, 2)
        splitter.addWidget(bottom)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

    # ------------------------------------------------------------------ helpers
    def _call_updates(self, result: AnalysisResult) -> None:
        processes = sorted({(call.process_id, call.process_name) for call in result.calls})
        self.combo_process.clear()
        self.combo_process.addItem("all processes", None)
        for pid, name in processes:
            self.combo_process.addItem(f"{name} (pid {pid})", pid)
        categories = sorted(result.categories())
        self.combo_category.clear()
        self.combo_category.addItem("all categories", None)
        for name in categories:
            self.combo_category.addItem(name, name)
        apis = sorted({call.api for call in result.calls})
        self.combo_api.clear()
        self.combo_api.addItem("")
        for name in apis:
            self.combo_api.addItem(name)
        maximum = max((call.timestamp for call in result.calls), default=0.0)
        self.spin_from.setMaximum(maximum or 1.0)
        self.spin_to.setMaximum(maximum or 1.0)
        self.spin_to.setValue(maximum or 1.0)

    def set_analysis(self, result: AnalysisResult | None) -> None:
        self._result = result
        if result is None:
            return
        self._call_updates(result)
        self.motifs.set_data([cluster.to_row() for cluster in result.clusters])
        self._refresh()

    # ------------------------------------------------------------------ filters
    def _refresh(self) -> None:
        result = self._result
        if result is None:
            return
        pid = self.combo_process.currentData()
        category = self.combo_category.currentData()
        api = (self.combo_api.currentText() or "").strip().lower()
        needle = (self.edit_search.text() or "").strip().lower()
        failed_only = self.chk_failed.isChecked()
        repeats_only = self.chk_repeats.isChecked()
        min_repeat = self.spin_repeat.value()
        suspicious_only = self.chk_suspicious.isChecked()
        start, end = self.spin_from.value(), self.spin_to.value()

        rows: list[list] = []
        kept: list = []
        for call in result.calls:
            if pid is not None and call.process_id != pid:
                continue
            if category and call.category != category:
                continue
            if api and api not in call.api.lower():
                continue
            if needle and needle not in call.arguments_text.lower():
                continue
            if failed_only and not call.failed:
                continue
            if repeats_only and call.repeated < min_repeat:
                continue
            if suspicious_only and not is_suspicious(call.api):
                continue
            if not (start <= call.timestamp <= end):
                continue
            rows.append(call.to_row() + [call.return_value or ""])
            kept.append(call)

        self._calls = kept
        self.table.set_data(rows)
        self.lbl_count.setText(f"{len(kept)} of {len(result.calls)} records shown")

    def _focus_motif(self) -> None:
        result = self._result
        index = self.motifs.selected_row_index()
        if result is None or index < 0 or index >= len(result.clusters):
            return
        cluster = result.clusters[index]
        self.edit_search.setText("")
        self.chk_failed.setChecked(False)
        apis = set(cluster.sequence)
        rows: list[list] = []
        kept: list = []
        for call in result.calls:
            if call.api not in apis:
                continue
            if cluster.process_id not in (None, call.process_id):
                continue
            rows.append(call.to_row() + [call.return_value or ""])
            kept.append(call)
        self._calls = kept
        self.table.set_data(rows)
        self.lbl_count.setText(f"motif filter: {len(kept)} records across {len(apis)} APIs")

    def _show_detail(self) -> None:
        index = self.table.selected_row_index()
        if index < 0 or index >= len(self._calls):
            return
        call = self._calls[index]
        lines = [
            f"API        : {call.api}",
            f"Category   : {call.category}",
            f"Time       : {call.timestamp:.3f}s",
            f"Process    : {call.process_name} (pid {call.process_id}"
            + (f", parent {call.parent_pid}" if call.parent_pid is not None else "")
            + ")",
            f"Status     : {call.status}",
            f"Return     : {call.return_value or '-'}",
            f"Repeated   : x{call.repeated}",
            f"Call id    : {call.call_id}",
        ]
        if call.arguments:
            lines.append("")
            lines.append("Arguments")
            for argument in call.arguments:
                lines.append(f"  {argument.name} = {argument.value}")
        self.detail.set_text("\n".join(lines))


# --------------------------------------------------------------------------- #
#  Patterns
# --------------------------------------------------------------------------- #
class PatternView(QWidget):
    """Behavioural findings plus the pattern catalogue they came from."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._result: AnalysisResult | None = None
        self._matches: list = []
        self._catalogue: list[dict] = detection.pattern_catalogue()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        self.stats = StatStrip()
        root.addWidget(self.stats)

        splitter = QSplitter(Qt.Horizontal)
        findings_card, fcl = _card()
        fcl.addWidget(section_label("Behavioural findings"))
        self.table = DataTable(
            ["Severity", "Pattern", "Process", "Start (s)", "Span (s)", "API chain", "Target"],
            export_name="findings",
        )
        self.table.rowSelected.connect(self._show_detail)
        fcl.addWidget(self.table)
        splitter.addWidget(findings_card)

        catalogue_card, ccl = _card()
        ccl.addWidget(section_label("Pattern catalogue"))
        self.catalogue = DataTable(
            ["ID", "Name", "Severity", "Steps", "Step sequence", "Gap", "Span cap", "Tags"],
            export_name="pattern_catalogue",
        )
        self.catalogue.set_data(
            [
                [
                    item["pattern_id"],
                    item["name"],
                    item["severity"],
                    item["steps"],
                    " -> ".join(item["steps"].split(" -> ")),
                    item["gap"],
                    item["max_span"],
                    ", ".join(item["tags"]),
                ]
                for item in self._catalogue
            ]
        )
        self.catalogue.table.itemSelectionChanged.connect(self._show_catalogue)
        ccl.addWidget(self.catalogue)
        splitter.addWidget(catalogue_card)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

        detail_card, dl = _card()
        dl.addWidget(section_label("Finding detail"))
        self.detail = _mono("Select a finding to see the matched calls and references.", 150)
        dl.addWidget(self.detail)
        root.addWidget(detail_card, 1)

    def set_analysis(self, result: AnalysisResult | None) -> None:
        self._result = result
        if result is None:
            return
        self._matches = list(result.matches)
        self.table.set_data([match.to_row() for match in self._matches])
        counts: dict[str, int] = {}
        for match in self._matches:
            counts[match.severity] = counts.get(match.severity, 0) + 1
        self.stats.set_stats(
            [
                ("Findings", len(self._matches), COLORS["warn"] if self._matches else COLORS["text_dim"]),
                ("Critical", counts.get("critical", 0), COLORS["bad"]),
                ("High", counts.get("high", 0), COLORS["bad"]),
                ("Medium", counts.get("medium", 0), COLORS["warn"]),
                ("Low / info", counts.get("low", 0) + counts.get("info", 0), COLORS["ok"]),
                ("Patterns in catalogue", len(self._catalogue), COLORS["text_dim"]),
            ]
        )

    def focus_pattern(self, pattern_id: str) -> None:
        for index, match in enumerate(self._matches):
            if match.pattern_id == pattern_id:
                self.table.table.selectRow(index)
                self._show_detail(index)
                return

    def _show_detail(self, index: int) -> None:
        if index < 0 or index >= len(self._matches):
            return
        match = self._matches[index]
        pattern = detection.PATTERN_INDEX.get(match.pattern_id)
        lines = [
            f"{match.pattern_id}  {match.name}",
            f"Severity   : {match.severity}",
            f"Process    : {match.process_name} (pid {match.process_id})",
            f"Window     : {match.start_ts:.3f}s .. {match.end_ts:.3f}s  (span {match.span:.3f}s)",
            f"Target     : {match.target or '-'}",
        ]
        if pattern is not None:
            lines.append(f"Steps      : {' -> '.join(step.glob for step in pattern.steps)}")
        lines.append("")
        lines.append("Matched calls")
        result = self._result
        calls = {call.call_id: call for call in (result.calls if result else [])}
        for call_id in match.call_ids:
            call = calls.get(call_id)
            if call is None:
                continue
            lines.append(
                f"  [{call.timestamp:8.3f}s] {call.api:34s} {call.arguments_text[:90]}"
            )
        if match.description:
            lines.append("")
            lines.append(match.description)
        for reference in match.references:
            lines.append(f"ref: {reference}")
        self.detail.set_text("\n".join(lines))

    def _show_catalogue(self) -> None:
        index = self.catalogue.selected_row_index()
        if index < 0 or index >= len(self._catalogue):
            return
        item = self._catalogue[index]
        lines = [
            f"{item['pattern_id']}  {item['name']}",
            f"Severity   : {item['severity']}",
            f"Gap        : up to {item['gap']} intervening calls per step",
            f"Span cap   : {item['max_span']}s",
            f"Tags       : {', '.join(item['tags']) or '-'}",
            "",
            item["description"],
            "",
            "Step sequence",
        ]
        lines.extend(f"  {position + 1}. {step}" for position, step in enumerate(item["steps"].split(" -> ")))
        for reference in item["references"]:
            lines.append(f"ref: {reference}")
        self.detail.set_text("\n".join(lines))


# --------------------------------------------------------------------------- #
#  Process tree
# --------------------------------------------------------------------------- #
class ProcessView(QWidget):
    """Reconstructed process tree with per-process behaviour detail."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._result: AnalysisResult | None = None
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        splitter = QSplitter(Qt.Horizontal)
        tree_card, tl = _card()
        tl.addWidget(section_label("Process tree"))
        tl.addWidget(dim_label("Parent links are taken from the report's own tree, then filled in from the calls."))
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Process", "PID", "Calls", "Failures"])
        self.tree.setAlternatingRowColors(True)
        self.tree.itemSelectionChanged.connect(self._show_detail)
        tl.addWidget(self.tree)
        splitter.addWidget(tree_card)

        detail_card, dl = _card()
        dl.addWidget(section_label("Process detail"))
        self.detail = _mono("Select a process.", 180)
        dl.addWidget(self.detail)
        dl.addWidget(section_label("Category mix"))
        self.chart = BarChart(height=170)
        dl.addWidget(self.chart)
        splitter.addWidget(detail_card)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

        table_card, tcl = _card()
        tcl.addWidget(section_label("Processes by call volume"))
        self.table = DataTable(
            ["Process", "PID", "Parent", "First seen (s)", "Calls", "Failures", "Top categories", "Path"],
            export_name="processes",
        )
        self.table.rowSelected.connect(lambda index: self._select_by_index(index))
        tcl.addWidget(self.table)
        root.addWidget(table_card, 1)

    def set_analysis(self, result: AnalysisResult | None) -> None:
        self._result = result
        if result is None:
            return
        self.tree.clear()
        nodes = {node.process_id: node for node in result.processes}
        children: dict[int | None, list[int]] = {}
        for node in result.processes:
            parent = node.parent_pid if node.parent_pid in nodes else None
            children.setdefault(parent, []).append(node.process_id)

        def build(pid: int, parent_item: QTreeWidgetItem | None) -> None:
            node = nodes[pid]
            item = QTreeWidgetItem(
                [
                    node.process_name + ("  *" if node.suspicious else ""),
                    str(node.process_id),
                    str(node.call_count),
                    str(node.failed_calls),
                ]
            )
            item.setData(0, Qt.UserRole, pid)
            if node.suspicious:
                item.setForeground(0, Qt.GlobalColor.red)
            if parent_item is None:
                self.tree.addTopLevelItem(item)
            else:
                parent_item.addChild(item)
            for child in sorted(children.get(pid, [])):
                build(child, item)

        roots = children.get(None, [])
        for pid in roots or [node.process_id for node in result.processes]:
            build(pid, None)
        self.tree.expandAll()
        self.table.set_data([node.to_row() for node in result.processes])
        if result.processes:
            self._select_by_index(0)

    def _select_by_index(self, index: int) -> None:
        result = self._result
        if result is None or index < 0 or index >= len(result.processes):
            return
        self._render(result.processes[index])

    def _show_detail(self) -> None:
        result = self._result
        items = self.tree.selectedItems()
        if result is None or not items:
            return
        pid = items[0].data(0, Qt.UserRole)
        node = next((item for item in result.processes if item.process_id == pid), None)
        if node is not None:
            self._render(node)

    def _render(self, node) -> None:
        result = self._result
        lines = [
            f"Process    : {node.process_name}",
            f"PID        : {node.process_id}",
            f"Parent     : {node.parent_pid if node.parent_pid is not None else '-'}",
            f"First seen : {node.first_seen:.3f}s",
            f"Calls      : {node.call_count}  (failed: {node.failed_calls})",
            f"Path       : {node.path or '-'}",
        ]
        if node.command_line:
            lines.append(f"Command    : {node.command_line}")
        if node.note:
            lines.append("")
            lines.append(f"Notes      : {node.note}")
        if result is not None:
            apis: dict[str, int] = {}
            for call in result.calls:
                if call.process_id == node.process_id:
                    apis[call.api] = apis.get(call.api, 0) + call.weight
            if apis:
                lines.append("")
                lines.append("Top APIs")
                for name, count in sorted(apis.items(), key=lambda item: -item[1])[:12]:
                    lines.append(f"  {count:6d}  {name}")
        self.detail.set_text("\n".join(lines))
        if node.categories:
            labels = list(node.categories.keys())
            self.chart.set_data(
                labels,
                [node.categories[name] for name in labels],
                unit=" calls",
                bands=[(1e12, COLORS["accent"])],
            )
        else:
            self.chart.set_data([], [])


# --------------------------------------------------------------------------- #
#  Graph
# --------------------------------------------------------------------------- #
class GraphView(QWidget):
    """Markov behaviour graph with the underlying transition table."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._result: AnalysisResult | None = None
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        graph_card, gl = _card()
        gl.addWidget(section_label("API transition graph"))
        gl.addWidget(
            dim_label(
                "Nodes are APIs sized by call volume; arrows are first-order transitions, "
                "thickness scaled by count. Click a node to filter the transition table."
            )
        )
        self.graph = BehaviorGraph()
        self.graph.nodeClicked.connect(self._focus_api)
        gl.addWidget(self.graph, 1)
        root.addWidget(graph_card, 2)

        splitter = QSplitter(Qt.Horizontal)
        trans_card, tl = _card()
        tl.addWidget(section_label("Transitions"))
        self.table = DataTable(["From", "To", "Count", "Probability", "Process"], export_name="transitions")
        tl.addWidget(self.table)
        splitter.addWidget(trans_card)

        path_card, pl = _card()
        pl.addWidget(section_label("Highest-probability behaviour paths"))
        self.paths = _mono("Run an analysis to derive paths.", 160)
        pl.addWidget(self.paths)
        pl.addWidget(section_label("Most common APIs"))
        self.apis = DataTable(["API", "Calls"], export_name="api_frequency")
        pl.addWidget(self.apis)
        splitter.addWidget(path_card)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        root.addWidget(splitter, 1)

    def set_analysis(self, result: AnalysisResult | None) -> None:
        self._result = result
        if result is None:
            return
        counts: dict[str, int] = {}
        categories: dict[str, str] = {}
        for call in result.calls:
            counts[call.api] = counts.get(call.api, 0) + call.weight
            categories.setdefault(call.api, call.category)
        nodes = [
            {"name": name, "count": count, "category": categories.get(name, "other")}
            for name, count in sorted(counts.items(), key=lambda item: -item[1])[:22]
        ]
        self.graph.set_graph(
            nodes,
            [
                {
                    "source": transition.source,
                    "target": transition.target,
                    "count": transition.count,
                }
                for transition in result.transitions
                if transition.target
            ],
        )
        self.table.set_data([transition.to_row() for transition in result.transitions])
        self.paths.set_text(
            "\n".join(" -> ".join(path) for path in result.paths) or "No multi-step paths were derived."
        )
        self.apis.set_data([[name, count] for name, count in sorted(counts.items(), key=lambda item: -item[1])[:40]])

    def _focus_api(self, api: str) -> None:
        result = self._result
        if result is None:
            return
        rows = [
            transition.to_row()
            for transition in result.transitions
            if transition.source == api or transition.target == api
        ]
        self.table.set_data(rows or [transition.to_row() for transition in result.transitions])


# --------------------------------------------------------------------------- #
#  Heatmap
# --------------------------------------------------------------------------- #
class HeatmapView(QWidget):
    """Process x category heatmap plus API frequency breakdown."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._result: AnalysisResult | None = None
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        heat_card, hl = _card()
        hl.addWidget(section_label("Behaviour heatmap — processes x API categories"))
        hl.addWidget(dim_label("Darker cells mean more calls. Click a cell to inspect the matching calls."))
        self.heatmap = HeatmapWidget()
        self.heatmap.cellClicked.connect(self._cell_clicked)
        hl.addWidget(self.heatmap, 1)
        root.addWidget(heat_card, 2)

        splitter = QSplitter(Qt.Horizontal)
        api_card, al = _card()
        al.addWidget(section_label("API frequency"))
        self.apis = DataTable(["API", "Category", "Calls", "Processes", "Failures", "Suspicion"], export_name="api_frequency")
        al.addWidget(self.apis)
        splitter.addWidget(api_card)

        detail_card, dl = _card()
        dl.addWidget(section_label("Cell detail"))
        self.detail = _mono("Click a heatmap cell.", 200)
        dl.addWidget(self.detail)
        splitter.addWidget(detail_card)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

    def set_analysis(self, result: AnalysisResult | None) -> None:
        self._result = result
        if result is None:
            return
        rows, columns, grid = result.heatmap()
        self.heatmap.set_matrix(rows, columns, grid)

        stats: dict[str, dict] = {}
        for call in result.calls:
            entry = stats.setdefault(
                call.api,
                {"category": call.category, "calls": 0, "processes": set(), "failed": 0, "suspicion": ""},
            )
            entry["calls"] += call.weight
            entry["processes"].add(call.process_id)
            if call.failed:
                entry["failed"] += call.weight
            entry["suspicion"] = entry["suspicion"] or is_suspicious(call.api)
        self.apis.set_data(
            [
                [
                    name,
                    entry["category"],
                    entry["calls"],
                    len(entry["processes"]),
                    entry["failed"],
                    entry["suspicion"] or "-",
                ]
                for name, entry in sorted(stats.items(), key=lambda item: -item[1]["calls"])
            ]
        )

    def _cell_clicked(self, row: int, column: int, value: int) -> None:
        result = self._result
        if result is None:
            return
        rows, columns, _grid = result.heatmap()
        if row >= len(rows):
            return
        label = rows[row]
        pid = None
        if "(" in label and label.endswith(")"):
            try:
                pid = int(label.rsplit("(", 1)[1].rstrip(")"))
            except ValueError:
                pid = None
        category = columns[column] if column < len(columns) else ""
        matching = [
            call
            for call in result.calls
            if call.category == category and (pid is None or call.process_id == pid)
        ]
        lines = [
            f"Process : {label}",
            f"Category: {category}",
            f"Calls   : {value}",
            "",
        ]
        for call in matching[:40]:
            lines.append(f"  [{call.timestamp:8.3f}s] {call.api:34s} {call.arguments_text[:80]}")
        if len(matching) > 40:
            lines.append(f"  … {len(matching) - 40} further calls")
        self.detail.set_text("\n".join(lines) if matching else "No calls in this cell.")


# --------------------------------------------------------------------------- #
#  IOCs
# --------------------------------------------------------------------------- #
class IOCView(QWidget):
    """Indicators extracted from the call stream and the report summary."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._iocs: list[dict] = []
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        self.stats = StatStrip()
        root.addWidget(self.stats)

        controls, cl = _row()
        cl.addWidget(QLabel("Type filter"))
        self.combo = QComboBox()
        self.combo.addItem("all types", None)
        for name in ("url", "ipv4", "domain", "file", "registry", "mutex", "service", "command"):
            self.combo.addItem(name, name)
        self.combo.currentIndexChanged.connect(self._refresh)
        cl.addWidget(self.combo)
        self.chk_high = QCheckBox("Confidence ≥ 0.8")
        self.chk_high.toggled.connect(self._refresh)
        cl.addWidget(self.chk_high)
        cl.addStretch(1)
        btn_copy = QPushButton("Copy all indicators")
        btn_copy.clicked.connect(self._copy)
        btn_export = QPushButton("Export IOC list (CSV)")
        btn_export.clicked.connect(self._export)
        cl.addWidget(btn_copy)
        cl.addWidget(btn_export)
        root.addWidget(controls)

        self.table = DataTable(
            ["Type", "Value", "Confidence", "Source", "Context"], export_name="indicators"
        )
        root.addWidget(self.table, 1)

        self.defanged = _mono("", 110)
        root.addWidget(self.defanged)

    def set_analysis(self, result: AnalysisResult | None) -> None:
        self._iocs = list(result.iocs) if result else []
        counts: dict[str, int] = {}
        for item in self._iocs:
            counts[item["type"]] = counts.get(item["type"], 0) + 1
        self.stats.set_stats(
            [("Indicators", len(self._iocs), COLORS["accent"])]
            + [(name, counts.get(name, 0), COLORS["info"]) for name in ("url", "ipv4", "domain", "file", "registry")]
        )
        self._refresh()

    def _refresh(self) -> None:
        kind = self.combo.currentData()
        minimum = 0.8 if self.chk_high.isChecked() else 0.0
        rows = [
            [item["type"], item["value"], f"{item.get('confidence', 0):.2f}", item.get("source", ""), item.get("context", "")]
            for item in self._iocs
            if (kind is None or item["type"] == kind) and float(item.get("confidence", 0)) >= minimum
        ]
        self.table.set_data(rows)
        self.defanged.set_text(
            "Defanged indicator list (safe to paste into a ticket)\n\n"
            + "\n".join(
                f"{row[0]:9s} {row[1].replace('.', '[.]').replace('http', 'hxxp')}"
                for row in rows[:60]
            )
        )

    def _copy(self) -> None:
        from PySide6.QtWidgets import QApplication

        lines = [
            f"{row[0]}\t{row[1]}\t{row[2]}\t{row[3]}"
            for row in self._visible_rows()
        ]
        QApplication.clipboard().setText("\n".join(lines))

    def _visible_rows(self) -> list[list]:
        return [
            [item["type"], item["value"], f"{item.get('confidence', 0):.2f}", item.get("source", "")]
            for item in self._iocs
        ]

    def _export(self) -> None:
        self.table.save_csv()
