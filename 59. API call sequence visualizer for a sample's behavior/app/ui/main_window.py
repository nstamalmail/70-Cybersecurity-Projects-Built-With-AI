"""Main window: tab layout, threaded analysis, settings and reports.

The window owns one :class:`~app.core.engine.Engine` and one
:class:`~app.core.engine.AnalysisResult`; every view receives the same result
through its ``set_analysis`` slot so the tabs always agree with each other.
"""
from __future__ import annotations

import json
import traceback
from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QSpinBox,
    QVBoxLayout,
)

from app import demo
from app.config import APP, cases_dir, cache_dir, data_root, demo_dir, logs_dir, patterns_dir
from app.core import detection, iocs as iocmod
from app.core.categorize import CATEGORIES
from app.core.engine import AnalysisResult, Engine, engine_info
from app.reporting import Report
from app.ui import views as views_mod
from app.ui.report_panel import _open_path
from app.ui.shell import AppShell


# --------------------------------------------------------------------------- #
#  Worker
# --------------------------------------------------------------------------- #
class RunWorker(QThread):
    """Runs one analysis off the UI thread."""

    progress = Signal(float, str)
    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(self, engine: Engine, *, path: str = "", demo_key: str = "", parent=None) -> None:
        super().__init__(parent)
        self.engine = engine
        self.path = path
        self.demo_key = demo_key

    def run(self) -> None:  # noqa: D102 - QThread entry point
        try:
            if self.demo_key:
                result = demo.run_demo(self.engine, self.demo_key, progress=self.progress.emit)
            else:
                result = self.engine.analyse_path(self.path, progress=self.progress.emit)
            self.finished_ok.emit(result)
        except Exception as exc:  # pragma: no cover - surfaced in the UI
            self.failed.emit(f"{exc.__class__.__name__}: {exc}\n\n{traceback.format_exc()}")


# --------------------------------------------------------------------------- #
#  Settings
# --------------------------------------------------------------------------- #
class SettingsDialog(QDialog):
    """Analysis tuning knobs (all persisted to settings.json)."""

    def __init__(self, settings, parent=None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle(f"{APP['name']} — settings")
        self.setMinimumWidth(460)
        root = QVBoxLayout(self)
        form = QFormLayout()

        self.spin_max_calls = QSpinBox()
        self.spin_max_calls.setRange(10_000, 20_000_000)
        self.spin_max_calls.setSingleStep(10_000)
        self.spin_max_calls.setValue(int(settings.get("max_calls", 2_000_000)))
        form.addRow("Maximum parsed calls", self.spin_max_calls)

        self.spin_mine = QSpinBox()
        self.spin_mine.setRange(1_000, 2_000_000)
        self.spin_mine.setSingleStep(1_000)
        self.spin_mine.setValue(int(settings.get("mine_max_calls", 120_000)))
        form.addRow("Mining sample size", self.spin_mine)

        self.spin_collapse = QSpinBox()
        self.spin_collapse.setRange(2, 500)
        self.spin_collapse.setValue(int(settings.get("collapse_threshold", 3)))
        form.addRow("Loop collapse threshold", self.spin_collapse)

        self.spin_min_occ = QSpinBox()
        self.spin_min_occ.setRange(2, 100)
        self.spin_min_occ.setValue(int(settings.get("ngram_min_occurrences", 2)))
        form.addRow("Minimum n-gram occurrences", self.spin_min_occ)

        self.spin_top = QSpinBox()
        self.spin_top.setRange(5, 2000)
        self.spin_top.setValue(int(settings.get("ngram_top", 60)))
        form.addRow("N-grams reported", self.spin_top)

        self.spin_support = QSpinBox()
        self.spin_support.setRange(2, 100)
        self.spin_support.setValue(int(settings.get("cluster_min_support", 2)))
        form.addRow("Cluster minimum support", self.spin_support)

        self.combo_severity = QComboBox()
        for name in ("info", "low", "medium", "high", "critical"):
            self.combo_severity.addItem(name, name)
        index = self.combo_severity.findData(str(settings.get("pattern_min_severity", "low")))
        self.combo_severity.setCurrentIndex(max(0, index))
        form.addRow("Minimum pattern severity", self.combo_severity)

        self.spin_conf = QDoubleSpinBox()
        self.spin_conf.setRange(0.0, 1.0)
        self.spin_conf.setSingleStep(0.05)
        self.spin_conf.setValue(float(settings.get("ioc_min_confidence", 0.0)))
        form.addRow("Minimum IOC confidence", self.spin_conf)

        self.spin_burst = QSpinBox()
        self.spin_burst.setRange(5, 5000)
        self.spin_burst.setValue(int(settings.get("burst_threshold", 40)))
        form.addRow("Burst threshold (calls/s)", self.spin_burst)

        self.edit_ignore = QLineEdit(", ".join(settings.get("ignore_categories", []) or []))
        self.edit_ignore.setPlaceholderText("categories to ignore, e.g. system, sync")
        form.addRow("Ignored categories", self.edit_ignore)

        self.spin_buckets = QSpinBox()
        self.spin_buckets.setRange(20, 1000)
        self.spin_buckets.setValue(int(settings.get("timeline_buckets", 120)))
        form.addRow("Timeline buckets", self.spin_buckets)

        root.addLayout(form)
        note = QLabel(
            "Analysis runs offline. Reports, cases and exported artefacts stay in "
            f"{data_root()}."
        )
        note.setWordWrap(True)
        note.setProperty("role", "dim")
        root.addWidget(note)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def apply(self) -> None:
        s = self.settings
        s.set("max_calls", self.spin_max_calls.value())
        s.set("mine_max_calls", self.spin_mine.value())
        s.set("collapse_threshold", self.spin_collapse.value())
        s.set("ngram_min_occurrences", self.spin_min_occ.value())
        s.set("ngram_top", self.spin_top.value())
        s.set("cluster_min_support", self.spin_support.value())
        s.set("pattern_min_severity", self.combo_severity.currentData())
        s.set("ioc_min_confidence", float(self.spin_conf.value()))
        s.set("burst_threshold", self.spin_burst.value())
        s.set("timeline_buckets", self.spin_buckets.value())
        s.set(
            "ignore_categories",
            [part.strip() for part in self.edit_ignore.text().split(",") if part.strip()],
        )
        s.save()


# --------------------------------------------------------------------------- #
#  Main window
# --------------------------------------------------------------------------- #
class MainWindow(AppShell):
    def __init__(self) -> None:
        from app.config import SETTINGS

        super().__init__()
        self.engine = Engine(SETTINGS, self.bus)
        self.result: AnalysisResult | None = None
        self.report: Report | None = None
        self._worker: RunWorker | None = None
        self._ingest.bind_settings(self.settings)
        self.refresh_recent()

    # ------------------------------------------------------------- app wiring
    @property
    def settings(self):
        from app.config import SETTINGS

        return SETTINGS

    def build_tabs(self) -> None:
        self._ingest = views_mod.IngestView()
        self._overview = views_mod.OverviewView()
        self._timeline = views_mod.TimelineView()
        self._sequences = views_mod.SequenceView()
        self._patterns = views_mod.PatternView()
        self._processes = views_mod.ProcessView()
        self._graph = views_mod.GraphView()
        self._heatmap = views_mod.HeatmapView()
        self._iocs = views_mod.IOCView()

        for widget, title in (
            (self._ingest, "Ingest"),
            (self._overview, "Overview"),
            (self._timeline, "Timeline"),
            (self._sequences, "Call sequence"),
            (self._patterns, "Patterns"),
            (self._processes, "Process tree"),
            (self._graph, "Behaviour graph"),
            (self._heatmap, "Heatmap"),
            (self._iocs, "Indicators"),
        ):
            self.add_tab(widget, title)

        self._ingest.analyseReport.connect(self.run_path)
        self._ingest.analyseDemo.connect(self.run_demo)
        self._overview.patternSelected.connect(self._focus_pattern)

    def current_report(self) -> Report | None:
        return self.report

    def open_artifact(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(
            self,
            "Open sandbox report",
            str(demo_dir()),
            "Sandbox reports (*.json *.jsonl *.bson *.log);;All files (*)",
        )
        if path:
            self.run_path(path)

    def build_tools_menu(self, menu) -> None:
        act_settings = QAction("Analysis settings…", self)
        act_settings.triggered.connect(self.open_settings)
        menu.addAction(act_settings)
        act_demo_all = QAction("Run every demo fixture", self)
        act_demo_all.triggered.connect(self.run_all_demos)
        menu.addAction(act_demo_all)
        menu.addSeparator()

        act_catalogue = QAction("Export pattern catalogue (JSON)", self)
        act_catalogue.triggered.connect(self.export_catalogue)
        menu.addAction(act_catalogue)
        act_info = QAction("Engine information…", self)
        act_info.triggered.connect(self.show_engine_info)
        menu.addAction(act_info)
        menu.addSeparator()

        act_demo_dir = QAction("Open demo fixture folder", self)
        act_demo_dir.triggered.connect(lambda: _open_path(demo_dir()))
        menu.addAction(act_demo_dir)
        act_patterns = QAction("Open pattern library folder", self)
        act_patterns.triggered.connect(lambda: _open_path(patterns_dir()))
        menu.addAction(act_patterns)
        act_cases = QAction("Open cases folder", self)
        act_cases.triggered.connect(lambda: _open_path(cases_dir()))
        menu.addAction(act_cases)
        act_logs = QAction("Open logs folder", self)
        act_logs.triggered.connect(lambda: _open_path(logs_dir()))
        menu.addAction(act_logs)
        act_cache = QAction("Open cache folder", self)
        act_cache.triggered.connect(lambda: _open_path(cache_dir()))
        menu.addAction(act_cache)

    # ------------------------------------------------------------------ runs
    def run_path(self, path: str) -> None:
        target = Path(path)
        if not target.exists():
            QMessageBox.warning(self, APP["name"], f"File not found:\n{target}")
            return
        self._ingest.apply_to_settings(self.settings)
        self.settings.save()
        self._start_worker(RunWorker(self.engine, path=str(target)))

    def run_demo(self, key: str) -> None:
        self._ingest.apply_to_settings(self.settings)
        self.settings.save()
        self._start_worker(RunWorker(self.engine, demo_key=key))

    def run_all_demos(self) -> None:
        for kind, _label in demo.fixtures():
            self.log(f"Running demo fixture: {kind}")
            result = demo.run_demo(self.engine, kind)
            self._ingest.apply_to_settings(self.settings)
            self._apply_result(result)
        self.log(f"All {len(demo.fixtures())} demo fixtures analysed", "ok")
        self.show_report_tab()

    def _start_worker(self, worker: RunWorker) -> None:
        if self._worker is not None and self._worker.isRunning():
            QMessageBox.information(self, APP["name"], "An analysis is already running.")
            return
        self._worker = worker
        worker.progress.connect(self._on_progress)
        worker.finished_ok.connect(self._on_finished)
        worker.failed.connect(self._on_failed)
        self.set_status("Analysing…")
        self.log(f"Starting analysis of {worker.path or worker.demo_key}")
        worker.start()

    def _on_progress(self, fraction: float, message: str) -> None:
        self.set_status(f"[{fraction * 100:4.0f}%] {message}")

    def _on_finished(self, result: AnalysisResult) -> None:
        self._apply_result(result)
        self.show_report_tab()

    def _on_failed(self, message: str) -> None:
        self.log(f"Analysis failed: {message}", "error")
        self.set_status("Analysis failed")
        QMessageBox.critical(self, APP["name"], f"Analysis failed:\n\n{message}")

    def _apply_result(self, result: AnalysisResult) -> None:
        self.result = result
        report = self.engine.build_report(result)
        self.report = report
        for view in (
            self._overview,
            self._timeline,
            self._sequences,
            self._patterns,
            self._processes,
            self._graph,
            self._heatmap,
            self._iocs,
        ):
            try:
                view.set_analysis(result)
            except Exception as exc:  # a broken view must not kill the run
                self.log(f"View update failed ({view.__class__.__name__}): {exc}", "error")
        self.set_header_chips(
            [
                (result.source_format, "info" if result.source_format != "unknown" else "medium"),
                (f"{result.call_count} calls", "info"),
                (f"{len(result.processes)} procs", "info"),
                (f"{len(result.matches)} findings", "medium" if result.matches else "low"),
                (result.severity, result.severity),
            ]
        )
        self.set_status(
            f"{result.source_name or 'report'}: {result.call_count} calls · "
            f"{len(result.matches)} findings · score {result.score}/100 ({result.severity})"
        )
        self._record_recent(result)
        self.refresh_report()
        self.refresh_recent()

    def _focus_pattern(self, pattern_id: str) -> None:
        self.tabs.setCurrentWidget(self._patterns)
        self._patterns.focus_pattern(pattern_id)

    # --------------------------------------------------------------- menu acts
    def open_settings(self) -> None:
        dialog = SettingsDialog(self.settings, self)
        if dialog.exec() == QDialog.Accepted:
            dialog.apply()
            self._ingest.bind_settings(self.settings)
            self.log("Settings saved", "ok")

    def export_catalogue(self) -> None:
        path = patterns_dir() / "pattern_catalogue.json"
        payload = {
            "app": APP["name"],
            "version": APP["version"],
            "patterns": detection.pattern_catalogue(),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.log(f"Pattern catalogue written to {path}", "ok")
        _open_path(path.parent)

    def show_engine_info(self) -> None:
        info = engine_info()
        QMessageBox.information(
            self,
            "Engine information",
            f"<b>{APP['name']}</b> v{APP['version']}<br><br>"
            f"Behavioural patterns: <b>{info['patterns']}</b><br>"
            f"Categories: {', '.join(CATEGORIES)}<br>"
            f"Indicators: {', '.join(iocmod.IocCollector.TYPE_ORDER)}<br><br>"
            "Mining: frequent n-grams, maximal recurring clusters, first-order Markov transitions.",
        )

    # --------------------------------------------------------------- recents
    def refresh_recent(self) -> None:
        path = data_root() / "recent.json"
        rows: list[list] = []
        if path.exists():
            try:
                rows = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                rows = []
        self._ingest.set_recent(rows)

    def _record_recent(self, result: AnalysisResult) -> None:
        import datetime as _dt

        path = data_root() / "recent.json"
        rows: list[list] = []
        if path.exists():
            try:
                rows = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                rows = []
        rows.insert(
            0,
            [
                _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                result.meta.sample_name or result.source_name,
                result.source_format,
                result.call_count,
                len(result.processes),
                len(result.matches),
                result.severity,
                f"{result.score}/100",
                result.source_path,
            ],
        )
        path.write_text(json.dumps(rows[:50], indent=1), encoding="utf-8")

    # ------------------------------------------------------------- life cycle
    def closeEvent(self, event) -> None:  # noqa: N802
        worker = self._worker
        if worker is not None and worker.isRunning():
            worker.terminate()
            worker.wait(1500)
        self.settings.save()
        super().closeEvent(event)
