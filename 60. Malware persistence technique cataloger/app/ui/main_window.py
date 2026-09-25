"""Main window: tab layout, threaded analysis, settings and reports."""
from __future__ import annotations

import json
import traceback
from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QFileDialog, QMessageBox,
)

from app import demo
from app.config import APP, data_root, reports_dir
from app.core.engine import AnalysisResult, Engine
from app.reporting import Report
from app.ui import views as views_mod
from app.ui.report_panel import _open_path
from app.ui.shell import AppShell


class RunWorker(QThread):
    progress = Signal(float, str)
    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(self, engine, *, path: str = "", demo_key: str = "", parent=None) -> None:
        super().__init__(parent)
        self.engine = engine
        self.path = path
        self.demo_key = demo_key

    def run(self) -> None:
        try:
            if self.demo_key:
                result = demo.run_demo(self.engine, self.demo_key, progress=self.progress.emit)
            else:
                result = self.engine.analyse_path(self.path, progress=self.progress.emit) if hasattr(self.engine, 'analyse_path') else self.engine.analyze(self.path)
            self.finished_ok.emit(result)
        except Exception as exc:
            self.failed.emit(f"{exc.__class__.__name__}: {exc}\n\n{traceback.format_exc()}")


class MainWindow(AppShell):
    def __init__(self) -> None:
        from app.config import SETTINGS
        super().__init__()
        self.engine = Engine(SETTINGS, self.bus)
        self.result: AnalysisResult | None = None
        self.report: Report | None = None
        self._worker: RunWorker | None = None
        self.refresh_recent()

    @property
    def settings(self):
        from app.config import SETTINGS
        return SETTINGS

    def build_tabs(self) -> None:
        self._ingest = views_mod.IngestView()
        self._catalog = views_mod.CatalogView()
        self._processes = views_mod.ProcessTreeView()
        self._attack = views_mod.ATTnCKView()
        self._iocs = views_mod.IOCView()

        for widget, title in (
            (self._ingest, "Ingest"),
            (self._catalog, "Persistence Catalog"),
            (self._processes, "Process Tree"),
            (self._attack, "ATT&CK Map"),
            (self._iocs, "Indicators"),
        ):
            self.add_tab(widget, title)

        self._ingest.analyseReport.connect(self.run_path)
        self._ingest.analyseDemo.connect(self.run_demo)

    def current_report(self) -> Report | None:
        return self.report

    def open_artifact(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open sandbox report", str(demo_dir()), "All files (*)")
        if path:
            self.run_path(path)

    def build_tools_menu(self, menu) -> None:
        act_demo_all = QAction("Run every demo fixture", self)
        act_demo_all.triggered.connect(self.run_all_demos)
        menu.addAction(act_demo_all)
        menu.addSeparator()
        act_catalogue = QAction("Export pattern catalogue (JSON)", self)
        act_catalogue.triggered.connect(self.export_catalogue)
        menu.addAction(act_catalogue)

    def run_path(self, path: str) -> None:
        target = Path(path)
        if not target.exists():
            QMessageBox.warning(self, APP["name"], f"File not found:\n{target}")
            return
        self._start_worker(RunWorker(self.engine, path=str(target)))

    def run_demo(self, key: str) -> None:
        self._start_worker(RunWorker(self.engine, demo_key=key))

    def run_all_demos(self) -> None:
        for kind, _label in demo.fixtures():
            self.log(f"Running demo: {kind}")
            result = demo.run_demo(self.engine, kind)
            self._apply_result(result)
        self.log(f"All {len(demo.fixtures())} demos analysed", "ok")
        self.show_report_tab()

    def _start_worker(self, worker: RunWorker) -> None:
        if self._worker is not None and self._worker.isRunning():
            QMessageBox.information(self, APP["name"], "An analysis is already running.")
            return
        self._worker = worker
        worker.progress.connect(lambda f, m: self.set_status(f"[{f*100:4.0f}%] {m}"))
        worker.finished_ok.connect(self._on_finished)
        worker.failed.connect(self._on_failed)
        self.set_status("Analysing...")
        self.log(f"Starting analysis of {worker.path or worker.demo_key}")
        worker.start()

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
        for view in (self._catalog, self._processes, self._attack, self._iocs):
            try:
                view.set_analysis(result)
            except Exception as exc:
                self.log(f"View update failed ({view.__class__.__name__}): {exc}", "error")
        self.set_header_chips([
            (result.source_format, "info"),
            (f"{len(result.calls)} calls", "info"),
            (f"{len(result.artifacts)} persistence", "medium" if result.artifacts else "low"),
            (result.severity, result.severity),
        ])
        self.set_status(f"{result.source_name}: {len(result.artifacts)} persistence mechanisms, score {result.score}/100 ({result.severity})")
        self._record_recent(result)
        self.refresh_report()
        self.refresh_recent()

    def export_catalogue(self) -> None:
        from app.config import patterns_dir
        path = patterns_dir() / "pattern_catalogue.json"
        payload = {"app": APP["name"], "version": APP["version"],
                   "patterns": detection.pattern_catalogue()}
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.log(f"Pattern catalogue written to {path}", "ok")
        _open_path(path.parent)

    def refresh_recent(self) -> None:
        path = data_root() / "recent.json"
        rows = []
        if path.exists():
            try:
                rows = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                rows = []
        self._ingest.set_recent(rows)

    def _record_recent(self, result: AnalysisResult) -> None:
        import datetime as _dt
        path = data_root() / "recent.json"
        rows = []
        if path.exists():
            try:
                rows = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                rows = []
        rows.insert(0, [
            _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            result.meta.sample_name or result.source_name, result.source_format,
            len(result.artifacts), f"{result.score}/100", result.source_path,
        ])
        path.write_text(json.dumps(rows[:50], indent=1), encoding="utf-8")

    def closeEvent(self, event) -> None:
        worker = self._worker
        if worker is not None and worker.isRunning():
            worker.terminate()
            worker.wait(1500)
        self.settings.save()
        super().closeEvent(event)


# Need to import detection for the export_catalogue method
from app.core import detection  # noqa: E402
