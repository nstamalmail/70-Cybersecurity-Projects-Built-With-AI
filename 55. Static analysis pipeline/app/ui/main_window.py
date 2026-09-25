"""Main window: wires the views to the analysis engine on a worker thread."""
from __future__ import annotations

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QSpinBox,
    QVBoxLayout,
)

from app.config import APP, SETTINGS, cases_dir, data_root, settings_path
from app.core.engine import AnalysisEngine, AnalysisResult
from app.demo import DEMO_NOTICE
from app.reporting import Report, verdict_color
from app.ui.report_panel import _open_path
from app.ui.shell import AppShell
from app.ui.theme import COLORS
from app.ui.views import (
    CapabilitiesView,
    HashView,
    IOCView,
    PEView,
    SampleView,
    StringsView,
    VerdictView,
)


class AnalyzeWorker(QThread):
    """Runs the pipeline off the UI thread and streams stage updates."""

    stageChanged = Signal(str, int, int)
    finishedOk = Signal(object)
    failed = Signal(str)

    def __init__(self, engine: AnalysisEngine, *, path: str | None = None, demo_kind: str | None = None, parent=None) -> None:
        super().__init__(parent)
        self.engine = engine
        self.path = path
        self.demo_kind = demo_kind

    def run(self) -> None:  # noqa: D102 (QThread API)
        try:
            def progress(stage: str, done: int = 0, total: int = 0) -> None:
                self.stageChanged.emit(stage, done, total)

            if self.demo_kind:
                from app import demo

                result = demo.run_demo(self.engine, self.demo_kind, progress=progress)
            else:
                result = self.engine.analyze(self.path, progress=progress)
            self.finishedOk.emit(result)
        except Exception as exc:  # surfaced in the UI and the console
            self.failed.emit(str(exc))


class SettingsDialog(QDialog):
    """Local configuration: thresholds and optional threat-intel API keys."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"{APP['name']} \u2014 Settings")
        self.resize(560, 320)
        root = QVBoxLayout(self)
        form = QFormLayout()

        self.minlen = QSpinBox()
        self.minlen.setRange(4, 32)
        self.minlen.setValue(int(SETTINGS.get("min_string_length", 4)))
        self.maxmb = QSpinBox()
        self.maxmb.setRange(1, 4096)
        self.maxmb.setValue(int(SETTINGS.get("max_file_size_mb", 500)))
        self.maxmb.setSuffix(" MB")
        self.analyst = QLineEdit(str(SETTINGS.get("analyst", "analyst")))
        self.network = QCheckBox("Enable network threat intel lookups (hash only)")
        self.network.setChecked(bool(SETTINGS.get("enable_network_lookups")))
        self.vt = QLineEdit(str(SETTINGS.get("virustotal_api_key", "")))
        self.vt.setEchoMode(QLineEdit.Password)
        self.mb = QLineEdit(str(SETTINGS.get("malwarebazaar_api_key", "")))
        self.mb.setEchoMode(QLineEdit.Password)
        self.otx = QLineEdit(str(SETTINGS.get("otx_api_key", "")))
        self.otx.setEchoMode(QLineEdit.Password)

        form.addRow("Analyst name", self.analyst)
        form.addRow("Minimum string length", self.minlen)
        form.addRow("Maximum file size", self.maxmb)
        form.addRow("", self.network)
        form.addRow("VirusTotal API key", self.vt)
        form.addRow("MalwareBazaar API key", self.mb)
        form.addRow("AlienVault OTX API key", self.otx)
        root.addLayout(form)

        note = QLabel(
            "Keys are stored locally in "
            f"{settings_path()} (plain text, this machine only). Lookups are hash based; "
            "the sample is never uploaded. Leave the toggle off to stay fully offline."
        )
        note.setWordWrap(True)
        note.setStyleSheet(f"color:{COLORS['text_dim']};")
        root.addWidget(note)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def values(self) -> dict:
        return {
            "analyst": self.analyst.text().strip() or "analyst",
            "min_string_length": self.minlen.value(),
            "max_file_size_mb": self.maxmb.value(),
            "enable_network_lookups": self.network.isChecked(),
            "virustotal_api_key": self.vt.text().strip(),
            "malwarebazaar_api_key": self.mb.text().strip(),
            "otx_api_key": self.otx.text().strip(),
        }


class MainWindow(AppShell):
    """Static Analysis Pipeline main window."""

    def __init__(self) -> None:
        self.result: AnalysisResult | None = None
        self.engine = AnalysisEngine(SETTINGS, None)  # bus re-bound below
        self._worker: AnalyzeWorker | None = None
        super().__init__()
        self.engine.bus = self.bus
        self.engine.intel.bus = self.bus
        self.set_header_chips([("static analysis", "info"), ("read-only", "low")])

    # ------------------------------------------------------------- tabs
    def build_tabs(self) -> None:
        self.sample_view = SampleView()
        self.hash_view = HashView()
        self.pe_view = PEView()
        self.strings_view = StringsView()
        self.capabilities_view = CapabilitiesView()
        self.verdict_view = VerdictView()
        self.ioc_view = IOCView()

        self.add_tab(self.sample_view, "Sample && Pipeline")
        self.add_tab(self.hash_view, "Hashes")
        self.add_tab(self.pe_view, "PE Inspector")
        self.add_tab(self.strings_view, "Strings")
        self.add_tab(self.capabilities_view, "Capabilities")
        self.add_tab(self.verdict_view, "Verdict")
        self.add_tab(self.ioc_view, "IOCs")

        self.sample_view.analyzeRequested.connect(self._start_file_analysis)
        self.sample_view.demoRequested.connect(self._start_demo)
        self.hash_view.lookupRequested.connect(self._lookup_only)
        self.verdict_view.overrideRequested.connect(self._apply_override)

    def build_tools_menu(self, menu) -> None:
        menu.addAction(
            "Run synthetic packed demo (in memory)",
            lambda: self._start_demo("packed"),
        )
        menu.addAction(
            "Run benign updater demo (file on disk)",
            lambda: self._start_demo("benign"),
        )
        menu.addAction("Re-run last sample", self._rerun)
        menu.addSeparator()
        menu.addAction("Settings\u2026", self._open_settings)
        menu.addAction("Open cases folder", lambda: _open_path(cases_dir()))
        menu.addAction("Open data folder", lambda: _open_path(data_root()))

    def open_artifact(self) -> None:
        self.sample_view.picker.browse()

    def current_report(self) -> Report | None:
        return self.result.report if self.result else None

    # --------------------------------------------------------- analysis
    def _sync_settings(self) -> None:
        opts = self.sample_view.options()
        SETTINGS.set("min_string_length", opts["min_string_length"])
        SETTINGS.set("max_file_size_mb", opts["max_file_size_mb"])
        SETTINGS.set("enable_network_lookups", opts["enable_network_lookups"])
        SETTINGS.save()

    def _start_file_analysis(self, path: str, options: dict) -> None:
        self._sync_settings()
        self._start_worker(AnalyzeWorker(self.engine, path=path))

    def _start_demo(self, kind: str) -> None:
        self.bus.info(
            f"Loading demo scenario '{kind}'. {DEMO_NOTICE}"
        )
        if kind == "packed":
            self.bus.warn(
                "The synthetic packed sample is generated in memory only - "
                "nothing suspicious is written to disk."
            )
        self._start_worker(AnalyzeWorker(self.engine, demo_kind=kind))

    def _rerun(self) -> None:
        if self._worker and self._worker.isRunning():
            return
        path = self.sample_view.sample_path()
        if path:
            self._start_file_analysis(path, self.sample_view.options())
        else:
            QMessageBox.information(self, APP["name"], "No sample selected yet.")

    def _start_worker(self, worker: AnalyzeWorker) -> None:
        if self._worker and self._worker.isRunning():
            QMessageBox.information(
                self, APP["name"], "An analysis is already running - please wait for it to finish."
            )
            return
        self._worker = worker
        self.result = None
        self.sample_view.begin()
        self.set_status("Analysis running\u2026")
        worker.stageChanged.connect(self.sample_view.set_stage)
        worker.finishedOk.connect(self._on_result)
        worker.failed.connect(self._on_error)
        worker.finished.connect(self._on_worker_finished)
        worker.start()

    def _on_worker_finished(self) -> None:
        self.set_status("Ready")
        self.sample_view.progress.setRange(0, 100)

    def _on_error(self, message: str) -> None:
        self.bus.error(message)
        self.sample_view.fail(message)
        QMessageBox.critical(self, APP["name"], f"Analysis failed:\n\n{message}")

    def _on_result(self, result: AnalysisResult) -> None:
        self.result = result
        self.sample_view.finish(result)
        self.hash_view.set_result(result)
        self.pe_view.set_result(result)
        self.strings_view.set_result(result)
        self.capabilities_view.set_result(result)
        self.verdict_view.set_result(result)
        self.ioc_view.set_result(result)

        v = result.verdict
        chips = [
            (result.file_type.split(" (")[0], "info"),
            (f"{len(result.iocs)} IOCs", "info"),
        ]
        if v:
            chips.insert(0, (v.verdict, verdict_color(v.verdict)))
        if result.warnings:
            chips.append(("demo data", "warning"))
        self.set_header_chips(chips)

        self.report_panel.refresh()
        self.set_status(
            f"{result.file_name}: {v.verdict if v else '?'} "
            f"(score {v.score if v else '-'}) in {result.duration:.2f}s"
        )
        self.tabs.setCurrentWidget(self.ioc_view if result.iocs else self.verdict_view)

    def _lookup_only(self) -> None:
        """Re-run threat intel for the current sample without re-parsing it."""
        if not self.result:
            QMessageBox.information(self, APP["name"], "Analyse a sample first.")
            return
        simulate = self.sample_view.check_simulate.isChecked()
        SETTINGS.set("enable_network_lookups", self.sample_view.check_network.isChecked())
        self.result.intel_results = self.engine.intel.lookup(self.result.hashes, simulate=simulate)
        from app.core.intel import intel_summary

        self.result.intel = intel_summary(self.result.intel_results)
        self.verdict_view.set_result(self.result)
        self.tabs.setCurrentWidget(self.verdict_view)
        self.bus.info(
            f"Threat intel refreshed: {self.result.intel['status']} "
            f"({self.result.intel['sources_queried']}/{self.result.intel['sources_total']} sources answered)"
        )

    def _apply_override(self, verdict: str, justification: str) -> None:
        if not self.result or not self.result.verdict:
            return
        from app.core.verdict import apply_override

        apply_override(
            self.result.verdict,
            verdict,
            justification,
            str(SETTINGS.get("analyst", "analyst")),
        )
        self.result.report = self.engine.build_report(self.result)
        self.verdict_view.set_result(self.result)
        self.report_panel.refresh()
        self.bus.log(
            f"Verdict overridden to {verdict} by {SETTINGS.get('analyst')}: {justification}",
            "warn",
        )

    def _open_settings(self) -> None:
        dialog = SettingsDialog(self)
        if dialog.exec() == QDialog.Accepted:
            values = dialog.values()
            SETTINGS.update(values)
            SETTINGS.save()
            self.sample_view.check_network.setChecked(bool(values["enable_network_lookups"]))
            self.sample_view.spin_minlen.setValue(values["min_string_length"])
            self.sample_view.spin_maxmb.setValue(values["max_file_size_mb"])
            self.bus.success(f"Settings saved to {settings_path()}")
