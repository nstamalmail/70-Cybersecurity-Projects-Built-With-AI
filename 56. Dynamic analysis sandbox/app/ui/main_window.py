"""Main window for the Dynamic Analysis Sandbox."""
from __future__ import annotations

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
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
from app.core.engine import DetonationResult, Engine
from app.core.hypervisor import adapter_catalogue
from app.demo import DEMO_NOTICE
from app.reporting import Report, verdict_color
from app.ui.report_panel import _open_path
from app.ui.shell import AppShell
from app.ui.theme import COLORS
from app.ui.views import (
    ApiCallsView,
    ArtifactsView,
    BackendsView,
    IOCView,
    NetworkView,
    ProcessesView,
    SessionView,
    TimelineView,
)


class SandboxWorker(QThread):
    """Runs ingest or detonation off the UI thread."""

    stageChanged = Signal(str, int, int)
    finishedOk = Signal(object)
    failed = Signal(str)

    def __init__(self, engine: Engine, *, path=None, detonate=False, options=None, demo_kind=None, parent=None) -> None:
        super().__init__(parent)
        self.engine = engine
        self.path = path
        self.detonate = detonate
        self.options = options or {}
        self.demo_kind = demo_kind

    def run(self) -> None:
        try:
            def progress(stage: str, done: int = 0, total: int = 0) -> None:
                self.stageChanged.emit(stage, done, total)

            if self.demo_kind:
                from app import demo

                result = demo.run_demo(self.engine, self.demo_kind, progress=progress)
            elif self.detonate:
                result = self.engine.detonate(
                    self.path,
                    progress=progress,
                    dry_run=bool(self.options.get("dry_run", True)),
                    collect=self._collector() if self.options.get("collect", True) else None,
                )
            else:
                result = self.engine.analyze(self.path, progress=progress)
            self.finishedOk.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))

    def _collector(self):
        """Return the telemetry collector for the selected back end.

        With a real hypervisor the guest-agent client would be used; without one
        the harness supplies clearly-labelled synthetic telemetry so the rest of
        the workflow stays exercisable.
        """
        engine = self.engine

        def collect(ctx):
            from app.core.hypervisor import SimulatedAdapter
            from app.demo import synthetic_session

            adapter = ctx["adapter"]
            if isinstance(adapter, SimulatedAdapter):
                engine._log(
                    "Simulation harness active - synthesising guest telemetry "
                    "(labelled SIMULATED in every artefact)",
                    "warn",
                )
                session = synthetic_session("ransomware", sample_name=ctx["sample"].name)
                session.vm_name = str(adapter.settings.get("vm_name", "win10-analysis"))
                return session

            engine._log(
                "No guest-agent collector is configured for a real hypervisor. "
                "Provide the guest agent endpoint in Settings, or use the simulation harness.",
                "error",
            )
            return None

        return collect


class SettingsDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"{APP['name']} \u2014 Settings")
        self.resize(600, 380)
        root = QVBoxLayout(self)
        form = QFormLayout()

        self.analyst = QLineEdit(str(SETTINGS.get("analyst", "analyst")))
        self.vm_name = QLineEdit(str(SETTINGS.get("vm_name", "win10-analysis")))
        self.snapshot = QLineEdit(str(SETTINGS.get("snapshot", "clean-baseline")))
        self.timeout = QSpinBox()
        self.timeout.setRange(30, 3600)
        self.timeout.setValue(int(SETTINGS.get("analysis_timeout_s", 120)))
        self.timeout.setSuffix(" s")
        self.backend = QComboBox()
        for entry in adapter_catalogue(SETTINGS):
            self.backend.addItem(entry["back end"], entry["back end"])
        current = str(SETTINGS.get("hypervisor", "auto"))
        index = self.backend.findData(current)
        self.backend.setCurrentIndex(index if index >= 0 else 0)
        self.network = QComboBox()
        for mode in ("simulated", "host-only", "none"):
            self.network.addItem(mode, mode)
        index = self.network.findData(str(SETTINGS.get("network_mode", "simulated")))
        self.network.setCurrentIndex(index if index >= 0 else 0)
        self.check_dryrun = QCheckBox("Default to dry-run for hypervisor commands")
        self.check_dryrun.setChecked(True)
        self.max_events = QSpinBox()
        self.max_events.setRange(1000, 5_000_000)
        self.max_events.setSingleStep(10000)
        self.max_events.setValue(int(SETTINGS.get("max_events", 500000)))

        form.addRow("Analyst name", self.analyst)
        form.addRow("VM name", self.vm_name)
        form.addRow("Clean snapshot name", self.snapshot)
        form.addRow("Analysis timeout", self.timeout)
        form.addRow("Hypervisor back end", self.backend)
        form.addRow("Network mode", self.network)
        form.addRow("Maximum ingest events", self.max_events)
        form.addRow("", self.check_dryrun)
        root.addLayout(form)

        note = QLabel(
            "Isolation is enforced by the pipeline, not by these settings: the snapshot is "
            "reverted before every run and networking is disabled at the hypervisor level. "
            f"Configuration is stored locally in {settings_path()}."
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
            "vm_name": self.vm_name.text().strip() or "win10-analysis",
            "snapshot": self.snapshot.text().strip() or "clean-baseline",
            "analysis_timeout_s": self.timeout.value(),
            "hypervisor": self.backend.currentData(),
            "network_mode": self.network.currentData(),
            "max_events": self.max_events.value(),
        }


class MainWindow(AppShell):
    """Dynamic Analysis Sandbox main window."""

    def __init__(self) -> None:
        self.result: DetonationResult | None = None
        self.engine = Engine(SETTINGS, None)
        self._worker: SandboxWorker | None = None
        super().__init__()
        self.engine.bus = self.bus
        self.set_header_chips([("isolated sandbox", "info"), ("read-only host", "low")])

    def build_tabs(self) -> None:
        self.session_view = SessionView()
        self.timeline_view = TimelineView()
        self.process_view = ProcessesView()
        self.network_view = NetworkView()
        self.artifacts_view = ArtifactsView()
        self.api_view = ApiCallsView()
        self.ioc_view = IOCView()
        self.backends_view = BackendsView(SETTINGS)

        self.add_tab(self.session_view, "Session && Detonation")
        self.add_tab(self.timeline_view, "Timeline")
        self.add_tab(self.process_view, "Process Tree")
        self.add_tab(self.network_view, "Network")
        self.add_tab(self.artifacts_view, "Files && Registry")
        self.add_tab(self.api_view, "API Calls")
        self.add_tab(self.ioc_view, "IOCs")
        self.add_tab(self.backends_view, "Sandbox Back Ends")

        self.session_view.ingestRequested.connect(self._start_ingest)
        self.session_view.detonateRequested.connect(self._start_detonation)
        self.session_view.demoRequested.connect(self._start_demo)

    def build_tools_menu(self, menu) -> None:
        menu.addAction("Run full detonation demo (simulated harness)",
                       lambda: self._start_demo("detonation"))
        menu.addAction("Load ransomware-style session demo",
                       lambda: self._start_demo("session-file"))
        menu.addAction("Load benign session demo", lambda: self._start_demo("benign"))
        menu.addSeparator()
        menu.addAction("Settings\u2026", self._open_settings)
        menu.addAction("Open cases folder", lambda: _open_path(cases_dir()))
        menu.addAction("Open data folder", lambda: _open_path(data_root()))

    def open_artifact(self) -> None:
        self.session_view.picker.browse()

    def current_report(self) -> Report | None:
        return self.result.report if self.result else None

    # ------------------------------------------------------------------ runs
    def _start_ingest(self, path: str) -> None:
        if not path:
            QMessageBox.warning(self, APP["name"], "Choose a behaviour log first.")
            return
        self._start_worker(SandboxWorker(self.engine, path=path))

    def _start_detonation(self, path: str, options: dict) -> None:
        if options.get("collect") and not options.get("dry_run"):
            confirm = QMessageBox.question(
                self,
                APP["name"],
                "Real hypervisor commands will be executed (dry-run is disabled).\n\n"
                "The VM will be reverted to the clean snapshot, booted headless and the "
                "sample will be executed inside it. Continue?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if confirm != QMessageBox.Yes:
                return
        self._start_worker(SandboxWorker(self.engine, path=path, detonate=True, options=options))

    def _start_demo(self, kind: str) -> None:
        self.bus.warn(f"Loading demo scenario '{kind}'. {DEMO_NOTICE}")
        self._start_worker(SandboxWorker(self.engine, demo_kind=kind))

    def _start_worker(self, worker: SandboxWorker) -> None:
        if self._worker and self._worker.isRunning():
            QMessageBox.information(self, APP["name"], "A run is already in progress.")
            return
        self._worker = worker
        self.result = None
        self.session_view.begin()
        self.set_status("Running\u2026")
        worker.stageChanged.connect(self.session_view.set_stage)
        worker.finishedOk.connect(self._on_result)
        worker.failed.connect(self._on_error)
        worker.finished.connect(lambda: self.set_status("Ready"))
        worker.start()

    def _on_error(self, message: str) -> None:
        self.bus.error(message)
        self.session_view.fail(message)
        QMessageBox.critical(self, APP["name"], f"Run failed:\n\n{message}")

    def _on_result(self, result: DetonationResult) -> None:
        self.result = result
        self.session_view.finish(result)
        self.timeline_view.set_result(result)
        self.process_view.set_result(result)
        self.network_view.set_result(result)
        self.artifacts_view.set_result(result)
        self.api_view.set_result(result)
        self.ioc_view.set_result(result)

        chips = [
            (result.severity.upper(), verdict_color(result.severity)),
            (f"{len(result.session.events)} events", "info"),
            (f"{len(result.signatures)} signatures", "warning" if result.signatures else "low"),
            (f"{len(result.iocs)} IOCs", "info"),
        ]
        if result.session.simulation:
            chips.append(("simulated telemetry", "warning"))
        self.set_header_chips(chips)
        self.report_panel.refresh()
        self.set_status(
            f"{result.session.sample_name}: {result.severity.upper()} "
            f"(score {result.score}) \u00b7 {len(result.session.events)} events"
        )
        self.tabs.setCurrentWidget(self.timeline_view)

    def _open_settings(self) -> None:
        dialog = SettingsDialog(self)
        if dialog.exec() == QDialog.Accepted:
            SETTINGS.update(dialog.values())
            SETTINGS.save()
            self.backends_view.table.set_data(
                [[e["back end"], e["available"], e["detail"], e["isolation"]]
                 for e in adapter_catalogue(SETTINGS)]
            )
            self.bus.success(f"Settings saved to {settings_path()}")
