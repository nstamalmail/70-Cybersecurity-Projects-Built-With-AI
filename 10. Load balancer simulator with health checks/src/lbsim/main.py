"""LBSim - Load Balancer Simulator GUI (PySide6).

Tabs: Backends | Simulation | Distribution | Health Log | Report.
File menu: import sample simulation JSON, export reports in 5 formats.
"""
from __future__ import annotations

import os
import sys
import threading
import time
import uuid
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QColor
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QDoubleSpinBox,
    QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QSplitter,
    QTableWidget, QTableWidgetItem, QTabWidget, QTextEdit, QVBoxLayout, QWidget,
)

import engine
import reporting
import theme
from engine import (
    ALGORITHMS, BackendPool, HealthCheckConfig, HealthChecker,
    SimulatedBackend, SimulationResult, TrafficGenerator,
)

APP_TITLE = "LBSim - Load Balancer Simulator (with Health Checks)"


def _samples_dir():
    """Locate sample_data/ next to the project; fall back sensibly in a frozen exe."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    d = os.path.join(here, "sample_data")
    return d if os.path.isdir(d) else here


def _reports_dir():
    """Reports go to <project>/reports (or cwd in a frozen exe)."""
    if getattr(sys, "frozen", False):
        return os.getcwd()
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")


class BackendDialog(QDialog):
    """Add / edit a simulated backend."""

    def __init__(self, parent=None, backend: SimulatedBackend | None = None):
        super().__init__(parent)
        self.setWindowTitle("Backend")
        self.setMinimumWidth(380)
        form = QFormLayout(self)
        self.name = QLineEdit(backend.name if backend else f"web-{uuid.uuid4().hex[:4]}")
        self.address = QLineEdit(backend.address if backend else "10.0.0.11:8080")
        self.weight = QSpinBox()
        self.weight.setRange(1, 100)
        self.weight.setValue(backend.weight if backend else 1)
        self.mode = QComboBox()
        self.mode.addItems(list(SimulatedBackend.MODES))
        if backend:
            self.mode.setCurrentText(backend.mode)
        form.addRow("Name", self.name)
        form.addRow("Address", self.address)
        form.addRow("Weight", self.weight)
        form.addRow("Failure mode", self.mode)
        row = QHBoxLayout()
        ok = QPushButton("Save")
        cancel = QPushButton("Cancel")
        ok.clicked.connect(self.accept)
        cancel.clicked.connect(self.reject)
        row.addStretch(1)
        row.addWidget(cancel)
        row.addWidget(ok)
        form.addRow(row)
        self.result_backend = None

    def accept(self):
        self.result_backend = SimulatedBackend(
            backend_id=uuid.uuid4().hex[:8],
            name=self.name.text().strip() or "backend",
            address=self.address.text().strip() or "0.0.0.0:0",
            weight=self.weight.value(),
            mode=self.mode.currentText(),
        )
        super().accept()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1180, 780)
        self.setStyleSheet(theme.QSS)

        self.pool = BackendPool()
        self.hc: HealthChecker | None = None
        self.tg: TrafficGenerator | None = None
        self._result: SimulationResult | None = None
        self._run_started = 0.0
        self._lock = threading.Lock()

        self._build_menu()
        self._build_ui()
        self._seed_backends()
        self.statusBar().showMessage(
            "Configure backends, pick an algorithm and press Start Simulation. "
            "Nothing leaves this machine - all backends are simulated.")

    # ------------------------------------------------------------- menu
    def _build_menu(self):
        m_file = self.menuBar().addMenu("&File")
        act_import = QAction("Import Simulation (JSON)...", self)
        act_import.triggered.connect(self._import_simulation)
        act_export = QAction("Export Report...", self)
        act_export.triggered.connect(self._export_report)
        act_quit = QAction("Exit", self)
        act_quit.triggered.connect(self.close)
        m_file.addAction(act_import)
        m_file.addAction(act_export)
        m_file.addSeparator()
        m_file.addAction(act_quit)

        m_help = self.menuBar().addMenu("&Help")
        act_about = QAction("About", self)
        act_about.triggered.connect(lambda: QMessageBox.information(
            self, "About",
            "LBSim simulates load-balancing algorithms (round robin, weighted RR,\n"
            "least connections, ip-hash) with health checks on in-process mock\n"
            "backends. Educational only - no packets are sent.\n\n"
            "Import sample_data/*.json to review a past simulation and export its report."))
        m_help.addAction(act_about)

    # --------------------------------------------------------------- ui
    def _build_ui(self):
        tabs = QTabWidget()
        tabs.addTab(self._tab_backends(), "Backends")
        tabs.addTab(self._tab_simulation(), "Simulation")
        tabs.addTab(self._tab_distribution(), "Distribution")
        tabs.addTab(self._tab_health_log(), "Health Log")
        tabs.addTab(self._tab_report(), "Report")
        self.setCentralWidget(tabs)

    def _tab_backends(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(QLabel(
            "Simulated backend pool. 'Failure mode' controls what the health probe sees:"))
        self.tbl_backends = QTableWidget(0, 6)
        self.tbl_backends.setHorizontalHeaderLabels(
            ["Name", "Address", "Weight", "Mode", "Health", "Requests"])
        self.tbl_backends.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_backends.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl_backends.setEditTriggers(QTableWidget.NoEditTriggers)
        v.addWidget(self.tbl_backends, 1)
        row = QHBoxLayout()
        b_add = QPushButton("Add Backend")
        b_add.clicked.connect(self._add_backend)
        b_edit = QPushButton("Edit")
        b_edit.clicked.connect(self._edit_backend)
        b_del = QPushButton("Remove")
        b_del.setObjectName("danger")
        b_del.clicked.connect(self._remove_backend)
        row.addWidget(b_add)
        row.addWidget(b_edit)
        row.addWidget(b_del)
        row.addStretch(1)
        v.addLayout(row)
        return w

    def _tab_simulation(self) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)

        left = QVBoxLayout()
        gb_alg = QGroupBox("Balancing algorithm")
        fa = QVBoxLayout(gb_alg)
        self.cmb_algorithm = QComboBox()
        self.cmb_algorithm.addItems(list(ALGORITHMS))
        fa.addWidget(self.cmb_algorithm)
        self.chk_affinity = QCheckBox("Sticky sessions (ip-hash style affinity is built in "
                                      "to the ip-hash algorithm)")
        fa.addWidget(self.chk_affinity)
        left.addWidget(gb_alg)

        gb_hc = QGroupBox("Health check")
        fh = QFormLayout(gb_hc)
        self.cmb_hc_type = QComboBox()
        self.cmb_hc_type.addItems(["tcp", "http"])
        self.sp_interval = QDoubleSpinBox()
        self.sp_interval.setRange(0.5, 30.0)
        self.sp_interval.setSingleStep(0.5)
        self.sp_interval.setValue(1.0)
        self.sp_fall = QSpinBox()
        self.sp_fall.setRange(1, 20)
        self.sp_fall.setValue(2)
        self.sp_rise = QSpinBox()
        self.sp_rise.setRange(1, 20)
        self.sp_rise.setValue(2)
        fh.addRow("Check type", self.cmb_hc_type)
        fh.addRow("Interval (s)", self.sp_interval)
        fh.addRow("Fall threshold", self.sp_fall)
        fh.addRow("Rise threshold", self.sp_rise)
        left.addWidget(gb_hc)

        gb_tg = QGroupBox("Traffic generator")
        ft = QFormLayout(gb_tg)
        self.sp_rate = QDoubleSpinBox()
        self.sp_rate.setRange(1.0, 200.0)
        self.sp_rate.setValue(25.0)
        self.sp_duration = QSpinBox()
        self.sp_duration.setRange(5, 300)
        self.sp_duration.setValue(20)
        ft.addRow("Requests / second", self.sp_rate)
        ft.addRow("Duration (s)", self.sp_duration)
        left.addWidget(gb_tg)

        row = QHBoxLayout()
        self.btn_start = QPushButton("Start Simulation")
        self.btn_start.setObjectName("ok")
        self.btn_start.clicked.connect(self._start)
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setObjectName("danger")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop)
        row.addWidget(self.btn_start)
        row.addWidget(self.btn_stop)
        left.addLayout(row)
        left.addStretch(1)

        right = QVBoxLayout()
        self.lbl_status = QLabel("Idle - no simulation running.")
        self.lbl_status.setWordWrap(True)
        right.addWidget(self.lbl_status)
        self.txt_events = QPlainTextEdit()
        self.txt_events.setReadOnly(True)
        self.txt_events.setMaximumBlockCount(2000)
        right.addWidget(self.txt_events, 1)
        gb_events = QGroupBox("Live event feed")
        gv = QVBoxLayout(gb_events)
        gv.addWidget(self.txt_events)
        right.addWidget(gb_events, 1)

        splitter = QSplitter(Qt.Horizontal)
        lw = QWidget(); lw.setLayout(left)
        rw = QWidget(); rw.setLayout(right)
        splitter.addWidget(lw)
        splitter.addWidget(rw)
        splitter.setSizes([380, 700])
        h.addWidget(splitter)
        return w

    def _tab_distribution(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        self.tbl_dist = QTableWidget(0, 4)
        self.tbl_dist.setHorizontalHeaderLabels(
            ["Backend", "Requests", "Share %", "Final health"])
        self.tbl_dist.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_dist.setEditTriggers(QTableWidget.NoEditTriggers)
        v.addWidget(self.tbl_dist, 1)
        return w

    def _tab_health_log(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        self.tbl_hclog = QTableWidget(0, 5)
        self.tbl_hclog.setHorizontalHeaderLabels(
            ["Time", "Backend", "Probe", "Latency ms", "Detail"])
        self.tbl_hclog.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_hclog.setEditTriggers(QTableWidget.NoEditTriggers)
        v.addWidget(self.tbl_hclog, 1)
        return w

    def _tab_report(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        row = QHBoxLayout()
        self.btn_export = QPushButton("Export Report...")
        self.btn_export.clicked.connect(self._export_report)
        row.addWidget(self.btn_export)
        row.addStretch(1)
        v.addLayout(row)
        self.txt_report = QTextEdit()
        self.txt_report.setReadOnly(True)
        v.addWidget(self.txt_report, 1)
        return w

    # ---------------------------------------------------------- backends
    def _seed_backends(self):
        defaults = [("web-a", "10.0.0.11:8080", 1, "healthy"),
                    ("web-b", "10.0.0.12:8080", 1, "healthy"),
                    ("web-c", "10.0.0.13:8080", 2, "healthy")]
        for name, addr, weight, mode in defaults:
            self.pool.add(SimulatedBackend(uuid.uuid4().hex[:8], name, addr, weight, mode))
        self._refresh_backends()

    def _refresh_backends(self):
        self.tbl_backends.setRowCount(0)
        for b in self.pool.backends:
            r = self.tbl_backends.rowCount()
            self.tbl_backends.insertRow(r)
            for c, val in enumerate([b.name, b.address, b.weight, b.mode, b.health,
                                     b.total_requests]):
                item = QTableWidgetItem(str(val))
                if c == 4:
                    item.setForeground(QColor(theme.GREEN if b.health == "UP" else theme.RED))
                self.tbl_backends.setItem(r, c, item)

    def _add_backend(self):
        dlg = BackendDialog(self)
        if dlg.exec() and dlg.result_backend:
            self.pool.add(dlg.result_backend)
            self._refresh_backends()

    def _edit_backend(self):
        row = self.tbl_backends.currentRow()
        if row < 0 or row >= len(self.pool.backends):
            return
        b = self.pool.backends[row]
        dlg = BackendDialog(self, b)
        if dlg.exec() and dlg.result_backend:
            nb = dlg.result_backend
            nb.backend_id = b.backend_id
            nb.health = b.health
            nb.total_requests = b.total_requests
            self.pool.backends[row] = nb
            self._refresh_backends()

    def _remove_backend(self):
        row = self.tbl_backends.currentRow()
        if row < 0 or row >= len(self.pool.backends):
            return
        self.pool.remove(self.pool.backends[row].backend_id)
        self._refresh_backends()

    # -------------------------------------------------------- simulation
    def _start(self):
        if self.hc or self.tg:
            return
        cfg = HealthCheckConfig(
            check_type=self.cmb_hc_type.currentText(),
            interval_seconds=self.sp_interval.value(),
            fall_threshold=self.sp_fall.value(),
            rise_threshold=self.sp_rise.value(),
        )
        for b in self.pool.backends:
            b.health = "UP"
            b.consecutive_failures = 0
            b.consecutive_successes = 0
            b.total_requests = 0
            b.active_connections = 0
        self.hc = HealthChecker(self.pool, cfg, on_event=self._on_hc_event)
        self.hc.start()
        self.tg = TrafficGenerator(self.pool, self.cmb_algorithm.currentText(),
                                   self.sp_rate.value(), on_event=self._on_tg_event)
        self.tg.start()
        self._run_started = time.monotonic()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.lbl_status.setText(
            f"Running: {self.cmb_algorithm.currentText()} @ {self.sp_rate.value()} rps, "
            f"health check every {cfg.interval_seconds}s. Stop to snapshot the report.")
        self.statusBar().showMessage("Simulation running...")

    def _stop(self):
        hc = self.hc
        if self.tg:
            self.tg.stop()
            self.tg = None
        if hc:
            hc.stop()
            self.hc = None
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self._snapshot(hc)

    def closeEvent(self, event):
        self._stop_threads()
        super().closeEvent(event)

    def _stop_threads(self):
        if self.tg:
            self.tg.stop()
            self.tg = None
        if self.hc:
            self.hc.stop()
            self.hc = None

    def _on_hc_event(self, rec: dict):
        with self._lock:
            if rec.get("transition"):
                line = (f"[{rec['ts']}] STATE {rec['backend']}: {rec['detail']}")
                self.txt_events.appendPlainText(line)

    def _on_tg_event(self, rec: dict):
        pass  # per-request updates are too chatty for the feed; distribution shows them

    def _snapshot(self, hc: HealthChecker | None):
        duration = time.monotonic() - self._run_started
        hc_log = list(hc.log) if hc else []
        transitions = [t for t in hc_log if t.get("transition")]
        self._result = SimulationResult(
            simulation_id=f"sim-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(),
            algorithm=self.cmb_algorithm.currentText(),
            health_check_config=self._hc_cfg().to_dict(),
            backends=[b.to_dict() for b in self.pool.backends],
            total_requests=sum(b.total_requests for b in self.pool.backends),
            state_transitions=[{
                "timestamp": t.get("ts"), "backend": t.get("backend"),
                "from_state": "UP", "to_state": t.get("health"),
                "reason": t.get("detail"),
            } for t in transitions],
            health_check_log=hc_log,
            duration_seconds=duration,
        )
        self._refresh_distribution(self._result)
        self._render_report(self._result)
        self._refresh_backends()
        self.statusBar().showMessage(
            f"Simulation finished: {self._result.total_requests} requests "
            f"across {len(self.pool.backends)} backends in {duration:.1f}s.")

    def _hc_cfg(self) -> HealthCheckConfig:
        return HealthCheckConfig(
            check_type=self.cmb_hc_type.currentText(),
            interval_seconds=self.sp_interval.value(),
            fall_threshold=self.sp_fall.value(),
            rise_threshold=self.sp_rise.value(),
        )

    def _refresh_distribution(self, result: SimulationResult):
        self.tbl_dist.setRowCount(0)
        total = result.total_requests or 1
        for b in result.backends:
            r = self.tbl_dist.rowCount()
            self.tbl_dist.insertRow(r)
            reqs = b.get("total_requests", 0) if isinstance(b, dict) else b.total_requests
            name = b.get("name") if isinstance(b, dict) else b.name
            health = b.get("health") if isinstance(b, dict) else b.health
            pct = 100.0 * reqs / total
            for c, val in enumerate([name, reqs, f"{pct:.1f}%", health]):
                item = QTableWidgetItem(str(val))
                if c == 3 and health == "DOWN":
                    item.setForeground(QColor(theme.RED))
                self.tbl_dist.setItem(r, c, item)

    def _render_report(self, result: SimulationResult):
        self.txt_report.setPlainText(reporting.to_txt(result))

    # ------------------------------------------------------------ import
    def _import_simulation(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import simulation", _samples_dir(),
            "Simulation JSON (*.json)")
        if not path:
            return
        try:
            import json
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            result = engine.simulation_from_dict(data)
            self._result = result
            self._refresh_distribution(result)
            self._render_report(result)
            self.statusBar().showMessage(f"Imported {os.path.basename(path)}")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Import failed", str(exc))

    # ------------------------------------------------------------ export
    def _export_report(self):
        if not self._result:
            QMessageBox.information(self, "No data",
                                    "Run or import a simulation first.")
            return
        fmt, ok = self._pick_format()
        if not ok:
            return
        default = os.path.join(_reports_dir(),
                               f"lbsim_report_{datetime.now():%Y%m%d_%H%M%S}.{fmt}")
        path, _ = QFileDialog.getSaveFileName(self, "Export report", default,
                                              f"{fmt.upper()} (*.{fmt})")
        if not path:
            return
        try:
            reporting.export(self._result, fmt, path)
            self.statusBar().showMessage(f"Report exported: {path}")
            QMessageBox.information(self, "Export complete", f"Report saved to:\n{path}")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Export failed", str(exc))

    @staticmethod
    def _pick_format():
        dlg = QDialog()
        dlg.setWindowTitle("Report format")
        v = QVBoxLayout(dlg)
        v.addWidget(QLabel("Choose the report format:"))
        cmb = QComboBox()
        cmb.addItems(["txt", "json", "csv", "html", "pdf"])
        v.addWidget(cmb)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(dlg.accept)
        bb.rejected.connect(dlg.reject)
        v.addWidget(bb)
        if dlg.exec():
            return cmb.currentText(), True
        return None, False


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("LBSim")
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
