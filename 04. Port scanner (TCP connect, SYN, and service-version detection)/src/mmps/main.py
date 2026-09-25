"""MMPS - Multi-Mode Port Scanner. Main Qt application entry point."""
from __future__ import annotations

import os
import sys
import time
import json

# Allow running from source tree or from PyInstaller frozen exe
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import time

from PySide6.QtCore import Qt, QTimer, Slot                      # noqa: E402
from PySide6.QtGui import QColor, QFont                          # noqa: E402
from PySide6.QtWidgets import (                                  # noqa: E402
    QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QProgressBar, QPushButton, QSpinBox,    QSplitter, QTableWidget,
    QTableWidgetItem, QTabWidget, QTextBrowser, QPlainTextEdit, QVBoxLayout, QWidget,
)

import theme
import reporting
from engine import ScanController, ScanResult, PortResult, _parse_ports

APP_NAME = "MMPS - Multi-Mode Port Scanner"
VERSION = "1.0.0"


def _samples_dir():
    """Locate sample_data/ next to the project; fall back sensibly in a frozen exe."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    d = os.path.join(here, "sample_data")
    return d if os.path.isdir(d) else here


def _cli():
    """Console entry: `mmps.exe scan <target> <ports> <mode>` (used for smoke tests)."""
    args = sys.argv[1:]
    if not args:
        return False
    if args[0] in ("scan", "--scan"):
        target = args[1] if len(args) > 1 else "127.0.0.1"
        ports = args[2] if len(args) > 2 else "top100"
        mode = args[3] if len(args) > 3 else "tcp_connect"
        ctrl = ScanController()
        box = {"res": None}

        def done(res, error):
            box["res"] = res
            ctrl.cancel_event.set()

        ctrl.start(
            {"target": target, "host": target, "ports_spec": ports, "mode": mode,
             "workers": 200, "timeout": 0.8, "grab_banners": True},
            on_progress=lambda *a: None,
            on_result=lambda *a: None,
            on_done=done,
        )
        while box["res"] is None:
            time.sleep(0.05)
        res: ScanResult = box["res"]
        for p in res.ports:
            if p.state == "OPEN":
                print(f"{p.port}/tcp open {p.service or '-'} {p.version or ''}")
        print(f"[MMPS] scan done: {res.open_count} open / {res.total_scanned} scanned")
        return True
    if args[0] in ("selftest", "--selftest"):
        res = ScanResult(scan_id="selftest", target="selftest", resolved_ip="127.0.0.1",
                         scan_mode="tcp_connect", timestamp=__import__("datetime").datetime.now())
        from engine import PortResult
        res.ports = [PortResult(22, "OPEN", "ssh", "OpenSSH 9.2"),
                     PortResult(80, "OPEN", "http", "nginx 1.24")]
        res.total_scanned = 100
        res.open_count = 2
        for p in res.ports:
            p.risk()
        for fmt in ("txt", "json", "csv", "html", "pdf"):
            out = reporting.export(res, fmt, os.path.join(_reports_dir(), f"selftest.{fmt}"))
            print(f"[MMPS] wrote {out}")
        print("[MMPS] selftest OK")
        return True
    return False


def time_sleep(sec):
    return time.sleep(sec)


def _reports_dir() -> str:
    base = os.environ.get("MMPS_DATA", os.path.expanduser("~/.mmps"))
    d = os.path.join(base, "reports")
    os.makedirs(d, exist_ok=True)
    return d


def _scan_result_from_dict(raw: dict) -> ScanResult:
    """Build a ScanResult from imported JSON (same schema as sample_data files)."""
    from datetime import datetime
    try:
        ts = datetime.fromisoformat(raw.get("timestamp"))
    except (TypeError, ValueError):
        ts = datetime.now()
    res = ScanResult(
        scan_id=raw.get("scan_id") or "imported",
        target=raw.get("target", "?"),
        resolved_ip=raw.get("resolved_ip", raw.get("target", "?")),
        scan_mode=raw.get("scan_mode", "imported"),
        timestamp=ts,
        os_fingerprint=raw.get("os_fingerprint"),
        total_scanned=int(raw.get("total_scanned", 0)),
        duration_seconds=float(raw.get("duration_seconds", 0.0)),
    )
    for p in raw.get("open_ports", []):
        pr = PortResult(
            port=int(p["port"]), state=p.get("state", "OPEN"),
            service=p.get("service"), version=p.get("version"), banner=p.get("banner"),
            cves=list(p.get("cves") or []),
            next_steps=list(p.get("next_steps") or []),
            risk_level=p.get("risk_level", "info"),
        )
        res.ports.append(pr)
    for port in raw.get("closed_ports", []):
        res.ports.append(PortResult(port=int(port), state="CLOSED"))
    for port in raw.get("filtered_ports", []):
        res.ports.append(PortResult(port=int(port), state="FILTERED"))
    res.open_count = sum(1 for p in res.ports if p.state == "OPEN")
    return res


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{VERSION}")
        self.resize(1180, 760)
        self.ctrl = ScanController()
        self._scan_done = True
        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_menu(self):
        from PySide6.QtGui import QAction
        bar = self.menuBar()
        m_file = bar.addMenu("&File")
        act_import = QAction("Import Scan Data (JSON)...", self)
        act_import.setShortcut("Ctrl+I")
        act_import.triggered.connect(self.import_scan_data)
        act_targets = QAction("Load Target List (TXT)...", self)
        act_targets.triggered.connect(self.load_target_list)
        act_quit = QAction("Exit", self)
        act_quit.triggered.connect(self.close)
        m_file.addAction(act_import)
        m_file.addAction(act_targets)
        m_file.addSeparator()
        m_file.addAction(act_quit)

    def _build_ui(self):
        central = QWidget()
        root = QVBoxLayout(central)

        self._build_menu()

        head = QHBoxLayout()
        title = QLabel("MMPS - Multi-Mode Port Scanner")
        title.setObjectName("banner")
        head.addWidget(title)
        head.addStretch(1)
        self.auth_label = QLabel("Authorized targets only")
        self.auth_label.setObjectName("dim")
        head.addWidget(self.auth_label)
        root.addLayout(head)

        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        # ---- Scan tab
        scan_tab = QWidget()
        tabs.addTab(scan_tab, "Scan")
        sv = QVBoxLayout(scan_tab)

        cfg_group = QGroupBox("Target && Scan Configuration")
        form = QFormLayout(cfg_group)
        self.target_edit = QLineEdit("127.0.0.1")
        self.ports_edit = QLineEdit("top100")
        self.ports_edit.setPlaceholderText("top100 | top1000 | 1-1024 | 22,80,443 | full")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["tcp_connect", "syn (raw sockets)"])
        self.timeout_spin = QSpinBox(); self.timeout_spin.setRange(1, 30); self.timeout_spin.setValue(1)
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(10, 500)
        self.workers_spin.setValue(200)
        self.grab_check = QCheckBox("Grab banners / probe services on open ports")
        self.grab_check.setChecked(True)
        form.addRow("Target (IP / host / CIDR):", self.target_edit)
        form.addRow("Ports:", self.ports_edit)
        form.addRow("Scan mode:", self.mode_combo)
        form.addRow("Timeout (s):", self.timeout_spin)
        form.addRow("Workers:", self.workers_spin)
        form.addRow("", self.grab_check)
        sv.addWidget(cfg_group)

        prog_group = QGroupBox("Progress")
        pv = QHBoxLayout(prog_group)
        self.progress = QProgressBar()
        self.status_label = QLabel("idle")
        pv.addWidget(self.progress, 1)
        pv.addWidget(self.status_label)
        sv.addWidget(prog_group)

        btns = QHBoxLayout()
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.setObjectName("primary")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.export_btn = QPushButton("Export Report...")
        self.export_btn.setEnabled(False)
        btns.addWidget(self.scan_btn)
        btns.addWidget(self.cancel_btn)
        btns.addStretch(1)
        btns.addWidget(self.export_btn)
        sv.addLayout(btns)

        split = QSplitter(Qt.Horizontal)
        left = QWidget(); self._left = left; lv = QVBoxLayout(left); lv.setContentsMargins(0, 0, 0, 0)
        lv.addWidget(QLabel("Results (live)"))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Port", "State", "Service", "Version / Banner", "Risk"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.setColumnWidth(0, 70); self.table.setColumnWidth(1, 90)
        self.table.setColumnWidth(2, 140); self.table.setColumnWidth(3, 380)
        self.table.setColumnWidth(4, 90)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(False)
        lv.addWidget(self.table)
        split.addWidget(left)
        right = QWidget(); self._right = right; rv = QVBoxLayout(right); rv.setContentsMargins(0, 0, 0, 0)
        rv.addWidget(QLabel("Console"))
        self.console = QPlainTextEdit(); self.console.setObjectName("console")
        self.console.setReadOnly(True)
        rv.addWidget(self.console)
        split.addWidget(right)
        split.setSizes([3, 2])
        sv.addWidget(split, 1)

        # ---- About tab
        about_tab = QWidget()
        tabs.addTab(about_tab, "About / Legal")
        av = QVBoxLayout(about_tab)
        about = QTextBrowserHelper()
        about.setHtml(
            "<h2>MMPS</h2><p>Multi-mode port scanner with service/version detection and "
            "multi-format report export (TXT/JSON/CSV/HTML/PDF).</p>"
            "<p><b>TCP Connect</b> completes the three-way handshake - reliable, no privileges "
            "needed, but logged by the target. <b>SYN scan</b> never completes the handshake - "
            "faster and stealthier, but needs admin/root and Npcap on Windows. On Windows without "
            "Npcap/admin, SYN mode falls back to FILTERED results; use TCP Connect.</p>"
            "<p><b>Legal:</b> Scanning systems you do not own or lack written permission for is "
            "illegal in most jurisdictions. The tool logs an authorization acknowledgment and "
            "all reports carry the disclaimer.</p>"
            "<p><b>Risk mapping:</b> known-risky services (SMB 445, RDP 3389, Telnet 23, Redis "
            "6379...) are flagged with severity and enumeration commands.</p>"
        )
        av.addWidget(about)

        # wire up
        self.scan_btn.clicked.connect(self.start_scan)
        self.cancel_btn.clicked.connect(self.ctrl.cancel)
        self.export_btn.clicked.connect(self.export_report)
        self.setCentralWidget(central)

    # ------------------------------------------------------------ scanning
    @Slot()
    def start_scan(self):
        if not self._scan_done:
            return
        target = self.target_edit.text().strip()
        if not target:
            QMessageBox.warning(self, APP_NAME, "Enter a target first.")
            return
        host = _resolve_target(target)
        if host is None:
            QMessageBox.critical(self, APP_NAME, f"Could not resolve target: {target}")
            return
        try:
            ports = _parse_ports(self.ports_edit.text())
        except ValueError as exc:
            QMessageBox.critical(self, APP_NAME, f"Bad port spec: {exc}")
            return
        if not ports:
            QMessageBox.critical(self, APP_NAME, "Port specification matched 0 ports.")
            return
        mode = "syn" if self.mode_combo.currentText().startswith("syn") else "tcp_connect"
        if mode == "syn":
            box = QMessageBox.question(
                self, APP_NAME,
                "SYN scan requires administrator/root privileges (and Npcap on Windows).\n"
                "Without them every port will read FILTERED. Continue anyway?",
            )
            if box != QMessageBox.Yes:
                return
        self._confirm_authorization()
        self.table.setRowCount(0)
        self.console.appendPlainText(
            f"[{self._ts()}] scan {host} ports={self.ports_edit.text()!r} mode={mode}")
        self._scan_done = False
        self.scan_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        self.progress.setValue(0)
        self.ctrl.start(
            {
                "target": target, "host": host, "ports_spec": self.ports_edit.text(),
                "mode": mode, "workers": self.workers_spin.value(),
                "timeout": self.timeout_spin.value(), "grab_banners": self.grab_check.isChecked(),
            },
            on_progress=self._on_progress,
            on_result=self._on_result,
            on_done=self._on_done,
        )

    def _confirm_authorization(self):
        if getattr(self, "_auth_confirmed", False):
            return
        box = QMessageBox.question(
            self, "Authorization",
            "Confirm you are AUTHORIZED to scan this target.\n\n"
            "Unauthorized scanning is illegal. This acknowledgment is recorded in the session log.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if box == QMessageBox.Yes:
            self._auth_confirmed = True

    # ----------------------------------------------------------- callbacks
    def _on_progress(self, done, total, label):
        # marshal to GUI thread
        QTimer.singleShot(0, lambda: self._apply_progress(done, total, label))

    def _apply_progress(self, done, total, label):
        self.progress.setMaximum(max(1, total))
        self.progress.setValue(done)
        self.status_label.setText(f"{done}/{total} - {label}")

    def _on_result(self, pres):
        QTimer.singleShot(0, lambda: self._apply_result(pres))

    def _apply_result(self, pres):
        row = self.table.rowCount()
        self.table.insertRow(row)
        vals = [str(pres.port), pres.state, pres.service or "-", 
                (pres.version or pres.banner or "-")[:60], pres.risk_level]
        for col, val in enumerate(vals):
            item = QTableWidgetItem(val)
            if col == 1:
                color = {"OPEN": theme.GREEN, "CLOSED": theme.GRAY,
                         "FILTERED": theme.ORANGE}.get(pres.state, theme.GRAY)
                item.setForeground(QColor(color))
            if col == 4:
                color = {"critical": theme.RED, "high": "#e67e22", "medium": theme.YELLOW,
                         "low": theme.ACCENT, "info": theme.TEXT_DIM}.get(pres.risk_level, theme.TEXT_DIM)
                item.setForeground(QColor(color))
            self.table.setItem(row, col, item)

    def _on_done(self, result, error):
        QTimer.singleShot(0, lambda: self._apply_done(result, error))

    def _apply_done(self, result: ScanResult, error):
        self._scan_done = True
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.export_btn.setEnabled(True)
        self.last_result = result
        if error:
            self.console.appendPlainText(f"[{self._ts()}] ERROR {error}")
            QMessageBox.critical(self, APP_NAME, f"Scan failed: {error}")
            return
        self.console.appendPlainText(
            f"[{self._ts()}] done: {result.open_count} open / {result.total_scanned} "
            f"in {result.duration_seconds:.1f}s - OS: {result.os_fingerprint or 'unknown'}")
        self.statusBar().showMessage(
            f"{result.open_count} open / {result.total_scanned} scanned - scan id {result.scan_id}")

    # ------------------------------------------------------------ reports
    def export_report(self):
        if not getattr(self, "last_result", None):
            return
        fmt = self._pick_format()
        if not fmt:
            return
        ext = fmt
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", os.path.join(_reports_dir(), f"scan_{self.last_result.scan_id}.{fmt}"),
            f"{fmt.upper()} (*.{fmt})")
        if not path:
            return
        try:
            out = reporting.export(self.last_result, fmt, path)
        except Exception as exc:                               # noqa: BLE001
            QMessageBox.critical(self, APP_NAME, f"Export failed: {exc}")
            return
        self.console.appendPlainText(f"[{self._ts()}] report -> {out}")
        QMessageBox.information(self, APP_NAME, f"Report written:\n{out}")

    def _pick_format(self):
        from PySide6.QtWidgets import QInputDialog
        fmts = ["pdf", "html", "json", "csv", "txt"]
        fmt, ok = QInputDialog.getItem(self, "Export", "Format:", fmts, 0, False)
        return fmt if ok else None

    # ------------------------------------------------------------ import
    def import_scan_data(self):
        """Load a scan result JSON (e.g. sample_data/*.json) and display it."""
        samples_dir = _samples_dir()
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Scan Data (JSON)", samples_dir, "Scan data (*.json);;All files (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            res = _scan_result_from_dict(raw)
        except Exception as exc:                               # noqa: BLE001
            QMessageBox.critical(self, APP_NAME, f"Import failed: {exc}")
            return
        self.table.setRowCount(0)
        for p in sorted(res.ports, key=lambda x: (x.state != "OPEN", x.port)):
            self._apply_result(p)
        self.last_result = res
        self.export_btn.setEnabled(True)
        self.progress.setMaximum(max(1, res.total_scanned))
        self.progress.setValue(res.total_scanned)
        self.status_label.setText(f"imported {res.open_count} open / {res.total_scanned}")
        self.console.appendPlainText(
            f"[{self._ts()}] imported scan data from {os.path.basename(path)}: "
            f"target={res.target} mode={res.scan_mode} open={res.open_count}")
        self.statusBar().showMessage(
            f"Imported: {res.target} - {res.open_count} open / {res.total_scanned} scanned")

    def load_target_list(self):
        """Load targets from a text file (one per line); fills the target field."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Target List", "", "Text files (*.txt);;All files (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                lines = [l.strip() for l in fh if l.strip() and not l.strip().startswith("#")]
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, f"Could not read file: {exc}")
            return
        if not lines:
            QMessageBox.warning(self, APP_NAME, "No targets found in file.")
            return
        self.target_edit.setText(lines[0])
        self.console.appendPlainText(
            f"[{self._ts()}] loaded {len(lines)} targets; first: {lines[0]} "
            f"(remaining listed in About/Console)")
        for extra in lines[1:]:
            self.console.appendPlainText(f"    target: {extra}")

    @staticmethod
    def _ts():
        from datetime import datetime
        return datetime.now().strftime("%H:%M:%S")


def _resolve_target(target: str) -> str | None:
    import socket as _s
    target = target.strip()
    if "/" in target:
        # CIDR: scan network address (simple approach: first host)
        import ipaddress
        try:
            net = ipaddress.ip_network(target, strict=False)
            return str(net.network_address)
        except ValueError:
            return None
    try:
        return _s.gethostbyname(target)
    except OSError:
        return None


class QTextBrowserHelper(QTextBrowser):
    """Read-only rich text view used for the About page."""

    def __init__(self):
        super().__init__()
        self.setOpenExternalLinks(True)
        self.setMinimumHeight(120)


def main():
    if _cli():
        return
    app = QApplication(sys.argv)
    app.setStyleSheet(theme.STYLESHEET)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
