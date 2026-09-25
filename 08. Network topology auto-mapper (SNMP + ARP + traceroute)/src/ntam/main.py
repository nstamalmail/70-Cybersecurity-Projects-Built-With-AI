"""NTAM - Network Topology Auto-Mapper. Main Qt application."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PySide6.QtCore import Qt, QTimer, Slot                        # noqa: E402
from PySide6.QtGui import QAction, QColor, QPainter, QPen           # noqa: E402
from PySide6.QtWidgets import (                                     # noqa: E402
    QApplication, QCheckBox, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSpinBox,
    QSplitter, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout,
    QWidget,
)

import theme                                                        # noqa: E402
import reporting                                                    # noqa: E402
from engine import DiscoveryController, topology_from_dict          # noqa: E402

APP_NAME = "NTAM - Network Topology Auto-Mapper"
VERSION = "1.0.0"

TYPE_COLORS = {"router": "#e74c3c", "switch": "#3498db", "server": "#2ecc71",
               "host": "#95a5a6", "unknown": "#f39c12"}


def _data_dir():
    base = os.environ.get("NTAM_DATA", os.path.expanduser("~/.ntam"))
    os.makedirs(base, exist_ok=True)
    return base


def _samples_dir():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    d = os.path.join(here, "sample_data")
    return d if os.path.isdir(d) else here


class GraphCanvas(QWidget):
    """Simple force-ish static layout graph: devices as colored nodes."""

    def __init__(self):
        super().__init__()
        self.nodes: list[dict] = []          # {'x','y','ip','dtype'}
        self.edges: list[tuple[int, int]] = []
        self.setMinimumHeight(300)
        self.selected = -1

    def set_topology(self, devices, links):
        import math
        self.nodes = []
        self.edges = []
        n = len(devices)
        if n == 0:
            self.update()
            return
        cx, cy = 0.5, 0.5
        radius = 0.36
        for i, d in enumerate(devices):
            if isinstance(d, dict):
                ip, dtype = d.get("ip", "?"), d.get("device_type", "unknown")
            else:
                ip, dtype = d.ip, d.device_type
            angle = 2 * math.pi * i / n - math.pi / 2
            self.nodes.append({"x": cx + radius * math.cos(angle),
                               "y": cy + radius * math.sin(angle),
                               "ip": str(ip), "dtype": dtype})
        id_map = {}
        for i, d in enumerate(devices):
            did = d.get("device_id") if isinstance(d, dict) else d.device_id
            id_map[did] = i
        for l in links:
            src = l.get("source_device") if isinstance(l, dict) else l.source_device
            dst = l.get("dest_device") if isinstance(l, dict) else l.dest_device
            if src in id_map and dst in id_map:
                self.edges.append((id_map[src], id_map[dst]))
        self.update()

    def paintEvent(self, event):                            # noqa: N802
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(theme.PANEL))
        w, h = self.width(), self.height()
        p.setPen(QPen(QColor(theme.BORDER), 1))
        for a, b in self.edges:
            if a < len(self.nodes) and b < len(self.nodes):
                p.drawLine(int(self.nodes[a]["x"] * w), int(self.nodes[a]["y"] * h),
                           int(self.nodes[b]["x"] * w), int(self.nodes[b]["y"] * h))
        for node in self.nodes:
            color = TYPE_COLORS.get(node["dtype"], theme.GRAY)
            p.setBrush(QColor(color))
            p.setPen(QColor(theme.BACKGROUND))
            p.drawEllipse(int(node["x"] * w) - 11, int(node["y"] * h) - 11, 22, 22)
            p.setPen(QColor(theme.TEXT))
            p.drawText(int(node["x"] * w) - 40, int(node["y"] * h) + 26, 80, 14,
                       Qt.AlignHCenter, node["ip"])
        if not self.nodes:
            p.setPen(QColor(theme.TEXT_DIM))
            p.drawText(self.rect(), Qt.AlignCenter,
                       "No topology yet - run discovery or import a topology JSON")
        p.end()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{VERSION}")
        self.resize(1200, 800)
        self.ctrl = DiscoveryController()
        self.topology = None
        self._scan_done = True
        central = QWidget()
        root = QVBoxLayout(central)
        self._build_menu()

        head = QHBoxLayout()
        t = QLabel("NTAM - Network Topology Auto-Mapper")
        t.setObjectName("banner")
        head.addWidget(t)
        head.addStretch(1)
        auth = QLabel("Authorized networks only")
        auth.setObjectName("dim")
        head.addWidget(auth)
        root.addLayout(head)

        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        # ---------------- Discovery tab
        disc_tab = QWidget()
        tabs.addTab(disc_tab, "Discovery")
        dv = QVBoxLayout(disc_tab)

        cfg = QGroupBox("Discovery Configuration")
        form = QFormLayout(cfg)
        self.scope_edit = QLineEdit()
        self.scope_edit.setPlaceholderText("192.168.1.0/24 (local /24 is filled by default)")
        self.scope_edit.setText(_default_scope())
        self.timeout_spin = QSpinBox(); self.timeout_spin.setRange(1, 10); self.timeout_spin.setValue(1)
        self.max_hosts_spin = QSpinBox(); self.max_hosts_spin.setRange(8, 4096); self.max_hosts_spin.setValue(254)
        self.snmp_check = QCheckBox("Enable SNMP enrichment (read-only sysDescr/sysName)")
        self.community_edit = QLineEdit("public")
        self.trace_check = QCheckBox("Run traceroute after discovery")
        form.addRow("Scan scope (CIDR):", self.scope_edit)
        form.addRow("Ping timeout (s):", self.timeout_spin)
        form.addRow("Max hosts:", self.max_hosts_spin)
        form.addRow("", self.snmp_check)
        form.addRow("SNMP community:", self.community_edit)
        form.addRow("", self.trace_check)
        dv.addWidget(cfg)

        prog_row = QHBoxLayout()
        self.progress = QProgressBar()
        self.status_label = QLabel("idle")
        prog_row.addWidget(self.progress, 1)
        prog_row.addWidget(self.status_label)
        dv.addLayout(prog_row)

        btns = QHBoxLayout()
        self.start_btn = QPushButton("Start Discovery")
        self.start_btn.setObjectName("primary")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.import_btn = QPushButton("Import Topology...")
        self.export_btn = QPushButton("Export Report...")
        self.export_btn.setEnabled(False)
        btns.addWidget(self.start_btn)
        btns.addWidget(self.cancel_btn)
        btns.addStretch(1)
        btns.addWidget(self.import_btn)
        btns.addWidget(self.export_btn)
        dv.addLayout(btns)

        self.graph = GraphCanvas()
        dv.addWidget(self.graph, 1)

        # ---------------- Inventory tab
        inv_tab = QWidget()
        tabs.addTab(inv_tab, "Device Inventory")
        iv = QVBoxLayout(inv_tab)
        self.inv_tbl = QTableWidget(0, 6)
        self.inv_tbl.setHorizontalHeaderLabels(["IP", "MAC", "Type", "Vendor", "Hostname", "SNMP"])
        self.inv_tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.inv_tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.inv_tbl.setAlternatingRowColors(True)
        iv.addWidget(self.inv_tbl)

        # ---------------- Console
        console_tab = QWidget()
        tabs.addTab(console_tab, "Console")
        cv = QVBoxLayout(console_tab)
        self.console = QPlainTextEdit()
        self.console.setObjectName("console")
        self.console.setReadOnly(True)
        cv.addWidget(self.console)

        # ---------------- About
        about_tab = QWidget()
        tabs.addTab(about_tab, "About / Legal")
        av = QVBoxLayout(about_tab)
        about = QLabel(
            "<h2>NTAM</h2>"
            "<p>Automated topology discovery: ICMP ping sweep of the configured CIDR, "
            "system ARP-cache correlation for MAC vendors, optional read-only SNMP "
            "enrichment (sysDescr / sysName) and optional traceroute path capture.</p>"
            "<p><b>Device classification</b> combines SNMP sysDescr keywords, TTL heuristics "
            "and hostname patterns (gw/rtr = router, sw = switch).</p>"
            "<p><b>Legal:</b> discovery generates ICMP/SNMP traffic. Run only on networks "
            "you own or are authorized to scan. SNMP queries are read-only GETs; the tool "
            "never writes to devices.</p>")
        about.setWordWrap(True)
        about.setAlignment(Qt.AlignTop)
        av.addWidget(about)

        self._wire()
        self.setCentralWidget(central)

    def _build_menu(self):
        bar = self.menuBar()
        m_file = bar.addMenu("&File")
        act_import = QAction("Import Topology (JSON)...", self)
        act_import.setShortcut("Ctrl+I")
        act_import.triggered.connect(self.import_topology)
        act_quit = QAction("Exit", self)
        act_quit.triggered.connect(self.close)
        m_file.addAction(act_import)
        m_file.addSeparator()
        m_file.addAction(act_quit)

    def _wire(self):
        self.start_btn.clicked.connect(self.start_discovery)
        self.cancel_btn.clicked.connect(self.ctrl.cancel)
        self.import_btn.clicked.connect(self.import_topology)
        self.export_btn.clicked.connect(self.export_report)

    # ------------------------------------------------------------ discovery
    @Slot()
    def start_discovery(self):
        if not self._scan_done:
            return
        scope = self.scope_edit.text().strip()
        if "/" not in scope:
            QMessageBox.warning(self, APP_NAME, "Scan scope must be CIDR, e.g. 192.168.1.0/24")
            return
        box = QMessageBox.question(
            self, "Authorization",
            f"Confirm you are authorized to discover devices on {scope}.\n"
            "Discovery sends ICMP packets and may query SNMP.")
        if box != QMessageBox.Yes:
            return
        self.inv_tbl.setRowCount(0)
        self.graph.nodes = []
        self.graph.update()
        self._scan_done = False
        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        self.ctrl.start(
            {
                "scan_scope": scope, "seed_ip": scope.split("/")[0],
                "timeout": self.timeout_spin.value(),
                "max_hosts": self.max_hosts_spin.value(),
                "snmp": {"enabled": self.snmp_check.isChecked(),
                         "community": self.community_edit.text().strip() or "public",
                         "timeout": 1.5},
                "traceroute": self.trace_check.isChecked(),
                "max_hops": 8,
            },
            on_progress=self._on_progress,
            on_result=self._on_device,
            on_done=self._on_done,
        )
        self._log(f"discovery started: {scope}")

    def _on_progress(self, done, total, label):
        QTimer.singleShot(0, lambda d=done, t=total, l=label:
                          (self.progress.setMaximum(max(1, t)), self.progress.setValue(d),
                           self.status_label.setText(f"{d}/{t} - {l}")))

    def _on_device(self, dev):
        QTimer.singleShot(0, lambda d=dev: self._apply_device(d))

    def _apply_device(self, dev):
        row = self.inv_tbl.rowCount()
        self.inv_tbl.insertRow(row)
        if isinstance(dev, dict):
            ip, mac, dtype = dev.get("ip"), dev.get("mac"), dev.get("device_type", "unknown")
            vendor, hostname = dev.get("vendor"), dev.get("hostname")
            snmp = dev.get("snmp_accessible")
        else:
            ip, mac, dtype = dev.ip, dev.mac, dev.device_type
            vendor, hostname = dev.vendor, dev.hostname
            snmp = dev.snmp_accessible
        vals = [str(ip), str(mac or "-"), dtype, str(vendor or "-"),
                str(hostname or "-"), "yes" if snmp else "no"]
        for col, v in enumerate(vals):
            item = QTableWidgetItem(v)
            if col == 2:
                item.setForeground(QColor(TYPE_COLORS.get(dtype, theme.TEXT)))
            self.inv_tbl.setItem(row, col, item)

    def _on_done(self, topo, error):
        QTimer.singleShot(0, lambda t=topo, e=error: self._apply_done(t, e))

    def _apply_done(self, topo, error):
        self._scan_done = True
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        if error:
            self._log(f"ERROR {error}", "red")
            QMessageBox.critical(self, APP_NAME, f"Discovery failed: {error}")
            return
        self.topology = topo
        self.graph.set_topology(topo.devices, topo.links)
        self.export_btn.setEnabled(True)
        if getattr(topo, "traceroute", None):
            for h in topo.traceroute:
                self._log(f"trace hop {h.get('hop')}: {h.get('ip') or '*'} "
                          f"{h.get('latency_ms') or ''} ms")
        self._log(f"discovery complete: {len(topo.devices)} devices, "
                  f"{len(topo.links)} links in {topo.discovery_duration:.1f}s")
        self.statusBar().showMessage(
            f"{len(topo.devices)} devices discovered - topology {topo.topology_id}")

    def _log(self, msg, color="gray"):
        hexc = {"red": theme.RED, "green": theme.GREEN, "blue": theme.ACCENT,
                "gray": theme.TEXT_DIM}.get(color, theme.TEXT_DIM)
        self.console.appendHtml(f'<span style="color:{hexc}">{msg}</span>')

    # -------------------------------------------------------------- import
    @Slot()
    def import_topology(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Topology (JSON)", _samples_dir(),
            "Topology (*.json);;All files (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            topo = topology_from_dict(raw)
        except Exception as exc:                              # noqa: BLE001
            QMessageBox.critical(self, APP_NAME, f"Import failed: {exc}")
            return
        self.topology = topo
        self.inv_tbl.setRowCount(0)
        for dev in topo.devices:
            self._apply_device(dev)
        self.graph.set_topology(topo.devices, topo.links)
        self.export_btn.setEnabled(True)
        self.progress.setMaximum(max(1, len(topo.devices)))
        self.progress.setValue(len(topo.devices))
        self.status_label.setText(f"imported {len(topo.devices)} devices")
        self._log(f"imported topology {topo.topology_id} from {os.path.basename(path)}")
        self.statusBar().showMessage(f"Imported topology: {len(topo.devices)} devices")

    # -------------------------------------------------------------- report
    @Slot()
    def export_report(self):
        if not self.topology:
            QMessageBox.information(self, APP_NAME, "Run discovery or import a topology first.")
            return
        fmt, ok = QInputDialog.getItem(
            self, "Export Report", "Format:",
            ["pdf", "html", "json", "csv", "txt", "dot (Graphviz)"], 0, False)
        if not ok:
            return
        fmt = fmt.split(" ")[0]
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report",
            os.path.join(_data_dir(), "reports", f"topology_{self.topology.topology_id}.{fmt}"),
            f"{fmt.upper()} (*.{fmt})")
        if not path:
            return
        try:
            out = reporting.export(self.topology, fmt, path)
        except Exception as exc:                              # noqa: BLE001
            QMessageBox.critical(self, APP_NAME, f"Export failed: {exc}")
            return
        self._log(f"report -> {out}", "blue")
        QMessageBox.information(self, APP_NAME, f"Report written:\n{out}")


def _default_scope() -> str:
    """Guess the local /24 for convenience."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except OSError:
        return "192.168.1.0/24"


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyleSheet(theme.STYLESHEET)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
