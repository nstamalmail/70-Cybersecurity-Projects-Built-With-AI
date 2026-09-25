"""CPS - Custom Proxy Server (HTTP/SOCKS5). Main Qt application."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PySide6.QtCore import Qt, QTimer, Slot                        # noqa: E402
from PySide6.QtGui import QAction, QColor                           # noqa: E402
from PySide6.QtWidgets import (                                     # noqa: E402
    QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QSplitter,
    QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

import theme                                                        # noqa: E402
import reporting                                                    # noqa: E402
from engine import ProxyConfig, ProxyServer, hash_password, session_from_traffic  # noqa: E402

APP_NAME = "CPS - Custom Proxy Server"
VERSION = "1.0.0"


def _data_dir():
    base = os.environ.get("CPS_DATA", os.path.expanduser("~/.cps"))
    os.makedirs(base, exist_ok=True)
    return base


def _samples_dir():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    d = os.path.join(here, "sample_data")
    return d if os.path.isdir(d) else here


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{VERSION}")
        self.resize(1200, 780)
        self.server: ProxyServer | None = None
        self.traffic_records: list[dict] = []
        self._recent: list[dict] = []
        central = QWidget()
        root = QVBoxLayout(central)
        self._build_menu()

        head = QHBoxLayout()
        t = QLabel("CPS - Custom Proxy Server")
        t.setObjectName("banner")
        head.addWidget(t)
        head.addStretch(1)
        self.status_pill = QLabel("STOPPED")
        self.status_pill.setStyleSheet(
            f"color:{theme.RED}; font-weight:bold; padding:2px 10px;"
            f"border:1px solid {theme.RED}; border-radius:4px;")
        head.addWidget(self.status_pill)
        root.addLayout(head)

        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        # ---------------- Traffic tab
        traffic_tab = QWidget()
        tabs.addTab(traffic_tab, "Live Traffic")
        tv = QVBoxLayout(traffic_tab)

        cfg = QGroupBox("Server Configuration")
        form = QFormLayout(cfg)
        self.host_edit = QLineEdit("127.0.0.1")
        self.port_spin = QSpinBox(); self.port_spin.setRange(1, 65535); self.port_spin.setValue(8080)
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["auto (HTTP + SOCKS5 on one port)", "http", "socks5"])
        self.auth_check = QCheckBox("Require authentication (users below)")
        self.users_edit = QLineEdit()
        self.users_edit.setPlaceholderText("user:password per line (comma separated), e.g. alice:secret,bob:hunter2")
        self.blocklist_check = QCheckBox("Enable blocklist")
        self.blocklist_check.setChecked(True)
        self.rules_edit = QPlainTextEdit()
        self.rules_edit.setPlaceholderText(
            "One rule per line: exact host (ads.example.com), wildcard (*.evil.com),\n"
            "CIDR (10.0.0.0/8), or regex (re:blocked-.*\\.net)")
        self.rules_edit.setMaximumHeight(90)
        form.addRow("Listen host:", self.host_edit)
        form.addRow("Listen port:", self.port_spin)
        form.addRow("Protocol:", self.mode_combo)
        form.addRow("", self.auth_check)
        form.addRow("Users:", self.users_edit)
        form.addRow("", self.blocklist_check)
        form.addRow("Blocklist rules:", self.rules_edit)
        tv.addWidget(cfg)

        btns = QHBoxLayout()
        self.start_btn = QPushButton("Start Server")
        self.start_btn.setObjectName("primary")
        self.stop_btn = QPushButton("Stop Server")
        self.stop_btn.setEnabled(False)
        self.import_btn = QPushButton("Import Traffic Log...")
        self.export_btn = QPushButton("Export Report...")
        self.export_btn.setEnabled(False)
        self.clear_btn = QPushButton("Clear View")
        for b in (self.start_btn, self.stop_btn, self.import_btn, self.export_btn, self.clear_btn):
            btns.addWidget(b)
        btns.addStretch(1)
        tv.addLayout(btns)

        self.summary_label = QLabel("0 connections - 0 blocked - up 0 B / down 0 B")
        self.summary_label.setObjectName("dim")
        tv.addWidget(self.summary_label)

        split = QSplitter(Qt.Vertical)
        traffic_wrap = QWidget(); self._tw = traffic_wrap
        twv = QVBoxLayout(traffic_wrap); twv.setContentsMargins(0, 0, 0, 0)
        self.traffic_tbl = QTableWidget(0, 8)
        self.traffic_tbl.setHorizontalHeaderLabels(
            ["Time", "Client", "Destination", "Port", "Protocol", "Up", "Down", "Status"])
        self.traffic_tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.traffic_tbl.setColumnWidth(0, 90); self.traffic_tbl.setColumnWidth(1, 110)
        self.traffic_tbl.setColumnWidth(2, 240); self.traffic_tbl.setColumnWidth(3, 60)
        self.traffic_tbl.setColumnWidth(4, 80); self.traffic_tbl.setColumnWidth(5, 80)
        self.traffic_tbl.setColumnWidth(6, 90); self.traffic_tbl.setColumnWidth(7, 100)
        self.traffic_tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.traffic_tbl.setAlternatingRowColors(True)
        twv.addWidget(self.traffic_tbl)
        split.addWidget(traffic_wrap)
        console_wrap = QWidget(); self._cw = console_wrap
        cwv = QVBoxLayout(console_wrap); cwv.setContentsMargins(0, 0, 0, 0)
        cwv.addWidget(QLabel("Server console"))
        self.console = QPlainTextEdit()
        self.console.setObjectName("console")
        self.console.setReadOnly(True)
        cwv.addWidget(self.console)
        split.addWidget(console_wrap)
        split.setSizes([5, 2])
        tv.addWidget(split, 1)

        # ---------------- About tab
        about_tab = QWidget()
        tabs.addTab(about_tab, "About / Legal")
        av = QVBoxLayout(about_tab)
        about = QLabel(
            "<h2>CPS</h2>"
            "<p>Dual-protocol proxy: <b>HTTP CONNECT</b> tunneling and <b>SOCKS5</b> (RFC 1928/1929), "
            "with single-port auto-detection by peeking the first byte (0x05 = SOCKS5, 'C' = CONNECT).</p>"
            "<p><b>Filtering:</b> exact host, wildcard (*.example.com), CIDR (10.0.0.0/8) and regex rules.</p>"
            "<p><b>Security notes:</b> binds to 127.0.0.1 by default; enabling authentication is "
            "strongly recommended when binding to a public interface. Passwords are stored "
            "SHA-256 salted-hashed in the session. TLS traffic is tunneled, never intercepted. "
            "Running an open proxy on a public network may violate policy or law.</p>")
        about.setWordWrap(True)
        about.setAlignment(Qt.AlignTop)
        av.addWidget(about)

        self._wire()
        self.setCentralWidget(central)

    def _build_menu(self):
        bar = self.menuBar()
        m_file = bar.addMenu("&File")
        act_import = QAction("Import Traffic Log (JSON/CSV)...", self)
        act_import.setShortcut("Ctrl+I")
        act_import.triggered.connect(self.import_traffic)
        act_quit = QAction("Exit", self)
        act_quit.triggered.connect(self.close)
        m_file.addAction(act_import)
        m_file.addSeparator()
        m_file.addAction(act_quit)

    def _wire(self):
        self.start_btn.clicked.connect(self.start_server)
        self.stop_btn.clicked.connect(self.stop_server)
        self.import_btn.clicked.connect(self.import_traffic)
        self.export_btn.clicked.connect(self.export_report)
        self.clear_btn.clicked.connect(self.clear_view)
        self.traffic_tbl.doubleClicked.connect(self.show_detail)

    # ---------------------------------------------------------- server I/O
    def _collect_config(self) -> ProxyConfig:
        users = {}
        if self.auth_check.isChecked():
            for chunk in self.users_edit.text().split(","):
                chunk = chunk.strip()
                if ":" in chunk:
                    user, _, pw = chunk.partition(":")
                    users[user.strip()] = hash_password(pw.strip())
        rules = self.rules_edit.toPlainText().splitlines()
        mode = "auto" if self.mode_combo.currentText().startswith("auto") else \
            self.mode_combo.currentText()
        return ProxyConfig(
            listen_host=self.host_edit.text().strip() or "127.0.0.1",
            listen_port=self.port_spin.value(),
            protocol_mode=mode,
            auth_required=self.auth_check.isChecked(),
            auth_users=users,
            blocklist_enabled=self.blocklist_check.isChecked(),
            blocklist_rules=rules,
        )

    @Slot()
    def start_server(self):
        if self.server and self.server.running:
            return
        cfg = self._collect_config()
        if cfg.listen_host not in ("127.0.0.1", "localhost", "::1") and not cfg.auth_required:
            box = QMessageBox.question(
                self, APP_NAME,
                "Binding to a non-loopback address WITHOUT authentication creates an "
                "OPEN PROXY. Continue anyway?")
            if box != QMessageBox.Yes:
                return
        self.server = ProxyServer(cfg, on_event=self._on_proxy_event)
        self.server.start()
        QTimer.singleShot(400, self._verify_started)

    def _verify_started(self):
        if self.server and self.server.running:
            self._log(f"server listening on {self.server.config.listen_host}:"
                      f"{self.server.config.listen_port} mode={self.server.config.protocol_mode}",
                      "green")
            self.status_pill.setText("RUNNING")
            self.status_pill.setStyleSheet(
                f"color:{theme.GREEN}; font-weight:bold; padding:2px 10px;"
                f"border:1px solid {theme.GREEN}; border-radius:4px;")
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.statusBar().showMessage(
                f"Proxy running - point clients at "
                f"http://{self.server.config.listen_host}:{self.server.config.listen_port} or "
                f"socks5://{self.server.config.listen_host}:{self.server.config.listen_port}")
        else:
            self._log("server failed to start (port busy?)", "red")
            QMessageBox.critical(self, APP_NAME, "Server failed to start - port busy or invalid host.")

    @Slot()
    def stop_server(self):
        if self.server:
            self.server.stop()
            self._log("server stopped", "gray")
        self.status_pill.setText("STOPPED")
        self.status_pill.setStyleSheet(
            f"color:{theme.RED}; font-weight:bold; padding:2px 10px;"
            f"border:1px solid {theme.RED}; border-radius:4px;")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _on_proxy_event(self, rec: dict):
        if rec.get("type") == "error":
            QTimer.singleShot(0, lambda r=rec: self._log(f"ERROR {r.get('detail')}", "red"))
            return
        self.traffic_records.append(rec)
        QTimer.singleShot(0, lambda r=rec: self._apply_record(r))

    def _apply_record(self, rec: dict):
        self._recent.insert(0, rec)
        del self._recent[500:]
        self.traffic_tbl.setRowCount(len(self._recent))
        status = rec.get("status", "")
        color = {"ALLOWED": theme.GREEN, "BLOCKED": theme.RED,
                 "ERROR": theme.ORANGE, "AUTH_FAIL": theme.ORANGE}.get(status, theme.TEXT)
        for col, key in enumerate(("timestamp", "client_ip", "dest_host", "dest_port",
                                   "protocol", "bytes_up", "bytes_down", "status")):
            val = rec.get(key, "")
            if key in ("bytes_up", "bytes_down"):
                val = reporting._fmt_bytes(val)
            item = QTableWidgetItem(str(val))
            if key == "status":
                item.setForeground(QColor(color))
            self.traffic_tbl.setItem(self._recent.index(rec), col, item)
        self._refresh_summary()

    def _refresh_summary(self):
        recs = self.traffic_records
        up = sum(r.get("bytes_up", 0) for r in recs)
        down = sum(r.get("bytes_down", 0) for r in recs)
        blocked = sum(1 for r in recs if r.get("status") == "BLOCKED")
        self.summary_label.setText(
            f"{len(recs)} connections - {blocked} blocked - up {reporting._fmt_bytes(up)} "
            f"/ down {reporting._fmt_bytes(down)}")

    def show_detail(self, index):
        row = index.row()
        if 0 <= row < len(self._recent):
            rec = self._recent[row]
            detail = "\n".join(f"{k}: {v}" for k, v in rec.items())
            QMessageBox.information(self, "Connection Detail", detail)

    def _log(self, msg, color="gray"):
        hexc = {"green": theme.GREEN, "red": theme.RED, "orange": theme.ORANGE,
                "blue": theme.ACCENT, "gray": theme.TEXT_DIM}.get(color, theme.TEXT_DIM)
        self.console.appendHtml(f'<span style="color:{hexc}">{msg}</span>')

    def clear_view(self):
        self.traffic_tbl.setRowCount(0)
        self._recent = []

    # ------------------------------------------------------------- import
    @Slot()
    def import_traffic(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Traffic Log", _samples_dir(),
            "Traffic logs (*.json *.jsonl *.csv);;All files (*)")
        if not path:
            return
        try:
            records = self._load_traffic_file(path)
        except Exception as exc:                              # noqa: BLE001
            QMessageBox.critical(self, APP_NAME, f"Import failed: {exc}")
            return
        if not records:
            QMessageBox.warning(self, APP_NAME, "No traffic records found in file.")
            return
        self.clear_view()
        self.traffic_records = list(records)
        for rec in reversed(self.traffic_records):
            self._recent.insert(0, rec)
        del self._recent[500:]
        self.traffic_tbl.setRowCount(len(self._recent))
        for row, rec in enumerate(self._recent):
            for col, key in enumerate(("timestamp", "client_ip", "dest_host", "dest_port",
                                       "protocol", "bytes_up", "bytes_down", "status")):
                val = rec.get(key, "")
                if key in ("bytes_up", "bytes_down"):
                    val = reporting._fmt_bytes(val)
                item = QTableWidgetItem(str(val))
                if key == "status":
                    item.setForeground(QColor(
                        {"ALLOWED": theme.GREEN, "BLOCKED": theme.RED,
                         "ERROR": theme.ORANGE, "AUTH_FAIL": theme.ORANGE}
                        .get(rec.get("status", ""), theme.TEXT)))
                self.traffic_tbl.setItem(row, col, item)
        self._refresh_summary()
        self.export_btn.setEnabled(True)
        self._log(f"imported {len(records)} records from {os.path.basename(path)}", "blue")
        self.statusBar().showMessage(f"Imported {len(records)} traffic records")

    def _load_traffic_file(self, path: str) -> list[dict]:
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read().strip()
        records: list[dict] = []
        if path.lower().endswith(".csv"):
            import csv as _csv
            import io
            for row in _csv.DictReader(io.StringIO(content)):
                for k in ("bytes_up", "bytes_down", "dest_port", "duration_ms"):
                    try:
                        row[k] = int(row.get(k) or 0)
                    except ValueError:
                        row[k] = 0
                records.append(row)
        elif content.startswith("["):
            records = json.loads(content)
        else:                                                  # JSON Lines
            for line in content.splitlines():
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    # ------------------------------------------------------------- report
    @Slot()
    def export_report(self):
        if not self.traffic_records:
            QMessageBox.information(self, APP_NAME, "No traffic to report yet - run the "
                                                    "server or import a traffic log.")
            return
        cfg = self.server.config.to_dict() if self.server else self._collect_config().to_dict()
        session = session_from_traffic(
            f"cps-{int(__import__('time').time())}", cfg, self.traffic_records)
        fmt, ok = QInputDialog.getItem(self, "Export Report", "Format:",
                                       ["pdf", "html", "json", "csv", "txt"], 0, False)
        if not ok:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report",
            os.path.join(_data_dir(), "reports", f"{session.session_id}.{fmt}"),
            f"{fmt.upper()} (*.{fmt})")
        if not path:
            return
        try:
            out = reporting.export(session, fmt, path)
        except Exception as exc:                              # noqa: BLE001
            QMessageBox.critical(self, APP_NAME, f"Export failed: {exc}")
            return
        self._log(f"report -> {out}", "blue")
        QMessageBox.information(self, APP_NAME, f"Report written:\n{out}")

    def closeEvent(self, event):
        self.stop_server()
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyleSheet(theme.STYLESHEET)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
