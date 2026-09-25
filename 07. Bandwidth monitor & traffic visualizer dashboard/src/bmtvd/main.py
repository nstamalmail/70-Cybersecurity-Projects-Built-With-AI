"""BMTVD - Bandwidth Monitor & Traffic Visualizer. Main Qt application."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PySide6.QtCore import Qt, QTimer, Slot                        # noqa: E402
from PySide6.QtGui import QAction, QColor, QPainter                 # noqa: E402
from PySide6.QtWidgets import (                                     # noqa: E402
    QApplication, QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog,
    QFormLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox,
    QSplitter, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout,
    QWidget,
)

import psutil                                                       # noqa: E402

import theme                                                        # noqa: E402
import reporting                                                    # noqa: E402
from engine import AlertEngine, Poller, _fmt_units, import_history  # noqa: E402

APP_NAME = "BMTVD - Bandwidth Monitor"
VERSION = "1.0.0"


def _data_dir():
    base = os.environ.get("BMTVD_DATA", os.path.expanduser("~/.bmtvd"))
    os.makedirs(base, exist_ok=True)
    return base


def _samples_dir():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    d = os.path.join(here, "sample_data")
    return d if os.path.isdir(d) else here


class RateChart(QWidget):
    """Minimal rolling rate chart (upload + download)."""

    def __init__(self, max_points: int = 120):
        super().__init__()
        self.up: list[float] = []
        self.down: list[float] = []
        self.max_points = max_points
        self.setMinimumHeight(160)

    def add(self, up: float, down: float):
        self.up.append(up)
        self.down.append(down)
        if len(self.up) > self.max_points:
            self.up.pop(0)
            self.down.pop(0)
        self.update()

    def load_series(self, ups, downs):
        self.up = list(ups)[-self.max_points:]
        self.down = list(downs)[-self.max_points:]
        self.update()

    def paintEvent(self, event):                            # noqa: N802
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(theme.PANEL))
        w, h = self.width(), self.height()
        peak = max([1.0] + self.up + self.down)
        # grid
        p.setPen(QColor(theme.BORDER))
        for frac in (0.25, 0.5, 0.75):
            y = int(h * frac)
            p.drawLine(0, y, w, y)
        if len(self.down) >= 2:
            def draw(series, color):
                p.setPen(QColor(color))
                step = w / max(1, self.max_points - 1)
                x0 = w - step * (len(series) - 1)
                prev = None
                for i, v in enumerate(series):
                    x = int(x0 + i * step)
                    y = int(h - (v / peak) * (h - 8) - 4)
                    if prev:
                        p.drawLine(prev[0], prev[1], x, y)
                    prev = (x, y)
            draw(self.down, theme.ACCENT)
            draw(self.up, theme.GREEN)
        p.setPen(QColor(theme.TEXT_DIM))
        p.drawText(8, 16, f"peak {_fmt_units(peak)}/s   "
                         f"down {len(self.down)} pts   up {len(self.up)} pts")
        p.end()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{VERSION}")
        self.resize(1200, 800)
        self.poller: Poller | None = None
        self.alerts_engine = AlertEngine(on_alert=self._on_alert)
        self.history: list[dict] = []          # snapshot dicts (live or imported)
        self.imported_mode = False
        central = QWidget()
        root = QVBoxLayout(central)
        self._build_menu()

        head = QHBoxLayout()
        t = QLabel("BMTVD - Bandwidth Monitor & Traffic Visualizer")
        t.setObjectName("banner")
        head.addWidget(t)
        head.addStretch(1)
        self.pill = QLabel("STOPPED")
        self.pill.setStyleSheet(f"color:{theme.RED}; font-weight:bold; padding:2px 10px;"
                                f"border:1px solid {theme.RED}; border-radius:4px;")
        head.addWidget(self.pill)
        root.addLayout(head)

        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        # ---------------- Dashboard tab
        dash = QWidget()
        tabs.addTab(dash, "Dashboard")
        dv = QVBoxLayout(dash)
        cards = QHBoxLayout()
        self.card_down = self._make_card("DOWNLOAD")
        self.card_up = self._make_card("UPLOAD")
        self.card_conns = self._make_card("CONNECTIONS")
        self.card_procs = self._make_card("ACTIVE PROCS")
        for c in (self.card_down, self.card_up, self.card_conns, self.card_procs):
            cards.addWidget(c)
        dv.addLayout(cards)
        self.chart = RateChart()
        dv.addWidget(self.chart, 1)

        ctrl_row = QHBoxLayout()
        self.start_btn = QPushButton("Start Monitoring")
        self.start_btn.setObjectName("primary")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.interval_spin = QDoubleSpinBox()
        self.interval_spin.setRange(0.5, 30.0)
        self.interval_spin.setValue(2.0)
        self.interval_spin.setSuffix(" s")
        ctrl_row.addWidget(self.start_btn)
        ctrl_row.addWidget(self.stop_btn)
        ctrl_row.addWidget(QLabel("Interval:"))
        ctrl_row.addWidget(self.interval_spin)
        ctrl_row.addStretch(1)
        dv.addLayout(ctrl_row)

        # ---------------- Processes tab
        proc_tab = QWidget()
        tabs.addTab(proc_tab, "Processes")
        pv = QVBoxLayout(proc_tab)
        self.proc_tbl = QTableWidget(0, 6)
        self.proc_tbl.setHorizontalHeaderLabels(
            ["PID", "Process", "Conn Count", "Est. Share", "Upload", "Download"])
        self.proc_tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.proc_tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.proc_tbl.setAlternatingRowColors(True)
        pv.addWidget(self.proc_tbl)
        hint = QLabel("Byte rates are estimated from connection share (psutil limitation). "
                      "Run as administrator for complete per-process visibility.")
        hint.setObjectName("dim")
        pv.addWidget(hint)

        # ---------------- Interfaces tab
        iface_tab = QWidget()
        tabs.addTab(iface_tab, "Interfaces")
        iv = QVBoxLayout(iface_tab)
        self.iface_tbl = QTableWidget(0, 6)
        self.iface_tbl.setHorizontalHeaderLabels(
            ["Interface", "Rate Down", "Rate Up", "Bytes Recv", "Bytes Sent", "Errors/Drops"])
        self.iface_tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.iface_tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.iface_tbl.setAlternatingRowColors(True)
        iv.addWidget(self.iface_tbl)

        # ---------------- Alerts tab
        alert_tab = QWidget()
        tabs.addTab(alert_tab, "Alerts")
        av = QVBoxLayout(alert_tab)
        cfg = QGroupBox("Threshold rule")
        form = QFormLayout(cfg)
        self.rule_target = QLineEdit()
        self.rule_target.setPlaceholderText("process name substring, or *total*")
        self.rule_threshold = QDoubleSpinBox()
        self.rule_threshold.setRange(0.01, 10000)
        self.rule_threshold.setValue(10)
        self.rule_threshold.setSuffix(" MB/s")
        self.rule_dir = QComboBox()
        self.rule_dir.addItems(["both", "up", "down"])
        form.addRow("Target:", self.rule_target)
        form.addRow("Threshold:", self.rule_threshold)
        form.addRow("Direction:", self.rule_dir)
        av.addWidget(cfg)
        arow = QHBoxLayout()
        add_rule_btn = QPushButton("Add Rule")
        clear_rules_btn = QPushButton("Clear Rules")
        arow.addWidget(add_rule_btn)
        arow.addWidget(clear_rules_btn)
        arow.addStretch(1)
        av.addLayout(arow)
        self.alert_list = QPlainTextEdit()
        self.alert_list.setObjectName("console")
        self.alert_list.setReadOnly(True)
        av.addWidget(self.alert_list, 1)
        add_rule_btn.clicked.connect(self._add_rule)
        clear_rules_btn.clicked.connect(self._clear_rules)

        # ---------------- History tab
        hist_tab = QWidget()
        tabs.addTab(hist_tab, "History / Import")
        hv = QVBoxLayout(hist_tab)
        hrow = QHBoxLayout()
        self.import_btn = QPushButton("Import History JSON...")
        self.export_btn = QPushButton("Export Report...")
        self.export_btn.setEnabled(False)
        hrow.addWidget(self.import_btn)
        hrow.addWidget(self.export_btn)
        hrow.addStretch(1)
        hv.addLayout(hrow)
        self.hist_info = QLabel("Import a history file to chart and report on past data.")
        self.hist_info.setObjectName("dim")
        hv.addWidget(self.hist_info)
        self.hist_chart = RateChart()
        hv.addWidget(self.hist_chart, 1)

        # ---------------- About
        about_tab = QWidget()
        tabs.addTab(about_tab, "About")
        av2 = QVBoxLayout(about_tab)
        about = QLabel(
            "<h2>BMTVD</h2>"
            "<p>Real-time bandwidth monitoring with per-process attribution via psutil, "
            "per-interface rates, rolling charts and threshold alerts.</p>"
            "<p><b>Accuracy note:</b> psutil exposes system-wide per-interface byte counters "
            "and per-process connection tables - but NOT per-process byte counts. This tool "
            "attributes interface deltas across processes by connection share and documents "
            "the limitation in every report. Run as administrator for full process visibility "
            "(otherwise some system processes appear as unknown).</p>")
        about.setWordWrap(True)
        about.setAlignment(Qt.AlignTop)
        av2.addWidget(about)

        self._wire()
        self.setCentralWidget(central)

    # ------------------------------------------------------------------ UI
    def _make_card(self, title):
        g = QGroupBox(title)
        lay = QVBoxLayout(g)
        val = QLabel("0 B/s" if title != "CONNECTIONS" and title != "ACTIVE PROCS" else "0")
        val.setStyleSheet(f"font-size:22px; font-weight:bold; color:{theme.ACCENT};")
        lay.addWidget(val)
        return g

    def _build_menu(self):
        bar = self.menuBar()
        m_file = bar.addMenu("&File")
        act_import = QAction("Import History (JSON)...", self)
        act_import.setShortcut("Ctrl+I")
        act_import.triggered.connect(self.import_history_file)
        act_quit = QAction("Exit", self)
        act_quit.triggered.connect(self.close)
        m_file.addAction(act_import)
        m_file.addSeparator()
        m_file.addAction(act_quit)

    def _wire(self):
        self.start_btn.clicked.connect(self.start_monitoring)
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.import_btn.clicked.connect(self.import_history_file)
        self.export_btn.clicked.connect(self.export_report)

    # ------------------------------------------------------------- polling
    @Slot()
    def start_monitoring(self):
        if self.poller and self.poller.is_alive():
            return
        self.imported_mode = False
        self.poller = Poller(interval=self.interval_spin.value(),
                             on_snapshot=self._on_snapshot,
                             on_event=lambda msg, level: QTimer.singleShot(
                                 0, lambda m=msg: self._log(m)))
        self.poller.start()
        self.pill.setText("MONITORING")
        self.pill.setStyleSheet(f"color:{theme.GREEN}; font-weight:bold; padding:2px 10px;"
                                f"border:1px solid {theme.GREEN}; border-radius:4px;")
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._log(f"monitoring started (interval {self.interval_spin.value()}s)")

    @Slot()
    def stop_monitoring(self):
        if self.poller:
            self.poller.stop()
        self.pill.setText("STOPPED")
        self.pill.setStyleSheet(f"color:{theme.RED}; font-weight:bold; padding:2px 10px;"
                                f"border:1px solid {theme.RED}; border-radius:4px;")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._log("monitoring stopped")

    def _on_snapshot(self, snap):
        record = {
            "timestamp": snap.timestamp.isoformat(timespec="seconds"),
            "total_upload_bps": snap.total_upload_bps,
            "total_download_bps": snap.total_download_bps,
            "connection_count": snap.connection_count,
            "interfaces": {name: {"bytes_sent": i.bytes_sent, "bytes_recv": i.bytes_recv,
                                  "packets_sent": i.packets_sent, "packets_recv": i.packets_recv,
                                  "errors_in": i.errors_in, "errors_out": i.errors_out,
                                  "drops_in": i.drops_in, "drops_out": i.drops_out}
                           for name, i in snap.interfaces.items()},
            "interface_rates": {name: {"up": r[0], "down": r[1]}
                                for name, r in snap.interface_rates.items()},
            "processes": [{"pid": p.pid, "name": p.name, "upload_bps": p.upload_bps,
                           "download_bps": p.download_bps,
                           "connection_count": p.connection_count}
                          for p in snap.processes],
        }
        self.history.append(record)
        del self.history[:3600]                 # cap ~2h at 2s
        self.alerts_engine.evaluate(snap)
        QTimer.singleShot(0, lambda r=record: self._apply_record(r))

    def _apply_record(self, rec):
        up = rec["total_upload_bps"]
        down = rec["total_download_bps"]
        self.card_down.findChild(QLabel).setText(f"{_fmt_units(down)}/s")
        self.card_up.findChild(QLabel).setText(f"{_fmt_units(up)}/s")
        self.card_conns.findChild(QLabel).setText(str(rec.get("connection_count", 0)))
        self.card_procs.findChild(QLabel).setText(str(len(rec.get("processes", []))))
        self.chart.add(up, down)
        # process table
        procs = rec.get("processes", [])
        self.proc_tbl.setRowCount(len(procs))
        for row, p in enumerate(procs):
            conns = p.get("connection_count", 0)
            share = f"{_fmt_units(p.get('download_bps', 0) + p.get('upload_bps', 0))}/s"
            vals = [str(p.get("pid")), p.get("name", "?"), str(conns), share,
                    f"{_fmt_units(p.get('upload_bps', 0))}/s",
                    f"{_fmt_units(p.get('download_bps', 0))}/s"]
            for col, v in enumerate(vals):
                self.proc_tbl.setItem(row, col, QTableWidgetItem(v))
        # interface table
        ifaces = rec.get("interface_rates", {})
        self.iface_tbl.setRowCount(len(ifaces))
        for row, (name, rate) in enumerate(ifaces.items()):
            counters = rec.get("interfaces", {}).get(name, {})
            errs = (counters.get("errors_in", 0) + counters.get("errors_out", 0)
                    + counters.get("drops_in", 0) + counters.get("drops_out", 0))
            vals = [name, f"{_fmt_units(rate.get('down', 0))}/s",
                    f"{_fmt_units(rate.get('up', 0))}/s",
                    _fmt_units(counters.get("bytes_recv", 0)),
                    _fmt_units(counters.get("bytes_sent", 0)), str(errs)]
            for col, v in enumerate(vals):
                self.iface_tbl.setItem(row, col, QTableWidgetItem(v))

    # -------------------------------------------------------------- alerts
    def _add_rule(self):
        target = self.rule_target.text().strip()
        if not target:
            QMessageBox.warning(self, APP_NAME, "Enter a target (process name or *total*).")
            return
        self.alerts_engine.add_rule(target, self.rule_threshold.value(),
                                    self.rule_dir.currentText())
        self._log(f"alert rule added: {target} > {self.rule_threshold.value()} MB/s")

    def _clear_rules(self):
        self.alerts_engine.clear()
        self._log("alert rules cleared")

    def _on_alert(self, msg, level):
        QTimer.singleShot(0, lambda m=msg: self._log(m, "red"))

    def _log(self, msg, color="gray"):
        hexc = {"red": theme.RED, "green": theme.GREEN,
                "gray": theme.TEXT_DIM}.get(color, theme.TEXT_DIM)
        self.alert_list.appendHtml(f'<span style="color:{hexc}">{msg}</span>')

    # ------------------------------------------------------------- import
    @Slot()
    def import_history_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import History (JSON)", _samples_dir(),
            "History (*.json);;All files (*)")
        if not path:
            return
        try:
            snaps = import_history(path)
        except Exception as exc:                              # noqa: BLE001
            QMessageBox.critical(self, APP_NAME, f"Import failed: {exc}")
            return
        if not snaps:
            QMessageBox.warning(self, APP_NAME, "No snapshots in file.")
            return
        self.history = list(snaps)
        self.imported_mode = True
        self.export_btn.setEnabled(True)
        ups = [s.get("total_upload_bps", 0) for s in snaps]
        downs = [s.get("total_download_bps", 0) for s in snaps]
        self.hist_chart.load_series(ups, downs)
        self.hist_info.setText(
            f"Imported {len(snaps)} snapshots from {os.path.basename(path)} - "
            f"{snaps[0].get('timestamp', '')} -> {snaps[-1].get('timestamp', '')}")
        self._log(f"imported {len(snaps)} snapshots from {os.path.basename(path)}")
        self.statusBar().showMessage(f"Imported history: {len(snaps)} snapshots")

    # ------------------------------------------------------------- report
    @Slot()
    def export_report(self):
        if not self.history:
            QMessageBox.information(self, APP_NAME, "No data yet - start monitoring or "
                                                    "import a history file.")
            return
        period = (self.history[0].get("timestamp", ""),
                  self.history[-1].get("timestamp", ""))
        alerts = self.alerts_engine.alerts
        system = (f"{os.name} / {psutil.cpu_count()} CPUs / "
                  f"{_fmt_units(psutil.virtual_memory().total)} RAM")
        session = (period, self.history, alerts, system)
        fmt, ok = __import__("PySide6.QtWidgets", fromlist=["QInputDialog"]) \
            .QInputDialog.getItem(self, "Export Report", "Format:",
                                  ["pdf", "html", "json", "csv", "txt"], 0, False)
        if not ok:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report",
            os.path.join(_data_dir(), "reports", f"bmtvd_{int(__import__('time').time())}.{fmt}"),
            f"{fmt.upper()} (*.{fmt})")
        if not path:
            return
        try:
            out = reporting.export(session, fmt, path)
        except Exception as exc:                              # noqa: BLE001
            QMessageBox.critical(self, APP_NAME, f"Export failed: {exc}")
            return
        self._log(f"report -> {out}")
        QMessageBox.information(self, APP_NAME, f"Report written:\n{out}")

    def closeEvent(self, event):
        self.stop_monitoring()
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
