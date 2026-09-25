"""DRCP - DNS Resolver & Cache Poisoning Lab. Main Qt application."""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PySide6.QtCore import Qt, QTimer, Slot                          # noqa: E402
from PySide6.QtGui import QAction, QColor                             # noqa: E402
from PySide6.QtWidgets import (                                       # noqa: E402
    QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QStatusBar,
    QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

import theme                                                          # noqa: E402
import reporting                                                      # noqa: E402
from engine import (                                                  # noqa: E402
    DNSCache, LabController, LabSession, check_isolation, session_from_dict,
)

APP_NAME = "DRCP - DNS Cache Poisoning Lab"
VERSION = "1.0.0"

COLORS = {"green": theme.GREEN, "red": theme.RED, "orange": theme.ORANGE,
          "blue": theme.ACCENT, "gray": theme.TEXT_DIM, "yellow": theme.YELLOW}


def _data_dir():
    base = os.environ.get("DRCP_DATA", os.path.expanduser("~/.drcp"))
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
        self.resize(1180, 780)
        self.lab = LabController()
        self.session: LabSession | None = None
        self._poll = QTimer(self)
        self._poll.timeout.connect(self._poll_logs)
        self._poll.start(150)
        central = QWidget()
        root = QVBoxLayout(central)

        head = QHBoxLayout()
        t = QLabel("DRCP - DNS Cache Poisoning Lab")
        t.setObjectName("banner")
        head.addWidget(t)
        head.addStretch(1)
        self.safety = QLabel("ISOLATED LAB ONLY")
        self.safety.setStyleSheet(f"color:{theme.RED}; font-weight:bold; padding:2px 10px;"
                                  f"border:1px solid {theme.RED}; border-radius:4px;")
        head.addWidget(self.safety)
        root.addLayout(head)

        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        # ---------------- Lab tab
        lab_tab = QWidget()
        tabs.addTab(lab_tab, "Lab")
        lv = QVBoxLayout(lab_tab)

        cfg = QGroupBox("Lab Configuration")
        form = QFormLayout(cfg)
        self.resolver_port = QSpinBox(); self.resolver_port.setRange(1024, 65535); self.resolver_port.setValue(5311)
        self.upstream_port = QSpinBox(); self.upstream_port.setRange(1024, 65535); self.upstream_port.setValue(5301)
        self.domain_edit = QLineEdit("bank.test.lab")
        self.legit_edit = QLineEdit("203.0.113.12")
        self.forged_edit = QLineEdit("6.6.6.6")
        self.rnd_port = QCheckBox("Randomize upstream source port (defense)")
        self.rnd_port.setChecked(True)
        self.dnssec = QCheckBox("Enable DNSSEC validation demo (defense)")
        form.addRow("Resolver listen port:", self.resolver_port)
        form.addRow("Fake authoritative port:", self.upstream_port)
        form.addRow("Target domain:", self.domain_edit)
        form.addRow("Legitimate answer:", self.legit_edit)
        form.addRow("Forged (attacker) answer:", self.forged_edit)
        form.addRow("", self.rnd_port)
        form.addRow("", self.dnssec)
        lv.addWidget(cfg)

        btns = QHBoxLayout()
        self.start_btn = QPushButton("Start Lab")
        self.start_btn.setObjectName("primary")
        self.stop_btn = QPushButton("Stop Lab")
        self.stop_btn.setEnabled(False)
        self.query_btn = QPushButton("1. Trigger Query")
        self.query_btn.setEnabled(False)
        self.attack_btn = QPushButton("2. Run Poisoning Attack")
        self.attack_btn.setObjectName("danger")
        self.attack_btn.setEnabled(False)
        self.verify_btn = QPushButton("3. Verify Cache")
        self.verify_btn.setEnabled(False)
        self.import_btn = QPushButton("Import Lab Session...")
        self.export_btn = QPushButton("Export Report...")
        self.export_btn.setEnabled(False)
        for b in (self.start_btn, self.stop_btn, self.query_btn, self.attack_btn,
                  self.verify_btn, self.import_btn, self.export_btn):
            btns.addWidget(b)
        btns.addStretch(1)
        lv.addLayout(btns)

        self.strategy_combo = QComboBox()
        self.strategy_combo.addItems(["known (educational omniscience)", "sequential", "random"])
        self.attempts_spin = QSpinBox()
        self.attempts_spin.setRange(100, 65536)
        self.attempts_spin.setValue(20000)
        srow = QHBoxLayout()
        srow.addWidget(QLabel("Guess strategy:"))
        srow.addWidget(self.strategy_combo)
        srow.addWidget(QLabel("Max attempts:"))
        srow.addWidget(self.attempts_spin)
        srow.addStretch(1)
        lv.addLayout(srow)

        self.console = QPlainTextEdit()
        self.console.setObjectName("console")
        self.console.setReadOnly(True)
        lv.addWidget(self.console, 1)

        # ---------------- Cache tab
        cache_tab = QWidget()
        tabs.addTab(cache_tab, "Cache Inspector")
        cv = QVBoxLayout(cache_tab)
        self.cache_tbl = QTableWidget(0, 5)
        self.cache_tbl.setHorizontalHeaderLabels(["Domain", "Type", "Value", "TTL", "Source"])
        self.cache_tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.cache_tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.cache_tbl.setAlternatingRowColors(True)
        cv.addWidget(self.cache_tbl)
        crow = QHBoxLayout()
        self.flush_btn = QPushButton("Flush Cache")
        self.refresh_btn = QPushButton("Refresh")
        crow.addWidget(self.flush_btn)
        crow.addWidget(self.refresh_btn)
        crow.addStretch(1)
        cv.addLayout(crow)

        # ---------------- Timeline tab
        tl_tab = QWidget()
        tabs.addTab(tl_tab, "Attack Timeline")
        tv = QVBoxLayout(tl_tab)
        self.tl_tbl = QTableWidget(0, 4)
        self.tl_tbl.setHorizontalHeaderLabels(["Time", "Event", "Detail", "Class"])
        self.tl_tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tl_tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        tv.addWidget(self.tl_tbl)

        # ---------------- About
        about_tab = QWidget()
        tabs.addTab(about_tab, "About / Safety")
        av = QVBoxLayout(about_tab)
        about = QLabel(
            "<h2>DRCP</h2>"
            "<p>Educational DNS resolver with a guided cache-poisoning demonstration.</p>"
            "<p><b>How the attack works:</b> DNS responses over UDP are matched to queries only by "
            "a 16-bit transaction ID (and, since 2008, the source port). If an attacker can guess "
            "the ID and reply before the legitimate authoritative server, the resolver caches the "
            "forged record for the TTL.</p>"
            "<p><b>Defenses demonstrated:</b> source port randomization (search space > 1 billion) "
            "and DNSSEC validation (forged answers lack valid RRSIG signatures and are rejected).</p>"
            "<p><b>Safety:</b> the lab refuses public resolvers (8.8.8.8, 1.1.1.1, ...); all "
            "traffic is confined to 127.0.0.1. The fake authoritative server serves a static "
            "zone. Nothing leaves your machine.</p>")
        about.setWordWrap(True)
        about.setAlignment(Qt.AlignTop)
        av.addWidget(about)

        self._wire()
        self.setCentralWidget(central)

    def _wire(self):
        self.start_btn.clicked.connect(self.start_lab)
        self.stop_btn.clicked.connect(self.stop_lab)
        self.query_btn.clicked.connect(self.trigger_query)
        self.attack_btn.clicked.connect(self.run_attack)
        self.verify_btn.clicked.connect(self.verify_cache)
        self.import_btn.clicked.connect(self.import_session)
        self.export_btn.clicked.connect(self.export_report)
        self.flush_btn.clicked.connect(self.flush_cache)
        self.refresh_btn.clicked.connect(self.refresh_cache)

    # ----------------------------------------------------------- lab flow
    @Slot()
    def start_lab(self):
        ok, msg = self.lab.start_lab(
            resolver_port=self.resolver_port.value(),
            upstream_port=self.upstream_port.value(),
            randomize_port=self.rnd_port.isChecked(),
            dnssec=self.dnssec.isChecked(),
        )
        self._log(msg, "green" if ok else "red")
        self.start_btn.setEnabled(not ok)
        self.stop_btn.setEnabled(ok)
        self.query_btn.setEnabled(ok)
        self.attack_btn.setEnabled(ok)
        self.verify_btn.setEnabled(ok)
        self.refresh_cache()

    @Slot()
    def stop_lab(self):
        self.lab.stop_lab()
        self._log("lab stopped", "gray")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.query_btn.setEnabled(False)
        self.attack_btn.setEnabled(False)
        self.verify_btn.setEnabled(False)

    @Slot()
    def trigger_query(self):
        domain = self.domain_edit.text().strip()
        self._log(f"stub query for {domain}", "blue")
        ans, status = self.lab.trigger_query(domain)
        if ans:
            self._log(f"resolver answered: {domain} -> {ans}", "green")
        else:
            self._log(f"query failed ({status})", "red")
        self.refresh_cache()

    @Slot()
    def run_attack(self):
        if not self.lab.resolver:
            return
        strategy = self.strategy_combo.currentText().split(" ")[0]
        self._cache_before = self.lab.resolver.cache.dump()
        attacker = self.lab.run_attack(
            self.domain_edit.text().strip(), self.forged_edit.text().strip(),
            strategy, self.attempts_spin.value())
        if attacker:
            self._log(f"attack running: strategy={strategy} forged-ip={self.forged_edit.text()}",
                      "red")
            self.attack_btn.setEnabled(False)
            QTimer.singleShot(500, self._check_attack)

    def _check_attack(self):
        atk = self.lab.attacker
        if atk and atk.is_alive():
            QTimer.singleShot(500, self._check_attack)
            return
        if not atk:
            return
        self.attack_btn.setEnabled(bool(self.lab.resolver))
        for entry in atk.log:
            self._log(entry["msg"], entry["color"])
        self.refresh_cache()
        success = atk.success
        cache_after = self.lab.resolver.cache.dump()
        # Build the session record
        legit = self.legit_edit.text().strip()
        self.session = LabSession(
            lab_id=f"lab-{int(time.time())}",
            timestamp=__import__("datetime").datetime.now(),
            resolver_port=self.resolver_port.value(),
            upstream_port=self.upstream_port.value(),
            target_domain=self.domain_edit.text().strip(),
            legitimate_answer=legit,
            forged_answer=self.forged_edit.text().strip(),
            port_randomization=self.rnd_port.isChecked(),
            dnssec_mode=self.dnssec.isChecked(),
            strategy=self.strategy_combo.currentText().split(" ")[0],
            attempts=atk.attempts,
            poisoning_successful=success,
            cache_before=self._cache_before,
            cache_after=cache_after,
            steps=[],
            resolver_log=self.lab.resolver.events if self.lab.resolver else [],
            attack_log=atk.log,
        )
        self.export_btn.setEnabled(True)
        verdict = "CACHE POISONED" if success else "DEFENSES HELD"
        self._log(f"=== {verdict} after {atk.attempts} attempts ===",
                  "red" if success else "green")
        self.statusBar().showMessage(verdict)

    @Slot()
    def verify_cache(self):
        if not self.lab.resolver:
            return
        from engine import verify_poisoning
        domain = self.domain_edit.text().strip()
        # bypass cache to test resolution path: flush first for clarity
        ans, poisoned = verify_poisoning(self.resolver_port.value(), domain)
        entry = self.lab.resolver.cache.get(domain, "A")
        self._log(f"verify {domain}: live answer={ans} cached={entry.value if entry else None} "
                  f"source={entry.source if entry else 'n/a'}",
                  "red" if entry and entry.source == "forged" else "green")
        self.refresh_cache()

    # ------------------------------------------------------------- helpers
    def refresh_cache(self):
        if not self.lab.resolver:
            return
        entries = self.lab.resolver.cache.dump()
        self.cache_tbl.setRowCount(0)
        for e in entries:
            row = self.cache_tbl.rowCount()
            self.cache_tbl.insertRow(row)
            vals = [e.domain, e.record_type, e.value, str(e.expires_in()), e.source]
            for col, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if col == 4:
                    item.setForeground(QColor(theme.RED if e.source == "forged" else theme.GREEN))
                self.cache_tbl.setItem(row, col, item)

    def flush_cache(self):
        if self.lab.resolver:
            self.lab.resolver.cache.flush()
            self._log("cache flushed", "gray")
            self.refresh_cache()

    def _poll_logs(self):
        if self.lab.resolver:
            for ev in self.lab.resolver.drain_events():
                self._log(f"[resolver] {ev['detail']}", ev["color"])
            self._update_timeline()

    def _update_timeline(self):
        if not self.lab.resolver:
            return
        events = (self.lab.resolver.events + self._recent_attack())
        # events were drained; use stored session if present
        if not self.session:
            return
        rows = []
        for ev in self.session.resolver_log:
            rows.append((ev.get("ts", ""), "resolver", ev.get("detail", "")))
        for ev in self.session.attack_log:
            rows.append((ev.get("ts", ""), "attack", ev.get("msg", "")))
        self.tl_tbl.setRowCount(0)
        for ts, src, detail in rows[-200:]:
            row = self.tl_tbl.rowCount()
            self.tl_tbl.insertRow(row)
            color = theme.RED if ("reject" in detail or "POISON" in detail.upper()) else theme.TEXT
            if "POISON" in detail.upper() or "forged" in detail:
                color = theme.RED
            for col, v in enumerate((ts, src, detail, src)):
                item = QTableWidgetItem(str(v))
                if col >= 1 and color != theme.TEXT:
                    item.setForeground(QColor(color))
                self.tl_tbl.setItem(row, col, item)

    def _recent_attack(self):
        if self.lab.attacker:
            return [{"ts": e["ts"], "kind": "attack", "detail": e["msg"], "color": e["color"]}
                    for e in self.lab.attacker.log[-5:]]
        return []

    def _log(self, msg, color="gray"):
        hexc = COLORS.get(color, theme.TEXT_DIM)
        self.console.appendHtml(f'<span style="color:{hexc}">{msg}</span>')

    # ------------------------------------------------------------- reports
    @Slot()
    def export_report(self):
        if not self.session:
            QMessageBox.information(self, APP_NAME, "Run the lab first (or import a session).")
            return
        fmt, ok = QInputDialog.getItem(self, "Export Report", "Format:",
                                       ["pdf", "html", "json", "csv", "txt"], 0, False)
        if not ok:
            return
        reports_dir = os.path.join(_data_dir(), "reports")
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", os.path.join(reports_dir, f"{self.session.lab_id}.{fmt}"),
            f"{fmt.upper()} (*.{fmt})")
        if not path:
            return
        try:
            out = reporting.export(self.session, fmt, path)
        except Exception as exc:                                # noqa: BLE001
            QMessageBox.critical(self, APP_NAME, f"Export failed: {exc}")
            return
        self._log(f"report -> {out}", "blue")
        QMessageBox.information(self, APP_NAME, f"Report written:\n{out}")

    @Slot()
    def import_session(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Lab Session (JSON)", _samples_dir(),
            "Lab session (*.json);;All files (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            self.session = session_from_dict(raw)
        except Exception as exc:                                # noqa: BLE001
            QMessageBox.critical(self, APP_NAME, f"Import failed: {exc}")
            return
        self.export_btn.setEnabled(True)
        # display imported cache
        self.cache_tbl.setRowCount(0)
        for e in self.session.cache_after:
            row = self.cache_tbl.rowCount()
            self.cache_tbl.insertRow(row)
            vals = [str(e.get("domain", "")), str(e.get("type", "A")), str(e.get("value", "")),
                    str(e.get("ttl", 0)), str(e.get("source", ""))]
            for col, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if col == 4 and v == "forged":
                    item.setForeground(QColor(theme.RED))
                self.cache_tbl.setItem(row, col, item)
        # display logs
        self._log(f"imported session {self.session.lab_id} from {os.path.basename(path)}", "blue")
        for ev in self.session.resolver_log:
            self._log(f"[resolver] {ev.get('detail', '')}", "gray")
        for ev in self.session.attack_log:
            self._log(f"[attack] {ev.get('msg', '')}", "red" if "SUCCESS" in str(ev.get("msg", "")).upper() else "gray")
        verdict = "POISONING SUCCESSFUL" if self.session.poisoning_successful else "DEFENSES HELD"
        self._log(f"=== {verdict} ({self.session.attempts} attempts) ===",
                  "red" if self.session.poisoning_successful else "green")
        self.statusBar().showMessage(f"Imported session {self.session.lab_id}")

    def closeEvent(self, event):
        self.lab.stop_lab()
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
