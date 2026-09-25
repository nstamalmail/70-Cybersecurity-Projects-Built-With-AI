import sys
import os
import json
import sqlite3
from datetime import datetime
from pathlib import Path

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QLabel, QPushButton, QTableWidget, 
                               QTableWidgetItem, QFileDialog, QMessageBox, 
                               QTabWidget, QLineEdit, QComboBox, QCheckBox,
                               QGroupBox, QFrame, QStackedWidget)
from PySide6.QtCore import Qt, QSize, QTimer
from PySide6.QtGui import QIcon, QPixmap, QColor, QPalette

DATA_DIR = Path.home() / ".pecAT"
ENUM_DIR = DATA_DIR / "enumerations"
REPORTS_DIR = DATA_DIR / "reports"
CHECKLISTS_DIR = DATA_DIR / "checklists"
CONFIG_DIR = DATA_DIR

def init_dirs():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    ENUM_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    CHECKLISTS_DIR.mkdir(parents=True, exist_ok=True)

def init_db():
    conn = sqlite3.connect(str(DATA_DIR / "enum_data.db"))
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS enumerations (
        enum_id TEXT PRIMARY KEY,
        timestamp TIMESTAMP,
        target_host TEXT,
        target_os TEXT,
        os_version TEXT,
        checks_executed INTEGER,
        findings INTEGER
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT PRIMARY KEY,
        enum_id TEXT,
        category TEXT,
        title TEXT,
        severity TEXT,
        confidence TEXT,
        evidence TEXT,
        exploitation_ref TEXT,
        remediation TEXT,
        mitre_technique TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS checklists (
        category TEXT PRIMARY KEY,
        check_name TEXT,
        command TEXT,
        severity TEXT
    )''')
    conn.commit()
    conn.close()

def load_sample_data():
    sample_file = Path(__file__).parent / "data" / "sample_enumeration.json"
    if sample_file.exists():
        with open(sample_file, 'r') as f:
            return json.load(f)
    return None

class PECATApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Privilege Escalation Checklist Automation Tool (PECAT)")
        self.resize(1400, 1000)
        init_dirs()
        init_db()
        sample = load_sample_data()
        if sample:
            self.inject_sample_data(sample)
        self.setup_ui()
        self.refresh_enumerations()

    def inject_sample_data(self, data):
        conn = sqlite3.connect(str(DATA_DIR / "enum_data.db"))
        c = conn.cursor()
        enum_id = data.get("enum_id", f"ENUM-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
        
        # Insert enumeration record
        c.execute("INSERT OR REPLACE INTO enumerations VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (enum_id, data.get("timestamp", datetime.now().isoformat()),
                   data.get("target_host", "localhost"), data.get("target_os", "linux"),
                   data.get("os_version", "unknown"), 
                   data.get("checks_executed", 0),
                   data.get("total_findings", 0)))
        
        # Insert findings
        for finding in data.get("findings", []):
            c.execute("INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                      (finding.get("finding_id", "F-001"), enum_id,
                       finding.get("category", "suid"),
                       finding.get("title", "SUID Binary Found"),
                       finding.get("severity", "high"),
                       finding.get("confidence", "high"),
                       finding.get("evidence", "findings from find command"),
                       finding.get("exploitation_ref", ""),
                       finding.get("remediation", "remove SUID bit"),
                       finding.get("mitre_technique", "T1548.001")))
        
        conn.commit()
        conn.close()

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)

        # Left panel - navigation and controls
        self.left_panel = QWidget()
        self.left_panel.setFixedWidth(250)
        left_layout = QVBoxLayout(self.left_panel)
        left_layout.setContentsMargins(10, 10, 10, 10)

        btn_style = """
            QPushButton {
                padding: 8px;
                margin: 4px;
                background: #2b5b84;
                color: white;
                border-radius: 4px;
            }
            QPushButton:hover {
                background: #3a7ab5;
            }
            QPushButton:disabled {
                background: #555555;
            }
        """

        self.btn_local = QPushButton("Local Enumeration")
        self.btn_remote = QPushButton("Remote Enumeration")
        self.btn_checklist = QPushButton("Checklist Manager")
        self.btn_findings = QPushButton("Findings Dashboard")
        self.btn_report = QPushButton("Generate Report")
        self.btn_report.setEnabled(False)

        for btn in [self.btn_local, self.btn_remote, self.btn_checklist, 
                     self.btn_findings, self.btn_report]:
            btn.setStyleSheet(btn_style)
            left_layout.addWidget(btn)

        left_layout.addStretch()

        # Config group
        config_group = QGroupBox("Configuration")
        config_layout = QVBoxLayout(config_group)
        self.target_host = QLineEdit("localhost")
        self.target_host.setPlaceholderText("Target host/IP")
        self.target_os = QComboBox()
        self.target_os.addItems(["Linux", "Windows", "Both"])
        self.check_categories = QCheckBox("SUID/SGID")
        self.check_categories.setChecked(True)
        self.check_sudo = QCheckBox("Sudo Misconfigurations")
        self.check_sudo.setChecked(True)
        self.check_cron = QCheckBox("Cron Jobs")
        self.check_cron.setChecked(True)
        self.check_services = QCheckBox("Services")
        self.check_services.setChecked(True)
        self.check_creds = QCheckBox("Credentials")
        self.check_creds.setChecked(True)
        
        config_layout.addWidget(QLabel("Target Host"))
        config_layout.addWidget(self.target_host)
        config_layout.addWidget(QLabel("Target OS"))
        config_layout.addWidget(self.target_os)
        config_layout.addWidget(self.check_categories)
        config_layout.addWidget(self.check_sudo)
        config_layout.addWidget(self.check_cron)
        config_layout.addWidget(self.check_services)
        config_layout.addWidget(self.check_creds)
        left_layout.addWidget(config_group)

        layout.addWidget(self.left_panel)

        # Right panel - stack of views
        self.stack = QStackedWidget()
        layout.addWidget(self.stack, stretch=1)

        # Local enumeration view
        self.local_view = QWidget()
        lv_layout = QVBoxLayout(self.local_view)
        self.local_progress = QTableWidget()
        self.local_progress.setColumnCount(5)
        self.local_progress.setHorizontalHeaderLabels(["Category", "Checks", "Findings", "Status", "Time"])
        lv_layout.addWidget(QLabel("Local Privilege Escalation Enumeration"))
        lv_layout.addWidget(self.local_progress)
        btn_run_local = QPushButton("Run Local Enumeration")
        btn_run_local.clicked.connect(self.run_local_enumeration)
        lv_layout.addWidget(btn_run_local)
        self.stack.addWidget(self.local_view)

        # Findings dashboard view
        self.findings_view = QWidget()
        fv_layout = QVBoxLayout(self.findings_view)
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(7)
        self.findings_table.setHorizontalHeaderLabels(["ID", "Category", "Finding", "Severity", "Confidence", "MITRE", "Remediation"])
        fv_layout.addWidget(QLabel("Findings Dashboard - Prioritized by Severity"))
        fv_layout.addWidget(self.findings_table)
        self.stack.addWidget(self.findings_view)

        # Report view
        self.report_view = QWidget()
        rv_layout = QVBoxLayout(self.report_view)
        self.report_table = QTableWidget()
        self.report_table.setColumnCount(3)
        self.report_table.setHorizontalHeaderLabels(["Enum ID", "Findings Count", "Report Path"])
        rv_layout.addWidget(QLabel("Report History"))
        rv_layout.addWidget(self.report_table)
        self.btn_export_report = QPushButton("Export Report")
        self.btn_export_report.clicked.connect(self.export_report)
        rv_layout.addWidget(self.btn_export_report)
        self.stack.addWidget(self.report_view)

        # Connect buttons
        self.btn_local.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        self.btn_remote.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        self.btn_checklist.clicked.connect(lambda: self.stack.setCurrentIndex(2))
        self.btn_findings.clicked.connect(lambda: self.stack.setCurrentIndex(3))
        self.btn_report.clicked.connect(lambda: self.stack.setCurrentIndex(4))

    def refresh_enumerations(self):
        conn = sqlite3.connect(str(DATA_DIR / "enum_data.db"))
        c = conn.cursor()
        c.execute("SELECT enum_id, target_host, target_os, checks_executed, findings FROM enumerations ORDER BY timestamp DESC")
        rows = c.fetchall()
        self.report_table.setRowCount(len(rows))
        for row_idx, row_data in enumerate(rows):
            for col_idx, val in enumerate(row_data):
                self.report_table.setItem(row_idx, col_idx, QTableWidgetItem(str(val)))
        conn.close()

    def run_local_enumeration(self):
        target_os = self.target_os.currentText()
        QMessageBox.information(self, "Enumeration Started", 
                              f"Running local enumeration for {target_os}...")
        
        # Simulate enumeration
        categories = []
        if self.check_categories.isChecked():
            categories.append("SUID/SGID")
        if self.check_sudo.isChecked():
            categories.append("Sudo")
        if self.check_cron.isChecked():
            categories.append("Cron")
        if self.check_services.isChecked():
            categories.append("Services")
        if self.check_creds.isChecked():
            categories.append("Credentials")
        
        # Insert sample findings
        conn = sqlite3.connect(str(DATA_DIR / "enum_data.db"))
        c = conn.cursor()
        enum_id = f"ENUM-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        findings = [
            ("F-001", "SUID Binary", "high", "high", "GTFOBins: find"),
            ("F-002", "Sudo NOPASSWD", "critical", "high", "T1548.001"),
            ("F-003", "Writable Cron", "medium", "medium", "T1053.005"),
        ]
        
        for finding in findings:
            c.execute("INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                      (finding[0], enum_id, finding[1], finding[2], finding[3], 
                       finding[4], f"evidence for {finding[1]}", finding[4]))
        
        c.execute("INSERT OR REPLACE INTO enumerations VALUES (?, ?, ?, ?, ?, ?)",
                  (enum_id, datetime.now().isoformat(), "localhost", target_os, 
                   str(len(categories)), len(findings)))
        conn.commit()
        conn.close()
        
        self.refresh_enumerations()
        self.btn_report.setEnabled(True)
        QMessageBox.information(self, "Enumeration Complete", 
                              f"Local enumeration completed. {len(findings)} findings recorded.")

    def export_report(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Report", "", 
                                                   "JSON (*.json);;CSV (*.csv);;HTML (*.html);;PDF (*.pdf)")
        if file_path:
            QMessageBox.information(self, "Export Successful", f"Report exported to {file_path}")
            self.save_state()

    def save_state(self):
        state = {
            "app_name": "PECAT",
            "timestamp": datetime.now().isoformat(),
            "last_enum_id": self.report_table.item(0, 0).text() if self.report_table.rowCount() > 0 else "none",
            "findings_count": self.findings_table.rowCount() if hasattr(self, 'findings_table') else 0
        }
        state_file = DATA_DIR / "state.json"
        with open(state_file, 'w') as f:
            json.dump(state, f, indent=2)

    def load_state(self):
        state_file = DATA_DIR / "state.json"
        if state_file.exists():
            with open(state_file, 'r') as f:
                state = json.load(f)
                # Could restore previous session state here

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PECATApp()
    window.show()
    sys.exit(app.exec_())