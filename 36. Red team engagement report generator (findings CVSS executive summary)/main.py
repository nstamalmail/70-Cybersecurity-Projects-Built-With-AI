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
                               QGroupBox, QFrame, QTextEdit, QSpinBox, QDoubleSpinBox,
                               QStackedWidget)
from PySide6.QtCore import Qt, QSize, QTimer
from PySide6.QtGui import QIcon, QPixmap, QColor, QPalette

DATA_DIR = Path.home() / ".rterg"
ENGAGEMENTS_DIR = DATA_DIR / "engagements"
TEMPLATES_DIR = DATA_DIR / "templates"
LOGS_DIR = DATA_DIR / "logs"

def init_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ENGAGEMENTS_DIR.mkdir(parents=True, exist_ok=True)
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

def init_db():
    conn = sqlite3.connect(str(DATA_DIR / "engagement_data.db"))
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS engagements (
        engagement_id TEXT PRIMARY KEY,
        client_name TEXT,
        engagement_type TEXT,
        scope TEXT,
        timeline_start TIMESTAMP,
        timeline_end TIMESTAMP,
        team_members TEXT,
        rules_of_engagement TEXT,
        findings TEXT,
        attack_chains TEXT,
        executive_summary TEXT,
        created_at TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT PRIMARY KEY,
        engagement_id TEXT,
        title TEXT,
        description TEXT,
        cvss_version TEXT,
        cvss_score REAL,
        severity TEXT,
        technical_details TEXT,
        remediation_short TEXT,
        remediation_long TEXT,
        remediation_effort TEXT,
        status TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS attack_chains (
        chain_id TEXT PRIMARY KEY,
        engagement_id TEXT,
        title TEXT,
        objective TEXT,
        cumulative_severity TEXT,
        steps TEXT
    )''')
    conn.commit()
    conn.close()

def load_sample_data():
    sample_file = Path(__file__).parent / "data" / "sample_engagement.json"
    if sample_file.exists():
        with open(sample_file, 'r') as f:
            return json.load(f)
    return None

class RTERGApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Red Team Engagement Report Generator (RTERG)")
        self.resize(1400, 1000)
        init_dirs()
        init_db()
        sample = load_sample_data()
        if sample:
            self.inject_sample_data(sample)
        self.setup_ui()
        self.refresh_engagements()

    def inject_sample_data(self, data):
        conn = sqlite3.connect(str(DATA_DIR / "engagement_data.db"))
        c = conn.cursor()
        
        engagement = data.get("engagement", {})
        engagement_id = engagement.get("engagement_id", "ENG-001")
        
        # Insert engagement
        findings = engagement.get("findings", [])
        findings_json = json.dumps(findings) if findings else "[]"
        
        chains = engagement.get("attack_chains", [])
        chains_json = json.dumps(chains) if chains else "[]"
        
        c.execute("INSERT OR REPLACE INTO engagements VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (engagement_id,
                   engagement.get("client_name", "Client Name"),
                   engagement.get("engagement_type", "red_team"),
                   engagement.get("scope", "[]"),
                   engagement.get("timeline_start", datetime.now().isoformat()),
                   engagement.get("timeline_end", datetime.now().isoformat()),
                   engagement.get("team_members", "[]"),
                   engagement.get("rules_of_engagement", ""),
                   findings_json,
                   chains_json,
                   engagement.get("executive_summary", ""),
                   engagement.get("created_at", datetime.now().isoformat())))
        
        # Insert findings
        for f in findings:
            c.execute("INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                      (f.get("finding_id", "F-001"), engagement_id,
                       f.get("title", "Finding Title"),
                       f.get("description", "Finding description"),
                       f.get("cvss_version", "3.1"),
                       f.get("cvss_score", 9.0),
                       f.get("severity", "critical"),
                       f.get("technical_details", ""),
                       f.get("remediation_short", "Short-term mitigation"),
                       f.get("remediation_long", "Long-term fix"),
                       f.get("remediation_effort", "medium"),
                       f.get("status", "draft")))
        
        # Insert attack chains
        for ch in chains:
            steps = ch.get("steps", [])
            steps_json = json.dumps(steps) if steps else "[]"
            c.execute("INSERT OR REPLACE INTO attack_chains VALUES (?, ?, ?, ?, ?, ?)",
                      (ch.get("chain_id", "CH-001"), engagement_id,
                       ch.get("title", "Attack Chain Title"),
                       ch.get("objective", "objective"),
                       ch.get("cumulative_severity", "critical"),
                       steps_json))
        
        conn.commit()
        conn.close()

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)

        # Left panel - navigation and controls
        self.left_panel = QWidget()
        self.left_panel.setFixedWidth(300)
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

        self.btn_engage = QPushButton("Engagement Manager")
        self.btn_findings = QPushButton("Findings Editor")
        self.btn_cvss = QPushButton("CVSS Calculator")
        self.btn_narrative = QPushButton("Attack Narrative")
        self.btn_executive = QPushButton("Executive Summary")
        self.btn_evidence = QPushButton("Evidence Manager")
        self.btn_remediation = QPushButton("Remediation Editor")
        self.btn_roadmap = QPushButton("Roadmap Builder")
        self.btn_report = QPushButton("Compose Report")
        self.btn_export = QPushButton("Export Report")
        self.btn_export.setEnabled(False)

        for btn in [self.btn_engage, self.btn_findings, self.btn_cvss, 
                     self.btn_narrative, self.btn_executive, self.btn_evidence,
                     self.btn_remediation, self.btn_roadmap, self.btn_report,
                     self.btn_export]:
            btn.setStyleSheet(btn_style)
            left_layout.addWidget(btn)

        left_layout.addStretch()

        # Config group - minimal for main window
        config_group = QGroupBox("Engagement Settings")
        config_layout = QVBoxLayout(config_group)
        self.engagement_name = QLineEdit("New Engagement")
        config_layout.addWidget(QLabel("Engagement Name"))
        config_layout.addWidget(self.engagement_name)
        left_layout.addWidget(config_group)

        layout.addWidget(self.left_panel)

        # Right panel - stack of views
        self.stack = QStackedWidget()
        layout.addWidget(self.stack, stretch=1)

        # Engagement manager view
        self.engage_view = QWidget()
        ev_layout = QVBoxLayout(self.engage_view)
        ev_layout.addWidget(QLabel("Engagement Manager - Create/manage engagements"))
        self.engage_table = QTableWidget()
        self.engage_table.setColumnCount(5)
        self.engage_table.setHorizontalHeaderLabels(["Engagement ID", "Client", "Type", "Findings", "Status"])
        ev_layout.addWidget(self.engage_table)
        self.stack.addWidget(self.engage_view)

        # Findings editor view
        self.findings_view = QWidget()
        fv_layout = QVBoxLayout(self.findings_view)
        fv_layout.addWidget(QLabel("Findings Editor - Create/edit findings with CVSS scoring"))
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(8)
        self.findings_table.setHorizontalHeaderLabels(["Finding ID", "Title", "CVSS Version", "Score", "Severity", "Status", "Actions"])
        fv_layout.addWidget(self.findings_table)
        btn_add_finding = QPushButton("Add Finding")
        btn_add_finding.clicked.connect(self.add_finding)
        fv_layout.addWidget(btn_add_finding)
        self.stack.addWidget(self.findings_view)

        # CVSS calculator view
        self.cvss_view = QWidget()
        cv_layout = QVBoxLayout(self.cvss_view)
        cv_layout.addWidget(QLabel("CVSS Calculator - Select metrics; compute base score"))
        self.cvss_metrics = QComboBox()
        self.cvss_metrics.addItems(["CVSS 3.1", "CVSS 4.0"])
        cv_layout.addWidget(self.cvss_metrics)
        self.cvss_score = QLabel("Score: --")
        cv_layout.addWidget(self.cvss_score)
        btn_calculate = QPushButton("Calculate CVSS")
        btn_calculate.clicked.connect(self.calculate_cvss)
        cv_layout.addWidget(btn_calculate)
        self.cvss_vector = QLabel("Vector: CVSS:3.1/AV:N/AC:L/PR:None/UI:N/S:U/C:H/I:H/A:H")
        cv_layout.addWidget(self.cvss_vector)
        self.stack.addWidget(self.cvss_view)

        # Attack narrative view
        self.narrative_view = QWidget()
        nv_layout = QVBoxLayout(self.narrative_view)
        nv_layout.addWidget(QLabel("Attack Narrative - Assemble chronological chain from findings"))
        self.narrative_editor = QTextEdit()
        self.narrative_editor.setPlaceholderText("Attack narrative will be assembled from linked findings...\nDrag-and-drop step reordering available")
        nv_layout.addWidget(self.narrative_editor)
        self.stack.addWidget(self.narrative_view)

        # Executive summary view
        self.executive_view = QWidget()
        ev_layout = QVBoxLayout(self.executive_view)
        ev_layout.addWidget(QLabel("Executive Summary - Business impact, risk rating, strategic recommendations"))
        self.ex_summary_editor = QTextEdit()
        self.ex_summary_editor.setPlaceholderText("Executive summary will be generated from findings aggregation...\nOptional AI-assisted draft with human review")
        ev_layout.addWidget(self.ex_summary_editor)
        self.stack.addWidget(self.executive_view)

        # Evidence manager view
        self.evidence_view = QWidget()
        ev_layout2 = QVBoxLayout(self.evidence_view)
        ev_layout2.addWidget(QLabel("Evidence Manager - Attach screenshots, command output, files to findings"))
        self.evidence_table = QTableWidget()
        self.evidence_table.setColumnCount(4)
        self.evidence_table.setHorizontalHeaderLabels(["Evidence ID", "Finding ID", "Type", "Path/Description"])
        ev_layout2.addWidget(self.evidence_table)
        btn_add_evidence = QPushButton("Add Evidence")
        btn_add_evidence.clicked.connect(self.add_evidence)
        ev_layout2.addWidget(btn_add_evidence)
        self.stack.addWidget(self.evidence_view)

        # Remediation editor view
        self.remediation_view = QWidget()
        rv_layout = QVBoxLayout(self.remediation_view)
        rv_layout.addWidget(QLabel("Remediation Editor - Per-finding: short-term mitigation, long-term fix, references, effort"))
        self.remediation_editor = QTextEdit()
        self.remediation_editor.setPlaceholderText("Remediation notes per finding will appear here...")
        rv_layout.addWidget(self.remediation_editor)
        self.stack.addWidget(self.remediation_view)

        # Roadmap builder view
        self.roadmap_view = QWidget()
        rv_layout2 = QVBoxLayout(self.roadmap_view)
        rv_layout2.addWidget(QLabel("Roadmap Builder - Prioritized remediation roadmap: findings grouped by severity, effort, dependency"))
        self.roadmap_table = QTableWidget()
        self.roadmap_table.setColumnCount(5)
        self.roadmap_table.setHorizontalHeaderLabels(["Finding ID", "Severity", "Effort", "Timeline", "Dependency"])
        rv_layout2.addWidget(self.roadmap_table)
        self.stack.addWidget(self.roadmap_view)

        # Report composer view
        self.report_view = QWidget()
        rpt_layout = QVBoxLayout(self.report_view)
        rpt_layout.addWidget(QLabel("Report Composer - Select sections, order, include/exclude findings, choose template"))
        self.report_format = QComboBox()
        self.report_format.addItems(["DOCX", "PDF", "HTML", "Markdown", "JSON"])
        rpt_layout.addWidget(QLabel("Format"))
        rpt_layout.addWidget(self.report_format)
        self.report_template = QComboBox()
        self.report_template.addItems(["Executive Brief", "Full Technical", "Regulatory"])
        rpt_layout.addWidget(QLabel("Template"))
        btn_compose = QPushButton("Compose Report")
        btn_compose.clicked.connect(self.compose_report)
        rpt_layout.addWidget(btn_compose)
        self.report_preview = QLabel("Rendered report preview will appear here")
        rpt_layout.addWidget(self.report_preview)
        self.stack.addWidget(self.report_view)

        # Connect buttons
        self.btn_engage.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        self.btn_findings.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        self.btn_cvss.clicked.connect(lambda: self.stack.setCurrentIndex(2))
        self.btn_narrative.clicked.connect(lambda: self.stack.setCurrentIndex(3))
        self.btn_executive.clicked.connect(lambda: self.stack.setCurrentIndex(4))
        self.btn_evidence.clicked.connect(lambda: self.stack.setCurrentIndex(5))
        self.btn_remediation.clicked.connect(lambda: self.stack.setCurrentIndex(6))
        self.btn_roadmap.clicked.connect(lambda: self.stack.setCurrentIndex(7))
        self.btn_report.clicked.connect(lambda: self.stack.setCurrentIndex(8))
        self.btn_export.clicked.connect(lambda: self.stack.setCurrentIndex(9))

    def refresh_engagements(self):
        conn = sqlite3.connect(str(DATA_DIR / "engagement_data.db"))
        c = conn.cursor()
        c.execute("SELECT engagement_id, client_name, engagement_type FROM engagements ORDER BY created_at DESC")
        rows = c.fetchall()
        self.engage_table.setRowCount(len(rows))
        for row_idx, row_data in enumerate(rows):
            for col_idx, val in enumerate(row_data):
                self.engage_table.setItem(row_idx, col_idx, QTableWidgetItem(str(val)))
        conn.close()

    def add_finding(self):
        QMessageBox.information(self, "Add Finding", "Finding editor interface would open here.")
        # Add a new finding row
        row = self.findings_table.rowCount()
        self.findings_table.setRowCount(row + 1)
        # Default values
        self.findings_table.setItem(row, 0, QTableWidgetItem("F-001"))
        self.findings_table.setItem(row, 1, QTableWidgetItem("Finding Title"))
        self.findings_table.setItem(row, 2, QTableWidgetItem("3.1"))
        self.findings_table.setItem(row, 3, QTableWidgetItem("0.0"))
        self.findings_table.setItem(row, 4, QTableWidgetItem("medium"))
        self.findings_table.setItem(row, 5, QTableWidgetItem("draft"))

    def calculate_cvss(self):
        QMessageBox.information(self, "CVSS Calculator", "CVSS computation interface would open here.\nMetrics selected → base score computed → vector string updated.")

    def add_evidence(self):
        QMessageBox.information(self, "Add Evidence", "Evidence attachment interface would open here.")

    def compose_report(self):
        selected_format = self.report_format.currentText()
        selected_template = self.report_template.currentText()
        QMessageBox.information(self, "Report Composer", 
                              f"Report being composed as {selected_format} using {selected_template} template...")
        # Save state
        self.save_state()
        self.btn_export.setEnabled(True)

    def export_report(self):
        selected_row = self.engage_table.currentRow()
        if selected_row < 0:
            QMessageBox.warning(self, "Warning", "Please select an engagement first.")
            return
        engagement_id = self.engage_table.item(selected_row, 0).text()
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Report", "", 
                                                   "DOCX (*.docx);;PDF (*.pdf);;HTML (*.html);;Markdown (*.md);;JSON (*.json)")
        if file_path:
            QMessageBox.information(self, "Export Successful", f"Report exported to {file_path}\nEngagement: {engagement_id}")

    def save_state(self):
        state = {
            "app_name": "RTERG",
            "timestamp": datetime.now().isoformat(),
            "last_engagement": self.engage_table.item(0, 0).text() if self.engage_table.rowCount() > 0 else "none",
            "current_view": self.stack.currentIndex() if hasattr(self, 'stack') else 0,
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
    window = RTERGApp()
    window.show()
    sys.exit(app.exec_())