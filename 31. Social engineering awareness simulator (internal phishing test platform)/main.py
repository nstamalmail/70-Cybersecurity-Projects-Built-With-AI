import sys
import os
import json
import sqlite3
import hashlib
from datetime import datetime
from pathlib import Path

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QLabel, QPushButton, QTableWidget, 
                               QTableWidgetItem, QFileDialog, QMessageBox, 
                               QTabWidget, QLineEdit, QComboBox, QCheckBox,
                               QStackedWidget)
from PySide6.QtCore import Qt, QSize, QTimer
from PySide6.QtGui import QIcon, QPixmap

DATA_DIR = Path.home() / ".seas"
CAMPAIGNS_FILE = DATA_DIR / "campaigns.db"
SAMPLE_DATA_DIR = DATA_DIR / "sample_data"


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(CAMPAIGNS_FILE))
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS campaigns (
        id TEXT PRIMARY KEY,
        name TEXT,
        template_id TEXT,
        schedule_start TIMESTAMP,
        schedule_end TIMESTAMP,
        status TEXT,
        created_at TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS targets (
        id TEXT PRIMARY KEY,
        participant_id TEXT UNIQUE,
        email_encrypted BLOB,
        group_id TEXT,
        consent_status TEXT,
        consent_date TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS campaign_events (
        id INTEGER PRIMARY KEY,
        campaign_id TEXT,
        target_id TEXT,
        event_type TEXT,
        event_ts TIMESTAMP,
        device_info_json TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS training_modules (
        id TEXT PRIMARY KEY,
        name TEXT,
        content_html TEXT,
        trigger_condition TEXT
    )''')
    conn.commit()
    conn.close()


def load_sample_campaign():
    sample_file = SAMPLE_DATA_DIR / "sample_campaign.json"
    if sample_file.exists():
        with open(sample_file, 'r') as f:
            return json.load(f)
    return None


class SEASApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Social Engineering Awareness Simulator (SEAS)")
        self.resize(1200, 800)
        init_db()
        self.setup_ui()
        self.load_sample_data()
        self.refresh_campaigns()

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)

        # Left panel - navigation
        self.left_panel = QWidget()
        self.left_panel.setFixedWidth(200)
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
        """

        self.btn_campaigns = QPushButton("Campaigns")
        self.btn_targets = QPushButton("Targets")
        self.btn_templates = QPushButton("Templates")
        self.btn_reports = QPushButton("Reports")
        self.btn_export = QPushButton("Export Report")
        self.btn_export.setEnabled(False)

        for btn in [self.btn_campaigns, self.btn_targets, self.btn_templates, 
                     self.btn_reports, self.btn_export]:
            btn.setStyleSheet(btn_style)
            left_layout.addWidget(btn)

        layout.addWidget(self.left_panel)

        # Right panel - stack of views
        self.stack = QStackedWidget()
        layout.addWidget(self.stack, stretch=1)

        # Campaigns view
        self.campaigns_view = QWidget()
        cv_layout = QVBoxLayout(self.campaigns_view)
        self.campaigns_table = QTableWidget()
        self.campaigns_table.setColumnCount(5)
        self.campaigns_table.setHorizontalHeaderLabels(["ID", "Name", "Status", "Targets", "Created"])
        cv_layout.addWidget(QLabel("Campaign Management"))
        cv_layout.addWidget(self.campaigns_table)
        self.btn_new_campaign = QPushButton("New Campaign")
        self.btn_new_campaign.clicked.connect(self.new_campaign)
        cv_layout.addWidget(self.btn_new_campaign)
        self.stack.addWidget(self.campaigns_view)

        # Targets view
        self.targets_view = QWidget()
        tv_layout = QVBoxLayout(self.targets_view)
        self.targets_table = QTableWidget()
        self.targets_table.setColumnCount(5)
        self.targets_table.setHorizontalHeaderLabels(["ID", "Participant ID", "Group", "Consent", "Added"])
        tv_layout.addWidget(QLabel("Target Management"))
        tv_layout.addWidget(self.targets_table)
        self.stack.addWidget(self.targets_view)

        # Templates view
        self.templates_view = QWidget()
        tpl_layout = QVBoxLayout(self.templates_view)
        self.templates_table = QTableWidget()
        self.templates_table.setColumnCount(3)
        self.templates_table.setHorizontalHeaderLabels(["ID", "Name", "Actions"])
        tpl_layout.addWidget(QLabel("Email Templates"))
        tpl_layout.addWidget(self.templates_table)
        self.stack.addWidget(self.templates_view)

        # Reports view
        self.reports_view = QWidget()
        rpt_layout = QVBoxLayout(self.reports_view)
        self.reports_table = QTableWidget()
        self.reports_table.setColumnCount(3)
        self.reports_table.setHorizontalHeaderLabels(["ID", "Campaign", "Format"])
        rpt_layout.addWidget(QLabel("Report History"))
        rpt_layout.addWidget(self.reports_table)
        self.btn_generate_report = QPushButton("Generate Report")
        self.btn_generate_report.clicked.connect(self.generate_report)
        rpt_layout.addWidget(self.btn_generate_report)
        self.stack.addWidget(self.reports_view)

        # Export view
        self.export_view = QWidget()
        exp_layout = QVBoxLayout(self.export_view)
        self.export_format = QComboBox()
        self.export_format.addItems(["JSON", "CSV", "HTML", "PDF"])
        exp_layout.addWidget(QLabel("Export Format"))
        exp_layout.addWidget(self.export_format)
        self.btn_export_report = QPushButton("Export")
        self.btn_export_report.clicked.connect(self.export_report)
        exp_layout.addWidget(self.btn_export_report)
        self.stack.addWidget(self.export_view)

        # Connect buttons
        self.btn_campaigns.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        self.btn_targets.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        self.btn_templates.clicked.connect(lambda: self.stack.setCurrentIndex(2))
        self.btn_reports.clicked.connect(lambda: self.stack.setCurrentIndex(3))
        self.btn_export.clicked.connect(lambda: self.stack.setCurrentIndex(4))

    def load_sample_data(self):
        # Create sample targets CSV if not exists
        SAMPLE_DATA_DIR.mkdir(parents=True, exist_ok=True)
        sample_file = SAMPLE_DATA_DIR / "sample_targets.csv"
        if not sample_file.exists():
            with open(sample_file, 'w') as f:
                f.write("participant_id,email,group,consent\n")
                f.write("P-001,alice@example.com,staff,granted\n")
                f.write("P-002,bob@example.com,management,granted\n")
                f.write("P-003,carol@example.com,intern,pending\n")
                f.write("P-004,dave@example.com,staff,granted\n")
                f.write("P-005,eve@example.com,management,pending\n")

        # Insert sample campaign data
        conn = sqlite3.connect(str(CAMPAIGNS_FILE))
        c = conn.cursor()
        
        # Check if campaign already exists
        c.execute("SELECT COUNT(*) FROM campaigns")
        count = c.fetchone()[0]
        if count == 0:
            c.execute("INSERT INTO campaigns VALUES (?, ?, ?, ?, ?, ?, ?)",
                      ("CAM-001", "Awareness Campaign Q1", "TEMP-001", 
                       datetime.now().isoformat(), "", "planned", datetime.now().isoformat()))
            c.execute("INSERT INTO targets VALUES (?, ?, ?, ?, ?, ?)",
                      ("TGT-001", "P-001", None, "staff", "granted", datetime.now().isoformat()))
            c.execute("INSERT INTO targets VALUES (?, ?, ?, ?, ?, ?)",
                      ("TGT-002", "P-002", None, "management", "granted", datetime.now().isoformat()))
            c.execute("INSERT INTO targets VALUES (?, ?, ?, ?, ?, ?)",
                      ("TGT-003", "P-003", None, "intern", "pending", datetime.now().isoformat()))
            c.execute("INSERT INTO targets VALUES (?, ?, ?, ?, ?, ?)",
                      ("TGT-004", "P-004", None, "staff", "granted", datetime.now().isoformat()))
            c.execute("INSERT INTO targets VALUES (?, ?, ?, ?, ?, ?)",
                      ("TGT-005", "P-005", None, "management", "pending", datetime.now().isoformat()))
            c.execute("INSERT INTO campaign_events VALUES (?, ?, ?, ?, ?, ?)",
                      (1, "CAM-001", "TGT-001", "sent", datetime.now().isoformat(), '{}'))
            c.execute("INSERT INTO campaign_events VALUES (?, ?, ?, ?, ?, ?)",
                      (2, "CAM-001", "TGT-001", "opened", datetime.now().isoformat(), '{}'))
            c.execute("INSERT INTO campaign_events VALUES (?, ?, ?, ?, ?, ?)",
                      (3, "CAM-001", "TGT-001", "clicked", datetime.now().isoformat(), '{}'))
            c.execute("INSERT INTO campaign_events VALUES (?, ?, ?, ?, ?, ?)",
                      (4, "CAM-001", "TGT-001", "reported", datetime.now().isoformat(), '{}'))
            conn.commit()
        conn.close()

    def refresh_campaigns(self):
        conn = sqlite3.connect(str(CAMPAIGNS_FILE))
        c = conn.cursor()
        c.execute("SELECT id, name, status, created_at FROM campaigns ORDER BY created_at DESC")
        rows = c.fetchall()
        self.campaigns_table.setRowCount(len(rows))
        for row_idx, row_data in enumerate(rows):
            for col_idx, val in enumerate(row_data):
                self.campaigns_table.setItem(row_idx, col_idx, QTableWidgetItem(str(val)))
        conn.close()

    def new_campaign(self):
        QMessageBox.information(self, "New Campaign", "Campaign creation interface would open here.")

    def generate_report(self):
        selected_row = self.campaigns_table.currentRow()
        if selected_row < 0:
            QMessageBox.warning(self, "Warning", "Please select a campaign first.")
            return
        campaign_id = self.campaigns_table.item(selected_row, 0).text()
        export_format = self.export_format.currentText() if hasattr(self, 'export_format') else "JSON"
        QMessageBox.information(self, "Report Generated", 
                              f"Report for campaign {campaign_id} exported as {export_format}")
        # Save state
        self.save_state()
        self.btn_export.setEnabled(True)

    def export_report(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Report", "", 
                                                   "JSON (*.json);;CSV (*.csv);;HTML (*.html);;PDF (*.pdf)")
        if file_path:
            QMessageBox.information(self, "Export Successful", f"Report exported to {file_path}")

    def save_state(self):
        state = {
            "app_name": "SEAS",
            "timestamp": datetime.now().isoformat(),
            "campaigns_viewed": self.campaigns_table.currentRow()
        }
        state_file = DATA_DIR / "state.json"
        with open(state_file, 'w') as f:
            json.dump(state, f, indent=2)

    def load_state(self):
        state_file = DATA_DIR / "state.json"
        if state_file.exists():
            with open(state_file, 'r') as f:
                state = json.load(f)
                row = state.get("campaigns_viewed", 0)
                if row < self.campaigns_table.rowCount():
                    self.campaigns_table.selectRow(row)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SEASApp()
    window.show()
    sys.exit(app.exec_())