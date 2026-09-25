"""
SOC Alert Triage Dashboard (Severity Scoring + Dedup)
Complete PySide6 GUI application for SOC alert management.
"""

import sys
import os
import json
import csv
import hashlib
import re
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter

try:
    import yaml
except ImportError:
    try:
        import PyYAML as yaml
    except ImportError:
        yaml = None

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QLabel, QTextEdit, QLineEdit,
    QComboBox, QSplitter, QGroupBox, QFormLayout, QMessageBox,
    QFileDialog, QProgressBar, QStatusBar, QFrame, QSpinBox,
    QAbstractItemView, QStyledItemDelegate, QStyle, QDialog,
    QDialogButtonBox, QPlainTextEdit
)
from PySide6.QtCore import Qt, QSize, QTimer
from PySide6.QtGui import QColor, QFont, QIcon, QPalette, QAction
try:
    from PySide6.QtPrintSupport import QPrinter, QPrintDialog
    HAS_PRINTER = True
except ImportError:
    HAS_PRINTER = False


# ─── Constants ────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "Critical": QColor(220, 38, 38),
    "High":     QColor(234, 140, 26),
    "Medium":   QColor(234, 195, 26),
    "Low":      QColor(59, 130, 246),
    "Info":     QColor(156, 163, 175),
    "Suppressed": QColor(120, 120, 120),
}

STATUS_COLORS = {
    "New":        QColor(220, 38, 38),
    "Triage":     QColor(234, 140, 26),
    "Assigned":   QColor(59, 130, 246),
    "Escalated":  QColor(220, 38, 38),
    "Resolved":   QColor(34, 197, 94),
    "Suppressed": QColor(120, 120, 120),
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Suppressed": 5}

SOURCE_RELIABILITY = {
    "Microsoft Defender": 1.3, "CrowdStrike": 1.3, "SentinelOne": 1.3,
    "Splunk": 1.2, "Palo Alto FW": 1.2, "Qualys": 1.1,
    "Nessus": 1.1, "OSSEC": 1.0,
}

SOURCE_CATEGORY = {
    "Microsoft Defender": "EDR", "CrowdStrike": "EDR", "SentinelOne": "EDR",
    "Splunk": "SIEM", "Palo Alto FW": "Firewall",
    "Qualys": "VulnScanner", "Nessus": "VulnScanner", "OSSEC": "HIDS",
}

def _get_base_dir():
    if getattr(sys, 'frozen', False):
        return Path(sys._MEIPASS)
    return Path(__file__).parent

BASE_DIR = _get_base_dir()
SAMPLE_DIR = BASE_DIR / "sample_data"


# ─── Utility Functions ────────────────────────────────────────────────────────

def severity_score(sev):
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}.get(sev, 0)


def score_to_severity(score):
    if score >= 3.5: return "Critical"
    if score >= 2.5: return "High"
    if score >= 1.5: return "Medium"
    if score >= 0.5: return "Low"
    return "Info"


def generate_group_key(alert):
    title_norm = re.sub(r'[\d\-:T]+Z?', '', alert.get("title", "").lower().strip())
    entities_sorted = '|'.join(sorted(alert.get("entities", [])))
    return hashlib.sha256(f"{title_norm}:{entities_sorted}".encode()).hexdigest()[:12]


def recalculate_severity(alert, cti_data):
    base = severity_score(alert.get("severity", "Medium"))
    reliability = SOURCE_RELIABILITY.get(alert.get("source", ""), 0.8)

    cti_mult = 1.0
    ioc_lookup = cti_data.get("ioc_lookup", {})
    campaigns = cti_data.get("campaigns", [])
    for ioc in alert.get("ioc_matches", []):
        ioc_info = ioc_lookup.get(ioc, {})
        campaign = ioc_info.get("campaign")
        confidence = ioc_info.get("confidence", 0)
        if campaign:
            for c in campaigns:
                if c["name"] == campaign:
                    cti_mult = max(cti_mult, c.get("severity_multiplier", 1.0))
                    break
        elif confidence >= 90:
            cti_mult = max(cti_mult, 1.2)
        elif confidence >= 70:
            cti_mult = max(cti_mult, 1.1)

    title_lower = alert.get("title", "").lower()
    if "ransomware" in title_lower:
        cti_mult = max(cti_mult, 1.5)

    calibrated = base * reliability * cti_mult
    calibrated_sev = score_to_severity(calibrated)

    orig_score = severity_score(alert.get("severity", "Medium"))
    cal_score = severity_score(calibrated_sev)
    if cal_score > orig_score:
        change = "Promoted"
    elif cal_score < orig_score:
        change = "Demoted"
    else:
        change = "Unchanged"

    return calibrated_sev, change


def normalize_alert(raw, cti_data, group_map, index):
    alert = dict(raw)
    alert.setdefault("description", alert.get("title", ""))
    alert.setdefault("entities", [])
    alert.setdefault("ioc_matches", [])
    alert.setdefault("status", "New")
    alert.setdefault("triage_notes", "")
    alert.setdefault("assigned_to", "")
    alert.setdefault("created_at", datetime.utcnow().isoformat() + "Z")
    alert.setdefault("updated_at", datetime.utcnow().isoformat() + "Z")

    if "group_id" not in alert or not alert["group_id"]:
        gk = generate_group_key(alert)
        if gk in group_map:
            alert["group_id"] = group_map[gk]
        else:
            alert["group_id"] = f"GRP-{1000 + index}"
            group_map[gk] = alert["group_id"]

    cal_sev, change = recalculate_severity(alert, cti_data)
    alert["calibrated_severity"] = cal_sev
    alert["severity_change"] = change
    return alert


# ─── Color Delegate ────────────────────────────────────────────────────────────

class SeverityDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        text = index.data(Qt.DisplayRole) or ""
        bg = SEVERITY_COLORS.get(text, QColor(128, 128, 128))
        painter.save()
        painter.fillRect(option.rect, bg)
        painter.setPen(QColor(255, 255, 255))
        painter.setFont(QFont("Segoe UI", 9, QFont.Bold))
        painter.drawText(option.rect, Qt.AlignCenter, text)
        painter.restore()


class StatusDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        text = index.data(Qt.DisplayRole) or ""
        bg = STATUS_COLORS.get(text, QColor(128, 128, 128))
        painter.save()
        painter.fillRect(option.rect, bg)
        painter.setPen(QColor(255, 255, 255))
        painter.setFont(QFont("Segoe UI", 9))
        painter.drawText(option.rect, Qt.AlignCenter, text)
        painter.restore()


# ─── Import Dialog ─────────────────────────────────────────────────────────────

class ImportDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Import Alerts")
        self.setMinimumWidth(500)
        layout = QVBoxLayout(self)

        info = QLabel("Select a JSON or CSV file containing alerts to import.\n\n"
                       "JSON format: array of alert objects\n"
                       "CSV columns: id,timestamp,source,severity,title,description,entities,status")
        info.setWordWrap(True)
        layout.addWidget(info)

        btn_row = QHBoxLayout()
        self.btn_json = QPushButton("Select JSON File")
        self.btn_csv = QPushButton("Select CSV File")
        self.btn_json.clicked.connect(lambda: self.select_file("json"))
        self.btn_csv.clicked.connect(lambda: self.select_file("csv"))
        btn_row.addWidget(self.btn_json)
        btn_row.addWidget(self.btn_csv)
        layout.addLayout(btn_row)

        self.file_label = QLabel("No file selected")
        layout.addWidget(self.file_label)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.file_path = None

    def select_file(self, ftype):
        if ftype == "json":
            path, _ = QFileDialog.getOpenFileName(self, "Select JSON File", "", "JSON Files (*.json)")
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Select CSV File", "", "CSV Files (*.csv)")
        if path:
            self.file_path = path
            self.file_label.setText(f"Selected: {os.path.basename(path)}")


# ─── Suppression Rule Editor ──────────────────────────────────────────────────

class SuppressionRuleEditor(QDialog):
    def __init__(self, parent=None, rule=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Suppression Rule" if rule else "New Suppression Rule")
        self.setMinimumWidth(450)
        layout = QFormLayout(self)

        self.name_edit = QLineEdit()
        self.desc_edit = QLineEdit()
        self.source_combo = QComboBox()
        self.source_combo.addItems(["Any"] + list(SOURCE_CATEGORY.keys()))
        self.title_contains = QLineEdit()
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["Any", "Critical", "High", "Medium", "Low", "Info"])
        self.action_combo = QComboBox()
        self.action_combo.addItems(["suppress", "escalate"])
        self.override_combo = QComboBox()
        self.override_combo.addItems(["Critical", "High", "Medium", "Low", "Info", "Suppressed"])
        self.expiry_spin = QSpinBox()
        self.expiry_spin.setRange(0, 8760)
        self.expiry_spin.setValue(24)
        self.expiry_spin.setSuffix(" hours")
        self.enabled_check = QComboBox()
        self.enabled_check.addItems(["Yes", "No"])

        layout.addRow("Name:", self.name_edit)
        layout.addRow("Description:", self.desc_edit)
        layout.addRow("Source:", self.source_combo)
        layout.addRow("Title Contains:", self.title_contains)
        layout.addRow("Severity:", self.severity_combo)
        layout.addRow("Action:", self.action_combo)
        layout.addRow("Override Severity:", self.override_combo)
        layout.addRow("Expiry:", self.expiry_spin)
        layout.addRow("Enabled:", self.enabled_check)

        if rule:
            self.name_edit.setText(rule.get("name", ""))
            self.desc_edit.setText(rule.get("description", ""))
            idx = self.source_combo.findText(rule.get("conditions", {}).get("source", "Any"))
            if idx >= 0: self.source_combo.setCurrentIndex(idx)
            self.title_contains.setText(rule.get("conditions", {}).get("title_contains", ""))
            idx = self.severity_combo.findText(rule.get("conditions", {}).get("severity", "Any"))
            if idx >= 0: self.severity_combo.setCurrentIndex(idx)
            self.action_combo.setCurrentText(rule.get("action", "suppress"))
            self.override_combo.setCurrentText(rule.get("severity_override", "Low"))
            self.expiry_spin.setValue(rule.get("expiry_hours", 24))
            self.enabled_check.setCurrentText("Yes" if rule.get("enabled", True) else "No")

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def get_rule(self):
        source = self.source_combo.currentText()
        rule = {
            "name": self.name_edit.text(),
            "description": self.desc_edit.text(),
            "enabled": self.enabled_check.currentText() == "Yes",
            "conditions": {},
            "action": self.action_combo.currentText(),
            "severity_override": self.override_combo.currentText(),
            "expiry_hours": self.expiry_spin.value(),
            "created_by": "analyst"
        }
        if source != "Any":
            rule["conditions"]["source"] = source
        if self.title_contains.text():
            rule["conditions"]["title_contains"] = self.title_contains.text()
        sev = self.severity_combo.currentText()
        if sev != "Any":
            rule["conditions"]["severity"] = sev
        return rule


# ─── Report Dialog ─────────────────────────────────────────────────────────────

class ReportDialog(QDialog):
    def __init__(self, parent=None, content="", title="Report"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(700, 500)
        layout = QVBoxLayout(self)

        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setPlainText(content)
        font = QFont("Consolas", 10)
        self.text.setFont(font)
        layout.addWidget(self.text)

        btn_row = QHBoxLayout()
        btn_save = QPushButton("Save to File")
        btn_print = QPushButton("Print")
        btn_close = QPushButton("Close")
        btn_save.clicked.connect(self.save_file)
        btn_print.clicked.connect(self.print_report)
        btn_close.clicked.connect(self.close)
        btn_row.addWidget(btn_save)
        btn_row.addWidget(btn_print)
        btn_row.addWidget(btn_close)
        layout.addLayout(btn_row)

        self.content = content

    def save_file(self):
        path, filt = QFileDialog.getSaveFileName(self, "Save Report", "", "All Files (*)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.content)
            QMessageBox.information(self, "Saved", f"Report saved to {path}")

    def print_report(self):
        if not HAS_PRINTER:
            QMessageBox.warning(self, "Not Available", "Print support is not available.")
            return
        printer = QPrinter(QPrinter.HighResolution)
        dialog = QPrintDialog(printer, self)
        if dialog.exec():
            from PySide6.QtGui import QTextDocument
            doc = QTextDocument()
            doc.setPlainText(self.content)
            doc.print_(printer)


# ─── Main Window ───────────────────────────────────────────────────────────────

class SOCAlertDashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SOC Alert Triage Dashboard — Severity Scoring + Dedup")
        self.setMinimumSize(1400, 900)

        # State
        self.alerts = []
        self.groups = {}
        self.cti_data = {"campaigns": [], "ioc_lookup": {}}
        self.suppression_rules = []
        self.triage_queue = []
        self.resolved_alerts = set()
        self.suppressed_alerts = set()
        self.escalated_alerts = set()
        self.triage_start_times = {}
        self.resolution_times = {}
        self.metrics = {
            "mttt": timedelta(),
            "mttr": timedelta(),
            "alert_backlog": 0,
            "total_triaged": 0,
            "promoted": 0,
            "demoted": 0,
        }
        self.group_map = {}
        self.alert_counter = 0

        self._build_ui()
        self._connect_signals()
        self._update_status("Ready. Load demo data or import alerts to begin.")

    # ── UI Construction ────────────────────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(6, 6, 6, 6)

        # Top toolbar
        toolbar = self._build_toolbar()
        main_layout.addLayout(toolbar)

        # Main splitter: left=alerts, right=details
        self.main_splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(self.main_splitter, 1)

        # Left: Alert inbox
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # Filters
        filter_row = QHBoxLayout()
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "Critical", "High", "Medium", "Low", "Info"])
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All Statuses", "New", "Triage", "Assigned", "Escalated", "Resolved", "Suppressed"])
        self.source_filter = QComboBox()
        self.source_filter.addItems(["All Sources", "Microsoft Defender", "CrowdStrike", "SentinelOne",
                                      "Splunk", "Palo Alto FW", "Qualys", "Nessus", "OSSEC"])
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search alerts...")
        self.search_box.setClearButtonEnabled(True)
        filter_row.addWidget(QLabel("Severity:"))
        filter_row.addWidget(self.severity_filter)
        filter_row.addWidget(QLabel("Status:"))
        filter_row.addWidget(self.status_filter)
        filter_row.addWidget(QLabel("Source:"))
        filter_row.addWidget(self.source_filter)
        filter_row.addWidget(self.search_box)
        left_layout.addLayout(filter_row)

        # Alert table
        self.alert_table = QTableWidget()
        self.alert_table.setColumnCount(8)
        self.alert_table.setHorizontalHeaderLabels(
            ["ID", "Timestamp", "Source", "Severity", "Title", "Group", "CTI", "Status"]
        )
        self.alert_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.alert_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.alert_table.setAlternatingRowColors(True)
        self.alert_table.setSortingEnabled(True)
        self.alert_table.setItemDelegateForColumn(3, SeverityDelegate())
        self.alert_table.setItemDelegateForColumn(7, StatusDelegate())
        left_layout.addWidget(self.alert_table)

        self.main_splitter.addWidget(left_widget)

        # Right: Tabbed detail panels
        right_widget = QTabWidget()
        self.main_splitter.addWidget(right_widget)
        self.main_splitter.setSizes([700, 700])

        # Tab 1: Triage Queue
        triage_tab = self._build_triage_tab()
        right_widget.addTab(triage_tab, "Triage Queue")

        # Tab 2: Group Viewer
        group_tab = self._build_group_tab()
        right_widget.addTab(group_tab, "Group Viewer")

        # Tab 3: CTI Context
        cti_tab = self._build_cti_tab()
        right_widget.addTab(cti_tab, "CTI Context")

        # Tab 4: Severity Dashboard
        sev_tab = self._build_severity_tab()
        right_widget.addTab(sev_tab, "Severity Dashboard")

        # Tab 5: Dedup Statistics
        dedup_tab = self._build_dedup_tab()
        right_widget.addTab(dedup_tab, "Dedup Statistics")

        # Tab 6: SOC Metrics
        metrics_tab = self._build_metrics_tab()
        right_widget.addTab(metrics_tab, "SOC Metrics")

        # Tab 7: Suppression Rules
        supp_tab = self._build_suppression_tab()
        right_widget.addTab(supp_tab, "Suppression Rules")

        # Status bar
        self.statusBar().showMessage("Ready")
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        self.statusBar().addPermanentWidget(self.progress_bar)

    def _build_toolbar(self):
        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)

        btn_style = "QPushButton { padding: 6px 14px; font-weight: bold; }"

        self.btn_load_demo = QPushButton("Load Demo Data")
        self.btn_load_demo.setStyleSheet(btn_style)
        self.btn_import = QPushButton("Import Alerts")
        self.btn_import.setStyleSheet(btn_style)
        self.btn_export_json = QPushButton("Export JSON")
        self.btn_export_csv = QPushButton("Export CSV")
        self.btn_export_html = QPushButton("Export HTML")
        self.btn_export_pdf = QPushButton("Export PDF")
        self.btn_apply_supp = QPushButton("Apply Suppression")
        self.btn_generate_report = QPushButton("Build Report")

        for btn in [self.btn_load_demo, self.btn_import,
                     self.btn_export_json, self.btn_export_csv,
                     self.btn_export_html, self.btn_export_pdf,
                     self.btn_apply_supp, self.btn_generate_report]:
            toolbar.addWidget(btn)

        toolbar.addStretch()
        self.alert_count_label = QLabel("Alerts: 0 | Groups: 0")
        self.alert_count_label.setStyleSheet("font-weight: bold; font-size: 13px; padding: 6px;")
        toolbar.addWidget(self.alert_count_label)

        return toolbar

    def _build_triage_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)

        # Alert detail
        detail_group = QGroupBox("Selected Alert Details")
        detail_layout = QFormLayout(detail_group)
        self.detail_id = QLabel("-")
        self.detail_timestamp = QLabel("-")
        self.detail_source = QLabel("-")
        self.detail_severity = QLabel("-")
        self.detail_cal_severity = QLabel("-")
        self.detail_title = QLabel("-")
        self.detail_description = QLabel("-")
        self.detail_description.setWordWrap(True)
        self.detail_group_id = QLabel("-")
        self.detail_entities = QLabel("-")
        self.detail_iocs = QLabel("-")
        self.detail_status = QLabel("-")
        self.detail_assigned = QLabel("-")

        for lbl in [self.detail_cal_severity]:
            lbl.setStyleSheet("font-weight: bold;")

        detail_layout.addRow("ID:", self.detail_id)
        detail_layout.addRow("Timestamp:", self.detail_timestamp)
        detail_layout.addRow("Source:", self.detail_source)
        detail_layout.addRow("Original Severity:", self.detail_severity)
        detail_layout.addRow("Calibrated Severity:", self.detail_cal_severity)
        detail_layout.addRow("Title:", self.detail_title)
        detail_layout.addRow("Description:", self.detail_description)
        detail_layout.addRow("Group:", self.detail_group_id)
        detail_layout.addRow("Entities:", self.detail_entities)
        detail_layout.addRow("IOC Matches:", self.detail_iocs)
        detail_layout.addRow("Status:", self.detail_status)
        detail_layout.addRow("Assigned To:", self.detail_assigned)

        layout.addWidget(detail_group)

        # Notes
        notes_group = QGroupBox("Triage Notes")
        notes_layout = QVBoxLayout(notes_group)
        self.notes_edit = QTextEdit()
        self.notes_edit.setMaximumHeight(80)
        self.notes_edit.setPlaceholderText("Add triage notes here...")
        notes_layout.addWidget(self.notes_edit)
        layout.addWidget(notes_group)

        # Action buttons
        action_row = QHBoxLayout()
        self.btn_assign = QPushButton("Assign to Me")
        self.btn_escalate = QPushButton("Escalate")
        self.btn_resolve = QPushButton("Resolve")
        self.btn_suppress = QPushButton("Suppress")
        self.btn_assign.setStyleSheet("QPushButton { background-color: #3b82f6; color: white; padding: 8px; }")
        self.btn_escalate.setStyleSheet("QPushButton { background-color: #ea8c1a; color: white; padding: 8px; }")
        self.btn_resolve.setStyleSheet("QPushButton { background-color: #22c55e; color: white; padding: 8px; }")
        self.btn_suppress.setStyleSheet("QPushButton { background-color: #6b7280; color: white; padding: 8px; }")
        for btn in [self.btn_assign, self.btn_escalate, self.btn_resolve, self.btn_suppress]:
            action_row.addWidget(btn)
        layout.addLayout(action_row)

        # Triage queue list
        queue_group = QGroupBox("Triage Queue")
        queue_layout = QVBoxLayout(queue_group)
        self.queue_table = QTableWidget()
        self.queue_table.setColumnCount(5)
        self.queue_table.setHorizontalHeaderLabels(["ID", "Severity", "Title", "Source", "Time in Queue"])
        self.queue_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        queue_layout.addWidget(self.queue_table)
        layout.addWidget(queue_group)

        return widget

    def _build_group_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)

        self.group_list = QTableWidget()
        self.group_list.setColumnCount(5)
        self.group_list.setHorizontalHeaderLabels(["Group ID", "Alert Count", "Severity", "Shared Entities", "Status"])
        self.group_list.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.group_list.setSelectionBehavior(QAbstractItemView.SelectRows)
        layout.addWidget(self.group_list)

        group_detail_group = QGroupBox("Group Alert Details")
        gd_layout = QVBoxLayout(group_detail_group)
        self.group_detail_table = QTableWidget()
        self.group_detail_table.setColumnCount(6)
        self.group_detail_table.setHorizontalHeaderLabels(["ID", "Timestamp", "Source", "Severity", "Title", "Status"])
        self.group_detail_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        gd_layout.addWidget(self.group_detail_table)
        layout.addWidget(group_detail_group)

        return widget

    def _build_cti_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)

        # Campaigns
        camp_group = QGroupBox("Threat Campaigns")
        camp_layout = QVBoxLayout(camp_group)
        self.campaign_table = QTableWidget()
        self.campaign_table.setColumnCount(5)
        self.campaign_table.setHorizontalHeaderLabels(["Campaign", "Aliases", "TTPs", "Sectors", "Multiplier"])
        self.campaign_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        camp_layout.addWidget(self.campaign_table)
        layout.addWidget(camp_group)

        # IOC matches for selected alert
        ioc_group = QGroupBox("IOC Matches for Selected Alert")
        ioc_layout = QVBoxLayout(ioc_group)
        self.ioc_table = QTableWidget()
        self.ioc_table.setColumnCount(5)
        self.ioc_table.setHorizontalHeaderLabels(["IOC", "Type", "Verdict", "Campaign", "Confidence"])
        self.ioc_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        ioc_layout.addWidget(self.ioc_table)
        layout.addWidget(ioc_group)

        return widget

    def _build_severity_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)

        # Summary labels
        summary = QGroupBox("Severity Recalibration Summary")
        s_layout = QGridLayout(summary)
        self.promoted_label = QLabel("Promoted: 0")
        self.promoted_label.setStyleSheet("font-size: 14px; color: #22c55e; font-weight: bold;")
        self.demoted_label = QLabel("Demoted: 0")
        self.demoted_label.setStyleSheet("font-size: 14px; color: #ea8c1a; font-weight: bold;")
        self.unchanged_label = QLabel("Unchanged: 0")
        self.unchanged_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.calibrated_summary = QLabel("Calibrated Breakdown: -")
        self.calibrated_summary.setStyleSheet("font-size: 13px;")
        s_layout.addWidget(self.promoted_label, 0, 0)
        s_layout.addWidget(self.demoted_label, 0, 1)
        s_layout.addWidget(self.unchanged_label, 0, 2)
        s_layout.addWidget(self.calibrated_summary, 1, 0, 1, 3)
        layout.addWidget(summary)

        # Original vs Calibrated table
        self.sev_compare_table = QTableWidget()
        self.sev_compare_table.setColumnCount(7)
        self.sev_compare_table.setHorizontalHeaderLabels([
            "ID", "Title", "Original", "Calibrated", "Change", "Source", "CTI Campaign"
        ])
        self.sev_compare_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        layout.addWidget(self.sev_compare_table)

        return widget

    def _build_dedup_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)

        stats_group = QGroupBox("Deduplication Statistics")
        sg_layout = QGridLayout(stats_group)
        self.dedup_total = QLabel("Total Alerts: 0")
        self.dedup_total.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.dedup_groups = QLabel("Unique Groups: 0")
        self.dedup_groups.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.dedup_ratio = QLabel("Dedup Ratio: 0%")
        self.dedup_ratio.setStyleSheet("font-size: 14px; font-weight: bold; color: #3b82f6;")
        sg_layout.addWidget(self.dedup_total, 0, 0)
        sg_layout.addWidget(self.dedup_groups, 0, 1)
        sg_layout.addWidget(self.dedup_ratio, 0, 2)
        layout.addWidget(stats_group)

        pattern_group = QGroupBox("Top Alert Patterns")
        pg_layout = QVBoxLayout(pattern_group)
        self.pattern_table = QTableWidget()
        self.pattern_table.setColumnCount(3)
        self.pattern_table.setHorizontalHeaderLabels(["Pattern", "Count", "Group IDs"])
        self.pattern_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        pg_layout.addWidget(self.pattern_table)
        layout.addWidget(pattern_group)

        group_detail_group = QGroupBox("Group Members")
        gd_layout = QVBoxLayout(group_detail_group)
        self.dedup_group_detail = QTableWidget()
        self.dedup_group_detail.setColumnCount(4)
        self.dedup_group_detail.setHorizontalHeaderLabels(["ID", "Source", "Severity", "Timestamp"])
        gd_layout.addWidget(self.dedup_group_detail)
        layout.addWidget(group_detail_group)

        return widget

    def _build_metrics_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)

        metrics_group = QGroupBox("SOC Performance Metrics")
        mg_layout = QGridLayout(metrics_group)
        self.mttt_label = QLabel("Mean Time to Triage: -")
        self.mttt_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        self.mttr_label = QLabel("Mean Time to Resolve: -")
        self.mttr_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        self.backlog_label = QLabel("Alert Backlog: 0")
        self.backlog_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #ea8c1a;")
        self.total_triaged_label = QLabel("Total Triaged: 0")
        self.total_triaged_label.setStyleSheet("font-size: 14px;")
        self.total_resolved_label = QLabel("Total Resolved: 0")
        self.total_resolved_label.setStyleSheet("font-size: 14px;")
        self.total_suppressed_label = QLabel("Total Suppressed: 0")
        self.total_suppressed_label.setStyleSheet("font-size: 14px;")
        self.total_escalated_label = QLabel("Total Escalated: 0")
        self.total_escalated_label.setStyleSheet("font-size: 14px;")

        mg_layout.addWidget(self.mttt_label, 0, 0, 1, 2)
        mg_layout.addWidget(self.mttr_label, 0, 2, 1, 2)
        mg_layout.addWidget(self.backlog_label, 1, 0, 1, 2)
        mg_layout.addWidget(self.total_triaged_label, 1, 2)
        mg_layout.addWidget(self.total_resolved_label, 1, 3)
        mg_layout.addWidget(self.total_suppressed_label, 2, 0)
        mg_layout.addWidget(self.total_escalated_label, 2, 1)
        layout.addWidget(metrics_group)

        # Source breakdown
        source_group = QGroupBox("Alerts by Source")
        src_layout = QVBoxLayout(source_group)
        self.source_breakdown = QTableWidget()
        self.source_breakdown.setColumnCount(4)
        self.source_breakdown.setHorizontalHeaderLabels(["Source", "Count", "Avg Severity", "Category"])
        src_layout.addWidget(self.source_breakdown)
        layout.addWidget(source_group)

        # Severity breakdown
        sev_group = QGroupBox("Alerts by Severity (Calibrated)")
        sev_layout = QVBoxLayout(sev_group)
        self.sev_breakdown = QTableWidget()
        self.sev_breakdown.setColumnCount(3)
        self.sev_breakdown.setHorizontalHeaderLabels(["Severity", "Count", "Percentage"])
        sev_layout.addWidget(self.sev_breakdown)
        layout.addWidget(sev_group)

        return widget

    def _build_suppression_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)

        btn_row = QHBoxLayout()
        self.btn_add_rule = QPushButton("Add Rule")
        self.btn_edit_rule = QPushButton("Edit Rule")
        self.btn_delete_rule = QPushButton("Delete Rule")
        self.btn_toggle_rule = QPushButton("Toggle Rule")
        btn_row.addWidget(self.btn_add_rule)
        btn_row.addWidget(self.btn_edit_rule)
        btn_row.addWidget(self.btn_delete_rule)
        btn_row.addWidget(self.btn_toggle_rule)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(7)
        self.rules_table.setHorizontalHeaderLabels([
            "ID", "Name", "Source", "Title Match", "Action", "Override", "Enabled"
        ])
        self.rules_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.rules_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        layout.addWidget(self.rules_table)

        return widget

    # ── Signal Connections ──────────────────────────────────────────────────────

    def _connect_signals(self):
        self.btn_load_demo.clicked.connect(self.load_demo_data)
        self.btn_import.clicked.connect(self.import_alerts)
        self.btn_export_json.clicked.connect(lambda: self.export_report("json"))
        self.btn_export_csv.clicked.connect(lambda: self.export_report("csv"))
        self.btn_export_html.clicked.connect(lambda: self.export_report("html"))
        self.btn_export_pdf.clicked.connect(lambda: self.export_report("pdf"))
        self.btn_apply_supp.clicked.connect(self.apply_suppression)
        self.btn_generate_report.clicked.connect(self.generate_report)

        self.severity_filter.currentTextChanged.connect(self._get_filtered_alerts)
        self.status_filter.currentTextChanged.connect(self._get_filtered_alerts)
        self.source_filter.currentTextChanged.connect(self._get_filtered_alerts)
        self.search_box.textChanged.connect(self._get_filtered_alerts)

        self.alert_table.currentCellChanged.connect(self._on_alert_selected)

        self.btn_assign.clicked.connect(self._triage_assign)
        self.btn_escalate.clicked.connect(self._triage_escalate)
        self.btn_resolve.clicked.connect(self._triage_resolve)
        self.btn_suppress.clicked.connect(self._triage_suppress)

        self.group_list.currentCellChanged.connect(self._on_group_selected)
        self.dedup_group_detail.currentCellChanged.connect(self._on_dedup_group_selected)

        self.btn_add_rule.clicked.connect(self._add_rule)
        self.btn_edit_rule.clicked.connect(self._edit_rule)
        self.btn_delete_rule.clicked.connect(self._delete_rule)
        self.btn_toggle_rule.clicked.connect(self._toggle_rule)

    # ── Data Loading ────────────────────────────────────────────────────────────

    def _load_json(self, path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def load_demo_data(self):
        self._update_status("Loading demo data...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(10)

        try:
            alerts_raw = self._load_json(SAMPLE_DIR / "sample_alerts.json")
            self.progress_bar.setValue(30)

            try:
                self.cti_data = self._load_json(SAMPLE_DIR / "sample_cti.json")
            except Exception:
                self.cti_data = {"campaigns": [], "ioc_lookup": {}}
            self.progress_bar.setValue(50)

            # Load suppression rules
            rules_path = SAMPLE_DIR / "sample_suppression_rules.yaml"
            if rules_path.exists():
                if yaml:
                    with open(rules_path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    self.suppression_rules = data.get("rules", []) if data else []
                else:
                    self._update_status("PyYAML not installed. Loading rules as simple format.")
                    self.suppression_rules = []

            self.progress_bar.setValue(70)

            # Normalize alerts
            self.group_map = {}
            self.alerts = []
            for i, raw in enumerate(alerts_raw):
                alert = normalize_alert(raw, self.cti_data, self.group_map, i)
                self.alerts.append(alert)
            self.alert_counter = len(self.alerts)

            self._build_groups()
            self.progress_bar.setValue(90)

            self._refresh_all()
            self.progress_bar.setValue(100)

            self._update_status(f"Loaded {len(self.alerts)} alerts in {len(self.groups)} groups. "
                                f"CTI: {len(self.cti_data.get('campaigns',[]))} campaigns, "
                                f"{len(self.cti_data.get('ioc_lookup',{}))} IOC entries.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load demo data:\n{e}")
        finally:
            QTimer.singleShot(500, lambda: self.progress_bar.setVisible(False))

    def import_alerts(self):
        dlg = ImportDialog(self)
        if dlg.exec() != QDialog.Accepted or not dlg.file_path:
            return

        self._update_status("Importing alerts...")
        try:
            path = dlg.file_path
            if path.endswith(".json"):
                raw_list = self._load_json(path)
            elif path.endswith(".csv"):
                raw_list = []
                with open(path, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        alert = dict(row)
                        if "entities" in alert and isinstance(alert["entities"], str):
                            alert["entities"] = [e.strip() for e in alert["entities"].split(",")]
                        if "ioc_matches" in alert and isinstance(alert["ioc_matches"], str):
                            alert["ioc_matches"] = [e.strip() for e in alert["ioc_matches"].split(",")]
                        raw_list.append(alert)
            else:
                QMessageBox.warning(self, "Unsupported", "Only JSON and CSV files are supported.")
                return

            count = 0
            for raw in raw_list:
                alert = normalize_alert(raw, self.cti_data, self.group_map, self.alert_counter)
                self.alerts.append(alert)
                self.alert_counter += 1
                count += 1

            self._build_groups()
            self._refresh_all()
            self._update_status(f"Imported {count} alerts. Total: {len(self.alerts)}")
        except Exception as e:
            QMessageBox.critical(self, "Import Error", str(e))

    def _build_groups(self):
        self.groups = {}
        for alert in self.alerts:
            gid = alert.get("group_id", "unknown")
            if gid not in self.groups:
                self.groups[gid] = []
            self.groups[gid].append(alert)

    # ── UI Refresh ──────────────────────────────────────────────────────────────

    def _refresh_all(self):
        self._populate_alert_table()
        self._populate_group_list()
        self._populate_campaigns()
        self._update_severity_dashboard()
        self._update_dedup_stats()
        self._update_metrics()
        self._populate_rules_table()
        self._update_queue_table()
        self.alert_count_label.setText(f"Alerts: {len(self.alerts)} | Groups: {len(self.groups)}")

    def _populate_alert_table(self):
        filtered = self._get_filtered_alerts()
        self.alert_table.setRowCount(len(filtered))
        self.alert_table.setSortingEnabled(False)
        for i, alert in enumerate(filtered):
            self.alert_table.setItem(i, 0, self._make_item(alert["id"]))
            self.alert_table.setItem(i, 1, self._make_item(alert.get("timestamp", "")[:19]))
            self.alert_table.setItem(i, 2, self._make_item(alert.get("source", "")))

            sev_item = QTableWidgetItem(alert.get("calibrated_severity", alert.get("severity", "")))
            sev_item.setTextAlignment(Qt.AlignCenter)
            self.alert_table.setItem(i, 3, sev_item)

            self.alert_table.setItem(i, 4, self._make_item(alert.get("title", "")))
            self.alert_table.setItem(i, 5, self._make_item(alert.get("group_id", "")))

            iocs = alert.get("ioc_matches", [])
            cti_text = f"{len(iocs)} IOCs" if iocs else "None"
            self.alert_table.setItem(i, 6, self._make_item(cti_text))

            status_item = QTableWidgetItem(alert.get("status", "New"))
            status_item.setTextAlignment(Qt.AlignCenter)
            self.alert_table.setItem(i, 7, status_item)

        self.alert_table.setSortingEnabled(True)

    def _get_filtered_alerts(self):
        result = self.alerts[:]
        sev = self.severity_filter.currentText()
        if sev != "All Severities":
            result = [a for a in result if a.get("calibrated_severity") == sev or a.get("severity") == sev]
        stat = self.status_filter.currentText()
        if stat != "All Statuses":
            result = [a for a in result if a.get("status") == stat]
        src = self.source_filter.currentText()
        if src != "All Sources":
            result = [a for a in result if a.get("source") == src]
        search = self.search_box.text().lower()
        if search:
            result = [a for a in result if search in a.get("title", "").lower()
                      or search in a.get("id", "").lower()
                      or search in a.get("description", "").lower()]
        return result

    def _populate_group_list(self):
        self.group_list.setRowCount(len(self.groups))
        for i, (gid, alerts) in enumerate(sorted(self.groups.items())):
            self.group_list.setItem(i, 0, self._make_item(gid))
            self.group_list.setItem(i, 1, self._make_item(str(len(alerts))))
            max_sev = max(alerts, key=lambda a: severity_score(a.get("severity", "Low")))
            self.group_list.setItem(i, 2, self._make_item(max_sev.get("calibrated_severity", max_sev.get("severity", ""))))
            all_entities = set()
            for a in alerts:
                all_entities.update(a.get("entities", []))
            self.group_list.setItem(i, 3, self._make_item(", ".join(sorted(all_entities)[:5]) + ("..." if len(all_entities) > 5 else "")))
            statuses = set(a.get("status", "New") for a in alerts)
            self.group_list.setItem(i, 4, self._make_item(", ".join(statuses)))

    def _populate_campaigns(self):
        campaigns = self.cti_data.get("campaigns", [])
        self.campaign_table.setRowCount(len(campaigns))
        for i, c in enumerate(campaigns):
            self.campaign_table.setItem(i, 0, self._make_item(c.get("name", "")))
            self.campaign_table.setItem(i, 1, self._make_item(", ".join(c.get("aliases", []))))
            self.campaign_table.setItem(i, 2, self._make_item(", ".join(c.get("ttps", []))))
            self.campaign_table.setItem(i, 3, self._make_item(", ".join(c.get("targeted_sectors", []))))
            self.campaign_table.setItem(i, 4, self._make_item(str(c.get("severity_multiplier", 1.0))))

    def _update_severity_dashboard(self):
        promoted = sum(1 for a in self.alerts if a.get("severity_change") == "Promoted")
        demoted = sum(1 for a in self.alerts if a.get("severity_change") == "Demoted")
        unchanged = len(self.alerts) - promoted - demoted

        self.metrics["promoted"] = promoted
        self.metrics["demoted"] = demoted
        self.promoted_label.setText(f"Promoted: {promoted}")
        self.demoted_label.setText(f"Demoted: {demoted}")
        self.unchanged_label.setText(f"Unchanged: {unchanged}")

        cal_counts = Counter(a.get("calibrated_severity", "Medium") for a in self.alerts)
        summary_parts = [f"{sev}: {cal_counts.get(sev, 0)}" for sev in ["Critical", "High", "Medium", "Low", "Info"]]
        self.calibrated_summary.setText("Calibrated Breakdown: " + " | ".join(summary_parts))

        self.sev_compare_table.setRowCount(len(self.alerts))
        for i, alert in enumerate(self.alerts):
            self.sev_compare_table.setItem(i, 0, self._make_item(alert.get("id", "")))
            self.sev_compare_table.setItem(i, 1, self._make_item(alert.get("title", "")))

            orig_item = QTableWidgetItem(alert.get("severity", ""))
            orig_item.setTextAlignment(Qt.AlignCenter)
            self.sev_compare_table.setItem(i, 2, orig_item)

            cal_item = QTableWidgetItem(alert.get("calibrated_severity", ""))
            cal_item.setTextAlignment(Qt.AlignCenter)
            self.sev_compare_table.setItem(i, 3, cal_item)

            change = alert.get("severity_change", "Unchanged")
            change_item = QTableWidgetItem(change)
            change_item.setTextAlignment(Qt.AlignCenter)
            if change == "Promoted":
                change_item.setForeground(QColor(34, 197, 94))
            elif change == "Demoted":
                change_item.setForeground(QColor(234, 140, 26))
            self.sev_compare_table.setItem(i, 4, change_item)

            self.sev_compare_table.setItem(i, 5, self._make_item(alert.get("source", "")))

            campaign = self._get_ioc_campaign(alert)
            self.sev_compare_table.setItem(i, 6, self._make_item(campaign))

    def _get_ioc_campaign(self, alert):
        ioc_lookup = self.cti_data.get("ioc_lookup", {})
        for ioc in alert.get("ioc_matches", []):
            info = ioc_lookup.get(ioc, {})
            if info.get("campaign"):
                return info["campaign"]
        return "-"

    def _update_dedup_stats(self):
        total = len(self.alerts)
        groups = len(self.groups)
        ratio = ((total - groups) / total * 100) if total > 0 else 0

        self.dedup_total.setText(f"Total Alerts: {total}")
        self.dedup_groups.setText(f"Unique Groups: {groups}")
        self.dedup_ratio.setText(f"Dedup Ratio: {ratio:.1f}%")

        # Top patterns
        title_counter = Counter()
        title_groups = {}
        for a in self.alerts:
            norm_title = re.sub(r'[\d\-:T]+Z?', '', a.get("title", "").lower().strip())
            title_counter[norm_title] += 1
            if norm_title not in title_groups:
                title_groups[norm_title] = set()
            title_groups[norm_title].add(a.get("group_id", ""))

        patterns = title_counter.most_common(15)
        self.pattern_table.setRowCount(len(patterns))
        for i, (pattern, count) in enumerate(patterns):
            self.pattern_table.setItem(i, 0, self._make_item(pattern))
            self.pattern_table.setItem(i, 1, self._make_item(str(count)))
            self.pattern_table.setItem(i, 2, self._make_item(
                ", ".join(sorted(title_groups.get(pattern, set())))))

    def _update_metrics(self):
        total = len(self.alerts)
        backlog = sum(1 for a in self.alerts if a.get("status") in ("New", "Triage"))
        self.metrics["alert_backlog"] = backlog

        # MTTT
        triaged_times = []
        for aid, start in self.triage_start_times.items():
            alert = next((a for a in self.alerts if a["id"] == aid), None)
            if alert and alert.get("status") not in ("New",):
                triaged_times.append(datetime.utcnow() - start)
        if triaged_times:
            self.metrics["mttt"] = sum(triaged_times, timedelta()) / len(triaged_times)

        # MTTR
        if self.resolution_times:
            self.metrics["mttr"] = sum(self.resolution_times.values(), timedelta()) / len(self.resolution_times)

        mttt_str = str(self.metrics["mttt"]).split(".")[0] if self.metrics["mttt"] else "-"
        mttr_str = str(self.metrics["mttr"]).split(".")[0] if self.metrics["mttr"] else "-"

        self.mttt_label.setText(f"Mean Time to Triage: {mttt_str}")
        self.mttr_label.setText(f"Mean Time to Resolve: {mttr_str}")
        self.backlog_label.setText(f"Alert Backlog: {backlog}")
        self.total_triaged_label.setText(f"Total Triaged: {sum(1 for a in self.alerts if a.get('status') != 'New')}")
        self.total_resolved_label.setText(f"Total Resolved: {len(self.resolved_alerts)}")
        self.total_suppressed_label.setText(f"Total Suppressed: {len(self.suppressed_alerts)}")
        self.total_escalated_label.setText(f"Total Escalated: {len(self.escalated_alerts)}")

        # Source breakdown
        src_counter = Counter(a.get("source", "Unknown") for a in self.alerts)
        self.source_breakdown.setRowCount(len(src_counter))
        for i, (src, count) in enumerate(src_counter.most_common()):
            sevs = [severity_score(a.get("calibrated_severity", "Medium"))
                    for a in self.alerts if a.get("source") == src]
            avg_sev = sum(sevs) / len(sevs) if sevs else 0
            self.source_breakdown.setItem(i, 0, self._make_item(src))
            self.source_breakdown.setItem(i, 1, self._make_item(str(count)))
            self.source_breakdown.setItem(i, 2, self._make_item(score_to_severity(avg_sev)))
            self.source_breakdown.setItem(i, 3, self._make_item(SOURCE_CATEGORY.get(src, "Unknown")))

        # Severity breakdown
        cal_counts = Counter(a.get("calibrated_severity", "Medium") for a in self.alerts)
        self.sev_breakdown.setRowCount(5)
        for i, sev in enumerate(["Critical", "High", "Medium", "Low", "Info"]):
            count = cal_counts.get(sev, 0)
            pct = f"{(count/total*100):.1f}%" if total > 0 else "0%"
            self.sev_breakdown.setItem(i, 0, self._make_item(sev))
            self.sev_breakdown.setItem(i, 1, self._make_item(str(count)))
            self.sev_breakdown.setItem(i, 2, self._make_item(pct))

    def _populate_rules_table(self):
        self.rules_table.setRowCount(len(self.suppression_rules))
        for i, rule in enumerate(self.suppression_rules):
            conds = rule.get("conditions", {})
            self.rules_table.setItem(i, 0, self._make_item(rule.get("id", "")))
            self.rules_table.setItem(i, 1, self._make_item(rule.get("name", "")))
            self.rules_table.setItem(i, 2, self._make_item(conds.get("source", "Any")))
            self.rules_table.setItem(i, 3, self._make_item(conds.get("title_contains", "Any")))
            self.rules_table.setItem(i, 4, self._make_item(rule.get("action", "suppress")))
            self.rules_table.setItem(i, 5, self._make_item(rule.get("severity_override", "")))
            enabled = "Yes" if rule.get("enabled", True) else "No"
            self.rules_table.setItem(i, 6, self._make_item(enabled))

    def _update_queue_table(self):
        queue_alerts = [a for a in self.alerts if a["id"] in self.triage_queue]
        self.queue_table.setRowCount(len(queue_alerts))
        for i, alert in enumerate(queue_alerts):
            self.queue_table.setItem(i, 0, self._make_item(alert.get("id", "")))
            self.queue_table.setItem(i, 1, self._make_item(alert.get("calibrated_severity", "")))
            self.queue_table.setItem(i, 2, self._make_item(alert.get("title", "")))
            self.queue_table.setItem(i, 3, self._make_item(alert.get("source", "")))

            start = self.triage_start_times.get(alert["id"])
            elapsed = str(datetime.utcnow() - start).split(".")[0] if start else "-"
            self.queue_table.setItem(i, 4, self._make_item(elapsed))

    # ── Alert Selection & Details ───────────────────────────────────────────────

    def _on_alert_selected(self, row, col, prev_row, prev_col):
        if row < 0:
            return
        id_item = self.alert_table.item(row, 0)
        if not id_item:
            return
        alert_id = id_item.text()
        alert = next((a for a in self.alerts if a["id"] == alert_id), None)
        if not alert:
            return

        self.detail_id.setText(alert.get("id", ""))
        self.detail_timestamp.setText(alert.get("timestamp", "")[:19])
        self.detail_source.setText(alert.get("source", ""))
        self.detail_severity.setText(alert.get("severity", ""))
        self.detail_cal_severity.setText(alert.get("calibrated_severity", ""))
        cal_sev = alert.get("calibrated_severity", "")
        color = SEVERITY_COLORS.get(cal_sev, QColor(128, 128, 128))
        self.detail_cal_severity.setStyleSheet(f"font-weight: bold; color: {color.name()};")

        self.detail_title.setText(alert.get("title", ""))
        self.detail_description.setText(alert.get("description", ""))
        self.detail_group_id.setText(alert.get("group_id", ""))
        self.detail_entities.setText(", ".join(alert.get("entities", [])))
        self.detail_iocs.setText(", ".join(alert.get("ioc_matches", [])))
        self.detail_status.setText(alert.get("status", "New"))
        self.detail_assigned.setText(alert.get("assigned_to", "") or "-")

        # Track triage start
        if alert.get("status") == "New" and alert_id not in self.triage_start_times:
            self.triage_start_times[alert_id] = datetime.utcnow()

        # Show CTI matches
        self._show_ioc_details(alert)
        self.notes_edit.setText(alert.get("triage_notes", ""))

    def _show_ioc_details(self, alert):
        ioc_lookup = self.cti_data.get("ioc_lookup", {})
        iocs = alert.get("ioc_matches", [])
        self.ioc_table.setRowCount(len(iocs))
        for i, ioc in enumerate(iocs):
            info = ioc_lookup.get(ioc, {})
            self.ioc_table.setItem(i, 0, self._make_item(ioc))
            self.ioc_table.setItem(i, 1, self._make_item(info.get("type", "unknown")))
            verdict = info.get("verdict", "unknown")
            verdict_item = QTableWidgetItem(verdict)
            verdict_item.setTextAlignment(Qt.AlignCenter)
            if verdict == "malicious":
                verdict_item.setForeground(QColor(220, 38, 38))
            elif verdict == "suspicious":
                verdict_item.setForeground(QColor(234, 140, 26))
            self.ioc_table.setItem(i, 2, verdict_item)
            self.ioc_table.setItem(i, 3, self._make_item(info.get("campaign", "-") or "-"))
            conf = info.get("confidence", 0)
            conf_item = QTableWidgetItem(f"{conf}%")
            conf_item.setTextAlignment(Qt.AlignCenter)
            self.ioc_table.setItem(i, 4, conf_item)

    def _on_group_selected(self, row, col, prev_row, prev_col):
        if row < 0:
            return
        gid_item = self.group_list.item(row, 0)
        if not gid_item:
            return
        gid = gid_item.text()
        alerts = self.groups.get(gid, [])

        self.group_detail_table.setRowCount(len(alerts))
        for i, alert in enumerate(alerts):
            self.group_detail_table.setItem(i, 0, self._make_item(alert.get("id", "")))
            self.group_detail_table.setItem(i, 1, self._make_item(alert.get("timestamp", "")[:19]))
            self.group_detail_table.setItem(i, 2, self._make_item(alert.get("source", "")))

            sev_item = QTableWidgetItem(alert.get("calibrated_severity", ""))
            sev_item.setTextAlignment(Qt.AlignCenter)
            self.group_detail_table.setItem(i, 3, sev_item)

            self.group_detail_table.setItem(i, 4, self._make_item(alert.get("title", "")))

            status_item = QTableWidgetItem(alert.get("status", "New"))
            status_item.setTextAlignment(Qt.AlignCenter)
            self.group_detail_table.setItem(i, 5, status_item)

    def _on_dedup_group_selected(self, row, col, prev_row, prev_col):
        if row < 0:
            return
        gid_item = self.dedup_group_detail.item(row, 0)
        if not gid_item:
            return

    # ── Triage Actions ─────────────────────────────────────────────────────────

    def _get_selected_alert_id(self):
        row = self.alert_table.currentRow()
        if row < 0:
            return None
        item = self.alert_table.item(row, 0)
        return item.text() if item else None

    def _get_selected_alert(self):
        aid = self._get_selected_alert_id()
        if not aid:
            return None
        return next((a for a in self.alerts if a["id"] == aid), None)

    def _triage_assign(self):
        alert = self._get_selected_alert()
        if not alert:
            QMessageBox.warning(self, "No Selection", "Select an alert first.")
            return
        alert["status"] = "Assigned"
        alert["assigned_to"] = "Current Analyst"
        alert["updated_at"] = datetime.utcnow().isoformat() + "Z"
        notes = self.notes_edit.toPlainText().strip()
        if notes:
            alert["triage_notes"] = notes
        if alert["id"] not in self.triage_queue:
            self.triage_queue.append(alert["id"])
        self._refresh_all()
        self._update_status(f"Alert {alert['id']} assigned to Current Analyst.")

    def _triage_escalate(self):
        alert = self._get_selected_alert()
        if not alert:
            QMessageBox.warning(self, "No Selection", "Select an alert first.")
            return
        alert["status"] = "Escalated"
        alert["updated_at"] = datetime.utcnow().isoformat() + "Z"
        alert["severity_change"] = "Promoted"
        alert["calibrated_severity"] = "Critical"
        notes = self.notes_edit.toPlainText().strip()
        if notes:
            alert["triage_notes"] = notes
        self.escalated_alerts.add(alert["id"])
        self._refresh_all()
        self._update_status(f"Alert {alert['id']} escalated to Critical.")

    def _triage_resolve(self):
        alert = self._get_selected_alert()
        if not alert:
            QMessageBox.warning(self, "No Selection", "Select an alert first.")
            return
        alert["status"] = "Resolved"
        alert["updated_at"] = datetime.utcnow().isoformat() + "Z"
        notes = self.notes_edit.toPlainText().strip()
        if notes:
            alert["triage_notes"] = notes
        self.resolved_alerts.add(alert["id"])
        if alert["id"] in self.triage_queue:
            self.triage_queue.remove(alert["id"])
        if alert["id"] in self.triage_start_times:
            elapsed = datetime.utcnow() - self.triage_start_times[alert["id"]]
            self.resolution_times[alert["id"]] = elapsed
        self._refresh_all()
        self._update_status(f"Alert {alert['id']} resolved.")

    def _triage_suppress(self):
        alert = self._get_selected_alert()
        if not alert:
            QMessageBox.warning(self, "No Selection", "Select an alert first.")
            return
        alert["status"] = "Suppressed"
        alert["calibrated_severity"] = "Suppressed"
        alert["updated_at"] = datetime.utcnow().isoformat() + "Z"
        notes = self.notes_edit.toPlainText().strip()
        if notes:
            alert["triage_notes"] = notes
        self.suppressed_alerts.add(alert["id"])
        if alert["id"] in self.triage_queue:
            self.triage_queue.remove(alert["id"])
        self._refresh_all()
        self._update_status(f"Alert {alert['id']} suppressed.")

    # ── Suppression Rules ──────────────────────────────────────────────────────

    def _add_rule(self):
        dlg = SuppressionRuleEditor(self)
        if dlg.exec() == QDialog.Accepted:
            rule = dlg.get_rule()
            rule["id"] = f"SUP-{len(self.suppression_rules)+1:03d}"
            self.suppression_rules.append(rule)
            self._populate_rules_table()
            self._update_status(f"Rule '{rule['name']}' added.")

    def _edit_rule(self):
        row = self.rules_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Select a rule to edit.")
            return
        rule = self.suppression_rules[row]
        dlg = SuppressionRuleEditor(self, rule=rule)
        if dlg.exec() == QDialog.Accepted:
            updated = dlg.get_rule()
            updated["id"] = rule["id"]
            self.suppression_rules[row] = updated
            self._populate_rules_table()
            self._update_status(f"Rule '{updated['name']}' updated.")

    def _delete_rule(self):
        row = self.rules_table.currentRow()
        if row < 0:
            return
        reply = QMessageBox.question(self, "Confirm", "Delete this rule?",
                                      QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            removed = self.suppression_rules.pop(row)
            self._populate_rules_table()
            self._update_status(f"Rule '{removed.get('name', '')}' deleted.")

    def _toggle_rule(self):
        row = self.rules_table.currentRow()
        if row < 0:
            return
        rule = self.suppression_rules[row]
        rule["enabled"] = not rule.get("enabled", True)
        self._populate_rules_table()

    def apply_suppression(self):
        if not self.suppression_rules:
            QMessageBox.information(self, "No Rules", "No suppression rules defined.")
            return

        applied = 0
        for alert in self.alerts:
            if alert.get("status") in ("Resolved", "Suppressed"):
                continue
            for rule in self.suppression_rules:
                if not rule.get("enabled", True):
                    continue
                conds = rule.get("conditions", {})
                match = True
                if "source" in conds and alert.get("source") != conds["source"]:
                    match = False
                if "title_contains" in conds:
                    if conds["title_contains"].lower() not in alert.get("title", "").lower():
                        match = False
                if "severity" in conds and alert.get("severity") != conds["severity"]:
                    match = False
                if "entity_contains" in conds:
                    entities = " ".join(alert.get("entities", []))
                    if conds["entity_contains"].lower() not in entities.lower():
                        match = False

                if match:
                    action = rule.get("action", "suppress")
                    if action == "suppress":
                        alert["status"] = "Suppressed"
                        alert["calibrated_severity"] = "Suppressed"
                        alert["updated_at"] = datetime.utcnow().isoformat() + "Z"
                        self.suppressed_alerts.add(alert["id"])
                    elif action == "escalate":
                        alert["calibrated_severity"] = rule.get("severity_override", "Critical")
                        alert["updated_at"] = datetime.utcnow().isoformat() + "Z"
                        self.escalated_alerts.add(alert["id"])
                    applied += 1
                    break

        self._refresh_all()
        self._update_status(f"Suppression rules applied. {applied} alerts affected.")

    # ── Export ──────────────────────────────────────────────────────────────────

    def export_report(self, fmt):
        if not self.alerts:
            QMessageBox.warning(self, "No Data", "Load alerts before exporting.")
            return

        default_name = f"soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        if fmt == "json":
            path, _ = QFileDialog.getSaveFileName(self, "Export JSON",
                                                    f"{default_name}.json", "JSON Files (*.json)")
            if not path: return
            export = []
            for a in self.alerts:
                export.append({
                    "id": a.get("id"), "timestamp": a.get("timestamp"),
                    "source": a.get("source"), "severity": a.get("severity"),
                    "calibrated_severity": a.get("calibrated_severity"),
                    "severity_change": a.get("severity_change"),
                    "title": a.get("title"), "description": a.get("description"),
                    "entities": a.get("entities"), "ioc_matches": a.get("ioc_matches"),
                    "status": a.get("status"), "group_id": a.get("group_id"),
                    "assigned_to": a.get("assigned_to"),
                    "triage_notes": a.get("triage_notes"),
                })
            with open(path, "w", encoding="utf-8") as f:
                json.dump(export, f, indent=2)
            self._update_status(f"Exported {len(export)} alerts to {path}")

        elif fmt == "csv":
            path, _ = QFileDialog.getSaveFileName(self, "Export CSV",
                                                    f"{default_name}.csv", "CSV Files (*.csv)")
            if not path: return
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["id","timestamp","source","severity","calibrated_severity",
                                  "severity_change","title","status","group_id","assigned_to","triage_notes"])
                for a in self.alerts:
                    writer.writerow([
                        a.get("id",""), a.get("timestamp",""), a.get("source",""),
                        a.get("severity",""), a.get("calibrated_severity",""),
                        a.get("severity_change",""), a.get("title",""),
                        a.get("status",""), a.get("group_id",""),
                        a.get("assigned_to",""), a.get("triage_notes","")
                    ])
            self._update_status(f"Exported CSV to {path}")

        elif fmt == "html":
            path, _ = QFileDialog.getSaveFileName(self, "Export HTML",
                                                    f"{default_name}.html", "HTML Files (*.html)")
            if not path: return
            html = self._generate_html_report()
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            self._update_status(f"Exported HTML report to {path}")

        elif fmt == "pdf":
            if not HAS_PRINTER:
                QMessageBox.warning(self, "Not Available", "PDF export via printer is not available. Use HTML export instead.")
                return
            path, _ = QFileDialog.getSaveFileName(self, "Export PDF",
                                                    f"{default_name}.pdf", "PDF Files (*.pdf)")
            if not path: return
            printer = QPrinter(QPrinter.HighResolution)
            printer.setOutputFormat(QPrinter.PdfFormat)
            printer.setOutputFileName(path)
            from PySide6.QtGui import QTextDocument
            doc = QTextDocument()
            doc.setHtml(self._generate_html_report())
            doc.print_(printer)
            self._update_status(f"Exported PDF to {path}")

    def _generate_html_report(self):
        total = len(self.alerts)
        cal_counts = Counter(a.get("calibrated_severity", "Medium") for a in self.alerts)
        backlog = sum(1 for a in self.alerts if a.get("status") in ("New", "Triage"))
        groups = len(self.groups)
        promoted = sum(1 for a in self.alerts if a.get("severity_change") == "Promoted")
        demoted = sum(1 for a in self.alerts if a.get("severity_change") == "Demoted")

        html = f"""<!DOCTYPE html>
<html><head><title>SOC Alert Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; }}
h1 {{ color: #1e293b; border-bottom: 2px solid #3b82f6; padding-bottom: 10px; }}
h2 {{ color: #374151; margin-top: 20px; }}
table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
th, td {{ border: 1px solid #d1d5db; padding: 8px; text-align: left; }}
th {{ background-color: #1e293b; color: white; }}
tr:nth-child(even) {{ background-color: #f3f4f6; }}
.critical {{ color: #dc2626; font-weight: bold; }}
.high {{ color: #ea8c1a; font-weight: bold; }}
.medium {{ color: #ca931a; font-weight: bold; }}
.low {{ color: #3b82f6; font-weight: bold; }}
.info {{ color: #6b7280; }}
.summary {{ background-color: #f0f9ff; padding: 15px; border-radius: 8px; margin: 10px 0; }}
.stat {{ display: inline-block; margin: 10px 20px; text-align: center; }}
.stat .num {{ font-size: 28px; font-weight: bold; color: #1e293b; }}
.stat .label {{ font-size: 12px; color: #6b7280; }}
</style></head><body>
<h1>SOC Alert Triage Dashboard Report</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<div class="summary">
<div class="stat"><div class="num">{total}</div><div class="label">Total Alerts</div></div>
<div class="stat"><div class="num">{groups}</div><div class="label">Unique Groups</div></div>
<div class="stat"><div class="num">{backlog}</div><div class="label">Backlog</div></div>
<div class="stat"><div class="num">{promoted}</div><div class="label">Promoted</div></div>
<div class="stat"><div class="num">{demoted}</div><div class="label">Demoted</div></div>
</div>

<h2>Calibrated Severity Breakdown</h2>
<table><tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>"""
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = cal_counts.get(sev, 0)
            pct = f"{(count/total*100):.1f}%" if total > 0 else "0%"
            html += f'<tr><td class="{sev.lower()}">{sev}</td><td>{count}</td><td>{pct}</td></tr>'
        html += "</table>"

        html += "<h2>Alert Details</h2><table><tr><th>ID</th><th>Time</th><th>Source</th><th>Original</th><th>Calibrated</th><th>Title</th><th>Status</th></tr>"
        for a in self.alerts:
            cal = a.get("calibrated_severity", "")
            html += f'<tr><td>{a.get("id","")}</td><td>{a.get("timestamp","")[:19]}</td>'
            html += f'<td>{a.get("source","")}</td><td>{a.get("severity","")}</td>'
            html += f'<td class="{cal.lower()}">{cal}</td><td>{a.get("title","")}</td>'
            html += f'<td>{a.get("status","")}</td></tr>'
        html += "</table>"

        html += "</body></html>"
        return html

    def generate_report(self):
        if not self.alerts:
            QMessageBox.warning(self, "No Data", "Load alerts first.")
            return

        total = len(self.alerts)
        groups = len(self.groups)
        backlog = sum(1 for a in self.alerts if a.get("status") in ("New", "Triage"))
        cal_counts = Counter(a.get("calibrated_severity", "Medium") for a in self.alerts)
        promoted = sum(1 for a in self.alerts if a.get("severity_change") == "Promoted")
        demoted = sum(1 for a in self.alerts if a.get("severity_change") == "Demoted")

        lines = [
            "=" * 60,
            "SOC ALERT TRIAGE DASHBOARD — SUMMARY REPORT",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 60,
            "",
            f"Total Alerts:        {total}",
            f"Unique Groups:       {groups}",
            f"Alert Backlog:       {backlog}",
            f"Promoted:            {promoted}",
            f"Demoted:             {demoted}",
            f"Resolved:            {len(self.resolved_alerts)}",
            f"Suppressed:          {len(self.suppressed_alerts)}",
            f"Escalated:           {len(self.escalated_alerts)}",
            "",
            "--- Calibrated Severity Breakdown ---",
        ]
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = cal_counts.get(sev, 0)
            pct = f"{(count/total*100):.1f}%" if total > 0 else "0%"
            lines.append(f"  {sev:10s}: {count:4d} ({pct})")

        lines.extend([
            "",
            "--- Top 10 Alert Titles ---",
        ])
        title_counts = Counter(a.get("title", "") for a in self.alerts)
        for title, count in title_counts.most_common(10):
            lines.append(f"  [{count:2d}] {title}")

        lines.extend([
            "",
            "--- Source Distribution ---",
        ])
        src_counts = Counter(a.get("source", "") for a in self.alerts)
        for src, count in src_counts.most_common():
            lines.append(f"  {src:20s}: {count}")

        lines.extend(["", "=" * 60])

        content = "\n".join(lines)
        dlg = ReportDialog(self, content=content, title="SOC Summary Report")
        dlg.exec()

    # ── Helpers ─────────────────────────────────────────────────────────────────

    def _make_item(self, text):
        item = QTableWidgetItem(str(text))
        return item

    def _update_status(self, msg):
        self.statusBar().showMessage(msg)


# ─── Entry Point ───────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)

    # Dark theme
    app.setStyleSheet("""
        QMainWindow { background-color: #0f172a; }
        QWidget { background-color: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', sans-serif; }
        QTabWidget::pane { border: 1px solid #334155; }
        QTabBar::tab { background: #1e293b; color: #94a3b8; padding: 8px 16px;
                       border: 1px solid #334155; border-bottom: none; border-top-left-radius: 4px;
                       border-top-right-radius: 4px; margin-right: 2px; }
        QTabBar::tab:selected { background: #334155; color: #f1f5f9; }
        QTabBar::tab:hover { background: #475569; }
        QTableWidget { background-color: #1e293b; gridline-color: #334155;
                       alternate-background-color: #1a2332; border: 1px solid #334155;
                       selection-background-color: #3b82f6; }
        QTableWidget::item { padding: 4px; }
        QHeaderView::section { background-color: #334155; color: #e2e8f0; padding: 6px;
                               border: 1px solid #475569; font-weight: bold; }
        QGroupBox { border: 1px solid #334155; border-radius: 6px; margin-top: 8px;
                    padding-top: 14px; font-weight: bold; color: #94a3b8; }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }
        QPushButton { background-color: #334155; color: #e2e8f0; border: 1px solid #475569;
                      border-radius: 4px; padding: 6px 12px; font-weight: bold; }
        QPushButton:hover { background-color: #475569; }
        QPushButton:pressed { background-color: #64748b; }
        QLineEdit, QComboBox, QSpinBox, QTextEdit, QPlainTextEdit {
            background-color: #1e293b; color: #e2e8f0; border: 1px solid #475569;
            border-radius: 4px; padding: 4px 8px; }
        QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus { border-color: #3b82f6; }
        QComboBox::drop-down { border: none; padding-right: 8px; }
        QComboBox QAbstractItemView { background-color: #1e293b; color: #e2e8f0;
                                       selection-background-color: #3b82f6; }
        QLabel { color: #e2e8f0; }
        QProgressBar { border: 1px solid #475569; border-radius: 4px; text-align: center; }
        QProgressBar::chunk { background-color: #3b82f6; border-radius: 3px; }
        QStatusBar { background-color: #1e293b; color: #94a3b8; }
        QSplitter::handle { background-color: #334155; }
        QScrollBar:vertical { background: #1e293b; width: 10px; }
        QScrollBar::handle:vertical { background: #475569; border-radius: 5px; min-height: 20px; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
        QMessageBox { background-color: #1e293b; }
        QDialog { background-color: #0f172a; }
    """)

    window = SOCAlertDashboard()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
