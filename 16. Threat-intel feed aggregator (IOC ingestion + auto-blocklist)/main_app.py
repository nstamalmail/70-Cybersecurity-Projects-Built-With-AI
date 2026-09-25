#!/usr/bin/env python3
"""
Threat-Intel Feed Aggregator (IOC Ingestion + Auto-Blocklist)
A complete PySide6 GUI application for threat intelligence management.
"""

import sys
import os
import csv
import json
import uuid
import hashlib
import random
import re
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTableWidget, QTableWidgetItem, QPushButton,
    QLabel, QLineEdit, QComboBox, QTextEdit, QFileDialog,
    QProgressBar, QGroupBox, QFormLayout, QHeaderView, QFrame,
    QMessageBox, QSpinBox, QCheckBox, QAbstractItemView, QGridLayout
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QColor, QFont, QPalette


class IOCType(Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"


@dataclass
class IOC:
    id: str = ""
    ioc_type: str = ""
    value: str = ""
    raw_value: str = ""
    source: str = ""
    confidence: int = 0
    first_seen: str = ""
    last_seen: str = ""
    tags: List[str] = field(default_factory=list)
    threat_type: str = ""
    malware_family: str = ""
    tlp: str = "GREEN"

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.first_seen:
            self.first_seen = datetime.now().isoformat() + "Z"
        if not self.last_seen:
            self.last_seen = datetime.now().isoformat() + "Z"


@dataclass
class Feed:
    name: str = ""
    feed_type: str = ""
    url: str = ""
    api_key: str = ""
    enabled: bool = True
    interval_minutes: int = 60
    last_sync: str = ""
    ioc_types: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    reliability_score: int = 20
    status: str = "idle"
    total_iocs: int = 0


@dataclass
class BlocklistConfig:
    format_name: str = ""
    include_ips: bool = True
    include_domains: bool = True
    include_urls: bool = True
    include_hashes: bool = True
    min_confidence: int = 0
    max_age_days: int = 365


class IOCNormalizer:
    IPV4_REGEX = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    )
    DOMAIN_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$"
    )
    URL_REGEX = re.compile(r"^https?://")
    MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
    SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
    SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
    EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

    @classmethod
    def detect_type(cls, value: str) -> str:
        value = value.strip()
        if cls.IPV4_REGEX.match(value):
            return IOCType.IPV4.value
        if cls.EMAIL_REGEX.match(value):
            return IOCType.EMAIL.value
        if cls.URL_REGEX.match(value):
            return IOCType.URL.value
        if cls.MD5_REGEX.match(value):
            return IOCType.MD5.value
        if cls.SHA256_REGEX.match(value):
            return IOCType.SHA256.value
        if cls.SHA1_REGEX.match(value):
            return IOCType.SHA1.value
        if cls.DOMAIN_REGEX.match(value):
            return IOCType.DOMAIN.value
        return "unknown"

    @classmethod
    def normalize(cls, value: str) -> str:
        value = value.strip()
        ioc_type = cls.detect_type(value)
        if ioc_type == IOCType.DOMAIN.value:
            return value.lower().rstrip(".")
        if ioc_type in (IOCType.MD5.value, IOCType.SHA1.value, IOCType.SHA256.value):
            return value.lower()
        if ioc_type == IOCType.EMAIL.value:
            return value.lower()
        return value


class ConfidenceCalculator:
    SOURCE_SCORES = {
        "MISP": 40,
        "TAXII/STIX": 35,
        "OTX AlienVault": 30,
        "OTX": 30,
        "URLhaus": 30,
        "Custom CSV": 20,
        "Manual Import": 15,
    }

    @classmethod
    def calculate(cls, ioc: IOC) -> int:
        base = cls.SOURCE_SCORES.get(ioc.source, 20)
        enrichment = 0
        if ioc.threat_type:
            enrichment += 5
        if ioc.malware_family:
            enrichment += 5
        age_score = cls._age_score(ioc.last_seen)
        total = base + enrichment + age_score
        return max(0, min(100, total))

    @classmethod
    def _age_score(cls, last_seen: str) -> int:
        try:
            dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            age = datetime.now().astimezone() - dt
            days = age.days
        except Exception:
            return 15
        if days <= 1:
            return 30
        if days <= 7:
            return 25
        if days <= 30:
            return 20
        if days <= 90:
            return 10
        if days <= 365:
            return 5
        return 0

    @classmethod
    def level(cls, confidence: int) -> Tuple[str, QColor]:
        if confidence >= 90:
            return "CRITICAL", QColor(220, 20, 60)
        if confidence >= 70:
            return "HIGH", QColor(255, 140, 0)
        if confidence >= 50:
            return "MEDIUM", QColor(255, 215, 0)
        if confidence >= 30:
            return "LOW", QColor(100, 149, 237)
        return "INFO", QColor(169, 169, 169)


class BlocklistGenerator:
    @staticmethod
    def generate(iocs: List[IOC], format_name: str, config: BlocklistConfig = None) -> str:
        if config is None:
            config = BlocklistConfig()
        filtered = BlocklistGenerator._filter(iocs, config)
        generators = {
            "Palo Alto EDL": BlocklistGenerator._palo_alto_edl,
            "FortiGate EBL": BlocklistGenerator._fortigate_ebl,
            "Nginx deny.conf": BlocklistGenerator._nginx_deny,
            "iptables": BlocklistGenerator._iptables,
            "DNS RPZ": BlocklistGenerator._dns_rpz,
            "Plain Text": BlocklistGenerator._plain_text,
        }
        gen_func = generators.get(format_name, BlocklistGenerator._plain_text)
        return gen_func(filtered)

    @staticmethod
    def _filter(iocs: List[IOC], config: BlocklistConfig) -> List[IOC]:
        result = []
        for ioc in iocs:
            if ioc.confidence < config.min_confidence:
                continue
            if ioc.ioc_type in ("ipv4", "ipv6") and not config.include_ips:
                continue
            if ioc.ioc_type == "domain" and not config.include_domains:
                continue
            if ioc.ioc_type == "url" and not config.include_urls:
                continue
            if ioc.ioc_type in ("md5", "sha1", "sha256") and not config.include_hashes:
                continue
            result.append(ioc)
        return result

    @staticmethod
    def _palo_alto_edl(iocs: List[IOC]) -> str:
        lines = [
            "# Palo Alto EDL Format",
            f"# Generated: {datetime.now().isoformat()}",
            f"# Total IOCs: {len(iocs)}",
        ]
        for ioc in iocs:
            lines.append(ioc.value)
        return "\n".join(lines)

    @staticmethod
    def _fortigate_ebl(iocs: List[IOC]) -> str:
        ips = [i for i in iocs if i.ioc_type in ("ipv4", "ipv6")]
        domains = [i for i in iocs if i.ioc_type == "domain"]
        urls = [i for i in iocs if i.ioc_type == "url"]
        lines = [
            "# FortiGate EBL Format",
            f"# Generated: {datetime.now().isoformat()}",
            "#IPs",
        ]
        for i in ips:
            lines.append(i.value)
        lines.append("#Domains")
        for d in domains:
            lines.append(d.value)
        lines.append("#URLs")
        for u in urls:
            lines.append(u.value)
        return "\n".join(lines)

    @staticmethod
    def _nginx_deny(iocs: List[IOC]) -> str:
        lines = [
            "# Nginx Deny Configuration",
            f"# Generated: {datetime.now().strftime('%Y-%m-%d')}",
        ]
        for ioc in iocs:
            lines.append(f"deny {ioc.value};")
        return "\n".join(lines)

    @staticmethod
    def _iptables(iocs: List[IOC]) -> str:
        lines = [
            "# iptables rules",
            f"# Generated: {datetime.now().strftime('%Y-%m-%d')}",
        ]
        for ioc in iocs:
            if ioc.ioc_type in ("ipv4", "ipv6"):
                lines.append(f"iptables -A INPUT -s {ioc.value} -j DROP")
                lines.append(f"iptables -A OUTPUT -d {ioc.value} -j DROP")
        return "\n".join(lines)

    @staticmethod
    def _dns_rpz(iocs: List[IOC]) -> str:
        domains = [i for i in iocs if i.ioc_type in ("domain", "url")]
        lines = [
            "; DNS RPZ Zone",
            "$TTL 300",
            "@ IN SOA ns.example.com. admin.example.com. (",
            "    2024011501 ; Serial",
            "    3600       ; Refresh",
            "    600        ; Retry",
            "    86400      ; Expire",
            "    300        ; Minimum",
            ")",
        ]
        for ioc in domains:
            domain = ioc.value
            if ioc.ioc_type == "url":
                try:
                    parsed = urlparse(ioc.value)
                    domain = parsed.hostname or domain
                except Exception:
                    pass
            lines.append(f"{domain} CNAME .")
            lines.append(f"*.{domain} CNAME .")
        return "\n".join(lines)

    @staticmethod
    def _plain_text(iocs: List[IOC]) -> str:
        lines = [
            "# Threat-Intel Blocklist",
            f"# Generated: {datetime.now().isoformat()}",
            f"# Total IOCs: {len(iocs)}",
            "# --------------------------------------------------",
        ]
        type_order = ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"]
        type_labels = {
            "ipv4": "IPs",
            "ipv6": "IPv6",
            "domain": "Domains",
            "url": "URLs",
            "md5": "MD5 Hashes",
            "sha1": "SHA1 Hashes",
            "sha256": "SHA256 Hashes",
            "email": "Emails",
        }
        grouped = {}
        for ioc in iocs:
            grouped.setdefault(ioc.ioc_type, []).append(ioc)
        for t in type_order:
            if t in grouped:
                lines.append(f"\n# {type_labels.get(t, t)}")
                for ioc in grouped[t]:
                    lines.append(ioc.value)
        return "\n".join(lines)


class SampleDataGenerator:
    SOURCES = ["OTX AlienVault", "URLhaus", "MISP", "Custom CSV", "Manual Import"]
    TAGS = [
        "malware", "c2", "phishing", "scanner", "apt",
        "ransomware", "exploit", "spam", "backdoor", "keylogger",
    ]
    THREAT_TYPES = [
        "malware", "phishing", "c2", "scanner",
        "ransomware", "exploit", "spam", "backdoor",
    ]
    MALWARE_FAMILIES = [
        "emotet", "trickbot", "cobalt_strike", "lockbit",
        "apt28", "apt29", "",
    ]

    @classmethod
    def generate(cls, count: int = 100) -> List[IOC]:
        iocs = []
        for _ in range(count):
            ioc_type = random.choice(list(IOCType))
            value = cls._generate_value(ioc_type)
            source = random.choice(cls.SOURCES)
            base_confidence = {
                "OTX AlienVault": 30,
                "URLhaus": 30,
                "MISP": 40,
                "Custom CSV": 20,
                "Manual Import": 15,
            }
            confidence = base_confidence.get(source, 20) + random.randint(0, 40)
            confidence = min(100, max(0, confidence))
            days_ago = random.randint(0, 90)
            first_seen = (
                datetime.now() - timedelta(days=days_ago + random.randint(0, 30))
            ).isoformat() + "Z"
            last_seen = (datetime.now() - timedelta(days=days_ago)).isoformat() + "Z"
            tags = random.sample(cls.TAGS, k=random.randint(1, 3))
            ioc = IOC(
                ioc_type=ioc_type.value,
                value=value,
                raw_value=value,
                source=source,
                confidence=confidence,
                first_seen=first_seen,
                last_seen=last_seen,
                tags=tags,
                threat_type=random.choice(cls.THREAT_TYPES),
                malware_family=random.choice(cls.MALWARE_FAMILIES),
                tlp=random.choice(["WHITE", "GREEN", "AMBER", "RED"]),
            )
            ioc.confidence = ConfidenceCalculator.calculate(ioc)
            iocs.append(ioc)
        return iocs

    @classmethod
    def _generate_value(cls, ioc_type: IOCType) -> str:
        if ioc_type == IOCType.IPV4:
            return (
                f"{random.randint(1,223)}.{random.randint(0,255)}"
                f".{random.randint(0,255)}.{random.randint(1,254)}"
            )
        if ioc_type == IOCType.DOMAIN:
            prefixes = [
                "malware", "phishing", "c2", "bot",
                "exploit", "spam", "apt", "backdoor",
            ]
            suffixes = ["evil.com", "bad.net", "dark.org", "scam.net", "threat.io"]
            return (
                f"{random.choice(prefixes)}-{uuid.uuid4().hex[:8]}"
                f".{random.choice(suffixes)}"
            )
        if ioc_type == IOCType.URL:
            domain = cls._generate_value(IOCType.DOMAIN)
            paths = ["/payload.exe", "/login.php", "/command", "/beacon", "/download", "/steal"]
            return f"http://{domain}{random.choice(paths)}"
        if ioc_type == IOCType.MD5:
            return hashlib.md5(uuid.uuid4().bytes).hexdigest()
        if ioc_type == IOCType.SHA1:
            return hashlib.sha1(uuid.uuid4().bytes).hexdigest()
        if ioc_type == IOCType.SHA256:
            return hashlib.sha256(uuid.uuid4().bytes).hexdigest()
        if ioc_type == IOCType.EMAIL:
            prefixes = ["attacker", "phisher", "spam", "bot", "c2", "dropper"]
            return f"{random.choice(prefixes)}@{cls._generate_value(IOCType.DOMAIN)}"
        return "unknown"


class IngestionWorker(QThread):
    progress = Signal(int, str)
    finished = Signal(list)
    error = Signal(str)

    def __init__(self, iocs: List[IOC]):
        super().__init__()
        self.iocs = iocs
        self._is_running = True

    def run(self):
        total = len(self.iocs)
        for i, ioc in enumerate(self.iocs):
            if not self._is_running:
                break
            ioc.confidence = ConfidenceCalculator.calculate(ioc)
            pct = int((i + 1) / total * 100)
            self.progress.emit(pct, f"Processing IOC {i+1}/{total}: {ioc.value[:40]}...")
            self.msleep(10)
        self.finished.emit(self.iocs)

    def stop(self):
        self._is_running = False


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Threat-Intel Feed Aggregator - IOC Ingestion + Auto-Blocklist")
        self.setMinimumSize(1200, 800)
        self.iocs: List[IOC] = []
        self.feeds: List[Feed] = []
        self.worker: Optional[IngestionWorker] = None
        self._setup_ui()
        self._connect_signals()
        self.statusBar().showMessage("Ready")

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(8, 8, 8, 8)
        toolbar = self._create_toolbar()
        main_layout.addWidget(toolbar)
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        self.tabs.addTab(self._create_feed_manager_tab(), "Feed Manager")
        self.tabs.addTab(self._create_ioc_inspector_tab(), "IOC Inspector")
        self.tabs.addTab(self._create_blocklist_tab(), "Blocklist Generator")
        self.tabs.addTab(self._create_confidence_tab(), "Confidence Dashboard")
        self.tabs.addTab(self._create_report_tab(), "Report Builder")
        self.tabs.addTab(self._create_progress_tab(), "Ingestion Progress")
        self.tabs.addTab(self._create_source_health_tab(), "Source Health")

    def _create_toolbar(self) -> QWidget:
        toolbar = QFrame()
        toolbar.setFrameShape(QFrame.StyledPanel)
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(4, 4, 4, 4)
        btn_demo = QPushButton("Load Demo Data")
        btn_demo.setStyleSheet(
            "background-color: #2196F3; color: white; padding: 8px 16px; font-weight: bold;"
        )
        btn_demo.clicked.connect(self.load_demo_data)
        toolbar_layout.addWidget(btn_demo)
        btn_import = QPushButton("Import IOCs")
        btn_import.setStyleSheet(
            "background-color: #4CAF50; color: white; padding: 8px 16px; font-weight: bold;"
        )
        btn_import.clicked.connect(self.import_iocs)
        toolbar_layout.addWidget(btn_import)
        btn_clear = QPushButton("Clear All")
        btn_clear.setStyleSheet(
            "background-color: #f44336; color: white; padding: 8px 16px; font-weight: bold;"
        )
        btn_clear.clicked.connect(self.clear_all)
        toolbar_layout.addWidget(btn_clear)
        toolbar_layout.addStretch()
        self.lbl_count = QLabel("IOCs: 0")
        self.lbl_count.setStyleSheet("font-weight: bold; font-size: 14px; padding: 8px;")
        toolbar_layout.addWidget(self.lbl_count)
        return toolbar

    def _create_feed_manager_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        grp = QGroupBox("Configured Feeds")
        grp_layout = QVBoxLayout(grp)
        self.feed_table = QTableWidget()
        self.feed_table.setColumnCount(7)
        self.feed_table.setHorizontalHeaderLabels(
            ["Name", "Type", "URL", "Enabled", "Interval (min)", "Status", "IOCs"]
        )
        self.feed_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.feed_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        grp_layout.addWidget(self.feed_table)
        btn_layout = QHBoxLayout()
        btn_add = QPushButton("Add Feed")
        btn_add.clicked.connect(self._add_feed)
        btn_layout.addWidget(btn_add)
        btn_remove = QPushButton("Remove Feed")
        btn_remove.clicked.connect(self._remove_feed)
        btn_layout.addWidget(btn_remove)
        btn_sync = QPushButton("Sync All Feeds")
        btn_sync.setStyleSheet("background-color: #FF9800; color: white;")
        btn_sync.clicked.connect(self._sync_feeds)
        btn_layout.addWidget(btn_sync)
        grp_layout.addLayout(btn_layout)
        layout.addWidget(grp)
        self._load_sample_feeds()
        return widget

    def _create_ioc_inspector_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        self.ioc_filter = QLineEdit()
        self.ioc_filter.setPlaceholderText("Search IOCs by value, type, or source...")
        filter_layout.addWidget(self.ioc_filter)
        filter_layout.addWidget(QLabel("Type:"))
        self.type_filter = QComboBox()
        self.type_filter.addItems(
            ["All", "ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"]
        )
        filter_layout.addWidget(self.type_filter)
        filter_layout.addWidget(QLabel("Source:"))
        self.source_filter = QComboBox()
        self.source_filter.addItems(
            ["All", "OTX AlienVault", "URLhaus", "MISP", "Custom CSV", "Manual Import"]
        )
        filter_layout.addWidget(self.source_filter)
        btn_apply = QPushButton("Apply Filter")
        btn_apply.clicked.connect(self._apply_filter)
        filter_layout.addWidget(btn_apply)
        layout.addLayout(filter_layout)
        self.ioc_table = QTableWidget()
        self.ioc_table.setColumnCount(9)
        self.ioc_table.setHorizontalHeaderLabels([
            "Type", "Value", "Source", "Confidence", "Level",
            "First Seen", "Last Seen", "Tags", "Threat Type",
        ])
        self.ioc_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.ioc_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.ioc_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.ioc_table.setAlternatingRowColors(True)
        layout.addWidget(self.ioc_table)
        btn_layout = QHBoxLayout()
        btn_delete = QPushButton("Delete Selected")
        btn_delete.clicked.connect(self._delete_selected_iocs)
        btn_layout.addWidget(btn_delete)
        btn_export_sel = QPushButton("Export Selected")
        btn_export_sel.clicked.connect(self._export_selected)
        btn_layout.addWidget(btn_export_sel)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        return widget

    def _create_blocklist_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        ctrl_layout = QHBoxLayout()
        grp_fmt = QGroupBox("Format")
        fmt_layout = QVBoxLayout(grp_fmt)
        self.blocklist_format = QComboBox()
        self.blocklist_format.addItems([
            "Palo Alto EDL", "FortiGate EBL", "Nginx deny.conf",
            "iptables", "DNS RPZ", "Plain Text",
        ])
        fmt_layout.addWidget(self.blocklist_format)
        ctrl_layout.addWidget(grp_fmt)
        grp_filter = QGroupBox("Filters")
        flt_layout = QFormLayout(grp_filter)
        self.chk_ips = QCheckBox("Include IPs")
        self.chk_ips.setChecked(True)
        flt_layout.addRow(self.chk_ips)
        self.chk_domains = QCheckBox("Include Domains")
        self.chk_domains.setChecked(True)
        flt_layout.addRow(self.chk_domains)
        self.chk_urls = QCheckBox("Include URLs")
        self.chk_urls.setChecked(True)
        flt_layout.addRow(self.chk_urls)
        self.chk_hashes = QCheckBox("Include Hashes")
        self.chk_hashes.setChecked(True)
        flt_layout.addRow(self.chk_hashes)
        self.spin_min_conf = QSpinBox()
        self.spin_min_conf.setRange(0, 100)
        self.spin_min_conf.setValue(0)
        flt_layout.addRow("Min Confidence:", self.spin_min_conf)
        ctrl_layout.addWidget(grp_filter)
        layout.addLayout(ctrl_layout)
        btn_gen = QPushButton("Generate Blocklist")
        btn_gen.setStyleSheet(
            "background-color: #9C27B0; color: white; padding: 10px; font-weight: bold;"
        )
        btn_gen.clicked.connect(self._generate_blocklist)
        layout.addWidget(btn_gen)
        self.blocklist_preview = QTextEdit()
        self.blocklist_preview.setReadOnly(True)
        self.blocklist_preview.setFont(QFont("Consolas", 10))
        layout.addWidget(self.blocklist_preview)
        btn_save = QPushButton("Save Blocklist")
        btn_save.setStyleSheet("background-color: #00BCD4; color: white;")
        btn_save.clicked.connect(self._save_blocklist)
        layout.addWidget(btn_save)
        return widget

    def _create_confidence_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        stats_layout = QGridLayout()
        self.lbl_critical = self._create_stat_card("CRITICAL", "0", "#DC143C")
        stats_layout.addWidget(self.lbl_critical, 0, 0)
        self.lbl_high = self._create_stat_card("HIGH", "0", "#FF8C00")
        stats_layout.addWidget(self.lbl_high, 0, 1)
        self.lbl_medium = self._create_stat_card("MEDIUM", "0", "#FFD700")
        stats_layout.addWidget(self.lbl_medium, 0, 2)
        self.lbl_low = self._create_stat_card("LOW", "0", "#6495ED")
        stats_layout.addWidget(self.lbl_low, 0, 3)
        self.lbl_info = self._create_stat_card("INFO", "0", "#A9A9A9")
        stats_layout.addWidget(self.lbl_info, 0, 4)
        layout.addLayout(stats_layout)
        layout.addWidget(QLabel("Confidence Distribution by Source"))
        self.conf_table = QTableWidget()
        self.conf_table.setColumnCount(5)
        self.conf_table.setHorizontalHeaderLabels(
            ["Source", "Avg Confidence", "IOC Count", "Critical", "High"]
        )
        self.conf_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.conf_table)
        btn_refresh = QPushButton("Refresh Dashboard")
        btn_refresh.clicked.connect(self._refresh_confidence)
        layout.addWidget(btn_refresh)
        return widget

    def _create_stat_card(self, title, value, color):
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        frame.setStyleSheet(
            f"QFrame {{ border: 2px solid {color}; border-radius: 8px; background-color: {color}22; }}"
        )
        layout = QVBoxLayout(frame)
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 12px;")
        lbl_title.setAlignment(Qt.AlignCenter)
        layout.addWidget(lbl_title)
        lbl_val = QLabel(value)
        lbl_val.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: bold;")
        lbl_val.setAlignment(Qt.AlignCenter)
        lbl_val.setObjectName("value_label")
        layout.addWidget(lbl_val)
        return frame

    def _create_report_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        ctrl_layout = QHBoxLayout()
        ctrl_layout.addWidget(QLabel("Export Format:"))
        self.export_format = QComboBox()
        self.export_format.addItems(["JSON", "CSV", "HTML"])
        ctrl_layout.addWidget(self.export_format)
        btn_export = QPushButton("Export Report")
        btn_export.setStyleSheet(
            "background-color: #607D8B; color: white; padding: 8px 16px;"
        )
        btn_export.clicked.connect(self._export_report)
        ctrl_layout.addWidget(btn_export)
        ctrl_layout.addStretch()
        layout.addLayout(ctrl_layout)
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setFont(QFont("Consolas", 10))
        layout.addWidget(self.report_preview)
        btn_preview = QPushButton("Preview Report")
        btn_preview.clicked.connect(self._preview_report)
        layout.addWidget(btn_preview)
        return widget

    def _create_progress_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        self.progress_label = QLabel("No ingestion in progress")
        layout.addWidget(self.progress_label)
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setFont(QFont("Consolas", 9))
        layout.addWidget(self.log_area)
        return widget

    def _create_source_health_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.health_table = QTableWidget()
        self.health_table.setColumnCount(6)
        self.health_table.setHorizontalHeaderLabels([
            "Source", "Status", "Uptime", "Total IOCs", "Reliability", "Last Error",
        ])
        self.health_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.health_table)
        btn_refresh = QPushButton("Refresh Health")
        btn_refresh.clicked.connect(self._refresh_health)
        layout.addWidget(btn_refresh)
        return widget

    def _connect_signals(self):
        self.ioc_filter.textChanged.connect(self._apply_filter)
        self.type_filter.currentTextChanged.connect(lambda: self._apply_filter())
        self.source_filter.currentTextChanged.connect(lambda: self._apply_filter())

    def _load_sample_feeds(self):
        self.feeds = [
            Feed(
                "OTX AlienVault", "otx",
                "https://otx.alienvault.com/api/v1/pulses/subscribed",
                "", True, 60, "",
                ["ipv4", "domain", "url", "sha256"],
                ["threat-intel"], 30, "healthy", 250,
            ),
            Feed(
                "URLhaus", "urlhaus",
                "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                "", True, 30, "",
                ["url", "domain", "ipv4"],
                ["malware", "phishing"], 30, "healthy", 180,
            ),
            Feed(
                "MISP Instance", "misp",
                "https://misp.example.com",
                "", True, 120, "",
                ["ipv4", "domain", "url", "sha256", "md5"],
                ["apt", "malware"], 40, "healthy", 320,
            ),
            Feed(
                "Custom CSV", "custom_csv",
                "sample_data/sample_iocs.csv",
                "", True, 1440, "",
                ["ipv4", "domain", "url", "sha256", "md5", "sha1", "email"],
                ["custom"], 20, "healthy", 100,
            ),
        ]
        self._refresh_feed_table()

    def _refresh_feed_table(self):
        self.feed_table.setRowCount(len(self.feeds))
        for i, feed in enumerate(self.feeds):
            self.feed_table.setItem(i, 0, QTableWidgetItem(feed.name))
            self.feed_table.setItem(i, 1, QTableWidgetItem(feed.feed_type))
            self.feed_table.setItem(i, 2, QTableWidgetItem(feed.url))
            chk = QTableWidgetItem()
            chk.setCheckState(Qt.Checked if feed.enabled else Qt.Unchecked)
            self.feed_table.setItem(i, 3, chk)
            self.feed_table.setItem(i, 4, QTableWidgetItem(str(feed.interval_minutes)))
            status_item = QTableWidgetItem(feed.status)
            if feed.status == "healthy":
                status_item.setForeground(QColor(76, 175, 80))
            elif feed.status == "error":
                status_item.setForeground(QColor(244, 67, 54))
            self.feed_table.setItem(i, 5, status_item)
            self.feed_table.setItem(i, 6, QTableWidgetItem(str(feed.total_iocs)))

    def load_demo_data(self):
        self.log("Loading demo data...")
        self.iocs = SampleDataGenerator.generate(100)
        self._apply_confidence_scores()
        self._refresh_ioc_table()
        self._update_count_label()
        self._refresh_confidence()
        self._refresh_health()
        self.log(f"Loaded {len(self.iocs)} demo IOCs")
        self.statusBar().showMessage(f"Loaded {len(self.iocs)} demo IOCs")

    def import_iocs(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import IOCs", "",
            "CSV Files (*.csv);;JSON Files (*.json);;All Files (*)",
        )
        if not file_path:
            return
        self.log(f"Importing from: {file_path}")
        try:
            ext = Path(file_path).suffix.lower()
            if ext == ".csv":
                self._import_csv(file_path)
            elif ext == ".json":
                self._import_json(file_path)
            else:
                QMessageBox.warning(self, "Error", "Unsupported file format. Use CSV or JSON.")
                return
            self._apply_confidence_scores()
            self._refresh_ioc_table()
            self._update_count_label()
            self._refresh_confidence()
            self._refresh_health()
            self.log(f"Imported {len(self.iocs)} total IOCs")
            self.statusBar().showMessage(f"Imported IOCs. Total: {len(self.iocs)}")
        except Exception as e:
            QMessageBox.critical(self, "Import Error", str(e))
            self.log(f"Import error: {e}")

    def _import_csv(self, path):
        new_iocs = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ioc_type = row.get("type", "").strip().lower()
                value = row.get("value", "").strip()
                if not value:
                    continue
                if not ioc_type:
                    ioc_type = IOCNormalizer.detect_type(value)
                value = IOCNormalizer.normalize(value)
                tags_raw = row.get("tags", "").strip("[]")
                ioc = IOC(
                    ioc_type=ioc_type,
                    value=value,
                    raw_value=row.get("value", value).strip(),
                    source=row.get("source", "Manual Import").strip(),
                    confidence=int(row.get("confidence", 0)),
                    first_seen=row.get(
                        "first_seen", datetime.now().isoformat() + "Z"
                    ).strip(),
                    last_seen=row.get(
                        "last_seen", datetime.now().isoformat() + "Z"
                    ).strip(),
                    tags=[t.strip() for t in tags_raw.split(",") if t.strip()],
                    threat_type=row.get("threat_type", "").strip(),
                    malware_family=row.get("malware_family", "").strip(),
                    tlp=row.get("tlp", "GREEN").strip(),
                )
                new_iocs.append(ioc)
        self.iocs.extend(new_iocs)

    def _import_json(self, path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict) and "iocs" in data:
            items = data["iocs"]
        else:
            items = [data]
        for item in items:
            ioc = IOC(
                ioc_type=item.get("ioc_type", item.get("type", "unknown")),
                value=item.get("value", ""),
                raw_value=item.get("raw_value", item.get("value", "")),
                source=item.get("source", "Manual Import"),
                confidence=int(item.get("confidence", 0)),
                first_seen=item.get(
                    "first_seen", datetime.now().isoformat() + "Z"
                ),
                last_seen=item.get(
                    "last_seen", datetime.now().isoformat() + "Z"
                ),
                tags=item.get("tags", []),
                threat_type=item.get("threat_type", ""),
                malware_family=item.get("malware_family", ""),
                tlp=item.get("tlp", "GREEN"),
            )
            self.iocs.append(ioc)

    def clear_all(self):
        reply = QMessageBox.question(
            self, "Confirm", "Clear all IOCs?", QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.iocs.clear()
            self._refresh_ioc_table()
            self._update_count_label()
            self._refresh_confidence()
            self.log("Cleared all IOCs")

    def _apply_confidence_scores(self):
        for ioc in self.iocs:
            ioc.confidence = ConfidenceCalculator.calculate(ioc)

    def _refresh_ioc_table(self, filtered=None):
        data = filtered if filtered is not None else self.iocs
        self.ioc_table.setRowCount(len(data))
        for i, ioc in enumerate(data):
            self.ioc_table.setItem(i, 0, QTableWidgetItem(ioc.ioc_type))
            val_item = QTableWidgetItem(ioc.value)
            val_item.setToolTip(ioc.value)
            self.ioc_table.setItem(i, 1, val_item)
            self.ioc_table.setItem(i, 2, QTableWidgetItem(ioc.source))
            conf_item = QTableWidgetItem(str(ioc.confidence))
            level_text, level_color = ConfidenceCalculator.level(ioc.confidence)
            conf_item.setForeground(level_color)
            conf_item.setTextAlignment(Qt.AlignCenter)
            self.ioc_table.setItem(i, 3, conf_item)
            level_item = QTableWidgetItem(level_text)
            level_item.setForeground(level_color)
            level_item.setTextAlignment(Qt.AlignCenter)
            self.ioc_table.setItem(i, 4, level_item)
            self.ioc_table.setItem(i, 5, QTableWidgetItem(ioc.first_seen[:19]))
            self.ioc_table.setItem(i, 6, QTableWidgetItem(ioc.last_seen[:19]))
            self.ioc_table.setItem(i, 7, QTableWidgetItem(", ".join(ioc.tags)))
            self.ioc_table.setItem(i, 8, QTableWidgetItem(ioc.threat_type))
            row_color = self._row_bg_color(ioc.confidence)
            for col in range(9):
                item = self.ioc_table.item(i, col)
                if item:
                    item.setBackground(row_color)

    def _row_bg_color(self, confidence):
        if confidence >= 90:
            return QColor(220, 20, 60, 30)
        if confidence >= 70:
            return QColor(255, 140, 0, 25)
        if confidence >= 50:
            return QColor(255, 215, 0, 20)
        if confidence >= 30:
            return QColor(100, 149, 237, 15)
        return QColor(200, 200, 200, 10)

    def _apply_filter(self):
        text = self.ioc_filter.text().lower()
        ioc_type = self.type_filter.currentText()
        source = self.source_filter.currentText()
        filtered = []
        for ioc in self.iocs:
            if text and text not in ioc.value.lower() and text not in ioc.ioc_type and text not in ioc.source.lower():
                continue
            if ioc_type != "All" and ioc.ioc_type != ioc_type:
                continue
            if source != "All" and ioc.source != source:
                continue
            filtered.append(ioc)
        self._refresh_ioc_table(filtered)

    def _delete_selected_iocs(self):
        rows = set()
        for item in self.ioc_table.selectedItems():
            rows.add(item.row())
        if not rows:
            QMessageBox.information(self, "Info", "No IOCs selected")
            return
        reply = QMessageBox.question(
            self, "Confirm", f"Delete {len(rows)} selected IOCs?"
        )
        if reply == QMessageBox.Yes:
            text_filter = self.ioc_filter.text().lower()
            ioc_type = self.type_filter.currentText()
            source = self.source_filter.currentText()
            filtered = []
            for ioc in self.iocs:
                if text_filter and text_filter not in ioc.value.lower():
                    continue
                if ioc_type != "All" and ioc.ioc_type != ioc_type:
                    continue
                if source != "All" and ioc.source != source:
                    continue
                filtered.append(ioc)
            data_to_remove = []
            for row in rows:
                if row < len(filtered):
                    data_to_remove.append(filtered[row])
            for ioc in data_to_remove:
                if ioc in self.iocs:
                    self.iocs.remove(ioc)
            self._apply_filter()
            self._update_count_label()
            self.log(f"Deleted {len(rows)} IOCs")

    def _export_selected(self):
        rows = set()
        for item in self.ioc_table.selectedItems():
            rows.add(item.row())
        if not rows:
            QMessageBox.information(self, "Info", "No IOCs selected")
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Selected IOCs", "selected_iocs.json", "JSON Files (*.json)"
        )
        if not file_path:
            return
        selected = []
        for row in rows:
            if row < len(self.iocs):
                selected.append(asdict(self.iocs[row]))
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(selected, f, indent=2)
        self.log(f"Exported {len(selected)} IOCs to {file_path}")

    def _update_count_label(self):
        self.lbl_count.setText(f"IOCs: {len(self.iocs)}")

    def _generate_blocklist(self):
        if not self.iocs:
            QMessageBox.information(
                self, "Info", "No IOCs loaded. Load demo data or import IOCs first."
            )
            return
        config = BlocklistConfig(
            include_ips=self.chk_ips.isChecked(),
            include_domains=self.chk_domains.isChecked(),
            include_urls=self.chk_urls.isChecked(),
            include_hashes=self.chk_hashes.isChecked(),
            min_confidence=self.spin_min_conf.value(),
        )
        fmt = self.blocklist_format.currentText()
        result = BlocklistGenerator.generate(self.iocs, fmt, config)
        self.blocklist_preview.setPlainText(result)
        self.log(f"Generated {fmt} blocklist with {len(self.iocs)} IOCs")

    def _save_blocklist(self):
        content = self.blocklist_preview.toPlainText()
        if not content:
            QMessageBox.information(self, "Info", "Generate a blocklist first")
            return
        fmt = self.blocklist_format.currentText()
        ext_map = {
            "Palo Alto EDL": "txt",
            "FortiGate EBL": "txt",
            "Nginx deny.conf": "conf",
            "iptables": "sh",
            "DNS RPZ": "rpz",
            "Plain Text": "txt",
        }
        ext = ext_map.get(fmt, "txt")
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Blocklist", f"blocklist.{ext}", f"Blocklist (*.{ext})"
        )
        if not file_path:
            return
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        self.log(f"Blocklist saved to {file_path}")
        self.statusBar().showMessage(f"Blocklist saved: {file_path}")

    def _refresh_confidence(self):
        if not self.iocs:
            return
        critical = sum(1 for i in self.iocs if i.confidence >= 90)
        high = sum(1 for i in self.iocs if 70 <= i.confidence < 90)
        medium = sum(1 for i in self.iocs if 50 <= i.confidence < 70)
        low = sum(1 for i in self.iocs if 30 <= i.confidence < 50)
        info = sum(1 for i in self.iocs if i.confidence < 30)
        self._update_stat_card(self.lbl_critical, str(critical))
        self._update_stat_card(self.lbl_high, str(high))
        self._update_stat_card(self.lbl_medium, str(medium))
        self._update_stat_card(self.lbl_low, str(low))
        self._update_stat_card(self.lbl_info, str(info))
        sources = {}
        for ioc in self.iocs:
            if ioc.source not in sources:
                sources[ioc.source] = []
            sources[ioc.source].append(ioc)
        self.conf_table.setRowCount(len(sources))
        for i, (src, iocs_list) in enumerate(sorted(sources.items())):
            avg_conf = sum(x.confidence for x in iocs_list) / len(iocs_list)
            crit_count = sum(1 for x in iocs_list if x.confidence >= 90)
            high_count = sum(1 for x in iocs_list if 70 <= x.confidence < 90)
            self.conf_table.setItem(i, 0, QTableWidgetItem(src))
            self.conf_table.setItem(i, 1, QTableWidgetItem(f"{avg_conf:.1f}"))
            self.conf_table.setItem(i, 2, QTableWidgetItem(str(len(iocs_list))))
            self.conf_table.setItem(i, 3, QTableWidgetItem(str(crit_count)))
            self.conf_table.setItem(i, 4, QTableWidgetItem(str(high_count)))

    def _update_stat_card(self, frame, value):
        lbl = frame.findChild(QLabel, "value_label")
        if lbl:
            lbl.setText(value)

    def _preview_report(self):
        if not self.iocs:
            QMessageBox.information(self, "Info", "No IOCs loaded")
            return
        fmt = self.export_format.currentText()
        if fmt == "JSON":
            self.report_preview.setPlainText(
                json.dumps([asdict(i) for i in self.iocs[:50]], indent=2)
            )
        elif fmt == "CSV":
            lines = [
                "type,value,source,confidence,first_seen,last_seen,tags,threat_type"
            ]
            for ioc in self.iocs[:50]:
                lines.append(
                    f"{ioc.ioc_type},{ioc.value},{ioc.source},{ioc.confidence},"
                    f"{ioc.first_seen},{ioc.last_seen},{'|'.join(ioc.tags)},"
                    f"{ioc.threat_type}"
                )
            self.report_preview.setPlainText("\n".join(lines))
        elif fmt == "HTML":
            html = (
                '<html><head><style>'
                "table{border-collapse:collapse;width:100%}"
                "th,td{border:1px solid #ddd;padding:8px;text-align:left}"
                "th{background-color:#4CAF50;color:white}"
                "tr:nth-child(even){background-color:#f2f2f2}"
                "</style></head><body>"
            )
            html += "<h2>Threat-Intel Report</h2>"
            html += f"<p>Generated: {datetime.now().isoformat()}</p>"
            html += f"<p>Total IOCs: {len(self.iocs)}</p>"
            html += (
                "<table><tr><th>Type</th><th>Value</th><th>Source</th>"
                "<th>Confidence</th><th>Level</th><th>Threat Type</th></tr>"
            )
            for ioc in self.iocs[:50]:
                level, color = ConfidenceCalculator.level(ioc.confidence)
                html += (
                    f'<tr><td>{ioc.ioc_type}</td><td>{ioc.value}</td>'
                    f"<td>{ioc.source}</td>"
                    f'<td style="color:{color.name()}">{ioc.confidence}</td>'
                    f'<td style="color:{color.name()}">{level}</td>'
                    f"<td>{ioc.threat_type}</td></tr>"
                )
            html += "</table></body></html>"
            self.report_preview.setPlainText(html)
        self.log(f"Preview generated ({fmt})")

    def _export_report(self):
        if not self.iocs:
            QMessageBox.information(self, "Info", "No IOCs to export")
            return
        fmt = self.export_format.currentText()
        ext_map = {"JSON": "json", "CSV": "csv", "HTML": "html"}
        ext = ext_map.get(fmt, "txt")
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", f"threat_report.{ext}", f"Report (*.{ext})"
        )
        if not file_path:
            return
        content = self.report_preview.toPlainText()
        if not content:
            self._preview_report()
            content = self.report_preview.toPlainText()
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        self.log(f"Report exported to {file_path}")
        self.statusBar().showMessage(f"Report exported: {file_path}")

    def _refresh_health(self):
        self.health_table.setRowCount(len(self.feeds))
        for i, feed in enumerate(self.feeds):
            self.health_table.setItem(i, 0, QTableWidgetItem(feed.name))
            status_item = QTableWidgetItem(feed.status)
            status_item.setForeground(
                QColor(76, 175, 80) if feed.status == "healthy" else QColor(244, 67, 54)
            )
            self.health_table.setItem(i, 1, status_item)
            self.health_table.setItem(
                i, 2, QTableWidgetItem("99.5%" if feed.status == "healthy" else "0%")
            )
            self.health_table.setItem(i, 3, QTableWidgetItem(str(feed.total_iocs)))
            self.health_table.setItem(
                i, 4, QTableWidgetItem(str(feed.reliability_score))
            )
            self.health_table.setItem(
                i, 5,
                QTableWidgetItem("None" if feed.status == "healthy" else "Connection failed"),
            )

    def _sync_feeds(self):
        self.log("Syncing all feeds...")
        for feed in self.feeds:
            if feed.enabled:
                feed.status = "syncing"
        self._refresh_feed_table()
        QTimer.singleShot(2000, self._finish_sync)

    def _finish_sync(self):
        for feed in self.feeds:
            if feed.status == "syncing":
                feed.status = "healthy"
                feed.last_sync = datetime.now().isoformat()
        self._refresh_feed_table()
        self._refresh_health()
        self.log("Feed sync complete")
        self.statusBar().showMessage("Feed sync complete")

    def _add_feed(self):
        self.feeds.append(
            Feed("New Feed", "custom_csv", "", "", True, 60, "", [], [], 20, "idle", 0)
        )
        self._refresh_feed_table()

    def _remove_feed(self):
        row = self.feed_table.currentRow()
        if row >= 0 and row < len(self.feeds):
            reply = QMessageBox.question(
                self, "Confirm", f"Remove feed '{self.feeds[row].name}'?"
            )
            if reply == QMessageBox.Yes:
                self.feeds.pop(row)
                self._refresh_feed_table()

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.append(f"[{timestamp}] {message}")


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, QColor(42, 42, 42))
    palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ToolTipBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ToolTipText, Qt.white)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(palette)
    app.setStyleSheet("""
        QTabWidget::pane { border: 1px solid #555; }
        QTabBar::tab { background: #3a3a3a; color: #ccc; padding: 8px 16px; border: 1px solid #555; }
        QTabBar::tab:selected { background: #4a4a4a; color: white; }
        QTableWidget { gridline-color: #555; alternate-background-color: #3a3a3a; }
        QHeaderView::section { background-color: #3a3a3a; color: white; padding: 4px; border: 1px solid #555; }
        QGroupBox { border: 1px solid #555; margin-top: 10px; padding-top: 10px; color: white; }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
        QPushButton { padding: 6px 12px; }
        QLineEdit, QComboBox, QSpinBox { padding: 4px; }
        QProgressBar { border: 1px solid #555; text-align: center; }
        QProgressBar::chunk { background-color: #4CAF50; }
    """)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
