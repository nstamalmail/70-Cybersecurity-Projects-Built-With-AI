"""
Endpoint Hardening & Compliance Checker (CIS Benchmark Automation)
Complete PySide6 GUI Application
"""

import sys
import os
import json
import csv
import time
import random
import hashlib
import platform
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QTabWidget, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QComboBox, QGroupBox, QFrame, QTextEdit,
    QFileDialog, QMessageBox, QDialog, QDialogButtonBox, QLineEdit,
    QFormLayout, QHeaderView, QProgressBar, QSplitter, QSizePolicy,
    QScrollArea, QSpinBox, QCheckBox, QAbstractItemView, QStatusBar
)
from PySide6.QtCore import Qt, QTimer, Signal, Slot, QSize, QThread
from PySide6.QtGui import (
    QPainter, QColor, QFont, QPen, QBrush, QLinearGradient,
    QPixmap, QIcon, QAction, QPalette, QFontMetrics
)

# ─── Circular Gauge Widget ─────────────────────────────────────────────────────

class CircularGauge(QWidget):
    """Circular gauge widget showing compliance score 0-100."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._score = 0
        self._target = 0
        self._animated = False
        self.setMinimumSize(220, 220)
        self.setMaximumSize(260, 260)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._animate)

    def set_score(self, value: int):
        self._score = max(0, min(100, value))
        self._target = self._score
        self._animated = True
        self._timer.start(16)
        self.update()

    def _animate(self):
        if abs(self._score - self._target) < 1:
            self._score = self._target
            self._timer.stop()
            self._animated = False
        self.update()

    def paintEvent(self, event):
        w, h = self.width(), self.height()
        size = min(w, h) - 20
        cx, cy = w / 2, h / 2
        radius = size / 2

        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        # Background arc
        bg_pen = QPen(QColor(60, 60, 60), 14, Qt.SolidLine, Qt.RoundCap)
        p.setPen(bg_pen)
        p.drawArc(
            int(cx - radius), int(cy - radius),
            int(size), int(size),
            225 * 16, -270 * 16
        )

        # Score arc
        score_pen = QPen(self._score_color(), 14, Qt.SolidLine, Qt.RoundCap)
        p.setPen(score_pen)
        span = int(-270 * (self._score / 100) * 16)
        p.drawArc(
            int(cx - radius), int(cy - radius),
            int(size), int(size),
            225 * 16, span
        )

        # Center text
        p.setPen(QColor(255, 255, 255))
        font = QFont("Segoe UI", max(28, int(radius / 3)), QFont.Bold)
        p.setFont(font)
        p.drawText(
            int(cx - radius), int(cy - radius),
            int(size), int(size),
            Qt.AlignCenter, f"{int(self._score)}%"
        )

        # Label
        small_font = QFont("Segoe UI", max(9, int(radius / 8)))
        p.setFont(small_font)
        p.setPen(QColor(180, 180, 180))
        p.drawText(
            int(cx - radius), int(cy + radius * 0.35),
            int(size), int(size * 0.4),
            Qt.AlignHCenter | Qt.AlignTop, "COMPLIANCE"
        )
        p.end()

    def _score_color(self):
        if self._score >= 80:
            return QColor(0, 200, 100)
        elif self._score >= 50:
            return QColor(255, 180, 0)
        return QColor(255, 60, 60)


# ─── Sample Data Generator ─────────────────────────────────────────────────────

CATEGORIES = {
    "1 - Identity and Access Management": [
        ("1.1.1", "Ensure password complexity requirements are enforced", "password must meet complexity requirements", "1", "1", True, "net accounts", "net accounts /pwreq:8 yes"),
        ("1.1.2", "Ensure minimum password age is 1+ day(s)", "minimum password age", "1", "1", True, "net accounts", "net accounts /minpwage:1"),
        ("1.1.3", "Ensure maximum password age is 60 or fewer day(s)", "maximum password age", "60", "60", False, "net accounts", "net accounts /maxpwage:60"),
        ("1.1.4", "Ensure 'Enforce password history' is set to 24", "enforce password history", "24", "24", True, "net accounts", "net accounts /uniquepw:24"),
        ("1.1.5", "Ensure reversible password encryption is Disabled", "reversible password encryption", "Disabled", "Disabled", True, "secedit /export", "secedit /export /cfg secpol.cfg"),
        ("1.2.1", "Ensure 'Account lockout threshold' is set to 5", "account lockout threshold", "5", "5", True, "net accounts", "net accounts /lockoutthreshold:5"),
        ("1.2.2", "Ensure 'Account lockout duration' is 15+ minutes", "account lockout duration", "15", "15", False, "net accounts", "net accounts /lockoutduration:15"),
        ("1.3.1", "Ensure 'Guest account status' is set to Disabled", "guest account status", "Disabled", "Disabled", True, "net user Guest", "net user Guest /active:no"),
        ("1.4.1", "Ensure 'Rename built-in Administrator account'", "renamed administrator", "True", "True", False, "wmic useraccount", "wmic useraccount where name='Administrator' rename Admin"),
        ("1.5.1", "Ensure 'Debug programs' right is not granted", "debug programs", "No One", "No One", True, "secedit /export", "secedit /export /cfg secpol.cfg"),
        ("1.6.1", "Ensure 'Create a token object' is not granted", "create token object", "No One", "No One", True, "secedit /export", "secedit /export /cfg secpol.cfg"),
        ("1.7.1", "Ensure 'Replace a process level token' is not granted", "replace process level token", "No One", "No One", True, "secedit /export", "secedit /export /cfg secpol.cfg"),
        ("1.8.1", "Ensure 'Create global objects' is not granted", "create global objects", "No One", "No One", True, "secedit /export", "secedit /export /cfg secpol.cfg"),
    ],
    "2 - Audit Policy": [
        ("2.1.1", "Ensure 'Audit credential validation' is enabled", "credential validation auditing", "Success and Failure", "Success and Failure", True, "auditpol /get", "auditpol /set /subcategory:'Credential Validation' /success:enable /failure:enable"),
        ("2.1.2", "Ensure 'Audit logon events' is enabled", "logon events auditing", "Success and Failure", "Success and Failure", False, "auditpol /get", "auditpol /set /subcategory:'Logon' /success:enable /failure:enable"),
        ("2.1.3", "Ensure 'Audit privilege use' is enabled", "privilege use auditing", "Failure", "Failure", True, "auditpol /get", "auditpol /set /subcategory:'Sensitive Privilege Use' /failure:enable"),
        ("2.1.4", "Ensure 'Audit policy change' is enabled", "policy change auditing", "Success", "Success", False, "auditpol /get", "auditpol /set /subcategory:'Audit Policy Change' /success:enable"),
        ("2.1.5", "Ensure 'Audit account management' is enabled", "account management auditing", "Success and Failure", "Success and Failure", True, "auditpol /get", "auditpol /set /subcategory:'User Account Management' /success:enable /failure:enable"),
        ("2.1.6", "Ensure 'Audit process tracking' is enabled", "process tracking auditing", "Success", "Success", True, "auditpol /get", "auditpol /set /subcategory:'Process Creation' /success:enable"),
        ("2.1.7", "Ensure 'Audit object access' is enabled", "object access auditing", "Success and Failure", "Success and Failure", False, "auditpol /get", "auditpol /set /subcategory:'File System' /success:enable /failure:enable"),
    ],
    "3 - Windows Firewall": [
        ("3.1.1", "Ensure Windows Defender Firewall is enabled", "firewall status", "On", "On", True, "netsh advfirewall show allprofiles", "netsh advfirewall set allprofiles state on"),
        ("3.1.2", "Ensure Firewall inbound rules - Block all by default", "default inbound action", "Block", "Block", False, "netsh advfirewall", "netsh advfirewall set allprofiles firewallpolicy blockinbound"),
        ("3.1.3", "Ensure Firewall outbound rules - Allow all by default", "default outbound action", "Allow", "Allow", True, "netsh advfirewall", "netsh advfirewall set allprofiles firewallpolicy allowoutbound"),
        ("3.1.4", "Ensure Firewall logging: Log dropped packets", "logging dropped", "Yes", "Yes", True, "netsh advfirewall", "netsh advfirewall set allprofiles logging droppedconnections enable"),
        ("3.1.5", "Ensure Firewall logging: Log successful connections", "logging allowed", "Yes", "Yes", False, "netsh advfirewall", "netsh advfirewall set allprofiles logging allowedconnections enable"),
        ("3.2.1", "Ensure 'Allow ICMP Redirect' is disabled", "icmp redirect", "Disabled", "Disabled", True, "Registry check", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v EnableICMPRedirect /t REG_DWORD /d 0 /f"),
    ],
    "4 - Windows Update": [
        ("4.1.1", "Ensure 'Configure Automatic Updates' is enabled", "automatic updates", "4 - Auto download and schedule install", "4", True, "reg query", "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v AUOptions /t REG_DWORD /d 4 /f"),
        ("4.1.2", "Ensure 'No auto-restart with logged on users' is disabled", "no auto restart", "Disabled", "Disabled", False, "reg query", "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 0 /f"),
        ("4.1.3", "Ensure 'Specify intranet Microsoft update service location'", "intranet update service", "Configured", "Configured", True, "reg query", "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate /v WUServer /t REG_SZ /d http://wsus.local:8530 /f"),
        ("4.1.4", "Ensure Windows Update service is running", "wuaserv service", "Running", "Running", True, "sc query wuauserv", "sc config wuauserv start= auto && sc start wuauserv"),
        ("4.2.1", "Ensure 'Turn off Microsoft Defender Antivirus' is disabled", "defender disabled", "Disabled", "Disabled", True, "reg query", "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender /v DisableAntiSpyware /t REG_DWORD /d 0 /f"),
        ("4.2.2", "Ensure 'Real-time Protection' is enabled", "real-time protection", "Enabled", "Enabled", True, "Get-MpPreference", "Set-MpPreference -DisableRealtimeMonitoring 0"),
    ],
    "5 - Account Policies": [
        ("5.1.1", "Ensure 'Enforce user account control' is enabled", "uac enabled", "1", "1", True, "reg query", "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f"),
        ("5.1.2", "Ensure 'Admin Approval Mode for Built-in Admin' is enabled", "admin approval mode", "1", "1", False, "reg query", "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v FilterAdministratorToken /t REG_DWORD /d 1 /f"),
        ("5.1.3", "Ensure 'UAC - Allow UIAccess apps to prompt' is disabled", "uiaccess prompt", "Disabled", "Disabled", True, "reg query", "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableSecureUIAPaths /t REG_DWORD /d 1 /f"),
        ("5.1.4", "Ensure 'Detect application installations' is enabled", "detect app installs", "Enabled", "Enabled", False, "reg query", "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f"),
        ("5.2.1", "Ensure 'Turn off BITS' is not enabled", "bits enabled", "Enabled", "Enabled", True, "sc query bits", "sc config bits start= auto"),
        ("5.2.2", "Ensure 'Remote Desktop Services' is disabled if not needed", "rdp service", "Disabled", "Disabled", True, "sc query TermService", "sc config TermService start= disabled"),
    ],
    "6 - Security Options": [
        ("6.1.1", "Ensure 'Interactive logon: Machine inactivity limit' is 900", "inactivity limit", "900", "900", True, "reg query", "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f"),
        ("6.1.2", "Ensure 'Smart card removal action' is set to Lock", "smart card removal", "Lock", "Lock", False, "reg query", "reg add HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon /v ScRemoveOption /t REG_SZ /d 1 /f"),
        ("6.1.3", "Ensure 'Machine account password age' is 30 or fewer", "machine acct password", "30", "30", True, "net accounts", "net accounts /maxpwage:30"),
        ("6.2.1", "Ensure 'Network security: LAN Manager auth level' is NTLMv2", "lm auth level", "NTLMv2 only", "NTLMv2 only", True, "reg query", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LmCompatibilityLevel /t REG_DWORD /d 5 /f"),
        ("6.2.2", "Ensure 'Network security: Minimum session security for NTLM' is enabled", "ntlm session security", "Enabled", "Enabled", False, "reg query", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0 /v NTLMMinServerSec /t REG_DWORD /d 536870912 /f"),
        ("6.2.3", "Ensure 'Network security: LDAP client signing requirements' is Negotiate", "ldap client signing", "Negotiate", "Negotiate", True, "reg query", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\LDAP\\RequireSigned /t REG_DWORD /d 1 /f"),
    ],
    "7 - Remote Access": [
        ("7.1.1", "Ensure 'Remote Desktop Protocol (RDP)' is disabled or restricted", "rdp status", "Disabled", "Disabled", True, "reg query", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 1 /f"),
        ("7.1.2", "Ensure 'Set client connection encryption level' is High", "rdp encryption", "High", "High", False, "reg query", "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services /v MinEncryptionLevel /t REG_DWORD /d 3 /f"),
        ("7.1.3", "Ensure 'Require NLA for RDP' is enabled", "nla required", "Enabled", "Enabled", True, "reg query", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp /v UserAuthentication /t REG_DWORD /d 1 /f"),
        ("7.1.4", "Ensure 'RDP session timeout' is 15 or fewer minutes", "rdp timeout", "15", "15", False, "reg query", "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services /v MaxIdleTime /t REG_DWORD /d 900000 /f"),
        ("7.2.1", "Ensure 'WinRM Service' is disabled if not used", "winrm service", "Disabled", "Disabled", True, "sc query WinRM", "sc config WinRM start= disabled"),
        ("7.2.2", "Ensure 'Windows Remote Management firewall exception' is disabled", "winrm firewall", "Disabled", "Disabled", False, "netsh advfirewall", "netsh advfirewall firewall set rule name='Windows Remote Management (HTTP-In)' new enable=no"),
    ],
    "8 - Logging and Monitoring": [
        ("8.1.1", "Ensure 'Event log size' for Application is 16384 KB+", "app log size", "16384", "16384", True, "wevtutil", "wevtutil sl Application /ms:16384000"),
        ("8.1.2", "Ensure 'Event log size' for Security is 16384 KB+", "security log size", "16384", "16384", False, "wevtutil", "wevtutil sl Security /ms:16384000"),
        ("8.1.3", "Ensure 'Event log size' for System is 16384 KB+", "system log size", "16384", "16384", True, "wevtutil", "wevtutil sl System /ms:16384000"),
        ("8.1.4", "Ensure 'Audit: Shut down system immediately if unable to log' is Disabled", "audit shutdown", "Disabled", "Disabled", True, "reg query", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v CrashOnAuditFail /t REG_DWORD /d 0 /f"),
        ("8.2.1", "Ensure 'Process creation and command line logging' is enabled", "cmd line logging", "Enabled", "Enabled", False, "reg query", "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit /v ProcessCreationIncludeCmdLineEnabled /t REG_DWORD /d 1 /f"),
        ("8.2.2", "Ensure 'PowerShell Script Block Logging' is enabled", "ps script block", "Enabled", "Enabled", True, "reg query", "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f"),
    ],
    "9 - Software Restrictions": [
        ("9.1.1", "Ensure 'Windows Installer' is set to 'Bypass' for admins", "installer bypass", "Bypass", "Bypass", True, "reg query", "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v EnableUserControl /t REG_DWORD /d 1 /f"),
        ("9.1.2", "Ensure 'AppLocker' rules are configured", "applocker", "Configured", "Configured", False, "Get-AppLockerPolicy", "New-AppLockerPolicy -RuleType Publisher,Hash,Path -User Everyone"),
        ("9.1.3", "Ensure 'WDAC' (Windows Defender Application Control) is enabled", "wdac", "Enabled", "Enabled", True, "Get-CimInstance", "Invoke-CimMethod -Namespace root/Microsoft/Windows/CI -ClassName MSFT_WDACSIPolicy -MethodName Apply"),
    ],
    "10 - Additional Hardening": [
        ("10.1.1", "Ensure 'Autorun/Autoplay' is disabled for all drives", "autoplay disabled", "Disabled", "Disabled", True, "reg query", "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f"),
        ("10.1.2", "Ensure 'Windows PowerShell' execution policy is Restricted", "ps exec policy", "Restricted", "Restricted", False, "Get-ExecutionPolicy", "Set-ExecutionPolicy -ExecutionPolicy Restricted -Force"),
        ("10.1.3", "Ensure 'Windows PowerShell 2.0' is removed", "ps2 removed", "Removed", "Removed", True, "OptionalFeatures", "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart"),
        ("10.1.4", "Ensure 'SMBv1 protocol' is disabled", "smbv1 disabled", "Disabled", "Disabled", False, "Get-SmbServerConfiguration", "Set-SmbServerConfiguration -EnableSMB1Protocol 0 -Force"),
        ("10.1.5", "Ensure 'LLMNR' is disabled via Group Policy", "llmnr disabled", "Disabled", "Disabled", True, "reg query", "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient /v EnableMulticast /t REG_DWORD /d 0 /f"),
        ("10.1.6", "Ensure 'NetBIOS over TCP/IP' is disabled", "netbios disabled", "Disabled", "Disabled", False, "Get-NetAdapter", "Set-NetAdapterProtocol -NetAdapterID * -NetbiosProtocol Disabled"),
    ],
}


def generate_demo_findings(benchmark: str = "CIS Windows 11 v3.0"):
    """Generate 50+ CIS control findings with pass/fail status."""
    findings = []
    finding_id = 1
    for category, controls in CATEGORIES.items():
        for ctrl_id, title, param, expected, actual, passed, check_cmd, remediation in controls:
            severity = random.choice(["Critical", "High", "Medium", "Low"]) if not passed else "Informational"
            findings.append({
                "finding_id": finding_id,
                "control_id": ctrl_id,
                "title": title,
                "category": category,
                "param_name": param,
                "expected_value": expected,
                "actual_value": actual,
                "status": "Pass" if passed else "Fail",
                "severity": severity,
                "check_command": check_cmd,
                "remediation": remediation,
                "description": f"Control {ctrl_id} check: {title}. Expected '{expected}', found '{actual}'.",
                "benchmark": benchmark,
                "timestamp": datetime.now().isoformat(),
            })
            finding_id += 1
    return findings


def generate_history_data(finding_count: int = 58):
    """Generate historical trend data."""
    history = []
    base_score = 55
    for i in range(12):
        dt = datetime.now() - timedelta(days=30 * (11 - i))
        score = min(100, max(30, base_score + random.randint(-8, 12) + i * 3))
        passed = int(finding_count * score / 100)
        history.append({
            "date": dt.strftime("%Y-%m-%d"),
            "score": score,
            "passed": passed,
            "failed": finding_count - passed,
            "total": finding_count,
            "benchmark": "CIS Windows 11 v3.0",
            "host": "DESKTOP-TEST01",
        })
    return history


# ─── Exceptions Manager Dialog ─────────────────────────────────────────────────

class ExceptionDialog(QDialog):
    def __init__(self, exceptions: list, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Exceptions Manager")
        self.setMinimumSize(600, 400)
        self.exceptions = list(exceptions)
        layout = QVBoxLayout(self)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Control ID", "Reason", "Expiry Date", "Approved By"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)

        btn_row = QHBoxLayout()
        self.btn_add = QPushButton("+ Add Exception")
        self.btn_add.clicked.connect(self._add)
        self.btn_remove = QPushButton("- Remove Selected")
        self.btn_remove.clicked.connect(self._remove)
        btn_row.addWidget(self.btn_add)
        btn_row.addWidget(self.btn_remove)
        layout.addLayout(btn_row)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._refresh()

    def _refresh(self):
        self.table.setRowCount(len(self.exceptions))
        for i, ex in enumerate(self.exceptions):
            self.table.setItem(i, 0, QTableWidgetItem(ex.get("control_id", "")))
            self.table.setItem(i, 1, QTableWidgetItem(ex.get("reason", "")))
            self.table.setItem(i, 2, QTableWidgetItem(ex.get("expiry", "")))
            self.table.setItem(i, 3, QTableWidgetItem(ex.get("approved_by", "")))

    def _add(self):
        self.exceptions.append({"control_id": "NEW-001", "reason": "", "expiry": "", "approved_by": ""})
        self._refresh()

    def _remove(self):
        row = self.table.currentRow()
        if 0 <= row < len(self.exceptions):
            self.exceptions.pop(row)
            self._refresh()

    def get_exceptions(self):
        return self.exceptions


# ─── Remediation Script Generator ──────────────────────────────────────────────

def generate_powershell_script(findings: list, exceptions: list) -> str:
    """Generate PowerShell remediation script for failed controls."""
    excepted_ids = {e.get("control_id") for e in exceptions}
    lines = [
        "# " + "=" * 70,
        "# CIS Benchmark Remediation Script",
        f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "# " + "=" * 70,
        "",
        "#Requires -RunAsAdministrator",
        "",
        "param(",
        '    [switch]$WhatIf = $true,',
        '    [string]$LogFile = "$env:USERPROFILE\\remediation_log.txt"',
        ")",
        "",
        "$ErrorActionPreference = 'Continue'",
        "$remediationCount = 0",
        "$successCount = 0",
        "$failCount = 0",
        "",
        "function Write-Log {",
        "    param([string]$Message, [string]$Level = 'INFO')",
        "    $entry = \"[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message\"",
        "    Write-Host $entry -ForegroundColor $(switch($Level){'ERROR'{1}'WARNING'{3}'SUCCESS'{2}default{7}})",
        "    Add-Content -Path $LogFile -Value $entry",
        "}",
        "",
        "Write-Host 'CIS Benchmark Remediation Script' -ForegroundColor Cyan",
        "Write-Host ('=' * 70) -ForegroundColor DarkGray",
        "Write-Log 'Remediation started'",
        "",
    ]

    failed = [f for f in findings if f["status"] == "Fail" and f["control_id"] not in excepted_ids]

    for f in failed:
        cid = f["control_id"]
        title = f["title"]
        rem = f.get("remediation", "")
        lines.append(f"# --- Control {cid}: {title} ---")
        lines.append(f"Write-Host 'Remediating {cid}: {title}'")
        if rem:
            lines.append(f"Write-Log 'Applying {cid}'")
            if rem.startswith("reg "):
                lines.append(f"if ($WhatIf) {{ Write-Host '  [WhatIf] Would execute: {rem}' }}")
                lines.append(f"else {{ Write-Log 'Running: {rem}' }}")
                lines.append(f"")
            elif rem.startswith("netsh"):
                lines.append(f"if ($WhatIf) {{ Write-Host '  [WhatIf] Would execute: {rem}' }}")
                lines.append(f"else {{ Write-Log 'Running: {rem}' }}")
            elif rem.startswith("auditpol"):
                lines.append(f"if ($WhatIf) {{ Write-Host '  [WhatIf] Would execute: {rem}' }}")
                lines.append(f"else {{ Write-Log 'Running: {rem}' }}")
            elif rem.startswith("Set-"):
                lines.append(f"if ($WhatIf) {{ Write-Host '  [WhatIf] Would execute: {rem}' }}")
                lines.append(f"else {{ Write-Log 'Running: {rem}' }}")
            else:
                lines.append(f"if ($WhatIf) {{ Write-Host '  [WhatIf] Would execute: {rem}' }}")
                lines.append(f"else {{ Write-Log 'Running: {rem}' }}")
            lines.append(f"$remediationCount++")
            lines.append("")
        lines.append("")

    lines.extend([
        "",
        "# Summary",
        "Write-Host '' -ForegroundColor Cyan",
        "Write-Host ('=' * 70) -ForegroundColor DarkGray",
        "Write-Host ('Remediation complete. Total actions: {0}' -f $remediationCount) -ForegroundColor Cyan",
        "Write-Host ('Review log at: {0}' -f $LogFile)",
        "Write-Host ''",
        "Write-Host 'IMPORTANT: Run without -WhatIf to apply changes.' -ForegroundColor Yellow",
        "",
    ])
    return "\n".join(lines)


def generate_bash_script(findings: list, exceptions: list) -> str:
    """Generate bash remediation script for Linux systems."""
    excepted_ids = {e.get("control_id") for e in exceptions}
    lines = [
        "#!/bin/bash",
        "# " + "=" * 70,
        "# CIS Benchmark Remediation Script (Linux/Ubuntu)",
        f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "# " + "=" * 70,
        "",
        "set -euo pipefail",
        "",
        "LOGFILE=\"/var/log/cis_remediation.log\"",
        "WHATIF=true",
        "",
        "if [[ \"$1\" == \"--apply\" ]]; then",
        "    WHATIF=false",
        "fi",
        "",
        "log() {",
        "    echo \"[$(date '+%Y-%m-%d %H:%M:%S')] $1\" | tee -a \"$LOGFILE\"",
        "}",
        "",
        "log 'CIS Benchmark Remediation Script Started'",
        "",
    ]

    linux_remediations = {
        "1.1.1": "# Ensure password complexity\nsed -i 's/pam_pwquality.so.*/pam_pwquality.so retry=3 minlen=14/' /etc/pam.d/common-password",
        "1.1.4": "# Ensure password history\nsed -i 's/pam_unix.so.*/pam_unix.so remember=24/' /etc/pam.d/common-password",
        "2.1.1": "# Ensure audit rules enabled\nsystemctl enable auditd && systemctl start auditd",
        "3.1.1": "# Ensure UFW is enabled\nufw enable && ufw default deny incoming && ufw default allow outgoing",
        "4.1.1": "# Ensure unattended-upgrades enabled\napt-get install -y unattended-upgrades\ndpkg-reconfigure -plow unattended-upgrades",
        "5.1.1": "# Ensure UAC equivalent - sudo requirement\necho 'Defaults use_pty' >> /etc/sudoers.d/cis",
        "6.1.1": "# Ensure session timeout\nsed -i 's/TMOUT=.*/TMOUT=900/' /etc/profile.d/cis_timeout.sh\necho 'TMOUT=900' >> /etc/profile.d/cis_timeout.sh",
        "7.1.1": "# Disable SSH root login\nsed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
        "8.1.1": "# Ensure logging configured\nsystemctl enable rsyslog && systemctl start rsyslog",
        "9.1.1": "# Ensure AppArmor enabled\nsystemctl enable apparmor && systemctl start apparmor",
        "10.1.1": "# Disable USB storage\necho 'install usb-storage /bin/true' > /etc/modprobe.d/cis_usb.conf",
    }

    for ctrl_id in linux_remediations:
        lines.append(f"# --- Control {ctrl_id} ---")
        lines.append(f"log 'Applying control {ctrl_id}'")
        lines.append(f"if $WHATIF; then echo '  [WhatIf] Would apply control {ctrl_id}'; fi")
        lines.append(linux_remediations[ctrl_id])
        lines.append("")

    lines.extend([
        "",
        "log 'Remediation complete'",
        "",
    ])
    return "\n".join(lines)


# ─── Report Generator ──────────────────────────────────────────────────────────

def generate_html_report(findings: list, score: int, benchmark: str, history: list) -> str:
    passed = sum(1 for f in findings if f["status"] == "Pass")
    failed = sum(1 for f in findings if f["status"] == "Fail")
    cat_counts = {}
    for f in findings:
        cat = f["category"].split(" - ", 1)[-1]
        cat_counts.setdefault(cat, {"pass": 0, "fail": 0})
        cat_counts[cat]["pass" if f["status"] == "Pass" else "fail"] += 1

    categories_html = ""
    for cat, c in cat_counts.items():
        total = c["pass"] + c["fail"]
        pct = int(c["pass"] / total * 100) if total else 0
        color = "#00c864" if pct >= 80 else "#ffb400" if pct >= 50 else "#ff3c3c"
        categories_html += f"""
        <div style="margin:8px 0">
            <div style="display:flex;justify-content:space-between">
                <span>{cat}</span><span>{pct}% ({c['pass']}/{total})</span>
            </div>
            <div style="background:#2a2a2a;border-radius:6px;height:12px;margin-top:4px">
                <div style="background:{color};width:{pct}%;height:12px;border-radius:6px"></div>
            </div>
        </div>"""

    findings_rows = ""
    for f in findings:
        badge = '<span style="color:#00c864;font-weight:bold">PASS</span>' if f["status"] == "Pass" else '<span style="color:#ff3c3c;font-weight:bold">FAIL</span>'
        sev_color = {"Critical": "#ff3c3c", "High": "#ff8c00", "Medium": "#ffb400", "Low": "#6ec6ff", "Informational": "#888"}.get(f["severity"], "#888")
        findings_rows += f"""<tr>
            <td>{f['control_id']}</td>
            <td>{f['title']}</td>
            <td>{badge}</td>
            <td><span style="color:{sev_color}">{f['severity']}</span></td>
            <td>{f['expected_value']}</td>
            <td>{f['actual_value']}</td>
            <td><code>{f['remediation']}</code></td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CIS Compliance Report</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #e0e0e0; margin: 40px; }}
h1, h2 {{ color: #00c8ff; border-bottom: 2px solid #333; padding-bottom: 8px; }}
table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
th {{ background: #16213e; padding: 10px; text-align: left; border: 1px solid #333; }}
td {{ padding: 8px 10px; border: 1px solid #333; }}
tr:nth-child(even) {{ background: #16213e; }}
.score-badge {{ font-size: 48px; font-weight: bold; color: {'#00c864' if score>=80 else '#ffb400' if score>=50 else '#ff3c3c'}; }}
.meta {{ color: #888; font-size: 14px; }}
code {{ background: #2a2a2a; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
</style></head><body>
<h1>CIS Benchmark Compliance Report</h1>
<div class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Benchmark: {benchmark}</div>
<div class="meta">System: {platform.node()} | OS: {platform.platform()}</div>
<div style="text-align:center;margin:30px 0">
    <div class="score-badge">{score}%</div>
    <div>Overall Compliance Score</div>
    <div class="meta">{passed} Passed / {failed} Failed / {len(findings)} Total</div>
</div>
<h2>Category Breakdown</h2>{categories_html}
<h2>Detailed Findings</h2>
<table><tr><th>ID</th><th>Title</th><th>Status</th><th>Severity</th><th>Expected</th><th>Actual</th><th>Remediation</th></tr>
{findings_rows}</table>
<h2>History Trend</h2>
<table><tr><th>Date</th><th>Score</th><th>Passed</th><th>Failed</th></tr>
{"".join(f'<tr><td>{h["date"]}</td><td>{h["score"]}%</td><td>{h["passed"]}</td><td>{h["failed"]}</td></tr>' for h in history)}
</table>
</body></html>"""


# ─── Main Window ────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CIS Benchmark Compliance Checker")
        self.setMinimumSize(1100, 700)
        self._findings = []
        self._exceptions = []
        self._history = []
        self._benchmark = "CIS Windows 11 v3.0"
        self._setup_ui()
        self.statusBar().showMessage("Ready | Load demo data or import a benchmark to begin")

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(8, 8, 8, 8)

        # Top toolbar
        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("Benchmark:"))
        self.combo_benchmark = QComboBox()
        self.combo_benchmark.addItems([
            "CIS Windows 11 v3.0", "CIS Windows Server 2022 v2.0",
            "CIS Ubuntu 22.04 LTS v1.0", "CIS RHEL 9 v1.0"
        ])
        self.combo_benchmark.currentTextChanged.connect(self._on_benchmark_change)
        toolbar.addWidget(self.combo_benchmark)
        toolbar.addSpacing(12)
        toolbar.addWidget(QLabel("Target:"))
        self.combo_target = QComboBox()
        self.combo_target.addItems(["Local System", "Remote - Windows", "Remote - Linux"])
        toolbar.addWidget(self.combo_target)
        toolbar.addStretch()
        self.btn_demo = QPushButton("Load Demo Data")
        self.btn_demo.setStyleSheet("QPushButton{background:#0066cc;color:white;padding:6px 14px;border-radius:4px;font-weight:bold}QPushButton:hover{background:#0088ff}")
        self.btn_demo.clicked.connect(self._load_demo)
        toolbar.addWidget(self.btn_demo)
        self.btn_import = QPushButton("Import Benchmark")
        self.btn_import.setStyleSheet("QPushButton{background:#333;color:white;padding:6px 14px;border-radius:4px}QPushButton:hover{background:#444}")
        self.btn_import.clicked.connect(self._import_benchmark)
        toolbar.addWidget(self.btn_import)
        main_layout.addLayout(toolbar)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.North)
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #444; background: #1e1e2e; }
            QTabBar::tab { background: #2a2a3e; color: #aaa; padding: 8px 16px; margin: 1px; border-radius: 4px 4px 0 0; }
            QTabBar::tab:selected { background: #0066cc; color: white; }
            QTabBar::tab:hover { background: #333355; }
        """)
        main_layout.addWidget(self.tabs)

        # ── Tab 1: Dashboard ──
        dash_tab = QWidget()
        dash_layout = QVBoxLayout(dash_tab)
        splitter = QSplitter(Qt.Horizontal)
        left = QWidget()
        left_l = QVBoxLayout(left)
        left_l.addWidget(QLabel("Compliance Score"))
        self.gauge = CircularGauge()
        left_l.addWidget(self.gauge, alignment=Qt.AlignCenter)
        left_l.addSpacing(10)

        self.lbl_passed = QLabel("Passed: 0")
        self.lbl_passed.setStyleSheet("color:#00c864;font-size:16px;font-weight:bold")
        self.lbl_failed = QLabel("Failed: 0")
        self.lbl_failed.setStyleSheet("color:#ff3c3c;font-size:16px;font-weight:bold")
        self.lbl_total = QLabel("Total: 0")
        self.lbl_total.setStyleSheet("color:#aaa;font-size:14px")
        left_l.addWidget(self.lbl_passed)
        left_l.addWidget(self.lbl_failed)
        left_l.addWidget(self.lbl_total)
        left_l.addSpacing(10)
        btn_row = QHBoxLayout()
        self.btn_scan = QPushButton("Run Assessment")
        self.btn_scan.setStyleSheet("QPushButton{background:#00aa44;color:white;padding:8px;border-radius:4px;font-weight:bold}QPushButton:hover{background:#00cc55}")
        self.btn_scan.clicked.connect(self._run_assessment)
        btn_row.addWidget(self.btn_scan)
        self.btn_exceptions = QPushButton("Exceptions")
        self.btn_exceptions.clicked.connect(self._manage_exceptions)
        btn_row.addWidget(self.btn_exceptions)
        left_l.addLayout(btn_row)
        left_l.addStretch()
        splitter.addWidget(left)

        # Right: category breakdown
        right = QWidget()
        right_l = QVBoxLayout(right)
        right_l.addWidget(QLabel("Category Compliance"))
        self.cat_table = QTableWidget()
        self.cat_table.setColumnCount(3)
        self.cat_table.setHorizontalHeaderLabels(["Category", "Compliance %", "Status"])
        self.cat_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.cat_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.cat_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        right_l.addWidget(self.cat_table)
        right_l.addWidget(QLabel("Recent Findings"))
        self.recent_table = QTableWidget()
        self.recent_table.setColumnCount(4)
        self.recent_table.setHorizontalHeaderLabels(["ID", "Title", "Status", "Severity"])
        self.recent_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.recent_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.recent_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.recent_table.doubleClicked.connect(self._show_finding_detail)
        right_l.addWidget(self.recent_table)
        splitter.addWidget(right)
        splitter.setSizes([280, 720])
        dash_layout.addWidget(splitter)
        self.tabs.addTab(dash_tab, "Dashboard")

        # ── Tab 2: Findings Detail ──
        findings_tab = QWidget()
        fl = QVBoxLayout(findings_tab)
        self.findings_filter = QComboBox()
        self.findings_filter.addItems(["All", "Pass", "Fail", "Critical", "High", "Medium", "Low"])
        self.findings_filter.currentTextChanged.connect(self._filter_findings)
        fl.addWidget(QLabel("Filter:"))
        fl.addWidget(self.findings_filter)
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(8)
        self.findings_table.setHorizontalHeaderLabels([
            "Control ID", "Title", "Status", "Severity",
            "Expected", "Current", "Check Command", "Remediation"
        ])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.findings_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.findings_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.findings_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.findings_table.doubleClicked.connect(self._show_finding_detail)
        fl.addWidget(self.findings_table)
        btn_row2 = QHBoxLayout()
        self.btn_detail = QPushButton("View Detail")
        self.btn_detail.clicked.connect(self._show_finding_detail)
        btn_row2.addWidget(self.btn_detail)
        self.btn_apply = QPushButton("Apply Remediation for Selected")
        self.btn_apply.setStyleSheet("QPushButton{background:#00aa44;color:white;padding:6px;border-radius:4px}QPushButton:hover{background:#00cc55}")
        self.btn_apply.clicked.connect(self._apply_remediation)
        btn_row2.addWidget(self.btn_apply)
        fl.addLayout(btn_row2)
        self.tabs.addTab(findings_tab, "Findings")

        # ── Tab 3: Remediation Guide ──
        remed_tab = QWidget()
        rl = QVBoxLayout(remed_tab)
        rl.addWidget(QLabel("Remediation Scripts"))
        btn_row3 = QHBoxLayout()
        btn_gen_ps = QPushButton("Generate PowerShell Script")
        btn_gen_ps.setStyleSheet("QPushButton{background:#0066cc;color:white;padding:8px;border-radius:4px}QPushButton:hover{background:#0088ff}")
        btn_gen_ps.clicked.connect(lambda: self._generate_script("powershell"))
        btn_row3.addWidget(btn_gen_ps)
        btn_gen_bash = QPushButton("Generate Bash Script")
        btn_gen_bash.setStyleSheet("QPushButton{background:#0066cc;color:white;padding:8px;border-radius:4px}QPushButton:hover{background:#0088ff}")
        btn_gen_bash.clicked.connect(lambda: self._generate_script("bash"))
        btn_row3.addWidget(btn_gen_bash)
        btn_copy = QPushButton("Copy to Clipboard")
        btn_copy.clicked.connect(self._copy_script)
        btn_row3.addWidget(btn_copy)
        btn_save = QPushButton("Save Script")
        btn_save.clicked.connect(self._save_script)
        btn_row3.addWidget(btn_save)
        rl.addLayout(btn_row3)
        self.script_preview = QTextEdit()
        self.script_preview.setReadOnly(True)
        self.script_preview.setStyleSheet("QTextEdit{background:#1a1a2e;color:#d4d4d4;font-family:'Consolas',monospace;font-size:12px}")
        self.script_preview.setPlaceholderText("Click 'Generate PowerShell Script' or 'Generate Bash Script' to create a remediation script for failed controls...")
        rl.addWidget(self.script_preview)
        self.tabs.addTab(remed_tab, "Remediation Guide")

        # ── Tab 4: History / Trends ──
        history_tab = QWidget()
        hl = QVBoxLayout(history_tab)
        hl.addWidget(QLabel("Compliance History & Trends"))
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels(["Date", "Score %", "Passed", "Failed", "Total", "Benchmark"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.history_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        hl.addWidget(self.history_table)
        hl.addWidget(QLabel("Score Trend (bar visualization)"))
        self.trend_bar_widget = TrendBarWidget()
        self.trend_bar_widget.setMinimumHeight(120)
        hl.addWidget(self.trend_bar_widget)
        self.tabs.addTab(history_tab, "History")

        # ── Tab 5: Reports ──
        report_tab = QWidget()
        rrl = QVBoxLayout(report_tab)
        rrl.addWidget(QLabel("Export & Report Builder"))
        btn_row4 = QHBoxLayout()
        for fmt, label in [("html", "Export HTML"), ("pdf", "Export PDF (via HTML)"), ("json", "Export JSON"), ("csv", "Export CSV")]:
            btn = QPushButton(label)
            btn.setStyleSheet("QPushButton{background:#2a2a3e;color:white;padding:8px;border-radius:4px}QPushButton:hover{background:#333355}")
            btn.clicked.connect(lambda _, f=fmt: self._export_report(f))
            btn_row4.addWidget(btn)
        rrl.addLayout(btn_row4)
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setStyleSheet("QTextEdit{background:#1a1a2e;color:#d4d4d4;font-family:'Consolas',monospace;font-size:11px}")
        rrl.addWidget(self.report_preview)
        self.tabs.addTab(report_tab, "Reports")

    # ── Slots ───────────────────────────────────────────────────────────────

    def _on_benchmark_change(self, text):
        self._benchmark = text
        self.statusBar().showMessage(f"Benchmark changed to: {text}")

    def _load_demo(self):
        self._benchmark = self.combo_benchmark.currentText()
        self._findings = generate_demo_findings(self._benchmark)
        self._history = generate_history_data(len(self._findings))
        self._exceptions = [
            {"control_id": "1.4.1", "reason": "Renamed admin account already via GPO", "expiry": "2026-12-31", "approved_by": "IT Security"},
            {"control_id": "5.2.2", "reason": "RDP required for admin access", "expiry": "2026-09-30", "approved_by": "CISO Office"},
        ]
        self._refresh_all()
        self.statusBar().showMessage(f"Demo data loaded: {len(self._findings)} findings from {self._benchmark}")

    def _refresh_all(self):
        self._refresh_dashboard()
        self._refresh_findings_table()
        self._refresh_category_table()
        self._refresh_history_table()
        self._refresh_recent_findings()

    def _refresh_dashboard(self):
        passed = sum(1 for f in self._findings if f["status"] == "Pass")
        failed = sum(1 for f in self._findings if f["status"] == "Fail")
        total = len(self._findings)
        score = int(passed / total * 100) if total else 0
        self.gauge.set_score(score)
        self.lbl_passed.setText(f"Passed: {passed}")
        self.lbl_failed.setText(f"Failed: {failed}")
        self.lbl_total.setText(f"Total: {total}")

    def _refresh_category_table(self):
        cat_counts = {}
        for f in self._findings:
            cat = f["category"]
            cat_counts.setdefault(cat, {"pass": 0, "fail": 0})
            cat_counts[cat]["pass" if f["status"] == "Pass" else "fail"] += 1
        self.cat_table.setRowCount(len(cat_counts))
        for i, (cat, c) in enumerate(sorted(cat_counts.items())):
            total = c["pass"] + c["fail"]
            pct = int(c["pass"] / total * 100) if total else 0
            self.cat_table.setItem(i, 0, QTableWidgetItem(cat))
            self.cat_table.setItem(i, 1, QTableWidgetItem(f"{pct}%"))
            status = "Compliant" if pct >= 80 else "Partial" if pct >= 50 else "Non-Compliant"
            item = QTableWidgetItem(status)
            color = QColor(0, 200, 100) if pct >= 80 else QColor(255, 180, 0) if pct >= 50 else QColor(255, 60, 60)
            item.setForeground(color)
            self.cat_table.setItem(i, 2, item)

    def _refresh_findings_table(self, filtered: list = None):
        data = filtered if filtered is not None else self._findings
        self.findings_table.setRowCount(len(data))
        for i, f in enumerate(data):
            for col, key in enumerate(["control_id", "title", "status", "severity", "expected_value", "actual_value", "check_command", "remediation"]):
                item = QTableWidgetItem(str(f.get(key, "")))
                if key == "status":
                    item.setForeground(QColor(0, 200, 100) if f[key] == "Pass" else QColor(255, 60, 60))
                elif key == "severity":
                    sev_color = {"Critical": "#ff3c3c", "High": "#ff8c00", "Medium": "#ffb400", "Low": "#6ec6ff", "Informational": "#888"}.get(f[key], "#888")
                    item.setForeground(QColor(sev_color))
                self.findings_table.setItem(i, col, item)

    def _refresh_recent_findings(self):
        recent = self._findings[:20]
        self.recent_table.setRowCount(len(recent))
        for i, f in enumerate(recent):
            self.recent_table.setItem(i, 0, QTableWidgetItem(f["control_id"]))
            self.recent_table.setItem(i, 1, QTableWidgetItem(f["title"][:60]))
            s_item = QTableWidgetItem(f["status"])
            s_item.setForeground(QColor(0, 200, 100) if f["status"] == "Pass" else QColor(255, 60, 60))
            self.recent_table.setItem(i, 2, s_item)
            self.recent_table.setItem(i, 3, QTableWidgetItem(f["severity"]))

    def _refresh_history_table(self):
        self.history_table.setRowCount(len(self._history))
        for i, h in enumerate(self._history):
            self.history_table.setItem(i, 0, QTableWidgetItem(h["date"]))
            s_item = QTableWidgetItem(f"{h['score']}%")
            color = QColor(0, 200, 100) if h["score"] >= 80 else QColor(255, 180, 0) if h["score"] >= 50 else QColor(255, 60, 60)
            s_item.setForeground(color)
            self.history_table.setItem(i, 1, s_item)
            self.history_table.setItem(i, 2, QTableWidgetItem(str(h["passed"])))
            self.history_table.setItem(i, 3, QTableWidgetItem(str(h["failed"])))
            self.history_table.setItem(i, 4, QTableWidgetItem(str(h["total"])))
            self.history_table.setItem(i, 5, QTableWidgetItem(h["benchmark"]))
        self.trend_bar_widget.set_history(self._history)

    def _filter_findings(self, text):
        if text == "All":
            self._refresh_findings_table()
        elif text in ("Pass", "Fail"):
            self._refresh_findings_table([f for f in self._findings if f["status"] == text])
        else:
            self._refresh_findings_table([f for f in self._findings if f["severity"] == text])

    def _show_finding_detail(self):
        row = self.findings_table.currentRow()
        if row < 0:
            row = self.recent_table.currentRow()
        if row < 0 or row >= len(self._findings):
            QMessageBox.information(self, "Info", "Select a finding to view details.")
            return
        f = self._findings[row]
        detail = QDialog(self)
        detail.setWindowTitle(f"Detail: {f['control_id']}")
        detail.setMinimumSize(550, 420)
        lay = QVBoxLayout(detail)
        for label, value in [
            ("Control ID:", f["control_id"]),
            ("Title:", f["title"]),
            ("Category:", f["category"]),
            ("Status:", f["status"]),
            ("Severity:", f["severity"]),
            ("Expected Value:", f["expected_value"]),
            ("Current Value:", f["actual_value"]),
            ("Check Command:", f["check_command"]),
            ("Remediation:", f["remediation"]),
            ("Description:", f["description"]),
        ]:
            g = QGroupBox(label)
            gl = QVBoxLayout(g)
            lbl = QLabel(value)
            lbl.setWordWrap(True)
            if label == "Remediation:":
                lbl.setStyleSheet("QLabel{font-family:Consolas;background:#1a1a2e;padding:6px;border-radius:4px;color:#d4d4d4}")
            gl.addWidget(lbl)
            lay.addWidget(g)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(detail.accept)
        lay.addWidget(buttons)
        detail.exec()

    def _apply_remediation(self):
        QMessageBox.information(self, "Remediation", "Remediation script generated. See the Remediation Guide tab.")

    def _generate_script(self, kind):
        if not self._findings:
            QMessageBox.warning(self, "No Data", "Load demo data or import findings first.")
            return
        if kind == "powershell":
            script = generate_powershell_script(self._findings, self._exceptions)
            self.script_preview.setPlainText(script)
        else:
            script = generate_bash_script(self._findings, self._exceptions)
            self.script_preview.setPlainText(script)
        self.tabs.setCurrentIndex(2)

    def _copy_script(self):
        text = self.script_preview.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            self.statusBar().showMessage("Script copied to clipboard")

    def _save_script(self):
        text = self.script_preview.toPlainText()
        if not text:
            QMessageBox.warning(self, "No Script", "Generate a script first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save Script", "", "PowerShell Scripts (*.ps1);;Bash Scripts (*.sh);;All Files (*)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            self.statusBar().showMessage(f"Script saved to {path}")

    def _manage_exceptions(self):
        dlg = ExceptionDialog(self._exceptions, self)
        if dlg.exec():
            self._exceptions = dlg.get_exceptions()
            self.statusBar().showMessage(f"Exceptions updated: {len(self._exceptions)} items")

    def _export_report(self, fmt):
        if not self._findings:
            QMessageBox.warning(self, "No Data", "Load demo data first.")
            return
        passed = sum(1 for f in self._findings if f["status"] == "Pass")
        total = len(self._findings)
        score = int(passed / total * 100) if total else 0

        if fmt == "html":
            content = generate_html_report(self._findings, score, self._benchmark, self._history)
            ext = "html"
            filter_str = "HTML Files (*.html)"
        elif fmt == "pdf":
            content = generate_html_report(self._findings, score, self._benchmark, self._history)
            ext = "html"
            filter_str = "HTML Files (*.html)"
            QMessageBox.information(self, "PDF Export", "PDF export saved as HTML. Print this HTML to PDF using your browser.")
        elif fmt == "json":
            content = json.dumps({
                "benchmark": self._benchmark,
                "score": score,
                "generated": datetime.now().isoformat(),
                "findings": self._findings,
                "history": self._history,
                "exceptions": self._exceptions,
            }, indent=2)
            ext = "json"
            filter_str = "JSON Files (*.json)"
        else:
            import io
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["Control ID", "Title", "Status", "Severity", "Expected", "Actual", "Remediation"])
            for f in self._findings:
                writer.writerow([f["control_id"], f["title"], f["status"], f["severity"],
                                 f["expected_value"], f["actual_value"], f["remediation"]])
            content = buf.getvalue()
            ext = "csv"
            filter_str = "CSV Files (*.csv)"

        path, _ = QFileDialog.getSaveFileName(self, f"Export {fmt.upper()} Report", f"cis_report.{ext}", filter_str)
        if path:
            with open(path, "w", encoding="utf-8") as fp:
                fp.write(content)
            self.statusBar().showMessage(f"Report exported: {path}")
            self.report_preview.setPlainText(content[:5000] + ("\n\n... [truncated for preview]" if len(content) > 5000 else ""))
            self.tabs.setCurrentIndex(4)

    def _import_benchmark(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Benchmark", "", "JSON/YAML Files (*.json *.yaml *.yml);;All Files (*)")
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and "findings" in data:
                    self._findings = data["findings"]
                elif isinstance(data, list):
                    self._findings = data
                self._benchmark = Path(path).stem
                self._refresh_all()
                self.statusBar().showMessage(f"Imported {len(self._findings)} findings from {path}")
            except Exception as e:
                QMessageBox.critical(self, "Import Error", str(e))

    def _run_assessment(self):
        self.statusBar().showMessage("Running assessment...")
        QTimer.singleShot(1500, self._complete_assessment)

    def _complete_assessment(self):
        if not self._findings:
            self._load_demo()
        else:
            for f in self._findings:
                f["status"] = random.choice(["Pass", "Fail"])
                if f["status"] == "Fail":
                    f["severity"] = random.choice(["Critical", "High", "Medium", "Low"])
                else:
                    f["severity"] = "Informational"
            self._refresh_all()
        self.statusBar().showMessage(f"Assessment complete: {len(self._findings)} findings evaluated")


# ─── Trend Bar Widget ──────────────────────────────────────────────────────────

class TrendBarWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._history = []
        self.setMinimumHeight(140)

    def set_history(self, history):
        self._history = history
        self.update()

    def paintEvent(self, event):
        if not self._history:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        margin_l, margin_r, margin_t, margin_b = 40, 20, 20, 30
        area_w = w - margin_l - margin_r
        area_h = h - margin_t - margin_b
        bar_w = max(10, int(area_w / len(self._history)) - 4)

        p.setPen(QColor(80, 80, 80))
        for y_pct in [0, 25, 50, 75, 100]:
            y = int(margin_t + area_h - (area_h * y_pct / 100))
            p.drawLine(margin_l, y, w - margin_r, y)
            p.setPen(QColor(120, 120, 120))
            p.drawText(2, y - 4, 36, 16, Qt.AlignRight, f"{y_pct}%")
            p.setPen(QColor(80, 80, 80))

        for i, h_item in enumerate(self._history):
            x = margin_l + i * (area_w / len(self._history)) + 2
            score = h_item["score"]
            bar_h = int(area_h * score / 100)
            color = QColor(0, 200, 100) if score >= 80 else QColor(255, 180, 0) if score >= 50 else QColor(255, 60, 60)
            p.fillRect(int(x), int(margin_t + area_h - bar_h), bar_w, bar_h, QBrush(color))
            p.setPen(QColor(200, 200, 200))
            p.drawText(int(x), int(margin_t + area_h - bar_h - 4), bar_w, 14, Qt.AlignHCenter, f"{score}%")
            p.drawText(int(x), int(h - 18), bar_w, 14, Qt.AlignHCenter, h_item["date"][5:])
        p.end()


# ─── Entry Point ────────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(30, 30, 46))
    palette.setColor(QPalette.WindowText, QColor(205, 214, 244))
    palette.setColor(QPalette.Base, QColor(24, 24, 37))
    palette.setColor(QPalette.AlternateBase, QColor(30, 30, 46))
    palette.setColor(QPalette.Text, QColor(205, 214, 244))
    palette.setColor(QPalette.Button, QColor(49, 50, 68))
    palette.setColor(QPalette.ButtonText, QColor(205, 214, 244))
    palette.setColor(QPalette.Highlight, QColor(0, 102, 204))
    palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    app.setPalette(palette)

    font = QFont("Segoe UI", 10)
    app.setFont(font)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
