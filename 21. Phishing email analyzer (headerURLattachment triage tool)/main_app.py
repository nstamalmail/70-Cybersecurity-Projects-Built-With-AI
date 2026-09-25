"""
Phishing Email Analyzer - Header/URL/Attachment Triage Tool
Complete PySide6 GUI application for phishing email analysis.
"""

import sys
import os
import re
import json
import csv
import hashlib
import email
import email.policy
from email import policy
from email.parser import BytesParser
from io import StringIO, BytesIO
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict
from pathlib import Path

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView,
    QFileDialog, QGroupBox, QGridLayout, QFrame, QSplitter, QProgressBar,
    QComboBox, QMessageBox, QSizePolicy, QScrollArea, QSpinBox, QCheckBox
)
from PySide6.QtCore import Qt, QSize, QTimer
from PySide6.QtGui import (
    QFont, QColor, QPalette, QIcon, QTextCursor, QPixmap, QPainter,
    QLinearGradient, QBrush, QPen
)

# ---------------------------------------------------------------------------
# Defanging Utilities
# ---------------------------------------------------------------------------

def defang_url(url: str) -> str:
    url = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    parsed = urlparse(url)
    if parsed.hostname:
        defanged_host = parsed.hostname.replace(".", "[.]")
        url = url.replace(parsed.hostname, defanged_host)
    return url


def defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")


def defang_email(addr: str) -> str:
    return addr.replace("@", "[at]").replace(".", "[.]")


def refang(text: str) -> str:
    text = text.replace("[.]", ".").replace("[at]", "@")
    text = text.replace("hxxp://", "http://").replace("hxxps://", "https://")
    return text

# ---------------------------------------------------------------------------
# Email Parsing
# ---------------------------------------------------------------------------

def parse_eml(raw: str) -> email.message.Message:
    return email.message_from_string(raw, policy=policy.default)


def get_header(msg: email.message.Message, name: str) -> str:
    val = msg.get(name, "")
    return str(val) if val else ""


def get_all_headers(msg: email.message.Message, name: str) -> list:
    vals = msg.get_all(name, [])
    return [str(v) for v in vals] if vals else []


def extract_body(msg: email.message.Message) -> str:
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/html", "text/plain"):
                try:
                    parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            parts.append(msg.get_content())
        except Exception:
            pass
    return "\n".join(parts)


def extract_text_body(msg: email.message.Message) -> str:
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                try:
                    parts.append(part.get_content())
                except Exception:
                    pass
    else:
        if msg.get_content_type() == "text/plain":
            try:
                parts.append(msg.get_content())
            except Exception:
                pass
    return "\n".join(parts)

# ---------------------------------------------------------------------------
# Header Analysis
# ---------------------------------------------------------------------------

def parse_auth_results(auth_header: str) -> dict:
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    if not auth_header:
        return results
    for mechanism in ("spf", "dkim", "dmarc"):
        pattern = rf"{mechanism}=(\w+)"
        m = re.search(pattern, auth_header, re.IGNORECASE)
        if m:
            results[mechanism] = m.group(1).lower()
    return results


def extract_spf_from_received(received_headers: list) -> str:
    for h in received_headers:
        m = re.search(r"spf=(\w+)", h, re.IGNORECASE)
        if m:
            return m.group(1).lower()
    return "none"


def parse_received_headers(headers: list) -> list:
    hops = []
    for h in headers:
        hop = {"raw": h}
        m = re.search(r"from\s+(\S+)", h)
        if m:
            hop["from"] = m.group(1)
        m = re.search(r"by\s+(\S+)", h)
        if m:
            hop["by"] = m.group(1)
        m = re.search(r"for\s+<([^>]+)>", h)
        if m:
            hop["for"] = m.group(1)
        m = re.search(r";\s*(.+)$", h)
        if m:
            hop["date"] = m.group(1).strip()
        hops.append(hop)
    return hops


def extract_ips_from_headers(headers: list) -> list:
    ips = []
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    for h in headers:
        for m in ip_pattern.finditer(h):
            ips.append(m.group(1))
    return list(set(ips))

# ---------------------------------------------------------------------------
# URL Analysis
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS = {
    "ru", "cn", "tk", "ml", "ga", "cf", "gq", "pw", "top", "xyz",
    "club", "work", "icu", "buzz", "loan", "racing", "win", "date",
    "stream", "download", "review", "accountant", "faith"
}

SUSPICIOUS_KEYWORDS = {
    "verify", "urgent", "account", "suspended", "login", "secure",
    "update", "confirm", "password", "billing", "unlock", "alert",
    "unusual", "activity", "limited", "restrict", "expire", "warning"
}

PHISHING_ATTACHMENTS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".msp", ".mst",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm"
}


def extract_urls_from_text(text: str) -> list:
    url_pattern = re.compile(
        r'https?://[^\s<>"\')\]]+',
        re.IGNORECASE
    )
    urls = url_pattern.findall(text)
    cleaned = []
    for u in urls:
        u = u.rstrip(".,;:!?")
        cleaned.append(u)
    return list(set(cleaned))


def extract_urls_from_html(html: str) -> list:
    urls = extract_urls_from_text(html)
    href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    for m in href_pattern.finditer(html):
        url = m.group(1)
        if url.startswith(("http://", "https://")):
            urls.append(url)
    return list(set(urls))


def analyze_url(url: str) -> dict:
    result = {
        "url": url,
        "defanged": defang_url(url),
        "domain": "",
        "tld": "",
        "is_ip": False,
        "redirect_chain": [],
        "risk": "Low",
        "risk_score": 0,
        "reasons": []
    }
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        result["domain"] = host
        parts = host.split(".")
        if parts:
            result["tld"] = parts[-1]
        ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        if ip_pattern.match(host):
            result["is_ip"] = True
            result["risk"] = "High"
            result["risk_score"] += 40
            result["reasons"].append("URL uses IP address instead of domain")
        if result["tld"] in SUSPICIOUS_TLDS:
            result["risk_score"] += 20
            result["reasons"].append(f"Suspicious TLD: .{result['tld']}")
            if result["risk"] == "Low":
                result["risk"] = "Medium"
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in url.lower():
                result["risk_score"] += 5
                result["reasons"].append(f"Contains keyword: {kw}")
                if result["risk"] == "Low":
                    result["risk"] = "Medium"
        if "@" in url:
            result["risk_score"] += 30
            result["reasons"].append("URL contains @ symbol (possible credential harvesting)")
            result["risk"] = "High"
        if len(parsed.path) > 50:
            result["risk_score"] += 5
            result["reasons"].append("Unusually long URL path")
        if url.count("/") > 5:
            result["risk_score"] += 5
            result["reasons"].append("Deep URL path (possible redirect chain)")
        if result["risk_score"] >= 40:
            result["risk"] = "High"
        elif result["risk_score"] >= 20:
            result["risk"] = "Medium"
        else:
            result["risk"] = "Low"
    except Exception:
        result["risk"] = "Unknown"
    return result

# ---------------------------------------------------------------------------
# Attachment Analysis
# ---------------------------------------------------------------------------

def analyze_attachments(msg: email.message.Message) -> list:
    attachments = []
    if not msg.is_multipart():
        return attachments
    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", ""))
        if "attachment" in content_disposition:
            filename = part.get_filename() or "unknown"
            mime_type = part.get_content_type()
            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0
            hashes = {}
            if payload:
                hashes["md5"] = hashlib.md5(payload).hexdigest()
                hashes["sha1"] = hashlib.sha1(payload).hexdigest()
                hashes["sha256"] = hashlib.sha256(payload).hexdigest()
            ext = os.path.splitext(filename)[1].lower()
            has_macros = ext in (".docm", ".xlsm", ".pptm", ".dotm", ".xltm")
            is_executable = ext in (".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
                                    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
                                    ".ps1", ".msi")
            risk = "Low"
            risk_score = 0
            reasons = []
            if has_macros:
                risk_score += 15
                reasons.append("Macro-enabled Office document")
            if is_executable:
                risk_score += 25
                reasons.append("Executable file type")
            if ext in SUSPICIOUS_ATTACHMENTS:
                risk_score += 10
                reasons.append(f"Suspicious extension: {ext}")
            if size > 5 * 1024 * 1024:
                risk_score += 3
                reasons.append("Large attachment (>5MB)")
            if risk_score >= 25:
                risk = "High"
            elif risk_score >= 10:
                risk = "Medium"
            else:
                risk = "Low"
            attachments.append({
                "filename": filename,
                "mime_type": mime_type,
                "size": size,
                "extension": ext,
                "hashes": hashes,
                "has_macros": has_macros,
                "is_executable": is_executable,
                "risk": risk,
                "risk_score": risk_score,
                "reasons": reasons
            })
    return attachments

# ---------------------------------------------------------------------------
# Risk Scoring
# ---------------------------------------------------------------------------

def compute_risk_score(auth_results: dict, from_domain: str, return_path: str,
                       reply_to: str, urls: list, attachments: list,
                       body_text: str, received_headers: list) -> dict:
    score = 0
    breakdown = []
    # SPF
    spf = auth_results.get("spf", "none")
    if spf == "fail":
        score += 25
        breakdown.append(("SPF Fail", 25, "red"))
    elif spf == "softfail":
        score += 10
        breakdown.append(("SPF Softfail", 10, "yellow"))
    elif spf == "none":
        score += 2
        breakdown.append(("SPF None", 2, "gray"))
    else:
        breakdown.append(("SPF Pass", 0, "green"))
    # DKIM
    dkim = auth_results.get("dkim", "none")
    if dkim == "fail":
        score += 20
        breakdown.append(("DKIM Fail", 20, "red"))
    elif dkim == "none":
        score += 5
        breakdown.append(("DKIM None", 5, "gray"))
    else:
        breakdown.append(("DKIM Pass", 0, "green"))
    # DMARC
    dmarc = auth_results.get("dmarc", "none")
    if dmarc == "fail":
        score += 25
        breakdown.append(("DMARC Fail", 25, "red"))
    elif dmarc == "none":
        score += 2
        breakdown.append(("DMARC None", 2, "gray"))
    else:
        breakdown.append(("DMARC Pass", 0, "green"))
    # From vs Return-Path mismatch
    if return_path:
        rp_domain = ""
        m = re.search(r"@([\w.-]+)", return_path)
        if m:
            rp_domain = m.group(1).lower()
        if rp_domain and rp_domain != from_domain.lower():
            score += 15
            breakdown.append(("From/Return-Path Mismatch", 15, "red"))
        else:
            breakdown.append(("From/Return-Path Match", 0, "green"))
    # URL risk
    high_urls = sum(1 for u in urls if u.get("risk") == "High")
    med_urls = sum(1 for u in urls if u.get("risk") == "Medium")
    url_score = high_urls * 10 + med_urls * 5
    if url_score > 0:
        score += min(url_score, 30)
        breakdown.append((f"URL Risk ({high_urls}H/{med_urls}M)", min(url_score, 30), "yellow" if url_score < 20 else "red"))
    else:
        breakdown.append(("URLs Clean", 0, "green"))
    # Attachments
    for att in attachments:
        if att["has_macros"]:
            score += 15
            breakdown.append((f"Macro: {att['filename']}", 15, "red"))
        if att["is_executable"]:
            score += 15
            breakdown.append((f"Executable: {att['filename']}", 15, "red"))
    # Phishing keywords in body
    keyword_hits = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in body_text.lower():
            keyword_hits.append(kw)
    if keyword_hits:
        kw_score = min(len(keyword_hits) * 3, 15)
        score += kw_score
        breakdown.append((f"Phishing Keywords ({len(keyword_hits)})", kw_score, "yellow"))
    # Display name spoofing
    display_from = ""
    m = re.match(r'"?([^"<]+)"?\s*<', get_header_from_string(body_text) or "")
    if not m:
        pass
    score = min(score, 100)
    if score >= 60:
        verdict = "Likely Phishing"
        verdict_color = "red"
    elif score >= 30:
        verdict = "Suspicious"
        verdict_color = "yellow"
    else:
        verdict = "Safe"
        verdict_color = "green"
    return {
        "score": score,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "breakdown": breakdown
    }


def get_header_from_string(s: str) -> str:
    return s

# ---------------------------------------------------------------------------
# IOC Extraction
# ---------------------------------------------------------------------------

def extract_iocs(urls: list, attachments: list, from_addr: str,
                 return_path: str, reply_to: str, received_headers: list) -> dict:
    ips = extract_ips_from_headers(received_headers)
    domains = set()
    email_addrs = set()
    url_strs = []
    for u in urls:
        try:
            parsed = urlparse(refang(u["url"]))
            if parsed.hostname:
                domains.add(parsed.hostname)
        except Exception:
            pass
        url_strs.append(u["defanged"])
    for addr in [from_addr, return_path, reply_to]:
        if addr:
            email_addrs.add(defang_email(addr))
    hashes = {"md5": [], "sha1": [], "sha256": []}
    macro_files = []
    for att in attachments:
        if att["hashes"].get("md5"):
            hashes["md5"].append(att["hashes"]["md5"])
        if att["hashes"].get("sha1"):
            hashes["sha1"].append(att["hashes"]["sha1"])
        if att["hashes"].get("sha256"):
            hashes["sha256"].append(att["hashes"]["sha256"])
        if att["has_macros"]:
            macro_files.append(att["filename"])
    return {
        "ips": [defang_ip(i) for i in ips],
        "domains": [defang_url(f"http://{d}").replace("hxxp://", "") for d in sorted(domains)],
        "urls": url_strs,
        "emails": sorted(email_addrs),
        "hashes": hashes,
        "macro_files": macro_files
    }

# ---------------------------------------------------------------------------
# Demo Data
# ---------------------------------------------------------------------------

DEMO_PHISHING = """\
From: PayPal Security <security-alert@paypa1-secure.com>
Reply-To: admin@paypa1-secure.com
Return-Path: bounce@malicious-relay.net
To: victim@company.com
Subject: URGENT: Your Account Has Been Suspended - Verify Now
Date: Mon, 21 Sep 2026 08:30:00 -0400
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_12345"
X-Mailer: PHPMailer 6.1.5
X-Originating-IP: 198.51.100.23
Received: from unknown (HELO phishing-server.ru) (198.51.100.23)
    by mx.victim-corp.com with SMTP; Mon, 21 Sep 2026 08:29:45 -0400
    (envelope-from <bounce@malicious-relay.net>)
Received: from mail.paypa1-secure.com (mail.paypa1-secure.com [203.0.113.45])
    by relay.malicious-relay.net with ESMTP id x1y2z3
    for <victim@company.com>; Mon, 21 Sep 2026 08:29:30 -0400
Received: from localhost (localhost [127.0.0.1])
    by mail.paypa1-secure.com (Postfix) with ESMTP id abc111
    for <victim@company.com>; Mon, 21 Sep 2026 08:29:00 -0400
Authentication-Results: mx.victim-corp.com;
    spf=fail (domain paypa1-secure.com does not designate 198.51.100.23 as permitted sender);
    dkim=fail header1=paypa1-secure.com;
    dmarc=fail (p=reject) header.from=paypa1-secure.com
Received-SPF: fail (mx.victim-corp.com: domain paypa1-secure.com does not designate 198.51.100.23 as permitted sender)
ARC-Authentication-Results: i=1; mx.victim-corp.com; spf=fail; dkim=fail; dmarc=fail
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=paypa1-secure.com; s=mail;
    bh=invalid=; b=forged=
Message-ID: <scam123@paypa1-secure.com>
X-Priority: 1
Importance: urgent

------=_Part_12345
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 7bit

<html>
<body style="font-family: Arial, sans-serif;">
<div style="background-color: #ff0000; color: white; padding: 10px; text-align: center;">
<h1>URGENT ACTION REQUIRED</h1>
</div>
<p>Dear Valued Customer,</p>
<p>We have detected <strong>unauthorized activity</strong> on your PayPal account. Your account has been <strong>suspended</strong> until you verify your identity.</p>
<p>Click the link below to verify your account immediately:</p>
<p><a href="https://paypa1-secure.com/verify?user=victim&token=abc123">Click Here to Verify Your Account</a></p>
<p>Or copy this link: hxxps://paypa1-secure[.]com/verify?user=victim&token=abc123</p>
<p><strong>Warning:</strong> If you do not verify within 24 hours, your account will be permanently closed.</p>
<p>Additional links:</p>
<ul>
<li><a href="https://192.168.1.100/phish/login">Direct Login</a></li>
<li><a href="http://login-verify.account-update.com/phish">Account Recovery</a></li>
</ul>
<p>You can also visit: https://www.paypal.com/signin</p>
<p>Regards,<br>PayPal Security Team</p>
<img src="http://tracker.paypa1-secure.com/open?id=12345" width="1" height="1" />
</body>
</html>

------=_Part_12345
Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="invoice_final.docm"
X-Attachment-Id: attach_001

UEsDBBQABgAIAAAAIQBgNnhF5AEAANkEAAATAAgCW0NvbnRlbnRfVHlwZXNdLnhtbCCiBAIooAAC
------=_Part_12345
Content-Type: application/pdf
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="payment_receipt.pdf"
X-Attachment-Id: attach_002

JVBERi0xLjAKMSAwIG9iago8PAovVHlwZSAvQ2F0YWxvZwovUGFnZXMgMiAwIFIKPj4KZW5kb2Jq
------=_Part_12345
Content-Type: application/x-msdownload
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="update_helper.exe"
X-Attachment-Id: attach_003

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
------=_Part_12345--
"""

DEMO_BENIGN = """\
From: Newsletter <newsletter@company.com>
To: alice@company.com
Subject: Weekly Company Update - September 21
Date: Mon, 21 Sep 2026 09:00:00 -0400
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 7bit
Received: from mail.company.com (mail.company.com [10.0.0.1])
    by mx.company.com with ESMTP id abc123
    for <alice@company.com>; Mon, 21 Sep 2026 09:00:00 -0400
Authentication-Results: mx.company.com;
    spf=pass (domain of newsletter@company.com designates 10.0.0.1 as permitted sender);
    dkim=pass header1=company.com;
    dmarc=pass (p=none) header.from=company.com
Received-SPF: pass (mx.company.com: domain of newsletter@company.com designates 10.0.0.1 as permitted sender)
ARC-Authentication-Results: i=1; mx.company.com; spf=pass; dkim=pass; dmarc=pass
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=company.com; s=default;
    bh=abc123=; b=xyz789=
Message-ID: <abc123@company.com>

<html>
<body>
<h2>Weekly Company Update</h2>
<p>Hi Team,</p>
<p>Here is this week's update. Please review the attached PDF for details.</p>
<p>No urgent action required.</p>
<p>Best regards,<br>Company Communications</p>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Color Constants
# ---------------------------------------------------------------------------

COLOR_GREEN = QColor(34, 139, 34)
COLOR_YELLOW = QColor(204, 153, 0)
COLOR_RED = QColor(200, 40, 40)
COLOR_GRAY = QColor(128, 128, 128)
COLOR_BG = QColor(30, 30, 30)
COLOR_CARD = QColor(40, 40, 40)
COLOR_TEXT = QColor(220, 220, 220)
COLOR_ACCENT = QColor(70, 130, 220)

STYLESHEET = """
QMainWindow { background-color: #1e1e1e; }
QWidget { background-color: #1e1e1e; color: #dcdcdc; font-family: 'Segoe UI', Arial; }
QTabWidget::pane { border: 1px solid #3a3a3a; background-color: #1e1e1e; }
QTabBar::tab {
    background-color: #2a2a2a; color: #aaaaaa; padding: 8px 16px;
    border: 1px solid #3a3a3a; border-bottom: none; border-top-left-radius: 4px;
    border-top-right-radius: 4px; margin-right: 2px;
}
QTabBar::tab:selected { background-color: #3a3a3a; color: #dcdcdc; }
QTabBar::tab:hover { background-color: #353535; }
QGroupBox {
    border: 1px solid #3a3a3a; border-radius: 6px; margin-top: 12px;
    padding-top: 16px; font-weight: bold; font-size: 12px;
}
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: #aaaaaa; }
QPushButton {
    background-color: #2a5db0; color: white; border: none; border-radius: 4px;
    padding: 8px 18px; font-weight: bold; font-size: 12px;
}
QPushButton:hover { background-color: #3a6dc0; }
QPushButton:pressed { background-color: #1a4da0; }
QPushButton#btnSecondary {
    background-color: #3a3a3a; color: #dcdcdc;
}
QPushButton#btnSecondary:hover { background-color: #4a4a4a; }
QPushButton#btnDanger { background-color: #a03030; }
QPushButton#btnDanger:hover { background-color: #c04040; }
QTextEdit {
    background-color: #252525; color: #dcdcdc; border: 1px solid #3a3a3a;
    border-radius: 4px; padding: 6px; font-family: 'Consolas', monospace;
    font-size: 11px;
}
QTableWidget {
    background-color: #252525; color: #dcdcdc; border: 1px solid #3a3a3a;
    gridline-color: #3a3a3a; font-size: 11px;
}
QTableWidget::item { padding: 4px; }
QTableWidget::item:selected { background-color: #2a5db0; }
QHeaderView::section {
    background-color: #2a2a2a; color: #aaaaaa; padding: 6px;
    border: 1px solid #3a3a3a; font-weight: bold; font-size: 11px;
}
QLabel { font-size: 12px; }
QProgressBar {
    border: 1px solid #3a3a3a; border-radius: 4px; text-align: center;
    background-color: #252525; color: #dcdcdc; font-weight: bold;
}
QProgressBar::chunk { border-radius: 3px; }
QScrollArea { border: none; }
QComboBox {
    background-color: #2a2a2a; color: #dcdcdc; border: 1px solid #3a3a3a;
    border-radius: 4px; padding: 4px 8px;
}
"""


# ---------------------------------------------------------------------------
# Score Widget (Custom Painted Gauge)
# ---------------------------------------------------------------------------

class ScoreGauge(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._score = 0
        self._verdict = "N/A"
        self._verdict_color = COLOR_GRAY
        self.setMinimumSize(220, 220)
        self.setMaximumSize(220, 220)

    def set_score(self, score: int, verdict: str, color: QColor):
        self._score = score
        self._verdict = verdict
        self._verdict_color = color
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        cx, cy = w // 2, h // 2 + 10
        radius = min(w, h) // 2 - 20
        # Background arc
        painter.setPen(QPen(QColor(50, 50, 50), 14, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(cx - radius, cy - radius, radius * 2, radius * 2, 225 * 16, -270 * 16)
        # Score arc
        angle = int(270 * (self._score / 100.0))
        if self._score < 30:
            col = COLOR_GREEN
        elif self._score < 60:
            col = COLOR_YELLOW
        else:
            col = COLOR_RED
        painter.setPen(QPen(col, 14, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(cx - radius, cy - radius, radius * 2, radius * 2, 225 * 16, -angle * 16)
        # Score text
        painter.setPen(QPen(COLOR_TEXT, 1))
        font = QFont("Segoe UI", 32, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(cx - radius, cy - 20, radius * 2, 40, Qt.AlignmentFlag.AlignCenter, str(self._score))
        # Verdict
        font2 = QFont("Segoe UI", 13, QFont.Weight.Bold)
        painter.setFont(font2)
        painter.setPen(QPen(self._verdict_color, 1))
        painter.drawText(cx - radius, cy + 10, radius * 2, 30, Qt.AlignmentFlag.AlignCenter, self._verdict)
        # Label
        font3 = QFont("Segoe UI", 9)
        painter.setFont(font3)
        painter.setPen(QPen(QColor(150, 150, 150), 1))
        painter.drawText(cx - radius, cy - 50, radius * 2, 20, Qt.AlignmentFlag.AlignCenter, "RISK SCORE")
        painter.end()


# ---------------------------------------------------------------------------
# Main Window
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Phishing Email Analyzer - Header/URL/Attachment Triage")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)
        self.current_analysis = None
        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)

        # ---- Top bar ----
        top_bar = QHBoxLayout()
        title = QLabel("Phishing Email Analyzer")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #4682dc;")
        top_bar.addWidget(title)
        top_bar.addStretch()
        self.btn_demo_phish = QPushButton("Load Demo (Phishing)")
        self.btn_demo_phish.setObjectName("btnDanger")
        self.btn_demo_phish.clicked.connect(lambda: self._load_demo(DEMO_PHISHING))
        top_bar.addWidget(self.btn_demo_phish)
        self.btn_demo_benign = QPushButton("Load Demo (Benign)")
        self.btn_demo_benign.clicked.connect(lambda: self._load_demo(DEMO_BENIGN))
        top_bar.addWidget(self.btn_demo_benign)
        self.btn_upload = QPushButton("Upload .eml")
        self.btn_upload.setObjectName("btnSecondary")
        self.btn_upload.clicked.connect(self._upload_eml)
        top_bar.addWidget(self.btn_upload)
        main_layout.addLayout(top_bar)

        # ---- Splitter: Input + Tabs ----
        splitter = QSplitter(Qt.Orientation.Vertical)

        # -- Input area --
        input_group = QGroupBox("Email Input")
        input_layout = QVBoxLayout(input_group)
        self.txt_input = QTextEdit()
        self.txt_input.setPlaceholderText("Paste raw email headers/body here or load a file...")
        self.txt_input.setMaximumHeight(140)
        input_layout.addWidget(self.txt_input)
        btn_row = QHBoxLayout()
        self.btn_analyze = QPushButton("Analyze Email")
        self.btn_analyze.clicked.connect(self._analyze)
        btn_row.addWidget(self.btn_analyze)
        btn_row.addStretch()
        input_layout.addLayout(btn_row)
        splitter.addWidget(input_group)

        # -- Tabs --
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_header_tab(), "Headers")
        self.tabs.addTab(self._build_url_tab(), "URLs")
        self.tabs.addTab(self._build_attachment_tab(), "Attachments")
        self.tabs.addTab(self._build_routing_tab(), "Routing Chain")
        self.tabs.addTab(self._build_dashboard_tab(), "Risk Dashboard")
        self.tabs.addTab(self._build_ioc_tab(), "IOC Summary")
        self.tabs.addTab(self._build_report_tab(), "Report")
        splitter.addWidget(self.tabs)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 4)
        main_layout.addWidget(splitter)

    # ---- Tab Builders ----

    def _build_header_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(4, 4, 4, 4)
        self.lbl_from = QLabel("From: -")
        self.lbl_return = QLabel("Return-Path: -")
        self.lbl_reply = QLabel("Reply-To: -")
        self.lbl_subject = QLabel("Subject: -")
        self.lbl_date = QLabel("Date: -")
        for lbl in (self.lbl_from, self.lbl_return, self.lbl_reply, self.lbl_subject, self.lbl_date):
            lbl.setFont(QFont("Consolas", 11))
            layout.addWidget(lbl)
        self.lbl_spf = QLabel("SPF: -")
        self.lbl_dkim = QLabel("DKIM: -")
        self.lbl_dmarc = QLabel("DMARC: -")
        for lbl in (self.lbl_spf, self.lbl_dkim, self.lbl_dmarc):
            lbl.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
            layout.addWidget(lbl)
        self.lbl_domain_mismatch = QLabel("")
        self.lbl_domain_mismatch.setFont(QFont("Consolas", 11))
        layout.addWidget(self.lbl_domain_mismatch)
        layout.addStretch()
        return w

    def _build_url_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(4, 4, 4, 4)
        self.url_table = QTableWidget()
        self.url_table.setColumnCount(5)
        self.url_table.setHorizontalHeaderLabels(["Defanged URL", "Domain", "TLD", "Risk", "Reasons"])
        self.url_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.url_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.url_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.url_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.url_table)
        return w

    def _build_attachment_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(4, 4, 4, 4)
        self.att_table = QTableWidget()
        self.att_table.setColumnCount(7)
        self.att_table.setHorizontalHeaderLabels([
            "Filename", "MIME Type", "Size", "MD5", "SHA256", "Macro", "Risk"
        ])
        self.att_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.att_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.att_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.att_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.att_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.att_table)
        return w

    def _build_routing_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(4, 4, 4, 4)
        self.routing_text = QTextEdit()
        self.routing_text.setReadOnly(True)
        layout.addWidget(self.routing_text)
        return w

    def _build_dashboard_tab(self) -> QWidget:
        w = QWidget()
        layout = QHBoxLayout(w)
        layout.setContentsMargins(4, 4, 4, 4)
        # Left: gauge
        left = QVBoxLayout()
        self.gauge = ScoreGauge()
        left.addWidget(self.gauge, alignment=Qt.AlignmentFlag.AlignCenter)
        left.addStretch()
        layout.addLayout(left)
        # Right: breakdown
        right = QVBoxLayout()
        right.addWidget(QLabel("Score Breakdown"))
        self.breakdown_table = QTableWidget()
        self.breakdown_table.setColumnCount(3)
        self.breakdown_table.setHorizontalHeaderLabels(["Factor", "Points", "Status"])
        self.breakdown_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.breakdown_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.breakdown_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        right.addWidget(self.breakdown_table)
        layout.addLayout(right)
        return w

    def _build_ioc_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(4, 4, 4, 4)
        self.ioc_text = QTextEdit()
        self.ioc_text.setReadOnly(True)
        self.ioc_text.setFont(QFont("Consolas", 11))
        layout.addWidget(self.ioc_text)
        return w

    def _build_report_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(4, 4, 4, 4)
        row = QHBoxLayout()
        self.btn_json = QPushButton("Export JSON")
        self.btn_json.clicked.connect(lambda: self._export("json"))
        row.addWidget(self.btn_json)
        self.btn_csv = QPushButton("Export CSV")
        self.btn_csv.clicked.connect(lambda: self._export("csv"))
        row.addWidget(self.btn_csv)
        self.btn_html = QPushButton("Export HTML")
        self.btn_html.clicked.connect(lambda: self._export("html"))
        row.addWidget(self.btn_html)
        self.btn_pdf = QPushButton("Export PDF")
        self.btn_pdf.clicked.connect(lambda: self._export("pdf"))
        row.addWidget(self.btn_pdf)
        row.addStretch()
        layout.addLayout(row)
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setFont(QFont("Consolas", 10))
        layout.addWidget(self.report_preview)
        return w

    # ---- Actions ----

    def _upload_eml(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Email File", "", "Email Files (*.eml);;All Files (*)"
        )
        if path:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            self.txt_input.setPlainText(content)
            self._analyze()

    def _load_demo(self, content: str):
        self.txt_input.setPlainText(content)
        self._analyze()

    def _analyze(self):
        raw = self.txt_input.toPlainText().strip()
        if not raw:
            QMessageBox.warning(self, "No Input", "Please paste an email or load a file first.")
            return
        msg = parse_eml(raw)
        # Headers
        from_addr = get_header(msg, "From")
        return_path = get_header(msg, "Return-Path")
        reply_to = get_header(msg, "Reply-To")
        subject = get_header(msg, "Subject")
        date = get_header(msg, "Date")
        # Authentication
        auth_header = get_header(msg, "Authentication-Results")
        auth_results = parse_auth_results(auth_header)
        if auth_results["spf"] == "none":
            received_spf = get_header(msg, "Received-SPF")
            spf_result = extract_spf_from_received([received_spf]) if received_spf else "none"
            if spf_result != "none":
                auth_results["spf"] = spf_result
        if auth_results["spf"] == "none":
            all_auth = get_all_headers(msg, "Authentication-Results")
            for ah in all_auth:
                r = parse_auth_results(ah)
                if r["spf"] != "none":
                    auth_results["spf"] = r["spf"]
                if r["dkim"] != "none":
                    auth_results["dkim"] = r["dkim"]
                if r["dmarc"] != "none":
                    auth_results["dmarc"] = r["dmarc"]
        # Extract from-domain
        from_domain = ""
        m = re.search(r"@([\w.-]+)", from_addr)
        if m:
            from_domain = m.group(1).lower()
        # URLs
        body = extract_body(msg)
        text_body = extract_text_body(msg)
        all_urls_raw = extract_urls_from_html(body) + extract_urls_from_text(text_body)
        all_urls_raw = list(set(all_urls_raw))
        urls = [analyze_url(u) for u in all_urls_raw]
        urls.sort(key=lambda x: {"High": 0, "Medium": 1, "Low": 2, "Unknown": 3}.get(x["risk"], 3))
        # Attachments
        attachments = analyze_attachments(msg)
        # Received headers
        received_headers = get_all_headers(msg, "Received")
        received_headers.reverse()
        hops = parse_received_headers(received_headers)
        # Risk score
        risk = compute_risk_score(auth_results, from_domain, return_path, reply_to, urls, attachments, body, received_headers)
        # IOCs
        iocs = extract_iocs(urls, attachments, from_addr, return_path, reply_to, received_headers)
        # Store
        self.current_analysis = {
            "from": from_addr, "return_path": return_path, "reply_to": reply_to,
            "subject": subject, "date": date, "auth": auth_results,
            "from_domain": from_domain, "urls": urls, "attachments": attachments,
            "hops": hops, "risk": risk, "iocs": iocs, "raw": raw
        }
        self._update_ui()

    def _update_ui(self):
        a = self.current_analysis
        if not a:
            return
        # Header tab
        self.lbl_from.setText(f"From: {a['from']}")
        self.lbl_return.setText(f"Return-Path: {a['return_path']}")
        self.lbl_reply.setText(f"Reply-To: {a['reply_to']}")
        self.lbl_subject.setText(f"Subject: {a['subject']}")
        self.lbl_date.setText(f"Date: {a['date']}")
        spf = a["auth"]["spf"]
        dkim = a["auth"]["dkim"]
        dmarc = a["auth"]["dmarc"]
        self.lbl_spf.setText(f"SPF: {spf.upper()}")
        self.lbl_spf.setStyleSheet(f"color: {self._status_color(spf)}; font-weight: bold; font-size: 13px;")
        self.lbl_dkim.setText(f"DKIM: {dkim.upper()}")
        self.lbl_dkim.setStyleSheet(f"color: {self._status_color(dkim)}; font-weight: bold; font-size: 13px;")
        self.lbl_dmarc.setText(f"DMARC: {dmarc.upper()}")
        self.lbl_dmarc.setStyleSheet(f"color: {self._status_color(dmarc)}; font-weight: bold; font-size: 13px;")
        # Domain mismatch
        rp_domain = ""
        m = re.search(r"@([\w.-]+)", a["return_path"])
        if m:
            rp_domain = m.group(1).lower()
        if rp_domain and rp_domain != a["from_domain"]:
            self.lbl_domain_mismatch.setText(
                f"ALERT: From domain '{a['from_domain']}' != Return-Path domain '{rp_domain}'"
            )
            self.lbl_domain_mismatch.setStyleSheet("color: #ff6666; font-weight: bold;")
        else:
            self.lbl_domain_mismatch.setText("Domains consistent")
            self.lbl_domain_mismatch.setStyleSheet("color: #66cc66;")
        # URL table
        self.url_table.setRowCount(len(a["urls"]))
        for i, u in enumerate(a["urls"]):
            self.url_table.setItem(i, 0, QTableWidgetItem(u["defanged"]))
            self.url_table.setItem(i, 1, QTableWidgetItem(u["domain"]))
            self.url_table.setItem(i, 2, QTableWidgetItem(u["tld"]))
            risk_item = QTableWidgetItem(u["risk"])
            risk_item.setForeground(self._risk_color(u["risk"]))
            self.url_table.setItem(i, 3, risk_item)
            self.url_table.setItem(i, 4, QTableWidgetItem("; ".join(u["reasons"])))
        # Attachment table
        self.att_table.setRowCount(len(a["attachments"]))
        for i, att in enumerate(a["attachments"]):
            self.att_table.setItem(i, 0, QTableWidgetItem(att["filename"]))
            self.att_table.setItem(i, 1, QTableWidgetItem(att["mime_type"]))
            size_str = f"{att['size']:,} bytes"
            if att["size"] > 1024:
                size_str += f" ({att['size']/1024:.1f} KB)"
            self.att_table.setItem(i, 2, QTableWidgetItem(size_str))
            md5 = att["hashes"].get("md5", "")[:12] + "..."
            self.att_table.setItem(i, 3, QTableWidgetItem(md5))
            sha256 = att["hashes"].get("sha256", "")[:16] + "..."
            self.att_table.setItem(i, 4, QTableWidgetItem(sha256))
            macro_item = QTableWidgetItem("YES" if att["has_macros"] else "No")
            if att["has_macros"]:
                macro_item.setForeground(COLOR_RED)
            self.att_table.setItem(i, 5, macro_item)
            risk_item = QTableWidgetItem(att["risk"])
            risk_item.setForeground(self._risk_color(att["risk"]))
            self.att_table.setItem(i, 6, risk_item)
        # Routing chain
        self._render_routing(a["hops"])
        # Dashboard
        self.gauge.set_score(
            a["risk"]["score"], a["risk"]["verdict"],
            self._risk_color(a["risk"]["verdict"])
        )
        bd = a["risk"]["breakdown"]
        self.breakdown_table.setRowCount(len(bd))
        for i, (factor, pts, color_name) in enumerate(bd):
            self.breakdown_table.setItem(i, 0, QTableWidgetItem(factor))
            pts_item = QTableWidgetItem(str(pts))
            col = {"green": COLOR_GREEN, "yellow": COLOR_YELLOW,
                   "red": COLOR_RED, "gray": COLOR_GRAY}.get(color_name, COLOR_GRAY)
            pts_item.setForeground(col)
            self.breakdown_table.setItem(i, 1, pts_item)
            status = "PASS" if pts == 0 else f"+{pts}"
            st_item = QTableWidgetItem(status)
            st_item.setForeground(col)
            self.breakdown_table.setItem(i, 2, st_item)
        # IOC summary
        self._render_iocs(a["iocs"])
        # Report preview
        self._render_report_preview()
        self.tabs.setCurrentIndex(0)

    def _render_routing(self, hops: list):
        if not hops:
            self.routing_text.setPlainText("No Received headers found.")
            return
        lines = []
        lines.append("=" * 60)
        lines.append("  ROUTING CHAIN (Received Headers)")
        lines.append("=" * 60)
        for i, hop in enumerate(hops):
            lines.append(f"\n  Hop {i + 1}:")
            if "from" in hop:
                lines.append(f"    From:  {hop['from']}")
            if "by" in hop:
                lines.append(f"    By:    {hop['by']}")
            if "for" in hop:
                lines.append(f"    For:   {hop['for']}")
            if "date" in hop:
                lines.append(f"    Date:  {hop['date']}")
            if i < len(hops) - 1:
                lines.append("       |")
                lines.append("       v")
        lines.append("\n" + "=" * 60)
        self.routing_text.setPlainText("\n".join(lines))

    def _render_iocs(self, iocs: dict):
        lines = []
        lines.append("=" * 60)
        lines.append("  INDICATORS OF COMPROMISE (IOCs)")
        lines.append("=" * 60)
        lines.append(f"\n  IPs ({len(iocs['ips'])}):")
        for ip in iocs["ips"]:
            lines.append(f"    {ip}")
        lines.append(f"\n  Domains ({len(iocs['domains'])}):")
        for d in iocs["domains"]:
            lines.append(f"    {d}")
        lines.append(f"\n  URLs ({len(iocs['urls'])}):")
        for u in iocs["urls"]:
            lines.append(f"    {u}")
        lines.append(f"\n  Emails ({len(iocs['emails'])}):")
        for e in iocs["emails"]:
            lines.append(f"    {e}")
        lines.append(f"\n  Hashes:")
        for h_type, vals in iocs["hashes"].items():
            if vals:
                lines.append(f"    {h_type.upper()}:")
                for v in vals:
                    lines.append(f"      {v}")
        if iocs.get("macro_files"):
            lines.append(f"\n  Macro-enabled files:")
            for f in iocs["macro_files"]:
                lines.append(f"    {f}")
        lines.append("\n" + "=" * 60)
        self.ioc_text.setPlainText("\n".join(lines))

    def _render_report_preview(self):
        a = self.current_analysis
        if not a:
            return
        lines = []
        lines.append("PHISHING EMAIL ANALYSIS REPORT")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 60)
        lines.append(f"Subject: {a['subject']}")
        lines.append(f"From: {a['from']}")
        lines.append(f"Return-Path: {a['return_path']}")
        lines.append(f"Date: {a['date']}")
        lines.append("")
        lines.append(f"RISK SCORE: {a['risk']['score']}/100")
        lines.append(f"VERDICT: {a['risk']['verdict']}")
        lines.append("")
        lines.append("Authentication:")
        lines.append(f"  SPF:  {a['auth']['spf'].upper()}")
        lines.append(f"  DKIM: {a['auth']['dkim'].upper()}")
        lines.append(f"  DMARC:{a['auth']['dmarc'].upper()}")
        lines.append("")
        lines.append(f"URLs Found: {len(a['urls'])}")
        for u in a["urls"]:
            lines.append(f"  [{u['risk']}] {u['defanged']}")
        lines.append("")
        lines.append(f"Attachments: {len(a['attachments'])}")
        for att in a["attachments"]:
            lines.append(f"  [{att['risk']}] {att['filename']} ({att['mime_type']}, {att['size']:,} bytes)")
            if att["has_macros"]:
                lines.append(f"         ** MACRO-ENABLED **")
        lines.append("")
        lines.append("Score Breakdown:")
        for factor, pts, color in a["risk"]["breakdown"]:
            lines.append(f"  {factor}: +{pts}")
        self.report_preview.setPlainText("\n".join(lines))

    # ---- Export ----

    def _export(self, fmt: str):
        a = self.current_analysis
        if not a:
            QMessageBox.warning(self, "No Data", "Analyze an email first.")
            return
        if fmt == "json":
            self._export_json(a)
        elif fmt == "csv":
            self._export_csv(a)
        elif fmt == "html":
            self._export_html(a)
        elif fmt == "pdf":
            self._export_pdf(a)

    def _export_json(self, a: dict):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save JSON Report", "phishing_report.json", "JSON Files (*.json)"
        )
        if not path:
            return
        data = {
            "report_date": datetime.now().isoformat(),
            "subject": a["subject"],
            "from": a["from"],
            "return_path": a["return_path"],
            "reply_to": a["reply_to"],
            "date": a["date"],
            "authentication": a["auth"],
            "risk_score": a["risk"]["score"],
            "verdict": a["risk"]["verdict"],
            "score_breakdown": [
                {"factor": f, "points": p, "status": s} for f, p, s in a["risk"]["breakdown"]
            ],
            "urls": a["urls"],
            "attachments": a["attachments"],
            "routing_hops": a["hops"],
            "iocs": a["iocs"]
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        QMessageBox.information(self, "Exported", f"JSON report saved to:\n{path}")

    def _export_csv(self, a: dict):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save CSV Report", "phishing_report.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Type", "Value", "Risk", "Details"])
            for u in a["urls"]:
                writer.writerow(["URL", u["defanged"], u["risk"], "; ".join(u["reasons"])])
            for att in a["attachments"]:
                writer.writerow([
                    "Attachment", att["filename"], att["risk"],
                    f"{att['mime_type']} | {att['size']} bytes | Macro:{att['has_macros']}"
                ])
            for ip in a["iocs"]["ips"]:
                writer.writerow(["IP", ip, "", ""])
            for d in a["iocs"]["domains"]:
                writer.writerow(["Domain", d, "", ""])
            for e in a["iocs"]["emails"]:
                writer.writerow(["Email", e, "", ""])
        QMessageBox.information(self, "Exported", f"CSV report saved to:\n{path}")

    def _export_html(self, a: dict):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save HTML Report", "phishing_report.html", "HTML Files (*.html)"
        )
        if not path:
            return
        html = self._generate_html(a)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        QMessageBox.information(self, "Exported", f"HTML report saved to:\n{path}")

    def _export_pdf(self, a: dict):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save PDF Report", "phishing_report.pdf", "PDF Files (*.pdf)"
        )
        if not path:
            return
        try:
            from PySide6.QtGui import QTextDocument
            from PySide6.QtPrintSupport import QPrinter
            html = self._generate_html(a)
            doc = QTextDocument()
            doc.setHtml(html)
            printer = QPrinter(QPrinter.OutputFormat.PdfResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(path)
            doc.print(printer)
            QMessageBox.information(self, "Exported", f"PDF report saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"PDF export failed: {e}")

    def _generate_html(self, a: dict) -> str:
        verdict_color = {"Safe": "#228b22", "Suspicious": "#cc9900", "Likely Phishing": "#cc2828"}
        vcolor = verdict_color.get(a["risk"]["verdict"], "#888888")
        spf_c = self._status_color(a["auth"]["spf"])
        dkim_c = self._status_color(a["auth"]["dkim"])
        dmarc_c = self._status_color(a["auth"]["dmarc"])
        url_rows = ""
        for u in a["urls"]:
            rc = self._html_risk_color(u["risk"])
            url_rows += f"<tr><td>{u['defanged']}</td><td>{u['domain']}</td><td style='color:{rc};font-weight:bold;'>{u['risk']}</td><td>{'; '.join(u['reasons'])}</td></tr>"
        att_rows = ""
        for att in a["attachments"]:
            rc = self._html_risk_color(att["risk"])
            macro = "<span style='color:red;font-weight:bold;'>YES</span>" if att["has_macros"] else "No"
            att_rows += f"<tr><td>{att['filename']}</td><td>{att['mime_type']}</td><td>{att['size']:,}</td><td>{macro}</td><td style='color:{rc};font-weight:bold;'>{att['risk']}</td></tr>"
        breakdown_rows = ""
        for factor, pts, color in a["risk"]["breakdown"]:
            cc = {"green": "#228b22", "yellow": "#cc9900", "red": "#cc2828", "gray": "#888888"}.get(color, "#888888")
            breakdown_rows += f"<tr><td>{factor}</td><td style='color:{cc};font-weight:bold;'>+{pts}</td></tr>"
        return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Phishing Analysis Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #dcdcdc; }}
h1 {{ color: #4682dc; }} h2 {{ color: #aaaaaa; border-bottom: 1px solid #3a3a3a; padding-bottom: 4px; }}
table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
th {{ background: #2a2a2a; padding: 8px; text-align: left; border: 1px solid #3a3a3a; color: #aaaaaa; }}
td {{ padding: 6px 8px; border: 1px solid #3a3a3a; }}
.score {{ font-size: 36px; font-weight: bold; color: {vcolor}; }}
.verdict {{ font-size: 20px; font-weight: bold; color: {vcolor}; }}
</style></head><body>
<h1>Phishing Email Analysis Report</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<h2>Email Details</h2>
<p><strong>Subject:</strong> {a['subject']}<br>
<strong>From:</strong> {a['from']}<br>
<strong>Return-Path:</strong> {a['return_path']}<br>
<strong>Date:</strong> {a['date']}</p>
<h2>Authentication Results</h2>
<p><span style="color:{spf_c};font-weight:bold;">SPF: {a['auth']['spf'].upper()}</span> |
<span style="color:{dkim_c};font-weight:bold;">DKIM: {a['auth']['dkim'].upper()}</span> |
<span style="color:{dmarc_c};font-weight:bold;">DMARC: {a['auth']['dmarc'].upper()}</span></p>
<h2>Risk Assessment</h2>
<p><span class="score">{a['risk']['score']}</span>/100 - <span class="verdict">{a['risk']['verdict']}</span></p>
<table><tr><th>Factor</th><th>Points</th></tr>{breakdown_rows}</table>
<h2>URLs ({len(a['urls'])})</h2>
<table><tr><th>Defanged URL</th><th>Domain</th><th>Risk</th><th>Reasons</th></tr>{url_rows}</table>
<h2>Attachments ({len(a['attachments'])})</h2>
<table><tr><th>Filename</th><th>MIME</th><th>Size</th><th>Macro</th><th>Risk</th></tr>{att_rows}</table>
</body></html>"""

    # ---- Helpers ----

    def _status_color(self, status: str) -> str:
        s = status.lower()
        if s == "pass":
            return "#228b22"
        elif s == "softfail":
            return "#cc9900"
        elif s == "fail":
            return "#cc2828"
        return "#888888"

    def _risk_color(self, risk: str) -> QColor:
        r = risk.lower()
        if r == "high":
            return COLOR_RED
        elif r == "medium":
            return COLOR_YELLOW
        elif r == "low":
            return COLOR_GREEN
        return COLOR_GRAY

    def _html_risk_color(self, risk: str) -> str:
        r = risk.lower()
        if r == "high":
            return "#cc2828"
        elif r == "medium":
            return "#cc9900"
        elif r == "low":
            return "#228b22"
        return "#888888"


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET)
    app.setFont(QFont("Segoe UI", 10))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
