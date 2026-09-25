"""
Log Anonymizer/Redactor for Safe Log Sharing
A PySide6 GUI application for detecting and redacting PII/secrets from logs.
"""

import sys
import os
import re
import hmac
import hashlib
import json
import csv
import random
import string
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QCheckBox, QTextEdit, QFileDialog,
    QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QGroupBox, QGridLayout, QLineEdit, QTabWidget, QMessageBox,
    QRadioButton, QButtonGroup, QFrame, QScrollArea, QSizePolicy
)
from PySide6.QtCore import Qt, QThread, Signal, Slot, QSize
from PySide6.QtGui import QFont, QColor, QPalette, QIcon, QSyntaxHighlighter, QTextCharFormat


# ============================================
# Constants and Configuration
# ============================================

VERSION = "1.0.0"
APP_NAME = "Log Anonymizer/Redactor"

# Color coding for detection types
COLORS = {
    "email": "#2196F3",      # Blue
    "ip_address": "#4CAF50", # Green
    "uuid": "#9C27B0",       # Purple
    "api_key": "#F44336",    # Red
    "bearer_token": "#F44336", # Red
    "aws_key": "#F44336",    # Red
    "ssn": "#FF9800",        # Orange
    "credit_card": "#FF9800", # Orange
    "password": "#F44336",   # Red
    "hostname": "#607D8B"    # Blue Grey
}

DETECTION_LABELS = {
    "email": "Email",
    "ip_address": "IP Address",
    "uuid": "UUID",
    "api_key": "API Key",
    "bearer_token": "Bearer Token",
    "aws_key": "AWS Key",
    "ssn": "SSN",
    "credit_card": "Credit Card",
    "password": "Password",
    "hostname": "Hostname"
}

# Profile configurations
PROFILES = {
    "GDPR": ["email", "ip_address", "uuid", "ssn"],
    "HIPAA": ["email", "ssn", "ip_address", "uuid"],
    "PCI DSS": ["credit_card", "api_key", "bearer_token", "aws_key"],
    "Basic": ["email", "ip_address", "ssn"],
    "Strict": list(DETECTION_LABELS.keys()),
    "Custom": []
}

# Regex patterns for detection
PATTERNS = {
    "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "ip_address": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
    "uuid": re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'),
    "api_key": re.compile(r'(?:api[_-]?key|apikey|ak_live|ak_test)[=:]\s*["\']?([a-zA-Z0-9]{20,})["\']?|ak_(?:live|test)_[a-zA-Z0-9]{20,}', re.IGNORECASE),
    "bearer_token": re.compile(r'Bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+|sk-proj-[a-zA-Z0-9]{20,}'),
    "aws_key": re.compile(r'AKIA[0-9A-Z]{16}|(?:aws[_-]?secret|wJalrXUtnFEMI)[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?'),
    "ssn": re.compile(r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b'),
    "credit_card": re.compile(r'\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b'),
    "password": re.compile(r'(?:password|passwd|pwd)[=:]\s*["\']?(\S+)["\']?', re.IGNORECASE),
    "hostname": re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:com|org|net|io|co|internal)\b')
}


# ============================================
# Core Redaction Engine
# ============================================

class RedactionEngine:
    """Core engine for detecting and redacting sensitive information."""
    
    def __init__(self, salt: Optional[bytes] = None):
        self.salt = salt or os.urandom(32)
        self.token_cache: Dict[str, str] = {}
        self.detection_stats: Dict[str, int] = {k: 0 for k in DETECTION_LABELS.keys()}
    
    def generate_salt(self) -> bytes:
        """Generate a new random salt."""
        self.salt = os.urandom(32)
        return self.salt
    
    def load_salt(self, filepath: str) -> bool:
        """Load salt from file."""
        try:
            with open(filepath, 'rb') as f:
                self.salt = f.read()
            return True
        except Exception:
            return False
    
    def save_salt(self, filepath: str) -> bool:
        """Save salt to file."""
        try:
            with open(filepath, 'wb') as f:
                f.write(self.salt)
            return True
        except Exception:
            return False
    
    def tokenize(self, value: str, detection_type: str) -> str:
        """Create deterministic token for a value."""
        cache_key = f"{value}:{detection_type}"
        if cache_key in self.token_cache:
            return self.token_cache[cache_key]
        
        # Create HMAC using salt
        hmac_obj = hmac.new(self.salt, value.encode('utf-8'), hashlib.sha256)
        hash_hex = hmac_obj.hexdigest()
        
        # Create short token (8 chars)
        short_hash = hash_hex[:8]
        
        # Format based on type
        type_prefix = {
            "email": "EMAIL",
            "ip_address": "IP",
            "uuid": "UUID",
            "api_key": "APIKEY",
            "bearer_token": "TOKEN",
            "aws_key": "AWSKEY",
            "ssn": "SSN",
            "credit_card": "CARD",
            "password": "PASS",
            "hostname": "HOST"
        }
        
        token = f"[{type_prefix.get(detection_type, 'DATA')}]_{short_hash}"
        self.token_cache[cache_key] = token
        return token
    
    def mask_value(self, value: str, detection_type: str) -> str:
        """Mask value showing first/last characters."""
        if len(value) <= 4:
            return "*" * len(value)
        
        if detection_type == "email":
            parts = value.split("@")
            if len(parts) == 2:
                masked_local = parts[0][0] + "***" + parts[0][-1] if len(parts[0]) > 2 else "***"
                domain_parts = parts[1].split(".")
                masked_domain = domain_parts[0][0] + "***" if len(domain_parts[0]) > 1 else "***"
                return f"{masked_local}@{masked_domain}.{'.'.join(domain_parts[1:])}"
        
        if detection_type == "ip_address":
            parts = value.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.*.*.*"
        
        # Default masking
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
    
    def redact_value(self, value: str, detection_type: str, strategy: str) -> str:
        """Apply redaction strategy to a detected value."""
        self.detection_stats[detection_type] = self.detection_stats.get(detection_type, 0) + 1
        
        if strategy == "tokenize":
            return self.tokenize(value, detection_type)
        elif strategy == "mask":
            return self.mask_value(value, detection_type)
        elif strategy == "redact":
            return "[REDACTED]"
        elif strategy == "label":
            return f"[{DETECTION_LABELS.get(detection_type, 'DATA').upper()}]"
        else:
            return self.tokenize(value, detection_type)
    
    def detect_and_redact(self, text: str, enabled_detectors: List[str], 
                          strategy: str = "tokenize") -> Tuple[str, List[Dict]]:
        """Detect sensitive data and apply redaction."""
        self.detection_stats = {k: 0 for k in DETECTION_LABELS.keys()}
        detections = []
        result = text
        
        # Process in order of specificity (most specific first)
        detection_order = [
            "aws_key", "bearer_token", "api_key", "password",
            "credit_card", "ssn", "email", "uuid", "ip_address", "hostname"
        ]
        
        for det_type in detection_order:
            if det_type not in enabled_detectors:
                continue
            
            pattern = PATTERNS.get(det_type)
            if not pattern:
                continue
            
            # Find all matches
            for match in pattern.finditer(text):
                value = match.group(0)
                start = match.start()
                end = match.end()
                
                # Record detection
                detections.append({
                    "type": det_type,
                    "value": value,
                    "start": start,
                    "end": end,
                    "replacement": self.redact_value(value, det_type, strategy)
                })
            
            # Apply redactions (reverse order to maintain positions)
            matches = list(pattern.finditer(result))
            for match in reversed(matches):
                value = match.group(0)
                replacement = self.redact_value(value, det_type, strategy)
                result = result[:match.start()] + replacement + result[match.end():]
        
        return result, detections


# ============================================
# Syntax Highlighter for Preview
# ============================================

class LogHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for log content with colored detection markers."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlight_rules = []
    
    def add_detection_rules(self, detections: List[Dict]):
        """Add rules for highlighting detected items."""
        self.highlight_rules = []
        
        for detection in detections:
            fmt = QTextCharFormat()
            color = QColor(COLORS.get(detection["type"], "#FFFFFF"))
            fmt.setForeground(color)
            fmt.setFontWeight(QFont.Bold)
            
            # Create pattern for this specific value
            escaped = re.escape(detection["value"])
            self.highlight_rules.append((re.compile(escaped), fmt))
        
        self.rehighlight()
    
    def highlightBlock(self, text: str):
        """Apply highlighting to a block of text."""
        for pattern, fmt in self.highlight_rules:
            for match in pattern.finditer(text):
                start = match.start()
                length = match.end() - start
                self.setFormat(start, length, fmt)


# ============================================
# Worker Thread for Processing
# ============================================

class ProcessingWorker(QThread):
    """Worker thread for processing log files."""
    
    progress = Signal(int, str)
    finished = Signal(str, list, dict)
    error = Signal(str)
    
    def __init__(self, content: str, engine: RedactionEngine, 
                 enabled_detectors: List[str], strategy: str):
        super().__init__()
        self.content = content
        self.engine = engine
        self.enabled_detectors = enabled_detectors
        self.strategy = strategy
        self._is_cancelled = False
    
    def cancel(self):
        self._is_cancelled = True
    
    def run(self):
        try:
            lines = self.content.split('\n')
            total_lines = len(lines)
            redacted_lines = []
            all_detections = []
            
            for i, line in enumerate(lines):
                if self._is_cancelled:
                    break
                
                redacted_line, detections = self.engine.detect_and_redact(
                    line, self.enabled_detectors, self.strategy
                )
                redacted_lines.append(redacted_line)
                all_detections.extend(detections)
                
                # Emit progress every 10 lines
                if (i + 1) % 10 == 0 or i == total_lines - 1:
                    progress_pct = int((i + 1) / total_lines * 100)
                    self.progress.emit(progress_pct, f"Processing line {i + 1}/{total_lines}")
            
            result = '\n'.join(redacted_lines)
            stats = dict(self.engine.detection_stats)
            stats["total_lines"] = total_lines
            stats["total_detections"] = sum(self.engine.detection_stats.values())
            
            self.finished.emit(result, all_detections, stats)
            
        except Exception as e:
            self.error.emit(str(e))


# ============================================
# Main Application Window
# ============================================

class LogAnonymizerApp(QMainWindow):
    """Main application window for Log Anonymizer/Redactor."""
    
    def __init__(self):
        super().__init__()
        self.engine = RedactionEngine()
        self.worker = None
        self.current_detections = []
        self.processing_stats = {}
        
        self.setup_ui()
        self.apply_styles()
    
    def setup_ui(self):
        """Set up the user interface."""
        self.setWindowTitle(f"{APP_NAME} v{VERSION}")
        self.setMinimumSize(1200, 800)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        # Safety Banner
        self.create_safety_banner(main_layout)
        
        # Main splitter
        main_splitter = QSplitter(Qt.Vertical)
        
        # Top section - Configuration
        config_widget = QWidget()
        config_layout = QHBoxLayout(config_widget)
        config_layout.setContentsMargins(0, 0, 0, 0)
        
        # Left panel - Input and Profile
        left_panel = self.create_left_panel()
        config_layout.addWidget(left_panel, 1)
        
        # Right panel - Detectors and Salt
        right_panel = self.create_right_panel()
        config_layout.addWidget(right_panel, 1)
        
        main_splitter.addWidget(config_widget)
        
        # Bottom section - Preview and Stats
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        
        # Preview tabs
        self.preview_tabs = QTabWidget()
        self.create_preview_tabs()
        bottom_layout.addWidget(self.preview_tabs)
        
        # Progress and Stats
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        bottom_layout.addWidget(self.progress_bar)
        
        self.stats_label = QLabel("Ready")
        self.stats_label.setAlignment(Qt.AlignCenter)
        bottom_layout.addWidget(self.stats_label)
        
        # Action buttons
        buttons_layout = QHBoxLayout()
        
        self.load_demo_btn = QPushButton("Load Demo Data")
        self.load_demo_btn.clicked.connect(self.load_demo_data)
        buttons_layout.addWidget(self.load_demo_btn)
        
        self.upload_btn = QPushButton("Upload Log File")
        self.upload_btn.clicked.connect(self.upload_log_file)
        buttons_layout.addWidget(self.upload_btn)
        
        self.process_btn = QPushButton("Process / Redact")
        self.process_btn.clicked.connect(self.process_content)
        buttons_layout.addWidget(self.process_btn)
        
        self.export_btn = QPushButton("Export Report")
        self.export_btn.clicked.connect(self.export_report)
        buttons_layout.addWidget(self.export_btn)
        
        self.clear_btn = QPushButton("Clear All")
        self.clear_btn.clicked.connect(self.clear_all)
        buttons_layout.addWidget(self.clear_btn)
        
        bottom_layout.addLayout(buttons_layout)
        
        main_splitter.addWidget(bottom_widget)
        main_splitter.setStretchFactor(0, 1)
        main_splitter.setStretchFactor(1, 2)
        
        main_layout.addWidget(main_splitter)
    
    def create_safety_banner(self, layout: QVBoxLayout):
        """Create the safety warning banner."""
        banner = QFrame()
        banner.setStyleSheet("""
            QFrame {
                background-color: #FFF3E0;
                border: 2px solid #FF9800;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        banner_layout = QHBoxLayout(banner)
        
        warning_icon = QLabel("⚠")
        warning_icon.setStyleSheet("font-size: 24px; color: #FF9800;")
        banner_layout.addWidget(warning_icon)
        
        warning_text = QLabel(
            "<b>SAFETY NOTICE:</b> This tool performs automated redaction of sensitive data. "
            "Always verify redacted output before sharing. No automated tool can guarantee "
            "100% detection of all sensitive information."
        )
        warning_text.setWordWrap(True)
        banner_layout.addWidget(warning_text, 1)
        
        layout.addWidget(banner)
    
    def create_left_panel(self) -> QWidget:
        """Create the left configuration panel."""
        panel = QGroupBox("Input & Profile")
        layout = QVBoxLayout(panel)
        
        # Input Mode
        input_group = QGroupBox("Input Mode")
        input_layout = QHBoxLayout()
        
        self.input_file_radio = QRadioButton("File")
        self.input_dir_radio = QRadioButton("Directory")
        self.input_paste_radio = QRadioButton("Paste Text")
        self.input_file_radio.setChecked(True)
        
        self.input_btn_group = QButtonGroup()
        self.input_btn_group.addButton(self.input_file_radio, 1)
        self.input_btn_group.addButton(self.input_dir_radio, 2)
        self.input_btn_group.addButton(self.input_paste_radio, 3)
        self.input_btn_group.buttonClicked.connect(self.input_mode_changed)
        
        input_layout.addWidget(self.input_file_radio)
        input_layout.addWidget(self.input_dir_radio)
        input_layout.addWidget(self.input_paste_radio)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # File/Directory selector
        path_layout = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Select file or directory...")
        path_layout.addWidget(self.path_input)
        
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_path)
        path_layout.addWidget(self.browse_btn)
        layout.addLayout(path_layout)
        
        # Paste text area
        self.paste_text = QTextEdit()
        self.paste_text.setPlaceholderText("Paste your log content here...")
        self.paste_text.setMaximumHeight(100)
        self.paste_text.setVisible(False)
        layout.addWidget(self.paste_text)
        
        # Profile Selector
        profile_group = QGroupBox("Redaction Profile")
        profile_layout = QVBoxLayout()
        
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(PROFILES.keys())
        self.profile_combo.currentTextChanged.connect(self.profile_changed)
        profile_layout.addWidget(self.profile_combo)
        
        self.profile_desc = QLabel("GDPR: Email, IP, UUID, SSN")
        self.profile_desc.setStyleSheet("color: #666; font-style: italic;")
        profile_layout.addWidget(self.profile_desc)
        
        profile_group.setLayout(profile_layout)
        layout.addWidget(profile_group)
        
        # Replacement Strategy
        strategy_group = QGroupBox("Replacement Strategy")
        strategy_layout = QVBoxLayout()
        
        self.strategy_combo = QComboBox()
        self.strategy_combo.addItems(["tokenize", "mask", "redact", "label"])
        strategy_layout.addWidget(self.strategy_combo)
        
        strategy_desc = QLabel("Tokenize: Same input = same output token")
        strategy_desc.setStyleSheet("color: #666; font-style: italic;")
        self.strategy_combo.currentTextChanged.connect(
            lambda t: strategy_desc.setText({
                "tokenize": "Tokenize: Same input = same output token",
                "mask": "Mask: Partially visible (j***@***.com)",
                "redact": "Redact: Complete removal [REDACTED]",
                "label": "Label: Type only [EMAIL]"
            }.get(t, ""))
        )
        strategy_layout.addWidget(strategy_desc)
        
        strategy_group.setLayout(strategy_layout)
        layout.addWidget(strategy_group)
        
        layout.addStretch()
        return panel
    
    def create_right_panel(self) -> QWidget:
        """Create the right configuration panel."""
        panel = QGroupBox("Detectors & Salt")
        layout = QVBoxLayout(panel)
        
        # Detector Checkboxes
        detectors_group = QGroupBox("Enable Detectors")
        detectors_layout = QGridLayout()
        
        self.detector_checkboxes = {}
        row, col = 0, 0
        for det_type, label in DETECTION_LABELS.items():
            cb = QCheckBox(label)
            cb.setChecked(True)
            cb.setStyleSheet(f"QCheckBox::indicator:checked {{ background-color: {COLORS[det_type]}; }}")
            self.detector_checkboxes[det_type] = cb
            detectors_layout.addWidget(cb, row, col)
            col += 1
            if col >= 2:
                col = 0
                row += 1
        
        detectors_group.setLayout(detectors_layout)
        layout.addWidget(detectors_group)
        
        # Salt Manager
        salt_group = QGroupBox("Salt Manager (for Deterministic Tokenization)")
        salt_layout = QVBoxLayout()
        
        self.salt_display = QLineEdit()
        self.salt_display.setReadOnly(True)
        self.salt_display.setPlaceholderText("No salt loaded")
        salt_layout.addWidget(self.salt_display)
        
        salt_buttons = QHBoxLayout()
        
        generate_salt_btn = QPushButton("Generate New")
        generate_salt_btn.clicked.connect(self.generate_salt)
        salt_buttons.addWidget(generate_salt_btn)
        
        load_salt_btn = QPushButton("Load Salt")
        load_salt_btn.clicked.connect(self.load_salt)
        salt_buttons.addWidget(load_salt_btn)
        
        save_salt_btn = QPushButton("Save Salt")
        save_salt_btn.clicked.connect(self.save_salt)
        salt_buttons.addWidget(save_salt_btn)
        
        salt_layout.addLayout(salt_buttons)
        salt_group.setLayout(salt_layout)
        layout.addWidget(salt_group)
        
        layout.addStretch()
        return panel
    
    def create_preview_tabs(self):
        """Create the preview tab widgets."""
        # Side by Side View
        side_by_side_widget = QWidget()
        side_by_side_layout = QHBoxLayout(side_by_side_widget)
        side_by_side_layout.setContentsMargins(0, 0, 0, 0)
        
        # Original
        orig_group = QGroupBox("Original")
        orig_layout = QVBoxLayout()
        self.original_text = QTextEdit()
        self.original_text.setReadOnly(True)
        self.original_highlighter = LogHighlighter(self.original_text.document())
        orig_layout.addWidget(self.original_text)
        orig_group.setLayout(orig_layout)
        side_by_side_layout.addWidget(orig_group)
        
        # Redacted
        red_group = QGroupBox("Redacted")
        red_layout = QVBoxLayout()
        self.redacted_text = QTextEdit()
        self.redacted_text.setReadOnly(True)
        self.redacted_highlighter = LogHighlighter(self.redacted_text.document())
        red_layout.addWidget(self.redacted_text)
        red_group.setLayout(red_layout)
        side_by_side_layout.addWidget(red_group)
        
        self.preview_tabs.addTab(side_by_side_widget, "Side by Side")
        
        # Diff View
        diff_widget = QWidget()
        diff_layout = QVBoxLayout(diff_widget)
        self.diff_text = QTextEdit()
        self.diff_text.setReadOnly(True)
        diff_layout.addWidget(self.diff_text)
        self.preview_tabs.addTab(diff_widget, "Diff View")
        
        # Detection Table
        detection_widget = QWidget()
        detection_layout = QVBoxLayout(detection_widget)
        self.detection_table = QTableWidget()
        self.detection_table.setColumnCount(4)
        self.detection_table.setHorizontalHeaderLabels(["Type", "Value", "Replacement", "Position"])
        self.detection_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        detection_layout.addWidget(self.detection_table)
        self.preview_tabs.addTab(detection_widget, "Detections")
        
        # Stats View
        stats_widget = QWidget()
        stats_layout = QVBoxLayout(stats_widget)
        self.stats_table = QTableWidget()
        self.stats_table.setColumnCount(2)
        self.stats_table.setHorizontalHeaderLabels(["Detection Type", "Count"])
        self.stats_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        stats_layout.addWidget(self.stats_table)
        self.preview_tabs.addTab(stats_widget, "Statistics")
    
    def apply_styles(self):
        """Apply application styles."""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 8px;
                margin-top: 1em;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #1565C0;
            }
            QProgressBar {
                border: 2px solid #cccccc;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 3px;
            }
            QTextEdit {
                border: 1px solid #cccccc;
                border-radius: 4px;
                font-family: Consolas, monospace;
                font-size: 12px;
            }
            QTableWidget {
                border: 1px solid #cccccc;
                border-radius: 4px;
            }
            QTableWidget::item:selected {
                background-color: #E3F2FD;
            }
        """)
    
    # ============================================
    # Slot Methods
    # ============================================
    
    def input_mode_changed(self, button):
        """Handle input mode change."""
        mode = self.input_btn_group.checkedId()
        self.path_input.setVisible(mode != 3)
        self.browse_btn.setVisible(mode != 3)
        self.paste_text.setVisible(mode == 3)
    
    def browse_path(self):
        """Browse for file or directory."""
        mode = self.input_btn_group.checkedId()
        
        if mode == 1:  # File
            path, _ = QFileDialog.getOpenFileName(
                self, "Select Log File", "",
                "Log Files (*.log *.txt *.csv);;All Files (*)"
            )
        else:  # Directory
            path = QFileDialog.getExistingDirectory(self, "Select Directory")
        
        if path:
            self.path_input.setText(path)
    
    def profile_changed(self, profile_name: str):
        """Handle profile selection change."""
        detectors = PROFILES.get(profile_name, [])
        for det_type, cb in self.detector_checkboxes.items():
            if profile_name == "Custom":
                cb.setChecked(True)
            else:
                cb.setChecked(det_type in detectors)
        
        desc = {
            "GDPR": "Email, IP, UUID, SSN",
            "HIPAA": "Email, SSN, IP, UUID",
            "PCI DSS": "Credit Card, API Key, Bearer Token, AWS Key",
            "Basic": "Email, IP, SSN",
            "Strict": "All detectors enabled",
            "Custom": "User-configured"
        }.get(profile_name, "")
        self.profile_desc.setText(f"{profile_name}: {desc}")
    
    def generate_salt(self):
        """Generate a new random salt."""
        salt = self.engine.generate_salt()
        self.salt_display.setText(salt.hex()[:32] + "...")
        QMessageBox.information(self, "Salt Generated", "New salt generated successfully.")
    
    def load_salt(self):
        """Load salt from file."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Salt File", "",
            "Salt Files (*.salt *.bin);;All Files (*)"
        )
        if path:
            if self.engine.load_salt(path):
                self.salt_display.setText(self.engine.salt.hex()[:32] + "...")
                QMessageBox.information(self, "Salt Loaded", "Salt loaded successfully.")
            else:
                QMessageBox.warning(self, "Error", "Failed to load salt file.")
    
    def save_salt(self):
        """Save salt to file."""
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Salt File", "redaction.salt",
            "Salt Files (*.salt *.bin);;All Files (*)"
        )
        if path:
            if self.engine.save_salt(path):
                QMessageBox.information(self, "Salt Saved", "Salt saved successfully.")
            else:
                QMessageBox.warning(self, "Error", "Failed to save salt file.")
    
    def load_demo_data(self):
        """Load sample log data for demonstration."""
        # Generate demo content
        demo_content = """2024-01-15 08:23:11 [INFO] User login successful: john.doe@example.com from 192.168.1.105
2024-01-15 08:23:15 [DEBUG] Session token generated: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
2024-01-15 08:24:01 [INFO] API key validated: ak_live_4eC39HqLyjWDarjtT1zdp7dc
2024-01-15 08:24:30 [WARN] Failed login attempt for user admin@company.org from 10.0.0.55
2024-01-15 08:25:12 [INFO] Password reset requested for: sarah.connor@skynet.com
2024-01-15 08:25:45 [ERROR] Database connection failed: host=db.prod.internal port=5432 user=app_user password=SuperSecret123!
2024-01-15 08:26:01 [INFO] AWS credentials detected: AKIAIOSFODNN7EXAMPLE
2024-01-15 08:26:30 [DEBUG] UUID detected: 550e8400-e29b-41d4-a716-446655440000
2024-01-15 08:27:15 [INFO] Credit card transaction: card number 4111-1111-1111-1111, amount $250.00
2024-01-15 08:27:45 [WARN] SSN found in record: 123-45-6789
2024-01-15 08:28:01 [INFO] Email sent to user@example.com regarding account update
2024-01-15 08:28:30 [DEBUG] Connection from IP: 172.16.0.100 established
2024-01-15 08:29:01 [ERROR] Authentication failed for user: bob.miller@test.co.uk
2024-01-15 08:29:30 [INFO] API endpoint /api/v1/users accessed by client_id=9876543210
2024-01-15 08:30:01 [WARN] Suspicious activity from 203.0.113.42 - multiple failed attempts"""
        
        self.original_text.setPlainText(demo_content)
        self.redacted_text.clear()
        self.diff_text.clear()
        self.detection_table.setRowCount(0)
        self.stats_table.setRowCount(0)
        self.current_detections = []
        self.processing_stats = {}
        self.stats_label.setText("Demo data loaded. Click 'Process / Redact' to begin.")
    
    def upload_log_file(self):
        """Upload a log file."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Upload Log File", "",
            "Log Files (*.log *.txt *.csv);;All Files (*)"
        )
        if path:
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                self.original_text.setPlainText(content)
                self.redacted_text.clear()
                self.diff_text.clear()
                self.detection_table.setRowCount(0)
                self.stats_table.setRowCount(0)
                self.current_detections = []
                self.processing_stats = {}
                self.path_input.setText(path)
                self.stats_label.setText(f"Loaded: {os.path.basename(path)}")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to load file:\n{str(e)}")
    
    def get_content_to_process(self) -> str:
        """Get content based on current input mode."""
        mode = self.input_btn_group.checkedId()
        
        if mode == 3:  # Paste
            return self.paste_text.toPlainText()
        else:  # File or Directory
            path = self.path_input.text()
            if not path:
                return self.original_text.toPlainText()
            
            if os.path.isfile(path):
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        return f.read()
                except Exception:
                    return self.original_text.toPlainText()
            elif os.path.isdir(path):
                # Process all log files in directory
                combined = []
                for file in Path(path).glob("*.log"):
                    try:
                        with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                            combined.append(f"=== {file.name} ===\n{f.read()}")
                    except Exception:
                        pass
                for file in Path(path).glob("*.txt"):
                    try:
                        with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                            combined.append(f"=== {file.name} ===\n{f.read()}")
                    except Exception:
                        pass
                return '\n'.join(combined)
            
            return self.original_text.toPlainText()
    
    def process_content(self):
        """Process and redact the content."""
        content = self.original_text.toPlainText()
        if not content:
            content = self.get_content_to_process()
        
        if not content.strip():
            QMessageBox.warning(self, "No Content", "Please load or paste content to process.")
            return
        
        # Get enabled detectors
        enabled = [t for t, cb in self.detector_checkboxes.items() if cb.isChecked()]
        if not enabled:
            QMessageBox.warning(self, "No Detectors", "Please enable at least one detector.")
            return
        
        strategy = self.strategy_combo.currentText()
        
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.process_btn.setEnabled(False)
        
        # Start worker thread
        self.worker = ProcessingWorker(content, self.engine, enabled, strategy)
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_processing_finished)
        self.worker.error.connect(self.on_processing_error)
        self.worker.start()
    
    @Slot(int, str)
    def on_progress(self, value: int, message: str):
        """Handle progress updates."""
        self.progress_bar.setValue(value)
        self.stats_label.setText(message)
    
    @Slot(str, list, dict)
    def on_processing_finished(self, result: str, detections: List[Dict], stats: Dict):
        """Handle processing completion."""
        self.progress_bar.setVisible(False)
        self.process_btn.setEnabled(True)
        
        self.current_detections = detections
        self.processing_stats = stats
        
        # Update preview
        self.redacted_text.setPlainText(result)
        self.update_diff_view(self.original_text.toPlainText(), result)
        self.update_detection_table(detections)
        self.update_stats_table(stats)
        
        # Highlight detections
        self.original_highlighter.add_detection_rules(detections)
        
        # Update stats label
        total = stats.get("total_detections", 0)
        lines = stats.get("total_lines", 0)
        self.stats_label.setText(
            f"Processed {lines} lines | Found {total} detections | "
            f"Redaction ratio: {total/max(len(self.original_text.toPlainText()), 1)*100:.2f}%"
        )
    
    @Slot(str)
    def on_processing_error(self, error_msg: str):
        """Handle processing error."""
        self.progress_bar.setVisible(False)
        self.process_btn.setEnabled(True)
        QMessageBox.critical(self, "Processing Error", f"An error occurred:\n{error_msg}")
    
    def update_diff_view(self, original: str, redacted: str):
        """Update the diff view with changes highlighted."""
        orig_lines = original.split('\n')
        red_lines = redacted.split('\n')
        
        diff_content = []
        max_lines = max(len(orig_lines), len(red_lines))
        
        for i in range(max_lines):
            orig = orig_lines[i] if i < len(orig_lines) else ""
            red = red_lines[i] if i < len(red_lines) else ""
            
            if orig != red:
                diff_content.append(f"<span style='color: #F44336;'>- {orig}</span>")
                diff_content.append(f"<span style='color: #4CAF50;'>+ {red}</span>")
            else:
                diff_content.append(f"<span style='color: #666;'>  {orig}</span>")
        
        self.diff_text.setHtml('<pre>' + '\n'.join(diff_content) + '</pre>')
    
    def update_detection_table(self, detections: List[Dict]):
        """Update the detection table."""
        self.detection_table.setRowCount(len(detections))
        
        for row, detection in enumerate(detections):
            # Type with color
            type_item = QTableWidgetItem(DETECTION_LABELS.get(detection["type"], detection["type"]))
            type_item.setBackground(QColor(COLORS.get(detection["type"], "#FFFFFF")))
            self.detection_table.setItem(row, 0, type_item)
            
            # Value
            value_item = QTableWidgetItem(detection["value"])
            self.detection_table.setItem(row, 1, value_item)
            
            # Replacement
            repl_item = QTableWidgetItem(detection["replacement"])
            self.detection_table.setItem(row, 2, repl_item)
            
            # Position
            pos_item = QTableWidgetItem(f"{detection['start']}-{detection['end']}")
            self.detection_table.setItem(row, 3, pos_item)
    
    def update_stats_table(self, stats: Dict):
        """Update the statistics table."""
        stats_items = [(k, v) for k, v in stats.items() 
                      if k in DETECTION_LABELS and v > 0]
        stats_items.sort(key=lambda x: x[1], reverse=True)
        
        self.stats_table.setRowCount(len(stats_items))
        
        for row, (det_type, count) in enumerate(stats_items):
            type_item = QTableWidgetItem(DETECTION_LABELS.get(det_type, det_type))
            type_item.setBackground(QColor(COLORS.get(det_type, "#FFFFFF")))
            self.stats_table.setItem(row, 0, type_item)
            
            count_item = QTableWidgetItem(str(count))
            self.stats_table.setItem(row, 1, count_item)
    
    def export_report(self):
        """Export redaction report."""
        if not self.current_detections and not self.processing_stats:
            QMessageBox.warning(self, "No Data", "No redaction data to export. Process content first.")
            return
        
        # Get export format
        formats = ["JSON", "CSV", "HTML", "PDF"]
        format_choice, ok = QInputDialog.getItem(
            self, "Export Format", "Select format:", formats, 0, False
        )
        
        if not ok:
            return
        
        # Get save path
        extensions = {"JSON": "json", "CSV": "csv", "HTML": "html", "PDF": "pdf"}
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", f"redaction_report.{extensions[format_choice]}",
            f"{format_choice} Files (*.{extensions[format_choice]})"
        )
        
        if not path:
            return
        
        try:
            if format_choice == "JSON":
                self.export_json(path)
            elif format_choice == "CSV":
                self.export_csv(path)
            elif format_choice == "HTML":
                self.export_html(path)
            elif format_choice == "PDF":
                self.export_pdf(path)
            
            QMessageBox.information(self, "Export Complete", f"Report exported to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export:\n{str(e)}")
    
    def export_json(self, path: str):
        """Export report as JSON."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "statistics": self.processing_stats,
            "detections": self.current_detections,
            "settings": {
                "profile": self.profile_combo.currentText(),
                "strategy": self.strategy_combo.currentText(),
                "detectors": {t: cb.isChecked() for t, cb in self.detector_checkboxes.items()}
            }
        }
        
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    def export_csv(self, path: str):
        """Export report as CSV."""
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Type", "Original Value", "Replacement", "Start Position", "End Position"])
            
            for detection in self.current_detections:
                writer.writerow([
                    detection["type"],
                    detection["value"],
                    detection["replacement"],
                    detection["start"],
                    detection["end"]
                ])
    
    def export_html(self, path: str):
        """Export report as HTML."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Log Redaction Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .email {{ color: #2196F3; }}
        .ip {{ color: #4CAF50; }}
        .secret {{ color: #F44336; }}
        .pii {{ color: #FF9800; }}
    </style>
</head>
<body>
    <h1>Log Redaction Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>Profile: {self.profile_combo.currentText()}</p>
    <p>Strategy: {self.strategy_combo.currentText()}</p>
    
    <h2>Statistics</h2>
    <table>
        <tr><th>Type</th><th>Count</th></tr>
"""
        for det_type, count in self.processing_stats.items():
            if det_type in DETECTION_LABELS and count > 0:
                html += f"        <tr><td>{DETECTION_LABELS[det_type]}</td><td>{count}</td></tr>\n"
        
        html += """    </table>
    
    <h2>Detections</h2>
    <table>
        <tr><th>Type</th><th>Value</th><th>Replacement</th></tr>
"""
        for detection in self.current_detections:
            type_class = "secret" if detection["type"] in ["api_key", "bearer_token", "aws_key", "password"] else \
                        "pii" if detection["type"] in ["ssn", "credit_card"] else \
                        "email" if detection["type"] == "email" else "ip"
            html += f'        <tr><td class="{type_class}">{DETECTION_LABELS.get(detection["type"], detection["type"])}</td>'
            html += f"<td>{detection['value']}</td>"
            html += f"<td>{detection['replacement']}</td></tr>\n"
        
        html += """    </table>
</body>
</html>"""
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def export_pdf(self, path: str):
        """Export report as PDF."""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            
            c = canvas.Canvas(path, pagesize=letter)
            width, height = letter
            
            # Title
            c.setFont("Helvetica-Bold", 16)
            c.drawString(72, height - 72, "Log Redaction Report")
            
            # Metadata
            c.setFont("Helvetica", 10)
            c.drawString(72, height - 100, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(72, height - 115, f"Profile: {self.profile_combo.currentText()}")
            c.drawString(72, height - 130, f"Strategy: {self.strategy_combo.currentText()}")
            
            # Statistics
            c.setFont("Helvetica-Bold", 12)
            c.drawString(72, height - 160, "Statistics")
            
            y = height - 180
            c.setFont("Helvetica", 10)
            for det_type, count in self.processing_stats.items():
                if det_type in DETECTION_LABELS and count > 0:
                    c.drawString(90, y, f"{DETECTION_LABELS[det_type]}: {count}")
                    y -= 15
            
            # Detections
            c.setFont("Helvetica-Bold", 12)
            c.drawString(72, y - 20, "Detections")
            y -= 40
            
            c.setFont("Helvetica", 8)
            for detection in self.current_detections[:50]:  # Limit to 50 for PDF
                if y < 72:
                    c.showPage()
                    y = height - 72
                
                c.drawString(90, y, f"{detection['type']}: {detection['value'][:50]}... -> {detection['replacement']}")
                y -= 12
            
            c.save()
        except ImportError:
            QMessageBox.warning(self, "Missing Library", 
                              "PDF export requires reportlab. Install with: pip install reportlab")
    
    def clear_all(self):
        """Clear all content and reset."""
        self.original_text.clear()
        self.redacted_text.clear()
        self.diff_text.clear()
        self.paste_text.clear()
        self.path_input.clear()
        self.detection_table.setRowCount(0)
        self.stats_table.setRowCount(0)
        self.current_detections = []
        self.processing_stats = {}
        self.original_highlighter.add_detection_rules([])
        self.stats_label.setText("Ready")


# ============================================
# Input Dialog Helper
# ============================================

class QInputDialog:
    """Simple input dialog replacement."""
    
    @staticmethod
    def getItem(parent, title, label, items, current=0, editable=True):
        """Show a dialog to select an item."""
        from PySide6.QtWidgets import QInputDialog
        return QInputDialog.getItem(parent, title, label, items, current, editable)


# ============================================
# Main Entry Point
# ============================================

def main():
    """Main entry point for the application."""
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Set application-wide palette
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(245, 245, 245))
    palette.setColor(QPalette.WindowText, QColor(33, 33, 33))
    palette.setColor(QPalette.Base, QColor(255, 255, 255))
    palette.setColor(QPalette.AlternateBase, QColor(245, 245, 245))
    palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 220))
    palette.setColor(QPalette.ToolTipText, QColor(33, 33, 33))
    palette.setColor(QPalette.Text, QColor(33, 33, 33))
    palette.setColor(QPalette.Button, QColor(240, 240, 240))
    palette.setColor(QPalette.ButtonText, QColor(33, 33, 33))
    palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.Link, QColor(33, 150, 243))
    palette.setColor(QPalette.Highlight, QColor(33, 150, 243))
    palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    app.setPalette(palette)
    
    window = LogAnonymizerApp()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
