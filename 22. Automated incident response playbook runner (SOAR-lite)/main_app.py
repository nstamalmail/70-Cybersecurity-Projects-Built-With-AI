"""
Automated Incident Response Playbook Runner (SOAR-lite)
A PySide6 GUI application for managing and executing incident response playbooks.
"""

import sys
import os
import json
import yaml
import time
import uuid
import csv
import io
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

def _get_base_dir():
    if getattr(sys, 'frozen', False):
        return Path(sys._MEIPASS)
    return Path(__file__).parent

BASE_DIR = _get_base_dir()

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QPushButton, QLabel, QLineEdit, QTextEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QComboBox, QSpinBox, QGroupBox,
    QFormLayout, QSplitter, QTreeWidget, QTreeWidgetItem, QProgressBar,
    QDialog, QDialogButtonBox, QMessageBox, QFileDialog, QStatusBar,
    QMenuBar, QMenu, QToolBar, QFrame, QScrollArea, QGridLayout,
    QRadioButton, QCheckBox, QSizePolicy
)
from PySide6.QtCore import (
    Qt, QTimer, QThread, Signal, Slot, QSize, QPropertyAnimation,
    QEasingCurve, QUrl
)
from PySide6.QtGui import (
    QFont, QColor, QPalette, QIcon, QAction, QDesktopServices,
    QSyntaxHighlighter, QTextCharFormat, QBrush, QPainter, QPen
)


# ============================================================
# Color Constants
# ============================================================
class Colors:
    SUCCESS_GREEN = "#2ecc71"
    FAILED_RED = "#e74c3c"
    AWAITING_YELLOW = "#f39c12"
    PENDING_GRAY = "#95a5a6"
    RUNNING_BLUE = "#3498db"
    DESTRUCTIVE_ORANGE = "#e67e22"
    BG_DARK = "#1e1e2e"
    BG_MEDIUM = "#2d2d44"
    BG_LIGHT = "#3d3d5c"
    TEXT_WHITE = "#ffffff"
    TEXT_LIGHT = "#b0b0b0"
    ACCENT_PURPLE = "#9b59b6"
    BORDER_COLOR = "#4a4a6a"


# ============================================================
# Data Models
# ============================================================
class PlaybookStep:
    def __init__(self, step_data: dict):
        self.id = step_data.get("id", "")
        self.name = step_data.get("name", "")
        self.type = step_data.get("type", "action")
        self.description = step_data.get("description", "")
        self.script = step_data.get("script", "")
        self.parameters = step_data.get("parameters", {})
        self.outputs = step_data.get("outputs", [])
        self.timeout = step_data.get("timeout", 30)
        self.next = step_data.get("next", None)
        self.requires_approval = step_data.get("requires_approval", False)
        self.dependencies = step_data.get("dependencies", [])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "description": self.description,
            "script": self.script,
            "parameters": self.parameters,
            "outputs": self.outputs,
            "timeout": self.timeout,
            "next": self.next,
            "requires_approval": self.requires_approval,
        }


class Playbook:
    def __init__(self, data: dict):
        self.name = data.get("name", "Untitled Playbook")
        self.version = data.get("version", "1.0")
        self.author = data.get("author", "Unknown")
        self.description = data.get("description", "")
        self.severity = data.get("severity", "medium")
        self.tags = data.get("tags", [])
        self.triggers = data.get("triggers", [])
        self.variables = data.get("variables", {})
        self.steps = [PlaybookStep(s) for s in data.get("steps", [])]
        self.raw_data = data

    def get_step_by_id(self, step_id: str) -> Optional[PlaybookStep]:
        for step in self.steps:
            if step.id == step_id:
                return step
        return None

    def to_yaml(self) -> str:
        return yaml.dump(self.raw_data, default_flow_style=False, sort_keys=False)

    @classmethod
    def from_yaml(cls, yaml_content: str) -> "Playbook":
        data = yaml.safe_load(yaml_content)
        return cls(data)


class StepExecution:
    def __init__(self, step: PlaybookStep):
        self.step = step
        self.status = "pending"
        self.started_at = None
        self.completed_at = None
        self.duration_seconds = 0
        self.approval_required = step.requires_approval
        self.approval_status = "auto_approved" if not step.requires_approval else "pending"
        self.approved_by = None
        self.approved_at = None
        self.outputs = {}
        self.error = None
        self.rollback_status = None

    def to_dict(self) -> dict:
        return {
            "step_id": self.step.id,
            "step_name": self.step.name,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "approval_required": self.approval_required,
            "approval_status": self.approval_status,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "outputs": self.outputs,
            "error": self.error,
            "rollback_status": self.rollback_status,
        }


class Execution:
    def __init__(self, playbook: Playbook, context: dict):
        self.execution_id = f"EXEC-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8]}"
        self.playbook = playbook
        self.context = context
        self.status = "pending"
        self.started_at = None
        self.completed_at = None
        self.total_duration_seconds = 0
        self.step_executions = [StepExecution(step) for step in playbook.steps]
        self.action_log = []
        self.summary = {}

    def get_step_execution(self, step_id: str) -> Optional[StepExecution]:
        for se in self.step_executions:
            if se.step.id == step_id:
                return se
        return None

    def to_dict(self) -> dict:
        return {
            "execution_id": self.execution_id,
            "playbook_name": self.playbook.name,
            "playbook_version": self.playbook.version,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_duration_seconds": self.total_duration_seconds,
            "context": self.context,
            "steps": [se.to_dict() for se in self.step_executions],
            "action_log": self.action_log,
            "summary": self.summary,
        }


# ============================================================
# YAML Highlighter
# ============================================================
class YAMLHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rules = []
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor(Colors.ACCENT_PURPLE))
        keyword_format.setFontWeight(QFont.Bold)
        self.rules.append((r'\b(true|false|null|yes|no)\b', keyword_format))

        string_format = QTextCharFormat()
        string_format.setForeground(QColor(Colors.SUCCESS_GREEN))
        self.rules.append((r'".*?"', string_format))
        self.rules.append((r"'.*?'", string_format))

        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor(Colors.PENDING_GRAY))
        comment_format.setFontItalic(True)
        self.rules.append((r'#.*$', comment_format))

        key_format = QTextCharFormat()
        key_format.setForeground(QColor(Colors.RUNNING_BLUE))
        self.rules.append((r'^[\w-]+:', key_format))

    def highlightBlock(self, text: str):
        import re
        for pattern, fmt in self.rules:
            for match in re.finditer(pattern, text, re.MULTILINE):
                start = match.start()
                length = match.end() - start
                self.setFormat(start, length, fmt)


# ============================================================
# Approval Dialog
# ============================================================
class ApprovalDialog(QDialog):
    def __init__(self, step: PlaybookStep, context: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Approval Required - Destructive Action")
        self.setMinimumSize(500, 400)
        self.result_action = "reject"
        self.reason = ""

        layout = QVBoxLayout(self)

        warning_label = QLabel("⚠ DESTRUCTIVE ACTION REQUIRES APPROVAL")
        warning_label.setStyleSheet(f"color: {Colors.DESTRUCTIVE_ORANGE}; font-weight: bold; font-size: 14px;")
        warning_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(warning_label)

        info_group = QGroupBox("Action Details")
        info_layout = QFormLayout(info_group)

        name_label = QLabel(step.name)
        name_label.setStyleSheet("font-weight: bold;")
        info_layout.addRow("Step:", name_label)

        desc_label = QLabel(step.description)
        desc_label.setWordWrap(True)
        info_layout.addRow("Description:", desc_label)

        type_label = QLabel(step.type)
        type_label.setStyleSheet(f"color: {Colors.DESTRUCTIVE_ORANGE};")
        info_layout.addRow("Type:", type_label)

        script_label = QLabel(step.script)
        info_layout.addRow("Script:", script_label)

        layout.addWidget(info_group)

        params_group = QGroupBox("Parameters")
        params_layout = QVBoxLayout(params_group)
        params_text = QTextEdit()
        params_text.setPlainText(json.dumps(step.parameters, indent=2, default=str))
        params_text.setReadOnly(True)
        params_text.setMaximumHeight(100)
        params_layout.addWidget(params_text)
        layout.addWidget(params_group)

        context_group = QGroupBox("Incident Context")
        context_layout = QVBoxLayout(context_group)
        context_text = QTextEdit()
        context_text.setPlainText(json.dumps(context, indent=2, default=str))
        context_text.setReadOnly(True)
        context_text.setMaximumHeight(120)
        context_layout.addWidget(context_text)
        layout.addWidget(context_group)

        reason_group = QGroupBox("Approval Notes")
        reason_layout = QVBoxLayout(reason_group)
        self.reason_input = QTextEdit()
        self.reason_input.setPlaceholderText("Enter reason for approval or rejection...")
        self.reason_input.setMaximumHeight(80)
        reason_layout.addWidget(self.reason_input)
        layout.addWidget(reason_group)

        button_layout = QHBoxLayout()

        self.approve_btn = QPushButton("✓ APPROVE")
        self.approve_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {Colors.SUCCESS_GREEN};
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
            }}
            QPushButton:hover {{ background-color: #27ae60; }}
        """)
        self.approve_btn.clicked.connect(self.approve)
        button_layout.addWidget(self.approve_btn)

        self.reject_btn = QPushButton("✗ REJECT")
        self.reject_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {Colors.FAILED_RED};
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
            }}
            QPushButton:hover {{ background-color: #c0392b; }}
        """)
        self.reject_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.reject_btn)

        self.defer_btn = QPushButton("⏳ DEFER")
        self.defer_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {Colors.AWAITING_YELLOW};
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
            }}
            QPushButton:hover {{ background-color: #e67e22; }}
        """)
        self.defer_btn.clicked.connect(self.defer)
        button_layout.addWidget(self.defer_btn)

        layout.addLayout(button_layout)

    def approve(self):
        self.result_action = "approve"
        self.reason = self.reason_input.toPlainText()
        self.accept()

    def reject(self):
        self.result_action = "reject"
        self.reason = self.reason_input.toPlainText()
        self.accept()

    def defer(self):
        self.result_action = "defer"
        self.reason = self.reason_input.toPlainText()
        self.accept()


# ============================================================
# Metrics Widget
# ============================================================
class MetricsWidget(QFrame):
    def __init__(self, title: str, value: str, color: str, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {Colors.BG_MEDIUM};
                border: 2px solid {color};
                border-radius: 10px;
                padding: 15px;
            }}
        """)
        layout = QVBoxLayout(self)

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet(f"color: {color}; font-size: 12px; font-weight: bold;")
        self.title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.title_label)

        self.value_label = QLabel(value)
        self.value_label.setStyleSheet("color: white; font-size: 28px; font-weight: bold;")
        self.value_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.value_label)

    def update_value(self, value: str):
        self.value_label.setText(value)


# ============================================================
# DAG Viewer Widget
# ============================================================
class DAGViewerWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.steps = []
        self.step_positions = {}
        self.setMinimumHeight(300)
        self.setStyleSheet(f"background-color: {Colors.BG_DARK};")

    def set_steps(self, steps: list):
        self.steps = steps
        self.calculate_positions()
        self.update()

    def calculate_positions(self):
        if not self.steps:
            return
        width = self.width() if self.width() > 0 else 800
        height = self.height() if self.height() > 0 else 400
        margin = 40
        node_width = 140
        node_height = 60
        cols = min(3, len(self.steps))
        x_spacing = (width - 2 * margin - cols * node_width) / max(cols - 1, 1)
        y_spacing = (height - 2 * margin - (len(self.steps) // cols + 1) * node_height) / max(len(self.steps) // cols, 1)
        for i, step in enumerate(self.steps):
            col = i % cols
            row = i // cols
            x = margin + col * (node_width + x_spacing)
            y = margin + row * (node_height + y_spacing)
            self.step_positions[step.id] = (x, y, node_width, node_height)

    def paintEvent(self, event):
        if not self.steps:
            painter = QPainter(self)
            painter.setPen(QColor(Colors.TEXT_LIGHT))
            painter.setFont(QFont("Segoe UI", 12))
            painter.drawText(self.rect(), Qt.AlignCenter, "No playbook loaded\nLoad a playbook to view the DAG")
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        node_width = 140
        node_height = 60

        for step in self.steps:
            pos = self.step_positions.get(step.id)
            if not pos:
                continue
            x, y, w, h = pos
            if step.next and step.next in self.step_positions:
                next_pos = self.step_positions[step.next]
                painter.setPen(QPen(QColor(Colors.BORDER_COLOR), 2))
                start_x = x + w / 2
                start_y = y + h
                end_x = next_pos[0] + w / 2
                end_y = next_pos[1]
                painter.drawLine(int(start_x), int(start_y), int(end_x), int(end_y))
                painter.setBrush(QColor(Colors.BORDER_COLOR))
                arrow_size = 8
                painter.drawPolygon([
                    (int(end_x), int(end_y)),
                    (int(end_x - arrow_size), int(end_y - arrow_size * 2)),
                    (int(end_x + arrow_size), int(end_y - arrow_size * 2))
                ])

        for step in self.steps:
            pos = self.step_positions.get(step.id)
            if not pos:
                continue
            x, y, w, h = pos
            if step.type == "destructive":
                bg_color = Colors.DESTRUCTIVE_ORANGE
                border_color = Colors.FAILED_RED
            else:
                bg_color = Colors.BG_MEDIUM
                border_color = Colors.RUNNING_BLUE
            painter.setPen(QPen(QColor(border_color), 2))
            painter.setBrush(QColor(bg_color))
            painter.drawRoundedRect(int(x), int(y), int(w), int(h), 8, 8)
            painter.setPen(QColor(Colors.TEXT_WHITE))
            painter.setFont(QFont("Segoe UI", 8, QFont.Bold))
            text_rect = (int(x), int(y + 5), int(w), int(h // 2))
            painter.drawText(text_rect[0], text_rect[1], text_rect[2], text_rect[3], Qt.AlignCenter, step.name[:18])
            painter.setPen(QColor(Colors.TEXT_LIGHT))
            painter.setFont(QFont("Segoe UI", 7))
            type_text = "DESTRUCTIVE" if step.requires_approval else "ACTION"
            painter.drawText(int(x), int(y + h // 2 + 5), int(w), int(h // 2), Qt.AlignCenter, type_text)

    def resizeEvent(self, event):
        self.calculate_positions()
        self.update()


# ============================================================
# Execution Worker Thread
# ============================================================
class ExecutionWorker(QThread):
    step_started = Signal(str, str)
    step_completed = Signal(str, str, dict)
    step_failed = Signal(str, str, str)
    execution_completed = Signal(str)
    approval_requested = Signal(object, dict)
    log_message = Signal(str)

    def __init__(self, execution: Execution, parent=None):
        super().__init__(parent)
        self.execution = execution
        self._is_paused = False
        self._is_stopped = False
        self.approval_response = None

    def run(self):
        self.execution.status = "running"
        self.execution.started_at = datetime.now()
        self.log_message.emit(f"Starting execution: {self.execution.execution_id}")

        for step_exec in self.execution.step_executions:
            if self._is_stopped:
                self.execution.status = "cancelled"
                break

            while self._is_paused:
                if self._is_stopped:
                    self.execution.status = "cancelled"
                    break
                self.msleep(100)

            if self._is_stopped:
                self.execution.status = "cancelled"
                break

            step_exec.status = "running"
            step_exec.started_at = datetime.now()
            self.step_started.emit(step_exec.step.id, step_exec.step.name)
            self.log_message.emit(f"[START] Step {step_exec.step.id}: {step_exec.step.name}")

            if step_exec.approval_required and step_exec.approval_status == "pending":
                self.log_message.emit(f"[APPROVAL] Requesting approval for: {step_exec.step.name}")
                self.approval_response = None
                self.approval_requested.emit(step_exec.step, self.execution.context)
                while self.approval_response is None:
                    if self._is_stopped:
                        self.execution.status = "cancelled"
                        break
                    self.msleep(100)
                if self._is_stopped:
                    break
                if self.approval_response == "approve":
                    step_exec.approval_status = "approved"
                    step_exec.approved_by = "operator"
                    step_exec.approved_at = datetime.now()
                    self.log_message.emit(f"[APPROVED] Step {step_exec.step.id} approved by operator")
                elif self.approval_response == "reject":
                    step_exec.approval_status = "rejected"
                    step_exec.status = "skipped"
                    step_exec.completed_at = datetime.now()
                    step_exec.duration_seconds = 0
                    self.log_message.emit(f"[REJECTED] Step {step_exec.step.id} rejected - skipping")
                    self.step_completed.emit(step_exec.step.id, "skipped", {})
                    continue
                else:
                    step_exec.approval_status = "deferred"
                    step_exec.status = "skipped"
                    step_exec.completed_at = datetime.now()
                    self.log_message.emit(f"[DEFERRED] Step {step_exec.step.id} deferred")
                    self.step_completed.emit(step_exec.step.id, "skipped", {})
                    continue

            simulated_duration = min(step_exec.step.timeout, 3)
            self.msleep(simulated_duration * 1000)
            step_exec.outputs = self._simulate_outputs(step_exec.step)
            step_exec.status = "completed"
            step_exec.completed_at = datetime.now()
            step_exec.duration_seconds = (step_exec.completed_at - step_exec.started_at).total_seconds()
            self.log_message.emit(f"[DONE] Step {step_exec.step.id} completed in {step_exec.duration_seconds:.1f}s")
            self.step_completed.emit(step_exec.step.id, "completed", step_exec.outputs)

        if not self._is_stopped:
            self.execution.status = "completed"
            self.execution.completed_at = datetime.now()
            self.execution.total_duration_seconds = (
                self.execution.completed_at - self.execution.started_at
            ).total_seconds()
            self._build_summary()
            self.execution_completed.emit(self.execution.execution_id)

    def _simulate_outputs(self, step: PlaybookStep) -> dict:
        outputs = {}
        for output in step.outputs:
            if "status" in output.lower():
                outputs[output] = "success"
            elif "count" in output.lower():
                outputs[output] = 1
            elif "id" in output.lower():
                outputs[output] = f"ID-{uuid.uuid4().hex[:8].upper()}"
            elif "url" in output.lower():
                outputs[output] = f"https://siem.company.com/{output}/{uuid.uuid4().hex[:6]}"
            elif "hash" in output.lower():
                outputs[output] = uuid.uuid4().hex
            elif "path" in output.lower():
                outputs[output] = f"/forensics/{uuid.uuid4().hex[:8]}.zip"
            else:
                outputs[output] = f"simulated_{output}"
        return outputs

    def _build_summary(self):
        completed = sum(1 for se in self.execution.step_executions if se.status == "completed")
        failed = sum(1 for se in self.execution.step_executions if se.status == "failed")
        skipped = sum(1 for se in self.execution.step_executions if se.status == "skipped")
        approvals = sum(1 for se in self.execution.step_executions if se.approval_required)
        approvals_granted = sum(1 for se in self.execution.step_executions if se.approval_status == "approved")
        self.execution.summary = {
            "total_steps": len(self.execution.step_executions),
            "completed_steps": completed,
            "failed_steps": failed,
            "skipped_steps": skipped,
            "approval_requests": approvals,
            "approvals_granted": approvals_granted,
            "total_duration": f"{self.execution.total_duration_seconds:.0f}s",
        }

    def pause(self):
        self._is_paused = True

    def resume(self):
        self._is_paused = False

    def stop(self):
        self._is_stopped = True
        self._is_paused = False


# ============================================================
# Main Window
# ============================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SOAR-lite - Automated Incident Response Playbook Runner")
        self.setMinimumSize(1200, 800)
        self.apply_dark_theme()
        self.playbooks = {}
        self.executions = []
        self.current_execution = None
        self.current_worker = None
        self.load_builtin_playbooks()
        self.setup_ui()
        self.setup_connections()
        self.load_sample_data()

    def apply_dark_theme(self):
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {Colors.BG_DARK};
            }}
            QWidget {{
                background-color: {Colors.BG_DARK};
                color: {Colors.TEXT_WHITE};
                font-family: 'Segoe UI', sans-serif;
            }}
            QTabWidget::pane {{
                border: 1px solid {Colors.BORDER_COLOR};
                background-color: {Colors.BG_DARK};
            }}
            QTabBar::tab {{
                background-color: {Colors.BG_MEDIUM};
                color: {Colors.TEXT_LIGHT};
                padding: 8px 16px;
                border: 1px solid {Colors.BORDER_COLOR};
                border-bottom: none;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                background-color: {Colors.BG_LIGHT};
                color: {Colors.TEXT_WHITE};
            }}
            QTabBar::tab:hover {{
                background-color: {Colors.BG_LIGHT};
            }}
            QPushButton {{
                background-color: {Colors.BG_MEDIUM};
                color: {Colors.TEXT_WHITE};
                border: 1px solid {Colors.BORDER_COLOR};
                padding: 8px 16px;
                border-radius: 5px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {Colors.BG_LIGHT};
            }}
            QPushButton:pressed {{
                background-color: {Colors.ACCENT_PURPLE};
            }}
            QPushButton:disabled {{
                background-color: {Colors.PENDING_GRAY};
                color: {Colors.BG_DARK};
            }}
            QLineEdit {{
                background-color: {Colors.BG_MEDIUM};
                color: {Colors.TEXT_WHITE};
                border: 1px solid {Colors.BORDER_COLOR};
                padding: 6px 10px;
                border-radius: 4px;
            }}
            QLineEdit:focus {{
                border: 1px solid {Colors.ACCENT_PURPLE};
            }}
            QTextEdit {{
                background-color: {Colors.BG_MEDIUM};
                color: {Colors.TEXT_WHITE};
                border: 1px solid {Colors.BORDER_COLOR};
                padding: 6px;
                border-radius: 4px;
            }}
            QTableWidget {{
                background-color: {Colors.BG_MEDIUM};
                color: {Colors.TEXT_WHITE};
                border: 1px solid {Colors.BORDER_COLOR};
                gridline-color: {Colors.BORDER_COLOR};
                selection-background-color: {Colors.ACCENT_PURPLE};
            }}
            QTableWidget::item {{
                padding: 5px;
            }}
            QHeaderView::section {{
                background-color: {Colors.BG_LIGHT};
                color: {Colors.TEXT_WHITE};
                padding: 8px;
                border: 1px solid {Colors.BORDER_COLOR};
                font-weight: bold;
            }}
            QGroupBox {{
                border: 1px solid {Colors.BORDER_COLOR};
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 12px;
                font-weight: bold;
                color: {Colors.TEXT_LIGHT};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }}
            QComboBox {{
                background-color: {Colors.BG_MEDIUM};
                color: {Colors.TEXT_WHITE};
                border: 1px solid {Colors.BORDER_COLOR};
                padding: 6px;
                border-radius: 4px;
            }}
            QComboBox::drop-down {{
                border: none;
                width: 20px;
            }}
            QComboBox QAbstractItemView {{
                background-color: {Colors.BG_MEDIUM};
                color: {Colors.TEXT_WHITE};
                selection-background-color: {Colors.ACCENT_PURPLE};
            }}
            QProgressBar {{
                border: 1px solid {Colors.BORDER_COLOR};
                border-radius: 5px;
                text-align: center;
                color: white;
            }}
            QProgressBar::chunk {{
                background-color: {Colors.RUNNING_BLUE};
                border-radius: 4px;
            }}
            QStatusBar {{
                background-color: {Colors.BG_MEDIUM};
                color: {Colors.TEXT_LIGHT};
                border-top: 1px solid {Colors.BORDER_COLOR};
            }}
            QTreeWidget {{
                background-color: {Colors.BG_MEDIUM};
                color: {Colors.TEXT_WHITE};
                border: 1px solid {Colors.BORDER_COLOR};
            }}
            QTreeWidget::item {{
                padding: 4px;
            }}
            QTreeWidget::item:selected {{
                background-color: {Colors.ACCENT_PURPLE};
            }}
            QScrollBar:vertical {{
                background-color: {Colors.BG_DARK};
                width: 12px;
                border: none;
            }}
            QScrollBar::handle:vertical {{
                background-color: {Colors.BG_LIGHT};
                min-height: 20px;
                border-radius: 6px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            QScrollBar:horizontal {{
                background-color: {Colors.BG_DARK};
                height: 12px;
                border: none;
            }}
            QScrollBar::handle:horizontal {{
                background-color: {Colors.BG_LIGHT};
                min-width: 20px;
                border-radius: 6px;
            }}
            QScrollArea {{
                border: none;
            }}
            QRadioButton {{
                color: {Colors.TEXT_WHITE};
                spacing: 8px;
            }}
            QRadioButton::indicator {{
                width: 14px;
                height: 14px;
            }}
            QCheckBox {{
                color: {Colors.TEXT_WHITE};
                spacing: 8px;
            }}
        """)

    def setup_ui(self):
        self.setup_menu_bar()
        self.setup_toolbar()
        self.setup_status_bar()

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)
        main_layout.setSpacing(5)

        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        self.setup_playbook_library_tab()
        self.setup_incident_context_tab()
        self.setup_execution_console_tab()
        self.setup_dag_viewer_tab()
        self.setup_rollback_viewer_tab()
        self.setup_action_log_tab()
        self.setup_metrics_tab()
        self.setup_report_builder_tab()

    def setup_menu_bar(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")
        import_action = QAction("Import Playbook (YAML)", self)
        import_action.triggered.connect(self.import_playbook)
        file_menu.addAction(import_action)

        export_action = QAction("Export Playbook (YAML)", self)
        export_action.triggered.connect(self.export_playbook)
        file_menu.addAction(export_action)

        file_menu.addSeparator()

        load_demo_action = QAction("Load Demo Data", self)
        load_demo_action.triggered.connect(self.load_sample_data)
        file_menu.addAction(load_demo_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        run_menu = menubar.addMenu("Run")
        execute_action = QAction("Execute Playbook", self)
        execute_action.triggered.connect(self.execute_current_playbook)
        run_menu.addAction(execute_action)

        stop_action = QAction("Stop Execution", self)
        stop_action.triggered.connect(self.stop_execution)
        run_menu.addAction(stop_action)

        help_menu = menubar.addMenu("Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def setup_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        toolbar.setStyleSheet(f"""
            QToolBar {{
                background-color: {Colors.BG_MEDIUM};
                border-bottom: 1px solid {Colors.BORDER_COLOR};
                spacing: 5px;
                padding: 5px;
            }}
        """)
        self.addToolBar(toolbar)

        import_btn = QPushButton("📁 Import Playbook")
        import_btn.clicked.connect(self.import_playbook)
        toolbar.addWidget(import_btn)

        demo_btn = QPushButton("📊 Load Demo Data")
        demo_btn.clicked.connect(self.load_sample_data)
        toolbar.addWidget(demo_btn)

        toolbar.addSeparator()

        self.execute_btn = QPushButton("▶ Execute Playbook")
        self.execute_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {Colors.SUCCESS_GREEN};
                color: white;
                font-weight: bold;
                padding: 8px 16px;
            }}
            QPushButton:hover {{ background-color: #27ae60; }}
        """)
        self.execute_btn.clicked.connect(self.execute_current_playbook)
        toolbar.addWidget(self.execute_btn)

        self.stop_btn = QPushButton("■ Stop")
        self.stop_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {Colors.FAILED_RED};
                color: white;
                font-weight: bold;
                padding: 8px 16px;
            }}
            QPushButton:hover {{ background-color: #c0392b; }}
        """)
        self.stop_btn.clicked.connect(self.stop_execution)
        self.stop_btn.setEnabled(False)
        toolbar.addWidget(self.stop_btn)

    def setup_status_bar(self):
        self.statusBar().showMessage("Ready")
        self.status_label = QLabel("Status: Idle")
        self.statusBar().addPermanentWidget(self.status_label)

    def setup_playbook_library_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        header_layout = QHBoxLayout()
        header_label = QLabel("Playbook Library")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold; color: white;")
        header_layout.addWidget(header_label)
        header_layout.addStretch()

        import_btn = QPushButton("📁 Import YAML")
        import_btn.clicked.connect(self.import_playbook)
        header_layout.addWidget(import_btn)

        upload_btn = QPushButton("📤 Upload Playbook")
        upload_btn.clicked.connect(self.upload_playbook)
        header_layout.addWidget(upload_btn)

        layout.addLayout(header_layout)

        self.playbook_table = QTableWidget()
        self.playbook_table.setColumnCount(5)
        self.playbook_table.setHorizontalHeaderLabels(["Name", "Version", "Severity", "Steps", "Description"])
        self.playbook_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.playbook_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.playbook_table.setSelectionMode(QTableWidget.SingleSelection)
        self.playbook_table.doubleClicked.connect(self.playbook_double_clicked)
        layout.addWidget(self.playbook_table)

        preview_group = QGroupBox("Playbook Preview")
        preview_layout = QVBoxLayout(preview_group)
        self.playbook_preview = QTextEdit()
        self.playbook_preview.setReadOnly(True)
        self.playbook_preview.setFont(QFont("Consolas", 10))
        preview_layout.addWidget(self.playbook_preview)
        layout.addWidget(preview_group)

        self.tab_widget.addTab(tab, "📚 Playbook Library")

    def setup_incident_context_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        header_label = QLabel("Incident Context")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold; color: white;")
        layout.addWidget(header_label)

        form_group = QGroupBox("Incident Details")
        form_layout = QFormLayout(form_group)

        self.incident_id_input = QLineEdit()
        self.incident_id_input.setPlaceholderText("e.g., INC-2026-001")
        form_layout.addRow("Incident ID:", self.incident_id_input)

        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["low", "medium", "high", "critical"])
        self.severity_combo.setCurrentText("high")
        form_layout.addRow("Severity:", self.severity_combo)

        self.affected_entities_input = QLineEdit()
        self.affected_entities_input.setPlaceholderText("e.g., user1@company.com, user2@company.com")
        form_layout.addRow("Affected Entities:", self.affected_entities_input)

        self.notes_input = QTextEdit()
        self.notes_input.setPlaceholderText("Enter incident notes and context...")
        self.notes_input.setMaximumHeight(100)
        form_layout.addRow("Notes:", self.notes_input)

        layout.addWidget(form_group)

        selection_group = QGroupBox("Select Playbook to Execute")
        selection_layout = QHBoxLayout(selection_group)
        self.playbook_select_combo = QComboBox()
        self.playbook_select_combo.setMinimumWidth(300)
        selection_layout.addWidget(QLabel("Playbook:"))
        selection_layout.addWidget(self.playbook_select_combo)
        selection_layout.addStretch()
        layout.addWidget(selection_group)

        context_preview_group = QGroupBox("Context Preview (JSON)")
        preview_layout = QVBoxLayout(context_preview_group)
        self.context_preview = QTextEdit()
        self.context_preview.setReadOnly(True)
        self.context_preview.setFont(QFont("Consolas", 10))
        self.context_preview.setMaximumHeight(200)
        preview_layout.addWidget(self.context_preview)
        layout.addWidget(context_preview_group)

        update_preview_btn = QPushButton("🔄 Update Preview")
        update_preview_btn.clicked.connect(self.update_context_preview)
        layout.addWidget(update_preview_btn)

        self.tab_widget.addTab(tab, "🎯 Incident Context")

    def setup_execution_console_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        header_layout = QHBoxLayout()
        header_label = QLabel("Execution Console")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold; color: white;")
        header_layout.addWidget(header_label)
        header_layout.addStretch()

        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(300)
        self.progress_bar.setValue(0)
        header_layout.addWidget(self.progress_bar)

        layout.addLayout(header_layout)

        self.execution_status_label = QLabel("No execution in progress")
        self.execution_status_label.setStyleSheet(f"color: {Colors.PENDING_GRAY}; font-weight: bold;")
        layout.addWidget(self.execution_status_label)

        self.steps_table = QTableWidget()
        self.steps_table.setColumnCount(6)
        self.steps_table.setHorizontalHeaderLabels([
            "Step ID", "Name", "Status", "Type", "Duration", "Output"
        ])
        self.steps_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.steps_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        layout.addWidget(self.steps_table)

        console_group = QGroupBox("Live Console Output")
        console_layout = QVBoxLayout(console_group)
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setFont(QFont("Consolas", 10))
        self.console_output.setStyleSheet(f"""
            QTextEdit {{
                background-color: #0a0a14;
                color: {Colors.SUCCESS_GREEN};
                border: 1px solid {Colors.BORDER_COLOR};
            }}
        """)
        console_layout.addWidget(self.console_output)
        layout.addWidget(console_group)

        self.tab_widget.addTab(tab, "🖥 Execution Console")

    def setup_dag_viewer_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        header_label = QLabel("Playbook DAG Viewer")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold; color: white;")
        layout.addWidget(header_label)

        info_label = QLabel("Visual representation of playbook steps and their dependencies")
        info_label.setStyleSheet(f"color: {Colors.TEXT_LIGHT};")
        layout.addWidget(info_label)

        legend_layout = QHBoxLayout()
        legend_items = [
            (Colors.RUNNING_BLUE, "Action Step"),
            (Colors.DESTRUCTIVE_ORANGE, "Destructive (Approval Required)"),
        ]
        for color, text in legend_items:
            color_box = QFrame()
            color_box.setFixedSize(16, 16)
            color_box.setStyleSheet(f"background-color: {color}; border-radius: 3px;")
            legend_layout.addWidget(color_box)
            legend_layout.addWidget(QLabel(text))
        legend_layout.addStretch()
        layout.addLayout(legend_layout)

        self.dag_viewer = DAGViewerWidget()
        layout.addWidget(self.dag_viewer)

        self.tab_widget.addTab(tab, "📊 DAG Viewer")

    def setup_rollback_viewer_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        header_layout = QHBoxLayout()
        header_label = QLabel("Rollback Viewer")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold; color: white;")
        header_layout.addWidget(header_label)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        info_label = QLabel("Completed actions can be rolled back using the buttons below")
        info_label.setStyleSheet(f"color: {Colors.TEXT_LIGHT};")
        layout.addWidget(info_label)

        self.rollback_table = QTableWidget()
        self.rollback_table.setColumnCount(5)
        self.rollback_table.setHorizontalHeaderLabels([
            "Step ID", "Name", "Status", "Duration", "Rollback"
        ])
        self.rollback_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        layout.addWidget(self.rollback_table)

        self.tab_widget.addTab(tab, "↩ Rollback Viewer")

    def setup_action_log_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        header_layout = QHBoxLayout()
        header_label = QLabel("Action Log")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold; color: white;")
        header_layout.addWidget(header_label)
        header_layout.addStretch()

        export_log_btn = QPushButton("📤 Export Log")
        export_log_btn.clicked.connect(self.export_action_log)
        header_layout.addWidget(export_log_btn)
        layout.addLayout(header_layout)

        self.action_log_table = QTableWidget()
        self.action_log_table.setColumnCount(6)
        self.action_log_table.setHorizontalHeaderLabels([
            "Timestamp", "Action", "Step", "Method", "Status", "Duration"
        ])
        self.action_log_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        layout.addWidget(self.action_log_table)

        detail_group = QGroupBox("Request/Response Details")
        detail_layout = QVBoxLayout(detail_group)
        self.log_detail_text = QTextEdit()
        self.log_detail_text.setReadOnly(True)
        self.log_detail_text.setFont(QFont("Consolas", 10))
        detail_layout.addWidget(self.log_detail_text)
        layout.addWidget(detail_group)

        self.action_log_table.clicked.connect(self.show_log_detail)

        self.tab_widget.addTab(tab, "📋 Action Log")

    def setup_metrics_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        header_label = QLabel("Metrics Dashboard")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold; color: white;")
        layout.addWidget(header_label)

        metrics_layout = QHBoxLayout()

        self.total_executions_widget = MetricsWidget("Total Executions", "0", Colors.RUNNING_BLUE)
        metrics_layout.addWidget(self.total_executions_widget)

        self.success_rate_widget = MetricsWidget("Success Rate", "0%", Colors.SUCCESS_GREEN)
        metrics_layout.addWidget(self.success_rate_widget)

        self.failed_count_widget = MetricsWidget("Failed", "0", Colors.FAILED_RED)
        metrics_layout.addWidget(self.failed_count_widget)

        self.avg_mttr_widget = MetricsWidget("Avg MTTR", "N/A", Colors.AWAITING_YELLOW)
        metrics_layout.addWidget(self.avg_mttr_widget)

        layout.addLayout(metrics_layout)

        history_group = QGroupBox("Execution History")
        history_layout = QVBoxLayout(history_group)
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels([
            "Execution ID", "Playbook", "Status", "Duration", "Started"
        ])
        self.history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.history_table.clicked.connect(self.show_execution_detail)
        history_layout.addWidget(self.history_table)
        layout.addWidget(history_group)

        self.tab_widget.addTab(tab, "📈 Metrics")

    def setup_report_builder_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        header_label = QLabel("Report Builder")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold; color: white;")
        layout.addWidget(header_label)

        export_group = QGroupBox("Export Options")
        export_layout = QGridLayout(export_group)

        self.export_json_btn = QPushButton("📄 Export JSON")
        self.export_json_btn.clicked.connect(lambda: self.export_report("json"))
        export_layout.addWidget(self.export_json_btn, 0, 0)

        self.export_csv_btn = QPushButton("📊 Export CSV")
        self.export_csv_btn.clicked.connect(lambda: self.export_report("csv"))
        export_layout.addWidget(self.export_csv_btn, 0, 1)

        self.export_html_btn = QPushButton("🌐 Export HTML")
        self.export_html_btn.clicked.connect(lambda: self.export_report("html"))
        export_layout.addWidget(self.export_html_btn, 0, 2)

        self.export_pdf_btn = QPushButton("📑 Export PDF")
        self.export_pdf_btn.clicked.connect(lambda: self.export_report("pdf"))
        export_layout.addWidget(self.export_pdf_btn, 0, 3)

        layout.addWidget(export_group)

        preview_group = QGroupBox("Report Preview")
        preview_layout = QVBoxLayout(preview_group)
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setFont(QFont("Consolas", 10))
        preview_layout.addWidget(self.report_preview)
        layout.addWidget(preview_group)

        preview_btn = QPushButton("🔄 Generate Preview")
        preview_btn.clicked.connect(self.generate_report_preview)
        layout.addWidget(preview_btn)

        self.tab_widget.addTab(tab, "📑 Report Builder")

    def setup_connections(self):
        self.playbook_table.clicked.connect(self.playbook_selected)
        self.incident_id_input.textChanged.connect(self.update_context_preview)
        self.affected_entities_input.textChanged.connect(self.update_context_preview)
        self.notes_input.textChanged.connect(self.update_context_preview)

    def load_builtin_playbooks(self):
        sample_dir = BASE_DIR / "sample_data"
        for yaml_file in sample_dir.glob("*.yaml"):
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    playbook = Playbook.from_yaml(f.read())
                    self.playbooks[playbook.name] = playbook
            except Exception as e:
                print(f"Error loading {yaml_file}: {e}")

    def load_sample_data(self):
        sample_dir = BASE_DIR / "sample_data"
        for yaml_file in sample_dir.glob("*.yaml"):
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    playbook = Playbook.from_yaml(f.read())
                    self.playbooks[playbook.name] = playbook
            except Exception as e:
                print(f"Error loading {yaml_file}: {e}")

        execution_file = sample_dir / "sample_execution.json"
        if execution_file.exists():
            try:
                with open(execution_file, "r", encoding="utf-8") as f:
                    exec_data = json.load(f)
                    self.executions.append(exec_data)
            except Exception as e:
                print(f"Error loading execution data: {e}")

        self.refresh_playbook_table()
        self.refresh_playbook_combo()
        self.refresh_metrics()
        self.refresh_history_table()
        self.statusBar().showMessage(f"Loaded {len(self.playbooks)} playbooks and {len(self.executions)} execution records")

    def refresh_playbook_table(self):
        self.playbook_table.setRowCount(0)
        self.playbook_table.setRowCount(len(self.playbooks))
        for i, (name, playbook) in enumerate(self.playbooks.items()):
            self.playbook_table.setItem(i, 0, QTableWidgetItem(playbook.name))
            self.playbook_table.setItem(i, 1, QTableWidgetItem(playbook.version))
            severity_item = QTableWidgetItem(playbook.severity)
            if playbook.severity == "critical":
                severity_item.setForeground(QColor(Colors.FAILED_RED))
            elif playbook.severity == "high":
                severity_item.setForeground(QColor(Colors.DESTRUCTIVE_ORANGE))
            elif playbook.severity == "medium":
                severity_item.setForeground(QColor(Colors.AWAITING_YELLOW))
            else:
                severity_item.setForeground(QColor(Colors.SUCCESS_GREEN))
            self.playbook_table.setItem(i, 2, severity_item)
            self.playbook_table.setItem(i, 3, QTableWidgetItem(str(len(playbook.steps))))
            self.playbook_table.setItem(i, 4, QTableWidgetItem(playbook.description))

    def refresh_playbook_combo(self):
        self.playbook_select_combo.clear()
        for name in self.playbooks.keys():
            self.playbook_select_combo.addItem(name)

    def playbook_selected(self, index):
        row = index.row()
        playbook_name = self.playbook_table.item(row, 0).text()
        if playbook_name in self.playbooks:
            playbook = self.playbooks[playbook_name]
            self.playbook_preview.setPlainText(playbook.to_yaml())
            self.dag_viewer.set_steps(playbook.steps)

    def playbook_double_clicked(self, index):
        self.playbook_selected(index)
        self.tab_widget.setCurrentIndex(1)

    def import_playbook(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Playbook", "", "YAML Files (*.yaml *.yml);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    playbook = Playbook.from_yaml(f.read())
                    self.playbooks[playbook.name] = playbook
                    self.refresh_playbook_table()
                    self.refresh_playbook_combo()
                    self.statusBar().showMessage(f"Imported playbook: {playbook.name}")
                    QMessageBox.information(self, "Success", f"Playbook '{playbook.name}' imported successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to import playbook:\n{str(e)}")

    def upload_playbook(self):
        self.import_playbook()

    def export_playbook(self):
        selected_rows = self.playbook_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Warning", "Please select a playbook to export")
            return
        row = selected_rows[0].row()
        playbook_name = self.playbook_table.item(row, 0).text()
        if playbook_name not in self.playbooks:
            return
        playbook = self.playbooks[playbook_name]
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Playbook", f"{playbook_name.replace(' ', '_')}.yaml",
            "YAML Files (*.yaml);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(playbook.to_yaml())
                self.statusBar().showMessage(f"Exported playbook to: {file_path}")
                QMessageBox.information(self, "Success", f"Playbook exported to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export playbook:\n{str(e)}")

    def update_context_preview(self):
        context = self.get_incident_context()
        self.context_preview.setPlainText(json.dumps(context, indent=2, default=str))

    def get_incident_context(self) -> dict:
        affected = [e.strip() for e in self.affected_entities_input.text().split(",") if e.strip()]
        return {
            "incident_id": self.incident_id_input.text() or f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "affected_users": affected,
            "severity": self.severity_combo.currentText(),
            "notes": self.notes_input.toPlainText(),
            "reported_at": datetime.now().isoformat(),
        }

    def execute_current_playbook(self):
        playbook_name = self.playbook_select_combo.currentText()
        if not playbook_name or playbook_name not in self.playbooks:
            QMessageBox.warning(self, "Warning", "Please select a playbook to execute")
            return

        playbook = self.playbooks[playbook_name]
        context = self.get_incident_context()

        execution = Execution(playbook, context)
        self.executions.append(execution.to_dict())
        self.current_execution = execution

        self.tab_widget.setCurrentIndex(2)
        self.setup_execution_display(execution)

        self.execute_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.execution_status_label.setText(f"Executing: {playbook.name}...")
        self.execution_status_label.setStyleSheet(f"color: {Colors.RUNNING_BLUE}; font-weight: bold;")

        self.current_worker = ExecutionWorker(execution, self)
        self.current_worker.step_started.connect(self.on_step_started)
        self.current_worker.step_completed.connect(self.on_step_completed)
        self.current_worker.step_failed.connect(self.on_step_failed)
        self.current_worker.execution_completed.connect(self.on_execution_completed)
        self.current_worker.approval_requested.connect(self.on_approval_requested)
        self.current_worker.log_message.connect(self.on_log_message)
        self.current_worker.start()

    def setup_execution_display(self, execution: Execution):
        self.steps_table.setRowCount(0)
        self.steps_table.setRowCount(len(execution.step_executions))
        for i, step_exec in enumerate(execution.step_executions):
            self.steps_table.setItem(i, 0, QTableWidgetItem(step_exec.step.id))
            self.steps_table.setItem(i, 1, QTableWidgetItem(step_exec.step.name))
            status_item = QTableWidgetItem(step_exec.status)
            status_item.setForeground(QColor(Colors.PENDING_GRAY))
            self.steps_table.setItem(i, 2, status_item)
            type_text = "DESTRUCTIVE" if step_exec.step.requires_approval else "ACTION"
            type_item = QTableWidgetItem(type_text)
            if step_exec.step.requires_approval:
                type_item.setForeground(QColor(Colors.DESTRUCTIVE_ORANGE))
            self.steps_table.setItem(i, 3, type_item)
            self.steps_table.setItem(i, 4, QTableWidgetItem("-"))
            self.steps_table.setItem(i, 5, QTableWidgetItem("-"))
        self.progress_bar.setMaximum(len(execution.step_executions))
        self.progress_bar.setValue(0)
        self.console_output.clear()

    @Slot(str, str)
    def on_step_started(self, step_id: str, step_name: str):
        for i in range(self.steps_table.rowCount()):
            if self.steps_table.item(i, 0) and self.steps_table.item(i, 0).text() == step_id:
                status_item = QTableWidgetItem("running")
                status_item.setForeground(QColor(Colors.RUNNING_BLUE))
                self.steps_table.setItem(i, 2, status_item)
                break

    @Slot(str, str, dict)
    def on_step_completed(self, step_id: str, status: str, outputs: dict):
        for i in range(self.steps_table.rowCount()):
            if self.steps_table.item(i, 0) and self.steps_table.item(i, 0).text() == step_id:
                status_item = QTableWidgetItem(status)
                if status == "completed":
                    status_item.setForeground(QColor(Colors.SUCCESS_GREEN))
                elif status == "failed":
                    status_item.setForeground(QColor(Colors.FAILED_RED))
                elif status == "skipped":
                    status_item.setForeground(QColor(Colors.AWAITING_YELLOW))
                self.steps_table.setItem(i, 2, status_item)

                duration = "-"
                if self.current_execution:
                    se = self.current_execution.get_step_execution(step_id)
                    if se and se.duration_seconds > 0:
                        duration = f"{se.duration_seconds:.1f}s"
                self.steps_table.setItem(i, 4, QTableWidgetItem(duration))

                output_text = json.dumps(outputs, indent=2, default=str)[:200]
                self.steps_table.setItem(i, 5, QTableWidgetItem(output_text))
                break
        self.progress_bar.setValue(self.progress_bar.value() + 1)
        self.update_rollback_table()

    @Slot(str, str, str)
    def on_step_failed(self, step_id: str, step_name: str, error: str):
        self.console_output.append(f"[ERROR] Step {step_id} failed: {error}")

    @Slot(str)
    def on_execution_completed(self, execution_id: str):
        self.execute_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.execution_status_label.setText(f"Execution Completed: {execution_id}")
        self.execution_status_label.setStyleSheet(f"color: {Colors.SUCCESS_GREEN}; font-weight: bold;")
        self.statusBar().showMessage(f"Execution {execution_id} completed successfully")
        self.refresh_metrics()
        self.refresh_history_table()
        self.update_rollback_table()
        self.update_action_log()

    @Slot(object, dict)
    def on_approval_requested(self, step: PlaybookStep, context: dict):
        dialog = ApprovalDialog(step, context, self)
        dialog.exec()
        if self.current_worker:
            self.current_worker.approval_response = dialog.result_action
            if dialog.result_action == "approve":
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "action": "approval_granted",
                    "step": step.id,
                    "approved_by": "operator",
                    "reason": dialog.reason,
                }
                self.current_execution.action_log.append(log_entry)
            elif dialog.result_action == "reject":
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "action": "approval_rejected",
                    "step": step.id,
                    "reason": dialog.reason,
                }
                self.current_execution.action_log.append(log_entry)

    @Slot(str)
    def on_log_message(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console_output.append(f"[{timestamp}] {message}")

    def stop_execution(self):
        if self.current_worker:
            reply = QMessageBox.question(
                self, "Confirm Stop",
                "Are you sure you want to stop the current execution?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                self.current_worker.stop()
                self.execute_btn.setEnabled(True)
                self.stop_btn.setEnabled(False)
                self.execution_status_label.setText("Execution Stopped")
                self.execution_status_label.setStyleSheet(f"color: {Colors.FAILED_RED}; font-weight: bold;")

    def update_rollback_table(self):
        if not self.current_execution:
            return
        self.rollback_table.setRowCount(0)
        completed_steps = [
            se for se in self.current_execution.step_executions
            if se.status == "completed"
        ]
        self.rollback_table.setRowCount(len(completed_steps))
        for i, se in enumerate(completed_steps):
            self.rollback_table.setItem(i, 0, QTableWidgetItem(se.step.id))
            self.rollback_table.setItem(i, 1, QTableWidgetItem(se.step.name))
            status_item = QTableWidgetItem(se.status)
            status_item.setForeground(QColor(Colors.SUCCESS_GREEN))
            self.rollback_table.setItem(i, 2, status_item)
            self.rollback_table.setItem(i, 3, QTableWidgetItem(f"{se.duration_seconds:.1f}s"))
            rollback_btn = QPushButton("↩ Rollback")
            rollback_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {Colors.AWAITING_YELLOW};
                    color: white;
                    font-weight: bold;
                    padding: 5px 10px;
                }}
                QPushButton:hover {{ background-color: #e67e22; }}
            """)
            rollback_btn.clicked.connect(lambda _, sid=se.step.id: self.rollback_step(sid))
            self.rollback_table.setCellWidget(i, 4, rollback_btn)

    def rollback_step(self, step_id: str):
        if not self.current_execution:
            return
        se = self.current_execution.get_step_execution(step_id)
        if not se or se.status != "completed":
            return
        reply = QMessageBox.question(
            self, "Confirm Rollback",
            f"Are you sure you want to rollback step: {se.step.name}?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            se.status = "rolled_back"
            se.rollback_status = "completed"
            self.statusBar().showMessage(f"Rolled back step: {se.step.name}")
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "action": "rollback",
                "step": step_id,
                "status": "completed",
            }
            self.current_execution.action_log.append(log_entry)
            self.update_rollback_table()
            self.update_action_log()

    def update_action_log(self):
        if not self.current_execution:
            return
        self.action_log_table.setRowCount(0)
        logs = self.current_execution.action_log
        self.action_log_table.setRowCount(len(logs))
        for i, log in enumerate(logs):
            self.action_log_table.setItem(i, 0, QTableWidgetItem(log.get("timestamp", "-")))
            self.action_log_table.setItem(i, 1, QTableWidgetItem(log.get("action", "-")))
            self.action_log_table.setItem(i, 2, QTableWidgetItem(log.get("step", "-")))
            self.action_log_table.setItem(i, 3, QTableWidgetItem(log.get("method", "-")))
            status = log.get("response_code", log.get("status", "-"))
            status_item = QTableWidgetItem(str(status))
            if str(status).startswith("2"):
                status_item.setForeground(QColor(Colors.SUCCESS_GREEN))
            elif str(status).startswith("4") or str(status).startswith("5"):
                status_item.setForeground(QColor(Colors.FAILED_RED))
            self.action_log_table.setItem(i, 4, status_item)
            self.action_log_table.setItem(i, 5, QTableWidgetItem(str(log.get("duration_ms", "-"))))

    def show_log_detail(self, index):
        if not self.current_execution:
            return
        row = index.row()
        if row < len(self.current_execution.action_log):
            log = self.current_execution.action_log[row]
            self.log_detail_text.setPlainText(json.dumps(log, indent=2, default=str))

    def refresh_metrics(self):
        total = len(self.executions)
        completed = sum(1 for e in self.executions if e.get("status") == "completed")
        failed = sum(1 for e in self.executions if e.get("status") == "failed")
        success_rate = (completed / total * 100) if total > 0 else 0
        durations = [e.get("total_duration_seconds", 0) for e in self.executions if e.get("total_duration_seconds", 0) > 0]
        avg_mttr = sum(durations) / len(durations) if durations else 0
        self.total_executions_widget.update_value(str(total))
        self.success_rate_widget.update_value(f"{success_rate:.1f}%")
        self.failed_count_widget.update_value(str(failed))
        if avg_mttr > 0:
            if avg_mttr < 60:
                self.avg_mttr_widget.update_value(f"{avg_mttr:.0f}s")
            else:
                self.avg_mttr_widget.update_value(f"{avg_mttr / 60:.1f}m")
        else:
            self.avg_mttr_widget.update_value("N/A")

    def refresh_history_table(self):
        self.history_table.setRowCount(0)
        self.history_table.setRowCount(len(self.executions))
        for i, exec_data in enumerate(self.executions):
            self.history_table.setItem(i, 0, QTableWidgetItem(exec_data.get("execution_id", "-")))
            self.history_table.setItem(i, 1, QTableWidgetItem(exec_data.get("playbook_name", "-")))
            status = exec_data.get("status", "-")
            status_item = QTableWidgetItem(status)
            if status == "completed":
                status_item.setForeground(QColor(Colors.SUCCESS_GREEN))
            elif status == "failed":
                status_item.setForeground(QColor(Colors.FAILED_RED))
            elif status == "running":
                status_item.setForeground(QColor(Colors.RUNNING_BLUE))
            else:
                status_item.setForeground(QColor(Colors.PENDING_GRAY))
            self.history_table.setItem(i, 2, status_item)
            duration = exec_data.get("total_duration_seconds", 0)
            self.history_table.setItem(i, 3, QTableWidgetItem(f"{duration}s" if duration else "-"))
            self.history_table.setItem(i, 4, QTableWidgetItem(exec_data.get("started_at", "-")))

    def show_execution_detail(self, index):
        row = index.row()
        if row < len(self.executions):
            exec_data = self.executions[row]
            self.report_preview.setPlainText(json.dumps(exec_data, indent=2, default=str))

    def export_action_log(self):
        if not self.current_execution or not self.current_execution.action_log:
            QMessageBox.warning(self, "Warning", "No action log data to export")
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Action Log", "action_log.json", "JSON Files (*.json)"
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(self.current_execution.action_log, f, indent=2, default=str)
                self.statusBar().showMessage(f"Action log exported to: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export log:\n{str(e)}")

    def generate_report_preview(self):
        if not self.executions:
            self.report_preview.setPlainText("No execution data available. Run a playbook first.")
            return
        latest = self.executions[-1]
        self.report_preview.setPlainText(json.dumps(latest, indent=2, default=str))

    def export_report(self, format_type: str):
        if not self.executions:
            QMessageBox.warning(self, "Warning", "No execution data to export")
            return
        latest = self.executions[-1]
        if format_type == "json":
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Report", "incident_report.json", "JSON Files (*.json)"
            )
            if file_path:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(latest, f, indent=2, default=str)
                self.statusBar().showMessage(f"JSON report exported to: {file_path}")

        elif format_type == "csv":
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Report", "incident_report.csv", "CSV Files (*.csv)"
            )
            if file_path:
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Step ID", "Step Name", "Status", "Duration", "Outputs"])
                    for step in latest.get("steps", []):
                        writer.writerow([
                            step.get("step_id", ""),
                            step.get("step_name", ""),
                            step.get("status", ""),
                            step.get("duration_seconds", 0),
                            json.dumps(step.get("outputs", {}), default=str),
                        ])
                self.statusBar().showMessage(f"CSV report exported to: {file_path}")

        elif format_type == "html":
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Report", "incident_report.html", "HTML Files (*.html)"
            )
            if file_path:
                html = self._generate_html_report(latest)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(html)
                self.statusBar().showMessage(f"HTML report exported to: {file_path}")

        elif format_type == "pdf":
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Report", "incident_report.html", "HTML Files (*.html)"
            )
            if file_path:
                html = self._generate_html_report(latest)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(html)
                self.statusBar().showMessage(
                    f"HTML report exported to: {file_path}\n"
                    "Note: Open in browser and print to PDF for PDF export"
                )

        QMessageBox.information(self, "Success", f"Report exported as {format_type.upper()}")

    def _generate_html_report(self, exec_data: dict) -> str:
        steps_html = ""
        for step in exec_data.get("steps", []):
            status_color = Colors.SUCCESS_GREEN if step.get("status") == "completed" else Colors.FAILED_RED
            steps_html += f"""
            <tr>
                <td>{step.get('step_id', '-')}</td>
                <td>{step.get('step_name', '-')}</td>
                <td style="color: {status_color}; font-weight: bold;">{step.get('status', '-')}</td>
                <td>{step.get('duration_seconds', 0)}s</td>
                <td><pre>{json.dumps(step.get('outputs', {}), indent=2, default=str)[:200]}</pre></td>
            </tr>
            """
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Incident Report - {exec_data.get('execution_id', '-')}</title>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #1e1e2e; color: #ffffff; }}
                h1 {{ color: #3498db; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                h2 {{ color: #9b59b6; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #4a4a6a; padding: 10px; text-align: left; }}
                th {{ background: #2d2d44; color: #ffffff; }}
                tr:nth-child(even) {{ background: #2d2d44; }}
                .meta {{ background: #2d2d44; padding: 15px; border-radius: 8px; margin: 10px 0; }}
                pre {{ background: #0a0a14; padding: 10px; border-radius: 5px; overflow-x: auto; font-size: 12px; }}
            </style>
        </head>
        <body>
            <h1>Incident Response Report</h1>
            <div class="meta">
                <p><strong>Execution ID:</strong> {exec_data.get('execution_id', '-')}</p>
                <p><strong>Playbook:</strong> {exec_data.get('playbook_name', '-')}</p>
                <p><strong>Status:</strong> {exec_data.get('status', '-')}</p>
                <p><strong>Started:</strong> {exec_data.get('started_at', '-')}</p>
                <p><strong>Duration:</strong> {exec_data.get('total_duration_seconds', 0)}s</p>
            </div>
            <h2>Step Execution Details</h2>
            <table>
                <tr>
                    <th>Step ID</th>
                    <th>Name</th>
                    <th>Status</th>
                    <th>Duration</th>
                    <th>Outputs</th>
                </tr>
                {steps_html}
            </table>
            <h2>Context</h2>
            <pre>{json.dumps(exec_data.get('context', {}), indent=2)}</pre>
        </body>
        </html>
        """

    def show_about(self):
        QMessageBox.about(
            self,
            "About SOAR-lite",
            "<h2>SOAR-lite</h2>"
            "<p>Automated Incident Response Playbook Runner</p>"
            "<p>Version 1.0</p>"
            "<p>A lightweight Security Orchestration, Automation, and Response tool</p>"
            "for managing and executing incident response playbooks.</p>"
            "<p>Features:</p>"
            "<ul>"
            "<li>YAML playbook management</li>"
            "<li>Step-by-step execution with progress tracking</li>"
            "<li>Approval gates for destructive actions</li>"
            "<li>Rollback support for completed actions</li>"
            "<li>Metrics dashboard and reporting</li>"
            "</ul>"
        )


# ============================================================
# Main Entry Point
# ============================================================
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
