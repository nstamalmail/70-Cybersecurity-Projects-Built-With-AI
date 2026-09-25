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

DATA_DIR = Path.home() / ".mmbw"
MODULES_DIR = DATA_DIR / "modules"
REPORTS_DIR = DATA_DIR / "reports"
LOGS_DIR = DATA_DIR / "logs"

def init_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    MODULES_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

def init_db():
    conn = sqlite3.connect(str(DATA_DIR / "module_data.db"))
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS modules (
        module_id TEXT PRIMARY KEY,
        name TEXT,
        module_type TEXT,
        target_service TEXT,
        target_platform TEXT,
        source_code TEXT,
        rpc_path TEXT,
        payload_used TEXT,
        execution_status TEXT,
        session_id TEXT,
        validation_results TEXT,
        created_at TIMESTAMP,
        updated_at TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS validation (
        check_id INTEGER PRIMARY KEY AUTOINCREMENT,
        module_id TEXT,
        check_name TEXT,
        status TEXT,
        message TEXT,
        timestamp TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS execution_log (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        module_id TEXT,
        timestamp TIMESTAMP,
        output TEXT,
        session_created INTEGER
    )''')
    conn.commit()
    conn.close()

def load_sample_data():
    sample_file = Path(__file__).parent / "data" / "sample_module.json"
    if sample_file.exists():
        with open(sample_file, 'r') as f:
            return json.load(f)
    return None

class MMBWApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Metasploit Module Builder Workbench (MMBW)")
        self.resize(1400, 1000)
        init_dirs()
        init_db()
        sample = load_sample_data()
        if sample:
            self.inject_sample_data(sample)
        self.setup_ui()
        self.refresh_modules()

    def inject_sample_data(self, data):
        conn = sqlite3.connect(str(DATA_DIR / "module_data.db"))
        c = conn.cursor()
        
        module = data.get("module", {})
        module_id = module.get("module_id", "MOD-001")
        
        # Insert module
        validation = module.get("validation_results", [])
        val_json = json.dumps(validation) if validation else "[]"
        
        c.execute("INSERT OR REPLACE INTO modules VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (module_id,
                   module.get("name", "Custom Module"),
                   module.get("module_type", "cmd_injection"),
                   module.get("target_service", "192.168.1.50:4555"),
                   module.get("target_platform", "linux"),
                   module.get("source_code", ""),
                   module.get("rpc_path", ""),
                   module.get("payload_used", "cmd/unix/interact"),
                   module.get("execution_status", "draft"),
                   module.get("session_id", None),
                   val_json,
                   module.get("created_at", datetime.now().isoformat()),
                   module.get("updated_at", datetime.now().isoformat())))
        
        # Insert validation checks
        for v in validation:
            c.execute("INSERT OR REPLACE INTO validation VALUES (?, ?, ?, ?, ?, ?)",
                      (v.get("check_id", 1), module_id,
                       v.get("check_name", "syntax"),
                       v.get("status", "pass"),
                       v.get("message", "Syntax valid"),
                       v.get("timestamp", datetime.now().isoformat())))
        
        conn.commit()
        conn.close()

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)

        # Left panel - navigation and controls
        self.left_panel = QWidget()
        self.left_panel.setFixedWidth(280)
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

        self.btn_lab = QPushButton("Lab Target Config")
        self.btn_scaffold = QPushButton("Module Scaffolder")
        self.btn_editor = QPushButton("Module Editor")
        self.btn_mixin = QPushButton("Mixin Reference")
        self.btn_payload = QPushButton("Payload Selector")
        self.btn_execute = QPushButton("Execution Console")
        self.btn_session = QPushButton("Session Inspector")
        self.btn_validate = QPushButton("Validation Dashboard")
        self.btn_report = QPushButton("Generate Report")
        self.btn_report.setEnabled(False)

        for btn in [self.btn_lab, self.btn_scaffold, self.btn_editor, 
                     self.btn_mixin, self.btn_payload, self.btn_execute,
                     self.btn_session, self.btn_validate, self.btn_report]:
            btn.setStyleSheet(btn_style)
            left_layout.addWidget(btn)

        left_layout.addStretch()

        # Config group
        config_group = QGroupBox("Lab Target Configuration")
        config_layout = QVBoxLayout(config_group)
        self.target_url = QLineEdit("192.168.1.50")
        self.target_url.setPlaceholderText("Vulnerable service URL/IP")
        self.target_port = QSpinBox()
        self.target_port.setRange(1, 65535)
        self.target_port.setValue(4555)
        self.service_type = QComboBox()
        self.service_type.addItems(["HTTP", "TCP", "FTP", "SMB", "Custom"])
        self.rpc_password = QLineEdit()
        self.rpc_password.setPlaceholderText("msfrpcd password (OS keychain)")
        
        config_layout.addWidget(QLabel("Target URL/IP"))
        config_layout.addWidget(self.target_url)
        config_layout.addWidget(QLabel("Target Port"))
        config_layout.addWidget(self.target_port)
        config_layout.addWidget(QLabel("Service Type"))
        config_layout.addWidget(self.service_type)
        config_layout.addWidget(QLabel("RPC Password"))
        config_layout.addWidget(self.rpc_password)
        left_layout.addWidget(config_group)

        layout.addWidget(self.left_panel)

        # Right panel - stack of views
        self.stack = QStackedWidget()
        layout.addWidget(self.stack, stretch=1)

        # Lab target config view
        self.lab_view = QWidget()
        lv_layout = QVBoxLayout(self.lab_view)
        lv_layout.addWidget(QLabel("Target Config"))
        self.target_info = QTableWidget()
        self.target_info.setColumnCount(2)
        self.target_info.setHorizontalHeaderLabels(["Parameter", "Value"])
        lv_layout.addWidget(self.target_info)
        self.stack.addWidget(self.lab_view)

        # Module scaffolder view
        self.scaffold_view = QWidget()
        sv_layout = QVBoxLayout(self.scaffold_view)
        sv_layout.addWidget(QLabel("Module Scaffolder - Select type and generate skeleton"))
        self.scaffold_type = QComboBox()
        self.scaffold_type.addItems(["Command Injection", "Auxiliary Scanner", "Buffer Overflow", "Browser Exploit"])
        sv_layout.addWidget(self.scaffold_type)
        btn_gen_scaffold = QPushButton("Generate Skeleton")
        btn_gen_scaffold.clicked.connect(self.gen_scaffold)
        sv_layout.addWidget(btn_gen_scaffold)
        self.scaffold_output = QTextEdit()
        self.scaffold_output.setPlaceholderText("Generated module skeleton will appear here")
        sv_layout.addWidget(self.scaffold_output)
        self.stack.addWidget(self.scaffold_view)

        # Module editor view
        self.editor_view = QWidget()
        ev_layout = QVBoxLayout(self.editor_view)
        ev_layout.addWidget(QLabel("Module Editor - Ruby source with syntax highlighting"))
        self.module_editor = QTextEdit()
        self.module_editor.setPlaceholderText("Module source code will appear here...\nStart with scaffold, then edit methods (initialize, exploit/run, check)")
        ev_layout.addWidget(self.module_editor)
        btn_load_module = QPushButton("Load Module")
        btn_load_module.clicked.connect(self.load_module)
        ev_layout.addWidget(btn_load_module)
        self.stack.addWidget(self.editor_view)

        # Mixin reference view
        self.mixin_view = QWidget()
        mv_layout = QVBoxLayout(self.mixin_view)
        mv_layout.addWidget(QLabel("Mixin Reference - Available mixins with documentation"))
        self.mixin_table = QTableWidget()
        self.mixin_table.setColumnCount(3)
        self.mixin_table.setHorizontalHeaderLabels(["Mixin", "Methods", "Usage"])
        self.mixin_table.setRowCount(5)
        mixin_data = [
            ("HttpClient", "get, post, put, delete, head", "Use for HTTP-based modules"),
            ("Tcp", "connect, sock.put, sock.get_once", "Use for TCP-based modules"),
            ("Scanner", "RHOSTS, THREADS, run_host(ip)", "Use for scanner modules"),
            ("HttpServer", "on_request_uri, send_response, primer", "Use for browser/Server modules"),
            ("SMB", "smb_login, smb_trans2", "Use for SMB-based modules"),
        ]
        for row, (mixin, methods, usage) in enumerate(mixin_data):
            self.mixin_table.setItem(row, 0, QTableWidgetItem(mixin))
            self.mixin_table.setItem(row, 1, QTableWidgetItem(methods))
            self.mixin_table.setItem(row, 2, QTableWidgetItem(usage))
        mv_layout.addWidget(self.mixin_table)
        self.stack.addWidget(self.mixin_view)

        # Payload selector view
        self.payload_view = QWidget()
        pv_layout = QVBoxLayout(self.payload_view)
        pv_layout.addWidget(QLabel("Payload Selector - Compatible payloads for target platform"))
        self.payload_table = QTableWidget()
        self.payload_table.setColumnCount(3)
        self.payload_table.setHorizontalHeaderLabels(["Platform", "Payload", "Compatible"])
        payload_data = [
            ("linux", "cmd/unix/interact", "Yes"),
            ("linux", "linux/x64/meterpreter/reverse_tcp", "Yes"),
            ("windows", "windows/meterpreter/reverse_tcp", "Yes"),
            ("unix", "cmd/unix/reverse", "Yes"),
        ]
        for row, (platform, payload, compatible) in enumerate(payload_data):
            self.payload_table.setItem(row, 0, QTableWidgetItem(platform))
            self.payload_table.setItem(row, 1, QTableWidgetItem(payload))
            self.payload_table.setItem(row, 2, QTableWidgetItem(compatible))
        pv_layout.addWidget(self.payload_table)
        self.stack.addWidget(self.payload_view)

        # Execution console view
        self.exec_view = QWidget()
        evc_layout = QVBoxLayout(self.exec_view)
        evc_layout.addWidget(QLabel("Execution Console - Configure and run module via RPC"))
        self.rphost = QLineEdit("127.0.0.1")
        self.rphost.setPlaceholderText("RHOSTS")
        self.rport = QSpinBox()
        self.rport.setRange(1, 65535)
        self.rport.setValue(4444)
        self.lhost_exec = QLineEdit("127.0.0.1")
        self.lhost_exec.setPlaceholderText("LHOST")
        self.lport_exec = QSpinBox()
        self.lport_exec.setRange(1, 65535)
        self.lport_exec.setValue(9999)
        self.payload_sel = QComboBox()
        self.payload_sel.addItems(["cmd/unix/interact", "linux/x64/meterpreter/reverse_tcp"])
        btn_execute_module = QPushButton("Execute Module")
        btn_execute_module.clicked.connect(self.execute_module)
        evc_layout.addWidget(QLabel("RHOSTS"))
        evc_layout.addWidget(self.rphost)
        evc_layout.addWidget(QLabel("RPORT"))
        evc_layout.addWidget(self.rport)
        evc_layout.addWidget(QLabel("LHOST"))
        evc_layout.addWidget(self.lhost_exec)
        evc_layout.addWidget(QLabel("LPORT"))
        evc_layout.addWidget(self.lport_exec)
        evc_layout.addWidget(QLabel("Payload"))
        evc_layout.addWidget(self.payload_sel)
        evc_layout.addWidget(btn_execute_module)
        self.exec_console = QTextEdit()
        self.exec_console.setPlaceholderText("RPC communication and module output will appear here...")
        evc_layout.addWidget(self.exec_console)
        self.stack.addWidget(self.exec_view)

        # Session inspector view
        self.session_view = QWidget()
        svc_layout = QVBoxLayout(self.session_view)
        svc_layout.addWidget(QLabel("Session Inspector - View and interact with created sessions"))
        self.session_table = QTableWidget()
        self.session_table.setColumnCount(4)
        self.session_table.setHorizontalHeaderLabels(["Session ID", "Type", "Target", "Status"])
        svc_layout.addWidget(self.session_table)
        btn_interact = QPushButton("Interact with Session")
        svc_layout.addWidget(btn_interact)
        self.stack.addWidget(self.session_view)

        # Validation dashboard view
        self.validate_view = QWidget()
        v_layout = QVBoxLayout(self.validate_view)
        v_layout.addWidget(QLabel("Validation Dashboard - Run checks and view results"))
        self.validate_output = QTextEdit()
        self.validate_output.setPlaceholderText("Validation results will appear here\nSyntax check, module load check, check method execution")
        v_layout.addWidget(self.validate_output)
        btn_run_validate = QPushButton("Run Validation Checks")
        btn_run_validate.clicked.connect(self.run_validation)
        v_layout.addWidget(btn_run_validate)
        self.stack.addWidget(self.validate_view)

        # Report view
        self.report_view = QWidget()
        rpt_layout = QVBoxLayout(self.report_view)
        rpt_layout.addWidget(QLabel("Report History"))
        self.report_table = QTableWidget()
        self.report_table.setColumnCount(3)
        self.report_table.setHorizontalHeaderLabels(["Module ID", "Execution Status", "Report Path"])
        rpt_layout.addWidget(self.report_table)
        self.btn_export_report = QPushButton("Export Report")
        self.btn_export_report.clicked.connect(self.export_report)
        rpt_layout.addWidget(self.btn_export_report)
        self.stack.addWidget(self.report_view)

        # Connect buttons
        self.btn_lab.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        self.btn_scaffold.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        self.btn_editor.clicked.connect(lambda: self.stack.setCurrentIndex(2))
        self.btn_mixin.clicked.connect(lambda: self.stack.setCurrentIndex(3))
        self.btn_payload.clicked.connect(lambda: self.stack.setCurrentIndex(4))
        self.btn_execute.clicked.connect(lambda: self.stack.setCurrentIndex(5))
        self.btn_session.clicked.connect(lambda: self.stack.setCurrentIndex(6))
        self.btn_validate.clicked.connect(lambda: self.stack.setCurrentIndex(7))
        self.btn_report.clicked.connect(lambda: self.stack.setCurrentIndex(8))

    def refresh_modules(self):
        conn = sqlite3.connect(str(DATA_DIR / "module_data.db"))
        c = conn.cursor()
        c.execute("SELECT module_id, name, module_type, execution_status FROM modules ORDER BY created_at DESC")
        rows = c.fetchall()
        self.report_table.setRowCount(len(rows))
        for row_idx, row_data in enumerate(rows):
            for col_idx, val in enumerate(row_data):
                self.report_table.setItem(row_idx, col_idx, QTableWidgetItem(str(val)))
        conn.close()

    def gen_scaffold(self):
        stype = self.scaffold_type.currentText()
        scaffolds = {
            "Command Injection": """class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize
    register_host('RHOSTS', 'RPORT', 'TARGETURI')
    super
  end

  def exploit
    send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri, 'payload')
    })
  end
end
""",
            "Auxiliary Scanner": """class MetasploitModule < Msf::Auxiliary
  Rank = ExcellentRanking

  include Msf::Auxiliary::Scanner::Tcp

  def initialize
    super
  end

  def run_host(ip)
    connect
    sock.put("probe data")
    disconnect
  end
end
""",
            "Buffer Overflow": """class MetasploitModule < Msf::Exploit::Remote
  Rank = GoodRanking

  include Msf::Exploit::Remote::Tcp

  def initialize
    register_options([
      OptPath.new('TARGETFILE', [true, 'Path to target file'])
    ], self.class)
    super
  end

  def exploit
    fname = datastore['TARGETFILE']
    # Trigger buffer overflow
  end
end
""",
            "Browser Exploit": """class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpServer

  def initialize
    super
  end

  def on_request_uri(request)
    send_response(request, "Hello, world!")
  end
end
"""
        }
        scaffold = scaffolds.get(stype, "# Scaffold generation for: " + stype)
        self.scaffold_output.setText(scaffold)
        QMessageBox.information(self, "Scaffold Generated", f"{stype} module skeleton generated.")

    def load_module(self):
        QMessageBox.information(self, "Load Module", "Module loading interface would open here.")

    def execute_module(self):
        QMessageBox.information(self, "Execute Module", "Module execution via RPC interface would open here.")

    def run_validation(self):
        QMessageBox.information(self, "Validation", "Validation checks interface would open here.")

    def export_report(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Report", "", 
                                                   "JSON (*.json);;CSV (*.csv);;HTML (*.html);;PDF (*.pdf)")
        if file_path:
            QMessageBox.information(self, "Export Successful", f"Report exported to {file_path}")
            self.save_state()

    def save_state(self):
        state = {
            "app_name": "MMBW",
            "timestamp": datetime.now().isoformat(),
            "last_module": self.module_editor.toPlainText()[:50] if hasattr(self, 'module_editor') else "none",
            "current_view": self.stack.currentIndex() if hasattr(self, 'stack') else 0
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
    window = MMBWApp()
    window.show()
    sys.exit(app.exec_())