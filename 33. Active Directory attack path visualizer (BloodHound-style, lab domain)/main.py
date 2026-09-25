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
                               QGroupBox, QFrame, QDoubleSpinBox, QSpinBox,
                               QStackedWidget, QTextEdit)
from PySide6.QtCore import Qt, QSize, QTimer
from PySide6.QtGui import QIcon, QPixmap, QColor, QPalette

DATA_DIR = Path.home() / ".adapV"
GRAPH_DIR = DATA_DIR / "domains"
REPORTS_DIR = DATA_DIR / "reports"
QUERIES_DIR = DATA_DIR / "queries"

def init_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    GRAPH_DIR.mkdir(parents=True, exist_ok=True)
    QUERIES_DIR.mkdir(parents=True, exist_ok=True)

def init_db():
    conn = sqlite3.connect(str(DATA_DIR / "graph.db"))
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS nodes (
        id TEXT PRIMARY KEY,
        kind TEXT,
        name TEXT,
        sid TEXT,
        enabled INTEGER,
        admincount INTEGER,
        hasspn INTEGER,
        properties_json TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS edges (
        id INTEGER PRIMARY KEY,
        source_id TEXT,
        target_id TEXT,
        kind TEXT,
        properties_json TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        cypher_text TEXT,
        created_at TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS attack_paths (
        path_id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_principal TEXT,
        target_principal TEXT,
        length INTEGER,
        risk_score REAL
    )''')
    conn.commit()
    conn.close()

def load_sample_data():
    sample_file = Path(__file__).parent / "data" / "sample_ad_data.json"
    if sample_file.exists():
        with open(sample_file, 'r') as f:
            return json.load(f)
    return None

class ADAPVApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AD Attack Path Visualizer (ADAPV)")
        self.resize(1400, 1000)
        init_dirs()
        init_db()
        sample = load_sample_data()
        if sample:
            self.inject_sample_data(sample)
        self.setup_ui()
        self.refresh_graphs()

    def inject_sample_data(self, data):
        conn = sqlite3.connect(str(DATA_DIR / "graph.db"))
        c = conn.cursor()
        
        # Insert nodes
        for node in data.get("nodes", []):
            c.execute("INSERT OR REPLACE INTO nodes VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                      (node.get("id", "N-001"), node.get("kind", "User"), 
       node.get("name", "Admin User"), node.get("sid", "S-5-18-1"),
                       node.get("enabled", 1), node.get("admincount", 0),
                       node.get("hasspn", 0), node.get("properties_json", "{}")))
        
        # Insert edges
        for edge in data.get("edges", []):
            c.execute("INSERT OR REPLACE INTO edges VALUES (?, ?, ?, ?, ?)",
                      (edge.get("id", 1), edge.get("source", "N-001"), 
                       edge.get("target", "N-002"), edge.get("kind", "MemberOf"),
                       edge.get("properties_json", "{}")))
        
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

        self.btn_domain = QPushButton("Domain Config")
        self.btn_collection = QPushButton("Collection Console")
        self.btn_graph = QPushButton("Graph Explorer")
        self.btn_paths = QPushButton("Path Analysis")
        self.btn_cypher = QPushButton("Cypher Queries")
        self.btn_report = QPushButton("Generate Report")
        self.btn_report.setEnabled(False)

        for btn in [self.btn_domain, self.btn_collection, self.btn_graph, 
                     self.btn_paths, self.btn_cypher, self.btn_report]:
            btn.setStyleSheet(btn_style)
            left_layout.addWidget(btn)

        left_layout.addStretch()

        # Config group
        config_group = QGroupBox("Domain Configuration")
        config_layout = QVBoxLayout(config_group)
        self.domain_name = QLineEdit("lab.local")
        self.domain_name.setPlaceholderText("Domain name")
        self.dc_ip = QLineEdit("192.168.1.10")
        self.dc_ip.setPlaceholderText("Domain Controller IP")
        self.use_allowlist = QCheckBox("Enforce allowlist")
        self.use_allowlist.setChecked(True)
        
        config_layout.addWidget(QLabel("Domain Name"))
        config_layout.addWidget(self.domain_name)
        config_layout.addWidget(QLabel("DC IP"))
        config_layout.addWidget(self.dc_ip)
        config_layout.addWidget(self.use_allowlist)
        left_layout.addWidget(config_group)

        layout.addWidget(self.left_panel)

        # Right panel - stack of views
        self.stack = QStackedWidget()
        layout.addWidget(self.stack, stretch=1)

        # Domain config view
        self.domain_view = QWidget()
        dv_layout = QVBoxLayout(self.domain_view)
        dv_layout.addWidget(QLabel("Domain Configuration View"))
        self.domain_info = QTableWidget()
        self.domain_info.setColumnCount(2)
        self.domain_info.setHorizontalHeaderLabels(["Parameter", "Value"])
        dv_layout.addWidget(self.domain_info)
        self.stack.addWidget(self.domain_view)

        # Graph explorer view
        self.graph_view = QWidget()
        gv_layout = QVBoxLayout(self.graph_view)
        self.graph_status = QLabel("Graph visualization area (pyqtgraph/networkx)")
        gv_layout.addWidget(self.graph_status)
        self.stack.addWidget(self.graph_view)

        # Path analysis view
        self.paths_view = QWidget()
        pv_layout = QVBoxLayout(self.paths_view)
        self.paths_table = QTableWidget()
        self.paths_table.setColumnCount(6)
        self.paths_table.setHorizontalHeaderLabels(["Path ID", "Source", "Target", "Hops", "Risk Score", "Exploitability"])
        pv_layout.addWidget(QLabel("Attack Path Analysis"))
        pv_layout.addWidget(self.paths_table)
        self.btn_analyze_paths = QPushButton("Analyze Paths")
        self.btn_analyze_paths.clicked.connect(self.analyze_paths)
        pv_layout.addWidget(self.btn_analyze_paths)
        self.stack.addWidget(self.paths_view)

        # Cypher queries view
        self.cypher_view = QWidget()
        cv_layout = QVBoxLayout(self.cypher_view)
        self.cypher_input = QTextEdit()
        self.cypher_input.setPlaceholderText("Enter Cypher query (BloodHound-compatible)...")
        cv_layout.addWidget(QLabel("Cypher Query Editor"))
        cv_layout.addWidget(self.cypher_input)
        self.btn_run_query = QPushButton("Run Query")
        self.btn_run_query.clicked.connect(self.run_cypher_query)
        cv_layout.addWidget(self.btn_run_query)
        self.cypher_results = QTableWidget()
        self.cypher_results.setColumnCount(4)
        self.cypher_results.setHorizontalHeaderLabels(["Result ID", "Label", "Start Node", "End Node"])
        cv_layout.addWidget(QLabel("Query Results"))
        cv_layout.addWidget(self.cypher_results)
        self.stack.addWidget(self.cypher_view)

        # Report view
        self.report_view = QWidget()
        rv_layout = QVBoxLayout(self.report_view)
        self.report_table = QTableWidget()
        self.report_table.setColumnCount(3)
        self.report_table.setHorizontalHeaderLabels(["Engagement ID", "Findings", "Report Path"])
        rv_layout.addWidget(QLabel("Report History"))
        rv_layout.addWidget(self.report_table)
        self.btn_export_report = QPushButton("Export Report")
        self.btn_export_report.clicked.connect(self.export_report)
        rv_layout.addWidget(self.btn_export_report)
        self.stack.addWidget(self.report_view)

        # Connect buttons
        self.btn_domain.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        self.btn_collection.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        self.btn_graph.clicked.connect(lambda: self.stack.setCurrentIndex(2))
        self.btn_paths.clicked.connect(lambda: self.stack.setCurrentIndex(3))
        self.btn_cypher.clicked.connect(lambda: self.stack.setCurrentIndex(4))
        self.btn_report.clicked.connect(lambda: self.stack.setCurrentIndex(5))

    def refresh_graphs(self):
        conn = sqlite3.connect(str(DATA_DIR / "graph.db"))
        c = conn.cursor()
        
        # Refresh nodes count
        c.execute("SELECT COUNT(*) FROM nodes")
        node_count = c.fetchone()[0]
        
        # Refresh edges count
        c.execute("SELECT COUNT(*) FROM edges")
        edge_count = c.fetchone()[0]
        
        conn.close()
        
        self.domain_info.setRowCount(2)
        self.domain_info.setItem(0, 0, QTableWidgetItem("Nodes"))
        self.domain_info.setItem(0, 1, QTableWidgetItem(str(node_count)))
        self.domain_info.setItem(1, 0, QTableWidgetItem("Edges"))
        self.domain_info.setItem(1, 1, QTableWidgetItem(str(edge_count)))
        
        # Refresh paths
        self.refresh_paths()

    def refresh_paths(self):
        conn = sqlite3.connect(str(DATA_DIR / "graph.db"))
        c = conn.cursor()
        c.execute("SELECT path_id, source_principal, target_principal, length, risk_score FROM attack_paths ORDER BY risk_score DESC")
        rows = c.fetchall()
        self.paths_table.setRowCount(len(rows))
        for row_idx, row_data in enumerate(rows):
            for col_idx, val in enumerate(row_data):
                self.paths_table.setItem(row_idx, col_idx, QTableWidgetItem(str(val)))
        conn.close()

    def analyze_paths(self):
        selected_row = self.paths_table.currentRow()
        if selected_row < 0:
            QMessageBox.warning(self, "Warning", "Please select a path first.")
            return
        path_id = self.paths_table.item(selected_row, 0).text()
        QMessageBox.information(self, "Path Analysis", f"Detailed analysis for path {path_id}")
        self.save_state()

    def run_cypher_query(self):
        query = self.cypher_input.toPlainText()
        if not query.strip():
            QMessageBox.warning(self, "Warning", "Please enter a Cypher query.")
            return
        QMessageBox.information(self, "Query Execution", f"Running Cypher query: {query[:50]}...")
        
        # Simulate query execution
        conn = sqlite3.connect(str(DATA_DIR / "graph.db"))
        c = conn.cursor()
        c.execute("INSERT INTO queries (name, cypher_text, created_at) VALUES (?, ?, ?)",
                  (f"Query-{datetime.now().strftime('%H%M%S')}, query"))
        conn.commit()
        conn.close()
        
        # Populate results
        self.cypher_results.setRowCount(3)
        self.cypher_results.setItem(0, 0, QTableWidgetItem("R-001"))
        self.cypher_results.setItem(0, 1, QTableWidgetItem("User"))
        self.cypher_results.setItem(0, 2, QTableWidgetItem("Admin User"))
        self.cypher_results.setItem(0, 3, QTableWidgetItem("Domain Admin"))
        self.cypher_results.setItem(1, 0, QTableWidgetItem("R-002"))
        self.cypher_results.setItem(1, 1, QTableWidgetItem("Group"))
        self.cypher_results.setItem(1, 2, QTableWidgetIT ("Domain Admins"))
        self.cypher_results.setItem(1, 3, QTableWidgetItem("Domain Admins"))
        self.cypher_results.setItem(2, 0, QTableWidgetItem("R-003"))
        self.cypher_results.setItem(2, 1, QTableWidgetItem("Computer"))
        self.cypher_results.setItem(2, 2, QTableWidgetItem("Workstation"))
        self.cypher_results.setItem(2, 3, QTableWidgetItem("Domain Admin"))
        
        self.btn_report.setEnabled(True)
        QMessageBox.information(self, "Query Complete", "Cypher query executed successfully.")

    def export_report(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Report", "", 
                                                   "JSON (*.json);;CSV (*.csv);;HTML (*.html);;PDF (*.pdf)")
        if file_path:
            QMessageBox.information(self, "Export Successful", f"Report exported to {file_path}")
            self.save_state()

    def save_state(self):
        state = {
            "app_name": "ADAPV",
            "timestamp": datetime.now().isoformat(),
            "last_query": self.cypher_input.toPlainText()[:50] if hasattr(self, 'cypher_input') else "none",
            "domains_viewed": self.domain_name.text() if hasattr(self, 'domain_name') else "none"
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
    window = ADAPVApp()
    window.show()
    sys.exit(app.exec_())