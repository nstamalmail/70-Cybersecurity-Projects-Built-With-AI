"""Views for the Dynamic Analysis Sandbox."""
from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import QUrl, Qt, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.config import APP, demo_dir
from app.core.engine import DetonationResult, STAGES
from app.core.hypervisor import adapter_catalogue
from app.core.iocs import defang
from app.ui.theme import COLORS, color_for
from app.ui.widgets import (
    BarChart,
    ClickableText,
    DataTable,
    FilePicker,
    KVGrid,
    StatStrip,
    TimelineStrip,
    dim_label,
    section_label,
)

STAGE_LABELS = {
    "intake": "Sample intake (hash, defang, metadata)",
    "static": "Static preview (headers, strings, YARA-ready)",
    "provision": "VM provisioning (revert to clean snapshot, isolate network)",
    "execute": "Execute sample in the guest and monitor",
    "collect": "Collect behaviour, PCAP and dropped files",
    "teardown": "Teardown and revert to clean baseline",
    "report": "Build behaviour report",
}


class SessionView(QWidget):
    """Ingest telemetry, or run a full detonation workflow."""

    ingestRequested = Signal(str)
    detonateRequested = Signal(str, dict)
    demoRequested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(10)
        split = QSplitter(Qt.Horizontal)

        # --------------------------------------------------------------- left
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(8)

        ll.addWidget(section_label("1 \u00b7 Ingest existing telemetry"))
        ll.addWidget(
            dim_label(
                "Load a behaviour log from any sandbox: a DAS session (.json/.jsonl), "
                "a CAPE/Cuckoo report.json or a ProcMon CSV export. Analysis is offline."
            )
        )
        self.picker = FilePicker(
            caption="Select a behaviour log",
            file_filter=";;".join(f"{label} ({pat})" for label, pat in APP["file_filters"]),
            placeholder="Drop a behaviour log / report here",
        )
        ll.addWidget(self.picker)
        row = QHBoxLayout()
        btn_ingest = QPushButton("Analyse telemetry")
        btn_ingest.setProperty("accent", "true")
        btn_ingest.clicked.connect(lambda: self.ingestRequested.emit(self.picker.text().strip()))
        btn_demo = QPushButton("Load demo data \u25be")
        btn_demo.setMenu(self._demo_menu())
        btn_folder = QPushButton("Open demo folder")
        btn_folder.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(demo_dir())))
        )
        row.addWidget(btn_ingest)
        row.addWidget(btn_demo)
        row.addWidget(btn_folder)
        row.addStretch(1)
        ll.addLayout(row)

        ll.addWidget(section_label("2 \u00b7 Detonate a sample in the sandbox"))
        ll.addWidget(
            dim_label(
                "Reverts the VM to the clean snapshot, forces hypervisor-level network "
                "isolation, boots the guest, executes the sample and collects telemetry. "
                "Dry-run is on by default: commands are printed, nothing is executed."
            )
        )
        self.sample_picker = FilePicker(
            caption="Select the sample to detonate",
            file_filter="Executables (*.exe *.dll *.sys *.scr);;All files (*)",
            placeholder="Drop the sample to detonate here",
        )
        ll.addWidget(self.sample_picker)
        options = QGroupBox("Detonation options")
        form = QFormLayout(options)
        self.combo_backend = QComboBox()
        for entry in adapter_catalogue(APP_SETTINGS_PROXY):
            self.combo_backend.addItem(
                f"{entry['back end']} ({entry['available']})", entry["back end"]
            )
        self.check_dryrun = QCheckBox("Dry run - print hypervisor commands without executing them")
        self.check_dryrun.setChecked(True)
        self.check_collect = QCheckBox("Collect telemetry from the guest agent (or harness)")
        self.check_collect.setChecked(True)
        form.addRow("Hypervisor back end", self.combo_backend)
        form.addRow("", self.check_dryrun)
        form.addRow("", self.check_collect)
        ll.addWidget(options)
        btn_detonate = QPushButton("Run detonation workflow")
        btn_detonate.setProperty("accent", "true")
        btn_detonate.clicked.connect(self._emit_detonate)
        ll.addWidget(btn_detonate)

        self.notes = QPlainTextEdit()
        self.notes.setReadOnly(True)
        self.notes.setMaximumHeight(140)
        self.notes.setPlainText(
            "Isolation guarantees enforced by this tool:\n"
            "  \u2022 revert to the clean-baseline snapshot before every run\n"
            "  \u2022 network disabled at the hypervisor level (--nic1 null)\n"
            "  \u2022 no shared folders, no clipboard, no USB passthrough\n"
            "  \u2022 sample is only ever read (hashed) on the host, never executed\n"
            "Telemetry from the built-in harness is always labelled SIMULATED."
        )
        ll.addWidget(self.notes)
        ll.addStretch(1)

        # -------------------------------------------------------------- right
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(8)
        rl.addWidget(section_label("Progress"))
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        rl.addWidget(self.progress)
        self.stage_list = QListWidget()
        for stage in STAGES:
            item = QListWidgetItem(f"\u00b7  {STAGE_LABELS.get(stage, stage)}")
            item.setData(Qt.UserRole, stage)
            self.stage_list.addItem(item)
        rl.addWidget(self.stage_list, 1)
        rl.addWidget(section_label("Result summary"))
        self.stats = StatStrip()
        self.stats.set_stats(
            [("Severity", "\u2014", None), ("Score", "\u2014", None),
             ("Events", "\u2014", None), ("Processes", "\u2014", None),
             ("Signatures", "\u2014", None), ("IOCs", "\u2014", None)]
        )
        rl.addWidget(self.stats)
        self.note = dim_label("")
        rl.addWidget(self.note)

        split.addWidget(left)
        split.addWidget(right)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        root.addWidget(split)

    # ---------------------------------------------------------------- helpers
    def _demo_menu(self) -> QMenu:
        menu = QMenu(self)
        menu.addAction("Full detonation workflow (simulated harness)",
                       lambda: self.demoRequested.emit("detonation"))
        menu.addAction("Ransomware-style session telemetry (file)",
                       lambda: self.demoRequested.emit("session-file"))
        menu.addAction("Benign updater session telemetry (file)",
                       lambda: self.demoRequested.emit("benign"))
        menu.addSeparator()
        menu.addAction("Open the demo folder",
                       lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(demo_dir()))))
        return menu

    def _emit_detonate(self) -> None:
        path = self.sample_picker.path()
        if not path:
            QMessageBox.warning(self, APP["name"], "Choose a sample to detonate first.")
            return
        self.detonateRequested.emit(
            str(path),
            {
                "backend": self.combo_backend.currentData(),
                "dry_run": self.check_dryrun.isChecked(),
                "collect": self.check_collect.isChecked(),
            },
        )

    # --------------------------------------------------------------- progress
    def begin(self) -> None:
        self.progress.setRange(0, 0)
        for i in range(self.stage_list.count()):
            item = self.stage_list.item(i)
            item.setText(f"\u00b7  {STAGE_LABELS.get(item.data(Qt.UserRole), '')}")
        self.note.setText("")

    def set_stage(self, stage: str, done: int = 0, total: int = 0) -> None:
        index = STAGES.index(stage) if stage in STAGES else -1
        for i in range(self.stage_list.count()):
            item = self.stage_list.item(i)
            label = STAGE_LABELS.get(item.data(Qt.UserRole), "")
            if i < index:
                item.setText(f"\u2713  {label}")
            elif i == index:
                item.setText(f"\u25b6  {label}")
        if index >= 0:
            self.progress.setValue(int((index + 1) / len(STAGES) * 100))

    def finish(self, result: DetonationResult) -> None:
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        for i in range(self.stage_list.count()):
            item = self.stage_list.item(i)
            item.setText(f"\u2713  {STAGE_LABELS.get(item.data(Qt.UserRole), '')}")
        self.stats.set_stats(
            [
                ("Severity", result.severity.upper(), color_for(result.severity)),
                ("Score", f"{result.score}/100", color_for(result.severity)),
                ("Events", len(result.session.events), None),
                ("Processes", len(result.session.processes), None),
                ("Signatures", len(result.signatures), color_for("high" if result.signatures else "low")),
                ("IOCs", len(result.iocs), None),
            ]
        )
        notes = list(result.warnings)
        if result.session.simulation:
            notes.insert(0, "SIMULATED telemetry")
        self.note.setText(" \u00b7 ".join(notes)[:420])
        if notes:
            self.note.setStyleSheet(f"color:{COLORS['warn']};")

    def fail(self, message: str) -> None:
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.note.setText(f"Failed: {message}")
        self.note.setStyleSheet(f"color:{COLORS['bad']};")


class TimelineView(QWidget):
    """Colour-coded behaviour timeline with a filterable event table."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)
        head = QHBoxLayout()
        head.addWidget(section_label("Behaviour timeline"))
        head.addStretch(1)
        self.combo_lane = QComboBox()
        self.combo_lane.addItem("All lanes", "")
        self.combo_lane.currentIndexChanged.connect(lambda _: self._refresh())
        self.combo_pid = QComboBox()
        self.combo_pid.addItem("All processes", "")
        self.combo_pid.currentIndexChanged.connect(lambda _: self._refresh())
        head.addWidget(QLabel("Lane"))
        head.addWidget(self.combo_lane)
        head.addWidget(QLabel("Process"))
        head.addWidget(self.combo_pid)
        root.addLayout(head)
        self.strip = TimelineStrip(height=170)
        self.strip.eventClicked.connect(self._focus_event)
        root.addWidget(self.strip)
        self.table = DataTable(
            ["Time", "Process", "Event", "Detail"], export_name="timeline"
        )
        root.addWidget(self.table, 1)
        self._result: DetonationResult | None = None

    def set_result(self, result: DetonationResult) -> None:
        self._result = result
        session = result.session
        lanes = sorted({e.lane for e in session.events})
        self.combo_lane.blockSignals(True)
        self.combo_lane.clear()
        self.combo_lane.addItem("All lanes", "")
        for lane in lanes:
            self.combo_lane.addItem(lane, lane)
        self.combo_lane.blockSignals(False)
        self.combo_pid.blockSignals(True)
        self.combo_pid.clear()
        self.combo_pid.addItem("All processes", "")
        for node in session.processes:
            self.combo_pid.addItem(f"{node.name} ({node.pid})", str(node.pid))
        self.combo_pid.blockSignals(False)
        self.strip.set_events(
            [
                {
                    "ts": e.ts,
                    "label": e.label,
                    "category": e.lane,
                    "detail": e.summary(),
                }
                for e in session.events
            ],
            lanes=["process", "file", "registry", "persistence", "network", "dns", "system"],
        )
        self._refresh()

    def _filtered(self):
        assert self._result
        lane = self.combo_lane.currentData() or ""
        pid = self.combo_pid.currentData() or ""
        for event in self._result.session.events:
            if lane and event.lane != lane:
                continue
            if pid and str(event.process_id) != str(pid):
                continue
            yield event

    def _refresh(self) -> None:
        if not self._result:
            return
        self.table.set_data(
            [[e.clock(), f"{e.process_name} ({e.process_id})", e.label, e.summary()[:400]]
             for e in self._filtered()]
        )

    def _focus_event(self, index: int) -> None:
        if not self._result:
            return
        events = list(self._filtered())
        if 0 <= index < len(events):
            event = events[index]
            self.table.table.selectRow(index)


class ProcessesView(QWidget):
    """Process tree plus a detail pane."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)
        root.addWidget(section_label("Process tree"))
        root.addWidget(
            dim_label(
                "Reconstructed from parent-child relationships in the telemetry. "
                "Colour shows whether a process injected, was injected into, or was targeted."
            )
        )
        split = QSplitter(Qt.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Process", "PID", "First seen", "Status"])
        self.tree.setColumnWidth(0, 300)
        self.tree.itemSelectionChanged.connect(self._on_select)
        split.addWidget(self.tree)
        detail = QWidget()
        dl = QVBoxLayout(detail)
        dl.setContentsMargins(0, 0, 0, 0)
        dl.addWidget(section_label("Process detail"))
        self.detail = KVGrid({})
        dl.addWidget(self.detail)
        self.related = DataTable(["Time", "Event", "Detail"], export_name="process_events", show_toolbar=False)
        dl.addWidget(self.related, 1)
        split.addWidget(detail)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 4)
        root.addWidget(split, 1)
        self.table = DataTable(
            ["PID", "Parent", "Name", "Path", "Command line", "First", "Last"],
            export_name="processes",
        )
        self.table.setMaximumHeight(190)
        root.addWidget(self.table)
        self._result: DetonationResult | None = None

    def set_result(self, result: DetonationResult) -> None:
        self._result = result
        session = result.session
        self.tree.clear()
        nodes = {p.pid: p for p in session.processes}
        items: dict[int, QTreeWidgetItem] = {}
        for node in sorted(session.processes, key=lambda p: (p.first_seen, p.pid)):
            item = QTreeWidgetItem([f"{node.name}", str(node.pid), f"{node.first_seen:.2f}s", node.status])
            colour = color_for(node.risk or ("high" if node.status in ("injected", "targeted") else "info"))
            item.setForeground(0, QColor(colour))
            item.setData(0, Qt.UserRole, node.pid)
            items[node.pid] = item
            parent = nodes.get(node.parent_pid) if node.parent_pid else None
            if parent and parent.pid in items:
                items[parent.pid].addChild(item)
            else:
                self.tree.addTopLevelItem(item)
        self.tree.expandAll()
        self.table.set_data(
            [
                [p.pid, p.parent_pid if p.parent_pid is not None else "-", p.name, p.path,
                 p.command_line, f"{p.first_seen:.2f}", f"{p.last_seen:.2f}"]
                for p in sorted(session.processes, key=lambda p: p.pid)
            ]
        )
        if self.tree.topLevelItemCount():
            self.tree.setCurrentItem(self.tree.topLevelItem(0))

    def _on_select(self) -> None:
        if not self._result:
            return
        item = self.tree.currentItem()
        if item is None:
            return
        pid = item.data(0, Qt.UserRole)
        node = self._result.session.process_by_pid(int(pid))
        if not node:
            return
        self.detail.set_data(
            {
                "PID": node.pid,
                "Parent PID": node.parent_pid if node.parent_pid is not None else "-",
                "Name": node.name,
                "Path": node.path,
                "Command line": node.command_line,
                "User": node.user,
                "First seen": f"{node.first_seen:.3f}s",
                "Last seen": f"{node.last_seen:.3f}s",
                "Status": node.status,
            }
        )
        events = [e for e in self._result.session.events if e.process_id == int(pid)]
        self.related.set_data(
            [[e.clock(), e.label, e.summary()[:300]] for e in events[:400]]
        )


class NetworkView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)
        root.addWidget(section_label("Network activity"))
        root.addWidget(
            dim_label(
                "Connections captured on the host side of the isolated virtual adapter "
                "(the guest never reaches the internet)."
            )
        )
        self.chart = BarChart(height=180)
        root.addWidget(self.chart)
        tabs = QTabWidget()
        self.connections = DataTable(
            ["Time", "Process", "Destination", "Port", "Protocol", "Sent", "Received"],
            export_name="connections",
        )
        self.dns = DataTable(["Time", "Process", "Query", "Answer", "Status"], export_name="dns")
        self.http = DataTable(
            ["Time", "Process", "URL", "Method", "User-Agent", "Bytes"],
            export_name="http",
        )
        tabs.addTab(self.connections, "Connections")
        tabs.addTab(self.dns, "DNS")
        tabs.addTab(self.http, "HTTP")
        root.addWidget(tabs, 1)

    def set_result(self, result: DetonationResult) -> None:
        session = result.session
        connections = [e for e in session.by_type("network") if e.dst_ip]
        counts: dict[str, int] = {}
        for event in connections:
            key = f"{event.dst_ip}:{event.dst_port or '-'}"
            counts[key] = counts.get(key, 0) + 1
        ordered = sorted(counts.items(), key=lambda kv: -kv[1])[:14]
        self.chart.set_data(
            [k for k, _ in ordered], [v for _, v in ordered], unit=" connections",
            bands=[(1e9, COLORS["bad"])],
        )
        self.connections.set_data(
            [
                [e.clock(), e.process_name, e.dst_ip, e.dst_port, e.protocol,
                 e.bytes_sent, e.bytes_received]
                for e in connections
            ]
        )
        self.dns.set_data(
            [
                [e.clock(), e.process_name, str(e.arguments.get("query", "")), e.dst_ip, e.status]
                for e in session.by_type("dns")
            ]
        )
        self.http.set_data(
            [
                [e.clock(), e.process_name, e.path, str(e.arguments.get("method", "")),
                 str(e.arguments.get("user-agent", ""))[:80], e.bytes_received]
                for e in session.by_type("http")
            ]
        )


class ArtifactsView(QWidget):
    """File system, registry and persistence changes."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)
        root.addWidget(section_label("System changes"))
        self.tabs = QTabWidget()
        self.files = DataTable(["Time", "Process", "Event", "Path", "SHA-256"], export_name="file_ops")
        self.dropped = DataTable(["Time", "Process", "Path", "SHA-256"], export_name="dropped_files")
        self.registry = DataTable(
            ["Time", "Process", "Event", "Key", "Value", "Data"], export_name="registry"
        )
        self.persistence = DataTable(
            ["Time", "Process", "Type", "Name", "Target"], export_name="persistence"
        )
        self.tabs.addTab(self.files, "File system")
        self.tabs.addTab(self.dropped, "Dropped files")
        self.tabs.addTab(self.registry, "Registry")
        self.tabs.addTab(self.persistence, "Persistence")
        root.addWidget(self.tabs, 1)

    def set_result(self, result: DetonationResult) -> None:
        files = result.file_events()
        self.files.set_data(
            [[e.clock(), e.process_name, e.event_type, e.path, e.sha256] for e in files[:1500]]
        )
        dropped = [e for e in files if e.event_type == "dropped_file" and e.path]
        self.dropped.set_data(
            [[e.clock(), e.process_name, e.path, e.sha256] for e in dropped[:600]]
        )
        self.registry.set_data(
            [
                [e.clock(), e.process_name, e.event_type, e.path,
                 str(e.arguments.get("value_name", "")), str(e.arguments.get("value_data", ""))[:300]]
                for e in result.registry_events()[:1500]
            ]
        )
        self.persistence.set_data(
            [
                [e.clock(), e.process_name, e.event_type,
                 str(e.arguments.get("service_name") or e.arguments.get("task_name") or ""),
                 str(e.arguments.get("binary_path") or e.arguments.get("command") or "")[:300]]
                for e in result.persistence_events()
            ]
        )


class ApiCallsView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)
        head = QHBoxLayout()
        head.addWidget(section_label("API call log"))
        head.addStretch(1)
        self.check_high_value = QCheckBox("Only high-value APIs")
        self.check_high_value.setChecked(False)
        self.check_high_value.stateChanged.connect(lambda _: self._refresh())
        head.addWidget(self.check_high_value)
        root.addLayout(head)
        import re as _re

        self._interesting = _re.compile(
            r"(?i)(reg(set|create|delete|query)|createservice|createprocess|createremotethread|"
            r"virtualalloc|writeprocessmemory|readprocessmemory|internetopen|internetconnect|"
            r"httpsendrequest|urldownload|writefile|deletefile|cryp|bcrypt|shellexecute|winexec|"
            r"schrpc|createfile|loadlibrary|getprocaddress|isdebuggerpresent|openprocess)"
        )
        self.chart = BarChart(height=170)
        root.addWidget(self.chart)
        self.table = DataTable(
            ["Time", "Process", "DLL", "Function", "Category", "Arguments", "Result"],
            export_name="api_calls",
        )
        root.addWidget(self.table, 1)
        self._result: DetonationResult | None = None

    def set_result(self, result: DetonationResult) -> None:
        self._result = result
        counts: dict[str, int] = {}
        for event in result.api_events():
            key = event.function or "(unknown)"
            counts[key] = counts.get(key, 0) + 1
        ordered = sorted(counts.items(), key=lambda kv: -kv[1])[:16]
        self.chart.set_data([k for k, _ in ordered], [v for _, v in ordered], unit=" calls")
        self._refresh()

    def _refresh(self) -> None:
        if not self._result:
            return
        events = self._result.api_events()
        if self.check_high_value.isChecked():
            events = [e for e in events if self._interesting.search(e.function or "")]
        self.table.set_data(
            [
                [e.clock(), e.process_name, e.dll, e.function, e.category,
                 json.dumps(e.arguments, default=str)[:300], e.return_value or e.status]
                for e in events[:3000]
            ]
        )


class IOCView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)
        head = QHBoxLayout()
        head.addWidget(section_label("Indicators of compromise (observed behaviour)"))
        head.addStretch(1)
        self.check_defang = QCheckBox("Defang values")
        self.check_defang.stateChanged.connect(lambda _: self._refresh())
        head.addWidget(self.check_defang)
        btn = QPushButton("Export IOC CSV\u2026")
        btn.clicked.connect(self._export)
        head.addWidget(btn)
        root.addLayout(head)
        self.chart = BarChart(height=160)
        root.addWidget(self.chart)
        self.table = DataTable(
            ["Type", "Value", "Source", "Confidence", "Context"], export_name="iocs"
        )
        root.addWidget(self.table, 1)
        self._result: DetonationResult | None = None

    def set_result(self, result: DetonationResult) -> None:
        self._result = result
        counts: dict[str, int] = {}
        for ioc in result.iocs:
            counts[ioc["ioc_type"]] = counts.get(ioc["ioc_type"], 0) + 1
        ordered = sorted(counts.items(), key=lambda kv: -kv[1])
        self.chart.set_data([k for k, _ in ordered], [v for _, v in ordered], unit=" IOCs")
        self._refresh()

    def _refresh(self) -> None:
        if not self._result:
            return
        rows = []
        for ioc in self._result.iocs:
            value = ioc["value"]
            if self.check_defang.isChecked() and ioc["ioc_type"] in (
                "url", "domain", "ipv4", "dns_query", "user_agent",
            ):
                value = defang(value)
            rows.append(
                [ioc["ioc_type"], value, ioc.get("sources", "dynamic"),
                 f"{ioc.get('confidence', 0):.2f}", ioc.get("context", "")]
            )
        self.table.set_data(rows)

    def _export(self) -> None:
        if not self._result:
            QMessageBox.warning(self, APP["name"], "Nothing to export yet.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export IOC list", "iocs.csv", "CSV (*.csv)")
        if not path:
            return
        Path(path).write_text(self.table.csv_text(), encoding="utf-8", newline="")
        QMessageBox.information(self, APP["name"], f"IOC list written to:\n{path}")


class BackendsView(QWidget):
    """Hypervisor availability and isolation posture."""

    def __init__(self, settings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)
        root.addWidget(section_label("Hypervisor back ends"))
        root.addWidget(
            dim_label(
                "Availability is probed locally. The simulated harness always works and is "
                "used when no hypervisor is present; its telemetry is labelled SIMULATED."
            )
        )
        self.table = DataTable(
            ["Back end", "Available", "Detail", "Isolation"], export_name="hypervisors"
        )
        self.table.set_data(
            [[e["back end"], e["available"], e["detail"], e["isolation"]]
             for e in adapter_catalogue(settings)]
        )
        root.addWidget(self.table, 1)
        root.addWidget(section_label("Isolation checklist"))
        self.checklist = ClickableText(
            "Revert to clean-baseline snapshot before every run ............ enforced by the pipeline\n"
            "Network disabled at hypervisor level (--nic1 null) ............ enforced by the adapter\n"
            "No shared folders, clipboard or USB passthrough ............... set by the adapter\n"
            "Sample is hashed on the host, never executed .................. enforced by the pipeline\n"
            "Dropped files are stored hashed and never executed ............ enforced by the pipeline\n"
            "Telemetry from the harness is labelled SIMULATED .............. enforced by the engine"
        )
        root.addWidget(self.checklist, 1)


# Imported lazily to avoid a circular import at module load time.
class _SettingsProxy:
    def get(self, key, default=None):
        from app.config import SETTINGS

        return SETTINGS.get(key, default)


APP_SETTINGS_PROXY = _SettingsProxy()

__all__ = [
    "SessionView",
    "TimelineView",
    "ProcessesView",
    "NetworkView",
    "ArtifactsView",
    "ApiCallsView",
    "IOCView",
    "BackendsView",
]
