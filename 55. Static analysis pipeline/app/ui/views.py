"""Views for the Static Analysis Pipeline."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QUrl, Qt, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
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
    QSpinBox,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.config import APP, demo_dir
from app.core.engine import STAGES, AnalysisResult
from app.ui.theme import COLORS, color_for
from app.ui.widgets import (
    BarChart,
    ClickableText,
    DataTable,
    FilePicker,
    KVGrid,
    StatStrip,
    dim_label,
    section_label,
)

STAGE_LABELS = {
    "load": "Load sample (read-only)",
    "hash": "Hash (MD5 / SHA-1 / SHA-256)",
    "pe": "Parse PE headers, sections, imports",
    "strings": "Extract and classify strings",
    "intel": "Threat intel hash lookups",
    "iocs": "Compile indicators of compromise",
    "verdict": "Score verdict",
    "report": "Build report",
}


# --------------------------------------------------------------------------- #
#  1. Sample loader / progress
# --------------------------------------------------------------------------- #
class SampleView(QWidget):
    """Load a sample, configure options, run the pipeline, watch progress."""

    analyzeRequested = Signal(str, dict)
    demoRequested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(10)

        split = QSplitter(Qt.Horizontal)

        # ------------------------------------------------------------ left
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(8)

        ll.addWidget(section_label("Sample"))
        ll.addWidget(
            dim_label(
                "Static, read-only triage. The file is never executed, uploaded or "
                "modified - it is only read as bytes."
            )
        )
        self.picker = FilePicker(
            caption="Select a sample",
            file_filter=";;".join(f"{label} ({pat})" for label, pat in APP["file_filters"]),
            placeholder="Drop a suspicious file here (or use Load demo data)",
        )
        ll.addWidget(self.picker)

        row = QHBoxLayout()
        self.btn_run = QPushButton("Run analysis")
        self.btn_run.setProperty("accent", "true")
        self.btn_run.clicked.connect(self._emit_analyze)
        self.btn_demo = QPushButton("Load demo data \u25be")
        self.btn_demo.setMenu(self._demo_menu())
        self.btn_folder = QPushButton("Open demo folder")
        self.btn_folder.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(demo_dir())))
        )
        row.addWidget(self.btn_run)
        row.addWidget(self.btn_demo)
        row.addWidget(self.btn_folder)
        row.addStretch(1)
        ll.addLayout(row)

        options = QGroupBox("Analysis options")
        form = QFormLayout(options)
        self.spin_minlen = QSpinBox()
        self.spin_minlen.setRange(4, 32)
        self.spin_minlen.setValue(4)
        self.spin_minlen.setToolTip("Minimum length for a string to be extracted")
        self.spin_maxmb = QSpinBox()
        self.spin_maxmb.setRange(1, 4096)
        self.spin_maxmb.setValue(500)
        self.spin_maxmb.setSuffix(" MB")
        self.check_network = QCheckBox("Enable threat intel lookups (hash only, needs API keys)")
        self.check_simulate = QCheckBox("Use SIMULATED intel response (demo only)")
        self.check_simulate.setToolTip(
            "Injects clearly-labelled synthetic intel so the results matrix can be "
            "demonstrated offline. Never presented as real intelligence."
        )
        form.addRow("Minimum string length", self.spin_minlen)
        form.addRow("Maximum file size", self.spin_maxmb)
        form.addRow("", self.check_network)
        form.addRow("", self.check_simulate)
        ll.addWidget(options)

        self.notes = QPlainTextEdit()
        self.notes.setReadOnly(True)
        self.notes.setMaximumHeight(120)
        self.notes.setPlainText(
            "Pipeline: load \u2192 hash \u2192 PE parse \u2192 strings \u2192 intel \u2192 IOCs \u2192 verdict \u2192 report.\n"
            "Hash and PE parsing run first; strings and intel follow. "
            "The report is generated automatically and is available on the "
            "'Report & Export' tab."
        )
        ll.addWidget(self.notes)
        ll.addStretch(1)

        # ----------------------------------------------------------- right
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(8)
        rl.addWidget(section_label("Progress"))
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
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
            [("Verdict", "\u2014", None), ("Risk score", "\u2014", None),
             ("Sections", "\u2014", None), ("Strings", "\u2014", None),
             ("IOCs", "\u2014", None), ("Duration", "\u2014", None)]
        )
        rl.addWidget(self.stats)
        self.demo_note = dim_label("")
        rl.addWidget(self.demo_note)

        split.addWidget(left)
        split.addWidget(right)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        root.addWidget(split)

    # ---------------------------------------------------------------- setup
    def _demo_menu(self) -> QMenu:
        menu = QMenu(self)
        menu.addAction(
            "Synthetic packed sample (in memory)",
            lambda: self.demoRequested.emit("packed"),
        )
        menu.addAction(
            "Benign updater sample (file on disk)",
            lambda: self.demoRequested.emit("benign"),
        )
        menu.addAction(
            "Inert text script (strings-only path)",
            lambda: self.demoRequested.emit("script"),
        )
        menu.addSeparator()
        menu.addAction(
            "Open the demo folder",
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(demo_dir()))),
        )
        return menu

    def options(self) -> dict:
        return {
            "min_string_length": self.spin_minlen.value(),
            "max_file_size_mb": self.spin_maxmb.value(),
            "enable_network_lookups": self.check_network.isChecked(),
            "simulate_intel": self.check_simulate.isChecked(),
        }

    def sample_path(self) -> str:
        path = self.picker.path()
        return str(path) if path else ""

    def _emit_analyze(self) -> None:
        if not self.sample_path():
            QMessageBox.warning(
                self, APP["name"], "Choose a sample first (or use Load demo data)."
            )
            return
        self.analyzeRequested.emit(self.sample_path(), self.options())

    # ------------------------------------------------------------- progress
    def begin(self) -> None:
        self.progress.setValue(0)
        self.progress.setRange(0, 0)
        for i in range(self.stage_list.count()):
            item = self.stage_list.item(i)
            item.setText(f"\u00b7  {STAGE_LABELS.get(item.data(Qt.UserRole), '')}")
            item.setForeground(Qt.white)
        self.demo_note.setText("")

    def set_stage(self, stage: str, done: int = 0, total: int = 0) -> None:
        index = STAGES.index(stage) if stage in STAGES else -1
        for i in range(self.stage_list.count()):
            item = self.stage_list.item(i)
            key = item.data(Qt.UserRole)
            label = STAGE_LABELS.get(key, key)
            if i < index:
                item.setText(f"\u2713  {label}")
            elif i == index:
                item.setText(f"\u25b6  {label}")
        if index >= 0:
            self.progress.setValue(int((index + 1) / len(STAGES) * 100))

    def finish(self, result: AnalysisResult) -> None:
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        for i in range(self.stage_list.count()):
            item = self.stage_list.item(i)
            item.setText(f"\u2713  {STAGE_LABELS.get(item.data(Qt.UserRole), '')}")
        v = result.verdict
        self.stats.set_stats(
            [
                ("Verdict", v.verdict if v else "\u2014", color_for(v.verdict) if v else None),
                ("Risk score", v.score if v else "\u2014", color_for(v.verdict) if v else None),
                ("Sections", len((result.pe_info or {}).get("sections", [])), None),
                ("Strings", result.string_stats.get("total", 0), None),
                ("IOCs", len(result.iocs), None),
                ("Duration", f"{result.duration:.2f}s", None),
            ]
        )
        note = " ".join(result.warnings) if result.warnings else ""
        self.demo_note.setText(note[:400])
        if note:
            self.demo_note.setStyleSheet(f"color:{COLORS['warn']};")

    def fail(self, message: str) -> None:
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.demo_note.setText(f"Failed: {message}")
        self.demo_note.setStyleSheet(f"color:{COLORS['bad']};")


# --------------------------------------------------------------------------- #
#  2. Hash panel
# --------------------------------------------------------------------------- #
class HashView(QWidget):
    lookupRequested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)
        root.addWidget(section_label("File hashes"))
        root.addWidget(
            dim_label(
                "Computed in a single streaming pass. Hashes are the only thing sent to "
                "threat intel sources - the sample itself is never uploaded."
            )
        )
        self.grid = KVGrid({})
        root.addWidget(self.grid)
        self.file_grid = KVGrid({})
        root.addWidget(self.file_grid)

        row = QHBoxLayout()
        self.btn_copy = QPushButton("Copy all hashes")
        self.btn_copy.clicked.connect(self._copy)
        self.btn_lookup = QPushButton("Look up hashes")
        self.btn_lookup.setProperty("accent", "true")
        self.btn_lookup.clicked.connect(self.lookupRequested.emit)
        row.addWidget(self.btn_copy)
        row.addWidget(self.btn_lookup)
        row.addStretch(1)
        root.addLayout(row)
        root.addStretch(1)

    def set_result(self, result: AnalysisResult) -> None:
        h = result.hashes
        self.grid.set_data(
            {
                "MD5": h.get("md5", ""),
                "SHA-1": h.get("sha1", ""),
                "SHA-256": h.get("sha256", ""),
                "imphash (PE imports)": (result.pe_info or {}).get("imphash", "n/a") or "n/a",
            }
        )
        self.file_grid.set_data(
            {
                "File name": result.file_name,
                "Path": result.path,
                "Size": f"{result.size} bytes",
                "File type": result.file_type,
                "Hashed bytes": h.get("hashed_bytes", result.size),
            }
        )

    def _copy(self) -> None:
        from PySide6.QtWidgets import QApplication

        rows = []
        for r in range(self.grid._table.rowCount()):
            key = self.grid._table.item(r, 0)
            val = self.grid._table.item(r, 1)
            rows.append(f"{key.text()}: {val.text()}")
        QApplication.clipboard().setText("\n".join(rows))


# --------------------------------------------------------------------------- #
#  3. PE inspector
# --------------------------------------------------------------------------- #
class PEView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)
        self.empty = dim_label("No PE image loaded. Analyse a Windows executable to populate this view.")
        root.addWidget(self.empty)
        self.tabs = QTabWidget()
        self.tabs.setVisible(False)
        root.addWidget(self.tabs, 1)

        self.header_grid = KVGrid({})
        self.sections = DataTable(["Name", "RVA", "Virtual size", "Raw size", "Entropy", "Perms", "Packer", "Risk"], export_name="sections")
        self.imports = DataTable(["DLL", "Functions"], export_name="imports")
        self.exports = DataTable(["Export"], export_name="exports")
        self.resources = DataTable(["Type", "Entries"], export_name="resources")
        self.debug = DataTable(["Type", "Timestamp", "PDB path", "Size"], export_name="debug")
        self.anomalies = DataTable(["Severity", "Finding", "Detail"], export_name="anomalies")
        self.entropy_chart = BarChart(height=210)

        for widget, title in (
            (self.header_grid, "Headers"),
            (self.sections, "Sections"),
            (self.imports, "Imports"),
            (self.exports, "Exports"),
            (self.resources, "Resources"),
            (self.debug, "Debug / PDB"),
            (self.anomalies, "Anomalies"),
        ):
            self.tabs.addTab(widget, title)

        entropy_page = QWidget()
        el = QVBoxLayout(entropy_page)
        el.setContentsMargins(8, 8, 8, 8)
        el.addWidget(
            dim_label(
                "Shannon entropy per section. Above the configured threshold (\u2265 7.0 by "
                "default) a section is very likely compressed, encrypted or packed."
            )
        )
        el.addWidget(self.entropy_chart)
        el.addStretch(1)
        self.tabs.addTab(entropy_page, "Entropy")

    def set_result(self, result: AnalysisResult) -> None:
        pe = result.pe_info
        if not pe:
            self.tabs.setVisible(False)
            self.empty.setVisible(True)
            self.empty.setText(
                "No PE image in this analysis: "
                + ("the input was not a Windows executable." if result.is_pe is False else "PE parsing failed.")
            )
            return
        self.empty.setVisible(False)
        self.tabs.setVisible(True)

        self.header_grid.set_data(
            {
                "Machine": f"{pe.get('machine', '')} ({pe.get('machine_raw', '')})",
                "Compile timestamp": pe.get("timestamp", ""),
                "Characteristics": pe.get("characteristics", ""),
                "DLL characteristics": pe.get("dll_characteristics", ""),
                "Address of entry point": f"0x{pe.get('entry_point', 0):08x}",
                "Entry point section": pe.get("entry_section", ""),
                "Image base": f"0x{pe.get('image_base', 0):08x}",
                "Subsystem": pe.get("subsystem", ""),
                "Size of image": pe.get("size_of_image", 0),
                "Size of headers": pe.get("size_of_headers", 0),
                "Overlay size": pe.get("overlay_size", 0),
                "Linker version": pe.get("linker", ""),
                "OS version": pe.get("os_version", ""),
                "Import count": pe.get("import_count", 0),
                "Export count": len(pe.get("exports", []) or []),
                "PDB path": pe.get("pdb_path") or "(none)",
                "Rich header": "yes" if pe.get("has_rich_header") else "no",
                "TLS directory": "yes" if pe.get("has_tls") else "no",
                "Load config": "yes" if pe.get("has_load_config") else "no",
            }
        )
        self.sections.set_data(result.section_rows())
        self.imports.set_data(
            [
                [dll, ", ".join(funcs)]
                for dll, funcs in sorted(
                    (pe.get("imports") or {}).items(), key=lambda kv: -len(kv[1])
                )
            ]
        )
        self.exports.set_data([[e] for e in (pe.get("exports") or [])] or [["(none)"]])
        self.resources.set_data(
            [[r["type"], r["count"]] for r in (pe.get("resources") or [])] or [["(none)", 0]]
        )
        self.debug.set_data(
            [[d["type"], d["timestamp"], d["pdb"], d["size"]] for d in (pe.get("debug_entries") or [])]
            or [["(none)", "", "", 0]]
        )
        self.anomalies.set_data(result.anomaly_rows() or [["-", "No structural anomalies detected", ""]])
        sections = pe.get("sections") or []
        self.entropy_chart.set_data(
            [s["name"] for s in sections],
            [float(s["entropy"]) for s in sections],
            unit=" bits/byte",
            bands=[(5.0, COLORS["ok"]), (7.0, COLORS["warn"]), (8.0, COLORS["bad"])],
            ref_line=7.0,
            ref_label="packing threshold (7.0)",
        )


# --------------------------------------------------------------------------- #
#  4. String explorer
# --------------------------------------------------------------------------- #
class StringsView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        head = QHBoxLayout()
        head.addWidget(section_label("Extracted strings"))
        head.addStretch(1)
        self.check_interesting = QCheckBox("Only actionable classes")
        self.check_interesting.setChecked(True)
        self.check_interesting.stateChanged.connect(lambda _: self._refresh_rows())
        head.addWidget(self.check_interesting)
        root.addLayout(head)

        split = QSplitter(Qt.Vertical)
        chart_page = QWidget()
        cl = QVBoxLayout(chart_page)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.addWidget(dim_label("Strings by classification"))
        self.chart = BarChart(height=180)
        cl.addWidget(self.chart)
        self.keywords = ClickableText("")
        self.keywords.setMaximumHeight(150)
        cl.addWidget(dim_label("Keyword themes (ransomware / credential / persistence / evasion / C2 / lateral)"))
        cl.addWidget(self.keywords)
        split.addWidget(chart_page)

        self.table = DataTable(
            ["Offset", "Type", "Length", "Class", "Value"], export_name="strings"
        )
        split.addWidget(self.table)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 5)
        root.addWidget(split, 1)
        self._result: AnalysisResult | None = None

    def set_result(self, result: AnalysisResult) -> None:
        self._result = result
        counts = (result.string_stats or {}).get("by_classification") or {}
        ordered = sorted(counts.items(), key=lambda kv: -kv[1])[:16]
        self.chart.set_data(
            [k for k, _ in ordered],
            [v for _, v in ordered],
            unit=" strings",
            bands=[(1e9, COLORS["info"])],
        )
        lines = []
        for group, hits in (result.keywords or {}).items():
            lines.append(f"\u25b6 {group} ({len(hits)})")
            for hit in hits[:6]:
                lines.append(f"    {hit[:160]}")
            lines.append("")
        self.keywords.set_text("\n".join(lines) or "No suspicious keyword themes detected.")
        self._refresh_rows()

    def _refresh_rows(self) -> None:
        if not self._result:
            return
        rows = (
            self._result.interesting_strings()
            if self.check_interesting.isChecked()
            else self._result.strings
        )
        self.table.set_data(
            [
                [r["offset_hex"], r["type"], r["length"], r["classification"], r["value"][:600]]
                for r in rows
            ]
        )


# --------------------------------------------------------------------------- #
#  5. Capabilities
# --------------------------------------------------------------------------- #
class CapabilitiesView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)
        root.addWidget(section_label("Capability indicators"))
        root.addWidget(
            dim_label(
                "Imported Windows APIs grouped by the capability they enable. Presence of an "
                "import is not proof of behaviour - it shows what the sample is built to do."
            )
        )
        self.summary = DataTable(
            ["Capability", "APIs", "Worst weight", "Example APIs"],
            export_name="capabilities",
        )
        root.addWidget(self.summary, 2)
        root.addWidget(section_label("Matched suspicious imports"))
        self.table = DataTable(
            ["API", "DLL", "Capability", "Weight", "Why it matters"],
            export_name="suspicious_imports",
        )
        root.addWidget(self.table, 3)

    def set_result(self, result: AnalysisResult) -> None:
        grouped: dict[str, list] = {}
        for hit in result.capabilities:
            grouped.setdefault(hit["capability"], []).append(hit)
        self.summary.set_data(
            [
                [
                    cap,
                    len(items),
                    max(i["weight"] for i in items),
                    ", ".join(sorted({i["api"] for i in items})[:5]),
                ]
                for cap, items in sorted(grouped.items(), key=lambda kv: -max(i["weight"] for i in kv[1]))
            ]
            or [["(none)", 0, 0, "No suspicious imports matched"]]
        )
        self.table.set_data(result.capability_rows() or [["-", "-", "-", 0, "No matches"]])


# --------------------------------------------------------------------------- #
#  6. Verdict dashboard
# --------------------------------------------------------------------------- #
class VerdictView(QWidget):
    overrideRequested = Signal(str, str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        self.banner = QLabel("\u2014 no analysis yet \u2014")
        self.banner.setAlignment(Qt.AlignCenter)
        self.banner.setStyleSheet(
            f"font-size:18pt;font-weight:700;color:{COLORS['text_dim']};"
            f"background:{COLORS['panel']};border:1px solid {COLORS['border']};"
            "border-radius:10px;padding:14px;"
        )
        root.addWidget(self.banner)
        self.summary = dim_label("")
        root.addWidget(self.summary)

        root.addWidget(section_label("Contributing indicators"))
        self.table = DataTable(["Indicator", "Weight", "Source", "Note"], export_name="verdict_rationale")
        root.addWidget(self.table, 3)

        root.addWidget(section_label("Threat intel lookups (hash only)"))
        self.intel = DataTable(
            ["Source", "Status", "Detections", "Family", "Tags", "First seen", "Reference"],
            export_name="intel",
        )
        root.addWidget(self.intel, 2)

        override = QGroupBox("Analyst verdict override (audit logged)")
        ol = QHBoxLayout(override)
        self.combo = QComboBox()
        self.combo.addItems(["MALICIOUS", "SUSPICIOUS", "LIKELY CLEAN"])
        self.justification = QLineEdit()
        self.justification.setPlaceholderText("Justification (required)")
        btn = QPushButton("Apply override")
        btn.clicked.connect(self._apply)
        ol.addWidget(QLabel("Verdict"))
        ol.addWidget(self.combo)
        ol.addWidget(self.justification, 1)
        ol.addWidget(btn)
        root.addWidget(override)

    def _apply(self) -> None:
        if not self.justification.text().strip():
            QMessageBox.warning(self, APP["name"], "A justification is required to override the verdict.")
            return
        self.overrideRequested.emit(self.combo.currentText(), self.justification.text().strip())

    def set_result(self, result: AnalysisResult) -> None:
        v = result.verdict
        if not v:
            return
        color = color_for(v.verdict)
        suffix = " (overridden)" if v.overridden else ""
        self.banner.setText(f"{v.verdict}{suffix}   \u00b7   risk score {v.score}/100")
        self.banner.setStyleSheet(
            f"font-size:18pt;font-weight:700;color:{color};"
            f"background:{COLORS['panel']};border:1px solid {color};"
            "border-radius:10px;padding:14px;"
        )
        self.summary.setText(
            f"Raw weighted total {v.raw_score}, clamped to {v.score}/100 from {len(v.rationale)} "
            f"indicators. Thresholds: \u2265 60 MALICIOUS \u00b7 25-59 SUSPICIOUS \u00b7 < 25 LIKELY CLEAN. "
            + (f"Override: {v.override_analyst} @ {v.override_at} - {v.override_note}" if v.overridden else "")
        )
        self.table.set_data(v.to_rows() or [["(no indicators)", "", "", ""]])
        self.intel.set_data(
            result.intel_rows()
            or [["(none)", "disabled", "-", "-", "-", "-", ""]]
        )


# --------------------------------------------------------------------------- #
#  7. IOC summary
# --------------------------------------------------------------------------- #
class IOCView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        head = QHBoxLayout()
        head.addWidget(section_label("Indicators of compromise"))
        head.addStretch(1)
        self.check_defang = QCheckBox("Defang values (safe to share)")
        head.addWidget(self.check_defang)
        self.btn_export = QPushButton("Export IOC CSV\u2026")
        self.btn_export.clicked.connect(self._export)
        head.addWidget(self.btn_export)
        root.addLayout(head)
        root.addWidget(
            dim_label(
                "Private, loopback and reserved addresses are filtered out. "
                "Vendor/OS noise (microsoft.com, scheme URIs, system DLLs) is excluded."
            )
        )

        self.chart = BarChart(height=170)
        root.addWidget(self.chart)
        self.table = DataTable(
            ["Type", "Value", "Source", "Confidence", "Context"], export_name="iocs"
        )
        root.addWidget(self.table, 1)
        self._result: AnalysisResult | None = None

    def set_result(self, result: AnalysisResult) -> None:
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
        from app.core.ioc import defang

        rows = []
        for ioc in self._result.iocs:
            value = ioc["value"]
            if self.check_defang.isChecked() and ioc["ioc_type"] in (
                "url", "domain", "ipv4", "tor_address", "email",
            ):
                value = defang(value)
            rows.append(
                [
                    ioc["ioc_type"],
                    value,
                    ioc.get("sources", ioc.get("source", "")),
                    f"{float(ioc.get('confidence', 0)):.2f}",
                    ioc.get("context", ""),
                ]
            )
        self.table.set_data(rows)

    def _export(self) -> None:
        if not self._result:
            QMessageBox.warning(self, APP["name"], "Nothing to export yet.")
            return
        from PySide6.QtWidgets import QFileDialog

        path, _ = QFileDialog.getSaveFileName(
            self, "Export IOC list", "iocs.csv", "CSV (*.csv)"
        )
        if not path:
            return
        Path(path).write_text(self.table.csv_text(), encoding="utf-8", newline="")
        QMessageBox.information(self, APP["name"], f"IOC list written to:\n{path}")


__all__ = [
    "SampleView",
    "HashView",
    "PEView",
    "StringsView",
    "CapabilitiesView",
    "VerdictView",
    "IOCView",
]
