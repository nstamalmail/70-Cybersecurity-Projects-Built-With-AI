"""Reusable Qt widgets shared by every workbench view.

Charting is done directly with ``QPainter`` so the suite needs no extra plotting
dependency, which keeps the portable executables small and dependency-light.
"""
from __future__ import annotations

import csv
import datetime as _dt
from pathlib import Path

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QFontMetrics, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.ui.theme import COLORS, color_for


# --------------------------------------------------------------------------- #
#  Small building blocks
# --------------------------------------------------------------------------- #
def hsep() -> QFrame:
    line = QFrame()
    line.setProperty("role", "hline")
    line.setFrameShape(QFrame.HLine)
    line.setFixedHeight(1)
    return line


def title_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setProperty("role", "title")
    return lbl


def dim_label(text: str = "") -> QLabel:
    lbl = QLabel(text)
    lbl.setProperty("role", "dim")
    lbl.setWordWrap(True)
    return lbl


def section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setProperty("role", "section")
    return lbl


def chip(text: str, color: str | None = None) -> QLabel:
    lbl = QLabel(text)
    lbl.setProperty("role", "chip")
    if color:
        lbl.setStyleSheet(
            f"background:{_shade(color)};border:1px solid {color};border-radius:11px;"
            f"padding:3px 10px;color:{color};font-weight:600;"
        )
    return lbl


def badge(text: str, color_key: str | None = None) -> QLabel:
    color = color_for(color_key or text)
    lbl = QLabel(str(text).upper())
    lbl.setStyleSheet(
        f"background:{_shade(color)};color:{color};border:1px solid {color};"
        "border-radius:6px;padding:3px 8px;font-weight:700;font-size:9pt;letter-spacing:.4px;"
    )
    return lbl


def _shade(hex_color: str, alpha: int = 40) -> str:
    """Return a translucent variant of a hex colour, as an rgba() string."""
    c = QColor(hex_color)
    return f"rgba({c.red()},{c.green()},{c.blue()},{alpha})"


def mono_label(text: str = "") -> QLabel:
    lbl = QLabel(text)
    lbl.setProperty("role", "mono")
    lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return lbl


class StatStrip(QWidget):
    """Horizontal strip of headline numbers (label above, value below)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(10)

    def set_stats(self, stats: list[tuple[str, object, str | None]]) -> None:
        while self._layout.count():
            item = self._layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        for label, value, color in stats:
            self._layout.addWidget(self._card(str(label), value, color))
        self._layout.addStretch(1)

    def _card(self, label: str, value, color: str | None) -> QWidget:
        card = QFrame()
        card.setProperty("role", "card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(1)
        val = QLabel(str(value))
        val.setStyleSheet(
            f"font-size:15pt;font-weight:700;color:{color or COLORS['text']};"
        )
        cap = QLabel(label.upper())
        cap.setStyleSheet(
            f"color:{COLORS['text_faint']};font-size:8pt;letter-spacing:.6px;"
        )
        lay.addWidget(val)
        lay.addWidget(cap)
        return card


class LogConsole(QPlainTextEdit):
    """Read-only colourised log tail."""

    LEVEL_COLORS = {
        "debug": "#6b7687",
        "info": "#c9d1d9",
        "warn": "#f5a524",
        "error": "#e5484d",
        "success": "#30a46c",
    }

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setMaximumBlockCount(6000)
        self.setProperty("role", "mono")
        self.setStyleSheet(
            f"background:{COLORS['bg']};border:1px solid {COLORS['border']};"
            "border-radius:8px;font-family:'Cascadia Mono',Consolas,monospace;font-size:9pt;"
        )
        self._auto_scroll = True

    def append_record(self, rec) -> None:
        color = self.LEVEL_COLORS.get(getattr(rec, "level", "info"), COLORS["text"])
        msg = (
            str(getattr(rec, "message", rec))
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        ts = getattr(rec, "ts", _dt.datetime.now())
        level = str(getattr(rec, "level", "info")).upper()
        self.appendHtml(
            f"<span style='color:#6b7687'>[{ts:%H:%M:%S}]</span> "
            f"<span style='color:{color}'>{level:<7}&nbsp;</span> "
            f"<span style='color:{COLORS['text_dim']}'>{msg}</span>"
        )
        if self._auto_scroll:
            self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())

    def append_plain(self, text: str) -> None:
        self.appendPlainText(text)


class DataTable(QWidget):
    """Table + filter box + copy / CSV export.  Rows are kept verbatim."""

    rowSelected = Signal(int)
    rowActivated = Signal(int)

    def __init__(
        self,
        columns: list[str] | None = None,
        parent: QWidget | None = None,
        export_name: str = "table",
        show_toolbar: bool = True,
    ) -> None:
        super().__init__(parent)
        self._columns: list[str] = list(columns or [])
        self._rows: list[list] = []
        self._export_name = export_name

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(6)

        self._filter = QLineEdit()
        self._filter.setPlaceholderText("Filter rows\u2026 (matches any column)")
        self._filter.textChanged.connect(self._apply_filter)

        if show_toolbar:
            bar = QHBoxLayout()
            bar.setSpacing(6)
            bar.addWidget(self._filter, 1)
            self._count = QLabel("")
            self._count.setProperty("role", "dim")
            bar.addWidget(self._count)
            btn_copy = QPushButton("Copy")
            btn_copy.setToolTip("Copy visible rows as tab-separated text")
            btn_copy.clicked.connect(self.copy_to_clipboard)
            btn_save = QPushButton("Save CSV")
            btn_save.clicked.connect(self.save_csv)
            bar.addWidget(btn_copy)
            bar.addWidget(btn_save)
            root.addLayout(bar)
        else:
            self._count = QLabel("")
            self._count.setProperty("role", "dim")

        self.table = QTableWidget(0, len(self._columns))
        self.table.setHorizontalHeaderLabels(self._columns)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setDefaultSectionSize(23)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._emit_selection)
        self.table.cellDoubleClicked.connect(lambda r, c: self.rowActivated.emit(self.data_index()))
        root.addWidget(self.table, 1)

    # ------------------------------------------------------------------ data
    def set_data(self, rows: list[list], columns: list[str] | None = None) -> None:
        if columns:
            self._columns = list(columns)
            self.table.setColumnCount(len(self._columns))
            self.table.setHorizontalHeaderLabels(self._columns)
        self._rows = [list(r) for r in rows]
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self._rows))
        for r, row in enumerate(self._rows):
            for c in range(len(self._columns)):
                value = row[c] if c < len(row) else ""
                item = QTableWidgetItem("" if value is None else str(value))
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    item.setData(Qt.DisplayRole, value)
                if c == 0:
                    # Remember the original data index so selection signals stay
                    # correct after the user sorts a column.
                    item.setData(Qt.UserRole, r)
                self.table.setItem(r, c, item)
        self.table.setSortingEnabled(True)
        self.table.resizeColumnsToContents()
        self._apply_filter(self._filter.text())
        self._update_count()

    def rows(self) -> list[list]:
        return list(self._rows)

    def data_index(self) -> int:
        """Data index of the current selection, valid even after sorting."""
        view_row = self.table.currentRow()
        if view_row < 0:
            return -1
        item = self.table.item(view_row, 0)
        stored = item.data(Qt.UserRole) if item else None
        if isinstance(stored, int) and 0 <= stored < len(self._rows):
            return stored
        return view_row

    def selected_row(self) -> list | None:
        idx = self.data_index()
        if 0 <= idx < len(self._rows):
            return self._rows[idx]
        return None

    def selected_row_index(self) -> int:
        return self.data_index()

    def clear(self) -> None:
        self.set_data([])

    # --------------------------------------------------------------- filters
    def _apply_filter(self, text: str) -> None:
        needle = (text or "").strip().lower()
        for r in range(self.table.rowCount()):
            if not needle:
                self.table.setRowHidden(r, False)
                continue
            match = False
            for c in range(self.table.columnCount()):
                item = self.table.item(r, c)
                if item and needle in item.text().lower():
                    match = True
                    break
            self.table.setRowHidden(r, not match)
        self._update_count()

    def _update_count(self) -> None:
        if not hasattr(self, "_count"):
            return
        visible = sum(
            1 for r in range(self.table.rowCount()) if not self.table.isRowHidden(r)
        )
        total = self.table.rowCount()
        self._count.setText(
            f"{visible} shown / {total} total" if visible != total else f"{total} rows"
        )

    def _emit_selection(self) -> None:
        self.rowSelected.emit(self.data_index())

    # ------------------------------------------------------------- clipboard
    def visible_rows(self) -> list[list]:
        out: list[list] = []
        for r in range(self.table.rowCount()):
            if self.table.isRowHidden(r):
                continue
            row = []
            for c in range(self.table.columnCount()):
                item = self.table.item(r, c)
                row.append(item.text() if item else "")
            out.append(row)
        return out

    def copy_to_clipboard(self) -> None:
        from PySide6.QtWidgets import QApplication

        lines = ["\t".join(str(c) for c in self._columns)]
        lines += ["\t".join(row) for row in self.visible_rows()]
        QApplication.clipboard().setText("\n".join(lines))

    def csv_text(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\r\n")
        w.writerow(self._columns)
        w.writerows(self.visible_rows())
        return buf.getvalue()

    def save_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save table as CSV", f"{self._export_name}.csv", "CSV (*.csv)"
        )
        if not path:
            return
        Path(path).write_text(self.csv_text(), encoding="utf-8", newline="")
        self._count.setText(f"saved \u2192 {Path(path).name}")


class PathDropEdit(QLineEdit):
    """Line edit that accepts a dropped file/folder and exposes a browse button."""

    pathChanged = Signal(str)

    def __init__(self, parent: QWidget | None = None, placeholder: str = "Drop a file here or browse\u2026") -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setPlaceholderText(placeholder)
        self.textChanged.connect(self.pathChanged.emit)

    def dragEnterEvent(self, event) -> None:  # noqa: N802 (Qt API)
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event) -> None:  # noqa: N802
        urls = event.mimeData().urls()
        if urls:
            self.setText(urls[0].toLocalFile())
            event.acceptProposedAction()
        else:
            super().dropEvent(event)

    def path(self) -> Path | None:
        text = self.text().strip().strip('"')
        return Path(text) if text else None


class FilePicker(QWidget):
    """Composite widget: drop-edit + Browse button."""

    changed = Signal(str)

    def __init__(
        self,
        caption: str = "Select file",
        file_filter: str = "All files (*)",
        parent: QWidget | None = None,
        placeholder: str = "Drop a file here or browse\u2026",
    ) -> None:
        super().__init__(parent)
        self._caption = caption
        self._filter = file_filter
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        self.edit = PathDropEdit(placeholder=placeholder)
        self.edit.pathChanged.connect(self.changed.emit)
        browse = QPushButton("Browse\u2026")
        browse.clicked.connect(self._browse)
        lay.addWidget(self.edit, 1)
        lay.addWidget(browse)

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, self._caption, "", self._filter)
        if path:
            self.edit.setText(path)

    def browse(self) -> None:
        """Open the file dialog (used by the File ▸ Open artefact menu entry)."""
        self._browse()

    def path(self) -> Path | None:
        return self.edit.path()

    def set_path(self, value: str | Path) -> None:
        self.edit.setText(str(value))

    def text(self) -> str:
        return self.edit.text()


# --------------------------------------------------------------------------- #
#  Charts (hand drawn with QPainter)
# --------------------------------------------------------------------------- #
class BarChart(QWidget):
    """Vertical bar chart with optional threshold colour bands and hover labels.

    ``bands`` is a list of ``(upper_bound, color)`` pairs; the first band whose
    bound is greater than or equal to the value wins.  Anything above the last
    bound uses the last colour.
    """

    barClicked = Signal(int)

    def __init__(self, parent: QWidget | None = None, height: int = 190) -> None:
        super().__init__(parent)
        self.setMinimumHeight(height)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._labels: list[str] = []
        self._values: list[float] = []
        self._unit = ""
        self._bands: list[tuple[float, str]] = [(1e9, COLORS["info"])]
        self._ref_line: float | None = None
        self._ref_label = ""
        self._hover = -1
        self.setMouseTracking(True)

    def set_data(
        self,
        labels: list[str],
        values: list[float],
        unit: str = "",
        bands: list[tuple[float, str]] | None = None,
        ref_line: float | None = None,
        ref_label: str = "",
    ) -> None:
        self._labels = list(labels)
        self._values = [float(v or 0.0) for v in values]
        self._unit = unit
        if bands:
            self._bands = sorted(bands, key=lambda b: b[0])
        self._ref_line = ref_line
        self._ref_label = ref_label
        self.update()

    def _color_for(self, value: float) -> str:
        for bound, color in self._bands:
            if value <= bound:
                return color
        return self._bands[-1][1]

    def _plot_rect(self) -> QRectF:
        return QRectF(64, 12, max(10.0, self.width() - 78), max(10.0, self.height() - 46))

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.fillRect(self.rect(), QColor(COLORS["panel"]))

        plot = self._plot_rect()
        grid_pen = QPen(QColor(COLORS["border"]))
        grid_pen.setWidth(1)
        painter.setPen(grid_pen)

        vmax = max(self._values) if self._values else 1.0
        vmax = max(vmax, self._ref_line or 0.0, 1e-9)
        vmax *= 1.12

        # horizontal grid + y labels
        font = QFont("Segoe UI", 7)
        painter.setFont(font)
        for i in range(5):
            y = plot.bottom() - plot.height() * i / 4
            painter.setPen(grid_pen)
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            painter.setPen(QColor(COLORS["text_faint"]))
            painter.drawText(
                QRectF(0, y - 9, 58, 18),
                Qt.AlignRight | Qt.AlignVCenter,
                f"{vmax * i / 4:.2f}",
            )

        if not self._values:
            painter.setPen(QColor(COLORS["text_faint"]))
            painter.drawText(plot, Qt.AlignCenter, "no data")
            return

        n = len(self._values)
        slot = plot.width() / max(1, n)
        bar_w = max(2.0, min(46.0, slot * 0.72))
        self._bar_rects: list[QRectF] = []

        for i, value in enumerate(self._values):
            h = 0.0 if vmax <= 0 else (value / vmax) * plot.height()
            x = plot.left() + slot * i + (slot - bar_w) / 2
            rect = QRectF(x, plot.bottom() - h, bar_w, max(h, 1.0))
            self._bar_rects.append(rect)
            base = QColor(self._color_for(value))
            if i == self._hover:
                base = base.lighter(135)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(base))
            painter.drawRoundedRect(rect, 2.5, 2.5)

        # threshold reference line
        if self._ref_line is not None and vmax > 0:
            y = plot.bottom() - (self._ref_line / vmax) * plot.height()
            pen = QPen(QColor(COLORS["warn"]))
            pen.setStyle(Qt.DashLine)
            painter.setPen(pen)
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            if self._ref_label:
                painter.setPen(QColor(COLORS["warn"]))
                painter.drawText(QRectF(plot.left() + 4, y - 15, 210, 14), Qt.AlignLeft, self._ref_label)

        # x labels (skip when crowded)
        painter.setPen(QColor(COLORS["text_dim"]))
        step = max(1, int(n / max(1, int(plot.width() / 62))))
        for i, label in enumerate(self._labels):
            if i % step:
                continue
            x = plot.left() + slot * i
            painter.save()
            painter.translate(x + slot / 2 - 30, plot.bottom() + 3)
            painter.drawText(
                QRectF(0, 0, 60, 30),
                Qt.AlignHCenter | Qt.AlignTop,
                str(label)[:16],
            )
            painter.restore()

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        rects = getattr(self, "_bar_rects", [])
        hover = -1
        for i, rect in enumerate(rects):
            if rect.adjusted(-3, -3, 3, 3).contains(event.position()):
                hover = i
                break
        if hover != self._hover:
            self._hover = hover
            self.update()
        if 0 <= hover < len(self._values):
            self.setToolTip(
                f"{self._labels[hover]}: {self._values[hover]:.3f}{self._unit}"
            )
        else:
            self.setToolTip("")

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if self._hover >= 0:
            self.barClicked.emit(self._hover)


class TimelineStrip(QWidget):
    """Horizontal time axis with colour coded event markers.

    Events are dicts: ``{ts: float, label: str, category: str, detail: str}``.
    """

    eventClicked = Signal(int)

    def __init__(self, parent: QWidget | None = None, height: int = 150) -> None:
        super().__init__(parent)
        self.setMinimumHeight(height)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._events: list[dict] = []
        self._hover = -1
        self._lanes: list[str] | None = None
        self.setMouseTracking(True)

    def set_events(self, events: list[dict], lanes: list[str] | None = None) -> None:
        self._events = sorted(events, key=lambda e: float(e.get("ts", 0.0)))
        self._lanes = lanes
        self.update()

    def _time_range(self) -> tuple[float, float]:
        if not self._events:
            return 0.0, 1.0
        ts = [float(e.get("ts", 0.0)) for e in self._events]
        lo, hi = min(ts), max(ts)
        return (lo, hi if hi > lo else lo + 1.0)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.fillRect(self.rect(), QColor(COLORS["panel"]))

        plot = QRectF(52, 26, max(10.0, self.width() - 66), max(10.0, self.height() - 54))
        lo, hi = self._time_range()
        span = hi - lo

        lanes = self._lanes or sorted({str(e.get("category", "other")) for e in self._events})
        if not lanes:
            lanes = ["events"]
        lane_h = plot.height() / len(lanes)

        painter.setFont(QFont("Segoe UI", 8))
        for i, lane in enumerate(lanes):
            y = plot.top() + lane_h * i
            painter.setPen(QPen(QColor(COLORS["border"])))
            painter.drawLine(QPointF(plot.left(), y + lane_h / 2), QPointF(plot.right(), y + lane_h / 2))
            painter.setPen(QColor(COLORS["text_faint"]))
            painter.drawText(
                QRectF(2, y, 46, lane_h), Qt.AlignRight | Qt.AlignVCenter, str(lane)[:9]
            )

        # time gridlines
        painter.setPen(QPen(QColor(COLORS["border"])))
        for i in range(6):
            x = plot.left() + plot.width() * i / 5
            painter.drawLine(QPointF(x, plot.top() - 6), QPointF(x, plot.bottom()))
            painter.setPen(QColor(COLORS["text_faint"]))
            painter.drawText(
                QRectF(x - 30, 4, 60, 16),
                Qt.AlignCenter,
                _fmt_seconds(lo + span * i / 5),
            )
            painter.setPen(QPen(QColor(COLORS["border"])))

        self._marker_rects: list[QRectF] = []
        for idx, ev in enumerate(self._events):
            cat = str(ev.get("category", "other"))
            lane_idx = lanes.index(cat) if cat in lanes else 0
            x = plot.left() + ((float(ev.get("ts", 0.0)) - lo) / span) * plot.width()
            y = plot.top() + lane_h * lane_idx + lane_h / 2
            color = QColor(color_for(cat))
            if idx == self._hover:
                color = color.lighter(150)
            h = max(6.0, min(lane_h - 6, lane_h * 0.8))
            rect = QRectF(x - 3, y - h / 2, 6, h)
            self._marker_rects.append(rect)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(color))
            painter.drawRoundedRect(rect, 2, 2)

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        hover = -1
        for i, rect in enumerate(getattr(self, "_marker_rects", [])):
            if rect.adjusted(-4, -4, 4, 4).contains(event.position()):
                hover = i
                break
        if hover != self._hover:
            self._hover = hover
            self.update()
        if 0 <= hover:
            ev = self._events[hover]
            self.setToolTip(
                f"[{_fmt_seconds(float(ev.get('ts', 0.0)))}] {ev.get('label','')}\n{ev.get('detail','')}"
            )
        else:
            self.setToolTip("")

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if self._hover >= 0:
            self.eventClicked.emit(self._hover)


def _fmt_seconds(value: float) -> str:
    value = float(value)
    if value >= 86400:
        return f"{value / 86400:.1f}d"
    if value >= 3600:
        return f"{value / 3600:.1f}h"
    if value >= 60:
        return f"{value / 60:.1f}m"
    if value >= 1:
        return f"{value:.1f}s"
    return f"{value * 1000:.0f}ms"


class AttackMatrix(QWidget):
    """ATT&CK Navigator style matrix: tactic columns of technique cells.

    ``columns`` is a list of ``(tactic_name, [cells])`` where each cell is a dict
    ``{"id": str, "name": str, "value": float, "max": float, "note": str,
    "level": str}``.  Cell fill intensity is ``value/max``; ``level`` overrides
    the colour when supplied.
    """

    cellClicked = Signal(dict)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(260)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._columns: list[tuple[str, list[dict]]] = []
        self._rects: list[tuple[QRectF, dict]] = []
        self.setMouseTracking(True)

    def set_columns(self, columns: list[tuple[str, list[dict]]]) -> None:
        self._columns = columns
        deepest = max((len(cells) for _, cells in columns), default=1)
        self.setMinimumHeight(max(260, 26 + 34 * deepest + 16))
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.fillRect(self.rect(), QColor(COLORS["bg"]))
        self._rects = []

        if not self._columns:
            painter.setPen(QColor(COLORS["text_faint"]))
            painter.drawText(self.rect(), Qt.AlignCenter, "no techniques mapped")
            return

        n = len(self._columns)
        pad = 6
        col_w = max(96.0, (self.width() - pad * (n + 1)) / n)
        header_h = 26
        painter.setFont(QFont("Segoe UI", 8, QFont.DemiBold))

        for ci, (tactic, cells) in enumerate(self._columns):
            x = pad + ci * (col_w + pad)
            painter.setPen(QColor(COLORS["text_dim"]))
            painter.drawText(
                QRectF(x, 4, col_w, header_h - 6),
                Qt.AlignLeft | Qt.AlignVCenter,
                tactic.replace("-", " ")[: max(6, int(col_w / 6))].upper(),
            )
            y = header_h
            for cell in cells:
                value = float(cell.get("value", 0.0) or 0.0)
                maximum = float(cell.get("max", 1.0) or 1.0)
                ratio = 0.0 if maximum <= 0 else max(0.0, min(1.0, value / maximum))
                base = QColor(color_for(str(cell.get("level", ""))))
                fill = QColor(base)
                fill.setAlpha(int(38 + ratio * 205))
                rect = QRectF(x, y, col_w, 30)
                painter.setPen(QPen(QColor(COLORS["border"]), 1))
                painter.setBrush(QBrush(fill))
                painter.drawRoundedRect(rect, 5, 5)
                painter.setPen(QColor("#e6e9ef" if ratio > 0.45 else COLORS["text"]))
                painter.setFont(QFont("Segoe UI", 8, QFont.DemiBold))
                painter.drawText(
                    rect.adjusted(6, 2, -6, -14), Qt.AlignLeft | Qt.AlignVCenter, str(cell.get("id", ""))
                )
                painter.setFont(QFont("Segoe UI", 7))
                painter.setPen(QColor(COLORS["text_dim"]))
                painter.drawText(
                    rect.adjusted(6, 14, -6, -2),
                    Qt.AlignLeft | Qt.AlignVCenter,
                    str(cell.get("name", ""))[: max(10, int(col_w / 5))],
                )
                self._rects.append((rect, cell))
                y += 34

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        for rect, cell in self._rects:
            if rect.contains(event.position()):
                self.setToolTip(
                    f"{cell.get('id','')} - {cell.get('name','')}\n"
                    f"value: {cell.get('value', 0)}\n{cell.get('note','')}"
                )
                return
        self.setToolTip("")

    def mousePressEvent(self, event) -> None:  # noqa: N802
        for rect, cell in self._rects:
            if rect.contains(event.position()):
                self.cellClicked.emit(cell)
                return


class KVGrid(QWidget):
    """Simple two-column key/value display."""

    def __init__(self, data: dict | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._table = QTableWidget(0, 2)
        self._table.setHorizontalHeaderLabels(["Field", "Value"])
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setAlternatingRowColors(True)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self._table)
        self.set_data(data or {})

    def set_data(self, data: dict) -> None:
        self._table.setRowCount(len(data))
        for r, (k, v) in enumerate(data.items()):
            key_item = QTableWidgetItem(str(k))
            key_item.setForeground(QColor(COLORS["text_dim"]))
            self._table.setItem(r, 0, key_item)
            self._table.setItem(r, 1, QTableWidgetItem("" if v is None else str(v)))
        fm = QFontMetrics(self._table.font())
        self._table.setMaximumHeight(min(420, 34 + 24 * max(1, len(data)) + 8))
        _ = fm


class ClickableText(QPlainTextEdit):
    """Read-only monospace text pane used for evidence / raw payloads."""

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setProperty("role", "mono")
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.setStyleSheet(
            f"background:{COLORS['bg']};border:1px solid {COLORS['border']};border-radius:8px;"
            "font-family:'Cascadia Mono',Consolas,monospace;font-size:9pt;"
        )
        self.setPlainText(text)

    def set_text(self, text: str) -> None:
        self.setPlainText(text)
