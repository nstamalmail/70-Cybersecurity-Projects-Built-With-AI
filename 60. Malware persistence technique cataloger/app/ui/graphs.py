"""Painter-drawn visualisations specific to this workbench.

``BehaviorGraph`` renders the Markov transition matrix as a directed node-link
diagram (nodes on a circle, edge width and opacity scaled by transition count),
and ``HeatmapWidget`` renders the process x category call matrix.  Both are drawn
with ``QPainter`` so the application needs no plotting dependency.
"""
from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QPen
from PySide6.QtWidgets import QSizePolicy, QWidget

from app.core.categorize import color_for as category_color
from app.ui.theme import COLORS, color_for


class BehaviorGraph(QWidget):
    """Directed API transition graph.

    ``set_graph(nodes, edges)`` where ``nodes`` is a list of
    ``{"name", "count", "category"}`` and ``edges`` a list of
    ``{"source", "target", "count"}``.
    """

    nodeClicked = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(360)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._nodes: list[dict] = []
        self._edges: list[dict] = []
        self._positions: dict[str, QPointF] = {}
        self._hover_node = ""
        self._hover_edge = -1
        self.setMouseTracking(True)

    # ------------------------------------------------------------------ input
    def set_graph(self, nodes: list[dict], edges: list[dict], max_nodes: int = 22) -> None:
        self._nodes = list(nodes)[:max_nodes]
        names = {node["name"] for node in self._nodes}
        self._edges = [
            edge for edge in edges if edge.get("source") in names and edge.get("target") in names
        ][: max(40, max_nodes * 6)]
        self._layout()
        self.update()

    def _layout(self) -> None:
        self._positions = {}
        count = len(self._nodes)
        if not count:
            return
        center = QPointF(self.width() / 2, self.height() / 2)
        radius = max(70.0, min(self.width(), self.height()) / 2 - 54)
        for index, node in enumerate(self._nodes):
            angle = (2 * math.pi * index / count) - math.pi / 2
            self._positions[node["name"]] = QPointF(
                center.x() + radius * math.cos(angle), center.y() + radius * math.sin(angle)
            )

    def resizeEvent(self, event) -> None:  # noqa: N802
        self._layout()

    # ----------------------------------------------------------------- paint
    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.fillRect(self.rect(), QColor(COLORS["panel"]))

        if not self._nodes:
            painter.setPen(QColor(COLORS["text_faint"]))
            painter.drawText(self.rect(), Qt.AlignCenter, "no transitions to graph yet")
            return

        max_count = max((float(edge.get("count", 1)) for edge in self._edges), default=1.0)
        for index, edge in enumerate(self._edges):
            start = self._positions.get(edge["source"])
            end = self._positions.get(edge["target"])
            if start is None or end is None:
                continue
            weight = float(edge.get("count", 1)) / max_count
            color = QColor(COLORS["accent"])
            color.setAlpha(int(70 + 150 * weight))
            if index == self._hover_edge:
                color = QColor("#ffffff")
            width = 1.0 + 3.4 * weight
            pen = QPen(color, width)
            pen.setCapStyle(Qt.RoundCap)
            painter.setPen(pen)
            # shorten the segment so the arrow lands on the node circle, not its centre
            painter.drawLine(self._trim(start, end))

            # arrow head
            angle = math.atan2(end.y() - start.y(), end.x() - start.x())
            tip = QPointF(end.x() - 17 * math.cos(angle), end.y() - 17 * math.sin(angle))
            left = QPointF(
                tip.x() - 9 * math.cos(angle - 0.42), tip.y() - 9 * math.sin(angle - 0.42)
            )
            right = QPointF(
                tip.x() - 9 * math.cos(angle + 0.42), tip.y() - 9 * math.sin(angle + 0.42)
            )
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.NoPen)
            painter.drawPolygon(tip, left, right)

        painter.setFont(QFont("Segoe UI", 8))
        for node in self._nodes:
            position = self._positions.get(node["name"])
            if position is None:
                continue
            base = QColor(category_color(node.get("category", "other")))
            fill = QColor(base)
            fill.setAlpha(220 if node["name"] != self._hover_node else 255)
            radius = 15 + min(9, math.log10(max(1, int(node.get("count", 1)))) * 4)
            painter.setPen(QPen(QColor(COLORS["border_strong"]), 2 if node["name"] == self._hover_node else 1))
            painter.setBrush(QBrush(fill))
            painter.drawEllipse(position, radius, radius)

            painter.setPen(QColor(COLORS["text"]))
            label = str(node["name"])
            if len(label) > 17:
                label = label[:16] + "…"
            painter.drawText(
                QRectF(position.x() - 58, position.y() - radius - 15, 116, 14),
                Qt.AlignHCenter | Qt.AlignVCenter,
                label,
            )

    def _trim(self, start: QPointF, end: QPointF) -> tuple[QPointF, QPointF]:
        dx, dy = end.x() - start.x(), end.y() - start.y()
        length = math.hypot(dx, dy) or 1.0
        pad = 18.0
        return (
            QPointF(start.x() + dx / length * pad, start.y() + dy / length * pad),
            QPointF(end.x() - dx / length * pad, end.y() - dy / length * pad),
        )

    # --------------------------------------------------------------- events
    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        position = event.position()
        hover_node = ""
        for name, point in self._positions.items():
            if math.hypot(point.x() - position.x(), point.y() - position.y()) <= 22:
                hover_node = name
                break
        hover_edge = -1
        if not hover_node:
            for index, edge in enumerate(self._edges):
                start = self._positions.get(edge["source"])
                end = self._positions.get(edge["target"])
                if start is None or end is None:
                    continue
                if self._distance_to_segment(position, start, end) <= 4:
                    hover_edge = index
                    break
        if hover_node != self._hover_node or hover_edge != self._hover_edge:
            self._hover_node = hover_node
            self._hover_edge = hover_edge
            self.update()
        if hover_node:
            node = next((item for item in self._nodes if item["name"] == hover_node), {})
            self.setToolTip(f"{hover_node}\ncalls: {node.get('count', 0)}")
        elif hover_edge >= 0:
            edge = self._edges[hover_edge]
            self.setToolTip(f"{edge['source']} -> {edge['target']}\ntransitions: {edge.get('count', 0)}")
        else:
            self.setToolTip("")

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if self._hover_node:
            self.nodeClicked.emit(self._hover_node)

    @staticmethod
    def _distance_to_segment(point: QPointF, start: QPointF, end: QPointF) -> float:
        dx, dy = end.x() - start.x(), end.y() - start.y()
        length_sq = dx * dx + dy * dy
        if length_sq <= 1e-9:
            return math.hypot(point.x() - start.x(), point.y() - start.y())
        t = max(0.0, min(1.0, ((point.x() - start.x()) * dx + (point.y() - start.y()) * dy) / length_sq))
        return math.hypot(point.x() - (start.x() + t * dx), point.y() - (start.y() + t * dy))


class HeatmapWidget(QWidget):
    """Process (rows) x API category (columns) call-count heatmap."""

    cellClicked = Signal(int, int, int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(280)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._rows: list[str] = []
        self._columns: list[str] = []
        self._grid: list[list[int]] = []
        self._rects: list[tuple[QRectF, int, int, int]] = []
        self.setMouseTracking(True)

    def set_matrix(self, rows: list[str], columns: list[str], grid: list[list[int]]) -> None:
        self._rows = list(rows)
        self._columns = list(columns)
        self._grid = [list(row) for row in grid]
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, False)
        painter.fillRect(self.rect(), QColor(COLORS["panel"]))
        self._rects = []

        if not self._rows or not self._columns:
            painter.setPen(QColor(COLORS["text_faint"]))
            painter.drawText(self.rect(), Qt.AlignCenter, "no behaviour loaded")
            return

        label_w = 168.0
        header_h = 46.0
        usable_w = max(40.0, self.width() - label_w - 12)
        usable_h = max(40.0, self.height() - header_h - 10)
        cell_w = usable_w / len(self._columns)
        cell_h = min(30.0, usable_h / len(self._rows))
        maximum = max((max(row, default=0) for row in self._grid), default=1) or 1

        painter.setFont(QFont("Segoe UI", 7))
        for column_index, name in enumerate(self._columns):
            x = label_w + column_index * cell_w
            painter.save()
            painter.translate(x + cell_w / 2, header_h - 8)
            painter.rotate(-40)
            painter.setPen(QColor(COLORS["text_dim"]))
            painter.drawText(0, 0, name)
            painter.restore()

        for row_index, label in enumerate(self._rows):
            y = header_h + row_index * cell_h
            painter.setPen(QColor(COLORS["text_dim"]))
            painter.drawText(
                QRectF(4, y, label_w - 8, cell_h), Qt.AlignRight | Qt.AlignVCenter, label[-26:]
            )
            for column_index, category in enumerate(self._columns):
                value = self._grid[row_index][column_index] if row_index < len(self._grid) else 0
                x = label_w + column_index * cell_w
                rect = QRectF(x + 1, y + 1, cell_w - 2, cell_h - 2)
                ratio = (value / maximum) ** 0.45 if maximum else 0.0
                base = QColor(color_for(category))
                if value <= 0:
                    base = QColor(COLORS["panel_alt"])
                    base.setAlpha(120)
                else:
                    base.setAlpha(int(40 + ratio * 210))
                painter.setPen(Qt.NoPen)
                painter.setBrush(QBrush(base))
                painter.drawRoundedRect(rect, 3, 3)
                if value and cell_w > 42:
                    painter.setPen(QColor(COLORS["text"] if ratio > 0.5 else COLORS["text_dim"]))
                    painter.drawText(rect, Qt.AlignCenter, str(value))
                self._rects.append((rect, row_index, column_index, value))

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        for rect, row_index, column_index, value in self._rects:
            if rect.contains(event.position()):
                self.setToolTip(
                    f"{self._rows[row_index]}\n{self._columns[column_index]}: {value} calls"
                )
                return
        self.setToolTip("")

    def mousePressEvent(self, event) -> None:  # noqa: N802
        for rect, row_index, column_index, value in self._rects:
            if rect.contains(event.position()):
                self.cellClicked.emit(row_index, column_index, value)
                return
