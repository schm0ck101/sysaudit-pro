"""Widgets partagés : jauges de note, cartes, cellules triables, tableaux."""
from __future__ import annotations

import math

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (QAbstractItemView, QFrame, QHeaderView, QLabel, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from ..analyze.model import CRIT, INFO, MAJOR, MINOR, NOT_CHECKED, OK
from . import theme


def sev_color(sev: int) -> str:
    p = theme.palette()
    return {CRIT: p.crit, MAJOR: p.bad, MINOR: p.warn, INFO: p.info, OK: p.ok, NOT_CHECKED: p.muted}.get(sev, p.muted)


def score_color(sc: float) -> str:
    p = theme.palette()
    return p.ok if sc >= 80 else p.bad if sc >= 55 else p.crit


class ScoreRing(QWidget):
    """Jauge circulaire de note /100."""

    def __init__(self, title: str, size: int = 120, parent=None):
        super().__init__(parent)
        self.title, self.value, self._s = title, None, size
        self.setFixedSize(size, size + 22)

    def set(self, v):
        self.value = v
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        pal = theme.palette()
        s = self._s
        w = max(7, s // 13)
        r = QRectF(w, w, s - 2 * w, s - 2 * w)
        p.setPen(QPen(QColor(pal.border), w, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(r, 0, 360 * 16)
        if self.value is not None:
            col = QColor(score_color(self.value))
            p.setPen(QPen(col, w, Qt.SolidLine, Qt.RoundCap))
            p.drawArc(r, 90 * 16, -int(360 * 16 * max(0, min(100, self.value)) / 100))
            p.setPen(col)
            f = QFont("Segoe UI", max(10, s // 5))
            f.setBold(True)
            p.setFont(f)
            p.drawText(QRectF(0, 0, s, s), Qt.AlignCenter, str(int(self.value)))
        p.setPen(QColor(pal.muted))
        p.setFont(QFont("Segoe UI", 9))
        p.drawText(QRectF(0, s + 2, s, 20), Qt.AlignHCenter | Qt.AlignTop, self.title)
        p.end()


class StatCard(QFrame):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setObjectName("StatCard")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(0)
        t = QLabel(title.upper())
        t.setObjectName("StatTitle")
        self.v = QLabel("—")
        self.v.setObjectName("StatValue")
        self.s = QLabel("")
        self.s.setObjectName("StatSub")
        lay.addWidget(t)
        lay.addWidget(self.v)
        lay.addWidget(self.s)

    def set(self, value: str, sub: str = "", color: str | None = None):
        self.v.setText(value)
        self.s.setText(sub)
        self.v.setStyleSheet(f"color:{color};" if color else "")


class NumItem(QTableWidgetItem):
    def __init__(self, text: str, value):
        super().__init__(text)
        self.value = -1e18 if value is None or (isinstance(value, float) and math.isnan(value)) else value
        self.setTextAlignment(int(Qt.AlignRight | Qt.AlignVCenter))

    def __lt__(self, other):
        return self.value < other.value if isinstance(other, NumItem) else super().__lt__(other)


class SortItem(QTableWidgetItem):
    """Texte affiché, tri sur une clé distincte."""

    def __init__(self, text: str, key):
        super().__init__(text)
        self.key = key

    def __lt__(self, other):
        return self.key < other.key if isinstance(other, SortItem) else super().__lt__(other)


def page_title(text: str) -> QLabel:
    lab = QLabel(text)
    lab.setObjectName("PageTitle")
    return lab


def muted(text: str) -> QLabel:
    lab = QLabel(text)
    lab.setObjectName("Muted")
    lab.setWordWrap(True)
    return lab


def panel(margins=(14, 12, 14, 12)) -> tuple[QFrame, QVBoxLayout]:
    f = QFrame()
    f.setObjectName("Panel")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(*margins)
    return f, lay


def make_table(headers: list[str], stretch: int | None = None) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().hide()
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setAlternatingRowColors(True)
    t.setWordWrap(False)
    hh = t.horizontalHeader()
    hh.setSectionResizeMode(QHeaderView.Interactive)
    hh.setStretchLastSection(stretch is None)
    if stretch is not None:
        hh.setSectionResizeMode(stretch, QHeaderView.Stretch)
    return t


def fill_table(t: QTableWidget, rows: list[list], numeric: set[int] = frozenset(), sortable: bool = True):
    t.setSortingEnabled(False)
    t.horizontalHeader().setSortIndicatorShown(sortable)
    t.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, v in enumerate(row):
            if c in numeric and isinstance(v, tuple):
                it = NumItem(*v)
            else:
                it = QTableWidgetItem("" if v is None else str(v))
            t.setItem(r, c, it)
    t.setSortingEnabled(sortable)
    t.resizeColumnsToContents()
    for c in range(t.columnCount()):
        if t.columnWidth(c) > 420:
            t.setColumnWidth(c, 420)
