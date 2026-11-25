"""Page « Historique » : toutes les analyses, par client et par poste."""
from __future__ import annotations

import time

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QInputDialog, QLineEdit, QMessageBox, QPushButton,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from .common import NumItem, SortItem, make_table, muted, page_title, score_color


class HistoryPage(QWidget):
    opened = Signal(int)

    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 18, 24, 14)
        root.addWidget(page_title("Historique des analyses"))
        root.addWidget(muted("Chaque analyse est conservée avec ses données brutes : un même poste analysé plusieurs fois "
                             "permet de suivre son évolution (problèmes résolus, nouveaux problèmes)."))
        bar = QHBoxLayout()
        self.client = QComboBox()
        self.client.currentIndexChanged.connect(self.refresh)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Rechercher un poste, un site, une note…")
        self.search.textChanged.connect(self.refresh)
        bar.addWidget(self.client)
        bar.addWidget(self.search, 1)
        self.b_open = QPushButton("Ouvrir")
        self.b_open.setObjectName("Primary")
        self.b_open.clicked.connect(self.open_sel)
        self.b_edit = QPushButton("Modifier client / site…")
        self.b_edit.clicked.connect(self.edit_sel)
        self.b_del = QPushButton("Supprimer")
        self.b_del.setObjectName("Danger")
        self.b_del.clicked.connect(self.delete_sel)
        for b in (self.b_edit, self.b_del, self.b_open):
            bar.addWidget(b)
        root.addLayout(bar)
        self.table = make_table(["Date", "Client", "Site", "Poste", "Rôle", "Système", "Note", "Critiques", "Majeurs", "Mineurs", "Notes"])
        self.table.doubleClicked.connect(lambda _i: self.open_sel())
        root.addWidget(self.table, 1)
        ctx.history_changed.connect(self.reload)
        self.reload()

    def reload(self):
        cur = self.client.currentData()
        self.client.blockSignals(True)
        self.client.clear()
        self.client.addItem("Tous les clients", None)
        for c in self.ctx.store.clients():
            self.client.addItem(c, c)
        i = self.client.findData(cur)
        self.client.setCurrentIndex(max(0, i))
        self.client.blockSignals(False)
        self.refresh()

    def refresh(self):
        rows = self.ctx.store.list(self.client.currentData(), self.search.text().strip())
        t = self.table
        t.setSortingEnabled(False)
        t.setRowCount(len(rows))
        for r, d in enumerate(rows):
            c = d.get("counts") or {}
            date = SortItem(time.strftime("%d/%m/%Y %H:%M", time.localtime(d["ts"])), d["ts"])
            date.setData(Qt.UserRole, d["id"])
            sc = NumItem(str(d.get("score")), d.get("score") or 0)
            sc.setForeground(QColor(score_color(d.get("score") or 0)))
            items = [date, QTableWidgetItem(d.get("client") or ""), QTableWidgetItem(d.get("site") or ""),
                     QTableWidgetItem(d.get("machine") or ""), QTableWidgetItem(d.get("role") or ""), QTableWidgetItem(d.get("os") or ""),
                     sc, NumItem(str(c.get("4", 0)), c.get("4", 0)), NumItem(str(c.get("3", 0)), c.get("3", 0)),
                     NumItem(str(c.get("2", 0)), c.get("2", 0)), QTableWidgetItem(d.get("notes") or "")]
            for col, it in enumerate(items):
                t.setItem(r, col, it)
        t.setSortingEnabled(True)
        t.resizeColumnsToContents()

    def _sel(self) -> int | None:
        rows = self.table.selectionModel().selectedRows()
        return self.table.item(rows[0].row(), 0).data(Qt.UserRole) if rows else None

    def open_sel(self):
        aid = self._sel()
        if aid:
            self.ctx.open(aid)
            self.opened.emit(aid)

    def edit_sel(self):
        aid = self._sel()
        if not aid:
            return
        rec = self.ctx.store.get(aid)
        client, ok = QInputDialog.getText(self, "Client", "Client :", text=rec.get("client") or "")
        if not ok:
            return
        site, ok = QInputDialog.getText(self, "Site", "Site :", text=rec.get("site") or "")
        if not ok:
            return
        notes, ok = QInputDialog.getText(self, "Notes", "Notes :", text=rec.get("notes") or "")
        if not ok:
            return
        self.ctx.store.update_meta(aid, client=client.strip(), site=site.strip(), notes=notes.strip())
        self.reload()
        if self.ctx.rec and self.ctx.rec.get("id") == aid:
            self.ctx.open(aid)

    def delete_sel(self):
        aid = self._sel()
        if not aid:
            return
        if QMessageBox.question(self, "Supprimer", "Supprimer définitivement cette analyse ?") != QMessageBox.Yes:
            return
        self.ctx.store.delete(aid)
        if self.ctx.rec and self.ctx.rec.get("id") == aid:
            self.ctx.rec = self.ctx.analysis = self.ctx.prev = None
            self.ctx.current_changed.emit()
        self.reload()
