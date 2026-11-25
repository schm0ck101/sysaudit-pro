"""Page « Résultats » : notes, liste des constats filtrable et détail."""
from __future__ import annotations

import html
import re
import time
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QSplitter, QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget)

from ..analyze.engine import analyze
from ..analyze.model import CRIT, DOMAINS, INFO, MAJOR, MINOR, NOT_CHECKED, OK, SEVERITY
from .. import followup as fu_mod
from .. import report
from . import theme
from .common import ScoreRing, make_table, muted, page_title, panel, score_color, sev_color

FILTERS = [("Problèmes à traiter", lambda f: f.severity >= MINOR), ("Critiques et majeurs", lambda f: f.severity >= MAJOR),
           ("Tous les constats", lambda f: True), ("Points conformes", lambda f: f.severity == OK),
           ("Non vérifiés", lambda f: f.severity == NOT_CHECKED), ("Informations", lambda f: f.severity == INFO)]


def safe_name(s: str) -> str:
    return re.sub(r'[\\/:*?"<>|]+', "_", s or "").strip() or "poste"


class ResultsPage(QWidget):
    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 18, 24, 14)
        root.setSpacing(10)
        top = QHBoxLayout()
        tv = QVBoxLayout()
        self.title = page_title("Résultats")
        self.sub = muted("")
        tv.addWidget(self.title)
        tv.addWidget(self.sub)
        top.addLayout(tv, 1)
        self.btn_pdf = QPushButton("  Rapport PDF")
        self.btn_pdf.setObjectName("Primary")
        self.btn_pdf.clicked.connect(self.export_pdf)
        self.btn_json = QPushButton("Exporter les données")
        self.btn_json.setToolTip("Données brutes et résultats au format JSON (archivage, support)")
        self.btn_json.clicked.connect(self.export_json)
        self.btn_re = QPushButton("Ré-analyser")
        self.btn_re.setToolTip("Applique les règles de cette version de l'application aux données déjà collectées")
        self.btn_re.clicked.connect(self.reanalyze)
        for b in (self.btn_re, self.btn_json, self.btn_pdf):
            top.addWidget(b)
        root.addLayout(top)

        # notes
        box, bl = panel((16, 10, 16, 10))
        row = QHBoxLayout()
        self.rings = {"global": ScoreRing("Note globale", 128)}
        row.addWidget(self.rings["global"])
        row.addSpacing(10)
        short = {"hw": "Matériel", "sys": "Système", "sec": "Sécurité", "svc": "Rôles, sauv."}
        for d, label in DOMAINS.items():
            self.rings[d] = ScoreRing(short.get(d, label), 96)
            self.rings[d].setToolTip(label)
            row.addWidget(self.rings[d], 0, Qt.AlignBottom)
        row.addSpacing(16)
        self.summary = QLabel("")
        self.summary.setWordWrap(True)
        self.summary.setTextFormat(Qt.RichText)
        row.addWidget(self.summary, 1)
        bl.addLayout(row)
        root.addWidget(box)

        # filtres
        f = QHBoxLayout()
        self.f_kind = QComboBox()
        for label, _fn in FILTERS:
            self.f_kind.addItem(label)
        self.f_domain = QComboBox()
        self.f_domain.addItem("Tous les domaines", None)
        for d, label in DOMAINS.items():
            self.f_domain.addItem(label, d)
        self.f_risk = QCheckBox("Risques à venir seulement")
        self.f_open = QCheckBox("Masquer les points traités")
        self.f_open.setToolTip("Cache les lignes « Fait » et « Non retenu »")
        self.f_text = QLineEdit()
        self.f_text.setPlaceholderText("Rechercher…")
        for w in (self.f_kind, self.f_domain, self.f_risk, self.f_open):
            f.addWidget(w)
        f.addWidget(self.f_text, 1)
        self.count_lbl = muted("")
        f.addWidget(self.count_lbl)
        root.addLayout(f)
        self.f_kind.currentIndexChanged.connect(self.fill)
        self.f_domain.currentIndexChanged.connect(self.fill)
        self.f_risk.toggled.connect(self.fill)
        self.f_open.toggled.connect(self.fill)
        self.f_text.textChanged.connect(self.fill)

        split = QSplitter(Qt.Horizontal)
        # plan d'action : case « fait », gravité, domaine, constat, suivi (menu), commentaire (modifiable)
        self.table = make_table(["Fait", "Gravité", "Domaine", "Constat", "Suivi", "Commentaire"], stretch=3)
        self.table.setEditTriggers(QAbstractItemView.DoubleClicked | QAbstractItemView.EditKeyPressed | QAbstractItemView.AnyKeyPressed)
        self.table.setToolTip("Cochez « Fait », choisissez une échéance dans « Suivi » ; double-cliquez sur « Commentaire » pour écrire.")
        self.table.itemSelectionChanged.connect(self.show_detail)
        self.table.itemChanged.connect(self._item_changed)
        self._filling = False
        self._style_checkboxes()
        split.addWidget(self.table)
        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(True)
        split.addWidget(self.detail)
        split.setSizes([940, 420])
        root.addWidget(split, 1)
        self.empty = muted("Aucune analyse ouverte. Lancez une analyse depuis la page « Analyse » ou ouvrez-en une depuis l'historique.")
        root.addWidget(self.empty)
        ctx.current_changed.connect(self.load)
        self.visible_findings = []
        self.load()

    def _style_checkboxes(self):
        """Case « Fait » vide bien visible, y compris en thème sombre."""
        self.table.setStyleSheet(f"QTableView::indicator:unchecked {{ border: 1px solid {theme.palette().muted}; "
                                 f"border-radius: 3px; background: transparent; width: 13px; height: 13px; }}")

    def apply_theme(self):
        self.btn_pdf.setIcon(theme.glyph_icon(theme.G_PDF, theme.palette().accent_text))
        self._style_checkboxes()
        self.load()

    # ---------------------------------------------------------------
    def load(self):
        a, rec = self.ctx.analysis, self.ctx.rec
        has = a is not None
        for w in (self.btn_pdf, self.btn_json, self.btn_re, self.table, self.detail):
            w.setEnabled(has)
        self.empty.setVisible(not has)
        if not has:
            self.title.setText("Résultats")
            self.sub.setText("")
            for r in self.rings.values():
                r.set(None)
            self.summary.setText("")
            self.table.setRowCount(0)
            self.detail.clear()
            return
        m = a.machine
        when = time.strftime("%d/%m/%Y %H:%M", time.localtime(rec.get("ts") or 0))
        self.title.setText(f"{m.get('name')} — {m.get('role')}")
        ctx_txt = " › ".join(x for x in (rec.get("client"), rec.get("site")) if x)
        self.sub.setText(f"{m.get('os')} · analysé le {when}" + (f" · {ctx_txt}" if ctx_txt else "")
                         + ("" if m.get("admin") else " · sans droits administrateur"))
        for k, r in self.rings.items():
            r.set(a.scores.get(k))
        c = a.counts()
        p = theme.palette()
        parts = [f"<span style='font-size:13pt; font-weight:600; color:{score_color(a.scores.get('global', 0))}'>"
                 f"{report.verdict(a.scores.get('global', 0))}</span><br>"]
        for sev in (CRIT, MAJOR, MINOR):
            parts.append(f"<span style='color:{sev_color(sev)}'>■</span> {c[sev]} {SEVERITY[sev].lower()}{'s' if c[sev] > 1 else ''} &nbsp; ")
        parts.append(f"<br><span style='color:{p.bad}'>⚠</span> {len(a.risks)} risque(s) à venir · "
                     f"<span style='color:{p.ok}'>✓</span> {c[OK]} point(s) conforme(s)"
                     + (f" · {c[NOT_CHECKED]} non vérifié(s)" if c[NOT_CHECKED] else ""))
        if self.ctx.prev:
            new, solved = report.diff(a, self.ctx.prev)
            parts.append(f"<br><span style='color:{p.muted}'>Depuis l'analyse précédente : {self.ctx.prev.scores.get('global')} → "
                         f"{a.scores.get('global')}, {len(solved)} résolu(s), {len(new)} nouveau(x)</span>")
        probs = list(a.problems)
        fus = rec.get("followup") or {}
        if probs:
            done = sum(1 for f in probs if fu_mod.is_closed(fus.get(f.id)))
            planned = sum(1 for f in probs if (fus.get(f.id) or {}).get("status") == "planned")
            parts.append(f"<br><b>Suivi :</b> {done} / {len(probs)} traité(s)" + (f" · {planned} prévu(s)" if planned else ""))
        if a.rule_errors:
            parts.append(f"<br><span style='color:{p.crit}'>{len(a.rule_errors)} règle(s) n'ont pas pu s'exécuter (voir le journal).</span>")
        self.summary.setText("".join(parts))
        self.fill()

    def fill(self):
        a = self.ctx.analysis
        if not a:
            return
        fus = (self.ctx.rec or {}).get("followup") or {}
        fn = FILTERS[self.f_kind.currentIndex()][1]
        dom = self.f_domain.currentData()
        txt = self.f_text.text().strip().lower()
        fs = [f for f in a.findings if fn(f) and (dom is None or f.domain == dom) and (not self.f_risk.isChecked() or f.predictive)
              and (not self.f_open.isChecked() or not fu_mod.is_closed(fus.get(f.id)))
              and (not txt or txt in f"{f.title} {f.detail} {f.fix} {(fus.get(f.id) or {}).get('note', '')}".lower())]
        fs.sort(key=lambda f: (-f.severity, f.domain, f.title))
        self.visible_findings = fs
        t = self.table
        self._filling = True
        t.setSortingEnabled(False)
        t.clearContents()
        t.setRowCount(len(fs))
        ro = Qt.ItemIsSelectable | Qt.ItemIsEnabled
        for r, f in enumerate(fs):
            fu = fus.get(f.id)
            actionable = f.severity >= INFO
            chk = QTableWidgetItem("")
            if actionable:
                chk.setFlags(ro | Qt.ItemIsUserCheckable)
                chk.setCheckState(Qt.Checked if (fu or {}).get("status") == "done" else Qt.Unchecked)
            else:
                chk.setFlags(ro)
            sev = QTableWidgetItem(SEVERITY[f.severity])
            sev.setForeground(QColor(sev_color(f.severity)))
            title = QTableWidgetItem(("⚠ " if f.predictive else "") + f.title)
            if f.predictive:
                title.setToolTip("Risque à venir")
            note = QTableWidgetItem((fu or {}).get("note", ""))
            items = [chk, sev, QTableWidgetItem(report.DOMAIN_SHORT.get(f.domain, DOMAINS[f.domain])), title, QTableWidgetItem(""), note]
            for c, it in enumerate(items):
                if c not in (0, 5):
                    it.setFlags(ro)
            if not actionable:
                note.setFlags(ro)
            if fu_mod.is_closed(fu):
                grey = QColor(theme.palette().muted)
                for it in items[1:]:
                    it.setForeground(grey)
                ft = QFont(title.font())
                ft.setStrikeOut(fu.get("status") == "done")
                title.setFont(ft)
            for c, it in enumerate(items):
                t.setItem(r, c, it)
            if actionable:
                t.setCellWidget(r, 4, self._status_combo(f, fu))
        for c in (0, 1, 2):
            t.resizeColumnToContents(c)
        t.setColumnWidth(4, 140)
        if not getattr(self, "_note_w", False):      # largeur initiale ; ensuite celle choisie par l'utilisateur
            t.setColumnWidth(5, 170)
            self._note_w = True
        self._filling = False
        self.count_lbl.setText(f"{len(fs)} constat(s)")
        if fs:
            t.selectRow(0)
        else:
            self.detail.clear()

    def _status_combo(self, f, fu) -> QComboBox:
        cb = QComboBox()
        cb.setFocusPolicy(Qt.StrongFocus)
        cb.wheelEvent = lambda e: e.ignore()        # pas de changement involontaire à la molette
        for code, lbl in fu_mod.CHOICES:
            cb.addItem(lbl, code)
        cur = fu_mod.choice_of(fu)
        if cur == "":                                # date fixée un autre jour : « Prévu le 28/11 », « En retard (24/11) »
            cb.insertItem(0, fu_mod.label(fu), "")
            cb.setCurrentIndex(0)
        else:
            cb.setCurrentIndex(max(0, cb.findData(cur)))
        col = fu_mod.color(fu)
        if col:
            cb.setStyleSheet(f"QComboBox {{ color: {col}; font-weight: 600; }}")
        cb.activated.connect(lambda _i, f=f, cb=cb: self._set_status(f, cb.currentData()))
        return cb

    def _set_status(self, f, choice):
        rec = self.ctx.rec
        if not rec or choice in (None, ""):
            return
        note = ((rec.get("followup") or {}).get(f.id) or {}).get("note", "")
        rec["followup"] = self.ctx.store.set_followup(rec["id"], f.id, fu_mod.make(choice, note=note))
        self._refresh_keep_selection(f)

    def _item_changed(self, it):
        if self._filling or not self.ctx.rec:
            return
        r, c = it.row(), it.column()
        if r >= len(self.visible_findings) or c not in (0, 5):
            return
        f = self.visible_findings[r]
        rec = self.ctx.rec
        cur = dict((rec.get("followup") or {}).get(f.id) or fu_mod.make("todo"))
        if c == 0:
            if (it.checkState() == Qt.Checked) == (cur.get("status") == "done"):
                return
            entry = fu_mod.make("done" if it.checkState() == Qt.Checked else "todo", note=cur.get("note", ""))
        else:
            if it.text().strip() == cur.get("note", ""):
                return
            cur["note"] = it.text().strip()
            entry = cur
        rec["followup"] = self.ctx.store.set_followup(rec["id"], f.id, entry)
        self._refresh_keep_selection(f)

    def _refresh_keep_selection(self, f):
        """Recharge le tableau et le résumé sans perdre la ligne en cours (hors du signal du tableau)."""
        from PySide6.QtCore import QTimer

        def later():
            sb = self.table.verticalScrollBar().value()
            self.load()
            for r, x in enumerate(self.visible_findings):
                if x.id == f.id:
                    self.table.selectRow(r)
                    break
            self.table.verticalScrollBar().setValue(sb)
        QTimer.singleShot(0, later)

    def show_detail(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        if rows[0].row() >= len(self.visible_findings):
            return
        f = self.visible_findings[rows[0].row()]
        p = theme.palette()
        e = html.escape
        col = sev_color(f.severity)
        h = [f"<p style='color:{col}; font-weight:600'>{SEVERITY[f.severity].upper()} · {DOMAINS[f.domain]}"
             + (" · RISQUE À VENIR" if f.predictive else "") + "</p>",
             f"<h3 style='margin-top:0'>{e(f.title)}</h3>"]
        for label, txt in (("Constat", f.detail), ("Pourquoi c'est important", f.impact), ("Que faire", f.fix)):
            if txt:
                h.append(f"<p><b>{label}</b><br>{e(txt)}</p>")
        if f.evidence:
            h.append(f"<p><b>Éléments relevés</b></p><p style='color:{p.muted}; font-family:Consolas; font-size:9pt'>"
                     + "<br><br>".join(e(x) for x in f.evidence if x) + "</p>")
        self.detail.setHtml("".join(h))

    # ---------------------------------------------------------------
    def _default_name(self, ext: str) -> str:
        rec, a = self.ctx.rec, self.ctx.analysis
        d = time.strftime("%Y-%m-%d", time.localtime(rec.get("ts") or 0))
        base = f"Diagnostic {safe_name(rec.get('client') or '')} {safe_name(a.machine.get('name'))} {d}".replace("  ", " ")
        return str(Path.home() / "Documents" / f"{base}.{ext}")

    def export_pdf(self):
        if not self.ctx.analysis:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Rapport PDF", self._default_name("pdf"), "PDF (*.pdf)")
        if not path:
            return
        try:
            report.export_pdf(path, self.ctx.rec, self.ctx.analysis, self.ctx.settings, self.ctx.prev)
        except Exception as exc:
            QMessageBox.warning(self, "Rapport", f"Impossible de créer le rapport :\n{exc}")
            return
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def export_json(self):
        if not self.ctx.rec:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exporter les données", self._default_name("json"), "JSON (*.json)")
        if path:
            report.export_json(path, self.ctx.rec)

    def reanalyze(self):
        rec = self.ctx.rec
        if not rec or not rec.get("snapshot"):
            return
        a = analyze(rec["snapshot"])
        self.ctx.store.update_analysis(rec["id"], a)
        self.ctx.history_changed.emit()
        self.ctx.open(rec["id"])
