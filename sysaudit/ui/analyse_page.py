"""Page « Analyse » : identification de l'intervention, lancement de la
collecte (en arrière-plan) et suivi de la progression."""
from __future__ import annotations

import logging
import platform
import socket
import threading
import time
import winreg

from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QFormLayout, QGridLayout, QHBoxLayout, QLabel,
                               QLineEdit, QMessageBox, QProgressBar, QPushButton, QVBoxLayout, QWidget)

from ..analyze.engine import analyze
from ..collect import runner, scripts
from . import theme
from .common import muted, page_title, panel

log = logging.getLogger(__name__)


def quick_identity() -> dict:
    """Informations immédiates (sans PowerShell) pour l'en-tête."""
    d = {"name": socket.gethostname(), "os": platform.platform()}
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        name = winreg.QueryValueEx(k, "ProductName")[0]
        build = int(winreg.QueryValueEx(k, "CurrentBuildNumber")[0])
        try:
            disp = winreg.QueryValueEx(k, "DisplayVersion")[0]
        except OSError:
            disp = ""
        if build >= 22000 and "Windows 10" in name:   # ProductName n'a jamais été corrigé pour Windows 11
            name = name.replace("Windows 10", "Windows 11")
        try:
            inst = winreg.QueryValueEx(k, "InstallationType")[0]
        except OSError:
            inst = ""
        d["os"] = f"{name} {disp}".strip()
        d["server"] = inst.lower() == "server"
    except OSError:
        pass
    return d


class Worker(QObject):
    progress = Signal(str, str, str, object)     # nom, libellé, état, Result
    finished = Signal(object, object)            # instantané, analyse
    failed = Signal(str)

    def __init__(self, options: dict):
        super().__init__()
        self.options = options
        self.cancel = threading.Event()

    def run(self):
        try:
            snap = runner.collect(self.options, progress=lambda *a: self.progress.emit(*a), cancel=self.cancel)
            if self.cancel.is_set():
                self.failed.emit("Analyse annulée.")
                return
            self.finished.emit(snap, analyze(snap))
        except Exception as exc:
            log.exception("Analyse")
            self.failed.emit(str(exc))


class AnalysePage(QWidget):
    done = Signal(int)          # id de l'analyse enregistrée

    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.thread: QThread | None = None
        self.worker: Worker | None = None
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 18)
        root.setSpacing(12)
        root.addWidget(page_title("Analyse du poste"))
        root.addWidget(muted("Diagnostic complet en lecture seule : rien n'est installé ni modifié sur le poste. "
                             "Durée : 1 à 3 minutes."))

        # bandeau administrateur
        self.admin_box, al = panel()
        row = QHBoxLayout()
        self.admin_lbl = QLabel()
        self.admin_lbl.setWordWrap(True)
        row.addWidget(self.admin_lbl, 1)
        self.elev = QPushButton("Relancer en administrateur")
        self.elev.setObjectName("Primary")
        self.elev.clicked.connect(self.elevate)
        row.addWidget(self.elev)
        al.addLayout(row)
        root.addWidget(self.admin_box)

        # poste
        ident = quick_identity()
        box, bl = panel()
        t = QLabel(f"<span style='font-size:15pt; font-weight:600'>{ident['name']}</span><br>"
                   f"<span>{ident.get('os', '')}</span>")
        bl.addWidget(t)
        root.addWidget(box)

        # intervention
        box, bl = panel()
        bl.addWidget(QLabel("<b>Intervention</b>"))
        form = QFormLayout()
        self.client = QComboBox()
        self.client.setEditable(True)
        self.client.setInsertPolicy(QComboBox.NoInsert)
        self.client.lineEdit().setPlaceholderText("Nom du client (facultatif)")
        self.site = QLineEdit()
        self.site.setPlaceholderText("Site, service ou emplacement du poste")
        self.notes = QLineEdit()
        self.notes.setPlaceholderText("Motif de l'intervention, remarques…")
        form.addRow("Client", self.client)
        form.addRow("Site", self.site)
        form.addRow("Notes", self.notes)
        bl.addLayout(form)
        opts = QHBoxLayout()
        self.opt_updates = QCheckBox("Rechercher les mises à jour disponibles (Internet, jusqu'à 2 min)")
        self.opt_net = QCheckBox("Tests réseau (passerelle, Internet, DNS, heure)")
        opts.addWidget(self.opt_updates)
        opts.addWidget(self.opt_net)
        opts.addStretch(1)
        bl.addLayout(opts)
        root.addWidget(box)

        # lancement + progression
        row = QHBoxLayout()
        self.go = QPushButton("  Lancer l'analyse")
        self.go.setObjectName("Primary")
        self.go.setMinimumHeight(42)
        self.go.setMinimumWidth(240)
        self.go.clicked.connect(self.start)
        self.stop_btn = QPushButton("Annuler")
        self.stop_btn.clicked.connect(self.stop)
        self.stop_btn.hide()
        row.addWidget(self.go)
        row.addWidget(self.stop_btn)
        self.status = QLabel("")
        self.status.setObjectName("Muted")
        row.addWidget(self.status, 1)
        root.addLayout(row)
        self.bar = QProgressBar()
        self.bar.setRange(0, len(scripts.COLLECTORS))
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(6)
        self.bar.hide()
        root.addWidget(self.bar)
        self.steps_box, sl = panel()
        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        self.rows: dict[str, tuple[QLabel, QLabel, QLabel]] = {}
        for i, (name, (label, _b, _t)) in enumerate(scripts.COLLECTORS.items()):
            dot = QLabel("○")
            lab = QLabel(label)
            st = QLabel("en attente")
            st.setObjectName("Muted")
            grid.addWidget(dot, i, 0)
            grid.addWidget(lab, i, 1)
            grid.addWidget(st, i, 2)
            self.rows[name] = (dot, lab, st)
        grid.setColumnStretch(2, 1)
        sl.addLayout(grid)
        self.steps_box.hide()
        root.addWidget(self.steps_box)
        root.addStretch(1)
        self.t0 = 0.0
        self.timer = QTimer(self, interval=500, timeout=self._tick)
        self.reload()

    # ----------------------------------------------------------------
    def reload(self):
        s = self.ctx.settings
        cur = self.client.currentText()
        self.client.clear()
        self.client.addItems(self.ctx.store.clients())
        self.client.setCurrentText(cur or s.get("last.client", ""))
        if not self.site.text():
            self.site.setText(s.get("last.site", ""))
        self.opt_updates.setChecked(bool(s.get("analysis.online_updates", True)))
        self.opt_net.setChecked(bool(s.get("analysis.network_tests", True)))
        self.apply_theme()

    def apply_theme(self):
        p = theme.palette()
        admin = runner.is_admin()
        if admin:
            self.admin_lbl.setText(f"<b style='color:{p.ok}'>Droits administrateur : oui</b> — tous les contrôles seront réalisés.")
            self.elev.hide()
        else:
            self.admin_lbl.setText(f"<b style='color:{p.warn}'>Lancé sans droits administrateur.</b> Certains contrôles "
                                   "(usure des disques, BitLocker, stratégie de mots de passe, journal de sécurité, "
                                   "intégrité de Windows…) seront indiqués comme « non vérifiés ».")
        self.go.setIcon(theme.glyph_icon(theme.G_PLAY, p.accent_text))

    def elevate(self):
        if self.thread:
            return
        if runner.relaunch_as_admin():
            QApplication.instance().quit()
        else:
            QMessageBox.warning(self, "Administrateur", "L'élévation a été refusée ou a échoué.")

    def start(self):
        if self.thread:
            return
        s = self.ctx.settings
        s.set("last.client", self.client.currentText().strip())
        s.set("last.site", self.site.text().strip())
        s.set("analysis.online_updates", self.opt_updates.isChecked())
        s.set("analysis.network_tests", self.opt_net.isChecked())
        try:
            s.save()
        except OSError:
            pass
        opts = {"days": int(s.get("analysis.days", 30)), "online_updates": self.opt_updates.isChecked(),
                "network_tests": self.opt_net.isChecked()}
        for dot, lab, st in self.rows.values():
            dot.setText("○")
            dot.setStyleSheet("")
            st.setText("en attente")
        self.done_n = 0
        self.bar.setValue(0)
        self.bar.show()
        self.steps_box.show()
        self.go.setEnabled(False)
        self.stop_btn.show()
        self.t0 = time.monotonic()
        self.timer.start()
        self.thread = QThread(self)
        self.worker = Worker(opts)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._progress)
        self.worker.finished.connect(self._finished)
        self.worker.failed.connect(self._failed)
        self.thread.start()

    def stop(self):
        if self.worker:
            self.worker.cancel.set()
            self.status.setText("Annulation…")

    def _tick(self):
        self.status.setText(f"Analyse en cours… {time.monotonic() - self.t0:.0f} s")

    def _progress(self, name, label, state, res):
        p = theme.palette()
        dot, lab, st = self.rows[name]
        if state == "start":
            dot.setText("●")
            dot.setStyleSheet(f"color:{p.accent}")
            st.setText("en cours…")
        else:
            self.done_n += 1
            self.bar.setValue(self.done_n)
            errs = len((res.data or {}).get("_errors") or [])
            if res.ok and res.error:
                dot.setText("!")
                dot.setStyleSheet(f"color:{p.warn}")
                st.setText(f"incomplet en {res.seconds:.0f} s : {res.error[:140]} (données partielles conservées)")
            elif res.ok:
                dot.setText("✓")
                dot.setStyleSheet(f"color:{p.ok}")
                st.setText(f"terminé en {res.seconds:.0f} s" + (f" · {errs} contrôle(s) non disponible(s)" if errs else ""))
            else:
                dot.setText("✖")
                dot.setStyleSheet(f"color:{p.crit}")
                st.setText(f"échec : {res.error[:140]}")

    def _cleanup(self):
        self.timer.stop()
        if self.thread:
            self.thread.quit()
            self.thread.wait(5000)
        self.thread = self.worker = None
        self.go.setEnabled(True)
        self.stop_btn.hide()

    def _finished(self, snap, analysis):
        dur = time.monotonic() - self.t0
        self._cleanup()
        s = self.ctx.settings
        aid = self.ctx.store.save(client=self.client.currentText().strip(), site=self.site.text().strip(),
                                  notes=self.notes.text().strip(), auditor=s.get("report.auditor", ""),
                                  analysis=analysis, snapshot=snap)
        self.status.setText(f"Analyse terminée en {dur:.0f} s — note {analysis.scores.get('global')} / 100")
        self.notes.clear()
        self.reload()
        self.ctx.history_changed.emit()
        self.done.emit(aid)

    def _failed(self, msg):
        self._cleanup()
        self.status.setText(msg)
        if msg != "Analyse annulée.":
            QMessageBox.warning(self, "Analyse", f"L'analyse a échoué :\n{msg}")
