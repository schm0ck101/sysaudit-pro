"""Page « Paramètres » : identité de l'intervenant (rapport), analyse, thème."""
from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QCheckBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QLineEdit, QPushButton,
                               QSpinBox, QVBoxLayout, QWidget)

from ..config import APP_NAME, APP_VERSION, AUTHOR, AUTHOR_URL, data_dir, is_portable
from .common import muted, page_title


class SettingsPage(QWidget):
    applied = Signal()

    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        s = ctx.settings
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 18)
        root.addWidget(page_title("Paramètres"))
        g = QGroupBox("Rapport client")
        f = QFormLayout(g)
        self.w = {}
        for key, label in (("report.company", "Société"), ("report.auditor", "Intervenant"), ("report.phone", "Téléphone"),
                           ("report.email", "E-mail"), ("report.website", "Site web")):
            self.w[key] = QLineEdit(s.get(key, "") or "")
            f.addRow(label, self.w[key])
        row = QWidget()
        rl = QHBoxLayout(row)
        rl.setContentsMargins(0, 0, 0, 0)
        self.w["report.logo"] = QLineEdit(s.get("report.logo", "") or "")
        self.w["report.logo"].setPlaceholderText(f"(logo {AUTHOR} par défaut)")
        pick = QPushButton("Choisir…")
        pick.clicked.connect(self._pick)
        rl.addWidget(self.w["report.logo"], 1)
        rl.addWidget(pick)
        f.addRow("Logo", row)
        self.w["report.include_ok"] = QCheckBox("Lister les points contrôlés conformes")
        self.w["report.include_ok"].setChecked(bool(s.get("report.include_ok", True)))
        self.w["report.include_inventory"] = QCheckBox("Inclure la fiche du poste")
        self.w["report.include_inventory"].setChecked(bool(s.get("report.include_inventory", True)))
        f.addRow("", self.w["report.include_ok"])
        f.addRow("", self.w["report.include_inventory"])
        root.addWidget(g)
        g = QGroupBox("Analyse")
        f = QFormLayout(g)
        self.w["analysis.days"] = QSpinBox()
        self.w["analysis.days"].setRange(7, 90)
        self.w["analysis.days"].setSuffix(" jours")
        self.w["analysis.days"].setValue(int(s.get("analysis.days", 30)))
        f.addRow("Période des journaux analysés", self.w["analysis.days"])
        root.addWidget(g)
        bar = QHBoxLayout()
        bar.addStretch(1)
        save = QPushButton("Enregistrer")
        save.setObjectName("Primary")
        save.clicked.connect(self.save)
        bar.addWidget(save)
        root.addLayout(bar)
        root.addStretch(1)
        root.addWidget(muted(f"{APP_NAME} {APP_VERSION} — créé par {AUTHOR} ({AUTHOR_URL}).<br>"
                             f"Données : {data_dir()}" + (" (version portable : à côté de l'exécutable)" if is_portable() else "")))

    def _pick(self):
        p, _ = QFileDialog.getOpenFileName(self, "Logo", "", "Images (*.png *.jpg *.jpeg *.bmp *.svg)")
        if p:
            self.w["report.logo"].setText(p)

    def save(self):
        s = self.ctx.settings
        for key, w in self.w.items():
            if isinstance(w, QCheckBox):
                s.set(key, w.isChecked())
            elif isinstance(w, QSpinBox):
                s.set(key, w.value())
            else:
                s.set(key, w.text().strip())
        s.save()
        self.applied.emit()
