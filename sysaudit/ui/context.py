"""État partagé de l'interface : paramètres, historique, analyse affichée."""
from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from ..analyze.engine import Analysis


class AppContext(QObject):
    current_changed = Signal()      # une analyse est ouverte (résultats / inventaire)
    history_changed = Signal()

    def __init__(self, settings, store):
        super().__init__()
        self.settings = settings
        self.store = store
        self.rec: dict | None = None
        self.analysis: Analysis | None = None
        self.prev: Analysis | None = None

    def open(self, aid: int):
        rec = self.store.get(aid)
        if not rec:
            return
        rec["snapshot_options"] = (rec.get("snapshot") or {}).get("options", {})
        self.rec = rec
        self.analysis = Analysis.from_dict(rec["analysis"])
        p = self.store.previous(rec.get("machine_key") or "", rec.get("ts") or 0)
        self.prev = Analysis.from_dict(p["analysis"]) if p else None
        self.current_changed.emit()

    def section(self, name: str) -> dict:
        if not self.rec:
            return {}
        return ((self.rec.get("snapshot") or {}).get("sections", {}).get(name) or {}).get("data") or {}
