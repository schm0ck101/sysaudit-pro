"""Page « Inventaire » : les données collectées, consultables par onglet."""
from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QLineEdit, QTabWidget, QVBoxLayout, QWidget

from ..analyze.model import as_list, fr_date, human_bytes, parse_dt, sjoin
from .common import fill_table, make_table, muted, page_title


def _d(s):
    return fr_date(parse_dt(s)) if s else ""


class InventoryPage(QWidget):
    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 18, 24, 14)
        top = QHBoxLayout()
        top.addWidget(page_title("Inventaire du poste"), 1)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filtrer le tableau affiché…")
        self.search.setFixedWidth(320)
        self.search.textChanged.connect(self._filter)
        top.addWidget(self.search)
        root.addLayout(top)
        self.sub = muted("")
        root.addWidget(self.sub)
        self.tabs = QTabWidget()
        self.tables = {}
        spec = {
            "Poste": ["Élément", "Valeur"],
            "Disques": ["Disque", "Type", "Bus", "Taille", "État", "Usure", "Température", "Heures", "Erreurs non corrigées"],
            "Volumes": ["Volume", "Nom", "Système de fichiers", "Taille", "Libre", "% libre"],
            "Logiciels": ["Nom", "Version", "Éditeur", "Installé le", "Portée"],
            "Services": ["Nom affiché", "Nom", "Démarrage", "État", "Code de sortie", "Compte"],
            "Démarrage": ["Nom", "Commande", "Emplacement", "Utilisateur"],
            "Tâches planifiées": ["Tâche", "Dossier", "État", "Dernière exécution", "Résultat", "Programme"],
            "Réseau": ["Interface", "Description", "État", "Vitesse", "Adresses IPv4", "Passerelle", "DNS"],
            "Processus": ["Processus", "PID", "Mémoire privée", "Handles", "Threads", "CPU %", "Démarré", "Éditeur"],
            "Mises à jour": ["KB", "Description", "Installée le"],
            "Pilotes": ["Périphérique", "Éditeur", "Version", "Date", "Classe"],
        }
        for name, headers in spec.items():
            t = make_table(headers)
            self.tables[name] = t
            self.tabs.addTab(t, name)
        root.addWidget(self.tabs, 1)
        self.tabs.currentChanged.connect(lambda _i: self._filter(self.search.text()))
        ctx.current_changed.connect(self.load)
        self.load()

    def load(self):
        rec = self.ctx.rec
        for t in self.tables.values():
            t.setRowCount(0)
        if not rec:
            self.sub.setText("Aucune analyse ouverte.")
            return
        S = self.ctx.section
        m = self.ctx.analysis.machine
        import time
        self.sub.setText(f"{m.get('name')} — {m.get('os')} — données collectées le "
                         f"{time.strftime('%d/%m/%Y à %H:%M', time.localtime(rec.get('ts') or 0))}")
        sysd, disks, ev, sw, net, upd = S("system"), S("disks"), S("events"), S("software"), S("network"), S("updates")
        os_, cs, bios = sysd.get("os") or {}, sysd.get("computer") or {}, sysd.get("bios") or {}
        cpu = (as_list(sysd.get("cpu")) or [{}])[0]
        mods = as_list(sysd.get("ram_modules"))
        slots = sysd.get("ram_slots") or {}
        rows = [["Nom", cs.get("name")], ["Domaine / groupe de travail", cs.get("domain")], ["Rôle", m.get("role")],
                ["Système", f"{os_.get('caption')} {os_.get('display_version') or ''}"], ["Build", f"{os_.get('version')}.{os_.get('ubr')}"],
                ["Architecture", os_.get("arch")], ["Installé le", _d(os_.get("install_date"))], ["Dernier démarrage", _d(os_.get("last_boot"))],
                ["Fabricant", cs.get("manufacturer")], ["Modèle", cs.get("model")], ["N° de série", bios.get("serial")],
                ["BIOS", f"{bios.get('manufacturer')} {bios.get('version')} ({_d(bios.get('release'))})"],
                ["Carte mère", f"{(sysd.get('board') or {}).get('manufacturer', '')} {(sysd.get('board') or {}).get('product', '')}"],
                ["Processeur", f"{cpu.get('name')} — {cpu.get('cores')} cœurs / {cpu.get('logical')} threads"],
                ["Mémoire", f"{human_bytes(cs.get('total_bytes'))} — {len(mods)} barrette(s)"
                            + (f" sur {slots.get('slots')} emplacement(s)" if slots.get("slots") else "")],
                *[[f"  Barrette {i + 1}", f"{human_bytes(b.get('capacity'))} {str(b.get('speed')) + ' MHz' if b.get('speed') else ''} {b.get('manufacturer') or ''} {b.get('part') or ''} ({b.get('slot') or ''})"]
                  for i, b in enumerate(mods)],
                *[["Carte graphique", f"{g.get('name')} (pilote {g.get('driver')}, {_d(g.get('driver_date'))})"] for g in as_list(sysd.get("gpu"))],
                ["Mode d'alimentation", (sysd.get("power_plan") or {}).get("name")],
                ["Fuseau horaire", sysd.get("timezone")], ["Utilisateur", m.get("user")],
                ["Logiciels installés", len(as_list(sw.get("software")))], ["Applications du Store", sw.get("appx_count")]]
        b = sysd.get("battery")
        if b:
            rows.append(["Batterie", f"{b.get('name')} — {b.get('charge')} % ; capacité {b.get('full_mwh')} / {b.get('design_mwh')} mWh"])
        rows = [[k, " ".join(str(v).replace("None", "").split()) if v is not None else ""] for k, v in rows]
        fill_table(self.tables["Poste"], rows, sortable=False)
        drows = []
        for d in as_list(disks.get("physical")):
            rc = d.get("reliability") or {}
            drows.append([d.get("name"), d.get("media"), d.get("bus"), (human_bytes(d.get("size")), d.get("size") or 0), d.get("health"),
                          "" if rc.get("wear") is None else f"{rc['wear']} %", "" if not rc.get("temperature") else f"{rc['temperature']} °C",
                          rc.get("power_on_hours") or "", (rc.get("read_uncorrected") or 0) + (rc.get("write_uncorrected") or 0) if rc else ""])
        fill_table(self.tables["Disques"], drows, numeric={3})
        vrows = []
        for v in as_list(disks.get("volumes")):
            size, free = v.get("size") or 0, v.get("free") or 0
            vrows.append([v.get("letter") or v.get("name"), v.get("label") or "", v.get("fs"), (human_bytes(size), size), (human_bytes(free), free),
                          (f"{free / size * 100:.0f} %" if size else "", free / size if size else 0)])
        fill_table(self.tables["Volumes"], vrows, numeric={3, 4, 5})
        fill_table(self.tables["Logiciels"], [[s.get("name"), s.get("version"), s.get("publisher"), s.get("installed"),
                                               "utilisateur" if s.get("scope") == "user" else "machine"] for s in as_list(sw.get("software"))])
        fill_table(self.tables["Services"], [[s.get("display"), s.get("name"), s.get("start"), s.get("state"), s.get("exit"), s.get("account")]
                                              for s in as_list(sw.get("services"))])
        fill_table(self.tables["Démarrage"], [[s.get("name"), s.get("command"), s.get("location"), s.get("user")] for s in as_list(sw.get("startup"))])
        fill_table(self.tables["Tâches planifiées"], [[t.get("name"), t.get("path"), t.get("state"), _d(t.get("last_run")),
                                                       "" if t.get("last_result") is None else f"0x{int(t['last_result']) & 0xFFFFFFFF:08X}",
                                                       t.get("exe")] for t in as_list(sw.get("tasks"))])
        ips = {i.get("alias"): i for i in as_list(net.get("ip"))}
        fill_table(self.tables["Réseau"], [[a.get("name"), a.get("description"), a.get("status"), a.get("speed"),
                                            sjoin(", ", ips.get(a.get("name"), {}).get("ipv4")),
                                            sjoin(", ", ips.get(a.get("name"), {}).get("gateway")),
                                            sjoin(", ", ips.get(a.get("name"), {}).get("dns"))] for a in as_list(net.get("adapters"))])
        procs = (sysd.get("processes") or {}).get("top") or []
        fill_table(self.tables["Processus"], [[p.get("name"), (str(p.get("pid")), p.get("pid") or 0),
                                               (human_bytes(p.get("private")), p.get("private") or 0), (str(p.get("handles")), p.get("handles") or 0),
                                               (str(p.get("threads")), p.get("threads") or 0), (str(p.get("cpu_pct") or 0), p.get("cpu_pct") or 0),
                                               _d(p.get("start")), p.get("company")] for p in procs], numeric={1, 2, 3, 4, 5})
        fill_table(self.tables["Mises à jour"], [[h.get("id"), h.get("description"), _d(h.get("installed"))]
                                                  for h in sorted(as_list(upd.get("hotfixes")), key=lambda h: h.get("installed") or "", reverse=True)])
        fill_table(self.tables["Pilotes"], [[d.get("device"), d.get("provider"), d.get("version"), _d(d.get("date")), d.get("class")]
                                             for d in as_list(sw.get("drivers"))])
        self._filter(self.search.text())

    def _filter(self, txt):
        t = self.tabs.currentWidget()
        txt = (txt or "").lower()
        for r in range(t.rowCount()):
            show = not txt or any(txt in (t.item(r, c).text().lower() if t.item(r, c) else "") for c in range(t.columnCount()))
            t.setRowHidden(r, not show)
