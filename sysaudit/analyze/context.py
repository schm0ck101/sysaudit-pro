"""Contexte d'analyse : accès sûr aux données collectées et profil du poste."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from .model import NOT_CHECKED, Finding, as_list, parse_dt

VM_PAT = re.compile(r"qemu|vmware|virtualbox|innotek|xen|kvm|bochs|parallels|red hat|virtual machine|nutanix|proxmox", re.I)

# erreurs « droits insuffisants » (Windows FR/EN)
DENIED = re.compile(r"accès refusé|access is denied|access denied|non autorisé|unauthorized|privil", re.I)

# libellés des contrôles qui ont échoué faute de droits
SECTION_LABEL = {
    "tpm": "Puce TPM", "thermal": "Températures (capteurs ACPI)", "smart_predict": "Prédiction de panne SMART",
    "physical": "Compteurs de fiabilité des disques", "bitlocker": "Chiffrement BitLocker", "security_logons": "Échecs de connexion (journal Sécurité)",
    "boot_perf": "Durée de démarrage", "boot_degradation": "Causes de lenteur au démarrage", "password_policy": "Stratégie de mots de passe",
    "dism_health": "Intégrité du magasin de composants Windows", "defender_threats": "Menaces détectées par Defender",
    "smb_server": "Configuration du serveur SMB", "reliability": "Indice de fiabilité", "pending": "Mises à jour disponibles",
    "wsb": "Sauvegarde Windows Server", "shadows": "Clichés instantanés", "auditpol": "Stratégie d'audit de sécurité",
    "restore_points": "Points de restauration", "virtual_disks": "Espaces de stockage", "ad": "Annuaire Active Directory",
    "mp_prefs": "Exclusions de l'antivirus", "psv2": "PowerShell 2.0",
}


class Ctx:
    def __init__(self, snapshot: dict):
        self.snap = snapshot
        self.findings: list[Finding] = []
        ts = snapshot.get("collected_at")
        self.now = datetime.fromtimestamp(ts, timezone.utc) if ts else datetime.now(timezone.utc)
        o = self.get("system", "os") or {}
        c = self.get("system", "computer") or {}
        self.os, self.cs = o, c
        self.build = int(o.get("build") or 0)
        self.product_type = int(o.get("product_type") or 1)
        self.is_server = self.product_type in (2, 3)
        self.is_dc = self.product_type == 2 or int(c.get("domain_role") or 0) in (4, 5)
        self.in_domain = bool(c.get("part_of_domain"))
        vm_text = f"{c.get('manufacturer', '')} {c.get('model', '')} {(self.get('system', 'bios') or {}).get('manufacturer', '')}"
        self.is_vm = bool(VM_PAT.search(vm_text))
        self.is_laptop = int(c.get("pc_type") or 0) == 2 or bool(self.get("system", "battery"))
        self.admin = bool(snapshot.get("admin"))
        self.ram = int(c.get("total_bytes") or 0) or int(o.get("total_kb") or 0) * 1024
        boot = parse_dt(o.get("last_boot"))
        self.uptime_days = (self.now - boot).total_seconds() / 86400 if boot else None

    # ----------------------------------------------------------- accès
    def section(self, name: str) -> dict:
        s = self.snap.get("sections", {}).get(name) or {}
        return s.get("data") or {}

    def get(self, section: str, key: str, default=None):
        v = self.section(section).get(key, default)
        return default if v is None else v

    def lst(self, section: str, key: str) -> list:
        return [x for x in as_list(self.section(section).get(key)) if x is not None]

    def has(self, section: str, key: str) -> bool:
        return key in self.section(section)

    def errors(self) -> dict[str, str]:
        out = {}
        for name, s in (self.snap.get("sections") or {}).items():
            if not s.get("ok"):
                out[name] = s.get("error") or "échec"
            for e in as_list((s.get("data") or {}).get("_errors")):
                k, _, msg = str(e).partition(":")
                out[k.strip()] = msg.strip()
        return out

    def add(self, f: Finding):
        self.findings.append(f)

    # ----------------------------------------------------------- journaux
    def events(self, provider: str | tuple, ids=None, logs=("system_errors", "system_warnings", "application_errors")) -> list[dict]:
        provs = (provider,) if isinstance(provider, str) else provider
        provs = tuple(p.lower() for p in provs)
        ids = set(ids) if ids else None
        out = []
        for key in logs:
            for g in self.lst("events", key):
                if (g.get("provider") or "").lower() in provs and (ids is None or int(g.get("id") or 0) in ids):
                    out.append(g)
        return out

    @staticmethod
    def count(groups: list[dict]) -> int:
        return sum(int(g.get("count") or 0) for g in groups)

    def count_since(self, groups: list[dict], days: int) -> int:
        lim = (self.now - timedelta(days=days)).date().isoformat()
        n = 0
        for g in groups:
            for d, c in (g.get("days") or {}).items():
                if d >= lim:
                    n += int(c)
        return n

    def trend(self, groups: list[dict], recent_days: int = 7, total_days: int = 30) -> tuple[float, float]:
        """(moyenne/jour récente, moyenne/jour antérieure)."""
        recent = self.count_since(groups, recent_days)
        total = self.count_since(groups, total_days)
        before = max(0, total - recent)
        return recent / recent_days, before / max(1, total_days - recent_days)

    def not_checked(self, fid: str, domain: str, title: str, why: str = ""):
        self.add(Finding(fid, domain, NOT_CHECKED, title,
                         detail=why or "Ce contrôle nécessite de lancer l'application en tant qu'administrateur."))
