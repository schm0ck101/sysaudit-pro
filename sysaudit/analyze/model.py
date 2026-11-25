"""Modèle des constats et outils communs aux règles d'analyse."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

# Domaines : matériel/stabilité, système/performances, sécurité, rôles serveur et sauvegardes
HW, SYS, SEC, SVC = "hw", "sys", "sec", "svc"
DOMAINS = {HW: "Matériel et stabilité", SYS: "Système et performances", SEC: "Sécurité", SVC: "Rôles et sauvegardes"}

# Gravités
NOT_CHECKED, OK, INFO, MINOR, MAJOR, CRIT = -1, 0, 1, 2, 3, 4
SEVERITY = {CRIT: "Critique", MAJOR: "Majeur", MINOR: "Mineur", INFO: "Information", OK: "Conforme",
            NOT_CHECKED: "Non vérifié"}


@dataclass
class Finding:
    id: str                    # identifiant stable (comparaison entre deux analyses)
    domain: str
    severity: int
    title: str
    detail: str = ""           # ce qui a été constaté
    impact: str = ""           # pourquoi c'est un problème
    fix: str = ""              # que faire
    evidence: list[str] = field(default_factory=list)
    predictive: bool = False   # risque à venir (et pas seulement un défaut actuel)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Finding":
        return Finding(**{k: d.get(k) for k in Finding.__dataclass_fields__ if k in d})


# ------------------------------------------------------------------ dates
_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})?$")


def parse_dt(s) -> datetime | None:
    """Date ISO de PowerShell (7 décimales, fuseau facultatif) -> datetime aware."""
    if not s or not isinstance(s, str):
        return None
    m = _ISO.match(s.strip())
    if not m:
        return None
    frac = m.group(2) or ""                      # ".1234567" : 6 chiffres max pour Python
    base = m.group(1) + (("." + frac[1:7]) if frac else "")
    tz = m.group(3) or ""
    try:
        d = datetime.fromisoformat(base + (tz.replace("Z", "+00:00")))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.astimezone()  # heure locale du poste
    return d


def days_between(a: datetime | None, b: datetime | None) -> float | None:
    if not a or not b:
        return None
    return (b - a).total_seconds() / 86400


def human_bytes(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if abs(n) < 1024 or unit == "To":
            return f"{n:.0f} {unit}" if unit == "o" else f"{n:.1f} {unit}".replace(".", ",")
        n /= 1024
    return f"{n:.1f} To"


def fr_date(d: datetime | None) -> str:
    return d.strftime("%d/%m/%Y") if d else "—"


def fr_num(x, dec: int = 0) -> str:
    s = f"{x:,.{dec}f}".replace(",", " ").replace(".", ",")
    return s


def sjoin(sep: str, items) -> str:
    """join() tolérant : ignore les valeurs vides (None) renvoyées par Windows."""
    return sep.join(str(x) for x in (items or []) if x is not None and str(x) != "")


def as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    if isinstance(v, dict) and not v:
        return []
    return [v]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


__all__ = ["Finding", "DOMAINS", "SEVERITY", "HW", "SYS", "SEC", "SVC", "NOT_CHECKED", "OK", "INFO", "MINOR", "MAJOR",
           "CRIT", "sjoin", "parse_dt", "days_between", "human_bytes", "fr_date", "fr_num", "as_list", "utcnow", "timedelta"]
