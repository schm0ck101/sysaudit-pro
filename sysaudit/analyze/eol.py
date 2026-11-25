"""Fin de support (cycle de vie Microsoft et logiciels courants).

Dates officielles de fin de support (sécurité). Mettre à jour cette table
lors des nouvelles versions de l'application.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class OsLife:
    name: str
    end: date | None          # None : date non connue / support en cours
    note: str = ""


# build -> (nom, fin Famille/Pro, fin Entreprise/Éducation)
CLIENT = {
    7601: ("Windows 7", date(2020, 1, 14), date(2020, 1, 14)),
    9600: ("Windows 8.1", date(2023, 1, 10), date(2023, 1, 10)),
    10240: ("Windows 10 1507", date(2017, 5, 9), date(2017, 5, 9)),
    14393: ("Windows 10 1607", date(2018, 4, 10), date(2019, 4, 9)),
    17763: ("Windows 10 1809", date(2020, 11, 10), date(2021, 5, 11)),
    18363: ("Windows 10 1909", date(2021, 5, 11), date(2022, 5, 10)),
    19041: ("Windows 10 2004", date(2021, 12, 14), date(2021, 12, 14)),
    19042: ("Windows 10 20H2", date(2022, 5, 10), date(2023, 5, 9)),
    19043: ("Windows 10 21H1", date(2022, 12, 13), date(2022, 12, 13)),
    19044: ("Windows 10 21H2", date(2023, 6, 13), date(2024, 6, 11)),
    19045: ("Windows 10 22H2", date(2025, 10, 14), date(2025, 10, 14)),
    22000: ("Windows 11 21H2", date(2023, 10, 10), date(2024, 10, 8)),
    22621: ("Windows 11 22H2", date(2024, 10, 8), date(2025, 10, 14)),
    22631: ("Windows 11 23H2", date(2025, 11, 11), date(2026, 11, 10)),
    26100: ("Windows 11 24H2", date(2026, 10, 13), date(2027, 10, 12)),
    26200: ("Windows 11 25H2", date(2027, 10, 12), date(2028, 10, 10)),
}
# éditions LTSC / LTSB (EditionID « EnterpriseS »)
LTSC = {
    14393: ("Windows 10 LTSB 2016", date(2026, 10, 13)),
    17763: ("Windows 10 LTSC 2019", date(2029, 1, 9)),
    19044: ("Windows 10 LTSC 2021", date(2027, 1, 12)),
    26100: ("Windows 11 LTSC 2024", date(2029, 10, 9)),
}
SERVER = {
    7601: ("Windows Server 2008 R2", date(2020, 1, 14)),
    9200: ("Windows Server 2012", date(2023, 10, 10)),
    9600: ("Windows Server 2012 R2", date(2023, 10, 10)),
    14393: ("Windows Server 2016", date(2027, 1, 12)),
    17763: ("Windows Server 2019", date(2029, 1, 9)),
    20348: ("Windows Server 2022", date(2031, 10, 14)),
    25398: ("Windows Server 23H2", date(2025, 10, 24)),
    26100: ("Windows Server 2025", date(2034, 11, 14)),
}


def os_life(build: int, product_type: int, edition: str | None) -> OsLife:
    ed = (edition or "").lower()
    if product_type in (2, 3):
        if build in SERVER:
            n, e = SERVER[build]
            return OsLife(n, e)
        older = [b for b in SERVER if b < build]
        return OsLife(f"Windows Server (build {build})", None, "version non répertoriée")
    if "enterprises" in ed or "ltsc" in ed or "ltsb" in ed:
        if build in LTSC:
            n, e = LTSC[build]
            return OsLife(n, e)
    if build in CLIENT:
        n, home, ent = CLIENT[build]
        is_ent = ed.startswith(("enterprise", "education", "iotenterprise"))
        return OsLife(n + (" (Entreprise/Éducation)" if is_ent and home != ent else ""), ent if is_ent else home)
    if build < 19045:
        return OsLife(f"Windows 10 (build {build})", date(2023, 6, 13), "version très ancienne")
    return OsLife(f"Windows (build {build})", None, "version récente non répertoriée")


# ------------------------------------------------------------------ logiciels
@dataclass(frozen=True)
class SoftRule:
    pattern: str
    label: str
    end: date | None = None         # fin de support
    max_vuln: str | None = None     # versions STRICTEMENT inférieures vulnérables
    why: str = ""


SOFTWARE_RULES = [
    SoftRule(r"^Microsoft Office .*\b2007\b", "Office 2007", date(2017, 10, 10)),
    SoftRule(r"^Microsoft Office .*\b2010\b", "Office 2010", date(2020, 10, 13)),
    SoftRule(r"^Microsoft Office .*\b2013\b", "Office 2013", date(2023, 4, 11)),
    SoftRule(r"^Microsoft Office .*\b2016\b", "Office 2016", date(2025, 10, 14)),
    SoftRule(r"^Microsoft Office .*\b2019\b", "Office 2019", date(2025, 10, 14)),
    SoftRule(r"^Microsoft Office .*\b(LTSC )?2021\b", "Office 2021", date(2026, 10, 13)),
    SoftRule(r"^Microsoft SQL Server 2008\b.*\((64|32)", "SQL Server 2008", date(2019, 7, 9)),
    SoftRule(r"^Microsoft SQL Server 2012\b.*\((64|32)", "SQL Server 2012", date(2022, 7, 12)),
    SoftRule(r"^Microsoft SQL Server 2014\b.*\((64|32)", "SQL Server 2014", date(2024, 7, 9)),
    SoftRule(r"^Microsoft SQL Server 2016\b.*\((64|32)", "SQL Server 2016", date(2026, 7, 14)),
    SoftRule(r"^Microsoft SQL Server 2017\b.*\((64|32)", "SQL Server 2017", date(2027, 10, 12)),
    SoftRule(r"^Microsoft Exchange Server 2013", "Exchange Server 2013", date(2023, 4, 11)),
    SoftRule(r"^Microsoft Exchange Server 201[69]", "Exchange Server 2016/2019", date(2025, 10, 14)),
    SoftRule(r"Adobe Flash Player", "Adobe Flash Player", date(2020, 12, 31)),
    SoftRule(r"Microsoft Silverlight", "Microsoft Silverlight", date(2021, 10, 12)),
    SoftRule(r"^Java(\(TM\))? [67] Update|^Java [67]\b", "Java 6/7", date(2015, 4, 30)),
    SoftRule(r"^Python 2\.", "Python 2", date(2020, 1, 1)),
    SoftRule(r"Adobe Reader XI|Adobe Acrobat XI", "Adobe Reader/Acrobat XI", date(2017, 10, 15)),
    SoftRule(r"Adobe Acrobat (Reader )?(DC )?\(?2015|Adobe Acrobat (Reader )?(DC )?\(?2017", "Adobe Acrobat 2015/2017", date(2022, 6, 6)),
    SoftRule(r"Adobe Acrobat (Reader )?2020", "Adobe Acrobat 2020", date(2025, 11, 30)),
    SoftRule(r"^WinRAR\b", "WinRAR", max_vuln="7.13",
             why="vulnérabilité CVE-2025-8088 exploitée activement (archives piégées)"),
    SoftRule(r"^7-Zip\b", "7-Zip", max_vuln="24.09",
             why="vulnérabilité CVE-2025-0411 (contournement de la protection des fichiers téléchargés)"),
    SoftRule(r"^PuTTY\b", "PuTTY", max_vuln="0.81", why="vulnérabilité CVE-2024-31497 (clés ECDSA récupérables)"),
]

REMOTE_ACCESS = re.compile(r"TeamViewer|AnyDesk|RustDesk|Splashtop|LogMeIn|ScreenConnect|ConnectWise Control|UltraViewer|"
                           r"RealVNC|TightVNC|UltraVNC|Chrome Remote Desktop|Supremo|Ammyy|NetSupport|Radmin|DWService|"
                           r"Zoho Assist|GoTo Resolve|Atera|NinjaOne|Remote Utilities|Parsec|AweSun|ToDesk|Dameware", re.I)


def version_tuple(v: str) -> tuple:
    parts = re.findall(r"\d+", v or "")
    return tuple(int(p) for p in parts[:4]) or (0,)


def version_lt(a: str, b: str) -> bool:
    ta, tb = version_tuple(a), version_tuple(b)
    n = max(len(ta), len(tb))
    return ta + (0,) * (n - len(ta)) < tb + (0,) * (n - len(tb))
