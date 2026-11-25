"""Moteur d'analyse : applique toutes les règles à un instantané et calcule
les notes."""
from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass, field

from . import rules_hw, rules_sec, rules_sys
from .context import Ctx
from .model import CRIT, DOMAINS, INFO, MAJOR, MINOR, NOT_CHECKED, OK, Finding, human_bytes, parse_dt

log = logging.getLogger(__name__)
ALL_RULES = rules_hw.RULES + rules_sys.RULES + rules_sec.RULES


@dataclass
class Analysis:
    findings: list[Finding]
    scores: dict[str, int]          # domaine -> /100, plus "global"
    machine: dict
    rule_errors: list[str] = field(default_factory=list)

    @property
    def problems(self) -> list[Finding]:
        return sorted((f for f in self.findings if f.severity >= MINOR), key=lambda f: (-f.severity, f.domain, f.title))

    @property
    def risks(self) -> list[Finding]:
        return [f for f in self.problems if f.predictive]

    def counts(self) -> dict[int, int]:
        out = {CRIT: 0, MAJOR: 0, MINOR: 0, INFO: 0, OK: 0, NOT_CHECKED: 0}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {"findings": [f.to_dict() for f in self.findings], "scores": self.scores, "machine": self.machine,
                "rule_errors": self.rule_errors}

    @staticmethod
    def from_dict(d: dict) -> "Analysis":
        return Analysis([Finding.from_dict(x) for x in d.get("findings", [])], d.get("scores", {}), d.get("machine", {}),
                        d.get("rule_errors", []))


def score(findings: list[Finding]) -> int:
    """100 moins des pénalités plafonnées par gravité (un seul problème
    critique coûte cher, mais dix mineurs ne valent pas un critique)."""
    n = {s: sum(1 for f in findings if f.severity == s) for s in (CRIT, MAJOR, MINOR)}
    pen = min(60, 25 * n[CRIT]) + min(30, 8 * n[MAJOR]) + min(12, 2 * n[MINOR])
    return max(0, 100 - pen)


def machine_info(c: Ctx) -> dict:
    o, cs = c.os, c.cs
    bios = c.get("system", "bios") or {}
    cpu = (c.lst("system", "cpu") or [{}])[0]
    disks = [f"{d.get('name')} ({human_bytes(d.get('size'))}, {d.get('media')})" for d in c.lst("disks", "physical")]
    ips = []
    for i in c.lst("network", "ip"):
        ips += [a.split("/")[0] for a in i.get("ipv4") or [] if a and not a.startswith("169.254")]
    return {
        "name": cs.get("name") or "?",
        "domain": cs.get("domain") or "",
        "in_domain": c.in_domain,
        "role": "Contrôleur de domaine" if c.is_dc else "Serveur" if c.is_server else "Poste de travail",
        "os": f"{o.get('caption', '')} {o.get('display_version') or ''}".strip(),
        "build": f"{o.get('version', '')}.{o.get('ubr') or 0}",
        "manufacturer": cs.get("manufacturer") or "",
        "model": cs.get("model") or "",
        "serial": bios.get("serial") or "",
        "cpu": cpu.get("name") or "",
        "ram": human_bytes(c.ram) if c.ram else "",
        "disks": disks,
        "ips": ips,
        "installed": (parse_dt(o.get("install_date")) or None) and parse_dt(o.get("install_date")).strftime("%d/%m/%Y"),
        "uptime_days": round(c.uptime_days, 1) if c.uptime_days is not None else None,
        "is_vm": c.is_vm,
        "is_laptop": c.is_laptop,
        "admin": c.admin,
        "user": (c.get("security", "uac_user") or {}).get("user", ""),
        "key": f"{cs.get('name') or ''}|{bios.get('serial') or ''}".upper(),
    }


def analyze(snapshot: dict) -> Analysis:
    c = Ctx(snapshot)
    errors = []
    for rule in ALL_RULES:
        try:
            rule(c)
        except Exception as exc:  # une règle défaillante ne doit pas bloquer l'analyse
            log.error("Règle %s : %s\n%s", rule.__name__, exc, traceback.format_exc())
            errors.append(f"{rule.__module__.rsplit('.', 1)[-1]}.{rule.__name__} : {exc}")
    # dédoublonnage (même identifiant : on garde le plus grave)
    best: dict[str, Finding] = {}
    for f in c.findings:
        if f.id not in best or f.severity > best[f.id].severity:
            best[f.id] = f
    findings = list(best.values())
    scores = {d: score([f for f in findings if f.domain == d]) for d in DOMAINS}
    scores["global"] = score(findings)
    return Analysis(findings, scores, machine_info(c), errors)
