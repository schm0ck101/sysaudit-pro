"""Rapport client PDF (Qt, sans dépendance externe) et export JSON.

Structure : page de garde · synthèse (notes, priorités, risques à venir) ·
constats détaillés par domaine · points conformes · points non vérifiés ·
fiche du poste · méthodologie.
"""
from __future__ import annotations

import html
import json
import time
from pathlib import Path

from .analyze.engine import Analysis
from .analyze.model import sjoin, CRIT, DOMAINS, INFO, MAJOR, MINOR, NOT_CHECKED, OK, SEVERITY
from .config import APP_NAME, APP_VERSION, AUTHOR, AUTHOR_URL

SEV_COLOR = {CRIT: "#c92a2a", MAJOR: "#e8590c", MINOR: "#d4a600", INFO: "#5b6879", OK: "#2b8a3e", NOT_CHECKED: "#868e96"}


def _e(s) -> str:
    return html.escape(str(s or ""))


def score_color(sc: int) -> str:
    return "#2b8a3e" if sc >= 80 else "#e8590c" if sc >= 55 else "#c92a2a"


def verdict(sc: int) -> str:
    if sc >= 85:
        return "Bon état général"
    if sc >= 70:
        return "État correct, quelques points à corriger"
    if sc >= 50:
        return "Plusieurs problèmes à traiter"
    return "État préoccupant : intervention recommandée"


def diff(cur: Analysis, prev: Analysis | None) -> tuple[list, list]:
    """(nouveaux problèmes, problèmes résolus) par rapport à l'analyse précédente."""
    if not prev:
        return [], []
    a = {f.id: f for f in cur.problems}
    b = {f.id: f for f in prev.problems}
    return [a[k] for k in a if k not in b], [b[k] for k in b if k not in a]


def export_pdf(path: str | Path, rec: dict, analysis: Analysis, settings, prev: Analysis | None = None) -> Path:
    from PySide6.QtCore import QMarginsF, QSizeF, QUrl
    from PySide6.QtGui import QImage, QPageLayout, QPageSize, QPdfWriter, QTextDocument

    from .ui.theme import asset_path

    path = Path(path)
    doc = QTextDocument()
    rep = settings.get("report", {}) or {}
    m = analysis.machine
    sc = int(analysis.scores.get("global", 0))
    when = time.strftime("%d/%m/%Y à %H:%M", time.localtime(rec.get("ts") or time.time()))
    counts = analysis.counts()

    def add_img(img: QImage) -> str:
        name = f"img://{id(img)}"
        doc.addResource(QTextDocument.ImageResource, QUrl(name), img)
        return name

    css = """
      body { font-family: 'Segoe UI'; font-size: 9pt; color: #1d2733; }
      h1 { font-size: 24pt; color: #14233b; margin: 0; }
      h2 { font-size: 14pt; color: #14233b; margin-top: 16px; border-bottom: 2px solid #3d7bd9; }
      h3 { font-size: 10.5pt; margin: 10px 0 2px 0; }
      .muted { color: #5b6879; }
      .small { font-size: 8pt; }
      table.grid { border-collapse: collapse; }
      table.grid th { background: #e8eef8; color: #24364f; padding: 4px 6px; text-align: left; font-size: 8.5pt; }
      table.grid td { padding: 3px 6px; border-bottom: 1px solid #e3e8ee; font-size: 8.5pt; vertical-align: top; }
      td.lbl { color: #5b6879; width: 32%; }
    """
    h = [f"<html><head><style>{css}</style></head><body>"]
    # --------------------------------------------------------- page de garde
    logo_path = rep.get("logo") or ""
    if not (logo_path and Path(logo_path).exists()):
        logo_path = str(asset_path("schmock.png"))
    img = QImage(logo_path)
    if not img.isNull():
        h.append(f"<p><img src='{add_img(img.scaledToHeight(min(70, img.height())))}'></p>")
    client = rec.get("client") or ""
    h.append(f"""<p style='margin-top:80px'><span class='muted' style='font-size:12pt'>RAPPORT DE DIAGNOSTIC</span></p>
    <h1>{_e(m.get('name'))}</h1>
    <p style='font-size:12pt'>{_e(m.get('role'))} · {_e(m.get('os'))}</p>
    <p style='margin-top:22px'><span style='font-size:15pt; font-weight:600'>{_e(client)}</span></p>
    <p style='font-size:11pt'>{_e(rec.get('site'))}</p>
    <p style='margin-top:36px'>Date de l'analyse : {when}<br>
    {('Intervenant : ' + _e(rec.get('auditor') or rep.get('auditor')) + '<br>') if (rec.get('auditor') or rep.get('auditor')) else ''}
    {' · '.join(_e(x) for x in (rep.get('company'), rep.get('phone'), rep.get('email')) if x)}</p>
    <p style='margin-top:50px'><span style='font-size:22pt; font-weight:700; color:{score_color(sc)}'>Note globale : {sc} / 100</span></p>
    <p style='font-size:12pt; color:{score_color(sc)}'>{verdict(sc)}</p>
    <p class='muted' style='margin-top:40px'>Document généré par {APP_NAME} {APP_VERSION}
    ({AUTHOR} · {AUTHOR_URL.removeprefix('https://')}) le {time.strftime('%d/%m/%Y à %H:%M')}.</p>""")

    # --------------------------------------------------------------- synthèse
    h.append("<h2 style='page-break-before: always'>1. Synthèse</h2>")
    h.append("<table class='grid' width='100%'><tr><th>Domaine</th><th>Note</th><th>Critiques</th><th>Majeurs</th><th>Mineurs</th></tr>")
    for d, label in DOMAINS.items():
        fs = [f for f in analysis.findings if f.domain == d]
        s = int(analysis.scores.get(d, 0))
        h.append(f"<tr><td><b>{label}</b></td><td style='color:{score_color(s)}'><b>{s} / 100</b></td>"
                 + "".join(f"<td>{sum(1 for f in fs if f.severity == sv) or '—'}</td>" for sv in (CRIT, MAJOR, MINOR)) + "</tr>")
    h.append("</table>")
    probs = analysis.problems
    if not probs:
        h.append("<p style='margin-top:10px'>Aucun problème détecté sur les points contrôlés.</p>")
    else:
        h.append(f"<p style='margin-top:10px'><b>{counts[CRIT]}</b> problème(s) critique(s), <b>{counts[MAJOR]}</b> majeur(s) et "
                 f"<b>{counts[MINOR]}</b> mineur(s) relevés.</p>")
        h.append("<h3>Priorités d'intervention</h3><table class='grid' width='100%'><tr><th>#</th><th>Gravité</th><th>Constat</th><th>Action recommandée</th></tr>")
        for i, f in enumerate([f for f in probs if f.severity >= MAJOR][:12] or probs[:8], 1):
            h.append(f"<tr><td>{i}</td><td style='color:{SEV_COLOR[f.severity]}'><b>{SEVERITY[f.severity]}</b></td>"
                     f"<td>{_e(f.title)}</td><td>{_e(f.fix)}</td></tr>")
        h.append("</table>")
    risks = analysis.risks
    if risks:
        h.append("<h3>Risques à venir</h3><p class='muted'>Problèmes qui ne bloquent pas encore le poste mais annoncent une panne, "
                 "une saturation ou une faille si rien n'est fait.</p><ul>")
        for f in risks:
            h.append(f"<li><b style='color:{SEV_COLOR[f.severity]}'>{_e(f.title)}</b> — {_e(f.impact)}</li>")
        h.append("</ul>")
    if prev:
        new, solved = diff(analysis, prev)
        h.append(f"<h3>Évolution depuis l'analyse précédente</h3><p>Note précédente : {prev.scores.get('global')} / 100 → "
                 f"<b>{sc} / 100</b>. {len(solved)} problème(s) résolu(s), {len(new)} nouveau(x).</p>")
        if solved:
            h.append("<p class='small'>Résolus : " + "; ".join(_e(f.title) for f in solved[:15]) + "</p>")
        if new:
            h.append("<p class='small'>Nouveaux : " + "; ".join(_e(f.title) for f in new[:15]) + "</p>")

    # ------------------------------------------------------------- détails
    n = 2
    for d, label in DOMAINS.items():
        fs = sorted((f for f in analysis.findings if f.domain == d and f.severity >= INFO), key=lambda f: (-f.severity, f.title))
        if not fs:
            continue
        h.append(f"<h2 style='page-break-before: always'>{n}. {label}</h2>")
        n += 1
        for f in fs:
            col = SEV_COLOR[f.severity]
            tag = " · <i>risque à venir</i>" if f.predictive else ""
            h.append(f"<h3><span style='color:{col}'>■ {SEVERITY[f.severity]}{tag}</span> — {_e(f.title)}</h3>")
            if f.detail:
                h.append(f"<p>{_e(f.detail)}</p>")
            if f.impact:
                h.append(f"<p><b>Risque :</b> {_e(f.impact)}</p>")
            if f.fix:
                h.append(f"<p><b>Action :</b> {_e(f.fix)}</p>")
            ev = [e for e in f.evidence if e]
            if ev:
                h.append("<p class='small muted'>" + "<br>".join(_e(e) for e in ev[:4]) + "</p>")

    # --------------------------------------------------- conformes / non vérifiés
    oks = [f for f in analysis.findings if f.severity == OK]
    if oks and rep.get("include_ok", True):
        h.append(f"<h2>{n}. Points contrôlés conformes</h2><ul>")
        n += 1
        for f in sorted(oks, key=lambda f: (f.domain, f.title)):
            h.append(f"<li><span style='color:{SEV_COLOR[OK]}'>✓</span> {_e(f.title)}" + (f" <span class='muted'>— {_e(f.detail)}</span>" if f.detail else "") + "</li>")
        h.append("</ul>")
    ncs = [f for f in analysis.findings if f.severity == NOT_CHECKED]
    if ncs:
        h.append(f"<h2>{n}. Points non vérifiés</h2><p>Ces contrôles n'ont pas pu être réalisés"
                 + (" (application lancée sans droits administrateur)" if not m.get("admin") else "") + " :</p><ul>")
        n += 1
        for f in ncs:
            h.append(f"<li>{_e(f.title)}</li>")
        h.append("</ul>")

    # -------------------------------------------------------------- fiche poste
    if rep.get("include_inventory", True):
        rows = [("Nom", m.get("name")), ("Domaine / groupe", m.get("domain")), ("Rôle", m.get("role")), ("Système", m.get("os")),
                ("Version", m.get("build")), ("Installé le", m.get("installed")), ("Fabricant / modèle", f"{m.get('manufacturer')} {m.get('model')}"),
                ("N° de série", m.get("serial")), ("Processeur", m.get("cpu")), ("Mémoire", m.get("ram")),
                ("Disques", sjoin(", ", m.get("disks"))), ("Adresses IP", sjoin(", ", m.get("ips"))),
                ("Démarré depuis", f"{m.get('uptime_days'):.1f} jour(s)".replace(".", ",") if m.get("uptime_days") is not None else "—"),
                ("Utilisateur", m.get("user"))]
        h.append(f"<h2 style='page-break-before: always'>{n}. Fiche du poste</h2><table class='grid' width='100%'>")
        n += 1
        for k, v in rows:
            h.append(f"<tr><td class='lbl'>{_e(k)}</td><td>{_e(v) or '—'}</td></tr>")
        h.append("</table>")
    if rec.get("notes"):
        h.append(f"<h3>Notes de l'intervenant</h3><p>{_e(rec['notes'])}</p>")

    days = (rec.get("snapshot_options") or {}).get("days", 30)
    h.append(f"""<h2>{n}. Méthodologie et limites</h2>
    <p>Analyse réalisée localement sur le poste avec {APP_NAME}, sans installation ni modification du système
    (lecture seule). Sources : informations système Windows (WMI/CIM), compteurs de fiabilité des disques,
    journaux d'événements des {days} derniers jours, historique Windows Update, indice de fiabilité Windows,
    configuration de sécurité (registre, stratégies, Defender, pare-feu, BitLocker), tests réseau ponctuels.</p>
    <p>Les « risques à venir » sont déduits des tendances et indicateurs d'usure enregistrés par Windows ; ils
    signalent une probabilité, pas une certitude. Un composant peut tomber en panne sans signe préalable :
    seule une sauvegarde régulière et testée protège les données. Les contrôles de sécurité couvrent la
    configuration du poste et ne remplacent pas un test d'intrusion.</p></body></html>""")

    doc.setHtml("".join(h))
    writer = QPdfWriter(str(path))
    writer.setPageSize(QPageSize(QPageSize.A4))
    writer.setPageMargins(QMarginsF(14, 14, 14, 14), QPageLayout.Millimeter)
    writer.setResolution(110)
    writer.setTitle(f"Diagnostic — {m.get('name')} — {client}")
    writer.setCreator(f"{APP_NAME} {APP_VERSION} — {AUTHOR}")
    rect = writer.pageLayout().paintRectPixels(writer.resolution())
    doc.setPageSize(QSizeF(rect.width(), rect.height()))
    doc.print_(writer)
    return path


def export_json(path: str | Path, rec: dict) -> Path:
    """Données brutes + résultat (support, archivage, ré-analyse)."""
    path = Path(path)
    out = {"application": f"{APP_NAME} {APP_VERSION}", "client": rec.get("client"), "site": rec.get("site"),
           "notes": rec.get("notes"), "analysis": rec.get("analysis"), "snapshot": rec.get("snapshot")}
    path.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    return path
