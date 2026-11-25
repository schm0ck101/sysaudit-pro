"""Rapport client PDF (Qt, sans dépendance externe) et export JSON.

Structure : page de garde (dessinée) · synthèse (notes, chiffres clés, priorités,
risques à venir) · constats détaillés par domaine · points conformes · points
non vérifiés · fiche du poste · méthodologie. Chaque page de contenu porte un
en-tête (logo, poste, client) et un pied de page numéroté.
"""
from __future__ import annotations

import html
import json
import time
from pathlib import Path

from .analyze.engine import Analysis
from .analyze.model import sjoin, CRIT, DOMAINS, INFO, MAJOR, MINOR, NOT_CHECKED, OK, SEVERITY
from .config import APP_NAME, APP_VERSION, AUTHOR, AUTHOR_URL

SEV_COLOR = {CRIT: "#c92a2a", MAJOR: "#e8590c", MINOR: "#d49a00", INFO: "#5b6879", OK: "#2b8a3e", NOT_CHECKED: "#868e96"}
SEV_TINT = {CRIT: "#fdf0f0", MAJOR: "#fef4ec", MINOR: "#fdf8e8", INFO: "#f3f5f8", OK: "#eef7f0", NOT_CHECKED: "#f3f5f8"}
NAVY = "#14233b"
ACCENT = "#f47c48"      # orange SCHMOCK
INK = "#1d2733"
MUTED = "#5b6879"
LINE = "#e3e8ee"


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


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n <= 1 else many}"


# ------------------------------------------------------------------ dessin
def _ring(p, cx: float, cy: float, r: float, width: float, value: int, color: str, font_px: float,
          track: str = "#e6ebf2", text_color: str | None = None, suffix_px: float = 0):
    """Jauge circulaire : piste + arc proportionnel à la note, note au centre."""
    from PySide6.QtCore import QPointF, QRectF, Qt
    from PySide6.QtGui import QColor, QFont, QPen

    p.save()
    p.setBrush(Qt.NoBrush)
    pen = QPen(QColor(track), width)
    p.setPen(pen)
    p.drawEllipse(QPointF(cx, cy), r, r)
    pen = QPen(QColor(color), width)
    pen.setCapStyle(Qt.RoundCap)
    p.setPen(pen)
    span = int(-360 * 16 * max(0, min(100, value)) / 100)
    if span:
        p.drawArc(QRectF(cx - r, cy - r, 2 * r, 2 * r), 90 * 16, span)
    f = QFont("Segoe UI")
    f.setPixelSize(max(1, int(font_px)))
    f.setWeight(QFont.Bold)
    p.setFont(f)
    p.setPen(QColor(text_color or color))
    if suffix_px:
        box = QRectF(cx - r, cy - r, 2 * r, 2 * r - suffix_px * 0.9)
        p.drawText(box, Qt.AlignCenter, str(value))
        f2 = QFont("Segoe UI")
        f2.setPixelSize(max(1, int(suffix_px)))
        p.setFont(f2)
        p.setPen(QColor(MUTED))
        p.drawText(QRectF(cx - r, cy + font_px * 0.32, 2 * r, suffix_px * 1.6), Qt.AlignHCenter | Qt.AlignTop, "/ 100")
    else:
        p.drawText(QRectF(cx - r, cy - r, 2 * r, 2 * r), Qt.AlignCenter, str(value))
    p.restore()


def _domains(analysis: Analysis) -> list[tuple[str, str]]:
    """Domaines notés dans cette analyse (une analyse ancienne n'a pas « Rôles et sauvegardes »)."""
    return [(d, label) for d, label in DOMAINS.items() if d in analysis.scores]


def _domain_rings_image(analysis: Analysis):
    """Image des trois jauges de domaine (insérée dans la synthèse)."""
    from PySide6.QtCore import QRectF, Qt
    from PySide6.QtGui import QColor, QFont, QImage, QPainter

    doms = _domains(analysis)
    W, H = 420 * len(doms), 420
    img = QImage(W, H, QImage.Format_ARGB32_Premultiplied)
    img.fill(Qt.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    col_w = W / len(doms)
    for i, (d, label) in enumerate(doms):
        s = int(analysis.scores.get(d, 0))
        cx = col_w * i + col_w / 2
        _ring(p, cx, 150, 112, 22, s, score_color(s), 92)
        f = QFont("Segoe UI")
        f.setPixelSize(36)
        f.setWeight(QFont.DemiBold)
        p.setFont(f)
        p.setPen(QColor(INK))
        p.drawText(QRectF(col_w * i, 290, col_w, 56), Qt.AlignCenter, label)
        fs = [x for x in analysis.findings if x.domain == d]
        parts = [f"{n} {lbl}" for n, lbl in ((sum(1 for x in fs if x.severity == CRIT), "crit."),
                                               (sum(1 for x in fs if x.severity == MAJOR), "maj."),
                                               (sum(1 for x in fs if x.severity == MINOR), "min.")) if n]
        f.setPixelSize(32)
        f.setWeight(QFont.Normal)
        p.setFont(f)
        p.setPen(QColor(MUTED))
        p.drawText(QRectF(col_w * i, 345, col_w, 50), Qt.AlignCenter, " · ".join(parts) or "aucun problème")
    p.end()
    return img


# ------------------------------------------------------------------ HTML
CSS = f"""
  body {{ font-family: 'Segoe UI'; font-size: 9pt; color: {INK}; }}
  p {{ margin: 0; }}
  h2 {{ font-size: 15pt; color: {NAVY}; font-weight: 600; margin: 0 0 2px 0; }}
  h3 {{ font-size: 11pt; color: {NAVY}; font-weight: 600; margin: 18px 0 6px 0; }}
  .muted {{ color: {MUTED}; }}
  .small {{ font-size: 8pt; }}
  .ev {{ font-family: 'Consolas'; font-size: 7.5pt; color: #6b7785; }}
  table.grid td {{ padding: 5px 8px; border-bottom: 1px solid {LINE}; vertical-align: top; }}
  td.lbl {{ color: {MUTED}; }}
"""


def _section(num: int, title: str, right: str = "", page_break: bool = True) -> str:
    """Titre de section (numéro, titre, note éventuelle à droite, filet) : un seul bloc
    de premier niveau pour que _keep_together le garde avec la suite."""
    pb = "page-break-before: always; " if page_break else ""
    tail = f"<td align='right' valign='bottom'>{right}</td>" if right else ""
    return (f"<table width='100%' cellspacing='0' cellpadding='0' style='{pb}margin-top:{0 if page_break else 22}px'><tr><td>"
            f"<table width='100%' cellspacing='0' cellpadding='0'><tr>"
            f"<td valign='bottom'><h2><span style='color:{ACCENT}'>{num:02d}</span>&nbsp;&nbsp;{_e(title)}</h2></td>{tail}</tr></table>"
            f"<table width='100%' cellspacing='0' cellpadding='0' style='margin-bottom:12px'><tr>"
            f"<td bgcolor='{NAVY}' width='12%' style='font-size:1.6pt'>&nbsp;</td><td bgcolor='{LINE}' style='font-size:1.6pt'>&nbsp;</td></tr></table>"
            f"</td></tr></table>")


def _keep_together(doc, page_h: float, min_gap: float) -> None:
    """QTextDocument ne gère pas « page-break-inside: avoid » : une fiche coupée en bas
    de page (ou un titre seul en bas de page) est renvoyée en haut de la page suivante."""
    import re

    from PySide6.QtGui import QTextFormat

    lay = doc.documentLayout()
    for _ in range(300):
        lay.documentSize()   # force la mise en page
        changed = False
        for fr in doc.rootFrame().childFrames():
            r = lay.frameBoundingRect(fr)
            fmt = fr.frameFormat()
            if r.height() > page_h * 0.6 or fmt.pageBreakPolicy() & QTextFormat.PageBreak_AlwaysBefore:
                continue
            first, last = int(r.top() // page_h), int((r.bottom() - 1) // page_h)
            inner = fr.childFrames()
            txt = fr.firstCursorPosition().block().text() or (inner[0].firstCursorPosition().block().text() if inner else "")
            heading = re.match(r"^\d\d ", txt or "")
            if r.top() % page_h < 1:   # déjà en haut de page
                continue
            if first != last or (heading and (first + 1) * page_h - r.bottom() < min_gap):
                fmt.setPageBreakPolicy(QTextFormat.PageBreak_AlwaysBefore)
                fr.setFrameFormat(fmt)
                changed = True
                break
        if not changed:
            return


def _pill(text: str, bg: str, fg: str = "#ffffff") -> str:
    return (f"<span style='background-color:{bg}; color:{fg}; font-size:7.5pt; font-weight:600'>"
            f"&nbsp;&nbsp;{_e(text.upper())}&nbsp;&nbsp;</span>")


def _card(f) -> str:
    col = SEV_COLOR[f.severity]
    pills = _pill(SEVERITY[f.severity], col)
    if f.predictive:
        pills += "&nbsp;&nbsp;" + _pill("Risque à venir", "#fff1cc", "#8a5a00")
    rows = []
    if f.impact:
        rows.append(("Risque", "#8a5a00", f.impact))
    if f.fix:
        rows.append(("Action", "#1d6b3a", f.fix))
    sub = ""
    if rows:
        sub = ("<table cellspacing='0' cellpadding='0' width='100%' style='margin-top:6px'>"
               + "".join(f"<tr><td width='54' style='color:{c}; font-weight:600; padding:2px 0'>{lbl}</td>"
                         f"<td style='padding:2px 0'>{_e(t)}</td></tr>" for lbl, c, t in rows)
               + "</table>")
    ev = [x for x in f.evidence if x]
    evh = ("<p class='ev' style='margin-top:6px'>" + "<br>".join(_e(x) for x in ev[:4]) + "</p>") if ev else ""
    det = f"<p style='margin-top:3px; color:#3a4656'>{_e(f.detail)}</p>" if f.detail else ""
    return (f"<table width='100%' cellspacing='0' cellpadding='0' style='margin-top:10px'><tr>"
            f"<td width='4' bgcolor='{col}'></td>"
            f"<td bgcolor='#f7f9fc' style='padding:9px 12px 10px 12px'>"
            f"<p>{pills}</p>"
            f"<p style='margin-top:5px; font-size:10.5pt; font-weight:600; color:{NAVY}'>{_e(f.title)}</p>"
            f"{det}{sub}{evh}</td></tr></table>")


def _build_html(rec: dict, analysis: Analysis, rep: dict, prev: Analysis | None, add_img) -> str:
    m = analysis.machine
    sc = int(analysis.scores.get("global", 0))
    counts = analysis.counts()
    h = [f"<html><head><style>{CSS}</style></head><body>"]
    n = 1

    # --------------------------------------------------------------- synthèse
    h.append(_section(n, "Synthèse", page_break=False).replace("margin-top:22px", "margin-top:0px"))
    n += 1
    h.append(f"<p style='font-size:10pt'>Note globale <b style='color:{score_color(sc)}'>{sc} / 100</b> — "
             f"<span style='color:{score_color(sc)}'>{verdict(sc)}</span>.</p>")
    h.append(f"<p style='margin-top:8px' align='center'><img src='{add_img(_domain_rings_image(analysis))}' width='{min(640, 190 * len(_domains(analysis)))}'></p>")
    risks = analysis.risks
    kpis = [(counts[CRIT], "critique" if counts[CRIT] <= 1 else "critiques", SEV_COLOR[CRIT], SEV_TINT[CRIT]),
            (counts[MAJOR], "majeur" if counts[MAJOR] <= 1 else "majeurs", SEV_COLOR[MAJOR], SEV_TINT[MAJOR]),
            (counts[MINOR], "mineur" if counts[MINOR] <= 1 else "mineurs", SEV_COLOR[MINOR], SEV_TINT[MINOR]),
            (len(risks), "risque à venir" if len(risks) <= 1 else "risques à venir", "#8a5a00", "#fff8e1")]
    h.append("<table width='100%' cellspacing='6' cellpadding='0' style='margin-top:10px'><tr>")
    for val, lbl, c, tint in kpis:
        h.append(f"<td width='25%' bgcolor='{tint}' align='center' style='padding:10px 4px'>"
                 f"<p style='font-size:20pt; font-weight:700; color:{c if val else '#9aa5b1'}'>{val}</p>"
                 f"<p style='font-size:8.5pt; color:{MUTED}'>{lbl}</p></td>")
    h.append("</tr></table>")

    probs = analysis.problems
    if not probs:
        h.append(f"<p style='margin-top:14px; color:{SEV_COLOR[OK]}; font-size:10.5pt'><b>✓ Aucun problème détecté sur les points contrôlés.</b></p>")
    else:
        # constats demandant la même action regroupés (ex. 7 partages ouverts à « Tout le monde »)
        groups: dict = {}
        for f in [f for f in probs if f.severity >= MAJOR] or probs:
            groups.setdefault((f.fix or f.id), []).append(f)
        top = list(groups.values())[:10]
        h.append("<h3>Priorités d'intervention</h3>")
        h.append("<table width='100%' cellspacing='0' cellpadding='0'>")
        for i, grp in enumerate(top, 1):
            f = grp[0]
            more = (f"<span style='color:{MUTED}'> — et {_plural(len(grp) - 1, 'autre constat', 'autres constats')} du même type</span>"
                    if len(grp) > 1 else "")
            h.append(f"<tr><td width='34' valign='top' style='padding:7px 0; border-bottom:1px solid {LINE}'>"
                     f"<span style='font-size:14pt; font-weight:700; color:#c3cbd6'>{i}</span></td>"
                     f"<td valign='top' style='padding:7px 0; border-bottom:1px solid {LINE}'>"
                     f"<p>{_pill(SEVERITY[f.severity], SEV_COLOR[f.severity])}&nbsp;&nbsp;<b style='color:{NAVY}'>{_e(f.title)}</b>{more}</p>"
                     + (f"<p style='margin-top:3px; color:#3a4656'><span style='color:#1d6b3a; font-weight:600'>→</span> {_e(f.fix)}</p>" if f.fix else "")
                     + "</td></tr>")
        h.append("</table>")
    if risks:
        h.append("<h3>Risques à venir</h3>")
        h.append("<table width='100%' cellspacing='0' cellpadding='0'><tr><td width='4' bgcolor='#e0a800'></td>"
                 "<td bgcolor='#fff8e1' style='padding:9px 12px'>"
                 "<p class='muted' style='margin-bottom:4px'>Ils ne bloquent pas encore le poste mais annoncent une panne, "
                 "une saturation ou une faille si rien n'est fait.</p>")
        for f in risks:
            h.append(f"<p style='margin-top:4px'><b style='color:{SEV_COLOR[f.severity]}'>■</b>&nbsp; <b>{_e(f.title)}</b>"
                     + (f" <span style='color:#3a4656'>— {_e(f.impact)}</span>" if f.impact else "") + "</p>")
        h.append("</td></tr></table>")
    if prev:
        new, solved = diff(analysis, prev)
        ps = int(prev.scores.get("global", 0))
        delta = sc - ps
        dcol = "#2b8a3e" if delta > 0 else "#c92a2a" if delta < 0 else MUTED
        h.append("<h3>Évolution depuis l'analyse précédente</h3>")
        h.append(f"<p>Note : {ps} → <b>{sc} / 100</b> <b style='color:{dcol}'>({delta:+d})</b> · "
                 f"{_plural(len(solved), 'problème résolu', 'problèmes résolus')} · {_plural(len(new), 'nouveau', 'nouveaux')}</p>")
        if solved:
            h.append(f"<p class='small' style='margin-top:4px'><b style='color:#2b8a3e'>Résolus :</b> "
                     + "; ".join(_e(f.title) for f in solved[:15]) + "</p>")
        if new:
            h.append(f"<p class='small' style='margin-top:4px'><b style='color:#c92a2a'>Nouveaux :</b> "
                     + "; ".join(_e(f.title) for f in new[:15]) + "</p>")

    # ------------------------------------------------------------- détails
    for d, label in DOMAINS.items():
        fs = sorted((f for f in analysis.findings if f.domain == d and f.severity >= INFO), key=lambda f: (-f.severity, f.title))
        if not fs:
            continue
        s = int(analysis.scores.get(d, 0))
        right = f"<span style='font-size:13pt; font-weight:700; color:{score_color(s)}'>{s}</span><span class='muted'> / 100</span>"
        h.append(_section(n, label, right))
        n += 1
        nb = sum(1 for f in fs if f.severity >= MINOR)
        h.append(f"<p class='muted'>{_plural(nb, 'problème relevé', 'problèmes relevés')}"
                 + (f", {_plural(len(fs) - nb, 'information', 'informations')}" if len(fs) > nb else "") + ".</p>")
        for f in fs:
            h.append(_card(f))

    # --------------------------------------------------- conformes / non vérifiés
    oks = sorted((f for f in analysis.findings if f.severity == OK), key=lambda f: (f.domain, f.title))
    ncs = [f for f in analysis.findings if f.severity == NOT_CHECKED]
    first = True
    if oks and rep.get("include_ok", True):
        h.append(_section(n, "Points contrôlés conformes"))
        n += 1
        first = False
        h.append("<table width='100%' cellspacing='0' cellpadding='0' class='grid'>")
        for f in oks:
            h.append(f"<tr><td width='22' style='color:{SEV_COLOR[OK]}; font-weight:700'>✓</td>"
                     f"<td><b>{_e(f.title)}</b>" + (f"<br><span class='muted'>{_e(f.detail)}</span>" if f.detail else "")
                     + f"</td><td width='26%' class='lbl' align='right'>{_e(DOMAINS.get(f.domain, ''))}</td></tr>")
        h.append("</table>")
    if ncs:
        h.append(_section(n, "Points non vérifiés", page_break=first))
        n += 1
        h.append("<p>Ces contrôles n'ont pas pu être réalisés"
                 + (" : l'application a été lancée sans droits administrateur." if not m.get("admin") else ".") + "</p>")
        h.append("<table width='100%' cellspacing='0' cellpadding='0' class='grid' style='margin-top:6px'>")
        for f in ncs:
            h.append(f"<tr><td width='22' style='color:{SEV_COLOR[NOT_CHECKED]}'>○</td><td>{_e(f.title)}"
                     + (f"<br><span class='muted'>{_e(f.detail)}</span>" if f.detail else "") + "</td></tr>")
        h.append("</table>")

    # -------------------------------------------------------------- fiche poste
    if rep.get("include_inventory", True):
        rows = [("Nom", m.get("name")), ("Domaine / groupe", m.get("domain")), ("Rôle", m.get("role")), ("Système", m.get("os")),
                ("Version", m.get("build")), ("Installé le", m.get("installed")),
                ("Fabricant / modèle", " ".join(x for x in (m.get("manufacturer"), m.get("model")) if x)),
                ("N° de série", m.get("serial")), ("Processeur", m.get("cpu")), ("Mémoire", m.get("ram")),
                ("Disques", sjoin(", ", m.get("disks"))), ("Adresses IP", sjoin(", ", m.get("ips"))),
                ("Démarré depuis", f"{m.get('uptime_days'):.1f} jour(s)".replace(".", ",") if m.get("uptime_days") is not None else "—"),
                ("Utilisateur", m.get("user"))]
        h.append(_section(n, "Fiche du poste"))
        n += 1
        h.append("<table width='100%' cellspacing='0' cellpadding='0' class='grid'>")
        for i, (k, v) in enumerate(rows):
            bg = " bgcolor='#f7f9fc'" if i % 2 == 0 else ""
            h.append(f"<tr{bg}><td class='lbl' width='30%'>{_e(k)}</td><td>{_e(v) or '—'}</td></tr>")
        h.append("</table>")
    if rec.get("notes"):
        h.append("<h3>Notes de l'intervenant</h3>"
                 f"<table width='100%' cellspacing='0' cellpadding='0'><tr><td width='4' bgcolor='{NAVY}'></td>"
                 f"<td bgcolor='#f7f9fc' style='padding:9px 12px'><p>{_e(rec['notes']).replace(chr(10), '<br>')}</p></td></tr></table>")

    days = (rec.get("snapshot_options") or {}).get("days", 30)
    h.append(_section(n, "Méthodologie et limites", page_break=not rep.get("include_inventory", True)))
    h.append(f"""<p style='line-height:140%'>Analyse réalisée localement sur le poste avec {APP_NAME}, sans installation ni
    modification du système (lecture seule). Sources : informations système Windows (WMI/CIM), compteurs de fiabilité des
    disques, journaux d'événements des {days} derniers jours, historique Windows Update, indice de fiabilité Windows,
    configuration de sécurité (registre, stratégies, Defender, pare-feu, BitLocker), tests réseau ponctuels.</p>
    <p style='margin-top:8px; line-height:140%'>Les « risques à venir » sont déduits des tendances et indicateurs d'usure
    enregistrés par Windows ; ils signalent une probabilité, pas une certitude. Un composant peut tomber en panne sans signe
    préalable : seule une sauvegarde régulière et testée protège les données. Les contrôles de sécurité couvrent la
    configuration du poste et ne remplacent pas un test d'intrusion.</p>
    <p style='margin-top:8px; line-height:140%'><b>Échelle de gravité.</b>
    {_pill('Critique', SEV_COLOR[CRIT])} à traiter immédiatement ·
    {_pill('Majeur', SEV_COLOR[MAJOR])} à planifier rapidement ·
    {_pill('Mineur', SEV_COLOR[MINOR])} amélioration recommandée ·
    {_pill('Information', SEV_COLOR[INFO])} pour mémoire.</p></body></html>""")
    return "".join(h)


# ------------------------------------------------------------------ PDF
def export_pdf(path: str | Path, rec: dict, analysis: Analysis, settings, prev: Analysis | None = None) -> Path:
    from PySide6.QtCore import QMarginsF, QPointF, QRectF, QSizeF, Qt, QUrl
    from PySide6.QtGui import (QColor, QFont, QFontMetricsF, QImage, QPageLayout, QPageSize, QPainter, QPdfWriter,
                               QPen, QTextDocument)

    from .ui.theme import asset_path

    path = Path(path)
    rep = settings.get("report", {}) or {}
    m = analysis.machine
    sc = int(analysis.scores.get("global", 0))
    counts = analysis.counts()
    when = time.strftime("%d/%m/%Y à %H:%M", time.localtime(rec.get("ts") or time.time()))
    day = time.strftime("%d/%m/%Y", time.localtime(rec.get("ts") or time.time()))
    client = rec.get("client") or ""
    site = rec.get("site") or ""

    writer = QPdfWriter(str(path))
    writer.setPageSize(QPageSize(QPageSize.A4))
    writer.setPageMargins(QMarginsF(0, 0, 0, 0), QPageLayout.Millimeter)
    writer.setResolution(300)
    writer.setTitle(f"Diagnostic — {m.get('name')}" + (f" — {client}" if client else ""))
    writer.setCreator(f"{APP_NAME} {APP_VERSION} — {AUTHOR}")
    res = writer.resolution()

    def mm(x: float) -> float:
        return x * res / 25.4

    def pt(x: float) -> int:
        return max(1, round(x * res / 72))

    def font(size_pt: float, weight=QFont.Normal, family="Segoe UI") -> QFont:
        f = QFont(family)
        f.setPixelSize(pt(size_pt))
        f.setWeight(weight)
        return f

    W, H = mm(210), mm(297)

    # logo (personnalisable dans les paramètres)
    logo_path = rep.get("logo") or ""
    if not (logo_path and Path(logo_path).exists()):
        logo_path = str(asset_path("schmock.png"))
    logo = QImage(logo_path)

    def draw_logo(p, x, y, h_mm):
        if logo.isNull():
            return
        hh = mm(h_mm)
        ww = hh * logo.width() / max(1, logo.height())
        p.drawImage(QRectF(x, y, ww, hh), logo)

    def text(p, rect, s, f, color, flags=Qt.AlignLeft | Qt.AlignVCenter):
        p.setFont(f)
        p.setPen(QColor(color))
        p.drawText(rect, flags, s)

    def elide(s, f, width):
        return QFontMetricsF(f).elidedText(s, Qt.ElideRight, width)

    # ---------------------------------------------------------------- contenu
    doc = QTextDocument()
    doc.documentLayout().setPaintDevice(writer)
    doc.setDefaultFont(QFont("Segoe UI", 9))
    doc.setDocumentMargin(0)

    def add_img(img: QImage) -> str:
        name = f"img://{id(img)}"
        doc.addResource(QTextDocument.ImageResource, QUrl(name), img)
        return name

    doc.setHtml(_build_html(rec, analysis, rep, prev, add_img))
    left, right, top, bottom = mm(18), mm(18), mm(24), mm(20)
    body = QSizeF(W - left - right, H - top - bottom)
    doc.setPageSize(body)
    _keep_together(doc, body.height(), mm(35))
    n_pages = 1 + doc.pageCount()

    p = QPainter(writer)
    p.setRenderHint(QPainter.Antialiasing)
    p.setRenderHint(QPainter.TextAntialiasing)
    p.setRenderHint(QPainter.SmoothPixmapTransform)

    # ----------------------------------------------------------- page de garde
    band = mm(128)
    p.fillRect(QRectF(0, 0, W, band), QColor(NAVY))
    p.fillRect(QRectF(0, band, W, mm(1.6)), QColor(ACCENT))
    draw_logo(p, mm(18), mm(18), 7.5)
    f_k = font(9.5, QFont.DemiBold)
    f_k.setLetterSpacing(QFont.AbsoluteSpacing, pt(2.2))
    text(p, QRectF(mm(18), mm(48), mm(170), mm(6)), "RAPPORT DE DIAGNOSTIC", f_k, "#9fb3cf")
    p.fillRect(QRectF(mm(18), mm(56), mm(14), mm(0.9)), QColor(ACCENT))
    f_name = font(30, QFont.Bold)
    text(p, QRectF(mm(18), mm(60), mm(174), mm(16)), elide(str(m.get("name") or "—"), f_name, mm(174)), f_name, "#ffffff")
    f_os = font(11.5)
    text(p, QRectF(mm(18), mm(76), mm(174), mm(8)),
         elide(" · ".join(str(x) for x in (m.get("role"), m.get("os")) if x), f_os, mm(174)), f_os, "#c9d4e3")
    if client or site:
        text(p, QRectF(mm(18), mm(95), mm(174), mm(5)), "CLIENT", font(7.5, QFont.DemiBold), "#7f93b0")
        f_cl = font(16, QFont.DemiBold)
        text(p, QRectF(mm(18), mm(100), mm(174), mm(10)), elide(client or site, f_cl, mm(174)), f_cl, "#ffffff")
        if client and site:
            text(p, QRectF(mm(18), mm(110), mm(174), mm(7)), elide(site, f_os, mm(174)), f_os, "#c9d4e3")

    # note globale
    cy = mm(170)
    _ring(p, mm(52), cy, mm(25), mm(4.2), sc, score_color(sc), pt(38), suffix_px=pt(10))
    x0 = mm(92)
    text(p, QRectF(x0, cy - mm(22), mm(100), mm(6)), "NOTE GLOBALE", f_k, MUTED)
    f_v = font(17, QFont.Bold)
    p.setFont(f_v)
    vr = QRectF(x0, cy - mm(15), mm(100), mm(22))
    text(p, vr, verdict(sc), f_v, score_color(sc), Qt.AlignLeft | Qt.AlignTop | Qt.TextWordWrap)
    lines = QFontMetricsF(f_v).boundingRect(vr, Qt.AlignLeft | Qt.AlignTop | Qt.TextWordWrap, verdict(sc)).height()
    yy = cy - mm(15) + lines + mm(3)
    f_c = font(10)
    xx = x0
    for val, lbl, col in ((counts[CRIT], "critique" if counts[CRIT] <= 1 else "critiques", SEV_COLOR[CRIT]),
                          (counts[MAJOR], "majeur" if counts[MAJOR] <= 1 else "majeurs", SEV_COLOR[MAJOR]),
                          (counts[MINOR], "mineur" if counts[MINOR] <= 1 else "mineurs", SEV_COLOR[MINOR])):
        p.setBrush(QColor(col if val else "#c3cbd6"))
        p.setPen(Qt.NoPen)
        p.drawEllipse(QPointF(xx + mm(1.3), yy + mm(3)), mm(1.3), mm(1.3))
        s = f"{val} {lbl}"
        text(p, QRectF(xx + mm(4), yy, mm(40), mm(6)), s, f_c, INK)
        xx += mm(4) + QFontMetricsF(f_c).horizontalAdvance(s) + mm(6)
    if analysis.risks:
        text(p, QRectF(x0, yy + mm(7), mm(100), mm(6)),
             f"⚠  {_plural(len(analysis.risks), 'risque à venir', 'risques à venir')} à anticiper", f_c, "#8a5a00")

    # notes par domaine
    # notes par domaine : jauge centrée, libellé dessous (3 ou 4 domaines)
    y_d = mm(206)
    p.setPen(QPen(QColor(LINE), mm(0.3)))
    p.drawLine(QPointF(mm(18), y_d - mm(8)), QPointF(mm(192), y_d - mm(8)))
    doms = _domains(analysis)
    dw = mm(174) / max(1, len(doms))
    f_dl = font(9, QFont.DemiBold)
    for i, (d, label) in enumerate(doms):
        s = int(analysis.scores.get(d, 0))
        x = mm(18) + dw * i
        _ring(p, x + dw / 2, y_d + mm(9), mm(8.5), mm(2), s, score_color(s), pt(13))
        text(p, QRectF(x + mm(2), y_d + mm(20), dw - mm(4), mm(10)), label, f_dl, INK, Qt.AlignHCenter | Qt.AlignTop | Qt.TextWordWrap)
    col_w = mm(174) / 3

    # informations
    y_i = mm(248)
    p.setPen(QPen(QColor(LINE), mm(0.3)))
    p.drawLine(QPointF(mm(18), y_i - mm(6)), QPointF(mm(192), y_i - mm(6)))
    auditor = rec.get("auditor") or rep.get("auditor") or ""
    contact = " · ".join(str(x) for x in (rep.get("phone"), rep.get("email")) if x)
    infos = [("DATE DE L'ANALYSE", when), ("INTERVENANT", auditor or rep.get("company") or AUTHOR),
             ("CONTACT", contact or (rep.get("website") or AUTHOR_URL).removeprefix("https://"))]
    f_l = font(7.5, QFont.DemiBold)
    f_val = font(10)
    for i, (k, v) in enumerate(infos):
        x = mm(18) + col_w * i
        text(p, QRectF(x, y_i, col_w - mm(4), mm(5)), k, f_l, "#8a96a6")
        text(p, QRectF(x, y_i + mm(5), col_w - mm(4), mm(7)), elide(str(v), f_val, col_w - mm(4)), f_val, INK)
    if rep.get("company") and auditor:
        text(p, QRectF(mm(18) + col_w, y_i + mm(11), col_w - mm(4), mm(6)), rep["company"], font(9), MUTED)

    # pied de garde
    p.fillRect(QRectF(0, H - mm(16), W, mm(16)), QColor("#f3f5f8"))
    f_f = font(7.5)
    text(p, QRectF(mm(18), H - mm(16), mm(120), mm(16)),
         f"Généré par {APP_NAME} {APP_VERSION} — {AUTHOR} · {AUTHOR_URL.removeprefix('https://')}", f_f, MUTED)
    text(p, QRectF(mm(100), H - mm(16), mm(92), mm(16)), "Document confidentiel destiné au client",
         f_f, MUTED, Qt.AlignRight | Qt.AlignVCenter)

    # ------------------------------------------------------ pages de contenu
    head = " · ".join(str(x) for x in (m.get("name"), client) if x)
    for i in range(doc.pageCount()):
        writer.newPage()
        # en-tête
        draw_logo(p, left, mm(10), 3.6)
        f_h = font(7.5)
        text(p, QRectF(W / 2 - mm(10), mm(9), W / 2 - right + mm(10), mm(6)), elide(f"Rapport de diagnostic · {head}", f_h, W / 2),
             f_h, MUTED, Qt.AlignRight | Qt.AlignVCenter)
        p.setPen(QPen(QColor(LINE), mm(0.25)))
        p.drawLine(QPointF(left, mm(16.5)), QPointF(W - right, mm(16.5)))
        # pied
        p.drawLine(QPointF(left, H - mm(13)), QPointF(W - right, H - mm(13)))
        text(p, QRectF(left, H - mm(12), mm(120), mm(6)), f"{APP_NAME} · {AUTHOR} · analyse du {day}", f_h, "#8a96a6")
        text(p, QRectF(W - right - mm(40), H - mm(12), mm(40), mm(6)), f"Page {i + 2} / {n_pages}", font(7.5, QFont.DemiBold),
             MUTED, Qt.AlignRight | Qt.AlignVCenter)
        # corps
        p.save()
        p.translate(left, top - i * body.height())
        doc.drawContents(p, QRectF(0, i * body.height(), body.width(), body.height()))
        p.restore()
    p.end()
    return path


def export_json(path: str | Path, rec: dict) -> Path:
    """Données brutes + résultat (support, archivage, ré-analyse)."""
    path = Path(path)
    out = {"application": f"{APP_NAME} {APP_VERSION}", "client": rec.get("client"), "site": rec.get("site"),
           "notes": rec.get("notes"), "analysis": rec.get("analysis"), "snapshot": rec.get("snapshot")}
    path.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    return path
