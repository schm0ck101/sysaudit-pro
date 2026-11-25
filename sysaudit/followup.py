"""Suivi des constats : chaque ligne du plan d'action reçoit un état (fait,
prévu aujourd'hui / demain / cette semaine, plus tard, non retenu) et un
commentaire. Enregistré avec l'analyse ; repris dans le PDF.

Un choix relatif (« Demain ») est stocké comme une DATE : rouvert trois jours
plus tard, il s'affiche « Prévu le 26/11 » ou « En retard ».
"""
from __future__ import annotations

from datetime import date, timedelta

# (code, libellé du menu)
CHOICES = [("todo", "À faire"), ("today", "Aujourd'hui"), ("tomorrow", "Demain"), ("week", "Cette semaine"),
           ("later", "Plus tard"), ("done", "Fait"), ("skip", "Non retenu")]

DONE_COLOR, LATE_COLOR, PLANNED_COLOR, SKIP_COLOR = "#2b8a3e", "#c92a2a", "#1c6dd0", "#868e96"


def make(choice: str, today: date | None = None, note: str = "") -> dict:
    """Entrée de suivi pour un choix du menu."""
    today = today or date.today()
    due = None
    status = choice
    if choice in ("today", "tomorrow", "week"):
        status = "planned"
        wd = today.weekday()
        due = today + timedelta(days={"today": 0, "tomorrow": 1}.get(choice, 4 - wd if wd <= 4 else 6 - wd))
    elif choice == "later":
        status = "planned"
    return {"status": status, "due": due.isoformat() if due else None, "note": note,
            "done_on": today.isoformat() if status == "done" else None}


def _d(iso: str | None) -> date | None:
    try:
        return date.fromisoformat(iso) if iso else None
    except ValueError:
        return None


def label(fu: dict | None, today: date | None = None) -> str:
    """Libellé lisible : « Fait le 25/11 », « Demain », « Prévu le 28/11 », « En retard (24/11) »…"""
    if not fu or fu.get("status") in (None, "todo"):
        return "À faire"
    today = today or date.today()
    st = fu["status"]
    if st == "done":
        d = _d(fu.get("done_on"))
        return f"Fait le {d:%d/%m}" if d else "Fait"
    if st == "skip":
        return "Non retenu"
    due = _d(fu.get("due"))
    if not due:
        return "Plus tard"
    if due < today:
        return f"En retard ({due:%d/%m})"
    if due == today:
        return "Aujourd'hui"
    if due == today + timedelta(days=1):
        return "Demain"
    return f"Prévu le {due:%d/%m}"


def color(fu: dict | None, today: date | None = None) -> str | None:
    if not fu:
        return None
    st = fu.get("status")
    if st == "done":
        return DONE_COLOR
    if st == "skip":
        return SKIP_COLOR
    if st == "planned":
        due = _d(fu.get("due"))
        return LATE_COLOR if due and due < (today or date.today()) else PLANNED_COLOR
    return None


def choice_of(fu: dict | None, today: date | None = None) -> str:
    """Entrée du menu correspondant à l'état enregistré ("" si c'est une date sans entrée équivalente)."""
    if not fu or fu.get("status") in (None, "todo"):
        return "todo"
    st = fu["status"]
    if st in ("done", "skip"):
        return st
    due = _d(fu.get("due"))
    if not due:
        return "later"
    today = today or date.today()
    if due == today:
        return "today"
    if due == today + timedelta(days=1):
        return "tomorrow"
    return ""


def is_closed(fu: dict | None) -> bool:
    return bool(fu) and fu.get("status") in ("done", "skip")
