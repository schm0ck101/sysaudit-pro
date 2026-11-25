"""Suivi des constats (plan d'action) : libellés, enregistrement, PDF."""
import sqlite3
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_roles import server  # noqa: E402
from test_rules import NOW  # noqa: E402

from sysaudit import followup as fu  # noqa: E402
from sysaudit.analyze.engine import analyze  # noqa: E402

D = date(2026, 11, 25)      # un mercredi


def test_relative_choices_become_dates():
    assert fu.make("tomorrow", D)["due"] == "2026-11-26"
    assert fu.make("week", D)["due"] == "2026-11-27"            # vendredi
    assert fu.make("week", date(2026, 11, 28))["due"] == "2026-11-29"   # samedi -> dimanche
    assert fu.label(fu.make("tomorrow", D), D) == "Demain"
    assert fu.label(fu.make("tomorrow", D), date(2026, 11, 26)) == "Aujourd'hui"
    assert fu.label(fu.make("tomorrow", D), date(2026, 11, 30)) == "En retard (26/11)"
    assert fu.label(fu.make("week", D), D) == "Prévu le 27/11"
    assert fu.choice_of(fu.make("week", D), D) == ""            # affiché comme date dans le menu
    assert fu.label(fu.make("done", D), D) == "Fait le 25/11"
    assert fu.label(fu.make("later", D), D) == "Plus tard"
    assert fu.label(None) == "À faire" and fu.is_closed(fu.make("skip", D))


def test_store_followup_and_migration(tmp_path):
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)        # base 1.0.9 : pas de colonne followup
    con.executescript("CREATE TABLE analyses (id INTEGER PRIMARY KEY, client_id INTEGER, site TEXT, notes TEXT, auditor TEXT,"
                      " machine TEXT, machine_key TEXT, role TEXT, os TEXT, ts REAL, score INTEGER, scores TEXT, counts TEXT,"
                      " analysis TEXT, snapshot BLOB);")
    con.close()
    from sysaudit.store import Store
    st = Store(db)
    a = analyze(server())
    aid = st.save(client="C", site="", notes="", auditor="", analysis=a, snapshot={"collected_at": NOW.timestamp()})
    assert st.get(aid)["followup"] == {}
    st.set_followup(aid, "x", fu.make("done", D, note="ok"))
    st.set_followup(aid, "y", fu.make("tomorrow", D))
    st.set_followup(aid, "y", None)
    assert set(st.get(aid)["followup"]) == {"x"}
    st.close()


def test_pdf_with_followup(tmp_path):
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication(["t"])  # noqa: F841
    from sysaudit import report
    from sysaudit.config import Settings
    a = analyze(server())
    probs = a.problems
    assert probs
    rec = {"client": "X", "ts": NOW.timestamp(), "followup": {probs[0].id: fu.make("done", D, note="fait sur place")}}
    out = report.export_pdf(tmp_path / "r.pdf", rec, a, Settings())
    assert out.stat().st_size > 10000
