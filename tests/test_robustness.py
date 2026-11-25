"""Robustesse : valeurs vides (None) un peu partout, comme sur certains
portables (cartes Wi-Fi/virtuelles sans passerelle ni DNS, noms absents)."""
import copy
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from test_rules import healthy  # noqa: E402

from sysaudit.analyze.engine import analyze  # noqa: E402


def noisy_snapshot():
    s = copy.deepcopy(healthy())
    d = lambda k: s["sections"][k]["data"]  # noqa: E731
    d("network")["adapters"] = [{"name": "Wi-Fi", "description": None, "status": "Up", "speed": None, "stats": None},
                                {"name": None, "status": "Disconnected"}]
    d("network")["ip"] = [{"alias": "Wi-Fi", "ipv4": [None, "10.0.0.5/24"], "gateway": [None], "dns": [None, "1.1.1.1"]},
                          {"alias": None, "ipv4": None, "gateway": None, "dns": None}]
    d("disks")["physical"].append({"id": None, "name": None, "serial": None, "media": None, "size": None, "health": None,
                                   "operational": [None], "reliability": None})
    d("security")["certificates"] = [{"subject": None, "not_after": "2026-12-01T00:00:00", "private_key": True, "eku": [None]}]
    d("security")["av_products"] = [{"name": None, "state": 0x41010}]
    d("security")["fw_products"] = [{"name": None}]
    d("system")["pending_reboot"] = [None, "cbs"]
    d("system")["gpu"] = [{"name": None, "driver": None, "driver_date": None}]
    d("system")["ram_modules"] = [{"capacity": None, "speed": None, "manufacturer": None, "part": None, "slot": None}]
    d("software")["software"] = [{"name": None, "version": None}, {"name": "7-Zip", "version": None}]
    d("software")["services"] = [{"name": None, "display": None, "start": "Auto", "state": "Stopped", "path": None}]
    d("software")["tasks"] = [{"name": None, "last_result": 1, "last_run": "2026-11-20T00:00:00", "state": None}]
    return s


def test_rules_tolerate_none():
    a = analyze(noisy_snapshot())
    assert a.rule_errors == [], a.rule_errors


def test_ui_and_pdf_tolerate_none(tmp_path):
    os.environ["SYSAUDIT_DATA_DIR"] = str(tmp_path)
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from sysaudit import report
    from sysaudit.config import Settings
    from sysaudit.store import Store
    from sysaudit.ui.context import AppContext
    from sysaudit.ui.main_window import MainWindow
    snap = noisy_snapshot()
    st = Store(tmp_path / "t.db")
    ctx = AppContext(Settings(tmp_path / "s.json"), st)
    win = MainWindow(ctx)
    aid = st.save(client="", site="", notes="", auditor="", analysis=analyze(snap), snapshot=snap)
    ctx.open(aid)                      # charge Résultats + Inventaire
    for i in range(5):
        win.show_page(i)
    win.results.f_kind.setCurrentIndex(2)
    for r in range(win.results.table.rowCount()):
        win.results.table.selectRow(r)
    report.export_pdf(tmp_path / "r.pdf", ctx.rec, ctx.analysis, ctx.settings, ctx.prev)
    win.close()
    st.close()
