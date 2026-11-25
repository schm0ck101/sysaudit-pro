"""Robustesse : valeurs vides (None) un peu partout, comme sur certains
portables (cartes Wi-Fi/virtuelles sans passerelle ni DNS, noms absents)."""
import copy
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from test_rules import healthy  # noqa: E402
from sysaudit.analyze.model import MINOR  # noqa: E402

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


def test_streamed_output_keeps_partial_sections():
    from sysaudit.collect.runner import parse_output
    out = ('@@{"is_admin":true}\n@@>os\n@@{"os":{"build":26100}}\n@@>computer\n@@{"computer":{"name":"PC-1"}}\n'
           '@@>processes\n')                       # tué pendant « processes »
    data, current, ended = parse_output(out)
    assert data["os"]["build"] == 26100 and data["computer"]["name"] == "PC-1"
    assert current == "processes" and not ended
    data, _c, ended = parse_output(out + '@@{"_errors":"x: y"}\n@@END\n')
    assert ended and data["_errors"] == ["x: y"]


def test_missing_system_section_never_says_windows10():
    from sysaudit.analyze.model import NOT_CHECKED
    s = copy.deepcopy(healthy())
    s["sections"]["system"] = {"ok": False, "data": {}, "error": "délai dépassé (90 s)"}
    s["host"] = {"name": "PC-AURA", "platform": "Windows-11"}
    a = analyze(s)
    assert not [f for f in a.findings if f.id == "os.support"]
    assert any(f.id == "nc.os" and f.severity == NOT_CHECKED for f in a.findings)
    assert any(f.id == "nc.collect.system" for f in a.findings)
    assert a.machine["name"] == "PC-AURA"


def test_apipa_only_on_real_connected_adapters():
    s = copy.deepcopy(healthy())
    n = s["sections"]["network"]["data"]
    n["adapters"] = [{"name": "Wi-Fi", "status": "Up", "description": "Intel Wi-Fi 6E"},
                     {"name": "Connexion réseau Bluetooth", "status": "Up", "description": "Bluetooth Device (PAN)"},
                     {"name": "Ethernet 2", "status": "Disconnected", "description": "Realtek USB GbE"},
                     {"name": "Ethernet", "status": "Up", "description": "Intel Ethernet I219"}]
    n["ip"] = [{"alias": "Wi-Fi", "ipv4": ["10.1.1.3/24"]},
               {"alias": "Connexion réseau Bluetooth", "ipv4": ["169.254.49.208/16"]},
               {"alias": "Ethernet 2", "ipv4": ["169.254.209.179/16"]},
               {"alias": "Ethernet", "ipv4": ["169.254.1.2/16"]}]
    a = analyze(s)
    ap = [f for f in a.findings if f.id.startswith("net.apipa")]
    assert [f.id for f in ap] == ["net.apipa.Ethernet"] and ap[0].severity == MINOR


def test_user_snapshot_regression():
    """Instantané réel envoyé par l'utilisateur (si présent en local, non versionné)."""
    import json
    p = Path(__file__).resolve().parents[1] / "dev" / "snapshot_portable_wipn.json"
    if not p.exists():
        return
    a = analyze(json.loads(p.read_text(encoding="utf-8"))["snapshot"])
    titles = " ".join(f.title for f in a.findings)
    assert "Windows 10" not in titles and not a.rule_errors
