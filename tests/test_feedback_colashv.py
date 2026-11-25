"""Retours du terrain (serveur COLASHV, Server 2016 + Veeam B&R, 25/11/2026)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_roles import server  # noqa: E402
from test_rules import ev, find, ids, iso  # noqa: E402

from sysaudit.analyze.engine import analyze, global_score  # noqa: E402
from sysaudit.analyze.model import CRIT, MAJOR, MINOR, Finding  # noqa: E402
from sysaudit.analyze.rules_svc import _backup_products  # noqa: E402


def test_global_score_is_not_a_sum_of_all_penalties():
    """2 critiques + 7 majeurs répartis sur 4 domaines donnaient 8/100."""
    fs = [Finding("a", "sec", CRIT, "x"), Finding("b", "svc", CRIT, "x"), Finding("c", "hw", MAJOR, "x"), Finding("d", "sys", MINOR, "x")]
    sc = global_score(fs, {"hw": 86, "sys": 84, "sec": 33, "svc": 65})
    assert sc == 49                      # plafonné à « préoccupant » à cause des critiques, mais pas 8
    assert global_score([Finding("c", "hw", MAJOR, "x")], {"hw": 80, "sys": 100, "sec": 100, "svc": 100}) == 80
    assert global_score([Finding("c", "hw", MAJOR, "x"), Finding("e", "sys", MINOR, "x")],
                        {"hw": 92, "sys": 98, "sec": 100, "svc": 100}) == 84
    assert global_score([], {"hw": 100}) == 100


def test_unexpected_shutdown_not_double_counted():
    s = server()
    s["sections"]["events"]["data"]["system_errors"] = [ev("Microsoft-Windows-Kernel-Power", 41, count=5),
                                                         ev("EventLog", 6008, count=5)]
    f = find(analyze(s), "stab.unexpected_shutdown")[0]
    assert "5 sur 30 jours" in f.title and "du serveur" in f.title
    assert "Dates :" in f.detail


def test_veeam_warning_counts_as_backup_and_single_error_is_minor():
    s = server()
    b = s["sections"]["backup"]["data"]
    b["veeam"] = [{"level": 4, "date": iso(22), "message": "Job A finished with Success"},
                  {"level": 3, "date": iso(0.5), "message": "Job A finished with Warning"}]
    s["sections"]["events"]["data"]["application_errors"] = [ev("Veeam Data Analyzer Service", 0, count=1, level=2, log="Application")]
    a = analyze(s)
    assert find(a, "bk.veeam.ok")
    assert "bk.veeam.age" not in ids(a)
    assert find(a, "bk.errors")[0].severity == MINOR


def test_backup_products_grouped():
    names = {"AWS Plug-In for Veeam Backup & Replication", "Kasten Plug-In for Veeam Backup & Replication",
             "Veeam Backup & Replication", "Veeam Backup Server RESTful API Service", "Acronis Cyber Protect 15 (x64)"}
    assert _backup_products(names) == ["Veeam Backup & Replication", "Acronis Cyber Protect 15"]
