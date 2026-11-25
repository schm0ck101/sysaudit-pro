"""Tests des contrôles approfondis : contrôleur de domaine, rôles serveur,
sauvegardes, sécurité avancée, stockage (instantanés construits)."""
import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_rules import NOW, ev, find, healthy, ids, iso  # noqa: E402

from sysaudit.analyze.engine import analyze  # noqa: E402
from sysaudit.analyze.model import CRIT, INFO, MAJOR, MINOR, NOT_CHECKED, OK  # noqa: E402

DN = "DC=cecof,DC=local"


def server(dc: bool = False) -> dict:
    s = healthy()
    d = s["sections"]
    d["system"]["data"]["os"].update(caption="Microsoft Windows Server 2019 Standard", version="10.0.17763", build=17763,
                                     product_type=2 if dc else 3)
    d["system"]["data"]["computer"].update(name="SRV-AD2", domain="cecof.local", part_of_domain=True, domain_role=5 if dc else 3,
                                           manufacturer="Dell Inc.", model="PowerEdge R640")
    d["system"]["data"]["ram_slots"] = {"slots": 8, "ecc": 6}
    d["network"]["data"]["ip"] = [{"alias": "Ethernet", "ipv4": ["10.0.0.11/24"], "gateway": ["10.0.0.1"], "dns": ["10.0.0.10", "127.0.0.1"]}]
    d["network"]["data"]["time_sync"] = {"type": "NT5DS", "offset_s": 0.01}
    d["roles"] = {"ok": True, "error": "", "data": {"role_services": [], "ad": None, "ad_repl": [], "sql": []}}
    d["backup"] = {"ok": True, "error": "", "data": {"wsb": None, "veeam": [], "backup_services": [], "shadows": []}}
    if dc:
        d["roles"]["data"].update(
            role_services=[{"name": n, "state": "Running", "start": "Auto"} for n in ("NTDS", "DNS", "Netlogon", "Kdc", "DFSR", "W32Time")],
            ad={"domain": "cecof.local", "domain_mode": "Windows2016Domain", "forest_mode": "Windows2016Forest",
                "pdc": "SRV-AD1.cecof.local", "rid": "SRV-AD1.cecof.local", "this": "SRV-AD2.cecof.local",
                "dcs": [{"name": "SRV-AD1.cecof.local", "os": "Windows Server 2019 Standard", "ip": "10.0.0.10"},
                        {"name": "SRV-AD2.cecof.local", "os": "Windows Server 2016 Standard", "ip": "10.0.0.11"}],
                "recycle_bin": True, "last_backup": iso(1), "tombstone_days": 180, "ds_errors": [],
                "pwd_policy": {"min_length": 12, "lockout": 10, "reversible": False}},
            ad_repl=[{"partner": f"CN=NTDS Settings,CN=SRV-AD1,CN=Servers,CN=Default,CN=Sites,CN=Configuration,{DN}", "partition": DN,
                      "last_success": iso(0.1), "result": 0, "failures": 0}],
            ad_accounts={"users": 50, "enabled": 40, "inactive_count": 0, "inactive": [], "krbtgt_pwd": iso(30),
                         "domain_admins": ["admin1", "admin2"], "schema_admins": [], "computers": 30, "laps_count": 30, "old_os_count": 0},
            sysvol={"dfsr_state": 3, "frs_state": None, "sysvol_share": True, "netlogon_share": True, "dfsr_errors": []})
        d["backup"]["data"]["wsb"] = {"policy": True, "last_success": iso(0.5), "last_result": 0, "versions": 20}
    return s


def test_healthy_dc_has_no_major_problem():
    a = analyze(server(dc=True))
    assert not a.rule_errors, a.rule_errors
    bad = [f.title for f in a.findings if f.severity >= MAJOR]
    assert bad == [], bad
    assert "svc" in a.scores and a.scores["svc"] >= 90
    assert find(a, "dc.repl.ok") and find(a, "dc.backup.ok") and find(a, "bk.wsb.ok")


def test_dc_problems_detected():
    s = server(dc=True)
    r = s["sections"]["roles"]["data"]
    r["ad"].update(dcs=r["ad"]["dcs"][1:], last_backup=iso(200), recycle_bin=False,
                   pwd_policy={"min_length": 7, "lockout": 0, "reversible": False})
    r["ad_repl"][0].update(failures=12, result=1722, last_success=iso(9))
    r["ad_accounts"].update(inactive_count=3, inactive=["a", "b", "c"], preauth=["svc_old"], krbtgt_pwd=iso(2000),
                            domain_admins=[f"adm{i}" for i in range(12)], laps_count=0, old_os_count=2, old_os=["PC1 (Windows 7)"])
    r["sysvol"].update(frs_state="Running", dfsr_state=None)
    s["sections"]["network"]["data"]["ip"][0]["dns"] = ["8.8.8.8"]
    a = analyze(s)
    assert not a.rule_errors, a.rule_errors
    got = ids(a)
    for fid in ("dc.single", "dc.repl", "dc.backup", "dc.recycle", "dc.frs", "dc.dns_external", "pwd.length", "pwd.lockout",
                "ad.inactive_users", "ad.asrep", "ad.krbtgt", "ad.domain_admins", "ad.laps", "ad.old_os"):
        assert fid in got, fid
    assert find(a, "dc.backup")[0].severity == CRIT          # au-delà de la durée de vie des objets supprimés
    assert find(a, "dc.repl")[0].severity == CRIT
    assert find(a, "ad.domain_admins")[0].severity == MAJOR


def test_pdc_time_source():
    s = server(dc=True)
    s["sections"]["roles"]["data"]["ad"]["this"] = "SRV-AD1.cecof.local"
    a = analyze(s)
    assert "dc.pdc_time" in ids(a)


def test_server_without_backup():
    s = server()
    a = analyze(s)
    assert find(a, "bk.none")[0].severity == MAJOR
    s["sections"]["system"]["data"]["computer"]["manufacturer"] = "QEMU"     # VM : peut-être sauvegardée par l'hyperviseur
    assert find(analyze(s), "bk.none")[0].severity == MINOR


def test_backup_age_and_veeam():
    s = server()
    s["sections"]["backup"]["data"]["wsb"] = {"policy": True, "last_success": iso(10), "last_result": 0, "versions": 3}
    s["sections"]["backup"]["data"]["veeam"] = [{"level": 4, "date": iso(5), "message": "Success"},
                                                {"level": 2, "date": iso(1), "message": "Failed"}]
    a = analyze(s)
    assert find(a, "bk.wsb.age")[0].severity == CRIT
    assert "bk.veeam.failed" in ids(a) and find(a, "bk.veeam.age")[0].severity == MAJOR
    assert "bk.none" not in ids(a, INFO)


def test_shadow_copies_on_shared_volumes():
    s = server()
    s["sections"]["backup"]["data"]["wsb"] = {"policy": True, "last_success": iso(0.5), "last_result": 0}
    s["sections"]["security"]["data"]["shares"] = [{"name": "Commun", "path": "D:\\Commun", "access": []}]
    assert "bk.shadows" in ids(analyze(s))
    s["sections"]["backup"]["data"]["shadows"] = [{"volume": "D:", "count": 12, "newest": iso(0.3)}]
    assert "bk.shadows" not in ids(analyze(s))


def test_hyperv_sql_dhcp():
    s = server()
    r = s["sections"]["roles"]["data"]
    r["hyperv"] = {"vms": [{"name": "VM-ERP", "state": "Running", "heartbeat": "OkApplicationsHealthy", "checkpoints": 2, "oldest_cp": iso(45)}],
                   "vhds": [{"vm": "VM-ERP", "path": "D:\\VM\\erp.vhdx", "type": "Dynamic", "file": 100 * 1024 ** 3, "max": 900 * 1024 ** 3}]}
    s["sections"]["disks"]["data"]["volumes"].append({"letter": "D:", "size": 1e12, "free": 200 * 1024 ** 3})
    r["sql"] = [{"instance": "SQLEXPRESS", "edition": "Express Edition", "version": "13.0.5026.0",
                 "mdf": [{"name": "GESTION.mdf", "bytes": int(9.7 * 1024 ** 3)}], "ldf": []}]
    r["dhcp"] = {"scopes": [{"id": "10.0.0.0", "name": "LAN", "state": "Active", "pct": 97.0, "in_use": 240, "free": 6, "lease_h": 192}],
                 "authorized": True}
    a = analyze(s)
    assert not a.rule_errors, a.rule_errors
    assert find(a, "hv.checkpoints")[0].severity == MAJOR
    assert "hv.overcommit.D:" in ids(a)
    assert find(a, "sql.express_limit.SQLEXPRESS.GESTION.mdf")[0].severity == CRIT
    assert "sql.eol.SQLEXPRESS" in ids(a)                       # SQL Server 2016 : fin de support le 14/07/2026
    assert find(a, "dhcp.full.10.0.0.0")[0].severity == MAJOR


def test_security_extras():
    s = healthy()
    sec = s["sections"]["security"]["data"]
    sec["mp_prefs"] = {"excl_path": ["C:\\", "D:\\Logiciel\\data"], "excl_proc": ["powershell.exe"], "excl_ext": [], "pua": 0}
    sec["auditpol"] = {"0CCE9215-69AE-11D9-BED3-505054503030": 1, "0CCE9235-69AE-11D9-BED3-505054503030": 0}
    sec["psv2"] = "Enabled"
    s["sections"]["software"]["data"]["tasks"] = [{"name": "Upd", "path": "\\", "user": "SYSTEM", "exe": "C:\\Users\\Public\\upd.exe"}]
    a = analyze(s)
    assert not a.rule_errors, a.rule_errors
    for fid in ("av.exclusions_risky", "av.pua", "audit.policy", "ps.v2", "persist.writable"):
        assert fid in ids(a), fid
    # exclusions illisibles sans droits administrateur : aucun constat
    sec["mp_prefs"] = {"excl_path": ["N/A: Must be an administrator to view exclusions"], "pua": 2}
    assert "av.exclusions_risky" not in ids(analyze(s), INFO)


def test_storage_spaces_and_raid():
    s = server()
    d = s["sections"]["disks"]["data"]
    d["virtual_disks"] = [{"name": "Donnees", "health": "Warning", "operational": ["Degraded"], "resiliency": "Mirror"}]
    s["sections"]["events"]["data"]["system_errors"] = [ev("megasas", 129, count=4, msg="Controller encountered a fatal error")]
    s["sections"]["system"]["data"]["ram_slots"]["ecc"] = 3
    a = analyze(s)
    assert find(a, "disk.vdisk.Donnees")[0].severity == CRIT
    assert find(a, "hw.raid_events")[0].severity == MAJOR
    assert "hw.no_ecc" in ids(a)


def test_old_analysis_without_new_domain_still_renders(tmp_path):
    """Une analyse enregistrée avant l'ajout du domaine « Rôles et sauvegardes » reste exportable."""
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication(["t"])  # noqa: F841
    from sysaudit import report
    from sysaudit.config import Settings
    a = analyze(healthy())
    a.scores.pop("svc", None)
    out = report.export_pdf(tmp_path / "r.pdf", {"client": "X", "ts": NOW.timestamp()}, a, Settings())
    assert out.stat().st_size > 10000
