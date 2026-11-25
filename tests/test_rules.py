"""Tests des règles d'analyse sur des instantanés construits (postes sains
ou défaillants), indépendants du poste qui exécute les tests."""
import copy
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sysaudit.analyze.engine import analyze, score  # noqa: E402
from sysaudit.analyze.eol import os_life, version_lt  # noqa: E402
from sysaudit.analyze.model import CRIT, MAJOR, MINOR, OK, Finding, parse_dt  # noqa: E402

NOW = datetime(2026, 11, 25, 9, 0, tzinfo=timezone.utc)


def iso(days_ago: float = 0) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


def day(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).date().isoformat()


def ev(provider, id_, count=1, level=2, key="", days_ago=1, log="System", props=None, msg="message"):
    return {"log": log, "provider": provider, "id": id_, "level": level, "key": key, "count": count, "first": iso(days_ago),
            "last": iso(days_ago), "days": {day(days_ago): count}, "message": msg, "props": props or []}


def healthy() -> dict:
    """Poste Windows 11 25H2 sain."""
    S = {
        "system": {"os": {"caption": "Microsoft Windows 11 Professionnel", "version": "10.0.26200", "build": 26200, "ubr": 7000,
                          "display_version": "25H2", "edition": "Professional", "product_type": 1, "last_boot": iso(2),
                          "install_date": iso(300), "total_kb": 16 * 1024 * 1024, "system_drive": "C:"},
                   "computer": {"name": "PC-TEST", "domain": "WORKGROUP", "part_of_domain": False, "domain_role": 0,
                                "manufacturer": "Dell Inc.", "model": "OptiPlex 7010", "total_bytes": 16 * 1024 ** 3, "pc_type": 1},
                   "bios": {"manufacturer": "Dell", "version": "1.20", "release": iso(400), "serial": "ABC123"},
                   "cpu": [{"name": "Intel Core i5"}], "cpu_load": [8, 10, 9],
                   "memory_perf": {"committed": 6 * 1024 ** 3, "commit_limit": 20 * 1024 ** 3, "available_mb": 9000, "pool_nonpaged": 300 * 1024 ** 2},
                   "pagefile": [{"name": "C:\\pagefile.sys", "allocated_mb": 4096, "peak_mb": 500}],
                   "processes": {"totals": {}, "top": []}, "pending_reboot": [], "secure_boot": {"enabled": 1, "firmware": 2},
                   "tpm": {"present": True}, "battery": None, "thermal": [], "power_plan": {"id": "381b4222-f694-41f0-9685-ff5bb260df2e"}},
        "disks": {"physical": [{"id": "0", "name": "Samsung SSD 980", "serial": "S1", "media": "SSD", "bus": "NVMe", "size": 512e9,
                                "health": "Healthy", "operational": ["OK"],
                                "reliability": {"wear": 3, "temperature": 38, "read_uncorrected": 0, "write_uncorrected": 0, "power_on_hours": 3000}}],
                  "smart_predict": [], "volumes": [{"letter": "C:", "size": 500e9, "free": 300e9, "dirty": False}],
                  "volume_health": [{"letter": "C", "health": "Healthy"}], "folders": [], "minidumps": []},
        "events": {"system_errors": [], "system_warnings": [], "application_errors": [],
                   "reliability": [{"t": iso(d / 24), "v": 9.5} for d in range(0, 600, 12)],
                   "log_coverage": [{"log": "System", "oldest": iso(200), "max_bytes": 20e6}], "boot_perf": []},
        "updates": {"hotfixes": [{"id": "KB1", "installed": iso(10)}], "history": [], "pending": [], "pending_checked": True,
                    "wu_policy": {}, "wu_services": [{"name": "wuauserv", "start": "Manual", "state": "Running"}]},
        "software": {"services": [], "tasks": [], "startup": [], "software": [], "devices": [], "drivers": []},
        "network": {"adapters": [], "ip": [{"alias": "Ethernet", "ipv4": ["192.168.1.10/24"]}],
                    "connectivity": {"gateway": {"host": "192.168.1.1", "sent": 4, "received": 4, "avg_ms": 1}, "dns_ok": True, "dns_ms": 20},
                    "time_sync": {"offset_s": 0.02, "reference": "time.windows.com"}, "hosts": [], "listening": [], "netbios": []},
        "security": {"defender": {"antivirus": True, "realtime": True, "sig_age": 0, "tamper": True},
                     "av_products": [{"name": "Windows Defender", "state": 397568}],
                     "firewall": [{"name": n, "enabled": "True"} for n in ("Domain", "Private", "Public")], "fw_products": [],
                     "bitlocker": [{"letter": "C:", "protection": 1}],
                     "registry": {"lsa_ppl": 2, "uac_lua": 1, "uac_admin_prompt": 5, "rdp_deny": 1, "llmnr": 0, "autorun": 255,
                                  "inactivity_timeout": 900, "smb1_client_start": 4},
                     "smb_server": {"smb1": False, "signing_required": True},
                     "local_users": [{"name": "Administrateur", "sid": "S-1-5-21-1-500", "enabled": False, "password_required": True},
                                     {"name": "jean", "sid": "S-1-5-21-1-1001", "enabled": True, "password_required": True}],
                     "admins": [{"name": "PC-TEST\\Administrateur", "sid": "S-1-5-21-1-500", "source": "Local"}],
                     "password_policy": {"MinimumPasswordLength": 12, "LockoutBadCount": 10},
                     "shares": [], "certificates": [], "uac_user": {"user": "PC-TEST\\jean"}},
    }
    return {"format": 1, "collected_at": NOW.timestamp(), "admin": True, "options": {"days": 30},
            "sections": {k: {"ok": True, "data": v, "error": ""} for k, v in S.items()}}


def with_(snap, section, key, value):
    s = copy.deepcopy(snap)
    s["sections"][section]["data"][key] = value
    return s


def ids(a, min_sev=MINOR):
    return {f.id for f in a.findings if f.severity >= min_sev}


def find(a, prefix):
    return [f for f in a.findings if f.id.startswith(prefix)]


# ------------------------------------------------------------------ tests
def test_parse_dt_powershell_formats():
    assert parse_dt("2026-11-25T07:21:36.1105935+01:00").hour == 7
    assert parse_dt("2026-09-13T00:00:00.0000000") is not None
    assert parse_dt("n'importe quoi") is None and parse_dt(None) is None


def test_healthy_machine_has_no_major_problem():
    a = analyze(healthy())
    assert not a.rule_errors
    bad = [f.title for f in a.findings if f.severity >= MAJOR]
    assert bad == [], bad
    assert a.scores["global"] >= 85
    assert find(a, "disk.ok")[0].severity == OK


def test_failing_disk_is_critical_and_predictive():
    s = healthy()
    d = s["sections"]["disks"]["data"]["physical"][0]
    d["reliability"].update(wear=93, read_uncorrected=4)
    s["sections"]["events"]["data"]["system_errors"] = [ev("disk", 7, count=12)]
    a = analyze(s)
    crit = [f for f in a.findings if f.severity == CRIT]
    assert {"disk.wear.S1", "disk.uncorrected.S1", "disk.event.7"} <= {f.id for f in crit}
    assert all(f.predictive for f in crit)
    assert not find(a, "disk.ok")
    assert a.scores["hw"] <= 40


def test_blue_screens_and_whea():
    s = healthy()
    s["sections"]["events"]["data"]["system_errors"] = [
        ev("Microsoft-Windows-WER-SystemErrorReporting", 1001, count=3, days_ago=3),
        ev("Microsoft-Windows-WHEA-Logger", 18, count=1)]
    s["sections"]["events"]["data"]["system_warnings"] = [ev("Microsoft-Windows-WHEA-Logger", 19, count=40, level=3)]
    a = analyze(s)
    assert find(a, "stab.bsod")[0].severity == CRIT
    assert find(a, "hw.whea.fatal")[0].severity == CRIT
    assert find(a, "hw.whea.corrected")[0].severity == MAJOR


def test_os_end_of_life():
    assert os_life(19045, 1, "Professional").end.year == 2025
    assert os_life(19044, 1, "EnterpriseS").name == "Windows 10 LTSC 2021"
    assert os_life(14393, 3, None).name == "Windows Server 2016"
    s = healthy()
    s["sections"]["system"]["data"]["os"].update(build=19045, caption="Microsoft Windows 10 Pro", display_version="22H2")
    f = find(analyze(s), "os.support")[0]
    assert f.severity == CRIT and "plus supporté" in f.title
    s["sections"]["system"]["data"]["os"].update(build=14393, product_type=3, caption="Windows Server 2016")
    f = find(analyze(s), "os.support")[0]
    assert f.severity == MAJOR and f.predictive          # fin le 12/01/2027 : moins de 6 mois


def test_updates_age_and_failures():
    s = with_(healthy(), "updates", "hotfixes", [{"id": "KB1", "installed": iso(95)}])
    s["sections"]["events"]["data"]["system_errors"] = [
        ev("Microsoft-Windows-WindowsUpdateClient", 20, count=6, key="2026-11 Mise à jour cumulative (KB5099999)"),
        ev("Microsoft-Windows-WindowsUpdateClient", 20, count=40, key="9N3RK8ZV2ZR8-Microsoft.WidgetsPlatformRuntime")]
    a = analyze(s)
    assert find(a, "wu.age")[0].severity == CRIT
    assert find(a, "wu.failures")[0].severity == MAJOR
    assert "KB5099999" in find(a, "wu.failures")[0].detail
    assert find(a, "wu.store_failures")[0].severity == MINOR    # applis du Store : mineur


def test_disk_space_levels():
    s = with_(healthy(), "disks", "volumes", [{"letter": "C:", "size": 250e9, "free": 6e9},
                                             {"letter": "D:", "size": 1000e9, "free": 120e9}])
    s["sections"]["disks"]["data"]["folders"] = [{"path": "C:\\Windows.old", "bytes": 25e9}]
    a = analyze(s)
    c = find(a, "disk.space.C:")[0]
    assert c.severity == CRIT and "Windows.old" in c.detail
    assert find(a, "disk.space.D:")[0].severity == MINOR


def test_memory_pressure_and_leak():
    s = healthy()
    m = s["sections"]["system"]["data"]
    m["memory_perf"].update(committed=19 * 1024 ** 3, available_mb=500, pool_nonpaged=2 * 1024 ** 3)
    m["processes"]["top"] = [{"name": "chrome", "pid": 4, "private": 1e9, "handles": 60000}]
    s["sections"]["events"]["data"]["system_warnings"] = [ev("Microsoft-Windows-Resource-Exhaustion-Detector", 2004, level=3)]
    a = analyze(s)
    assert find(a, "mem.commit")[0].severity == CRIT
    assert find(a, "mem.pool")[0].predictive
    assert find(a, "mem.leak") and find(a, "mem.exhaustion")


def test_security_critical_settings():
    s = healthy()
    r = s["sections"]["security"]["data"]["registry"]
    r.update(wdigest=1, uac_lua=0, autologon="1", autologon_password_set=True, rdp_deny=0, rdp_nla=0)
    s["sections"]["security"]["data"]["smb_server"] = {"smb1": True, "signing_required": False}
    s["sections"]["security"]["data"]["defender"] = {"antivirus": False, "realtime": False}
    s["sections"]["security"]["data"]["av_products"] = []
    s["sections"]["security"]["data"]["firewall"][2]["enabled"] = "False"
    a = analyze(s)
    crit = {f.id for f in a.findings if f.severity == CRIT}
    assert {"proto.wdigest", "uac.off", "acct.autologon", "proto.smb1", "av.none", "fw.off"} <= crit
    assert find(a, "rdp.nla")[0].severity == MAJOR
    assert a.scores["sec"] <= 40


def test_third_party_antivirus_state_decoding():
    s = healthy()
    s["sections"]["security"]["data"]["defender"] = {"antivirus": False, "realtime": False}
    s["sections"]["security"]["data"]["av_products"] = [{"name": "ESET Security", "state": 0x41000},      # actif, à jour
                                                         {"name": "Windows Defender", "state": 0x60100}]  # désactivé (393472)
    a = analyze(s)
    assert not find(a, "av.none")
    assert "ESET" in find(a, "av.ok")[0].title and "Defender" not in find(a, "av.ok")[0].title
    s["sections"]["security"]["data"]["av_products"] = [{"name": "ESET Security", "state": 0x41010}]  # 266256 : signatures périmées
    assert find(analyze(s), "av.outdated")
    s["sections"]["security"]["data"]["av_products"] = [{"name": "Windows Defender", "state": 397568}]  # 0x61100 : Defender actif
    s["sections"]["security"]["data"]["defender"] = {"antivirus": True, "realtime": True, "sig_age": 0}
    a = analyze(s)
    assert not find(a, "av.outdated") and find(a, "av.ok")


def test_accounts_shares_certificates():
    s = healthy()
    sec = s["sections"]["security"]["data"]
    sec["local_users"].append({"name": "Invité", "sid": "S-1-5-21-1-501", "enabled": True, "password_required": False})
    sec["shares"] = [{"name": "Compta", "path": "D:\\Compta", "access": [{"account": "Tout le monde", "right": "Full", "type": "Allow"}]}]
    sec["certificates"] = [{"subject": "CN=srv.exemple.fr", "issuer": "CN=R3", "not_after": iso(-10), "private_key": True,
                            "thumbprint": "AB", "self_signed": False}]
    sec["password_policy"] = {"MinimumPasswordLength": 6, "LockoutBadCount": 0}
    a = analyze(s)
    assert find(a, "acct.guest")[0].severity == MAJOR
    assert find(a, "share.everyone.Compta")[0].severity == MAJOR
    cert = find(a, "cert.AB")[0]
    assert cert.severity == MAJOR and cert.predictive and "10 jours" in cert.title
    assert find(a, "pwd.length")[0].severity == MAJOR and find(a, "pwd.lockout")


def test_software_end_of_life_and_vulnerable_versions():
    assert version_lt("24.08", "24.09") and not version_lt("24.09", "24.09") and version_lt("7.01.0", "7.13")
    s = with_(healthy(), "software", "software", [
        {"name": "Microsoft Office Professionnel Plus 2016", "version": "16.0.4266"},
        {"name": "7-Zip 23.01 (x64)", "version": "23.01"},
        {"name": "WinRAR 7.20 (64-bit)", "version": "7.20.0"},
        {"name": "AnyDesk", "version": "9.0"}])
    a = analyze(s)
    assert find(a, "soft.eol.Office 2016")[0].severity == MAJOR
    assert find(a, "soft.vuln.7-Zip")
    assert not find(a, "soft.vuln.WinRAR")
    assert find(a, "soft.remote")


def test_trends_are_predictive():
    s = healthy()
    ev_ = s["sections"]["events"]["data"]
    ev_["reliability"] = [{"t": iso(d), "v": 9.8 if d > 7 else 5.0} for d in range(0, 28)]
    ev_["boot_perf"] = [{"date": iso(60 - i), "boot_ms": 30000} for i in range(10)] + \
                       [{"date": iso(5 - i), "boot_ms": 95000} for i in range(5)]
    a = analyze(s)
    assert find(a, "stab.reliability_trend")[0].predictive
    b = find(a, "boot.time")[0]
    assert b.predictive and "hausse" in b.title


def test_server_context():
    s = healthy()
    s["sections"]["system"]["data"]["os"].update(product_type=2, build=20348, caption="Windows Server 2022")
    s["sections"]["system"]["data"]["computer"].update(part_of_domain=True, domain_role=5)
    s["sections"]["security"]["data"]["registry"]["print_spooler"] = "Running"
    s["sections"]["security"]["data"]["smb_server"]["signing_required"] = False
    a = analyze(s)
    assert a.machine["role"] == "Contrôleur de domaine"
    assert find(a, "svc.spooler_dc")[0].severity == MAJOR
    assert find(a, "proto.smb_signing")[0].severity == MAJOR
    assert find(a, "power.server")


def test_missing_sections_do_not_crash():
    s = healthy()
    for k in list(s["sections"]):
        s["sections"][k] = {"ok": False, "data": {}, "error": "délai dépassé"}
    a = analyze(s)
    assert not a.rule_errors
    s = healthy()
    s["sections"]["system"]["data"]["pending_reboot"] = "cbs"          # élément unique « déroulé » par PowerShell
    s["sections"]["security"]["data"]["firewall"] = {"name": "Public", "enabled": "False"}
    a = analyze(s)
    assert not a.rule_errors and find(a, "os.pending_reboot") and find(a, "fw.off")


def test_score_caps():
    mk = lambda sev, n: [Finding(f"x{i}", "hw", sev, "t") for i in range(n)]   # noqa: E731
    assert score([]) == 100
    assert score(mk(CRIT, 1)) == 75
    assert score(mk(MINOR, 30)) == 88                 # les mineurs ne font pas s'effondrer la note
    assert score(mk(CRIT, 5) + mk(MAJOR, 10) + mk(MINOR, 10)) == 0


def test_real_snapshot_if_available():
    """Instantané réel du poste de développement (dev/snapshot_vm.json)."""
    p = Path(__file__).resolve().parents[1] / "dev" / "snapshot_vm.json"
    if not p.exists():
        return
    import json
    a = analyze(json.loads(p.read_text(encoding="utf-8")))
    assert not a.rule_errors
    assert a.machine["is_vm"] and a.findings
