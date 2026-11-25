"""Exécution des collecteurs PowerShell, en parallèle et sans fenêtre.

Windows PowerShell 5.1 reçoit chaque script en mémoire (entrée standard) :
aucun fichier .ps1 écrit dans %TEMP%, pas de contournement de la stratégie
d'exécution, pas de -EncodedCommand.
"""
from __future__ import annotations

import ctypes
import json
import logging
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from . import scripts

log = logging.getLogger(__name__)
CREATE_NO_WINDOW = 0x08000000


def powershell_exe() -> str:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    # processus 32 bits sur Windows 64 bits : passer par Sysnative pour voir le vrai système
    for sub in ("Sysnative", "System32"):
        p = Path(root) / sub / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if p.exists():
            return str(p)
    return "powershell.exe"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """Relance l'application avec élévation (invite UAC). True si lancée."""
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, " ".join(f'"{a}"' for a in sys.argv[1:])
    else:
        exe = sys.executable.replace("python.exe", "pythonw.exe")
        params = " ".join(f'"{a}"' for a in [os.path.abspath(sys.argv[0])] + sys.argv[1:])
    try:
        r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return int(r) > 32
    except Exception:
        log.exception("Élévation impossible")
        return False


@dataclass
class Result:
    name: str
    label: str
    ok: bool = False
    data: dict = field(default_factory=dict)
    error: str = ""
    seconds: float = 0.0

    def to_dict(self) -> dict:
        return {"ok": self.ok, "data": self.data, "error": self.error, "seconds": round(self.seconds, 1)}


def parse_output(txt: str) -> tuple[dict, str, bool]:
    """Lignes « @@{json} » (une section chacune), « @@>nom » (section en cours),
    « @@END ». Renvoie (données, dernière section commencée, fin atteinte)."""
    data: dict = {}
    current, ended = "", False
    for line in txt.splitlines():
        line = line.strip()
        if line == "@@END":
            ended = True
        elif line.startswith("@@>"):
            current = line[3:]
        elif line.startswith("@@{"):
            try:
                data.update(json.loads(line[2:]))
            except json.JSONDecodeError:
                log.warning("Section illisible : %s", line[:120])
    errs = data.get("_errors")
    if errs is not None and not isinstance(errs, list):
        data["_errors"] = [errs]
    return data, current, ended


# Le script est transmis en mémoire par l'entrée standard puis exécuté comme bloc de script :
# aucun fichier écrit sur le disque, et pas de « -ExecutionPolicy Bypass » (la stratégie
# d'exécution ne concerne que les fichiers .ps1). Le contenu reste analysé par l'antivirus (AMSI).
STDIN_RUNNER = "$s = [Console]::In.ReadToEnd(); & ([scriptblock]::Create($s))"


def to_ascii_script(text: str) -> bytes:
    """Retire les lignes de commentaire (seules à contenir des accents) : l'entrée standard de
    PowerShell 5.1 est lue dans la page de code de la console, l'ASCII est sûr partout."""
    lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def run_script(text: str, timeout: int, cancel: threading.Event | None = None) -> tuple[dict | None, str]:
    """Exécute un script et renvoie (objet JSON, erreur)."""
    payload = to_ascii_script(text)
    cmd = [powershell_exe(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", STDIN_RUNNER]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE,
                             creationflags=CREATE_NO_WINDOW)
        t0 = time.monotonic()
        out = err = b""
        stopped = ""
        first = True
        while True:
            try:
                out, err = p.communicate(input=payload if first else None, timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                first = False
                if (cancel and cancel.is_set()) or time.monotonic() - t0 > timeout:
                    p.kill()
                    out, err = p.communicate()      # ce qui a déjà été écrit est conservé
                    stopped = "annulé" if cancel and cancel.is_set() else f"délai dépassé ({timeout} s)"
                    break
        data, current, ended = parse_output(out.decode("utf-8", "replace"))
        if stopped:
            if current and not ended:
                stopped += f" pendant « {current} »"
                data.setdefault("_errors", []).append(f"{current}: {stopped}")
            return (data or None), stopped
        if not data:
            return None, (err.decode("utf-8", "replace") or out.decode("utf-8", "replace") or "aucune donnée").strip()[:800]
        return data, ""
    except OSError as exc:
        return None, f"PowerShell introuvable ou bloqué : {exc}"


def collect(options: dict | None = None, progress=None, cancel: threading.Event | None = None,
            only: list[str] | None = None) -> dict:
    """Lance tous les collecteurs (4 en parallèle). `progress(name, label, state, result)`
    est appelé avec state = "start" puis "done". Renvoie l'instantané complet."""
    o = {"days": 30, "online_updates": True, "network_tests": True, **(options or {})}
    names = only or list(scripts.COLLECTORS)
    results: dict[str, Result] = {}

    def job(name: str):
        label, _body, timeout = scripts.COLLECTORS[name]
        r = Result(name, label)
        if progress:
            progress(name, label, "start", r)
        t0 = time.monotonic()
        text = scripts.build(name, days=o["days"], online_updates=o["online_updates"], network_tests=o["network_tests"])
        data, err = run_script(text, timeout, cancel)
        r.seconds = time.monotonic() - t0
        # ok = données exploitables (éventuellement partielles si le délai a été dépassé)
        r.ok, r.data, r.error = bool(data), data or {}, err
        if err:
            log.warning("Collecte %s : %s", name, err)
        results[name] = r
        if progress:
            progress(name, label, "done", r)

    # les collecteurs longs d'abord
    order = sorted(names, key=lambda n: -scripts.COLLECTORS[n][2])
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="collect") as ex:
        list(ex.map(job, order))
    import platform
    import socket
    return {
        "format": 1,
        "collected_at": time.time(),
        "options": o,
        "admin": is_admin(),
        # identité minimale lue sans PowerShell (repli si la collecte « système » échoue)
        "host": {"name": socket.gethostname(), "platform": platform.platform(),
                 "user": f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}"},
        "sections": {n: results[n].to_dict() for n in names if n in results},
    }
