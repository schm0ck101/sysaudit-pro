"""Exécution des collecteurs PowerShell, en parallèle et sans fenêtre.

Les scripts sont écrits dans un fichier .ps1 temporaire (pas de
-EncodedCommand, souvent signalé par les antivirus) puis lancés avec
Windows PowerShell 5.1 (`-NoProfile -ExecutionPolicy Bypass`).
"""
from __future__ import annotations

import ctypes
import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid
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


def run_script(text: str, timeout: int, cancel: threading.Event | None = None) -> tuple[dict | None, str]:
    """Exécute un script et renvoie (objet JSON, erreur)."""
    tmp = Path(tempfile.gettempdir()) / "SysAuditPro"
    tmp.mkdir(exist_ok=True)
    f = tmp / f"c_{uuid.uuid4().hex}.ps1"
    # BOM UTF-8 : indispensable pour que PowerShell 5.1 lise les accents du script
    f.write_text(text, encoding="utf-8-sig")
    cmd = [powershell_exe(), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(f)]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                             creationflags=CREATE_NO_WINDOW)
        t0 = time.monotonic()
        out = err = b""
        while True:
            try:
                out, err = p.communicate(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                if (cancel and cancel.is_set()) or time.monotonic() - t0 > timeout:
                    p.kill()
                    p.communicate()
                    return None, "annulé" if cancel and cancel.is_set() else f"délai dépassé ({timeout} s)"
        txt = out.decode("utf-8", "replace").strip()
        start = txt.find("{")
        if start < 0:
            return None, (err.decode("utf-8", "replace") or txt or "aucune donnée").strip()[:800]
        try:
            return json.loads(txt[start:]), ""
        except json.JSONDecodeError as exc:
            return None, f"réponse illisible : {exc}"
    except OSError as exc:
        return None, f"PowerShell introuvable ou bloqué : {exc}"
    finally:
        try:
            f.unlink()
        except OSError:
            pass


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
        r.ok, r.data, r.error = data is not None, data or {}, err
        if err:
            log.warning("Collecte %s : %s", name, err)
        results[name] = r
        if progress:
            progress(name, label, "done", r)

    # les collecteurs longs d'abord
    order = sorted(names, key=lambda n: -scripts.COLLECTORS[n][2])
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="collect") as ex:
        list(ex.map(job, order))
    return {
        "format": 1,
        "collected_at": time.time(),
        "options": o,
        "admin": is_admin(),
        "sections": {n: results[n].to_dict() for n in names if n in results},
    }
