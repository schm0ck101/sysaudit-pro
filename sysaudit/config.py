"""Configuration persistante et emplacement des données.

Version portable : les données (historique des clients, paramètres) sont
enregistrées À CÔTÉ de l'exécutable, dans « SysAuditPro-Donnees », pour
voyager avec la clé USB d'intervention. Si le dossier n'est pas accessible
en écriture (CD, dossier protégé), repli sur %APPDATA%\\SysAuditPro.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import sys
import threading
from pathlib import Path

APP_NAME = "SysAudit Pro"
APP_VERSION = "1.0.3"
AUTHOR = "SCHMOCK"
AUTHOR_URL = "https://schmock.fr"
log = logging.getLogger(__name__)
_DATA: Path | None = None


def _writable(p: Path) -> bool:
    try:
        p.mkdir(parents=True, exist_ok=True)
        t = p / ".write_test"
        t.write_text("ok", encoding="utf-8")
        t.unlink()
        return True
    except OSError:
        return False


def is_portable() -> bool:
    return getattr(sys, "frozen", False) and "portable" in Path(sys.executable).stem.lower()


def data_dir() -> Path:
    global _DATA
    if _DATA:
        return _DATA
    env = os.environ.get("SYSAUDIT_DATA_DIR")
    if env:
        p = Path(env)
    else:
        p = None
        if is_portable():
            cand = Path(sys.executable).resolve().parent / "SysAuditPro-Donnees"
            if _writable(cand):
                p = cand
        if p is None:
            p = Path(os.environ.get("APPDATA", str(Path.home()))) / "SysAuditPro"
    p.mkdir(parents=True, exist_ok=True)
    _DATA = p
    return p


DEFAULTS: dict = {
    "analysis": {"days": 30, "online_updates": True, "network_tests": True},
    "report": {"company": AUTHOR, "auditor": "", "logo": "", "phone": "", "email": "", "website": AUTHOR_URL,
               "include_ok": True, "include_inventory": True},
    "ui": {"theme": "dark"},
    "last": {"client": "", "site": ""},
}


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        out[k] = _merge(out[k], v) if isinstance(out.get(k), dict) and isinstance(v, dict) else v
    return out


class Settings:
    def __init__(self, path: Path | None = None):
        self.path = path or data_dir() / "settings.json"
        self._lock = threading.RLock()
        self._d = copy.deepcopy(DEFAULTS)
        try:
            if self.path.exists():
                self._d = _merge(DEFAULTS, json.loads(self.path.read_text(encoding="utf-8")))
        except Exception as exc:
            log.warning("Paramètres illisibles (%s), valeurs par défaut", exc)

    def get(self, key: str, default=None):
        with self._lock:
            node = self._d
            for part in key.split("."):
                if not isinstance(node, dict) or part not in node:
                    return default
                node = node[part]
            return copy.deepcopy(node)

    def set(self, key: str, value) -> None:
        with self._lock:
            node = self._d
            parts = key.split(".")
            for p in parts[:-1]:
                node = node.setdefault(p, {})
            node[parts[-1]] = value

    def save(self) -> None:
        with self._lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._d, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self.path)


def setup_logging(debug: bool = False) -> None:
    import logging.handlers
    root = logging.getLogger()
    if any(isinstance(h, logging.handlers.RotatingFileHandler) for h in root.handlers):
        return
    root.setLevel(logging.DEBUG if debug else logging.INFO)
    fh = logging.handlers.RotatingFileHandler(data_dir() / "sysaudit.log", maxBytes=2_000_000, backupCount=2, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(threadName)s %(name)s : %(message)s"))
    root.addHandler(fh)
