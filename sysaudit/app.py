"""Point d'entrée de SysAudit Pro."""
from __future__ import annotations

import argparse
import ctypes
import json
import logging
import sys
import threading
import traceback

from .config import APP_NAME, APP_VERSION, Settings, data_dir, setup_logging

log = logging.getLogger("sysaudit")


def _excepthook(t, e, tb):
    log.error("Exception non gérée :\n%s", "".join(traceback.format_exception(t, e, tb)))
    from PySide6.QtWidgets import QApplication, QMessageBox
    if QApplication.instance() and threading.current_thread() is threading.main_thread():
        QMessageBox.warning(None, APP_NAME, f"Erreur inattendue :\n{e}\n\nDétails : {data_dir() / 'sysaudit.log'}")


def cli_collect(out: str, analyse_only: str | None = None) -> int:
    """Mode ligne de commande (sans interface) : collecte + analyse -> JSON."""
    from .analyze.engine import analyze
    from .collect.runner import collect
    snap = json.load(open(analyse_only, encoding="utf-8")) if analyse_only else collect()
    a = analyze(snap)
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"analysis": a.to_dict(), "snapshot": snap}, f, ensure_ascii=False, indent=1)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="SysAuditPro")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--collect", metavar="FICHIER.json", help="analyse sans interface, résultat en JSON")
    args, _rest = ap.parse_known_args(argv)
    setup_logging(args.debug)
    log.info("Démarrage %s %s", APP_NAME, APP_VERSION)
    if args.collect:
        return cli_collect(args.collect)
    sys.excepthook = _excepthook
    threading.excepthook = lambda a: log.error("Exception dans %s", a.thread.name,
                                               exc_info=(a.exc_type, a.exc_value, a.exc_traceback))
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SCHMOCK.SysAuditPro")
    except Exception:
        pass
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont, QIcon
    from PySide6.QtWidgets import QApplication

    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv[:1])
    app.setApplicationName(APP_NAME)
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))
    from .store import Store
    from .ui import theme
    from .ui.context import AppContext
    from .ui.main_window import MainWindow

    settings = Settings()
    theme.apply_theme(settings.get("ui.theme", "dark"))
    app.setWindowIcon(QIcon(theme.app_icon_pixmap(256)))
    store = Store()
    ctx = AppContext(settings, store)
    win = MainWindow(ctx)
    win.show()
    code = app.exec()
    store.close()
    return code
