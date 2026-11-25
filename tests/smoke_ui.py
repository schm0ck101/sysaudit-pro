"""Test de bout en bout de l'interface : VRAIE analyse du poste courant,
captures de chaque page (thèmes sombre et clair), rapport PDF et export JSON.
Usage : python tests/smoke_ui.py <dossier de sortie>"""
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = Path(sys.argv[1])
OUT.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("SYSAUDIT_DATA_DIR", str(OUT / "data"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402
from PySide6.QtGui import QFont  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from sysaudit import report  # noqa: E402
from sysaudit.config import Settings  # noqa: E402
from sysaudit.store import Store  # noqa: E402
from sysaudit.ui import theme  # noqa: E402
from sysaudit.ui.context import AppContext  # noqa: E402
from sysaudit.ui.main_window import MainWindow  # noqa: E402

app = QApplication([])
app.setStyle("Fusion")
app.setFont(QFont("Segoe UI", 10))
settings = Settings()
theme.apply_theme("dark")
store = Store()
ctx = AppContext(settings, store)
win = MainWindow(ctx)
win.resize(1500, 950)
win.show()


def wait(ms):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def shot(name):
    wait(300)
    win.grab().save(str(OUT / f"{name}.png"))


shot("01_analyse")
win.analyse.client.setCurrentText("Client Test")
win.analyse.site.setText("Bureau principal")
win.analyse.notes.setText("Test de recette")
win.analyse.opt_updates.setChecked(False)
win.analyse._admin_asked = True      # pas de proposition d'élévation (boîte modale) pendant le test
done = []
win.analyse.done.connect(lambda aid: done.append(aid))
t0 = time.time()
win.analyse.start()
wait(4000)
shot("02_analyse_en_cours")
while not done and time.time() - t0 < 400:
    wait(500)
print("analyse terminée en", round(time.time() - t0), "s, id", done)
assert done, "analyse non terminée"
shot("03_resultats")
a = ctx.analysis
print("notes", a.scores, "constats", len(a.findings), "erreurs de règles", a.rule_errors)
win.results.f_kind.setCurrentIndex(2)
shot("04_resultats_tous")
win.show_page(2)
shot("05_inventaire")
win.inventory.tabs.setCurrentIndex(3)
shot("06_inventaire_logiciels")
win.show_page(3)
shot("07_historique")
win.show_page(4)
shot("08_parametres")
settings.set("ui.theme", "light")
win.apply_settings()
win.show_page(1)
win.results.f_kind.setCurrentIndex(0)
shot("09_resultats_clair")
win.show_page(0)
shot("10_analyse_clair")
report.export_pdf(OUT / "rapport.pdf", ctx.rec, ctx.analysis, settings, ctx.prev)
report.export_json(OUT / "donnees.json", ctx.rec)
# seconde analyse du même poste -> comparaison avec la précédente
done.clear()
win.analyse.start()
t0 = time.time()
while not done and time.time() - t0 < 400:
    wait(500)
print("2e analyse : précédente trouvée =", ctx.prev is not None)
report.export_pdf(OUT / "rapport2.pdf", ctx.rec, ctx.analysis, settings, ctx.prev)
win.close()
store.close()
print("OK")
