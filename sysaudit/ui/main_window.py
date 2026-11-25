"""Fenêtre principale : barre latérale et pages."""
from __future__ import annotations

from PySide6.QtCore import QSize, Qt, QUrl
from PySide6.QtGui import QDesktopServices, QIcon
from PySide6.QtWidgets import (QButtonGroup, QFrame, QHBoxLayout, QLabel, QMainWindow, QPushButton, QStackedWidget,
                               QVBoxLayout, QWidget)

from ..collect.runner import is_admin
from ..config import APP_NAME, APP_VERSION, AUTHOR, AUTHOR_URL
from . import theme
from .analyse_page import AnalysePage
from .history_page import HistoryPage
from .inventory_page import InventoryPage
from .results_page import ResultsPage
from .settings_page import SettingsPage


class MainWindow(QMainWindow):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.setWindowTitle(APP_NAME + ("" if is_admin() else " (sans droits administrateur)"))
        self.setWindowIcon(QIcon(theme.app_icon_pixmap(256)))
        self.resize(1400, 900)
        self.setMinimumSize(1100, 700)
        central = QWidget()
        central.setObjectName("Central")
        self.setCentralWidget(central)
        lay = QHBoxLayout(central)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        side = QFrame()
        side.setObjectName("Sidebar")
        side.setFixedWidth(228)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(12, 16, 12, 14)
        sl.setSpacing(3)
        head = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(theme.app_icon_pixmap(76).scaled(38, 38, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        head.addWidget(logo)
        hb = QVBoxLayout()
        hb.setSpacing(0)
        t = QLabel(APP_NAME)
        t.setObjectName("AppTitle")
        st = QLabel(f"Diagnostic de postes · v{APP_VERSION}")
        st.setObjectName("AppSubtitle")
        hb.addWidget(t)
        hb.addWidget(st)
        head.addLayout(hb, 1)
        sl.addLayout(head)
        sl.addSpacing(16)

        self.stack = QStackedWidget()
        self.analyse = AnalysePage(ctx)
        self.results = ResultsPage(ctx)
        self.inventory = InventoryPage(ctx)
        self.history = HistoryPage(ctx)
        self.settings_page = SettingsPage(ctx)
        self.pages = [(theme.G_SCAN, "Analyse", self.analyse), (theme.G_RESULTS, "Résultats", self.results),
                      (theme.G_INVENTORY, "Inventaire", self.inventory), (theme.G_HISTORY, "Historique", self.history),
                      (theme.G_SETTINGS, "Paramètres", self.settings_page)]
        self.nav = QButtonGroup(self)
        self.buttons = []
        for i, (glyph, label, page) in enumerate(self.pages):
            b = QPushButton(f"  {label}")
            b.setObjectName("NavButton")
            b.setCheckable(True)
            b.setIconSize(QSize(18, 18))
            b.setProperty("glyph", glyph)
            b.setCursor(Qt.PointingHandCursor)
            self.nav.addButton(b, i)
            self.buttons.append(b)
            sl.addWidget(b)
            self.stack.addWidget(page)
        self.nav.idClicked.connect(self.show_page)
        sl.addStretch(1)
        self.cur_lbl = QLabel("")
        self.cur_lbl.setObjectName("Muted")
        self.cur_lbl.setWordWrap(True)
        sl.addWidget(self.cur_lbl)
        self.theme_btn = QPushButton()
        self.theme_btn.setObjectName("NavButton")
        self.theme_btn.clicked.connect(self.toggle_theme)
        sl.addWidget(self.theme_btn)
        brand = QLabel()
        brand.setAlignment(Qt.AlignCenter)
        pm = theme.brand_pixmap(16)
        if pm.isNull():
            brand.setText(f"Créé par {AUTHOR}")
        else:
            brand.setPixmap(pm)
        brand.setToolTip(f"{APP_NAME} — créé par {AUTHOR} · {AUTHOR_URL}")
        brand.setCursor(Qt.PointingHandCursor)
        brand.mousePressEvent = lambda e: QDesktopServices.openUrl(QUrl(AUTHOR_URL))
        brand.setContentsMargins(0, 6, 0, 2)
        sl.addWidget(brand)
        lay.addWidget(side)
        lay.addWidget(self.stack, 1)

        self.analyse.done.connect(lambda aid: (ctx.open(aid), self.show_page(1)))
        self.history.opened.connect(lambda _aid: self.show_page(1))
        self.settings_page.applied.connect(self.apply_settings)
        ctx.current_changed.connect(self.update_current)
        self.apply_icons()
        self.update_current()
        self.show_page(0)

    def show_page(self, i: int):
        self.buttons[i].setChecked(True)
        self.stack.setCurrentIndex(i)

    def update_current(self):
        a = self.ctx.analysis
        self.cur_lbl.setText(f"Analyse ouverte :<br><b>{a.machine.get('name')}</b> — {a.scores.get('global')} / 100" if a else "")

    def apply_icons(self):
        p = theme.palette()
        for b in self.buttons:
            b.setIcon(theme.glyph_icon(b.property("glyph"), p.text))
        dark = p.name == "dark"
        self.theme_btn.setIcon(theme.glyph_icon("" if dark else "", p.text))
        self.theme_btn.setText("  Mode clair" if dark else "  Mode sombre")

    def toggle_theme(self):
        s = self.ctx.settings
        s.set("ui.theme", "light" if theme.palette().name == "dark" else "dark")
        s.save()
        self.apply_settings()

    def apply_settings(self):
        theme.apply_theme(self.ctx.settings.get("ui.theme", "dark"))
        self.apply_icons()
        for _g, _l, page in self.pages:
            if hasattr(page, "apply_theme"):
                page.apply_theme()
