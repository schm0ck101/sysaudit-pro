# -*- mode: python ; coding: utf-8 -*-
# Spécification PyInstaller : application fenêtrée (sans console).
# SYSAUDIT_ONEFILE=1 : version portable en un seul fichier (build.ps1).
import os

# Modules inutiles : exclus pour alléger l'exécutable (seuls QtCore/QtGui/QtWidgets servent)
excludes = [
    "tkinter", "matplotlib", "scipy", "pandas", "numpy", "IPython", "pytest", "PIL", "pyqtgraph",
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick", "PySide6.QtWebChannel",
    "PySide6.QtWebSockets", "PySide6.QtQuick", "PySide6.QtQuick3D", "PySide6.QtQuickWidgets", "PySide6.QtQml",
    "PySide6.Qt3DCore", "PySide6.Qt3DRender", "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets", "PySide6.QtCharts",
    "PySide6.QtDataVisualization", "PySide6.QtGraphs", "PySide6.QtPdf", "PySide6.QtPdfWidgets", "PySide6.QtBluetooth",
    "PySide6.QtNfc", "PySide6.QtPositioning", "PySide6.QtLocation", "PySide6.QtSensors", "PySide6.QtSerialPort",
    "PySide6.QtSql", "PySide6.QtTest", "PySide6.QtDesigner", "PySide6.QtHelp", "PySide6.QtOpenGL", "PySide6.QtOpenGLWidgets",
    "PySide6.QtRemoteObjects", "PySide6.QtScxml", "PySide6.QtSpatialAudio", "PySide6.QtTextToSpeech",
    "PySide6.QtHttpServer", "PySide6.QtNetworkAuth", "PySide6.QtVirtualKeyboard", "PySide6.QtNetwork", "PySide6.QtSvg",
]

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[("assets/SysAuditPro.ico", "assets"), ("assets/schmock.png", "assets")],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=1,
)

DROP = ("opengl32sw.dll", "qt6quick", "qt6qml", "qt6virtualkeyboard", "qt6pdf", "qt6network", "qt6opengl",
        "qdirect2d", "qtiff", "qwebp", "qicns", "qtga", "qwbmp", "qpdf", "qsvg", "qt6svg")


def _keep(entry):
    name = entry[0].replace("\\", "/").lower()
    base = name.rsplit("/", 1)[-1]
    if any(base.startswith(d) or base == d for d in DROP):
        return False
    if "/translations/" in name and not base.endswith("_fr.qm"):
        return False
    return True


a.binaries = [b for b in a.binaries if _keep(b)]
a.datas = [d for d in a.datas if _keep(d)]
pyz = PYZ(a.pure)

ONEFILE = os.environ.get("SYSAUDIT_ONEFILE") == "1"
common = dict(debug=False, strip=False, upx=False, console=False,
              icon="assets/SysAuditPro.ico", version="tools/version_info.txt")
if ONEFILE:
    exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="SysAuditPro-Portable", runtime_tmpdir=None, **common)
else:
    exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="SysAuditPro", **common)
    coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="SysAuditPro")
