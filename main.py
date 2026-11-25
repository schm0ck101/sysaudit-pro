"""Lanceur de SysAudit Pro (utilisé aussi par PyInstaller)."""
import sys

from sysaudit.app import main

if __name__ == "__main__":
    sys.exit(main())
