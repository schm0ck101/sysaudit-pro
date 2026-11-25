"""Historique des analyses (SQLite) : clients, postes, analyses.

L'instantané brut (données collectées) est conservé compressé : il permet de
ré-analyser une ancienne collecte avec des règles plus récentes et de
produire un export pour le support.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import zlib
from pathlib import Path

from .config import data_dir

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, created REAL);
CREATE TABLE IF NOT EXISTS analyses (
  id INTEGER PRIMARY KEY,
  client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL,
  site TEXT, notes TEXT, auditor TEXT,
  machine TEXT, machine_key TEXT, role TEXT, os TEXT,
  ts REAL, score INTEGER, scores TEXT, counts TEXT,
  analysis TEXT, snapshot BLOB
);
CREATE INDEX IF NOT EXISTS ix_an_key ON analyses(machine_key, ts);
"""


class Store:
    def __init__(self, path: Path | None = None):
        self.path = path or data_dir() / "sysaudit.db"
        self._lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)
        self.db.commit()

    def close(self):
        with self._lock:
            self.db.close()

    # ------------------------------------------------------------ clients
    def clients(self) -> list[str]:
        with self._lock:
            return [r[0] for r in self.db.execute("SELECT name FROM clients ORDER BY name COLLATE NOCASE")]

    def client_id(self, name: str) -> int | None:
        name = (name or "").strip()
        if not name:
            return None
        with self._lock:
            r = self.db.execute("SELECT id FROM clients WHERE name=?", (name,)).fetchone()
            if r:
                return r[0]
            cur = self.db.execute("INSERT INTO clients(name, created) VALUES(?,?)", (name, time.time()))
            self.db.commit()
            return cur.lastrowid

    # ----------------------------------------------------------- analyses
    def save(self, *, client: str, site: str, notes: str, auditor: str, analysis, snapshot: dict) -> int:
        m = analysis.machine
        counts = {str(k): v for k, v in analysis.counts().items()}
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO analyses(client_id, site, notes, auditor, machine, machine_key, role, os, ts, score, scores, counts, analysis, snapshot)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (self.client_id(client), site, notes, auditor, m.get("name"), m.get("key"), m.get("role"), m.get("os"),
                 snapshot.get("collected_at") or time.time(), analysis.scores.get("global"), json.dumps(analysis.scores),
                 json.dumps(counts), json.dumps(analysis.to_dict(), ensure_ascii=False),
                 zlib.compress(json.dumps(snapshot, ensure_ascii=False).encode("utf-8"), 6)))
            self.db.commit()
            return cur.lastrowid

    def update_meta(self, aid: int, *, client: str, site: str, notes: str):
        with self._lock:
            self.db.execute("UPDATE analyses SET client_id=?, site=?, notes=? WHERE id=?", (self.client_id(client), site, notes, aid))
            self.db.commit()

    def update_analysis(self, aid: int, analysis):
        with self._lock:
            self.db.execute("UPDATE analyses SET score=?, scores=?, counts=?, analysis=? WHERE id=?",
                            (analysis.scores.get("global"), json.dumps(analysis.scores),
                             json.dumps({str(k): v for k, v in analysis.counts().items()}),
                             json.dumps(analysis.to_dict(), ensure_ascii=False), aid))
            self.db.commit()

    def list(self, client: str | None = None, search: str = "") -> list[dict]:
        q = ("SELECT a.id, a.ts, a.machine, a.role, a.os, a.score, a.counts, a.site, a.notes, a.machine_key, c.name AS client "
             "FROM analyses a LEFT JOIN clients c ON c.id = a.client_id")
        args, where = [], []
        if client:
            where.append("c.name = ?")
            args.append(client)
        if search:
            where.append("(a.machine LIKE ? OR c.name LIKE ? OR a.site LIKE ? OR a.notes LIKE ?)")
            args += [f"%{search}%"] * 4
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " ORDER BY a.ts DESC"
        with self._lock:
            out = []
            for r in self.db.execute(q, args):
                d = dict(r)
                d["counts"] = json.loads(d["counts"] or "{}")
                out.append(d)
            return out

    def get(self, aid: int) -> dict | None:
        with self._lock:
            r = self.db.execute("SELECT a.*, c.name AS client FROM analyses a LEFT JOIN clients c ON c.id = a.client_id WHERE a.id=?",
                                (aid,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["analysis"] = json.loads(d["analysis"])
        d["scores"] = json.loads(d["scores"] or "{}")
        d["snapshot"] = json.loads(zlib.decompress(d["snapshot"]).decode("utf-8")) if d["snapshot"] else {}
        return d

    def previous(self, machine_key: str, before_ts: float) -> dict | None:
        with self._lock:
            r = self.db.execute("SELECT id FROM analyses WHERE machine_key=? AND ts<? ORDER BY ts DESC LIMIT 1",
                                (machine_key, before_ts)).fetchone()
        return self.get(r[0]) if r else None

    def delete(self, aid: int):
        with self._lock:
            self.db.execute("DELETE FROM analyses WHERE id=?", (aid,))
            self.db.commit()
