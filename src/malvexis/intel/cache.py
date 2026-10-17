"""Tiny SQLite cache so repeat hashes don't burn API quota."""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path


class Cache:
    def __init__(self, directory: Path, ttl: int = 24 * 3600):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl
        self._db = sqlite3.connect(str(directory / "cache.sqlite3"))
        self._db.execute("CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, value TEXT NOT NULL, ts REAL NOT NULL)")
        self._db.commit()

    def get(self, key: str) -> dict | None:
        row = self._db.execute("SELECT value, ts FROM cache WHERE key = ?", (key,)).fetchone()
        if not row:
            return None
        value, ts = row
        if time.time() - ts > self.ttl:
            self._db.execute("DELETE FROM cache WHERE key = ?", (key,))
            self._db.commit()
            return None
        return json.loads(value)

    def set(self, key: str, value: dict) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO cache (key, value, ts) VALUES (?, ?, ?)",
            (key, json.dumps(value), time.time()),
        )
        self._db.commit()

    def close(self) -> None:
        self._db.close()
