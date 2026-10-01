"""SQLite storage for private participant records and certificate mappings."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path


APP_DIR = Path(__file__).resolve().parent


def data_dir() -> Path:
    return Path(os.environ.get("PORTAL_DATA_DIR", str(APP_DIR / ".private"))).expanduser()


def database_path() -> Path:
    configured = os.environ.get("PORTAL_DB_PATH", "").strip()
    return Path(configured).expanduser() if configured else data_dir() / "portal.sqlite3"


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    target = Path(path).expanduser() if path else database_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(target), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS participants (
            id TEXT PRIMARY KEY,
            source_row INTEGER NOT NULL,
            name TEXT NOT NULL,
            email_norm TEXT,
            cert1_url TEXT,
            cert2_url TEXT,
            cert1_token TEXT,
            cert2_token TEXT,
            cert1_token_hash TEXT,
            cert2_token_hash TEXT
        );
        CREATE INDEX IF NOT EXISTS participant_email_idx ON participants(email_norm);
        CREATE INDEX IF NOT EXISTS cert1_token_idx ON participants(cert1_token_hash);
        CREATE INDEX IF NOT EXISTS cert2_token_idx ON participants(cert2_token_hash);
        """
    )
    return connection
