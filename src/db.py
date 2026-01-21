# src/db.py
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

# Store DB in a local folder so it is easy to find and screenshot
DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
DB_PATH = DATA_DIR / "app.db"


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                totp_secret TEXT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
            );
            """
        )
        conn.commit()


@contextmanager
def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
