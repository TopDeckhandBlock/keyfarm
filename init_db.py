"""Create empty keys DB schema (fresh runner starts with no DB)."""
import os
import sqlite3

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "data", "keys.db")
os.makedirs(os.path.dirname(DB), exist_ok=True)

conn = sqlite3.connect(DB)
conn.execute("""
CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT UNIQUE,
    val TEXT,
    prov TEXT,
    status TEXT DEFAULT 'NEW',
    plan TEXT,
    price TEXT,
    remaining TEXT,
    found TEXT,
    repo TEXT
)""")
conn.commit()
n = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
print(f"init_db: {DB} ready, rows={n}")
