"""Export all rows from this run's DB into results/run_<ts>.json.

Fresh runner DB starts empty (gitignored), so every row in it is a
find of THIS run. VPS importer picks the files up and dedups by hash.
"""
import json
import os
import sqlite3
import time

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "data", "keys.db")
OUT_DIR = os.path.join(BASE, "results")
os.makedirs(OUT_DIR, exist_ok=True)

conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row
rows = [dict(r) for r in conn.execute(
    "SELECT hash, val, prov, status, plan, price, remaining, found, repo "
    "FROM keys")]
ts = time.strftime("%Y%m%d_%H%M%S")
out = os.path.join(OUT_DIR, f"run_{ts}.json")
with open(out, "w", encoding="utf-8") as f:
    json.dump(rows, f, ensure_ascii=False)
working = sum(1 for r in rows if r["status"] == "WORKING")
print(f"exported {len(rows)} rows ({working} WORKING) -> {out}")
