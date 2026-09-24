#!/usr/bin/env python3
"""UNIVERSAL KEY CLASSIFIER — probes unknown sk-*/key-like tokens against
every known provider's cheapest endpoint to identify what they actually are.

Problem it solves: DeepSeek / DashScope / Kimi / many relays share the sk-<hex>
shape. A regex cannot tell them apart — only a live probe can. This module
takes a candidate key and returns which provider(s) it is ALIVE on + models.

Used as a second validation pass for keys whose DB provider came back DEAD —
often the key was misclassified and is alive on another endpoint.

Run standalone:  python universal_validator.py keys.txt
"""
import concurrent.futures as cf
import json
import sys
import urllib.error
import urllib.request

UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

# (provider, base_url, header_fn, probe_path)
ENDPOINTS = [
    ('deepseek',   'https://api.deepseek.com',                          lambda k: {'Authorization': f'Bearer {k}'}, '/models'),
    ('dashscope',  'https://dashscope.aliyuncs.com/compatible-mode/v1', lambda k: {'Authorization': f'Bearer {k}'}, '/models'),
    ('moonshot',   'https://api.moonshot.cn/v1',                        lambda k: {'Authorization': f'Bearer {k}'}, '/models'),
    ('openai',     'https://api.openai.com/v1',                         lambda k: {'Authorization': f'Bearer {k}'}, '/models'),
    ('openrouter', 'https://openrouter.ai/api/v1',                      lambda k: {'Authorization': f'Bearer {k}'}, '/models'),
    ('groq',       'https://api.groq.com/openai/v1',                    lambda k: {'Authorization': f'Bearer {k}'}, '/models'),
    ('zai',        'https://api.z.ai/api/paas/v4',                      lambda k: {'Authorization': f'Bearer {k}'}, '/models'),
    ('mistral',    'https://api.mistral.ai/v1',                         lambda k: {'Authorization': f'Bearer {k}'}, '/models'),
    ('together',   'https://api.together.xyz/v1',                       lambda k: {'Authorization': f'Bearer {k}'}, '/models'),
    ('fireworks',  'https://api.fireworks.ai/v1',                       lambda k: {'Authorization': f'Bearer {k}'}, '/models'),
    ('anthropic',  'https://api.anthropic.com/v1',                      lambda k: {'x-api-key': k, 'anthropic-version': '2023-06-01'}, '/models'),
    ('siliconflow','https://api.siliconflow.cn/v1',                     lambda k: {'Authorization': f'Bearer {k}'}, '/models'),
    ('novita',     'https://api.novita.ai/v3/openai',                   lambda k: {'Authorization': f'Bearer {k}'}, '/models'),
]


def _get(url, headers, timeout=12):
    h = dict(UA)
    h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:400]
    except Exception:
        return -1, b''


def probe(key, timeout=12):
    """Return list of providers where the key is ALIVE, with model samples."""
    alive = []
    for name, base, hdr_fn, path in ENDPOINTS:
        st, body = _get(base + path, hdr_fn(key), timeout)
        if st == 200:
            models = []
            try:
                d = json.loads(body)
                data = d.get('data') or d.get('models') or []
                models = [m.get('id') or m.get('name', '') for m in data[:12]]
            except Exception:
                pass
            alive.append({'provider': name, 'models': models})
    return alive


def probe_many(keys, workers=20):
    out = {}
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe, k): k for k in keys}
        for f in cf.as_completed(futs):
            k = futs[f]
            try:
                r = f.result()
            except Exception:
                r = []
            out[k] = r
    return out


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'keys.txt'
    keys = [l.strip() for l in open(path, encoding='utf-8') if l.strip() and not l.startswith('#')]
    print(f'probing {len(keys)} keys against {len(ENDPOINTS)} providers...')
    res = probe_many(keys)
    alive_n = 0
    for k, providers in res.items():
        if providers:
            alive_n += 1
            for p in providers:
                print(f"ALIVE {k[:16]}... -> {p['provider']}: {', '.join(p['models'][:6])}")
    print(f'\ntotal alive: {alive_n}/{len(keys)}')
