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


# Auth-gated probe paths. Some providers expose /models publicly (OpenRouter,
# Novita) — probing those returns 200 even for a garbage key. So we probe an
# endpoint that REQUIRES a valid key, and treat 200 as alive.
AUTH_PROBE = {
    # provider: (base, path, header_fn, parser)
    'deepseek':   ('https://api.deepseek.com', '/user/balance', lambda k: {'Authorization': f'Bearer {k}'}),
    'dashscope':  ('https://dashscope.aliyuncs.com/compatible-mode/v1', '/models', lambda k: {'Authorization': f'Bearer {k}'}),
    'moonshot':   ('https://api.moonshot.cn/v1', '/users/me/balance', lambda k: {'Authorization': f'Bearer {k}'}),
    'openai':     ('https://api.openai.com/v1', '/models', lambda k: {'Authorization': f'Bearer {k}'}),
    'openrouter': ('https://openrouter.ai/api/v1', '/key', lambda k: {'Authorization': f'Bearer {k}'}),
    'groq':       ('https://api.groq.com/openai/v1', '/models', lambda k: {'Authorization': f'Bearer {k}'}),
    'zai':        ('https://api.z.ai/api/paas/v4', '/models', lambda k: {'Authorization': f'Bearer {k}'}),
    'mistral':    ('https://api.mistral.ai/v1', '/models', lambda k: {'Authorization': f'Bearer {k}'}),
    'together':   ('https://api.together.xyz/v1', '/models', lambda k: {'Authorization': f'Bearer {k}'}),
    'fireworks':  ('https://api.fireworks.ai/v1', '/models', lambda k: {'Authorization': f'Bearer {k}'}),
    'anthropic':  ('https://api.anthropic.com/v1', '/models', lambda k: {'x-api-key': k, 'anthropic-version': '2023-06-01'}),
    'siliconflow':('https://api.siliconflow.cn/v1', '/models', lambda k: {'Authorization': f'Bearer {k}'}),
    # novita removed: /models is public (200 for any key) — no auth-gated free endpoint
}

# Providers whose /models is PUBLIC — must use an auth-gated path instead.
PUBLIC_MODELS = {'openrouter', 'novita'}  # never trust their /models


def _parse_models(d):
    data = d.get('data') or d.get('models') or []
    return [m.get('id') or m.get('name', '') for m in data[:12]] if isinstance(data, list) else []


def probe(key, timeout=12):
    """Return providers where the key is ALIVE, using auth-gated endpoints only."""
    alive = []
    for name, (base, path, hdr_fn) in AUTH_PROBE.items():
        st, body = _get(base + path, hdr_fn(key), timeout)
        if st != 200:
            continue
        try:
            d = json.loads(body)
        except Exception:
            continue
        info = {'provider': name, 'models': []}
        if name == 'openrouter':
            data = d.get('data', {})
            lim, usage = data.get('limit'), data.get('usage', 0)
            info['balance'] = 'unlimited free-tier' if lim is None else f'${max(0, lim - usage):.2f}/${lim}'
            info['models'] = [data.get('label', 'router')]
        elif name == 'deepseek':
            b = (d.get('balance_infos') or [{}])[0]
            info['balance'] = f"${b.get('total_balance', '?')}"
            info['models'] = ['deepseek-chat', 'deepseek-reasoner']
        elif name == 'moonshot':
            info['balance'] = f"¥{d.get('data', {}).get('balance', '?')}"
        else:
            info['models'] = _parse_models(d)
        alive.append(info)
    return alive


# ── Non-/models probes (different auth shapes) ─────────────────────────────
SPECIAL_PROBES = [
    # (provider, url_template with {key}, header_fn, ok_check)
    ('telegram_bot', 'https://api.telegram.org/bot{key}/getMe', lambda: {}, lambda st, d: st == 200 and d.get('ok')),
    ('huggingface', 'https://huggingface.co/api/whoami-v2', lambda k: {'Authorization': f'Bearer {k}'}, lambda st, d: st == 200),
    ('github_pat', 'https://api.github.com/user', lambda k: {'Authorization': f'token {k}', 'User-Agent': 'kf'}, lambda st, d: st == 200),
    ('npm', 'https://registry.npmjs.org/-/user/org.couchdb.user:me', lambda k: {'Authorization': f'Bearer {k}'}, lambda st, d: st == 200),
    ('slack', 'https://slack.com/api/auth.test', lambda k: {'Authorization': f'Bearer {k}'}, lambda st, d: st == 200 and d.get('ok')),
    ('replicate', 'https://api.replicate.com/v1/account', lambda k: {'Authorization': f'Token {k}'}, lambda st, d: st == 200),
    ('gemini', 'https://generativelanguage.googleapis.com/v1beta/models?key=' + chr(123) + 'key' + chr(125), lambda: {}, lambda st, d: st == 200),
]


def probe_special(key):
    """Probe providers that don't use the OpenAI-style /models endpoint."""
    alive = []
    for name, url_t, hdr_fn, ok in SPECIAL_PROBES:
        try:
            url = url_t.replace('{key}', key)
            h = dict(UA)
            h.update(hdr_fn(key) if hdr_fn.__code__.co_argcount else hdr_fn())
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=10) as r:
                st = r.status
                try:
                    d = json.loads(r.read())
                except Exception:
                    d = {}
            if ok(st, d):
                info = {'provider': name}
                if name == 'telegram_bot' and d.get('result'):
                    info['models'] = ['@' + d['result'].get('username', '?')]
                if name == 'github_pat' and d.get('login'):
                    info['models'] = [d['login']]
                if name == 'replicate' and d.get('username'):
                    info['models'] = [d['username']]
                alive.append(info)
        except Exception:
            continue
    return alive


def probe_all(key):
    """Full classification: /models endpoints + special probes."""
    return probe(key) + probe_special(key)

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
