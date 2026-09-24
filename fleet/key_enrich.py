#!/usr/bin/env python3
"""KEY ENRICHER — live balance + model list per provider.

Called by key_poster before posting: queries the provider API directly.
"""
import json
import urllib.error
import urllib.request


UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36'}


def _get(url, headers=None, timeout=15):
    h = dict(UA)
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except Exception:
        return -1, {}


def enrich_deepseek(key):
    st, d = _get('https://api.deepseek.com/user/balance',
                 {'Authorization': f'Bearer {key}'})
    out = {'alive': st == 200}
    if st == 200 and d.get('balance_infos'):
        b = d['balance_infos'][0]
        out['balance'] = f"${b.get('total_balance', '?')} ({b.get('currency','')})"
    st2, m = _get('https://api.deepseek.com/models', {'Authorization': f'Bearer {key}'})
    if st2 == 200 and m.get('data'):
        out['models'] = ', '.join(x.get('id', '') for x in m['data'][:8])
    return out


def enrich_openrouter(key):
    out = {'alive': False}
    st, d = _get('https://openrouter.ai/api/v1/key', {'Authorization': f'Bearer {key}'})
    if st == 200 and d.get('data'):
        out['alive'] = True
        data = d['data']
        lim = data.get('limit')
        usage = data.get('usage', 0)
        if lim is None:
            out['balance'] = f"unlimited (used ${usage})"
        else:
            out['balance'] = f"${max(0, lim - usage):.2f} / ${lim}"
        out['models'] = data.get('label') or 'all models (router)'
    return out


def enrich_replicate(key):
    out = {'alive': False}
    st, d = _get('https://api.replicate.com/v1/account',
                 {'Authorization': f'Token {key}'})
    if st == 200 and d:
        out['alive'] = True
        out['models'] = f"acc={d.get('username', '?')} type={d.get('type', '?')} — все модели Replicate"
    return out


def enrich_dashscope(key):
    out = {'alive': False}
    st, d = _get('https://dashscope.aliyuncs.com/compatible-mode/v1/models',
                 {'Authorization': f'Bearer {key}'})
    if st == 200 and d.get('data'):
        out['alive'] = True
        out['models'] = ', '.join(x.get('id', '') for x in d['data'][:8])
    return out


def enrich_moonshot(key):
    out = {'alive': False}
    st, d = _get('https://api.moonshot.cn/v1/users/me/balance',
                 {'Authorization': f'Bearer {key}'})
    if st == 200 and d.get('data'):
        out['alive'] = True
        out['balance'] = f"¥{d['data'].get('balance', '?')}"
    return out


def enrich_zai(key):
    out = {'alive': False}
    st, d = _get('https://api.z.ai/api/biz/subscription/list',
                 {'Authorization': f'Bearer {key}'})
    if st == 200:
        out['alive'] = True
        try:
            subs = d.get('data', {}).get('subscription_list', [])
            if subs:
                out['balance'] = f"{subs[0].get('resource_package_name','?')} quota={subs[0].get('remaining_quota','?')}"
        except Exception:
            pass
    return out


def enrich_groq(key):
    out = {'alive': False}
    st, d = _get('https://api.groq.com/openai/v1/models',
                 {'Authorization': f'Bearer {key}'})
    if st == 200 and d.get('data'):
        out['alive'] = True
        out['models'] = ', '.join(x.get('id', '') for x in d['data'][:8])
    return out


def enrich_tavily(key):
    out = {'alive': False}
    req = urllib.request.Request(
        'https://api.tavily.com/usage',
        data=json.dumps({'api_key': key}).encode(),
        headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read())
            out['alive'] = True
            out['balance'] = f"credits left: {d.get('credits_left', '?')}"
    except Exception:
        pass
    return out


def enrich_twocaptcha(key):
    out = {'alive': False}
    st, d = _get(f'https://api.2captcha.com/res.php?key={key}&action=getbalance&json=1')
    if st == 200 and d.get('status') == 1:
        out['alive'] = True
        out['balance'] = f"${d.get('request', d.get('balance', '?'))}"
    return out


def enrich_anticaptcha(key):
    out = {'alive': False}
    req = urllib.request.Request('https://api.anti-captcha.com/getBalance',
                                 data=json.dumps({'clientKey': key}).encode(),
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read())
            if d.get('balance') is not None:
                out['alive'] = True
                out['balance'] = f"${d['balance']}"
    except Exception:
        pass
    return out



def enrich_gemini(key):
    out = {'alive': False}
    st, d = _get('https://generativelanguage.googleapis.com/v1beta/models?key=' + key)
    if st == 200 and d.get('models'):
        out['alive'] = True
        names = [m.get('name','').replace('models/','') for m in d['models'][:8]]
        out['models'] = ', '.join(names)
    return out


def enrich_relay(key):
    """sk-proj-/sk-ant-/sk-cp- relays: OpenAI-compat /v1/models probe."""
    out = {'alive': False}
    for base in ('https://api.openai.com', 'https://api.anthropic.com'):
        st, d = _get(base + '/v1/models', {'Authorization': f'Bearer {key}'})
        if st == 200 and d.get('data'):
            out['alive'] = True
            out['models'] = ', '.join(x.get('id','') for x in d['data'][:8])
            break
    if not out['alive'] and key.startswith('sk-ant'):
        st, d = _get('https://api.anthropic.com/v1/messages',
                     {'Authorization': f'Bearer {key}', 'anthropic-version': '2023-06-01'})
        if st != 401:
            out['alive'] = True
            out['models'] = 'anthropic relay (claude)'
    return out


ENRICHERS = {
    'DEEPSEEK': enrich_deepseek,
    'OPENROUTER': enrich_openrouter,
    'REPLICATE': enrich_replicate,
    'DASHSCOPE': enrich_dashscope,
    'KIMI': enrich_moonshot,
    'MOONSHOT': enrich_moonshot,
    'ZAI': enrich_zai,
    'GROQ': enrich_groq,
    'TAVILY': enrich_tavily,
    'TWOCAPTCHA': enrich_twocaptcha,
    'ANTICAPTCHA': enrich_anticaptcha,
    'deepseek': enrich_deepseek,
    'openrouter': enrich_openrouter,
    'replicate': enrich_replicate,
    'groq': enrich_groq,
    'tavily': enrich_tavily,
    'gemini': enrich_gemini,
    'google': enrich_gemini,
    'RELAY': enrich_relay,
    'relay': enrich_relay,
    'GEMINI': enrich_gemini,
    'ELEVENLABS': None,
    'elevenlabs': None,
}


def enrich(prov, key):
    """Returns dict {alive, balance?, models?} — safe, never raises."""
    fn = ENRICHERS.get(prov) or ENRICHERS.get(prov.upper())
    if not fn:
        return {'alive': None}
    try:
        return fn(key)
    except Exception:
        return {'alive': None}
