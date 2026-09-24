#!/usr/bin/env python3
"""Batch PAT harvest from gh_accounts.json pool — continues past failures."""
import json, re, sys, time, random
import requests, pyotp

UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'}
POOL = r'C:\Users\User\tmp\gh_pats_fleet.json'
ACC_FILE = r'C:\Users\User\tmp\gh_accounts.json'

def load_pool():
    try:
        return json.load(open(POOL, encoding='utf-8'))
    except Exception:
        return []

def save_pool(p):
    json.dump(p, open(POOL, 'w', encoding='utf-8'), indent=1)

def login(acc):
    s = requests.Session()
    s.headers.update(UA)
    r = s.get('https://github.com/login', timeout=30)
    at = re.search(r'name="authenticity_token"[^>]*value="([^"]+)"', r.text)
    if not at:
        return None, 'no authenticity_token'
    r = s.post('https://github.com/session', data={
        'authenticity_token': at.group(1),
        'login': acc['email'],
        'password': acc['password'],
    }, allow_redirects=False, timeout=30)
    loc = r.headers.get('Location', '')
    if 'two-factor' in loc:
        u = loc if loc.startswith('http') else 'https://github.com' + loc
        r2 = s.get(u, timeout=30)
        at2 = re.search(r'name="authenticity_token"[^>]*value="([^"]+)"', r2.text)
        if not at2:
            return None, 'no token on 2fa page'
        otp = pyotp.TOTP(acc['totp']).now()
        r3 = s.post('https://github.com/sessions/two-factor', data={
            'authenticity_token': at2.group(1),
            'app_otp': otp,
        }, allow_redirects=True, timeout=30)
        if 'checkup' in r3.url:
            return None, 'checkup page'
    rv = s.get('https://github.com/settings/profile', timeout=30)
    if rv.status_code != 200:
        return None, f'not logged in status={rv.status_code}'
    return s, 'ok'

def create_pat(s, name='imba-node'):
    r = s.get('https://github.com/settings/tokens/new', timeout=30)
    if r.status_code != 200:
        return None, f'tokens/new status {r.status_code}'
    if 'two_factor_checkup' in r.url:
        return None, 'checkup interstitial'
    at = re.search(r'name="authenticity_token"[^>]*value="([^"]+)"', r.text)
    if not at:
        return None, 'no authenticity_token'
    data = {
        'authenticity_token': at.group(1),
        'oauth_access[description]': name,
        'oauth_access[scopes][]': ['repo', 'workflow'],
        'oauth_access[default_expires_at]': '90',
    }
    r2 = s.post('https://github.com/settings/tokens', data=data, allow_redirects=True, timeout=30)
    m = re.search(r'(ghp_[A-Za-z0-9]{36})', r2.text)
    if m:
        return m.group(1), 'ok'
    return None, f'no token, url={r2.url[:60]}'

def main():
    start = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    accs = json.load(open(ACC_FILE, encoding='utf-8'))
    pool = load_pool()
    have = {p['login'] for p in pool}
    ok, fail = 0, 0
    for acc in accs[start:start+count]:
        if acc['login'] in have:
            continue
        try:
            s, err = login(acc)
            if not s:
                print(f"[FAIL] {acc['login']}: login: {err}", flush=True)
                fail += 1
            else:
                tok, err2 = create_pat(s)
                if tok:
                    pool.append({'login': acc['login'], 'email': acc['email'], 'pat': tok})
                    save_pool(pool)
                    print(f"[OK] {acc['login']}: PAT harvested ({tok[:6]}...)", flush=True)
                    ok += 1
                else:
                    print(f"[FAIL] {acc['login']}: pat: {err2}", flush=True)
                    fail += 1
        except Exception as e:
            print(f"[ERR] {acc['login']}: {type(e).__name__} {str(e)[:80]}", flush=True)
            fail += 1
        time.sleep(random.uniform(2, 5))
    print(f"DONE ok={ok} fail={fail} pool_total={len(pool)}")

if __name__ == '__main__':
    main()
