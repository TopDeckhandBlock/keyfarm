#!/usr/bin/env python3
"""FLEET DEPLOYER — deploy the IMBA parser to N GitHub accounts.

For each account (needs PAT with repo+workflow scope):
  1. create private repo keyfarm-node (skip if exists)
  2. push all files from local keyfarm-node dir via Git Data API (tree at once)
  3. set secrets: POOL_KEY (shared Fernet key) + NODE_TOKENS (own PAT, comma-sep)
  4. verify workflow exists; schedule runs automatically (cron every 3 days)

Resumable: fleet_state.json tracks per-account status.

Usage: python fleet_deploy.py [start] [count]
"""
import base64
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(r'C:/Users/User/Desktop/keyfarm-node')
FLEET_POOL = Path(r'C:/Users/User/tmp/gh_pats_all.json')
STATE = Path(r'C:/Users/User/tmp/fleet_state.json')
POOL_KEY = Path(r'C:/Users/User/tmp/imba_pool_key.txt').read_text().strip()

EXCLUDE_NAMES = {'gh_tokens.txt', 'working_keys_verified.txt', 'gh_accounts.json', 'pool.json'}

def api(token, path, method='GET', body=None, raw=False):
    req = urllib.request.Request(f'https://api.github.com{path}', method=method)
    req.add_header('Authorization', f'token {token}')
    req.add_header('Accept', 'application/vnd.github+json')
    req.add_header('User-Agent', 'fleet-deployer')
    if body is not None:
        req.data = json.dumps(body).encode()
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            b = r.read()
            if raw: return r.status, b
            return r.status, (json.loads(b) if b else {})
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read())
        except Exception: return e.code, {'message': 'err'}
    except Exception as e:
        return -1, {'message': str(e)[:120]}

def load_state():
    try: return json.load(open(STATE, encoding='utf-8'))
    except Exception: return {}

def save_state(st):
    json.dump(st, open(STATE, 'w', encoding='utf-8'), indent=0)

def collect_files():
    files = []
    for f in ROOT.rglob('*'):
        if not f.is_file(): continue
        rel = f.relative_to(ROOT).as_posix()
        if rel.startswith('data/clones') or rel.endswith(('.pyc', '.log')) or '__pycache__' in rel: continue
        if os.path.basename(rel) in EXCLUDE_NAMES: continue
        files.append((rel, f.read_bytes()))
    return files

def set_secret(token, repo, name, value):
    st, pk = api(token, f'/repos/{repo}/actions/secrets/public-key')
    if st != 200: return False, f'pubkey {st}'
    import nacl.public
    box = nacl.public.SealedBox(nacl.public.PublicKey(base64.b64decode(pk['key'])))
    sealed = base64.b64encode(box.encrypt(value.encode())).decode()
    st2, r = api(token, f'/repos/{repo}/actions/secrets/{name}', method='PUT',
                 body={'encrypted_value': sealed, 'key_id': pk['key_id']})
    return st2 in (201, 204), str(st2)

def deploy_account(login, token, files):
    repo = f'{login}/keyfarm-node'
    out = {'login': login}
    # 1. create repo
    st, r = api(token, '/user/repos', method='POST',
                body={'name': 'keyfarm-node', 'private': True, 'auto_init': False})
    if st == 201:
        out['repo'] = 'created'
    elif st == 422 and 'already exists' in str(r):
        out['repo'] = 'exists'
    else:
        out['error'] = f'repo {st}: {str(r)[:100]}'
        return out
    time.sleep(2)

    # 2. push tree: init commit first (empty repo needs a base)
    st, r = api(token, f'/repos/{repo}/contents/README.md', method='PUT',
                body={'message': 'init', 'content': base64.b64encode(b'# imba node\n').decode()})
    if st not in (200, 201, 422):
        out['error'] = f'init {st}'
        return out
    st, ref = api(token, f'/repos/{repo}/git/ref/heads/main')
    if st != 200:
        out['error'] = f'ref {st}'
        return out
    base_sha = ref['object']['sha']

    # blobs (files list may be ~40 items; batch tree)
    tree_items = []
    for rel, content in files:
        st, blob = api(token, f'/repos/{repo}/git/blobs', method='POST',
                       body={'content': base64.b64encode(content).decode(), 'encoding': 'base64'})
        if st not in (200, 201):
            out.setdefault('blob_fail', []).append(rel)
            continue
        tree_items.append({'path': rel, 'mode': '100644', 'type': 'blob', 'sha': blob['sha']})
    if not tree_items:
        out['error'] = 'no blobs'
        return out
    st, tree = api(token, f'/repos/{repo}/git/trees', method='POST', body={'tree': tree_items})
    if st != 201:
        out['error'] = f'tree {st}: {str(tree)[:80]}'
        return out
    st, commit = api(token, f'/repos/{repo}/git/commits', method='POST',
                     body={'message': 'imba node deploy', 'tree': tree['sha'], 'parents': [base_sha]})
    if st != 201:
        out['error'] = f'commit {st}'
        return out
    st, upd = api(token, f'/repos/{repo}/git/refs/heads/main', method='PATCH', body={'sha': commit['sha']})
    if st != 200:
        out['error'] = f'refupd {st}'
        return out
    out['files'] = len(tree_items)

    # 3. secrets
    ok1, m1 = set_secret(token, repo, 'POOL_KEY', POOL_KEY)
    ok2, m2 = set_secret(token, repo, 'NODE_TOKENS', token)
    out['secrets'] = {'POOL_KEY': ok1, 'NODE_TOKENS': ok2}

    # 4. verify workflow file present
    time.sleep(2)
    st, wf = api(token, f'/repos/{repo}/contents/.github/workflows/imba.yml')
    out['workflow'] = 'ok' if st == 200 else f'missing({st})'
    out['status'] = 'deployed' if (ok1 and ok2 and st == 200) else 'partial'
    return out

def main():
    start = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 999
    fleet = json.load(open(FLEET_POOL, encoding='utf-8'))
    state = load_state()
    files = collect_files()
    print(f'fleet={len(fleet)} files={len(files)} start={start}', flush=True)

    ok = fail = skip = 0
    for a in fleet[start:start + count]:
        login = a['login']
        if state.get(login, {}).get('status') == 'deployed':
            skip += 1
            continue
        r = deploy_account(login, a['pat'], files)
        state[login] = r
        save_state(state)
        if r.get('status') == 'deployed':
            ok += 1
            print(f'[DEPLOYED] {login}', flush=True)
        else:
            fail += 1
            print(f'[FAIL] {login}: {r.get("error") or r}', flush=True)
        time.sleep(random.uniform(1.5, 3.5))
    print(f'DONE ok={ok} fail={fail} skip={skip}', flush=True)

if __name__ == '__main__':
    main()
