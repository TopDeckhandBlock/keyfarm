"""
KeyFarm NPM Scanner — searches NPM packages for leaked API keys.

NPM packages often contain hardcoded keys in:
- package.json (config sections)
- README.md (usage examples with real keys)
- index.js / main file (hardcoded during dev)
"""
from __future__ import annotations
import logging
import re
import time

log = logging.getLogger("keyfarm")
from key_patterns import KEY_PATTERNS, ENV_RE, KIMI_PATTERN, extract_all_keys

KEY_PATTERNS = {
    "ZAI": re.compile(r'[a-f0-9]{32}\.[A-Za-z0-9]{10,30}'),
    "DASHSCOPE": re.compile(r'sk-[a-f0-9]{28,40}'),
    "OPENROUTER": re.compile(r'sk-or-v1-[a-f0-9]{40,80}'),
    "KIMI": re.compile(r'sk-[A-Za-z0-9]{40,80}'),
    "DEEPSEEK": re.compile(r'sk-[a-f0-9]{28,40}'),
    "GROQ": re.compile(r'gsk_[A-Za-z0-9]{40,60}'),
}

ENV_RE = re.compile(
    r'(?:DASHSCOPE_API_KEY|ZHIPU_API_KEY|Z_AI_API_KEY|BIGMODEL_API_KEY|'
    r'ZAI_API_KEY|GLM_API_KEY|OPENROUTER_API_KEY|MOONSHOT_API_KEY|'
    r'KIMI_API_KEY|DEEPSEEK_API_KEY|REPLICATE_API_TOKEN|'
    r'TOGETHER_API_KEY|FIREWORKS_API_KEY|NVIDIA_API_KEY|'
    r'GROQ_API_KEY)'
    r'\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,120})["\']?', re.IGNORECASE)

NPM_QUERIES = [
    "openai api_key", "anthropic api_key", "dashscope",
    "openrouter", "deepseek", "groq",
    "zhipu glm", "kimi moonshot", "together ai",
    "fireworks ai", "replicate api", "nvidia nim",
]


class NPMScanner:
    def __init__(self, proj):
        self.proj = proj
        self.session = None
        self.query_idx = 0
        self.interval = 180

    def _get_session(self):
        import requests
        if self.session is None:
            self.session = requests.Session()
            self.session.trust_env = False
            self.session.headers['User-Agent'] = 'Mozilla/5.0'
        return self.session

    def _search(self, query: str) -> list:
        """Search NPM packages. Returns [(name, version)]."""
        s = self._get_session()
        results = []
        try:
            r = s.get("https://registry.npmjs.org/-/v1/search",
                      params={"text": query, "size": 10}, timeout=12)
            if r.status_code == 200:
                for item in r.json().get("objects", [])[:10]:
                    pkg = item.get("package", {})
                    name = pkg.get("name", "")
                    version = pkg.get("version", "")
                    if name:
                        results.append((name, version))
        except Exception as e:
            log.debug("[NPM] search: %r", e)
        return results

    def _download_package(self, name: str, version: str) -> str:
        """Download package README + package.json."""
        s = self._get_session()
        text = ""
        # package.json (has config, scripts with keys)
        try:
            r = s.get(f"https://registry.npmjs.org/{name}/{version}",
                      timeout=10)
            if r.status_code == 200:
                d = r.json()
                text += d.get("readme", "") or ""
                # Check for keys in dist-tags, scripts, etc
                import json
                text += "\n" + json.dumps(d)
        except Exception as e:
            log.debug("[NPM] download: %r", e)
        return text

    def _extract_keys(self, text: str) -> list:
        return extract_all_keys(text)


    def _scan_once(self) -> int:
        import sys
        sys.path.insert(0, str(self.proj / "src"))
        try:
            import eternal_v10 as e
        except Exception:
            return 0

        query = NPM_QUERIES[self.query_idx % len(NPM_QUERIES)]
        self.query_idx += 1

        total = 0
        packages = self._search(query)
        for name, version in packages[:5]:
            text = self._download_package(name, version)
            if text:
                keys = self._extract_keys(text)
                for prov, key in keys:
                    if e.db_add_key(key, prov, f"npm:{name}"):
                        total += 1
                        log.info("📦 [NPM] +%s from %s", prov, name[:30])
            time.sleep(1)
        return total

    def loop(self, stop_event):
        log.info("📦 [NPM] NPM scanner started (180s interval)")
        while not stop_event.is_set():
            try:
                found = self._scan_once()
                if found:
                    log.info("📦 [NPM] +%d NEW keys", found)
            except Exception as ex:
                log.warning("[NPM] error: %r", ex)
            for _ in range(self.interval):
                if stop_event.is_set():
                    break
                time.sleep(1)
