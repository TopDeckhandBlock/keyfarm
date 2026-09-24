"""
KeyHunter Docker Hub Scanner — searches Docker Hub for leaked API keys.

Docker images often contain .env files baked into layers.
We scan public Dockerfile + image configs for secrets.
"""
from __future__ import annotations
import logging
import re
import time

log = logging.getLogger("keyhunter")
from key_patterns import KEY_PATTERNS, ENV_RE, KIMI_PATTERN, extract_all_keys

KEY_PATTERNS = {
    "ZAI": re.compile(r'[a-f0-9]{32}\.[A-Za-z0-9]{10,30}'),
    "DASHSCOPE": re.compile(r'sk-[a-f0-9]{28,40}'),
    "OPENROUTER": re.compile(r'sk-or-v1-[a-f0-9]{40,80}'),
    "KIMI": re.compile(r'sk-[A-Za-z0-9]{40,80}'),
    "DEEPSEEK": re.compile(r'sk-[a-f0-9]{28,40}'),
    "REPLICATE": re.compile(r'r8_[A-Za-z0-9]{30,100}'),
    "GROQ": re.compile(r'gsk_[A-Za-z0-9]{40,60}'),
}

ENV_RE = re.compile(
    r'(?:DASHSCOPE_API_KEY|ZHIPU_API_KEY|Z_AI_API_KEY|BIGMODEL_API_KEY|'
    r'ZAI_API_KEY|GLM_API_KEY|OPENROUTER_API_KEY|MOONSHOT_API_KEY|'
    r'KIMI_API_KEY|DEEPSEEK_API_KEY|REPLICATE_API_TOKEN|'
    r'TOGETHER_API_KEY|FIREWORKS_API_KEY|NVIDIA_API_KEY|'
    r'GROQ_API_KEY)'
    r'\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,120})["\']?', re.IGNORECASE)

DOCKER_QUERIES = [
    "openrouter", "dashscope", "zhipu", "glm", "kimi",
    "deepseek", "groq", "llm", "openai-proxy",
    "chatgpt", "api-proxy", "ai-agent", "streamlit",
]


class DockerScanner:
    def __init__(self, proj):
        self.proj = proj
        self.session = None
        self.query_idx = 0
        self.interval = 120

    def _get_session(self):
        import requests
        if self.session is None:
            self.session = requests.Session()
            self.session.trust_env = False
            self.session.headers['User-Agent'] = 'Mozilla/5.0'
        return self.session

    def _search(self, query: str) -> list:
        """Search Docker Hub repos. Returns [(repo_name)]."""
        s = self._get_session()
        results = []
        try:
            r = s.get("https://hub.docker.com/v2/search/repositories",
                      params={"query": query, "page_size": 10,
                              "ordering": "-star_count"},
                      timeout=12)
            if r.status_code == 200:
                for item in r.json().get("results", []):
                    name = item.get("repo_name", "")
                    if name:
                        results.append(name)
        except Exception as e:
            log.debug("[DOCKER] search: %r", e)
        return results

    def _get_dockerfile(self, repo: str) -> str:
        """Get Dockerfile or README from Docker Hub repo."""
        s = self._get_session()
        try:
            r = s.get(f"https://hub.docker.com/v2/repositories/{repo}",
                      timeout=10)
            if r.status_code == 200:
                desc = r.json().get("description", "") or ""
                full = r.json().get("full_description", "") or ""
                return desc + "\n" + full
        except Exception:
            pass
        return ""

    def _extract_keys(self, text: str) -> list:
        return extract_all_keys(text)


    def _scan_once(self) -> int:
        import sys
        sys.path.insert(0, str(self.proj / "src"))
        try:
            import eternal_v10 as e
        except Exception:
            return 0

        query = DOCKER_QUERIES[self.query_idx % len(DOCKER_QUERIES)]
        self.query_idx += 1

        total = 0
        repos = self._search(query)
        for repo in repos[:8]:
            text = self._get_dockerfile(repo)
            if text:
                keys = self._extract_keys(text)
                for prov, key in keys:
                    if e.db_add_key(key, prov, f"docker:{repo}"):
                        total += 1
                        log.info("🐳 [DOCKER] +%s from %s", prov, repo[:30])
            time.sleep(0.5)
        return total

    def loop(self, stop_event):
        log.info("🐳 [DOCKER] Docker Hub scanner started (120s interval)")
        while not stop_event.is_set():
            try:
                found = self._scan_once()
                if found:
                    log.info("🐳 [DOCKER] +%d NEW keys", found)
            except Exception as ex:
                log.warning("[DOCKER] error: %r", ex)
            for _ in range(self.interval):
                if stop_event.is_set():
                    break
                time.sleep(1)
