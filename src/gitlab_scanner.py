"""
KeyFarm GitLab Scanner — searches GitLab.com public projects for leaked API keys.

GitLab has a free public API with code search (unlike GitHub which needs PAT).
Polls every 120s with rotating search queries.
"""
from __future__ import annotations
import logging
import re
import threading
import time
import os

log = logging.getLogger("keyfarm")
from key_patterns import KEY_PATTERNS, ENV_RE, KIMI_PATTERN, extract_all_keys

# Search terms — rotated each cycle
SEARCH_QUERIES = [
    "DASHSCOPE_API_KEY",
    "ZHIPU_API_KEY",
    "ZAI_API_KEY",
    "OPENROUTER_API_KEY",
    "MOONSHOT_API_KEY",
    "KIMI_API_KEY",
    "DEEPSEEK_API_KEY",
    "REPLICATE_API_TOKEN",
    "TOGETHER_API_KEY",
    "FIREWORKS_API_KEY",
    "NVIDIA_API_KEY",
    "COHERE_API_KEY",
    "GROQ_API_KEY",
    "SILICONFLOW_API_KEY",
    "ELEVENLABS_API_KEY",
    "STABILITY_API_KEY",
    "filename:.env",
    "filename:docker-compose.yml API_KEY",
]

# Key patterns imported from key_patterns module (shared, precise)
# KEY_PATTERNS, ENV_RE, extract_all_keys come from the import above.


class GitLabScanner:
    def __init__(self, proj):
        self.proj = proj
        self.session = None
        self.query_idx = 0
        self.interval = 120

    def _get_session(self):
        import requests
        if self.session is None:
            self.session = requests.Session()
            self.session.trust_env = False  # direct, no proxy
            self.session.headers['User-Agent'] = 'Mozilla/5.0'
        return self.session

    def _search_code(self, query: str) -> list:
        """Search GitLab projects matching query. Returns [(proj_id, full_name)].

        GitLab's code search (blobs scope) needs auth, but project search is free.
        We find projects, then download their .env/config files.
        """
        s = self._get_session()
        results = []
        try:
            # Project search — free, no auth needed
            r = s.get("https://gitlab.com/api/v4/projects",
                      params={"search": query.replace("_API_KEY", "").lower(),
                              "per_page": 10, "order_by": "last_activity_at",
                              "sort": "desc"},
                      timeout=15)
            if r.status_code == 200:
                for p in r.json()[:10]:
                    pid = p.get("id")
                    name = p.get("path_with_namespace", "")
                    if pid:
                        results.append((pid, name))
            elif r.status_code == 429:
                log.warning("[GITLAB] rate limited, backing off")
                time.sleep(30)
        except Exception as e:
            log.debug("gitlab search: %r", e)
        return results

    def _get_project_tree(self, proj_id: int) -> list:
        """Get file list for a GitLab project (look for config files)."""
        s = self._get_session()
        interesting = []
        # Match by extension (any path) + specific filenames
        target_exts = ('.env', '.cfg', '.ini', '.yaml', '.yml', '.json',
                       '.toml', '.envrc', '.conf')
        target_names = {'docker-compose.yml', 'docker-compose.yaml',
                        'config.json', 'config.py', 'config.yaml',
                        'settings.py', 'settings.json', 'app.py', 'main.py',
                        'README.md', 'Procfile', 'render.yaml',
                        'streamlit_app.py', 'gradio_app.py', '.envrc',
                        '.env', '.env.example', '.env.local',
                        '.env.production', 'env.dev', 'Makefile'}
        try:
            r = s.get(f"https://gitlab.com/api/v4/projects/{proj_id}/repository/tree",
                      params={"per_page": 100, "recursive": "true"},
                      timeout=15)
            if r.status_code == 200:
                for item in r.json():
                    if item.get("type") != "blob":
                        continue
                    path = item.get("path", "")
                    fname = path.rsplit('/', 1)[-1]
                    # Match by exact name or extension
                    if fname in target_names or fname.endswith(target_exts):
                        interesting.append(path)
        except Exception as e:
            log.debug("gitlab tree: %r", e)
        return interesting

    def _download_file(self, proj_id: int, path: str, ref: str = "main") -> str:
        """Download raw file from GitLab."""
        s = self._get_session()
        try:
            import urllib.parse
            encoded = urllib.parse.quote(path, safe='')
            url = f"https://gitlab.com/api/v4/projects/{proj_id}/repository/files/{encoded}/raw"
            # Try main then master
            for branch in ["main", "master"]:
                r = s.get(url, params={"ref": branch}, timeout=15)
                if r.status_code == 200:
                    return r.text
        except Exception as e:
            log.debug("gitlab download: %r", e)
        return ""

    def _extract_keys(self, text: str) -> list:
        return extract_all_keys(text)


    def _scan_once(self) -> int:
        """Run one search scan cycle. Returns keys found."""
        import sys
        sys.path.insert(0, str(self.proj / "src"))
        try:
            import eternal_v10 as e
        except Exception:
            return 0

        # Rotate through queries — 3 per cycle
        queries_this_cycle = []
        for i in range(3):
            queries_this_cycle.append(
                SEARCH_QUERIES[self.query_idx % len(SEARCH_QUERIES)])
            self.query_idx += 1

        total_found = 0
        for query in queries_this_cycle:
            projects = self._search_code(query)
            for proj_id, proj_name in projects[:5]:  # limit per query
                # Get config files in this project
                config_files = self._get_project_tree(proj_id)
                for path in config_files[:5]:  # top 5 files
                    text = self._download_file(proj_id, path)
                    if not text:
                        continue
                    keys = self._extract_keys(text)
                    for prov, key in keys:
                        if e.db_add_key(key, prov, f"gitlab:{proj_name}"):
                            total_found += 1
                            log.info("📝 [GITLAB] +%s key from %s/%s",
                                     prov, proj_name[:25], path[:25])
                time.sleep(1)  # be nice
            time.sleep(2)

        return total_found

    def loop(self, stop_event):
        """Main loop — runs in background thread."""
        log.info("🦊 [GITLAB] GitLab scanner started (120s interval)")
        while not stop_event.is_set():
            try:
                found = self._scan_once()
                if found:
                    log.info("🦊 [GITLAB] +%d NEW keys this cycle", found)
            except Exception as ex:
                log.warning("gitlab scanner error: %r", ex)
            # Sleep in slices for shutdown responsiveness
            for _ in range(self.interval):
                if stop_event.is_set():
                    break
                time.sleep(1)
