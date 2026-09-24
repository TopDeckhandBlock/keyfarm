"""
KeyFarm GitHub Commits Scanner — searches commit messages for leaked keys.

GitHub has a separate /search/commits endpoint (different from /search/code).
People often commit secrets in messages or as part of commit content.
Uses token rotation like the main parser — no rate limit issues.

Rate limit: 30 req/min per token × 297 tokens = ~9000 req/min total.
"""
from __future__ import annotations
import logging
import re
import time

log = logging.getLogger("keyfarm")
from key_patterns import KEY_PATTERNS, ENV_RE, KIMI_PATTERN, extract_all_keys

# Search queries — commit search finds where keys appear in messages/diffs
COMMIT_QUERIES = [
    "DASHSCOPE_API_KEY",
    "ZHIPU_API_KEY",
    "Z_AI_API_KEY",
    "BIGMODEL_API_KEY",
    "GLM_API_KEY",
    "OPENROUTER_API_KEY",
    "MOONSHOT_API_KEY",
    "KIMI_API_KEY",
    "DEEPSEEK_API_KEY",
    "REPLICATE_API_TOKEN",
    "TOGETHER_API_KEY",
    "FIREWORKS_API_KEY",
    "NVIDIA_API_KEY",
    "NIM_API_KEY",
    "GROQ_API_KEY",
    "SILICONFLOW_API_KEY",
    "COHERE_API_KEY",
    "ELEVENLABS_API_KEY",
    "STABILITY_API_KEY",
    "PERPLEXITY_API_KEY",
    "sk-or-v1-",
    "nvapi-",
    "r8_",
    "gsk_",
]

# Key patterns imported from key_patterns module (shared, precise)


class CommitScanner:
    """Searches GitHub commits for leaked keys. Uses token rotation."""

    def __init__(self, proj, tokens):
        self.proj = proj
        self.tokens = list(tokens)
        self.token_idx = 0
        self.query_idx = 0
        self.session = None
        self.interval = 60  # poll every 60s

    def _next_token(self):
        if not self.tokens:
            return ""
        t = self.tokens[self.token_idx % len(self.tokens)]
        self.token_idx += 1
        return t

    def _get_session(self):
        import requests
        if self.session is None:
            self.session = requests.Session()
            self.session.trust_env = False
            self.session.headers['User-Agent'] = 'Mozilla/5.0'
        return self.session

    def _search_commits(self, query: str, max_results: int = 20) -> list:
        """Search commits. Returns [(repo, sha, message)]."""
        s = self._get_session()
        token = self._next_token()
        h = {"Authorization": f"token {token}",
             "Accept": "application/vnd.github.cloak-preview+json"}
        results = []
        try:
            r = s.get("https://api.github.com/search/commits",
                      params={"q": query, "per_page": min(max_results, 30),
                              "sort": "author-date", "order": "desc"},
                      headers=h, timeout=15)
            if r.status_code == 200:
                for item in r.json().get("items", [])[:max_results]:
                    repo = item.get("repo", {}).get("full_name", "")
                    sha = item.get("sha", "")
                    msg = item.get("commit", {}).get("message", "")
                    if repo and sha:
                        results.append((repo, sha, msg))
            elif r.status_code == 429 or r.status_code == 403:
                log.debug("[COMMITS] rate limited on token %s...%s",
                          token[:8], token[-4:])
        except Exception as e:
            log.debug("[COMMITS] search: %r", e)
        return results

    def _get_commit_diff(self, repo: str, sha: str) -> str:
        """Download commit diff (contains added lines with secrets)."""
        s = self._get_session()
        token = self._next_token()
        h = {"Authorization": f"token {token}",
             "Accept": "application/vnd.github.v3.diff"}
        try:
            r = s.get(f"https://api.github.com/repos/{repo}/commits/{sha}",
                      headers=h, timeout=15)
            if r.status_code == 200:
                return r.text
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

        # 3 queries per cycle
        total = 0
        for _ in range(3):
            query = COMMIT_QUERIES[self.query_idx % len(COMMIT_QUERIES)]
            self.query_idx += 1
            commits = self._search_commits(query, max_results=10)
            for repo, sha, msg in commits:
                diff = self._get_commit_diff(repo, sha)
                if diff:
                    keys = self._extract_keys(diff)
                    for prov, key in keys:
                        if e.db_add_key(key, prov, f"commit:{repo}/{sha[:7]}"):
                            total += 1
                            log.info("📦 [COMMITS] +%s key from %s@%s",
                                     prov, repo[:30], sha[:7])
                time.sleep(0.5)
            time.sleep(1)
        return total

    def loop(self, stop_event):
        log.info("📦 [COMMITS] GitHub commit scanner started "
                 "(%d queries, %d tokens, 60s interval)" %
                 (len(COMMIT_QUERIES), len(self.tokens)))
        while not stop_event.is_set():
            try:
                found = self._scan_once()
                if found:
                    log.info("📦 [COMMITS] +%d NEW keys", found)
            except Exception as ex:
                log.warning("[COMMITS] error: %r", ex)
            for _ in range(self.interval):
                if stop_event.is_set():
                    break
                time.sleep(1)
