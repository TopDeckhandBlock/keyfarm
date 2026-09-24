"""
KeyFarm GitHub Issues Scanner.

People paste API keys in GitHub issues, PRs, and discussions when:
  - Reporting bugs ("my key doesn't work: DASHSCOPE_API_KEY=sk-xxxx")
  - Sharing code examples
  - Asking for help

This is a HUGE untapped surface — 639+ issues with DASHSCOPE_API_KEY alone.
Uses token rotation (same as commit scanner).
"""
from __future__ import annotations

import logging
import time
import requests

log = logging.getLogger("keyfarm")

ISSUE_QUERIES = [
    "DASHSCOPE_API_KEY",
    "ZHIPU_API_KEY",
    "Z_AI_API_KEY",
    "OPENROUTER_API_KEY",
    "DEEPSEEK_API_KEY",
    "MOONSHOT_API_KEY",
    "KIMI_API_KEY",
    "sk-or-v1-",
    "nvapi-",
    "r8_",
    "BAILIAN_API_KEY",
    "MODELSCOPE_API_KEY",
    "QWEN_API_KEY",
    "GLM_API_KEY",
    "FIREWORKS_API_KEY",
]


class IssuesScanner:
    """Searches GitHub issues/PRs for leaked keys."""

    def __init__(self, proj, tokens):
        self.proj = proj
        self.tokens = list(tokens)
        self.token_idx = 0
        self.query_idx = 0
        self.session = None
        self.interval = 90

    def _next_token(self):
        if not self.tokens:
            return ""
        t = self.tokens[self.token_idx % len(self.tokens)]
        self.token_idx += 1
        return t

    def _get_session(self):
        if self.session is None:
            self.session = requests.Session()
            self.session.trust_env = False
            self.session.headers['User-Agent'] = 'Mozilla/5.0'
        return self.session

    def _search_issues(self, query: str) -> list:
        """Search issues/PRs. Returns [(repo, issue_number, body)]."""
        s = self._get_session()
        token = self._next_token()
        h = {"Authorization": "token " + token,
             "Accept": "application/vnd.github.text-match+json"}
        results = []
        try:
            r = s.get("https://api.github.com/search/issues",
                      params={"q": query + " type:issue", "per_page": 10},
                      headers=h, timeout=15)
            if r.status_code == 200:
                for item in r.json().get("items", [])[:10]:
                    repo_url = item.get("repository_url", "")
                    repo = repo_url.replace("https://api.github.com/repos/", "")
                    number = item.get("number", 0)
                    body = item.get("body", "") or ""
                    title = item.get("title", "") or ""
                    results.append((repo, number, title + "\n" + body))
            elif r.status_code == 429 or r.status_code == 403:
                log.debug("[ISSUES] rate limited")
        except Exception as e:
            log.debug("[ISSUES] search: %r", e)
        return results

    def _extract_keys(self, text: str) -> list:
        import sys
        sys.path.insert(0, str(self.proj / "src"))
        try:
            from key_patterns import extract_all_keys
            return extract_all_keys(text)
        except Exception:
            return []

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
            query = ISSUE_QUERIES[self.query_idx % len(ISSUE_QUERIES)]
            self.query_idx += 1
            issues = self._search_issues(query)
            for repo, number, body in issues:
                if not body:
                    continue
                keys = self._extract_keys(body)
                for prov, key in keys:
                    if e.db_add_key(key, prov, f"issue:{repo}#{number}"):
                        total += 1
                        log.info("💬 [ISSUES] +%s from %s#%d",
                                 prov, repo[:25], number)
                time.sleep(0.3)
            time.sleep(1)
        return total

    def loop(self, stop_event):
        log.info("💬 [ISSUES] GitHub Issues scanner started "
                 "(%d queries, %d tokens, 90s)" %
                 (len(ISSUE_QUERIES), len(self.tokens)))
        while not stop_event.is_set():
            try:
                found = self._scan_once()
                if found:
                    log.info("💬 [ISSUES] +%d NEW keys", found)
            except Exception as ex:
                log.warning("[ISSUES] error: %r", ex)
            for _ in range(self.interval):
                if stop_event.is_set():
                    break
                time.sleep(1)
