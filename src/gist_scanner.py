"""
GitHub Gists scanner — public gists often contain hardcoded API keys.

Polls /gists/public every 30s, downloads each gist's files, scans with
the same regex as the main parser. People use gists as "pastebin" and
accidentally leak secrets.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Set

log = logging.getLogger("keyhunter")

_GIST_MAX_FILES = 5          # cap files per gist to avoid huge dumps
_GIST_MAX_FILE_SIZE = 50_000  # 50 KB


class GistScanner:
    def __init__(self, http_pool, extract_fn, db_add_fn, seen_max: int = 15_000):
        self.http = http_pool
        self._extract = extract_fn
        self._db_add = db_add_fn
        self._seen: Set[str] = set()
        self._seen_max = seen_max
        self._lock = threading.Lock()
        self.stop_event: threading.Event = threading.Event()
        self.keys_found = 0

    def _mark_seen(self, gist_id: str) -> bool:
        with self._lock:
            if gist_id in self._seen:
                return False
            self._seen.add(gist_id)
            if len(self._seen) > self._seen_max:
                for _ in range(self._seen_max // 2):
                    self._seen.pop()
            return True

    def _fetch_recent(self, limit: int = 100) -> list:
        """Fetch recent public gists. Needs a token for higher rate limit."""
        tok = ""
        try:
            import sys
            mod = sys.modules.get("eternal_v9")
            if mod:
                tok = mod.TOKENS.next()
        except Exception:
            pass
        headers = {"Accept": "application/vnd.github.v3+json"}
        if tok:
            headers["Authorization"] = f"token {tok}"
        try:
            r = self.http.session().get(
                "https://api.github.com/gists/public",
                params={"per_page": limit},
                headers=headers, timeout=15)
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            log.debug("gist fetch: %r", e)
        return []

    def _scan_gist(self, gist: dict) -> int:
        gid = gist.get("id", "")
        if not gid or not self._mark_seen(gid):
            return 0
        files = gist.get("files", {})
        # Limit files per gist.
        items = list(files.items())[:_GIST_MAX_FILES]
        new_keys = 0
        for fname, fmeta in items:
            if self.stop_event.is_set():
                break
            # Use raw_url to fetch content directly.
            raw_url = fmeta.get("raw_url")
            size = fmeta.get("size", 0)
            if not raw_url or size > _GIST_MAX_FILE_SIZE:
                continue
            try:
                r = self.http.session().get(raw_url, timeout=10)
                if r.status_code == 200:
                    results = self._extract(r.text)
                    for prov_name, keys in results.items():
                        for k in keys:
                            if self._db_add(k, prov_name, f"gist:{gid}"):
                                new_keys += 1
            except Exception as e:
                log.debug("gist %s/%s: %r", gid, fname, e)
        return new_keys

    def poll_once(self) -> int:
        gists = self._fetch_recent(limit=100)
        if not gists:
            return 0
        new_keys = 0
        for gist in gists:
            if self.stop_event.is_set():
                break
            try:
                new_keys += self._scan_gist(gist)
            except Exception as e:
                log.debug("gist scan error: %r", e)
        if new_keys:
            log.info("📝 [GIST] +%d NEW keys from GitHub Gists", new_keys)
            self.keys_found += new_keys
        return new_keys

    def loop(self) -> None:
        log.info("📝 [GIST] GitHub Gists scanner started (30s interval)")
        while not self.stop_event.is_set():
            try:
                self.poll_once()
            except Exception as e:
                log.debug("gist loop error: %r", e)
            # Poll every 30s — gists refresh fast.
            for _ in range(30):
                if self.stop_event.is_set():
                    break
                time.sleep(1)
        log.info("📝 [GIST] scanner stopped")
