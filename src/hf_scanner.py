"""
HuggingFace Spaces scanner — parallel source for leaked keys.

People hardcode API keys in public HF Spaces (Dockerfile, app.py, .env).
This scans freshly-created/modified Spaces in real-time via the HF API.

Architecture:
    - Poll HF /api/spaces every 60s (sorted by lastModified)
    - For each new Space: list files, download interesting ones, scan with regex
    - Found keys → DB (same as GitHub source)

Yield expectation: HF Spaces are LESS scanned than GitHub, so keys live longer.
"""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple

import requests

log = logging.getLogger("keyfarm")


# File types where keys are most likely committed in HF Spaces.
_HF_INTERESTING_FILES = [
    "app.py", "main.py", "Dockerfile", ".env", "config.py",
    "requirements.txt", "README.md", "config.json", "settings.py",
    "server.py", "index.py", "run.py", "streamlit_app.py",
    "gradio_app.py", "ui.py", "api.py", "utils.py",
]
_HF_INTERESTING_EXTS = ('.py', '.env', '.json', '.yaml', '.yml', '.toml',
                        '.cfg', '.ini', '.sh', '.js', '.ts', '.md')
_HF_MAX_FILE_SIZE = 200_000  # 200 KB — skip huge files


class HFScanner:
    def __init__(self, http_pool, extract_fn, db_add_fn, seen_max: int = 20_000):
        self.http = http_pool
        self._extract = extract_fn
        self._db_add = db_add_fn
        self._seen: Set[str] = set()
        self._seen_max = seen_max
        self._seen_lock = threading.Lock()
        self.stop_event: threading.Event = threading.Event()
        self.keys_found = 0

    def _mark_seen(self, space_id: str) -> bool:
        """Returns True if newly seen (not duplicate)."""
        with self._seen_lock:
            if space_id in self._seen:
                return False
            self._seen.add(space_id)
            if len(self._seen) > self._seen_max:
                # Drop oldest half.
                for _ in range(self._seen_max // 2):
                    self._seen.pop()
            return True

    def _fetch_recent_spaces(self, limit: int = 100) -> List[dict]:
        """Fetch recently-modified public Spaces."""
        try:
            r = self.http.session().get(
                "https://huggingface.co/api/spaces",
                params={"limit": limit, "sort": "lastModified",
                        "direction": "-1"},
                timeout=15)
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            log.debug("HF fetch spaces: %r", e)
        return []

    def _list_files(self, space_id: str) -> List[str]:
        """List files in a Space's main branch."""
        try:
            r = self.http.session().get(
                f"https://huggingface.co/api/spaces/{space_id}/tree/main",
                timeout=10)
            if r.status_code == 200:
                paths = []
                for item in r.json():
                    if item.get("type") == "file":
                        paths.append(item.get("path", ""))
                return paths
        except Exception as e:
            log.debug("HF list %s: %r", space_id, e)
        return []

    def _download_and_scan(self, space_id: str, fpath: str
                           ) -> Dict[str, Set[str]]:
        """Download one file, scan for keys."""
        url = f"https://huggingface.co/spaces/{space_id}/raw/main/{fpath}"
        try:
            r = self.http.session().get(url, timeout=10)
            if r.status_code == 200 and len(r.text) < _HF_MAX_FILE_SIZE:
                return self._extract(r.text)
        except Exception as e:
            log.debug("HF download %s/%s: %r", space_id, fpath, e)
        return {}

    def _scan_space(self, space_id: str) -> int:
        """Scan one Space. Returns count of NEW keys added."""
        if not self._mark_seen(space_id):
            return 0
        files = self._list_files(space_id)
        if not files:
            return 0
        # Filter to interesting files.
        targets = [f for f in files
                   if f in _HF_INTERESTING_FILES or f.endswith(_HF_INTERESTING_EXTS)]
        if not targets:
            return 0
        # Cap per space to avoid huge repos.
        targets = targets[:15]

        new_keys = 0
        for fpath in targets:
            if self.stop_event.is_set():
                break
            results = self._download_and_scan(space_id, fpath)
            for prov_name, keys in results.items():
                for k in keys:
                    if self._db_add(k, prov_name, f"hf:{space_id}"):
                        new_keys += 1
        return new_keys

    def poll_once(self) -> int:
        """Fetch recent Spaces, scan new ones. Returns total new keys."""
        spaces = self._fetch_recent_spaces(limit=100)
        if not spaces:
            return 0
        # Scan in parallel (file downloads are I/O bound).
        new_keys = 0
        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = {ex.submit(self._scan_space, s.get("id", "")): s
                    for s in spaces if s.get("id")}
            for f in as_completed(futs, timeout=120):
                if self.stop_event.is_set():
                    break
                try:
                    new_keys += f.result()
                except Exception as e:
                    log.debug("HF scan error: %r", e)
        if new_keys:
            log.info("🤗 [HF] +%d NEW keys from HuggingFace Spaces", new_keys)
            self.keys_found += new_keys
        return new_keys

    def loop(self) -> None:
        """Background thread: poll HF Spaces every 30s (doubled frequency — 31% yield)."""
        log.info("🤗 [HF] HuggingFace scanner started (30s interval)")
        while not self.stop_event.is_set():
            try:
                self.poll_once()
            except Exception as e:
                log.debug("HF loop error: %r", e)
            for _ in range(30):
                if self.stop_event.is_set():
                    break
                time.sleep(1)
        log.info("🤗 [HF] scanner stopped")
