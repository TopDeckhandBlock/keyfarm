"""
KeyHunter HuggingFace Models + Datasets Scanner.

Extends HF scanning beyond Spaces to:
  - Models (model cards with README containing keys)
  - Datasets (people upload .env in dataset files)

HF has 3 surfaces: spaces, models, datasets. We already scan spaces;
this adds the other two with the same high-yield approach.
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

import requests

log = logging.getLogger("keyhunter")

_HF_INTERESTING = ['.env', '.env.local', 'README.md', 'app.py', 'main.py',
                   'config.json', 'config.yaml', 'requirements.txt',
                   'Dockerfile', 'CLAUDE.md', 'mcp.json', '.cursorrules']


class HFModelsScanner:
    """Scans HuggingFace Models and Datasets for leaked keys."""

    def __init__(self, proj):
        self.proj = proj
        self.session = None
        self.interval = 120
        self.models_offset = 0
        self.datasets_offset = 0

    def _get_session(self):
        if self.session is None:
            self.session = requests.Session()
            self.session.trust_env = False
            self.session.headers['User-Agent'] = 'Mozilla/5.0'
        return self.session

    def _scan_hf_type(self, hf_type: str, offset: int) -> int:
        """Scan HF models or datasets. Returns keys found."""
        import sys
        sys.path.insert(0, str(self.proj / "src"))
        try:
            import eternal_v10 as e
            from key_patterns import extract_all_keys
        except Exception:
            return 0

        s = self._get_session()
        total_found = 0
        try:
            # Get recent models/datasets
            url = f"https://huggingface.co/api/{hf_type}"
            r = s.get(url, params={"limit": 20, "sort": "lastModified",
                                   "direction": "-1", "offset": offset},
                      timeout=15)
            if r.status_code != 200:
                return 0

            items = r.json()
            for item in items[:15]:
                repo_id = item.get("id", "") or item.get("modelId", "")
                if not repo_id:
                    continue

                # Download README (most common leak in models/datasets)
                for fname in ['README.md', '.env', 'config.json', 'app.py']:
                    try:
                        raw_url = f"https://huggingface.co/{hf_type[:-1] if hf_type.endswith('s') else hf_type}/{repo_id}/resolve/main/{fname}"
                        # HF uses /models/ and /datasets/ paths
                        prefix = hf_type.rstrip('s') if hf_type.endswith('s') else hf_type
                        raw_url = f"https://huggingface.co/{prefix}/{repo_id}/resolve/main/{fname}"
                        r2 = s.get(raw_url, timeout=10)
                        if r2.status_code == 200 and len(r2.text) > 10:
                            keys = extract_all_keys(r2.text)
                            for prov, key in keys:
                                if e.db_add_key(key, prov, f"hf:{prefix}/{repo_id}"):
                                    total_found += 1
                                    log.info("🤗 [HF-%s] +%s from %s/%s",
                                             hf_type, prov, repo_id[:25], fname)
                    except Exception:
                        pass
                time.sleep(0.3)
        except Exception as ex:
            log.debug("[HF-%s] error: %r", hf_type, ex)
        return total_found

    def loop(self, stop_event):
        log.info("🤗 [HF-MODELS] HuggingFace Models+Datasets scanner started (120s)")
        while not stop_event.is_set():
            try:
                # Alternate between models and datasets
                m = self._scan_hf_type("models", self.models_offset)
                self.models_offset += 15
                d = self._scan_hf_type("datasets", self.datasets_offset)
                self.datasets_offset += 15

                total = m + d
                if total:
                    log.info("🤗 [HF-MODELS] +%d NEW keys (models=%d, datasets=%d)",
                             total, m, d)

                # Reset offset after scanning enough
                if self.models_offset > 500:
                    self.models_offset = 0
                if self.datasets_offset > 500:
                    self.datasets_offset = 0
            except Exception as ex:
                log.warning("[HF-MODELS] error: %r", ex)
            for _ in range(self.interval):
                if stop_event.is_set():
                    break
                time.sleep(1)
