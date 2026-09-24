"""
KeyHunter Revalidation Scanner — re-checks LIMITED keys that may have revived.

ZAI keys reset their 5-hour chat window periodically.
KIMI keys reset daily.
These should be re-checked every 2 hours.
"""
from __future__ import annotations
import logging
import time

log = logging.getLogger("keyhunter")

REVALIDATE_PROVIDERS = ["ZAI", "KIMI"]


class RevalidateScanner:
    def __init__(self, proj):
        self.proj = proj
        self.interval = 7200  # 2 hours between cycles
        self.session = None

    def _revalidate_once(self) -> int:
        """Re-check LIMITED keys. Returns count that became WORKING."""
        import sqlite3
        import sys
        sys.path.insert(0, str(self.proj / "src"))
        try:
            import eternal_v10 as e
        except Exception:
            return 0

        revived = 0
        for prov in REVALIDATE_PROVIDERS:
            c = sqlite3.connect(str(e.DB_PATH), timeout=30)
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA busy_timeout=30000")
            cur = c.cursor()
            cur.execute("SELECT val FROM keys WHERE prov=? AND status='LIMITED'",
                        (prov,))
            keys = [r[0] for r in cur.fetchall()]
            c.close()

            if not keys:
                continue

            log.info("🔄 [REVAL] re-checking %d %s LIMITED keys",
                     len(keys), prov)
            for key in keys[:50]:
                try:
                    status, plan, price, remaining = e.validate(key, prov)
                    if status == "WORKING":
                        revived += 1
                        log.info("🔄 [REVAL] %s key REVIVED: %s... → WORKING (%s)",
                                 prov, key[:16], plan or "?")
                except Exception as ex:
                    log.debug("[REVAL] %s error: %r", prov, ex)
                time.sleep(1)
        return revived

    def loop(self, stop_event):
        log.info("🔄 [REVAL] Revalidation scanner started (2h interval)")
        while not stop_event.is_set():
            # Initial 10 min wait (let main parser warm up first)
            for _ in range(600):
                if stop_event.is_set():
                    return
                time.sleep(1)
            try:
                revived = self._revalidate_once()
                if revived:
                    log.info("🔄 [REVAL] %d keys REVIVED!", revived)
            except Exception as ex:
                log.warning("[REVAL] error: %r", ex)
            # Then 2h cycle
            for _ in range(7200):
                if stop_event.is_set():
                    return
                time.sleep(1)
