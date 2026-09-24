"""
KeyFarm Validator — standalone validation process.

Runs in parallel with eternal_v9.py (parser). Continuously reads NEW/ERR
keys from the DB, validates them against provider APIs, and updates status.

Architecture (producer-consumer):
    parser (eternal_v9.py)     →  writes NEW keys to DB
    validator (this file)      →  reads NEW keys, validates, updates status

Both processes share keys.db (SQLite WAL mode → safe concurrent access).

Usage:
    python -u src/validator.py

Env knobs:
    KEYFARM_VAL_INTERVAL=2   — seconds between polls (default 2)
    KEYFARM_VAL_BATCH=100    — max keys per poll (default 100)
    KEYFARM_VAL_WORKERS=30   — concurrent validation threads (default 30)
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import signal
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# Make eternal_v10 importable for shared DB layer + PROVIDERS + validate().
sys.path.insert(0, str(Path(__file__).resolve().parent))
import eternal_v10 as e  # noqa: E402

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
PROJ = Path(__file__).resolve().parent.parent
POLL_INTERVAL = float(os.environ.get("KEYFARM_VAL_INTERVAL", "2"))
BATCH_SIZE = int(os.environ.get("KEYFARM_VAL_BATCH", "100"))
WORKERS = int(os.environ.get("KEYFARM_VAL_WORKERS", "30"))
LOG_LEVEL = os.environ.get("KEYFARM_LOG_LEVEL", "INFO").upper()

_STOP = threading.Event()


def _on_signal(signum, _frame):
    print(f"\n[VALIDATOR] Signal {signum} — shutting down...")
    _STOP.set()


for _sig in (signal.SIGINT, signal.SIGTERM):
    try:
        signal.signal(_sig, _on_signal)
    except (ValueError, OSError):
        pass


# --------------------------------------------------------------------------- #
# Logging — separate file so it doesn't mix with parser log
# --------------------------------------------------------------------------- #
def _setup_logging() -> logging.Logger:
    log = logging.getLogger("keyfarm-validator")
    log.setLevel(LOG_LEVEL)
    if log.handlers:
        return log
    fmt = logging.Formatter("%(asctime)s %(levelname)-5s %(message)s",
                            "%H:%M:%S")
    log_dir = PROJ / "data" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    fh = logging.handlers.RotatingFileHandler(
        log_dir / "validator_v10.log", maxBytes=5_000_000,
        backupCount=5, encoding="utf-8")
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    log.addHandler(fh)
    log.addHandler(ch)
    return log


log = _setup_logging()


# --------------------------------------------------------------------------- #
# Single-instance lock (so two validators don't run)
# --------------------------------------------------------------------------- #
def _acquire_lock() -> bool:
    """Atomic single-instance lock via OS-level file locking (msvcrt).

    Prevents the race condition where multiple validator instances
    check-then-write simultaneously and all proceed.
    """
    lock_file = PROJ / "data" / "validator.lock"
    pid_file = PROJ / "data" / "validator.pid"
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(lock_file), os.O_CREAT | os.O_RDWR)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            try:
                old_pid = pid_file.read_text().strip()
            except Exception:
                old_pid = "?"
            log.error("Another validator holds lock (PID %s). Exiting.",
                      old_pid)
            return False
        pid_file.write_text(str(os.getpid()))
        # Keep fd open — lock released on process exit.
        return True
    except Exception as ex:
        log.warning("lock acquire failed: %r", ex)
        return True


# --------------------------------------------------------------------------- #
# Pick keys to validate
# --------------------------------------------------------------------------- #
def _fetch_batch() -> list:
    """Fetch a batch of NEW/ERR keys.

    PRIORITY ORDER:
      1. ZAI (GLM) + DASHSCOPE (Qwen) + DEEPSEEK — highest value first
      2. Other non-TG providers (fill remaining slots)
      3. Telegram (limited per cycle)
    """
    c = e._connect()
    try:
        all_rows = []
        # Priority 1: ZAI + DASHSCOPE + DEEPSEEK first.
        rows = c.execute(
            'SELECT val, prov FROM keys '
            'WHERE status IN ("NEW","ERR") '
            'AND prov IN ("ZAI","DASHSCOPE","DEEPSEEK") '
            'LIMIT ?', (BATCH_SIZE,)).fetchall()
        all_rows.extend(rows)
        # Priority 2: fill remaining slots with other providers.
        remaining = BATCH_SIZE - len(all_rows)
        if remaining > 0:
            rows = c.execute(
                'SELECT val, prov FROM keys '
                'WHERE status IN ("NEW","ERR") '
                'AND prov NOT IN ("TELEGRAM","ZAI","DASHSCOPE","DEEPSEEK") '
                'LIMIT ?', (remaining,)).fetchall()
            all_rows.extend(rows)
        # Priority 3: TG keys (fill any remaining slots).
        remaining = BATCH_SIZE - len(all_rows)
        if remaining > 0:
            rows = c.execute(
                'SELECT val, prov FROM keys '
                'WHERE status IN ("NEW","ERR") AND prov = "TELEGRAM" '
                'LIMIT ?', (min(remaining, 50),)).fetchall()
            all_rows.extend(rows)
        return all_rows
    finally:
        c.close()


def _count_pending() -> int:
    c = e._connect()
    try:
        return c.execute(
            'SELECT COUNT(*) FROM keys WHERE status IN ("NEW","ERR")'
        ).fetchone()[0]
    finally:
        c.close()


# --------------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------------- #
def main() -> None:
    if not _acquire_lock():
        sys.exit(1)

    e.db_init()  # ensure schema exists

    print("=" * 60)
    print("  KeyFarm VALIDATOR v10")
    print(f"  Poll: {POLL_INTERVAL}s | batch={BATCH_SIZE} | threads={WORKERS}")
    print(f"  Providers: {len(e.PROVIDERS)}")
    print("  Reads NEW keys from DB -> validates -> updates status")
    print("=" * 60)
    log.info("Validator started. Pending keys: %d", _count_pending())

    total_checked = 0
    total_working = 0
    cycles_idle = 0
    last_heartbeat = time.time()

    # Periodic WAL checkpoint to prevent DB bloat + lock contention.
    def _wal_checkpoint():
        try:
            c = e._connect()
            c.execute("PRAGMA wal_checkpoint(PASSIVE)")
            c.close()
        except Exception:
            pass
    total_working = 0
    cycles_idle = 0

    while not _STOP.is_set():
        # Periodic WAL checkpoint (every ~5 min).
        if time.time() - last_heartbeat > 300:
            _wal_checkpoint()
            last_heartbeat = time.time()

        try:
            batch = _fetch_batch()
        except Exception as fetch_err:
            log.warning("DB fetch error (will retry): %r", fetch_err)
            for _ in range(int(POLL_INTERVAL * 10)):
                if _STOP.is_set():
                    break
                time.sleep(0.1)
            continue

        if not batch:
            cycles_idle += 1
            # Heartbeat every ~60s.
            if cycles_idle % 30 == 0:
                log.info("⏳ waiting for NEW keys... (checked=%d, working=%d)",
                         total_checked, total_working)
            for _ in range(int(POLL_INTERVAL * 10)):
                if _STOP.is_set():
                    break
                time.sleep(0.1)
            continue
        cycles_idle = 0

        log.info("🔑 validating %d keys... (pending=%d)",
                 len(batch), _count_pending())

        # Validate in parallel — with watchdog timeout (90s per batch).
        # Short timeout ensures stuck threads don't block the whole validator.
        ex = ThreadPoolExecutor(max_workers=WORKERS)
        futs = {ex.submit(e.validate, k, p): (k, p) for k, p in batch}
        batch_working = 0
        completed = 0
        try:
            for f in as_completed(futs, timeout=90):
                if _STOP.is_set():
                    break
                k, p = futs[f]
                try:
                    status, plan, price, rem = f.result(timeout=45)
                    completed += 1
                    total_checked += 1
                    if status == "WORKING":
                        batch_working += 1
                        total_working += 1
                        log.info("   ✅ WORKING [%s] %s | %s | $%s | rem=%s",
                                 p, e.mask(k), plan, price, rem)
                    elif status == "LIMITED":
                        log.info("   ⚠️  limited [%s] %s", p, e.mask(k))
                    elif status == "FREE":
                        log.info("   🆓 free [%s] %s", p, e.mask(k))
                except Exception as ex_err:
                    log.debug("validate error: %r", ex_err)
        except Exception as ex_timeout:
            stuck = len(batch) - completed
            log.warning("⚠️  batch timeout (90s) — %d/%d keys stuck, skipping",
                        stuck, len(batch))
        for f in futs:
            f.cancel()
        ex.shutdown(wait=False, cancel_futures=True)

        log.info("✅ batch done: %d working / %d checked | "
                 "totals: working=%d checked=%d",
                 batch_working, len(batch),
                 total_working, total_checked)

        # Tiny pause before next poll — slice for prompt shutdown + liveness.
        if not _STOP.is_set():
            for _ in range(int(POLL_INTERVAL * 10)):
                if _STOP.is_set():
                    break
                time.sleep(0.1)

    log.info("Validator stopped. Total checked=%d, working=%d",
             total_checked, total_working)
    # Release lock.
    lock_file = PROJ / "data" / "validator.pid"
    try:
        lock_file.unlink(missing_ok=True)
    except Exception:
        pass


if __name__ == "__main__":
    main()
