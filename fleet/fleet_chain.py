#!/usr/bin/env python3
"""FLEET CHAIN — keeps launching deploy waves as the token pool grows.

Wave N deploys accounts [0..len(pool)) — fleet_deploy.py skips already-deployed
via fleet_state.json, so each wave only processes NEW tokens.
Stops when pool stops growing for 3 consecutive checks (2h idle) or max_waves hit.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

POOL = Path(r'C:/Users/User/tmp/gh_pats_all.json')
STATE = Path(r'C:/Users/User/tmp/fleet_state.json')
PY = r'C:/Users/User/AppData/Local/Programs/Python/Python311/python.exe'
SCRIPT = Path(r'C:/Users/User/tmp/fleet_deploy.py')
MAX_WAVES = 30
IDLE_LIMIT = 3  # consecutive no-growth waves


def pool_size():
    try:
        return len(json.load(open(POOL, encoding='utf-8')))
    except Exception:
        return 0


def deployed_count():
    try:
        st = json.load(open(STATE, encoding='utf-8'))
        return sum(1 for v in st.values() if v.get('status') == 'deployed')
    except Exception:
        return 0


def main():
    idle = 0
    last_pool = -1
    for wave in range(1, MAX_WAVES + 1):
        size = pool_size()
        dep = deployed_count()
        print(f'[chain] wave {wave}: pool={size} deployed={dep}', flush=True)
        if size == last_pool:
            idle += 1
        else:
            idle = 0
        last_pool = size
        if idle >= IDLE_LIMIT and dep >= size - 2:
            print('[chain] pool stable and fully deployed — stop', flush=True)
            break
        if dep < size:
            # wait for any running fleet_deploy to finish (single instance via state lock file)
            lock = Path(r'C:/Users/User/tmp/fleet_wave.lock')
            if lock.exists() and time.time() - lock.stat().st_mtime < 3600:
                print('[chain] wave in progress, wait 10min', flush=True)
                time.sleep(600)
                continue
            lock.write_text(str(wave))
            r = subprocess.run([PY, '-u', str(SCRIPT), '0', str(size)],
                               capture_output=True, text=True, timeout=7200)
            print(r.stdout[-800:], flush=True)
            print(r.stderr[-300:], flush=True)
            try:
                lock.unlink()
            except Exception:
                pass
        time.sleep(600)
    print(f'[chain] DONE deployed={deployed_count()} pool={pool_size()}', flush=True)


if __name__ == '__main__':
    main()
