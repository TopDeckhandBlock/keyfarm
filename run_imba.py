#!/usr/bin/env python3
"""IMBA orchestrator — runs KeyHunter parser + validator with a time budget.

Designed for GitHub Actions cron (6h runs, max 360 min per run).
  python run_imba.py --minutes 280

Spawns:
  - src/eternal_v10.py   (parser: 13 providers, realtime firehose, 12 source scanners)
  - src/validator_v10.py (live key validation)
Both get SIGTERM/SIGINT graceful shutdown, then we export results.
"""
import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

PROJ = Path(__file__).parent
PY = sys.executable


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--minutes', type=int, default=280, help='run budget')
    ap.add_argument('--jitter', type=int, default=1800, help='max random start delay (s)')
    args = ap.parse_args()

    # stagger fleet load: random sleep before starting engines
    if args.jitter > 0:
        import random
        delay = random.randint(0, args.jitter)
        print(f'[imba] jitter sleep {delay}s', flush=True)
        time.sleep(delay)

    env = dict(os.environ)
    env['PYTHONUNBUFFERED'] = '1'

    procs = []
    logs = {}
    for script, logname in (
        ('src/eternal_v10.py', 'parser.log'),
        ('src/validator_v10.py', 'validator.log'),
    ):
        lf = open(PROJ / logname, 'ab')
        p = subprocess.Popen([PY, '-u', script], cwd=PROJ, env=env,
                             stdout=lf, stderr=subprocess.STDOUT)
        procs.append(p)
        logs[script] = (p, lf, logname)
        print(f'[imba] started {script} pid={p.pid} -> {logname}', flush=True)

    deadline = time.time() + args.minutes * 60
    try:
        while time.time() < deadline:
            if all(p.poll() is not None for p, _, _ in logs.values()):
                print('[imba] both engines exited early', flush=True)
                break
            time.sleep(30)
    except KeyboardInterrupt:
        pass
    finally:
        for p, lf, logname in logs.values():
            if p.poll() is None:
                print(f'[imba] stopping {logname}', flush=True)
                if os.name == 'nt':
                    p.terminate()
                else:
                    p.send_signal(signal.SIGTERM)
        for p, lf, _ in logs.values():
            try:
                p.wait(timeout=60)
            except subprocess.TimeoutExpired:
                p.kill()
            lf.close()

    # export results summary
    import sqlite3
    db = PROJ / 'data' / 'keys.db'
    if db.exists():
        c = sqlite3.connect(str(db))
        try:
            rows = list(c.execute(
                "SELECT status, COUNT(*) FROM keys GROUP BY status ORDER BY 2 DESC"))
            total = sum(r[1] for r in rows)
            summary = {'total': total, 'by_status': dict(rows)}
            working = list(c.execute(
                "SELECT prov, plan, price, val FROM keys WHERE status='WORKING'"))
            print(f'[imba] SUMMARY {summary}', flush=True)
            print(f'[imba] WORKING keys: {len(working)}', flush=True)
            out = PROJ / 'results'
            out.mkdir(exist_ok=True)
            with open(out / 'working_keys.txt', 'w', encoding='utf-8') as f:
                for prov, plan, price, val in working:
                    f.write(f'{prov}\t{plan}\t{price}\t{val}\n')
            with open(out / 'summary.json', 'w', encoding='utf-8') as f:
                import json
                json.dump(summary, f, indent=1)
            print(f'[imba] results exported to results/', flush=True)
        finally:
            c.close()
    else:
        print('[imba] WARNING: no keys.db found', flush=True)


if __name__ == '__main__':
    main()
