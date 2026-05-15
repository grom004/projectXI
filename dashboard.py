"""
PentestKit Dashboard — web interface + SQLite scan history.

Install:  pip install flask
Run:      python dashboard.py
Open:     http://localhost:5000

Automatically imports all JSON reports from the reports/ folder.
Allows launching new scans directly from the browser with live logs.
"""
from __future__ import annotations

import json
import os
import queue
import re
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, g, jsonify, render_template_string, request

# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════════════════════
REPORTS_DIR = Path("reports")
DB_PATH     = Path("pentestkit.db")
HOST        = "127.0.0.1"
PORT        = 5000

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

app = Flask(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
#  DATABASE
# ═══════════════════════════════════════════════════════════════════════════════
SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    target    TEXT    NOT NULL,
    timestamp TEXT    NOT NULL,
    elapsed   REAL    DEFAULT 0,
    n_urls    INTEGER DEFAULT 0,
    n_total   INTEGER DEFAULT 0,
    n_crit    INTEGER DEFAULT 0,
    n_high    INTEGER DEFAULT 0,
    n_med     INTEGER DEFAULT 0,
    n_low     INTEGER DEFAULT 0,
    modules   TEXT    DEFAULT '',
    source    TEXT    DEFAULT 'import'
);
CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module         TEXT,
    severity       TEXT,
    title          TEXT,
    url            TEXT,
    detail         TEXT,
    evidence       TEXT,
    recommendation TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev  ON findings(severity);
"""

def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
    return db

@app.teardown_appcontext
def close_db(_):
    db = getattr(g, "_db", None)
    if db: db.close()

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.executescript(SCHEMA)

# ═══════════════════════════════════════════════════════════════════════════════
#  JSON IMPORT
# ═══════════════════════════════════════════════════════════════════════════════
def import_json(path: Path, db: sqlite3.Connection) -> int | None:
    """Import a single JSON report file. Returns scan_id or None if duplicate."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

    meta     = data.get("meta", {})
    findings = data.get("findings", [])
    target   = meta.get("target", str(path))
    ts       = meta.get("timestamp", path.stem)

    # Skip duplicates
    exists = db.execute("SELECT id FROM scans WHERE target=? AND timestamp=?",
                        (target, ts)).fetchone()
    if exists:
        return None

    counts = {s: sum(1 for f in findings if f.get("severity") == s)
              for s in SEV_ORDER}
    cur = db.execute(
        """INSERT INTO scans(target,timestamp,elapsed,n_urls,n_total,
                             n_crit,n_high,n_med,n_low,modules,source)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (target, ts,
         meta.get("elapsed", 0), meta.get("urls", 0), len(findings),
         counts.get("critical",0), counts.get("high",0),
         counts.get("medium",0), counts.get("low",0),
         ",".join(meta.get("modules", [])), "import")
    )
    scan_id = cur.lastrowid
    db.executemany(
        """INSERT INTO findings(scan_id,module,severity,title,url,
                                detail,evidence,recommendation)
           VALUES(?,?,?,?,?,?,?,?)""",
        [(scan_id,
          f.get("module",""), f.get("severity","info"),
          f.get("title",""), f.get("url",""),
          f.get("detail",""), f.get("evidence",""),
          f.get("recommendation",""))
         for f in findings]
    )
    db.commit()
    return scan_id

def import_all_reports():
    """Scan reports/ dir and import any new JSON files."""
    if not REPORTS_DIR.exists():
        return
    with sqlite3.connect(DB_PATH) as db:
        db.execute("PRAGMA foreign_keys=ON")
        for p in sorted(REPORTS_DIR.glob("*.json")):
            import_json(p, db)

# ═══════════════════════════════════════════════════════════════════════════════
#  LIVE SCAN (SSE)
# ═══════════════════════════════════════════════════════════════════════════════
_scan_queues: dict[str, queue.Queue] = {}
_scan_lock = threading.Lock()

def _run_scan_thread(job_id: str, target: str, modules: list[str],
                     depth: int, rps: float):
    q = _scan_queues[job_id]

    def emit(msg: str):
        q.put(f"data: {msg}\n\n")

    emit(f"[info] Starting scan: {target}")
    emit(f"[info] Modules: {', '.join(modules)}  |  Depth: {depth}  |  RPS: {rps}")

    cmd = [
        sys.executable, "pentestkit.py",
        "--url", target,
        "--modules", *modules,
        "--depth", str(depth),
        "--rps",   str(rps),
        "--output", str(REPORTS_DIR),
    ]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        # Stream subprocess stdout line by line, stripping ANSI colour codes
        for line in proc.stdout:
            clean = re.sub(r"\x1b\[[0-9;]*m", "", line).rstrip()
            if clean:
                emit(f"[log] {clean}")
        proc.wait()
        if proc.returncode == 0:
            emit("[done] Scan complete. Importing report…")
            import_all_reports()
            emit("[done] Done! Dashboard updated.")
        else:
            emit(f"[error] Process exited with code {proc.returncode}")
    except Exception as ex:
        emit(f"[error] {ex}")
    finally:
        q.put(None)   # sentinel — signals SSE stream to close

# ═══════════════════════════════════════════════════════════════════════════════
#  ROUTES — API
# ═══════════════════════════════════════════════════════════════════════════════
@app.get("/api/stats")
def api_stats():
    db = get_db()
    total_scans    = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    total_findings = db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    by_sev = {row["severity"]: row["cnt"] for row in
              db.execute("SELECT severity, COUNT(*) cnt FROM findings GROUP BY severity")}
    recent = [dict(r) for r in db.execute(
        "SELECT id,target,timestamp,n_total,n_crit,n_high FROM scans ORDER BY id DESC LIMIT 8"
    )]
    trend = [dict(r) for r in db.execute(
        """SELECT timestamp, n_crit, n_high, n_med, n_low
           FROM scans ORDER BY id DESC LIMIT 12"""
    )]
    return jsonify({"total_scans": total_scans, "total_findings": total_findings,
                    "by_severity": by_sev, "recent": recent, "trend": trend[::-1]})

@app.get("/api/scans")
def api_scans():
    db   = get_db()
    rows = [dict(r) for r in db.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT 100"
    )]
    return jsonify(rows)

@app.get("/api/scans/<int:scan_id>")
def api_scan(scan_id):
    db   = get_db()
    scan = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan: return jsonify({"error": "not found"}), 404
    findings = [dict(r) for r in db.execute(
        "SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity "
        "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        "WHEN 'low' THEN 3 ELSE 4 END", (scan_id,)
    )]
    return jsonify({"scan": dict(scan), "findings": findings})

@app.delete("/api/scans/<int:scan_id>")
def api_delete_scan(scan_id):
    db = get_db()
    db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    db.commit()
    return jsonify({"ok": True})

@app.post("/api/run")
def api_run():
    body    = request.get_json(silent=True) or {}
    target  = (body.get("target") or "").strip()
    if not target: return jsonify({"error": "target required"}), 400
    if not target.startswith(("http://","https://")):
        target = "https://" + target
    modules = body.get("modules") or ["sql","xss","lfi","ssrf","csrf",
                                       "redirect","headers","overflow"]
    depth   = int(body.get("depth", 2))
    rps     = float(body.get("rps", 10))
    job_id  = f"job_{int(time.time()*1000)}"
    with _scan_lock:
        _scan_queues[job_id] = queue.Queue()
    t = threading.Thread(target=_run_scan_thread,
                         args=(job_id, target, modules, depth, rps),
                         daemon=True)
    t.start()
    return jsonify({"job_id": job_id})

@app.get("/api/run/<job_id>/stream")
def api_stream(job_id):
    if job_id not in _scan_queues:
        return Response("data: [error] job not found\n\n",
                        mimetype="text/event-stream")
    q = _scan_queues[job_id]
    def generate():
        while True:
            msg = q.get()
            if msg is None:
                yield "data: [close]\n\n"
                with _scan_lock:
                    _scan_queues.pop(job_id, None)
                break
            yield msg
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ═══════════════════════════════════════════════════════════════════════════════
#  HTML TEMPLATE
# ═══════════════════════════════════════════════════════════════════════════════
PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PentestKit Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;700&family=Syne:wght@400;700;800&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#07090d; --s1:#0c1018; --s2:#111622; --border:#1c2535;
  --text:#c8d8e8; --muted:#4a6080; --accent:#00d4ff;
  --crit:#ff2d55; --high:#ff6b2b; --med:#f5c400; --low:#34c759; --info:#636366;
}
html{height:100%} body{font-family:'IBM Plex Mono',monospace;background:var(--bg);color:var(--text);min-height:100%;display:flex;flex-direction:column}
a{color:inherit;text-decoration:none}
::-webkit-scrollbar{width:6px;height:6px} ::-webkit-scrollbar-track{background:var(--s1)} ::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}

/* ── LAYOUT ── */
.app{display:flex;flex:1;min-height:0}
nav{width:220px;min-width:220px;background:var(--s1);border-right:1px solid var(--border);display:flex;flex-direction:column;padding:0}
.nav-logo{padding:1.5rem 1.25rem 1rem;border-bottom:1px solid var(--border)}
.nav-logo .brand{font-family:'Syne',sans-serif;font-size:1.15rem;font-weight:800;letter-spacing:-.02em}
.nav-logo .brand em{color:var(--accent);font-style:normal}
.nav-logo .sub{font-size:.65rem;color:var(--muted);margin-top:.15rem}
.nav-links{padding:.75rem 0;flex:1}
.nav-link{display:flex;align-items:center;gap:.6rem;padding:.55rem 1.25rem;font-size:.78rem;color:var(--muted);cursor:pointer;transition:all .15s;border-left:2px solid transparent}
.nav-link:hover,.nav-link.active{color:var(--text);border-left-color:var(--accent);background:rgba(0,212,255,.04)}
.nav-link .icon{font-size:1rem;width:18px;text-align:center}
.nav-footer{padding:.75rem 1.25rem;border-top:1px solid var(--border);font-size:.65rem;color:var(--muted)}

main{flex:1;overflow-y:auto;padding:1.75rem 2rem}
.page{display:none} .page.active{display:block}

/* ── TYPOGRAPHY ── */
h1{font-family:'Syne',sans-serif;font-size:1.4rem;font-weight:800;margin-bottom:1.5rem}
h1 span{color:var(--accent)}
h2{font-size:.65rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:.9rem}
.section{margin-bottom:2rem}

/* ── STAT CARDS ── */
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:.9rem;margin-bottom:2rem}
.stat{background:var(--s2);border:1px solid var(--border);border-radius:8px;padding:1.1rem 1.25rem;position:relative;overflow:hidden}
.stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent);opacity:.5}
.stat.crit::before{background:var(--crit)} .stat.high::before{background:var(--high)}
.stat.med::before{background:var(--med)}   .stat.low::before{background:var(--low)}
.stat-val{font-size:2rem;font-weight:700;line-height:1;margin-bottom:.3rem}
.stat-lbl{font-size:.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}

/* ── CHARTS ── */
.charts{display:grid;grid-template-columns:1fr 1fr;gap:.9rem;margin-bottom:2rem}
.chart-box{background:var(--s2);border:1px solid var(--border);border-radius:8px;padding:1.25rem}
.chart-box h2{margin-bottom:1rem}
.chart-wrap{position:relative;height:200px}

/* ── TABLES ── */
table{width:100%;border-collapse:collapse;font-size:.78rem}
th{padding:.6rem .85rem;text-align:left;font-size:.62rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border);font-weight:500}
td{padding:.6rem .85rem;border-bottom:1px solid rgba(28,37,53,.7);vertical-align:middle}
tr:hover td{background:rgba(0,212,255,.025)}
.tbl-wrap{background:var(--s2);border:1px solid var(--border);border-radius:8px;overflow:hidden}
.tbl-title{padding:.9rem 1rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.tbl-title h2{margin:0}

/* ── BADGES ── */
.badge{display:inline-block;padding:.18rem .55rem;border-radius:20px;font-size:.62rem;font-weight:700;letter-spacing:.06em;color:#000}
.badge.critical{background:var(--crit)} .badge.high{background:var(--high)}
.badge.medium{background:var(--med)}    .badge.low{background:var(--low)}
.badge.info{background:var(--info);color:#ccc}

/* ── BUTTONS ── */
.btn{display:inline-flex;align-items:center;gap:.4rem;padding:.45rem .9rem;border-radius:6px;font-family:'IBM Plex Mono',monospace;font-size:.75rem;cursor:pointer;border:1px solid var(--border);background:var(--s2);color:var(--text);transition:all .15s}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn.primary{background:var(--accent);color:#000;border-color:var(--accent);font-weight:700}
.btn.primary:hover{background:#00b8dd;border-color:#00b8dd;color:#000}
.btn.danger{border-color:var(--crit);color:var(--crit)}
.btn.danger:hover{background:rgba(255,45,85,.1)}
.btn:disabled{opacity:.4;cursor:not-allowed}

/* ── SCAN PANEL ── */
.scan-form{background:var(--s2);border:1px solid var(--border);border-radius:8px;padding:1.5rem;margin-bottom:1.25rem}
.form-row{display:flex;gap:.75rem;align-items:flex-end;flex-wrap:wrap;margin-bottom:1rem}
.field{display:flex;flex-direction:column;gap:.35rem}
.field label{font-size:.65rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.field input,.field select{background:var(--s1);border:1px solid var(--border);border-radius:5px;padding:.45rem .75rem;font-family:'IBM Plex Mono',monospace;font-size:.8rem;color:var(--text);outline:none;transition:border-color .15s}
.field input:focus,.field select:focus{border-color:var(--accent)}
.field input.url-input{width:380px}
.modules-grid{display:flex;flex-wrap:wrap;gap:.45rem;margin-bottom:1rem}
.mod-toggle{padding:.3rem .65rem;border-radius:4px;font-size:.7rem;cursor:pointer;border:1px solid var(--border);background:var(--s1);color:var(--muted);transition:all .15s;user-select:none}
.mod-toggle.on{background:rgba(0,212,255,.12);border-color:var(--accent);color:var(--accent)}

/* ── LIVE LOG ── */
.log-box{background:#04060a;border:1px solid var(--border);border-radius:6px;padding:1rem;font-size:.73rem;height:260px;overflow-y:auto;line-height:1.7}
.log-box .info{color:#4a90d9} .log-box .log{color:var(--muted)}
.log-box .done{color:var(--low);font-weight:700} .log-box .error{color:var(--crit)}

/* ── FINDINGS DETAIL ── */
.back-btn{margin-bottom:1.25rem;display:inline-flex}
.finding-filters{display:flex;gap:.5rem;margin-bottom:1rem;flex-wrap:wrap}
.filter-btn{padding:.3rem .7rem;border-radius:4px;font-size:.7rem;cursor:pointer;border:1px solid var(--border);background:var(--s1);color:var(--muted);transition:all .15s}
.filter-btn.active,.filter-btn:hover{border-color:var(--accent);color:var(--accent)}
.finding-card{background:var(--s2);border:1px solid var(--border);border-left-width:3px;border-radius:7px;padding:1.1rem 1.25rem;margin-bottom:.65rem;transition:transform .1s}
.finding-card:hover{transform:translateX(3px)}
.fc-head{display:flex;align-items:center;gap:.65rem;margin-bottom:.5rem;flex-wrap:wrap}
.fc-title{font-weight:700;font-size:.88rem}
.fc-mod{font-size:.68rem;color:var(--muted);margin-left:auto}
.fc-url{font-size:.72rem;color:#5eaeff;margin-bottom:.45rem;word-break:break-all}
.fc-detail{font-size:.8rem;color:#90a8c0;line-height:1.55;margin-bottom:.4rem}
.fc-ev{background:#03050a;border:1px solid var(--border);border-radius:4px;padding:.6rem;font-size:.68rem;color:#506070;overflow-x:auto;margin-bottom:.4rem;white-space:pre-wrap;word-break:break-all;max-height:120px;overflow-y:auto}
.fc-rec{font-size:.75rem;color:#607888;border-top:1px solid #141e2a;padding-top:.4rem;margin-top:.4rem}

/* ── MISC ── */
.empty{color:var(--muted);text-align:center;padding:3rem;font-size:.82rem}
.tag{display:inline-block;padding:.15rem .45rem;background:rgba(0,212,255,.08);border:1px solid rgba(0,212,255,.2);border-radius:3px;font-size:.65rem;color:var(--accent);margin:.1rem}
.url-cell{max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#5eaeff}
.ts-cell{color:var(--muted)}
.scan-id{color:var(--muted);font-size:.7rem}
.pulse{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--low);margin-right:.4rem;animation:pulse 1.4s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle;margin-right:.4rem}
@keyframes spin{to{transform:rotate(360deg)}}
.toast{position:fixed;bottom:1.5rem;right:1.5rem;background:var(--s2);border:1px solid var(--border);border-radius:6px;padding:.75rem 1.1rem;font-size:.78rem;z-index:999;transform:translateY(100px);opacity:0;transition:all .25s}
.toast.show{transform:translateY(0);opacity:1}
</style>
</head>
<body>
<div class="app">

<!-- ── NAV ── -->
<nav>
  <div class="nav-logo">
    <div class="brand">Pentest<em>Kit</em></div>
    <div class="sub">Security Dashboard</div>
  </div>
  <div class="nav-links">
    <div class="nav-link active" onclick="showPage('dashboard',this)"><span class="icon">◈</span> Dashboard</div>
    <div class="nav-link" onclick="showPage('scans',this)"><span class="icon">☰</span> Scan History</div>
    <div class="nav-link" onclick="showPage('run',this)"><span class="icon">▶</span> New Scan</div>
  </div>
  <div class="nav-footer">v2.0 · authorised use only</div>
</nav>

<!-- ── MAIN ── -->
<main>

<!-- DASHBOARD -->
<div id="page-dashboard" class="page active">
  <h1>Overview <span>·</span> Security Dashboard</h1>
  <div class="stat-grid">
    <div class="stat"><div class="stat-val" id="s-scans">—</div><div class="stat-lbl">Total Scans</div></div>
    <div class="stat crit"><div class="stat-val" id="s-crit">—</div><div class="stat-lbl">Critical</div></div>
    <div class="stat high"><div class="stat-val" id="s-high">—</div><div class="stat-lbl">High</div></div>
    <div class="stat med"><div class="stat-val" id="s-findings">—</div><div class="stat-lbl">Total Findings</div></div>
  </div>
  <div class="charts">
    <div class="chart-box"><h2>Distribution by Severity</h2><div class="chart-wrap"><canvas id="chart-sev"></canvas></div></div>
    <div class="chart-box"><h2>Critical / High Trend</h2><div class="chart-wrap"><canvas id="chart-trend"></canvas></div></div>
  </div>
  <div class="section">
    <div class="tbl-wrap">
      <div class="tbl-title"><h2>Recent Scans</h2><button class="btn" onclick="loadDashboard()">↺ Refresh</button></div>
      <table><thead><tr><th>#</th><th>Target</th><th>Time</th><th>Crit</th><th>High</th><th>Med</th><th>Total</th><th></th></tr></thead>
      <tbody id="recent-tbody"></tbody></table>
    </div>
  </div>
</div>

<!-- SCANS -->
<div id="page-scans" class="page">
  <h1>History <span>·</span> All Scans</h1>
  <div class="tbl-wrap">
    <div class="tbl-title"><h2>Scans</h2><button class="btn" onclick="loadScans()">↺ Refresh</button></div>
    <table><thead><tr><th>#</th><th>Target</th><th>Date / Time</th><th>URLs</th><th>Critical</th><th>High</th><th>Med</th><th>Low</th><th>Total</th><th></th></tr></thead>
    <tbody id="scans-tbody"></tbody></table>
  </div>
</div>

<!-- RUN -->
<div id="page-run" class="page">
  <h1>Launch <span>·</span> New Scan</h1>
  <div class="scan-form">
    <div class="form-row">
      <div class="field">
        <label>Target (URL)</label>
        <input id="run-url" class="url-input" type="text" placeholder="https://target.com">
      </div>
      <div class="field">
        <label>Depth</label>
        <select id="run-depth">
          <option value="1">1 (fast)</option>
          <option value="2" selected>2 (standard)</option>
          <option value="3">3 (deep)</option>
          <option value="4">4 (max)</option>
        </select>
      </div>
      <div class="field">
        <label>RPS (requests/sec)</label>
        <select id="run-rps">
          <option value="5">5 (cautious)</option>
          <option value="10" selected>10 (standard)</option>
          <option value="20">20 (aggressive)</option>
        </select>
      </div>
    </div>
    <div style="margin-bottom:.6rem"><h2>Modules</h2></div>
    <div class="modules-grid" id="modules-grid"></div>
    <div style="display:flex;gap:.6rem;align-items:center">
      <button class="btn primary" id="run-btn" onclick="startScan()">▶ Run Scan</button>
      <button class="btn" onclick="toggleAll()">Select all / deselect</button>
      <span id="run-status" style="font-size:.75rem;color:var(--muted)"></span>
    </div>
  </div>
  <div class="section">
    <h2>Live Log</h2>
    <div class="log-box" id="live-log"><span style="color:var(--muted)">Log will appear once a scan is running…</span></div>
  </div>
</div>

<!-- FINDINGS DETAIL (pseudo-page) -->
<div id="page-findings" class="page">
  <button class="btn back-btn" onclick="showPage('scans',null,true)">← Back to scans</button>
  <div id="findings-header"></div>
  <div class="finding-filters" id="finding-filters"></div>
  <div id="findings-list"></div>
</div>

</main>
</div>

<!-- TOAST -->
<div class="toast" id="toast"></div>

<script>
const MODS = ['sql','xss','lfi','ssrf','csrf','redirect','headers','overflow'];
const SEV_COL = {critical:'#ff2d55',high:'#ff6b2b',medium:'#f5c400',low:'#34c759',info:'#636366'};
let sevChart=null, trendChart=null;

// ── NAVIGATION ──
function showPage(name, el, skipLoad){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(l=>l.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  if(el) el.classList.add('active');
  if(!skipLoad){
    if(name==='dashboard') loadDashboard();
    if(name==='scans') loadScans();
    if(name==='run') initRunPage();
  }
}

// ── TOAST ──
function toast(msg, dur=3000){
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),dur);
}

// ── DASHBOARD ──
async function loadDashboard(){
  const d = await fetch('/api/stats').then(r=>r.json());
  document.getElementById('s-scans').textContent    = d.total_scans;
  document.getElementById('s-findings').textContent = d.total_findings;
  document.getElementById('s-crit').textContent     = d.by_severity?.critical||0;
  document.getElementById('s-high').textContent     = d.by_severity?.high||0;

  // Severity doughnut chart
  const sevCtx = document.getElementById('chart-sev').getContext('2d');
  if(sevChart) sevChart.destroy();
  const sevLabels=['Critical','High','Medium','Low','Info'];
  const sevData=[
    d.by_severity?.critical||0, d.by_severity?.high||0,
    d.by_severity?.medium||0,   d.by_severity?.low||0, d.by_severity?.info||0
  ];
  sevChart = new Chart(sevCtx,{type:'doughnut',data:{
    labels:sevLabels,
    datasets:[{data:sevData,backgroundColor:Object.values(SEV_COL),borderWidth:0,hoverOffset:4}]
  },options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{color:'#c8d8e8',font:{family:"'IBM Plex Mono'",size:11},boxWidth:12}}}}});

  // Critical / High trend line chart
  const tCtx = document.getElementById('chart-trend').getContext('2d');
  if(trendChart) trendChart.destroy();
  const labels = d.trend.map(r=>r.timestamp?.slice(0,13)||'');
  trendChart = new Chart(tCtx,{type:'line',data:{
    labels,
    datasets:[
      {label:'Critical',data:d.trend.map(r=>r.n_crit),borderColor:'#ff2d55',backgroundColor:'rgba(255,45,85,.08)',tension:.3,pointRadius:3,fill:true},
      {label:'High',    data:d.trend.map(r=>r.n_high),borderColor:'#ff6b2b',backgroundColor:'rgba(255,107,43,.05)',tension:.3,pointRadius:3,fill:true},
    ]
  },options:{responsive:true,maintainAspectRatio:false,
    scales:{x:{ticks:{color:'#4a6080',font:{size:9}},grid:{color:'#111622'}},
            y:{ticks:{color:'#4a6080'},grid:{color:'#111622'},beginAtZero:true}},
    plugins:{legend:{labels:{color:'#c8d8e8',font:{size:11},boxWidth:12}}}}});

  // Recent scans table
  const tbody = document.getElementById('recent-tbody');
  tbody.innerHTML = d.recent.map(s=>`
    <tr>
      <td class="scan-id">#${s.id}</td>
      <td class="url-cell" title="${esc(s.target)}">${esc(s.target)}</td>
      <td class="ts-cell">${s.timestamp||''}</td>
      <td style="color:var(--crit)">${s.n_crit||0}</td>
      <td style="color:var(--high)">${s.n_high||0}</td>
      <td>${s.n_total||0}</td>
      <td>${s.n_total||0}</td>
      <td><button class="btn" onclick="openScan(${s.id})">Open</button></td>
    </tr>`).join('') || `<tr><td colspan="8" class="empty">No scans yet</td></tr>`;
}

// ── SCANS ──
async function loadScans(){
  const scans = await fetch('/api/scans').then(r=>r.json());
  const tbody = document.getElementById('scans-tbody');
  tbody.innerHTML = scans.map(s=>`
    <tr>
      <td class="scan-id">#${s.id}</td>
      <td class="url-cell" title="${esc(s.target)}">${esc(s.target)}</td>
      <td class="ts-cell" style="white-space:nowrap">${s.timestamp||''}</td>
      <td style="color:var(--muted)">${s.n_urls||0}</td>
      <td style="color:var(--crit);font-weight:700">${s.n_crit||0}</td>
      <td style="color:var(--high)">${s.n_high||0}</td>
      <td style="color:var(--med)">${s.n_med||0}</td>
      <td style="color:var(--low)">${s.n_low||0}</td>
      <td style="font-weight:700">${s.n_total||0}</td>
      <td style="display:flex;gap:.4rem">
        <button class="btn" onclick="openScan(${s.id})">Open</button>
        <button class="btn danger" onclick="deleteScan(${s.id},this)">✕</button>
      </td>
    </tr>`).join('') || `<tr><td colspan="10" class="empty">No scans yet. Run your first one!</td></tr>`;
}

async function deleteScan(id, btn){
  if(!confirm('Delete scan #'+id+'?')) return;
  await fetch('/api/scans/'+id,{method:'DELETE'});
  btn.closest('tr').remove();
  toast('Scan #'+id+' deleted');
}

// ── FINDINGS ──
async function openScan(id){
  const data = await fetch('/api/scans/'+id).then(r=>r.json());
  const {scan, findings} = data;

  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.getElementById('page-findings').classList.add('active');

  document.getElementById('findings-header').innerHTML = `
    <h1>Scan #${scan.id} <span>·</span> ${esc(scan.target)}</h1>
    <div style="display:flex;gap:1.5rem;margin-bottom:1.25rem;font-size:.78rem;color:var(--muted)">
      <span>${scan.timestamp}</span>
      <span>${scan.n_urls||0} URLs scanned</span>
      <span>${scan.elapsed||0}s</span>
      <span style="color:${scan.n_crit?'var(--crit)':'var(--muted)'}">${scan.n_crit||0} Critical</span>
      <span style="color:${scan.n_high?'var(--high)':'var(--muted)'}">${scan.n_high||0} High</span>
    </div>`;

  // Build severity filter buttons
  const sevs = ['all','critical','high','medium','low','info'];
  document.getElementById('finding-filters').innerHTML = sevs.map(s=>`
    <button class="filter-btn ${s==='all'?'active':''}" data-sev="${s}" onclick="filterFindings('${s}',this)">
      ${s==='all'?'All':s.charAt(0).toUpperCase()+s.slice(1)}
      (${s==='all'?findings.length:findings.filter(f=>f.severity===s).length})
    </button>`).join('');

  window._findings = findings;
  renderFindings(findings);
}

function filterFindings(sev, btn){
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  renderFindings(sev==='all'?window._findings:window._findings.filter(f=>f.severity===sev));
}

function renderFindings(list){
  const col = s => SEV_COL[s]||'#fff';
  document.getElementById('findings-list').innerHTML = list.length
    ? list.map(f=>`
      <div class="finding-card" style="border-left-color:${col(f.severity)}">
        <div class="fc-head">
          <span class="badge ${f.severity}">${f.severity.toUpperCase()}</span>
          <span class="fc-title">${esc(f.title)}</span>
          <span class="fc-mod">[${esc(f.module)}]</span>
        </div>
        <div class="fc-url">🔗 <a href="${esc(f.url)}" target="_blank">${esc(f.url.length>90?f.url.slice(0,90)+'…':f.url)}</a></div>
        <div class="fc-detail">${esc(f.detail)}</div>
        ${f.evidence?`<pre class="fc-ev">${esc(f.evidence.slice(0,500))}</pre>`:''}
        <div class="fc-rec">💡 ${esc(f.recommendation)}</div>
      </div>`).join('')
    : '<div class="empty">No findings for this filter 🎉</div>';
}

// ── RUN PAGE ──
function initRunPage(){
  const grid = document.getElementById('modules-grid');
  if(grid.children.length) return;
  // Render module toggle buttons
  grid.innerHTML = MODS.map(m=>`
    <span class="mod-toggle on" data-mod="${m}" onclick="this.classList.toggle('on')">${m}</span>`).join('');
}

function toggleAll(){
  const els = document.querySelectorAll('.mod-toggle');
  const allOn = [...els].every(e=>e.classList.contains('on'));
  els.forEach(e=>allOn?e.classList.remove('on'):e.classList.add('on'));
}

async function startScan(){
  const url = document.getElementById('run-url').value.trim();
  if(!url){toast('Please enter a target URL!');return;}
  const modules = [...document.querySelectorAll('.mod-toggle.on')].map(e=>e.dataset.mod);
  if(!modules.length){toast('Please select at least one module!');return;}
  const depth = +document.getElementById('run-depth').value;
  const rps   = +document.getElementById('run-rps').value;

  const btn = document.getElementById('run-btn');
  btn.disabled=true; btn.innerHTML='<span class="spinner"></span> Starting…';
  document.getElementById('run-status').textContent='';

  const log = document.getElementById('live-log');
  log.innerHTML = '<span style="color:var(--accent)">▶ Initialising…</span>\n';

  const res  = await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({target:url,modules,depth,rps})});
  const {job_id, error} = await res.json();
  if(error){toast('Error: '+error);btn.disabled=false;btn.textContent='▶ Run Scan';return;}

  // Connect to SSE stream for live log output
  const es = new EventSource('/api/run/'+job_id+'/stream');
  es.onmessage = e => {
    const raw = e.data;
    if(raw==='[close]'){es.close();btn.disabled=false;btn.textContent='▶ Run Scan';
      document.getElementById('run-status').innerHTML='<span style="color:var(--low)">✓ Complete</span>';
      toast('Scan complete! Check the history.');return;}
    const cls = raw.startsWith('[done]')?'done':raw.startsWith('[error]')?'error':
                raw.startsWith('[info]')?'info':'log';
    const line = document.createElement('div');
    line.className=cls; line.textContent=raw.replace(/^\[[a-z]+\] /,'');
    log.appendChild(line); log.scrollTop=log.scrollHeight;
  };
  es.onerror = ()=>{es.close();btn.disabled=false;btn.textContent='▶ Run Scan';};
}

// ── UTILS ──
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

// ── INIT ──
loadDashboard();
</script>
</body>
</html>"""

@app.get("/")
def index():
    return render_template_string(PAGE)

# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n  ██ PentestKit Dashboard")
    print(f"  ██ Database:  {DB_PATH}")
    print(f"  ██ Reports:   {REPORTS_DIR}/")
    print(f"  ██ Server:    http://{HOST}:{PORT}\n")

    init_db()

    # Import any existing JSON reports from the reports/ folder
    imported = 0
    if REPORTS_DIR.exists():
        with sqlite3.connect(DB_PATH) as db:
            db.execute("PRAGMA foreign_keys=ON")
            for p in sorted(REPORTS_DIR.glob("*.json")):
                if import_json(p, db):
                    imported += 1
    if imported:
        print(f"  ✓  Imported {imported} report(s) from {REPORTS_DIR}/\n")

    print(f"  Open in browser: http://{HOST}:{PORT}\n")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
