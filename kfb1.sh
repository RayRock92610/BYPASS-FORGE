#!/usr/bin/env bash

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

# CALLSIGN: KFB1 | VERSION: 4.1.4-ELECTRIC
# ADMIN: rayrock9261 | KEYS: 1987 / 7891

# --- RGB TRUECOLOR DEFINITIONS (ELECTRIC) ---
RED='\033[38;2;255;49;49m'    # Electric Red
GREEN='\033[38;2;57;255;20m'  # Neon Green
ORANGE='\033[38;2;255;165;0m' # Electric Orange
GRAY='\033[38;2;105;105;105m'
NC='\033[0m' 

set -e

# --- CONFIG & PATHS ---
ALPHA_KEY="1987"
OMEGA_KEY="7891"
DB_PATH="$HOME/kessel-flow-system/data/kessel_vault.db"
CASE_ROOT="$HOME/forensic-cases"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

vlog() { echo -e "${GRAY}[TELEMETRY] $(date +%H:%M:%S) - $1${NC}"; }

init_db() {
    mkdir -p "$(dirname "$DB_PATH")"
    sqlite3 "$DB_PATH" "CREATE TABLE IF NOT EXISTS missions (id TEXT PRIMARY KEY, target TEXT, ts DATETIME DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, mission_id TEXT, agent TEXT, url TEXT, data TEXT);"
}

verify_admin() {
    clear
    echo -e "${RED}[!] SYSTEM ENCRYPTED${NC}"
    echo -ne "${ORANGE}[?] ENTER ALPHA KEY: ${NC}"
    read -r input_key
    if [[ "$input_key" != "$ALPHA_KEY" ]]; then
        echo -e "${RED}[!] ACCESS DENIED. SCRUBBING SESSION.${NC}"
        history -c && exit 1
    fi
    echo -e "${GREEN}[+] ADMIN IDENTITY CONFIRMED. KFB1 ONLINE.${NC}"
}

init_mission() {
    local cid; cid="$(date -u +%Y%m%dT%H%M%SZ)_KFB1_${1//./_}"
    mkdir -p "$CASE_ROOT/$cid"/{intake,zoo_crew_outputs,hashes}
    python3 -c '
import sqlite3, sys
try:
    with sqlite3.connect(sys.argv[1]) as conn:
        conn.execute("INSERT INTO missions (id, target) VALUES (?, ?)", (sys.argv[2], sys.argv[3]))
except Exception as err:
    raise RuntimeError("Failed to insert mission") from err
' "$DB_PATH" "$cid" "$1"
    echo "$cid"
}

deploy_ghost() {
    local cid=$1; local dom=$2
    echo -e "${ORANGE}[*] AGENT GHOST: Initiating Stealth Intake...${NC}"
    vlog "Querying passive shards..."
    if command -v subfinder &> /dev/null; then
        timeout 15s subfinder -d "$dom" -silent | sort -u > "$CASE_ROOT/$cid/intake/subs.txt" || echo "$dom" > "$CASE_ROOT/$cid/intake/subs.txt"
    else
        echo "$dom" > "$CASE_ROOT/$cid/intake/subs.txt"
    fi
}

deploy_strikeforce() {
    local cid=$1
    echo -ne "${ORANGE}[?] ENTER OMEGA KEY TO RELEASE ZOO CREW: ${NC}"
    read -r o_key
    [[ "$o_key" != "$OMEGA_KEY" ]] && return 0
    
    echo -e "${RED}[*] AGENT INQUISITOR: Probing for API/Auth Leaks...${NC}"
    while read -r target; do
        [[ -z "$target" ]] && continue
        # Validate target is a URL or domain/IP syntax to prevent command injection
        if [[ ! "$target" =~ ^[a-zA-Z0-9.:/_-]+$ ]]; then
            continue
        fi
        vlog "Probing: $target"
        local header; header=$(curl -IsL --connect-timeout 2 --max-time 3 -A "$UA" -- "$target" 2>/dev/null | grep -Ei "Set-Cookie|Authorization|API-Key" | tr -d '\r' | tr '\n' ' ')
        if [[ -n "$header" ]]; then
            printf "%s\t%s\t%s\n" "$cid" "$target" "$header" >> "$CASE_ROOT/$cid/intake/findings.tmp"
        fi
    done < "$CASE_ROOT/$cid/intake/subs.txt"

    if [[ -f "$CASE_ROOT/$cid/intake/findings.tmp" ]]; then
        python3 -c '
import sqlite3, sys
try:
    with sqlite3.connect(sys.argv[1]) as conn, open(sys.argv[2]) as f:
        data = []
        for line in f:
            if not line.strip(): continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 3:
                data.append((parts[0], "INQUISITOR", parts[1], parts[2]))
        if data:
            conn.executemany("INSERT INTO findings (mission_id, agent, url, data) VALUES (?, ?, ?, ?)", data)
except Exception as err:
    raise RuntimeError("Failed to batch insert findings") from err
' "$DB_PATH" "$CASE_ROOT/$cid/intake/findings.tmp"
        rm -f "$CASE_ROOT/$cid/intake/findings.tmp"
    fi
}

deploy_bones() {
    local cid=$1
    echo -e "${ORANGE}[*] AGENT BONES: Finalizing Forensic Artifacts...${NC}"
    find "$CASE_ROOT/$cid" -type f -exec sha256sum {} + > "$CASE_ROOT/$cid/hashes/final.tsv"
    history -c
    echo -e "${GREEN}[*] MISSION COMPLETE. STATUS: GONE.${NC}"
}

main() {
    if [[ $# -lt 1 ]]; then
        echo -e "${RED}[!] ERROR: TARGET REQUIRED${NC}"
        echo -e "${ORANGE}Usage: ./kfb1.sh <target.com>${NC}"
        exit 1
    fi
    init_db
    verify_admin
    local CID; CID=$(init_mission "$1")
    deploy_ghost "$CID" "$1"
    deploy_strikeforce "$CID"
    deploy_bones "$CID"
}

main "$@"
