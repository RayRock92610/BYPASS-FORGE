# BYPASS-FORGE

## System Architecture
* **Orchestration:** Kessel Memory
* **Node:** Cactus [17]
* **Role:** Production Asset

## Description
BYPASS-FORGE is a comprehensive security tool designed for assessing and forging bypass techniques. It is managed via the Kessel Flow global index.

## Installation & Setup
1. Clone the repository.
2. Install necessary dependencies, such as `python3`, `sqlite3`, and `chromium` (required for `snap_it.py`).
3. Set environment variables if needed (e.g., `FORGE_CALLSIGN`, `FWE_SECRET`).

## Components & Usage

### 1. `bypass_forge_server.py`
A server for testing path, header, and verb bypass techniques against endpoints.
**Usage:**
```bash
python3 bypass_forge_server.py
```
Access the web UI at `http://127.0.0.1:7444`.

### 2. `kfb1.sh`
Agent scripts for stealth intake, API/Auth leak probing, and final artifact generation. Requires an Alpha and Omega key.
**Usage:**
```bash
./kfb1.sh <target.com>
```

### 3. `snap_it.py`
A headless Chromium script for generating visual snapshots of code or files.
**Usage:**
```bash
python3 snap_it.py <file>
```

### 4. `fwe`
A filtering engine that processes standard input based on a confidence score and a configured threshold.
**Usage:**
```bash
echo 'data' | ./fwe <confidence_score>
```

## License
MIT License - Copyright (c) 2026 Ray. See the [LICENSE](LICENSE) file for more details.
